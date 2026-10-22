//! TS-vs-Rust parity for the M6b step-2 DLP writes (DESIGN §16.3, §16.5–§16.8).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh [`FixtureServer`] seeded with the DLP dataset (whose write
//! routes change it) and a fresh [`Sandbox`]. `parity` tests compare exit codes, the
//! write requests (JSON bodies as JSON, D35; multipart uploads by part names, filenames,
//! content types, metadata JSON and file hash) and the output with the D172 move applied:
//! TypeScript writes its success lines on stdout, airs-cli-rs on stderr. airs-cli-rs reads
//! the record before every replace, patch and delete (the guard, D166), so the request
//! lists are compared without its guard reads. `divergence` tests pin both sides of each
//! §12 row this step implements (named by its D#).

use std::time::Duration;

use airs_test_harness::{
    Cli, Collection, Dl, DlpData, FixtureServer, Planned, RecordedRequest, Route, Run, RunOptions,
    Sandbox, multipart, normalise_program, require_ts, run, spawn, split_outcome_lines,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
}

type Seed<'a> = &'a dyn Fn(&mut DlpData);
type Files<'a> = &'a [(&'a str, &'a [u8])];

/// Runs `cli` (`runtime dlp <args>`) on a fresh seeded server and sandbox; `files` are
/// written under `tmp/` and `@name` in `args` is replaced by the absolute path of file
/// `name`.
fn exec(cli: &Cli, args: &[&str], seed: Seed<'_>, files: Files<'_>, options: &RunOptions) -> Side {
    let server = FixtureServer::start();
    server.seed_dlp();
    server.dlp(|data| seed(data));
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    for (name, bytes) in files {
        std::fs::write(sandbox.tmp().join(name), bytes).unwrap();
    }
    let args: Vec<String> = ["runtime", "dlp"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .chain(args.iter().map(|arg| match arg.strip_prefix('@') {
            Some(name) => sandbox.tmp().join(name).display().to_string(),
            None => (*arg).to_owned(),
        }))
        .collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run(cli, &sandbox, &args, options);
    let requests = server.requests();
    Side { run: out, requests }
}

fn unchanged(_: &mut DlpData) {}

/// Both sides with their own arguments (`None` after a `PARITY SKIPPED` notice).
fn pair(
    name: &str,
    rust_args: &[&str],
    ts_args: &[&str],
    seed: Seed<'_>,
    files: Files<'_>,
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    let options = RunOptions::new();
    Some((
        exec(&rust(), rust_args, seed, files, &options),
        exec(&ts, ts_args, seed, files, &options),
    ))
}

fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    pair(name, args, args, &unchanged, &[])
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// The writes of a side (every non-GET DLP request).
fn writes(side: &Side) -> Vec<&RecordedRequest> {
    side.requests
        .iter()
        .filter(|request| request.route.is_write())
        .collect()
}

/// The API requests of a side without the token requests and, for airs-cli-rs, without
/// the guard read of `id` (D166).
fn api_without_guard(side: &Side, guard: Option<&str>) -> Vec<String> {
    let mut lines: Vec<String> = side
        .requests
        .iter()
        .filter(|request| request.route != Route::Token)
        .map(RecordedRequest::line)
        .collect();
    if let Some(guard) = guard
        && let Some(index) = lines.iter().position(|line| line == guard)
    {
        lines.remove(index);
    }
    lines
}

/// A write's comparable shape: method, path, content type (without a multipart
/// boundary) and body (JSON, or the multipart parts).
fn shape(request: &RecordedRequest) -> Value {
    let content_type = request
        .header("content-type")
        .map(|value| value.split(';').next().unwrap_or_default().to_owned());
    let body = match multipart(request) {
        Some(parts) => Value::Array(
            parts
                .parts
                .iter()
                .map(|part| {
                    // JSON parts compare as JSON (key order differs, D35); others by hash.
                    let bytes = match &part.json {
                        Some(_) => Value::Null,
                        None => json!([part.len, part.sha256]),
                    };
                    json!({
                        "name": part.name,
                        "filename": part.filename,
                        "contentType": part.content_type,
                        "json": part.json,
                        "bytes": bytes,
                    })
                })
                .collect(),
        ),
        None => request.body_json().unwrap_or(Value::Null),
    };
    json!({
        "method": request.method,
        "path": request.path,
        "query": request.query,
        "contentType": content_type,
        "body": airs_test_harness::js_normalize(&body),
    })
}

/// Both sides sent the same writes.
fn assert_same_writes(r: &Side, t: &Side) {
    let rust: Vec<Value> = writes(r).into_iter().map(shape).collect();
    let ts: Vec<Value> = writes(t).into_iter().map(shape).collect();
    assert_eq!(rust, ts, "writes differ{}", context(r, t));
}

/// The ack parity of D172: TypeScript's stdout success line (pretty) is airs-cli-rs's
/// stderr line, which airs-cli-rs prints in every format; the rest of TypeScript's stdout
/// is airs-cli-rs's stdout.
fn assert_moved_acks(r: &Side, t: &Side, success: &str) {
    assert_eq!(r.run.code, t.run.code, "exit codes differ{}", context(r, t));
    let (outcome, rest) = split_outcome_lines(&t.run.stdout);
    assert_eq!(r.run.stdout, rest, "stdout differs{}", context(r, t));
    assert_eq!(r.run.stderr, success, "stderr differs{}", context(r, t));
    assert!(
        outcome.is_empty() || outcome == success,
        "TS outcome {outcome:?}{}",
        context(r, t)
    );
}

fn kw_files() -> Vec<(&'static str, &'static [u8])> {
    vec![("kw.txt", b"FAKE-KW-A\nFAKE-KW-B\n")]
}

const DICTIONARY: [&str; 12] = [
    "--name",
    "D1",
    "--category",
    "Confidential",
    "--region",
    "United States",
    "--description",
    "dd",
    "--classification",
    "pab",
    "--file",
    "@kw.txt",
];

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The acks in pretty, table and json: the same bytes, the success line moved to
    /// stderr (D172); the same POST body (JSON equality, D35).
    #[test]
    fn acks_match_typescript_in_every_format() {
        let args = [
            "patterns",
            "create",
            "--name",
            "NP1",
            "--description",
            "d",
            "--confidence-levels",
            "high, low,",
            "--regex",
            "a+",
            "--weighted-regex",
            "A|B|2.5",
            "--proximity-keyword",
            "near",
            "--proximity-distance",
            "50",
            "--delimiter",
            ",",
            "--tag",
            "compliance=PCI, HIPAA",
            "--tag",
            "compliance=SOX",
            "--tag",
            "my_tag=x",
        ];
        for format in ["pretty", "table", "json"] {
            let mut full = args.to_vec();
            full.extend(["--output", format]);
            let Some((r, t)) = sides("acks_match_typescript_in_every_format", &full) else {
                return;
            };
            assert_moved_acks(&r, &t, "  ✓ created p-new-1  NP1 v1\n");
            if format == "pretty" {
                assert_eq!(t.run.stdout, "  ✓ created p-new-1  NP1 v1\n");
            }
            assert_same_writes(&r, &t);
        }
    }

    /// Profiles, dictionaries and filtering profiles: the same write requests (the
    /// guard read aside) and acks; `--pattern-id` reads the patterns in the same order.
    #[test]
    fn write_requests_match_typescript() {
        let mut dictionary_create = vec!["dictionaries", "create", "--include-keywords"];
        dictionary_create.extend(DICTIONARY);
        let mut dictionary_replace = vec!["dictionaries", "replace", "d-cus-1"];
        dictionary_replace.extend(DICTIONARY);
        let profile_body = r#"{"name":"BP","profile_type":"advanced","detection_rules":[{"rule_type":"multi_profile","multi_profile":{"data_profile_ids":[1],"operator_type":"and"}}]}"#;
        let files = kw_files();
        let cases: Vec<(Vec<&str>, Vec<&str>, Option<&str>)> = vec![
            (
                vec![
                    "profiles",
                    "create",
                    "--name",
                    "NP",
                    "--description",
                    "dd",
                    "--granular",
                    "--pattern-id",
                    "p-cus-1",
                    "--pattern-id",
                    "p-pre-1",
                    "--combinator",
                    "AND",
                ],
                vec![],
                None,
            ),
            (
                vec!["profiles", "create", "--body", profile_body],
                vec![],
                None,
            ),
            (
                vec!["profiles", "replace", "dp-cus-1", "--body", profile_body],
                vec!["--force"],
                Some("GET /dlp/v2/api/data-profiles/dp-cus-1"),
            ),
            (
                vec![
                    "profiles",
                    "patch",
                    "dp-cus-1",
                    "--set",
                    "name=P",
                    "profile_type=advanced",
                    "--clear",
                    "description",
                ],
                vec![],
                Some("GET /dlp/v2/api/data-profiles/dp-cus-1"),
            ),
            (dictionary_create, vec![], None),
            (
                dictionary_replace,
                vec!["--force"],
                Some("GET /dlp/v2/api/dictionaries/d-cus-1"),
            ),
            (
                vec![
                    "dictionaries",
                    "patch",
                    "d-cus-1",
                    "--set",
                    "category=Legal",
                    "name=N",
                    "original_file_name=kw.txt",
                    "--clear",
                    "description",
                ],
                vec![],
                Some("GET /dlp/v2/api/dictionaries/d-cus-1"),
            ),
            (
                vec![
                    "filtering-profiles",
                    "replace",
                    "fp-2",
                    "--file-based",
                    "--non-file-based",
                    "--description",
                    "d",
                    "--direction",
                    "UPLOAD",
                    "--log-severity",
                    "HIGH",
                    "--scan-type",
                    "exclude",
                    "--data-profile-id",
                    "123",
                    "--euc-template-id",
                    "e1",
                    "--end-user-coaching",
                    "--granular",
                    "--file-type",
                    "pdf",
                    "--file-type",
                    "docx",
                ],
                vec!["--force"],
                Some("GET /dlp/v2/api/data-filtering-profiles/fp-2"),
            ),
            (
                vec![
                    "patterns",
                    "replace",
                    "p-cus-1",
                    "--name",
                    "R",
                    "--type",
                    "custom",
                    "--technique",
                    "regex",
                ],
                vec!["--force"],
                Some("GET /dlp/v2/api/data-patterns/p-cus-1"),
            ),
            (
                vec![
                    "patterns",
                    "patch",
                    "p-cus-1",
                    "--set",
                    "name=My",
                    "type=custom",
                    r#"detection_config={"technique":"regex"}"#,
                    "n=5",
                    r#"s="5""#,
                    "b=true",
                    "arr=[1,2]",
                    "bad={oops",
                    "--clear",
                    "description",
                ],
                vec![],
                Some("GET /dlp/v2/api/data-patterns/p-cus-1"),
            ),
        ];
        for (args, rust_extra, guard) in cases {
            let mut rust_args = args.clone();
            rust_args.extend(rust_extra);
            for format in ["pretty", "json"] {
                let mut rust_full = rust_args.clone();
                rust_full.extend(["--output", format]);
                let mut ts_full = args.clone();
                ts_full.extend(["--output", format]);
                let Some((r, t)) = pair(
                    "write_requests_match_typescript",
                    &rust_full,
                    &ts_full,
                    &unchanged,
                    &files,
                ) else {
                    return;
                };
                assert_same_writes(&r, &t);
                assert_eq!(
                    api_without_guard(&r, guard),
                    api_without_guard(&t, None),
                    "{args:?}{}",
                    context(&r, &t)
                );
                assert_eq!(r.run.code, 0, "{args:?}{}", context(&r, &t));
                let (outcome, rest) = split_outcome_lines(&t.run.stdout);
                assert_eq!(r.run.stdout, rest, "{args:?}{}", context(&r, &t));
                let success = r.run.stderr.lines().last().unwrap_or_default();
                assert!(success.starts_with("  ✓ "), "{args:?}{}", context(&r, &t));
                if format == "pretty" {
                    assert_eq!(
                        outcome,
                        format!("{success}\n"),
                        "{args:?}{}",
                        context(&r, &t)
                    );
                }
            }
        }
    }

    /// The shared argument texts (exit 2 on both sides).
    #[test]
    fn shared_usage_errors_match_typescript() {
        let name33 = "x".repeat(33);
        for (args, message) in [
            (vec!["patterns", "create"], "--name is required"),
            (
                vec![
                    "patterns",
                    "patch",
                    "p-cus-1",
                    "--body-file",
                    "b.json",
                    "--set",
                    "x=1",
                ],
                "--body-file is mutually exclusive with --set/--clear",
            ),
            (
                vec![
                    "filtering-profiles",
                    "replace",
                    "fp-2",
                    "--file-based",
                    "--force",
                ],
                "--file-based and --non-file-based are both required",
            ),
            (vec!["profiles", "create"], "--name is required"),
            (
                vec!["profiles", "create", "--name", &name33],
                "Profile name must be at most 32 characters",
            ),
            (
                vec!["profiles", "create", "--name", " "],
                "Profile name is required and must be a nonblank string",
            ),
            (
                vec![
                    "profiles",
                    "create",
                    "--name",
                    "x",
                    "--profile-type",
                    "basic",
                ],
                "Basic profile writes are unsupported: the API returned advanced for basic requests. Use advanced or manage basic profiles in SCM.",
            ),
            (
                vec![
                    "profiles",
                    "create",
                    "--name",
                    "x",
                    "--profile-type",
                    "other",
                ],
                "Profile type must be advanced",
            ),
            (
                vec!["profiles", "create", "--name", "x", "--combinator", "xor"],
                "--combinator must be one of and|or|not|and_not|or_not",
            ),
            (
                vec!["profiles", "create", "--name", "x", "--confidence", "HIGH"],
                "--confidence must be low|medium|high",
            ),
            (
                vec!["profiles", "create", "--name", "x"],
                "Invalid profile metadata: verify required fields and value types",
            ),
            (
                vec![
                    "profiles",
                    "create",
                    "--body",
                    "{}",
                    "--body-file",
                    "b.json",
                ],
                "--body and --body-file are mutually exclusive",
            ),
            (
                vec!["profiles", "create", "--body", "{x"],
                "Cannot read profile body as JSON; verify the file and JSON syntax",
            ),
            (
                vec!["profiles", "create", "--body", "[]"],
                "Profile body must be a JSON object",
            ),
            (
                vec!["profiles", "patch", "dp-cus-1", "--set", "noequals"],
                "Invalid profile patch: verify JSON syntax and --set key=value/--clear key flags",
            ),
            (
                vec!["profiles", "patch", "dp-cus-1", "--set", "description=x"],
                "Profile name is required and must be a nonblank string",
            ),
            (
                vec!["profiles", "patch", "dp-cus-1", "--set", "name=x"],
                "Invalid profile metadata: verify required fields and value types",
            ),
            (
                vec!["dictionaries", "create", "--name", "x", "--file", "k.txt"],
                "--name, --category, --region, and --file are required",
            ),
            (
                vec!["dictionaries", "patch", "d-cus-1", "--set", "a.b=1"],
                "Invalid dictionary patch flags: use --set key=value, --clear key, or --body-file for nested fields",
            ),
            (
                vec!["dictionaries", "patch", "d-cus-1", "--set", "name=x"],
                "Invalid dictionary metadata: verify required fields and value types",
            ),
        ] {
            // TypeScript has no `--force`.
            let ts_args: Vec<&str> = args
                .iter()
                .copied()
                .filter(|arg| *arg != "--force")
                .collect();
            let Some((r, t)) = pair(
                "shared_usage_errors_match_typescript",
                &args,
                &ts_args,
                &unchanged,
                &[],
            ) else {
                return;
            };
            let expected = format!("\n  ✗ {message}\n\n");
            r.run.assert_code(2);
            t.run.assert_code(2);
            assert_eq!(r.run.stderr, expected, "{args:?}{}", context(&r, &t));
            assert_eq!(t.run.stderr, expected, "{args:?}{}", context(&r, &t));
            assert!(r.requests.is_empty() && writes(&t).is_empty(), "{args:?}");
        }
    }

    /// `profiles delete`: the same refusal (the program name aside, D73), exit 2, no
    /// request on either side.
    #[test]
    fn profiles_delete_is_the_typescript_refusal() {
        let Some((r, t)) = sides(
            "profiles_delete_is_the_typescript_refusal",
            &["profiles", "rm", "dp-cus-1"],
        ) else {
            return;
        };
        r.run.assert_code(2);
        t.run.assert_code(2);
        assert_eq!(t.run.stderr, normalise_program(&r.run.stderr));
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// A write rejected with a problem: the same error block (exit 1); a dictionary
    /// upload rejected without detail prints TS's region hint first.
    #[test]
    fn http_errors_match_typescript() {
        let mut dictionary = vec!["dictionaries", "create"];
        dictionary.extend(DICTIONARY);
        let files = kw_files();
        for (route, planned, args) in [
            (
                Dl::Create(Collection::Profiles),
                Planned::json(409, &json!({"title": "Conflict", "status": 409})),
                vec![
                    "profiles",
                    "create",
                    "--body",
                    r#"{"name":"BP","detection_rules":[]}"#,
                ],
            ),
            (
                Dl::Create(Collection::Dictionaries),
                Planned::json(
                    400,
                    &json!({"title": "Bad Request", "status": 400, "errors": [{"property": "originalFileName", "reason": "must not be blank"}]}),
                ),
                dictionary.clone(),
            ),
            (
                Dl::Create(Collection::Dictionaries),
                Planned::json(400, &json!({"title": "Bad Request", "status": 400})),
                dictionary.clone(),
            ),
        ] {
            let Some(ts) = require_ts("http_errors_match_typescript") else {
                return;
            };
            let mut outs = Vec::new();
            for cli in [rust(), ts] {
                let server = FixtureServer::start();
                server.seed_dlp();
                server.set_default(Route::Dlp(route), planned.clone());
                let sandbox = Sandbox::new();
                sandbox.single_tenant(&server, "prod", TSG);
                std::fs::write(sandbox.tmp().join("kw.txt"), files[0].1).unwrap();
                let full: Vec<String> = ["runtime", "dlp"]
                    .iter()
                    .map(|a| (*a).to_owned())
                    .chain(args.iter().map(|arg| match arg.strip_prefix('@') {
                        Some(name) => sandbox.tmp().join(name).display().to_string(),
                        None => (*arg).to_owned(),
                    }))
                    .collect();
                let full: Vec<&str> = full.iter().map(String::as_str).collect();
                outs.push(run(&cli, &sandbox, &full, &RunOptions::new()));
            }
            outs[0].assert_code(1);
            outs[1].assert_code(1);
            assert_eq!(outs[0].stderr, outs[1].stderr, "{route:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Help (§16.2)
// ---------------------------------------------------------------------------

mod help {
    use super::*;

    /// Every write leaf carries TypeScript's description and option texts, with the
    /// §16.2 changes (`--force`, the D169 `--type`/`--technique` texts of `patterns
    /// replace`, `--metadata-file` of `dictionaries create`).
    #[test]
    fn write_help_texts_match_typescript() {
        let Some(ts) = require_ts("write_help_texts_match_typescript") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let help = |cli: &Cli, path: &[&str]| {
            let mut args = vec!["runtime", "dlp"];
            args.extend_from_slice(path);
            args.push("--help");
            let out = run(cli, &sandbox, &args, &RunOptions::new());
            out.assert_success();
            out.stdout
        };
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let options = |text: &str| -> Vec<(String, String)> {
            let mut out: Vec<(String, String)> = Vec::new();
            let mut lines = text.lines();
            if !lines.any(|line| line == "Options:") {
                return out;
            }
            for line in lines.take_while(|line| !line.trim().is_empty()) {
                let trimmed = line.trim_start();
                if trimmed.starts_with('-') {
                    let (spec, description) = trimmed.split_once("  ").unwrap_or((trimmed, ""));
                    let name = spec
                        .split([',', ' '])
                        .find(|part| part.starts_with("--"))
                        .unwrap_or(spec)
                        .to_owned();
                    out.push((name, squash(description)));
                } else if let Some((_, description)) = out.last_mut() {
                    *description = squash(&format!("{description} {trimmed}"));
                }
            }
            out
        };
        let mut problems = Vec::new();
        for path in [
            &["filtering-profiles", "replace"][..],
            &["patterns", "create"],
            &["patterns", "replace"],
            &["patterns", "patch"],
            &["patterns", "delete"],
            &["profiles", "create"],
            &["profiles", "replace"],
            &["profiles", "patch"],
            &["profiles", "delete"],
            &["dictionaries", "create"],
            &["dictionaries", "replace"],
            &["dictionaries", "patch"],
            &["dictionaries", "delete"],
        ] {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let rust_options = options(&r);
            for (flag, description) in options(&t) {
                if matches!(flag.as_str(), "--help" | "--output") {
                    continue;
                }
                let expected = match (path, flag.as_str()) {
                    (["patterns", "replace"], "--type") => s(
                        "Pattern type: predefined|custom|file_property (default: the current type)",
                    ),
                    (["patterns", "replace"], "--technique") => {
                        s("Detection technique (default: the current technique)")
                    }
                    (["dictionaries", "create"], "--metadata-file") => {
                        s("JSON metadata file (cannot be combined with --name/--category/...)")
                    }
                    _ => description,
                };
                match rust_options.iter().find(|(f, _)| *f == flag) {
                    Some((_, actual)) if *actual == expected => {}
                    other => problems.push(format!("{path:?} {flag}: {other:?} vs {expected:?}")),
                }
            }
            let confirms = matches!(
                path,
                [
                    "filtering-profiles" | "patterns" | "profiles" | "dictionaries",
                    "replace"
                ] | ["patterns" | "dictionaries", "delete"]
            );
            let force = rust_options.iter().find(|(flag, _)| flag == "--force");
            if confirms != force.is_some() {
                problems.push(format!("{path:?}: --force {force:?}"));
            }
            if let Some((_, text)) = force
                && text != "Skip the confirmation prompt"
            {
                problems.push(format!("{path:?}: --force text {text:?}"));
            }
            let ts_about = t
                .split("\n\n")
                .nth(1)
                .filter(|p| !p.starts_with("Options:"))
                .map(squash)
                .unwrap_or_default();
            let rust_about = r
                .split("\n\n")
                .next()
                .filter(|first| !first.starts_with("Usage:"))
                .map(squash)
                .unwrap_or_default();
            // §16.2 (D172): the dictionary replace describes the Rust 204 fallback.
            let ts_about = if path == ["dictionaries", "replace"] {
                assert!(ts_about.contains("(state not echoed)"), "{ts_about}");
                "Full-replace via multipart upload. --file required. May return 200 (body) or 204 (re-get; when the re-get fails, warns and prints the id).".to_owned()
            } else {
                ts_about
            };
            if rust_about != ts_about {
                problems.push(format!(
                    "{path:?} description: {rust_about:?} vs {ts_about:?}"
                ));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    fn s(text: &str) -> String {
        text.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D50 (0.7 extension): TypeScript renders a write ack as yaml; airs-cli-rs refuses
    /// the format before the tenant (exit 2, no request).
    #[test]
    fn d50_dropped_formats_are_usage_errors_on_dlp_writes() {
        let Some((r, t)) = sides(
            "d50_dropped_formats_are_usage_errors_on_dlp_writes",
            &["patterns", "create", "--name", "Y", "--output", "yaml"],
        ) else {
            return;
        };
        t.run.assert_success();
        assert!(t.run.stdout.contains("action: created"), "{}", t.run.stdout);
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Invalid output format 'yaml'. Expected: pretty, table, json\n\n"
        );
        assert!(r.requests.is_empty());
    }

    /// D52 (0.7 extension): a name with ESC in a write answer reaches TypeScript's
    /// terminal raw; airs-cli-rs replaces it in the ack.
    #[test]
    fn d52_dlp_ack_text_is_terminal_safe() {
        let name = "Bad\u{1b}[31mName";
        let args = [
            "patterns",
            "patch",
            "p-cus-1",
            "--set",
            "type=custom",
            r#"detection_config={"technique":"regex"}"#,
            &format!("name={name}"),
        ];
        let Some((r, t)) = sides("d52_dlp_ack_text_is_terminal_safe", &args) else {
            return;
        };
        t.run.assert_success();
        assert!(t.run.stdout.contains(name));
        r.run.assert_success();
        assert!(!r.run.stderr.contains('\u{1b}'));
        assert!(r.run.stderr.contains("Bad\u{fffd}[31mName"));
    }

    /// D116 (0.7 extension): a pattern body the schema refuses: TypeScript lists the field
    /// paths and zod codes; airs-cli-rs names the request only (both exit 2, no request).
    #[test]
    fn d116_dlp_body_schema_failures_name_no_fields() {
        let Some((r, t)) = sides(
            "d116_dlp_body_schema_failures_name_no_fields",
            &["patterns", "create", "--name", "x", "--type", "bogus"],
        ) else {
            return;
        };
        t.run.assert_code(2);
        assert_eq!(
            t.run.stderr,
            "\n  ✗ AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v2/api/data-patterns did not match schema: type: invalid_enum_value\n\n"
        );
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v2/api/data-patterns did not match schema\n\n"
        );
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// D160: a 503 with `Retry-After: 0`: one airs-cli-rs POST and the outcome line,
    /// more than one TypeScript POST; a 403: one airs-cli-rs POST, TypeScript replays it.
    #[test]
    fn d160_dlp_writes_are_one_attempt() {
        let Some(ts) = require_ts("d160_dlp_writes_are_one_attempt") else {
            return;
        };
        for (planned, rust_count) in [
            (
                Planned::json(503, &json!({"title": "busy", "status": 503})).with_retry_after(0),
                1,
            ),
            (Planned::empty_json(403), 1),
        ] {
            let mut counts = Vec::new();
            let mut stderrs = Vec::new();
            for cli in [rust(), ts.clone()] {
                let server = FixtureServer::start();
                server.seed_dlp();
                server.set_default(
                    Route::Dlp(Dl::Create(Collection::Patterns)),
                    planned.clone(),
                );
                let sandbox = Sandbox::new();
                sandbox.single_tenant(&server, "prod", TSG);
                let out = run(
                    &cli,
                    &sandbox,
                    &["runtime", "dlp", "patterns", "create", "--name", "x"],
                    &RunOptions::new().timeout(Duration::from_secs(120)),
                );
                counts.push(server.dl_requests(Dl::Create(Collection::Patterns)).len());
                stderrs.push(out.stderr);
            }
            assert_eq!(counts[0], rust_count, "{}", stderrs[0]);
            assert!(counts[1] > 1, "TypeScript re-sends: {counts:?}");
            if planned.status == 503 {
                assert!(stderrs[0].contains("    Outcome unknown: the data pattern may have been created.\n    Check 'airs runtime dlp patterns list' before creating it again.\n"));
                assert!(!stderrs[1].contains("Outcome"));
            }
        }
    }

    /// D161: a write the service rejects: TypeScript exits 2 with the bare message;
    /// airs-cli-rs exits 1 with the §6 block.
    #[test]
    fn d161_dlp_write_failures_exit_1() {
        let Some(ts) = require_ts("d161_dlp_write_failures_exit_1") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_dlp();
            server.set_default(
                Route::Dlp(Dl::Create(Collection::Patterns)),
                Planned::json(400, &json!({"title": "Bad Request", "status": 400})),
            );
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            outs.push(run(
                &cli,
                &sandbox,
                &["runtime", "dlp", "patterns", "create", "--name", "x"],
                &RunOptions::new(),
            ));
        }
        outs[1].assert_code(2);
        assert_eq!(
            outs[1].stderr,
            "\n  ✗ AISEC_CLIENT_SIDE_ERROR:API error 400; Bad Request\n\n"
        );
        outs[0].assert_code(1);
        assert_eq!(
            outs[0].stderr,
            "\n  ✗ Error: AISEC_CLIENT_SIDE_ERROR:API error 400; Bad Request\n    HTTP 400\n    Re-run with --debug to capture redacted API diagnostics.\n\n"
        );
    }

    /// D162: TypeScript sends `matching_rules: {}` for `--proximity-distance abc` and
    /// duplicate leaves for a repeated `--pattern-id`; airs-cli-rs refuses both before
    /// the tenant.
    #[test]
    fn d162_dlp_write_arguments_are_checked_before_the_tenant() {
        for (args, message) in [
            (
                vec![
                    "patterns",
                    "create",
                    "--name",
                    "x",
                    "--proximity-distance",
                    "abc",
                ],
                "--proximity-distance must be an integer from 2 to 1000",
            ),
            (
                vec![
                    "profiles",
                    "create",
                    "--name",
                    "x",
                    "--pattern-id",
                    "p-cus-1",
                    "--pattern-id",
                    "p-cus-1",
                ],
                "--pattern-id lists the same data pattern twice",
            ),
        ] {
            let Some((r, t)) = sides(
                "d162_dlp_write_arguments_are_checked_before_the_tenant",
                &args,
            ) else {
                return;
            };
            t.run.assert_success();
            assert_eq!(writes(&t).len(), 1, "{args:?}");
            let body = t
                .requests
                .iter()
                .find(|q| q.route.is_write())
                .unwrap()
                .body_json()
                .unwrap();
            if args[0] == "patterns" {
                assert_eq!(body["matching_rules"], json!({}));
            } else {
                assert_eq!(
                    body["detection_rules"][0]["expression_tree"]["sub_expressions"]
                        .as_array()
                        .unwrap()
                        .len(),
                    2
                );
            }
            r.run.assert_code(2);
            assert_eq!(r.run.stderr, format!("\n  ✗ {message}\n\n"));
            assert!(r.requests.is_empty());
        }
    }

    /// D163: TypeScript quotes the body in its JSON error; airs-cli-rs names the flag.
    #[test]
    fn d163_dlp_errors_never_echo_input() {
        let Some((r, t)) = sides(
            "d163_dlp_errors_never_echo_input",
            &["patterns", "create", "--body", "PRIVATE-REGEX-123"],
        ) else {
            return;
        };
        t.run.assert_code(2);
        assert!(
            t.run.stderr.contains("PRIVATE-REGEX-123"),
            "{}",
            t.run.stderr
        );
        r.run.assert_code(2);
        assert_eq!(r.run.stderr, "\n  ✗ --body is not valid JSON\n\n");
    }

    /// D164: TypeScript sends a body file of any size; airs-cli-rs refuses one over 1 MiB
    /// before the tenant (exit 1, no request).
    #[test]
    fn d164_dlp_input_files_are_bounded() {
        let body = json!({"name": "x", "type": "custom", "detection_config": {"technique": "regex"}, "description": "d".repeat(1024 * 1024)}).to_string();
        let files = [("big.json", body.as_bytes())];
        let Some((r, t)) = pair(
            "d164_dlp_input_files_are_bounded",
            &["patterns", "create", "--body-file", "@big.json"],
            &["patterns", "create", "--body-file", "@big.json"],
            &unchanged,
            &files,
        ) else {
            return;
        };
        t.run.assert_success();
        assert_eq!(writes(&t).len(), 1);
        r.run.assert_code(1);
        assert!(
            r.run.stderr.contains("larger than 1 MiB"),
            "{}",
            r.run.stderr
        );
        assert!(r.requests.is_empty());
    }

    /// D165: TypeScript ignores a build flag given with `--body`; airs-cli-rs refuses it.
    #[test]
    fn d165_ambiguous_body_inputs_are_refused() {
        let body = r#"{"name":"B1","type":"custom","detection_config":{"technique":"regex"}}"#;
        let Some((r, t)) = sides(
            "d165_ambiguous_body_inputs_are_refused",
            &["patterns", "create", "--body", body, "--name", "ignored"],
        ) else {
            return;
        };
        t.run.assert_success();
        let sent = writes(&t)[0].body_json().unwrap();
        assert_eq!(sent["name"], "B1");
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --body and --body-file cannot be combined with --name\n\n"
        );
        assert!(r.requests.is_empty());
    }

    /// D166: TypeScript deletes and replaces predefined records and sends
    /// `type: predefined`; airs-cli-rs reads the record first and refuses.
    #[test]
    fn d166_predefined_resources_are_never_written() {
        let Some((r, t)) = pair(
            "d166_predefined_resources_are_never_written",
            &["patterns", "rm", "p-pre-1", "--force"],
            &["patterns", "rm", "p-pre-1"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        t.run.assert_success();
        assert_eq!(t.run.stdout, "  ✓ archived p-pre-1\n");
        assert_eq!(writes(&t).len(), 1);
        r.run.assert_code(1);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Error: p-pre-1 is a predefined data pattern; airs never modifies or deletes predefined resources\n\n"
        );
        assert!(writes(&r).is_empty());
        let Some((r, t)) = sides(
            "d166_predefined_resources_are_never_written",
            &["patterns", "create", "--name", "x", "--type", "predefined"],
        ) else {
            return;
        };
        t.run.assert_success();
        assert_eq!(writes(&t)[0].body_json().unwrap()["type"], "predefined");
        r.run.assert_code(2);
        assert!(r.requests.is_empty());
    }

    /// D167: without a terminal TypeScript deletes at once; airs-cli-rs refuses without
    /// `--force` before the tenant (exit 2, no request).
    #[test]
    fn d167_destructive_dlp_commands_confirm() {
        let Some((r, t)) = sides(
            "d167_destructive_dlp_commands_confirm",
            &["dictionaries", "rm", "d-cus-1"],
        ) else {
            return;
        };
        t.run.assert_success();
        assert_eq!(writes(&t).len(), 1);
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ refusing to delete dictionary d-cus-1 without --force in non-interactive mode\n\n"
        );
        assert!(r.requests.is_empty());
    }

    /// D168: a flag-built filtering-profile replace drops the exclusions and rules
    /// silently in TypeScript; airs-cli-rs names them before the write.
    #[test]
    fn d168_a_replace_names_what_it_drops() {
        let args = [
            "filtering-profiles",
            "replace",
            "fp-2",
            "--file-based",
            "--non-file-based",
        ];
        let mut rust_args = args.to_vec();
        rust_args.push("--force");
        let Some((r, t)) = pair(
            "d168_a_replace_names_what_it_drops",
            &rust_args,
            &args,
            &unchanged,
            &[],
        ) else {
            return;
        };
        t.run.assert_success();
        assert_eq!(t.run.stderr, "");
        r.run.assert_success();
        assert!(
            r.run.stderr.starts_with("  ⚠ The replacement omits 3 field(s) the filtering profile has now: description, exclusions, rule1\n"),
            "{}",
            r.run.stderr
        );
        assert_same_writes(&r, &t);
    }

    /// D169: TypeScript rewrites a `weighted_regex` pattern to `regex` (and the type to
    /// `custom`) on a flag replace; airs-cli-rs keeps the current values.
    #[test]
    fn d169_patterns_replace_keeps_the_type_and_technique() {
        let seed = |data: &mut DlpData| data.patterns[2]["type"] = json!("file_property");
        let Some((r, t)) = pair(
            "d169_patterns_replace_keeps_the_type_and_technique",
            &["patterns", "replace", "p-dis-1", "--name", "R", "--force"],
            &["patterns", "replace", "p-dis-1", "--name", "R"],
            &seed,
            &[],
        ) else {
            return;
        };
        let body = |side: &Side| writes(side)[0].body_json().unwrap();
        assert_eq!(body(&t)["type"], "custom");
        assert_eq!(body(&t)["detection_config"]["technique"], "regex");
        assert_eq!(body(&r)["type"], "file_property");
        assert_eq!(body(&r)["detection_config"]["technique"], "weighted_regex");
    }

    /// D172: TypeScript prints the pretty ack and the delete line on stdout, also under
    /// `--quiet`; airs-cli-rs prints them on stderr and `--quiet` drops them.
    #[test]
    fn d172_dlp_outcome_lines_go_to_stderr() {
        let Some((r, t)) = sides(
            "d172_dlp_outcome_lines_go_to_stderr",
            &["--quiet", "patterns", "create", "--name", "Q"],
        ) else {
            return;
        };
        assert_eq!(t.run.stdout, "  ✓ created p-new-1  Q v1\n");
        assert_eq!((r.run.stdout.as_str(), r.run.stderr.as_str()), ("", ""));
        let Some((r, t)) = pair(
            "d172_dlp_outcome_lines_go_to_stderr",
            &["patterns", "rm", "p-cus-1", "--force", "--output", "json"],
            &["patterns", "rm", "p-cus-1"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(t.run.stdout, "  ✓ archived p-cus-1\n");
        assert_eq!(r.run.stdout, "");
        assert_eq!(r.run.stderr, "  ✓ archived p-cus-1\n");
    }

    /// D172: a dictionary replace answered without a body whose re-read fails:
    /// TypeScript prints `(state not echoed by region)` on stdout in every format;
    /// airs-cli-rs warns on stderr and prints the reduced ack.
    #[test]
    fn d172_a_replace_without_a_body_warns() {
        let seed = |data: &mut DlpData| data.dictionary_replace_empty = true;
        let mut args = vec!["dictionaries", "replace", "d-cus-1"];
        args.extend(DICTIONARY);
        args.extend(["--output", "json"]);
        let mut rust_args = args.clone();
        rust_args.push("--force");
        let files = kw_files();
        let ts = match require_ts("d172_a_replace_without_a_body_warns") {
            Some(ts) => ts,
            None => return,
        };
        let mut outs = Vec::new();
        for (cli, args) in [(rust(), &rust_args), (ts, &args)] {
            let server = FixtureServer::start();
            server.seed_dlp();
            server.dlp(seed);
            if !cli.is_ts() {
                // The guard read answers; the re-read after the PUT fails.
                server.push_once(
                    Route::Dlp(Dl::Get(Collection::Dictionaries)),
                    Planned::builtin(),
                );
            }
            server.set_default(
                Route::Dlp(Dl::Get(Collection::Dictionaries)),
                Planned::json(404, &json!({"title": "Not Found", "status": 404})),
            );
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            std::fs::write(sandbox.tmp().join("kw.txt"), files[0].1).unwrap();
            let full: Vec<String> = ["runtime", "dlp"]
                .iter()
                .map(|a| (*a).to_owned())
                .chain(args.iter().map(|arg| match arg.strip_prefix('@') {
                    Some(name) => sandbox.tmp().join(name).display().to_string(),
                    None => (*arg).to_owned(),
                }))
                .collect();
            let full: Vec<&str> = full.iter().map(String::as_str).collect();
            outs.push(run(&cli, &sandbox, &full, &RunOptions::new()));
        }
        outs[1].assert_success();
        assert_eq!(
            outs[1].stdout,
            "  ✓ replaced d-cus-1 (state not echoed by region)\n"
        );
        outs[0].assert_success();
        assert_eq!(
            outs[0].stdout,
            "{\n  \"action\": \"replaced\",\n  \"id\": \"d-cus-1\"\n}\n"
        );
        assert!(
            outs[0]
                .stderr
                .ends_with("  ⚠ replaced d-cus-1; the service did not return the new state\n"),
            "{}",
            outs[0].stderr
        );
    }

    /// D173: TypeScript uploads an unknown `--category`; airs-cli-rs refuses the metadata
    /// before the tenant.
    #[test]
    fn d173_dictionary_metadata_is_validated() {
        let mut args = vec!["dictionaries", "create"];
        args.extend(DICTIONARY);
        let index = args.iter().position(|arg| *arg == "Confidential").unwrap();
        args[index] = "Bogus";
        let files = kw_files();
        let Some((r, t)) = pair(
            "d173_dictionary_metadata_is_validated",
            &args,
            &args,
            &unchanged,
            &files,
        ) else {
            return;
        };
        t.run.assert_success();
        assert_eq!(writes(&t).len(), 1);
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Invalid dictionary metadata: verify required fields and value types\n\n"
        );
        assert!(r.requests.is_empty());
    }

    /// D174 (writes): a signal while a create is held kills TypeScript with nothing
    /// printed; airs-cli-rs reports that the change may already have been applied.
    #[test]
    fn d174_an_interrupted_write_prints_its_context() {
        let Some(ts) = require_ts("d174_an_interrupted_write_prints_its_context") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_dlp();
            server.push_once(
                Route::Dlp(Dl::Create(Collection::Patterns)),
                Planned::held(),
            );
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let running = spawn(
                &cli,
                &sandbox,
                &["runtime", "dlp", "patterns", "create", "--name", "held"],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Dlp(Dl::Create(Collection::Patterns)),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal("INT");
            outs.push(running.wait());
            server.release_held();
        }
        assert_eq!(outs[0].code, 130);
        assert_eq!(
            outs[0].stderr,
            "\n  ✗ Error: Interrupted; the change may already have been applied (outcome unknown)\n\n"
        );
        assert_eq!(outs[1].code, 130);
        assert_eq!(outs[1].stdout, "");
        assert_eq!(outs[1].stderr, "");
    }
}
