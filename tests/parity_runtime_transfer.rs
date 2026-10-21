//! TS-vs-Rust parity for `runtime profiles backup` and `runtime profiles restore` (DESIGN
//! §18.15, §18.16), the M6d step-3 commands.
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript reference,
//! each on a fresh [`FixtureServer`] seeded with the same profiles and topics and a fresh
//! [`Sandbox`]. The two CLIs write different backup formats (D215), so backups are
//! compared by their summaries and records (D35: key order ignored), and a restore is
//! given the same records in each CLI's own format (TypeScript's envelope is built from
//! the Rust file). `divergence` tests pin both sides of each §12 row this step implements
//! (named by its D#).

use std::time::Duration;

use airs_test_harness::{
    Cli, Collection, Dl, FixtureServer, Planned, RecordedRequest, Route, Run, RunOptions, Sandbox,
    fixtures, json_semantic_eq, normalise_program, require_ts, run,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const SOURCE: &str = "100";
const DEST: &str = "200";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn topic() -> Value {
    fixtures::topic(11, "Restricted", 3, "Restricted business topics")
}

fn production() -> Value {
    let mut profile = fixtures::profile(1, "Production", 2);
    profile["tsg_id"] = json!(SOURCE);
    profile["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"] = json!([{
        "name": "topic-guardrails", "action": "",
        "topic-list": [{"action": "block", "topic": [
            {"topic_name": "Restricted", "topic_id": fixtures::uuid(11), "revision": 3}
        ]}]
    }]);
    profile
}

fn staging() -> Value {
    let mut profile = fixtures::profile(2, "Staging", 1);
    profile["tsg_id"] = json!(SOURCE);
    profile
}

/// [`staging`] with a custom DLP member (`My Profile`).
fn with_dlp() -> Value {
    let mut profile = staging();
    profile["policy"]["ai-security-profiles"][0]["model-configuration"]["data-protection"] = json!({
        "data-leak-detection": {"action": "block",
            "member": [{"text": "My Profile", "id": "dp-src", "version": "1"}]}
    });
    profile
}

type Seed = fn(&FixtureServer);

/// The source TSG 100: `Production` (referencing the topic) and `Staging`.
fn standard(server: &FixtureServer) {
    server.set_profiles(SOURCE, vec![production(), staging()]);
    server.set_topics(SOURCE, vec![topic()]);
}

/// The source TSG 100 with the DLP-referencing `Staging` only.
fn dlp(server: &FixtureServer) {
    server.set_profiles(SOURCE, vec![with_dlp()]);
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    server: FixtureServer,
    sandbox: Sandbox,
}

impl Side {
    fn api(&self) -> Vec<String> {
        self.requests
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    fn writes(&self) -> Vec<&RecordedRequest> {
        self.requests
            .iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    fn tmp(&self, name: &str) -> String {
        self.sandbox.tmp().join(name).display().to_string()
    }
}

/// A fresh server seeded with `seed` (and the DLP dataset) and a tenant `prod` of `tsg`;
/// `files` land under `tmp/`.
fn world(tsg: &str, seed: Seed, files: &[(&str, &str)]) -> (FixtureServer, Sandbox) {
    let server = FixtureServer::start();
    server.seed_dlp();
    seed(&server);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", tsg);
    for (name, text) in files {
        std::fs::write(sandbox.tmp().join(name), text).unwrap();
    }
    (server, sandbox)
}

/// Runs `runtime profiles <args>` (`@name` is the absolute path of `tmp/<name>`).
fn exec_with(
    cli: &Cli,
    tsg: &str,
    seed: Seed,
    files: &[(&str, &str)],
    args: &[&str],
    edit: impl FnOnce(&FixtureServer),
) -> Side {
    let (server, sandbox) = world(tsg, seed, files);
    edit(&server);
    let args: Vec<String> = ["runtime", "profiles"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .chain(args.iter().map(|arg| match arg.strip_prefix('@') {
            Some(name) => sandbox.tmp().join(name).display().to_string(),
            None => (*arg).to_owned(),
        }))
        .collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run(
        cli,
        &sandbox,
        &args,
        &RunOptions::new().allow_writes_under("cwd"),
    );
    let requests = server.requests();
    Side {
        run: out,
        requests,
        server,
        sandbox,
    }
}

fn exec(cli: &Cli, tsg: &str, seed: Seed, files: &[(&str, &str)], args: &[&str]) -> Side {
    exec_with(cli, tsg, seed, files, args, |_| {})
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// A Rust backup of `seed` (TSG 100): the file's JSON text.
fn rust_backup(seed: Seed) -> String {
    let side = exec(
        &rust(),
        SOURCE,
        seed,
        &[],
        &["backup", "--output-file", "@b.json"],
    );
    side.run.assert_success();
    std::fs::read_to_string(side.sandbox.tmp().join("b.json")).unwrap()
}

/// The same records in the TypeScript envelope.
fn ts_envelope(rust: &str) -> String {
    let file: Value = serde_json::from_str(rust).unwrap();
    let records = |key: &str| -> Vec<Value> {
        file[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["record"].clone())
            .collect()
    };
    json!({"version": 1, "resourceType": "runtime-security-profiles", "exportedAt": file["exportedAt"],
        "source": {"tsgId": file["tsgId"]}, "profiles": records("profiles"), "topics": records("topics")})
    .to_string()
}

/// Both CLIs restore the same records onto a tenant of `tsg`: airs-cli-rs from its file
/// (with `rust_extra`), TypeScript from its envelope.
fn restore_pair(
    ts: &Cli,
    backup: &str,
    tsg: &str,
    args: &[&str],
    rust_extra: &[&str],
    edit: fn(&FixtureServer),
) -> (Side, Side) {
    let envelope = ts_envelope(backup);
    let mut rust_args = vec!["restore", "@b.json"];
    rust_args.extend_from_slice(args);
    rust_args.extend_from_slice(rust_extra);
    let mut ts_args = vec!["restore", "@b.json"];
    ts_args.extend_from_slice(args);
    let empty: Seed = |_| {};
    (
        exec_with(&rust(), tsg, empty, &[("b.json", backup)], &rust_args, edit),
        exec_with(ts, tsg, empty, &[("b.json", &envelope)], &ts_args, edit),
    )
}

/// A write's comparable shape: method, path, query and JSON body.
fn shape(request: &RecordedRequest) -> Value {
    json!({"method": request.method, "path": request.path, "query": request.query,
        "body": request.body_json().unwrap_or(Value::Null)})
}

fn without_rust_keys(mut doc: Value) -> Value {
    if let Some(object) = doc[0].as_object_mut() {
        object.remove("outcomeUnknown");
        object.remove("notAttempted");
    }
    doc
}

const FORCE: [&str; 3] = ["--expect-tsg", DEST, "--force"];

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The backup summary is TypeScript's in every format (the absolute path given to
    /// both); the stored records are TypeScript's (D35: key order ignored).
    #[test]
    fn backup_summaries_and_records_match_typescript() {
        let Some(ts) = require_ts("backup_summaries_and_records_match_typescript") else {
            return;
        };
        for format in ["pretty", "table", "json"] {
            let args = ["backup", "--output-file", "@b.json", "--output", format];
            let r = exec(&rust(), SOURCE, standard, &[], &args);
            let t = exec(&ts, SOURCE, standard, &[], &args);
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            let (rust_path, ts_path) = (r.tmp("b.json"), t.tmp("b.json"));
            assert_eq!(
                r.run.stdout.replace(&rust_path, "<file>"),
                t.run.stdout.replace(&ts_path, "<file>"),
                "{format}{}",
                context(&r, &t)
            );
            assert_eq!(r.api(), t.api(), "the same reads");
            let rust_file: Value =
                serde_json::from_str(&std::fs::read_to_string(&rust_path).unwrap()).unwrap();
            let ts_file: Value =
                serde_json::from_str(&std::fs::read_to_string(&ts_path).unwrap()).unwrap();
            for key in ["profiles", "topics"] {
                let rust_records: Vec<&Value> = rust_file[key]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| &entry["record"])
                    .collect();
                let ts_records: Vec<&Value> = ts_file[key].as_array().unwrap().iter().collect();
                assert_eq!(rust_records.len(), ts_records.len(), "{key}");
                for (rust_record, ts_record) in rust_records.iter().zip(&ts_records) {
                    assert!(
                        json_semantic_eq(rust_record, ts_record),
                        "{key}: {rust_record} vs {ts_record}"
                    );
                }
            }
        }
    }

    /// The restore preview: the same plan in every layout, the DLP fallback warning on
    /// stderr on both.
    #[test]
    fn restore_previews_match_typescript() {
        let Some(ts) = require_ts("restore_previews_match_typescript") else {
            return;
        };
        let backup = rust_backup(standard);
        for format in ["pretty", "table", "json"] {
            let (r, t) = restore_pair(
                &ts,
                &backup,
                DEST,
                &["--dry-run", "--output", format],
                &["--allow-other-tenant"],
                |_| {},
            );
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            assert_eq!(r.run.stdout, t.run.stdout, "{format}{}", context(&r, &t));
            assert_eq!(r.api(), t.api());
        }
        let backup = rust_backup(dlp);
        for format in ["pretty", "json"] {
            let (r, t) = restore_pair(
                &ts,
                &backup,
                DEST,
                &["--dry-run", "--on-missing-dlp", "basic", "--output", format],
                &["--allow-other-tenant"],
                |_| {},
            );
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(r.run.stdout, t.run.stdout, "{format}{}", context(&r, &t));
            let warning = "  ⚠ DLP protection change: Staging will use Basic detection instead of My Profile. Custom rules are not preserved.\n";
            assert!(
                r.run.stderr.contains(warning) && t.run.stderr.contains(warning),
                "{}",
                context(&r, &t)
            );
        }
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &[
                "--dry-run",
                "--dlp-map",
                "My Profile=My Profile",
                "--output",
                "json",
            ],
            &["--allow-other-tenant"],
            |_| {},
        );
        assert_eq!(r.run.code, 0, "{}", context(&r, &t));
        assert_eq!(r.run.json(), t.run.json(), "{}", context(&r, &t));
        assert_eq!(
            r.server.dl_requests(Dl::List(Collection::Profiles)).len(),
            1
        );
        assert_eq!(
            t.server.dl_requests(Dl::List(Collection::Profiles)).len(),
            1
        );
    }

    /// A forced cross-tenant restore: the same writes (bodies equal), the same result
    /// (the Rust-only keys removed) in json and pretty.
    #[test]
    fn restore_results_and_writes_match_typescript() {
        let Some(ts) = require_ts("restore_results_and_writes_match_typescript") else {
            return;
        };
        let backup = rust_backup(standard);
        for format in ["json", "pretty"] {
            let (r, t) = restore_pair(
                &ts,
                &backup,
                DEST,
                &["--expect-tsg", DEST, "--force", "--output", format],
                &["--allow-other-tenant"],
                |_| {},
            );
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            let rust_writes: Vec<Value> = r.writes().iter().map(|request| shape(request)).collect();
            let ts_writes: Vec<Value> = t.writes().iter().map(|request| shape(request)).collect();
            assert_eq!(rust_writes.len(), 3);
            for (rust_write, ts_write) in rust_writes.iter().zip(&ts_writes) {
                assert!(
                    json_semantic_eq(rust_write, ts_write),
                    "{rust_write} vs {ts_write}"
                );
            }
            assert_eq!(r.api(), t.api(), "the same reads around each write");
            if format == "json" {
                let rust_doc = r.run.json();
                assert_eq!(rust_doc[0]["outcomeUnknown"], Value::Null);
                assert_eq!(rust_doc[0]["notAttempted"], json!([]));
                assert_eq!(
                    without_rust_keys(rust_doc),
                    t.run.json(),
                    "{}",
                    context(&r, &t)
                );
            } else {
                assert_eq!(
                    r.run.stdout,
                    t.run.stdout,
                    "a complete run has no Rust-only block{}",
                    context(&r, &t)
                );
            }
        }
        // `skip` and `verify` re-runs send no write, on both.
        let seeded: fn(&FixtureServer) = |server| {
            let mut existing = staging();
            existing["tsg_id"] = json!(DEST);
            existing["profile_id"] = json!(fixtures::uuid(55));
            server.set_profiles(DEST, vec![existing]);
        };
        let backup =
            rust_backup(|server: &FixtureServer| server.set_profiles(SOURCE, vec![staging()]));
        for conflict in ["skip", "verify"] {
            let (r, t) = restore_pair(
                &ts,
                &backup,
                DEST,
                &[
                    "--on-conflict",
                    conflict,
                    "--expect-tsg",
                    DEST,
                    "--force",
                    "--output",
                    "json",
                ],
                &["--allow-other-tenant"],
                seeded,
            );
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            assert!(r.writes().is_empty() && t.writes().is_empty());
            assert_eq!(
                without_rust_keys(r.run.json()),
                t.run.json(),
                "{conflict}{}",
                context(&r, &t)
            );
        }
    }

    /// The plan refusals carry TypeScript's texts (exit 1, no write).
    #[test]
    fn restore_refusals_match_typescript() {
        let Some(ts) = require_ts("restore_refusals_match_typescript") else {
            return;
        };
        let backup = rust_backup(standard);
        let seeded: fn(&FixtureServer) = |server| {
            let mut existing = production();
            existing["tsg_id"] = json!(DEST);
            server.set_profiles(DEST, vec![existing]);
        };
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &["--dry-run"],
            &["--allow-other-tenant"],
            seeded,
        );
        let message = "Destination profile already exists: Production; choose --on-conflict verify, skip or update";
        assert_eq!(r.run.code, 1);
        assert_eq!(t.run.code, 1);
        assert!(
            r.run.stderr.contains(message) && t.run.stderr.contains(message),
            "{}",
            context(&r, &t)
        );
        let differs: fn(&FixtureServer) = |server| {
            server.set_topics(
                DEST,
                vec![fixtures::topic(60, "Restricted", 1, "Different")],
            );
        };
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &["--dry-run"],
            &["--allow-other-tenant"],
            differs,
        );
        let message = "Destination topic differs: Restricted; use --name-prefix to avoid changing a shared topic";
        assert!(
            r.run.stderr.contains(message) && t.run.stderr.contains(message),
            "{}",
            context(&r, &t)
        );
        assert!(r.writes().is_empty() && t.writes().is_empty());
    }

    /// The argument checks shared with TypeScript: the same texts and exit 2.
    #[test]
    fn shared_usage_errors_match_typescript() {
        let Some(ts) = require_ts("shared_usage_errors_match_typescript") else {
            return;
        };
        for args in [
            &["backup", "--max-pages", "0"][..],
            &["backup", "Production", "--all"],
            &["backup", "--output-file", "-"],
            &["backup", "--output-file", "x.txt"],
            &["restore", "@x.json", "--max-pages", "1001"],
            &["restore", "@x.json", "--on-conflict", "replace"],
            &["restore", "@x.json", "--on-missing-dlp", "drop"],
            &["restore", "@x.json", "--force"],
            &["restore", "@x.json", "--dlp-map", "a"],
            &["restore", "@x.json", "--dlp-map", "a=b", "--dlp-map", "a=c"],
        ] {
            let r = exec(&rust(), SOURCE, standard, &[], args);
            let t = exec(&ts, SOURCE, standard, &[], args);
            assert_eq!(r.run.code, 2, "{args:?}{}", context(&r, &t));
            assert_eq!(t.run.code, 2, "{args:?}{}", context(&r, &t));
            let line = |side: &Side| {
                side.run
                    .stderr
                    .lines()
                    .find(|line| line.contains('✗'))
                    .unwrap_or_default()
                    .trim()
                    .trim_start_matches("✗ ")
                    .to_owned()
            };
            assert_eq!(line(&r), line(&t), "{args:?}");
            assert!(r.requests.is_empty());
        }
    }

    /// Help: TypeScript's descriptions and options (`--file-format` without yaml, D215;
    /// `--allow-other-tenant` Rust-only, D216), the examples with the program name, and
    /// the `runtime profiles` group listing both commands.
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let sandbox = Sandbox::new();
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let help = |cli: &Cli, path: &[&str]| {
            let mut args = vec!["runtime", "profiles"];
            args.extend_from_slice(path);
            args.push("--help");
            let out = run(cli, &sandbox, &args, &RunOptions::new());
            out.assert_success();
            out.stdout
        };
        let options = |text: &str| -> Vec<(String, String)> {
            let mut out: Vec<(String, String)> = Vec::new();
            let mut lines = text.lines();
            if !lines.any(|line| line == "Options:") {
                return out;
            }
            for line in lines.take_while(|line| !line.trim().is_empty()) {
                let trimmed = line.trim_start();
                if trimmed.starts_with('-') && line.len() - trimmed.len() <= 6 {
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
        for leaf in ["backup", "restore"] {
            let (t, r) = (help(&ts, &[leaf]), help(&rust(), &[leaf]));
            let rust_options = options(&r);
            for (flag, description) in options(&t) {
                if matches!(flag.as_str(), "--help" | "--output") {
                    continue;
                }
                let expected = if (leaf, flag.as_str()) == ("backup", "--file-format") {
                    "Backup file format: json (default: \"json\")".to_owned()
                } else {
                    description
                };
                let found = rust_options
                    .iter()
                    .find(|(f, _)| *f == flag)
                    .map(|(_, d)| d.clone());
                assert_eq!(found.as_deref(), Some(expected.as_str()), "{leaf} {flag}");
            }
            let about = |text: &str, first: bool| {
                let block = if first {
                    text.split("\n\n").next()
                } else {
                    text.split("\n\n").nth(1)
                };
                block.map(squash).unwrap_or_default()
            };
            assert_eq!(about(&r, true), about(&t, false), "{leaf} description");
            let examples = |text: &str| -> Vec<String> {
                text.lines()
                    .skip_while(|line| *line != "Examples:")
                    .skip(1)
                    .take_while(|line| !line.trim().is_empty())
                    .map(normalise_program)
                    .collect()
            };
            let mut ts_examples = examples(&t);
            if leaf == "backup" {
                ts_examples[1] = ts_examples[1].replace(
                    " --file-format yaml --output-file ./production.yaml",
                    " --output-file ./production.json",
                );
            }
            assert_eq!(examples(&r), ts_examples, "{leaf}");
            assert!(!r.contains("yaml"), "{r}");
        }
        assert!(options(&help(&rust(), &["restore"])).contains(&(
            "--allow-other-tenant".to_owned(),
            "Restore a backup exported from another TSG into the selected tenant".to_owned()
        )));
        let commands = |text: &str| -> Vec<String> {
            text.lines()
                .skip_while(|line| *line != "Commands:")
                .skip(1)
                .take_while(|line| !line.trim().is_empty())
                .filter(|line| line.len() - line.trim_start().len() <= 4)
                .map(|line| {
                    line.split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .split('|')
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                })
                .filter(|name| name != "help")
                .collect()
        };
        assert_eq!(
            commands(&help(&rust(), &[])),
            commands(&help(&ts, &[])),
            "the group listing"
        );
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D226: a destination that names no file (`b.json/`) is refused before the tenant
    /// with no request; TypeScript drops the trailing `/` (`resolve`) and writes `b.json`.
    #[test]
    fn d226_a_destination_that_names_no_file_is_refused_first() {
        let Some(ts) = require_ts("d226_a_destination_that_names_no_file_is_refused_first") else {
            return;
        };
        let seed: Seed = |server| {
            server.set_profiles(SOURCE, vec![production()]);
            server.set_topics(SOURCE, vec![topic()]);
        };
        let args = ["backup", "--output-file", "@b.json/"];
        let r = exec(&rust(), SOURCE, seed, &[], &args);
        let t = exec(&ts, SOURCE, seed, &[], &args);
        r.run.assert_code(1);
        assert!(
            r.run.stderr.contains(&format!(
                "Cannot write {}/; check that its directory exists and is writable",
                r.tmp("b.json")
            )),
            "{}",
            r.run.stderr
        );
        assert!(r.requests.is_empty());
        assert!(!std::path::Path::new(&r.tmp("b.json")).exists());
        t.run.assert_success();
        assert!(!t.requests.is_empty(), "TS reads the inventories");
        assert!(
            std::path::Path::new(&t.tmp("b.json")).is_file(),
            "TS writes b.json"
        );
    }

    /// D215: the Rust format (TS: its envelope), `--file-format yaml` refused (TS writes
    /// YAML), the destination checked before any request (TS reads first), no fabricated
    /// `examples: []` (TS stores one).
    #[test]
    fn d215_the_backup_is_the_rust_format_checked_before_any_request() {
        let Some(ts) = require_ts("d215_the_backup_is_the_rust_format_checked_before_any_request")
        else {
            return;
        };
        let bare: Seed = |server| {
            let mut topic = topic();
            topic.as_object_mut().unwrap().remove("examples");
            server.set_profiles(SOURCE, vec![production()]);
            server.set_topics(SOURCE, vec![topic]);
        };
        let args = ["backup", "--output-file", "@b.json"];
        let r = exec(&rust(), SOURCE, bare, &[], &args);
        let t = exec(&ts, SOURCE, bare, &[], &args);
        r.run.assert_success();
        t.run.assert_success();
        let rust_file: Value =
            serde_json::from_str(&std::fs::read_to_string(r.tmp("b.json")).unwrap()).unwrap();
        let ts_file: Value =
            serde_json::from_str(&std::fs::read_to_string(t.tmp("b.json")).unwrap()).unwrap();
        assert_eq!(rust_file["format"], "airs-cli-rs.runtime-profiles");
        assert_eq!(ts_file["resourceType"], "runtime-security-profiles");
        assert!(rust_file["topics"][0]["record"].get("examples").is_none());
        assert_eq!(
            ts_file["topics"][0]["examples"],
            json!([]),
            "TS invents examples (G27)"
        );
        // yaml
        let args = [
            "backup",
            "--file-format",
            "yaml",
            "--output-file",
            "@b.yaml",
        ];
        let r = exec(&rust(), SOURCE, standard, &[], &args);
        let t = exec(&ts, SOURCE, standard, &[], &args);
        r.run.assert_code(2);
        assert!(
            r.run
                .stderr
                .contains("--file-format must be json (yaml was dropped)")
        );
        t.run.assert_success();
        // An existing file: refused before the tenant (TS after every read).
        let files = [("b.json", "keep")];
        let args = ["backup", "--output-file", "@b.json"];
        let r = exec(&rust(), SOURCE, standard, &files, &args);
        let t = exec(&ts, SOURCE, standard, &files, &args);
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert!(r.requests.is_empty());
        assert!(!t.api().is_empty(), "TS reads before it finds the file");
        assert!(
            r.run
                .stderr
                .contains("already exists; choose another --output-file")
        );
        assert_eq!(std::fs::read_to_string(r.tmp("b.json")).unwrap(), "keep");
        assert_eq!(std::fs::read_to_string(t.tmp("b.json")).unwrap(), "keep");
    }

    /// D216: a TypeScript backup is refused (TS restores it); another TSG needs
    /// `--allow-other-tenant` (TS: no flag); `--dry-run --force` is a usage error (TS
    /// accepts it); an `--expect-tsg` mismatch exits 1 (TS 2); the non-interactive
    /// refusal comes before the file and any request (TS after the plan's reads).
    #[test]
    fn d216_restore_refuses_typescript_backups_and_other_tsgs() {
        let Some(ts) = require_ts("d216_restore_refuses_typescript_backups_and_other_tsgs") else {
            return;
        };
        let backup = rust_backup(standard);
        let envelope = ts_envelope(&backup);
        let files = [("ts.json", envelope.as_str())];
        let args = ["restore", "@ts.json", "--dry-run"];
        let empty: Seed = |_| {};
        let r = exec(&rust(), DEST, empty, &files, &args);
        let t = exec(&ts, DEST, empty, &files, &args);
        r.run.assert_code(1);
        assert!(
            r.run
                .stderr
                .contains("is a TypeScript airs-cli backup; airs cannot restore it.")
        );
        assert!(r.requests.is_empty());
        t.run.assert_success();
        // Another TSG without the flag.
        let (r, t) = restore_pair(&ts, &backup, DEST, &["--dry-run"], &[], |_| {});
        r.run.assert_code(1);
        assert!(r.run.stderr.contains("was exported from TSG 100; the selected tenant uses TSG 200. Pass --allow-other-tenant to restore it here."));
        assert!(r.requests.is_empty());
        t.run.assert_success();
        // --dry-run --force.
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &["--dry-run", "--force", "--expect-tsg", DEST],
            &["--allow-other-tenant"],
            |_| {},
        );
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --dry-run cannot be combined with --force\n\n"
        );
        t.run.assert_success();
        // --expect-tsg mismatch.
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &["--expect-tsg", "300", "--force"],
            &["--allow-other-tenant"],
            |_| {},
        );
        r.run.assert_code(1);
        t.run.assert_code(2);
        let message =
            "--expect-tsg does not match the selected destination tenant; no API request was made";
        assert!(r.run.stderr.contains(message) && t.run.stderr.contains(message));
        assert!(r.requests.is_empty() && t.api().is_empty());
        // Non-interactive without --force.
        let (r, t) = restore_pair(&ts, &backup, DEST, &[], &["--allow-other-tenant"], |_| {});
        r.run.assert_code(2);
        t.run.assert_code(2);
        assert!(
            r.run
                .stderr
                .contains("refusing to restore profiles without --force in non-interactive mode")
        );
        assert!(
            t.run.stderr.contains(
                "refusing to restore profiles into TSG 200 without --force in non-interactive mode"
            ),
            "{}",
            t.run.stderr
        );
        assert!(r.requests.is_empty());
        assert!(!t.api().is_empty(), "TS refuses after the plan's reads");
        let missing = exec(&rust(), DEST, empty, &[], &["restore", "@absent.json"]);
        missing.run.assert_code(2);
        assert!(
            missing.run.stderr.contains("refusing to restore profiles"),
            "before the file"
        );
    }

    /// D217: one attempt per write: a 403 on the profile create is sent once (TS twice);
    /// a 503 is an outcome-unknown stop naming the profile (TS: only the status).
    #[test]
    fn d217_restore_writes_are_one_attempt() {
        let Some(ts) = require_ts("d217_restore_writes_are_one_attempt") else {
            return;
        };
        let backup =
            rust_backup(|server: &FixtureServer| server.set_profiles(SOURCE, vec![staging()]));
        let forbidden: fn(&FixtureServer) =
            |server| server.set_default(Route::ProfileCreate, Planned::json(403, &json!({})));
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &FORCE,
            &["--allow-other-tenant"],
            forbidden,
        );
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert_eq!(r.server.route_count(Route::ProfileCreate), 1);
        assert_eq!(
            t.server.route_count(Route::ProfileCreate),
            2,
            "TS replays a POST after a 403"
        );
        let unavailable: fn(&FixtureServer) = |server| {
            server.set_default(
                Route::ProfileCreate,
                Planned::json(503, &json!({})).with_retry_after(0),
            );
        };
        let mut args = FORCE.to_vec();
        args.extend(["--output", "json"]);
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &args,
            &["--allow-other-tenant"],
            unavailable,
        );
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert_eq!(r.server.route_count(Route::ProfileCreate), 1);
        assert_eq!(
            r.run.json()[0]["outcomeUnknown"],
            json!({"kind": "profile", "name": "Staging", "action": "create"})
        );
        assert_eq!(
            r.run.json()[0]["error"],
            "Outcome unknown: the security profile Staging may have been created; run the restore again with --on-conflict verify to check it"
        );
        assert_eq!(
            t.run.json()[0]["error"],
            "API request failed (HTTP 503); verify destination state before retrying"
        );
        // A topic created whose answer does not verify: TS lists no topic row, so nothing
        // says it exists; airs-cli-rs keeps its `created` row (choice 68).
        let backup = rust_backup(|server: &FixtureServer| {
            server.set_profiles(SOURCE, vec![production()]);
            server.set_topics(SOURCE, vec![topic()]);
        });
        let normalised: fn(&FixtureServer) = |server| {
            let answer = fixtures::topic(77, "Restricted", 1, "normalised by the service");
            server.set_default(Route::TopicCreate, Planned::json(200, &answer));
        };
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &args,
            &["--allow-other-tenant"],
            normalised,
        );
        r.run.assert_code(1);
        t.run.assert_code(1);
        let error = "Topic response did not verify: Restricted";
        assert_eq!(r.run.json()[0]["error"], error);
        assert_eq!(t.run.json()[0]["error"], error);
        assert_eq!(
            r.run.json()[0]["topics"],
            json!([{"name": "Restricted", "id": fixtures::uuid(77), "action": "created"}])
        );
        assert_eq!(t.run.json()[0]["topics"], json!([]), "TS names nothing");
    }

    /// D218: an absent destination profile collection is refused (TS plans creates over
    /// existing profiles); an absent source collection fails the backup (TS: no
    /// matching profiles).
    #[test]
    fn d218_absent_collections_are_refused() {
        let Some(ts) = require_ts("d218_absent_collections_are_refused") else {
            return;
        };
        let backup = rust_backup(standard);
        let absent: fn(&FixtureServer) = |server| {
            let mut existing = production();
            existing["tsg_id"] = json!(DEST);
            server.set_profiles(DEST, vec![existing]);
            server.set_default(Route::Profiles, Planned::json(200, &json!({})));
        };
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &["--dry-run", "--output", "json"],
            &["--allow-other-tenant"],
            absent,
        );
        r.run.assert_code(1);
        assert!(r.run.stderr.contains(
            "Destination inventory of security profiles was not returned; nothing was changed"
        ));
        t.run.assert_success();
        assert_eq!(
            t.run.json()[0]["profiles"][0],
            json!({"name": "Production", "action": "create"}),
            "TS plans a duplicate"
        );
        let edit: fn(&FixtureServer) =
            |server| server.set_default(Route::Profiles, Planned::json(200, &json!({})));
        let r = exec_with(
            &rust(),
            SOURCE,
            standard,
            &[],
            &["backup", "--output-file", "@b.json"],
            edit,
        );
        let t = exec_with(
            &ts,
            SOURCE,
            standard,
            &[],
            &["backup", "--output-file", "@b.json"],
            edit,
        );
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert!(
            r.run
                .stderr
                .contains("Inventory of security profiles was not returned; retry the operation")
        );
        assert!(
            t.run.stderr.contains("No matching profiles to back up"),
            "{}",
            t.run.stderr
        );
    }

    /// D50: yaml, markdown and csv are usage errors on both transfer commands (TS renders
    /// them).
    #[test]
    fn d50_dropped_formats_are_usage_errors_on_profile_transfer() {
        let Some(ts) = require_ts("d50_dropped_formats_are_usage_errors_on_profile_transfer")
        else {
            return;
        };
        for format in ["yaml", "markdown", "csv"] {
            let args = ["backup", "--output-file", "@b.json", "--output", format];
            let r = exec(&rust(), SOURCE, standard, &[], &args);
            let t = exec(&ts, SOURCE, standard, &[], &args);
            r.run.assert_code(2);
            assert!(r.run.stderr.contains(&format!(
                "Invalid output format '{format}'. Expected: pretty, table, json"
            )));
            assert!(r.requests.is_empty());
            t.run.assert_success();
        }
    }

    /// D156 (extended): `--debug` is refused by both transfer commands before any log; TS
    /// refuses it too, naming `PANW_AI_SEC_DEBUG`.
    #[test]
    fn d156_profile_transfer_refuses_debug() {
        let Some(ts) = require_ts("d156_profile_transfer_refuses_debug") else {
            return;
        };
        for leaf in [&["backup"][..], &["restore", "x.json", "--dry-run"]] {
            let mut args = vec!["--debug", "runtime", "profiles"];
            args.extend_from_slice(leaf);
            let sandbox = Sandbox::new();
            let r = run(&rust(), &sandbox, &args, &RunOptions::new());
            let t = run(&ts, &sandbox, &args, &RunOptions::new());
            r.assert_code(2);
            t.assert_code(2);
            assert_eq!(
                r.stderr,
                "\n  ✗ Disable --debug for profile transfer; backups can contain sensitive policy configuration\n\n"
            );
            assert!(t.stderr.contains("Disable --debug"), "{}", t.stderr);
            assert!(!sandbox.home().join(".local/state/airs-cli/debug").exists());
        }
    }

    /// D73 (extended): the DLP mapping hint names `airs` (TS `airs-cli`).
    #[test]
    fn d73_the_dlp_mapping_hint_names_airs() {
        let Some(ts) = require_ts("d73_the_dlp_mapping_hint_names_airs") else {
            return;
        };
        let backup = rust_backup(dlp);
        let (r, t) = restore_pair(
            &ts,
            &backup,
            DEST,
            &["--dry-run"],
            &["--allow-other-tenant"],
            |_| {},
        );
        r.run.assert_code(1);
        t.run.assert_code(1);
        let hint = |program: &str| {
            format!(
                "Inspect destination resources with {program} runtime dlp profiles list --all --output json"
            )
        };
        assert!(r.run.stderr.contains(&hint("airs")), "{}", r.run.stderr);
        assert!(t.run.stderr.contains(&hint("airs-cli")) && !t.run.stderr.contains(&hint("airs")));
    }

    /// D224: an interrupted restore names its writes (TS exits by the signal with nothing
    /// printed).
    #[test]
    fn d224_an_interrupted_restore_prints_its_context() {
        let Some(ts) = require_ts("d224_an_interrupted_restore_prints_its_context") else {
            return;
        };
        let backup = rust_backup(standard);
        let envelope = ts_envelope(&backup);
        for (cli, text, extra) in [
            (rust(), backup.as_str(), &["--allow-other-tenant"][..]),
            (ts.clone(), envelope.as_str(), &[][..]),
        ] {
            let (server, sandbox) = world(DEST, |_| {}, &[("b.json", text)]);
            server.push_once(Route::ProfileCreate, Planned::held());
            let file = sandbox.tmp().join("b.json").display().to_string();
            let mut args = vec![
                "runtime",
                "profiles",
                "restore",
                file.as_str(),
                "--expect-tsg",
                DEST,
                "--force",
            ];
            args.extend_from_slice(extra);
            let running =
                airs_test_harness::spawn(&cli, &sandbox, &args, &RunOptions::new().expect_signal());
            assert!(server.wait_for_route(Route::ProfileCreate, 1, Duration::from_secs(30)));
            running.send_signal("INT");
            let out = running.wait();
            server.release_held();
            if cli.is_ts() {
                assert!(!out.stderr.contains("Interrupted"), "{}", out.stderr);
            } else {
                out.assert_code(130);
                assert!(out.stderr.contains("Interrupted; 1 topic(s) and 0 profile(s) written; the security profile Production may also have been created (outcome unknown)"), "{}", out.stderr);
            }
        }
    }
}
