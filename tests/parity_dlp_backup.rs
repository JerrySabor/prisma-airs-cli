//! TS-vs-Rust parity for the M6b step-3 DLP backup and restore (DESIGN §16.10, §16.11).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh [`FixtureServer`] seeded with the same DLP dataset and a
//! fresh [`Sandbox`]. The two CLIs write different backup formats (D175), so backups are
//! compared by their summaries, counts and name sets, and a restore is given the same
//! records in each CLI's own format. TypeScript prints its progress lines on stdout and
//! airs-cli-rs on stderr (D172), so pretty stdout is compared without them. `divergence`
//! tests pin both sides of each §12 row this step implements (named by its D#).

use std::time::Duration;

use airs_test_harness::{
    Cli, Collection, Dl, DlpData, FixtureServer, Planned, RecordedRequest, Route, Run, RunOptions,
    Sandbox, multipart, require_ts, run, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

type Seed = fn(&mut DlpData);

/// The seeded dataset without its unsupported profile and unexported pattern.
fn clean(data: &mut DlpData) {
    data.profiles
        .retain(|profile| profile["id"] != "dp-multi-1");
    data.patterns.retain(|pattern| pattern["id"] != "p-par-1");
}

fn unchanged(_: &mut DlpData) {}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    server: FixtureServer,
    sandbox: Sandbox,
}

impl Side {
    /// The API requests (token requests left out).
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
}

/// A fresh server seeded with `seed` and a tenant `prod` of TSG `tsg`; `files` land
/// under `tmp/`.
fn world(tsg: &str, seed: Seed, files: &[(&str, &[u8])]) -> (FixtureServer, Sandbox) {
    let server = FixtureServer::start();
    server.seed_dlp();
    server.dlp(seed);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", tsg);
    for (name, bytes) in files {
        std::fs::write(sandbox.tmp().join(name), bytes).unwrap();
    }
    (server, sandbox)
}

/// Runs `runtime dlp <args>` (`@name` is the absolute path of `tmp/<name>`).
fn exec_in(
    cli: &Cli,
    server: FixtureServer,
    sandbox: Sandbox,
    args: &[&str],
    options: &RunOptions,
) -> Side {
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
    Side {
        run: out,
        requests,
        server,
        sandbox,
    }
}

fn exec(cli: &Cli, tsg: &str, seed: Seed, files: &[(&str, &[u8])], args: &[&str]) -> Side {
    let (server, sandbox) = world(tsg, seed, files);
    exec_in(cli, server, sandbox, args, &RunOptions::new())
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// A Rust backup of the `seed` dataset (TSG 100); the file's JSON.
fn rust_backup(seed: Seed, extra: &[&str]) -> Value {
    let mut args = vec!["backup", "--output-file", "@b.json"];
    args.extend_from_slice(extra);
    let side = exec(&rust(), TSG, seed, &[], &args);
    side.run.assert_success();
    let text = std::fs::read_to_string(side.sandbox.tmp().join("b.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The same records in the TypeScript envelope (`version`, `resourceType`, `source`).
fn ts_envelope(rust: &Value) -> Value {
    let records = |key: &str| -> Vec<Value> {
        rust[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["record"].clone())
            .collect()
    };
    json!({"version": 1, "resourceType": "dlp-resources", "exportedAt": rust["exportedAt"],
        "source": {"tsgId": rust["tsgId"]}, "dictionaries": records("dictionaries"),
        "patterns": records("patterns"), "profiles": records("profiles")})
}

/// Both CLIs restore the same records: airs-cli-rs from its file, TypeScript from its
/// envelope; `rust_extra` are the Rust-only arguments (`--allow-other-tenant`).
fn restore_pair(
    name: &str,
    backup: &Value,
    tsg: &str,
    seed: Seed,
    args: &[&str],
    rust_extra: &[&str],
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    let rust_file = backup.to_string();
    let ts_file = ts_envelope(backup).to_string();
    let mut rust_args = vec!["restore", "@b.json"];
    rust_args.extend_from_slice(args);
    rust_args.extend_from_slice(rust_extra);
    let mut ts_args = vec!["restore", "@b.json"];
    ts_args.extend_from_slice(args);
    Some((
        exec(
            &rust(),
            tsg,
            seed,
            &[("b.json", rust_file.as_bytes())],
            &rust_args,
        ),
        exec(&ts, tsg, seed, &[("b.json", ts_file.as_bytes())], &ts_args),
    ))
}

/// A destination of another TSG and DLP tenant holding only predefined records.
fn destination(data: &mut DlpData) {
    clean(data);
    data.dictionaries
        .retain(|record| record["type"] == "predefined");
    data.patterns
        .retain(|record| record["type"] == "predefined");
    data.profiles.clear();
    for record in data.patterns.iter_mut() {
        record["tenant_id"] = json!("dlp-tenant-200");
    }
    data.created_tenant_id = Some("dlp-tenant-200".to_owned());
}

/// `clean`, with `My Profile` also referencing the predefined pattern and dictionary.
fn rich(data: &mut DlpData) {
    clean(data);
    let profile = data
        .profiles
        .iter_mut()
        .find(|profile| profile["id"] == "dp-cus-1")
        .unwrap();
    let leaves = profile["detection_rules"][0]["expression_tree"]["sub_expressions"]
        .as_array_mut()
        .unwrap();
    for (technique, id, name, version) in [
        ("regex", "p-pre-1", "Credit Card Number", Some(2)),
        ("dictionary", "d-pre-1", "Predef Dict", None),
        ("dictionary", "d-cus-1", "My Dict", None),
    ] {
        let mut item = json!({"detection_technique": technique, "id": id, "name": name,
            "match_type": "include", "confidence_level": "high", "occurrence_count": 1,
            "occurrence_operator_type": "any"});
        if let Some(version) = version {
            item["version"] = json!(version);
        }
        leaves.push(json!({"rule_item": item}));
    }
}

/// TypeScript's pretty stdout without its progress and bullet lines (D172).
fn without_progress(stdout: &str) -> String {
    stdout
        .split_inclusive('\n')
        .filter(|line| {
            !["  ℹ ", "  ✓ ", "  ○ "]
                .iter()
                .any(|prefix| line.starts_with(prefix))
        })
        .collect()
}

/// A write's comparable shape: method, path, query, content type, JSON body or the
/// multipart parts (metadata JSON and file hash).
fn shape(request: &RecordedRequest) -> Value {
    let body = match multipart(request) {
        Some(parts) => Value::Array(
            parts
                .parts
                .iter()
                .map(|part| {
                    json!({"name": part.name, "filename": part.filename, "contentType": part.content_type,
                        "json": part.json, "sha256": if part.json.is_some() { Value::Null } else { json!(part.sha256) }})
                })
                .collect(),
        ),
        None => request.body_json().unwrap_or(Value::Null),
    };
    json!({"method": request.method, "path": request.path, "query": request.query,
        "body": airs_test_harness::js_normalize(&body)})
}

/// The cells of a box table (`" a │ b "` rows), header and data rows, trimmed.
fn cells(table: &str) -> Vec<Vec<String>> {
    table
        .lines()
        .filter(|line| line.contains('│'))
        .map(|line| line.split('│').map(|cell| cell.trim().to_owned()).collect())
        .collect()
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The backup summary: TypeScript's columns and counts (airs-cli-rs adds `Failed`,
    /// and in json `failed` and `complete`, D175); the skipped-profile warning on stderr
    /// on both; the two files hold the same number of entries with the same names.
    #[test]
    fn backup_summaries_and_contents_match_typescript() {
        let Some(ts) = require_ts("backup_summaries_and_contents_match_typescript") else {
            return;
        };
        for format in ["table", "json", "pretty"] {
            let args = [
                "backup",
                "--skip-unsupported",
                "--output-file",
                "@b.json",
                "--output",
                format,
            ];
            let r = exec(&rust(), TSG, unchanged, &[], &args);
            let t = exec(&ts, TSG, unchanged, &[], &args);
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            let warning = "  ⚠ Skipped unsupported data profile: Multi Profile (Unsupported detection rule type: multi_profile)\n";
            assert!(r.run.stderr.contains(warning) && t.run.stderr.contains(warning));
            let path = r.sandbox.tmp().join("b.json").display().to_string();
            let ts_path = t.sandbox.tmp().join("b.json").display().to_string();
            match format {
                "json" => {
                    let mut rust_doc: Value = serde_json::from_str(&r.run.stdout).unwrap();
                    let ts_doc: Value = serde_json::from_str(&t.run.stdout).unwrap();
                    assert_eq!(rust_doc[0]["failed"], 0);
                    assert_eq!(rust_doc[0]["complete"], false);
                    let object = rust_doc[0].as_object_mut().unwrap();
                    object.remove("failed");
                    object.remove("complete");
                    object.insert("file".to_owned(), json!("<file>"));
                    let mut ts_doc = ts_doc;
                    ts_doc[0]["file"] = json!("<file>");
                    assert_eq!(rust_doc, ts_doc, "{}", context(&r, &t));
                }
                _ => {
                    let stdout = if format == "pretty" {
                        without_progress(&t.run.stdout)
                    } else {
                        t.run.stdout.clone()
                    };
                    let mut rust_cells = cells(&r.run.stdout);
                    let mut ts_cells = cells(&stdout);
                    for row in rust_cells.iter_mut() {
                        assert!(matches!(row.pop().as_deref(), Some("Failed" | "0")));
                    }
                    rust_cells[1][0] = path.replace(&path, "<file>");
                    ts_cells[1][0] = ts_path.replace(&ts_path, "<file>");
                    assert_eq!(rust_cells, ts_cells, "{}", context(&r, &t));
                }
            }
            // Counts and names of the two files (the formats differ, D175).
            let rust_file: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let ts_file: Value =
                serde_json::from_str(&std::fs::read_to_string(&ts_path).unwrap()).unwrap();
            for key in ["dictionaries", "patterns", "profiles"] {
                let names = |list: &Value, field: Option<&str>| -> Vec<String> {
                    list.as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let record = field.map_or(item, |field| &item[field]);
                            record["name"].as_str().unwrap().to_owned()
                        })
                        .collect()
                };
                assert_eq!(
                    names(&rust_file[key], Some("record")),
                    names(&ts_file[key], None),
                    "{key}"
                );
                for (rust_entry, ts_record) in rust_file[key]
                    .as_array()
                    .unwrap()
                    .iter()
                    .zip(ts_file[key].as_array().unwrap())
                {
                    assert!(
                        airs_test_harness::json_semantic_eq(&rust_entry["record"], ts_record),
                        "{key}: the stored records are equal"
                    );
                }
            }
        }
    }

    /// The restore preview: the same plan in every layout (TypeScript's progress line
    /// moved to stderr, D172).
    #[test]
    fn restore_previews_match_typescript() {
        let backup = rust_backup(rich, &[]);
        for format in ["pretty", "table", "json"] {
            let Some((r, t)) = restore_pair(
                "restore_previews_match_typescript",
                &backup,
                "200",
                destination,
                &[
                    "--dry-run",
                    "--name-prefix",
                    "migrated-",
                    "--output",
                    format,
                ],
                &["--allow-other-tenant"],
            ) else {
                return;
            };
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            let ts_stdout = without_progress(&t.run.stdout);
            if format == "json" {
                let rust_doc: Value = serde_json::from_str(&r.run.stdout).unwrap();
                let ts_doc: Value = serde_json::from_str(&ts_stdout).unwrap();
                assert_eq!(rust_doc, ts_doc, "{}", context(&r, &t));
            } else {
                assert_eq!(r.run.stdout, ts_stdout, "{}", context(&r, &t));
            }
            assert_eq!(
                r.api(),
                t.api()
                    .iter()
                    .map(|line| line.replace("&keywords=true", ""))
                    .collect::<Vec<_>>()
            );
            assert!(r.writes().is_empty() && t.writes().is_empty());
        }
    }

    /// The restore itself: the same creates (JSON bodies and multipart parts), the same
    /// result (airs-cli-rs adds `outcomeUnknown` and `notAttempted`, D177).
    #[test]
    fn restore_results_and_writes_match_typescript() {
        let backup = rust_backup(rich, &[]);
        for format in ["table", "json"] {
            let Some((r, t)) = restore_pair(
                "restore_results_and_writes_match_typescript",
                &backup,
                "200",
                destination,
                &[
                    "--expect-tsg",
                    "200",
                    "--force",
                    "--name-prefix",
                    "migrated-",
                    "--output",
                    format,
                ],
                &["--allow-other-tenant"],
            ) else {
                return;
            };
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            let rust_writes: Vec<Value> = r.writes().into_iter().map(shape).collect();
            let ts_writes: Vec<Value> = t.writes().into_iter().map(shape).collect();
            assert_eq!(rust_writes, ts_writes, "{}", context(&r, &t));
            assert_eq!(rust_writes.len(), 3);
            if format == "json" {
                let mut rust_doc: Value = serde_json::from_str(&r.run.stdout).unwrap();
                let ts_doc: Value = serde_json::from_str(&t.run.stdout).unwrap();
                let object = rust_doc[0].as_object_mut().unwrap();
                assert_eq!(object.remove("outcomeUnknown"), Some(Value::Null));
                assert_eq!(object.remove("notAttempted"), Some(json!([])));
                assert_eq!(rust_doc, ts_doc, "{}", context(&r, &t));
            } else {
                assert_eq!(r.run.stdout, t.run.stdout, "{}", context(&r, &t));
            }
        }
    }

    /// The plan refusals and the stop texts are TypeScript's (the error block differs:
    /// TS `ui.error` prints `  ✗ <text>`, airs-cli-rs the §6 block).
    #[test]
    fn restore_refusals_match_typescript() {
        let backup = rust_backup(clean, &[]);
        let message = |stderr: &str| -> String {
            stderr
                .lines()
                .find_map(|line| line.trim().strip_prefix("✗ "))
                .map(|text| text.strip_prefix("Error: ").unwrap_or(text).to_owned())
                .unwrap_or_default()
        };
        let cases: [(Seed, &[&str]); 3] = [
            (clean, &["--dry-run"]),
            (
                |data| {
                    clean(data);
                    data.patterns[3]["description"] = json!("changed");
                },
                &["--dry-run", "--on-conflict", "skip"],
            ),
            (
                clean,
                &[
                    "--dry-run",
                    "--on-conflict",
                    "verify",
                    "--name-prefix",
                    "x",
                    "--pattern-map",
                    "Ghost=y",
                ],
            ),
        ];
        for (seed, args) in cases {
            let Some((r, t)) = restore_pair(
                "restore_refusals_match_typescript",
                &backup,
                TSG,
                seed,
                args,
                &[],
            ) else {
                return;
            };
            assert_eq!(r.run.code, 1, "{}", context(&r, &t));
            assert_eq!(t.run.code, 1, "{}", context(&r, &t));
            assert_eq!(
                message(&r.run.stderr),
                message(&t.run.stderr),
                "{}",
                context(&r, &t)
            );
            assert!(!message(&r.run.stderr).is_empty());
        }
    }

    /// The shared usage errors: the same text and exit 2 on both, nothing sent.
    #[test]
    fn shared_usage_errors_match_typescript() {
        let Some(ts) = require_ts("shared_usage_errors_match_typescript") else {
            return;
        };
        for args in [
            &["restore", "@b.json", "--on-conflict", "update"][..],
            &["restore", "@b.json", "--force"],
            &["restore", "@b.json", "--pattern-map", "=x"],
            &[
                "restore",
                "@b.json",
                "--pattern-map",
                "a=b",
                "--pattern-map",
                "a=c",
            ],
            &["restore", "@b.json", "--max-pages", "0"],
            &["backup", "--max-pages", "1001"],
            &["backup", "--output-file", "-"],
            &["backup", "--output-file", "@b.txt"],
        ] {
            let r = exec(&rust(), TSG, unchanged, &[], args);
            let t = exec(&ts, TSG, unchanged, &[], args);
            assert_eq!(r.run.code, 2, "{args:?}{}", context(&r, &t));
            assert_eq!(t.run.code, 2, "{args:?}{}", context(&r, &t));
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}{}", context(&r, &t));
            assert!(r.api().is_empty() && t.api().is_empty(), "{args:?}");
        }
    }

    /// The help of both leaves (§16.2: the Rust `--file-format`, `--output-file` and
    /// `--allow-other-tenant` texts).
    #[test]
    fn backup_and_restore_help_match_typescript() {
        let Some(ts) = require_ts("backup_and_restore_help_match_typescript") else {
            return;
        };
        let sandbox = Sandbox::new();
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
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
            let help = |cli: &Cli| {
                let out = run(
                    cli,
                    &sandbox,
                    &["runtime", "dlp", leaf, "--help"],
                    &RunOptions::new(),
                );
                out.assert_success();
                out.stdout
            };
            let (t, r) = (help(&ts), help(&rust()));
            let rust_options = options(&r);
            for (flag, description) in options(&t) {
                if matches!(flag.as_str(), "--help" | "--output") {
                    continue;
                }
                let expected = match (leaf, flag.as_str()) {
                    ("backup", "--file-format") => "Backup file format: json (default: \"json\")".to_owned(),
                    ("backup", "--output-file") => {
                        "New private backup file; defaults to the current directory; never overwrite".to_owned()
                    }
                    _ => description,
                };
                let found = rust_options
                    .iter()
                    .find(|(f, _)| *f == flag)
                    .map(|(_, d)| d.clone());
                assert_eq!(found.as_deref(), Some(expected.as_str()), "{leaf} {flag}");
            }
            if leaf == "restore" {
                assert!(rust_options.contains(&(
                    "--allow-other-tenant".to_owned(),
                    "Restore a backup exported from another TSG".to_owned()
                )));
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
            assert!(r.contains("Examples:\n  $ airs runtime dlp"), "{r}");
            assert!(!r.contains("yaml"), "{r}");
        }
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D175: the backup is the Rust format, refused before the tenant at an existing path
    /// (TS reads every inventory first, then fails `EEXIST`), records `skipped`, reads
    /// keywords per dictionary (TS: one keyword-bearing listing) and refuses
    /// `--file-format yaml` (TS writes YAML).
    #[test]
    fn d175_the_backup_is_the_rust_format_checked_before_any_request() {
        let Some(ts) = require_ts("d175_the_backup_is_the_rust_format_checked_before_any_request")
        else {
            return;
        };
        let files: &[(&str, &[u8])] = &[("taken.json", b"keep")];
        let args = ["backup", "--output-file", "@taken.json"];
        let r = exec(&rust(), TSG, clean, files, &args);
        let t = exec(&ts, TSG, clean, files, &args);
        r.run.assert_code(1);
        assert!(
            r.run
                .stderr
                .contains("already exists; choose another --output-file")
        );
        assert!(r.requests.is_empty(), "Rust: no token, no read");
        t.run.assert_code(1);
        assert_eq!(
            t.run.stderr,
            "  ✗ DLP transfer file operation failed (EEXIST); existing files are not overwritten.\n"
        );
        assert_eq!(t.api().len(), 3, "TS: every inventory read first");
        // The formats, `skipped` and the keyword reads.
        let args = ["backup", "--skip-unsupported", "--output-file", "@b.json"];
        let r = exec(&rust(), TSG, unchanged, &[], &args);
        let t = exec(&ts, TSG, unchanged, &[], &args);
        r.run.assert_success();
        t.run.assert_success();
        let read = |side: &Side| -> Value {
            serde_json::from_str(
                &std::fs::read_to_string(side.sandbox.tmp().join("b.json")).unwrap(),
            )
            .unwrap()
        };
        let (rust_file, ts_file) = (read(&r), read(&t));
        assert_eq!(rust_file["format"], "airs-cli-rs.dlp-resources");
        assert_eq!(rust_file["skipped"][0]["name"], "Multi Profile");
        assert_eq!(rust_file["complete"], false);
        assert_eq!(ts_file["resourceType"], "dlp-resources");
        assert!(ts_file.get("skipped").is_none(), "TS records no exclusion");
        assert!(
            r.api()
                .contains(&"GET /dlp/v2/api/dictionaries/d-cus-1?keywords=true".to_owned())
        );
        assert_eq!(
            r.api()[0],
            "GET /dlp/v2/api/dictionaries?page=0&size=100&sort=name%2Casc"
        );
        assert_eq!(
            t.api()[0],
            "GET /dlp/v2/api/dictionaries?page=0&size=100&sort=name%2Casc&keywords=true"
        );
        // YAML.
        let args = [
            "backup",
            "--file-format",
            "yaml",
            "--output-file",
            "@b.yaml",
        ];
        let r = exec(&rust(), TSG, clean, &[], &args);
        let t = exec(&ts, TSG, clean, &[], &args);
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --file-format must be json (yaml was dropped)\n\n"
        );
        t.run.assert_success();
        assert!(t.sandbox.tmp().join("b.yaml").exists());
    }

    /// D176: airs-cli-rs refuses a TypeScript backup (TS restores it) and needs
    /// `--allow-other-tenant` for another TSG's backup (TS restores across TSGs as is);
    /// `--dry-run --force` is a usage error (TS accepts it).
    #[test]
    fn d176_restore_refuses_typescript_backups_and_other_tsgs() {
        let Some(ts) = require_ts("d176_restore_refuses_typescript_backups_and_other_tsgs") else {
            return;
        };
        let backup = rust_backup(clean, &[]);
        let envelope = ts_envelope(&backup).to_string();
        let files: &[(&str, &[u8])] = &[("ts.json", envelope.as_bytes())];
        let args = ["restore", "@ts.json", "--dry-run", "--name-prefix", "c-"];
        let r = exec(&rust(), TSG, clean, files, &args);
        let t = exec(&ts, TSG, clean, files, &args);
        r.run.assert_code(1);
        assert!(
            r.run
                .stderr
                .contains("is a TypeScript airs-cli backup; airs cannot restore it.")
        );
        assert!(r.requests.is_empty());
        t.run.assert_success();
        // Another TSG.
        let Some((r, t)) = restore_pair(
            "d176_restore_refuses_typescript_backups_and_other_tsgs",
            &backup,
            "200",
            destination,
            &["--dry-run"],
            &[],
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert!(r.run.stderr.contains("was exported from TSG 100; the selected tenant uses TSG 200. Pass --allow-other-tenant to restore it here."));
        assert!(r.requests.is_empty());
        t.run.assert_success();
        // --dry-run --force.
        let Some((r, t)) = restore_pair(
            "d176_restore_refuses_typescript_backups_and_other_tsgs",
            &backup,
            TSG,
            clean,
            &[
                "--dry-run",
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
            ],
            &[],
        ) else {
            return;
        };
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --dry-run cannot be combined with --force\n\n"
        );
        t.run.assert_success();
    }

    /// D177 (with D160): a create is one attempt (a 403 is never replayed; TS replays it
    /// after a new token), an unknown outcome names the resource, and `reconcile` uses a
    /// deterministic suffix: a re-run verifies the copy where TS creates another one.
    #[test]
    fn d177_restore_creates_once_and_reconcile_never_duplicates() {
        let backup = rust_backup(clean, &[]);
        let Some((r, t)) = restore_pair(
            "d177_restore_creates_once_and_reconcile_never_duplicates",
            &backup,
            TSG,
            clean,
            &[
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
                "--output",
                "json",
            ],
            &[],
        ) else {
            return;
        };
        // (A plain run on both first, to prove the shapes agree.)
        r.run.assert_success();
        t.run.assert_success();
        let ts = require_ts("d177_restore_creates_once_and_reconcile_never_duplicates").unwrap();
        let forbid = |cli: &Cli, file: &[u8], planned: Planned| -> Side {
            let (server, sandbox) = world(TSG, clean, &[("b.json", file)]);
            server.push_once(Route::Dlp(Dl::Create(Collection::Patterns)), planned);
            exec_in(
                cli,
                server,
                sandbox,
                &[
                    "restore",
                    "@b.json",
                    "--force",
                    "--expect-tsg",
                    "100",
                    "--name-prefix",
                    "c-",
                    "--output",
                    "json",
                ],
                &RunOptions::new(),
            )
        };
        let rust_file = backup.to_string();
        let ts_file = ts_envelope(&backup).to_string();
        let r = forbid(&rust(), rust_file.as_bytes(), Planned::empty_json(403));
        let t = forbid(&ts, ts_file.as_bytes(), Planned::empty_json(403));
        r.run.assert_code(1);
        assert_eq!(
            r.server.dl_requests(Dl::Create(Collection::Patterns)).len(),
            1
        );
        t.run.assert_success();
        assert_eq!(
            t.server.dl_requests(Dl::Create(Collection::Patterns)).len(),
            2,
            "TS replays a 403"
        );
        let r = forbid(
            &rust(),
            rust_file.as_bytes(),
            Planned::json(503, &json!({"title": "busy"})),
        );
        let t = forbid(
            &ts,
            ts_file.as_bytes(),
            Planned::json(503, &json!({"title": "busy"})),
        );
        r.run.assert_code(1);
        t.run.assert_code(1);
        let rust_doc: Value = serde_json::from_str(&r.run.stdout).unwrap();
        let ts_doc: Value = serde_json::from_str(&t.run.stdout).unwrap();
        assert_eq!(
            rust_doc[0]["outcomeUnknown"],
            json!({"kind": "patterns", "name": "c-My Pattern"})
        );
        assert!(
            rust_doc[0]["error"].as_str().unwrap().starts_with(
                "Outcome unknown: the data pattern c-My Pattern may have been created"
            )
        );
        assert_eq!(
            ts_doc[0]["error"],
            "API request failed (HTTP 503); verify destination state before retrying"
        );
        assert!(ts_doc[0].get("outcomeUnknown").is_none());
        // Reconcile, twice, on a tenant that reserves the archived name.
        let reconcile = |cli: &Cli, file: &[u8]| -> FixtureServer {
            let (server, sandbox) = world(
                TSG,
                |data| {
                    clean(data);
                    data.reserved_profile_names = vec!["c-My Profile".to_owned()];
                },
                &[("b.json", file)],
            );
            let args: Vec<String> = [
                "runtime",
                "dlp",
                "restore",
                "",
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
                "--on-conflict",
                "reconcile",
            ]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect();
            let mut args = args;
            args[3] = sandbox.tmp().join("b.json").display().to_string();
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            for _ in 0..2 {
                run(cli, &sandbox, &args, &RunOptions::new()).assert_success();
            }
            server
        };
        let copies = |server: &FixtureServer| -> Vec<String> {
            server
                .dlp_data()
                .profiles
                .iter()
                .filter_map(|profile| profile["name"].as_str())
                .filter(|name| name.starts_with("c-My Profile-"))
                .map(str::to_owned)
                .collect()
        };
        let rust_server = reconcile(&rust(), rust_file.as_bytes());
        let ts_server = reconcile(&ts, ts_file.as_bytes());
        assert_eq!(
            copies(&rust_server).len(),
            1,
            "Rust: the re-run verifies its copy"
        );
        assert_eq!(copies(&ts_server).len(), 2, "TS: every re-run adds a copy");
    }

    /// D161: an `--expect-tsg` mismatch exits 1 in airs-cli-rs (TS: 2).
    #[test]
    fn d161_an_expect_tsg_mismatch_exits_1() {
        let backup = rust_backup(clean, &[]);
        let Some((r, t)) = restore_pair(
            "d161_an_expect_tsg_mismatch_exits_1",
            &backup,
            TSG,
            clean,
            &["--expect-tsg", "999", "--force", "--name-prefix", "c-"],
            &[],
        ) else {
            return;
        };
        let text =
            "--expect-tsg does not match the selected destination tenant; no API request was made";
        r.run.assert_code(1);
        assert_eq!(r.run.stderr, format!("\n  ✗ Error: {text}\n\n"));
        t.run.assert_code(2);
        assert_eq!(t.run.stderr, format!("\n  ✗ {text}\n\n"));
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// D162: `--resources` and `--name-prefix` errors are usage errors before the tenant
    /// (TS: a stack trace with exit 1, and a plan error with exit 1).
    #[test]
    fn d162_backup_and_restore_argument_errors_are_usage_errors() {
        let Some(ts) = require_ts("d162_backup_and_restore_argument_errors_are_usage_errors")
        else {
            return;
        };
        let args = ["backup", "--resources", "nope"];
        let r = exec(&rust(), TSG, clean, &[], &args);
        let t = exec(&ts, TSG, clean, &[], &args);
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --resources takes a unique list of dictionaries, patterns, profiles\n\n"
        );
        t.run.assert_code(1);
        assert!(
            t.run.stderr.contains("CliUsageError"),
            "TS crashes: {}",
            t.run.stderr
        );
        let backup = rust_backup(clean, &[]);
        let Some((r, t)) = restore_pair(
            "d162_backup_and_restore_argument_errors_are_usage_errors",
            &backup,
            TSG,
            clean,
            &["--dry-run", "--name-prefix", "a\tb"],
            &[],
        ) else {
            return;
        };
        r.run.assert_code(2);
        assert_eq!(r.run.stderr, "\n  ✗ Invalid --name-prefix\n\n");
        assert!(r.requests.is_empty());
        t.run.assert_code(1);
        assert_eq!(t.run.stderr, "  ✗ Invalid --name-prefix\n");
    }

    /// D164: the restore file is read with the input rules and decided by its content
    /// (TS refuses a name without `.json|.yaml|.yml` and a directory as usage errors).
    #[test]
    fn d164_the_restore_file_is_read_by_content() {
        let backup = rust_backup(clean, &[]);
        let Some(ts) = require_ts("d164_the_restore_file_is_read_by_content") else {
            return;
        };
        let rust_file = backup.to_string();
        let ts_file = ts_envelope(&backup).to_string();
        let r = exec(
            &rust(),
            TSG,
            clean,
            &[("b.txt", rust_file.as_bytes())],
            &["restore", "@b.txt", "--dry-run", "--name-prefix", "c-"],
        );
        let t = exec(
            &ts,
            TSG,
            clean,
            &[("b.txt", ts_file.as_bytes())],
            &["restore", "@b.txt", "--dry-run", "--name-prefix", "c-"],
        );
        r.run.assert_success();
        t.run.assert_code(2);
        assert_eq!(
            t.run.stderr,
            "\n  ✗ Backup file must use .json, .yaml or .yml\n\n"
        );
    }

    /// D167: without a terminal and without `--force` airs-cli-rs refuses before the
    /// tenant (TS refuses after reading the inventories, only when something is created).
    #[test]
    fn d167_a_non_interactive_restore_needs_force_up_front() {
        let backup = rust_backup(clean, &[]);
        let Some((r, t)) = restore_pair(
            "d167_a_non_interactive_restore_needs_force_up_front",
            &backup,
            TSG,
            clean,
            &["--name-prefix", "c-"],
            &[],
        ) else {
            return;
        };
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ refusing to restore DLP resources without --force in non-interactive mode\n\n"
        );
        assert!(r.requests.is_empty());
        t.run.assert_code(2);
        assert_eq!(
            t.run.stderr,
            "\n  ✗ refusing to restore DLP resources into TSG 100 without --force in non-interactive mode\n\n"
        );
        assert_eq!(t.api().len(), 3, "TS read the inventories first");
    }

    /// D172: the progress lines and bullets are on stderr and quiet-suppressed in
    /// airs-cli-rs (TS: stdout, pretty only, bullets even under `--quiet`).
    #[test]
    fn d172_restore_progress_is_on_stderr() {
        let backup = rust_backup(clean, &[]);
        let Some((r, t)) = restore_pair(
            "d172_restore_progress_is_on_stderr",
            &backup,
            TSG,
            clean,
            &["--force", "--expect-tsg", "100", "--name-prefix", "c-"],
            &[],
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let bullet = "  ✓ data pattern created: c-My Pattern (1/1)\n";
        assert!(r.run.stderr.contains(bullet) && !r.run.stdout.contains(bullet));
        assert!(t.run.stdout.contains(bullet) && !t.run.stderr.contains(bullet));
        assert_eq!(r.run.stdout, without_progress(&t.run.stdout));
        let ts = require_ts("d172_restore_progress_is_on_stderr").unwrap();
        let quiet_rust = {
            let (server, sandbox) = world(TSG, clean, &[("b.json", backup.to_string().as_bytes())]);
            let path = sandbox.tmp().join("b.json").display().to_string();
            let out = run(
                &rust(),
                &sandbox,
                &[
                    "--quiet",
                    "runtime",
                    "dlp",
                    "restore",
                    &path,
                    "--force",
                    "--expect-tsg",
                    "100",
                    "--name-prefix",
                    "c-",
                ],
                &RunOptions::new(),
            );
            drop(server);
            out
        };
        let quiet_ts = {
            let envelope = ts_envelope(&backup).to_string();
            let (server, sandbox) = world(TSG, clean, &[("b.json", envelope.as_bytes())]);
            let path = sandbox.tmp().join("b.json").display().to_string();
            let out = run(
                &ts,
                &sandbox,
                &[
                    "--quiet",
                    "runtime",
                    "dlp",
                    "restore",
                    &path,
                    "--force",
                    "--expect-tsg",
                    "100",
                    "--name-prefix",
                    "c-",
                ],
                &RunOptions::new(),
            );
            drop(server);
            out
        };
        quiet_rust.assert_success();
        quiet_ts.assert_success();
        assert_eq!(quiet_rust.stderr, "");
        assert!(
            quiet_ts.stdout.contains(bullet),
            "TS keeps its bullets under --quiet"
        );
    }

    /// D174: an interrupted backup prints its context (TS dies by the signal silently).
    #[test]
    fn d174_an_interrupted_backup_prints_its_context() {
        let Some(ts) = require_ts("d174_an_interrupted_backup_prints_its_context") else {
            return;
        };
        for cli in [rust(), ts] {
            let (server, sandbox) = world(TSG, clean, &[]);
            server.push_once(Route::Dlp(Dl::List(Collection::Patterns)), Planned::held());
            let path = sandbox.tmp().join("b.json").display().to_string();
            let running = spawn(
                &cli,
                &sandbox,
                &["runtime", "dlp", "backup", "--output-file", &path],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Dlp(Dl::List(Collection::Patterns)),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal("INT");
            let out = running.wait();
            server.release_held();
            out.assert_code(130);
            assert!(!std::path::Path::new(&path).exists());
            if cli.is_ts() {
                assert_eq!(out.stderr, "", "TS prints nothing");
            } else {
                assert!(
                    out.stderr
                        .ends_with("\n  ✗ Error: Interrupted; no backup file was written\n\n"),
                    "{}",
                    out.stderr
                );
            }
        }
    }

    /// D50 (0.7 extension): `markdown`, `csv` and `yaml` are usage errors on backup and
    /// restore (TS renders them).
    #[test]
    fn d50_dropped_formats_are_usage_errors_on_backup_and_restore() {
        let Some(ts) = require_ts("d50_dropped_formats_are_usage_errors_on_backup_and_restore")
        else {
            return;
        };
        for format in ["markdown", "csv", "yaml"] {
            let args = ["backup", "--output-file", "@b.json", "--output", format];
            let r = exec(&rust(), TSG, clean, &[], &args);
            let t = exec(&ts, TSG, clean, &[], &args);
            r.run.assert_code(2);
            assert_eq!(
                r.run.stderr,
                format!(
                    "\n  ✗ Invalid output format '{format}'. Expected: pretty, table, json\n\n"
                )
            );
            assert!(r.requests.is_empty());
            t.run.assert_success();
            assert!(!t.run.stdout.is_empty());
        }
    }

    /// D52 (0.7 extension): a server name with control characters is written raw by
    /// TypeScript and replaced by airs-cli-rs in the backup and restore messages.
    #[test]
    fn d52_names_in_backup_messages_are_terminal_safe() {
        let Some(ts) = require_ts("d52_names_in_backup_messages_are_terminal_safe") else {
            return;
        };
        let seed: Seed = |data| {
            for profile in data.profiles.iter_mut() {
                if profile["id"] == "dp-multi-1" {
                    profile["name"] = json!("Evil\u{1b}[31mMulti");
                }
            }
        };
        let args = ["backup", "--skip-unsupported", "--output-file", "@b.json"];
        let r = exec(&rust(), TSG, seed, &[], &args);
        let t = exec(&ts, TSG, seed, &[], &args);
        r.run.assert_success();
        t.run.assert_success();
        assert!(
            t.run
                .stderr
                .contains("Skipped unsupported data profile: Evil\u{1b}[31mMulti")
        );
        assert!(
            r.run
                .stderr
                .contains("Skipped unsupported data profile: Evil\u{fffd}[31mMulti")
        );
        assert!(!r.run.stderr.contains('\u{1b}'));
    }
}
