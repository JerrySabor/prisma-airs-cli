//! Executable acceptance tests for the M6b step-3 DLP backup and restore (DESIGN §16.10,
//! §16.11; D175–D177 and the backup and restore parts of D160–D174).
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server with the
//! seeded DLP dataset (whose write routes change it, so a restore's read-backs see its
//! creates). Records carry `FAKE-DLP-CONTENT-<nn>` markers; the runner's leak check
//! forbids every marker on stderr, the pty transcript and the debug log of each run, and
//! these tests assert that stdout never carries one either (§16.9). The behaviours of the
//! TypeScript `tests/unit/backup/dlp-resources.spec.ts` and
//! `tests/integration/dlp-transfer-contract.spec.ts` are ported here (the
//! `typescript_specs` module), adjusted by the §12 rows.

use std::time::Duration;

use airs_test_harness::fixtures::dlp as fx;
use airs_test_harness::{
    Cli, Collection, Dl, DlpData, FixtureServer, Planned, PtyRun, RecordedRequest, Route, Run,
    RunOptions, Sandbox, debug_log, multipart, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";

/// An edit of the seeded dataset.
type Edit = fn(&mut DlpData);

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn s(text: &str) -> String {
    text.to_owned()
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seeded dataset, edited by `edit`, and one tenant `prod` of TSG `tsg`.
fn fx_with(tsg: &str, edit: impl FnOnce(&mut DlpData)) -> Fx {
    let server = FixtureServer::start();
    server.seed_dlp();
    server.dlp(edit);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", tsg);
    Fx { server, sandbox }
}

/// The seeded DLP dataset and tenant `prod` (TSG 100).
fn fx() -> Fx {
    fx_with(TSG, |_| {})
}

/// A sandbox with no tenant at all: usage errors must not need one.
fn bare() -> Fx {
    Fx {
        server: FixtureServer::start(),
        sandbox: Sandbox::new(),
    }
}

/// The seeded dataset without its unsupported profile (`multi_profile`) and its
/// unexported pattern (`regexes: null`): every custom record round-trips.
fn clean(data: &mut DlpData) {
    data.profiles
        .retain(|profile| profile["id"] != "dp-multi-1");
    data.patterns.retain(|pattern| pattern["id"] != "p-par-1");
}

/// [`clean`], with `My Profile` also referencing the predefined pattern and both
/// dictionaries (a profile with every kind of dependency).
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
    let leaf = |technique: &str, id: &str, name: &str, version: Option<u64>| {
        let mut item = json!({"detection_technique": technique, "id": id, "name": name,
            "match_type": "include", "confidence_level": "high", "occurrence_count": 1,
            "occurrence_operator_type": "any"});
        if let Some(version) = version {
            item["version"] = json!(version);
        }
        json!({"rule_item": item})
    };
    leaves.push(leaf("regex", "p-pre-1", "Credit Card Number", Some(2)));
    leaves.push(leaf("dictionary", "d-pre-1", "Predef Dict", None));
    leaves.push(leaf("dictionary", "d-cus-1", "My Dict", Some(1)));
}

/// A destination tenant of TSG `tsg` whose catalog holds only predefined records (under
/// other ids and versions) with its own DLP `tenant_id`.
fn destination(tsg: &str) -> Fx {
    fx_with(tsg, |data| {
        data.patterns = vec![{
            let mut pattern = fx::pattern(
                "p-pre-9",
                "Credit Card Number",
                "predefined",
                "active",
                "regex",
                5,
                None,
            );
            pattern["tenant_id"] = json!("dlp-tenant-200");
            pattern
        }];
        data.dictionaries = vec![fx::dictionary(
            "d-pre-9",
            "Predef Dict",
            "predefined",
            "active",
            1,
            None,
        )];
        data.profiles = Vec::new();
        data.filtering_profiles = Vec::new();
        data.created_tenant_id = Some(s("dlp-tenant-200"));
    })
}

fn dlp_args(args: &[&str]) -> Vec<String> {
    ["runtime", "dlp"]
        .iter()
        .chain(args.iter())
        .map(|arg| (*arg).to_owned())
        .collect()
}

impl Fx {
    /// `runtime dlp <args>`, with the loopback, no-overwrite and no-marker checks.
    fn dlp(&self, args: &[&str]) -> Run {
        self.dlp_with(args, &RunOptions::new())
    }

    fn dlp_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let full = dlp_args(args);
        let out = run(&rust(), &self.sandbox, &strs(&full), options);
        self.check(&out);
        out
    }

    fn check(&self, out: &Run) {
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        for request in self.server.requests() {
            assert!(
                !matches!(request.method.as_str(), "PUT" | "PATCH" | "DELETE"),
                "backup and restore never update or delete: {}",
                request.line()
            );
        }
        for marker in fx::markers() {
            assert!(!out.stdout.contains(&marker), "stdout carries {marker}");
        }
    }

    /// The `METHOD /path?query` of every API request (the token requests left out).
    fn api(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    /// The writes sent (every non-GET DLP request).
    fn writes(&self) -> Vec<RecordedRequest> {
        self.server
            .requests()
            .into_iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    /// An absolute path under the sandbox's `tmp/`.
    fn tmp(&self, name: &str) -> String {
        self.sandbox.tmp().join(name).display().to_string()
    }

    /// A file under `tmp/`; its absolute path.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.sandbox.tmp().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    }

    /// `backup --output-file tmp/<name> <extra>`; the run and the file as JSON.
    fn backup(&self, name: &str, extra: &[&str]) -> (Run, Value) {
        let path = self.tmp(name);
        let mut args = vec!["backup", "--output-file", path.as_str()];
        args.extend_from_slice(extra);
        let out = self.dlp(&args);
        let doc = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(Value::Null);
        (out, doc)
    }

    fn records(&self, collection: Collection) -> Vec<Value> {
        self.server.dlp_data().records(collection).clone()
    }

    fn names(&self, collection: Collection) -> Vec<String> {
        self.records(collection)
            .iter()
            .filter_map(|record| record["name"].as_str().map(str::to_owned))
            .collect()
    }
}

/// A backup file of the `clean` (or `rich`) source written by airs-cli-rs; its JSON.
fn source_backup(edit: fn(&mut DlpData), extra: &[&str]) -> Value {
    let source = fx_with(TSG, edit);
    let (out, doc) = source.backup("source.json", extra);
    out.assert_success();
    doc
}

fn usage_block(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
}

fn error_block(message: &str) -> String {
    format!("\n  ✗ Error: {message}\n\n")
}

/// A usage error in a sandbox without any tenant: exit 2, the exact message, no request,
/// nothing on stdout.
fn assert_usage(args: &[&str], message: &str) {
    let f = bare();
    let out = f.dlp(args);
    out.assert_code(2);
    assert_eq!(out.stdout, "", "{args:?}");
    assert_eq!(out.stderr, usage_block(message), "{args:?}");
    assert_eq!(f.server.request_count(), 0, "{args:?}");
}

const INVENTORIES: [&str; 3] = [
    "GET /dlp/v2/api/dictionaries?page=0&size=100&sort=name%2Casc",
    "GET /dlp/v2/api/data-patterns?page=0&size=100&sort=name%2Casc",
    "GET /dlp/v2/api/data-profiles?page=0&size=100&sort=name%2Casc",
];

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

// ---------------------------------------------------------------------------
// backup (§16.10; TS DR-spec `backupDlpResources`)
// ---------------------------------------------------------------------------

mod backup {
    use super::*;

    /// One private file in the Rust format: the three inventory sweeps (dictionaries
    /// without keywords), the keywords read per custom dictionary, the predefined stubs,
    /// the skipped profile recorded, the TS summary table plus `Failed` on stdout.
    #[test]
    fn writes_one_private_file_in_the_rust_format() {
        use std::os::unix::fs::PermissionsExt;
        let f = fx();
        let path = f.tmp("b.json");
        let out = f.dlp(&["backup", "--skip-unsupported", "--output-file", &path]);
        out.assert_success();
        let mut expected = INVENTORIES.map(s).to_vec();
        expected.push(s("GET /dlp/v2/api/dictionaries/d-cus-1?keywords=true"));
        assert_eq!(f.api(), expected);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("}\n"));
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["format"], "airs-cli-rs.dlp-resources");
        assert_eq!(doc["version"], 1);
        assert_eq!(doc["tenant"], "prod");
        assert_eq!(doc["tsgId"], TSG);
        assert_eq!(doc["dlpTenantId"], fx::TENANT_ID);
        assert_eq!(
            doc["resources"],
            json!(["dictionaries", "patterns", "profiles"])
        );
        assert_eq!(doc["complete"], false);
        assert_eq!(
            doc["skipped"],
            json!([{"kind": "profile", "id": "dp-multi-1", "name": "Multi Profile", "reason": "Unsupported detection rule type: multi_profile"}])
        );
        assert_eq!(doc["failed"], json!([]));
        let names = |key: &str| -> Vec<String> {
            doc[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["name"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(names("dictionaries"), ["My Dict"]);
        assert_eq!(names("patterns"), ["My Pattern", "Parent Pattern"]);
        assert_eq!(names("profiles"), ["My Profile"]);
        // The custom dictionary is the keyword-bearing GET record; nothing is invented.
        let dictionary = &doc["dictionaries"][0];
        assert_eq!(dictionary["predefined"], false);
        assert_eq!(
            dictionary["record"]["keywords"],
            json!([fx::content(8), fx::content(9)])
        );
        assert_eq!(dictionary["record"], f.records(Collection::Dictionaries)[0]);
        assert_eq!(
            doc["patterns"][0]["record"],
            f.records(Collection::Patterns)[3]
        );
        assert_eq!(
            out.stdout,
            format!(
                " Backup file{pad} │ Source TSG │ Dictionaries │ Patterns │ Profiles │ Skipped │ Failed \n{rule}┼────────────┼──────────────┼──────────┼──────────┼─────────┼────────\n {path} │ 100        │ 1            │ 2        │ 1        │ 1       │ 0      \n",
                pad = " ".repeat(path.len() - "Backup file".len()),
                rule = "─".repeat(path.len() + 2),
            )
        );
        assert_eq!(
            out.stderr,
            format!(
                "  ℹ Reading inventories (dictionaries, data patterns, data profiles)…\n  ⚠ Skipped unsupported data profile: Multi Profile (Unsupported detection rule type: multi_profile)\n  ⚠ {path} contains DLP dictionary keywords and pattern definitions; keep it private (mode 0600)\n"
            )
        );
        let leftovers: Vec<_> = std::fs::read_dir(f.sandbox.tmp())
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".airs-"))
            .collect();
        assert!(leftovers.is_empty(), "no temporary is left");
    }

    /// json: TS's one-element array plus `failed` and `complete`; `--quiet` drops the
    /// progress line, never the warnings.
    #[test]
    fn the_json_summary_and_quiet() {
        let f = fx_with(TSG, clean);
        let path = f.tmp("b.json");
        let out = f.dlp(&[
            "--quiet",
            "backup",
            "--output-file",
            &path,
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            serde_json::from_str::<Value>(&out.stdout).unwrap(),
            json!([{"file": path, "sourceTsgId": "100", "dictionaries": 1, "patterns": 1, "profiles": 1, "skipped": 0, "failed": 0, "complete": true}])
        );
        assert_eq!(
            out.stderr,
            format!(
                "  ⚠ {path} contains DLP dictionary keywords and pattern definitions; keep it private (mode 0600)\n"
            )
        );
    }

    /// Without `--output-file` the file is `./airs-dlp-backup-<stamp>-<8 hex>.json` in
    /// the current directory.
    #[test]
    fn the_default_path_is_in_the_current_directory() {
        let f = fx_with(TSG, clean);
        let out = f.dlp_with(
            &["backup", "--output", "json"],
            &RunOptions::new().allow_writes_under("cwd"),
        );
        out.assert_success();
        let listing = f.sandbox.cwd_listing();
        assert_eq!(listing.len(), 1, "{listing:?}");
        let name = listing[0].display().to_string();
        let shape = name
            .strip_prefix("airs-dlp-backup-")
            .and_then(|rest| rest.strip_suffix(".json"))
            .and_then(|rest| rest.split_once('-'))
            .is_some_and(|(stamp, hex)| {
                stamp.len() == 16
                    && stamp.as_bytes()[8] == b'T'
                    && stamp.ends_with('Z')
                    && hex.len() == 8
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            });
        assert!(shape, "{name}");
        let doc: Value = serde_json::from_str(&out.stdout).unwrap();
        assert_eq!(doc[0]["file"], format!("./{name}"));
    }

    /// TS DR-spec "every unsupported reason at once": without `--skip-unsupported` the
    /// run fails before any keyword read and writes no file.
    #[test]
    fn unsupported_profiles_fail_the_run_with_no_file() {
        let f = fx();
        let path = f.tmp("b.json");
        let out = f.dlp(&["backup", "--output-file", &path]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert!(out.stderr.ends_with(&error_block(
            "Profiles cannot be exported: Multi Profile (Unsupported detection rule type: multi_profile); exclude unsupported profiles explicitly with --skip-unsupported"
        )), "{}", out.stderr);
        assert_eq!(f.api(), INVENTORIES.map(s));
        assert!(!std::path::Path::new(&path).exists());
    }

    /// TS DR-spec "selection by --resources": patterns only reads no keyword; profiles
    /// only still embeds the dependencies; predefined dependencies are stubs.
    #[test]
    fn resources_select_primaries_and_profiles_close_over_their_dependencies() {
        let f = fx_with(TSG, rich);
        let (out, doc) = f.backup("p.json", &["--resources", "patterns"]);
        out.assert_success();
        assert_eq!(doc["resources"], json!(["patterns"]));
        assert_eq!(doc["dictionaries"], json!([]));
        assert_eq!(doc["profiles"], json!([]));
        assert_eq!(doc["patterns"].as_array().unwrap().len(), 1);
        assert_eq!(f.api(), INVENTORIES.map(s), "no keyword read");
        let f = fx_with(TSG, rich);
        let (out, doc) = f.backup("q.json", &["--resources", " profiles "]);
        out.assert_success();
        let entries = |key: &str| doc[key].as_array().unwrap().clone();
        let dictionaries = entries("dictionaries");
        assert_eq!(dictionaries.len(), 2);
        assert_eq!(dictionaries[0]["name"], "My Dict");
        assert_eq!(
            dictionaries[1],
            json!({"id": "d-pre-1", "name": "Predef Dict", "predefined": true, "record": {"id": "d-pre-1", "name": "Predef Dict", "type": "predefined"}})
        );
        let patterns = entries("patterns");
        assert_eq!(
            patterns[0]["record"],
            json!({"id": "p-pre-1", "name": "Credit Card Number", "type": "predefined", "version": 2, "detection_config": {"technique": "regex"}})
        );
        assert_eq!(patterns[1]["name"], "My Pattern");
        assert!(
            f.api()
                .contains(&s("GET /dlp/v2/api/dictionaries/d-cus-1?keywords=true"))
        );
        assert!(
            !f.api().iter().any(|line| line.contains("d-pre-1")),
            "no keywords of a predefined dictionary"
        );
    }

    /// Anything at the path (a file, a dangling symlink) and a missing directory are
    /// refused before the tenant is read and before any request (D175).
    #[test]
    fn existing_paths_and_missing_directories_are_refused_before_any_request() {
        let f = fx();
        let existing = f.file("taken.json", b"keep");
        let out = f.dlp(&["backup", "--output-file", &existing]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(&format!(
                "{existing} already exists; choose another --output-file"
            ))
        );
        assert_eq!(std::fs::read(&existing).unwrap(), b"keep");
        let dangling = f.tmp("dangling.json");
        std::os::unix::fs::symlink(f.tmp("nowhere.json"), &dangling).unwrap();
        let out = f.dlp(&["backup", "--output-file", &dangling]);
        out.assert_code(1);
        assert!(out.stderr.contains("already exists"), "{}", out.stderr);
        assert!(!std::path::Path::new(&f.tmp("nowhere.json")).exists());
        let missing = f.tmp("nodir/b.json");
        let out = f.dlp(&["backup", "--output-file", &missing]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(&format!(
                "Cannot write a backup into {}; it must be an existing directory",
                f.tmp("nodir")
            ))
        );
        assert_eq!(f.server.request_count(), 0, "no token, no read");
        // A symlinked directory is followed.
        std::fs::create_dir(f.sandbox.tmp().join("real")).unwrap();
        std::os::unix::fs::symlink(f.sandbox.tmp().join("real"), f.sandbox.tmp().join("link"))
            .unwrap();
        let through = f.tmp("link/b.json");
        f.dlp(&["backup", "--skip-unsupported", "--output-file", &through])
            .assert_success();
        assert!(f.sandbox.tmp().join("real/b.json").exists());
    }

    /// A keyword read that fails is that dictionary's `failed` row: the file is still
    /// written (`complete: false`), the warning names no content, exit 1 (D175).
    #[test]
    fn a_failed_keyword_read_is_a_failed_row() {
        let f = fx_with(TSG, clean);
        f.server.push_once(
            Route::Dlp(Dl::Get(Collection::Dictionaries)),
            Planned::json(
                404,
                &json!({"title": "Not Found", "status": 404, "detail": fx::content(10)}),
            ),
        );
        let (out, doc) = f.backup("b.json", &[]);
        out.assert_code(1);
        assert_eq!(doc["complete"], false);
        assert_eq!(doc["dictionaries"], json!([]));
        assert_eq!(doc["failed"][0]["kind"], "dictionary");
        assert_eq!(doc["failed"][0]["id"], "d-cus-1");
        assert_eq!(doc["failed"][0]["name"], "My Dict");
        assert!(
            out.stderr
                .contains("  ⚠ Could not back up dictionary My Dict: "),
            "{}",
            out.stderr
        );
        assert!(out.stdout.contains("│ 1      \n"), "{}", out.stdout);
        // The profile that references it stays stored.
        assert_eq!(doc["profiles"].as_array().unwrap().len(), 1);
        // A record without its keywords is a failed row too.
        let f = fx_with(TSG, clean);
        f.server.push_once(
            Route::Dlp(Dl::Get(Collection::Dictionaries)),
            Planned::json(200, &json!({"id": "d-cus-1", "name": "My Dict"})),
        );
        let (out, doc) = f.backup("c.json", &[]);
        out.assert_code(1);
        assert_eq!(
            doc["failed"][0]["error"],
            "Dictionary keywords were not returned by the region: My Dict"
        );
    }

    /// TS DR-spec inventory checks: a repeated page, totals that disagree, more pages than
    /// `--max-pages`, mixed tenant identities; no file in every case.
    #[test]
    fn inventory_checks_refuse_incomplete_or_inconsistent_sweeps() {
        fn many(data: &mut DlpData) {
            clean(data);
            for n in 0..120 {
                data.patterns.push(fx::pattern(
                    &format!("p-x-{n:03}"),
                    &format!("X {n:03}"),
                    "custom",
                    "active",
                    "regex",
                    1,
                    None,
                ));
            }
        }
        let cases: [(Edit, &[&str], &str); 4] = [
            (
                |data| {
                    many(data);
                    data.ignore_page = true;
                },
                &[],
                "Inventory of data patterns has inconsistent pagination metadata; retry the operation",
            ),
            (
                |data| {
                    clean(data);
                    data.extra_pages = 1;
                },
                &[],
                "Inventory of dictionaries has inconsistent pagination metadata; retry the operation",
            ),
            (
                many,
                &["--max-pages", "1"],
                "Inventory of data patterns is incomplete: increase --max-pages",
            ),
            (
                |data| {
                    clean(data);
                    data.profiles[0]["tenant_id"] = json!("other-tenant");
                },
                &[],
                "Inventory reports mixed DLP tenant identities",
            ),
        ];
        for (edit, extra, message) in cases {
            let f = fx_with(TSG, edit);
            let (out, doc) = f.backup("b.json", extra);
            out.assert_code(1);
            assert!(
                out.stderr.ends_with(&error_block(message)),
                "{message}: {}",
                out.stderr
            );
            assert_eq!(doc, Value::Null, "no file");
        }
        // A capped page size (dictionaries: 100 → 50) continues the sweep.
        let f = fx_with(TSG, |data| {
            clean(data);
            for n in 0..60 {
                data.dictionaries.push(fx::dictionary(
                    &format!("d-x-{n:02}"),
                    &format!("Dx {n:02}"),
                    "predefined",
                    "active",
                    1,
                    None,
                ));
            }
        });
        let (out, _) = f.backup("b.json", &[]);
        out.assert_success();
        assert!(f.api().contains(&s(
            "GET /dlp/v2/api/dictionaries?page=1&size=100&sort=name%2Casc"
        )));
    }

    /// Inventory and keyword reads use the SDK's replay-safe retries (D175, choice 21).
    #[test]
    fn reads_are_retried_by_the_sdk() {
        let f = fx_with(TSG, clean);
        f.server.push_once(
            Route::Dlp(Dl::List(Collection::Patterns)),
            Planned::json(503, &json!({"title": "busy"})).with_retry_after(0),
        );
        let (out, _) = f.backup("b.json", &[]);
        out.assert_success();
        assert_eq!(
            f.server.dl_requests(Dl::List(Collection::Patterns)).len(),
            2
        );
    }

    /// Names: missing, control characters, duplicates; nothing to back up (TS texts).
    #[test]
    fn name_rules_and_an_empty_selection() {
        let cases: [(Edit, &str); 3] = [
            (
                |data| {
                    clean(data);
                    data.patterns[3]["name"] = json!("Evil\u{1b}[31mRed");
                },
                "DLP resource names must be nonempty and contain no control characters",
            ),
            (
                |data| {
                    clean(data);
                    let mut twin = data.patterns[3].clone();
                    twin["id"] = json!("p-twin");
                    data.patterns.push(twin);
                },
                "Backup contains duplicate data pattern names: My Pattern",
            ),
            (
                |data| {
                    data.dictionaries
                        .retain(|record| record["type"] == "predefined");
                    data.patterns
                        .retain(|record| record["type"] == "predefined");
                    data.profiles
                        .retain(|record| record["type"] == "predefined");
                },
                "No matching DLP resources to back up",
            ),
        ];
        for (edit, message) in cases {
            let f = fx_with(TSG, edit);
            let (out, doc) = f.backup("b.json", &[]);
            out.assert_code(1);
            assert!(
                out.stderr.ends_with(&error_block(message)),
                "{message}: {}",
                out.stderr
            );
            assert!(!out.stderr.contains('\u{1b}'));
            assert_eq!(doc, Value::Null);
        }
    }

    /// Every argument check is a usage error before the tenant (D162, D175).
    #[test]
    fn argument_checks_are_usage_errors_before_the_tenant() {
        for (args, message) in [
            (
                &["backup", "--file-format", "yaml"][..],
                "--file-format must be json (yaml was dropped)",
            ),
            (
                &["backup", "--file-format", "JSON"],
                "--file-format must be json (yaml was dropped)",
            ),
            (
                &["backup", "--resources", "nope"],
                "--resources takes a unique list of dictionaries, patterns, profiles",
            ),
            (
                &["backup", "--resources", "patterns,patterns"],
                "--resources takes a unique list of dictionaries, patterns, profiles",
            ),
            (
                &["backup", "--resources", ""],
                "--resources takes a unique list of dictionaries, patterns, profiles",
            ),
            (
                &["backup", "--max-pages", "0"],
                "--max-pages must be an integer from 1 to 1000",
            ),
            (
                &["backup", "--max-pages", "1001"],
                "--max-pages must be an integer from 1 to 1000",
            ),
            (
                &["backup", "--max-pages", "1.5"],
                "--max-pages must be an integer from 1 to 1000",
            ),
            (
                &["backup", "--output-file", "-"],
                "Backups contain dictionary keywords and require a private file destination, not stdout",
            ),
            (
                &["backup", "--output-file", ""],
                "--output-file needs a path",
            ),
            (
                &["backup", "--output-file", "./noext"],
                "Backup filename extension must match --file-format",
            ),
            (
                &["backup", "--output-file", "./b.yaml"],
                "Backup filename extension must match --file-format",
            ),
        ] {
            assert_usage(args, message);
        }
        // `.JSON` is accepted (TS lower-cases the extension); it fails later on the tenant.
        let f = bare();
        let out = f.dlp(&["backup", "--output-file", &f.tmp("A.JSON")]);
        out.assert_code(1);
        for format in ["markdown", "csv", "yaml"] {
            assert_usage(
                &["backup", "--output", format],
                &format!("Invalid output format '{format}'. Expected: pretty, table, json"),
            );
        }
    }

    /// The debug log records status and headers only (§2.9).
    #[test]
    fn the_debug_log_holds_no_body_or_query() {
        let f = fx_with(TSG, clean);
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let path = f.tmp("b.json");
        f.dlp_with(
            &["--debug", "backup", "--output-file", &path],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        )
        .assert_success();
        let (log, records) = debug_log::only_log(&f.sandbox);
        let text = std::fs::read_to_string(log).unwrap();
        assert!(!text.contains("FAKE-DLP-CONTENT"));
        assert!(!text.contains("keywords=true"));
        assert!(!text.contains("sort="));
        let operations: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(
            operations,
            [
                "oauth.token",
                "dlp.dictionaries.list",
                "dlp.data_patterns.list",
                "dlp.data_profiles.list",
                "dlp.dictionaries.get"
            ]
        );
    }

    /// A signal before the file is linked: `no backup file was written`, no file, no
    /// temporary (D174).
    #[test]
    fn an_interrupted_backup_writes_no_file() {
        for (signal, code) in [("INT", 130), ("TERM", 143)] {
            let f = fx_with(TSG, clean);
            f.server.push_once(
                Route::Dlp(Dl::Get(Collection::Dictionaries)),
                Planned::held(),
            );
            let path = f.tmp("b.json");
            let args = dlp_args(&["backup", "--output-file", &path]);
            let running = spawn(
                &rust(),
                &f.sandbox,
                &strs(&args),
                &RunOptions::new().expect_signal(),
            );
            assert!(f.server.wait_for_route(
                Route::Dlp(Dl::Get(Collection::Dictionaries)),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal(signal);
            let out = running.wait();
            f.server.release_held();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert!(
                out.stderr
                    .ends_with("\n  ✗ Error: Interrupted; no backup file was written\n\n"),
                "{}",
                out.stderr
            );
            assert!(!std::path::Path::new(&path).exists());
            assert_eq!(std::fs::read_dir(f.sandbox.tmp()).unwrap().count(), 0);
        }
    }
}

// ---------------------------------------------------------------------------
// restore (§16.11; TS DR-spec `planDlpResourcesRestore`, `restoreDlpResources`)
// ---------------------------------------------------------------------------

mod restore {
    use super::*;

    /// Writes `doc` under `tmp/<name>`; its path.
    fn put(f: &Fx, name: &str, doc: &Value) -> String {
        f.file(name, format!("{doc:#}\n").as_bytes())
    }

    fn restore(f: &Fx, file: &str, extra: &[&str]) -> Run {
        let mut args = vec!["restore", file];
        args.extend_from_slice(extra);
        f.dlp(&args)
    }

    fn json_result(out: &Run) -> Value {
        let doc: Value = serde_json::from_str(&out.stdout).unwrap_or(Value::Null);
        doc[0].clone()
    }

    /// TS DR-spec "prefixed restore with remapped ids and versions": dependencies first,
    /// the predefined ones resolved by name to the destination's ids and versions, the
    /// created ones bound from their read-backs; every create read back; the json result.
    #[test]
    fn restores_across_tsgs_with_remapped_ids_and_versions() {
        let doc = source_backup(rich, &[]);
        let f = destination("200");
        let file = put(&f, "b.json", &doc);
        let out = restore(
            &f,
            &file,
            &[
                "--allow-other-tenant",
                "--expect-tsg",
                "200",
                "--force",
                "--name-prefix",
                "migrated-",
                "--output",
                "json",
            ],
        );
        out.assert_success();
        let mut expected = INVENTORIES.map(s).to_vec();
        expected.extend(INVENTORIES.map(s));
        expected.extend([
            s("POST /dlp/v2/api/dictionaries?keywords=true"),
            s("GET /dlp/v2/api/dictionaries/d-new-1?keywords=true"),
            s("POST /dlp/v2/api/data-patterns"),
            s("GET /dlp/v2/api/data-patterns/p-new-2"),
            s("POST /dlp/v2/api/data-profiles"),
            s("GET /dlp/v2/api/data-profiles/dp-new-3"),
        ]);
        assert_eq!(f.api(), expected);
        let upload =
            multipart(&f.server.dl_requests(Dl::Create(Collection::Dictionaries))[0]).unwrap();
        assert_eq!(
            upload.part("json").unwrap().json,
            Some(
                json!({"category": "Financial", "name": "migrated-My Dict", "original_file_name": "keywords.txt",
                "region_name": "United States", "description": format!("dict {}", fx::content(7)),
                "is_case_sensitive": false, "tags": {"classification": ["pab"]}})
            )
        );
        let file_part = upload.part("file").unwrap();
        assert_eq!(file_part.content_type.as_deref(), Some("text/plain"));
        assert_eq!(file_part.filename.as_deref(), Some("keywords.txt"));
        let text = format!("{}\n{}\n", fx::content(8), fx::content(9));
        assert_eq!(
            file_part.sha256,
            airs_test_harness::sha256_hex(text.as_bytes())
        );
        let pattern: Value = f.server.dl_requests(Dl::Create(Collection::Patterns))[0]
            .body_json()
            .unwrap();
        assert_eq!(pattern["name"], "migrated-My Pattern");
        assert_eq!(pattern["type"], "custom");
        assert!(pattern.get("tenant_id").is_none() && pattern.get("id").is_none());
        let profile: Value = f.server.dl_requests(Dl::Create(Collection::Profiles))[0]
            .body_json()
            .unwrap();
        assert_eq!(profile["name"], "migrated-My Profile");
        let leaves: Vec<Value> =
            profile["detection_rules"][0]["expression_tree"]["sub_expressions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|leaf| leaf["rule_item"].clone())
                .collect();
        let pick = |leaf: &Value| {
            (
                leaf["id"].clone(),
                leaf["name"].clone(),
                leaf["version"].clone(),
            )
        };
        assert_eq!(
            pick(&leaves[0]),
            (json!("p-new-2"), json!("migrated-My Pattern"), json!(1))
        );
        assert_eq!(
            pick(&leaves[1]),
            (json!("p-pre-9"), json!("Credit Card Number"), json!(5))
        );
        assert_eq!(
            pick(&leaves[2]),
            (json!("d-pre-9"), json!("Predef Dict"), Value::Null)
        );
        assert_eq!(
            pick(&leaves[3]),
            (json!("d-new-1"), json!("migrated-My Dict"), json!(1))
        );
        let result = json_result(&out);
        assert_eq!(result["complete"], true);
        assert_eq!(result["sourceTsgId"], "100");
        assert_eq!(result["destinationTsgId"], "200");
        assert_eq!(
            result["dictionaries"],
            json!([{"name": "migrated-My Dict", "action": "created", "id": "d-new-1"}, {"name": "Predef Dict", "action": "resolved", "id": "d-pre-9"}])
        );
        assert_eq!(
            result["patterns"],
            json!([{"name": "Credit Card Number", "action": "resolved", "id": "p-pre-9"}, {"name": "migrated-My Pattern", "action": "created", "id": "p-new-2"}])
        );
        assert_eq!(
            result["profiles"],
            json!([{"name": "migrated-My Profile", "action": "created", "id": "dp-new-3"}])
        );
        assert_eq!(
            result["serverAdded"],
            json!([{"resource": "data pattern migrated-My Pattern", "fields": ["body.detection_config.supported_confidence_levels"]}])
        );
        assert_eq!(result["unverifiedCreates"], json!([]));
        assert_eq!(result["outcomeUnknown"], Value::Null);
        assert_eq!(result["notAttempted"], json!([]));
        assert!(result.get("error").is_none());
        let keys: Vec<&String> = result.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 11);
        assert!(
            out.stderr
                .contains("  ✓ data profile created: migrated-My Profile (1/1)\n")
        );
        // A second run reuses and verifies: no write (TS DR-spec "resumable second pass").
        f.server.clear_requests();
        let again = restore(
            &f,
            &file,
            &[
                "--allow-other-tenant",
                "--expect-tsg",
                "200",
                "--force",
                "--name-prefix",
                "migrated-",
                "--on-conflict",
                "verify",
                "--output",
                "json",
            ],
        );
        again.assert_success();
        assert!(f.writes().is_empty(), "{:?}", f.api());
        let result = json_result(&again);
        assert_eq!(result["dictionaries"][0]["action"], "reused");
        assert_eq!(result["patterns"][1]["action"], "reused");
        assert_eq!(result["profiles"][0]["action"], "verified");
    }

    /// `--dry-run`: the plan in each layout, inventory reads only, exit 0 (TS layouts).
    #[test]
    fn the_dry_run_prints_the_plan_and_writes_nothing() {
        let doc = source_backup(rich, &[]);
        let f = destination("200");
        let file = put(&f, "b.json", &doc);
        let out = restore(&f, &file, &["--allow-other-tenant", "--dry-run"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            "Restore preview — no changes made\n\nSource TSG: 100\nDestination TSG: 200\n\nDictionaries (2)\n\n Action  │ Name        \n─────────┼─────────────\n create  │ My Dict     \n resolve │ Predef Dict \n\nData patterns (2)\n\n Action  │ Name               \n─────────┼────────────────────\n resolve │ Credit Card Number \n create  │ My Pattern         \n\nData profiles (1)\n\n Action │ Name       \n────────┼────────────\n create │ My Profile \n"
        );
        assert_eq!(
            out.stderr,
            "  ℹ Reading inventories (dictionaries, data patterns, data profiles)…\n"
        );
        assert_eq!(f.api(), INVENTORIES.map(s));
        let out = restore(
            &f,
            &file,
            &["--allow-other-tenant", "--dry-run", "--output", "json"],
        );
        out.assert_success();
        assert_eq!(
            json_result(&out),
            json!({"sourceTsgId": "100", "destinationTsgId": "200", "dryRun": true,
                "dictionaries": [{"name": "My Dict", "action": "create"}, {"name": "Predef Dict", "action": "resolve"}],
                "patterns": [{"name": "Credit Card Number", "action": "resolve"}, {"name": "My Pattern", "action": "create"}],
                "profiles": [{"name": "My Profile", "action": "create"}],
                "unresolved": []})
        );
        assert!(f.writes().is_empty());
    }

    /// A TypeScript backup (JSON or YAML) is refused with the fixed message before the
    /// tenant, whatever its name (D176).
    #[test]
    fn typescript_backups_are_refused_before_the_tenant() {
        let f = bare();
        let message = |path: &str| {
            error_block(&format!(
                "{path} is a TypeScript airs-cli backup; airs cannot restore it. Restore it with the TypeScript airs-cli, or back the resources up again with 'airs runtime dlp backup'."
            ))
        };
        let json_file = f.file(
            "ts.json",
            json!({"version": 1, "resourceType": "dlp-resources", "exportedAt": "2026-09-11T00:00:00.000Z",
                "source": {"tsgId": "100"}, "dictionaries": [], "patterns": [], "profiles": []})
            .to_string()
            .as_bytes(),
        );
        let yaml_file = f.file(
            "ts.yaml",
            b"version: 1\nresourceType: dlp-resources\nexportedAt: '2026-09-11T00:00:00.000Z'\nsource:\n  tsgId: '100'\n",
        );
        for file in [json_file, yaml_file] {
            let out = restore(&f, &file, &["--dry-run"]);
            out.assert_code(1);
            assert_eq!(out.stderr, message(&file));
        }
        assert_eq!(f.server.request_count(), 0);
    }

    /// The file rules (exit 1 before the tenant, no content echoed).
    #[test]
    fn broken_files_are_refused_before_the_tenant() {
        let doc = source_backup(clean, &[]);
        let f = bare();
        let cases: Vec<(Value, &str)> = vec![
            (json!([1]), "the file does not hold a JSON object"),
            (
                {
                    let mut d = doc.clone();
                    d["format"] = json!("airs-cli-rs.redteam-targets");
                    d
                },
                "it is not an airs DLP backup",
            ),
            (
                {
                    let mut d = doc.clone();
                    d["extra"] = json!(fx::content(11));
                    d
                },
                "the envelope has an unknown key",
            ),
            (
                {
                    let mut d = doc.clone();
                    d["patterns"][0]["record"]["version"] = json!("2");
                    d
                },
                "patterns[0] does not match the data pattern response schema",
            ),
            (
                {
                    let mut d = doc.clone();
                    d["complete"] = json!(false);
                    d
                },
                "complete does not match the skipped and failed lists",
            ),
        ];
        for (value, reason) in cases {
            let path = put(&f, "b.json", &value);
            let out = restore(&f, &path, &["--dry-run"]);
            out.assert_code(1);
            assert_eq!(
                out.stderr,
                error_block(&format!("Invalid DLP backup {path}: {reason}"))
            );
            assert!(!out.stderr.contains("FAKE-DLP-CONTENT"));
        }
        let malformed = f.file(
            "bad.json",
            format!("{{\"x\": {}", fx::content(12)).as_bytes(),
        );
        let out = restore(&f, &malformed, &["--dry-run"]);
        assert_eq!(
            out.stderr,
            error_block(&format!("Invalid DLP backup {malformed}: malformed JSON"))
        );
        let mut newer = doc.clone();
        newer["version"] = json!(2);
        let path = put(&f, "new.json", &newer);
        let out = restore(&f, &path, &["--dry-run"]);
        assert_eq!(
            out.stderr,
            error_block(&format!(
                "{path} was written by a newer version of airs; upgrade airs to restore it"
            ))
        );
        let missing = f.tmp("missing.json");
        let out = restore(&f, &missing, &["--dry-run"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(&format!(
                "Cannot read {missing} (missing, not a regular file, unreadable or larger than 20 MiB)"
            ))
        );
        let mut absent = doc.clone();
        absent["patterns"][0]["name"] = json!("My Pattern");
        let path = put(&f, "m.json", &absent);
        let out = restore(&f, &path, &["--dry-run", "--pattern-map", "Ghost=x"]);
        assert_eq!(
            out.stderr,
            error_block("--pattern-map names absent from the backup: Ghost")
        );
        assert_eq!(f.server.request_count(), 0);
    }

    /// A backup from another TSG needs `--allow-other-tenant`; `--expect-tsg` must name
    /// the destination; both checks come before any request (D176, D161).
    #[test]
    fn the_tsg_checks_come_before_any_request() {
        let doc = source_backup(clean, &[]);
        let f = destination("200");
        let file = put(&f, "b.json", &doc);
        let out = restore(&f, &file, &["--dry-run"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(&format!(
                "{file} was exported from TSG 100; the selected tenant uses TSG 200. Pass --allow-other-tenant to restore it here."
            ))
        );
        let out = restore(
            &f,
            &file,
            &["--allow-other-tenant", "--expect-tsg", "300", "--force"],
        );
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "--expect-tsg does not match the selected destination tenant; no API request was made"
            )
        );
        assert_eq!(f.server.request_count(), 0);
    }

    /// Every argument check is a usage error before the file and the tenant (D162,
    /// D167, D176).
    #[test]
    fn argument_checks_are_usage_errors_before_the_file() {
        for (args, message) in [
            (
                &["restore", "x.json", "--on-conflict", "update", "--dry-run"][..],
                "--on-conflict must be error, verify, skip or reconcile",
            ),
            (
                &["restore", "x.json", "--force"],
                "--force requires --expect-tsg <destination-tsg>",
            ),
            (
                &[
                    "restore",
                    "x.json",
                    "--dry-run",
                    "--force",
                    "--expect-tsg",
                    "1",
                ],
                "--dry-run cannot be combined with --force",
            ),
            (
                &["restore", "x.json", "--dry-run", "--pattern-map", "=b"],
                "--pattern-map requires source-name=destination-name",
            ),
            (
                &["restore", "x.json", "--dry-run", "--pattern-map", "a="],
                "--pattern-map requires source-name=destination-name",
            ),
            (
                &["restore", "x.json", "--dry-run", "--pattern-map", "ab"],
                "--pattern-map requires source-name=destination-name",
            ),
            (
                &[
                    "restore",
                    "x.json",
                    "--dry-run",
                    "--pattern-map",
                    "a=b",
                    "--pattern-map",
                    "a=c",
                ],
                "Duplicate source names in --pattern-map",
            ),
            (
                &["restore", "x.json", "--dry-run", "--name-prefix", "a\tb"],
                "Invalid --name-prefix",
            ),
            (
                &["restore", "x.json", "--dry-run", "--max-pages", "0"],
                "--max-pages must be an integer from 1 to 1000",
            ),
            (
                &["restore", "x.json", "--expect-tsg", "12a", "--force"],
                "--expect-tsg must be a TSG ID (1-32 digits)",
            ),
            (
                &["restore", "x.json"],
                "refusing to restore DLP resources without --force in non-interactive mode",
            ),
        ] {
            assert_usage(args, message);
        }
        let long = "p".repeat(65);
        assert_usage(
            &["restore", "x.json", "--dry-run", "--name-prefix", &long],
            "Invalid --name-prefix",
        );
        // `a=b=c` maps `a` to `b=c`; 64 units is allowed.
        let f = bare();
        let ok = "p".repeat(64);
        let out = f.dlp(&[
            "restore",
            &f.tmp("x.json"),
            "--dry-run",
            "--pattern-map",
            "a=b=c",
            "--name-prefix",
            &ok,
        ]);
        out.assert_code(1);
        assert!(out.stderr.contains("Cannot read"), "{}", out.stderr);
    }

    /// The plan refuses before any write (TS DR-spec plan cases, adapted).
    #[test]
    fn plan_refusals_write_nothing() {
        let doc = source_backup(rich, &[]);
        // A destination without the predefined pattern: the miss with its candidates.
        let f = fx_with("200", |data| {
            data.patterns = vec![fx::pattern(
                "p-x",
                "credit-card-number",
                "predefined",
                "active",
                "regex",
                1,
                None,
            )];
            data.dictionaries = vec![fx::dictionary(
                "d-pre-9",
                "Predef Dict",
                "predefined",
                "active",
                1,
                None,
            )];
            data.profiles.clear();
            data.created_tenant_id = Some(s("dlp-tenant-200"));
            for record in data.patterns.iter_mut().chain(data.dictionaries.iter_mut()) {
                record["tenant_id"] = json!("dlp-tenant-200");
            }
        });
        let file = put(&f, "b.json", &doc);
        let out = restore(&f, &file, &["--allow-other-tenant", "--dry-run"]);
        out.assert_code(1);
        assert!(out.stderr.ends_with(&error_block(
            "Missing predefined destination data patterns: Credit Card Number (candidates: \"credit-card-number\"); bind each with --pattern-map \"<source-name>=<destination-name>\""
        )), "{}", out.stderr);
        // Mapped explicitly, the plan resolves.
        let out = restore(
            &f,
            &file,
            &[
                "--allow-other-tenant",
                "--dry-run",
                "--pattern-map",
                "Credit Card Number=credit-card-number",
            ],
        );
        out.assert_success();
        assert!(
            out.stdout.contains(" map    │ credit-card-number \n"),
            "{}",
            out.stdout
        );
        // An existing profile under the default policy.
        let f = fx_with(TSG, clean);
        let doc = {
            let source = fx_with(TSG, clean);
            source.backup("s.json", &[]).1
        };
        let file = put(&f, "b.json", &doc);
        let out = restore(&f, &file, &["--dry-run"]);
        out.assert_code(1);
        assert!(out.stderr.ends_with(&error_block(
            "Destination data profile already exists: My Profile; choose --on-conflict verify or skip"
        )), "{}", out.stderr);
        // Same TSG, same tenant: everything reuses or verifies (no write).
        let out = restore(
            &f,
            &file,
            &["--dry-run", "--on-conflict", "verify", "--output", "json"],
        );
        out.assert_success();
        let result = json_result(&out);
        assert_eq!(result["dictionaries"][0]["action"], "reuse");
        assert_eq!(result["patterns"][0]["action"], "reuse");
        assert_eq!(result["profiles"][0]["action"], "verify");
        // A destination dictionary that differs.
        let f = fx_with(TSG, |data| {
            clean(data);
            data.dictionaries[0]["keywords"] = json!(["other"]);
        });
        let file = put(&f, "b.json", &doc);
        let out = restore(&f, &file, &["--dry-run", "--on-conflict", "skip"]);
        out.assert_code(1);
        assert!(out.stderr.ends_with(&error_block(
            "Destination dictionary differs: My Dict; use --name-prefix to avoid changing a shared dictionary"
        )), "{}", out.stderr);
        // A cross-TSG restore into the same DLP tenant.
        let f = fx_with("200", clean);
        let file = put(&f, "b.json", &doc);
        let out = restore(
            &f,
            &file,
            &["--dry-run", "--allow-other-tenant", "--name-prefix", "x-"],
        );
        out.assert_code(1);
        assert!(out.stderr.ends_with(&error_block(
            "Destination credentials report the source DLP tenant; check the selected tenant before restoring"
        )), "{}", out.stderr);
        assert!(f.writes().is_empty());
    }

    /// D160, D177: a create is sent once. A 5xx stops the run with the outcome-unknown
    /// line and record; a 401 is replayed once; a 403 never is.
    #[test]
    fn each_create_is_one_attempt() {
        let doc = source_backup(clean, &[]);
        let args = [
            "--force",
            "--expect-tsg",
            "100",
            "--name-prefix",
            "c-",
            "--output",
            "json",
        ];
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Patterns)),
            Planned::json(503, &json!({"title": "busy", "detail": fx::content(13)}))
                .with_retry_after(0),
        );
        let out = restore(&f, &file, &args);
        out.assert_code(1);
        assert_eq!(
            f.server.dl_requests(Dl::Create(Collection::Patterns)).len(),
            1
        );
        assert!(
            f.server
                .dl_requests(Dl::Create(Collection::Profiles))
                .is_empty()
        );
        let message = "Outcome unknown: the data pattern c-My Pattern may have been created; run the restore again to reuse it (a data profile needs --on-conflict verify)";
        assert!(
            out.stderr.ends_with(&format!("  ✗ {message}\n")),
            "{}",
            out.stderr
        );
        let result = json_result(&out);
        assert_eq!(result["complete"], false);
        assert_eq!(result["error"], message);
        assert_eq!(
            result["outcomeUnknown"],
            json!({"kind": "patterns", "name": "c-My Pattern"})
        );
        assert_eq!(
            result["notAttempted"],
            json!([{"kind": "profiles", "name": "c-My Profile"}])
        );
        assert_eq!(result["dictionaries"][0]["action"], "created");
        // 401: token, write, token, write.
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Patterns)),
            Planned::empty_json(401),
        );
        restore(&f, &file, &args).assert_success();
        assert_eq!(
            f.server.dl_requests(Dl::Create(Collection::Patterns)).len(),
            2
        );
        // 403: one request, a rejection.
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Patterns)),
            Planned::empty_json(403),
        );
        let out = restore(&f, &file, &args);
        out.assert_code(1);
        assert_eq!(
            f.server.dl_requests(Dl::Create(Collection::Patterns)).len(),
            1
        );
        assert_eq!(
            json_result(&out)["error"],
            "API request failed (HTTP 403); verify destination state before retrying"
        );
        assert_eq!(json_result(&out)["outcomeUnknown"], Value::Null);
    }

    /// TS DT-spec: a dictionary create rejected with a body that echoes keywords stops
    /// before patterns and profiles; nothing echoes the keywords.
    #[test]
    fn a_rejected_create_stops_before_the_later_stages() {
        let doc = source_backup(clean, &[]);
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Dictionaries)),
            Planned::raw(
                400,
                "application/problem+json",
                json!({"title": "Bad Request", "detail": fx::content(8), "errors": [{"property": "file", "reason": fx::content(9)}]})
                    .to_string(),
            ),
        );
        let out = restore(
            &f,
            &file,
            &["--force", "--expect-tsg", "100", "--name-prefix", "c-"],
        );
        out.assert_code(1);
        assert!(
            f.server
                .dl_requests(Dl::Create(Collection::Patterns))
                .is_empty()
        );
        assert!(
            out.stdout
                .contains("Restore incomplete — completed writes remain")
        );
        assert!(out.stdout.contains("Not attempted\n\n Resource │ Name         \n──────────┼──────────────\n patterns │ c-My Pattern \n profiles │ c-My Profile \n"), "{}", out.stdout);
        assert!(out.stdout.ends_with(
            "Error: API request failed (HTTP 400); verify destination state before retrying\n"
        ));
    }

    /// A create applied and then dropped: one request, outcome unknown, nothing looked up.
    #[test]
    fn a_dropped_create_is_an_unknown_outcome() {
        let doc = source_backup(clean, &[]);
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Dictionaries)),
            Planned::applied_then_dropped(),
        );
        let out = restore(
            &f,
            &file,
            &[
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
                "--output",
                "json",
            ],
        );
        out.assert_code(1);
        assert_eq!(
            f.server
                .dl_requests(Dl::Create(Collection::Dictionaries))
                .len(),
            1
        );
        assert!(
            f.names(Collection::Dictionaries).contains(&s("c-My Dict")),
            "applied"
        );
        let result = json_result(&out);
        assert_eq!(
            result["outcomeUnknown"],
            json!({"kind": "dictionaries", "name": "c-My Dict"})
        );
        assert_eq!(result["dictionaries"], json!([]));
        assert_eq!(
            result["notAttempted"],
            json!([{"kind": "patterns", "name": "c-My Pattern"}, {"kind": "profiles", "name": "c-My Profile"}])
        );
        // The re-run reuses the applied dictionary (the exact echo) and completes.
        let again = restore(
            &f,
            &file,
            &[
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
                "--output",
                "json",
            ],
        );
        again.assert_success();
        assert_eq!(json_result(&again)["dictionaries"][0]["action"], "reused");
    }

    /// TS DR-spec "receipts on read-back failure": the created id is kept as an
    /// unverified receipt and the later stages stop.
    #[test]
    fn a_failed_read_back_keeps_the_receipt() {
        let doc = source_backup(clean, &[]);
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        f.server.push_once(
            Route::Dlp(Dl::Get(Collection::Dictionaries)),
            Planned::json(404, &json!({"title": "Not Found", "status": 404})),
        );
        let out = restore(
            &f,
            &file,
            &["--force", "--expect-tsg", "100", "--name-prefix", "c-"],
        );
        out.assert_code(1);
        let error = "API request failed (HTTP 404); verify destination state before retrying; unverified create: dictionaries c-My Dict (id d-new-1); inspect this resource before retrying";
        assert!(out.stdout.contains("Created resources awaiting verification\n\n Resource     │ Name      │ Created ID \n──────────────┼───────────┼────────────\n dictionaries │ c-My Dict │ d-new-1    \n"), "{}", out.stdout);
        assert!(
            out.stdout.ends_with(&format!("Error: {error}\n")),
            "{}",
            out.stdout
        );
        assert!(out.stderr.ends_with(&format!("  ✗ {error}\n")));
        // A read-back that does not echo.
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        f.server.push_once(
            Route::Dlp(Dl::Get(Collection::Patterns)),
            Planned::json(200, &json!({"id": "p-new-2", "name": "c-My Pattern", "type": "custom", "detection_config": {"technique": "regex"}})),
        );
        let out = restore(
            &f,
            &file,
            &[
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
                "--output",
                "json",
            ],
        );
        out.assert_code(1);
        assert_eq!(
            json_result(&out)["error"],
            "Restored data pattern did not verify: c-My Pattern (created id p-new-2; inspect it before retrying); unverified create: patterns c-My Pattern (id p-new-2); inspect this resource before retrying"
        );
    }

    /// §16.12: a create answered 2xx without an id was applied, so it is recorded in
    /// `outcomeUnknown` with the `Outcome: … was created, but the response could not be
    /// read` text (never reported as nothing written); later items are not attempted.
    #[test]
    fn a_created_answer_without_an_id_is_an_unreadable_outcome() {
        let doc = source_backup(clean, &[]);
        let args = [
            "--force",
            "--expect-tsg",
            "100",
            "--name-prefix",
            "c-",
            "--output",
            "json",
        ];
        let hint = "run the restore again to reuse it (a data profile needs --on-conflict verify)";
        for (collection, kind, label, name, not_attempted) in [
            (
                Collection::Dictionaries,
                "dictionaries",
                "dictionary",
                "c-My Dict",
                json!([{"kind": "patterns", "name": "c-My Pattern"}, {"kind": "profiles", "name": "c-My Profile"}]),
            ),
            (
                Collection::Patterns,
                "patterns",
                "data pattern",
                "c-My Pattern",
                json!([{"kind": "profiles", "name": "c-My Profile"}]),
            ),
            (
                Collection::Profiles,
                "profiles",
                "data profile",
                "c-My Profile",
                json!([]),
            ),
        ] {
            let f = fx_with(TSG, clean);
            let file = put(&f, "b.json", &doc);
            f.server.push_once(
                Route::Dlp(Dl::Create(collection)),
                Planned::json(201, &json!({})),
            );
            let out = restore(&f, &file, &args);
            out.assert_code(1);
            assert_eq!(f.server.dl_requests(Dl::Create(collection)).len(), 1);
            let message = format!(
                "Outcome: the {label} {name} was created, but the response could not be read; {hint}"
            );
            assert!(
                out.stderr.ends_with(&format!("  ✗ {message}\n")),
                "{kind}: {}",
                out.stderr
            );
            let result = json_result(&out);
            assert_eq!(result["complete"], false, "{kind}");
            assert_eq!(result["error"], json!(message), "{kind}");
            assert_eq!(
                result["outcomeUnknown"],
                json!({"kind": kind, "name": name}),
                "{kind}"
            );
            assert_eq!(result["unverifiedCreates"], json!([]), "{kind}");
            assert_eq!(result["notAttempted"], not_attempted, "{kind}");
            // The pretty result names it as possibly created.
            let f = fx_with(TSG, clean);
            let file = put(&f, "b.json", &doc);
            f.server.push_once(
                Route::Dlp(Dl::Create(collection)),
                Planned::json(201, &json!({})),
            );
            let out = restore(&f, &file, &args[..5]);
            out.assert_code(1);
            assert!(
                out.stdout.contains("Possibly created (outcome unknown)"),
                "{kind}: {}",
                out.stdout
            );
        }
    }

    /// D177: an unknown outcome of the reconcile copy (the suffixed name) points to
    /// `--on-conflict reconcile`, the only mode whose plan looks the copy up; following
    /// the hint verifies the applied copy and writes nothing.
    #[test]
    fn an_unknown_reconcile_copy_is_verified_by_a_reconcile_rerun() {
        let doc = source_backup(clean, &[]);
        let f = fx_with(TSG, |data| {
            clean(data);
            data.reserved_profile_names = vec![s("c-My Profile")];
        });
        let file = put(&f, "b.json", &doc);
        // The first profile POST (the reserved name) is the fixture's 409; the suffixed
        // one is applied and then dropped.
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Profiles)),
            Planned::builtin(),
        );
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Profiles)),
            Planned::applied_then_dropped(),
        );
        let args = [
            "--force",
            "--expect-tsg",
            "100",
            "--name-prefix",
            "c-",
            "--on-conflict",
            "reconcile",
            "--output",
            "json",
        ];
        let out = restore(&f, &file, &args);
        out.assert_code(1);
        let posts = f.server.dl_requests(Dl::Create(Collection::Profiles));
        assert_eq!(posts.len(), 2);
        let renamed = posts[1].body_json().unwrap()["name"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(renamed.starts_with("c-My Profile-"), "{renamed}");
        assert!(f.names(Collection::Profiles).contains(&renamed), "applied");
        let message = format!(
            "Outcome unknown: the data profile {renamed} may have been created; run the restore again with --on-conflict reconcile to verify it"
        );
        let result = json_result(&out);
        assert_eq!(result["error"], json!(message));
        assert_eq!(
            result["outcomeUnknown"],
            json!({"kind": "profiles", "name": renamed})
        );
        assert!(out.stderr.ends_with(&format!("  ✗ {message}\n")));
        // Following the hint: the copy is verified, nothing is written.
        f.server.clear_requests();
        let again = restore(&f, &file, &args);
        again.assert_success();
        assert!(f.writes().is_empty(), "{:?}", f.api());
        let result = json_result(&again);
        assert_eq!(result["profiles"][0]["action"], "verified");
        assert_eq!(result["profiles"][0]["name"], json!(renamed));
    }

    /// D177: under `--on-conflict reconcile` a 409 is retried once under the deterministic
    /// suffix; a re-run verifies that copy instead of creating another. Outside reconcile a
    /// 409 stops the run.
    #[test]
    fn reconcile_uses_a_deterministic_suffix_and_never_duplicates() {
        let doc = source_backup(clean, &[]);
        let f = fx_with(TSG, |data| {
            clean(data);
            data.reserved_profile_names = vec![s("c-My Profile")];
        });
        let file = put(&f, "b.json", &doc);
        let args = [
            "--force",
            "--expect-tsg",
            "100",
            "--name-prefix",
            "c-",
            "--output",
            "json",
        ];
        let out = restore(&f, &file, &args);
        out.assert_code(1);
        assert_eq!(
            json_result(&out)["error"],
            "API request failed (HTTP 409); verify destination state before retrying"
        );
        assert_eq!(
            f.server.dl_requests(Dl::Create(Collection::Profiles)).len(),
            1
        );
        let mut reconcile = args.to_vec();
        reconcile.extend(["--on-conflict", "reconcile"]);
        f.server.clear_requests();
        let out = restore(&f, &file, &reconcile);
        out.assert_success();
        let posts = f.server.dl_requests(Dl::Create(Collection::Profiles));
        assert_eq!(posts.len(), 2);
        let renamed = posts[1].body_json().unwrap()["name"]
            .as_str()
            .unwrap()
            .to_owned();
        let suffix = renamed.strip_prefix("c-My Profile-").unwrap();
        assert_eq!(suffix.len(), 6);
        assert!(
            suffix
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let result = json_result(&out);
        assert_eq!(
            result["profiles"],
            json!([{"name": renamed, "action": "created", "id": "dp-new-3", "renamedFrom": "c-My Profile"}])
        );
        // The re-run plans `verify` for the suffixed copy and writes nothing.
        f.server.clear_requests();
        let again = restore(&f, &file, &reconcile);
        again.assert_success();
        assert!(f.writes().is_empty(), "{:?}", f.api());
        assert_eq!(json_result(&again)["profiles"][0]["action"], "verified");
        assert_eq!(json_result(&again)["profiles"][0]["name"], renamed);
        // The same suffix on every run (a fresh tenant gets the same name).
        let g = fx_with(TSG, |data| {
            clean(data);
            data.reserved_profile_names = vec![s("c-My Profile")];
        });
        let file = put(&g, "b.json", &doc);
        restore(&g, &file, &reconcile).assert_success();
        assert!(g.names(Collection::Profiles).contains(&renamed));
    }

    /// The recheck refuses a destination that changed after planning (no write).
    #[test]
    fn the_recheck_refuses_a_changed_destination() {
        let doc = source_backup(clean, &[]);
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        // The plan's pattern sweep is the fixture's; the recheck's lists a new record
        // under the planned name.
        f.server.push_once(
            Route::Dlp(Dl::List(Collection::Patterns)),
            Planned::builtin(),
        );
        f.server.push_once(
            Route::Dlp(Dl::List(Collection::Patterns)),
            Planned::json(
                200,
                &json!({"content": [{"id": "p-sneak", "name": "c-My Pattern", "type": "custom", "status": "active"}], "last": true}),
            ),
        );
        let out = restore(
            &f,
            &file,
            &[
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
                "--output",
                "json",
            ],
        );
        out.assert_code(1);
        assert!(f.writes().is_empty());
        let result = json_result(&out);
        assert_eq!(
            result["error"],
            "Destination data pattern changed after planning: c-My Pattern"
        );
        assert_eq!(result["notAttempted"].as_array().unwrap().len(), 3);
    }

    /// D167: the prompt names both TSGs; `y` restores, anything else is `Aborted` with
    /// no write; a plan without a create needs no prompt.
    #[test]
    fn the_confirmation_prompt() {
        let doc = source_backup(clean, &[]);
        let prompt = "? Restore 3 DLP resources from TSG 100 to TSG 100? (y/N) ";
        for (answer, writes) in [(&b"y\n"[..], 6), (b"n\n", 0), (b"\n", 0), (b"\x04", 0)] {
            let f = fx_with(TSG, clean);
            let file = put(&f, "b.json", &doc);
            let args = dlp_args(&["restore", &file, "--name-prefix", "c-"]);
            let mut session = spawn_pty(&rust(), &f.sandbox, &strs(&args), &RunOptions::new());
            session.expect(prompt);
            assert!(f.writes().is_empty(), "no write while the prompt waits");
            session.send(answer);
            let out = session.wait();
            out.run.assert_success();
            assert_eq!(f.writes().len() * 2, writes, "{answer:?}");
            if writes == 0 {
                assert!(
                    transcript(&out).contains("ℹ Aborted"),
                    "{}",
                    transcript(&out)
                );
            }
        }
        // Nothing to create: no prompt, and `--force` is not needed on a terminal either.
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        let args = dlp_args(&["restore", &file, "--on-conflict", "verify"]);
        let session = spawn_pty(&rust(), &f.sandbox, &strs(&args), &RunOptions::new());
        let out = session.wait();
        out.run.assert_success();
        assert!(!transcript(&out).contains("(y/N)"));
        assert!(f.writes().is_empty());
    }

    /// D174: a signal while a create is held reports what was created and what may have
    /// been; nothing is re-sent.
    #[test]
    fn an_interrupted_restore_reports_its_context() {
        let doc = source_backup(clean, &[]);
        for (signal, code) in [("INT", 130), ("TERM", 143)] {
            let f = fx_with(TSG, clean);
            let file = put(&f, "b.json", &doc);
            f.server.push_once(
                Route::Dlp(Dl::Create(Collection::Patterns)),
                Planned::held(),
            );
            let args = dlp_args(&[
                "restore",
                &file,
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
            ]);
            let running = spawn(
                &rust(),
                &f.sandbox,
                &strs(&args),
                &RunOptions::new().expect_signal(),
            );
            assert!(f.server.wait_for_route(
                Route::Dlp(Dl::Create(Collection::Patterns)),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal(signal);
            let out = running.wait();
            f.server.release_held();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert!(
                out.stderr.ends_with("\n  ✗ Error: Interrupted; 1 resource(s) created; the data pattern c-My Pattern may also have been created (outcome unknown); run the restore again to resume\n\n"),
                "{}",
                out.stderr
            );
            assert_eq!(
                f.server.dl_requests(Dl::Create(Collection::Patterns)).len(),
                1
            );
        }
        // Before any write: nothing was changed.
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        f.server
            .push_once(Route::Dlp(Dl::List(Collection::Profiles)), Planned::held());
        let args = dlp_args(&[
            "restore",
            &file,
            "--force",
            "--expect-tsg",
            "100",
            "--name-prefix",
            "c-",
        ]);
        let running = spawn(
            &rust(),
            &f.sandbox,
            &strs(&args),
            &RunOptions::new().expect_signal(),
        );
        assert!(f.server.wait_for_route(
            Route::Dlp(Dl::List(Collection::Profiles)),
            1,
            Duration::from_secs(20)
        ));
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert!(
            out.stderr
                .ends_with("\n  ✗ Error: Interrupted; nothing was changed\n\n"),
            "{}",
            out.stderr
        );
        assert!(f.writes().is_empty());
    }

    /// An incomplete backup warns; a profile that references a dependency the backup
    /// could not store is refused, or skipped with `--skip-unresolved` (D175).
    #[test]
    fn incomplete_backups_warn_and_failed_dependencies_skip_profiles() {
        let source = fx_with(TSG, clean);
        source.server.push_once(
            Route::Dlp(Dl::Get(Collection::Dictionaries)),
            Planned::json(404, &json!({"title": "Not Found", "status": 404})),
        );
        let (out, doc) = source.backup("s.json", &[]);
        out.assert_code(1);
        // Make the profile reference the failed dictionary.
        let mut doc = doc;
        let leaf = json!({"rule_item": {"detection_technique": "dictionary", "id": "d-cus-1", "name": "My Dict",
            "match_type": "include", "confidence_level": "high", "occurrence_count": 1, "occurrence_operator_type": "any"}});
        doc["profiles"][0]["record"]["detection_rules"][0]["expression_tree"]["sub_expressions"]
            .as_array_mut()
            .unwrap()
            .push(leaf);
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        let out = restore(&f, &file, &["--dry-run", "--name-prefix", "c-"]);
        out.assert_code(1);
        assert!(
            out.stderr.starts_with(&format!(
                "  ⚠ {file} is incomplete: 1 resource(s) were skipped or could not be backed up\n"
            )),
            "{}",
            out.stderr
        );
        assert!(out.stderr.ends_with(&error_block(
            "Backup data profile references a resource that could not be backed up: c-My Profile"
        )), "{}", out.stderr);
        let out = restore(
            &f,
            &file,
            &["--dry-run", "--name-prefix", "c-", "--skip-unresolved"],
        );
        out.assert_success();
        assert!(out.stderr.contains(
            "  ⚠ Skipping data profile: c-My Profile (its dictionary My Dict could not be backed up)\n"
        ), "{}", out.stderr);
        assert!(
            out.stdout.contains(" skip   │ c-My Profile \n"),
            "{}",
            out.stdout
        );
    }

    /// TS DR-spec "CSV/TXT upload fidelity": a CSV dictionary uploads a `keywords` header
    /// (the service consumes it) and reads back its exact keywords.
    #[test]
    fn csv_dictionaries_round_trip() {
        let doc = source_backup(
            |data| {
                clean(data);
                data.dictionaries[0]["dictionary_metadata"]["original_file_name"] =
                    json!("words.CSV");
            },
            &[],
        );
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        restore(
            &f,
            &file,
            &["--force", "--expect-tsg", "100", "--name-prefix", "c-"],
        )
        .assert_success();
        let upload =
            multipart(&f.server.dl_requests(Dl::Create(Collection::Dictionaries))[0]).unwrap();
        let text = format!("keywords\n{}\n{}\n", fx::content(8), fx::content(9));
        assert_eq!(
            upload.part("file").unwrap().sha256,
            airs_test_harness::sha256_hex(text.as_bytes())
        );
        assert_eq!(
            upload.part("file").unwrap().filename.as_deref(),
            Some("words.CSV")
        );
        // A keyword with a comma cannot round-trip through a CSV.
        let mut comma = doc.clone();
        comma["dictionaries"][0]["record"]["keywords"] = json!(["a,b"]);
        let file = put(&f, "c.json", &comma);
        let out = restore(&f, &file, &["--dry-run", "--name-prefix", "d-"]);
        out.assert_code(1);
        assert!(out.stderr.ends_with(&error_block(
            "Dictionary CSV contains unsupported multi-column keywords"
        )));
    }

    /// The debug log of a restore holds status and headers only.
    #[test]
    fn the_debug_log_holds_no_body() {
        let doc = source_backup(clean, &[]);
        let f = fx_with(TSG, clean);
        let file = put(&f, "b.json", &doc);
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        f.dlp_with(
            &[
                "--debug",
                "restore",
                &file,
                "--force",
                "--expect-tsg",
                "100",
                "--name-prefix",
                "c-",
            ],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        )
        .assert_success();
        let (log, _) = debug_log::only_log(&f.sandbox);
        let text = std::fs::read_to_string(log).unwrap();
        assert!(!text.contains("FAKE-DLP-CONTENT"));
        assert!(!text.contains("c-My"));
    }
}

// ---------------------------------------------------------------------------
// The TypeScript specs, case by case (`integration/dlp-transfer-contract.spec.ts`)
// ---------------------------------------------------------------------------

mod typescript_specs {
    use super::*;

    fn predefined(id: &str, name: &str) -> Value {
        json!({"id": id, "name": name, "type": "predefined", "version": 1, "status": "active",
            "detection_config": {"technique": "regex"}})
    }

    fn profile(name: &str, patterns: &[&Value]) -> Value {
        let leaves: Vec<Value> = patterns
            .iter()
            .map(|pattern| json!({"rule_item": {"detection_technique": "regex", "id": pattern["id"], "name": pattern["name"],
                "version": pattern["version"], "confidence_level": "high", "match_type": "include",
                "occurrence_operator_type": "any", "occurrence_count": 1}}))
            .collect();
        json!({"id": format!("source-{name}"), "name": name, "type": "custom", "profile_type": "advanced",
            "profile_status": "active", "tenant_id": "source-tenant",
            "detection_rules": [{"rule_type": "expression_tree", "expression_tree": {"operator_type": "or", "sub_expressions": leaves}}]})
    }

    fn entry(record: &Value) -> Value {
        json!({"id": record["id"], "name": record["name"], "predefined": record["type"] == "predefined", "record": record})
    }

    /// A Rust-format envelope of TSG 100 (the TS spec's `envelope`).
    fn envelope(patterns: &[Value], profiles: &[Value]) -> Value {
        json!({"format": "airs-cli-rs.dlp-resources", "version": 1, "exportedAt": "2026-09-11T00:00:00.000Z",
            "tenant": "src", "tsgId": "100", "dlpTenantId": "source-tenant",
            "resources": ["dictionaries", "patterns", "profiles"], "complete": true,
            "dictionaries": [], "patterns": patterns.iter().map(entry).collect::<Vec<_>>(),
            "profiles": profiles.iter().map(entry).collect::<Vec<_>>(), "skipped": [], "failed": []})
    }

    /// The destination `dev` (TSG 200) with `patterns` and nothing else.
    fn dev(patterns: Vec<Value>) -> Fx {
        fx_with("200", move |data| {
            data.patterns = patterns;
            data.dictionaries.clear();
            data.profiles.clear();
            data.filtering_profiles.clear();
            data.created_tenant_id = Some(s("destination-tenant"));
        })
    }

    fn restore(f: &Fx, backup: &Value, flags: &[&str], code: i32) -> Run {
        let file = f.file("backup.json", backup.to_string().as_bytes());
        let mut args = vec![
            "restore",
            file.as_str(),
            "--allow-other-tenant",
            "--expect-tsg",
            "200",
            "--force",
            "--output",
            "json",
        ];
        args.extend_from_slice(flags);
        let out = f.dlp(&args);
        out.assert_code(code);
        out
    }

    fn report(out: &Run) -> Value {
        serde_json::from_str::<Value>(&out.stdout).unwrap()[0].clone()
    }

    fn created_leaves(f: &Fx, index: usize) -> Vec<Value> {
        let body = f.server.dl_requests(Dl::Create(Collection::Profiles))[index]
            .body_json()
            .unwrap();
        body["detection_rules"][0]["expression_tree"]["sub_expressions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|leaf| leaf["rule_item"].clone())
            .collect()
    }

    #[test]
    fn aggregates_missing_references_and_ranks_suggestions_without_creating_any_resources() {
        let passport = predefined("source-passport", "Passport - UK");
        let tax = predefined("source-tax", "Tax - ID");
        let f = dev(vec![
            predefined("passport-enhanced", "Passport - UK Enhanced"),
            predefined("passport-normalized", "Passport UK"),
            predefined("tax-normalized", "Tax ID"),
        ]);
        let backup = envelope(
            &[passport.clone(), tax.clone()],
            &[profile("Missing both", &[&passport, &tax])],
        );
        let out = restore(&f, &backup, &[], 1);
        for needle in ["Passport - UK", "Tax - ID", "Passport UK", "Tax ID"] {
            assert!(out.stderr.contains(needle), "{needle}: {}", out.stderr);
        }
        assert!(out.stderr.find("\"Passport UK\"") < out.stderr.find("\"Passport - UK Enhanced\""));
        assert!(f.writes().is_empty());
    }

    #[test]
    fn honors_explicit_pattern_maps_and_verifies_the_created_profile_through_re_get() {
        let source = predefined("source-passport", "Passport - UK");
        let f = dev(vec![predefined("chosen-destination", "Passport UK")]);
        let out = restore(
            &f,
            &envelope(
                std::slice::from_ref(&source),
                &[profile("Mapped profile", &[&source])],
            ),
            &["--pattern-map", "Passport - UK=Passport UK"],
            0,
        );
        assert_eq!(report(&out)["complete"], true);
        assert_eq!(f.writes().len(), 1);
        let leaves = created_leaves(&f, 0);
        assert_eq!(leaves[0]["id"], "chosen-destination");
        assert_eq!(leaves[0]["name"], "Passport UK");
        assert_eq!(
            f.api().last().unwrap(),
            "GET /dlp/v2/api/data-profiles/dp-new-1"
        );
    }

    #[test]
    fn skips_the_whole_mixed_profile_while_restoring_an_independent_resolvable_profile() {
        let present = predefined("source-present", "Present Pattern");
        let missing = predefined("source-missing", "Missing Pattern");
        let f = dev(vec![predefined("destination-present", "Present Pattern")]);
        let out = restore(
            &f,
            &envelope(
                &[present.clone(), missing.clone()],
                &[
                    profile("Mixed profile", &[&present, &missing]),
                    profile("Independent profile", &[&present]),
                ],
            ),
            &["--skip-unresolved"],
            0,
        );
        let result = report(&out);
        assert_eq!(result["complete"], true);
        let actions: Vec<(String, String)> = result["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["name"].as_str().unwrap().to_owned(),
                    row["action"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert!(actions.contains(&(s("Mixed profile"), s("skipped"))));
        assert!(actions.contains(&(s("Independent profile"), s("created"))));
        let names: Vec<Value> = f
            .server
            .dl_requests(Dl::Create(Collection::Profiles))
            .iter()
            .map(|request| request.body_json().unwrap()["name"].clone())
            .collect();
        assert_eq!(names, [json!("Independent profile")]);
        assert_eq!(created_leaves(&f, 0)[0]["id"], "destination-present");
        assert!(out.stderr.contains("Skipping data profile: Mixed profile"));
    }

    #[test]
    fn reports_a_verified_dictionary_create_then_stops_on_http_400_before_patterns_and_profiles_without_leaking_keywords()
     {
        let custom = json!({"id": "source-custom", "name": "Custom Pattern", "type": "custom", "version": 1,
            "status": "active", "detection_config": {"technique": "regex"},
            "matching_rules": {"regexes": [{"regex": format!("{}-[0-9]{{6}}", fx::content(20)), "weight": 1}]}});
        let mut backup = envelope(
            std::slice::from_ref(&custom),
            &[profile("Pending profile", &[&custom])],
        );
        backup["dictionaries"] = json!(
            ["A created dictionary", "B rejected dictionary"]
                .iter()
                .enumerate()
                .map(|(i, name)| entry(
                    &json!({"id": format!("source-dictionary-{i}"), "name": name,
                "category": "Confidential", "region_name": "United States", "type": "custom",
                "dictionary_metadata": {"original_file_name": "words.txt"},
                "keywords": [fx::content(21 + i as u32)]})
                ))
                .collect::<Vec<_>>()
        );
        let f = dev(Vec::new());
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Dictionaries)),
            Planned::builtin(),
        );
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Dictionaries)),
            Planned::raw(
                400,
                "application/problem+json",
                json!({"title": "Bad Request", "detail": format!("PRIVATE-ERROR-PAYLOAD {}", fx::content(22)),
                    "errors": [{"property": "file", "reason": fx::content(22)}]})
                    .to_string(),
            ),
        );
        let out = restore(&f, &backup, &[], 1);
        let result = report(&out);
        assert_eq!(result["complete"], false);
        assert_eq!(
            result["dictionaries"],
            json!([{"name": "A created dictionary", "action": "created", "id": "d-new-1"}])
        );
        assert_eq!(
            result["error"],
            "API request failed (HTTP 400); verify destination state before retrying"
        );
        assert!(
            f.server
                .dl_requests(Dl::Create(Collection::Patterns))
                .is_empty()
        );
        assert!(
            f.server
                .dl_requests(Dl::Create(Collection::Profiles))
                .is_empty()
        );
        assert!(
            !out.stderr.contains("PRIVATE-ERROR-PAYLOAD")
                && !out.stdout.contains("PRIVATE-ERROR-PAYLOAD")
        );
    }

    #[test]
    fn restores_a_backup_file_with_ids_remapped_and_never_sends_put_patch_or_delete() {
        let custom = json!({"id": "source-custom", "name": "Custom Pattern", "type": "custom", "version": 4,
            "status": "active", "tenant_id": "source-tenant", "detection_config": {"technique": "regex"},
            "matching_rules": {"regexes": [{"regex": "x[0-9]+", "weight": 1}]}});
        let f = dev(Vec::new());
        let out = restore(
            &f,
            &envelope(
                std::slice::from_ref(&custom),
                &[profile("Profile", &[&custom])],
            ),
            &[],
            0,
        );
        let result = report(&out);
        assert_eq!(result["patterns"][0]["id"], "p-new-1");
        let leaf = &created_leaves(&f, 0)[0];
        assert_eq!(leaf["id"], "p-new-1");
        assert_eq!(leaf["version"], 1, "the read-back version");
        // `dlp()` asserts no PUT, PATCH or DELETE was sent.
    }
}
