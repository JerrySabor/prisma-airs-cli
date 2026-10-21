//! Executable acceptance tests for the M6b step-2 DLP writes (DESIGN §16.3, §16.5–§16.9):
//! `runtime dlp filtering-profiles replace`, `patterns create|replace|patch|delete`,
//! `profiles create|replace|patch|delete`, `dictionaries create|replace|patch|delete`.
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server with the
//! seeded DLP dataset, whose write routes change the dataset (a later read sees the
//! change). Request bodies and inputs carry `FAKE-DLP-CONTENT-<nn>` markers; the
//! runner's leak check forbids every marker on stderr, the pty transcript and the debug
//! log of each run (§16.9). The write cases of the TypeScript
//! `tests/unit/cli/dlp-build-body.spec.ts`, `dlp-patch.spec.ts`, `dlp-renderer.spec.ts`,
//! `dlp-delete-safety.spec.ts`, `dlp-debug.spec.ts`, `tests/unit/airs/dlp/*.spec.ts`,
//! `tests/integration/dlp-dictionary-errors.spec.ts`, `dlp-profile-pattern-flags.spec.ts`
//! and `dlp-tenant-auth.spec.ts` are ported here, adjusted by the §12 rows.

use std::time::Duration;

use airs_test_harness::fixtures::dlp as fx;
use airs_test_harness::{
    Cli, Collection, Dl, FixtureServer, Planned, PtyRun, RecordedRequest, Route, Run, RunOptions,
    Sandbox, debug_log, multipart, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const DEBUG_HINT: &str = "    Re-run with --debug to capture redacted API diagnostics.\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seeded DLP dataset and one standard tenant `prod` (TSG 100).
fn fx() -> Fx {
    let server = FixtureServer::start();
    server.seed_dlp();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |_| {});
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

/// A sandbox with no tenant at all: usage errors must not need one.
fn bare() -> Fx {
    Fx {
        server: FixtureServer::start(),
        sandbox: Sandbox::new(),
    }
}

fn dlp_args(args: &[&str]) -> Vec<String> {
    ["runtime", "dlp"]
        .iter()
        .chain(args.iter())
        .map(|arg| (*arg).to_owned())
        .collect()
}

impl Fx {
    /// `runtime dlp <args>`, with the loopback and no-stray-files checks.
    fn dlp(&self, args: &[&str]) -> Run {
        self.dlp_with(args, &RunOptions::new())
    }

    fn dlp_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let full = dlp_args(args);
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let out = run(&rust(), &self.sandbox, &full, options);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.cwd_listing().is_empty(), "wrote into cwd");
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        assert!(
            self.server
                .dl_requests(Dl::Delete(Collection::Profiles))
                .is_empty(),
            "the profile DELETE trap was hit"
        );
        out
    }

    /// The `METHOD /path?query` of every API request (the token request left out).
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

    /// The JSON body of the only request on `route`.
    fn body(&self, route: Dl) -> Value {
        let requests = self.server.dl_requests(route);
        assert_eq!(requests.len(), 1, "{route:?}: {requests:?}");
        serde_json::from_slice(&requests[0].body).unwrap()
    }

    /// A file under the sandbox's `tmp/`; its absolute path.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.sandbox.tmp().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    }

    fn record(&self, collection: Collection, id: &str) -> Option<Value> {
        self.server
            .dlp_data()
            .records(collection)
            .iter()
            .find(|record| record["id"] == id)
            .cloned()
    }

    fn clear(&self) {
        self.server.clear_requests();
    }
}

fn error_block(message: &str, status: Option<u16>, details: &[&str]) -> String {
    let mut text = format!("\n  ✗ Error: {message}\n");
    if let Some(status) = status {
        text.push_str(&format!("    HTTP {status}\n{DEBUG_HINT}"));
    }
    for line in details {
        text.push_str(&format!("    {line}\n"));
    }
    text.push('\n');
    text
}

fn usage_block(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
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

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

const PATTERNS: &str = "/dlp/v2/api/data-patterns";
const PROFILES: &str = "/dlp/v2/api/data-profiles";
const DICTIONARIES: &str = "/dlp/v2/api/dictionaries";
const FILTERING: &str = "/dlp/v2/api/data-filtering-profiles";

fn s(text: &str) -> String {
    text.to_owned()
}

/// The standard dictionary create flags over the keyword file `file`.
fn dictionary_flags(file: &str) -> Vec<String> {
    [
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
        file,
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect()
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

// ---------------------------------------------------------------------------
// Patterns (§16.6; TS `unit/airs/dlp/data-patterns.spec.ts`, `dlp-build-body.spec.ts`)
// ---------------------------------------------------------------------------

mod patterns {
    use super::*;

    /// A flag-built create: one token, one POST with the TS body; the ack on stderr in
    /// pretty (stdout empty), the record readable afterwards.
    #[test]
    fn create_posts_the_flag_body_and_acks_on_stderr() {
        let f = fx();
        let regex = format!("{}-[0-9]+", fx::content(21));
        let out = f.dlp(&[
            "patterns",
            "create",
            "--name",
            "NP1",
            "--description",
            "d",
            "--confidence-levels",
            "high, low,",
            "--regex",
            &regex,
            "--weighted-regex",
            "A|B|2.5",
            "--proximity-keyword",
            &fx::content(22),
            "--proximity-distance",
            "50",
            "--delimiter",
            ",",
            "--tag",
            "compliance=PCI, HIPAA",
            "--tag",
            "compliance=SOX",
        ]);
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "  ✓ created p-new-1  NP1 v1\n");
        assert_eq!(f.api(), [format!("POST {PATTERNS}")]);
        let request = &f.server.dl_requests(Dl::Create(Collection::Patterns))[0];
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            f.body(Dl::Create(Collection::Patterns)),
            json!({
                "name": "NP1",
                "type": "custom",
                "detection_config": {"technique": "regex", "supported_confidence_levels": ["high", "low"]},
                "description": "d",
                "matching_rules": {
                    "delimiter": ",",
                    "proximity_distance": 50,
                    "proximity_keywords": [fx::content(22)],
                    "regexes": [{"regex": regex, "weight": 1}, {"regex": "A|B", "weight": 2.5}]
                },
                "tags": {"compliance": ["PCI", "HIPAA", "SOX"]}
            })
        );
        assert_eq!(
            f.record(Collection::Patterns, "p-new-1").unwrap()["status"],
            "active"
        );
    }

    /// The acks in each format (TS `emitAck`): json and table on stdout, the success
    /// line on stderr in every format, `--quiet` drops it.
    #[test]
    fn acks_in_every_format() {
        let f = fx();
        let out = f.dlp(&["patterns", "create", "--name", "NP2", "--output", "json"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            "{\n  \"action\": \"created\",\n  \"id\": \"p-new-1\",\n  \"name\": \"NP2\",\n  \"type\": \"custom\",\n  \"status\": \"active\",\n  \"version\": 1\n}\n"
        );
        assert_eq!(out.stderr, "  ✓ created p-new-1  NP2 v1\n");
        let out = f.dlp(&["patterns", "create", "--name", "NP3", "--output", "table"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            " action  │ id      │ name │ type   │ status │ version \n─────────┼─────────┼──────┼────────┼────────┼─────────\n created │ p-new-2 │ NP3  │ custom │ active │ 1       \n"
        );
        let out = f.dlp(&["--quiet", "patterns", "create", "--name", "NP4"]);
        out.assert_success();
        assert_eq!((out.stdout.as_str(), out.stderr.as_str()), ("", ""));
        let out = f.dlp(&[
            "--quiet", "patterns", "create", "--name", "NP5", "--output", "json",
        ]);
        assert_eq!(out.json()["action"], "created");
        assert_eq!(out.stderr, "");
    }

    /// `--body`, `--body-file` and `--body -` send the object as given (sorted keys,
    /// D35; JSON equality).
    #[test]
    fn escape_hatches_send_the_object() {
        let body = json!({"name": "B1", "type": "custom", "detection_config": {"technique": "regex"}, "description": fx::content(23), "extra": [1]});
        let text = body.to_string();
        let f = fx();
        let file = f.file("body.json", text.as_bytes());
        for (args, options) in [
            (vec![s("--body"), text.clone()], RunOptions::new()),
            (vec![s("--body-file"), file.clone()], RunOptions::new()),
            (
                vec![s("--body"), s("-")],
                RunOptions::new().stdin(text.clone()),
            ),
        ] {
            f.clear();
            let mut full = vec![s("patterns"), s("create")];
            full.extend(args);
            f.dlp_with(&strs(&full), &options).assert_success();
            assert_eq!(f.body(Dl::Create(Collection::Patterns)), body);
        }
    }

    /// `replace <id>`: the guard read, then one PUT (`--force` without a terminal); the
    /// current type and technique are kept when the flags are absent (D169).
    #[test]
    fn replace_reads_first_and_keeps_the_current_type_and_technique() {
        let f = fx();
        let out = f.dlp(&[
            "patterns", "replace", "p-dis-1", "--name", "Renamed", "--force",
        ]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {PATTERNS}/p-dis-1"),
                format!("PUT {PATTERNS}/p-dis-1")
            ]
        );
        assert_eq!(
            f.body(Dl::Replace(Collection::Patterns)),
            json!({"name": "Renamed", "type": "custom", "detection_config": {"technique": "weighted_regex"}})
        );
        assert_eq!(
            out.stderr,
            "  ⚠ The replacement omits 1 field(s) the data pattern has now: matching_rules\n  ✓ replaced p-dis-1  Renamed v5\n"
        );
        f.clear();
        f.dlp(&[
            "patterns",
            "replace",
            "p-dis-1",
            "--name",
            "Again",
            "--type",
            "file_property",
            "--technique",
            "regex",
            "--force",
        ])
        .assert_success();
        assert_eq!(
            f.body(Dl::Replace(Collection::Patterns))["type"],
            "file_property"
        );
    }

    /// `patch <id>`: the guard read, one PATCH with `application/merge-patch+json` and the
    /// TS coercions (TS `dlp-patch.spec.ts`).
    #[test]
    fn patch_sends_the_merge_patch() {
        let f = fx();
        let out = f.dlp(&[
            "patterns",
            "patch",
            "p-cus-1",
            "--set",
            "name=My",
            "type=custom",
            r#"detection_config={"technique":"regex"}"#,
            "--set",
            "n=5",
            r#"s="5""#,
            "b=true",
            "arr=[1,2]",
            "bad={oops",
            "--clear",
            "description",
        ]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {PATTERNS}/p-cus-1"),
                format!("PATCH {PATTERNS}/p-cus-1")
            ]
        );
        let request = &f.server.dl_requests(Dl::Patch(Collection::Patterns))[0];
        assert_eq!(
            request.header("content-type"),
            Some("application/merge-patch+json")
        );
        assert_eq!(
            f.body(Dl::Patch(Collection::Patterns)),
            json!({"name":"My","type":"custom","detection_config":{"technique":"regex"},"description":null,"n":5,"s":"5","b":true,"arr":[1,2],"bad":"{oops"})
        );
        assert_eq!(out.stderr, "  ✓ patched p-cus-1  My v2\n");
        // The service keeps the archived record patchable (§16.12): sent.
        f.clear();
        f.dlp(&[
            "patterns",
            "patch",
            "p-del-1",
            "--body-file",
            &f.file(
                "p.json",
                br#"{"name":"A","type":"custom","detection_config":{"technique":"regex"}}"#,
            ),
        ])
        .assert_success();
        assert_eq!(
            f.server.dl_requests(Dl::Patch(Collection::Patterns)).len(),
            1
        );
    }

    /// `delete <id> --force`: the guard read, one DELETE, `✓ archived <id>` on stderr,
    /// stdout empty in every format; the record stays readable as `deleted` (soft).
    #[test]
    fn delete_archives_with_force() {
        for format in ["pretty", "json", "table"] {
            let f = fx();
            let out = f.dlp(&["patterns", "rm", "p-cus-1", "--force", "--output", format]);
            out.assert_success();
            assert_eq!(out.stdout, "", "{format}");
            assert_eq!(out.stderr, "  ✓ archived p-cus-1\n");
            assert_eq!(
                f.api(),
                [
                    format!("GET {PATTERNS}/p-cus-1"),
                    format!("DELETE {PATTERNS}/p-cus-1")
                ]
            );
            assert_eq!(
                f.record(Collection::Patterns, "p-cus-1").unwrap()["status"],
                "deleted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Filtering profiles (§16.5)
// ---------------------------------------------------------------------------

mod filtering {
    use super::*;

    /// The flag builder (both booleans, every optional field), the guard read, the
    /// omitted-fields warning (D168) and the ack of a nameless answer.
    #[test]
    fn replace_sends_the_flag_body() {
        let f = fx();
        let out = f.dlp(&[
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
            "--force",
        ]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {FILTERING}/fp-2"),
                format!("PUT {FILTERING}/fp-2")
            ]
        );
        assert_eq!(
            f.body(Dl::Replace(Collection::FilteringProfiles)),
            json!({"file_based":true,"non_file_based":true,"description":"d","direction":"UPLOAD","log_severity":"HIGH","scan_type":"exclude","data_profile_id":123,"euc_template_id":"e1","is_end_user_coaching_enabled":true,"is_granular_profile":true,"file_type":["pdf","docx"]})
        );
        assert_eq!(
            out.stderr,
            "  ⚠ The replacement omits 2 field(s) the filtering profile has now: exclusions, rule1\n  ✓ replaced fp-2  Custom FP v3\n"
        );
    }

    #[test]
    fn the_builder_needs_both_booleans_and_checks_its_values() {
        assert_usage(
            &[
                "filtering-profiles",
                "replace",
                "fp-2",
                "--file-based",
                "--force",
            ],
            "--file-based and --non-file-based are both required",
        );
        assert_usage(
            &[
                "filtering-profiles",
                "replace",
                "fp-2",
                "--file-based",
                "--non-file-based",
                "--data-profile-id",
                "abc",
                "--force",
            ],
            "--data-profile-id must be a non-negative integer",
        );
        assert_usage(
            &[
                "filtering-profiles",
                "replace",
                "fp-2",
                "--file-based",
                "--non-file-based",
                "--direction",
                "sideways",
                "--force",
            ],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v2/api/data-filtering-profiles/fp-2 did not match schema",
        );
    }
}

// ---------------------------------------------------------------------------
// Profiles (§16.7; TS `integration/dlp-profile-pattern-flags.spec.ts`,
// `unit/cli/dlp-delete-safety.spec.ts`)
// ---------------------------------------------------------------------------

mod profiles {
    use super::*;

    /// `--pattern-id` reads each pattern in order, then one POST whose rule leaves carry
    /// the patterns' ids, names, versions, techniques and levels.
    #[test]
    fn pattern_ids_are_read_then_built_into_leaves() {
        let f = fx();
        f.server.dlp(|data| {
            data.patterns.push(fx::pattern(
                "p-two",
                "Two",
                "custom",
                "active",
                "weighted_regex",
                3,
                None,
            ));
        });
        let out = f.dlp(&[
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
            "p-two",
            "--combinator",
            "AND",
        ]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {PATTERNS}/p-cus-1"),
                format!("GET {PATTERNS}/p-two"),
                format!("POST {PROFILES}")
            ]
        );
        let leaf = |id: &str, name: &str, version: u64, technique: &str| json!({"rule_item": {"id": id, "name": name, "version": version, "detection_technique": technique, "confidence_level": "high", "supported_confidence_levels": ["high"], "match_type": "include", "occurrence_operator_type": "more_than_equal_to", "occurrence_count": 1}});
        assert_eq!(
            f.body(Dl::Create(Collection::Profiles)),
            json!({
                "name": "NP",
                "profile_type": "advanced",
                "description": "dd",
                "is_granular_data_profile": true,
                "detection_rules": [{"rule_type": "expression_tree", "expression_tree": {"operator_type": "and", "sub_expressions": [leaf("p-cus-1", "My Pattern", 1, "regex"), leaf("p-two", "Two", 3, "weighted_regex")]}}]
            })
        );
        assert_eq!(out.stderr, "  ✓ created dp-new-1  NP v1\n");
    }

    /// Missing, inactive and mismatched patterns stop before the write (exit 1).
    #[test]
    fn bad_references_stop_before_the_write() {
        for (id, message, status) in [
            (
                "missing",
                "AISEC_CLIENT_SIDE_ERROR:API error 404; Not Found; [withheld]",
                Some(404),
            ),
            (
                "p-dis-1",
                "Referenced pattern is not active; no profile was written",
                None,
            ),
        ] {
            let f = fx();
            let out = f.dlp(&["profiles", "create", "--name", "NP", "--pattern-id", id]);
            out.assert_code(1);
            assert_eq!(out.stderr, error_block(message, status, &[]), "{id}");
            assert!(f.writes().is_empty(), "{id}");
        }
        let f = fx();
        f.server.push_once(
            Route::Dlp(Dl::Get(Collection::Patterns)),
            Planned::json(
                200,
                &fx::pattern("other", "Other", "custom", "active", "regex", 1, None),
            ),
        );
        let out = f.dlp(&[
            "profiles",
            "create",
            "--name",
            "NP",
            "--pattern-id",
            "p-cus-1",
        ]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "Referenced pattern did not return a matching ID, name, technique, and version; no profile was written"
            )
        );
        assert!(f.writes().is_empty());
        // A confidence the pattern lacks: after the read, before the write (D161).
        let f = fx();
        let out = f.dlp(&[
            "profiles",
            "create",
            "--name",
            "NP",
            "--pattern-id",
            "p-cus-1",
            "--confidence",
            "low",
        ]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some("Requested confidence is not supported by every referenced pattern")
        );
        assert!(f.writes().is_empty());
    }

    /// The flag checks are usage errors before the tenant (TS texts).
    #[test]
    fn flag_checks_are_usage_errors() {
        let name33 = "x".repeat(33);
        for (args, message) in [
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
                    "Advanced",
                ],
                "Profile type must be advanced",
            ),
            (
                vec![
                    "profiles",
                    "create",
                    "--body",
                    "{}",
                    "--profile-type",
                    "basic",
                ],
                "Basic profile writes are unsupported: the API returned advanced for basic requests. Use advanced or manage basic profiles in SCM.",
            ),
            (vec!["profiles", "create"], "--name is required"),
            (
                vec!["profiles", "create", "--name", " "],
                "Profile name is required and must be a nonblank string",
            ),
            (
                vec!["profiles", "create", "--name", &name33],
                "Profile name must be at most 32 characters",
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
                vec![
                    "profiles",
                    "create",
                    "--name",
                    "x",
                    "--pattern-id",
                    "p1",
                    "--pattern-id",
                    "p1",
                ],
                "--pattern-id lists the same data pattern twice",
            ),
            (
                vec!["profiles", "create", "--name", "x"],
                "Invalid profile metadata: verify required fields and value types",
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
                vec![
                    "profiles",
                    "create",
                    "--body",
                    r#"{"name":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#,
                ],
                "Profile name must be at most 32 characters",
            ),
            (
                vec![
                    "profiles",
                    "create",
                    "--body",
                    r#"{"name":"x","profile_type":"basic"}"#,
                ],
                "Basic profile writes are unsupported: the API returned advanced for basic requests. Use advanced or manage basic profiles in SCM.",
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
                vec!["profiles", "create", "--body", "{}", "--name", "x"],
                "--body and --body-file cannot be combined with --name",
            ),
            (
                vec!["profiles", "patch", "dp-cus-1", "--set", "description=x"],
                "Profile name is required and must be a nonblank string",
            ),
            (
                vec!["profiles", "patch", "dp-cus-1", "--set", "noequals"],
                "Invalid profile patch: verify JSON syntax and --set key=value/--clear key flags",
            ),
            (
                vec![
                    "profiles",
                    "patch",
                    "dp-cus-1",
                    "--set",
                    "name=x",
                    "--set",
                    "profile_type=basic",
                ],
                "Basic profile writes are unsupported: the API returned advanced for basic requests. Use advanced or manage basic profiles in SCM.",
            ),
            (
                vec!["profiles", "patch", "dp-cus-1", "--set", "name=x"],
                "Invalid profile metadata: verify required fields and value types",
            ),
        ] {
            assert_usage(&args, message);
        }
        // 32 characters are accepted (the live limit), with flags and bodies.
        let f = fx();
        let name32 = "x".repeat(32);
        f.dlp(&[
            "profiles",
            "create",
            "--name",
            &name32,
            "--pattern-id",
            "p-cus-1",
        ])
        .assert_success();
    }

    /// A body profile create, a replace (guard, omitted fields) and a patch.
    #[test]
    fn body_create_replace_and_patch() {
        let f = fx();
        let rules = json!([{"rule_type": "multi_profile", "multi_profile": {"data_profile_ids": [1], "operator_type": "and"}}]);
        let body = json!({"name": "BP", "profile_type": "advanced", "detection_rules": rules});
        f.dlp(&["profiles", "create", "--body", &body.to_string()])
            .assert_success();
        assert_eq!(f.body(Dl::Create(Collection::Profiles)), body);
        f.clear();
        let out = f.dlp(&[
            "profiles",
            "replace",
            "dp-cus-1",
            "--body",
            &body.to_string(),
            "--force",
        ]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {PROFILES}/dp-cus-1"),
                format!("PUT {PROFILES}/dp-cus-1")
            ]
        );
        assert_eq!(
            out.stderr,
            "  ⚠ The replacement omits 2 field(s) the data profile has now: description, is_granular_data_profile\n  ✓ replaced dp-cus-1  BP v2\n"
        );
        f.clear();
        let out = f.dlp(&[
            "profiles",
            "patch",
            "dp-cus-1",
            "--set",
            "name=Patched",
            "--set",
            "profile_type=advanced",
            "--clear",
            "description",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Dl::Patch(Collection::Profiles)),
            json!({"name": "Patched", "profile_type": "advanced", "description": null})
        );
        assert_eq!(
            out.json()["status"],
            "active",
            "profile_status is the status"
        );
    }

    /// TS `dlp-delete-safety.spec.ts`: no tenant, no request, exit 2, the texts; no debug
    /// log either.
    #[test]
    fn delete_is_refused_without_a_request() {
        let f = bare();
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let out = f.dlp_with(
            &["profiles", "rm", "dp-cus-1", "--debug"],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        );
        out.assert_code(2);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            "\n  ✗ This DLP API has no DELETE for data profiles.\n  Status-based retirement is not live-verified: the latest owned-fixture\n  PATCH/PUT returned HTTP 500; an advertised DELETE returned HTTP 501.\n  No API request was sent by this command. Do not assume the profile was removed.\n  Inspect current state with: airs runtime dlp profiles get dp-cus-1 --output json\n\n"
        );
        assert!(out.stderr.contains("not live-verified"));
        assert!(out.stderr.contains("No API request was sent"));
        assert_eq!(f.server.request_count(), 0);
        assert!(debug_log::log_files(&debug_log::log_dir(&f.sandbox)).is_empty());
        // No `--force` and no `--set profile_status` exist on it.
        let out = f.dlp(&["profiles", "delete", "x", "--force"]);
        out.assert_code(2);
        assert!(out.stderr.contains("--force"), "{}", out.stderr);
        // The id is terminal-safe.
        let out = f.dlp(&["profiles", "delete", "a\u{1b}[2Jb"]);
        assert!(!out.stderr.contains('\u{1b}'));
    }
}

// ---------------------------------------------------------------------------
// Dictionaries (§16.8; TS `integration/dlp-dictionary-errors.spec.ts`,
// `unit/airs/dlp/dictionaries.spec.ts`)
// ---------------------------------------------------------------------------

mod dictionaries {
    use super::*;

    /// The multipart upload: the `json` part (`metadata.json`, `application/json`) and the
    /// `file` part (the basename, `application/octet-stream`, the bytes as read).
    #[test]
    fn create_uploads_the_metadata_and_the_file() {
        let f = fx();
        let keywords = format!("{}\n{}\n", fx::content(24), fx::content(25));
        let file = f.file("kw.txt", keywords.as_bytes());
        let mut args = vec![s("dictionaries"), s("create")];
        args.extend(dictionary_flags(&file));
        args.push(s("--include-keywords"));
        let out = f.dlp(&strs(&args));
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "  ✓ created d-new-1  D1 v1\n");
        assert_eq!(f.api(), [format!("POST {DICTIONARIES}?keywords=true")]);
        let request = &f.server.dl_requests(Dl::Create(Collection::Dictionaries))[0];
        assert!(
            request
                .header("content-type")
                .unwrap()
                .starts_with("multipart/form-data; boundary=")
        );
        let parts = multipart(request).unwrap();
        let names: Vec<&str> = parts.parts.iter().map(|part| part.name.as_str()).collect();
        assert_eq!(names, ["json", "file"]);
        let json_part = parts.part("json").unwrap();
        assert_eq!(json_part.filename.as_deref(), Some("metadata.json"));
        assert_eq!(json_part.content_type.as_deref(), Some("application/json"));
        assert_eq!(
            json_part.json,
            Some(
                json!({"name":"D1","category":"Confidential","region_name":"United States","original_file_name":"kw.txt","description":"dd","classification":"pab"})
            )
        );
        let file_part = parts.part("file").unwrap();
        assert_eq!(file_part.filename.as_deref(), Some("kw.txt"));
        assert_eq!(
            file_part.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(file_part.len, keywords.len());
        assert_eq!(
            file_part.sha256,
            airs_test_harness::sha256_hex(keywords.as_bytes())
        );
        let stored = f.record(Collection::Dictionaries, "d-new-1").unwrap();
        assert_eq!(
            stored["keywords"],
            json!([fx::content(24), fx::content(25)])
        );
    }

    /// A metadata file is sent as written (no `original_file_name` added); it cannot be
    /// combined with the metadata flags (D165).
    #[test]
    fn a_metadata_file_is_sent_as_written() {
        let f = fx();
        let file = f.file("kw.txt", b"a\n");
        let metadata = json!({"name": "M", "category": "Legal", "region_name": "United States", "original_file_name": "renamed.csv"});
        let path = f.file("meta.json", metadata.to_string().as_bytes());
        f.dlp(&[
            "dictionaries",
            "create",
            "--metadata-file",
            &path,
            "--file",
            &file,
        ])
        .assert_success();
        let request = &f.server.dl_requests(Dl::Create(Collection::Dictionaries))[0];
        let parts = multipart(request).unwrap();
        assert_eq!(parts.part("json").unwrap().json, Some(metadata));
        assert_eq!(
            parts.part("file").unwrap().filename.as_deref(),
            Some("renamed.csv")
        );
        assert_usage(
            &[
                "dictionaries",
                "create",
                "--metadata-file",
                "m.json",
                "--name",
                "x",
                "--file",
                "k",
            ],
            "--metadata-file cannot be combined with --name",
        );
    }

    /// Usage errors before any request; no keyword or metadata value in any output.
    #[test]
    fn usage_errors_come_before_any_request() {
        for (args, message) in [
            (
                vec![
                    "dictionaries",
                    "create",
                    "--name",
                    "x",
                    "--category",
                    "Legal",
                    "--file",
                    "k.txt",
                ],
                "--name, --category, --region, and --file are required",
            ),
            (
                vec!["dictionaries", "create", "--metadata-file", "m.json"],
                "--file is required (multipart upload)",
            ),
            (
                vec![
                    "dictionaries",
                    "create",
                    "--name",
                    "x",
                    "--category",
                    "Bogus",
                    "--region",
                    "US",
                    "--file",
                    "k.txt",
                ],
                "Invalid dictionary metadata: verify required fields and value types",
            ),
            (
                vec![
                    "dictionaries",
                    "create",
                    "--name",
                    "x",
                    "--category",
                    "Legal",
                    "--region",
                    "US",
                    "--file",
                    "bad\"name",
                ],
                "Invalid dictionary metadata: verify required fields and value types",
            ),
            (
                vec!["dictionaries", "patch", "d-cus-1", "--set", "a.b=1"],
                "Invalid dictionary patch flags: use --set key=value, --clear key, or --body-file for nested fields",
            ),
            (
                vec!["dictionaries", "patch", "d-cus-1", "--set", "name=x"],
                "Invalid dictionary metadata: verify required fields and value types",
            ),
            (
                vec![
                    "dictionaries",
                    "patch",
                    "d-cus-1",
                    "--body-file",
                    "b.json",
                    "--set",
                    "x=1",
                ],
                "--body-file is mutually exclusive with --set/--clear",
            ),
            (
                vec![
                    "dictionaries",
                    "patch",
                    "d-cus-1",
                    "--set",
                    "name=x",
                    "--set",
                    "category=Legal",
                    "--set",
                    "original_file_name=k",
                    "--set",
                    "type=predefined",
                ],
                "dictionary bodies cannot set \"type\": \"predefined\"; predefined resources are shipped by Palo Alto Networks and never written by airs",
            ),
        ] {
            assert_usage(&args, message);
        }
    }

    /// File errors (exit 1, before the tenant, no request): a missing keyword file, a
    /// directory, an oversized file, a metadata file that is not JSON or not an object,
    /// and an upload over the body budget.
    #[test]
    fn file_errors_exit_1_before_any_request() {
        let f = fx();
        let dir = f.sandbox.tmp().join("dir");
        std::fs::create_dir_all(&dir).unwrap();
        let missing = f.sandbox.tmp().join("missing.txt").display().to_string();
        let big = f.sandbox.tmp().join("big.txt");
        std::fs::write(&big, vec![b'a'; 7 * 1024 * 1024 + 1]).unwrap();
        let near = f.sandbox.tmp().join("near.txt");
        std::fs::write(&near, vec![b'a'; 7 * 1024 * 1024]).unwrap();
        let bad_json = f.file(
            "bad.json",
            format!("{{\"{}\": x}}", fx::content(26)).as_bytes(),
        );
        let array = f.file("array.json", b"[]");
        let kw = f.file("kw.txt", b"a\n");
        let big_meta = f.file(
            "bigmeta.json",
            json!({"name": "M", "category": "Legal", "region_name": "US", "original_file_name": "k.txt", "description": "d".repeat(1_000_000)}).to_string().as_bytes(),
        );
        let limit = |path: &str, mib: u64| {
            format!(
                "Cannot read {path} (missing, not a regular file, unreadable or larger than {mib} MiB)"
            )
        };
        let cases: Vec<(Vec<String>, String)> = vec![
            (
                [
                    vec![s("dictionaries"), s("create")],
                    dictionary_flags(&missing),
                ]
                .concat(),
                limit(&missing, 7),
            ),
            (
                [
                    vec![s("dictionaries"), s("create")],
                    dictionary_flags(&dir.display().to_string()),
                ]
                .concat(),
                limit(&dir.display().to_string(), 7),
            ),
            (
                [
                    vec![s("dictionaries"), s("create")],
                    dictionary_flags(&big.display().to_string()),
                ]
                .concat(),
                limit(&big.display().to_string(), 7),
            ),
            (
                vec![
                    s("dictionaries"),
                    s("create"),
                    s("--metadata-file"),
                    bad_json.clone(),
                    s("--file"),
                    kw.clone(),
                ],
                s("Invalid JSON in dictionary metadata file"),
            ),
            (
                vec![
                    s("dictionaries"),
                    s("create"),
                    s("--metadata-file"),
                    array.clone(),
                    s("--file"),
                    kw.clone(),
                ],
                s("Dictionary metadata must be a JSON object"),
            ),
            (
                vec![
                    s("dictionaries"),
                    s("patch"),
                    s("d-cus-1"),
                    s("--body-file"),
                    bad_json.clone(),
                ],
                s("Invalid JSON in dictionary metadata file"),
            ),
            (
                vec![
                    s("dictionaries"),
                    s("create"),
                    s("--metadata-file"),
                    big_meta.clone(),
                    s("--file"),
                    near.display().to_string(),
                ],
                format!(
                    "{} and its metadata exceed the 8 MiB upload limit",
                    near.display()
                ),
            ),
        ];
        for (args, message) in cases {
            f.clear();
            let out = f.dlp(&strs(&args));
            out.assert_code(1);
            assert_eq!(out.stderr, error_block(&message, None, &[]), "{args:?}");
            assert_eq!(f.server.request_count(), 0, "{args:?}");
        }
    }

    /// Field errors print the allowlisted problem text (exit 1); a 400 with no detail
    /// and no field errors first prints the region hint (TS text and placement).
    #[test]
    fn upload_errors_and_the_region_hint() {
        let f = fx();
        let file = f.file("kw.txt", b"a\n");
        let mut args = vec![s("dictionaries"), s("create")];
        args.extend(dictionary_flags(&file));
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Dictionaries)),
            Planned::json(400, &json!({"title": "Bad Request", "status": 400, "errors": [{"property": "originalFileName", "reason": "must not be blank"}]})),
        );
        let out = f.dlp(&strs(&args));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_CLIENT_SIDE_ERROR:API error 400; Bad Request; originalFileName: must not be blank",
                Some(400),
                &[]
            )
        );
        for planned in [
            Planned::json(400, &json!({"title": "Bad Request", "status": 400})),
            Planned::raw(400, "text/plain", format!("bad {}", fx::content(27))),
        ] {
            f.server
                .push_once(Route::Dlp(Dl::Create(Collection::Dictionaries)), planned);
            let out = f.dlp(&strs(&args));
            out.assert_code(1);
            assert!(
                out.stderr.starts_with("Dictionary upload rejected. Verify the SCM region display name (for example, --region \"United States\"); region codes such as GLOBAL or us-west-2 are not equivalent.\n\n  ✗ Error: AISEC_CLIENT_SIDE_ERROR:API error 400"),
                "{}",
                out.stderr
            );
        }
        // Not for another status.
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Dictionaries)),
            Planned::json(409, &json!({"title": "Conflict", "status": 409})),
        );
        let out = f.dlp(&strs(&args));
        assert!(!out.stderr.contains("Dictionary upload rejected"));
    }

    /// `replace <id>`: guard read, omitted fields, PUT; a 2xx with a body acks it.
    #[test]
    fn replace_reads_first_and_uploads() {
        let f = fx();
        let file = f.file("kw.txt", b"a\nb\n");
        let mut args = vec![s("dictionaries"), s("replace"), s("d-cus-1")];
        args.extend(dictionary_flags(&file));
        args.push(s("--force"));
        let out = f.dlp(&strs(&args));
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {DICTIONARIES}/d-cus-1"),
                format!("PUT {DICTIONARIES}/d-cus-1")
            ]
        );
        assert_eq!(
            out.stderr,
            "  ⚠ The replacement omits 2 field(s) the dictionary has now: is_case_sensitive, type\n  ✓ replaced d-cus-1  D1 v3\n"
        );
    }

    /// A 2xx without a body: one re-read acks the new state; when the re-read fails the
    /// warning and the reduced ack (exit 0, D172).
    #[test]
    fn a_replace_without_a_body_is_read_back() {
        let f = fx();
        f.server.dlp(|data| data.dictionary_replace_empty = true);
        let file = f.file("kw.txt", b"a\n");
        let mut args = vec![s("dictionaries"), s("replace"), s("d-cus-1")];
        args.extend(dictionary_flags(&file));
        args.extend([s("--force"), s("--output"), s("json")]);
        let out = f.dlp(&strs(&args));
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {DICTIONARIES}/d-cus-1"),
                format!("PUT {DICTIONARIES}/d-cus-1"),
                format!("GET {DICTIONARIES}/d-cus-1")
            ]
        );
        assert_eq!(out.json()["name"], "D1");
        f.clear();
        // The guard read answers; the re-read fails (a 404, not retried).
        f.server.set_default(
            Route::Dlp(Dl::Get(Collection::Dictionaries)),
            Planned::json(404, &json!({"title": "Not Found", "status": 404})),
        );
        for (format, stdout) in [
            (
                "json",
                "{\n  \"action\": \"replaced\",\n  \"id\": \"d-cus-1\"\n}\n",
            ),
            ("pretty", ""),
        ] {
            f.server.push_once(
                Route::Dlp(Dl::Get(Collection::Dictionaries)),
                Planned::builtin(),
            );
            let mut args = vec![s("dictionaries"), s("replace"), s("d-cus-1")];
            args.extend(dictionary_flags(&file));
            args.extend([s("--force"), s("--output"), s(format)]);
            let out = f.dlp(&strs(&args));
            out.assert_success();
            assert_eq!(out.stdout, stdout);
            assert!(
                out.stderr
                    .ends_with("  ⚠ replaced d-cus-1; the service did not return the new state\n"),
                "{}",
                out.stderr
            );
            assert!(!out.stderr.contains('✓'));
        }
    }

    /// `patch <id>` and `delete <id>`.
    #[test]
    fn patch_and_delete() {
        let f = fx();
        f.dlp(&[
            "dictionaries",
            "patch",
            "d-cus-1",
            "--set",
            "category=Legal",
            "name=N",
            "original_file_name=kw.txt",
            "--clear",
            "description",
        ])
        .assert_success();
        assert_eq!(
            f.body(Dl::Patch(Collection::Dictionaries)),
            json!({"category":"Legal","name":"N","original_file_name":"kw.txt","description":null})
        );
        f.clear();
        let out = f.dlp(&["dictionaries", "delete", "d-cus-1", "--force"]);
        out.assert_success();
        assert_eq!(out.stderr, "  ✓ deleted d-cus-1\n");
        assert_eq!(
            f.api(),
            [
                format!("GET {DICTIONARIES}/d-cus-1"),
                format!("DELETE {DICTIONARIES}/d-cus-1")
            ]
        );
        assert!(f.record(Collection::Dictionaries, "d-cus-1").is_none());
    }
}

// ---------------------------------------------------------------------------
// The body checks (§16.3, D162–D166)
// ---------------------------------------------------------------------------

mod checks {
    use super::*;

    #[test]
    fn hatches_and_builders_are_checked_before_the_tenant() {
        let secret = fx::content(28);
        let body_flag = format!("{secret}-not-json");
        let weighted = format!("{secret}|x");
        let tag = secret.clone();
        let set = secret.clone();
        for (args, message) in [
            (vec!["patterns", "create"], "--name is required"),
            (
                vec!["patterns", "create", "--body", &body_flag],
                "--body is not valid JSON",
            ),
            (
                vec!["patterns", "create", "--body", "null"],
                "--body must contain a JSON object",
            ),
            (
                vec!["patterns", "create", "--body", ""],
                "--body needs a JSON object",
            ),
            (
                vec!["patterns", "create", "--body-file", ""],
                "--body-file needs a path",
            ),
            (
                vec![
                    "patterns",
                    "create",
                    "--body",
                    "{}",
                    "--body-file",
                    "b.json",
                ],
                "--body and --body-file are mutually exclusive",
            ),
            (
                vec![
                    "patterns", "create", "--body", "{}", "--tag", "a=b", "--name", "x",
                ],
                "--body and --body-file cannot be combined with --name",
            ),
            (
                vec![
                    "patterns",
                    "create",
                    "--name",
                    "x",
                    "--weighted-regex",
                    &weighted,
                ],
                "--weighted-regex must be PATTERN|weight with a numeric weight",
            ),
            (
                vec!["patterns", "create", "--name", "x", "--tag", &tag],
                "--tag must be key=value[,value...]",
            ),
            (
                vec!["patterns", "create", "--name", "x", "--tag", "geo="],
                "--tag needs at least one value",
            ),
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
                vec!["patterns", "create", "--name", "x", "--type", "predefined"],
                "data pattern bodies cannot set \"type\": \"predefined\"; predefined resources are shipped by Palo Alto Networks and never written by airs",
            ),
            (
                vec!["patterns", "create", "--body", r#"{"type":"predefined"}"#],
                "data pattern bodies cannot set \"type\": \"predefined\"; predefined resources are shipped by Palo Alto Networks and never written by airs",
            ),
            (
                vec!["patterns", "create", "--name", "x", "--type", "bogus"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v2/api/data-patterns did not match schema",
            ),
            (
                vec!["patterns", "patch", "a/b", "--set", "name=x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PATCH /v2/api/data-patterns/a%2Fb did not match schema",
            ),
            (
                vec!["patterns", "patch", "p", "--set", &set],
                "--set expects key=value",
            ),
            (
                vec!["patterns", "patch", "p", "--set", "a.b=1"],
                "--set and --clear take top-level fields; use --body-file for nested fields",
            ),
            (
                vec!["patterns", "patch", "p", "--clear", "a.b"],
                "--set and --clear take top-level fields; use --body-file for nested fields",
            ),
            (
                vec!["patterns", "patch", "p", "--set", "k=null"],
                "--set cannot set null; use --clear for that field",
            ),
            (
                vec!["patterns", "patch", "p", "--set", "k=12345678901234567890"],
                "--set numbers must keep their exact value; quote them to send a string",
            ),
            (
                vec![
                    "patterns",
                    "patch",
                    "p",
                    "--body-file",
                    "b.json",
                    "--clear",
                    "x",
                ],
                "--body-file is mutually exclusive with --set/--clear",
            ),
            (
                vec!["patterns", "patch", "p"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PATCH /v2/api/data-patterns/p did not match schema",
            ),
            (vec!["patterns", "get", ".."], "Invalid data pattern id: .."),
            (
                vec!["patterns", "replace", "..", "--name", "x", "--force"],
                "Invalid data pattern id: ..",
            ),
            (
                vec!["patterns", "delete", "", "--force"],
                "Invalid data pattern id: ",
            ),
            (
                vec!["dictionaries", "rm", "a\\b", "--force"],
                "Invalid dictionary id: a\\b",
            ),
            (
                vec![
                    "filtering-profiles",
                    "replace",
                    ".",
                    "--file-based",
                    "--non-file-based",
                    "--force",
                ],
                "Invalid filtering profile id: .",
            ),
            (
                vec!["profiles", "replace", "%2e%2e", "--name", "x", "--force"],
                "Invalid data profile id: %2e%2e",
            ),
            (
                vec!["profiles", "create", "--name", "x", "--pattern-id", ".."],
                "Invalid data pattern id: ..",
            ),
        ] {
            assert_usage(&args, message);
            let joined = args.join(" ");
            if joined.contains(&secret) {
                assert!(!message.contains(&secret));
            }
        }
    }

    /// `--body -` needs piped stdin: a terminal is a usage error; empty, invalid or
    /// oversized stdin is refused (exit 2) before the tenant.
    #[test]
    fn stdin_bodies() {
        let f = fx();
        for (stdin, message) in [
            (Vec::new(), "--body is not valid JSON"),
            (b"[1]".to_vec(), "--body must contain a JSON object"),
            (
                vec![b' '; 1024 * 1024 + 1],
                "--body - must be UTF-8 JSON of at most 1 MiB on stdin",
            ),
            (
                vec![0xff, 0xfe],
                "--body - must be UTF-8 JSON of at most 1 MiB on stdin",
            ),
        ] {
            let out = f.dlp_with(
                &["patterns", "create", "--body", "-"],
                &RunOptions::new().stdin(stdin),
            );
            out.assert_code(2);
            assert_eq!(out.stderr, usage_block(message));
            assert_eq!(f.server.request_count(), 0);
        }
        let mut session = spawn_pty(
            &rust(),
            &f.sandbox,
            &["runtime", "dlp", "patterns", "create", "--body", "-"],
            &RunOptions::new(),
        );
        session.expect("--body - requires piped input on stdin");
        let out = session.wait();
        out.run.assert_code(2);
        assert_eq!(f.server.request_count(), 0);
    }

    /// Body files: the §13.2 texts (exit 1, before the tenant); content never echoed.
    #[test]
    fn body_files_follow_the_input_rules() {
        let f = fx();
        let bad = f.file(
            "bad.json",
            format!("{{\"{}\": x}}", fx::content(29)).as_bytes(),
        );
        let array = f.file("array.json", b"[]");
        let big = f.sandbox.tmp().join("big.json");
        std::fs::write(&big, vec![b' '; 1024 * 1024 + 1]).unwrap();
        let big = big.display().to_string();
        for (path, message) in [
            (bad.clone(), format!("{bad} is not valid JSON")),
            (array.clone(), format!("{array} must contain a JSON object")),
            (
                big.clone(),
                format!(
                    "Cannot read {big} (missing, not a regular file, unreadable or larger than 1 MiB)"
                ),
            ),
        ] {
            let out = f.dlp(&["patterns", "create", "--body-file", &path]);
            out.assert_code(1);
            assert_eq!(out.stderr, error_block(&message, None, &[]));
            assert_eq!(f.server.request_count(), 0);
        }
        // Profiles keep their own texts; a file body's schema failure is exit 2.
        let out = f.dlp(&["profiles", "create", "--body-file", &bad]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some("Cannot read profile body as JSON; verify the file and JSON syntax")
        );
        let nameless = f.file("nameless.json", b"{}");
        let out = f.dlp(&["profiles", "create", "--body-file", &nameless]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_block("Profile name is required and must be a nonblank string")
        );
        let invalid = f.file("invalid.json", br#"{"name":"x","type":"custom"}"#);
        let out = f.dlp(&["patterns", "create", "--body-file", &invalid]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v2/api/data-patterns did not match schema"
            )
        );
        assert_eq!(f.server.request_count(), 0);
    }

    /// D50: markdown, csv and yaml are usage errors on every write.
    #[test]
    fn dropped_formats_are_usage_errors() {
        for format in ["markdown", "csv", "yaml"] {
            for args in [
                &["patterns", "create", "--name", "x"][..],
                &["patterns", "rm", "p", "--force"],
                &["profiles", "rm", "p"],
                &["dictionaries", "patch", "d", "--set", "a=1"],
            ] {
                let mut full = args.to_vec();
                full.extend(["--output", format]);
                assert_usage(
                    &full,
                    &format!("Invalid output format '{format}'. Expected: pretty, table, json"),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The predefined guard (D166)
// ---------------------------------------------------------------------------

mod guard {
    use super::*;

    /// Every replace, patch and delete of a predefined, parent-managed or mismatched
    /// record is refused after the read, before any write (exit 1).
    #[test]
    fn predefined_parent_managed_and_mismatched_records_are_refused() {
        fn file(f: &Fx) -> String {
            f.file("kw.txt", b"a\n")
        }
        type Args = fn(&Fx, &str) -> Vec<String>;
        let commands: Vec<(Collection, &str, Args)> = vec![
            (Collection::Patterns, "data pattern", |_, id| {
                vec![
                    s("patterns"),
                    s("replace"),
                    s(id),
                    s("--name"),
                    s("x"),
                    s("--force"),
                ]
            }),
            (Collection::Patterns, "data pattern", |_, id| {
                vec![
                    s("patterns"),
                    s("patch"),
                    s(id),
                    s("--set"),
                    s("name=x"),
                    s("type=custom"),
                    s(r#"detection_config={"technique":"regex"}"#),
                ]
            }),
            (Collection::Patterns, "data pattern", |_, id| {
                vec![s("patterns"), s("delete"), s(id), s("--force")]
            }),
            (Collection::Profiles, "data profile", |_, id| {
                vec![
                    s("profiles"),
                    s("replace"),
                    s(id),
                    s("--body"),
                    s(r#"{"name":"x","detection_rules":[]}"#),
                    s("--force"),
                ]
            }),
            (Collection::Profiles, "data profile", |_, id| {
                vec![
                    s("profiles"),
                    s("patch"),
                    s(id),
                    s("--set"),
                    s("name=x"),
                    s("profile_type=advanced"),
                ]
            }),
            (Collection::Dictionaries, "dictionary", |f, id| {
                let mut args = vec![s("dictionaries"), s("replace"), s(id)];
                args.extend(dictionary_flags(&file(f)));
                args.push(s("--force"));
                args
            }),
            (Collection::Dictionaries, "dictionary", |_, id| {
                vec![
                    s("dictionaries"),
                    s("patch"),
                    s(id),
                    s("--set"),
                    s("name=x"),
                    s("category=Legal"),
                    s("original_file_name=k"),
                ]
            }),
            (Collection::Dictionaries, "dictionary", |_, id| {
                vec![s("dictionaries"), s("rm"), s(id), s("--force")]
            }),
            (
                Collection::FilteringProfiles,
                "filtering profile",
                |_, id| {
                    vec![
                        s("filtering-profiles"),
                        s("replace"),
                        s(id),
                        s("--file-based"),
                        s("--non-file-based"),
                        s("--force"),
                    ]
                },
            ),
        ];
        for (collection, resource, args) in commands {
            for case in ["predefined", "parent", "mismatch"] {
                let f = fx();
                let id = "g-1";
                f.server.dlp(|data| {
                    let mut record = data.records(collection)[0].clone();
                    record["id"] = json!(id);
                    record["type"] = json!(if case == "predefined" {
                        "predefined"
                    } else {
                        "custom"
                    });
                    record["is_parent_managed"] = json!(case == "parent");
                    data.records_mut(collection).push(record);
                });
                if case == "mismatch" {
                    let mut other = f.server.dlp_data().records(collection)[0].clone();
                    other["id"] = json!("someone-else");
                    other["type"] = json!("custom");
                    other["is_parent_managed"] = json!(false);
                    f.server
                        .push_once(Route::Dlp(Dl::Get(collection)), Planned::json(200, &other));
                }
                let full = args(&f, id);
                let out = f.dlp(&strs(&full));
                out.assert_code(1);
                let expected = match case {
                    "predefined" => format!(
                        "{id} is a predefined {resource}; airs never modifies or deletes predefined resources"
                    ),
                    "parent" => format!(
                        "{id} is managed by a parent tenant; airs never modifies or deletes it here"
                    ),
                    _ => format!(
                        "The service returned a different {resource} for {id}; nothing was changed"
                    ),
                };
                assert_eq!(
                    out.stderr,
                    error_block(&expected, None, &[]),
                    "{full:?} {case}"
                );
                assert!(f.writes().is_empty(), "{full:?} {case}");
                assert_eq!(out.stdout, "");
            }
        }
    }

    /// The seeded predefined records: refused too.
    #[test]
    fn the_seeded_predefined_records_are_never_written() {
        let f = fx();
        for args in [
            &["patterns", "rm", "p-pre-1", "--force"][..],
            &[
                "patterns",
                "patch",
                "p-par-1",
                "--set",
                "name=x",
                "type=custom",
                r#"detection_config={"technique":"regex"}"#,
            ],
            &["dictionaries", "rm", "d-pre-1", "--force"],
            &[
                "filtering-profiles",
                "replace",
                "fp-1",
                "--file-based",
                "--non-file-based",
                "--force",
            ],
            &[
                "profiles",
                "patch",
                "dp-pre-1",
                "--set",
                "name=x",
                "profile_type=advanced",
            ],
        ] {
            f.dlp(args).assert_code(1);
        }
        assert!(f.writes().is_empty());
    }

    /// A record whose `type` is outside the tenant-created vocabulary (kept by the SDK's
    /// tolerant response mode, D178) is refused like a predefined one.
    #[test]
    fn an_unfamiliar_type_is_refused() {
        let f = fx();
        f.server
            .dlp(|data| data.dictionaries[0]["type"] = json!("shared"));
        let out = f.dlp(&["dictionaries", "rm", "d-cus-1", "--force"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "d-cus-1 has a dictionary type airs does not recognise; it modifies or deletes only tenant-created resources",
                None,
                &[]
            )
        );
        assert!(f.writes().is_empty());
        // `file_property` patterns are tenant-created: written.
        f.server
            .dlp(|data| data.patterns[3]["type"] = json!("file_property"));
        f.dlp(&["patterns", "rm", "p-cus-1", "--force"])
            .assert_success();
    }

    /// A failed guard read is the §6 read error (a 404 included).
    #[test]
    fn a_failed_guard_read_is_the_read_error() {
        let f = fx();
        let out = f.dlp(&["patterns", "rm", "nope", "--force"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_CLIENT_SIDE_ERROR:API error 404; Not Found; [withheld]",
                Some(404),
                &[]
            )
        );
        assert!(f.writes().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Confirmations (D167, D168)
// ---------------------------------------------------------------------------

mod confirmations {
    use super::*;

    /// Without a terminal and without `--force`: the usage error before the tenant.
    #[test]
    fn non_interactive_runs_need_force() {
        for (args, message) in [
            (
                vec!["patterns", "delete", "p-cus-1"],
                "refusing to delete data pattern p-cus-1 without --force in non-interactive mode",
            ),
            (
                vec!["dictionaries", "rm", "d-cus-1"],
                "refusing to delete dictionary d-cus-1 without --force in non-interactive mode",
            ),
            (
                vec!["patterns", "replace", "p-cus-1", "--name", "x"],
                "refusing to replace data pattern p-cus-1 without --force in non-interactive mode",
            ),
            (
                vec![
                    "profiles",
                    "replace",
                    "dp-cus-1",
                    "--name",
                    "x",
                    "--pattern-id",
                    "p",
                ],
                "refusing to replace data profile dp-cus-1 without --force in non-interactive mode",
            ),
            (
                vec![
                    "dictionaries",
                    "replace",
                    "d-cus-1",
                    "--name",
                    "x",
                    "--category",
                    "Legal",
                    "--region",
                    "US",
                    "--file",
                    "k",
                ],
                "refusing to replace dictionary d-cus-1 without --force in non-interactive mode",
            ),
            (
                vec![
                    "filtering-profiles",
                    "replace",
                    "fp-2",
                    "--file-based",
                    "--non-file-based",
                ],
                "refusing to replace filtering profile fp-2 without --force in non-interactive mode",
            ),
        ] {
            assert_usage(&args, message);
        }
    }

    fn pty(f: &Fx, args: &[&str], prompt: &str, answer: &[u8]) -> PtyRun {
        let full = dlp_args(args);
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let mut session = spawn_pty(&rust(), &f.sandbox, &full, &RunOptions::new());
        session.expect(prompt);
        assert!(f.writes().is_empty(), "no write while the prompt waits");
        session.send(answer);
        session.wait()
    }

    /// `y`/`yes` confirm; `n`, Enter and EOF decline with `ℹ Aborted` and no write.
    #[test]
    fn the_delete_prompt() {
        let prompt = "? Delete data pattern p-cus-1 (My Pattern)? (y/N) ";
        for answer in [&b"y\n"[..], b" YES \n"] {
            let f = fx();
            let out = pty(&f, &["patterns", "delete", "p-cus-1"], prompt, answer);
            out.run.assert_success();
            assert!(
                transcript(&out).contains("✓ archived p-cus-1"),
                "{}",
                transcript(&out)
            );
            assert_eq!(f.writes().len(), 1);
        }
        for answer in [&b"n\n"[..], b"\n", b"\x04", b"yep\n"] {
            let f = fx();
            let out = pty(&f, &["patterns", "delete", "p-cus-1"], prompt, answer);
            out.run.assert_success();
            assert!(transcript(&out).contains("  ℹ Aborted\n"), "{answer:?}");
            assert!(f.writes().is_empty(), "{answer:?}");
        }
        let f = fx();
        pty(
            &f,
            &["dictionaries", "delete", "d-cus-1"],
            "? Delete dictionary d-cus-1 (My Dict)? (y/N) ",
            b"y\n",
        )
        .run
        .assert_success();
    }

    /// A replace prompt names the fields it drops (D168).
    #[test]
    fn the_replace_prompt_names_the_dropped_fields() {
        let f = fx();
        let out = pty(
            &f,
            &[
                "filtering-profiles",
                "replace",
                "fp-2",
                "--file-based",
                "--non-file-based",
            ],
            "? Replace filtering profile fp-2 (Custom FP)? The replacement omits 3 field(s) it has now: description, exclusions, rule1. (y/N) ",
            b"n\n",
        );
        out.run.assert_success();
        assert!(f.writes().is_empty());
        let f = fx();
        let out = pty(
            &f,
            &[
                "patterns",
                "replace",
                "p-cus-1",
                "--body",
                r#"{"name":"x","type":"custom","detection_config":{"technique":"regex"},"description":"d","matching_rules":{},"tags":{}}"#,
            ],
            "? Replace data pattern p-cus-1 (My Pattern)? (y/N) ",
            b"y\n",
        );
        out.run.assert_success();
        assert_eq!(f.writes().len(), 1);
    }

    /// Ctrl-C at a prompt: `Cancelled; nothing was changed.`, exit 130, no write.
    #[test]
    fn ctrl_c_at_the_prompt_changes_nothing() {
        let f = fx();
        let full = dlp_args(&["dictionaries", "rm", "d-cus-1"]);
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let mut session = spawn_pty(&rust(), &f.sandbox, &full, &RunOptions::new());
        session.expect("(y/N) ");
        session.signal("INT");
        let out = session.wait();
        out.run.assert_code(130);
        assert!(
            transcript(&out).contains("\n  Cancelled; nothing was changed.\n"),
            "{}",
            transcript(&out)
        );
        assert!(f.writes().is_empty());
    }

    /// Patch and create never ask.
    #[test]
    fn patch_and_create_do_not_confirm() {
        let f = fx();
        let full = dlp_args(&[
            "patterns",
            "patch",
            "p-cus-1",
            "--set",
            "name=x",
            "type=custom",
            r#"detection_config={"technique":"regex"}"#,
        ]);
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let out = spawn_pty(&rust(), &f.sandbox, &full, &RunOptions::new()).wait();
        out.run.assert_success();
        assert!(!transcript(&out).contains("(y/N)"));
    }
}

// ---------------------------------------------------------------------------
// One attempt per write (D160)
// ---------------------------------------------------------------------------

mod attempts {
    use super::*;

    /// Each write, its route and its arguments.
    fn writes(f: &Fx) -> Vec<(Dl, Vec<String>)> {
        let kw = f.file("kw.txt", b"a\n");
        let dict = |id: Option<&str>| {
            let mut args = vec![s("dictionaries")];
            match id {
                Some(id) => args.extend([s("replace"), s(id)]),
                None => args.push(s("create")),
            }
            args.extend(dictionary_flags(&kw));
            if id.is_some() {
                args.push(s("--force"));
            }
            args
        };
        let profile = json!({"name": "BP", "detection_rules": []}).to_string();
        vec![
            (
                Dl::Create(Collection::Patterns),
                vec![s("patterns"), s("create"), s("--name"), s("x")],
            ),
            (
                Dl::Replace(Collection::Patterns),
                vec![
                    s("patterns"),
                    s("replace"),
                    s("p-cus-1"),
                    s("--name"),
                    s("x"),
                    s("--force"),
                ],
            ),
            (
                Dl::Patch(Collection::Patterns),
                vec![
                    s("patterns"),
                    s("patch"),
                    s("p-cus-1"),
                    s("--set"),
                    s("name=x"),
                    s("type=custom"),
                    s(r#"detection_config={"technique":"regex"}"#),
                ],
            ),
            (
                Dl::Delete(Collection::Patterns),
                vec![s("patterns"), s("rm"), s("p-cus-1"), s("--force")],
            ),
            (
                Dl::Create(Collection::Profiles),
                vec![s("profiles"), s("create"), s("--body"), profile.clone()],
            ),
            (
                Dl::Replace(Collection::Profiles),
                vec![
                    s("profiles"),
                    s("replace"),
                    s("dp-cus-1"),
                    s("--body"),
                    profile.clone(),
                    s("--force"),
                ],
            ),
            (
                Dl::Patch(Collection::Profiles),
                vec![
                    s("profiles"),
                    s("patch"),
                    s("dp-cus-1"),
                    s("--set"),
                    s("name=x"),
                    s("profile_type=advanced"),
                ],
            ),
            (Dl::Create(Collection::Dictionaries), dict(None)),
            (Dl::Replace(Collection::Dictionaries), dict(Some("d-cus-1"))),
            (
                Dl::Patch(Collection::Dictionaries),
                vec![
                    s("dictionaries"),
                    s("patch"),
                    s("d-cus-1"),
                    s("--set"),
                    s("name=x"),
                    s("category=Legal"),
                    s("original_file_name=k"),
                ],
            ),
            (
                Dl::Delete(Collection::Dictionaries),
                vec![s("dictionaries"), s("rm"), s("d-cus-1"), s("--force")],
            ),
            (
                Dl::Replace(Collection::FilteringProfiles),
                vec![
                    s("filtering-profiles"),
                    s("replace"),
                    s("fp-2"),
                    s("--file-based"),
                    s("--non-file-based"),
                    s("--force"),
                ],
            ),
        ]
    }

    fn tokens(f: &Fx) -> usize {
        f.server
            .routes()
            .iter()
            .filter(|route| **route == Route::Token)
            .count()
    }

    /// The arguments of `route` in the sandbox of `f`.
    fn args_of(f: &Fx, route: Dl) -> Vec<String> {
        writes(f)
            .into_iter()
            .find(|(found, _)| *found == route)
            .map(|(_, args)| args)
            .unwrap()
    }

    /// A 5xx with `Retry-After: 0` is one request and an unknown outcome (with the
    /// create hint); a 401 is `token, write, token, write`; a 403 is one request.
    #[test]
    fn every_write_is_one_attempt() {
        let routes: Vec<Dl> = writes(&fx()).into_iter().map(|(route, _)| route).collect();
        for route in routes {
            let f = fx();
            let args = args_of(&f, route);
            let args = strs(&args);
            f.server.push_once(
                Route::Dlp(route),
                Planned::json(503, &json!({"title": "busy", "status": 503})).with_retry_after(0),
            );
            let out = f.dlp(&args);
            out.assert_code(1);
            assert_eq!(f.server.dl_requests(route).len(), 1, "{route:?} 5xx");
            let resource = match route {
                Dl::Create(c) | Dl::Replace(c) | Dl::Patch(c) | Dl::Delete(c) => c,
                _ => unreachable!(),
            };
            let (thing, group) = match resource {
                Collection::Patterns => ("data pattern", "patterns"),
                Collection::Profiles => ("data profile", "profiles"),
                Collection::Dictionaries => ("dictionary", "dictionaries"),
                Collection::FilteringProfiles => ("filtering profile", "filtering-profiles"),
            };
            let done = match route {
                Dl::Create(_) => "created",
                Dl::Replace(_) => "replaced",
                Dl::Patch(_) => "patched",
                _ => "deleted",
            };
            let unknown = format!("    Outcome unknown: the {thing} may have been {done}.\n");
            assert!(out.stderr.contains(&unknown), "{route:?}: {}", out.stderr);
            if let Dl::Create(_) = route {
                let tail = if resource == Collection::Profiles {
                    "; data profiles cannot be deleted."
                } else {
                    "."
                };
                let hint = format!(
                    "{unknown}    Check 'airs runtime dlp {group} list' before creating it again{tail}\n"
                );
                assert!(out.stderr.contains(&hint), "{route:?}: {}", out.stderr);
            } else {
                assert!(!out.stderr.contains("Check '"), "{route:?}");
            }
            let f = fx();
            let args = args_of(&f, route);
            f.server
                .push_once(Route::Dlp(route), Planned::empty_json(401));
            f.dlp(&strs(&args)).assert_success();
            assert_eq!(f.server.dl_requests(route).len(), 2, "{route:?} 401");
            assert_eq!(tokens(&f), 2, "{route:?}: a fresh token for the replay");
            let f = fx();
            let args = args_of(&f, route);
            f.server
                .push_once(Route::Dlp(route), Planned::empty_json(403));
            let out = f.dlp(&strs(&args));
            out.assert_code(1);
            assert_eq!(f.server.dl_requests(route).len(), 1, "{route:?} 403");
            assert!(!out.stderr.contains("Outcome"), "{route:?}");
        }
    }

    /// A dropped connection after the write was applied: one request, the outcome line;
    /// an unreadable 2xx says the change was made.
    #[test]
    fn unknown_and_unreadable_outcomes() {
        let f = fx();
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Patterns)),
            Planned::applied_then_dropped(),
        );
        let out = f.dlp(&["patterns", "create", "--name", "x"]);
        out.assert_code(1);
        assert!(out.stderr.contains("    Outcome unknown: the data pattern may have been created.\n    Check 'airs runtime dlp patterns list' before creating it again.\n"), "{}", out.stderr);
        assert_eq!(
            f.server.dl_requests(Dl::Create(Collection::Patterns)).len(),
            1
        );
        f.server.push_once(
            Route::Dlp(Dl::Patch(Collection::Patterns)),
            Planned::raw(200, "application/json", "{not json"),
        );
        let out = f.dlp(&[
            "patterns",
            "patch",
            "p-cus-1",
            "--set",
            "name=x",
            "type=custom",
            r#"detection_config={"technique":"regex"}"#,
        ]);
        out.assert_code(1);
        assert!(
            out.stderr.contains(
                "    Outcome: the data pattern was patched, but the response could not be read.\n"
            ),
            "{}",
            out.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// Server text and sensitive data (D52, D163, §16.9)
// ---------------------------------------------------------------------------

mod text {
    use super::*;

    /// Control characters in a returned name are replaced in the ack and the prompt.
    #[test]
    fn server_text_is_terminal_safe() {
        let f = fx();
        f.server.dlp(|data| {
            data.patterns[3]["name"] = json!("Bad\u{1b}[31mName");
        });
        let out = f.dlp(&[
            "patterns",
            "patch",
            "p-cus-1",
            "--set",
            "type=custom",
            r#"detection_config={"technique":"regex"}"#,
            "name=Bad\u{1b}[31mName",
            "--output",
            "table",
        ]);
        out.assert_success();
        assert!(!out.stderr.contains('\u{1b}'), "{:?}", out.stderr);
        assert!(!out.stdout.contains('\u{1b}'), "{:?}", out.stdout);
        assert!(out.stderr.contains("Bad\u{fffd}[31mName"));
    }

    /// An echoed error body with detection content never reaches stderr (the runner's
    /// marker check), and neither do the body, the merge patch or the keyword file.
    #[test]
    fn detection_content_is_never_printed() {
        let f = fx();
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Patterns)),
            Planned::json(400, &json!({"title": "Bad Request", "status": 400, "detail": fx::content(30), "regex": fx::content(21)})),
        );
        let out = f.dlp(&[
            "patterns",
            "create",
            "--name",
            "x",
            "--regex",
            &fx::content(22),
        ]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
    }
}

// ---------------------------------------------------------------------------
// --debug (TS `unit/cli/dlp-debug.spec.ts`, §2.9)
// ---------------------------------------------------------------------------

mod debug {
    use super::*;

    /// The debug log of every write holds status and headers only: no body, no query,
    /// no detection content; the SDK operation names (G17).
    #[test]
    fn write_logs_hold_status_and_headers_only() {
        let probe = fx();
        let kw = format!("{}\n", fx::content(24));
        for (args, operations) in [
            (
                vec![
                    s("patterns"),
                    s("create"),
                    s("--name"),
                    s("x"),
                    s("--regex"),
                    fx::content(21),
                ],
                vec!["oauth.token", "dlp.data_patterns.create"],
            ),
            (
                vec![s("patterns"), s("rm"), s("p-cus-1"), s("--force")],
                vec![
                    "oauth.token",
                    "dlp.data_patterns.get",
                    "dlp.data_patterns.delete",
                ],
            ),
            (
                vec![
                    s("profiles"),
                    s("create"),
                    s("--name"),
                    s("x"),
                    s("--pattern-id"),
                    s("p-cus-1"),
                ],
                vec![
                    "oauth.token",
                    "dlp.data_patterns.get",
                    "dlp.data_profiles.create",
                ],
            ),
            (
                vec![
                    s("profiles"),
                    s("patch"),
                    s("dp-cus-1"),
                    s("--set"),
                    s("name=x"),
                    s("profile_type=advanced"),
                ],
                vec![
                    "oauth.token",
                    "dlp.data_profiles.get",
                    "dlp.data_profiles.patch",
                ],
            ),
            (
                vec![
                    s("filtering-profiles"),
                    s("replace"),
                    s("fp-2"),
                    s("--file-based"),
                    s("--non-file-based"),
                    s("--force"),
                ],
                vec![
                    "oauth.token",
                    "dlp.filtering_profiles.get",
                    "dlp.filtering_profiles.replace",
                ],
            ),
            (
                vec![s("dictionaries"), s("rm"), s("d-cus-1"), s("--force")],
                vec![
                    "oauth.token",
                    "dlp.dictionaries.get",
                    "dlp.dictionaries.delete",
                ],
            ),
            (
                vec![
                    s("dictionaries"),
                    s("patch"),
                    s("d-cus-1"),
                    s("--set"),
                    s("name=x"),
                    s("category=Legal"),
                    s("original_file_name=k"),
                ],
                vec![
                    "oauth.token",
                    "dlp.dictionaries.get",
                    "dlp.dictionaries.patch",
                ],
            ),
            (
                vec![
                    s("dictionaries"),
                    s("create"),
                    s("--name"),
                    s("D"),
                    s("--category"),
                    s("Legal"),
                    s("--region"),
                    s("US"),
                    s("--include-keywords"),
                    s("--file"),
                    s("KW"),
                ],
                vec!["oauth.token", "dlp.dictionaries.create"],
            ),
        ] {
            let f = fx();
            let path = f.file("kw.txt", kw.as_bytes());
            let args: Vec<String> = args
                .into_iter()
                .map(|arg| if arg == "KW" { path.clone() } else { arg })
                .collect();
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec![s("--debug")];
            full.extend(args.clone());
            f.dlp_with(
                &strs(&full),
                &RunOptions::new().env("XDG_STATE_HOME", &state),
            )
            .assert_success();
            let (path, records) = debug_log::only_log(&f.sandbox);
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(!text.contains("FAKE-DLP-CONTENT"), "{args:?}");
            assert!(!text.contains("keywords=true"), "{args:?}");
            assert!(!text.contains("name=x"), "{args:?}");
            let found: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .collect();
            assert_eq!(found, operations, "{args:?}");
            debug_log::assert_logs_clean(
                &f.sandbox,
                &f.server,
                &[debug_log::log_dir(&f.sandbox)],
                &[],
            );
        }
        drop(probe);
    }

    /// A usage error opens no log.
    #[test]
    fn usage_errors_open_no_log() {
        let f = bare();
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        f.dlp_with(
            &["--debug", "patterns", "create"],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        )
        .assert_code(2);
        assert!(debug_log::log_files(&debug_log::log_dir(&f.sandbox)).is_empty());
    }
}

// ---------------------------------------------------------------------------
// Tenants (TS `integration/dlp-tenant-auth.spec.ts`)
// ---------------------------------------------------------------------------

mod tenants {
    use super::*;

    /// Missing management credentials send nothing; the write goes to the tenant's
    /// `dlpEndpoint` with its bearer.
    #[test]
    fn writes_use_the_selected_tenant_only() {
        let server = FixtureServer::start();
        server.seed_dlp();
        let sandbox = Sandbox::new();
        let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
            config.remove("mgmtClientSecret");
        });
        sandbox.register(&[&tenant], Some("prod"));
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "dlp", "patterns", "create", "--name", "x"],
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert!(
            out.error_line()
                .unwrap()
                .starts_with("Management credentials are not configured")
        );
        assert_eq!(server.request_count(), 0);
        // Two tenants: the selected one (or `--tenant`) carries every request, on its
        // `dlpEndpoint` (`mgmtEndpoint` is not used).
        let server = FixtureServer::start();
        server.seed_dlp();
        let sandbox = Sandbox::new();
        let prod = sandbox.add_fixture_tenant_with(&server, "prod", "100", |config| {
            config.set("mgmtEndpoint", server.url("/not-the-dlp-host"));
        });
        let dev = sandbox.add_fixture_tenant_with(&server, "dev", "200", |config| {
            config.set("mgmtEndpoint", server.url("/not-the-dlp-host"));
        });
        sandbox.register(&[&prod, &dev], Some("prod"));
        // TS `creates and reads a pattern and advanced profile in each tenant without
        // changing credentials`.
        for (n, (tenant, tsg)) in [(None, "100"), (Some("dev"), "200")]
            .into_iter()
            .enumerate()
        {
            server.clear_requests();
            let created = format!("p-new-{}", 2 * n + 1);
            for command in [
                vec!["runtime", "dlp", "patterns", "create", "--name", "TP"],
                vec![
                    "runtime",
                    "dlp",
                    "profiles",
                    "create",
                    "--name",
                    "TPR",
                    "--pattern-id",
                    &created,
                ],
                vec!["runtime", "dlp", "patterns", "get", &created],
            ] {
                let mut args = Vec::new();
                if let Some(tenant) = tenant {
                    args.extend(["--tenant", tenant]);
                }
                args.extend(command);
                let before = sandbox.snapshot();
                run(&rust(), &sandbox, &args, &RunOptions::new()).assert_success();
                sandbox.assert_unchanged(&before);
            }
            let requests = server.requests();
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r.route != Route::Token)
                    .map(|r| r.route)
                    .collect::<Vec<_>>(),
                [
                    Route::Dlp(Dl::Create(Collection::Patterns)),
                    Route::Dlp(Dl::Get(Collection::Patterns)),
                    Route::Dlp(Dl::Create(Collection::Profiles)),
                    Route::Dlp(Dl::Get(Collection::Patterns))
                ]
            );
            for request in &requests {
                if request.route == Route::Token {
                    continue;
                }
                assert!(request.path.starts_with("/dlp/v2/api/"), "{}", request.path);
                assert_eq!(
                    request.auth,
                    airs_test_harness::AuthIdentity::Bearer { tsg: Some(s(tsg)) }
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Interruption (§16.3, D174)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    fn spawn_dlp(f: &Fx, args: &[&str], options: RunOptions) -> airs_test_harness::Running {
        let full = dlp_args(args);
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        spawn(&rust(), &f.sandbox, &full, &options.expect_signal())
    }

    /// A signal while the write is held: the change may have been applied; nothing is
    /// re-sent; afterwards the service holds the change (it applied the held write).
    #[test]
    fn a_signal_during_a_create_a_replace_or_an_upload_reports_an_unknown_outcome() {
        type Args = fn(&Fx) -> Vec<String>;
        let cases: [(Dl, Args); 3] = [
            (Dl::Create(Collection::Patterns), |_| {
                vec![s("patterns"), s("create"), s("--name"), s("held")]
            }),
            (Dl::Replace(Collection::Patterns), |_| {
                vec![
                    s("patterns"),
                    s("replace"),
                    s("p-cus-1"),
                    s("--name"),
                    s("held"),
                    s("--force"),
                ]
            }),
            (Dl::Create(Collection::Dictionaries), |f| {
                [
                    vec![s("dictionaries"), s("create")],
                    dictionary_flags(&f.file("kw.txt", b"a\n")),
                ]
                .concat()
            }),
        ];
        for (route, args) in cases {
            for (signal, code) in [("INT", 130), ("TERM", 143)] {
                let f = fx();
                let args = args(&f);
                f.server.push_once(Route::Dlp(route), Planned::held());
                let running = spawn_dlp(&f, &strs(&args), RunOptions::new());
                assert!(
                    f.server
                        .wait_for_route(Route::Dlp(route), 1, Duration::from_secs(20))
                );
                running.send_signal(signal);
                let out = running.wait();
                f.server.release_held();
                out.assert_code(code);
                assert_eq!(out.stdout, "");
                assert!(
                    out.stderr.ends_with(
                        "\n  ✗ Error: Interrupted; the change may already have been applied (outcome unknown)\n\n"
                    ),
                    "{route:?}: {}",
                    out.stderr
                );
                assert_eq!(
                    f.server.dl_requests(route).len(),
                    1,
                    "{route:?}: nothing re-sent"
                );
                let changed = match route {
                    Dl::Create(Collection::Patterns) => {
                        f.record(Collection::Patterns, "p-new-1").is_some()
                    }
                    Dl::Replace(_) => {
                        f.record(Collection::Patterns, "p-cus-1").unwrap()["name"] == "held"
                    }
                    _ => f.record(Collection::Dictionaries, "d-new-1").is_some(),
                };
                assert!(changed, "{route:?}: the service applied the held write");
            }
        }
    }

    /// `--body -` with a pipe the writer keeps open: the first signal ends the process
    /// (the wait is marked for the signal thread), with nothing sent. The debug notice,
    /// printed just before the signal thread starts, tells that the CLI is running.
    #[test]
    fn a_signal_while_a_body_is_read_from_stdin_changes_nothing() {
        let cases: [&[&str]; 3] = [
            &["patterns", "create", "--body", "-"],
            &["profiles", "create", "--body", "-"],
            &[
                "filtering-profiles",
                "replace",
                "fp-1",
                "--body",
                "-",
                "--force",
            ],
        ];
        for args in cases {
            for (signal, code) in [("INT", 130), ("TERM", 143)] {
                let f = fx();
                let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
                let mut full = vec!["--debug"];
                full.extend_from_slice(args);
                let mut running = spawn_dlp(
                    &f,
                    &full,
                    RunOptions::new()
                        .stdin_held_open()
                        .env("XDG_STATE_HOME", &state),
                );
                assert!(running.wait_for_stderr("Debug: API log", Duration::from_secs(20)));
                std::thread::sleep(Duration::from_millis(200));
                running.send_signal(signal);
                let out = running.wait();
                out.assert_code(code);
                assert_eq!(out.stdout, "");
                assert!(
                    out.stderr
                        .ends_with("\n  ✗ Error: Interrupted; nothing was changed\n\n"),
                    "{args:?}: {}",
                    out.stderr
                );
                assert_eq!(f.server.request_count(), 0, "{args:?}");
            }
        }
    }

    /// A signal before the write (the guard read hangs): nothing was changed.
    #[test]
    fn a_signal_before_the_write_changes_nothing() {
        let f = fx();
        f.server
            .push_once(Route::Dlp(Dl::Get(Collection::Patterns)), Planned::hang());
        let running = spawn_dlp(
            &f,
            &["patterns", "rm", "p-cus-1", "--force"],
            RunOptions::new(),
        );
        assert!(f.server.wait_for_route(
            Route::Dlp(Dl::Get(Collection::Patterns)),
            1,
            Duration::from_secs(20)
        ));
        running.send_signal("INT");
        let out = running.wait();
        out.assert_code(130);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; nothing was changed\n\n"
        );
        assert!(f.writes().is_empty());
    }
}

// ---------------------------------------------------------------------------
// The TypeScript integration specs, case by case (`dlp-dictionary-errors.spec.ts`,
// `dlp-profile-pattern-flags.spec.ts`)
// ---------------------------------------------------------------------------

mod typescript_specs {
    use super::*;

    /// `renders safe field-level %s errors with operational exit 1`: the allowlisted
    /// field error is printed, the rest withheld; one request with the multipart parts.
    #[test]
    fn dictionary_field_errors_are_operational() {
        for command in ["create", "replace"] {
            let f = fx();
            let file = f.file("kw.txt", b"a\n");
            let route = if command == "create" {
                Dl::Create(Collection::Dictionaries)
            } else {
                Dl::Replace(Collection::Dictionaries)
            };
            f.server.push_once(
                Route::Dlp(route),
                Planned::json(400, &json!({
                    "title": "Bad Request",
                    "status": 400,
                    "detail": format!("Rejected {}", fx::content(21)),
                    "request": {"keywords": [fx::content(22)]},
                    "errors": [
                        {"property": "originalFileName", "reason": "must not be blank", "rejectedValue": fx::content(23)},
                        {"property": "keywords", "reason": format!("contains {}", fx::content(24))}
                    ]
                })),
            );
            let mut args = vec![s("dictionaries"), s(command)];
            if command == "replace" {
                args.push(s("d-cus-1"));
            }
            args.extend(dictionary_flags(&file));
            args.push(s("--force"));
            if command == "create" {
                args.pop();
            }
            let out = f.dlp(&strs(&args));
            out.assert_code(1);
            assert!(
                out.stderr.contains("originalFileName: must not be blank"),
                "{}",
                out.stderr
            );
            assert!(!out.stderr.contains("Dictionary upload rejected"));
            assert_eq!(out.stdout, "");
            assert_eq!(f.server.dl_requests(route).len(), 1);
            let parts = multipart(&f.server.dl_requests(route)[0]).unwrap();
            assert_eq!(
                parts.part("json").unwrap().json.as_ref().unwrap()["region_name"],
                "United States"
            );
            assert!(parts.part("file").is_some());
        }
    }

    /// `offers a neutral region hint for detail-free 400 without changing the supplied
    /// region`.
    #[test]
    fn the_region_hint_keeps_the_supplied_region() {
        let f = fx();
        let file = f.file("kw.txt", b"a\n");
        let mut args = vec![s("dictionaries"), s("create")];
        args.extend(dictionary_flags(&file));
        let index = args.iter().position(|arg| arg == "United States").unwrap();
        args[index] = s("GLOBAL");
        f.server.push_once(
            Route::Dlp(Dl::Create(Collection::Dictionaries)),
            Planned::json(400, &json!({"title": "Bad Request", "status": 400})),
        );
        let out = f.dlp(&strs(&args));
        out.assert_code(1);
        assert!(out.stderr.contains("SCM region display name"));
        assert!(out.stderr.contains("United States"));
        let request = &f.server.dl_requests(Dl::Create(Collection::Dictionaries))[0];
        assert_eq!(
            multipart(request)
                .unwrap()
                .part("json")
                .unwrap()
                .json
                .as_ref()
                .unwrap()["region_name"],
            "GLOBAL"
        );
    }

    /// `classifies PATCH API rejection as operational and preserves safe validation
    /// detail`.
    #[test]
    fn a_rejected_dictionary_patch_is_operational() {
        let f = fx();
        f.server.push_once(
            Route::Dlp(Dl::Patch(Collection::Dictionaries)),
            Planned::json(400, &json!({"title": "Bad Request", "status": 400, "errors": [{"property": "originalFileName", "reason": "must not be blank"}]})),
        );
        let out = f.dlp(&[
            "dictionaries",
            "patch",
            "d-cus-1",
            "--set",
            "name=test",
            "--set",
            "category=Confidential",
            "--set",
            "original_file_name=keywords.txt",
        ]);
        out.assert_code(1);
        assert!(out.stderr.contains("originalFileName: must not be blank"));
        let methods: Vec<String> = f.writes().iter().map(|w| w.method.clone()).collect();
        assert_eq!(methods, ["PATCH"]);
    }

    /// `keeps missing %s flags as usage exit 2 before a request`, `does not echo
    /// malformed %s metadata`, `rejects nonobject metadata before upload` (file content
    /// errors exit 1 here, D164), `keeps SDK request-schema validation as usage exit 2`.
    #[test]
    fn dictionary_usage_and_metadata_errors() {
        assert_usage(
            &["dictionaries", "create"],
            "--name, --category, --region, and --file are required",
        );
        assert_usage(
            &["dictionaries", "replace", "d-cus-1", "--force"],
            "--name, --category, --region, and --file are required",
        );
        let category = fx::content(25);
        let category = format!("category={category}");
        assert_usage(
            &[
                "dictionaries",
                "patch",
                "d",
                "--set",
                "name=test",
                "--set",
                &category,
                "--set",
                "original_file_name=k.txt",
            ],
            "Invalid dictionary metadata: verify required fields and value types",
        );
        let f = fx();
        let bad = f.file(
            "metadata.json",
            format!("{{\"keywords\": {}}}", fx::content(26)).as_bytes(),
        );
        let kw = f.file("kw.txt", b"a\n");
        for args in [
            vec![
                s("dictionaries"),
                s("create"),
                s("--metadata-file"),
                bad.clone(),
                s("--file"),
                kw.clone(),
            ],
            vec![
                s("dictionaries"),
                s("replace"),
                s("d-cus-1"),
                s("--metadata-file"),
                bad.clone(),
                s("--file"),
                kw.clone(),
                s("--force"),
            ],
            vec![
                s("dictionaries"),
                s("patch"),
                s("d-cus-1"),
                s("--body-file"),
                bad.clone(),
            ],
        ] {
            let out = f.dlp(&strs(&args));
            out.assert_code(1);
            assert_eq!(
                out.error_line().as_deref(),
                Some("Invalid JSON in dictionary metadata file")
            );
        }
        assert_eq!(f.server.request_count(), 0);
    }

    /// `rejects explicit basic %s before OAuth`, `rejects basic raw %s bodies`,
    /// `rejects invalid %s before OAuth`, the 32- and 33-character names for flags and
    /// bodies, `sanitizes malformed raw JSON before OAuth`.
    #[test]
    fn profile_flag_and_body_checks() {
        let basic = "Basic profile writes are unsupported: the API returned advanced for basic requests. Use advanced or manage basic profiles in SCM.";
        for command in ["create", "replace"] {
            let mut args = vec!["profiles", command];
            if command == "replace" {
                args.push("dp-cus-1");
            }
            args.extend([
                "--name",
                "Basic",
                "--pattern-id",
                "p1",
                "--profile-type",
                "basic",
                "--force",
            ]);
            if command == "create" {
                args.pop();
            }
            assert_usage(&args, basic);
            for (flag, value, message) in [
                (
                    "--combinator",
                    "xor",
                    "--combinator must be one of and|or|not|and_not|or_not",
                ),
                (
                    "--confidence",
                    "unknown",
                    "--confidence must be low|medium|high",
                ),
            ] {
                let mut args = vec!["profiles", command];
                if command == "replace" {
                    args.extend(["dp-cus-1", "--force"]);
                }
                args.extend(["--name", "Invalid", "--pattern-id", "p1", flag, value]);
                assert_usage(&args, message);
            }
            let long = "A".repeat(33);
            let mut args = vec!["profiles", command];
            if command == "replace" {
                args.extend(["dp-cus-1", "--force"]);
            }
            args.extend(["--name", &long, "--pattern-id", "p1"]);
            assert_usage(&args, "Profile name must be at most 32 characters");
        }
        let f = fx();
        let basic_file = f.file("basic.json", br#"{"name":"Basic","profile_type":"basic"}"#);
        let long_file = f.file(
            "long.json",
            format!(
                r#"{{"name":"{}","profile_type":"advanced"}}"#,
                "A".repeat(33)
            )
            .as_bytes(),
        );
        let rules = json!([{"rule_type": "expression_tree", "expression_tree": {"operator_type": "or", "sub_expressions": [{"rule_item": {"id": "p-cus-1", "name": "My Pattern", "version": 1, "detection_technique": "regex", "confidence_level": "high", "match_type": "include", "occurrence_operator_type": "more_than_equal_to", "occurrence_count": 1}}]}}]);
        let valid_file = f.file(
            "valid.json",
            json!({"name": "A".repeat(32), "profile_type": "advanced", "detection_rules": rules})
                .to_string()
                .as_bytes(),
        );
        for command in ["create", "replace", "patch"] {
            let args = |path: &str| {
                let mut args = vec![s("profiles"), s(command)];
                if command != "create" {
                    args.push(s("dp-cus-1"));
                }
                args.extend([s("--body-file"), s(path)]);
                if command == "replace" {
                    args.push(s("--force"));
                }
                args
            };
            f.clear();
            let out = f.dlp(&strs(&args(&basic_file)));
            out.assert_code(2);
            assert_eq!(out.stderr, usage_block(basic));
            let out = f.dlp(&strs(&args(&long_file)));
            out.assert_code(2);
            assert_eq!(
                out.stderr,
                usage_block("Profile name must be at most 32 characters")
            );
            assert_eq!(f.server.request_count(), 0, "{command}: before OAuth");
            f.dlp(&strs(&args(&valid_file))).assert_success();
            let write = f.writes().pop().unwrap();
            assert_eq!(write.body_json().unwrap()["name"], json!("A".repeat(32)));
        }
        for command in ["create", "replace"] {
            let f = fx();
            let mut args = vec!["profiles", command];
            if command == "replace" {
                args.extend(["dp-cus-1", "--force"]);
            }
            let name = "A".repeat(32);
            args.extend(["--name", &name, "--pattern-id", "p-cus-1"]);
            f.dlp(&args).assert_success();
            assert_eq!(f.writes()[0].body_json().unwrap()["name"], json!(name));
        }
        let marker = fx::content(27);
        assert_usage(
            &[
                "profiles",
                "create",
                "--body",
                &format!("{{\"{marker}\":invalid}}"),
            ],
            "Cannot read profile body as JSON; verify the file and JSON syntax",
        );
    }
}
