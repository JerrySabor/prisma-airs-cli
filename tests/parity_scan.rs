//! TS-vs-Rust parity for `runtime scan` (DESIGN §8; divergences from §12).
//!
//! Every scenario runs once per CLI, each on a fresh fixture server and sandbox with the
//! same synthetic tenant (`prod`, TSG 100, every endpoint on the loopback fixture,
//! `airsNumRetries: 0` unless stated). Parity tests compare exit codes, stdout, the
//! normalised request log (plus raw body bytes and `x-payload-hash`) and the key stderr
//! lines. Divergence tests assert both sides' actual behaviour and name the §12 entry so
//! a change on either side is detected. A missing or unverified reference CLI fails each test (`AIRS_ALLOW_PARITY_SKIP=1`
//! skips it with a `PARITY SKIPPED` notice).

use std::time::Duration;

use airs_test_harness::{
    AuthIdentity, Cli, ENDPOINT_KEYS, FixtureConfig, FixtureServer, Planned, RecordedRequest,
    Route, Run, RunOptions, Sandbox, fixtures, normalise_program, normalize_all, payload_hash,
    require_ts, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------------------

const PROFILE: &str = "fixture-profile";
const API_KEY: &str = "FAKE-APIKEY-100";
const API_TOKEN: &str = "FAKE-APITOKEN-100";
const TS_DEBUG_HINT: &str = "Re-run with --debug to capture redacted API diagnostics.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// What one CLI did in one fresh scenario.
struct Outcome {
    run: Run,
    requests: Vec<RecordedRequest>,
}

impl Outcome {
    fn scans(&self) -> Vec<&RecordedRequest> {
        self.requests
            .iter()
            .filter(|request| request.route == Route::ScanSync)
            .collect()
    }

    fn routes(&self) -> Vec<Route> {
        self.requests.iter().map(|request| request.route).collect()
    }

    fn only_scan(&self) -> &RecordedRequest {
        assert_eq!(
            self.routes(),
            vec![Route::ScanSync],
            "{}: expected exactly one scan POST",
            self.run.cli
        );
        self.scans()[0]
    }
}

/// One scenario: config edit, server preparation, argv and run options.
struct Scenario<'a> {
    args: Vec<&'a str>,
    edit: Box<dyn Fn(&mut FixtureConfig) + 'a>,
    prepare: Box<dyn Fn(&FixtureServer) + 'a>,
    options: RunOptions,
    allow_unknown_routes: bool,
    with_tenant: bool,
}

impl<'a> Scenario<'a> {
    fn new(args: &[&'a str]) -> Self {
        Self {
            args: args.to_vec(),
            edit: Box::new(|_| {}),
            prepare: Box::new(|_| {}),
            options: RunOptions::new(),
            allow_unknown_routes: false,
            with_tenant: true,
        }
    }

    fn edit(mut self, edit: impl Fn(&mut FixtureConfig) + 'a) -> Self {
        self.edit = Box::new(edit);
        self
    }

    fn prepare(mut self, prepare: impl Fn(&FixtureServer) + 'a) -> Self {
        self.prepare = Box::new(prepare);
        self
    }

    /// Every scan POST answers `planned`.
    fn scan_response(self, planned: Planned) -> Self {
        self.prepare(move |server| server.set_default(Route::ScanSync, planned.clone()))
    }

    fn verdict(self, body: Value) -> Self {
        self.scan_response(Planned::json(200, &body))
    }

    fn options(mut self, options: RunOptions) -> Self {
        self.options = options;
        self
    }

    fn allow_unknown_routes(mut self) -> Self {
        self.allow_unknown_routes = true;
        self
    }

    fn without_tenant(mut self) -> Self {
        self.with_tenant = false;
        self
    }

    /// Runs `cli` on a fresh server and sandbox; checks the read-only and loopback
    /// invariants.
    fn exec(&self, cli: &Cli) -> Outcome {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        if self.with_tenant {
            let tenant = sandbox
                .add_fixture_tenant_with(&server, "prod", "100", |config| (self.edit)(config));
            for key in ENDPOINT_KEYS {
                assert!(
                    tenant
                        .config
                        .get_str(key)
                        .is_some_and(|value| value.starts_with(&server.base_url())),
                    "{key} must point at the fixture server"
                );
            }
            sandbox.register(&[&tenant], Some("prod"));
        }
        (self.prepare)(&server);
        let before = sandbox.snapshot();
        let run = airs_test_harness::run(cli, &sandbox, &self.args, &self.options);
        sandbox.assert_unchanged(&before);
        assert!(
            sandbox.home_listing().is_empty(),
            "{} wrote into HOME",
            cli.label()
        );
        assert!(
            sandbox.cwd_listing().is_empty(),
            "{} wrote into cwd",
            cli.label()
        );
        if !self.allow_unknown_routes {
            server.assert_no_unknown_routes();
        }
        Outcome {
            run,
            requests: server.requests(),
        }
    }

    /// `(rust, ts)`, or `None` after the PARITY SKIPPED notice.
    fn both(&self, test: &str) -> Option<(Outcome, Outcome)> {
        let ts = require_ts(test)?;
        Some((self.exec(&rust()), self.exec(&ts)))
    }
}

fn scan_args(prompt: &str) -> Vec<&str> {
    vec!["runtime", "scan", "--profile", PROFILE, prompt]
}

fn status_lines(profile: &str, preview: &str) -> String {
    format!("  Prisma AIRS Runtime Scan\n  Profile: {profile}\n  Prompt:  \"{preview}\"\n")
}

fn verdict(extra: Value) -> Value {
    let mut value = json!({
        "report_id": "R-1",
        "scan_id": "S-1",
        "category": "benign",
        "action": "allow",
        "timeout": false,
        "error": false,
        "errors": []
    });
    for (key, item) in extra.as_object().expect("object") {
        value[key] = item.clone();
    }
    value
}

fn block_without_response_detections() -> Value {
    let mut block = fixtures::scan_block(PROFILE);
    block
        .as_object_mut()
        .expect("object")
        .remove("response_detected");
    block
}

const ALLOW_STDOUT: &str = "\n  Scan Result\n\n  Action     ALLOW\n  Category   benign\n  Triggered  no\n  Scan ID    00000000-0000-4000-8000-0000000000a1\n  Report ID  R00000000-0000-4000-8000-0000000000a1\n";
const BLOCK_HEAD: &str = "\n  Scan Result\n\n  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n  Scan ID    00000000-0000-4000-8000-0000000000b2\n  Report ID  R00000000-0000-4000-8000-0000000000b2\n\n  Detections\n\n";

/// Same exit code, stdout and stderr bytes.
fn assert_same_streams(rust: &Outcome, ts: &Outcome) {
    assert_eq!(
        rust.run.code,
        ts.run.code,
        "exit codes differ\n{rust:?}\n{ts:?}",
        rust = rust.run,
        ts = ts.run
    );
    assert_eq!(rust.run.stdout, ts.run.stdout, "stdout differs");
    // Hints name airs (D73, pinned in tests/parity_tenant.rs).
    assert_eq!(
        normalise_program(&rust.run.stderr),
        ts.run.stderr,
        "stderr differs"
    );
}

/// Same normalised request log, plus identical raw scan bodies and payload hashes.
fn assert_same_requests(rust: &Outcome, ts: &Outcome) {
    assert_eq!(
        normalize_all(&rust.requests),
        normalize_all(&ts.requests),
        "normalised request logs differ"
    );
    let (rust_scans, ts_scans) = (rust.scans(), ts.scans());
    assert_eq!(rust_scans.len(), ts_scans.len());
    for (r, t) in rust_scans.iter().zip(&ts_scans) {
        assert_eq!(r.body, t.body, "scan body bytes differ");
        assert_eq!(r.raw_query, t.raw_query);
        for name in [
            "x-pan-token",
            "x-payload-hash",
            "authorization",
            "content-type",
            "service-name",
        ] {
            assert_eq!(r.header(name), t.header(name), "header {name} differs");
        }
        for side in [r, t] {
            assert!(
                side.header("user-agent")
                    .is_some_and(|ua| ua.starts_with("PAN-AIRS/")),
                "user-agent must start with PAN-AIRS/"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Parity: requests
// ---------------------------------------------------------------------------------------

mod parity_requests {
    use super::*;

    #[test]
    fn prompt_only_request_bytes_and_hash_identical() {
        let Some((rust, ts)) = Scenario::new(&scan_args("hello world"))
            .both("prompt_only_request_bytes_and_hash_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_same_requests(&rust, &ts);
        let request = rust.only_scan();
        assert_eq!(
            request.body_text(),
            r#"{"ai_profile":{"profile_name":"fixture-profile"},"contents":[{"prompt":"hello world"}]}"#
        );
        assert_eq!(
            ts.only_scan().header("x-payload-hash"),
            Some(payload_hash(API_KEY, &request.body).as_str())
        );
        assert_eq!(rust.run.stdout, ALLOW_STDOUT);
    }

    #[test]
    fn prompt_and_response_request_bytes_and_hash_identical() {
        let Some((rust, ts)) = Scenario::new(&[
            "runtime",
            "scan",
            "--profile",
            "p",
            "--response",
            "an answer",
            "q",
        ])
        .both("prompt_and_response_request_bytes_and_hash_identical") else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_same_requests(&rust, &ts);
        assert_eq!(
            ts.only_scan().body_text(),
            r#"{"ai_profile":{"profile_name":"p"},"contents":[{"prompt":"q","response":"an answer"}]}"#
        );
    }

    #[test]
    fn empty_response_is_omitted_by_both() {
        let Some((rust, ts)) =
            Scenario::new(&["runtime", "scan", "--profile", "p", "--response", "", "q"])
                .both("empty_response_is_omitted_by_both")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_same_requests(&rust, &ts);
        assert_eq!(
            ts.only_scan().body_text(),
            r#"{"ai_profile":{"profile_name":"p"},"contents":[{"prompt":"q"}]}"#
        );
    }

    #[test]
    fn empty_prompt_with_response_identical() {
        let Some((rust, ts)) =
            Scenario::new(&["runtime", "scan", "--profile", "p", "--response", "R", ""])
                .both("empty_prompt_with_response_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_same_requests(&rust, &ts);
        assert_eq!(
            ts.only_scan().body_text(),
            r#"{"ai_profile":{"profile_name":"p"},"contents":[{"prompt":"","response":"R"}]}"#
        );
    }

    #[test]
    fn unicode_and_control_characters_serialise_identically() {
        let prompt = "h\u{e9}llo \u{1F600} \"q\" back\\slash\nline\ttab \u{1}\u{7f} \u{2028}";
        let Some((rust, ts)) = Scenario::new(&scan_args(prompt))
            .both("unicode_and_control_characters_serialise_identically")
        else {
            return;
        };
        assert_eq!(rust.run.code, 0);
        assert_eq!(ts.run.code, 0);
        assert_eq!(rust.run.stdout, ts.run.stdout);
        assert_same_requests(&rust, &ts);
    }

    #[test]
    fn dash_values_and_double_dash_prompt_identical() {
        let Some((rust, ts)) = Scenario::new(&[
            "runtime",
            "scan",
            "--profile",
            "-p",
            "--response",
            "-x",
            "--",
            "-prompt",
        ])
        .both("dash_values_and_double_dash_prompt_identical") else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_same_requests(&rust, &ts);
    }

    #[test]
    fn token_only_tenant_identical_headers() {
        let Some((rust, ts)) = Scenario::new(&scan_args("hello world"))
            .edit(|config| {
                config.remove("airsApiKey");
                config.set("airsApiToken", API_TOKEN);
            })
            .both("token_only_tenant_identical_headers")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_same_requests(&rust, &ts);
        assert_eq!(
            ts.only_scan().auth,
            AuthIdentity::ApiToken {
                token_id: "100".into()
            }
        );
    }

    #[test]
    fn key_and_token_tenant_identical_headers() {
        let Some((rust, ts)) = Scenario::new(&scan_args("hello world"))
            .edit(|config| {
                config.set("airsApiToken", API_TOKEN);
            })
            .both("key_and_token_tenant_identical_headers")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_same_requests(&rust, &ts);
        assert_eq!(
            ts.only_scan().auth,
            AuthIdentity::ApiKeyAndToken {
                key_id: Some("100".into()),
                hash_valid: true,
                token_id: Some("100".into())
            }
        );
    }

    #[test]
    fn endpoint_environment_variable_ignored_by_both() {
        // The decoy is a second loopback server standing in for an env-provided endpoint.
        let decoy = FixtureServer::start();
        let Some((rust, ts)) = Scenario::new(&scan_args("hello world"))
            .options(RunOptions::new().env("PANW_AI_SEC_API_ENDPOINT", decoy.url("/scan")))
            .both("endpoint_environment_variable_ignored_by_both")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_same_requests(&rust, &ts);
        assert_eq!(decoy.request_count(), 0);
    }
}

// ---------------------------------------------------------------------------------------
// Parity: pretty output and status lines
// ---------------------------------------------------------------------------------------

mod parity_output {
    use super::*;

    #[test]
    fn allow_pretty_identical() {
        let Some((rust, ts)) =
            Scenario::new(&scan_args("hello world")).both("allow_pretty_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_eq!(ts.run.stdout, ALLOW_STDOUT);
        assert_eq!(ts.run.stderr, status_lines(PROFILE, "hello world"));
    }

    #[test]
    fn block_without_response_detections_pretty_identical() {
        let Some((rust, ts)) = Scenario::new(&scan_args("please block"))
            .verdict(block_without_response_detections())
            .both("block_without_response_detections_pretty_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_eq!(
            ts.run.stdout,
            format!("{BLOCK_HEAD}  ● injection\n  ● toxic_content\n")
        );
    }

    #[test]
    fn prompt_detection_order_identical() {
        let body = r#"{"report_id":"R-1","scan_id":"S-1","category":"malicious","action":"block","timeout":false,"error":false,"errors":[],"prompt_detected":{"agent":true,"source_code":true,"malicious_code":true,"url_cats":true,"dlp":true,"toxic_content":true,"injection":true,"topic_violation":true}}"#;
        let Some((rust, ts)) = Scenario::new(&scan_args("x"))
            .scan_response(Planned::raw(200, "application/json", body))
            .both("prompt_detection_order_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert!(ts.run.stdout.ends_with(
            "  ● topic_violation\n  ● injection\n  ● toxic_content\n  ● dlp\n  ● url_cats\n  ● malicious_code\n  ● source_code\n  ● agent\n"
        ));
    }

    #[test]
    fn quiet_block_identical() {
        let Some((rust, ts)) =
            Scenario::new(&["--quiet", "runtime", "scan", "--profile", PROFILE, "x"])
                .verdict(block_without_response_detections())
                .both("quiet_block_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_eq!(ts.run.stderr, "");
        assert_eq!(
            ts.run.stdout,
            "  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n  Scan ID    00000000-0000-4000-8000-0000000000b2\n  Report ID  R00000000-0000-4000-8000-0000000000b2\n  ● injection\n  ● toxic_content\n"
        );
    }

    #[test]
    fn uppercase_block_identical() {
        let Some((rust, ts)) = Scenario::new(&scan_args("x"))
            .verdict(verdict(json!({"action": "BLOCK", "category": "malicious"})))
            .both("uppercase_block_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert!(ts.run.stdout.contains("  Action     BLOCK\n"));
    }

    #[test]
    fn tenant_default_output_ignored_by_both() {
        let Some((rust, ts)) = Scenario::new(&scan_args("hello world"))
            .edit(|config| {
                config.set("defaultOutput", "json");
            })
            .both("tenant_default_output_ignored_by_both")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_eq!(ts.run.stdout, ALLOW_STDOUT);
    }

    #[test]
    fn preview_truncation_identical_ascii_and_bmp() {
        let ascii = format!("{}bcd", "a".repeat(80));
        let exact = "a".repeat(80);
        let bmp = "\u{e9}".repeat(81);
        for (name, prompt) in [("ascii", &ascii), ("exact", &exact), ("bmp", &bmp)] {
            let Some((rust, ts)) = Scenario::new(&scan_args(prompt))
                .both(&format!("preview_truncation_identical_{name}"))
            else {
                return;
            };
            assert_same_streams(&rust, &ts);
        }
    }

    #[test]
    fn newline_in_prompt_preview_identical() {
        let Some((rust, ts)) =
            Scenario::new(&scan_args("line1\nline2")).both("newline_in_prompt_preview_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
    }
}

// ---------------------------------------------------------------------------------------
// Parity: errors and request counts
// ---------------------------------------------------------------------------------------

mod parity_errors {
    use super::*;

    /// Exit 1 on both, same `✗ Error:` line, same `HTTP` line, same request log.
    fn assert_same_failure(rust: &Outcome, ts: &Outcome) {
        assert_eq!(rust.run.code, 1, "{:?}", rust.run);
        assert_eq!(ts.run.code, 1, "{:?}", ts.run);
        assert_eq!(rust.run.stdout, "");
        assert_eq!(ts.run.stdout, "");
        assert_eq!(rust.run.error_line(), ts.run.error_line());
        assert_eq!(rust.run.http_status(), ts.run.http_status());
        assert_same_requests(rust, ts);
    }

    fn http_case(test: &str, planned: Planned) -> Option<(Outcome, Outcome)> {
        Scenario::new(&scan_args("hi"))
            .scan_response(planned)
            .both(test)
    }

    #[test]
    fn status_401_empty_body_same_error_and_one_post() {
        let Some((rust, ts)) = http_case(
            "status_401_empty_body_same_error_and_one_post",
            Planned::empty_json(401),
        ) else {
            return;
        };
        assert_same_failure(&rust, &ts);
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 401")
        );
        assert_eq!(ts.run.http_status(), Some(401));
        assert_eq!(ts.scans().len(), 1);
    }

    #[test]
    fn status_403_empty_body_same_error_and_one_post() {
        let Some((rust, ts)) = http_case(
            "status_403_empty_body_same_error_and_one_post",
            Planned::empty_json(403),
        ) else {
            return;
        };
        assert_same_failure(&rust, &ts);
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 403")
        );
        assert_eq!(ts.scans().len(), 1);
    }

    #[test]
    fn status_429_empty_body_same_error_and_one_post() {
        let Some((rust, ts)) = http_case(
            "status_429_empty_body_same_error_and_one_post",
            Planned::empty_json(429).with_retry_after(0),
        ) else {
            return;
        };
        assert_same_failure(&rust, &ts);
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 429")
        );
        assert_eq!(ts.scans().len(), 1);
    }

    #[test]
    fn status_500_with_zero_retries_one_post_each() {
        let Some((rust, ts)) = http_case(
            "status_500_with_zero_retries_one_post_each",
            Planned::empty_json(500),
        ) else {
            return;
        };
        assert_same_failure(&rust, &ts);
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("AISEC_SERVER_SIDE_ERROR:API error 500")
        );
        assert_eq!(ts.scans().len(), 1);
    }

    #[test]
    fn status_503_with_zero_retries_one_post_each() {
        let Some((rust, ts)) = http_case(
            "status_503_with_zero_retries_one_post_each",
            Planned::empty_json(503).with_retry_after(0),
        ) else {
            return;
        };
        assert_same_failure(&rust, &ts);
        assert_eq!(ts.run.http_status(), Some(503));
        assert_eq!(ts.scans().len(), 1);
        assert!(rust.run.stderr.contains(
            "    Outcome unknown: the scan may have been received and processed by AIRS.\n"
        ));
    }

    #[test]
    fn missing_scanner_credentials_identical() {
        let Some((rust, ts)) = Scenario::new(&scan_args("hi"))
            .edit(|config| {
                config.remove("airsApiKey");
            })
            .both("missing_scanner_credentials_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_eq!(ts.run.code, 1);
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
        assert_eq!(
            ts.run.stderr,
            "\n  ✗ Error: Scanner credentials are not configured (airsApiKey or airsApiToken). Run 'airs-cli tenant set prod <key>' for airsApiKey (secrets prompt hidden, or use --stdin)\n\n"
        );
    }

    #[test]
    fn no_tenant_selected_identical() {
        let Some((rust, ts)) = Scenario::new(&scan_args("hi"))
            .without_tenant()
            .both("no_tenant_selected_identical")
        else {
            return;
        };
        assert_same_streams(&rust, &ts);
        assert_eq!(ts.run.code, 1);
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn null_prompt_detected_rejected_by_both() {
        // Both SDKs reject `null` for an optional object; texts differ per D38.
        let Some((rust, ts)) = Scenario::new(&scan_args("hi"))
            .verdict(verdict(json!({"prompt_detected": null})))
            .both("null_prompt_detected_rejected_by_both")
        else {
            return;
        };
        assert_eq!(rust.run.code, 1);
        assert_eq!(ts.run.code, 1);
        assert_eq!(rust.run.stdout, "");
        assert_eq!(ts.run.stdout, "");
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("AISEC_RESPONSE_VALIDATION:Response did not match the expected schema")
        );
        assert!(
            ts.run
                .error_line()
                .is_some_and(|line| line.starts_with("AISEC_RESPONSE_VALIDATION:")),
            "{:?}",
            ts.run
        );
        assert_same_requests(&rust, &ts);
    }
}

// ---------------------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D5: TS ignores `--output json` (pretty only); Rust prints the §8.5 JSON document.
    #[test]
    fn d5_output_json() {
        let Some((rust, ts)) = Scenario::new(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "json",
            "hello world",
        ])
        .both("d5_output_json") else {
            return;
        };
        assert_eq!(ts.run.code, 0);
        assert_eq!(ts.run.stdout, ALLOW_STDOUT);
        assert_eq!(rust.run.code, 0);
        let value = rust.run.json();
        assert_eq!(value["action"], "allow");
        assert_eq!(value["scanId"], "00000000-0000-4000-8000-0000000000a1");
        // Same request and status lines either way.
        assert_eq!(rust.run.stderr, ts.run.stderr);
        assert_same_requests(&rust, &ts);
    }

    /// D5: TS silently ignores unsupported (`yaml`) and invalid (`bogus`) formats; Rust
    /// rejects them as usage errors before reading the tenant.
    #[test]
    fn d5_output_yaml_and_bogus() {
        for format in ["yaml", "markdown", "csv", "bogus"] {
            let Some((rust, ts)) = Scenario::new(&[
                "runtime",
                "scan",
                "--profile",
                PROFILE,
                "--output",
                format,
                "hello world",
            ])
            .both(&format!("d5_output_{format}")) else {
                return;
            };
            assert_eq!(ts.run.code, 0, "{format}");
            assert_eq!(ts.run.stdout, ALLOW_STDOUT);
            assert_eq!(ts.scans().len(), 1);
            assert_eq!(rust.run.code, 2, "{format}");
            assert_eq!(rust.run.stdout, "");
            assert_eq!(
                rust.run.stderr,
                format!(
                    "\n  ✗ Invalid output format '{format}'. Expected: pretty, table, json\n\n"
                )
            );
            assert!(rust.requests.is_empty());
        }
    }

    /// D5: `--output table` is a Rust `Key │ Value` table of the JSON record without
    /// `result`; TS ignores the option and prints pretty. Status lines, requests and
    /// exit codes are those of pretty on both sides (a failed scan is D6).
    #[test]
    fn d5_output_table() {
        let args = [
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "table",
            "hello world",
        ];
        let Some((rust, ts)) = Scenario::new(&args).both("d5_output_table") else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(ts.run.stdout, ALLOW_STDOUT);
        let detections = r#"{"topic_violation":false,"injection":false,"toxic_content":false,"dlp":false,"url_cats":false,"malicious_code":false,"source_code":false,"agent":false}"#;
        let width = detections.len();
        let row = |key: &str, value: &str| format!(" {key:<18} │ {value:<width$} \n");
        let expected = [
            row("Key", "Value"),
            format!("{}┼{}\n", "─".repeat(20), "─".repeat(width + 2)),
            row("profileName", PROFILE),
            row("scanId", "00000000-0000-4000-8000-0000000000a1"),
            row("reportId", "R00000000-0000-4000-8000-0000000000a1"),
            row("action", "allow"),
            row("category", "benign"),
            row("triggered", "false"),
            row("detections", detections),
            row("responseDetections", "{}"),
        ]
        .concat();
        assert_eq!(rust.run.stdout, expected);
        assert_eq!(rust.run.stderr, ts.run.stderr);
        assert_same_requests(&rust, &ts);

        let block = Scenario::new(&args).verdict(fixtures::scan_block(PROFILE));
        let Some((rust, ts)) = block.both("d5_output_table_block") else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert!(ts.run.stdout.starts_with(BLOCK_HEAD));
        assert!(
            rust.run.stdout.contains(" action             │ block "),
            "{}",
            rust.run.stdout
        );
        assert!(
            rust.run.stdout.contains(" triggered          │ true "),
            "{}",
            rust.run.stdout
        );
        assert!(
            rust.run
                .stdout
                .contains(r#" responseDetections │ {"dlp":true,"url_cats":false} "#),
            "{}",
            rust.run.stdout
        );

        let failed =
            Scenario::new(&args).verdict(verdict(json!({"error": true, "category": "benign"})));
        let Some((rust, ts)) = failed.both("d5_output_table_failed") else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 0));
        let lines: Vec<&str> = rust.run.stdout.lines().collect();
        assert!(
            lines.last().is_some_and(
                |line| line.starts_with(" error ") && line.contains("AIRS scan failed")
            ),
            "{}",
            rust.run.stdout
        );
        assert!(rust.run.stdout.contains(" action             │ failed "));
        assert!(
            rust.run
                .stderr
                .ends_with("\n  ✗ Error: AIRS scan did not complete: AIRS scan failed\n\n")
        );
        assert!(!rust.run.stdout.contains("\"result\""));
    }

    /// The pretty result under forced colour (`CLICOLOR_FORCE` for Rust, `FORCE_COLOR`
    /// for TS): identical escape codes on stdout and on the status lines (§2.8, R§3.10).
    #[test]
    fn pretty_forced_colour_parity() {
        let Some(ts) = require_ts("scan_pretty_forced_colour") else {
            return;
        };
        let forced = |name: &str| RunOptions::new().without_env("NO_COLOR").env(name, "1");
        for body in [None, Some(block_without_response_detections())] {
            let scenario = |options: RunOptions| {
                let scenario = Scenario::new(&scan_args("BLOCKME please")).options(options);
                match &body {
                    Some(body) => scenario.verdict(body.clone()),
                    None => scenario,
                }
            };
            let rust_side = scenario(forced("CLICOLOR_FORCE")).exec(&rust());
            let ts_side = scenario(forced("FORCE_COLOR")).exec(&ts);
            assert_same_streams(&rust_side, &ts_side);
            assert!(
                rust_side
                    .run
                    .stdout
                    .contains("\u{1b}[2mAction   \u{1b}[22m  "),
                "{}",
                rust_side.run.stdout
            );
            assert!(
                rust_side
                    .run
                    .stderr
                    .contains("  \u{1b}[2mPrisma AIRS Runtime Scan\u{1b}[22m\n")
            );
        }
    }

    /// D6: failed / timed-out / unknown-action scans: TS shows ALLOW, Category error,
    /// exit 0 (reason discarded); Rust shows FAILED with the reason and exits 1.
    #[test]
    fn d6_failed_scans_fail_closed() {
        let cases = [
            (fixtures::scan_failed(), "dlp: error: prompt"),
            (
                verdict(json!({"timeout": true, "action": "block"})),
                "AIRS scan timed out",
            ),
            (
                verdict(json!({"action": "alert"})),
                "Unknown AIRS action: alert",
            ),
        ];
        for (body, reason) in cases {
            let Some((rust, ts)) = Scenario::new(&scan_args("x"))
                .verdict(body)
                .both("d6_failed_scans_fail_closed")
            else {
                return;
            };
            assert_eq!(ts.run.code, 0, "{reason}");
            assert!(
                ts.run
                    .stdout
                    .contains("  Action     ALLOW\n  Category   error\n  Triggered  no\n"),
                "{reason}: {}",
                ts.run.stdout
            );
            assert!(!ts.run.stdout.contains("Error"));
            assert_eq!(ts.run.stderr, status_lines(PROFILE, "x"));

            assert_eq!(rust.run.code, 1, "{reason}");
            assert!(
                rust.run
                    .stdout
                    .contains("  Action     FAILED\n  Category   error\n  Triggered  no\n")
            );
            assert!(
                rust.run
                    .stdout
                    .contains(&format!("  Error      {reason}\n"))
            );
            assert_eq!(
                rust.run.stderr,
                format!(
                    "{}\n  ✗ Error: AIRS scan did not complete: {reason}\n\n",
                    status_lines(PROFILE, "x")
                )
            );
            assert_same_requests(&rust, &ts);
        }
    }

    /// D7: TS ignores `response_detected`; Rust lists `response.<key>` bullets.
    #[test]
    fn d7_response_detections_listed() {
        let Some((rust, ts)) = Scenario::new(&scan_args("please block"))
            .verdict(fixtures::scan_block(PROFILE))
            .both("d7_response_detections_listed")
        else {
            return;
        };
        assert_eq!(ts.run.code, 0);
        assert_eq!(rust.run.code, 0);
        assert_eq!(
            ts.run.stdout,
            format!("{BLOCK_HEAD}  ● injection\n  ● toxic_content\n")
        );
        assert_eq!(
            rust.run.stdout,
            format!("{BLOCK_HEAD}  ● injection\n  ● toxic_content\n  ● response.dlp\n")
        );
        assert_eq!(rust.run.stderr, ts.run.stderr);
    }

    /// D7: a response-only detection sets Triggered in Rust only.
    #[test]
    fn d7_response_only_detection_triggers() {
        let Some((rust, ts)) = Scenario::new(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--response",
            "r",
            "x",
        ])
        .verdict(verdict(json!({"response_detected": {"ungrounded": true}})))
        .both("d7_response_only_detection_triggers") else {
            return;
        };
        assert_eq!(ts.run.code, 0);
        assert_eq!(rust.run.code, 0);
        assert!(ts.run.stdout.contains("  Triggered  no\n"));
        assert!(!ts.run.stdout.contains("Detections"));
        assert!(rust.run.stdout.contains("  Triggered  yes\n"));
        assert!(
            rust.run
                .stdout
                .ends_with("\n  Detections\n\n  ● response.ungrounded\n")
        );
    }

    /// D8: token-only tenant with `PANW_AI_SEC_API_KEY` exported: the TS SDK falls back
    /// to the environment key and sends `x-pan-token`; Rust never does.
    #[test]
    fn d8_env_api_key_fallback() {
        const ENV_KEY: &str = "ENV-LEAK-APIKEY-0001";
        let Some((rust, ts)) = Scenario::new(&scan_args("hello world"))
            .edit(|config| {
                config.remove("airsApiKey");
                config.set("airsApiToken", API_TOKEN);
            })
            .options(
                RunOptions::new()
                    .env("PANW_AI_SEC_API_KEY", ENV_KEY)
                    .secret(ENV_KEY),
            )
            .both("d8_env_api_key_fallback")
        else {
            return;
        };
        let ts_scan = ts.only_scan();
        assert_eq!(ts_scan.header("x-pan-token"), Some(ENV_KEY));
        assert_eq!(
            ts_scan.header("x-payload-hash"),
            Some(payload_hash(ENV_KEY, &ts_scan.body).as_str())
        );
        // The fixture does not know the env key, so it rejects the TS request.
        assert_eq!(ts.run.code, 1);
        assert_eq!(ts.run.http_status(), Some(401));

        let rust_scan = rust.only_scan();
        assert_eq!(rust.run.code, 0);
        assert_eq!(rust_scan.header("x-pan-token"), None);
        assert_eq!(
            rust_scan.auth,
            AuthIdentity::ApiToken {
                token_id: "100".into()
            }
        );
        assert_eq!(rust_scan.body, ts_scan.body);
    }

    /// D8: key-only tenant with `PANW_AI_SEC_API_TOKEN` exported: TS adds a bearer.
    #[test]
    fn d8_env_api_token_fallback() {
        const ENV_TOKEN: &str = "ENV-LEAK-APITOKEN-0001";
        let Some((rust, ts)) = Scenario::new(&scan_args("hello world"))
            .options(
                RunOptions::new()
                    .env("PANW_AI_SEC_API_TOKEN", ENV_TOKEN)
                    .secret(ENV_TOKEN),
            )
            .both("d8_env_api_token_fallback")
        else {
            return;
        };
        let ts_scan = ts.only_scan();
        assert_eq!(
            ts_scan.header("authorization"),
            Some(format!("Bearer {ENV_TOKEN}").as_str())
        );
        assert_eq!(ts.run.code, 1);
        let rust_scan = rust.only_scan();
        assert_eq!(rust.run.code, 0);
        assert_eq!(rust_scan.header("authorization"), None);
        assert_eq!(
            rust_scan.auth,
            AuthIdentity::ApiKey {
                key_id: Some("100".into()),
                hash_valid: true
            }
        );
    }

    /// D9: with `airsNumRetries: 2` TS re-POSTs a 503 scan twice (3 POSTs); Rust sends one.
    #[test]
    fn d9_scan_post_never_replayed() {
        let Some((rust, ts)) = Scenario::new(&scan_args("hi"))
            .edit(|config| {
                config.set("airsNumRetries", 2);
            })
            .scan_response(Planned::json(503, &json!({"message": "busy"})).with_retry_after(0))
            .both("d9_scan_post_never_replayed")
        else {
            return;
        };
        assert_eq!(ts.routes(), vec![Route::ScanSync; 3]);
        assert_eq!(rust.routes(), vec![Route::ScanSync]);
        assert_eq!(ts.run.code, 1);
        assert_eq!(rust.run.code, 1);
        assert_eq!(ts.run.http_status(), Some(503));
        assert_eq!(rust.run.http_status(), Some(503));
        // Every TS replay carries the identical body and hash.
        for replay in ts.scans() {
            assert_eq!(replay.body, rust.scans()[0].body);
            assert_eq!(
                replay.header("x-payload-hash"),
                rust.scans()[0].header("x-payload-hash")
            );
        }
    }

    /// D11: TS echoes server message text; Rust prints `API error <s>` only. Both add
    /// the `--debug` hint after the HTTP line.
    #[test]
    fn d11_server_text_not_echoed() {
        let cases = [
            (
                Planned::json(401, &json!({"message": "Invalid API key"})),
                "AISEC_CLIENT_SIDE_ERROR:Invalid API key",
                "AISEC_CLIENT_SIDE_ERROR:API error 401",
                401,
            ),
            (
                Planned::json(403, &json!({"error": {"message": "Forbidden"}})),
                "AISEC_CLIENT_SIDE_ERROR:Forbidden",
                "AISEC_CLIENT_SIDE_ERROR:API error 403",
                403,
            ),
            (
                Planned::json(429, &json!({"message": "slow down"})).with_retry_after(0),
                "AISEC_CLIENT_SIDE_ERROR:slow down",
                "AISEC_CLIENT_SIDE_ERROR:API error 429",
                429,
            ),
            (
                Planned::raw(502, "text/plain", "oops"),
                "AISEC_SERVER_SIDE_ERROR:API error 502: oops",
                "AISEC_SERVER_SIDE_ERROR:API error 502",
                502,
            ),
        ];
        for (planned, ts_line, rust_line, status) in cases {
            let Some((rust, ts)) = Scenario::new(&scan_args("hi"))
                .scan_response(planned)
                .both("d11_server_text_not_echoed")
            else {
                return;
            };
            assert_eq!(ts.run.code, 1);
            assert_eq!(rust.run.code, 1);
            assert_eq!(ts.run.error_line().as_deref(), Some(ts_line));
            assert_eq!(rust.run.error_line().as_deref(), Some(rust_line));
            assert_eq!(ts.run.http_status(), Some(status));
            assert_eq!(rust.run.http_status(), Some(status));
            let hint = format!("    HTTP {status}\n    {TS_DEBUG_HINT}\n");
            assert!(ts.run.stderr.contains(&hint));
            assert!(rust.run.stderr.contains(&hint));
            assert_eq!(ts.scans().len(), 1);
            assert_eq!(rust.scans().len(), 1);
        }
    }

    /// D11: connection refused texts differ (TS `fetch failed`); neither prints `HTTP`.
    #[test]
    fn d11_connection_refused_text() {
        let Some(ts) = require_ts("d11_connection_refused_text") else {
            return;
        };
        let run_dead = |cli: &Cli| {
            let dead = FixtureServer::start();
            let base = dead.base_url();
            drop(dead);
            let sandbox = Sandbox::new();
            let config = FixtureConfig::standard(&base, "100");
            let path = sandbox.write_fixture_config("prod", &config);
            sandbox.write_registry(
                &[airs_test_harness::RegistryEntry::new("prod", &path, "100")],
                Some("prod"),
            );
            let before = sandbox.snapshot();
            let out = airs_test_harness::run(cli, &sandbox, &scan_args("hi"), &RunOptions::new());
            sandbox.assert_unchanged(&before);
            out
        };
        let (rust, ts) = (run_dead(&rust()), run_dead(&ts));
        assert_eq!(rust.code, 1);
        assert_eq!(ts.code, 1);
        assert_eq!(rust.http_status(), None);
        assert_eq!(ts.http_status(), None);
        assert_eq!(
            rust.error_line().as_deref(),
            Some(
                "AISEC_CLIENT_SIDE_ERROR:Network request failed (connection refused, reset or unreachable)"
            )
        );
        assert_eq!(
            ts.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:fetch failed")
        );
    }

    /// D18: local input errors: TS exits 1 after the status lines; Rust exits 2 before
    /// reading the tenant. Neither sends a request.
    #[test]
    fn d18_input_validation_exit_codes() {
        let long_profile = "p".repeat(101);
        let cases: [(Vec<&str>, &str); 3] = [
            (
                vec!["runtime", "scan", "--profile", PROFILE, ""],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided",
            ),
            (
                vec!["runtime", "scan", "--profile", "", "hi"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile: custom",
            ),
            (
                vec!["runtime", "scan", "--profile", &long_profile, "hi"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile.profile_name: too_big",
            ),
        ];
        for (args, message) in cases {
            let Some((rust, ts)) = Scenario::new(&args).both("d18_input_validation_exit_codes")
            else {
                return;
            };
            assert_eq!(ts.run.code, 1, "{args:?}");
            assert_eq!(ts.run.error_line().as_deref(), Some(message));
            assert!(
                ts.run.stderr.starts_with("  Prisma AIRS Runtime Scan\n"),
                "TS prints the status lines first: {:?}",
                ts.run.stderr
            );
            assert!(ts.requests.is_empty());

            assert_eq!(rust.run.code, 2, "{args:?}");
            assert_eq!(rust.run.stderr, format!("\n  ✗ {message}\n\n"));
            assert_eq!(rust.run.stdout, "");
            assert!(rust.requests.is_empty());
        }
    }

    /// D18 + D2: with no tenant registered, TS fails on the tenant (exit 1) while Rust
    /// still reports the usage error (exit 2).
    #[test]
    fn d18_input_validation_needs_no_tenant() {
        let Some((rust, ts)) = Scenario::new(&["runtime", "scan", "--profile", PROFILE, ""])
            .without_tenant()
            .both("d18_input_validation_needs_no_tenant")
        else {
            return;
        };
        assert_eq!(ts.run.code, 1);
        assert!(
            ts.run
                .error_line()
                .is_some_and(|line| line.starts_with("No tenant selected."))
        );
        assert_eq!(rust.run.code, 2);
        assert!(rust.run.stderr.contains("must be provided"));
    }

    /// D1: a missing `--profile` is a commander error (exit 1) in TS, clap exit 2 in Rust.
    #[test]
    fn d1_missing_profile() {
        let Some((rust, ts)) = Scenario::new(&["runtime", "scan", "q"]).both("d1_missing_profile")
        else {
            return;
        };
        assert_eq!(ts.run.code, 1);
        assert_eq!(
            ts.run.stderr,
            "error: required option '--profile <name>' not specified\n"
        );
        assert_eq!(rust.run.code, 2);
        assert!(rust.run.stderr.contains("--profile"));
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    /// D30: TS follows a 302 on the scan POST to the target; Rust refuses redirects.
    #[test]
    fn d30_redirect() {
        let Some((rust, ts)) = Scenario::new(&scan_args("hi"))
            .prepare(|server| {
                server.set_default(
                    Route::ScanSync,
                    Planned::redirect(302, &server.url("/elsewhere")),
                );
            })
            .allow_unknown_routes()
            .both("d30_redirect")
        else {
            return;
        };
        assert_eq!(rust.routes(), vec![Route::ScanSync]);
        assert_eq!(rust.run.code, 1);
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:Redirect responses are not followed")
        );
        assert_eq!(rust.run.http_status(), Some(302));

        assert_eq!(ts.routes(), vec![Route::ScanSync, Route::Unknown]);
        assert_eq!(ts.requests[1].path, "/elsewhere");
        assert_eq!(ts.run.code, 1);
        assert_eq!(ts.run.http_status(), Some(404));
    }

    /// D38: decode failures: TS names the zod issues / non-JSON body; Rust prints one
    /// generic message (plus the outcome line).
    #[test]
    fn d38_response_validation_text() {
        let cases = [
            (
                Planned::raw(200, "application/json", "{not json"),
                "AISEC_RESPONSE_VALIDATION:Response body is not valid JSON",
            ),
            (
                Planned::json(
                    200,
                    &json!({"report_id": "R", "scan_id": "S", "category": "benign", "action": "allow"}),
                ),
                "AISEC_RESPONSE_VALIDATION:Response did not match schema: timeout: invalid_type; error: invalid_type; errors: invalid_type",
            ),
        ];
        for (planned, ts_line) in cases {
            let Some((rust, ts)) = Scenario::new(&scan_args("hi"))
                .scan_response(planned)
                .both("d38_response_validation_text")
            else {
                return;
            };
            assert_eq!(ts.run.code, 1);
            assert_eq!(rust.run.code, 1);
            assert_eq!(ts.run.error_line().as_deref(), Some(ts_line));
            assert_eq!(
                rust.run.error_line().as_deref(),
                Some("AISEC_RESPONSE_VALIDATION:Response did not match the expected schema")
            );
            assert_eq!(ts.run.http_status(), None);
            assert_eq!(rust.run.http_status(), None);
            assert_eq!(rust.scans().len(), 1);
            assert_eq!(ts.scans().len(), 1);
        }
    }

    /// D32: SIGINT while the scan POST is in flight: TS dies by the signal with empty
    /// streams after the status lines; Rust cancels, explains and exits 130.
    #[test]
    fn d32_sigint_during_scan() {
        let Some(ts) = require_ts("d32_sigint_during_scan") else {
            return;
        };
        let interrupt = |cli: &Cli| {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", "100");
            server.set_default(Route::ScanSync, Planned::hang());
            let before = sandbox.snapshot();
            let running = spawn(
                cli,
                &sandbox,
                &scan_args("hi"),
                &RunOptions::new().expect_signal(),
            );
            assert!(
                server.wait_for_requests(1, Duration::from_secs(20)),
                "{}: scan POST never arrived",
                cli.label()
            );
            running.send_signal("INT");
            let out = running.wait();
            assert!(
                server.wait_for_disconnects(1, Duration::from_secs(10)),
                "{}: client did not disconnect",
                cli.label()
            );
            sandbox.assert_unchanged(&before);
            (out, server.requests_for(Route::ScanSync).len())
        };
        let (rust_out, rust_posts) = interrupt(&rust());
        let (ts_out, ts_posts) = interrupt(&ts);
        assert_eq!(rust_posts, 1);
        assert_eq!(ts_posts, 1);

        assert_eq!(ts_out.signal, Some(2), "{ts_out:?}");
        assert_eq!(ts_out.stdout, "");
        assert_eq!(ts_out.stderr, status_lines(PROFILE, "hi"));

        assert_eq!(rust_out.signal, None);
        assert_eq!(rust_out.code, 130);
        assert_eq!(rust_out.stdout, "");
        assert_eq!(
            rust_out.stderr,
            format!(
                "{}\n  ✗ Error: Interrupted; the scan request may already have reached AIRS (outcome unknown)\n\n",
                status_lines(PROFILE, "hi")
            )
        );
    }

    /// D43: the TS preview slices UTF-16 units and can split a surrogate pair (written
    /// as U+FFFD); Rust drops the whole character.
    #[test]
    fn d43_preview_surrogate_split() {
        let prompt = format!("{}\u{1F600}", "a".repeat(79));
        let Some((rust, ts)) =
            Scenario::new(&scan_args(&prompt)).both("d43_preview_surrogate_split")
        else {
            return;
        };
        assert_eq!(rust.run.code, 0);
        assert_eq!(ts.run.code, 0);
        assert_eq!(rust.run.stdout, ts.run.stdout);
        assert_eq!(
            rust.run.stderr,
            status_lines(PROFILE, &format!("{}...", "a".repeat(79)))
        );
        assert_eq!(
            ts.run.stderr,
            status_lines(PROFILE, &format!("{}\u{FFFD}...", "a".repeat(79)))
        );
        assert_same_requests(&rust, &ts);
    }
}
