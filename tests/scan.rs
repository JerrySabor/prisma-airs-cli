//! Executable-level acceptance tests for `airs-cli-rs runtime scan` (DESIGN §8, plus the
//! scan rows of §2, §3.5, §5 and §6).
//!
//! Every test spawns the real binary against the loopback fixture server from
//! `crates/airs-test-harness`. Fixture tenants point every endpoint key at that server
//! (`FixtureConfig::standard`); the only exception is the Rust-only endpoint admission
//! test, which proves zero requests. After every invocation the tenant files are checked
//! unchanged and `HOME`/cwd empty; the runner's secret leak check stays on.
//!
//! Not covered here (documented in the inventory): prompt/response > 2 MiB cannot be
//! passed through argv on macOS (`ARG_MAX` = 1 MiB), so the 2,097,152-byte bound is only
//! unit-tested in `src/commands/scan.rs`; the 60 s request deadline is too slow for an
//! executable test.

use std::time::Duration;

use airs_test_harness::{
    AuthIdentity, Cli, ENDPOINT_KEYS, FixtureConfig, FixtureServer, Planned, RecordedRequest,
    RegistryEntry, Route, Run, RunOptions, Sandbox, fixtures, payload_hash, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------------------

const PROFILE: &str = "fixture-profile";
const API_KEY: &str = "FAKE-APIKEY-100";
const API_TOKEN: &str = "FAKE-APITOKEN-100";
const ALLOW_SCAN_ID: &str = "00000000-0000-4000-8000-0000000000a1";
const ALLOW_REPORT_ID: &str = "R00000000-0000-4000-8000-0000000000a1";
const BLOCK_SCAN_ID: &str = "00000000-0000-4000-8000-0000000000b2";
const BLOCK_REPORT_ID: &str = "R00000000-0000-4000-8000-0000000000b2";
const OUTCOME_UNKNOWN: &str =
    "Outcome unknown: the scan may have been received and processed by AIRS.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// A fixture server plus a sandbox with one registered, active tenant `prod` (TSG 100).
struct Env {
    server: FixtureServer,
    sandbox: Sandbox,
    config: Option<FixtureConfig>,
}

fn setup() -> Env {
    setup_with(|_| {})
}

/// Standard tenant whose config `edit` may change (credentials, retries, ...). Endpoint
/// keys must keep pointing at the fixture server; `Env::run` re-checks that.
fn setup_with(edit: impl FnOnce(&mut FixtureConfig)) -> Env {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", "100", edit);
    sandbox.register(&[&tenant], Some("prod"));
    Env {
        server,
        sandbox,
        config: Some(tenant.config),
    }
}

/// No registry at all (usage errors must not need a tenant).
fn setup_without_tenant() -> Env {
    Env {
        server: FixtureServer::start(),
        sandbox: Sandbox::new(),
        config: None,
    }
}

impl Env {
    fn run(&self, args: &[&str]) -> Run {
        self.run_opts(args, RunOptions::new())
    }

    fn run_opts(&self, args: &[&str], options: RunOptions) -> Run {
        self.assert_loopback_config();
        let before = self.sandbox.snapshot();
        let out = airs_test_harness::run(&rust(), &self.sandbox, args, &options);
        self.finish(&before);
        out
    }

    fn finish(&self, before: &airs_test_harness::Snapshot) {
        self.sandbox.assert_unchanged(before);
        assert!(
            self.sandbox.home_listing().is_empty(),
            "CLI wrote into HOME"
        );
        assert!(self.sandbox.cwd_listing().is_empty(), "CLI wrote into cwd");
        self.server.assert_no_unknown_routes();
    }

    /// Every endpoint key of the fixture tenant is present and on the fixture server.
    fn assert_loopback_config(&self) {
        let Some(config) = &self.config else { return };
        for key in ENDPOINT_KEYS {
            let value = config.get_str(key).unwrap_or_default();
            assert!(
                value.starts_with(&self.server.base_url()),
                "{key} must point at the fixture server"
            );
        }
    }

    fn scans(&self) -> Vec<RecordedRequest> {
        self.server.requests_for(Route::ScanSync)
    }

    /// Exactly one request, a sync scan POST; returns it.
    fn only_scan(&self) -> RecordedRequest {
        assert_eq!(
            self.server.routes(),
            vec![Route::ScanSync],
            "expected exactly one scan POST and nothing else (no OAuth)"
        );
        self.scans().remove(0)
    }

    fn assert_no_requests(&self) {
        assert_eq!(self.server.request_count(), 0, "expected zero requests");
        assert_eq!(self.server.connections(), 0, "expected zero connections");
    }
}

fn scan_args(prompt: &str) -> Vec<&str> {
    vec!["runtime", "scan", "--profile", PROFILE, prompt]
}

fn status_lines(profile: &str, preview: &str) -> String {
    format!("  Prisma AIRS Runtime Scan\n  Profile: {profile}\n  Prompt:  \"{preview}\"\n")
}

/// The pretty result (DESIGN §8.4).
struct Pretty<'a> {
    action: &'a str,
    category: &'a str,
    triggered: bool,
    scan_id: &'a str,
    report_id: &'a str,
    error: Option<&'a str>,
    bullets: &'a [&'a str],
}

impl Pretty<'_> {
    fn render(&self, quiet: bool) -> String {
        let mut out = String::new();
        if !quiet {
            out.push_str("\n  Scan Result\n\n");
        }
        out.push_str(&format!("  Action     {}\n", self.action));
        out.push_str(&format!("  Category   {}\n", self.category));
        out.push_str(&format!(
            "  Triggered  {}\n",
            if self.triggered { "yes" } else { "no" }
        ));
        out.push_str(&format!("  Scan ID    {}\n", self.scan_id));
        out.push_str(&format!("  Report ID  {}\n", self.report_id));
        if let Some(error) = self.error {
            out.push_str(&format!("  Error      {error}\n"));
        }
        if !self.bullets.is_empty() {
            if !quiet {
                out.push_str("\n  Detections\n\n");
            }
            for bullet in self.bullets {
                out.push_str(&format!("  ● {bullet}\n"));
            }
        }
        out
    }
}

fn allow_pretty() -> String {
    Pretty {
        action: "ALLOW",
        category: "benign",
        triggered: false,
        scan_id: ALLOW_SCAN_ID,
        report_id: ALLOW_REPORT_ID,
        error: None,
        bullets: &[],
    }
    .render(false)
}

/// A minimal valid verdict (the seven required fields) merged with `extra`.
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

/// Serves `body` (200) for every scan POST.
fn serve_verdict(env: &Env, body: &Value) {
    env.server
        .set_default(Route::ScanSync, Planned::json(200, body));
}

fn block_without_response_detections() -> Value {
    let mut block = fixtures::scan_block(PROFILE);
    block
        .as_object_mut()
        .expect("object")
        .remove("response_detected");
    block
}

fn header<'a>(request: &'a RecordedRequest, name: &str) -> Option<&'a str> {
    request.header(name)
}

fn operational(message: &str, extra: &[&str]) -> String {
    let mut text = format!("\n  ✗ Error: {message}\n");
    for line in extra {
        text.push_str(&format!("    {line}\n"));
        // DESIGN §2.2: the TS hint follows the HTTP line when --debug is off.
        if line.starts_with("HTTP ") {
            text.push_str("    Re-run with --debug to capture redacted API diagnostics.\n");
        }
    }
    text.push('\n');
    text
}

fn usage(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
}

// ---------------------------------------------------------------------------------------
// §8.2 Request bytes and headers
// ---------------------------------------------------------------------------------------

mod request {
    use super::*;

    #[test]
    fn prompt_only_body_bytes_headers_and_hash() {
        let env = setup();
        let out = env.run(&scan_args("hello world"));
        out.assert_success();
        let request = env.only_scan();
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/scan/v1/scan/sync/request");
        assert_eq!(request.raw_query, None, "no query string");
        assert_eq!(
            request.body_text(),
            r#"{"ai_profile":{"profile_name":"fixture-profile"},"contents":[{"prompt":"hello world"}]}"#
        );
        assert_eq!(header(&request, "content-type"), Some("application/json"));
        assert_eq!(header(&request, "service-name"), Some("api"));
        assert!(
            header(&request, "user-agent").is_some_and(|ua| ua.starts_with("PAN-AIRS/")),
            "user-agent must start with PAN-AIRS/: {:?}",
            header(&request, "user-agent")
        );
        assert_eq!(header(&request, "x-pan-token"), Some(API_KEY));
        assert_eq!(
            header(&request, "x-payload-hash"),
            Some(payload_hash(API_KEY, &request.body).as_str()),
            "x-payload-hash is the lowercase hex HMAC-SHA256 of the exact body"
        );
        assert_eq!(header(&request, "authorization"), None);
        assert_eq!(header(&request, "x-tsg-id"), None);
        assert_eq!(
            request.auth,
            AuthIdentity::ApiKey {
                key_id: Some("100".into()),
                hash_valid: true
            }
        );
    }

    #[test]
    fn prompt_and_response_body_bytes() {
        let env = setup();
        env.run(&[
            "runtime",
            "scan",
            "--profile",
            "p",
            "--response",
            "an answer",
            "q",
        ])
        .assert_success();
        let request = env.only_scan();
        assert_eq!(
            request.body_text(),
            r#"{"ai_profile":{"profile_name":"p"},"contents":[{"prompt":"q","response":"an answer"}]}"#
        );
        assert_eq!(
            header(&request, "x-payload-hash"),
            Some(payload_hash(API_KEY, &request.body).as_str())
        );
        assert!(matches!(
            request.auth,
            AuthIdentity::ApiKey {
                hash_valid: true,
                ..
            }
        ));
    }

    #[test]
    fn empty_response_flag_is_omitted_from_body() {
        let env = setup();
        env.run(&["runtime", "scan", "--profile", "p", "--response", "", "q"])
            .assert_success();
        assert_eq!(
            env.only_scan().body_text(),
            r#"{"ai_profile":{"profile_name":"p"},"contents":[{"prompt":"q"}]}"#
        );
    }

    #[test]
    fn empty_prompt_with_response_is_sent_with_empty_prompt() {
        let env = setup();
        let out = env.run(&["runtime", "scan", "--profile", "p", "--response", "R", ""]);
        out.assert_success();
        assert_eq!(
            env.only_scan().body_text(),
            r#"{"ai_profile":{"profile_name":"p"},"contents":[{"prompt":"","response":"R"}]}"#
        );
        assert_eq!(out.stderr, status_lines("p", ""));
    }

    #[test]
    fn json_escaping_of_unicode_quotes_and_control_characters() {
        let env = setup();
        let prompt = "h\u{e9}llo \u{1F600} \"q\" back\\slash\nline\ttab \u{1}\u{7f} \u{2028}";
        env.run(&scan_args(prompt)).assert_success();
        let request = env.only_scan();
        let expected = format!(
            "{{\"ai_profile\":{{\"profile_name\":\"fixture-profile\"}},\"contents\":[{{\"prompt\":{}}}]}}",
            "\"h\u{e9}llo \u{1F600} \\\"q\\\" back\\\\slash\\nline\\ttab \\u0001\u{7f} \u{2028}\""
        );
        assert_eq!(request.body_text(), expected);
        assert!(matches!(
            request.auth,
            AuthIdentity::ApiKey {
                hash_valid: true,
                ..
            }
        ));
    }

    #[test]
    fn option_values_may_start_with_dash_and_prompt_after_double_dash() {
        let env = setup();
        env.run(&[
            "runtime",
            "scan",
            "--profile",
            "-p",
            "--response",
            "-x",
            "--",
            "-prompt",
        ])
        .assert_success();
        assert_eq!(
            env.only_scan().body_text(),
            r#"{"ai_profile":{"profile_name":"-p"},"contents":[{"prompt":"-prompt","response":"-x"}]}"#
        );
    }

    #[test]
    fn large_prompt_is_sent_byte_exact() {
        // One argv element: Linux caps each at MAX_ARG_STRLEN (128 KiB with 4 KiB
        // pages; execve fails with E2BIG above it), so 120 KiB runs on every platform.
        // The 2 MiB bound is unit-tested.
        let env = setup();
        let prompt = "x".repeat(120 * 1024);
        let out = env.run(&scan_args(&prompt));
        out.assert_success();
        let request = env.only_scan();
        assert_eq!(
            request.body_text(),
            format!(
                r#"{{"ai_profile":{{"profile_name":"fixture-profile"}},"contents":[{{"prompt":"{prompt}"}}]}}"#
            )
        );
        assert!(matches!(
            request.auth,
            AuthIdentity::ApiKey {
                hash_valid: true,
                ..
            }
        ));
        assert_eq!(
            out.stderr,
            status_lines(PROFILE, &format!("{}...", "x".repeat(80)))
        );
    }

    #[test]
    fn token_only_tenant_sends_bearer_only() {
        let env = setup_with(|config| {
            config.remove("airsApiKey");
            config.set("airsApiToken", API_TOKEN);
        });
        env.run(&scan_args("hello world")).assert_success();
        let request = env.only_scan();
        assert_eq!(
            header(&request, "authorization"),
            Some(format!("Bearer {API_TOKEN}").as_str())
        );
        assert_eq!(header(&request, "x-pan-token"), None);
        assert_eq!(header(&request, "x-payload-hash"), None);
        assert_eq!(
            request.auth,
            AuthIdentity::ApiToken {
                token_id: "100".into()
            }
        );
    }

    #[test]
    fn key_and_token_tenant_sends_both() {
        let env = setup_with(|config| {
            config.set("airsApiToken", API_TOKEN);
        });
        env.run(&scan_args("hello world")).assert_success();
        let request = env.only_scan();
        assert_eq!(header(&request, "x-pan-token"), Some(API_KEY));
        assert_eq!(
            header(&request, "x-payload-hash"),
            Some(payload_hash(API_KEY, &request.body).as_str())
        );
        assert_eq!(
            header(&request, "authorization"),
            Some(format!("Bearer {API_TOKEN}").as_str())
        );
        assert_eq!(
            request.auth,
            AuthIdentity::ApiKeyAndToken {
                key_id: Some("100".into()),
                hash_valid: true,
                token_id: Some("100".into())
            }
        );
    }

    #[test]
    fn scanner_credentials_are_trimmed() {
        let env = setup_with(|config| {
            config.set("airsApiKey", format!("  {API_KEY}\t"));
        });
        // The server knows the padded key; register the trimmed one too.
        env.server
            .add_tenant("100", "client-100", "FAKE-SECRET-100", Some(API_KEY), None);
        env.run(&scan_args("hello world")).assert_success();
        let request = env.only_scan();
        assert_eq!(header(&request, "x-pan-token"), Some(API_KEY));
        assert_eq!(
            header(&request, "x-payload-hash"),
            Some(payload_hash(API_KEY, &request.body).as_str())
        );
    }

    #[test]
    fn management_credentials_are_neither_required_nor_sent() {
        let env = setup_with(|config| {
            config.remove("mgmtClientId");
            config.remove("mgmtClientSecret");
        });
        let out = env.run(&scan_args("hello world"));
        out.assert_success();
        assert_eq!(out.stdout, allow_pretty());
        let request = env.only_scan();
        assert_eq!(header(&request, "authorization"), None);
    }

    #[test]
    fn endpoint_path_prefix_is_kept_and_trailing_slash_dropped() {
        let env = setup_with(|config| {
            let base = config
                .get_str("airsApiEndpoint")
                .expect("endpoint")
                .to_owned();
            config.set("airsApiEndpoint", format!("{base}/"));
        });
        env.run(&scan_args("hello world")).assert_success();
        assert_eq!(env.only_scan().path, "/scan/v1/scan/sync/request");
    }

    #[test]
    fn credential_environment_variables_are_ignored() {
        // A decoy loopback server stands in for an environment-provided endpoint.
        let decoy = FixtureServer::start();
        let env = setup();
        let options = RunOptions::new()
            .env("PANW_AI_SEC_API_KEY", "ENV-LEAK-APIKEY-0001")
            .env("PANW_AI_SEC_API_TOKEN", "ENV-LEAK-APITOKEN-0001")
            .env("PANW_AI_SEC_API_ENDPOINT", decoy.url("/scan"))
            .env("PANW_AI_SEC_TIMEOUT_MS", "1")
            .secret("ENV-LEAK-APIKEY-0001")
            .secret("ENV-LEAK-APITOKEN-0001");
        let out = env.run_opts(&scan_args("hello world"), options);
        out.assert_success();
        let request = env.only_scan();
        assert_eq!(header(&request, "x-pan-token"), Some(API_KEY));
        assert_eq!(header(&request, "authorization"), None);
        assert_eq!(decoy.request_count(), 0, "env endpoint must not be used");
    }

    /// D8 (Rust side): a token-only tenant never picks up an environment API key.
    #[test]
    fn token_only_tenant_ignores_env_api_key() {
        let env = setup_with(|config| {
            config.remove("airsApiKey");
            config.set("airsApiToken", API_TOKEN);
        });
        let options = RunOptions::new()
            .env("PANW_AI_SEC_API_KEY", "ENV-LEAK-APIKEY-0001")
            .secret("ENV-LEAK-APIKEY-0001");
        env.run_opts(&scan_args("hello world"), options)
            .assert_success();
        let request = env.only_scan();
        assert_eq!(header(&request, "x-pan-token"), None);
        assert_eq!(header(&request, "x-payload-hash"), None);
        assert_eq!(
            request.auth,
            AuthIdentity::ApiToken {
                token_id: "100".into()
            }
        );
    }

    /// D8 (Rust side): a key-only tenant never picks up an environment API token.
    #[test]
    fn key_only_tenant_ignores_env_api_token() {
        let env = setup();
        let options = RunOptions::new()
            .env("PANW_AI_SEC_API_TOKEN", "ENV-LEAK-APITOKEN-0001")
            .secret("ENV-LEAK-APITOKEN-0001");
        env.run_opts(&scan_args("hello world"), options)
            .assert_success();
        assert_eq!(header(&env.only_scan(), "authorization"), None);
    }
}

// ---------------------------------------------------------------------------------------
// §8.2 status lines, §8.3/§8.4 pretty output
// ---------------------------------------------------------------------------------------

mod pretty {
    use super::*;

    #[test]
    fn allow_exact_stdout_and_stderr() {
        let env = setup();
        let out = env.run(&scan_args("hello world"));
        out.assert_success();
        assert_eq!(
            out.stdout,
            "\n  Scan Result\n\n  Action     ALLOW\n  Category   benign\n  Triggered  no\n  Scan ID    00000000-0000-4000-8000-0000000000a1\n  Report ID  R00000000-0000-4000-8000-0000000000a1\n"
        );
        assert_eq!(
            out.stderr,
            "  Prisma AIRS Runtime Scan\n  Profile: fixture-profile\n  Prompt:  \"hello world\"\n"
        );
    }

    #[test]
    fn block_without_response_detections_exact() {
        let env = setup();
        serve_verdict(&env, &block_without_response_detections());
        let out = env.run(&scan_args("please block"));
        out.assert_success();
        assert_eq!(
            out.stdout,
            "\n  Scan Result\n\n  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n  Scan ID    00000000-0000-4000-8000-0000000000b2\n  Report ID  R00000000-0000-4000-8000-0000000000b2\n\n  Detections\n\n  ● injection\n  ● toxic_content\n"
        );
        assert_eq!(out.stderr, status_lines(PROFILE, "please block"));
        env.only_scan();
    }

    /// D7: response detections are listed as `response.<key>` after prompt detections.
    #[test]
    fn block_with_response_detection_lists_response_bullet() {
        let env = setup();
        serve_verdict(&env, &fixtures::scan_block(PROFILE));
        let out = env.run(&scan_args("please block"));
        out.assert_success();
        assert_eq!(
            out.stdout,
            Pretty {
                action: "BLOCK",
                category: "malicious",
                triggered: true,
                scan_id: BLOCK_SCAN_ID,
                report_id: BLOCK_REPORT_ID,
                error: None,
                bullets: &["injection", "toxic_content", "response.dlp"],
            }
            .render(false)
        );
    }

    #[test]
    fn prompt_detections_use_fixed_order_regardless_of_json_key_order() {
        let env = setup();
        // All eight prompt keys true, in reverse of the report order.
        let body = r#"{"report_id":"R-1","scan_id":"S-1","category":"malicious","action":"block","timeout":false,"error":false,"errors":[],"prompt_detected":{"agent":true,"source_code":true,"malicious_code":true,"url_cats":true,"dlp":true,"toxic_content":true,"injection":true,"topic_violation":true}}"#;
        env.server
            .set_default(Route::ScanSync, Planned::raw(200, "application/json", body));
        let out = env.run(&scan_args("x"));
        out.assert_success();
        assert_eq!(
            out.stdout,
            Pretty {
                action: "BLOCK",
                category: "malicious",
                triggered: true,
                scan_id: "S-1",
                report_id: "R-1",
                error: None,
                bullets: &[
                    "topic_violation",
                    "injection",
                    "toxic_content",
                    "dlp",
                    "url_cats",
                    "malicious_code",
                    "source_code",
                    "agent",
                ],
            }
            .render(false)
        );
    }

    /// D7: every response key, fixed order, regardless of JSON key order.
    #[test]
    fn response_detections_use_fixed_order() {
        let env = setup();
        let body = r#"{"report_id":"R-1","scan_id":"S-1","category":"malicious","action":"block","timeout":false,"error":false,"errors":[],"prompt_detected":{"dlp":true},"response_detected":{"ungrounded":true,"db_security":true,"agent":true,"malicious_code":true,"url_cats":true,"dlp":true,"toxic_content":true,"topic_violation":true}}"#;
        env.server
            .set_default(Route::ScanSync, Planned::raw(200, "application/json", body));
        let out = env.run(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--response",
            "r",
            "x",
        ]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            Pretty {
                action: "BLOCK",
                category: "malicious",
                triggered: true,
                scan_id: "S-1",
                report_id: "R-1",
                error: None,
                bullets: &[
                    "dlp",
                    "response.topic_violation",
                    "response.toxic_content",
                    "response.dlp",
                    "response.url_cats",
                    "response.malicious_code",
                    "response.agent",
                    "response.db_security",
                    "response.ungrounded",
                ],
            }
            .render(false)
        );
    }

    /// D7: a response-only detection sets Triggered on an allow verdict.
    #[test]
    fn response_only_detection_triggers_allow() {
        let env = setup();
        serve_verdict(
            &env,
            &verdict(json!({"response_detected": {"db_security": true, "dlp": false}})),
        );
        let out = env.run(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--response",
            "r",
            "x",
        ]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            Pretty {
                action: "ALLOW",
                category: "benign",
                triggered: true,
                scan_id: "S-1",
                report_id: "R-1",
                error: None,
                bullets: &["response.db_security"],
            }
            .render(false)
        );
    }

    #[test]
    fn false_and_absent_detections_do_not_trigger() {
        let env = setup();
        serve_verdict(
            &env,
            &verdict(json!({
                "prompt_detected": {"injection": false},
                "response_detected": {"dlp": false}
            })),
        );
        let out = env.run(&scan_args("x"));
        out.assert_success();
        assert!(out.stdout.contains("  Triggered  no\n"));
        assert!(!out.stdout.contains("Detections"));
    }

    #[test]
    fn uppercase_block_and_allow_pass_through() {
        for (wire, shown) in [("BLOCK", "BLOCK"), ("Allow", "ALLOW")] {
            let env = setup();
            serve_verdict(&env, &verdict(json!({"action": wire})));
            let out = env.run(&scan_args("x"));
            out.assert_success();
            assert!(
                out.stdout.starts_with(&format!(
                    "\n  Scan Result\n\n  Action     {shown}\n  Category   benign\n"
                )),
                "{wire}: {}",
                out.stdout
            );
            assert!(!out.stdout.contains("Error"));
        }
    }

    #[test]
    fn quiet_suppresses_status_lines_and_headings() {
        let env = setup();
        serve_verdict(&env, &fixtures::scan_block(PROFILE));
        let out = env.run(&["--quiet", "runtime", "scan", "--profile", PROFILE, "x"]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert_eq!(
            out.stdout,
            "  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n  Scan ID    00000000-0000-4000-8000-0000000000b2\n  Report ID  R00000000-0000-4000-8000-0000000000b2\n  ● injection\n  ● toxic_content\n  ● response.dlp\n"
        );
    }

    #[test]
    fn quiet_after_subcommand_allow() {
        let env = setup();
        let out = env.run(&["runtime", "scan", "--profile", PROFILE, "x", "--quiet"]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert_eq!(
            out.stdout,
            Pretty {
                action: "ALLOW",
                category: "benign",
                triggered: false,
                scan_id: ALLOW_SCAN_ID,
                report_id: ALLOW_REPORT_ID,
                error: None,
                bullets: &[],
            }
            .render(true)
        );
    }

    #[test]
    fn tenant_default_output_is_ignored() {
        for default in ["json", "table"] {
            let env = setup_with(|config| {
                config.set("defaultOutput", default);
            });
            let out = env.run(&scan_args("hello world"));
            out.assert_success();
            assert_eq!(out.stdout, allow_pretty(), "defaultOutput {default}");
            assert_eq!(out.stderr, status_lines(PROFILE, "hello world"));
        }
    }

    #[test]
    fn explicit_pretty_output() {
        let env = setup();
        let out = env.run(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "pretty",
            "hello world",
        ]);
        out.assert_success();
        assert_eq!(out.stdout, allow_pretty());
    }
}

mod preview {
    use super::*;

    fn stderr_for(prompt: &str) -> String {
        let env = setup();
        let out = env.run(&scan_args(prompt));
        out.assert_success();
        env.only_scan();
        out.stderr
    }

    #[test]
    fn exactly_80_characters_is_not_truncated() {
        let prompt = "a".repeat(80);
        assert_eq!(stderr_for(&prompt), status_lines(PROFILE, &prompt));
    }

    #[test]
    fn longer_than_80_is_truncated_with_ellipsis() {
        let prompt = format!("{}bcd", "a".repeat(80));
        assert_eq!(
            stderr_for(&prompt),
            status_lines(PROFILE, &format!("{}...", "a".repeat(80)))
        );
    }

    #[test]
    fn multibyte_bmp_characters_count_as_one() {
        // 'é' is 2 UTF-8 bytes but 1 UTF-16 unit.
        let exact = "\u{e9}".repeat(80);
        assert_eq!(stderr_for(&exact), status_lines(PROFILE, &exact));
        let long = "\u{e9}".repeat(81);
        assert_eq!(
            stderr_for(&long),
            status_lines(PROFILE, &format!("{}...", "\u{e9}".repeat(80)))
        );
    }

    #[test]
    fn astral_character_straddling_the_limit_is_not_split() {
        // 79 units + an emoji (2 UTF-16 units) = 81 units: the emoji is dropped whole.
        let prompt = format!("{}\u{1F600}", "a".repeat(79));
        assert_eq!(
            stderr_for(&prompt),
            status_lines(PROFILE, &format!("{}...", "a".repeat(79)))
        );
        // 78 units + emoji = 80 units: shown whole, no ellipsis.
        let fits = format!("{}\u{1F600}", "a".repeat(78));
        assert_eq!(stderr_for(&fits), status_lines(PROFILE, &fits));
    }

    #[test]
    fn prompt_newlines_are_embedded_raw() {
        assert_eq!(
            stderr_for("line1\nline2"),
            status_lines(PROFILE, "line1\nline2")
        );
    }
}

// ---------------------------------------------------------------------------------------
// §8.3 fail closed (D6)
// ---------------------------------------------------------------------------------------

mod failed {
    use super::*;

    fn failed_run(body: &Value, args: &[&str]) -> (Env, Run) {
        let env = setup();
        serve_verdict(&env, body);
        let out = env.run(args);
        out.assert_code(1);
        env.only_scan();
        (env, out)
    }

    fn did_not_complete(reason: &str) -> String {
        operational(&format!("AIRS scan did not complete: {reason}"), &[])
    }

    #[test]
    fn engine_error_with_errors_entries() {
        let (_, out) = failed_run(&fixtures::scan_failed(), &scan_args("x"));
        assert_eq!(
            out.stdout,
            Pretty {
                action: "FAILED",
                category: "error",
                triggered: false,
                scan_id: "00000000-0000-4000-8000-0000000000c3",
                report_id: "R00000000-0000-4000-8000-0000000000c3",
                error: Some("dlp: error: prompt"),
                bullets: &[],
            }
            .render(false)
        );
        assert_eq!(
            out.stderr,
            format!(
                "{}{}",
                status_lines(PROFILE, "x"),
                did_not_complete("dlp: error: prompt")
            )
        );
    }

    #[test]
    fn several_errors_entries_are_joined() {
        let body = verdict(json!({
            "error": true,
            "errors": [
                {"content_type": "prompt", "feature": "dlp", "status": "error"},
                {"content_type": "response", "feature": "toxic_content", "status": "timeout"}
            ]
        }));
        let (_, out) = failed_run(&body, &scan_args("x"));
        let reason = "dlp: error: prompt; toxic_content: timeout: response";
        assert!(out.stdout.contains(&format!("  Error      {reason}\n")));
        assert!(out.stderr.ends_with(&did_not_complete(reason)));
    }

    #[test]
    fn timeout_true_fails_even_with_block_action() {
        let body = verdict(json!({"timeout": true, "action": "block", "category": "malicious"}));
        let (_, out) = failed_run(&body, &scan_args("x"));
        assert_eq!(
            out.stdout,
            Pretty {
                action: "FAILED",
                category: "error",
                triggered: false,
                scan_id: "S-1",
                report_id: "R-1",
                error: Some("AIRS scan timed out"),
                bullets: &[],
            }
            .render(false)
        );
        assert!(
            out.stderr
                .ends_with(&did_not_complete("AIRS scan timed out"))
        );
    }

    #[test]
    fn error_true_without_entries() {
        let (_, out) = failed_run(&verdict(json!({"error": true})), &scan_args("x"));
        assert!(
            out.stdout
                .contains("  Action     FAILED\n  Category   error\n")
        );
        assert!(out.stdout.contains("  Error      AIRS scan failed\n"));
        assert!(out.stderr.ends_with(&did_not_complete("AIRS scan failed")));
    }

    #[test]
    fn unknown_action_alert() {
        let (_, out) = failed_run(&verdict(json!({"action": "alert"})), &scan_args("x"));
        assert_eq!(
            out.stdout,
            Pretty {
                action: "FAILED",
                category: "error",
                triggered: false,
                scan_id: "S-1",
                report_id: "R-1",
                error: Some("Unknown AIRS action: alert"),
                bullets: &[],
            }
            .render(false)
        );
        assert!(
            out.stderr
                .ends_with(&did_not_complete("Unknown AIRS action: alert"))
        );
    }

    #[test]
    fn failed_with_detections_shows_error_line_then_detections() {
        let body = verdict(json!({
            "error": true,
            "prompt_detected": {"injection": true}
        }));
        let (_, out) = failed_run(&body, &scan_args("x"));
        assert_eq!(
            out.stdout,
            Pretty {
                action: "FAILED",
                category: "error",
                triggered: true,
                scan_id: "S-1",
                report_id: "R-1",
                error: Some("AIRS scan failed"),
                bullets: &["injection"],
            }
            .render(false)
        );
    }

    #[test]
    fn quiet_failed_keeps_error_on_stderr() {
        let (_, out) = failed_run(
            &fixtures::scan_failed(),
            &["--quiet", "runtime", "scan", "--profile", PROFILE, "x"],
        );
        assert_eq!(
            out.stdout,
            "  Action     FAILED\n  Category   error\n  Triggered  no\n  Scan ID    00000000-0000-4000-8000-0000000000c3\n  Report ID  R00000000-0000-4000-8000-0000000000c3\n  Error      dlp: error: prompt\n"
        );
        assert_eq!(out.stderr, did_not_complete("dlp: error: prompt"));
    }
}

// ---------------------------------------------------------------------------------------
// §8.5 JSON output (D5)
// ---------------------------------------------------------------------------------------

mod json_output {
    use super::*;

    /// Top-level keys of a 2-space pretty JSON object, in document order.
    fn top_level_keys(text: &str) -> Vec<String> {
        text.lines()
            .filter(|line| line.starts_with("  \""))
            .filter_map(|line| line.trim_start().split('"').nth(1).map(str::to_owned))
            .collect()
    }

    /// Keys of the nested object `name` (4-space indented), in document order.
    fn nested_keys(text: &str, name: &str) -> Vec<String> {
        let start = format!("  \"{name}\": {{\n");
        let Some(index) = text.find(&start) else {
            return Vec::new();
        };
        text[index + start.len()..]
            .lines()
            .take_while(|line| line.starts_with("    "))
            .filter(|line| line.starts_with("    \""))
            .filter_map(|line| line.trim_start().split('"').nth(1).map(str::to_owned))
            .collect()
    }

    #[test]
    fn allow_shape_key_order_and_result() {
        let env = setup();
        let prompt = "SECRET-PROMPT-TEXT-0001";
        let out = env.run(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "json",
            prompt,
        ]);
        out.assert_success();
        assert_eq!(out.stderr, status_lines(PROFILE, prompt));
        assert!(out.stdout.ends_with("}\n"));
        assert!(!out.stdout.contains(prompt), "prompt must not be echoed");
        let value = out.json();
        assert_eq!(
            top_level_keys(&out.stdout),
            [
                "profileName",
                "scanId",
                "reportId",
                "action",
                "category",
                "triggered",
                "detections",
                "responseDetections",
                "result"
            ]
        );
        assert_eq!(value["profileName"], PROFILE);
        assert_eq!(value["scanId"], ALLOW_SCAN_ID);
        assert_eq!(value["reportId"], ALLOW_REPORT_ID);
        assert_eq!(value["action"], "allow");
        assert_eq!(value["category"], "benign");
        assert_eq!(value["triggered"], false);
        assert_eq!(
            nested_keys(&out.stdout, "detections"),
            [
                "topic_violation",
                "injection",
                "toxic_content",
                "dlp",
                "url_cats",
                "malicious_code",
                "source_code",
                "agent"
            ]
        );
        assert!(
            value["detections"]
                .as_object()
                .expect("object")
                .values()
                .all(|flag| flag == &json!(false))
        );
        assert_eq!(value["responseDetections"], json!({}));
        assert!(value.get("error").is_none());
        airs_test_harness::assert_json_semantic_eq(
            &value["result"],
            &fixtures::scan_allow(PROFILE),
        );
        env.only_scan();
    }

    #[test]
    fn block_with_response_detections() {
        let env = setup();
        serve_verdict(&env, &fixtures::scan_block(PROFILE));
        let out = env.run(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--response",
            "RESPONSE-TEXT-0001",
            "--output",
            "json",
            "PROMPT-TEXT-0001",
        ]);
        out.assert_success();
        let value = out.json();
        assert_eq!(value["action"], "block");
        assert_eq!(value["category"], "malicious");
        assert_eq!(value["triggered"], true);
        assert_eq!(
            nested_keys(&out.stdout, "responseDetections"),
            ["dlp", "url_cats"]
        );
        assert_eq!(
            value["responseDetections"],
            json!({"dlp": true, "url_cats": false})
        );
        assert_eq!(value["detections"]["injection"], true);
        assert_eq!(value["detections"]["toxic_content"], true);
        assert!(!out.stdout.contains("RESPONSE-TEXT-0001"));
        assert!(!out.stdout.contains("PROMPT-TEXT-0001"));
        airs_test_harness::assert_json_semantic_eq(
            &value["result"],
            &fixtures::scan_block(PROFILE),
        );
    }

    #[test]
    fn result_preserves_unknown_fields() {
        let env = setup();
        let body = verdict(json!({
            "zz_future": {"b": 1, "a": [2.0, "x"], "c": null},
            "prompt_detected": {"dlp": false, "new_detector": true},
            "tool_detected": {"anything": {"nested": true}}
        }));
        serve_verdict(&env, &body);
        let out = env.run(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "json",
            "x",
        ]);
        out.assert_success();
        let value = out.json();
        airs_test_harness::assert_json_semantic_eq(&value["result"], &body);
        // Only the eight known prompt keys are normalised.
        assert_eq!(value["detections"], json!({"dlp": false}));
        assert_eq!(value["triggered"], false);
    }

    #[test]
    fn failed_json_has_error_and_exit_1() {
        let env = setup();
        serve_verdict(&env, &fixtures::scan_failed());
        let out = env.run(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "json",
            "x",
        ]);
        out.assert_code(1);
        let value = out.json();
        assert_eq!(
            top_level_keys(&out.stdout),
            [
                "profileName",
                "scanId",
                "reportId",
                "action",
                "category",
                "triggered",
                "detections",
                "responseDetections",
                "error",
                "result"
            ]
        );
        assert_eq!(value["action"], "failed");
        assert_eq!(value["category"], "error");
        assert_eq!(value["error"], "dlp: error: prompt");
        assert_eq!(value["detections"], json!({}));
        airs_test_harness::assert_json_semantic_eq(&value["result"], &fixtures::scan_failed());
        assert_eq!(
            out.stderr,
            format!(
                "{}{}",
                status_lines(PROFILE, "x"),
                operational("AIRS scan did not complete: dlp: error: prompt", &[])
            )
        );
    }

    #[test]
    fn quiet_json_has_empty_stderr() {
        let env = setup();
        let out = env.run(&[
            "--quiet",
            "--output",
            "json",
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "x",
        ]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert_eq!(out.json()["action"], "allow");
    }

    #[test]
    fn output_flag_last_occurrence_wins() {
        let env = setup();
        let out = env.run(&[
            "--output",
            "yaml",
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "json",
            "x",
        ]);
        out.assert_success();
        assert_eq!(out.json()["action"], "allow");

        let env = setup();
        let out = env.run(&[
            "--output",
            "json",
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "pretty",
            "x",
        ]);
        out.assert_success();
        assert_eq!(out.stdout, allow_pretty());
    }

    #[test]
    fn json_output_ignores_tenant_default_output() {
        let env = setup_with(|config| {
            config.set("defaultOutput", "pretty");
        });
        let out = env.run(&[
            "runtime",
            "scan",
            "--profile",
            PROFILE,
            "--output",
            "json",
            "x",
        ]);
        out.assert_success();
        assert_eq!(out.json()["action"], "allow");
    }
}

// ---------------------------------------------------------------------------------------
// §8.1 input validation and §2.4 output formats: usage errors (exit 2), zero requests,
// no tenant needed
// ---------------------------------------------------------------------------------------

mod usage_errors {
    use super::*;

    const EMPTY_CONTENT: &str = "AISEC_USER_REQUEST_PAYLOAD_ERROR:At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided";
    const EMPTY_PROFILE: &str = "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile: custom";
    const LONG_PROFILE: &str = "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile.profile_name: too_big";

    /// Asserts exit 2, the exact usage stderr, empty stdout and zero requests, both with
    /// a valid tenant and with no registry at all.
    fn assert_usage(args: &[&str], message: &str) {
        for env in [setup(), setup_without_tenant()] {
            let out = env.run(args);
            out.assert_code(2);
            assert_eq!(out.stdout, "");
            assert_eq!(out.stderr, usage(message));
            env.assert_no_requests();
        }
    }

    #[test]
    fn empty_prompt_without_response() {
        assert_usage(
            &["runtime", "scan", "--profile", PROFILE, ""],
            EMPTY_CONTENT,
        );
    }

    #[test]
    fn empty_prompt_with_empty_response() {
        assert_usage(
            &[
                "runtime",
                "scan",
                "--profile",
                PROFILE,
                "--response",
                "",
                "",
            ],
            EMPTY_CONTENT,
        );
    }

    #[test]
    fn empty_profile() {
        assert_usage(&["runtime", "scan", "--profile", "", "hi"], EMPTY_PROFILE);
    }

    #[test]
    fn empty_content_is_reported_before_empty_profile() {
        assert_usage(&["runtime", "scan", "--profile", "", ""], EMPTY_CONTENT);
    }

    #[test]
    fn profile_of_101_units_is_too_big() {
        let profile = "p".repeat(101);
        assert_usage(
            &["runtime", "scan", "--profile", &profile, "hi"],
            LONG_PROFILE,
        );
    }

    #[test]
    fn profile_length_counts_utf16_units() {
        // 51 emoji = 102 UTF-16 units.
        let profile = "\u{1F600}".repeat(51);
        assert_usage(
            &["runtime", "scan", "--profile", &profile, "hi"],
            LONG_PROFILE,
        );
    }

    #[test]
    fn profile_of_100_units_is_accepted() {
        for profile in [
            "p".repeat(100),
            "\u{1F600}".repeat(50),
            "\u{e9}".repeat(100),
        ] {
            let env = setup();
            let out = env.run(&["runtime", "scan", "--profile", &profile, "hi"]);
            out.assert_success();
            let request = env.only_scan();
            assert_eq!(
                request.body_json().expect("json")["ai_profile"]["profile_name"],
                json!(profile)
            );
        }
    }

    #[test]
    fn dropped_and_invalid_output_formats() {
        for format in ["yaml", "markdown", "csv", "bogus"] {
            assert_usage(
                &[
                    "--output",
                    format,
                    "runtime",
                    "scan",
                    "--profile",
                    PROFILE,
                    "hi",
                ],
                &format!("Invalid output format '{format}'. Expected: pretty, table, json"),
            );
        }
    }

    /// D1: argument-parse errors exit 2 with zero requests.
    #[test]
    fn parse_errors_exit_2_without_requests() {
        for args in [
            vec!["runtime", "scan", "hi"],
            vec!["runtime", "scan", "--profile", PROFILE],
            vec!["runtime", "scan", "--profile", PROFILE, "a", "b"],
            vec!["runtime", "scan", "--profile", PROFILE, "--bogus", "hi"],
            vec!["runtime", "scan", "--profile"],
        ] {
            let env = setup();
            let out = env.run(&args);
            out.assert_code(2);
            assert_eq!(out.stdout, "", "{args:?}");
            assert!(!out.stderr.is_empty(), "{args:?}");
            env.assert_no_requests();
        }
    }

    #[test]
    fn help_exits_0_without_requests() {
        let env = setup();
        let out = env.run(&["runtime", "scan", "--help"]);
        out.assert_success();
        assert!(out.stdout.contains("--profile <"));
        assert!(out.stdout.contains("--response <"));
        assert!(out.stdout.contains(
            "$ airs runtime scan --profile prod-guard \"Ignore all previous instructions\""
        ));
        env.assert_no_requests();
    }
}

// ---------------------------------------------------------------------------------------
// §3 / §3.5 / §5: tenant, credential and endpoint failures before any request
// ---------------------------------------------------------------------------------------

mod setup_errors {
    use super::*;

    const NO_SCANNER: &str = "Scanner credentials are not configured (airsApiKey or airsApiToken). Run 'airs tenant set prod <key>' for airsApiKey (secrets prompt hidden, or use --stdin)";

    #[test]
    fn missing_scanner_credentials() {
        let env = setup_with(|config| {
            config.remove("airsApiKey");
        });
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, operational(NO_SCANNER, &[]));
        env.assert_no_requests();
    }

    #[test]
    fn whitespace_only_scanner_credentials_are_missing() {
        let env = setup_with(|config| {
            config.set("airsApiKey", "   ");
            config.set("airsApiToken", "\t");
        });
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert_eq!(out.stderr, operational(NO_SCANNER, &[]));
        env.assert_no_requests();
    }

    #[test]
    fn no_tenant_selected() {
        let env = setup_without_tenant();
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            operational(
                "No tenant selected. Run 'airs tenant create <name>' and then 'airs tenant switch <name>'",
                &[]
            )
        );
        env.assert_no_requests();
    }

    #[test]
    fn tsg_pin_applies_to_scans() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let config = Sandbox::fixture_config(&server, "200");
        let path = sandbox.write_fixture_config("prod", &config);
        sandbox.write_registry(&[RegistryEntry::new("prod", &path, "100")], Some("prod"));
        let env = Env {
            server,
            sandbox,
            config: Some(config),
        };
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            operational(
                "Tenant config TSG differs from its registered identity; register it under a new name",
                &[]
            )
        );
        env.assert_no_requests();
    }

    /// Rust-only: a non-loopback http endpoint is rejected locally (never contacted).
    #[test]
    fn non_loopback_http_endpoint_is_rejected_without_requests() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        // Rust-only (harness opt-out): the value never reaches the network.
        let tenant = sandbox.add_fixture_tenant_allowing_external_endpoints(
            &server,
            "prod",
            "100",
            |config| {
                config.set("airsApiEndpoint", "http://example.test/scan");
            },
        );
        sandbox.register(&[&tenant], Some("prod"));
        let before = sandbox.snapshot();
        let out = airs_test_harness::run(&rust(), &sandbox, &scan_args("hi"), &RunOptions::new());
        sandbox.assert_unchanged(&before);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            operational(
                "Invalid airsApiEndpoint: endpoints must use https (http is allowed only for loopback hosts) and must not contain credentials, a query or a fragment",
                &[]
            )
        );
        assert!(
            !out.stderr.contains("example.test"),
            "value must not be echoed"
        );
        assert_eq!(server.request_count(), 0);
    }

    #[test]
    fn endpoint_with_query_is_rejected_without_requests() {
        let env = setup_with(|config| {
            let base = config
                .get_str("airsApiEndpoint")
                .expect("endpoint")
                .to_owned();
            config.set("airsApiEndpoint", format!("{base}?q=1"));
        });
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert!(
            out.error_line()
                .is_some_and(|line| line.starts_with("Invalid airsApiEndpoint: "))
        );
        env.assert_no_requests();
    }
}

// ---------------------------------------------------------------------------------------
// §6 HTTP / network / decode errors on the scan POST
// ---------------------------------------------------------------------------------------

mod http_errors {
    use super::*;

    /// One scan POST answered with `planned`; exit 1, empty stdout, exactly one request.
    fn failing(planned: Planned) -> (Env, Run) {
        let env = setup();
        env.server.set_default(Route::ScanSync, planned);
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            env.scans().len(),
            1,
            "exactly one scan POST, never replayed"
        );
        env.only_scan();
        (env, out)
    }

    fn expect_stderr(out: &Run, message: &str, extra: &[&str]) {
        assert_eq!(
            out.stderr,
            format!(
                "{}{}",
                status_lines(PROFILE, "hi"),
                operational(message, extra)
            )
        );
    }

    #[test]
    fn status_401_one_attempt_no_outcome_line() {
        let (_, out) = failing(Planned::json(401, &json!({"message": "Invalid API key"})));
        expect_stderr(&out, "AISEC_CLIENT_SIDE_ERROR:API error 401", &["HTTP 401"]);
    }

    #[test]
    fn status_403_server_text_not_echoed() {
        let (_, out) = failing(Planned::json(
            403,
            &json!({"error": {"message": "Forbidden"}}),
        ));
        expect_stderr(&out, "AISEC_CLIENT_SIDE_ERROR:API error 403", &["HTTP 403"]);
    }

    #[test]
    fn status_403_with_error_code() {
        let (_, out) = failing(Planned::json(
            403,
            &json!({"error": {"code": "AIRS-403-01", "message": "Forbidden"}}),
        ));
        expect_stderr(
            &out,
            "AISEC_CLIENT_SIDE_ERROR:API error 403 (errorCode: AIRS-403-01)",
            &["HTTP 403"],
        );
    }

    #[test]
    fn status_429_is_not_retried() {
        let (_, out) =
            failing(Planned::json(429, &json!({"message": "slow down"})).with_retry_after(0));
        expect_stderr(&out, "AISEC_CLIENT_SIDE_ERROR:API error 429", &["HTTP 429"]);
    }

    #[test]
    fn status_500_outcome_unknown() {
        let (_, out) = failing(Planned::empty_json(500));
        expect_stderr(
            &out,
            "AISEC_SERVER_SIDE_ERROR:API error 500",
            &["HTTP 500", OUTCOME_UNKNOWN],
        );
    }

    #[test]
    fn status_503_with_retry_after_is_one_post_outcome_unknown() {
        let (_, out) = failing(Planned::json(503, &json!({"message": "busy"})).with_retry_after(0));
        expect_stderr(
            &out,
            "AISEC_SERVER_SIDE_ERROR:API error 503",
            &["HTTP 503", OUTCOME_UNKNOWN],
        );
    }

    /// D9: `airsNumRetries` never replays the scan POST.
    #[test]
    fn status_503_with_num_retries_5_is_still_one_post() {
        let env = setup_with(|config| {
            config.set("airsNumRetries", 5);
        });
        env.server.set_default(
            Route::ScanSync,
            Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
        );
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert_eq!(env.scans().len(), 1);
        assert_eq!(out.http_status(), Some(503));
    }

    #[test]
    fn status_502_non_json_body_not_echoed() {
        let (_, out) = failing(Planned::raw(502, "text/plain", "oops upstream body"));
        expect_stderr(
            &out,
            "AISEC_SERVER_SIDE_ERROR:API error 502",
            &["HTTP 502", OUTCOME_UNKNOWN],
        );
    }

    #[test]
    fn request_id_header_is_reported() {
        let (_, out) = failing(Planned::empty_json(500).with_header("x-request-id", "req-0001"));
        expect_stderr(
            &out,
            "AISEC_SERVER_SIDE_ERROR:API error 500",
            &["HTTP 500", "Request ID: req-0001", OUTCOME_UNKNOWN],
        );
    }

    #[test]
    fn server_echoing_the_api_key_is_never_printed() {
        let (_, out) = failing(
            Planned::json(
                401,
                &json!({"message": format!("key {API_KEY} rejected"), "code": API_KEY}),
            )
            .with_header("x-request-id", API_KEY),
        );
        // The runner's leak check already proved the key is absent from both streams.
        expect_stderr(&out, "AISEC_CLIENT_SIDE_ERROR:API error 401", &["HTTP 401"]);
    }

    #[test]
    fn server_echoing_the_api_token_is_never_printed() {
        let env = setup_with(|config| {
            config.remove("airsApiKey");
            config.set("airsApiToken", API_TOKEN);
        });
        env.server.set_default(
            Route::ScanSync,
            Planned::json(
                500,
                &json!({"message": API_TOKEN, "error": {"code": API_TOKEN}}),
            )
            .with_header("x-correlation-id", API_TOKEN),
        );
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            format!(
                "{}{}",
                status_lines(PROFILE, "hi"),
                operational(
                    "AISEC_SERVER_SIDE_ERROR:API error 500",
                    &["HTTP 500", OUTCOME_UNKNOWN]
                )
            )
        );
    }

    #[test]
    fn redirect_is_not_followed() {
        let env = setup();
        env.server.set_default(
            Route::ScanSync,
            Planned::redirect(302, &env.server.url("/elsewhere")),
        );
        let out = env.run(&scan_args("hi"));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        env.only_scan(); // nothing reached /elsewhere
        assert_eq!(
            out.stderr,
            format!(
                "{}{}",
                status_lines(PROFILE, "hi"),
                operational(
                    "AISEC_CLIENT_SIDE_ERROR:Redirect responses are not followed",
                    &["HTTP 302"]
                )
            )
        );
    }

    #[test]
    fn ok_with_non_json_body() {
        let (_, out) = failing(Planned::raw(200, "application/json", "{not json"));
        expect_stderr(
            &out,
            "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema",
            &[OUTCOME_UNKNOWN],
        );
    }

    #[test]
    fn ok_missing_required_fields() {
        let (_, out) = failing(Planned::json(
            200,
            &json!({"report_id": "R", "scan_id": "S", "category": "benign", "action": "allow"}),
        ));
        expect_stderr(
            &out,
            "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema",
            &[OUTCOME_UNKNOWN],
        );
    }

    #[test]
    fn ok_with_non_boolean_detection() {
        let (_, out) = failing(Planned::json(
            200,
            &verdict(json!({"prompt_detected": {"injection": "yes"}})),
        ));
        expect_stderr(
            &out,
            "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema",
            &[OUTCOME_UNKNOWN],
        );
    }

    /// `prompt_detected: null` does not match the SDK schema (the TS zod schema rejects
    /// null too), so it is a decode failure, never a silent "no detections".
    #[test]
    fn ok_with_null_prompt_detected_is_a_validation_error() {
        let (_, out) = failing(Planned::json(
            200,
            &verdict(json!({"prompt_detected": null})),
        ));
        expect_stderr(
            &out,
            "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema",
            &[OUTCOME_UNKNOWN],
        );
    }

    #[test]
    fn connection_refused() {
        // Every endpoint points at a loopback port whose server was stopped.
        let dead = FixtureServer::start();
        let base = dead.base_url();
        drop(dead);
        let sandbox = Sandbox::new();
        let config = FixtureConfig::standard(&base, "100");
        let path = sandbox.write_fixture_config("prod", &config);
        sandbox.write_registry(&[RegistryEntry::new("prod", &path, "100")], Some("prod"));
        let before = sandbox.snapshot();
        let out = airs_test_harness::run(&rust(), &sandbox, &scan_args("hi"), &RunOptions::new());
        sandbox.assert_unchanged(&before);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(out.http_status(), None);
        // The SDK reports the remote outcome of a refused connection as Unknown, so the
        // outcome line is printed (fail-safe wording; see the inventory notes).
        assert_eq!(
            out.stderr,
            format!(
                "{}{}",
                status_lines(PROFILE, "hi"),
                operational(
                    "AISEC_CLIENT_SIDE_ERROR:Network request failed (connection refused, reset or unreachable)",
                    &[OUTCOME_UNKNOWN]
                )
            )
        );
    }
}

// ---------------------------------------------------------------------------------------
// §2.5 cancellation (D32)
// ---------------------------------------------------------------------------------------

mod cancellation {
    use super::*;

    fn interrupted(signal: &str, code: i32) {
        let env = setup();
        env.server.set_default(Route::ScanSync, Planned::hang());
        env.assert_loopback_config();
        let before = env.sandbox.snapshot();
        let running = spawn(
            &rust(),
            &env.sandbox,
            &scan_args("hi"),
            &RunOptions::new().timeout(Duration::from_secs(30)),
        );
        assert!(
            env.server.wait_for_requests(1, Duration::from_secs(20)),
            "scan POST never arrived"
        );
        running.send_signal(signal);
        let out = running.wait();
        env.finish(&before);
        out.assert_code(code);
        assert_eq!(out.signal, None, "must exit with a code, not die by signal");
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            format!(
                "{}\n  ✗ Error: Interrupted; the scan request may already have reached AIRS (outcome unknown)\n\n",
                status_lines(PROFILE, "hi")
            )
        );
        assert!(
            env.server.wait_for_disconnects(1, Duration::from_secs(10)),
            "the in-flight request was not cancelled"
        );
        assert_eq!(env.scans().len(), 1);
    }

    #[test]
    fn sigint_during_scan_exits_130() {
        interrupted("INT", 130);
    }

    #[test]
    fn sigterm_during_scan_exits_143() {
        interrupted("TERM", 143);
    }
}

// ---------------------------------------------------------------------------------------
// §8.3–§8.5: server text is scrubbed of configured secrets and of control characters
// ---------------------------------------------------------------------------------------

mod hostile_responses {
    use super::*;

    /// A response that echoes the configured API key in an `errors[]` status, in the
    /// category, in an unknown field (value and key) and in its IDs. The runner's leak
    /// check (raw, URL-encoded, base64) guards stdout and stderr of both formats.
    fn echoing_verdict() -> Value {
        verdict(json!({
            "error": true,
            "category": format!("cat {API_KEY}"),
            "scan_id": format!("S-{API_KEY}"),
            "report_id": format!("R-{API_KEY}"),
            "errors": [{"feature": "dlp", "status": format!("echo {API_KEY}"), "content_type": "prompt"}],
            "zz_echo": {"value": API_KEY, API_KEY: true, "b64": "RkFLRS1BUElLRVktMTAw"}
        }))
    }

    #[test]
    fn echoed_api_key_is_withheld_in_pretty_output_and_the_error() {
        let env = setup();
        serve_verdict(&env, &echoing_verdict());
        let out = env.run(&scan_args("x"));
        out.assert_code(1);
        assert_eq!(
            out.stdout,
            Pretty {
                action: "FAILED",
                category: "error",
                triggered: false,
                scan_id: "[withheld]",
                report_id: "[withheld]",
                error: Some("dlp: [withheld]: prompt"),
                bullets: &[],
            }
            .render(false)
        );
        assert!(
            out.stderr.ends_with(&operational(
                "AIRS scan did not complete: dlp: [withheld]: prompt",
                &[]
            )),
            "{}",
            out.stderr
        );
    }

    #[test]
    fn echoed_api_key_is_withheld_everywhere_in_json_output() {
        let env = setup();
        let mut body = echoing_verdict();
        body["error"] = json!(false);
        body["errors"] = json!([]);
        serve_verdict(&env, &body);
        let out = env.run(&[
            "runtime",
            "scan",
            "--output",
            "json",
            "--profile",
            PROFILE,
            "x",
        ]);
        out.assert_success();
        let json = out.json();
        assert_eq!(json["scanId"], "[withheld]");
        assert_eq!(json["reportId"], "[withheld]");
        assert_eq!(json["category"], "[withheld]");
        assert_eq!(json["result"]["category"], "[withheld]");
        assert_eq!(
            json["result"]["zz_echo"],
            json!({"b64": "[withheld]", "value": "[withheld]"}),
            "a value or key that carries the key is withheld or dropped"
        );
    }

    #[test]
    fn control_characters_never_reach_the_terminal() {
        let env = setup();
        serve_verdict(
            &env,
            &verdict(json!({
                "error": true,
                "category": "benign\u{1b}[31m",
                "scan_id": "S\u{1b}[2K",
                "report_id": "R\u{1b}]0;pwned\u{7}",
                "errors": [{"feature": "dlp", "status": "\u{9b}2J", "content_type": "\u{1b}[31mred\n  ✓ forged"}]
            })),
        );
        let out = env.run(&scan_args("x"));
        out.assert_code(1);
        for (stream, text) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
            assert!(
                !text.contains(['\u{1b}', '\u{7}', '\u{9b}']),
                "{stream} carries a control character: {text:?}"
            );
            assert!(
                !text.contains("\n  ✓ forged"),
                "{stream}: a forged line: {text:?}"
            );
        }
        assert!(
            out.stdout
                .contains("  Report ID  R\u{fffd}]0;pwned\u{fffd}\n"),
            "{}",
            out.stdout
        );
        assert!(
            out.stderr.contains(
                "AIRS scan did not complete: dlp: \u{fffd}2J: \u{fffd}[31mred\u{fffd}  ✓ forged"
            ),
            "{}",
            out.stderr
        );
    }
}
