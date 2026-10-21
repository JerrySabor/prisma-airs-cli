//! Validates the harness against the TypeScript reference CLI (a missing or unverified
//! reference fails; `AIRS_ALLOW_PARITY_SKIP=1` skips with a `PARITY SKIPPED` notice).
//! These pin the observed behaviour recorded in `docs/research/ts-baseline-observed.md`.

use airs_test_harness::{
    AuthIdentity, BasicEncoding, Cli, ENDPOINT_KEYS, FixtureServer, FixtureTenant, Gw,
    NormalizedBody, Planned, Route, Run, RunOptions, Sandbox, error_line, fixtures, http_status,
    normalize, require_ts, run,
};
use serde_json::{Value, json};

/// The sentinel for the whole suite: a green run means the TypeScript reference was
/// found, runs on node major `SUPPORTED_NODE_MAJOR`, and (for the default clone) is at
/// the commit pinned by `scripts/build-reference-cli.sh` with no modified tracked files.
#[test]
fn reference_cli_is_usable_and_pinned() {
    match airs_test_harness::reference() {
        Ok(cli) => assert!(cli.is_ts()),
        Err(reason) => {
            assert!(
                std::env::var("AIRS_ALLOW_PARITY_SKIP").as_deref() == Ok("1")
                    && std::env::var("AIRS_REQUIRE_PARITY").as_deref() != Ok("1"),
                "TypeScript reference CLI unusable: {reason}; run scripts/build-reference-cli.sh \
                 (or set AIRS_ALLOW_PARITY_SKIP=1 to skip parity tests)"
            );
        }
    }
}

#[test]
fn a_clone_off_the_pinned_commit_is_rejected() {
    let pinned = airs_test_harness::pinned_reference_commit().expect("pinned commit");
    assert_eq!(pinned.len(), 40);
    let clone = airs_test_harness::workspace_root().join(".reference/prisma-airs-cli");
    if !clone.join(".git").exists() {
        return; // no clone: the sentinel above reports it
    }
    let problem = airs_test_harness::check_reference_clone(&clone, &"0".repeat(40))
        .expect_err("a wrong pin must be rejected");
    assert!(problem.contains("expected the pinned"), "{problem}");
}

struct Fixture {
    server: FixtureServer,
    sandbox: Sandbox,
    tenant: FixtureTenant,
}

fn fixture() -> Fixture {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    let tenant = sandbox.single_tenant(&server, "prod", "100");
    Fixture {
        server,
        sandbox,
        tenant,
    }
}

impl Fixture {
    /// Runs the CLI, then checks the loopback and read-only invariants.
    fn run(&self, cli: &Cli, args: &[&str]) -> Run {
        let config: Value =
            serde_json::from_str(&self.tenant.config.to_json()).expect("config json");
        for key in ENDPOINT_KEYS {
            let endpoint = config[key].as_str().unwrap_or_default();
            assert!(
                endpoint.starts_with(&self.server.base_url()),
                "{key} is not loopback"
            );
        }
        let before = self.sandbox.snapshot();
        let out = run(cli, &self.sandbox, args, &RunOptions::new());
        self.sandbox.assert_unchanged(&before);
        self.server.assert_no_unknown_routes();
        assert!(
            self.sandbox.home_listing().is_empty(),
            "CLI wrote into HOME"
        );
        assert!(self.sandbox.cwd_listing().is_empty(), "CLI wrote into cwd");
        out
    }
}

const LIST: &[&str] = &["runtime", "profiles", "list", "--output", "json"];

fn token_identity() -> AuthIdentity {
    AuthIdentity::Basic {
        client_id: "client-100".into(),
        tsg: Some("100".into()),
        valid: true,
    }
}

fn names(run: &Run, key: &str) -> Vec<(String, u64)> {
    run.json()
        .as_array()
        .expect("array")
        .iter()
        .map(|row| {
            (
                row[key].as_str().unwrap_or_default().to_owned(),
                row["revision"].as_u64().unwrap_or_default(),
            )
        })
        .collect()
}

#[test]
fn profiles_list_empty() {
    let Some(ts) = require_ts("profiles_list_empty") else {
        return;
    };
    let f = fixture();
    let out = f.run(&ts, LIST);
    out.assert_success();
    assert_eq!(
        (out.stdout.as_str(), out.stderr.as_str()),
        ("[]\n", "  Showing 0\n")
    );

    let requests = f.server.requests();
    assert_eq!(f.server.routes(), vec![Route::Token, Route::Profiles]);
    let token = &requests[0];
    assert_eq!(token.auth, token_identity());
    assert_eq!(token.basic_encoding, Some(BasicEncoding::Indistinguishable));
    assert_eq!(
        token.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        token.body_text(),
        "grant_type=client_credentials&scope=tsg_id%3A100"
    );
    let list = normalize(&requests[1]);
    assert_eq!(
        list.auth,
        AuthIdentity::Bearer {
            tsg: Some("100".into())
        }
    );
    assert_eq!(
        requests[1].raw_query.as_deref(),
        Some("offset=0&limit=100&latest=true")
    );
    assert_eq!(list.body, NormalizedBody::None);
    assert_eq!(
        list.headers.get("service-name").map(String::as_str),
        Some("api")
    );
    assert!(!list.headers.contains_key("x-tsg-id"));
    assert!(
        requests[1]
            .header("user-agent")
            .is_some_and(|ua| ua.starts_with("PAN-AIRS/"))
    );
}

#[test]
fn profiles_list_with_data_collapses_revisions_server_side() {
    let Some(ts) = require_ts("profiles_list_with_data") else {
        return;
    };
    let f = fixture();
    f.server.set_profiles(
        "100",
        vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(2, "alpha", 2),
            fixtures::profile(3, "beta", 1),
        ],
    );
    let out = f.run(&ts, LIST);
    out.assert_success();
    assert_eq!(
        names(&out, "profileName"),
        vec![("alpha".into(), 2), ("beta".into(), 1)]
    );
    let first = &out.json()[0];
    let keys: Vec<&String> = first.as_object().expect("object").keys().collect();
    assert_eq!(keys.len(), 8);
    assert_eq!(first["profileId"], fixtures::uuid(2));
    assert_eq!(out.stderr, "  Showing 2\n");
}

#[test]
fn profiles_list_all_walks_pages() {
    let Some(ts) = require_ts("profiles_list_all_walks_pages") else {
        return;
    };
    let f = fixture();
    f.server.set_profiles(
        "100",
        vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(2, "alpha", 2),
            fixtures::profile(3, "beta", 1),
        ],
    );
    let out = f.run(
        &ts,
        &[
            "runtime",
            "profiles",
            "list",
            "--output",
            "json",
            "--all",
            "--limit",
            "1",
            "--all-versions",
        ],
    );
    out.assert_success();
    assert_eq!(names(&out, "profileName").len(), 3);
    assert_eq!(out.stderr, "  Showing all 3\n");
    let queries: Vec<Option<String>> = f
        .server
        .requests_for(Route::Profiles)
        .into_iter()
        .map(|r| r.raw_query)
        .collect();
    assert_eq!(
        queries,
        ["0", "1", "2"]
            .map(|offset| Some(format!("offset={offset}&limit=1&latest=false")))
            .to_vec()
    );
    // One token for the whole walk.
    assert_eq!(f.server.requests_for(Route::Token).len(), 1);
}

#[test]
fn profiles_list_next_offset_zero_quirk() {
    let Some(ts) = require_ts("profiles_list_next_offset_zero_quirk") else {
        return;
    };
    let f = fixture();
    f.server.set_zero_next_offset_on_last_page(true);
    let out = f.run(&ts, LIST);
    out.assert_success();
    assert_eq!(out.stderr, "  Showing 0 (more available)\n");
}

#[test]
fn topics_list_latest() {
    let Some(ts) = require_ts("topics_list_latest") else {
        return;
    };
    let f = fixture();
    f.server.set_topics(
        "100",
        vec![
            fixtures::topic(11, "fin", 1, "old"),
            fixtures::topic(12, "fin", 2, "new"),
            fixtures::topic(13, "legal", 1, "l"),
        ],
    );
    let out = f.run(&ts, &["runtime", "topics", "list", "--output", "json"]);
    out.assert_success();
    assert_eq!(
        names(&out, "topicName"),
        vec![("fin".into(), 2), ("legal".into(), 1)]
    );
    assert_eq!(out.stderr, "  Showing 2\n");
    let topics = f.server.requests_for(Route::Topics);
    assert_eq!(topics.len(), 1);
    assert_eq!(topics[0].raw_query.as_deref(), Some("offset=0&limit=200"));
}

#[test]
fn profiles_get_by_name_and_not_found() {
    let Some(ts) = require_ts("profiles_get_by_name_and_not_found") else {
        return;
    };
    let f = fixture();
    f.server.set_profiles(
        "100",
        vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(2, "alpha", 2),
        ],
    );
    let out = f.run(
        &ts,
        &["runtime", "profiles", "get", "alpha", "--output", "json"],
    );
    out.assert_success();
    assert_eq!(out.json()["revision"], 2);
    assert_eq!(out.stderr, "");
    assert_eq!(
        f.server.requests_for(Route::Profiles)[0]
            .raw_query
            .as_deref(),
        Some("offset=0&limit=100")
    );

    let missing = f.run(
        &ts,
        &["runtime", "profiles", "get", "missing", "--output", "json"],
    );
    missing.assert_code(1);
    assert_eq!(missing.stdout, "");
    assert_eq!(
        missing.stderr,
        "\n  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: missing\n\n"
    );
}

fn scan(ts: &Cli, f: &Fixture, prompt: &str) -> Run {
    f.run(
        ts,
        &["runtime", "scan", "--profile", "fixture-profile", prompt],
    )
}

#[test]
fn scan_allow_and_block() {
    let Some(ts) = require_ts("scan_allow_and_block") else {
        return;
    };
    let f = fixture();
    f.server
        .add_scan_verdict("BLOCK", &fixtures::scan_block("fixture-profile"));

    let allow = scan(&ts, &f, "hello world");
    allow.assert_success();
    assert_eq!(
        allow.stdout,
        "\n  Scan Result\n\n  Action     ALLOW\n  Category   benign\n  Triggered  no\n  Scan ID    00000000-0000-4000-8000-0000000000a1\n  Report ID  R00000000-0000-4000-8000-0000000000a1\n"
    );
    assert_eq!(
        allow.stderr,
        "  Prisma AIRS Runtime Scan\n  Profile: fixture-profile\n  Prompt:  \"hello world\"\n"
    );

    let block = scan(&ts, &f, "please BLOCK this");
    block.assert_success();
    assert!(
        block
            .stdout
            .contains("  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n")
    );
    assert!(
        block
            .stdout
            .ends_with("\n  Detections\n\n  ● injection\n  ● toxic_content\n")
    );

    let requests = f.server.requests();
    assert_eq!(f.server.routes(), vec![Route::ScanSync, Route::ScanSync]);
    let first = &requests[0];
    assert_eq!(
        first.auth,
        AuthIdentity::ApiKey {
            key_id: Some("100".into()),
            hash_valid: true
        }
    );
    assert!(first.header("x-payload-hash").is_some() && first.header("authorization").is_none());
    assert_eq!(
        first.body_text(),
        r#"{"ai_profile":{"profile_name":"fixture-profile"},"contents":[{"prompt":"hello world"}]}"#
    );
    assert_eq!(first.header("content-type"), Some("application/json"));
    assert_eq!(first.header("service-name"), Some("api"));
}

#[test]
fn doctor_json_stays_on_loopback() {
    let Some(ts) = require_ts("doctor_json_stays_on_loopback") else {
        return;
    };
    let f = fixture();
    let out = f.run(&ts, &["doctor", "--output", "json"]);
    out.assert_success();
    let checks = out.json();
    let status = |name: &str| {
        checks
            .as_array()
            .and_then(|all| all.iter().find(|check| check["name"] == name))
            .map(|check| (check["status"].clone(), check["detail"].clone()))
            .unwrap_or_else(|| panic!("check {name} missing"))
    };
    assert_eq!(
        status("Scanner API"),
        (json!("pass"), json!("endpoint reachable, API key accepted"))
    );
    assert_eq!(
        status("Management OAuth"),
        (
            json!("pass"),
            json!("OAuth token obtained, topics API answered (0 custom topics)")
        )
    );
    assert_eq!(
        status("AI Gateway API"),
        (
            json!("pass"),
            json!("endpoint reachable (0 workspaces in scope)")
        )
    );
    assert_eq!(
        status("Environment"),
        (json!("pass"), json!("no configuration variables set"))
    );
    assert_eq!(checks.as_array().map(Vec::len), Some(11));

    assert_eq!(
        f.server.routes(),
        vec![
            Route::ScanResults,
            Route::Token,
            Route::Topics,
            Route::Token,
            Route::Gateway(Gw::DataWorkspaces)
        ]
    );
    let probe = &f.server.requests()[0];
    assert_eq!(probe.query.len(), 1);
    assert_eq!(probe.query[0].0, "scan_ids");
    assert!(probe.header("x-payload-hash").is_none());
    let gateway = f.server.requests_for(Route::Gateway(Gw::DataWorkspaces));
    assert_eq!(gateway[0].header("x-tsg-id"), Some("100"));
}

#[test]
fn token_401_fails_before_any_api_request() {
    let Some(ts) = require_ts("token_401_fails_before_any_api_request") else {
        return;
    };
    let f = fixture();
    f.server.set_default(Route::Token, Planned::empty_json(401));
    let out = f.run(&ts, LIST);
    out.assert_code(1);
    assert_eq!(out.stdout, "");
    assert_eq!(
        error_line(&out.stderr).as_deref(),
        Some("AISEC_OAUTH_ERROR:Token request failed with status 401")
    );
    assert_eq!(http_status(&out.stderr), Some(401));
    assert_eq!(f.server.routes(), vec![Route::Token]);
}

#[test]
fn profiles_404_reports_http_status() {
    let Some(ts) = require_ts("profiles_404_reports_http_status") else {
        return;
    };
    let f = fixture();
    f.server.set_default(
        Route::Profiles,
        Planned::json(404, &json!({"message": "nope"})),
    );
    let out = f.run(&ts, LIST);
    out.assert_code(1);
    assert_eq!(
        out.stderr,
        "\n  ✗ Error: AISEC_CLIENT_SIDE_ERROR:nope\n    HTTP 404\n    Re-run with --debug to capture redacted API diagnostics.\n\n"
    );
    assert_eq!(f.server.routes(), vec![Route::Token, Route::Profiles]);
}

#[test]
fn management_503_is_retried_and_401_refreshes_the_token() {
    let Some(ts) = require_ts("management_503_is_retried") else {
        return;
    };
    let f = fixture();
    f.server.set_default(
        Route::Profiles,
        Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
    );
    let out = f.run(&ts, LIST);
    out.assert_code(1);
    assert_eq!(
        error_line(&out.stderr).as_deref(),
        Some("AISEC_SERVER_SIDE_ERROR:busy")
    );
    // airsNumRetries does not apply to management: 1 + 5 retries.
    assert_eq!(f.server.requests_for(Route::Profiles).len(), 6);

    f.server.clear_overrides(Route::Profiles);
    f.server.clear_requests();
    f.server
        .push_once(Route::Profiles, Planned::empty_json(401));
    let out = f.run(&ts, LIST);
    out.assert_success();
    assert_eq!(
        f.server.routes(),
        vec![Route::Token, Route::Profiles, Route::Token, Route::Profiles]
    );
}

#[test]
fn commander_parse_errors_exit_1_and_usage_errors_exit_2() {
    let Some(ts) = require_ts("commander_parse_errors") else {
        return;
    };
    let f = fixture();
    let unknown = f.run(&ts, &["runtime", "profiles", "list", "--bogus"]);
    assert_eq!(
        (unknown.code, unknown.stderr.as_str()),
        (1, "error: unknown option '--bogus'\n")
    );
    let usage = f.run(&ts, &["runtime", "profiles", "list", "--limit", "0"]);
    assert_eq!(
        (usage.code, usage.stderr.as_str()),
        (2, "\n  ✗ --limit must be a positive integer\n\n")
    );
    assert_eq!(f.server.request_count(), 0);
}
