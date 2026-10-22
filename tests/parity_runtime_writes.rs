//! TS-vs-Rust parity for the M4 topic and profile writes (DESIGN §13.5–§13.7,
//! §13.12–§13.14, §10 M4).
//!
//! Each scenario runs once on each CLI, on a fresh sandbox and fixture server seeded with
//! the same state. Parity tests compare exit codes, the outcome lines (TypeScript stdout
//! against Rust stderr, D106), the rest of stdout, the write requests (JSON bodies
//! compared semantically, D35) and the resulting fixture state. `dNN_` tests pin both
//! sides of a DESIGN §12 row.
//!
//! TypeScript `topics create` ignores the tenant's `mgmtEndpoint` (D93): its scenarios
//! point `PANW_MGMT_ENDPOINT` at the server's second base (`/ts-env/aisec`, sharing the
//! state); without it the runner's trap answers. Every request stays on loopback.

use airs_test_harness::{
    Cli, FixtureServer, Planned, PtyRun, RUNTIME_BANNER, RecordedRequest, Route, Run, RunOptions,
    Sandbox, assert_json_semantic_eq, error_line, fixtures, require_ts, run, spawn_pty,
    spawn_pty_all, split_outcome_lines, usage_line,
};
use serde_json::{Value, json};

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn id(n: u64) -> String {
    fixtures::uuid(n)
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    topics: Vec<Value>,
    profiles: Vec<Value>,
}

impl Side {
    fn writes(&self) -> Vec<&RecordedRequest> {
        self.requests
            .iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    /// Every write as `METHOD path?query` (the base stripped) and its JSON body.
    fn write_summary(&self) -> Vec<(String, Option<Value>)> {
        self.writes()
            .iter()
            .map(|request| {
                let line = request.line();
                let line = line.replacen(request.base, "", 1);
                (line, request.body_json())
            })
            .collect()
    }

    fn count(&self, route: Route) -> usize {
        self.requests.iter().filter(|r| r.route == route).count()
    }

    fn bases(&self, route: Route) -> Vec<&'static str> {
        self.requests
            .iter()
            .filter(|r| r.route == route)
            .map(|r| r.base)
            .collect()
    }
}

/// How a scenario prepares its world.
#[derive(Clone, Copy)]
struct Setup<'a> {
    /// Whether the standard tenant is registered.
    tenant: bool,
    /// TypeScript gets `PANW_MGMT_ENDPOINT=<server>/ts-env/aisec` (family-B commands).
    ts_env: bool,
    seed: &'a dyn Fn(&FixtureServer, &Sandbox),
    quiet: bool,
}

fn no_seed(_: &FixtureServer, _: &Sandbox) {}

fn setup(seed: &dyn Fn(&FixtureServer, &Sandbox)) -> Setup<'_> {
    Setup {
        tenant: true,
        ts_env: false,
        seed,
        quiet: false,
    }
}

/// The standard dataset: topic `fin` revisions 1 (id 11) and 2 (id 12, listed second),
/// topic `other` (id 13); profile `alpha` (id 1).
fn standard(server: &FixtureServer) {
    server.set_topics(
        TSG,
        vec![
            fixtures::topic(11, "fin", 1, "finance"),
            fixtures::topic(12, "fin", 2, "finance v2"),
            fixtures::topic(13, "other", 1, "other topic"),
        ],
    );
    server.set_profiles(TSG, vec![fixtures::profile(1, "alpha", 1)]);
}

/// Runs `args` (with `TMP` replaced by the sandbox's `tmp/`) on a fresh world.
fn exec(cli: &Cli, setup: Setup<'_>, args: &[&str]) -> Side {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    if setup.tenant {
        sandbox.single_tenant(&server, "prod", TSG);
    }
    standard(&server);
    (setup.seed)(&server, &sandbox);
    let mut options = RunOptions::new();
    if setup.ts_env && cli.is_ts() {
        options = options.env("PANW_MGMT_ENDPOINT", server.ts_env_mgmt_url());
    }
    let tmp = sandbox.tmp().display().to_string();
    let mut args: Vec<String> = args.iter().map(|arg| arg.replace("TMP", &tmp)).collect();
    if setup.quiet {
        args.push("--quiet".into());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run(cli, &sandbox, &args, &options);
    server.assert_no_unknown_routes();
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
    // The TypeScript CLI runs against TMP paths; normalise them out of its output.
    let mut out = out;
    out.stdout = out.stdout.replace(&tmp, "TMP");
    out.stderr = out.stderr.replace(&tmp, "TMP");
    Side {
        run: out,
        requests: server.requests(),
        topics: server.topics(TSG),
        profiles: server.profiles(TSG),
    }
}

/// Both CLIs on the same scenario, or `None` when the reference is skipped.
fn both(test: &str, setup: Setup<'_>, args: &[&str]) -> Option<(Side, Side)> {
    let ts = require_ts(test)?;
    Some((exec(&rust(), setup, args), exec(&ts, setup, args)))
}

/// The parity contract of a successful write: equal exit codes, the TypeScript outcome
/// lines equal to the Rust stderr, the rest of the TypeScript stdout equal to the Rust
/// stdout, equal write requests and equal resulting state.
fn assert_write_parity(rust: &Side, ts: &Side) {
    assert_eq!(rust.run.code, ts.run.code, "{:?}\n{:?}", rust.run, ts.run);
    let (outcome, rest) = split_outcome_lines(&ts.run.stdout);
    assert_eq!(rust.run.stderr, outcome, "outcome lines (D106)");
    assert_eq!(rust.run.stdout, rest, "data");
    let (rust_writes, ts_writes) = (rust.write_summary(), ts.write_summary());
    assert_eq!(
        rust_writes.len(),
        ts_writes.len(),
        "{rust_writes:?}\n{ts_writes:?}"
    );
    for ((rust_line, rust_body), (ts_line, ts_body)) in rust_writes.iter().zip(&ts_writes) {
        assert_eq!(rust_line, ts_line);
        match (rust_body, ts_body) {
            (Some(rust_body), Some(ts_body)) => assert_json_semantic_eq(rust_body, ts_body),
            (rust_body, ts_body) => assert_eq!(rust_body, ts_body),
        }
    }
    assert_json_semantic_eq(&json!(rust.topics), &json!(ts.topics));
    assert_json_semantic_eq(&json!(rust.profiles), &json!(ts.profiles));
}

/// The parity contract of a `profiles create|update` (8.0, TS 7.3.0): its outcome is a
/// status line on stderr on both CLIs (`Profile created|updated: <id>`), so stdout and
/// stderr compare byte for byte, then the writes and the resulting state.
fn assert_profile_write_parity(rust: &Side, ts: &Side) {
    assert_eq!(rust.run.code, ts.run.code, "{:?}\n{:?}", rust.run, ts.run);
    assert_eq!(rust.run.stderr, ts.run.stderr, "status line");
    assert_eq!(rust.run.stdout, ts.run.stdout, "data");
    let (rust_writes, ts_writes) = (rust.write_summary(), ts.write_summary());
    assert_eq!(
        rust_writes.len(),
        ts_writes.len(),
        "{rust_writes:?}\n{ts_writes:?}"
    );
    for ((rust_line, rust_body), (ts_line, ts_body)) in rust_writes.iter().zip(&ts_writes) {
        assert_eq!(rust_line, ts_line);
        match (rust_body, ts_body) {
            (Some(rust_body), Some(ts_body)) => assert_json_semantic_eq(rust_body, ts_body),
            (rust_body, ts_body) => assert_eq!(rust_body, ts_body),
        }
    }
    assert_json_semantic_eq(&json!(rust.topics), &json!(ts.topics));
    assert_json_semantic_eq(&json!(rust.profiles), &json!(ts.profiles));
}

fn create_topic<'a>(name: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "runtime",
        "topics",
        "create",
        "--name",
        name,
        "--description",
        "a topic",
        "--examples",
        "first",
        "second",
    ];
    args.extend_from_slice(extra);
    args
}

mod parity {
    use super::*;

    #[test]
    fn topics_create_new_through_the_ts_env_base() {
        let mut world = setup(&no_seed);
        world.ts_env = true;
        let Some((rust, ts)) = both("topics_create_new", world, &create_topic("fresh", &[])) else {
            return;
        };
        assert_write_parity(&rust, &ts);
        assert_eq!(rust.run.stderr, "  ✓ Topic created: fresh\n");
    }

    #[test]
    fn topics_update_from_a_config_file() {
        let seed = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(
                sandbox.tmp().join("t.json"),
                br#"{"topic_name": "fin", "description": "edited", "examples": ["x", "y"]}"#,
            )
            .unwrap();
        };
        let target = id(11);
        let args = [
            "runtime",
            "topics",
            "update",
            &target,
            "--config",
            "TMP/t.json",
        ];
        let Some((rust, ts)) = both("topics_update", setup(&seed), &args) else {
            return;
        };
        assert_write_parity(&rust, &ts);
        assert_eq!(rust.run.stderr, format!("  ✓ Topic updated: {target}\n"));
    }

    #[test]
    fn topics_delete_force_sends_the_same_request() {
        let target = id(13);
        let args = [
            "runtime",
            "topics",
            "delete",
            &target,
            "--force",
            "--updated-by",
            "ops team@example.com",
        ];
        let Some((rust, ts)) = both("topics_delete_force", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.write_summary(), ts.write_summary());
        assert_eq!(rust.topics, ts.topics);
    }

    #[test]
    fn profiles_create_from_flags() {
        let args = [
            "runtime",
            "profiles",
            "create",
            "--name",
            "gamma",
            "--prompt-injection",
            "block",
            "--toxic-content",
            "alert",
            "--malicious-code",
            "block",
            "--block-url-categories",
            "a, b",
            "--agent-security",
            "alert",
            "--dlp-action",
            "block",
            "--dlp-profiles",
            "PII",
            "--db-security-read",
            "allow",
            "--inline-timeout-action",
            "allow",
            "--max-inline-latency",
            "9",
            "--mask-data-in-storage",
            "--no-active",
        ];
        let Some((rust, ts)) = both("profiles_create_flags", setup(&no_seed), &args) else {
            return;
        };
        assert_profile_write_parity(&rust, &ts);
    }

    /// The file names the profile; `--name` is not given (TS 7.3.0 refuses it beside
    /// `--config`, as airs-cli-rs does).
    #[test]
    fn profiles_create_from_a_config_file() {
        let seed = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(
                sandbox.tmp().join("p.json"),
                br#"{"profile_name": "gamma", "active": true, "policy": {"ai-security-profiles": [{"model-type": "default", "model-configuration": {"mask-data-in-storage": true}}]}}"#,
            )
            .unwrap();
        };
        let args = ["runtime", "profiles", "create", "--config", "TMP/p.json"];
        let Some((rust, ts)) = both("profiles_create_config", setup(&seed), &args) else {
            return;
        };
        assert_profile_write_parity(&rust, &ts);
        let args = [
            "runtime",
            "profiles",
            "create",
            "--name",
            "gamma",
            "--config",
            "TMP/p.json",
        ];
        let Some((rust, ts)) = both("profiles_create_config_name", setup(&seed), &args) else {
            return;
        };
        for side in [&rust, &ts] {
            side.run.assert_code(2);
            assert!(side.requests.is_empty());
        }
        assert_eq!(rust.run.stderr, ts.run.stderr);
    }

    #[test]
    fn profiles_update_merges_flags() {
        let args = [
            "runtime",
            "profiles",
            "update",
            "alpha",
            "--prompt-injection",
            "block",
            "--url-action",
            "alert",
            "--db-security-delete",
            "block",
            "--malicious-code",
            "block",
            "--name",
            "alpha2",
        ];
        let Some((rust, ts)) = both("profiles_update_merge", setup(&no_seed), &args) else {
            return;
        };
        assert_profile_write_parity(&rust, &ts);
        assert_eq!(
            rust.write_summary()[0].1.as_ref().unwrap()["policy"]["ai-security-profiles"][0]["model-configuration"]
                ["app-protection"]["malicious-code-protection"],
            json!({"action": "block", "name": "malicious-code"}),
            "the update merge names a new item `malicious-code` (TS 7.3.0)"
        );
    }

    /// TS 7.3.0: `--[no-]mask-data-inline` and `--dlp-profiles` change only their fields
    /// on update, without `--dlp-action`; explicit `false` is kept.
    #[test]
    fn masking_changes_alone_without_a_dlp_action() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            let mut alpha = fixtures::profile(1, "alpha", 1);
            alpha["policy"]["ai-security-profiles"][0]["model-configuration"]["data-protection"] = json!({
                "data-leak-detection": {"action": "alert", "member": [{"text": "PII"}], "mask-data-inline": true}
            });
            server.set_profiles(TSG, vec![alpha]);
        };
        let args = [
            "runtime",
            "profiles",
            "update",
            "alpha",
            "--no-mask-data-inline",
            "--dlp-profiles",
            "PCI",
            "--no-mask-data-in-storage",
        ];
        let Some((rust, ts)) = both("profiles_update_masking", setup(&seed), &args) else {
            return;
        };
        assert_profile_write_parity(&rust, &ts);
        let config = &rust.write_summary()[0].1.clone().unwrap()["policy"]["ai-security-profiles"]
            [0]["model-configuration"];
        assert_eq!(
            config["data-protection"]["data-leak-detection"],
            json!({"action": "alert", "member": [{"text": "PCI"}], "mask-data-inline": false})
        );
        assert_eq!(config["mask-data-in-storage"], false);
    }

    #[test]
    fn profiles_update_of_a_missing_profile() {
        let args = [
            "runtime",
            "profiles",
            "update",
            "nope",
            "--prompt-injection",
            "block",
        ];
        let Some((rust, ts)) = both("profiles_update_missing", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(rust.run.error_line(), ts.run.error_line());
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: nope")
        );
        assert!(rust.writes().is_empty() && ts.writes().is_empty());
    }

    #[test]
    fn profiles_delete_force_by_name() {
        let args = [
            "runtime",
            "profiles",
            "delete",
            "alpha",
            "--force",
            "--updated-by",
            "a@b",
        ];
        let Some((rust, ts)) = both("profiles_delete_force", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        let (outcome, rest) = split_outcome_lines(&ts.run.stdout);
        assert_eq!(rust.run.stderr, outcome);
        assert_eq!(outcome, format!("  ✓ Profile deleted: alpha ({})\n", id(1)));
        assert_eq!(
            (rust.run.stdout.as_str(), rest.as_str()),
            ("", RUNTIME_BANNER)
        );
        assert_eq!(rust.write_summary(), ts.write_summary());
        assert_eq!(rust.profiles, ts.profiles);
    }

    /// D95 keeps TypeScript's one replay after a 401 on a write.
    #[test]
    fn a_401_on_a_write_is_replayed_once_on_both() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            server.push_once(Route::ProfileCreate, Planned::empty_json(401));
        };
        let args = [
            "runtime",
            "profiles",
            "create",
            "--name",
            "gamma",
            "--prompt-injection",
            "block",
        ];
        let Some((rust, ts)) = both("write_401_replay", setup(&seed), &args) else {
            return;
        };
        assert_profile_write_parity(&rust, &ts);
        for side in [&rust, &ts] {
            let routes: Vec<Route> = side.requests.iter().map(|r| r.route).collect();
            assert_eq!(
                routes,
                [
                    Route::Token,
                    Route::ProfileCreate,
                    Route::Token,
                    Route::ProfileCreate
                ]
            );
        }
    }
}

mod divergence {
    use super::*;

    /// D93: TypeScript `topics create` sends its data requests to `PANW_MGMT_ENDPOINT`
    /// (here the trap, else the `/ts-env` base), never the tenant's `mgmtEndpoint`;
    /// airs-cli-rs uses the tenant's endpoint.
    #[test]
    fn d93_topics_create_uses_the_tenant_endpoint() {
        let args = create_topic("fresh", &[]);
        let Some((rust, trapped)) = both("d93_trap", setup(&no_seed), &args) else {
            return;
        };
        rust.run.assert_success();
        assert_eq!(rust.bases(Route::Topics), [""]);
        assert_eq!(rust.bases(Route::TopicCreate), [""]);
        trapped.run.assert_code(1);
        assert_eq!(
            trapped.count(Route::TsEnvTrap),
            1,
            "the data request hit the trap"
        );
        assert_eq!(
            trapped.count(Route::Topics),
            0,
            "never the tenant's endpoint"
        );
        assert_eq!(
            trapped.bases(Route::Token),
            [""],
            "the token uses the tenant's endpoint"
        );
        let mut world = setup(&no_seed);
        world.ts_env = true;
        let Some(ts) = require_ts("d93_ts_env") else {
            return;
        };
        let ts = exec(&ts, world, &args);
        ts.run.assert_success();
        assert_eq!(ts.bases(Route::Topics), ["/ts-env"]);
        assert_eq!(ts.bases(Route::TopicCreate), ["/ts-env"]);
    }

    /// D94: the root parser eats TypeScript's `--output`; airs-cli-rs honours it. The
    /// hidden `--format` reaches JSON on both, and airs-cli-rs validates its value.
    #[test]
    fn d94_output_is_honoured() {
        let mut world = setup(&no_seed);
        world.ts_env = true;
        let args = create_topic("fresh", &["--output", "json"]);
        let Some((rust, ts)) = both("d94_output", world, &args) else {
            return;
        };
        assert_eq!(rust.run.json()["topicName"], "fresh");
        assert!(
            ts.run.stdout.contains("  ✓ Topic created: fresh\n  ID  "),
            "TS prints pretty"
        );
        let args = create_topic("fresh", &["--format", "json"]);
        let Some((rust, ts)) = both("d94_format", world, &args) else {
            return;
        };
        assert_json_semantic_eq(&rust.run.json(), &ts.run.json());
        let warning = "  ⚠ --format is deprecated and will be removed in v4 — use --output\n";
        assert_eq!(ts.run.stderr, warning);
        assert_eq!(
            rust.run.stderr,
            format!("{warning}  ✓ Topic created: fresh\n"),
            "Rust adds the outcome line on stderr (D106)"
        );
        let args = create_topic("fresh", &["--format", "xml"]);
        let Some((rust, ts)) = both("d94_format_invalid", world, &args) else {
            return;
        };
        ts.run.assert_success();
        assert!(
            ts.run.stdout.contains("✓ Topic created"),
            "any other value is pretty"
        );
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("Invalid output format 'xml'. Expected: pretty, table, json")
        );
        assert!(rust.requests.is_empty());
    }

    /// D95: TypeScript re-sends a write on 5xx; airs-cli-rs sends it once and says the
    /// outcome is unknown.
    #[test]
    fn d95_writes_are_never_resent_on_server_errors() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            server.set_default(
                Route::TopicForceDelete,
                Planned::json(503, &json!({})).with_retry_after(0),
            );
        };
        let target = id(13);
        let args = [
            "runtime",
            "topics",
            "delete",
            &target,
            "--force",
            "--updated-by",
            "a@b",
        ];
        let Some((rust, ts)) = both("d95_resend", setup(&seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(rust.count(Route::TopicForceDelete), 1);
        assert!(ts.count(Route::TopicForceDelete) > 1, "TypeScript retries");
        assert!(
            rust.run
                .stderr
                .contains("    Outcome unknown: the topic may have been deleted.\n")
        );
        assert!(!ts.run.stderr.contains("Outcome"));
        assert_eq!(rust.run.error_line(), ts.run.error_line());
    }

    /// D96: an existing topic name is updated at its highest revision, not at the
    /// first-listed one.
    #[test]
    fn d96_create_updates_the_highest_revision() {
        let mut world = setup(&no_seed);
        world.ts_env = true;
        let Some((rust, ts)) = both("d96", world, &create_topic("fin", &[])) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(
            rust.write_summary()[0].0,
            format!("PUT /aisec/v1/mgmt/topic/uuid/{}", id(12))
        );
        assert_eq!(
            ts.write_summary()[0].0,
            format!("PUT /aisec/v1/mgmt/topic/uuid/{}", id(11))
        );
    }

    /// D100: TypeScript re-activates the profile and PUTs with nothing to change.
    #[test]
    fn d100_profiles_update_keeps_active() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            let mut alpha = fixtures::profile(1, "alpha", 1);
            alpha["active"] = json!(false);
            server.set_profiles(TSG, vec![alpha]);
        };
        let args = [
            "runtime",
            "profiles",
            "update",
            "alpha",
            "--prompt-injection",
            "block",
        ];
        let Some((rust, ts)) = both("d100_active", setup(&seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.write_summary()[0].1.as_ref().unwrap()["active"], false);
        assert_eq!(
            ts.write_summary()[0].1.as_ref().unwrap()["active"],
            false,
            "7.3.0 changes active only when given"
        );
        let args = ["runtime", "profiles", "update", "alpha"];
        let Some((rust, ts)) = both("d100_nothing", setup(&seed), &args) else {
            return;
        };
        ts.run.assert_success();
        assert_eq!(ts.writes().len(), 1, "TypeScript PUTs anyway");
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some(
                "Nothing to update: pass --name, --active, --no-active, a policy flag or --config"
            )
        );
        assert!(rust.requests.is_empty());
    }

    /// D101: a 409 is an error on both CLIs (7.3.0 no longer looks the name up);
    /// airs-cli-rs names the profile, TypeScript prints the SDK's status text.
    #[test]
    fn d101_a_conflict_is_an_error() {
        let empty = |server: &FixtureServer, _: &Sandbox| {
            server.push_once(Route::ProfileCreate, Planned::status(409));
        };
        let args = [
            "runtime",
            "profiles",
            "create",
            "--name",
            "alpha",
            "--prompt-injection",
            "block",
        ];
        let Some((rust, ts)) = both("d101_empty", setup(&empty), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 409")
        );
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("Profile \"alpha\" already exists. Use 'profiles update' to modify it.")
        );
        assert_eq!(rust.run.http_status(), Some(409));
        for side in [&rust, &ts] {
            assert_eq!(side.count(Route::Profiles), 0, "no lookup");
            assert_eq!(side.run.stdout, "");
        }
        let message = |server: &FixtureServer, _: &Sandbox| {
            server.push_once(
                Route::ProfileCreate,
                Planned::json(409, &json!({"message": "exists"})),
            );
        };
        let Some((rust, ts)) = both("d101_json", setup(&message), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:exists"),
            "TypeScript echoes the server message"
        );
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("Profile \"alpha\" already exists. Use 'profiles update' to modify it.")
        );
    }

    /// D102: flag combinations that cannot succeed, or would create a profile without
    /// protections, are usage errors with fixed texts. TypeScript 7.3.0 creates an empty
    /// policy from `--name` alone, accepts JavaScript number forms for
    /// `--max-inline-latency`, and refuses the rest with its schema text (exit 2).
    #[test]
    fn d102_profile_flag_usage_errors() {
        for (extra, rust_message, ts_code) in [
            (
                &[][..],
                "Specify at least one policy flag (for example --prompt-injection block) or --config <path>",
                0,
            ),
            (
                &["--max-inline-latency", "1e1"],
                "--max-inline-latency must be a non-negative integer",
                0,
            ),
            (
                &["--max-inline-latency", "1.5"],
                "--max-inline-latency must be a non-negative integer",
                2,
            ),
            (
                &["--prompt-injection", "block", "--dlp-profiles", "PII"],
                "--dlp-profiles and --[no-]mask-data-inline require --dlp-action when creating a profile",
                2,
            ),
        ] {
            let mut args = vec!["runtime", "profiles", "create", "--name", "gamma"];
            args.extend_from_slice(extra);
            let Some((rust, ts)) = both("d102", setup(&no_seed), &args) else {
                return;
            };
            rust.run.assert_code(2);
            assert_eq!(usage_line(&rust.run.stderr).as_deref(), Some(rust_message));
            assert!(rust.requests.is_empty());
            ts.run.assert_code(ts_code);
            if ts_code == 0 {
                assert_eq!(ts.writes().len(), 1, "TypeScript creates the profile");
            } else {
                assert!(ts.requests.is_empty(), "refused before OAuth");
            }
        }
        let args = ["runtime", "profiles", "create", "--name", "gamma"];
        let Some((_, ts)) = both("d102_empty", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!(
            ts.write_summary()[0].1.as_ref().unwrap()["policy"],
            json!({}),
            "an empty policy"
        );
    }

    /// D103: input files are read before the tenant with fixed messages (exit 1; TS 7.3.0
    /// exit 2 with Node's text for a profile file), and an update file's `profile_name`
    /// must name the resolved profile (TS renames silently).
    #[test]
    fn d103_input_files() {
        let args = ["runtime", "profiles", "create", "--config", "TMP/none.json"];
        let Some((rust, ts)) = both("d103_missing", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 2));
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some(
                "Cannot read TMP/none.json (missing, not a regular file, unreadable or larger than 1 MiB)"
            )
        );
        assert_eq!(
            usage_line(&ts.run.stderr).as_deref(),
            Some("ENOENT: no such file or directory, open 'TMP/none.json'")
        );
        let other = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(
                sandbox.tmp().join("p.json"),
                br#"{"profile_name": "other", "policy": {"ai-security-profiles": [{"model-type": "default", "model-configuration": {}}]}}"#,
            )
            .unwrap();
        };
        let args = [
            "runtime",
            "profiles",
            "update",
            "alpha",
            "--config",
            "TMP/p.json",
        ];
        let Some((rust, ts)) = both("d103_name", setup(&other), &args) else {
            return;
        };
        ts.run.assert_success();
        assert_eq!(
            ts.write_summary()[0].1.as_ref().unwrap()["profile_name"],
            "other",
            "TypeScript renames"
        );
        rust.run.assert_code(1);
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some(
                "profile_name in TMP/p.json differs from the profile being updated; rename with --name instead"
            )
        );
        assert!(rust.writes().is_empty());
        let array = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(sandbox.tmp().join("t.json"), b"[1]").unwrap();
        };
        let target = id(11);
        let args = [
            "runtime",
            "topics",
            "update",
            &target,
            "--config",
            "TMP/t.json",
        ];
        let Some((rust, ts)) = both("d103_array", setup(&array), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("TMP/t.json must contain a JSON object")
        );
        assert!(
            ts.run
                .error_line()
                .unwrap_or_default()
                .ends_with("did not match schema: <root>: invalid_type")
        );
    }

    /// D104: the M4 argument checks are usage errors before the tenant is read.
    #[test]
    fn d104_usage_checks_before_the_tenant() {
        let args = [
            "runtime",
            "topics",
            "create",
            "--name",
            "",
            "--description",
            "d",
            "--examples",
            "a",
        ];
        let Some((rust, ts)) = both("d104_constraints", setup(&no_seed), &args) else {
            return;
        };
        let message = "name: Name is required; examples: At least 2 examples required";
        rust.run.assert_code(2);
        assert_eq!(usage_line(&rust.run.stderr).as_deref(), Some(message));
        ts.run.assert_code(1);
        assert_eq!(ts.run.error_line().as_deref(), Some(message));
        let file = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(sandbox.tmp().join("x.json"), br#"{"topic_name": "x"}"#).unwrap();
        };
        let args = [
            "runtime",
            "topics",
            "update",
            "fin",
            "--config",
            "TMP/x.json",
        ];
        let Some((rust, ts)) = both("d104_id", setup(&file), &args) else {
            return;
        };
        let message = "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid topic_id: fin";
        rust.run.assert_code(2);
        assert_eq!(usage_line(&rust.run.stderr).as_deref(), Some(message));
        ts.run.assert_code(1);
        assert_eq!(ts.run.error_line().as_deref(), Some(message));
        let target = id(13);
        let args = ["runtime", "topics", "delete", &target, "--force"];
        let Some((rust, ts)) = both("d104_updated_by", setup(&no_seed), &args) else {
            return;
        };
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("--updated-by <email> is required with --force")
        );
        ts.run.assert_code(1);
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("AISEC_USER_REQUEST_PAYLOAD_ERROR:updatedBy is required")
        );
        let args = ["runtime", "profiles", "delete", "alpha", "--force"];
        let Some((rust, ts)) = both("d104_profile_updated_by", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (2, 2));
        assert_eq!(
            usage_line(&rust.run.stderr),
            usage_line(&ts.run.stderr),
            "the same text"
        );
        assert!(rust.requests.is_empty());
        assert_eq!(
            ts.count(Route::Profiles),
            1,
            "TypeScript checks after the lookup"
        );
    }

    /// D104: an `--updated-by` with a control character is a usage error that names it,
    /// before the tenant; TypeScript sends it form-encoded to the force endpoint.
    #[test]
    fn d104_updated_by_with_control_characters() {
        let target = id(13);
        let args = [
            "runtime",
            "topics",
            "delete",
            &target,
            "--force",
            "--updated-by",
            "ops\tteam@x",
        ];
        let Some((rust, ts)) = both("d104_updated_by_control", setup(&no_seed), &args) else {
            return;
        };
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("--updated-by <email> must not contain control characters")
        );
        assert!(rust.requests.is_empty());
        ts.run.assert_code(0);
        assert_eq!(
            ts.write_summary(),
            [(
                format!("DELETE /aisec/v1/mgmt/topic/{target}/force?updated_by=ops%09team%40x"),
                None
            )]
        );
    }

    /// D105: the non-interactive refusal comes before the tenant and names the argument.
    #[test]
    fn d105_refusals_come_before_the_tenant() {
        let target = id(1);
        let args = ["runtime", "profiles", "delete", &target];
        let Some((rust, ts)) = both("d105_refusal", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (2, 2));
        assert_eq!(
            usage_line(&rust.run.stderr),
            Some(format!(
                "refusing to delete profile \"{target}\" without --force in non-interactive mode"
            ))
        );
        assert_eq!(
            usage_line(&ts.run.stderr).as_deref(),
            Some("refusing to delete profile \"alpha\" without --force in non-interactive mode"),
            "TypeScript names the resolved profile, after its lookup"
        );
        assert!(rust.requests.is_empty());
        assert_eq!(ts.count(Route::Profiles), 1);
        let mut none = setup(&no_seed);
        none.tenant = false;
        let topic = id(13);
        let args = ["runtime", "topics", "delete", &topic];
        let Some((rust, ts)) = both("d105_no_tenant", none, &args) else {
            return;
        };
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr),
            Some(format!(
                "refusing to delete topic {topic} without --force in non-interactive mode"
            ))
        );
        ts.run.assert_code(1);
        assert!(ts.run.error_line().is_some(), "the tenant is read first");
    }

    fn visible(out: &PtyRun) -> String {
        let mut plain = String::new();
        let mut chars = out.transcript.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                continue;
            }
            if c != '\r' {
                plain.push(c);
            }
        }
        plain
    }

    /// D105: TypeScript asks when stdout is a terminal; airs-cli-rs when stdin and stderr
    /// are. Both decline on `n` and send nothing.
    #[test]
    fn d105_the_prompt_and_its_terminals() {
        let Some(ts) = require_ts("d105_prompt") else {
            return;
        };
        let target = id(13);
        let args = ["runtime", "topics", "delete", target.as_str()];
        let world = |cli: &Cli, all: bool| -> (PtyRun, Vec<RecordedRequest>) {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            standard(&server);
            let mut session = if all {
                spawn_pty_all(cli, &sandbox, &args, &RunOptions::new())
            } else {
                spawn_pty(cli, &sandbox, &args, &RunOptions::new())
            };
            session.expect(&format!("Delete topic {target}?"));
            std::thread::sleep(std::time::Duration::from_millis(150));
            session.send(if cli.is_ts() { b"n\r" } else { b"n\n" });
            (session.wait(), server.requests())
        };
        let (rust_out, rust_requests) = world(&rust(), false);
        let (ts_out, ts_requests) = world(&ts, true);
        rust_out.run.assert_success();
        ts_out.run.assert_success();
        for out in [&rust_out, &ts_out] {
            let text = visible(out);
            assert!(
                text.contains(&format!("Delete topic {target}?")),
                "{text:?}"
            );
            assert!(text.contains("ℹ Aborted"), "{text:?}");
        }
        assert!(rust_requests.is_empty());
        assert!(ts_requests.iter().all(|r| !r.route.is_write()));
        // With only stdin and stderr on the terminal TypeScript refuses.
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        standard(&server);
        let refused = spawn_pty(&ts, &sandbox, &args, &RunOptions::new()).wait();
        refused.run.assert_code(2);
        assert!(visible(&refused).contains("refusing to delete topic"));
    }

    /// D106: TypeScript writes its outcome lines on stdout and never quiet-suppresses
    /// success; airs-cli-rs writes them on stderr, quiet-suppressed.
    #[test]
    fn d106_outcome_lines_on_stderr() {
        let args = [
            "runtime",
            "profiles",
            "create",
            "--name",
            "gamma",
            "--prompt-injection",
            "block",
        ];
        let mut quiet = setup(&no_seed);
        quiet.quiet = true;
        let Some((rust, ts)) = both("d106_quiet_profile", quiet, &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(
            (rust.run.stderr.as_str(), ts.run.stderr.as_str()),
            ("", ""),
            "7.3.0 prints a quiet-suppressed status line on stderr, as airs-cli-rs does"
        );
        let args = create_topic("gamma", &[]);
        let mut quiet = setup(&no_seed);
        quiet.quiet = true;
        quiet.ts_env = true;
        let Some((rust, ts)) = both("d106_quiet", quiet, &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.run.stderr, "");
        assert!(ts.run.stdout.contains("  ✓ Topic created: gamma\n"));
        let target = id(13);
        let args = [
            "runtime",
            "topics",
            "delete",
            &target,
            "--force",
            "--updated-by",
            "a@b",
        ];
        let failing = |server: &FixtureServer, _: &Sandbox| {
            server.set_default(Route::TopicForceDelete, Planned::empty_json(404));
        };
        let Some((rust, ts)) = both("d106_failing", setup(&failing), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(
            rust.run.stdout, "",
            "stdout is empty when the command fails"
        );
        assert_eq!(
            ts.run.stdout, RUNTIME_BANNER,
            "TypeScript prints the banner"
        );
        assert_eq!(rust.run.error_line(), ts.run.error_line());
    }

    /// D107: `topics delete --force` prints a fixed line, never the server's message.
    #[test]
    fn d107_force_delete_prints_a_fixed_line() {
        let target = id(13);
        let args = [
            "runtime",
            "topics",
            "delete",
            &target,
            "--force",
            "--updated-by",
            "a@b",
        ];
        for (body, ts_line) in [
            (json!({}), "  ✓ undefined\n".to_owned()),
            (
                json!({"message": "removed by the service"}),
                "  ✓ removed by the service\n".to_owned(),
            ),
        ] {
            let seed = move |server: &FixtureServer, _: &Sandbox| {
                server.push_once(Route::TopicForceDelete, Planned::json(200, &body));
            };
            let Some((rust, ts)) = both("d107", setup(&seed), &args) else {
                return;
            };
            assert_eq!((rust.run.code, ts.run.code), (0, 0));
            assert_eq!(split_outcome_lines(&ts.run.stdout).0, ts_line);
            assert_eq!(
                rust.run.stderr,
                format!("  ✓ Topic {target} force-deleted.\n")
            );
        }
    }

    /// D115: no Node stack trace and no `undefined` ids.
    #[test]
    fn d115_no_crashes_or_undefined_ids() {
        let mut none = setup(&no_seed);
        none.tenant = false;
        let args = [
            "runtime",
            "profiles",
            "create",
            "--name",
            "gamma",
            "--prompt-injection",
            "block",
        ];
        let Some((rust, ts)) = both("d115_tenant", none, &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        for side in [&rust, &ts] {
            assert!(
                !side.run.stderr.contains("    at "),
                "no stack trace (7.3.0 handles the tenant error)"
            );
        }
        assert!(rust.run.error_line().is_some());
        let no_id = |server: &FixtureServer, _: &Sandbox| {
            let mut alpha = fixtures::profile(1, "alpha", 1);
            alpha.as_object_mut().unwrap().remove("profile_id");
            server.set_profiles(TSG, vec![alpha]);
        };
        let args = [
            "runtime",
            "profiles",
            "update",
            "alpha",
            "--prompt-injection",
            "block",
        ];
        let Some((rust, ts)) = both("d115_id", setup(&no_id), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid profile_id: undefined")
        );
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("Profile alpha has no profile_id")
        );
    }

    /// D116: the request-body validation text has no field list.
    #[test]
    fn d116_request_body_text_without_field_paths() {
        let seed = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(sandbox.tmp().join("t.json"), br#"{"topic_name": 5}"#).unwrap();
        };
        let target = id(11);
        let args = [
            "runtime",
            "topics",
            "update",
            &target,
            "--config",
            "TMP/t.json",
        ];
        let Some((rust, ts)) = both("d116", setup(&seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        let base = format!(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/mgmt/topic/uuid/{target} did not match schema"
        );
        assert_eq!(rust.run.error_line(), Some(base.clone()));
        assert_eq!(
            ts.run.error_line(),
            Some(format!("{base}: topic_name: invalid_type"))
        );
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
        assert_eq!(error_line(&rust.run.stderr), rust.run.error_line());
    }

    /// `--dlp-action` changes only the action of `data-leak-detection` on both CLIs (D117,
    /// retired in 8.0: TS 7.3.0 merges recursively).
    #[test]
    fn dlp_action_overlay_keeps_the_dlp_profiles() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            let mut alpha = fixtures::profile(1, "alpha", 1);
            alpha["policy"]["ai-security-profiles"][0]["model-configuration"]["data-protection"] = json!({
                "data-leak-detection": {"action": "alert", "member": [{"text": "PII"}], "mask-data-inline": true}
            });
            server.set_profiles(TSG, vec![alpha]);
        };
        let args = [
            "runtime",
            "profiles",
            "update",
            "alpha",
            "--dlp-action",
            "block",
        ];
        let Some((rust, ts)) = both("d117", setup(&seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        let leak = |side: &Side| {
            side.write_summary()[0].1.as_ref().unwrap()["policy"]["ai-security-profiles"][0]
                ["model-configuration"]["data-protection"]["data-leak-detection"]
                .clone()
        };
        assert_eq!(
            leak(&rust),
            json!({"action": "block", "member": [{"text": "PII"}], "mask-data-inline": true})
        );
        assert_eq!(leak(&ts), leak(&rust), "7.3.0 overlays too (D117 retired)");
    }
}
