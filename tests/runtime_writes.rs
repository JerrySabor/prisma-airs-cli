//! Executable-level acceptance tests for the M4 topic and profile writes (DESIGN §13.1–
//! §13.7, §13.12–§13.14): `runtime topics create|update|delete` and `runtime profiles
//! create|update|delete`.
//!
//! Every test spawns the real `airs-cli-rs` binary against the loopback fixture server
//! with its stateful write routes. Usage errors are proven to need no tenant and to send
//! nothing; every write is checked request by request (one attempt, the single 401
//! replay, outcome lines), and the resulting fixture state is read back.

use std::time::Duration;

use airs_test_harness::{
    AuthIdentity, Cli, ClosedPort, FixtureServer, FixtureTenant, Planned, PtyRun, RecordedRequest,
    Route, Run, RunOptions, Sandbox, fixtures, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

const TSG: &str = "100";
const DEBUG_HINT: &str = "    Re-run with --debug to capture redacted API diagnostics.\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn id(n: u64) -> String {
    fixtures::uuid(n)
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
    #[allow(dead_code)]
    tenant: FixtureTenant,
}

/// The standard tenant `prod` (TSG 100) with two revisions of topic `fin` (the older,
/// id 11, listed first), topic `other` (id 13), and profiles `alpha` (id 1) and `beta`
/// revisions 1 and 3 (ids 2 and 4, the older first).
fn world() -> Fx {
    fx_with(|_| {})
}

fn fx_with(edit: impl FnOnce(&mut airs_test_harness::FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    server.set_topics(
        TSG,
        vec![
            fixtures::topic(11, "fin", 1, "finance"),
            fixtures::topic(12, "fin", 2, "finance v2"),
            fixtures::topic(13, "other", 1, "other topic"),
        ],
    );
    server.set_profiles(
        TSG,
        vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(2, "beta", 1),
            fixtures::profile(4, "beta", 3),
        ],
    );
    Fx {
        server,
        sandbox,
        tenant,
    }
}

/// A sandbox with no tenant at all: usage errors must not need one.
fn bare() -> (FixtureServer, Sandbox) {
    (FixtureServer::start(), Sandbox::new())
}

impl Fx {
    fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, &RunOptions::new())
    }

    fn run_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let out = run(&rust(), &self.sandbox, args, options);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        assert!(self.sandbox.cwd_listing().is_empty(), "wrote into cwd");
        out
    }

    fn lines(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .map(RecordedRequest::line)
            .collect()
    }

    fn routes(&self) -> Vec<Route> {
        self.server.routes()
    }

    fn writes(&self) -> Vec<RecordedRequest> {
        self.server
            .requests()
            .into_iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    /// A file under the sandbox's `tmp/`.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.sandbox.tmp().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    }

    fn topic_ids(&self) -> Vec<String> {
        self.server
            .topics(TSG)
            .iter()
            .map(|row| row["topic_id"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    fn profile(&self, id: &str) -> Option<Value> {
        self.server
            .profiles(TSG)
            .into_iter()
            .find(|row| row["profile_id"] == id)
    }
}

/// The exact stderr error block (no `--debug`).
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

/// Runs a usage error in a sandbox without any tenant: exit 2, the exact message, no
/// request.
fn assert_usage(args: &[&str], message: &str) {
    let (server, sandbox) = bare();
    let out = run(&rust(), &sandbox, args, &RunOptions::new());
    out.assert_code(2);
    assert_eq!(out.stdout, "", "{args:?}");
    assert_eq!(out.stderr, usage_block(message), "{args:?}");
    assert_eq!(server.request_count(), 0, "{args:?}");
}

fn bearer(request: &RecordedRequest) -> Option<&str> {
    request.header("authorization")
}

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

const CREATE: [&str; 9] = [
    "runtime",
    "topics",
    "create",
    "--name",
    "fresh",
    "--description",
    "a new topic",
    "--examples",
    "first",
];

fn create_args<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut args: Vec<&str> = CREATE.to_vec();
    args.push("second");
    args.extend_from_slice(extra);
    args
}

mod topics_create {
    use super::*;

    #[test]
    fn a_new_name_is_posted_once_with_the_exact_body() {
        let fx = world();
        let out = fx.run(&create_args(&[]));
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!("  ID        {}\n  Revision  1\n", id(901))
        );
        assert_eq!(out.stderr, "  ✓ Topic created: fresh\n");
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                "GET /aisec/v1/mgmt/topics/tsg/100?offset=0&limit=100".to_owned(),
                "POST /aisec/v1/mgmt/topic".to_owned(),
            ]
        );
        let write = &fx.writes()[0];
        assert_eq!(
            write.body_json(),
            Some(
                json!({"topic_name": "fresh", "description": "a new topic", "examples": ["first", "second"]})
            )
        );
        assert_eq!(
            write.auth,
            AuthIdentity::Bearer {
                tsg: Some(TSG.into())
            }
        );
        assert_eq!(bearer(write), Some("Bearer mock-token-100"));
        assert_eq!(fx.topic_ids().last(), Some(&id(901)));
    }

    /// D96: an existing name updates its highest revision (id 12), not the first listed.
    #[test]
    fn an_existing_name_updates_its_highest_revision_d96() {
        let fx = world();
        let out = fx.run(&[
            "runtime",
            "topics",
            "create",
            "--name",
            "fin",
            "--description",
            "changed",
            "--examples",
            "a",
            "b",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({"topicId": id(12), "topicName": "fin", "revision": 3, "created": false})
        );
        assert_eq!(out.stderr, "  ✓ Topic updated: fin\n");
        let writes = fx.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].line(),
            format!("PUT /aisec/v1/mgmt/topic/uuid/{}", id(12))
        );
        assert_eq!(
            writes[0].body_json(),
            Some(json!({"topic_name": "fin", "description": "changed", "examples": ["a", "b"]})),
            "the existing topic's other fields are not carried over"
        );
    }

    #[test]
    fn table_output_is_the_record() {
        let fx = world();
        let out = fx.run(&create_args(&["--output", "table"]));
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                " Key       │ Value                                \n───────────┼──────────────────────────────────────\n topicId   │ {} \n topicName │ fresh                                \n revision  │ 1                                    \n created   │ true                                 \n",
                id(901)
            )
        );
    }

    #[test]
    fn the_tenant_default_output_is_ignored() {
        let fx = fx_with(|config| {
            config.set("defaultOutput", "json");
        });
        let out = fx.run(&create_args(&[]));
        out.assert_success();
        assert!(out.stdout.starts_with("  ID        "), "{}", out.stdout);
    }

    #[test]
    fn quiet_keeps_the_data_and_drops_the_outcome_line() {
        let fx = world();
        let out = fx.run(&create_args(&["--quiet"]));
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!("  ID        {}\n  Revision  1\n", id(901))
        );
        assert_eq!(out.stderr, "");
    }

    #[test]
    fn colour_follows_each_stream() {
        let fx = world();
        let out = fx.run_with(
            &create_args(&[]),
            &RunOptions::new()
                .without_env("NO_COLOR")
                .env("CLICOLOR_FORCE", "1"),
        );
        out.assert_success();
        assert_eq!(out.stderr, "  \u{1b}[32m✓ Topic created: fresh\u{1b}[39m\n");
        assert_eq!(
            out.stdout,
            format!(
                "  \u{1b}[2mID      \u{1b}[22m  {}\n  \u{1b}[2mRevision\u{1b}[22m  1\n",
                id(901)
            )
        );
    }

    /// Server and argument text in outcome lines and data cannot drive the terminal.
    #[test]
    fn control_characters_are_replaced_in_outcome_lines_and_data() {
        let fx = world();
        let out = fx.run(&[
            "runtime",
            "topics",
            "create",
            "--name",
            "evil\u{1b}]0;x",
            "--description",
            "d",
            "--examples",
            "a",
            "b",
            "--output",
            "table",
        ]);
        out.assert_success();
        assert_eq!(out.stderr, "  ✓ Topic created: evil\u{fffd}]0;x\n");
        assert!(!out.stdout.contains('\u{1b}'), "{:?}", out.stdout);
        assert!(out.stdout.contains("evil\u{fffd}]0;x"));
    }

    /// The constraints are usage errors before the tenant (D104), collected in order.
    #[test]
    fn constraint_failures_are_usage_errors_without_a_tenant_d104() {
        assert_usage(
            &[
                "runtime",
                "topics",
                "create",
                "--name",
                "",
                "--description",
                "",
                "--examples",
                "only",
            ],
            "name: Name is required; description: Description is required; examples: At least 2 examples required",
        );
        let long = "x".repeat(101);
        assert_usage(
            &[
                "runtime",
                "topics",
                "create",
                "--name",
                &long,
                "--description",
                "d",
                "--examples",
                "a",
                "",
                "c",
                "--examples",
                "d",
                "e",
                "f",
            ],
            "name: Name must be at most 100 bytes; examples: At most 5 examples allowed; examples[1]: Example 1 is required",
        );
        let big = "y".repeat(250);
        assert_usage(
            &[
                "runtime",
                "topics",
                "create",
                "--name",
                "n",
                "--description",
                &big,
                "--examples",
                &big,
                &big,
                &big,
                &big,
            ],
            "topic: Combined length (1251) exceeds 1000 bytes",
        );
    }

    /// The hidden `--format` warns first, is validated like `--output`, and `--output`
    /// wins over it (D94).
    #[test]
    fn the_deprecated_format_alias_d94() {
        let fx = world();
        let out = fx.run(&create_args(&["--format", "json"]));
        out.assert_success();
        assert_eq!(out.json()["topicName"], "fresh");
        assert_eq!(
            out.stderr,
            "  ⚠ --format is deprecated and will be removed in v4 — use --output\n  ✓ Topic created: fresh\n"
        );
        let fx = world();
        let out = fx.run(&create_args(&["--format", "json", "--output", "pretty"]));
        out.assert_success();
        assert!(out.stdout.starts_with("  ID  "), "--output wins");
        let (server, sandbox) = bare();
        let out = run(
            &rust(),
            &sandbox,
            &create_args(&["--format", "xml", "--quiet"]),
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            format!(
                "  ⚠ --format is deprecated and will be removed in v4 — use --output\n{}",
                usage_block("Invalid output format 'xml'. Expected: pretty, table, json")
            ),
            "the warning is never quiet-suppressed"
        );
        assert_eq!(server.request_count(), 0);
        let help = run(
            &rust(),
            &sandbox,
            &["runtime", "topics", "create", "--help"],
            &RunOptions::new(),
        );
        help.assert_success();
        assert!(!help.stdout.contains("--format"), "hidden from help");
    }

    /// D95: a 5xx answer is never re-sent; the outcome is unknown.
    #[test]
    fn a_server_error_is_one_post_with_an_unknown_outcome_d95() {
        let fx = world();
        fx.server.push_once(
            Route::TopicCreate,
            Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
        );
        let out = fx.run(&create_args(&[]));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 503",
                Some(503),
                &["Outcome unknown: the topic may have been created."]
            )
        );
        assert_eq!(fx.writes().len(), 1);
    }

    /// D95: a 401 on the write is replayed once with a fresh token.
    #[test]
    fn a_rejected_token_is_replayed_once_d95() {
        let fx = world();
        fx.server
            .push_once(Route::TopicCreate, Planned::empty_json(401));
        let out = fx.run(&create_args(&[]));
        out.assert_success();
        assert_eq!(
            fx.routes(),
            [
                Route::Token,
                Route::Topics,
                Route::TopicCreate,
                Route::Token,
                Route::TopicCreate
            ]
        );
        let fx = world();
        fx.server
            .set_default(Route::TopicCreate, Planned::empty_json(401));
        let out = fx.run(&create_args(&[]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 401", Some(401), &[]),
            "a rejection is final after the one replay"
        );
        assert_eq!(fx.writes().len(), 2);
    }

    #[test]
    fn a_forbidden_write_is_never_replayed_d95() {
        let fx = world();
        fx.server
            .push_once(Route::TopicCreate, Planned::empty_json(403));
        let out = fx.run(&create_args(&[]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 403", Some(403), &[])
        );
        assert_eq!(fx.writes().len(), 1);
    }

    #[test]
    fn an_unreadable_success_body_says_the_topic_was_created() {
        let fx = world();
        fx.server.push_once(
            Route::TopicCreate,
            Planned::raw(200, "application/json", "{not json"),
        );
        let out = fx.run(&create_args(&[]));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema",
                None,
                &["Outcome: the topic was created, but the response could not be read."]
            )
        );
    }

    #[test]
    fn a_response_without_topic_id_is_an_error_after_the_write() {
        let fx = world();
        fx.server.push_once(
            Route::TopicCreate,
            Planned::json(
                200,
                &json!({"topic_name": "fresh", "revision": 1, "description": "a new topic"}),
            ),
        );
        let out = fx.run(&create_args(&[]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "API response missing topic_id",
                None,
                &["Outcome: the topic was created, but the response carried no topic_id."]
            )
        );
    }

    #[test]
    fn an_existing_match_without_topic_id_writes_nothing() {
        let fx = world();
        fx.server.set_topics(
            TSG,
            vec![json!({"topic_name": "fin", "revision": 1, "description": "d"})],
        );
        let out = fx.run(&[
            "runtime",
            "topics",
            "create",
            "--name",
            "fin",
            "--description",
            "d",
            "--examples",
            "a",
            "b",
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("Existing topic 'fin' has no topic_id", None, &[])
        );
        assert!(fx.writes().is_empty());
    }

    #[test]
    fn a_failed_lookup_writes_nothing() {
        let fx = world();
        fx.server
            .set_default(Route::Topics, Planned::empty_json(404));
        let out = fx.run(&create_args(&[]));
        out.assert_code(1);
        assert_eq!(out.http_status(), Some(404));
        assert!(fx.writes().is_empty());
    }

    /// A signal while the write is in flight: the change may have been applied.
    #[test]
    fn an_interrupted_write_reports_an_unknown_outcome() {
        let fx = world();
        fx.server.push_once(Route::TopicCreate, Planned::hang());
        let running = spawn(&rust(), &fx.sandbox, &create_args(&[]), &RunOptions::new());
        assert!(
            fx.server.wait_for_requests(3, Duration::from_secs(20)),
            "the POST arrived"
        );
        running.send_signal("INT");
        let out = running.wait();
        out.assert_code(130);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; the change may already have been applied (outcome unknown)\n\n"
        );
    }
}

mod topics_update {
    use super::*;

    fn update<'a>(id: &'a str, path: &'a str) -> Vec<&'a str> {
        vec!["runtime", "topics", "update", id, "--config", path]
    }

    #[test]
    fn the_file_is_the_body_and_the_response_is_rendered() {
        let fx = world();
        let path = fx.file(
            "topic.json",
            br#"{"topic_name": "fin", "description": "edited", "examples": ["x"], "x-extra": {"kept": true}}"#,
        );
        let target = id(11);
        let out = fx.run(&update(&target, &path));
        out.assert_success();
        assert_eq!(out.stderr, format!("  ✓ Topic updated: {target}\n"));
        assert!(out.stdout.contains("  Topic Detail:"), "{}", out.stdout);
        assert!(out.stdout.contains("  Description  edited"));
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                format!("PUT /aisec/v1/mgmt/topic/uuid/{target}")
            ],
            "no lookup"
        );
        assert_eq!(
            fx.writes()[0].body_json(),
            Some(
                json!({"topic_name": "fin", "description": "edited", "examples": ["x"], "x-extra": {"kept": true}})
            ),
            "unknown keys are kept"
        );
        let json = fx.run(&[
            "runtime", "topics", "update", &target, "--config", &path, "--output", "json",
        ]);
        json.assert_success();
        assert_eq!(json.json()["topicId"], target);
        assert_eq!(json.json()["revision"], 3);
    }

    #[test]
    fn a_non_uuid_id_is_a_usage_error_d104() {
        assert_usage(
            &["runtime", "topics", "update", "fin", "--config", "x.json"],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid topic_id: fin",
        );
    }

    /// D103: file errors are fixed messages before the tenant, with no request.
    #[test]
    fn file_errors_come_before_the_tenant_d103() {
        let (server, sandbox) = bare();
        let target = id(11);
        let tmp = sandbox.tmp();
        for (name, bytes, message) in [
            (
                "absent.json",
                None,
                "(missing, not a regular file, unreadable or larger than 1 MiB)",
            ),
            ("broken.json", Some(&b"{\"a\": "[..]), "is not valid JSON"),
            (
                "array.json",
                Some(&b"[1, 2]"[..]),
                "must contain a JSON object",
            ),
            (
                "latin1.json",
                Some(&b"{\"a\": \"\xe9\"}"[..]),
                "is not valid UTF-8",
            ),
        ] {
            let path = tmp.join(name);
            if let Some(bytes) = bytes {
                std::fs::write(&path, bytes).unwrap();
            }
            let shown = path.display().to_string();
            let out = run(
                &rust(),
                &sandbox,
                &update(&target, &shown),
                &RunOptions::new(),
            );
            out.assert_code(1);
            let expected = if message.starts_with('(') {
                format!("Cannot read {shown} {message}")
            } else {
                format!("{shown} {message}")
            };
            assert_eq!(out.stderr, error_block(&expected, None, &[]), "{name}");
            assert!(!out.stderr.contains("\"a\""), "no file content is echoed");
        }
        let directory = tmp.display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &update(&target, &directory),
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert!(out.stderr.contains("not a regular file"), "{}", out.stderr);
        assert_eq!(server.request_count(), 0);
    }

    /// D116: a body that fails the request schema is refused locally, without the
    /// field list, before the tenant is read.
    #[test]
    fn a_body_that_fails_the_schema_is_not_sent_d116() {
        let (server, sandbox) = bare();
        let path = sandbox.tmp().join("bad.json");
        std::fs::write(&path, br#"{"topic_name": 5}"#).unwrap();
        let target = id(11);
        let out = run(
            &rust(),
            &sandbox,
            &update(&target, &path.display().to_string()),
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                &format!(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/mgmt/topic/uuid/{target} did not match schema"
                ),
                None,
                &[]
            )
        );
        assert_eq!(server.request_count(), 0);
    }

    #[test]
    fn a_missing_topic_is_the_servers_404() {
        let fx = world();
        let path = fx.file("t.json", br#"{"topic_name": "x"}"#);
        let missing = id(99);
        let out = fx.run(&update(&missing, &path));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 404", Some(404), &[])
        );
    }

    /// G3: a refused connection after dispatch is reported as an unknown outcome.
    #[test]
    fn a_refused_connection_is_an_unknown_outcome() {
        let closed = ClosedPort::new();
        let fx = fx_with(|config| {
            config.set(
                "mgmtEndpoint",
                format!("http://127.0.0.1:{}/aisec", closed.port()),
            );
        });
        let path = fx.file("t.json", br#"{"topic_name": "x"}"#);
        let target = id(11);
        let out = fx.run(&update(&target, &path));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_CLIENT_SIDE_ERROR:Network request failed (connection refused, reset or unreachable)",
                None,
                &["Outcome unknown: the topic may have been updated."]
            )
        );
        assert_eq!(fx.routes(), [Route::Token]);
    }
}

mod topics_delete {
    use super::*;

    fn delete(extra: &[&str]) -> Vec<String> {
        let mut args: Vec<String> = ["runtime", "topics", "delete"]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect();
        args.push(id(13));
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        args
    }

    fn refs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }

    #[test]
    fn force_uses_the_audit_endpoint_and_a_fixed_line_d107() {
        let fx = world();
        fx.server.push_once(
            Route::TopicForceDelete,
            Planned::json(200, &json!({"message": "\u{1b}]0;server text"})),
        );
        let args = delete(&["--force", "--updated-by", "ops team@example.com"]);
        let out = fx.run(&refs(&args));
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, format!("  ✓ Topic {} force-deleted.\n", id(13)));
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                format!(
                    "DELETE /aisec/v1/mgmt/topic/{}/force?updated_by=ops+team%40example.com",
                    id(13)
                )
            ]
        );
    }

    #[test]
    fn a_plain_delete_with_force_and_quiet() {
        let fx = world();
        let args = delete(&["--force", "--updated-by", "a@b", "--quiet"]);
        let out = fx.run(&refs(&args));
        out.assert_success();
        assert_eq!(out.stderr, "", "the outcome line is quiet-suppressed");
        assert!(!fx.topic_ids().contains(&id(13)));
    }

    #[test]
    fn usage_checks_come_before_the_tenant_d104() {
        assert_usage(
            &refs(&delete(&[])),
            &format!(
                "refusing to delete topic {} without --force in non-interactive mode",
                id(13)
            ),
        );
        assert_usage(
            &[
                "runtime",
                "topics",
                "rm",
                "fin",
                "--force",
                "--updated-by",
                "a@b",
            ],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid topic_id: fin",
        );
        assert_usage(
            &["runtime", "topics", "rm", "fin"],
            "refusing to delete topic fin without --force in non-interactive mode",
        );
        for extra in [&["--force"][..], &["--force", "--updated-by", " \t"]] {
            assert_usage(
                &refs(&delete(extra)),
                "--updated-by <email> is required with --force",
            );
        }
        // D104: a control character is named as such, not as a missing flag.
        assert_usage(
            &refs(&delete(&["--force", "--updated-by", "ops\tteam@x"])),
            "--updated-by <email> must not contain control characters",
        );
        assert_usage(
            &refs(&delete(&[
                "--force",
                "--updated-by",
                "a@b",
                "--output",
                "yaml",
            ])),
            "Invalid output format 'yaml'. Expected: pretty, table, json",
        );
    }

    #[test]
    fn a_referenced_topic_is_refused_with_409() {
        let fx = world();
        let mut profile = fixtures::profile(1, "alpha", 1);
        profile["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"] = json!([{
            "name": "topic-guardrails", "action": "allow",
            "topic-list": [{"action": "block", "topic": [{"topic_id": id(13), "topic_name": "other", "revision": 1}]}]
        }]);
        fx.server.set_profiles(TSG, vec![profile]);
        let out = fx.run_with(
            &["runtime", "topics", "delete", &id(13)],
            &RunOptions::new(),
        );
        // Non-interactive without --force is refused before anything else.
        out.assert_code(2);
        let args = delete(&["--force", "--updated-by", "a@b"]);
        fx.server.push_once(
            Route::TopicForceDelete,
            Planned::json(
                409,
                &json!({"message": "in use", "payload": [{"profile_id": id(1), "profile_name": "alpha", "revision": 1}]}),
            ),
        );
        let out = fx.run(&refs(&args));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 409", Some(409), &[]),
            "a rejection: no outcome line, no server text (G2)"
        );
        assert!(fx.topic_ids().contains(&id(13)));
    }

    #[test]
    fn a_server_error_is_one_delete_with_an_unknown_outcome_d95() {
        let fx = world();
        fx.server.set_default(
            Route::TopicForceDelete,
            Planned::json(500, &json!({})).with_retry_after(0),
        );
        let args = delete(&["--force", "--updated-by", "a@b"]);
        let out = fx.run(&refs(&args));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 500",
                Some(500),
                &["Outcome unknown: the topic may have been deleted."]
            )
        );
        assert_eq!(fx.writes().len(), 1);
    }

    fn pty_delete(fx: &Fx, answer: &[u8]) -> PtyRun {
        let target = id(13);
        let mut session = spawn_pty(
            &rust(),
            &fx.sandbox,
            &[
                "runtime",
                "topics",
                "delete",
                &target,
                "--updated-by",
                "unused@x",
            ],
            &RunOptions::new(),
        );
        session.expect(&format!("? Delete topic {target}? (y/N) "));
        assert!(
            fx.server.requests().is_empty(),
            "no request while the prompt waits"
        );
        session.send(answer);
        session.wait()
    }

    /// D105: the prompt is on stderr with stdin and stderr on a terminal; the token is
    /// fetched only after it was answered.
    #[test]
    fn the_confirmation_accepts_y_and_yes_d105() {
        for answer in [&b"y\n"[..], b" YES \n"] {
            let fx = world();
            let out = pty_delete(&fx, answer);
            out.run.assert_success();
            assert_eq!(out.run.stdout, "");
            assert!(
                transcript(&out).contains(&format!("  ✓ Topic {} deleted.\n", id(13))),
                "{}",
                transcript(&out)
            );
            assert_eq!(
                fx.lines(),
                [
                    "POST /oauth/token".to_owned(),
                    format!("DELETE /aisec/v1/mgmt/topic/{}", id(13))
                ],
                "a plain delete; --updated-by without --force is unused"
            );
        }
    }

    #[test]
    fn declining_or_eof_aborts_with_nothing_sent_d105() {
        for answer in [&b"n\n"[..], b"\n", b"yolo\n", b"\x04"] {
            let fx = world();
            let out = pty_delete(&fx, answer);
            out.run.assert_success();
            assert!(transcript(&out).contains("  ℹ Aborted\n"), "{answer:?}");
            assert_eq!(fx.server.request_count(), 0, "{answer:?}");
        }
    }

    #[test]
    fn ctrl_c_at_the_prompt_changes_nothing_d105() {
        let fx = world();
        let target = id(13);
        let mut session = spawn_pty(
            &rust(),
            &fx.sandbox,
            &["runtime", "topics", "delete", &target],
            &RunOptions::new(),
        );
        session.expect("(y/N) ");
        session.signal("INT");
        let out = session.wait();
        out.run.assert_code(130);
        assert!(
            transcript(&out).contains("\n  Cancelled; nothing was changed.\n"),
            "{}",
            transcript(&out)
        );
        assert_eq!(fx.server.request_count(), 0);
    }
}

fn create_profile<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["runtime", "profiles", "create", "--name", "gamma"];
    args.extend_from_slice(extra);
    args
}

mod profiles_create {
    use super::*;

    #[test]
    fn flags_build_the_typescript_body() {
        let fx = world();
        let out = fx.run(&create_profile(&[
            "--prompt-injection",
            "block",
            "--toxic-content",
            "alert",
            "--dlp-action",
            "block",
            "--dlp-profiles",
            "PII, ,PCI",
            "--mask-data-inline",
            "--no-active",
            "--max-inline-latency",
            "7",
            "--output",
            "json",
        ]));
        out.assert_success();
        // TS 7.3.0 prints a status line (dim, quiet-suppressed), no check mark.
        assert_eq!(out.stderr, format!("  Profile created: {}\n", id(901)));
        assert_eq!(out.json()["profileName"], "gamma");
        assert_eq!(out.json()["active"], false);
        assert_eq!(
            fx.lines(),
            ["POST /oauth/token", "POST /aisec/v1/mgmt/profile"]
        );
        assert_eq!(
            fx.writes()[0].body_json(),
            Some(json!({
                "profile_name": "gamma",
                "active": false,
                "policy": {"ai-security-profiles": [{
                    "model-type": "default",
                    "model-configuration": {
                        "model-protection": [
                            {"name": "prompt-injection", "action": "block"},
                            {"name": "toxic-content", "action": "high:alert, moderate:alert"}
                        ],
                        "data-protection": {"data-leak-detection": {
                            "action": "block",
                            "member": [{"text": "PII"}, {"text": "PCI"}],
                            "mask-data-inline": true
                        }},
                        "app-protection": {
                            "default-url-category": {"member": ["malicious"]},
                            "url-detected-action": "block"
                        },
                        "latency": {"max-inline-latency": 7},
                        "mask-data-in-storage": false
                    }
                }]}
            }))
        );
    }

    #[test]
    fn pretty_and_table_render_the_response() {
        let fx = world();
        let out = fx.run(&create_profile(&["--prompt-injection", "block"]));
        out.assert_success();
        // TS 7.3.0: the detail without the runtime banner.
        assert!(
            out.stdout.starts_with("\n  Profile Detail:\n\n"),
            "{}",
            out.stdout
        );
        let fx = world();
        let out = fx.run(&create_profile(&[
            "--prompt-injection",
            "block",
            "--output",
            "table",
        ]));
        out.assert_success();
        assert!(out.stdout.starts_with(" Key "), "{}", out.stdout);
        assert!(
            out.stdout.contains(" profileName    │ gamma "),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn usage_errors_need_no_tenant_d102() {
        assert_usage(
            &create_profile(&[]),
            "Specify at least one policy flag (for example --prompt-injection block) or --config <path>",
        );
        assert_usage(
            &create_profile(&["--prompt-injection", ""]),
            "Specify at least one policy flag (for example --prompt-injection block) or --config <path>",
        );
        assert_usage(
            &[
                "runtime",
                "profiles",
                "create",
                "--prompt-injection",
                "block",
            ],
            "--name is required unless --config is supplied",
        );
        // D336: a directional flag create that fills no direction (no flag, or shared
        // settings only) is refused before the tenant is read.
        for shared in [
            &[][..],
            &["--max-inline-latency", "8"],
            &["--inline-timeout-action", "allow"],
            &["--mask-data-in-storage"],
            &["--no-enable-full-conversation-inspection"],
            &["--max-inline-latency", "8", "--no-mask-data-in-storage"],
        ] {
            let mut args = create_profile(&["--direction", "response"]);
            args.extend_from_slice(shared);
            assert_usage(
                &args,
                "Directional flag creation requires at least one protection flag, not only \
                 shared settings: the service refuses a directional policy with no protection \
                 in any direction",
            );
        }
        assert_usage(
            &create_profile(&["--direction", "sideways", "--prompt-injection", "block"]),
            "--direction must be prompt, response, tool-call, or tool-response",
        );
        for bad in ["1.5", "abc", "-1", ""] {
            assert_usage(
                &create_profile(&["--max-inline-latency", bad]),
                "--max-inline-latency must be a non-negative integer",
            );
        }
        for extra in [
            &["--dlp-profiles", "PII"][..],
            &["--mask-data-inline"],
            &["--no-mask-data-inline"],
            &["--dlp-profiles", ""],
        ] {
            let mut args = create_profile(&["--prompt-injection", "block"]);
            args.extend_from_slice(extra);
            assert_usage(
                &args,
                "--dlp-profiles and --[no-]mask-data-inline require --dlp-action when creating a profile",
            );
        }
        for extra in [
            &["--no-active"][..],
            &["--prompt-injection", ""],
            &["--name", "gamma"],
            &["--direction", "prompt"],
            &["--no-mask-data-in-storage"],
            &["--enable-full-conversation-inspection"],
        ] {
            let mut args = vec!["runtime", "profiles", "create", "--config", "p.json"];
            args.extend_from_slice(extra);
            assert_usage(
                &args,
                "--config cannot be combined with profile write flags or selectors",
            );
        }
    }

    /// 8.0 (TS 7.3.0): the file is the whole body and names the profile; `--name` is
    /// refused beside it (§13.17).
    #[test]
    fn a_config_file_is_sent_as_is_and_names_the_profile() {
        let fx = world();
        let body = json!({"profile_name": "gamma", "active": true, "policy": {"ai-security-profiles": [{"model-type": "default", "model-configuration": {"x-custom": 1}}]}});
        let path = fx.file("p.json", body.to_string().as_bytes());
        let out = fx.run(&["runtime", "profiles", "create", "--config", &path]);
        out.assert_success();
        assert_eq!(fx.writes()[0].body_json(), Some(body));
        assert_eq!(out.stderr, format!("  Profile created: {}\n", id(901)));
    }

    /// 8.0: a `--config` body that fails the TypeScript 0.35.0 request schema is a usage
    /// error before the tenant (D116 text, exit 2).
    #[test]
    fn a_config_file_that_fails_the_schema_is_a_usage_error_d116() {
        let fx = world();
        let mut bad = fixtures::runtime::directional_profile();
        bad["policy"]["ai-security-profiles"][0]["content-type-configurations"]["response"]["model-protection"]
            [0]["severity"] = json!(123);
        let path = fx.file("bad.json", bad.to_string().as_bytes());
        let out = fx.run(&["runtime", "profiles", "create", "--config", &path]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/mgmt/profile did not match schema"
            )
        );
        assert_eq!(fx.server.request_count(), 0, "before the tenant");
    }

    /// D101: a 409 is an error, never a lookup, whatever its body.
    #[test]
    fn a_conflict_is_an_error_without_a_lookup_d101() {
        for planned in [
            Planned::status(409),
            Planned::json(409, &json!({"message": "exists"})),
        ] {
            let fx = world();
            fx.server.push_once(Route::ProfileCreate, planned);
            let out = fx.run(&[
                "runtime",
                "profiles",
                "create",
                "--name",
                "alpha",
                "--prompt-injection",
                "block",
            ]);
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                error_block(
                    "Profile \"alpha\" already exists. Use 'profiles update' to modify it.",
                    Some(409),
                    &[]
                )
            );
            assert_eq!(fx.routes(), [Route::Token, Route::ProfileCreate]);
        }
    }

    /// 8.0 (TS 7.3.0): `profiles create|update` resolve their format like reads: the
    /// tenant's `defaultOutput` applies unless `--output` is given; `yaml` stays refused
    /// (D50).
    #[test]
    fn the_tenant_default_output_applies_d50() {
        for command in ["create", "update"] {
            let fx = fx_with(|config| {
                config.set("defaultOutput", "json");
            });
            let args: Vec<&str> = if command == "create" {
                create_profile(&["--prompt-injection", "block"])
            } else {
                vec![
                    "runtime",
                    "profiles",
                    "update",
                    "alpha",
                    "--prompt-injection",
                    "block",
                ]
            };
            let out = fx.run(&args);
            out.assert_success();
            assert!(out.json()["profileName"].is_string(), "{}", out.stdout);
            let mut pretty = args.clone();
            pretty.extend(["--output", "pretty"]);
            let out = fx.run(&pretty);
            out.assert_success();
            assert!(
                out.stdout.starts_with("\n  Profile Detail:\n"),
                "{}",
                out.stdout
            );
            let mut yaml = args.clone();
            yaml.extend(["--output", "yaml"]);
            assert_usage(
                &yaml,
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            );
        }
    }

    /// 8.0: a directional flag body (§13.17; the other three directions written empty,
    /// D335), and the protection locations of the answer.
    #[test]
    fn a_direction_creates_one_directional_entry() {
        let fx = world();
        let out = fx.run(&create_profile(&[
            "--direction",
            "tool-response",
            "--agent-security",
            "block",
            "--mask-data-in-storage",
        ]));
        out.assert_success();
        assert_eq!(
            fx.writes()[0].body_json().unwrap()["policy"],
            json!({"ai-security-profiles": [{
                "model-type": "default",
                "content-type-mode": "per_content_type",
                "model-configuration": {"mask-data-in-storage": true},
                "content-type-configurations": {
                    "prompt": {},
                    "response": {},
                    "tool-call": {},
                    "tool-response": {
                        "agent-protection": [{"name": "agent-security", "action": "block"}]
                    }
                }
            }]})
        );
        assert!(
            out.stdout.contains(
                "  Protection locations  AI[0] default / prompt, AI[0] default / response, \
                 AI[0] default / tool-call, AI[0] default / tool-response\n"
            ),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn a_server_error_is_an_unknown_outcome_d95() {
        let fx = world();
        fx.server.push_once(
            Route::ProfileCreate,
            Planned::json(502, &json!({})).with_retry_after(0),
        );
        let out = fx.run(&create_profile(&["--prompt-injection", "block"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 502",
                Some(502),
                &["Outcome unknown: the profile may have been created."]
            )
        );
        assert_eq!(fx.writes().len(), 1);
    }

    #[test]
    fn missing_credentials_are_reported_without_requests_d115() {
        let (server, sandbox) = bare();
        let out = run(
            &rust(),
            &sandbox,
            &create_profile(&["--prompt-injection", "block"]),
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert!(out.stderr.starts_with("\n  ✗ Error: "), "{}", out.stderr);
        assert!(!out.stderr.contains("    at "), "no stack trace");
        assert_eq!(server.request_count(), 0);
    }
}

mod profiles_update {
    use super::*;

    fn update<'a>(target: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec!["runtime", "profiles", "update", target];
        args.extend_from_slice(extra);
        args
    }

    #[test]
    fn a_policy_flag_merges_into_the_highest_revision_and_keeps_active_d100() {
        let fx = world();
        let mut beta = fixtures::profile(4, "beta", 3);
        beta["active"] = json!(false);
        fx.server
            .set_profiles(TSG, vec![fixtures::profile(2, "beta", 1), beta]);
        let out = fx.run(&update("beta", &["--prompt-injection", "block"]));
        out.assert_success();
        assert_eq!(out.stderr, format!("  Profile updated: {}\n", id(4)));
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                "GET /aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100".to_owned(),
                format!("PUT /aisec/v1/mgmt/profile/uuid/{}", id(4))
            ]
        );
        assert_eq!(
            fx.writes()[0].body_json(),
            Some(json!({
                "profile_name": "beta",
                "active": false,
                "policy": {
                    "ai-security-profiles": [{
                        "model-type": "default",
                        "model-configuration": {
                            "mask-data-in-storage": false,
                            "model-protection": [{"name": "prompt-injection", "action": "block"}]
                        }
                    }],
                    "dlp-data-profiles": []
                }
            }))
        );
    }

    /// The service may answer a PUT with a new revision under a new id (DESIGN §10 M4):
    /// the outcome line and the data name the response's id.
    #[test]
    fn a_new_revision_under_a_new_id_is_reported() {
        let fx = world();
        fx.server.set_put_appends_new_record(true);
        let out = fx.run(&update(
            "alpha",
            &["--prompt-injection", "block", "--output", "json"],
        ));
        out.assert_success();
        assert_eq!(out.stderr, format!("  Profile updated: {}\n", id(901)));
        assert_eq!(out.json()["profileId"], id(901));
        assert_eq!(out.json()["revision"], 2);
        assert!(fx.profile(&id(1)).is_some(), "the old revision is kept");
    }

    #[test]
    fn rename_and_activation_flags() {
        let fx = world();
        let target = id(1);
        let out = fx.run(&update(&target, &["--name", "alpha2", "--no-active"]));
        out.assert_success();
        let body = fx.writes()[0].body_json().unwrap();
        assert_eq!(body["profile_name"], "alpha2");
        assert_eq!(body["active"], false);
        assert_eq!(
            body["policy"],
            fixtures::profile(1, "alpha", 1)["policy"],
            "the policy as read"
        );
        assert_eq!(fx.profile(&target).unwrap()["profile_name"], "alpha2");
        let fx = world();
        let out = fx.run(&update(
            "alpha",
            &["--active", "--quiet", "--output", "json"],
        ));
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert_eq!(out.json()["active"], true);
    }

    /// `--dlp-action` changes only the action (D117, retired in 8.0: TS 7.3.0 matches).
    #[test]
    fn dlp_action_keeps_the_dlp_profiles() {
        let fx = world();
        let mut alpha = fixtures::profile(1, "alpha", 1);
        alpha["policy"]["ai-security-profiles"][0]["model-configuration"]["data-protection"] = json!({
            "data-leak-detection": {"action": "alert", "member": [{"text": "PII"}], "mask-data-inline": true}
        });
        fx.server.set_profiles(TSG, vec![alpha]);
        let out = fx.run(&update("alpha", &["--dlp-action", "block"]));
        out.assert_success();
        assert_eq!(
            fx.writes()[0].body_json().unwrap()["policy"]["ai-security-profiles"][0]["model-configuration"]
                ["data-protection"],
            json!({"data-leak-detection": {"action": "block", "member": [{"text": "PII"}], "mask-data-inline": true}})
        );
    }

    #[test]
    fn usage_errors_need_no_tenant_d100() {
        assert_usage(
            &update("alpha", &[]),
            "Nothing to update: pass --name, --active, --no-active, a policy flag or --config",
        );
        assert_usage(
            &update(
                "alpha",
                &["--direction", "prompt", "--ai-profile-index", "0"],
            ),
            "Nothing to update: pass --name, --active, --no-active, a policy flag or --config",
        );
        for extra in [
            &["--name", "x"][..],
            &["--active"],
            &["--direction", "prompt"],
            &["--ai-profile-index", "1"],
            &["--no-enable-full-conversation-inspection"],
        ] {
            let mut args = update("alpha", &["--config", "p.json"]);
            args.extend_from_slice(extra);
            assert_usage(
                &args,
                "--config cannot be combined with profile write flags or selectors",
            );
        }
        assert_usage(
            &update(
                "alpha",
                &["--direction", "invalid", "--prompt-injection", "block"],
            ),
            "--direction must be prompt, response, tool-call, or tool-response",
        );
        for bad in ["-1", "1.5", "x", ""] {
            assert_usage(
                &update(
                    "alpha",
                    &["--ai-profile-index", bad, "--prompt-injection", "block"],
                ),
                "--ai-profile-index must be a nonnegative integer",
            );
        }
        assert_usage(
            &update(
                "alpha",
                &["--prompt-injection", "block", "--max-inline-latency", "2.5"],
            ),
            "--max-inline-latency must be a non-negative integer",
        );
        let (server, sandbox) = bare();
        let out = run(
            &rust(),
            &sandbox,
            &update("alpha", &["--active", "--no-active"]),
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert!(out.stderr.contains("cannot be used with"), "{}", out.stderr);
        assert_eq!(server.request_count(), 0);
    }

    /// 8.0 (§13.17): a layout refusal after the read is a usage error with nothing
    /// written; the selected direction's edit keeps the rest; the table answer carries
    /// `dlpTenantId`.
    #[test]
    fn directional_updates_follow_the_layout_rules() {
        let fx = world();
        fx.server
            .set_profiles(TSG, vec![fixtures::runtime::directional_profile()]);
        let name = "Directionality Test";
        let out = fx.run(&update(name, &["--prompt-injection", "alert"]));
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_block("Directional protection edits require --direction")
        );
        assert!(fx.writes().is_empty());
        let out = fx.run(&update(
            name,
            &[
                "--direction",
                "prompt",
                "--prompt-injection",
                "alert",
                "--output",
                "table",
            ],
        ));
        out.assert_success();
        assert!(
            out.stdout
                .contains(" dlpTenantId    │ 8259670718644550000 "),
            "{}",
            out.stdout
        );
        let body = fx.writes()[0].body_json().unwrap();
        let directions = &body["policy"]["ai-security-profiles"][0]["content-type-configurations"];
        let before = fixtures::runtime::directional_profile();
        let prior = &before["policy"]["ai-security-profiles"][0]["content-type-configurations"];
        assert_eq!(
            directions["prompt"]["model-protection"][0],
            json!({"name": "prompt-injection", "action": "alert", "severity": "medium"})
        );
        assert_eq!(directions["response"], prior["response"]);
        let out = fx.run(&update(
            name,
            &["--ai-profile-index", "3", "--max-inline-latency", "4"],
        ));
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_block("--ai-profile-index does not identify an existing AI profile entry")
        );
    }

    #[test]
    fn a_config_file_must_name_the_resolved_profile_d103() {
        let fx = world();
        let good = fx.file(
            "a.json",
            br#"{"profile_name": "alpha", "active": true, "policy": {"ai-security-profiles": []}}"#,
        );
        let out = fx.run(&update("alpha", &["--config", &good]));
        out.assert_success();
        assert_eq!(
            fx.writes()[0].body_json(),
            Some(
                json!({"profile_name": "alpha", "active": true, "policy": {"ai-security-profiles": []}})
            )
        );
        let fx = world();
        let renamed = fx.file("b.json", br#"{"profile_name": "zeta", "policy": {}}"#);
        let out = fx.run(&update("alpha", &["--config", &renamed]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                &format!(
                    "profile_name in {renamed} differs from the profile being updated; rename with --name instead"
                ),
                None,
                &[]
            )
        );
        assert!(fx.writes().is_empty());
    }

    #[test]
    fn not_found_and_missing_ids_write_nothing_d115() {
        let fx = world();
        let out = fx.run(&update("nope", &["--prompt-injection", "block"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: nope",
                None,
                &[]
            )
        );
        let fx = world();
        let mut row = fixtures::profile(1, "alpha", 1);
        row.as_object_mut().unwrap().remove("profile_id");
        fx.server.set_profiles(TSG, vec![row]);
        let out = fx.run(&update("alpha", &["--prompt-injection", "block"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("Profile alpha has no profile_id", None, &[])
        );
        assert!(fx.writes().is_empty());
    }

    #[test]
    fn an_unreadable_success_body_says_the_profile_was_updated() {
        let fx = world();
        fx.server.push_once(
            Route::ProfileUpdate,
            Planned::json(200, &json!({"profile_name": 7})),
        );
        let out = fx.run(&update("alpha", &["--prompt-injection", "block"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema",
                None,
                &["Outcome: the profile was updated, but the response could not be read."]
            )
        );
    }
}

mod profiles_delete {
    use super::*;

    #[test]
    fn force_by_name_deletes_the_highest_revision() {
        let fx = world();
        let out = fx.run(&[
            "runtime",
            "profiles",
            "delete",
            "beta",
            "--force",
            "--updated-by",
            "a@b",
        ]);
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            format!("  ✓ Profile deleted: beta ({})\n", id(4))
        );
        assert_eq!(
            fx.writes()[0].line(),
            format!(
                "DELETE /aisec/v1/mgmt/profile/{}/force?updated_by=a%40b",
                id(4)
            )
        );
        assert!(fx.profile(&id(4)).is_none());
        assert!(fx.profile(&id(2)).is_some(), "only the highest revision");
    }

    #[test]
    fn usage_checks_come_before_the_tenant_d104() {
        assert_usage(
            &["runtime", "profiles", "rm", "beta"],
            "refusing to delete profile \"beta\" without --force in non-interactive mode",
        );
        assert_usage(
            &["runtime", "profiles", "rm", "beta", "--force"],
            "--updated-by <email> is required with --force",
        );
        assert_usage(
            &[
                "runtime",
                "profiles",
                "rm",
                "beta",
                "--force",
                "--updated-by",
                "  ",
            ],
            "--updated-by <email> is required with --force",
        );
        assert_usage(
            &[
                "runtime",
                "profiles",
                "rm",
                "beta",
                "--force",
                "--updated-by",
                "ops\tteam@x",
            ],
            "--updated-by <email> must not contain control characters",
        );
    }

    #[test]
    fn the_prompt_names_the_resolved_profile_d105() {
        let fx = world();
        let mut session = spawn_pty(
            &rust(),
            &fx.sandbox,
            &["runtime", "profiles", "delete", "beta"],
            &RunOptions::new(),
        );
        session.expect(&format!(
            "? Delete security profile \"beta\" ({})? (y/N) ",
            id(4)
        ));
        let before = fx.server.request_count();
        session.send(b"y\n");
        let out = session.wait();
        out.run.assert_success();
        assert!(
            transcript(&out).contains(&format!("  ✓ Profile deleted: beta ({})\n", id(4))),
            "{}",
            transcript(&out)
        );
        assert_eq!(before, 2, "token and lookup before the prompt");
        assert_eq!(
            fx.writes()[0].line(),
            format!("DELETE /aisec/v1/mgmt/profile/{}", id(4))
        );
    }

    #[test]
    fn by_uuid_and_declined() {
        let fx = world();
        let target = id(2);
        let mut session = spawn_pty(
            &rust(),
            &fx.sandbox,
            &["runtime", "profiles", "rm", &target],
            &RunOptions::new(),
        );
        session.expect(&format!(
            "? Delete security profile \"beta\" ({target})? (y/N) "
        ));
        session.send(b"no\n");
        let out = session.wait();
        out.run.assert_success();
        assert!(transcript(&out).contains("  ℹ Aborted\n"));
        assert!(fx.writes().is_empty());
    }

    #[test]
    fn a_missing_profile_is_not_found() {
        let fx = world();
        let out = fx.run(&[
            "runtime",
            "profiles",
            "delete",
            "nope",
            "--force",
            "--updated-by",
            "a@b",
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: nope",
                None,
                &[]
            )
        );
        assert!(fx.writes().is_empty());
    }

    #[test]
    fn an_unknown_outcome_is_reported_d95() {
        let fx = world();
        fx.server.push_once(
            Route::ProfileForceDelete,
            Planned::json(504, &json!({})).with_retry_after(0),
        );
        let out = fx.run(&[
            "runtime",
            "profiles",
            "delete",
            "alpha",
            "--force",
            "--updated-by",
            "a@b",
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 504",
                Some(504),
                &["Outcome unknown: the profile may have been deleted."]
            )
        );
        assert_eq!(fx.writes().len(), 1);
    }
}

mod debug {
    use super::*;

    #[test]
    fn writes_are_logged_without_bodies() {
        let fx = world();
        let xdg = airs_test_harness::debug_log::xdg_state_home(&fx.sandbox);
        let out = fx.run_with(
            &create_args(&["--debug"]),
            &RunOptions::new().env("XDG_STATE_HOME", xdg.display().to_string()),
        );
        out.assert_success();
        let (_, records) = airs_test_harness::debug_log::only_log(&fx.sandbox);
        let text = serde_json::to_string(&records).unwrap();
        assert!(text.contains("/v1/mgmt/topic"), "{text}");
        assert!(!text.contains("a new topic"), "no request body");
    }

    /// 8.0 (scm-sdk 0.2.4): a directional create and a directional flag update log the SDK
    /// operation names unchanged (the update's lookup walk `airs.management.profiles.list`,
    /// then `airs.management.profiles.update`) and neither the policy nor the
    /// `dlp_tenant_id` they send.
    #[test]
    fn directional_writes_log_their_operation_names_and_no_body() {
        let fx = world();
        fx.server
            .set_profiles(TSG, vec![fixtures::runtime::directional_profile()]);
        let config = fx.file(
            "directional.json",
            fixtures::runtime::directional_profile()
                .to_string()
                .replace("Directionality Test", "Directional Copy")
                .as_bytes(),
        );
        let xdg = airs_test_harness::debug_log::xdg_state_home(&fx.sandbox);
        let options = RunOptions::new().env("XDG_STATE_HOME", xdg.display().to_string());
        fx.run_with(
            &[
                "runtime", "profiles", "create", "--config", &config, "--debug",
            ],
            &options,
        )
        .assert_success();
        let (_, records) = airs_test_harness::debug_log::only_log(&fx.sandbox);
        let operations: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(
            operations,
            ["oauth.token", "airs.management.profiles.create"]
        );
        let text = serde_json::to_string(&records).unwrap();
        for secret in [
            "8259670718644550000",
            "content-type-configurations",
            "sensitive content",
        ] {
            assert!(!text.contains(secret), "{secret} in the debug log");
        }
        let log = airs_test_harness::debug_log::log_dir(&fx.sandbox);
        std::fs::remove_dir_all(&log).unwrap();
        fx.run_with(
            &[
                "runtime",
                "profiles",
                "update",
                "550e8400-e29b-41d4-a716-446655440000",
                "--direction",
                "response",
                "--toxic-content",
                "alert",
                "--debug",
            ],
            &options,
        )
        .assert_success();
        let (_, records) = airs_test_harness::debug_log::only_log(&fx.sandbox);
        let operations: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(
            operations,
            [
                "oauth.token",
                "airs.management.profiles.list",
                "airs.management.profiles.update"
            ]
        );
        let text = serde_json::to_string(&records).unwrap();
        for secret in ["content-type-configurations", "toxic-content"] {
            assert!(!text.contains(secret), "{secret} in the debug log");
        }
    }
}

/// 8.0: scm-sdk 0.2.4's directional profile fields through `profiles create|update`
/// (DESIGN §13.17, §15.25): the request schema runs before the tenant, an omitted setting
/// stays omitted, an explicit `false` stays `false`, and a stored value the request schema
/// refuses stops the update before its write.
mod sdk_0_2_4 {
    use super::*;

    fn directional() -> Value {
        fixtures::runtime::directional_profile()
    }

    const ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    /// The new fields' request checks (null or a wrong type) need no tenant and send
    /// nothing: the tenant named does not exist.
    #[test]
    fn invalid_new_fields_are_refused_before_the_tenant() {
        let (server, sandbox) = bare();
        type Edit = fn(&mut Value);
        let edits: [Edit; 4] = [
            |p| p["dlp_tenant_id"] = json!(42),
            |p| p["dlp_tenant_id"] = Value::Null,
            |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-configurations"]["prompt"] =
                    json!("block")
            },
            |p| {
                p["policy"]["ai-security-profiles"][0]["model-configuration"]["enable-full-conversation-inspection"] =
                    json!(0)
            },
        ];
        for edit in edits {
            let mut bad = directional();
            edit(&mut bad);
            let path = sandbox.tmp().join("bad.json");
            std::fs::write(&path, bad.to_string()).unwrap();
            let path = path.display().to_string();
            for (args, line) in [
                (
                    vec!["runtime", "profiles", "create", "--config", &path],
                    "POST /v1/mgmt/profile".to_owned(),
                ),
                (
                    vec!["runtime", "profiles", "update", ID, "--config", &path],
                    format!("PUT /v1/mgmt/profile/uuid/{ID}"),
                ),
            ] {
                let mut args = args;
                args.extend(["--tenant", "missing"]);
                let out = run(&rust(), &sandbox, &args, &RunOptions::new());
                out.assert_code(2);
                assert_eq!(
                    out.stderr,
                    usage_block(&format!(
                        "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for {line} did not match schema"
                    )),
                    "{bad}"
                );
                assert_eq!(server.request_count(), 0);
            }
        }
    }

    /// A string `dlp_tenant_id` (even one that looks like a number) is sent as a string;
    /// every direction is sent with its hyphenated key; an explicit `false` is sent.
    #[test]
    fn a_complete_create_sends_every_field_as_given() {
        let fx = world();
        let config = fx.file("p.json", directional().to_string().as_bytes());
        fx.run(&["runtime", "profiles", "create", "--config", &config])
            .assert_success();
        let body = fx.writes()[0].body_json().unwrap();
        assert_eq!(body["dlp_tenant_id"], json!("8259670718644550000"));
        let ai = &body["policy"]["ai-security-profiles"][0];
        let mut keys: Vec<&String> = ai["content-type-configurations"]
            .as_object()
            .unwrap()
            .keys()
            .collect();
        keys.sort();
        assert_eq!(keys, ["prompt", "response", "tool-call", "tool-response"]);
        assert_eq!(ai["content-type-mode"], "per_content_type");
        assert_eq!(
            ai["model-configuration"]["enable-full-conversation-inspection"],
            json!(false)
        );
        let raw = fx.writes()[0].body_text();
        for key in [
            "tool_call",
            "tool_response",
            "content_type_mode",
            "content_type_configurations",
            "enable_full_conversation_inspection",
            "data_protection",
            "dlp-tenant-id",
        ] {
            assert!(!raw.contains(key), "{key} is not a wire key");
        }
    }

    /// A flag update sends only what the flags change: settings the user omitted stay
    /// omitted (no default `false` is inserted) and a stored `false` stays `false`.
    #[test]
    fn omitted_settings_stay_omitted_and_false_stays_false() {
        let fx = world();
        let mut omitted = directional();
        let config = omitted["policy"]["ai-security-profiles"][0]["model-configuration"]
            .as_object_mut()
            .unwrap();
        config.remove("enable-full-conversation-inspection");
        config.remove("mask-data-in-storage");
        fx.server.set_profiles(TSG, vec![omitted.clone()]);
        fx.run(&[
            "runtime",
            "profiles",
            "update",
            ID,
            "--direction",
            "prompt",
            "--prompt-injection",
            "alert",
        ])
        .assert_success();
        let body = fx.writes()[0].body_json().unwrap();
        let shared = &body["policy"]["ai-security-profiles"][0]["model-configuration"];
        assert_eq!(
            shared,
            &omitted["policy"]["ai-security-profiles"][0]["model-configuration"]
        );
        assert!(shared.get("enable-full-conversation-inspection").is_none());
        assert!(shared.get("mask-data-in-storage").is_none());

        let fx = world();
        fx.server.set_profiles(TSG, vec![directional()]);
        fx.run(&[
            "runtime",
            "profiles",
            "update",
            ID,
            "--max-inline-latency",
            "3",
        ])
        .assert_success();
        let body = fx.writes()[0].body_json().unwrap();
        let shared = &body["policy"]["ai-security-profiles"][0]["model-configuration"];
        assert_eq!(shared["enable-full-conversation-inspection"], json!(false));
        assert_eq!(shared["mask-data-in-storage"], json!(false));
        assert_eq!(shared["latency"]["max-inline-latency"], json!(3));
        assert!(
            body.get("dlp_tenant_id").is_none(),
            "TS 7.3.0's update body"
        );
    }

    /// A stored value the request schema refuses (here an explicit `null` the tolerant
    /// read kept, D334) is never sent back: the merged body fails the schema after the
    /// read, before any write (§13.17).
    #[test]
    fn a_stored_null_stops_the_update_before_its_write() {
        let fx = world();
        let mut stored = directional();
        stored["policy"]["ai-security-profiles"][0]["model-configuration"]["enable-full-conversation-inspection"] =
            Value::Null;
        fx.server.set_profiles(TSG, vec![stored]);
        let out = fx.run(&[
            "runtime",
            "profiles",
            "update",
            ID,
            "--max-inline-latency",
            "3",
        ]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_block(&format!(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/mgmt/profile/uuid/{ID} did not match schema"
            ))
        );
        assert!(fx.writes().is_empty());
        // `topics apply` keeps its exit 1 for a schema failure (§13.17).
        let out = fx.run(&[
            "runtime",
            "topics",
            "apply",
            "--profile",
            "Directionality Test",
            "--name",
            "fin",
            "--direction",
            "prompt",
        ]);
        out.assert_code(1);
        assert!(
            out.stderr.contains(&format!(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/mgmt/profile/uuid/{ID} did not match schema"
            )),
            "{}",
            out.stderr
        );
        assert!(fx.writes().is_empty());
    }
}
