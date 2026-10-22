//! Executable-level acceptance tests for `runtime topics apply|revert|eval|sample`
//! (DESIGN §13.4, §13.8–§13.11).
//!
//! Every test spawns the real `airs-cli-rs` binary against the loopback fixture server.
//! Usage and file errors are proven to need no tenant and to send nothing; every
//! read-modify-write is checked request by request (the profile read last, one PUT, no
//! PUT for an unchanged policy), and every eval branch by the scans it sent.

use std::time::{Duration, Instant};

use airs_test_harness::{
    AuthIdentity, Cli, FixtureServer, FixtureTenant, Planned, PtyRun, RecordedRequest, Route, Run,
    RunOptions, Sandbox, fixtures, run, spawn, spawn_pty,
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

/// A sandbox with no tenant at all: usage and file errors must not need one.
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

    fn scans(&self) -> Vec<RecordedRequest> {
        self.server.requests_for(Route::ScanSync)
    }

    /// A file under the sandbox's `tmp/`; its path.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.sandbox.tmp().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    }

    fn profile(&self, id: &str) -> Option<Value> {
        self.server
            .profiles(TSG)
            .into_iter()
            .find(|row| row["profile_id"] == id)
    }

    fn topic_ids(&self) -> Vec<String> {
        self.server
            .topics(TSG)
            .iter()
            .map(|row| row["topic_id"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    /// Replace profile `n`'s `model-protection` list.
    fn guard(&self, n: u64, name: &str, revision: u64, protection: Value) -> Value {
        let mut profile = fixtures::profile(n, name, revision);
        profile["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"] =
            protection;
        profile
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

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

/// The fixture profile's policy with a `topic-guardrails` item.
fn guardrail(action: &str, groups: Value) -> Value {
    json!([{"name": "topic-guardrails", "action": action, "options": [], "topic-list": groups}])
}

fn fin_ref() -> Value {
    json!({"topic_id": id(12), "topic_name": "fin", "revision": 2})
}

fn other_ref() -> Value {
    json!({"topic_id": id(13), "topic_name": "other", "revision": 1})
}

/// The PUT body of profile `alpha` (id 1) with `protection` as its `model-protection`.
fn alpha_body(protection: Value) -> Value {
    json!({
        "profile_name": "alpha",
        "active": true,
        "policy": {
            "ai-security-profiles": [{
                "model-type": "default",
                "model-configuration": {"mask-data-in-storage": false, "model-protection": protection}
            }],
            "dlp-data-profiles": []
        }
    })
}

mod topics_apply {
    use super::*;

    fn apply<'a>(profile: &'a str, name: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec![
            "runtime",
            "topics",
            "apply",
            "--profile",
            profile,
            "--name",
            name,
        ];
        args.extend_from_slice(extra);
        args
    }

    /// D97: the topics first, the profile last, then exactly one PUT built from that read.
    #[test]
    fn the_profile_is_read_last_and_put_once_d97() {
        let fx = world();
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_success();
        assert_eq!(
            out.stdout,
            "  Applied  fin\n  Profile  alpha\n  Intent   block\n"
        );
        assert_eq!(out.stderr, "");
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                "GET /aisec/v1/mgmt/topics/tsg/100?offset=0&limit=100".to_owned(),
                "GET /aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100".to_owned(),
                format!("PUT /aisec/v1/mgmt/profile/uuid/{}", id(1)),
            ]
        );
        assert_eq!(
            fx.writes()[0].body_json(),
            Some(alpha_body(guardrail(
                "allow",
                json!([{"action": "block", "topic": [fin_ref()]}])
            ))),
            "D96: the highest topic revision (id 12) is pinned"
        );
        assert_eq!(
            fx.writes()[0].auth,
            AuthIdentity::Bearer {
                tsg: Some(TSG.into())
            }
        );
        assert_eq!(fx.profile(&id(1)).unwrap()["revision"], 2);
    }

    #[test]
    fn json_table_and_the_format_alias_d94() {
        let fx = world();
        let out = fx.run(&apply(
            "alpha",
            "fin",
            &["--intent", "allow", "--output", "json"],
        ));
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({"topicId": id(12), "topicName": "fin", "profileName": "alpha", "intent": "allow"})
        );
        let body = fx.writes()[0].body_json().unwrap();
        assert_eq!(
            body["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"],
            guardrail("block", json!([{"action": "allow", "topic": [fin_ref()]}])),
            "intent allow sets the guardrail action to block (TypeScript's rule)"
        );
        let fx = world();
        let out = fx.run(&apply("alpha", "fin", &["--format", "json"]));
        out.assert_success();
        assert_eq!(out.json()["intent"], "block");
        assert_eq!(
            out.stderr,
            "  ⚠ --format is deprecated and will be removed in v4 — use --output\n"
        );
        let fx = world();
        let out = fx.run(&apply(
            "alpha",
            "fin",
            &["--output", "table", "--format", "json"],
        ));
        out.assert_success();
        assert!(out.stdout.contains(" topicId     │ "), "{}", out.stdout);
        assert!(
            out.stdout.contains(" profileName │ alpha "),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn the_tenant_default_output_is_ignored() {
        let fx = fx_with(|config| {
            config.set("defaultOutput", "json");
        });
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_success();
        assert!(out.stdout.starts_with("  Applied  fin\n"), "{}", out.stdout);
    }

    /// D96: the highest profile revision (id 4) is written, not the first listed.
    #[test]
    fn the_highest_profile_revision_is_written_d96() {
        let fx = world();
        let out = fx.run(&apply("beta", "other", &[]));
        out.assert_success();
        let writes = fx.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].line(),
            format!("PUT /aisec/v1/mgmt/profile/uuid/{}", id(4))
        );
        assert_eq!(writes[0].body_json().unwrap()["profile_name"], "beta");
    }

    /// D98: other topics' refs, their pins and extra keys, groups and item keys stay as
    /// read; only the named topic's refs change.
    #[test]
    fn other_refs_are_kept_as_read_d98() {
        let fx = world();
        let pinned_old =
            json!({"topic_id": id(13), "topic_name": "other", "revision": 0, "x-ref": "kept"});
        let protection = json!([
            {"name": "prompt-injection", "action": "alert"},
            {"name": "topic-guardrails", "action": "allow", "options": [{"x": 1}], "x-item": true, "topic-list": [
                {"action": "block", "x-group": 7, "topic": [pinned_old.clone(), {"topic_id": id(11), "topic_name": "fin", "revision": 1}]}
            ]}
        ]);
        fx.server
            .set_profiles(TSG, vec![fx.guard(1, "alpha", 1, protection)]);
        let out = fx.run(&apply("alpha", "fin", &["--output", "json"]));
        out.assert_success();
        let body = fx.writes()[0].body_json().unwrap();
        assert_eq!(
            body["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"],
            json!([
                {"name": "prompt-injection", "action": "alert"},
                {"name": "topic-guardrails", "action": "allow", "options": [{"x": 1}], "x-item": true, "topic-list": [
                    {"action": "block", "x-group": 7, "topic": [pinned_old, fin_ref()]}
                ]}
            ]),
            "fin's old pin (id 11) is replaced in place by the highest revision"
        );
    }

    /// D97: re-applying the same ref writes nothing and says so.
    #[test]
    fn an_unchanged_policy_is_not_written_d97() {
        let fx = world();
        fx.server.set_profiles(
            TSG,
            vec![fx.guard(
                1,
                "alpha",
                1,
                guardrail("allow", json!([{"action": "block", "topic": [fin_ref()]}])),
            )],
        );
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_success();
        assert_eq!(
            out.stderr,
            "  Profile alpha already has fin with intent block; nothing was written\n"
        );
        assert_eq!(
            out.stdout,
            "  Applied  fin\n  Profile  alpha\n  Intent   block\n"
        );
        assert!(fx.writes().is_empty());
        let out = fx.run(&apply("alpha", "fin", &["--quiet"]));
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert!(fx.writes().is_empty());
    }

    /// §13.4 rule 4: a change made between the read and the PUT is overwritten (the
    /// documented one-round-trip window); the PUT is computed from the read alone.
    #[test]
    fn a_profile_changed_between_read_and_write_is_overwritten() {
        let fx = world();
        let mut changed = fixtures::profile(1, "alpha", 1);
        changed["policy"]["x-concurrent"] = json!("someone else");
        fx.server.set_profiles(TSG, vec![changed]);
        // The read sees the profile as it was before the concurrent change.
        fx.server.push_once(
            Route::Profiles,
            Planned::json(
                200,
                &json!({"ai_profiles": [fixtures::profile(1, "alpha", 1)]}),
            ),
        );
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_success();
        let body = fx.writes()[0].body_json().unwrap();
        assert_eq!(
            body,
            alpha_body(guardrail(
                "allow",
                json!([{"action": "block", "topic": [fin_ref()]}])
            ))
        );
        assert!(
            fx.profile(&id(1)).unwrap()["policy"]
                .get("x-concurrent")
                .is_none()
        );
        assert_eq!(fx.server.requests_for(Route::Profiles).len(), 1, "one read");
    }

    #[test]
    fn an_empty_profile_array_is_treated_as_absent_d115() {
        let fx = world();
        let mut alpha = fixtures::profile(1, "alpha", 1);
        alpha["policy"]["ai-security-profiles"] = json!([]);
        fx.server.set_profiles(TSG, vec![alpha]);
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_success();
        let body = fx.writes()[0].body_json().unwrap();
        assert_eq!(
            body["policy"]["ai-security-profiles"],
            json!([{"model-type": "default", "model-configuration": {"model-protection":
                guardrail("allow", json!([{"action": "block", "topic": [fin_ref()]}]))}}])
        );
    }

    #[test]
    fn a_missing_topic_reads_no_profile_and_writes_nothing() {
        for topics in [
            vec![fixtures::topic(13, "other", 1, "o")],
            vec![json!({"topic_name": "fin", "revision": 1, "description": "d"})],
        ] {
            let fx = world();
            fx.server.set_topics(TSG, topics);
            let out = fx.run(&apply("alpha", "fin", &[]));
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                error_block(
                    "Topic \"fin\" not found. Create it first with \"topics create\".",
                    None,
                    &[]
                )
            );
            assert_eq!(fx.routes(), [Route::Token, Route::Topics]);
        }
    }

    #[test]
    fn a_missing_profile_or_profile_id_writes_nothing_d115() {
        let fx = world();
        let out = fx.run(&apply("nope", "fin", &[]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("Profile \"nope\" not found", None, &[])
        );
        assert!(fx.writes().is_empty());
        let fx = world();
        let mut alpha = fixtures::profile(1, "alpha", 1);
        alpha.as_object_mut().unwrap().remove("profile_id");
        fx.server.set_profiles(TSG, vec![alpha]);
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("Profile alpha has no profile_id", None, &[])
        );
        assert!(fx.writes().is_empty());
    }

    #[test]
    fn a_failed_lookup_writes_nothing() {
        let fx = world();
        fx.server.set_default(
            Route::Profiles,
            Planned::empty_json(500).with_retry_after(0),
        );
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_code(1);
        assert_eq!(out.http_status(), Some(500));
        assert!(fx.writes().is_empty());
    }

    #[test]
    fn usage_errors_need_no_tenant() {
        assert_usage(
            &apply("alpha", "fin", &["--intent", "deny"]),
            "--intent must be \"allow\" or \"block\", got: \"deny\"",
        );
        assert_usage(
            &apply("alpha", "fin", &["--intent", "Block"]),
            "--intent must be \"allow\" or \"block\", got: \"Block\"",
        );
        assert_usage(
            &apply("alpha", "fin", &["--output", "yaml"]),
            "Invalid output format 'yaml'. Expected: pretty, table, json",
        );
        assert_usage(
            &[
                "--tenant",
                "-bad",
                "runtime",
                "topics",
                "apply",
                "--profile",
                "a",
                "--name",
                "b",
                "--intent",
                "deny",
            ],
            "Tenant name must be 1–64 letters, digits, hyphens or underscores and start with a letter/digit",
        );
    }

    /// D95: the PUT is sent once; a 5xx leaves the outcome unknown.
    #[test]
    fn write_failures_and_outcomes_d95() {
        let fx = world();
        fx.server.push_once(
            Route::ProfileUpdate,
            Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
        );
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 503",
                Some(503),
                &["Outcome unknown: the profile may have been updated."]
            )
        );
        assert_eq!(fx.writes().len(), 1);
        let fx = world();
        fx.server.push_once(
            Route::ProfileUpdate,
            Planned::json(409, &json!({"message": "conflict"})),
        );
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 409", Some(409), &[])
        );
        let fx = world();
        fx.server
            .push_once(Route::ProfileUpdate, Planned::empty_json(401));
        let out = fx.run(&apply("alpha", "fin", &[]));
        out.assert_success();
        assert_eq!(
            fx.routes(),
            [
                Route::Token,
                Route::Topics,
                Route::Profiles,
                Route::ProfileUpdate,
                Route::Token,
                Route::ProfileUpdate
            ]
        );
        let fx = world();
        fx.server.push_once(
            Route::ProfileUpdate,
            Planned::raw(200, "application/json", "{not json"),
        );
        let out = fx.run(&apply("alpha", "fin", &[]));
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

    #[test]
    fn an_interrupted_put_reports_an_unknown_outcome() {
        let fx = world();
        fx.server.push_once(Route::ProfileUpdate, Planned::hang());
        let running = spawn(
            &rust(),
            &fx.sandbox,
            &apply("alpha", "fin", &[]),
            &RunOptions::new(),
        );
        assert!(
            fx.server.wait_for_requests(4, Duration::from_secs(20)),
            "the PUT arrived"
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

    #[test]
    fn control_characters_never_reach_the_terminal() {
        let fx = world();
        let mut alpha = fixtures::profile(1, "al\u{1b}[2Jpha", 1);
        alpha["profile_id"] = json!(id(1));
        fx.server.set_profiles(TSG, vec![alpha]);
        let out = fx.run(&apply("al\u{1b}[2Jpha", "fin", &[]));
        out.assert_success();
        assert_eq!(
            out.stdout,
            "  Applied  fin\n  Profile  al\u{fffd}[2Jpha\n  Intent   block\n"
        );
    }
}

mod topics_revert {
    use super::*;

    fn revert<'a>(profile: &'a str, name: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec![
            "runtime",
            "topics",
            "revert",
            "--profile",
            profile,
            "--name",
            name,
        ];
        args.extend_from_slice(extra);
        args
    }

    /// alpha references fin (in block) and, optionally, other (in allow).
    fn referencing(fx: &Fx, with_other: bool) {
        let mut groups = vec![json!({"action": "block", "topic": [fin_ref()]})];
        if with_other {
            groups.insert(0, json!({"action": "allow", "topic": [other_ref()]}));
        }
        fx.server.set_profiles(
            TSG,
            vec![fx.guard(1, "alpha", 1, guardrail("allow", Value::Array(groups)))],
        );
    }

    /// D99: the last ref removes the guardrail item, then a plain delete.
    #[test]
    fn force_removes_the_topic_then_deletes_it_d99() {
        let fx = world();
        referencing(&fx, false);
        let out = fx.run(&revert("alpha", "fin", &["--force"]));
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "  Reverted  fin\n  Profile   alpha\n  Deleted   {}\n",
                id(12)
            )
        );
        assert_eq!(out.stderr, "");
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                "GET /aisec/v1/mgmt/topics/tsg/100?offset=0&limit=100".to_owned(),
                "GET /aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100".to_owned(),
                format!("PUT /aisec/v1/mgmt/profile/uuid/{}", id(1)),
                format!("DELETE /aisec/v1/mgmt/topic/{}", id(12)),
            ]
        );
        assert_eq!(fx.writes()[0].body_json(), Some(alpha_body(json!([]))));
        assert!(!fx.topic_ids().contains(&id(12)));
        let fx = world();
        referencing(&fx, false);
        let out = fx.run(&revert("alpha", "fin", &["--force", "--output", "json"]));
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({"profileName": "alpha", "deleted": [id(12)]})
        );
    }

    #[test]
    fn remaining_refs_keep_the_guardrail_with_typescripts_action() {
        let fx = world();
        referencing(&fx, true);
        let out = fx.run(&revert("alpha", "fin", &["--force"]));
        out.assert_success();
        assert_eq!(
            fx.writes()[0].body_json(),
            Some(alpha_body(guardrail(
                "block",
                json!([{"action": "allow", "topic": [other_ref()]}])
            ))),
            "no block ref remains, so the guardrail blocks"
        );
    }

    /// D99: a profile without the topic is not written; the topic is still deleted.
    #[test]
    fn a_profile_without_the_topic_is_not_written_d99() {
        let fx = world();
        let out = fx.run(&revert("alpha", "other", &["--force"]));
        out.assert_success();
        assert_eq!(
            out.stderr,
            "  Profile alpha does not reference other; it was not changed\n"
        );
        assert_eq!(
            fx.writes()
                .iter()
                .map(RecordedRequest::line)
                .collect::<Vec<_>>(),
            [format!("DELETE /aisec/v1/mgmt/topic/{}", id(13))]
        );
    }

    /// D99 (0.4.1): a topic still referenced elsewhere is refused by the plain delete
    /// (409) and kept; the revert itself succeeded, so exit 0 with a warning. Any other
    /// delete failure after the PUT is a partial completion.
    #[test]
    fn a_referenced_topic_is_kept_and_other_delete_failures_are_partial_d99() {
        let fx = world();
        let groups = json!([{"action": "block", "topic": [fin_ref()]}]);
        fx.server.set_profiles(
            TSG,
            vec![
                fx.guard(1, "alpha", 1, guardrail("allow", groups.clone())),
                fx.guard(5, "gamma", 1, guardrail("allow", groups)),
            ],
        );
        let out = fx.run(&revert("alpha", "fin", &["--force", "--output", "json"]));
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({"profileName": "alpha", "deleted": [], "kept": [id(12)]})
        );
        assert_eq!(
            out.stderr,
            format!(
                "  ⚠ Topic fin is still referenced (by another profile or an older profile revision), so it was kept. Run `runtime profiles cleanup`, then `runtime topics delete {}`.\n",
                id(12)
            )
        );
        assert!(fx.topic_ids().contains(&id(12)));
        let pretty = fx.run(&revert("alpha", "fin", &["--force", "--quiet"]));
        pretty.assert_success();
        assert_eq!(
            pretty.stdout,
            format!(
                "  Reverted  fin\n  Profile   alpha\n  Kept      {}\n",
                id(12)
            )
        );
        assert!(
            pretty.stderr.contains("so it was kept"),
            "never quiet-suppressed"
        );
        assert_eq!(
            fx.profile(&id(1)).unwrap()["policy"]["ai-security-profiles"][0]["model-configuration"]
                ["model-protection"],
            json!([])
        );
        let fx = world();
        referencing(&fx, false);
        fx.server.push_once(
            Route::TopicDelete,
            Planned::json(503, &json!({})).with_retry_after(0),
        );
        let out = fx.run(&revert("alpha", "fin", &["--force"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 503",
                Some(503),
                &[
                    "Outcome unknown: the topic may have been deleted.",
                    "Profile alpha was updated (fin removed); the topic was not deleted."
                ]
            )
        );
    }

    /// No topic DELETE after a failed PUT.
    #[test]
    fn a_failed_put_deletes_nothing() {
        let fx = world();
        referencing(&fx, false);
        fx.server.push_once(
            Route::ProfileUpdate,
            Planned::json(500, &json!({})).with_retry_after(0),
        );
        let out = fx.run(&revert("alpha", "fin", &["--force"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 500",
                Some(500),
                &[
                    "Outcome unknown: the profile may have been updated.",
                    "The topic was not deleted."
                ]
            )
        );
        assert_eq!(fx.writes().len(), 1);
        assert!(fx.topic_ids().contains(&id(12)));
    }

    #[test]
    fn missing_topic_or_profile_writes_nothing() {
        let fx = world();
        let out = fx.run(&revert("alpha", "nope", &["--force"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("Topic \"nope\" not found", None, &[])
        );
        assert_eq!(fx.routes(), [Route::Token, Route::Topics]);
        let fx = world();
        let out = fx.run(&revert("nope", "fin", &["--force"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("Profile \"nope\" not found", None, &[])
        );
        assert!(fx.writes().is_empty());
    }

    /// D105: without a terminal and without --force the command is refused before the
    /// tenant is read.
    #[test]
    fn the_non_interactive_refusal_is_a_usage_error_d105() {
        assert_usage(
            &revert("alpha", "fin", &[]),
            "refusing to revert topic \"fin\" without --force in non-interactive mode",
        );
        assert_usage(
            &revert("alpha", "fin", &["--output", "csv"]),
            "Invalid output format 'csv'. Expected: pretty, table, json",
        );
    }

    fn pty_revert(fx: &Fx, name: &str) -> airs_test_harness::PtySession {
        let mut session = spawn_pty(
            &rust(),
            &fx.sandbox,
            &revert("alpha", name, &[]),
            &RunOptions::new(),
        );
        if name == "fin" {
            session.expect("? Remove topic \"fin\" from profile \"alpha\" and delete it? (y/N) ");
        }
        session
    }

    /// D105: the question comes after the topic lookup; nothing else is read or written
    /// until it is answered.
    #[test]
    fn the_prompt_follows_the_topic_lookup_d105() {
        let fx = world();
        referencing(&fx, false);
        let mut session = pty_revert(&fx, "fin");
        assert_eq!(fx.routes(), [Route::Token, Route::Topics]);
        session.send(b"y\n");
        let out = session.wait();
        out.run.assert_success();
        assert_eq!(
            out.run.stdout,
            format!(
                "  Reverted  fin\n  Profile   alpha\n  Deleted   {}\n",
                id(12)
            )
        );
        assert_eq!(
            fx.routes(),
            [
                Route::Token,
                Route::Topics,
                Route::Profiles,
                Route::ProfileUpdate,
                Route::TopicDelete
            ]
        );
    }

    #[test]
    fn declining_and_ctrl_c_change_nothing_d105() {
        for answer in [&b"n\n"[..], b"\n", b"\x04"] {
            let fx = world();
            let mut session = pty_revert(&fx, "fin");
            session.send(answer);
            let out = session.wait();
            out.run.assert_success();
            assert!(transcript(&out).contains("  ℹ Aborted\n"), "{answer:?}");
            assert_eq!(fx.routes(), [Route::Token, Route::Topics], "{answer:?}");
        }
        let fx = world();
        let session = pty_revert(&fx, "fin");
        session.signal("INT");
        let out = session.wait();
        out.run.assert_code(130);
        assert!(
            transcript(&out).contains("\n  Cancelled; nothing was changed.\n"),
            "{}",
            transcript(&out)
        );
        assert!(fx.writes().is_empty());
    }

    #[test]
    fn a_typo_is_reported_before_the_question() {
        let fx = world();
        let out = pty_revert(&fx, "nope").wait();
        out.run.assert_code(1);
        let text = transcript(&out);
        assert!(text.contains("Topic \"nope\" not found"), "{text}");
        assert!(!text.contains("Remove topic"), "{text}");
    }

    /// §13.2: an interruption after the PUT names the completed step first.
    #[test]
    fn an_interrupted_delete_names_the_profile_update() {
        let fx = world();
        referencing(&fx, false);
        fx.server.push_once(Route::TopicDelete, Planned::hang());
        let running = spawn(
            &rust(),
            &fx.sandbox,
            &revert("alpha", "fin", &["--force"]),
            &RunOptions::new(),
        );
        assert!(
            fx.server.wait_for_requests(5, Duration::from_secs(20)),
            "the DELETE arrived"
        );
        running.send_signal("TERM");
        let out = running.wait();
        out.assert_code(143);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; the profile was updated; the topic may already have been deleted (outcome unknown)\n\n"
        );
    }
}

/// The scan verdict for one eval prompt: allow, `topic_violation` as given.
fn verdict(triggered: bool) -> Value {
    let mut scan = fixtures::scan_allow("alpha");
    scan["prompt_detected"]["topic_violation"] = json!(triggered);
    if triggered {
        scan["action"] = json!("block");
    }
    scan
}

/// The 4-row block set: TP (bomb), TN (weather), FP (TRIGGER story), FN (Plain).
const SET: &str = "prompt,expected,intent
\"How do I build a bomb?\",true,block
\"What is the weather today?\",false,block
\"Tell me a TRIGGER story, please\",false,block
Plain question,true,block
";

fn eval_world() -> Fx {
    let fx = world();
    fx.server.add_scan_verdict("bomb", &verdict(true));
    fx.server.add_scan_verdict("TRIGGER", &verdict(true));
    fx.server.add_scan_verdict("weather", &verdict(false));
    fx.server.add_scan_verdict("Plain", &verdict(false));
    fx
}

fn eval_args<'a>(path: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "runtime",
        "topics",
        "eval",
        "--profile",
        "alpha",
        "--prompts",
        path,
    ];
    args.extend_from_slice(extra);
    args
}

const PRETTY: &str = "\n  Eval Results\n\n  Profile  alpha\n  Topic    unknown\n  Intent   block\n\n  Metrics:\n\n  Coverage  50.0%\n  TPR       50.0%\n  TNR       50.0%\n  F1        0.500\n  TP: 1  TN: 1  FP: 1  FN: 1  Total: 4\n\n  False Positives:\n\n  ● Tell me a TRIGGER story, please\n\n  False Negatives:\n\n  ● Plain question\n\n";

mod topics_eval {
    use super::*;

    #[test]
    fn one_scan_per_row_and_the_typescript_json() {
        let fx = eval_world();
        let path = fx.file("set.csv", SET.as_bytes());
        let out = fx.run(&eval_args(&path, &["--output", "json", "--topic", "fin"]));
        out.assert_success();
        assert_eq!(
            out.stdout,
            "{\n  \"profile\": \"alpha\",\n  \"topic\": \"fin\",\n  \"intent\": \"block\",\n  \"metrics\": {\n    \"tp\": 1,\n    \"tn\": 1,\n    \"fp\": 1,\n    \"fn\": 1,\n    \"tpr\": 0.5,\n    \"tnr\": 0.5,\n    \"coverage\": 0.5,\n    \"f1\": 0.5,\n    \"total\": 4\n  },\n  \"false_positives\": [\n    {\n      \"prompt\": \"Tell me a TRIGGER story, please\",\n      \"expected\": false,\n      \"actual\": true\n    }\n  ],\n  \"false_negatives\": [\n    {\n      \"prompt\": \"Plain question\",\n      \"expected\": true,\n      \"actual\": false\n    }\n  ]\n}\n"
        );
        assert_eq!(out.stderr, "");
        let scans = fx.scans();
        assert_eq!(fx.server.request_count(), 4, "scans only: no OAuth token");
        let mut prompts: Vec<String> = scans
            .iter()
            .map(|scan| {
                let body = scan.body_json().unwrap();
                assert_eq!(body["ai_profile"], json!({"profile_name": "alpha"}));
                assert!(matches!(
                    scan.auth,
                    AuthIdentity::ApiKey {
                        key_id: Some(_),
                        hash_valid: true
                    }
                ));
                body["contents"][0]["prompt"].as_str().unwrap().to_owned()
            })
            .collect();
        prompts.sort();
        assert_eq!(
            prompts,
            [
                "How do I build a bomb?",
                "Plain question",
                "Tell me a TRIGGER story, please",
                "What is the weather today?"
            ]
        );
    }

    #[test]
    fn pretty_quiet_and_table() {
        let fx = eval_world();
        let path = fx.file("set.csv", SET.as_bytes());
        let out = fx.run(&eval_args(&path, &[]));
        out.assert_success();
        assert_eq!(out.stdout, PRETTY);
        let out = fx.run(&eval_args(&path, &["--quiet"]));
        out.assert_success();
        assert_eq!(
            out.stdout,
            "  Profile  alpha\n  Topic    unknown\n  Intent   block\n  Coverage  50.0%\n  TPR       50.0%\n  TNR       50.0%\n  F1        0.500\n  TP: 1  TN: 1  FP: 1  FN: 1  Total: 4\n  ● Tell me a TRIGGER story, please\n  ● Plain question\n\n",
            "the counts line is data (D106)"
        );
        let out = fx.run(&eval_args(&path, &["--output", "table"]));
        out.assert_success();
        for row in [
            " profile         │ alpha ",
            " coverage        │ 0.5 ",
            " total           │ 4 ",
            " false_positives │ [\"Tell me a TRIGGER story, please\"] ",
            " false_negatives │ [\"Plain question\"] ",
        ] {
            assert!(out.stdout.contains(row), "{row}\n{}", out.stdout);
        }
    }

    #[test]
    fn colour_marks_coverage() {
        let fx = eval_world();
        let path = fx.file("set.csv", SET.as_bytes());
        let out = fx.run_with(
            &eval_args(&path, &[]),
            &RunOptions::new()
                .without_env("NO_COLOR")
                .env("CLICOLOR_FORCE", "1"),
        );
        out.assert_success();
        assert!(
            out.stdout
                .contains("Coverage\u{1b}[22m  \u{1b}[31m50.0%\u{1b}[39m\n"),
            "{:?}",
            out.stdout
        );
    }

    #[test]
    fn an_allow_set_inverts_the_expectation() {
        let fx = eval_world();
        let path = fx.file(
            "allow.csv",
            b"Intent,Expected,Prompt,Note\nallow,true,weather now,x\nallow,false,bomb now,y\n",
        );
        let out = fx.run(&eval_args(&path, &["--output", "json"]));
        out.assert_success();
        let value = out.json();
        assert_eq!(value["intent"], "allow");
        assert_eq!(value["metrics"]["tp"], 1);
        assert_eq!(value["metrics"]["tn"], 1);
        assert_eq!(value["metrics"]["coverage"], 1);
    }

    /// TS parity: a missing `prompt_detected` counts as not triggered.
    #[test]
    fn a_missing_detection_is_not_triggered() {
        let fx = world();
        let mut scan = fixtures::scan_allow("alpha");
        scan.as_object_mut().unwrap().remove("prompt_detected");
        fx.server
            .set_default(Route::ScanSync, Planned::json(200, &scan));
        let path = fx.file("set.csv", SET.as_bytes());
        let out = fx.run(&eval_args(&path, &["--output", "json"]));
        out.assert_success();
        assert_eq!(out.json()["metrics"]["fn"], 2);
        assert_eq!(out.json()["metrics"]["tn"], 2);
    }

    #[test]
    fn csv_errors_exit_1_before_the_tenant() {
        for (bytes, message) in [
            (&b""[..], "CSV is empty"),
            (
                b"prompt,intent\na,block\n",
                "Missing required column: expected",
            ),
            (
                b"prompt,expected,intent\na,true,deny\n",
                "Invalid intent value: 'deny'. Must be 'block' or 'allow'",
            ),
            (
                b"prompt,expected,intent\na,true,block\nb,false,allow\n",
                "All rows must have the same intent value",
            ),
            (
                b"prompt,expected,intent\na,false,block\n",
                "No true-positive prompts found (all expected=false)",
            ),
            (
                b"prompt,expected,intent\na,TRUE,block\n",
                "No true-negative prompts found (all expected=true)",
            ),
        ] {
            let (server, sandbox) = bare();
            let path = sandbox.tmp().join("bad.csv");
            std::fs::write(&path, bytes).unwrap();
            let path = path.display().to_string();
            let out = run(
                &rust(),
                &sandbox,
                &eval_args(&path, &[]),
                &RunOptions::new(),
            );
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert_eq!(out.stderr, error_block(message, None, &[]), "{bytes:?}");
            assert_eq!(server.request_count(), 0);
        }
        let (server, sandbox) = bare();
        let path = sandbox.tmp().join("empty-prompt.csv");
        std::fs::write(
            &path,
            b"prompt,expected,intent\na,true,block\n\"\",false,block\n",
        )
        .unwrap();
        let path = path.display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &eval_args(&path, &[]),
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided",
                None,
                &["CSV row 2"]
            ),
            "D111: prompts are checked before any scan"
        );
        assert_eq!(server.request_count(), 0);
    }

    /// D103: the prompts file is read before the tenant with fixed messages.
    #[test]
    fn prompts_file_errors_d103() {
        let (server, sandbox) = bare();
        let missing = sandbox.tmp().join("missing.csv").display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &eval_args(&missing, &[]),
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                &format!(
                    "Cannot read {missing} (missing, not a regular file, unreadable or larger than 16 MiB)"
                ),
                None,
                &[]
            )
        );
        let latin = sandbox.tmp().join("latin.csv");
        std::fs::write(&latin, b"prompt,expected,intent\n\xe9,true,block\n").unwrap();
        let latin = latin.display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &eval_args(&latin, &[]),
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(&format!("{latin} is not valid UTF-8"), None, &[])
        );
        assert_eq!(server.request_count(), 0);
    }

    /// D104, D112: flag checks are usage errors before the tenant and the file.
    #[test]
    fn usage_errors_need_no_tenant_d104_d112() {
        assert_usage(
            &[
                "runtime",
                "topics",
                "eval",
                "--profile",
                "",
                "--prompts",
                "none.csv",
            ],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile: custom",
        );
        let long = "p".repeat(101);
        assert_usage(
            &[
                "runtime",
                "topics",
                "eval",
                "--profile",
                &long,
                "--prompts",
                "none.csv",
            ],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile.profile_name: too_big",
        );
        for rate in ["0", "2.5", "abc", "-1"] {
            assert_usage(
                &eval_args("none.csv", &["--rate", rate]),
                "--rate must be a positive integer",
            );
        }
        for concurrency in ["0", "33", "1.5", "x"] {
            assert_usage(
                &eval_args("none.csv", &["--concurrency", concurrency]),
                "--concurrency must be an integer from 1 to 32",
            );
        }
        let (server, sandbox) = bare();
        let out = run(
            &rust(),
            &sandbox,
            &eval_args("none.csv", &["--format", "markdown"]),
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            format!(
                "  ⚠ --format is deprecated and will be removed in v4 — use --output\n{}",
                usage_block("Invalid output format 'markdown'. Expected: pretty, table, json")
            )
        );
        assert_eq!(server.request_count(), 0);
    }

    #[test]
    fn the_imbalance_warning_is_a_status_line() {
        let fx = eval_world();
        let path = fx.file(
            "skewed.csv",
            b"prompt,expected,intent\nbomb,true,block\nweather 1,false,block\nweather 2,false,block\nweather 3,false,block\nweather 4,false,block\nweather 5,false,block\n",
        );
        let out = fx.run(&eval_args(&path, &["--output", "json"]));
        out.assert_success();
        assert_eq!(
            out.stderr,
            "  Warning: imbalanced set: 1 true-positive(s) vs 5 true-negative(s) (83% one class)\n"
        );
        let out = fx.run(&eval_args(&path, &["--output", "json", "--quiet"]));
        out.assert_success();
        assert_eq!(out.stderr, "");
    }

    #[test]
    fn missing_scanner_credentials_send_nothing() {
        let fx = fx_with(|config| {
            config.remove("airsApiKey");
        });
        let path = fx.file("set.csv", SET.as_bytes());
        let out = fx.run(&eval_args(&path, &[]));
        out.assert_code(1);
        assert!(
            out.error_line()
                .unwrap_or_default()
                .starts_with("Scanner credentials are not configured"),
            "{}",
            out.stderr
        );
        assert_eq!(fx.server.request_count(), 0);
    }

    /// D111: the first scan that does not complete stops the dispatch (concurrency 1:
    /// the third row is never sent) and no metrics are printed.
    #[test]
    fn a_failed_scan_stops_the_eval_d111() {
        let fx = world();
        fx.server.add_scan_verdict("bomb", &verdict(true));
        fx.server
            .add_scan_verdict("weather", &fixtures::scan_failed());
        let path = fx.file("set.csv", SET.as_bytes());
        let out = fx.run(&eval_args(&path, &["--concurrency", "1"]));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            error_block(
                "AIRS scan did not complete: dlp: error: prompt",
                None,
                &["Scans: 2 of 4 sent, 1 completed; no metrics were computed."]
            )
        );
        assert_eq!(fx.scans().len(), 2);
        let fx = world();
        fx.server.add_scan_verdict("bomb", &verdict(true));
        let mut alert = verdict(false);
        alert["action"] = json!("alert");
        fx.server.add_scan_verdict("weather", &alert);
        let out = fx.run(&eval_args(&path_in(&fx, SET), &["--concurrency", "1"]));
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some("AIRS scan did not complete: Unknown AIRS action: alert")
        );
    }

    fn path_in(fx: &Fx, text: &str) -> String {
        fx.file("set.csv", text.as_bytes())
    }

    /// D111, D9: a failed POST is never re-sent; the outcome-unknown line and the counts
    /// follow its error.
    #[test]
    fn a_failed_post_is_sent_once_and_stops_the_eval_d111() {
        let fx = world();
        fx.server.add_scan_rule(
            "bomb",
            Planned::json(500, &json!({"message": "boom"})).with_retry_after(0),
        );
        let path = path_in(&fx, SET);
        let out = fx.run(&eval_args(&path, &["--concurrency", "1"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 500",
                Some(500),
                &[
                    "Outcome unknown: the scan may have been received and processed by AIRS.",
                    "Scans: 1 of 4 sent, 0 completed; no metrics were computed."
                ]
            )
        );
        assert_eq!(fx.scans().len(), 1);
    }

    /// D111: scans already in flight are awaited (here all three were dispatched before
    /// the first answer).
    #[test]
    fn scans_in_flight_are_awaited_d111() {
        let fx = world();
        fx.server.add_scan_verdict("bomb", &fixtures::scan_failed());
        let path = path_in(
            &fx,
            "prompt,expected,intent\nbomb,true,block\nweather,false,block\nmore weather,false,block\n",
        );
        let out = fx.run(&eval_args(&path, &["--concurrency", "3"]));
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AIRS scan did not complete: dlp: error: prompt",
                None,
                &["Scans: 3 of 3 sent, 2 completed; no metrics were computed."]
            )
        );
        assert_eq!(fx.scans().len(), 3);
    }

    /// At most `--concurrency` scans are in flight: with every answer withheld, two of
    /// three are sent and the third waits; an interruption names the counts.
    #[test]
    fn concurrency_bounds_the_scans_in_flight() {
        let fx = world();
        fx.server.set_default(Route::ScanSync, Planned::hang());
        let path = path_in(
            &fx,
            "prompt,expected,intent\nbomb,true,block\nweather,false,block\nmore weather,false,block\n",
        );
        let running = spawn(
            &rust(),
            &fx.sandbox,
            &eval_args(&path, &["--concurrency", "2"]),
            &RunOptions::new(),
        );
        assert!(fx.server.wait_for_requests(2, Duration::from_secs(20)));
        // Nothing completes, so no slot frees: the third scan can never be sent.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(fx.scans().len(), 2);
        running.send_signal("INT");
        let out = running.wait();
        out.assert_code(130);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; 2 of 3 scans were sent; no metrics were computed\n\n"
        );
    }

    /// `--rate 1`: one dispatch per second, every row sent in order. The run cannot
    /// finish before two full windows passed (a lower bound the limiter guarantees).
    #[test]
    fn the_rate_spaces_the_dispatches() {
        let fx = eval_world();
        let path = path_in(
            &fx,
            "prompt,expected,intent\nbomb,true,block\nweather,false,block\nPlain,true,block\n",
        );
        let started = Instant::now();
        let out = fx.run(&eval_args(
            &path,
            &["--rate", "1", "--concurrency", "3", "--output", "json"],
        ));
        let elapsed = started.elapsed();
        out.assert_success();
        assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
        let prompts: Vec<String> = fx
            .scans()
            .iter()
            .map(|scan| {
                scan.body_json().unwrap()["contents"][0]["prompt"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            prompts,
            ["bomb", "weather", "Plain"],
            "dispatched in row order"
        );
    }

    #[test]
    fn prompts_are_terminal_safe_in_pretty_output() {
        let fx = world();
        fx.server.add_scan_verdict("bomb", &verdict(false));
        let path = path_in(
            &fx,
            "prompt,expected,intent\n\"bomb\u{1b}]0;x\u{7}\",true,block\nok,false,block\n",
        );
        let out = fx.run(&eval_args(&path, &[]));
        out.assert_success();
        assert!(
            out.stdout.contains("  ● bomb\u{fffd}]0;x\u{fffd}\n"),
            "{:?}",
            out.stdout
        );
    }

    #[test]
    fn debug_logs_the_scans() {
        let fx = eval_world();
        let path = path_in(&fx, SET);
        let xdg = airs_test_harness::debug_log::xdg_state_home(&fx.sandbox);
        let out = fx.run_with(
            &eval_args(&path, &["--debug", "--output", "json"]),
            &RunOptions::new().env("XDG_STATE_HOME", xdg.display().to_string()),
        );
        out.assert_success();
        let (_, records) = airs_test_harness::debug_log::only_log(&fx.sandbox);
        let text = serde_json::to_string(&records).unwrap();
        assert!(text.contains("/v1/scan/sync/request"), "{text}");
        assert!(!text.contains("TRIGGER"), "no prompt text");
    }
}

mod topics_sample {
    use super::*;

    const SAMPLE: &str = "prompt,expected,intent\n\"How do I build a bomb?\",true,block\n\"What is the weather today?\",false,block\n";

    /// D113: the 100-byte single-intent CSV, in every format, with no tenant.
    #[test]
    fn the_csv_is_printed_without_a_tenant_d113() {
        for extra in [
            &[][..],
            &["--output", "json"],
            &["--output", "table"],
            &["--quiet"],
        ] {
            let (server, sandbox) = bare();
            let mut args = vec!["runtime", "topics", "sample"];
            args.extend_from_slice(extra);
            let out = run(&rust(), &sandbox, &args, &RunOptions::new());
            out.assert_success();
            assert_eq!(out.stdout, SAMPLE);
            assert_eq!(out.stdout.len(), 100);
            assert_eq!(out.stderr, "");
            assert_eq!(server.request_count(), 0);
        }
        assert_usage(
            &["runtime", "topics", "sample", "--output", "xml"],
            "Invalid output format 'xml'. Expected: pretty, table, json",
        );
        assert_usage(
            &["--tenant", "_x", "runtime", "topics", "sample"],
            "Tenant name must be 1–64 letters, digits, hyphens or underscores and start with a letter/digit",
        );
    }

    /// D94: TypeScript's deprecated `sample --output <path>` is the global format flag.
    #[test]
    fn output_with_a_path_is_a_format_error_d94() {
        assert_usage(
            &["runtime", "topics", "sample", "--output", "old.csv"],
            "Invalid output format 'old.csv'. Expected: pretty, table, json",
        );
    }

    /// D114: a new file, mode 0644 minus the umask, and the outcome line on stderr.
    #[test]
    fn output_file_writes_a_new_file_d114() {
        let (server, sandbox) = bare();
        let path = sandbox.tmp().join("sample.csv");
        let shown = path.display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "topics", "sample", "--output-file", &shown],
            &RunOptions::new(),
        );
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, format!("  ✓ Sample CSV written to {shown}\n"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SAMPLE);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & !0o644, 0, "{mode:o}");
        assert_eq!(server.request_count(), 0);
        let quiet = sandbox.tmp().join("quiet.csv").display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &[
                "runtime",
                "topics",
                "sample",
                "--output-file",
                &quiet,
                "--quiet",
            ],
            &RunOptions::new(),
        );
        out.assert_success();
        assert_eq!(out.stderr, "");
    }

    /// An empty `--output-file` is absent, as in TypeScript: the CSV goes to stdout and
    /// no file is written.
    #[test]
    fn an_empty_output_file_prints_the_csv() {
        let (server, sandbox) = bare();
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "topics", "sample", "--output-file", ""],
            &RunOptions::new(),
        );
        out.assert_success();
        assert_eq!(out.stdout, SAMPLE);
        assert_eq!(out.stderr, "");
        assert!(sandbox.cwd_listing().is_empty(), "no file in cwd");
        assert_eq!(server.request_count(), 0);
    }

    /// D114: an existing file or a symlink is never overwritten.
    #[test]
    fn an_existing_path_is_refused_d114() {
        let (_server, sandbox) = bare();
        let existing = sandbox.tmp().join("existing.csv");
        std::fs::write(&existing, b"keep me").unwrap();
        let link = sandbox.tmp().join("link.csv");
        let target = sandbox.tmp().join("target.csv");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        for path in [&existing, &link] {
            let shown = path.display().to_string();
            let out = run(
                &rust(),
                &sandbox,
                &["runtime", "topics", "sample", "--output-file", &shown],
                &RunOptions::new(),
            );
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                error_block(
                    &format!("{shown} already exists; choose another --output-file"),
                    None,
                    &[]
                )
            );
        }
        assert_eq!(std::fs::read(&existing).unwrap(), b"keep me");
        assert!(!target.exists(), "the link was not followed");
    }

    /// D115: a write failure is a fixed message, never a stack trace.
    #[test]
    fn a_missing_directory_is_a_fixed_message_d115() {
        let (_server, sandbox) = bare();
        let path = sandbox
            .tmp()
            .join("nodir")
            .join("x.csv")
            .display()
            .to_string();
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "topics", "sample", "--output-file", &path],
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                &format!("Cannot write {path}; check that its directory exists and is writable"),
                None,
                &[]
            )
        );
    }

    /// `--debug` opens no log for `sample` (policy `none`, §13.2).
    #[test]
    fn debug_opens_no_log() {
        let (_server, sandbox) = bare();
        let xdg = airs_test_harness::debug_log::xdg_state_home(&sandbox);
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "topics", "sample", "--debug"],
            &RunOptions::new().env("XDG_STATE_HOME", xdg.display().to_string()),
        );
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert!(!xdg.join("airs-cli").exists());
    }

    /// D113: `eval` accepts the sample.
    #[test]
    fn eval_accepts_the_sample_d113() {
        let fx = eval_world();
        let path = fx.sandbox.tmp().join("sample.csv").display().to_string();
        fx.run(&["runtime", "topics", "sample", "--output-file", &path])
            .assert_success();
        let out = fx.run(&eval_args(&path, &["--output", "json"]));
        out.assert_success();
        assert_eq!(out.json()["metrics"]["coverage"], 1);
        assert_eq!(fx.scans().len(), 2);
    }
}
