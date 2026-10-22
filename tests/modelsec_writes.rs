//! Executable acceptance tests for the M6c step-2 model-security writes (DESIGN §17.3,
//! §17.8–§17.11): `model-security groups create|update|delete|rm`, `rule-instances
//! update`, `scans create` and `labels add|set|delete|rm`.
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server with the
//! seeded model-security dataset, whose write routes change the dataset (a later read sees
//! the change). Configs and labels carry `FAKE-MS-SECRET-<nn>` markers; the runner's leak
//! check forbids every marker on stderr, the pty transcript and the debug log of each run
//! (§17.15), and the tests assert where stdout may hold them. The write cases of the
//! TypeScript `tests/unit/airs/modelsecurity.spec.ts` (`createGroup` `:220-243`,
//! `updateGroup`, `deleteGroupAndVerify` `:274-304`, `updateRuleInstance` `:375-403`, the
//! label bodies `:741-767`) and `aliases.spec.ts:66-86` (`rm`) are ported here, adjusted
//! by the §12 rows (§17.17).

use std::time::Duration;

use airs_test_harness::fixtures::modelsec as fx;
use airs_test_harness::{
    Cli, FixtureServer, GroupDeleteMode, Ms, Planned, PtyRun, RecordedRequest, Route, Run,
    RunOptions, Sandbox, debug_log, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n";
const DEBUG_HINT: &str = "    Re-run with --debug to capture redacted API diagnostics.\n";
const GROUPS: &str = "/aims/mgmt/v1/security-groups";
const SCANS: &str = "/aims/data/v1/scans";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn u(n: u64) -> String {
    fx::uuid(n)
}

fn s(text: &str) -> String {
    text.to_owned()
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seeded model-security dataset and one standard tenant `prod` (TSG 100).
fn fx() -> Fx {
    let server = FixtureServer::start();
    server.seed_modelsec();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |_| {});
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

/// A sandbox with no tenant at all: usage and file errors must not need one.
fn bare() -> Fx {
    Fx {
        server: FixtureServer::start(),
        sandbox: Sandbox::new(),
    }
}

fn ms_args(args: &[&str]) -> Vec<String> {
    std::iter::once("model-security")
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

impl Fx {
    /// `model-security <args>`, with the loopback and no-stray-files checks.
    fn ms(&self, args: &[&str]) -> Run {
        self.ms_with(args, &RunOptions::new())
    }

    fn ms_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let full = ms_args(args);
        let out = run(&rust(), &self.sandbox, &strs(&full), options);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.cwd_listing().is_empty(), "wrote into cwd");
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        // The billed `POST /v1/scans` is sent only by `scans create` (DESIGN §10 M6c).
        if !(args.contains(&"scans") && args.contains(&"create")) {
            assert!(
                self.server.ms_requests(Ms::ScanCreate).is_empty(),
                "a scan was created by {args:?}"
            );
        }
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

    /// The writes sent (every non-GET model-security request).
    fn writes(&self) -> Vec<RecordedRequest> {
        self.server
            .requests()
            .into_iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    /// The JSON body of the only request on `route`.
    fn body(&self, route: Ms) -> Value {
        let requests = self.server.ms_requests(route);
        assert_eq!(requests.len(), 1, "{route:?}: {requests:?}");
        serde_json::from_slice(&requests[0].body).unwrap()
    }

    /// A file under the sandbox's `tmp/`; its absolute path.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.sandbox.tmp().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    }

    fn json_file(&self, name: &str, value: &Value) -> String {
        self.file(name, value.to_string().as_bytes())
    }

    fn tokens(&self) -> usize {
        self.server
            .routes()
            .iter()
            .filter(|route| **route == Route::Token)
            .count()
    }

    fn group(&self, uuid: &str) -> Option<Value> {
        self.server
            .modelsec_data()
            .groups
            .into_iter()
            .find(|group| group["uuid"] == uuid)
    }

    fn scan(&self, uuid: &str) -> Value {
        self.server
            .modelsec_data()
            .scans
            .into_iter()
            .find(|scan| scan["uuid"] == uuid)
            .unwrap()
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
    let out = f.ms(args);
    out.assert_code(2);
    assert_eq!(out.stdout, "", "{args:?}");
    assert_eq!(out.stderr, usage_block(message), "{args:?}");
    assert_eq!(f.server.request_count(), 0, "{args:?}");
}

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

/// The pretty group detail of the TS layout (MS§5.2).
fn group_detail(uuid: &str, name: &str, description: &str, source: &str, state: &str) -> String {
    format!(
        "\n  Security Group Detail:\n\n  UUID         {uuid}\n  Name         {name}\n  Description  {description}\n  Source Type  {source}\n  State        {state}\n  Created      2026-01-01T00:00:00Z\n  Updated      2026-01-01T00:00:00Z\n\n"
    )
}

fn group_config() -> Value {
    json!({
        "name": "g1",
        "source_type": "LOCAL",
        "description": "d1",
        "rule_configurations": {u(201): {"state": "BLOCKING"}}
    })
}

fn labels_json(pairs: &[(&str, &str)]) -> String {
    Value::Array(
        pairs
            .iter()
            .map(|(key, value)| json!({"key": key, "value": value}))
            .collect(),
    )
    .to_string()
}

// ---------------------------------------------------------------------------
// groups create|update|delete (§17.8)
// ---------------------------------------------------------------------------

mod groups {
    use super::*;

    /// `createGroup` (`modelsecurity.spec.ts:220-243`): the four keys, the rule
    /// configurations passed through; one `POST`; the group on stdout under the banner and
    /// `✓ Group created: <uuid>` on stderr (D190).
    #[test]
    fn create_posts_the_config_and_prints_the_group() {
        let f = fx();
        let config = f.json_file("g.json", &group_config());
        let out = f.ms(&["groups", "create", "--config", &config]);
        out.assert_success();
        let g = u(101);
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}{}",
                group_detail(&g, "g1", "d1", "LOCAL", "PENDING")
            )
        );
        assert_eq!(out.stderr, format!("  ✓ Group created: {g}\n"));
        assert_eq!(f.api(), [format!("POST {GROUPS}")]);
        assert_eq!(f.body(Ms::GroupCreate), group_config());
        assert!(f.group(&g).is_some(), "the service holds the group");
        // A config without a description sends the schema default `""` (both SDKs).
        let f = fx();
        let config = f.json_file("g.json", &json!({"name": "g2", "source_type": "LOCAL"}));
        f.ms(&["groups", "create", "--config", &config])
            .assert_success();
        assert_eq!(
            f.body(Ms::GroupCreate),
            json!({"name": "g2", "source_type": "LOCAL", "description": ""})
        );
    }

    /// The created group in every format (D189); `--quiet` drops the outcome line, the
    /// banner and the section, never the data (D190).
    #[test]
    fn create_prints_in_every_format() {
        let f = fx();
        let config = f.json_file("g.json", &group_config());
        let g = u(101);
        let out = f.ms(&["groups", "create", "--config", &config, "--output", "json"]);
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({"uuid": g, "name": "g1", "description": "d1", "sourceType": "LOCAL", "state": "PENDING", "createdAt": fx::AT, "updatedAt": fx::AT})
        );
        assert_eq!(out.stderr, format!("  ✓ Group created: {g}\n"));
        let out = f.ms(&["groups", "create", "--config", &config, "--output", "table"]);
        out.assert_success();
        assert!(out.stdout.contains(" uuid        │ "), "{}", out.stdout);
        assert!(out.stdout.contains(&u(102)), "{}", out.stdout);
        let out = f.ms(&["--quiet", "groups", "create", "--config", &config]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert!(out.stdout.starts_with("  UUID         "), "{}", out.stdout);
        assert!(!out.stdout.contains("Prisma AIRS"), "{}", out.stdout);
        // The tenant's `defaultOutput` does not apply to a write (choice 19).
        let server = FixtureServer::start();
        server.seed_modelsec();
        let sandbox = Sandbox::new();
        let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
            config.set("defaultOutput", "json");
        });
        sandbox.register(&[&tenant], Some("prod"));
        let path = sandbox.tmp().join("g.json");
        std::fs::write(&path, group_config().to_string()).unwrap();
        let path = path.display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &["model-security", "groups", "create", "--config", &path],
            &RunOptions::new(),
        );
        out.assert_success();
        assert!(out.stdout.starts_with(BANNER), "{}", out.stdout);
    }

    /// `updateGroup`: each given flag sent as given; `--description ''` clears (D187);
    /// the service's answer printed.
    #[test]
    fn update_sends_what_was_given() {
        let f = fx();
        let g = u(1);
        let out = f.ms(&[
            "groups",
            "update",
            &g,
            "--name",
            "Updated",
            "--description",
            "new desc",
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Ms::GroupUpdate),
            json!({"name": "Updated", "description": "new desc"})
        );
        assert_eq!(f.api(), [format!("PUT {GROUPS}/{g}")]);
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}{}",
                group_detail(&g, "Updated", "new desc", "LOCAL", "ACTIVE")
            )
        );
        assert_eq!(out.stderr, format!("  ✓ Group updated: {g}\n"));
        let f = fx();
        let out = f.ms(&["groups", "update", &g, "--description", ""]);
        out.assert_success();
        assert_eq!(f.body(Ms::GroupUpdate), json!({"description": ""}));
        assert!(
            out.stdout.contains("  Description  (none)\n"),
            "{}",
            out.stdout
        );
        assert_eq!(f.group(&g).unwrap()["description"], "");
    }

    /// `deleteGroupAndVerify` (`modelsecurity.spec.ts:274-304`) with D186: a 404 on the
    /// re-read confirms, a tombstone confirms, a group still present warns with its state
    /// and the hint, any other failure warns that the result is unverified; exit 0 in all
    /// four; stdout empty in every format.
    #[test]
    fn delete_is_verified_by_one_read() {
        let g = u(1);
        let recheck = format!("re-check with 'airs model-security groups get {g}'");
        for (mode, stderr) in [
            (GroupDeleteMode::Hard, format!("  ✓ Group {g} deleted.\n")),
            (
                GroupDeleteMode::Tombstone,
                format!("  ✓ Group {g} deleted (the service is removing it).\n"),
            ),
            (
                GroupDeleteMode::StillActive,
                format!(
                    "  ⚠ Delete request accepted, but group {g} still reports state 'ACTIVE'.\n  Deletion is asynchronous (soft-delete) — {recheck}.\n"
                ),
            ),
        ] {
            for alias in ["delete", "rm"] {
                let f = fx();
                f.server.modelsec(|data| data.group_delete = mode);
                let out = f.ms(&["groups", alias, &g, "--force", "--output", "json"]);
                out.assert_success();
                assert_eq!(out.stdout, "", "{mode:?}");
                assert_eq!(out.stderr, stderr, "{mode:?}");
                assert_eq!(
                    f.api(),
                    [format!("DELETE {GROUPS}/{g}"), format!("GET {GROUPS}/{g}")],
                    "{mode:?}: TS's sequence with --force"
                );
            }
        }
        // `--quiet` keeps the warning, drops the hint.
        let f = fx();
        f.server
            .modelsec(|data| data.group_delete = GroupDeleteMode::StillActive);
        let out = f.ms(&["--quiet", "groups", "rm", &g, "--force"]);
        out.assert_success();
        assert_eq!(
            out.stderr,
            format!("  ⚠ Delete request accepted, but group {g} still reports state 'ACTIVE'.\n")
        );
        // A failed re-read (a 500 the SDK read retries see six times) is unverified.
        let f = fx();
        f.server.set_default(
            Route::ModelSecurity(Ms::GroupGet),
            Planned::json(500, &json!({"message": "busy"})).with_retry_after(0),
        );
        let out = f.ms(&["groups", "rm", &g, "--force"]);
        out.assert_success();
        assert_eq!(
            out.stderr,
            format!(
                "  ⚠ Delete request accepted, but its result could not be verified; {recheck}.\n"
            )
        );
        assert_eq!(f.server.ms_requests(Ms::GroupDelete).len(), 1);
        // A failed DELETE is its error (TS propagates it); no re-read.
        let f = fx();
        let missing = u(77);
        let out = f.ms(&["groups", "rm", &missing, "--force"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 404", Some(404), &[])
        );
        assert_eq!(f.api(), [format!("DELETE {GROUPS}/{missing}")]);
    }

    /// Bad configs are file errors (exit 1) before the tenant (D188): unknown keys, the
    /// schema (D116); no request, the content never echoed.
    #[test]
    fn create_configs_are_checked_before_the_tenant() {
        let f = bare();
        for (config, message) in [
            (
                json!({"name": "g", "source_type": "LOCAL", "secret": fx::secret(5)}),
                "has an unknown key secret; a security group config takes name, source_type, description and rule_configurations",
            ),
            (
                json!({"name": "", "source_type": "LOCAL", "description": fx::secret(6)}),
                "",
            ),
        ] {
            let path = f.json_file("g.json", &config);
            let out = f.ms(&["groups", "create", "--config", &path]);
            out.assert_code(1);
            let expected = if message.is_empty() {
                s(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/security-groups did not match schema",
                )
            } else {
                format!("{path} {message}")
            };
            assert_eq!(out.stderr, error_block(&expected, None, &[]));
            assert_eq!(out.stdout, "");
            assert_eq!(f.server.request_count(), 0);
        }
    }
}

// ---------------------------------------------------------------------------
// rule-instances update (§17.9)
// ---------------------------------------------------------------------------

mod rule_instances {
    use super::*;

    /// `updateRuleInstance` (`modelsecurity.spec.ts:375-403`): the body carries the
    /// positional group and only the named fields; the instance is printed.
    #[test]
    fn update_sends_the_group_and_the_named_fields() {
        let f = fx();
        let (g, i) = (u(1), u(302));
        let config = f.json_file(
            "ri.json",
            &json!({"state": "ALLOWING", "field_values": {"approved_formats": ["onnx"]}}),
        );
        let out = f.ms(&["rule-instances", "update", &g, &i, "--config", &config]);
        out.assert_success();
        assert_eq!(
            f.body(Ms::RuleInstanceUpdate),
            json!({"security_group_uuid": g, "state": "ALLOWING", "field_values": {"approved_formats": ["onnx"]}})
        );
        assert_eq!(f.api(), [format!("PUT {GROUPS}/{g}/rule-instances/{i}")]);
        assert_eq!(out.stderr, format!("  ✓ Rule instance updated: {i}\n"));
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Rule Instance Detail:\n\n  UUID        {i}\n  Group UUID  {g}\n  Rule UUID   {}\n  State       ALLOWING\n  Created     2026-01-01T00:00:00Z\n  Updated     2026-01-01T00:00:00Z\n\n  Field Values:\n\n  approved_formats  onnx\n\n",
                u(202)
            )
        );
        // `state` alone, `null` included (TS sends it), and the file's own group in any
        // case.
        let f = fx();
        let config = f.json_file(
            "ri.json",
            &json!({"security_group_uuid": g.to_uppercase(), "field_values": null}),
        );
        f.ms(&[
            "rule-instances",
            "update",
            &g,
            &i,
            "--config",
            &config,
            "--output",
            "json",
        ])
        .assert_success();
        assert_eq!(
            f.body(Ms::RuleInstanceUpdate),
            json!({"security_group_uuid": g, "field_values": null})
        );
    }

    /// D187, D188: a file that changes nothing, names another group or an unknown key is
    /// refused (exit 1) before the tenant.
    #[test]
    fn configs_that_change_nothing_or_elsewhere_are_refused() {
        let f = bare();
        let (g, i) = (u(1), u(302));
        for (config, message) in [
            (json!({}), s("must set state or field_values")),
            (
                json!({"security_group_uuid": g}),
                s("must set state or field_values"),
            ),
            (
                json!({"security_group_uuid": u(2), "state": "BLOCKING"}),
                format!("names another security group than {g}"),
            ),
            (
                json!({"state": "BLOCKING", "rule_name": "x"}),
                s(
                    "has an unknown key rule_name; a rule instance config takes state, field_values and security_group_uuid",
                ),
            ),
        ] {
            let path = f.json_file("ri.json", &config);
            let out = f.ms(&["rule-instances", "update", &g, &i, "--config", &path]);
            out.assert_code(1);
            assert_eq!(
                out.stderr,
                error_block(&format!("{path} {message}"), None, &[])
            );
            assert_eq!(f.server.request_count(), 0);
        }
        let path = f.json_file("ri.json", &json!({"state": "ON"}));
        let out = f.ms(&["rule-instances", "update", &g, &i, "--config", &path]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                &format!(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/security-groups/{g}/rule-instances/{i} did not match schema"
                ),
                None,
                &[]
            )
        );
    }
}

// ---------------------------------------------------------------------------
// scans create (§17.10)
// ---------------------------------------------------------------------------

mod scans {
    use super::*;

    /// The whole file is the body, unknown keys kept; one billed `POST`; the pending scan
    /// shows no `Rules` line (D180); the URI's credential parts are withheld in every
    /// format and never reach stderr (D191).
    #[test]
    fn create_posts_the_whole_file_once() {
        let f = fx();
        let g = u(1);
        let uri = format!(
            "https://{}:{}@models.example.invalid/org/model.bin?X-Amz-Signature={}",
            fx::secret(1),
            fx::secret(2),
            fx::secret(3)
        );
        let config = json!({
            "model_uri": uri,
            "security_group_uuid": g,
            "scan_origin": "MODEL_SECURITY_SDK",
            "labels": [{"key": "env", "value": fx::secret(7)}],
            "unknown": "kept"
        });
        let path = f.json_file("scan.json", &config);
        let out = f.ms(&["scans", "create", "--config", &path]);
        out.assert_success();
        let scan = u(451);
        assert_eq!(f.body(Ms::ScanCreate), config);
        assert_eq!(f.api(), [format!("POST {SCANS}")]);
        assert_eq!(out.stderr, format!("  ✓ Scan created: {scan}\n"));
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Scan Detail:\n\n  UUID       {scan}\n  Outcome    PENDING\n  Model URI  https://[withheld]@models.example.invalid/org/model.bin?[withheld]\n  Origin     MODEL_SECURITY_SDK\n  Source     HUGGING_FACE\n  Group      Default LOCAL\n  Created    2026-01-01T00:00:00Z\n  Updated    2026-01-01T00:00:00Z\n\n  Labels:\n\n  env  {}\n\n",
                fx::secret(7)
            )
        );
        for format in ["json", "table"] {
            let f = fx();
            let path = f.json_file("scan.json", &config);
            let out = f.ms(&["scans", "create", "--config", &path, "--output", format]);
            out.assert_success();
            for marker in [fx::secret(1), fx::secret(2), fx::secret(3)] {
                assert!(!out.stdout.contains(&marker), "{format}: {}", out.stdout);
            }
            assert!(out.stdout.contains("[withheld]"), "{format}");
            if format == "json" {
                let doc = out.json();
                assert_eq!(doc["evalOutcome"], "PENDING");
                assert!(doc.get("evalSummary").is_none_or(Value::is_null), "{doc}");
            }
        }
    }

    /// The scan schema (`model_uri`, `security_group_uuid`, the origin enum) is checked
    /// before the tenant (D116, exit 1).
    #[test]
    fn create_configs_are_checked_before_the_tenant() {
        let f = bare();
        for config in [
            json!({"model_uri": "hf://org/model"}),
            json!({"model_uri": "hf://org/model", "security_group_uuid": u(1), "scan_origin": "CLI"}),
        ] {
            let path = f.json_file("scan.json", &config);
            let out = f.ms(&["scans", "create", "--config", &path]);
            out.assert_code(1);
            assert_eq!(
                out.stderr,
                error_block(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scans did not match schema",
                    None,
                    &[]
                )
            );
            assert_eq!(f.server.request_count(), 0);
        }
    }
}

// ---------------------------------------------------------------------------
// labels add|set|delete (§17.11)
// ---------------------------------------------------------------------------

mod labels {
    use super::*;

    /// `addLabels`, `setLabels`, `deleteLabels` (`modelsecurity.spec.ts:741-767`): the
    /// bodies and keys; the service merges, replaces and deletes; stdout empty in every
    /// format; the TS outcome lines on stderr.
    #[test]
    fn add_set_and_delete_change_the_scan_labels() {
        let scan = u(401);
        for format in ["pretty", "json", "table"] {
            let f = fx();
            let added = labels_json(&[("env", "staging"), ("new", &fx::secret(8))]);
            let out = f.ms(&[
                "labels", "add", &scan, "--labels", &added, "--output", format,
            ]);
            out.assert_success();
            assert_eq!(out.stdout, "", "{format}");
            assert_eq!(out.stderr, "  ✓ Labels added.\n");
            assert_eq!(
                f.body(Ms::LabelsAdd),
                json!({"labels": [{"key": "env", "value": "staging"}, {"key": "new", "value": fx::secret(8)}]})
            );
            assert_eq!(
                f.scan(&scan)["labels"],
                json!([{"key": "env", "value": "staging"}, {"key": "team", "value": "ml"}, {"key": "new", "value": fx::secret(8)}])
            );
            f.clear();
            let only = labels_json(&[("only", "x")]);
            let out = f.ms(&[
                "labels", "set", &scan, "--labels", &only, "--force", "--output", format,
            ]);
            out.assert_success();
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "  ⚠ The replacement drops 3 label(s) the scan has now: env, team, new\n  ✓ Labels set.\n"
            );
            assert_eq!(
                f.api(),
                [
                    format!("GET {SCANS}/{scan}"),
                    format!("PUT {SCANS}/{scan}/labels")
                ]
            );
            assert_eq!(
                f.body(Ms::LabelsSet),
                json!({"labels": [{"key": "only", "value": "x"}]})
            );
            assert_eq!(
                f.scan(&scan)["labels"],
                json!([{"key": "only", "value": "x"}])
            );
            f.clear();
            let out = f.ms(&[
                "labels",
                "rm",
                &scan,
                "--keys",
                "only, nope",
                "--force",
                "--output",
                format,
            ]);
            out.assert_success();
            assert_eq!(out.stdout, "");
            assert_eq!(out.stderr, "  ✓ Labels deleted.\n");
            assert_eq!(
                f.api(),
                [format!("DELETE {SCANS}/{scan}/labels?keys=only&keys=nope")]
            );
            assert_eq!(f.scan(&scan)["labels"], json!([]));
        }
    }

    /// A replacement that keeps every key prints no warning; `--quiet` keeps the
    /// warning and drops the outcome line.
    #[test]
    fn set_warns_only_about_dropped_keys() {
        let f = fx();
        let scan = u(401);
        let same = labels_json(&[("team", "x"), ("env", "y")]);
        let out = f.ms(&["labels", "set", &scan, "--labels", &same, "--force"]);
        out.assert_success();
        assert_eq!(out.stderr, "  ✓ Labels set.\n");
        let fewer = labels_json(&[("team", "x")]);
        let out = f.ms(&[
            "--quiet", "labels", "set", &scan, "--labels", &fewer, "--force",
        ]);
        out.assert_success();
        assert_eq!(
            out.stderr,
            "  ⚠ The replacement drops 1 label(s) the scan has now: env\n"
        );
        // A failed read of the scan sends nothing (its §6 error).
        let f = fx();
        let missing = u(499);
        let out = f.ms(&["labels", "set", &missing, "--labels", &fewer, "--force"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 404", Some(404), &[])
        );
        assert!(f.writes().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Argument and file checks before the tenant (D184, D187, D188, D50)
// ---------------------------------------------------------------------------

mod checks {
    use super::*;

    /// Every argument error is a usage error (exit 2) in a sandbox without a tenant, with
    /// no request: ids, the update flags and schema, `--labels`, `--keys`, the formats and
    /// the non-interactive confirmations (D185).
    #[test]
    fn argument_errors_are_usage_errors_before_the_tenant() {
        let (g, scan) = (u(1), u(401));
        let long = "d".repeat(1001);
        let ok = labels_json(&[("k", "v")]);
        for (args, message) in [
            (
                vec![s("groups"), s("update"), s("x"), s("--name"), s("n")],
                s("AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: x"),
            ),
            (
                vec![s("groups"), s("update"), g.clone()],
                s("groups update needs --name or --description"),
            ),
            (
                vec![s("groups"), s("update"), g.clone(), s("--name"), s("")],
                format!(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/security-groups/{g} did not match schema"
                ),
            ),
            (
                vec![
                    s("groups"),
                    s("update"),
                    g.clone(),
                    s("--description"),
                    long,
                ],
                format!(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/security-groups/{g} did not match schema"
                ),
            ),
            (
                vec![s("groups"), s("delete"), s("not-a-uuid"), s("--force")],
                s("AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: not-a-uuid"),
            ),
            (
                vec![s("groups"), s("delete"), g.clone()],
                format!(
                    "refusing to delete security group {g} without --force in non-interactive mode"
                ),
            ),
            (
                vec![
                    s("rule-instances"),
                    s("update"),
                    s("x"),
                    g.clone(),
                    s("--config"),
                    s("r.json"),
                ],
                s("AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: x"),
            ),
            (
                vec![
                    s("rule-instances"),
                    s("update"),
                    g.clone(),
                    s("x"),
                    s("--config"),
                    s("r.json"),
                ],
                s("AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid rule instance uuid: x"),
            ),
            (
                vec![s("labels"), s("add"), s("x"), s("--labels"), ok.clone()],
                s("AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid scan uuid: x"),
            ),
            (
                vec![
                    s("labels"),
                    s("add"),
                    scan.clone(),
                    s("--labels"),
                    format!("PRIVATE-NOT-JSON-{}", fx::secret(9)),
                ],
                s("--labels is not valid JSON"),
            ),
            (
                vec![
                    s("labels"),
                    s("add"),
                    scan.clone(),
                    s("--labels"),
                    json!({"key": "k", "value": "v"}).to_string(),
                ],
                s(
                    "--labels must be a JSON array of {\"key\", \"value\"} objects (key 1-128, value 1-256 characters)",
                ),
            ),
            (
                vec![
                    s("labels"),
                    s("set"),
                    scan.clone(),
                    s("--labels"),
                    s("[]"),
                    s("--force"),
                ],
                s(
                    "--labels must be a JSON array of {\"key\", \"value\"} objects (key 1-128, value 1-256 characters)",
                ),
            ),
            (
                vec![
                    s("labels"),
                    s("add"),
                    scan.clone(),
                    s("--labels"),
                    labels_json(&[("", "v")]),
                ],
                s(
                    "--labels must be a JSON array of {\"key\", \"value\"} objects (key 1-128, value 1-256 characters)",
                ),
            ),
            (
                vec![
                    s("labels"),
                    s("set"),
                    scan.clone(),
                    s("--labels"),
                    ok.clone(),
                ],
                format!(
                    "refusing to replace the labels of scan {scan} without --force in non-interactive mode"
                ),
            ),
            (
                vec![
                    s("labels"),
                    s("delete"),
                    scan.clone(),
                    s("--keys"),
                    s(""),
                    s("--force"),
                ],
                s("--keys values must not be empty"),
            ),
            (
                vec![
                    s("labels"),
                    s("rm"),
                    scan.clone(),
                    s("--keys"),
                    s(","),
                    s("--force"),
                ],
                s("--keys values must not be empty"),
            ),
            (
                vec![s("labels"), s("rm"), scan.clone(), s("--keys"), s("env")],
                format!(
                    "refusing to delete labels from scan {scan} without --force in non-interactive mode"
                ),
            ),
            (
                vec![
                    s("labels"),
                    s("rm"),
                    scan.clone(),
                    s("--keys"),
                    s("env"),
                    s("--force"),
                    s("--output"),
                    s("yaml"),
                ],
                s("Invalid output format 'yaml'. Expected: pretty, table, json"),
            ),
            (
                vec![
                    s("groups"),
                    s("create"),
                    s("--config"),
                    s("g.json"),
                    s("--output"),
                    s("markdown"),
                ],
                s("Invalid output format 'markdown'. Expected: pretty, table, json"),
            ),
            (
                vec![
                    s("scans"),
                    s("create"),
                    s("--config"),
                    s("s.json"),
                    s("--output"),
                    s("csv"),
                ],
                s("Invalid output format 'csv'. Expected: pretty, table, json"),
            ),
        ] {
            assert_usage(&strs(&args), &message);
        }
    }

    /// The `--config` files follow the §13.2 input rules before the tenant (exit 1, the
    /// path named, no content echoed, no request), on every command that reads one.
    #[test]
    fn config_files_follow_the_input_rules() {
        let f = bare();
        let (g, i) = (u(1), u(302));
        let dir = f.sandbox.tmp().join("dir");
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.display().to_string();
        let missing = f.sandbox.tmp().join("missing.json").display().to_string();
        let big = f.file("big.json", &vec![b' '; 1_048_577]);
        let binary = f.file("bin.json", b"{\"name\": \"\xff\"}");
        let broken = f.file(
            "broken.json",
            format!("{{\"name\": {}", fx::secret(10)).as_bytes(),
        );
        let array = f.file("array.json", b"[1]");
        let null = f.file("null.json", b"null");
        let unreadable = |path: &str| {
            format!(
                "Cannot read {path} (missing, not a regular file, unreadable or larger than 1 MiB)"
            )
        };
        for (path, message) in [
            (missing.clone(), unreadable(&missing)),
            (dir.clone(), unreadable(&dir)),
            (big.clone(), unreadable(&big)),
            (binary.clone(), format!("{binary} is not valid UTF-8")),
            (broken.clone(), format!("{broken} is not valid JSON")),
            (array.clone(), format!("{array} must contain a JSON object")),
            (null.clone(), format!("{null} must contain a JSON object")),
        ] {
            for args in [
                vec![s("groups"), s("create"), s("--config"), path.clone()],
                vec![s("scans"), s("create"), s("--config"), path.clone()],
                vec![
                    s("rule-instances"),
                    s("update"),
                    g.clone(),
                    i.clone(),
                    s("--config"),
                    path.clone(),
                ],
            ] {
                let out = f.ms(&strs(&args));
                out.assert_code(1);
                assert_eq!(out.stdout, "", "{args:?}");
                assert_eq!(out.stderr, error_block(&message, None, &[]), "{args:?}");
                assert_eq!(f.server.request_count(), 0);
            }
        }
    }

    /// The file and argument checks come before the tenant: a valid file in a sandbox
    /// without a tenant reaches the tenant error (exit 1), no request.
    #[test]
    fn a_valid_config_reaches_the_tenant_check() {
        let f = bare();
        let path = f.json_file("g.json", &group_config());
        let out = f.ms(&["groups", "create", "--config", &path]);
        out.assert_code(1);
        assert!(out.stderr.contains("No tenant selected"), "{}", out.stderr);
        assert_eq!(f.server.request_count(), 0);
    }
}

// ---------------------------------------------------------------------------
// Confirmations on a terminal (D185)
// ---------------------------------------------------------------------------

mod confirmations {
    use super::*;

    fn pty(f: &Fx, args: &[&str], prompt: &str, answer: &[u8]) -> PtyRun {
        let full = ms_args(args);
        let mut session = spawn_pty(&rust(), &f.sandbox, &strs(&full), &RunOptions::new());
        session.expect(prompt);
        assert!(f.writes().is_empty(), "no write while the prompt waits");
        session.send(answer);
        session.wait()
    }

    /// `groups delete`: the token, the read that names the group, the prompt; `y`/`yes`
    /// confirm; `n`, Enter, EOF and anything else decline with `ℹ Aborted`.
    #[test]
    fn the_group_delete_prompt_names_the_group() {
        let g = u(1);
        let prompt = format!("? Delete security group {g} (Default LOCAL)? (y/N) ");
        for answer in [&b"y\n"[..], b" YES \n"] {
            let f = fx();
            let out = pty(&f, &["groups", "delete", &g], &prompt, answer);
            out.run.assert_success();
            assert!(
                transcript(&out).contains(&format!("✓ Group {g} deleted.")),
                "{}",
                transcript(&out)
            );
            assert_eq!(
                f.api(),
                [
                    format!("GET {GROUPS}/{g}"),
                    format!("DELETE {GROUPS}/{g}"),
                    format!("GET {GROUPS}/{g}")
                ]
            );
        }
        for answer in [&b"n\n"[..], b"\n", b"\x04", b"yep\n"] {
            let f = fx();
            let out = pty(&f, &["groups", "rm", &g], &prompt, answer);
            out.run.assert_success();
            assert!(transcript(&out).contains("  ℹ Aborted\n"), "{answer:?}");
            assert!(f.writes().is_empty(), "{answer:?}");
            assert!(f.group(&g).is_some());
        }
        // A group without a name: no ` (<name>)`; a name with a control character is
        // terminal-safe.
        let f = fx();
        f.server
            .modelsec(|data| data.groups[0]["name"] = json!("Evil\u{1b}[31m"));
        let out = pty(
            &f,
            &["groups", "rm", &g],
            &format!("? Delete security group {g} (Evil\u{fffd}[31m)? (y/N) "),
            b"n\n",
        );
        out.run.assert_success();
    }

    /// `labels set` names the labels it drops; `labels delete` names the keys.
    #[test]
    fn the_label_prompts_name_the_keys() {
        let scan = u(401);
        let f = fx();
        let out = pty(
            &f,
            &[
                "labels",
                "set",
                &scan,
                "--labels",
                &labels_json(&[("env", "x")]),
            ],
            &format!(
                "? Replace all labels on scan {scan}? It drops 1 label(s) the scan has now: team. (y/N) "
            ),
            b"y\n",
        );
        out.run.assert_success();
        assert_eq!(f.writes().len(), 1);
        assert!(transcript(&out).contains("✓ Labels set."));
        let f = fx();
        let out = pty(
            &f,
            &[
                "labels",
                "set",
                &scan,
                "--labels",
                &labels_json(&[("env", "x"), ("team", "y")]),
            ],
            &format!("? Replace all labels on scan {scan}? (y/N) "),
            b"n\n",
        );
        out.run.assert_success();
        assert!(f.writes().is_empty());
        let f = fx();
        let out = pty(
            &f,
            &["labels", "delete", &scan, "--keys", "env,team"],
            &format!("? Delete label(s) env, team from scan {scan}? (y/N) "),
            b"yes\n",
        );
        out.run.assert_success();
        assert_eq!(f.scan(&scan)["labels"], json!([]));
        assert_eq!(
            f.api(),
            [format!("DELETE {SCANS}/{scan}/labels?keys=env&keys=team")],
            "no read before the delete prompt"
        );
    }

    /// Ctrl-C at a prompt: `Cancelled; nothing was changed.`, exit 130, no write.
    #[test]
    fn ctrl_c_at_the_prompt_changes_nothing() {
        let (g, scan) = (u(1), u(401));
        for args in [
            vec![s("groups"), s("delete"), g.clone()],
            vec![s("labels"), s("rm"), scan.clone(), s("--keys"), s("env")],
            vec![
                s("labels"),
                s("set"),
                scan.clone(),
                s("--labels"),
                labels_json(&[("a", "b")]),
            ],
        ] {
            let f = fx();
            let full = ms_args(&strs(&args));
            let mut session = spawn_pty(&rust(), &f.sandbox, &strs(&full), &RunOptions::new());
            session.expect("(y/N) ");
            session.signal("INT");
            let out = session.wait();
            out.run.assert_code(130);
            assert!(
                transcript(&out).contains("\n  Cancelled; nothing was changed.\n"),
                "{}",
                transcript(&out)
            );
            assert!(f.writes().is_empty(), "{args:?}");
        }
    }

    /// `groups create|update`, `rule-instances update`, `scans create` and `labels add`
    /// never ask (choice 9).
    #[test]
    fn the_other_writes_do_not_confirm() {
        let f = fx();
        let (g, i, scan) = (u(1), u(302), u(401));
        let group = f.json_file("g.json", &group_config());
        let instance = f.json_file("ri.json", &json!({"state": "BLOCKING"}));
        let scan_config = f.json_file(
            "s.json",
            &json!({"model_uri": "hf://org/model", "security_group_uuid": g}),
        );
        for args in [
            vec![s("groups"), s("create"), s("--config"), group],
            vec![s("groups"), s("update"), g.clone(), s("--name"), s("n")],
            vec![
                s("rule-instances"),
                s("update"),
                g.clone(),
                i,
                s("--config"),
                instance,
            ],
            vec![s("scans"), s("create"), s("--config"), scan_config],
            vec![
                s("labels"),
                s("add"),
                scan,
                s("--labels"),
                labels_json(&[("a", "b")]),
            ],
        ] {
            let full = ms_args(&strs(&args));
            let out = spawn_pty(&rust(), &f.sandbox, &strs(&full), &RunOptions::new()).wait();
            out.run.assert_success();
            assert!(!transcript(&out).contains("(y/N)"), "{args:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// One attempt per write (D179)
// ---------------------------------------------------------------------------

mod attempts {
    use super::*;

    /// Each write: its route, its arguments, its outcome words and hint.
    fn writes(f: &Fx) -> Vec<(Ms, Vec<String>, &'static str, Option<String>)> {
        let (g, i, scan) = (u(1), u(302), u(401));
        let group = f.json_file("g.json", &group_config());
        let instance = f.json_file("ri.json", &json!({"state": "BLOCKING"}));
        let scan_config = f.json_file(
            "s.json",
            &json!({"model_uri": "hf://org/model", "security_group_uuid": g}),
        );
        vec![
            (
                Ms::GroupCreate,
                vec![s("groups"), s("create"), s("--config"), group],
                "the security group may have been created",
                Some(s(
                    "Check 'airs model-security groups list' before creating it again.",
                )),
            ),
            (
                Ms::GroupUpdate,
                vec![s("groups"), s("update"), g.clone(), s("--name"), s("n")],
                "the security group may have been updated",
                None,
            ),
            (
                Ms::GroupDelete,
                vec![s("groups"), s("rm"), g.clone(), s("--force")],
                "the security group may have been deleted",
                Some(format!(
                    "Check it with 'airs model-security groups get {g}'."
                )),
            ),
            (
                Ms::RuleInstanceUpdate,
                vec![
                    s("rule-instances"),
                    s("update"),
                    g.clone(),
                    i,
                    s("--config"),
                    instance,
                ],
                "the rule instance may have been updated",
                None,
            ),
            (
                Ms::ScanCreate,
                vec![s("scans"), s("create"), s("--config"), scan_config],
                "the scan may have been created",
                Some(s(
                    "Check 'airs model-security scans list' before creating another scan; scans are billed and cannot be deleted.",
                )),
            ),
            (
                Ms::LabelsAdd,
                vec![
                    s("labels"),
                    s("add"),
                    scan.clone(),
                    s("--labels"),
                    labels_json(&[("a", "b")]),
                ],
                "the labels may have been added",
                None,
            ),
            (
                Ms::LabelsSet,
                vec![
                    s("labels"),
                    s("set"),
                    scan.clone(),
                    s("--labels"),
                    labels_json(&[("a", "b")]),
                    s("--force"),
                ],
                "the labels may have been replaced",
                None,
            ),
            (
                Ms::LabelsDelete,
                vec![
                    s("labels"),
                    s("rm"),
                    scan,
                    s("--keys"),
                    s("env"),
                    s("--force"),
                ],
                "the labels may have been deleted",
                None,
            ),
        ]
    }

    /// A 5xx with `Retry-After: 0` is one request and an unknown outcome (with the hint
    /// of `groups create|delete` and `scans create`); a 401 is `token, write, token,
    /// write`; a 403 is one request with no outcome line.
    #[test]
    fn every_write_is_one_attempt() {
        let count = writes(&fx()).len();
        for index in 0..count {
            let f = fx();
            let (route, args, unknown, hint) = writes(&f).remove(index);
            f.server.push_once(
                Route::ModelSecurity(route),
                Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
            );
            let out = f.ms(&strs(&args));
            out.assert_code(1);
            assert_eq!(f.server.ms_requests(route).len(), 1, "{route:?} 5xx");
            let mut details = vec![format!("Outcome unknown: {unknown}.")];
            details.extend(hint.clone());
            let details: Vec<&str> = details.iter().map(String::as_str).collect();
            assert_eq!(
                out.stderr.replace(
                    "  ⚠ The replacement drops 2 label(s) the scan has now: env, team\n",
                    ""
                ),
                error_block("AISEC_SERVER_SIDE_ERROR:API error 503", Some(503), &details),
                "{route:?}"
            );
            assert_eq!(out.stdout, "");
            let f = fx();
            let (_, args, _, _) = writes(&f).remove(index);
            f.server
                .push_once(Route::ModelSecurity(route), Planned::empty_json(401));
            f.ms(&strs(&args)).assert_success();
            assert_eq!(f.server.ms_requests(route).len(), 2, "{route:?} 401");
            assert_eq!(f.tokens(), 2, "{route:?}: a fresh token for the replay");
            let f = fx();
            let (_, args, _, _) = writes(&f).remove(index);
            f.server
                .push_once(Route::ModelSecurity(route), Planned::empty_json(403));
            let out = f.ms(&strs(&args));
            out.assert_code(1);
            assert_eq!(f.server.ms_requests(route).len(), 1, "{route:?} 403");
            assert!(!out.stderr.contains("Outcome"), "{route:?}");
        }
    }

    /// An applied write whose connection drops: one request, the outcome line and hint;
    /// `scans create` is never followed by a read. A 2xx that cannot be read says the
    /// change was made.
    #[test]
    fn unknown_and_unreadable_outcomes() {
        let f = fx();
        let config = f.json_file(
            "s.json",
            &json!({"model_uri": "hf://org/model", "security_group_uuid": u(1)}),
        );
        f.server.push_once(
            Route::ModelSecurity(Ms::ScanCreate),
            Planned::applied_then_dropped(),
        );
        let out = f.ms(&["scans", "create", "--config", &config]);
        out.assert_code(1);
        assert!(out.stderr.contains("    Outcome unknown: the scan may have been created.\n    Check 'airs model-security scans list' before creating another scan; scans are billed and cannot be deleted.\n"), "{}", out.stderr);
        assert_eq!(f.api(), [format!("POST {SCANS}")], "one POST, no read");
        assert_eq!(
            f.server.modelsec_data().scans.len(),
            3,
            "the service applied it"
        );
        let f = fx();
        f.server.push_once(
            Route::ModelSecurity(Ms::LabelsAdd),
            Planned::raw(200, "application/json", "{not json"),
        );
        let out = f.ms(&[
            "labels",
            "add",
            &u(401),
            "--labels",
            &labels_json(&[("a", "b")]),
        ]);
        out.assert_code(1);
        assert!(
            out.stderr.contains(
                "    Outcome: the labels was added, but the response could not be read.\n"
            ),
            "{}",
            out.stderr
        );
        let f = fx();
        let config = f.json_file("g.json", &group_config());
        f.server.push_once(
            Route::ModelSecurity(Ms::GroupCreate),
            Planned::raw(200, "text/plain", "created"),
        );
        let out = f.ms(&["groups", "create", "--config", &config]);
        out.assert_code(1);
        assert!(out.stderr.contains("    Outcome: the security group was created, but the response could not be read.\n    Check 'airs model-security groups list' before creating it again.\n"), "{}", out.stderr);
    }

    /// Server text in a write error is never echoed (D11): the §6 message only.
    #[test]
    fn write_errors_name_the_status_only() {
        let f = fx();
        f.server.push_once(
            Route::ModelSecurity(Ms::GroupUpdate),
            Planned::json(
                400,
                &json!({"message": format!("bad {} \u{1b}[31m", fx::secret(11))}),
            ),
        );
        let out = f.ms(&["groups", "update", &u(1), "--name", "n"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 400", Some(400), &[])
        );
    }
}

// ---------------------------------------------------------------------------
// Server text and sensitive data (D52, §17.15)
// ---------------------------------------------------------------------------

mod text {
    use super::*;

    /// Control characters in an answered name are replaced in the layout and the
    /// outcome line; a returned name carrying a secret of the run is withheld.
    #[test]
    fn answered_text_is_terminal_safe_and_withheld() {
        let f = fx();
        let config = f.json_file(
            "g.json",
            &json!({"name": "Evil\u{1b}[31m\tname", "source_type": "LOCAL"}),
        );
        let out = f.ms(&["groups", "create", "--config", &config]);
        out.assert_success();
        assert!(
            out.stdout
                .contains("  Name         Evil\u{fffd}[31m\u{fffd}name\n"),
            "{}",
            out.stdout
        );
        assert!(!out.stdout.contains('\u{1b}'));
        let f = fx();
        f.server.push_once(
            Route::ModelSecurity(Ms::GroupUpdate),
            Planned::json(
                200,
                &json!({
                    "uuid": u(1), "tsg_id": TSG, "created_at": fx::AT, "updated_at": fx::AT,
                    "name": format!("x FAKE-SECRET-{TSG} y"), "description": "", "source_type": "LOCAL",
                    "state": "ACTIVE", "is_tombstone": false
                }),
            ),
        );
        let out = f.ms(&["groups", "update", &u(1), "--name", "x", "--output", "json"]);
        out.assert_success();
        assert_eq!(out.json()["name"], "[withheld]");
    }

    /// Label values and config values never reach stderr or the debug log (the runner's
    /// marker check); label values reach no prompt or warning either.
    #[test]
    fn label_values_and_configs_stay_out_of_messages() {
        let f = fx();
        let scan = u(401);
        f.server.modelsec(|data| {
            data.scans[0]["labels"] = json!([{"key": "env", "value": fx::secret(12)}]);
        });
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let labels = labels_json(&[("team", &fx::secret(13))]);
        let out = f.ms_with(
            &[
                "--debug", "labels", "set", &scan, "--labels", &labels, "--force",
            ],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        );
        out.assert_success();
        assert!(
            out.stderr
                .contains("drops 1 label(s) the scan has now: env\n")
        );
        let markers = fx::markers();
        let markers: Vec<&str> = markers.iter().map(String::as_str).collect();
        debug_log::assert_logs_clean(
            &f.sandbox,
            &f.server,
            &[debug_log::log_dir(&f.sandbox)],
            &markers,
        );
    }
}

// ---------------------------------------------------------------------------
// --debug (D64, G23)
// ---------------------------------------------------------------------------

mod debug {
    use super::*;

    /// Every write records its SDK operation name, status and headers only: no body, no
    /// query, no marker.
    #[test]
    fn writes_record_their_operation_names_and_no_body() {
        type Case = (Box<dyn Fn(&Fx) -> Vec<String>>, Vec<&'static str>);
        let cases: Vec<Case> = vec![
            (
                Box::new(|f: &Fx| {
                    let config =
                        json!({"name": "g", "source_type": "LOCAL", "description": fx::secret(14)});
                    vec![
                        s("groups"),
                        s("create"),
                        s("--config"),
                        f.json_file("g.json", &config),
                    ]
                }),
                vec!["airs.model_security.groups.create"],
            ),
            (
                Box::new(move |_: &Fx| {
                    vec![
                        s("groups"),
                        s("update"),
                        u(1),
                        s("--description"),
                        fx::secret(15),
                    ]
                }),
                vec!["airs.model_security.groups.update"],
            ),
            (
                Box::new(|_: &Fx| vec![s("groups"), s("rm"), u(1), s("--force")]),
                vec![
                    "airs.model_security.groups.delete",
                    "airs.model_security.groups.get",
                ],
            ),
            (
                Box::new(move |f: &Fx| {
                    let config = json!({"field_values": {"approved_formats": [fx::secret(16)]}});
                    vec![
                        s("rule-instances"),
                        s("update"),
                        u(1),
                        u(302),
                        s("--config"),
                        f.json_file("ri.json", &config),
                    ]
                }),
                vec!["airs.model_security.groups.update_rule_instance"],
            ),
            (
                Box::new(move |f: &Fx| {
                    let config = json!({"model_uri": format!("s3://bucket/m?sig={}", fx::secret(17)), "security_group_uuid": u(1)});
                    vec![
                        s("scans"),
                        s("create"),
                        s("--config"),
                        f.json_file("s.json", &config),
                    ]
                }),
                vec!["airs.model_security.scans.create"],
            ),
            (
                Box::new(move |_: &Fx| {
                    vec![
                        s("labels"),
                        s("add"),
                        u(401),
                        s("--labels"),
                        labels_json(&[("k", &fx::secret(18))]),
                    ]
                }),
                vec!["airs.model_security.scans.add_labels"],
            ),
            (
                Box::new(move |_: &Fx| {
                    vec![
                        s("labels"),
                        s("set"),
                        u(401),
                        s("--labels"),
                        labels_json(&[("k", &fx::secret(19))]),
                        s("--force"),
                    ]
                }),
                vec![
                    "airs.model_security.scans.get",
                    "airs.model_security.scans.set_labels",
                ],
            ),
            (
                Box::new(move |_: &Fx| {
                    vec![
                        s("labels"),
                        s("rm"),
                        u(401),
                        s("--keys"),
                        s("secret-key"),
                        s("--force"),
                    ]
                }),
                vec!["airs.model_security.scans.delete_labels"],
            ),
        ];
        for (args, operations) in cases {
            let f = fx();
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec![s("--debug")];
            full.extend(args(&f));
            let out = f.ms_with(
                &strs(&full),
                &RunOptions::new().env("XDG_STATE_HOME", &state),
            );
            out.assert_success();
            let (path, records) = debug_log::only_log(&f.sandbox);
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains("secret-key") && !text.contains("keys="),
                "no query"
            );
            assert!(!text.contains("Default LOCAL"), "no body");
            let found: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .collect();
            let mut expected = vec!["oauth.token"];
            expected.extend(operations.iter().copied());
            assert_eq!(found, expected, "{full:?}");
            let markers = fx::markers();
            let markers: Vec<&str> = markers.iter().map(String::as_str).collect();
            debug_log::assert_logs_clean(
                &f.sandbox,
                &f.server,
                &[debug_log::log_dir(&f.sandbox)],
                &markers,
            );
        }
    }

    /// A usage error opens no log.
    #[test]
    fn usage_errors_open_no_log() {
        let f = fx();
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let out = f.ms_with(
            &["--debug", "groups", "update", &u(1)],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        );
        out.assert_code(2);
        assert!(debug_log::log_files(&debug_log::log_dir(&f.sandbox)).is_empty());
    }
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

mod tenants {
    use super::*;

    /// The writes use the selected tenant's management credentials and its two bases.
    #[test]
    fn writes_use_the_selected_tenant() {
        let server = FixtureServer::start();
        server.seed_modelsec();
        let sandbox = Sandbox::new();
        let prod = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |_| {});
        let other = sandbox.add_fixture_tenant_with(&server, "other", "200", |_| {});
        sandbox.register(&[&prod, &other], Some("prod"));
        let out = run(
            &rust(),
            &sandbox,
            &[
                "--tenant",
                "other",
                "model-security",
                "labels",
                "add",
                &u(401),
                "--labels",
                &labels_json(&[("a", "b")]),
            ],
            &RunOptions::new(),
        );
        out.assert_success();
        let token = &server.requests_for(Route::Token)[0];
        assert!(
            format!("{:?}", token.auth).contains("200"),
            "the other tenant's credentials: {:?}",
            token.auth
        );
        let write = &server.ms_requests(Ms::LabelsAdd)[0];
        assert!(write.path.starts_with("/aims/data/v1/"), "{}", write.path);
        assert!(write.header("x-pan-token").is_none());
    }
}

// ---------------------------------------------------------------------------
// Interruption (D193)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    fn spawn_ms(f: &Fx, args: &[&str]) -> airs_test_harness::Running {
        let full = ms_args(args);
        spawn(
            &rust(),
            &f.sandbox,
            &strs(&full),
            &RunOptions::new().expect_signal(),
        )
    }

    /// A signal while a create, an update or a `scans create` is held: the change may
    /// have been applied; nothing is re-sent; afterwards the service holds the change.
    #[test]
    fn a_signal_during_a_write_reports_an_unknown_outcome() {
        type Args = fn(&Fx) -> Vec<String>;
        let cases: [(Ms, Args); 3] = [
            (Ms::GroupCreate, |f| {
                vec![
                    s("groups"),
                    s("create"),
                    s("--config"),
                    f.json_file("g.json", &group_config()),
                ]
            }),
            (Ms::GroupUpdate, |_| {
                vec![s("groups"), s("update"), u(1), s("--name"), s("held")]
            }),
            (Ms::ScanCreate, |f| {
                vec![
                    s("scans"),
                    s("create"),
                    s("--config"),
                    f.json_file(
                        "s.json",
                        &json!({"model_uri": "hf://org/held", "security_group_uuid": u(1)}),
                    ),
                ]
            }),
        ];
        for (route, args) in cases {
            for (signal, code) in [("INT", 130), ("TERM", 143)] {
                let f = fx();
                let args = args(&f);
                f.server
                    .push_once(Route::ModelSecurity(route), Planned::held());
                let running = spawn_ms(&f, &strs(&args));
                assert!(f.server.wait_for_route(
                    Route::ModelSecurity(route),
                    1,
                    Duration::from_secs(20)
                ));
                running.send_signal(signal);
                let out = running.wait();
                f.server.release_held();
                out.assert_code(code);
                assert_eq!(out.stdout, "");
                assert_eq!(
                    out.stderr,
                    "\n  ✗ Error: Interrupted; the change may already have been applied (outcome unknown)\n\n",
                    "{route:?}"
                );
                assert_eq!(
                    f.server.ms_requests(route).len(),
                    1,
                    "{route:?}: nothing re-sent"
                );
                let data = f.server.modelsec_data();
                let changed = match route {
                    Ms::GroupCreate => data.groups.iter().any(|g| g["uuid"] == u(101)),
                    Ms::GroupUpdate => data.groups[0]["name"] == "held",
                    _ => data
                        .scans
                        .iter()
                        .any(|scan| scan["model_uri"] == "hf://org/held"),
                };
                assert!(changed, "{route:?}: the service applied the held write");
            }
        }
    }

    /// A signal during the verification read after an accepted `DELETE`.
    #[test]
    fn a_signal_during_the_delete_verification() {
        let f = fx();
        let g = u(1);
        f.server
            .modelsec(|data| data.group_delete = GroupDeleteMode::StillActive);
        f.server
            .push_once(Route::ModelSecurity(Ms::GroupGet), Planned::hang());
        let running = spawn_ms(&f, &["groups", "rm", &g, "--force"]);
        assert!(f.server.wait_for_route(
            Route::ModelSecurity(Ms::GroupGet),
            1,
            Duration::from_secs(20)
        ));
        running.send_signal("INT");
        let out = running.wait();
        out.assert_code(130);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; the delete request was accepted; its result was not verified\n\n"
        );
        assert_eq!(f.server.ms_requests(Ms::GroupDelete).len(), 1);
    }

    /// A signal before the write (the read of `labels set` hangs): nothing was changed.
    #[test]
    fn a_signal_before_the_write_changes_nothing() {
        let f = fx();
        f.server
            .push_once(Route::ModelSecurity(Ms::ScanGet), Planned::hang());
        let running = spawn_ms(
            &f,
            &[
                "labels",
                "set",
                &u(401),
                "--labels",
                &labels_json(&[("a", "b")]),
                "--force",
            ],
        );
        assert!(f.server.wait_for_route(
            Route::ModelSecurity(Ms::ScanGet),
            1,
            Duration::from_secs(20)
        ));
        running.send_signal("TERM");
        let out = running.wait();
        out.assert_code(143);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; nothing was changed\n\n"
        );
        assert!(f.writes().is_empty());
    }
}
