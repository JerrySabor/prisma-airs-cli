//! Executable acceptance tests for the M6e chunk-1 gateway reads (DESIGN §19.1–§19.8):
//! `gateway workspaces list|get`, `gateway scopes list|get` and every `gateway telemetry`
//! read.
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server with the
//! seeded gateway dataset (`FixtureServer::seed_gateway`). The runner's leak check forbids
//! every `FAKE-GW-SECRET-*` marker on every stream and in the debug log of each run (DESIGN
//! §10 M6e). The chunk-1 cases of the TypeScript `tests/unit/cli/aigateway-command-tree.spec.ts`,
//! `aigateway-renderer.spec.ts`, `tests/unit/airs/aigateway.spec.ts` (reads, name
//! resolution, cost, the grant hint), `aigateway-chart-filters.spec.ts` and
//! `tests/integration/sdk-gateway-{telemetry,chart-flags,group-flags}.spec.ts` are ported
//! here (§19.19), adjusted by the §12 rows.

use std::time::Duration;

use airs_test_harness::fixtures::gateway as fx;
use airs_test_harness::{
    Cli, FixtureConfig, FixtureServer, GatewayData, Gw, Planned, RecordedRequest, Route, Run,
    RunOptions, Sandbox, debug_log, run, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — AI Gateway\n  Gateway workspace operations\n\n";
const DATA_PLANE_NOTE: &str = "  Data-plane list shows only active workspaces you are scoped to — use --plane admin or --all for the whole tenant.\n";
const WORKSPACES: &str = "GET /ai_gw/v2/workspaces";
const ADMIN_WORKSPACES: &str = "GET /ai_gw/admin/v2/workspaces";
const ARCHIVED_WORKSPACES: &str = "GET /ai_gw/admin/v2/workspaces?status=archived";
/// The pinned window and its query (UTC, seconds; G41).
const WINDOW: [&str; 4] = [
    "--start",
    "2026-10-01T00:00:00Z",
    "--end",
    "2026-10-02T00:00:00Z",
];
const WINDOW_QUERY: &str = "organisationId=100&workspaceSlug=ws-main-a-349e0e&timeOfGenerationMin=2026-10-01T00%3A00%3A00%2B00%3A00&timeOfGenerationMax=2026-10-02T00%3A00%3A00%2B00%3A00";
const WORKSPACE_HINT: &str = "  ⚠ 403: the service account is missing a workspace-scope grant (data plane, /ai_gw/v2). SCM Access Management edits the existing role row by default — use \"Add Role\" so the account ends up with both role rows, not one row moved.\n";
const ADMIN_HINT: &str = "  ⚠ 403: the service account is missing a tenant-root admin grant (admin plane, /ai_gw/admin/v2). SCM Access Management edits the existing role row by default — use \"Add Role\" so the account ends up with both role rows, not one row moved.\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seeded gateway dataset and one standard tenant `prod` (TSG 100).
fn fx() -> Fx {
    fx_with(|_| {})
}

fn fx_with(edit: impl FnOnce(&mut FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    server.seed_gateway();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

impl Fx {
    fn run_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let before = self.sandbox.snapshot();
        let out = run(&rust(), &self.sandbox, args, options);
        self.sandbox.assert_unchanged(&before);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.cwd_listing().is_empty(), "wrote into cwd");
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        out
    }

    /// `gateway <args>`, with the read-only and loopback checks.
    fn gw(&self, args: &[&str]) -> Run {
        self.gw_with(args, &RunOptions::new())
    }

    fn gw_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let mut full = vec!["gateway"];
        full.extend_from_slice(args);
        self.run_with(&full, options)
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

    fn clear(&self) {
        self.server.clear_requests();
    }

    fn data(&self, edit: impl FnOnce(&mut GatewayData)) {
        self.server.gateway(edit);
    }
}

fn windowed<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut all = args.to_vec();
    all.extend_from_slice(&WINDOW);
    all
}

fn ids(value: &Value, key: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row[key].as_str().unwrap_or_default().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// The command tree (TS aigateway-command-tree.spec.ts, chunk 1)
// ---------------------------------------------------------------------------

mod tree {
    use super::*;

    fn commands(help: &str) -> Vec<String> {
        help.lines()
            .skip_while(|line| *line != "Commands:")
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .filter_map(|line| line.split_whitespace().next())
            .filter(|name| *name != "help")
            .map(str::to_owned)
            .collect()
    }

    /// The groups, alphabetically; `workspace` is an alias of `workspaces`; the
    /// root lists `gateway` and no `aigateway` (D227).
    #[test]
    fn groups_and_leaves_are_registered_in_typescript_order() {
        let f = fx();
        let help = f.gw(&["--help"]).stdout;
        assert_eq!(
            commands(&help),
            [
                "admin-guardrails",
                "api-keys",
                "audit-logs",
                "configs",
                "deployments",
                "guardrails",
                "inference",
                "integrations",
                "mcp",
                "organisations",
                "plugins",
                "providers",
                "report",
                "scopes",
                "telemetry",
                "workspaces"
            ],
            "chunk 2 adds the inventory groups (tests/gateway_inventory.rs)"
        );
        assert!(help.contains("Manage and observe Prisma AIRS AI Gateway resources"));
        assert!(help.contains("[aliases: workspace]"));
        assert_eq!(
            commands(&f.gw(&["scopes", "--help"]).stdout),
            ["bind", "create", "delete", "get", "list"],
            "chunk 3 adds the scope writes (tests/gateway_writes.rs)"
        );
        assert_eq!(
            commands(&f.gw(&["workspace", "--help"]).stdout),
            ["archive", "create", "get", "list", "update"]
        );
        assert_eq!(
            commands(&f.gw(&["telemetry", "--help"]).stdout),
            [
                "cache",
                "cost",
                "error-category-trends",
                "error-trends",
                "errors",
                "feedback",
                "filter-boundaries",
                "group-by",
                "grouped-errors",
                "latency",
                "logs",
                "requests",
                "rescued-retries",
                "tokens",
                "user-trends",
                "users",
            ]
        );
        assert_eq!(
            commands(&f.gw(&["telemetry", "cache", "--help"]).stdout),
            ["summary", "trend"]
        );
        assert_eq!(
            commands(&f.gw(&["telemetry", "feedback", "--help"]).stdout),
            ["distribution", "models", "trend", "weighted"]
        );
        assert_eq!(
            commands(&f.gw(&["telemetry", "logs", "--help"]).stdout),
            ["list"]
        );
        let root = f.run_with(&["--help"], &RunOptions::new()).stdout;
        assert!(
            root.contains(
                "  gateway         Manage and observe Prisma AIRS AI Gateway resources\n"
            ),
            "{root}"
        );
        assert!(!root.contains("aigateway"));
        assert!(f.server.requests().is_empty());
    }

    /// Every leaf's `--output` help comes from the format policy (§19.2: pretty, table,
    /// json) and the list leaves carry `ls`.
    #[test]
    fn leaves_offer_three_formats_and_list_aliases() {
        let f = fx();
        for path in [
            &["workspaces", "list"][..],
            &["scopes", "get"],
            &["telemetry", "cost"],
            &["telemetry", "logs", "list"],
        ] {
            let mut args = path.to_vec();
            args.push("--help");
            let help = f.gw(&args).stdout;
            assert!(
                help.contains("Output format: pretty, table, json"),
                "{path:?}: {help}"
            );
        }
        for group in [&["workspaces"][..], &["scopes"], &["telemetry", "logs"]] {
            let mut args = group.to_vec();
            args.push("--help");
            assert!(f.gw(&args).stdout.contains("[aliases: ls]"), "{group:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// workspaces (§19.5; TS aigateway.spec.ts, aigateway-renderer.spec.ts)
// ---------------------------------------------------------------------------

mod workspaces {
    use super::*;

    /// The data-plane list: the TS bytes, the status line on stderr in every format
    /// (choice 8), one read with the tenant's `x-tsg-id`.
    #[test]
    fn list_reads_the_data_plane_with_the_typescript_layout() {
        let f = fx();
        let out = f.gw(&["workspaces", "list"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  AI Gateway Workspaces:\n\n  {}\n    Main A  ws-main-a-349e0e  active  default\n    scope: main_airs_workspace_1852583913\n\n",
                fx::uuid(1)
            )
        );
        assert_eq!(out.stderr, DATA_PLANE_NOTE);
        assert_eq!(f.api(), [WORKSPACES]);
        for request in f.server.requests() {
            if request.route != Route::Token {
                assert_eq!(request.header("x-tsg-id"), Some(TSG), "{}", request.line());
            }
        }
        for format in ["table", "json"] {
            let out = f.gw(&["workspaces", "ls", "--output", format]);
            assert_eq!(out.stderr, DATA_PLANE_NOTE, "{format}");
        }
        let out = f.gw(&["--quiet", "workspaces", "list"]);
        assert_eq!(
            out.stdout,
            format!(
                "  {}\n    Main A  ws-main-a-349e0e  active  default\n    scope: main_airs_workspace_1852583913\n\n",
                fx::uuid(1)
            ),
            "--quiet keeps every data line (D230)"
        );
        assert_eq!(out.stderr, "");
    }

    /// TS `aigateway.spec.ts`: the plane and status pass through; `--all` merges admin
    /// active and archived, read one after the other (choice 15); `is_default` 0 is false.
    #[test]
    fn planes_statuses_and_all() {
        let f = fx();
        let out = f.gw(&["workspaces", "list", "--plane", "admin", "--output", "json"]);
        out.assert_success();
        assert_eq!(f.api(), [ADMIN_WORKSPACES]);
        assert_eq!(ids(&out.json(), "id"), [fx::uuid(1), fx::uuid(2)]);
        assert_eq!(out.json()[1]["isDefault"], false);
        assert_eq!(out.stderr, "", "no data-plane note for the admin plane");
        f.clear();
        let out = f.gw(&[
            "workspaces",
            "list",
            "--plane",
            "admin",
            "--status",
            "archived",
            "--output",
            "json",
        ]);
        assert_eq!(f.api(), [ARCHIVED_WORKSPACES]);
        assert_eq!(
            out.json(),
            json!([{
                "id": fx::uuid(3),
                "slug": "ws-old-aaaaaa",
                "name": "Old",
                "status": "archived",
                "isDefault": false,
                "scopeName": "ws_old_aaaaaa"
            }])
        );
        f.clear();
        let out = f.gw(&[
            "workspaces",
            "list",
            "--status",
            "active",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(f.api(), ["GET /ai_gw/v2/workspaces?status=active"]);
        f.clear();
        let out = f.gw(&["workspaces", "list", "--all", "--output", "json"]);
        out.assert_success();
        assert_eq!(f.api(), [ADMIN_WORKSPACES, ARCHIVED_WORKSPACES]);
        assert_eq!(
            ids(&out.json(), "id"),
            [fx::uuid(1), fx::uuid(2), fx::uuid(3)]
        );
        assert_eq!(out.stderr, "");
        let out = f.gw(&["workspaces", "list", "--all", "--output", "table"]);
        assert_eq!(
            out.stdout.lines().next().unwrap(),
            " ID                                   │ Slug             │ Name       │ Status   │ Default │ Scope                          "
        );
    }

    /// D231: an empty list prints the phrase in pretty, `[]` in json and nothing in table.
    #[test]
    fn an_empty_list_in_every_format() {
        let f = fx();
        f.data(|data| data.data_plane.clear());
        assert_eq!(
            f.gw(&["workspaces", "list"]).stdout,
            format!("{BANNER}  No workspaces found\n")
        );
        assert_eq!(
            f.gw(&["workspaces", "list", "--output", "json"]).stdout,
            "[]\n"
        );
        assert_eq!(
            f.gw(&["workspaces", "list", "--output", "table"]).stdout,
            ""
        );
    }

    /// D248 (G39): a `total` other than the rows, or `has_more`, is a stderr warning; the
    /// rows print and the run succeeds.
    #[test]
    fn an_incomplete_list_warns() {
        let f = fx();
        f.data(|data| data.has_more = Some(true));
        let out = f.gw(&["workspaces", "list", "--plane", "admin", "--output", "json"]);
        out.assert_success();
        assert_eq!(out.json().as_array().unwrap().len(), 2);
        assert_eq!(
            out.stderr,
            "  ⚠ The service returned 2 of more than 2 workspaces; the list is incomplete (the API offers no continuation)\n"
        );
        f.data(|data| {
            data.has_more = None;
            data.list_total = Some(json!(4));
        });
        let out = f.gw(&["--quiet", "workspaces", "list", "--all", "--output", "json"]);
        assert_eq!(
            out.stderr,
            "  ⚠ The service returned 2 of 4 workspaces; the list is incomplete (the API offers no continuation)\n  ⚠ The service returned 1 of 4 workspaces; the list is incomplete (the API offers no continuation)\n",
            "warnings survive --quiet"
        );
        f.data(|data| data.list_total = Some(json!(2.5)));
        let out = f.gw(&["workspaces", "list", "--plane", "admin", "--output", "json"]);
        assert_eq!(out.stderr, "", "a total that is not a count says nothing");
    }

    /// The detail: TS bytes with every settings block, the table of the projection (D231),
    /// the json projection (TS `normalizeWorkspaceDetail`).
    #[test]
    fn get_prints_the_detail_in_every_format() {
        let f = fx();
        let out = f.gw(&["workspaces", "get", "ws-main-a-349e0e"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Workspace Detail:\n\n  ID           {}\n  Slug         ws-main-a-349e0e\n  Name         Main A\n  Status       active\n  Default      yes\n  Description  Default workspace\n  Created      {at}\n  Updated      {at}\n\n  Defaults:\n\n{{\n  \"config_id\": \"cfg-1\",\n  \"metadata\": {{\n    \"env\": \"dev\"\n  }}\n}}\n\n  Usage Limits:\n\n[\n  {{\n    \"credit_limit\": 10000,\n    \"type\": \"cost\",\n    \"alert_threshold\": 80\n  }}\n]\n\n  Security Settings:\n\n  block_pii    true\n  log_prompts  false\n\n",
                fx::uuid(1),
                at = fx::AT
            )
        );
        assert_eq!(f.api(), ["GET /ai_gw/v2/workspaces/ws-main-a-349e0e"]);
        let out = f.gw(&["workspaces", "get", "ws-main-a-349e0e", "--output", "table"]);
        let lines: Vec<&str> = out.stdout.lines().collect();
        assert!(lines[0].starts_with(" Key                       │ Value"));
        assert!(
            lines.iter().any(|line| line.starts_with(" usageLimits               │ [{\"credit_limit\":10000,\"type\":\"cost\",\"alert_threshold\":80}] ")),
            "{}",
            out.stdout
        );
        assert_eq!(lines.len(), 2 + 15);
        let out = f.gw(&["workspaces", "get", &fx::uuid(1), "--output", "json"]);
        let json = out.json();
        assert_eq!(json["isDefault"], true);
        assert_eq!(json["rateLimits"], json!([]));
        assert!(
            json.get("scopeName").is_none(),
            "the detail has no scope_name"
        );
        assert!(out.stdout.starts_with("{\n  \"id\": "), "TS key order");
    }

    /// Choice 187 (the live run of `workspaces get` against a tenant): the workspace's API-key
    /// settings print as the service sends them, in json and table, as TypeScript prints them:
    /// a count, two lifetimes and an unset rotation period are no credential, though their
    /// names hold `api_key`.
    #[test]
    fn d238_workspace_api_key_settings_print_as_sent() {
        let f = fx();
        let out = f.gw(&["workspaces", "get", "ws-main-a-349e0e", "--output", "json"]);
        out.assert_success();
        assert_eq!(
            out.json()["settings"],
            json!({
                "y": 2,
                "user_api_key_auto_create": false,
                "user_api_key_count": 5,
                "user_api_key_max_ttl": 7_776_000,
                "user_api_key_ttl": 2_592_000,
                "user_api_key_rotation_period": "",
            })
        );
        assert!(!out.stdout.contains("[withheld]"), "{}", out.stdout);
        let table = f.gw(&["workspaces", "get", "ws-main-a-349e0e", "--output", "table"]);
        table.assert_success();
        assert!(
            table.stdout.contains("\"user_api_key_max_ttl\":7776000"),
            "{}",
            table.stdout
        );
        assert!(!table.stdout.contains("[withheld]"), "{}", table.stdout);
    }

    /// TS: a `null` status is `unknown`, never inactive; legacy one-object limits become an
    /// array and `null` limits `[]`.
    #[test]
    fn get_normalises_status_and_limits() {
        let f = fx();
        let out = f.gw(&["workspaces", "get", "ws-produc-985697", "--plane", "admin"]);
        out.assert_success();
        assert!(out.stdout.contains("  Status   unknown\n"));
        assert!(!out.stdout.to_lowercase().contains("inactive"));
        assert_eq!(f.api(), ["GET /ai_gw/admin/v2/workspaces/ws-produc-985697"]);
        let out = f.gw(&[
            "workspaces",
            "get",
            "ws-produc-985697",
            "--plane",
            "admin",
            "--output",
            "json",
        ]);
        let json = out.json();
        assert_eq!(json["status"], Value::Null);
        assert_eq!(
            json["usageLimits"],
            json!([{"credit_limit": 5, "type": "cost"}])
        );
        assert_eq!(json["defaults"], Value::Null);
        let out = f.gw(&["workspaces", "get", "ws-old-aaaaaa", "--plane", "admin"]);
        out.assert_code(1);
        assert!(out.stderr.contains("HTTP 404"));
    }

    /// TS `aigateway.spec.ts` "get retries once with a resolved ref after a 404": a display
    /// name is read by its slug from the requested plane's list (choice 14); several
    /// matches are TS's ambiguity error; no match is the original 404; a failing list is
    /// its own error.
    #[test]
    fn get_resolves_a_name_after_a_404() {
        let f = fx();
        let out = f.gw(&[
            "workspaces",
            "get",
            "Production",
            "--plane",
            "admin",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(out.json()["id"], fx::uuid(2));
        assert_eq!(
            f.api(),
            [
                "GET /ai_gw/admin/v2/workspaces/Production",
                ADMIN_WORKSPACES,
                "GET /ai_gw/admin/v2/workspaces/ws-produc-985697"
            ]
        );
        f.clear();
        let out = f.gw(&["workspaces", "get", "Nothing"]);
        out.assert_code(1);
        assert_eq!(f.api(), ["GET /ai_gw/v2/workspaces/Nothing", WORKSPACES]);
        assert!(
            out.stderr.contains("API error 404 (errorCode: AB08)"),
            "{}",
            out.stderr
        );
        f.data(|data| {
            let mut twin = data.workspaces[1].clone();
            twin["id"] = json!(fx::uuid(9));
            twin["slug"] = json!("ws-produc-111111");
            data.workspaces.push(twin);
        });
        let out = f.gw(&["workspaces", "get", "Production", "--plane", "admin"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: workspace name 'Production' is ambiguous (ws-produc-985697, ws-produc-111111) — use a slug or UUID\n\n"
        );
        f.clear();
        f.server.set_default(
            Route::Gateway(Gw::DataWorkspaces),
            Planned::json(400, &json!({"message": "no"})),
        );
        let out = f.gw(&["workspaces", "get", "Main"]);
        out.assert_code(1);
        assert!(out.stderr.contains("HTTP 400"), "{}", out.stderr);
    }

    /// D254: after a 404, an incomplete list (`has_more`) resolves no display name: the
    /// visible row may not be the only one with it.
    #[test]
    fn d254_get_resolves_no_name_on_an_incomplete_list() {
        let f = fx();
        f.data(|data| data.has_more = Some(true));
        let out = f.gw(&["workspaces", "get", "Production", "--plane", "admin"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Workspace 'Production' cannot be resolved: the workspace list is incomplete (the API offers no continuation); use the workspace slug or UUID\n\n"
        );
        assert_eq!(
            f.api(),
            [
                "GET /ai_gw/admin/v2/workspaces/Production",
                ADMIN_WORKSPACES
            ]
        );
    }
}

// ---------------------------------------------------------------------------
// scopes (§19.7)
// ---------------------------------------------------------------------------

mod scopes {
    use super::*;

    /// TS `aigateway.spec.ts` "listScopes normalizes items and flags unbound scopes" and
    /// the renderer spec: bindings as `type:id`, the unbound marker, `[]` when empty.
    #[test]
    fn list_in_every_format() {
        let f = fx();
        let out = f.gw(&["scopes", "list"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  IAM Scopes:\n\n    main_airs_workspace_1852583913  workspace:ws-main-a-349e0e\n    Main workspace scope\n\n    ws_production_bx7qw0  workspace:ws-produc-985697\n    All production applications\n\n    ws_orphan_zzzzzz  unbound\n    Left over\n\n"
            )
        );
        assert_eq!(f.api(), ["GET /iam/scopes"]);
        assert_eq!(
            f.server.requests()[1].header("x-tsg-id"),
            Some(TSG),
            "IAM requests carry x-tsg-id too (TS)"
        );
        let out = f.gw(&["scopes", "ls", "--output", "json"]);
        assert_eq!(
            out.json()[0],
            json!({
                "name": "main_airs_workspace_1852583913",
                "description": "Main workspace scope",
                "resources": "workspace:ws-main-a-349e0e",
                "tsgId": "100"
            })
        );
        assert_eq!(out.json()[2]["resources"], "");
        let out = f.gw(&["scopes", "list", "--output", "table"]);
        assert_eq!(
            out.stdout.lines().next().unwrap(),
            " Name                           │ Description                 │ Bound resources            │ TSG "
        );
        f.data(|data| data.scopes.clear());
        assert_eq!(
            f.gw(&["scopes", "list"]).stdout,
            format!("{BANNER}  No IAM scopes found\n")
        );
        assert_eq!(f.gw(&["scopes", "list", "--output", "json"]).stdout, "[]\n");
        assert_eq!(f.gw(&["scopes", "list", "--output", "table"]).stdout, "");
        f.data(|data| {
            data.scopes = fx::scopes();
            data.scope_count = Some(json!(5));
        });
        let out = f.gw(&["scopes", "list", "--output", "json"]);
        assert_eq!(
            out.stderr,
            "  ⚠ The service returned 3 of 5 IAM scopes; the list is incomplete (the API offers no continuation)\n"
        );
    }

    /// The detail: TS bytes (`(none)` for an empty description, `none — unbound`), json
    /// with the resource array, the table of the record (D231).
    #[test]
    fn get_in_every_format() {
        let f = fx();
        let out = f.gw(&["scopes", "get", "ws_orphan_zzzzzz"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  IAM Scope:\n\n  Name             ws_orphan_zzzzzz\n  Description      Left over\n  TSG              100\n  ID               ws_orphan_zzzzzz:100\n  Bound resources  none — unbound\n\n"
            )
        );
        assert_eq!(f.api(), ["GET /iam/scopes/ws_orphan_zzzzzz"]);
        let out = f.gw(&[
            "scopes",
            "get",
            "main_airs_workspace_1852583913",
            "--output",
            "json",
        ]);
        assert_eq!(
            out.json(),
            json!({
                "name": "main_airs_workspace_1852583913",
                "description": "Main workspace scope",
                "resources": [{"resourceType": "workspace", "resourceId": "ws-main-a-349e0e"}],
                "tsgId": "100",
                "id": "main_airs_workspace_1852583913:100"
            })
        );
        let out = f.gw(&["scopes", "get", "ws_production_bx7qw0", "--output", "table"]);
        assert!(out.stdout.contains(
            " resources   │ [{\"resourceType\":\"workspace\",\"resourceId\":\"ws-produc-985697\"}] "
        ));
        f.data(|data| data.scopes[2]["description"] = json!(""));
        let out = f.gw(&["scopes", "get", "ws_orphan_zzzzzz"]);
        assert!(out.stdout.contains("  Description      (none)\n"));
        let out = f.gw(&["scopes", "get", "no_such_scope"]);
        out.assert_code(1);
        assert!(out.stderr.contains("HTTP 404"));
    }
}

// ---------------------------------------------------------------------------
// telemetry (§19.8)
// ---------------------------------------------------------------------------

mod telemetry {
    use super::*;

    /// Every leaf resolves `--workspace` (D235) and then sends one data-plane read with
    /// TS's path and the window in TS key order, in UTC (G41).
    #[test]
    fn every_leaf_resolves_then_reads_its_route() {
        let f = fx();
        for (leaf, path) in [
            (&["errors"][..], "/logs/charts/errors"),
            (&["users"], "/logs/charts/users"),
            (&["error-trends"], "/logs/charts/error-trends"),
            (
                &["error-category-trends"],
                "/logs/charts/error-category-trends",
            ),
            (&["grouped-errors"], "/logs/charts/grouped-errors"),
            (&["rescued-retries"], "/logs/charts/rescued-retries"),
            (&["user-trends"], "/logs/charts/user-trends"),
            (&["cache", "summary"], "/logs/charts/cache-summary"),
            (&["cache", "trend"], "/logs/charts/cache-hit-trend"),
            (
                &["feedback", "distribution"],
                "/logs/charts/feedback-score-distribution",
            ),
            (&["feedback", "models"], "/logs/charts/feedback-models"),
            (&["feedback", "trend"], "/logs/charts/feedback-trend"),
            (&["feedback", "weighted"], "/logs/charts/feedback-weighted"),
            (&["latency"], "/logs/charts/latency"),
            (&["requests"], "/logs/charts/requests"),
            (&["tokens"], "/logs/charts/tokens"),
            (&["group-by", "ai_service"], "/logs/groups/ai_service"),
            (&["group-by", "model"], "/logs/groups/model"),
            (&["group-by", "api_key"], "/logs/groups/api_key"),
            (&["group-by", "provider"], "/logs/groups/provider"),
            (&["group-by", "status_code"], "/logs/groups/status_code"),
            (&["group-by", "users"], "/logs/groups/users"),
        ] {
            f.clear();
            let mut args = vec!["telemetry"];
            args.extend_from_slice(leaf);
            args.extend(["--workspace", "Main A", "--output", "json"]);
            let out = f.gw(&windowed(&args));
            out.assert_success();
            assert_eq!(
                f.api(),
                [
                    WORKSPACES.to_owned(),
                    ADMIN_WORKSPACES.to_owned(),
                    ARCHIVED_WORKSPACES.to_owned(),
                    format!("GET /ai_gw/v2{path}?{WINDOW_QUERY}")
                ],
                "a name reads every list first (choice 127): {leaf:?}"
            );
        }
        f.clear();
        let out = f.gw(&windowed(&[
            "telemetry",
            "filter-boundaries",
            "--workspace",
            "ws-main-a-349e0e",
        ]));
        out.assert_success();
        assert_eq!(
            f.api()[1],
            "GET /ai_gw/v2/analytics/filter-boundaries?workspaceSlug=ws-main-a-349e0e&timeOfGenerationMin=2026-10-01T00%3A00%3A00%2B00%3A00&timeOfGenerationMax=2026-10-02T00%3A00%3A00%2B00%3A00",
            "no organisationId (TS)"
        );
    }

    /// The envelope's `Field │ Value` table (choice 9) and the json envelope.
    #[test]
    fn reads_print_the_envelope() {
        let f = fx();
        let out = f.gw(&windowed(&[
            "telemetry",
            "errors",
            "--workspace",
            "ws-main-a-349e0e",
        ]));
        assert_eq!(
            out.stdout,
            " Field   │ Value                                                                                               \n─────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────\n success │ true                                                                                                \n data    │ {\"records\":[{\"x\":\"2026-09-30\",\"y\":42},{\"x\":\"2026-10-01\",\"y\":7}],\"total\":49,\"isQuotaExceeded\":false} \n"
        );
        assert_eq!(out.stderr, "");
        let out = f.gw(&windowed(&[
            "telemetry",
            "group-by",
            "model",
            "--workspace",
            "ws-main-a-349e0e",
            "--output",
            "table",
        ]));
        let fields: Vec<&str> = out
            .stdout
            .lines()
            .skip(2)
            .map(|line| line.split('│').next().unwrap().trim())
            .collect();
        assert_eq!(fields, ["object", "is_quota_exceeded", "total", "data"]);
        let out = f.gw(&windowed(&[
            "telemetry",
            "users",
            "--workspace",
            "ws-main-a-349e0e",
            "--output",
            "json",
        ]));
        assert_eq!(out.json()["data"]["total"], 49);
    }

    /// The default window is the 7 days before the time of the check; `--days`, `--end`
    /// alone and seconds truncation (G41).
    #[test]
    fn windows() {
        let f = fx();
        let span = |f: &Fx| {
            let request = f
                .server
                .requests()
                .into_iter()
                .find(|request| request.path.contains("/logs/charts/"))
                .unwrap();
            let value = |key: &str| {
                request
                    .query
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.clone())
                    .unwrap()
            };
            (value("timeOfGenerationMin"), value("timeOfGenerationMax"))
        };
        let out = f.gw(&["telemetry", "errors", "--workspace", "ws-main-a-349e0e"]);
        out.assert_success();
        let (min, max) = span(&f);
        assert!(min.ends_with("+00:00") && max.ends_with("+00:00"));
        assert_eq!(min[11..], max[11..], "seven whole days: {min} {max}");
        f.clear();
        f.gw(&[
            "telemetry",
            "errors",
            "--workspace",
            "ws-main-a-349e0e",
            "--days",
            "2",
            "--end",
            "2026-10-03T10:20:30.999+02:00",
        ])
        .assert_success();
        assert_eq!(
            span(&f),
            (
                "2026-10-01T08:20:30+00:00".to_owned(),
                "2026-10-03T08:20:30+00:00".to_owned()
            )
        );
    }

    /// `cost`: the TS record (cents from the API, dollars by `toFixed(2)`, choice 11) in
    /// every format, the 7-day default (TS spec "defaults days to 7").
    #[test]
    fn cost_in_every_format() {
        let f = fx();
        let out = f.gw(&["telemetry", "cost", "--workspace", "ws-main-a-349e0e"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Cost — ws-main-a-349e0e (last 7d):\n\n  Total          $12.39\n  Daily average  $6.20\n\n  Per day:\n\n  2026-09-30  $12.34\n  2026-10-01  $0.05\n\n"
            )
        );
        let out = f.gw(&[
            "telemetry",
            "cost",
            "--workspace",
            "ws-main-a-349e0e",
            "--output",
            "json",
        ]);
        assert_eq!(
            out.json(),
            json!({
                "workspaceSlug": "ws-main-a-349e0e",
                "days": 7,
                "totalCents": 1239,
                "totalUsd": 12.39,
                "avgCents": 619.5,
                "avgUsd": 6.195,
                "quotaExceeded": false,
                "records": [
                    {"date": "2026-09-30", "costCents": 1234, "costUsd": 12.34},
                    {"date": "2026-10-01", "costCents": 5, "costUsd": 0.05}
                ]
            })
        );
        let out = f.gw(&[
            "telemetry",
            "cost",
            "--workspace",
            "ws-main-a-349e0e",
            "--output",
            "table",
        ]);
        assert!(out.stdout.starts_with(" Key           │ Value"));
        f.data(|data| {
            data.charts.get_mut("cost").unwrap()["data"] = json!({
                "records": [],
                "total": 12.5,
                "avg": 0.125,
                "isQuotaExceeded": true
            });
        });
        let out = f.gw(&["telemetry", "cost", "--workspace", "ws-main-a-349e0e"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Cost — ws-main-a-349e0e (last 7d):\n\n  Total          $0.13\n  Daily average  $0.00\n\n"
            )
        );
        assert_eq!(
            out.stderr,
            "  ⚠ Telemetry quota exceeded — data may be truncated\n"
        );
    }

    /// TS `aigateway.spec.ts` "telemetry cost resolves a display name to the slug" and the
    /// chart-flags spec "resolves a cost workspace UUID": a name or UUID becomes the slug;
    /// an archived workspace is found on the third list (choice 13).
    #[test]
    fn resolution_over_three_lists() {
        let f = fx();
        // An exact id or slug stops at its list; a display name is matched only after
        // every list was read for an exact reference (choice 127).
        for (reference, slug, lists) in [
            ("Main A", "ws-main-a-349e0e", 3),
            (fx::uuid(1).as_str(), "ws-main-a-349e0e", 1),
            ("ws-main-a-349e0e", "ws-main-a-349e0e", 1),
            ("Production", "ws-produc-985697", 3),
            ("ws-produc-985697", "ws-produc-985697", 2),
            ("Old", "ws-old-aaaaaa", 3),
        ] {
            f.clear();
            let out = f.gw(&[
                "telemetry",
                "cost",
                "--workspace",
                reference,
                "--output",
                "json",
            ]);
            out.assert_success();
            assert_eq!(out.json()["workspaceSlug"], slug);
            let api = f.api();
            assert_eq!(
                api[..lists],
                [WORKSPACES, ADMIN_WORKSPACES, ARCHIVED_WORKSPACES][..lists],
                "{reference}"
            );
            assert!(api[lists].contains(&format!("workspaceSlug={slug}&")));
        }
        f.data(|data| {
            let mut twin = data.workspaces[0].clone();
            twin["id"] = json!(fx::uuid(8));
            twin["slug"] = json!("ws-main-b-000000");
            data.workspaces.push(twin);
            data.data_plane.insert(fx::uuid(8));
        });
        f.clear();
        let out = f.gw(&["telemetry", "errors", "--workspace", "Main A"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: workspace name 'Main A' is ambiguous (ws-main-a-349e0e, ws-main-b-000000) — use a slug or UUID\n\n"
        );
        assert_eq!(f.api(), [WORKSPACES, ADMIN_WORKSPACES, ARCHIVED_WORKSPACES]);
        f.clear();
        let out = f.gw(&["telemetry", "requests", "--workspace", "Nowhere"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Workspace 'Nowhere' was not found on the data and admin planes; nothing was sent\n\n"
        );
        assert_eq!(f.api(), [WORKSPACES, ADMIN_WORKSPACES, ARCHIVED_WORKSPACES]);
        // Choice 127: a data-plane workspace whose display name is an admin-only
        // workspace's exact slug does not shadow that slug.
        f.data(|data| {
            let mut shadow = data.workspaces[0].clone();
            shadow["id"] = json!(fx::uuid(10));
            shadow["slug"] = json!("ws-shadow-000000");
            shadow["name"] = json!("ws-produc-985697");
            data.workspaces.push(shadow);
            data.data_plane.insert(fx::uuid(10));
        });
        f.clear();
        let out = f.gw(&[
            "telemetry",
            "cost",
            "--workspace",
            "ws-produc-985697",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(out.json()["workspaceSlug"], "ws-produc-985697");
        assert_eq!(f.api()[..2], [WORKSPACES, ADMIN_WORKSPACES]);
        assert!(f.api()[2].contains("workspaceSlug=ws-produc-985697&"));
        // A name, once every list was read, still resolves on the first list carrying it.
        f.clear();
        let out = f.gw(&[
            "telemetry",
            "cost",
            "--workspace",
            "ws-shadow-000000",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(out.json()["workspaceSlug"], "ws-shadow-000000");
    }

    /// The chart-flags spec: every filter maps to TS's query key in TS order, zero and
    /// fractional cents kept, `group-by --columns` trimmed and comma-joined.
    #[test]
    fn filters_reach_the_query_in_typescript_order() {
        let f = fx();
        let filters = [
            "--trace-id",
            "owned",
            "--metadata",
            r#"{"environment":"dev"}"#,
            "--status-codes",
            "200,446",
            "--api-key-ids",
            "11111111-1111-4111-8111-111111111111",
            "--ai-org-models",
            "openai__gpt-5.6-terra",
            "--total-units-min",
            "0",
            "--total-units-max",
            "42",
            "--cost-min",
            "0",
            "--cost-max",
            "0.125",
        ];
        let tail = "traceId=owned&metadata=%7B%22environment%22%3A%22dev%22%7D&statusCode=200%2C446&apiKeyIds=11111111-1111-4111-8111-111111111111&aiOrgModel=openai__gpt-5.6-terra&totalUnitsMin=0&totalUnitsMax=42&costMin=0&costMax=0.125";
        for metric in ["requests", "tokens", "latency"] {
            f.clear();
            let mut args = vec!["telemetry", metric, "--workspace", "ws-main-a-349e0e"];
            args.extend_from_slice(&filters);
            f.gw(&windowed(&args)).assert_success();
            assert_eq!(
                f.api()[1],
                format!("GET /ai_gw/v2/logs/charts/{metric}?{WINDOW_QUERY}&{tail}")
            );
        }
        f.clear();
        let mut args = vec![
            "telemetry",
            "group-by",
            "provider",
            "--workspace",
            "ws-main-a-349e0e",
            "--columns",
            "cost, total_tokens",
        ];
        args.extend_from_slice(&filters);
        f.gw(&windowed(&args)).assert_success();
        assert_eq!(
            f.api()[1],
            format!(
                "GET /ai_gw/v2/logs/groups/provider?{WINDOW_QUERY}&{tail}&columns=cost%2Ctotal_tokens"
            )
        );
        f.clear();
        f.gw(&windowed(&[
            "telemetry",
            "group-by",
            "users",
            "--workspace",
            "ws-main-a-349e0e",
            "--cost-min",
            "2e1",
        ]))
        .assert_success();
        assert_eq!(
            f.api()[1],
            format!("GET /ai_gw/v2/logs/groups/users?{WINDOW_QUERY}&costMin=20")
        );
    }

    /// `logs list`: the TS paging query, one page, and the status line when the total says
    /// more pages exist (choice 64); the quota warning (choice 10).
    #[test]
    fn logs_list_pages() {
        let f = fx();
        let out = f.gw(&windowed(&[
            "telemetry",
            "logs",
            "list",
            "--workspace",
            "ws-main-a-349e0e",
            "--output",
            "json",
        ]));
        out.assert_success();
        assert_eq!(
            f.api()[1],
            format!("GET /ai_gw/v2/logs?{WINDOW_QUERY}&pageSize=50&currentPage=0")
        );
        assert_eq!(out.stderr, "");
        assert_eq!(out.json()["data"]["records"].as_array().unwrap().len(), 3);
        f.clear();
        f.data(|data| data.logs_quota = true);
        let out = f.gw(&windowed(&[
            "telemetry",
            "logs",
            "ls",
            "--workspace",
            "ws-main-a-349e0e",
            "--page-size",
            "1",
            "--current-page",
            "1",
            "--status-code",
            "446",
            "--trace-id",
            "trace-2",
            "--output",
            "json",
        ]));
        out.assert_success();
        assert_eq!(
            f.api()[1],
            format!(
                "GET /ai_gw/v2/logs?{WINDOW_QUERY}&pageSize=1&currentPage=1&traceId=trace-2&statusCode=446"
            )
        );
        assert_eq!(out.json()["data"]["records"][0]["id"], "log-2");
        assert_eq!(
            out.stderr,
            "  ⚠ Telemetry quota exceeded — data may be truncated\n  Returned 1 of 3 request logs (page 1, 1 per page); this is one page.\n"
        );
    }

    /// The withholding policy (D238, D251): `filter-boundaries` `data` whole (choice 18);
    /// a credential-named log member and a value it echoes elsewhere; URL userinfo, query
    /// and fragment. The runner's leak check forbids the markers everywhere.
    #[test]
    fn telemetry_documents_are_withheld() {
        let f = fx();
        f.data(|data| {
            data.filter_boundaries.as_mut().unwrap()["data"]["unique_api_keys"] =
                json!([fx::marker(4)]);
            data.logs[0]["client_secret"] = json!(fx::marker(5));
            data.logs[1]["prompt_slug"] = json!(format!("echo {}", fx::marker(5)));
            data.logs[2]["request_url"] = json!(format!(
                "https://u:{}@h.example/p?key={}",
                fx::marker(6),
                fx::marker(7)
            ));
        });
        for format in ["pretty", "table", "json"] {
            let out = f.gw(&windowed(&[
                "telemetry",
                "filter-boundaries",
                "--workspace",
                "ws-main-a-349e0e",
                "--output",
                format,
            ]));
            out.assert_success();
            assert!(out.stdout.contains("[withheld]"), "{format}");
            let out = f.gw(&windowed(&[
                "telemetry",
                "logs",
                "list",
                "--workspace",
                "ws-main-a-349e0e",
                "--output",
                format,
            ]));
            out.assert_success();
        }
        let out = f.gw(&windowed(&[
            "telemetry",
            "logs",
            "list",
            "--workspace",
            "ws-main-a-349e0e",
            "--output",
            "json",
        ]));
        let records = &out.json()["data"]["records"];
        assert_eq!(records[0]["client_secret"], "[withheld]");
        assert_eq!(records[1]["prompt_slug"], "[withheld]");
        assert_eq!(
            records[2]["request_url"],
            "https://[withheld]@h.example/p?[withheld]"
        );
        assert_eq!(
            records[0]["api_key_id"],
            fx::uuid(501),
            "ids are not credentials"
        );
    }
}

// ---------------------------------------------------------------------------
// Argument checks (§19.3 "Argument checks", D232)
// ---------------------------------------------------------------------------

mod checks {
    use super::*;

    /// Every chunk-1 argument check is a usage error before the tenant, with no request and
    /// no debug log (with `--debug`); the TS spec cases that must not reach a client.
    #[test]
    fn argument_errors_are_usage_errors_before_the_tenant() {
        let cases: Vec<(Vec<&str>, &str)> = vec![
            (
                vec!["workspaces", "list", "--plane", "bogus"],
                "Invalid --plane 'bogus'. Valid planes: data, admin",
            ),
            (
                vec!["workspaces", "list", "--status", "bogus"],
                "Invalid --status 'bogus'. Valid statuses: active, archived",
            ),
            (
                vec!["workspaces", "list", "--all", "--status", "active"],
                "--all already merges admin-plane active + archived; drop --plane/--status",
            ),
            (
                vec!["workspaces", "get", "bad ref!"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid workspaceRef: bad ref! (expected a workspace UUID or slug)",
            ),
            (
                vec!["scopes", "get", "bad/name"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid name: bad/name (expected an IAM scope name such as ws_production_bx7qw0)",
            ),
            (
                vec!["telemetry", "errors", "--workspace", ""],
                "--workspace cannot be empty",
            ),
            (
                vec!["telemetry", "cost", "--workspace", "w", "--days", "7junk"],
                "Invalid --days: Expected an integer",
            ),
            (
                vec!["telemetry", "cost", "--workspace", "w", "--days", "0"],
                "Invalid --days: Expected a positive integer",
            ),
            (
                vec![
                    "telemetry",
                    "cost",
                    "--workspace",
                    "w",
                    "--days",
                    "9007199254740992",
                ],
                "Invalid --days: Expected a safe integer",
            ),
            (
                vec![
                    "telemetry",
                    "requests",
                    "--workspace",
                    "w",
                    "--cost-min",
                    "1",
                    "--cost-max",
                    "0",
                ],
                "Invalid chart filters: check status codes, UUIDs, provider__model pairs, string metadata and inclusive nonnegative bounds",
            ),
            (
                vec![
                    "telemetry",
                    "tokens",
                    "--workspace",
                    "w",
                    "--status-codes",
                    "200,",
                ],
                "Invalid chart filters: check JSON, CSV and numeric flag syntax",
            ),
            (
                vec![
                    "telemetry",
                    "latency",
                    "--workspace",
                    "w",
                    "--metadata",
                    r#"{"sensitive":{"secret":"do-not-echo"}}"#,
                ],
                "Invalid chart filters: check status codes, UUIDs, provider__model pairs, string metadata and inclusive nonnegative bounds",
            ),
            (
                vec![
                    "telemetry",
                    "group-by",
                    "provider/../../secret",
                    "--workspace",
                    "w",
                ],
                "Invalid grouping dimension: choose from ai_service, model, api_key, provider, status_code, users",
            ),
            (
                vec![
                    "telemetry",
                    "group-by",
                    "model",
                    "--workspace",
                    "w",
                    "--columns",
                    "cost,",
                ],
                "Invalid --columns: choose from cost, avg_latency, avg_tokens, total_tokens, success_rate, last_seen",
            ),
            (
                vec![
                    "telemetry",
                    "group-by",
                    "users",
                    "--workspace",
                    "w",
                    "--columns",
                    "cost,total_tokens",
                ],
                "User grouping does not support --columns",
            ),
            (
                vec![
                    "telemetry",
                    "group-by",
                    "model",
                    "--workspace",
                    "w",
                    "--start",
                    "not-a-date",
                ],
                "Invalid --start: Expected an ISO-8601 timestamp",
            ),
            (
                vec![
                    "telemetry",
                    "errors",
                    "--workspace",
                    "w",
                    "--start",
                    "2026-10-02T00:00:00Z",
                    "--end",
                    "2026-10-01T00:00:00Z",
                ],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid telemetry query options or time window",
            ),
            (
                vec![
                    "telemetry",
                    "errors",
                    "--workspace",
                    "w",
                    "--days",
                    "3",
                    "--start",
                    "2026-10-01T00:00:00Z",
                ],
                "Use --days or --start/--end, not both",
            ),
            (
                vec![
                    "telemetry",
                    "logs",
                    "list",
                    "--workspace",
                    "w",
                    "--page-size",
                    "0",
                ],
                "Invalid --page-size: Expected a positive integer",
            ),
            (
                vec![
                    "telemetry",
                    "logs",
                    "list",
                    "--workspace",
                    "w",
                    "--current-page",
                    "1.5",
                ],
                "--current-page must be a nonnegative safe integer",
            ),
            (
                vec![
                    "telemetry",
                    "logs",
                    "list",
                    "--workspace",
                    "w",
                    "--status-code",
                    "0",
                ],
                "Invalid --status-code: Expected a positive integer",
            ),
            (
                vec![
                    "telemetry",
                    "logs",
                    "list",
                    "--workspace",
                    "w",
                    "--trace-id",
                    "a\u{1}b",
                ],
                "--trace-id must be at most 4096 bytes and contain no control characters",
            ),
            (
                vec!["scopes", "list", "--output", "yaml"],
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            ),
        ];
        // No tenant at all: the checks come first.
        let bare = Sandbox::new();
        for (args, message) in &cases {
            let f = fx();
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec!["--debug"];
            full.extend(args.iter().copied());
            let out = f.gw_with(&full, &RunOptions::new().env("XDG_STATE_HOME", &state));
            out.assert_code(2);
            assert_eq!(out.stdout, "", "{args:?}");
            assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
            assert!(!out.stderr.contains("do-not-echo"));
            assert!(f.server.requests().is_empty(), "{args:?}");
            assert!(
                debug_log::log_files(&debug_log::log_dir(&f.sandbox)).is_empty(),
                "{args:?}: no debug log"
            );
            let mut plain = vec!["gateway"];
            plain.extend(args.iter().copied());
            run(&rust(), &bare, &plain, &RunOptions::new()).assert_code(2);
        }
    }

    /// clap's own errors (D1): a missing `--workspace`, an unknown option, an excess
    /// argument.
    #[test]
    fn parse_errors_exit_2() {
        let f = fx();
        for args in [
            &["telemetry", "errors"][..],
            &[
                "telemetry",
                "cost",
                "--start",
                "2026-10-01T00:00:00Z",
                "--workspace",
                "w",
            ],
            &["scopes", "list", "extra"],
            &["workspaces", "bogus"],
        ] {
            let out = f.gw(args);
            out.assert_code(2);
            assert_eq!(out.stdout, "");
        }
        assert!(f.server.requests().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Configuration, credentials and failures (§19.3)
// ---------------------------------------------------------------------------

mod failures {
    use super::*;

    /// The §3.5 credential check before any client; endpoint admission names the key
    /// (D48); a token failure is the §6 OAuth message.
    #[test]
    fn configuration_and_token_errors_come_before_any_api_request() {
        let f = fx_with(|config| {
            config.remove("mgmtClientSecret");
        });
        let out = f.gw(&["scopes", "list"]);
        out.assert_code(1);
        assert!(
            out.stderr.contains("missing mgmtClientSecret"),
            "{}",
            out.stderr
        );
        assert!(f.server.requests().is_empty());
        for key in ["aiGwDataEndpoint", "aiGwAdminEndpoint", "iamEndpoint"] {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            let tenant = sandbox.add_fixture_tenant_allowing_external_endpoints(
                &server,
                "prod",
                TSG,
                |config| {
                    config.set(key, "http://gateway.example.test/x");
                },
            );
            sandbox.rust_only(&[&tenant], Some("prod"));
            let out = run(
                &rust(),
                &sandbox,
                &["gateway", "scopes", "list"],
                &RunOptions::new(),
            );
            out.assert_code(1);
            let rust_key = key.replace("aiGw", "gateway");
            assert!(
                out.stderr
                    .contains(&format!("Invalid {rust_key}: endpoints must use https")),
                "{}",
                out.stderr
            );
            assert!(!out.stderr.contains("example.test"));
            assert!(server.requests().is_empty());
        }
        let f = fx();
        f.server
            .push_once(Route::Token, Planned::json(401, &json!({"error": "nope"})));
        let out = f.gw(&["scopes", "list"]);
        out.assert_code(1);
        assert!(
            out.stderr
                .contains("AISEC_OAUTH_ERROR:Token request failed with status 401"),
            "{}",
            out.stderr
        );
        assert_eq!(f.api(), Vec::<String>::new());
    }

    /// G42, D234: the grant hint by service code and plane, on stderr before the error; no
    /// hint for IAM or a data-plane 403 with another code.
    #[test]
    fn the_grant_hint_follows_the_code_and_the_plane() {
        for (route, args, body, hint) in [
            (
                Gw::DataWorkspaces,
                &["workspaces", "list"][..],
                json!({"message": "x"}),
                Some(WORKSPACE_HINT),
            ),
            (
                Gw::DataWorkspaces,
                &["workspaces", "list"],
                json!({"errorCode": "AB01"}),
                None,
            ),
            (
                Gw::AdminWorkspaces,
                &["workspaces", "list", "--plane", "admin"],
                json!({"message": "x"}),
                Some(ADMIN_HINT),
            ),
            (
                Gw::AdminWorkspaces,
                &["workspaces", "list", "--plane", "admin"],
                json!({"data": {"errorCode": "AB03"}}),
                Some(WORKSPACE_HINT),
            ),
            (
                Gw::ScopeGet,
                &["scopes", "get", "ws_orphan_zzzzzz"],
                json!({"errorCode": "AB03"}),
                None,
            ),
            (
                Gw::Chart,
                &["telemetry", "errors", "--workspace", "ws-main-a-349e0e"],
                json!({"message": "x"}),
                Some(WORKSPACE_HINT),
            ),
        ] {
            let f = fx();
            f.server
                .set_default(Route::Gateway(route), Planned::json(403, &body));
            let out = f.gw(args);
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            match hint {
                Some(hint) => assert!(out.stderr.starts_with(hint), "{args:?}: {}", out.stderr),
                None => assert!(
                    out.stderr.starts_with("\n  ✗ Error:"),
                    "{args:?}: {}",
                    out.stderr
                ),
            }
            assert!(out.stderr.contains("    HTTP 403\n"));
            // A read 403 is re-read once after a token refresh (D10, the SDK read rule).
            assert_eq!(f.server.route_count(Route::Gateway(route)), 2, "{args:?}");
        }
    }

    /// A data-plane-only grant (the admin plane answers 403): a slug or UUID resolves from
    /// the data-plane list alone, while a display name also reads the admin-plane lists
    /// (choice 127), so its 403 carries the admin grant hint and then the hint that a
    /// slug or UUID needs only the data plane.
    #[test]
    fn a_display_name_under_a_data_plane_only_grant_hints_at_the_slug() {
        let f = fx();
        f.server.set_default(
            Route::Gateway(Gw::AdminWorkspaces),
            Planned::json(403, &json!({"message": "x"})),
        );
        for reference in ["ws-main-a-349e0e", fx::uuid(1).as_str()] {
            f.clear();
            let out = f.gw(&windowed(&[
                "telemetry",
                "errors",
                "--workspace",
                reference,
                "--output",
                "json",
            ]));
            out.assert_success();
            assert_eq!(f.api()[0], WORKSPACES, "{reference}");
            assert!(
                !f.api()
                    .iter()
                    .any(|line| line.starts_with(ADMIN_WORKSPACES)),
                "{reference}: {:?}",
                f.api()
            );
        }
        f.clear();
        let out = f.gw(&windowed(&["telemetry", "errors", "--workspace", "Main A"]));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        let hint = "  ⚠ 'Main A' is no workspace id or slug on the data-plane list, so the admin-plane lists were read too: use the workspace slug or UUID (a display name also reads the admin-plane lists, which need the admin grant)\n";
        assert!(
            out.stderr
                .starts_with(&format!("{ADMIN_HINT}{hint}\n  ✗ Error:")),
            "{}",
            out.stderr
        );
        assert!(out.stderr.contains("    HTTP 403\n"));
        assert_eq!(f.api()[0], WORKSPACES);
        assert!(f.api()[1].starts_with(ADMIN_WORKSPACES));
        assert!(
            !f.api().iter().any(|line| line.contains("workspaceSlug=")),
            "no chart read: {:?}",
            f.api()
        );
        // A failing data-plane list carries no such hint (no list was read before it).
        let f = fx();
        f.server.set_default(
            Route::Gateway(Gw::DataWorkspaces),
            Planned::json(403, &json!({"message": "x"})),
        );
        let out = f.gw(&windowed(&["telemetry", "errors", "--workspace", "Main A"]));
        out.assert_code(1);
        assert!(
            out.stderr
                .starts_with(&format!("{WORKSPACE_HINT}\n  ✗ Error:")),
            "{}",
            out.stderr
        );
    }

    /// Reads use the SDK read retries (D10): a 503 is read again; server text is never
    /// printed (D11).
    #[test]
    fn reads_retry_and_print_no_server_text() {
        let f = fx();
        f.server.push_once(
            Route::Gateway(Gw::ScopeList),
            Planned::json(503, &json!({"message": "busy SERVERTEXT"}))
                .with_header("retry-after", "0"),
        );
        let out = f.gw(&["scopes", "list", "--output", "json"]);
        out.assert_success();
        assert_eq!(f.server.route_count(Route::Gateway(Gw::ScopeList)), 2);
        f.server.set_default(
            Route::Gateway(Gw::ScopeList),
            Planned::json(400, &json!({"message": "bad SERVERTEXT \u{1b}[31m"})),
        );
        let out = f.gw(&["scopes", "list"]);
        out.assert_code(1);
        assert!(!out.stderr.contains("SERVERTEXT"));
        assert!(out.stderr.contains("AISEC_CLIENT_SIDE_ERROR:API error 400"));
    }

    /// A malformed answer is the §6 decode error, and nothing is printed.
    #[test]
    fn a_malformed_answer_is_a_decode_error() {
        let f = fx();
        f.server.push_once(
            Route::Gateway(Gw::Chart),
            Planned::json(200, &json!({"success": true, "data": {"records": "no"}})),
        );
        let out = f.gw(&["telemetry", "users", "--workspace", "ws-main-a-349e0e"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert!(
            out.stderr
                .contains("AISEC_RESPONSE_VALIDATION:Response did not match the expected schema"),
            "{}",
            out.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// Debug log (§19.3, D64, G45)
// ---------------------------------------------------------------------------

mod debug {
    use super::*;

    /// Every read records its SDK operation name (G45) and no body or query.
    #[test]
    fn reads_record_their_operations_and_no_body_or_query() {
        for (args, operations) in [
            (
                vec!["workspaces", "list", "--all"],
                vec![
                    "airs.gateway.workspaces.list",
                    "airs.gateway.workspaces.list",
                ],
            ),
            (
                vec!["workspaces", "get", "ws-main-a-349e0e"],
                vec!["airs.gateway.workspaces.get"],
            ),
            (vec!["scopes", "list"], vec!["shared.iam.scopes.list"]),
            (
                vec!["scopes", "get", "ws_orphan_zzzzzz"],
                vec!["shared.iam.scopes.get"],
            ),
            (
                vec!["telemetry", "errors", "--workspace", "ws-main-a-349e0e"],
                vec![
                    "airs.gateway.workspaces.list",
                    "airs.gateway.telemetry.chart",
                ],
            ),
            (
                vec!["telemetry", "cost", "--workspace", "ws-main-a-349e0e"],
                vec![
                    "airs.gateway.workspaces.list",
                    "airs.gateway.telemetry.cost",
                ],
            ),
            (
                vec![
                    "telemetry",
                    "logs",
                    "list",
                    "--workspace",
                    "ws-main-a-349e0e",
                ],
                vec![
                    "airs.gateway.workspaces.list",
                    "airs.gateway.telemetry.logs",
                ],
            ),
            (
                vec![
                    "telemetry",
                    "group-by",
                    "users",
                    "--workspace",
                    "ws-main-a-349e0e",
                ],
                vec![
                    "airs.gateway.workspaces.list",
                    "airs.gateway.telemetry.by_user",
                ],
            ),
        ] {
            let f = fx();
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec!["--debug", "gateway"];
            full.extend(args.iter().copied());
            let out = f.run_with(&full, &RunOptions::new().env("XDG_STATE_HOME", &state));
            out.assert_success();
            let (path, records) = debug_log::only_log(&f.sandbox);
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(!text.contains("timeOfGeneration"), "{args:?}");
            assert!(
                !text.contains("Main A") && !text.contains("main_airs"),
                "{args:?}"
            );
            let found: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .filter(|operation| *operation != "oauth.token")
                .collect();
            assert_eq!(found, operations, "{args:?}");
            debug_log::assert_logs_clean(
                &f.sandbox,
                &f.server,
                &[debug_log::log_dir(&f.sandbox)],
                &[],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Interruption (§19.3, D252)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    /// A signal during a read, the resolution's lists included, writes no data (exit 130 /
    /// 143).
    #[test]
    fn a_signal_during_a_read_writes_nothing() {
        for (signal, code, route, args) in [
            (
                "INT",
                130,
                Gw::AdminWorkspaces,
                vec!["gateway", "telemetry", "cost", "--workspace", "Old"],
            ),
            (
                "TERM",
                143,
                Gw::Chart,
                vec![
                    "gateway",
                    "telemetry",
                    "errors",
                    "--workspace",
                    "ws-main-a-349e0e",
                ],
            ),
            (
                "INT",
                130,
                Gw::DataWorkspaceGet,
                vec!["gateway", "workspaces", "get", "x"],
            ),
        ] {
            let f = fx();
            f.server.push_once(Route::Gateway(route), Planned::hang());
            let running = spawn(
                &rust(),
                &f.sandbox,
                &args,
                &RunOptions::new().expect_signal(),
            );
            assert!(
                f.server
                    .wait_for_route(Route::Gateway(route), 1, Duration::from_secs(10))
            );
            running.send_signal(signal);
            let out = running.wait();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "\n  ✗ Error: Interrupted; no data was written\n\n"
            );
        }
    }
}
