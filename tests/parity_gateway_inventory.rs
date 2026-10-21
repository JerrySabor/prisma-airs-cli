//! TS-vs-Rust parity for the M6e chunk-2 gateway reads (DESIGN §19.9, §19.13): every
//! inventory read (`api-keys`, `audit-logs`, `configs`, `deployments`, `guardrails`,
//! `integrations`, `mcp integrations`, `organisations`, `plugins`, `providers`) and the
//! `admin-guardrails` reads (TS `aigateway …`, renamed, D227).
//!
//! Each scenario runs once against airs-cli-rs (`gateway …`) and once against the
//! TypeScript reference (`aigateway …`), each on a fresh [`FixtureServer`] seeded with the
//! gateway dataset and a fresh [`Sandbox`]. `parity` tests compare exit codes, stdout bytes
//! (pretty and table) or JSON (json), stderr and the requests of the reads whose answers
//! carry no credential; the secret-bearing reads compare everything outside the members
//! airs-cli-rs withholds (D238). `divergence` tests pin both sides of each §12 row this
//! chunk implements (named by its D#). The TypeScript side prints the fixture markers
//! (D238), so its runs disable the marker check; the airs-cli-rs runs keep it.

use airs_test_harness::fixtures::gateway as fx;
use airs_test_harness::{
    Cli, FixtureServer, GatewayData, Gw, Planned, RecordedRequest, Route, Run, RunOptions, Sandbox,
    assert_json_semantic_eq, require_ts, run,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const START: &str = "2026-10-01T00:00:00Z";
const END: &str = "2026-10-02T00:00:00Z";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn u(n: u64) -> String {
    fx::uuid(n)
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
}

impl Side {
    /// `METHOD path?query` of every API request (the token request left out).
    fn api(&self) -> Vec<String> {
        self.requests
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }
}

fn unchanged(_: &mut GatewayData) {}

fn exec_with(
    cli: &Cli,
    args: &[&str],
    seed: &dyn Fn(&mut GatewayData),
    plan: &dyn Fn(&FixtureServer),
) -> Side {
    let server = FixtureServer::start();
    server.seed_gateway();
    server.gateway(|data| seed(data));
    plan(&server);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    let mut full = vec![if cli.is_ts() { "aigateway" } else { "gateway" }];
    full.extend_from_slice(args);
    let options = if cli.is_ts() {
        RunOptions::new().allow_secret_output()
    } else {
        RunOptions::new()
    };
    let out = run(cli, &sandbox, &full, &options);
    server.assert_no_unknown_routes();
    Side {
        run: out,
        requests: server.requests(),
    }
}

fn sides_with(
    name: &str,
    args: &[&str],
    seed: &dyn Fn(&mut GatewayData),
    plan: &dyn Fn(&FixtureServer),
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((
        exec_with(&rust(), args, seed, plan),
        exec_with(&ts, args, seed, plan),
    ))
}

fn sides_seeded(
    name: &str,
    args: &[&str],
    seed: &dyn Fn(&mut GatewayData),
) -> Option<(Side, Side)> {
    sides_with(name, args, seed, &|_| {})
}

fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_seeded(name, args, &unchanged)
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// Byte parity: exit code, stdout, stderr and the request lines.
fn assert_bytes(r: &Side, t: &Side) {
    assert_eq!(r.run.code, t.run.code, "exit codes differ{}", context(r, t));
    assert_eq!(
        r.run.stdout,
        t.run.stdout,
        "stdout differs{}",
        context(r, t)
    );
    assert_eq!(
        r.run.stderr,
        t.run.stderr,
        "stderr differs{}",
        context(r, t)
    );
    assert_eq!(r.api(), t.api(), "requests differ{}", context(r, t));
}

/// The reads whose answers carry no credential (every format compared byte for byte).
fn plain_reads() -> Vec<Vec<String>> {
    let ws = u(1);
    let strings = |args: &[&str]| args.iter().map(|arg| (*arg).to_owned()).collect();
    vec![
        strings(&["api-keys", "service", "list", "--workspace", &ws]),
        strings(&["api-keys", "user", "ls", "--workspace", &ws]),
        strings(&["configs", "list", "--workspace", &ws]),
        strings(&["deployments", "list"]),
        strings(&["deployments", "ping", &u(fx::DEPLOYMENT)]),
        strings(&["guardrails", "ls", "--workspace", &ws]),
        strings(&["guardrails", "get", &u(fx::GUARDRAIL)]),
        strings(&["guardrails", "catalog"]),
        strings(&["integrations", "list"]),
        strings(&["integrations", "providers"]),
        strings(&["integrations", "workspaces", "list", &u(fx::INTEGRATION)]),
        strings(&["mcp", "integrations", "list"]),
        strings(&[
            "mcp",
            "integrations",
            "capabilities",
            "ls",
            &u(fx::MCP_INTEGRATION),
        ]),
        strings(&["mcp", "integrations", "metadata", &u(fx::MCP_INTEGRATION)]),
        strings(&["organisations", "self", "get"]),
        strings(&["admin-guardrails", "list"]),
        strings(&["admin-guardrails", "get", &u(fx::ADMIN_GUARDRAIL)]),
        strings(&[
            "admin-guardrails",
            "mcp-servers",
            "list",
            &u(fx::ADMIN_GUARDRAIL),
        ]),
    ]
}

/// The secret-bearing reads (TS `--tsg-id` is required, so both sides pass it).
fn secret_reads() -> Vec<Vec<String>> {
    let strings = |args: &[&str]| args.iter().map(|arg| (*arg).to_owned()).collect();
    vec![
        strings(&["api-keys", "service", "get", &u(fx::SERVICE_KEY)]),
        strings(&["api-keys", "user", "get", &u(fx::USER_KEY)]),
        strings(&["audit-logs", "list", "--start", START, "--end", END]),
        strings(&["configs", "get", &u(fx::CONFIG)]),
        strings(&["configs", "versions", &u(fx::CONFIG)]),
        strings(&["deployments", "get", &u(fx::DEPLOYMENT)]),
        strings(&["integrations", "get", &u(fx::INTEGRATION)]),
        strings(&["mcp", "integrations", "get", &u(fx::MCP_INTEGRATION)]),
        strings(&[
            "mcp",
            "integrations",
            "workspaces",
            "list",
            &u(fx::MCP_INTEGRATION),
        ]),
        strings(&["organisations", "info", "--tsg-id", TSG]),
        strings(&["organisations", "auth-settings", "get", "--tsg-id", TSG]),
        strings(&["plugins", "list"]),
        strings(&["providers", "list", "--workspace", &u(1)]),
        strings(&["providers", "get", &u(fx::PROVIDER)]),
    ]
}

fn refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// `value` (a TypeScript document) with every member that `withheld` (the airs-cli-rs
/// document) shows as `[withheld]`, or as a string carrying `[withheld]`, replaced by that
/// string, and every member TypeScript masks (`***`, `[REDACTED]`) replaced by the
/// airs-cli-rs value (TS over-masks `masked_api_key`, D238).
fn masked(value: &Value, withheld: &Value) -> Value {
    match (value, withheld) {
        (_, Value::String(text)) if text.contains("[withheld]") => withheld.clone(),
        (Value::String(text), _) if text == "***" || text == "[REDACTED]" => withheld.clone(),
        (Value::Object(entries), Value::Object(shown)) => Value::Object(
            entries
                .iter()
                .map(|(key, member)| {
                    let member = shown
                        .get(key)
                        .map_or_else(|| member.clone(), |shown| masked(member, shown));
                    (key.clone(), member)
                })
                .collect(),
        ),
        (Value::Array(items), Value::Array(shown)) if items.len() == shown.len() => Value::Array(
            items
                .iter()
                .zip(shown)
                .map(|(item, shown)| masked(item, shown))
                .collect(),
        ),
        _ => value.clone(),
    }
}

/// The first column of every row of a box table (the `Field` names of a detail).
fn first_column(table: &str) -> Vec<String> {
    table
        .lines()
        .filter(|line| !line.starts_with('─'))
        .map(|line| line.split('│').next().unwrap_or_default().trim().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// Every credential-free read in pretty and table, byte for byte, with its request; the
    /// guardrail catalog, which the service sends in its own member order, cell by cell with
    /// its JSON cells compared as JSON (D35,
    /// `divergence::d35_the_guardrail_catalog_differs_only_in_member_order`).
    #[test]
    fn inventory_reads_match_typescript() {
        for read in plain_reads() {
            if read == ["guardrails", "catalog"] {
                continue;
            }
            for format in ["pretty", "table"] {
                let mut args = refs(&read);
                args.extend(["--output", format]);
                let Some((r, t)) = sides("inventory_reads_match_typescript", &args) else {
                    return;
                };
                r.run.assert_success();
                assert_bytes(&r, &t);
            }
        }
    }

    /// The same reads in json, compared as JSON (D35).
    #[test]
    fn inventory_json_matches_typescript() {
        for read in plain_reads() {
            let mut args = refs(&read);
            args.extend(["--output", "json"]);
            let Some((r, t)) = sides("inventory_json_matches_typescript", &args) else {
                return;
            };
            r.run.assert_success();
            t.run.assert_success();
            // The API-key lists carry `key` (D238); nothing else differs.
            let rust_doc = r.run.json();
            assert_json_semantic_eq(&rust_doc, &masked(&t.run.json(), &rust_doc));
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}");
            assert_eq!(r.api(), t.api(), "{args:?}");
        }
    }

    /// The secret-bearing reads agree with TypeScript outside the members airs-cli-rs
    /// withholds (D238): the same JSON once TypeScript's values there are masked, the same
    /// detail fields in the same order, the same requests.
    #[test]
    fn secret_bearing_reads_match_outside_the_withheld_members() {
        for read in secret_reads() {
            let mut args = refs(&read);
            args.extend(["--output", "json"]);
            let Some((r, t)) = sides("secret_bearing_reads_match", &args) else {
                return;
            };
            r.run.assert_success();
            t.run.assert_success();
            let (rust_doc, ts_doc) = (r.run.json(), t.run.json());
            assert!(rust_doc.to_string().contains("[withheld]"), "{args:?}");
            assert_json_semantic_eq(&rust_doc, &masked(&ts_doc, &rust_doc));
            assert_eq!(r.api(), t.api(), "{args:?}");
            let mut args = refs(&read);
            args.extend(["--output", "table"]);
            let Some((r, t)) = sides("secret_bearing_reads_match", &args) else {
                return;
            };
            assert_eq!(
                first_column(&r.run.stdout),
                first_column(&t.run.stdout),
                "{args:?}{}",
                context(&r, &t)
            );
        }
    }

    /// `admin-guardrails list` sends only the given keys in TS order, an explicit page 0
    /// included (TS `aigateway-admin-guardrails.spec.ts`); the paging checks are TS's,
    /// before anything else.
    #[test]
    fn admin_guardrail_paging_matches_typescript() {
        for args in [
            &["admin-guardrails", "list", "--current-page", "0"][..],
            &[
                "admin-guardrails",
                "ls",
                "--workspace",
                "11111111-1111-4111-8111-000000000001",
                "--page-size",
                "25",
                "--current-page",
                "3",
            ],
        ] {
            let Some((r, t)) = sides("admin_guardrail_paging_matches_typescript", args) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.api(), t.api(), "{args:?}");
        }
        for args in [
            &["admin-guardrails", "list", "--page-size", "0"][..],
            &["admin-guardrails", "list", "--page-size", "1001"],
            &["admin-guardrails", "list", "--current-page", "-1"],
            &["admin-guardrails", "list", "--current-page", "x"],
        ] {
            let Some((r, t)) = sides("admin_guardrail_paging_matches_typescript", args) else {
                return;
            };
            r.run.assert_code(2);
            assert_bytes(&r, &t);
            assert!(r.requests.is_empty());
        }
    }

    /// `audit-logs list` sends the pinned window as `toISOString()` instants on both sides
    /// (the SDK's `date_iso`).
    #[test]
    fn audit_windows_match_typescript() {
        let Some((r, t)) = sides(
            "audit_windows_match_typescript",
            &[
                "audit-logs",
                "ls",
                "--start",
                "2026-10-01T05:30:00+05:30",
                "--end",
                END,
                "--output",
                "json",
            ],
        ) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(r.api(), t.api());
        assert_eq!(
            r.api(),
            [
                "GET /ai_gw/admin/v2/audit-logs?start_time=2026-10-01T00%3A00%3A00.000Z&end_time=2026-10-02T00%3A00%3A00.000Z"
            ]
        );
    }

    /// An empty list in pretty and json (the TS empty phrases and `[]`).
    #[test]
    fn empty_lists_match_typescript() {
        let empty = |data: &mut GatewayData| {
            data.inventory.insert(
                Gw::Deployments,
                json!({"object": "list", "total": 0, "data": []}),
            );
            data.inventory
                .insert(Gw::AdminGuardrails, json!({"data": [], "total": 0}));
        };
        for args in [
            &["deployments", "list"][..],
            &["deployments", "list", "--output", "json"],
            &["admin-guardrails", "list"],
            &[
                "configs",
                "list",
                "--workspace",
                "11111111-1111-4111-8111-000000000009",
            ],
        ] {
            let Some((r, t)) = sides_seeded("empty_lists_match_typescript", args, &empty) else {
                return;
            };
            r.run.assert_success();
            assert_bytes(&r, &t);
        }
    }

    /// The tenant's `defaultOutput` applies to the inventory reads (choice 5).
    #[test]
    fn the_tenant_default_output_applies() {
        let Some(ts) = require_ts("the_tenant_default_output_applies") else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_gateway();
            let sandbox = Sandbox::new();
            let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
                config.set("defaultOutput", "json");
            });
            sandbox.register(&[&tenant], Some("prod"));
            let root = if cli.is_ts() { "aigateway" } else { "gateway" };
            let out = run(
                &cli,
                &sandbox,
                &[root, "plugins", "list"],
                &RunOptions::new().allow_secret_output(),
            );
            out.assert_success();
            assert_eq!(out.json()[0]["id"], u(fx::PLUGIN), "{}", cli.label());
        }
    }

    /// Every chunk-2 group and leaf carries TypeScript's descriptions and option texts
    /// (program `airs`, `aigateway` read as `gateway`; §19.2), apart from the
    /// options §19.2 changes: `--tsg-id` (optional, D245), the hidden `--reveal-sensitive`
    /// (D238) and the audit-log `--reveal-sensitive` (D239).
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let help = |cli: &Cli, path: &[&str]| {
            let mut args = vec![if cli.is_ts() { "aigateway" } else { "gateway" }];
            args.extend_from_slice(path);
            args.push("--help");
            let out = run(cli, &sandbox, &args, &RunOptions::new());
            out.assert_success();
            out.stdout
        };
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let entries = |text: &str, title: &str| -> Vec<(String, String)> {
            let mut lines = text.lines();
            if !lines.any(|line| line == title) {
                return Vec::new();
            }
            let mut out: Vec<(String, String)> = Vec::new();
            for line in lines.take_while(|line| !line.trim().is_empty()) {
                let trimmed = line.trim_start();
                let indent = line.len() - trimmed.len();
                if indent <= 6 {
                    let (spec, description) = trimmed.split_once("  ").unwrap_or((trimmed, ""));
                    let name = spec
                        .split([',', ' '])
                        .find(|part| {
                            if title == "Options:" {
                                part.starts_with("--")
                            } else {
                                !part.is_empty()
                            }
                        })
                        .unwrap_or(spec);
                    let name = name.split('|').next().unwrap_or(name).to_owned();
                    out.push((name, squash(description)));
                } else if let Some((_, description)) = out.last_mut() {
                    *description = squash(&format!("{description} {trimmed}"));
                }
            }
            out
        };
        // The commands chunk 2 builds (reads only; the writes are chunk 3).
        let built = [
            "admin-guardrails",
            "api-keys",
            "audit-logs",
            "configs",
            "deployments",
            "guardrails",
            "integrations",
            "mcp",
            "organisations",
            "plugins",
            "providers",
            "scopes",
            "telemetry",
            "workspaces",
            "service",
            "user",
            "list",
            "get",
            "versions",
            "ping",
            "catalog",
            "providers",
            "models",
            "integrations",
            "capabilities",
            "metadata",
            "info",
            "self",
            "auth-settings",
            "mcp-servers",
            // chunk 4's leaves (tests/parity_gateway_inference.rs, parity_gateway_report.rs)
            "inference",
            "report",
            // chunk 3's write leaves (tests/parity_gateway_writes.rs)
            "archive",
            "bind",
            "create",
            "delete",
            "rotate",
            "set",
            "sync",
            "update",
            "upsert",
        ];
        let mut problems = Vec::new();
        let groups: [&[&str]; 18] = [
            &[],
            &["admin-guardrails"],
            &["admin-guardrails", "mcp-servers"],
            &["api-keys"],
            &["api-keys", "service"],
            &["api-keys", "user"],
            &["audit-logs"],
            &["configs"],
            &["deployments"],
            &["guardrails"],
            &["integrations"],
            &["integrations", "models"],
            &["integrations", "workspaces"],
            &["mcp"],
            &["mcp", "integrations"],
            &["organisations"],
            &["organisations", "self"],
            &["plugins"],
        ];
        let more: [&[&str]; 4] = [
            &["providers"],
            &["mcp", "integrations", "capabilities"],
            &["mcp", "integrations", "workspaces"],
            &["organisations", "auth-settings"],
        ];
        for path in groups.iter().chain(more.iter()) {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let ts_subs: Vec<(String, String)> = entries(&t, "Commands:")
                .into_iter()
                .filter(|(name, _)| built.contains(&name.as_str()))
                .collect();
            let rust_subs: Vec<(String, String)> = entries(&r, "Commands:")
                .into_iter()
                .filter(|(name, _)| name != "help")
                .map(|(name, text)| {
                    let text = text
                        .split(" [aliases:")
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    (name, text)
                })
                .collect();
            if ts_subs != rust_subs {
                problems.push(format!("{path:?}: {rust_subs:?} vs {ts_subs:?}"));
            }
            let ts_about = squash(t.split("\n\n").nth(1).unwrap_or_default());
            if !squash(&r).contains(&ts_about) {
                problems.push(format!("{path:?} description: {ts_about:?}"));
            }
        }
        let leaves: [&[&str]; 33] = [
            &["admin-guardrails", "get"],
            &["admin-guardrails", "list"],
            &["admin-guardrails", "mcp-servers", "list"],
            &["api-keys", "service", "get"],
            &["api-keys", "service", "list"],
            &["api-keys", "user", "get"],
            &["api-keys", "user", "list"],
            &["audit-logs", "list"],
            &["configs", "get"],
            &["configs", "list"],
            &["configs", "versions"],
            &["deployments", "get"],
            &["deployments", "list"],
            &["deployments", "ping"],
            &["guardrails", "catalog"],
            &["guardrails", "get"],
            &["guardrails", "list"],
            &["integrations", "get"],
            &["integrations", "list"],
            &["integrations", "models", "list"],
            &["integrations", "providers"],
            &["integrations", "workspaces", "list"],
            &["mcp", "integrations", "capabilities", "list"],
            &["mcp", "integrations", "get"],
            &["mcp", "integrations", "list"],
            &["mcp", "integrations", "metadata"],
            &["mcp", "integrations", "workspaces", "list"],
            &["organisations", "auth-settings", "get"],
            &["organisations", "info"],
            &["organisations", "self", "get"],
            &["plugins", "list"],
            &["providers", "get"],
            &["providers", "list"],
        ];
        let tsg_help =
            "Numeric TSG id (default: the selected tenant's mgmtTsgId; another value is refused)";
        for path in leaves {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let command = path.join(" ");
            let rust_options = entries(&r, "Options:");
            for (flag, description) in entries(&t, "Options:") {
                if matches!(flag.as_str(), "--help" | "--output") {
                    continue;
                }
                let expected = match (flag.as_str(), command.as_str()) {
                    ("--tsg-id", _) => Some(tsg_help.to_owned()),
                    ("--reveal-sensitive", "audit-logs list") => Some(
                        "Show request fields; credentials inside them stay withheld".to_owned(),
                    ),
                    ("--reveal-sensitive", _) => None,
                    _ => Some(description),
                };
                let found = rust_options.iter().find(|(f, _)| *f == flag);
                match (expected, found) {
                    (Some(expected), Some((_, actual))) if *actual == expected => {}
                    (None, None) => {}
                    (expected, found) => {
                        problems.push(format!("{command} {flag}: {found:?} vs {expected:?}"))
                    }
                }
            }
            let ts_about = squash(t.split("\n\n").nth(1).unwrap_or_default());
            if !squash(&r).contains(&ts_about) {
                problems.push(format!("{command} description: {ts_about:?}"));
            }
        }
        assert!(
            problems.is_empty(),
            "help differs:\n{}",
            problems.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    fn hint(data_plane: bool) -> String {
        let grant = if data_plane {
            "the service account is missing a workspace-scope grant (data plane, /ai_gw/v2)"
        } else {
            "the service account is missing a tenant-root admin grant (admin plane, /ai_gw/admin/v2)"
        };
        format!(
            "  ⚠ 403: {grant}. SCM Access Management edits the existing role row by default — use \"Add Role\" so the account ends up with both role rows, not one row moved.\n"
        )
    }

    /// The trimmed cells of every row of a box table (the rules dropped).
    fn table_rows(table: &str) -> Vec<Vec<String>> {
        table
            .lines()
            .filter(|line| line.contains('│'))
            .map(|line| line.split('│').map(|cell| cell.trim().to_owned()).collect())
            .collect()
    }

    /// Whether two table cells agree: the same text, or both JSON objects or arrays equal as
    /// JSON (D35: key order ignored).
    fn cells_agree(rust: &str, ts: &str) -> bool {
        let json = |cell: &str| {
            serde_json::from_str::<Value>(cell)
                .ok()
                .filter(|value| value.is_object() || value.is_array())
        };
        rust == ts
            || matches!((json(rust), json(ts)), (Some(r), Some(t)) if airs_test_harness::json_semantic_eq(&r, &t))
    }

    /// D35 (live, choice 156): the service sends the guardrail catalog in its own member
    /// order (`{"type": …, "text": …}`; the fixture server's `service_order`); TypeScript
    /// prints the nested members in that order and airs-cli-rs sorts them, so the pretty
    /// and table outputs differ in bytes but every cell is equal, the JSON one as JSON; the
    /// json output is compared as JSON (`inventory_json_matches_typescript`).
    #[test]
    fn d35_the_guardrail_catalog_differs_only_in_member_order() {
        for format in ["table", "pretty"] {
            let args = ["guardrails", "catalog", "--output", format];
            let Some((r, t)) = sides(
                "d35_the_guardrail_catalog_differs_only_in_member_order",
                &args,
            ) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.run.code, t.run.code, "{format}");
            assert_ne!(r.run.stdout, t.run.stdout, "{format}: the order differs");
            assert!(
                t.run.stdout.contains(r#"{"type":"subHeading","text":"#),
                "{format}: TS keeps the service order"
            );
            assert!(
                r.run.stdout.contains(r#"{"text":"Checks prompts"#),
                "{format}: airs sorts"
            );
            let (rust_rows, ts_rows) = (table_rows(&r.run.stdout), table_rows(&t.run.stdout));
            assert_eq!(rust_rows.len(), 3, "{format}: Field, object, evals");
            assert_eq!(rust_rows.len(), ts_rows.len(), "{format}");
            for (rust_row, ts_row) in rust_rows.iter().zip(&ts_rows) {
                assert_eq!(rust_row.len(), ts_row.len(), "{format}");
                for (rust_cell, ts_cell) in rust_row.iter().zip(ts_row) {
                    assert!(
                        cells_agree(rust_cell, ts_cell),
                        "{format}: {rust_cell} vs {ts_cell}"
                    );
                }
            }
            assert!(!r.run.stdout.contains("[withheld]"), "{format}");
            assert_eq!(r.run.stderr, t.run.stderr, "{format}");
            assert_eq!(r.api(), t.api(), "{format}");
        }
    }

    /// D238 (choices 146, 147; live): the guardrail catalog, whose parameter schemas sit
    /// under credential names, prints the same `Field │ Value` cells on both CLIs; the one
    /// difference is a real credential (a `default` under the credential-named `apiKey`,
    /// and its echo in a name), which TypeScript prints and airs-cli-rs shows as
    /// `[withheld]`. Without a credential the catalog differs only in its member order
    /// (`d35_the_guardrail_catalog_differs_only_in_member_order`).
    #[test]
    fn d238_the_guardrail_catalog_withholds_only_its_credential() {
        let seed = |data: &mut GatewayData| {
            let catalog = data.inventory.get_mut(&Gw::GuardrailCatalog).unwrap();
            catalog["evals"][0]["parameters"]["properties"]["credentials"]["properties"]["apiKey"]
                ["default"] = json!(fx::marker(48));
            catalog["evals"][1]["name"] = json!(format!("Webhook {}", fx::marker(48)));
        };
        for format in ["table", "pretty"] {
            let args = ["guardrails", "catalog", "--output", format];
            let Some((r, t)) = sides_seeded(
                "d238_the_guardrail_catalog_withholds_only_its_credential",
                &args,
                &seed,
            ) else {
                return;
            };
            r.run.assert_success();
            t.run.assert_success();
            assert!(t.run.stdout.contains(&fx::marker(48)), "TS prints it");
            assert!(!r.run.stdout.contains(&fx::marker(48)));
            let rust_rows = table_rows(&r.run.stdout);
            let ts_rows = table_rows(&t.run.stdout);
            assert_eq!(rust_rows.len(), 3, "{format}: Field, object, evals");
            assert_eq!(rust_rows.len(), ts_rows.len(), "{format}");
            for (rust_row, ts_row) in rust_rows.iter().zip(&ts_rows) {
                assert_eq!(rust_row.len(), ts_row.len(), "{format}");
                for (rust_cell, ts_cell) in rust_row.iter().zip(ts_row) {
                    // The only tolerated differences: TS's credential where Rust shows
                    // `[withheld]` (the whole string that carries it, D47), and the member
                    // order of a JSON cell (D35).
                    let shown = ts_cell
                        .replace(&format!("\"Webhook {}\"", fx::marker(48)), "\"[withheld]\"")
                        .replace(&fx::marker(48), "[withheld]");
                    assert!(
                        cells_agree(rust_cell, &shown),
                        "{format}: {rust_cell} vs {shown}"
                    );
                }
            }
            assert_eq!(rust_rows[1], ["object", "list"], "{format}");
            assert_eq!(
                rust_rows[2][1].matches("[withheld]").count(),
                2,
                "{format}: only the credential and its echo"
            );
            assert_eq!(r.api(), t.api(), "{format}");
        }
    }

    /// D238 (extended): every credential the inventory reads return is `[withheld]` in
    /// every format; TypeScript prints provider list keys, integration and MCP secrets,
    /// SSO secrets, plugin credentials and deployment credentials, and masks others with
    /// `***`/`[REDACTED]` (also the non-secret `masked_api_key`).
    #[test]
    fn d238_inventory_credentials_are_withheld() {
        for (args, member, ts_shows) in [
            (
                vec![
                    "providers".to_owned(),
                    "list".into(),
                    "--workspace".into(),
                    u(1),
                ],
                "/0/key",
                Some(fx::marker(26)),
            ),
            (
                vec!["providers".to_owned(), "get".into(), u(fx::PROVIDER)],
                "/key",
                Some("***".to_owned()),
            ),
            (
                vec!["providers".to_owned(), "get".into(), u(fx::PROVIDER)],
                "/model_config",
                Some("[REDACTED]".to_owned()),
            ),
            (
                vec!["integrations".to_owned(), "get".into(), u(fx::INTEGRATION)],
                "/configurations/custom_headers/x-tenant",
                Some(fx::marker(18)),
            ),
            (
                vec![
                    "mcp".to_owned(),
                    "integrations".into(),
                    "get".into(),
                    u(fx::MCP_INTEGRATION),
                ],
                "/configurations/client_secret",
                Some(fx::marker(19)),
            ),
            (
                vec![
                    "organisations".to_owned(),
                    "auth-settings".into(),
                    "get".into(),
                    "--tsg-id".into(),
                    TSG.into(),
                ],
                "/data/auth_settings/client_secret",
                Some(fx::marker(22)),
            ),
            (
                vec!["plugins".to_owned(), "list".into()],
                "/0/credentials",
                None,
            ),
            (
                vec!["deployments".to_owned(), "get".into(), u(fx::DEPLOYMENT)],
                "/client_auth",
                Some(fx::marker(16)),
            ),
            (
                vec![
                    "api-keys".to_owned(),
                    "service".into(),
                    "get".into(),
                    u(fx::SERVICE_KEY),
                ],
                "/key",
                Some("***".to_owned()),
            ),
        ] {
            let mut full = refs(&args);
            full.extend(["--output", "json"]);
            let Some((r, t)) = sides("d238_inventory_credentials_are_withheld", &full) else {
                return;
            };
            r.run.assert_success();
            t.run.assert_success();
            assert_eq!(
                r.run.json().pointer(member),
                Some(&json!("[withheld]")),
                "{full:?}"
            );
            let ts_value = t.run.json().pointer(member).cloned();
            match ts_shows {
                Some(text) => assert_eq!(ts_value, Some(json!(text)), "{full:?}"),
                None => assert!(ts_value.is_some_and(|value| value.is_object()), "{full:?}"),
            }
        }
        let Some((r, t)) = sides(
            "d238_inventory_credentials_are_withheld",
            &["providers", "get", &u(fx::PROVIDER), "--output", "json"],
        ) else {
            return;
        };
        assert_eq!(r.run.json()["masked_api_key"], "sk-...abcd");
        assert_eq!(t.run.json()["masked_api_key"], "***");
        // Choice 164: the secret mapping prints whole (its `secret_key` names the key inside
        // the referenced secret); TypeScript masks the whole list by its name.
        assert_eq!(
            r.run.json()["secret_mappings"],
            fx::provider_detail()["secret_mappings"]
        );
        assert_eq!(t.run.json()["secret_mappings"], "***");
        // `--reveal-sensitive` is refused before the tenant (TS shows the credentials).
        let Some((r, t)) = sides(
            "d238_inventory_credentials_are_withheld",
            &[
                "providers",
                "get",
                &u(fx::PROVIDER),
                "--reveal-sensitive",
                "--output",
                "json",
            ],
        ) else {
            return;
        };
        r.run.assert_code(2);
        assert_eq!(
            airs_test_harness::usage_line(&r.run.stderr).as_deref(),
            Some("--reveal-sensitive is not supported here: airs never prints credentials")
        );
        assert!(r.requests.is_empty());
        t.run.assert_success();
        assert_eq!(t.run.json()["key"], fx::marker(24));
    }

    /// Names TypeScript's `redactDeep` pattern (`debug-logger.ts` `SENSITIVE_KEY_PATTERN`)
    /// masks, one per alternative in camelCase, snake_case, upper-case, prefix and plural
    /// forms (choice 163: `access_tokens`, `refreshTokens`, `apiTokens`, `tokens`).
    const TS_VOCABULARY: [&str; 34] = [
        "accessToken",
        "access_tokens",
        "refreshTokens",
        "apiTokens",
        "tokens",
        "awsSessionToken",
        "bearerToken",
        "token_value",
        "SESSION_TOKEN",
        "clientSecret",
        "secret_value",
        "SecretAccessKey",
        "adminpassword",
        "dbPassword",
        "password_hash",
        "userPasswd",
        "credentialJson",
        "serviceCredentials",
        "authorizationHeader",
        "proxyAuthorization",
        "sessionCookie",
        "cookie_jar",
        "apiKey",
        "xApiKey",
        "api-key-value",
        "openaiApiKey",
        "apikeyValue",
        "clientAuth",
        "client_auth_method",
        "authCode",
        "dAuthCode",
        "key",
        "Key",
        "Authorization",
    ];

    /// The names TypeScript masks that airs-cli-rs prints by name whatever their value (D238,
    /// choices 157, 163, 165): the designed fingerprint, identifiers and references of a
    /// credential, token counts, a tokenizer, two guardrail settings. (A secret mapping's
    /// `secret_key`, printed beside its anchor, is checked by
    /// `d238_inventory_credentials_are_withheld`.)
    const TS_MASKED_RUST_PRINTS: [&str; 12] = [
        "masked_api_key",
        "api_key_id",
        "apiKeyIds",
        "api_key_defaults_id",
        "secret_mappings",
        "secret_path",
        "secret_reference_id",
        "total_tokens",
        "max_tokens",
        "tokenizer",
        "secrets_categories",
        "maxTokenAge",
    ];

    /// D238 (choice 157, review): TypeScript's own vocabulary is the floor of the name
    /// rule. Every name of [`TS_VOCABULARY`] seeded into a `providers get` detail is masked
    /// by TypeScript and withheld by airs-cli-rs, and withheld again inside a revealed audit
    /// body (TypeScript prints audit bodies verbatim); only [`TS_MASKED_RUST_PRINTS`],
    /// which TypeScript masks too, is printed by airs-cli-rs.
    #[test]
    fn d238_every_name_typescript_masks_is_withheld() {
        let value = |n: usize| format!("VOCAB-{n:02}-hunter2x-0123456789");
        let all: Vec<&str> = TS_VOCABULARY
            .iter()
            .chain(&TS_MASKED_RUST_PRINTS)
            .copied()
            .collect();
        let configurations: serde_json::Map<String, Value> = all
            .iter()
            .enumerate()
            .map(|(n, name)| ((*name).to_owned(), json!(value(n))))
            .collect();
        let body = json!({"configurations": configurations.clone()}).to_string();
        let seed = |data: &mut GatewayData| {
            let detail = data.inventory.get_mut(&Gw::ProviderGet).unwrap();
            detail["configurations"] = json!(configurations.clone());
            let logs = data.inventory.get_mut(&Gw::AuditLogs).unwrap();
            logs["records"][0]["request_body"] = json!(body.clone());
        };
        let Some((r, t)) = sides_seeded(
            "d238_every_name_typescript_masks_is_withheld",
            &["providers", "get", &u(fx::PROVIDER), "--output", "json"],
            &seed,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let (rust_doc, ts_doc) = (r.run.json(), t.run.json());
        for (n, name) in all.iter().enumerate() {
            let pointer = format!("/configurations/{name}");
            assert_eq!(
                ts_doc.pointer(&pointer),
                Some(&json!("***")),
                "TypeScript masks {name}"
            );
            let expected = if TS_MASKED_RUST_PRINTS.contains(name) {
                json!(value(n))
            } else {
                json!("[withheld]")
            };
            assert_eq!(rust_doc.pointer(&pointer), Some(&expected), "{name}");
        }
        let Some((r, t)) = sides_seeded(
            "d238_every_name_typescript_masks_is_withheld",
            &[
                "audit-logs",
                "list",
                "--start",
                START,
                "--end",
                END,
                "--reveal-sensitive",
                "--output",
                "json",
            ],
            &seed,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        assert_eq!(t.run.json()[0]["request_body"], json!(body), "TS verbatim");
        let rows = r.run.json();
        let revealed: Value =
            serde_json::from_str(rows[0]["request_body"].as_str().unwrap()).unwrap();
        for (n, name) in all.iter().enumerate() {
            let expected = if TS_MASKED_RUST_PRINTS.contains(name) {
                json!(value(n))
            } else {
                json!("[withheld]")
            };
            assert_eq!(
                revealed.pointer(&format!("/configurations/{name}")),
                Some(&expected),
                "{name}"
            );
        }
    }

    /// D239: audit-log request bodies, headers and queries are withheld by default; with
    /// `--reveal-sensitive` their JSON is shown with the credentials still withheld and
    /// plain text stays withheld. TypeScript prints them verbatim either way.
    #[test]
    fn d239_audit_request_fields_are_withheld() {
        let window = ["--start", START, "--end", END, "--output", "json"];
        let mut args = vec!["audit-logs", "list"];
        args.extend(window);
        let Some((r, t)) = sides("d239_audit_request_fields_are_withheld", &args) else {
            return;
        };
        let (rust_rows, ts_rows) = (r.run.json(), t.run.json());
        for field in ["request_body", "request_headers", "query_params"] {
            assert_eq!(rust_rows[0][field], "[withheld]", "{field}");
        }
        assert!(
            ts_rows[0]["request_body"]
                .as_str()
                .unwrap()
                .contains(&fx::marker(12))
        );
        assert_eq!(ts_rows[1]["request_body"], "plain text body");
        args.push("--reveal-sensitive");
        let Some((r, t)) = sides("d239_audit_request_fields_are_withheld", &args) else {
            return;
        };
        let rust_rows = r.run.json();
        assert_eq!(
            rust_rows[0]["request_body"],
            r#"{"key":"[withheld]","name":"ci-bot"}"#
        );
        assert_eq!(
            rust_rows[0]["request_headers"],
            r#"{"authorization":"[withheld]","content-type":"application/json"}"#
        );
        assert_eq!(
            rust_rows[0]["query_params"],
            r#"{"api_key":"[withheld]","page":"1"}"#
        );
        assert_eq!(rust_rows[1]["request_body"], "[withheld]", "plain text");
        assert_eq!(rust_rows[1]["request_headers"], "{}");
        assert!(
            t.run.json()[0]["request_headers"]
                .as_str()
                .unwrap()
                .contains(&fx::marker(13))
        );
    }

    /// D232 (extended): the id, TSG and reveal checks of the inventory reads are usage
    /// errors before the tenant; TypeScript reads the tenant and its SDK refuses the id
    /// (exit 1) or sends it.
    #[test]
    fn d232_inventory_checks_come_before_the_tenant() {
        let Some(ts) = require_ts("d232_inventory_checks_come_before_the_tenant") else {
            return;
        };
        for args in [
            &["configs", "get", "config-1"][..],
            &["api-keys", "service", "list", "--workspace", "workspace-1"],
            &["deployments", "ping", "deployment-1"],
            &["integrations", "models", "list", "integration-1"],
            &["mcp", "integrations", "metadata", "mcp-1"],
            &["organisations", "info", "--tsg-id", "12x"],
            &["audit-logs", "list", "--end", "not-a-date"],
        ] {
            let sandbox = Sandbox::new();
            let mut rust_args = vec!["gateway"];
            rust_args.extend_from_slice(args);
            let mut ts_args = vec!["aigateway"];
            ts_args.extend_from_slice(args);
            let r = run(&rust(), &sandbox, &rust_args, &RunOptions::new());
            let t = run(&ts, &sandbox, &ts_args, &RunOptions::new());
            r.assert_code(2);
            assert!(!r.stderr.contains("tenant"), "{}", r.stderr);
            t.assert_code(1);
            assert!(t.stderr.contains("No tenant"), "{args:?}: {}", t.stderr);
        }
        let Some((r, t)) = sides(
            "d232_inventory_checks_come_before_the_tenant",
            &["configs", "get", "config-1"],
        ) else {
            return;
        };
        r.run.assert_code(2);
        assert!(r.requests.is_empty());
        t.run.assert_code(1);
        assert_eq!(
            airs_test_harness::usage_line(&r.run.stderr),
            airs_test_harness::error_line(&t.run.stderr),
            "the TS SDK text, as a usage error"
        );
    }

    /// D245 (extended): `--tsg-id` defaults to the tenant's TSG and another value is refused
    /// with nothing sent; TypeScript requires it and sends any value under the tenant's
    /// `x-tsg-id`.
    #[test]
    fn d245_tsg_ids_default_to_the_tenant() {
        let Some((r, t)) = sides(
            "d245_tsg_ids_default_to_the_tenant",
            &["organisations", "info", "--tsg-id", "999"],
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert_eq!(
            r.run.error_line().as_deref(),
            Some(
                "--tsg-id 999 is not the selected tenant's TSG; airs reads and changes only the selected tenant's organisation"
            )
        );
        assert!(r.requests.is_empty(), "no token, no request");
        t.run.assert_code(1);
        assert!(!t.api().is_empty());
        assert!(
            t.api()
                .iter()
                .all(|line| line == "GET /ai_gw/admin/v2/organisations/999/info"),
            "{:?}",
            t.api()
        );
        let Some(ts) = require_ts("d245_tsg_ids_default_to_the_tenant") else {
            return;
        };
        let r = exec_with(
            &rust(),
            &["organisations", "auth-settings", "get"],
            &unchanged,
            &|_| {},
        );
        r.run.assert_success();
        assert_eq!(
            r.api(),
            ["GET /ai_gw/admin/v2/organisations/100/auth-settings"]
        );
        let t = exec_with(
            &ts,
            &["organisations", "auth-settings", "get"],
            &unchanged,
            &|_| {},
        );
        t.run.assert_code(1);
        assert!(
            t.run
                .stderr
                .contains("required option '--tsg-id <tsg>' not specified"),
            "{}",
            t.run.stderr
        );
    }

    /// D248 (extended): an inventory list whose `total` or `has_more` says it is
    /// incomplete warns on stderr (exit 0); TypeScript is silent.
    #[test]
    fn d248_incomplete_inventory_lists_warn() {
        let partial = |data: &mut GatewayData| {
            let mut body = fx::configs();
            body["total"] = json!(5);
            data.inventory.insert(Gw::Configs, body);
        };
        let Some((r, t)) = sides_seeded(
            "d248_incomplete_inventory_lists_warn",
            &["configs", "list", "--workspace", &u(1), "--output", "json"],
            &partial,
        ) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(
            r.run.stderr,
            "  ⚠ The service returned 1 of 5 configs; the list is incomplete (the API offers no continuation)\n"
        );
        t.run.assert_success();
        assert_eq!(t.run.stderr, "");
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
    }

    /// D231 (extended): an empty inventory list prints nothing in table (TS: the pretty
    /// phrase); pretty and json agree (`empty_lists_match_typescript`).
    #[test]
    fn d231_empty_inventory_lists_in_table() {
        for (args, phrase) in [
            (
                vec![
                    "configs".to_owned(),
                    "list".into(),
                    "--workspace".into(),
                    u(9),
                    "--output".into(),
                    "table".into(),
                ],
                "  No configs found\n",
            ),
            (
                vec![
                    "api-keys".to_owned(),
                    "user".into(),
                    "list".into(),
                    "--workspace".into(),
                    u(9),
                    "--output".into(),
                    "table".into(),
                ],
                "  No user API keys found\n",
            ),
        ] {
            let Some((r, t)) = sides("d231_empty_inventory_lists_in_table", &refs(&args)) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.run.stdout, "");
            assert_eq!(t.run.stdout, phrase);
        }
    }

    /// D234 (extended): a data-plane inventory 403 without a service code gets the
    /// workspace-scope hint on stderr (TS: the admin hint, on stdout); an admin-plane 403
    /// the admin hint on both.
    #[test]
    fn d234_inventory_grant_hints() {
        let forbidden = json!({"message": "Forbidden"});
        for (route, args, data_plane) in [
            (
                Gw::Configs,
                vec![
                    "configs".to_owned(),
                    "list".into(),
                    "--workspace".into(),
                    u(1),
                ],
                true,
            ),
            (
                Gw::Plugins,
                vec!["plugins".to_owned(), "list".into()],
                false,
            ),
        ] {
            let plan = |server: &FixtureServer| {
                server.set_default(Route::Gateway(route), Planned::json(403, &forbidden));
            };
            let Some((r, t)) = sides_with(
                "d234_inventory_grant_hints",
                &refs(&args),
                &unchanged,
                &plan,
            ) else {
                return;
            };
            r.run.assert_code(1);
            t.run.assert_code(1);
            assert!(
                r.run.stderr.starts_with(&hint(data_plane)),
                "{}",
                r.run.stderr
            );
            assert_eq!(r.run.stdout, "");
            assert!(t.run.stdout.ends_with(&hint(false)), "{}", t.run.stdout);
        }
    }

    /// D253: `integrations models list` prints the answer's `models`; TypeScript's generic
    /// list finds no rows in `{models: […]}` and always prints the empty phrase.
    #[test]
    fn d253_integration_models_are_listed() {
        for (format, ts_text) in [
            ("pretty", "  No integration models found\n"),
            ("json", "[]\n"),
        ] {
            let Some((r, t)) = sides(
                "d253_integration_models_are_listed",
                &[
                    "integrations",
                    "models",
                    "list",
                    &u(fx::INTEGRATION),
                    "--output",
                    format,
                ],
            ) else {
                return;
            };
            r.run.assert_success();
            assert!(r.run.stdout.contains("gpt-4o"), "{}", r.run.stdout);
            // Choice 165: the prices under `request_token` and `response_token` are printed.
            assert!(!r.run.stdout.contains("[withheld]"), "{}", r.run.stdout);
            if format == "json" {
                assert_eq!(r.run.json(), fx::integration_models()["models"]);
            }
            assert_eq!(t.run.stdout, ts_text);
            assert_eq!(r.api(), t.api());
        }
    }

    /// D178 (extended, G40): an unfamiliar vocabulary value in a gateway answer (a guardrail
    /// `target`, an admin guardrail `status`, a new `pricing_adjustments.multiplier` key) is
    /// printed; TypeScript's strict response schema fails the whole read.
    #[test]
    fn d178_unfamiliar_gateway_vocabulary_is_printed() {
        let seed = |data: &mut GatewayData| {
            data.inventory.get_mut(&Gw::Guardrails).unwrap()["data"][0]["target"] = json!("a2a");
            data.inventory.get_mut(&Gw::AdminGuardrails).unwrap()["data"][0]["status"] =
                json!("paused");
            data.inventory.get_mut(&Gw::IntegrationGet).unwrap()["pricing_adjustments"] =
                json!({"multiplier": {"input": 1, "newUnit": 2}});
        };
        for (args, pointer, value) in [
            (
                vec![
                    "guardrails".to_owned(),
                    "list".into(),
                    "--workspace".into(),
                    u(1),
                ],
                "/0/target",
                json!("a2a"),
            ),
            (
                vec!["admin-guardrails".to_owned(), "list".into()],
                "/0/status",
                json!("paused"),
            ),
            (
                vec!["integrations".to_owned(), "get".into(), u(fx::INTEGRATION)],
                "/pricing_adjustments/multiplier/newUnit",
                json!(2),
            ),
        ] {
            let mut full = refs(&args);
            full.extend(["--output", "json"]);
            let Some((r, t)) = sides_seeded(
                "d178_unfamiliar_gateway_vocabulary_is_printed",
                &full,
                &seed,
            ) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.run.json().pointer(pointer), Some(&value), "{full:?}");
            t.run.assert_code(1);
            assert!(
                t.run.stderr.contains("AISEC_RESPONSE_VALIDATION"),
                "{full:?}: {}",
                t.run.stderr
            );
        }
    }

    /// D1 (extended): a missing required `--workspace` is a usage error (exit 2; TS:
    /// commander, exit 1).
    #[test]
    fn d1_missing_required_options_are_usage_errors() {
        let Some((r, t)) = sides("d1_missing_required_options", &["configs", "list"]) else {
            return;
        };
        r.run.assert_code(2);
        t.run.assert_code(1);
        assert!(
            t.run
                .stderr
                .contains("required option '--workspace <uuid>' not specified"),
            "{}",
            t.run.stderr
        );
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// D11, D52 (extended): an inventory error prints the §6 message, never the server's
    /// text; TypeScript prints the message verbatim, control characters included.
    #[test]
    fn d11_d52_inventory_server_text_is_not_echoed() {
        let plan = |server: &FixtureServer| {
            server.set_default(
                Route::Gateway(Gw::DeploymentGet),
                Planned::json(400, &json!({"message": "bad SERVERTEXT \u{1b}[31m"})),
            );
        };
        let Some((r, t)) = sides_with(
            "d11_d52_inventory_server_text_is_not_echoed",
            &["deployments", "get", &u(fx::DEPLOYMENT)],
            &unchanged,
            &plan,
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert!(!r.run.stderr.contains("SERVERTEXT"), "{}", r.run.stderr);
        assert!(
            t.run.stderr.contains("SERVERTEXT \u{1b}[31m"),
            "{}",
            t.run.stderr
        );
    }

    /// D50 (extended): `markdown`, `csv` and `yaml` are usage errors before the tenant on
    /// the inventory reads; TypeScript renders them.
    #[test]
    fn d50_dropped_formats_on_inventory_reads() {
        for format in ["markdown", "csv", "yaml"] {
            let Some((r, t)) = sides(
                "d50_dropped_formats_on_inventory_reads",
                &["deployments", "list", "--output", format],
            ) else {
                return;
            };
            r.run.assert_code(2);
            assert!(r.requests.is_empty());
            t.run.assert_success();
        }
    }
}
