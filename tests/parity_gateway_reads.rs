//! TS-vs-Rust parity for the M6e chunk-1 gateway reads (DESIGN §19.1–§19.8):
//! `gateway workspaces list|get`, `gateway scopes list|get` and every `gateway telemetry`
//! read (TS `aigateway …`, renamed, D227).
//!
//! Each scenario runs once against airs-cli-rs (`gateway …`) and once against the
//! TypeScript reference (`aigateway …`), each on a fresh [`FixtureServer`] seeded with the
//! gateway dataset and a fresh [`Sandbox`] whose tenant points the data, admin and IAM
//! endpoints at the server (the TypeScript client passes all three explicitly, GW§0, and
//! its runs get `TZ=UTC`, G41). `parity` tests compare exit codes, stdout bytes (pretty and
//! table) or JSON (json), stderr and the requests, window queries as instants.
//! `divergence` tests pin both sides of each §12 row this chunk implements (named by its
//! D#). The TypeScript side may print the fixture markers (D238), so its runs disable the
//! marker check; the airs-cli-rs runs keep it.

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
const BANNER: &str = "\n  Prisma AIRS — AI Gateway\n  Gateway workspace operations\n\n";
/// A pinned window (D242 compares instants; both sides send `+00:00` under `TZ=UTC`).
const WINDOW: [&str; 4] = [
    "--start",
    "2026-10-01T00:00:00Z",
    "--end",
    "2026-10-02T00:00:00Z",
];

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
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

/// Runs `cli` (`gateway <args>` or, for TypeScript, `aigateway <args>`) on a fresh seeded
/// server and sandbox; `seed` edits the dataset; `plan` queues planned answers.
fn exec_with(
    cli: &Cli,
    args: &[&str],
    seed: &dyn Fn(&mut GatewayData),
    plan: &dyn Fn(&FixtureServer),
    options: &RunOptions,
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
        options.clone().allow_secret_output()
    } else {
        options.clone()
    };
    let out = run(cli, &sandbox, &full, &options);
    server.assert_no_unknown_routes();
    Side {
        run: out,
        requests: server.requests(),
    }
}

fn exec(cli: &Cli, args: &[&str], seed: &dyn Fn(&mut GatewayData)) -> Side {
    exec_with(cli, args, seed, &|_| {}, &RunOptions::new())
}

/// Both sides (`None` after a `PARITY SKIPPED` notice).
fn sides_seeded(
    name: &str,
    args: &[&str],
    seed: &dyn Fn(&mut GatewayData),
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((exec(&rust(), args, seed), exec(&ts, args, seed)))
}

fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_seeded(name, args, &unchanged)
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// The data-plane status line, which airs-cli-rs prints in every format (choice 8; TS:
/// pretty only).
const DATA_PLANE_NOTE: &str = "  Data-plane list shows only active workspaces you are scoped to — use --plane admin or --all for the whole tenant.\n";

/// The Rust stderr without the status lines TypeScript prints only in pretty (choice 8).
fn rust_stderr(r: &Side) -> String {
    let pretty = !r.run.args.iter().any(|arg| arg == "table" || arg == "json");
    if pretty {
        r.run.stderr.clone()
    } else {
        r.run.stderr.replace(DATA_PLANE_NOTE, "")
    }
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
        rust_stderr(r),
        t.run.stderr,
        "stderr differs{}",
        context(r, t)
    );
    assert_requests(r, t);
}

/// The request lines. With `--all`, TS reads the two admin lists concurrently, so its
/// order varies; Rust reads active, then archived (choice 15), and the two sides are
/// compared as sets.
fn assert_requests(r: &Side, t: &Side) {
    if r.run.args.iter().any(|arg| arg == "--all") {
        let mut ts_api = t.api();
        ts_api.sort();
        let mut rust_api = r.api();
        assert_eq!(
            rust_api,
            [
                "GET /ai_gw/admin/v2/workspaces",
                "GET /ai_gw/admin/v2/workspaces?status=archived"
            ],
            "Rust reads active, then archived{}",
            context(r, t)
        );
        rust_api.sort();
        assert_eq!(rust_api, ts_api, "requests differ{}", context(r, t));
    } else {
        assert_eq!(r.api(), t.api(), "requests differ{}", context(r, t));
    }
}

/// The arguments with the pinned window appended.
fn windowed<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut all = args.to_vec();
    all.extend_from_slice(&WINDOW);
    all
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The workspace and scope reads in pretty and table, byte for byte (the banner, the
    /// sections and the data lines), with the requests. `workspaces get` and `scopes get`
    /// in `table` print YAML on the TypeScript side (D231), so their pretty bytes only.
    #[test]
    fn workspace_and_scope_reads_match_typescript() {
        for args in [
            &["workspaces", "list"][..],
            &["workspaces", "ls", "--output", "table"],
            &["workspace", "list", "--plane", "admin"],
            &[
                "workspaces",
                "list",
                "--plane",
                "admin",
                "--status",
                "archived",
            ],
            &[
                "workspaces",
                "list",
                "--plane",
                "admin",
                "--output",
                "table",
            ],
            &["workspaces", "list", "--all"],
            &["workspaces", "list", "--all", "--output", "table"],
            &["workspaces", "get", "ws-main-a-349e0e"],
            &["workspaces", "get", &fx::uuid(1)],
            &["workspaces", "get", "ws-produc-985697", "--plane", "admin"],
            &["workspaces", "get", "Production", "--plane", "admin"],
            &["scopes", "list"],
            &["scopes", "ls", "--output", "table"],
            &["scopes", "get", "ws_production_bx7qw0"],
            &["scopes", "get", "ws_orphan_zzzzzz"],
        ] {
            let Some((r, t)) = sides("workspace_and_scope_reads_match_typescript", args) else {
                return;
            };
            r.run.assert_success();
            assert_bytes(&r, &t);
        }
    }

    /// JSON documents compared as JSON (D35).
    #[test]
    fn json_documents_match_typescript() {
        for args in [
            &["workspaces", "list", "--output", "json"][..],
            &["workspaces", "list", "--all", "--output", "json"],
            &["workspaces", "get", "ws-main-a-349e0e", "--output", "json"],
            &[
                "workspaces",
                "get",
                "ws-produc-985697",
                "--plane",
                "admin",
                "--output",
                "json",
            ],
            &["scopes", "list", "--output", "json"],
            &[
                "scopes",
                "get",
                "main_airs_workspace_1852583913",
                "--output",
                "json",
            ],
        ] {
            let Some((r, t)) = sides("json_documents_match_typescript", args) else {
                return;
            };
            r.run.assert_success();
            t.run.assert_success();
            assert_json_semantic_eq(&r.run.json(), &t.run.json());
            assert_eq!(rust_stderr(&r), t.run.stderr, "{args:?}");
            assert_requests(&r, &t);
        }
    }

    /// Every telemetry read in pretty and table: TS's `Field │ Value` envelope table
    /// (choice 9), the window and filters in TS key order. TypeScript sends `--workspace`
    /// unresolved (D235), so the Rust side reads the data-plane list first.
    #[test]
    fn telemetry_reads_match_typescript() {
        let leaves: [&[&str]; 18] = [
            &["telemetry", "errors"],
            &["telemetry", "users"],
            &["telemetry", "error-trends"],
            &["telemetry", "error-category-trends"],
            &["telemetry", "grouped-errors"],
            &["telemetry", "rescued-retries"],
            &["telemetry", "user-trends"],
            &["telemetry", "cache", "summary"],
            &["telemetry", "cache", "trend"],
            &["telemetry", "feedback", "distribution"],
            &["telemetry", "feedback", "models"],
            &["telemetry", "feedback", "trend"],
            &["telemetry", "feedback", "weighted"],
            &["telemetry", "latency"],
            &["telemetry", "requests"],
            &["telemetry", "tokens"],
            &["telemetry", "group-by", "model"],
            &["telemetry", "logs", "list"],
        ];
        for leaf in leaves {
            for format in ["pretty", "table"] {
                let mut args = leaf.to_vec();
                args.extend(["--workspace", "ws-main-a-349e0e", "--output", format]);
                let args = windowed(&args);
                let Some((r, t)) = sides("telemetry_reads_match_typescript", &args) else {
                    return;
                };
                r.run.assert_success();
                assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
                assert_eq!(r.run.stdout, t.run.stdout, "{args:?}{}", context(&r, &t));
                assert_eq!(r.run.stderr, t.run.stderr, "{args:?}{}", context(&r, &t));
                let rust_api = r.api();
                assert_eq!(rust_api[0], "GET /ai_gw/v2/workspaces", "{args:?}");
                assert_eq!(rust_api[1..], t.api()[..], "{args:?}");
            }
        }
    }
    /// The request lines with the rolling window's two instants replaced, and the window's
    /// length in milliseconds (both CLIs compute `now` on their own).
    fn rolling(side: &Side) -> (Vec<String>, Vec<i64>) {
        let mut spans = Vec::new();
        let lines = side
            .requests
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(|request| {
                let instant = |key: &str| {
                    request
                        .query
                        .iter()
                        .find(|(name, _)| name == key)
                        .map(|(_, value)| value.clone())
                };
                if let (Some(min), Some(max)) = (
                    instant("timeOfGenerationMin"),
                    instant("timeOfGenerationMax"),
                ) {
                    let ms = |text: &str| utc_ms(text);
                    spans.push(ms(&max) - ms(&min));
                    request
                        .line()
                        .replace(&min, "<min>")
                        .replace(&urlencode(&min), "<min>")
                        .replace(&max, "<max>")
                        .replace(&urlencode(&max), "<max>")
                } else {
                    request.line()
                }
            })
            .collect();
        (lines, spans)
    }

    /// `YYYY-MM-DDTHH:MM:SS+00:00` in epoch milliseconds.
    fn utc_ms(text: &str) -> i64 {
        assert!(text.ends_with("+00:00"), "{text}");
        let number = |range: std::ops::Range<usize>| text[range].parse::<i64>().unwrap();
        let (year, month, day) = (number(0..4), number(5..7), number(8..10));
        let (y, m) = if month <= 2 {
            (year - 1, month + 9)
        } else {
            (year, month - 3)
        };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * m + 2) / 5 + day - 1;
        let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
        ((days * 24 + number(11..13)) * 60 + number(14..16)) * 60_000 + number(17..19) * 1000
    }

    fn urlencode(text: &str) -> String {
        airs_test_harness::percent_encode(text)
    }

    /// `telemetry cost` in every format, the 7-day default and `--days 30`, a UUID and a
    /// display name resolved to the slug, the filters in TS key order.
    #[test]
    fn cost_matches_typescript() {
        let filters = [
            "--trace-id",
            "owned",
            "--metadata",
            r#"{"environment":"dev"}"#,
            "--status-codes",
            "200, 446",
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
            "1.25e-1",
        ];
        let uuid = fx::uuid(1);
        let mut with_filters = vec!["telemetry", "cost", "--workspace", "Main A"];
        with_filters.extend_from_slice(&filters);
        for (args, days) in [
            (
                vec!["telemetry", "cost", "--workspace", "ws-main-a-349e0e"],
                7,
            ),
            (
                vec![
                    "telemetry",
                    "cost",
                    "--workspace",
                    &uuid,
                    "--days",
                    "30",
                    "--output",
                    "table",
                ],
                30,
            ),
            (
                vec![
                    "telemetry",
                    "cost",
                    "--workspace",
                    "Main A",
                    "--output",
                    "json",
                ],
                7,
            ),
            (with_filters.clone(), 7),
        ] {
            let Some((r, t)) = sides("cost_matches_typescript", &args) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
            if args.contains(&"json") {
                assert_json_semantic_eq(&r.run.json(), &t.run.json());
            } else {
                assert_eq!(r.run.stdout, t.run.stdout, "{args:?}{}", context(&r, &t));
            }
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}");
            let (rust_lines, rust_spans) = rolling(&r);
            let (mut ts_lines, ts_spans) = rolling(&t);
            if args[3] == "Main A" {
                // A display name: TS stops at the data-plane match; Rust first reads the
                // admin lists for an exact id or slug (choice 127, D235).
                ts_lines.splice(
                    1..1,
                    [
                        "GET /ai_gw/admin/v2/workspaces".to_owned(),
                        "GET /ai_gw/admin/v2/workspaces?status=archived".to_owned(),
                    ],
                );
            }
            assert_eq!(rust_lines, ts_lines, "{args:?}");
            assert_eq!(rust_spans, [days * 86_400_000]);
            assert_eq!(ts_spans, [days * 86_400_000]);
        }
    }

    /// The filtered metrics, `group-by` (every dimension, `--columns`) and `logs list`
    /// paging send TS's query keys in TS order.
    #[test]
    fn telemetry_queries_match_typescript() {
        let filters = [
            "--trace-id",
            "owned",
            "--metadata",
            r#"{"environment":"dev"}"#,
            "--status-codes",
            "200,446",
            "--total-units-min",
            "0",
            "--cost-max",
            "0.125",
        ];
        let mut cases: Vec<Vec<&str>> = Vec::new();
        for metric in ["latency", "requests", "tokens"] {
            let mut args = vec!["telemetry", metric, "--workspace", "ws-main-a-349e0e"];
            args.extend_from_slice(&filters);
            cases.push(args);
        }
        for dimension in [
            "ai_service",
            "model",
            "api_key",
            "provider",
            "status_code",
            "users",
        ] {
            let mut args = vec![
                "telemetry",
                "group-by",
                dimension,
                "--workspace",
                "ws-main-a-349e0e",
            ];
            args.extend_from_slice(&filters);
            if dimension != "users" {
                args.extend(["--columns", "cost, total_tokens"]);
            }
            cases.push(args);
        }
        cases.push(vec![
            "telemetry",
            "logs",
            "ls",
            "--workspace",
            "ws-main-a-349e0e",
            "--page-size",
            "2",
            "--current-page",
            "1",
            "--status-code",
            "200",
            "--trace-id",
            "trace-3",
        ]);
        for args in cases {
            let mut args = args.clone();
            args.extend(["--output", "json"]);
            let args = windowed(&args);
            let Some((r, t)) = sides("telemetry_queries_match_typescript", &args) else {
                return;
            };
            r.run.assert_success();
            t.run.assert_success();
            assert_json_semantic_eq(&r.run.json(), &t.run.json());
            assert_eq!(r.api()[1..], t.api()[..], "{args:?}");
        }
    }

    /// TS `sdk-gateway-telemetry.spec.ts`: an empty latency keeps its `null` aggregates.
    #[test]
    fn null_aggregates_are_kept() {
        let empty = |data: &mut GatewayData| {
            data.charts.insert(
                "latency".into(),
                json!({"success": true, "data": {
                    "records": [{"x": "2026-09-06T00:00:00.000Z", "y": 0, "p50": 0, "p90": 0, "p99": 0}],
                    "total": null, "p50": null, "p90": null, "p99": null, "isQuotaExceeded": false
                }}),
            );
        };
        let Some((r, t)) = sides_seeded(
            "null_aggregates_are_kept",
            &windowed(&[
                "telemetry",
                "latency",
                "--workspace",
                "ws-main-a-349e0e",
                "--output",
                "json",
            ]),
            &empty,
        ) else {
            return;
        };
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        assert_eq!(r.run.json()["data"]["total"], Value::Null);
    }

    /// The tenant's `defaultOutput` applies to every gateway read (choice 5, TS).
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
            let group = if cli.is_ts() { "aigateway" } else { "gateway" };
            let options = if cli.is_ts() {
                RunOptions::new().allow_secret_output()
            } else {
                RunOptions::new()
            };
            let out = run(&cli, &sandbox, &[group, "scopes", "list"], &options);
            out.assert_success();
            assert_eq!(
                out.json()[0]["name"],
                "main_airs_workspace_1852583913",
                "{}",
                cli.label()
            );
        }
    }

    /// Every gateway group and chunk-1 leaf carries TypeScript's descriptions, option texts
    /// and examples (program `airs`, `aigateway` read as `gateway`; §19.2), the
    /// non-`cost` `--workspace` help aside (D235); the groups list chunk 1's commands in
    /// TypeScript's sorted order.
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
        let section = |text: &str, title: &str| -> Vec<String> {
            let mut lines = text.lines();
            if !lines.any(|line| line == title) {
                return Vec::new();
            }
            lines
                .take_while(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect()
        };
        let entries = |text: &str, title: &str| -> Vec<(String, String)> {
            let mut out: Vec<(String, String)> = Vec::new();
            for line in section(text, title) {
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
        let built = [
            // chunk 2's groups (their leaves: tests/parity_gateway_inventory.rs)
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
            "workspaces",
            "scopes",
            "telemetry",
            "list",
            "get",
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
            "summary",
            "trend",
            "distribution",
            "models",
            "weighted",
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
        let groups: [&[&str]; 7] = [
            &[],
            &["workspaces"],
            &["scopes"],
            &["telemetry"],
            &["telemetry", "cache"],
            &["telemetry", "feedback"],
            &["telemetry", "logs"],
        ];
        for path in groups {
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
            let ts_about = t.lines().nth(2).unwrap_or_default().to_owned();
            if !r.contains(&ts_about) {
                problems.push(format!("{path:?} description: {ts_about:?}"));
            }
        }
        let leaves: [&[&str]; 24] = [
            &["workspaces", "list"],
            &["workspaces", "get"],
            &["scopes", "list"],
            &["scopes", "get"],
            &["telemetry", "cache", "summary"],
            &["telemetry", "cache", "trend"],
            &["telemetry", "cost"],
            &["telemetry", "error-category-trends"],
            &["telemetry", "error-trends"],
            &["telemetry", "errors"],
            &["telemetry", "feedback", "distribution"],
            &["telemetry", "feedback", "models"],
            &["telemetry", "feedback", "trend"],
            &["telemetry", "feedback", "weighted"],
            &["telemetry", "filter-boundaries"],
            &["telemetry", "group-by"],
            &["telemetry", "grouped-errors"],
            &["telemetry", "latency"],
            &["telemetry", "logs", "list"],
            &["telemetry", "requests"],
            &["telemetry", "rescued-retries"],
            &["telemetry", "tokens"],
            &["telemetry", "user-trends"],
            &["telemetry", "users"],
        ];
        for path in leaves {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let command = path.join(" ");
            let rust_options = entries(&r, "Options:");
            for (flag, description) in entries(&t, "Options:") {
                if matches!(flag.as_str(), "--help" | "--output") {
                    continue;
                }
                // D235: every non-`cost` `--workspace` is resolved like `cost`'s.
                let description = if flag == "--workspace" {
                    "Workspace slug, UUID, or unique display name".to_owned()
                } else {
                    description
                };
                match rust_options.iter().find(|(f, _)| *f == flag) {
                    Some((_, actual)) if *actual == description => {}
                    other => {
                        problems.push(format!("{command} {flag}: {other:?} vs {description:?}"))
                    }
                }
            }
            let ts_about = t.lines().nth(2).unwrap_or_default().to_owned();
            if !r.contains(&ts_about) {
                problems.push(format!("{command} description: {ts_about:?}"));
            }
            if let Some(examples) = t.split("Examples:\n").nth(1) {
                let expected = examples
                    .trim_end()
                    .replace("airs-cli aigateway ", "airs gateway ");
                if !r.contains(&expected) {
                    problems.push(format!("{command} examples: {expected:?}"));
                }
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
    use airs_test_harness::spawn;
    use std::time::Duration;

    /// The 403 grant hint text (TS `aiGatewayGrantHint`), workspace-scope or admin.
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

    /// D227: the group is `gateway`; `aigateway` is not an alias. The help examples name
    /// `airs-cli-rs gateway`.
    #[test]
    fn d227_the_group_is_gateway_without_an_aigateway_alias() {
        let Some(ts) = require_ts("d227_the_group_is_gateway_without_an_aigateway_alias") else {
            return;
        };
        let server = FixtureServer::start();
        server.seed_gateway();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let r = run(
            &rust(),
            &sandbox,
            &["aigateway", "workspaces", "list"],
            &RunOptions::new(),
        );
        r.assert_code(2);
        assert!(
            r.stderr.contains("unrecognized subcommand 'aigateway'"),
            "{}",
            r.stderr
        );
        let t = run(
            &ts,
            &sandbox,
            &["aigateway", "workspaces", "list"],
            &RunOptions::new(),
        );
        t.assert_success();
        let r = run(
            &rust(),
            &sandbox,
            &["gateway", "workspaces", "list"],
            &RunOptions::new(),
        );
        r.assert_success();
        assert_eq!(r.stdout, t.stdout);
        let help = run(
            &rust(),
            &sandbox,
            &["gateway", "telemetry", "cost", "--help"],
            &RunOptions::new(),
        );
        assert!(
            help.stdout
                .contains("  $ airs gateway telemetry cost --workspace ws-main-a-349e0e\n")
        );
        let help = run(
            &ts,
            &sandbox,
            &["aigateway", "telemetry", "cost", "--help"],
            &RunOptions::new(),
        );
        assert!(
            help.stdout
                .contains("  $ airs-cli aigateway telemetry cost --workspace ws-main-a-349e0e\n")
        );
    }

    /// D230: the grant hint goes to stderr (TS: stdout, before the error), the banner
    /// needs a successful pretty run (TS prints it on failing runs), `--quiet` keeps the
    /// workspace id lines (TS drops them) and the cost quota warning is a stderr line (TS:
    /// inside the pretty data).
    #[test]
    fn d230_streams_banner_and_quiet() {
        let plan = |server: &FixtureServer| {
            server.set_default(
                Route::Gateway(Gw::DataWorkspaces),
                Planned::json(403, &json!({"message": "Forbidden"})),
            );
        };
        let Some(ts) = require_ts("d230_streams_banner_and_quiet") else {
            return;
        };
        let r = exec_with(
            &rust(),
            &["workspaces", "list"],
            &unchanged,
            &plan,
            &RunOptions::new(),
        );
        let t = exec_with(
            &ts,
            &["workspaces", "list"],
            &unchanged,
            &plan,
            &RunOptions::new(),
        );
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert_eq!(t.run.stdout, format!("{BANNER}{}", hint(false)));
        assert_eq!(r.run.stdout, "");
        assert!(r.run.stderr.starts_with(&hint(true)), "{}", r.run.stderr);
        let Some((r, t)) = sides(
            "d230_streams_banner_and_quiet",
            &["--quiet", "workspaces", "list"],
        ) else {
            return;
        };
        assert!(!t.run.stdout.contains(&fx::uuid(1)));
        assert!(r.run.stdout.starts_with(&format!("  {}\n", fx::uuid(1))));
        let quota = |data: &mut GatewayData| {
            data.charts.get_mut("cost").unwrap()["data"]["isQuotaExceeded"] = json!(true);
        };
        let Some((r, t)) = sides_seeded(
            "d230_streams_banner_and_quiet",
            &["telemetry", "cost", "--workspace", "ws-main-a-349e0e"],
            &quota,
        ) else {
            return;
        };
        let warning = "  ⚠ Telemetry quota exceeded — data may be truncated\n";
        assert!(t.run.stdout.contains(warning));
        assert!(!r.run.stdout.contains(warning));
        assert_eq!(r.run.stderr, warning);
        assert_eq!(r.run.stdout, t.run.stdout.replace(warning, ""));
    }

    /// D231: `table` prints a table (TS: YAML for `workspaces get` and `scopes get`), an
    /// empty json list prints `[]` (TS: the empty phrase) and an empty table nothing.
    #[test]
    fn d231_each_format_prints_its_own_document() {
        for args in [
            &["workspaces", "get", "ws-main-a-349e0e", "--output", "table"][..],
            &["scopes", "get", "ws_orphan_zzzzzz", "--output", "table"],
        ] {
            let Some((r, t)) = sides("d231_each_format_prints_its_own_document", args) else {
                return;
            };
            assert!(
                t.run.stdout.contains(": "),
                "TS prints YAML: {}",
                t.run.stdout
            );
            assert!(r.run.stdout.starts_with(" Key "), "{}", r.run.stdout);
            assert!(r.run.stdout.contains("│"));
        }
        let none = |data: &mut GatewayData| {
            data.data_plane.clear();
            data.scopes.clear();
        };
        for (args, ts_text) in [
            (
                &["workspaces", "list", "--output", "json"][..],
                "  No workspaces found\n",
            ),
            (
                &["workspaces", "list", "--output", "table"],
                "  No workspaces found\n",
            ),
            (
                &["scopes", "list", "--output", "table"],
                "  No IAM scopes found\n",
            ),
        ] {
            let Some((r, t)) =
                sides_seeded("d231_each_format_prints_its_own_document", args, &none)
            else {
                return;
            };
            assert_eq!(t.run.stdout, ts_text, "{args:?}");
            let expected = if args.contains(&"json") { "[]\n" } else { "" };
            assert_eq!(r.run.stdout, expected, "{args:?}");
        }
        let empty = |data: &mut GatewayData| {
            data.charts.insert("errors".into(), json!({"success": true, "data": {"records": [], "total": null, "isQuotaExceeded": false}}));
        };
        let Some((r, t)) = sides_seeded(
            "d231_each_format_prints_its_own_document",
            &windowed(&[
                "telemetry",
                "errors",
                "--workspace",
                "ws-main-a-349e0e",
                "--output",
                "json",
            ]),
            &empty,
        ) else {
            return;
        };
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
    }

    /// D232: argument checks are usage errors before the tenant (TS: the tenant first,
    /// exit 1, for the workspace ref, the scope name and the window of a metric read).
    #[test]
    fn d232_argument_checks_come_before_the_tenant() {
        let Some(ts) = require_ts("d232_argument_checks_come_before_the_tenant") else {
            return;
        };
        for args in [
            &["workspaces", "get", "Main A"][..],
            &["scopes", "get", "bad/name"],
            &["telemetry", "errors", "--workspace", "w", "--days", "0"],
            &[
                "telemetry",
                "logs",
                "list",
                "--workspace",
                "w",
                "--current-page",
                "x",
            ],
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
            "d232_argument_checks_come_before_the_tenant",
            &["workspaces", "get", "Main A"],
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

    /// D234: the hint follows the service code and the plane, on stderr: a data-plane 403
    /// with a top-level `errorCode: AB03` gets the workspace-scope hint (TS: the admin hint,
    /// its message never carries the code), an IAM 403 none (TS: the admin hint), an
    /// admin-plane 403 the admin hint on both.
    #[test]
    fn d234_the_grant_hint_follows_the_code_and_the_plane() {
        let Some(ts) = require_ts("d234_the_grant_hint_follows_the_code_and_the_plane") else {
            return;
        };
        let coded = json!({"message": "Forbidden", "errorCode": "AB03"});
        let plain = json!({"message": "Forbidden"});
        for (route, args, body, rust_hint) in [
            (
                Gw::DataWorkspaces,
                &["workspaces", "list"][..],
                &coded,
                Some(hint(true)),
            ),
            (Gw::ScopeList, &["scopes", "list"], &coded, None),
            (
                Gw::AdminWorkspaces,
                &["workspaces", "list", "--plane", "admin"],
                &plain,
                Some(hint(false)),
            ),
        ] {
            let plan = |server: &FixtureServer| {
                server.set_default(Route::Gateway(route), Planned::json(403, body));
            };
            let r = exec_with(&rust(), args, &unchanged, &plan, &RunOptions::new());
            let t = exec_with(&ts, args, &unchanged, &plan, &RunOptions::new());
            r.run.assert_code(1);
            t.run.assert_code(1);
            assert!(
                t.run.stdout.ends_with(&hint(false)),
                "{args:?}: {}",
                t.run.stdout
            );
            assert!(!r.run.stdout.contains("403"));
            match rust_hint {
                Some(text) => assert!(
                    r.run.stderr.starts_with(&text),
                    "{args:?}: {}",
                    r.run.stderr
                ),
                None => assert!(!r.run.stderr.contains("⚠"), "{args:?}: {}", r.run.stderr),
            }
            assert_eq!(
                r.run.stderr.contains("(errorCode: AB03)"),
                body.get("errorCode").is_some(),
                "{}",
                r.run.stderr
            );
        }
    }

    /// D235: references resolve fail-closed. A metric read sends the slug of a display name
    /// (TS sends the name as a slug); an unmatched `cost` reference is refused with nothing
    /// sent (TS sends it as typed); a failing data-plane list is an error (TS skips it);
    /// `get` resolves a name on the requested plane only (TS also lists the admin plane).
    #[test]
    fn d235_workspace_references_resolve_fail_closed() {
        let Some((r, t)) = sides(
            "d235_workspace_references_resolve_fail_closed",
            &windowed(&[
                "telemetry",
                "errors",
                "--workspace",
                "Production",
                "--output",
                "json",
            ]),
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        assert!(
            t.api()[0].contains("workspaceSlug=Production&"),
            "{:?}",
            t.api()
        );
        // A display name is matched only after every list was read for an exact id or
        // slug (choice 127).
        assert_eq!(
            r.api()[..3],
            [
                "GET /ai_gw/v2/workspaces",
                "GET /ai_gw/admin/v2/workspaces",
                "GET /ai_gw/admin/v2/workspaces?status=archived"
            ]
        );
        assert!(
            r.api()[3].contains("workspaceSlug=ws-produc-985697&"),
            "{:?}",
            r.api()
        );
        let Some((r, t)) = sides(
            "d235_workspace_references_resolve_fail_closed",
            &["telemetry", "cost", "--workspace", "NoSuch"],
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert_eq!(
            airs_test_harness::error_line(&r.run.stderr).as_deref(),
            Some("Workspace 'NoSuch' was not found on the data and admin planes; nothing was sent")
        );
        assert_eq!(
            r.api(),
            [
                "GET /ai_gw/v2/workspaces",
                "GET /ai_gw/admin/v2/workspaces",
                "GET /ai_gw/admin/v2/workspaces?status=archived"
            ]
        );
        t.run.assert_success();
        assert!(t.api().last().unwrap().contains("workspaceSlug=NoSuch&"));
        let Some(ts) = require_ts("d235_workspace_references_resolve_fail_closed") else {
            return;
        };
        let plan = |server: &FixtureServer| {
            server.set_default(
                Route::Gateway(Gw::DataWorkspaces),
                Planned::json(403, &json!({"message": "Forbidden"})),
            );
        };
        let args = [
            "telemetry",
            "cost",
            "--workspace",
            "Production",
            "--output",
            "json",
        ];
        let r = exec_with(&rust(), &args, &unchanged, &plan, &RunOptions::new());
        let t = exec_with(&ts, &args, &unchanged, &plan, &RunOptions::new());
        r.run.assert_code(1);
        assert!(
            !r.api().iter().any(|line| line.contains("/logs/")),
            "{:?}",
            r.api()
        );
        t.run.assert_success();
        assert_eq!(t.run.json()["workspaceSlug"], "ws-produc-985697");
        let Some((r, t)) = sides(
            "d235_workspace_references_resolve_fail_closed",
            &["workspaces", "get", "Production"],
        ) else {
            return;
        };
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert_eq!(
            r.api(),
            [
                "GET /ai_gw/v2/workspaces/Production",
                "GET /ai_gw/v2/workspaces"
            ]
        );
        assert_eq!(
            t.api(),
            [
                "GET /ai_gw/v2/workspaces/Production",
                "GET /ai_gw/v2/workspaces",
                "GET /ai_gw/admin/v2/workspaces",
                "GET /ai_gw/v2/workspaces/ws-produc-985697"
            ]
        );
    }

    /// D238 (chunk 1): one withholding policy. `filter-boundaries` `data` is `[withheld]`
    /// (TS `[REDACTED]`), and a credential-named log member is withheld (TS prints it).
    #[test]
    fn d238_telemetry_documents_are_withheld() {
        let Some((r, t)) = sides(
            "d238_telemetry_documents_are_withheld",
            &windowed(&[
                "telemetry",
                "filter-boundaries",
                "--workspace",
                "ws-main-a-349e0e",
                "--output",
                "json",
            ]),
        ) else {
            return;
        };
        assert_eq!(t.run.json()["data"], "[REDACTED]");
        assert_eq!(r.run.json()["data"], "[withheld]");
        assert!(!t.api()[0].contains("organisationId="));
        assert_eq!(r.api()[1], t.api()[0]);
        let secret = |data: &mut GatewayData| {
            data.logs[0]["upstream_token"] = json!(fx::marker(1));
        };
        let Some((r, t)) = sides_seeded(
            "d238_telemetry_documents_are_withheld",
            &windowed(&[
                "telemetry",
                "logs",
                "list",
                "--workspace",
                "ws-main-a-349e0e",
                "--output",
                "json",
            ]),
            &secret,
        ) else {
            return;
        };
        assert_eq!(
            t.run.json()["data"]["records"][0]["upstream_token"],
            fx::marker(1)
        );
        assert_eq!(
            r.run.json()["data"]["records"][0]["upstream_token"],
            "[withheld]"
        );
    }

    /// D242: the window takes the zod offset grammar, is sent in UTC and refuses an
    /// explicit `--days` with `--start`. TS reads `new Date` (a date-only start), sends the
    /// host's offset (`TZ=Asia/Kolkata`: `+05:30`) and ignores `--days`.
    #[test]
    fn d242_windows_take_the_offset_grammar_and_utc() {
        let args = [
            "telemetry",
            "errors",
            "--workspace",
            "ws-main-a-349e0e",
            "--start",
            "2026-10-01T00:00:00Z",
            "--end",
            "2026-10-02T00:00:00Z",
            "--output",
            "json",
        ];
        let Some(ts) = require_ts("d242_windows_take_the_offset_grammar_and_utc") else {
            return;
        };
        let kolkata = RunOptions::new().env("TZ", "Asia/Kolkata");
        let r = exec_with(&rust(), &args, &unchanged, &|_| {}, &kolkata);
        let t = exec_with(&ts, &args, &unchanged, &|_| {}, &kolkata);
        r.run.assert_success();
        t.run.assert_success();
        let query = |side: &Side| {
            side.requests
                .iter()
                .find(|request| request.path.contains("/logs/charts/"))
                .map(|request| request.query.clone())
                .unwrap()
        };
        let value = |pairs: &[(String, String)], key: &str| {
            pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
                .unwrap()
        };
        assert_eq!(
            value(&query(&r), "timeOfGenerationMin"),
            "2026-10-01T00:00:00+00:00"
        );
        assert_eq!(
            value(&query(&t), "timeOfGenerationMin"),
            "2026-10-01T05:30:00+05:30"
        );
        for extra in [
            &["--start", "2026-10-01", "--end", "2026-10-02T00:00:00Z"][..],
            &[
                "--days",
                "7",
                "--start",
                "2026-10-01T00:00:00Z",
                "--end",
                "2026-10-02T00:00:00Z",
            ],
        ] {
            let mut args = vec!["telemetry", "errors", "--workspace", "ws-main-a-349e0e"];
            args.extend_from_slice(extra);
            let Some((r, t)) = sides("d242_windows_take_the_offset_grammar_and_utc", &args) else {
                return;
            };
            r.run.assert_code(2);
            assert!(r.requests.is_empty());
            t.run.assert_success();
        }
    }

    /// D248: a workspace list whose `total` or `has_more` says it is incomplete gets a
    /// stderr warning (exit 0); TS prints it as complete.
    #[test]
    fn d248_incomplete_lists_warn() {
        let partial = |data: &mut GatewayData| {
            data.list_total = Some(json!(5));
            data.scope_count = Some(json!(9));
        };
        for (args, warning) in [
            (
                &["workspaces", "list", "--output", "json"][..],
                "  ⚠ The service returned 1 of 5 workspaces; the list is incomplete (the API offers no continuation)\n",
            ),
            (
                &["scopes", "list", "--output", "json"],
                "  ⚠ The service returned 3 of 9 IAM scopes; the list is incomplete (the API offers no continuation)\n",
            ),
        ] {
            let Some((r, t)) = sides_seeded("d248_incomplete_lists_warn", args, &partial) else {
                return;
            };
            r.run.assert_success();
            t.run.assert_success();
            assert_json_semantic_eq(&r.run.json(), &t.run.json());
            assert!(r.run.stderr.contains(warning), "{}", r.run.stderr);
            assert!(!t.run.stderr.contains("incomplete"));
        }
    }

    /// D251: a URL's userinfo, query and fragment are withheld; TS prints the URL whole.
    #[test]
    fn d251_urls_lose_userinfo_and_queries() {
        let url = |data: &mut GatewayData| {
            data.logs[0]["request_url"] = json!(format!(
                "https://user:{}@api.example.test/v1/chat?key={}#frag",
                fx::marker(2),
                fx::marker(3)
            ));
        };
        let Some((r, t)) = sides_seeded(
            "d251_urls_lose_userinfo_and_queries",
            &windowed(&[
                "telemetry",
                "logs",
                "list",
                "--workspace",
                "ws-main-a-349e0e",
                "--output",
                "json",
            ]),
            &url,
        ) else {
            return;
        };
        assert!(
            t.run.json()["data"]["records"][0]["request_url"]
                .as_str()
                .unwrap()
                .contains(&fx::marker(3))
        );
        assert_eq!(
            r.run.json()["data"]["records"][0]["request_url"],
            "https://[withheld]@api.example.test/v1/chat?[withheld]#[withheld]"
        );
    }

    /// D252: an interrupted read prints its context (exit 130/143); TS exits by the signal
    /// with nothing printed.
    #[test]
    fn d252_an_interrupted_read_says_no_data_was_written() {
        let Some(ts) = require_ts("d252_an_interrupted_read_says_no_data_was_written") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_gateway();
            server.push_once(Route::Gateway(Gw::ScopeList), Planned::hang());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let group = if cli.is_ts() { "aigateway" } else { "gateway" };
            let running = spawn(
                &cli,
                &sandbox,
                &[group, "scopes", "list", "--output", "json"],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Gateway(Gw::ScopeList),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal("TERM");
            outs.push(running.wait());
        }
        assert_eq!(outs[0].code, 143);
        assert_eq!(
            outs[0].stderr,
            "\n  ✗ Error: Interrupted; no data was written\n\n"
        );
        assert_eq!(outs[1].code, 143);
        assert_eq!(outs[1].stderr, "");
    }

    /// D1 (extended): a gateway group without a subcommand prints its help on stderr
    /// (exit 2; TS: stdout, exit 0) and a missing `--workspace` is exit 2 (TS: 1).
    #[test]
    fn d1_gateway_groups_and_parse_errors() {
        for args in [
            &[][..],
            &["workspaces"],
            &["scopes"],
            &["telemetry"],
            &["telemetry", "cache"],
            &["telemetry", "feedback"],
            &["telemetry", "logs"],
        ] {
            let Some((r, t)) = sides("d1_gateway_groups_and_parse_errors", args) else {
                return;
            };
            r.run.assert_code(2);
            assert_eq!(r.run.stdout, "");
            assert!(r.run.stderr.contains("Usage: airs gateway"), "{args:?}");
            t.run.assert_success();
            assert!(
                t.run.stdout.contains("Usage: airs-cli aigateway"),
                "{args:?}"
            );
            assert!(r.requests.is_empty() && t.requests.is_empty());
        }
        let Some((r, t)) = sides(
            "d1_gateway_groups_and_parse_errors",
            &["telemetry", "errors"],
        ) else {
            return;
        };
        r.run.assert_code(2);
        t.run.assert_code(1);
        assert!(
            t.run
                .stderr
                .contains("required option '--workspace <slug>'")
        );
    }

    /// D11 and D52 (extended): a server message is not echoed (TS prints it raw), and
    /// control characters in a workspace name are replaced.
    #[test]
    fn d11_d52_gateway_server_text_is_neither_echoed_nor_raw() {
        let Some(ts) = require_ts("d11_d52_gateway_server_text_is_neither_echoed_nor_raw") else {
            return;
        };
        let plan = |server: &FixtureServer| {
            server.push_once(
                Route::Gateway(Gw::ScopeGet),
                Planned::json(409, &json!({"message": "scope \u{1b}[31mECHOED clash"})),
            );
        };
        let args = ["scopes", "get", "ws_orphan_zzzzzz"];
        let r = exec_with(&rust(), &args, &unchanged, &plan, &RunOptions::new());
        let t = exec_with(&ts, &args, &unchanged, &plan, &RunOptions::new());
        assert!(t.run.stderr.contains("\u{1b}[31mECHOED"));
        assert!(!r.run.stderr.contains("ECHOED"));
        assert!(r.run.stderr.contains("API error 409"), "{}", r.run.stderr);
        let evil = |data: &mut GatewayData| {
            data.workspaces[0]["name"] = json!("evil\u{1b}[31mRED");
        };
        let Some((r, t)) = sides_seeded(
            "d11_d52_gateway_server_text_is_neither_echoed_nor_raw",
            &["workspaces", "list"],
            &evil,
        ) else {
            return;
        };
        assert!(t.run.stdout.contains("evil\u{1b}[31mRED"));
        assert!(r.run.stdout.contains("evil\u{fffd}[31mRED"));
    }

    /// D35 (extended): unknown members are printed in sorted order (TS: as received);
    /// equal as JSON.
    #[test]
    fn d35_unknown_members_are_sorted() {
        let extra = |data: &mut GatewayData| {
            let scope = data.scopes[2].as_object_mut().unwrap();
            scope.insert("zeta".into(), json!(1));
            scope.insert("alpha".into(), json!(2));
        };
        let Some((r, t)) = sides_seeded(
            "d35_unknown_members_are_sorted",
            &[
                "telemetry",
                "errors",
                "--workspace",
                "ws-main-a-349e0e",
                "--output",
                "json",
            ],
            &|data: &mut GatewayData| {
                extra(data);
                let errors = data.charts.get_mut("errors").unwrap();
                let object = errors.as_object_mut().unwrap();
                object.insert("zeta".into(), json!(1));
                object.insert("alpha".into(), json!(2));
            },
        ) else {
            return;
        };
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        let position = |text: &str, key: &str| text.find(key).unwrap();
        assert!(position(&r.run.stdout, "\"alpha\"") < position(&r.run.stdout, "\"zeta\""));
    }

    /// D50 (extended): `markdown`, `csv` and `yaml` are usage errors before the tenant;
    /// TypeScript renders them.
    #[test]
    fn d50_dropped_formats_are_usage_errors_on_gateway_reads() {
        for format in ["markdown", "csv", "yaml"] {
            let Some((r, t)) = sides(
                "d50_dropped_formats_are_usage_errors_on_gateway_reads",
                &["scopes", "list", "--output", format],
            ) else {
                return;
            };
            assert_eq!(r.run.code, 2);
            assert!(r.requests.is_empty());
            t.run.assert_success();
        }
    }
}
