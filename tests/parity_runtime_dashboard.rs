//! TS-vs-Rust parity for `runtime dashboard *` and `runtime sessions *` (DESIGN §18.12,
//! §18.13).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript reference on
//! a fresh seeded [`FixtureServer`] and [`Sandbox`] (both clients use the tenant's
//! `mgmtDashboardEndpoint` with `x-tsg-id`). `parity` tests compare exit codes, stdout,
//! stderr and the requests; `divergence` tests pin both sides of D212, D220, D224 and D225.

use std::time::Duration;

use airs_test_harness::fixtures::runtime as fx;
use airs_test_harness::{
    Cli, FixtureServer, NormalizedRequest, Planned, Route, Run, RunOptions, RuntimeData, Rx,
    Sandbox, assert_json_semantic_eq, normalize_all, require_ts, run, spawn,
};
use serde_json::{Value, json};

const TSG: &str = "100";
const FAILED: &str = "Check credentials, query options, and any output destination. No existing file is overwritten.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    lines: Vec<String>,
}

fn unchanged(_: &mut RuntimeData) {}

fn exec_with(
    cli: &Cli,
    args: &[&str],
    seed: &dyn Fn(&mut RuntimeData),
    plan: &dyn Fn(&FixtureServer),
) -> Side {
    let server = FixtureServer::start();
    server.seed_runtime();
    server.runtime(|data| seed(data));
    plan(&server);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    let mut full = vec!["runtime"];
    full.extend_from_slice(args);
    let options = if cli.is_ts() {
        RunOptions::new().allow_secret_output()
    } else {
        RunOptions::new()
    };
    let out = run(cli, &sandbox, &full, &options);
    let raw = server.requests();
    Side {
        run: out,
        requests: normalize_all(&raw),
        lines: raw.iter().map(|request| request.line()).collect(),
    }
}

fn sides_with(
    name: &str,
    args: &[&str],
    seed: &dyn Fn(&mut RuntimeData),
    plan: &dyn Fn(&FixtureServer),
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((
        exec_with(&rust(), args, seed, plan),
        exec_with(&ts, args, seed, plan),
    ))
}

fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_with(name, args, &unchanged, &|_| {})
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

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
    assert_eq!(r.requests, t.requests, "requests differ{}", context(r, t));
}

const IDENTITY: [&str; 6] = [
    "--session-id",
    "pan_session",
    "--app-id",
    "app",
    "--app-name",
    "A & B",
];

fn page(items: &[Value], total: u64, skip: u64) -> Planned {
    Planned::json(
        200,
        &json!({"items": items, "pagination": {"total_items": total, "skip": skip, "limit": 25}}),
    )
}

mod parity {
    use super::*;

    /// Every read, pretty and json: the same JSON text (D35 order holds for these records,
    /// whose keys are in schema order), the same requests.
    #[test]
    fn reads_match_typescript() {
        let transaction = [
            &IDENTITY[..],
            &["--scan-id", "scan", "--scan-sub-req-id", "0"],
        ]
        .concat();
        let reads: Vec<Vec<&str>> = vec![
            vec!["dashboard", "applications"],
            vec![
                "dashboard",
                "applications",
                "--interval",
                "7",
                "--unit",
                "days",
                "--limit",
                "2",
                "--offset",
                "1",
            ],
            vec![
                "dashboard",
                "application",
                "--app-id",
                "uuid-shared",
                "--app-name",
                "chatbot",
                "--interval",
                "07",
            ],
            vec![
                "dashboard",
                "application-violations",
                "--app-id",
                "uuid-shared",
                "--app-name",
                "chatbot",
            ],
            vec!["dashboard", "top-applications"],
            vec![
                "dashboard",
                "violations-trend",
                "--interval",
                "24",
                "--unit",
                "hours",
            ],
            vec!["dashboard", "apps-list"],
            vec!["sessions", "chart"],
            vec!["sessions", "list", "--offset", "2"],
            vec!["sessions", "ls", "--all", "--limit", "2"],
            [&["sessions", "get"][..], &IDENTITY].concat(),
            [&["sessions", "transaction"][..], &transaction].concat(),
            vec![
                "sessions",
                "scan-content",
                "--scan-id",
                "s c",
                "--scan-sub-req-id",
                "007",
                "--show-content",
            ],
        ];
        for args in reads {
            for format in ["pretty", "json"] {
                let mut full = args.clone();
                full.extend(["--output", format]);
                let Some((r, t)) = sides("reads_match_typescript", &full) else {
                    return;
                };
                assert_bytes(&r, &t);
            }
        }
    }

    /// The `--all` stability failures, the cap and the TS generic failure line, on both
    /// sides; no 5xx retry on either.
    #[test]
    fn walks_and_failures_match_typescript() {
        let entry = fx::session_item("app", "A & B", "pan_session");
        for later in [
            page(std::slice::from_ref(&entry), 3, 1),
            page(std::slice::from_ref(&entry), 2, 1),
            page(&[], 2, 1),
            page(std::slice::from_ref(&entry), 0, 1),
        ] {
            let plan = |server: &FixtureServer| {
                server.push_once(
                    Route::Runtime(Rx::SessionsOverview),
                    page(std::slice::from_ref(&entry), 2, 0),
                );
                server.push_once(Route::Runtime(Rx::SessionsOverview), later.clone());
            };
            let Some((r, t)) = sides_with(
                "walks_and_failures_match_typescript",
                &["sessions", "list", "--all", "--output", "json"],
                &unchanged,
                &plan,
            ) else {
                return;
            };
            assert_bytes(&r, &t);
            assert_eq!(r.run.code, 1);
        }
        let Some((r, t)) = sides(
            "walks_and_failures_match_typescript",
            &[
                "sessions", "list", "--all", "--max", "1", "--output", "json",
            ],
        ) else {
            return;
        };
        assert_bytes(&r, &t);
        assert_eq!(r.run.code, 1);
        for planned in [
            Planned::json(500, &json!({"message": "SECRET BODY"})),
            Planned::json(404, &json!({"message": "SECRET BODY"})),
            Planned::raw(200, "application/json", "oops"),
        ] {
            let plan = |server: &FixtureServer| {
                server.set_default(Route::Runtime(Rx::SessionsChart), planned.clone());
            };
            let Some((r, t)) = sides_with(
                "walks_and_failures_match_typescript",
                &["sessions", "chart"],
                &unchanged,
                &plan,
            ) else {
                return;
            };
            assert_bytes(&r, &t);
            assert!(!r.run.stderr.contains("SECRET"));
        }
    }

    /// G7: a 403 is re-read once with a fresh token on both sides.
    #[test]
    fn a_rejected_read_is_re_read_once() {
        let plan = |server: &FixtureServer| {
            server.set_default(
                Route::Runtime(Rx::SessionsChart),
                Planned::json(403, &json!({"message": "SECRET BODY"})),
            );
        };
        let Some((r, t)) = sides_with(
            "a_rejected_read_is_re_read_once",
            &["sessions", "chart"],
            &unchanged,
            &plan,
        ) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert_eq!(r.run.stderr, t.run.stderr);
        assert_eq!(
            r.run.stderr,
            format!("  ✗ Dashboard operation failed (HTTP 403). {FAILED}\n")
        );
        let reads = |side: &Side| {
            side.lines
                .iter()
                .filter(|l| l.contains("sessionschart"))
                .count()
        };
        assert_eq!(reads(&r), 2);
        assert_eq!(reads(&t), 2);
    }

    /// Unit and number checks: the same usage errors (exit 2) on both sides where TypeScript
    /// checks before its tenant read too.
    #[test]
    fn usage_errors_match_typescript() {
        for args in [
            &["sessions", "chart", "--unit", "week"][..],
            &["sessions", "chart", "--interval", "1oops"],
            &["dashboard", "applications", "--interval", "14"],
            &[
                "dashboard",
                "application",
                "--app-id",
                "a",
                "--app-name",
                "n",
                "--interval",
                "1",
            ],
            &[
                "sessions",
                "scan-content",
                "--scan-id",
                "x",
                "--scan-sub-req-id",
                "0",
            ],
        ] {
            let Some((r, t)) = sides("usage_errors_match_typescript", args) else {
                return;
            };
            assert_eq!(r.run.code, 2, "{args:?}");
            assert_eq!(t.run.code, 2, "{args:?}");
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}");
            assert!(r.lines.is_empty() && t.lines.is_empty());
        }
    }
}

mod divergence {
    use super::*;

    /// D212: `table` works (TS refuses it), `yaml` is refused (TS renders it), C1 controls
    /// are escaped (TS prints them raw), and a credential error keeps its message (TS: the
    /// generic line).
    #[test]
    fn d212_formats_c1_and_store_errors() {
        let Some((r, t)) = sides(
            "d212_formats_c1_and_store_errors",
            &["sessions", "chart", "--output", "table"],
        ) else {
            return;
        };
        r.run.assert_success();
        assert!(r.run.stdout.starts_with(" Key "));
        assert_eq!(t.run.code, 2);
        assert!(
            t.run
                .stderr
                .contains("Output format 'table' is not supported here")
        );
        let Some((r, t)) = sides(
            "d212_formats_c1_and_store_errors",
            &["sessions", "chart", "--output", "yaml"],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        t.run.assert_success();
        let c1 = |data: &mut RuntimeData| {
            data.sessions[0]["application_name"] = json!("a\u{9b}31m");
        };
        let Some((r, t)) = sides_with(
            "d212_formats_c1_and_store_errors",
            &["sessions", "list", "--output", "json"],
            &c1,
            &|_| {},
        ) else {
            return;
        };
        assert!(t.run.stdout.contains('\u{9b}'));
        assert!(!r.run.stdout.contains('\u{9b}'));
        assert!(r.run.stdout.contains("a\\u009b31m"));
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        let Some(ts) = require_ts("d212_formats_c1_and_store_errors") else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_runtime();
            let sandbox = Sandbox::new();
            let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
                config.remove("mgmtClientSecret");
            });
            sandbox.register(&[&tenant], Some("prod"));
            let out = run(
                &cli,
                &sandbox,
                &["runtime", "sessions", "chart"],
                &RunOptions::new(),
            );
            out.assert_code(1);
            if cli.is_ts() {
                assert!(
                    out.stderr.contains("Dashboard operation failed"),
                    "{}",
                    out.stderr
                );
            } else {
                assert!(out.stderr.contains("mgmtClientSecret"), "{}", out.stderr);
            }
        }
    }

    /// D220: `sessions list` checks its arguments before the tenant config; TypeScript loads
    /// the config first, so a broken config turns the usage error into exit 1.
    #[test]
    fn d220_session_checks_come_before_the_tenant() {
        let Some(ts) = require_ts("d220_session_checks_come_before_the_tenant") else {
            return;
        };
        let sandbox = Sandbox::new();
        for cli in [rust(), ts] {
            let out = run(
                &cli,
                &sandbox,
                &["runtime", "sessions", "list", "--limit", "0"],
                &RunOptions::new(),
            );
            if cli.is_ts() {
                out.assert_code(1);
            } else {
                out.assert_code(2);
                assert_eq!(out.stderr, "\n  ✗ --limit must be a safe integer >= 1\n\n");
            }
        }
    }

    /// D226: an `--output-file` that names no file (`out.json/`) is refused before any
    /// request; TypeScript fetches the stored content and writes `out.json` (`resolve`).
    #[test]
    fn d226_a_scan_content_file_that_names_no_file_is_refused_first() {
        let Some(ts) = require_ts("d226_a_scan_content_file_that_names_no_file_is_refused_first")
        else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_runtime();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let file = sandbox.root().join("tmp").join("out.json");
            let given = format!("{}/", file.display());
            let options = if cli.is_ts() {
                RunOptions::new().allow_secret_output()
            } else {
                RunOptions::new()
            };
            let out = run(
                &cli,
                &sandbox,
                &[
                    "runtime",
                    "sessions",
                    "scan-content",
                    "--scan-id",
                    "s",
                    "--scan-sub-req-id",
                    "0",
                    "--output-file",
                    &given,
                ],
                &options,
            );
            if cli.is_ts() {
                out.assert_success();
                assert_eq!(server.rx_requests(Rx::ScanContent).len(), 1);
                assert!(file.is_file(), "TS writes out.json");
            } else {
                out.assert_code(1);
                assert_eq!(server.request_count(), 0);
                assert!(
                    out.stderr.contains(&format!(
                        "Cannot write {given}; check that its directory exists and is writable"
                    )),
                    "{}",
                    out.stderr
                );
                assert!(!file.exists());
            }
        }
    }

    /// D225: an existing `--output-file` and a missing directory are refused before any
    /// request (TS fetches the content first for a missing directory); `--output table`
    /// writes the JSON text (TS refuses table).
    #[test]
    fn d225_scan_content_files_are_checked_first() {
        let Some(ts) = require_ts("d225_scan_content_files_are_checked_first") else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_runtime();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let missing = sandbox.root().join("tmp").join("missing").join("scan.json");
            let missing = missing.display().to_string();
            let options = if cli.is_ts() {
                RunOptions::new().allow_secret_output()
            } else {
                RunOptions::new()
            };
            let out = run(
                &cli,
                &sandbox,
                &[
                    "runtime",
                    "sessions",
                    "scan-content",
                    "--scan-id",
                    "s",
                    "--scan-sub-req-id",
                    "0",
                    "--output-file",
                    &missing,
                ],
                &options,
            );
            out.assert_code(1);
            let reads = server.rx_requests(Rx::ScanContent).len();
            if cli.is_ts() {
                assert_eq!(reads, 1, "TS fetched the content");
            } else {
                assert_eq!(server.request_count(), 0);
                assert!(out.stderr.contains("check that its directory exists"));
            }
            let path = sandbox.root().join("tmp").join("scan.json");
            let path = path.display().to_string();
            let out = run(
                &cli,
                &sandbox,
                &[
                    "runtime",
                    "sessions",
                    "scan-content",
                    "--scan-id",
                    "s",
                    "--scan-sub-req-id",
                    "0",
                    "--output-file",
                    &path,
                    "--output",
                    "table",
                ],
                &options,
            );
            if cli.is_ts() {
                out.assert_code(2);
            } else {
                out.assert_success();
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(serde_json::from_str::<Value>(&text).is_ok());
            }
        }
    }

    /// D224: an interrupted dashboard read prints its context; TypeScript exits by the
    /// signal with nothing printed.
    #[test]
    fn d224_an_interrupted_dashboard_read_prints_its_context() {
        let Some(ts) = require_ts("d224_an_interrupted_dashboard_read_prints_its_context") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_runtime();
            server.push_once(Route::Runtime(Rx::SessionsChart), Planned::hang());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let running = spawn(
                &cli,
                &sandbox,
                &["runtime", "sessions", "chart"],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Runtime(Rx::SessionsChart),
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
}
