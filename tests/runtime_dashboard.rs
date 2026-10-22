//! Executable acceptance tests for `runtime dashboard *` and `runtime sessions *` (DESIGN
//! §18.12, §18.13), with the cases of the TypeScript
//! `tests/integration/cli/runtime-dashboard.spec.ts` ported (§18.19).
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server with the
//! seeded runtime extras dataset. The runner's leak check forbids the scan-content
//! markers everywhere except `scan-content --show-content`'s stdout (DESIGN §10 M6d).

use std::time::Duration;

use airs_test_harness::fixtures::runtime as fx;
use airs_test_harness::{
    Cli, FixtureConfig, FixtureServer, Planned, RecordedRequest, Route, Run, RunOptions, Rx,
    Sandbox, debug_log, run, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const DASH: &str = "/dashboard/v1/mgmt/dashboard/v2";
const CONTENT: &str = "/dashboard/v1/mgmt/reports/scancontent";
const FAILED: &str = "Check credentials, query options, and any output destination. No existing file is overwritten.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

fn fx() -> Fx {
    fx_with(|_| {})
}

fn fx_with(edit: impl FnOnce(&mut FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    server.seed_runtime();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

impl Fx {
    fn rt_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let mut full = vec!["runtime"];
        full.extend_from_slice(args);
        let before = self.sandbox.snapshot();
        let out = run(&rust(), &self.sandbox, &full, options);
        self.sandbox.assert_unchanged(&before);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        out
    }

    fn rt(&self, args: &[&str]) -> Run {
        self.rt_with(args, &RunOptions::new())
    }

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
}

const IDENTITY: [&str; 6] = [
    "--session-id",
    "pan_session",
    "--app-id",
    "app",
    "--app-name",
    "A & B",
];

fn failure(status: Option<u16>) -> String {
    let status = status.map_or_else(String::new, |status| format!(" (HTTP {status})"));
    format!("  ✗ Dashboard operation failed{status}. {FAILED}\n")
}

/// A `sessionsoverview` page answer.
fn page(items: &[Value], total: u64, skip: u64, limit: u64) -> Planned {
    Planned::json(
        200,
        &json!({"items": items, "pagination": {"total_items": total, "skip": skip, "limit": limit}}),
    )
}

// ---------------------------------------------------------------------------
// Requests (TS `runtime-dashboard.spec.ts`)
// ---------------------------------------------------------------------------

mod requests {
    use super::*;

    /// The exact default queries of every command, on the dashboard base with `x-tsg-id`
    /// (TS `wires dashboard %s with exact defaults`, `maps %s identity and detail window`,
    /// `maps detail and transaction`).
    #[test]
    fn every_command_sends_the_typescript_defaults() {
        let f = fx();
        let transaction = [
            &IDENTITY[..],
            &["--scan-id", "scan", "--scan-sub-req-id", "0"],
        ]
        .concat();
        let session = IDENTITY.to_vec();
        for (args, line) in [
            (
                vec!["dashboard", "applications"],
                format!(
                    "GET {DASH}/apps/applicationsoverview?time_interval=1&time_unit=day&limit=25&offset=0"
                ),
            ),
            (
                vec!["dashboard", "top-applications"],
                format!("GET {DASH}/apps/topapplicationsviolations?time_interval=1&time_unit=day"),
            ),
            (
                vec![
                    "dashboard",
                    "violations-trend",
                    "--interval",
                    "24",
                    "--unit",
                    "hours",
                ],
                format!(
                    "GET {DASH}/apps/applicationsviolationstrend?time_interval=24&time_unit=hours"
                ),
            ),
            (
                vec!["dashboard", "apps-list"],
                format!("GET {DASH}/apps/appslist?time_interval=30&time_unit=days"),
            ),
            (
                vec![
                    "dashboard",
                    "application",
                    "--app-id",
                    "app",
                    "--app-name",
                    "A & B",
                    "--interval",
                    "7",
                ],
                format!(
                    "GET {DASH}/apps/application?appid=app&appname=A+%26+B&time_interval=7&time_unit=days"
                ),
            ),
            (
                vec![
                    "dashboard",
                    "application-violations",
                    "--app-id",
                    "app",
                    "--app-name",
                    "A & B",
                ],
                format!(
                    "GET {DASH}/apps/applicationviolationbreakdown?appid=app&appname=A+%26+B&time_interval=30&time_unit=days"
                ),
            ),
            (
                vec!["sessions", "chart"],
                format!("GET {DASH}/sessions/sessionschart?time_interval=1&time_unit=day"),
            ),
            (
                vec!["sessions", "list", "--offset", "2"],
                format!(
                    "GET {DASH}/sessions/sessionsoverview?time_interval=1&time_unit=day&limit=25&offset=2"
                ),
            ),
            (
                [&["sessions", "get"][..], &session].concat(),
                format!(
                    "GET {DASH}/sessions/session?session_id=pan_session&app_id=app&app_name=A+%26+B&offset=0&limit=25&time_interval=30&time_unit=days"
                ),
            ),
            (
                [&["sessions", "transaction"][..], &transaction].concat(),
                format!(
                    "GET {DASH}/sessions/sessiontransaction?session_id=pan_session&app_id=app&app_name=A+%26+B&scan_id=scan&scan_sub_req_id=0&time_interval=30&time_unit=days"
                ),
            ),
            (
                vec![
                    "sessions",
                    "scan-content",
                    "--scan-id",
                    "s c",
                    "--scan-sub-req-id",
                    "007",
                    "--show-content",
                ],
                format!("GET {CONTENT}?scan_id=s+c&scan_sub_req_id=7"),
            ),
        ] {
            f.clear();
            let mut full = args.clone();
            full.extend(["--output", "json"]);
            let out = f.rt(&full);
            out.assert_success();
            assert_eq!(f.api(), [line], "{args:?}");
            let request = &f.server.requests()[1];
            assert_eq!(request.header("x-tsg-id"), Some(TSG), "{args:?}");
            assert!(out.stdout.starts_with(['{', '[']), "{args:?}");
        }
        // `transaction` never reads scan content.
        assert!(f.server.rx_requests(Rx::ScanContent).len() == 1);
    }

    /// TS `preserves the supported %s %s query`: `1 hour`, `24 hours`, `1 day`, `7 days`,
    /// and the bare `items` array (TS `outputting a bare array`).
    #[test]
    fn supported_windows_and_the_bare_items_array() {
        let f = fx();
        for (interval, unit) in [("1", "hour"), ("24", "hours"), ("1", "day"), ("7", "days")] {
            f.clear();
            let out = f.rt(&[
                "sessions",
                "list",
                "--interval",
                interval,
                "--unit",
                unit,
                "--output",
                "json",
            ]);
            out.assert_success();
            assert_eq!(
                f.api(),
                [format!(
                    "GET {DASH}/sessions/sessionsoverview?time_interval={interval}&time_unit={unit}&limit=25&offset=0"
                )]
            );
            assert_eq!(out.json(), Value::Array(fx::sessions()));
            assert_eq!(
                out.stderr,
                "  Returned 3 of 3 sessions; this is one page.\n"
            );
        }
        f.server.runtime(|data| data.omit_totals = true);
        let out = f.rt(&["sessions", "list"]);
        assert_eq!(
            out.stderr,
            "  Returned 3 of unknown sessions; this is one page.\n"
        );
    }

    /// TS `walks all pages and preserves same-name identities`.
    #[test]
    fn all_walks_pages_with_same_name_identities() {
        let f = fx();
        let entry = fx::session_item("app", "A & B", "pan_session");
        let other = fx::session_item("other", "A & B", "pan_session");
        f.server.push_once(
            Route::Runtime(Rx::SessionsOverview),
            page(std::slice::from_ref(&entry), 2, 0, 25),
        );
        f.server.push_once(
            Route::Runtime(Rx::SessionsOverview),
            page(&[other], 2, 1, 25),
        );
        let out = f.rt(&["sessions", "list", "--all", "--output", "json"]);
        out.assert_success();
        assert_eq!(
            f.api()[1],
            format!(
                "GET {DASH}/sessions/sessionsoverview?time_interval=1&time_unit=day&limit=25&offset=1"
            )
        );
        assert_eq!(out.json().as_array().unwrap().len(), 2);
        assert_eq!(
            out.stderr,
            "  Retrieved 2 sessions from offset 0; pagination complete.\n"
        );
        // `--offset` with `--all` starts there (TS).
        let f = fx();
        let out = f.rt(&[
            "sessions", "list", "--all", "--limit", "2", "--offset", "1", "--output", "json",
        ]);
        out.assert_success();
        assert_eq!(out.json().as_array().unwrap().len(), 2);
        assert_eq!(
            out.stderr,
            "  Retrieved 2 sessions from offset 1; pagination complete.\n"
        );
    }

    /// TS `does not emit a successful inventory for unstable pages`: a changed total, an
    /// overlapping page, an empty page before the total, a total of 0 with rows; and a
    /// mismatched `skip` or `limit` echo.
    #[test]
    fn unstable_pages_are_failures_without_output() {
        let entry = fx::session_item("app", "A & B", "pan_session");
        for later in [
            page(std::slice::from_ref(&entry), 3, 1, 25),
            page(std::slice::from_ref(&entry), 2, 1, 25),
            page(&[], 2, 1, 25),
            page(std::slice::from_ref(&entry), 0, 1, 25),
            page(&[fx::session_item("x", "y", "z")], 2, 0, 25),
            page(&[fx::session_item("x", "y", "z")], 2, 1, 10),
        ] {
            let f = fx();
            f.server.push_once(
                Route::Runtime(Rx::SessionsOverview),
                page(std::slice::from_ref(&entry), 2, 0, 25),
            );
            f.server
                .push_once(Route::Runtime(Rx::SessionsOverview), later);
            let out = f.rt(&["sessions", "list", "--all", "--output", "json"]);
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert_eq!(out.stderr, failure(None));
        }
    }

    /// TS `marks capped lists partial and returns only the cap`, and the page cap.
    #[test]
    fn caps_print_partial_lists_and_exit_1() {
        let f = fx();
        let out = f.rt(&[
            "sessions", "list", "--all", "--max", "1", "--output", "json",
        ]);
        out.assert_code(1);
        assert_eq!(out.json().as_array().unwrap().len(), 1);
        assert_eq!(
            out.stderr,
            "  Session item cap reached; output is partial.\n"
        );
        assert_eq!(f.api().len(), 1);
        // Exactly the cap and complete: a success.
        let f = fx();
        let out = f.rt(&[
            "sessions", "list", "--all", "--max", "3", "--output", "json",
        ]);
        out.assert_success();
        // Exactly the cap with more to come: partial.
        let f = fx();
        let out = f.rt(&[
            "sessions", "list", "--all", "--limit", "2", "--max", "2", "--output", "json",
        ]);
        out.assert_code(1);
        assert_eq!(out.json().as_array().unwrap().len(), 2);
        // 100 pages without reaching the total.
        let f = fx();
        let rows: Vec<Value> = (0..101)
            .map(|n| fx::session_item("app", "n", &format!("s{n}")))
            .collect();
        f.server.runtime(|data| data.sessions = rows);
        let out = f.rt(&[
            "sessions", "list", "--all", "--limit", "1", "--max", "0", "--output", "json",
        ]);
        out.assert_code(1);
        assert_eq!(out.json().as_array().unwrap().len(), 100);
        assert_eq!(
            out.stderr,
            "  Session page cap reached; output is partial.\n"
        );
        assert_eq!(f.api().len(), 100);
    }
}

// ---------------------------------------------------------------------------
// Checks (D220)
// ---------------------------------------------------------------------------

mod checks {
    use super::*;

    /// TS `rejects week before configuration/authentication`, `rejects unsupported unit`,
    /// `rejects unsupported units consistently` and `validates before authentication`: exit
    /// 2, no request, no debug log, also with an unusable tenant store.
    #[test]
    fn argument_errors_come_before_the_tenant() {
        let sandbox = Sandbox::new();
        let state = debug_log::xdg_state_home(&sandbox).display().to_string();
        let units = "Unsupported --unit. Supported units: hour, hours, day, days. For one week, use --interval 7 --unit days.";
        let mut cases: Vec<(Vec<&str>, &str)> = Vec::new();
        for unit in [
            "week",
            "weeks",
            "month",
            "months",
            "year",
            "years",
            "fortnight",
            "DAY",
            " day ",
        ] {
            cases.push((
                vec!["sessions", "list", "--interval", "1", "--unit", unit],
                units,
            ));
        }
        for args in [
            vec!["sessions", "chart"],
            [&["sessions", "get"][..], &IDENTITY].concat(),
            [
                &["sessions", "transaction"][..],
                &IDENTITY,
                &["--scan-id", "scan", "--scan-sub-req-id", "0"],
            ]
            .concat(),
            vec!["dashboard", "top-applications"],
            vec!["dashboard", "violations-trend"],
            vec!["dashboard", "apps-list"],
        ] {
            let mut args = args;
            args.extend(["--unit", "week"]);
            cases.push((args, units));
        }
        cases.extend([
            (
                vec!["sessions", "list", "--limit", "0"],
                "--limit must be a safe integer >= 1",
            ),
            (
                vec!["sessions", "list", "--offset", "-1"],
                "--offset must be a safe integer >= 0",
            ),
            (
                vec!["sessions", "list", "--max", "NaN"],
                "--max must be a safe integer >= 0",
            ),
            (
                vec!["sessions", "chart", "--interval", "1oops"],
                "--interval must be a safe integer >= 1",
            ),
            (
                vec![
                    "dashboard",
                    "application",
                    "--app-id",
                    "app",
                    "--app-name",
                    "name",
                    "--interval",
                    "1",
                ],
                "Application detail requires 7, 30, or 60 days",
            ),
            (
                vec!["dashboard", "applications", "--interval", "14"],
                "Application overview supports interval 1/7/30/60 and unit day/days/hour",
            ),
            (
                vec![
                    "sessions",
                    "scan-content",
                    "--scan-id",
                    "scan",
                    "--scan-sub-req-id",
                    "0",
                ],
                "Scan content requires exactly one of --show-content or --output-file <new-path>",
            ),
            (
                vec![
                    "sessions",
                    "scan-content",
                    "--scan-id",
                    "scan",
                    "--scan-sub-req-id",
                    "0",
                    "--show-content",
                    "--output-file",
                    "file",
                ],
                "Scan content requires exactly one of --show-content or --output-file <new-path>",
            ),
            (
                vec![
                    "sessions",
                    "get",
                    "--session-id",
                    " ",
                    "--app-id",
                    "a",
                    "--app-name",
                    "n",
                ],
                "--session-id is required",
            ),
            (
                vec!["sessions", "chart", "--output", "yaml"],
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            ),
        ]);
        for (args, message) in cases {
            let mut full = vec!["--debug", "runtime"];
            full.extend_from_slice(&args);
            let out = run(
                &rust(),
                &sandbox,
                &full,
                &RunOptions::new().env("XDG_STATE_HOME", &state),
            );
            out.assert_code(2);
            assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
            assert!(
                debug_log::log_files(&debug_log::log_dir(&sandbox)).is_empty(),
                "{args:?}"
            );
        }
    }

    /// TS `advertises the supported units in session help`.
    #[test]
    fn help_names_the_units() {
        let f = fx();
        let out = f.rt(&["sessions", "list", "--help"]);
        out.assert_success();
        assert!(out.stdout.contains("Time unit: hour, hours, day, days"));
    }

    /// D212: tenant, store and credential errors keep their own messages; the dashboard
    /// line is for failures after the client is built.
    #[test]
    fn tenant_errors_keep_their_messages() {
        let f = fx_with(|config| {
            config.remove("mgmtClientSecret");
        });
        let out = f.rt(&["sessions", "chart"]);
        out.assert_code(1);
        assert!(out.stderr.contains("mgmtClientSecret"), "{}", out.stderr);
        assert!(!out.stderr.contains("Dashboard operation failed"));
        assert_eq!(f.server.request_count(), 0);
    }
}

// ---------------------------------------------------------------------------
// Failures and output (D212)
// ---------------------------------------------------------------------------

mod output {
    use super::*;

    /// TS `requires explicit display and sanitizes upstream failures`: a 403 with a secret
    /// body prints only the generic line; the read is re-read once (G7); no 5xx retry.
    #[test]
    fn failures_print_the_generic_line_only() {
        let f = fx();
        f.server.set_default(
            Route::Runtime(Rx::SessionsChart),
            Planned::json(403, &json!({"message": "SECRET BODY"})),
        );
        let out = f.rt(&["sessions", "chart"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, failure(Some(403)));
        assert_eq!(
            f.server.rx_requests(Rx::SessionsChart).len(),
            2,
            "one G7 re-read"
        );
        for (planned, status, sent) in [
            (
                Planned::json(500, &json!({"message": "boom"})).with_retry_after(0),
                Some(500),
                1,
            ),
            (
                Planned::json(503, &json!({})).with_retry_after(0),
                Some(503),
                1,
            ),
            (
                Planned::json(429, &json!({})).with_retry_after(0),
                Some(429),
                1,
            ),
            (Planned::json(404, &json!({})), Some(404), 1),
            (Planned::raw(200, "application/json", "oops"), None, 1),
            (Planned::json(200, &json!({"buckets": "x"})), None, 1),
        ] {
            let f = fx();
            f.server
                .set_default(Route::Runtime(Rx::SessionsChart), planned);
            let out = f.rt(&["sessions", "chart"]);
            out.assert_code(1);
            assert_eq!(out.stderr, failure(status));
            assert_eq!(f.server.rx_requests(Rx::SessionsChart).len(), sent);
        }
        // A token failure is the dashboard line too.
        let f = fx();
        f.server
            .set_default(Route::Token, Planned::json(401, &json!({})));
        let out = f.rt(&["sessions", "chart"]);
        out.assert_code(1);
        assert!(
            out.stderr.starts_with("  ✗ Dashboard operation failed"),
            "{}",
            out.stderr
        );
    }

    /// D212: pretty and json are the same JSON text, C1 controls escaped; table is a row
    /// table for the list answers, else `Key │ Value`.
    #[test]
    fn formats() {
        let f = fx();
        f.server.runtime(|data| {
            data.sessions[0]["application_name"] = json!("a\u{9b}31m\u{1b}b");
        });
        let pretty = f.rt(&["sessions", "list"]);
        let json = f.rt(&["sessions", "list", "--output", "json"]);
        assert_eq!(pretty.stdout, json.stdout);
        assert!(pretty.stdout.contains("a\\u009b31m\\u001bb"));
        assert!(!pretty.stdout.contains('\u{9b}'));
        let table = f.rt(&["sessions", "list", "--output", "table"]);
        assert!(
            table.stdout.starts_with(" Application "),
            "{}",
            table.stdout
        );
        assert!(
            table
                .stdout
                .contains("│ Application ID │ Session ID  │ Status │ Last activity")
        );
        let table = f.rt(&["dashboard", "applications", "--output", "table"]);
        assert!(
            table
                .stdout
                .starts_with(" ID           │ Name    │ Cloud │ Source │ Sessions │ Violating \n"),
            "{}",
            table.stdout
        );
        let table = f.rt(&["dashboard", "top-applications", "--output", "table"]);
        assert!(
            table
                .stdout
                .starts_with(" ID          │ Name    │ Violations \n"),
            "{}",
            table.stdout
        );
        let table = f.rt(&["dashboard", "apps-list", "--output", "table"]);
        assert!(
            table.stdout.starts_with(" ID           │ Name    \n"),
            "{}",
            table.stdout
        );
        let table = f.rt(&["sessions", "chart", "--output", "table"]);
        assert!(
            table.stdout.starts_with(" Key                 │ Value"),
            "{}",
            table.stdout
        );
        // The tenant `defaultOutput: table` works (TS: a usage error).
        let f = fx_with(|config| {
            config.set("defaultOutput", "table");
        });
        f.rt(&["dashboard", "apps-list"]).assert_success();
    }

    /// `scan_contents: null` is printed as sent; an answer without the required `items` is a
    /// decode failure (the dashboard line), not an empty list.
    #[test]
    fn absent_and_null_members() {
        let f = fx();
        f.server.set_default(
            Route::Runtime(Rx::ScanContent),
            Planned::json(
                200,
                &json!({"report_id": "r", "scan_id": "s", "sub_scan_req_id": 0, "transaction_id": "t", "scan_contents": null}),
            ),
        );
        let out = f.rt(&[
            "sessions",
            "scan-content",
            "--scan-id",
            "s",
            "--scan-sub-req-id",
            "0",
            "--show-content",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(out.json()["scan_contents"], Value::Null);
        f.server.set_default(
            Route::Runtime(Rx::SessionsOverview),
            Planned::json(200, &json!({"pagination": {"total_items": 0}})),
        );
        let out = f.rt(&["sessions", "list"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, failure(None));
    }

    /// D64: every dashboard and sessions read records its SDK operation name (G34), status
    /// and headers only, no query.
    #[test]
    fn the_debug_log_names_every_read() {
        let transaction = [
            &IDENTITY[..],
            &["--scan-id", "scan", "--scan-sub-req-id", "0"],
        ]
        .concat();
        for (args, operation) in [
            (
                vec!["dashboard", "applications"],
                "airs.management.dashboard.applications_overview",
            ),
            (
                vec![
                    "dashboard",
                    "application",
                    "--app-id",
                    "a",
                    "--app-name",
                    "n",
                ],
                "airs.management.dashboard.application",
            ),
            (
                vec![
                    "dashboard",
                    "application-violations",
                    "--app-id",
                    "a",
                    "--app-name",
                    "n",
                ],
                "airs.management.dashboard.application_violation_breakdown",
            ),
            (
                vec!["dashboard", "top-applications"],
                "airs.management.dashboard.top_applications_violations",
            ),
            (
                vec!["dashboard", "violations-trend"],
                "airs.management.dashboard.applications_violations_trend",
            ),
            (
                vec!["dashboard", "apps-list"],
                "airs.management.dashboard.apps_list",
            ),
            (
                vec!["sessions", "chart"],
                "airs.management.dashboard.sessions_chart",
            ),
            (
                vec!["sessions", "list"],
                "airs.management.dashboard.sessions_overview",
            ),
            (
                [&["sessions", "get"][..], &IDENTITY].concat(),
                "airs.management.dashboard.session",
            ),
            (
                [&["sessions", "transaction"][..], &transaction].concat(),
                "airs.management.dashboard.session_transaction",
            ),
        ] {
            let f = fx();
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec!["--debug"];
            full.extend(args.iter().copied());
            let out = f.rt_with(&full, &RunOptions::new().env("XDG_STATE_HOME", &state));
            out.assert_success();
            let (_, records) = debug_log::only_log(&f.sandbox);
            let operations: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .collect();
            assert_eq!(operations, ["oauth.token", operation], "{args:?}");
            debug_log::assert_logs_clean(
                &f.sandbox,
                &f.server,
                &[debug_log::log_dir(&f.sandbox)],
                &["pan_session", "A & B"],
            );
        }
    }

    /// `transaction` prints the attributes TS prints (choice 15) and `--quiet` keeps the
    /// data.
    #[test]
    fn transaction_attributes_and_quiet() {
        let f = fx();
        let mut args = vec!["--quiet", "sessions", "transaction"];
        args.extend(IDENTITY);
        args.extend(["--scan-id", "scan", "--scan-sub-req-id", "0"]);
        let out = f.rt(&args);
        out.assert_success();
        assert_eq!(out.json()["attributes"]["user_ip"], "192.0.2.1");
        assert_eq!(out.json()["scan_sub_req_id"], 0);
        assert_eq!(out.stderr, "");
    }
}

// ---------------------------------------------------------------------------
// scan-content (D225)
// ---------------------------------------------------------------------------

mod scan_content {
    use super::*;

    const ARGS: [&str; 5] = [
        "sessions",
        "scan-content",
        "--scan-id",
        "scan",
        "--scan-sub-req-id",
    ];

    fn args(extra: &[&str]) -> Vec<String> {
        let mut out: Vec<String> = ARGS.iter().map(|arg| (*arg).to_owned()).collect();
        out.push("0".to_owned());
        out.extend(extra.iter().map(|arg| (*arg).to_owned()));
        out
    }

    /// TS `protects content exports and refuses to clobber files before authentication`:
    /// the file is 0600 JSON, stdout is empty, a second run refuses before any request.
    #[test]
    fn exports_to_a_new_private_file() {
        let f = fx();
        let path = f.sandbox.root().join("tmp").join("scan.json");
        let path_text = path.display().to_string();
        for format in ["json", "pretty", "table"] {
            let _ = std::fs::remove_file(&path);
            f.clear();
            let full = args(&["--output-file", &path_text, "--output", format]);
            let full: Vec<&str> = full.iter().map(String::as_str).collect();
            let out = f.rt(&full);
            out.assert_success();
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "  Scan content exported to the requested private file (0600).\n"
            );
            let text = std::fs::read_to_string(&path).unwrap();
            let document: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                document["scan_contents"]["response"],
                fx::response_content(TSG),
                "{format}"
            );
            assert!(text.ends_with("}\n"));
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        f.clear();
        let full = args(&["--output-file", &path_text]);
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let out = f.rt(&full);
        out.assert_code(1);
        assert_eq!(
            f.server.request_count(),
            0,
            "refused before the tenant and any request"
        );
        assert!(
            out.stderr
                .contains("already exists; choose another --output-file")
        );
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// A dangling symlink and a missing directory are refused before any request (TS fetches
    /// the content first for a missing directory).
    #[test]
    fn unwritable_destinations_are_refused_first() {
        let f = fx();
        let tmp = f.sandbox.root().join("tmp");
        let link = tmp.join("dangling.json");
        std::os::unix::fs::symlink(tmp.join("nowhere"), &link).unwrap();
        let missing = tmp.join("missing").join("scan.json");
        for (path, message) in [
            (
                link.display().to_string(),
                "already exists; choose another --output-file",
            ),
            (
                missing.display().to_string(),
                "check that its directory exists and is writable",
            ),
            // D226: a path that names no file (TS writes `out.json`).
            (
                format!("{}/out.json/", tmp.display()),
                "check that its directory exists and is writable",
            ),
            (
                format!("{}/out.json/..", tmp.display()),
                "check that its directory exists and is writable",
            ),
        ] {
            let full = args(&["--output-file", &path]);
            let full: Vec<&str> = full.iter().map(String::as_str).collect();
            let out = f.rt(&full);
            out.assert_code(1);
            assert!(out.stderr.contains(message), "{}", out.stderr);
            assert_eq!(f.server.request_count(), 0);
        }
    }

    /// `--show-content` prints the stored prompt and response on stdout only.
    #[test]
    fn show_content_prints_on_stdout() {
        let f = fx();
        let full = args(&["--show-content"]);
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let out = f.rt(&full);
        out.assert_success();
        assert_eq!(
            out.json()["scan_contents"]["prompt"],
            fx::prompt_content(TSG)
        );
        assert_eq!(out.stderr, "");
    }

    /// D64: the debug log never holds scan content or the query.
    #[test]
    fn the_debug_log_holds_no_content() {
        let f = fx();
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let mut full = vec!["--debug".to_owned(), "runtime".to_owned()];
        full.extend(args(&["--show-content"]));
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let before = f.sandbox.snapshot();
        let out = run(
            &rust(),
            &f.sandbox,
            &full,
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        );
        f.sandbox.assert_unchanged(&before);
        out.assert_success();
        let (_, records) = debug_log::only_log(&f.sandbox);
        let operations: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(
            operations,
            ["oauth.token", "airs.management.dashboard.scan_content"]
        );
        debug_log::assert_logs_clean(
            &f.sandbox,
            &f.server,
            &[debug_log::log_dir(&f.sandbox)],
            &[
                &fx::prompt_content(TSG),
                &fx::response_content(TSG),
                "scan_id=",
            ],
        );
    }
}

// ---------------------------------------------------------------------------
// Interruption (D224)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    #[test]
    fn a_signal_during_a_read_writes_nothing() {
        for (signal, code, route, args) in [
            (
                "INT",
                130,
                Rx::SessionsChart,
                vec!["runtime", "sessions", "chart"],
            ),
            (
                "TERM",
                143,
                Rx::SessionsOverview,
                vec!["runtime", "sessions", "list", "--all"],
            ),
        ] {
            let f = fx();
            f.server.push_once(Route::Runtime(route), Planned::hang());
            let running = spawn(
                &rust(),
                &f.sandbox,
                &args,
                &RunOptions::new().expect_signal(),
            );
            assert!(
                f.server
                    .wait_for_route(Route::Runtime(route), 1, Duration::from_secs(10))
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
