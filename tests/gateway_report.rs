//! Executable acceptance tests for `gateway report|dashboard` (DESIGN §19.15, chunk 4): the
//! TypeScript `tests/integration/cli/aigateway-dashboard.spec.ts` cases against the
//! loopback fixture's seeded gateway dataset (adjusted by D155, D156, D214, D227, D249),
//! plus the Rust additions (the 25 reads with their queries, the G7 re-read, the window
//! bounds, interruption). The collector and renderer cases of
//! `tests/unit/reports/aigateway.spec.ts` are unit tests in `src/report/gateway_tests.rs`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airs_test_harness::{
    Cli, FixtureConfig, FixtureServer, GatewayData, Gw, Planned, RecordedRequest, Route, Run,
    RunOptions, Sandbox, run, spawn,
};
use serde_json::json;

const TSG: &str = "100";
const FAILED_LINE: &str = "  ✗ Report generation failed. Verify Management API configuration and a writable, new output path. Existing files are never overwritten.\n";
const COLLECTING: &str =
    "  Collecting AI Gateway statistics and current configuration (read-only)...\n";
const SLUG: &str = "ws-main-a-349e0e";
/// The pinned window around the fixture's log rows (`2026-10-01T12:00:00Z`).
const WINDOW: [&str; 4] = [
    "--start",
    "2026-10-01T00:00:00Z",
    "--end",
    "2026-10-02T00:00:00Z",
];
const QUERY: &str = "workspaceSlug=ws-main-a-349e0e&timeOfGenerationMin=2026-10-01T00%3A00%3A00%2B00%3A00&timeOfGenerationMax=2026-10-02T00%3A00%3A00%2B00%3A00";

/// The 17 chart paths in TS order.
const CHARTS: [&str; 17] = [
    "requests",
    "errors",
    "users",
    "cost",
    "latency",
    "tokens",
    "cache-summary",
    "cache-hit-trend",
    "user-trends",
    "error-trends",
    "error-category-trends",
    "grouped-errors",
    "rescued-retries",
    "feedback-trend",
    "feedback-weighted",
    "feedback-score-distribution",
    "feedback-models",
];

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
    server.seed_gateway();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

impl Fx {
    /// `gateway report <args>`; writes allowed under `cwd/` (the default name).
    fn report(&self, args: &[&str]) -> Run {
        let mut full = vec!["gateway", "report"];
        full.extend_from_slice(args);
        self.run_raw(&full)
    }

    /// `gateway report --workspace <slug> <the window> <args>`.
    fn windowed(&self, args: &[&str]) -> Run {
        let mut full = vec!["--workspace", SLUG];
        full.extend_from_slice(&WINDOW);
        full.extend_from_slice(args);
        self.report(&full)
    }

    fn run_raw(&self, args: &[&str]) -> Run {
        let out = run(
            &rust(),
            &self.sandbox,
            args,
            &RunOptions::new().allow_writes_under("cwd"),
        );
        self.server.assert_no_unknown_routes();
        out
    }

    /// `METHOD /path?query` of every API request, in order (the token left out).
    fn api(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    fn tmp(&self, name: &str) -> String {
        self.sandbox.tmp().join(name).display().to_string()
    }

    fn cwd_files(&self, prefix: &str) -> Vec<PathBuf> {
        self.sandbox
            .cwd_listing()
            .into_iter()
            .filter(|path| path.to_string_lossy().starts_with(prefix))
            .map(|path| self.sandbox.cwd().join(path))
            .collect()
    }

    fn data(&self, edit: impl FnOnce(&mut GatewayData)) {
        self.server.gateway(edit);
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn no_temporaries(dir: &Path) {
    let left: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".airs-"))
        .collect();
    assert!(left.is_empty(), "temporaries left: {left:?}");
}

/// The 25 reads of a report on the seeded workspace, in TS order.
fn expected_reads() -> Vec<String> {
    let mut reads = vec!["GET /ai_gw/admin/v2/workspaces".to_owned()];
    for chart in CHARTS {
        reads.push(format!(
            "GET /ai_gw/v2/logs/charts/{chart}?organisationId=100&{QUERY}"
        ));
    }
    reads.push(format!("GET /ai_gw/v2/analytics/filter-boundaries?{QUERY}"));
    reads.push(format!(
        "GET /ai_gw/v2/logs?organisationId=100&{QUERY}&pageSize=50&currentPage=0"
    ));
    let id = "workspace_id=11111111-1111-4111-8111-000000000001";
    reads.push(format!("GET /ai_gw/v2/configs?{id}"));
    reads.push(format!("GET /ai_gw/v2/api-keys/service?{id}"));
    reads.push(format!("GET /ai_gw/v2/api-keys/user?{id}"));
    reads.push("GET /ai_gw/admin/v2/organisations/100/info".to_owned());
    reads.push("GET /ai_gw/admin/v2/utils/static-resources/schema?resource=guardrails".to_owned());
    reads
}

/// The evidence rows `(source, status)` of a report.
fn evidence(html: &str) -> Vec<(String, String)> {
    let at = html
        .find("<section id=\"table-5\">")
        .expect("evidence section");
    let section = &html[at..];
    let section = &section[..section.find("</section>").unwrap()];
    section
        .split("<tr>")
        .skip(2)
        .map(|row| {
            let cells: Vec<&str> = row
                .split("<td>")
                .skip(1)
                .map(|cell| cell.split("</td>").next().unwrap())
                .collect();
            (cells[0].to_owned(), cells[3].to_owned())
        })
        .collect()
}

/// HTML despite the tenant's `defaultOutput: json`; the 25 reads with the TS queries (UTC
/// offsets, G41); a new private file; the TS status lines; aggregates only.
#[test]
fn writes_html_with_the_typescript_reads() {
    let f = fx_with(|config| {
        config.set("defaultOutput", "json");
    });
    let path = f.tmp("daily.html");
    let out = f.windowed(&["--output-file", &path]);
    out.assert_success();
    let html = std::fs::read_to_string(&path).unwrap();
    assert!(html.starts_with("<!doctype html>\n"));
    assert!(html.ends_with("</body></html>\n"));
    assert_eq!(mode(Path::new(&path)), 0o600);
    no_temporaries(&f.sandbox.tmp());
    assert_eq!(out.stdout, "");
    assert_eq!(
        out.stderr,
        format!("{COLLECTING}  Report → {path} (mode 0600)\n")
    );
    assert_eq!(f.api(), expected_reads());
    let tokens = f
        .server
        .requests()
        .iter()
        .filter(|request| request.route == Route::Token)
        .count();
    assert_eq!(tokens, 1, "one token per run");
    let rows = evidence(&html);
    assert_eq!(rows.len(), 25);
    assert!(
        rows.iter().all(|(_, status)| status == "complete"),
        "{rows:?}"
    );
    assert!(html.contains("<span class=\"badge\">Review required</span>"));
    assert!(html.contains("Gateway errors or policy blocks observed"));
    assert!(html.contains(
        "<p>Telemetry window (UTC): 2026-10-01T00:00:00.000Z → 2026-10-02T00:00:00.000Z</p>"
    ));
    assert!(html.contains("<title>AI Gateway environment report</title>"));
    // Aggregates only: no workspace, key, model, user, URL or credential.
    for needle in [
        SLUG,
        "Main A",
        "11111111-",
        "FAKE-GW-SECRET",
        "gpt-x",
        "alice",
        "example.test",
        "Example Org",
    ] {
        assert!(!html.contains(needle), "{needle}");
    }
}

/// D227: the default name is `airs-gateway-report-<time>-<8 hex>.html` in the working
/// directory; two runs, two files; `dashboard` is an alias.
#[test]
fn the_default_name_and_the_alias() {
    let f = fx();
    f.windowed(&[]).assert_success();
    let mut args = vec!["--quiet", "gateway", "dashboard", "--workspace", SLUG];
    args.extend_from_slice(&WINDOW);
    let out = f.run_raw(&args);
    out.assert_success();
    assert_eq!(out.stderr, "");
    let files = f.cwd_files("airs-gateway-report-");
    assert_eq!(files.len(), 2, "{files:?}");
    let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
    assert_eq!(
        name.len(),
        "airs-gateway-report-2026-10-17T12-00-00.000Z-0a1b2c3d.html".len(),
        "{name}"
    );
    assert!(!name.contains(':'));
    assert_eq!(mode(&files[0]), 0o600);
    assert!(f.cwd_files("airs-aigateway-report-").is_empty());
}

/// `--output-file -`: one document on stdout; a closed pipe is the failure line (exit 1;
/// TS crashes with a stack trace).
#[test]
fn stdout_delivery() {
    let f = fx();
    let mut args = vec!["--quiet", "gateway", "report", "--workspace", SLUG];
    args.extend_from_slice(&WINDOW);
    args.extend(["--output-file", "-"]);
    let out = f.run_raw(&args);
    out.assert_success();
    assert!(out.stdout.starts_with("<!doctype html>\n"));
    assert_eq!(out.stdout.matches("<!doctype html>").count(), 1);
    assert_eq!(out.stderr, "");
    assert!(f.sandbox.cwd_listing().is_empty());
    let out = run(
        &rust(),
        &f.sandbox,
        &args,
        &RunOptions::new().close_stdout_after(0),
    );
    out.assert_code(1);
    assert!(out.stderr.ends_with(FAILED_LINE), "{}", out.stderr);
}

/// No retry (`numRetries: 0`): a failing source is `unavailable`, the report is useful
/// (exit 0); `--strict` exits 1 after writing.
#[test]
fn a_partial_report_and_strict() {
    let f = fx();
    f.data(|data| {
        data.charts.remove("errors");
    });
    let first = f.tmp("partial.html");
    let out = f.windowed(&["--output-file", &first]);
    out.assert_success();
    assert!(
        out.stderr
            .ends_with("  1 source(s) incomplete; review the evidence section.\n"),
        "{}",
        out.stderr
    );
    let html = std::fs::read_to_string(&first).unwrap();
    assert!(html.contains(
        "<td>telemetry.errors</td><td>telemetry.errors</td><td>Displayed telemetry window</td><td>unavailable</td><td>0</td><td>0</td><td>HTTP 404: request failed; check access and service availability.</td>"
    ));
    assert!(html.contains("Incomplete evidence: telemetry.errors"));
    assert!(!html.contains("Unknown chart"), "no server text");
    let second = f.tmp("strict.html");
    let out = f.windowed(&["--strict", "--output-file", &second]);
    out.assert_code(1);
    assert!(!out.stderr.contains('✗'), "{}", out.stderr);
    assert!(
        std::fs::read_to_string(&second)
            .unwrap()
            .contains("unavailable")
    );
}

/// A 5xx is read once (no retry); a 403 is re-read once (G7).
#[test]
fn a_5xx_is_read_once_and_a_403_twice() {
    let f = fx();
    f.server.push_once(
        Route::Gateway(Gw::FilterBoundaries),
        Planned::json(503, &json!({"message": "PRIVATE-ERROR"})).with_retry_after(0),
    );
    f.server.set_default(
        Route::Gateway(Gw::OrganisationInfo),
        Planned::json(403, &json!({"message": "PRIVATE-ERROR"})),
    );
    let out = f.windowed(&["--output-file", "-"]);
    out.assert_success();
    assert_eq!(f.server.gw_requests(Gw::FilterBoundaries).len(), 1);
    assert_eq!(f.server.gw_requests(Gw::OrganisationInfo).len(), 2);
    assert!(out.stdout.contains("HTTP 503: request failed"));
    assert!(out.stdout.contains("HTTP 403: request failed"));
    assert!(!out.stdout.contains("PRIVATE-ERROR"));
}

/// TS "exits 1 and still creates a diagnostic report when no source is available".
#[test]
fn no_telemetry_available_still_writes_the_report() {
    let f = fx();
    for gw in [Gw::Chart, Gw::FilterBoundaries, Gw::Logs] {
        f.server.set_default(
            Route::Gateway(gw),
            Planned::json(500, &json!({"message": "PRIVATE-ERROR"})).with_retry_after(0),
        );
    }
    let path = f.tmp("unavailable.html");
    let out = f.windowed(&["--output-file", &path]);
    out.assert_code(1);
    let html = std::fs::read_to_string(&path).unwrap();
    assert!(html.contains("Unable to assess"));
    assert!(!html.contains("PRIVATE-ERROR"));
    assert!(
        out.stderr
            .ends_with("  19 source(s) incomplete; review the evidence section.\n")
    );
    assert!(html.contains("<td>Server total</td><td>Unknown</td>"));
}

/// TS "does not fetch a different workspace when the requested name is absent": the
/// workspace-bound sources send nothing; only the tenant reads run.
#[test]
fn an_unknown_workspace_reads_only_the_tenant_sources() {
    let f = fx();
    let mut args = vec!["--workspace", "Missing"];
    args.extend_from_slice(&WINDOW);
    args.extend(["--output-file", "-"]);
    let out = f.report(&args);
    out.assert_code(1);
    assert_eq!(
        f.api(),
        [
            "GET /ai_gw/admin/v2/workspaces",
            "GET /ai_gw/admin/v2/organisations/100/info",
            "GET /ai_gw/admin/v2/utils/static-resources/schema?resource=guardrails"
        ]
    );
    assert!(out.stdout.contains("Unable to assess"));
    assert!(
        out.stderr
            .ends_with("  23 source(s) incomplete; review the evidence section.\n")
    );
    // A display name resolves (TS).
    let f = fx();
    let mut args = vec!["--workspace", "Main A"];
    args.extend_from_slice(&WINDOW);
    args.extend(["--output-file", "-"]);
    f.report(&args).assert_success();
    assert_eq!(f.api(), expected_reads());
}

/// The transaction log pages: the budget note with `--max-pages`, and D249 (a zone-less
/// `created_at` is not a valid time).
#[test]
fn log_pages_follow_the_budget_and_the_window() {
    let f = fx();
    f.data(|data| {
        data.logs = (1..=60)
            .map(|n| {
                let mut row = airs_test_harness::fixtures::gateway::log(n);
                row["response_status_code"] = json!(if n % 2 == 0 { 200 } else { 446 });
                row
            })
            .collect();
    });
    let out = f.windowed(&["--max-pages", "1", "--output-file", "-"]);
    out.assert_success();
    assert!(out.stdout.contains(
        "Transaction page budget reached. Increase --max-pages to collect the remaining rows."
    ));
    assert!(out.stdout.contains("<td>Server total</td><td>60</td></tr><tr><td>Unique collected</td><td>50</td></tr><tr><td>HTTP 200</td><td>25</td></tr><tr><td>HTTP 446</td><td>25</td>"));
    assert_eq!(f.server.gw_requests(Gw::Logs).len(), 1);
    f.server.clear_requests();
    let out = f.windowed(&["--output-file", "-"]);
    out.assert_success();
    assert_eq!(
        f.server
            .gw_requests(Gw::Logs)
            .iter()
            .map(|request| request.query_value("currentPage").unwrap().to_owned())
            .collect::<Vec<_>>(),
        ["0", "1"]
    );
    assert!(out.stdout.contains("<td>Unique collected</td><td>60</td>"));
    // D249: a zone-less time (TS reads it in the host's zone) is outside the window.
    let f = fx();
    f.data(|data| {
        data.logs[0]["created_at"] = json!("2026-10-01T12:00:00");
    });
    let out = f.windowed(&["--output-file", "-"]);
    out.assert_success();
    assert!(
        out.stdout.contains("<td>telemetry.logs</td><td>telemetry.logs</td><td>Displayed telemetry window</td><td>unavailable</td>"),
        "{}",
        out.stdout
    );
}

/// An existing path (a dangling symlink included), a missing parent and a path that names
/// no file are refused before the tenant and any request (D214, D226): the failure line.
#[test]
fn the_destination_is_checked_before_any_request() {
    let f = fx();
    let existing = f.sandbox.tmp().join("existing.html");
    std::fs::write(&existing, "KEEP").unwrap();
    let dangling = f.sandbox.tmp().join("dangling.html");
    std::os::unix::fs::symlink(f.sandbox.tmp().join("nowhere"), &dangling).unwrap();
    let missing = f.sandbox.tmp().join("nodir").join("r.html");
    let slash = PathBuf::from(format!("{}/sub/", f.sandbox.tmp().display()));
    for path in [&existing, &dangling, &missing, &slash] {
        let out = f.windowed(&["--output-file", &path.display().to_string()]);
        out.assert_code(1);
        assert_eq!(out.stderr, FAILED_LINE, "{}", path.display());
        assert_eq!(out.stdout, "");
    }
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "KEEP");
    assert!(!missing.exists());
    assert_eq!(f.server.request_count(), 0);
    // A missing credential or an invalid config: the failure line only, no request, no
    // file content echoed.
    let f = fx_with(|config| {
        config.remove("mgmtClientSecret");
    });
    let out = f.windowed(&["--output-file", "-"]);
    out.assert_code(1);
    assert_eq!(out.stderr, FAILED_LINE);
    assert_eq!(f.server.request_count(), 0);
}

/// TS "rejects invalid options before client creation", plus the Rust window bounds
/// (D249), D155 and D156: exit 2, no request, nothing written.
#[test]
fn invalid_options_exit_2_before_any_request() {
    let f = fx();
    let long = "x".repeat(241);
    let w = |extra: &[&'static str]| -> Vec<String> {
        let mut args: Vec<String> = ["gateway", "report", "--workspace", SLUG]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect();
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        args
    };
    let window_error = "Provide a valid increasing ISO-8601 window with timezone";
    let mut cases: Vec<(Vec<String>, &str)> = vec![
        (
            vec![
                "--debug".into(),
                "gateway".into(),
                "report".into(),
                "--workspace".into(),
                SLUG.into(),
            ],
            "Disable --debug for environment reports to avoid persisting sensitive traffic content",
        ),
        (
            vec![
                "--output".into(),
                "json".into(),
                "gateway".into(),
                "dashboard".into(),
                "--workspace".into(),
                SLUG.into(),
            ],
            "The environment report is written as HTML; omit --output",
        ),
        (
            vec![
                "--output".into(),
                "markdown".into(),
                "gateway".into(),
                "report".into(),
                "--workspace".into(),
                SLUG.into(),
            ],
            "Invalid output format 'markdown'. Expected: pretty, table, json",
        ),
        (
            vec![
                "gateway".into(),
                "report".into(),
                "--workspace".into(),
                "  ".into(),
            ],
            "--workspace cannot be empty",
        ),
        (w(&["--days", "0"]), "--days must be a positive integer"),
        (w(&["--days", "1.5"]), "--days must be a positive integer"),
        (
            w(&["--days", "100000000000000000000"]),
            "--days must be a positive integer",
        ),
        (
            w(&[
                "--days",
                "0",
                "--start",
                "2026-09-01T00:00:00Z",
                "--end",
                "2026-09-02T00:00:00Z",
            ]),
            "--days must be a positive integer",
        ),
        (
            w(&["--start", "2026-09-01T00:00:00Z"]),
            "--start and --end must be supplied together",
        ),
        (
            w(&[
                "--days",
                "1",
                "--start",
                "2026-09-01T00:00:00Z",
                "--end",
                "2026-09-02T00:00:00Z",
            ]),
            "Use --days or --start/--end, not both",
        ),
        (
            w(&["--start", "invalid", "--end", "2026-09-02T00:00:00Z"]),
            window_error,
        ),
        (
            w(&[
                "--start",
                "2026-09-02T00:00:00Z",
                "--end",
                "2026-09-01T00:00:00Z",
            ]),
            window_error,
        ),
        (
            w(&[
                "--start",
                "2026-09-01T00:00:00",
                "--end",
                "2026-09-02T00:00:00Z",
            ]),
            window_error,
        ),
        (w(&["--days", "100000000"]), window_error),
        (
            w(&["--max-pages", "0"]),
            "--max-pages must be an integer from 1 to 100",
        ),
        (
            w(&["--max-pages", "1.5"]),
            "--max-pages must be an integer from 1 to 100",
        ),
        (
            w(&["--max-pages", "101"]),
            "--max-pages must be an integer from 1 to 100",
        ),
        (w(&["--title", ""]), "--title must contain 1–240 characters"),
        (w(&["--output-file", " "]), "--output-file cannot be empty"),
    ];
    let mut title = w(&["--title"]);
    title.push(long);
    cases.push((title, "--title must contain 1–240 characters"));
    for (args, message) in cases {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = f.run_raw(&refs);
        out.assert_code(2);
        assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
        assert_eq!(out.stdout, "");
    }
    // A missing --workspace is clap's usage error (TS: commander, exit 1).
    let out = f.run_raw(&["gateway", "report"]);
    out.assert_code(2);
    assert!(out.stderr.contains("--workspace <ref>"), "{}", out.stderr);
    assert_eq!(f.server.request_count(), 0);
    assert!(f.sandbox.cwd_listing().is_empty());
}

/// The help: TS's options with the program name and the `gateway` group; the Markdown
/// example dropped (D155).
#[test]
fn the_help_names_the_gateway_report() {
    let f = fx();
    let out = f.run_raw(&["gateway", "report", "--help"]);
    out.assert_success();
    assert!(
        out.stdout
            .contains("Generate an AI Gateway environment report (read-only)")
    );
    assert!(out.stdout.contains(
        "$ airs gateway report --workspace ws-develo-71f8d8 --strict --max-pages 20 --output-file - > daily.html"
    ));
    assert!(!out.stdout.contains("markdown"));
    assert!(
        out.stdout
            .contains("Refused by this command: the report is written as HTML (omit --output)")
    );
    let out = f.run_raw(&["gateway", "--help"]);
    assert!(
        out.stdout.contains("[aliases: dashboard]"),
        "{}",
        out.stdout
    );
}

/// A signal during a source read: `Interrupted; no report was written` (D252).
#[test]
fn a_signal_during_collection_writes_no_report() {
    let f = fx();
    f.server
        .push_once(Route::Gateway(Gw::Chart), Planned::hang());
    let path = f.tmp("signal.html");
    let mut args = vec!["gateway", "report", "--workspace", SLUG];
    args.extend_from_slice(&WINDOW);
    args.extend(["--output-file", &path]);
    let running = spawn(
        &rust(),
        &f.sandbox,
        &args,
        &RunOptions::new().expect_signal(),
    );
    assert!(
        f.server
            .wait_for_route(Route::Gateway(Gw::Chart), 1, Duration::from_secs(20))
    );
    running.send_signal("TERM");
    let out = running.wait();
    out.assert_code(143);
    assert_eq!(
        out.stderr,
        format!("{COLLECTING}\n  ✗ Error: Interrupted; no report was written\n\n")
    );
    assert!(!Path::new(&path).exists());
    no_temporaries(&f.sandbox.tmp());
}
