//! Executable acceptance tests for `supplychain report` (DESIGN §20.9, M6f chunk 2): the
//! TypeScript `tests/integration/cli/agentguard.spec.ts:129-190` cases against the loopback
//! fixture's seeded supplychain dataset (real shapes, §20.13; adjusted by D155, D156, D214,
//! D226, D309–D311, D314, D322, D323), plus the Rust additions (the three sources' requests,
//! the G63 re-read, no retries, the page budget, the token failure, redirects, the
//! destination checks, interruption). The collector and renderer cases of
//! `tests/unit/reports/agentguard.spec.ts` are unit tests in `src/report/supplychain_tests.rs`.
//!
//! The scans are [`fx::recent_scans`]: their creation times sit an hour before the run, so
//! they fall inside the report's 30-day window that ends at the run's own clock.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airs_test_harness::fixtures::supplychain as fx;
use airs_test_harness::{
    Cli, FixtureConfig, FixtureServer, Planned, RecordedRequest, Route, Run, RunOptions, Sandbox,
    Sc, SupplychainData, run, spawn,
};
use serde_json::json;

const TSG: &str = "100";
const DATA: &str = "/agentguard/data/v1";
const MGMT: &str = "/agentguard/mgmt/v1";
const FAILED_LINE: &str = "  ✗ Supply chain report failed. Check credentials and a writable, new output path. Existing files are never overwritten.\n";
const INCOMPLETE_NOTE: &str = "Inventory incomplete: pagination changed, repeated, stopped early, failed or reached its budget.";
const EXCLUDED_NOTE: &str = "Rows with missing or out-of-window creation timestamps were excluded.";
const FAILED_NOTE: &str = "Request or validation failed; no upstream error body included.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

fn fx() -> Fx {
    fx_with(|_| {}, |_| {})
}

fn seeded(seed: impl FnOnce(&mut SupplychainData)) -> Fx {
    fx_with(seed, |_| {})
}

fn fx_with(seed: impl FnOnce(&mut SupplychainData), edit: impl FnOnce(&mut FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    server.seed_supplychain();
    server.supplychain(|data| {
        data.scans = fx::recent_scans();
        seed(data);
    });
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

impl Fx {
    /// `supplychain report <args>`; writes allowed under `cwd/` (the default name).
    fn report(&self, args: &[&str]) -> Run {
        let mut full = vec!["supplychain", "report"];
        full.extend_from_slice(args);
        self.run_raw(&full)
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

    fn tokens(&self) -> usize {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route == Route::Token)
            .count()
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

/// The cell texts of the rows of the table section titled `title`.
fn table(html: &str, title: &str) -> Vec<Vec<String>> {
    let heading = format!("<h2>{title}</h2>");
    let at = html.find(&heading).unwrap_or_else(|| panic!("{title}"));
    let section = &html[at..];
    let section = &section[..section.find("</section>").unwrap()];
    section
        .split("<tr>")
        .skip(2)
        .map(|row| {
            row.split("<td>")
                .skip(1)
                .map(|cell| cell.split("</td>").next().unwrap().to_owned())
                .collect()
        })
        .collect()
}

/// The evidence rows `(source, status, records, pages, notes)`.
fn evidence(html: &str) -> Vec<(String, String, String, String, String)> {
    table(html, "Evidence and completeness")
        .into_iter()
        .map(|cells| {
            (
                cells[0].clone(),
                cells[3].clone(),
                cells[4].clone(),
                cells[5].clone(),
                cells[6].clone(),
            )
        })
        .collect()
}

fn scans_line(skip: u64, start: &str, end: &str) -> String {
    let encode = |text: &str| text.replace(':', "%3A");
    format!(
        "GET {DATA}/scans?skip={skip}&limit=10&isBackgroundRefresh=false&start_time={}&end_time={}",
        encode(start),
        encode(end)
    )
}

/// Milliseconds of `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn millis(iso: &str) -> i64 {
    let digits = |range: std::ops::Range<usize>| iso[range].parse::<i64>().unwrap();
    let (year, month, day) = (digits(0..4), digits(5..7), digits(8..10));
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    days * 86_400_000
        + digits(11..13) * 3_600_000
        + digits(14..16) * 60_000
        + digits(17..19) * 1000
        + digits(20..23)
}

// ---------------------------------------------------------------------------
// Collection and publishing (TS `it.spec:129-174`)
// ---------------------------------------------------------------------------

mod collection {
    use super::*;

    /// HTML despite the tenant's `defaultOutput: json`; the three sources' TS requests
    /// (the 30-day window as `start_time`/`end_time`, `limit=10`, the rules walk to a short
    /// page), one token; a new private file; the TS status lines; the seeded dataset's
    /// aggregates (the zone-less, 2020 and `garbage` rows excluded, D322).
    #[test]
    fn writes_html_with_the_typescript_reads() {
        let f = fx_with(
            |_| {},
            |config| {
                config.set("defaultOutput", "json");
            },
        );
        let path = f.tmp("supply.html");
        let out = f.report(&["--output-file", &path]);
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            format!(
                "  Report → {path} (mode 0600)\n  1 source(s) incomplete; review the evidence section.\n"
            )
        );
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.starts_with("<!doctype html>\n"));
        assert!(html.ends_with("</body></html>\n"));
        assert_eq!(mode(Path::new(&path)), 0o600);
        no_temporaries(&f.sandbox.tmp());
        // The requests.
        let scans = f.server.sc_requests(Sc::Scans);
        let start = scans[0].query_value("start_time").unwrap().to_owned();
        let end = scans[0].query_value("end_time").unwrap().to_owned();
        assert_eq!(millis(&end) - millis(&start), 30 * 86_400_000);
        assert_eq!(
            f.api(),
            [
                scans_line(0, &start, &end),
                scans_line(10, &start, &end),
                format!("GET {DATA}/stats/scans?time_period=30_DAYS"),
                format!("GET {MGMT}/rules?skip=0&limit=10"),
                format!("GET {MGMT}/rules?skip=10&limit=10"),
                format!("GET {MGMT}/rules?skip=20&limit=10"),
            ]
        );
        assert_eq!(f.tokens(), 1, "one token per run");
        // The document.
        assert!(html.contains("<title>Supply chain environment report</title>"));
        assert!(html.contains("<header><p>Prisma AIRS AI Supply Chain — AgentGuard</p><h1>Supply chain environment report</h1><span class=\"badge\">Attention required</span>"));
        assert!(html.contains(&format!(
            "<p>30-day scan inventory; rolling 30_DAYS statistics; current rule catalog: {start} → {end}</p>"
        )));
        assert_eq!(
            table(&html, "Scan outcomes"),
            [
                ["AGENT / ALLOWED", "1"],
                ["AGENT / BLOCKED", "1"],
                ["OTHER / ALLOWED", "1"],
                ["OTHER / OTHER", "1"],
                ["SKILL / ALLOWED", "1"],
                ["SKILL / BLOCKED", "1"],
                ["SKILL / ERROR", "1"],
                ["SKILL / UNKNOWN", "1"],
            ]
        );
        assert!(html.contains("<p class=\"note\">Collected 12 rows; excluded 1 parent/batch rows. Partial inventory only.</p>"));
        assert_eq!(
            table(&html, "Skill statistics"),
            [
                ["Unique skills scanned", "4", "12.5"],
                ["Vulnerabilities found", "7", "Unknown"]
            ]
        );
        assert_eq!(
            table(&html, "Rule catalog defaults"),
            [["ALLOWING", "9"], ["BLOCKING", "16"]]
        );
        assert_eq!(
            evidence(&html),
            [
                (
                    "Scans".into(),
                    "partial".into(),
                    "12".into(),
                    "2".into(),
                    EXCLUDED_NOTE.into()
                ),
                (
                    "Statistics".into(),
                    "complete".into(),
                    "1".into(),
                    "1".into(),
                    "Collection completed.".into()
                ),
                (
                    "Rules".into(),
                    "complete".into(),
                    "25".into(),
                    "3".into(),
                    "Collection completed.".into()
                ),
            ]
        );
        assert!(html.contains(&format!(
            "<tr><td>Scans</td><td>listScans()</td><td>{start} to {end}</td>"
        )));
        for (title, evidence) in [
            (
                "Blocked scans require review",
                "2 collected non-parent scan rows have BLOCKED evaluations.",
            ),
            (
                "Scans without a completed decision",
                "3 collected non-parent rows are pending, failed or have an unfamiliar status.",
            ),
            ("Scans incomplete", EXCLUDED_NOTE),
            (
                "Skill vulnerabilities reported",
                "7 findings reported in the server statistics window.",
            ),
        ] {
            assert!(
                html.contains(&format!("<h3>{title}</h3><p>{evidence}</p>")),
                "{title}"
            );
        }
    }

    /// TS `it.spec:129-143` (D309, D310): the default file `airs-supplychain-report-<time>-<8
    /// hex>.html` in the working directory at 0600 (TS `airs-agentguard-report-…`), with
    /// no marker; two runs, two files; `--quiet` keeps the file and drops the status lines.
    #[test]
    fn writes_private_default_html_in_the_working_directory() {
        let f = fx();
        f.report(&[]).assert_success();
        let out = f.run_raw(&["--quiet", "supplychain", "report"]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        let files = f.cwd_files("airs-supplychain-report-");
        assert_eq!(files.len(), 2, "{files:?}");
        for file in &files {
            let name = file.file_name().unwrap().to_string_lossy().into_owned();
            assert_eq!(
                name.len(),
                "airs-supplychain-report-2026-10-19T03-00-16.233Z-6b8c8bee.html".len(),
                "{name}"
            );
            assert!(!name.contains(':'));
            assert_eq!(mode(file), 0o600);
            let html = std::fs::read_to_string(file).unwrap();
            assert!(html.starts_with("<!doctype"));
            assert!(!html.contains(fx::MARKER));
            assert!(html.contains("<title>Supply chain environment report</title>"));
        }
        assert!(f.cwd_files("airs-agentguard-report-").is_empty());
        no_temporaries(&f.sandbox.cwd());
    }

    /// TS `it.spec:152-166`: `--output-file -` writes the document only; a closed pipe is the
    /// failure line (exit 1).
    #[test]
    fn stdout_delivery_and_a_broken_pipe() {
        let f = fx();
        let out = f.run_raw(&["--quiet", "supplychain", "report", "--output-file", "-"]);
        out.assert_success();
        assert!(out.stdout.starts_with("<!doctype html>\n"));
        assert_eq!(out.stdout.matches("<!doctype html>").count(), 1);
        assert_eq!(out.stderr, "");
        assert!(f.sandbox.cwd_listing().is_empty());
        let out = f.report(&["--output-file", "-"]);
        assert_eq!(
            out.stderr,
            "  1 source(s) incomplete; review the evidence section.\n"
        );
        let out = run(
            &rust(),
            &f.sandbox,
            &["supplychain", "report", "--output-file", "-"],
            &RunOptions::new().close_stdout_after(0),
        );
        out.assert_code(1);
        assert!(out.stderr.ends_with(FAILED_LINE), "{}", out.stderr);
    }

    /// TS `it.spec:167-174`: rules at 403 (re-read once, G63) make the Rules source
    /// unavailable; the diagnostic document is still written, without server text; exit 0,
    /// and 1 with `--strict`.
    #[test]
    fn strict_fails_an_incomplete_collection_after_writing() {
        let f = fx();
        f.server.set_default(
            Route::Supplychain(Sc::Rules),
            Planned::json(403, &json!({"message": "PRIVATE-ERROR"})),
        );
        let path = f.tmp("partial.html");
        let out = f.report(&["--strict", "--output-file", &path]);
        out.assert_code(1);
        assert!(!out.stderr.contains('✗'), "{}", out.stderr);
        assert!(
            out.stderr
                .ends_with("  2 source(s) incomplete; review the evidence section.\n")
        );
        assert_eq!(f.server.sc_requests(Sc::Rules).len(), 2, "G63 re-read");
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains(&format!(
            "<tr><td>Rules</td><td>listRules()</td><td>Current catalog</td><td>unavailable</td><td>0</td><td>0</td><td>{FAILED_NOTE}</td></tr>"
        )));
        assert!(!html.contains("Rule catalog defaults"));
        assert!(!html.contains("PRIVATE"));
        assert!(!html.contains("HTTP 403"));
        let out = f.report(&["--output-file", &f.tmp("lenient.html")]);
        out.assert_success();
    }

    /// TS's all-failing capture: every source unavailable, `Unable to assess`, no data
    /// tables, the file still written, exit 1 (even without `--strict`).
    #[test]
    fn every_source_failing_is_unable_to_assess() {
        let f = fx();
        for sc in [Sc::Scans, Sc::Stats, Sc::Rules] {
            f.server.set_default(
                Route::Supplychain(sc),
                Planned::json(500, &json!({"message": "PRIVATE-ERROR"})),
            );
        }
        let path = f.tmp("down.html");
        let out = f.report(&["--output-file", &path]);
        out.assert_code(1);
        assert!(
            out.stderr
                .ends_with("  3 source(s) incomplete; review the evidence section.\n"),
            "{}",
            out.stderr
        );
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("<span class=\"badge\">Unable to assess</span>"));
        for title in ["Scan outcomes", "Skill statistics", "Rule catalog defaults"] {
            assert!(!html.contains(title), "{title}");
        }
        assert!(
            evidence(&html)
                .iter()
                .all(|row| row.1 == "unavailable" && row.2 == "0" && row.4 == FAILED_NOTE)
        );
        // No retries: one GET per source (TS `numRetries: 0`).
        assert_eq!(
            [Sc::Scans, Sc::Stats, Sc::Rules].map(|sc| f.server.sc_requests(sc).len()),
            [1, 1, 1]
        );
    }

    /// SC§9.3's token capture: a token 401 fails each source on its own token request
    /// (three token requests, no API request), the document is written, exit 1.
    #[test]
    fn a_token_failure_fails_every_source() {
        let f = fx();
        f.server
            .set_default(Route::Token, Planned::json(401, &json!({})));
        let path = f.tmp("token.html");
        let out = f.report(&["--output-file", &path]);
        out.assert_code(1);
        assert!(f.api().is_empty());
        assert_eq!(f.tokens(), 3);
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("Unable to assess"));
        assert!(out.stderr.contains("3 source(s) incomplete"));
    }

    /// No retries: a 429, a 5xx and a dropped connection are read once; a 401 is re-read
    /// once (G63: token, GET(401), token, GET), and the source completes.
    #[test]
    fn reads_are_sent_once_plus_one_reread() {
        for planned in [
            Planned::json(429, &json!({})).with_retry_after(0),
            Planned::json(503, &json!({})).with_retry_after(0),
            Planned::disconnect(),
        ] {
            let f = fx();
            f.server
                .push_once(Route::Supplychain(Sc::Stats), planned.clone());
            let path = f.tmp("once.html");
            f.report(&["--output-file", &path]).assert_success();
            assert_eq!(f.server.sc_requests(Sc::Stats).len(), 1);
            let html = std::fs::read_to_string(&path).unwrap();
            assert!(html.contains("<tr><td>Statistics</td><td>getScanStats()</td><td>Server rolling 30_DAYS</td><td>unavailable</td>"));
        }
        let f = fx();
        f.server.push_once(
            Route::Supplychain(Sc::Stats),
            Planned::json(401, &json!({})),
        );
        let path = f.tmp("reread.html");
        f.report(&["--output-file", &path]).assert_success();
        assert_eq!(f.server.sc_requests(Sc::Stats).len(), 2);
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("<tr><td>Statistics</td><td>getScanStats()</td><td>Server rolling 30_DAYS</td><td>complete</td>"));
    }

    /// D30 extended (G65): a redirect is never followed; the source is unavailable.
    #[test]
    fn redirects_are_not_followed() {
        let other = FixtureServer::start();
        let f = fx();
        f.server.set_default(
            Route::Supplychain(Sc::Stats),
            Planned::redirect(302, &other.url("/agentguard/data/v1/stats/scans")),
        );
        let path = f.tmp("redirect.html");
        f.report(&["--output-file", &path]).assert_success();
        assert_eq!(other.request_count(), 0);
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("<td>Statistics</td><td>getScanStats()</td><td>Server rolling 30_DAYS</td><td>unavailable</td>"));
    }

    /// SC§9.4's `--max-pages 2` capture over 25 scans and 25 rules: two pages each, both
    /// sources partial with the budget note, 20 rows counted, exit 0 without `--strict`.
    #[test]
    fn the_page_budget_bounds_both_inventories() {
        let f = seeded(|data| {
            let template = fx::recent_scans()[0].clone();
            data.scans = (1..=25)
                .map(|n| {
                    let mut row = template.clone();
                    row.set("uuid", serde_json::Value::from(fx::uuid(500 + n)));
                    row
                })
                .collect();
        });
        let path = f.tmp("budget.html");
        f.report(&["--max-pages", "2", "--output-file", &path])
            .assert_success();
        let skips = |sc: Sc| -> Vec<String> {
            f.server
                .sc_requests(sc)
                .iter()
                .map(|request| request.query_value("skip").unwrap().to_owned())
                .collect()
        };
        assert_eq!(skips(Sc::Scans), ["0", "10"]);
        assert_eq!(skips(Sc::Rules), ["0", "10"]);
        let html = std::fs::read_to_string(&path).unwrap();
        let note = format!("Reached the 2-page budget. {INCOMPLETE_NOTE}");
        let rows = evidence(&html);
        assert_eq!(
            (rows[0].1.as_str(), rows[0].2.as_str(), rows[0].4.as_str()),
            ("partial", "20", note.as_str())
        );
        assert_eq!(
            (rows[2].1.as_str(), rows[2].2.as_str(), rows[2].4.as_str()),
            ("partial", "20", note.as_str())
        );
        assert!(
            html.contains(
                "Collected 20 rows; excluded 0 parent/batch rows. Partial inventory only."
            )
        );
    }

    /// The page checks make a source partial (rows kept) or unavailable: a repeated uuid on
    /// the second page, a total that changes, a schema-invalid answer.
    #[test]
    fn bad_pages_make_the_source_partial() {
        let f = fx();
        f.server
            .push_once(Route::Supplychain(Sc::Scans), Planned::builtin());
        let mut repeated = fx::recent_scans();
        repeated.truncate(2);
        f.server.push_once(
            Route::Supplychain(Sc::Scans),
            Planned::raw(200, "application/json", fx::scan_list_body(&repeated, 12)),
        );
        let path = f.tmp("repeated.html");
        f.report(&["--output-file", &path]).assert_success();
        let html = std::fs::read_to_string(&path).unwrap();
        let rows = evidence(&html);
        assert_eq!((rows[0].1.as_str(), rows[0].2.as_str()), ("partial", "10"));
        assert!(rows[0].4.contains(INCOMPLETE_NOTE), "{}", rows[0].4);
        // A contract failure on the first page (a scan without a `uuid`; G71's tolerant
        // read refuses it): unavailable, the generic note.
        let f = fx();
        let mut invalid = fx::recent_scans()[0].clone();
        invalid.remove("uuid");
        f.server.set_default(
            Route::Supplychain(Sc::Scans),
            Planned::raw(200, "application/json", fx::scan_list_body(&[invalid], 1)),
        );
        let path = f.tmp("invalid.html");
        f.report(&["--output-file", &path]).assert_success();
        let rows = evidence(&std::fs::read_to_string(&path).unwrap());
        assert_eq!(
            (rows[0].1.as_str(), rows[0].4.as_str()),
            ("unavailable", FAILED_NOTE)
        );
    }

    /// G71: the Scans source reads scan rows with the `null`s the service sends (the
    /// observed `"fingerprint": null` and every other member the tolerant read accepts as
    /// `null`): a `null` creation time is excluded, a `null` artifact type is `UNKNOWN`, a
    /// row of unknown batch membership is left out of the counts with its note, and nothing
    /// of the rows' sensitive members reaches the document.
    #[test]
    fn scan_rows_with_nulls_are_read() {
        let f = seeded(|data| {
            let mut rows = fx::recent_null_scans();
            let mut unknown_batch = rows[2].clone();
            unknown_batch.set("uuid", json!(fx::uuid(116)));
            unknown_batch.set("is_batch", serde_json::Value::Null);
            rows.push(unknown_batch);
            let mut no_type = rows[0].clone();
            no_type.set("uuid", json!(fx::uuid(117)));
            no_type.set("artifact_type", serde_json::Value::Null);
            no_type.set("status", serde_json::Value::Null);
            rows.push(no_type);
            data.scans = rows;
        });
        let path = f.tmp("nulls.html");
        f.report(&["--output-file", &path]).assert_success();
        let html = std::fs::read_to_string(&path).unwrap();
        let rows = evidence(&html);
        assert_eq!(
            (rows[0].0.as_str(), rows[0].1.as_str(), rows[0].2.as_str()),
            ("Scans", "partial", "5")
        );
        assert_eq!(
            rows[0].4,
            format!(
                "{EXCLUDED_NOTE} Rows with unknown batch membership were excluded from outcome counts."
            )
        );
        assert_eq!(
            table(&html, "Scan outcomes"),
            [
                vec!["AGENT / ALLOWED".to_owned(), "1".to_owned()],
                vec!["SKILL / BLOCKED".to_owned(), "1".to_owned()],
                vec!["UNKNOWN / BLOCKED".to_owned(), "1".to_owned()],
            ]
        );
        assert!(
            html.contains(
                "Collected 5 rows; excluded 0 parent/batch rows. Partial inventory only."
            )
        );
        assert!(html.contains(
            "1 collected non-parent rows are pending, failed or have an unfamiliar status."
        ));
        for needle in [fx::MARKER, "11111111-", "git.example.invalid"] {
            assert!(!html.contains(needle), "{needle}");
        }
        // A scan without a `uuid` still fails the page: the source is unavailable.
        let f = seeded(|data| {
            let mut rows = fx::recent_null_scans();
            rows[1].remove("uuid");
            data.scans = rows;
        });
        let path = f.tmp("refused.html");
        f.report(&["--output-file", &path]).assert_success();
        let rows = evidence(&std::fs::read_to_string(&path).unwrap());
        assert_eq!(
            (rows[0].1.as_str(), rows[0].4.as_str()),
            ("unavailable", FAILED_NOTE)
        );
    }

    /// G66 on the raw read (§20.16): a scan page past the SDK's validation depth (65) fails
    /// its page like any other failure (the Scans source `unavailable`, the generic note);
    /// at depth 64 the source is read as the seeded rows are.
    #[test]
    fn scan_pages_past_the_validation_depth_fail_the_source() {
        let source = |depth: usize| {
            let f = seeded(move |data| {
                let deep = fx::deep_scans(depth)[0]
                    .get("eval_details")
                    .cloned()
                    .unwrap();
                data.scans[0].set("eval_details", deep);
            });
            let path = f.tmp("deep.html");
            f.report(&["--output-file", &path]).assert_success();
            let rows = evidence(&std::fs::read_to_string(&path).unwrap());
            (rows[0].0.clone(), rows[0].1.clone(), rows[0].4.clone())
        };
        let (name, status, note) = source(65);
        assert_eq!(
            (name.as_str(), status.as_str(), note.as_str()),
            ("Scans", "unavailable", FAILED_NOTE)
        );
        let plain = fx();
        let path = plain.tmp("plain.html");
        plain.report(&["--output-file", &path]).assert_success();
        let expected = evidence(&std::fs::read_to_string(&path).unwrap());
        let (name, status, note) = source(64);
        assert_eq!(
            (name, status, note),
            (
                expected[0].0.clone(),
                expected[0].1.clone(),
                expected[0].4.clone()
            )
        );
    }

    /// Aggregates only (TS `ut.spec:11-28`): no scan name, id, URL, fingerprint, device
    /// metadata, rule text, finding text or server string reaches the document; no
    /// finding is read.
    #[test]
    fn the_document_holds_aggregates_only() {
        let f = fx();
        let out = f.run_raw(&["supplychain", "report", "--output-file", "-"]);
        out.assert_success();
        let html = out.stdout;
        assert!(f.server.sc_requests(Sc::Vulnerabilities).is_empty());
        for needle in [
            fx::MARKER,
            "11111111-",
            "git.example.invalid",
            "UNLISTED",
            "Secret exposure",
            fx::ORDINARY_RULE_TEXT,
            "SECRET_EXPOSURE",
            "skills.git",
            "darwin",
            "1.4.2",
        ] {
            assert!(!html.contains(needle), "{needle}");
        }
    }
}

// ---------------------------------------------------------------------------
// Checks before the tenant (TS `it.spec:144-151`, `it.spec:175-190`)
// ---------------------------------------------------------------------------

mod checks {
    use super::*;

    /// TS `refuses overwrite before constructing a client` (D214, D226): an existing path, a
    /// dangling symlink, a missing parent and a path that names no file are refused before
    /// the tenant and any request, with the report's failure line (D311).
    #[test]
    fn the_destination_is_checked_before_any_request() {
        let f = fx();
        let existing = f.sandbox.tmp().join("keep.html");
        std::fs::write(&existing, "KEEP").unwrap();
        let dangling = f.sandbox.tmp().join("dangling.html");
        std::os::unix::fs::symlink(f.sandbox.tmp().join("nowhere"), &dangling).unwrap();
        let missing = f.sandbox.tmp().join("nodir").join("r.html");
        let slash = PathBuf::from(format!("{}/sub/", f.sandbox.tmp().display()));
        for path in [&existing, &dangling, &missing, &slash] {
            let out = f.report(&["--output-file", &path.display().to_string()]);
            out.assert_code(1);
            assert_eq!(out.stderr, FAILED_LINE, "{}", path.display());
            assert_eq!(out.stdout, "");
        }
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "KEEP");
        assert!(!missing.exists());
        assert_eq!(f.server.request_count(), 0);
    }

    /// D311 for the tenant, credential and configuration errors (the report keeps its one
    /// line, TS; D316 does not apply here): no request, nothing written.
    #[test]
    fn tenant_and_credential_errors_print_the_report_line() {
        let f = fx_with(
            |_| {},
            |config| {
                config.remove("mgmtClientSecret");
            },
        );
        let out = f.report(&["--output-file", "-"]);
        out.assert_code(1);
        assert_eq!(out.stderr, FAILED_LINE);
        assert_eq!(out.stdout, "");
        assert_eq!(f.server.request_count(), 0);
        let f = fx_with(
            |_| {},
            |config| {
                config.set("agentGuardDataEndpoint", "not a url");
            },
        );
        let out = f.report(&["--output-file", "-"]);
        out.assert_code(1);
        assert_eq!(out.stderr, FAILED_LINE);
        assert_eq!(f.server.request_count(), 0);
        let f = fx();
        let out = f.run_raw(&["--tenant", "missing", "supplychain", "report"]);
        out.assert_code(1);
        assert_eq!(out.stderr, FAILED_LINE);
        assert!(f.sandbox.cwd_listing().is_empty());
    }

    /// TS `rejects invalid arguments before API work` (`report --max-pages 0`, `report
    /// --output json`, `report --debug`) and the other §20.9 checks: exit 2, no tenant
    /// read, no request, nothing written (D155, D156, D314).
    #[test]
    fn invalid_options_exit_2_before_any_request() {
        let f = fx();
        for (args, message) in [
            (
                vec!["--debug", "supplychain", "report"],
                "Disable --debug for environment reports to avoid persisting sensitive traffic content",
            ),
            (
                vec!["--output", "json", "supplychain", "report"],
                "The environment report is written as HTML; omit --output",
            ),
            (
                vec!["supplychain", "report", "--output", "table"],
                "The environment report is written as HTML; omit --output",
            ),
            (
                vec!["--output", "markdown", "supplychain", "report"],
                "Invalid output format 'markdown'. Expected: pretty, table, json",
            ),
            (
                vec!["--output", "html", "supplychain", "report"],
                "Invalid output format 'html'. Expected: pretty, table, json",
            ),
            (
                vec!["supplychain", "report", "--max-pages", "0"],
                "--max-pages must be between 1 and 100",
            ),
            (
                vec!["supplychain", "report", "--max-pages", "101"],
                "--max-pages must be between 1 and 100",
            ),
            (
                vec!["supplychain", "report", "--max-pages", "abc"],
                "--max-pages must be between 1 and 100",
            ),
            (
                vec!["supplychain", "report", "--max-pages", "-1"],
                "--max-pages must be between 1 and 100",
            ),
            (
                vec!["supplychain", "report", "--title", " "],
                "--title must contain 1–240 characters",
            ),
            (
                vec!["supplychain", "report", "--output-file", " "],
                "--output-file cannot be empty",
            ),
            (
                vec![
                    "--debug",
                    "supplychain",
                    "report",
                    "--max-pages",
                    "0",
                    "--title",
                    "",
                ],
                "Disable --debug for environment reports to avoid persisting sensitive traffic content",
            ),
            (
                vec!["supplychain", "report", "--max-pages", "0", "--title", " "],
                "--max-pages must be between 1 and 100",
            ),
        ] {
            let out = f.run_raw(&args);
            out.assert_code(2);
            assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
            assert_eq!(out.stdout, "");
        }
        let title = "x".repeat(241);
        let out = f.report(&["--title", &title]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            "\n  ✗ --title must contain 1–240 characters\n\n"
        );
        assert_eq!(f.server.request_count(), 0);
        assert!(f.sandbox.cwd_listing().is_empty());
        let xdg = f.sandbox.home().join(".local/state/airs-cli/debug");
        assert!(!xdg.exists(), "no debug log");
        // 240 units pass; the title is written as given, escaped.
        let path = f.tmp("title.html");
        let title = format!("<b>{}", "x".repeat(237));
        f.report(&["--title", &title, "--output-file", &path])
            .assert_success();
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains(&format!("<title>&#60;b&#62;{}</title>", "x".repeat(237))));
    }

    /// The help: TS's options and description (HTML only, D155) under `airs-cli-rs
    /// supplychain`, the refused `--output` line, the renamed default title (D309).
    #[test]
    fn the_help_names_the_supplychain_report() {
        let f = fx();
        let out = f.report(&["--help"]);
        out.assert_success();
        for needle in [
            "Generate an aggregate-only 30-day HTML report",
            "Usage: airs supplychain report [OPTIONS]",
            "--max-pages <n>       Page budget per inventory (1–100, 10 rows/page) (default: 40)",
            "--output <format>     Refused by this command: the report is written as HTML (omit --output)",
            "--output-file <path>  New file in CWD by default; - for stdout; never overwrite",
            "--strict              Exit 1 after writing if any source is incomplete",
            "--title <text>        Report title (default: \"Supply chain environment report\")",
        ] {
            assert!(out.stdout.contains(needle), "{needle}\n{}", out.stdout);
        }
        assert!(!out.stdout.contains("Markdown"));
        let out = f.run_raw(&["supplychain", "--help"]);
        assert!(
            out.stdout
                .contains("report  Generate an aggregate-only 30-day HTML report"),
            "{}",
            out.stdout
        );
    }
}

// ---------------------------------------------------------------------------
// Interruption (D323)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    /// A signal during a source read: `Interrupted; no report was written`, no file and no
    /// temporary left.
    #[test]
    fn a_signal_during_collection_writes_no_report() {
        for (route, signal, code) in [(Sc::Scans, "INT", 130), (Sc::Rules, "TERM", 143)] {
            let f = fx();
            f.server
                .push_once(Route::Supplychain(route), Planned::hang());
            let path = f.tmp("signal.html");
            let running = spawn(
                &rust(),
                &f.sandbox,
                &["supplychain", "report", "--output-file", &path],
                &RunOptions::new().expect_signal(),
            );
            assert!(
                f.server
                    .wait_for_route(Route::Supplychain(route), 1, Duration::from_secs(20))
            );
            running.send_signal(signal);
            let out = running.wait();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "\n  ✗ Error: Interrupted; no report was written\n\n"
            );
            assert!(!Path::new(&path).exists());
            no_temporaries(&f.sandbox.tmp());
        }
    }

    /// A signal once the report is published names the file (the report stays). The run
    /// writes nothing to stderr before its `Report →` line, which follows the publish, so
    /// a stderr that is already full (`fill_stderr`) holds it right after the publish,
    /// before it can exit; a merely stalled stderr would not (that line is far shorter than
    /// any pipe buffer, and the run could finish before the signal).
    #[test]
    fn a_signal_after_the_report_is_saved_names_it() {
        let f = fx();
        let path = f.tmp("saved.html");
        let mut running = spawn(
            &rust(),
            &f.sandbox,
            &["supplychain", "report", "--output-file", &path],
            &RunOptions::new()
                .fill_stderr()
                .expect_signal()
                .signal_marker(&f.sandbox.tmp().join("signal.marker")),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !Path::new(&path).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the report was never saved"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        running.send_signal_recorded("INT");
        running.release_stderr();
        let out = running.wait();
        out.assert_code(130);
        // The lines of the run held on its `Report →` line, then the interruption naming
        // the file.
        assert_eq!(
            out.stderr,
            format!(
                "  Report → {path} (mode 0600)\n  1 source(s) incomplete; review the evidence section.\n\n  ✗ Error: Interrupted; the report was saved in {path}\n\n"
            )
        );
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .starts_with("<!doctype html>")
        );
        no_temporaries(&f.sandbox.tmp());
    }
}
