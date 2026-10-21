//! The TypeScript `tests/unit/reports/redteam.spec.ts` cases, against a scripted
//! [`Reader`].

use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;

fn json(text: &str) -> OValue {
    crate::json::parse(text).unwrap()
}

/// One scripted source: a queue of answers (the last one repeats) and the skips asked.
#[derive(Default)]
struct Script {
    answers: RefCell<VecDeque<Result<OValue, ReadError>>>,
    skips: RefCell<Vec<u64>>,
}

impl Script {
    fn of(answers: Vec<Result<OValue, ReadError>>) -> Self {
        Self {
            answers: RefCell::new(answers.into()),
            skips: RefCell::new(Vec::new()),
        }
    }
    fn next(&self, skip: u64) -> Result<OValue, ReadError> {
        self.skips.borrow_mut().push(skip);
        let mut answers = self.answers.borrow_mut();
        if answers.len() > 1 {
            answers.pop_front().unwrap()
        } else {
            answers.front().cloned().unwrap()
        }
    }
}

/// The TS `redTeamReportClient()` helper: every source complete, one failed scan and a
/// high-risk rating; private fields that must never reach the report.
struct Client {
    overview: Script,
    statistics: Script,
    targets: Script,
    quota: Script,
    scans: Script,
    stats: Script,
    adapters: Script,
}

fn ok(text: &str) -> Vec<Result<OValue, ReadError>> {
    vec![Ok(json(text))]
}

impl Client {
    fn standard() -> Self {
        Self {
            overview: Script::of(ok(r#"{"total_targets": 1}"#)),
            statistics: Script::of(ok(
                r#"{"total_scans": 4, "targets_scanned": 1, "risk_profile": [{"risk_rating": "HIGH", "total": 1}], "scan_status": [{"name": "COMPLETED", "count": 4}]}"#,
            )),
            quota: Script::of(ok(
                r#"{"static": {"allocated": 0, "consumed": 0, "unlimited": true}, "dynamic": {"allocated": 50, "consumed": 0, "unlimited": false}, "custom": {"allocated": 50, "consumed": 5, "unlimited": false}}"#,
            )),
            targets: Script::of(ok(
                r#"{"data": [{"uuid": "target", "target_type": "APPLICATION", "connection_params": {"password": "PRIVATE-CONNECTION"}}], "pagination": {"total_items": 1}}"#,
            )),
            scans: Script::of(ok(
                r#"{"data": [{"uuid": "scan", "created_at": "2026-09-07T12:00:00Z", "status": "FAILED", "name": "PRIVATE-SCAN", "job_metadata": {"prompt": "PRIVATE-PROMPT"}}], "pagination": {"total_items": 1}}"#,
            )),
            adapters: Script::of(ok(
                r#"{"data": [{"uuid": "adapter", "status": "ACTIVE", "script_b64": "PRIVATE-SCRIPT"}], "pagination": {"total_items": 1}}"#,
            )),
            stats: Script::of(ok(r#"{"total_channels": 7, "online_channels": 1}"#)),
        }
    }
}

impl Reader for Client {
    async fn overview(&self) -> Result<OValue, ReadError> {
        self.overview.next(0)
    }
    async fn statistics(&self) -> Result<OValue, ReadError> {
        self.statistics.next(0)
    }
    async fn targets(&self, skip: u64) -> Result<OValue, ReadError> {
        self.targets.next(skip)
    }
    async fn quota(&self) -> Result<OValue, ReadError> {
        self.quota.next(0)
    }
    async fn scans(&self, skip: u64) -> Result<OValue, ReadError> {
        self.scans.next(skip)
    }
    async fn channel_stats(&self) -> Result<OValue, ReadError> {
        self.stats.next(0)
    }
    async fn adapters(&self, skip: u64) -> Result<OValue, ReadError> {
        self.adapters.next(skip)
    }
}

/// 2026-09-07T22:00:00Z.
const NOW: i64 = 1_788_818_400_000;

fn collect_with(client: &Client, max_pages: u32, title: &str) -> Report {
    let now = || NOW;
    let options = Options {
        title,
        max_pages,
        now: &now,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime
        .block_on(collect(client, &options))
        .expect("not interrupted")
}

fn report(client: &Client) -> Report {
    collect_with(client, 40, "Red Team environment report")
}

fn source<'a>(report: &'a Report, name: &str) -> &'a Source {
    report.sources.iter().find(|s| s.name == name).unwrap()
}

fn table<'a>(report: &'a Report, title: &str) -> Option<&'a Table> {
    report.tables.iter().find(|t| t.title.contains(title))
}

fn everything(report: &Report) -> String {
    format!("{report:?}\n{}", html::render(report, &html::RED_TEAM))
}

#[test]
fn the_clock_is_iso_8601() {
    assert_eq!(iso(NOW), "2026-09-07T22:00:00.000Z");
    assert_eq!(parse_iso("2026-09-07T22:00:00Z"), Some(NOW));
    assert_eq!(parse_iso("2026-09-07T22:00:00.5Z"), Some(NOW + 500));
    assert_eq!(parse_iso("2026-09-08T00:00:00+02:00"), Some(NOW));
    assert_eq!(parse_iso("2026-09-07T22:00Z"), Some(NOW));
    assert_eq!(parse_iso("2026-09-07T12:00:00"), None);
    assert_eq!(parse_iso("2026-02-30T00:00:00Z"), None);
    assert!(has_zone("x+01:00") && has_zone("xz") && !has_zone("2026-09-07T12:00:00"));
}

/// "collects seven reads, preserves independent windows and excludes sensitive fields"
#[test]
fn collects_seven_reads_and_excludes_sensitive_fields() {
    let client = Client::standard();
    let r = report(&client);
    assert_eq!(r.sources.len(), 7);
    assert!(r.sources.iter().all(|s| s.status == Status::Complete));
    assert_eq!(r.health, Health::Attention);
    assert!(!everything(&r).contains("PRIVATE"));
    assert!(
        !r.findings
            .iter()
            .any(|finding| finding.title.contains("static quota"))
    );
    assert!(table(&r, "daily creation").unwrap().rows.contains(&vec![
        Cell::from("Created in preceding 24 hours"),
        Cell::Count(1)
    ]));
    assert_eq!(*client.adapters.skips.borrow(), [0]);
    assert_eq!(r.collection_started_at, "2026-09-07T22:00:00.000Z");
    assert_eq!(r.window_start, "2026-09-06T22:00:00.000Z");
}

/// "retains partial records on budget, repeated identity and later page failure"
#[test]
fn retains_partial_records() {
    for mode in ["budget", "repeat", "failure"] {
        let client = Client::standard();
        let page = r#"{"data": [{"uuid": "scan", "status": "COMPLETED"}], "pagination": {"total_items": 2}}"#;
        client.scans.answers.replace(match mode {
            "failure" => vec![Ok(json(page)), Err(ReadError::Status(403))].into(),
            _ => vec![Ok(json(page))].into(),
        });
        let r = collect_with(&client, if mode == "budget" { 1 } else { 2 }, "t");
        let scans = source(&r, "Scans");
        assert_eq!(scans.status, Status::Partial, "{mode}");
        assert_eq!(scans.records, 1, "{mode}");
        assert!(!everything(&r).contains("PRIVATE"));
        let note = match mode {
            "budget" => "Reached the 1-page budget; inventory is incomplete.",
            "repeat" => "Missing or repeated identity; pagination stopped.",
            _ => {
                "HTTP 403: source unavailable; check credentials, service availability and SDK compatibility."
            }
        };
        assert_eq!(scans.notes, [note], "{mode}");
    }
}

/// "paginates until the reported total without fetching extra pages"
#[test]
fn paginates_until_the_reported_total() {
    let client = Client::standard();
    client.scans.answers.replace(
        vec![
            Ok(json(
                r#"{"data": [{"uuid": "one"}], "pagination": {"total_items": 2}}"#,
            )),
            Ok(json(
                r#"{"data": [{"uuid": "two"}], "pagination": {"total_items": 2}}"#,
            )),
        ]
        .into(),
    );
    let r = report(&client);
    assert_eq!(*client.scans.skips.borrow(), [0, 1]);
    let scans = source(&r, "Scans");
    assert_eq!(
        (scans.status, scans.records, scans.pages),
        (Status::Complete, 2, 2)
    );
}

/// "does not report invalid inventory as zero"
#[test]
fn invalid_inventory_is_unavailable_not_zero() {
    for body in [
        "{}",
        r#"{"data": [], "pagination": {"total_items": null}}"#,
        r#"{"data": [], "pagination": {"total_items": 1}}"#,
        r#"{"data": [{"uuid": ""}], "pagination": {"total_items": 1}}"#,
    ] {
        let client = Client::standard();
        client.targets.answers.replace(vec![Ok(json(body))].into());
        let r = report(&client);
        assert_eq!(source(&r, "Targets").status, Status::Unavailable, "{body}");
        assert!(table(&r, "Target inventory").is_none(), "{body}");
    }
}

/// "fails closed on missing quota" (the Rust SDK always has the GET; a failed read is
/// unavailable, and nothing falls back to the POST).
#[test]
fn a_failed_quota_read_is_unavailable() {
    let client = Client::standard();
    client
        .quota
        .answers
        .replace(vec![Err(ReadError::Failed)].into());
    let r = report(&client);
    assert_eq!(source(&r, "Quota").status, Status::Unavailable);
    assert_eq!(
        source(&r, "Quota").notes,
        ["Source request or validation failed. No upstream error body is included."]
    );
}

/// "flags finite exhausted quotas but not unlimited zero allocation"
#[test]
fn flags_finite_exhausted_quotas_only() {
    let client = Client::standard();
    client.quota.answers.replace(
        ok(r#"{"static": {"allocated": 0, "consumed": 0, "unlimited": true}, "dynamic": {"allocated": 50, "consumed": 0, "unlimited": false}, "custom": {"allocated": 50, "consumed": 50, "unlimited": false}}"#)
            .into(),
    );
    let r = report(&client);
    let quota: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|finding| finding.title.contains("quota"))
        .collect();
    assert_eq!(quota.len(), 1);
    assert_eq!(quota[0].title, "custom quota has no remaining allocation");
}

/// "does not infer broker outages or equate statistics and inventory counts"
#[test]
fn broker_and_statistics() {
    let r = report(&Client::standard());
    let broker = r
        .findings
        .iter()
        .find(|finding| finding.source == "Network broker")
        .unwrap();
    assert_eq!(broker.priority, Priority::Review);
    assert!(
        table(&r, "Dashboard scan statistics")
            .unwrap()
            .rows
            .contains(&vec![Cell::from("Scans"), Cell::Count(4)])
    );
}

/// "excludes out-of-window timestamps and flags missing/future/ambiguous timestamps"
#[test]
fn the_daily_window() {
    let client = Client::standard();
    let rows: Vec<String> = [
        "\"2026-09-06T21:59:59Z\"",
        "\"2026-09-06T22:00:00Z\"",
        "\"2026-09-07T22:00:00Z\"",
        "\"2026-09-08T00:00:00Z\"",
        "\"2026-09-07T12:00:00\"",
        "null",
    ]
    .iter()
    .enumerate()
    .map(|(i, created)| format!(r#"{{"uuid": "{i}", "created_at": {created}}}"#))
    .collect();
    client.scans.answers.replace(
        vec![Ok(json(&format!(
            r#"{{"data": [{}], "pagination": {{"total_items": 6}}}}"#,
            rows.join(",")
        )))]
        .into(),
    );
    let r = report(&client);
    assert!(table(&r, "daily creation").unwrap().rows.contains(&vec![
        Cell::from("Created in preceding 24 hours"),
        Cell::Count(2)
    ]));
    assert!(
        r.findings
            .iter()
            .any(|finding| finding.title.contains("timestamp gaps"))
    );
}

/// "renders … with escaped API text, no raw JSON, inline assets and CSP"
#[test]
fn renders_escaped_self_contained_html() {
    let r = collect_with(
        &Client::standard(),
        40,
        "</script><img src=x onerror=alert(1)>",
    );
    let text = html::render(&r, &html::RED_TEAM);
    assert!(!text.contains("<img"));
    assert!(!text.contains("PRIVATE"));
    assert!(text.contains("Evidence and completeness"));
    assert!(text.contains("Content-Security-Policy"));
    assert!(text.contains("<style>"));
    assert!(text.contains("<script>"));
    assert!(!text.contains("<script src"));
    assert!(text.starts_with("<!doctype html>\n<html lang=\"en\">"));
    assert!(text.ends_with("</body></html>\n"));
}

/// Every source unavailable: `Unable to assess`.
#[test]
fn no_source_is_unknown_health() {
    let client = Client::standard();
    for script in [
        &client.overview,
        &client.statistics,
        &client.targets,
        &client.quota,
        &client.scans,
        &client.stats,
        &client.adapters,
    ] {
        script
            .answers
            .replace(vec![Err(ReadError::Status(503))].into());
    }
    let r = report(&client);
    assert_eq!(r.health, Health::Unknown);
    assert_eq!(r.incomplete(), 7);
    assert!(html::render(&r, &html::RED_TEAM).contains("Unable to assess"));
}

/// A cancelled read stops the whole report.
#[test]
fn a_cancelled_read_stops_the_report() {
    let client = Client::standard();
    client
        .targets
        .answers
        .replace(vec![Err(ReadError::Cancelled)].into());
    let now = || NOW;
    let options = Options {
        title: "t",
        max_pages: 40,
        now: &now,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    assert_eq!(
        runtime.block_on(collect(&client, &options)),
        Err(Interrupted)
    );
}

#[test]
fn labels_counts_and_order() {
    assert_eq!(label(Some(&json("\"a\\u0007b\\u200bc\""))), "a b c");
    assert_eq!(label(Some(&json("7"))), "Unknown");
    let long = format!("{}😀", "x".repeat(119));
    assert_eq!(
        label(Some(&OValue::String(long))),
        format!("{}\u{fffd}", "x".repeat(119))
    );
    assert_eq!(count(Some(&json("3"))), Ok(3));
    for bad in ["-1", "1.5", "9007199254740992", "\"3\"", "null"] {
        assert!(count(Some(&json(bad))).is_err(), "{bad}");
    }
    let rows = groups(
        [
            json("\"b\""),
            json("\"A\""),
            json("\"a\""),
            json("\"_x\""),
            json("\"b\""),
        ]
        .iter()
        .map(Some),
    );
    let names: Vec<&Cell> = rows.iter().map(|row| &row[0]).collect();
    assert_eq!(
        names,
        [
            &Cell::from("_x"),
            &Cell::from("a"),
            &Cell::from("A"),
            &Cell::from("b")
        ]
    );
}
