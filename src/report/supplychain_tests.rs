//! The TypeScript `tests/unit/reports/agentguard.spec.ts` cases (and its
//! `tests/helpers/agentguard.ts` client), against a scripted [`Reader`], plus the Rust
//! additions of DESIGN §20.9 (D322: zoned and date-only times; the page budget and
//! classification captures of SC§9.4; the finding order and health; the renderer
//! profile; a cancelled read).

use super::*;
use crate::report::html;
use std::cell::RefCell;
use std::collections::VecDeque;

/// `2026-09-08T12:00:00Z` (TS `options.now`).
const NOW: i64 = 1_788_868_800_000;
const START_ISO: &str = "2026-08-09T12:00:00.000Z";
const END_ISO: &str = "2026-09-08T12:00:00.000Z";

/// A queue of answers (the last one repeats).
struct Script<T>(RefCell<VecDeque<Result<T, ReadError>>>);

impl<T: Clone> Script<T> {
    fn of(answers: Vec<Result<T, ReadError>>) -> Self {
        Self(RefCell::new(answers.into()))
    }
    fn next(&self) -> Result<T, ReadError> {
        let mut answers = self.0.borrow_mut();
        if answers.len() > 1 {
            answers.pop_front().unwrap()
        } else {
            answers.front().cloned().unwrap()
        }
    }
    fn set(&self, answers: Vec<Result<T, ReadError>>) {
        *self.0.borrow_mut() = answers.into();
    }
}

/// TS `scan(uuid)`: a complete `SKILL`/`BLOCKED` scan created two hours before `NOW`.
fn scan(uuid: &str) -> ScanRow {
    ScanRow {
        uuid: uuid.to_owned(),
        created_at: Some("2026-09-08T10:00:00Z".to_owned()),
        artifact_type: Some("SKILL".to_owned()),
        status: Some("COMPLETED".to_owned()),
        eval_outcome: Some("BLOCKED".to_owned()),
        is_batch: Some(false),
        children: Some(0),
    }
}

fn rule(uuid: &str, state: &str) -> RuleRow {
    RuleRow {
        uuid: uuid.to_owned(),
        default_state: Some(state.to_owned()),
    }
}

fn page<T>(rows: Vec<T>, total: f64) -> Result<Page<T>, ReadError> {
    Ok(Page { rows, total })
}

fn metric(count: f64, percent_change: Option<f64>) -> Metric {
    Metric {
        count,
        percent_change,
    }
}

/// TS `client()`: one scan, the statistics (2 vulnerabilities), one rule. Every call is
/// recorded.
struct Client {
    scans: Script<Page<ScanRow>>,
    stats: Script<Stats>,
    rules: Script<Page<RuleRow>>,
    calls: RefCell<Vec<String>>,
}

impl Client {
    fn standard() -> Self {
        Self {
            scans: Script::of(vec![page(
                vec![scan("550e8400-e29b-41d4-a716-446655440000")],
                1.0,
            )]),
            stats: Script::of(vec![Ok(Stats {
                unique_skills_scanned: metric(1.0, None),
                total_vulnerabilities_found: metric(2.0, None),
            })]),
            rules: Script::of(vec![page(vec![rule("rule", "BLOCKING")], 1.0)]),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Reader for Client {
    async fn scans(&self, skip: u64, start: &str, end: &str) -> Result<Page<ScanRow>, ReadError> {
        self.calls
            .borrow_mut()
            .push(format!("scans {skip} {start} {end}"));
        self.scans.next()
    }
    async fn stats(&self) -> Result<Stats, ReadError> {
        self.calls.borrow_mut().push("stats".to_owned());
        self.stats.next()
    }
    async fn rules(&self, skip: u64) -> Result<Page<RuleRow>, ReadError> {
        self.calls.borrow_mut().push(format!("rules {skip}"));
        self.rules.next()
    }
}

fn collect_with(client: &Client, max_pages: u32) -> Result<Report, Interrupted> {
    let now = || NOW;
    let options = Options {
        title: DEFAULT_TITLE,
        max_pages,
        now: &now,
    };
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(collect(client, &options))
}

fn report_with(client: &Client, max_pages: u32) -> Report {
    collect_with(client, max_pages).expect("not interrupted")
}

fn report(client: &Client) -> Report {
    report_with(client, DEFAULT_MAX_PAGES)
}

fn source<'a>(report: &'a Report, name: &str) -> &'a Source {
    report.sources.iter().find(|s| s.name == name).unwrap()
}

fn table<'a>(report: &'a Report, title: &str) -> &'a Table {
    report.tables.iter().find(|t| t.title == title).unwrap()
}

fn text(value: &str) -> Cell {
    Cell::Text(value.to_owned())
}

fn everything(report: &Report) -> String {
    format!("{report:?}\n{}", html::render(report, &html::SUPPLYCHAIN))
}

/// TS `collects all three sources, reports findings and excludes sensitive records`.
#[test]
fn collects_all_three_sources_reports_findings_and_excludes_sensitive_records() {
    let client = Client::standard();
    let r = report(&client);
    assert_eq!(r.health, Health::Attention);
    assert!(r.sources.iter().all(|s| s.status == Status::Complete));
    assert_eq!(
        client.calls(),
        [
            format!("scans 0 {START_ISO} {END_ISO}"),
            "stats".to_owned(),
            "rules 0".to_owned()
        ]
    );
    assert_eq!(
        (r.window_start.as_str(), r.window_end.as_str()),
        (START_ISO, END_ISO)
    );
    assert_eq!(r.collection_started_at, END_ISO);
    assert_eq!(r.generated_at, END_ISO);
    assert!(html::render(&r, &html::SUPPLYCHAIN).starts_with("<!doctype html>"));
    assert_eq!(r.tables[1].title, "Skill statistics");
    assert_eq!(r.tables[1].rows[0][2], Cell::Null);
    let names: Vec<(&str, &str, &str)> = r
        .sources
        .iter()
        .map(|s| (s.name, s.method, s.window.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            (
                "Scans",
                "listScans()",
                "2026-08-09T12:00:00.000Z to 2026-09-08T12:00:00.000Z"
            ),
            ("Statistics", "getScanStats()", "Server rolling 30_DAYS"),
            ("Rules", "listRules()", "Current catalog"),
        ]
    );
    assert_eq!(
        table(&r, "Scan outcomes").rows,
        [vec![text("SKILL / BLOCKED"), Cell::Count(1)]]
    );
    assert_eq!(
        table(&r, "Rule catalog defaults").rows,
        [vec![text("BLOCKING"), Cell::Count(1)]]
    );
}

/// TS `walks pages based on total and actual rows returned`.
#[test]
fn walks_pages_based_on_total_and_actual_rows_returned() {
    let client = Client::standard();
    client.scans.set(vec![
        page(vec![scan("first")], 2.0),
        page(vec![scan("second")], 2.0),
    ]);
    let r = report(&client);
    assert!(
        client.calls()[1].starts_with("scans 1 "),
        "{:?}",
        client.calls()
    );
    let s = source(&r, "Scans");
    assert_eq!((s.records, s.pages, s.status), (2, 2, Status::Complete));
}

/// TS `marks %s pagination as partial` (`repeated`, `empty`, `changed`, `failed`,
/// `oversized`).
#[test]
fn marks_bad_pagination_as_partial() {
    for mode in ["repeated", "empty", "changed", "failed", "oversized"] {
        let client = Client::standard();
        let second = match mode {
            "failed" => Err(ReadError::Status(500)),
            "empty" => page(Vec::new(), 2.0),
            "oversized" => page((0..11).map(|i| scan(&i.to_string())).collect(), 2.0),
            "changed" => page(vec![scan("PRIVATE-next")], 3.0),
            _ => page(vec![scan("PRIVATE-first")], 2.0),
        };
        client
            .scans
            .set(vec![page(vec![scan("PRIVATE-first")], 2.0), second]);
        let r = report(&client);
        let s = source(&r, "Scans");
        assert_eq!(s.status, Status::Partial, "{mode}");
        assert_eq!(s.records, 1, "{mode}");
        assert_eq!(s.notes, [INCOMPLETE_NOTE], "{mode}");
        assert!(!everything(&r).contains("PRIVATE-"), "{mode}");
    }
}

/// TS `honors budgets, excludes parent rows and flags incomplete decisions`.
#[test]
fn honors_budgets_excludes_parent_rows_and_flags_incomplete_decisions() {
    let client = Client::standard();
    let mut parent = scan("parent");
    parent.is_batch = Some(true);
    let mut child = scan("child");
    child.eval_outcome = Some("PENDING".to_owned());
    child.status = Some("RUNNING".to_owned());
    client.scans.set(vec![page(vec![parent, child], 3.0)]);
    let r = report_with(&client, 1);
    let s = source(&r, "Scans");
    assert_eq!(s.status, Status::Partial);
    assert_eq!(s.notes, ["Reached the 1-page budget.", INCOMPLETE_NOTE]);
    assert_eq!(
        table(&r, "Scan outcomes").rows,
        [vec![text("SKILL / PENDING"), Cell::Count(1)]]
    );
    assert_eq!(
        table(&r, "Scan outcomes").note,
        "Collected 2 rows; excluded 1 parent/batch rows. Partial inventory only."
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.title.contains("completed decision"))
    );
}

/// TS `never converts source failures to zero or leaks upstream errors`.
#[test]
fn never_converts_source_failures_to_zero_or_leaks_upstream_errors() {
    let client = Client::standard();
    client.scans.set(vec![Err(ReadError::Status(500))]);
    client.stats.set(vec![Err(ReadError::Failed)]);
    client.rules.set(vec![Err(ReadError::Status(403))]);
    let r = report(&client);
    assert_eq!(r.health, Health::Unknown);
    assert!(r.tables.is_empty());
    for s in &r.sources {
        assert_eq!(
            (s.status, s.records, s.pages, s.notes.as_slice()),
            (Status::Unavailable, 0, 0, &[FAILED_NOTE.to_owned()][..])
        );
    }
    let titles: Vec<&str> = r.findings.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Scans incomplete",
            "Statistics incomplete",
            "Rules incomplete"
        ]
    );
    assert!(r.findings.iter().all(|f| f.priority == Priority::Review
        && f.evidence == FAILED_NOTE
        && f.recommendation
            == "Check service access or increase the page budget, then regenerate."));
    assert!(!everything(&r).contains("HTTP"));
}

/// TS `excludes timestamps outside the requested window and unfamiliar category text`.
#[test]
fn excludes_timestamps_outside_the_window_and_unfamiliar_category_text() {
    let client = Client::standard();
    let mut old = scan("old");
    old.created_at = Some("invalid".to_owned());
    let mut new = scan("new");
    new.artifact_type = Some("PRIVATE-NEW".to_owned());
    new.eval_outcome = Some("PRIVATE-NEW".to_owned());
    client.scans.set(vec![page(vec![old, new], 2.0)]);
    let r = report(&client);
    let s = source(&r, "Scans");
    assert_eq!(s.status, Status::Partial);
    assert_eq!(s.notes, [EXCLUDED_NOTE]);
    assert_eq!(
        table(&r, "Scan outcomes").rows,
        [vec![text("OTHER / OTHER"), Cell::Count(1)]]
    );
    assert!(!everything(&r).contains("PRIVATE-"));
}

/// TS `distinguishes valid empty data from unavailable data`.
#[test]
fn distinguishes_valid_empty_data_from_unavailable_data() {
    let client = Client::standard();
    client.scans.set(vec![page(Vec::new(), 0.0)]);
    client.rules.set(vec![page(Vec::new(), 0.0)]);
    client.stats.set(vec![Ok(Stats {
        unique_skills_scanned: metric(0.0, None),
        total_vulnerabilities_found: metric(0.0, None),
    })]);
    let r = report(&client);
    assert_eq!(r.health, Health::NoFindings);
    assert!(r.sources.iter().all(|s| s.status == Status::Complete));
    assert!(table(&r, "Scan outcomes").rows.is_empty());
    let html = html::render(&r, &html::SUPPLYCHAIN);
    assert!(html.contains(
        "<p>No findings in available evidence; this does not establish absence of risk.</p>"
    ));
    assert!(html.contains("<h2>Scan outcomes</h2><p class=\"note\">Collected 0 rows; excluded 0 parent/batch rows. Complete inventory for requested window.</p><p>No rows collected; consult source completeness before interpreting this as empty.</p>"));
}

/// TS `does not truncate the rule catalog at a page-count total` (G62).
#[test]
fn does_not_truncate_the_rule_catalog_at_a_page_count_total() {
    let client = Client::standard();
    client.rules.set(vec![
        page(
            (0..10).map(|i| rule(&i.to_string(), "BLOCKING")).collect(),
            10.0,
        ),
        page(vec![rule("last", "ALLOWING")], 1.0),
    ]);
    let r = report(&client);
    let s = source(&r, "Rules");
    assert_eq!((s.records, s.pages, s.status), (11, 2, Status::Complete));
    assert_eq!(
        table(&r, "Rule catalog defaults").rows,
        [
            vec![text("ALLOWING"), Cell::Count(1)],
            vec![text("BLOCKING"), Cell::Count(10)]
        ]
    );
    assert_eq!(client.calls()[2..], ["rules 0", "rules 10"]);
}

/// SC§9.4's `--max-pages 2` capture over 25 scans and 25 rules: both partial with the
/// budget note, 20 rows counted, the source still read.
#[test]
fn the_page_budget_keeps_the_rows_read() {
    let client = Client::standard();
    let scans: Vec<ScanRow> = (0..25).map(|i| scan(&format!("s{i}"))).collect();
    client.scans.set(vec![
        page(scans[..10].to_vec(), 25.0),
        page(scans[10..20].to_vec(), 25.0),
    ]);
    client.rules.set(vec![
        page(
            (0..10)
                .map(|i| rule(&format!("a{i}"), "BLOCKING"))
                .collect(),
            10.0,
        ),
        page(
            (0..10)
                .map(|i| rule(&format!("b{i}"), "ALLOWING"))
                .collect(),
            10.0,
        ),
    ]);
    let r = report_with(&client, 2);
    for name in ["Scans", "Rules"] {
        let s = source(&r, name);
        assert_eq!(
            (s.status, s.records, s.pages),
            (Status::Partial, 20, 2),
            "{name}"
        );
        assert_eq!(
            s.notes.join(" "),
            "Reached the 2-page budget. Inventory incomplete: pagination changed, repeated, stopped early, failed or reached its budget."
        );
    }
    assert_eq!(
        table(&r, "Scan outcomes").note,
        "Collected 20 rows; excluded 0 parent/batch rows. Partial inventory only."
    );
    assert_eq!(
        table(&r, "Rule catalog defaults").rows,
        [
            vec![text("ALLOWING"), Cell::Count(10)],
            vec![text("BLOCKING"), Cell::Count(10)]
        ]
    );
    assert_eq!(r.health, Health::Attention);
}

/// SC§9.4's classification capture: a batch parent, a parent with children, a child with
/// a `null` outcome, an unfamiliar artifact and outcome, a 2020 row, a `garbage` time,
/// `FAILED`/`ERROR` and a lowercase `skill`.
#[test]
fn classification_uses_closed_vocabularies() {
    let client = Client::standard();
    let mut rows = Vec::new();
    let mut batch = scan("batch");
    batch.is_batch = Some(true);
    rows.push(batch);
    let mut parent = scan("parent");
    parent.children = Some(1);
    rows.push(parent);
    let mut child = scan("child");
    child.eval_outcome = None;
    rows.push(child);
    let mut odd = scan("odd");
    odd.artifact_type = Some("PRIVATE<b>".to_owned());
    odd.eval_outcome = Some("PRIVATE-X".to_owned());
    rows.push(odd);
    let mut old = scan("old");
    old.created_at = Some("2020-01-01T00:00:00Z".to_owned());
    rows.push(old);
    let mut garbage = scan("garbage");
    garbage.created_at = Some("garbage".to_owned());
    rows.push(garbage);
    let mut failed = scan("failed");
    failed.status = Some("FAILED".to_owned());
    failed.eval_outcome = Some("ERROR".to_owned());
    rows.push(failed);
    let mut lower = scan("lower");
    lower.artifact_type = Some("skill".to_owned());
    lower.eval_outcome = Some("ALLOWED".to_owned());
    rows.push(lower);
    client.scans.set(vec![page(rows, 8.0)]);
    let r = report(&client);
    let outcomes = table(&r, "Scan outcomes");
    assert_eq!(
        outcomes.rows,
        [
            vec![text("OTHER / ALLOWED"), Cell::Count(1)],
            vec![text("OTHER / OTHER"), Cell::Count(1)],
            vec![text("SKILL / ERROR"), Cell::Count(1)],
            vec![text("SKILL / UNKNOWN"), Cell::Count(1)],
        ]
    );
    assert_eq!(
        outcomes.note,
        "Collected 8 rows; excluded 2 parent/batch rows. Partial inventory only."
    );
    assert_eq!(source(&r, "Scans").notes, [EXCLUDED_NOTE]);
    // No BLOCKED leaf: the blocked finding is absent; three leaves are unsettled.
    let titles: Vec<&str> = r.findings.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Scans without a completed decision",
            "Scans incomplete",
            "Skill vulnerabilities reported"
        ]
    );
    assert_eq!(
        r.findings[0].evidence,
        "3 collected non-parent rows are pending, failed or have an unfamiliar status."
    );
    assert!(!everything(&r).contains("PRIVATE"));
}

/// G71: members the service sends as `null` stay unknown, never a value: a `null`
/// creation time is a missing one (excluded, [`EXCLUDED_NOTE`]), a `null` status is not a
/// completed decision, a `null` artifact type or outcome is `UNKNOWN`, and a row whose
/// `is_batch` or `child_scan_uuids` is `null` is left out of the outcome counts (it could be
/// a parent counted beside its children) with [`UNKNOWN_BATCH_NOTE`]; the source is partial.
#[test]
fn null_members_stay_unknown() {
    let client = Client::standard();
    let mut rows = Vec::new();
    let mut undated = scan("undated");
    undated.created_at = None;
    rows.push(undated);
    let mut unsettled = scan("unsettled");
    unsettled.status = None;
    unsettled.artifact_type = None;
    rows.push(unsettled);
    let mut unknown_batch = scan("unknown-batch");
    unknown_batch.is_batch = None;
    rows.push(unknown_batch);
    let mut unknown_children = scan("unknown-children");
    unknown_children.children = None;
    rows.push(unknown_children);
    let mut parent = scan("parent");
    parent.is_batch = Some(true);
    rows.push(parent);
    rows.push(scan("leaf"));
    client.scans.set(vec![page(rows, 6.0)]);
    let r = report(&client);
    let scans = source(&r, "Scans");
    assert_eq!(scans.status, Status::Partial);
    assert_eq!(scans.records, 6);
    assert_eq!(scans.notes, [EXCLUDED_NOTE, UNKNOWN_BATCH_NOTE]);
    let outcomes = table(&r, "Scan outcomes");
    assert_eq!(
        outcomes.rows,
        [
            vec![text("SKILL / BLOCKED"), Cell::Count(1)],
            vec![text("UNKNOWN / BLOCKED"), Cell::Count(1)],
        ]
    );
    assert_eq!(
        outcomes.note,
        "Collected 6 rows; excluded 1 parent/batch rows. Partial inventory only."
    );
    let unsettled = r
        .findings
        .iter()
        .find(|f| f.title == "Scans without a completed decision")
        .unwrap();
    assert_eq!(
        unsettled.evidence,
        "1 collected non-parent rows are pending, failed or have an unfamiliar status."
    );
    // Known membership everywhere: no note, the typed-model counts.
    let client = Client::standard();
    client
        .scans
        .set(vec![page(vec![scan("a"), scan("b")], 2.0)]);
    let r = report(&client);
    assert_eq!(source(&r, "Scans").status, Status::Complete);
    assert!(source(&r, "Scans").notes.is_empty());
}

/// Choice 84: either batch signal alone shows a parent (`is_batch` true, or a child listed),
/// whatever the other holds (`null` included); a leaf needs both (`false`, no child); only
/// a row neither decides is of unknown membership ([`UNKNOWN_BATCH_NOTE`], partial).
#[test]
fn either_batch_signal_decides_a_parent() {
    let with = |uuid: &str, is_batch: Option<bool>, children: Option<usize>| {
        let mut row = scan(uuid);
        row.is_batch = is_batch;
        row.children = children;
        row
    };
    for (is_batch, children, expected) in [
        (Some(true), None, Membership::Parent),
        (Some(true), Some(0), Membership::Parent),
        (Some(true), Some(2), Membership::Parent),
        (None, Some(2), Membership::Parent),
        (Some(false), Some(3), Membership::Parent),
        (Some(false), Some(0), Membership::Leaf),
        (None, None, Membership::Unknown),
        (None, Some(0), Membership::Unknown),
        (Some(false), None, Membership::Unknown),
    ] {
        assert_eq!(
            batch_membership(&with("x", is_batch, children)),
            expected,
            "{is_batch:?} {children:?}"
        );
    }
    // Parents decided by one signal, beside a `null` in the other: excluded, the source
    // complete, no unknown-membership note.
    let client = Client::standard();
    client.scans.set(vec![page(
        vec![
            with("parent-flag", Some(true), None),
            with("parent-children", None, Some(2)),
            with("parent-both", Some(false), Some(1)),
            scan("leaf"),
        ],
        4.0,
    )]);
    let r = report(&client);
    let scans = source(&r, "Scans");
    assert_eq!(scans.status, Status::Complete);
    assert!(scans.notes.is_empty(), "{:?}", scans.notes);
    let outcomes = table(&r, "Scan outcomes");
    assert_eq!(
        outcomes.rows,
        [vec![text("SKILL / BLOCKED"), Cell::Count(1)]]
    );
    assert_eq!(
        outcomes.note,
        "Collected 4 rows; excluded 3 parent/batch rows. Complete inventory for requested window."
    );
    // A row neither signal decides (`is_batch` null, no child; `false` with a null list)
    // stays unknown: left out of the counts and of the excluded parents.
    let client = Client::standard();
    client.scans.set(vec![page(
        vec![
            with("parent-flag", Some(true), None),
            with("unknown-flag", None, Some(0)),
            with("unknown-children", Some(false), None),
            scan("leaf"),
        ],
        4.0,
    )]);
    let r = report(&client);
    let scans = source(&r, "Scans");
    assert_eq!(scans.status, Status::Partial);
    assert_eq!(scans.notes, [UNKNOWN_BATCH_NOTE]);
    let outcomes = table(&r, "Scan outcomes");
    assert_eq!(
        outcomes.rows,
        [vec![text("SKILL / BLOCKED"), Cell::Count(1)]]
    );
    assert_eq!(
        outcomes.note,
        "Collected 4 rows; excluded 1 parent/batch rows. Partial inventory only."
    );
}

/// D322: a zoned ISO date-time (any offset, `T`/`t`, `Z`/`z`, a fraction of any length) and
/// a date-only `YYYY-MM-DD` (UTC midnight) are usable; a zone-less date-time and every
/// loose form are not (TS `Date.parse` reads them in the host's zone or loosely). The
/// window is inclusive at both ends, in milliseconds.
#[test]
fn d322_creation_times_need_a_zone() {
    for (created_at, usable) in [
        ("2026-09-08T10:00:00Z", true),
        ("2026-09-08t10:00:00z", true),
        ("2026-09-08T12:00:00.000+00:00", true),
        ("2026-09-08T13:00:00+01:00", true),
        ("2026-09-08T10:00Z", true),
        ("2026-09-08T10:00:00.123456789Z", true),
        ("2026-08-09T12:00:00.000Z", true),
        ("2026-09-08", true),
        ("2026-08-09T11:59:59.999Z", false),
        ("2026-09-08T12:00:00.001Z", false),
        ("2026-08-09", false),
        ("2026-09-08T10:00:00", false),
        ("2026-09-08 10:00:00Z", false),
        ("Tue, 08 Sep 2026 10:00:00 GMT", false),
        ("2026-09-08T10:00:00+0100", false),
        ("", false),
    ] {
        let client = Client::standard();
        let mut row = scan("x");
        row.created_at = Some(created_at.to_owned());
        client.scans.set(vec![page(vec![row], 1.0)]);
        let r = report(&client);
        let s = source(&r, "Scans");
        let expected = if usable {
            Status::Complete
        } else {
            Status::Partial
        };
        assert_eq!(s.status, expected, "{created_at:?}");
        let counted = !table(&r, "Scan outcomes").rows.is_empty();
        assert_eq!(counted, usable, "{created_at:?}");
    }
}

/// The finding order is TypeScript's (the Scans findings, the Scans incomplete finding,
/// the Statistics finding or, for a failed read, the Statistics incomplete finding, the
/// Rules incomplete finding), not sorted; health `attention` wins over `review`; `review`
/// alone is `review`.
#[test]
fn findings_keep_the_typescript_order() {
    let client = Client::standard();
    let mut pending = scan("pending");
    pending.status = Some("RUNNING".to_owned());
    pending.eval_outcome = None;
    let mut out = scan("out");
    out.created_at = Some("2020-01-01T00:00:00Z".to_owned());
    client
        .scans
        .set(vec![page(vec![scan("blocked"), pending, out], 3.0)]);
    client.rules.set(vec![Err(ReadError::Status(403))]);
    let r = report(&client);
    let titles: Vec<(&str, &str)> = r
        .findings
        .iter()
        .map(|f| (f.title.as_str(), f.source.as_str()))
        .collect();
    assert_eq!(
        titles,
        [
            ("Blocked scans require review", "Scans"),
            ("Scans without a completed decision", "Scans"),
            ("Scans incomplete", "Scans"),
            ("Skill vulnerabilities reported", "Statistics"),
            ("Rules incomplete", "Rules"),
        ]
    );
    assert_eq!(r.health, Health::Attention);
    assert_eq!(
        r.findings[0].evidence,
        "1 collected non-parent scan rows have BLOCKED evaluations."
    );
    assert_eq!(
        r.findings[3].evidence,
        "2 findings reported in the server statistics window."
    );
    // A failed Statistics read: its incomplete finding takes the Statistics place.
    let client = Client::standard();
    let mut pending = scan("pending");
    pending.status = Some("RUNNING".to_owned());
    pending.eval_outcome = None;
    let mut out = scan("out");
    out.created_at = Some("2020-01-01T00:00:00Z".to_owned());
    client
        .scans
        .set(vec![page(vec![scan("blocked"), pending, out], 3.0)]);
    client.stats.set(vec![Err(ReadError::Failed)]);
    client.rules.set(vec![Err(ReadError::Status(403))]);
    let r = report(&client);
    let titles: Vec<(&str, &str)> = r
        .findings
        .iter()
        .map(|f| (f.title.as_str(), f.source.as_str()))
        .collect();
    assert_eq!(
        titles,
        [
            ("Blocked scans require review", "Scans"),
            ("Scans without a completed decision", "Scans"),
            ("Scans incomplete", "Scans"),
            ("Statistics incomplete", "Statistics"),
            ("Rules incomplete", "Rules"),
        ]
    );
    // Review only.
    let client = Client::standard();
    let mut allowed = scan("a");
    allowed.eval_outcome = Some("ALLOWED".to_owned());
    client.scans.set(vec![page(vec![allowed], 1.0)]);
    client.stats.set(vec![Ok(Stats {
        unique_skills_scanned: metric(1.0, None),
        total_vulnerabilities_found: metric(0.0, None),
    })]);
    client.rules.set(vec![Err(ReadError::Failed)]);
    let r = report(&client);
    assert_eq!(r.health, Health::Review);
    assert_eq!(r.findings.len(), 1);
    // A source that is only partly unavailable keeps the health assessable.
    let client = Client::standard();
    client.scans.set(vec![Err(ReadError::Failed)]);
    client.stats.set(vec![Err(ReadError::Failed)]);
    assert_eq!(report(&client).health, Health::Review);
}

/// The statistics as JavaScript prints them: `percent_change` `null` is `Unknown`, server
/// numbers through `Number::toString` (`12.5`, `-3`, `1e-7`); the counts are integers (both
/// SDKs validate them so, choice 49).
#[test]
fn statistics_print_server_numbers() {
    let client = Client::standard();
    client.stats.set(vec![Ok(Stats {
        unique_skills_scanned: metric(4.0, Some(12.5)),
        total_vulnerabilities_found: metric(7.0, Some(-3.0)),
    })]);
    let r = report(&client);
    let html = html::render(&r, &html::SUPPLYCHAIN);
    assert!(html.contains("<tr><td>Unique skills scanned</td><td>4</td><td>12.5</td></tr><tr><td>Vulnerabilities found</td><td>7</td><td>-3</td></tr>"), "{html}");
    assert!(html.contains("<p>7 findings reported in the server statistics window.</p>"));
    client.stats.set(vec![Ok(Stats {
        unique_skills_scanned: metric(0.0, Some(1e-7)),
        total_vulnerabilities_found: metric(0.0, None),
    })]);
    let html = html::render(&report(&client), &html::SUPPLYCHAIN);
    assert!(html.contains("<td>0</td><td>1e-7</td>"), "{html}");
    assert!(html.contains("<td>0</td><td>Unknown</td>"), "{html}");
    let s = source(&report(&client), "Statistics").clone();
    assert_eq!((s.records, s.pages), (1, 1));
}

/// The rendering is the shared template with the supplychain profile (SC§9.4): the product
/// line, the window label, the evidence rows with the run's window, the five limitations
/// and the footer; the title escaped.
#[test]
fn the_document_uses_the_supplychain_profile() {
    let client = Client::standard();
    let now = || NOW;
    let options = Options {
        title: "<b>\"T&x'</b>",
        max_pages: 40,
        now: &now,
    };
    let r = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(collect(&client, &options))
        .unwrap();
    let html = html::render(&r, &html::SUPPLYCHAIN);
    assert!(html.contains("<title>&#60;b&#62;&#34;T&#38;x&#39;&#60;/b&#62;</title>"));
    assert!(
        html.contains("<header><p>Prisma AIRS AI Supply Chain — AgentGuard</p><h1>&#60;b&#62;")
    );
    assert!(html.contains("<span class=\"badge\">Attention required</span><p>Collection: 2026-09-08T12:00:00.000Z → 2026-09-08T12:00:00.000Z</p><p>30-day scan inventory; rolling 30_DAYS statistics; current rule catalog: 2026-08-09T12:00:00.000Z → 2026-09-08T12:00:00.000Z</p>"));
    assert!(html.contains("<tr><td>Scans</td><td>listScans()</td><td>2026-08-09T12:00:00.000Z to 2026-09-08T12:00:00.000Z</td><td>complete</td><td>1</td><td>1</td><td>Collection completed.</td></tr><tr><td>Statistics</td><td>getScanStats()</td><td>Server rolling 30_DAYS</td><td>complete</td><td>1</td><td>1</td><td>Collection completed.</td></tr><tr><td>Rules</td><td>listRules()</td><td>Current catalog</td><td>complete</td><td>1</td><td>1</td><td>Collection completed.</td></tr>"));
    let limitations: String = LIMITATIONS
        .iter()
        .map(|item| format!("<li>{item}</li>"))
        .collect();
    assert!(html.contains(&format!(
        "<section id=\"scope\"><h2>Scope and limitations</h2><ul>{limitations}</ul></section><footer>Prisma AIRS CLI · Experimental browser APIs report schema 1 · Works offline and without JavaScript.</footer>"
    )));
    let sections: Vec<&str> = html
        .match_indices("<section id=\"")
        .map(|(at, _)| &html[at + 13..at + 13 + html[at + 13..].find('"').unwrap()])
        .collect();
    assert_eq!(
        sections,
        [
            "findings", "table-0", "table-1", "table-2", "table-3", "scope"
        ]
    );
    assert!(html.ends_with("</script></body></html>\n"));
}

/// A cancelled read stops the report at once (D323); the later sources are not read.
#[test]
fn a_cancelled_read_stops_the_report() {
    let client = Client::standard();
    client.stats.set(vec![Err(ReadError::Cancelled)]);
    assert_eq!(collect_with(&client, 40), Err(Interrupted));
    assert_eq!(client.calls().len(), 2);
    let client = Client::standard();
    client
        .scans
        .set(vec![page(vec![scan("a")], 2.0), Err(ReadError::Cancelled)]);
    assert_eq!(collect_with(&client, 40), Err(Interrupted));
    assert_eq!(client.calls().len(), 2);
}

/// Page checks in TypeScript's order: a total that is not a safe non-negative integer, a
/// page over 10 rows, rows beyond the total, an empty `uuid` fail the page; on a first page
/// that leaves the source unavailable (no rows).
#[test]
fn page_checks_fail_the_page() {
    for (name, first) in [
        ("negative total", page(vec![scan("a")], -1.0)),
        ("fractional total", page(vec![scan("a")], 1.5)),
        (
            "unsafe total",
            page(vec![scan("a")], 9_007_199_254_740_992.0),
        ),
        ("over the total", page(vec![scan("a"), scan("b")], 1.0)),
        ("empty uuid", page(vec![scan("")], 1.0)),
        (
            "eleven rows",
            page((0..11).map(|i| scan(&i.to_string())).collect(), 11.0),
        ),
        ("empty page", page(Vec::new(), 1.0)),
    ] {
        let client = Client::standard();
        client.scans.set(vec![first]);
        let r = report(&client);
        let s = source(&r, "Scans");
        assert_eq!(s.status, Status::Unavailable, "{name}");
        assert_eq!(s.notes, [FAILED_NOTE], "{name}");
        assert_eq!(s.pages, 1, "{name}");
        assert!(
            r.tables.iter().all(|t| t.title != "Scan outcomes"),
            "{name}: no table without rows"
        );
    }
    // A repeated uuid in the middle of a page keeps the rows before it (TS pushes row by
    // row).
    let client = Client::standard();
    client
        .scans
        .set(vec![page(vec![scan("a"), scan("b"), scan("a")], 3.0)]);
    let s = source(&report(&client), "Scans").clone();
    assert_eq!((s.status, s.records), (Status::Partial, 2));
}
