//! The TypeScript `tests/unit/reports/aigateway.spec.ts` cases (and its
//! `tests/helpers/aigateway-report.ts` fixture), against a scripted [`Reader`], plus the
//! Rust additions of DESIGN §19.15 (D249: zone-less times, the window bounds; the
//! renderer profile).

use super::*;
use crate::report::html;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};

fn json(text: &str) -> OValue {
    crate::json::parse(text).unwrap()
}

fn value(value: serde_json::Value) -> OValue {
    crate::json::to_ordered(&value).unwrap()
}

/// The TS fixture's chart `data` (every chart field present, `PRIVATE-CANARY` beside it).
fn data() -> serde_json::Value {
    serde_json::json!({
        "total": 0, "avg": 0, "p50": null, "p90": null, "p99": null,
        "total_request_units": 0, "total_response_units": 0,
        "retryTotal": 0, "fallbackTotal": 0, "isQuotaExceeded": false,
        "records": [], "trend": [],
        "summary": {
            "cacheHits": 0, "avgCacheLatency": null, "totalRequests": 0, "cacheSpeedup": 0,
            "totalCacheHits": 0, "hitRate": 0, "total": 0, "unique": 0, "avg": 0,
            "errorPercent": 0, "totalErrors": 0, "totalUniqueErrorCodes": 0
        },
        "unique_ai_models": [], "unique_status_codes": [],
        "secret": "PRIVATE-CANARY"
    })
}

fn envelope_of(data: serde_json::Value) -> OValue {
    value(serde_json::json!({"success": true, "data": data}))
}

/// `data()` with `edit` applied, in an envelope.
fn edited(edit: impl FnOnce(&mut serde_json::Value)) -> OValue {
    let mut data = data();
    edit(&mut data);
    envelope_of(data)
}

/// One transaction log row (TS `row(id)`).
fn row(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id, "workspace_slug": "workspace-slug", "created_at": "2026-09-01T12:00:00Z",
        "response_status_code": 200, "metadataValue": ["PRIVATE-CANARY"]
    })
}

type Answer = Result<OValue, ReadError>;

/// A queue of answers (the last one repeats).
#[derive(Default)]
struct Script(RefCell<VecDeque<Answer>>);

impl Script {
    fn of(answers: Vec<Answer>) -> Self {
        Self(RefCell::new(answers.into()))
    }
    fn next(&self) -> Answer {
        let mut answers = self.0.borrow_mut();
        if answers.len() > 1 {
            answers.pop_front().unwrap()
        } else {
            answers.front().cloned().unwrap()
        }
    }
    fn set(&self, answers: Vec<Answer>) {
        *self.0.borrow_mut() = answers.into();
    }
}

/// The TS `gatewayReportFixtures()` client: every source complete; private fields that
/// must never reach the report. Every call is recorded (`calls`).
struct Client {
    workspaces: Script,
    charts: BTreeMap<&'static str, Script>,
    boundaries: Script,
    logs: Script,
    listed: Script,
    info: Script,
    catalog: Script,
    calls: RefCell<Vec<String>>,
}

impl Client {
    fn standard() -> Self {
        Self {
            workspaces: Script::of(vec![Ok(json(
                r#"{"total": 1, "data": [{"id": "workspace-id", "slug": "workspace-slug", "name": "dev", "secret": "PRIVATE-CANARY"}]}"#,
            ))]),
            charts: Chart::ALL
                .iter()
                .map(|chart| (chart.method(), Script::of(vec![Ok(envelope_of(data()))])))
                .collect(),
            boundaries: Script::of(vec![Ok(envelope_of(data()))]),
            logs: Script::of(vec![Ok(envelope_of(data()))]),
            listed: Script::of(vec![Ok(json(
                r#"{"total": 1, "data": [{"id": "PRIVATE-ID", "key": "PRIVATE-CANARY"}]}"#,
            ))]),
            info: Script::of(vec![Ok(json(
                r#"{"benefits": {"limits": {"workspaces": -1}}, "settings": {"secret": "PRIVATE-CANARY"}}"#,
            ))]),
            catalog: Script::of(vec![Ok(json(
                r#"{"evals": [{"secret": "PRIVATE-CANARY"}]}"#,
            ))]),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn chart(&self, method: &str) -> &Script {
        &self.charts[method]
    }

    fn record(&self, call: String) {
        self.calls.borrow_mut().push(call);
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Reader for Client {
    async fn workspaces(&self) -> Answer {
        self.record("workspaces".into());
        self.workspaces.next()
    }
    async fn chart(&self, chart: Chart, slug: &str) -> Answer {
        self.record(format!("{} {slug}", chart.method()));
        self.chart(chart.method()).next()
    }
    async fn filter_boundaries(&self, slug: &str) -> Answer {
        self.record(format!("filterBoundaries {slug}"));
        self.boundaries.next()
    }
    async fn logs(&self, slug: &str, page: u32) -> Answer {
        self.record(format!("logs {slug} {page}"));
        self.logs.next()
    }
    async fn configs(&self, id: &str) -> Answer {
        self.record(format!("configs {id}"));
        self.listed.next()
    }
    async fn service_keys(&self, id: &str) -> Answer {
        self.record(format!("service {id}"));
        self.listed.next()
    }
    async fn user_keys(&self, id: &str) -> Answer {
        self.record(format!("user {id}"));
        self.listed.next()
    }
    async fn organisation_info(&self) -> Answer {
        self.record("info".into());
        self.info.next()
    }
    async fn catalog(&self) -> Answer {
        self.record("catalog".into());
        self.catalog.next()
    }
}

/// `2026-09-01T00:00:00Z`, `2026-09-02T00:00:00Z`, `2026-09-03T00:00:00Z`.
const START: i64 = 1_788_220_800_000;
const END: i64 = START + 86_400_000;
const NOW: i64 = END + 86_400_000;

fn collect_with(client: &Client, workspace: &str, max_pages: u32, title: &str) -> Report {
    let now = || NOW;
    let options = Options {
        title,
        max_pages,
        workspace,
        start_ms: START,
        end_ms: END,
        now: &now,
    };
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(collect(client, &options))
        .expect("not interrupted")
}

fn report(client: &Client) -> Report {
    collect_with(client, "dev", 40, "AI Gateway environment report")
}

fn source<'a>(report: &'a Report, name: &str) -> &'a Source {
    report.sources.iter().find(|s| s.name == name).unwrap()
}

fn rows<'a>(report: &'a Report, title: &str) -> &'a [Vec<Cell>] {
    &report
        .tables
        .iter()
        .find(|t| t.title == title)
        .unwrap()
        .rows
}

fn everything(report: &Report) -> String {
    format!("{report:?}\n{}", html::render(report, &html::GATEWAY))
}

fn text(value: &str) -> Cell {
    Cell::Text(value.to_owned())
}

#[test]
fn highlights_http_2xx_error_classifications_without_changing_server_totals() {
    let client = Client::standard();
    client.chart("errorCategoryTrends").set(vec![Ok(edited(|d| {
        d["trend"] = serde_json::json!([{"response_status_code": 200, "count": 2}]);
    }))]);
    let r = report(&client);
    assert!(
        r.findings
            .iter()
            .any(|f| f.title.contains("Success-status"))
    );
    assert!(rows(&r, "Error categories").contains(&vec![Cell::Count(200), Cell::Count(2)]));
}

#[test]
fn distinguishes_expected_policy_blocks_from_server_outages() {
    let client = Client::standard();
    client.chart("errorCategoryTrends").set(vec![Ok(edited(|d| {
        d["trend"] = serde_json::json!([{"response_status_code": 446, "count": 2}]);
    }))]);
    let r = report(&client);
    assert_eq!(r.health, Health::Review);
    assert_eq!(
        r.findings[0].title,
        "Gateway errors or policy blocks observed"
    );
}

#[test]
fn rejects_invalid_request_counts() {
    for total in [
        Some(serde_json::json!(-1)),
        Some(serde_json::json!(0.5)),
        None,
    ] {
        let client = Client::standard();
        client
            .chart("requests")
            .set(vec![Ok(edited(|d| match &total {
                Some(total) => d["total"] = total.clone(),
                None => {
                    d.as_object_mut().unwrap().remove("total");
                }
            }))]);
        let r = report(&client);
        assert_eq!(
            source(&r, "telemetry.requests").status,
            Status::Unavailable,
            "{total:?}"
        );
    }
}

#[test]
fn preserves_signed_feedback_and_fractional_cost() {
    let client = Client::standard();
    client
        .chart("feedbackWeighted")
        .set(vec![Ok(edited(|d| d["total"] = serde_json::json!(-2.5)))]);
    client
        .chart("cost")
        .set(vec![Ok(edited(|d| d["total"] = serde_json::json!(0.031)))]);
    let r = report(&client);
    assert!(r.sources.iter().all(|s| s.status == Status::Complete));
    let metrics = rows(&r, "Telemetry metrics");
    assert!(metrics.contains(&vec![
        text("feedbackWeighted"),
        text("total"),
        Cell::Number(-2.5)
    ]));
    assert!(metrics.contains(&vec![text("cost"), text("total"), Cell::Number(0.031)]));
    // null stays unknown: never zero.
    assert!(metrics.contains(&vec![text("latency"), text("p99"), Cell::Null]));
    let page = html::render(&r, &html::GATEWAY);
    assert!(page.contains("<td>-2.5</td>") && page.contains("<td>0.031</td>"));
    assert!(page.contains("<td>p99</td><td>Unknown</td>"));
}

#[test]
fn does_not_fetch_a_different_workspace_when_the_requested_name_is_absent() {
    let client = Client::standard();
    let r = collect_with(&client, "missing", 40, "t");
    assert_eq!(r.health, Health::Unknown);
    assert_eq!(client.calls(), ["workspaces", "info", "catalog"]);
    assert_eq!(source(&r, "workspaces.list").status, Status::Partial);
    assert_eq!(r.incomplete(), 23);
}

#[test]
fn an_ambiguous_display_name_resolves_nothing() {
    let client = Client::standard();
    client.workspaces.set(vec![Ok(json(
        r#"{"total": 2, "data": [{"id": "a", "slug": "s-a", "name": "dev"}, {"id": "b", "slug": "s-b", "name": "dev"}]}"#,
    ))]);
    let r = report(&client);
    assert_eq!(client.calls(), ["workspaces", "info", "catalog"]);
    assert_eq!(r.incomplete(), 23);
    // By id and by slug resolve too.
    for reference in ["workspace-id", "workspace-slug"] {
        let client = Client::standard();
        let r = collect_with(&client, reference, 40, "t");
        assert_eq!(r.incomplete(), 0, "{reference}");
    }
}

/// D254: on an incomplete workspace list a display name resolves nothing (a second row
/// with the name may sit beyond the answer); an exact id or slug still resolves.
#[test]
fn d254_an_incomplete_list_resolves_only_an_id_or_slug() {
    for incomplete in [
        r#"{"total": 50, "data": [{"id": "a", "slug": "s-a", "name": "dev"}]}"#,
        r#"{"total": 1, "has_more": true, "data": [{"id": "a", "slug": "s-a", "name": "dev"}]}"#,
    ] {
        let client = Client::standard();
        client.workspaces.set(vec![Ok(json(incomplete))]);
        let r = collect_with(&client, "dev", 40, "t");
        assert_eq!(
            client.calls(),
            ["workspaces", "info", "catalog"],
            "{incomplete}"
        );
        assert_eq!(source(&r, "workspaces.list").status, Status::Partial);
        for reference in ["a", "s-a"] {
            let client = Client::standard();
            client.workspaces.set(vec![Ok(json(incomplete))]);
            let r = collect_with(&client, reference, 40, "t");
            assert_eq!(client.calls()[1], "requests s-a", "{reference}");
            assert_eq!(source(&r, "workspaces.list").status, Status::Partial);
        }
    }
}

#[test]
fn collects_all_25_sources_with_one_fixed_window_and_no_sensitive_fields() {
    let client = Client::standard();
    let r = report(&client);
    assert_eq!(r.sources.len(), 25);
    assert!(r.sources.iter().all(|s| s.status == Status::Complete));
    assert_eq!(r.health, Health::NoFindings);
    let calls = client.calls();
    assert_eq!(calls.len(), 25);
    assert_eq!(calls[0], "workspaces");
    for (call, chart) in calls[1..18].iter().zip(Chart::ALL) {
        assert_eq!(*call, format!("{} workspace-slug", chart.method()));
    }
    assert_eq!(
        calls[18..],
        [
            "filterBoundaries workspace-slug",
            "logs workspace-slug 0",
            "configs workspace-id",
            "service workspace-id",
            "user workspace-id",
            "info",
            "catalog"
        ]
    );
    let all = everything(&r);
    assert!(!all.contains("PRIVATE"));
    assert!(!all.contains("workspace-id") && !all.contains("workspace-slug"));
    let page = html::render(&r, &html::GATEWAY);
    assert!(page.contains("connect-src &#39;none&#39;"));
    assert!(page.contains(
        "<p>Telemetry window (UTC): 2026-09-01T00:00:00.000Z → 2026-09-02T00:00:00.000Z</p>"
    ));
    assert!(
        page.contains("<p>Collection: 2026-09-03T00:00:00.000Z → 2026-09-03T00:00:00.000Z</p>")
    );
    assert!(page.contains("<header><p>Prisma AIRS AI Gateway</p>"));
    assert!(page.contains(
        "<footer>Prisma AIRS CLI · AI Gateway report schema 1 · Works offline and without JavaScript.</footer>"
    ));
    assert!(page.ends_with("</html>\n") && !page.ends_with("\n\n"));
    for limitation in LIMITATIONS {
        assert!(page.contains(&format!("<li>{}</li>", html::escape(limitation))));
    }
    let titles: Vec<String> = r.all_tables().into_iter().map(|t| t.title).collect();
    assert_eq!(
        titles,
        [
            "Telemetry metrics",
            "Error categories",
            "Error timeline",
            "Current configuration and capabilities",
            "Transaction coverage",
            "Evidence and completeness"
        ]
    );
    assert_eq!(
        rows(&r, "Current configuration and capabilities"),
        [
            vec![
                text("workspaces.list"),
                text("Active workspaces returned"),
                Cell::Count(1)
            ],
            vec![text("configs.list"), text("Rows returned"), Cell::Count(1)],
            vec![
                text("apiKeys.listService"),
                text("Rows returned"),
                Cell::Count(1)
            ],
            vec![
                text("apiKeys.listUser"),
                text("Rows returned"),
                Cell::Count(1)
            ],
            vec![
                text("organisations.getInfo"),
                text("Configured limit categories"),
                Cell::Count(1)
            ],
            vec![
                text("guardrails.getCatalog"),
                text("Available evaluators"),
                Cell::Count(1)
            ],
        ]
    );
    // 34 metric rows (TS capture): the chart fields, feedbackModels and the two
    // boundary counts.
    assert_eq!(rows(&r, "Telemetry metrics").len(), 34);
    assert_eq!(
        rows(&r, "Transaction coverage"),
        [
            vec![text("Server total"), Cell::Count(0)],
            vec![text("Unique collected"), Cell::Count(0)]
        ]
    );
}

#[test]
fn paginates_zero_based_pages_and_counts_unique_transactions_only() {
    let client = Client::standard();
    client.logs.set(vec![
        Ok(edited(|d| {
            d["total"] = serde_json::json!(2);
            d["records"] = serde_json::json!([row("a")]);
        })),
        Ok(edited(|d| {
            d["total"] = serde_json::json!(2);
            d["records"] = serde_json::json!([row("b")]);
        })),
    ]);
    let r = report(&client);
    let logs = source(&r, "telemetry.logs");
    assert_eq!(
        (logs.status, logs.records, logs.pages),
        (Status::Complete, 2, 2)
    );
    let pages: Vec<String> = client
        .calls()
        .into_iter()
        .filter(|call| call.starts_with("logs"))
        .collect();
    assert_eq!(pages, ["logs workspace-slug 0", "logs workspace-slug 1"]);
    assert_eq!(
        rows(&r, "Transaction coverage"),
        [
            vec![text("Server total"), Cell::Count(2)],
            vec![text("Unique collected"), Cell::Count(2)],
            vec![text("HTTP 200"), Cell::Count(2)]
        ]
    );
}

#[test]
fn marks_broken_pagination_partial() {
    for problem in [
        "duplicate",
        "empty",
        "changed-total",
        "wrong-workspace",
        "outside-window",
        "zone-less",
    ] {
        let client = Client::standard();
        let second = match problem {
            "duplicate" => row("a"),
            "wrong-workspace" => {
                let mut row = row("b");
                row["workspace_slug"] = serde_json::json!("other");
                row
            }
            "outside-window" => {
                let mut row = row("b");
                row["created_at"] = serde_json::json!("2000-01-01");
                row
            }
            // D249: a zone-less time is not a valid time (TS reads it in the host's zone).
            "zone-less" => {
                let mut row = row("b");
                row["created_at"] = serde_json::json!("2026-09-01T12:00:00");
                row
            }
            _ => row("b"),
        };
        client.logs.set(vec![
            Ok(edited(|d| {
                d["total"] = serde_json::json!(2);
                d["records"] = serde_json::json!([row("a")]);
            })),
            Ok(edited(|d| {
                d["total"] = serde_json::json!(if problem == "changed-total" { 3 } else { 2 });
                d["records"] = if problem == "empty" {
                    serde_json::json!([])
                } else {
                    serde_json::json!([second])
                };
            })),
        ]);
        let r = report(&client);
        let logs = source(&r, "telemetry.logs");
        assert_eq!(logs.status, Status::Partial, "{problem}");
        assert_eq!(logs.notes, [GENERIC_NOTE], "{problem}");
    }
}

#[test]
fn the_window_is_inclusive_at_both_ends_and_a_date_only_time_is_utc_midnight() {
    let client = Client::standard();
    let mut first = row("a");
    first["created_at"] = serde_json::json!("2026-09-01T00:00:00.000Z");
    let mut last = row("b");
    last["created_at"] = serde_json::json!("2026-09-02T02:00:00+02:00");
    let mut midnight = row("c");
    midnight["created_at"] = serde_json::json!("2026-09-02");
    client.logs.set(vec![Ok(edited(|d| {
        d["total"] = serde_json::json!(3);
        d["records"] = serde_json::json!([first, last, midnight]);
    }))]);
    let r = report(&client);
    assert_eq!(source(&r, "telemetry.logs").status, Status::Complete);
}

#[test]
fn a_record_outside_the_window_makes_the_logs_unavailable_with_their_coverage_rows() {
    let client = Client::standard();
    let mut late = row("a");
    late["created_at"] = serde_json::json!("2026-09-02T00:00:00.001Z");
    client.logs.set(vec![Ok(edited(|d| {
        d["total"] = serde_json::json!(3);
        d["records"] = serde_json::json!([late]);
    }))]);
    let r = report(&client);
    let logs = source(&r, "telemetry.logs");
    assert_eq!(
        (logs.status, logs.records, logs.pages),
        (Status::Unavailable, 0, 1)
    );
    assert_eq!(
        rows(&r, "Transaction coverage"),
        [
            vec![text("Server total"), Cell::Count(3)],
            vec![text("Unique collected"), Cell::Count(0)]
        ]
    );
}

#[test]
fn marks_budget_truncation_and_inventory_truncation_partial() {
    let client = Client::standard();
    client.logs.set(vec![Ok(edited(|d| {
        d["total"] = serde_json::json!(2);
        d["records"] = serde_json::json!([row("a")]);
    }))]);
    client.listed.set(vec![Ok(json(
        r#"{"total": 3, "has_more": true, "data": []}"#,
    ))]);
    let r = collect_with(&client, "dev", 1, "t");
    assert_eq!(
        r.sources
            .iter()
            .filter(|s| s.status == Status::Partial)
            .count(),
        4
    );
    assert_eq!(source(&r, "telemetry.logs").notes, [BUDGET_NOTE]);
    assert_eq!(source(&r, "configs.list").notes, [LIST_NOTE]);
}

#[test]
fn keeps_http_failure_evidence_without_error_body_leaks() {
    for status in [400, 401, 403, 429, 500] {
        let client = Client::standard();
        client
            .chart("errors")
            .set(vec![Err(ReadError::Status(status))]);
        let r = report(&client);
        let errors = source(&r, "telemetry.errors");
        assert_eq!((errors.status, errors.records), (Status::Unavailable, 0));
        assert_eq!(
            errors.notes,
            [format!(
                "HTTP {status}: request failed; check access and service availability."
            )]
        );
        assert!(!everything(&r).contains("PRIVATE"));
    }
    // A status outside 400–599 and a failure without one get the generic note.
    for error in [ReadError::Status(302), ReadError::Failed] {
        let client = Client::standard();
        client.chart("errors").set(vec![Err(error)]);
        assert_eq!(
            source(&report(&client), "telemetry.errors").notes,
            [GENERIC_NOTE]
        );
    }
}

#[test]
fn flags_quota_limits_and_missing_metrics_without_replacing_them_with_zero() {
    let client = Client::standard();
    client.chart("errors").set(vec![Ok(edited(|d| {
        d["isQuotaExceeded"] = serde_json::json!(true);
        d["total"] = serde_json::Value::Null;
    }))]);
    client.chart("cost").set(vec![Ok(edited(|d| {
        d.as_object_mut().unwrap().remove("total");
    }))]);
    let r = report(&client);
    let errors = source(&r, "telemetry.errors");
    assert_eq!(errors.status, Status::Partial);
    assert_eq!(errors.notes, [QUOTA_NOTE]);
    assert_eq!(source(&r, "telemetry.cost").status, Status::Unavailable);
    assert!(rows(&r, "Telemetry metrics").contains(&vec![
        text("errors"),
        text("total"),
        Cell::Null
    ]));
    // The quota note is repeated once per log page (TS).
    let client = Client::standard();
    client.logs.set(vec![
        Ok(edited(|d| {
            d["isQuotaExceeded"] = serde_json::json!(true);
            d["total"] = serde_json::json!(2);
            d["records"] = serde_json::json!([row("a")]);
        })),
        Ok(edited(|d| {
            d["isQuotaExceeded"] = serde_json::json!(true);
            d["total"] = serde_json::json!(2);
            d["records"] = serde_json::json!([row("b")]);
        })),
    ]);
    let logs = source(&report(&client), "telemetry.logs").clone();
    assert_eq!(logs.status, Status::Partial);
    assert_eq!(logs.notes, [QUOTA_NOTE, QUOTA_NOTE]);
}

#[test]
fn rejects_success_false_and_returns_unknown_without_available_telemetry() {
    let client = Client::standard();
    let failed = value(serde_json::json!({"success": false, "data": data()}));
    for script in client.charts.values() {
        script.set(vec![Ok(failed.clone())]);
    }
    client.boundaries.set(vec![Ok(failed.clone())]);
    client.logs.set(vec![Ok(failed)]);
    let r = report(&client);
    assert_eq!(r.health, Health::Unknown);
    assert_eq!(
        r.sources
            .iter()
            .filter(|s| s.status == Status::Unavailable)
            .count(),
        19
    );
}

#[test]
fn the_logs_alone_make_the_health_known() {
    let client = Client::standard();
    for script in client.charts.values() {
        script.set(vec![Err(ReadError::Status(503))]);
    }
    client.boundaries.set(vec![Err(ReadError::Status(503))]);
    let r = report(&client);
    assert_eq!(r.health, Health::Review);
    assert_eq!(source(&r, "telemetry.logs").status, Status::Complete);
}

#[test]
fn flags_server_errors_formats_utc_trends_and_escapes_report_titles() {
    let client = Client::standard();
    client.chart("errorCategoryTrends").set(vec![Ok(edited(|d| {
        d["trend"] = serde_json::json!([{"response_status_code": 503, "count": 2}]);
    }))]);
    client.chart("groupedErrors").set(vec![Ok(edited(|d| {
        d["trend"] = serde_json::json!([
            {"x": "2026-09-01T01:00:00Z", "y": [{"response_status_code": 503, "count": 2}]},
            {"x": "2026-09-01T11:00:00+02:00", "y": [{"response_status_code": 446, "count": 1}]}
        ]);
    }))]);
    let r = collect_with(&client, "dev", 40, "<script>alert(1)</script>");
    assert_eq!(r.health, Health::Attention);
    assert!(!html::render(&r, &html::GATEWAY).contains("<script>alert"));
    assert_eq!(
        rows(&r, "Error timeline"),
        [
            vec![
                text("2026-09-01T01:00:00.000Z"),
                Cell::Count(503),
                Cell::Count(2)
            ],
            vec![
                text("2026-09-01T09:00:00.000Z"),
                Cell::Count(446),
                Cell::Count(1)
            ]
        ]
    );
}

#[test]
fn an_invalid_bucket_keeps_its_records_but_adds_no_rows() {
    let client = Client::standard();
    client.chart("groupedErrors").set(vec![Ok(edited(|d| {
        d.as_object_mut().unwrap().remove("records");
        d["trend"] = serde_json::json!([{"x": "2026-09-01T01:00", "y": []}]);
    }))]);
    let r = report(&client);
    let grouped = source(&r, "telemetry.groupedErrors");
    assert_eq!(
        (grouped.status, grouped.records, grouped.pages),
        (Status::Partial, 1, 1)
    );
    assert!(rows(&r, "Error timeline").is_empty());
    assert!(
        !rows(&r, "Telemetry metrics")
            .iter()
            .any(|row| row[0] == text("groupedErrors"))
    );
}

#[test]
fn findings_keep_typescript_push_order_and_numbers_print_as_javascript() {
    let client = Client::standard();
    client.chart("errorCategoryTrends").set(vec![Ok(edited(|d| {
        d["trend"] = serde_json::json!([{"response_status_code": 446, "count": 2}]);
    }))]);
    client
        .chart("errors")
        .set(vec![Err(ReadError::Status(500))]);
    client.chart("cost").set(vec![Ok(edited(|d| {
        d["total"] = serde_json::json!(1e21);
        d["avg"] = serde_json::json!(1e-7);
    }))]);
    client
        .chart("feedbackWeighted")
        .set(vec![Ok(edited(|d| d["total"] = serde_json::json!(-0.0)))]);
    let r = report(&client);
    let titles: Vec<&str> = r.findings.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Gateway errors or policy blocks observed",
            "Incomplete evidence: telemetry.errors"
        ],
        "not sorted (TS)"
    );
    let page = html::render(&r, &html::GATEWAY);
    assert!(page.contains("<td>cost</td><td>total</td><td>1e+21</td>"));
    assert!(page.contains("<td>cost</td><td>avg</td><td>1e-7</td>"));
    assert!(page.contains("<td>feedbackWeighted</td><td>total</td><td>0</td>"));
}

#[test]
fn filter_boundaries_count_their_values_and_never_print_them() {
    let client = Client::standard();
    client.boundaries.set(vec![Ok(edited(|d| {
        d["unique_ai_models"] = serde_json::json!(["PRIVATE-MODEL", "PRIVATE-MODEL-2"]);
        d["unique_status_codes"] = serde_json::json!([200]);
    }))]);
    let r = report(&client);
    let metrics = rows(&r, "Telemetry metrics");
    assert!(metrics.contains(&vec![
        text("filterBoundaries"),
        text("unique_ai_models count"),
        Cell::Count(2)
    ]));
    assert!(!everything(&r).contains("PRIVATE"));
    // A second key that is not an array leaves the first row (TS pushes as it goes).
    let client = Client::standard();
    client.boundaries.set(vec![Ok(edited(|d| {
        d["unique_status_codes"] = serde_json::json!({});
    }))]);
    let r = report(&client);
    assert_eq!(
        source(&r, "telemetry.filterBoundaries").status,
        Status::Unavailable
    );
    assert!(rows(&r, "Telemetry metrics").contains(&vec![
        text("filterBoundaries"),
        text("unique_ai_models count"),
        Cell::Count(0)
    ]));
}

#[test]
fn a_cancelled_read_stops_the_report() {
    let client = Client::standard();
    client.chart("latency").set(vec![Err(ReadError::Cancelled)]);
    let now = || NOW;
    let options = Options {
        title: "t",
        max_pages: 40,
        workspace: "dev",
        start_ms: START,
        end_ms: END,
        now: &now,
    };
    let outcome = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(collect(&client, &options));
    assert_eq!(outcome, Err(Interrupted));
}

#[test]
fn a_window_before_1970_is_written_as_typescript_does() {
    assert_eq!(iso(-62_167_219_200_000), "0000-01-01T00:00:00.000Z");
    assert_eq!(iso(-1), "1969-12-31T23:59:59.999Z");
    assert_eq!(iso(253_402_300_799_999), "9999-12-31T23:59:59.999Z");
}
