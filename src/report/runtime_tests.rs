//! The TypeScript `tests/unit/reports/runtime.spec.ts` and the runtime cases of
//! `render.spec.ts`, against a scripted [`Reader`] (the TS `reportClient()` helper).

use super::*;
use crate::report::runtime_html;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::VecDeque;

/// `2026-09-07T12:00:00.000Z` (TS `REPORT_NOW`).
const NOW: i64 = 1_788_782_400_000;

fn ordered(value: &Value) -> OValue {
    crate::json::to_ordered(value).unwrap()
}

/// One scripted source: answers in order (the last one repeats), and the offsets asked.
#[derive(Default)]
struct Script {
    answers: RefCell<VecDeque<Result<Value, ReadError>>>,
    offsets: RefCell<Vec<u64>>,
}

impl Script {
    fn of(answer: Value) -> Self {
        Self::seq(vec![Ok(answer)])
    }
    fn seq(answers: Vec<Result<Value, ReadError>>) -> Self {
        Self {
            answers: RefCell::new(answers.into()),
            offsets: RefCell::new(Vec::new()),
        }
    }
    fn set(&self, answer: Value) {
        *self.answers.borrow_mut() = vec![Ok(answer)].into();
    }
    fn set_seq(&self, answers: Vec<Result<Value, ReadError>>) {
        *self.answers.borrow_mut() = answers.into();
    }
    fn fail(&self, error: ReadError) {
        *self.answers.borrow_mut() = vec![Err(error)].into();
    }
    fn next(&self, offset: u64) -> Result<OValue, ReadError> {
        self.offsets.borrow_mut().push(offset);
        let mut answers = self.answers.borrow_mut();
        let answer = if answers.len() > 1 {
            answers.pop_front().unwrap()
        } else {
            answers.front().cloned().unwrap()
        };
        answer.map(|value| ordered(&value))
    }
    fn calls(&self) -> Vec<u64> {
        self.offsets.borrow().clone()
    }
}

fn no_violations() -> Value {
    json!({"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
}

/// TS `reportProfile(overrides)`.
fn profile(overrides: Value) -> Value {
    let mut base = json!({
        "profile_name": "Production guardrail",
        "profile_id": "profile-private-id",
        "revision": 4,
        "active": true,
        "policy": {"ai-security-profiles": [{"model-configuration": {
            "mask-data-in-storage": true,
            "latency": {"inline-timeout-action": "block"}
        }}]},
    });
    for (key, value) in overrides.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

/// TS `reportSession(overrides)`.
fn session(overrides: Value) -> Value {
    let mut base = json!({
        "session_id": "private-session",
        "application_id": "app-1",
        "application_name": "Assistant",
        "last_session_activity": "2026-09-07T11:00:00Z",
        "violation_status": "passed",
        "violation_breakdown": no_violations(),
        "detection_type_violation_breakdown": [],
        "prompt": "NEVER-EXPORT-PROMPT",
        "response": "NEVER-EXPORT-RESPONSE",
        "user": "private@example.test",
    });
    for (key, value) in overrides.as_object().unwrap() {
        if value.is_null() {
            base.as_object_mut().unwrap().remove(key);
        } else {
            base[key] = value.clone();
        }
    }
    base
}

fn page(items: Vec<Value>, total: u64, skip: u64) -> Value {
    json!({"items": items, "pagination": {"total_items": total, "skip": skip, "limit": 25}})
}

struct Client {
    applications: Script,
    profiles: Script,
    customer_apps: Script,
    sessions: Script,
    chart: Script,
    top: Script,
    trend: Script,
}

impl Client {
    /// TS `reportClient()`.
    fn standard() -> Self {
        Self {
            applications: Script::of(json!({
                "items": [{"id": "app-1", "name": "Assistant", "sessions_total": 25, "sessions_violated": 0}],
                "pagination": {"total_items": 1}
            })),
            sessions: Script::of(page(vec![session(json!({}))], 1, 0)),
            chart: Script::of(json!({"bucket_size_seconds": 8640, "buckets": [{
                "bucket_number": 0, "time": "2026-09-07T12:00:00.000Z", "total": 1, "violating": 0,
                "violation_breakdown": no_violations(), "detection_type_violation_breakdown": []
            }]})),
            top: Script::of(json!({"applications": []})),
            trend: Script::of(
                json!({"violations": [{"bucket_number": 0, "date": "2026-09-07T12:00:00.000Z", "violation_breakdown": no_violations()}]}),
            ),
            profiles: Script::of(json!({"ai_profiles": [profile(json!({}))], "next_offset": 0})),
            customer_apps: Script::of(json!({"customer_apps": [{
                "customer_appId": "app-1", "tsg_id": "private-tenant", "app_name": "Registered assistant",
                "environment": "production", "cloud_provider": "aws", "model_name": "Example model",
                "api_keys_dp_info": [{"api_key_name": "private-key-name", "dp_name": "private-deployment", "auth_code": "NEVER-EXPORT-AUTH-CODE"}]
            }], "next_offset": 0})),
        }
    }

    fn all(&self) -> [&Script; 7] {
        [
            &self.applications,
            &self.profiles,
            &self.customer_apps,
            &self.sessions,
            &self.chart,
            &self.top,
            &self.trend,
        ]
    }
}

impl Reader for Client {
    async fn applications(&self, offset: u64) -> Result<OValue, ReadError> {
        self.applications.next(offset)
    }
    async fn profiles(&self, offset: u64) -> Result<OValue, ReadError> {
        self.profiles.next(offset)
    }
    async fn customer_apps(&self, offset: u64) -> Result<OValue, ReadError> {
        self.customer_apps.next(offset)
    }
    async fn sessions(&self, offset: u64) -> Result<OValue, ReadError> {
        self.sessions.next(offset)
    }
    async fn sessions_chart(&self) -> Result<OValue, ReadError> {
        self.chart.next(0)
    }
    async fn top_applications(&self) -> Result<OValue, ReadError> {
        self.top.next(0)
    }
    async fn violations_trend(&self) -> Result<OValue, ReadError> {
        self.trend.next(0)
    }
}

fn now() -> i64 {
    NOW
}

fn collect_with(client: &Client, title: &str, max_pages: u32) -> Report {
    let options = Options {
        title,
        max_pages,
        now: &now,
    };
    futures_util::FutureExt::now_or_never(collect_report(client, &options))
        .expect("the scripted reader never waits")
        .expect("not interrupted")
}

fn collect(client: &Client) -> Report {
    collect_with(client, "Daily environment report", 40)
}

fn titles(report: &Report) -> Vec<String> {
    report.findings.iter().map(|f| f.title.clone()).collect()
}

/// Every string of the model, for the "never exported" checks.
fn dump(report: &Report) -> String {
    format!("{report:?}")
}

#[test]
fn seven_read_only_sources_and_no_raw_identifiers() {
    let client = Client::standard();
    let report = collect(&client);
    assert_eq!(client.sessions.calls(), [0]);
    assert_eq!(client.applications.calls(), [0]);
    assert_eq!(client.profiles.calls(), [0]);
    assert_eq!(report.sources.len(), 7);
    assert!(report.sources.iter().all(|s| s.status == Status::Complete));
    assert_eq!(report.health, Health::NoFindings);
    assert_eq!(report.sessions_total, Some(25));
    assert_eq!(report.violating_total, Some(0));
    assert_eq!(report.sessions.entries, Some(1));
    assert_eq!(report.chart_sessions, Some(1));
    assert_eq!(report.window_start, "2026-09-06T12:00:00.000Z");
    assert_eq!(report.window_end, "2026-09-07T12:00:00.000Z");
    assert_eq!(report.applications[0].registered, Some(true));
    let text = dump(&report);
    for secret in [
        "NEVER-EXPORT",
        "private-tenant",
        "private-session",
        "private-key-name",
        "private-deployment",
        "private@example.test",
        "profile-private-id",
    ] {
        assert!(!text.contains(secret), "{secret}");
    }
}

#[test]
fn missing_bodies_are_not_explicit_empty_collections() {
    let client = Client::standard();
    client.applications.set(json!({}));
    client.sessions.set(json!({}));
    client.chart.set(json!({}));
    let report = collect(&client);
    assert_eq!(report.sessions_total, None);
    assert_eq!(report.sessions.entries, None);
    assert_eq!(report.chart_sessions, None);
    assert_eq!(report.health, Health::Review);
    client.applications.set(json!({"items": []}));
    client.sessions.set(page(vec![], 0, 0));
    client.chart.set(json!({"buckets": []}));
    client.profiles.set(json!({"ai_profiles": []}));
    client.customer_apps.set(json!({"customer_apps": []}));
    let report = collect(&client);
    assert!(report.sources.iter().all(|s| s.status == Status::Complete));
    assert_eq!(report.sessions_total, Some(0));
    let found = titles(&report);
    assert!(found.contains(&"No sessions reported in the daily window".to_owned()));
    assert!(found.contains(&"No security profiles returned".to_owned()));
    // D214: an absent profile list is no record array, not an empty inventory.
    client.profiles.set(json!({}));
    let report = collect(&client);
    assert_eq!(report.sources[1].status, Status::Unavailable);
    assert_eq!(
        report.sources[1].notes,
        [
            "The API returned no record array. An empty object or absent collection does not establish zero activity."
        ]
    );
    assert!(!titles(&report).contains(&"No security profiles returned".to_owned()));
}

#[test]
fn raw_errors_are_withheld_for_every_status() {
    for (error, note) in [
        (
            ReadError::Status(401),
            "HTTP 401: check Management API credentials and grants.",
        ),
        (
            ReadError::Status(403),
            "HTTP 403: check Management API credentials and grants.",
        ),
        (
            ReadError::Status(429),
            "HTTP 429: rate limited; retry the report later.",
        ),
        (
            ReadError::Status(500),
            "HTTP 500: source request failed; verify service availability and API compatibility.",
        ),
        (
            ReadError::Failed,
            "Source request or response validation failed; check connectivity and SDK compatibility.",
        ),
        (
            ReadError::Status(999),
            "Source request or response validation failed; check connectivity and SDK compatibility.",
        ),
    ] {
        let client = Client::standard();
        for script in client.all() {
            script.fail(error.clone());
        }
        let report = collect(&client);
        assert_eq!(report.health, Health::Unknown);
        assert!(
            report
                .sources
                .iter()
                .all(|s| s.status == Status::Unavailable)
        );
        assert!(
            report.sources.iter().all(|s| s.notes == [note]),
            "{error:?}"
        );
    }
}

#[test]
fn session_pages_use_composite_identities_and_keep_chart_counts() {
    let client = Client::standard();
    client.sessions.set_seq(vec![
        Ok(page(vec![session(json!({}))], 2, 0)),
        Ok(page(
            vec![session(json!({"application_id": "another-app"}))],
            2,
            1,
        )),
    ]);
    let report = collect(&client);
    assert_eq!(client.sessions.calls(), [0, 1]);
    assert_eq!(report.sessions.entries, Some(2));
    assert_eq!(report.chart_sessions, Some(1));
    assert!(titles(&report).contains(&"Session sources disagree".to_owned()));
}

#[test]
fn incoherent_initial_session_metadata_is_unavailable() {
    for response in [
        json!({"items": [], "pagination": {"limit": 25, "skip": 0, "total_items": 2}}),
        json!({"items": [session(json!({}))], "pagination": {"limit": 25, "skip": 1, "total_items": 1}}),
        json!({"items": [session(json!({}))], "pagination": {"limit": 10, "skip": 0, "total_items": 1}}),
        json!({"items": [session(json!({}))], "pagination": {}}),
        page(vec![session(json!({}))], 0, 0),
    ] {
        let client = Client::standard();
        client.sessions.set(response.clone());
        assert_eq!(
            collect(&client).sources[3].status,
            Status::Unavailable,
            "{response}"
        );
    }
}

#[test]
fn changing_totals_overlap_caps_and_later_errors_are_partial() {
    for later in [
        Ok(page(vec![session(json!({"session_id": "second"}))], 3, 1)),
        Ok(page(vec![session(json!({}))], 2, 1)),
        Err(ReadError::Failed),
    ] {
        let client = Client::standard();
        client
            .sessions
            .set_seq(vec![Ok(page(vec![session(json!({}))], 2, 0)), later]);
        let report = collect(&client);
        assert_eq!(report.sources[3].status, Status::Partial);
        assert_eq!(report.sessions.entries, Some(1));
    }
    let client = Client::standard();
    client.sessions.set(page(vec![session(json!({}))], 2, 0));
    let report = collect_with(&client, "t", 1);
    assert!(report.sources[3].notes.join(",").contains("page budget"));
    assert_eq!(
        report.sources[3].notes,
        ["Reached the 1-page budget; this is not a complete inventory."]
    );
}

#[test]
fn metadata_is_bounded_and_inconsistent_rates_are_withheld() {
    let client = Client::standard();
    client.customer_apps.fail(ReadError::Failed);
    client.applications.set(json!({"items": [
        {"id": "a", "name": format!("\u{1b}{}", "A".repeat(400)), "sessions_total": 1, "sessions_violated": 2},
        {"id": "b", "sessions_total": -1, "sessions_violated": 0.5},
        {"id": "c", "sessions_total": 9_007_199_254_740_992_u64}
    ]}));
    let report = collect_with(&client, "\u{0} ", 40);
    assert_eq!(report.title, "Unknown");
    assert_eq!(report.violation_rate, None);
    assert_eq!(report.sessions_total, None);
    let first = &report.applications[0];
    assert_eq!(first.name.encode_utf16().count(), 240);
    assert_eq!(first.registered, None);
    client.applications.set(json!({"items": [
        {"id": "a", "sessions_total": 9_007_199_254_740_991_u64, "sessions_violated": 0},
        {"id": "b", "sessions_total": 1, "sessions_violated": 0}
    ]}));
    assert_eq!(collect(&client).sessions_total, None);
}

#[test]
fn application_total_changes_and_incomplete_pages() {
    let client = Client::standard();
    client.applications.set_seq(vec![
        Ok(json!({"items": [{"id": "a", "name": "A", "sessions_total": 2, "sessions_violated": 1}], "pagination": {"total_items": 2}})),
        Ok(json!({"items": [{"id": "b"}], "pagination": {"total_items": 3}})),
    ]);
    let report = collect(&client);
    assert_eq!(report.sources[0].status, Status::Partial);
    assert_eq!(report.sessions_total, Some(2));
    client
        .applications
        .set(json!({"items": [], "pagination": {"total_items": 5}}));
    assert_eq!(collect(&client).sources[0].status, Status::Unavailable);
    client
        .applications
        .set(json!({"items": [{"id": "a"}], "pagination": {"total_items": 0}}));
    assert_eq!(collect(&client).sources[0].status, Status::Unavailable);
}

#[test]
fn probes_next_offsets_duplicates_and_non_advancing_inventories() {
    let client = Client::standard();
    let hundred: Vec<Value> = (0..100)
        .map(|i| json!({"id": i.to_string(), "sessions_total": 1, "sessions_violated": 0}))
        .collect();
    client.applications.set_seq(vec![
        Ok(json!({"items": hundred})),
        Ok(json!({"items": []})),
    ]);
    let profiles: Vec<Value> = (0..100)
        .map(|i| profile(json!({"profile_name": i.to_string()})))
        .collect();
    client.profiles.set_seq(vec![
        Ok(json!({"ai_profiles": profiles})),
        Ok(json!({"ai_profiles": []})),
    ]);
    let report = collect(&client);
    assert_eq!(report.sources[0].status, Status::Complete);
    assert_eq!(client.profiles.calls(), [0, 100]);
    client.applications.set(json!({"items": [
        {"id": "a", "sessions_total": 1}, {"id": "a", "sessions_total": 1}
    ]}));
    client
        .profiles
        .set(json!({"ai_profiles": [profile(json!({}))], "next_offset": 7}));
    client.customer_apps.set_seq(vec![
        Ok(json!({"customer_apps": [], "next_offset": 5})),
        Ok(json!({"customer_apps": []})),
    ]);
    let report = collect(&client);
    assert_eq!(report.sources[0].status, Status::Partial);
    assert!(
        report.sources[1]
            .notes
            .join(",")
            .contains("Pagination did not advance")
    );
    assert_eq!(report.sources[2].status, Status::Partial);
}

#[test]
fn explicit_policy_settings_and_latest_revisions_only() {
    let client = Client::standard();
    client.profiles.set(json!({"ai_profiles": [
        profile(json!({"revision": 1, "active": false})),
        profile(json!({})),
        profile(json!({"profile_name": "Inactive", "active": false})),
        profile(json!({
            "profile_name": "Review",
            "last_modified_ts": "2026-09-07T01:00:00Z",
            "policy": {"ai-security-profiles": [{"model-configuration": {
                "latency": {"inline-timeout-action": "allow"},
                "mask-data-in-storage": false
            }}]}
        })),
        {"profile_name": "Missing", "policy": {"ai-security-profiles": [{}]}, "last_modified_ts": "bad"}
    ]}));
    let report = collect(&client);
    let found = titles(&report);
    for title in [
        "Inactive profile: Inactive",
        "Timeout allows traffic: Review",
        "Storage masking disabled: Review",
    ] {
        assert!(found.contains(&title.to_owned()), "{title}");
    }
    assert!(
        !found
            .iter()
            .any(|t| t.contains("Production guardrail") || t.contains("Missing"))
    );
    let missing = report
        .profiles
        .iter()
        .find(|p| p.name == "Missing")
        .unwrap();
    assert_eq!(missing.active, None);
    assert_eq!(missing.revision, None);
    assert_eq!(missing.modified, None);
    assert_eq!(missing.storage_masking, "Unknown");
    let review = report.profiles.iter().find(|p| p.name == "Review").unwrap();
    assert_eq!(review.modified.as_deref(), Some("2026-09-07T01:00:00.000Z"));
}

#[test]
fn sessions_are_filtered_to_the_half_open_window() {
    let client = Client::standard();
    let rows: Vec<Value> = [
        Some("2026-09-06T12:00:00Z"),
        Some("2026-09-07T12:00:00Z"),
        None,
        Some("bad"),
        Some("2026-09-06T11:59:59Z"),
        Some("2026-09-07T11:00:00Z"),
    ]
    .iter()
    .enumerate()
    .map(|(i, time)| {
        session(json!({
            "session_id": i.to_string(),
            "last_session_activity": time.map_or(Value::Null, |t| json!(t)),
            "violation_status": if i == 0 { "FAILED" } else { "new-state" },
        }))
    })
    .collect();
    let count = rows.len() as u64;
    client.sessions.set(page(rows, count, 0));
    let report = collect(&client);
    assert_eq!(report.sessions.entries, Some(2));
    assert_eq!(report.sessions.missing_timestamps, 2);
    assert_eq!(report.sessions.outside_window, 2);
    assert!(titles(&report).contains(&"Session processing failures observed".to_owned()));
}

#[test]
fn rankings_and_severity_counts_are_kept() {
    let client = Client::standard();
    client.top.set(json!({"applications": [{
        "id": "private", "name": "Priority", "total_violations": 12,
        "policy_violations": [{"detection_type": "new-detector", "total": 12}]
    }]}));
    let mut breakdown = no_violations();
    breakdown["high"] = json!(4);
    breakdown["total"] = json!(12);
    client.trend.set(json!({"violations": [{"bucket_number": 0, "date": "nanosecond timestamp", "violation_breakdown": breakdown}]}));
    let report = collect(&client);
    assert_eq!(report.top_applications[0].name, "Priority");
    assert_eq!(report.top_applications[0].violations, Some(12));
    assert_eq!(report.violation_trend[0].violations.high, Some(4));
    assert!(titles(&report).contains(&"High or critical detector violations observed".to_owned()));
}

#[test]
fn labels_trim_strip_and_cut() {
    assert_eq!(label_text(" \u{200b}a\u{7}b "), "a b");
    assert_eq!(label_text("\u{0} "), "Unknown");
    let long = format!("{}😀", "x".repeat(239));
    assert_eq!(label_text(&long), format!("{}\u{fffd}", "x".repeat(239)));
}

// ---------------------------------------------------------------------------
// render.spec.ts (runtime cases; the Markdown cases are not ported, D155)
// ---------------------------------------------------------------------------

#[test]
fn a_complete_document_with_hash_pinned_assets() {
    let html = runtime_html::render(&collect(&Client::standard()));
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.ends_with("</html>\n"));
    assert!(html.contains("<html lang=\"en\">"));
    assert!(html.contains("No findings in available evidence"));
    assert!(html.contains("default-src &#39;none&#39;"));
    for forbidden in ["<link", "<iframe", "<img", " src="] {
        assert!(!html.to_lowercase().contains(forbidden), "{forbidden}");
    }
    assert!(html.contains("25"));
    assert!(html.contains("@media print"));
    assert!(html.contains("scope=\"col\""));
    assert!(html.contains("role=\"status\""));
}

#[test]
fn every_dynamic_surface_is_escaped() {
    let attack = "</script><script>globalThis.PWNED=1</script><img src=x onerror=alert(1)> \" & [click](https://evil.test) | \n";
    let mut report = collect(&Client::standard());
    report.title = attack.to_owned();
    report.applications[0].name = attack.to_owned();
    report.profiles[0].name = attack.to_owned();
    report.registered_apps[0].name = attack.to_owned();
    report.findings.push(Finding {
        priority: Priority::Review,
        title: attack.to_owned(),
        evidence: attack.to_owned(),
        recommendation: attack.to_owned(),
        source: attack.to_owned(),
    });
    report.sources[0].notes.push(attack.to_owned());
    report.limitations.push(attack.to_owned());
    report.top_applications.push(TopApplication {
        name: attack.to_owned(),
        violations: Some(40),
        detectors: vec![(attack.to_owned(), Some(40))],
    });
    report.violation_trend.push(TrendBucket {
        time: attack.to_owned(),
        violations: Severity::default(),
    });
    report.chart_buckets.push(ChartBucket {
        time: attack.to_owned(),
        sessions: Some(174),
        violating_sessions: Some(34),
        violations: Severity::default(),
    });
    let html = runtime_html::render(&report);
    assert_eq!(html.matches("<script>").count(), 1);
    assert!(!html.contains("<img"));
    assert!(!html.contains("<script>globalThis"));
    assert!(html.contains("&lt;/script&gt;"));
    assert!(!html.contains("innerHTML"));
}

#[test]
fn html_evidence_for_an_attention_report() {
    let client = Client::standard();
    client.applications.set(
        json!({"items": [{"name": "Priority app", "sessions_total": 40, "sessions_violated": 10}]}),
    );
    let html = runtime_html::render(&collect(&client));
    for text in [
        "Attention required",
        "Priority app",
        "25%",
        "Violating sessions observed",
        "Next step:",
        "Current security profiles",
        "Evidence and collection coverage",
        "not a configuration-change audit",
        "Report schema 2",
    ] {
        assert!(html.contains(text), "{text}");
    }
}

#[test]
fn unknown_and_empty_sources_fabricate_no_zero() {
    let client = Client::standard();
    client.applications.set(json!({}));
    client.profiles.set(json!({"ai_profiles": []}));
    client.customer_apps.set(json!({}));
    client.sessions.set(json!({}));
    let html = runtime_html::render(&collect(&client));
    for text in ["Unknown", "No rows available", "unavailable"] {
        assert!(html.contains(text), "{text}");
    }
}

#[test]
fn null_policy_fields_and_inconsistent_rates() {
    let client = Client::standard();
    client.profiles.set(
        json!({"ai_profiles": [{"profile_name": "Unknown"}, {"profile_name": "Inactive", "active": false}]}),
    );
    client.customer_apps.set(json!({"customer_apps": [
        {"customer_appId": "a", "app_name": "A", "cloud_provider": "aws", "environment": "dev"}
    ]}));
    client.applications.set(
        json!({"items": [{"id": "b", "name": "B", "sessions_total": 1, "sessions_violated": 2}]}),
    );
    let mut report = collect(&client);
    let html = runtime_html::render(&report);
    assert!(html.contains("Not in returned inventory"));
    assert!(!html.contains("200%"));
    report.sources.clear();
    assert!(runtime_html::render(&report).contains("Source: unavailable"));
}

/// TS 7.3.0 `protectionConfigurations` (§13.17): one row per active block, the sections
/// that hold something, the shared settings left out.
#[test]
fn protection_configurations_name_every_active_block() {
    let mut directional = airs_test_harness::fixtures::runtime::directional_profile();
    directional["policy"]["ai-security-profiles"][0]["content-type-configurations"]["tool-response"] =
        json!({"x-future": true, "model-protection": []});
    let rows = protection_configurations(ordered(&directional).get("policy"));
    assert_eq!(
        rows,
        [
            "AI[0] default / prompt: model-protection, app-protection, data-protection",
            "AI[0] default / response: model-protection, app-protection, data-protection",
            "AI[0] default / tool-call: model-protection, app-protection, data-protection",
            "AI[0] default / tool-response: No modeled protection sections returned",
        ]
    );
    let legacy = json!({"policy": {"ai-security-profiles": [
        {"model-type": "default", "model-configuration": {"agent-protection": [{"name": "a"}], "latency": {}}},
        {"model-configuration": {"mask-data-in-storage": true}},
        "not an object"
    ]}});
    assert_eq!(
        protection_configurations(ordered(&legacy).get("policy")),
        [
            "AI[0] default / legacy: agent-protection",
            "AI[1] Unknown / legacy: No modeled protection sections returned",
        ]
    );
    assert!(protection_configurations(None).is_empty());
}
