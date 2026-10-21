//! Runtime extras wire bodies (DESIGN §10 M6d): API keys, customer apps, deployment
//! profiles and the dashboard and sessions answers. Every record validates against the
//! TypeScript SDK's zod schemas and the Rust SDK models
//! (`scm::airs::management::models`); keys are in schema order, so both SDKs re-serialise
//! them in the same order.
//!
//! Ids are `22222222-2222-4222-8222-<12 digits>` ([`uuid`]): API keys 1–99, customer apps
//! 101–199.
//!
//! Sensitive markers: `FAKE-APIKEY-SECRET-<tsg>-<n>` (a key value; never printed by
//! airs-cli-rs, D204/D205), `FAKE-AUTHCODE-<n>` (stdout only), and
//! `FAKE-PROMPT-CONTENT-<tsg>` / `FAKE-RESPONSE-CONTENT-<tsg>` (scan content: only on
//! `scan-content --show-content`'s stdout or in its `--output-file`).

use serde_json::{Value, json};

/// The TSG of the standard tenant.
pub const TSG: &str = "100";
/// The timestamp of every fixture record.
pub const AT: &str = "2026-01-01T00:00:00Z";

/// `22222222-2222-4222-8222-<n:012>`.
pub fn uuid(n: u64) -> String {
    format!("22222222-2222-4222-8222-{n:012}")
}

/// `FAKE-APIKEY-SECRET-<tsg>-<n>`: an API key value.
pub fn key_secret(tsg: &str, n: &str) -> String {
    format!("FAKE-APIKEY-SECRET-{tsg}-{n}")
}

/// The prefix of every API key marker (the runner's leak check).
pub const KEY_MARKER: &str = "FAKE-APIKEY-SECRET-";

/// `FAKE-AUTHCODE-<n>`.
pub fn auth_code(n: u64) -> String {
    format!("FAKE-AUTHCODE-{n}")
}

/// The prefix of every auth code marker.
pub const AUTHCODE_MARKER: &str = "FAKE-AUTHCODE-";

/// The stored prompt of a scan content answer.
pub fn prompt_content(tsg: &str) -> String {
    format!("FAKE-PROMPT-CONTENT-{tsg}")
}

/// The stored response of a scan content answer.
pub fn response_content(tsg: &str) -> String {
    format!("FAKE-RESPONSE-CONTENT-{tsg}")
}

/// The prefixes of the scan-content markers.
pub const CONTENT_MARKERS: [&str; 2] = ["FAKE-PROMPT-CONTENT-", "FAKE-RESPONSE-CONTENT-"];

/// The key markers the datasets can use for `tsg` (the runner checks these forms).
pub fn key_markers(tsg: &str) -> Vec<String> {
    let mut markers = vec![key_secret(tsg, "list"), key_secret(tsg, "nested")];
    markers.extend((1..=20).map(|n| key_secret(tsg, &n.to_string())));
    markers
}

/// API key `n` (schema-valid: `api_key_id`, `api_key_last8`, `auth_code`, `expiration`,
/// `revoked` required) without TS's `created_at`/`expires_at`.
pub fn api_key(n: u64) -> Value {
    json!({
        "api_key_id": uuid(n),
        "api_key_last8": format!("LAST8-{n:02}"),
        "api_key_name": format!("key-{n}"),
        "auth_code": auth_code(n),
        "tsg_id": TSG,
        "expiration": format!("2027-{n:02}-01T00:00:00Z"),
        "revoked": false,
        "cust_app": "app-1",
        "created_by": "admin@example.com",
        "creation_ts": AT,
    })
}

/// [`api_key`] with the keys TypeScript reads (`created_at`, `expires_at`), so both CLIs
/// project the same dates (the parity datasets; D207 uses [`api_key`]).
pub fn api_key_ts(n: u64) -> Value {
    let mut key = api_key(n);
    key["created_at"] = json!(AT);
    key["expires_at"] = key["expiration"].clone();
    key
}

/// The three standard API keys.
pub fn api_keys() -> Vec<Value> {
    (1..=3).map(api_key).collect()
}

/// Customer app `n` (101–199), as a list row (`CustomerAppWithKeys`).
pub fn customer_app(n: u64) -> Value {
    json!({
        "customer_appId": uuid(n),
        "tsg_id": TSG,
        "app_name": format!("app-{}", n - 100),
        "model_name": "gpt",
        "cloud_provider": "aws",
        "environment": "prod",
        "ai_agent_framework": "none",
        "api_keys_dp_info": [
            {"api_key_name": format!("key-{}", n - 100), "dp_name": "dp-1", "auth_code": auth_code(n - 100)}
        ],
    })
}

/// [`customer_app`] with the `customer_app_id` key TypeScript reads (the parity datasets).
pub fn customer_app_ts(n: u64) -> Value {
    let mut app = customer_app(n);
    app["customer_app_id"] = json!(uuid(n));
    app
}

/// The three standard customer apps.
pub fn customer_apps() -> Vec<Value> {
    (101..=103).map(customer_app).collect()
}

/// Deployment profile `n` (`dp_name` and `auth_code` required).
pub fn deployment_profile(n: u64, status: &str) -> Value {
    json!({
        "dp_name": format!("dp-{n}"),
        "auth_code": auth_code(n),
        "tsg_id": TSG,
        "status": status,
        "expiration_date": "2027-01-01",
    })
}

/// A dashboard overview item.
pub fn overview_item(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "cloud": "other",
        "source": "api",
        "sessions": [{"bucket_number": 0, "date": AT, "total": 40, "violated": 10}],
        "sessions_total": 40,
        "sessions_violated": 10,
    })
}

/// The standard dashboard buckets (TS `management.spec.ts:1229-1236`): one id under two
/// names, and a third app.
pub fn overview_items() -> Vec<Value> {
    vec![
        overview_item("uuid-shared", "chatbot"),
        overview_item("uuid-shared", "LiteLLM"),
        overview_item("uuid-litellm", "litellm"),
    ]
}

/// The `apps/application` answer of a bucket with every value sent.
pub fn application(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "cloud": "other",
        "source": "api",
        "created_at": "2026-04-29T17:04:52Z",
        "profiles": ["ms-tuned", "golden-v2"],
        "token_stats": {
            "average_daily_tokens": 744.233,
            "average_daily_tokens_scale": "K",
            "monthly_total_tokens": 17.71,
            "monthly_total_tokens_scale": "M"
        },
        "session_stats": {"total": 56935, "violating": 31136},
    })
}

/// The `applicationviolationbreakdown` answer with two firing detectors and a silent one.
pub fn breakdown() -> Value {
    json!({
        "detection_type_violation_breakdown": [
            {"detection_type": "topic_guardrails", "violation_breakdown": {"critical": 0, "high": 0, "medium": 3, "low": 0, "total": 3}},
            {"detection_type": "pi", "violation_breakdown": {"critical": 1, "high": 2, "medium": 0, "low": 0, "total": 3}},
            {"detection_type": "dlp", "violation_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}}
        ],
        "total_violating": 6,
    })
}

fn counts(total: u64) -> Value {
    json!({"critical": 0, "high": total, "medium": 0, "low": 0, "total": total})
}

/// `topapplicationsviolations`.
pub fn top_applications() -> Value {
    json!({"applications": [
        {"id": "uuid-shared", "name": "chatbot", "policy_violations": [{"detection_type": "pi", "total": 3}], "total_violations": 3}
    ]})
}

/// `applicationsviolationstrend`.
pub fn violations_trend() -> Value {
    json!({"violations": [{"bucket_number": 0, "date": AT, "violation_breakdown": counts(2)}]})
}

/// `appslist`.
pub fn apps_list() -> Value {
    json!({"applications": [
        {"application_id": "uuid-shared", "application_name": "chatbot"},
        {"application_id": "uuid-litellm", "application_name": "litellm"}
    ]})
}

/// `sessionschart`.
pub fn sessions_chart() -> Value {
    json!({
        "bucket_size_seconds": 3600,
        "buckets": [{"bucket_number": 0, "time": AT, "total": 5, "violating": 1, "detection_type_violation_breakdown": [], "violation_breakdown": counts(1)}],
    })
}

/// A `sessionsoverview` item.
pub fn session_item(app_id: &str, app_name: &str, session: &str) -> Value {
    json!({
        "application_id": app_id,
        "application_name": app_name,
        "session_id": session,
        "last_session_activity": AT,
        "violation_status": "passed",
        "violation_breakdown": counts(0),
        "detection_type_violation_breakdown": [],
    })
}

/// The three standard sessions.
pub fn sessions() -> Vec<Value> {
    vec![
        session_item("uuid-shared", "A & B", "pan_session"),
        session_item("uuid-shared", "A & B", "second"),
        session_item("uuid-litellm", "litellm", "third"),
    ]
}

fn action(session: &str) -> Value {
    json!({
        "application_id": "uuid-shared",
        "application_name": "A & B",
        "session_id": session,
        "scan_id": "scan-1",
        "scan_sub_req_id": 0,
        "status": "passed",
        "detection_type_violation_breakdown": [],
        "violation_breakdown": counts(0),
    })
}

/// `sessions/session` for `session`.
pub fn session(session: &str) -> Value {
    json!({
        "application": {"id": "uuid-shared", "name": "A & B"},
        "id": session,
        "session_actions": [action(session)],
        "pagination": {"limit": 25, "skip": 0, "total_items": 1},
        "violation_status": "passed",
    })
}

/// `sessions/sessiontransaction` (with the `attributes` TS prints, choice 15).
pub fn transaction(session: &str, scan: &str, sub_request: u64) -> Value {
    json!({
        "application_id": "uuid-shared",
        "application_name": "A & B",
        "session_id": session,
        "scan_id": scan,
        "scan_sub_req_id": sub_request,
        "status": "passed",
        "detection_type_violation_breakdown": [],
        "violation_breakdown": counts(0),
        "attributes": {"environment": "prod", "model_name": "gpt", "profile": "default", "user_id": "user-1", "user_ip": "192.0.2.1"},
    })
}

/// `reports/scancontent` for `scan` (the stored prompt and response markers).
pub fn scan_content(tsg: &str, scan: &str, sub_request: u64) -> Value {
    json!({
        "report_id": "report-1",
        "scan_id": scan,
        "sub_scan_req_id": sub_request,
        "transaction_id": "tx-1",
        "scan_contents": {"prompt": prompt_content(tsg), "response": response_content(tsg)},
    })
}
