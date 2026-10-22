//! Canned wire bodies that validate against both the TS SDK (zod) schemas and the Rust
//! SDK models (see `docs/research/ts-runtime-scan.md` §11 and `ts-runtime-mgmt-read.md`
//! §10). Optional fields are omitted, never `null`.

use serde_json::{Value, json};

/// A deterministic v4-shaped UUID: `00000000-0000-4000-8000-<n, 12 digits>`.
pub fn uuid(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

/// The scan id of the `n`th receipt (1-based) the async route issues.
pub fn async_scan_id(n: u64) -> String {
    uuid(7000 + n)
}

/// The report id of the `n`th receipt.
pub fn async_report_id(n: u64) -> String {
    format!("R{}", async_scan_id(n))
}

/// A security profile row (`ai_profiles[]` item).
pub fn profile(n: u64, name: &str, revision: u64) -> Value {
    json!({
        "profile_id": uuid(n),
        "profile_name": name,
        "revision": revision,
        "active": true,
        "created_by": "creator@example.com",
        "updated_by": "updater@example.com",
        "last_modified_ts": "2026-02-01T00:00:00Z",
        "policy": {
            "ai-security-profiles": [{
                "model-type": "default",
                "model-configuration": {"mask-data-in-storage": false}
            }],
            "dlp-data-profiles": []
        }
    })
}

/// A custom topic row (`custom_topics[]` item).
pub fn topic(n: u64, name: &str, revision: u64, description: &str) -> Value {
    json!({
        "topic_id": uuid(n),
        "topic_name": name,
        "revision": revision,
        "active": true,
        "description": description,
        "examples": [format!("{name} example")],
        "created_by": "creator@example.com",
        "last_modified_ts": "2026-02-01T00:00:00Z",
        "created_ts": "2026-01-01T00:00:00Z"
    })
}

/// The default sync-scan verdict: allow / benign, no detections.
pub fn scan_allow(profile_name: &str) -> Value {
    json!({
        "report_id": "R00000000-0000-4000-8000-0000000000a1",
        "scan_id": "00000000-0000-4000-8000-0000000000a1",
        "profile_id": "11111111-1111-4111-8111-111111111111",
        "profile_name": profile_name,
        "category": "benign",
        "action": "allow",
        "timeout": false,
        "error": false,
        "errors": [],
        "prompt_detected": {
            "url_cats": false, "dlp": false, "injection": false, "toxic_content": false,
            "malicious_code": false, "source_code": false, "agent": false,
            "topic_violation": false
        },
        "created_at": "2026-10-16T00:00:00Z",
        "completed_at": "2026-10-16T00:00:01Z"
    })
}

/// A block / malicious verdict with prompt detections `injection` and `toxic_content`
/// and a `response_detected.dlp` (ignored by TS, listed by airs-cli-rs).
pub fn scan_block(profile_name: &str) -> Value {
    json!({
        "report_id": "R00000000-0000-4000-8000-0000000000b2",
        "scan_id": "00000000-0000-4000-8000-0000000000b2",
        "profile_name": profile_name,
        "category": "malicious",
        "action": "block",
        "timeout": false,
        "error": false,
        "errors": [],
        "prompt_detected": {
            "toxic_content": true, "injection": true, "dlp": false, "url_cats": false,
            "malicious_code": false, "source_code": false, "agent": false,
            "topic_violation": false
        },
        "response_detected": {"dlp": true, "url_cats": false},
        "prompt_detection_details": {"toxic_content_details": {"toxic_categories": ["violence"]}}
    })
}

/// A scan whose engine reported an error (`error: true`, one `errors[]` entry).
pub fn scan_failed() -> Value {
    json!({
        "report_id": "R00000000-0000-4000-8000-0000000000c3",
        "scan_id": "00000000-0000-4000-8000-0000000000c3",
        "category": "benign",
        "action": "allow",
        "timeout": false,
        "error": true,
        "errors": [{"content_type": "prompt", "feature": "dlp", "status": "error"}]
    })
}

/// An empty AI Gateway list (`GET /workspaces`; the unseeded gateway dataset's answer).
pub fn aigw_workspaces_empty() -> Value {
    gateway::workspaces_empty()
}

/// The red team datasets (DESIGN §10 M6a): wire bodies that validate against both SDKs.
#[path = "fixtures_redteam.rs"]
pub mod redteam;

#[path = "fixtures_dlp.rs"]
pub mod dlp;

/// The model-security datasets (DESIGN §10 M6c).
#[path = "fixtures_modelsec.rs"]
pub mod modelsec;

/// The runtime extras datasets (DESIGN §10 M6d).
#[path = "fixtures_runtime.rs"]
pub mod runtime;

/// The gateway datasets (DESIGN §10 M6e).
#[path = "fixtures_gateway.rs"]
pub mod gateway;

/// The supplychain datasets (DESIGN §10 M6f).
#[path = "fixtures_supplychain.rs"]
pub mod supplychain;
