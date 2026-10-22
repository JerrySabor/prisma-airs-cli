//! The contract guard (DESIGN §15.23, G60): every vocabulary and bound the red team
//! argument checks accept passes the pinned SDK's vendor 0.93.0 schema in request mode,
//! and the first value past each bound is refused by it. A later pin that tightens the
//! contract fails here, before an SDK validation error (which names no field) could
//! reach a user.

use super::args::{self, ScanOptions};
use super::{JOB_STATUSES, LIST_JOB_TYPES, MAX_PAGE, MAX_STREAM, SEVERITIES};
use scm::validation::{Mode, parse};
use serde_json::{Value, json};

const TARGET: &str = "00000000-0000-4000-8000-000000000201";
const JOBS: &str = "vendor:red-team-dp:0.93.0:list_jobs_v1_scan_get:query";
const ATTACKS: &str =
    "vendor:red-team-dp:0.93.0:list_attacks_v1_report_static__job_id__list_attacks_get:query";
const CUSTOM_ATTACKS: &str = "vendor:red-team-dp:0.93.0:list_custom_attacks_v1_custom_attacks_job__job_id__list_custom_attacks_get:query";
const ERROR_LOGS: &str = "vendor:red-team-dp:0.93.0:list_error_logs_for_target_profile_v1_error_log_target_profile__target_id__get:query";
const SCAN_BODY: &str = "vendor:red-team-dp:0.93.0:create_job_v1_scan_post:body";

fn accepted(schema: &str, value: Value) -> bool {
    parse(schema, value, Mode::Request).is_ok()
}

#[test]
fn list_queries_accept_exactly_the_cli_vocabularies() {
    for status in JOB_STATUSES {
        assert!(accepted(JOBS, json!({"status": status})), "{status}");
    }
    for job_type in LIST_JOB_TYPES {
        assert!(accepted(JOBS, json!({"job_type": job_type})), "{job_type}");
    }
    assert!(accepted(
        JOBS,
        json!({"skip": 0, "limit": MAX_PAGE, "status": "COMPLETED", "job_type": "STATIC", "target_id": TARGET})
    ));
    assert!(accepted(JOBS, json!({"limit": 1})));
    for refused in [
        json!({"limit": MAX_PAGE + 1}),
        json!({"status": "completed"}),
        json!({"status": "PROFILING"}),
        json!({"status": ""}),
        json!({"job_type": "static"}),
        json!({"job_type": ""}),
        json!({"target_id": "t-1"}),
        json!({"target_id": ""}),
    ] {
        assert!(!accepted(JOBS, refused.clone()), "{refused}");
    }
}

#[test]
fn attack_queries_accept_the_cli_bound_and_severities() {
    for severity in SEVERITIES {
        assert!(
            accepted(ATTACKS, json!({"limit": 20, "severity": severity})),
            "{severity}"
        );
    }
    assert!(accepted(ATTACKS, json!({"limit": MAX_PAGE})));
    for refused in [
        json!({"limit": MAX_PAGE + 1}),
        json!({"severity": ""}),
        json!({"severity": "high"}),
    ] {
        assert!(!accepted(ATTACKS, refused.clone()), "{refused}");
    }
    // The CLI bound (100) is within the custom-attack bound (1,000).
    assert!(accepted(CUSTOM_ATTACKS, json!({"limit": MAX_PAGE})));
    assert!(accepted(CUSTOM_ATTACKS, json!({"limit": 1_000})));
    assert!(!accepted(CUSTOM_ATTACKS, json!({"limit": 1_001})));
}

#[test]
fn error_log_queries_take_only_a_bounded_limit() {
    assert!(accepted(ERROR_LOGS, json!({})));
    assert!(accepted(ERROR_LOGS, json!({"limit": 1})));
    assert!(accepted(ERROR_LOGS, json!({"limit": MAX_PAGE})));
    for refused in [
        json!({"limit": MAX_PAGE + 1}),
        json!({"skip": 0}),
        json!({"search": "upstream"}),
    ] {
        assert!(!accepted(ERROR_LOGS, refused.clone()), "{refused}");
    }
}

/// The body `args::scan` and `args::scan_body` build from `options`.
fn body(options: &ScanOptions<'_>) -> Value {
    let spec = args::scan(options).unwrap();
    let categories = json!({"SECURITY": ["JAILBREAK"]});
    args::scan_body(&spec, Some(&categories), &["leak".to_owned()])
}

#[test]
fn scan_bodies_the_cli_accepts_pass_the_vendor_body() {
    let base = ScanOptions {
        target: TARGET,
        name: "abc",
        ..ScanOptions::default()
    };
    let depth = MAX_STREAM.to_string();
    let long = "x".repeat(255);
    for options in [
        base.clone(),
        ScanOptions {
            name: "\u{1F600}\u{1F600}\u{1F600}",
            ..base.clone()
        },
        ScanOptions {
            name: &long,
            ..base.clone()
        },
        ScanOptions {
            job_type: Some("DYNAMIC"),
            depth: Some(&depth),
            breadth: Some(&depth),
            ..base.clone()
        },
        ScanOptions {
            job_type: Some("DYNAMIC"),
            depth: Some("1"),
            breadth: Some("1"),
            ..base.clone()
        },
        ScanOptions {
            job_type: Some("CUSTOM"),
            prompt_sets: Some("00000000-0000-4000-8000-000000000301"),
            ..base.clone()
        },
    ] {
        let body = body(&options);
        assert!(accepted(SCAN_BODY, body.clone()), "{body}");
    }
    // The first values past the bounds the CLI refuses (D304, D305) fail the body too.
    let mut deep = body(&ScanOptions {
        job_type: Some("DYNAMIC"),
        ..base.clone()
    });
    deep["job_metadata"]["stream_depth"] = json!(MAX_STREAM + 1);
    assert!(!accepted(SCAN_BODY, deep));
    let mut wide = body(&ScanOptions {
        job_type: Some("DYNAMIC"),
        ..base.clone()
    });
    wide["job_metadata"]["stream_breadth"] = json!(MAX_STREAM + 1);
    assert!(!accepted(SCAN_BODY, wide));
    let mut short = body(&base);
    short["name"] = json!("\u{1F600}a");
    assert!(!accepted(SCAN_BODY, short));
    let mut opaque = body(&base);
    opaque["target"]["uuid"] = json!("t-1");
    assert!(!accepted(SCAN_BODY, opaque));
}

/// The management 0.86.0 target contract of scm-sdk 0.2.3 (DESIGN §15.24, D328, D329):
/// the create, update and probe bodies accept the new vocabulary and the Vertex AI and
/// `client_session` configs, a Vertex AI field outside its request pattern (a server
/// mask included) is refused, and the target answer accepts every shape the bodies do,
/// masks included, without the request patterns.
#[test]
fn management_0_86_target_contract() {
    let vertex = json!({
        "project_id": "example-project",
        "location": "us-central1",
        "engine_id": "12345",
        "customer_sa_email": "service@example.invalid"
    });
    let bodies = [
        json!({"name": "t", "connection_type": "VERTEX_AI"}),
        json!({"name": "t", "connection_type": "N8N"}),
        json!({"name": "t", "response_mode": "REALTIME"}),
        json!({"name": "t", "connection_params": {"multi_turn_config": {"type": "client_session"}}}),
        json!({"name": "t", "connection_params": {"target_connection_config": vertex.clone()}}),
        json!({"name": "t", "connection_params": {"audio_request_json": {"a": 1}, "audio_curl": "curl x"}}),
        json!({"name": "t", "auth_config": {"basic_username": "u", "basic_password": "p"}}),
    ];
    for schema in [
        "TargetCreateRequestSchema",
        "TargetUpdateRequestSchema",
        "TargetProbeRequestSchema",
    ] {
        for body in &bodies {
            assert!(accepted(schema, body.clone()), "{schema}: {body}");
        }
        for (field, value) in [
            ("project_id", "Example_Project"),
            ("project_id", "****"),
            ("location", "US Central"),
            ("engine_id", "engine-1"),
        ] {
            let mut config = vertex.clone();
            config[field] = json!(value);
            let body =
                json!({"name": "t", "connection_params": {"target_connection_config": config}});
            assert!(!accepted(schema, body.clone()), "{schema}: {body}");
        }
        // Values outside the 0.86.0 vocabularies stay refused.
        for body in [
            json!({"name": "t", "connection_type": "vertex_ai"}),
            json!({"name": "t", "response_mode": "AUDIO"}),
            json!({"name": "t", "connection_params": {"multi_turn_config": {"type": "client"}}}),
        ] {
            assert!(!accepted(schema, body.clone()), "{schema}: {body}");
        }
    }
    // The backup's placeholders (§15.24 choice 13) pass the real create parse in place of
    // all three masked identifiers, so a pattern change in a later pin fails here.
    let all_masked = crate::json::parse(
        r#"{"name":"t","connection_params":{"target_connection_config":{"project_id":"****","location":"****","engine_id":"****","customer_sa_email":"****"}}}"#,
    )
    .unwrap();
    let create = |projection: &crate::json::OValue| {
        serde_json::to_value(projection).is_ok_and(|wire| {
            scm::airs::red_team::models::TargetCreateRequest::parse(wire, Mode::Request).is_ok()
        })
    };
    let masked_ids = super::backup::masked_vertex_ids(&all_masked);
    assert_eq!(masked_ids, ["project_id", "location", "engine_id"]);
    assert!(!create(&all_masked));
    assert!(create(&super::backup::with_vertex_placeholders(
        &all_masked,
        &masked_ids
    )));
    let answer = |extra: Value| {
        let mut target = json!({
            "uuid": TARGET, "tsg_id": "100", "name": "t", "status": "ACTIVE",
            "active": true, "validated": true,
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
        });
        for (key, value) in extra.as_object().unwrap() {
            target[key] = value.clone();
        }
        target
    };
    let masked = json!({"project_id": "****", "location": "****", "engine_id": "****", "customer_sa_email": "****"});
    for extra in bodies
        .iter()
        .map(|body| {
            let mut body = body.clone();
            body.as_object_mut().unwrap().remove("name");
            body
        })
        .chain([json!({"connection_params": {"target_connection_config": masked}})])
    {
        let target = answer(extra.clone());
        let read = parse(
            "TargetResponseSchema",
            target.clone(),
            Mode::ResponseWithoutDefaults,
        );
        assert_eq!(read.ok(), Some(target), "{extra}");
    }
}
