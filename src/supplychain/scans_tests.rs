//! Unit tests of G71's tolerant scan read (DESIGN §20.5): byte-identical projections for
//! every answer the SDK's schema accepts, `null` read as `null`, the refusals, and nothing
//! sensitive kept.

use super::*;
use crate::json::{OValue, to_compact};
use crate::supplychain::{member, views};
use airs_test_harness::fixtures::supplychain::{self as fx, Wire, obj, w};
use scm::airs::agentguard::models::{AgentGuardScan, AgentGuardScanList, Nullable};
use scm::validation::Mode;
use serde_json::json;

/// The typed-model projection (scm-sdk 0.2.2 `AgentGuardScan`), the reference the tolerant read must
/// reproduce for every scan the SDK accepts).
fn typed_projection(scan: &AgentGuardScan) -> OValue {
    let text = |value: &str| OValue::String(value.to_owned());
    let nullable = |value: &Nullable<String>| match value {
        Nullable::Null => OValue::Null,
        Nullable::Value(value) => text(value),
    };
    let number = |value: &FiniteNumber| OValue::Number(value.as_number().clone());
    let (vulnerabilities, chains) = match &scan.summary {
        Nullable::Null => (OValue::Null, OValue::Null),
        Nullable::Value(summary) => (
            number(&summary.vulnerability_count),
            number(&summary.attack_chain_count),
        ),
    };
    OValue::Object(vec![
        member("uuid", text(&scan.uuid)),
        member("artifact_type", text(&scan.artifact_type)),
        member("status", text(&scan.status)),
        member("eval_outcome", nullable(&scan.eval_outcome)),
        member("created_at", text(&scan.created_at)),
        member("vulnerability_count", vulnerabilities),
        member("attack_chain_count", chains),
        member("is_batch", OValue::Bool(scan.is_batch)),
        member("parent_uuid", nullable(&scan.parent_uuid)),
    ])
}

fn body(rows: &[Wire], total: u64) -> Value {
    serde_json::from_str(&fx::scan_list_body(rows, total)).unwrap()
}

fn compact(scans: &[Scan]) -> Vec<String> {
    scans
        .iter()
        .map(|scan| to_compact(&views::scan(scan)).unwrap())
        .collect()
}

/// Every answer the SDK's response schema accepts (the seeded scans, the report's recent
/// ones, and numbers written as `2.0`, `1e0` and large safe integers) projects to the bytes
/// the typed model gave; the total is the SDK's.
#[test]
fn accepted_answers_project_as_the_typed_model_did() {
    let mut numbers = fx::scans();
    numbers.truncate(3);
    numbers[0].set(
        "summary",
        obj(vec![
            ("vulnerability_count", Wire::Leaf(json!(2.0))),
            (
                "attack_chain_count",
                Wire::Leaf(json!(9_007_199_254_740_991_u64)),
            ),
        ]),
    );
    let exponent: Value = serde_json::from_str("1e0").unwrap();
    numbers[1].set(
        "summary",
        obj(vec![
            ("vulnerability_count", Wire::Leaf(exponent)),
            ("attack_chain_count", w(json!(0))),
        ]),
    );
    numbers[2].set("artifact_type", w(json!("ü 日本\u{1b}[31m\u{85}")));
    for (rows, total) in [
        (fx::scans(), fx::SCAN_COUNT),
        (fx::recent_scans(), fx::SCAN_COUNT),
        (numbers, 3),
        (Vec::new(), 0),
    ] {
        let answer = body(&rows, total);
        let typed = AgentGuardScanList::parse(answer.clone(), Mode::ResponseWithoutDefaults)
            .expect("the SDK accepts the fixture");
        let page = project(&answer).unwrap();
        assert_eq!(Some(page.total), typed.pagination.total_items.as_u64());
        let expected: Vec<String> = typed
            .scans
            .iter()
            .map(|scan| to_compact(&typed_projection(scan)).unwrap())
            .collect();
        assert_eq!(compact(&page.scans), expected);
    }
}

/// G71: the observed `"fingerprint": null` and every other `null` the read accepts; the
/// SDK refuses the same page; an absent member reads as `null` too.
#[test]
fn nulls_read_as_null() {
    let answer = body(&fx::null_scans(), 3);
    assert!(AgentGuardScanList::parse(answer.clone(), Mode::ResponseWithoutDefaults).is_err());
    let page = project(&answer).unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(
        compact(&page.scans),
        [
            r#"{"uuid":"11111111-1111-4111-8111-000000000113","artifact_type":"SKILL","status":"COMPLETED","eval_outcome":"BLOCKED","created_at":"2026-10-19T03:04:05.006Z","vulnerability_count":1,"attack_chain_count":1,"is_batch":false,"parent_uuid":null}"#,
            r#"{"uuid":"11111111-1111-4111-8111-000000000114","artifact_type":null,"status":null,"eval_outcome":null,"created_at":null,"vulnerability_count":null,"attack_chain_count":null,"is_batch":null,"parent_uuid":null}"#,
            r#"{"uuid":"11111111-1111-4111-8111-000000000115","artifact_type":"AGENT","status":"COMPLETED","eval_outcome":"ALLOWED","created_at":"2026-10-19T03:04:05.006Z","vulnerability_count":null,"attack_chain_count":3,"is_batch":false,"parent_uuid":null}"#,
        ]
    );
    assert_eq!(page.scans[1].children, None);
    assert_eq!(page.scans[0].children, Some(0));
    let bare = scan(&json!({"uuid": "u"})).unwrap();
    assert_eq!(
        to_compact(&views::scan(&bare)).unwrap(),
        r#"{"uuid":"u","artifact_type":null,"status":null,"eval_outcome":null,"created_at":null,"vulnerability_count":null,"attack_chain_count":null,"is_batch":null,"parent_uuid":null}"#
    );
}

/// Nothing the CLI never prints is kept: the read holds only its nine members, so no
/// name, URL, fingerprint, device metadata, error text or passthrough value can reach an
/// output (§20.11).
#[test]
fn nothing_sensitive_is_kept() {
    for rows in [fx::scans(), fx::null_scans()] {
        let page = project(&body(&rows, 1)).unwrap();
        let kept = format!("{page:?}");
        assert!(!kept.contains(fx::MARKER), "{kept}");
    }
}

/// The contract the read keeps: a page, its pagination and total, a scans array, an object
/// per scan with a string `uuid`, and the documented type (or `null`) for every member it
/// reads. Members it does not read are not checked.
#[test]
fn refusals() {
    let good = fx::scans()[0].clone();
    let with = |key: &str, value: Value| {
        let mut row = good.clone();
        row.set(key, Wire::Leaf(value));
        body(&[row], 1)
    };
    for (answer, refused) in [
        (json!([]), Refused::Page),
        (json!({"scans": []}), Refused::Page),
        (json!({"pagination": null, "scans": []}), Refused::Page),
        (
            json!({"pagination": {"total_items": null}, "scans": []}),
            Refused::Page,
        ),
        (
            json!({"pagination": {"total_items": -1}, "scans": []}),
            Refused::Page,
        ),
        (
            json!({"pagination": {"total_items": 1.5}, "scans": []}),
            Refused::Page,
        ),
        (
            json!({"pagination": {"total_items": 9_007_199_254_740_992_u64}, "scans": []}),
            Refused::Page,
        ),
        (
            json!({"pagination": {"total_items": 1}, "scans": null}),
            Refused::Page,
        ),
        (
            json!({"pagination": {"total_items": 1}, "scans": [null]}),
            Refused::Identity,
        ),
        (with("uuid", Value::Null), Refused::Identity),
        (with("uuid", json!(101)), Refused::Identity),
        (with("status", json!(1)), Refused::Member),
        (with("created_at", json!({})), Refused::Member),
        (with("is_batch", json!("false")), Refused::Member),
        (with("child_scan_uuids", json!({})), Refused::Member),
        (with("summary", json!([])), Refused::Member),
        (
            with(
                "summary",
                json!({"vulnerability_count": "2", "attack_chain_count": 0}),
            ),
            Refused::Member,
        ),
        (
            with(
                "summary",
                json!({"vulnerability_count": -1, "attack_chain_count": 0}),
            ),
            Refused::Member,
        ),
    ] {
        assert_eq!(project(&answer), Err(refused), "{answer}");
    }
    let mut no_uuid = good.clone();
    no_uuid.remove("uuid");
    assert_eq!(project(&body(&[no_uuid], 1)), Err(Refused::Identity));
    // Unread members are not validated (G71: a type drift there refuses nothing), and an
    // empty `uuid` is the walk's page check (§20.4), not a refusal.
    for (key, value) in [
        ("fingerprint", json!(7)),
        ("name", json!(["x"])),
        ("device_metadata", json!("x")),
        ("uuid", json!("")),
    ] {
        assert!(project(&with(key, value)).is_ok(), "{key}");
    }
}

/// G66 on the raw read (§20.16): [`within_bounds`] draws the typed call's line. The SDK's
/// scan-list schema at the supplychain bounds accepts a page whose deepest value sits at
/// depth 64 and refuses one at 65 as a `Limit`, and so does the raw read's check; the
/// seeded pages (ordinary data) pass. The value and byte bounds are the preflight's too.
#[test]
fn the_validation_bounds_are_the_typed_calls() {
    let limits = crate::clients::supplychain_validation_limits().unwrap();
    for (depth, accepted) in [(64, true), (65, false), (100, false)] {
        let answer = body(&fx::deep_scans(depth), fx::SCAN_COUNT);
        assert_eq!(fx::json_depth(&answer), depth);
        let typed = scm::validation::parse_with_limits(
            "AgentGuardScanListSchema",
            answer.clone(),
            Mode::ResponseWithoutDefaults,
            &limits,
        );
        match &typed {
            Ok(_) => assert!(accepted, "{depth}"),
            Err(error) => {
                assert!(!accepted, "{depth}: {error:?}");
                assert_eq!(error.kind(), scm::ErrorKind::Limit);
            }
        }
        assert_eq!(within_bounds(&answer, &limits), accepted, "{depth}");
    }
    for rows in [
        fx::scans(),
        fx::recent_scans(),
        fx::null_scans(),
        Vec::new(),
    ] {
        assert!(within_bounds(&body(&rows, 1), &limits));
    }
    let answer = json!({"pagination": {"total_items": 1}, "scans": [{"uuid": "abc"}]});
    let mut small = limits.clone();
    // The page, its pagination, the total, the array, the scan and its uuid.
    small.max_nodes = 6;
    assert!(within_bounds(&answer, &small));
    small.max_nodes = 5;
    assert!(!within_bounds(&answer, &small));
    let mut small = limits.clone();
    // "pagination" + "total_items" + "scans" + "uuid" + "abc"
    small.max_input_bytes = 10 + 11 + 5 + 4 + 3;
    assert!(within_bounds(&answer, &small));
    small.max_input_bytes -= 1;
    assert!(!within_bounds(&answer, &small));
}
