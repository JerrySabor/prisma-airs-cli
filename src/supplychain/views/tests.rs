//! Unit tests of the supplychain projections and layouts (DESIGN §20.3, §20.5–§20.8).

use super::*;
use crate::json::{parse, to_compact};

fn scan_model(summary: serde_json::Value, outcome: serde_json::Value) -> scans::Scan {
    scans::scan(&serde_json::json!({
        "uuid": "11111111-1111-4111-8111-000000000101",
        "tsg_id": "100",
        "created_at": "2026-10-19T01:57:59.751Z",
        "updated_at": "2026-10-19T01:57:59.751Z",
        "name": "PRIVATE-NAME",
        "git_url": "https://PRIVATE-USER:PRIVATE-TOKEN@git.example.invalid/r.git?PRIVATE-Q=1",
        "artifact_type": "SKILL",
        "status": "COMPLETED",
        "error_message": null,
        "summary": summary,
        "eval_outcome": outcome,
        "eval_summary": null,
        "eval_details": null,
        "duration_seconds": 1,
        "fingerprint": "PRIVATE-FINGERPRINT",
        "scanner_version": null,
        "device_metadata": {"token": "PRIVATE-TOKEN"},
        "parent_uuid": null,
        "is_batch": false,
        "child_scan_uuids": [],
        "batch_summary": null,
        "zz_added": "PRIVATE-PASSTHROUGH"
    }))
    .unwrap()
}

/// §20.5: exactly the nine keys in TS order; `null` counts when `summary` is `null`; nothing
/// else of the scan.
#[test]
fn the_scan_projection() {
    let projected = scan(&scan_model(
        serde_json::json!({"vulnerability_count": 2, "attack_chain_count": 0}),
        serde_json::json!("BLOCKED"),
    ));
    assert_eq!(
        to_compact(&projected).unwrap(),
        r#"{"uuid":"11111111-1111-4111-8111-000000000101","artifact_type":"SKILL","status":"COMPLETED","eval_outcome":"BLOCKED","created_at":"2026-10-19T01:57:59.751Z","vulnerability_count":2,"attack_chain_count":0,"is_batch":false,"parent_uuid":null}"#
    );
    let pending = scan(&scan_model(
        serde_json::Value::Null,
        serde_json::Value::Null,
    ));
    assert_eq!(pending.get("vulnerability_count"), Some(&OValue::Null));
    assert_eq!(pending.get("attack_chain_count"), Some(&OValue::Null));
    assert_eq!(pending.get("eval_outcome"), Some(&OValue::Null));
    assert!(!to_compact(&pending).unwrap().contains("PRIVATE"));
}

/// §20.6: the default finding projection is TS's four keys.
#[test]
fn the_finding_projection() {
    let model: AgentGuardVulnerability = serde_json::from_value(serde_json::json!({
        "uuid": "u1", "tsg_id": "100", "created_at": "t", "updated_at": "t", "scan_uuid": "s1",
        "title": "PRIVATE-T", "description": "PRIVATE-D", "vulnerability_type": "SECRET_EXPOSURE",
        "file_path": "PRIVATE-P", "node_id": null, "node_type": null, "node_name": null,
        "remediation_description": null, "original_code": "PRIVATE-CODE", "suggested_code": null,
        "attack_chain_count": 1, "attack_chain_uuids": ["c"], "type_description": "x"
    }))
    .unwrap();
    assert_eq!(
        to_compact(&finding(&model)).unwrap(),
        r#"{"uuid":"u1","scan_uuid":"s1","vulnerability_type":"SECRET_EXPOSURE","attack_chain_count":1}"#
    );
}

/// §20.3 "Record mode": the union of keys in first-seen order, `description` and
/// `remediation` filtered, nine columns at most, `_` read as a space, `null` and absent
/// cells empty, nested values compact JSON, control characters replaced (D52).
#[test]
fn the_record_table() {
    let records = parse(
        r#"[{"uuid":"a","description":"d","b_key":null,"list":["x"]},
            {"uuid":"b","remediation":"r","late":"L\u001b"}]"#,
    )
    .unwrap();
    let records = records.as_array().unwrap();
    assert_eq!(
        format!("{}\n", record_table(records)),
        " uuid │ b key │ list  │ late \n──────┼───────┼───────┼──────\n a    │       │ [\"x\"] │      \n b    │       │       │ L\u{fffd}   \n"
    );
    let wide = parse(
        r#"[{"k1":1,"k2":2,"k3":3,"k4":4,"k5":5,"description":"x","k6":6,"k7":7,"k8":8,"k9":9,"k10":10}]"#,
    )
    .unwrap();
    let table = record_table(wide.as_array().unwrap());
    let header = table.lines().next().unwrap();
    assert!(
        header.contains(" k9 ") && !header.contains("k10"),
        "{header}"
    );
    assert_eq!(record_table(&[]), "", "no rows: the empty string");
}

/// §20.3 "Field mode" (D318): every member, `null` as `null`, objects and arrays compact
/// JSON, numbers in JavaScript form.
#[test]
fn the_field_table() {
    let document = parse(
        r#"{"a":{"count":4,"percent_change":1e-7},"top":null,"list":[1,2.0],"note":"x\nline","flag":true,"n":12.50}"#,
    )
    .unwrap();
    assert_eq!(
        format!("{}\n", field_table(&document)),
        " Field │ Value                             \n───────┼───────────────────────────────────\n a     │ {\"count\":4,\"percent_change\":1e-7} \n top   │ null                              \n list  │ [1,2]                             \n note  │ x\u{fffd}line                            \n flag  │ true                              \n n     │ 12.5                              \n"
    );
}

/// D313, D321.
#[test]
fn status_lines() {
    assert_eq!(
        status_line(3, None),
        "Returned 3 records; see JSON for pagination metadata."
    );
    assert_eq!(
        status_line(10, Some(25)),
        "Returned 10 records; more are available (next --offset 25); see JSON for pagination metadata."
    );
    assert!(CONTENT_NOTICE.ends_with("keep this output private."));
}

/// The rendered documents: JSON with C1 escapes (D212) and no status line; tables with the
/// status line on stderr; `stats` without one.
#[test]
fn rendering() {
    let document =
        parse(r#"{"pagination":{"total_items":1},"rules":[{"uuid":"a","name":"x\u0085"}]}"#)
            .unwrap();
    let (mut out, stdout, stderr) = crate::output::testing::capture(false);
    render_records(&mut out, Format::Json, &document, "rules", Some(1)).unwrap();
    out.commit().unwrap();
    assert!(stdout.text().contains("\"name\": \"x\\u0085\""));
    assert_eq!(stderr.text(), "");
    let (mut out, stdout, stderr) = crate::output::testing::capture(false);
    render_records(&mut out, Format::Pretty, &document, "rules", Some(1)).unwrap();
    out.commit().unwrap();
    assert_eq!(
        stdout.text(),
        " uuid │ name \n──────┼──────\n a    │ x\u{fffd}   \n"
    );
    assert_eq!(
        stderr.text(),
        "  Returned 1 records; more are available (next --offset 1); see JSON for pagination metadata.\n"
    );
    let (mut out, _, stderr) = crate::output::testing::capture(false);
    render_fields(&mut out, Format::Table, &document).unwrap();
    assert_eq!(stderr.text(), "");
}

/// D47: a printed string that carries a registered secret is withheld, a member named by
/// one is dropped; ordinary text (timestamps, ids, words like "secret") is unchanged.
#[test]
fn withholding_touches_only_registered_secrets() {
    let secrets = crate::error::SecretSet::default();
    secrets.add("FAKE-SECRET-100");
    let mut document = parse(
        r#"{"rules":[{"description":"echo FAKE-SECRET-100","FAKE-SECRET-100":1,"name":"a secret token","created_at":"2026-10-19T01:57:59.751Z","uuid":"100","path":"src/password_reset.py"}]}"#,
    )
    .unwrap();
    crate::secrets::withhold(&mut document, &secrets);
    assert_eq!(
        to_compact(&document).unwrap(),
        r#"{"rules":[{"description":"[withheld]","name":"a secret token","created_at":"2026-10-19T01:57:59.751Z","uuid":"100","path":"src/password_reset.py"}]}"#
    );
}
