//! Model Security wire bodies (DESIGN §10 M6c). Every record validates against the
//! TypeScript SDK's zod schemas and the Rust SDK models (`scm::airs::model_security`);
//! keys are in schema order, so both SDKs re-serialise them in the same order.
//!
//! Ids are `11111111-1111-4111-8111-<12 digits>` ([`uuid`], `U(n)` in the research
//! captures): groups 1–99, rules 201–299, rule instances 301–399, scans 401–499,
//! evaluations 501–599, violations 601–699, files 701–799, models 801–899, versions
//! 901–999. The seeded dataset is the one the TypeScript captures (MS§5–§10) were taken
//! from, so a parity test sees identical bytes; the variants the §12 rows need (a summary
//! without counts, a URI carrying a credential, a custom-rule instance, …) are added by
//! the tests that pin them.
//!
//! Sensitive values carry `FAKE-MS-SECRET-<nn>` markers ([`secret`]). The runner's leak
//! check forbids every marker on stderr and in the debug log of each airs-cli-rs
//! model-security run; stdout may hold them only where §17.15 prints them (the tests
//! assert where), never inside URI userinfo or queries (withheld, D191).

use serde_json::{Value, json};

/// The TSG every model-security fixture belongs to.
pub const TSG: &str = "100";
/// The timestamp of every fixture record.
pub const AT: &str = "2026-01-01T00:00:00Z";
/// The highest marker number the datasets use.
pub const MARKER_COUNT: u32 = 20;

/// `11111111-1111-4111-8111-<n:012>`.
pub fn uuid(n: u64) -> String {
    format!("11111111-1111-4111-8111-{n:012}")
}

/// `FAKE-MS-SECRET-<nn>`: a sensitive value in a fixture.
pub fn secret(n: u32) -> String {
    format!("FAKE-MS-SECRET-{n:02}")
}

/// Every marker the datasets can use.
pub fn markers() -> Vec<String> {
    (1..=MARKER_COUNT).map(secret).collect()
}

/// The `expires_at` of every PyPI auth answer.
pub const PYPI_EXPIRES: &str = "2026-10-18T15:06:25";

/// The PyPI password of tenant `tsg`: `FAKE-PYPI-SECRET-<tsg>` (DESIGN §10 M6c).
pub fn pypi_secret(tsg: &str) -> String {
    format!("FAKE-PYPI-SECRET-{tsg}")
}

/// The prefix of every PyPI password marker (the runner's leak check).
pub const PYPI_MARKER: &str = "FAKE-PYPI-SECRET-";

/// The PyPI index host of the fixture (`.invalid`: never resolvable, never contacted).
pub const PYPI_HOST: &str = "pypi.invalid";

/// The credential-free index of the fixture's PyPI URL.
pub const PYPI_INDEX: &str = "https://pypi.invalid/airs/simple/";

/// `https://oauth2accesstoken:FAKE-PYPI-SECRET-<tsg>@pypi.invalid/airs/simple/`.
pub fn pypi_url(tsg: &str) -> String {
    format!(
        "https://oauth2accesstoken:{}@{PYPI_HOST}/airs/simple/",
        pypi_secret(tsg)
    )
}

/// A security group.
pub fn group(n: u64, name: &str, description: &str, source: &str, state: &str) -> Value {
    json!({
        "uuid": uuid(n),
        "tsg_id": TSG,
        "created_at": AT,
        "updated_at": AT,
        "name": name,
        "description": description,
        "source_type": source,
        "state": state,
        "is_tombstone": false
    })
}

/// The two TS-capture groups (MS§5.1).
pub fn groups() -> Vec<Value> {
    vec![
        group(1, "Default LOCAL", "Auto group", "LOCAL", "ACTIVE"),
        group(2, "Pending S3", "", "S3", "PENDING"),
    ]
}

/// The two TS-capture rules (MS§6): one with a remediation, one with an editable field.
pub fn rules() -> Vec<Value> {
    vec![
        json!({
            "uuid": uuid(201),
            "name": "Load Time Code Execution Check",
            "description": "No unsafe operators at load time",
            "rule_type": "ARTIFACT",
            "compatible_sources": ["ALL"],
            "default_state": "BLOCKING",
            "remediation": {
                "description": "Remove unsafe operators",
                "steps": ["Review the violation", "Use a safe format"],
                "url": "https://docs.example.invalid/r1"
            },
            "editable_fields": [],
            "constant_values": {},
            "default_values": {}
        }),
        json!({
            "uuid": uuid(202),
            "name": "Stored In Approved File Format",
            "description": "Formats must be approved",
            "rule_type": "METADATA",
            "compatible_sources": ["LOCAL", "S3"],
            "default_state": "ALLOWING",
            "remediation": {"description": "", "steps": [], "url": ""},
            "editable_fields": [{
                "attribute_name": "approved_formats",
                "type": "LIST",
                "display_name": "Approved Formats",
                "display_type": "MULTI_SELECT",
                "description": "Formats allowed",
                "dropdown_values": [{"value": "onnx", "label": "ONNX"}]
            }],
            "constant_values": {},
            "default_values": {"approved_formats": ["onnx"]}
        }),
    ]
}

/// The rule instances of group `U(1)` (MS§7): one with the rule embedded, one without.
pub fn rule_instances() -> Vec<Value> {
    let rule = rules()[0].clone();
    vec![
        json!({
            "uuid": uuid(301),
            "tsg_id": TSG,
            "created_at": AT,
            "updated_at": AT,
            "security_group_uuid": uuid(1),
            "security_rule_uuid": uuid(201),
            "state": "BLOCKING",
            "rule": rule,
            "field_values": {}
        }),
        json!({
            "uuid": uuid(302),
            "tsg_id": TSG,
            "created_at": AT,
            "updated_at": AT,
            "security_group_uuid": uuid(1),
            "security_rule_uuid": uuid(202),
            "state": "DISABLED",
            "field_values": {"approved_formats": ["onnx", "safetensors"]}
        }),
    ]
}

/// An instance of a custom rule (D192): no `security_rule_uuid`, no `rule`, a
/// `custom_rule`.
pub fn custom_rule_instance(n: u64) -> Value {
    json!({
        "custom_rule": {"description": "A tenant rule", "name": "Tenant Custom Rule", "uuid": uuid(311)},
        "custom_rule_uuid": uuid(311),
        "uuid": uuid(n),
        "tsg_id": TSG,
        "security_group_uuid": uuid(1),
        "state": "BLOCKING"
    })
}

/// A scan.
pub fn scan(n: u64, outcome: &str, uri: &str, origin: &str, summary: Option<Value>) -> Value {
    let mut scan = json!({
        "uuid": uuid(n),
        "tsg_id": TSG,
        "created_at": AT,
        "updated_at": AT,
        "model_uri": uri,
        "owner": "someone@example.com",
        "scan_origin": origin,
        "security_group_uuid": uuid(1),
        "security_group_name": "Default LOCAL",
        "eval_outcome": outcome,
        "source_type": "HUGGING_FACE"
    });
    if let Some(summary) = summary {
        scan["eval_summary"] = summary;
    }
    scan
}

/// The two TS-capture scans (MS§8.1, §8.2).
pub fn scans() -> Vec<Value> {
    let mut first = scan(
        401,
        "BLOCKED",
        "hf://org/model",
        "MODEL_SECURITY_SDK",
        Some(json!({"rules_failed": 1, "rules_passed": 3, "total_rules": 4})),
    );
    first["labels"] = json!([{"key": "env", "value": "prod"}, {"key": "team", "value": "ml"}]);
    vec![first, scan(402, "ALLOWED", "", "MODEL_SECURITY_API", None)]
}

/// A pending scan whose summary carries no counts (D180: TS prints `0 failed`).
pub fn pending_scan(n: u64) -> Value {
    scan(
        n,
        "PENDING",
        "hf://org/pending",
        "MODEL_SECURITY_API",
        Some(json!({})),
    )
}

/// A scan whose URI carries userinfo and a signed query (markers 1–3, D191).
pub fn credential_uri_scan(n: u64) -> Value {
    scan(
        n,
        "ALLOWED",
        &format!(
            "https://{}:{}@models.example.invalid/org/model.bin?X-Amz-Signature={}&X-Amz-Expires=3600#{}",
            secret(1),
            secret(2),
            secret(3),
            secret(4)
        ),
        "MODEL_SECURITY_SDK",
        Some(json!({"rules_failed": 0, "rules_passed": 2, "total_rules": 2})),
    )
}

/// The evaluations of scan `U(401)` (MS§8.4).
pub fn evaluations() -> Vec<Value> {
    let evaluation = |n: u64,
                      result: &str,
                      count: u64,
                      instance: u64,
                      name: &str,
                      description: &str,
                      state: &str| {
        json!({
            "uuid": uuid(n),
            "tsg_id": TSG,
            "created_at": AT,
            "updated_at": AT,
            "result": result,
            "violation_count": count,
            "rule_instance_uuid": uuid(instance),
            "scan_uuid": uuid(401),
            "rule_name": name,
            "rule_description": description,
            "rule_instance_state": state
        })
    };
    vec![
        evaluation(
            501,
            "FAILED",
            2,
            301,
            "Load Time Code Execution Check",
            "No unsafe operators",
            "BLOCKING",
        ),
        evaluation(
            502,
            "PASSED",
            0,
            302,
            "Stored In Approved File Format",
            "Formats must be approved",
            "ALLOWING",
        ),
    ]
}

/// The violations of scan `U(401)` (MS§8.5); keyed by scan through `scan_uuid` (a
/// fixture field the schemas pass through).
pub fn violations() -> Vec<Value> {
    vec![json!({
        "uuid": uuid(601),
        "tsg_id": TSG,
        "created_at": AT,
        "updated_at": AT,
        "description": "Found os.system",
        "rule_instance_uuid": uuid(301),
        "rule_name": "Load Time Code Execution Check",
        "rule_description": "No unsafe operators",
        "rule_instance_state": "BLOCKING",
        "file": "model.pkl",
        "threat": "PAIT-PKL-100",
        "threat_description": "Arbitrary code at load time",
        "scan_uuid": uuid(401)
    })]
}

/// A file record.
pub fn file(
    n: u64,
    path: &str,
    kind: &str,
    result: &str,
    formats: Option<&[&str]>,
    scan: u64,
    version: u64,
) -> Value {
    let mut file = json!({
        "uuid": uuid(n),
        "tsg_id": TSG,
        "created_at": AT,
        "updated_at": AT,
        "path": path,
        "parent_path": "",
        "type": kind,
        "result": result,
        "model_version_uuid": uuid(version)
    });
    if let Some(formats) = formats {
        file["formats"] = json!(formats);
    }
    file["scan_uuid"] = json!(uuid(scan));
    file
}

/// The files of scan `U(401)` / version `U(901)` (MS§8.6; one without `formats`).
pub fn files() -> Vec<Value> {
    vec![
        file(
            701,
            "model.pkl",
            "FILE",
            "FAILED",
            Some(&["pickle"]),
            401,
            901,
        ),
        file(702, "README.md", "FILE", "SKIPPED", Some(&[]), 401, 901),
        file(703, "weights", "DIRECTORY", "SUCCESS", Some(&[]), 401, 901),
    ]
}

/// The two TS-capture models (MS§9.1).
pub fn models() -> Vec<Value> {
    vec![
        json!({
            "uuid": uuid(801),
            "tsg_id": TSG,
            "created_at": AT,
            "updated_at": AT,
            "name": "org/model",
            "latest_version_uuid": uuid(901),
            "latest_version_revision": "main",
            "latest_version_outcome": "BLOCKED",
            "latest_version_formats": ["pickle", "onnx"],
            "latest_version_source_types": ["HUGGING_FACE"],
            "latest_version_scan_time": AT
        }),
        json!({
            "uuid": uuid(802),
            "tsg_id": TSG,
            "created_at": AT,
            "updated_at": AT,
            "name": "local/unscanned"
        }),
    ]
}

/// The versions of model `U(801)` (MS§9.3).
pub fn versions() -> Vec<Value> {
    vec![
        json!({
            "uuid": uuid(901),
            "tsg_id": TSG,
            "created_at": AT,
            "updated_at": AT,
            "revision": "main",
            "model_uuid": uuid(801),
            "file_count": 3,
            "license": "mit",
            "latest_scan_time": AT,
            "hf_model_name": "model",
            "hf_organization": "org",
            "model_formats": ["pickle"],
            "source_types": ["HUGGING_FACE"],
            "last_eval_outcome": "BLOCKED",
            "last_eval_summary": {"rules_failed": 1, "rules_passed": 3, "total_rules": 4}
        }),
        json!({
            "uuid": uuid(902),
            "tsg_id": TSG,
            "created_at": AT,
            "updated_at": AT,
            "revision": "v0",
            "model_uuid": uuid(801)
        }),
    ]
}

/// A version whose summary carries no counts (D180).
pub fn uncounted_version(n: u64) -> Value {
    json!({
        "uuid": uuid(n),
        "tsg_id": TSG,
        "created_at": AT,
        "updated_at": AT,
        "revision": "pending",
        "model_uuid": uuid(801),
        "last_eval_outcome": "PENDING",
        "last_eval_summary": {}
    })
}
