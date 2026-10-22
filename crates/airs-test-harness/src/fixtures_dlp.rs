//! DLP wire bodies (DESIGN §10 M6b). Every record validates against the TypeScript SDK's
//! zod schemas and the Rust SDK models (`scm::dlp::models`); keys are in schema order, so
//! both SDKs re-serialise them in the same order.
//!
//! Detection content (descriptions of custom records, regexes, proximity keywords, tag
//! values, dictionary keywords) carries the markers of [`content`]. The runner's leak
//! check treats every marker as forbidden on stderr and in the debug log of every
//! airs-cli-rs DLP run; stdout may hold them only where a read prints the record (the
//! tests assert where).

use serde_json::{Value, json};

/// The TSG every DLP fixture belongs to.
pub const TSG: &str = "100";
/// The DLP `tenant_id` of the fixture records.
pub const TENANT_ID: &str = "dlp-tenant-100";
/// The highest marker number the datasets use.
pub const MARKER_COUNT: u32 = 30;
/// `audit_metadata.updated_at` of the fixtures (`2023-11-14T22:13:20.000Z`).
pub const UPDATED_MS: u64 = 1_700_000_000_000;

/// `FAKE-DLP-CONTENT-<nn>`: sensitive detection content in a fixture.
pub fn content(n: u32) -> String {
    format!("FAKE-DLP-CONTENT-{n:02}")
}

/// Every marker the datasets can use.
pub fn markers() -> Vec<String> {
    (1..=MARKER_COUNT).map(content).collect()
}

fn audit() -> Value {
    json!({"created_by": "someone@example.com", "updated_at": UPDATED_MS})
}

/// A data filtering profile.
pub fn filtering_profile(id: &str, name: &str, kind: &str, version: u64) -> Value {
    json!({
        "id": id,
        "name": name,
        "tenant_id": TENANT_ID,
        "type": kind,
        "data_profile_id": 11_995_031,
        "direction": "c2s",
        "file_based": true,
        "non_file_based": false,
        "log_severity": "low",
        "scan_type": "include",
        "is_parent_managed": false,
        "version": version,
        "file_type": ["pdf", "docx"],
        "audit_metadata": audit()
    })
}

/// The custom filtering profile: no direction or severity, exclusions whose category keys
/// are data (D171).
pub fn custom_filtering_profile(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "description": "Custom filtering profile",
        "tenant_id": TENANT_ID,
        "type": "custom",
        "file_based": false,
        "non_file_based": true,
        "is_parent_managed": false,
        "version": 2,
        "exclusions": {
            "app_exclusion_list": [{"app_id": "app-1", "app_name": "App One"}],
            "exclusion_list": {"my_category": ["one"], "Some_Category": []}
        },
        "rule1": {"action": "block"}
    })
}

/// A data pattern of `kind` (`custom`, `predefined`) with `status` and `technique`;
/// `markers` gives the first marker number of its content (description, proximity
/// keyword, regex, two tag values), `None` for a record without content.
pub fn pattern(
    id: &str,
    name: &str,
    kind: &str,
    status: &str,
    technique: &str,
    version: u64,
    markers: Option<u32>,
) -> Value {
    let mut record = json!({
        "id": id,
        "name": name,
        "tenant_id": TENANT_ID,
        "type": kind,
        "status": status,
        "license_type": "standard",
        "is_parent_managed": false,
        "version": version,
        "detection_config": {"technique": technique, "supported_confidence_levels": ["high"]},
        "audit_metadata": audit()
    });
    match markers {
        Some(first) => {
            record["description"] = json!(format!("desc {}", content(first)));
            record["matching_rules"] = json!({
                "proximity_keywords": [content(first + 1)],
                "regexes": [{"regex": format!("{}-[0-9]+", content(first + 2)), "weight": 1}]
            });
            record["tags"] = json!({
                "compliance": [content(first + 3)],
                "my_tag": [content(first + 4)]
            });
        }
        None => record["matching_rules"] = json!({"regexes": null}),
    }
    record
}

/// A data profile: a `basic` one has `detection_rules: null`, an `advanced` one a
/// multi-profile rule (see [`with_pattern_rule`] for an expression tree).
pub fn profile(
    id: &str,
    name: &str,
    kind: &str,
    status: &str,
    profile_type: &str,
    version: u64,
) -> Value {
    let rules = if profile_type == "basic" {
        Value::Null
    } else {
        json!([{
            "rule_type": "multi_profile",
            "multi_profile": {"data_profile_ids": [1, 2], "operator_type": "and"}
        }])
    };
    json!({
        "id": id,
        "name": name,
        "tenant_id": TENANT_ID,
        "type": kind,
        "profile_status": status,
        "profile_type": profile_type,
        "is_granular_data_profile": false,
        "is_parent_managed": false,
        "version": version,
        "detection_rules": rules,
        "audit_metadata": audit()
    })
}

/// `profile` with an expression tree over one pattern (`id`, `name`).
pub fn with_pattern_rule(mut profile: Value, pattern_id: &str, pattern_name: &str) -> Value {
    profile["detection_rules"] = json!([{
        "rule_type": "expression_tree",
        "expression_tree": {
            "operator_type": "or",
            "sub_expressions": [{"rule_item": {
                "detection_technique": "regex",
                "id": pattern_id,
                "name": pattern_name,
                "version": 1,
                "match_type": "include",
                "confidence_level": "high",
                "occurrence_count": 1,
                "occurrence_operator_type": "any"
            }}]
        }
    }]);
    profile
}

/// `record` with a description carrying marker `n`.
pub fn with_description(mut record: Value, n: u32) -> Value {
    record["description"] = json!(format!("profile {}", content(n)));
    record
}

/// A dictionary (the keywords are served only with `keywords=true`); `markers` gives the
/// first marker of its description and two keywords.
pub fn dictionary(
    id: &str,
    name: &str,
    kind: &str,
    status: &str,
    version: u64,
    markers: Option<u32>,
) -> Value {
    let mut record = json!({
        "id": id,
        "name": name,
        "category": "Financial",
        "region_name": "United States",
        "type": kind,
        "is_case_sensitive": false,
        "is_parent_managed": false,
        "detection_technique": "dictionary",
        "dictionary_metadata": {"number_of_keywords": 2, "original_file_name": "keywords.txt"},
        "tags": {"classification": ["pab"]},
        "audit_metadata": audit(),
        "status": status,
        "version": version
    });
    record["keywords"] = match markers {
        Some(first) => {
            record["description"] = json!(format!("dict {}", content(first)));
            json!([content(first + 1), content(first + 2)])
        }
        None => json!(["predefined-keyword"]),
    };
    record
}

/// The seeded filtering profiles (service order is by name).
pub fn filtering_profiles() -> Vec<Value> {
    vec![
        filtering_profile("fp-1", "Bulk CCN", "predefined", 1),
        custom_filtering_profile("fp-2", "Custom FP"),
    ]
}

/// The seeded patterns: one predefined (with `regexes: null`), two custom with content,
/// one disabled, one archived and one parent-managed.
pub fn patterns() -> Vec<Value> {
    let mut parent = pattern(
        "p-par-1",
        "Parent Pattern",
        "custom",
        "active",
        "regex",
        1,
        None,
    );
    parent["is_parent_managed"] = json!(true);
    vec![
        pattern(
            "p-del-1",
            "Archived Pattern",
            "custom",
            "deleted",
            "regex",
            3,
            None,
        ),
        pattern(
            "p-pre-1",
            "Credit Card Number",
            "predefined",
            "active",
            "regex",
            2,
            None,
        ),
        pattern(
            "p-dis-1",
            "Disabled Pattern",
            "custom",
            "disabled",
            "weighted_regex",
            4,
            None,
        ),
        pattern(
            "p-cus-1",
            "My Pattern",
            "custom",
            "active",
            "regex",
            1,
            Some(1),
        ),
        parent,
    ]
}

/// The seeded profiles: a predefined `basic` profile with `detection_rules: null`, a
/// custom expression-tree profile, a multi-profile one and a disabled one.
pub fn profiles() -> Vec<Value> {
    vec![
        with_pattern_rule(
            profile(
                "dp-dis-1",
                "Disabled Profile",
                "custom",
                "disabled",
                "advanced",
                2,
            ),
            "p-cus-1",
            "My Pattern",
        ),
        profile(
            "dp-multi-1",
            "Multi Profile",
            "custom",
            "active",
            "advanced",
            1,
        ),
        with_description(
            with_pattern_rule(
                profile("dp-cus-1", "My Profile", "custom", "active", "advanced", 1),
                "p-cus-1",
                "My Pattern",
            ),
            6,
        ),
        profile(
            "dp-pre-1",
            "PCI Profile",
            "predefined",
            "active",
            "basic",
            3,
        ),
    ]
}

/// The seeded dictionaries.
pub fn dictionaries() -> Vec<Value> {
    vec![
        dictionary("d-cus-1", "My Dict", "custom", "active", 2, Some(7)),
        dictionary("d-pre-1", "Predef Dict", "predefined", "active", 1, None),
    ]
}
