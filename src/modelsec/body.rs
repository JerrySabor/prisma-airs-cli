//! The model-security request bodies (DESIGN §17.3, §17.8–§17.11): the `--config` key
//! rules of `groups create`, `rule-instances update` and `scans create`, the bodies and
//! their SDK schema checks (D116), `--labels` and `--keys`, the empty-update refusals
//! (D187), and the dropped keys and key lists of the label confirmations (D185).
//!
//! Everything here is pure. Messages name the flag, the path or a key, never a value
//! (D188): configs, label values and field values are user data.

use super::comma_list;
use crate::error::CliError;
use crate::json::OValue;
use crate::output::terminal_safe;
use crate::writes;
use scm::airs::model_security::models as msm;
use scm::validation::Mode;
use serde_json::{Map, Value};

/// The keys a security group config takes (TS `ms.ts:158-163`).
pub const GROUP_KEYS: [&str; 4] = ["name", "source_type", "description", "rule_configurations"];
/// The keys a rule-instance config takes (TS `svc.ts:330-347`).
pub const INSTANCE_KEYS: [&str; 3] = ["state", "field_values", "security_group_uuid"];
/// The number of label keys a prompt or warning names before `, and <k> more`.
pub const LISTED_KEYS: usize = 20;

/// A key as a message shows it: terminal-safe, at most 64 characters.
fn shown_key(key: &str) -> String {
    let safe = terminal_safe(key);
    let mut chars = safe.chars();
    let cut: String = chars.by_ref().take(64).collect();
    if chars.next().is_some() {
        format!("{cut}…")
    } else {
        cut
    }
}

/// `<path> has an unknown key <key>; a <what> config takes <list>` for the first key of
/// `config` (in key order) that `allowed` does not hold.
fn unknown_key(
    path: &str,
    config: &Map<String, Value>,
    allowed: &[&str],
    what: &str,
    list: &str,
) -> Result<(), CliError> {
    match config.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(CliError::operational(format!(
            "{path} has an unknown key {}; a {what} config takes {list}",
            shown_key(key)
        ))),
        None => Ok(()),
    }
}

/// The D116 failure of a body: exit 1 for a file body, exit 2 for one built from flags.
fn schema_failure(method: &str, path: &str, from_file: bool) -> CliError {
    let failure = writes::invalid_body(method, path);
    if from_file {
        failure
    } else {
        CliError::usage(failure.message())
    }
}

/// `groups create --config <path>` (§17.8): only the four group keys (choice 15), the
/// body validated with `ModelSecurityGroupCreateRequest` (whose request default sends a
/// missing `description` as `""`, both SDKs).
pub fn group_create(
    path: &str,
    config: Map<String, Value>,
) -> Result<msm::ModelSecurityGroupCreateRequest, CliError> {
    unknown_key(
        path,
        &config,
        &GROUP_KEYS,
        "security group",
        "name, source_type, description and rule_configurations",
    )?;
    msm::ModelSecurityGroupCreateRequest::parse(Value::Object(config), Mode::Request)
        .map_err(|_| schema_failure("POST", "/v1/security-groups", true))
}

/// `groups update <uuid> [--name] [--description]` (§17.8, D187): at least one flag;
/// each given value is sent as given (`--description ''` clears); the body validated
/// with `ModelSecurityGroupUpdateRequest` (exit 2).
pub fn group_update(
    uuid: &str,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<msm::ModelSecurityGroupUpdateRequest, CliError> {
    if name.is_none() && description.is_none() {
        return Err(CliError::usage(
            "groups update needs --name or --description",
        ));
    }
    let mut body = Map::new();
    if let Some(name) = name {
        body.insert("name".to_owned(), Value::String(name.to_owned()));
    }
    if let Some(description) = description {
        body.insert(
            "description".to_owned(),
            Value::String(description.to_owned()),
        );
    }
    msm::ModelSecurityGroupUpdateRequest::parse(Value::Object(body), Mode::Request)
        .map_err(|_| schema_failure("PUT", &format!("/v1/security-groups/{uuid}"), false))
}

/// `rule-instances update <g> <i> --config <path>` (§17.9): the three instance keys; a
/// `security_group_uuid` must name `<g>` (ASCII case-insensitively); `state` or
/// `field_values` must be present (a `null` counts, TS sends it); the body is
/// `{security_group_uuid: <g>, state?, field_values?}`, validated with
/// `ModelSecurityRuleInstanceUpdateRequest`. Only the named fields are sent (choice 14).
pub fn rule_instance_update(
    path: &str,
    group: &str,
    instance: &str,
    config: Map<String, Value>,
) -> Result<msm::ModelSecurityRuleInstanceUpdateRequest, CliError> {
    unknown_key(
        path,
        &config,
        &INSTANCE_KEYS,
        "rule instance",
        "state, field_values and security_group_uuid",
    )?;
    if let Some(named) = config.get("security_group_uuid")
        && !named
            .as_str()
            .is_some_and(|named| named.eq_ignore_ascii_case(group))
    {
        return Err(CliError::operational(format!(
            "{path} names another security group than {group}"
        )));
    }
    if !config.contains_key("state") && !config.contains_key("field_values") {
        return Err(CliError::operational(format!(
            "{path} must set state or field_values"
        )));
    }
    let mut body = Map::new();
    body.insert(
        "security_group_uuid".to_owned(),
        Value::String(group.to_owned()),
    );
    for key in ["state", "field_values"] {
        if let Some(value) = config.get(key) {
            body.insert(key.to_owned(), value.clone());
        }
    }
    msm::ModelSecurityRuleInstanceUpdateRequest::parse(Value::Object(body), Mode::Request).map_err(
        |_| {
            schema_failure(
                "PUT",
                &format!("/v1/security-groups/{group}/rule-instances/{instance}"),
                true,
            )
        },
    )
}

/// `scans create --config <path>` (§17.10): the whole file is the body (TS), validated
/// with `ScanCreateRequest`; unknown keys are kept and sent (choice 15).
pub fn scan_create(config: Map<String, Value>) -> Result<msm::ScanCreateRequest, CliError> {
    msm::ScanCreateRequest::parse(Value::Object(config), Mode::Request)
        .map_err(|_| schema_failure("POST", "/v1/scans", true))
}

/// The `--labels` shape message.
pub const LABELS_SHAPE: &str = "--labels must be a JSON array of {\"key\", \"value\"} objects (key 1-128, value 1-256 characters)";

/// `--labels <json>` (§17.3 "JSON arguments", D188): one JSON value (the D44 classes
/// invalid), an array of at least one object, each a valid label of the SDK's
/// `LabelsCreateRequest` schema; no excerpt of the input is ever echoed (exit 2).
pub fn labels(text: &str) -> Result<msm::LabelsCreateRequest, CliError> {
    let value: Value =
        serde_json::from_str(text).map_err(|_| CliError::usage("--labels is not valid JSON"))?;
    let shape = || CliError::usage(LABELS_SHAPE);
    let Value::Array(items) = &value else {
        return Err(shape());
    };
    if items.is_empty() || !items.iter().all(Value::is_object) {
        return Err(shape());
    }
    let mut body = Map::new();
    body.insert("labels".to_owned(), value);
    msm::LabelsCreateRequest::parse(Value::Object(body), Mode::Request).map_err(|_| shape())
}

/// `--keys <keys>` (§17.3, D187): split on `,`, each trimmed (TS); no empty item; each
/// within the filter bound; at most 256 keys.
pub fn keys(text: &str) -> Result<Vec<String>, CliError> {
    Ok(comma_list("--keys", Some(text))?.unwrap_or_default())
}

/// The label keys of a scan record (raw wire shape), in the scan's order.
pub fn label_keys(scan: &OValue) -> Vec<String> {
    scan.get("labels")
        .and_then(OValue::as_array)
        .map(|labels| {
            labels
                .iter()
                .filter_map(|label| label.get("key").and_then(OValue::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The keys `labels set` drops (§17.11): the scan's current keys that the new list does
/// not name, in the scan's order, each once.
pub fn dropped_keys(current: &[String], replacement: &msm::LabelsCreateRequest) -> Vec<String> {
    let mut dropped: Vec<String> = Vec::new();
    for key in current {
        if !replacement.labels.iter().any(|label| label.key == *key) && !dropped.contains(key) {
            dropped.push(key.clone());
        }
    }
    dropped
}

/// Label keys for a prompt or warning: joined `, `, at most [`LISTED_KEYS`], then
/// `, and <k> more` (§17.3).
pub fn key_list(keys: &[String]) -> String {
    let shown: Vec<String> = keys
        .iter()
        .take(LISTED_KEYS)
        .map(|key| terminal_safe(key).into_owned())
        .collect();
    let mut text = shown.join(", ");
    if keys.len() > LISTED_KEYS {
        text.push_str(&format!(", and {} more", keys.len() - LISTED_KEYS));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(text: &str) -> Map<String, Value> {
        match serde_json::from_str(text).unwrap() {
            Value::Object(map) => map,
            _ => panic!("not an object"),
        }
    }

    fn message<T>(result: Result<T, CliError>) -> (u8, String) {
        match result {
            Err(CliError::Usage(message)) => (2, message),
            Err(error) => (1, error.message()),
            Ok(_) => panic!("expected an error"),
        }
    }

    fn wire<T: serde::Serialize>(model: &T) -> Value {
        serde_json::to_value(model).unwrap()
    }

    const G: &str = "11111111-1111-4111-8111-000000000001";
    const I: &str = "11111111-1111-4111-8111-000000000302";

    /// `modelsecurity.spec.ts:220-243`: rule configurations pass through; a missing
    /// description is the schema default `""`; unknown keys are refused (choice 15).
    #[test]
    fn group_configs_take_four_keys() {
        let body = group_create(
            "g.json",
            object(r#"{"name":"G","source_type":"LOCAL","rule_configurations":{"r-1":{"state":"BLOCKING"}}}"#),
        )
        .unwrap();
        assert_eq!(
            wire(&body),
            serde_json::json!({"name":"G","source_type":"LOCAL","description":"","rule_configurations":{"r-1":{"state":"BLOCKING"}}})
        );
        assert_eq!(
            message(group_create(
                "g.json",
                object(r#"{"name":"G","source_type":"LOCAL","extra\u001b[31m":1}"#)
            )),
            (
                1,
                "g.json has an unknown key extra\u{fffd}[31m; a security group config takes name, source_type, description and rule_configurations".to_owned()
            )
        );
        let long = format!(r#"{{"{}":1}}"#, "k".repeat(80));
        let (_, text) = message(group_create("g.json", object(&long)));
        assert!(
            text.contains(&format!("key {}…;", "k".repeat(64))),
            "{text}"
        );
        // Choice 51: a `null` for an optional key is the schema's refusal (TS drops a
        // `null` `rule_configurations` and sends the rest).
        for bad in [
            r#"{"name":"","source_type":"LOCAL"}"#,
            r#"{"name":"G","source_type":"FTP"}"#,
            r#"{"source_type":"LOCAL"}"#,
            r#"{"name":"G","source_type":"LOCAL","rule_configurations":null}"#,
            r#"{"name":"G","source_type":"LOCAL","description":null}"#,
        ] {
            assert_eq!(
                message(group_create("g.json", object(bad))),
                (
                    1,
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/security-groups did not match schema".to_owned()
                ),
                "{bad}"
            );
        }
    }

    /// D187: an update needs a flag; `--description ''` is sent; schema failures exit 2.
    #[test]
    fn group_updates_send_what_was_given() {
        assert_eq!(
            message(group_update(G, None, None)),
            (2, "groups update needs --name or --description".to_owned())
        );
        assert_eq!(
            wire(&group_update(G, None, Some("")).unwrap()),
            serde_json::json!({"description": ""})
        );
        assert_eq!(
            wire(&group_update(G, Some("Updated"), Some("new desc")).unwrap()),
            serde_json::json!({"name": "Updated", "description": "new desc"})
        );
        assert_eq!(
            message(group_update(G, Some(""), None)),
            (
                2,
                format!(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/security-groups/{G} did not match schema"
                )
            )
        );
        let long = "d".repeat(1001);
        assert_eq!(message(group_update(G, None, Some(&long))).0, 2);
    }

    /// `modelsecurity.spec.ts:375-403`: the body carries the positional group; D187 and
    /// D188 refuse files that change nothing or name another group.
    #[test]
    fn rule_instance_configs_name_a_field_and_the_group() {
        let body = rule_instance_update(
            "ri.json",
            G,
            I,
            object(r#"{"state":"BLOCKING","field_values":{"approved_formats":["onnx"]}}"#),
        )
        .unwrap();
        assert_eq!(
            wire(&body),
            serde_json::json!({"security_group_uuid": G, "state": "BLOCKING", "field_values": {"approved_formats": ["onnx"]}})
        );
        let upper = G.to_uppercase();
        let body = rule_instance_update(
            "ri.json",
            G,
            I,
            object(&format!(
                r#"{{"security_group_uuid":"{upper}","state":null}}"#
            )),
        )
        .unwrap();
        assert_eq!(
            wire(&body),
            serde_json::json!({"security_group_uuid": G, "state": null})
        );
        for (config, text) in [
            (
                r#"{"state":"BLOCKING","rule":"x"}"#.to_owned(),
                "ri.json has an unknown key rule; a rule instance config takes state, field_values and security_group_uuid".to_owned(),
            ),
            (
                r#"{"security_group_uuid":"11111111-1111-4111-8111-000000000002","state":"BLOCKING"}"#.to_owned(),
                format!("ri.json names another security group than {G}"),
            ),
            (
                r#"{"security_group_uuid":7,"state":"BLOCKING"}"#.to_owned(),
                format!("ri.json names another security group than {G}"),
            ),
            (
                format!(r#"{{"security_group_uuid":"{G}"}}"#),
                "ri.json must set state or field_values".to_owned(),
            ),
            (
                r#"{}"#.to_owned(),
                "ri.json must set state or field_values".to_owned(),
            ),
            (
                r#"{"state":"ON"}"#.to_owned(),
                format!("AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/security-groups/{G}/rule-instances/{I} did not match schema"),
            ),
        ] {
            assert_eq!(
                message(rule_instance_update("ri.json", G, I, object(&config))),
                (1, text),
                "{config}"
            );
        }
    }

    /// The scan config is the body, unknown keys kept (TS).
    #[test]
    fn scan_configs_are_sent_whole() {
        let body = scan_create(object(&format!(
            r#"{{"model_uri":"hf://org/model","security_group_uuid":"{G}","unknown":"kept"}}"#
        )))
        .unwrap();
        assert_eq!(wire(&body)["unknown"], "kept");
        for bad in [
            r#"{"model_uri":"hf://org/model"}"#.to_owned(),
            format!(r#"{{"model_uri":"hf://x","security_group_uuid":"{G}","scan_origin":"CLI"}}"#),
        ] {
            assert_eq!(
                message(scan_create(object(&bad))),
                (
                    1,
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scans did not match schema".to_owned()
                )
            );
        }
    }

    /// `modelsecurity.spec.ts:741-767`: the label bodies; D188: no excerpt is echoed.
    #[test]
    fn labels_and_keys_are_checked_without_echoing_them() {
        let body = labels(r#"[{"key":"env","value":"prod"}]"#).unwrap();
        assert_eq!(
            wire(&body),
            serde_json::json!({"labels": [{"key": "env", "value": "prod"}]})
        );
        for bad in ["PRIVATE-NOT-JSON", "[", "", r#"{"key":"x"}"#] {
            let (code, text) = message(labels(bad));
            assert_eq!(code, 2);
            assert!(!text.contains("PRIVATE"), "{text}");
            assert!(
                text == "--labels is not valid JSON" || text == LABELS_SHAPE,
                "{bad}: {text}"
            );
        }
        assert_eq!(
            message(labels("PRIVATE-NOT-JSON")).1,
            "--labels is not valid JSON"
        );
        for bad in [
            "[]",
            r#"[1]"#,
            r#"[{"key":"","value":"v"}]"#,
            r#"[{"key":"k","value":""}]"#,
            r#"[{"key":"k"}]"#,
        ] {
            assert_eq!(message(labels(bad)), (2, LABELS_SHAPE.to_owned()), "{bad}");
        }
        let key = "k".repeat(129);
        assert_eq!(
            message(labels(&format!(r#"[{{"key":"{key}","value":"v"}}]"#))).1,
            LABELS_SHAPE
        );
        assert!(
            labels(&format!(
                r#"[{{"key":"{}","value":"{}"}}]"#,
                "k".repeat(128),
                "v".repeat(256)
            ))
            .is_ok()
        );
        assert_eq!(keys(" env , team").unwrap(), ["env", "team"]);
        for bad in ["", ",", "env,,team"] {
            assert_eq!(
                message(keys(bad)),
                (2, "--keys values must not be empty".to_owned())
            );
        }
    }

    /// D185: the dropped keys in the scan's order and the key list cut at 20.
    #[test]
    fn dropped_keys_and_key_lists() {
        let scan = crate::json::parse(
            r#"{"labels":[{"key":"env","value":"a"},{"key":"team","value":"b"},{"key":"new","value":"c"}]}"#,
        )
        .unwrap();
        let current = label_keys(&scan);
        assert_eq!(current, ["env", "team", "new"]);
        let replacement =
            labels(r#"[{"key":"team","value":"x"},{"key":"only","value":"y"}]"#).unwrap();
        assert_eq!(dropped_keys(&current, &replacement), ["env", "new"]);
        assert!(label_keys(&crate::json::parse("{}").unwrap()).is_empty());
        let many: Vec<String> = (0..23).map(|n| format!("k{n}")).collect();
        let text = key_list(&many);
        assert!(text.starts_with("k0, k1, "), "{text}");
        assert!(text.ends_with("k19, and 3 more"), "{text}");
        assert_eq!(key_list(&["a\u{1b}b".to_owned()]), "a\u{fffd}b");
    }
}
