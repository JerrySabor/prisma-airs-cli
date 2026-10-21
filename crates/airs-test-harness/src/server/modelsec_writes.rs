//! The model-security write routes of the fixture (DESIGN §10 M6c, step 2). Each one
//! changes the dataset, so a later read sees the change:
//!
//! - `POST <mgmt>/security-groups`: a new group `U(101 + n)` in state `PENDING`
//!   (`is_tombstone: false`), its `description` as sent (else `""`); `name` and
//!   `source_type` are required (else 422);
//! - `PUT <mgmt>/security-groups/{uuid}`: `name` and `description` replaced when sent;
//! - `DELETE <mgmt>/security-groups/{uuid}`: 204, then [`GroupDeleteMode`] (removed, a
//!   tombstone, or still active);
//! - `PUT <mgmt>/security-groups/{g}/rule-instances/{i}`: the body's
//!   `security_group_uuid` must name `{g}` (else 422); `state` and `field_values` replaced
//!   when sent;
//! - `POST <data>/scans`: a new `PENDING` scan `U(451 + n)` without a summary, from the
//!   body's `model_uri`, `security_group_uuid`, `scan_origin` and `labels`;
//! - `POST|PUT <data>/scans/{s}/labels`: merge by key, or replace; `{}`;
//! - `DELETE <data>/scans/{s}/labels?keys=…`: the named keys removed; 204.

use serde_json::{Value, json};

use super::modelsec::{GroupDeleteMode, ModelSecData, Ms, find, not_found};
use super::plan::Planned;
use super::record::RecordedRequest;
use crate::fixtures::modelsec as fx;

fn unprocessable(message: &str) -> Planned {
    Planned::json(422, &json!({"detail": [{"msg": message}]}))
}

fn index_of(rows: &[Value], id: &str) -> Option<usize> {
    rows.iter()
        .position(|row| row.get("uuid").and_then(Value::as_str) == Some(id))
}

fn text<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str)
}

/// The answer of a model-security write route (credentials already checked);
/// `part(n)` is the `n`-th decoded path segment after the plane's `/v1`.
pub(crate) fn answer(
    data: &mut ModelSecData,
    route: Ms,
    request: &RecordedRequest,
    part: &dyn Fn(usize) -> String,
) -> Planned {
    let body = request.body_json().unwrap_or(Value::Null);
    match route {
        Ms::GroupCreate => {
            let (Some(name), Some(source)) = (text(&body, "name"), text(&body, "source_type"))
            else {
                return unprocessable("name and source_type are required");
            };
            if name.is_empty() {
                return unprocessable("name must not be empty");
            }
            data.groups_created += 1;
            let group = fx::group(
                100 + data.groups_created,
                name,
                text(&body, "description").unwrap_or_default(),
                source,
                "PENDING",
            );
            let mut group = group;
            if let Some(at) = data.stamp() {
                group["created_at"] = json!(at);
                group["updated_at"] = json!(at);
            }
            data.groups.push(group.clone());
            if data.instances_for_created_groups {
                let mut instance = fx::rule_instances()[0].clone();
                instance["uuid"] = json!(fx::uuid(350 + data.groups_created));
                instance["security_group_uuid"] = group["uuid"].clone();
                data.rule_instances.push(instance);
            }
            Planned::json(200, &group)
        }
        Ms::GroupUpdate => {
            let Some(index) = index_of(&data.groups, &part(1)) else {
                return not_found("security group");
            };
            let group = &mut data.groups[index];
            for key in ["name", "description"] {
                if let Some(value) = text(&body, key) {
                    group[key] = json!(value);
                }
            }
            Planned::json(200, group)
        }
        Ms::GroupDelete => {
            let Some(index) = index_of(&data.groups, &part(1)) else {
                return not_found("security group");
            };
            match data.group_delete {
                GroupDeleteMode::Hard => {
                    data.groups.remove(index);
                }
                GroupDeleteMode::Tombstone => {
                    data.groups[index]["is_tombstone"] = json!(true);
                }
                GroupDeleteMode::StillActive => {}
                GroupDeleteMode::Lagging(reads) => {
                    data.delete_lag.insert(part(1), reads);
                }
            }
            Planned::status(204)
        }
        Ms::RuleInstanceUpdate => {
            let (group, instance) = (part(1), part(3));
            if find(&data.groups, &group).is_none() {
                return not_found("security group");
            }
            let named = text(&body, "security_group_uuid").unwrap_or_default();
            if !named.eq_ignore_ascii_case(&group) {
                return unprocessable("security_group_uuid does not match the path");
            }
            let Some(row) = data.rule_instances.iter_mut().find(|row| {
                text(row, "uuid") == Some(instance.as_str())
                    && text(row, "security_group_uuid") == Some(group.as_str())
            }) else {
                return not_found("rule instance");
            };
            if let Some(state) = text(&body, "state") {
                row["state"] = json!(state);
            }
            match body.get("field_values") {
                Some(Value::Object(values)) => row["field_values"] = Value::Object(values.clone()),
                Some(Value::Null) => row["field_values"] = json!({}),
                _ => {}
            }
            Planned::json(200, row)
        }
        Ms::ScanCreate => {
            let (Some(uri), Some(group)) =
                (text(&body, "model_uri"), text(&body, "security_group_uuid"))
            else {
                return unprocessable("model_uri and security_group_uuid are required");
            };
            data.scans_created += 1;
            let mut scan = fx::scan(
                450 + data.scans_created,
                "PENDING",
                uri,
                text(&body, "scan_origin").unwrap_or("MODEL_SECURITY_API"),
                None,
            );
            scan["security_group_uuid"] = json!(group);
            scan["security_group_name"] = json!(
                find(&data.groups, group)
                    .and_then(|row| text(row, "name"))
                    .unwrap_or_default()
            );
            if let Some(at) = data.stamp() {
                scan["created_at"] = json!(at);
                scan["updated_at"] = json!(at);
            }
            if let Some(labels) = body.get("labels").filter(|labels| labels.is_array()) {
                scan["labels"] = labels.clone();
            }
            data.scans.push(scan.clone());
            Planned::json(200, &scan)
        }
        Ms::LabelsAdd | Ms::LabelsSet | Ms::LabelsDelete => {
            let Some(index) = index_of(&data.scans, &part(1)) else {
                return not_found("scan");
            };
            let scan = &mut data.scans[index];
            let mut labels: Vec<Value> = scan
                .get("labels")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let sent: Vec<Value> = body
                .get("labels")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            match route {
                Ms::LabelsAdd | Ms::LabelsSet => {
                    if sent.is_empty() {
                        return unprocessable("labels must not be empty");
                    }
                    if route == Ms::LabelsSet {
                        labels.clear();
                    }
                    for label in sent {
                        let key = text(&label, "key").unwrap_or_default().to_owned();
                        match labels.iter_mut().find(|row| text(row, "key") == Some(&key)) {
                            Some(row) => *row = label,
                            None => labels.push(label),
                        }
                    }
                }
                _ => {
                    let keys: Vec<&str> = request
                        .query
                        .iter()
                        .filter(|(name, _)| name == "keys")
                        .map(|(_, value)| value.as_str())
                        .collect();
                    labels.retain(|row| !keys.contains(&text(row, "key").unwrap_or_default()));
                }
            }
            scan["labels"] = Value::Array(labels);
            if route == Ms::LabelsDelete {
                Planned::status(204)
            } else {
                Planned::json(200, &json!({}))
            }
        }
        _ => Planned::empty_json(404),
    }
}
