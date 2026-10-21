//! The airs red team target backup (DESIGN §15.18, §15.19, D151, D152): the
//! create-request projection of a target, the one-file
//! format (`airs-cli-rs.redteam-targets` version 1), its strict reader with the
//! TypeScript-backup refusal, and the restore plan with its refusals. Pure: no I/O.

use super::secrets::{REDACTED, VERTEX_AI_IDS, is_mask};
use crate::json::OValue;
use crate::render::join_and;

/// The `format` of a backup file.
pub const FORMAT: &str = "airs-cli-rs.redteam-targets";
/// The newest format version this build writes and reads.
pub const VERSION: u64 = 1;

/// The `TargetCreateRequest` keys, in schema order: what a backup stores per target.
pub const CREATE_KEYS: [&str; 18] = [
    "name",
    "description",
    "target_type",
    "connection_type",
    "api_endpoint_type",
    "response_mode",
    "connection_params",
    "auth_config",
    "auth_type",
    "canonical_id",
    "session_supported",
    "target_metadata",
    "target_background",
    "additional_context",
    "extra_info",
    "network_broker_channel_uuid",
    "adapter_uuid",
    "adapter_variable_overrides",
];

/// The create-request projection of a target as the service returned it (§15.18): the
/// [`CREATE_KEYS`] present and not `null`, nested values as returned;
/// `target_metadata` without `multi_turn_error_message` when `multi_turn` is `false`
/// (TS); each `adapter_variable_overrides` entry as `{key, value, type}`.
pub fn projection(raw: &OValue) -> OValue {
    let mut entries = Vec::new();
    for key in CREATE_KEYS {
        let Some(value) = raw.get(key) else {
            continue;
        };
        if matches!(value, OValue::Null) {
            continue;
        }
        let value = match key {
            "target_metadata" => metadata(value),
            "adapter_variable_overrides" => overrides(value),
            _ => value.clone(),
        };
        entries.push((key.to_owned(), value));
    }
    OValue::Object(entries)
}

fn metadata(value: &OValue) -> OValue {
    match value {
        OValue::Object(entries) if value.get("multi_turn") == Some(&OValue::Bool(false)) => {
            OValue::Object(
                entries
                    .iter()
                    .filter(|(key, _)| key != "multi_turn_error_message")
                    .cloned()
                    .collect(),
            )
        }
        other => other.clone(),
    }
}

fn overrides(value: &OValue) -> OValue {
    match value {
        OValue::Array(items) => OValue::Array(
            items
                .iter()
                .map(|item| match item {
                    OValue::Object(_) => OValue::Object(
                        ["key", "value", "type"]
                            .iter()
                            .filter_map(|key| {
                                item.get(key)
                                    .map(|value| ((*key).to_owned(), value.clone()))
                            })
                            .collect(),
                    ),
                    other => other.clone(),
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The failed-row reason of a projection the create schema refuses (§15.18).
pub const SCHEMA_REASON: &str = "its settings do not match the target create schema";

/// The [`VERTEX_AI_IDS`] of a projection's `target_connection_config` that hold
/// `[REDACTED]` or a server mask, in contract order: the service masked them, and a mask
/// fails their request patterns (§15.24 choice 13).
pub fn masked_vertex_ids(projection: &OValue) -> Vec<&'static str> {
    let config = projection
        .get("connection_params")
        .and_then(|params| params.get("target_connection_config"));
    VERTEX_AI_IDS
        .into_iter()
        .map(|(id, _)| id)
        .filter(|id| {
            config
                .and_then(|config| config.get(id))
                .and_then(OValue::as_str)
                .is_some_and(|text| text == REDACTED || is_mask(text))
        })
        .collect()
}

/// `projection` with each of the `ids` in its `target_connection_config` replaced by the
/// placeholder of [`VERTEX_AI_IDS`], the smallest value of its request pattern.
pub fn with_vertex_placeholders(projection: &OValue, ids: &[&str]) -> OValue {
    let mut filled = projection.clone();
    if let Some(OValue::Object(entries)) = entry_mut(&mut filled, "connection_params")
        .and_then(|params| entry_mut(params, "target_connection_config"))
    {
        for (key, value) in entries.iter_mut() {
            if let Some((_, placeholder)) = VERTEX_AI_IDS
                .iter()
                .find(|(id, _)| id == key && ids.contains(id))
            {
                *value = OValue::String((*placeholder).to_owned());
            }
        }
    }
    filled
}

/// The failed-row reason of a projection that `valid` (the create schema) refuses: the
/// masked Vertex AI identifiers when they alone fail it, that is when the projection
/// passes with each replaced by a value of its pattern; otherwise [`SCHEMA_REASON`]
/// (§15.24 choice 13).
pub fn create_schema_reason(projection: &OValue, valid: impl Fn(&OValue) -> bool) -> String {
    let masked = masked_vertex_ids(projection);
    if masked.is_empty() {
        return SCHEMA_REASON.to_owned();
    }
    if !valid(&with_vertex_placeholders(projection, &masked)) {
        return SCHEMA_REASON.to_owned();
    }
    format!(
        "the service masked its Vertex AI {}, which the target create schema refuses; recreate the target or set its identifiers by hand",
        join_and(&masked)
    )
}

/// The value of `key` in an object.
fn entry_mut<'a>(value: &'a mut OValue, key: &str) -> Option<&'a mut OValue> {
    match value {
        OValue::Object(entries) => entries
            .iter_mut()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value),
        _ => None,
    }
}

/// The restore refusal of a target whose credentials were withheld (§15.19 plan rule 2).
pub const WITHHELD_REASON: &str = "the service withheld its credentials when it was backed up, so it cannot be restored; recreate the target or set its credentials by hand";

/// One stored target.
#[derive(Clone, Debug, PartialEq)]
pub struct Stored {
    pub uuid: String,
    pub name: String,
    /// The service withheld its credentials (`credentialsWithheld`, D157): stored as
    /// returned, masks included, and refused by restore.
    pub credentials_withheld: bool,
    /// The create-request projection.
    pub target: OValue,
}

/// One target that could not be backed up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failed {
    pub uuid: String,
    pub name: String,
    pub error: String,
}

/// A backup file.
#[derive(Clone, Debug, PartialEq)]
pub struct Backup {
    pub exported_at: String,
    pub tenant: String,
    pub tsg_id: String,
    pub targets: Vec<Stored>,
    pub failed: Vec<Failed>,
}

fn text(value: &str) -> OValue {
    OValue::String(value.to_owned())
}

impl Backup {
    /// The document, keys in the §15.18 order.
    pub fn document(&self) -> OValue {
        OValue::Object(vec![
            ("format".into(), text(FORMAT)),
            ("version".into(), OValue::Number(VERSION.into())),
            ("exportedAt".into(), text(&self.exported_at)),
            ("tenant".into(), text(&self.tenant)),
            ("tsgId".into(), text(&self.tsg_id)),
            ("complete".into(), OValue::Bool(self.failed.is_empty())),
            (
                "targets".into(),
                OValue::Array(
                    self.targets
                        .iter()
                        .map(|stored| {
                            OValue::Object(vec![
                                ("uuid".into(), text(&stored.uuid)),
                                ("name".into(), text(&stored.name)),
                                (
                                    "credentialsWithheld".into(),
                                    OValue::Bool(stored.credentials_withheld),
                                ),
                                ("target".into(), stored.target.clone()),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "failed".into(),
                OValue::Array(
                    self.failed
                        .iter()
                        .map(|failed| {
                            OValue::Object(vec![
                                ("uuid".into(), text(&failed.uuid)),
                                ("name".into(), text(&failed.name)),
                                ("error".into(), text(&failed.error)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    /// The file bytes: the 2-space JSON document and one newline.
    pub fn to_text(&self) -> String {
        let mut text = crate::json::to_pretty(&self.document()).unwrap_or_default();
        text.push('\n');
        text
    }
}

/// Why a file is not a restorable airs backup (§15.19; fixed texts, never file
/// content).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadFailure {
    /// Not JSON (the D44 classes included).
    Malformed,
    /// A TypeScript airs-cli backup envelope.
    TypeScript,
    /// The format of a newer version of airs.
    Newer,
    /// Any other schema break, with its reason.
    Invalid(String),
}

/// The keys of the envelope, in order; nothing else is allowed.
const ENVELOPE: [&str; 8] = [
    "format",
    "version",
    "exportedAt",
    "tenant",
    "tsgId",
    "complete",
    "targets",
    "failed",
];

/// Whether text that is not JSON is a TypeScript `--file-format yaml` envelope (js-yaml
/// output): a top-level `resourceType:` line, or `version: '1'` / `version: "1"`.
fn typescript_yaml(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_end();
        line.starts_with("resourceType:") || line == "version: '1'" || line == "version: \"1\""
    })
}

/// Parses a backup file strictly; `valid_target` checks one stored target against the
/// target create schema.
pub fn parse(text: &str, valid_target: impl Fn(&OValue) -> bool) -> Result<Backup, ReadFailure> {
    let document = crate::json::parse(text).map_err(|_| {
        if typescript_yaml(text) {
            ReadFailure::TypeScript
        } else {
            ReadFailure::Malformed
        }
    })?;
    let invalid = |reason: &str| ReadFailure::Invalid(reason.to_owned());
    let OValue::Object(entries) = &document else {
        return Err(invalid("the file does not hold a JSON object"));
    };
    if document.get("resourceType").is_some()
        || matches!(document.get("version"), Some(OValue::String(_)))
    {
        return Err(ReadFailure::TypeScript);
    }
    if document.get("format").and_then(OValue::as_str) != Some(FORMAT) {
        return Err(invalid("it is not an airs red team target backup"));
    }
    let version = match document.get("version") {
        Some(OValue::Number(number)) => number.as_u64(),
        _ => None,
    };
    match version {
        Some(VERSION) => {}
        Some(version) if version > VERSION => return Err(ReadFailure::Newer),
        _ => return Err(invalid("version must be 1")),
    }
    if let Some((key, _)) = entries
        .iter()
        .find(|(key, _)| !ENVELOPE.contains(&key.as_str()))
    {
        let _ = key;
        return Err(invalid("the envelope has an unknown key"));
    }
    let string = |key: &str| -> Result<String, ReadFailure> {
        document
            .get(key)
            .and_then(OValue::as_str)
            .map(str::to_owned)
            .ok_or_else(|| ReadFailure::Invalid(format!("{key} must be a string")))
    };
    let exported_at = string("exportedAt")?;
    let tenant = string("tenant")?;
    let tsg_id = string("tsgId")?;
    let Some(OValue::Bool(complete)) = document.get("complete") else {
        return Err(invalid("complete must be true or false"));
    };
    let Some(OValue::Array(targets)) = document.get("targets") else {
        return Err(invalid("targets must be an array"));
    };
    let Some(OValue::Array(failed)) = document.get("failed") else {
        return Err(invalid("failed must be an array"));
    };
    let entry = |value: &OValue, keys: &[&str], index: usize, list: &str| {
        let OValue::Object(fields) = value else {
            return Err(ReadFailure::Invalid(format!(
                "{list}[{index}] must be an object"
            )));
        };
        if fields.len() != keys.len()
            || keys.iter().any(|key| value.get(key).is_none())
            || fields.iter().any(|(key, _)| !keys.contains(&key.as_str()))
        {
            return Err(ReadFailure::Invalid(format!(
                "{list}[{index}] must have exactly the keys {}",
                keys.join(", ")
            )));
        }
        Ok(())
    };
    let mut stored = Vec::with_capacity(targets.len());
    for (index, value) in targets.iter().enumerate() {
        entry(
            value,
            &["uuid", "name", "credentialsWithheld", "target"],
            index,
            "targets",
        )?;
        let (Some(uuid), Some(name)) = (
            value.get("uuid").and_then(OValue::as_str),
            value.get("name").and_then(OValue::as_str),
        ) else {
            return Err(ReadFailure::Invalid(format!(
                "targets[{index}] uuid and name must be strings"
            )));
        };
        let target = value.get("target").cloned().unwrap_or(OValue::Null);
        if name.is_empty() || target.get("name").and_then(OValue::as_str) != Some(name) {
            return Err(ReadFailure::Invalid(format!(
                "targets[{index}] name must be the target's name"
            )));
        }
        let Some(OValue::Bool(credentials_withheld)) = value.get("credentialsWithheld") else {
            return Err(ReadFailure::Invalid(format!(
                "targets[{index}] credentialsWithheld must be true or false"
            )));
        };
        if !valid_target(&target) {
            return Err(ReadFailure::Invalid(format!(
                "targets[{index}] does not match the target create schema"
            )));
        }
        stored.push(Stored {
            uuid: uuid.to_owned(),
            name: name.to_owned(),
            credentials_withheld: *credentials_withheld,
            target,
        });
    }
    let mut failures = Vec::with_capacity(failed.len());
    for (index, value) in failed.iter().enumerate() {
        entry(value, &["uuid", "name", "error"], index, "failed")?;
        let field = |key: &str| value.get(key).and_then(OValue::as_str).map(str::to_owned);
        let (Some(uuid), Some(name), Some(error)) = (field("uuid"), field("name"), field("error"))
        else {
            return Err(ReadFailure::Invalid(format!(
                "failed[{index}] uuid, name and error must be strings"
            )));
        };
        failures.push(Failed { uuid, name, error });
    }
    if *complete != failures.is_empty() {
        return Err(invalid("complete does not match the failed list"));
    }
    Ok(Backup {
        exported_at,
        tenant,
        tsg_id,
        targets: stored,
        failed: failures,
    })
}

/// What restore does with one backup target (§15.19 "Plan").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Planned {
    /// Rules 1–3: a refusal with its fixed reason.
    Failed(String),
    /// Rule 4 without `--overwrite`: the existing target's id.
    Skip(String),
    /// Rule 4 with `--overwrite`: the existing target's id.
    Update(String),
    /// Rule 5.
    Create,
}

/// The plan rows in file order: `(name, existing)` of the tenant's targets, and
/// `withheld` telling whether a stored target lacks its credentials. Rule 2 refuses a
/// target marked `credentialsWithheld` and one whose credentials `withheld` finds
/// missing, whatever the marker says.
pub fn plan(
    backup: &Backup,
    tenant_targets: &[(String, String)],
    overwrite: bool,
    withheld: impl Fn(&OValue) -> bool,
) -> Vec<Planned> {
    backup
        .targets
        .iter()
        .map(|stored| {
            let name = &stored.name;
            let shown = crate::output::terminal_safe(name);
            if backup
                .targets
                .iter()
                .filter(|other| other.name == *name)
                .count()
                > 1
            {
                return Planned::Failed(format!(
                    "the backup holds more than one target named {shown}"
                ));
            }
            if stored.credentials_withheld || withheld(&stored.target) {
                return Planned::Failed(WITHHELD_REASON.to_owned());
            }
            let existing: Vec<&String> = tenant_targets
                .iter()
                .filter(|(other, _)| other == name)
                .map(|(_, uuid)| uuid)
                .collect();
            match existing.as_slice() {
                [] => Planned::Create,
                [uuid] if overwrite => Planned::Update((*uuid).clone()),
                [uuid] => Planned::Skip((*uuid).clone()),
                _ => Planned::Failed(format!("more than one target named {shown} exists")),
            }
        })
        .collect()
}

/// TS's routing defaults of a create (`connection_type` `CUSTOM`, `api_endpoint_type`
/// `PUBLIC`, `response_mode` `REST`), or of an update (`target_type`, then those three
/// taken from `current` first, TS `prepareTargetPayload`).
pub fn with_routing(stored: &OValue, current: Option<&OValue>) -> OValue {
    let mut entries = stored.as_object().unwrap_or_default().to_vec();
    let fields: &[(&str, Option<&str>)] = &[
        ("target_type", None),
        ("connection_type", Some("CUSTOM")),
        ("api_endpoint_type", Some("PUBLIC")),
        ("response_mode", Some("REST")),
    ];
    for (key, default) in fields {
        let missing = !entries.iter().any(|(name, value)| {
            name == key && matches!(value, OValue::String(text) if !text.is_empty())
        });
        if !missing {
            continue;
        }
        let value = current
            .and_then(|current| current.get(key))
            .filter(|value| matches!(value, OValue::String(text) if !text.is_empty()))
            .cloned()
            .or_else(|| default.map(text));
        if let Some(value) = value {
            match entries.iter_mut().find(|(name, _)| name == key) {
                Some((_, slot)) => *slot = value,
                None => entries.push(((*key).to_owned(), value)),
            }
        }
    }
    OValue::Object(entries)
}

/// The UTC stamp of a backup file name: `yyyymmddThhmmssZ` from an ISO time.
pub fn stamp(iso: &str) -> String {
    let mut out: String = iso
        .chars()
        .take(19)
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    out.push('Z');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse as json;

    fn backup(targets: &[(&str, &str)]) -> Backup {
        Backup {
            exported_at: "2026-10-17T12:00:00.000Z".into(),
            tenant: "prod".into(),
            tsg_id: "100".into(),
            targets: targets
                .iter()
                .map(|(uuid, name)| Stored {
                    uuid: (*uuid).into(),
                    name: (*name).into(),
                    credentials_withheld: false,
                    target: json(&format!(
                        r#"{{"name": "{name}", "target_type": "APPLICATION"}}"#
                    ))
                    .unwrap(),
                })
                .collect(),
            failed: Vec::new(),
        }
    }

    #[test]
    fn the_projection_keeps_the_create_keys_in_schema_order() {
        let raw = json(
            r#"{"uuid": "u", "status": "ACTIVE", "auth_type": "HEADERS", "name": "t",
                "target_metadata": {"multi_turn": false, "multi_turn_error_message": "noise", "rate_limit": 5},
                "adapter_variable_overrides": [{"type": "SECRET", "value": "s", "key": "k", "is_redacted": false}],
                "description": null, "canonical_id": "c", "created_at": "x"}"#,
        )
        .unwrap();
        assert_eq!(
            crate::json::to_compact(&projection(&raw)).unwrap(),
            r#"{"name":"t","auth_type":"HEADERS","canonical_id":"c","target_metadata":{"multi_turn":false,"rate_limit":5},"adapter_variable_overrides":[{"key":"k","value":"s","type":"SECRET"}]}"#
        );
    }

    #[test]
    fn a_written_backup_reads_back() {
        let mut written = backup(&[("u1", "one"), ("u2", "two")]);
        written.targets[1].credentials_withheld = true;
        written.failed.push(Failed {
            uuid: "u3".into(),
            name: "three".into(),
            error: "AISEC_SDK_ERROR:x".into(),
        });
        let text = written.to_text();
        assert!(
            text.starts_with(
                "{\n  \"format\": \"airs-cli-rs.redteam-targets\",\n  \"version\": 1,\n"
            )
        );
        assert!(text.contains("\"complete\": false"));
        assert!(text.contains(
            "\"name\": \"two\",\n      \"credentialsWithheld\": true,\n      \"target\": {"
        ));
        assert_eq!(parse(&text, |_| true).unwrap(), written);
    }

    #[test]
    fn foreign_and_broken_files_are_refused_with_fixed_reasons() {
        let refused = |text: &str| parse(text, |_| true).unwrap_err();
        assert_eq!(refused("{"), ReadFailure::Malformed);
        assert_eq!(refused(r#"{"a": "\ud800"}"#), ReadFailure::Malformed);
        assert_eq!(
            refused(r#"{"version": "1", "resourceType": "redteam-target", "data": {}}"#),
            ReadFailure::TypeScript
        );
        assert_eq!(refused(r#"{"version": "1"}"#), ReadFailure::TypeScript);
        // A TypeScript `--file-format yaml` backup (js-yaml output) is refused the same way.
        assert_eq!(
            refused(
                "version: '1'\nresourceType: redteam-target\nexportedAt: '2026-10-17T12:00:00.000Z'\ndata:\n  name: t\n"
            ),
            ReadFailure::TypeScript
        );
        assert_eq!(
            refused("version: \"1\"\nresourceType: redteam-target\n"),
            ReadFailure::TypeScript
        );
        assert_eq!(
            refused("name: t\n  resourceType: x\n"),
            ReadFailure::Malformed
        );
        let newer = backup(&[])
            .to_text()
            .replace("\"version\": 1", "\"version\": 2");
        assert_eq!(refused(&newer), ReadFailure::Newer);
        let extra = backup(&[]).to_text().replacen('{', "{\"extra\": 1,", 1);
        assert!(matches!(refused(&extra), ReadFailure::Invalid(_)));
        let lying = backup(&[])
            .to_text()
            .replace("\"complete\": true", "\"complete\": false");
        assert!(matches!(refused(&lying), ReadFailure::Invalid(_)));
        let text = backup(&[("u1", "one")]).to_text();
        assert_eq!(
            parse(&text, |_| false).unwrap_err(),
            ReadFailure::Invalid("targets[0] does not match the target create schema".into())
        );
        let renamed = text.replace(
            "\"name\": \"one\",\n      \"credentialsWithheld\"",
            "\"name\": \"other\",\n      \"credentialsWithheld\"",
        );
        assert!(matches!(
            parse(&renamed, |_| true),
            Err(ReadFailure::Invalid(_))
        ));
        assert!(matches!(refused("[]"), ReadFailure::Invalid(_)));
        // The marker is required and must be a boolean.
        let unmarked = text.replace("      \"credentialsWithheld\": false,\n", "");
        assert_eq!(
            parse(&unmarked, |_| true).unwrap_err(),
            ReadFailure::Invalid(
                "targets[0] must have exactly the keys uuid, name, credentialsWithheld, target"
                    .into()
            )
        );
        let textual = text.replace(
            "\"credentialsWithheld\": false",
            "\"credentialsWithheld\": \"no\"",
        );
        assert_eq!(
            parse(&textual, |_| true).unwrap_err(),
            ReadFailure::Invalid("targets[0] credentialsWithheld must be true or false".into())
        );
    }

    #[test]
    fn the_plan_applies_the_first_rule_that_matches() {
        let mut file = backup(&[
            ("u1", "dup"),
            ("u2", "dup"),
            ("u3", "secret"),
            ("u4", "two"),
            ("u5", "one"),
            ("u6", "new"),
            ("u7", "marked"),
        ]);
        file.targets[6].credentials_withheld = true;
        let tenant = [
            ("two".to_owned(), "t1".to_owned()),
            ("two".to_owned(), "t2".to_owned()),
            ("one".to_owned(), "t3".to_owned()),
        ];
        let withheld =
            |target: &OValue| target.get("name").and_then(OValue::as_str) == Some("secret");
        let rows = plan(&file, &tenant, false, withheld);
        assert_eq!(
            rows,
            [
                Planned::Failed("the backup holds more than one target named dup".into()),
                Planned::Failed("the backup holds more than one target named dup".into()),
                Planned::Failed(WITHHELD_REASON.into()),
                Planned::Failed("more than one target named two exists".into()),
                Planned::Skip("t3".into()),
                Planned::Create,
                // Marked by the backup: refused although nothing is detected now.
                Planned::Failed(WITHHELD_REASON.into()),
            ]
        );
        assert_eq!(
            plan(&file, &tenant, true, withheld)[4],
            Planned::Update("t3".into())
        );
    }

    #[test]
    fn routing_defaults_fill_only_what_is_missing() {
        let stored =
            json(r#"{"name": "t", "target_type": "MODEL", "response_mode": "STREAMING"}"#).unwrap();
        assert_eq!(
            crate::json::to_compact(&with_routing(&stored, None)).unwrap(),
            r#"{"name":"t","target_type":"MODEL","response_mode":"STREAMING","connection_type":"CUSTOM","api_endpoint_type":"PUBLIC"}"#
        );
        let bare = json(r#"{"name": "t"}"#).unwrap();
        let current = json(r#"{"target_type": "AGENT", "connection_type": "OPENAI"}"#).unwrap();
        assert_eq!(
            crate::json::to_compact(&with_routing(&bare, Some(&current))).unwrap(),
            r#"{"name":"t","target_type":"AGENT","connection_type":"OPENAI","api_endpoint_type":"PUBLIC","response_mode":"REST"}"#
        );
        assert_eq!(stamp("2026-10-17T12:03:04.567Z"), "20261017T120304Z");
    }

    /// §15.24 choice 13: the reason names the masked identifiers (`[REDACTED]` or four or
    /// more `*`, contract order) only when they alone fail the create schema.
    #[test]
    fn a_masked_vertex_projection_names_its_masked_identifiers() {
        let config = |fields: &str| {
            json(&format!(
                r#"{{"name":"t","connection_params":{{"target_connection_config":{{{fields},"customer_sa_email":"****"}}}}}}"#
            ))
            .unwrap()
        };
        // The real create schema, as the backup checks it.
        let valid = |projection: &OValue| {
            serde_json::to_value(projection).is_ok_and(|wire| {
                scm::airs::red_team::models::TargetCreateRequest::parse(
                    wire,
                    scm::validation::Mode::Request,
                )
                .is_ok()
            })
        };
        let reason = |names: &str| {
            format!(
                "the service masked its Vertex AI {names}, which the target create schema refuses; recreate the target or set its identifiers by hand"
            )
        };
        for (fields, expected) in [
            (
                r#""project_id":"Bad_Project","location":"us-central1","engine_id":"1""#,
                SCHEMA_REASON.to_owned(),
            ),
            (
                r#""engine_id":"1","project_id":"****","location":"us-central1""#,
                reason("project_id"),
            ),
            (
                r#""project_id":"p","location":"[REDACTED]","engine_id":"******""#,
                reason("location and engine_id"),
            ),
            (
                r#""engine_id":"****","location":"****","project_id":"****""#,
                reason("project_id, location and engine_id"),
            ),
            // A mask beside another failure: the masks are not the whole cause.
            (
                r#""project_id":"****","location":"US Central","engine_id":"1""#,
                SCHEMA_REASON.to_owned(),
            ),
        ] {
            assert_eq!(
                create_schema_reason(&config(fields), valid),
                expected,
                "{fields}"
            );
        }
        let mut nameless = config(r#""project_id":"****","location":"l","engine_id":"1""#);
        if let OValue::Object(entries) = &mut nameless {
            entries.retain(|(key, _)| key != "name");
        }
        assert_eq!(create_schema_reason(&nameless, valid), SCHEMA_REASON);
        assert_eq!(
            masked_vertex_ids(&json(r#"{"connection_params":{}}"#).unwrap()),
            Vec::<&str>::new()
        );
    }
}
