//! Profile and topic JSON projections (DESIGN §7.5), their pretty layouts and tables
//! (§7.6), and revision selection (§7.2).
//!
//! Projections are ordered `Serialize` structs: field order is the printed key order,
//! unset fields are omitted and fields outside the projection (`csp_id`, `tsg_id`,
//! unknown top-level keys) are dropped. Revisions compare numerically, like the
//! JavaScript numbers the TypeScript CLI compares.

use crate::error::CliError;
use crate::json::{self, OValue};
use crate::output::{Format, Output, terminal_safe};
use crate::render::style::Style;
use crate::render::{cell_text, js_json_number, pretty, table, utf16_prefix};
use scm::airs::management::models::{CustomTopic, FiniteNumber, Policy, SecurityProfile};
use serde::Serialize;

/// `{profileId, profileName, revision, active, createdBy, updatedBy, lastModifiedTs, policy,
/// dlpTenantId}` (`dlpTenantId` from 8.0, TS 7.3.0, only when the record carries
/// `dlp_tenant_id`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<&'a str>,
    pub profile_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<&'a FiniteNumber>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified_ts: Option<&'a str>,
    /// The policy as TypeScript SDK 0.35.0 prints it ([`printed_policy`]): schema-ordered
    /// keys, then sorted unknown keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<OValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dlp_tenant_id: Option<&'a str>,
}

impl<'a> ProfileView<'a> {
    pub fn new(profile: &'a SecurityProfile) -> Result<Self, CliError> {
        Ok(Self {
            profile_id: profile
                .profile_id
                .as_ref()
                .into_option()
                .map(String::as_str),
            profile_name: &profile.profile_name,
            revision: profile.revision.as_ref().into_option(),
            active: profile.active.as_ref().into_option().copied(),
            created_by: profile
                .created_by
                .as_ref()
                .into_option()
                .map(String::as_str),
            updated_by: profile
                .updated_by
                .as_ref()
                .into_option()
                .map(String::as_str),
            last_modified_ts: profile
                .last_modified_ts
                .as_ref()
                .into_option()
                .map(String::as_str),
            policy: profile
                .policy
                .as_ref()
                .into_option()
                .map(printed_policy)
                .transpose()?,
            dlp_tenant_id: profile
                .dlp_tenant_id
                .as_ref()
                .into_option()
                .map(String::as_str),
        })
    }
}

/// The key order of an AI entry in TypeScript SDK 0.35.0's `AiSecurityProfileSchema`.
const AI_ENTRY_ORDER: [&str; 5] = [
    "model-type",
    "content-type",
    "content-type-mode",
    "content-type-configurations",
    "model-configuration",
];

/// The key order of TypeScript SDK 0.35.0's `ModelConfigurationSchema`
/// (`ContentTypeConfigurationSchema.extend(...)`: the protections first, then the shared
/// settings).
const MODEL_CONFIGURATION_ORDER: [&str; 7] = [
    "data-protection",
    "app-protection",
    "model-protection",
    "agent-protection",
    "mask-data-in-storage",
    "latency",
    "enable-full-conversation-inspection",
];

/// Move the `order` keys to the front, in that order; the rest keep theirs.
fn reorder(fields: &mut Vec<(String, OValue)>, order: &[&str]) {
    let mut front = Vec::with_capacity(fields.len());
    for key in order {
        if let Some(at) = fields.iter().position(|(name, _)| name == key) {
            front.push(fields.remove(at));
        }
    }
    front.append(fields);
    *fields = front;
}

/// A policy in the key order TypeScript 7.3.0 prints (SDK 0.35.0 schema order, §13.17):
/// scm-sdk 0.2.4 keeps its 0.34.0 field order for the AI entry and `model-configuration`,
/// so those two objects are reordered; everything else is the SDK's serialisation (D35).
pub fn printed_policy(policy: &Policy) -> Result<OValue, CliError> {
    let mut value = ordered(policy)?;
    let OValue::Object(fields) = &mut value else {
        return Ok(value);
    };
    for (key, entries) in fields.iter_mut() {
        let (true, OValue::Array(entries)) = (key == "ai-security-profiles", entries) else {
            continue;
        };
        for entry in entries {
            let OValue::Object(entry) = entry else {
                continue;
            };
            reorder(entry, &AI_ENTRY_ORDER);
            for (name, config) in entry.iter_mut() {
                if let (true, OValue::Object(config)) = (name == "model-configuration", config) {
                    reorder(config, &MODEL_CONFIGURATION_ORDER);
                }
            }
        }
    }
    Ok(value)
}

/// `{topicId, topicName, revision, active, description, examples, createdBy, updatedBy,
/// lastModifiedTs, createdTs}`; `examples` is `[]` when the service omits it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicView<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic_id: Option<&'a str>,
    pub topic_name: &'a str,
    pub revision: &'a FiniteNumber,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    pub description: &'a str,
    pub examples: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified_ts: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_ts: Option<&'a str>,
}

impl<'a> From<&'a CustomTopic> for TopicView<'a> {
    fn from(topic: &'a CustomTopic) -> Self {
        let text = |value: &'a scm::data::Optional<String>| {
            value.as_ref().into_option().map(String::as_str)
        };
        Self {
            topic_id: text(&topic.topic_id),
            topic_name: &topic.topic_name,
            revision: &topic.revision,
            active: topic.active.as_ref().into_option().copied(),
            description: &topic.description,
            examples: topic
                .examples
                .as_ref()
                .into_option()
                .map_or(&[], Vec::as_slice),
            created_by: text(&topic.created_by),
            updated_by: text(&topic.updated_by),
            last_modified_ts: text(&topic.last_modified_ts),
            created_ts: text(&topic.created_ts),
        }
    }
}

pub fn profile_views(profiles: &[SecurityProfile]) -> Result<Vec<ProfileView<'_>>, CliError> {
    profiles.iter().map(ProfileView::new).collect()
}

pub fn topic_views(topics: &[CustomTopic]) -> Vec<TopicView<'_>> {
    topics.iter().map(TopicView::from).collect()
}

/// The banner every pretty management layout starts with (§7.6).
pub(crate) fn runtime_banner(out: &mut Output) {
    pretty::banner(
        out,
        "Prisma AIRS — Runtime Configuration",
        Some("Security profile and topic management"),
    );
}

fn serialization_failed() -> CliError {
    CliError::operational("AISEC_SDK_ERROR:Output could not be serialized as JSON")
}

/// A projection as an ordered JSON object (numbers kept as serialised).
fn ordered<T: Serialize>(view: &T) -> Result<OValue, CliError> {
    json::to_ordered(view).map_err(|_| serialization_failed())
}

/// Table rows: `columns` (JSON keys) of each record, as cell texts.
fn table_rows<T: Serialize>(views: &[T], columns: &[&str]) -> Result<Vec<Vec<String>>, CliError> {
    views
        .iter()
        .map(|view| {
            let value = ordered(view)?;
            Ok(columns
                .iter()
                .map(|key| cell_text(value.get(key)))
                .collect())
        })
        .collect()
}

/// A detail table: every key of `keys` (unset keys are empty rows).
fn detail_table<T: Serialize>(view: &T, keys: &[&str]) -> Result<String, CliError> {
    let value = ordered(view)?;
    Ok(table::key_value_table(
        keys.iter()
            .map(|key| ((*key).to_owned(), cell_text(value.get(key))))
            .collect(),
    ))
}

/// A list table followed by its newline, or nothing for an empty list (§2.7).
fn emit_list_table(out: &mut Output, labels: &[&str], rows: &[Vec<String>]) {
    let text = table::table(labels, rows);
    if !text.is_empty() {
        out.data_line(&text);
    }
}

/// The dim ID line of a pretty list (data, D55); omitted without an ID (D56).
fn id_line(out: &mut Output, id: Option<&str>) {
    if let Some(id) = id {
        let id = out.paint(Style::Dim, &terminal_safe(id));
        out.data_line(&format!("  {id}"));
    }
}

fn revision_text(revision: &FiniteNumber) -> String {
    js_json_number(revision.as_number())
}

/// `active` / `inactive` (TS truthiness: absent is inactive), green / yellow.
fn status_word(out: &Output, active: Option<bool>) -> String {
    if active == Some(true) {
        out.paint(Style::Green, "active")
    } else {
        out.paint(Style::Yellow, "inactive")
    }
}

const PROFILE_LIST_KEYS: [&str; 4] = ["profileId", "profileName", "active", "revision"];
const PROFILE_LIST_LABELS: [&str; 4] = ["ID", "Name", "Active", "Revision"];
const PROFILE_DETAIL_KEYS: [&str; 8] = [
    "profileId",
    "profileName",
    "revision",
    "active",
    "createdBy",
    "updatedBy",
    "lastModifiedTs",
    "policy",
];

/// `profiles list` (and `profiles get --all-versions`) in `format` (§7.5, §7.6).
pub fn render_profile_list(
    out: &mut Output,
    profiles: &[SecurityProfile],
    format: Format,
) -> Result<(), CliError> {
    let views = profile_views(profiles)?;
    match format {
        Format::Json => out.json(&views),
        Format::Table => {
            let rows = table_rows(&views, &PROFILE_LIST_KEYS)?;
            emit_list_table(out, &PROFILE_LIST_LABELS, &rows);
            Ok(())
        }
        Format::Pretty => {
            runtime_banner(out);
            if views.is_empty() {
                pretty::empty_list(out, "profiles");
                return Ok(());
            }
            pretty::section(out, "Security Profiles:");
            for view in &views {
                id_line(out, view.profile_id);
                let status = status_word(out, view.active);
                let revision = view.revision.map_or_else(String::new, |revision| {
                    out.paint(Style::Dim, &format!(" rev:{}", revision_text(revision)))
                });
                out.data_line(&format!(
                    "    {}  {status}{revision}",
                    terminal_safe(view.profile_name)
                ));
            }
            out.data("\n");
            Ok(())
        }
    }
}

/// The pretty `Policy` value: `JSON.stringify(policy, null, 2)` with every line break
/// followed by two spaces (TS), each line terminal-safe (§7.6).
fn policy_block(policy: &OValue) -> Result<String, CliError> {
    let text = json::to_pretty(policy).map_err(|_| serialization_failed())?;
    Ok(text
        .split('\n')
        .map(|line| terminal_safe(line).into_owned())
        .collect::<Vec<_>>()
        .join("\n  "))
}

/// The `Protection locations` value (TS 7.3.0, §13.17): every active protection block as
/// `AI[<i>] <model-type> / <direction|legacy>`, joined by `, `; `None` when there is none.
fn protection_locations(policy: &OValue) -> Result<Option<String>, CliError> {
    let value = crate::json::value_of(policy);
    let labels: Vec<String> = crate::profile_policy::locations(Some(&value))
        .iter()
        .filter(|location| location.active)
        .map(|location| {
            terminal_safe(&crate::profile_policy::location_label(location)).into_owned()
        })
        .collect();
    Ok((!labels.is_empty()).then(|| labels.join(", ")))
}

/// A non-empty text value (TS truthiness), terminal-safe.
fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .filter(|text| !text.is_empty())
        .map(|text| terminal_safe(text).into_owned())
}

/// `profiles get` in `format` (§7.5, §7.6).
pub fn render_profile_detail(
    out: &mut Output,
    profile: &SecurityProfile,
    format: Format,
) -> Result<(), CliError> {
    render_profile(out, profile, format, true)
}

/// The response of `profiles create|update` in `format`: the detail forms without the
/// runtime banner in pretty (TS 7.3.0 `emitDetail`, §13.17).
pub fn render_written_profile(
    out: &mut Output,
    profile: &SecurityProfile,
    format: Format,
) -> Result<(), CliError> {
    render_profile(out, profile, format, false)
}

fn render_profile(
    out: &mut Output,
    profile: &SecurityProfile,
    format: Format,
    banner: bool,
) -> Result<(), CliError> {
    let view = ProfileView::new(profile)?;
    match format {
        Format::Json => out.json(&view),
        Format::Table => {
            let mut keys = PROFILE_DETAIL_KEYS.to_vec();
            if view.dlp_tenant_id.is_some() {
                keys.push("dlpTenantId");
            }
            let text = detail_table(&view, &keys)?;
            out.data_line(&text);
            Ok(())
        }
        Format::Pretty => {
            if banner {
                runtime_banner(out);
            }
            pretty::section(out, "Profile Detail:");
            let mut pairs = vec![
                (
                    "ID",
                    terminal_safe(view.profile_id.unwrap_or("")).into_owned(),
                ),
                ("Name", terminal_safe(view.profile_name).into_owned()),
                ("Status", status_word(out, view.active)),
            ];
            if let Some(tenant) = view.dlp_tenant_id {
                pairs.push(("DLP tenant", terminal_safe(tenant).into_owned()));
            }
            if let Some(revision) = view.revision {
                pairs.push(("Revision", revision_text(revision)));
            }
            for (key, value) in [
                ("Created", view.created_by),
                ("Updated", view.updated_by),
                ("Modified", view.last_modified_ts),
            ] {
                if let Some(value) = non_empty(value) {
                    pairs.push((key, value));
                }
            }
            if let Some(policy) = &view.policy {
                if let Some(locations) = protection_locations(policy)? {
                    pairs.push(("Protection locations", locations));
                }
                pairs.push(("Policy", policy_block(policy)?));
            }
            pretty::key_value(out, &pairs);
            out.data("\n");
            Ok(())
        }
    }
}

const TOPIC_LIST_KEYS: [&str; 4] = ["topicId", "topicName", "revision", "description"];
const TOPIC_LIST_LABELS: [&str; 4] = ["ID", "Name", "Revision", "Description"];
const TOPIC_DETAIL_KEYS: [&str; 10] = [
    "topicId",
    "topicName",
    "revision",
    "active",
    "description",
    "examples",
    "createdBy",
    "updatedBy",
    "lastModifiedTs",
    "createdTs",
];
/// The pretty topic-list description preview, in UTF-16 code units (no ellipsis).
const DESCRIPTION_PREVIEW_UNITS: usize = 80;

/// `topics list` (and `topics get --all-versions`) in `format` (§7.5, §7.6).
pub fn render_topic_list(
    out: &mut Output,
    topics: &[CustomTopic],
    format: Format,
) -> Result<(), CliError> {
    let views = topic_views(topics);
    match format {
        Format::Json => out.json(&views),
        Format::Table => {
            let rows = table_rows(&views, &TOPIC_LIST_KEYS)?;
            emit_list_table(out, &TOPIC_LIST_LABELS, &rows);
            Ok(())
        }
        Format::Pretty => {
            runtime_banner(out);
            if views.is_empty() {
                pretty::empty_list(out, "topics");
                return Ok(());
            }
            pretty::section(out, "Custom Topics:");
            for view in &views {
                id_line(out, view.topic_id);
                let revision = out.paint(
                    Style::Dim,
                    &format!(" rev:{}", revision_text(view.revision)),
                );
                let description = if view.description.is_empty() {
                    String::new()
                } else {
                    // D54: a character straddling the cut is dropped; no ellipsis.
                    let (preview, _) = utf16_prefix(view.description, DESCRIPTION_PREVIEW_UNITS);
                    out.paint(Style::Dim, &format!(" — {}", terminal_safe(preview)))
                };
                out.data_line(&format!(
                    "    {}{revision}{description}",
                    terminal_safe(view.topic_name)
                ));
            }
            out.data("\n");
            Ok(())
        }
    }
}

/// `topics get` in `format` (§7.5, §7.6).
pub fn render_topic_detail(
    out: &mut Output,
    topic: &CustomTopic,
    format: Format,
) -> Result<(), CliError> {
    let view = TopicView::from(topic);
    match format {
        Format::Json => out.json(&view),
        Format::Table => {
            let text = detail_table(&view, &TOPIC_DETAIL_KEYS)?;
            out.data_line(&text);
            Ok(())
        }
        Format::Pretty => {
            runtime_banner(out);
            pretty::section(out, "Topic Detail:");
            let mut pairs = vec![
                (
                    "ID",
                    terminal_safe(view.topic_id.unwrap_or("")).into_owned(),
                ),
                ("Name", terminal_safe(view.topic_name).into_owned()),
                ("Revision", revision_text(view.revision)),
            ];
            if let Some(description) = non_empty(Some(view.description)) {
                pairs.push(("Description", description));
            }
            pretty::key_value(out, &pairs);
            if !view.examples.is_empty() {
                out.data_line("  Examples:");
                for example in view.examples {
                    pretty::bullet(out, &terminal_safe(example), pretty::Bullet::Neutral);
                }
            }
            let meta: Vec<(&str, String)> = [
                ("Created", view.created_by),
                ("Updated", view.updated_by),
                ("Modified", view.last_modified_ts),
            ]
            .into_iter()
            .filter_map(|(key, value)| non_empty(value).map(|value| (key, value)))
            .collect();
            if !meta.is_empty() {
                pretty::key_value(out, &meta);
            }
            out.data("\n");
            Ok(())
        }
    }
}

/// A server id that is present and non-empty (TS truthiness: an empty id counts as
/// missing, D115).
pub fn non_empty_id(id: Option<&String>) -> Option<&str> {
    id.map(String::as_str).filter(|id| !id.is_empty())
}

/// An M4 outcome record (DESIGN §13.2): `json` prints the record, `table` its
/// `Key │ Value` table (one row per key in record order, §8.6 convention) and `pretty`
/// the key/value block of `pairs` (data, values terminal-safe).
pub fn render_record<T: Serialize>(
    out: &mut Output,
    record: &T,
    pairs: &[(&str, String)],
    format: Format,
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(record),
        Format::Table => {
            let value = ordered(record)?;
            let rows = value
                .as_object()
                .unwrap_or_default()
                .iter()
                .map(|(key, value)| (key.clone(), cell_text(Some(value))))
                .collect();
            out.data_line(&table::key_value_table(rows));
            Ok(())
        }
        Format::Pretty => {
            pretty::key_value(out, pairs);
            Ok(())
        }
    }
}

/// A management record that has revisions (profiles and topics).
pub trait Revisioned {
    fn id(&self) -> Option<&str>;
    fn name(&self) -> &str;
    /// `None` when the service omitted it (profiles only).
    fn revision(&self) -> Option<&FiniteNumber>;
}

impl Revisioned for SecurityProfile {
    fn id(&self) -> Option<&str> {
        self.profile_id.as_ref().into_option().map(String::as_str)
    }
    fn name(&self) -> &str {
        &self.profile_name
    }
    fn revision(&self) -> Option<&FiniteNumber> {
        self.revision.as_ref().into_option()
    }
}

impl Revisioned for CustomTopic {
    fn id(&self) -> Option<&str> {
        self.topic_id.as_ref().into_option().map(String::as_str)
    }
    fn name(&self) -> &str {
        &self.topic_name
    }
    fn revision(&self) -> Option<&FiniteNumber> {
        Some(&self.revision)
    }
}

/// The revision as a JavaScript number; unset counts as 0.
pub fn revision_value<T: Revisioned>(row: &T) -> f64 {
    row.revision().and_then(FiniteNumber::as_f64).unwrap_or(0.0)
}

/// `revision === wanted`; an unset revision matches nothing.
pub fn revision_is<T: Revisioned>(row: &T, wanted: u64) -> bool {
    row.revision()
        .is_some_and(|revision| match revision.as_u64() {
            Some(exact) => exact == wanted,
            // Converting a safe integer (≤ 2^53, enforced by flag parsing) is exact.
            None => revision.as_f64() == Some(wanted as f64),
        })
}

/// Whether a row is the one a `get` names: exact id for a UUID, else exact name.
pub fn is_named<T: Revisioned>(row: &T, value: &str, by_id: bool) -> bool {
    if by_id {
        row.id() == Some(value)
    } else {
        row.name() == value
    }
}

/// Rows for a `get` with `--revision` and/or `--all-versions`, in API order.
pub fn matching_versions<T: Revisioned>(
    rows: Vec<T>,
    value: &str,
    by_id: bool,
    revision: Option<u64>,
) -> Vec<T> {
    rows.into_iter()
        .filter(|row| is_named(row, value, by_id))
        .filter(|row| revision.is_none_or(|wanted| revision_is(row, wanted)))
        .collect()
}

/// The highest revision per name, in first-seen name order; ties keep the first row.
pub fn latest_per_name<T: Revisioned>(rows: Vec<T>) -> Vec<T> {
    let mut positions = std::collections::HashMap::<String, usize>::new();
    let mut latest: Vec<T> = Vec::new();
    for row in rows {
        match positions.get(row.name()) {
            Some(&index) => {
                if revision_value(&row) > revision_value(&latest[index]) {
                    latest[index] = row;
                }
            }
            None => {
                positions.insert(row.name().to_owned(), latest.len());
                latest.push(row);
            }
        }
    }
    latest
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(value: serde_json::Value) -> SecurityProfile {
        serde_json::from_value(value).unwrap()
    }

    fn topic(value: serde_json::Value) -> CustomTopic {
        serde_json::from_value(value).unwrap()
    }

    fn topic_rev(name: &str, revision: serde_json::Value, id: &str) -> CustomTopic {
        topic(json!({"topic_id": id, "topic_name": name, "revision": revision, "description": "d"}))
    }

    #[test]
    fn profile_projection_order_omission_and_dropping() {
        let row = profile(json!({
            "zzz": 1,
            "policy": {"zeta": {"b": 1, "a": 2}, "dlp-data-profiles": [], "ai-security-profiles": [{"model-type": "default"}]},
            "last_modified_ts": "2026-02-01T00:00:00Z",
            "tsg_id": "100",
            "csp_id": "c",
            "active": true,
            "revision": 2.0,
            "profile_name": "alpha",
            "profile_id": "00000000-0000-4000-8000-000000000002",
        }));
        assert_eq!(
            crate::json::to_pretty(&ProfileView::new(&row).unwrap()).unwrap(),
            r#"{
  "profileId": "00000000-0000-4000-8000-000000000002",
  "profileName": "alpha",
  "revision": 2,
  "active": true,
  "lastModifiedTs": "2026-02-01T00:00:00Z",
  "policy": {
    "ai-security-profiles": [
      {
        "model-type": "default"
      }
    ],
    "dlp-data-profiles": [],
    "zeta": {
      "a": 2,
      "b": 1
    }
  }
}"#
        );
        let bare = profile(json!({"profile_name": "p", "created_by": "a", "updated_by": "b"}));
        assert_eq!(
            crate::json::to_pretty(&profile_views(&[bare]).unwrap()).unwrap(),
            "[\n  {\n    \"profileName\": \"p\",\n    \"createdBy\": \"a\",\n    \"updatedBy\": \"b\"\n  }\n]"
        );
    }

    #[test]
    fn topic_projection_order_and_examples_default() {
        let row = topic(json!({
            "created_ts": "2025-12-01T00:00:00Z",
            "unknown": {"x": 1},
            "tsg_id": "1",
            "description": "old",
            "revision": 1,
            "topic_name": "fin",
            "active": true,
            "created_by": "a@example.com",
            "last_modified_ts": "2026-01-01T00:00:00Z",
            "examples": ["e1"],
            "topic_id": "00000000-0000-4000-8000-000000000011",
        }));
        assert_eq!(
            crate::json::to_pretty(&TopicView::from(&row)).unwrap(),
            r#"{
  "topicId": "00000000-0000-4000-8000-000000000011",
  "topicName": "fin",
  "revision": 1,
  "active": true,
  "description": "old",
  "examples": [
    "e1"
  ],
  "createdBy": "a@example.com",
  "lastModifiedTs": "2026-01-01T00:00:00Z",
  "createdTs": "2025-12-01T00:00:00Z"
}"#
        );
        let bare = topic(json!({"topic_name": "t", "revision": 3.0, "description": ""}));
        assert_eq!(
            crate::json::to_pretty(&topic_views(&[bare])).unwrap(),
            "[\n  {\n    \"topicName\": \"t\",\n    \"revision\": 3,\n    \"description\": \"\",\n    \"examples\": []\n  }\n]"
        );
    }

    #[test]
    fn revisions_compare_numerically() {
        let unset = profile(json!({"profile_name": "p"}));
        let float = profile(json!({"profile_name": "p", "revision": 2.0}));
        let int = profile(json!({"profile_name": "p", "revision": 2}));
        let frac = profile(json!({"profile_name": "p", "revision": 2.5}));
        assert_eq!(revision_value(&unset), 0.0);
        assert!(!revision_is(&unset, 0), "unset never equals --revision 0");
        assert!(revision_is(&float, 2) && revision_is(&int, 2));
        assert!(!revision_is(&frac, 2) && !revision_is(&int, 3));
        assert!(revision_value(&frac) > revision_value(&float));
    }

    #[test]
    fn latest_per_name_keeps_first_seen_order_and_first_tie() {
        let rows = vec![
            topic_rev("a", json!(1), "a1"),
            topic_rev("b", json!(2), "b2"),
            topic_rev("a", json!(3), "a3"),
            topic_rev("a", json!(3.0), "a3-tie"),
            topic_rev("c", json!(0), "c0"),
            topic_rev("b", json!(1), "b1"),
        ];
        let ids: Vec<_> = latest_per_name(rows)
            .iter()
            .map(|row| row.id().unwrap().to_owned())
            .collect();
        assert_eq!(ids, ["a3", "b2", "c0"]);
    }

    #[test]
    fn unset_profile_revisions_count_as_zero_and_ties_keep_the_first() {
        let rows = vec![
            profile(json!({"profile_name": "p", "profile_id": "first"})),
            profile(json!({"profile_name": "p", "profile_id": "zero", "revision": 0})),
            profile(json!({"profile_name": "q", "profile_id": "q"})),
            profile(json!({"profile_name": "p", "profile_id": "one", "revision": 1})),
            profile(json!({"profile_name": "p", "profile_id": "one-tie", "revision": 1.0})),
        ];
        let ids: Vec<_> = latest_per_name(rows)
            .iter()
            .map(|row| row.id().unwrap().to_owned())
            .collect();
        assert_eq!(ids, ["one", "q"]);
        let rows = vec![
            profile(json!({"profile_name": "p", "profile_id": "first"})),
            profile(json!({"profile_name": "p", "profile_id": "zero", "revision": 0})),
        ];
        assert_eq!(latest_per_name(rows)[0].id(), Some("first"));
    }

    #[test]
    fn matching_versions_filter_by_id_or_name_then_revision() {
        let id = "0000abcd-0000-4000-8000-00000000000a";
        let rows = || {
            vec![
                topic_rev("a", json!(1), id),
                topic_rev("a", json!(2), "00000000-0000-4000-8000-000000000002"),
                topic_rev("b", json!(2), id),
            ]
        };
        let names = |rows: Vec<CustomTopic>| -> Vec<(String, f64)> {
            rows.iter()
                .map(|row| (row.name().to_owned(), revision_value(row)))
                .collect()
        };
        assert_eq!(
            names(matching_versions(rows(), "a", false, None)),
            [("a".into(), 1.0), ("a".into(), 2.0)]
        );
        assert_eq!(
            names(matching_versions(rows(), "a", false, Some(2))),
            [("a".into(), 2.0)]
        );
        assert_eq!(
            names(matching_versions(rows(), id, true, None)),
            [("a".into(), 1.0), ("b".into(), 2.0)]
        );
        // Ids compare exactly even though UUID detection is case-insensitive.
        assert!(matching_versions(rows(), &id.to_uppercase(), true, None).is_empty());
        assert!(matching_versions(rows(), "a", false, Some(9)).is_empty());
    }
}
