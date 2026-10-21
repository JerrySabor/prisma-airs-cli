//! The red team documents and layouts (DESIGN §15.5–§15.15): the TypeScript normalisers
//! (`normalizeJob`, `normalizeTargetDetail`, `normalizeAdapterDetail`, `normalizeChannel`,
//! `normalizeErrorLog`, `normalizePromptSet`, `normalizePrompt`) over the SDK answers as
//! ordered JSON, and the pretty (`renderer/redteam.ts` bytes), table and json renderings.
//!
//! A document is built from the raw answer: a key the answer lacks is omitted, `null` is
//! kept (TypeScript `raw.x as T`). Server text (names, descriptions, prompts, goals,
//! messages) is `[withheld]` when it carries a known secret, and every string printed in
//! a pretty layout or a table cell goes through `terminal_safe` (D52).

use crate::error::{CliError, SecretSet};
use crate::json::{OValue, number};
use crate::output::{Format, Output, terminal_safe, terminal_safe_lines};
use crate::render::style::Style;
use crate::render::{cell_text, js_json_number, js_number, pretty, table, utf16_prefix};

/// Server-text keys whose values are withheld when they carry a secret or a fragment of
/// one (the last three are the scan report texts, §15.16); any other string is withheld
/// when it contains a registered secret.
const TEXT_KEYS: [&str; 13] = [
    "name",
    "description",
    "content",
    "prompt",
    "goal",
    "errorMessage",
    "displayName",
    "targetName",
    "message",
    "promptText",
    "reportSummary",
    "promptSetName",
    "subCategoryDisplayName",
];

/// A string field.
pub fn text<'a>(value: &'a OValue, key: &str) -> Option<&'a str> {
    value.get(key).and_then(OValue::as_str)
}

/// JavaScript `!= null`: present and not `null`.
pub fn present(value: Option<&OValue>) -> bool {
    !matches!(value, None | Some(OValue::Null))
}

/// JavaScript truthiness.
pub fn truthy(value: Option<&OValue>) -> bool {
    match value {
        None | Some(OValue::Null) => false,
        Some(OValue::Bool(value)) => *value,
        Some(OValue::String(text)) => !text.is_empty(),
        Some(OValue::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Some(OValue::Array(_) | OValue::Object(_)) => true,
    }
}

/// An object built field by field: `None` omits the key.
#[derive(Default)]
pub struct Doc(Vec<(String, OValue)>);

impl Doc {
    pub fn put(mut self, key: &str, value: Option<OValue>) -> Self {
        if let Some(value) = value {
            self.0.push((key.to_owned(), value));
        }
        self
    }
    /// `to: raw[from]` when present (`null` kept).
    pub fn copy(self, raw: &OValue, from: &str, to: &str) -> Self {
        let value = raw.get(from).cloned();
        self.put(to, value)
    }
    pub fn build(self) -> OValue {
        OValue::Object(self.0)
    }
}

/// `[withheld]` for every string of `doc` (at any depth, under any key) that carries a
/// secret of `secrets` (§15.4): a credential the CLI redacted at one path is never printed
/// at another (a header value echoed in `request_json`, `extra_info`, a probe answer).
/// The server-text fields ([`TEXT_KEYS`]) use the full §6 rule, fragments included.
pub fn withhold(doc: &mut OValue, secrets: &SecretSet) {
    withhold_in(doc, false, secrets);
}

fn withhold_in(doc: &mut OValue, text_key: bool, secrets: &SecretSet) {
    match doc {
        OValue::String(text) => {
            let tainted = if text_key {
                secrets.taints(text)
            } else {
                secrets.carried_by(text)
            };
            if tainted {
                *text = crate::error::WITHHELD.to_owned();
            }
        }
        OValue::Array(items) => {
            for item in items {
                withhold_in(item, false, secrets);
            }
        }
        OValue::Object(entries) => {
            for (key, value) in entries {
                withhold_in(value, TEXT_KEYS.contains(&key.as_str()), secrets);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Rendering primitives
// ---------------------------------------------------------------------------

/// `String(v)` of a scalar for a pretty value (`undefined`/`null` → `""`, as
/// `ui.keyValue`'s `String(v ?? '')`); strings terminal-safe.
fn scalar(value: Option<&OValue>) -> String {
    match value {
        None | Some(OValue::Null) => String::new(),
        Some(OValue::String(text)) => terminal_safe(text).into_owned(),
        Some(OValue::Number(number)) => js_json_number(number),
        Some(OValue::Bool(value)) => value.to_string(),
        Some(nested) => {
            terminal_safe(&crate::json::to_compact(nested).unwrap_or_default()).into_owned()
        }
    }
}

/// A terminal-safe string field (empty when absent).
pub fn shown(value: &OValue, key: &str) -> String {
    scalar(value.get(key))
}

/// A multi-line server-text field (§15.3 "Multi-line server text"): a string keeps its
/// line feeds, CR LF pairs and tabs, as TypeScript prints it ([`terminal_safe_lines`]);
/// any other value as [`shown`].
pub fn prose(value: &OValue, key: &str) -> String {
    match value.get(key) {
        Some(OValue::String(text)) => terminal_safe_lines(text).into_owned(),
        other => scalar(other),
    }
}

/// `JSON.stringify(v, null, 2)`, DEL and C1 controls replaced (JSON escapes the C0
/// controls inside strings; its own line breaks stay).
pub fn json_block(value: &OValue) -> String {
    crate::json::to_pretty(value)
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
}

/// JavaScript `x.toFixed(1)` (`(-0.04).toFixed(1)` is `-0.0`, `(-0).toFixed(1)` is `0.0`).
pub fn fixed1(value: f64) -> String {
    if !value.is_finite() || value.abs() >= 1e21 {
        return js_number(value);
    }
    let text = crate::commands::topic_eval::to_fixed(value.abs(), 1);
    if value < 0.0 {
        format!("-{text}")
    } else {
        text
    }
}

/// A prompt preview: more than 80 UTF-16 units become the longest prefix of at most 77
/// units that does not split a character, then `...` (D54).
pub fn preview(text: &str) -> String {
    if text.encode_utf16().count() > 80 {
        format!("{}...", utf16_prefix(text, 77).0)
    } else {
        text.to_owned()
    }
}

/// The red team banner (pretty only, decoration).
pub fn banner(out: &mut Output) {
    pretty::banner(out, super::BANNER_TITLE, Some(super::BANNER_SUBTITLE));
}

/// `ui.dim(text)` that carries data (kept under `--quiet`, D145).
pub fn dim_data(out: &mut Output, text: &str) {
    let text = out.paint(Style::Dim, text);
    out.data_line(&format!("  {text}"));
}

/// A key/value block with owned keys, padded to the longest key in UTF-16 units (TS
/// `padEnd`); keys and values arrive terminal-safe.
pub fn key_values(out: &mut Output, pairs: &[(String, String)]) {
    let width = pairs
        .iter()
        .map(|(key, _)| key.encode_utf16().count())
        .max()
        .unwrap_or(0);
    for (key, value) in pairs {
        let pad = width - key.encode_utf16().count();
        let key = out.paint(Style::Dim, &format!("{key}{}", " ".repeat(pad)));
        out.data_line(&format!("  {key}  {value}"));
    }
}

pub fn pairs<const N: usize>(items: [(&str, String); N]) -> Vec<(String, String)> {
    items
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// `statusColor` of a job status.
pub fn status_style(status: &str) -> Style {
    match status {
        "COMPLETED" => Style::Green,
        "RUNNING" => Style::Blue,
        "QUEUED" | "INIT" | "PARTIALLY_COMPLETE" => Style::Yellow,
        "FAILED" | "ABORTED" => Style::Red,
        _ => Style::White,
    }
}

/// `activeState`: `active` green, `inactive` red.
fn active_state(out: &Output, active: bool) -> String {
    if active {
        out.paint(Style::Green, "active")
    } else {
        out.paint(Style::Red, "inactive")
    }
}

/// `channelStatusColor`.
fn channel_style(status: &str) -> Style {
    match status.to_ascii_uppercase().as_str() {
        "ONLINE" => Style::Green,
        "DRAFT" => Style::Yellow,
        "OFFLINE" => Style::Red,
        _ => Style::White,
    }
}

/// The table of a list (labels and the keys of the columns); nothing when empty.
fn list_table(out: &mut Output, columns: &[(&str, &str)], rows: &[OValue]) {
    if rows.is_empty() {
        return;
    }
    let labels: Vec<&str> = columns.iter().map(|(_, label)| *label).collect();
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            columns
                .iter()
                .map(|(key, _)| cell_text(row.get(key)))
                .collect()
        })
        .collect();
    out.data_line(&table::table(&labels, &cells));
}

/// The `Key │ Value` table of a document's top-level keys.
pub fn detail_table(out: &mut Output, doc: &OValue) {
    let rows = doc
        .as_object()
        .unwrap_or_default()
        .iter()
        .map(|(key, value)| (terminal_safe(key).into_owned(), cell_text(Some(value))))
        .collect();
    let text = table::key_value_table(rows);
    if !text.is_empty() {
        out.data_line(&text);
    }
}

/// A detail document in `format`: json, the `Key │ Value` table, or the banner and the
/// pretty layout.
pub fn detail(
    out: &mut Output,
    format: Format,
    doc: &OValue,
    layout: impl FnOnce(&mut Output),
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(doc),
        Format::Table => {
            detail_table(out, doc);
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            layout(out);
            Ok(())
        }
    }
}

/// A list in `format`: json (`[]` when empty), the table (nothing when empty), or the
/// banner and the pretty layout (`No <empty> found` when empty, D146).
pub fn list(
    out: &mut Output,
    format: Format,
    rows: &[OValue],
    columns: &[(&str, &str)],
    empty: &str,
    layout: impl FnOnce(&mut Output, &[OValue]),
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(&OValue::Array(rows.to_vec())),
        Format::Table => {
            list_table(out, columns, rows);
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if rows.is_empty() {
                pretty::empty_list(out, empty);
            } else {
                layout(out, rows);
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Scans (§15.5)
// ---------------------------------------------------------------------------

/// `normalizeJob`: `{uuid, name, status, jobType, targetId, targetName, score, asr, total,
/// completed, createdAt}`.
pub fn job(raw: &OValue) -> OValue {
    let target_name = raw
        .get("target")
        .and_then(|target| target.get("name"))
        .cloned();
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "name", "name")
        .copy(raw, "status", "status")
        .copy(raw, "job_type", "jobType")
        .copy(raw, "target_id", "targetId")
        .put("targetName", target_name)
        .copy(raw, "score", "score")
        .copy(raw, "asr", "asr")
        .copy(raw, "total", "total")
        .copy(raw, "completed", "completed")
        .copy(raw, "created_at", "createdAt")
        .build()
}

/// A `redteam list` row: `{id, name, status, type, score, createdAt}` (`""` for a missing
/// score or creation time, TS).
pub fn job_row(job: &OValue) -> OValue {
    let or_empty = |key: &str| match job.get(key) {
        None | Some(OValue::Null) => OValue::String(String::new()),
        Some(value) => value.clone(),
    };
    Doc::default()
        .copy(job, "uuid", "id")
        .copy(job, "name", "name")
        .copy(job, "status", "status")
        .copy(job, "jobType", "type")
        .put("score", Some(or_empty("score")))
        .put("createdAt", Some(or_empty("createdAt")))
        .build()
}

pub const JOB_COLUMNS: [(&str, &str); 6] = [
    ("id", "ID"),
    ("name", "Name"),
    ("status", "Status"),
    ("type", "Type"),
    ("score", "Score"),
    ("createdAt", "Created"),
];

/// The pretty `Recent Scans:` layout of `redteam list` (jobs as [`job`] documents).
pub fn scan_list_layout(out: &mut Output, jobs: &[OValue]) {
    pretty::section(out, "Recent Scans:");
    for job in jobs {
        dim_data(out, &shown(job, "uuid"));
        let status = shown(job, "status");
        let status = out.paint(status_style(&status), &status);
        let score = if present(job.get("score")) {
            format!("  score: {}", shown(job, "score"))
        } else {
            String::new()
        };
        out.data_line(&format!(
            "    {}  {status}  {}{score}",
            shown(job, "name"),
            shown(job, "jobType")
        ));
        if truthy(job.get("createdAt")) {
            let created = out.paint(Style::Dim, &shown(job, "createdAt"));
            out.data_line(&format!("    {created}"));
        }
        out.data_line("");
    }
}

/// `renderScanStatus` (a [`job`] document): the `Scan Status:` block and a blank line.
pub fn scan_status_layout(out: &mut Output, job: &OValue) {
    pretty::section(out, "Scan Status:");
    let mut kv = pairs([
        ("ID", shown(job, "uuid")),
        ("Name", shown(job, "name")),
        ("Type", shown(job, "jobType")),
    ]);
    if truthy(job.get("targetName")) {
        kv.push(("Target".into(), shown(job, "targetName")));
    }
    let status = shown(job, "status");
    kv.push(("Status".into(), out.paint(status_style(&status), &status)));
    if present(job.get("total")) && present(job.get("completed")) {
        kv.push((
            "Progress".into(),
            format!("{}/{}", shown(job, "completed"), shown(job, "total")),
        ));
    }
    if present(job.get("score")) {
        kv.push(("Score".into(), shown(job, "score")));
    }
    if present(job.get("asr")) {
        let asr = number(job, "asr").map(fixed1).unwrap_or_default();
        kv.push(("ASR".into(), format!("{asr}%")));
    }
    key_values(out, &kv);
    out.data_line("");
}

/// `getCategories`: `[{id, displayName, description, subCategories: [{id, displayName,
/// description}]}]`.
pub fn categories(raw: &OValue) -> OValue {
    let category = |raw: &OValue| {
        let subs: Vec<OValue> = raw
            .get("sub_categories")
            .and_then(OValue::as_array)
            .unwrap_or_default()
            .iter()
            .map(|sub| {
                Doc::default()
                    .copy(sub, "id", "id")
                    .copy(sub, "display_name", "displayName")
                    .copy(sub, "description", "description")
                    .build()
            })
            .collect();
        Doc::default()
            .copy(raw, "id", "id")
            .copy(raw, "display_name", "displayName")
            .copy(raw, "description", "description")
            .put("subCategories", Some(OValue::Array(subs)))
            .build()
    };
    OValue::Array(
        raw.as_array()
            .unwrap_or_default()
            .iter()
            .map(category)
            .collect(),
    )
}

/// `categories` in `format`: the TS tree (pretty), one row per sub-category (table), the
/// array (json).
pub fn render_categories(out: &mut Output, format: Format, doc: &OValue) -> Result<(), CliError> {
    let categories = doc.as_array().unwrap_or_default();
    match format {
        Format::Json => out.json(doc),
        Format::Table => {
            let mut rows = Vec::new();
            for category in categories {
                let id = cell_text(category.get("id"));
                let subs = category
                    .get("subCategories")
                    .and_then(OValue::as_array)
                    .unwrap_or_default();
                if subs.is_empty() {
                    rows.push(vec![
                        id.clone(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                }
                for sub in subs {
                    rows.push(vec![
                        id.clone(),
                        cell_text(sub.get("id")),
                        cell_text(sub.get("displayName")),
                        cell_text(sub.get("description")),
                    ]);
                }
            }
            if !rows.is_empty() {
                out.data_line(&table::table(
                    &["Category", "ID", "Name", "Description"],
                    &rows,
                ));
            }
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if categories.is_empty() {
                pretty::empty_list(out, "categories");
                return Ok(());
            }
            pretty::section(out, "Attack Categories:");
            for category in categories {
                let line = category_line(out, category, "  ", true);
                out.data_line(&line);
                for sub in category
                    .get("subCategories")
                    .and_then(OValue::as_array)
                    .unwrap_or_default()
                {
                    let bullet = out.paint(Style::Dim, "•");
                    let line = category_line(out, sub, "", false);
                    out.data_line(&format!("    {bullet} {line}"));
                }
                out.data_line("");
            }
            Ok(())
        }
    }
}

/// `<displayName> (<id>)[ — <description>]`, the name bold for a category.
fn category_line(out: &Output, value: &OValue, indent: &str, bold: bool) -> String {
    let name = shown(value, "displayName");
    let name = if bold {
        out.paint(Style::Bold, &name)
    } else {
        name
    };
    let id = out.paint(Style::Cyan, &format!("({})", shown(value, "id")));
    let description = if truthy(value.get("description")) {
        out.paint(Style::Dim, &format!(" — {}", prose(value, "description")))
    } else {
        String::new()
    };
    format!("{indent}{name} {id}{description}")
}

/// `getLanguages`: `{multilingualEnabled, supportedJobTypes, languages: [{code, name}]}`.
pub fn languages(raw: &OValue) -> OValue {
    let enabled = truthy(raw.get("multilingual_enabled"));
    let types = match raw.get("supported_job_types") {
        None | Some(OValue::Null) => OValue::Array(Vec::new()),
        Some(value) => value.clone(),
    };
    let languages: Vec<OValue> = raw
        .get("languages")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|language| {
            Doc::default()
                .copy(language, "code", "code")
                .copy(language, "name", "name")
                .build()
        })
        .collect();
    Doc::default()
        .put("multilingualEnabled", Some(OValue::Bool(enabled)))
        .put("supportedJobTypes", Some(types))
        .put("languages", Some(OValue::Array(languages)))
        .build()
}

/// `languages` in `format` (table: `Code │ Name` of the languages, TS).
pub fn render_languages(out: &mut Output, format: Format, doc: &OValue) -> Result<(), CliError> {
    let languages = doc
        .get("languages")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    match format {
        Format::Json => out.json(doc),
        Format::Table => {
            list_table(out, &[("code", "Code"), ("name", "Name")], languages);
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            pretty::section(out, "Tenant Languages:");
            let multilingual = active_state(
                out,
                matches!(doc.get("multilingualEnabled"), Some(OValue::Bool(true))),
            );
            let types: Vec<String> = doc
                .get("supportedJobTypes")
                .and_then(OValue::as_array)
                .unwrap_or_default()
                .iter()
                .map(|value| scalar(Some(value)))
                .collect();
            let types = if types.is_empty() {
                "(none)".to_owned()
            } else {
                types.join(", ")
            };
            key_values(
                out,
                &pairs([
                    ("Multilingual", multilingual),
                    ("Supported Job Types", types),
                ]),
            );
            if languages.is_empty() {
                pretty::empty_list(out, "languages");
                return Ok(());
            }
            pretty::section(out, "Languages:");
            for language in languages {
                let code = out.paint(Style::Dim, &shown(language, "code"));
                out.data_line(&format!("    {code}  {}", shown(language, "name")));
            }
            out.data_line("");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// EULA, instances (§15.7, §15.8)
// ---------------------------------------------------------------------------

/// The EULA status document `{uuid, isAccepted, acceptedAt, acceptedByUserId}` (present
/// fields).
pub fn eula_status(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "is_accepted", "isAccepted")
        .copy(raw, "accepted_at", "acceptedAt")
        .copy(raw, "accepted_by_user_id", "acceptedByUserId")
        .build()
}

/// `renderEulaStatus`.
pub fn eula_status_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "EULA Status:");
    let accepted = if matches!(doc.get("isAccepted"), Some(OValue::Bool(true))) {
        out.paint(Style::Green, "yes")
    } else {
        out.paint(Style::Red, "no")
    };
    let mut kv = pairs([("Accepted", accepted)]);
    if truthy(doc.get("acceptedAt")) {
        kv.push(("Accepted At".into(), shown(doc, "acceptedAt")));
    }
    if truthy(doc.get("acceptedByUserId")) {
        kv.push(("Accepted By".into(), shown(doc, "acceptedByUserId")));
    }
    key_values(out, &kv);
    out.data_line("");
}

/// `renderEulaContent`: `  <content>\n\n`, the content multi-line server text.
pub fn eula_content_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "EULA Content:");
    let content = text(doc, "content").unwrap_or_default();
    out.data_line(&format!("  {}\n", terminal_safe_lines(content)));
}

/// The instance detail `{tsgId, tenantId, appId, region}`.
pub fn instance(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "tsg_id", "tsgId")
        .copy(raw, "tenant_id", "tenantId")
        .copy(raw, "app_id", "appId")
        .copy(raw, "region", "region")
        .build()
}

/// `renderInstanceDetail`.
pub fn instance_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Instance Detail:");
    key_values(
        out,
        &pairs([
            ("TSG ID", shown(doc, "tsgId")),
            ("Tenant ID", shown(doc, "tenantId")),
            ("App ID", shown(doc, "appId")),
            ("Region", shown(doc, "region")),
        ]),
    );
    out.data_line("");
}

// ---------------------------------------------------------------------------
// Prompt sets, prompts, properties (§15.9–§15.11)
// ---------------------------------------------------------------------------

/// A `prompt-sets list` row `{id, name, status: active|inactive}`.
pub fn prompt_set_row(raw: &OValue) -> OValue {
    let active = matches!(raw.get("active"), Some(OValue::Bool(true)));
    Doc::default()
        .copy(raw, "uuid", "id")
        .copy(raw, "name", "name")
        .put(
            "status",
            Some(OValue::String(
                if active { "active" } else { "inactive" }.to_owned(),
            )),
        )
        .build()
}

pub const PROMPT_SET_COLUMNS: [(&str, &str); 3] =
    [("id", "ID"), ("name", "Name"), ("status", "Status")];

/// `renderPromptSetList`.
pub fn prompt_set_list_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Prompt Sets:");
    for row in rows {
        dim_data(out, &shown(row, "id"));
        let state = active_state(out, text(row, "status") == Some("active"));
        out.data_line(&format!("    {}  {state}", shown(row, "name")));
    }
    out.data_line("");
}

/// `normalizePromptSet`: `{uuid, name, active, archive, description, createdAt,
/// updatedAt}`.
pub fn prompt_set(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "name", "name")
        .copy(raw, "active", "active")
        .copy(raw, "archive", "archive")
        .copy(raw, "description", "description")
        .copy(raw, "created_at", "createdAt")
        .copy(raw, "updated_at", "updatedAt")
        .build()
}

/// The TS version-info document `{uuid, version, stats}`.
pub fn version_info(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "version", "version")
        .copy(raw, "stats", "stats")
        .build()
}

/// The `prompt-sets get` document: the set and, when it was read, `versionInfo`.
pub fn prompt_set_detail(set: OValue, info: Option<OValue>) -> OValue {
    let OValue::Object(mut entries) = set else {
        return set;
    };
    if let Some(info) = info {
        entries.push(("versionInfo".to_owned(), info));
    }
    OValue::Object(entries)
}

/// `renderPromptSetDetail` and the version-info block (D148: the counts come from
/// `stats.total_prompts`, `active_prompts`, `inactive_prompts`).
pub fn prompt_set_layout(out: &mut Output, doc: &OValue, with_version: bool) {
    pretty::section(out, "Prompt Set Detail:");
    let active = matches!(doc.get("active"), Some(OValue::Bool(true)));
    let archived = if matches!(doc.get("archive"), Some(OValue::Bool(true))) {
        "yes"
    } else {
        "no"
    };
    let mut kv = pairs([
        ("UUID", shown(doc, "uuid")),
        ("Name", shown(doc, "name")),
        ("Status", active_state(out, active)),
        ("Archived", archived.to_owned()),
    ]);
    for (key, label) in [
        ("description", "Description"),
        ("createdAt", "Created"),
        ("updatedAt", "Updated"),
    ] {
        if truthy(doc.get(key)) {
            let value = if key == "description" {
                prose(doc, key)
            } else {
                shown(doc, key)
            };
            kv.push((label.to_owned(), value));
        }
    }
    key_values(out, &kv);
    out.data_line("");
    if !with_version {
        return;
    }
    pretty::section(out, "Version Info:");
    match doc.get("versionInfo") {
        Some(info) => {
            let stats = info.get("stats").cloned().unwrap_or(OValue::Null);
            key_values(
                out,
                &pairs([
                    ("Version", shown(info, "version")),
                    ("Total", shown(&stats, "total_prompts")),
                    ("Active", shown(&stats, "active_prompts")),
                    ("Inactive", shown(&stats, "inactive_prompts")),
                ]),
            );
        }
        None => dim_data(out, "unavailable (version-info endpoint returned an error)"),
    }
    out.data_line("");
}

/// `normalizePrompt`: `{uuid, prompt, goal, active, promptSetId}`.
pub fn prompt(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "prompt", "prompt")
        .copy(raw, "goal", "goal")
        .copy(raw, "active", "active")
        .copy(raw, "prompt_set_id", "promptSetId")
        .build()
}

/// `prompts list` table: `UUID │ Status │ Prompt │ Goal`.
pub fn render_prompt_list(
    out: &mut Output,
    format: Format,
    rows: &[OValue],
) -> Result<(), CliError> {
    if format == Format::Table {
        let projected: Vec<OValue> = rows
            .iter()
            .map(|row| {
                let active = matches!(row.get("active"), Some(OValue::Bool(true)));
                Doc::default()
                    .copy(row, "uuid", "uuid")
                    .put(
                        "status",
                        Some(OValue::String(
                            if active { "active" } else { "inactive" }.to_owned(),
                        )),
                    )
                    .copy(row, "prompt", "prompt")
                    .copy(row, "goal", "goal")
                    .build()
            })
            .collect();
        list_table(
            out,
            &[
                ("uuid", "UUID"),
                ("status", "Status"),
                ("prompt", "Prompt"),
                ("goal", "Goal"),
            ],
            &projected,
        );
        return Ok(());
    }
    list(out, format, rows, &[], "prompts", |out, rows| {
        pretty::section(out, "Prompts:");
        for row in rows {
            let uuid = out.paint(Style::Dim, &shown(row, "uuid"));
            let status = if matches!(row.get("active"), Some(OValue::Bool(true))) {
                out.paint(Style::Green, "active")
            } else {
                out.paint(Style::Dim, "inactive")
            };
            out.data_line(&format!("  {uuid}  {status}"));
            let prompt = preview(text(row, "prompt").unwrap_or_default());
            out.data_line(&format!("    {}", terminal_safe_lines(&prompt)));
            if truthy(row.get("goal")) {
                let goal = out.paint(Style::Dim, &format!("Goal: {}", prose(row, "goal")));
                out.data_line(&format!("    {goal}"));
            }
        }
        out.data_line("");
    })
}

/// `renderPromptDetail`.
pub fn prompt_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Prompt Detail:");
    let status = if matches!(doc.get("active"), Some(OValue::Bool(true))) {
        out.paint(Style::Green, "active")
    } else {
        out.paint(Style::Dim, "inactive")
    };
    let mut kv = pairs([
        ("UUID", shown(doc, "uuid")),
        ("Set UUID", shown(doc, "promptSetId")),
        ("Status", status),
        ("Prompt", prose(doc, "prompt")),
    ]);
    if truthy(doc.get("goal")) {
        kv.push(("Goal".into(), prose(doc, "goal")));
    }
    key_values(out, &kv);
    out.data_line("");
}

/// `properties list` in `format`: the names (json), column `Name`, or bullets.
pub fn render_property_names(
    out: &mut Output,
    format: Format,
    names: &[OValue],
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(&OValue::Array(names.to_vec())),
        Format::Table => {
            let rows: Vec<Vec<String>> = names
                .iter()
                .map(|name| vec![cell_text(Some(name))])
                .collect();
            if !rows.is_empty() {
                out.data_line(&table::table(&["Name"], &rows));
            }
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if names.is_empty() {
                pretty::empty_list(out, "property names");
                return Ok(());
            }
            pretty::section(out, "Property Names:");
            for name in names {
                pretty::bullet(out, &scalar(Some(name)), pretty::Bullet::Neutral);
            }
            out.data_line("");
            Ok(())
        }
    }
}

/// `properties values` in `format`: `{name, values}`, `Property │ Value` rows, or the
/// TS layout.
pub fn render_property_values(
    out: &mut Output,
    format: Format,
    doc: &OValue,
) -> Result<(), CliError> {
    let values = doc
        .get("values")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    match format {
        Format::Json => out.json(doc),
        Format::Table => {
            let name = cell_text(doc.get("name"));
            let rows: Vec<Vec<String>> = values
                .iter()
                .map(|value| vec![name.clone(), cell_text(Some(value))])
                .collect();
            if !rows.is_empty() {
                out.data_line(&table::table(&["Property", "Value"], &rows));
            }
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if values.is_empty() {
                pretty::empty_list(out, "property values");
                return Ok(());
            }
            pretty::section(out, "Property Values:");
            key_values(out, &pairs([("Property", shown(doc, "name"))]));
            for value in values {
                pretty::bullet(out, &scalar(Some(value)), pretty::Bullet::Neutral);
            }
            out.data_line("");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Targets (§15.12)
// ---------------------------------------------------------------------------

/// A `targets list` row `{id, name, status: active|inactive, type}`.
pub fn target_row(raw: &OValue) -> OValue {
    let active = matches!(raw.get("active"), Some(OValue::Bool(true)));
    let kind = match raw.get("target_type") {
        None | Some(OValue::Null) => OValue::String(String::new()),
        Some(OValue::String(text)) => OValue::String(text.clone()),
        Some(other) => OValue::String(scalar(Some(other))),
    };
    Doc::default()
        .copy(raw, "uuid", "id")
        .copy(raw, "name", "name")
        .put(
            "status",
            Some(OValue::String(
                if active { "active" } else { "inactive" }.to_owned(),
            )),
        )
        .put("type", Some(kind))
        .build()
}

pub const TARGET_COLUMNS: [(&str, &str); 4] = [
    ("id", "ID"),
    ("name", "Name"),
    ("status", "Status"),
    ("type", "Type"),
];

/// `renderTargetList`.
pub fn target_list_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Targets:");
    for row in rows {
        dim_data(out, &shown(row, "id"));
        let state = active_state(out, text(row, "status") == Some("active"));
        let kind = if truthy(row.get("type")) {
            format!("  type: {}", shown(row, "type"))
        } else {
            String::new()
        };
        out.data_line(&format!("    {}  {state}{kind}", shown(row, "name")));
    }
    out.data_line("");
}

/// `sanitizeTargetMetadata`: drop `multi_turn_error_message` when `multi_turn` is `false`.
pub fn sanitize_metadata(metadata: Option<OValue>) -> Option<OValue> {
    match metadata {
        Some(OValue::Object(entries))
            if entries
                .iter()
                .any(|(key, value)| key == "multi_turn" && *value == OValue::Bool(false)) =>
        {
            Some(OValue::Object(
                entries
                    .into_iter()
                    .filter(|(key, _)| key != "multi_turn_error_message")
                    .collect(),
            ))
        }
        other => other,
    }
}

/// `normalizeTargetDetail`.
pub fn target_detail(raw: &OValue) -> OValue {
    let metadata = sanitize_metadata(raw.get("target_metadata").cloned());
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "name", "name")
        .copy(raw, "status", "status")
        .copy(raw, "target_type", "targetType")
        .copy(raw, "active", "active")
        .copy(raw, "connection_type", "connectionType")
        .copy(raw, "api_endpoint_type", "apiEndpointType")
        .copy(raw, "response_mode", "responseMode")
        .copy(raw, "auth_type", "authType")
        .copy(raw, "auth_config", "authConfig")
        .copy(
            raw,
            "network_broker_channel_uuid",
            "networkBrokerChannelUuid",
        )
        .copy(raw, "session_supported", "sessionSupported")
        .copy(raw, "extra_info", "extraInfo")
        .copy(raw, "description", "description")
        .copy(raw, "connection_params", "connectionParams")
        .copy(raw, "target_background", "background")
        .copy(raw, "additional_context", "additionalContext")
        .put("metadata", metadata)
        .build()
}

/// `formatDetailValue`: `null` → `null`, a scalar → `String(v)`, an object → its
/// 2-space JSON with every line break followed by two spaces.
fn detail_value(value: &OValue) -> String {
    match value {
        OValue::Null => "null".to_owned(),
        OValue::Array(_) | OValue::Object(_) => json_block(value).replace('\n', "\n  "),
        scalar_value => scalar(Some(scalar_value)),
    }
}

/// `keyValueFromObject`.
fn object_block(out: &mut Output, object: &OValue, skip_nullish: bool) {
    let kv: Vec<(String, String)> = object
        .as_object()
        .unwrap_or_default()
        .iter()
        .filter(|(_, value)| !(skip_nullish && *value == OValue::Null))
        .map(|(key, value)| (terminal_safe(key).into_owned(), detail_value(value)))
        .collect();
    if !kv.is_empty() {
        key_values(out, &kv);
    }
}

/// `renderTargetDetail` (a [`target_detail`] document, redacted).
pub fn target_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Target Detail:");
    let active = matches!(doc.get("active"), Some(OValue::Bool(true)));
    let mut kv = pairs([
        ("UUID", shown(doc, "uuid")),
        ("Name", shown(doc, "name")),
        ("Status", active_state(out, active)),
    ]);
    if truthy(doc.get("targetType")) {
        kv.push(("Type".into(), shown(doc, "targetType")));
    }
    key_values(out, &kv);
    for (key, label, skip) in [
        ("connectionParams", "Connection:", false),
        ("background", "Background:", true),
        ("metadata", "Metadata:", true),
    ] {
        if let Some(value) = doc.get(key).filter(|value| truthy(Some(value))) {
            pretty::section(out, label);
            object_block(out, value, skip);
        }
    }
    out.data_line("");
}

/// A document printed as `JSON.stringify(x, null, 2)` (data).
pub fn json_layout(out: &mut Output, doc: &OValue) {
    out.data_line(&json_block(doc));
}

/// `renderTargetTemplates`: per provider its bold name and the dim indented JSON. Both
/// are data (D145): `--quiet` keeps each template with the provider it belongs to.
pub fn templates_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Target Templates:");
    for (provider, config) in doc.as_object().unwrap_or_default() {
        let name = out.paint(Style::Bold, &terminal_safe(provider));
        out.data(&format!("\n  {name}\n\n"));
        dim_data(out, &json_block(config).replace('\n', "\n  "));
        out.data_line("");
    }
}

/// `targets templates` table: `Provider │ Template`.
pub fn templates_table(out: &mut Output, doc: &OValue) {
    let rows: Vec<Vec<String>> = doc
        .as_object()
        .unwrap_or_default()
        .iter()
        .map(|(provider, config)| {
            vec![
                terminal_safe(provider).into_owned(),
                cell_text(Some(config)),
            ]
        })
        .collect();
    if !rows.is_empty() {
        out.data_line(&table::table(&["Provider", "Template"], &rows));
    }
}

/// `normalizeErrorLog`.
pub fn error_log(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "created_at", "createdAt")
        .copy(raw, "updated_at", "updatedAt")
        .copy(raw, "job_id", "jobId")
        .copy(raw, "target_id", "targetId")
        .copy(raw, "target_version", "targetVersion")
        .copy(raw, "attack_id", "attackId")
        .copy(raw, "error_type", "errorType")
        .copy(raw, "error_source", "errorSource")
        .copy(raw, "error_message", "errorMessage")
        .copy(raw, "target_object", "targetObject")
        .copy(raw, "extra_info", "extraInfo")
        .copy(raw, "version", "version")
        .build()
}

/// `targets error-logs` in `format` (table `Created │ Type │ Source │ Job │ Message`).
pub fn render_error_logs(
    out: &mut Output,
    format: Format,
    logs: &[OValue],
) -> Result<(), CliError> {
    if format == Format::Table {
        list_table(
            out,
            &[
                ("createdAt", "Created"),
                ("errorType", "Type"),
                ("errorSource", "Source"),
                ("jobId", "Job"),
                ("errorMessage", "Message"),
            ],
            logs,
        );
        return Ok(());
    }
    list(out, format, logs, &[], "error logs", |out, logs| {
        pretty::section(out, "Target-Profile Error Logs:");
        for log in logs {
            let created = out.paint(Style::Dim, &shown(log, "createdAt"));
            let kind = if truthy(log.get("errorType")) {
                out.paint(Style::Red, &shown(log, "errorType"))
            } else {
                out.paint(Style::Dim, "error")
            };
            let source = if truthy(log.get("errorSource")) {
                format!("  ({})", shown(log, "errorSource"))
            } else {
                String::new()
            };
            out.data_line(&format!("    {created}  {kind}{source}"));
            if truthy(log.get("errorMessage")) {
                out.data_line(&format!("      {}", prose(log, "errorMessage")));
            }
            if truthy(log.get("jobId")) {
                let job = out.paint(Style::Dim, &format!("job: {}", shown(log, "jobId")));
                out.data_line(&format!("      {job}"));
            }
            out.data_line("");
        }
    })
}

// ---------------------------------------------------------------------------
// Adapters (§15.14)
// ---------------------------------------------------------------------------

/// An `adapter list` row `{uuid, name, status, targets, updated}`.
pub fn adapter_row(raw: &OValue) -> OValue {
    let or_empty = |key: &str| match raw.get(key) {
        None | Some(OValue::Null) => OValue::String(String::new()),
        Some(value) => value.clone(),
    };
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "name", "name")
        .copy(raw, "status", "status")
        .put("targets", Some(or_empty("target_count")))
        .put("updated", Some(or_empty("updated_at")))
        .build()
}

pub const ADAPTER_COLUMNS: [(&str, &str); 5] = [
    ("uuid", "UUID"),
    ("name", "Name"),
    ("status", "Status"),
    ("targets", "Targets"),
    ("updated", "Updated"),
];

/// `renderAdapterList`: the rows and, for a single page that carried it, the total
/// (data, D145).
pub fn adapter_list_layout(out: &mut Output, rows: &[OValue], total: Option<&OValue>) {
    pretty::section(out, "Custom Target Adapters:");
    for row in rows {
        dim_data(out, &shown(row, "uuid"));
        let status = shown(row, "status");
        let style = if status == "ACTIVE" {
            Style::Green
        } else {
            Style::Yellow
        };
        let status = out.paint(style, &status);
        let targets = match row.get("targets") {
            Some(OValue::String(text)) if text.is_empty() => String::new(),
            Some(value) => format!("  targets: {}", scalar(Some(value))),
            None => String::new(),
        };
        out.data_line(&format!("    {}  {status}{targets}", shown(row, "name")));
        out.data_line("");
    }
    if let Some(total) = total {
        dim_data(out, &format!("{} total", scalar(Some(total))));
    }
}

/// `normalizeAdapterDetail`.
pub fn adapter_detail(raw: &OValue) -> OValue {
    let variables: Vec<OValue> = raw
        .get("variables")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|variable| {
            Doc::default()
                .copy(variable, "key", "key")
                .copy(variable, "value", "value")
                .copy(variable, "type", "type")
                .copy(variable, "is_redacted", "isRedacted")
                .build()
        })
        .collect();
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "tsg_id", "tsgId")
        .copy(raw, "name", "name")
        .copy(raw, "script_b64", "scriptB64")
        .copy(raw, "status", "status")
        .copy(raw, "description", "description")
        .copy(
            raw,
            "network_broker_channel_uuid",
            "networkBrokerChannelUuid",
        )
        .put("variables", Some(OValue::Array(variables)))
        .copy(raw, "target_count", "targetCount")
        .copy(raw, "created_at", "createdAt")
        .copy(raw, "updated_at", "updatedAt")
        .copy(raw, "created_by_user_id", "createdByUserId")
        .copy(raw, "updated_by_user_id", "updatedByUserId")
        .build()
}

/// `renderAdapterDetail`; a `SECRET` variable is always the dim `(redacted)`.
pub fn adapter_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Adapter Detail:");
    let status = shown(doc, "status");
    let style = if status == "ACTIVE" {
        Style::Green
    } else {
        Style::Yellow
    };
    let script_length = text(doc, "scriptB64").map_or(0, |script| script.encode_utf16().count());
    let mut kv = pairs([
        ("UUID", shown(doc, "uuid")),
        ("Name", shown(doc, "name")),
        ("Status", out.paint(style, &status)),
        ("Script", format!("{script_length} base64 chars")),
    ]);
    for (key, label) in [
        ("description", "Description"),
        ("networkBrokerChannelUuid", "Broker Channel"),
        ("targetCount", "Targets"),
        ("createdAt", "Created"),
        ("updatedAt", "Updated"),
    ] {
        if present(doc.get(key)) {
            let value = if key == "description" {
                prose(doc, key)
            } else {
                shown(doc, key)
            };
            kv.push((label.to_owned(), value));
        }
    }
    key_values(out, &kv);
    let variables = doc
        .get("variables")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    if !variables.is_empty() {
        pretty::section(out, "Variables:");
        let kv: Vec<(String, String)> = variables
            .iter()
            .map(|variable| {
                let hidden = text(variable, "type") == Some("SECRET")
                    || matches!(variable.get("isRedacted"), Some(OValue::Bool(true)));
                let value = if hidden {
                    out.paint(Style::Dim, "(redacted)")
                } else {
                    shown(variable, "value")
                };
                (
                    format!("{} ({})", shown(variable, "key"), shown(variable, "type")),
                    value,
                )
            })
            .collect();
        key_values(out, &kv);
    }
    out.data_line("");
}

// ---------------------------------------------------------------------------
// Network broker (§15.15)
// ---------------------------------------------------------------------------

/// `normalizeChannel`.
pub fn channel(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "uuid", "uuid")
        .copy(raw, "name", "name")
        .copy(raw, "description", "description")
        .copy(raw, "status", "status")
        .copy(raw, "added_by", "addedBy")
        .copy(raw, "created_at", "createdAt")
        .copy(raw, "updated_at", "updatedAt")
        .copy(raw, "last_online_at", "lastOnlineAt")
        .copy(raw, "connected_clients_count", "connectedClientsCount")
        .copy(raw, "outdated_clients_count", "outdatedClientsCount")
        .copy(raw, "features", "features")
        .build()
}

/// A `channels list` row `{id, name, status, clients, lastOnline}` (nulls → `""`).
pub fn channel_row(channel: &OValue) -> OValue {
    let or_empty = |key: &str| match channel.get(key) {
        None | Some(OValue::Null) => OValue::String(String::new()),
        Some(value) => value.clone(),
    };
    Doc::default()
        .put("id", Some(or_empty("uuid")))
        .put("name", Some(or_empty("name")))
        .put("status", Some(or_empty("status")))
        .put("clients", Some(or_empty("connectedClientsCount")))
        .put("lastOnline", Some(or_empty("lastOnlineAt")))
        .build()
}

pub const CHANNEL_COLUMNS: [(&str, &str); 5] = [
    ("id", "ID"),
    ("name", "Name"),
    ("status", "Status"),
    ("clients", "Clients"),
    ("lastOnline", "Last Online"),
];

/// `renderChannelList` (channels as [`channel`] documents).
pub fn channel_list_layout(out: &mut Output, channels: &[OValue]) {
    pretty::section(out, "Network Broker Channels:");
    for channel in channels {
        if truthy(channel.get("uuid")) {
            dim_data(out, &shown(channel, "uuid"));
        }
        let status = if truthy(channel.get("status")) {
            let status = shown(channel, "status");
            out.paint(channel_style(&status), &status)
        } else {
            out.paint(Style::Dim, "unknown")
        };
        let clients = if present(channel.get("connectedClientsCount")) {
            format!("  clients: {}", shown(channel, "connectedClientsCount"))
        } else {
            String::new()
        };
        let name = if present(channel.get("name")) {
            shown(channel, "name")
        } else {
            "(unnamed)".to_owned()
        };
        out.data_line(&format!("    {name}  {status}{clients}"));
        out.data_line("");
    }
}

/// `renderChannelDetail`.
pub fn channel_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Channel Detail:");
    let mut kv = pairs([("UUID", shown(doc, "uuid"))]);
    for (key, label) in [
        ("name", "Name"),
        ("description", "Description"),
        ("status", "Status"),
        ("connectedClientsCount", "Connected Clients"),
        ("outdatedClientsCount", "Outdated Clients"),
        ("lastOnlineAt", "Last Online"),
        ("addedBy", "Added By"),
        ("createdAt", "Created"),
        ("updatedAt", "Updated"),
    ] {
        if !present(doc.get(key)) {
            continue;
        }
        let value = if key == "status" {
            let status = shown(doc, key);
            out.paint(channel_style(&status), &status)
        } else if key == "description" {
            prose(doc, key)
        } else {
            shown(doc, key)
        };
        kv.push((label.to_owned(), value));
    }
    key_values(out, &kv);
    if let Some(OValue::Object(features)) = doc.get("features")
        && !features.is_empty()
    {
        pretty::section(out, "Features:");
        let kv: Vec<(String, String)> = features
            .iter()
            .map(|(key, value)| (terminal_safe(key).into_owned(), scalar(Some(value))))
            .collect();
        key_values(out, &kv);
    }
    out.data_line("");
}

/// The channel statistics `{serverDomain, dockerRegistry, helmChart, dockerImage,
/// onlineChannels, totalChannels, clientVersion}`.
pub fn channel_stats(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "network_channels_server_domain", "serverDomain")
        .copy(raw, "docker_registry", "dockerRegistry")
        .copy(raw, "helm_chart", "helmChart")
        .copy(raw, "docker_image", "dockerImage")
        .copy(raw, "online_channels", "onlineChannels")
        .copy(raw, "total_channels", "totalChannels")
        .copy(raw, "client_version", "clientVersion")
        .build()
}

/// `renderChannelStats`.
pub fn channel_stats_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Network Broker Stats:");
    let mut kv = Vec::new();
    for (key, label) in [
        ("onlineChannels", "Online Channels"),
        ("totalChannels", "Total Channels"),
        ("serverDomain", "Server Domain"),
        ("dockerRegistry", "Docker Registry"),
        ("dockerImage", "Docker Image"),
        ("helmChart", "Helm Chart"),
        ("clientVersion", "Client Version"),
    ] {
        if present(doc.get(key)) {
            kv.push((label.to_owned(), shown(doc, key)));
        }
    }
    key_values(out, &kv);
    out.data_line("");
}

// ---------------------------------------------------------------------------
// Write documents and layouts (step 2: §15.5–§15.15)
// ---------------------------------------------------------------------------

/// `  Job ID  <uuid>` (data, after the scan blocks).
pub fn job_id_line(out: &mut Output, uuid: &str) {
    key_values(out, &pairs([("Job ID", terminal_safe(uuid).into_owned())]));
}

/// The TS `InstanceResponse` document `{tsgId, tenantId, appId, isSuccess}` (present
/// fields).
pub fn instance_response(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "tsg_id", "tsgId")
        .copy(raw, "tenant_id", "tenantId")
        .copy(raw, "app_id", "appId")
        .copy(raw, "is_success", "isSuccess")
        .build()
}

/// `renderInstanceResponse`.
pub fn instance_response_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Instance:");
    let mut kv = pairs([("TSG ID", shown(doc, "tsgId"))]);
    if truthy(doc.get("tenantId")) {
        kv.push(("Tenant ID".into(), shown(doc, "tenantId")));
    }
    if truthy(doc.get("appId")) {
        kv.push(("App ID".into(), shown(doc, "appId")));
    }
    if let Some(OValue::Bool(success)) = doc.get("isSuccess") {
        let text = if *success {
            out.paint(Style::Green, "yes")
        } else {
            out.paint(Style::Red, "no")
        };
        kv.push(("Success".into(), text));
    }
    key_values(out, &kv);
    out.data_line("");
}

/// The withheld registry token (D139).
pub const TOKEN_WITHHELD: &str = "(withheld; use --output json to print it)";

/// `registry-credentials` in `format` (D139: the token only in json).
pub fn render_registry(out: &mut Output, format: Format, doc: &OValue) -> Result<(), CliError> {
    let shown_doc = Doc::default()
        .put("token", Some(OValue::String(TOKEN_WITHHELD.to_owned())))
        .copy(doc, "expiry", "expiry")
        .build();
    match format {
        Format::Json => out.json(doc),
        Format::Table => {
            detail_table(out, &shown_doc);
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            pretty::section(out, "Registry Credentials:");
            key_values(
                out,
                &pairs([
                    ("Token", TOKEN_WITHHELD.to_owned()),
                    ("Expiry", shown(doc, "expiry")),
                ]),
            );
            out.data_line("");
            Ok(())
        }
    }
}

/// `  Name  <name>` (the pretty output of `prompt-sets create`).
pub fn name_line(out: &mut Output, doc: &OValue) {
    key_values(out, &pairs([("Name", shown(doc, "name"))]));
}

/// The TS auth-validation document `{validated, tokenPreview, expiresIn}` (present
/// fields).
pub fn auth_validation(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "validated", "validated")
        .copy(raw, "token_preview", "tokenPreview")
        .copy(raw, "expires_in", "expiresIn")
        .build()
}

/// `renderAuthValidation` (the token preview already `[REDACTED]`).
pub fn auth_validation_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Auth Validation:");
    let validated = if matches!(doc.get("validated"), Some(OValue::Bool(true))) {
        out.paint(Style::Green, "yes")
    } else {
        out.paint(Style::Red, "no")
    };
    let mut kv = pairs([("Validated", validated)]);
    if truthy(doc.get("tokenPreview")) {
        kv.push(("Token".into(), shown(doc, "tokenPreview")));
    }
    if present(doc.get("expiresIn")) {
        kv.push(("Expires In".into(), format!("{}s", shown(doc, "expiresIn"))));
    }
    key_values(out, &kv);
    out.data_line("");
}

/// The adapter-validation document `{validated, stdout, stderr, traceback}`.
pub fn adapter_validation(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "validated", "validated")
        .copy(raw, "stdout", "stdout")
        .copy(raw, "stderr", "stderr")
        .copy(raw, "traceback", "traceback")
        .build()
}

/// `[withheld]` for each script output that carries a known secret (§15.4).
pub fn withhold_outputs(doc: &mut OValue, secrets: &SecretSet) {
    if let OValue::Object(entries) = doc {
        for (key, value) in entries {
            if matches!(key.as_str(), "stdout" | "stderr" | "traceback")
                && let OValue::String(text) = value
                && secrets.taints(text)
            {
                *text = crate::error::WITHHELD.to_owned();
            }
        }
    }
}

/// The sections of `renderAdapterValidation` (the outcome line goes to stderr):
/// `\n  <label>\n\n<text>\n` per non-empty output (`stderr` and `traceback` red), then a
/// blank line; each text multi-line server text.
pub fn adapter_validation_layout(out: &mut Output, doc: &OValue) {
    for (key, label, style) in [
        ("stdout", "stdout:", None),
        ("stderr", "stderr:", Some(Style::Red)),
        ("traceback", "traceback:", Some(Style::Red)),
    ] {
        let Some(text) = text(doc, key).filter(|text| !text.is_empty()) else {
            continue;
        };
        pretty::section(out, label);
        let body = terminal_safe_lines(text).into_owned();
        let body = match style {
            Some(style) => out.paint(style, &body),
            None => body,
        };
        out.data_line(&body);
    }
    out.data_line("");
}

// ---------------------------------------------------------------------------
// Scan reports (§15.16)
// ---------------------------------------------------------------------------

/// The `{{…_RISK}}` placeholders of static summaries (TS `REPORT_SUMMARY_TOKENS`); an
/// unknown `{{…}}` stays visible.
const SUMMARY_TOKENS: [(&str, &str); 5] = [
    ("{{CRITICAL_RISK}}", "critical risk"),
    ("{{HIGH_RISK}}", "high risk"),
    ("{{MEDIUM_RISK}}", "medium risk"),
    ("{{LOW_RISK}}", "low risk"),
    ("{{INFORMATIONAL_RISK}}", "informational risk"),
];

/// `interpolateReportSummary` on a `report_summary` value (`null`, `""` and non-strings
/// unchanged).
pub fn interpolate_summary(value: Option<&OValue>) -> Option<OValue> {
    match value {
        Some(OValue::String(text)) if !text.is_empty() => {
            let mut text = text.clone();
            for (token, replacement) in SUMMARY_TOKENS {
                text = text.replace(token, replacement);
            }
            Some(OValue::String(text))
        }
        other => other.cloned(),
    }
}

/// A number field, `0` when absent or `null` (TS `?? 0`).
fn number_or_zero(raw: &OValue, key: &str) -> OValue {
    match raw.get(key) {
        None | Some(OValue::Null) => OValue::Number(0.into()),
        Some(value) => value.clone(),
    }
}

/// A finite `f64` as a JSON number (integers stay integers).
fn json_f64(value: f64) -> OValue {
    if value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        // The range check above keeps the cast exact.
        #[allow(clippy::cast_possible_truncation)]
        let integer = value as i64;
        OValue::Number(integer.into())
    } else {
        serde_json::Number::from_f64(value).map_or(OValue::Null, OValue::Number)
    }
}

/// `getStaticReport`: `{score, asr, severityBreakdown, reportSummary, categories}`.
pub fn static_report(raw: &OValue) -> OValue {
    let stats = raw
        .get("severity_report")
        .and_then(|report| report.get("stats"))
        .and_then(OValue::as_array)
        .unwrap_or_default();
    let breakdown: Vec<OValue> = stats
        .iter()
        .map(|stat| {
            Doc::default()
                .copy(stat, "severity", "severity")
                .put("successful", Some(number_or_zero(stat, "successful")))
                .put("failed", Some(number_or_zero(stat, "failed")))
                .build()
        })
        .collect();
    let subs = raw
        .get("security_report")
        .and_then(|report| report.get("sub_categories"))
        .and_then(OValue::as_array)
        .unwrap_or_default();
    let categories: Vec<OValue> = subs
        .iter()
        .map(|sub| {
            let successful = number(sub, "successful").unwrap_or(0.0);
            let failed = number(sub, "failed").unwrap_or(0.0);
            let total = match sub.get("total") {
                None | Some(OValue::Null) => json_f64(successful + failed),
                Some(value) => value.clone(),
            };
            let total_number = match &total {
                OValue::Number(number) => number.as_f64().unwrap_or(0.0),
                _ => 0.0,
            };
            let asr = if total_number > 0.0 {
                successful / total_number * 100.0
            } else {
                0.0
            };
            Doc::default()
                .copy(sub, "id", "id")
                .copy(sub, "display_name", "displayName")
                .put("asr", Some(json_f64(asr)))
                .put("successful", Some(number_or_zero(sub, "successful")))
                .put("failed", Some(number_or_zero(sub, "failed")))
                .put("total", Some(total))
                .build()
        })
        .collect();
    Doc::default()
        .copy(raw, "score", "score")
        .copy(raw, "asr", "asr")
        .put("severityBreakdown", Some(OValue::Array(breakdown)))
        .put(
            "reportSummary",
            interpolate_summary(raw.get("report_summary")),
        )
        .put("categories", Some(OValue::Array(categories)))
        .build()
}

/// `getDynamicReport`.
pub fn dynamic_report(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "score", "score")
        .copy(raw, "asr", "asr")
        .copy(raw, "total_goals", "totalGoals")
        .copy(raw, "goals_achieved", "goalsAchieved")
        .copy(raw, "total_streams", "totalStreams")
        .copy(raw, "total_threats", "totalThreats")
        .put(
            "reportSummary",
            interpolate_summary(raw.get("report_summary")),
        )
        .build()
}

/// `getCustomReport`.
pub fn custom_report(raw: &OValue) -> OValue {
    let sets: Vec<OValue> = raw
        .get("custom_attack_reports")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|set| {
            Doc::default()
                .copy(set, "prompt_set_id", "promptSetId")
                .copy(set, "prompt_set_name", "promptSetName")
                .copy(set, "total_prompts", "totalPrompts")
                .copy(set, "total_attacks", "totalAttacks")
                .copy(set, "total_threats", "totalThreats")
                .copy(set, "threat_rate", "threatRate")
                .build()
        })
        .collect();
    Doc::default()
        .copy(raw, "total_prompts", "totalPrompts")
        .copy(raw, "total_attacks", "totalAttacks")
        .copy(raw, "total_threats", "totalThreats")
        .copy(raw, "failed_attacks", "failedAttacks")
        .copy(raw, "score", "score")
        .copy(raw, "asr", "asr")
        .put("promptSets", Some(OValue::Array(sets)))
        .build()
}

/// A boolean field, `false` when absent or `null` (TS `?? false`).
fn bool_or_false(raw: &OValue, key: &str) -> OValue {
    match raw.get(key) {
        None | Some(OValue::Null) => OValue::Bool(false),
        Some(value) => value.clone(),
    }
}

/// `listAttacks` rows: `{id, name, severity, category, subCategory,
/// subCategoryDisplayName, successful}` (the attack prompt is never kept).
pub fn attack(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "uuid", "id")
        .copy(raw, "attack_name", "name")
        .copy(raw, "severity", "severity")
        .copy(raw, "category", "category")
        .copy(raw, "sub_category", "subCategory")
        .copy(raw, "sub_category_display_name", "subCategoryDisplayName")
        .put("successful", Some(bool_or_false(raw, "threat")))
        .build()
}

/// `listCustomAttacks` rows: `{promptId, promptText, goal, threat, asr, promptSetName}`.
pub fn custom_attack(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "prompt_id", "promptId")
        .copy(raw, "prompt_text", "promptText")
        .copy(raw, "goal", "goal")
        .put("threat", Some(bool_or_false(raw, "threat")))
        .copy(raw, "asr", "asr")
        .copy(raw, "prompt_set_name", "promptSetName")
        .build()
}

/// `severityColor`.
pub fn severity_style(severity: &str) -> Style {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => Style::Red,
        "HIGH" => Style::Magenta,
        "MEDIUM" => Style::Yellow,
        "LOW" => Style::Cyan,
        _ => Style::Dim,
    }
}

/// `text.padEnd(width)` in UTF-16 units.
fn pad_end(text: &str, width: usize) -> String {
    let units = text.encode_utf16().count();
    format!("{text}{}", " ".repeat(width.saturating_sub(units)))
}

/// `ui.table(columns, rows)`: the §2.7 table, each line indented by two spaces (data).
fn indented_table(out: &mut Output, labels: &[&str], rows: &[Vec<String>]) {
    let text = table::table(labels, rows);
    if text.is_empty() {
        return;
    }
    for line in text.lines() {
        out.data_line(&format!("  {line}"));
    }
}

/// The score and ASR pairs of a report block (each only when present and not `null`).
fn score_pairs(report: &OValue, asr_factor: f64) -> Vec<(String, String)> {
    let mut kv = Vec::new();
    if present(report.get("score")) {
        kv.push(("Score".to_owned(), shown(report, "score")));
    }
    if present(report.get("asr")) {
        let asr = number(report, "asr").map_or_else(String::new, |asr| fixed1(asr * asr_factor));
        kv.push(("ASR".to_owned(), format!("{asr}%")));
    }
    kv
}

/// The `Summary:` block when the summary is truthy: `    <summary>`, the summary
/// multi-line server text (continuation lines start at column 0, TS).
fn summary_block(out: &mut Output, report: &OValue) {
    if truthy(report.get("reportSummary")) {
        pretty::section(out, "Summary:");
        out.data_line(&format!("    {}", prose(report, "reportSummary")));
    }
}

/// `renderStaticReport`.
pub fn static_report_layout(out: &mut Output, report: &OValue) {
    pretty::section(out, "Static Scan Report:");
    let kv = score_pairs(report, 1.0);
    if !kv.is_empty() {
        key_values(out, &kv);
    }
    let breakdown = report
        .get("severityBreakdown")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    if !breakdown.is_empty() {
        pretty::section(out, "Severity Breakdown:");
        for stat in breakdown {
            let severity = shown(stat, "severity");
            let label = out.paint(severity_style(&severity), &pad_end(&severity, 10));
            let bypassed = out.paint(
                Style::Red,
                &format!("{} bypassed", shown(stat, "successful")),
            );
            let blocked = out.paint(Style::Green, &format!("{} blocked", shown(stat, "failed")));
            out.data_line(&format!("    {label} {bypassed}  {blocked}"));
        }
    }
    let categories = report
        .get("categories")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    if !categories.is_empty() {
        pretty::section(out, "Categories:");
        let rows: Vec<Vec<String>> = categories
            .iter()
            .map(|category| {
                vec![
                    shown(category, "displayName"),
                    format!(
                        "{}%",
                        number(category, "asr").map(fixed1).unwrap_or_default()
                    ),
                    format!(
                        "{}/{}",
                        shown(category, "successful"),
                        shown(category, "total")
                    ),
                ]
            })
            .collect();
        indented_table(out, &["Category", "ASR", "Bypassed/Total"], &rows);
    }
    summary_block(out, report);
    out.data_line("");
}

/// `renderDynamicReport` (the ASR is a fraction: × 100, TS).
pub fn dynamic_report_layout(out: &mut Output, report: &OValue) {
    pretty::section(out, "Dynamic Scan Report:");
    let mut kv = score_pairs(report, 100.0);
    if present(report.get("totalGoals")) || present(report.get("goalsAchieved")) {
        let or_zero = |key: &str| {
            if present(report.get(key)) {
                shown(report, key)
            } else {
                "0".to_owned()
            }
        };
        kv.push((
            "Goals".to_owned(),
            format!(
                "{} achieved / {} total",
                or_zero("goalsAchieved"),
                or_zero("totalGoals")
            ),
        ));
    }
    for (key, label) in [("totalStreams", "Streams"), ("totalThreats", "Threats")] {
        if present(report.get(key)) {
            kv.push((label.to_owned(), shown(report, key)));
        }
    }
    if !kv.is_empty() {
        key_values(out, &kv);
    }
    summary_block(out, report);
    out.data_line("");
}

/// `renderCustomReport`.
pub fn custom_report_layout(out: &mut Output, report: &OValue) {
    pretty::section(out, "Custom Attack Report:");
    let asr = number(report, "asr").map(fixed1).unwrap_or_default();
    key_values(
        out,
        &pairs([
            ("Score", shown(report, "score")),
            ("ASR", format!("{asr}%")),
            ("Attacks", shown(report, "totalAttacks")),
            ("Threats", shown(report, "totalThreats")),
        ]),
    );
    let sets = report
        .get("promptSets")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    if !sets.is_empty() {
        pretty::section(out, "Prompt Sets:");
        let rows: Vec<Vec<String>> = sets
            .iter()
            .map(|set| {
                vec![
                    shown(set, "promptSetName"),
                    format!(
                        "{}/{}",
                        shown(set, "totalThreats"),
                        shown(set, "totalPrompts")
                    ),
                    format!(
                        "{}%",
                        number(set, "threatRate").map(fixed1).unwrap_or_default()
                    ),
                ]
            })
            .collect();
        indented_table(out, &["Prompt Set", "Threats", "Threat Rate"], &rows);
    }
    out.data_line("");
}

/// `buildAttackListFootnote`: the list returned fewer attacks of `--severity` than the
/// breakdown expects.
pub fn attack_footnote(
    severity: Option<&str>,
    total_items: Option<f64>,
    report: &OValue,
) -> Option<String> {
    let (severity, total) = (severity?, total_items?);
    let row = report
        .get("severityBreakdown")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .find(|stat| text(stat, "severity") == Some(severity))?;
    let expected = number(row, "successful").unwrap_or(0.0) + number(row, "failed").unwrap_or(0.0);
    (total < expected).then(|| {
        format!(
            "(showing {} of {} expected for severity {} — list-attacks endpoint excludes some variants; tracking upstream divergence at #206)",
            js_number(total),
            js_number(expected),
            terminal_safe(severity)
        )
    })
}

/// `renderAttackList` with its footnote.
pub fn attack_list_layout(out: &mut Output, attacks: &[OValue], footnote: Option<&str>) {
    if attacks.is_empty() {
        pretty::empty_list(out, "attacks");
        if let Some(footnote) = footnote {
            pretty::dim(out, footnote);
        }
        return;
    }
    pretty::section(out, "Attacks:");
    for attack in attacks {
        let severity = if present(attack.get("severity")) && truthy(attack.get("severity")) {
            let severity = shown(attack, "severity");
            out.paint(severity_style(&severity), &pad_end(&severity, 10))
        } else {
            out.paint(Style::Dim, &pad_end("N/A", 10))
        };
        let result = if truthy(attack.get("successful")) {
            out.paint(Style::Red, "BYPASSED")
        } else {
            out.paint(Style::Green, "BLOCKED")
        };
        let label = if present(attack.get("subCategoryDisplayName")) {
            shown(attack, "subCategoryDisplayName")
        } else if present(attack.get("subCategory")) {
            shown(attack, "subCategory")
        } else {
            "—".to_owned()
        };
        let category = if truthy(attack.get("category")) {
            out.paint(Style::Dim, &format!(" [{}]", shown(attack, "category")))
        } else {
            String::new()
        };
        out.data_line(&format!("    {severity} {result}  {label}{category}"));
    }
    if let Some(footnote) = footnote {
        pretty::dim(out, footnote);
    }
    out.data_line("");
}

/// `renderCustomAttackList` (prompt previews of 80 UTF-16 units, D54).
pub fn custom_attack_list_layout(out: &mut Output, attacks: &[OValue]) {
    if attacks.is_empty() {
        pretty::empty_list(out, "custom attacks");
        return;
    }
    pretty::section(out, "Custom Attacks:");
    for attack in attacks {
        let result = if truthy(attack.get("threat")) {
            out.paint(Style::Red, "THREAT")
        } else {
            out.paint(Style::Green, "SAFE")
        };
        let asr = if present(attack.get("asr")) {
            let asr = number(attack, "asr").map(fixed1).unwrap_or_default();
            out.paint(Style::Dim, &format!(" ASR: {asr}%"))
        } else {
            String::new()
        };
        let prompt = preview(&prose(attack, "promptText"));
        out.data_line(&format!("    {result}{asr}  {prompt}"));
        if truthy(attack.get("goal")) {
            let goal = out.paint(Style::Dim, &prose(attack, "goal"));
            out.data_line(&format!("      {goal}"));
        }
    }
    out.data_line("");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;
    use crate::output::testing::{capture, capture_colored};

    fn pretty_bytes(render: impl FnOnce(&mut Output)) -> String {
        let (mut out, stdout, _) = capture(false);
        render(&mut out);
        out.commit().unwrap();
        stdout.text()
    }

    #[test]
    fn previews_and_fixed_decimals_follow_javascript() {
        assert_eq!(preview("short"), "short");
        let long = "Y".repeat(90);
        assert_eq!(preview(&long), format!("{}...", "Y".repeat(77)));
        assert_eq!(preview(&"x".repeat(80)), "x".repeat(80));
        // The 77th unit is the first half of a surrogate pair: the emoji is dropped (D54).
        let split = format!("{}🚀{}", "a".repeat(76), "b".repeat(10));
        assert_eq!(preview(&split), format!("{}...", "a".repeat(76)));
        assert_eq!(fixed1(12.345), "12.3");
        assert_eq!(fixed1(0.25), "0.3");
        assert_eq!(fixed1(20.0), "20.0");
        assert_eq!(fixed1(-0.04), "-0.0");
        assert_eq!(fixed1(-1.25), "-1.3");
    }

    #[test]
    fn scan_status_and_list_bytes() {
        let raw = parse(
            r#"{"uuid":"u1","name":"fixture-scan","target":{"name":"fixture-target"},"job_type":"STATIC","status":"COMPLETED","total":40,"completed":40,"score":7.5,"asr":12.345,"created_at":"2026-10-17T10:00:00Z"}"#,
        )
        .unwrap();
        let doc = job(&raw);
        assert_eq!(
            pretty_bytes(|out| scan_status_layout(out, &doc)),
            "\n  Scan Status:\n\n  ID        u1\n  Name      fixture-scan\n  Type      STATIC\n  Target    fixture-target\n  Status    COMPLETED\n  Progress  40/40\n  Score     7.5\n  ASR       12.3%\n\n"
        );
        let bare = parse(r#"{"uuid":"u2","name":"second","job_type":"DYNAMIC","status":"RUNNING","score":null,"created_at":null}"#).unwrap();
        let row = job_row(&job(&bare));
        assert_eq!(
            crate::json::to_compact(&row).unwrap(),
            r#"{"id":"u2","name":"second","status":"RUNNING","type":"DYNAMIC","score":"","createdAt":""}"#
        );
        let (mut out, stdout, _) = capture_colored(false);
        scan_list_layout(&mut out, &[job(&bare)]);
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  \u{1b}[1mRecent Scans:\u{1b}[22m\n\n  \u{1b}[2mu2\u{1b}[22m\n    second  \u{1b}[34mRUNNING\u{1b}[39m  DYNAMIC\n\n"
        );
    }

    #[test]
    fn categories_layout_and_table() {
        let doc = categories(
            &parse(r#"[{"id":"SECURITY","display_name":"Security","description":"Security attacks","sub_categories":[{"id":"JAILBREAK","display_name":"Jailbreak","description":"Bypass"},{"id":"PI","display_name":"Prompt injection","description":""}]},{"id":"EMPTY","display_name":"Empty","description":"","sub_categories":[]}]"#).unwrap(),
        );
        let text = pretty_bytes(|out| render_categories(out, Format::Pretty, &doc).unwrap());
        assert!(text.ends_with(
            "\n  Attack Categories:\n\n  Security (SECURITY) — Security attacks\n    • Jailbreak (JAILBREAK) — Bypass\n    • Prompt injection (PI)\n\n  Empty (EMPTY)\n\n"
        ));
        let table = pretty_bytes(|out| render_categories(out, Format::Table, &doc).unwrap());
        assert_eq!(
            table,
            " Category │ ID        │ Name             │ Description \n──────────┼───────────┼──────────────────┼─────────────\n SECURITY │ JAILBREAK │ Jailbreak        │ Bypass      \n SECURITY │ PI        │ Prompt injection │             \n EMPTY    │           │                  │             \n"
        );
        let empty = pretty_bytes(|out| {
            render_categories(out, Format::Pretty, &OValue::Array(vec![])).unwrap()
        });
        assert!(empty.ends_with("\n\n  No categories found\n"));
    }

    #[test]
    fn targets_drop_the_multi_turn_noise() {
        let raw = parse(r#"{"uuid":"t","name":"n","active":true,"target_metadata":{"multi_turn":false,"multi_turn_error_message":"noise","rate_limit":50}}"#).unwrap();
        let doc = target_detail(&raw);
        assert_eq!(
            crate::json::to_compact(doc.get("metadata").unwrap()).unwrap(),
            r#"{"multi_turn":false,"rate_limit":50}"#
        );
        let kept = parse(r#"{"multi_turn":true,"multi_turn_error_message":"kept"}"#).unwrap();
        assert_eq!(sanitize_metadata(Some(kept.clone())), Some(kept));
        assert_eq!(detail_value(&OValue::Null), "null");
        assert_eq!(
            detail_value(&parse(r#"{"a":["x"]}"#).unwrap()),
            "{\n    \"a\": [\n      \"x\"\n    ]\n  }"
        );
    }

    #[test]
    fn withholding_replaces_server_text_carrying_a_secret() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-TARGET-SECRET-99");
        let mut doc = parse(r#"[{"name":"echo FAKE-TARGET-SECRET-99","uuid":"u","nested":{"description":"plain"}}]"#).unwrap();
        withhold(&mut doc, &secrets);
        assert_eq!(
            crate::json::to_compact(&doc).unwrap(),
            r#"[{"name":"[withheld]","uuid":"u","nested":{"description":"plain"}}]"#
        );
        // Under any key, at any depth: a body template or an extra field that echoes a
        // registered credential is withheld too.
        let mut doc = parse(r#"{"connectionParams":{"request_json":{"input":"{INPUT}","auth":"FAKE-TARGET-SECRET-99"},"response_json":["x FAKE-TARGET-SECRET-99"]},"extraInfo":{"note":"FAKE-TARGET-SECRET-99"},"type":"SECRET","count":3}"#).unwrap();
        withhold(&mut doc, &secrets);
        assert_eq!(
            crate::json::to_compact(&doc).unwrap(),
            r#"{"connectionParams":{"request_json":{"input":"{INPUT}","auth":"[withheld]"},"response_json":["[withheld]"]},"extraInfo":{"note":"[withheld]"},"type":"SECRET","count":3}"#,
            "a fragment of a secret outside the server-text fields is kept"
        );
    }
}
