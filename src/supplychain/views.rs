//! The supplychain projections and layouts (DESIGN §20.3, §20.5–§20.8; TS `emit`,
//! `ag.ts:44-80`): the 9-key scan projection built from G71's tolerant scan and the 4-key
//! finding projection built from the typed SDK model, the record table (the union of the
//! record keys without `description` and `remediation`, cut to 9) and the field table (`Field │ Value`, D318), the status lines
//! (D313, D321), the JSON writer with C1 escapes (D212) and the `SecretSet` rule over every
//! printed string is the shared `secrets::withhold` (D47), applied by the commands.

use crate::error::CliError;
use crate::json::OValue;
use crate::output::{Format, Output, terminal_safe};
use crate::render::{cell_text, js_json_number, table};
use crate::supplychain::{member, scans};
use scm::airs::agentguard::models::{AgentGuardVulnerability, FiniteNumber};

/// The keys no record table shows (TS).
const FILTERED: [&str; 2] = ["description", "remediation"];
/// The record table's column cap (TS).
const MAX_COLUMNS: usize = 9;

/// The `--include-content` notice (D321; stderr, dim, quiet-suppressed).
pub const CONTENT_NOTICE: &str = "Finding content included: source code, file paths and finding text can contain secrets from the scanned artifacts; keep this output private.";

fn number(value: &FiniteNumber) -> OValue {
    OValue::Number(value.as_number().clone())
}

fn text(value: &str) -> OValue {
    OValue::String(value.to_owned())
}

/// The scan projection (TS `ag.ts:164-174`, §20.5): exactly these nine keys in this order,
/// read from the tolerant scan of G71 ([`scans::scan`]); a `null` (or absent) member is
/// `null`, and the counts are `null` when `summary` is, never `0`. Nothing else of the scan
/// (its name, git URL, fingerprint, device metadata, …) is ever read for output. For a scan
/// the SDK's schema accepts, the projection is the one the typed model gave (pinned by
/// `scans::tests`).
pub fn scan(scan: &scans::Scan) -> OValue {
    let optional = |value: &Option<String>| value.as_deref().map_or(OValue::Null, text);
    let count = |value: Option<&serde_json::Number>| {
        value.map_or(OValue::Null, |number| OValue::Number(number.clone()))
    };
    let summary = scan.summary.as_ref();
    OValue::Object(vec![
        member("uuid", text(&scan.uuid)),
        member("artifact_type", optional(&scan.artifact_type)),
        member("status", optional(&scan.status)),
        member("eval_outcome", optional(&scan.eval_outcome)),
        member("created_at", optional(&scan.created_at)),
        member(
            "vulnerability_count",
            count(summary.and_then(|summary| summary.vulnerability_count.as_ref())),
        ),
        member(
            "attack_chain_count",
            count(summary.and_then(|summary| summary.attack_chain_count.as_ref())),
        ),
        member("is_batch", scan.is_batch.map_or(OValue::Null, OValue::Bool)),
        member("parent_uuid", optional(&scan.parent_uuid)),
    ])
}

/// The default finding projection (TS `ag.ts:190-200`, §20.6): exactly four keys.
pub fn finding(finding: &AgentGuardVulnerability) -> OValue {
    OValue::Object(vec![
        member("uuid", text(&finding.uuid)),
        member("scan_uuid", text(&finding.scan_uuid)),
        member("vulnerability_type", text(&finding.vulnerability_type)),
        member("attack_chain_count", number(&finding.attack_chain_count)),
    ])
}

/// The record table (§20.3 "Record mode"): the union of the record keys in first-seen
/// order without `description` and `remediation`, the first nine, each label the key
/// with `_` read as a space; no rows is the empty string.
pub fn record_table(records: &[OValue]) -> String {
    let mut keys: Vec<&str> = Vec::new();
    for record in records {
        for (key, _) in record.as_object().unwrap_or_default() {
            if !FILTERED.contains(&key.as_str()) && !keys.contains(&key.as_str()) {
                keys.push(key);
            }
        }
    }
    keys.truncate(MAX_COLUMNS);
    let labels: Vec<String> = keys
        .iter()
        .map(|key| terminal_safe(key).replace('_', " "))
        .collect();
    let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|record| keys.iter().map(|key| cell_text(record.get(key))).collect())
        .collect();
    table::table(&labels, &rows)
}

/// A field-table value (TS `typeof v === 'object' ? JSON.stringify(v) : String(v)`):
/// `null` is `null`, objects and arrays compact JSON.
fn field_value(value: &OValue) -> String {
    match value {
        OValue::Null => "null".to_owned(),
        OValue::String(text) => terminal_safe(text).into_owned(),
        OValue::Number(number) => js_json_number(number),
        OValue::Bool(value) => value.to_string(),
        nested @ (OValue::Array(_) | OValue::Object(_)) => cell_text(Some(nested)),
    }
}

/// The field table (§20.3 "Field mode", D318): one `Field │ Value` row per top-level
/// member in the printed JSON order, whatever the members hold.
pub fn field_table(document: &OValue) -> String {
    let rows: Vec<Vec<String>> = document
        .as_object()
        .unwrap_or_default()
        .iter()
        .map(|(key, value)| vec![terminal_safe(key).into_owned(), field_value(value)])
        .collect();
    table::table(&["Field", "Value"], &rows)
}

/// The record-table status line (D313): complete, or truncated with the next offset.
pub fn status_line(returned: usize, next_offset: Option<u64>) -> String {
    match next_offset {
        None => format!("Returned {returned} records; see JSON for pagination metadata."),
        Some(next) => format!(
            "Returned {returned} records; more are available (next --offset {next}); see JSON for pagination metadata."
        ),
    }
}

/// `JSON.stringify(value, null, 2)` plus a newline, C1 controls escaped (D212).
pub fn json(out: &mut Output, document: &OValue) -> Result<(), CliError> {
    let text = crate::json::json_text(document)?;
    out.data_line(&text);
    Ok(())
}

/// A list document (`scans list`, `scans vulnerabilities`, `rules list`): the JSON text,
/// or the record table of `document[records]` and the status line (pretty is the table,
/// TS).
pub fn render_records(
    out: &mut Output,
    format: Format,
    document: &OValue,
    records: &str,
    next_offset: Option<u64>,
) -> Result<(), CliError> {
    if format == Format::Json {
        return json(out, document);
    }
    let rows = document
        .get(records)
        .and_then(OValue::as_array)
        .unwrap_or_default();
    out.data_line(&record_table(rows));
    out.status(&status_line(rows.len(), next_offset));
    Ok(())
}

/// The `stats` document: the JSON text or the field table, no status line (§20.7).
pub fn render_fields(out: &mut Output, format: Format, document: &OValue) -> Result<(), CliError> {
    if format == Format::Json {
        return json(out, document);
    }
    out.data_line(&field_table(document));
    Ok(())
}

#[cfg(test)]
mod tests;
