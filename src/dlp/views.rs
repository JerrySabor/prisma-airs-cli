//! The DLP documents and layouts (DESIGN §16.3 "JSON", "Server text", §16.4): the
//! camelCase JSON of a record (TS `camelize`, with the data keys under `tags` and
//! `exclusions.exclusion_list` kept, D171), the pretty list and get layouts (TS
//! `renderer/dlp.ts` bytes), the table projections, the `Updated` field and the page
//! status lines.
//!
//! Records arrive as ordered JSON from the SDK models (known keys in schema order,
//! extensions sorted, D35). Every server string printed in a pretty layout or a table
//! cell goes through `terminal_safe` (a get's `description` through
//! `terminal_safe_lines`, D52); a printed `name`, `description`, `region_name` or
//! `category` that carries a secret of the invocation is `[withheld]` in every format.

use super::Kind;
use crate::error::{CliError, SecretSet};
use crate::json::OValue;
use crate::output::{Format, Output, terminal_safe, terminal_safe_lines};
use crate::render::style::Style;
use crate::render::{cell_text, js_json_number, pretty, table};

/// The server-text keys checked against the invocation's secrets.
const TEXT_KEYS: [&str; 4] = ["name", "description", "region_name", "category"];

/// `[withheld]` for every string under a [`TEXT_KEYS`] key (at any depth) that contains a
/// registered secret form (raw, trimmed, form-encoded or base64). Ids, statuses,
/// versions and timestamps are not checked.
pub fn withhold(doc: &mut OValue, secrets: &SecretSet) {
    match doc {
        OValue::Array(items) => {
            for item in items {
                withhold(item, secrets);
            }
        }
        OValue::Object(entries) => {
            for (key, value) in entries {
                match value {
                    OValue::String(text) if TEXT_KEYS.contains(&key.as_str()) => {
                        if secrets.carried_by(text) {
                            *text = crate::error::WITHHELD.to_owned();
                        }
                    }
                    other => withhold(other, secrets),
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// camelCase JSON (D171)
// ---------------------------------------------------------------------------

/// TS `camelKey`: every `_x` or `-x` with `x` in `[a-z0-9]` becomes `X`.
pub fn camel_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut chars = key.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '_' | '-')
            && let Some(&next) = chars.peek()
            && (next.is_ascii_lowercase() || next.is_ascii_digit())
        {
            out.push(next.to_ascii_uppercase());
            chars.next();
        } else {
            out.push(c);
        }
    }
    out
}

/// Where a value sits: under `exclusions` the `exclusion_list` keys are data.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Under {
    Record,
    Exclusions,
}

/// The camelCase document of a record: every object key camelCased (TS `camelize`),
/// except the keys of the object under a `tags` key and under
/// `exclusions.exclusion_list`, which are the user's data and kept verbatim (D171).
pub fn camelize(value: &OValue) -> OValue {
    convert(value, Under::Record)
}

fn convert(value: &OValue, under: Under) -> OValue {
    match value {
        OValue::Array(items) => OValue::Array(
            items
                .iter()
                .map(|item| convert(item, Under::Record))
                .collect(),
        ),
        OValue::Object(entries) => {
            let mut out: Vec<(String, OValue)> = Vec::with_capacity(entries.len());
            for (key, child) in entries {
                let data_keys =
                    key == "tags" || (under == Under::Exclusions && key == "exclusion_list");
                let converted = match child {
                    OValue::Object(data) if data_keys => OValue::Object(
                        data.iter()
                            .map(|(name, item)| (name.clone(), convert(item, Under::Record)))
                            .collect(),
                    ),
                    _ if key == "exclusions" => convert(child, Under::Exclusions),
                    _ => convert(child, Under::Record),
                };
                put(&mut out, camel_key(key), converted);
            }
            OValue::Object(out)
        }
        other => other.clone(),
    }
}

/// `Object.fromEntries`: a repeated key keeps its first position and takes the last value.
fn put(entries: &mut Vec<(String, OValue)>, key: String, value: OValue) {
    match entries.iter_mut().find(|(name, _)| *name == key) {
        Some((_, slot)) => *slot = value,
        None => entries.push((key, value)),
    }
}

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

/// A field at `path` (`["detection_config", "technique"]`).
fn at<'a>(row: &'a OValue, path: &[&str]) -> Option<&'a OValue> {
    path.iter().try_fold(row, |value, key| value.get(key))
}

/// `String(v)` of a present, non-null scalar (strings terminal-safe); `None` for an
/// absent or `null` value.
fn text(value: Option<&OValue>) -> Option<String> {
    match value? {
        OValue::Null => None,
        OValue::String(text) => Some(terminal_safe(text).into_owned()),
        OValue::Number(number) => Some(js_json_number(number)),
        OValue::Bool(value) => Some(value.to_string()),
        nested => {
            Some(terminal_safe(&crate::json::to_compact(nested).unwrap_or_default()).into_owned())
        }
    }
}

/// JavaScript truthiness of a field.
fn truthy(value: Option<&OValue>) -> bool {
    crate::redteam::views::truthy(value)
}

/// The length of an array field.
fn array_len(value: Option<&OValue>) -> Option<usize> {
    value.and_then(OValue::as_array).map(<[OValue]>::len)
}

/// TS `statusColor`: `active` green, `deleted`/`disabled` yellow, any other dim, a
/// missing (falsy) one a dim `—`.
fn status_span(out: &Output, status: Option<&OValue>) -> String {
    match text(status).filter(|status| !status.is_empty()) {
        Some(status) => {
            let style = match status.as_str() {
                "active" => Style::Green,
                "deleted" | "disabled" => Style::Yellow,
                _ => Style::Dim,
            };
            out.paint(style, &status)
        }
        None => out.paint(Style::Dim, "—"),
    }
}

/// A dim ` <prefix><value>` span when the field is truthy (TS `x ? chalk.dim(...) : ''`).
fn dim_if_truthy(out: &Output, value: Option<&OValue>, prefix: &str) -> String {
    if truthy(value) {
        out.paint(
            Style::Dim,
            &format!(" {prefix}{}", text(value).unwrap_or_default()),
        )
    } else {
        String::new()
    }
}

/// The dim ` v<version>` span when the version is not `null` (TS `!= null`).
fn version_span(out: &Output, row: &OValue) -> String {
    match text(row.get("version")) {
        Some(version) => out.paint(Style::Dim, &format!(" v{version}")),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// `Updated` (§16.4)
// ---------------------------------------------------------------------------

/// The largest JavaScript time value (`±8.64e15` ms).
const MAX_TIME: f64 = 8.64e15;

/// `audit_metadata.updated_at` as `Date.prototype.toISOString`: a number is epoch
/// milliseconds (truncated, within ±8.64e15, else dropped; `0` dropped as falsy, TS); a
/// string is accepted when it is an ISO 8601 date (`YYYY`, `YYYY-MM`, `YYYY-MM-DD`, UTC)
/// or a date-time with a `Z` or `±hh:mm` offset, normalised to UTC; anything else is
/// dropped (D56: JavaScript `Date` also reads other forms, and an ISO date-time without an
/// offset as local time).
pub fn updated(row: &OValue) -> Option<String> {
    let ms = match at(row, &["audit_metadata", "updated_at"])? {
        OValue::Number(number) => {
            let ms = number.as_f64()?;
            if ms == 0.0 || !ms.is_finite() || ms.abs() > MAX_TIME {
                return None;
            }
            // Checked: finite and within ±8.64e15, so the cast is exact after `trunc`.
            #[allow(clippy::cast_possible_truncation)]
            let ms = ms.trunc() as i64;
            ms
        }
        OValue::String(text) if !text.is_empty() => {
            let iso = match text.len() {
                4 => format!("{text}-01-01T00:00Z"),
                7 => format!("{text}-01T00:00Z"),
                10 => format!("{text}T00:00Z"),
                _ => text.clone(),
            };
            let ms = crate::report::parse_iso(&iso)?;
            if ms.unsigned_abs() > 8_640_000_000_000_000 {
                return None;
            }
            ms
        }
        _ => return None,
    };
    Some(iso(ms))
}

/// `Date.prototype.toISOString` of epoch milliseconds (any sign; years outside
/// 0–9999 in the six-digit signed form).
pub fn iso(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000
    )
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

// ---------------------------------------------------------------------------
// Lists (§16.4)
// ---------------------------------------------------------------------------

/// The table columns of a list: label and the record path of its value (`keywords` is
/// the count, empty without keywords).
fn columns(kind: Kind) -> &'static [(&'static str, &'static [&'static str])] {
    match kind {
        Kind::FilteringProfile => &[
            ("ID", &["id"]),
            ("Name", &["name"]),
            ("Type", &["type"]),
            ("Direction", &["direction"]),
            ("Severity", &["log_severity"]),
            ("Version", &["version"]),
        ],
        Kind::Pattern => &[
            ("ID", &["id"]),
            ("Name", &["name"]),
            ("Type", &["type"]),
            ("Status", &["status"]),
            ("Technique", &["detection_config", "technique"]),
            ("Version", &["version"]),
        ],
        Kind::Profile => &[
            ("ID", &["id"]),
            ("Name", &["name"]),
            ("Type", &["type"]),
            ("Profile Type", &["profile_type"]),
            ("Status", &["profile_status"]),
            ("Version", &["version"]),
        ],
        Kind::Dictionary => &[
            ("ID", &["id"]),
            ("Name", &["name"]),
            ("Type", &["type"]),
            ("Status", &["status"]),
            ("Keywords", &["keywords"]),
            ("Version", &["version"]),
        ],
    }
}

/// One table row of a list.
fn table_row(kind: Kind, row: &OValue) -> Vec<String> {
    columns(kind)
        .iter()
        .map(|(label, path)| {
            if *label == "Keywords" {
                array_len(at(row, path)).map_or_else(String::new, |n| n.to_string())
            } else {
                cell_text(at(row, path))
            }
        })
        .collect()
}

/// One pretty list entry (TS `prettyLine`): the dim id line (omitted for a row without
/// an id, D56), then the name (empty when missing, D56) and the record's spans.
fn entry(out: &Output, kind: Kind, row: &OValue) -> String {
    let mut line = String::new();
    if let Some(id) = text_of_id(row) {
        line.push_str(&format!("  {}\n", out.paint(Style::Dim, &id)));
    }
    let name = text(row.get("name")).unwrap_or_default();
    let kind_span = out.paint(Style::Cyan, &text(row.get("type")).unwrap_or_default());
    let version = version_span(out, row);
    let rest = match kind {
        Kind::FilteringProfile => format!(
            "{kind_span}{}{}{version}",
            dim_if_truthy(out, row.get("direction"), "dir:"),
            dim_if_truthy(out, row.get("log_severity"), "sev:"),
        ),
        Kind::Pattern => format!(
            "{kind_span}  {}{}{version}",
            status_span(out, row.get("status")),
            dim_if_truthy(out, at(row, &["detection_config", "technique"]), ""),
        ),
        Kind::Profile => format!(
            "{kind_span}  {}{}{version}",
            status_span(out, row.get("profile_status")),
            dim_if_truthy(out, row.get("profile_type"), ""),
        ),
        Kind::Dictionary => {
            let keywords = match array_len(row.get("keywords")) {
                Some(count) => out.paint(Style::Dim, &format!(" {count} kw")),
                None => String::new(),
            };
            format!(
                "{kind_span}  {}{keywords}{version}",
                status_span(out, row.get("status")),
            )
        }
    };
    line.push_str(&format!("    {name}  {rest}"));
    line
}

/// The id of a row as printed (`None` when absent or `null`).
fn text_of_id(row: &OValue) -> Option<String> {
    text(row.get("id"))
}

/// A list in `format` (rows raw, already withheld): json is the bare array of camelCase
/// records (`[]` when empty), table the projection (nothing when empty), pretty the
/// heading (decoration), the entries and a blank line, or `No <header> found`.
pub fn render_list(
    out: &mut Output,
    kind: Kind,
    format: Format,
    rows: &[OValue],
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(&OValue::Array(rows.iter().map(camelize).collect())),
        Format::Table => {
            if !rows.is_empty() {
                let labels: Vec<&str> = columns(kind).iter().map(|(label, _)| *label).collect();
                let cells: Vec<Vec<String>> = rows.iter().map(|row| table_row(kind, row)).collect();
                out.data_line(&table::table(&labels, &cells));
            }
            Ok(())
        }
        Format::Pretty => {
            if rows.is_empty() {
                pretty::empty_list(out, &kind.list_header().to_lowercase());
                return Ok(());
            }
            pretty::section(out, &format!("{}:", kind.list_header()));
            for row in rows {
                let line = entry(out, kind, row);
                out.data_line(&line);
            }
            out.data_line("");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Gets (§16.4)
// ---------------------------------------------------------------------------

/// The pretty get fields of a record, in TS order, with the absent, `null` and `""`
/// values dropped.
fn get_fields(kind: Kind, row: &OValue) -> Vec<(&'static str, String)> {
    let field = |path: &[&str]| text(at(row, path));
    let description = match row.get("description") {
        Some(OValue::String(text)) => Some(terminal_safe_lines(text).into_owned()),
        other => text(other),
    };
    let count = |path: &[&str]| array_len(at(row, path)).map(|n| n.to_string());
    let yes_no = |key: &str| Some(if truthy(row.get(key)) { "yes" } else { "no" }.to_owned());
    let fields: Vec<(&'static str, Option<String>)> = match kind {
        Kind::FilteringProfile => vec![
            ("ID", field(&["id"])),
            ("Name", field(&["name"])),
            ("Type", field(&["type"])),
            ("Data Profile", field(&["data_profile_id"])),
            ("Direction", field(&["direction"])),
            ("Severity", field(&["log_severity"])),
            ("Scan Type", field(&["scan_type"])),
            ("File Based", yes_no("file_based")),
            ("Non-File Based", yes_no("non_file_based")),
            ("Version", field(&["version"])),
            ("File Types", count(&["file_type"])),
            ("Updated", updated(row)),
        ],
        Kind::Pattern => {
            let confidence = at(row, &["detection_config", "supported_confidence_levels"])
                .and_then(OValue::as_array)
                .map(|levels| {
                    levels
                        .iter()
                        .map(|level| text(Some(level)).unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join(", ")
                });
            vec![
                ("ID", field(&["id"])),
                ("Name", field(&["name"])),
                ("Description", description),
                ("Type", field(&["type"])),
                ("Status", field(&["status"])),
                ("Technique", field(&["detection_config", "technique"])),
                ("Confidence", confidence),
                ("Regexes", count(&["matching_rules", "regexes"])),
                ("Version", field(&["version"])),
                ("Updated", updated(row)),
            ]
        }
        Kind::Profile => vec![
            ("ID", field(&["id"])),
            ("Name", field(&["name"])),
            ("Description", description),
            ("Type", field(&["type"])),
            ("Profile Type", field(&["profile_type"])),
            ("Status", field(&["profile_status"])),
            ("Version", field(&["version"])),
            ("Updated", updated(row)),
        ],
        Kind::Dictionary => vec![
            ("ID", field(&["id"])),
            ("Name", field(&["name"])),
            ("Description", description),
            ("Type", field(&["type"])),
            ("Status", field(&["status"])),
            ("Keywords", count(&["keywords"])),
            ("Version", field(&["version"])),
            ("Updated", updated(row)),
        ],
    };
    fields
        .into_iter()
        .filter_map(|(label, value)| value.filter(|value| !value.is_empty()).map(|v| (label, v)))
        .collect()
}

/// A get in `format` (the record raw, already withheld): json is the camelCase record,
/// table its `Key │ Value` table (objects and arrays as compact JSON), pretty the heading
/// (decoration), the key/value block and a blank line.
pub fn render_get(
    out: &mut Output,
    kind: Kind,
    format: Format,
    row: &OValue,
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(&camelize(row)),
        Format::Table => {
            crate::redteam::views::detail_table(out, &camelize(row));
            Ok(())
        }
        Format::Pretty => {
            pretty::section(out, &format!("{}:", kind.get_title()));
            pretty::key_value(out, &get_fields(kind, row));
            out.data_line("");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Acks (§16.3 "Streams, quiet and formats", D172)
// ---------------------------------------------------------------------------

/// TS `ackObject`: `{action}` plus, when not `null`, `id`, `name`, `type`, `status`
/// (`profile_status` overwrites it) and `version`, in that order (not camelCased).
pub fn ack_doc(action: &str, record: &OValue) -> OValue {
    let mut out: Vec<(String, OValue)> =
        vec![("action".to_owned(), OValue::String(action.to_owned()))];
    let present = |key: &str| {
        record
            .get(key)
            .filter(|value| !matches!(value, OValue::Null))
    };
    for key in ["id", "name", "type"] {
        if let Some(value) = present(key) {
            out.push((key.to_owned(), value.clone()));
        }
    }
    let status = present("profile_status").or_else(|| present("status"));
    if let Some(status) = status {
        out.push(("status".to_owned(), status.clone()));
    }
    if let Some(version) = present("version") {
        out.push(("version".to_owned(), version.clone()));
    }
    OValue::Object(out)
}

/// The success line of an ack (TS `  ✓ <verb> <id>  <name>[ v<version>]`).
pub fn ack_line(action: &str, record: &OValue) -> String {
    let field = |key: &str| match record.get(key) {
        None | Some(OValue::Null) => String::new(),
        other => text(other).unwrap_or_default(),
    };
    let version = match record.get("version") {
        None | Some(OValue::Null) => String::new(),
        other => format!(" v{}", text(other).unwrap_or_default()),
    };
    format!("{action} {}  {}{version}", field("id"), field("name"))
}

/// An ack in `format` (the record already withheld): json the ack document on stdout,
/// table its one-row table (columns are its keys), pretty nothing on stdout; then the
/// success line on stderr in every format (quiet-suppressed).
pub fn render_ack(
    out: &mut Output,
    format: Format,
    action: &str,
    record: &OValue,
) -> Result<(), CliError> {
    render_ack_doc(out, format, &ack_doc(action, record))?;
    out.success(&ack_line(action, record));
    Ok(())
}

/// The data part of an ack document (json or its one-row table; nothing in pretty).
pub fn render_ack_doc(out: &mut Output, format: Format, doc: &OValue) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(doc),
        Format::Table => {
            let entries = doc.as_object().unwrap_or_default();
            let labels: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
            let row: Vec<String> = entries
                .iter()
                .map(|(_, value)| cell_text(Some(value)))
                .collect();
            out.data_line(&table::table(&labels, &[row]));
            Ok(())
        }
        Format::Pretty => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Status lines (§16.3)
// ---------------------------------------------------------------------------

/// A single server page: `Showing <rows> of <total>[ (next --offset <k>)]` with the
/// server's total and `k = (page + 1) × size` when `k < total` (TS `pageMeta`), else
/// `Showing <rows>` when the page reports no total.
pub fn server_page_status(page: &OValue, returned: usize) -> String {
    let (number, size, total) = super::walk::status_numbers(page, returned);
    match total {
        Some(total) => {
            let next = number.saturating_add(1).saturating_mul(size);
            if next < total {
                format!("Showing {returned} of {total} (next --offset {next})")
            } else {
                format!("Showing {returned} of {total}")
            }
        }
        None => format!("Showing {returned}"),
    }
}

/// A client slice: `Showing <rows> of <custom rows>[ (next --offset <k>)]`, `k` the end of
/// the slice when rows remain after it.
pub fn slice_status(returned: usize, total: usize, next: Option<u64>) -> String {
    match next {
        Some(next) if next < total as u64 => {
            format!("Showing {returned} of {total} (next --offset {next})")
        }
        _ => format!("Showing {returned} of {total}"),
    }
}

/// A complete `--all` listing: `Showing <n> of <n>` (TS).
pub fn all_status(returned: usize) -> String {
    format!("Showing {returned} of {returned}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing::{capture, capture_colored};

    fn parse(text: &str) -> OValue {
        crate::json::parse(text).unwrap()
    }

    fn compact(value: &OValue) -> String {
        crate::json::to_compact(value).unwrap()
    }

    #[test]
    fn camel_keys_follow_the_typescript_regex() {
        for (raw, camel) in [
            ("detection_config", "detectionConfig"),
            ("supported_confidence_levels", "supportedConfidenceLevels"),
            ("is_parent_managed", "isParentManaged"),
            ("rule1", "rule1"),
            ("page_size2", "pageSize2"),
            ("x_1", "x1"),
            ("kebab-case-key", "kebabCaseKey"),
            ("Some_Category", "Some_Category"),
            ("trailing_", "trailing_"),
            ("double__x", "double_X"),
            ("dataProfileId", "dataProfileId"),
        ] {
            assert_eq!(camel_key(raw), camel, "{raw}");
        }
    }

    /// TS `dlp-renderer.spec.ts`: the full record, camelCased (D171 keeps data keys).
    #[test]
    fn camelize_keeps_the_data_keys_of_tags_and_exclusion_lists() {
        let record = parse(
            r#"{"id":"a","data_profile_id":1,"scan_type":"include","file_based":true,"non_file_based":false,"file_type":["txt"],"tags":{"my_tag":["v"],"compliance":["PCI"]},"exclusions":{"app_exclusion_list":[{"app_id":"x"}],"exclusion_list":{"my_category":["a_b"],"Some_Category":[]}},"detection_config":{"technique":"regex","supported_confidence_levels":["high"]},"audit_metadata":{"updated_at":1}}"#,
        );
        assert_eq!(
            compact(&camelize(&record)),
            r#"{"id":"a","dataProfileId":1,"scanType":"include","fileBased":true,"nonFileBased":false,"fileType":["txt"],"tags":{"my_tag":["v"],"compliance":["PCI"]},"exclusions":{"appExclusionList":[{"appId":"x"}],"exclusionList":{"my_category":["a_b"],"Some_Category":[]}},"detectionConfig":{"technique":"regex","supportedConfidenceLevels":["high"]},"auditMetadata":{"updatedAt":1}}"#
        );
        // `exclusion_list` elsewhere is an ordinary field name.
        assert_eq!(
            compact(&camelize(&parse(r#"{"x":{"exclusion_list":{"a_b":1}}}"#))),
            r#"{"x":{"exclusionList":{"aB":1}}}"#
        );
        // A repeated key after camelCasing keeps its first position and the last value.
        assert_eq!(
            compact(&camelize(&parse(r#"{"file_type":1,"x":2,"fileType":3}"#))),
            r#"{"fileType":3,"x":2}"#
        );
    }

    #[test]
    fn withhold_checks_the_text_keys_at_any_depth() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-SECRET-100");
        let mut doc = parse(
            r#"{"id":"FAKE-SECRET-100","name":"x FAKE-SECRET-100","description":"ok","region_name":"FAKE-SECRET-100","category":"c","detection_rules":[{"rule_item":{"name":"FAKE-SECRET-100"}}],"keywords":["FAKE-SECRET-100"]}"#,
        );
        withhold(&mut doc, &secrets);
        assert_eq!(
            compact(&doc),
            r#"{"id":"FAKE-SECRET-100","name":"[withheld]","description":"ok","region_name":"[withheld]","category":"c","detection_rules":[{"rule_item":{"name":"[withheld]"}}],"keywords":["FAKE-SECRET-100"]}"#
        );
    }

    #[test]
    fn updated_is_to_iso_string_of_numbers_and_iso_strings_only() {
        let at = |value: &str| {
            updated(&parse(&format!(
                r#"{{"audit_metadata":{{"updated_at":{value}}}}}"#
            )))
        };
        assert_eq!(
            at("1700000000000").as_deref(),
            Some("2023-11-14T22:13:20.000Z")
        );
        assert_eq!(
            at("1700000000000.9").as_deref(),
            Some("2023-11-14T22:13:20.000Z")
        );
        assert_eq!(at("-1").as_deref(), Some("1969-12-31T23:59:59.999Z"));
        assert_eq!(
            at("8.64e15").as_deref(),
            Some("+275760-09-13T00:00:00.000Z")
        );
        assert_eq!(
            at("-8.64e15").as_deref(),
            Some("-271821-04-20T00:00:00.000Z")
        );
        assert_eq!(
            at("8.64e15 ").as_deref(),
            Some("+275760-09-13T00:00:00.000Z")
        );
        for dropped in [
            "0",
            "8.7e15",
            "null",
            "true",
            "\"\"",
            "\"yesterday\"",
            "\"1700000000000\"",
            "\"2026-10-02T00:00:00\"",
            "{}",
        ] {
            assert_eq!(at(dropped), None, "{dropped}");
        }
        assert_eq!(
            at("\"2026-10-02T00:00:00Z\"").as_deref(),
            Some("2026-10-02T00:00:00.000Z")
        );
        assert_eq!(
            at("\"2026-10-02T01:30:00.5+01:30\"").as_deref(),
            Some("2026-10-02T00:00:00.500Z")
        );
        assert_eq!(
            at("\"2026-10-02\"").as_deref(),
            Some("2026-10-02T00:00:00.000Z")
        );
        assert_eq!(
            at("\"2026-10\"").as_deref(),
            Some("2026-10-01T00:00:00.000Z")
        );
        assert_eq!(at("\"2026\"").as_deref(), Some("2026-01-01T00:00:00.000Z"));
        assert_eq!(updated(&parse(r#"{"audit_metadata":null}"#)), None);
        assert_eq!(updated(&parse("{}")), None);
    }

    fn pattern_rows() -> Vec<OValue> {
        vec![
            parse(
                r#"{"id":"p-cus-1","name":"My Pattern","type":"custom","status":"active","version":1,"detection_config":{"technique":"regex"}}"#,
            ),
            parse(
                r#"{"id":"p-dis-1","name":"Disabled Pattern","type":"custom","status":"disabled","version":4,"detection_config":{"technique":"weighted_regex"}}"#,
            ),
        ]
    }

    /// TD§3.5 captures.
    #[test]
    fn pretty_lists_are_the_typescript_bytes() {
        let (mut out, stdout, _) = capture(false);
        render_list(&mut out, Kind::Pattern, Format::Pretty, &pattern_rows()).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Data Patterns:\n\n  p-cus-1\n    My Pattern  custom  active regex v1\n  p-dis-1\n    Disabled Pattern  custom  disabled weighted_regex v4\n\n"
        );
        let (mut out, stdout, _) = capture(true);
        render_list(&mut out, Kind::Pattern, Format::Pretty, &pattern_rows()).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "  p-cus-1\n    My Pattern  custom  active regex v1\n  p-dis-1\n    Disabled Pattern  custom  disabled weighted_regex v4\n\n",
            "--quiet keeps the entries (TS)"
        );
        let rows = vec![
            parse(
                r#"{"id":"fp-1","name":"Bulk CCN","type":"predefined","direction":"c2s","log_severity":"low","version":1}"#,
            ),
            parse(r#"{"id":"fp-2","name":"Custom FP","type":"custom","version":2}"#),
        ];
        let (mut out, stdout, _) = capture(false);
        render_list(&mut out, Kind::FilteringProfile, Format::Pretty, &rows).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Data Filtering Profiles:\n\n  fp-1\n    Bulk CCN  predefined dir:c2s sev:low v1\n  fp-2\n    Custom FP  custom v2\n\n"
        );
        let rows = vec![
            parse(
                r#"{"id":"d-pre-1","name":"Predef Dict","type":"predefined","status":"active","version":1}"#,
            ),
            parse(
                r#"{"id":"d-cus-1","name":"My Dict","type":"custom","status":"active","version":2,"keywords":["a","b"]}"#,
            ),
        ];
        let (mut out, stdout, _) = capture(false);
        render_list(&mut out, Kind::Dictionary, Format::Pretty, &rows).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Data Dictionaries:\n\n  d-pre-1\n    Predef Dict  predefined  active v1\n  d-cus-1\n    My Dict  custom  active 2 kw v2\n\n"
        );
        for (kind, phrase) in [
            (Kind::Pattern, "  No data patterns found\n"),
            (Kind::Profile, "  No data profiles found\n"),
            (
                Kind::FilteringProfile,
                "  No data filtering profiles found\n",
            ),
            (Kind::Dictionary, "  No data dictionaries found\n"),
        ] {
            let (mut out, stdout, _) = capture(false);
            render_list(&mut out, kind, Format::Pretty, &[]).unwrap();
            out.commit().unwrap();
            assert_eq!(stdout.text(), phrase);
        }
    }

    /// D56 (0.7): a row without an id omits the id line; a missing name, type or status
    /// prints as empty / a dim dash.
    #[test]
    fn missing_fields_in_a_pretty_entry() {
        let (mut out, stdout, _) = capture(false);
        render_list(
            &mut out,
            Kind::Profile,
            Format::Pretty,
            &[parse(r#"{"name":null,"profile_type":"advanced"}"#)],
        )
        .unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Data Profiles:\n\n        — advanced\n\n"
        );
    }

    /// TD§2.3: the colour spans.
    #[test]
    fn coloured_entries_use_the_typescript_spans() {
        let (mut out, stdout, _) = capture_colored(false);
        render_list(
            &mut out,
            Kind::Pattern,
            Format::Pretty,
            &pattern_rows()[..1],
        )
        .unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  \u{1b}[1mData Patterns:\u{1b}[22m\n\n  \u{1b}[2mp-cus-1\u{1b}[22m\n    My Pattern  \u{1b}[36mcustom\u{1b}[39m  \u{1b}[32mactive\u{1b}[39m\u{1b}[2m regex\u{1b}[22m\u{1b}[2m v1\u{1b}[22m\n\n"
        );
        let (mut out, stdout, _) = capture_colored(false);
        render_list(
            &mut out,
            Kind::Dictionary,
            Format::Pretty,
            &[
                parse(r#"{"id":"d","name":"n","status":"deleted"}"#),
                parse(r#"{"id":"e","name":"m","status":"weird"}"#),
            ],
        )
        .unwrap();
        out.commit().unwrap();
        let text = stdout.text();
        assert!(text.contains("  \u{1b}[33mdeleted\u{1b}[39m\n"), "{text:?}");
        assert!(text.contains("  \u{1b}[2mweird\u{1b}[22m\n"), "{text:?}");
    }

    /// TD§3.5 table capture.
    #[test]
    fn table_lists_are_the_typescript_bytes() {
        let mut rows = vec![parse(
            r#"{"id":"p-pre-1","name":"Credit Card Number","type":"predefined","status":"active","version":2,"detection_config":{"technique":"regex"}}"#,
        )];
        rows.extend(pattern_rows());
        let (mut out, stdout, _) = capture(false);
        render_list(&mut out, Kind::Pattern, Format::Table, &rows).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            " ID      │ Name               │ Type       │ Status   │ Technique      │ Version \n─────────┼────────────────────┼────────────┼──────────┼────────────────┼─────────\n p-pre-1 │ Credit Card Number │ predefined │ active   │ regex          │ 2       \n p-cus-1 │ My Pattern         │ custom     │ active   │ regex          │ 1       \n p-dis-1 │ Disabled Pattern   │ custom     │ disabled │ weighted_regex │ 4       \n"
        );
        let (mut out, stdout, _) = capture(false);
        render_list(&mut out, Kind::Dictionary, Format::Table, &[]).unwrap();
        out.commit().unwrap();
        assert_eq!(stdout.text(), "", "an empty table prints nothing");
        let (mut out, stdout, _) = capture(false);
        render_list(
            &mut out,
            Kind::Dictionary,
            Format::Table,
            &[
                parse(r#"{"id":"d","keywords":["a","b","c"]}"#),
                parse(r#"{"id":"e"}"#),
            ],
        )
        .unwrap();
        out.commit().unwrap();
        assert!(
            stdout
                .text()
                .contains(" d  │      │      │        │ 3        │         \n"),
            "{:?}",
            stdout.text()
        );
    }

    /// TD§4 captures.
    #[test]
    fn pretty_gets_are_the_typescript_bytes() {
        let pattern = parse(
            r#"{"id":"p-cus-1","name":"My Pattern","description":"desc one","type":"custom","status":"active","version":1,"detection_config":{"technique":"regex","supported_confidence_levels":["high"]},"matching_rules":{"regexes":[{"regex":"x","weight":1}]},"audit_metadata":{"updated_at":1700000000000}}"#,
        );
        let (mut out, stdout, _) = capture(false);
        render_get(&mut out, Kind::Pattern, Format::Pretty, &pattern).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Data Pattern:\n\n  ID           p-cus-1\n  Name         My Pattern\n  Description  desc one\n  Type         custom\n  Status       active\n  Technique    regex\n  Confidence   high\n  Regexes      1\n  Version      1\n  Updated      2023-11-14T22:13:20.000Z\n\n"
        );
        let profile = parse(
            r#"{"id":"fp-1","name":"Bulk CCN","type":"predefined","data_profile_id":11995031,"direction":"c2s","log_severity":"low","scan_type":"include","file_based":true,"non_file_based":false,"version":1,"file_type":["a","b"],"audit_metadata":{"updated_at":1700000000000}}"#,
        );
        let (mut out, stdout, _) = capture(false);
        render_get(&mut out, Kind::FilteringProfile, Format::Pretty, &profile).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Data Filtering Profile:\n\n  ID              fp-1\n  Name            Bulk CCN\n  Type            predefined\n  Data Profile    11995031\n  Direction       c2s\n  Severity        low\n  Scan Type       include\n  File Based      yes\n  Non-File Based  no\n  Version         1\n  File Types      2\n  Updated         2023-11-14T22:13:20.000Z\n\n"
        );
        // A multi-line description keeps its line breaks; other controls are replaced.
        let dictionary = parse(
            r#"{"id":"d","name":"N\u001b[31m","description":"one\ntwo\u0007","keywords":[]}"#,
        );
        let (mut out, stdout, _) = capture(true);
        render_get(&mut out, Kind::Dictionary, Format::Pretty, &dictionary).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "  ID           d\n  Name         N\u{fffd}[31m\n  Description  one\ntwo\u{fffd}\n  Keywords     0\n\n"
        );
    }

    #[test]
    fn table_and_json_gets_are_the_camel_case_record() {
        let record = parse(
            r#"{"id":"d1","name":"n","keywords":["k1","k2"],"tags":{"my_tag":["x"]},"is_case_sensitive":false,"description":null}"#,
        );
        let (mut out, stdout, _) = capture(false);
        render_get(&mut out, Kind::Dictionary, Format::Table, &record).unwrap();
        out.commit().unwrap();
        let expected = table::key_value_table(
            [
                ("id", "d1"),
                ("name", "n"),
                ("keywords", r#"["k1","k2"]"#),
                ("tags", r#"{"my_tag":["x"]}"#),
                ("isCaseSensitive", "false"),
                ("description", ""),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
        );
        assert_eq!(stdout.text(), format!("{expected}\n"));
        let (mut out, stdout, _) = capture(false);
        render_get(&mut out, Kind::Dictionary, Format::Json, &record).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "{\n  \"id\": \"d1\",\n  \"name\": \"n\",\n  \"keywords\": [\n    \"k1\",\n    \"k2\"\n  ],\n  \"tags\": {\n    \"my_tag\": [\n      \"x\"\n    ]\n  },\n  \"isCaseSensitive\": false,\n  \"description\": null\n}\n"
        );
        let (mut out, stdout, _) = capture(false);
        render_list(&mut out, Kind::Profile, Format::Json, &[]).unwrap();
        out.commit().unwrap();
        assert_eq!(stdout.text(), "[]\n");
    }

    #[test]
    fn status_lines() {
        let page =
            parse(r#"{"content":[{}],"totalElements":2,"pageable":{"pageNumber":0,"pageSize":1}}"#);
        assert_eq!(
            server_page_status(&page, 1),
            "Showing 1 of 2 (next --offset 1)"
        );
        let page =
            parse(r#"{"content":[{}],"totalElements":2,"pageable":{"pageNumber":1,"pageSize":1}}"#);
        assert_eq!(server_page_status(&page, 1), "Showing 1 of 2");
        let page = parse(r#"{"content":[{},{}],"totalElements":5}"#);
        assert_eq!(
            server_page_status(&page, 2),
            "Showing 2 of 5 (next --offset 2)"
        );
        assert_eq!(
            server_page_status(&parse(r#"{"content":[]}"#), 0),
            "Showing 0"
        );
        assert_eq!(
            slice_status(2, 5, Some(4)),
            "Showing 2 of 5 (next --offset 4)"
        );
        assert_eq!(slice_status(1, 5, Some(5)), "Showing 1 of 5");
        assert_eq!(slice_status(5, 5, None), "Showing 5 of 5");
        assert_eq!(all_status(3), "Showing 3 of 3");
    }

    /// TS `emitAck`: the ack document, its one-row table and the success line.
    #[test]
    fn acks_are_the_typescript_documents() {
        let record = parse(
            r#"{"id":"dp-1","name":"NP","type":"custom","profile_status":"active","status":"x","version":2,"description":"d"}"#,
        );
        assert_eq!(
            compact(&ack_doc("created", &record)),
            r#"{"action":"created","id":"dp-1","name":"NP","type":"custom","status":"active","version":2}"#
        );
        assert_eq!(ack_line("created", &record), "created dp-1  NP v2");
        let nameless = parse(r#"{"id":"fp-1","name":null,"version":2}"#);
        assert_eq!(ack_line("replaced", &nameless), "replaced fp-1   v2");
        assert_eq!(
            compact(&ack_doc("replaced", &nameless)),
            r#"{"action":"replaced","id":"fp-1","version":2}"#
        );
        let (mut out, stdout, stderr) = capture(false);
        render_ack(&mut out, Format::Table, "created", &record).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            " action  │ id   │ name │ type   │ status │ version \n─────────┼──────┼──────┼────────┼────────┼─────────\n created │ dp-1 │ NP   │ custom │ active │ 2       \n"
        );
        assert_eq!(stderr.text(), "  ✓ created dp-1  NP v2\n");
        let (mut out, stdout, stderr) = capture(true);
        render_ack(&mut out, Format::Pretty, "patched", &record).unwrap();
        out.commit().unwrap();
        assert_eq!(
            (stdout.text(), stderr.text()),
            (String::new(), String::new())
        );
    }
}
