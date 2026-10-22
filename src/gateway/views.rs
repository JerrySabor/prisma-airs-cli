//! The gateway projections and layouts (DESIGN §19.3, §19.5, §19.7, §19.8): the TypeScript
//! workspace, scope and cost records (`svc.ts` normalisers, `rgw.ts` renderers), the
//! generic `Field │ Value` detail (`sh.ts` `renderGatewayDetail`), the empty phrases and
//! the JSON writer with C1 escapes (choice 43). Every document arrives withheld
//! (`gateway::withhold`); every server string is made terminal-safe here.

use crate::error::CliError;
use crate::json::OValue;
use crate::output::{Format, Output, terminal_safe, terminal_safe_lines};
use crate::render::style::Style;
use crate::render::{cell_text, pretty, table, width};

/// The gateway banner (pretty only, above successful data, D230).
pub fn banner(out: &mut Output) {
    pretty::banner(out, super::BANNER_TITLE, Some(super::BANNER_SUBTITLE));
}

/// `JSON.stringify(value, null, 2)` plus a newline, C1 controls escaped (choice 43).
pub fn json(out: &mut Output, value: &OValue) -> Result<(), CliError> {
    let text = crate::json::json_text(value)?;
    out.data_line(&text);
    Ok(())
}

/// JavaScript truthiness of a member (absent is `undefined`).
fn truthy(value: Option<&OValue>) -> bool {
    match value {
        None | Some(OValue::Null) => false,
        Some(OValue::Bool(value)) => *value,
        Some(OValue::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0),
        Some(OValue::String(text)) => !text.is_empty(),
        Some(OValue::Array(_) | OValue::Object(_)) => true,
    }
}

/// `String(v ?? '')`: a member as text (terminal-safe).
fn text(value: Option<&OValue>) -> String {
    match value {
        None | Some(OValue::Null) => String::new(),
        Some(OValue::String(text)) => terminal_safe(text).into_owned(),
        other => cell_text(other),
    }
}

/// `` `${value}` `` of a template string: like [`text`], `undefined`/`null` spelled out.
fn template(value: Option<&OValue>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(OValue::Null) => "null".to_owned(),
        other => text(other),
    }
}

fn push(entries: &mut Vec<(String, OValue)>, key: &str, value: Option<&OValue>) {
    if let Some(value) = value {
        entries.push((key.to_owned(), value.clone()));
    }
}

/// TS `normalizeWorkspace` (`svc.ts:37-50`); members the record lacks are left out
/// (`JSON.stringify` drops `undefined`).
pub fn workspace(raw: &OValue) -> OValue {
    let mut entries = Vec::new();
    for (key, source) in [
        ("id", "id"),
        ("slug", "slug"),
        ("name", "name"),
        ("icon", "icon"),
        ("description", "description"),
        ("createdAt", "created_at"),
        ("lastUpdatedAt", "last_updated_at"),
    ] {
        push(&mut entries, key, raw.get(source));
    }
    entries.push((
        "isDefault".to_owned(),
        OValue::Bool(truthy(raw.get("is_default"))),
    ));
    push(&mut entries, "status", raw.get("status"));
    push(&mut entries, "scopeName", raw.get("scope_name"));
    OValue::Object(entries)
}

/// TS `toLimitArray`: an array as is, an object as `[object]`, anything else `[]`.
fn limits(value: Option<&OValue>) -> OValue {
    match value {
        Some(OValue::Array(items)) => OValue::Array(items.clone()),
        Some(object @ OValue::Object(_)) => OValue::Array(vec![object.clone()]),
        _ => OValue::Array(Vec::new()),
    }
}

/// TS `normalizeWorkspaceDetail` (`svc.ts:53-65`).
pub fn workspace_detail(raw: &OValue) -> OValue {
    let OValue::Object(mut entries) = workspace(raw) else {
        return OValue::Object(Vec::new());
    };
    push(&mut entries, "defaults", raw.get("defaults"));
    entries.push(("usageLimits".to_owned(), limits(raw.get("usage_limits"))));
    entries.push(("rateLimits".to_owned(), limits(raw.get("rate_limits"))));
    push(
        &mut entries,
        "securitySettings",
        raw.get("security_settings"),
    );
    push(
        &mut entries,
        "dataPlaneSecuritySettings",
        raw.get("data_plane_security_settings"),
    );
    push(&mut entries, "settings", raw.get("settings"));
    OValue::Object(entries)
}

/// TS `statusLabel`: `status ?? 'unknown'`.
fn status_label(record: &OValue) -> String {
    match record.get("status") {
        None | Some(OValue::Null) => "unknown".to_owned(),
        other => text(other),
    }
}

/// TS `statusColor`: `active` green, `archived` yellow, anything else dim.
fn status_style(label: &str) -> Style {
    match label.to_lowercase().as_str() {
        "active" => Style::Green,
        "archived" => Style::Yellow,
        _ => Style::Dim,
    }
}

/// A list table followed by its newline, or nothing for no rows (§2.7).
fn emit_table(out: &mut Output, labels: &[&str], rows: &[Vec<String>]) {
    let text = table::table(labels, rows);
    if !text.is_empty() {
        out.data_line(&text);
    }
}

/// A `<labels>` two-column table of an object's members in their order.
fn pairs_table(out: &mut Output, labels: [&str; 2], record: &OValue) {
    let text = pairs_text(labels, record);
    if !text.is_empty() {
        out.data(&text);
    }
}

/// The text of [`pairs_table`] (with its newline; empty without members): the table of
/// `gateway inference --output table`, written as it is printed (§19.14).
pub fn pairs_text(labels: [&str; 2], record: &OValue) -> String {
    let rows: Vec<Vec<String>> = record
        .as_object()
        .unwrap_or_default()
        .iter()
        .map(|(key, value)| vec![terminal_safe(key).into_owned(), cell_text(Some(value))])
        .collect();
    let text = table::table(&labels, &rows);
    if text.is_empty() {
        text
    } else {
        format!("{text}\n")
    }
}

/// `ui.keyValue` with keys padded by display width (server keys, D53).
fn key_value(out: &mut Output, pairs: &[(String, String)]) {
    let widest = pairs.iter().map(|(key, _)| width(key)).max().unwrap_or(0);
    for (key, value) in pairs {
        let padded = format!("{key}{}", " ".repeat(widest - width(key)));
        let key = out.paint(Style::Dim, &padded);
        out.data_line(&format!("  {key}  {value}"));
    }
}

/// `workspaces list` (§19.5): `rows` are [`workspace`] records.
pub fn render_workspace_list(
    out: &mut Output,
    rows: &[OValue],
    format: Format,
) -> Result<(), CliError> {
    match format {
        Format::Json => {
            let projected: Vec<OValue> = rows.iter().map(workspace_row).collect();
            json(out, &OValue::Array(projected))
        }
        Format::Table => {
            let cells: Vec<Vec<String>> = rows
                .iter()
                .map(|row| {
                    let row = workspace_row(row);
                    ["id", "slug", "name", "status", "isDefault", "scopeName"]
                        .iter()
                        .map(|key| cell_text(row.get(key)))
                        .collect()
                })
                .collect();
            emit_table(
                out,
                &["ID", "Slug", "Name", "Status", "Default", "Scope"],
                &cells,
            );
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if rows.is_empty() {
                pretty::empty_list(out, "workspaces");
                return Ok(());
            }
            pretty::section(out, "AI Gateway Workspaces:");
            for row in rows {
                let id = out.paint(Style::Dim, &template(row.get("id")));
                out.data_line(&format!("  {id}"));
                let label = status_label(row);
                let status = out.paint(status_style(&label), &label);
                let default = if truthy(row.get("isDefault")) {
                    out.paint(Style::Cyan, "  default")
                } else {
                    String::new()
                };
                let slug = out.paint(Style::Dim, &template(row.get("slug")));
                out.data_line(&format!(
                    "    {}  {slug}  {status}{default}",
                    template(row.get("name"))
                ));
                if truthy(row.get("scopeName")) {
                    let scope = out.paint(
                        Style::Dim,
                        &format!("scope: {}", template(row.get("scopeName"))),
                    );
                    out.data_line(&format!("    {scope}"));
                }
                out.data_line("");
            }
            Ok(())
        }
    }
}

/// The structured row of `workspaces list` (`rgw.ts:48-55`).
fn workspace_row(record: &OValue) -> OValue {
    let mut entries = Vec::new();
    push(&mut entries, "id", record.get("id"));
    push(&mut entries, "slug", record.get("slug"));
    push(&mut entries, "name", record.get("name"));
    entries.push((
        "status".to_owned(),
        OValue::String(status_label_raw(record)),
    ));
    push(&mut entries, "isDefault", record.get("isDefault"));
    entries.push((
        "scopeName".to_owned(),
        match record.get("scopeName") {
            None | Some(OValue::Null) => OValue::String(String::new()),
            Some(value) => value.clone(),
        },
    ));
    OValue::Object(entries)
}

/// [`status_label`] without the terminal-safe replacement (structured data).
fn status_label_raw(record: &OValue) -> String {
    match record.get("status") {
        None | Some(OValue::Null) => "unknown".to_owned(),
        Some(OValue::String(text)) => text.clone(),
        other => cell_text(other),
    }
}

/// A JSON block of the workspace detail (dim, not indented; line breaks kept).
fn json_block(out: &mut Output, title: &str, value: &OValue) -> Result<(), CliError> {
    pretty::section(out, title);
    let text = crate::json::to_pretty(value).map_err(|_| {
        CliError::operational("AISEC_SDK_ERROR:Output could not be serialized as JSON")
    })?;
    let block = out.paint(Style::Dim, &terminal_safe_lines(&text));
    out.data_line(&block);
    Ok(())
}

/// Whether a value has keys (`Object.keys(v).length > 0` of a truthy value).
fn has_keys(value: Option<&OValue>) -> bool {
    match value {
        Some(OValue::Object(entries)) => !entries.is_empty(),
        Some(OValue::Array(items)) => !items.is_empty(),
        Some(OValue::String(text)) => !text.is_empty(),
        _ => false,
    }
}

/// `workspaces get` (§19.5): `detail` is a [`workspace_detail`] record.
pub fn render_workspace_detail(
    out: &mut Output,
    detail: &OValue,
    format: Format,
) -> Result<(), CliError> {
    match format {
        Format::Json => json(out, detail),
        Format::Table => {
            pairs_table(out, ["Key", "Value"], detail);
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            pretty::section(out, "Workspace Detail:");
            let label = status_label(detail);
            let status = out.paint(status_style(&label), &label);
            let mut pairs = vec![
                ("ID".to_owned(), text(detail.get("id"))),
                ("Slug".to_owned(), text(detail.get("slug"))),
                ("Name".to_owned(), text(detail.get("name"))),
                ("Status".to_owned(), status),
                (
                    "Default".to_owned(),
                    if truthy(detail.get("isDefault")) {
                        "yes"
                    } else {
                        "no"
                    }
                    .to_owned(),
                ),
            ];
            for (label, key) in [
                ("Description", "description"),
                ("Scope", "scopeName"),
                ("Created", "createdAt"),
                ("Updated", "lastUpdatedAt"),
            ] {
                if !matches!(detail.get(key), None | Some(OValue::Null)) {
                    pairs.push((label.to_owned(), text(detail.get(key))));
                }
            }
            key_value(out, &pairs);
            if truthy(detail.get("defaults")) && has_keys(detail.get("defaults")) {
                json_block(
                    out,
                    "Defaults:",
                    detail.get("defaults").unwrap_or(&OValue::Null),
                )?;
            }
            for (title, key) in [
                ("Usage Limits:", "usageLimits"),
                ("Rate Limits:", "rateLimits"),
            ] {
                if let Some(value @ OValue::Array(items)) = detail.get(key)
                    && !items.is_empty()
                {
                    json_block(out, title, value)?;
                }
            }
            if let Some(OValue::Object(settings)) = detail.get("securitySettings")
                && !settings.is_empty()
            {
                pretty::section(out, "Security Settings:");
                let pairs: Vec<(String, String)> = settings
                    .iter()
                    .map(|(key, value)| (terminal_safe(key).into_owned(), text(Some(value))))
                    .collect();
                key_value(out, &pairs);
            }
            out.data_line("");
            Ok(())
        }
    }
}

/// TS `normalizeScope` (`svc.ts:68-79`).
pub fn scope(raw: &OValue) -> OValue {
    let mut entries = Vec::new();
    push(&mut entries, "name", raw.get("name"));
    push(&mut entries, "description", raw.get("description"));
    let resources = raw
        .get("resources")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|resource| {
            let mut binding = Vec::new();
            push(&mut binding, "resourceType", resource.get("resource_type"));
            push(&mut binding, "resourceId", resource.get("resource_id"));
            OValue::Object(binding)
        })
        .collect();
    entries.push(("resources".to_owned(), OValue::Array(resources)));
    push(&mut entries, "tsgId", raw.get("tsg_id"));
    push(&mut entries, "id", raw.get("id"));
    OValue::Object(entries)
}

/// TS `scopeBindings`: `type:id` joined with `, `.
fn bindings(scope: &OValue, safe: bool) -> String {
    scope
        .get("resources")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|resource| {
            let part = |key: &str| match resource.get(key) {
                Some(OValue::String(text)) if !safe => text.clone(),
                other => template(other),
            };
            format!("{}:{}", part("resourceType"), part("resourceId"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `scopes list` (§19.7): `scopes` are [`scope`] records.
pub fn render_scope_list(
    out: &mut Output,
    scopes: &[OValue],
    format: Format,
) -> Result<(), CliError> {
    let row = |scope: &OValue| {
        let mut entries = Vec::new();
        push(&mut entries, "name", scope.get("name"));
        push(&mut entries, "description", scope.get("description"));
        entries.push((
            "resources".to_owned(),
            OValue::String(bindings(scope, false)),
        ));
        push(&mut entries, "tsgId", scope.get("tsgId"));
        OValue::Object(entries)
    };
    match format {
        Format::Json => json(out, &OValue::Array(scopes.iter().map(row).collect())),
        Format::Table => {
            let cells: Vec<Vec<String>> = scopes
                .iter()
                .map(|scope| {
                    let row = row(scope);
                    ["name", "description", "resources", "tsgId"]
                        .iter()
                        .map(|key| cell_text(row.get(key)))
                        .collect()
                })
                .collect();
            emit_table(
                out,
                &["Name", "Description", "Bound resources", "TSG"],
                &cells,
            );
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if scopes.is_empty() {
                pretty::empty_list(out, "IAM scopes");
                return Ok(());
            }
            pretty::section(out, "IAM Scopes:");
            for scope in scopes {
                let bound = bindings(scope, true);
                let shown = if bound.is_empty() {
                    out.paint(Style::Yellow, "unbound")
                } else {
                    out.paint(Style::Dim, &bound)
                };
                out.data_line(&format!("    {}  {shown}", template(scope.get("name"))));
                if truthy(scope.get("description")) {
                    let description = out.paint(Style::Dim, &text(scope.get("description")));
                    out.data_line(&format!("    {description}"));
                }
                out.data_line("");
            }
            Ok(())
        }
    }
}

/// `scopes get` (§19.7): `scope` is a [`scope`] record.
pub fn render_scope_detail(
    out: &mut Output,
    scope: &OValue,
    format: Format,
) -> Result<(), CliError> {
    match format {
        Format::Json => json(out, scope),
        Format::Table => {
            pairs_table(out, ["Key", "Value"], scope);
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            pretty::section(out, "IAM Scope:");
            let description = if truthy(scope.get("description")) {
                text(scope.get("description"))
            } else {
                out.paint(Style::Dim, "(none)")
            };
            let bound = bindings(scope, true);
            let bound = if bound.is_empty() {
                out.paint(Style::Yellow, "none — unbound")
            } else {
                bound
            };
            key_value(
                out,
                &[
                    ("Name".to_owned(), text(scope.get("name"))),
                    ("Description".to_owned(), description),
                    ("TSG".to_owned(), text(scope.get("tsgId"))),
                    ("ID".to_owned(), text(scope.get("id"))),
                    ("Bound resources".to_owned(), bound),
                ],
            );
            out.data_line("");
            Ok(())
        }
    }
}

/// `cents / 100` as a JSON number (`null` for a non-number).
fn usd(cents: Option<&OValue>) -> OValue {
    cents
        .and_then(|value| match value {
            OValue::Number(number) => number.as_f64(),
            _ => None,
        })
        .and_then(|cents| serde_json::Number::from_f64(cents / 100.0))
        .map_or(OValue::Null, OValue::Number)
}

/// The TS cost record (`svc.ts:281-294`) of a `CostChartResponse` document.
pub fn cost_record(slug: &str, days: u64, doc: &OValue) -> OValue {
    let data = doc.get("data").cloned().unwrap_or(OValue::Null);
    let member = |key: &str| data.get(key).cloned().unwrap_or(OValue::Null);
    let records = data
        .get("records")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|record| {
            OValue::Object(vec![
                (
                    "date".to_owned(),
                    record.get("x").cloned().unwrap_or(OValue::Null),
                ),
                (
                    "costCents".to_owned(),
                    record.get("y").cloned().unwrap_or(OValue::Null),
                ),
                ("costUsd".to_owned(), usd(record.get("y"))),
            ])
        })
        .collect();
    OValue::Object(vec![
        ("workspaceSlug".to_owned(), OValue::String(slug.to_owned())),
        ("days".to_owned(), OValue::Number(days.into())),
        ("totalCents".to_owned(), member("total")),
        ("totalUsd".to_owned(), usd(data.get("total"))),
        ("avgCents".to_owned(), member("avg")),
        ("avgUsd".to_owned(), usd(data.get("avg"))),
        ("quotaExceeded".to_owned(), member("isQuotaExceeded")),
        ("records".to_owned(), OValue::Array(records)),
    ])
}

/// JavaScript `(cents / 100).toFixed(2)` (choice 11): the exact binary value rounded to
/// two places, a tie to the larger magnitude; `1e21` and beyond as `String(x)`.
pub fn to_fixed_2(value: f64) -> String {
    if !value.is_finite() {
        return crate::render::js_number(value);
    }
    if value.abs() >= 1e21 {
        return crate::render::js_number(value);
    }
    let negative = value < 0.0;
    // Rust's fixed-precision formatting is exact for enough digits (1074 fraction digits
    // hold any double).
    let exact = format!("{:.1100}", value.abs());
    let (whole, fraction) = exact.split_once('.').unwrap_or((exact.as_str(), ""));
    let mut digits: Vec<u8> = whole.bytes().chain(fraction.bytes().take(2)).collect();
    let round_up = fraction
        .as_bytes()
        .get(2)
        .is_some_and(|digit| *digit >= b'5');
    if round_up {
        let mut index = digits.len();
        loop {
            if index == 0 {
                digits.insert(0, b'1');
                break;
            }
            index -= 1;
            if digits[index] == b'9' {
                digits[index] = b'0';
            } else {
                digits[index] += 1;
                break;
            }
        }
    }
    let text = String::from_utf8(digits).unwrap_or_default();
    let (int_part, frac_part) = text.split_at(text.len() - 2);
    format!("{}{int_part}.{frac_part}", if negative { "-" } else { "" })
}

/// `$<toFixed(2)>` of a cents member.
fn dollars(cents: Option<&OValue>) -> String {
    match cents {
        Some(OValue::Number(number)) => {
            format!(
                "${}",
                to_fixed_2(number.as_f64().unwrap_or_default() / 100.0)
            )
        }
        // `(undefined / 100).toFixed(2)` is `NaN`.
        _ => "$NaN".to_owned(),
    }
}

/// `telemetry cost` (§19.8): `record` is a [`cost_record`].
pub fn render_cost(out: &mut Output, record: &OValue, format: Format) -> Result<(), CliError> {
    match format {
        Format::Json => json(out, record),
        Format::Table => {
            pairs_table(out, ["Key", "Value"], record);
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            pretty::section(
                out,
                &format!(
                    "Cost — {} (last {}d):",
                    text(record.get("workspaceSlug")),
                    text(record.get("days"))
                ),
            );
            key_value(
                out,
                &[
                    ("Total".to_owned(), dollars(record.get("totalCents"))),
                    ("Daily average".to_owned(), dollars(record.get("avgCents"))),
                ],
            );
            let records = record
                .get("records")
                .and_then(OValue::as_array)
                .unwrap_or_default();
            if !records.is_empty() {
                pretty::section(out, "Per day:");
                let pairs: Vec<(String, String)> = records
                    .iter()
                    .map(|day| (text(day.get("date")), dollars(day.get("costCents"))))
                    .collect();
                key_value(out, &pairs);
            }
            out.data_line("");
            Ok(())
        }
    }
}

/// TS `asRecord`: an object as it is, anything else `{"value": <it>}`.
fn as_record(value: &OValue) -> OValue {
    match value {
        OValue::Object(_) => value.clone(),
        other => OValue::Object(vec![("value".to_owned(), other.clone())]),
    }
}

/// TS `responseItems` (`sh.ts:82-90`; §19.3): the answer when it is an array, else its
/// `data` array, else `data.records`, else `records`; no rows otherwise. Non-object rows
/// become `{"value": <row>}`.
pub fn response_items(answer: &OValue) -> Vec<OValue> {
    let rows = match answer {
        OValue::Array(items) => Some(items.as_slice()),
        _ => answer
            .get("data")
            .and_then(OValue::as_array)
            .or_else(|| {
                answer
                    .get("data")
                    .and_then(|data| data.get("records"))
                    .and_then(OValue::as_array)
            })
            .or_else(|| answer.get("records").and_then(OValue::as_array)),
    };
    rows.unwrap_or_default().iter().map(as_record).collect()
}

/// The preferred columns of TS `displayColumns`.
const PREFERRED: [&str; 8] = [
    "id",
    "slug",
    "name",
    "type",
    "status",
    "enabled",
    "created_at",
    "last_updated_at",
];

/// TS `displayColumns` (`sh.ts:96-118`): a key is eligible when no row holds an object or
/// an array there; the eligible preferred keys first, then every other eligible key in
/// UTF-16 code-unit order (JS `sort`), at most 8.
///
/// `rows` are the withheld rows (a member the policy dropped has no column); `shape` are
/// the same rows as the service sent them, so a withheld object or array (now the string
/// `[withheld]`) stays ineligible and the columns are TypeScript's (choice 79).
pub fn display_columns_of(rows: &[OValue], shape: &[OValue]) -> Vec<String> {
    let container = |row: &OValue, key: &str| {
        matches!(row.get(key), Some(OValue::Object(_) | OValue::Array(_)))
    };
    ordered_columns(rows)
        .into_iter()
        .filter(|key| !shape.iter().any(|row| container(row, key)))
        .take(8)
        .collect()
}

/// Every eligible key of `rows`: the preferred keys first, then the rest in UTF-16
/// code-unit order (JS `sort`).
fn ordered_columns(rows: &[OValue]) -> Vec<String> {
    let mut keys: Vec<&str> = Vec::new();
    for row in rows {
        for (key, _) in row.as_object().unwrap_or_default() {
            if !keys.contains(&key.as_str()) {
                keys.push(key);
            }
        }
    }
    let scalar = |key: &str| {
        rows.iter()
            .all(|row| !matches!(row.get(key), Some(OValue::Object(_) | OValue::Array(_))))
    };
    let mut rest: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|key| !PREFERRED.contains(key) && scalar(key))
        .collect();
    rest.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    PREFERRED
        .iter()
        .copied()
        .filter(|key| keys.contains(key) && scalar(key))
        .chain(rest)
        .map(str::to_owned)
        .collect()
}

/// TS's column label: `_` → space, then the first letter of each word uppercased
/// (`created_at` → `Created At`; JS `\b\w`, so a digit or `_`-free word boundary counts).
pub fn column_label(key: &str) -> String {
    let spaced = key.replace('_', " ");
    let mut label = String::with_capacity(spaced.len());
    let mut previous_word = false;
    for c in spaced.chars() {
        let word = c.is_ascii_alphanumeric() || c == '_';
        if word && !previous_word {
            label.push(c.to_ascii_uppercase());
        } else {
            label.push(c);
        }
        previous_word = word;
    }
    terminal_safe(&label).into_owned()
}

/// TS `renderGatewayList` (`sh.ts:120-140`; §19.3): json the rows; pretty and table the
/// same box table of [`display_columns`]; an empty list prints `No <label> found` in
/// pretty, nothing in table and `[]` in json (D231).
pub fn render_list(
    out: &mut Output,
    rows: &[OValue],
    shape: &[OValue],
    format: Format,
    label: &str,
) -> Result<(), CliError> {
    match format {
        Format::Json => json(out, &OValue::Array(rows.to_vec())),
        Format::Pretty if rows.is_empty() => {
            pretty::empty_list(out, label);
            Ok(())
        }
        Format::Pretty | Format::Table => {
            let columns = display_columns_of(rows, shape);
            let labels: Vec<String> = columns.iter().map(|key| column_label(key)).collect();
            let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
            let cells: Vec<Vec<String>> = rows
                .iter()
                .map(|row| columns.iter().map(|key| cell_text(row.get(key))).collect())
                .collect();
            emit_table(out, &labels, &cells);
            Ok(())
        }
    }
}

/// TS `renderGatewayDetail` (`sh.ts:142-165`; §19.3): pretty and table the `Field │ Value`
/// table of the top-level members, nested values as compact JSON; json the object; a
/// non-object answer is `{"value": <it>}`; an empty object prints `No fields returned`
/// in pretty, nothing in table and `{}` in json (D231).
pub fn render_detail(out: &mut Output, value: &OValue, format: Format) -> Result<(), CliError> {
    let wrapped;
    let record = match value {
        OValue::Object(_) => value,
        other => {
            wrapped = OValue::Object(vec![("value".to_owned(), other.clone())]);
            &wrapped
        }
    };
    let empty = record.as_object().is_some_and(<[_]>::is_empty);
    match format {
        Format::Json => json(out, record),
        Format::Table => {
            pairs_table(out, ["Field", "Value"], record);
            Ok(())
        }
        Format::Pretty if empty => {
            let text = out.paint(Style::Dim, "No fields returned");
            out.data_line(&format!("  {text}"));
            Ok(())
        }
        Format::Pretty => {
            pairs_table(out, ["Field", "Value"], record);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;
    use crate::output::testing::{capture, capture_colored};

    fn v(text: &str) -> OValue {
        parse(text).unwrap()
    }

    const ROW: &str = r#"{"id":"ws-uuid-1","slug":"ws-main-a-349e0e","name":"Main","icon":null,"description":null,"created_at":"2026-07-01T00:00:00Z","last_updated_at":"2026-07-02T00:00:00Z","is_default":1,"status":"active","scope_name":"main_airs_workspace_1852583913","object":"workspace"}"#;

    /// TS `aigateway.spec.ts` "normalizes list rows to camelCase with boolean isDefault".
    #[test]
    fn workspaces_normalise_like_typescript() {
        assert_eq!(
            crate::json::to_compact(&workspace(&v(ROW))).unwrap(),
            r#"{"id":"ws-uuid-1","slug":"ws-main-a-349e0e","name":"Main","icon":null,"description":null,"createdAt":"2026-07-01T00:00:00Z","lastUpdatedAt":"2026-07-02T00:00:00Z","isDefault":true,"status":"active","scopeName":"main_airs_workspace_1852583913"}"#
        );
        assert_eq!(
            workspace(&v(r#"{"is_default":0}"#)).get("isDefault"),
            Some(&OValue::Bool(false))
        );
        let detail = workspace_detail(&v(
            r#"{"id":"ws-uuid-1","name":"Main","description":null,"created_at":"a","last_updated_at":"b","is_default":0,"slug":"s","icon":null,"defaults":{"metadata":{"env":"production"}},"usage_limits":{"type":"cost","credit_limit":5},"rate_limits":null,"security_settings":{"membersViewLogs":true},"status":null}"#,
        ));
        assert_eq!(
            crate::json::to_compact(&detail).unwrap(),
            r#"{"id":"ws-uuid-1","slug":"s","name":"Main","icon":null,"description":null,"createdAt":"a","lastUpdatedAt":"b","isDefault":false,"status":null,"defaults":{"metadata":{"env":"production"}},"usageLimits":[{"type":"cost","credit_limit":5}],"rateLimits":[],"securitySettings":{"membersViewLogs":true}}"#
        );
    }

    /// TS `aigateway-renderer.spec.ts`: rows, the null status, scopes and the empty phrases.
    #[test]
    fn renderers_follow_the_typescript_layouts() {
        let (mut out, stdout, _) = capture(false);
        render_workspace_list(&mut out, &[workspace(&v(ROW))], Format::Pretty).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Prisma AIRS — AI Gateway\n  Gateway workspace operations\n\n\n  AI Gateway Workspaces:\n\n  ws-uuid-1\n    Main  ws-main-a-349e0e  active  default\n    scope: main_airs_workspace_1852583913\n\n"
        );
        let (mut out, stdout, _) = capture(true);
        render_workspace_list(&mut out, &[workspace(&v(ROW))], Format::Pretty).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "  ws-uuid-1\n    Main  ws-main-a-349e0e  active  default\n    scope: main_airs_workspace_1852583913\n\n",
            "--quiet keeps every data line (D230)"
        );
        let (mut out, stdout, _) = capture(false);
        render_workspace_list(&mut out, &[], Format::Json).unwrap();
        render_workspace_list(&mut out, &[], Format::Table).unwrap();
        render_scope_list(&mut out, &[], Format::Json).unwrap();
        out.commit().unwrap();
        assert_eq!(stdout.text(), "[]\n[]\n", "D231");
        let detail = workspace_detail(&v(r#"{"id":"x","slug":"s","name":"n","status":null}"#));
        let (mut out, stdout, _) = capture(false);
        render_workspace_detail(&mut out, &detail, Format::Pretty).unwrap();
        out.commit().unwrap();
        assert!(stdout.text().contains("  Status   unknown\n"));
        assert!(!stdout.text().to_lowercase().contains("inactive"));
        let bound = scope(&v(
            r#"{"name":"ws_truffles_ggolfu","description":"Online recipe generation application","resources":[{"metadata":[],"resource_id":"ws-truffl-03e7d9","resource_type":"workspace"}],"tsg_id":"1001464285","id":"ws_truffles_ggolfu:1001464285"}"#,
        ));
        assert_eq!(
            crate::json::to_compact(&bound).unwrap(),
            r#"{"name":"ws_truffles_ggolfu","description":"Online recipe generation application","resources":[{"resourceType":"workspace","resourceId":"ws-truffl-03e7d9"}],"tsgId":"1001464285","id":"ws_truffles_ggolfu:1001464285"}"#
        );
        let (mut out, stdout, _) = capture_colored(false);
        render_scope_detail(
            &mut out,
            &scope(&v(
                r#"{"name":"ws_orphan","description":"","resources":[],"tsg_id":"1","id":"ws_orphan:1"}"#,
            )),
            Format::Pretty,
        )
        .unwrap();
        out.commit().unwrap();
        assert!(stdout.text().contains("\u{1b}[33mnone — unbound\u{1b}[39m"));
        assert!(stdout.text().contains("\u{1b}[2m(none)\u{1b}[22m"));
    }

    /// Choice 11: JavaScript `toFixed(2)` on the exact binary value.
    #[test]
    fn dollars_follow_javascript_to_fixed() {
        for (value, text) in [
            (12.39, "12.39"),
            (6.195, "6.20"),
            (0.125, "0.13"),
            (0.005, "0.01"),
            (1.005, "1.00"),
            (0.0, "0.00"),
            (-0.0, "0.00"),
            (-0.001, "-0.00"),
            (999.995, "1000.00"),
            (1234.5678, "1234.57"),
            (1e21, "1e+21"),
        ] {
            assert_eq!(to_fixed_2(value), text, "{value}");
        }
    }

    /// TS `responseItems`, `displayColumns` and the labels (`sh.ts:82-118`).
    #[test]
    fn generic_lists_follow_the_typescript_rules() {
        assert_eq!(response_items(&v(r#"[1,{"a":2}]"#)).len(), 2);
        assert_eq!(
            crate::json::to_compact(&response_items(&v("[1]"))[0]).unwrap(),
            r#"{"value":1}"#
        );
        assert_eq!(response_items(&v(r#"{"data":[{}]}"#)).len(), 1);
        assert_eq!(
            response_items(&v(r#"{"data":{"records":[{},{}]}}"#)).len(),
            2
        );
        assert_eq!(response_items(&v(r#"{"records":[{}]}"#)).len(), 1);
        assert!(response_items(&v(r#"{"models":[{}]}"#)).is_empty());
        let rows = vec![
            v(r#"{"zeta":1,"name":"a","nested":{"x":1},"id":"1","Alpha":2,"status":null}"#),
            v(r#"{"beta":[1],"last_updated_at":"t","extra":"e"}"#),
        ];
        assert_eq!(
            display_columns_of(&rows, &rows),
            [
                "id",
                "name",
                "status",
                "last_updated_at",
                "Alpha",
                "extra",
                "zeta"
            ]
        );
        let many: Vec<OValue> = vec![v(
            r#"{"a":1,"b":1,"c":1,"d":1,"e":1,"f":1,"g":1,"h":1,"i":1,"id":1}"#,
        )];
        assert_eq!(display_columns_of(&many, &many).len(), 8);
        // A withheld object keeps its column out (choice 79).
        let withheld = vec![v(r#"{"id":"p","credentials":"[withheld]","owner_id":"o"}"#)];
        let sent = vec![v(r#"{"id":"p","credentials":{"k":"x"},"owner_id":"o"}"#)];
        assert_eq!(display_columns_of(&withheld, &sent), ["id", "owner_id"]);
        assert_eq!(column_label("created_at"), "Created At");
        assert_eq!(column_label("ai_provider_id"), "Ai Provider Id");
        assert_eq!(column_label("x-api-key"), "X-Api-Key");
        assert_eq!(column_label("v2name"), "V2name");
        let (mut out, stdout, _) = capture(false);
        render_list(&mut out, &[], &[], Format::Pretty, "configs").unwrap();
        render_list(&mut out, &[], &[], Format::Table, "configs").unwrap();
        render_list(&mut out, &[], &[], Format::Json, "configs").unwrap();
        let row = v(r#"{"id":"c1","is_default":1,"slug":"s"}"#);
        render_list(
            &mut out,
            std::slice::from_ref(&row),
            std::slice::from_ref(&row),
            Format::Table,
            "configs",
        )
        .unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "  No configs found\n[]\n Id │ Slug │ Is Default \n────┼──────┼────────────\n c1 │ s    │ 1          \n"
        );
    }

    #[test]
    fn generic_details_and_empty_objects() {
        let (mut out, stdout, _) = capture(false);
        render_detail(
            &mut out,
            &v(r#"{"success":true,"data":{"total":42}}"#),
            Format::Pretty,
        )
        .unwrap();
        render_detail(&mut out, &v("{}"), Format::Pretty).unwrap();
        render_detail(&mut out, &v("{}"), Format::Table).unwrap();
        render_detail(&mut out, &v("{}"), Format::Json).unwrap();
        render_detail(&mut out, &v("3"), Format::Json).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            " Field   │ Value        \n─────────┼──────────────\n success │ true         \n data    │ {\"total\":42} \n  No fields returned\n{}\n{\n  \"value\": 3\n}\n"
        );
    }
}
