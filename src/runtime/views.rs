//! The M6d read projections and layouts (DESIGN §18.4, §18.7, §18.9–§18.13): the
//! TypeScript projections without the values TypeScript invents (D207, D209), the
//! `api_key` withholding (D205), the pretty, table and json layouts, and the dashboard
//! JSON text with C1 escapes (D212).

use crate::error::{CliError, SecretSet, WITHHELD};
use crate::json::{OValue, json_text};
use crate::output::{Format, Output, terminal_safe, terminal_safe_lines};
use crate::render::style::Style;
use crate::render::{cell_text, js_json_number, pretty, table, utf16_prefix};
use crate::secrets::withhold;

/// The runtime banner (§18.3; TS `renderRuntimeConfigHeader`), pretty only.
pub fn banner(out: &mut Output) {
    crate::views::runtime_banner(out);
}

fn serialization_failed() -> CliError {
    CliError::operational("AISEC_SDK_ERROR:Output could not be serialized as JSON")
}

/// An SDK model as ordered JSON (schema order, unknown keys sorted, D35; the shared
/// `crate::json::page_value`).
pub use crate::json::page_value as ordered;

/// D205: every object member named `api_key`, at any depth, is removed; its string value
/// joins the `SecretSet` first (so any other field that echoes it is withheld).
pub fn strip_api_keys(value: &mut OValue, secrets: &SecretSet) {
    match value {
        OValue::Object(entries) => {
            entries.retain(|(key, member)| {
                if key == "api_key" {
                    if let OValue::String(secret) = member
                        && !secret.is_empty()
                    {
                        secrets.add(secret);
                    }
                    false
                } else {
                    true
                }
            });
            for (_, member) in entries.iter_mut() {
                strip_api_keys(member, secrets);
            }
        }
        OValue::Array(items) => {
            for item in items {
                strip_api_keys(item, secrets);
            }
        }
        _ => {}
    }
}

/// [`strip_api_keys`] then [`withhold`]: the treatment of every M6d read document.
pub fn sanitize(value: &mut OValue, secrets: &SecretSet) {
    strip_api_keys(value, secrets);
    withhold(value, secrets);
}

/// A string member (`None` when absent, `null` or not a string).
pub fn text<'a>(value: &'a OValue, key: &str) -> Option<&'a str> {
    value.get(key).and_then(OValue::as_str)
}

/// The first member of `keys` that is present and not `null` (TS `a ?? b`).
fn first<'a>(value: &'a OValue, keys: &[&str]) -> Option<&'a OValue> {
    keys.iter()
        .find_map(|key| value.get(key).filter(|member| **member != OValue::Null))
}

fn string(text: &str) -> OValue {
    OValue::String(text.to_owned())
}

/// A non-empty string (TS truthiness of a string), terminal-safe.
fn truthy(value: Option<&OValue>) -> Option<String> {
    match value {
        Some(OValue::String(text)) if !text.is_empty() => Some(terminal_safe(text).into_owned()),
        _ => None,
    }
}

/// `String(v ?? '')` of a projection value for a pretty key/value pair.
fn shown_value(value: Option<&OValue>) -> String {
    match value {
        None | Some(OValue::Null) => String::new(),
        Some(OValue::String(text)) => terminal_safe(text).into_owned(),
        Some(other) => cell_text(Some(other)),
    }
}

/// A list table followed by its newline, or nothing for an empty list (§2.7).
fn emit_table(out: &mut Output, labels: &[&str], rows: &[Vec<String>]) {
    let text = table::table(labels, rows);
    if !text.is_empty() {
        out.data_line(&text);
    }
}

/// The table rows of `docs` for `keys`.
fn rows(docs: &[OValue], keys: &[&str]) -> Vec<Vec<String>> {
    docs.iter()
        .map(|doc| keys.iter().map(|key| cell_text(doc.get(key))).collect())
        .collect()
}

/// A `Key │ Value` table of an object's members in their order.
fn key_value_table(doc: &OValue) -> String {
    table::key_value_table(
        doc.as_object()
            .unwrap_or_default()
            .iter()
            .map(|(key, value)| (terminal_safe(key).into_owned(), cell_text(Some(value))))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// API keys (§18.4)
// ---------------------------------------------------------------------------

/// `{id, name, last8, createdAt, expiresAt}` (TS `normalizeApiKey` without `apiKey`, D205;
/// `creation_ts` and `expiration` read too, D207). `id` and `name` are TS's `?? ''`.
pub fn api_key(row: &OValue) -> OValue {
    let mut doc = vec![
        (
            "id".to_owned(),
            first(row, &["id", "api_key_id"])
                .cloned()
                .unwrap_or_else(|| string("")),
        ),
        (
            "name".to_owned(),
            first(row, &["name", "api_key_name"])
                .cloned()
                .unwrap_or_else(|| string("")),
        ),
    ];
    for (key, sources) in [
        ("last8", &["api_key_last8"][..]),
        ("createdAt", &["created_at", "creation_ts"]),
        ("expiresAt", &["expires_at", "expiration"]),
    ] {
        if let Some(value) = first(row, sources) {
            doc.push((key.to_owned(), value.clone()));
        }
    }
    OValue::Object(doc)
}

/// `api-keys list` (TX§5.1).
pub fn render_api_keys(out: &mut Output, keys: &[OValue], format: Format) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(keys),
        Format::Table => {
            emit_table(
                out,
                &["ID", "Name", "Last 8", "Expires"],
                &rows(keys, &["id", "name", "last8", "expiresAt"]),
            );
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if keys.is_empty() {
                pretty::empty_list(out, "API keys");
                return Ok(());
            }
            pretty::section(out, "API Keys:");
            for key in keys {
                // D222: the key id is data (TS prints it with `ui.dim`, dropped by --quiet).
                let id = out.paint(Style::Dim, &shown_value(key.get("id")));
                out.data_line(&format!("  {id}"));
                let last8 = truthy(key.get("last8"))
                    .map(|last8| out.paint(Style::Dim, &format!(" key: …{last8}")))
                    .unwrap_or_default();
                let expires = truthy(key.get("expiresAt"))
                    .map(|expires| out.paint(Style::Dim, &format!(" expires: {expires}")))
                    .unwrap_or_default();
                out.data_line(&format!(
                    "    {}{last8}{expires}",
                    shown_value(key.get("name"))
                ));
            }
            out.data("\n");
            Ok(())
        }
    }
}

/// The record of `api-keys create|regenerate` (§18.5 "Output", D204, D223): the §18.4
/// projection plus `keyFile` (the path as given); pretty is TypeScript's detail block
/// with `Key` as `…<last8>` (never the key) and the Rust row `Key file`.
pub fn render_api_key_detail(
    out: &mut Output,
    key: &OValue,
    key_file: &str,
    format: Format,
) -> Result<(), CliError> {
    let mut doc = key.clone();
    if let OValue::Object(entries) = &mut doc {
        entries.push(("keyFile".to_owned(), string(key_file)));
    }
    match format {
        Format::Json => out.json(&doc),
        Format::Table => {
            out.data_line(&key_value_table(&doc));
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            pretty::section(out, "API Key Detail:");
            let mut pairs: Vec<(&str, String)> = vec![
                ("ID", shown_value(doc.get("id"))),
                ("Name", shown_value(doc.get("name"))),
            ];
            if let Some(last8) = truthy(doc.get("last8")) {
                pairs.push(("Key", format!("…{last8}")));
            }
            if let Some(created) = truthy(doc.get("createdAt")) {
                pairs.push(("Created", created));
            }
            if let Some(expires) = truthy(doc.get("expiresAt")) {
                pairs.push(("Expires", expires));
            }
            pairs.push(("Key file", terminal_safe(key_file).into_owned()));
            pretty::key_value(out, &pairs);
            out.data("\n");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Customer apps (§18.7)
// ---------------------------------------------------------------------------

/// The pretty `Data` cut (TS `JSON.stringify(raw, null, 2).slice(0, 500)`).
const DATA_UNITS: usize = 500;
/// The pretty list's description preview (TS `slice(0, 80)`, no ellipsis, D54).
const DESCRIPTION_UNITS: usize = 80;

/// `{id, name, description, raw}` (TS `normalizeCustomerApp`; `customer_appId` read too,
/// D207; `raw` is the record without `api_key` members, D205).
pub fn customer_app(row: &OValue) -> OValue {
    let mut doc = Vec::new();
    if let Some(id) = first(row, &["customer_app_id", "id", "customer_appId"]) {
        doc.push(("id".to_owned(), id.clone()));
    }
    doc.push((
        "name".to_owned(),
        first(row, &["app_name", "name"])
            .cloned()
            .unwrap_or_else(|| string("")),
    ));
    if let Some(description) = first(row, &["description"]) {
        doc.push(("description".to_owned(), description.clone()));
    }
    doc.push(("raw".to_owned(), row.clone()));
    OValue::Object(doc)
}

/// `customer-apps list` (TX§6.1).
pub fn render_customer_apps(
    out: &mut Output,
    apps: &[OValue],
    format: Format,
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(apps),
        Format::Table => {
            emit_table(
                out,
                &["ID", "Name", "Description"],
                &rows(apps, &["id", "name", "description"]),
            );
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if apps.is_empty() {
                pretty::empty_list(out, "customer apps");
                return Ok(());
            }
            pretty::section(out, "Customer Apps:");
            for app in apps {
                if let Some(id) = truthy(app.get("id")) {
                    let id = out.paint(Style::Dim, &id);
                    out.data_line(&format!("  {id}"));
                }
                let description = match app.get("description") {
                    Some(OValue::String(text)) if !text.is_empty() => {
                        let (preview, _) = utf16_prefix(text, DESCRIPTION_UNITS);
                        out.paint(Style::Dim, &format!(" — {}", terminal_safe(preview)))
                    }
                    _ => String::new(),
                };
                out.data_line(&format!(
                    "    {}{description}",
                    shown_value(app.get("name"))
                ));
            }
            out.data("\n");
            Ok(())
        }
    }
}

/// `customer-apps get` (TX§6.2; the `ID` row and the cut note, D207).
pub fn render_customer_app(out: &mut Output, app: &OValue, format: Format) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(app),
        Format::Table => {
            out.data_line(&table::key_value_table(
                ["id", "name", "description", "raw"]
                    .iter()
                    .map(|key| ((*key).to_owned(), cell_text(app.get(key))))
                    .collect(),
            ));
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            pretty::section(out, "Customer App Detail:");
            let mut pairs: Vec<(&str, String)> = Vec::new();
            if let Some(id) = truthy(app.get("id")) {
                pairs.push(("ID", id));
            }
            pairs.push(("Name", shown_value(app.get("name"))));
            if let Some(description) = truthy(app.get("description")) {
                pairs.push(("Desc", description));
            }
            let raw = app.get("raw").cloned().unwrap_or(OValue::Null);
            let data = crate::json::to_pretty(&raw).map_err(|_| serialization_failed())?;
            let (data, cut) = utf16_prefix(&data, DATA_UNITS);
            pairs.push(("Data", terminal_safe_lines(data).into_owned()));
            pretty::key_value(out, &pairs);
            if cut {
                let note = out.paint(
                    Style::Dim,
                    "… (cut at 500 characters; use --output json for the whole record)",
                );
                out.data_line(&format!("  {note}"));
            }
            out.data("\n");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Deployment profiles (§18.10)
// ---------------------------------------------------------------------------

/// `{name, status, authCode}` (TS renderer `rr.ts:562-566`: each `?? ''`).
pub fn deployment_profile(row: &OValue) -> OValue {
    let member = |keys: &[&str]| first(row, keys).cloned().unwrap_or_else(|| string(""));
    OValue::Object(vec![
        (
            "name".to_owned(),
            member(&["dp_name", "profile_name", "name"]),
        ),
        ("status".to_owned(), member(&["status"])),
        ("authCode".to_owned(), member(&["auth_code"])),
    ])
}

/// `deployment-profiles list` (TX§7; an empty json list is `[]`, D222) of the sanitized
/// wire rows: json and table the [`deployment_profile`] projection, pretty the TS
/// renderer's own reads (`dp_name ?? profile_name ?? name ?? 'unknown'`, so an empty
/// name prints empty).
pub fn render_deployment_profiles(
    out: &mut Output,
    raw: &[OValue],
    format: Format,
) -> Result<(), CliError> {
    let projected: Vec<OValue> = raw.iter().map(deployment_profile).collect();
    match format {
        Format::Json => out.json(&projected),
        Format::Table => {
            emit_table(
                out,
                &["Name", "Status", "Auth Code"],
                &rows(&projected, &["name", "status", "authCode"]),
            );
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if raw.is_empty() {
                pretty::empty_list(out, "deployment profiles");
                return Ok(());
            }
            pretty::section(out, "Deployment Profiles:");
            for row in raw {
                let name = match first(row, &["dp_name", "profile_name", "name"]) {
                    None => "unknown".to_owned(),
                    some => shown_value(some),
                };
                let status = match row.get("status") {
                    Some(OValue::String(status)) if !status.is_empty() => {
                        let style = if status == "active" {
                            Style::Green
                        } else {
                            Style::Dim
                        };
                        format!("  {}", out.paint(style, &terminal_safe(status)))
                    }
                    _ => String::new(),
                };
                let code = truthy(row.get("auth_code"))
                    .map(|code| format!("  {}", out.paint(Style::Dim, &code)))
                    .unwrap_or_default();
                out.data_line(&format!("    {name}{status}{code}"));
            }
            out.data("\n");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Consumption (§18.9)
// ---------------------------------------------------------------------------

/// One application's consumption, with only what the server sent (D209).
#[derive(Clone, Debug, PartialEq)]
pub struct Consumption {
    pub app_id: String,
    pub app_name: String,
    pub cloud: Option<String>,
    pub source: Option<String>,
    pub monitoring_since: Option<String>,
    pub profiles: Option<Vec<String>>,
    pub daily: Option<(serde_json::Number, Option<String>)>,
    pub monthly: Option<(serde_json::Number, Option<String>)>,
    pub sessions_total: Option<serde_json::Number>,
    pub sessions_violating: Option<serde_json::Number>,
    pub detectors: Vec<Detector>,
    pub total_violating: Option<serde_json::Number>,
}

/// One detector of the violation breakdown.
#[derive(Clone, Debug, PartialEq)]
pub struct Detector {
    pub kind: Option<String>,
    pub critical: Option<serde_json::Number>,
    pub high: Option<serde_json::Number>,
    pub medium: Option<serde_json::Number>,
    pub low: Option<serde_json::Number>,
    pub total: Option<serde_json::Number>,
}

fn number(value: &OValue, key: &str) -> Option<serde_json::Number> {
    match value.get(key) {
        Some(OValue::Number(number)) => Some(number.clone()),
        _ => None,
    }
}

fn owned(value: &OValue, key: &str) -> Option<String> {
    text(value, key).map(str::to_owned)
}

impl Consumption {
    /// TS `getCustomerAppConsumption` (`mgmt.ts:476-503`) without `?? 0`, `?? 'unknown'`
    /// and `?? []`: `application` is the `apps/application` answer, `breakdown` the
    /// `applicationviolationbreakdown` answer.
    pub fn from_answers(
        app_id: &str,
        app_name: &str,
        application: &OValue,
        breakdown: &OValue,
    ) -> Self {
        let tokens = application
            .get("token_stats")
            .cloned()
            .unwrap_or(OValue::Null);
        let sessions = application
            .get("session_stats")
            .cloned()
            .unwrap_or(OValue::Null);
        let token = |value: &str, scale: &str| {
            number(&tokens, value).map(|number| (number, owned(&tokens, scale)))
        };
        let profiles = application.get("profiles").and_then(|profiles| {
            profiles.as_array().map(|items| {
                items
                    .iter()
                    .filter_map(OValue::as_str)
                    .map(str::to_owned)
                    .collect()
            })
        });
        let detectors = breakdown
            .get("detection_type_violation_breakdown")
            .and_then(OValue::as_array)
            .unwrap_or_default()
            .iter()
            .map(|entry| {
                let counts = entry
                    .get("violation_breakdown")
                    .cloned()
                    .unwrap_or(OValue::Null);
                Detector {
                    kind: owned(entry, "detection_type"),
                    critical: number(&counts, "critical"),
                    high: number(&counts, "high"),
                    medium: number(&counts, "medium"),
                    low: number(&counts, "low"),
                    total: number(&counts, "total"),
                }
            })
            .collect();
        Self {
            app_id: app_id.to_owned(),
            app_name: app_name.to_owned(),
            cloud: owned(application, "cloud"),
            source: owned(application, "source"),
            monitoring_since: owned(application, "created_at"),
            profiles,
            daily: token("average_daily_tokens", "average_daily_tokens_scale"),
            monthly: token("monthly_total_tokens", "monthly_total_tokens_scale"),
            sessions_total: number(&sessions, "total"),
            sessions_violating: number(&sessions, "violating"),
            detectors,
            total_violating: number(breakdown, "total_violating"),
        }
    }

    /// Every server string `[withheld]` when it carries a secret.
    pub fn withhold(&mut self, secrets: &SecretSet) {
        let scrub = |text: &mut String| {
            if secrets.carried_by(text) {
                *text = WITHHELD.to_owned();
            }
        };
        scrub(&mut self.app_id);
        scrub(&mut self.app_name);
        for text in [
            &mut self.cloud,
            &mut self.source,
            &mut self.monitoring_since,
        ]
        .into_iter()
        .flatten()
        {
            scrub(text);
        }
        for profile in self.profiles.iter_mut().flatten() {
            scrub(profile);
        }
        for (_, scale) in [&mut self.daily, &mut self.monthly].into_iter().flatten() {
            if let Some(scale) = scale {
                scrub(scale);
            }
        }
        for detector in &mut self.detectors {
            if let Some(kind) = &mut detector.kind {
                scrub(kind);
            }
        }
    }
}

/// `<n><scale>` (TS `fmt`), `None` when the count was not sent.
fn token_text(token: Option<&(serde_json::Number, Option<String>)>) -> Option<String> {
    token.map(|(number, scale)| {
        format!(
            "{}{}",
            js_json_number(number),
            scale.as_deref().unwrap_or("")
        )
    })
}

fn count(value: Option<&serde_json::Number>, absent: &str) -> String {
    value.map_or_else(|| absent.to_owned(), js_json_number)
}

fn number_value(value: Option<&serde_json::Number>) -> OValue {
    value.map_or(OValue::Null, |number| OValue::Number(number.clone()))
}

fn opt_string(value: Option<&str>) -> OValue {
    value.map_or(OValue::Null, string)
}

/// The json and table rows of `apps` (TS `rr.ts:467-505`): one row per detector, an app
/// without detectors as one row with `detector: null` (D210); absent values `null` (D209).
pub fn consumption_rows(apps: &[Consumption]) -> Vec<OValue> {
    let mut out = Vec::new();
    for app in apps {
        let context = |row: &mut Vec<(String, OValue)>| {
            row.push(("app_name".to_owned(), string(&app.app_name)));
            row.push(("app_id".to_owned(), string(&app.app_id)));
            row.push((
                "monitoring_since".to_owned(),
                opt_string(app.monitoring_since.as_deref()),
            ));
            row.push((
                "daily_avg".to_owned(),
                opt_string(token_text(app.daily.as_ref()).as_deref()),
            ));
            row.push((
                "monthly_total".to_owned(),
                opt_string(token_text(app.monthly.as_ref()).as_deref()),
            ));
            row.push((
                "sessions_total".to_owned(),
                number_value(app.sessions_total.as_ref()),
            ));
            row.push((
                "sessions_violating".to_owned(),
                number_value(app.sessions_violating.as_ref()),
            ));
        };
        let empty = Detector {
            kind: None,
            critical: None,
            high: None,
            medium: None,
            low: None,
            total: None,
        };
        let detectors: Vec<&Detector> = if app.detectors.is_empty() {
            vec![&empty]
        } else {
            app.detectors.iter().collect()
        };
        for detector in detectors {
            let mut row = Vec::new();
            context(&mut row);
            row.push(("detector".to_owned(), opt_string(detector.kind.as_deref())));
            for (key, value) in [
                ("critical", &detector.critical),
                ("high", &detector.high),
                ("medium", &detector.medium),
                ("low", &detector.low),
                ("total", &detector.total),
            ] {
                row.push((key.to_owned(), number_value(value.as_ref())));
            }
            out.push(OValue::Object(row));
        }
    }
    out
}

const CONSUMPTION_KEYS: [&str; 13] = [
    "app_name",
    "app_id",
    "monitoring_since",
    "daily_avg",
    "monthly_total",
    "sessions_total",
    "sessions_violating",
    "detector",
    "critical",
    "high",
    "medium",
    "low",
    "total",
];
const CONSUMPTION_LABELS: [&str; 13] = [
    "App",
    "AppId",
    "MonitoringSince",
    "DailyAvg",
    "MonthlyTotal",
    "Sessions",
    "Violating",
    "Detector",
    "C",
    "H",
    "M",
    "L",
    "Total",
];

/// `customer-apps consumption` for the apps that succeeded (§18.9): pretty one block per
/// app (TS `renderCustomerAppConsumption`), json one array for the run, table its rows.
/// `empty_overview`: the all-apps run found no dashboard application, so pretty prints
/// the §18.9 phrase (never when the overview had apps and their reads failed).
pub fn render_consumption(
    out: &mut Output,
    apps: &[Consumption],
    format: Format,
    empty_overview: bool,
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(&consumption_rows(apps)),
        Format::Table => {
            emit_table(
                out,
                &CONSUMPTION_LABELS,
                &rows(&consumption_rows(apps), &CONSUMPTION_KEYS),
            );
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if empty_overview {
                pretty::empty_list(out, "dashboard applications");
                return Ok(());
            }
            for app in apps {
                consumption_block(out, app);
            }
            Ok(())
        }
    }
}

fn consumption_block(out: &mut Output, app: &Consumption) {
    // The title is data (D222): TS prints it with `ui.header`, dropped by --quiet.
    let title = out.paint(Style::Bold, &terminal_safe(&app.app_name));
    let id = out.paint(Style::Dim, &format!("({})", terminal_safe(&app.app_id)));
    out.data(&format!("\n  {title}\n  {id}\n\n"));
    let mut pairs: Vec<(&str, String)> = Vec::new();
    for (key, value) in [
        ("Monitoring since", &app.monitoring_since),
        ("Source", &app.source),
        ("Cloud", &app.cloud),
    ] {
        if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
            pairs.push((key, terminal_safe(value).into_owned()));
        }
    }
    if let Some(profiles) = app
        .profiles
        .as_ref()
        .filter(|profiles| !profiles.is_empty())
    {
        pairs.push(("Profiles", terminal_safe(&profiles.join(", ")).into_owned()));
    }
    if !pairs.is_empty() {
        pretty::key_value(out, &pairs);
    }
    pretty::section(out, "Token consumption:");
    pretty::key_value(
        out,
        &[
            (
                "Daily avg",
                terminal_safe(&token_text(app.daily.as_ref()).unwrap_or_else(|| "-".to_owned()))
                    .into_owned(),
            ),
            (
                "Monthly total",
                terminal_safe(&token_text(app.monthly.as_ref()).unwrap_or_else(|| "-".to_owned()))
                    .into_owned(),
            ),
        ],
    );
    pretty::section(out, "Sessions:");
    pretty::key_value(
        out,
        &[
            ("Total", count(app.sessions_total.as_ref(), "-")),
            ("Violating", count(app.sessions_violating.as_ref(), "-")),
        ],
    );
    let firing: Vec<&Detector> = app
        .detectors
        .iter()
        .filter(|detector| {
            detector
                .total
                .as_ref()
                .and_then(serde_json::Number::as_f64)
                .is_some_and(|total| total > 0.0)
        })
        .collect();
    pretty::section(
        out,
        &format!(
            "Detectors ({} violating, {}/{} firing):",
            count(app.total_violating.as_ref(), "?"),
            firing.len(),
            app.detectors.len()
        ),
    );
    if firing.is_empty() {
        // Data under --quiet (D222).
        let note = out.paint(Style::Dim, "no detector violations in window");
        out.data_line(&format!("  {note}"));
    } else {
        let rows: Vec<Vec<String>> = firing
            .iter()
            .map(|detector| {
                vec![
                    terminal_safe(detector.kind.as_deref().unwrap_or("?")).into_owned(),
                    count(detector.total.as_ref(), "?"),
                    format!(
                        "c={} h={} m={} l={}",
                        count(detector.critical.as_ref(), "?"),
                        count(detector.high.as_ref(), "?"),
                        count(detector.medium.as_ref(), "?"),
                        count(detector.low.as_ref(), "?")
                    ),
                ]
            })
            .collect();
        let text = table::table(&["Detector", "Total", "Severity"], &rows);
        let indented: Vec<String> = text.split('\n').map(|line| format!("  {line}")).collect();
        out.data_line(&indented.join("\n"));
    }
    out.data("\n");
}

// ---------------------------------------------------------------------------
// Dashboard and sessions (§18.12, §18.13)
// ---------------------------------------------------------------------------

/// The row table of a list-shaped dashboard answer (D212).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DashTable {
    /// `dashboard applications`: `items[]`.
    Applications,
    /// `dashboard top-applications`: `applications[]`.
    TopApplications,
    /// `dashboard apps-list`: `applications[]`.
    AppsList,
    /// `sessions list`: the bare `items` array.
    Sessions,
    /// Anything else: `Key │ Value` of the envelope.
    Envelope,
}

/// A row table: the member that holds the rows (`None`: the document is the bare array),
/// the column labels and the row keys.
type RowLayout = (
    Option<&'static str>,
    &'static [&'static str],
    &'static [&'static str],
);

impl DashTable {
    fn layout(self) -> Option<RowLayout> {
        Some(match self {
            Self::Applications => (
                Some("items"),
                &["ID", "Name", "Cloud", "Source", "Sessions", "Violating"],
                &[
                    "id",
                    "name",
                    "cloud",
                    "source",
                    "sessions_total",
                    "sessions_violated",
                ],
            ),
            Self::TopApplications => (
                Some("applications"),
                &["ID", "Name", "Violations"],
                &["id", "name", "total_violations"],
            ),
            Self::AppsList => (
                Some("applications"),
                &["ID", "Name"],
                &["application_id", "application_name"],
            ),
            Self::Sessions => (
                None,
                &[
                    "Application",
                    "Application ID",
                    "Session ID",
                    "Status",
                    "Last activity",
                ],
                &[
                    "application_name",
                    "application_id",
                    "session_id",
                    "violation_status",
                    "last_session_activity",
                ],
            ),
            Self::Envelope => return None,
        })
    }
}

/// A dashboard or sessions document (already sanitized) in `format`: pretty and json the
/// JSON text, table the row table or `Key │ Value` (D212).
pub fn render_dashboard(
    out: &mut Output,
    doc: &OValue,
    format: Format,
    layout: DashTable,
) -> Result<(), CliError> {
    match format {
        Format::Pretty | Format::Json => {
            let text = json_text(doc)?;
            out.data_line(&text);
            Ok(())
        }
        Format::Table => {
            match layout.layout() {
                Some((member, labels, keys)) => {
                    let items = match member {
                        None => doc.as_array(),
                        Some(member) => doc.get(member).and_then(OValue::as_array),
                    };
                    match items {
                        Some(items) => emit_table(out, labels, &rows(items, keys)),
                        None => out.data_line(&key_value_table(doc)),
                    }
                }
                None => out.data_line(&key_value_table(doc)),
            }
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

    #[test]
    fn api_key_members_are_removed_at_any_depth_and_registered() {
        let secrets = SecretSet::default();
        let mut doc = v(
            r#"{"api_key":"FAKE-K1","a":[{"api_key":"FAKE-K2","b":"x FAKE-K1 y"}],"api_key_last8":"K1"}"#,
        );
        sanitize(&mut doc, &secrets);
        assert_eq!(
            crate::json::to_compact(&doc).unwrap(),
            r#"{"a":[{"b":"[withheld]"}],"api_key_last8":"K1"}"#
        );
        assert!(secrets.carried_by("FAKE-K2"));
    }

    /// D207: `creation_ts`, `expiration` and `customer_appId` are read when TS's keys are
    /// absent; TS's own keys win.
    #[test]
    fn projections_read_the_wire_keys() {
        let key = api_key(&v(
            r#"{"api_key_id":"k1","api_key_last8":"ABCD1234","api_key_name":"n","creation_ts":"c","expiration":"e"}"#,
        ));
        assert_eq!(
            crate::json::to_compact(&key).unwrap(),
            r#"{"id":"k1","name":"n","last8":"ABCD1234","createdAt":"c","expiresAt":"e"}"#
        );
        let key = api_key(&v(
            r#"{"id":"x","api_key_id":"k1","expires_at":"E","expiration":"e"}"#,
        ));
        assert_eq!(
            crate::json::to_compact(&key).unwrap(),
            r#"{"id":"x","name":"","expiresAt":"E"}"#
        );
        let app = customer_app(&v(r#"{"customer_appId":"a1","app_name":"one"}"#));
        assert_eq!(
            crate::json::to_compact(&app).unwrap(),
            r#"{"id":"a1","name":"one","raw":{"customer_appId":"a1","app_name":"one"}}"#
        );
    }

    #[test]
    fn api_key_list_bytes() {
        let keys = vec![
            api_key(&v(
                r#"{"api_key_id":"k1","api_key_name":"one","api_key_last8":"LAST8-01","expires_at":"2027"}"#,
            )),
            api_key(&v(r#"{"api_key_id":"k2"}"#)),
        ];
        let (mut out, stdout, _) = capture(true);
        render_api_keys(&mut out, &keys, Format::Pretty).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "  k1\n    one key: …LAST8-01 expires: 2027\n  k2\n    \n\n",
            "--quiet keeps the key ids (D222)"
        );
        let (mut out, stdout, _) = capture_colored(false);
        render_api_keys(&mut out, &keys[..1], Format::Pretty).unwrap();
        out.commit().unwrap();
        assert!(stdout.text().ends_with(
            "  \u{1b}[2mk1\u{1b}[22m\n    one\u{1b}[2m key: …LAST8-01\u{1b}[22m\u{1b}[2m expires: 2027\u{1b}[22m\n\n"
        ));
    }

    #[test]
    fn customer_app_data_is_cut_with_a_note() {
        let long = "x".repeat(600);
        let app = customer_app(&v(&format!(
            r#"{{"customer_appId":"a1","app_name":"one","notes":"{long}"}}"#
        )));
        let (mut out, stdout, _) = capture(false);
        render_customer_app(&mut out, &app, Format::Pretty).unwrap();
        out.commit().unwrap();
        let text = stdout.text();
        assert!(text.contains("\n  ID    a1\n  Name  one\n  Data  {\n  \"customer_appId\""));
        assert!(text.ends_with(
            "\n  … (cut at 500 characters; use --output json for the whole record)\n\n"
        ));
    }

    #[test]
    fn deployment_profiles_and_empty_json() {
        let (mut out, stdout, _) = capture(false);
        render_deployment_profiles(&mut out, &[], Format::Json).unwrap();
        out.commit().unwrap();
        assert_eq!(stdout.text(), "[]\n", "D222");
        let raw = vec![v(
            r#"{"dp_name":"dp-1","auth_code":"CODE","status":"active"}"#,
        )];
        let (mut out, stdout, _) = capture_colored(false);
        render_deployment_profiles(&mut out, &raw, Format::Pretty).unwrap();
        out.commit().unwrap();
        assert!(
            stdout
                .text()
                .ends_with("    dp-1  \u{1b}[32mactive\u{1b}[39m  \u{1b}[2mCODE\u{1b}[22m\n\n")
        );
        // TS: an absent `status` or `auth_code` is `''` in json; an empty `dp_name` prints
        // empty, only an absent name is `unknown`.
        let raw = vec![
            v(r#"{"dp_name":"dp-1","auth_code":"A"}"#),
            v(r#"{"dp_name":"","status":"activated"}"#),
            v(r#"{"status":null}"#),
        ];
        let (mut out, stdout, _) = capture(false);
        render_deployment_profiles(&mut out, &raw, Format::Json).unwrap();
        out.commit().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stdout.text()).unwrap(),
            serde_json::json!([
                {"name": "dp-1", "status": "", "authCode": "A"},
                {"name": "", "status": "activated", "authCode": ""},
                {"name": "", "status": "", "authCode": ""}
            ])
        );
        let (mut out, stdout, _) = capture(false);
        render_deployment_profiles(&mut out, &raw, Format::Pretty).unwrap();
        out.commit().unwrap();
        assert!(
            stdout
                .text()
                .ends_with("    dp-1  A\n      activated\n    unknown\n\n"),
            "{}",
            stdout.text()
        );
    }

    /// D209: the TS spec's `null` stats print no invented zeros.
    #[test]
    fn consumption_invents_nothing() {
        let app = Consumption::from_answers(
            "uuid-shared",
            "chatbot",
            &v(r#"{"name":null,"token_stats":null,"session_stats":null,"profiles":null}"#),
            &v("{}"),
        );
        assert_eq!(app.sessions_total, None);
        assert_eq!(app.profiles, None);
        assert!(app.detectors.is_empty());
        assert_eq!(app.total_violating, None);
        let projected = consumption_rows(std::slice::from_ref(&app));
        assert_eq!(
            crate::json::to_compact(&projected).unwrap(),
            r#"[{"app_name":"chatbot","app_id":"uuid-shared","monitoring_since":null,"daily_avg":null,"monthly_total":null,"sessions_total":null,"sessions_violating":null,"detector":null,"critical":null,"high":null,"medium":null,"low":null,"total":null}]"#
        );
        let (mut out, stdout, _) = capture(false);
        render_consumption(&mut out, &[app], Format::Pretty, false).unwrap();
        out.commit().unwrap();
        assert!(stdout.text().ends_with(
            "\n  chatbot\n  (uuid-shared)\n\n\n  Token consumption:\n\n  Daily avg      -\n  Monthly total  -\n\n  Sessions:\n\n  Total      -\n  Violating  -\n\n  Detectors (? violating, 0/0 firing):\n\n  no detector violations in window\n\n"
        ));
    }

    /// §18.9: the empty-overview phrase follows the overview, not the apps that were read:
    /// an overview whose every read failed prints only the banner.
    #[test]
    fn the_empty_overview_phrase_needs_an_empty_overview() {
        let (mut out, stdout, _) = capture(false);
        render_consumption(&mut out, &[], Format::Pretty, true).unwrap();
        out.commit().unwrap();
        assert!(
            stdout
                .text()
                .ends_with("\n\n  No dashboard applications found\n")
        );
        let (mut out, stdout, _) = capture(false);
        render_consumption(&mut out, &[], Format::Pretty, false).unwrap();
        out.commit().unwrap();
        assert!(!stdout.text().contains("No dashboard applications found"));
        let (mut out, stdout, _) = capture(false);
        render_consumption(&mut out, &[], Format::Json, false).unwrap();
        out.commit().unwrap();
        assert_eq!(stdout.text(), "[]\n");
    }

    /// The TS capture of TX§6.5 (with every value sent).
    #[test]
    fn consumption_pretty_matches_the_typescript_capture() {
        let app = Consumption::from_answers(
            "uuid-shared",
            "chatbot",
            &v(
                r#"{"cloud":"other","source":"api","created_at":"2026-04-29T17:04:52Z","profiles":["ms-tuned","golden-v2"],"token_stats":{"average_daily_tokens":744.233,"average_daily_tokens_scale":"K","monthly_total_tokens":17.71,"monthly_total_tokens_scale":"M"},"session_stats":{"total":56935,"violating":31136}}"#,
            ),
            &v(
                r#"{"detection_type_violation_breakdown":[{"detection_type":"topic_guardrails","violation_breakdown":{"critical":0,"high":0,"medium":3,"low":0,"total":3}},{"detection_type":"pi","violation_breakdown":{"critical":1,"high":2,"medium":0,"low":0,"total":3}},{"detection_type":"dlp","violation_breakdown":{"critical":0,"high":0,"medium":0,"low":0,"total":0}}],"total_violating":6}"#,
            ),
        );
        let (mut out, stdout, _) = capture(false);
        render_consumption(&mut out, &[app], Format::Pretty, false).unwrap();
        out.commit().unwrap();
        assert!(stdout.text().ends_with("\n  chatbot\n  (uuid-shared)\n\n  Monitoring since  2026-04-29T17:04:52Z\n  Source            api\n  Cloud             other\n  Profiles          ms-tuned, golden-v2\n\n  Token consumption:\n\n  Daily avg      744.233K\n  Monthly total  17.71M\n\n  Sessions:\n\n  Total      56935\n  Violating  31136\n\n  Detectors (6 violating, 2/3 firing):\n\n   Detector         │ Total │ Severity        \n  ──────────────────┼───────┼─────────────────\n   topic_guardrails │ 3     │ c=0 h=0 m=3 l=0 \n   pi               │ 3     │ c=1 h=2 m=0 l=0 \n\n"));
    }

    #[test]
    fn dashboard_tables() {
        let doc = v(
            r#"{"items":[{"id":"a","name":"n","cloud":"aws","source":"api","sessions_total":4,"sessions_violated":1}],"pagination":{"total_items":1}}"#,
        );
        let (mut out, stdout, _) = capture(false);
        render_dashboard(&mut out, &doc, Format::Table, DashTable::Applications).unwrap();
        render_dashboard(
            &mut out,
            &v(r#"{"bucket_size_seconds":3600,"buckets":[]}"#),
            Format::Table,
            DashTable::Envelope,
        )
        .unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            " ID │ Name │ Cloud │ Source │ Sessions │ Violating \n────┼──────┼───────┼────────┼──────────┼───────────\n a  │ n    │ aws   │ api    │ 4        │ 1         \n Key                 │ Value \n─────────────────────┼───────\n bucket_size_seconds │ 3600  \n buckets             │ []    \n"
        );
    }
}
