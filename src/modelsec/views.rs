//! The model-security documents and layouts (DESIGN §17.3–§17.7): the TypeScript
//! normalisers (`svc.ts:29-192`) over the SDK answers as ordered JSON, without the values
//! TypeScript invents (D180), and the pretty (`renderer/modelsecurity.ts` bytes), table and
//! json renderings.
//!
//! A document is built from the raw answer: a key the answer lacks is omitted, `null` is
//! kept (TypeScript `raw.x as T`). An eval summary keeps TypeScript's keys with `null` for
//! a count the server did not send. Model URIs are printed in their withheld form
//! (userinfo, query and fragment `[withheld]`, D191). Server text is `[withheld]` when it
//! carries a known secret, and every string printed in a pretty layout or a table cell
//! goes through `terminal_safe` (D52).

use crate::error::{CliError, SecretSet, WITHHELD};
use crate::json::OValue;
use crate::output::{Format, Output, terminal_safe, terminal_safe_lines};
use crate::redteam::views::{Doc, dim_data, key_values, present};
use crate::render::style::Style;
use crate::render::{cell_text, js_json_number, pretty, table};

/// The record kinds (one TypeScript normaliser each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Group,
    Rule,
    RuleInstance,
    Scan,
    Evaluation,
    Violation,
    File,
    Model,
    ModelVersion,
}

/// The list layouts (`files` is one layout for scans and model versions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum List {
    Groups,
    Rules,
    RuleInstances,
    Scans,
    Evaluations,
    Violations,
    Files,
    Models,
    Versions,
}

impl List {
    /// The record kind of the rows.
    pub fn kind(self) -> Kind {
        match self {
            Self::Groups => Kind::Group,
            Self::Rules => Kind::Rule,
            Self::RuleInstances => Kind::RuleInstance,
            Self::Scans => Kind::Scan,
            Self::Evaluations => Kind::Evaluation,
            Self::Violations => Kind::Violation,
            Self::Files => Kind::File,
            Self::Models => Kind::Model,
            Self::Versions => Kind::ModelVersion,
        }
    }

    /// The `ui.emptyList` resource word.
    fn empty(self) -> &'static str {
        match self {
            Self::Groups => "security groups",
            Self::Rules => "security rules",
            Self::RuleInstances => "rule instances",
            Self::Scans => "scans",
            Self::Evaluations => "evaluations",
            Self::Violations => "violations",
            Self::Files => "files",
            Self::Models => "models",
            Self::Versions => "versions",
        }
    }
}

// ---------------------------------------------------------------------------
// Model URIs (D191)
// ---------------------------------------------------------------------------

/// A URI that parses with an authority, and its parts to withhold.
fn parsed_uri(text: &str) -> Option<url::Url> {
    let url = url::Url::parse(text).ok()?;
    url.has_host().then_some(url)
}

/// The withheld form of a model URI (§17.3 "Model URIs"): userinfo → `[withheld]@`, a
/// query → `?[withheld]`, a fragment → `#[withheld]`; scheme, host, port and path kept. A
/// value without such parts, or that does not parse with an authority, is returned as it
/// is (the caller makes it terminal-safe).
pub fn withheld_uri(text: &str) -> String {
    let Some(url) = parsed_uri(text) else {
        return text.to_owned();
    };
    let userinfo = !url.username().is_empty() || url.password().is_some();
    if !userinfo && url.query().is_none() && url.fragment().is_none() {
        return text.to_owned();
    }
    let mut out = format!("{}://", url.scheme());
    if userinfo {
        out.push_str(WITHHELD);
        out.push('@');
    }
    out.push_str(url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        out.push_str(&format!(":{port}"));
    }
    out.push_str(url.path());
    if url.query().is_some() {
        out.push('?');
        out.push_str(WITHHELD);
    }
    if url.fragment().is_some() {
        out.push('#');
        out.push_str(WITHHELD);
    }
    out
}

/// The query keys whose values are credentials or signatures (ASCII case ignored):
/// their values join the `SecretSet` whatever their length (§17.3, choice 44).
pub const CREDENTIAL_QUERY_KEYS: [&str; 26] = [
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "x-goog-signature",
    "x-goog-credential",
    "x-goog-security-token",
    "x-ms-signature",
    "signature",
    "sig",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "session_token",
    "security_token",
    "sas",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "key",
    "code",
    "auth",
    "credential",
];

/// The shortest URI part that joins the `SecretSet` without being a credential (a
/// password or the value of a [`CREDENTIAL_QUERY_KEYS`] key): shorter ones such as
/// `host`, `3600` or `b` are ordinary words that would withhold unrelated names.
pub const MIN_URI_PART: usize = 8;

/// The parts of a model URI that join the invocation's `SecretSet` before anything is
/// printed (choice 44), raw and percent-decoded: the password and the value of every
/// credential query key whatever their length; the username, the fragment and every
/// other query value (a bare query word included) of at least [`MIN_URI_PART`]
/// characters. The printed URI withholds the whole userinfo, query and fragment anyway.
pub fn uri_secrets(text: &str) -> Vec<String> {
    let Some(url) = parsed_uri(text) else {
        return Vec::new();
    };
    let decode = |part: &str| -> String {
        url::form_urlencoded::parse(format!("x={part}").as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    };
    let mut parts = Vec::new();
    let mut push = |part: &str, credential: bool| {
        let decoded = decode(part);
        for form in [part, decoded.as_str()] {
            let long = form.chars().count() >= MIN_URI_PART;
            if !form.is_empty() && (credential || long) && !parts.iter().any(|p| p == form) {
                parts.push(form.to_owned());
            }
        }
    };
    push(url.username(), false);
    if let Some(password) = url.password() {
        push(password, true);
    }
    if let Some(query) = url.query() {
        for piece in query.split('&') {
            let (key, value) = piece.split_once('=').unwrap_or((piece, ""));
            let credential = CREDENTIAL_QUERY_KEYS
                .iter()
                .any(|known| decode(key).eq_ignore_ascii_case(known));
            if value.is_empty() {
                // A bare word (`?TOKEN`): the word itself may be the credential.
                push(key, false);
            } else {
                push(value, credential);
            }
        }
    }
    if let Some(fragment) = url.fragment() {
        push(fragment, false);
    }
    parts
}

/// Register the withheld parts of every `model_uri` in `rows` (raw scan records).
pub fn register_uris(rows: &[OValue], secrets: &SecretSet) {
    for row in rows {
        if let Some(uri) = row.get("model_uri").and_then(OValue::as_str) {
            for part in uri_secrets(uri) {
                secrets.add(&part);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Documents (the TS normalisers, D180)
// ---------------------------------------------------------------------------

/// The projection keys of a kind, in TypeScript's order; the table detail lists every
/// one (an absent value is an empty cell, TS) except the Rust additions, which appear only
/// when the server sent them (D192).
pub fn keys(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Group => &[
            "uuid",
            "name",
            "description",
            "sourceType",
            "state",
            "createdAt",
            "updatedAt",
        ],
        Kind::Rule => &[
            "uuid",
            "name",
            "description",
            "ruleType",
            "compatibleSources",
            "defaultState",
            "remediation",
            "editableFields",
            "constantValues",
            "defaultValues",
        ],
        Kind::RuleInstance => &[
            "uuid",
            "securityGroupUuid",
            "securityRuleUuid",
            "customRuleUuid",
            "state",
            "createdAt",
            "updatedAt",
            "rule",
            "customRule",
            "fieldValues",
        ],
        Kind::Scan => &[
            "uuid",
            "evalOutcome",
            "modelUri",
            "scanOrigin",
            "sourceType",
            "securityGroupName",
            "evalSummary",
            "createdAt",
            "updatedAt",
            "labels",
        ],
        Kind::Evaluation => &[
            "uuid",
            "result",
            "violationCount",
            "ruleInstanceUuid",
            "ruleName",
            "ruleDescription",
            "ruleInstanceState",
        ],
        Kind::Violation => &[
            "uuid",
            "description",
            "threat",
            "threatDescription",
            "file",
            "ruleName",
            "ruleDescription",
            "ruleInstanceState",
        ],
        Kind::File => &["uuid", "path", "type", "formats", "result"],
        Kind::Model => &[
            "uuid",
            "tsgId",
            "name",
            "createdAt",
            "updatedAt",
            "latestVersionUuid",
            "latestVersionFingerprint",
            "latestVersionRevision",
            "latestVersionHfCommitSha",
            "latestVersionOutcome",
            "latestVersionFormats",
            "latestVersionSourceTypes",
            "latestVersionScanTime",
        ],
        Kind::ModelVersion => &[
            "uuid",
            "tsgId",
            "modelUuid",
            "revision",
            "createdAt",
            "updatedAt",
            "fingerprint",
            "fileCount",
            "license",
            "latestScanTime",
            "hfCommitSha",
            "hfCommitTitle",
            "hfCommitAuthors",
            "hfModelName",
            "hfOrganization",
            "modelFormats",
            "sourceTypes",
            "lastEvalOutcome",
            "lastEvalSummary",
        ],
    }
}

/// The keys TypeScript does not print (D192): listed only when present.
const RUST_ONLY: [&str; 2] = ["customRuleUuid", "customRule"];

/// The snake_case wire key of a projection key (`sourceType` → `source_type`).
fn wire_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// An eval summary as TypeScript projects it (`{rulesFailed, rulesPassed, totalRules}`),
/// with `null` for a count the server did not send (D180).
fn summary(raw: &OValue) -> OValue {
    let count = |key: &str| raw.get(key).cloned().unwrap_or(OValue::Null);
    Doc::default()
        .put("rulesFailed", Some(count("rules_failed")))
        .put("rulesPassed", Some(count("rules_passed")))
        .put("totalRules", Some(count("total_rules")))
        .build()
}

/// An editable field of a rule (`svc.ts:61-71`).
fn editable_field(raw: &OValue) -> OValue {
    Doc::default()
        .copy(raw, "attribute_name", "attributeName")
        .copy(raw, "type", "type")
        .copy(raw, "display_name", "displayName")
        .copy(raw, "display_type", "displayType")
        .copy(raw, "description", "description")
        .copy(raw, "dropdown_values", "dropdownValues")
        .build()
}

/// The TypeScript projection of a raw record (snake_case wire keys → camelCase), the
/// values TypeScript invents left out (D180), model URIs in their withheld form (D191).
pub fn project(kind: Kind, raw: &OValue) -> OValue {
    let mut doc = Doc::default();
    for key in keys(kind) {
        let value = match (kind, *key) {
            (Kind::Scan, "evalSummary") => Some(match raw.get("eval_summary") {
                Some(object @ OValue::Object(_)) => summary(object),
                _ => OValue::Null,
            }),
            (Kind::ModelVersion, "lastEvalSummary") => match raw.get("last_eval_summary") {
                Some(object @ OValue::Object(_)) => Some(summary(object)),
                other => other.cloned(),
            },
            (Kind::Scan, "modelUri") => raw.get("model_uri").map(|uri| match uri {
                OValue::String(text) => OValue::String(withheld_uri(text)),
                other => other.clone(),
            }),
            (Kind::Rule, "editableFields") => {
                raw.get("editable_fields").map(|fields| match fields {
                    OValue::Array(items) => {
                        OValue::Array(items.iter().map(editable_field).collect())
                    }
                    other => other.clone(),
                })
            }
            (Kind::RuleInstance, "customRule") => raw.get("custom_rule").cloned(),
            (_, "tsgId") => raw.get("tsg_id").cloned(),
            (_, key) => raw.get(&wire_key(key)).cloned(),
        };
        doc = doc.put(key, value);
    }
    doc.build()
}

/// Projections of raw rows.
pub fn project_all(kind: Kind, rows: &[OValue]) -> Vec<OValue> {
    rows.iter().map(|row| project(kind, row)).collect()
}

/// Server-text keys whose string values are `[withheld]` when they carry a secret or a
/// fragment of one (§17.3 "Server text"); ids, states, outcomes and timestamps are not
/// checked.
const TEXT_KEYS: [&str; 12] = [
    "name",
    "description",
    "displayName",
    "ruleName",
    "ruleDescription",
    "threatDescription",
    "securityGroupName",
    "path",
    "file",
    "key",
    "value",
    "display_name",
];

/// `[withheld]` for the server-text strings of `doc` (at any depth) that carry a secret
/// of `secrets` (§17.3, as §15.3).
pub fn withhold(doc: &mut OValue, secrets: &SecretSet) {
    withhold_in(doc, false, secrets);
}

fn withhold_in(doc: &mut OValue, text_key: bool, secrets: &SecretSet) {
    match doc {
        OValue::String(text) if text_key && secrets.taints(text) => {
            *text = WITHHELD.to_owned();
        }
        OValue::Array(items) => {
            for item in items {
                withhold_in(item, text_key, secrets);
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

/// The label keys or values of `labels keys|values`, each `[withheld]` when it carries a
/// secret.
pub fn withhold_strings(items: &mut [String], secrets: &SecretSet) {
    for item in items {
        if secrets.taints(item) {
            *item = WITHHELD.to_owned();
        }
    }
}

// ---------------------------------------------------------------------------
// Pretty primitives
// ---------------------------------------------------------------------------

/// A string field, terminal-safe (empty when absent, `null` or not a string scalar).
fn text(doc: &OValue, key: &str) -> String {
    scalar(doc.get(key))
}

/// `String(v ?? '')` of a scalar, terminal-safe.
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

/// A multi-line server text field (descriptions keep their line breaks, §15.3).
fn prose(doc: &OValue, key: &str) -> String {
    match doc.get(key) {
        Some(OValue::String(text)) => terminal_safe_lines(text).into_owned(),
        other => scalar(other),
    }
}

/// Whether a string field is present and non-empty (JavaScript truthiness of a string).
fn truthy_text(doc: &OValue, key: &str) -> bool {
    doc.get(key)
        .and_then(OValue::as_str)
        .is_some_and(|text| !text.is_empty())
}

/// The items of a string array field, terminal-safe (non-strings as their text).
fn items(doc: &OValue, key: &str) -> Vec<String> {
    doc.get(key)
        .and_then(OValue::as_array)
        .map(|items| items.iter().map(|item| scalar(Some(item))).collect())
        .unwrap_or_default()
}

/// `stateColor` (`rms.ts:50-67`).
pub fn state_style(state: &str) -> Style {
    match state {
        "ACTIVE" | "ALLOWED" | "ALLOWING" | "PASSED" | "SUCCESS" => Style::Green,
        "BLOCKED" | "BLOCKING" | "FAILED" => Style::Red,
        "DISABLED" => Style::Dim,
        _ => Style::Yellow,
    }
}

/// `stateColor(v)(v)` of a field.
fn state_span(out: &Output, doc: &OValue, key: &str) -> String {
    let value = text(doc, key);
    let raw = doc.get(key).and_then(OValue::as_str).unwrap_or_default();
    out.paint(state_style(raw), &value)
}

/// A group state: green `ACTIVE`, yellow otherwise.
fn group_state(out: &Output, doc: &OValue) -> String {
    let style = if doc.get("state").and_then(OValue::as_str) == Some("ACTIVE") {
        Style::Green
    } else {
        Style::Yellow
    };
    out.paint(style, &text(doc, "state"))
}

/// The banner (pretty only, decoration).
pub fn banner(out: &mut Output) {
    pretty::banner(out, super::BANNER_TITLE, Some(super::BANNER_SUBTITLE));
}

/// A count of a summary for pretty output: the number, `?` when the server sent none.
fn count(summary: &OValue, key: &str) -> String {
    match summary.get(key) {
        Some(OValue::Number(number)) => js_json_number(number),
        _ => "?".to_owned(),
    }
}

/// Whether a projected summary carries at least one count (D180).
fn has_count(summary: Option<&OValue>) -> bool {
    summary.is_some_and(|summary| {
        ["rulesFailed", "rulesPassed", "totalRules"]
            .iter()
            .any(|key| matches!(summary.get(key), Some(OValue::Number(_))))
    })
}

/// `<green N passed>  <red N failed>  / T total`.
fn rules_span(out: &Output, summary: &OValue) -> String {
    format!(
        "{}  {}  / {} total",
        out.paint(
            Style::Green,
            &format!("{} passed", count(summary, "rulesPassed"))
        ),
        out.paint(
            Style::Red,
            &format!("{} failed", count(summary, "rulesFailed"))
        ),
        count(summary, "totalRules")
    )
}

/// A rule instance's label (D192): the first present of the rule's name, the custom
/// rule's name, `securityRuleUuid`, `customRuleUuid`; else empty (TS `undefined`).
fn instance_label(doc: &OValue) -> String {
    let name = |key: &str| {
        doc.get(key)
            .and_then(|rule| rule.get("name"))
            .filter(|v| present(Some(v)))
    };
    name("rule")
        .or_else(|| name("customRule"))
        .or_else(|| doc.get("securityRuleUuid").filter(|v| present(Some(v))))
        .or_else(|| doc.get("customRuleUuid").filter(|v| present(Some(v))))
        .map(|value| scalar(Some(value)))
        .unwrap_or_default()
}

/// The `Rule UUID` / `Rule ID` of an instance: `securityRuleUuid`, else `customRuleUuid`.
fn instance_rule_id(doc: &OValue) -> Option<&OValue> {
    doc.get("securityRuleUuid")
        .filter(|value| present(Some(value)))
        .or_else(|| {
            doc.get("customRuleUuid")
                .filter(|value| present(Some(value)))
        })
}

/// A field value as the pretty detail prints it: arrays joined `, `, objects as compact
/// JSON (TS `[object Object]`, D192), other values `String(v)`.
fn field_value(value: &OValue) -> String {
    match value {
        OValue::Array(items) => items
            .iter()
            .map(|item| match item {
                OValue::Null => String::new(),
                other => scalar(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(", "),
        other => scalar(Some(other)),
    }
}

// ---------------------------------------------------------------------------
// Pretty layouts (`rms.ts`)
// ---------------------------------------------------------------------------

fn groups_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Security Groups:");
    for row in rows {
        dim_data(out, &text(row, "uuid"));
        let state = group_state(out, row);
        let source = out.paint(Style::Dim, &text(row, "sourceType"));
        out.data_line(&format!(
            "    {}  {state}  source: {source}",
            text(row, "name")
        ));
    }
    out.data_line("");
}

fn group_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Security Group Detail:");
    let description = if truthy_text(doc, "description") {
        prose(doc, "description")
    } else {
        out.paint(Style::Dim, "(none)")
    };
    let state = group_state(out, doc);
    pretty::key_value(
        out,
        &[
            ("UUID", text(doc, "uuid")),
            ("Name", text(doc, "name")),
            ("Description", description),
            ("Source Type", text(doc, "sourceType")),
            ("State", state),
            ("Created", text(doc, "createdAt")),
            ("Updated", text(doc, "updatedAt")),
        ],
    );
    out.data_line("");
}

fn rules_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Security Rules:");
    for row in rows {
        dim_data(out, &text(row, "uuid"));
        let kind = out.paint(Style::Dim, &text(row, "ruleType"));
        let default = out.paint(Style::Dim, &text(row, "defaultState"));
        out.data_line(&format!(
            "    {}  type: {kind}  default: {default}",
            text(row, "name")
        ));
        let description = out.paint(Style::Dim, &prose(row, "description"));
        out.data_line(&format!("    {description}"));
        let sources: Vec<String> = items(row, "compatibleSources")
            .iter()
            .map(|source| out.paint(Style::Dim, source))
            .collect();
        out.data_line(&format!("    Sources: {}", sources.join(", ")));
    }
    out.data_line("");
}

fn rule_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Security Rule Detail:");
    pretty::key_value(
        out,
        &[
            ("UUID", text(doc, "uuid")),
            ("Name", text(doc, "name")),
            ("Description", prose(doc, "description")),
            ("Rule Type", text(doc, "ruleType")),
            ("Default State", text(doc, "defaultState")),
            ("Sources", items(doc, "compatibleSources").join(", ")),
        ],
    );
    if let Some(remediation) = doc.get("remediation")
        && truthy_text(remediation, "description")
    {
        pretty::section(out, "Remediation:");
        out.data_line(&format!("  {}", prose(remediation, "description")));
        if let Some(steps) = remediation.get("steps").and_then(OValue::as_array) {
            for step in steps {
                let step = match step {
                    OValue::String(text) => terminal_safe_lines(text).into_owned(),
                    other => scalar(Some(other)),
                };
                pretty::bullet(out, &step, pretty::Bullet::Neutral);
            }
        }
        if truthy_text(remediation, "url") {
            // Data: kept under --quiet (D190).
            dim_data(out, &text(remediation, "url"));
        }
    }
    if let Some(fields) = doc.get("editableFields").and_then(OValue::as_array)
        && !fields.is_empty()
    {
        pretty::section(out, "Editable Fields:");
        for field in fields {
            let attribute = out.paint(Style::Dim, &text(field, "attributeName"));
            out.data_line(&format!(
                "  {} ({attribute}): {}",
                text(field, "displayName"),
                text(field, "displayType")
            ));
            if truthy_text(field, "description") {
                let description = out.paint(Style::Dim, &prose(field, "description"));
                out.data_line(&format!("    {description}"));
            }
        }
    }
    out.data_line("");
}

fn instances_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Rule Instances:");
    for row in rows {
        dim_data(out, &text(row, "uuid"));
        let state = state_span(out, row, "state");
        out.data_line(&format!("    {}  {state}", instance_label(row)));
    }
    out.data_line("");
}

fn instance_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Rule Instance Detail:");
    let mut pairs = vec![
        ("UUID".to_owned(), text(doc, "uuid")),
        ("Group UUID".to_owned(), text(doc, "securityGroupUuid")),
        ("Rule UUID".to_owned(), scalar(instance_rule_id(doc))),
        ("State".to_owned(), state_span(out, doc, "state")),
    ];
    let name = |key: &str| {
        doc.get(key)
            .and_then(|rule| rule.get("name"))
            .and_then(OValue::as_str)
            .filter(|name| !name.is_empty())
    };
    if let Some(name) = name("rule").or_else(|| name("customRule")) {
        pairs.push(("Rule Name".to_owned(), terminal_safe(name).into_owned()));
    }
    pairs.push(("Created".to_owned(), text(doc, "createdAt")));
    pairs.push(("Updated".to_owned(), text(doc, "updatedAt")));
    key_values(out, &pairs);
    if let Some(values) = doc.get("fieldValues").and_then(OValue::as_object)
        && !values.is_empty()
    {
        pretty::section(out, "Field Values:");
        let pairs: Vec<(String, String)> = values
            .iter()
            .map(|(key, value)| (terminal_safe(key).into_owned(), field_value(value)))
            .collect();
        key_values(out, &pairs);
    }
    out.data_line("");
}

fn scans_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Model Security Scans:");
    for row in rows {
        dim_data(out, &text(row, "uuid"));
        let outcome = state_span(out, row, "evalOutcome");
        let origin = out.paint(Style::Dim, &text(row, "scanOrigin"));
        let created = out.paint(Style::Dim, &text(row, "createdAt"));
        out.data_line(&format!("    {outcome}  {origin}  {created}"));
        if truthy_text(row, "modelUri") {
            let uri = out.paint(Style::Dim, &text(row, "modelUri"));
            out.data_line(&format!("    {uri}"));
        }
        if let Some(summary) = row.get("evalSummary")
            && has_count(Some(summary))
        {
            let rules = rules_span(out, summary);
            out.data_line(&format!("    Rules: {rules}"));
        }
    }
    out.data_line("");
}

fn scan_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Scan Detail:");
    let mut pairs = vec![
        ("UUID", text(doc, "uuid")),
        ("Outcome", state_span(out, doc, "evalOutcome")),
    ];
    if truthy_text(doc, "modelUri") {
        pairs.push(("Model URI", text(doc, "modelUri")));
    }
    pairs.push(("Origin", text(doc, "scanOrigin")));
    pairs.push(("Source", text(doc, "sourceType")));
    pairs.push(("Group", text(doc, "securityGroupName")));
    pairs.push(("Created", text(doc, "createdAt")));
    pairs.push(("Updated", text(doc, "updatedAt")));
    if let Some(summary) = doc.get("evalSummary")
        && has_count(Some(summary))
    {
        pairs.push(("Rules", rules_span(out, summary)));
    }
    pretty::key_value(out, &pairs);
    if let Some(labels) = doc.get("labels").and_then(OValue::as_array)
        && !labels.is_empty()
    {
        pretty::section(out, "Labels:");
        let pairs: Vec<(String, String)> = labels
            .iter()
            .map(|label| (text(label, "key"), text(label, "value")))
            .collect();
        key_values(out, &pairs);
    }
    out.data_line("");
}

fn evaluations_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Rule Evaluations:");
    for row in rows {
        dim_data(out, &text(row, "uuid"));
        let result = state_span(out, row, "result");
        let state = out.paint(Style::Dim, &text(row, "ruleInstanceState"));
        out.data_line(&format!("    {}  {result}  {state}", text(row, "ruleName")));
    }
    out.data_line("");
}

fn evaluation_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Evaluation Detail:");
    let result = state_span(out, doc, "result");
    pretty::key_value(
        out,
        &[
            ("UUID", text(doc, "uuid")),
            ("Rule", text(doc, "ruleName")),
            ("Description", prose(doc, "ruleDescription")),
            ("Instance UUID", text(doc, "ruleInstanceUuid")),
            ("Instance State", text(doc, "ruleInstanceState")),
            ("Result", result),
            ("Violations", text(doc, "violationCount")),
        ],
    );
    out.data_line("");
}

fn violations_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Violations:");
    for row in rows {
        dim_data(out, &text(row, "uuid"));
        let rule = out.paint(Style::Red, &text(row, "ruleName"));
        let file = out.paint(Style::Dim, &text(row, "file"));
        out.data_line(&format!("    {rule}  {file}"));
        out.data_line(&format!("    {}", prose(row, "description")));
        let threat = out.paint(Style::Dim, &text(row, "threat"));
        out.data_line(&format!("    Threat: {threat}"));
    }
    out.data_line("");
}

fn violation_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Violation Detail:");
    let rule = out.paint(Style::Red, &text(doc, "ruleName"));
    pretty::key_value(
        out,
        &[
            ("UUID", text(doc, "uuid")),
            ("Rule", rule),
            ("Description", prose(doc, "ruleDescription")),
            ("State", text(doc, "ruleInstanceState")),
            ("File", text(doc, "file")),
            ("Threat", text(doc, "threat")),
            ("Detail", prose(doc, "description")),
        ],
    );
    out.data_line("");
}

fn files_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Scanned Files:");
    for row in rows {
        let result = row
            .get("result")
            .and_then(OValue::as_str)
            .unwrap_or_default();
        let style = match result {
            "SUCCESS" => Style::Green,
            "SKIPPED" => Style::Yellow,
            _ => Style::Red,
        };
        let result = out.paint(style, &text(row, "result"));
        let formats = items(row, "formats");
        let formats = if formats.is_empty() {
            String::new()
        } else {
            out.paint(Style::Dim, &format!(" [{}]", formats.join(", ")))
        };
        out.data_line(&format!(
            "    {result}  {}  {}{formats}",
            text(row, "type"),
            text(row, "path")
        ));
    }
    out.data_line("");
}

/// `stateColor(outcome)` of a present outcome, else dim `unscanned`.
fn outcome_or_unscanned(out: &Output, doc: &OValue, key: &str) -> String {
    if truthy_text(doc, key) {
        state_span(out, doc, key)
    } else {
        out.paint(Style::Dim, "unscanned")
    }
}

fn models_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Models:");
    for row in rows {
        dim_data(out, &text(row, "uuid"));
        let outcome = outcome_or_unscanned(out, row, "latestVersionOutcome");
        let formats = items(row, "latestVersionFormats");
        let formats = if formats.is_empty() {
            String::new()
        } else {
            out.paint(Style::Dim, &format!(" [{}]", formats.join(", ")))
        };
        out.data_line(&format!("    {}  {outcome}{formats}", text(row, "name")));
        out.data_line("");
    }
}

fn model_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Model Detail:");
    let mut pairs = vec![
        ("UUID", text(doc, "uuid")),
        ("Name", text(doc, "name")),
        ("Created", text(doc, "createdAt")),
        ("Updated", text(doc, "updatedAt")),
    ];
    let given = |key: &str| present(doc.get(key));
    if given("latestVersionUuid") {
        pairs.push(("Latest Version", text(doc, "latestVersionUuid")));
    }
    if given("latestVersionRevision") {
        pairs.push(("Latest Revision", text(doc, "latestVersionRevision")));
    }
    if given("latestVersionOutcome") {
        pairs.push((
            "Latest Outcome",
            state_span(out, doc, "latestVersionOutcome"),
        ));
    }
    let formats = items(doc, "latestVersionFormats");
    if !formats.is_empty() {
        pairs.push(("Formats", formats.join(", ")));
    }
    let sources = items(doc, "latestVersionSourceTypes");
    if !sources.is_empty() {
        pairs.push(("Source Types", sources.join(", ")));
    }
    if given("latestVersionScanTime") {
        pairs.push(("Last Scan", text(doc, "latestVersionScanTime")));
    }
    pretty::key_value(out, &pairs);
    out.data_line("");
}

fn versions_layout(out: &mut Output, rows: &[OValue]) {
    pretty::section(out, "Model Versions:");
    for row in rows {
        dim_data(out, &text(row, "uuid"));
        let outcome = outcome_or_unscanned(out, row, "lastEvalOutcome");
        let files = if present(row.get("fileCount")) {
            format!("  files: {}", text(row, "fileCount"))
        } else {
            String::new()
        };
        out.data_line(&format!("    {}  {outcome}{files}", text(row, "revision")));
        out.data_line("");
    }
}

fn version_layout(out: &mut Output, doc: &OValue) {
    pretty::section(out, "Model Version Detail:");
    let mut pairs = vec![
        ("UUID", text(doc, "uuid")),
        ("Model", text(doc, "modelUuid")),
        ("Revision", text(doc, "revision")),
        ("Created", text(doc, "createdAt")),
        ("Updated", text(doc, "updatedAt")),
    ];
    let given = |key: &str| present(doc.get(key));
    if given("fileCount") {
        pairs.push(("File Count", text(doc, "fileCount")));
    }
    if given("license") {
        pairs.push(("License", text(doc, "license")));
    }
    let formats = items(doc, "modelFormats");
    if !formats.is_empty() {
        pairs.push(("Formats", formats.join(", ")));
    }
    let sources = items(doc, "sourceTypes");
    if !sources.is_empty() {
        pairs.push(("Source Types", sources.join(", ")));
    }
    if given("hfModelName") {
        pairs.push(("HF Model", text(doc, "hfModelName")));
    }
    if given("hfOrganization") {
        pairs.push(("HF Organization", text(doc, "hfOrganization")));
    }
    if given("lastEvalOutcome") {
        pairs.push(("Last Outcome", state_span(out, doc, "lastEvalOutcome")));
    }
    if given("latestScanTime") {
        pairs.push(("Last Scan", text(doc, "latestScanTime")));
    }
    pretty::key_value(out, &pairs);
    if let Some(summary) = doc.get("lastEvalSummary")
        && has_count(Some(summary))
    {
        pretty::section(out, "Last Eval Summary:");
        pretty::key_value(
            out,
            &[
                ("Passed", count(summary, "rulesPassed")),
                ("Failed", count(summary, "rulesFailed")),
                ("Total", count(summary, "totalRules")),
            ],
        );
    }
    out.data_line("");
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// A table cell of a list column: the field's text, or a string array joined `, `
/// (TypeScript's `get` columns).
fn joined(value: Option<&OValue>) -> String {
    match value {
        Some(OValue::Array(items)) => items
            .iter()
            .map(|item| scalar(Some(item)))
            .collect::<Vec<_>>()
            .join(", "),
        other => cell_text(other),
    }
}

/// The list columns (`rms.ts`, MS§11.1, §11.3): labels and the cell of a row.
fn columns(list: List) -> &'static [&'static str] {
    match list {
        List::Groups => &["ID", "Name", "State", "Source Type"],
        List::Rules => &["ID", "Name", "Type", "Default State", "Sources"],
        List::RuleInstances => &["ID", "Rule ID", "State"],
        List::Scans => &["ID", "Outcome", "Origin", "Model URI", "Created"],
        List::Evaluations => &["ID", "Rule", "Result", "State"],
        List::Violations => &["ID", "Rule", "File", "Threat"],
        List::Files => &["ID", "Path", "Type", "Result"],
        List::Models => &["ID", "Name", "Outcome", "Formats", "Last Scan"],
        List::Versions => &["ID", "Revision", "Files", "Outcome", "Last Scan"],
    }
}

fn row_cells(list: List, row: &OValue) -> Vec<String> {
    let cell = |key: &str| cell_text(row.get(key));
    match list {
        List::Groups => vec![
            cell("uuid"),
            cell("name"),
            cell("state"),
            cell("sourceType"),
        ],
        List::Rules => vec![
            cell("uuid"),
            cell("name"),
            cell("ruleType"),
            cell("defaultState"),
            joined(row.get("compatibleSources")),
        ],
        List::RuleInstances => vec![
            cell("uuid"),
            cell_text(instance_rule_id(row)),
            cell("state"),
        ],
        List::Scans => vec![
            cell("uuid"),
            cell("evalOutcome"),
            cell("scanOrigin"),
            cell("modelUri"),
            cell("createdAt"),
        ],
        List::Evaluations => vec![
            cell("uuid"),
            cell("ruleName"),
            cell("result"),
            cell("ruleInstanceState"),
        ],
        List::Violations => vec![cell("uuid"), cell("ruleName"), cell("file"), cell("threat")],
        List::Files => vec![cell("uuid"), cell("path"), cell("type"), cell("result")],
        List::Models => vec![
            cell("uuid"),
            cell("name"),
            cell("latestVersionOutcome"),
            match row.get("latestVersionFormats") {
                Some(OValue::Array(_)) => joined(row.get("latestVersionFormats")),
                _ => String::new(),
            },
            cell("latestVersionScanTime"),
        ],
        List::Versions => vec![
            cell("uuid"),
            cell("revision"),
            cell("fileCount"),
            cell("lastEvalOutcome"),
            cell("latestScanTime"),
        ],
    }
}

/// The `Key │ Value` table of a document: every projection key in order (an absent one
/// an empty cell, TS), the Rust additions only when present (D192).
fn detail_table(out: &mut Output, kind: Kind, doc: &OValue) {
    let rows: Vec<(String, String)> = keys(kind)
        .iter()
        .filter(|key| !RUST_ONLY.contains(key) || doc.get(key).is_some())
        .map(|key| ((*key).to_owned(), cell_text(doc.get(key))))
        .collect();
    let text = table::key_value_table(rows);
    if !text.is_empty() {
        out.data_line(&text);
    }
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

/// A list in `format`: json (a bare array, `[]` when empty), the table (nothing when
/// empty), or the banner and the pretty layout (`No <things> found` when empty).
pub fn render_list(
    out: &mut Output,
    list: List,
    format: Format,
    rows: &[OValue],
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(&OValue::Array(rows.to_vec())),
        Format::Table => {
            if !rows.is_empty() {
                let cells: Vec<Vec<String>> = rows.iter().map(|row| row_cells(list, row)).collect();
                out.data_line(&table::table(columns(list), &cells));
            }
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            if rows.is_empty() {
                pretty::empty_list(out, list.empty());
                return Ok(());
            }
            match list {
                List::Groups => groups_layout(out, rows),
                List::Rules => rules_layout(out, rows),
                List::RuleInstances => instances_layout(out, rows),
                List::Scans => scans_layout(out, rows),
                List::Evaluations => evaluations_layout(out, rows),
                List::Violations => violations_layout(out, rows),
                List::Files => files_layout(out, rows),
                List::Models => models_layout(out, rows),
                List::Versions => versions_layout(out, rows),
            }
            Ok(())
        }
    }
}

/// A document in `format`: json, the `Key │ Value` table, or the banner and the detail.
pub fn render_get(
    out: &mut Output,
    kind: Kind,
    format: Format,
    doc: &OValue,
) -> Result<(), CliError> {
    match format {
        Format::Json => out.json(doc),
        Format::Table => {
            detail_table(out, kind, doc);
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            match kind {
                Kind::Group => group_layout(out, doc),
                Kind::Rule => rule_layout(out, doc),
                Kind::RuleInstance => instance_layout(out, doc),
                Kind::Scan => scan_layout(out, doc),
                Kind::Evaluation => evaluation_layout(out, doc),
                Kind::Violation => violation_layout(out, doc),
                Kind::Model => model_layout(out, doc),
                Kind::ModelVersion => version_layout(out, doc),
                Kind::File => files_layout(out, std::slice::from_ref(doc)),
            }
            Ok(())
        }
    }
}

/// `labels keys` (`key: None`) or `labels values <key>`: json a bare array of strings
/// (choice 13), the one-column table, or the TS layout.
pub fn render_labels(
    out: &mut Output,
    key: Option<&str>,
    format: Format,
    items: &[String],
) -> Result<(), CliError> {
    match format {
        Format::Json => {
            let array: Vec<OValue> = items.iter().cloned().map(OValue::String).collect();
            out.json(&OValue::Array(array))
        }
        Format::Table => {
            if !items.is_empty() {
                let label = if key.is_some() { "Value" } else { "Key" };
                let cells: Vec<Vec<String>> = items
                    .iter()
                    .map(|item| vec![terminal_safe(item).into_owned()])
                    .collect();
                out.data_line(&table::table(&[label], &cells));
            }
            Ok(())
        }
        Format::Pretty => {
            banner(out);
            let key = key.map(|key| terminal_safe(key).into_owned());
            if items.is_empty() {
                match &key {
                    Some(key) => pretty::empty_list(out, &format!("values for key \"{key}\"")),
                    None => pretty::empty_list(out, "label keys"),
                }
                return Ok(());
            }
            match &key {
                Some(key) => pretty::section(out, &format!("Label Values for \"{key}\":")),
                None => pretty::section(out, "Label Keys:"),
            }
            for item in items {
                out.data_line(&format!("  {}", terminal_safe(item)));
            }
            out.data_line("");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing::{capture, capture_colored};

    fn doc(text: &str) -> OValue {
        crate::json::parse(text).unwrap()
    }

    const U1: &str = "11111111-1111-4111-8111-000000000001";

    fn group(uuid: &str, name: &str, source: &str, state: &str) -> OValue {
        doc(&format!(
            r#"{{"uuid":"{uuid}","tsg_id":"100","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","name":"{name}","description":"Auto group","source_type":"{source}","state":"{state}","is_tombstone":false}}"#
        ))
    }

    fn pretty_list(list: List, raw: &[OValue], quiet: bool) -> String {
        let (mut out, stdout, _) = capture(quiet);
        let rows = project_all(list.kind(), raw);
        render_list(&mut out, list, Format::Pretty, &rows).unwrap();
        out.commit().unwrap();
        stdout.text()
    }

    fn pretty_get(kind: Kind, raw: &OValue) -> String {
        let (mut out, stdout, _) = capture(false);
        render_get(&mut out, kind, Format::Pretty, &project(kind, raw)).unwrap();
        out.commit().unwrap();
        stdout.text()
    }

    const BANNER: &str = "\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n";

    /// MS§5.1, MS§5.2 captures; `--quiet` keeps the ids (D190).
    #[test]
    fn groups_are_the_typescript_bytes() {
        let raw = [
            group(U1, "Default LOCAL", "LOCAL", "ACTIVE"),
            group(
                "11111111-1111-4111-8111-000000000002",
                "Pending S3",
                "S3",
                "PENDING",
            ),
        ];
        assert_eq!(
            pretty_list(List::Groups, &raw, false),
            format!(
                "{BANNER}\n  Security Groups:\n\n  11111111-1111-4111-8111-000000000001\n    Default LOCAL  ACTIVE  source: LOCAL\n  11111111-1111-4111-8111-000000000002\n    Pending S3  PENDING  source: S3\n\n"
            )
        );
        assert_eq!(
            pretty_list(List::Groups, &raw, true),
            "  11111111-1111-4111-8111-000000000001\n    Default LOCAL  ACTIVE  source: LOCAL\n  11111111-1111-4111-8111-000000000002\n    Pending S3  PENDING  source: S3\n\n"
        );
        assert_eq!(
            pretty_get(Kind::Group, &raw[0]),
            format!(
                "{BANNER}\n  Security Group Detail:\n\n  UUID         {U1}\n  Name         Default LOCAL\n  Description  Auto group\n  Source Type  LOCAL\n  State        ACTIVE\n  Created      2026-01-01T00:00:00Z\n  Updated      2026-01-01T00:00:00Z\n\n"
            )
        );
        assert_eq!(
            pretty_list(List::Groups, &[], false),
            format!("{BANNER}  No security groups found\n")
        );
        // JSON: the projection (`tsg_id`, `is_tombstone` dropped).
        assert_eq!(
            crate::json::to_compact(&project(Kind::Group, &raw[0])).unwrap(),
            format!(
                r#"{{"uuid":"{U1}","name":"Default LOCAL","description":"Auto group","sourceType":"LOCAL","state":"ACTIVE","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}}"#
            )
        );
    }

    #[test]
    fn coloured_group_lines_use_the_typescript_spans() {
        let (mut out, stdout, _) = capture_colored(false);
        let rows = project_all(Kind::Group, &[group(U1, "G", "LOCAL", "ACTIVE")]);
        render_list(&mut out, List::Groups, Format::Pretty, &rows).unwrap();
        out.commit().unwrap();
        assert!(stdout.text().contains(&format!(
            "  \u{1b}[2m{U1}\u{1b}[22m\n    G  \u{1b}[32mACTIVE\u{1b}[39m  source: \u{1b}[2mLOCAL\u{1b}[22m\n"
        )));
    }

    /// D180: a summary without counts prints no `Rules` line and `null` counts; a scan
    /// without labels has none in json.
    #[test]
    fn scans_print_only_what_the_server_sent() {
        let full = doc(
            r#"{"uuid":"s1","eval_outcome":"BLOCKED","model_uri":"hf://org/model","scan_origin":"MODEL_SECURITY_SDK","source_type":"HUGGING_FACE","security_group_name":"Default LOCAL","eval_summary":{"rules_failed":1,"rules_passed":3,"total_rules":4},"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","labels":[{"key":"env","value":"prod"},{"key":"team","value":"ml"}]}"#,
        );
        let empty = doc(
            r#"{"uuid":"s2","eval_outcome":"PENDING","model_uri":"","scan_origin":"MODEL_SECURITY_API","source_type":"LOCAL","security_group_name":"g","eval_summary":{},"created_at":"c","updated_at":"u"}"#,
        );
        let partial = doc(
            r#"{"uuid":"s3","eval_outcome":"ALLOWED","model_uri":"","scan_origin":"o","source_type":"LOCAL","security_group_name":"g","eval_summary":{"rules_passed":2},"created_at":"c","updated_at":"u"}"#,
        );
        let text = pretty_list(List::Scans, &[full.clone(), empty.clone(), partial], false);
        assert_eq!(
            text,
            format!(
                "{BANNER}\n  Model Security Scans:\n\n  s1\n    BLOCKED  MODEL_SECURITY_SDK  2026-01-01T00:00:00Z\n    hf://org/model\n    Rules: 3 passed  1 failed  / 4 total\n  s2\n    PENDING  MODEL_SECURITY_API  c\n  s3\n    ALLOWED  o  c\n    Rules: 2 passed  ? failed  / ? total\n\n"
            )
        );
        assert_eq!(
            pretty_get(Kind::Scan, &full),
            format!(
                "{BANNER}\n  Scan Detail:\n\n  UUID       s1\n  Outcome    BLOCKED\n  Model URI  hf://org/model\n  Origin     MODEL_SECURITY_SDK\n  Source     HUGGING_FACE\n  Group      Default LOCAL\n  Created    2026-01-01T00:00:00Z\n  Updated    2026-01-01T00:00:00Z\n  Rules      3 passed  1 failed  / 4 total\n\n  Labels:\n\n  env   prod\n  team  ml\n\n"
            )
        );
        assert_eq!(
            crate::json::to_compact(&project(Kind::Scan, &empty)).unwrap(),
            r#"{"uuid":"s2","evalOutcome":"PENDING","modelUri":"","scanOrigin":"MODEL_SECURITY_API","sourceType":"LOCAL","securityGroupName":"g","evalSummary":{"rulesFailed":null,"rulesPassed":null,"totalRules":null},"createdAt":"c","updatedAt":"u"}"#
        );
        let none = doc(
            r#"{"uuid":"s4","eval_outcome":"PENDING","model_uri":"x","scan_origin":"o","source_type":"LOCAL","security_group_name":"g","created_at":"c","updated_at":"u","eval_summary":null}"#,
        );
        assert_eq!(
            project(Kind::Scan, &none).get("evalSummary"),
            Some(&OValue::Null)
        );
        let absent = doc(r#"{"uuid":"s5"}"#);
        assert_eq!(
            project(Kind::Scan, &absent).get("evalSummary"),
            Some(&OValue::Null)
        );
    }

    /// D191: userinfo, query and fragment withheld; plain URIs kept as they are.
    #[test]
    fn model_uris_are_withheld() {
        for (uri, shown) in [
            ("hf://org/model", "hf://org/model"),
            ("s3://bucket/path/model.pkl", "s3://bucket/path/model.pkl"),
            ("/local/path", "/local/path"),
            (
                "https://user:pass@example.test:8443/m?X-Amz-Signature=abc#frag",
                "https://[withheld]@example.test:8443/m?[withheld]#[withheld]",
            ),
            ("s3://key@bucket/m", "s3://[withheld]@bucket/m"),
            ("gs://bucket/m?sig=1", "gs://bucket/m?[withheld]"),
        ] {
            assert_eq!(withheld_uri(uri), shown, "{uri}");
        }
        let parts = uri_secrets(
            "https://us%40er-name:p%40ss@example.test/m?sig=S1&x=S2&long=LONGVALUE1#FRAGMENT-1",
        );
        for part in [
            "us%40er-name",
            "us@er-name",
            "p%40ss",
            "p@ss",
            "S1",
            "LONGVALUE1",
            "FRAGMENT-1",
        ] {
            assert!(parts.contains(&part.to_owned()), "{part}: {parts:?}");
        }
        // Short non-credential parts stay out (choice 44): `S2`, a short username, the
        // presigned-URL words `host`, `3600`, Azure's `b` and `r`.
        assert!(!parts.contains(&"S2".to_owned()), "{parts:?}");
        let presigned = uri_secrets(
            "https://bucket.s3.amazonaws.com/llm.bin?X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=ab12",
        );
        assert_eq!(presigned, ["ab12"]);
        let sas =
            uri_secrets("https://acct.blob.core.windows.net/c/m?sv=2022-11-02&ss=b&sp=r&sig=s%2Bg");
        assert_eq!(sas, ["2022-11-02", "s%2Bg", "s+g"]);
        assert_eq!(uri_secrets("https://git@h.example/m"), Vec::<String>::new());
        assert_eq!(
            uri_secrets("https://h.example/m?BAREWORDTOKEN"),
            ["BAREWORDTOKEN"]
        );
        assert!(uri_secrets("hf://org/model").is_empty());
        let secrets = SecretSet::default();
        register_uris(
            &[doc(r#"{"model_uri":"https://u:FAKE-MS-SECRET-01@h/m"}"#)],
            &secrets,
        );
        assert!(secrets.carried_by("x FAKE-MS-SECRET-01 y"));
    }

    /// D192: a custom-rule instance is named, and json keeps its custom rule.
    #[test]
    fn rule_instances_name_custom_rules() {
        let builtin = doc(
            r#"{"uuid":"i1","tsg_id":"100","security_group_uuid":"g","security_rule_uuid":"r1","state":"BLOCKING","created_at":"c","updated_at":"u","rule":{"uuid":"r1","name":"Load Time Code Execution Check","rule_type":"ARTIFACT"},"field_values":{}}"#,
        );
        let bare = doc(
            r#"{"uuid":"i2","tsg_id":"100","security_group_uuid":"g","security_rule_uuid":"r2","state":"DISABLED","created_at":"c","updated_at":"u","field_values":{"approved_formats":["onnx","safetensors"],"limits":{"a":1}}}"#,
        );
        let custom = doc(
            r#"{"uuid":"i3","tsg_id":"100","security_group_uuid":"g","state":"BLOCKING","custom_rule_uuid":"cr","custom_rule":{"uuid":"cr","name":"My rule","description":"d"}}"#,
        );
        assert_eq!(
            pretty_list(
                List::RuleInstances,
                &[builtin, bare.clone(), custom.clone()],
                false
            ),
            format!(
                "{BANNER}\n  Rule Instances:\n\n  i1\n    Load Time Code Execution Check  BLOCKING\n  i2\n    r2  DISABLED\n  i3\n    My rule  BLOCKING\n\n"
            )
        );
        assert_eq!(
            pretty_get(Kind::RuleInstance, &bare),
            format!(
                "{BANNER}\n  Rule Instance Detail:\n\n  UUID        i2\n  Group UUID  g\n  Rule UUID   r2\n  State       DISABLED\n  Created     c\n  Updated     u\n\n  Field Values:\n\n  approved_formats  onnx, safetensors\n  limits            {{\"a\":1}}\n\n"
            )
        );
        let json = crate::json::to_compact(&project(Kind::RuleInstance, &custom)).unwrap();
        assert_eq!(
            json,
            r#"{"uuid":"i3","securityGroupUuid":"g","customRuleUuid":"cr","state":"BLOCKING","customRule":{"uuid":"cr","name":"My rule","description":"d"}}"#
        );
        assert!(pretty_get(Kind::RuleInstance, &custom).contains(
            "  Rule UUID   cr\n  State       BLOCKING\n  Rule Name   My rule\n  Created     \n"
        ));
    }

    /// MS§6 captures.
    #[test]
    fn rules_are_the_typescript_bytes() {
        let rule = doc(
            r#"{"uuid":"r1","name":"Load Time Code Execution Check","description":"No unsafe operators at load time","rule_type":"ARTIFACT","compatible_sources":["ALL"],"default_state":"BLOCKING","remediation":{"description":"Remove unsafe operators","steps":["Review the violation","Use a safe format"],"url":"https://docs.example.invalid/r1"},"editable_fields":[],"constant_values":{},"default_values":{}}"#,
        );
        let fields = doc(
            r#"{"uuid":"r2","name":"Stored In Approved File Format","description":"Formats must be approved","rule_type":"METADATA","compatible_sources":["LOCAL","S3"],"default_state":"ALLOWING","remediation":{"description":"","steps":[],"url":""},"editable_fields":[{"attribute_name":"approved_formats","type":"LIST","display_name":"Approved Formats","display_type":"MULTI_SELECT","description":"Formats allowed"}],"constant_values":{},"default_values":{}}"#,
        );
        assert_eq!(
            pretty_list(List::Rules, &[rule.clone(), fields.clone()], false),
            format!(
                "{BANNER}\n  Security Rules:\n\n  r1\n    Load Time Code Execution Check  type: ARTIFACT  default: BLOCKING\n    No unsafe operators at load time\n    Sources: ALL\n  r2\n    Stored In Approved File Format  type: METADATA  default: ALLOWING\n    Formats must be approved\n    Sources: LOCAL, S3\n\n"
            )
        );
        assert_eq!(
            pretty_get(Kind::Rule, &rule),
            format!(
                "{BANNER}\n  Security Rule Detail:\n\n  UUID           r1\n  Name           Load Time Code Execution Check\n  Description    No unsafe operators at load time\n  Rule Type      ARTIFACT\n  Default State  BLOCKING\n  Sources        ALL\n\n  Remediation:\n\n  Remove unsafe operators\n  • Review the violation\n  • Use a safe format\n  https://docs.example.invalid/r1\n\n"
            )
        );
        assert!(pretty_get(Kind::Rule, &fields).ends_with("  Sources        LOCAL, S3\n\n  Editable Fields:\n\n  Approved Formats (approved_formats): MULTI_SELECT\n    Formats allowed\n\n"));
        // D190: --quiet keeps the remediation URL.
        let (mut out, stdout, _) = capture(true);
        render_get(
            &mut out,
            Kind::Rule,
            Format::Pretty,
            &project(Kind::Rule, &rule),
        )
        .unwrap();
        out.commit().unwrap();
        assert!(stdout.text().ends_with("  Sources        ALL\n  Remove unsafe operators\n  • Review the violation\n  • Use a safe format\n  https://docs.example.invalid/r1\n\n"));
    }

    /// MS§8.4–§8.6 and §9 captures.
    #[test]
    fn sub_reads_and_models_are_the_typescript_bytes() {
        let files = [
            doc(
                r#"{"uuid":"f1","path":"model.pkl","type":"FILE","formats":["pickle"],"result":"FAILED"}"#,
            ),
            doc(r#"{"uuid":"f2","path":"README.md","type":"FILE","result":"SKIPPED"}"#),
            doc(
                r#"{"uuid":"f3","path":"weights","type":"DIRECTORY","formats":null,"result":"SUCCESS"}"#,
            ),
        ];
        assert_eq!(
            pretty_list(List::Files, &files, false),
            format!(
                "{BANNER}\n  Scanned Files:\n\n    FAILED  FILE  model.pkl [pickle]\n    SKIPPED  FILE  README.md\n    SUCCESS  DIRECTORY  weights\n\n"
            )
        );
        assert_eq!(
            crate::json::to_compact(&project(Kind::File, &files[1])).unwrap(),
            r#"{"uuid":"f2","path":"README.md","type":"FILE","result":"SKIPPED"}"#
        );
        let models = [
            doc(
                r#"{"uuid":"m1","tsg_id":"100","name":"org/model","created_at":"c","updated_at":"u","latest_version_uuid":"v1","latest_version_revision":"main","latest_version_outcome":"BLOCKED","latest_version_formats":["pickle","onnx"],"latest_version_source_types":["HUGGING_FACE"],"latest_version_scan_time":"t"}"#,
            ),
            doc(
                r#"{"uuid":"m2","tsg_id":"100","name":"local/unscanned","created_at":"c","updated_at":"u"}"#,
            ),
        ];
        assert_eq!(
            pretty_list(List::Models, &models, false),
            format!(
                "{BANNER}\n  Models:\n\n  m1\n    org/model  BLOCKED [pickle, onnx]\n\n  m2\n    local/unscanned  unscanned\n\n"
            )
        );
        assert_eq!(
            pretty_get(Kind::Model, &models[0]),
            format!(
                "{BANNER}\n  Model Detail:\n\n  UUID             m1\n  Name             org/model\n  Created          c\n  Updated          u\n  Latest Version   v1\n  Latest Revision  main\n  Latest Outcome   BLOCKED\n  Formats          pickle, onnx\n  Source Types     HUGGING_FACE\n  Last Scan        t\n\n"
            )
        );
        let version = doc(
            r#"{"uuid":"v1","tsg_id":"100","model_uuid":"m1","revision":"main","created_at":"c","updated_at":"u","file_count":3,"license":"mit","model_formats":["pickle"],"source_types":["HUGGING_FACE"],"hf_model_name":"model","hf_organization":"org","last_eval_outcome":"BLOCKED","latest_scan_time":"t","last_eval_summary":{"rules_failed":1,"rules_passed":3,"total_rules":4}}"#,
        );
        assert_eq!(
            pretty_get(Kind::ModelVersion, &version),
            format!(
                "{BANNER}\n  Model Version Detail:\n\n  UUID             v1\n  Model            m1\n  Revision         main\n  Created          c\n  Updated          u\n  File Count       3\n  License          mit\n  Formats          pickle\n  Source Types     HUGGING_FACE\n  HF Model         model\n  HF Organization  org\n  Last Outcome     BLOCKED\n  Last Scan        t\n\n  Last Eval Summary:\n\n  Passed  3\n  Failed  1\n  Total   4\n\n"
            )
        );
        let unscanned = doc(
            r#"{"uuid":"v2","tsg_id":"100","model_uuid":"m1","revision":"v0","created_at":"c","updated_at":"u","last_eval_summary":{}}"#,
        );
        assert_eq!(
            pretty_list(List::Versions, &[version, unscanned.clone()], false),
            format!(
                "{BANNER}\n  Model Versions:\n\n  v1\n    main  BLOCKED  files: 3\n\n  v2\n    v0  unscanned\n\n"
            )
        );
        assert!(!pretty_get(Kind::ModelVersion, &unscanned).contains("Last Eval Summary"));
        assert_eq!(
            project(Kind::ModelVersion, &unscanned).get("lastEvalSummary"),
            Some(&doc(
                r#"{"rulesFailed":null,"rulesPassed":null,"totalRules":null}"#
            ))
        );
        let evaluations = [doc(
            r#"{"uuid":"e1","result":"FAILED","violation_count":2,"rule_instance_uuid":"i1","rule_name":"Load Time Code Execution Check","rule_description":"No unsafe operators","rule_instance_state":"BLOCKING"}"#,
        )];
        assert_eq!(
            pretty_list(List::Evaluations, &evaluations, false),
            format!(
                "{BANNER}\n  Rule Evaluations:\n\n  e1\n    Load Time Code Execution Check  FAILED  BLOCKING\n\n"
            )
        );
        assert_eq!(
            pretty_get(Kind::Evaluation, &evaluations[0]),
            format!(
                "{BANNER}\n  Evaluation Detail:\n\n  UUID            e1\n  Rule            Load Time Code Execution Check\n  Description     No unsafe operators\n  Instance UUID   i1\n  Instance State  BLOCKING\n  Result          FAILED\n  Violations      2\n\n"
            )
        );
        let violations = [doc(
            r#"{"uuid":"x1","description":"Found os.system","threat":"PAIT-PKL-100","file":"model.pkl","rule_name":"Load Time Code Execution Check","rule_description":"No unsafe operators","rule_instance_state":"BLOCKING"}"#,
        )];
        assert_eq!(
            pretty_list(List::Violations, &violations, false),
            format!(
                "{BANNER}\n  Violations:\n\n  x1\n    Load Time Code Execution Check  model.pkl\n    Found os.system\n    Threat: PAIT-PKL-100\n\n"
            )
        );
    }

    #[test]
    fn tables_use_the_typescript_columns_and_every_detail_key() {
        let (mut out, stdout, _) = capture(false);
        let rows = project_all(
            Kind::Group,
            &[group(U1, "Default LOCAL", "LOCAL", "ACTIVE")],
        );
        render_list(&mut out, List::Groups, Format::Table, &rows).unwrap();
        render_get(
            &mut out,
            Kind::Model,
            Format::Table,
            &project(
                Kind::Model,
                &doc(
                    r#"{"uuid":"m2","tsg_id":"100","name":"n","created_at":"c","updated_at":"u"}"#,
                ),
            ),
        )
        .unwrap();
        out.commit().unwrap();
        let text = stdout.text();
        assert!(text.starts_with(
            " ID                                   │ Name          │ State  │ Source Type \n"
        ));
        assert!(
            text.contains(" latestVersionScanTime    │       \n"),
            "{text}"
        );
        let (mut out, stdout, _) = capture(false);
        render_list(&mut out, List::Groups, Format::Table, &[]).unwrap();
        render_labels(&mut out, None, Format::Table, &[]).unwrap();
        out.commit().unwrap();
        assert_eq!(stdout.text(), "");
    }

    #[test]
    fn labels_render_in_every_format() {
        let items = vec!["env".to_owned(), "team".to_owned()];
        let (mut out, stdout, _) = capture(false);
        render_labels(&mut out, None, Format::Pretty, &items).unwrap();
        render_labels(&mut out, Some("a\u{1b}b"), Format::Pretty, &[]).unwrap();
        render_labels(&mut out, Some("env"), Format::Json, &items).unwrap();
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            format!(
                "{BANNER}\n  Label Keys:\n\n  env\n  team\n\n{BANNER}  No values for key \"a\u{fffd}b\" found\n[\n  \"env\",\n  \"team\"\n]\n"
            )
        );
    }

    /// §17.3 "Server text": names and descriptions carrying a secret are withheld at any
    /// depth; ids are not checked.
    #[test]
    fn withhold_checks_the_text_keys() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-SECRET-100");
        let mut d = doc(
            r#"{"uuid":"FAKE-SECRET-100","name":"x FAKE-SECRET-100","rule":{"name":"FAKE-SECRET-100"},"labels":[{"key":"k","value":"FAKE-SECRET-100"}]}"#,
        );
        withhold(&mut d, &secrets);
        assert_eq!(
            crate::json::to_compact(&d).unwrap(),
            r#"{"uuid":"FAKE-SECRET-100","name":"[withheld]","rule":{"name":"[withheld]"},"labels":[{"key":"k","value":"[withheld]"}]}"#
        );
        let mut items = vec!["FAKE-SECRET-100".to_owned(), "env".to_owned()];
        withhold_strings(&mut items, &secrets);
        assert_eq!(items, ["[withheld]", "env"]);
    }

    /// D52: control characters replaced, descriptions keep their line breaks.
    #[test]
    fn server_text_is_terminal_safe() {
        let raw = group(U1, "Evil\\u001b[31mRED", "LOCAL", "ACTIVE");
        let text = pretty_list(List::Groups, &[raw], false);
        assert!(text.contains("Evil\u{fffd}[31mRED"));
        assert!(!text.contains('\u{1b}'));
        let mut raw = group(U1, "g", "LOCAL", "ACTIVE");
        if let OValue::Object(entries) = &mut raw {
            for (key, value) in entries.iter_mut() {
                if key == "description" {
                    *value = OValue::String("line1\nline2\u{7}".to_owned());
                }
            }
        }
        assert!(pretty_get(Kind::Group, &raw).contains("  Description  line1\nline2\u{fffd}\n"));
    }
}
