//! The telemetry windows, chart filters, group-by dimensions and columns, and the logs
//! paging of `gateway telemetry` (DESIGN §19.8; D242, D232, D233, G41).
//!
//! Everything is checked during planning, before the tenant is read, and the window is
//! fixed there: `end` is `--end`, else the time of the check, and `start` is `--start`,
//! else `end − days × 24 h`. Timestamps take the zod `datetime({offset: true})` grammar
//! (§17.3), so no host time zone is ever consulted; the SDK sends the instants in UTC.

use super::{integer, positive};
use crate::error::CliError;
use scm::airs::gateway::models::AIGatewayChartFilters;
use scm::airs::gateway::{
    AIGatewayChartOptions, AIGatewayGroupColumn, AIGatewayGroupDimension, AIGatewayWindowOptions,
};
use scm::validation::NativeDate;
use serde_json::{Map, Number, Value};

/// The window error of the TypeScript SDK (`invalidWindow`).
pub const WINDOW_ERROR: &str =
    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid telemetry query options or time window";
/// TS: a chart flag that does not parse (`tf.ts:69-71`).
pub const FILTER_SYNTAX: &str = "Invalid chart filters: check JSON, CSV and numeric flag syntax";
/// TS: a chart flag the SDK filter schema refuses (`tf.ts:72-77`).
pub const FILTER_SEMANTICS: &str = "Invalid chart filters: check status codes, UUIDs, provider__model pairs, string metadata and inclusive nonnegative bounds";

/// `0000-01-01T00:00:00Z` and `9999-12-31T23:59:59.999Z` in epoch milliseconds.
const FIRST_MS: i64 = -62_167_219_200_000;
const LAST_MS: i64 = 253_402_300_799_999;
/// One day in milliseconds.
const DAY_MS: i128 = 86_400_000;

/// A fixed time window (epoch milliseconds, `start <= end`, both within 0000–9999).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub start_ms: i64,
    pub end_ms: i64,
}

impl Window {
    /// The SDK window for `slug` (offset 0: `+00:00`, G41).
    pub fn options(&self, slug: &str) -> Result<AIGatewayWindowOptions, CliError> {
        let failed = || CliError::usage(WINDOW_ERROR);
        let mut options = AIGatewayWindowOptions::new(slug);
        options.start = Some(NativeDate::from_epoch_millis(self.start_ms).map_err(|_| failed())?);
        options.end = Some(NativeDate::from_epoch_millis(self.end_ms).map_err(|_| failed())?);
        Ok(options)
    }
}

/// The current time in epoch milliseconds (the time of the check).
pub fn now_ms() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |ms| -ms),
    }
}

/// A `--start`/`--end` value: the zod offset grammar and a valid instant, else
/// `Invalid <flag>: Expected an ISO-8601 timestamp` (TS text).
fn timestamp(flag: &str, value: &str) -> Result<i64, CliError> {
    crate::modelsec::datetime_millis(value)
        .ok_or_else(|| CliError::usage(format!("Invalid {flag}: Expected an ISO-8601 timestamp")))
}

/// The window of a telemetry leaf (§19.8 "Window", in that order): `--days` (when given;
/// default 7), `--start`, `--end`, an explicit `--days` with `--start`, then the computed
/// range.
pub fn window(
    days: Option<&str>,
    start: Option<&str>,
    end: Option<&str>,
    now: i64,
) -> Result<Window, CliError> {
    let given_days = days.map(|value| positive("--days", value)).transpose()?;
    let start = start.map(|value| timestamp("--start", value)).transpose()?;
    let end = end.map(|value| timestamp("--end", value)).transpose()?;
    if given_days.is_some() && start.is_some() {
        return Err(CliError::usage("Use --days or --start/--end, not both"));
    }
    let end_ms = end.unwrap_or(now);
    let start_ms = match start {
        Some(start) => i128::from(start),
        None => i128::from(end_ms) - i128::from(given_days.unwrap_or(7)) * DAY_MS,
    };
    bounded(start_ms, i128::from(end_ms))
}

/// `cost`'s window: `--days` (default 7) back from the time of the check.
pub fn days_window(days: Option<&str>, now: i64) -> Result<(u64, Window), CliError> {
    let days = days.map_or(Ok(7), |value| positive("--days", value))?;
    let window = bounded(i128::from(now) - i128::from(days) * DAY_MS, i128::from(now))?;
    Ok((days, window))
}

fn bounded(start: i128, end: i128) -> Result<Window, CliError> {
    let range = i128::from(FIRST_MS)..=i128::from(LAST_MS);
    if start > end || !range.contains(&start) || !range.contains(&end) {
        return Err(CliError::usage(WINDOW_ERROR));
    }
    let to_ms = |value: i128| i64::try_from(value).map_err(|_| CliError::usage(WINDOW_ERROR));
    Ok(Window {
        start_ms: to_ms(start)?,
        end_ms: to_ms(end)?,
    })
}

/// The chart filter flags as typed (TS `ChartFilterFlags`).
#[derive(Clone, Debug, Default)]
pub struct FilterFlags<'a> {
    pub trace_id: Option<&'a str>,
    pub metadata: Option<&'a str>,
    pub status_codes: Option<&'a str>,
    pub api_key_ids: Option<&'a str>,
    pub ai_org_models: Option<&'a str>,
    pub total_units_min: Option<&'a str>,
    pub total_units_max: Option<&'a str>,
    pub cost_min: Option<&'a str>,
    pub cost_max: Option<&'a str>,
}

/// Validated chart filters: the SDK request model of `AIGatewayChartFiltersSchema`.
#[derive(Clone)]
pub struct Filters(AIGatewayChartFilters);

impl std::fmt::Debug for Filters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Filters([REDACTED])")
    }
}

impl PartialEq for Filters {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_value(&self.0).ok() == serde_json::to_value(&other.0).ok()
    }
}

impl Filters {
    /// The SDK chart options of `window` for `slug` with these filters.
    pub fn chart(&self, window: &Window, slug: &str) -> Result<AIGatewayChartOptions, CliError> {
        let mut options =
            AIGatewayChartOptions::new(window.options(slug)?).map_err(|_| semantics())?;
        options.filters = self.0.clone();
        Ok(options)
    }

    /// The filters as their wire JSON (tests).
    #[cfg(test)]
    pub fn wire(&self) -> Value {
        serde_json::to_value(&self.0).unwrap_or(Value::Null)
    }
}

fn syntax() -> CliError {
    CliError::usage(FILTER_SYNTAX)
}

fn semantics() -> CliError {
    CliError::usage(FILTER_SEMANTICS)
}

/// TS `csv` (`tf.ts:33-37`): split on `,`, each item trimmed, an empty item refused.
fn csv(value: &str) -> Option<Vec<String>> {
    let items: Vec<String> = value
        .split(',')
        .map(|item| crate::tenant::config::js_trim(item).to_owned())
        .collect();
    (!items.iter().any(String::is_empty)).then_some(items)
}

/// TS `decimal` (`tf.ts:39-45`): the JSON number grammar, then `Number(value)` (which can
/// be `Infinity`; the schema refuses it later).
fn decimal(value: &str) -> Option<f64> {
    let bytes = value.as_bytes();
    let mut at = 0;
    if bytes.first() == Some(&b'-') {
        at += 1;
    }
    let digits = |at: &mut usize| {
        let begin = *at;
        while bytes.get(*at).is_some_and(u8::is_ascii_digit) {
            *at += 1;
        }
        *at - begin
    };
    match bytes.get(at) {
        Some(b'0') => at += 1,
        Some(b'1'..=b'9') => {
            digits(&mut at);
        }
        _ => return None,
    }
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        if digits(&mut at) == 0 {
            return None;
        }
    }
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        at += 1;
        if matches!(bytes.get(at), Some(b'+' | b'-')) {
            at += 1;
        }
        if digits(&mut at) == 0 {
            return None;
        }
    }
    if at != bytes.len() {
        return None;
    }
    value.parse::<f64>().ok()
}

/// A JavaScript whitespace character (`\s` of a JS regular expression).
fn js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// `^[^,\s]+__[^,\s]+$` (the SDK's `provider__model` pair).
fn model_pair(value: &str) -> bool {
    if value.chars().any(|c| c == ',' || js_space(c)) {
        return false;
    }
    value
        .match_indices("__")
        .any(|(index, _)| index > 0 && index + 2 < value.len())
}

const UNSAFE_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// TS `chartFiltersFrom` (`tf.ts:48-78`): every flag parsed first (the syntax text), then
/// the SDK filter schema and its bounds (the semantic text). Values are never echoed.
pub fn filters(flags: &FilterFlags<'_>) -> Result<Filters, CliError> {
    let mut object = Map::new();
    let integer_value =
        |text: &str| -> Result<i64, CliError> { integer(text).map_err(|_| syntax()) };
    if let Some(trace) = flags.trace_id {
        object.insert("traceId".into(), Value::String(trace.to_owned()));
    }
    let metadata = flags
        .metadata
        .map(|text| serde_json::from_str::<Value>(text).map_err(|_| syntax()))
        .transpose()?;
    if let Some(metadata) = &metadata {
        object.insert("metadata".into(), metadata.clone());
    }
    if let Some(codes) = flags.status_codes {
        let items = csv(codes).ok_or_else(syntax)?;
        let numbers = items
            .iter()
            .map(|item| integer_value(item).map(|n| Value::Number(n.into())))
            .collect::<Result<Vec<_>, _>>()?;
        object.insert("statusCodes".into(), Value::Array(numbers));
    }
    if let Some(ids) = flags.api_key_ids {
        let items = csv(ids).ok_or_else(syntax)?;
        object.insert(
            "apiKeyIds".into(),
            Value::Array(items.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(models) = flags.ai_org_models {
        let items = csv(models).ok_or_else(syntax)?;
        object.insert(
            "aiOrgModels".into(),
            Value::Array(items.into_iter().map(Value::String).collect()),
        );
    }
    for (key, value) in [
        ("totalUnitsMin", flags.total_units_min),
        ("totalUnitsMax", flags.total_units_max),
    ] {
        if let Some(text) = value {
            object.insert(key.into(), Value::Number(integer_value(text)?.into()));
        }
    }
    let mut costs = Vec::new();
    for (key, value) in [("costMin", flags.cost_min), ("costMax", flags.cost_max)] {
        if let Some(text) = value {
            let number = decimal(text).ok_or_else(syntax)?;
            costs.push((key, number));
        }
    }
    // The schema checks (`chartFilterFields`, `validChartBounds`).
    if flags
        .trace_id
        .is_some_and(|trace| crate::tenant::config::js_trim(trace).is_empty())
    {
        return Err(semantics());
    }
    if let Some(metadata) = &metadata {
        let Value::Object(entries) = metadata else {
            return Err(semantics());
        };
        if entries
            .iter()
            .any(|(key, value)| UNSAFE_KEYS.contains(&key.as_str()) || !value.is_string())
        {
            return Err(semantics());
        }
    }
    let nonnegative = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_array)
            .is_none_or(|items| {
                items
                    .iter()
                    .all(|item| item.as_i64().is_some_and(|n| n >= 0))
            })
    };
    if !nonnegative("statusCodes") {
        return Err(semantics());
    }
    let strings = |key: &str| -> Vec<String> {
        object
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    if !strings("apiKeyIds")
        .iter()
        .all(|id| crate::pagination::is_uuid(id))
        || !strings("aiOrgModels").iter().all(|pair| model_pair(pair))
    {
        return Err(semantics());
    }
    let units = |key: &str| object.get(key).and_then(Value::as_i64);
    for key in ["totalUnitsMin", "totalUnitsMax"] {
        if units(key).is_some_and(|n| n < 0) {
            return Err(semantics());
        }
    }
    if let (Some(min), Some(max)) = (units("totalUnitsMin"), units("totalUnitsMax"))
        && min > max
    {
        return Err(semantics());
    }
    for (key, number) in &costs {
        if !number.is_finite() || *number < 0.0 {
            return Err(semantics());
        }
        let number = Number::from_f64(*number).ok_or_else(semantics)?;
        object.insert((*key).into(), Value::Number(number));
    }
    if let [(_, min), (_, max)] = costs.as_slice()
        && min > max
    {
        return Err(semantics());
    }
    AIGatewayChartFilters::parse(Value::Object(object), scm::validation::Mode::Request)
        .map(Filters)
        .map_err(|_| semantics())
}

/// A `group-by` dimension (§19.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dimension {
    Grouped(AIGatewayGroupDimension),
    StatusCode,
    Users,
}

/// The dimensions in TS order (`AI_GW_GROUP_DIMENSIONS`, then `status_code`, `users`).
pub const DIMENSIONS: [&str; 6] = [
    "ai_service",
    "model",
    "api_key",
    "provider",
    "status_code",
    "users",
];

/// The columns in TS order (`AI_GW_GROUP_COLUMNS`).
pub const COLUMNS: [&str; 6] = [
    "cost",
    "avg_latency",
    "avg_tokens",
    "total_tokens",
    "success_rate",
    "last_seen",
];

/// TS `isGroupDimension`, else `Invalid grouping dimension: choose from …`.
pub fn dimension(value: &str) -> Result<Dimension, CliError> {
    Ok(match value {
        "ai_service" => Dimension::Grouped(AIGatewayGroupDimension::AiService),
        "model" => Dimension::Grouped(AIGatewayGroupDimension::Model),
        "api_key" => Dimension::Grouped(AIGatewayGroupDimension::ApiKey),
        "provider" => Dimension::Grouped(AIGatewayGroupDimension::Provider),
        "status_code" => Dimension::StatusCode,
        "users" => Dimension::Users,
        _ => {
            return Err(CliError::usage(format!(
                "Invalid grouping dimension: choose from {}",
                DIMENSIONS.join(", ")
            )));
        }
    })
}

/// TS `groupOptionsFrom`'s `--columns` (`tel.ts:121-133`): refused for `users`; each item
/// (split on `,`, trimmed) a known column.
pub fn columns(
    dimension: Dimension,
    value: Option<&str>,
) -> Result<Option<Vec<AIGatewayGroupColumn>>, CliError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if dimension == Dimension::Users {
        return Err(CliError::usage("User grouping does not support --columns"));
    }
    value
        .split(',')
        .map(|item| match crate::tenant::config::js_trim(item) {
            "cost" => Ok(AIGatewayGroupColumn::Cost),
            "avg_latency" => Ok(AIGatewayGroupColumn::AvgLatency),
            "avg_tokens" => Ok(AIGatewayGroupColumn::AvgTokens),
            "total_tokens" => Ok(AIGatewayGroupColumn::TotalTokens),
            "success_rate" => Ok(AIGatewayGroupColumn::SuccessRate),
            "last_seen" => Ok(AIGatewayGroupColumn::LastSeen),
            _ => Err(CliError::usage(format!(
                "Invalid --columns: choose from {}",
                COLUMNS.join(", ")
            ))),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// `logs list` paging (§19.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogsPaging {
    pub page_size: u64,
    pub current_page: u64,
    pub status_code: Option<u64>,
    pub trace_id: Option<String>,
}

/// TS `logsList` (`tel.ts:226-240`): `--page-size` (default 50) positive,
/// `--current-page` (default 0) a nonnegative safe integer, `--status-code` positive when
/// given non-empty, `--trace-id` sent when non-empty (non-blank and bounded, the SDK rule).
pub fn logs_paging(
    page_size: Option<&str>,
    current_page: Option<&str>,
    status_code: Option<&str>,
    trace_id: Option<&str>,
) -> Result<LogsPaging, CliError> {
    let page_size = positive("--page-size", page_size.unwrap_or("50"))?;
    let current = current_page.unwrap_or("0");
    let current_page = (!current.is_empty() && current.bytes().all(|b| b.is_ascii_digit()))
        .then(|| current.trim_start_matches('0'))
        .and_then(|digits| match digits {
            "" => Some(0),
            digits if digits.len() > 16 => None,
            digits => digits.parse::<u64>().ok(),
        })
        .filter(|page| i64::try_from(*page).is_ok_and(|page| page <= super::MAX_SAFE_INTEGER))
        .ok_or_else(|| CliError::usage("--current-page must be a nonnegative safe integer"))?;
    let status_code = status_code
        .filter(|code| !code.is_empty())
        .map(|code| positive("--status-code", code))
        .transpose()?;
    let trace_id = match trace_id.filter(|trace| !trace.is_empty()) {
        Some(trace) => {
            super::check_resolved_ref("--trace-id", trace)?;
            Some(trace.to_owned())
        }
        None => None,
    };
    Ok(LogsPaging {
        page_size,
        current_page,
        status_code,
        trace_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_795_000_000_000;

    fn flags() -> FilterFlags<'static> {
        FilterFlags::default()
    }

    /// TS `aigateway-chart-filters.spec.ts`: every filter parsed without losing zero or
    /// fractional cents; absent flags omitted.
    #[test]
    fn filters_parse_like_typescript() {
        assert_eq!(filters(&flags()).unwrap().wire(), json!({}));
        let all = FilterFlags {
            trace_id: Some("owned"),
            metadata: Some(r#"{"environment":"dev"}"#),
            status_codes: Some("200, 446"),
            api_key_ids: Some("11111111-1111-4111-8111-111111111111"),
            ai_org_models: Some("openai__gpt-5.6-terra"),
            total_units_min: Some("0"),
            total_units_max: Some("42"),
            cost_min: Some("0"),
            cost_max: Some("1.25e-1"),
        };
        let wire = filters(&all).unwrap().wire();
        assert_eq!(
            crate::json::to_compact(&crate::json::to_ordered(&wire).unwrap()).unwrap(),
            r#"{"aiOrgModels":["openai__gpt-5.6-terra"],"apiKeyIds":["11111111-1111-4111-8111-111111111111"],"costMax":0.125,"costMin":0,"metadata":{"environment":"dev"},"statusCodes":[200,446],"totalUnitsMax":42,"totalUnitsMin":0,"traceId":"owned"}"#
        );
        let equal = FilterFlags {
            total_units_min: Some("0"),
            total_units_max: Some("0"),
            cost_min: Some("0"),
            cost_max: Some("0"),
            ..flags()
        };
        assert!(filters(&equal).is_ok(), "inclusive equal bounds");
        let codes = FilterFlags {
            status_codes: Some("0,99,600"),
            ..flags()
        };
        assert_eq!(
            filters(&codes).unwrap().wire()["statusCodes"],
            json!([0, 99, 600])
        );
    }

    /// The rejected cases of the TS spec, each with its text and without the value.
    #[test]
    fn invalid_filters_are_refused_without_their_values() {
        type Edit = fn(&mut FilterFlags<'static>);
        let cases: [(Edit, &str); 34] = [
            (|f| f.status_codes = Some(""), FILTER_SYNTAX),
            (|f| f.status_codes = Some("200,"), FILTER_SYNTAX),
            (|f| f.status_codes = Some("200,,446"), FILTER_SYNTAX),
            (|f| f.status_codes = Some("-1"), FILTER_SEMANTICS),
            (|f| f.status_codes = Some("9007199254740992"), FILTER_SYNTAX),
            (|f| f.status_codes = Some("200junk"), FILTER_SYNTAX),
            (|f| f.status_codes = Some("200.0"), FILTER_SYNTAX),
            (|f| f.status_codes = Some("0200"), FILTER_SYNTAX),
            (|f| f.api_key_ids = Some("not-a-uuid"), FILTER_SEMANTICS),
            (
                |f| f.api_key_ids = Some("11111111-1111-4111-8111-111111111111,"),
                FILTER_SYNTAX,
            ),
            (
                |f| f.ai_org_models = Some("@openai/gpt-5.6-terra"),
                FILTER_SEMANTICS,
            ),
            (|f| f.ai_org_models = Some("openai__"), FILTER_SEMANTICS),
            (
                |f| f.ai_org_models = Some("openai__gpt-5.6-terra,"),
                FILTER_SYNTAX,
            ),
            (|f| f.trace_id = Some(" "), FILTER_SEMANTICS),
            (|f| f.metadata = Some("{"), FILTER_SYNTAX),
            (|f| f.metadata = Some("null"), FILTER_SEMANTICS),
            (|f| f.metadata = Some("[]"), FILTER_SEMANTICS),
            (|f| f.metadata = Some(r#"{"value":123}"#), FILTER_SEMANTICS),
            (
                |f| f.metadata = Some(r#"{"__proto__":"danger"}"#),
                FILTER_SEMANTICS,
            ),
            (|f| f.total_units_min = Some("-1"), FILTER_SEMANTICS),
            (|f| f.total_units_min = Some("1.5"), FILTER_SYNTAX),
            (|f| f.total_units_min = Some("1e2"), FILTER_SYNTAX),
            (
                |f| f.total_units_max = Some("9007199254740992"),
                FILTER_SYNTAX,
            ),
            (
                |f| {
                    f.total_units_min = Some("2");
                    f.total_units_max = Some("1");
                },
                FILTER_SEMANTICS,
            ),
            (|f| f.cost_min = Some(""), FILTER_SYNTAX),
            (|f| f.cost_min = Some(" "), FILTER_SYNTAX),
            (|f| f.cost_min = Some("Infinity"), FILTER_SYNTAX),
            (|f| f.cost_min = Some("NaN"), FILTER_SYNTAX),
            (|f| f.cost_min = Some("0x10"), FILTER_SYNTAX),
            (|f| f.cost_min = Some("1junk"), FILTER_SYNTAX),
            (|f| f.cost_min = Some("-1"), FILTER_SEMANTICS),
            (|f| f.cost_min = Some("1e999"), FILTER_SEMANTICS),
            (|f| f.cost_min = Some("01"), FILTER_SYNTAX),
            (
                |f| {
                    f.cost_min = Some("1");
                    f.cost_max = Some("0");
                },
                FILTER_SEMANTICS,
            ),
        ];
        for (edit, text) in cases {
            let mut flags = flags();
            edit(&mut flags);
            assert_eq!(
                filters(&flags).unwrap_err(),
                CliError::usage(text),
                "{flags:?}"
            );
        }
        let secret = FilterFlags {
            metadata: Some(r#"{"value":{"secret":"do-not-echo"}}"#),
            ..flags()
        };
        assert!(
            !filters(&secret)
                .unwrap_err()
                .message()
                .contains("do-not-echo")
        );
    }

    #[test]
    fn decimals_and_pairs() {
        assert_eq!(decimal("2e1"), Some(20.0));
        assert_eq!(decimal("-0.5"), Some(-0.5));
        for bad in ["", ".5", "1.", "+1", "1e", "1e+", "00", "1 "] {
            assert_eq!(decimal(bad), None, "{bad}");
        }
        assert!(model_pair("a__b"));
        assert!(model_pair("a__b__c"));
        assert!(!model_pair("__b"));
        assert!(!model_pair("a b__c"));
    }

    /// D242: the zod grammar, UTC instants, the `--days` rules and the range.
    #[test]
    fn windows_are_fixed_at_check_time_and_never_read_the_host_zone() {
        assert_eq!(
            window(None, None, None, NOW).unwrap(),
            Window {
                start_ms: NOW - 7 * 86_400_000,
                end_ms: NOW
            }
        );
        assert_eq!(
            window(Some("1"), None, Some("2026-10-02T00:00:00+05:30"), NOW).unwrap(),
            Window {
                start_ms: 1_790_879_400_000 - 86_400_000,
                end_ms: 1_790_879_400_000
            }
        );
        assert_eq!(
            window(None, Some("2026-10-01T00:00:00Z"), None, NOW).unwrap(),
            Window {
                start_ms: 1_790_812_800_000,
                end_ms: NOW
            }
        );
        for (days, start, end, message) in [
            (
                Some("0"),
                None,
                None,
                "Invalid --days: Expected a positive integer",
            ),
            (
                Some("7junk"),
                None,
                None,
                "Invalid --days: Expected an integer",
            ),
            (
                Some("9007199254740992"),
                None,
                None,
                "Invalid --days: Expected a safe integer",
            ),
            (
                None,
                Some("2026-10-01"),
                None,
                "Invalid --start: Expected an ISO-8601 timestamp",
            ),
            (
                None,
                None,
                Some("Oct 2 2026"),
                "Invalid --end: Expected an ISO-8601 timestamp",
            ),
            (
                None,
                Some("2026-10-01T00:00:00"),
                None,
                "Invalid --start: Expected an ISO-8601 timestamp",
            ),
            (
                None,
                Some("2026-10-01T00:00:00+24:00"),
                None,
                "Invalid --start: Expected an ISO-8601 timestamp",
            ),
            (
                Some("7"),
                Some("2026-10-01T00:00:00Z"),
                None,
                "Use --days or --start/--end, not both",
            ),
            (
                None,
                Some("2026-10-02T00:00:00Z"),
                Some("2026-10-01T00:00:00Z"),
                WINDOW_ERROR,
            ),
            (Some("100000000"), None, None, WINDOW_ERROR),
        ] {
            assert_eq!(
                window(days, start, end, NOW).unwrap_err(),
                CliError::usage(message),
                "{days:?} {start:?} {end:?}"
            );
        }
        assert_eq!(
            days_window(Some("30"), NOW).unwrap(),
            (
                30,
                Window {
                    start_ms: NOW - 30 * 86_400_000,
                    end_ms: NOW
                }
            )
        );
    }

    #[test]
    fn dimensions_columns_and_paging() {
        assert_eq!(dimension("users").unwrap(), Dimension::Users);
        for bad in ["status", "user", "api-key", "provider/../../secret"] {
            assert_eq!(
                dimension(bad).unwrap_err(),
                CliError::usage(
                    "Invalid grouping dimension: choose from ai_service, model, api_key, provider, status_code, users"
                )
            );
        }
        assert_eq!(
            columns(Dimension::StatusCode, Some("cost, total_tokens")).unwrap(),
            Some(vec![
                AIGatewayGroupColumn::Cost,
                AIGatewayGroupColumn::TotalTokens
            ])
        );
        for bad in ["", "cost,", "invented"] {
            assert_eq!(
                columns(Dimension::StatusCode, Some(bad)).unwrap_err(),
                CliError::usage(
                    "Invalid --columns: choose from cost, avg_latency, avg_tokens, total_tokens, success_rate, last_seen"
                )
            );
        }
        assert_eq!(
            columns(Dimension::Users, Some("cost")).unwrap_err(),
            CliError::usage("User grouping does not support --columns")
        );
        assert_eq!(
            logs_paging(None, None, None, None).unwrap(),
            LogsPaging {
                page_size: 50,
                current_page: 0,
                status_code: None,
                trace_id: None
            }
        );
        assert_eq!(
            logs_paging(Some("5"), Some("007"), Some(""), Some("")).unwrap(),
            LogsPaging {
                page_size: 5,
                current_page: 7,
                status_code: None,
                trace_id: None
            }
        );
        for (args, message) in [
            (
                [Some("0"), None, None, None],
                "Invalid --page-size: Expected a positive integer",
            ),
            (
                [None, Some("-1"), None, None],
                "--current-page must be a nonnegative safe integer",
            ),
            (
                [None, Some("9007199254740992"), None, None],
                "--current-page must be a nonnegative safe integer",
            ),
            (
                [None, None, Some("0"), None],
                "Invalid --status-code: Expected a positive integer",
            ),
            ([None, None, None, Some(" ")], "--trace-id cannot be empty"),
            (
                [None, None, None, Some("a\u{1}")],
                "--trace-id must be at most 4096 bytes and contain no control characters",
            ),
        ] {
            assert_eq!(
                logs_paging(args[0], args[1], args[2], args[3]).unwrap_err(),
                CliError::usage(message),
                "{args:?}"
            );
        }
    }
}
