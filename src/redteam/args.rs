//! The argument rules of the red team writes (DESIGN §15.6, §15.13, §15.14): the scan
//! checks of D134, the adapter script and variables checks of D141 and D154, the
//! `targets init` providers and scaffold (`buildTargetScaffold`), and base64. Every
//! check here is pure; planning runs them before the tenant is read.

use crate::error::CliError;
use crate::json::OValue;
use crate::pagination;
use crate::redteam::{self as rt, LimitText};
use crate::tenant::config::js_trim;

/// The scan job types the help offers (`CLARA`, which the schema allows, is refused).
pub const JOB_TYPES: [&str; 3] = ["STATIC", "DYNAMIC", "CUSTOM"];
/// The longest `--wait-timeout` (7 days, in minutes).
pub const MAX_WAIT_MINUTES: u32 = 10_080;
/// The default `--wait-timeout` (24 hours, in minutes).
pub const DEFAULT_WAIT_MINUTES: u32 = 1_440;

const SCAN_SCHEMA: &str =
    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema";

/// Where the `--goals` come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Goals {
    None,
    /// An inline JSON array, checked.
    Inline(Vec<String>),
    /// A file path (the JavaScript-trimmed value, TS), read before the tenant.
    File(String),
}

/// The raw `redteam scan` options, as clap parsed them.
#[derive(Clone, Debug, Default)]
pub struct ScanOptions<'a> {
    pub target: &'a str,
    pub name: &'a str,
    pub job_type: Option<&'a str>,
    pub categories: Option<&'a str>,
    pub prompt_sets: Option<&'a str>,
    pub goals: Option<&'a str>,
    pub depth: Option<&'a str>,
    pub breadth: Option<&'a str>,
    pub no_wait: bool,
    pub wait_timeout: Option<&'a str>,
}

/// A validated `redteam scan`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanSpec {
    pub target: String,
    pub name: String,
    pub job_type: String,
    /// The `--categories` object (STATIC), `None` for the server default.
    pub categories: Option<serde_json::Value>,
    pub prompt_sets: Vec<String>,
    pub goals: Goals,
    pub depth: u32,
    pub breadth: u32,
    /// `None` with `--no-wait`; otherwise the bound in minutes.
    pub wait_minutes: Option<u32>,
}

/// One JSON value from text, the D44 classes (lone surrogates, out-of-range numbers)
/// counting as invalid.
fn json(text: &str) -> Option<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(text).ok()
}

/// The D134 checks in the §15.6 order.
pub fn scan(options: &ScanOptions<'_>) -> Result<ScanSpec, CliError> {
    let job_type = options.job_type.unwrap_or("STATIC");
    if !JOB_TYPES.contains(&job_type) {
        return Err(CliError::usage(format!(
            "{SCAN_SCHEMA}: job_type: invalid_enum_value"
        )));
    }
    // The frozen TS schema counts UTF-16 units and the vendor body code points; a
    // name must pass both (D305).
    let units = options.name.encode_utf16().count();
    if units < 3 || options.name.chars().count() < 3 {
        return Err(CliError::usage(format!("{SCAN_SCHEMA}: name: too_small")));
    }
    if units > 255 {
        return Err(CliError::usage(format!("{SCAN_SCHEMA}: name: too_big")));
    }
    if !pagination::is_uuid(options.target) {
        return Err(CliError::usage(format!(
            "{SCAN_SCHEMA}: target.uuid: invalid_string"
        )));
    }
    for (flag, given, wanted) in [
        ("--categories", options.categories.is_some(), "STATIC"),
        ("--goals", options.goals.is_some(), "DYNAMIC"),
        ("--depth", options.depth.is_some(), "DYNAMIC"),
        ("--breadth", options.breadth.is_some(), "DYNAMIC"),
        ("--prompt-sets", options.prompt_sets.is_some(), "CUSTOM"),
    ] {
        if given && job_type != wanted {
            return Err(CliError::usage(format!(
                "{flag} applies only to --type {wanted}"
            )));
        }
    }
    let categories = options.categories.map(categories).transpose()?;
    let goals = match options.goals {
        None | Some("") => Goals::None,
        Some(value) => {
            let trimmed = js_trim(value);
            if trimmed.starts_with('[') {
                Goals::Inline(goal_list(trimmed, "--goals").map_err(CliError::usage)?)
            } else {
                Goals::File(trimmed.to_owned())
            }
        }
    };
    // The vendor body allows 1 to 20 streams (D304).
    let streams = |flag: &str, value: &str| {
        rt::bounded_positive(flag, value, LimitText::Typescript, rt::MAX_STREAM)
    };
    let depth = options
        .depth
        .map(|value| streams("--depth", value))
        .transpose()?
        .unwrap_or(10);
    let breadth = options
        .breadth
        .map(|value| streams("--breadth", value))
        .transpose()?
        .unwrap_or(6);
    let prompt_sets = if job_type == "CUSTOM" {
        let Some(list) = options.prompt_sets else {
            return Err(CliError::usage(
                "--prompt-sets is required with --type CUSTOM",
            ));
        };
        let parts: Vec<String> = list
            .split(',')
            .map(|part| js_trim(part).to_owned())
            .collect();
        if parts.iter().any(|part| !pagination::is_uuid(part)) {
            return Err(CliError::usage(
                "--prompt-sets must be a comma-separated list of prompt set UUIDs",
            ));
        }
        parts
    } else {
        Vec::new()
    };
    let wait_minutes = match options.wait_timeout {
        Some(value) => {
            let minutes = value
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| value.parse::<u32>().ok())
                .flatten()
                .filter(|minutes| (1..=MAX_WAIT_MINUTES).contains(minutes))
                .ok_or_else(|| {
                    CliError::usage(format!(
                        "--wait-timeout must be an integer from 1 to {MAX_WAIT_MINUTES} minutes"
                    ))
                })?;
            if options.no_wait {
                return Err(CliError::usage(
                    "--wait-timeout cannot be combined with --no-wait",
                ));
            }
            Some(minutes)
        }
        None if options.no_wait => None,
        None => Some(DEFAULT_WAIT_MINUTES),
    };
    Ok(ScanSpec {
        target: options.target.to_owned(),
        name: options.name.to_owned(),
        job_type: job_type.to_owned(),
        categories,
        prompt_sets,
        goals,
        depth,
        breadth,
        wait_minutes,
    })
}

/// `--categories`: an object with at least one key whose every value is an array of
/// non-empty strings (`null` included in the refusal).
fn categories(text: &str) -> Result<serde_json::Value, CliError> {
    let value = json(text).ok_or_else(|| CliError::usage("--categories: invalid JSON"))?;
    let valid = value.as_object().is_some_and(|object| {
        !object.is_empty()
            && object.values().all(|ids| {
                ids.as_array().is_some_and(|ids| {
                    ids.iter()
                        .all(|id| id.as_str().is_some_and(|id| !id.is_empty()))
                })
            })
    });
    if valid {
        Ok(value)
    } else {
        Err(CliError::usage(
            "--categories: expected a JSON object of category IDs to arrays of sub-category IDs",
        ))
    }
}

/// The TS `parseAttackGoals` checks: JSON, then an array of non-empty strings.
/// `label` names the source (`--goals`).
pub fn goal_list(text: &str, label: &str) -> Result<Vec<String>, String> {
    let value = json(text).ok_or_else(|| format!("{label}: invalid JSON"))?;
    let goals: Option<Vec<String>> = value.as_array().and_then(|items| {
        items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|goal| !goal.is_empty())
                    .map(str::to_owned)
            })
            .collect()
    });
    goals.ok_or_else(|| format!("{label}: expected a JSON array of non-empty strings"))
}

/// The TS default STATIC categories: every category's sub-category ids except
/// `MULTI_TURN`, in server order, and the number of sub-categories kept.
pub fn default_categories(categories: &OValue) -> (serde_json::Value, usize) {
    let mut map = serde_json::Map::new();
    let mut count = 0;
    for category in categories.as_array().unwrap_or_default() {
        let Some(id) = category.get("id").and_then(OValue::as_str) else {
            continue;
        };
        let subs: Vec<serde_json::Value> = category
            .get("sub_categories")
            .and_then(OValue::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|sub| sub.get("id").and_then(OValue::as_str))
            .filter(|sub| *sub != "MULTI_TURN")
            .map(|sub| serde_json::Value::String(sub.to_owned()))
            .collect();
        count += subs.len();
        map.insert(id.to_owned(), serde_json::Value::Array(subs));
    }
    (serde_json::Value::Object(map), count)
}

/// The scan body (RS§9.2): `{name, target: {uuid}, job_type, job_metadata}`.
pub fn scan_body(
    spec: &ScanSpec,
    categories: Option<&serde_json::Value>,
    goals: &[String],
) -> serde_json::Value {
    let metadata = match spec.job_type.as_str() {
        "STATIC" => serde_json::json!({ "categories": categories.cloned().unwrap_or_default() }),
        "CUSTOM" => serde_json::json!({ "custom_prompt_sets": spec.prompt_sets }),
        _ => {
            let mut metadata = serde_json::json!({
                "stream_breadth": spec.breadth,
                "stream_depth": spec.depth,
            });
            if !goals.is_empty() {
                metadata["attack_goals"] = serde_json::json!(goals);
            }
            metadata
        }
    };
    serde_json::json!({
        "name": spec.name,
        "target": { "uuid": spec.target },
        "job_type": spec.job_type,
        "job_metadata": metadata,
    })
}

// ---------------------------------------------------------------------------
// Adapters (§15.14)
// ---------------------------------------------------------------------------

/// Where the adapter script comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Script {
    None,
    /// `--script-b64`, sent as given (TS).
    Base64(String),
    /// `--script-file`, read before the tenant and base64-encoded as read.
    File(std::ffi::OsString),
}

/// Where the adapter variables come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Variables {
    None,
    /// `--variables`, checked (no `SECRET` value, D154).
    Inline(serde_json::Value),
    /// `--variables-file`, read and checked before the tenant.
    File(std::ffi::OsString),
}

/// `--script-file` with `--script-b64` is refused; `required`: neither is refused too.
pub fn script(
    file: Option<&std::ffi::OsStr>,
    b64: Option<&str>,
    required: bool,
) -> Result<Script, CliError> {
    match (file, b64) {
        (Some(_), Some(_)) => Err(CliError::usage(
            "--script-file and --script-b64 are mutually exclusive",
        )),
        (None, Some(b64)) => Ok(Script::Base64(b64.to_owned())),
        (Some(file), None) => Ok(Script::File(file.to_owned())),
        (None, None) if required => Err(CliError::usage(
            "one of --script-file or --script-b64 is required",
        )),
        (None, None) => Ok(Script::None),
    }
}

const VARIABLES_SHAPE: &str =
    r#"expected a JSON array of { "key": string, "value"?: string|null, "type": "VAR"|"SECRET" }"#;

/// The TS `parseAdapterVariables` checks of `text` (`label`: `--variables` or
/// `--variables-file`).
pub fn variable_list(text: &str, label: &str) -> Result<serde_json::Value, String> {
    let value = json(text).ok_or_else(|| format!("{label}: invalid JSON"))?;
    let valid = value.as_array().is_some_and(|items| {
        items.iter().all(|item| {
            item.as_object().is_some_and(|entry| {
                entry.get("key").is_some_and(serde_json::Value::is_string)
                    && matches!(
                        entry.get("type").and_then(serde_json::Value::as_str),
                        Some("VAR" | "SECRET")
                    )
            })
        })
    });
    if valid {
        Ok(value)
    } else {
        Err(format!("{label}: {VARIABLES_SHAPE}"))
    }
}

/// D154: a `SECRET` entry with a value on the command line.
pub const SECRET_ON_ARGV: &str = "Do not pass SECRET values as arguments; put the variables in a file and use --variables-file <path>";

/// `--variables` / `--variables-file` (refused together); an argv `SECRET` value is
/// refused (D154).
pub fn variables(
    inline: Option<&str>,
    file: Option<&std::ffi::OsStr>,
) -> Result<Variables, CliError> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(CliError::usage(
            "--variables and --variables-file cannot be combined",
        )),
        (Some(text), None) => {
            let value = variable_list(text, "--variables").map_err(CliError::usage)?;
            let secret_on_argv = value.as_array().is_some_and(|items| {
                items.iter().any(|item| {
                    item.get("type").and_then(serde_json::Value::as_str) == Some("SECRET")
                        && item.get("value").is_some_and(|value| !value.is_null())
                })
            });
            if secret_on_argv {
                return Err(CliError::usage(SECRET_ON_ARGV));
            }
            Ok(Variables::Inline(value))
        }
        (None, Some(file)) => Ok(Variables::File(file.to_owned())),
        (None, None) => Ok(Variables::None),
    }
}

/// TS `preserveVariablesForUpdate`: `{key, value: isRedacted ? null : value ?? null,
/// type}` for each stored variable (an absent value is `null`: keep the stored one).
pub fn preserve_variables(current: &OValue) -> serde_json::Value {
    let items = current
        .get("variables")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|variable| {
            let redacted = matches!(variable.get("is_redacted"), Some(OValue::Bool(true)));
            let value = match variable.get("value") {
                Some(OValue::String(text)) if !redacted => serde_json::Value::String(text.clone()),
                _ => serde_json::Value::Null,
            };
            serde_json::json!({
                "key": variable.get("key").and_then(OValue::as_str).unwrap_or_default(),
                "value": value,
                "type": variable.get("type").and_then(OValue::as_str).unwrap_or_default(),
            })
        })
        .collect();
    serde_json::Value::Array(items)
}

/// Standard base64 with padding (RFC 4648 §4).
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextet = |shift: u32| char::from(ALPHABET[((n >> shift) & 63) as usize]);
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

// ---------------------------------------------------------------------------
// `targets init` (§15.13)
// ---------------------------------------------------------------------------

/// The providers of `targets init` (TS `VALID_TARGET_PROVIDERS`).
pub const PROVIDERS: [&str; 8] = [
    "OPENAI",
    "HUGGING_FACE",
    "DATABRICKS",
    "BEDROCK",
    "REST",
    "STREAMING",
    "WEBSOCKET",
    "CUSTOM_TARGET_ADAPTER",
];

/// The provider upper-cased, or the TS usage error.
pub fn provider(value: &str) -> Result<String, CliError> {
    let key = value.to_ascii_uppercase();
    if PROVIDERS.contains(&key.as_str()) {
        Ok(key)
    } else {
        Err(CliError::usage(format!(
            "Unknown provider \"{value}\". Valid providers: {}",
            PROVIDERS.join(", ")
        )))
    }
}

fn object(entries: Vec<(&str, OValue)>) -> OValue {
    OValue::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn text(value: &str) -> OValue {
    OValue::String(value.to_owned())
}

fn parsed(json: &str) -> OValue {
    crate::json::parse(json).unwrap_or(OValue::Null)
}

/// TS `buildTargetScaffold` for the upper-cased `key`, keys in the TS insertion order.
pub fn scaffold(key: &str, templates: &OValue) -> OValue {
    let template = templates.get(key).cloned();
    if key == "CUSTOM_TARGET_ADAPTER" {
        return object(vec![
            ("name", text("")),
            ("target_type", text("AGENT")),
            ("connection_type", text("CUSTOM_TARGET_ADAPTER")),
            ("api_endpoint_type", text("NETWORK_BROKER")),
            ("network_broker_channel_uuid", text("<channel-uuid>")),
            ("adapter_uuid", text("<adapter-uuid>")),
            ("adapter_variable_overrides", OValue::Array(Vec::new())),
            ("target_background", object(vec![("use_case", text(""))])),
            ("additional_context", OValue::Object(Vec::new())),
        ]);
    }
    let auth = object(vec![(
        "auth_header",
        object(vec![("Authorization", text("Bearer <token>"))]),
    )]);
    if matches!(key, "REST" | "STREAMING" | "WEBSOCKET" | "HUGGING_FACE") {
        let template = template.unwrap_or(OValue::Object(Vec::new()));
        // `tpl.url as string | undefined ?? ''`: any non-nullish url is kept as is.
        let endpoint = match template.get("url") {
            None | Some(OValue::Null) => text(""),
            Some(value) => value.clone(),
        };
        let or_default = |key: &str, default: &str| match template.get(key) {
            None | Some(OValue::Null) => parsed(default),
            Some(value) => value.clone(),
        };
        let mode = match key {
            "STREAMING" => "STREAMING",
            "WEBSOCKET" => "WEBSOCKET",
            _ => "REST",
        };
        return object(vec![
            ("name", text("")),
            ("target_type", text("APPLICATION")),
            ("connection_type", text("CUSTOM")),
            ("api_endpoint_type", text("PUBLIC")),
            ("response_mode", text(mode)),
            ("auth_type", text("HEADERS")),
            ("auth_config", auth),
            (
                "connection_params",
                object(vec![
                    ("api_endpoint", endpoint),
                    (
                        "request_headers",
                        object(vec![("Content-Type", text("application/json"))]),
                    ),
                    (
                        "request_json",
                        or_default(
                            "request_json",
                            r#"{"messages":[{"role":"user","content":"{INPUT}"}]}"#,
                        ),
                    ),
                    (
                        "response_json",
                        or_default(
                            "response_json",
                            r#"{"choices":[{"message":{"content":"{RESPONSE}"}}]}"#,
                        ),
                    ),
                    ("response_key", text("choices.0.message.content")),
                ]),
            ),
            ("target_background", OValue::Object(Vec::new())),
            ("additional_context", OValue::Object(Vec::new())),
        ]);
    }
    let config = match template {
        None | Some(OValue::Null) => OValue::Object(Vec::new()),
        Some(value) => value,
    };
    object(vec![
        ("name", text("")),
        ("target_type", text("APPLICATION")),
        ("connection_type", text(key)),
        ("api_endpoint_type", text("PUBLIC")),
        ("response_mode", text("REST")),
        ("auth_type", text("HEADERS")),
        ("auth_config", auth),
        (
            "connection_params",
            object(vec![("target_connection_config", config)]),
        ),
        ("target_background", OValue::Object(Vec::new())),
        ("additional_context", OValue::Object(Vec::new())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "00000000-0000-4000-8000-000000000201";
    const SET: &str = "00000000-0000-4000-8000-000000000301";

    fn options() -> ScanOptions<'static> {
        ScanOptions {
            target: TARGET,
            name: "nightly",
            ..ScanOptions::default()
        }
    }

    fn usage(result: Result<impl std::fmt::Debug, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    #[test]
    fn scan_bounds_accept_the_api_maximum() {
        let spec = scan(&ScanOptions {
            job_type: Some("DYNAMIC"),
            depth: Some("20"),
            breadth: Some("20"),
            ..options()
        })
        .unwrap();
        assert_eq!((spec.depth, spec.breadth), (20, 20));
        // Three code points in six UTF-16 units; 255 units at the top (D305).
        for name in ["\u{1F600}\u{1F600}\u{1F600}", "abc", &"x".repeat(255)] {
            assert_eq!(scan(&ScanOptions { name, ..options() }).unwrap().name, name);
        }
    }

    #[test]
    fn scan_checks_follow_the_section_order() {
        let spec = scan(&options()).unwrap();
        assert_eq!(spec.job_type, "STATIC");
        assert_eq!((spec.depth, spec.breadth), (10, 6));
        assert_eq!(spec.wait_minutes, Some(DEFAULT_WAIT_MINUTES));
        for (edit, message) in [
            (
                ScanOptions {
                    job_type: Some("CLARA"),
                    name: "x",
                    ..options()
                },
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema: job_type: invalid_enum_value",
            ),
            (
                ScanOptions {
                    name: "ab",
                    target: "nope",
                    ..options()
                },
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema: name: too_small",
            ),
            (
                // Three UTF-16 units but two code points (D305).
                ScanOptions {
                    name: "\u{1F600}a",
                    target: "nope",
                    ..options()
                },
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema: name: too_small",
            ),
            (
                ScanOptions {
                    target: "nope",
                    ..options()
                },
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema: target.uuid: invalid_string",
            ),
            (
                ScanOptions {
                    job_type: Some("DYNAMIC"),
                    categories: Some("{}"),
                    ..options()
                },
                "--categories applies only to --type STATIC",
            ),
            (
                ScanOptions {
                    goals: Some("[]"),
                    ..options()
                },
                "--goals applies only to --type DYNAMIC",
            ),
            (
                ScanOptions {
                    depth: Some("3"),
                    ..options()
                },
                "--depth applies only to --type DYNAMIC",
            ),
            (
                ScanOptions {
                    prompt_sets: Some(SET),
                    ..options()
                },
                "--prompt-sets applies only to --type CUSTOM",
            ),
            (
                ScanOptions {
                    categories: Some("{nope"),
                    ..options()
                },
                "--categories: invalid JSON",
            ),
            (
                ScanOptions {
                    categories: Some("[1,2]"),
                    ..options()
                },
                "--categories: expected a JSON object of category IDs to arrays of sub-category IDs",
            ),
            (
                ScanOptions {
                    categories: Some("null"),
                    ..options()
                },
                "--categories: expected a JSON object of category IDs to arrays of sub-category IDs",
            ),
            (
                ScanOptions {
                    categories: Some(r#"{"A":[""]}"#),
                    ..options()
                },
                "--categories: expected a JSON object of category IDs to arrays of sub-category IDs",
            ),
            (
                ScanOptions {
                    job_type: Some("DYNAMIC"),
                    goals: Some("  [nope"),
                    ..options()
                },
                "--goals: invalid JSON",
            ),
            (
                ScanOptions {
                    job_type: Some("DYNAMIC"),
                    goals: Some(r#"["a", ""]"#),
                    ..options()
                },
                "--goals: expected a JSON array of non-empty strings",
            ),
            (
                ScanOptions {
                    job_type: Some("DYNAMIC"),
                    depth: Some("2.5x"),
                    ..options()
                },
                "--depth: expected a positive integer, got \"2.5x\"",
            ),
            (
                ScanOptions {
                    job_type: Some("DYNAMIC"),
                    breadth: Some("0"),
                    ..options()
                },
                "--breadth: expected a positive integer, got \"0\"",
            ),
            (
                ScanOptions {
                    job_type: Some("DYNAMIC"),
                    depth: Some("21"),
                    breadth: Some("0"),
                    ..options()
                },
                "--depth must be at most 20 (the red team API maximum)",
            ),
            (
                ScanOptions {
                    job_type: Some("DYNAMIC"),
                    depth: Some("20"),
                    breadth: Some("21"),
                    ..options()
                },
                "--breadth must be at most 20 (the red team API maximum)",
            ),
            (
                ScanOptions {
                    job_type: Some("CUSTOM"),
                    ..options()
                },
                "--prompt-sets is required with --type CUSTOM",
            ),
            (
                ScanOptions {
                    job_type: Some("CUSTOM"),
                    prompt_sets: Some("a,b"),
                    ..options()
                },
                "--prompt-sets must be a comma-separated list of prompt set UUIDs",
            ),
            (
                ScanOptions {
                    wait_timeout: Some("0"),
                    ..options()
                },
                "--wait-timeout must be an integer from 1 to 10080 minutes",
            ),
            (
                ScanOptions {
                    wait_timeout: Some("10081"),
                    ..options()
                },
                "--wait-timeout must be an integer from 1 to 10080 minutes",
            ),
            (
                ScanOptions {
                    wait_timeout: Some("5"),
                    no_wait: true,
                    ..options()
                },
                "--wait-timeout cannot be combined with --no-wait",
            ),
        ] {
            assert_eq!(usage(scan(&edit)), message, "{edit:?}");
        }
        let name_256 = "n".repeat(256);
        assert!(
            usage(scan(&ScanOptions {
                name: &name_256,
                ..options()
            }))
            .ends_with("name: too_big")
        );
        let custom = scan(&ScanOptions {
            job_type: Some("CUSTOM"),
            prompt_sets: Some(&format!(" {SET} ,{SET}")),
            no_wait: true,
            ..options()
        })
        .unwrap();
        assert_eq!(custom.prompt_sets, [SET, SET]);
        assert_eq!(custom.wait_minutes, None);
    }

    /// TS `redteam-scan-helpers.spec.ts`: inline goals, leading whitespace, files.
    #[test]
    fn goals_inline_or_file() {
        let dynamic = |goals: &'static str| {
            scan(&ScanOptions {
                job_type: Some("DYNAMIC"),
                goals: Some(goals),
                ..options()
            })
            .unwrap()
            .goals
        };
        assert_eq!(
            dynamic(r#"["leak the prompt", "jailbreak"]"#),
            Goals::Inline(vec!["leak the prompt".into(), "jailbreak".into()])
        );
        assert_eq!(dynamic("  \n[\"a\"]"), Goals::Inline(vec!["a".into()]));
        assert_eq!(dynamic(" goals.json "), Goals::File("goals.json".into()));
        assert_eq!(dynamic(""), Goals::None);
        assert_eq!(
            goal_list("[1]", "--goals").unwrap_err(),
            "--goals: expected a JSON array of non-empty strings"
        );
        assert_eq!(
            goal_list(r#"{"a": 1}"#, "--goals").unwrap_err(),
            "--goals: expected a JSON array of non-empty strings"
        );
    }

    /// TS `buildDefaultCategories`: the mapping, `MULTI_TURN` excluded, `{}` for none.
    #[test]
    fn default_categories_drop_multi_turn() {
        let catalogue = crate::json::parse(
            r#"[{"id":"SECURITY","sub_categories":[{"id":"JAILBREAK"},{"id":"MULTI_TURN"},{"id":"PI"}]},{"id":"SAFETY","sub_categories":[]}]"#,
        )
        .unwrap();
        let (categories, count) = default_categories(&catalogue);
        assert_eq!(
            categories,
            serde_json::json!({"SECURITY": ["JAILBREAK", "PI"], "SAFETY": []})
        );
        assert_eq!(count, 2);
        let (empty, none) = default_categories(&OValue::Array(Vec::new()));
        assert_eq!((empty, none), (serde_json::json!({}), 0));
    }

    #[test]
    fn scan_bodies_per_type() {
        let spec = scan(&ScanOptions {
            job_type: Some("DYNAMIC"),
            depth: Some("3"),
            ..options()
        })
        .unwrap();
        assert_eq!(
            scan_body(&spec, None, &[]),
            serde_json::json!({
                "name": "nightly", "target": {"uuid": TARGET}, "job_type": "DYNAMIC",
                "job_metadata": {"stream_breadth": 6, "stream_depth": 3}
            })
        );
        assert_eq!(
            scan_body(&spec, None, &["g".into()])["job_metadata"]["attack_goals"],
            serde_json::json!(["g"])
        );
        let spec = scan(&options()).unwrap();
        let categories = serde_json::json!({"A": ["B"]});
        assert_eq!(
            scan_body(&spec, Some(&categories), &[])["job_metadata"],
            serde_json::json!({"categories": {"A": ["B"]}})
        );
    }

    /// TS `redteam-adapter-helpers.spec.ts`: script passthrough, both or neither, the
    /// variables shapes; D154 refuses argv `SECRET` values.
    #[test]
    fn adapter_scripts_and_variables() {
        assert_eq!(
            script(None, Some("cHJpbnQ="), true).unwrap(),
            Script::Base64("cHJpbnQ=".into())
        );
        assert_eq!(
            usage(script(Some("a.py".as_ref()), Some("x"), false)),
            "--script-file and --script-b64 are mutually exclusive"
        );
        assert_eq!(
            usage(script(None, None, true)),
            "one of --script-file or --script-b64 is required"
        );
        assert_eq!(script(None, None, false).unwrap(), Script::None);
        assert!(matches!(
            variables(
                Some(
                    r#"[{"key":"k","value":null,"type":"SECRET"},{"key":"e","value":"v","type":"VAR"}]"#
                ),
                None
            ),
            Ok(Variables::Inline(_))
        ));
        for (text, message) in [
            ("[nope", "--variables: invalid JSON"),
            (
                r#"{"key":"k"}"#,
                r#"--variables: expected a JSON array of { "key": string, "value"?: string|null, "type": "VAR"|"SECRET" }"#,
            ),
            (
                r#"[{"key":"k","type":"OTHER"}]"#,
                r#"--variables: expected a JSON array of { "key": string, "value"?: string|null, "type": "VAR"|"SECRET" }"#,
            ),
            (
                r#"[null]"#,
                r#"--variables: expected a JSON array of { "key": string, "value"?: string|null, "type": "VAR"|"SECRET" }"#,
            ),
            (
                r#"[{"key":"api_token","value":"FAKE-SECRET","type":"SECRET"}]"#,
                SECRET_ON_ARGV,
            ),
        ] {
            assert_eq!(usage(variables(Some(text), None)), message, "{text}");
        }
        assert_eq!(
            usage(variables(Some("[]"), Some("v.json".as_ref()))),
            "--variables and --variables-file cannot be combined"
        );
        let stored = crate::json::parse(
            r#"{"variables":[{"key":"e","value":"http://x","type":"VAR"},{"key":"t","value":"****","type":"SECRET","is_redacted":true},{"key":"n","type":"VAR"}]}"#,
        )
        .unwrap();
        assert_eq!(
            preserve_variables(&stored),
            serde_json::json!([
                {"key": "e", "value": "http://x", "type": "VAR"},
                {"key": "t", "value": null, "type": "SECRET"},
                {"key": "n", "value": null, "type": "VAR"}
            ])
        );
    }

    #[test]
    fn base64_matches_rfc_4648() {
        for (bytes, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"print('hi')\n", "cHJpbnQoJ2hpJykK"),
            (b"\xff\xfe\x00", "//4A"),
        ] {
            assert_eq!(base64(bytes), encoded);
        }
    }

    /// TS `redteam-init.spec.ts`: the scaffold per provider family, case-insensitive
    /// providers and the unknown-provider text.
    #[test]
    fn scaffolds_per_provider_family() {
        let templates = crate::json::parse(
            r#"{"OPENAI":{"model_name":"gpt-4o"},"REST":{"url":"https://api.example.com","request_json":{"input":"{INPUT}"}}}"#,
        )
        .unwrap();
        assert_eq!(provider("rest").unwrap(), "REST");
        assert_eq!(
            usage(provider("nope")),
            "Unknown provider \"nope\". Valid providers: OPENAI, HUGGING_FACE, DATABRICKS, BEDROCK, REST, STREAMING, WEBSOCKET, CUSTOM_TARGET_ADAPTER"
        );
        let compact = |value: &OValue| crate::json::to_compact(value).unwrap();
        assert_eq!(
            compact(&scaffold("REST", &templates)),
            r#"{"name":"","target_type":"APPLICATION","connection_type":"CUSTOM","api_endpoint_type":"PUBLIC","response_mode":"REST","auth_type":"HEADERS","auth_config":{"auth_header":{"Authorization":"Bearer <token>"}},"connection_params":{"api_endpoint":"https://api.example.com","request_headers":{"Content-Type":"application/json"},"request_json":{"input":"{INPUT}"},"response_json":{"choices":[{"message":{"content":"{RESPONSE}"}}]},"response_key":"choices.0.message.content"},"target_background":{},"additional_context":{}}"#
        );
        let streaming = scaffold("STREAMING", &templates);
        assert_eq!(
            streaming.get("response_mode").and_then(OValue::as_str),
            Some("STREAMING")
        );
        assert_eq!(
            compact(
                streaming
                    .get("connection_params")
                    .unwrap()
                    .get("api_endpoint")
                    .unwrap()
            ),
            r#""""#
        );
        assert_eq!(
            compact(&scaffold("OPENAI", &templates)),
            r#"{"name":"","target_type":"APPLICATION","connection_type":"OPENAI","api_endpoint_type":"PUBLIC","response_mode":"REST","auth_type":"HEADERS","auth_config":{"auth_header":{"Authorization":"Bearer <token>"}},"connection_params":{"target_connection_config":{"model_name":"gpt-4o"}},"target_background":{},"additional_context":{}}"#
        );
        assert_eq!(
            compact(
                scaffold("BEDROCK", &templates)
                    .get("connection_params")
                    .unwrap()
            ),
            r#"{"target_connection_config":{}}"#
        );
        assert_eq!(
            compact(&scaffold("CUSTOM_TARGET_ADAPTER", &templates)),
            r#"{"name":"","target_type":"AGENT","connection_type":"CUSTOM_TARGET_ADAPTER","api_endpoint_type":"NETWORK_BROKER","network_broker_channel_uuid":"<channel-uuid>","adapter_uuid":"<adapter-uuid>","adapter_variable_overrides":[],"target_background":{"use_case":""},"additional_context":{}}"#
        );
    }
}
