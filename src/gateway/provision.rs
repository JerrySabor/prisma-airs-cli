//! The workspace and scope writes' pure parts (DESIGN §19.6, §19.7; D229, D236, D246):
//! the TS `buildWorkspaceWriteRequest` with the Rust checks, `scopeNameLooksUnrelated`,
//! the provisioning texts and the scope-delete prompt.

use crate::error::CliError;
use crate::json::OValue;
use crate::store::PROGRAM;
use scm::airs::gateway::models::{
    GatewayRateLimitInput, GatewayUsageLimitInput, GatewayWorkspaceCreateRequest,
    GatewayWorkspaceUpdateRequest,
};
use scm::validation::Mode;
use serde_json::{Map, Value};

/// `workspaces update` without a field (TS text).
pub const UPDATE_NEEDS_A_FIELD: &str = "Specify at least one of --name --description --icon --metadata --defaults --usage-limits --rate-limits";

/// The JSON flags of `workspaces create|update` (raw text as typed).
#[derive(Clone, Copy, Debug, Default)]
pub struct JsonFlags<'a> {
    pub defaults: Option<&'a str>,
    pub metadata: Option<&'a str>,
    pub usage_limits: Option<&'a str>,
    pub rate_limits: Option<&'a str>,
}

/// `<flag> must be valid JSON` (TS text; the value is never echoed).
fn parse_json(flag: &str, text: Option<&str>) -> Result<Option<Value>, CliError> {
    text.map(|text| {
        super::body::js_json(text)
            .map_err(|_| CliError::usage(format!("{flag} must be valid JSON")))
    })
    .transpose()
}

/// A JSON array whose every item passes `parse` (`Mode::Request`), else the fixed text.
fn limits(
    flag: &str,
    text: Option<&str>,
    what: &str,
    parse: impl Fn(Value) -> bool,
) -> Result<Option<Value>, CliError> {
    let Some(value) = parse_json(flag, text)? else {
        return Ok(None);
    };
    match &value {
        Value::Array(items) if items.iter().all(|item| parse(item.clone())) => Ok(Some(value)),
        _ => Err(CliError::usage(format!(
            "Invalid {flag}: expected a JSON array of {what} policies"
        ))),
    }
}

/// TS `buildWorkspaceWriteRequest` (`gw.ts:82-110`) with the Rust checks (§19.6): only the
/// flags given; `defaults` = `--defaults` (an object) with `metadata` replaced whole by
/// `--metadata` (a flat map of strings, choice 19); the limits JSON arrays of the SDK
/// input schemas; `users` split, trimmed, empty items dropped.
pub fn workspace_fields(
    texts: &[(&'static str, Option<&String>)],
    users: Option<&str>,
    flags: JsonFlags<'_>,
) -> Result<Map<String, Value>, CliError> {
    let mut out = Map::new();
    for (key, value) in texts {
        if let Some(value) = value {
            out.insert((*key).to_owned(), Value::String((*value).clone()));
        }
    }
    let defaults = parse_json("--defaults", flags.defaults)?;
    let metadata = parse_json("--metadata", flags.metadata)?;
    if let Some(defaults) = &defaults
        && !defaults.is_object()
    {
        return Err(CliError::usage("--defaults must be a JSON object"));
    }
    if let Some(metadata) = &metadata {
        let flat = metadata
            .as_object()
            .is_some_and(|map| map.values().all(Value::is_string));
        if !flat {
            return Err(CliError::usage(
                "--metadata must be a JSON object of strings",
            ));
        }
    }
    if defaults.is_some() || metadata.is_some() {
        let mut merged = defaults
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        if let Some(metadata) = metadata {
            merged.insert("metadata".to_owned(), metadata);
        }
        out.insert("defaults".to_owned(), Value::Object(merged));
    }
    if let Some(users) = users {
        let ids: Vec<Value> = users
            .split(',')
            .map(|id| crate::tenant::config::js_trim(id).to_owned())
            .filter(|id| !id.is_empty())
            .map(Value::String)
            .collect();
        out.insert("users".to_owned(), Value::Array(ids));
    }
    if let Some(usage) = limits(
        "--usage-limits",
        flags.usage_limits,
        "usage-limit",
        |item| GatewayUsageLimitInput::parse(item, Mode::Request).is_ok(),
    )? {
        out.insert("usage_limits".to_owned(), usage);
    }
    if let Some(rate) = limits("--rate-limits", flags.rate_limits, "rate-limit", |item| {
        GatewayRateLimitInput::parse(item, Mode::Request).is_ok()
    })? {
        out.insert("rate_limits".to_owned(), rate);
    }
    Ok(out)
}

/// The create body checked with `GatewayWorkspaceCreateRequest` (the D116 usage text).
pub fn check_create(body: &Value) -> Result<(), CliError> {
    super::body::validate(
        body,
        "POST",
        "/workspaces",
        GatewayWorkspaceCreateRequest::parse,
    )
    .map(|_| ())
}

/// The update body checked with `GatewayWorkspaceUpdateRequest`.
pub fn check_update(body: &Value, reference: &str) -> Result<(), CliError> {
    super::body::validate(
        body,
        "PUT",
        &format!("/workspaces/{reference}"),
        GatewayWorkspaceUpdateRequest::parse,
    )
    .map(|_| ())
}

/// TS `scopeNameLooksUnrelated` (`gw.ts:118-125`): the name lowercased without
/// non-alphanumerics, at least 4 characters, not contained in the folded scope.
pub fn scope_name_looks_unrelated(name: &str, scope: &str) -> bool {
    let fold = |text: &str| -> String {
        text.to_lowercase()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect()
    };
    let token = fold(name);
    token.chars().count() >= 4 && !fold(scope).contains(&token)
}

/// The unrelated-scope warning (TS text, stderr, D230).
pub fn unrelated_warning(scope: &str, name: &str) -> String {
    format!(
        "⚠ --scope-name '{}' shares no token with --name '{}'. Operators find workspaces by scope in SCM Access Management; an unrelated name is easy to lose.",
        super::shown(scope),
        super::shown(name)
    )
}

/// The blocks a workspace update replaces whole (`defaults`, `usage_limits`,
/// `rate_limits`), as the prompt names them.
pub fn replaced_blocks(body: &Map<String, Value>) -> Vec<&'static str> {
    [
        ("defaults", "defaults"),
        ("usage_limits", "usage limits"),
        ("rate_limits", "rate limits"),
    ]
    .iter()
    .filter(|(key, _)| body.contains_key(*key))
    .map(|(_, label)| *label)
    .collect()
}

/// The scope-delete prompt (TS text, D236): the bindings of the scope read, at most 20,
/// then `, and <k> more`.
pub fn scope_delete_prompt(name: &str, scope: Option<&OValue>) -> String {
    let mut prompt =
        format!("Delete IAM scope {name}? Workspaces bound to it lose their data-plane grant.");
    let bindings: Vec<String> = scope
        .and_then(|scope| scope.get("resources"))
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(|resource| {
            let part = |key: &str| {
                resource
                    .get(key)
                    .and_then(OValue::as_str)
                    .map(|text| crate::output::terminal_safe(text).into_owned())
                    .unwrap_or_default()
            };
            format!("{}:{}", part("resource_type"), part("resource_id"))
        })
        .collect();
    if !bindings.is_empty() {
        let shown: Vec<&str> = bindings.iter().take(20).map(String::as_str).collect();
        let more = bindings.len().saturating_sub(20);
        let extra = if more > 0 {
            format!(", and {more} more")
        } else {
            String::new()
        };
        prompt.push_str(&format!(
            " It binds {} resource(s): {}{extra}.",
            bindings.len(),
            shown.join(", ")
        ));
    }
    prompt
}

/// The remedy hints of provisioning (§19.6).
pub struct Hints;

impl Hints {
    pub fn scope_unknown(scope: &str) -> String {
        format!(
            "Check it with '{PROGRAM} gateway scopes get {scope}'; reuse it with '{PROGRAM} gateway workspaces create --existing-scope --scope-name {scope} …' or delete it with '{PROGRAM} gateway scopes delete {scope}'."
        )
    }

    pub fn scope_still_present(scope: &str) -> String {
        format!(
            "Delete it with '{PROGRAM} gateway scopes delete {scope}' or reuse it with --existing-scope."
        )
    }

    pub fn workspace_unknown(scope: &str, existing: bool) -> String {
        let mut hint = format!(
            "Check '{PROGRAM} gateway workspaces list --plane admin'; if the workspace exists, finish with '{PROGRAM} gateway scopes bind {scope} --workspace <slug or name>'"
        );
        if existing {
            hint.push('.');
        } else {
            hint.push_str(&format!(
                "; otherwise delete the scope with '{PROGRAM} gateway scopes delete {scope}'."
            ));
        }
        hint
    }

    pub fn bind(scope: &str, slug: &str) -> String {
        format!("Finish with '{PROGRAM} gateway scopes bind {scope} --workspace {slug}'.")
    }

    pub fn bind_unknown(scope: &str, slug: &str) -> String {
        format!(
            "Check it with '{PROGRAM} gateway scopes get {scope}'; finish with '{PROGRAM} gateway scopes bind {scope} --workspace {slug}' if needed."
        )
    }
}

/// The success status line (TS text).
pub fn provisioned_status(scope: &str, slug: &str, created: bool) -> String {
    format!(
        "IAM scope {scope} {}bound to workspace {slug}. Grant that scope to the service accounts that should reach the workspace on the data plane.",
        if created { "created and " } else { "" }
    )
}

/// The archive status line (TS text).
pub const ARCHIVE_STATUS: &str = "This is a soft delete — the workspace remains visible via `workspaces list --plane admin --status archived`. A `get` on it now answers 404; that is expected.";

/// The hidden `delete`'s warning (TS text with `gateway`, stderr).
pub const DELETE_DEPRECATED: &str = "⚠ `gateway workspace delete` is deprecated because this operation archives; use `gateway workspaces archive`.";

/// The `scopes create` status line (TS text).
pub const SCOPE_CREATED_STATUS: &str = "The scope is not bound to anything yet — `workspaces create --existing-scope` or `scopes bind` finishes the job.";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn usage(result: Result<impl std::fmt::Debug, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("{other:?}"),
        }
    }

    /// TS `aigateway-write-helpers.spec.ts`: only passed flags; `--metadata` replaces
    /// `defaults.metadata`; `--users` split and trimmed; invalid JSON; the limit schemas.
    #[test]
    fn workspace_write_requests() {
        let name = "x".to_owned();
        let body = workspace_fields(
            &[("name", Some(&name)), ("icon", None)],
            None,
            JsonFlags::default(),
        )
        .unwrap();
        assert_eq!(Value::Object(body), json!({"name": "x"}));
        assert!(
            workspace_fields(&[], None, JsonFlags::default())
                .unwrap()
                .is_empty()
        );
        let body = workspace_fields(
            &[],
            Some("u1, u2,,u3"),
            JsonFlags {
                defaults: Some(r#"{"config_id":"cfg-1","metadata":{"env":"dev","team":"a"}}"#),
                metadata: Some(r#"{"env":"production"}"#),
                usage_limits: Some(r#"[{"type":"cost","credit_limit":5}]"#),
                rate_limits: Some(r#"[{"type":"requests","unit":"rpm","value":100}]"#),
            },
        )
        .unwrap();
        assert_eq!(
            Value::Object(body),
            json!({
                "defaults": {"config_id": "cfg-1", "metadata": {"env": "production"}},
                "users": ["u1", "u2", "u3"],
                "usage_limits": [{"type": "cost", "credit_limit": 5}],
                "rate_limits": [{"type": "requests", "unit": "rpm", "value": 100}],
            })
        );
        for (flags, message) in [
            (
                JsonFlags {
                    defaults: Some("{nope"),
                    ..JsonFlags::default()
                },
                "--defaults must be valid JSON",
            ),
            (
                JsonFlags {
                    defaults: Some("[1]"),
                    ..JsonFlags::default()
                },
                "--defaults must be a JSON object",
            ),
            (
                JsonFlags {
                    metadata: Some(r#"{"n":1}"#),
                    ..JsonFlags::default()
                },
                "--metadata must be a JSON object of strings",
            ),
            (
                JsonFlags {
                    usage_limits: Some(r#"[{"type":"FAKE-ENUM"}]"#),
                    ..JsonFlags::default()
                },
                "Invalid --usage-limits: expected a JSON array of usage-limit policies",
            ),
            (
                JsonFlags {
                    rate_limits: Some(r#"{"type":"requests"}"#),
                    ..JsonFlags::default()
                },
                "Invalid --rate-limits: expected a JSON array of rate-limit policies",
            ),
        ] {
            assert_eq!(usage(workspace_fields(&[], None, flags)), message);
        }
    }

    /// TS `scopeNameLooksUnrelated`: contained, unrelated, too short.
    #[test]
    fn unrelated_scope_names() {
        assert!(!scope_name_looks_unrelated(
            "Production",
            "ws_production_bx7qw0"
        ));
        assert!(scope_name_looks_unrelated(
            "Production",
            "ws_staging_q1x8mz"
        ));
        assert!(!scope_name_looks_unrelated("abc", "zzz"));
    }

    #[test]
    fn scope_delete_prompts_name_bindings() {
        let scope = crate::json::parse(
            r#"{"resources":[{"resource_type":"workspace","resource_id":"ws-a"}]}"#,
        )
        .unwrap();
        assert_eq!(
            scope_delete_prompt("s", Some(&scope)),
            "Delete IAM scope s? Workspaces bound to it lose their data-plane grant. It binds 1 resource(s): workspace:ws-a."
        );
        assert_eq!(
            scope_delete_prompt("s", None),
            "Delete IAM scope s? Workspaces bound to it lose their data-plane grant."
        );
        let many = (0..22)
            .map(|n| format!(r#"{{"resource_type":"workspace","resource_id":"w{n}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let scope = crate::json::parse(&format!(r#"{{"resources":[{many}]}}"#)).unwrap();
        let prompt = scope_delete_prompt("s", Some(&scope));
        assert!(prompt.ends_with(", workspace:w19, and 2 more."), "{prompt}");
    }
}
