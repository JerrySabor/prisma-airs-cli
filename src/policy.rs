//! Pure `serde_json::Value` surgery on security-profile policies (DESIGN §13.4, §13.12,
//! §13.13): the TypeScript profile builder (`builders/profile-builder.ts`) with its
//! section defaults, and `mergeProfilePolicy` with the D117 overlay of
//! `data-leak-detection`. No I/O; unit-tested here.
//!
//! The topic-guardrails edits of `topics apply|revert` join this module with those
//! commands.

use crate::cli::PolicyFlags;
use crate::error::CliError;
use serde_json::{Map, Value, json};

/// The largest `--max-inline-latency` (2^53, the largest integer every JSON reader
/// holds exactly).
const MAX_LATENCY: u64 = 9_007_199_254_740_992;

/// Validated policy flags: TypeScript treats an empty value as absent, so empty strings
/// are dropped here.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Flags {
    pub prompt_injection: Option<String>,
    pub toxic_content: Option<String>,
    pub contextual_grounding: Option<String>,
    pub malicious_code: Option<String>,
    pub url_action: Option<String>,
    pub allow_url_categories: Option<Vec<String>>,
    pub block_url_categories: Option<Vec<String>>,
    pub alert_url_categories: Option<Vec<String>>,
    pub agent_security: Option<String>,
    pub dlp_action: Option<String>,
    pub dlp_profiles: Option<Vec<String>>,
    pub mask_data_inline: bool,
    pub db_security: [Option<String>; 4],
    pub inline_timeout_action: Option<String>,
    pub max_inline_latency: Option<u64>,
    /// `--max-inline-latency` was given (valid or not: TS counts `NaN` as given).
    pub latency_given: bool,
    pub mask_data_in_storage: bool,
}

/// `Some(value)` when it is non-empty (TS truthiness).
fn given(value: Option<&String>) -> Option<String> {
    value.filter(|text| !text.is_empty()).cloned()
}

/// TS `parseList`: an empty value is absent; items are trimmed and empty items dropped.
fn list(value: Option<&String>) -> Option<Vec<String>> {
    let value = value.filter(|text| !text.is_empty())?;
    Some(
        value
            .split(',')
            .map(crate::tenant::config::js_trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// The database-security item names, in the builder's order.
const DB_OPS: [&str; 4] = [
    "database-security-create",
    "database-security-read",
    "database-security-update",
    "database-security-delete",
];

impl Flags {
    /// Read the raw flags (an invalid `--max-inline-latency` counts as given; [`Flags::check`]
    /// reports it).
    pub fn read(raw: &PolicyFlags) -> Self {
        let max_inline_latency = raw.max_inline_latency.as_deref().and_then(|text| {
            (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| text.parse::<u64>().ok())
                .flatten()
                .filter(|value| *value <= MAX_LATENCY)
        });
        Self {
            prompt_injection: given(raw.prompt_injection.as_ref()),
            toxic_content: given(raw.toxic_content.as_ref()),
            contextual_grounding: given(raw.contextual_grounding.as_ref()),
            malicious_code: given(raw.malicious_code.as_ref()),
            url_action: given(raw.url_action.as_ref()),
            allow_url_categories: list(raw.allow_url_categories.as_ref()),
            block_url_categories: list(raw.block_url_categories.as_ref()),
            alert_url_categories: list(raw.alert_url_categories.as_ref()),
            agent_security: given(raw.agent_security.as_ref()),
            dlp_action: given(raw.dlp_action.as_ref()),
            dlp_profiles: list(raw.dlp_profiles.as_ref()),
            mask_data_inline: raw.mask_data_inline,
            db_security: [
                given(raw.db_security_create.as_ref()),
                given(raw.db_security_read.as_ref()),
                given(raw.db_security_update.as_ref()),
                given(raw.db_security_delete.as_ref()),
            ],
            inline_timeout_action: given(raw.inline_timeout_action.as_ref()),
            max_inline_latency,
            latency_given: raw.max_inline_latency.is_some(),
            mask_data_in_storage: raw.mask_data_in_storage,
        }
    }

    /// The value checks of §13.12, in order: `--max-inline-latency` (decimal digits, at
    /// most 2^53), then the `--dlp-action` rule (D102).
    pub fn check(&self) -> Result<(), CliError> {
        if self.latency_given && self.max_inline_latency.is_none() {
            return Err(CliError::usage(
                "--max-inline-latency must be a non-negative integer",
            ));
        }
        if self.dlp_without_action() {
            return Err(CliError::usage(
                "--dlp-profiles and --mask-data-inline require --dlp-action",
            ));
        }
        Ok(())
    }

    /// Whether any policy flag was given at all, empty values included (the `--config`
    /// conflict checks).
    pub fn raw_any(raw: &PolicyFlags) -> bool {
        [
            &raw.prompt_injection,
            &raw.toxic_content,
            &raw.contextual_grounding,
            &raw.malicious_code,
            &raw.url_action,
            &raw.allow_url_categories,
            &raw.block_url_categories,
            &raw.alert_url_categories,
            &raw.agent_security,
            &raw.dlp_action,
            &raw.dlp_profiles,
            &raw.db_security_create,
            &raw.db_security_read,
            &raw.db_security_update,
            &raw.db_security_delete,
            &raw.inline_timeout_action,
            &raw.max_inline_latency,
        ]
        .iter()
        .any(|value| value.is_some())
            || raw.mask_data_inline
            || raw.mask_data_in_storage
    }

    /// `--dlp-profiles` or `--mask-data-inline` without `--dlp-action` (D102).
    pub fn dlp_without_action(&self) -> bool {
        (self.dlp_profiles.is_some() || self.mask_data_inline) && self.dlp_action.is_none()
    }

    /// TS `hasAnyProtectionFlag`: every policy flag except `--dlp-profiles` and
    /// `--mask-data-inline`.
    pub fn any_protection(&self) -> bool {
        self.prompt_injection.is_some()
            || self.toxic_content.is_some()
            || self.contextual_grounding.is_some()
            || self.malicious_code.is_some()
            || self.url_action.is_some()
            || self.allow_url_categories.is_some()
            || self.block_url_categories.is_some()
            || self.alert_url_categories.is_some()
            || self.agent_security.is_some()
            || self.dlp_action.is_some()
            || self.db_security.iter().any(Option::is_some)
            || self.inline_timeout_action.is_some()
            || self.latency_given
            || self.mask_data_in_storage
    }
}

fn named(name: &str, action: &str) -> Value {
    json!({"name": name, "action": action})
}

/// The flags' `model-protection` items (TS `buildModelProtection`).
fn model_protection(flags: &Flags) -> Option<Vec<Value>> {
    let mut items = Vec::new();
    if let Some(action) = &flags.prompt_injection {
        items.push(named("prompt-injection", action));
    }
    if let Some(action) = &flags.toxic_content {
        // A bare value is expanded to the "high:<v>, moderate:<v>" form the AIRS UI uses.
        let action = if action.contains(':') {
            action.clone()
        } else {
            format!("high:{action}, moderate:{action}")
        };
        items.push(named("toxic-content", &action));
    }
    if let Some(action) = &flags.contextual_grounding {
        items.push(named("contextual-grounding", action));
    }
    (!items.is_empty()).then_some(items)
}

/// TS `buildAppProtection`.
fn app_protection(flags: &Flags) -> Option<Map<String, Value>> {
    let mut section = Map::new();
    if let Some(action) = &flags.malicious_code {
        section.insert(
            "malicious-code-protection".into(),
            named("malicious-code-detection", action),
        );
    }
    if let Some(action) = &flags.url_action {
        section.insert("url-detected-action".into(), json!(action));
    }
    for (key, members) in [
        ("allow-url-category", &flags.allow_url_categories),
        ("block-url-category", &flags.block_url_categories),
        ("alert-url-category", &flags.alert_url_categories),
    ] {
        if let Some(members) = members {
            section.insert(key.into(), json!({"member": members}));
        }
    }
    (!section.is_empty()).then_some(section)
}

/// The `data-leak-detection` object of the flags (TS `buildDataProtection`).
fn leak_detection(flags: &Flags) -> Option<Map<String, Value>> {
    let action = flags.dlp_action.as_ref()?;
    let mut object = Map::new();
    object.insert("action".into(), json!(action));
    if let Some(profiles) = &flags.dlp_profiles {
        let members: Vec<Value> = profiles.iter().map(|text| json!({"text": text})).collect();
        object.insert("member".into(), Value::Array(members));
    }
    if flags.mask_data_inline {
        object.insert("mask-data-inline".into(), json!(true));
    }
    Some(object)
}

fn database_security(flags: &Flags) -> Option<Vec<Value>> {
    let items: Vec<Value> = DB_OPS
        .iter()
        .zip(&flags.db_security)
        .filter_map(|(name, action)| action.as_ref().map(|action| named(name, action)))
        .collect();
    (!items.is_empty()).then_some(items)
}

/// TS `buildDataProtection`.
fn data_protection(flags: &Flags) -> Option<Map<String, Value>> {
    let mut section = Map::new();
    if let Some(object) = leak_detection(flags) {
        section.insert("data-leak-detection".into(), Value::Object(object));
    }
    if let Some(items) = database_security(flags) {
        section.insert("database-security".into(), Value::Array(items));
    }
    (!section.is_empty()).then_some(section)
}

/// TS `buildLatency`.
fn latency(flags: &Flags) -> Option<Map<String, Value>> {
    let mut section = Map::new();
    if let Some(action) = &flags.inline_timeout_action {
        section.insert("inline-timeout-action".into(), json!(action));
    }
    if let Some(seconds) = flags.max_inline_latency {
        section.insert("max-inline-latency".into(), json!(seconds));
    }
    (!section.is_empty()).then_some(section)
}

/// TS `buildModelConfiguration`: only the sections the flags fill.
fn model_configuration(flags: &Flags) -> Map<String, Value> {
    let mut config = Map::new();
    if let Some(items) = model_protection(flags) {
        config.insert("model-protection".into(), Value::Array(items));
    }
    if let Some(section) = app_protection(flags) {
        config.insert("app-protection".into(), Value::Object(section));
    }
    if let Some(action) = &flags.agent_security {
        config.insert(
            "agent-protection".into(),
            json!([named("agent-security", action)]),
        );
    }
    if let Some(section) = data_protection(flags) {
        config.insert("data-protection".into(), Value::Object(section));
    }
    if let Some(section) = latency(flags) {
        config.insert("latency".into(), Value::Object(section));
    }
    if flags.mask_data_in_storage {
        config.insert("mask-data-in-storage".into(), json!(true));
    }
    config
}

/// The `profiles create` body from flags (TS `buildProfileRequest`): the configuration
/// with TypeScript's defaults for the sections the flags left out. The caller has
/// checked that a protection flag is present (D102).
pub fn create_request(name: &str, active: bool, flags: &Flags) -> Value {
    let mut config = model_configuration(flags);
    config.entry("app-protection").or_insert_with(|| {
        json!({
            "default-url-category": {"member": ["malicious"]},
            "url-detected-action": "block",
        })
    });
    config.entry("data-protection").or_insert_with(|| {
        json!({
            "data-leak-detection": {"action": "", "mask-data-inline": false, "member": null},
            "database-security": null,
        })
    });
    config
        .entry("latency")
        .or_insert_with(|| json!({"inline-timeout-action": "block", "max-inline-latency": 5}));
    config
        .entry("mask-data-in-storage")
        .or_insert_with(|| json!(false));
    json!({
        "profile_name": name,
        "active": active,
        "policy": {
            "ai-security-profiles": [{
                "model-type": "default",
                "model-configuration": Value::Object(config),
            }],
        },
    })
}

/// The `model-configuration` object of `ai-security-profiles[0]`, created as DESIGN
/// §13.4 says when the array is absent or empty (TS throws on an empty array, D115) or
/// the object is absent.
pub fn first_configuration(policy: &mut Map<String, Value>) -> &mut Map<String, Value> {
    let profiles = policy
        .entry("ai-security-profiles")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !matches!(profiles, Value::Array(items) if !items.is_empty()) {
        *profiles = json!([{"model-type": "default", "model-configuration": {}}]);
    }
    let Value::Array(items) = profiles else {
        unreachable!("set to an array above")
    };
    if !items[0].is_object() {
        items[0] = json!({"model-type": "default", "model-configuration": {}});
    }
    let Value::Object(element) = &mut items[0] else {
        unreachable!("an object")
    };
    let config = element
        .entry("model-configuration")
        .or_insert_with(|| Value::Object(Map::new()));
    if !config.is_object() {
        *config = Value::Object(Map::new());
    }
    let Value::Object(config) = config else {
        unreachable!("an object")
    };
    config
}

/// Merge items by `name`: the fields of a matching item are overwritten, new items are
/// appended (TS `Object.assign` per item).
fn merge_by_name(base: Option<Value>, overrides: Vec<Value>) -> Value {
    let mut items = match base {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    };
    for over in overrides {
        let name = over.get("name").cloned();
        match items
            .iter_mut()
            .find(|item| item.get("name").is_some() && item.get("name").cloned() == name)
        {
            Some(Value::Object(existing)) => {
                if let Value::Object(fields) = over {
                    existing.extend(fields);
                }
            }
            _ => items.push(over),
        }
    }
    Value::Array(items)
}

/// A field overlay of `fields` onto the object at `base` (created when absent).
fn overlay(base: Option<Value>, fields: Map<String, Value>) -> Value {
    let mut object = match base {
        Some(Value::Object(object)) => object,
        _ => Map::new(),
    };
    object.extend(fields);
    Value::Object(object)
}

/// `profiles update`: TS `mergeProfilePolicy` of the flags into the read policy (absent
/// is `{}`), with `data-leak-detection` overlaid field by field (D117). Without a
/// protection flag the policy is returned as read. No section defaults are added.
pub fn merge(existing: Option<Value>, flags: &Flags) -> Value {
    let mut policy = match existing {
        Some(Value::Object(policy)) => policy,
        _ => Map::new(),
    };
    if !flags.any_protection() {
        return Value::Object(policy);
    }
    let config = first_configuration(&mut policy);
    if let Some(items) = model_protection(flags) {
        let merged = merge_by_name(config.remove("model-protection"), items);
        config.insert("model-protection".into(), merged);
    }
    if let Some(section) = app_protection(flags) {
        let merged = overlay(config.remove("app-protection"), section);
        config.insert("app-protection".into(), merged);
    }
    if let Some(action) = &flags.agent_security {
        let merged = merge_by_name(
            config.remove("agent-protection"),
            vec![named("agent-security", action)],
        );
        config.insert("agent-protection".into(), merged);
    }
    let leak = leak_detection(flags);
    let database = database_security(flags);
    if leak.is_some() || database.is_some() {
        let mut section = match config.remove("data-protection") {
            Some(Value::Object(section)) => section,
            _ => Map::new(),
        };
        if let Some(fields) = leak {
            let merged = overlay(section.remove("data-leak-detection"), fields);
            section.insert("data-leak-detection".into(), merged);
        }
        if let Some(items) = database {
            let merged = merge_by_name(section.remove("database-security"), items);
            section.insert("database-security".into(), merged);
        }
        config.insert("data-protection".into(), Value::Object(section));
    }
    if let Some(section) = latency(flags) {
        let merged = overlay(config.remove("latency"), section);
        config.insert("latency".into(), merged);
    }
    if flags.mask_data_in_storage {
        config.insert("mask-data-in-storage".into(), json!(true));
    }
    Value::Object(policy)
}

/// The `model-protection` item that holds the topic refs.
pub const GUARDRAIL: &str = "topic-guardrails";

/// A topic as the guardrail edits see it (§13.4): its name and the id of every listed
/// revision with that name. A ref belongs to the topic when its `topic_name` is the
/// name or its `topic_id` is one of the ids.
#[derive(Clone, Copy, Debug)]
pub struct TopicIdentity<'a> {
    pub name: &'a str,
    pub ids: &'a [String],
}

impl TopicIdentity<'_> {
    fn owns(&self, reference: &Value) -> bool {
        reference.get("topic_name").and_then(Value::as_str) == Some(self.name)
            || reference
                .get("topic_id")
                .and_then(Value::as_str)
                .is_some_and(|id| self.ids.iter().any(|known| known == id))
    }
}

/// The position of the first `topic-guardrails` item.
fn guardrail_index(items: &[Value]) -> Option<usize> {
    items
        .iter()
        .position(|item| item.get("name").and_then(Value::as_str) == Some(GUARDRAIL))
}

/// The `(group, ref)` positions of the topic's refs in a `topic-list`.
fn ref_positions(groups: &[Value], topic: TopicIdentity<'_>) -> Vec<(usize, usize)> {
    groups
        .iter()
        .enumerate()
        .flat_map(|(group, value)| {
            value
                .get("topic")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
                .filter(move |(_, reference)| topic.owns(reference))
                .map(move |(index, _)| (group, index))
        })
        .collect()
}

/// Remove every ref of the topic from `groups`; a group the removal leaves empty is
/// removed too (other groups, empty ones included, are kept as read).
fn remove_refs(groups: &mut Vec<Value>, topic: TopicIdentity<'_>) {
    groups.retain_mut(|group| {
        let Some(Value::Array(refs)) = group.get_mut("topic") else {
            return true;
        };
        let before = refs.len();
        refs.retain(|reference| !topic.owns(reference));
        refs.len() == before || !refs.is_empty()
    });
}

/// The group's `action`.
fn group_action(group: &Value) -> Option<&str> {
    group.get("action").and_then(Value::as_str)
}

/// `topics apply` (§13.4): the policy with `new_ref` (the resolved revision's ref) under
/// the `intent` group of `ai-security-profiles[0]`'s topic guardrails. Every other ref,
/// group and key is kept as read (D98); the item's `action` follows TypeScript's rule.
pub fn apply_topic(
    policy: Option<Value>,
    topic: TopicIdentity<'_>,
    new_ref: Value,
    intent: &str,
) -> Value {
    let mut policy = match policy {
        Some(Value::Object(policy)) => policy,
        _ => Map::new(),
    };
    let guard_action = if intent == "block" { "allow" } else { "block" };
    let config = first_configuration(&mut policy);
    let protection = config
        .entry("model-protection")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !protection.is_array() {
        *protection = Value::Array(Vec::new());
    }
    let Value::Array(items) = protection else {
        unreachable!("set to an array above")
    };
    let index = guardrail_index(items).unwrap_or_else(|| {
        items.push(json!({
            "name": GUARDRAIL, "action": guard_action, "options": [], "topic-list": []
        }));
        items.len() - 1
    });
    let Value::Object(item) = &mut items[index] else {
        unreachable!("a named item is an object")
    };
    let list = item
        .entry("topic-list")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !list.is_array() {
        *list = Value::Array(Vec::new());
    }
    let Value::Array(groups) = list else {
        unreachable!("set to an array above")
    };
    let positions = ref_positions(groups, topic);
    match positions.as_slice() {
        [(group, index)] if group_action(&groups[*group]) == Some(intent) => {
            if let Some(Value::Array(refs)) = groups[*group].get_mut("topic") {
                refs[*index] = new_ref;
            }
        }
        _ => {
            remove_refs(groups, topic);
            let target = groups.iter_mut().find(|group| {
                group_action(group) == Some(intent)
                    && group.get("topic").is_none_or(Value::is_array)
            });
            match target {
                Some(Value::Object(group)) => {
                    let refs = group
                        .entry("topic")
                        .or_insert_with(|| Value::Array(Vec::new()));
                    if let Value::Array(refs) = refs {
                        refs.push(new_ref);
                    }
                }
                _ => groups.push(json!({"action": intent, "topic": [new_ref]})),
            }
        }
    }
    item.insert("action".into(), json!(guard_action));
    Value::Object(policy)
}

/// `topics revert` (§13.4): the policy without the topic's refs, or `None` when
/// `ai-security-profiles[0]` holds no ref of it (nothing is written). Groups the removal
/// empties are removed; when no ref remains the guardrail item itself is removed (D99),
/// otherwise its `action` follows TypeScript's rule.
pub fn revert_topic(policy: Option<&Value>, topic: TopicIdentity<'_>) -> Option<Value> {
    let mut policy = policy?.clone();
    let items = policy
        .get_mut("ai-security-profiles")?
        .get_mut(0)?
        .get_mut("model-configuration")?
        .get_mut("model-protection")?
        .as_array_mut()?;
    let index = guardrail_index(items)?;
    let groups = items[index].get_mut("topic-list")?.as_array_mut()?;
    if ref_positions(groups, topic).is_empty() {
        return None;
    }
    remove_refs(groups, topic);
    let remaining: Vec<&Value> = groups
        .iter()
        .filter(|group| {
            group
                .get("topic")
                .and_then(Value::as_array)
                .is_some_and(|refs| !refs.is_empty())
        })
        .collect();
    if remaining.is_empty() {
        items.remove(index);
    } else {
        let blocks = remaining
            .iter()
            .any(|group| group_action(group) == Some("block"));
        let action = if blocks { "allow" } else { "block" };
        if let Some(item) = items[index].as_object_mut() {
            item.insert("action".into(), json!(action));
        }
    }
    Some(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(edit: impl FnOnce(&mut PolicyFlags)) -> Flags {
        let mut raw = PolicyFlags::default();
        edit(&mut raw);
        let flags = Flags::read(&raw);
        flags.check().unwrap();
        flags
    }

    #[test]
    fn latency_must_be_a_decimal_integer() {
        for bad in ["", "1.5", "abc", "-1", "1e3", "0x10", "9007199254740993"] {
            let raw = PolicyFlags {
                max_inline_latency: Some(bad.to_owned()),
                ..PolicyFlags::default()
            };
            let read = Flags::read(&raw);
            assert!(
                read.any_protection(),
                "an invalid value still counts as given"
            );
            assert_eq!(
                read.check(),
                Err(CliError::usage(
                    "--max-inline-latency must be a non-negative integer"
                )),
                "{bad}"
            );
        }
        let good = flags(|raw| raw.max_inline_latency = Some("0".into()));
        assert_eq!(good.max_inline_latency, Some(0));
        assert!(good.any_protection());
    }

    #[test]
    fn empty_values_are_absent_and_dlp_needs_an_action() {
        let empty = flags(|raw| {
            raw.prompt_injection = Some(String::new());
            raw.dlp_profiles = Some(String::new());
        });
        assert!(!empty.any_protection());
        assert!(!empty.dlp_without_action());
        assert!(Flags::raw_any(&PolicyFlags {
            prompt_injection: Some(String::new()),
            ..PolicyFlags::default()
        }));
        assert!(!Flags::raw_any(&PolicyFlags::default()));
        let mask = Flags::read(&PolicyFlags {
            mask_data_inline: true,
            ..PolicyFlags::default()
        });
        assert!(mask.dlp_without_action());
        assert!(!mask.any_protection(), "not a protection flag");
        assert_eq!(
            mask.check(),
            Err(CliError::usage(
                "--dlp-profiles and --mask-data-inline require --dlp-action"
            ))
        );
        let profiles = Flags::read(&PolicyFlags {
            dlp_profiles: Some("a".into()),
            ..PolicyFlags::default()
        });
        assert!(profiles.dlp_without_action());
        let with_action = flags(|raw| {
            raw.dlp_profiles = Some(" a , ,b ".into());
            raw.dlp_action = Some("block".into());
        });
        assert!(!with_action.dlp_without_action());
        assert_eq!(with_action.dlp_profiles, Some(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn create_request_matches_the_typescript_builder() {
        let body = create_request(
            "p",
            true,
            &flags(|raw| raw.prompt_injection = Some("block".into())),
        );
        assert_eq!(
            body,
            json!({
                "profile_name": "p",
                "active": true,
                "policy": {"ai-security-profiles": [{
                    "model-type": "default",
                    "model-configuration": {
                        "model-protection": [{"name": "prompt-injection", "action": "block"}],
                        "app-protection": {
                            "default-url-category": {"member": ["malicious"]},
                            "url-detected-action": "block"
                        },
                        "data-protection": {
                            "data-leak-detection": {"action": "", "mask-data-inline": false, "member": null},
                            "database-security": null
                        },
                        "latency": {"inline-timeout-action": "block", "max-inline-latency": 5},
                        "mask-data-in-storage": false
                    }
                }]}
            })
        );
        let every = create_request(
            "q",
            false,
            &flags(|raw| {
                raw.toxic_content = Some("block".into());
                raw.contextual_grounding = Some("alert".into());
                raw.malicious_code = Some("block".into());
                raw.url_action = Some("alert".into());
                raw.allow_url_categories = Some("a, b".into());
                raw.block_url_categories = Some("c".into());
                raw.alert_url_categories = Some("d,".into());
                raw.agent_security = Some("block".into());
                raw.dlp_action = Some("block".into());
                raw.dlp_profiles = Some("PII, PCI".into());
                raw.mask_data_inline = true;
                raw.db_security_read = Some("allow".into());
                raw.db_security_create = Some("block".into());
                raw.inline_timeout_action = Some("allow".into());
                raw.max_inline_latency = Some("10".into());
                raw.mask_data_in_storage = true;
            }),
        );
        assert_eq!(
            every["policy"]["ai-security-profiles"][0]["model-configuration"],
            json!({
                "model-protection": [
                    {"name": "toxic-content", "action": "high:block, moderate:block"},
                    {"name": "contextual-grounding", "action": "alert"}
                ],
                "app-protection": {
                    "malicious-code-protection": {"name": "malicious-code-detection", "action": "block"},
                    "url-detected-action": "alert",
                    "allow-url-category": {"member": ["a", "b"]},
                    "block-url-category": {"member": ["c"]},
                    "alert-url-category": {"member": ["d"]}
                },
                "agent-protection": [{"name": "agent-security", "action": "block"}],
                "data-protection": {
                    "data-leak-detection": {
                        "action": "block",
                        "member": [{"text": "PII"}, {"text": "PCI"}],
                        "mask-data-inline": true
                    },
                    "database-security": [
                        {"name": "database-security-create", "action": "block"},
                        {"name": "database-security-read", "action": "allow"}
                    ]
                },
                "latency": {"inline-timeout-action": "allow", "max-inline-latency": 10},
                "mask-data-in-storage": true
            })
        );
        assert_eq!(every["active"], json!(false));
        let toxic = create_request(
            "t",
            true,
            &flags(|raw| raw.toxic_content = Some("high:block".into())),
        );
        assert_eq!(
            toxic["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"],
            json!([{"name": "toxic-content", "action": "high:block"}])
        );
    }

    #[test]
    fn merge_keeps_everything_the_flags_do_not_change() {
        let existing = json!({
            "ai-security-profiles": [{
                "model-type": "default",
                "model-configuration": {
                    "model-protection": [
                        {"name": "prompt-injection", "action": "allow", "options": []},
                        {"name": "topic-guardrails", "action": "allow", "topic-list": [{"action": "block", "topic": []}]}
                    ],
                    "app-protection": {"url-detected-action": "block", "default-url-category": {"member": ["malicious"]}},
                    "data-protection": {
                        "data-leak-detection": {"action": "alert", "member": [{"text": "PII"}], "mask-data-inline": true},
                        "database-security": [{"name": "database-security-read", "action": "block"}]
                    },
                    "latency": {"inline-timeout-action": "block", "max-inline-latency": 5},
                    "x-unknown": {"kept": 1.0}
                }
            }],
            "dlp-data-profiles": [{"name": "PII"}]
        });
        let merged = merge(
            Some(existing.clone()),
            &flags(|raw| {
                raw.prompt_injection = Some("block".into());
                raw.contextual_grounding = Some("alert".into());
                raw.url_action = Some("alert".into());
                raw.dlp_action = Some("block".into());
                raw.db_security_read = Some("allow".into());
                raw.db_security_delete = Some("block".into());
                raw.max_inline_latency = Some("9".into());
            }),
        );
        let config = &merged["ai-security-profiles"][0]["model-configuration"];
        assert_eq!(
            config["model-protection"],
            json!([
                {"name": "prompt-injection", "action": "block", "options": []},
                {"name": "topic-guardrails", "action": "allow", "topic-list": [{"action": "block", "topic": []}]},
                {"name": "contextual-grounding", "action": "alert"}
            ])
        );
        assert_eq!(
            config["app-protection"],
            json!({"url-detected-action": "alert", "default-url-category": {"member": ["malicious"]}})
        );
        // D117: only the action changes; the DLP profiles and the mask stay.
        assert_eq!(
            config["data-protection"]["data-leak-detection"],
            json!({"action": "block", "member": [{"text": "PII"}], "mask-data-inline": true})
        );
        assert_eq!(
            config["data-protection"]["database-security"],
            json!([
                {"name": "database-security-read", "action": "allow"},
                {"name": "database-security-delete", "action": "block"}
            ])
        );
        assert_eq!(
            config["latency"],
            json!({"inline-timeout-action": "block", "max-inline-latency": 9})
        );
        assert_eq!(config["x-unknown"], json!({"kept": 1.0}));
        assert_eq!(merged["dlp-data-profiles"], existing["dlp-data-profiles"]);
        // No protection flag: the policy as read.
        assert_eq!(merge(Some(existing.clone()), &Flags::default()), existing);
        assert_eq!(merge(None, &Flags::default()), json!({}));
    }

    #[test]
    fn merge_creates_the_first_profile_when_absent_or_empty() {
        let only = flags(|raw| raw.prompt_injection = Some("block".into()));
        let expected = json!({"ai-security-profiles": [{
            "model-type": "default",
            "model-configuration": {"model-protection": [{"name": "prompt-injection", "action": "block"}]}
        }]});
        assert_eq!(merge(None, &only), expected);
        assert_eq!(
            merge(Some(json!({"ai-security-profiles": []})), &only),
            expected,
            "an empty array is treated as absent (D115)"
        );
        assert_eq!(
            merge(
                Some(json!({"ai-security-profiles": [{"model-type": "default"}]})),
                &only
            ),
            expected
        );
        let profiles = flags(|raw| {
            raw.dlp_action = Some("block".into());
            raw.dlp_profiles = Some("A".into());
            raw.mask_data_inline = true;
        });
        assert_eq!(
            merge(
                Some(
                    json!({"ai-security-profiles": [{"model-type": "default", "model-configuration": {
                        "data-protection": {"data-leak-detection": {"action": "alert", "member": [{"text": "B"}]}}
                    }}]})
                ),
                &profiles
            )["ai-security-profiles"][0]["model-configuration"]["data-protection"],
            json!({"data-leak-detection": {"action": "block", "member": [{"text": "A"}], "mask-data-inline": true}})
        );
    }

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// A policy whose topic guardrails hold `groups`, beside other items and keys.
    fn guarded(groups: Value) -> Value {
        json!({"x-policy": 1.5, "ai-security-profiles": [{"model-type": "default", "model-configuration": {
            "x-config": {"keep": true},
            "model-protection": [
                {"name": "prompt-injection", "action": "alert"},
                {"name": "topic-guardrails", "action": "allow", "options": [{"o": 1}], "x-item": 2, "topic-list": groups}
            ]
        }}]})
    }

    fn groups_of(policy: &Value) -> Value {
        policy["ai-security-profiles"][0]["model-configuration"]["model-protection"][1]["topic-list"].clone()
    }

    fn item_of(policy: &Value) -> Value {
        policy["ai-security-profiles"][0]["model-configuration"]["model-protection"][1].clone()
    }

    #[test]
    fn apply_appends_the_guardrail_and_creates_the_profile_element() {
        let known = ids(&["T1"]);
        let topic = TopicIdentity {
            name: "fin",
            ids: &known,
        };
        let new_ref = json!({"topic_id": "T1", "topic_name": "fin", "revision": 2});
        for policy in [
            None,
            Some(json!({})),
            Some(json!({"ai-security-profiles": []})),
        ] {
            assert_eq!(
                apply_topic(policy, topic, new_ref.clone(), "block"),
                json!({"ai-security-profiles": [{"model-type": "default", "model-configuration": {
                    "model-protection": [{"name": "topic-guardrails", "action": "allow", "options": [],
                        "topic-list": [{"action": "block", "topic": [new_ref.clone()]}]}]
                }}]})
            );
        }
        let allowed = apply_topic(None, topic, new_ref.clone(), "allow");
        assert_eq!(
            allowed["ai-security-profiles"][0]["model-configuration"]["model-protection"][0]["action"],
            "block",
            "intent allow sets the guardrail to block (TypeScript's rule)"
        );
    }

    #[test]
    fn apply_keeps_every_other_ref_and_key_d98() {
        let known = ids(&["T1", "T0"]);
        let topic = TopicIdentity {
            name: "fin",
            ids: &known,
        };
        let new_ref = json!({"topic_id": "T1", "topic_name": "fin", "revision": 2});
        let other = json!({"topic_id": "O1", "topic_name": "other", "revision": 1, "x-ref": true});
        let policy = guarded(json!([
            {"action": "block", "x-group": 1, "topic": [other.clone(), {"topic_id": "T0", "topic_name": "fin-old-name", "revision": 1}]}
        ]));
        let after = apply_topic(Some(policy.clone()), topic, new_ref.clone(), "block");
        assert_eq!(
            groups_of(&after),
            json!([{"action": "block", "x-group": 1, "topic": [other.clone(), new_ref.clone()]}]),
            "a single ref in the intent group is replaced in place (matched by an old revision's id)"
        );
        let item = item_of(&after);
        assert_eq!(
            (item["options"].clone(), item["x-item"].clone()),
            (json!([{"o": 1}]), json!(2))
        );
        assert_eq!(after["x-policy"], 1.5);
        assert_eq!(
            after["ai-security-profiles"][0]["model-configuration"]["x-config"],
            json!({"keep": true})
        );
        assert_eq!(
            after["ai-security-profiles"][0]["model-configuration"]["model-protection"][0],
            json!({"name": "prompt-injection", "action": "alert"})
        );
        let moved = apply_topic(Some(policy), topic, new_ref.clone(), "allow");
        assert_eq!(
            groups_of(&moved),
            json!([{"action": "block", "x-group": 1, "topic": [other.clone()]}, {"action": "allow", "topic": [new_ref.clone()]}]),
            "another intent moves the ref to a new group at the end"
        );
        assert_eq!(item_of(&moved)["action"], "block");
        let twice = guarded(json!([
            {"action": "allow", "topic": [{"topic_id": "T1", "topic_name": "fin", "revision": 1}]},
            {"action": "block", "topic": [{"topic_name": "fin"}]},
            {"action": "block", "topic": [other.clone()]},
            {"action": "block", "topic": []}
        ]));
        assert_eq!(
            groups_of(&apply_topic(Some(twice), topic, new_ref.clone(), "block")),
            json!([{"action": "block", "topic": [other, new_ref.clone()]}, {"action": "block", "topic": []}]),
            "duplicate refs are removed, emptied groups dropped, the first intent group gets the ref"
        );
        let same = guarded(json!([{"action": "block", "topic": [new_ref.clone()]}]));
        assert_eq!(
            apply_topic(Some(same.clone()), topic, new_ref, "block"),
            same,
            "re-applying changes nothing"
        );
    }

    #[test]
    fn revert_removes_refs_and_the_last_one_removes_the_item_d99() {
        let known = ids(&["T1"]);
        let topic = TopicIdentity {
            name: "fin",
            ids: &known,
        };
        let other = json!({"topic_id": "O1", "topic_name": "other", "revision": 1});
        assert_eq!(revert_topic(None, topic), None);
        assert_eq!(
            revert_topic(Some(&json!({})), topic),
            None,
            "no profile element is created"
        );
        let unrelated = guarded(json!([{"action": "block", "topic": [other.clone()]}]));
        assert_eq!(revert_topic(Some(&unrelated), topic), None);
        let mixed = guarded(json!([
            {"action": "allow", "topic": [other.clone()]},
            {"action": "block", "topic": [{"topic_id": "T1", "topic_name": "renamed"}]}
        ]));
        let after = revert_topic(Some(&mixed), topic).unwrap();
        assert_eq!(
            groups_of(&after),
            json!([{"action": "allow", "topic": [other.clone()]}])
        );
        assert_eq!(item_of(&after)["action"], "block", "no block refs remain");
        let blocks = guarded(json!([
            {"action": "block", "topic": [other.clone(), {"topic_name": "fin"}]}
        ]));
        let after = revert_topic(Some(&blocks), topic).unwrap();
        assert_eq!(
            groups_of(&after),
            json!([{"action": "block", "topic": [other]}])
        );
        assert_eq!(item_of(&after)["action"], "allow");
        let last = guarded(
            json!([{"action": "block", "topic": [{"topic_name": "fin"}]}, {"action": "allow", "topic": []}]),
        );
        let after = revert_topic(Some(&last), topic).unwrap();
        assert_eq!(
            after["ai-security-profiles"][0]["model-configuration"]["model-protection"],
            json!([{"name": "prompt-injection", "action": "alert"}]),
            "the guardrail item goes with its last ref"
        );
        assert_eq!(after["x-policy"], 1.5);
    }
}
