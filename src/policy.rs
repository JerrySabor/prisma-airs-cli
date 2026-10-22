//! Pure `serde_json::Value` surgery on security-profile policies (DESIGN §13.4, §13.12,
//! §13.13, §13.17): TypeScript 7.3.0's profile builder (`builders/profile-builder.ts`)
//! with its legacy section defaults and its directional layout, `mergeProfilePolicy`
//! (the recursive merge of one selected AI entry and direction), and the
//! topic-guardrails edits of `topics apply|revert` on the selected protection block.
//! The layout rules live in [`crate::profile_policy`]. No I/O; unit-tested here.

use crate::cli::PolicyFlags;
use crate::error::CliError;
use crate::profile_policy::{self as layout, Selector};
use serde_json::{Map, Value, json};

/// The largest `--max-inline-latency` (2^53, the largest integer every JSON reader
/// holds exactly).
const MAX_LATENCY: u64 = 9_007_199_254_740_992;

/// The request schema every profile body is validated with (scm-sdk 0.2.4, the
/// TypeScript 0.35.0 root that the SDK's create and update also apply, §15.25).
pub const REQUEST_SCHEMA: &str = "typescript:0.35.0:CreateSecurityProfileRequestSchema";

/// Validate a profile body with [`REQUEST_SCHEMA`] and type it. `None` when it does not
/// match (the caller reports the D116 text).
pub fn request_body(
    value: Value,
) -> Option<scm::airs::management::models::CreateSecurityProfileRequest> {
    use scm::validation::Mode;
    let value = scm::validation::parse(REQUEST_SCHEMA, value, Mode::Request).ok()?;
    scm::airs::management::models::CreateSecurityProfileRequest::parse(value, Mode::Request).ok()
}

/// Validated policy flags. The text flags follow TypeScript 7.3.0: an empty value is
/// absent, except `--dlp-action` and `--dlp-profiles`, which count when given at all.
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
    /// `--dlp-action`, an empty value included.
    pub dlp_action: Option<String>,
    /// `--dlp-profiles` was given (an empty value included).
    pub dlp_profiles_given: bool,
    /// Its items (`None` for an empty value: no `member` is written).
    pub dlp_profiles: Option<Vec<String>>,
    /// `--mask-data-inline` (`true`) / `--no-mask-data-inline` (`false`), the last wins.
    pub mask_data_inline: Option<bool>,
    pub db_security: [Option<String>; 4],
    pub inline_timeout_action: Option<String>,
    pub max_inline_latency: Option<u64>,
    /// `--max-inline-latency` was given (valid or not).
    pub latency_given: bool,
    /// `--[no-]mask-data-in-storage`.
    pub mask_data_in_storage: Option<bool>,
    /// `--[no-]enable-full-conversation-inspection`.
    pub enable_full_conversation_inspection: Option<bool>,
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

/// A positive / negative flag pair (clap keeps only the last one given).
fn pair(on: bool, off: bool) -> Option<bool> {
    match (on, off) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
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
            dlp_action: raw.dlp_action.clone(),
            dlp_profiles_given: raw.dlp_profiles.is_some(),
            dlp_profiles: list(raw.dlp_profiles.as_ref()),
            mask_data_inline: pair(raw.mask_data_inline, raw.no_mask_data_inline),
            db_security: [
                given(raw.db_security_create.as_ref()),
                given(raw.db_security_read.as_ref()),
                given(raw.db_security_update.as_ref()),
                given(raw.db_security_delete.as_ref()),
            ],
            inline_timeout_action: given(raw.inline_timeout_action.as_ref()),
            max_inline_latency,
            latency_given: raw.max_inline_latency.is_some(),
            mask_data_in_storage: pair(raw.mask_data_in_storage, raw.no_mask_data_in_storage),
            enable_full_conversation_inspection: pair(
                raw.enable_full_conversation_inspection,
                raw.no_enable_full_conversation_inspection,
            ),
        }
    }

    /// The value check of §13.1: `--max-inline-latency` (decimal digits, at most 2^53;
    /// D102).
    pub fn check(&self) -> Result<(), CliError> {
        if self.latency_given && self.max_inline_latency.is_none() {
            return Err(CliError::usage(
                "--max-inline-latency must be a non-negative integer",
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
            || raw.no_mask_data_inline
            || raw.mask_data_in_storage
            || raw.no_mask_data_in_storage
            || raw.enable_full_conversation_inspection
            || raw.no_enable_full_conversation_inspection
    }

    /// A `data-leak-detection` block is written without `--dlp-action` (`--dlp-profiles`
    /// or `--[no-]mask-data-inline` alone). An update overlays it on the read block; a
    /// create refuses it (§13.12).
    pub fn dlp_without_action(&self) -> bool {
        (self.dlp_profiles_given || self.mask_data_inline.is_some()) && self.dlp_action.is_none()
    }

    /// TS 7.3.0 `hasAnyProtectionFlag`: every protection and shared-setting flag.
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
            || self.dlp_profiles_given
            || self.mask_data_inline.is_some()
            || self.db_security.iter().any(Option::is_some)
            || self.inline_timeout_action.is_some()
            || self.latency_given
            || self.mask_data_in_storage.is_some()
            || self.enable_full_conversation_inspection.is_some()
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

/// TS `buildAppProtection`: the malicious-code item is named `malicious-code` in a
/// directional block and `malicious-code-detection` in a legacy one.
fn app_protection(flags: &Flags, directional: bool) -> Option<Map<String, Value>> {
    let mut section = Map::new();
    if let Some(action) = &flags.malicious_code {
        let name = if directional {
            "malicious-code"
        } else {
            "malicious-code-detection"
        };
        section.insert("malicious-code-protection".into(), named(name, action));
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

/// The `data-leak-detection` object of the flags (TS 7.3.0 `buildDataProtection`):
/// written when `--dlp-action`, `--dlp-profiles` or `--[no-]mask-data-inline` is given,
/// with only the fields given.
fn leak_detection(flags: &Flags) -> Option<Map<String, Value>> {
    if flags.dlp_action.is_none() && !flags.dlp_profiles_given && flags.mask_data_inline.is_none() {
        return None;
    }
    let mut object = Map::new();
    if let Some(action) = &flags.dlp_action {
        object.insert("action".into(), json!(action));
    }
    if let Some(profiles) = &flags.dlp_profiles {
        let members: Vec<Value> = profiles.iter().map(|text| json!({"text": text})).collect();
        object.insert("member".into(), Value::Array(members));
    }
    if let Some(mask) = flags.mask_data_inline {
        object.insert("mask-data-inline".into(), json!(mask));
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

/// TS `buildModelConfiguration`: only the sections the flags fill, the shared settings
/// included.
fn model_configuration(flags: &Flags, directional: bool) -> Map<String, Value> {
    let mut config = Map::new();
    if let Some(items) = model_protection(flags) {
        config.insert("model-protection".into(), Value::Array(items));
    }
    if let Some(section) = app_protection(flags, directional) {
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
    if let Some(mask) = flags.mask_data_in_storage {
        config.insert("mask-data-in-storage".into(), json!(mask));
    }
    if let Some(inspect) = flags.enable_full_conversation_inspection {
        config.insert("enable-full-conversation-inspection".into(), json!(inspect));
    }
    config
}

/// The `profiles create` body from flags (TS 7.3.0 `buildProfileRequest`). The caller
/// has checked that a protection or shared-setting flag is present (§13.12).
/// - Without `direction`: one legacy entry, with TypeScript's defaults for the sections
///   the flags left out.
/// - With `direction`: one directional entry (`content-type-mode: per_content_type`)
///   holding the protections under that direction, the other three known directions as
///   empty objects (D335: the service refuses a directional entry that lacks one; TS
///   7.3.0 writes the selected direction only), and the shared settings in
///   `model-configuration`; no defaults are added.
pub fn create_request(name: &str, active: bool, flags: &Flags, direction: Option<&str>) -> Value {
    let entry = match direction {
        Some(direction) => {
            let mut config = model_configuration(flags, true);
            let shared = layout::extract_shared(&mut config);
            let mut directions: Map<String, Value> = layout::DIRECTIONS
                .iter()
                .map(|known| ((*known).to_owned(), json!({})))
                .collect();
            directions.insert(direction.to_owned(), Value::Object(config));
            json!({
                "model-type": "default",
                "content-type-mode": layout::PER_CONTENT_TYPE,
                "model-configuration": Value::Object(shared),
                "content-type-configurations": Value::Object(directions),
            })
        }
        None => {
            let mut config = model_configuration(flags, false);
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
            config.entry("latency").or_insert_with(
                || json!({"inline-timeout-action": "block", "max-inline-latency": 5}),
            );
            config
                .entry("mask-data-in-storage")
                .or_insert_with(|| json!(false));
            json!({"model-type": "default", "model-configuration": Value::Object(config)})
        }
    };
    json!({
        "profile_name": name,
        "active": active,
        "policy": {"ai-security-profiles": [entry]},
    })
}

/// The flags of a `profiles update` (TS 7.3.0 `buildProfileOverrides`): the protection
/// sections (the `malicious-code-protection` item without its `name`, which the merge
/// keeps or sets), the shared settings, and the direction they were built for.
#[derive(Clone, Debug, PartialEq)]
pub struct Patch {
    pub protection: Map<String, Value>,
    pub shared: Map<String, Value>,
    pub direction: Option<&'static str>,
}

impl Patch {
    /// `None` when no protection or shared-setting flag is given.
    pub fn new(flags: &Flags, direction: Option<&'static str>) -> Option<Self> {
        if !flags.any_protection() {
            return None;
        }
        let mut protection = model_configuration(flags, direction.is_some());
        if let Some(Value::Object(item)) = protection
            .get_mut("app-protection")
            .and_then(|section| section.get_mut("malicious-code-protection"))
        {
            item.remove("name");
        }
        let shared = layout::extract_shared(&mut protection);
        Some(Self {
            protection,
            shared,
            direction,
        })
    }
}

/// `profiles update`: TS 7.3.0 `mergeProfilePolicy` of the flags into the read policy
/// (absent is `{}`), §13.17. Exactly one AI entry is selected (never the first of
/// several by guess); its protection block (the legacy `model-configuration`, or the
/// selected direction) is merged recursively with [`layout::merge_settings`], and the
/// shared settings go to the entry's `model-configuration`. Every other entry,
/// direction, detector and key is kept as read. Without a patch the policy is returned
/// as read, after the selector's layout checks. A layout refusal is a usage error.
pub fn merge(
    existing: Option<Value>,
    patch: Option<&Patch>,
    selector: &Selector,
) -> Result<Value, CliError> {
    let mut policy = match existing {
        Some(Value::Object(policy)) => policy,
        _ => Map::new(),
    };
    let Some(patch) = patch else {
        if selector.is_given() {
            let mut probe = policy.clone();
            let index = layout::select_ai_profile(&mut probe, selector)?;
            if let Some(direction) = selector.direction {
                let mut entry = layout::entry_mut(&mut probe, index).clone();
                layout::select_protections(&mut entry, Some(direction), true)?;
            }
        }
        return Ok(Value::Object(policy));
    };
    let index = layout::select_ai_profile(&mut policy, selector)?;
    let direction = patch.direction.or(selector.direction);
    if direction.is_some() || !patch.protection.is_empty() {
        let entry = layout::entry_mut(&mut policy, index);
        if patch.protection.is_empty() {
            // A shared-only edit with a direction checks the layout; nothing is inserted.
            let mut probe = entry.clone();
            layout::select_protections(&mut probe, direction, true)?;
        } else {
            let target = layout::select_protections(entry, direction, false)?;
            layout::merge_settings(target, &patch.protection)?;
        }
    }
    if !patch.shared.is_empty() {
        let entry = layout::entry_mut(&mut policy, index);
        layout::merge_settings(layout::shared_settings(entry), &patch.shared)?;
    }
    Ok(Value::Object(policy))
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

/// Whether a protection block holds a ref of the topic in any `topic-guardrails` item.
fn holds(configuration: &Map<String, Value>, topic: TopicIdentity<'_>) -> bool {
    configuration
        .get("model-protection")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("name").and_then(Value::as_str) == Some(GUARDRAIL))
        .filter_map(|item| item.get("topic-list").and_then(Value::as_array))
        .any(|groups| !ref_positions(groups, topic).is_empty())
}

/// The selected protection block of a topic edit (TS 7.3.0 `assignTopicsToProfile`):
/// the selector's entry and block under the §13.17 layout rules, with at most one
/// `topic-guardrails` item.
fn guarded_block<'a>(
    policy: &'a mut Map<String, Value>,
    selector: &Selector,
) -> Result<&'a mut Map<String, Value>, CliError> {
    let index = layout::select_ai_profile(policy, selector)?;
    let block =
        layout::select_protections(layout::entry_mut(policy, index), selector.direction, false)?;
    let guardrails = block
        .get("model-protection")
        .and_then(Value::as_array)
        .map_or(0, |items| {
            items
                .iter()
                .filter(|item| item.get("name").and_then(Value::as_str) == Some(GUARDRAIL))
                .count()
        });
    if guardrails > 1 {
        return Err(CliError::usage(
            "Ambiguous topic-guardrails identity in selected protection section",
        ));
    }
    Ok(block)
}

/// `topics apply` (§13.4, §13.17): the policy with `new_ref` (the resolved revision's
/// ref) under the `intent` group of the selected block's topic guardrails. Every other
/// ref, group, block, direction and key is kept as read (D98); the item's `action`
/// follows TypeScript's rule. A layout refusal is a usage error.
pub fn apply_topic(
    policy: Option<Value>,
    selector: &Selector,
    topic: TopicIdentity<'_>,
    new_ref: Value,
    intent: &str,
) -> Result<Value, CliError> {
    let mut policy = match policy {
        Some(Value::Object(policy)) => policy,
        _ => Map::new(),
    };
    let guard_action = if intent == "block" { "allow" } else { "block" };
    let config = guarded_block(&mut policy, selector)?;
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
    Ok(Value::Object(policy))
}

/// `topics revert` (§13.4, §13.17): the policy without the topic's refs in the selected
/// block. Refused (usage errors, nothing written or deleted):
/// - with a selector, the selector's layout checks first;
/// - the topic has no ref in scope (the selected block, or without a selector every
///   active block): `Topic "<name>" is not assigned to the selected protection section`;
/// - with a selector, another block (another direction, another entry or a retained
///   inactive `model-configuration`) still holds a ref of it;
/// - the selection of the write itself (several entries, or a directional entry,
///   without a selector).
///
/// Groups the removal empties are removed; when no ref remains the guardrail item
/// itself is removed (D99), otherwise its `action` follows TypeScript's rule.
pub fn revert_topic(
    policy: Option<&Value>,
    selector: &Selector,
    topic: TopicIdentity<'_>,
) -> Result<Value, CliError> {
    let mut map = match policy {
        Some(Value::Object(policy)) => policy.clone(),
        _ => Map::new(),
    };
    let selected = if selector.is_given() {
        let mut probe = map.clone();
        let index = layout::select_ai_profile(&mut probe, selector)?;
        let mut entry = layout::entry_mut(&mut probe, index).clone();
        layout::select_protections(&mut entry, selector.direction, false)?;
        Some(layout::Place {
            index,
            direction: selector.direction.map(str::to_owned),
        })
    } else {
        None
    };
    let read = Value::Object(map.clone());
    let found = layout::locations(Some(&read));
    let in_scope = found.iter().any(|location| {
        let scoped = match &selected {
            Some(place) => &location.place == place,
            None => location.active,
        };
        scoped && holds(location.configuration, topic)
    });
    if !in_scope {
        return Err(CliError::usage(format!(
            "Topic \"{}\" is not assigned to the selected protection section",
            topic.name
        )));
    }
    if let Some(place) = &selected
        && found
            .iter()
            .any(|location| &location.place != place && holds(location.configuration, topic))
    {
        return Err(CliError::usage(
            "Topic is referenced in another direction or AI entry; detach those references before reverting and deleting",
        ));
    }
    let config = guarded_block(&mut map, selector)?;
    let Some(Value::Array(items)) = config.get_mut("model-protection") else {
        unreachable!("the block holds the topic's refs")
    };
    let index = guardrail_index(items).expect("the block holds the topic's refs");
    let Some(Value::Array(groups)) = items[index].get_mut("topic-list") else {
        unreachable!("the guardrail holds the topic's refs")
    };
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
    Ok(Value::Object(map))
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

    fn none() -> Selector {
        Selector::default()
    }

    fn dir(direction: &'static str) -> Selector {
        Selector {
            direction: Some(direction),
            ai_profile_index: None,
        }
    }

    fn usage(message: &str) -> Result<Value, CliError> {
        Err(CliError::usage(message))
    }

    /// The TypeScript 7.3.0 directional fixture (`tests/fixtures/directional-security-profile.json`).
    fn directional() -> Value {
        airs_test_harness::fixtures::runtime::directional_profile()["policy"].clone()
    }

    /// scm-sdk 0.2.4's typed request (§15.25): a body validated with [`REQUEST_SCHEMA`]
    /// keeps a string `dlp_tenant_id`, an explicit `false` (`Optional::Value(false)`), an
    /// omitted setting (`Optional::Unset`), every direction and an unknown direction key,
    /// and serialises back to the same document. The 0.35.0 root refuses `null` and wrong
    /// types of the new fields, which the model's own 0.34.0 binding would let through.
    #[test]
    fn request_bodies_keep_the_directional_fields_as_given() {
        use scm::data::Optional;
        let mut body = airs_test_harness::fixtures::runtime::directional_profile();
        body["policy"]["ai-security-profiles"][0]["content-type-configurations"]["audio"] =
            json!({"future-setting": [1]});
        body["policy"]["ai-security-profiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({"model-type": "legacy", "model-configuration": {"mask-data-in-storage": true}}));
        let typed = request_body(body.clone()).expect("a valid body");
        assert_eq!(
            typed.dlp_tenant_id,
            Optional::Value("8259670718644550000".to_owned())
        );
        let entries = typed
            .policy
            .ai_security_profiles
            .as_ref()
            .into_option()
            .unwrap();
        let shared = |at: usize| {
            entries[at]
                .model_configuration
                .as_ref()
                .into_option()
                .unwrap()
                .enable_full_conversation_inspection
                .clone()
        };
        assert_eq!(shared(0), Optional::Value(false));
        assert_eq!(shared(1), Optional::Unset);
        assert_eq!(
            entries[0].content_type_mode,
            Optional::Value("per_content_type".to_owned())
        );
        let directions = entries[0]
            .content_type_configurations
            .as_ref()
            .into_option()
            .unwrap();
        for direction in [
            &directions.prompt,
            &directions.response,
            &directions.tool_call,
            &directions.tool_response,
        ] {
            assert!(!direction.is_unset());
        }
        assert_eq!(
            directions
                .extensions
                .get("audio")
                .map(scm::data::JsonValue::as_value),
            Some(&json!({"future-setting": [1]}))
        );
        assert!(entries[1].content_type_configurations.is_unset());
        assert_eq!(serde_json::to_value(&typed).unwrap(), body);

        for (pointer, bad) in [
            ("/dlp_tenant_id", json!(1)),
            ("/dlp_tenant_id", Value::Null),
            (
                "/policy/ai-security-profiles/0/content-type-mode",
                Value::Null,
            ),
            (
                "/policy/ai-security-profiles/0/content-type-configurations/response",
                Value::Null,
            ),
            (
                "/policy/ai-security-profiles/0/model-configuration/enable-full-conversation-inspection",
                json!("true"),
            ),
        ] {
            let mut invalid = airs_test_harness::fixtures::runtime::directional_profile();
            *invalid.pointer_mut(pointer).unwrap() = bad.clone();
            assert!(request_body(invalid.clone()).is_none(), "{pointer} = {bad}");
            assert!(
                scm::airs::management::models::CreateSecurityProfileRequest::parse(
                    invalid,
                    scm::validation::Mode::Request
                )
                .is_ok(),
                "the model's 0.34.0 binding accepts {pointer} = {bad}: keep the 0.35.0 root"
            );
        }
    }

    #[test]
    fn latency_must_be_a_decimal_integer() {
        for bad in [
            "",
            "1.5",
            "abc",
            "-1",
            "1e3",
            "0x10",
            "9007199254740993",
            "NaN",
            "5garbage",
        ] {
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
    fn flag_presence_follows_typescript_7_3() {
        let empty = flags(|raw| raw.prompt_injection = Some(String::new()));
        assert!(!empty.any_protection(), "an empty action is absent");
        assert!(Flags::raw_any(&PolicyFlags {
            prompt_injection: Some(String::new()),
            ..PolicyFlags::default()
        }));
        assert!(!Flags::raw_any(&PolicyFlags::default()));
        // --dlp-action and --dlp-profiles count when given at all.
        let action = flags(|raw| raw.dlp_action = Some(String::new()));
        assert!(action.any_protection());
        assert!(!action.dlp_without_action());
        let profiles = flags(|raw| raw.dlp_profiles = Some(String::new()));
        assert!(profiles.any_protection());
        assert!(profiles.dlp_without_action());
        assert_eq!(profiles.dlp_profiles, None);
        let listed = flags(|raw| raw.dlp_profiles = Some(" a , ,b ".into()));
        assert_eq!(listed.dlp_profiles, Some(vec!["a".into(), "b".into()]));
        // The negative booleans are given values.
        for (edit, check) in [
            (
                (|raw: &mut PolicyFlags| raw.no_mask_data_inline = true) as fn(&mut PolicyFlags),
                (|flags: &Flags| flags.mask_data_inline == Some(false)) as fn(&Flags) -> bool,
            ),
            (
                |raw| raw.no_mask_data_in_storage = true,
                |flags| flags.mask_data_in_storage == Some(false),
            ),
            (
                |raw| raw.no_enable_full_conversation_inspection = true,
                |flags| flags.enable_full_conversation_inspection == Some(false),
            ),
            (
                |raw| raw.enable_full_conversation_inspection = true,
                |flags| flags.enable_full_conversation_inspection == Some(true),
            ),
        ] {
            let read = flags(edit);
            assert!(read.any_protection());
            assert!(check(&read));
            let mut raw = PolicyFlags::default();
            edit(&mut raw);
            assert!(Flags::raw_any(&raw));
        }
        assert!(flags(|raw| raw.no_mask_data_inline = true).dlp_without_action());
    }

    #[test]
    fn create_request_matches_the_typescript_builder() {
        let body = create_request(
            "p",
            true,
            &flags(|raw| raw.prompt_injection = Some("block".into())),
            None,
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
        assert!(request_body(body).is_some());
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
                raw.no_enable_full_conversation_inspection = true;
            }),
            None,
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
                "mask-data-in-storage": true,
                "enable-full-conversation-inspection": false
            })
        );
        assert_eq!(every["active"], json!(false));
        assert!(request_body(every).is_some());
        let unmasked = create_request(
            "s",
            true,
            &flags(|raw| {
                raw.prompt_injection = Some("block".into());
                raw.no_mask_data_in_storage = true;
            }),
            None,
        );
        assert_eq!(
            unmasked["policy"]["ai-security-profiles"][0]["model-configuration"]["mask-data-in-storage"],
            json!(false)
        );
    }

    /// D335: the flags fill the selected direction and the other three known directions
    /// are written empty (the service refuses a directional entry without all four).
    #[test]
    fn directional_create_fills_one_direction_and_writes_the_others_empty() {
        let request = create_request(
            "Directional",
            true,
            &flags(|raw| {
                raw.prompt_injection = Some("block".into());
                raw.no_enable_full_conversation_inspection = true;
            }),
            Some("tool-call"),
        );
        assert_eq!(
            request["policy"]["ai-security-profiles"][0],
            json!({
                "model-type": "default",
                "content-type-mode": "per_content_type",
                "model-configuration": {"enable-full-conversation-inspection": false},
                "content-type-configurations": {
                    "prompt": {},
                    "response": {},
                    "tool-call": {"model-protection": [{"name": "prompt-injection", "action": "block"}]},
                    "tool-response": {}
                }
            })
        );
        assert!(request_body(request).is_some());
        // Each of the four directions under its exact wire key, the others empty (the
        // shared settings an empty `model-configuration`, as TS 7.3.0 builds it).
        for direction in ["prompt", "response", "tool-call", "tool-response"] {
            let request = create_request(
                "Directional",
                true,
                &flags(|raw| raw.prompt_injection = Some("alert".into())),
                Some(direction),
            );
            let entry = &request["policy"]["ai-security-profiles"][0];
            let mut expected =
                json!({"prompt": {}, "response": {}, "tool-call": {}, "tool-response": {}});
            expected[direction] =
                json!({"model-protection": [{"name": "prompt-injection", "action": "alert"}]});
            assert_eq!(
                entry["content-type-configurations"], expected,
                "{direction}"
            );
            assert_eq!(entry["model-configuration"], json!({}), "{direction}");
            let typed = request_body(request.clone()).expect("a valid body");
            assert_eq!(
                serde_json::to_value(&typed).unwrap(),
                request,
                "{direction}"
            );
        }
        let malicious = create_request(
            "Directional",
            true,
            &flags(|raw| {
                raw.malicious_code = Some("block".into());
                raw.max_inline_latency = Some("8".into());
            }),
            Some("prompt"),
        );
        let entry = &malicious["policy"]["ai-security-profiles"][0];
        assert_eq!(
            entry["content-type-configurations"]["prompt"]["app-protection"]["malicious-code-protection"]
                ["name"],
            "malicious-code"
        );
        assert_eq!(
            entry["model-configuration"],
            json!({"latency": {"max-inline-latency": 8}})
        );
    }

    fn patch(direction: Option<&'static str>, edit: impl FnOnce(&mut PolicyFlags)) -> Patch {
        Patch::new(&flags(edit), direction).unwrap()
    }

    #[test]
    fn legacy_merge_keeps_everything_the_flags_do_not_change() {
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
                        "database-security": [{"name": "database-security-read", "action": "block", "severity": "low"}]
                    },
                    "latency": {"inline-timeout-action": "block", "max-inline-latency": 5},
                    "x-unknown": {"kept": 1.0}
                }
            }],
            "dlp-data-profiles": [{"name": "PII"}]
        });
        let merged = merge(
            Some(existing.clone()),
            Some(&patch(None, |raw| {
                raw.prompt_injection = Some("block".into());
                raw.contextual_grounding = Some("alert".into());
                raw.url_action = Some("alert".into());
                raw.dlp_action = Some("block".into());
                raw.db_security_read = Some("allow".into());
                raw.db_security_delete = Some("block".into());
                raw.max_inline_latency = Some("9".into());
                raw.malicious_code = Some("block".into());
            })),
            &none(),
        )
        .unwrap();
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
            json!({"url-detected-action": "alert", "default-url-category": {"member": ["malicious"]},
                "malicious-code-protection": {"action": "block", "name": "malicious-code"}}),
            "the update merge names a new malicious-code item `malicious-code` (TS 7.3.0)"
        );
        // Only the action changes; the DLP profiles and the mask stay (D117 retired: 7.3.0 matches).
        assert_eq!(
            config["data-protection"]["data-leak-detection"],
            json!({"action": "block", "member": [{"text": "PII"}], "mask-data-inline": true})
        );
        assert_eq!(
            config["data-protection"]["database-security"],
            json!([
                {"name": "database-security-read", "action": "allow", "severity": "low"},
                {"name": "database-security-delete", "action": "block"}
            ])
        );
        assert_eq!(
            config["latency"],
            json!({"inline-timeout-action": "block", "max-inline-latency": 9})
        );
        assert_eq!(config["x-unknown"], json!({"kept": 1.0}));
        assert_eq!(merged["dlp-data-profiles"], existing["dlp-data-profiles"]);
        // No patch: the policy as read.
        assert_eq!(
            merge(Some(existing.clone()), None, &none()).unwrap(),
            existing
        );
        assert_eq!(merge(None, None, &none()).unwrap(), json!({}));
    }

    #[test]
    fn merge_creates_the_first_entry_when_absent_or_empty() {
        let only = patch(None, |raw| raw.prompt_injection = Some("block".into()));
        let expected = json!({"ai-security-profiles": [{
            "model-type": "default",
            "model-configuration": {"model-protection": [{"name": "prompt-injection", "action": "block"}]}
        }]});
        assert_eq!(merge(None, Some(&only), &none()).unwrap(), expected);
        assert_eq!(
            merge(
                Some(json!({"ai-security-profiles": []})),
                Some(&only),
                &none()
            )
            .unwrap(),
            expected,
            "an empty array is treated as absent (D115)"
        );
        assert_eq!(
            merge(
                Some(json!({"ai-security-profiles": [{"model-type": "default"}]})),
                Some(&only),
                &none()
            )
            .unwrap(),
            expected
        );
        let masking = patch(None, |raw| raw.no_mask_data_inline = true);
        assert_eq!(
            merge(
                Some(
                    json!({"ai-security-profiles": [{"model-type": "default", "model-configuration": {
                        "data-protection": {"data-leak-detection": {"action": "alert", "member": [{"text": "B"}]}}
                    }}]})
                ),
                Some(&masking),
                &none()
            )
            .unwrap()["ai-security-profiles"][0]["model-configuration"]["data-protection"],
            json!({"data-leak-detection": {"action": "alert", "member": [{"text": "B"}], "mask-data-inline": false}}),
            "masking changes alone, without --dlp-action"
        );
    }

    #[test]
    fn directional_merge_edits_one_direction_and_keeps_the_rest() {
        for direction in layout::DIRECTIONS {
            let before = directional();
            let result = merge(
                Some(before.clone()),
                Some(&patch(Some(direction), |raw| {
                    raw.toxic_content = Some("high:alert, moderate:block".into());
                    raw.malicious_code = Some("alert".into());
                    raw.dlp_action = Some("allow".into());
                    raw.db_security_read = Some("alert".into());
                })),
                &dir(direction),
            )
            .unwrap();
            let configs = &result["ai-security-profiles"][0]["content-type-configurations"];
            let prior = &before["ai-security-profiles"][0]["content-type-configurations"];
            for other in layout::DIRECTIONS
                .iter()
                .filter(|other| **other != direction)
            {
                assert_eq!(configs[*other], prior[*other], "{direction}: {other}");
            }
            let selected = &configs[direction];
            let toxic = selected["model-protection"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["name"] == "toxic-content")
                .unwrap();
            assert_eq!(toxic["action"], "high:alert, moderate:block");
            assert_eq!(
                toxic["severity-by-confidence"],
                json!({"high": "medium", "moderate": "low"})
            );
            assert_eq!(
                selected["app-protection"]["malicious-code-protection"],
                json!({"name": "malicious-code", "action": "alert", "severity": "high"})
            );
            assert_eq!(
                selected["data-protection"]["data-leak-detection"]["member"],
                prior[direction]["data-protection"]["data-leak-detection"]["member"]
            );
            assert_eq!(
                result["ai-security-profiles"][0]["model-configuration"],
                before["ai-security-profiles"][0]["model-configuration"]
            );
        }
        let masked = merge(
            Some(directional()),
            Some(&patch(Some("response"), |raw| {
                raw.no_mask_data_inline = true
            })),
            &dir("response"),
        )
        .unwrap();
        let mut expected = directional()["ai-security-profiles"][0]["content-type-configurations"]
            ["response"]["data-protection"]["data-leak-detection"]
            .clone();
        expected["mask-data-inline"] = json!(false);
        assert_eq!(
            masked["ai-security-profiles"][0]["content-type-configurations"]["response"]["data-protection"]
                ["data-leak-detection"],
            expected
        );
    }

    #[test]
    fn shared_edits_preserve_every_direction() {
        let mut base = directional();
        base["ai-security-profiles"][0]["content-type-configurations"]["future-direction"] =
            json!({"enabled": true});
        let result = merge(
            Some(base.clone()),
            Some(&patch(None, |raw| {
                raw.max_inline_latency = Some("12".into());
                raw.no_mask_data_in_storage = true;
                raw.no_enable_full_conversation_inspection = true;
            })),
            &none(),
        )
        .unwrap();
        assert_eq!(
            result["ai-security-profiles"][0]["content-type-configurations"],
            base["ai-security-profiles"][0]["content-type-configurations"]
        );
        assert_eq!(
            result["ai-security-profiles"][0]["model-configuration"],
            json!({"enable-full-conversation-inspection": false, "mask-data-in-storage": false,
                "latency": {"inline-timeout-action": "block", "max-inline-latency": 12}})
        );
        // A shared edit with an absent direction selected inserts nothing.
        let mut absent = directional();
        absent["ai-security-profiles"][0]["content-type-configurations"]
            .as_object_mut()
            .unwrap()
            .remove("response");
        let result = merge(
            Some(absent.clone()),
            Some(&patch(Some("response"), |raw| {
                raw.mask_data_in_storage = true
            })),
            &dir("response"),
        )
        .unwrap();
        assert_eq!(
            result["ai-security-profiles"][0]["content-type-configurations"],
            absent["ai-security-profiles"][0]["content-type-configurations"]
        );
        assert_eq!(
            result["ai-security-profiles"][0]["model-configuration"]["mask-data-in-storage"],
            json!(true)
        );
    }

    #[test]
    fn merge_refuses_ambiguous_layouts() {
        let toxic = |direction| patch(direction, |raw| raw.toxic_content = Some("alert".into()));
        assert_eq!(
            merge(Some(directional()), Some(&toxic(None)), &none()),
            usage("Directional protection edits require --direction")
        );
        let legacy = json!({"ai-security-profiles": [{"model-configuration": {}}]});
        let legacy_text = "A legacy profile cannot be converted by --direction; use a complete --config replacement";
        assert_eq!(
            merge(
                Some(legacy.clone()),
                Some(&toxic(Some("response"))),
                &dir("response")
            ),
            usage(legacy_text)
        );
        assert_eq!(
            merge(Some(legacy), None, &dir("response")),
            usage(legacy_text)
        );
        let mut multi = directional();
        multi["ai-security-profiles"].as_array_mut().unwrap().insert(
            0,
            json!({"model-type": "other", "model-configuration": {"model-protection": [{"name": "other", "action": "allow"}]}}),
        );
        assert_eq!(
            merge(
                Some(multi.clone()),
                Some(&toxic(Some("response"))),
                &dir("response")
            ),
            usage("Multiple AI profile entries: specify --ai-profile-index or use --config")
        );
        let second = Selector {
            direction: Some("response"),
            ai_profile_index: Some(1),
        };
        let result = merge(Some(multi.clone()), Some(&toxic(Some("response"))), &second).unwrap();
        assert_eq!(
            result["ai-security-profiles"][0],
            multi["ai-security-profiles"][0]
        );
        let mut absent = directional();
        absent["ai-security-profiles"][0]["content-type-configurations"]
            .as_object_mut()
            .unwrap()
            .remove("response");
        assert_eq!(
            merge(
                Some(absent),
                Some(&toxic(Some("response"))),
                &dir("response")
            ),
            usage(
                "Selected direction is absent; add it with a complete --config replacement before editing protections or topics"
            )
        );
        let first = Selector {
            direction: None,
            ai_profile_index: Some(0),
        };
        assert_eq!(
            merge(Some(json!({})), Some(&toxic(None)), &first),
            usage("--ai-profile-index does not identify an existing AI profile entry")
        );
        let mut unknown = directional();
        unknown["ai-security-profiles"][0]["content-type-mode"] = json!("future_mode");
        let kept = merge(
            Some(unknown.clone()),
            Some(&patch(None, |raw| {
                raw.max_inline_latency = Some("7".into())
            })),
            &none(),
        )
        .unwrap();
        assert_eq!(
            kept["ai-security-profiles"][0]["content-type-mode"], "future_mode",
            "an unknown mode is retained by shared edits"
        );
        assert_eq!(
            merge(Some(unknown), Some(&toxic(Some("prompt"))), &dir("prompt")),
            usage("Unknown content-type-mode: use a complete --config replacement")
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
                apply_topic(policy, &none(), topic, new_ref.clone(), "block").unwrap(),
                json!({"ai-security-profiles": [{"model-type": "default", "model-configuration": {
                    "model-protection": [{"name": "topic-guardrails", "action": "allow", "options": [],
                        "topic-list": [{"action": "block", "topic": [new_ref.clone()]}]}]
                }}]})
            );
        }
        let allowed = apply_topic(None, &none(), topic, new_ref.clone(), "allow").unwrap();
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
        let after = apply_topic(
            Some(policy.clone()),
            &none(),
            topic,
            new_ref.clone(),
            "block",
        )
        .unwrap();
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
        let moved = apply_topic(Some(policy), &none(), topic, new_ref.clone(), "allow").unwrap();
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
            groups_of(&apply_topic(Some(twice), &none(), topic, new_ref.clone(), "block").unwrap()),
            json!([{"action": "block", "topic": [other, new_ref.clone()]}, {"action": "block", "topic": []}]),
            "duplicate refs are removed, emptied groups dropped, the first intent group gets the ref"
        );
        let same = guarded(json!([{"action": "block", "topic": [new_ref.clone()]}]));
        assert_eq!(
            apply_topic(Some(same.clone()), &none(), topic, new_ref, "block").unwrap(),
            same,
            "re-applying changes nothing"
        );
    }

    #[test]
    fn apply_edits_only_the_selected_direction() {
        let known = ids(&["T1"]);
        let topic = TopicIdentity {
            name: "Restricted",
            ids: &known,
        };
        let new_ref = json!({"topic_id": "T1", "topic_name": "Restricted", "revision": 3});
        let before = directional();
        let after = apply_topic(
            Some(before.clone()),
            &dir("response"),
            topic,
            new_ref.clone(),
            "block",
        )
        .unwrap();
        let configs = &after["ai-security-profiles"][0]["content-type-configurations"];
        assert_eq!(
            configs["response"]["model-protection"]
                .as_array()
                .unwrap()
                .last(),
            Some(
                &json!({"name": "topic-guardrails", "action": "allow", "options": [],
                "topic-list": [{"action": "block", "topic": [new_ref.clone()]}]})
            )
        );
        for other in ["prompt", "tool-call", "tool-response"] {
            assert_eq!(
                configs[other],
                before["ai-security-profiles"][0]["content-type-configurations"][other]
            );
        }
        assert_eq!(
            apply_topic(
                Some(before.clone()),
                &none(),
                topic,
                new_ref.clone(),
                "block"
            ),
            usage("Directional protection edits require --direction")
        );
        let mut absent = before.clone();
        absent["ai-security-profiles"][0]["content-type-configurations"]
            .as_object_mut()
            .unwrap()
            .remove("tool-response");
        assert_eq!(
            apply_topic(
                Some(absent),
                &dir("tool-response"),
                topic,
                new_ref.clone(),
                "block"
            ),
            usage(
                "Selected direction is absent; add it with a complete --config replacement before editing protections or topics"
            )
        );
        let mut doubled = before;
        doubled["ai-security-profiles"][0]["content-type-configurations"]["prompt"]["model-protection"] = json!([
            {"name": "topic-guardrails", "topic-list": []}, {"name": "topic-guardrails", "topic-list": []}
        ]);
        assert_eq!(
            apply_topic(Some(doubled), &dir("prompt"), topic, new_ref, "block"),
            usage("Ambiguous topic-guardrails identity in selected protection section")
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
        let unassigned = "Topic \"fin\" is not assigned to the selected protection section";
        assert_eq!(revert_topic(None, &none(), topic), usage(unassigned));
        assert_eq!(
            revert_topic(Some(&json!({})), &none(), topic),
            usage(unassigned)
        );
        let unrelated = guarded(json!([{"action": "block", "topic": [other.clone()]}]));
        assert_eq!(
            revert_topic(Some(&unrelated), &none(), topic),
            usage(unassigned)
        );
        let mixed = guarded(json!([
            {"action": "allow", "topic": [other.clone()]},
            {"action": "block", "topic": [{"topic_id": "T1", "topic_name": "renamed"}]}
        ]));
        let after = revert_topic(Some(&mixed), &none(), topic).unwrap();
        assert_eq!(
            groups_of(&after),
            json!([{"action": "allow", "topic": [other.clone()]}])
        );
        assert_eq!(item_of(&after)["action"], "block", "no block refs remain");
        let blocks = guarded(json!([
            {"action": "block", "topic": [other.clone(), {"topic_name": "fin"}]}
        ]));
        let after = revert_topic(Some(&blocks), &none(), topic).unwrap();
        assert_eq!(
            groups_of(&after),
            json!([{"action": "block", "topic": [other]}])
        );
        assert_eq!(item_of(&after)["action"], "allow");
        let last = guarded(
            json!([{"action": "block", "topic": [{"topic_name": "fin"}]}, {"action": "allow", "topic": []}]),
        );
        let after = revert_topic(Some(&last), &none(), topic).unwrap();
        assert_eq!(
            after["ai-security-profiles"][0]["model-configuration"]["model-protection"],
            json!([{"name": "prompt-injection", "action": "alert"}]),
            "the guardrail item goes with its last ref"
        );
        assert_eq!(after["x-policy"], 1.5);
    }

    #[test]
    fn revert_refuses_references_outside_the_selected_direction() {
        let known = ids(&["T1"]);
        let topic = TopicIdentity {
            name: "Restricted",
            ids: &known,
        };
        let guardrail = json!({"name": "topic-guardrails", "action": "allow", "topic-list": [
            {"action": "block", "topic": [{"topic_id": "T1", "topic_name": "Restricted", "revision": 3}]}
        ]});
        let with = |directions: &[&str], legacy: bool| {
            let mut policy = directional();
            let entry = &mut policy["ai-security-profiles"][0];
            for direction in directions {
                entry["content-type-configurations"][*direction]["model-protection"]
                    .as_array_mut()
                    .unwrap()
                    .push(guardrail.clone());
            }
            if legacy {
                entry["model-configuration"]["model-protection"] = json!([guardrail.clone()]);
            }
            policy
        };
        let one = with(&["response"], false);
        let after = revert_topic(Some(&one), &dir("response"), topic).unwrap();
        assert_eq!(after, directional(), "the item goes with its last ref");
        let referenced = "Topic is referenced in another direction or AI entry; detach those references before reverting and deleting";
        assert_eq!(
            revert_topic(
                Some(&with(&["prompt", "response"], false)),
                &dir("response"),
                topic
            ),
            usage(referenced)
        );
        assert_eq!(
            revert_topic(Some(&with(&["response"], true)), &dir("response"), topic),
            usage(referenced),
            "a retained inactive legacy block counts"
        );
        assert_eq!(
            revert_topic(Some(&one), &dir("prompt"), topic),
            usage("Topic \"Restricted\" is not assigned to the selected protection section")
        );
        assert_eq!(
            revert_topic(Some(&one), &none(), topic),
            usage("Directional protection edits require --direction")
        );
        let mut absent = one.clone();
        absent["ai-security-profiles"][0]["content-type-configurations"]
            .as_object_mut()
            .unwrap()
            .remove("tool-response");
        assert_eq!(
            revert_topic(Some(&absent), &dir("tool-response"), topic),
            usage(
                "Selected direction is absent; add it with a complete --config replacement before editing protections or topics"
            )
        );
        let legacy = guarded(json!([{"action": "block", "topic": [{"topic_name": "Restricted"}]}]));
        assert_eq!(
            revert_topic(Some(&legacy), &dir("prompt"), topic),
            usage(
                "A legacy profile cannot be converted by --direction; use a complete --config replacement"
            )
        );
    }
}
