//! The TypeScript profile-transfer rules (`src/backup/runtime-profiles.ts`, DESIGN §18.15,
//! §18.16), pure and unit-tested without I/O: the inventory walk's page checks
//! (`offsetPages`), `latestProfiles`, `assertTenant`, `topicReferences`, `dlpReferences`,
//! `basicFallback`, `assertKnownPolicyReferences`, `sameTopic`, `canonicalPolicy`,
//! `unchanged` and `mappedPolicy`, and the restore planner as stages between the reads
//! the command makes (`prepare`, `plan_profiles`, `plan_topics`, `dlp_names`,
//! `finish`).
//!
//! Records are `serde_json::Value`s of the SDK models re-serialised without response
//! defaults (G27). Messages are TypeScript's; names in them are raw here and pass
//! `terminal_safe` where they are printed. The rules a restore also runs while it writes
//! (the inventory walk, `latestProfiles`, `assertTenant`, the reference walks and
//! `mappedPolicy`) refuse with a [`Refusal`] that says whether the restore result states
//! the message or the generic stop (TS `result.error`, D217).

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value, json};

use super::policy::{self, strict_eq};
use crate::dlp::backup::retired_profile;
use crate::json::OValue;
use crate::json::{PathStep, at_path};
use crate::tenant::config::js_trim;

/// The safety limit of one inventory (TS).
pub const MAX_INVENTORY: usize = 10_000;
/// The page size of the inventory walks (TS).
pub const PAGE_LIMIT: u32 = 100;
/// The largest safe JavaScript integer.
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// A rule's refusal, typed by what a restore that stops on it during execution reports as
/// `result.error` (TS keeps its own inventory, destination, verification and mapping
/// messages and replaces every other local failure with the generic stop, D217). Before
/// the first write both are the planning error's text alike.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A message the restore result states as it is (TS: `Destination…`, `Inventory…`,
    /// `Missing planned…`, the DLP inventory's messages).
    Stated(String),
    /// A local rule the restore result replaces with the generic stop.
    Withheld(String),
}

impl Refusal {
    /// The message, whichever the kind.
    pub fn message(&self) -> &str {
        match self {
            Self::Stated(message) | Self::Withheld(message) => message,
        }
    }

    /// The message the restore result states, if this kind is stated.
    pub fn stated(&self) -> Option<&str> {
        match self {
            Self::Stated(message) => Some(message),
            Self::Withheld(_) => None,
        }
    }
}

/// The planner stages report plain messages.
impl From<Refusal> for String {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Stated(message) | Refusal::Withheld(message) => message,
        }
    }
}

// ---------------------------------------------------------------------------
// The inventory walk (TS `offsetPages`)
// ---------------------------------------------------------------------------

/// The two offset-paged inventories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Collection {
    Profiles,
    Topics,
}

impl Collection {
    /// The answer's array key.
    pub fn key(self) -> &'static str {
        match self {
            Self::Profiles => "ai_profiles",
            Self::Topics => "custom_topics",
        }
    }

    /// The words of the D218 messages.
    pub fn label(self) -> &'static str {
        match self {
            Self::Profiles => "security profiles",
            Self::Topics => "custom topics",
        }
    }
}

/// Whether a walk needs another page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Read the page at this offset next.
    Next(u64),
    Done,
}

/// One inventory walk: pages from offset 0, at most `max_pages` of them and
/// [`MAX_INVENTORY`] records; `next_offset` absent or 0 ends it. An answer without the
/// collection is `absent` (D218: never an empty inventory).
#[derive(Debug)]
pub struct OffsetWalk {
    collection: Collection,
    absent: String,
    max_pages: u64,
    pages: u64,
    offset: u64,
    items: Vec<OValue>,
}

/// TS `Inventory is incomplete: …`.
pub const INCOMPLETE: &str =
    "Inventory is incomplete: increase --max-pages before exporting or restoring";

impl OffsetWalk {
    /// A walk of `collection`; `absent` is the message of an answer without it (stated:
    /// the restore's own D218 text).
    pub fn new(collection: Collection, max_pages: u64, absent: String) -> Self {
        Self {
            collection,
            absent,
            max_pages,
            pages: 0,
            offset: 0,
            items: Vec::new(),
        }
    }

    /// The offset of the first page.
    pub fn start(&self) -> u64 {
        0
    }

    /// The records read so far.
    pub fn into_items(self) -> Vec<OValue> {
        self.items
    }

    /// Checks one page (its answer as ordered JSON) and keeps its rows.
    pub fn accept(&mut self, answer: &OValue) -> Result<Step, Refusal> {
        let Some(OValue::Array(rows)) = answer.get(self.collection.key()) else {
            return Err(Refusal::Stated(self.absent.clone()));
        };
        self.pages += 1;
        self.items.extend(rows.iter().cloned());
        if self.items.len() > MAX_INVENTORY {
            return Err(Refusal::Stated(format!(
                "Inventory exceeds the {MAX_INVENTORY}-record safety limit"
            )));
        }
        let next = match answer.get("next_offset") {
            None => return Ok(Step::Done),
            Some(OValue::Number(number)) => number.as_f64(),
            Some(_) => None,
        };
        if next == Some(0.0) {
            return Ok(Step::Done);
        }
        let advance = match next {
            Some(next) if next.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&next) => {
                // A safe integer (checked above), so the conversion is exact.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let next = next as u64;
                (!rows.is_empty() && next > self.offset).then_some(next)
            }
            _ => None,
        };
        let Some(next) = advance else {
            return Err(Refusal::Stated(
                "Inventory pagination did not advance".to_owned(),
            ));
        };
        if self.pages >= self.max_pages {
            return Err(Refusal::Stated(INCOMPLETE.to_owned()));
        }
        self.offset = next;
        Ok(Step::Next(next))
    }
}

// ---------------------------------------------------------------------------
// Record rules
// ---------------------------------------------------------------------------

/// TS `assertName`.
pub const NAME_RULE: &str =
    "Profile/topic names must be nonempty and contain no control characters";

/// TS `assertName`: non-blank under JavaScript trim, no C0 control and no DEL.
pub fn assert_name(name: &str) -> Result<(), String> {
    if js_trim(name).is_empty() || name.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        Err(NAME_RULE.to_owned())
    } else {
        Ok(())
    }
}

/// A string member of a record.
pub fn text<'a>(record: &'a Value, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// A record's `profile_name` (or `topic_name`).
fn name_of<'a>(record: &'a Value, key: &str) -> &'a str {
    text(record, key).unwrap_or_default()
}

/// The `revision ?? 0` of a record (TS).
fn revision_or_zero(record: &Value) -> f64 {
    record
        .get("revision")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
}

/// `JSON.stringify` of a string.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_default()
}

/// `JSON.stringify` of an optional scalar member (`null` when absent).
fn scalar(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "null".to_owned(),
        Some(Value::Number(number)) => number
            .as_f64()
            .map_or_else(|| number.to_string(), crate::render::js_number),
        Some(Value::String(text)) => quoted(text),
        Some(other) => other.to_string(),
    }
}

/// TS `latestProfiles`: every name valid, no repeated `[name, id, revision]`, one id per
/// name, the highest `revision ?? 0` per name; the indexes of the kept records, sorted by
/// name (the `localeCompare` approximation).
pub fn latest_profiles(profiles: &[Value]) -> Result<Vec<usize>, Refusal> {
    let mut names: Vec<(String, usize)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (index, profile) in profiles.iter().enumerate() {
        let name = name_of(profile, "profile_name");
        assert_name(name).map_err(Refusal::Withheld)?;
        let identity = format!(
            "[{},{},{}]",
            quoted(name),
            scalar(profile.get("profile_id")),
            scalar(profile.get("revision"))
        );
        if !seen.insert(identity) {
            return Err(Refusal::Stated(
                "Inventory contains repeated profile records".to_owned(),
            ));
        }
        match names.iter_mut().find(|(known, _)| known == name) {
            Some((_, prior)) => {
                let earlier = &profiles[*prior];
                if !strict_eq(earlier.get("profile_id"), profile.get("profile_id")) {
                    return Err(Refusal::Withheld(format!("Ambiguous profile name: {name}")));
                }
                if revision_or_zero(profile) > revision_or_zero(earlier) {
                    *prior = index;
                }
            }
            None => names.push((name.to_owned(), index)),
        }
    }
    names.sort_by(|(a, _), (b, _)| crate::report::locale_order(a, b));
    Ok(names.into_iter().map(|(_, index)| index).collect())
}

/// TS `assertTenant`: every `tsg_id` that is set equals `tsg`.
pub fn assert_tenant<'a>(
    profiles: impl IntoIterator<Item = &'a Value>,
    tsg: &str,
) -> Result<(), Refusal> {
    let other = profiles
        .into_iter()
        .any(|profile| match profile.get("tsg_id") {
            None | Some(Value::Null) => false,
            Some(Value::String(id)) => id != tsg,
            Some(other) => scalar(Some(other)) != tsg,
        });
    if other {
        Err(Refusal::Stated(
            "Destination/source profile tenant identity does not match the selected TSG".into(),
        ))
    } else {
        Ok(())
    }
}

/// The latest profiles of an inventory (TS `profiles()`), in name order.
pub fn inventory_profiles(items: &[OValue]) -> Result<Vec<Value>, Refusal> {
    let values: Vec<Value> = items.iter().map(crate::json::value_of).collect();
    let kept = latest_profiles(&values)?;
    Ok(kept
        .into_iter()
        .map(|index| values[index].clone())
        .collect())
}

/// One topic reference of a policy (an object with a `topic_id` key).
#[derive(Clone, Debug, PartialEq)]
pub struct TopicRef {
    pub path: Vec<PathStep>,
    pub topic_id: String,
    pub topic_name: String,
    pub revision: f64,
}

impl TopicRef {
    /// TS `topicKey`.
    pub fn key(&self) -> String {
        topic_key(Some(&Value::String(self.topic_id.clone())), self.revision)
    }
}

/// TS `topicKey`: `JSON.stringify([topic_id, revision])`.
pub fn topic_key(id: Option<&Value>, revision: f64) -> String {
    format!("[{},{}]", scalar(id), crate::render::js_number(revision))
}

/// The key of a topic record.
pub fn record_key(topic: &Value) -> String {
    topic_key(
        topic.get("topic_id"),
        topic
            .get("revision")
            .and_then(Value::as_f64)
            .unwrap_or(f64::NAN),
    )
}

fn is_object(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Object(_)))
}

/// TS `topicReferences`: every object anywhere in `policy` with a `topic_id` key, which
/// must have a string `topic_id`, a string `topic_name` and a safe integer `revision >= 0`.
pub fn topic_references(policy: Option<&Value>) -> Result<Vec<TopicRef>, Refusal> {
    fn visit(
        value: &Value,
        path: &mut Vec<PathStep>,
        out: &mut Vec<TopicRef>,
    ) -> Result<(), Refusal> {
        match value {
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    path.push(PathStep::Index(index));
                    visit(item, path, out)?;
                    path.pop();
                }
            }
            Value::Object(map) => {
                if map.contains_key("topic_id") {
                    let revision = map.get("revision").and_then(Value::as_f64);
                    match (
                        map.get("topic_id").and_then(Value::as_str),
                        map.get("topic_name").and_then(Value::as_str),
                        revision,
                    ) {
                        (Some(id), Some(name), Some(revision))
                            if revision.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&revision) =>
                        {
                            out.push(TopicRef {
                                path: path.clone(),
                                topic_id: id.to_owned(),
                                topic_name: name.to_owned(),
                                revision,
                            });
                        }
                        _ => {
                            return Err(Refusal::Withheld(
                                "Invalid topic identity in profile policy".to_owned(),
                            ));
                        }
                    }
                }
                for (key, child) in map {
                    path.push(PathStep::Key(key.clone()));
                    visit(child, path, out)?;
                    path.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut out = Vec::new();
    if let Some(policy) = policy {
        visit(policy, &mut Vec::new(), &mut out)?;
    }
    Ok(out)
}

/// How a DLP reference sits in a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DlpKind {
    /// A `dlp-data-profiles[]` entry.
    Embedded,
    /// A `data-leak-detection.member[]` entry.
    Member,
}

/// One DLP reference of a policy.
#[derive(Clone, Debug, PartialEq)]
pub struct DlpRef {
    pub path: Vec<PathStep>,
    pub name: String,
    pub kind: DlpKind,
    /// Whether the referencing object has a `version` key.
    pub has_version: bool,
}

/// TS `dlpReferences`: each `dlp-data-profiles[]` entry and each
/// `data-leak-detection.member[]` except the built-in Basic `sensitive content` member.
pub fn dlp_references(policy: Option<&Value>) -> Result<Vec<DlpRef>, Refusal> {
    let Some(Value::Object(policy)) = policy else {
        return Ok(Vec::new());
    };
    let mut refs: Vec<DlpRef> = Vec::new();
    if let Some(Value::Array(entries)) = policy.get("dlp-data-profiles") {
        for (index, entry) in entries.iter().enumerate() {
            let Some(name) = entry
                .as_object()
                .and_then(|map| map.get("name"))
                .and_then(Value::as_str)
            else {
                return Err(Refusal::Withheld(
                    "Invalid embedded DLP reference".to_owned(),
                ));
            };
            refs.push(DlpRef {
                path: vec![
                    PathStep::Key("dlp-data-profiles".into()),
                    PathStep::Index(index),
                ],
                name: name.to_owned(),
                kind: DlpKind::Embedded,
                has_version: entry.get("version").is_some(),
            });
        }
    }
    if let Some(Value::Array(entries)) = policy.get("ai-security-profiles") {
        for (index, entry) in entries.iter().enumerate() {
            let model = entry.get("model-configuration");
            if !is_object(Some(entry)) || !is_object(model) {
                continue;
            }
            let protection = model.and_then(|model| model.get("data-protection"));
            let detection = protection.and_then(|protection| protection.get("data-leak-detection"));
            if !is_object(protection) || !is_object(detection) {
                continue;
            }
            let Some(Value::Array(members)) =
                detection.and_then(|detection| detection.get("member"))
            else {
                continue;
            };
            for (at, member) in members.iter().enumerate() {
                let Some(name) = member
                    .as_object()
                    .and_then(|map| map.get("text"))
                    .and_then(Value::as_str)
                else {
                    return Err(Refusal::Withheld("Invalid DLP member".to_owned()));
                };
                let id = member.get("id");
                let version = member.get("version");
                let id_empty = match id {
                    None => true,
                    Some(Value::String(id)) => id.is_empty(),
                    Some(_) => false,
                };
                let builtin = name.to_lowercase() == "sensitive content"
                    && id_empty
                    && (version.is_none() || version.and_then(Value::as_str) == Some("2"))
                    && !refs
                        .iter()
                        .any(|r| r.kind == DlpKind::Embedded && r.name == name);
                if builtin {
                    continue;
                }
                refs.push(DlpRef {
                    path: vec![
                        PathStep::Key("ai-security-profiles".into()),
                        PathStep::Index(index),
                        PathStep::Key("model-configuration".into()),
                        PathStep::Key("data-protection".into()),
                        PathStep::Key("data-leak-detection".into()),
                        PathStep::Key("member".into()),
                        PathStep::Index(at),
                    ],
                    name: name.to_owned(),
                    kind: DlpKind::Member,
                    has_version: version.is_some(),
                });
            }
        }
    }
    Ok(refs)
}

/// The unique names of the DLP references of a policy, in order.
pub fn dlp_names_of(policy: Option<&Value>) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = Vec::new();
    for reference in dlp_references(policy)? {
        if !names.contains(&reference.name) {
            names.push(reference.name);
        }
    }
    Ok(names)
}

/// JavaScript truthiness of a JSON value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// The D116 text of a profile body that fails its request schema.
pub fn invalid_profile_body() -> String {
    crate::writes::invalid_body("POST", "/v1/mgmt/profile").message()
}

/// TS `basicFallback`: the whole profile's custom DLP detection becomes Basic.
pub fn basic_fallback(policy: Option<&Value>) -> Result<Value, String> {
    let mut result = policy.cloned().unwrap_or(Value::Null);
    let custom: Vec<String> = dlp_names_of(Some(&result))?;
    let mut converted = false;
    if let Some(Value::Array(entries)) = result.get_mut("ai-security-profiles") {
        for entry in entries.iter_mut() {
            let Some(detection) = entry
                .get_mut("model-configuration")
                .and_then(|model| model.get_mut("data-protection"))
                .and_then(|protection| protection.get_mut("data-leak-detection"))
            else {
                continue;
            };
            let names_custom = detection
                .get("member")
                .and_then(Value::as_array)
                .is_some_and(|members| {
                    members.iter().any(|member| {
                        member
                            .get("text")
                            .and_then(Value::as_str)
                            .is_some_and(|text| custom.iter().any(|name| name == text))
                    })
                });
            if !names_custom {
                continue;
            }
            let action = detection.get("action").and_then(Value::as_str);
            if !matches!(action, Some("block" | "allow" | "")) {
                return Err("Cannot safely fall back to Basic: unsupported DLP action".into());
            }
            if truthy(detection.get("mask-data-inline")) && action != Some("block") {
                return Err(
                    "Cannot safely fall back to Basic: inline masking requires a block action"
                        .into(),
                );
            }
            detection["member"] = if action == Some("") {
                Value::Null
            } else {
                json!([{"text": "sensitive content", "id": "", "version": "2"}])
            };
            converted = true;
        }
    }
    if !converted {
        return Err(
            "Cannot safely fall back to Basic: no matching DLP detection configuration".into(),
        );
    }
    if let Some(map) = result.as_object_mut()
        && map.contains_key("dlp-data-profiles")
    {
        map.insert("dlp-data-profiles".into(), Value::Array(Vec::new()));
    }
    scm::airs::management::models::Policy::parse(result.clone(), scm::validation::Mode::Request)
        .map_err(|_| invalid_profile_body())?;
    Ok(result)
}

/// Whether a key names a tenant-bound identifier (TS
/// `/(?:^|[-_])(id|uuid)$|(?:Id|ID|Uuid|UUID)$/`).
pub fn id_like(key: &str) -> bool {
    let lower = ["id", "uuid"].iter().any(|suffix| {
        key == *suffix
            || key.ends_with(&format!("-{suffix}"))
            || key.ends_with(&format!("_{suffix}"))
    });
    lower
        || ["Id", "ID", "Uuid", "UUID"]
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

/// TS `assertKnownPolicyReferences`: a cross-tenant restore refuses every identifier key
/// whose value is not `null` or `''`, except a topic reference's `topic_id`, an embedded
/// DLP entry's `id`/`uuid` and a DLP member's `id`.
pub fn assert_known_policy_references(policy: Option<&Value>) -> Result<(), String> {
    let mut known: HashMap<Vec<PathStep>, &'static [&'static str]> = HashMap::new();
    for reference in topic_references(policy)? {
        known.insert(reference.path, &["topic_id"]);
    }
    for reference in dlp_references(policy)? {
        let keys: &'static [&'static str] = match reference.kind {
            DlpKind::Embedded => &["id", "uuid"],
            DlpKind::Member => &["id"],
        };
        known.insert(reference.path, keys);
    }
    fn visit(
        value: &Value,
        text: &str,
        path: &mut Vec<PathStep>,
        known: &HashMap<Vec<PathStep>, &'static [&'static str]>,
    ) -> Result<(), String> {
        match value {
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    path.push(PathStep::Index(index));
                    visit(item, &format!("{text}[{index}]"), path, known)?;
                    path.pop();
                }
            }
            Value::Object(map) => {
                for (key, child) in map {
                    let empty = matches!(child, Value::Null)
                        || matches!(child, Value::String(text) if text.is_empty());
                    let allowed = known
                        .get(path.as_slice())
                        .is_some_and(|keys| keys.contains(&key.as_str()));
                    if !empty && id_like(key) && !allowed {
                        return Err(format!(
                            "Unsupported cross-tenant policy reference at {text}.{key}"
                        ));
                    }
                    path.push(PathStep::Key(key.clone()));
                    visit(child, &format!("{text}.{key}"), path, known)?;
                    path.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }
    if let Some(policy) = policy {
        visit(policy, "policy", &mut Vec::new(), &known)?;
    }
    Ok(())
}

/// The `examples` of a topic, an absent one as `[]` (choice 24).
fn examples(topic: &Value) -> Value {
    match topic.get("examples") {
        None => Value::Array(Vec::new()),
        Some(value) => value.clone(),
    }
}

/// `active ?? true`.
fn active_or_true(record: &Value) -> Value {
    match record.get("active") {
        None | Some(Value::Null) => Value::Bool(true),
        Some(value) => value.clone(),
    }
}

/// TS `sameTopic`: equal `description`, `examples` (absent read as `[]`, choice 24) and
/// `active ?? true`.
pub fn same_topic(a: &Value, b: &Value) -> bool {
    strict_eq(a.get("description"), b.get("description"))
        && js_equal(&examples(a), &examples(b))
        && strict_eq(Some(&active_or_true(a)), Some(&active_or_true(b)))
}

/// Deep equality as `JSON.stringify` sees it (numbers by value, key order ignored, which
/// TypeScript's `canonical` sorts away).
pub fn js_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| js_equal(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(key, value)| y.get(key).is_some_and(|other| js_equal(value, other)))
        }
        (x, y) => strict_eq(Some(x), Some(y)),
    }
}

/// TS `canonicalPolicy`: an absent `database-security` in a `data-protection` object reads
/// as `null` (the observed API normalisation).
pub fn canonical_policy(policy: Option<&Value>) -> Option<Value> {
    let mut value = policy.cloned()?;
    if let Some(Value::Array(entries)) = value.get_mut("ai-security-profiles") {
        for entry in entries {
            if let Some(Value::Object(protection)) = entry
                .get_mut("model-configuration")
                .and_then(|model| model.get_mut("data-protection"))
                && !protection.contains_key("database-security")
            {
                protection.insert("database-security".into(), Value::Null);
            }
        }
    }
    Some(value)
}

/// TS `unchanged`: the same id, revision, `active` and canonical policy.
pub fn unchanged(current: Option<&Value>, prior: &Value) -> bool {
    let Some(current) = current else {
        return false;
    };
    let policies = match (
        canonical_policy(current.get("policy")),
        canonical_policy(prior.get("policy")),
    ) {
        (None, None) => true,
        (Some(a), Some(b)) => js_equal(&a, &b),
        _ => false,
    };
    strict_eq(current.get("profile_id"), prior.get("profile_id"))
        && strict_eq(current.get("revision"), prior.get("revision"))
        && strict_eq(current.get("active"), prior.get("active"))
        && policies
}

// ---------------------------------------------------------------------------
// The restore plan (TS `planRuntimeProfilesRestore`)
// ---------------------------------------------------------------------------

/// `--on-conflict`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conflict {
    Error,
    Verify,
    Skip,
    Update,
}

impl Conflict {
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "error" => Self::Error,
            "verify" => Self::Verify,
            "skip" => Self::Skip,
            "update" => Self::Update,
            _ => return None,
        })
    }
}

/// `--on-missing-dlp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingDlp {
    Error,
    Basic,
}

/// The restore options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub prefix: String,
    pub conflict: Conflict,
    /// `--dlp-map` source → destination, in the order given.
    pub dlp_map: Vec<(String, String)>,
    pub missing_dlp: MissingDlp,
}

impl Options {
    fn mapped(&self, name: &str) -> Option<&str> {
        self.dlp_map
            .iter()
            .find(|(source, _)| source == name)
            .map(|(_, destination)| destination.as_str())
    }
}

/// What the restore does with one profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Create,
    Update,
    Skip,
    Verify,
}

impl Action {
    /// The plan word.
    pub fn word(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Skip => "skip",
            Self::Verify => "verify",
        }
    }
}

/// One planned profile.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfilePlan {
    /// The destination name (prefix included).
    pub name: String,
    pub source: Value,
    pub existing: Option<Value>,
    pub action: Action,
    /// The policy after an accepted Basic fallback (the source is kept).
    pub fallback: Option<Value>,
}

/// One planned topic.
#[derive(Clone, Debug, PartialEq)]
pub struct TopicPlan {
    pub key: String,
    pub name: String,
    pub source: Value,
    pub existing: Option<Value>,
}

/// One resolved DLP binding.
#[derive(Clone, Debug, PartialEq)]
pub struct DlpMapping {
    pub source: String,
    pub destination: String,
    pub id: String,
    pub version: Option<Value>,
}

/// One accepted Basic fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DlpFallback {
    pub profile: String,
    pub unresolved: Vec<String>,
    pub replaced: Vec<String>,
}

/// Server defaults verified on one profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerDefaults {
    pub profile: String,
    pub fields: Vec<String>,
}

/// The validated selection of a backup, before any request.
#[derive(Clone, Debug, PartialEq)]
pub struct Prepared {
    /// The file's profiles, latest per name, in name order.
    pub selected: Vec<Value>,
    pub cross_tenant: bool,
}

/// The create body of a profile (TS `{profile_name, active, policy}`; `active` only when
/// the record has a boolean one).
pub fn profile_body(name: &str, source: &Value, policy: &Value) -> Value {
    let mut body = Map::new();
    body.insert("profile_name".into(), Value::String(name.to_owned()));
    if let Some(active) = source.get("active").filter(|value| value.is_boolean()) {
        body.insert("active".into(), active.clone());
    }
    body.insert("policy".into(), policy.clone());
    Value::Object(body)
}

/// The create body of a topic: `topic_name` with the prefix and the record's `active`,
/// `description` and `examples` when it has them (TS sends `undefined` for an absent one).
pub fn topic_body(name: &str, source: &Value) -> Value {
    let mut body = Map::new();
    body.insert("topic_name".into(), Value::String(name.to_owned()));
    for key in ["active", "description", "examples"] {
        if let Some(value) = source.get(key).filter(|value| !value.is_null()) {
            body.insert(key.into(), value.clone());
        }
    }
    Value::Object(body)
}

/// Whether a profile body passes the SDK request schema.
pub fn valid_profile_body(body: &Value) -> bool {
    scm::airs::management::models::CreateSecurityProfileRequest::parse(
        body.clone(),
        scm::validation::Mode::Request,
    )
    .is_ok()
}

/// Stage 1 (no request): the file's latest profiles, their tenant, one revision per name,
/// the create bodies and, cross-tenant, the reference allowlist.
pub fn prepare(
    profiles: &[Value],
    source_tsg: &str,
    destination_tsg: &str,
    options: &Options,
) -> Result<Prepared, String> {
    let kept = latest_profiles(profiles)?;
    let selected: Vec<Value> = kept.iter().map(|index| profiles[*index].clone()).collect();
    assert_tenant(&selected, source_tsg)?;
    if selected.len() != profiles.len() {
        return Err("Backup contains duplicate profile names/revisions".to_owned());
    }
    let cross_tenant = source_tsg != destination_tsg;
    for profile in &selected {
        let Some(policy) = profile.get("policy").filter(|policy| !policy.is_null()) else {
            return Err("Backup profile has no policy".to_owned());
        };
        let name = format!("{}{}", options.prefix, name_of(profile, "profile_name"));
        if !valid_profile_body(&profile_body(&name, profile, policy)) {
            return Err(invalid_profile_body());
        }
        if cross_tenant {
            assert_known_policy_references(Some(policy))?;
        }
    }
    Ok(Prepared {
        selected,
        cross_tenant,
    })
}

/// Stage 2: each profile against the destination's latest profiles (already checked for
/// their tenant).
pub fn plan_profiles(
    prepared: &Prepared,
    existing: &[Value],
    options: &Options,
) -> Result<Vec<ProfilePlan>, String> {
    let mut plans = Vec::with_capacity(prepared.selected.len());
    for source in &prepared.selected {
        let name = format!("{}{}", options.prefix, name_of(source, "profile_name"));
        let found = existing
            .iter()
            .find(|profile| text(profile, "profile_name") == Some(name.as_str()));
        if found.is_some() && options.conflict == Conflict::Error {
            return Err(format!(
                "Destination profile already exists: {name}; choose --on-conflict verify, skip or update"
            ));
        }
        if found.is_some_and(|profile| !truthy(profile.get("profile_id"))) {
            return Err("Destination profile has no identity".to_owned());
        }
        let action = match (found, options.conflict) {
            (None, _) => Action::Create,
            (Some(_), Conflict::Skip) => Action::Skip,
            (Some(_), Conflict::Verify) => Action::Verify,
            (Some(_), _) => Action::Update,
        };
        plans.push(ProfilePlan {
            name,
            source: source.clone(),
            existing: found.cloned(),
            action,
            fallback: None,
        });
    }
    Ok(plans)
}

/// The topic references of the profiles that are not skipped.
pub fn changing_refs(plans: &[ProfilePlan]) -> Result<Vec<TopicRef>, String> {
    let mut refs = Vec::new();
    for plan in plans.iter().filter(|plan| plan.action != Action::Skip) {
        refs.extend(topic_references(plan.source.get("policy"))?);
    }
    Ok(refs)
}

/// Stage 3: one topic plan per referenced `[topic_id, revision]`, against the
/// destination's topics (every revision).
pub fn plan_topics(
    refs: &[TopicRef],
    backup_topics: &[Value],
    target_topics: &[Value],
    prefix: &str,
) -> Result<Vec<TopicPlan>, String> {
    let mut plans: Vec<TopicPlan> = Vec::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for reference in refs {
        let key = reference.key();
        if plans.iter().any(|plan| plan.key == key) {
            continue;
        }
        let definitions: Vec<&Value> = backup_topics
            .iter()
            .filter(|topic| {
                record_key(topic) == key
                    && text(topic, "topic_name") == Some(reference.topic_name.as_str())
            })
            .collect();
        let [source] = definitions.as_slice() else {
            return Err(format!(
                "Backup lacks an unambiguous topic definition: {}",
                reference.topic_name
            ));
        };
        let name = format!("{prefix}{}", name_of(source, "topic_name"));
        assert_name(&name)?;
        if names.get(&name).is_some_and(|known| *known != key) {
            return Err(format!(
                "Multiple source revisions use topic name {name}; split the backup by profile/revision before restoring"
            ));
        }
        names.insert(name.clone(), key.clone());
        let mut matches: Vec<&Value> = target_topics
            .iter()
            .filter(|topic| text(topic, "topic_name") == Some(name.as_str()))
            .collect();
        // Highest revision first (a stable sort, as `Array.prototype.sort`).
        matches.sort_by(|a, b| revision_or_nan(b).total_cmp(&revision_or_nan(a)));
        let mut ids: Vec<String> = matches
            .iter()
            .map(|topic| scalar(topic.get("topic_id")))
            .collect();
        ids.sort();
        ids.dedup();
        if ids.len() > 1 {
            return Err(format!("Ambiguous destination topic name: {name}"));
        }
        let found = matches.first().copied();
        if let Some(found) = found
            && (!truthy(found.get("topic_id")) || !same_topic(source, found))
        {
            return Err(format!(
                "Destination topic differs: {name}; use --name-prefix to avoid changing a shared topic"
            ));
        }
        plans.push(TopicPlan {
            key,
            name,
            source: (*source).clone(),
            existing: found.cloned(),
        });
    }
    Ok(plans)
}

fn revision_or_nan(topic: &Value) -> f64 {
    topic
        .get("revision")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN)
}

/// The DLP names of a plan before the catalog.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DlpNames {
    /// Every DLP reference of the changing profiles that is considered (cross-tenant or
    /// with `--on-missing-dlp basic`).
    pub refs: Vec<DlpRef>,
    pub names: Vec<String>,
    pub unresolved: Vec<String>,
}

impl DlpNames {
    /// Whether the catalog must be read: some name has a destination name.
    pub fn needs_catalog(&self, cross_tenant: bool, options: &Options) -> bool {
        self.names
            .iter()
            .any(|name| target_for(name, cross_tenant, options).is_some())
    }
}

/// TS `targetFor`: the `--dlp-map` destination, else nothing cross-tenant, else the name.
fn target_for<'a>(name: &'a str, cross_tenant: bool, options: &'a Options) -> Option<&'a str> {
    match options.mapped(name) {
        Some(destination) => Some(destination),
        None if cross_tenant => None,
        None => Some(name),
    }
}

/// Stage 4 (no request): the DLP names of the changing profiles and the unmapped ones.
pub fn dlp_names(
    plans: &[ProfilePlan],
    cross_tenant: bool,
    options: &Options,
) -> Result<DlpNames, String> {
    let mut out = DlpNames::default();
    if !(cross_tenant || options.missing_dlp == MissingDlp::Basic) {
        return Ok(out);
    }
    for plan in plans.iter().filter(|plan| plan.action != Action::Skip) {
        out.refs.extend(dlp_references(plan.source.get("policy"))?);
    }
    for reference in &out.refs {
        if !out.names.contains(&reference.name) {
            out.names.push(reference.name.clone());
        }
    }
    for name in &out.names {
        if target_for(name, cross_tenant, options).is_none() {
            if options.missing_dlp == MissingDlp::Error {
                return Err(format!(
                    "Cross-tenant DLP reference requires explicit --dlp-map \"{name}=<destination-name>\"; DLP resources are not cloned. Inspect destination resources with airs runtime dlp profiles list --all --output json, or explicitly accept --on-missing-dlp basic."
                ));
            }
            out.unresolved.push(name.clone());
        }
    }
    Ok(out)
}

/// The active catalog entries named `target` (TS: not `deleted` or `disabled`).
pub fn catalog_matches<'a>(catalog: &'a [Value], target: &str) -> Vec<&'a Value> {
    catalog
        .iter()
        .filter(|profile| text(profile, "name") == Some(target) && !retired_profile(profile))
        .collect()
}

/// The complete restore plan.
#[derive(Clone, Debug, PartialEq)]
pub struct RestorePlan {
    pub source_tsg: String,
    pub destination_tsg: String,
    pub profiles: Vec<ProfilePlan>,
    pub topics: Vec<TopicPlan>,
    pub dlp_mappings: Vec<DlpMapping>,
    pub dlp_fallbacks: Vec<DlpFallback>,
    pub server_defaults: Vec<ServerDefaults>,
    pub cross_tenant: bool,
}

impl RestorePlan {
    /// The profiles the confirmation counts (`create` or `update`).
    pub fn changing(&self) -> usize {
        self.profiles
            .iter()
            .filter(|plan| matches!(plan.action, Action::Create | Action::Update))
            .count()
    }

    /// The planned updates.
    pub fn updates(&self) -> usize {
        self.profiles
            .iter()
            .filter(|plan| plan.action == Action::Update)
            .count()
    }
}

/// The inputs of the last stage.
pub struct Finish<'a> {
    pub source_tsg: &'a str,
    pub destination_tsg: &'a str,
    pub cross_tenant: bool,
    pub profiles: Vec<ProfilePlan>,
    pub topics: Vec<TopicPlan>,
    pub dlp: DlpNames,
    /// The DLP data-profile catalog (empty when it was not needed).
    pub catalog: &'a [Value],
}

/// Stage 5: the DLP bindings, the Basic fallbacks and the `verify` checks, before any
/// write.
pub fn finish(input: Finish<'_>, options: &Options) -> Result<RestorePlan, String> {
    let Finish {
        source_tsg,
        destination_tsg,
        cross_tenant,
        mut profiles,
        topics,
        dlp,
        catalog,
    } = input;
    let mut unresolved = dlp.unresolved.clone();
    let mut resolved: Vec<DlpMapping> = Vec::new();
    for name in &dlp.names {
        let Some(target) = target_for(name, cross_tenant, options) else {
            continue;
        };
        let matches = catalog_matches(catalog, target);
        if matches.is_empty() && options.missing_dlp == MissingDlp::Basic {
            unresolved.push(name.clone());
            continue;
        }
        let id = match matches.as_slice() {
            [only] if truthy(only.get("id")) => scalar_text(only.get("id")),
            _ => {
                return Err(format!(
                    "Missing or ambiguous destination DLP profile: {target}"
                ));
            }
        };
        let version = matches[0]
            .get("version")
            .filter(|value| !value.is_null())
            .cloned();
        if dlp
            .refs
            .iter()
            .any(|reference| reference.name == *name && reference.has_version)
            && version.is_none()
        {
            return Err(format!("Destination DLP version is unknown: {target}"));
        }
        resolved.push(DlpMapping {
            source: name.clone(),
            destination: target.to_owned(),
            id,
            version,
        });
    }
    let mut fallbacks = Vec::new();
    for plan in profiles
        .iter_mut()
        .filter(|plan| plan.action != Action::Skip)
    {
        let replaced = dlp_names_of(plan.source.get("policy"))?;
        let missing: Vec<String> = replaced
            .iter()
            .filter(|name| unresolved.contains(name))
            .cloned()
            .collect();
        if missing.is_empty() {
            continue;
        }
        plan.fallback = Some(basic_fallback(plan.source.get("policy"))?);
        fallbacks.push(DlpFallback {
            profile: plan.name.clone(),
            unresolved: missing,
            replaced,
        });
    }
    let mut remaining: Vec<String> = Vec::new();
    for plan in profiles.iter().filter(|plan| plan.action != Action::Skip) {
        remaining.extend(dlp_names_of(
            plan.fallback.as_ref().or_else(|| plan.source.get("policy")),
        )?);
    }
    let dlp_mappings: Vec<DlpMapping> = resolved
        .into_iter()
        .filter(|mapping| remaining.contains(&mapping.source))
        .collect();
    let mut plan = RestorePlan {
        source_tsg: source_tsg.to_owned(),
        destination_tsg: destination_tsg.to_owned(),
        profiles,
        topics,
        dlp_mappings,
        dlp_fallbacks: fallbacks,
        server_defaults: Vec::new(),
        cross_tenant,
    };
    let existing_topics: Vec<(String, Value)> = plan
        .topics
        .iter()
        .filter_map(|topic| Some((topic.key.clone(), topic.existing.clone()?)))
        .collect();
    let mut defaults = Vec::new();
    for item in plan
        .profiles
        .iter()
        .filter(|plan| plan.action == Action::Verify)
    {
        let expected = mapped_policy(item, &plan.dlp_mappings, &existing_topics)?;
        let existing = item.existing.as_ref();
        let comparison = policy::compare(
            Some(&expected),
            existing.and_then(|record| record.get("policy")),
        );
        let active_differs = item.source.get("active").is_some()
            && !strict_eq(
                existing.and_then(|record| record.get("active")),
                item.source.get("active"),
            );
        if !comparison.matches || active_differs {
            return Err(format!(
                "Destination profile does not match restore plan: {}; verification made no changes",
                item.name
            ));
        }
        if !comparison.server_defaults.is_empty() {
            defaults.push(ServerDefaults {
                profile: item.name.clone(),
                fields: comparison.server_defaults,
            });
        }
    }
    plan.server_defaults = defaults;
    Ok(plan)
}

/// `String(value)` of a scalar id.
fn scalar_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number
            .as_f64()
            .map_or_else(|| number.to_string(), crate::render::js_number),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// TS `mappedPolicy`: the (fallback or source) policy with each topic reference bound to
/// its destination topic and each mapped DLP reference to its destination profile.
/// `topics` maps a topic key to the destination topic record.
pub fn mapped_policy(
    item: &ProfilePlan,
    mappings: &[DlpMapping],
    topics: &[(String, Value)],
) -> Result<Value, Refusal> {
    let mut policy = item
        .fallback
        .clone()
        .or_else(|| item.source.get("policy").cloned())
        .unwrap_or(Value::Null);
    for reference in topic_references(Some(&policy))? {
        let key = reference.key();
        let topic = topics
            .iter()
            .find(|(known, _)| *known == key)
            .map(|(_, topic)| topic)
            .filter(|topic| truthy(topic.get("topic_id")));
        let Some(topic) = topic else {
            return Err(Refusal::Stated("Missing planned topic mapping; an existing profile cannot be verified without its destination dependencies".to_owned()));
        };
        if let Some(Value::Object(object)) = at_path(&mut policy, &reference.path) {
            for field in ["topic_id", "topic_name", "revision"] {
                match topic.get(field) {
                    Some(value) => {
                        object.insert(field.into(), value.clone());
                    }
                    None => {
                        object.remove(field);
                    }
                }
            }
        }
    }
    for reference in dlp_references(Some(&policy))? {
        let Some(mapping) = mappings
            .iter()
            .find(|mapping| mapping.source == reference.name)
        else {
            continue;
        };
        let Some(Value::Object(object)) = at_path(&mut policy, &reference.path) else {
            continue;
        };
        match reference.kind {
            DlpKind::Embedded => {
                object.insert("name".into(), Value::String(mapping.destination.clone()));
                object.insert("uuid".into(), Value::String(mapping.id.clone()));
            }
            DlpKind::Member => {
                object.insert("text".into(), Value::String(mapping.destination.clone()));
            }
        }
        if object.contains_key("id") {
            object.insert("id".into(), Value::String(mapping.id.clone()));
        }
        if object.contains_key("version") {
            let Some(version) = &mapping.version else {
                return Err(Refusal::Stated(
                    "Destination DLP version is unknown".to_owned(),
                ));
            };
            object.insert("version".into(), Value::String(scalar_text(Some(version))));
        }
    }
    Ok(policy)
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
