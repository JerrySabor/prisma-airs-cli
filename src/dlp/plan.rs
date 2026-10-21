//! The DLP restore planner (DESIGN §16.11, D176, D177; TS `planDlpResourcesRestore`,
//! TB§5.2–§5.5): name matching against the destination inventories, the dependency rows
//! (`create`, `reuse`, `resolve`, `map`), the profile rows (`create`, `verify`, `skip`),
//! the bindings and id remapping of profile rules, the echo comparison (`compareEcho`),
//! the dictionary upload text and the deterministic reconcile suffix. Pure: no I/O. Every
//! refusal is the TS text (exit 1) and happens before any write.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use super::backup::{
    self, Backup, Leaf, PathStep, at_path, predefined, retired_pattern, retired_profile,
    rule_leaves, unique_names, valid_name, value_of,
};

/// `--on-conflict <policy>`: existing data profile names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conflict {
    Error,
    Verify,
    Skip,
    Reconcile,
}

impl Conflict {
    /// `error|verify|skip|reconcile`.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "error" => Some(Self::Error),
            "verify" => Some(Self::Verify),
            "skip" => Some(Self::Skip),
            "reconcile" => Some(Self::Reconcile),
            _ => None,
        }
    }
}

/// The plan options of a restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub prefix: String,
    pub conflict: Conflict,
    /// `--pattern-map` source name → destination name, in order.
    pub pattern_map: Vec<(String, String)>,
    pub skip_unresolved: bool,
}

impl Options {
    fn mapped(&self, source: &str) -> Option<&str> {
        self.pattern_map
            .iter()
            .find(|(from, _)| from == source)
            .map(|(_, to)| to.as_str())
    }
}

/// The three destination inventories (dictionaries without keywords, G13) and the
/// keywords of the destination dictionaries a backup dictionary's name matches, read per
/// id ([`keyword_reads`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Destination {
    pub dictionaries: Vec<Value>,
    pub patterns: Vec<Value>,
    pub profiles: Vec<Value>,
    /// Destination dictionary id → its `keywords`.
    pub keywords: BTreeMap<String, Value>,
}

/// The ids of the destination dictionaries whose keywords the plan compares: those a
/// custom backup dictionary's (prefixed) name matches (G13: the inventory carries no
/// keywords).
pub fn keyword_reads(backup: &Backup, destination: &Destination, prefix: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for entry in &backup.dictionaries {
        if entry.predefined {
            continue;
        }
        let name = format!("{prefix}{}", entry.name);
        if let Ok(Some(found)) =
            destination_match(destination, backup::Resource::Dictionaries, &name)
            && let Some(id) = id_of(found)
            && !ids.iter().any(|known: &String| known == id)
        {
            ids.push(id.to_owned());
        }
    }
    ids
}

/// The action of a dictionary or pattern row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyAction {
    Create,
    Reuse,
    Resolve,
    Map,
}

impl DependencyAction {
    /// The plan word (`create`, …).
    pub fn word(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Reuse => "reuse",
            Self::Resolve => "resolve",
            Self::Map => "map",
        }
    }

    /// The result word (`created`, …).
    pub fn done(self) -> &'static str {
        match self {
            Self::Create => "created",
            Self::Reuse => "reused",
            Self::Resolve => "resolved",
            Self::Map => "mapped",
        }
    }
}

/// The action of a profile row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileAction {
    Create,
    Verify,
    Skip,
}

impl ProfileAction {
    pub fn word(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Verify => "verify",
            Self::Skip => "skip",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DictionaryPlan {
    pub source_id: String,
    pub name: String,
    pub action: DependencyAction,
    /// The rebuilt `DictionaryRequest` (custom dictionaries).
    pub metadata: Option<Value>,
    /// The keywords, sorted (TS `keywordSet`).
    pub keywords: Vec<String>,
    pub existing: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PatternPlan {
    pub source_id: String,
    pub name: String,
    pub action: DependencyAction,
    /// The rebuilt `DataPatternRequest` (custom patterns).
    pub body: Option<Value>,
    pub existing: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProfilePlan {
    /// The destination name (the prefix applied; under `reconcile` the suffixed name of
    /// an earlier run's copy, D177).
    pub name: String,
    /// The name before the reconcile suffix, when [`ProfilePlan::name`] carries it.
    pub renamed_from: Option<String>,
    pub source_id: String,
    pub source: Value,
    pub action: ProfileAction,
    pub existing: Option<Value>,
    /// Why the profile is skipped by unresolved references.
    pub reason: Option<String>,
}

/// A reference the destination cannot satisfy, skipped under `--skip-unresolved`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unresolved {
    /// `dictionary` or `pattern`.
    pub kind: &'static str,
    pub source_id: String,
    pub name: String,
    pub reason: String,
    pub candidates: Vec<String>,
}

/// A validated restore plan.
#[derive(Clone, Debug, PartialEq)]
pub struct RestorePlan {
    pub source_tsg: String,
    pub destination_tsg: String,
    pub dictionaries: Vec<DictionaryPlan>,
    pub patterns: Vec<PatternPlan>,
    pub profiles: Vec<ProfilePlan>,
    pub unresolved: Vec<Unresolved>,
    /// `--on-conflict reconcile`: a create answered 409 is retried once under the
    /// deterministic suffix.
    pub reconcile: bool,
}

impl RestorePlan {
    /// The `create` rows (the confirmation's `<n>`).
    pub fn creates(&self) -> usize {
        self.dictionaries
            .iter()
            .filter(|row| row.action == DependencyAction::Create)
            .count()
            + self
                .patterns
                .iter()
                .filter(|row| row.action == DependencyAction::Create)
                .count()
            + self
                .profiles
                .iter()
                .filter(|row| row.action == ProfileAction::Create)
                .count()
    }

    pub fn cross_tenant(&self) -> bool {
        self.source_tsg != self.destination_tsg
    }
}

/// Where a source dependency id points in the destination.
#[derive(Clone, Debug, PartialEq)]
pub struct Binding {
    pub dictionary: bool,
    pub technique: Option<String>,
    pub id: String,
    pub name: String,
    pub version: Option<Value>,
}

// ---------------------------------------------------------------------------
// Value rules (JavaScript semantics)
// ---------------------------------------------------------------------------

/// `null` and an absent value unify (`?? null`).
fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

/// Canonical equality (TS `canonical`: sorted keys, numbers by value).
pub fn canonical_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| canonical_eq(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(key, a)| y.get(key).is_some_and(|b| canonical_eq(a, b)))
        }
        (x, y) => x == y,
    }
}

/// `===` of two primitives (numbers by value).
fn strictly_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(_) | Value::Object(_), _) | (_, Value::Array(_) | Value::Object(_)) => false,
        (x, y) => x == y,
    }
}

/// The response-only metadata keys a comparison ignores at the top level when the request
/// does not set them (TS `SERVER_METADATA_KEYS`).
const SERVER_METADATA_KEYS: [&str; 16] = [
    "id",
    "version",
    "status",
    "profile_status",
    "tenant_id",
    "license_type",
    "is_parent_managed",
    "audit_metadata",
    "type",
    "advance_data_patterns_rule_request",
    "dictionary_metadata",
    "detection_technique",
    "detection_sub_technique",
    "attributes",
    "keywords",
    "tags",
];

/// The result of [`compare_echo`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Echo {
    pub differences: Vec<String>,
    pub server_added: Vec<String>,
}

impl Echo {
    pub fn matches(&self) -> bool {
        self.differences.is_empty()
    }
}

/// TS `compareEcho`: every requested field must equal the read-back (`null` ≡ absent);
/// fields only the server has are server-added; a `supported_confidence_levels` array may
/// gain levels; the top-level server metadata keys are ignored when not requested.
pub fn compare_echo(request: &Value, read_back: Option<&Value>) -> Echo {
    fn visit(
        source: Option<&Value>,
        target: Option<&Value>,
        path: &str,
        top: bool,
        echo: &mut Echo,
    ) {
        let (a, b) = (present(source), present(target));
        let (a, b) = match (a, b) {
            (None, None) => return,
            (None, Some(_)) => {
                echo.server_added.push(path.to_owned());
                return;
            }
            (Some(_), None) => {
                echo.differences.push(path.to_owned());
                return;
            }
            (Some(a), Some(b)) => (a, b),
        };
        if path.ends_with(".supported_confidence_levels")
            && let (Value::Array(want), Value::Array(have)) = (a, b)
            && want
                .iter()
                .all(|level| have.iter().any(|other| strictly_equal(level, other)))
        {
            if want.len() != have.len() {
                echo.server_added.push(path.to_owned());
            }
            return;
        }
        match (a, b) {
            (Value::Array(want), Value::Array(have)) => {
                if want.len() != have.len() {
                    echo.differences.push(path.to_owned());
                    return;
                }
                for (index, item) in want.iter().enumerate() {
                    visit(
                        Some(item),
                        have.get(index),
                        &format!("{path}[{index}]"),
                        false,
                        echo,
                    );
                }
            }
            (Value::Array(_), _) | (_, Value::Array(_)) => echo.differences.push(path.to_owned()),
            (Value::Object(want), Value::Object(have)) => {
                let keys: BTreeSet<&String> = want.keys().chain(have.keys()).collect();
                for key in keys {
                    if top
                        && !want.contains_key(key)
                        && SERVER_METADATA_KEYS.contains(&key.as_str())
                    {
                        continue;
                    }
                    visit(
                        want.get(key),
                        have.get(key),
                        &format!("{path}.{key}"),
                        false,
                        echo,
                    );
                }
            }
            (a, b) => {
                if !strictly_equal(a, b) {
                    echo.differences.push(path.to_owned());
                }
            }
        }
    }
    let mut echo = Echo::default();
    visit(Some(request), read_back, "body", true, &mut echo);
    echo
}

/// Sorted keywords (TS `keywordSet`: `[...keywords].sort()`, UTF-16 code-unit order);
/// `None` unless a string array.
pub fn keyword_set(value: Option<&Value>) -> Option<Vec<String>> {
    let items = value?.as_array()?;
    let mut words: Vec<String> = items
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    words.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    Some(words)
}

/// TS `dictionaryFile`: the upload text of `keywords` for the metadata's file name (CSV:
/// a `keywords` header row, which the service consumes; TXT: one keyword per line).
pub fn dictionary_file(metadata: &Value, keywords: &[String]) -> Result<String, String> {
    if keywords.is_empty()
        || keywords
            .iter()
            .any(|word| word.is_empty() || word.contains(['\r', '\n']))
    {
        return Err("Dictionary contains keywords that cannot be faithfully uploaded".to_owned());
    }
    let file = metadata
        .get("original_file_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if file.ends_with(".csv") {
        if keywords.iter().any(|word| word.contains(',')) {
            return Err("Dictionary CSV contains unsupported multi-column keywords".to_owned());
        }
        return Ok(format!("keywords\n{}\n", keywords.join("\n")));
    }
    if file.ends_with(".txt") {
        return Ok(format!("{}\n", keywords.join("\n")));
    }
    Err("Dictionary filename must end in .csv or .txt for a verified upload".to_owned())
}

/// TS `dictionaryEcho`: the metadata without `original_file_name` echoes, the echoed file
/// name (when given) is the requested one, and the sorted keywords are equal.
pub fn dictionary_echo(metadata: &Value, record: Option<&Value>, keywords: &[String]) -> Echo {
    let mut projection = metadata.clone();
    let file = projection
        .as_object_mut()
        .and_then(|map| map.remove("original_file_name"));
    let mut echo = compare_echo(&projection, record);
    let echoed_file = record
        .and_then(|record| record.get("dictionary_metadata"))
        .and_then(|meta| present(meta.get("original_file_name")));
    let file_ok = echoed_file.is_none_or(|echoed| file.as_ref().is_some_and(|file| echoed == file));
    let keywords_ok = keyword_set(record.and_then(|record| record.get("keywords")))
        .is_some_and(|echoed| echoed == keywords);
    if !file_ok || !keywords_ok {
        echo.differences.push("body.keywords".to_owned());
    }
    echo
}

/// TS `dictionaryRequest`: the create metadata of a backed-up dictionary under `name`.
pub fn dictionary_request(source: &Value, name: &str) -> Result<Value, String> {
    let mut map = Map::new();
    if let Some(category) = source.get("category") {
        map.insert("category".to_owned(), category.clone());
    }
    map.insert("name".to_owned(), json!(name));
    let file = source
        .get("dictionary_metadata")
        .and_then(|meta| present(meta.get("original_file_name")))
        .cloned()
        .unwrap_or_else(|| json!("keywords.txt"));
    map.insert("original_file_name".to_owned(), file);
    if let Some(region) = source.get("region_name") {
        map.insert("region_name".to_owned(), region.clone());
    }
    for key in ["description", "is_case_sensitive", "tags"] {
        if let Some(value) = present(source.get(key)) {
            map.insert(key.to_owned(), value.clone());
        }
    }
    let metadata = Value::Object(map);
    let parsed = scm::dlp::models::DictionaryRequest::parse(
        metadata.clone(),
        scm::validation::Mode::Request,
    );
    match parsed {
        Ok(request) if super::body::file_name_ok(&request.original_file_name) => Ok(metadata),
        _ => Err(format!(
            "Dictionary cannot be rebuilt from the backup: {}",
            source_name(source)
        )),
    }
}

/// TS `patternRequest`: the create body of a backed-up pattern under `name`.
pub fn pattern_request(source: &Value, name: &str) -> Result<Value, String> {
    let mut map = Map::new();
    map.insert("name".to_owned(), json!(name));
    for key in ["type", "detection_config"] {
        if let Some(value) = source.get(key) {
            map.insert(key.to_owned(), value.clone());
        }
    }
    for key in ["matching_rules", "description", "tags"] {
        if let Some(value) = present(source.get(key)) {
            map.insert(key.to_owned(), value.clone());
        }
    }
    let body = Value::Object(map);
    scm::dlp::models::DataPatternRequest::parse(body.clone(), scm::validation::Mode::Request)
        .map(|_| body)
        .map_err(|_| {
            format!(
                "Data pattern cannot be rebuilt from the backup: {}",
                source_name(source)
            )
        })
}

fn source_name(record: &Value) -> String {
    match record.get("name") {
        Some(Value::String(name)) => name.clone(),
        _ => "undefined".to_owned(),
    }
}

fn technique(record: &Value) -> Option<&str> {
    record
        .get("detection_config")
        .and_then(|config| config.get("technique"))
        .and_then(Value::as_str)
}

fn id_of(record: &Value) -> Option<&str> {
    record
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

fn name_of(record: &Value) -> Option<&str> {
    record
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
}

/// TS `normalizedName`.
fn normalized(name: &str) -> String {
    let lowered = name.to_lowercase();
    let mut out = String::new();
    let mut gap = false;
    for c in lowered.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if gap {
                out.push(' ');
                gap = false;
            }
            out.push(c);
        } else {
            gap = true;
        }
    }
    if gap {
        out.push(' ');
    }
    out.trim().to_owned()
}

/// TS `predefinedCandidates`: up to 3 active same-technique predefined destination
/// patterns whose normalised name equals (2) or contains, or is contained in (1), the
/// source's; best first, then by name. Suggestions only.
pub fn predefined_candidates(source: &Value, records: &[Value]) -> Vec<String> {
    let wanted = normalized(name_of(source).unwrap_or_default());
    let mut scored: BTreeMap<String, u8> = BTreeMap::new();
    for record in records {
        let Some(name) = record.get("name").and_then(Value::as_str) else {
            continue;
        };
        if !predefined(record) || retired_pattern(record) || technique(record) != technique(source)
        {
            continue;
        }
        let have = normalized(name);
        let score = if have == wanted {
            2
        } else if have.contains(&wanted) || wanted.contains(&have) {
            1
        } else {
            0
        };
        if score > 0 {
            let best = scored.entry(name.to_owned()).or_insert(0);
            *best = (*best).max(score);
        }
    }
    let mut ranked: Vec<(String, u8)> = scored.into_iter().collect();
    ranked.sort_by(|(a, x), (b, y)| y.cmp(x).then_with(|| crate::report::locale_order(a, b)));
    ranked.into_iter().take(3).map(|(name, _)| name).collect()
}

/// TS `matchByName`: the one destination record named `name` that `retired` keeps;
/// several are `Ambiguous destination <label> name: <name>`.
fn match_by_name<'a>(
    records: &'a [Value],
    name: &str,
    retired: impl Fn(&Value) -> bool,
    label: &str,
) -> Result<Option<&'a Value>, String> {
    let matches: Vec<&Value> = records
        .iter()
        .filter(|record| {
            record.get("name").and_then(Value::as_str) == Some(name) && !retired(record)
        })
        .collect();
    if matches.len() > 1 {
        return Err(format!("Ambiguous destination {label} name: {name}"));
    }
    Ok(matches.first().copied())
}

/// The name-match rule of `resource` (dictionaries have no lifecycle filter).
pub fn destination_match<'a>(
    destination: &'a Destination,
    resource: backup::Resource,
    name: &str,
) -> Result<Option<&'a Value>, String> {
    match resource {
        backup::Resource::Dictionaries => {
            match_by_name(&destination.dictionaries, name, |_| false, "dictionary")
        }
        backup::Resource::Patterns => {
            match_by_name(&destination.patterns, name, retired_pattern, "data pattern")
        }
        backup::Resource::Profiles => {
            match_by_name(&destination.profiles, name, retired_profile, "data profile")
        }
    }
}

/// Whether a key names a reference to another tenant's resource (TS
/// `/(?:^|[-_])(id|uuid)$|(?:Id|ID|Uuid|UUID)$/`).
fn reference_key(key: &str) -> bool {
    for tail in ["id", "uuid"] {
        if let Some(head) = key.strip_suffix(tail)
            && (head.is_empty() || head.ends_with(['-', '_']))
        {
            return true;
        }
    }
    ["Id", "ID", "Uuid", "UUID"]
        .iter()
        .any(|tail| key.ends_with(tail))
}

/// TS `assertKnownReferences`: no non-empty id-like key outside the rule leaves'
/// `id` (the paths of `known`, relative to `body`).
fn assert_known_references(
    body: &Value,
    known: &[Vec<PathStep>],
    label: &str,
) -> Result<(), String> {
    fn visit(
        value: &Value,
        path: &str,
        steps: &mut Vec<PathStep>,
        known: &[Vec<PathStep>],
        label: &str,
    ) -> Result<(), String> {
        match value {
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    steps.push(PathStep::Index(index));
                    visit(item, &format!("{path}[{index}]"), steps, known, label)?;
                    steps.pop();
                }
            }
            Value::Object(map) => {
                let is_known = known.iter().any(|leaf| leaf == steps);
                for (key, child) in map {
                    let empty = child.is_null() || child.as_str() == Some("");
                    if !empty && reference_key(key) && !(is_known && key == "id") {
                        return Err(format!(
                            "Unsupported cross-tenant reference in {label} at {path}.{key}"
                        ));
                    }
                    steps.push(PathStep::Key(key.clone()));
                    visit(child, &format!("{path}.{key}"), steps, known, label)?;
                    steps.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(body, label, &mut Vec::new(), known, label)
}

/// TS `assertLeafBinding`.
fn assert_leaf_binding(leaf: &Leaf, binding: &Binding) -> Result<(), String> {
    let leaf_dictionary = leaf.technique == "dictionary";
    if leaf_dictionary != binding.dictionary
        || binding.technique.as_deref() != Some(leaf.technique.as_str())
    {
        return Err(
            "Data profile rule detection technique does not match its dependency".to_owned(),
        );
    }
    Ok(())
}

/// TS `planBindings`: the bindings known at plan time (every row but the creates).
pub fn plan_bindings(plan: &RestorePlan) -> BTreeMap<String, Binding> {
    let mut bindings = BTreeMap::new();
    for row in &plan.dictionaries {
        if let Some(id) = row.existing.as_ref().and_then(id_of) {
            bindings.insert(
                row.source_id.clone(),
                Binding {
                    dictionary: true,
                    technique: Some("dictionary".to_owned()),
                    id: id.to_owned(),
                    name: row.name.clone(),
                    version: Some(json!(1)),
                },
            );
        }
    }
    for row in &plan.patterns {
        if let Some(existing) = &row.existing
            && let Some(id) = id_of(existing)
        {
            bindings.insert(
                row.source_id.clone(),
                Binding {
                    dictionary: false,
                    technique: technique(existing).map(str::to_owned),
                    id: id.to_owned(),
                    name: row.name.clone(),
                    version: present(existing.get("version")).cloned(),
                },
            );
        }
    }
    bindings
}

/// The UTF-16 length of a name (the live 32-unit profile limit).
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// TS `profileRequest`: the remapped create body of a profile row; `None` while a
/// still-to-create dependency has no binding (`require` false), otherwise every binding
/// must exist.
pub fn profile_request(
    row: &ProfilePlan,
    bindings: &BTreeMap<String, Binding>,
    cross_tenant: bool,
    require: bool,
) -> Result<Option<Value>, String> {
    let create = row.action == ProfileAction::Create;
    if create && utf16_len(&row.name) > 32 {
        return Err("Data profile name exceeds the live API limit of 32 characters".to_owned());
    }
    if create && row.source.get("profile_type").and_then(Value::as_str) == Some("basic") {
        return Err("Data profile basic writes cannot round-trip through the API".to_owned());
    }
    let rules = present(row.source.get("detection_rules"));
    if create && rules.and_then(Value::as_array).is_none_or(Vec::is_empty) {
        return Err("Data profile has no exported detection rules to create".to_owned());
    }
    let mut detection_rules = rules.cloned().unwrap_or_else(|| json!([]));
    let leaves = rule_leaves(Some(&detection_rules))?;
    let mut deferred = false;
    for leaf in &leaves {
        let id = match present(leaf.item.get("id")) {
            None => continue,
            Some(Value::String(id)) if id.is_empty() => continue,
            Some(Value::String(id)) => id.clone(),
            Some(other) => other.to_string(),
        };
        let version = present(leaf.item.get("version"));
        if leaf.technique == "dictionary"
            && version.is_some_and(|version| version.as_f64() != Some(1.0))
        {
            return Err("Dictionary rule has an unsupported version pin".to_owned());
        }
        let Some(binding) = bindings.get(&id) else {
            if require {
                return Err(format!(
                    "Missing planned dependency binding; an existing data profile cannot be verified without its destination dependencies: {}",
                    row.name
                ));
            }
            deferred = true;
            continue;
        };
        assert_leaf_binding(leaf, binding)?;
        let Some(item) = at_path(&mut detection_rules, &leaf.path) else {
            continue;
        };
        item["id"] = json!(binding.id);
        if present(item.get("name")).is_some() {
            item["name"] = json!(binding.name);
        }
        if present(item.get("version")).is_some() {
            let Some(version) = &binding.version else {
                return Err(format!(
                    "Destination data pattern version is unknown: {}",
                    binding.name
                ));
            };
            item["version"] = version.clone();
        }
    }
    let mut map = Map::new();
    map.insert("name".to_owned(), json!(row.name));
    map.insert("detection_rules".to_owned(), detection_rules);
    for key in ["profile_type", "description", "is_granular_data_profile"] {
        if let Some(value) = present(row.source.get(key)) {
            map.insert(key.to_owned(), value.clone());
        }
    }
    let body = Value::Object(map);
    if cross_tenant {
        // The leaves' own ids are understood references (paths relative to the body).
        let known: Vec<Vec<PathStep>> = leaves
            .iter()
            .map(|leaf| {
                let mut path = vec![PathStep::Key("detection_rules".to_owned())];
                path.extend(leaf.path.iter().cloned());
                path
            })
            .collect();
        assert_known_references(&body, &known, &format!("profile {}", row.name))?;
    }
    scm::dlp::models::AdvancedDataProfileRequest::parse(
        body.clone(),
        scm::validation::Mode::Request,
    )
    .map_err(|_| SCHEMA_TEXT.to_owned())?;
    Ok((!deferred).then_some(body))
}

/// A rebuilt request that fails its SDK schema (TS `ZodError` in the plan).
pub const SCHEMA_TEXT: &str = "Invalid DLP backup/request schema; content is not logged.";

/// The deterministic reconcile suffix (D177): the first 6 lowercase hex digits of
/// SHA-256 over `<backup tsgId>:<source profile id>`.
pub fn reconcile_suffix(tsg: &str, source_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{tsg}:{source_id}").as_bytes());
    digest
        .iter()
        .take(3)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// TS `suffixedProfileName`: `<base>-<suffix>`, the base cut so the result fits 32
/// UTF-16 units.
pub fn suffixed_profile_name(name: &str, suffix: &str) -> String {
    let tail = format!("-{suffix}");
    let room = 32usize.saturating_sub(utf16_len(&tail));
    let (base, _) = crate::render::utf16_prefix(name, room);
    format!("{base}{tail}")
}

/// The validation of a backup before any request (TS, the start of
/// `planDlpResourcesRestore`): unique, control-free names per kind and unique dependency
/// ids across dictionaries and patterns.
pub fn prevalidate(backup: &Backup) -> Result<(), String> {
    for (resource, label) in [
        (backup::Resource::Dictionaries, "dictionary"),
        (backup::Resource::Patterns, "data pattern"),
        (backup::Resource::Profiles, "data profile"),
    ] {
        unique_names(
            backup
                .entries(resource)
                .iter()
                .map(|entry| Some(entry.name.as_str())),
            label,
        )?;
    }
    let mut ids = BTreeSet::new();
    for entry in backup.dictionaries.iter().chain(&backup.patterns) {
        if entry.id.is_empty() {
            continue;
        }
        if !ids.insert(entry.id.clone()) {
            return Err("Backup contains duplicate dependency identities".to_owned());
        }
    }
    Ok(())
}

/// `--pattern-map names absent from the backup: <a>, <b>` (TS), when a map source is not
/// a backup pattern name.
pub fn absent_map_names(backup: &Backup, options: &Options) -> Option<String> {
    let absent: Vec<&str> = options
        .pattern_map
        .iter()
        .map(|(source, _)| source.as_str())
        .filter(|source| !backup.patterns.iter().any(|entry| entry.name == *source))
        .collect();
    (!absent.is_empty()).then(|| {
        format!(
            "--pattern-map names absent from the backup: {}",
            absent.join(", ")
        )
    })
}

/// TS `planDlpResourcesRestore` after its inventory reads: the rows, the bindings and
/// the profile checks (D177's reconcile lookup added). The error is the TS message.
pub fn plan(
    backup: &Backup,
    destination_tsg: &str,
    destination: &Destination,
    options: &Options,
) -> Result<RestorePlan, String> {
    let prefix = options.prefix.as_str();
    let cross_tenant = backup.tsg_id != destination_tsg;
    let source_records = |entries: &[backup::Entry]| -> Vec<Value> {
        entries
            .iter()
            .map(|entry| value_of(&entry.record))
            .collect()
    };
    let dictionaries = source_records(&backup.dictionaries);
    let patterns = source_records(&backup.patterns);
    let profiles = source_records(&backup.profiles);
    let mut source_bindings: BTreeMap<String, Binding> = BTreeMap::new();
    for record in &dictionaries {
        if let Some(id) = id_of(record) {
            source_bindings.insert(
                id.to_owned(),
                Binding {
                    dictionary: true,
                    technique: Some("dictionary".to_owned()),
                    id: id.to_owned(),
                    name: name_of(record).unwrap_or_default().to_owned(),
                    version: Some(json!(1)),
                },
            );
        }
    }
    for record in &patterns {
        if let Some(id) = id_of(record) {
            source_bindings.insert(
                id.to_owned(),
                Binding {
                    dictionary: false,
                    technique: technique(record).map(str::to_owned),
                    id: id.to_owned(),
                    name: name_of(record).unwrap_or_default().to_owned(),
                    version: present(record.get("version")).cloned(),
                },
            );
        }
    }
    let source_tenant = backup::tenant_identity(patterns.iter().chain(&profiles))?;
    let destination_tenant =
        backup::tenant_identity(destination.patterns.iter().chain(&destination.profiles))?;
    if let (Some(source), Some(target)) = (&source_tenant, &destination_tenant) {
        if cross_tenant && source == target {
            return Err("Destination credentials report the source DLP tenant; check the selected tenant before restoring".to_owned());
        }
        if !cross_tenant && source != target {
            return Err("Destination DLP tenant does not match the backup source; use distinct tenant credentials deliberately".to_owned());
        }
    }
    let mut unresolved: Vec<Unresolved> = Vec::new();
    let safe = |name: &str| crate::output::terminal_safe(name).into_owned();

    // Dictionaries.
    let mut dictionary_rows = Vec::new();
    for source in &dictionaries {
        let (Some(source_id), Some(source_name)) = (id_of(source), name_of(source)) else {
            return Err("Backup dictionary lacks identity".to_owned());
        };
        if predefined(source) {
            let found = destination_match(destination, backup::Resource::Dictionaries, source_name)
                .map_err(|error| safe(&error))?;
            match found.filter(|record| id_of(record).is_some() && predefined(record)) {
                Some(found) => dictionary_rows.push(DictionaryPlan {
                    source_id: source_id.to_owned(),
                    name: source_name.to_owned(),
                    action: DependencyAction::Resolve,
                    metadata: None,
                    keywords: Vec::new(),
                    existing: Some(found.clone()),
                }),
                None if options.skip_unresolved => unresolved.push(Unresolved {
                    kind: "dictionary",
                    source_id: source_id.to_owned(),
                    name: source_name.to_owned(),
                    reason: "missing predefined destination dictionary".to_owned(),
                    candidates: Vec::new(),
                }),
                None => {
                    return Err(format!(
                        "Missing predefined destination dictionary: {}",
                        safe(source_name)
                    ));
                }
            }
            continue;
        }
        let name = format!("{prefix}{source_name}");
        if !valid_name(&name) {
            return Err(backup::NAME_RULE.to_owned());
        }
        let metadata = dictionary_request(source, &name).map_err(|error| safe(&error))?;
        let Some(keywords) = keyword_set(source.get("keywords")) else {
            return Err(format!(
                "Backup dictionary lacks keywords: {}",
                safe(source_name)
            ));
        };
        let found = destination_match(destination, backup::Resource::Dictionaries, &name)
            .map_err(|error| safe(&error))?;
        match found {
            None => {
                dictionary_file(&metadata, &keywords)?;
                dictionary_rows.push(DictionaryPlan {
                    source_id: source_id.to_owned(),
                    name,
                    action: DependencyAction::Create,
                    metadata: Some(metadata),
                    keywords,
                    existing: None,
                });
            }
            Some(found) => {
                if id_of(found).is_none() {
                    return Err(format!(
                        "Destination dictionary has no identity: {}",
                        safe(&name)
                    ));
                }
                let mut echoed = found.clone();
                if let (Some(id), Value::Object(map)) = (id_of(found), &mut echoed)
                    && let Some(words) = destination.keywords.get(id)
                {
                    map.insert("keywords".to_owned(), words.clone());
                }
                if !dictionary_echo(&metadata, Some(&echoed), &keywords).matches() {
                    return Err(format!(
                        "Destination dictionary differs: {}; use --name-prefix to avoid changing a shared dictionary",
                        safe(&name)
                    ));
                }
                dictionary_rows.push(DictionaryPlan {
                    source_id: source_id.to_owned(),
                    name,
                    action: DependencyAction::Reuse,
                    metadata: Some(metadata),
                    keywords,
                    existing: Some(found.clone()),
                });
            }
        }
    }

    // Patterns.
    let mut pattern_rows = Vec::new();
    let mut missing_predefined: Vec<(String, Vec<String>)> = Vec::new();
    for source in &patterns {
        let (Some(source_id), Some(source_name)) = (id_of(source), name_of(source)) else {
            return Err("Backup data pattern lacks identity".to_owned());
        };
        let mapped = options.mapped(source_name);
        if predefined(source) && mapped.is_none() {
            let by_id = destination.patterns.iter().find(|record| {
                id_of(record) == Some(source_id)
                    && predefined(record)
                    && !retired_pattern(record)
                    && technique(record) == technique(source)
            });
            let found = match by_id {
                Some(found) => Some(found),
                None => destination_match(destination, backup::Resource::Patterns, source_name)
                    .map_err(|error| safe(&error))?,
            };
            let usable = found.filter(|record| {
                id_of(record).is_some() && name_of(record).is_some() && predefined(record)
            });
            let Some(found) = usable else {
                let candidates = predefined_candidates(source, &destination.patterns);
                if options.skip_unresolved {
                    unresolved.push(Unresolved {
                        kind: "pattern",
                        source_id: source_id.to_owned(),
                        name: source_name.to_owned(),
                        reason: "no identity or name match in the destination catalog".to_owned(),
                        candidates,
                    });
                } else {
                    missing_predefined.push((source_name.to_owned(), candidates));
                }
                continue;
            };
            if technique(source).is_none() || technique(found) != technique(source) {
                return Err(format!(
                    "Destination data pattern detection technique differs: {}",
                    safe(source_name)
                ));
            }
            pattern_rows.push(PatternPlan {
                source_id: source_id.to_owned(),
                name: name_of(found).unwrap_or_default().to_owned(),
                action: DependencyAction::Resolve,
                body: None,
                existing: Some(found.clone()),
            });
            continue;
        }
        if let Some(target) = mapped {
            let found = destination_match(destination, backup::Resource::Patterns, target)
                .map_err(|error| safe(&error))?;
            let Some(found) = found.filter(|record| id_of(record).is_some()) else {
                return Err(format!(
                    "Missing mapped destination data pattern: {}",
                    safe(target)
                ));
            };
            if technique(source).is_none() || technique(found) != technique(source) {
                return Err(format!(
                    "Mapped destination data pattern detection technique differs: {}",
                    safe(target)
                ));
            }
            pattern_rows.push(PatternPlan {
                source_id: source_id.to_owned(),
                name: target.to_owned(),
                action: DependencyAction::Map,
                body: None,
                existing: Some(found.clone()),
            });
            continue;
        }
        let portable = matches!(
            technique(source),
            Some("regex" | "weighted_regex" | "file_property")
        );
        if !portable {
            if options.skip_unresolved {
                unresolved.push(Unresolved {
                    kind: "pattern",
                    source_id: source_id.to_owned(),
                    name: source_name.to_owned(),
                    reason: "tenant-bound detection technique without --pattern-map".to_owned(),
                    candidates: Vec::new(),
                });
                continue;
            }
            let shown = safe(source_name);
            return Err(format!(
                "Data pattern uses a tenant-bound detection technique: {shown}; provision it in the destination and bind it with --pattern-map \"{shown}=<destination-name>\""
            ));
        }
        let regexes = source
            .get("matching_rules")
            .and_then(|rules| rules.get("regexes"))
            .and_then(Value::as_array)
            .is_some_and(|regexes| !regexes.is_empty());
        if matches!(technique(source), Some("regex" | "weighted_regex")) && !regexes {
            if options.skip_unresolved {
                unresolved.push(Unresolved {
                    kind: "pattern",
                    source_id: source_id.to_owned(),
                    name: source_name.to_owned(),
                    reason: "detection content is not exported by the API (copy of a predefined pattern)".to_owned(),
                    candidates: Vec::new(),
                });
                continue;
            }
            let shown = safe(source_name);
            return Err(format!(
                "Data pattern has no exported detection content (a copy of a predefined pattern): {shown}; bind an equivalent with --pattern-map \"{shown}=<destination-name>\" or exclude dependents with --skip-unresolved"
            ));
        }
        let name = format!("{prefix}{source_name}");
        if !valid_name(&name) {
            return Err(backup::NAME_RULE.to_owned());
        }
        let body = pattern_request(source, &name).map_err(|error| safe(&error))?;
        if cross_tenant {
            assert_known_references(&body, &[], &format!("pattern {source_name}"))
                .map_err(|error| safe(&error))?;
        }
        let found = destination_match(destination, backup::Resource::Patterns, &name)
            .map_err(|error| safe(&error))?;
        match found {
            None => pattern_rows.push(PatternPlan {
                source_id: source_id.to_owned(),
                name,
                action: DependencyAction::Create,
                body: Some(body),
                existing: None,
            }),
            Some(found) => {
                if id_of(found).is_none() {
                    return Err(format!(
                        "Destination data pattern has no identity: {}",
                        safe(&name)
                    ));
                }
                if !compare_echo(&body, Some(found)).matches() {
                    return Err(format!(
                        "Destination data pattern differs: {}; use --name-prefix to avoid changing a shared pattern",
                        safe(&name)
                    ));
                }
                pattern_rows.push(PatternPlan {
                    source_id: source_id.to_owned(),
                    name,
                    action: DependencyAction::Reuse,
                    body: Some(body),
                    existing: Some(found.clone()),
                });
            }
        }
    }
    if !missing_predefined.is_empty() {
        let parts: Vec<String> = missing_predefined
            .iter()
            .map(|(name, candidates)| {
                if candidates.is_empty() {
                    format!("{} (no candidates)", safe(name))
                } else {
                    let quoted: Vec<String> = candidates
                        .iter()
                        .map(|candidate| format!("\"{}\"", safe(candidate)))
                        .collect();
                    format!("{} (candidates: {})", safe(name), quoted.join(", "))
                }
            })
            .collect();
        return Err(format!(
            "Missing predefined destination data patterns: {}; bind each with --pattern-map \"<source-name>=<destination-name>\"",
            parts.join("; ")
        ));
    }

    // Profiles.
    let mut profile_rows = Vec::new();
    for source in &profiles {
        let Some(source_name) = name_of(source) else {
            return Err("Backup data profile lacks identity".to_owned());
        };
        if predefined(source) {
            return Err("Backup contains a predefined data profile".to_owned());
        }
        let name = format!("{prefix}{source_name}");
        if !valid_name(&name) {
            return Err(backup::NAME_RULE.to_owned());
        }
        let source_id = id_of(source).unwrap_or_default().to_owned();
        let found = destination_match(destination, backup::Resource::Profiles, &name)
            .map_err(|error| safe(&error))?;
        if found.is_some() && options.conflict == Conflict::Error {
            return Err(format!(
                "Destination data profile already exists: {}; choose --on-conflict verify or skip",
                safe(&name)
            ));
        }
        if found.is_some_and(|record| id_of(record).is_none()) {
            return Err(format!(
                "Destination data profile has no identity: {}",
                safe(&name)
            ));
        }
        let mut row = ProfilePlan {
            name: name.clone(),
            renamed_from: None,
            source_id: source_id.clone(),
            source: source.clone(),
            action: match (found, options.conflict) {
                (None, _) => ProfileAction::Create,
                (Some(_), Conflict::Skip) => ProfileAction::Skip,
                (Some(_), _) => ProfileAction::Verify,
            },
            existing: found.cloned(),
            reason: None,
        };
        // D177: an earlier reconcile run's suffixed copy is verified, never created again.
        if found.is_none() && options.conflict == Conflict::Reconcile {
            let suffixed =
                suffixed_profile_name(&name, &reconcile_suffix(&backup.tsg_id, &source_id));
            let copy = destination_match(destination, backup::Resource::Profiles, &suffixed)
                .map_err(|error| safe(&error))?;
            if let Some(copy) = copy {
                if id_of(copy).is_none() {
                    return Err(format!(
                        "Destination data profile has no identity: {}",
                        safe(&suffixed)
                    ));
                }
                row.renamed_from = Some(name);
                row.name = suffixed;
                row.action = ProfileAction::Verify;
                row.existing = Some(copy.clone());
            }
        }
        profile_rows.push(row);
    }

    let mut plan = RestorePlan {
        source_tsg: backup.tsg_id.clone(),
        destination_tsg: destination_tsg.to_owned(),
        dictionaries: dictionary_rows,
        patterns: pattern_rows,
        profiles: profile_rows,
        unresolved,
        reconcile: options.conflict == Conflict::Reconcile,
    };
    let bindings = plan_bindings(&plan);
    let planned: BTreeSet<&str> = plan
        .dictionaries
        .iter()
        .map(|row| row.source_id.as_str())
        .chain(plan.patterns.iter().map(|row| row.source_id.as_str()))
        .collect();
    let unresolved_by_id: BTreeMap<&str, &str> = plan
        .unresolved
        .iter()
        .map(|item| (item.source_id.as_str(), item.name.as_str()))
        .collect();
    // Dependencies the backup could not store (D175): unresolved for their profiles.
    let failed_by_id: BTreeMap<&str, (&str, &str)> = backup
        .failed
        .iter()
        .filter(|row| row.kind == "dictionary" || row.kind == "pattern")
        .map(|row| {
            let kind = if row.kind == "dictionary" {
                "dictionary"
            } else {
                "data pattern"
            };
            (row.id.as_str(), (kind, row.name.as_str()))
        })
        .collect();
    let mut updates: Vec<(usize, Option<String>)> = Vec::new();
    for (index, row) in plan.profiles.iter().enumerate() {
        if row.action == ProfileAction::Skip {
            continue;
        }
        let mut missing: Vec<String> = Vec::new();
        for leaf in rule_leaves(row.source.get("detection_rules")).map_err(|error| safe(&error))? {
            let id = match present(leaf.item.get("id")) {
                None => continue,
                Some(Value::String(id)) if id.is_empty() => continue,
                Some(Value::String(id)) => id.clone(),
                Some(_) => {
                    return Err("Backup contains a non-string rule reference ID".to_owned());
                }
            };
            if let Some(binding) = source_bindings.get(&id) {
                assert_leaf_binding(&leaf, binding)?;
                if let Some(version) = present(leaf.item.get("version"))
                    && !binding
                        .version
                        .as_ref()
                        .is_some_and(|held| strictly_equal(held, version))
                {
                    return Err("Backup rule pins an unknown source dependency version".to_owned());
                }
            }
            if !planned.contains(id.as_str()) && !missing.contains(&id) {
                missing.push(id);
            }
        }
        if !missing.is_empty() {
            let failed: Vec<&(&str, &str)> = missing
                .iter()
                .filter_map(|id| failed_by_id.get(id.as_str()))
                .collect();
            if !failed.is_empty() && !options.skip_unresolved {
                return Err(format!(
                    "Backup data profile references a resource that could not be backed up: {}",
                    safe(&row.name)
                ));
            }
            let skippable: Vec<&str> = missing
                .iter()
                .filter_map(|id| unresolved_by_id.get(id.as_str()).copied())
                .collect();
            if skippable.len() + failed.len() == missing.len() {
                let mut parts = Vec::new();
                if !skippable.is_empty() {
                    parts.push(format!("unresolved references: {}", skippable.join(", ")));
                }
                for (kind, name) in failed {
                    parts.push(format!("its {kind} {name} could not be backed up"));
                }
                updates.push((index, Some(parts.join("; "))));
                continue;
            }
            return Err(format!(
                "Backup data profile references a resource absent from the backup: {}",
                safe(&row.name)
            ));
        }
        let body = profile_request(
            row,
            &bindings,
            cross_tenant,
            row.action == ProfileAction::Verify,
        )
        .map_err(|error| safe(&error))?;
        if row.action == ProfileAction::Verify
            && let Some(body) = &body
            && !compare_echo(body, row.existing.as_ref()).matches()
        {
            return Err(format!(
                "Destination data profile does not match restore plan: {}; verification made no changes",
                safe(&row.name)
            ));
        }
    }
    for (index, reason) in updates {
        plan.profiles[index].action = ProfileAction::Skip;
        plan.profiles[index].reason = reason;
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlp::backup::Entry;

    fn o(value: &Value) -> crate::json::OValue {
        crate::json::parse(&value.to_string()).unwrap()
    }

    fn entry(record: Value) -> Entry {
        Entry {
            id: record["id"].as_str().unwrap_or_default().to_owned(),
            name: record["name"].as_str().unwrap_or_default().to_owned(),
            predefined: predefined(&record),
            record: o(&record),
        }
    }

    fn options() -> Options {
        Options {
            prefix: String::new(),
            conflict: Conflict::Error,
            pattern_map: Vec::new(),
            skip_unresolved: false,
        }
    }

    fn dictionary() -> Value {
        json!({"id": "src-dict-1", "name": "Secret Words", "description": "kw dict", "category": "Confidential",
            "region_name": "United States", "type": "custom", "is_case_sensitive": false,
            "dictionary_metadata": {"number_of_keywords": 2, "original_file_name": "words.txt"},
            "keywords": ["PRIVATE-KW-BRAVO", "PRIVATE-KW-ALPHA"], "tenant_id": null})
    }

    fn pattern() -> Value {
        json!({"id": "src-pat-1", "name": "Custom Regex", "description": "regex pat", "tenant_id": "src-tenant",
            "type": "custom", "status": "active", "version": 2,
            "detection_config": {"technique": "regex", "supported_confidence_levels": ["high"]},
            "matching_rules": {"regexes": [{"regex": "PRIVATE-REGEX-[0-9]{6}", "weight": 1}]}})
    }

    fn predefined_pattern() -> Value {
        json!({"id": "src-pat-pre", "name": "Social Security Numbers", "type": "predefined", "version": 3,
            "detection_config": {"technique": "ml"}})
    }

    fn legal() -> Value {
        json!({"id": "src-dict-pre", "name": "Legal Terms", "type": "predefined"})
    }

    fn profile() -> Value {
        json!({"id": "src-prof-1", "name": "PII Guardrail", "description": "prof", "tenant_id": "src-tenant",
        "type": "custom", "profile_status": "active", "profile_type": "advanced", "version": 4,
        "detection_rules": [{"rule_type": "expression_tree", "expression_tree": {"operator_type": "or",
            "sub_expressions": [
                {"rule_item": {"detection_technique": "regex", "id": "src-pat-1", "name": "Custom Regex", "version": 2, "match_type": "include", "confidence_level": "high", "occurrence_operator_type": "any"}},
                {"rule_item": {"detection_technique": "ml", "id": "src-pat-pre", "name": "Social Security Numbers", "version": 3, "match_type": "include", "confidence_level": "high", "occurrence_operator_type": "any"}},
                {"rule_item": {"detection_technique": "dictionary", "id": "src-dict-pre", "name": "Legal Terms", "match_type": "include", "confidence_level": "high", "occurrence_operator_type": "any"}},
                {"rule_item": {"detection_technique": "dictionary", "id": "src-dict-1", "name": "Secret Words", "match_type": "include", "confidence_level": "high", "occurrence_operator_type": "any"}}
            ]}}]})
    }

    fn backup_of(dictionaries: Vec<Value>, patterns: Vec<Value>, profiles: Vec<Value>) -> Backup {
        Backup {
            exported_at: "2026-10-18T12:00:00.000Z".into(),
            tenant: "src".into(),
            tsg_id: "100".into(),
            dlp_tenant_id: None,
            resources: backup::Resource::ALL.to_vec(),
            dictionaries: dictionaries.into_iter().map(entry).collect(),
            patterns: patterns.into_iter().map(entry).collect(),
            profiles: profiles.into_iter().map(entry).collect(),
            skipped: Vec::new(),
            failed: Vec::new(),
        }
    }

    fn standard() -> Backup {
        backup_of(
            vec![legal(), dictionary()],
            vec![pattern(), predefined_pattern()],
            vec![profile()],
        )
    }

    fn destination() -> Destination {
        Destination {
            dictionaries: vec![
                json!({"id": "dst-dict-pre", "name": "Legal Terms", "type": "predefined"}),
            ],
            patterns: vec![
                json!({"id": "dst-pat-pre", "name": "Social Security Numbers", "type": "predefined",
                "version": 7, "status": "active", "tenant_id": "dst-tenant", "detection_config": {"technique": "ml"}}),
            ],
            profiles: vec![],
            keywords: BTreeMap::new(),
        }
    }

    fn actions(plan: &RestorePlan) -> Vec<(String, &'static str)> {
        plan.dictionaries
            .iter()
            .map(|row| (row.name.clone(), row.action.word()))
            .chain(
                plan.patterns
                    .iter()
                    .map(|row| (row.name.clone(), row.action.word())),
            )
            .chain(
                plan.profiles
                    .iter()
                    .map(|row| (row.name.clone(), row.action.word())),
            )
            .collect()
    }

    /// TS DR-spec "stage plan": resolve the predefined, create the custom, with the
    /// prefix on custom names only.
    #[test]
    fn plans_every_stage_with_the_prefix_on_custom_names() {
        let mut opts = options();
        opts.prefix = "migrated-".into();
        let plan = plan(&standard(), "200", &destination(), &opts).unwrap();
        assert_eq!(
            actions(&plan),
            [
                ("Legal Terms".to_owned(), "resolve"),
                ("migrated-Secret Words".to_owned(), "create"),
                ("migrated-Custom Regex".to_owned(), "create"),
                ("Social Security Numbers".to_owned(), "resolve"),
                ("migrated-PII Guardrail".to_owned(), "create"),
            ]
        );
        assert_eq!(plan.creates(), 3);
        assert_eq!(
            plan.dictionaries[1].keywords,
            ["PRIVATE-KW-ALPHA", "PRIVATE-KW-BRAVO"]
        );
        assert_eq!(
            plan.dictionaries[1].metadata,
            Some(
                json!({"category": "Confidential", "name": "migrated-Secret Words", "original_file_name": "words.txt",
                "region_name": "United States", "description": "kw dict", "is_case_sensitive": false})
            )
        );
        assert_eq!(
            plan.patterns[0].body,
            Some(
                json!({"name": "migrated-Custom Regex", "type": "custom", "description": "regex pat",
                "detection_config": {"technique": "regex", "supported_confidence_levels": ["high"]},
                "matching_rules": {"regexes": [{"regex": "PRIVATE-REGEX-[0-9]{6}", "weight": 1}]}})
            )
        );
        // The bindings remap the predefined ids and versions; the created ones defer.
        let mut bindings = plan_bindings(&plan);
        assert!(
            profile_request(&plan.profiles[0], &bindings, true, false)
                .unwrap()
                .is_none()
        );
        for (source, id, name) in [
            ("src-dict-1", "d-new", "migrated-Secret Words"),
            ("src-pat-1", "p-new", "migrated-Custom Regex"),
        ] {
            bindings.insert(
                source.into(),
                Binding {
                    dictionary: source.contains("dict"),
                    technique: Some(
                        if source.contains("dict") {
                            "dictionary"
                        } else {
                            "regex"
                        }
                        .into(),
                    ),
                    id: id.into(),
                    name: name.into(),
                    version: Some(json!(1)),
                },
            );
        }
        let body = profile_request(&plan.profiles[0], &bindings, true, true)
            .unwrap()
            .unwrap();
        let leaves: Vec<&Value> = body["detection_rules"][0]["expression_tree"]["sub_expressions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|leaf| &leaf["rule_item"])
            .collect();
        assert_eq!(
            (leaves[0]["id"].clone(), leaves[0]["version"].clone()),
            (json!("p-new"), json!(1))
        );
        assert_eq!(
            (leaves[1]["id"].clone(), leaves[1]["version"].clone()),
            (json!("dst-pat-pre"), json!(7))
        );
        assert_eq!(leaves[1]["name"], "Social Security Numbers");
        assert_eq!(leaves[2]["id"], "dst-dict-pre");
        assert_eq!(leaves[3]["name"], "migrated-Secret Words");
        assert_eq!(body["name"], "migrated-PII Guardrail");
        assert_eq!(body["profile_type"], "advanced");
    }

    #[test]
    fn predefined_misses_report_ranked_candidates_at_once() {
        let mut dest = destination();
        dest.patterns = vec![
            json!({"id": "x1", "name": "SSN - Social Security Numbers (US)", "type": "predefined", "detection_config": {"technique": "ml"}}),
            json!({"id": "x2", "name": "social-security-numbers", "type": "predefined", "detection_config": {"technique": "ml"}}),
            json!({"id": "x3", "name": "Social Security Numbers v2", "type": "predefined", "detection_config": {"technique": "regex"}}),
            json!({"id": "x4", "name": "Numbers", "type": "predefined", "status": "deleted", "detection_config": {"technique": "ml"}}),
        ];
        let mut other = predefined_pattern();
        other["id"] = json!("src-pat-2");
        other["name"] = json!("Bank Accounts");
        let backup = backup_of(vec![legal()], vec![predefined_pattern(), other], vec![]);
        assert_eq!(
            plan(&backup, "200", &dest, &options()).unwrap_err(),
            "Missing predefined destination data patterns: Social Security Numbers (candidates: \"social-security-numbers\", \"SSN - Social Security Numbers (US)\"); Bank Accounts (no candidates); bind each with --pattern-map \"<source-name>=<destination-name>\""
        );
        let mut opts = options();
        opts.skip_unresolved = true;
        let skipped = plan(&backup, "200", &dest, &opts).unwrap();
        assert_eq!(skipped.unresolved.len(), 2);
        assert_eq!(skipped.unresolved[0].candidates.len(), 2);
        // The same id beats the name.
        let mut by_id = destination();
        by_id.patterns[0]["id"] = json!("src-pat-pre");
        by_id.patterns[0]["name"] = json!("Renamed SSN");
        let backup = backup_of(vec![], vec![predefined_pattern()], vec![]);
        let resolved = plan(&backup, "200", &by_id, &options()).unwrap();
        assert_eq!(actions(&resolved), [("Renamed SSN".to_owned(), "resolve")]);
        // A technique mismatch by name.
        let mut mismatch = destination();
        mismatch.patterns[0]["detection_config"]["technique"] = json!("regex");
        assert_eq!(
            plan(&backup, "200", &mismatch, &options()).unwrap_err(),
            "Destination data pattern detection technique differs: Social Security Numbers"
        );
    }

    #[test]
    fn pattern_maps_bind_predefined_and_tenant_bound_patterns() {
        let mut edm = pattern();
        edm["id"] = json!("src-edm");
        edm["name"] = json!("EDM SSN");
        edm["detection_config"]["technique"] = json!("edm");
        let mut dest = destination();
        dest.patterns.push(json!({"id": "dst-edm", "name": "Dest SSN", "type": "custom", "detection_config": {"technique": "edm"}}));
        let backup = backup_of(vec![], vec![edm.clone(), predefined_pattern()], vec![]);
        assert_eq!(
            plan(&backup, "200", &dest, &options()).unwrap_err(),
            "Data pattern uses a tenant-bound detection technique: EDM SSN; provision it in the destination and bind it with --pattern-map \"EDM SSN=<destination-name>\""
        );
        let mut opts = options();
        opts.pattern_map = vec![("EDM SSN".into(), "Dest SSN".into())];
        let mapped = plan(&backup, "200", &dest, &opts).unwrap();
        assert_eq!(mapped.patterns[0].action, DependencyAction::Map);
        assert_eq!(mapped.patterns[0].name, "Dest SSN");
        opts.pattern_map = vec![("EDM SSN".into(), "Nope".into())];
        assert_eq!(
            plan(&backup, "200", &dest, &opts).unwrap_err(),
            "Missing mapped destination data pattern: Nope"
        );
        opts.pattern_map = vec![("Social Security Numbers".into(), "Dest SSN".into())];
        assert_eq!(
            plan(&backup, "200", &dest, &opts)
                .unwrap_err()
                .split(':')
                .next(),
            Some("Data pattern uses a tenant-bound detection technique")
        );
        let mut absent = options();
        absent.pattern_map = vec![("Ghost".into(), "x".into()), ("Spook".into(), "y".into())];
        assert_eq!(
            absent_map_names(&backup, &absent).as_deref(),
            Some("--pattern-map names absent from the backup: Ghost, Spook")
        );
        // Copies of predefined patterns export no content.
        let mut copy = pattern();
        copy["matching_rules"] = json!({"regexes": null});
        let backup = backup_of(vec![], vec![copy], vec![]);
        assert!(plan(&backup, "200", &destination(), &options()).unwrap_err().starts_with(
            "Data pattern has no exported detection content (a copy of a predefined pattern): Custom Regex;"
        ));
    }

    #[test]
    fn existing_dependencies_are_reused_only_when_they_echo() {
        let mut dest = destination();
        let mut same = pattern();
        same["id"] = json!("dst-pat-1");
        same["tenant_id"] = json!("dst-tenant");
        same["detection_config"]["supported_confidence_levels"] = json!(["high", "low"]);
        dest.patterns.push(same.clone());
        let mut existing_dictionary = dictionary();
        existing_dictionary["id"] = json!("dst-dict-1");
        existing_dictionary
            .as_object_mut()
            .unwrap()
            .remove("keywords");
        dest.dictionaries.push(existing_dictionary.clone());
        assert_eq!(keyword_reads(&standard(), &dest, ""), ["dst-dict-1"]);
        dest.keywords.insert(
            "dst-dict-1".into(),
            json!(["PRIVATE-KW-ALPHA", "PRIVATE-KW-BRAVO"]),
        );
        let plan_ok = plan(&standard(), "200", &dest, &{
            let mut opts = options();
            opts.conflict = Conflict::Verify;
            opts
        })
        .unwrap();
        assert_eq!(plan_ok.dictionaries[1].action, DependencyAction::Reuse);
        assert_eq!(plan_ok.patterns[0].action, DependencyAction::Reuse);
        let mut differs = dest.clone();
        differs.patterns[1]["description"] = json!("changed");
        assert_eq!(
            plan(&standard(), "200", &differs, &options()).unwrap_err(),
            "Destination data pattern differs: Custom Regex; use --name-prefix to avoid changing a shared pattern"
        );
        let mut differs = dest.clone();
        differs
            .keywords
            .insert("dst-dict-1".into(), json!(["OTHER"]));
        assert_eq!(
            plan(&standard(), "200", &differs, &options()).unwrap_err(),
            "Destination dictionary differs: Secret Words; use --name-prefix to avoid changing a shared dictionary"
        );
        // A retired same-name pattern is ignored (created anew); two active ones are ambiguous.
        let mut retired = dest.clone();
        retired.patterns[1]["status"] = json!("deleted");
        let created = plan(&standard(), "200", &retired, &options()).unwrap();
        assert_eq!(created.patterns[0].action, DependencyAction::Create);
        let mut twice = dest.clone();
        twice.patterns.push(same);
        assert_eq!(
            plan(&standard(), "200", &twice, &options()).unwrap_err(),
            "Ambiguous destination data pattern name: Custom Regex"
        );
    }

    #[test]
    fn profile_conflicts_follow_the_policy_and_reconcile_is_deterministic() {
        let mut dest = destination();
        let existing = json!({"id": "dst-prof", "name": "PII Guardrail", "type": "custom", "profile_status": "active"});
        dest.profiles.push(existing);
        let backup = backup_of(
            vec![legal()],
            vec![predefined_pattern()],
            vec![{
                let mut p = profile();
                let leaves = p["detection_rules"][0]["expression_tree"]["sub_expressions"]
                    .as_array_mut()
                    .unwrap();
                leaves.retain(|leaf| {
                    leaf["rule_item"]["id"] != "src-pat-1"
                        && leaf["rule_item"]["id"] != "src-dict-1"
                });
                p
            }],
        );
        assert_eq!(
            plan(&backup, "200", &dest, &options()).unwrap_err(),
            "Destination data profile already exists: PII Guardrail; choose --on-conflict verify or skip"
        );
        let mut opts = options();
        opts.conflict = Conflict::Skip;
        assert_eq!(
            plan(&backup, "200", &dest, &opts).unwrap().profiles[0].action,
            ProfileAction::Skip
        );
        opts.conflict = Conflict::Verify;
        assert_eq!(
            plan(&backup, "200", &dest, &opts).unwrap_err(),
            "Destination data profile does not match restore plan: PII Guardrail; verification made no changes"
        );
        // Reconcile looks the deterministic suffixed name up.
        let suffix = reconcile_suffix("100", "src-prof-1");
        assert_eq!(suffix.len(), 6);
        assert_eq!(suffix, reconcile_suffix("100", "src-prof-1"));
        assert_ne!(suffix, reconcile_suffix("200", "src-prof-1"));
        let suffixed = suffixed_profile_name("PII Guardrail", &suffix);
        assert_eq!(suffixed, format!("PII Guardrail-{suffix}"));
        opts.conflict = Conflict::Reconcile;
        let fresh = plan(&backup, "200", &destination(), &opts).unwrap();
        let mut copy = profile_request(&fresh.profiles[0], &plan_bindings(&fresh), true, true)
            .unwrap()
            .unwrap();
        copy["name"] = json!(suffixed);
        copy["id"] = json!("dst-copy");
        let mut reconcile = destination();
        reconcile.profiles.push(copy);
        let planned = plan(&backup, "200", &reconcile, &opts).unwrap();
        assert_eq!(planned.profiles[0].action, ProfileAction::Verify);
        assert_eq!(
            planned.profiles[0].renamed_from.as_deref(),
            Some("PII Guardrail")
        );
        assert_eq!(planned.creates(), 0);
        assert_eq!(fresh.profiles[0].action, ProfileAction::Create);
        assert!(fresh.reconcile);
        // The cut keeps the result within 32 UTF-16 units.
        let long = suffixed_profile_name(&"x".repeat(40), "abcdef");
        assert_eq!(utf16_len(&long), 32);
        assert!(long.ends_with("-abcdef"));
    }

    #[test]
    fn profile_rules_refuse_what_cannot_round_trip() {
        let mut opts = options();
        opts.prefix = "p".repeat(20);
        assert_eq!(
            plan(&standard(), "200", &destination(), &opts).unwrap_err(),
            "Data profile name exceeds the live API limit of 32 characters"
        );
        let mut basic = profile();
        basic["profile_type"] = json!("basic");
        let backup = backup_of(
            vec![legal(), dictionary()],
            vec![pattern(), predefined_pattern()],
            vec![basic],
        );
        assert_eq!(
            plan(&backup, "200", &destination(), &options()).unwrap_err(),
            "Data profile basic writes cannot round-trip through the API"
        );
        let mut absent = profile();
        absent["detection_rules"][0]["expression_tree"]["sub_expressions"][0]["rule_item"]["id"] =
            json!("ghost");
        let backup = backup_of(
            vec![legal(), dictionary()],
            vec![pattern(), predefined_pattern()],
            vec![absent],
        );
        assert_eq!(
            plan(&backup, "200", &destination(), &options()).unwrap_err(),
            "Backup data profile references a resource absent from the backup: PII Guardrail"
        );
        let mut pinned = profile();
        pinned["detection_rules"][0]["expression_tree"]["sub_expressions"][0]["rule_item"]["version"] =
            json!(9);
        let backup = backup_of(
            vec![legal(), dictionary()],
            vec![pattern(), predefined_pattern()],
            vec![pinned],
        );
        assert_eq!(
            plan(&backup, "200", &destination(), &options()).unwrap_err(),
            "Backup rule pins an unknown source dependency version"
        );
        let mut technique = profile();
        technique["detection_rules"][0]["expression_tree"]["sub_expressions"][0]["rule_item"]["detection_technique"] =
            json!("dictionary");
        let backup = backup_of(
            vec![legal(), dictionary()],
            vec![pattern(), predefined_pattern()],
            vec![technique],
        );
        assert_eq!(
            plan(&backup, "200", &destination(), &options()).unwrap_err(),
            "Data profile rule detection technique does not match its dependency"
        );
        // A cross-tenant id reference outside the leaves.
        let mut reference = pattern();
        reference["detection_config"]["edm_dataset_id"] = json!("e-1");
        let backup = backup_of(vec![], vec![reference], vec![]);
        assert_eq!(
            plan(&backup, "200", &destination(), &options()).unwrap_err(),
            "Unsupported cross-tenant reference in pattern Custom Regex at pattern Custom Regex.detection_config.edm_dataset_id"
        );
        // The same TSG allows it.
        assert!(plan(&backup, "100", &Destination::default(), &options()).is_ok());
    }

    #[test]
    fn unresolved_and_failed_dependencies_skip_whole_profiles() {
        let mut dest = destination();
        dest.dictionaries.clear();
        let mut opts = options();
        assert_eq!(
            plan(&standard(), "200", &dest, &opts).unwrap_err(),
            "Missing predefined destination dictionary: Legal Terms"
        );
        opts.skip_unresolved = true;
        let planned = plan(&standard(), "200", &dest, &opts).unwrap();
        assert_eq!(planned.profiles[0].action, ProfileAction::Skip);
        assert_eq!(
            planned.profiles[0].reason.as_deref(),
            Some("unresolved references: Legal Terms")
        );
        assert_eq!(
            planned.unresolved[0].reason,
            "missing predefined destination dictionary"
        );
        // A dictionary the backup could not store (D175).
        let mut failed = backup_of(
            vec![legal()],
            vec![pattern(), predefined_pattern()],
            vec![profile()],
        );
        failed.failed.push(backup::Failed {
            kind: "dictionary".into(),
            id: "src-dict-1".into(),
            name: "Secret Words".into(),
            error: "x".into(),
        });
        assert_eq!(
            plan(&failed, "200", &destination(), &options()).unwrap_err(),
            "Backup data profile references a resource that could not be backed up: PII Guardrail"
        );
        let skipped = plan(&failed, "200", &destination(), &opts).unwrap();
        assert_eq!(
            skipped.profiles[0].reason.as_deref(),
            Some("its dictionary Secret Words could not be backed up")
        );
    }

    #[test]
    fn tenant_identities_and_prevalidation() {
        let mut dest = destination();
        dest.patterns[0]["tenant_id"] = json!("src-tenant");
        assert_eq!(
            plan(&standard(), "200", &dest, &options()).unwrap_err(),
            "Destination credentials report the source DLP tenant; check the selected tenant before restoring"
        );
        assert_eq!(
            plan(&standard(), "100", &destination(), &options()).unwrap_err(),
            "Destination DLP tenant does not match the backup source; use distinct tenant credentials deliberately"
        );
        let mut dup = standard();
        dup.patterns[1].id = "src-dict-1".into();
        assert_eq!(
            prevalidate(&dup),
            Err("Backup contains duplicate dependency identities".into())
        );
        assert_eq!(prevalidate(&standard()), Ok(()));
    }

    #[test]
    fn compare_echo_unifies_null_and_reports_server_added_fields() {
        let echo = compare_echo(
            &json!({"name": "a", "detection_config": {"technique": "regex", "supported_confidence_levels": ["high"]}, "x": null}),
            Some(
                &json!({"name": "a", "id": "1", "status": "active", "extra": 1,
                "detection_config": {"technique": "regex", "supported_confidence_levels": ["high", "low"]}}),
            ),
        );
        assert!(echo.matches());
        assert_eq!(
            echo.server_added,
            [
                "body.detection_config.supported_confidence_levels",
                "body.extra"
            ]
        );
        assert!(!compare_echo(&json!({"a": [1, 2]}), Some(&json!({"a": [1]}))).matches());
        assert!(!compare_echo(&json!({"a": 1}), Some(&json!({"a": "1"}))).matches());
        assert!(compare_echo(&json!({"a": 1}), Some(&json!({"a": 1.0}))).matches());
        assert!(!compare_echo(&json!({"a": 1}), None).matches());
    }

    #[test]
    fn upload_text_rules() {
        let txt = json!({"original_file_name": "k.TXT"});
        let csv = json!({"original_file_name": "k.csv"});
        let words = |list: &[&str]| list.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            dictionary_file(&txt, &words(&["a", "b"])).unwrap(),
            "a\nb\n"
        );
        assert_eq!(
            dictionary_file(&csv, &words(&["a", "b"])).unwrap(),
            "keywords\na\nb\n"
        );
        assert_eq!(
            dictionary_file(&csv, &words(&["a,b"])).unwrap_err(),
            "Dictionary CSV contains unsupported multi-column keywords"
        );
        for bad in [&[][..], &["a\nb"], &[""]] {
            assert_eq!(
                dictionary_file(&txt, &words(bad)).unwrap_err(),
                "Dictionary contains keywords that cannot be faithfully uploaded"
            );
        }
        assert_eq!(
            dictionary_file(&json!({"original_file_name": "k.data"}), &words(&["a"])).unwrap_err(),
            "Dictionary filename must end in .csv or .txt for a verified upload"
        );
        assert_eq!(
            keyword_set(Some(&json!(["b", "a"]))),
            Some(words(&["a", "b"]))
        );
        assert_eq!(keyword_set(Some(&json!(["b", 1]))), None);
        let echo = dictionary_echo(
            &json!({"name": "n", "original_file_name": "k.txt"}),
            Some(
                &json!({"name": "n", "keywords": ["b", "a"], "dictionary_metadata": {"original_file_name": "k.txt"}}),
            ),
            &words(&["a", "b"]),
        );
        assert!(echo.matches());
        assert!(!dictionary_echo(
            &json!({"name": "n", "original_file_name": "k.txt"}),
            Some(&json!({"name": "n", "keywords": ["a", "b"], "dictionary_metadata": {"original_file_name": "other.txt"}})),
            &words(&["a", "b"]),
        ).matches());
    }

    #[test]
    fn reference_keys_follow_the_typescript_pattern() {
        for key in [
            "id",
            "uuid",
            "edm_dataset_id",
            "x-id",
            "fooId",
            "fooID",
            "barUuid",
            "barUUID",
            "a_uuid",
        ] {
            assert!(reference_key(key), "{key}");
        }
        for key in ["valid", "ids", "identity", "android", "Idx", "fluid"] {
            assert!(!reference_key(key), "{key}");
        }
    }
}
