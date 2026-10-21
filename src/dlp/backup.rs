//! The airs DLP backup (DESIGN §16.10, §16.11, D175, D176): the resource kinds of
//! a backup, the inventory sweep checks (`dlp::walk` inventory mode, TS `springPages`),
//! the selection with its dependency closure (TS `backupDlpResources`), the one-file
//! format (`airs-cli-rs.dlp-resources` version 1) and its strict reader with the
//! TypeScript-backup refusal. Pure: no I/O.

use std::collections::HashSet;

use crate::error::CliError;
use crate::json::OValue;
use serde_json::Value;

/// The `format` of a backup file.
pub const FORMAT: &str = "airs-cli-rs.dlp-resources";
/// The newest format version this build writes and reads.
pub const VERSION: u64 = 1;
/// The most records one inventory, and one kind of a backup, may hold (TS).
pub const MAX_RECORDS: usize = 10_000;
/// The largest backup file (TS, 20 MiB): written and read.
pub const MAX_BACKUP_BYTES: usize = 20 * 1_048_576;
/// The page size of every inventory request (TS).
pub const PAGE_SIZE: u32 = 100;
/// The default `--max-pages`.
pub const DEFAULT_MAX_PAGES: u64 = 100;

/// The three kinds a backup holds (filtering profiles are tenant configuration with no
/// create, and are neither backed up nor restored).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Resource {
    Dictionaries,
    Patterns,
    Profiles,
}

impl Resource {
    /// Canonical order.
    pub const ALL: [Self; 3] = [Self::Dictionaries, Self::Patterns, Self::Profiles];

    /// The `--resources` word and the file's array key (`dictionaries`, …).
    pub fn key(self) -> &'static str {
        match self {
            Self::Dictionaries => "dictionaries",
            Self::Patterns => "patterns",
            Self::Profiles => "profiles",
        }
    }

    /// The inventory and restore-stage label (`dictionaries`, `data patterns`, …).
    pub fn label(self) -> &'static str {
        match self {
            Self::Dictionaries => "dictionaries",
            Self::Patterns => "data patterns",
            Self::Profiles => "data profiles",
        }
    }

    /// One resource of the kind (`dictionary`, `data pattern`, `data profile`).
    pub fn singular(self) -> &'static str {
        match self {
            Self::Dictionaries => "dictionary",
            Self::Patterns => "data pattern",
            Self::Profiles => "data profile",
        }
    }

    /// The `kind` of a `skipped` or `failed` row (`dictionary`, `pattern`, `profile`).
    pub fn row_kind(self) -> &'static str {
        match self {
            Self::Dictionaries => "dictionary",
            Self::Patterns => "pattern",
            Self::Profiles => "profile",
        }
    }

    fn of_row_kind(kind: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|resource| resource.row_kind() == kind)
    }

    fn of_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|resource| resource.key() == key)
    }
}

/// `--resources <list>` (TS `resourceKinds`): split on `,`, items trimmed, each
/// `dictionaries`, `patterns` or `profiles`, none repeated; returned in canonical order.
pub fn parse_resources(text: &str) -> Result<Vec<Resource>, CliError> {
    let invalid =
        || CliError::usage("--resources takes a unique list of dictionaries, patterns, profiles");
    let mut kinds = Vec::new();
    for item in text.split(',').map(str::trim) {
        let kind = Resource::of_key(item).ok_or_else(invalid)?;
        if kinds.contains(&kind) {
            return Err(invalid());
        }
        kinds.push(kind);
    }
    kinds.sort();
    Ok(kinds)
}

// ---------------------------------------------------------------------------
// The inventory sweep (TS `springPages`, DESIGN §16.10 "Requests")
// ---------------------------------------------------------------------------

/// A metadata field of a page: absent, or present with a value of the wrong type (a
/// `null` included), which is inconsistent metadata (fail closed).
fn number_field(object: Option<&OValue>, key: &str) -> Result<Option<f64>, ()> {
    match object.and_then(|object| object.get(key)) {
        None => Ok(None),
        Some(OValue::Number(number)) => number.as_f64().map(Some).ok_or(()),
        Some(_) => Err(()),
    }
}

fn bool_field(object: &OValue, key: &str) -> Result<Option<bool>, ()> {
    match object.get(key) {
        None => Ok(None),
        Some(OValue::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(()),
    }
}

/// TS `alias`: two spellings of one field must agree; the camelCase one wins.
fn alias(camel: Option<f64>, snake: Option<f64>) -> Result<Option<f64>, ()> {
    match (camel, snake) {
        (Some(a), Some(b)) if a != b => Err(()),
        (Some(a), _) => Ok(Some(a)),
        (None, b) => Ok(b),
    }
}

/// `Number.isSafeInteger`.
fn safe_integer(value: f64) -> bool {
    value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0
}

/// Whether a sweep needs another page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    More,
    Done,
}

/// One inventory sweep of a kind: pages `0, 1, …`, each checked against every metadata
/// field it supplies (camelCase and snake_case alike), ids non-empty and unique, at most
/// [`MAX_RECORDS`] records (TS `springPages`).
#[derive(Debug)]
pub struct Sweep {
    label: &'static str,
    items: Vec<OValue>,
    ids: HashSet<String>,
    total_pages: Option<f64>,
    total_elements: Option<f64>,
    effective: Option<f64>,
}

impl Sweep {
    pub fn new(resource: Resource) -> Self {
        Self {
            label: resource.label(),
            items: Vec::new(),
            ids: HashSet::new(),
            total_pages: None,
            total_elements: None,
            effective: None,
        }
    }

    fn inconsistent(&self) -> String {
        format!(
            "Inventory of {} has inconsistent pagination metadata; retry the operation",
            self.label
        )
    }

    /// `Inventory of <label> is incomplete: increase --max-pages`.
    pub fn incomplete(&self) -> String {
        format!(
            "Inventory of {} is incomplete: increase --max-pages",
            self.label
        )
    }

    /// The records swept so far.
    pub fn into_items(self) -> Vec<OValue> {
        self.items
    }

    /// Checks page `page` (its answer as ordered JSON) and keeps its rows; `Done` at the
    /// last page. The error is the TS message (exit 1).
    pub fn accept(&mut self, page: u64, answer: &OValue) -> Result<Step, String> {
        let label = self.label;
        let bad = |()| {
            format!(
                "Inventory of {label} has inconsistent pagination metadata; retry the operation"
            )
        };
        let content = answer
            .get("content")
            .and_then(OValue::as_array)
            .ok_or_else(|| self.inconsistent())?;
        // A `pageable` that is not an object supplies nothing (TS optional chaining).
        let pageable = answer
            .get("pageable")
            .filter(|value| value.as_object().is_some());
        let length = content.len() as f64;
        // Page indexes are bounded by `--max-pages` (1000), so the cast is exact.
        #[allow(clippy::cast_precision_loss)]
        let index = page as f64;
        let page_size = alias(
            number_field(pageable, "pageSize").map_err(bad)?,
            number_field(pageable, "page_size").map_err(bad)?,
        )
        .map_err(bad)?;
        let supplied_size =
            alias(number_field(Some(answer), "size").map_err(bad)?, page_size).map_err(bad)?;
        if let Some(size) = supplied_size
            && (!safe_integer(size)
                || !(1.0..=100.0).contains(&size)
                || self.effective.is_some_and(|effective| effective != size))
        {
            return Err(self.inconsistent());
        }
        let effective = supplied_size.or(self.effective).unwrap_or(100.0);
        self.effective = Some(effective);
        let supplied_pages = alias(
            number_field(Some(answer), "totalPages").map_err(bad)?,
            number_field(Some(answer), "total_pages").map_err(bad)?,
        )
        .map_err(bad)?;
        let supplied_elements = alias(
            number_field(Some(answer), "totalElements").map_err(bad)?,
            number_field(Some(answer), "total_elements").map_err(bad)?,
        )
        .map_err(bad)?;
        if self.items.len() + content.len() > MAX_RECORDS {
            return Err(format!(
                "Inventory of {} exceeds the {MAX_RECORDS}-record safety limit",
                self.label
            ));
        }
        let numbers = [
            (number_field(Some(answer), "number").map_err(bad)?, index),
            (number_field(Some(answer), "size").map_err(bad)?, effective),
            (
                alias(
                    number_field(Some(answer), "numberOfElements").map_err(bad)?,
                    number_field(Some(answer), "number_of_elements").map_err(bad)?,
                )
                .map_err(bad)?,
                length,
            ),
            (
                alias(
                    number_field(pageable, "pageNumber").map_err(bad)?,
                    number_field(pageable, "page_number").map_err(bad)?,
                )
                .map_err(bad)?,
                index,
            ),
            (page_size, effective),
            (
                number_field(pageable, "offset").map_err(bad)?,
                index * effective,
            ),
        ];
        if numbers
            .iter()
            .any(|(actual, expected)| actual.is_some_and(|actual| actual != *expected))
        {
            return Err(self.inconsistent());
        }
        let first = bool_field(answer, "first").map_err(bad)?;
        let empty = bool_field(answer, "empty").map_err(bad)?;
        if first.is_some_and(|first| first != (page == 0))
            || empty.is_some_and(|empty| empty != content.is_empty())
        {
            return Err(self.inconsistent());
        }
        for (actual, previous) in [
            (supplied_pages, self.total_pages),
            (supplied_elements, self.total_elements),
        ] {
            if let Some(actual) = actual
                && (!safe_integer(actual)
                    || actual < 0.0
                    || previous.is_some_and(|previous| previous != actual))
            {
                return Err(self.inconsistent());
            }
        }
        self.total_pages = supplied_pages.or(self.total_pages);
        self.total_elements = supplied_elements.or(self.total_elements);
        if let (Some(pages), Some(elements)) = (self.total_pages, self.total_elements)
            && pages != (elements / effective).ceil()
        {
            return Err(self.inconsistent());
        }
        if let Some(pages) = self.total_pages
            && (index >= pages.max(1.0) || (pages == 0.0 && !content.is_empty()))
        {
            return Err(self.inconsistent());
        }
        if let Some(elements) = self.total_elements
            && length != effective.min((elements - index * effective).max(0.0))
        {
            return Err(self.inconsistent());
        }
        for item in content {
            let id = match item.get("id") {
                Some(OValue::String(id)) if !id.trim().is_empty() => id,
                _ => {
                    return Err(format!(
                        "Inventory of {} contains a missing resource ID; retry the operation",
                        self.label
                    ));
                }
            };
            if !self.ids.insert(id.clone()) {
                return Err(format!(
                    "Inventory of {} contains duplicate resource IDs; retry the operation",
                    self.label
                ));
            }
            self.items.push(item.clone());
        }
        #[allow(clippy::cast_precision_loss)]
        let swept = self.items.len() as f64;
        let expected_last = match (self.total_pages, self.total_elements) {
            (Some(pages), _) => Some(index + 1.0 >= pages),
            (None, Some(elements)) => Some(swept == elements),
            (None, None) => None,
        };
        let reported_last = bool_field(answer, "last").map_err(bad)?;
        if let (Some(reported), Some(expected)) = (reported_last, expected_last)
            && reported != expected
        {
            return Err(self.inconsistent());
        }
        let last = reported_last
            .or(expected_last)
            .unwrap_or(length < effective);
        if let Some(pages) = self.total_pages
            && pages > 0.0
            && ((!last && length != effective) || (last && content.is_empty()))
        {
            return Err(self.inconsistent());
        }
        if last {
            if self
                .total_elements
                .is_some_and(|elements| swept != elements)
            {
                return Err(self.inconsistent());
            }
            return Ok(Step::Done);
        }
        if content.is_empty() {
            return Err(format!("Inventory of {} did not advance", self.label));
        }
        Ok(Step::More)
    }
}

/// The uniform DLP `tenant_id` of `records` (TS `tenantIdentity`): more than one
/// distinct non-null value is `Inventory reports mixed DLP tenant identities`.
pub fn tenant_identity<'a>(
    records: impl IntoIterator<Item = &'a Value>,
) -> Result<Option<String>, String> {
    let mut seen: Vec<String> = Vec::new();
    for record in records {
        match record.get("tenant_id") {
            None | Some(Value::Null) => {}
            Some(value) => {
                let text = value.to_string();
                if !seen.contains(&text) {
                    seen.push(text);
                }
            }
        }
    }
    if seen.len() > 1 {
        return Err("Inventory reports mixed DLP tenant identities".to_owned());
    }
    Ok(seen
        .first()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| value.as_str().map(str::to_owned)))
}

// ---------------------------------------------------------------------------
// Shared record rules
// ---------------------------------------------------------------------------

/// The ordered-record conversion and the TypeScript YAML sniffer, feature-neutral in
/// `crate::json` and `crate::files` (re-exported for the DLP backup).
pub use crate::files::typescript_yaml;
pub use crate::json::value_of;
/// The JSON path steps and the `--max-pages` rule, feature-neutral in `crate::json` and
/// `crate::pagination` (re-exported for the DLP backup).
pub use crate::json::{PathStep, at_path};
pub use crate::pagination::parse_max_pages;

/// `type == "predefined"`.
pub fn predefined(record: &Value) -> bool {
    record.get("type").and_then(Value::as_str) == Some("predefined")
}

/// Patterns and profiles whose lifecycle state is `deleted` or `disabled` (an absent or
/// `null` state is active).
pub fn retired_pattern(record: &Value) -> bool {
    matches!(
        record.get("status").and_then(Value::as_str),
        Some("deleted" | "disabled")
    )
}

/// [`retired_pattern`] for a profile's `profile_status`.
pub fn retired_profile(record: &Value) -> bool {
    matches!(
        record.get("profile_status").and_then(Value::as_str),
        Some("deleted" | "disabled")
    )
}

/// TS `assertName`: non-empty after trim, no C0 control and no DEL.
pub fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && !name.chars().any(|c| (c as u32) < 32 || c as u32 == 127)
}

/// `DLP resource names must be nonempty and contain no control characters`.
pub const NAME_RULE: &str = "DLP resource names must be nonempty and contain no control characters";

/// TS `uniqueNames` over the names of `records` (`<label>` `dictionary`, `data pattern`,
/// `data profile`).
pub fn unique_names<'a>(
    names: impl IntoIterator<Item = Option<&'a str>>,
    label: &str,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for name in names {
        let Some(name) = name.filter(|name| !name.is_empty()) else {
            return Err(format!("Backup contains a {label} without a name"));
        };
        if !valid_name(name) {
            return Err(NAME_RULE.to_owned());
        }
        if !seen.insert(name) {
            return Err(format!("Backup contains duplicate {label} names: {name}"));
        }
    }
    Ok(())
}

/// One expression-tree leaf of a profile's detection rules.
#[derive(Clone, Debug, PartialEq)]
pub struct Leaf {
    /// The `rule_item` object.
    pub item: Value,
    pub technique: String,
    /// The path of the leaf within `detection_rules` (for remapping).
    pub path: Vec<PathStep>,
}

/// TS `ruleLeaves`: every `rule_item` of every `expression_tree` rule, in order. A rule
/// that is not an object, a rule type other than `expression_tree`, a tree deeper than
/// 100 and a leaf without a string technique are errors (the TS texts).
pub fn rule_leaves(rules: Option<&Value>) -> Result<Vec<Leaf>, String> {
    fn visit(
        node: &Value,
        depth: usize,
        path: &mut Vec<PathStep>,
        leaves: &mut Vec<Leaf>,
    ) -> Result<(), String> {
        if depth > 100 {
            return Err("Unsupported detection rule: expression tree too deep".to_owned());
        }
        let Some(object) = node.as_object() else {
            return Ok(());
        };
        if let Some(item) = object.get("rule_item").filter(|item| item.is_object()) {
            let Some(technique) = item.get("detection_technique").and_then(Value::as_str) else {
                return Err(
                    "Unsupported detection rule: leaf without a detection technique".to_owned(),
                );
            };
            let mut at = path.clone();
            at.push(PathStep::Key("rule_item".to_owned()));
            leaves.push(Leaf {
                item: item.clone(),
                technique: technique.to_owned(),
                path: at,
            });
        }
        if let Some(children) = object.get("sub_expressions").and_then(Value::as_array) {
            for (index, child) in children.iter().enumerate() {
                path.push(PathStep::Key("sub_expressions".to_owned()));
                path.push(PathStep::Index(index));
                visit(child, depth + 1, path, leaves)?;
                path.pop();
                path.pop();
            }
        }
        Ok(())
    }
    let mut leaves = Vec::new();
    let Some(rules) = rules.and_then(Value::as_array) else {
        return Ok(leaves);
    };
    for (index, rule) in rules.iter().enumerate() {
        let Some(object) = rule.as_object() else {
            return Err("Unsupported detection rule shape".to_owned());
        };
        match object.get("rule_type") {
            Some(Value::String(kind)) if kind == "expression_tree" => {}
            other => {
                let shown = match other {
                    None => "undefined".to_owned(),
                    Some(Value::String(text)) => text.clone(),
                    Some(value) => value.to_string(),
                };
                return Err(format!("Unsupported detection rule type: {shown}"));
            }
        }
        let mut path = vec![
            PathStep::Index(index),
            PathStep::Key("expression_tree".to_owned()),
        ];
        if let Some(tree) = object.get("expression_tree") {
            visit(tree, 0, &mut path, &mut leaves)?;
        }
    }
    Ok(leaves)
}

// ---------------------------------------------------------------------------
// Selection (TS `backupDlpResources`, DESIGN §16.10 "Selection")
// ---------------------------------------------------------------------------

/// One stored record of a backup.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub predefined: bool,
    pub record: OValue,
}

/// A profile excluded under `--skip-unsupported`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub kind: String,
    pub id: String,
    pub name: String,
    pub reason: String,
}

/// A record that could not be backed up (a dictionary whose keywords were not read).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failed {
    pub kind: String,
    pub id: String,
    pub name: String,
    pub error: String,
}

/// The three inventories, as the service returned them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Inventory {
    pub dictionaries: Vec<OValue>,
    pub patterns: Vec<OValue>,
    pub profiles: Vec<OValue>,
}

/// What a backup selected: the entries per kind (custom dictionaries still without
/// their keywords, which are read per dictionary next), the skipped profiles and the
/// uniform DLP tenant id.
#[derive(Clone, Debug, PartialEq)]
pub struct Selection {
    pub dictionaries: Vec<Entry>,
    pub patterns: Vec<Entry>,
    pub profiles: Vec<Entry>,
    pub skipped: Vec<Skipped>,
    pub tenant_id: Option<String>,
}

fn text_of(record: &Value, key: &str) -> Option<String> {
    record.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// The predefined stub of a dictionary (`{id, name, type}`, TS).
fn dictionary_stub(record: &OValue) -> OValue {
    let mut entries = Vec::new();
    for key in ["id", "name", "type"] {
        if let Some(value) = record.get(key) {
            entries.push((key.to_owned(), value.clone()));
        }
    }
    OValue::Object(entries)
}

/// The predefined stub of a pattern (`{id, name, type, version?, detection_config?:
/// {technique}}`, TS).
fn pattern_stub(record: &OValue) -> OValue {
    let mut entries = Vec::new();
    for key in ["id", "name", "type"] {
        if let Some(value) = record.get(key) {
            entries.push((key.to_owned(), value.clone()));
        }
    }
    if let Some(version) = record.get("version").filter(|v| !matches!(v, OValue::Null)) {
        entries.push(("version".to_owned(), version.clone()));
    }
    let technique = record
        .get("detection_config")
        .and_then(|config| config.get("technique"));
    if let Some(technique) = technique.filter(|technique| match technique {
        OValue::String(text) => !text.is_empty(),
        OValue::Null => false,
        OValue::Bool(value) => *value,
        OValue::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        _ => true,
    }) {
        entries.push((
            "detection_config".to_owned(),
            OValue::Object(vec![("technique".to_owned(), technique.clone())]),
        ));
    }
    OValue::Object(entries)
}

fn entry_of(record: OValue) -> Entry {
    let plain = value_of(&record);
    Entry {
        id: text_of(&plain, "id").unwrap_or_default(),
        name: text_of(&plain, "name").unwrap_or_default(),
        predefined: predefined(&plain),
        record,
    }
}

/// The dependencies one profile adds (committed only when the profile passes).
#[derive(Default)]
struct Dependencies {
    dictionaries: Vec<usize>,
    patterns: Vec<usize>,
}

/// The per-profile checks of TB§4.2 (TS order); the dependencies on success.
fn profile_dependencies(
    profile: &Value,
    dictionaries: &[Value],
    patterns: &[Value],
) -> Result<Dependencies, String> {
    let rules = profile.get("detection_rules");
    if rules
        .and_then(Value::as_array)
        .is_none_or(|rules| rules.is_empty())
    {
        return Err(
            "has no exported detection rules (the API does not expose basic data profile content)"
                .to_owned(),
        );
    }
    let mut found = Dependencies::default();
    for leaf in rule_leaves(rules)? {
        let id = match leaf.item.get("id") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) if id.is_empty() => None,
            Some(value) => Some(value),
        };
        let Some(id) = id else {
            if leaf
                .item
                .get("edm_dataset_id")
                .is_some_and(|value| !value.is_null())
            {
                return Err("references an EDM dataset directly".to_owned());
            }
            continue;
        };
        let Some(id) = id.as_str() else {
            return Err("has a non-string rule reference id".to_owned());
        };
        let version = leaf.item.get("version").filter(|value| !value.is_null());
        if leaf.technique == "dictionary" {
            let Some(index) = dictionaries
                .iter()
                .position(|record| record.get("id").and_then(Value::as_str) == Some(id))
            else {
                return Err(format!("references an unknown dictionary: {id}"));
            };
            if version.is_some_and(|version| version.as_f64() != Some(1.0)) {
                return Err(format!("references a version-pinned dictionary: {id}"));
            }
            found.dictionaries.push(index);
        } else {
            let Some(index) = patterns
                .iter()
                .position(|record| record.get("id").and_then(Value::as_str) == Some(id))
            else {
                return Err(format!("references an unknown data pattern: {id}"));
            };
            let record = &patterns[index];
            let technique = record
                .get("detection_config")
                .and_then(|config| config.get("technique"))
                .and_then(Value::as_str);
            if technique != Some(leaf.technique.as_str()) {
                return Err(
                    "references a data pattern with a different detection technique".to_owned(),
                );
            }
            if retired_pattern(record) {
                let name = text_of(record, "name").unwrap_or_else(|| id.to_owned());
                return Err(format!("references a retired data pattern: {name}"));
            }
            if let Some(version) = version {
                let held = record.get("version").filter(|value| !value.is_null());
                if !held.is_some_and(|held| numbers_equal(held, version)) {
                    let shown = |value: Option<&Value>| match value {
                        Some(Value::Number(number)) => crate::render::js_json_number(number),
                        Some(Value::String(text)) => text.clone(),
                        Some(other) => other.to_string(),
                        None => "unknown".to_owned(),
                    };
                    return Err(format!(
                        "references data pattern version {}, but the catalog holds version {}: {id}",
                        shown(Some(version)),
                        shown(held)
                    ));
                }
            }
            found.patterns.push(index);
        }
    }
    Ok(found)
}

/// JavaScript `===` for two JSON values (numbers by value).
pub fn numbers_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (x, y) => x == y,
    }
}

/// Selects the backup of `kinds` from `inventory` (TB§4.2): primaries by kind (custom,
/// patterns and profiles not retired), each kept profile's dependencies (predefined ones
/// as stubs), the profile checks (without `skip_unsupported` every failing profile fails
/// the run at once), the sort by name and the name rules. The error is the TS message.
pub fn select(
    inventory: &Inventory,
    kinds: &[Resource],
    skip_unsupported: bool,
) -> Result<Selection, String> {
    let plain = |records: &[OValue]| records.iter().map(value_of).collect::<Vec<Value>>();
    let dictionaries = plain(&inventory.dictionaries);
    let patterns = plain(&inventory.patterns);
    let profiles = plain(&inventory.profiles);
    let tenant_id = tenant_identity(patterns.iter().chain(&profiles))?;
    // Indexes into the inventories, in first-added order.
    let mut chosen_dictionaries: Vec<usize> = Vec::new();
    let mut chosen_patterns: Vec<usize> = Vec::new();
    let add = |list: &mut Vec<usize>, index: usize| {
        if !list.contains(&index) {
            list.push(index);
        }
    };
    if kinds.contains(&Resource::Dictionaries) {
        for (index, record) in dictionaries.iter().enumerate() {
            if !predefined(record) {
                add(&mut chosen_dictionaries, index);
            }
        }
    }
    if kinds.contains(&Resource::Patterns) {
        for (index, record) in patterns.iter().enumerate() {
            if !predefined(record) && !retired_pattern(record) {
                add(&mut chosen_patterns, index);
            }
        }
    }
    let mut chosen_profiles: Vec<usize> = Vec::new();
    let mut skipped = Vec::new();
    if kinds.contains(&Resource::Profiles) {
        for (index, profile) in profiles.iter().enumerate() {
            if predefined(profile) || retired_profile(profile) {
                continue;
            }
            match profile_dependencies(profile, &dictionaries, &patterns) {
                Ok(found) => {
                    for index in found.dictionaries {
                        add(&mut chosen_dictionaries, index);
                    }
                    for index in found.patterns {
                        add(&mut chosen_patterns, index);
                    }
                    chosen_profiles.push(index);
                }
                Err(reason) => skipped.push(Skipped {
                    kind: Resource::Profiles.row_kind().to_owned(),
                    id: text_of(profile, "id").unwrap_or_default(),
                    name: text_of(profile, "name").unwrap_or_else(|| "(unnamed)".to_owned()),
                    reason,
                }),
            }
        }
        if !skipped.is_empty() && !skip_unsupported {
            let reasons: Vec<String> = skipped
                .iter()
                .map(|item| {
                    format!(
                        "{} ({})",
                        crate::output::terminal_safe(&item.name),
                        item.reason
                    )
                })
                .collect();
            return Err(format!(
                "Profiles cannot be exported: {}; exclude unsupported profiles explicitly with --skip-unsupported",
                reasons.join("; ")
            ));
        }
    }
    let by_name = |entries: &mut Vec<Entry>| {
        entries.sort_by(|a, b| crate::report::locale_order(&a.name, &b.name));
    };
    let mut dictionary_entries: Vec<Entry> = chosen_dictionaries
        .iter()
        .map(|&index| {
            let record = &inventory.dictionaries[index];
            if predefined(&dictionaries[index]) {
                entry_of(dictionary_stub(record))
            } else {
                entry_of(record.clone())
            }
        })
        .collect();
    let mut pattern_entries: Vec<Entry> = chosen_patterns
        .iter()
        .map(|&index| {
            let record = &inventory.patterns[index];
            if predefined(&patterns[index]) {
                entry_of(pattern_stub(record))
            } else {
                entry_of(record.clone())
            }
        })
        .collect();
    let mut profile_entries: Vec<Entry> = chosen_profiles
        .iter()
        .map(|&index| entry_of(inventory.profiles[index].clone()))
        .collect();
    by_name(&mut dictionary_entries);
    by_name(&mut pattern_entries);
    by_name(&mut profile_entries);
    let names = |entries: &[Entry]| -> Vec<Option<String>> {
        entries
            .iter()
            .map(|entry| {
                entry
                    .record
                    .get("name")
                    .and_then(OValue::as_str)
                    .map(str::to_owned)
            })
            .collect()
    };
    for (entries, label) in [
        (&dictionary_entries, "dictionary"),
        (&pattern_entries, "data pattern"),
        (&profile_entries, "data profile"),
    ] {
        let names = names(entries);
        unique_names(names.iter().map(Option::as_deref), label)
            .map_err(|message| crate::output::terminal_safe(&message).into_owned())?;
    }
    if dictionary_entries.is_empty() && pattern_entries.is_empty() && profile_entries.is_empty() {
        return Err("No matching DLP resources to back up".to_owned());
    }
    Ok(Selection {
        dictionaries: dictionary_entries,
        patterns: pattern_entries,
        profiles: profile_entries,
        skipped,
        tenant_id,
    })
}

// ---------------------------------------------------------------------------
// The file (DESIGN §16.10 "Format")
// ---------------------------------------------------------------------------

/// A backup file.
#[derive(Clone, Debug, PartialEq)]
pub struct Backup {
    pub exported_at: String,
    pub tenant: String,
    pub tsg_id: String,
    pub dlp_tenant_id: Option<String>,
    pub resources: Vec<Resource>,
    pub dictionaries: Vec<Entry>,
    pub patterns: Vec<Entry>,
    pub profiles: Vec<Entry>,
    pub skipped: Vec<Skipped>,
    pub failed: Vec<Failed>,
}

fn text(value: &str) -> OValue {
    OValue::String(value.to_owned())
}

impl Backup {
    /// `complete`: nothing skipped and nothing failed.
    pub fn complete(&self) -> bool {
        self.skipped.is_empty() && self.failed.is_empty()
    }

    /// The entries of `resource`.
    pub fn entries(&self, resource: Resource) -> &[Entry] {
        match resource {
            Resource::Dictionaries => &self.dictionaries,
            Resource::Patterns => &self.patterns,
            Resource::Profiles => &self.profiles,
        }
    }

    /// The document, keys in the §16.10 order.
    pub fn document(&self) -> OValue {
        let entries = |entries: &[Entry]| {
            OValue::Array(
                entries
                    .iter()
                    .map(|entry| {
                        OValue::Object(vec![
                            ("id".into(), text(&entry.id)),
                            ("name".into(), text(&entry.name)),
                            ("predefined".into(), OValue::Bool(entry.predefined)),
                            ("record".into(), entry.record.clone()),
                        ])
                    })
                    .collect(),
            )
        };
        OValue::Object(vec![
            ("format".into(), text(FORMAT)),
            ("version".into(), OValue::Number(VERSION.into())),
            ("exportedAt".into(), text(&self.exported_at)),
            ("tenant".into(), text(&self.tenant)),
            ("tsgId".into(), text(&self.tsg_id)),
            (
                "dlpTenantId".into(),
                self.dlp_tenant_id.as_deref().map_or(OValue::Null, text),
            ),
            (
                "resources".into(),
                OValue::Array(self.resources.iter().map(|r| text(r.key())).collect()),
            ),
            ("complete".into(), OValue::Bool(self.complete())),
            ("dictionaries".into(), entries(&self.dictionaries)),
            ("patterns".into(), entries(&self.patterns)),
            ("profiles".into(), entries(&self.profiles)),
            (
                "skipped".into(),
                OValue::Array(
                    self.skipped
                        .iter()
                        .map(|item| {
                            OValue::Object(vec![
                                ("kind".into(), text(&item.kind)),
                                ("id".into(), text(&item.id)),
                                ("name".into(), text(&item.name)),
                                ("reason".into(), text(&item.reason)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "failed".into(),
                OValue::Array(
                    self.failed
                        .iter()
                        .map(|item| {
                            OValue::Object(vec![
                                ("kind".into(), text(&item.kind)),
                                ("id".into(), text(&item.id)),
                                ("name".into(), text(&item.name)),
                                ("error".into(), text(&item.error)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    /// The file bytes: the 2-space JSON document and one newline.
    pub fn to_text(&self) -> String {
        let mut text = crate::json::to_pretty(&self.document()).unwrap_or_default();
        text.push('\n');
        text
    }
}

/// Why a file is not a restorable airs DLP backup (fixed texts, never content).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadFailure {
    /// Not JSON (the D44 classes included).
    Malformed,
    /// A TypeScript airs-cli backup (JSON or the `--file-format yaml` envelope).
    TypeScript,
    /// The format of a newer version of airs.
    Newer,
    /// Any other break of the format, with its reason.
    Invalid(String),
}

/// The envelope keys; nothing else is allowed.
const ENVELOPE: [&str; 12] = [
    "format",
    "version",
    "exportedAt",
    "tenant",
    "tsgId",
    "dlpTenantId",
    "resources",
    "complete",
    "dictionaries",
    "patterns",
    "profiles",
    "skipped",
];

/// Whether `object` has exactly `keys` (each a string value).
fn exact_strings(object: &OValue, keys: &[&str]) -> bool {
    let Some(fields) = object.as_object() else {
        return false;
    };
    fields.len() == keys.len()
        && keys
            .iter()
            .all(|key| matches!(object.get(key), Some(OValue::String(_))))
}

/// Parses a backup file strictly; `valid(resource, record)` checks a stored record with
/// the SDK response schema of its kind.
pub fn parse(text: &str, valid: impl Fn(Resource, &OValue) -> bool) -> Result<Backup, ReadFailure> {
    let document = crate::json::parse(text).map_err(|_| {
        if typescript_yaml(text) {
            ReadFailure::TypeScript
        } else {
            ReadFailure::Malformed
        }
    })?;
    let invalid = |reason: &str| ReadFailure::Invalid(reason.to_owned());
    let OValue::Object(fields) = &document else {
        return Err(invalid("the file does not hold a JSON object"));
    };
    if document.get("resourceType").is_some()
        || (document.get("version").is_some() && document.get("format").is_none())
    {
        return Err(ReadFailure::TypeScript);
    }
    if document.get("format").and_then(OValue::as_str) != Some(FORMAT) {
        return Err(invalid("it is not an airs DLP backup"));
    }
    let version = match document.get("version") {
        Some(OValue::Number(number)) => number.as_u64(),
        _ => None,
    };
    match version {
        Some(VERSION) => {}
        Some(version) if version > VERSION => return Err(ReadFailure::Newer),
        _ => return Err(invalid("version must be 1")),
    }
    if fields
        .iter()
        .any(|(key, _)| !ENVELOPE.contains(&key.as_str()) && key != "failed")
    {
        return Err(invalid("the envelope has an unknown key"));
    }
    let string = |key: &str| -> Result<String, ReadFailure> {
        document
            .get(key)
            .and_then(OValue::as_str)
            .map(str::to_owned)
            .ok_or_else(|| ReadFailure::Invalid(format!("{key} must be a string")))
    };
    let exported_at = string("exportedAt")?;
    let tenant = string("tenant")?;
    let tsg_id = string("tsgId")?;
    let dlp_tenant_id = match document.get("dlpTenantId") {
        Some(OValue::String(id)) => Some(id.clone()),
        Some(OValue::Null) => None,
        _ => return Err(invalid("dlpTenantId must be a string or null")),
    };
    let resources = {
        let bad = || invalid("resources must be a unique list of dictionaries, patterns, profiles");
        let Some(OValue::Array(items)) = document.get("resources") else {
            return Err(bad());
        };
        let mut kinds = Vec::new();
        for item in items {
            let kind = item.as_str().and_then(Resource::of_key).ok_or_else(bad)?;
            if kinds.contains(&kind) {
                return Err(bad());
            }
            kinds.push(kind);
        }
        if kinds.is_empty() {
            return Err(bad());
        }
        kinds.sort();
        kinds
    };
    let Some(OValue::Bool(complete)) = document.get("complete") else {
        return Err(invalid("complete must be true or false"));
    };
    let mut lists: Vec<Vec<Entry>> = Vec::new();
    for resource in Resource::ALL {
        let key = resource.key();
        let Some(OValue::Array(items)) = document.get(key) else {
            return Err(ReadFailure::Invalid(format!("{key} must be an array")));
        };
        if items.len() > MAX_RECORDS {
            return Err(ReadFailure::Invalid(format!(
                "{key} holds more than {MAX_RECORDS} entries"
            )));
        }
        let mut entries = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let keys_ok = item.as_object().is_some_and(|fields| {
                fields.len() == 4
                    && ["id", "name", "predefined", "record"]
                        .iter()
                        .all(|key| item.get(key).is_some())
            });
            if !keys_ok {
                return Err(ReadFailure::Invalid(format!(
                    "{key}[{index}] must have exactly the keys id, name, predefined, record"
                )));
            }
            let record = item.get("record").cloned().unwrap_or(OValue::Null);
            if record.as_object().is_none() || !valid(resource, &record) {
                return Err(ReadFailure::Invalid(format!(
                    "{key}[{index}] does not match the {} response schema",
                    resource.singular()
                )));
            }
            let (Some(OValue::String(id)), Some(OValue::String(name))) =
                (item.get("id"), item.get("name"))
            else {
                return Err(ReadFailure::Invalid(format!(
                    "{key}[{index}] id and name must be its record's"
                )));
            };
            if record.get("id").and_then(OValue::as_str) != Some(id.as_str())
                || record.get("name").and_then(OValue::as_str) != Some(name.as_str())
            {
                return Err(ReadFailure::Invalid(format!(
                    "{key}[{index}] id and name must be its record's"
                )));
            }
            let is_predefined = record.get("type").and_then(OValue::as_str) == Some("predefined");
            if item.get("predefined") != Some(&OValue::Bool(is_predefined)) {
                return Err(ReadFailure::Invalid(format!(
                    "{key}[{index}] predefined must match its record's type"
                )));
            }
            entries.push(Entry {
                id: id.clone(),
                name: name.clone(),
                predefined: is_predefined,
                record,
            });
        }
        lists.push(entries);
    }
    let rows = |key: &str, last: &str| -> Result<Vec<[String; 4]>, ReadFailure> {
        let Some(OValue::Array(items)) = document.get(key) else {
            return Err(ReadFailure::Invalid(format!("{key} must be an array")));
        };
        let mut out = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let shape = || {
                ReadFailure::Invalid(format!(
                    "{key}[{index}] must have exactly the keys kind, id, name, {last}"
                ))
            };
            if !exact_strings(item, &["kind", "id", "name", last]) {
                return Err(shape());
            }
            let field = |name: &str| {
                item.get(name)
                    .and_then(OValue::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let kind = field("kind");
            if Resource::of_row_kind(&kind).is_none() {
                return Err(shape());
            }
            out.push([kind, field("id"), field("name"), field(last)]);
        }
        Ok(out)
    };
    let skipped: Vec<Skipped> = rows("skipped", "reason")?
        .into_iter()
        .map(|[kind, id, name, reason]| Skipped {
            kind,
            id,
            name,
            reason,
        })
        .collect();
    let failed: Vec<Failed> = rows("failed", "error")?
        .into_iter()
        .map(|[kind, id, name, error]| Failed {
            kind,
            id,
            name,
            error,
        })
        .collect();
    if *complete != (skipped.is_empty() && failed.is_empty()) {
        return Err(invalid(
            "complete does not match the skipped and failed lists",
        ));
    }
    let profiles = lists.pop().unwrap_or_default();
    let patterns = lists.pop().unwrap_or_default();
    let dictionaries = lists.pop().unwrap_or_default();
    Ok(Backup {
        exported_at,
        tenant,
        tsg_id,
        dlp_tenant_id,
        resources,
        dictionaries,
        patterns,
        profiles,
        skipped,
        failed,
    })
}

/// `yyyymmddThhmmssZ` of an ISO timestamp (the default file name).
pub fn stamp(iso: &str) -> String {
    crate::redteam::backup::stamp(iso)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn o(value: Value) -> OValue {
        crate::json::parse(&value.to_string()).unwrap()
    }

    fn usage(result: Result<impl std::fmt::Debug, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    #[test]
    fn resources_and_max_pages_follow_the_typescript_rules() {
        assert_eq!(
            parse_resources(" patterns , profiles ").unwrap(),
            [Resource::Patterns, Resource::Profiles]
        );
        assert_eq!(
            parse_resources("profiles,dictionaries").unwrap(),
            [Resource::Dictionaries, Resource::Profiles]
        );
        for bad in [
            "",
            "nope",
            "patterns,patterns",
            "patterns,",
            ",",
            "Patterns",
        ] {
            assert_eq!(
                usage(parse_resources(bad)),
                "--resources takes a unique list of dictionaries, patterns, profiles",
                "{bad:?}"
            );
        }
        assert_eq!(parse_max_pages("007").unwrap(), 7);
        assert_eq!(parse_max_pages("1000").unwrap(), 1000);
        for bad in [
            "0",
            "1001",
            "1.5",
            "abc",
            "",
            "-1",
            "+1",
            "00000000000000000000001001",
        ] {
            assert_eq!(
                usage(parse_max_pages(bad)),
                "--max-pages must be an integer from 1 to 1000",
                "{bad:?}"
            );
        }
        assert_eq!(parse_max_pages("00000000000000000000000001").unwrap(), 1);
    }

    fn rows(range: std::ops::Range<u64>) -> Vec<Value> {
        range.map(|n| json!({"id": format!("r{n}")})).collect()
    }

    fn sweep(pages: &[Value]) -> Result<usize, String> {
        let mut sweep = Sweep::new(Resource::Dictionaries);
        for (index, page) in pages.iter().enumerate() {
            if sweep.accept(index as u64, &o(page.clone()))? == Step::Done {
                return Ok(sweep.into_items().len());
            }
        }
        Err(sweep.incomplete())
    }

    const INCONSISTENT: &str =
        "Inventory of dictionaries has inconsistent pagination metadata; retry the operation";

    #[test]
    fn sweeps_accept_consistent_camel_snake_and_capped_pages() {
        let camel = |page: u64, content: Vec<Value>, total: u64| {
            let n = content.len();
            json!({"content": content, "number": page, "size": 2, "numberOfElements": n,
                "first": page == 0, "empty": n == 0, "totalElements": total,
                "totalPages": total.div_ceil(2), "last": page + 1 >= total.div_ceil(2),
                "pageable": {"pageNumber": page, "pageSize": 2, "offset": page * 2}})
        };
        assert_eq!(
            sweep(&[camel(0, rows(0..2), 3), camel(1, rows(2..3), 3)]),
            Ok(3)
        );
        // The live dictionaries: size 100 capped at 50, snake_case, no `last`.
        let snake = |page: u64, content: Vec<Value>, total: u64| {
            json!({"content": content, "total_elements": total, "total_pages": total.div_ceil(50),
                "number_of_elements": content.len(), "size": 50,
                "pageable": {"page_number": page, "page_size": 50, "offset": page * 50}})
        };
        assert_eq!(
            sweep(&[snake(0, rows(0..50), 51), snake(1, rows(50..51), 51)]),
            Ok(51)
        );
        // A bare page shorter than 100 is the last.
        assert_eq!(sweep(&[json!({"content": rows(0..3)})]), Ok(3));
        // An empty tenant: zero totals.
        assert_eq!(
            sweep(&[json!({"content": [], "totalElements": 0, "totalPages": 0})]),
            Ok(0)
        );
        assert_eq!(sweep(&[json!({"content": [], "last": true})]), Ok(0));
    }

    #[test]
    fn sweeps_refuse_every_inconsistency() {
        for page in [
            json!({"content": rows(0..2), "number": 1}),
            json!({"content": rows(0..2), "size": 0}),
            json!({"content": rows(0..2), "size": 101}),
            json!({"content": rows(0..2), "size": 2.5}),
            json!({"content": rows(0..2), "numberOfElements": 3}),
            json!({"content": rows(0..2), "numberOfElements": 2, "number_of_elements": 1}),
            json!({"content": rows(0..2), "first": false}),
            json!({"content": rows(0..2), "empty": true}),
            json!({"content": rows(0..2), "pageable": {"pageNumber": 3}}),
            json!({"content": rows(0..2), "pageable": {"offset": 7}}),
            json!({"content": rows(0..2), "pageable": {"pageSize": 2, "page_size": 3}}),
            json!({"content": rows(0..2), "totalElements": -1}),
            json!({"content": rows(0..2), "totalElements": 2, "total_elements": 3}),
            json!({"content": rows(0..2), "totalElements": 2, "totalPages": 2}),
            json!({"content": rows(0..2), "totalPages": 0}),
            json!({"content": rows(0..2), "totalElements": 5}),
            json!({"content": rows(0..2), "totalElements": 2, "last": false}),
            json!({"content": rows(0..2), "number": null}),
            json!({"content": rows(0..2), "number": "0"}),
            json!({"content": rows(0..2), "last": "yes"}),
        ] {
            assert_eq!(
                sweep(std::slice::from_ref(&page)),
                Err(INCONSISTENT.into()),
                "{page}"
            );
        }
        // Totals that change between pages.
        assert_eq!(
            sweep(&[
                json!({"content": rows(0..100), "totalElements": 150}),
                json!({"content": rows(100..150), "totalElements": 151}),
            ]),
            Err(INCONSISTENT.into())
        );
        // A non-object pageable supplies nothing (TS optional chaining).
        assert_eq!(
            sweep(&[json!({"content": rows(0..2), "pageable": "INSTANCE"})]),
            Ok(2)
        );
    }

    #[test]
    fn sweeps_refuse_missing_and_duplicate_ids_stalls_and_overflows() {
        assert_eq!(
            sweep(&[json!({"content": [{"id": " "}]})]),
            Err(
                "Inventory of dictionaries contains a missing resource ID; retry the operation"
                    .into()
            )
        );
        assert_eq!(
            sweep(&[json!({"content": [{"name": "x"}]})]),
            Err(
                "Inventory of dictionaries contains a missing resource ID; retry the operation"
                    .into()
            )
        );
        assert_eq!(
            sweep(&[json!({"content": [{"id": "a"}, {"id": "a"}]})]),
            Err(
                "Inventory of dictionaries contains duplicate resource IDs; retry the operation"
                    .into()
            )
        );
        assert_eq!(
            sweep(&[
                json!({"content": rows(0..100), "last": false}),
                json!({"content": [], "last": false}),
            ]),
            Err("Inventory of dictionaries did not advance".into())
        );
        let full =
            |page: u64| json!({"content": rows(page * 100..page * 100 + 100), "last": false});
        let pages: Vec<Value> = (0..101).map(full).collect();
        assert_eq!(
            sweep(&pages),
            Err("Inventory of dictionaries exceeds the 10000-record safety limit".into())
        );
        let mut sweep = Sweep::new(Resource::Patterns);
        assert_eq!(sweep.accept(0, &o(full(0))), Ok(Step::More));
        assert_eq!(
            sweep.incomplete(),
            "Inventory of data patterns is incomplete: increase --max-pages"
        );
    }

    #[test]
    fn tenant_identities_must_agree() {
        let records = [
            json!({"tenant_id": "a"}),
            json!({"tenant_id": null}),
            json!({}),
        ];
        assert_eq!(tenant_identity(&records), Ok(Some("a".into())));
        let mixed = [json!({"tenant_id": "a"}), json!({"tenant_id": "b"})];
        assert_eq!(
            tenant_identity(&mixed),
            Err("Inventory reports mixed DLP tenant identities".into())
        );
        assert_eq!(tenant_identity(&[]), Ok(None));
    }

    fn leaf(technique: &str, id: Option<&str>, version: Option<u64>) -> Value {
        let mut item = json!({"detection_technique": technique, "name": "n"});
        if let Some(id) = id {
            item["id"] = json!(id);
        }
        if let Some(version) = version {
            item["version"] = json!(version);
        }
        json!({"rule_item": item})
    }

    fn profile(id: &str, name: &str, leaves: Vec<Value>) -> Value {
        json!({"id": id, "name": name, "type": "custom", "profile_status": "active",
            "detection_rules": [{"rule_type": "expression_tree",
                "expression_tree": {"operator_type": "or", "sub_expressions": leaves}}]})
    }

    fn inventory(
        dictionaries: Vec<Value>,
        patterns: Vec<Value>,
        profiles: Vec<Value>,
    ) -> Inventory {
        Inventory {
            dictionaries: dictionaries.into_iter().map(o).collect(),
            patterns: patterns.into_iter().map(o).collect(),
            profiles: profiles.into_iter().map(o).collect(),
        }
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.name.as_str()).collect()
    }

    /// TS DR-spec `backupDlpResources`: the closure, the stubs, the sort, the selection.
    #[test]
    fn selection_closes_over_dependencies_with_predefined_stubs() {
        let inv = inventory(
            vec![
                json!({"id": "d1", "name": "Secret Words", "type": "custom"}),
                json!({"id": "d2", "name": "Legal Terms", "type": "predefined", "category": "x"}),
                json!({"id": "d3", "name": "Unused", "type": "predefined"}),
            ],
            vec![
                json!({"id": "p1", "name": "Custom Regex", "type": "custom", "status": "active", "version": 2,
                    "detection_config": {"technique": "regex"}, "matching_rules": {"regexes": [{"regex": "x"}]}}),
                json!({"id": "p2", "name": "SSN", "type": "predefined", "version": 3,
                    "detection_config": {"technique": "ml", "supported_confidence_levels": ["high"]},
                    "matching_rules": {"regexes": [{"regex": "y"}]}}),
                json!({"id": "p3", "name": "Gone", "type": "custom", "status": "deleted",
                    "detection_config": {"technique": "regex"}}),
            ],
            vec![profile(
                "f1",
                "PII Guardrail",
                vec![
                    leaf("regex", Some("p1"), Some(2)),
                    leaf("ml", Some("p2"), Some(3)),
                    leaf("dictionary", Some("d2"), Some(1)),
                    leaf("dictionary", Some("d1"), None),
                    leaf("regex", None, None),
                ],
            )],
        );
        let all = select(&inv, &Resource::ALL, false).unwrap();
        assert_eq!(names(&all.dictionaries), ["Legal Terms", "Secret Words"]);
        assert_eq!(names(&all.patterns), ["Custom Regex", "SSN"]);
        assert_eq!(names(&all.profiles), ["PII Guardrail"]);
        assert_eq!(
            value_of(&all.dictionaries[0].record),
            json!({"id": "d2", "name": "Legal Terms", "type": "predefined"})
        );
        assert!(all.dictionaries[0].predefined);
        assert_eq!(
            value_of(&all.patterns[1].record),
            json!({"id": "p2", "name": "SSN", "type": "predefined", "version": 3, "detection_config": {"technique": "ml"}})
        );
        // `--resources profiles` still embeds the dependencies.
        let profiles = select(&inv, &[Resource::Profiles], false).unwrap();
        assert_eq!(profiles.dictionaries.len(), 2);
        assert_eq!(profiles.patterns.len(), 2);
        // `--resources patterns`: custom and active only.
        let patterns = select(&inv, &[Resource::Patterns], false).unwrap();
        assert_eq!(names(&patterns.patterns), ["Custom Regex"]);
        assert!(patterns.dictionaries.is_empty() && patterns.profiles.is_empty());
        let dictionaries = select(&inv, &[Resource::Dictionaries], false).unwrap();
        assert_eq!(names(&dictionaries.dictionaries), ["Secret Words"]);
        assert_eq!(
            select(&inventory(vec![], vec![], vec![]), &Resource::ALL, false),
            Err("No matching DLP resources to back up".into())
        );
    }

    /// Every unsupported reason at once; `--skip-unsupported` records them and adds no
    /// dependency of a skipped profile.
    #[test]
    fn unsupported_profiles_fail_together_or_are_skipped() {
        let multi = json!({"id": "f2", "name": "Multi", "type": "custom",
            "detection_rules": [{"rule_type": "multi_profile", "multi_profile": {}}]});
        let basic = json!({"id": "f3", "name": "Basic", "type": "custom", "detection_rules": null});
        let edm = profile(
            "f4",
            "Edm",
            vec![json!({"rule_item": {"detection_technique": "edm", "edm_dataset_id": "e"}})],
        );
        let unknown = profile("f5", "Unknown", vec![leaf("regex", Some("nope"), None)]);
        let pinned = profile(
            "f6",
            "Pinned",
            vec![leaf("dictionary", Some("d1"), Some(2))],
        );
        let technique = profile("f7", "Tech", vec![leaf("weighted_regex", Some("p1"), None)]);
        let retired = profile("f8", "Retired", vec![leaf("regex", Some("p3"), None)]);
        let version = profile("f9", "Version", vec![leaf("regex", Some("p1"), Some(1))]);
        // A first leaf that would add a dependency, then a failing one.
        let partial = profile(
            "fa",
            "Partial",
            vec![
                leaf("dictionary", Some("d1"), None),
                leaf("regex", Some("nope"), None),
            ],
        );
        let inv = inventory(
            vec![json!({"id": "d1", "name": "Words", "type": "custom"})],
            vec![
                json!({"id": "p1", "name": "Re", "type": "custom", "version": 2, "detection_config": {"technique": "regex"}}),
                json!({"id": "p3", "name": "Old", "type": "custom", "status": "disabled", "detection_config": {"technique": "regex"}}),
            ],
            vec![
                multi, basic, edm, unknown, pinned, technique, retired, version, partial,
            ],
        );
        let error = select(&inv, &[Resource::Profiles], false).unwrap_err();
        assert_eq!(
            error,
            "Profiles cannot be exported: Multi (Unsupported detection rule type: multi_profile); \
             Basic (has no exported detection rules (the API does not expose basic data profile content)); \
             Edm (references an EDM dataset directly); Unknown (references an unknown data pattern: nope); \
             Pinned (references a version-pinned dictionary: d1); \
             Tech (references a data pattern with a different detection technique); \
             Retired (references a retired data pattern: Old); \
             Version (references data pattern version 1, but the catalog holds version 2: p1); \
             Partial (references an unknown data pattern: nope); \
             exclude unsupported profiles explicitly with --skip-unsupported"
        );
        let skipped = select(&inv, &[Resource::Profiles], true).unwrap_err();
        assert_eq!(skipped, "No matching DLP resources to back up");
        let mut with_good = inv.clone();
        with_good.profiles.push(o(profile(
            "fb",
            "Good",
            vec![leaf("regex", Some("p1"), Some(2))],
        )));
        let selection = select(&with_good, &[Resource::Profiles], true).unwrap();
        assert_eq!(selection.skipped.len(), 9);
        assert_eq!(selection.skipped[0].kind, "profile");
        assert_eq!(selection.skipped[0].id, "f2");
        assert_eq!(names(&selection.profiles), ["Good"]);
        assert_eq!(names(&selection.patterns), ["Re"]);
        assert!(
            selection.dictionaries.is_empty(),
            "no dependency of a skipped profile"
        );
    }

    #[test]
    fn names_must_be_unique_and_control_free() {
        let dup = inventory(
            vec![],
            vec![
                json!({"id": "a", "name": "Same", "type": "custom"}),
                json!({"id": "b", "name": "Same", "type": "custom"}),
            ],
            vec![],
        );
        assert_eq!(
            select(&dup, &Resource::ALL, false),
            Err("Backup contains duplicate data pattern names: Same".into())
        );
        let evil = inventory(
            vec![],
            vec![json!({"id": "a", "name": "Evil\u{1b}[31mRed", "type": "custom"})],
            vec![],
        );
        assert_eq!(select(&evil, &Resource::ALL, false), Err(NAME_RULE.into()));
        let unnamed = inventory(vec![json!({"id": "a", "type": "custom"})], vec![], vec![]);
        assert_eq!(
            select(&unnamed, &Resource::ALL, false),
            Err("Backup contains a dictionary without a name".into())
        );
        let mixed = inventory(
            vec![],
            vec![json!({"id": "a", "name": "A", "tenant_id": "x"})],
            vec![json!({"id": "b", "name": "B", "tenant_id": "y", "type": "predefined"})],
        );
        assert_eq!(
            select(&mixed, &Resource::ALL, false),
            Err("Inventory reports mixed DLP tenant identities".into())
        );
    }

    fn backup() -> Backup {
        Backup {
            exported_at: "2026-10-18T12:00:00.000Z".into(),
            tenant: "prod".into(),
            tsg_id: "100".into(),
            dlp_tenant_id: Some("t".into()),
            resources: Resource::ALL.to_vec(),
            dictionaries: vec![Entry {
                id: "d1".into(),
                name: "D".into(),
                predefined: false,
                record: o(json!({"id": "d1", "name": "D", "type": "custom", "keywords": ["k"]})),
            }],
            patterns: vec![Entry {
                id: "p1".into(),
                name: "P".into(),
                predefined: true,
                record: o(json!({"id": "p1", "name": "P", "type": "predefined"})),
            }],
            profiles: vec![],
            skipped: vec![],
            failed: vec![],
        }
    }

    #[test]
    fn the_document_round_trips_in_the_format_order() {
        let original = backup();
        let text = original.to_text();
        assert!(text.ends_with("}\n"));
        let keys: Vec<String> = crate::json::parse(&text)
            .unwrap()
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, _)| key.clone())
            .collect();
        assert_eq!(
            keys,
            [
                "format",
                "version",
                "exportedAt",
                "tenant",
                "tsgId",
                "dlpTenantId",
                "resources",
                "complete",
                "dictionaries",
                "patterns",
                "profiles",
                "skipped",
                "failed"
            ]
        );
        assert_eq!(parse(&text, |_, _| true), Ok(original));
    }

    #[test]
    fn the_reader_refuses_typescript_newer_and_broken_files() {
        let text = |value: Value| value.to_string();
        let doc = || value_of(&backup().document());
        assert_eq!(parse("{", |_, _| true), Err(ReadFailure::Malformed));
        assert_eq!(
            parse("version: 1\nresourceType: dlp-resources\n", |_, _| true),
            Err(ReadFailure::TypeScript)
        );
        assert_eq!(
            parse(
                &text(json!({"version": 1, "resourceType": "dlp-resources"})),
                |_, _| true
            ),
            Err(ReadFailure::TypeScript)
        );
        assert_eq!(
            parse(&text(json!({"version": 1})), |_, _| true),
            Err(ReadFailure::TypeScript)
        );
        let mut newer = doc();
        newer["version"] = json!(2);
        assert_eq!(parse(&text(newer), |_, _| true), Err(ReadFailure::Newer));
        let invalid = |edit: &dyn Fn(&mut Value), reason: &str| {
            let mut value = doc();
            edit(&mut value);
            assert_eq!(
                parse(&text(value), |_, _| true),
                Err(ReadFailure::Invalid(reason.into())),
                "{reason}"
            );
        };
        assert_eq!(
            parse("[1]", |_, _| true),
            Err(ReadFailure::Invalid(
                "the file does not hold a JSON object".into()
            ))
        );
        invalid(
            &|v| v["format"] = json!("airs-cli-rs.redteam-targets"),
            "it is not an airs DLP backup",
        );
        invalid(&|v| v["version"] = json!(0), "version must be 1");
        invalid(&|v| v["version"] = json!("1"), "version must be 1");
        invalid(
            &|v| v["extra"] = json!(1),
            "the envelope has an unknown key",
        );
        invalid(&|v| v["tsgId"] = json!(100), "tsgId must be a string");
        invalid(
            &|v| v["dlpTenantId"] = json!(1),
            "dlpTenantId must be a string or null",
        );
        invalid(
            &|v| v["resources"] = json!(["patterns", "patterns"]),
            "resources must be a unique list of dictionaries, patterns, profiles",
        );
        invalid(
            &|v| v["resources"] = json!([]),
            "resources must be a unique list of dictionaries, patterns, profiles",
        );
        invalid(
            &|v| v["complete"] = json!("yes"),
            "complete must be true or false",
        );
        invalid(&|v| v["patterns"] = json!({}), "patterns must be an array");
        invalid(
            &|v| v["dictionaries"][0]["extra"] = json!(1),
            "dictionaries[0] must have exactly the keys id, name, predefined, record",
        );
        invalid(
            &|v| v["dictionaries"][0]["name"] = json!("Other"),
            "dictionaries[0] id and name must be its record's",
        );
        invalid(
            &|v| v["patterns"][0]["predefined"] = json!(false),
            "patterns[0] predefined must match its record's type",
        );
        invalid(
            &|v| v["skipped"] = json!([{"kind": "profile", "id": "x", "name": "n"}]),
            "skipped[0] must have exactly the keys kind, id, name, reason",
        );
        invalid(
            &|v| v["failed"] = json!([{"kind": "thing", "id": "x", "name": "n", "error": "e"}]),
            "failed[0] must have exactly the keys kind, id, name, error",
        );
        invalid(
            &|v| {
                v["failed"] = json!([{"kind": "dictionary", "id": "x", "name": "n", "error": "e"}])
            },
            "complete does not match the skipped and failed lists",
        );
        let mut many = doc();
        many["profiles"] = Value::Array(vec![json!(1); MAX_RECORDS + 1]);
        assert_eq!(
            parse(&text(many), |_, _| true),
            Err(ReadFailure::Invalid(
                "profiles holds more than 10000 entries".into()
            ))
        );
        assert_eq!(
            parse(&text(doc()), |resource, _| resource
                != Resource::Dictionaries),
            Err(ReadFailure::Invalid(
                "dictionaries[0] does not match the dictionary response schema".into()
            ))
        );
    }

    #[test]
    fn rule_leaves_walk_nested_trees_and_refuse_bad_shapes() {
        let rules = json!([{"rule_type": "expression_tree", "expression_tree": {"sub_expressions": [
            {"rule_item": {"detection_technique": "regex", "id": "a"}},
            {"sub_expressions": [{"rule_item": {"detection_technique": "dictionary", "id": "b"}}]}
        ]}}]);
        let leaves = rule_leaves(Some(&rules)).unwrap();
        assert_eq!(leaves.len(), 2);
        let mut copy = rules.clone();
        let item = at_path(&mut copy[0], &leaves[1].path[1..]).unwrap();
        assert_eq!(item["id"], "b");
        assert_eq!(
            rule_leaves(Some(&json!([1]))),
            Err("Unsupported detection rule shape".into())
        );
        assert_eq!(
            rule_leaves(Some(&json!([{"rule_type": "multi_profile"}]))),
            Err("Unsupported detection rule type: multi_profile".into())
        );
        assert_eq!(
            rule_leaves(Some(
                &json!([{"rule_type": "expression_tree", "expression_tree": {"sub_expressions": [{"rule_item": {"id": "x"}}]}}])
            )),
            Err("Unsupported detection rule: leaf without a detection technique".into())
        );
        let mut deep = json!({"rule_item": {"detection_technique": "regex"}});
        for _ in 0..101 {
            deep = json!({"sub_expressions": [deep]});
        }
        assert_eq!(
            rule_leaves(Some(
                &json!([{"rule_type": "expression_tree", "expression_tree": deep}])
            )),
            Err("Unsupported detection rule: expression tree too deep".into())
        );
    }
}
