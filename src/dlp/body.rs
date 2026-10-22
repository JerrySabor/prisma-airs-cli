//! DLP request bodies (DESIGN §16.3, §16.5–§16.8): the escape hatches (`--body <json>`,
//! `--body -`, `--body-file`) and their exclusivity rules (D165), the pattern,
//! filtering-profile and profile builders (TS `build-body.ts`, D162, D163), the dictionary
//! metadata (D173), the `type: predefined` refusal (D166), the schema checks (D116) and
//! the omitted-fields list of a replace (D168).
//!
//! Everything here is pure except [`read_input`], which reads a body file or piped stdin
//! (after the debug log, before the tenant). No message echoes body content, a `--set`,
//! `--tag` or `--weighted-regex` value, or file content: only flags and paths.

use super::Kind;
use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::output::Output;
use crate::signals::{Phase, SignalState};
use serde_json::{Map, Value, json};
use std::ffi::{OsStr, OsString};

/// The cap of a JSON body file, `--body -` stdin and a metadata file (1 MiB).
pub const JSON_LIMIT: u64 = crate::files::CONFIG_LIMIT;

/// Where a create or replace body comes from, once the arguments are checked.
#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    /// Built from the flags or parsed from `--body <json>` during planning.
    Ready(Value),
    /// `--body-file <path>`, read before the tenant.
    File(OsString),
    /// `--body -`: piped stdin, read before the tenant.
    Stdin,
}

/// The JSON texts of a body source (TS keeps resource-specific texts that echo nothing;
/// the generic ones replace TS's excerpting `invalid JSON in body: …`, D163).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Texts {
    /// Patterns and filtering profiles: `--body is not valid JSON`, and the §13.2 file
    /// texts for a file.
    Body,
    /// Profile create and replace (TS `Cannot read profile body as JSON; …`).
    Profile,
    /// Profile patch (TS `Invalid profile patch: …`).
    ProfilePatch,
    /// Dictionary metadata and dictionary patch files (TS `readMetadata`).
    Dictionary,
}

const PROFILE_JSON: &str = "Cannot read profile body as JSON; verify the file and JSON syntax";
const PROFILE_OBJECT: &str = "Profile body must be a JSON object";
/// TS's masked profile patch text.
pub const PROFILE_PATCH: &str =
    "Invalid profile patch: verify JSON syntax and --set key=value/--clear key flags";
/// TS's masked dictionary patch text.
pub const DICTIONARY_PATCH: &str = "Invalid dictionary patch flags: use --set key=value, --clear key, or --body-file for nested fields";
const DICTIONARY_JSON: &str = "Invalid JSON in dictionary metadata file";
const DICTIONARY_OBJECT: &str = "Dictionary metadata must be a JSON object";
/// TS's masked profile schema text.
pub const PROFILE_METADATA: &str =
    "Invalid profile metadata: verify required fields and value types";
/// TS's masked dictionary schema text.
pub const DICTIONARY_METADATA: &str =
    "Invalid dictionary metadata: verify required fields and value types";

impl Texts {
    /// `(not JSON, not an object)` for `--body <json>` and stdin.
    fn inline(self) -> (&'static str, &'static str) {
        match self {
            Self::Body => (
                "--body is not valid JSON",
                "--body must contain a JSON object",
            ),
            Self::Profile => (PROFILE_JSON, PROFILE_OBJECT),
            Self::ProfilePatch => (PROFILE_PATCH, PROFILE_OBJECT),
            Self::Dictionary => (DICTIONARY_JSON, DICTIONARY_OBJECT),
        }
    }

    /// `(not JSON, not an object)` for a file at `path` (exit 1).
    fn file(self, path: &OsStr) -> (String, String) {
        match self {
            Self::Body => {
                let shown = crate::files::shown(path);
                (
                    format!("{shown} is not valid JSON"),
                    format!("{shown} must contain a JSON object"),
                )
            }
            other => {
                let (invalid, object) = other.inline();
                (invalid.to_owned(), object.to_owned())
            }
        }
    }
}

/// One JSON object from `text`; `Err(true)` for invalid JSON, `Err(false)` for another
/// value (`null`, `0`, `false`, `""`, an array).
fn object_of(text: &str) -> Result<Value, bool> {
    match serde_json::from_str::<Value>(text) {
        Ok(value @ Value::Object(_)) => Ok(value),
        Ok(_) => Err(false),
        Err(_) => Err(true),
    }
}

/// `--body <json>` as one JSON object (usage errors, exit 2).
pub fn parse_inline(text: &str, texts: Texts) -> Result<Value, CliError> {
    let (invalid, object) = texts.inline();
    object_of(text).map_err(|json| CliError::usage(if json { invalid } else { object }))
}

/// The escape hatch of a create or replace, checked during planning (D165):
/// `--body` and `--body-file` together, a hatch together with the build flag `first_flag`
/// (the first one given, in help order), an empty value, and `--body -` on a terminal are
/// usage errors; `--body <json>` is parsed here. `None`: build the body from the flags.
pub fn hatch(
    body: Option<&str>,
    body_file: Option<&OsStr>,
    first_flag: Option<&str>,
    texts: Texts,
    stdin_terminal: bool,
) -> Result<Option<Input>, CliError> {
    if body.is_none() && body_file.is_none() {
        return Ok(None);
    }
    if body.is_some() && body_file.is_some() {
        return Err(CliError::usage(
            "--body and --body-file are mutually exclusive",
        ));
    }
    if let Some(flag) = first_flag {
        return Err(CliError::usage(format!(
            "--body and --body-file cannot be combined with --{flag}"
        )));
    }
    if let Some(path) = body_file {
        if path.is_empty() {
            return Err(CliError::usage("--body-file needs a path"));
        }
        return Ok(Some(Input::File(path.to_owned())));
    }
    match body.unwrap_or_default() {
        "" => Err(CliError::usage("--body needs a JSON object")),
        "-" if stdin_terminal => Err(CliError::usage("--body - requires piped input on stdin")),
        "-" => Ok(Some(Input::Stdin)),
        text => parse_inline(text, texts).map(|value| Some(Input::Ready(value))),
    }
}

/// A JSON object file of at most 1 MiB (§13.2 read rules; the parse texts of `texts`,
/// exit 1).
pub fn read_object_file(path: &OsStr, texts: Texts) -> Result<Value, CliError> {
    let text = crate::files::read_text(path, JSON_LIMIT)?;
    let (invalid, object) = texts.file(path);
    object_of(&text).map_err(|json| CliError::operational(if json { invalid } else { object }))
}

/// The `--body -` text: piped stdin, UTF-8, at most 1 MiB (exit 2 otherwise). The wait
/// is marked for the signal thread, so a signal ends the process even while the writer
/// keeps the pipe open (`Interrupted; nothing was changed`, as `input::read_piped_stdin`).
fn read_stdin(output: &Output) -> Result<String, CliError> {
    use std::io::Read;
    let refused = || CliError::usage("--body - must be UTF-8 JSON of at most 1 MiB on stdin");
    let signals = output.signals();
    let _waiting = signals
        .as_deref()
        .map(|state| state.enter(Phase::WaitingBody));
    // A signal that arrived before the phase was entered only cancelled the session:
    // stop now rather than block on the pipe (the phase is stored before the code is
    // read, and the signal thread records the code before it reads the phase).
    if signals.as_deref().and_then(SignalState::code).is_some() {
        return Err(CliError::Interrupted(InterruptContext::NothingChanged));
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(JSON_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    if bytes.len() as u64 > JSON_LIMIT {
        return Err(refused());
    }
    String::from_utf8(bytes).map_err(|_| refused())
}

/// The body of an [`Input`]: a file or stdin is read now (after the debug log, before
/// the tenant).
pub fn read_input(input: &Input, texts: Texts, output: &Output) -> Result<Value, CliError> {
    match input {
        Input::Ready(value) => Ok(value.clone()),
        Input::File(path) => read_object_file(path, texts),
        Input::Stdin => parse_inline(&read_stdin(output)?, texts),
    }
}

/// The first of `flags` (name, given) that was given.
pub fn first_given(flags: &[(&'static str, bool)]) -> Option<&'static str> {
    flags
        .iter()
        .find_map(|(name, given)| given.then_some(*name))
}

// ---------------------------------------------------------------------------
// `type: predefined` (D166) and the schema checks (D116)
// ---------------------------------------------------------------------------

/// `<resource> bodies cannot set "type": "predefined"; …` (exit 2) when the top-level
/// `type` of `body` is `predefined`.
pub fn refuse_predefined(kind: Kind, body: &Value) -> Result<(), CliError> {
    if body.get("type").and_then(Value::as_str) == Some("predefined") {
        return Err(CliError::usage(format!(
            "{} bodies cannot set \"type\": \"predefined\"; predefined resources are shipped by Palo Alto Networks and never written by airs",
            kind.resource()
        )));
    }
    Ok(())
}

/// TS `encodeURIComponent` (the id inside a request path).
pub fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        let c = byte as char;
        if c.is_ascii_alphanumeric() || "-_.!~*'()".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The SDK path of a request on `kind` (`/v2/api/data-patterns[/<id>]`).
pub fn api_path(kind: Kind, id: Option<&str>) -> String {
    let collection = match kind {
        Kind::FilteringProfile => "data-filtering-profiles",
        Kind::Pattern => "data-patterns",
        Kind::Profile => "data-profiles",
        Kind::Dictionary => "dictionaries",
    };
    match id {
        Some(id) => format!("/v2/api/{collection}/{}", encode_component(id)),
        None => format!("/v2/api/{collection}"),
    }
}

/// What a schema failure reads (§16.3): the D116 text for patterns and filtering
/// profiles, TS's masked texts for profiles and dictionaries.
pub fn schema_text(kind: Kind, method: &str, id: Option<&str>) -> String {
    match kind {
        Kind::Pattern | Kind::FilteringProfile => format!(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for {method} {} did not match schema",
            api_path(kind, id)
        ),
        Kind::Profile => PROFILE_METADATA.to_owned(),
        Kind::Dictionary => DICTIONARY_METADATA.to_owned(),
    }
}

/// Parse `body` with the SDK request schema `parse` (`Mode::Request`); `text` on failure,
/// exit 2 during planning (`usage`), exit 1 for a body completed from server data.
pub fn schema<M>(
    body: &Value,
    parse: impl FnOnce(Value, scm::validation::Mode) -> scm::Result<M>,
    text: &str,
    usage: bool,
) -> Result<M, CliError> {
    parse(body.clone(), scm::validation::Mode::Request).map_err(|_| {
        if usage {
            CliError::usage(text)
        } else {
            CliError::operational(text)
        }
    })
}

/// Check `body` as the request of a write on `kind` (`method`, the id of the path).
pub fn check(
    kind: Kind,
    write: Write,
    id: Option<&str>,
    body: &Value,
    usage: bool,
) -> Result<(), CliError> {
    use scm::dlp::models as m;
    let text = schema_text(kind, write.method(), id);
    match (kind, write) {
        (Kind::Pattern, Write::Patch) => {
            schema(body, m::DataPatternPatchRequest::parse, &text, usage).map(drop)
        }
        (Kind::Pattern, _) => schema(body, m::DataPatternRequest::parse, &text, usage).map(drop),
        (Kind::Profile, Write::Patch) => {
            schema(body, m::DataProfilePatchRequest::parse, &text, usage).map(drop)
        }
        (Kind::Profile, _) => {
            schema(body, m::AdvancedDataProfileRequest::parse, &text, usage).map(drop)
        }
        (Kind::Dictionary, Write::Patch) => {
            schema(body, m::DictionaryPatchRequest::parse, &text, usage).map(drop)
        }
        (Kind::Dictionary, _) => {
            let metadata = schema(body, m::DictionaryRequest::parse, &text, usage)?;
            if file_name_ok(&metadata.original_file_name) {
                Ok(())
            } else {
                Err(CliError::usage(text))
            }
        }
        (Kind::FilteringProfile, _) => {
            schema(body, m::DataFilteringProfileRequest::parse, &text, usage).map(drop)
        }
    }
}

/// The kind of a DLP write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    Create,
    Replace,
    Patch,
}

impl Write {
    pub fn method(self) -> &'static str {
        match self {
            Self::Create => "POST",
            Self::Replace => "PUT",
            Self::Patch => "PATCH",
        }
    }
}

/// The SDK multipart file-name rule (G14): 1–255 bytes, not `.` or `..`, no control
/// character, `/`, `\` or `"`.
pub fn file_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | '"'))
}

// ---------------------------------------------------------------------------
// The pattern builder (§16.6, TS `bb.ts:65-93`)
// ---------------------------------------------------------------------------

/// The pattern flags of `patterns create` and `replace`.
#[derive(Clone, Debug, Default)]
pub struct PatternFlags {
    pub name: Option<String>,
    pub r#type: Option<String>,
    pub description: Option<String>,
    pub technique: Option<String>,
    pub confidence_levels: Option<String>,
    pub regex: Vec<String>,
    pub weighted_regex: Vec<String>,
    pub delimiter: Option<String>,
    pub proximity_distance: Option<String>,
    pub proximity_keyword: Vec<String>,
    pub tag: Vec<String>,
}

impl PatternFlags {
    /// The first build flag given, in help order (for the D165 message).
    pub fn first_given(&self) -> Option<&'static str> {
        first_given(&[
            ("confidence-levels", self.confidence_levels.is_some()),
            ("delimiter", self.delimiter.is_some()),
            ("description", self.description.is_some()),
            ("name", self.name.is_some()),
            ("proximity-distance", self.proximity_distance.is_some()),
            ("proximity-keyword", !self.proximity_keyword.is_empty()),
            ("regex", !self.regex.is_empty()),
            ("tag", !self.tag.is_empty()),
            ("technique", self.technique.is_some()),
            ("type", self.r#type.is_some()),
            ("weighted-regex", !self.weighted_regex.is_empty()),
        ])
    }
}

/// A CSV list: split on `,`, trimmed, empties dropped.
fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `^-?\d+(\.\d+)?$` as a JSON number in JavaScript form.
fn decimal(raw: &str) -> Option<Value> {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    let (int, fraction) = digits.split_once('.').unwrap_or((digits, "0"));
    let ok = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !(ok(int) && ok(fraction)) {
        return None;
    }
    if let Some(number) = super::patch::js_number(raw) {
        return Some(Value::Number(number));
    }
    raw.parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
        .and_then(serde_json::Number::from_f64)
        .map(Value::Number)
}

/// The regexes: each `--regex` with weight 1, then each `--weighted-regex` split at its
/// last `|` into a non-empty regex and a finite decimal weight.
fn regexes(plain: &[String], weighted: &[String]) -> Result<Vec<Value>, CliError> {
    let mut out: Vec<Value> = plain
        .iter()
        .map(|regex| json!({"regex": regex, "weight": 1}))
        .collect();
    for entry in weighted {
        let parsed = entry
            .rsplit_once('|')
            .filter(|(regex, _)| !regex.is_empty())
            .and_then(|(regex, weight)| decimal(weight).map(|weight| (regex, weight)));
        let Some((regex, weight)) = parsed else {
            return Err(CliError::usage(
                "--weighted-regex must be PATTERN|weight with a numeric weight",
            ));
        };
        out.push(json!({"regex": regex, "weight": weight}));
    }
    Ok(out)
}

/// `--tag k=v[,v…]`, appended per key across repeats.
fn tags(values: &[String]) -> Result<Option<Map<String, Value>>, CliError> {
    if values.is_empty() {
        return Ok(None);
    }
    let mut out: Map<String, Value> = Map::new();
    for entry in values {
        let Some((key, value)) = entry
            .split_once('=')
            .map(|(key, value)| (key.trim(), value))
            .filter(|(key, _)| !key.is_empty())
        else {
            return Err(CliError::usage("--tag must be key=value[,value...]"));
        };
        let parts = csv(value);
        if parts.is_empty() {
            return Err(CliError::usage("--tag needs at least one value"));
        }
        let slot = out
            .entry(key.to_owned())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(items) = slot {
            items.extend(parts.into_iter().map(Value::String));
        }
    }
    Ok(Some(out))
}

/// The pattern defaults of TS's builder (a replace takes the current values instead,
/// D169).
pub const DEFAULT_PATTERN_TYPE: &str = "custom";
pub const DEFAULT_TECHNIQUE: &str = "regex";

/// The pattern body from the flags (`type` and `technique` default to `custom` and
/// `regex`); the checks run in TS's order: `--name`, `--weighted-regex`, `--tag`, then
/// `--proximity-distance`.
pub fn pattern_body(flags: &PatternFlags) -> Result<Value, CliError> {
    let Some(name) = flags.name.as_deref().filter(|name| !name.is_empty()) else {
        return Err(CliError::usage("--name is required"));
    };
    let technique = flags.technique.as_deref().unwrap_or(DEFAULT_TECHNIQUE);
    let regexes = regexes(&flags.regex, &flags.weighted_regex)?;
    let tags = tags(&flags.tag)?;
    let mut detection = Map::new();
    detection.insert("technique".to_owned(), json!(technique));
    if let Some(levels) = flags.confidence_levels.as_deref() {
        let levels = csv(levels);
        if !levels.is_empty() {
            detection.insert("supported_confidence_levels".to_owned(), json!(levels));
        }
    }
    let mut rules = Map::new();
    if let Some(delimiter) = &flags.delimiter {
        rules.insert("delimiter".to_owned(), json!(delimiter));
    }
    if let Some(distance) = &flags.proximity_distance {
        let value = distance
            .parse::<u16>()
            .ok()
            .filter(|n| distance.bytes().all(|b| b.is_ascii_digit()) && (2..=1000).contains(n))
            .ok_or_else(|| {
                CliError::usage("--proximity-distance must be an integer from 2 to 1000")
            })?;
        rules.insert("proximity_distance".to_owned(), json!(value));
    }
    if !flags.proximity_keyword.is_empty() {
        rules.insert(
            "proximity_keywords".to_owned(),
            json!(flags.proximity_keyword),
        );
    }
    if !regexes.is_empty() {
        rules.insert("regexes".to_owned(), Value::Array(regexes));
    }
    let mut body = Map::new();
    body.insert("name".to_owned(), json!(name));
    body.insert(
        "type".to_owned(),
        json!(flags.r#type.as_deref().unwrap_or(DEFAULT_PATTERN_TYPE)),
    );
    body.insert("detection_config".to_owned(), Value::Object(detection));
    if let Some(description) = &flags.description {
        body.insert("description".to_owned(), json!(description));
    }
    if !rules.is_empty() {
        body.insert("matching_rules".to_owned(), Value::Object(rules));
    }
    if let Some(tags) = tags {
        body.insert("tags".to_owned(), Value::Object(tags));
    }
    Ok(Value::Object(body))
}

/// A pattern replace body completed from the current record (D169): the type and the
/// technique the flags did not give.
pub fn complete_pattern(body: &mut Value, current: &OValue, fill_type: bool, fill_technique: bool) {
    if fill_type && let Some(kind) = current.get("type").and_then(OValue::as_str) {
        body["type"] = json!(kind);
    }
    if fill_technique
        && let Some(technique) = current
            .get("detection_config")
            .and_then(|config| config.get("technique"))
            .and_then(OValue::as_str)
    {
        body["detection_config"]["technique"] = json!(technique);
    }
}

// ---------------------------------------------------------------------------
// The filtering-profile builder (§16.5, TS `bb.ts:99-117`)
// ---------------------------------------------------------------------------

/// The flags of `filtering-profiles replace`.
#[derive(Clone, Debug, Default)]
pub struct FilteringFlags {
    pub file_based: bool,
    pub non_file_based: bool,
    pub description: Option<String>,
    pub direction: Option<String>,
    pub log_severity: Option<String>,
    pub scan_type: Option<String>,
    pub data_profile_id: Option<String>,
    pub euc_template_id: Option<String>,
    pub end_user_coaching: bool,
    pub granular: bool,
    pub file_type: Vec<String>,
}

impl FilteringFlags {
    /// The first build flag given, in help order.
    pub fn first_given(&self) -> Option<&'static str> {
        first_given(&[
            ("data-profile-id", self.data_profile_id.is_some()),
            ("description", self.description.is_some()),
            ("direction", self.direction.is_some()),
            ("end-user-coaching", self.end_user_coaching),
            ("euc-template-id", self.euc_template_id.is_some()),
            ("file-based", self.file_based),
            ("file-type", !self.file_type.is_empty()),
            ("granular", self.granular),
            ("log-severity", self.log_severity.is_some()),
            ("non-file-based", self.non_file_based),
            ("scan-type", self.scan_type.is_some()),
        ])
    }
}

/// The largest `--data-profile-id` (2^53 − 1).
const MAX_SAFE: u64 = (1 << 53) - 1;

/// The filtering-profile body from the flags.
pub fn filtering_body(flags: &FilteringFlags) -> Result<Value, CliError> {
    if !(flags.file_based && flags.non_file_based) {
        return Err(CliError::usage(
            "--file-based and --non-file-based are both required",
        ));
    }
    let mut body = Map::new();
    body.insert("file_based".to_owned(), json!(true));
    body.insert("non_file_based".to_owned(), json!(true));
    let mut text = |key: &str, value: &Option<String>| {
        if let Some(value) = value {
            body.insert(key.to_owned(), json!(value));
        }
    };
    text("description", &flags.description);
    text("direction", &flags.direction);
    text("log_severity", &flags.log_severity);
    text("scan_type", &flags.scan_type);
    if let Some(raw) = &flags.data_profile_id {
        let id = raw
            .parse::<u64>()
            .ok()
            .filter(|id| raw.bytes().all(|b| b.is_ascii_digit()) && *id <= MAX_SAFE)
            .ok_or_else(|| CliError::usage("--data-profile-id must be a non-negative integer"))?;
        body.insert("data_profile_id".to_owned(), json!(id));
    }
    if let Some(template) = &flags.euc_template_id {
        body.insert("euc_template_id".to_owned(), json!(template));
    }
    if flags.end_user_coaching {
        body.insert("is_end_user_coaching_enabled".to_owned(), json!(true));
    }
    if flags.granular {
        body.insert("is_granular_profile".to_owned(), json!(true));
    }
    if !flags.file_type.is_empty() {
        body.insert("file_type".to_owned(), json!(flags.file_type));
    }
    Ok(Value::Object(body))
}

// ---------------------------------------------------------------------------
// The profile builder (§16.7, TS `bb.ts:127-213`)
// ---------------------------------------------------------------------------

/// The flags of `profiles create` and `replace`.
#[derive(Clone, Debug, Default)]
pub struct ProfileFlags {
    pub name: Option<String>,
    pub profile_type: Option<String>,
    pub description: Option<String>,
    pub granular: bool,
    pub pattern_id: Vec<String>,
    pub combinator: Option<String>,
    pub confidence: Option<String>,
}

impl ProfileFlags {
    /// The first build flag given, in help order (`--profile-type` is checked with a
    /// body too, TS).
    pub fn first_given(&self) -> Option<&'static str> {
        first_given(&[
            ("combinator", self.combinator.is_some()),
            ("confidence", self.confidence.is_some()),
            ("description", self.description.is_some()),
            ("granular", self.granular),
            ("name", self.name.is_some()),
            ("pattern-id", !self.pattern_id.is_empty()),
        ])
    }
}

/// TS `validateProfileType`: `basic` and any other value but `advanced` are refused.
pub fn check_profile_type(value: Option<&Value>) -> Result<(), CliError> {
    match value {
        None => Ok(()),
        Some(Value::String(kind)) if kind == "advanced" => Ok(()),
        Some(Value::String(kind)) if kind == "basic" => Err(CliError::usage(
            "Basic profile writes are unsupported: the API returned advanced for basic requests. Use advanced or manage basic profiles in SCM.",
        )),
        Some(_) => Err(CliError::usage("Profile type must be advanced")),
    }
}

/// TS `validateProfileName`: a nonblank string of at most 32 UTF-16 units.
pub fn check_profile_name(value: Option<&Value>) -> Result<(), CliError> {
    let Some(name) = value
        .and_then(Value::as_str)
        .filter(|name| !crate::tenant::config::js_trim(name).is_empty())
    else {
        return Err(CliError::usage(
            "Profile name is required and must be a nonblank string",
        ));
    };
    if name.encode_utf16().count() > 32 {
        return Err(CliError::usage(
            "Profile name must be at most 32 characters",
        ));
    }
    Ok(())
}

/// TS `validateBodyType`: a profile body or patch must carry a valid `name` and a
/// `profile_type` that is `advanced` or absent.
pub fn check_profile_body(body: &Value) -> Result<(), CliError> {
    check_profile_name(body.get("name"))?;
    check_profile_type(body.get("profile_type"))
}

/// The combinators of `--combinator` (lower-cased).
const COMBINATORS: [&str; 5] = ["and", "or", "not", "and_not", "or_not"];
/// The confidence levels of `--confidence` (case-sensitive).
const LEVELS: [&str; 3] = ["low", "medium", "high"];

/// The validated profile flags: the combinator (lower-cased, default `or`) and the
/// confidence (default `high`).
pub fn check_profile_flags(flags: &ProfileFlags) -> Result<(String, String), CliError> {
    if flags.name.as_deref().is_none_or(str::is_empty) {
        return Err(CliError::usage("--name is required"));
    }
    check_profile_name(flags.name.as_ref().map(|name| json!(name)).as_ref())?;
    let combinator = flags.combinator.as_deref().unwrap_or("or").to_lowercase();
    if !COMBINATORS.contains(&combinator.as_str()) {
        return Err(CliError::usage(
            "--combinator must be one of and|or|not|and_not|or_not",
        ));
    }
    let confidence = flags.confidence.as_deref().unwrap_or("high").to_owned();
    if !LEVELS.contains(&confidence.as_str()) {
        return Err(CliError::usage("--confidence must be low|medium|high"));
    }
    let mut seen = std::collections::HashSet::new();
    for id in &flags.pattern_id {
        super::check_id(Kind::Pattern, id)?;
        if !seen.insert(id.as_str()) {
            return Err(CliError::usage(
                "--pattern-id lists the same data pattern twice",
            ));
        }
    }
    Ok((combinator, confidence))
}

/// The profile body of the flags without its rules (`{name, profile_type, description?,
/// is_granular_data_profile?}`).
pub fn profile_base(flags: &ProfileFlags) -> Value {
    let mut body = Map::new();
    body.insert(
        "name".to_owned(),
        json!(flags.name.clone().unwrap_or_default()),
    );
    body.insert("profile_type".to_owned(), json!("advanced"));
    if let Some(description) = &flags.description {
        body.insert("description".to_owned(), json!(description));
    }
    if flags.granular {
        body.insert("is_granular_data_profile".to_owned(), json!(true));
    }
    Value::Object(body)
}

/// A referenced pattern, read and checked (TD§10.2).
#[derive(Clone, Debug, PartialEq)]
pub struct Referenced {
    pub id: String,
    pub name: String,
    pub version: Value,
    pub technique: String,
    pub levels: Vec<String>,
}

/// Check a `--pattern-id` read (`id` the argument): the same id, a name, a technique and
/// an integer version of at least 1, then `status: active` (exit 1, no write).
pub fn referenced(id: &str, record: &OValue) -> Result<Referenced, CliError> {
    let mismatch = || {
        CliError::operational(
            "Referenced pattern did not return a matching ID, name, technique, and version; no profile was written",
        )
    };
    fn text(value: Option<&OValue>) -> Option<&str> {
        value.and_then(OValue::as_str).filter(|s| !s.is_empty())
    }
    let version = match record.get("version") {
        Some(OValue::Number(number))
            if number
                .as_f64()
                .is_some_and(|v| v.fract() == 0.0 && v >= 1.0) =>
        {
            crate::json::to_compact(number)
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .ok_or_else(mismatch)?
        }
        _ => return Err(mismatch()),
    };
    let technique = record
        .get("detection_config")
        .and_then(|config| text(config.get("technique")));
    let (Some(found), Some(name), Some(technique)) =
        (text(record.get("id")), text(record.get("name")), technique)
    else {
        return Err(mismatch());
    };
    if found != id {
        return Err(mismatch());
    }
    if record.get("status").and_then(OValue::as_str) != Some("active") {
        return Err(CliError::operational(
            "Referenced pattern is not active; no profile was written",
        ));
    }
    let levels = record
        .get("detection_config")
        .and_then(|config| config.get("supported_confidence_levels"))
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(OValue::as_str)
        .map(str::to_owned)
        .collect();
    Ok(Referenced {
        id: found.to_owned(),
        name: name.to_owned(),
        version,
        technique: technique.to_owned(),
        levels,
    })
}

/// The one `expression_tree` rule over the referenced patterns (TS leaf shape).
pub fn profile_rules(
    patterns: &[Referenced],
    combinator: &str,
    confidence: &str,
) -> Result<Value, CliError> {
    let mut leaves = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        if !pattern.levels.is_empty() && !pattern.levels.iter().any(|level| level == confidence) {
            return Err(CliError::operational(
                "Requested confidence is not supported by every referenced pattern",
            ));
        }
        let supported = if pattern.levels.is_empty() {
            vec![confidence.to_owned()]
        } else {
            pattern.levels.clone()
        };
        leaves.push(json!({"rule_item": {
            "id": pattern.id,
            "name": pattern.name,
            "version": pattern.version,
            "detection_technique": pattern.technique,
            "confidence_level": confidence,
            "supported_confidence_levels": supported,
            "match_type": "include",
            "occurrence_operator_type": "more_than_equal_to",
            "occurrence_count": 1
        }}));
    }
    Ok(json!([{
        "rule_type": "expression_tree",
        "expression_tree": {"operator_type": combinator, "sub_expressions": leaves}
    }]))
}

// ---------------------------------------------------------------------------
// Dictionary metadata (§16.8)
// ---------------------------------------------------------------------------

/// The metadata flags of `dictionaries create` and `replace`.
#[derive(Clone, Debug, Default)]
pub struct DictionaryFlags {
    pub name: Option<String>,
    pub category: Option<String>,
    pub description: Option<String>,
    pub region: Option<String>,
    pub classification: Option<String>,
}

impl DictionaryFlags {
    /// The first metadata flag given, in help order.
    pub fn first_given(&self) -> Option<&'static str> {
        first_given(&[
            ("category", self.category.is_some()),
            ("classification", self.classification.is_some()),
            ("description", self.description.is_some()),
            ("name", self.name.is_some()),
            ("region", self.region.is_some()),
        ])
    }
}

/// The metadata from the flags (`--name`, `--category`, `--region` and `--file`
/// required): `{name, category, region_name, original_file_name: <basename of --file>,
/// description?, classification?}`.
pub fn dictionary_metadata(
    flags: &DictionaryFlags,
    file: Option<&OsStr>,
) -> Result<Value, CliError> {
    fn given(value: &Option<String>) -> Option<&str> {
        value.as_deref().filter(|value| !value.is_empty())
    }
    let (Some(name), Some(category), Some(region), Some(file)) = (
        given(&flags.name),
        given(&flags.category),
        given(&flags.region),
        file.filter(|file| !file.is_empty()),
    ) else {
        return Err(CliError::usage(
            "--name, --category, --region, and --file are required",
        ));
    };
    let base = std::path::Path::new(file)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut metadata = Map::new();
    metadata.insert("name".to_owned(), json!(name));
    metadata.insert("category".to_owned(), json!(category));
    metadata.insert("region_name".to_owned(), json!(region));
    metadata.insert("original_file_name".to_owned(), json!(base));
    if let Some(description) = &flags.description {
        metadata.insert("description".to_owned(), json!(description));
    }
    if let Some(classification) = &flags.classification {
        metadata.insert("classification".to_owned(), json!(classification));
    }
    Ok(Value::Object(metadata))
}

/// The SDK body budget of a multipart upload (8 MiB − 64 KiB, as D132).
pub const UPLOAD_BUDGET: usize = 8 * 1024 * 1024 - 64 * 1024;

// ---------------------------------------------------------------------------
// The omitted fields of a replace (D168)
// ---------------------------------------------------------------------------

/// The top-level request-schema fields of a replace on `kind`, in schema order.
fn request_fields(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::FilteringProfile => &[
            "file_based",
            "non_file_based",
            "description",
            "direction",
            "log_severity",
            "scan_type",
            "data_profile_id",
            "euc_template_id",
            "is_end_user_coaching_enabled",
            "is_granular_profile",
            "file_type",
            "criteria_details",
            "exception_rules",
            "exclusions",
            "rule1",
            "rule2",
        ],
        Kind::Pattern => &[
            "name",
            "type",
            "detection_config",
            "description",
            "matching_rules",
            "tags",
        ],
        Kind::Profile => &[
            "name",
            "detection_rules",
            "description",
            "is_granular_data_profile",
        ],
        Kind::Dictionary => &[
            "category",
            "name",
            "original_file_name",
            "region_name",
            "description",
            "is_case_sensitive",
            "type",
        ],
    }
}

/// The request-schema fields the current record holds (present, not `null`) that the
/// replacement `body` does not set, in schema order (names only).
pub fn omitted_fields(kind: Kind, current: &OValue, body: &Value) -> Vec<&'static str> {
    request_fields(kind)
        .iter()
        .copied()
        .filter(|field| {
            current
                .get(field)
                .is_some_and(|value| !matches!(value, OValue::Null))
                && body.get(field).is_none()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage<T: std::fmt::Debug>(result: Result<T, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    fn pattern(edit: impl FnOnce(&mut PatternFlags)) -> Result<Value, CliError> {
        let mut flags = PatternFlags {
            name: Some("P".into()),
            ..PatternFlags::default()
        };
        edit(&mut flags);
        pattern_body(&flags)
    }

    /// TS `dlp-build-body.spec.ts`: the pattern builder.
    #[test]
    fn the_pattern_builder_follows_typescript() {
        assert_eq!(
            pattern(|_| {}).unwrap(),
            json!({"name": "P", "type": "custom", "detection_config": {"technique": "regex"}})
        );
        let body = pattern(|f| {
            f.r#type = Some("file_property".into());
            f.technique = Some("weighted_regex".into());
            f.confidence_levels = Some("high, low,".into());
            f.regex = strings(&["a+"]);
            f.weighted_regex = strings(&["A|B|2.5", "c|3", "d|-1", "e|4.0"]);
            f.delimiter = Some(",".into());
            f.proximity_distance = Some("50".into());
            f.proximity_keyword = strings(&["near"]);
            f.tag = strings(&["compliance=PCI, HIPAA", "compliance=SOX", "geo=US"]);
            f.description = Some("d".into());
        })
        .unwrap();
        assert_eq!(
            body,
            json!({
                "name": "P",
                "type": "file_property",
                "detection_config": {"technique": "weighted_regex", "supported_confidence_levels": ["high", "low"]},
                "description": "d",
                "matching_rules": {
                    "delimiter": ",",
                    "proximity_distance": 50,
                    "proximity_keywords": ["near"],
                    "regexes": [
                        {"regex": "a+", "weight": 1},
                        {"regex": "A|B", "weight": 2.5},
                        {"regex": "c", "weight": 3},
                        {"regex": "d", "weight": -1},
                        {"regex": "e", "weight": 4}
                    ]
                },
                "tags": {"compliance": ["PCI", "HIPAA", "SOX"], "geo": ["US"]}
            })
        );
        // An empty confidence list sends no levels; no rule flag sends no matching_rules.
        assert_eq!(
            pattern(|f| f.confidence_levels = Some(" , ".into())).unwrap()["detection_config"],
            json!({"technique": "regex"})
        );
    }

    #[test]
    fn pattern_builder_errors_name_the_flag_only() {
        assert_eq!(usage(pattern(|f| f.name = None)), "--name is required");
        assert_eq!(
            usage(pattern(|f| f.name = Some(String::new()))),
            "--name is required"
        );
        for bad in [
            "abc",
            "a|",
            "|2",
            "a|zz",
            "a|1e3",
            "a|Infinity",
            "SECRET-RE|x",
        ] {
            let text = usage(pattern(|f| f.weighted_regex = strings(&[bad])));
            assert_eq!(
                text,
                "--weighted-regex must be PATTERN|weight with a numeric weight"
            );
            assert!(!text.contains("SECRET"));
        }
        for bad in ["foo", "=v", " =v"] {
            assert_eq!(
                usage(pattern(|f| f.tag = strings(&[bad]))),
                "--tag must be key=value[,value...]"
            );
        }
        for bad in ["geo=", "geo= , "] {
            assert_eq!(
                usage(pattern(|f| f.tag = strings(&[bad]))),
                "--tag needs at least one value"
            );
        }
        for bad in ["abc", "1", "1001", "2.5", "-3", "", "+5"] {
            assert_eq!(
                usage(pattern(|f| f.proximity_distance = Some(bad.into()))),
                "--proximity-distance must be an integer from 2 to 1000",
                "{bad}"
            );
        }
        for good in ["2", "1000"] {
            assert!(pattern(|f| f.proximity_distance = Some(good.into())).is_ok());
        }
        // TS order: the weighted regex before the tag before the distance.
        assert_eq!(
            usage(pattern(|f| {
                f.weighted_regex = strings(&["x"]);
                f.tag = strings(&["x"]);
                f.proximity_distance = Some("x".into());
            })),
            "--weighted-regex must be PATTERN|weight with a numeric weight"
        );
    }

    #[test]
    fn a_replace_takes_the_current_type_and_technique() {
        let mut body = pattern(|_| {}).unwrap();
        let current = crate::json::parse(
            r#"{"type":"file_property","detection_config":{"technique":"weighted_regex"}}"#,
        )
        .unwrap();
        complete_pattern(&mut body, &current, true, true);
        assert_eq!(body["type"], "file_property");
        assert_eq!(body["detection_config"]["technique"], "weighted_regex");
        let mut body = pattern(|f| f.r#type = Some("custom".into())).unwrap();
        complete_pattern(&mut body, &current, false, false);
        assert_eq!(body["type"], "custom");
        assert_eq!(body["detection_config"]["technique"], "regex");
    }

    #[test]
    fn the_filtering_builder_needs_both_booleans() {
        let both = FilteringFlags {
            file_based: true,
            non_file_based: true,
            ..FilteringFlags::default()
        };
        assert_eq!(
            filtering_body(&both).unwrap(),
            json!({"file_based": true, "non_file_based": true})
        );
        for one in [
            FilteringFlags {
                file_based: true,
                ..FilteringFlags::default()
            },
            FilteringFlags::default(),
        ] {
            assert_eq!(
                usage(filtering_body(&one)),
                "--file-based and --non-file-based are both required"
            );
        }
        let full = FilteringFlags {
            description: Some("d".into()),
            direction: Some("UPLOAD".into()),
            log_severity: Some("HIGH".into()),
            scan_type: Some("exclude".into()),
            data_profile_id: Some("123".into()),
            euc_template_id: Some("e1".into()),
            end_user_coaching: true,
            granular: true,
            file_type: strings(&["pdf", "docx"]),
            ..both.clone()
        };
        assert_eq!(
            filtering_body(&full).unwrap(),
            json!({"file_based":true,"non_file_based":true,"description":"d","direction":"UPLOAD","log_severity":"HIGH","scan_type":"exclude","data_profile_id":123,"euc_template_id":"e1","is_end_user_coaching_enabled":true,"is_granular_profile":true,"file_type":["pdf","docx"]})
        );
        for bad in ["abc", "1e3", "-1", "1.5", "9007199254740992", ""] {
            let flags = FilteringFlags {
                data_profile_id: Some(bad.into()),
                ..both.clone()
            };
            assert_eq!(
                usage(filtering_body(&flags)),
                "--data-profile-id must be a non-negative integer",
                "{bad}"
            );
        }
    }

    fn profile(edit: impl FnOnce(&mut ProfileFlags)) -> Result<(String, String), CliError> {
        let mut flags = ProfileFlags {
            name: Some("NP".into()),
            ..ProfileFlags::default()
        };
        edit(&mut flags);
        check_profile_flags(&flags)
    }

    #[test]
    fn the_profile_flags_follow_typescript() {
        assert_eq!(
            profile(|_| {}).unwrap(),
            ("or".to_owned(), "high".to_owned())
        );
        assert_eq!(
            profile(|f| f.combinator = Some("AND_NOT".into()))
                .unwrap()
                .0,
            "and_not"
        );
        assert_eq!(usage(profile(|f| f.name = None)), "--name is required");
        assert_eq!(
            usage(profile(|f| f.name = Some("   ".into()))),
            "Profile name is required and must be a nonblank string"
        );
        assert!(profile(|f| f.name = Some("x".repeat(32))).is_ok());
        assert_eq!(
            usage(profile(|f| f.name = Some("x".repeat(33)))),
            "Profile name must be at most 32 characters"
        );
        // UTF-16 units: 16 astral characters are 32 units.
        assert!(profile(|f| f.name = Some("😀".repeat(16))).is_ok());
        assert!(profile(|f| f.name = Some("😀".repeat(17))).is_err());
        assert_eq!(
            usage(profile(|f| f.combinator = Some("xor".into()))),
            "--combinator must be one of and|or|not|and_not|or_not"
        );
        assert_eq!(
            usage(profile(|f| f.confidence = Some("HIGH".into()))),
            "--confidence must be low|medium|high"
        );
        assert_eq!(
            usage(profile(|f| f.pattern_id = strings(&["p1", "p2", "p1"]))),
            "--pattern-id lists the same data pattern twice"
        );
        assert_eq!(
            usage(profile(|f| f.pattern_id = strings(&[".."]))),
            "Invalid data pattern id: .."
        );
        assert!(check_profile_type(Some(&json!("advanced"))).is_ok());
        assert!(check_profile_type(None).is_ok());
        assert!(
            usage(check_profile_type(Some(&json!("basic"))))
                .starts_with("Basic profile writes are unsupported")
        );
        assert_eq!(
            usage(check_profile_type(Some(&json!(null)))),
            "Profile type must be advanced"
        );
    }

    #[test]
    fn referenced_patterns_are_checked_and_build_leaves() {
        let read = |text: &str| crate::json::parse(text).unwrap();
        let good = read(
            r#"{"id":"p1","name":"P1","status":"active","version":2,"detection_config":{"technique":"regex","supported_confidence_levels":["high","low"]}}"#,
        );
        let pattern = referenced("p1", &good).unwrap();
        assert_eq!(pattern.version, json!(2));
        assert_eq!(pattern.levels, ["high", "low"]);
        let rules = profile_rules(std::slice::from_ref(&pattern), "or", "low").unwrap();
        assert_eq!(
            rules,
            json!([{"rule_type":"expression_tree","expression_tree":{"operator_type":"or","sub_expressions":[{"rule_item":{"id":"p1","name":"P1","version":2,"detection_technique":"regex","confidence_level":"low","supported_confidence_levels":["high","low"],"match_type":"include","occurrence_operator_type":"more_than_equal_to","occurrence_count":1}}]}}])
        );
        match profile_rules(&[pattern], "or", "medium") {
            Err(CliError::Operational(failure)) => assert_eq!(
                failure.message,
                "Requested confidence is not supported by every referenced pattern"
            ),
            other => panic!("{other:?}"),
        }
        for bad in [
            r#"{"id":"p2","name":"P1","status":"active","version":2,"detection_config":{"technique":"regex"}}"#,
            r#"{"id":"p1","status":"active","version":2,"detection_config":{"technique":"regex"}}"#,
            r#"{"id":"p1","name":"P1","status":"active","version":0,"detection_config":{"technique":"regex"}}"#,
            r#"{"id":"p1","name":"P1","status":"active","version":1.5,"detection_config":{"technique":"regex"}}"#,
            r#"{"id":"p1","name":"P1","status":"active","version":1}"#,
        ] {
            assert!(
                matches!(
                    referenced("p1", &read(bad)),
                    Err(CliError::Operational(failure)) if failure.message.starts_with("Referenced pattern did not return")
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            referenced("p1", &read(r#"{"id":"p1","name":"P1","status":"disabled","version":1,"detection_config":{"technique":"regex"}}"#)),
            Err(CliError::Operational(failure)) if failure.message == "Referenced pattern is not active; no profile was written"
        ));
        // No levels: the leaf supports the requested confidence only.
        let bare = referenced(
            "p1",
            &read(r#"{"id":"p1","name":"P1","status":"active","version":1,"detection_config":{"technique":"regex"}}"#),
        )
        .unwrap();
        let rules = profile_rules(&[bare], "and", "medium").unwrap();
        assert_eq!(
            rules[0]["expression_tree"]["sub_expressions"][0]["rule_item"]["supported_confidence_levels"],
            json!(["medium"])
        );
    }

    #[test]
    fn hatches_are_exclusive_and_checked_before_any_read() {
        let file = OsStr::new("b.json");
        assert_eq!(
            hatch(None, None, Some("name"), Texts::Body, false).unwrap(),
            None
        );
        assert_eq!(
            usage(hatch(Some("{}"), Some(file), None, Texts::Body, false)),
            "--body and --body-file are mutually exclusive"
        );
        assert_eq!(
            usage(hatch(Some("{}"), None, Some("name"), Texts::Body, false)),
            "--body and --body-file cannot be combined with --name"
        );
        assert_eq!(
            usage(hatch(Some(""), None, None, Texts::Body, false)),
            "--body needs a JSON object"
        );
        assert_eq!(
            usage(hatch(None, Some(OsStr::new("")), None, Texts::Body, false)),
            "--body-file needs a path"
        );
        assert_eq!(
            usage(hatch(Some("-"), None, None, Texts::Body, true)),
            "--body - requires piped input on stdin"
        );
        assert_eq!(
            hatch(Some("-"), None, None, Texts::Body, false).unwrap(),
            Some(Input::Stdin)
        );
        assert_eq!(
            hatch(None, Some(file), None, Texts::Body, true).unwrap(),
            Some(Input::File(file.to_owned()))
        );
        for (text, message) in [
            ("PRIVATE-REGEX-123", "--body is not valid JSON"),
            ("null", "--body must contain a JSON object"),
            ("0", "--body must contain a JSON object"),
            ("false", "--body must contain a JSON object"),
            ("\"\"", "--body must contain a JSON object"),
            ("[]", "--body must contain a JSON object"),
        ] {
            let error = usage(hatch(Some(text), None, None, Texts::Body, false));
            assert_eq!(error, message);
            assert!(!error.contains("PRIVATE"));
        }
        assert_eq!(
            usage(hatch(Some("{x"), None, None, Texts::Profile, false)),
            "Cannot read profile body as JSON; verify the file and JSON syntax"
        );
        assert_eq!(
            usage(hatch(Some("[]"), None, None, Texts::Profile, false)),
            "Profile body must be a JSON object"
        );
        assert_eq!(
            hatch(Some(r#"{"name":"B1"}"#), None, None, Texts::Body, false).unwrap(),
            Some(Input::Ready(json!({"name": "B1"})))
        );
    }

    #[test]
    fn predefined_bodies_and_schema_texts() {
        assert!(refuse_predefined(Kind::Pattern, &json!({"type": "custom"})).is_ok());
        assert_eq!(
            usage(refuse_predefined(
                Kind::Dictionary,
                &json!({"type": "predefined"})
            )),
            "dictionary bodies cannot set \"type\": \"predefined\"; predefined resources are shipped by Palo Alto Networks and never written by airs"
        );
        assert_eq!(encode_component("a/b?c"), "a%2Fb%3Fc");
        assert_eq!(encode_component("p-1_(x)!~*'."), "p-1_(x)!~*'.");
        assert_eq!(encode_component("é"), "%C3%A9");
        assert_eq!(
            schema_text(Kind::Pattern, "PUT", Some("a/b")),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v2/api/data-patterns/a%2Fb did not match schema"
        );
        assert_eq!(
            schema_text(Kind::FilteringProfile, "PUT", Some("fp-1")),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v2/api/data-filtering-profiles/fp-1 did not match schema"
        );
        assert_eq!(
            usage(check(
                Kind::Pattern,
                Write::Create,
                None,
                &json!({"name": "x"}),
                true
            )),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v2/api/data-patterns did not match schema"
        );
        assert!(check(
            Kind::Pattern,
            Write::Create,
            None,
            &json!({"name": "x", "type": "custom", "detection_config": {"technique": "regex"}, "extra": 1}),
            true
        )
        .is_ok());
        assert_eq!(
            usage(check(
                Kind::Profile,
                Write::Create,
                None,
                &json!({"name": "x", "profile_type": "advanced"}),
                true
            )),
            PROFILE_METADATA
        );
        let metadata = json!({"name": "D", "category": "Financial", "region_name": "United States", "original_file_name": "kw.txt"});
        assert!(check(Kind::Dictionary, Write::Create, None, &metadata, true).is_ok());
        for bad in [
            json!({"name": "D", "category": "Bogus", "region_name": "US", "original_file_name": "kw.txt"}),
            json!({"name": "D", "category": "Financial", "region_name": "US"}),
            json!({"name": "D", "category": "Financial", "region_name": "US", "original_file_name": "a\"b"}),
            json!({"name": "D", "category": "Financial", "region_name": "US", "original_file_name": ".."}),
        ] {
            assert_eq!(
                usage(check(Kind::Dictionary, Write::Create, None, &bad, true)),
                DICTIONARY_METADATA
            );
        }
        assert!(matches!(
            check(
                Kind::FilteringProfile,
                Write::Replace,
                Some("fp"),
                &json!({"file_based": true, "non_file_based": true, "direction": "sideways"}),
                false
            ),
            Err(CliError::Operational(_))
        ));
    }

    #[test]
    fn dictionary_metadata_from_the_flags() {
        let flags = DictionaryFlags {
            name: Some("D1".into()),
            category: Some("Confidential".into()),
            region: Some("United States".into()),
            description: Some("dd".into()),
            classification: Some("pab".into()),
        };
        assert_eq!(
            dictionary_metadata(&flags, Some(OsStr::new("dir/kw.txt"))).unwrap(),
            json!({"name":"D1","category":"Confidential","region_name":"United States","original_file_name":"kw.txt","description":"dd","classification":"pab"})
        );
        for (edit, file) in [
            (
                DictionaryFlags {
                    name: None,
                    ..flags.clone()
                },
                Some("kw.txt"),
            ),
            (
                DictionaryFlags {
                    region: None,
                    ..flags.clone()
                },
                Some("kw.txt"),
            ),
            (flags.clone(), None),
        ] {
            assert_eq!(
                usage(dictionary_metadata(&edit, file.map(OsStr::new))),
                "--name, --category, --region, and --file are required"
            );
        }
        assert_eq!(flags.first_given(), Some("category"));
        assert_eq!(DictionaryFlags::default().first_given(), None);
    }

    #[test]
    fn the_omitted_fields_are_named_in_schema_order() {
        let current = crate::json::parse(
            r#"{"id":"fp-2","name":"Custom FP","description":"x","type":"custom","file_based":false,"non_file_based":true,"version":2,"exclusions":{},"rule1":{"action":"block"},"rule2":null}"#,
        )
        .unwrap();
        let body = json!({"file_based": true, "non_file_based": true});
        assert_eq!(
            omitted_fields(Kind::FilteringProfile, &current, &body),
            ["description", "exclusions", "rule1"]
        );
        let full = json!({"file_based": true, "non_file_based": true, "description": "d", "exclusions": {}, "rule1": {}});
        assert!(omitted_fields(Kind::FilteringProfile, &current, &full).is_empty());
    }
}
