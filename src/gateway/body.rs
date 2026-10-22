//! Structured request input of the gateway writes (DESIGN §19.3 "Request bodies"; D246,
//! D233, G49): the scalar flag parsers (TS `structured-input.ts`), the `--set` and
//! `--set-string` assignments, a port of the TypeScript SDK's dotted paths
//! (`nested-values.ts`, with its texts: the Rust SDK's helpers return bare validation
//! errors), the bounded `--file` body, the CLI refinements and the SDK request schema.
//!
//! Every message names the flag, field, path or route only, never a value (D233). The
//! parsers run during planning (exit 2, before the debug log and the tenant); the body is
//! built after the debug log, once `--file` was read (§19.3 "Validation order").

use crate::error::CliError;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::ffi::OsString;

/// The prefix of every dotted-path, refinement and schema text (TS `asUsageError`).
pub const INVALID_REQUEST: &str = "Invalid AI Gateway request";

/// `--file` that is not one JSON object (choice 32).
pub const FILE_NOT_OBJECT: &str =
    "--file must contain one JSON object (YAML request files are not supported)";

/// The keys TypeScript's JSON schemas refuse (`unsafeJsonKeys`).
const UNSAFE_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// `Invalid --<flag>: <reason>` (the flag as typed, D233).
fn invalid(flag: &str, reason: &str) -> CliError {
    CliError::usage(format!("Invalid {flag}: {reason}"))
}

/// `Invalid AI Gateway request: AISEC_USER_REQUEST_PAYLOAD_ERROR:<reason>`.
fn payload(reason: &str) -> CliError {
    CliError::usage(format!(
        "{INVALID_REQUEST}: AISEC_USER_REQUEST_PAYLOAD_ERROR:{reason}"
    ))
}

/// `Invalid AI Gateway request: <path>: <message>` (a refinement, TS zod text).
pub fn refinement(path: &str, message: &str) -> CliError {
    CliError::usage(format!("{INVALID_REQUEST}: {path}: {message}"))
}

/// The D116 text of a body that fails the SDK request schema, as a usage error (§19.3).
pub fn schema_error(method: &str, path: &str) -> CliError {
    CliError::usage(format!(
        "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for {method} {path} did not match schema"
    ))
}

// ---------------------------------------------------------------------------
// Scalar flags (TS `parse*Option`, GW§2.8)
// ---------------------------------------------------------------------------

/// `true` or `false` (`Expected true or false`).
pub fn boolean(flag: &str, value: &str) -> Result<bool, CliError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid(flag, "Expected true or false")),
    }
}

/// `^-?(0|[1-9]\d*)$` and safe (`Expected an integer`, `Expected a safe integer`).
pub fn integer(flag: &str, value: &str) -> Result<i64, CliError> {
    super::integer(value).map_err(|reason| invalid(flag, reason))
}

/// A trimmed comma list without empty items, at least one item.
pub fn csv(flag: &str, value: &str) -> Result<Vec<String>, CliError> {
    let items: Vec<String> = value
        .split(',')
        .map(|item| crate::tenant::config::js_trim(item).to_owned())
        .filter(|item| !item.is_empty())
        .collect();
    if items.is_empty() {
        Err(invalid(flag, "Expected a non-empty comma-separated list"))
    } else {
        Ok(items)
    }
}

/// Why [`js_json`] refused a text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsJsonError {
    /// Not JSON.
    Invalid,
    /// JSON whose number overflows a double (JS `JSON.parse` reads it as `Infinity`).
    NonFinite,
}

/// Parse JSON the way JS `JSON.parse` then `JSON.stringify` sees it: a number literal that
/// overflows a double is [`JsJsonError::NonFinite`] (never a string), and every number is
/// in its `JSON.stringify` form ([`js_numbers`]).
pub fn js_json(text: &str) -> Result<Value, JsJsonError> {
    match serde_json::from_str::<Value>(text) {
        Ok(mut value) => {
            js_numbers(&mut value);
            Ok(value)
        }
        Err(_) if overflows(text) => Err(JsJsonError::NonFinite),
        Err(_) => Err(JsJsonError::Invalid),
    }
}

/// Whether a number token outside the strings of `text` overflows a double.
fn overflows(text: &str) -> bool {
    let mut in_string = false;
    let mut escaped = false;
    let mut chars = text.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '-' | '0'..='9' => {
                let mut end = start + c.len_utf8();
                while let Some(&(at, next)) = chars.peek() {
                    if next.is_ascii_digit() || matches!(next, '.' | 'e' | 'E' | '+' | '-') {
                        end = at + next.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                if text[start..end]
                    .parse::<f64>()
                    .is_ok_and(|number| number.is_infinite())
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// The `JSON.stringify` form of every number in `value`: an integral double within the
/// safe-integer range is an integer (`1e2` → `100`, `1.0` → `1`, `-0` → `0`); other
/// numbers stay as parsed.
pub fn js_numbers(value: &mut Value) {
    match value {
        Value::Number(number) if number.is_f64() => {
            if let Some(float) = number.as_f64()
                && float.fract() == 0.0
                && float.abs() <= 9_007_199_254_740_991.0
            {
                // Checked: integral and within the safe range, so the cast is exact.
                #[allow(clippy::cast_possible_truncation)]
                let integer = float as i64;
                *value = Value::from(integer);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(js_numbers),
        Value::Object(map) => map.values_mut().for_each(js_numbers),
        _ => {}
    }
}

/// One JSON value (`Expected valid JSON`; the text is never echoed). A number that
/// overflows a double is TS's `Dotted value must be finite JSON` (JS reads `Infinity`).
pub fn json(flag: &str, value: &str) -> Result<Value, CliError> {
    js_json(value).map_err(|error| match error {
        JsJsonError::Invalid => invalid(flag, "Expected valid JSON"),
        JsJsonError::NonFinite => payload("Dotted value must be finite JSON"),
    })
}

/// An ISO-8601 timestamp with an offset or `Z` (the zod `datetime({offset: true})`
/// grammar, choice 62); the text is sent as typed.
pub fn timestamp(flag: &str, value: &str) -> Result<String, CliError> {
    match crate::modelsec::datetime_millis(value) {
        Some(_) => Ok(value.to_owned()),
        None => Err(invalid(flag, "Expected an ISO-8601 timestamp")),
    }
}

/// `<key>=<value>` split at the first `=`, which may not be first.
fn split_pair<'a>(raw: &'a str, label: &str) -> Result<(&'a str, &'a str), String> {
    match raw.find('=') {
        Some(at) if at > 0 => Ok((&raw[..at], &raw[at + 1..])),
        _ => Err(format!("Expected {label}=value")),
    }
}

/// A `true`/`false` binding value (the reason only).
fn enabled(text: &str) -> Result<bool, String> {
    match text {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("Expected true or false".to_owned()),
    }
}

/// `id=true|false`… → `[{id, enabled}]` (`--workspace-binding`).
pub fn id_bindings(flag: &str, values: &[String]) -> Result<Value, CliError> {
    values
        .iter()
        .map(|raw| {
            let (id, state) = split_pair(raw, "id")?;
            Ok(serde_json::json!({"id": id, "enabled": enabled(state)?}))
        })
        .collect::<Result<Vec<Value>, String>>()
        .map(Value::Array)
        .map_err(|reason| invalid(flag, &reason))
}

/// `slug=true|false`… → `[{slug, enabled}]` (`--model`).
pub fn model_bindings(flag: &str, values: &[String]) -> Result<Value, CliError> {
    values
        .iter()
        .map(|raw| {
            let (slug, state) = split_pair(raw, "slug")?;
            Ok(serde_json::json!({"slug": slug, "enabled": enabled(state)?}))
        })
        .collect::<Result<Vec<Value>, String>>()
        .map(Value::Array)
        .map_err(|reason| invalid(flag, &reason))
}

/// `type:name=true|false`… → `[{type, name, enabled}]` (`--capability`).
pub fn capability_bindings(flag: &str, values: &[String]) -> Result<Value, CliError> {
    values
        .iter()
        .map(|raw| {
            let (identity, state) = split_pair(raw, "type:name")?;
            let (kind, name) = match identity.find(':') {
                Some(at) if at > 0 && at + 1 < identity.len() => {
                    (&identity[..at], &identity[at + 1..])
                }
                _ => return Err("Expected type:name=enabled".to_owned()),
            };
            Ok(serde_json::json!({"type": kind, "name": name, "enabled": enabled(state)?}))
        })
        .collect::<Result<Vec<Value>, String>>()
        .map(Value::Array)
        .map_err(|reason| invalid(flag, &reason))
}

/// `key=value`… → `{key: value}` (`--header`, `--credential`): `__proto__`,
/// `constructor` and `prototype` are `Unsafe key: <key>`, a repeated key `Duplicate key:
/// <key>` (key names are printed, values never; D233).
pub fn string_map(flag: &str, values: &[String]) -> Result<Value, CliError> {
    let mut map = Map::new();
    for raw in values {
        let (key, item) = split_pair(raw, "key").map_err(|reason| invalid(flag, &reason))?;
        if UNSAFE_KEYS.contains(&key) {
            return Err(invalid(flag, &format!("Unsafe key: {}", super::shown(key))));
        }
        if map.contains_key(key) {
            return Err(invalid(
                flag,
                &format!("Duplicate key: {}", super::shown(key)),
            ));
        }
        map.insert(key.to_owned(), Value::String(item.to_owned()));
    }
    Ok(Value::Object(map))
}

/// One `--set path=value` (`value` as JSON, else the literal string) or `--set-string
/// path=value` (the string); `Invalid --set: Expected path=value` without the argument
/// (TS echoes it, D233).
fn assignment(flag: &str, raw: &str, force_string: bool) -> Result<(String, Value), CliError> {
    let (path, text) = split_pair(raw, "path").map_err(|reason| invalid(flag, &reason))?;
    let value = if force_string {
        Value::String(text.to_owned())
    } else {
        match js_json(text) {
            Ok(value) => value,
            // JS reads an overflowing number as `Infinity`, which TS refuses (never the
            // literal string).
            Err(JsJsonError::NonFinite) => {
                return Err(payload("Dotted value must be finite JSON"));
            }
            Err(JsJsonError::Invalid) => Value::String(text.to_owned()),
        }
    };
    Ok((path.to_owned(), value))
}

/// Every `--set`, then every `--set-string` (TS order).
pub fn assignments(
    sets: &[String],
    set_strings: &[String],
) -> Result<Vec<(String, Value)>, CliError> {
    let mut out = Vec::new();
    for raw in sets {
        out.push(assignment("--set", raw, false)?);
    }
    for raw in set_strings {
        out.push(assignment("--set-string", raw, true)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Dotted paths (a port of TS `nested-values.ts`)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Token {
    Property(String),
    Index(usize),
}

/// TS `parsePath` with its texts (the path is quoted terminal-safe; it is not a value).
fn parse_path(path: &str) -> Result<Vec<Token>, CliError> {
    if path.is_empty() {
        return Err(payload("Dotted path must not be empty"));
    }
    let shown = super::shown(path);
    let fail = |text: &str| payload(&format!("{text}: {shown}"));
    let chars: Vec<char> = path.chars().collect();
    let mut tokens = Vec::new();
    let mut property = String::new();
    let mut after_dot = false;
    let mut after_index = false;
    let push = |tokens: &mut Vec<Token>, value: &str| -> Result<(), CliError> {
        if value.is_empty() {
            return Err(payload(&format!("Invalid dotted path: {shown}")));
        }
        if UNSAFE_KEYS.contains(&value) {
            return Err(payload(&format!(
                "Unsafe dotted path segment: {}",
                super::shown(value)
            )));
        }
        tokens.push(Token::Property(value.to_owned()));
        Ok(())
    };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                i += 1;
                match chars.get(i) {
                    Some(escaped @ ('.' | '[' | ']' | '\\')) => {
                        if after_index {
                            return Err(fail("Missing dot after array index in path"));
                        }
                        property.push(*escaped);
                        after_dot = false;
                    }
                    _ => return Err(fail("Invalid escape in dotted path")),
                }
            }
            '.' => {
                if !property.is_empty() {
                    push(&mut tokens, &property)?;
                    property.clear();
                } else if !after_index {
                    return Err(fail("Invalid empty segment in dotted path"));
                }
                after_dot = true;
                after_index = false;
            }
            '[' => {
                if after_dot {
                    return Err(fail("Invalid array segment in dotted path"));
                }
                if !property.is_empty() {
                    push(&mut tokens, &property)?;
                    property.clear();
                } else if tokens.is_empty() {
                    return Err(fail("Dotted paths must start with an object property"));
                }
                let Some(close) = chars[i + 1..].iter().position(|c| *c == ']') else {
                    return Err(fail("Unclosed array index in dotted path"));
                };
                let raw: String = chars[i + 1..i + 1 + close].iter().collect();
                let shaped = !raw.is_empty()
                    && raw.bytes().all(|b| b.is_ascii_digit())
                    && (raw == "0" || !raw.starts_with('0'));
                if !shaped {
                    return Err(fail("Invalid array index in dotted path"));
                }
                // An index beyond `usize` can only leave a sparse array (TS fails there).
                let index = raw
                    .parse::<usize>()
                    .map_err(|_| payload("Sparse arrays are not supported"))?;
                tokens.push(Token::Index(index));
                i += close + 1;
                after_index = true;
                after_dot = false;
            }
            ']' => return Err(fail("Unexpected ] in dotted path")),
            other => {
                if after_index {
                    return Err(fail("Missing dot after array index in path"));
                }
                property.push(other);
                after_dot = false;
            }
        }
        i += 1;
    }
    if !property.is_empty() {
        push(&mut tokens, &property)?;
    } else if after_dot {
        return Err(fail("Dotted path must not end with a dot"));
    }
    if tokens.is_empty() {
        return Err(payload(&format!("Invalid dotted path: {shown}")));
    }
    Ok(tokens)
}

/// A JSON tree whose arrays may have holes while assignments are applied.
#[derive(Clone, Debug)]
enum Node {
    Leaf(Value),
    Object(BTreeMap<String, Node>),
    Array(BTreeMap<usize, Node>),
}

impl Node {
    fn from_value(value: Value) -> Self {
        match value {
            Value::Object(map) => Self::Object(
                map.into_iter()
                    .map(|(key, value)| (key, Self::from_value(value)))
                    .collect(),
            ),
            Value::Array(items) => Self::Array(
                items
                    .into_iter()
                    .map(Self::from_value)
                    .enumerate()
                    .collect(),
            ),
            leaf => Self::Leaf(leaf),
        }
    }

    /// The value, or `Sparse arrays are not supported` for an array with a hole.
    fn into_value(self) -> Result<Value, CliError> {
        Ok(match self {
            Self::Leaf(value) => value,
            Self::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, node)| node.into_value().map(|value| (key, value)))
                    .collect::<Result<_, _>>()?,
            ),
            Self::Array(map) => {
                let mut items = Vec::with_capacity(map.len());
                for (index, node) in map {
                    if index != items.len() {
                        return Err(payload("Sparse arrays are not supported"));
                    }
                    items.push(node.into_value()?);
                }
                Value::Array(items)
            }
        })
    }

    fn container(array: bool) -> Self {
        if array {
            Self::Array(BTreeMap::new())
        } else {
            Self::Object(BTreeMap::new())
        }
    }

    fn is_container(&self, array: bool) -> bool {
        matches!(
            (self, array),
            (Self::Array(_), true) | (Self::Object(_), false)
        )
    }
}

/// TS `assign`: walk `tokens` from `root`, creating containers, and set `value`.
fn assign(root: &mut Node, tokens: &[Token], value: &Value, replace: bool) -> Result<(), CliError> {
    let mut current = root;
    for (i, token) in tokens.iter().enumerate() {
        let last = i + 1 == tokens.len();
        let expect_array = matches!(tokens.get(i + 1), Some(Token::Index(_)));
        current = match (current, token) {
            (Node::Object(map), Token::Property(key)) => {
                if last {
                    if map.contains_key(key) && !replace {
                        return Err(payload("Duplicate dotted path"));
                    }
                    map.insert(key.clone(), Node::from_value(value.clone()));
                    return Ok(());
                }
                let child = map
                    .entry(key.clone())
                    .or_insert_with(|| Node::container(expect_array));
                if !child.is_container(expect_array) {
                    return Err(payload("Dotted path shape conflict"));
                }
                child
            }
            (Node::Array(map), Token::Index(index)) => {
                if last {
                    if map.contains_key(index) && !replace {
                        return Err(payload("Duplicate dotted path"));
                    }
                    map.insert(*index, Node::from_value(value.clone()));
                    return Ok(());
                }
                let child = map
                    .entry(*index)
                    .or_insert_with(|| Node::container(expect_array));
                if !child.is_container(expect_array) {
                    return Err(payload("Dotted path shape conflict"));
                }
                child
            }
            (_, Token::Index(_)) => {
                return Err(payload("Array index conflicts with an object path"));
            }
            (_, Token::Property(_)) => {
                return Err(payload("Object property conflicts with an array path"));
            }
        };
    }
    Ok(())
}

/// Whether a value is TS's finite, prototype-safe JSON (no unsafe key at any depth).
fn safe(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .all(|(key, value)| !UNSAFE_KEYS.contains(&key.as_str()) && safe(value)),
        Value::Array(items) => items.iter().all(safe),
        _ => true,
    }
}

/// TS `setDottedValue` (replacing an existing value).
fn set_dotted(body: Value, path: &str, value: &Value) -> Result<Value, CliError> {
    let tokens = parse_path(path)?;
    if !safe(value) {
        return Err(payload("Dotted value must be finite JSON"));
    }
    let mut root = Node::from_value(body);
    assign(&mut root, &tokens, value, true)?;
    root.into_value()
}

/// TS `buildDottedObject`: the assignments as a set (no path twice, no shape conflict
/// between them, no sparse array).
fn check_assignments(assignments: &[(String, Value)]) -> Result<(), CliError> {
    let mut parsed = Vec::new();
    for (path, value) in assignments {
        let tokens = parse_path(path)?;
        if !safe(value) {
            return Err(payload("Dotted value must be finite JSON"));
        }
        parsed.push((tokens, value));
    }
    let mut seen = std::collections::HashSet::new();
    for (tokens, _) in &parsed {
        if !seen.insert(tokens.clone()) {
            return Err(payload("Duplicate dotted path"));
        }
    }
    let mut root = Node::Object(BTreeMap::new());
    for (tokens, value) in &parsed {
        assign(&mut root, tokens, value, false)?;
    }
    root.into_value().map(|_| ())
}

// ---------------------------------------------------------------------------
// The body
// ---------------------------------------------------------------------------

/// The structured input of one write, parsed during planning.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Input {
    /// `--file <path>` (read after the debug log, before the tenant).
    pub file: Option<OsString>,
    /// The named flags given, in TS field order: `(request path, value)`.
    pub named: Vec<(&'static str, Value)>,
    /// `--set`, then `--set-string`: `(path, value)`.
    pub sets: Vec<(String, Value)>,
}

impl Input {
    /// A named flag's value at `path` (no-op for `None`).
    pub fn named(&mut self, path: &'static str, value: Option<Value>) {
        if let Some(value) = value {
            self.named.push((path, value));
        }
    }

    /// A text flag at `path`.
    pub fn text(&mut self, path: &'static str, value: Option<&String>) {
        self.named(path, value.map(|text| Value::String(text.clone())));
    }
}

/// Read `--file`: the §13.2 input rules (1 MiB, UTF-8, the messages naming `--file`'s
/// path; exit 1), then one JSON object (else [`FILE_NOT_OBJECT`], exit 2) without an
/// unsafe key (TS `GatewayJsonObjectSchema`).
pub fn read_file(path: &std::ffi::OsStr) -> Result<Value, CliError> {
    let text = crate::files::read_text(path, crate::files::CONFIG_LIMIT)?;
    let unsafe_object = || refinement("<root>", "Expected a finite, prototype-safe JSON object");
    match js_json(&text) {
        Ok(value @ Value::Object(_)) if safe(&value) => Ok(value),
        Ok(Value::Object(_)) => Err(unsafe_object()),
        // An overflowing number in an object is JS `Infinity` (TS's refinement).
        Err(JsJsonError::NonFinite) if text.trim_start().starts_with('{') => Err(unsafe_object()),
        _ => Err(CliError::usage(FILE_NOT_OBJECT)),
    }
}

/// Build the body (TS `buildStructuredRequest`): the `--file` object < the named flags <
/// the assignments (checked as a set first). The schema and the refinements follow.
pub fn build(input: &Input) -> Result<Value, CliError> {
    let mut body = match &input.file {
        Some(path) => read_file(path)?,
        None => Value::Object(Map::new()),
    };
    for (path, value) in &input.named {
        body = set_dotted(body, path, value)?;
    }
    check_assignments(&input.sets)?;
    for (path, value) in &input.sets {
        body = set_dotted(body, path, value)?;
    }
    Ok(body)
}

/// Whether the body has no member (the `Provide at least one field` refinement).
pub fn is_empty(body: &Value) -> bool {
    body.as_object().is_none_or(Map::is_empty)
}

/// The update refinement (G49): `Invalid AI Gateway request: <root>: Provide at least
/// one field`.
pub fn require_fields(body: &Value) -> Result<(), CliError> {
    if is_empty(body) {
        Err(refinement("<root>", "Provide at least one field"))
    } else {
        Ok(())
    }
}

/// Validate `body` with an SDK request schema (`Mode::Request`); a failure is the D116
/// usage text naming `<METHOD> <path>`.
pub fn validate<M>(
    body: &Value,
    method: &str,
    path: &str,
    parse: impl FnOnce(Value, scm::validation::Mode) -> scm::Result<M>,
) -> Result<M, CliError> {
    parse(body.clone(), scm::validation::Mode::Request).map_err(|_| schema_error(method, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn message(result: Result<impl std::fmt::Debug, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    fn input(named: Vec<(&'static str, Value)>, sets: &[(&str, Value)]) -> Input {
        Input {
            file: None,
            named,
            sets: sets
                .iter()
                .map(|(path, value)| ((*path).to_owned(), value.clone()))
                .collect(),
        }
    }

    /// TS `aigateway-structured-input.spec.ts` "parses reusable scalar option types
    /// strictly".
    #[test]
    fn scalars_are_strict() {
        assert!(boolean("--is-default", "true").unwrap());
        assert_eq!(
            message(boolean("--is-default", "yes")),
            "Invalid --is-default: Expected true or false"
        );
        assert_eq!(integer("--transition-ms", "1800000").unwrap(), 1_800_000);
        assert_eq!(
            message(integer("--transition-ms", "1.5")),
            "Invalid --transition-ms: Expected an integer"
        );
        assert_eq!(
            message(integer("--transition-ms", "9007199254740992")),
            "Invalid --transition-ms: Expected a safe integer"
        );
        assert_eq!(csv("--scopes", " a, ,b ").unwrap(), ["a", "b"]);
        assert_eq!(
            message(csv("--scopes", " , ")),
            "Invalid --scopes: Expected a non-empty comma-separated list"
        );
        assert_eq!(
            message(json("--checks", "{nope FAKE")),
            "Invalid --checks: Expected valid JSON"
        );
        assert_eq!(
            timestamp("--expires-at", "2027-01-01T00:00:00Z").unwrap(),
            "2027-01-01T00:00:00Z"
        );
        assert_eq!(
            message(timestamp("--expires-at", "2027-01-01")),
            "Invalid --expires-at: Expected an ISO-8601 timestamp"
        );
    }

    #[test]
    fn bindings_and_maps() {
        assert_eq!(
            id_bindings("--workspace-binding", &["ws-a=true".into()]).unwrap(),
            json!([{"id": "ws-a", "enabled": true}])
        );
        assert_eq!(
            message(id_bindings("--workspace-binding", &["=true".into()])),
            "Invalid --workspace-binding: Expected id=value"
        );
        assert_eq!(
            model_bindings("--model", &["gpt-4o=false".into()]).unwrap(),
            json!([{"slug": "gpt-4o", "enabled": false}])
        );
        assert_eq!(
            message(model_bindings("--model", &["gpt=maybe".into()])),
            "Invalid --model: Expected true or false"
        );
        assert_eq!(
            capability_bindings("--capability", &["tool:search=true".into()]).unwrap(),
            json!([{"type": "tool", "name": "search", "enabled": true}])
        );
        for bad in ["tool=true", ":x=true", "tool:=true"] {
            assert_eq!(
                message(capability_bindings("--capability", &[bad.into()])),
                "Invalid --capability: Expected type:name=enabled",
                "{bad}"
            );
        }
        assert_eq!(
            string_map("--header", &["x-a=1=2".into(), "x-b=".into()]).unwrap(),
            json!({"x-a": "1=2", "x-b": ""})
        );
        assert_eq!(
            message(string_map(
                "--header",
                &["a=FAKE-ONE".into(), "a=FAKE-TWO".into()]
            )),
            "Invalid --header: Duplicate key: a"
        );
        assert_eq!(
            message(string_map("--credential", &["__proto__=x".into()])),
            "Invalid --credential: Unsafe key: __proto__"
        );
        assert_eq!(
            message(string_map("--credential", &["novalue".into()])),
            "Invalid --credential: Expected key=value"
        );
    }

    /// TS "supports forced strings and rejects malformed or unsafe paths": `--set` values
    /// are JSON or literal strings, `--set-string` keeps the text; no value is echoed.
    #[test]
    fn assignments_and_paths() {
        let parsed =
            assignments(&["a.b=3".into(), "c=not json".into()], &["d=123".into()]).unwrap();
        assert_eq!(
            parsed,
            [
                ("a.b".to_owned(), json!(3)),
                ("c".to_owned(), json!("not json")),
                ("d".to_owned(), json!("123")),
            ]
        );
        assert_eq!(
            message(assignments(&["FAKE-SECRET-NOEQUALS".into()], &[])),
            "Invalid --set: Expected path=value"
        );
        assert_eq!(
            message(assignments(&[], &["=x".into()])),
            "Invalid --set-string: Expected path=value"
        );
        let prefix = "Invalid AI Gateway request: AISEC_USER_REQUEST_PAYLOAD_ERROR:";
        for (path, reason) in [
            ("a..b", "Invalid empty segment in dotted path: a..b"),
            ("a.__proto__.b", "Unsafe dotted path segment: __proto__"),
            ("constructor", "Unsafe dotted path segment: constructor"),
            ("a.", "Dotted path must not end with a dot: a."),
            (
                "[0]",
                "Dotted paths must start with an object property: [0]",
            ),
            ("a[01]", "Invalid array index in dotted path: a[01]"),
            ("a[0", "Unclosed array index in dotted path: a[0"),
            ("a]", "Unexpected ] in dotted path: a]"),
            ("a[0]b", "Missing dot after array index in path: a[0]b"),
            ("a\\x", "Invalid escape in dotted path: a\\x"),
            (".a", "Invalid empty segment in dotted path: .a"),
        ] {
            assert_eq!(
                message(build(&input(Vec::new(), &[(path, json!(1))]))),
                format!("{prefix}{reason}"),
                "{path}"
            );
        }
        assert_eq!(
            message(build(&input(Vec::new(), &[("", json!(1))]))),
            format!("{prefix}Dotted path must not be empty")
        );
        // Escapes keep dots and brackets in a property name.
        assert_eq!(
            build(&input(Vec::new(), &[("a\\.b.c\\[0\\]", json!(1))])).unwrap(),
            json!({"a.b": {"c[0]": 1}})
        );
    }

    /// TS "builds and validates a request from named and repeatable dotted flags" and
    /// "merges an optional file with command flags taking precedence".
    #[test]
    fn precedence_duplicates_and_shapes() {
        let body = build(&input(
            vec![("name", json!("from-flags")), ("workspace_id", json!("w"))],
            &[
                ("config.retry.attempts", json!(3)),
                ("config.strategy.mode", json!("fallback")),
                ("checks[0].id", json!("prompt-injection")),
            ],
        ))
        .unwrap();
        assert_eq!(
            body,
            json!({
                "name": "from-flags",
                "workspace_id": "w",
                "config": {"retry": {"attempts": 3}, "strategy": {"mode": "fallback"}},
                "checks": [{"id": "prompt-injection"}],
            })
        );
        // An assignment overwrites a named flag (replace), not another assignment.
        assert_eq!(
            build(&input(
                vec![("name", json!("flag"))],
                &[("name", json!("set"))]
            ))
            .unwrap(),
            json!({"name": "set"})
        );
        let prefix = "Invalid AI Gateway request: AISEC_USER_REQUEST_PAYLOAD_ERROR:";
        for (sets, reason) in [
            (
                &[("config.a", json!(1)), ("config.a", json!(2))][..],
                "Duplicate dotted path",
            ),
            (
                &[("a", json!(1)), ("a.b", json!(2))],
                "Dotted path shape conflict",
            ),
            (
                &[("a[0]", json!(1)), ("a.b", json!(2))],
                "Dotted path shape conflict",
            ),
            (
                &[("a.b", json!(1)), ("a[0]", json!(2))],
                "Dotted path shape conflict",
            ),
            (&[("a[1]", json!(1))], "Sparse arrays are not supported"),
            (
                &[("a", json!({"__proto__": 1}))],
                "Dotted value must be finite JSON",
            ),
        ] {
            assert_eq!(
                message(build(&input(Vec::new(), sets))),
                format!("{prefix}{reason}")
            );
        }
        // A file value is replaced by a flag and an assignment.
        let dir = crate::test_support::TempDir::new("body-test");
        let path = dir.join("request.json");
        std::fs::write(
            &path,
            r#"{"name":"file","config":{"retry":{"attempts":1},"keep":true}}"#,
        )
        .unwrap();
        let mut from_file = input(
            vec![("name", json!("override"))],
            &[("config.retry.attempts", json!(5))],
        );
        from_file.file = Some(path.into_os_string());
        assert_eq!(
            build(&from_file).unwrap(),
            json!({"name": "override", "config": {"retry": {"attempts": 5}, "keep": true}})
        );
    }

    /// D246: one JSON object only; YAML and other values refused without echoing them.
    #[test]
    fn files_are_one_json_object() {
        let dir = crate::test_support::TempDir::new("body-test");
        for (name, bytes) in [
            ("a.yaml", &b"name: x\nsecret: FAKE-YAML-SECRET\n"[..]),
            ("b.json", b"[1]"),
            ("c.json", b"{"),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(message(read_file(path.as_os_str())), FILE_NOT_OBJECT);
        }
        let path = dir.join("d.json");
        std::fs::write(&path, br#"{"a":{"constructor":1}}"#).unwrap();
        assert_eq!(
            message(read_file(path.as_os_str())),
            "Invalid AI Gateway request: <root>: Expected a finite, prototype-safe JSON object"
        );
        assert!(require_fields(&json!({})).is_err());
        assert!(require_fields(&json!({"a": 1})).is_ok());
        let path = dir.join("e.json");
        std::fs::write(&path, br#"{"n":1e400}"#).unwrap();
        assert_eq!(
            message(read_file(path.as_os_str())),
            "Invalid AI Gateway request: <root>: Expected a finite, prototype-safe JSON object",
            "JS reads Infinity"
        );
        let path = dir.join("f.json");
        std::fs::write(&path, br#"{"n":1e2,"m":[1.0,-0,2.5]}"#).unwrap();
        assert_eq!(
            serde_json::to_string(&read_file(path.as_os_str()).unwrap()).unwrap(),
            r#"{"m":[1,0,2.5],"n":100}"#
        );
    }

    /// Numbers as JS `JSON.parse` then `JSON.stringify` see them: an overflow is TS's
    /// finite-JSON refusal (never the literal string), an integral double an integer.
    #[test]
    fn numbers_take_the_javascript_form() {
        let wire = |text: &str| serde_json::to_string(&js_json(text).unwrap()).unwrap();
        for (text, expected) in [
            ("1e2", "100"),
            ("1.0", "1"),
            ("-0", "0"),
            ("-0.0", "0"),
            ("2.5", "2.5"),
            ("9007199254740991", "9007199254740991"),
            (r#"{"value":5.0,"s":"1e400"}"#, r#"{"s":"1e400","value":5}"#),
        ] {
            assert_eq!(wire(text), expected, "{text}");
        }
        for text in ["1e400", "-1e400", r#"{"a":[1e999]}"#] {
            assert_eq!(js_json(text), Err(JsJsonError::NonFinite), "{text}");
        }
        for text in ["not json", r#""1e400"#, "{"] {
            assert_eq!(js_json(text), Err(JsJsonError::Invalid), "{text}");
        }
        let finite = "Invalid AI Gateway request: AISEC_USER_REQUEST_PAYLOAD_ERROR:Dotted value must be finite JSON";
        assert_eq!(
            message(assignments(&["n=1e400".into()], &[]).map(|_| ())),
            finite
        );
        assert_eq!(message(json("--rate-limit", "1e400").map(|_| ())), finite);
        assert_eq!(
            assignments(&["n=1e2".into(), "s=word".into()], &["t=1e2".into()]).unwrap(),
            vec![
                ("n".to_owned(), json!(100)),
                ("s".to_owned(), json!("word")),
                ("t".to_owned(), json!("1e2"))
            ]
        );
    }
}
