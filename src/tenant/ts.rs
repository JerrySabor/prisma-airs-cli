//! The TypeScript CLI's registry and JSON tenant configs, read-only (DESIGN §3.13).
//!
//! From 0.3 no command reads these files for normal operation. `tenant import` reads
//! them (§3.12), and the import suffix (§3.4) and doctor's import hint (§9) only check
//! whether the registry path exists ([`registry_exists`]). Nothing here writes,
//! creates, locks, chmods or renames a file, and `*.lock` files are never opened.

use super::Environment;
use crate::error::CliError;
use crate::json::{self, OValue};
use crate::store::{MAX_FILE_BYTES, MAX_TENANTS, normalize, valid_tenant_name};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The 31 TypeScript schema keys, in TypeScript schema order.
pub const TS_KEYS: [&str; 31] = [
    "airsApiKey",
    "airsApiToken",
    "airsApiEndpoint",
    "airsNumRetries",
    "mgmtClientId",
    "mgmtClientSecret",
    "mgmtTsgId",
    "mgmtEndpoint",
    "mgmtDashboardEndpoint",
    "mgmtTokenEndpoint",
    "dlpEndpoint",
    "redTeamDataEndpoint",
    "redTeamMgmtEndpoint",
    "redTeamNetworkBrokerEndpoint",
    "modelSecDataEndpoint",
    "modelSecMgmtEndpoint",
    "agentGuardDataEndpoint",
    "agentGuardMgmtEndpoint",
    "aiGwDataEndpoint",
    "aiGwAdminEndpoint",
    "iamEndpoint",
    "aiGwInferenceEndpoint",
    "aiGwInferenceApiKey",
    "aiGwInferenceModel",
    "aiGwEmbeddingModel",
    "typesafeApiKey",
    "typesafeBaseUrl",
    "typesafeModel",
    "scanConcurrency",
    "defaultOutput",
    "dataDir",
];

/// The output formats TypeScript accepted that airs dropped (D50, D51).
pub const DEAD_FORMATS: [&str; 3] = ["markdown", "csv", "yaml"];

/// Resolve the registry path exactly like the TypeScript `tenantStorePath()`.
pub fn registry_path(env: &Environment) -> Result<PathBuf, CliError> {
    let home = || {
        env.home
            .as_deref()
            .ok_or_else(|| CliError::operational("Cannot determine the home directory"))
    };
    if let Some(value) = &env.tenants_path {
        let path = Path::new(value);
        let expanded = match path.strip_prefix("~") {
            Ok(rest) => home()?.join(rest),
            Err(_) => path.to_path_buf(),
        };
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            env.cwd
                .as_deref()
                .ok_or_else(|| CliError::operational("Cannot determine the current directory"))?
                .join(expanded)
        };
        return Ok(normalize(&absolute));
    }
    if let Some(state) = &env.xdg_state_home {
        if !Path::new(state).is_absolute() {
            return Err(CliError::operational(
                "XDG_STATE_HOME must be an absolute path",
            ));
        }
        return Ok(normalize(
            &Path::new(state).join("prisma-airs").join("tenants.json"),
        ));
    }
    Ok(normalize(
        &home()?.join(".local/state/prisma-airs/tenants.json"),
    ))
}

/// The registry path when it resolves and exists (`symlink_metadata` succeeds; the
/// file is never opened). A resolution error counts as absent (§3.4).
pub fn registry_exists(env: &Environment) -> Option<PathBuf> {
    let path = registry_path(env).ok()?;
    let absolute = if path.is_absolute() {
        path
    } else {
        normalize(&env.cwd.as_deref()?.join(path))
    };
    std::fs::symlink_metadata(&absolute).ok().map(|_| absolute)
}

/// One registry entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantEntry {
    pub name: String,
    pub config_path: String,
    pub tsg_id: String,
}

/// The validated registry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    pub active: Option<String>,
    pub tenants: Vec<TenantEntry>,
}

impl Registry {
    pub fn find(&self, name: &str) -> Option<&TenantEntry> {
        self.tenants.iter().find(|entry| entry.name == name)
    }
    #[cfg(test)]
    pub fn names(&self) -> Vec<&str> {
        self.tenants
            .iter()
            .map(|entry| entry.name.as_str())
            .collect()
    }
}

/// Why a TypeScript file could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedReadError {
    NotFound,
    Unreadable,
}

/// Read a regular file (not following a final symlink) of at most 1 MiB.
pub fn read_bounded(path: &Path) -> Result<Vec<u8>, BoundedReadError> {
    let kind = |error: std::io::Error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BoundedReadError::NotFound
        } else {
            BoundedReadError::Unreadable
        }
    };
    let metadata = std::fs::symlink_metadata(path).map_err(kind)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(BoundedReadError::Unreadable);
    }
    let file = std::fs::File::open(path).map_err(kind)?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BoundedReadError::Unreadable)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(BoundedReadError::Unreadable);
    }
    Ok(bytes)
}

pub fn registry_error(path: &Path) -> CliError {
    CliError::operational(format!(
        "Cannot read tenant registry at {}; restore a valid registry before proceeding",
        crate::store::shown(path)
    ))
}

/// Read the registry. `Ok(None)`: no registry (`NotFound`); anything else that is not a
/// valid registry fails with one message that echoes nothing.
pub fn read_registry(path: &Path) -> Result<Option<Registry>, CliError> {
    let bytes = match read_bounded(path) {
        Ok(bytes) => bytes,
        Err(BoundedReadError::NotFound) => return Ok(None),
        Err(BoundedReadError::Unreadable) => return Err(registry_error(path)),
    };
    String::from_utf8(bytes)
        .ok()
        .and_then(|text| json::parse(&text).ok())
        .and_then(|value| parse_registry(&value))
        .map(Some)
        .ok_or_else(|| registry_error(path))
}

fn strict_object<'a>(value: &'a OValue, allowed: &[&str]) -> Option<&'a [(String, OValue)]> {
    let entries = value.as_object()?;
    entries
        .iter()
        .all(|(key, _)| allowed.contains(&key.as_str()))
        .then_some(entries)
}

/// Validate the strict registry schema.
pub fn parse_registry(value: &OValue) -> Option<Registry> {
    strict_object(value, &["version", "active", "tenants"])?;
    match value.get("version")? {
        OValue::Number(number) if number.as_f64() == Some(1.0) => {}
        _ => return None,
    }
    let active = match value.get("active")? {
        OValue::Null => None,
        OValue::String(name) => Some(name.clone()),
        _ => return None,
    };
    let items = value.get("tenants")?.as_array()?;
    if items.len() > MAX_TENANTS {
        return None;
    }
    let mut tenants = Vec::with_capacity(items.len());
    let mut seen = HashSet::new();
    for item in items {
        strict_object(item, &["name", "configPath", "tsgId"])?;
        let name = item.get("name")?.as_str()?;
        let config_path = item.get("configPath")?.as_str()?;
        let tsg_id = item.get("tsgId")?.as_str()?;
        if !valid_tenant_name(name)
            || !config_path.starts_with('/')
            || tsg_id.is_empty()
            || !seen.insert(name)
        {
            return None;
        }
        tenants.push(TenantEntry {
            name: name.to_owned(),
            config_path: config_path.to_owned(),
            tsg_id: tsg_id.to_owned(),
        });
    }
    let registry = Registry { active, tenants };
    if let Some(name) = &registry.active
        && registry.find(name).is_none()
    {
        return None;
    }
    Some(registry)
}

// -- JSON configs ------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    Text,
    Url,
    Retries,
    Concurrency,
    Output,
}

fn rule(key: &str) -> Rule {
    match key {
        "airsNumRetries" => Rule::Retries,
        "scanConcurrency" => Rule::Concurrency,
        "defaultOutput" => Rule::Output,
        "mgmtDashboardEndpoint"
        | "agentGuardDataEndpoint"
        | "agentGuardMgmtEndpoint"
        | "typesafeBaseUrl" => Rule::Url,
        _ => Rule::Text,
    }
}

/// JavaScript `Number(value)` for a JSON value; `None` is `NaN`.
pub fn js_number(value: &OValue) -> Option<f64> {
    match value {
        OValue::Null => Some(0.0),
        OValue::Bool(flag) => Some(if *flag { 1.0 } else { 0.0 }),
        OValue::Number(number) => number.as_f64(),
        OValue::String(text) => js_string_number(text),
        // `Number([x])` is `Number(String([x]))`; two or more elements join with ','.
        OValue::Array(items) => match items.as_slice() {
            [] => Some(0.0),
            [item] => match item {
                OValue::Null => Some(0.0),
                OValue::Bool(_) | OValue::Object(_) => None,
                other => js_number(other),
            },
            _ => None,
        },
        OValue::Object(_) => None,
    }
}

/// JavaScript `StringToNumber`: trimmed, empty is 0, decimal with optional sign and
/// exponent, `Infinity`, or unsigned `0x`/`0o`/`0b` integers.
pub fn js_string_number(text: &str) -> Option<f64> {
    let text = super::config::js_trim(text);
    if text.is_empty() {
        return Some(0.0);
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            return radix_number(digits, radix);
        }
    }
    let (sign, unsigned) = match text.as_bytes()[0] {
        b'+' => (1.0, &text[1..]),
        b'-' => (-1.0, &text[1..]),
        _ => (1.0, text),
    };
    if unsigned == "Infinity" {
        return Some(sign * f64::INFINITY);
    }
    if !is_decimal_literal(unsigned) {
        return None;
    }
    unsigned.parse::<f64>().ok().map(|value| sign * value)
}

fn radix_number(digits: &str, radix: u32) -> Option<f64> {
    if digits.is_empty() {
        return None;
    }
    let mut value = 0.0_f64;
    for c in digits.chars() {
        value = value * f64::from(radix) + f64::from(c.to_digit(radix)?);
    }
    Some(value)
}

/// `StrUnsignedDecimalLiteral` without `Infinity`: digits[.digits][e[+-]digits] or .digits[...].
fn is_decimal_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    let digits = |index: &mut usize| {
        let start = *index;
        while *index < bytes.len() && bytes[*index].is_ascii_digit() {
            *index += 1;
        }
        *index - start
    };
    let integer = digits(&mut index);
    let mut fraction = 0;
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        fraction = digits(&mut index);
    }
    if integer == 0 && fraction == 0 {
        return false;
    }
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        index += 1;
        if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            index += 1;
        }
        if digits(&mut index) == 0 {
            return false;
        }
    }
    index == bytes.len()
}

/// An integer in `min..=max` after `Number()` coercion (zod `coerce.number().int()`).
fn coerced_integer(value: &OValue, min: i64, max: i64) -> Option<i64> {
    let number = js_number(value)?;
    if !number.is_finite() || number.fract() != 0.0 {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    let in_range = number >= min as f64 && number <= max as f64;
    // In range of a small integer interval, so the conversion is exact.
    #[allow(clippy::cast_possible_truncation)]
    in_range.then_some(number as i64)
}

/// A value that passed the TypeScript schema: strings as written (`""` kept), the two
/// numeric keys coerced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TsValue {
    Text(String),
    Integer(i64),
}

/// The TypeScript rule for `key`. For import, a dead `defaultOutput` passes (§3.12).
fn validate_value(key: &str, value: &OValue) -> Option<TsValue> {
    let text = || value.as_str().map(str::to_owned);
    match rule(key) {
        Rule::Text => text().map(TsValue::Text),
        Rule::Url => text()
            .filter(|text| url::Url::parse(text).is_ok())
            .map(TsValue::Text),
        Rule::Output => text()
            .filter(|text| {
                crate::output::Format::parse(text).is_some()
                    || DEAD_FORMATS.contains(&text.as_str())
            })
            .map(TsValue::Text),
        Rule::Retries => coerced_integer(value, 0, 5).map(TsValue::Integer),
        Rule::Concurrency => coerced_integer(value, 1, 20).map(TsValue::Integer),
    }
}

/// Why a TypeScript config document could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigFileError {
    NotFound,
    Unreadable,
    InvalidJson,
    /// JSON that `JSON.parse` accepts but serde_json cannot represent (D44).
    Unrepresentable,
    NotObject,
}

/// Read a config document: the canonical target must be a regular file of at most
/// 1 MiB containing a UTF-8 JSON object.
pub fn read_document(path: impl AsRef<Path>) -> Result<Vec<(String, OValue)>, ConfigFileError> {
    let canonical = std::fs::canonicalize(path.as_ref()).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
            ConfigFileError::NotFound
        }
        _ => ConfigFileError::Unreadable,
    })?;
    let bytes = read_bounded(&canonical).map_err(|error| match error {
        BoundedReadError::NotFound => ConfigFileError::NotFound,
        BoundedReadError::Unreadable => ConfigFileError::Unreadable,
    })?;
    let text = String::from_utf8(bytes).map_err(|_| ConfigFileError::InvalidJson)?;
    let value = json::parse(&text).map_err(|error| {
        if json::unrepresentable(&error) {
            ConfigFileError::Unrepresentable
        } else {
            ConfigFileError::InvalidJson
        }
    })?;
    match value {
        OValue::Object(entries) => Ok(entries),
        _ => Err(ConfigFileError::NotObject),
    }
}

/// A TypeScript config that passed the schema.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TsConfig {
    /// Schema keys present, in file order, with validated values.
    pub present: Vec<(&'static str, TsValue)>,
    /// Keys outside the TypeScript schema, in file order.
    pub unknown: Vec<String>,
}

/// Validate every key against the TypeScript schema. On failure returns the invalid
/// key names in schema order.
pub fn validate(entries: &[(String, OValue)]) -> Result<TsConfig, Vec<&'static str>> {
    let mut invalid = Vec::new();
    let mut config = TsConfig::default();
    for (name, value) in entries {
        match TS_KEYS.iter().copied().find(|key| key == name) {
            Some(key) => match validate_value(key, value) {
                Some(validated) => config.present.push((key, validated)),
                None => invalid.push(key),
            },
            None => config.unknown.push(name.clone()),
        }
    }
    if invalid.is_empty() {
        Ok(config)
    } else {
        invalid.sort_by_key(|key| TS_KEYS.iter().position(|k| k == key));
        invalid.dedup();
        Err(invalid)
    }
}

/// The raw `mgmtTsgId` equals the registry pin exactly (missing never matches).
pub fn tsg_matches(entries: &[(String, OValue)], registered: &str) -> bool {
    entries
        .iter()
        .find(|(name, _)| name == "mgmtTsgId")
        .and_then(|(_, value)| value.as_str())
        == Some(registered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testdir::TestDir;

    fn env() -> Environment {
        Environment {
            home: Some(PathBuf::from("/home/u")),
            cwd: Some(PathBuf::from("/work/dir")),
            ..Environment::default()
        }
    }

    fn with_path(value: &str) -> PathBuf {
        let mut env = env();
        env.tenants_path = Some(value.into());
        registry_path(&env).unwrap()
    }

    #[test]
    fn registry_path_resolution() {
        assert_eq!(
            registry_path(&env()).unwrap(),
            PathBuf::from("/home/u/.local/state/prisma-airs/tenants.json")
        );
        assert_eq!(with_path("~"), PathBuf::from("/home/u"));
        assert_eq!(with_path("~/r.json"), PathBuf::from("/home/u/r.json"));
        assert_eq!(with_path("r.json"), PathBuf::from("/work/dir/r.json"));
        assert_eq!(
            with_path("~other/r.json"),
            PathBuf::from("/work/dir/~other/r.json")
        );
        assert_eq!(
            with_path("/a/./b//c/../r.json/"),
            PathBuf::from("/a/b/r.json")
        );
        let mut xdg = env();
        xdg.xdg_state_home = Some("/s/../t".into());
        assert_eq!(
            registry_path(&xdg).unwrap(),
            PathBuf::from("/t/prisma-airs/tenants.json")
        );
        xdg.xdg_state_home = Some("relative".into());
        assert_eq!(
            registry_path(&xdg),
            Err(CliError::operational(
                "XDG_STATE_HOME must be an absolute path"
            ))
        );
        xdg.tenants_path = Some("/r.json".into());
        assert_eq!(registry_path(&xdg).unwrap(), PathBuf::from("/r.json"));
        let mut empty = env();
        empty.home = Some(PathBuf::new());
        assert_eq!(
            registry_path(&empty).unwrap(),
            PathBuf::from(".local/state/prisma-airs/tenants.json"),
            "relative, like TS join('', '.local', …)"
        );
    }

    #[test]
    fn existence_check_never_opens_the_file() {
        let dir = TestDir::new("ts-exists");
        let mut env = env();
        let registry = dir.write("tenants.json", b"not json", 0o000);
        env.tenants_path = Some(registry.clone().into_os_string());
        assert_eq!(
            registry_exists(&env),
            Some(registry),
            "unreadable still exists"
        );
        env.tenants_path = Some(dir.path().join("missing.json").into_os_string());
        assert_eq!(registry_exists(&env), None);
        env.tenants_path = None;
        env.xdg_state_home = Some("relative".into());
        assert_eq!(registry_exists(&env), None, "a resolution error is absent");
        env.xdg_state_home = None;
        env.home = Some(PathBuf::new());
        env.cwd = Some(dir.path().to_path_buf());
        dir.write(".local/state/prisma-airs/tenants.json", b"{}", 0o600);
        assert_eq!(
            registry_exists(&env),
            Some(dir.path().join(".local/state/prisma-airs/tenants.json")),
            "an empty HOME resolves against the current directory"
        );
    }

    fn registry(text: &str) -> Option<Registry> {
        parse_registry(&json::parse(text).ok()?)
    }

    const ENTRY: &str = r#"{"name":"dev","configPath":"/r/dev.json","tsgId":"100"}"#;

    #[test]
    fn registry_schema() {
        let parsed = registry(&format!(
            r#"{{"version":1,"active":"dev","tenants":[{ENTRY}]}}"#
        ))
        .unwrap();
        assert_eq!(parsed.active.as_deref(), Some("dev"));
        assert_eq!(parsed.names(), ["dev"]);
        assert!(registry(r#"{"version":1.0,"active":null,"tenants":[]}"#).is_some());
        assert!(registry(r#"{"version":2,"version":1,"active":null,"tenants":[]}"#).is_some());
        for text in [
            "null".to_owned(),
            r#"{"version":2,"active":null,"tenants":[]}"#.to_owned(),
            r#"{"version":1,"tenants":[]}"#.to_owned(),
            r#"{"version":1,"active":"ghost","tenants":[]}"#.to_owned(),
            r#"{"version":1,"active":null,"tenants":[],"extra":1}"#.to_owned(),
            format!(r#"{{"version":1,"active":null,"tenants":[{ENTRY},{ENTRY}]}}"#),
            r#"{"version":1,"active":null,"tenants":[{"name":"dev","configPath":"r","tsgId":"1"}]}"#
                .to_owned(),
        ] {
            assert!(registry(&text).is_none(), "{text}");
        }
    }

    #[test]
    fn registry_files() {
        let dir = TestDir::new("ts-registry");
        assert_eq!(
            read_registry(&dir.path().join("nope/tenants.json")),
            Ok(None)
        );
        let corrupt = dir.write("corrupt.json", br#"{"SUPER-SECRET""#, 0o600);
        let message = read_registry(&corrupt).unwrap_err().message();
        assert!(message.starts_with("Cannot read tenant registry at"));
        assert!(!message.contains("SUPER-SECRET"));
        // Invalid UTF-8 is rejected (D27), unlike TypeScript's lossy decode.
        let lossy = dir.write(
            "lossy.json",
            b"{\"version\":1,\"active\":null,\"tenants\":[],\"x\":\"\xff\"}",
            0o600,
        );
        assert!(read_registry(&lossy).is_err());
        let surrogate = dir.write(
            "surrogate.json",
            br#"{"version":1,"active":null,"tenants":[{"name":"dev","configPath":"/c\ud800","tsgId":"1"}]}"#,
            0o600,
        );
        assert!(read_registry(&surrogate).is_err(), "D44");
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&corrupt, &link).unwrap();
        assert!(read_registry(&link).is_err(), "a symlink is rejected");
        assert!(
            read_registry(dir.path()).is_err(),
            "a directory is rejected"
        );
    }

    #[test]
    fn js_number_coercion_table() {
        let cases: &[(&str, Option<f64>)] = &[
            ("3", Some(3.0)),
            ("true", Some(1.0)),
            ("null", Some(0.0)),
            ("\"\"", Some(0.0)),
            ("\" 3 \"", Some(3.0)),
            ("\"0x5\"", Some(5.0)),
            ("\"0o7\"", Some(7.0)),
            ("\"0b101\"", Some(5.0)),
            ("\"1e1\"", Some(10.0)),
            ("\".5\"", Some(0.5)),
            ("\"-4\"", Some(-4.0)),
            ("\"Infinity\"", Some(f64::INFINITY)),
            ("\"abc\"", None),
            ("\"0x\"", None),
            ("\"-0x5\"", None),
            ("\"1_000\"", None),
            ("\"NaN\"", None),
            ("[]", Some(0.0)),
            ("[\"4\"]", Some(4.0)),
            ("[[2]]", Some(2.0)),
            ("[true]", None),
            ("[1,2]", None),
            ("{}", None),
        ];
        for (text, expected) in cases {
            let value = json::parse(text).unwrap();
            assert_eq!(js_number(&value), *expected, "Number({text})");
        }
    }

    fn doc(text: &str) -> Vec<(String, OValue)> {
        match json::parse(text).unwrap() {
            OValue::Object(entries) => entries,
            _ => panic!("object expected"),
        }
    }

    #[test]
    fn config_schema_with_coercion_and_dead_formats() {
        let cfg = validate(&doc(
            r#"{"scanConcurrency":"3","airsNumRetries":true,"aiGwDataEndpoint":"x",
                "defaultOutput":"markdown","custom":1,"airsApiKey":"","dataDir":"/d"}"#,
        ))
        .unwrap();
        assert_eq!(
            cfg.present,
            [
                ("scanConcurrency", TsValue::Integer(3)),
                ("airsNumRetries", TsValue::Integer(1)),
                ("aiGwDataEndpoint", TsValue::Text("x".into())),
                ("defaultOutput", TsValue::Text("markdown".into())),
                ("airsApiKey", TsValue::Text(String::new())),
                ("dataDir", TsValue::Text("/d".into())),
            ]
        );
        assert_eq!(cfg.unknown, ["custom"]);
        assert_eq!(
            validate(&doc(
                r#"{"defaultOutput":"xml","scanConcurrency":99,"airsApiKey":1}"#
            )),
            Err(vec!["airsApiKey", "scanConcurrency", "defaultOutput"])
        );
        assert!(tsg_matches(&doc(r#"{"mgmtTsgId":"100"}"#), "100"));
        assert!(!tsg_matches(&doc(r#"{"mgmtTsgId":" 100"}"#), "100"));
        assert!(!tsg_matches(&doc(r#"{}"#), "100"));
    }

    #[test]
    fn documents_are_read_strictly() {
        let dir = TestDir::new("ts-config");
        let file =
            |name: &str, bytes: &[u8]| dir.write(name, bytes, 0o600).to_string_lossy().into_owned();
        assert!(read_document(file("ok.json", br#"{"a":1}"#)).is_ok());
        assert_eq!(
            read_document(file("arr.json", b"[]")),
            Err(ConfigFileError::NotObject)
        );
        assert_eq!(
            read_document(file("bad.json", br#"{"mgmtClientSecret":"S",oops"#)),
            Err(ConfigFileError::InvalidJson)
        );
        assert_eq!(
            read_document(file("utf8.json", b"{\"a\":\"\xff\"}")),
            Err(ConfigFileError::InvalidJson)
        );
        assert_eq!(
            read_document(file("surrogate.json", br#"{"a":"\ud800"}"#)),
            Err(ConfigFileError::Unrepresentable)
        );
        assert_eq!(
            read_document(dir.path().join("missing.json")),
            Err(ConfigFileError::NotFound)
        );
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(dir.path().join("ok.json"), &link).unwrap();
        assert!(read_document(&link).is_ok(), "config symlinks are followed");
    }
}
