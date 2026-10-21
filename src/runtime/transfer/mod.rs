//! The runtime profile backup format (DESIGN §18.15, D215, D216): the writer, the strict
//! reader and the recognition of TypeScript backups (refused, choice 21).
//!
//! One JSON document, `format` `airs-cli-rs.runtime-profiles`, version 1: the store name
//! and `mgmtTsgId` of the source tenant, the selector, and each profile and referenced
//! topic as `{id, name, revision, record}`, `record` being the SDK response model
//! re-serialised without response defaults (lossless; no `examples: []` invented, G27).

pub mod plan;
pub mod policy;

use crate::json::OValue;
use std::collections::HashSet;

/// The `format` of the file.
pub const FORMAT: &str = "airs-cli-rs.runtime-profiles";
/// The file version this build writes and reads.
pub const VERSION: u64 = 1;
/// The size limit of a backup (TS), written and read.
pub const MAX_BACKUP_BYTES: usize = 20 * 1_048_576;
/// The most profiles or topics a backup holds (TS).
pub const MAX_RECORDS: usize = 10_000;

/// Which list an entry belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Profile,
    Topic,
}

impl Kind {
    /// The envelope key.
    pub fn key(self) -> &'static str {
        match self {
            Self::Profile => "profiles",
            Self::Topic => "topics",
        }
    }

    /// The SDK schema's words in the reader's messages.
    pub fn schema(self) -> &'static str {
        match self {
            Self::Profile => "security profile",
            Self::Topic => "custom topic",
        }
    }

    fn id_key(self) -> &'static str {
        match self {
            Self::Profile => "profile_id",
            Self::Topic => "topic_id",
        }
    }

    fn name_key(self) -> &'static str {
        match self {
            Self::Profile => "profile_name",
            Self::Topic => "topic_name",
        }
    }
}

/// One stored record.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub record: OValue,
}

impl Entry {
    /// The entry object: `id`, `name`, `revision` of the record (`null` when absent) and
    /// the record.
    fn document(&self, kind: Kind) -> OValue {
        let member = |key: &str| match self.record.get(key) {
            Some(value @ (OValue::String(_) | OValue::Number(_))) => value.clone(),
            _ => OValue::Null,
        };
        OValue::Object(vec![
            ("id".into(), member(kind.id_key())),
            ("name".into(), member(kind.name_key())),
            ("revision".into(), member("revision")),
            ("record".into(), self.record.clone()),
        ])
    }
}

/// A backup file.
#[derive(Clone, Debug, PartialEq)]
pub struct Backup {
    pub exported_at: String,
    pub tenant: String,
    pub tsg_id: String,
    pub selector: Option<String>,
    pub profiles: Vec<Entry>,
    pub topics: Vec<Entry>,
}

fn text(value: &str) -> OValue {
    OValue::String(value.to_owned())
}

impl Backup {
    /// The document, keys in the §18.15 order.
    pub fn document(&self) -> OValue {
        let entries = |kind: Kind, entries: &[Entry]| {
            OValue::Array(entries.iter().map(|entry| entry.document(kind)).collect())
        };
        OValue::Object(vec![
            ("format".into(), text(FORMAT)),
            ("version".into(), OValue::Number(VERSION.into())),
            ("exportedAt".into(), text(&self.exported_at)),
            ("tenant".into(), text(&self.tenant)),
            ("tsgId".into(), text(&self.tsg_id)),
            (
                "selector".into(),
                self.selector.as_deref().map_or(OValue::Null, text),
            ),
            ("profiles".into(), entries(Kind::Profile, &self.profiles)),
            ("topics".into(), entries(Kind::Topic, &self.topics)),
        ])
    }

    /// The file bytes: the 2-space JSON document and one newline.
    pub fn to_text(&self) -> String {
        let mut text = crate::json::to_pretty(&self.document()).unwrap_or_default();
        text.push('\n');
        text
    }
}

/// Why a file is not a restorable airs runtime profiles backup (fixed texts).
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
const ENVELOPE: [&str; 8] = [
    "format",
    "version",
    "exportedAt",
    "tenant",
    "tsgId",
    "selector",
    "profiles",
    "topics",
];

/// A TSG id: 1–32 ASCII digits.
pub fn is_tsg(text: &str) -> bool {
    (1..=32).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit())
}

/// Parses a backup file strictly; `valid(kind, record)` checks a stored record with the
/// SDK response schema of its kind (`Mode::ResponseWithoutDefaults`).
pub fn parse(text: &str, valid: impl Fn(Kind, &OValue) -> bool) -> Result<Backup, ReadFailure> {
    let document = crate::json::parse(text).map_err(|_| {
        if crate::files::typescript_yaml(text) {
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
        return Err(invalid("it is not an airs runtime profiles backup"));
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
        .any(|(key, _)| !ENVELOPE.contains(&key.as_str()))
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
    if !is_tsg(&tsg_id) {
        return Err(invalid("tsgId must be a TSG ID (1-32 digits)"));
    }
    let selector = match document.get("selector") {
        Some(OValue::String(selector)) => Some(selector.clone()),
        Some(OValue::Null) => None,
        _ => return Err(invalid("selector must be a string or null")),
    };
    let profiles = entries(&document, Kind::Profile, &valid)?;
    let topics = entries(&document, Kind::Topic, &valid)?;
    let mut names: HashSet<&str> = HashSet::with_capacity(profiles.len());
    for (index, entry) in profiles.iter().enumerate() {
        let name = entry
            .record
            .get("profile_name")
            .and_then(OValue::as_str)
            .unwrap_or_default();
        if !names.insert(name) {
            return Err(ReadFailure::Invalid(format!(
                "profiles holds more than one entry named {}",
                crate::output::terminal_safe(name)
            )));
        }
        if matches!(entry.record.get("policy"), None | Some(OValue::Null)) {
            return Err(ReadFailure::Invalid(format!(
                "profiles[{index}] has no policy"
            )));
        }
    }
    let mut keys: HashSet<String> = HashSet::with_capacity(topics.len());
    for entry in &topics {
        let key = plan::record_key(&crate::json::value_of(&entry.record));
        if !keys.insert(key) {
            return Err(invalid(
                "topics holds more than one entry for one topic revision",
            ));
        }
    }
    Ok(Backup {
        exported_at,
        tenant,
        tsg_id,
        selector,
        profiles,
        topics,
    })
}

/// The entries of one list.
fn entries(
    document: &OValue,
    kind: Kind,
    valid: &impl Fn(Kind, &OValue) -> bool,
) -> Result<Vec<Entry>, ReadFailure> {
    let key = kind.key();
    let range = match kind {
        Kind::Profile => "profiles must hold 1 to 10000 entries",
        Kind::Topic => "topics must hold at most 10000 entries",
    };
    let Some(OValue::Array(items)) = document.get(key) else {
        return Err(ReadFailure::Invalid(range.to_owned()));
    };
    if items.len() > MAX_RECORDS || (kind == Kind::Profile && items.is_empty()) {
        return Err(ReadFailure::Invalid(range.to_owned()));
    }
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let keys_ok = item.as_object().is_some_and(|fields| {
            fields.len() == 4
                && ["id", "name", "revision", "record"]
                    .iter()
                    .all(|key| item.get(key).is_some())
        });
        if !keys_ok {
            return Err(ReadFailure::Invalid(format!(
                "{key}[{index}] must have exactly the keys id, name, revision, record"
            )));
        }
        let record = item.get("record").cloned().unwrap_or(OValue::Null);
        if record.as_object().is_none() || !valid(kind, &record) {
            return Err(ReadFailure::Invalid(format!(
                "{key}[{index}] does not match the {} response schema",
                kind.schema()
            )));
        }
        let entry = Entry { record };
        let expected = entry.document(kind);
        if ["id", "name", "revision"]
            .iter()
            .any(|field| expected.get(field) != item.get(field))
        {
            return Err(ReadFailure::Invalid(format!(
                "{key}[{index}] id, name and revision must be its record's"
            )));
        }
        out.push(entry);
    }
    Ok(out)
}

/// `yyyy-mm-ddThh-mm-ss-mmmZ` of an ISO timestamp (TS `toISOString().replace(/[:.]/g,
/// '-')`, the default file name).
pub fn stamp(iso: &str) -> String {
    iso.replace([':', '.'], "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any(_: Kind, _: &OValue) -> bool {
        true
    }

    fn sample() -> Backup {
        let record = crate::json::parse(
            r#"{"profile_id":"p1","profile_name":"Production","revision":2,"policy":{"x":1}}"#,
        )
        .unwrap();
        let topic = crate::json::parse(
            r#"{"topic_id":"t1","topic_name":"T","revision":3,"description":"d"}"#,
        )
        .unwrap();
        Backup {
            exported_at: "2026-10-18T12:00:00.000Z".into(),
            tenant: "prod".into(),
            tsg_id: "100".into(),
            selector: Some("Production".into()),
            profiles: vec![Entry { record }],
            topics: vec![Entry { record: topic }],
        }
    }

    #[test]
    fn the_document_round_trips() {
        let backup = sample();
        let text = backup.to_text();
        assert!(text.ends_with("}\n"));
        assert!(
            text.starts_with(
                "{\n  \"format\": \"airs-cli-rs.runtime-profiles\",\n  \"version\": 1,"
            )
        );
        assert_eq!(parse(&text, any).unwrap(), backup);
        assert!(!text.contains("examples"), "no default is invented");
    }

    #[test]
    fn the_reader_is_strict() {
        let text = sample().to_text();
        let edit = |from: &str, to: &str| parse(&text.replacen(from, to, 1), any);
        let reason = |result: Result<Backup, ReadFailure>| match result {
            Err(ReadFailure::Invalid(reason)) => reason,
            other => panic!("{other:?}"),
        };
        assert_eq!(parse("not json", any), Err(ReadFailure::Malformed));
        assert_eq!(parse("version: 1\n", any), Err(ReadFailure::TypeScript));
        assert_eq!(
            parse(
                r#"{"version":1,"resourceType":"runtime-security-profiles"}"#,
                any
            ),
            Err(ReadFailure::TypeScript)
        );
        assert_eq!(
            edit("\"version\": 1", "\"version\": 2"),
            Err(ReadFailure::Newer)
        );
        assert_eq!(
            reason(edit("\"version\": 1", "\"version\": 0")),
            "version must be 1"
        );
        assert_eq!(
            reason(edit("runtime-profiles", "dlp-resources")),
            "it is not an airs runtime profiles backup"
        );
        assert_eq!(
            reason(edit("\"tsgId\": \"100\"", "\"tsgId\": \"x1\"")),
            "tsgId must be a TSG ID (1-32 digits)"
        );
        assert_eq!(
            reason(edit("\"selector\": \"Production\"", "\"selector\": 1")),
            "selector must be a string or null"
        );
        assert_eq!(
            reason(edit(
                "\"tenant\": \"prod\"",
                "\"tenant\": \"prod\", \"extra\": 1"
            )),
            "the envelope has an unknown key"
        );
        assert_eq!(
            reason(edit("\"tenant\": \"prod\"", "\"tenant\": null")),
            "tenant must be a string"
        );
        assert_eq!(
            reason(edit("\"revision\": 2,\n", "\"revision\": 3,\n")),
            "profiles[0] id, name and revision must be its record's"
        );
        assert_eq!(
            reason(parse(&text, |kind, _| kind == Kind::Topic)),
            "profiles[0] does not match the security profile response schema"
        );
        let mut doubled = sample();
        doubled.profiles.push(doubled.profiles[0].clone());
        assert_eq!(
            reason(parse(&doubled.to_text(), any)),
            "profiles holds more than one entry named Production"
        );
        let mut topics = sample();
        topics.topics.push(topics.topics[0].clone());
        assert_eq!(
            reason(parse(&topics.to_text(), any)),
            "topics holds more than one entry for one topic revision"
        );
        let mut empty = sample();
        empty.profiles.clear();
        assert_eq!(
            reason(parse(&empty.to_text(), any)),
            "profiles must hold 1 to 10000 entries"
        );
    }

    #[test]
    fn default_names_replace_colons_and_dots() {
        assert_eq!(
            stamp("2026-10-19T00:25:46.303Z"),
            "2026-10-19T00-25-46-303Z"
        );
        assert!(is_tsg("100") && !is_tsg("") && !is_tsg(&"1".repeat(33)) && !is_tsg("1a"));
    }
}
