//! The `tenant import` conversion and plan (DESIGN §3.12): a TypeScript config becomes
//! a TOML tenant file, and each selected entry gets an action and report notes.
//!
//! Everything here is pure: the command (`commands::tenant_import`) reads the
//! TypeScript files with [`super::ts`] and writes the store in one transaction. Notes
//! hold key names, fixed texts, dead format names and the registry's `configPath`
//! only, never a setting's value.

use super::config::{ConfigValue, DROPPED_KEYS, RENAMES, TenantConfig, schema_key};
use super::ts::{self, DEAD_FORMATS, TsValue};
use crate::error::CliError;
use crate::json::OValue;
use crate::store::{Index, MAX_TENANTS};

/// What import does with one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Import,
    Replace,
    Skip,
}

impl Action {
    /// The report word (the same with and without `--dry-run`).
    pub fn word(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Replace => "replace",
            Self::Skip => "skip",
        }
    }

    /// Whether the entry is written.
    pub fn writes(self) -> bool {
        matches!(self, Self::Import | Self::Replace)
    }
}

/// One entry read from the TypeScript side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    /// The airs tenant name (the registry name, or `--name`).
    pub name: String,
    /// The TSG to pin: the registry's `tsgId`, or the `--from-config` file's `mgmtTsgId`.
    pub tsg_id: String,
    pub content: Content,
}

/// A source entry's config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// Converted, with the conversion notes in file order.
    Converted {
        config: TenantConfig,
        notes: Vec<String>,
    },
    /// Skip reasons 1 and 2 of §3.12 (unreadable config, pin mismatch): the note.
    Failed(String),
}

/// One report row (§3.12 "Report"), with the converted config for the writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub tsg_id: String,
    pub action: Action,
    pub notes: Vec<String>,
    /// Skipped because the config could not be read or failed the pin: the run exits 1.
    pub failed: bool,
    /// The tenant file content, for `import` and `replace` rows.
    pub config: Option<TenantConfig>,
}

/// The note of skip reason 1.
pub fn unreadable_note(config_path: &str) -> String {
    format!("cannot read a valid tenant config at {config_path}")
}

/// The note of skip reason 2.
pub const PIN_NOTE: &str = "config TSG differs from its registered identity";

/// The airs key of a TypeScript schema key that is kept or renamed; `None` for
/// the dropped keys.
fn rust_key(ts_key: &str) -> Option<(&'static str, bool)> {
    if let Some((_, new)) = RENAMES.iter().find(|(old, _)| *old == ts_key) {
        return Some((new, true));
    }
    schema_key(ts_key).map(|key| (key, false))
}

/// Convert a TypeScript config object (already read with [`ts::read_document`]) with
/// the §3.12 table. `None` when the TypeScript schema rejects it (with import's
/// dead-format exception, §3.13).
pub fn convert(entries: &[(String, OValue)]) -> Option<(TenantConfig, Vec<String>)> {
    let validated = ts::validate(entries).ok()?;
    let mut values = Vec::new();
    let mut notes = Vec::new();
    // The object keeps file order (duplicate keys resolve like JSON.parse), so notes
    // follow the file.
    for (name, raw) in entries {
        let Some(value) = validated
            .present
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
        else {
            notes.push(format!("ignored unknown key {name}"));
            continue;
        };
        if DROPPED_KEYS.contains(&name.as_str()) {
            notes.push(format!("dropped {name} (no longer used)"));
            continue;
        }
        if name == "defaultOutput"
            && let TsValue::Text(format) = value
            && DEAD_FORMATS.contains(&format.as_str())
        {
            notes.push(format!(
                "dropped defaultOutput {format} (format no longer supported)"
            ));
            continue;
        }
        // TypeScript treats "" as unset (the numeric keys included: `""` coerces, then
        // is stripped).
        if raw.as_str() == Some("") {
            notes.push(format!("dropped empty {name}"));
            continue;
        }
        let (key, renamed) = rust_key(name)?;
        if renamed {
            notes.push(format!("renamed {name} to {key}"));
        }
        values.push((
            key,
            match value {
                TsValue::Text(text) => ConfigValue::Text(text.clone()),
                TsValue::Integer(number) => ConfigValue::Integer(*number),
            },
        ));
    }
    let config = TenantConfig::from_values(values);
    // Every value passed the TypeScript schema, so the store's read rules accept the
    // result; checked anyway, so import can never write a file the store rejects.
    TenantConfig::parse(config.to_toml().as_bytes()).ok()?;
    Some((config, notes))
}

/// The action for each source, in byte order of names (§3.12 "Planning"), against the
/// store's `index`. A name that differs only in case from an existing tenant, or from
/// an earlier row that this import writes, is skipped (D85), with or without
/// `--replace`. Fails when the new tenants would exceed the store's limit.
pub fn plan(sources: &[Source], index: &Index, replace: bool) -> Result<Vec<Row>, CliError> {
    let mut ordered: Vec<&Source> = sources.iter().collect();
    ordered.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let mut rows: Vec<Row> = Vec::with_capacity(ordered.len());
    for source in ordered {
        let skip = |note: String, failed: bool| Row {
            name: source.name.clone(),
            tsg_id: source.tsg_id.clone(),
            action: Action::Skip,
            notes: vec![note],
            failed,
            config: None,
        };
        let (config, notes) = match &source.content {
            Content::Failed(note) => {
                rows.push(skip(note.clone(), true));
                continue;
            }
            Content::Converted { config, notes } => (config, notes),
        };
        let conflict = index.case_conflict(&source.name).or_else(|| {
            rows.iter()
                .filter(|row| row.action.writes())
                .map(|row| row.name.as_str())
                .find(|other| *other != source.name && other.eq_ignore_ascii_case(&source.name))
        });
        if let Some(other) = conflict {
            rows.push(skip(
                format!(
                    "conflicts with existing tenant {other}; names may not differ only in case"
                ),
                false,
            ));
            continue;
        }
        let action = match (index.tsg(&source.name).is_some(), replace) {
            (true, false) => {
                rows.push(skip(
                    "already exists; use --replace to overwrite".to_owned(),
                    false,
                ));
                continue;
            }
            (true, true) => Action::Replace,
            (false, _) => Action::Import,
        };
        rows.push(Row {
            name: source.name.clone(),
            tsg_id: source.tsg_id.clone(),
            action,
            notes: notes.clone(),
            failed: false,
            config: Some(config.clone()),
        });
    }
    let new: Vec<&Row> = rows
        .iter()
        .filter(|row| row.action == Action::Import)
        .collect();
    if let Some(first) = new.first()
        && index.tenants.len() + new.len() > MAX_TENANTS
    {
        return Err(CliError::operational(format!(
            "Cannot create tenant {}: at most 1000 tenants can be registered",
            first.name
        )));
    }
    Ok(rows)
}

/// The tenant to select: the TypeScript registry's `active`, when the store had no
/// selection and that row is written (§3.12 "Writing").
pub fn selection(index: &Index, ts_active: Option<&str>, rows: &[Row]) -> Option<String> {
    if index.active.is_some() {
        return None;
    }
    let active = ts_active?;
    rows.iter()
        .find(|row| row.name == active && row.action.writes())
        .map(|row| row.name.clone())
}

/// `index` with the written rows registered (new entries, replaced pins) and `select`
/// made active.
pub fn apply(index: &Index, rows: &[Row], select: Option<&str>) -> Index {
    let mut next = index.clone();
    for row in rows.iter().filter(|row| row.action.writes()) {
        next.tenants.insert(row.name.clone(), row.tsg_id.clone());
    }
    if let Some(name) = select {
        next.active = Some(name.to_owned());
    }
    next.exists = true;
    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn doc(text: &str) -> Vec<(String, OValue)> {
        match json::parse(text).unwrap() {
            OValue::Object(entries) => entries,
            _ => panic!("object expected"),
        }
    }

    fn converted(text: &str) -> (String, Vec<String>) {
        let (config, notes) = convert(&doc(text)).unwrap();
        (config.to_toml(), notes)
    }

    #[test]
    fn conversion_table() {
        let (toml, notes) = converted(
            r#"{"mgmtTsgId":"100","aiGwDataEndpoint":"http://127.0.0.1:1/gw",
                "agentGuardMgmtEndpoint":"http://127.0.0.1:1/ag","dataDir":"/d",
                "typesafeApiKey":"SECRET-T","airsNumRetries":"0x2","scanConcurrency":[4],
                "defaultOutput":"markdown","airsApiKey":"","aiGwInferenceModel":"",
                "custom":"SECRET-C","redTeamTokenEndpoint":"x","airsApiToken":"tok"}"#,
        );
        assert_eq!(
            toml,
            "airsApiToken = \"tok\"\nairsNumRetries = 2\nmgmtTsgId = \"100\"\nsupplychainMgmtEndpoint = \"http://127.0.0.1:1/ag\"\ngatewayDataEndpoint = \"http://127.0.0.1:1/gw\"\nscanConcurrency = 4\n"
        );
        assert_eq!(
            notes,
            [
                "renamed aiGwDataEndpoint to gatewayDataEndpoint",
                "renamed agentGuardMgmtEndpoint to supplychainMgmtEndpoint",
                "dropped dataDir (no longer used)",
                "dropped typesafeApiKey (no longer used)",
                "dropped defaultOutput markdown (format no longer supported)",
                "dropped empty airsApiKey",
                "dropped empty aiGwInferenceModel",
                "ignored unknown key custom",
                "ignored unknown key redTeamTokenEndpoint",
            ]
        );
        assert!(notes.iter().all(|note| !note.contains("SECRET")));
        let (toml, notes) = converted(r#"{"airsNumRetries":"","defaultOutput":"json"}"#);
        assert_eq!(toml, "defaultOutput = \"json\"\n");
        assert_eq!(notes, ["dropped empty airsNumRetries"]);
        for invalid in [
            r#"{"scanConcurrency":""}"#,
            r#"{"defaultOutput":"xml"}"#,
            r#"{"airsApiKey":1}"#,
            r#"{"mgmtDashboardEndpoint":"not a url"}"#,
        ] {
            assert!(convert(&doc(invalid)).is_none(), "{invalid}");
        }
        assert_eq!(converted("{}"), (String::new(), Vec::new()));
    }

    fn source(name: &str, tsg: &str) -> Source {
        Source {
            name: name.to_owned(),
            tsg_id: tsg.to_owned(),
            content: Content::Converted {
                config: TenantConfig::from_values([(
                    "mgmtTsgId",
                    ConfigValue::Text(tsg.to_owned()),
                )]),
                notes: Vec::new(),
            },
        }
    }

    fn index(names: &[&str], active: Option<&str>) -> Index {
        Index {
            exists: true,
            active: active.map(str::to_owned),
            tenants: names
                .iter()
                .map(|name| ((*name).to_owned(), "1".to_owned()))
                .collect(),
        }
    }

    fn actions(rows: &[Row]) -> Vec<(&str, &str)> {
        rows.iter()
            .map(|row| (row.name.as_str(), row.action.word()))
            .collect()
    }

    #[test]
    fn planning_rules() {
        let failed = Source {
            content: Content::Failed(PIN_NOTE.to_owned()),
            ..source("bad", "9")
        };
        let sources = [
            source("dev", "1"),
            source("Dev", "2"),
            source("new", "3"),
            source("Prod", "4"),
            failed,
        ];
        let store = index(&["dev", "prod"], None);
        let rows = plan(&sources, &store, false).unwrap();
        assert_eq!(
            actions(&rows),
            [
                ("Dev", "skip"),
                ("Prod", "skip"),
                ("bad", "skip"),
                ("dev", "skip"),
                ("new", "import"),
            ],
            "byte order"
        );
        assert_eq!(
            rows[0].notes,
            ["conflicts with existing tenant dev; names may not differ only in case"]
        );
        assert!(rows[2].failed && !rows[3].failed);
        assert_eq!(
            rows[3].notes,
            ["already exists; use --replace to overwrite"]
        );
        let rows = plan(&sources, &store, true).unwrap();
        assert_eq!(
            actions(&rows),
            [
                ("Dev", "skip"),
                ("Prod", "skip"),
                ("bad", "skip"),
                ("dev", "replace"),
                ("new", "import"),
            ],
            "case conflicts are skipped even with --replace"
        );
        // Two TypeScript names that differ only in case: the first in byte order wins.
        let rows = plan(
            &[source("dev", "1"), source("Dev", "2")],
            &Index::default(),
            false,
        )
        .unwrap();
        assert_eq!(actions(&rows), [("Dev", "import"), ("dev", "skip")]);
        assert_eq!(
            rows[1].notes,
            ["conflicts with existing tenant Dev; names may not differ only in case"]
        );
    }

    #[test]
    fn the_tenant_limit_covers_the_whole_plan() {
        let names: Vec<String> = (0..999).map(|n| format!("t{n:04}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let store = index(&refs, None);
        assert!(plan(&[source("a", "1")], &store, false).is_ok());
        assert_eq!(
            plan(&[source("b", "1"), source("a", "1")], &store, false)
                .unwrap_err()
                .message(),
            "Cannot create tenant a: at most 1000 tenants can be registered"
        );
        assert!(
            plan(&[source("t0001", "1")], &store, true).is_ok(),
            "a replace adds no tenant"
        );
    }

    #[test]
    fn selection_rule() {
        let rows = plan(
            &[source("dev", "1"), source("old", "2")],
            &index(&["old"], None),
            false,
        )
        .unwrap();
        assert_eq!(
            selection(&Index::default(), Some("dev"), &rows),
            Some("dev".into())
        );
        assert_eq!(
            selection(&Index::default(), Some("old"), &rows),
            None,
            "skipped"
        );
        assert_eq!(selection(&Index::default(), None, &rows), None);
        assert_eq!(
            selection(&index(&["old"], Some("old")), Some("dev"), &rows),
            None,
            "an existing selection is kept"
        );
        let next = apply(&index(&["old"], None), &rows, Some("dev"));
        assert_eq!(
            next.to_toml(),
            "version = 1\nactive = \"dev\"\n\n[tenants.dev]\ntsg_id = \"1\"\n\n[tenants.old]\ntsg_id = \"1\"\n"
        );
    }
}
