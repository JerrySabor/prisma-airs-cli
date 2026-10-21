//! `tenant import` (DESIGN §3.12): copy tenants from the TypeScript CLI's registry and
//! JSON configs, which are only read (never written, locked, renamed or chmod'ed), into
//! the TOML store, and report what was done.
//!
//! Order of work: the usage checks of [`plan`]; the TypeScript source (registry or
//! `--from-config` file); the store location and an unlocked read of `config.toml`;
//! the plan ([`import::plan`]); unless `--dry-run`, one locked [`Transaction`] that
//! re-plans against the re-read store and writes every tenant file, then `config.toml`
//! (the commit point); finally the report on stdout and the status lines on stderr.

use super::Invocation;
use super::tenant_write::{begin, finish};
use crate::cli::ImportArgs;
use crate::error::CliError;
use crate::output::{Format, terminal_safe};
use crate::render::{pretty, table};
use crate::store::atomic::{self, Transaction};
use crate::store::{Store, TenantFileRead, normalize, shown, valid_tenant_name};
use crate::tenant::import::{self, Content, Row, Source};
use crate::tenant::{NAME_RULE, ts};
use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Where the TypeScript tenants come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportSource {
    /// A registry: `--from <path>`, or `None` for the one the TypeScript CLI uses.
    Registry(Option<OsString>),
    /// `--from-config <path>`, imported as the tenant `--name`.
    Config(OsString),
}

/// A validated `tenant import`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportPlan {
    pub source: ImportSource,
    /// `--name`: the one registry entry to import, or the `--from-config` tenant's name.
    pub name: Option<String>,
    pub replace: bool,
    pub dry_run: bool,
    pub format: Format,
}

/// The usage checks of §3.12 "Validation", in order (exit 2).
pub fn plan(args: &ImportArgs, format: Format) -> Result<ImportPlan, CliError> {
    if args.from.is_some() && args.from_config.is_some() {
        return Err(CliError::usage(
            "--from and --from-config cannot be combined",
        ));
    }
    if args.from.as_ref().is_some_and(|from| from.is_empty()) {
        return Err(CliError::usage("--from needs a path"));
    }
    if args
        .from_config
        .as_ref()
        .is_some_and(|path| path.is_empty())
    {
        return Err(CliError::usage("--from-config needs a path"));
    }
    if args.from_config.is_some() && args.name.is_none() {
        return Err(CliError::usage("--from-config requires --name <name>"));
    }
    if let Some(name) = &args.name
        && !valid_tenant_name(name)
    {
        return Err(CliError::usage(NAME_RULE));
    }
    Ok(ImportPlan {
        source: match &args.from_config {
            Some(path) => ImportSource::Config(path.clone()),
            None => ImportSource::Registry(args.from.clone()),
        },
        name: args.name.clone(),
        replace: args.replace,
        dry_run: args.dry_run,
        format,
    })
}

/// `path` made absolute against the current directory and lexically normalised (no
/// `~` expansion).
fn absolute(invocation: &Invocation, path: &Path) -> Result<PathBuf, CliError> {
    if path.has_root() {
        return Ok(normalize(path));
    }
    let cwd = invocation
        .env
        .cwd
        .as_deref()
        .ok_or_else(|| CliError::operational("Cannot determine the current directory"))?;
    Ok(normalize(&cwd.join(path)))
}

/// The selected sources and the registry's `active`.
struct Sources {
    entries: Vec<Source>,
    ts_active: Option<String>,
}

/// One registry entry's config (§3.12 "Planning" reasons 1 and 2, then the conversion).
fn registry_source(entry: &ts::TenantEntry) -> Source {
    let content = match ts::read_document(&entry.config_path) {
        Err(_) => Content::Failed(import::unreadable_note(&entry.config_path)),
        Ok(document) => match import::convert(&document) {
            None => Content::Failed(import::unreadable_note(&entry.config_path)),
            Some(_) if !ts::tsg_matches(&document, &entry.tsg_id) => {
                Content::Failed(import::PIN_NOTE.to_owned())
            }
            Some((config, notes)) => Content::Converted { config, notes },
        },
    };
    Source {
        name: entry.name.clone(),
        tsg_id: entry.tsg_id.clone(),
        content,
    }
}

fn read_registry(
    invocation: &Invocation,
    from: Option<&OsString>,
    name: Option<&str>,
) -> Result<Sources, CliError> {
    let path = match from {
        Some(from) => absolute(invocation, Path::new(from))?,
        None => absolute(invocation, &ts::registry_path(&invocation.env)?)?,
    };
    let registry = ts::read_registry(&path)?.ok_or_else(|| {
        CliError::operational(format!(
            "No TypeScript tenant registry at {}; pass --from <registry> or --from-config <file> --name <name>",
            shown(&path)
        ))
    })?;
    let selected: Vec<&ts::TenantEntry> = match name {
        Some(name) => vec![
            registry
                .find(name)
                .ok_or_else(|| CliError::operational("Tenant not found"))?,
        ],
        None => registry.tenants.iter().collect(),
    };
    Ok(Sources {
        entries: selected.into_iter().map(registry_source).collect(),
        ts_active: registry.active.clone(),
    })
}

/// `--from-config`: direct errors in TypeScript's `create --config` order; only
/// `mgmtTsgId` is required (D82, D84).
fn read_config_file(
    invocation: &Invocation,
    path: &OsString,
    name: &str,
) -> Result<Sources, CliError> {
    let path = absolute(invocation, Path::new(path))?;
    let real = std::fs::canonicalize(&path).map_err(|_| {
        CliError::operational("Tenant config file does not exist or cannot be resolved")
    })?;
    let invalid = || {
        CliError::operational(format!(
            "Cannot read a valid tenant config at {}",
            shown(&real)
        ))
    };
    let document = ts::read_document(&real).map_err(|_| invalid())?;
    let (config, notes) = import::convert(&document).ok_or_else(invalid)?;
    let tsg = document
        .iter()
        .find(|(key, _)| key == "mgmtTsgId")
        .and_then(|(_, value)| value.as_str())
        .filter(|tsg| !crate::tenant::config::js_trim(tsg).is_empty())
        .ok_or_else(|| {
            CliError::operational(format!(
                "{} has no mgmtTsgId; it cannot be imported",
                shown(&real)
            ))
        })?;
    Ok(Sources {
        entries: vec![Source {
            name: name.to_owned(),
            tsg_id: tsg.to_owned(),
            content: Content::Converted { config, notes },
        }],
        ts_active: None,
    })
}

/// What the run did to the store.
struct Outcome {
    rows: Vec<Row>,
    selected: Option<String>,
}

pub fn run(invocation: &mut Invocation, plan: ImportPlan) -> Result<(), CliError> {
    let sources = match &plan.source {
        ImportSource::Registry(from) => {
            read_registry(invocation, from.as_ref(), plan.name.as_deref())?
        }
        // `plan` guarantees `--name` with `--from-config`.
        ImportSource::Config(path) => {
            read_config_file(invocation, path, plan.name.as_deref().unwrap_or_default())?
        }
    };
    for source in &sources.entries {
        if let Content::Converted { config, .. } = &source.content {
            invocation.secrets.register_config(config);
        }
    }
    let store = invocation.env.store()?;
    let unlocked = store.read_index()?;
    let rows = import::plan(&sources.entries, &unlocked, plan.replace)?;
    let ts_active = sources.ts_active.as_deref();
    let outcome = if plan.dry_run || !rows.iter().any(|row| row.action.writes()) {
        Outcome {
            selected: import::selection(&unlocked, ts_active, &rows),
            rows,
        }
    } else {
        let mut transaction = begin(invocation, &store, true)?;
        let outcome = import_locked(
            &mut transaction,
            &store,
            &sources.entries,
            ts_active,
            plan.replace,
        )?;
        invocation.committed = outcome.rows.iter().any(|row| row.action.writes());
        finish(invocation, transaction);
        outcome
    };
    report(invocation, &plan, &store, &outcome)
}

/// Under the lock: re-plan against the re-read store (a tenant created meanwhile
/// becomes a `skip`), check every target before writing anything, write the tenant
/// files, then `config.toml` (the commit point). Any write failure restores what was
/// written (best effort).
fn import_locked(
    transaction: &mut Transaction,
    store: &Store,
    sources: &[Source],
    ts_active: Option<&str>,
    replace: bool,
) -> Result<Outcome, CliError> {
    let index = store.read_index()?;
    let rows = import::plan(sources, &index, replace)?;
    let selected = import::selection(&index, ts_active, &rows);
    let written: Vec<&Row> = rows.iter().filter(|row| row.action.writes()).collect();
    if written.is_empty() {
        return Ok(Outcome { rows, selected });
    }
    let index_bytes = import::apply(&index, &rows, selected.as_deref()).to_toml();
    let index_path = store.index_path();
    // Size, safety and read-only refusals come first, so they write nothing (D87).
    atomic::check_size(&index_path, index_bytes.as_bytes())?;
    atomic::check_replaceable(&index_path)?;
    let mut files = Vec::with_capacity(written.len());
    for row in &written {
        let path = store.tenant_path(&row.name);
        let bytes = row
            .config
            .as_ref()
            .map(|config| config.to_toml())
            .unwrap_or_default();
        atomic::check_size(&path, bytes.as_bytes())?;
        atomic::check_replaceable(&path)?;
        let previous = match store.read_tenant_bytes(&row.name) {
            Ok(bytes) => Some(bytes),
            Err(TenantFileRead::NotFound) => None,
            Err(_) => return Err(not_imported(&path, true)),
        };
        files.push((path, bytes, previous));
    }
    for (path, bytes, previous) in files {
        if transaction
            .write(&path, bytes.as_bytes(), previous)
            .is_err()
        {
            let restored = transaction.rollback();
            return Err(not_imported(&path, restored));
        }
    }
    if transaction
        .write(&index_path, index_bytes.as_bytes(), None)
        .is_err()
    {
        let restored = transaction.rollback();
        return Err(not_imported(&index_path, restored));
    }
    Ok(Outcome { rows, selected })
}

/// `Cannot save <path>; no tenant was imported` when the rollback restored every
/// tenant file, otherwise
/// `Cannot save <path>; some tenant files could not be restored, so run the same import again to finish it`.
fn not_imported(path: &Path, restored: bool) -> CliError {
    CliError::operational(format!(
        "Cannot save {}; {}",
        shown(path),
        if restored {
            "no tenant was imported"
        } else {
            "some tenant files could not be restored, so run the same import again to finish it"
        }
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportRow<'a> {
    name: &'a str,
    tsg_id: &'a str,
    action: &'static str,
    notes: &'a [String],
}

const REPORT_COLUMNS: [&str; 4] = ["Tenant", "TSG ID", "Action", "Notes"];

/// The report (stdout, data), then the status lines (stderr, quiet-suppressed) and the
/// exit status (§3.12 "Report", "Exit code").
fn report(
    invocation: &mut Invocation,
    plan: &ImportPlan,
    store: &Store,
    outcome: &Outcome,
) -> Result<(), CliError> {
    let output = &mut invocation.output;
    let rows = &outcome.rows;
    match plan.format {
        Format::Json => {
            let rows: Vec<ReportRow<'_>> = rows
                .iter()
                .map(|row| ReportRow {
                    name: &row.name,
                    tsg_id: &row.tsg_id,
                    action: row.action.word(),
                    notes: &row.notes,
                })
                .collect();
            output.json(&rows)?;
        }
        Format::Pretty if rows.is_empty() => pretty::empty_list(output, "tenants"),
        Format::Pretty | Format::Table => {
            let cells: Vec<Vec<String>> = rows
                .iter()
                .map(|row| {
                    vec![
                        terminal_safe(&row.name).into_owned(),
                        terminal_safe(&row.tsg_id).into_owned(),
                        row.action.word().to_owned(),
                        terminal_safe(&row.notes.join("; ")).into_owned(),
                    ]
                })
                .collect();
            output.data_line(&table::table(&REPORT_COLUMNS, &cells));
        }
    }
    // The data first, then the status lines.
    let _ = output.commit();
    let count = |action: import::Action| rows.iter().filter(|row| row.action == action).count();
    let (imported, replaced, skipped) = (
        count(import::Action::Import),
        count(import::Action::Replace),
        count(import::Action::Skip),
    );
    if output.pending_signal().is_none() {
        if plan.dry_run {
            output.status(&format!(
                "Dry run: would import {imported}, replace {replaced}, skip {skipped}; nothing was written"
            ));
        } else {
            output.status(&format!(
                "Imported {imported}, replaced {replaced}, skipped {skipped} into {}",
                shown(store.dir())
            ));
        }
        if let Some(name) = &outcome.selected {
            let verb = if plan.dry_run {
                "Would select"
            } else {
                "Selected"
            };
            output.status(&format!(
                "{verb} {name} (selected in the TypeScript registry)"
            ));
        }
    }
    match rows.iter().filter(|row| row.failed).count() {
        0 => Ok(()),
        1 => Err(CliError::operational("1 tenant could not be imported")),
        failed => Err(CliError::operational(format!(
            "{failed} tenants could not be imported"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, TenantCommand, TopCommand};
    use crate::store::testdir::TestDir;
    use clap::FromArgMatches;

    fn planned(args: &[&str]) -> Result<ImportPlan, CliError> {
        let mut full = vec!["airs", "tenant", "import"];
        full.extend_from_slice(args);
        let matches = crate::cli::command().try_get_matches_from(&full).unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();
        match cli.command {
            Some(TopCommand::Tenant(crate::cli::TenantGroup {
                command: Some(TenantCommand::Import(args)),
            })) => plan(&args, Format::Pretty),
            _ => unreachable!(),
        }
    }

    fn usage(args: &[&str]) -> String {
        match planned(args) {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error for {args:?}, got {other:?}"),
        }
    }

    #[test]
    fn validation_order() {
        assert_eq!(
            usage(&["--from", "", "--from-config", "", "--name", "-x"]),
            "--from and --from-config cannot be combined"
        );
        assert_eq!(
            usage(&["--from", "", "--name", "-x"]),
            "--from needs a path"
        );
        assert_eq!(
            usage(&["--from-config", "", "--name", "-x"]),
            "--from-config needs a path"
        );
        assert_eq!(
            usage(&["--from-config", "dev.json"]),
            "--from-config requires --name <name>"
        );
        assert_eq!(usage(&["--name", "-x"]), NAME_RULE);
        assert_eq!(usage(&["--name", ""]), NAME_RULE);
        let ok = planned(&["--from-config", "c.json", "--name", "dev", "--replace"]).unwrap();
        assert_eq!(ok.source, ImportSource::Config("c.json".into()));
        assert!(ok.replace && !ok.dry_run);
        let ok = planned(&["--dry-run"]).unwrap();
        assert_eq!(ok.source, ImportSource::Registry(None));
        assert!(ok.dry_run);
    }

    fn row(name: &str, action: import::Action) -> Row {
        Row {
            name: name.to_owned(),
            tsg_id: "1".to_owned(),
            action,
            notes: Vec::new(),
            failed: false,
            config: Some(crate::tenant::config::TenantConfig::from_values([(
                "mgmtTsgId",
                crate::tenant::config::ConfigValue::Text("1".to_owned()),
            )])),
        }
    }

    fn source(name: &str) -> Source {
        let row = row(name, import::Action::Import);
        Source {
            name: row.name,
            tsg_id: row.tsg_id,
            content: Content::Converted {
                config: row.config.unwrap_or_default(),
                notes: Vec::new(),
            },
        }
    }

    #[test]
    fn a_failed_index_write_restores_every_tenant_file() {
        use crate::store::atomic::{Step, fail_writes};
        let dir = TestDir::new("import-rollback");
        let store = Store::at(dir.path().join("D"));
        dir.write(
            "D/config.toml",
            b"version = 1\n\n[tenants.old]\ntsg_id = \"1\"\n",
            0o600,
        );
        dir.write(
            "D/tenants/old.toml",
            b"mgmtTsgId = \"1\"\nairsApiKey = \"K\"\n",
            0o600,
        );
        let index_before = std::fs::read(store.index_path()).unwrap();
        let mut transaction =
            Transaction::begin(&store, true, &mut crate::store::lock::Silent).unwrap();
        // Writes: new.toml (1), old.toml (2), config.toml (3).
        fail_writes(Some(Step::Rename), &[3]);
        let result = import_locked(
            &mut transaction,
            &store,
            &[source("new"), source("old")],
            None,
            true,
        );
        fail_writes(None, &[]);
        assert_eq!(
            result.err().map(|error| error.message()),
            Some(format!(
                "Cannot save {}; no tenant was imported",
                store.index_path().display()
            ))
        );
        drop(transaction);
        assert!(!store.tenant_path("new").exists(), "a new file is unlinked");
        assert_eq!(
            std::fs::read(store.tenant_path("old")).unwrap(),
            b"mgmtTsgId = \"1\"\nairsApiKey = \"K\"\n",
            "a replaced file gets its bytes back"
        );
        assert_eq!(std::fs::read(store.index_path()).unwrap(), index_before);
    }

    #[test]
    fn a_failed_restore_says_the_import_must_be_run_again() {
        use crate::store::atomic::{Step, fail_writes};
        let dir = TestDir::new("import-restore-fail");
        let store = Store::at(dir.path().join("D"));
        dir.write(
            "D/config.toml",
            b"version = 1\n\n[tenants.old]\ntsg_id = \"1\"\n",
            0o600,
        );
        dir.write(
            "D/tenants/old.toml",
            b"mgmtTsgId = \"1\"\nairsApiKey = \"K\"\n",
            0o600,
        );
        let index_before = std::fs::read(store.index_path()).unwrap();
        let mut transaction =
            Transaction::begin(&store, true, &mut crate::store::lock::Silent).unwrap();
        // Writes: old.toml (1), config.toml (2, fails), the restore of old.toml (3, fails).
        fail_writes(Some(Step::Rename), &[2, 3]);
        let result = import_locked(&mut transaction, &store, &[source("old")], None, true);
        fail_writes(None, &[]);
        assert_eq!(
            result.err().map(|error| error.message()),
            Some(format!(
                "Cannot save {}; some tenant files could not be restored, so run the same import again to finish it",
                store.index_path().display()
            ))
        );
        drop(transaction);
        assert_eq!(
            std::fs::read(store.tenant_path("old")).unwrap(),
            b"mgmtTsgId = \"1\"\n",
            "the replaced file still holds the imported content"
        );
        assert_eq!(std::fs::read(store.index_path()).unwrap(), index_before);
    }

    #[test]
    fn a_failed_tenant_write_writes_nothing_else() {
        use crate::store::atomic::{Step, fail_writes};
        let dir = TestDir::new("import-tenant-fail");
        let store = Store::at(dir.path().join("D"));
        let mut transaction =
            Transaction::begin(&store, true, &mut crate::store::lock::Silent).unwrap();
        fail_writes(Some(Step::Write), &[2]);
        let result = import_locked(
            &mut transaction,
            &store,
            &[source("a"), source("b")],
            Some("a"),
            false,
        );
        fail_writes(None, &[]);
        assert_eq!(
            result.err().map(|error| error.message()),
            Some(format!(
                "Cannot save {}; no tenant was imported",
                store.tenant_path("b").display()
            ))
        );
        drop(transaction);
        assert!(!store.tenant_path("a").exists());
        assert!(!store.index_path().exists());
    }

    #[test]
    fn the_locked_plan_sees_tenants_created_meanwhile() {
        let dir = TestDir::new("import-recheck");
        let store = Store::at(dir.path().join("D"));
        let mut transaction =
            Transaction::begin(&store, true, &mut crate::store::lock::Silent).unwrap();
        // Created after the unlocked plan, before the lock.
        dir.write(
            "D/config.toml",
            b"version = 1\n\n[tenants.dev]\ntsg_id = \"1\"\n",
            0o600,
        );
        let outcome = import_locked(
            &mut transaction,
            &store,
            &[source("dev")],
            Some("dev"),
            false,
        )
        .unwrap();
        assert_eq!(outcome.rows[0].action, import::Action::Skip);
        assert_eq!(outcome.selected, None);
        assert!(!store.tenant_path("dev").exists());
    }
}
