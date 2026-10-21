//! `runtime dlp backup` and `runtime dlp restore <file>` (DESIGN §16.10, §16.11; D175,
//! D176, D177).
//!
//! A backup is one airs file per run: the destination is checked before the
//! tenant is read, the three inventories are swept with the TS page checks, the
//! selection closes over each profile's dependencies, the keywords are read per
//! dictionary (a failed read is a `failed` row), and the file is published exclusively at
//! 0600 after every read. A restore reads only such a file (a TypeScript backup is
//! refused), checks it against the selected tenant, plans every row against the
//! destination inventories before the first write, rechecks them, sends each create once
//! and stops at the first failure.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::Invocation;
use super::dlp::{BackupRun, NO_BACKUP_WRITTEN, RestoreRun};
use super::redteam::{page_value, value};
use crate::clients::{DlpClients, SINGLE_REQUEST_BUDGET, WALK_BUDGET};
use crate::dlp::backup::{self as bk, Backup, Failed, Inventory, Resource, Step, Sweep};
use crate::dlp::plan::{
    self as pl, Binding, DependencyAction, Destination, ProfileAction, RestorePlan,
};
use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::output::{self, Format, terminal_safe};
use crate::render::style::Style;
use crate::render::table;
use crate::store::PROGRAM;
use crate::writes::{self, Failure, classify};
use scm::dlp::models as m;
use scm::dlp::{DictionaryListParams, DlpClient, SpringListParams};
use serde_json::{Value, json};

/// The selected tenant's DLP client (not yet authenticated), store name, `mgmtTsgId`
/// and `defaultOutput`.
struct Prepared {
    clients: DlpClients,
    tenant: String,
    tsg: String,
    default_output: Option<String>,
}

impl Invocation {
    /// Load the tenant, check the management credentials (§3.5) and build the DLP
    /// client; no request.
    fn dlp_prepare(&mut self) -> Result<Prepared, CliError> {
        let context = self.load_tenant()?;
        let default_output = context.config.default_output().map(str::to_owned);
        crate::tenant::config::require_management(&context.config, Some(context.name()))?;
        let clients = DlpClients::build(
            &context.config,
            &self.session,
            &self.secrets,
            self.debug.as_ref(),
        )?;
        Ok(Prepared {
            clients,
            tenant: context.name().to_owned(),
            tsg: crate::tenant::config::js_trim(
                context
                    .config
                    .effective_str("mgmtTsgId")
                    .unwrap_or_default(),
            )
            .to_owned(),
            default_output,
        })
    }
}

/// An interruption reports `context`; other errors pass.
fn within(context: &InterruptContext) -> impl Fn(CliError) -> CliError + '_ {
    move |error| match error {
        CliError::Interrupted(_) => CliError::Interrupted(context.clone()),
        other => other,
    }
}

/// A server name for printing: `[withheld]` when it carries a secret, terminal-safe.
fn shown(invocation: &Invocation, name: &str) -> String {
    if invocation.secrets.carried_by(name) {
        crate::error::WITHHELD.to_owned()
    } else {
        terminal_safe(name).into_owned()
    }
}

/// A server name for a JSON document: `[withheld]` when it carries a secret.
fn raw(invocation: &Invocation, name: &str) -> String {
    if invocation.secrets.carried_by(name) {
        crate::error::WITHHELD.to_owned()
    } else {
        name.to_owned()
    }
}

/// One inventory page of `resource` (`size=100`, `sort=name,asc`; dictionaries without
/// keywords, G13), as ordered JSON.
async fn inventory_page(
    dlp: &DlpClient,
    resource: Resource,
    page: u64,
    options: &scm::RequestOptions,
) -> Result<OValue, scm::Error> {
    let sort = vec![crate::dlp::DEFAULT_SORT.to_owned()];
    match resource {
        Resource::Dictionaries => {
            let mut query = DictionaryListParams::default();
            query.page = Some(page);
            query.size = Some(bk::PAGE_SIZE);
            query.sort = sort;
            page_value(&dlp.dictionaries().list(&query, Some(options)).await?)
        }
        Resource::Patterns | Resource::Profiles => {
            let mut query = SpringListParams::new().sort(sort);
            query.page = Some(page);
            query.size = Some(bk::PAGE_SIZE);
            if resource == Resource::Patterns {
                page_value(&dlp.data_patterns().list(&query, Some(options)).await?)
            } else {
                page_value(&dlp.data_profiles().list(&query, Some(options)).await?)
            }
        }
    }
}

/// The three inventories in TS order (dictionaries, data patterns, data profiles), each
/// swept with the TS page checks under one walk deadline.
async fn inventories(
    invocation: &Invocation,
    dlp: &DlpClient,
    max_pages: u64,
) -> Result<Inventory, CliError> {
    let deadline = super::walk_options()?;
    let mut inventory = Inventory::default();
    for resource in Resource::ALL {
        let mut sweep = Sweep::new(resource);
        let mut done = false;
        for page in 0..max_pages {
            let answer = inventory_page(dlp, resource, page, &deadline)
                .await
                .map_err(|error| invocation.management_error(&error, WALK_BUDGET))?;
            if sweep.accept(page, &answer).map_err(CliError::operational)? == Step::Done {
                done = true;
                break;
            }
        }
        if !done {
            return Err(CliError::operational(sweep.incomplete()));
        }
        let items = sweep.into_items();
        match resource {
            Resource::Dictionaries => inventory.dictionaries = items,
            Resource::Patterns => inventory.patterns = items,
            Resource::Profiles => inventory.profiles = items,
        }
    }
    Ok(inventory)
}

// ---------------------------------------------------------------------------
// backup (§16.10)
// ---------------------------------------------------------------------------

/// The keyword-bearing record of a custom dictionary (`GET …/<id>?keywords=true`, a
/// read with the SDK retries): the same `id` and `name` and a `keywords` string array.
async fn keywords_of(
    invocation: &Invocation,
    dlp: &DlpClient,
    id: &str,
    name: &str,
) -> Result<OValue, CliError> {
    let record = dlp
        .dictionaries()
        .get(id, Some(true), None)
        .await
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
    let record = value(&record)?;
    let words = record.get("keywords").and_then(OValue::as_array);
    let ok = record.get("id").and_then(OValue::as_str) == Some(id)
        && record.get("name").and_then(OValue::as_str) == Some(name)
        && words.is_some_and(|words| words.iter().all(|word| word.as_str().is_some()));
    if ok {
        Ok(record)
    } else {
        Err(CliError::operational(format!(
            "Dictionary keywords were not returned by the region: {}",
            terminal_safe(name)
        )))
    }
}

/// `runtime dlp backup` (§16.10).
pub async fn backup(invocation: &mut Invocation, run: &BackupRun) -> Result<(), CliError> {
    // The location, before the tenant and any request.
    let exported_at = crate::debug::iso_timestamp(std::time::SystemTime::now());
    let path: PathBuf = match &run.output_file {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(".").join(format!(
            "airs-dlp-backup-{}-{}.json",
            bk::stamp(&exported_at),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        )),
    };
    let dir = crate::files::parent_dir(&path);
    if !std::fs::metadata(&dir).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(CliError::operational(format!(
            "Cannot write a backup into {}; it must be an existing directory",
            crate::files::shown(dir.as_os_str())
        )));
    }
    crate::files::refuse_existing(&path, "--output-file")?;
    let context = InterruptContext::Context(NO_BACKUP_WRITTEN.to_owned());
    let prepared = invocation.dlp_prepare().map_err(within(&context))?;
    let format = output::resolve_tenant_default(run.format, prepared.default_output.as_deref());
    let deadline = super::walk_options()?;
    prepared
        .clients
        .authenticate(Some(&deadline), WALK_BUDGET)
        .await
        .map_err(within(&context))?;
    let dlp = prepared.clients.dlp.clone();
    invocation
        .output
        .info("Reading inventories (dictionaries, data patterns, data profiles)…");
    let inventory = inventories(invocation, &dlp, run.max_pages)
        .await
        .map_err(within(&context))?;
    let mut selection = bk::select(&inventory, &run.resources, run.skip_unsupported)
        .map_err(CliError::operational)?;
    for item in &selection.skipped {
        invocation.output.warning(&format!(
            "⚠ Skipped unsupported data profile: {} ({})",
            shown(invocation, &item.name),
            terminal_safe(&item.reason)
        ));
    }
    // The keywords, per custom dictionary in name order (G13).
    let mut failed: Vec<Failed> = Vec::new();
    let mut kept = Vec::with_capacity(selection.dictionaries.len());
    for mut entry in std::mem::take(&mut selection.dictionaries) {
        if entry.predefined {
            kept.push(entry);
            continue;
        }
        match keywords_of(invocation, &dlp, &entry.id, &entry.name).await {
            Ok(record) => {
                entry.record = record;
                kept.push(entry);
            }
            Err(CliError::Interrupted(_)) => return Err(CliError::Interrupted(context)),
            Err(error) => failed.push(Failed {
                kind: Resource::Dictionaries.row_kind().to_owned(),
                id: entry.id.clone(),
                name: entry.name.clone(),
                error: error.message(),
            }),
        }
    }
    selection.dictionaries = kept;
    for item in &failed {
        invocation.output.warning(&format!(
            "⚠ Could not back up {} {}: {}",
            item.kind,
            shown(invocation, &item.name),
            terminal_safe(&item.error)
        ));
    }
    let contents = selection.dictionaries.iter().any(|entry| !entry.predefined)
        || selection.patterns.iter().any(|entry| !entry.predefined);
    let document = Backup {
        exported_at,
        tenant: prepared.tenant.clone(),
        tsg_id: prepared.tsg.clone(),
        dlp_tenant_id: selection.tenant_id.clone(),
        resources: run.resources.clone(),
        dictionaries: selection.dictionaries,
        patterns: selection.patterns,
        profiles: selection.profiles,
        skipped: selection.skipped,
        failed,
    };
    let text = document.to_text();
    if text.len() > bk::MAX_BACKUP_BYTES {
        return Err(CliError::operational(
            "Backup exceeds the 20 MiB size limit; select fewer --resources",
        ));
    }
    if invocation.output.pending_signal().is_some() {
        return Err(CliError::Interrupted(context));
    }
    let published = crate::files::publish_new(&path, text.as_bytes(), "--output-file")?;
    let shown_path = crate::files::shown(path.as_os_str());
    invocation.interrupt = Some(InterruptContext::Context(format!(
        "the backup was saved in {}",
        terminal_safe(&shown_path)
    )));
    if published == crate::files::Published::DirectoryNotSynced {
        invocation
            .output
            .warning(&crate::store::atomic::dir_sync_warning(&path));
    }
    if contents {
        invocation.output.warning(&format!(
            "⚠ {} contains DLP dictionary keywords and pattern definitions; keep it private (mode 0600)",
            terminal_safe(&shown_path)
        ));
    }
    render_backup(invocation, format, &shown_path, &document)
}

/// The TS one-row summary (`Failed` is Rust-only) or the one-element JSON array.
fn render_backup(
    invocation: &mut Invocation,
    format: Format,
    file: &str,
    document: &Backup,
) -> Result<(), CliError> {
    let count = |n: usize| n.to_string();
    match format {
        Format::Json => {
            let number = |n: usize| OValue::Number((n as u64).into());
            let doc = OValue::Array(vec![OValue::Object(vec![
                ("file".into(), OValue::String(file.to_owned())),
                (
                    "sourceTsgId".into(),
                    OValue::String(document.tsg_id.clone()),
                ),
                ("dictionaries".into(), number(document.dictionaries.len())),
                ("patterns".into(), number(document.patterns.len())),
                ("profiles".into(), number(document.profiles.len())),
                ("skipped".into(), number(document.skipped.len())),
                ("failed".into(), number(document.failed.len())),
                ("complete".into(), OValue::Bool(document.complete())),
            ])]);
            invocation.output.json(&doc)?;
        }
        Format::Pretty | Format::Table => {
            let row = vec![
                terminal_safe(file).into_owned(),
                terminal_safe(&document.tsg_id).into_owned(),
                count(document.dictionaries.len()),
                count(document.patterns.len()),
                count(document.profiles.len()),
                count(document.skipped.len()),
                count(document.failed.len()),
            ];
            invocation.output.data_line(&table::table(
                &[
                    "Backup file",
                    "Source TSG",
                    "Dictionaries",
                    "Patterns",
                    "Profiles",
                    "Skipped",
                    "Failed",
                ],
                &[row],
            ));
        }
    }
    if !document.failed.is_empty() {
        let _ = invocation.output.commit();
        return Err(CliError::Reported(crate::error::EXIT_OPERATIONAL));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// restore (§16.11)
// ---------------------------------------------------------------------------

/// The restore file limit (TS, 20 MiB).
const RESTORE_LIMIT: u64 = 20 * 1_048_576;

/// Whether a stored record matches the SDK response schema of its kind.
fn valid_record(resource: Resource, record: &OValue) -> bool {
    let wire = serde_json::to_value(record).unwrap_or(Value::Null);
    let mode = scm::validation::Mode::Response;
    match resource {
        Resource::Dictionaries => m::DictionaryResponse::parse(wire, mode).is_ok(),
        Resource::Patterns => m::DataPatternResponse::parse(wire, mode).is_ok(),
        Resource::Profiles => m::DataProfileResponse::parse(wire, mode).is_ok(),
    }
}

/// Reads and checks the backup file before the tenant (§16.11 "The file").
fn read_backup(file: &std::ffi::OsStr) -> Result<Backup, CliError> {
    let shown = crate::files::shown(file);
    let text = crate::files::read_text(file, RESTORE_LIMIT)?;
    bk::parse(&text, valid_record).map_err(|failure| {
        CliError::operational(match failure {
            bk::ReadFailure::Malformed => format!("Invalid DLP backup {shown}: malformed JSON"),
            bk::ReadFailure::TypeScript => format!(
                "{shown} is a TypeScript airs-cli backup; {PROGRAM} cannot restore it. Restore it with the TypeScript airs-cli, or back the resources up again with '{PROGRAM} runtime dlp backup'."
            ),
            bk::ReadFailure::Newer => format!(
                "{shown} was written by a newer version of {PROGRAM}; upgrade {PROGRAM} to restore it"
            ),
            bk::ReadFailure::Invalid(reason) => format!("Invalid DLP backup {shown}: {reason}"),
        })
    })
}

/// The destination inventories as plain values.
fn destination_of(inventory: &Inventory) -> Destination {
    let plain = |records: &[OValue]| records.iter().map(bk::value_of).collect();
    Destination {
        dictionaries: plain(&inventory.dictionaries),
        patterns: plain(&inventory.patterns),
        profiles: plain(&inventory.profiles),
        keywords: BTreeMap::new(),
    }
}

/// `runtime dlp restore <file>` (§16.11).
pub async fn restore(invocation: &mut Invocation, run: &RestoreRun) -> Result<(), CliError> {
    let shown_file = crate::files::shown(&run.file);
    let backup = read_backup(&run.file)?;
    if !backup.complete() {
        invocation.output.warning(&format!(
            "⚠ {} is incomplete: {} resource(s) were skipped or could not be backed up",
            terminal_safe(&shown_file),
            backup.skipped.len() + backup.failed.len()
        ));
    }
    if let Some(message) = pl::absent_map_names(&backup, &run.options) {
        return Err(CliError::operational(terminal_safe(&message).into_owned()));
    }
    pl::prevalidate(&backup)
        .map_err(|message| CliError::operational(terminal_safe(&message).into_owned()))?;
    let nothing = InterruptContext::NothingChanged;
    let prepared = invocation.dlp_prepare().map_err(within(&nothing))?;
    if backup.tsg_id != prepared.tsg && !run.allow_other_tenant {
        return Err(CliError::operational(format!(
            "{} was exported from TSG {}; the selected tenant uses TSG {}. Pass --allow-other-tenant to restore it here.",
            terminal_safe(&shown_file),
            terminal_safe(&backup.tsg_id),
            terminal_safe(&prepared.tsg)
        )));
    }
    if run
        .expect_tsg
        .as_deref()
        .is_some_and(|expected| expected != prepared.tsg)
    {
        return Err(CliError::operational(
            "--expect-tsg does not match the selected destination tenant; no API request was made",
        ));
    }
    let format = output::resolve_tenant_default(run.format, prepared.default_output.as_deref());
    let deadline = super::walk_options()?;
    prepared
        .clients
        .authenticate(Some(&deadline), WALK_BUDGET)
        .await
        .map_err(within(&nothing))?;
    let dlp = prepared.clients.dlp.clone();
    invocation
        .output
        .info("Reading inventories (dictionaries, data patterns, data profiles)…");
    let inventory = inventories(invocation, &dlp, run.max_pages)
        .await
        .map_err(within(&nothing))?;
    let mut destination = destination_of(&inventory);
    // The keywords of the same-name destination dictionaries, read per id (G13).
    for id in pl::keyword_reads(&backup, &destination, &run.options.prefix) {
        let record = dlp
            .dictionaries()
            .get(&id, Some(true), None)
            .await
            .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))
            .map_err(within(&nothing))?;
        let record = serde_json::to_value(&record).unwrap_or(Value::Null);
        if let Some(words) = record.get("keywords") {
            destination.keywords.insert(id, words.clone());
        }
    }
    let plan = pl::plan(&backup, &prepared.tsg, &destination, &run.options)
        .map_err(CliError::operational)?;
    for entry in &plan.unresolved {
        let kind = if entry.kind == "dictionary" {
            "dictionary"
        } else {
            "data pattern"
        };
        let candidates = if entry.candidates.is_empty() {
            String::new()
        } else {
            let quoted: Vec<String> = entry
                .candidates
                .iter()
                .map(|name| format!("\"{}\"", shown(invocation, name)))
                .collect();
            format!("; candidates: {}", quoted.join(", "))
        };
        invocation.output.warning(&format!(
            "⚠ Unresolved {kind}: {} ({}){candidates}",
            shown(invocation, &entry.name),
            terminal_safe(&entry.reason)
        ));
    }
    for row in &plan.profiles {
        if let Some(reason) = &row.reason {
            invocation.output.warning(&format!(
                "⚠ Skipping data profile: {} ({})",
                shown(invocation, &row.name),
                terminal_safe(reason)
            ));
        }
    }
    if run.dry_run {
        return render_preview(invocation, format, &plan);
    }
    let creates = plan.creates();
    if creates > 0 && !run.force {
        let message = format!(
            "Restore {creates} DLP resources from TSG {} to TSG {}?",
            plan.source_tsg, plan.destination_tsg
        );
        if !super::write_common::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let result = execute(invocation, &dlp, &plan, run.max_pages).await?;
    render_result(invocation, format, &plan, &result)
}

// ---------------------------------------------------------------------------
// Execution (TS `restoreDlpResources`, D160, D177)
// ---------------------------------------------------------------------------

/// One result row.
#[derive(Clone, Debug, Default)]
struct Row {
    name: String,
    action: &'static str,
    id: Option<String>,
    reason: Option<String>,
    renamed_from: Option<String>,
}

/// What an execution did.
#[derive(Debug, Default)]
struct Outcome {
    complete: bool,
    dictionaries: Vec<Row>,
    patterns: Vec<Row>,
    profiles: Vec<Row>,
    server_added: Vec<(String, Vec<String>)>,
    /// `(kind, name, id)` of a confirmed create not yet verified.
    unverified: Vec<(&'static str, String, String)>,
    /// `(kind, name)` of a create that may have been applied (Rust-only).
    outcome_unknown: Option<(&'static str, String)>,
    /// `(kind, name)` of every planned item after the failure (Rust-only).
    not_attempted: Vec<(&'static str, String)>,
    error: Option<String>,
    created: usize,
}

impl Outcome {
    /// The interrupt context (§16.11 "Interruption").
    fn context(&self) -> InterruptContext {
        if self.created == 0 && self.outcome_unknown.is_none() {
            return InterruptContext::NothingChanged;
        }
        let mut text = format!("{} resource(s) created", self.created);
        if let Some((kind, name)) = &self.outcome_unknown {
            text.push_str(&format!(
                "; the {} {} may also have been created (outcome unknown)",
                singular(kind),
                terminal_safe(name)
            ));
        }
        text.push_str("; run the restore again to resume");
        InterruptContext::Context(text)
    }
}

/// The TS `unverifiedCreates` kind of a stage.
fn stage_key(resource: Resource) -> &'static str {
    resource.key()
}

fn singular(key: &str) -> &'static str {
    match key {
        "dictionaries" => "dictionary",
        "patterns" => "data pattern",
        _ => "data profile",
    }
}

/// TS `result.error` of an error that is not an SDK status (its own text when it is
/// one of the restore's messages, else the generic stop).
fn stop_text(message: &str) -> String {
    const KEPT: [&str; 8] = [
        "Destination",
        "Restored",
        "Missing",
        "Inventory",
        "Ambiguous",
        "Dictionary",
        "Data pattern",
        "Data profile",
    ];
    if KEPT.iter().any(|prefix| message.starts_with(prefix)) {
        message.to_owned()
    } else {
        "Restore stopped; verify destination state before retrying".to_owned()
    }
}

fn http_text(status: Option<u16>) -> String {
    match status {
        Some(status) => {
            format!("API request failed (HTTP {status}); verify destination state before retrying")
        }
        None => "Restore stopped; verify destination state before retrying".to_owned(),
    }
}

/// The text of a read failure (a read-back or a recheck read).
fn read_failure(error: &CliError, sdk: Option<&scm::Error>) -> String {
    match sdk {
        Some(error) if error.kind() == scm::ErrorKind::Http => http_text(error.status()),
        Some(_) => "Restore stopped; verify destination state before retrying".to_owned(),
        None => stop_text(&error.message()),
    }
}

struct Executor<'a> {
    invocation: &'a mut Invocation,
    dlp: &'a DlpClient,
    plan: &'a RestorePlan,
    max_pages: u64,
    outcome: Outcome,
    bindings: BTreeMap<String, Binding>,
    /// The `(stage, index)` of the item being processed (`None` before the first).
    cursor: Option<(u8, usize)>,
}

/// Why a stage stopped.
enum Stop {
    /// The run stops; the outcome holds the error.
    Failed,
    /// A signal: the caller reports the outcome's context.
    Interrupted,
}

impl Executor<'_> {
    fn bullet(&mut self, resource: Resource, action: &str, name: &str, index: usize, total: usize) {
        if self.invocation.output.quiet() || self.invocation.output.pending_signal().is_some() {
            return;
        }
        let (glyph, style) = if action == "skipped" {
            ("○", Style::Yellow)
        } else {
            ("✓", Style::Green)
        };
        let glyph = self.invocation.output.paint_err(style, glyph);
        let name = shown(self.invocation, name);
        let line = format!(
            "  {glyph} {} {action}: {name} ({index}/{total})\n",
            resource.singular()
        );
        self.invocation.output.write_stderr(&line);
    }

    fn fail(&mut self, message: String) -> Stop {
        let mut message = message;
        if let Some((kind, name, id)) = self.outcome.unverified.first() {
            message.push_str(&format!(
                "; unverified create: {kind} {} (id {}); inspect this resource before retrying",
                terminal_safe(name),
                terminal_safe(id)
            ));
        }
        self.outcome.error = Some(message);
        Stop::Failed
    }

    fn checkpoint(&mut self) -> Result<(), Stop> {
        self.invocation.interrupt = Some(self.outcome.context());
        if self.invocation.output.pending_signal().is_some() {
            return Err(Stop::Interrupted);
        }
        Ok(())
    }

    /// The failure of a create attempt: its error text, the outcome-unknown record.
    /// `renamed`: the create was the reconcile copy under the deterministic suffix, which
    /// only a `--on-conflict reconcile` re-run looks up (D177).
    fn create_failed(
        &mut self,
        resource: Resource,
        name: &str,
        renamed: bool,
        failure: Failure,
    ) -> Stop {
        let kind = stage_key(resource);
        let hint = if renamed {
            "run the restore again with --on-conflict reconcile to verify it"
        } else {
            "run the restore again to reuse it (a data profile needs --on-conflict verify)"
        };
        match failure {
            Failure::Interrupted { sent } => {
                if sent {
                    self.outcome.outcome_unknown = Some((kind, name.to_owned()));
                }
                Stop::Interrupted
            }
            Failure::Rejected(status) => self.fail(http_text(status)),
            Failure::Local => {
                self.fail("Restore stopped; verify destination state before retrying".to_owned())
            }
            Failure::Unknown => {
                self.outcome.outcome_unknown = Some((kind, name.to_owned()));
                self.fail(format!(
                    "Outcome unknown: the {} {} may have been created; {hint}",
                    resource.singular(),
                    terminal_safe(name)
                ))
            }
            Failure::Unreadable => {
                self.outcome.outcome_unknown = Some((kind, name.to_owned()));
                self.fail(format!(
                    "Outcome: the {} {} was created, but the response could not be read; {hint}",
                    resource.singular(),
                    terminal_safe(name)
                ))
            }
        }
    }

    /// A read-back failure after a confirmed create (the receipt stays).
    fn read_back_failed(&mut self, error: &scm::Error) -> Stop {
        if error.kind() == scm::ErrorKind::Cancelled {
            return Stop::Interrupted;
        }
        let text = read_failure(&CliError::operational(""), Some(error));
        self.fail(text)
    }

    fn not_verified(&mut self, resource: Resource, name: &str, id: &str) -> Stop {
        self.fail(format!(
            "Restored {} did not verify: {} (created id {}; inspect it before retrying)",
            resource.singular(),
            terminal_safe(name),
            terminal_safe(id)
        ))
    }

    async fn recheck(&mut self) -> Result<(), Stop> {
        self.invocation
            .output
            .info("Rechecking destination state before writing…");
        let inventory = match inventories(self.invocation, self.dlp, self.max_pages).await {
            Ok(inventory) => inventory,
            Err(CliError::Interrupted(_)) => return Err(Stop::Interrupted),
            Err(error) => {
                let text = match &error {
                    CliError::Operational(failure) if failure.status.is_some() => {
                        http_text(failure.status)
                    }
                    other => stop_text(&other.message()),
                };
                return Err(self.fail(text));
            }
        };
        let current = destination_of(&inventory);
        let mut problem = None;
        for (resource, rows) in [
            (
                Resource::Dictionaries,
                self.plan
                    .dictionaries
                    .iter()
                    .map(|row| (row.name.as_str(), row.existing.as_ref()))
                    .collect::<Vec<_>>(),
            ),
            (
                Resource::Patterns,
                self.plan
                    .patterns
                    .iter()
                    .map(|row| (row.name.as_str(), row.existing.as_ref()))
                    .collect(),
            ),
            (
                Resource::Profiles,
                self.plan
                    .profiles
                    .iter()
                    .map(|row| (row.name.as_str(), row.existing.as_ref()))
                    .collect(),
            ),
        ] {
            for (name, existing) in rows {
                let found = match pl::destination_match(&current, resource, name) {
                    Ok(found) => found,
                    Err(message) => {
                        problem.get_or_insert(terminal_safe(&message).into_owned());
                        break;
                    }
                };
                let changed = match (existing, found) {
                    (Some(existing), Some(found)) => !pl::canonical_eq(existing, found),
                    (Some(_), None) => true,
                    (None, found) => {
                        if found.is_some() {
                            problem.get_or_insert(format!(
                                "Destination {} changed after planning: {}",
                                resource.singular(),
                                terminal_safe(name)
                            ));
                        }
                        false
                    }
                };
                if changed {
                    problem.get_or_insert(format!(
                        "Destination {}: {} changed after planning",
                        resource.singular(),
                        terminal_safe(name)
                    ));
                }
            }
        }
        match problem {
            Some(message) => Err(self.fail(message)),
            None => Ok(()),
        }
    }

    async fn dictionaries(&mut self) -> Result<(), Stop> {
        let resource = Resource::Dictionaries;
        let total = self.plan.dictionaries.len();
        if total > 0 {
            self.invocation
                .output
                .info(&format!("Restoring {} ({total})…", resource.label()));
        }
        for (index, row) in self.plan.dictionaries.iter().enumerate() {
            self.cursor = Some((0, index));
            if row.action != DependencyAction::Create {
                let Some(id) = row.existing.as_ref().and_then(id_of) else {
                    return Err(self.fail(format!(
                        "Destination dictionary has no identity: {}",
                        terminal_safe(&row.name)
                    )));
                };
                self.outcome.dictionaries.push(Row {
                    name: row.name.clone(),
                    action: row.action.done(),
                    id: Some(id),
                    ..Row::default()
                });
                self.bullet(resource, row.action.done(), &row.name, index + 1, total);
                continue;
            }
            self.checkpoint()?;
            let (Some(metadata), keywords) = (&row.metadata, &row.keywords) else {
                return Err(self.fail("Dictionary plan is incomplete".to_owned()));
            };
            let upload =
                m::DictionaryRequest::parse(metadata.clone(), scm::validation::Mode::Request)
                    .ok()
                    .zip(pl::dictionary_file(metadata, keywords).ok())
                    .and_then(|(request, text)| {
                        scm::dlp::DictionaryUpload::text(request, text).ok()
                    })
                    .map(|upload| upload.include_keywords(true));
            let Some(upload) = upload else {
                return Err(self
                    .fail("Restore stopped; verify destination state before retrying".to_owned()));
            };
            let dictionaries = self.dlp.dictionaries();
            let created =
                match writes::attempt(async || dictionaries.create(&upload, None).await).await {
                    Ok(created) => created,
                    Err(error) => {
                        let failure = classify(&error);
                        return Err(self.create_failed(resource, &row.name, false, failure));
                    }
                };
            // A 2xx without a usable id: applied, the answer unusable (§16.12).
            let Some(id) = created_id(&created) else {
                return Err(self.create_failed(resource, &row.name, false, Failure::Unreadable));
            };
            self.outcome.created += 1;
            self.outcome
                .unverified
                .push((stage_key(resource), row.name.clone(), id.clone()));
            self.invocation.interrupt = Some(self.outcome.context());
            let read_back = match dictionaries.get(&id, Some(true), None).await {
                Ok(record) => serde_json::to_value(&record).unwrap_or(Value::Null),
                Err(error) => return Err(self.read_back_failed(&error)),
            };
            let echo = pl::dictionary_echo(metadata, Some(&read_back), keywords);
            if !echo.matches()
                || id_of(&read_back).as_deref() != Some(id.as_str())
                || read_back.get("name").and_then(Value::as_str) != Some(row.name.as_str())
            {
                return Err(self.not_verified(resource, &row.name, &id));
            }
            if !echo.server_added.is_empty() {
                self.outcome
                    .server_added
                    .push((format!("dictionary {}", row.name), echo.server_added));
            }
            self.bindings.insert(
                row.source_id.clone(),
                Binding {
                    dictionary: true,
                    technique: Some("dictionary".to_owned()),
                    id: id.clone(),
                    name: row.name.clone(),
                    version: Some(json!(1)),
                },
            );
            self.outcome.dictionaries.push(Row {
                name: row.name.clone(),
                action: "created",
                id: Some(id),
                ..Row::default()
            });
            self.outcome.unverified.pop();
            self.bullet(resource, "created", &row.name, index + 1, total);
        }
        Ok(())
    }

    async fn patterns(&mut self) -> Result<(), Stop> {
        let resource = Resource::Patterns;
        let total = self.plan.patterns.len();
        if total > 0 {
            self.invocation
                .output
                .info(&format!("Restoring {} ({total})…", resource.label()));
        }
        for (index, row) in self.plan.patterns.iter().enumerate() {
            self.cursor = Some((1, index));
            if row.action != DependencyAction::Create {
                let Some(id) = row.existing.as_ref().and_then(id_of) else {
                    return Err(self.fail(format!(
                        "Destination data pattern has no identity: {}",
                        terminal_safe(&row.name)
                    )));
                };
                self.outcome.patterns.push(Row {
                    name: row.name.clone(),
                    action: row.action.done(),
                    id: Some(id),
                    ..Row::default()
                });
                self.bullet(resource, row.action.done(), &row.name, index + 1, total);
                continue;
            }
            self.checkpoint()?;
            let Some(body) = &row.body else {
                return Err(self.fail("Data pattern plan is incomplete".to_owned()));
            };
            let Ok(request) =
                m::DataPatternRequest::parse(body.clone(), scm::validation::Mode::Request)
            else {
                return Err(self
                    .fail("Restore stopped; verify destination state before retrying".to_owned()));
            };
            let patterns = self.dlp.data_patterns();
            let created =
                match writes::attempt(async || patterns.create(&request, None).await).await {
                    Ok(created) => created,
                    Err(error) => {
                        let failure = classify(&error);
                        return Err(self.create_failed(resource, &row.name, false, failure));
                    }
                };
            // A 2xx without a usable id: applied, the answer unusable (§16.12).
            let Some(id) = created_id(&created) else {
                return Err(self.create_failed(resource, &row.name, false, Failure::Unreadable));
            };
            self.outcome.created += 1;
            self.outcome
                .unverified
                .push((stage_key(resource), row.name.clone(), id.clone()));
            self.invocation.interrupt = Some(self.outcome.context());
            let read_back = match patterns.get(&id, None).await {
                Ok(record) => serde_json::to_value(&record).unwrap_or(Value::Null),
                Err(error) => return Err(self.read_back_failed(&error)),
            };
            let echo = pl::compare_echo(body, Some(&read_back));
            if !echo.matches()
                || id_of(&read_back).as_deref() != Some(id.as_str())
                || read_back.get("name").and_then(Value::as_str) != Some(row.name.as_str())
                || bk::retired_pattern(&read_back)
            {
                return Err(self.not_verified(resource, &row.name, &id));
            }
            if !echo.server_added.is_empty() {
                self.outcome
                    .server_added
                    .push((format!("data pattern {}", row.name), echo.server_added));
            }
            self.bindings.insert(
                row.source_id.clone(),
                Binding {
                    dictionary: false,
                    technique: read_back
                        .get("detection_config")
                        .and_then(|config| config.get("technique"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    id: id.clone(),
                    name: row.name.clone(),
                    version: read_back.get("version").filter(|v| !v.is_null()).cloned(),
                },
            );
            self.outcome.patterns.push(Row {
                name: row.name.clone(),
                action: "created",
                id: Some(id),
                ..Row::default()
            });
            self.outcome.unverified.pop();
            self.bullet(resource, "created", &row.name, index + 1, total);
        }
        Ok(())
    }

    async fn profiles(&mut self) -> Result<(), Stop> {
        let resource = Resource::Profiles;
        let total = self.plan.profiles.len();
        if total > 0 {
            self.invocation
                .output
                .info(&format!("Restoring {} ({total})…", resource.label()));
        }
        let cross_tenant = self.plan.cross_tenant();
        for (index, row) in self.plan.profiles.iter().enumerate() {
            self.cursor = Some((2, index));
            if row.action == ProfileAction::Skip {
                self.outcome.profiles.push(Row {
                    name: row.name.clone(),
                    action: "skipped",
                    id: row.existing.as_ref().and_then(id_of),
                    reason: row.reason.clone(),
                    renamed_from: None,
                });
                self.bullet(resource, "skipped", &row.name, index + 1, total);
                continue;
            }
            let body = match pl::profile_request(row, &self.bindings, cross_tenant, true) {
                Ok(Some(body)) => body,
                Ok(None) => {
                    return Err(self.fail(format!(
                        "Missing planned dependency binding: {}",
                        terminal_safe(&row.name)
                    )));
                }
                Err(message) => return Err(self.fail(stop_text(&terminal_safe(&message)))),
            };
            if row.action == ProfileAction::Verify {
                let echo = pl::compare_echo(&body, row.existing.as_ref());
                if !echo.matches() {
                    return Err(self.fail(format!(
                        "Destination data profile does not match restore plan: {}",
                        terminal_safe(&row.name)
                    )));
                }
                if !echo.server_added.is_empty() {
                    self.outcome
                        .server_added
                        .push((format!("data profile {}", row.name), echo.server_added));
                }
                self.outcome.profiles.push(Row {
                    name: row.name.clone(),
                    action: "verified",
                    id: row.existing.as_ref().and_then(id_of),
                    reason: None,
                    renamed_from: row.renamed_from.clone(),
                });
                self.bullet(resource, "verified", &row.name, index + 1, total);
                continue;
            }
            self.checkpoint()?;
            let profiles = self.dlp.data_profiles();
            let parse = |body: &Value| {
                m::AdvancedDataProfileRequest::parse(body.clone(), scm::validation::Mode::Request)
                    .ok()
            };
            let Some(request) = parse(&body) else {
                return Err(self
                    .fail("Restore stopped; verify destination state before retrying".to_owned()));
            };
            let mut write_body = body.clone();
            let mut final_name = row.name.clone();
            let created = match writes::attempt(async || profiles.create(&request, None).await)
                .await
            {
                Ok(created) => created,
                Err(error)
                    if self.plan.reconcile
                        && error.kind() == scm::ErrorKind::Http
                        && error.status() == Some(409)
                        && error.remote_outcome() == scm::RemoteOutcome::Rejected =>
                {
                    // An archived name (D177): one create under the deterministic suffix.
                    final_name = pl::suffixed_profile_name(
                        &row.name,
                        &pl::reconcile_suffix(&self.plan.source_tsg, &row.source_id),
                    );
                    write_body["name"] = json!(final_name);
                    let Some(renamed) = parse(&write_body) else {
                        return Err(self.fail(
                            "Restore stopped; verify destination state before retrying".to_owned(),
                        ));
                    };
                    self.checkpoint()?;
                    match writes::attempt(async || profiles.create(&renamed, None).await).await {
                        Ok(created) => created,
                        Err(error) => {
                            let failure = classify(&error);
                            return Err(self.create_failed(resource, &final_name, true, failure));
                        }
                    }
                }
                Err(error) => {
                    let failure = classify(&error);
                    return Err(self.create_failed(resource, &row.name, false, failure));
                }
            };
            // A 2xx without a usable id: applied, the answer unusable (§16.12).
            let Some(id) = created_id(&created) else {
                let renamed = final_name != row.name;
                return Err(self.create_failed(
                    resource,
                    &final_name,
                    renamed,
                    Failure::Unreadable,
                ));
            };
            self.outcome.created += 1;
            self.outcome
                .unverified
                .push((stage_key(resource), final_name.clone(), id.clone()));
            self.invocation.interrupt = Some(self.outcome.context());
            let read_back = match profiles.get(&id, None).await {
                Ok(record) => serde_json::to_value(&record).unwrap_or(Value::Null),
                Err(error) => return Err(self.read_back_failed(&error)),
            };
            let echo = pl::compare_echo(&write_body, Some(&read_back));
            if !echo.matches()
                || id_of(&read_back).as_deref() != Some(id.as_str())
                || read_back.get("name").and_then(Value::as_str) != Some(final_name.as_str())
                || bk::retired_profile(&read_back)
            {
                return Err(self.not_verified(resource, &final_name, &id));
            }
            if !echo.server_added.is_empty() {
                self.outcome
                    .server_added
                    .push((format!("data profile {final_name}"), echo.server_added));
            }
            let renamed_from = (final_name != row.name).then(|| row.name.clone());
            self.outcome.profiles.push(Row {
                name: final_name.clone(),
                action: "created",
                id: Some(id),
                reason: None,
                renamed_from,
            });
            self.outcome.unverified.pop();
            self.bullet(resource, "created", &final_name, index + 1, total);
        }
        Ok(())
    }

    /// Every planned item after the one that stopped the run (all of them when the
    /// recheck stopped it).
    fn mark_not_attempted(&mut self) {
        let after = |stage: u8, index: usize| match self.cursor {
            None => true,
            Some((at_stage, at_index)) => (stage, index) > (at_stage, at_index),
        };
        let mut rest = Vec::new();
        for (index, row) in self.plan.dictionaries.iter().enumerate() {
            if after(0, index) {
                rest.push(("dictionaries", row.name.clone()));
            }
        }
        for (index, row) in self.plan.patterns.iter().enumerate() {
            if after(1, index) {
                rest.push(("patterns", row.name.clone()));
            }
        }
        for (index, row) in self.plan.profiles.iter().enumerate() {
            if after(2, index) {
                rest.push(("profiles", row.name.clone()));
            }
        }
        self.outcome.not_attempted = rest;
    }
}

/// The non-empty string `id` of a record.
fn id_of(record: &Value) -> Option<String> {
    record
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
}

/// The `id` of a create's answer.
fn created_id<T: serde::Serialize>(answer: &T) -> Option<String> {
    id_of(&serde_json::to_value(answer).unwrap_or(Value::Null))
}

/// The recheck and the stages, in order; the first failure stops the run (TS). A
/// signal reports the run's context.
async fn execute(
    invocation: &mut Invocation,
    dlp: &DlpClient,
    plan: &RestorePlan,
    max_pages: u64,
) -> Result<Outcome, CliError> {
    let mut executor = Executor {
        invocation,
        dlp,
        plan,
        max_pages,
        outcome: Outcome::default(),
        bindings: pl::plan_bindings(plan),
        cursor: None,
    };
    executor.invocation.interrupt = Some(InterruptContext::NothingChanged);
    let mut stopped = executor.recheck().await;
    if stopped.is_ok() {
        stopped = executor.dictionaries().await;
    }
    if stopped.is_ok() {
        stopped = executor.patterns().await;
    }
    if stopped.is_ok() {
        stopped = executor.profiles().await;
    }
    match stopped {
        Ok(()) => executor.outcome.complete = true,
        Err(Stop::Interrupted) => {
            return Err(CliError::Interrupted(executor.outcome.context()));
        }
        Err(Stop::Failed) => executor.mark_not_attempted(),
    }
    executor.invocation.interrupt = Some(executor.outcome.context());
    Ok(executor.outcome)
}

// ---------------------------------------------------------------------------
// Restore output (TS `renderRestore`, TB§5.7, §5.10)
// ---------------------------------------------------------------------------

/// A two-column `Action │ Name` table, or `(none)`.
fn action_table(invocation: &Invocation, rows: &[(String, String)]) -> String {
    if rows.is_empty() {
        return "(none)".to_owned();
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|(action, name)| vec![action.clone(), shown(invocation, name)])
        .collect();
    table::table(&["Action", "Name"], &cells)
}

/// The blocks shared by the preview and the result.
struct Blocks<'a> {
    heading: &'static str,
    source: &'a str,
    destination: &'a str,
    sections: [Vec<(String, String)>; 3],
}

fn blocks_text(invocation: &Invocation, blocks: &Blocks<'_>, extra: Vec<String>) -> String {
    let mut out = vec![
        blocks.heading.to_owned(),
        format!(
            "Source TSG: {}\nDestination TSG: {}",
            terminal_safe(blocks.source),
            terminal_safe(blocks.destination)
        ),
    ];
    for (title, rows) in ["Dictionaries", "Data patterns", "Data profiles"]
        .iter()
        .zip(&blocks.sections)
    {
        out.push(format!("{title} ({})", rows.len()));
        out.push(action_table(invocation, rows));
    }
    out.extend(extra);
    out.join("\n\n")
}

fn unresolved_lines(invocation: &Invocation, plan: &RestorePlan) -> Vec<String> {
    if plan.unresolved.is_empty() {
        return Vec::new();
    }
    let mut lines = vec!["Unresolved references — dependent profiles skipped".to_owned()];
    for entry in &plan.unresolved {
        lines.push(format!(
            "{} {}: {}",
            entry.kind,
            shown(invocation, &entry.name),
            terminal_safe(&entry.reason)
        ));
    }
    lines
}

fn unresolved_json(invocation: &Invocation, plan: &RestorePlan, full: bool) -> OValue {
    OValue::Array(
        plan.unresolved
            .iter()
            .map(|entry| {
                let mut fields = vec![("kind".to_owned(), OValue::String(entry.kind.to_owned()))];
                if full {
                    fields.push((
                        "sourceId".to_owned(),
                        OValue::String(entry.source_id.clone()),
                    ));
                }
                fields.push((
                    "name".to_owned(),
                    OValue::String(raw(invocation, &entry.name)),
                ));
                fields.push(("reason".to_owned(), OValue::String(entry.reason.clone())));
                if full && !entry.candidates.is_empty() {
                    fields.push((
                        "candidates".to_owned(),
                        OValue::Array(
                            entry
                                .candidates
                                .iter()
                                .map(|name| OValue::String(raw(invocation, name)))
                                .collect(),
                        ),
                    ));
                }
                OValue::Object(fields)
            })
            .collect(),
    )
}

/// `--dry-run`: the plan (TS layouts), exit 0.
fn render_preview(
    invocation: &mut Invocation,
    format: Format,
    plan: &RestorePlan,
) -> Result<(), CliError> {
    let dictionaries: Vec<(String, String)> = plan
        .dictionaries
        .iter()
        .map(|row| (row.action.word().to_owned(), row.name.clone()))
        .collect();
    let patterns: Vec<(String, String)> = plan
        .patterns
        .iter()
        .map(|row| (row.action.word().to_owned(), row.name.clone()))
        .collect();
    let profiles: Vec<(String, String)> = plan
        .profiles
        .iter()
        .map(|row| (row.action.word().to_owned(), row.name.clone()))
        .collect();
    match format {
        Format::Json => {
            let rows = |items: Vec<OValue>| OValue::Array(items);
            let row = |name: &str, action: &str, reason: Option<&String>| {
                let mut fields = vec![
                    ("name".to_owned(), OValue::String(raw(invocation, name))),
                    ("action".to_owned(), OValue::String(action.to_owned())),
                ];
                if let Some(reason) = reason {
                    fields.push(("reason".to_owned(), OValue::String(reason.clone())));
                }
                OValue::Object(fields)
            };
            let doc = OValue::Array(vec![OValue::Object(vec![
                (
                    "sourceTsgId".into(),
                    OValue::String(plan.source_tsg.clone()),
                ),
                (
                    "destinationTsgId".into(),
                    OValue::String(plan.destination_tsg.clone()),
                ),
                ("dryRun".into(), OValue::Bool(true)),
                (
                    "dictionaries".into(),
                    rows(
                        plan.dictionaries
                            .iter()
                            .map(|r| row(&r.name, r.action.word(), None))
                            .collect(),
                    ),
                ),
                (
                    "patterns".into(),
                    rows(
                        plan.patterns
                            .iter()
                            .map(|r| row(&r.name, r.action.word(), None))
                            .collect(),
                    ),
                ),
                (
                    "profiles".into(),
                    rows(
                        plan.profiles
                            .iter()
                            .map(|r| row(&r.name, r.action.word(), r.reason.as_ref()))
                            .collect(),
                    ),
                ),
                (
                    "unresolved".into(),
                    unresolved_json(invocation, plan, false),
                ),
            ])]);
            invocation.output.json(&doc)
        }
        Format::Pretty | Format::Table => {
            let blocks = Blocks {
                heading: "Restore preview — no changes made",
                source: &plan.source_tsg,
                destination: &plan.destination_tsg,
                sections: [dictionaries, patterns, profiles],
            };
            let text = blocks_text(invocation, &blocks, unresolved_lines(invocation, plan));
            invocation.output.data_line(&text);
            Ok(())
        }
    }
}

/// The result of an execution (TS layouts plus the Rust-only blocks); exit 1 unless
/// complete, with `  ✗ <error>` on stderr.
fn render_result(
    invocation: &mut Invocation,
    format: Format,
    plan: &RestorePlan,
    outcome: &Outcome,
) -> Result<(), CliError> {
    let pairs = |rows: &[Row]| -> Vec<(String, String)> {
        rows.iter()
            .map(|row| (row.action.to_owned(), row.name.clone()))
            .collect()
    };
    match format {
        Format::Json => {
            let row = |row: &Row| {
                let mut fields = vec![
                    (
                        "name".to_owned(),
                        OValue::String(raw(invocation, &row.name)),
                    ),
                    ("action".to_owned(), OValue::String(row.action.to_owned())),
                ];
                if let Some(id) = &row.id {
                    fields.push(("id".to_owned(), OValue::String(id.clone())));
                }
                if let Some(reason) = &row.reason {
                    fields.push(("reason".to_owned(), OValue::String(reason.clone())));
                }
                if let Some(from) = &row.renamed_from {
                    fields.push((
                        "renamedFrom".to_owned(),
                        OValue::String(raw(invocation, from)),
                    ));
                }
                OValue::Object(fields)
            };
            let kind_name = |kind: &str, name: &str| {
                OValue::Object(vec![
                    ("kind".to_owned(), OValue::String(kind.to_owned())),
                    ("name".to_owned(), OValue::String(raw(invocation, name))),
                ])
            };
            let mut doc = vec![
                (
                    "sourceTsgId".to_owned(),
                    OValue::String(plan.source_tsg.clone()),
                ),
                (
                    "destinationTsgId".to_owned(),
                    OValue::String(plan.destination_tsg.clone()),
                ),
                ("complete".to_owned(), OValue::Bool(outcome.complete)),
                (
                    "dictionaries".to_owned(),
                    OValue::Array(outcome.dictionaries.iter().map(row).collect()),
                ),
                (
                    "patterns".to_owned(),
                    OValue::Array(outcome.patterns.iter().map(row).collect()),
                ),
                (
                    "profiles".to_owned(),
                    OValue::Array(outcome.profiles.iter().map(row).collect()),
                ),
                (
                    "serverAdded".to_owned(),
                    OValue::Array(
                        outcome
                            .server_added
                            .iter()
                            .map(|(resource, fields)| {
                                OValue::Object(vec![
                                    (
                                        "resource".to_owned(),
                                        OValue::String(raw(invocation, resource)),
                                    ),
                                    (
                                        "fields".to_owned(),
                                        OValue::Array(
                                            fields
                                                .iter()
                                                .map(|field| OValue::String(field.clone()))
                                                .collect(),
                                        ),
                                    ),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "unverifiedCreates".to_owned(),
                    OValue::Array(
                        outcome
                            .unverified
                            .iter()
                            .map(|(kind, name, id)| {
                                OValue::Object(vec![
                                    ("kind".to_owned(), OValue::String((*kind).to_owned())),
                                    ("name".to_owned(), OValue::String(raw(invocation, name))),
                                    ("id".to_owned(), OValue::String(id.clone())),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "unresolved".to_owned(),
                    unresolved_json(invocation, plan, true),
                ),
                (
                    "outcomeUnknown".to_owned(),
                    outcome
                        .outcome_unknown
                        .as_ref()
                        .map_or(OValue::Null, |(kind, name)| kind_name(kind, name)),
                ),
                (
                    "notAttempted".to_owned(),
                    OValue::Array(
                        outcome
                            .not_attempted
                            .iter()
                            .map(|(kind, name)| kind_name(kind, name))
                            .collect(),
                    ),
                ),
            ];
            if let Some(error) = &outcome.error {
                doc.push(("error".to_owned(), OValue::String(error.clone())));
            }
            invocation
                .output
                .json(&OValue::Array(vec![OValue::Object(doc)]))?;
        }
        Format::Pretty | Format::Table => {
            let mut extra = unresolved_lines(invocation, plan);
            if !outcome.unverified.is_empty() {
                extra.push("Created resources awaiting verification".to_owned());
                let cells: Vec<Vec<String>> = outcome
                    .unverified
                    .iter()
                    .map(|(kind, name, id)| {
                        vec![
                            (*kind).to_owned(),
                            shown(invocation, name),
                            terminal_safe(id).into_owned(),
                        ]
                    })
                    .collect();
                extra.push(table::table(&["Resource", "Name", "Created ID"], &cells));
            }
            let renamed: Vec<&Row> = outcome
                .profiles
                .iter()
                .filter(|row| row.renamed_from.is_some())
                .collect();
            if !renamed.is_empty() {
                extra.push("Renamed around archived-name collisions".to_owned());
                for row in renamed {
                    extra.push(format!(
                        "{} -> {}",
                        shown(invocation, row.renamed_from.as_deref().unwrap_or_default()),
                        shown(invocation, &row.name)
                    ));
                }
            }
            if !outcome.server_added.is_empty() {
                extra.push("Verified server-added fields (source omitted these)".to_owned());
                for (resource, fields) in &outcome.server_added {
                    extra.push(format!(
                        "{}: {} fields; use --output json for paths",
                        shown(invocation, resource),
                        fields.len()
                    ));
                }
            }
            if let Some((kind, name)) = &outcome.outcome_unknown {
                extra.push("Possibly created (outcome unknown)".to_owned());
                extra.push(table::table(
                    &["Resource", "Name"],
                    &[vec![(*kind).to_owned(), shown(invocation, name)]],
                ));
            }
            if !outcome.not_attempted.is_empty() {
                extra.push("Not attempted".to_owned());
                let cells: Vec<Vec<String>> = outcome
                    .not_attempted
                    .iter()
                    .map(|(kind, name)| vec![(*kind).to_owned(), shown(invocation, name)])
                    .collect();
                extra.push(table::table(&["Resource", "Name"], &cells));
            }
            if let Some(error) = &outcome.error {
                extra.push(format!("Error: {}", terminal_safe(error)));
            }
            let blocks = Blocks {
                heading: if outcome.complete {
                    "Restore complete"
                } else {
                    "Restore incomplete — completed writes remain"
                },
                source: &plan.source_tsg,
                destination: &plan.destination_tsg,
                sections: [
                    pairs(&outcome.dictionaries),
                    pairs(&outcome.patterns),
                    pairs(&outcome.profiles),
                ],
            };
            let text = blocks_text(invocation, &blocks, extra);
            invocation.output.data_line(&text);
        }
    }
    if outcome.complete {
        return Ok(());
    }
    let _ = invocation.output.commit();
    let error = outcome.error.as_deref().unwrap_or("Restore incomplete");
    let text = invocation
        .output
        .paint_err(Style::Red, &format!("✗ {}", terminal_safe(error)));
    invocation.output.write_stderr(&format!("  {text}\n"));
    Err(CliError::Reported(crate::error::EXIT_OPERATIONAL))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_keep_their_restore_texts_or_stop() {
        assert_eq!(
            stop_text("Destination dictionary changed after planning: x"),
            "Destination dictionary changed after planning: x"
        );
        assert_eq!(
            stop_text("network down"),
            "Restore stopped; verify destination state before retrying"
        );
        assert_eq!(
            http_text(Some(409)),
            "API request failed (HTTP 409); verify destination state before retrying"
        );
    }

    #[test]
    fn interrupt_contexts_count_the_creates() {
        let mut outcome = Outcome::default();
        assert_eq!(outcome.context(), InterruptContext::NothingChanged);
        // A 2xx create without a usable id (§16.12): never "nothing was changed".
        outcome.outcome_unknown = Some(("dictionaries", "D".to_owned()));
        assert_eq!(
            outcome.context().text(),
            "0 resource(s) created; the dictionary D may also have been created (outcome unknown); run the restore again to resume"
        );
        outcome.created = 2;
        outcome.outcome_unknown = Some(("patterns", "P".to_owned()));
        assert_eq!(
            outcome.context().text(),
            "2 resource(s) created; the data pattern P may also have been created (outcome unknown); run the restore again to resume"
        );
    }
}
