//! `runtime profiles restore <file>` (DESIGN §18.16, D216, D217, D218).
//!
//! Reads only an airs runtime profiles backup (a TypeScript backup is refused),
//! strictly and before the tenant; checks it against the selected tenant (another TSG
//! needs `--allow-other-tenant`, `--expect-tsg` must match) before any request; plans
//! every profile and topic against the destination inventories (an absent collection is
//! an error, D218) with the TypeScript rules; confirms under D81; rechecks; then sends
//! each create or update once (`writes::attempt`) and stops at the first failure, naming
//! a write whose outcome is unknown. A re-run never duplicates: a created topic is reused
//! when identical and a profile that exists is refused or verified.

use std::ffi::OsString;

use super::Invocation;
use super::profile_backup::{self as backup, DEBUG_REFUSED, WalkError, within};
use crate::cli::ProfileRestoreArgs;
use crate::clients::{ManagementClients, Planes, SINGLE_REQUEST_BUDGET, WALK_BUDGET};
use crate::dlp::backup::{Resource, Step as SweepStep, Sweep};
use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::output::{Format, terminal_safe};
use crate::render::style::Style;
use crate::render::table;
use crate::runtime::transfer::plan::{
    self as pl, Action, Collection, Conflict, DlpMapping, MissingDlp, Options, Refusal,
    RestorePlan, ServerDefaults,
};
use crate::runtime::transfer::{self, Kind, ReadFailure};
use crate::store::PROGRAM;
use crate::writes::{self, Failure};
use scm::airs::management::models as m;
use serde_json::Value;

/// A validated `runtime profiles restore <file>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreRun {
    pub file: OsString,
    pub dry_run: bool,
    pub expect_tsg: Option<String>,
    pub force: bool,
    pub allow_other_tenant: bool,
    pub max_pages: u64,
    pub options: Options,
    pub format: Option<Format>,
}

/// `--dlp-map` (TS `dlpMap`): split at the first `=`, neither side empty; sources unique.
fn dlp_map(values: &[String]) -> Result<Vec<(String, String)>, CliError> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for value in values {
        match value.find('=') {
            Some(at) if at > 0 && at + 1 < value.len() => {
                entries.push((value[..at].to_owned(), value[at + 1..].to_owned()));
            }
            _ => {
                return Err(CliError::usage(
                    "--dlp-map requires source-name=destination-name",
                ));
            }
        }
    }
    let mut sources: Vec<&str> = entries.iter().map(|(source, _)| source.as_str()).collect();
    sources.sort_unstable();
    sources.dedup();
    if sources.len() != entries.len() {
        return Err(CliError::usage("Duplicate source names in --dlp-map"));
    }
    Ok(entries)
}

/// The argument checks of §18.16, in order (exit 2, before the file and the tenant).
pub fn plan(
    args: &ProfileRestoreArgs,
    format: Option<Format>,
    debug: bool,
) -> Result<RestoreRun, CliError> {
    if debug {
        return Err(CliError::usage(DEBUG_REFUSED));
    }
    let max_pages = backup::max_pages(args.max_pages.as_deref())?;
    let conflict = match args.on_conflict.as_deref() {
        None => Conflict::Error,
        Some(text) => Conflict::parse(text).ok_or_else(|| {
            CliError::usage("--on-conflict must be error, verify, skip or update")
        })?,
    };
    let missing_dlp = match args.on_missing_dlp.as_deref() {
        None | Some("error") => MissingDlp::Error,
        Some("basic") => MissingDlp::Basic,
        Some(_) => return Err(CliError::usage("--on-missing-dlp must be error or basic")),
    };
    if args.force && args.expect_tsg.is_none() {
        return Err(CliError::usage(
            "--force requires --expect-tsg <destination-tsg>",
        ));
    }
    if args.dry_run && args.force {
        return Err(CliError::usage("--dry-run cannot be combined with --force"));
    }
    let dlp_map = dlp_map(&args.dlp_map)?;
    let prefix = args.name_prefix.clone().unwrap_or_default();
    if prefix.encode_utf16().count() > 64
        || prefix.chars().any(|c| (c as u32) < 32 || c as u32 == 127)
    {
        return Err(CliError::usage("Invalid --name-prefix"));
    }
    if let Some(tsg) = &args.expect_tsg
        && !transfer::is_tsg(tsg)
    {
        return Err(CliError::usage(
            "--expect-tsg must be a TSG ID (1-32 digits)",
        ));
    }
    if !args.dry_run {
        super::runtime_write::gate(args.force, "restore profiles")?;
    }
    Ok(RestoreRun {
        file: args.file.clone(),
        dry_run: args.dry_run,
        expect_tsg: args.expect_tsg.clone(),
        force: args.force,
        allow_other_tenant: args.allow_other_tenant,
        max_pages,
        options: Options {
            prefix,
            conflict,
            dlp_map,
            missing_dlp,
        },
        format,
    })
}

/// Whether a stored record matches the SDK response schema of its kind (no defaults).
fn valid_record(kind: Kind, record: &OValue) -> bool {
    let wire = serde_json::to_value(record).unwrap_or(Value::Null);
    let mode = scm::validation::Mode::ResponseWithoutDefaults;
    match kind {
        Kind::Profile => m::SecurityProfile::parse(wire, mode).is_ok(),
        Kind::Topic => m::CustomTopic::parse(wire, mode).is_ok(),
    }
}

/// Reads and checks the backup file before the tenant (§18.16 "The file").
fn read_backup(file: &std::ffi::OsStr) -> Result<transfer::Backup, CliError> {
    let shown = terminal_safe(&crate::files::shown(file)).into_owned();
    let text = crate::files::read_text(file, transfer::MAX_BACKUP_BYTES as u64)?;
    transfer::parse(&text, valid_record).map_err(|failure| {
        CliError::operational(match failure {
            ReadFailure::Malformed => {
                format!("Invalid runtime profiles backup {shown}: malformed JSON")
            }
            ReadFailure::TypeScript => format!(
                "{shown} is a TypeScript airs-cli backup; {PROGRAM} cannot restore it. Restore it with the TypeScript airs-cli, or back the profiles up again with '{PROGRAM} runtime profiles backup'."
            ),
            ReadFailure::Newer => format!(
                "{shown} was written by a newer version of {PROGRAM}; upgrade {PROGRAM} to restore it"
            ),
            ReadFailure::Invalid(reason) => {
                format!("Invalid runtime profiles backup {shown}: {reason}")
            }
        })
    })
}

/// A name for printing: `[withheld]` when it carries a secret, terminal-safe.
fn shown(invocation: &Invocation, name: &str) -> String {
    crate::runtime::shown(name, &invocation.secrets)
}

/// A name for a JSON document: `[withheld]` when it carries a secret.
fn raw(invocation: &Invocation, name: &str) -> String {
    if invocation.secrets.carried_by(name) {
        crate::error::WITHHELD.to_owned()
    } else {
        name.to_owned()
    }
}

/// The D218 text of an absent destination collection: `nothing was changed` before the
/// first write, a resume hint after it (choice 57).
fn absent(collection: Collection, written: bool) -> String {
    if written {
        format!(
            "Destination inventory of {} was not returned; verify destination state before retrying",
            collection.label()
        )
    } else {
        format!(
            "Destination inventory of {} was not returned; nothing was changed",
            collection.label()
        )
    }
}

/// The destination's DLP data-profile catalog (the M6b inventory sweep, choice 26).
async fn catalog(clients: &ManagementClients, max_pages: u64) -> Result<Vec<Value>, WalkError> {
    let Some(dlp) = &clients.dlp else {
        return Err(WalkError::Rule(Refusal::Withheld(STOPPED.to_owned())));
    };
    let options = crate::runtime::options(WALK_BUDGET)
        .map_err(|error| WalkError::Rule(Refusal::Withheld(error.message())))?;
    let mut sweep = Sweep::new(Resource::Profiles);
    for page in 0..max_pages {
        let mut query =
            scm::dlp::SpringListParams::new().sort(vec![crate::dlp::DEFAULT_SORT.to_owned()]);
        query.page = Some(page);
        query.size = Some(crate::dlp::backup::PAGE_SIZE);
        let answer = dlp
            .data_profiles()
            .list(&query, Some(&options))
            .await
            .map_err(WalkError::Sdk)?;
        let answer = crate::json::page_value(&answer).map_err(WalkError::Sdk)?;
        // Every sweep message is the restore's own DLP inventory text (TS `DLP inventory…`).
        let step = sweep
            .accept(page, &answer)
            .map_err(|message| WalkError::Rule(Refusal::Stated(message)))?;
        if step == SweepStep::Done {
            return Ok(sweep
                .into_items()
                .iter()
                .map(crate::json::value_of)
                .collect());
        }
    }
    Err(WalkError::Rule(Refusal::Stated(sweep.incomplete())))
}

/// The latest destination profiles, checked for their tenant.
async fn destination_profiles(
    clients: &ManagementClients,
    plan_tsg: &str,
    max_pages: u64,
    written: bool,
) -> Result<Vec<Value>, WalkError> {
    let items = backup::inventory(
        clients,
        Collection::Profiles,
        max_pages,
        absent(Collection::Profiles, written),
    )
    .await?;
    let profiles = pl::inventory_profiles(&items).map_err(WalkError::Rule)?;
    pl::assert_tenant(&profiles, plan_tsg).map_err(WalkError::Rule)?;
    Ok(profiles)
}

async fn destination_topics(
    clients: &ManagementClients,
    max_pages: u64,
    written: bool,
) -> Result<Vec<Value>, WalkError> {
    let items = backup::inventory(
        clients,
        Collection::Topics,
        max_pages,
        absent(Collection::Topics, written),
    )
    .await?;
    Ok(items.iter().map(crate::json::value_of).collect())
}

/// `runtime profiles restore <file>` (§18.16).
pub async fn run(invocation: &mut Invocation, run: &RestoreRun) -> Result<(), CliError> {
    let shown_file = terminal_safe(&crate::files::shown(&run.file)).into_owned();
    let file = read_backup(&run.file)?;
    let nothing = InterruptContext::NothingChanged;
    // The tenant checks come after the credential check and before the client (§18.3,
    // §18.16): an inadmissible endpoint does not hide a TSG refusal.
    let tenant = invocation.runtime_tenant().map_err(within(&nothing))?;
    if file.tsg_id != tenant.tsg() && !run.allow_other_tenant {
        return Err(CliError::operational(format!(
            "{shown_file} was exported from TSG {}; the selected tenant uses TSG {}. Pass --allow-other-tenant to restore it here.",
            terminal_safe(&file.tsg_id),
            terminal_safe(tenant.tsg())
        )));
    }
    if run
        .expect_tsg
        .as_deref()
        .is_some_and(|expected| expected != tenant.tsg())
    {
        return Err(CliError::operational(
            "--expect-tsg does not match the selected destination tenant; no API request was made",
        ));
    }
    let connected = invocation
        .connect_tenant(
            &tenant,
            Planes {
                dlp: true,
                ..Planes::default()
            },
        )
        .map_err(within(&nothing))?;
    let format = connected.format(run.format);
    let clients = &connected.clients;
    let refused = |message: String| CliError::operational(terminal_safe(&message).into_owned());
    let profiles: Vec<Value> = file
        .profiles
        .iter()
        .map(|entry| crate::json::value_of(&entry.record))
        .collect();
    let topics: Vec<Value> = file
        .topics
        .iter()
        .map(|entry| crate::json::value_of(&entry.record))
        .collect();
    let prepared =
        pl::prepare(&profiles, &file.tsg_id, tenant.tsg(), &run.options).map_err(refused)?;
    let deadline = crate::runtime::options(WALK_BUDGET)?;
    clients
        .authenticate(Some(&deadline), WALK_BUDGET)
        .await
        .map_err(within(&nothing))?;
    let read = |error: WalkError, invocation: &Invocation| error.into_cli(invocation);
    let existing = destination_profiles(clients, tenant.tsg(), run.max_pages, false)
        .await
        .map_err(|error| read(error, invocation))
        .map_err(within(&nothing))?;
    let plans = pl::plan_profiles(&prepared, &existing, &run.options).map_err(refused)?;
    let refs = pl::changing_refs(&plans).map_err(refused)?;
    let target_topics = if refs.is_empty() {
        Vec::new()
    } else {
        destination_topics(clients, run.max_pages, false)
            .await
            .map_err(|error| read(error, invocation))
            .map_err(within(&nothing))?
    };
    let topic_plans =
        pl::plan_topics(&refs, &topics, &target_topics, &run.options.prefix).map_err(refused)?;
    let dlp = pl::dlp_names(&plans, prepared.cross_tenant, &run.options).map_err(refused)?;
    let dlp_catalog = if dlp.needs_catalog(prepared.cross_tenant, &run.options) {
        catalog(clients, run.max_pages)
            .await
            .map_err(|error| read(error, invocation))
            .map_err(within(&nothing))?
    } else {
        Vec::new()
    };
    let plan = pl::finish(
        pl::Finish {
            source_tsg: &file.tsg_id,
            destination_tsg: tenant.tsg(),
            cross_tenant: prepared.cross_tenant,
            profiles: plans,
            topics: topic_plans,
            dlp,
            catalog: &dlp_catalog,
        },
        &run.options,
    )
    .map_err(refused)?;
    for fallback in &plan.dlp_fallbacks {
        let names: Vec<String> = fallback
            .replaced
            .iter()
            .map(|name| shown(invocation, name))
            .collect();
        invocation.output.warning(&format!(
            "⚠ DLP protection change: {} will use Basic detection instead of {}. Custom rules are not preserved.",
            shown(invocation, &fallback.profile),
            names.join(", ")
        ));
    }
    if run.dry_run {
        return render_preview(invocation, format, &plan);
    }
    let changing = plan.changing();
    if changing > 0 && !run.force {
        let message = format!(
            "Restore {changing} profiles from TSG {} to TSG {} ({} updates, {} Basic DLP fallbacks losing custom detection)?",
            plan.source_tsg,
            plan.destination_tsg,
            plan.updates(),
            plan.dlp_fallbacks.len()
        );
        if !super::runtime_write::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let outcome = execute(invocation, clients, &plan, run.max_pages).await?;
    render_result(invocation, format, &plan, &outcome)
}

// ---------------------------------------------------------------------------
// Execution (TS `restoreRuntimeProfiles`, D217)
// ---------------------------------------------------------------------------

/// The kind of a resource in the Rust-only rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ItemKind {
    Topic,
    Profile,
}

impl ItemKind {
    fn key(self) -> &'static str {
        match self {
            Self::Topic => "topic",
            Self::Profile => "profile",
        }
    }

    fn words(self) -> &'static str {
        match self {
            Self::Topic => "custom topic",
            Self::Profile => "security profile",
        }
    }
}

/// One result row.
#[derive(Clone, Debug)]
struct Row {
    name: String,
    action: &'static str,
    id: Option<String>,
}

/// What an execution did.
#[derive(Debug, Default)]
struct Outcome {
    complete: bool,
    topics: Vec<Row>,
    profiles: Vec<Row>,
    server_defaults: Vec<ServerDefaults>,
    /// `(kind, name, action)` of a write that may have been applied (Rust-only).
    outcome_unknown: Option<(ItemKind, String, &'static str)>,
    /// `(kind, name)` of every planned item after the failure (Rust-only).
    not_attempted: Vec<(ItemKind, String)>,
    error: Option<String>,
    written_topics: usize,
    written_profiles: usize,
}

impl Outcome {
    fn written(&self) -> bool {
        self.written_topics + self.written_profiles > 0 || self.outcome_unknown.is_some()
    }

    /// The interrupt context (§18.16 "Interruption").
    fn context(&self) -> InterruptContext {
        if !self.written() {
            return InterruptContext::NothingChanged;
        }
        let mut text = format!(
            "{} topic(s) and {} profile(s) written",
            self.written_topics, self.written_profiles
        );
        if let Some((kind, name, action)) = &self.outcome_unknown {
            text.push_str(&format!(
                "; the {} {} may also have been {action} (outcome unknown)",
                kind.words(),
                terminal_safe(name)
            ));
        }
        text.push_str("; run the restore again with --on-conflict verify to resume");
        InterruptContext::Context(text)
    }
}

/// TS `result.error` of a local failure whose text the result does not state.
const STOPPED: &str = "Restore stopped; verify destination state before retrying";

/// TS `result.error` of a refused rule: its own text when the refusal is stated, else the
/// generic stop.
fn stop_text(refusal: &Refusal) -> String {
    refusal.stated().unwrap_or(STOPPED).to_owned()
}

fn http_text(status: u16) -> String {
    format!("API request failed (HTTP {status}); verify destination state before retrying")
}

/// Why a step stopped.
enum Stop {
    Failed,
    Interrupted,
}

struct Executor<'a> {
    invocation: &'a mut Invocation,
    clients: &'a ManagementClients,
    plan: &'a RestorePlan,
    max_pages: u64,
    outcome: Outcome,
    /// `(stage, index)` of the item being processed (`None` before the first).
    cursor: Option<(u8, usize)>,
}

impl Executor<'_> {
    fn fail(&mut self, message: String) -> Stop {
        self.outcome.error = Some(terminal_safe(&message).into_owned());
        Stop::Failed
    }

    fn checkpoint(&mut self) -> Result<(), Stop> {
        self.invocation.interrupt = Some(self.outcome.context());
        if self.invocation.output.pending_signal().is_some() {
            return Err(Stop::Interrupted);
        }
        Ok(())
    }

    /// A failed inventory read during execution.
    fn read_failed(&mut self, error: WalkError) -> Stop {
        match error {
            WalkError::Sdk(error) if error.kind() == scm::ErrorKind::Cancelled => Stop::Interrupted,
            WalkError::Sdk(error) => match error.status() {
                Some(status) if error.kind() == scm::ErrorKind::Http => {
                    self.fail(http_text(status))
                }
                _ => self.fail(STOPPED.to_owned()),
            },
            WalkError::Rule(refusal) => self.fail(stop_text(&refusal)),
        }
    }

    /// The failure of a create or update attempt (D217).
    fn write_failed(
        &mut self,
        kind: ItemKind,
        name: &str,
        action: &'static str,
        failure: Failure,
    ) -> Stop {
        let hint = "run the restore again with --on-conflict verify to check it";
        match failure {
            Failure::Interrupted { sent } => {
                if sent {
                    self.outcome.outcome_unknown = Some((kind, name.to_owned(), action));
                }
                Stop::Interrupted
            }
            Failure::Rejected(Some(status)) => self.fail(http_text(status)),
            Failure::Rejected(None) | Failure::Local => self.fail(STOPPED.to_owned()),
            Failure::Unknown => {
                self.outcome.outcome_unknown = Some((kind, name.to_owned(), action));
                self.fail(format!(
                    "Outcome unknown: the {} {name} may have been {action}; {hint}",
                    kind.words()
                ))
            }
            Failure::Unreadable => {
                self.outcome.outcome_unknown = Some((kind, name.to_owned(), action));
                self.fail(format!(
                    "Outcome: the {} {name} was {action}, but the response could not be read; {hint}",
                    kind.words()
                ))
            }
        }
    }

    /// The recheck before the first write (TS): the destination profiles, the DLP
    /// bindings and every non-skipped profile's planned state.
    async fn recheck(&mut self) -> Result<(), Stop> {
        let latest = match destination_profiles(
            self.clients,
            &self.plan.destination_tsg,
            self.max_pages,
            false,
        )
        .await
        {
            Ok(latest) => latest,
            Err(error) => return Err(self.read_failed(error)),
        };
        if !self.plan.dlp_mappings.is_empty() {
            let catalog = match catalog(self.clients, self.max_pages).await {
                Ok(catalog) => catalog,
                Err(error) => return Err(self.read_failed(error)),
            };
            for mapping in &self.plan.dlp_mappings {
                if !mapping_unchanged(&catalog, mapping) {
                    return Err(self.fail(format!(
                        "Destination DLP profile changed after planning: {}",
                        mapping.destination
                    )));
                }
            }
        }
        for item in &self.plan.profiles {
            if item.action == Action::Skip {
                continue;
            }
            if changed(&latest, item) {
                return Err(self.fail(format!(
                    "Destination profile changed after planning: {}",
                    item.name
                )));
            }
        }
        Ok(())
    }

    async fn topics(&mut self) -> Result<Vec<(String, Value)>, Stop> {
        let mut mapped: Vec<(String, Value)> = Vec::new();
        for (index, item) in self.plan.topics.iter().enumerate() {
            self.cursor = Some((0, index));
            let inventory = match destination_topics(
                self.clients,
                self.max_pages,
                self.outcome.written(),
            )
            .await
            {
                Ok(inventory) => inventory,
                Err(error) => return Err(self.read_failed(error)),
            };
            let topic = match &item.existing {
                Some(existing) => {
                    let current = inventory.iter().find(|topic| {
                        policy_eq(topic.get("topic_id"), existing.get("topic_id"))
                            && policy_eq(topic.get("revision"), existing.get("revision"))
                    });
                    if !current.is_some_and(|current| pl::same_topic(current, &item.source)) {
                        return Err(self.fail(format!(
                            "Destination topic changed after planning: {}",
                            item.name
                        )));
                    }
                    existing.clone()
                }
                None => {
                    if inventory
                        .iter()
                        .any(|topic| pl::text(topic, "topic_name") == Some(item.name.as_str()))
                    {
                        return Err(self.fail(format!(
                            "Destination topic changed after planning: {}",
                            item.name
                        )));
                    }
                    self.checkpoint()?;
                    let body = pl::topic_body(&item.name, &item.source);
                    let Ok(request) =
                        m::CreateCustomTopicRequest::parse(body, scm::validation::Mode::Request)
                    else {
                        return Err(self.fail(STOPPED.to_owned()));
                    };
                    let client = self.clients.management.topics();
                    let created = writes::attempt(async || {
                        let options = crate::runtime::request_options(SINGLE_REQUEST_BUDGET)?;
                        client.create(&request, Some(&options)).await
                    })
                    .await;
                    match created {
                        Ok(created) => {
                            self.outcome.written_topics += 1;
                            self.invocation.interrupt = Some(self.outcome.context());
                            serde_json::to_value(&created).unwrap_or(Value::Null)
                        }
                        Err(error) => {
                            let failure = writes::classify(&error);
                            return Err(self.write_failed(
                                ItemKind::Topic,
                                &item.name,
                                "created",
                                failure,
                            ));
                        }
                    }
                }
            };
            let verified = pl::text(&topic, "topic_id").is_some_and(|id| !id.is_empty())
                && pl::text(&topic, "topic_name") == Some(item.name.as_str())
                && topic
                    .get("revision")
                    .and_then(Value::as_f64)
                    .is_some_and(|revision| {
                        revision.fract() == 0.0 && revision.abs() <= 9_007_199_254_740_991.0
                    })
                && pl::same_topic(&topic, &item.source);
            if !verified {
                // A created topic exists whatever its answer says: its `created` row is
                // kept, so the result names it (as a profile's, choice 64; choice 68).
                if item.existing.is_none() {
                    self.outcome.topics.push(Row {
                        name: item.name.clone(),
                        action: "created",
                        id: pl::text(&topic, "topic_id")
                            .filter(|id| !id.is_empty())
                            .map(str::to_owned),
                    });
                }
                return Err(self.fail(format!("Topic response did not verify: {}", item.name)));
            }
            self.outcome.topics.push(Row {
                name: item.name.clone(),
                action: if item.existing.is_some() {
                    "reused"
                } else {
                    "created"
                },
                id: pl::text(&topic, "topic_id").map(str::to_owned),
            });
            mapped.push((item.key.clone(), topic));
        }
        Ok(mapped)
    }

    async fn profiles(&mut self, topics: &[(String, Value)]) -> Result<(), Stop> {
        for (index, item) in self.plan.profiles.iter().enumerate() {
            self.cursor = Some((1, index));
            if item.action == Action::Skip {
                self.outcome.profiles.push(Row {
                    name: item.name.clone(),
                    action: "skipped",
                    id: item
                        .existing
                        .as_ref()
                        .and_then(|existing| pl::text(existing, "profile_id"))
                        .map(str::to_owned),
                });
                continue;
            }
            let policy = match pl::mapped_policy(item, &self.plan.dlp_mappings, topics) {
                Ok(policy) => policy,
                Err(refusal) => return Err(self.fail(stop_text(&refusal))),
            };
            let body = pl::profile_body(&item.name, &item.source, &policy);
            let Ok(request) =
                m::CreateSecurityProfileRequest::parse(body, scm::validation::Mode::Request)
            else {
                return Err(self.fail(STOPPED.to_owned()));
            };
            let inventory = match destination_profiles(
                self.clients,
                &self.plan.destination_tsg,
                self.max_pages,
                self.outcome.written(),
            )
            .await
            {
                Ok(inventory) => inventory,
                Err(error) => return Err(self.read_failed(error)),
            };
            if changed(&inventory, item) {
                return Err(self.fail(format!(
                    "Destination profile changed after planning: {}",
                    item.name
                )));
            }
            let current = inventory
                .iter()
                .find(|profile| pl::text(profile, "profile_name") == Some(item.name.as_str()));
            if item.action == Action::Verify {
                let comparison = crate::runtime::transfer::policy::compare(
                    Some(&policy),
                    current.and_then(|current| current.get("policy")),
                );
                if !comparison.matches {
                    return Err(
                        self.fail(format!("Restored profile did not verify: {}", item.name))
                    );
                }
                self.outcome.profiles.push(Row {
                    name: item.name.clone(),
                    action: "verified",
                    id: current
                        .and_then(|current| pl::text(current, "profile_id"))
                        .map(str::to_owned),
                });
                if !comparison.server_defaults.is_empty() {
                    self.outcome.server_defaults.push(ServerDefaults {
                        profile: item.name.clone(),
                        fields: comparison.server_defaults,
                    });
                }
                continue;
            }
            self.checkpoint()?;
            let (done, update_id) = match item.action {
                Action::Update => (
                    "updated",
                    item.existing
                        .as_ref()
                        .and_then(|existing| pl::text(existing, "profile_id"))
                        .map(str::to_owned),
                ),
                _ => ("created", None),
            };
            let client = self.clients.management.profiles();
            let answer = writes::attempt(async || {
                let options = crate::runtime::request_options(SINGLE_REQUEST_BUDGET)?;
                match &update_id {
                    Some(id) => client.update(id, &request, Some(&options)).await,
                    None => client.create(&request, Some(&options)).await,
                }
            })
            .await;
            let response = match answer {
                Ok(response) => serde_json::to_value(&response).unwrap_or(Value::Null),
                Err(error) => {
                    let failure = writes::classify(&error);
                    return Err(self.write_failed(ItemKind::Profile, &item.name, done, failure));
                }
            };
            self.outcome.written_profiles += 1;
            self.invocation.interrupt = Some(self.outcome.context());
            let response_id = pl::text(&response, "profile_id").map(str::to_owned);
            self.outcome.profiles.push(Row {
                name: item.name.clone(),
                action: done,
                id: response_id.clone(),
            });
            let after = match destination_profiles(
                self.clients,
                &self.plan.destination_tsg,
                self.max_pages,
                true,
            )
            .await
            {
                Ok(after) => after,
                Err(error) => return Err(self.read_failed(error)),
            };
            let verified = after
                .iter()
                .find(|profile| pl::text(profile, "profile_name") == Some(item.name.as_str()));
            let comparison = crate::runtime::transfer::policy::compare(
                Some(&policy),
                verified.and_then(|verified| verified.get("policy")),
            );
            let verified_id = verified
                .and_then(|verified| pl::text(verified, "profile_id"))
                .filter(|id| !id.is_empty());
            let active_differs = item.source.get("active").is_some_and(Value::is_boolean)
                && !policy_eq(
                    verified.and_then(|verified| verified.get("active")),
                    item.source.get("active"),
                );
            if verified_id.is_none()
                || response_id
                    .as_deref()
                    .is_some_and(|id| Some(id) != verified_id)
                || active_differs
                || !comparison.matches
            {
                return Err(self.fail(format!("Restored profile did not verify: {}", item.name)));
            }
            if !comparison.server_defaults.is_empty() {
                self.outcome.server_defaults.push(ServerDefaults {
                    profile: item.name.clone(),
                    fields: comparison.server_defaults,
                });
            }
        }
        Ok(())
    }

    /// Every planned item after the one that stopped the run (all of them when the
    /// recheck stopped it).
    fn mark_not_attempted(&mut self) {
        let after = |stage: u8, index: usize| match self.cursor {
            None => true,
            Some(cursor) => (stage, index) > cursor,
        };
        let mut rest = Vec::new();
        for (index, item) in self.plan.topics.iter().enumerate() {
            if after(0, index) {
                rest.push((ItemKind::Topic, item.name.clone()));
            }
        }
        for (index, item) in self.plan.profiles.iter().enumerate() {
            if after(1, index) {
                rest.push((ItemKind::Profile, item.name.clone()));
            }
        }
        self.outcome.not_attempted = rest;
    }
}

/// `===` of two optional JSON scalars.
fn policy_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    crate::runtime::transfer::policy::strict_eq(a, b)
}

/// TS: a planned update or verify must find its profile `unchanged`, a create none.
fn changed(inventory: &[Value], item: &pl::ProfilePlan) -> bool {
    let current = inventory
        .iter()
        .find(|profile| pl::text(profile, "profile_name") == Some(item.name.as_str()));
    match &item.existing {
        Some(existing) => !pl::unchanged(current, existing),
        None => current.is_some(),
    }
}

/// TS recheck of one DLP binding: exactly one active entry with the same id and version.
fn mapping_unchanged(catalog: &[Value], mapping: &DlpMapping) -> bool {
    let matches = pl::catalog_matches(catalog, &mapping.destination);
    let [only] = matches.as_slice() else {
        return false;
    };
    let id_same = match only.get("id") {
        Some(Value::String(id)) => *id == mapping.id,
        Some(Value::Number(number)) => {
            number.as_f64().map(crate::render::js_number).as_deref() == Some(mapping.id.as_str())
        }
        _ => false,
    };
    let version = only.get("version").filter(|value| !value.is_null());
    id_same && policy_eq(version, mapping.version.as_ref())
}

/// The recheck and the writes in order; the first failure stops the run (TS). A signal
/// reports the run's context.
async fn execute(
    invocation: &mut Invocation,
    clients: &ManagementClients,
    plan: &RestorePlan,
    max_pages: u64,
) -> Result<Outcome, CliError> {
    let mut executor = Executor {
        invocation,
        clients,
        plan,
        max_pages,
        outcome: Outcome::default(),
        cursor: None,
    };
    executor.invocation.interrupt = Some(InterruptContext::NothingChanged);
    let mut stopped = executor.recheck().await;
    let mut topics = Vec::new();
    if stopped.is_ok() {
        match executor.topics().await {
            Ok(mapped) => topics = mapped,
            Err(stop) => stopped = Err(stop),
        }
    }
    if stopped.is_ok() {
        stopped = executor.profiles(&topics).await;
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
// Output (TS `renderRestore`, TR§7.4, §7.7)
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

/// The blocks shared by the preview and the result (TS `renderRestore`).
#[allow(clippy::too_many_arguments)]
fn blocks(
    invocation: &Invocation,
    heading: &str,
    plan: &RestorePlan,
    profiles: &[(String, String)],
    topics: &[(String, String)],
    mappings: bool,
    defaults: &[ServerDefaults],
    extra: Vec<String>,
) -> String {
    let mut out = vec![
        heading.to_owned(),
        format!(
            "Source TSG: {}\nDestination TSG: {}",
            terminal_safe(&plan.source_tsg),
            terminal_safe(&plan.destination_tsg)
        ),
        format!("Profiles ({})", profiles.len()),
        action_table(invocation, profiles),
        format!("Topics ({})", topics.len()),
        action_table(invocation, topics),
    ];
    if mappings && !plan.dlp_mappings.is_empty() {
        out.push("DLP mappings".to_owned());
        let cells: Vec<Vec<String>> = plan
            .dlp_mappings
            .iter()
            .map(|mapping| {
                vec![
                    shown(invocation, &mapping.source),
                    shown(invocation, &mapping.destination),
                ]
            })
            .collect();
        out.push(table::table(&["Source", "Destination"], &cells));
    }
    if !plan.dlp_fallbacks.is_empty() {
        out.push("Basic DLP fallbacks — custom protection lost".to_owned());
        for fallback in &plan.dlp_fallbacks {
            let names: Vec<String> = fallback
                .replaced
                .iter()
                .map(|name| shown(invocation, name))
                .collect();
            out.push(format!(
                "{}: {}",
                shown(invocation, &fallback.profile),
                names.join(", ")
            ));
        }
    }
    if !defaults.is_empty() {
        out.push("Verified server-added defaults (source omitted these fields)".to_owned());
        for item in defaults {
            out.push(format!(
                "{}: {} fields; use --output json for paths",
                shown(invocation, &item.profile),
                item.fields.len()
            ));
        }
    }
    out.extend(extra);
    out.join("\n\n")
}

fn strings(invocation: &Invocation, items: &[String]) -> OValue {
    OValue::Array(
        items
            .iter()
            .map(|item| OValue::String(raw(invocation, item)))
            .collect(),
    )
}

fn fallbacks_json(invocation: &Invocation, plan: &RestorePlan) -> OValue {
    OValue::Array(
        plan.dlp_fallbacks
            .iter()
            .map(|fallback| {
                OValue::Object(vec![
                    (
                        "profile".into(),
                        OValue::String(raw(invocation, &fallback.profile)),
                    ),
                    (
                        "unresolved".into(),
                        strings(invocation, &fallback.unresolved),
                    ),
                    ("replaced".into(), strings(invocation, &fallback.replaced)),
                    (
                        "reason".into(),
                        OValue::String("unmapped-or-missing".into()),
                    ),
                    ("protection".into(), OValue::String("basic".into())),
                ])
            })
            .collect(),
    )
}

fn defaults_json(invocation: &Invocation, defaults: &[ServerDefaults]) -> OValue {
    OValue::Array(
        defaults
            .iter()
            .map(|item| {
                OValue::Object(vec![
                    (
                        "profile".into(),
                        OValue::String(raw(invocation, &item.profile)),
                    ),
                    (
                        "fields".into(),
                        OValue::Array(
                            item.fields
                                .iter()
                                .map(|field| OValue::String(field.clone()))
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect(),
    )
}

fn name_action(invocation: &Invocation, name: &str, action: &str) -> OValue {
    OValue::Object(vec![
        ("name".into(), OValue::String(raw(invocation, name))),
        ("action".into(), OValue::String(action.to_owned())),
    ])
}

/// `--dry-run`: the plan (TS layouts), exit 0.
fn render_preview(
    invocation: &mut Invocation,
    format: Format,
    plan: &RestorePlan,
) -> Result<(), CliError> {
    let profiles: Vec<(String, String)> = plan
        .profiles
        .iter()
        .map(|item| (item.action.word().to_owned(), item.name.clone()))
        .collect();
    let topics: Vec<(String, String)> = plan
        .topics
        .iter()
        .map(|item| {
            let action = if item.existing.is_some() {
                "reuse"
            } else {
                "create"
            };
            (action.to_owned(), item.name.clone())
        })
        .collect();
    match format {
        Format::Json => {
            let rows = |rows: &[(String, String)]| {
                OValue::Array(
                    rows.iter()
                        .map(|(action, name)| name_action(invocation, name, action))
                        .collect(),
                )
            };
            let mappings = OValue::Array(
                plan.dlp_mappings
                    .iter()
                    .map(|mapping| {
                        OValue::Object(vec![
                            (
                                "source".into(),
                                OValue::String(raw(invocation, &mapping.source)),
                            ),
                            (
                                "destination".into(),
                                OValue::String(raw(invocation, &mapping.destination)),
                            ),
                        ])
                    })
                    .collect(),
            );
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
                ("profiles".into(), rows(&profiles)),
                ("topics".into(), rows(&topics)),
                ("dlpMappings".into(), mappings),
                ("dlpFallbacks".into(), fallbacks_json(invocation, plan)),
                (
                    "serverDefaults".into(),
                    defaults_json(invocation, &plan.server_defaults),
                ),
            ])]);
            invocation.output.json(&doc)
        }
        Format::Pretty | Format::Table => {
            let text = blocks(
                invocation,
                "Restore preview — no changes made",
                plan,
                &profiles,
                &topics,
                true,
                &plan.server_defaults,
                Vec::new(),
            );
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
    match format {
        Format::Json => {
            let row = |row: &Row, id_after_name: bool| {
                let mut fields = vec![(
                    "name".to_owned(),
                    OValue::String(raw(invocation, &row.name)),
                )];
                let id = row
                    .id
                    .as_ref()
                    .map(|id| ("id".to_owned(), OValue::String(id.clone())));
                if id_after_name && let Some(id) = id.clone() {
                    fields.push(id);
                }
                fields.push(("action".to_owned(), OValue::String(row.action.to_owned())));
                if !id_after_name && let Some(id) = id {
                    fields.push(id);
                }
                OValue::Object(fields)
            };
            let kind_name = |kind: ItemKind, name: &str| {
                OValue::Object(vec![
                    ("kind".to_owned(), OValue::String(kind.key().to_owned())),
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
                ("dlpFallbacks".to_owned(), fallbacks_json(invocation, plan)),
                (
                    "serverDefaults".to_owned(),
                    defaults_json(invocation, &outcome.server_defaults),
                ),
                (
                    "topics".to_owned(),
                    OValue::Array(outcome.topics.iter().map(|r| row(r, true)).collect()),
                ),
                (
                    "profiles".to_owned(),
                    OValue::Array(outcome.profiles.iter().map(|r| row(r, false)).collect()),
                ),
                (
                    "outcomeUnknown".to_owned(),
                    outcome.outcome_unknown.as_ref().map_or(
                        OValue::Null,
                        |(kind, name, action)| {
                            OValue::Object(vec![
                                ("kind".to_owned(), OValue::String(kind.key().to_owned())),
                                ("name".to_owned(), OValue::String(raw(invocation, name))),
                                (
                                    "action".to_owned(),
                                    OValue::String(action_word(action).to_owned()),
                                ),
                            ])
                        },
                    ),
                ),
                (
                    "notAttempted".to_owned(),
                    OValue::Array(
                        outcome
                            .not_attempted
                            .iter()
                            .map(|(kind, name)| kind_name(*kind, name))
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
            let pairs = |rows: &[Row]| -> Vec<(String, String)> {
                rows.iter()
                    .map(|row| (row.action.to_owned(), row.name.clone()))
                    .collect()
            };
            let mut extra = Vec::new();
            if let Some((kind, name, action)) = &outcome.outcome_unknown {
                extra.push("Possibly written (outcome unknown)".to_owned());
                extra.push(table::table(
                    &["Resource", "Name", "Action"],
                    &[vec![
                        kind.key().to_owned(),
                        shown(invocation, name),
                        action_word(action).to_owned(),
                    ]],
                ));
            }
            if !outcome.not_attempted.is_empty() {
                extra.push("Not attempted".to_owned());
                let cells: Vec<Vec<String>> = outcome
                    .not_attempted
                    .iter()
                    .map(|(kind, name)| vec![kind.key().to_owned(), shown(invocation, name)])
                    .collect();
                extra.push(table::table(&["Resource", "Name"], &cells));
            }
            if let Some(error) = &outcome.error {
                extra.push(format!("Error: {}", terminal_safe(error)));
            }
            let heading = if outcome.complete {
                "Restore complete"
            } else {
                "Restore incomplete — completed writes remain"
            };
            let text = blocks(
                invocation,
                heading,
                plan,
                &pairs(&outcome.profiles),
                &pairs(&outcome.topics),
                false,
                &outcome.server_defaults,
                extra,
            );
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

/// The plan word of a done word (`created` → `create`).
fn action_word(done: &str) -> &'static str {
    match done {
        "updated" => "update",
        _ => "create",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_keep_their_restore_texts_or_stop() {
        assert_eq!(
            stop_text(&Refusal::Stated(
                "Inventory pagination did not advance".to_owned()
            )),
            "Inventory pagination did not advance"
        );
        assert_eq!(
            stop_text(&Refusal::Withheld("Invalid DLP member".to_owned())),
            STOPPED
        );
        assert_eq!(
            http_text(409),
            "API request failed (HTTP 409); verify destination state before retrying"
        );
    }

    #[test]
    fn interrupt_contexts_count_the_writes() {
        let mut outcome = Outcome::default();
        assert_eq!(outcome.context(), InterruptContext::NothingChanged);
        outcome.outcome_unknown = Some((ItemKind::Topic, "T".into(), "created"));
        assert_eq!(
            outcome.context().text(),
            "0 topic(s) and 0 profile(s) written; the custom topic T may also have been created (outcome unknown); run the restore again with --on-conflict verify to resume"
        );
        outcome.outcome_unknown = None;
        outcome.written_topics = 1;
        outcome.written_profiles = 2;
        assert_eq!(
            outcome.context().text(),
            "1 topic(s) and 2 profile(s) written; run the restore again with --on-conflict verify to resume"
        );
    }

    #[test]
    fn dlp_maps_split_at_the_first_equals() {
        assert_eq!(
            dlp_map(&["a=b=c".into()]).unwrap(),
            vec![("a".to_owned(), "b=c".to_owned())]
        );
        for bad in ["=b", "a=", "ab"] {
            assert!(dlp_map(&[bad.into()]).is_err(), "{bad}");
        }
        assert!(dlp_map(&["a=b".into(), "a=c".into()]).is_err());
    }
}
