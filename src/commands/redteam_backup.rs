//! `redteam targets backup` and `targets restore` (DESIGN §15.18, §15.19, D151, D152).
//!
//! A backup is one airs file per run, published exclusively at 0600 into an
//! existing directory after every read. A restore reads only such a file (a TypeScript
//! backup is refused), checks it against the selected tenant, plans every row before
//! the first write, sends each write once (D133) and stops at the first unknown outcome.

use super::Invocation;
use super::redteam::{page_of, page_value, target_options, walk_all, walk_deadline};
use super::redteam_write::{self as rw, Contexts};
use crate::clients::{SINGLE_REQUEST_BUDGET, WALK_BUDGET};
use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::output::{Format, terminal_safe};
use crate::redteam::backup::{self as bk, Backup, Failed, Planned, ReadFailure, Stored};
use crate::redteam::secrets::{self, Shape};
use crate::render::pretty::{self, Bullet};
use crate::render::{cell_text, table};
use crate::store::PROGRAM;
use crate::writes::{self, Change, OutcomeLines};
use scm::airs::red_team::{
    RedTeamTargetsClient, TargetListOptions, TargetOperationOptions, models as rtm,
};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// The backup and restore banner (pretty only, decoration).
fn banner(invocation: &mut Invocation) {
    pretty::banner(
        &mut invocation.output,
        "Prisma AIRS — Backup & Restore",
        None,
    );
}

/// A name for printing: `[withheld]` when it carries a secret, terminal-safe.
fn shown_name(invocation: &Invocation, name: &str) -> String {
    if invocation.secrets.taints(name) {
        crate::error::WITHHELD.to_owned()
    } else {
        terminal_safe(name).into_owned()
    }
}

/// Every target of the tenant as `(uuid, name)` (the complete §15.12 walk).
async fn listing(
    invocation: &mut Invocation,
    targets: &RedTeamTargetsClient,
    deadline: &scm::RequestOptions,
) -> Result<Vec<(String, String)>, CliError> {
    let rows = walk_all(invocation, 100, 0, false, |skip, limit| {
        let mut page = TargetListOptions::default();
        page.skip = Some(skip);
        page.limit = Some(limit);
        let targets = targets.clone();
        let deadline = deadline.clone();
        async move {
            let answer = targets.list(&page, Some(&deadline)).await?;
            Ok(page_of(&page_value(&answer)?))
        }
    })
    .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let field = |key: &str| {
                row.get(key)
                    .and_then(OValue::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            (field("uuid"), field("name"))
        })
        .collect())
}

// ---------------------------------------------------------------------------
// targets backup (§15.18)
// ---------------------------------------------------------------------------

/// One target of a backup run.
enum Row {
    /// Stored; `withheld`: the service withheld its credentials (D157).
    Ok {
        uuid: String,
        name: String,
        withheld: bool,
    },
    Failed(Failed),
}

/// The pretty note of a stored target whose credentials the service withheld (D157).
const WITHHELD_NOTE: &str = "credentials withheld by the service; restore will refuse it";

/// `targets backup [--output-dir <dir>] [--name <n>]`.
pub async fn backup(
    invocation: &mut Invocation,
    dir: Option<&OsStr>,
    name: Option<&str>,
    format: Format,
) -> Result<(), CliError> {
    // The location, before the tenant and any request.
    let dir = dir.map_or_else(|| OsString::from("."), OsStr::to_owned);
    let is_dir = std::fs::metadata(&dir).is_ok_and(|metadata| metadata.is_dir());
    if !is_dir {
        return Err(CliError::operational(format!(
            "Cannot write a backup into {}; it must be an existing directory",
            crate::files::shown(&dir)
        )));
    }
    let now = std::time::SystemTime::now();
    let exported_at = crate::debug::iso_timestamp(now);
    let path = PathBuf::from(&dir).join(format!(
        "airs-redteam-targets-{}-{}.json",
        bk::stamp(&exported_at),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    crate::files::refuse_existing(&path, "--output-dir")?;

    let contexts = Contexts {
        not_sent: InterruptContext::Context("no backup file was written".to_owned()),
        sent: InterruptContext::Context("no backup file was written".to_owned()),
    };
    let deadline = walk_deadline()?;
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    prepared
        .clients
        .authenticate(Some(&deadline), WALK_BUDGET)
        .await
        .map_err(|error| contexts.before(error))?;
    let targets = prepared.client().targets();
    let all = listing(invocation, &targets, &deadline)
        .await
        .map_err(|error| contexts.before(error))?;
    let selected: Vec<(String, String)> = match name {
        Some(name) => {
            let matching: Vec<_> = all.into_iter().filter(|(_, n)| n == name).collect();
            if matching.is_empty() {
                return Err(CliError::operational(format!("Target not found: {name}")));
            }
            matching
        }
        None => all,
    };
    if selected.is_empty() {
        return render_backup(invocation, format, None, &[]);
    }
    let mut stored = Vec::new();
    let mut rows = Vec::new();
    for (uuid, target_name) in selected {
        match fetch(invocation, &targets, &uuid).await {
            Ok(target) => {
                let withheld = secrets::withheld(&target);
                rows.push(Row::Ok {
                    uuid: uuid.clone(),
                    name: target_name.clone(),
                    withheld,
                });
                stored.push(Stored {
                    uuid,
                    name: target_name,
                    credentials_withheld: withheld,
                    target,
                });
            }
            Err(CliError::Interrupted(_)) => {
                return Err(CliError::Interrupted(contexts.not_sent.clone()));
            }
            Err(error) => rows.push(Row::Failed(Failed {
                uuid,
                name: target_name,
                error: error.message(),
            })),
        }
    }
    let failed: Vec<Failed> = rows
        .iter()
        .filter_map(|row| match row {
            Row::Failed(failed) => Some(failed.clone()),
            Row::Ok { .. } => None,
        })
        .collect();
    // The warning only when the file holds a credential the service returned.
    let credentials = stored
        .iter()
        .any(|stored| secrets::carries_credentials(&stored.target));
    let document = Backup {
        exported_at,
        tenant: prepared.tenant.clone(),
        tsg_id: prepared.tsg.clone(),
        targets: stored,
        failed,
    };
    if invocation.output.pending_signal().is_some() {
        return Err(CliError::Interrupted(contexts.not_sent.clone()));
    }
    let published =
        crate::files::publish_new(&path, document.to_text().as_bytes(), "--output-dir")?;
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
    if credentials {
        invocation.output.warning(&format!(
            "⚠ {} contains target credentials; keep it private (mode 0600)",
            terminal_safe(&shown_path)
        ));
    }
    render_backup(invocation, format, Some(&path), &rows)
}

/// Whether a target body passes the create schema (the body restore sends).
fn valid_target(target: &OValue) -> bool {
    serde_json::to_value(target).is_ok_and(|wire| {
        rtm::TargetCreateRequest::parse(wire, scm::validation::Mode::Request).is_ok()
    })
}

/// The typed `GET /v1/target/<uuid>` without the SDK's schema defaults (D153,
/// scm-sdk 0.1.1): only the keys the server sent, `null`s and unknown keys included,
/// validated against the response schema, and taken through `serde_json::Value` so the
/// stored keys keep the order of the raw read (sorted below the create projection). The
/// create projection, checked against the create schema and stored as returned, masks
/// included (the caller marks a projection whose credentials the service withheld,
/// D157); a projection that fails it is a failed row, which names the Vertex AI
/// identifiers the service masked (§15.24 choice 13). The credentials join the secret set.
async fn fetch(
    invocation: &Invocation,
    targets: &RedTeamTargetsClient,
    uuid: &str,
) -> Result<OValue, CliError> {
    let failed = |error: &scm::Error| invocation.management_error(error, SINGLE_REQUEST_BUDGET);
    let answer = targets
        .get(
            uuid,
            Some(&target_options().map_err(|error| failed(&error))?),
        )
        .await
        .map_err(|error| failed(&error))?;
    let raw = serde_json::to_value(&answer)
        .ok()
        .and_then(|wire| crate::json::to_ordered(&wire).ok())
        .ok_or_else(|| failed(&scm::Error::new(scm::ErrorKind::Decode)))?;
    let mut registered = raw.clone();
    secrets::redact(&mut registered, Shape::Target, &invocation.secrets);
    let projection = bk::projection(&raw);
    if !valid_target(&projection) {
        return Err(CliError::operational(bk::create_schema_reason(
            &projection,
            valid_target,
        )));
    }
    Ok(projection)
}

fn render_backup(
    invocation: &mut Invocation,
    format: Format,
    path: Option<&Path>,
    rows: &[Row],
) -> Result<(), CliError> {
    let failures = rows
        .iter()
        .filter(|row| matches!(row, Row::Failed(_)))
        .count();
    let file = path.map(|path| crate::files::shown(path.as_os_str()));
    match format {
        Format::Json => {
            let text = |value: &str| OValue::String(value.to_owned());
            let doc = OValue::Object(vec![
                ("file".into(), file.as_deref().map_or(OValue::Null, text)),
                (
                    "backedUp".into(),
                    OValue::Number(((rows.len() - failures) as u64).into()),
                ),
                (
                    "failed".into(),
                    OValue::Array(
                        rows.iter()
                            .filter_map(|row| match row {
                                Row::Failed(failed) => Some(OValue::Object(vec![
                                    ("uuid".into(), text(&failed.uuid)),
                                    ("name".into(), text(&shown_raw(invocation, &failed.name))),
                                    ("error".into(), text(&failed.error)),
                                ])),
                                Row::Ok { .. } => None,
                            })
                            .collect(),
                    ),
                ),
                (
                    "targets".into(),
                    OValue::Array(
                        rows.iter()
                            .filter_map(|row| match row {
                                Row::Ok {
                                    uuid,
                                    name,
                                    withheld,
                                } => Some(OValue::Object(vec![
                                    ("uuid".into(), text(uuid)),
                                    ("name".into(), text(&shown_raw(invocation, name))),
                                    ("credentialsWithheld".into(), OValue::Bool(*withheld)),
                                ])),
                                Row::Failed(_) => None,
                            })
                            .collect(),
                    ),
                ),
            ]);
            invocation.output.json(&doc)?;
        }
        Format::Table => {
            let cells: Vec<Vec<String>> = rows
                .iter()
                .map(|row| {
                    let (name, uuid, status) = match row {
                        Row::Ok {
                            uuid,
                            name,
                            withheld,
                        } => (name, uuid, if *withheld { "withheld" } else { "ok" }),
                        Row::Failed(failed) => (&failed.name, &failed.uuid, "failed"),
                    };
                    vec![
                        cell_text(Some(&OValue::String(shown_raw(invocation, name)))),
                        cell_text(Some(&OValue::String(uuid.clone()))),
                        status.to_owned(),
                    ]
                })
                .collect();
            if !cells.is_empty() {
                invocation
                    .output
                    .data_line(&table::table(&["Target", "UUID", "Status"], &cells));
            }
        }
        Format::Pretty => {
            banner(invocation);
            match &file {
                None => pretty::empty_list(&mut invocation.output, "targets"),
                Some(file) => {
                    pretty::section(
                        &mut invocation.output,
                        &format!(
                            "Backed up {} target(s) to {}:",
                            rows.len() - failures,
                            terminal_safe(file)
                        ),
                    );
                    for row in rows {
                        if let Row::Ok { name, withheld, .. } = row {
                            let name = shown_name(invocation, name);
                            if *withheld {
                                let text = format!("{name} — {WITHHELD_NOTE}");
                                pretty::bullet(&mut invocation.output, &text, Bullet::Warn);
                            } else {
                                pretty::bullet(&mut invocation.output, &name, Bullet::Pass);
                            }
                        }
                    }
                    if failures > 0 {
                        pretty::section(&mut invocation.output, &format!("Failed ({failures}):"));
                        for row in rows {
                            if let Row::Failed(failed) = row {
                                let text = format!(
                                    "{}: {}",
                                    shown_name(invocation, &failed.name),
                                    terminal_safe(&failed.error)
                                );
                                pretty::bullet(&mut invocation.output, &text, Bullet::Fail);
                            }
                        }
                    }
                    invocation.output.data("\n");
                }
            }
        }
    }
    if failures > 0 {
        let _ = invocation.output.commit();
        return Err(CliError::Reported(crate::error::EXIT_OPERATIONAL));
    }
    Ok(())
}

/// A name for a JSON document: `[withheld]` when it carries a secret.
fn shown_raw(invocation: &Invocation, name: &str) -> String {
    if invocation.secrets.taints(name) {
        crate::error::WITHHELD.to_owned()
    } else {
        name.to_owned()
    }
}

// ---------------------------------------------------------------------------
// targets restore (§15.19)
// ---------------------------------------------------------------------------

/// A validated `targets restore`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestorePlan {
    pub file: OsString,
    pub overwrite: bool,
    pub validate: bool,
    pub dry_run: bool,
    pub force: bool,
    pub allow_other_tenant: bool,
    pub format: Format,
}

/// The restore file limit (16 MiB, §15.3).
const RESTORE_LIMIT: u64 = 16 * 1_048_576;

/// The status of one restore row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Created,
    Updated,
    Skipped,
    Failed,
    Unknown,
    NotAttempted,
    WouldCreate,
    WouldUpdate,
}

impl Status {
    fn json(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::NotAttempted => "notAttempted",
            Self::WouldCreate => "wouldCreate",
            Self::WouldUpdate => "wouldUpdate",
        }
    }

    fn words(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
            Self::Unknown => "outcome unknown",
            Self::NotAttempted => "not attempted",
            Self::WouldCreate => "would create",
            Self::WouldUpdate => "would update",
        }
    }
}

struct Outcome {
    name: String,
    uuid: Option<String>,
    action: &'static str,
    status: Status,
    error: Option<String>,
    /// The write was applied but its answer could not be read: the run exits 1 (§15.3).
    unreadable: bool,
}

/// Reads and checks the backup file before the tenant (§15.19 "The file").
fn read_backup(file: &OsStr) -> Result<Backup, CliError> {
    let shown = crate::files::shown(file);
    let text = crate::files::read_text(file, RESTORE_LIMIT)?;
    bk::parse(&text, valid_target).map_err(|failure| {
        CliError::operational(match failure {
            ReadFailure::Malformed => {
                format!("Invalid red team target backup {shown}: malformed JSON")
            }
            ReadFailure::TypeScript => format!(
                "{shown} is a TypeScript airs-cli backup; {PROGRAM} cannot restore it. Restore it with the TypeScript airs-cli, or back the targets up again with '{PROGRAM} redteam targets backup'."
            ),
            ReadFailure::Newer => format!(
                "{shown} was written by a newer version of {PROGRAM}; upgrade {PROGRAM} to restore it"
            ),
            ReadFailure::Invalid(reason) => {
                format!("Invalid red team target backup {shown}: {reason}")
            }
        })
    })
}

/// `<c> created, <u> updated[, <k> outcome unknown], <n> not attempted`.
fn stopped(outcomes: &[Outcome]) -> InterruptContext {
    let count = |status: Status| outcomes.iter().filter(|o| o.status == status).count();
    let unknown = count(Status::Unknown);
    let mut text = format!(
        "{} created, {} updated",
        count(Status::Created),
        count(Status::Updated)
    );
    if unknown > 0 {
        text.push_str(&format!(", {unknown} outcome unknown"));
    }
    text.push_str(&format!(", {} not attempted", count(Status::NotAttempted)));
    InterruptContext::Context(text)
}

/// `targets restore --file <backup>`.
pub async fn restore(invocation: &mut Invocation, plan: &RestorePlan) -> Result<(), CliError> {
    let shown_file = crate::files::shown(&plan.file);
    let backup = read_backup(&plan.file)?;
    if !backup.failed.is_empty() {
        invocation.output.warning(&format!(
            "⚠ {} is incomplete: {} target(s) could not be backed up",
            terminal_safe(&shown_file),
            backup.failed.len()
        ));
    }
    // The stored credentials are sent, never printed.
    for stored in &backup.targets {
        let mut copy = stored.target.clone();
        secrets::redact(&mut copy, Shape::Target, &invocation.secrets);
    }
    let contexts = Contexts::plain();
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    if backup.tsg_id != prepared.tsg && !plan.allow_other_tenant {
        return Err(CliError::operational(format!(
            "{} was exported from TSG {}; the selected tenant uses TSG {}. Pass --allow-other-tenant to restore it here.",
            shown_file,
            terminal_safe(&backup.tsg_id),
            prepared.tsg
        )));
    }
    let deadline = walk_deadline()?;
    prepared
        .clients
        .authenticate(Some(&deadline), WALK_BUDGET)
        .await
        .map_err(|error| contexts.before(error))?;
    let targets = prepared.client().targets();
    let tenant: Vec<(String, String)> = listing(invocation, &targets, &deadline)
        .await
        .map_err(|error| contexts.before(error))?
        .into_iter()
        .map(|(uuid, name)| (name, uuid))
        .collect();
    let planned = bk::plan(&backup, &tenant, plan.overwrite, secrets::withheld);
    let mut outcomes: Vec<Outcome> = backup
        .targets
        .iter()
        .zip(&planned)
        .map(|(stored, row)| {
            let (action, status, uuid, error) = match row {
                Planned::Failed(reason) => ("fail", Status::Failed, None, Some(reason.clone())),
                Planned::Skip(uuid) => ("skip", Status::Skipped, Some(uuid.clone()), None),
                Planned::Update(uuid) => (
                    "update",
                    if plan.dry_run {
                        Status::WouldUpdate
                    } else {
                        Status::NotAttempted
                    },
                    Some(uuid.clone()),
                    None,
                ),
                Planned::Create => (
                    "create",
                    if plan.dry_run {
                        Status::WouldCreate
                    } else {
                        Status::NotAttempted
                    },
                    None,
                    None,
                ),
            };
            Outcome {
                name: stored.name.clone(),
                uuid,
                action,
                status,
                error,
                unreadable: false,
            }
        })
        .collect();
    if plan.dry_run {
        return render_restore(invocation, plan, &outcomes);
    }
    let updates = planned
        .iter()
        .filter(|row| matches!(row, Planned::Update(_)))
        .count();
    if updates > 0 && !plan.force {
        let plural = if updates == 1 { "" } else { "s" };
        if !rw::confirm(
            invocation,
            &format!(
                "Overwrite {updates} existing target{plural} with the settings in {shown_file}?"
            ),
        )? {
            return Ok(());
        }
    }
    let operation = {
        let mut operation = TargetOperationOptions::default();
        operation.validate = plan.validate.then_some(true);
        operation
    };
    for index in 0..outcomes.len() {
        if !matches!(planned[index], Planned::Create | Planned::Update(_)) {
            continue;
        }
        invocation.interrupt = Some(interrupt_of(&outcomes));
        if invocation.output.pending_signal().is_some() {
            return Err(CliError::Interrupted(interrupt_of(&outcomes)));
        }
        let stored = &backup.targets[index].target;
        let result = match &planned[index] {
            Planned::Create => create(invocation, &targets, stored, &operation).await,
            Planned::Update(uuid) => update(invocation, &targets, uuid, stored, &operation).await,
            _ => continue,
        };
        let outcome = &mut outcomes[index];
        match result {
            Ok(Written::Done(uuid)) => {
                outcome.status = if outcome.action == "create" {
                    Status::Created
                } else {
                    Status::Updated
                };
                if uuid.is_some() {
                    outcome.uuid = uuid;
                }
            }
            Ok(Written::Rejected(message)) => {
                outcome.status = Status::Failed;
                outcome.error = Some(message);
            }
            Ok(Written::Unreadable(message)) => {
                outcome.status = if outcome.action == "create" {
                    Status::Created
                } else {
                    Status::Updated
                };
                outcome.error = Some(message);
                outcome.unreadable = true;
                break;
            }
            Ok(Written::Unknown(message)) => {
                outcome.status = Status::Unknown;
                outcome.error = Some(message);
                break;
            }
            Err(Interrupted { sent }) => {
                if sent {
                    outcome.status = Status::Unknown;
                }
                return Err(CliError::Interrupted(interrupt_of(&outcomes)));
            }
        }
    }
    invocation.interrupt = Some(interrupt_of(&outcomes));
    render_restore(invocation, plan, &outcomes)
}

/// The interrupt context of the restore so far.
fn interrupt_of(outcomes: &[Outcome]) -> InterruptContext {
    if outcomes.iter().any(|o| {
        matches!(
            o.status,
            Status::Created | Status::Updated | Status::Unknown
        )
    }) {
        stopped(outcomes)
    } else {
        InterruptContext::NothingChanged
    }
}

/// What one restore write did.
enum Written {
    /// Applied; the target id from the answer when it had one.
    Done(Option<String>),
    /// Refused (nothing was applied): the §6 message.
    Rejected(String),
    /// Applied, but the answer could not be read: `Outcome: the target was <done>, but
    /// the response could not be read.`
    Unreadable(String),
    /// May have been applied.
    Unknown(String),
}

/// A signal stopped a write; `sent`: the request may have reached the service.
struct Interrupted {
    sent: bool,
}

/// The outcome of one attempt (D133).
fn written<T: serde::Serialize>(
    invocation: &Invocation,
    change: Change,
    result: scm::Result<T>,
) -> Result<Written, Interrupted> {
    match result {
        Ok(answer) => {
            let uuid = crate::json::to_ordered(&answer)
                .ok()
                .and_then(|doc| doc.get("uuid").and_then(OValue::as_str).map(str::to_owned));
            Ok(Written::Done(uuid))
        }
        Err(error) => match writes::describe(&error, change, &invocation.secrets) {
            CliError::Interrupted(context) => Err(Interrupted {
                sent: context != InterruptContext::NothingChanged,
            }),
            failure => Ok(match writes::classify(&error) {
                writes::Failure::Unreadable => Written::Unreadable(change.unreadable_line()),
                writes::Failure::Unknown => Written::Unknown(failure.message()),
                _ => Written::Rejected(failure.message()),
            }),
        },
    }
}

async fn create(
    invocation: &Invocation,
    targets: &RedTeamTargetsClient,
    stored: &OValue,
    operation: &TargetOperationOptions,
) -> Result<Written, Interrupted> {
    let body = bk::with_routing(stored, None);
    let wire = serde_json::to_value(&body).unwrap_or(serde_json::Value::Null);
    let Ok(body) = rtm::TargetCreateRequest::parse(wire, scm::validation::Mode::Request) else {
        return Ok(Written::Rejected(
            writes::invalid_body("POST", "/v1/target").message(),
        ));
    };
    let result = writes::attempt(async || targets.create(&body, Some(operation), None).await).await;
    written(invocation, Change::Words("target", "created"), result)
}

async fn update(
    invocation: &Invocation,
    targets: &RedTeamTargetsClient,
    uuid: &str,
    stored: &OValue,
    operation: &TargetOperationOptions,
) -> Result<Written, Interrupted> {
    let current = match targets.get(uuid, None).await {
        Ok(current) => crate::json::to_ordered(&current).unwrap_or(OValue::Null),
        Err(error) if error.kind() == scm::ErrorKind::Cancelled => {
            return Err(Interrupted { sent: false });
        }
        Err(error) => {
            return Ok(Written::Rejected(
                invocation
                    .management_error(&error, SINGLE_REQUEST_BUDGET)
                    .message(),
            ));
        }
    };
    let body = bk::with_routing(stored, Some(&current));
    let wire = serde_json::to_value(&body).unwrap_or(serde_json::Value::Null);
    let Ok(body) = rtm::TargetUpdateRequest::parse(wire, scm::validation::Mode::Request) else {
        return Ok(Written::Rejected(
            writes::invalid_body("PUT", &format!("/v1/target/{uuid}")).message(),
        ));
    };
    let result =
        writes::attempt(async || targets.update(uuid, &body, Some(operation), None).await).await;
    written(invocation, Change::Words("target", "updated"), result)
}

fn render_restore(
    invocation: &mut Invocation,
    plan: &RestorePlan,
    outcomes: &[Outcome],
) -> Result<(), CliError> {
    let count = |status: Status| outcomes.iter().filter(|o| o.status == status).count();
    let dirty = outcomes.iter().any(|o| {
        o.unreadable
            || matches!(
                o.status,
                Status::Failed | Status::Unknown | Status::NotAttempted
            )
    });
    match plan.format {
        Format::Json => {
            let number = |n: usize| OValue::Number((n as u64).into());
            let details: Vec<OValue> = outcomes
                .iter()
                .map(|o| {
                    let mut entries = vec![(
                        "name".to_owned(),
                        OValue::String(shown_raw(invocation, &o.name)),
                    )];
                    if let Some(uuid) = &o.uuid {
                        entries.push(("uuid".into(), OValue::String(uuid.clone())));
                    }
                    entries.push(("action".into(), OValue::String(o.action.to_owned())));
                    entries.push(("status".into(), OValue::String(o.status.json().to_owned())));
                    if let Some(error) = &o.error {
                        entries.push(("error".into(), OValue::String(error.clone())));
                    }
                    OValue::Object(entries)
                })
                .collect();
            let doc = OValue::Object(vec![
                (
                    "file".into(),
                    OValue::String(crate::files::shown(&plan.file)),
                ),
                ("dryRun".into(), OValue::Bool(plan.dry_run)),
                ("created".into(), number(count(Status::Created))),
                ("updated".into(), number(count(Status::Updated))),
                ("skipped".into(), number(count(Status::Skipped))),
                ("failed".into(), number(count(Status::Failed))),
                ("unknown".into(), number(count(Status::Unknown))),
                ("notAttempted".into(), number(count(Status::NotAttempted))),
                ("details".into(), OValue::Array(details)),
            ]);
            invocation.output.json(&doc)?;
        }
        Format::Table => {
            let cells: Vec<Vec<String>> = outcomes
                .iter()
                .map(|o| {
                    vec![
                        cell_text(Some(&OValue::String(shown_raw(invocation, &o.name)))),
                        o.action.to_owned(),
                        o.status.json().to_owned(),
                        o.error
                            .as_deref()
                            .map(|e| cell_text(Some(&OValue::String(e.to_owned()))))
                            .unwrap_or_default(),
                    ]
                })
                .collect();
            if !cells.is_empty() {
                invocation.output.data_line(&table::table(
                    &["Target", "Action", "Status", "Error"],
                    &cells,
                ));
            }
        }
        Format::Pretty => {
            banner(invocation);
            pretty::section(&mut invocation.output, "Restore results:");
            for o in outcomes {
                let name = shown_name(invocation, &o.name);
                let suffix = o
                    .error
                    .as_deref()
                    .map(|error| format!(": {}", terminal_safe(error)))
                    .unwrap_or_default();
                let kind = match o.status {
                    Status::Created | Status::Updated => Bullet::Pass,
                    Status::Failed | Status::Unknown => Bullet::Fail,
                    Status::Skipped | Status::NotAttempted => Bullet::Skip,
                    Status::WouldCreate | Status::WouldUpdate => Bullet::Neutral,
                };
                let text = format!("{name} — {}{suffix}", o.status.words());
                pretty::bullet(&mut invocation.output, &text, kind);
            }
            let parts: Vec<String> = [
                Status::WouldCreate,
                Status::WouldUpdate,
                Status::Created,
                Status::Updated,
                Status::Skipped,
                Status::Failed,
                Status::Unknown,
                Status::NotAttempted,
            ]
            .iter()
            .filter(|status| count(**status) > 0)
            .map(|status| format!("{} {}", count(*status), status.words()))
            .collect();
            invocation
                .output
                .data(&format!("\n  Total: {}\n\n", parts.join(", ")));
        }
    }
    if dirty {
        let _ = invocation.output.commit();
        return Err(CliError::Reported(crate::error::EXIT_OPERATIONAL));
    }
    Ok(())
}
