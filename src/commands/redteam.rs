//! `redteam` planning and dispatch (DESIGN §15). Planning runs every argument check of
//! §15.3 before the tenant is read (D141); dispatch connects the red team client from
//! the tenant's endpoints and runs the command.
//!
//! Steps 1 and 2 of §15.1 (the reads, the writes and the scan) are implemented here;
//! the reports and backups of step 3 join the command tree as they are built.

use super::redteam_adapters::{AdapterKind, AdapterPlan};
use super::redteam_backup::RestorePlan;
use super::redteam_infra::{DeviceWrite, InstanceWrite};
use super::redteam_report::EnvReportPlan;
use super::redteam_targets::TargetWrite;
use super::redteam_write::gate;
use super::report_command::ReportDestination;
use super::{Invocation, Plan, walk_options};
use crate::cli::{
    AdapterCommand, ChannelsCommand, DevicesCommand, EulaCommand, InstancesCommand,
    NetworkBrokerCommand, PromptSetsCommand, PromptsCommand, PropertiesCommand, RedteamCommand,
    RedteamGroup, TargetsCommand,
};
use crate::clients::{RedTeamClients, SINGLE_REQUEST_BUDGET, TOKEN_BUDGET, WALK_BUDGET};
use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::output::{self, Format};
use crate::redteam::args::{self, ScanSpec};
use crate::redteam::{self as rt, LimitText, ListParams};
use crate::walk::{self, Page, Walked};
use scm::airs::red_team::RedTeamClient;
use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;

/// Where `prompt-sets download` writes the template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Stdout,
    File(PathBuf),
}

/// The `redteam list` filters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanFilters {
    pub status: Option<String>,
    pub job_type: Option<String>,
    pub target: Option<String>,
}

/// A validated red team invocation. `Option<Format>` is the explicit `--output` of a
/// read that honours the tenant's `defaultOutput` (§15.3 "Formats").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RtPlan {
    ScanList {
        filters: ScanFilters,
        params: ListParams,
        format: Option<Format>,
    },
    Status {
        job_id: String,
        format: Format,
    },
    Categories(Format),
    Languages {
        management: bool,
        format: Option<Format>,
    },
    EulaStatus(Format),
    EulaContent(Format),
    InstanceGet {
        tenant_id: String,
        format: Option<Format>,
    },
    PromptSetList {
        params: ListParams,
        format: Option<Format>,
    },
    PromptSetGet {
        uuid: String,
        format: Option<Format>,
    },
    Download {
        uuid: String,
        destination: Destination,
    },
    PromptList {
        set: String,
        params: ListParams,
        format: Option<Format>,
    },
    PromptGet {
        set: String,
        prompt: String,
        format: Option<Format>,
    },
    PropertyList {
        params: ListParams,
        format: Option<Format>,
    },
    PropertyValues {
        name: String,
        format: Option<Format>,
    },
    TargetList {
        params: ListParams,
        format: Option<Format>,
    },
    TargetGet {
        uuid: String,
        format: Option<Format>,
    },
    TargetProfile {
        uuid: String,
        format: Format,
    },
    TargetMetadata(Format),
    TargetTemplates(Format),
    ErrorLogs {
        target: String,
        limit: Option<u32>,
        format: Format,
    },
    AdapterList {
        params: ListParams,
        search: Option<String>,
        format: Option<Format>,
    },
    AdapterGet {
        uuid: String,
        format: Option<Format>,
    },
    ChannelList {
        params: ListParams,
        search: Option<String>,
        statuses: Vec<String>,
        format: Option<Format>,
    },
    ChannelGet {
        id: String,
        format: Option<Format>,
    },
    Stats(Option<Format>),
    // Step 2: writes and the scan (§15.1).
    Scan {
        spec: Box<ScanSpec>,
        format: Format,
    },
    Abort {
        job_id: String,
        force: bool,
    },
    EulaAccept {
        force: bool,
        format: Format,
    },
    RegistryCredentials(Option<Format>),
    InstanceWrite {
        kind: InstanceWrite,
        body: serde_json::Value,
        format: Format,
    },
    InstanceDelete {
        tenant_id: String,
        force: bool,
        format: Format,
    },
    Devices {
        kind: DeviceWrite,
        tenant_id: String,
        config: OsString,
        format: Format,
    },
    DevicesDelete {
        tenant_id: String,
        serials: String,
        force: bool,
        format: Format,
    },
    PromptSetCreate {
        body: serde_json::Value,
        format: Format,
    },
    PromptSetUpdate {
        uuid: String,
        body: serde_json::Value,
        format: Format,
    },
    PromptSetArchive {
        uuid: String,
        archive: bool,
    },
    Upload {
        uuid: String,
        file: OsString,
    },
    PromptAdd {
        body: serde_json::Value,
        format: Format,
    },
    PromptUpdate {
        set: String,
        prompt: String,
        body: serde_json::Value,
        format: Format,
    },
    PromptDelete {
        set: String,
        prompt: String,
        force: bool,
    },
    PropertyCreate(serde_json::Value),
    PropertyAddValue(serde_json::Value),
    TargetWrite {
        kind: TargetWrite,
        config: OsString,
        validate: bool,
        format: Format,
    },
    TargetDelete {
        uuid: String,
        force: bool,
    },
    ValidateAuth {
        auth_type: String,
        config: OsString,
        target_id: Option<String>,
        format: Format,
    },
    TargetInit {
        key: String,
        path: PathBuf,
        given: String,
        format: Format,
    },
    Adapter(Box<AdapterPlan>),
    AdapterDelete {
        uuid: String,
        force: bool,
    },
    ChannelWrite {
        id: Option<String>,
        body: serde_json::Value,
        format: Format,
    },
    // Step 3: reports and backups (§15.1).
    JobReport {
        job_id: String,
        attacks: bool,
        severity: Option<String>,
        limit: u32,
        format: Format,
    },
    EnvReport(Box<EnvReportPlan>),
    Backup {
        dir: Option<OsString>,
        name: Option<String>,
        format: Format,
    },
    Restore(Box<RestorePlan>),
}

impl RtPlan {
    /// Whether this is the environment report (debug policy `refused`, §2.9).
    pub fn is_environment_report(&self) -> bool {
        matches!(self, Self::EnvReport(_))
    }

    /// What an interruption reports (§15.3 "Interruption").
    pub fn interrupt_context(&self) -> InterruptContext {
        match self {
            Self::Download { .. } | Self::TargetInit { .. } => InterruptContext::NoFileWritten,
            Self::EnvReport(_) => InterruptContext::Context("no report was written".to_owned()),
            Self::Backup { .. } => {
                InterruptContext::Context("no backup file was written".to_owned())
            }
            Self::Restore(_) => InterruptContext::NothingChanged,
            Self::Scan { .. } => InterruptContext::Context("no scan was started".to_owned()),
            Self::Abort { .. }
            | Self::EulaAccept { .. }
            | Self::RegistryCredentials(_)
            | Self::InstanceWrite { .. }
            | Self::InstanceDelete { .. }
            | Self::Devices { .. }
            | Self::DevicesDelete { .. }
            | Self::PromptSetCreate { .. }
            | Self::PromptSetUpdate { .. }
            | Self::PromptSetArchive { .. }
            | Self::Upload { .. }
            | Self::PromptAdd { .. }
            | Self::PromptUpdate { .. }
            | Self::PromptDelete { .. }
            | Self::PropertyCreate(_)
            | Self::PropertyAddValue(_)
            | Self::TargetWrite { .. }
            | Self::TargetDelete { .. }
            | Self::ValidateAuth { .. }
            | Self::Adapter(_)
            | Self::AdapterDelete { .. }
            | Self::ChannelWrite { .. } => InterruptContext::NothingChanged,
            _ => InterruptContext::NoDataWritten,
        }
    }
}

/// The deprecation warnings of the red team aliases (§15.3 "Validation order"), printed
/// before any other check: `--confirm` of `eula accept`, `--format` of `targets backup`.
pub fn deprecation_warnings(group: &RedteamGroup) -> Vec<&'static str> {
    match &group.command {
        Some(RedteamCommand::Targets(targets)) => match &targets.command {
            Some(TargetsCommand::Backup(args)) if args.format.is_some() => {
                vec!["⚠ --format is deprecated and will be removed in v4 — use --file-format"]
            }
            _ => Vec::new(),
        },
        Some(RedteamCommand::Eula(eula)) => match &eula.command {
            Some(EulaCommand::Accept(args)) if args.confirm => {
                vec!["⚠ --confirm is deprecated and will be removed in v4 — use --force"]
            }
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// A body built from arguments only, validated with its SDK schema during planning
/// (§15.3 "Request bodies").
fn planned_body<M>(
    value: serde_json::Value,
    method: &str,
    path: &str,
    parse: impl FnOnce(serde_json::Value, scm::validation::Mode) -> scm::Result<M>,
) -> Result<serde_json::Value, CliError> {
    super::redteam_write::body(value.clone(), method, path, parse)?;
    Ok(value)
}

/// Plan a `redteam` command line; `--output` was validated already (§15.3 order).
/// `debug` is the global `--debug` (the environment report refuses it, §15.17).
pub fn plan(group: &RedteamGroup, explicit: Option<&str>, debug: bool) -> Result<Plan, CliError> {
    let format = output::validate_explicit(explicit)?;
    let pretty = format.unwrap_or(Format::Pretty);
    let interactive = || crate::input::Terminals::detect().interactive();
    use scm::airs::red_team::models as rtm;
    let Some(command) = &group.command else {
        return Ok(Plan::GroupHelp(&["redteam"]));
    };
    let plan = match command {
        RedteamCommand::List(args) => {
            // The vendor 0.93.0 vocabularies and page bound (D301, D302, §15.23).
            let filters = ScanFilters {
                status: rt::vocabulary_filter(
                    "--status",
                    args.status.as_deref(),
                    &rt::JOB_STATUSES,
                )?,
                job_type: rt::vocabulary_filter(
                    "--type",
                    args.job_type.as_deref(),
                    &rt::LIST_JOB_TYPES,
                )?,
                target: rt::target_filter(args.target.as_deref())?,
            };
            let params = rt::bounded_list_params(
                args.limit.as_deref(),
                args.offset.as_deref(),
                args.all,
                args.max.as_deref(),
                LimitText::Contract,
                Some(rt::MAX_PAGE),
            )?;
            RtPlan::ScanList {
                filters,
                params,
                format,
            }
        }
        RedteamCommand::Status(args) => {
            rt::check_uuid("job id", &args.job_id)?;
            RtPlan::Status {
                job_id: args.job_id.clone(),
                format: pretty,
            }
        }
        RedteamCommand::Categories => RtPlan::Categories(pretty),
        RedteamCommand::Scan(scan) => {
            let spec = args::scan(&args::ScanOptions {
                target: &scan.target,
                name: &scan.name,
                job_type: scan.job_type.as_deref(),
                categories: scan.categories.as_deref(),
                prompt_sets: scan.prompt_sets.as_deref(),
                goals: scan.goals.as_deref(),
                depth: scan.depth.as_deref(),
                breadth: scan.breadth.as_deref(),
                no_wait: scan.no_wait,
                wait_timeout: scan.wait_timeout.as_deref(),
            })?;
            RtPlan::Scan {
                spec: Box::new(spec),
                format: pretty,
            }
        }
        RedteamCommand::Abort(abort) => {
            rt::check_uuid("job id", &abort.job_id)?;
            gate(
                abort.force,
                interactive(),
                &format!("abort scan {}", abort.job_id),
            )?;
            RtPlan::Abort {
                job_id: abort.job_id.clone(),
                force: abort.force,
            }
        }
        RedteamCommand::RegistryCredentials => RtPlan::RegistryCredentials(format),
        RedteamCommand::Report(report) => match &report.job_id {
            Some(job_id) => {
                rt::check_uuid("job id", job_id)?;
                if report.output_file.is_some()
                    || report.title.is_some()
                    || report.max_pages.is_some()
                    || report.strict
                {
                    return Err(CliError::usage(
                        "Environment report options cannot be combined with a scan job ID",
                    ));
                }
                let checked = rt::attack_list_args(
                    report.limit.as_deref(),
                    report.severity.as_deref(),
                    report.attacks,
                )?;
                RtPlan::JobReport {
                    job_id: job_id.clone(),
                    attacks: report.attacks,
                    severity: checked.severity,
                    limit: checked.limit,
                    format: pretty,
                }
            }
            None => RtPlan::EnvReport(Box::new(env_report_plan(report, explicit, debug)?)),
        },
        RedteamCommand::Devices(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "devices"])),
            Some(DevicesCommand::Create(devices) | DevicesCommand::Update(devices)) => {
                crate::segment::check_segment("tenant id", &devices.tenant_id)?;
                let kind = match &group.command {
                    Some(DevicesCommand::Create(_)) => DeviceWrite::Create,
                    _ => DeviceWrite::Update,
                };
                RtPlan::Devices {
                    kind,
                    tenant_id: devices.tenant_id.clone(),
                    config: devices.config.clone(),
                    format: pretty,
                }
            }
            Some(DevicesCommand::Delete(devices)) => {
                crate::segment::check_segment("tenant id", &devices.tenant_id)?;
                rt::check_filter("--serial-numbers", &devices.serial_numbers)?;
                rt::check_serial_numbers(&devices.serial_numbers)?;
                gate(devices.force, interactive(), "delete devices")?;
                RtPlan::DevicesDelete {
                    tenant_id: devices.tenant_id.clone(),
                    serials: devices.serial_numbers.clone(),
                    force: devices.force,
                    format: pretty,
                }
            }
        },
        RedteamCommand::Languages(args) => RtPlan::Languages {
            management: args.management,
            format,
        },
        RedteamCommand::Eula(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "eula"])),
            Some(EulaCommand::Status) => RtPlan::EulaStatus(pretty),
            Some(EulaCommand::Content) => RtPlan::EulaContent(pretty),
            Some(EulaCommand::Accept(accept)) => {
                let force = accept.force || accept.confirm;
                gate(force, interactive(), "accept the Red Team EULA")?;
                RtPlan::EulaAccept {
                    force,
                    format: pretty,
                }
            }
        },
        RedteamCommand::Instances(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "instances"])),
            Some(InstancesCommand::Get { tenant_id }) => {
                crate::segment::check_segment("tenant id", tenant_id)?;
                RtPlan::InstanceGet {
                    tenant_id: tenant_id.clone(),
                    format,
                }
            }
            Some(InstancesCommand::Create(create)) => RtPlan::InstanceWrite {
                kind: InstanceWrite::Create,
                body: planned_body(
                    serde_json::json!({
                        "tsg_id": create.tsg_id,
                        "tenant_id": create.tenant_id,
                        "app_id": create.app_id,
                        "region": create.region,
                    }),
                    "POST",
                    "/v1/instances",
                    rtm::InstanceRequest::parse,
                )?,
                format: pretty,
            },
            Some(InstancesCommand::Update(update)) => {
                crate::segment::check_segment("tenant id", &update.tenant_id)?;
                RtPlan::InstanceWrite {
                    kind: InstanceWrite::Update(update.tenant_id.clone()),
                    body: planned_body(
                        serde_json::json!({
                            "tsg_id": update.tsg_id,
                            "tenant_id": update.tenant_id,
                            "app_id": update.app_id,
                            "region": update.region,
                        }),
                        "PUT",
                        &format!("/v1/instances/{}", update.tenant_id),
                        rtm::InstanceRequest::parse,
                    )?,
                    format: pretty,
                }
            }
            Some(InstancesCommand::Delete(delete)) => {
                crate::segment::check_segment("tenant id", &delete.tenant_id)?;
                gate(
                    delete.force,
                    interactive(),
                    &format!("delete instance {}", delete.tenant_id),
                )?;
                RtPlan::InstanceDelete {
                    tenant_id: delete.tenant_id.clone(),
                    force: delete.force,
                    format: pretty,
                }
            }
        },
        RedteamCommand::PromptSets(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "prompt-sets"])),
            Some(PromptSetsCommand::List(flags)) => RtPlan::PromptSetList {
                params: client_list(flags)?,
                format,
            },
            Some(PromptSetsCommand::Get { uuid }) => {
                rt::check_uuid("prompt set uuid", uuid)?;
                RtPlan::PromptSetGet {
                    uuid: uuid.clone(),
                    format,
                }
            }
            Some(PromptSetsCommand::Download(args)) => {
                rt::check_uuid("prompt set uuid", &args.uuid)?;
                let destination = match args.output_file.as_deref() {
                    Some(path) if path.is_empty() => {
                        return Err(CliError::usage("--output-file needs a path"));
                    }
                    Some(path) if path == "-" => Destination::Stdout,
                    Some(path) => Destination::File(PathBuf::from(path)),
                    None => Destination::File(PathBuf::from(format!("{}-template.csv", args.uuid))),
                };
                RtPlan::Download {
                    uuid: args.uuid.clone(),
                    destination,
                }
            }
            Some(PromptSetsCommand::Create(create)) => {
                let mut body = serde_json::json!({ "name": create.name });
                if let Some(description) = create.description.as_deref().filter(|d| !d.is_empty()) {
                    body["description"] = serde_json::json!(description);
                }
                RtPlan::PromptSetCreate {
                    body: planned_body(
                        body,
                        "POST",
                        "/v1/custom-attack/custom-prompt-set",
                        rtm::CustomPromptSetCreateRequest::parse,
                    )?,
                    format: pretty,
                }
            }
            Some(PromptSetsCommand::Update(update)) => {
                rt::check_uuid("prompt set uuid", &update.uuid)?;
                let mut body = serde_json::Map::new();
                for (key, value) in [("name", &update.name), ("description", &update.description)] {
                    if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
                        body.insert(key.to_owned(), serde_json::json!(value));
                    }
                }
                if body.is_empty() {
                    return Err(CliError::usage(
                        "Specify --name and/or --description to update",
                    ));
                }
                RtPlan::PromptSetUpdate {
                    uuid: update.uuid.clone(),
                    body: planned_body(
                        serde_json::Value::Object(body),
                        "PUT",
                        &format!("/v1/custom-attack/custom-prompt-set/{}", update.uuid),
                        rtm::CustomPromptSetUpdateRequest::parse,
                    )?,
                    format: pretty,
                }
            }
            Some(PromptSetsCommand::Archive(archive)) => {
                rt::check_uuid("prompt set uuid", &archive.uuid)?;
                RtPlan::PromptSetArchive {
                    uuid: archive.uuid.clone(),
                    archive: !archive.unarchive,
                }
            }
            Some(PromptSetsCommand::Upload(upload)) => {
                rt::check_uuid("prompt set uuid", &upload.uuid)?;
                RtPlan::Upload {
                    uuid: upload.uuid.clone(),
                    file: upload.file.clone(),
                }
            }
        },
        RedteamCommand::Prompts(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "prompts"])),
            Some(PromptsCommand::List(args)) => {
                rt::check_uuid("prompt set uuid", &args.set_uuid)?;
                let params = rt::list_params(
                    args.limit.as_deref(),
                    args.offset.as_deref(),
                    args.all,
                    args.max.as_deref(),
                    LimitText::Contract,
                )?;
                RtPlan::PromptList {
                    set: args.set_uuid.clone(),
                    params,
                    format,
                }
            }
            Some(PromptsCommand::Get {
                set_uuid,
                prompt_uuid,
            }) => {
                rt::check_uuid("prompt set uuid", set_uuid)?;
                rt::check_uuid("prompt uuid", prompt_uuid)?;
                RtPlan::PromptGet {
                    set: set_uuid.clone(),
                    prompt: prompt_uuid.clone(),
                    format,
                }
            }
            Some(PromptsCommand::Add(add)) => {
                rt::check_uuid("prompt set uuid", &add.set_uuid)?;
                let mut body =
                    serde_json::json!({ "prompt": add.prompt, "prompt_set_id": add.set_uuid });
                if let Some(goal) = add.goal.as_deref().filter(|goal| !goal.is_empty()) {
                    body["goal"] = serde_json::json!(goal);
                }
                RtPlan::PromptAdd {
                    body: planned_body(
                        body,
                        "POST",
                        "/v1/custom-attack/custom-prompt-set/custom-prompt",
                        rtm::CustomPromptCreateRequest::parse,
                    )?,
                    format: pretty,
                }
            }
            Some(PromptsCommand::Update(update)) => {
                rt::check_uuid("prompt set uuid", &update.set_uuid)?;
                rt::check_uuid("prompt uuid", &update.prompt_uuid)?;
                let mut body = serde_json::Map::new();
                for (key, value) in [("prompt", &update.prompt), ("goal", &update.goal)] {
                    if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
                        body.insert(key.to_owned(), serde_json::json!(value));
                    }
                }
                if body.is_empty() {
                    return Err(CliError::usage("Specify --prompt and/or --goal to update"));
                }
                RtPlan::PromptUpdate {
                    set: update.set_uuid.clone(),
                    prompt: update.prompt_uuid.clone(),
                    body: planned_body(
                        serde_json::Value::Object(body),
                        "PUT",
                        &format!(
                            "/v1/custom-attack/custom-prompt-set/{}/custom-prompt/{}",
                            update.set_uuid, update.prompt_uuid
                        ),
                        rtm::CustomPromptUpdateRequest::parse,
                    )?,
                    format: pretty,
                }
            }
            Some(PromptsCommand::Delete(delete)) => {
                rt::check_uuid("prompt set uuid", &delete.set_uuid)?;
                rt::check_uuid("prompt uuid", &delete.prompt_uuid)?;
                gate(
                    delete.force,
                    interactive(),
                    &format!("delete prompt {}", delete.prompt_uuid),
                )?;
                RtPlan::PromptDelete {
                    set: delete.set_uuid.clone(),
                    prompt: delete.prompt_uuid.clone(),
                    force: delete.force,
                }
            }
        },
        RedteamCommand::Properties(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "properties"])),
            Some(PropertiesCommand::List(flags)) => RtPlan::PropertyList {
                params: client_list(flags)?,
                format,
            },
            Some(PropertiesCommand::Values { name }) => {
                crate::segment::check_segment("property name", name)?;
                RtPlan::PropertyValues {
                    name: name.clone(),
                    format,
                }
            }
            Some(PropertiesCommand::Create(create)) => RtPlan::PropertyCreate(planned_body(
                serde_json::json!({ "name": create.name }),
                "POST",
                "/v1/custom-attack/property-names",
                rtm::PropertyNameCreateRequest::parse,
            )?),
            Some(PropertiesCommand::AddValue(add)) => RtPlan::PropertyAddValue(planned_body(
                serde_json::json!({ "property_name": add.name, "property_value": add.value }),
                "POST",
                "/v1/custom-attack/property-values",
                rtm::PropertyValueCreateRequest::parse,
            )?),
        },
        RedteamCommand::Targets(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "targets"])),
            Some(TargetsCommand::Backup(backup)) => {
                let file_format = backup.file_format.as_deref().or(backup.format.as_deref());
                if file_format.is_some_and(|value| value != "json") {
                    return Err(CliError::usage(
                        "--file-format must be json (yaml was dropped)",
                    ));
                }
                if backup.name.as_deref() == Some("") {
                    return Err(CliError::usage("--name needs a target name"));
                }
                if backup.output_dir.as_ref().is_some_and(|dir| dir.is_empty()) {
                    return Err(CliError::usage("--output-dir needs a path"));
                }
                RtPlan::Backup {
                    dir: backup.output_dir.clone(),
                    name: backup.name.clone(),
                    format: pretty,
                }
            }
            Some(TargetsCommand::Restore(restore)) => {
                if restore.input_dir.is_some() {
                    return Err(CliError::usage(
                        "--input-dir is not supported: an airs backup is one file; pass --file <backup>",
                    ));
                }
                let file = match &restore.file {
                    Some(file) if !file.is_empty() => file.clone(),
                    _ => return Err(CliError::usage("Specify --file <path>")),
                };
                if restore.dry_run && restore.force {
                    return Err(CliError::usage("--dry-run cannot be combined with --force"));
                }
                if restore.overwrite && !restore.dry_run {
                    gate(restore.force, interactive(), "overwrite targets")?;
                }
                RtPlan::Restore(Box::new(RestorePlan {
                    file,
                    overwrite: restore.overwrite,
                    validate: restore.validate,
                    dry_run: restore.dry_run,
                    force: restore.force,
                    allow_other_tenant: restore.allow_other_tenant,
                    format: pretty,
                }))
            }
            Some(TargetsCommand::List(flags)) => RtPlan::TargetList {
                params: client_list(flags)?,
                format,
            },
            Some(TargetsCommand::Get { uuid }) => {
                rt::check_uuid("target uuid", uuid)?;
                RtPlan::TargetGet {
                    uuid: uuid.clone(),
                    format,
                }
            }
            Some(TargetsCommand::Profile { uuid }) => {
                rt::check_uuid("target uuid", uuid)?;
                RtPlan::TargetProfile {
                    uuid: uuid.clone(),
                    format: pretty,
                }
            }
            Some(TargetsCommand::Metadata) => RtPlan::TargetMetadata(pretty),
            Some(TargetsCommand::Templates) => RtPlan::TargetTemplates(pretty),
            Some(TargetsCommand::ErrorLogs(args)) => {
                // The vendor contract declares only `limit`, at most 100 (D300, D301).
                let limit = args
                    .limit
                    .as_deref()
                    .map(|value| {
                        rt::bounded_positive("--limit", value, LimitText::Typescript, rt::MAX_PAGE)
                    })
                    .transpose()?;
                for (flag, given) in [
                    ("--offset", args.offset.is_some()),
                    ("--search", args.search.is_some()),
                ] {
                    rt::refuse_option(flag, given, "target error logs", "--limit")?;
                }
                rt::check_uuid("target id", &args.target_id)?;
                RtPlan::ErrorLogs {
                    target: args.target_id.clone(),
                    limit,
                    format: pretty,
                }
            }
            Some(TargetsCommand::Create(create)) => RtPlan::TargetWrite {
                kind: TargetWrite::Create,
                config: create.config.clone(),
                validate: create.validate,
                format: pretty,
            },
            Some(TargetsCommand::Update(update)) => {
                rt::check_uuid("target uuid", &update.uuid)?;
                RtPlan::TargetWrite {
                    kind: TargetWrite::Update(update.uuid.clone()),
                    config: update.config.clone(),
                    validate: update.validate,
                    format: pretty,
                }
            }
            Some(TargetsCommand::Probe(probe)) => RtPlan::TargetWrite {
                kind: TargetWrite::Probe,
                config: probe.config.clone(),
                validate: false,
                format: pretty,
            },
            Some(TargetsCommand::UpdateProfile(update)) => {
                rt::check_uuid("target uuid", &update.uuid)?;
                RtPlan::TargetWrite {
                    kind: TargetWrite::UpdateProfile(update.uuid.clone()),
                    config: update.config.clone(),
                    validate: false,
                    format: pretty,
                }
            }
            Some(TargetsCommand::Delete(delete)) => {
                // The gate before the id check (TS order, D137).
                gate(
                    delete.force,
                    interactive(),
                    &format!("delete target {}", delete.uuid),
                )?;
                rt::check_uuid("target uuid", &delete.uuid)?;
                RtPlan::TargetDelete {
                    uuid: delete.uuid.clone(),
                    force: delete.force,
                }
            }
            Some(TargetsCommand::ValidateAuth(validate)) => {
                if !matches!(
                    validate.auth_type.as_str(),
                    "HEADERS" | "BASIC_AUTH" | "OAUTH2"
                ) {
                    return Err(CliError::usage(
                        "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/target/validate-auth did not match schema: auth_type: invalid_enum_value",
                    ));
                }
                if let Some(target) = &validate.target_id {
                    rt::check_uuid("target id", target)?;
                }
                RtPlan::ValidateAuth {
                    auth_type: validate.auth_type.clone(),
                    config: validate.config.clone(),
                    target_id: validate.target_id.clone(),
                    format: pretty,
                }
            }
            Some(TargetsCommand::Init(init)) => {
                let key = args::provider(&init.provider)?;
                let given = match &init.output_file {
                    Some(path) if path.is_empty() => {
                        return Err(CliError::usage("--output-file needs a path"));
                    }
                    Some(path) => path.clone(),
                    None => OsString::from(format!("{}-target.json", init.provider.to_lowercase())),
                };
                let path = std::path::absolute(&given).map_err(|_| {
                    CliError::operational(format!(
                        "Cannot write {}; check that its directory exists and is writable",
                        crate::files::shown(&given)
                    ))
                })?;
                RtPlan::TargetInit {
                    key,
                    path,
                    given: crate::files::shown(&given),
                    format: pretty,
                }
            }
        },
        RedteamCommand::Adapter(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "adapter"])),
            Some(AdapterCommand::List(args)) => {
                let search = rt::query_filter("--search", args.search.as_deref())?;
                let params = rt::list_params(
                    args.limit.as_deref(),
                    args.offset.as_deref(),
                    args.all,
                    args.max.as_deref(),
                    LimitText::Typescript,
                )?;
                RtPlan::AdapterList {
                    params,
                    search,
                    format,
                }
            }
            Some(AdapterCommand::Get { uuid }) => {
                rt::check_uuid("adapter uuid", uuid)?;
                RtPlan::AdapterGet {
                    uuid: uuid.clone(),
                    format,
                }
            }
            Some(AdapterCommand::Create(create)) => {
                let script = args::script(
                    create.script.script_file.as_deref(),
                    create.script.script_b64.as_deref(),
                    true,
                )?;
                let variables = args::variables(
                    create.variables.as_deref(),
                    create.variables_file.as_deref(),
                )?;
                if let Some(channel) = &create.channel {
                    rt::check_uuid("channel id", channel)?;
                }
                RtPlan::Adapter(Box::new(AdapterPlan {
                    kind: AdapterKind::Create,
                    name: Some(create.name.clone()),
                    prompt: create.prompt.clone(),
                    script,
                    description: create.description.clone(),
                    channel: create.channel.clone(),
                    variables,
                    draft: create.draft,
                    format: pretty,
                }))
            }
            Some(AdapterCommand::Update(update)) => {
                rt::check_uuid("adapter uuid", &update.uuid)?;
                let script = args::script(
                    update.script.script_file.as_deref(),
                    update.script.script_b64.as_deref(),
                    false,
                )?;
                let variables = args::variables(
                    update.variables.as_deref(),
                    update.variables_file.as_deref(),
                )?;
                if let Some(channel) = &update.channel {
                    rt::check_uuid("channel id", channel)?;
                }
                RtPlan::Adapter(Box::new(AdapterPlan {
                    kind: AdapterKind::Update(update.uuid.clone()),
                    name: update.name.clone(),
                    prompt: update.prompt.clone(),
                    script,
                    description: update.description.clone(),
                    channel: update.channel.clone(),
                    variables,
                    draft: update.draft,
                    format: pretty,
                }))
            }
            Some(AdapterCommand::Validate(validate)) => {
                let script = args::script(
                    validate.script.script_file.as_deref(),
                    validate.script.script_b64.as_deref(),
                    true,
                )?;
                let variables = args::variables(
                    validate.variables.as_deref(),
                    validate.variables_file.as_deref(),
                )?;
                rt::check_uuid("channel id", &validate.channel)?;
                if let Some(adapter) = &validate.adapter {
                    rt::check_uuid("adapter uuid", adapter)?;
                }
                RtPlan::Adapter(Box::new(AdapterPlan {
                    kind: AdapterKind::Validate(validate.adapter.clone()),
                    name: None,
                    prompt: validate.prompt.clone(),
                    script,
                    description: None,
                    channel: Some(validate.channel.clone()),
                    variables,
                    draft: false,
                    format: pretty,
                }))
            }
            Some(AdapterCommand::Delete(delete)) => {
                // The gate before the id check (TS order, D137).
                gate(
                    delete.force,
                    interactive(),
                    &format!("delete adapter {}", delete.uuid),
                )?;
                rt::check_uuid("adapter uuid", &delete.uuid)?;
                RtPlan::AdapterDelete {
                    uuid: delete.uuid.clone(),
                    force: delete.force,
                }
            }
        },
        RedteamCommand::NetworkBroker(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["redteam", "network-broker"])),
            Some(NetworkBrokerCommand::Stats) => RtPlan::Stats(format),
            Some(NetworkBrokerCommand::Channels(channels)) => match &channels.command {
                None => {
                    return Ok(Plan::GroupHelp(&["redteam", "network-broker", "channels"]));
                }
                Some(ChannelsCommand::List(args)) => {
                    let search = rt::query_filter("--search", args.paging.search.as_deref())?;
                    let statuses = rt::statuses(&args.status)?;
                    let params = rt::list_params(
                        args.paging.limit.as_deref(),
                        args.paging.offset.as_deref(),
                        args.paging.all,
                        args.paging.max.as_deref(),
                        LimitText::Typescript,
                    )?;
                    RtPlan::ChannelList {
                        params,
                        search,
                        statuses,
                        format,
                    }
                }
                Some(ChannelsCommand::Get { channel_id }) => {
                    rt::check_uuid("channel id", channel_id)?;
                    RtPlan::ChannelGet {
                        id: channel_id.clone(),
                        format,
                    }
                }
                Some(ChannelsCommand::Create(create)) => {
                    let units = create.name.encode_utf16().count();
                    let schema = "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/channels did not match schema";
                    if units < 1 {
                        return Err(CliError::usage(format!("{schema}: name: too_small")));
                    }
                    if units > 64 {
                        return Err(CliError::usage(format!("{schema}: name: too_big")));
                    }
                    let mut body = serde_json::json!({ "name": create.name });
                    if let Some(description) = &create.description {
                        body["description"] = serde_json::json!(description);
                    }
                    RtPlan::ChannelWrite {
                        id: None,
                        body: planned_body(
                            body,
                            "POST",
                            "/v1/channels",
                            rtm::CreateChannelRequest::parse,
                        )?,
                        format: pretty,
                    }
                }
                Some(ChannelsCommand::Update(update)) => {
                    if update.name.is_none() && update.description.is_none() {
                        return Err(CliError::usage(
                            "Specify --name and/or --description to update",
                        ));
                    }
                    rt::check_uuid("channel id", &update.channel_id)?;
                    let mut body = serde_json::Map::new();
                    for (key, value) in
                        [("name", &update.name), ("description", &update.description)]
                    {
                        if let Some(value) = value {
                            body.insert(key.to_owned(), serde_json::json!(value));
                        }
                    }
                    RtPlan::ChannelWrite {
                        id: Some(update.channel_id.clone()),
                        body: planned_body(
                            serde_json::Value::Object(body),
                            "PATCH",
                            &format!("/v1/channels/{}", update.channel_id),
                            rtm::UpdateChannelRequest::parse,
                        )?,
                        format: pretty,
                    }
                }
            },
        },
    };
    Ok(Plan::RedTeam(Box::new(plan)))
}

/// The environment report's checks (§15.17, in TS order) and its destination.
fn env_report_plan(
    report: &crate::cli::ReportArgs,
    explicit: Option<&str>,
    debug: bool,
) -> Result<EnvReportPlan, CliError> {
    if debug {
        return Err(CliError::usage(
            "Disable --debug for environment reports to avoid persisting sensitive traffic content",
        ));
    }
    if report.attacks || report.severity.is_some() || report.limit.is_some() {
        return Err(CliError::usage(
            "--attacks, --severity and --limit require a scan job ID",
        ));
    }
    if explicit.is_some() {
        return Err(CliError::usage(
            "The environment report is written as HTML; omit --output",
        ));
    }
    let max_pages = report.max_pages.as_deref().unwrap_or("40");
    let pages = (!max_pages.is_empty()
        && !max_pages.starts_with('0')
        && max_pages.bytes().all(|byte| byte.is_ascii_digit()))
    .then(|| max_pages.parse::<u32>().ok())
    .flatten()
    .filter(|pages| (1..=100).contains(pages))
    .ok_or_else(|| CliError::usage("--max-pages must be an integer from 1 to 100"))?;
    let title = report
        .title
        .clone()
        .unwrap_or_else(|| "Red Team environment report".to_owned());
    if crate::tenant::config::js_trim(&title).is_empty() || title.encode_utf16().count() > 240 {
        return Err(CliError::usage("--title must contain 1–240 characters"));
    }
    let destination = match &report.output_file {
        Some(path) if crate::tenant::config::js_trim(&path.to_string_lossy()).is_empty() => {
            return Err(CliError::usage("--output-file cannot be empty"));
        }
        Some(path) if path == "-" => ReportDestination::Stdout,
        Some(path) => ReportDestination::File(PathBuf::from(path)),
        None => ReportDestination::File(PathBuf::from(super::redteam_report::default_name(
            std::time::SystemTime::now(),
        ))),
    };
    Ok(EnvReportPlan {
        destination,
        title,
        max_pages: pages,
        strict: report.strict,
    })
}

/// The client-side list flags (`--limit must be a positive integer`).
fn client_list(flags: &crate::cli::ClientListFlags) -> Result<ListParams, CliError> {
    rt::list_params(
        flags.limit.as_deref(),
        flags.offset.as_deref(),
        flags.all,
        flags.max.as_deref(),
        LimitText::Contract,
    )
}

/// Run a red team plan.
pub async fn dispatch(invocation: &mut Invocation, plan: RtPlan) -> Result<(), CliError> {
    use super::{redteam_adapters as adapters, redteam_custom as custom};
    use super::{redteam_infra as infra, redteam_scan as scan, redteam_targets as targets};
    match plan {
        RtPlan::ScanList {
            filters,
            params,
            format,
        } => scan::list(invocation, &filters, &params, format).await,
        RtPlan::Status { job_id, format } => scan::status(invocation, &job_id, format).await,
        RtPlan::Categories(format) => scan::categories(invocation, format).await,
        RtPlan::Languages { management, format } => {
            scan::languages(invocation, management, format).await
        }
        RtPlan::EulaStatus(format) => infra::eula_status(invocation, format).await,
        RtPlan::EulaContent(format) => infra::eula_content(invocation, format).await,
        RtPlan::InstanceGet { tenant_id, format } => {
            infra::instance_get(invocation, &tenant_id, format).await
        }
        RtPlan::ChannelList {
            params,
            search,
            statuses,
            format,
        } => infra::channel_list(invocation, &params, search, statuses, format).await,
        RtPlan::ChannelGet { id, format } => infra::channel_get(invocation, &id, format).await,
        RtPlan::Stats(format) => infra::stats(invocation, format).await,
        RtPlan::PromptSetList { params, format } => {
            custom::prompt_set_list(invocation, &params, format).await
        }
        RtPlan::PromptSetGet { uuid, format } => {
            custom::prompt_set_get(invocation, &uuid, format).await
        }
        RtPlan::Download { uuid, destination } => {
            custom::download(invocation, &uuid, &destination).await
        }
        RtPlan::PromptList {
            set,
            params,
            format,
        } => custom::prompt_list(invocation, &set, &params, format).await,
        RtPlan::PromptGet {
            set,
            prompt,
            format,
        } => custom::prompt_get(invocation, &set, &prompt, format).await,
        RtPlan::PropertyList { params, format } => {
            custom::property_list(invocation, &params, format).await
        }
        RtPlan::PropertyValues { name, format } => {
            custom::property_values(invocation, &name, format).await
        }
        RtPlan::TargetList { params, format } => targets::list(invocation, &params, format).await,
        RtPlan::TargetGet { uuid, format } => targets::get(invocation, &uuid, format).await,
        RtPlan::TargetProfile { uuid, format } => targets::profile(invocation, &uuid, format).await,
        RtPlan::TargetMetadata(format) => targets::metadata(invocation, format).await,
        RtPlan::TargetTemplates(format) => targets::templates(invocation, format).await,
        RtPlan::ErrorLogs {
            target,
            limit,
            format,
        } => targets::error_logs(invocation, &target, limit, format).await,
        RtPlan::AdapterList {
            params,
            search,
            format,
        } => adapters::list(invocation, &params, search, format).await,
        RtPlan::AdapterGet { uuid, format } => adapters::get(invocation, &uuid, format).await,
        RtPlan::Scan { spec, format } => scan::scan(invocation, &spec, format).await,
        RtPlan::Abort { job_id, force } => scan::abort(invocation, &job_id, force).await,
        RtPlan::EulaAccept { force, format } => infra::eula_accept(invocation, force, format).await,
        RtPlan::RegistryCredentials(format) => {
            infra::registry_credentials(invocation, format).await
        }
        RtPlan::InstanceWrite { kind, body, format } => {
            infra::instance_write(invocation, &kind, &body, format).await
        }
        RtPlan::InstanceDelete {
            tenant_id,
            force,
            format,
        } => infra::instance_delete(invocation, &tenant_id, force, format).await,
        RtPlan::Devices {
            kind,
            tenant_id,
            config,
            format,
        } => infra::devices(invocation, kind, &tenant_id, &config, format).await,
        RtPlan::DevicesDelete {
            tenant_id,
            serials,
            force,
            format,
        } => infra::devices_delete(invocation, &tenant_id, &serials, force, format).await,
        RtPlan::PromptSetCreate { body, format } => {
            custom::prompt_set_create(invocation, &body, format).await
        }
        RtPlan::PromptSetUpdate { uuid, body, format } => {
            custom::prompt_set_update(invocation, &uuid, &body, format).await
        }
        RtPlan::PromptSetArchive { uuid, archive } => {
            custom::prompt_set_archive(invocation, &uuid, archive).await
        }
        RtPlan::Upload { uuid, file } => custom::upload(invocation, &uuid, &file).await,
        RtPlan::PromptAdd { body, format } => custom::prompt_add(invocation, &body, format).await,
        RtPlan::PromptUpdate {
            set,
            prompt,
            body,
            format,
        } => custom::prompt_update(invocation, &set, &prompt, &body, format).await,
        RtPlan::PromptDelete { set, prompt, force } => {
            custom::prompt_delete(invocation, &set, &prompt, force).await
        }
        RtPlan::PropertyCreate(body) => custom::property_create(invocation, &body).await,
        RtPlan::PropertyAddValue(body) => custom::property_add_value(invocation, &body).await,
        RtPlan::TargetWrite {
            kind,
            config,
            validate,
            format,
        } => targets::write(invocation, &kind, &config, validate, format).await,
        RtPlan::TargetDelete { uuid, force } => targets::delete(invocation, &uuid, force).await,
        RtPlan::ValidateAuth {
            auth_type,
            config,
            target_id,
            format,
        } => {
            targets::validate_auth(
                invocation,
                &auth_type,
                &config,
                target_id.as_deref(),
                format,
            )
            .await
        }
        RtPlan::TargetInit {
            key,
            path,
            given,
            format,
        } => targets::init(invocation, &key, &path, &given, format).await,
        RtPlan::Adapter(plan) => adapters::write(invocation, &plan).await,
        RtPlan::AdapterDelete { uuid, force } => adapters::delete(invocation, &uuid, force).await,
        RtPlan::ChannelWrite { id, body, format } => {
            infra::channel_write(invocation, id.as_deref(), &body, format).await
        }
        RtPlan::JobReport {
            job_id,
            attacks,
            severity,
            limit,
            format,
        } => {
            super::redteam_report::job_report(
                invocation,
                &job_id,
                attacks,
                severity.as_deref(),
                limit,
                format,
            )
            .await
        }
        RtPlan::EnvReport(plan) => {
            super::redteam_report::environment_report(invocation, &plan).await
        }
        RtPlan::Backup { dir, name, format } => {
            super::redteam_backup::backup(invocation, dir.as_deref(), name.as_deref(), format).await
        }
        RtPlan::Restore(plan) => super::redteam_backup::restore(invocation, &plan).await,
    }
}

/// A connected red team client and the tenant's `defaultOutput`.
pub struct Connected {
    pub client: RedTeamClient,
    pub default_output: Option<String>,
}

impl Connected {
    /// The format of a read that honours `defaultOutput`.
    pub fn format(&self, explicit: Option<Format>) -> Format {
        output::resolve_tenant_default(explicit, self.default_output.as_deref())
    }
}

impl Invocation {
    /// Load the tenant, check the management credentials (§3.5), build the red team
    /// client from the tenant's endpoints (§15.3) and fetch the OAuth token under
    /// `options` (a walk's shared deadline; `None`: the SDK's token budget).
    pub async fn connect_red_team(
        &mut self,
        options: Option<&scm::RequestOptions>,
    ) -> Result<Connected, CliError> {
        let context = self.load_tenant()?;
        let default_output = context.config.default_output().map(str::to_owned);
        crate::tenant::config::require_management(&context.config, Some(context.name()))?;
        let clients = RedTeamClients::build(
            &context.config,
            &self.session,
            &self.secrets,
            self.debug.as_ref(),
        )?;
        let budget = if options.is_some() {
            WALK_BUDGET
        } else {
            TOKEN_BUDGET
        };
        clients.authenticate(options, budget).await?;
        Ok(Connected {
            client: clients.red_team,
            default_output,
        })
    }
}

/// The SDK-model conversions, feature-neutral in `crate::json` (re-exported for the
/// red team, DLP and model-security commands).
pub use crate::json::{model_value as value, page_value};

/// The rows (`data`, `[]` when absent) and `pagination.total_items` of a list answer.
pub fn page_of(answer: &OValue) -> Page<OValue> {
    let rows = answer
        .get("data")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .to_vec();
    let total = answer
        .get("pagination")
        .and_then(|pagination| crate::json::number(pagination, "total_items"));
    Page::new(rows, walk::total_of(total))
}

/// Run a single red team read under the SDK's per-request budget.
pub async fn read<T>(
    invocation: &Invocation,
    call: impl Future<Output = scm::Result<T>>,
) -> Result<T, CliError> {
    call.await
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))
}

/// The options of one typed target operation whose document is printed or stored
/// (D153): the SDK's per-request budget (what `None` gives, retries unchanged) with the
/// typed response validated without the frozen schema defaults (scm-sdk 0.1.1), so the
/// document holds only the fields the server sent.
pub fn target_options() -> scm::Result<scm::RequestOptions> {
    Ok(scm::RequestOptions::with_timeout(SINGLE_REQUEST_BUDGET)?.without_response_defaults())
}

/// Walk every page (`page(skip, limit)` sends one) under the walk budget; prints the
/// `--max` status line when `--max` stopped it (D14 text).
pub async fn walk_all<F, Fut>(
    invocation: &mut Invocation,
    limit: u32,
    max: u64,
    status_line: bool,
    page: F,
) -> Result<Vec<OValue>, CliError>
where
    F: FnMut(u64, u32) -> Fut,
    Fut: Future<Output = Result<Page<OValue>, scm::Error>>,
{
    let walked: Walked<OValue> = walk::walk(
        limit,
        max,
        page,
        |row| crate::json::to_compact(row).map_or(0, |text| text.len()),
        |row| {
            row.get("uuid")
                .and_then(OValue::as_str)
                .filter(|uuid| !uuid.is_empty())
                .map(str::to_owned)
        },
    )
    .await
    .map_err(|error| invocation.management_error(&error, WALK_BUDGET))?;
    if status_line && walked.stopped_at_max {
        invocation
            .output
            .status(&crate::pagination::showing_first(walked.rows.len(), max));
    }
    Ok(walked.rows)
}

/// The shared deadline of a walk (its token request included, §5).
pub fn walk_deadline() -> Result<scm::RequestOptions, CliError> {
    walk_options()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::FromArgMatches;

    fn plan_of(args: &[&str]) -> Result<Plan, CliError> {
        let mut full = vec!["airs"];
        full.extend_from_slice(args);
        let matches = crate::cli::command().try_get_matches_from(&full).unwrap();
        super::super::plan(&crate::cli::Cli::from_arg_matches(&matches).unwrap())
    }

    fn rt_plan(args: &[&str]) -> RtPlan {
        match plan_of(args) {
            Ok(Plan::RedTeam(plan)) => *plan,
            Ok(_) => panic!("not a red team plan"),
            Err(error) => panic!("{args:?}: {error:?}"),
        }
    }

    fn usage(args: &[&str]) -> String {
        match plan_of(args) {
            Err(CliError::Usage(message)) => message,
            Err(other) => panic!("expected a usage error, got {other:?}"),
            Ok(_) => panic!("{args:?}: expected a usage error"),
        }
    }

    #[test]
    fn output_is_checked_before_the_tenant_flag_and_the_arguments() {
        assert_eq!(
            usage(&[
                "--tenant", "-bad", "redteam", "status", "nope", "--output", "yaml"
            ]),
            "Invalid output format 'yaml'. Expected: pretty, table, json"
        );
        assert!(
            usage(&["--tenant", "-bad", "redteam", "status", "nope"])
                .starts_with("Tenant name must be")
        );
        assert_eq!(
            usage(&["redteam", "status", "nope"]),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: nope"
        );
    }

    #[test]
    fn id_segment_filter_and_number_checks() {
        let id = "00000000-0000-4000-8000-000000000101";
        for (args, message) in [
            (
                &["redteam", "prompt-sets", "get", "x"][..],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid prompt set uuid: x",
            ),
            (
                &["redteam", "prompts", "get", id, "y"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid prompt uuid: y",
            ),
            (
                &["redteam", "prompts", "ls", "z"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid prompt set uuid: z",
            ),
            (
                &["redteam", "targets", "get", "t"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid target uuid: t",
            ),
            (
                &["redteam", "targets", "profile", "t"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid target uuid: t",
            ),
            (
                &["redteam", "targets", "error-logs", "t"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid target id: t",
            ),
            (
                &["redteam", "adapter", "get", "a"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid adapter uuid: a",
            ),
            (
                &["redteam", "network-broker", "channels", "get", "c"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid channel id: c",
            ),
            (
                &["redteam", "instances", "get", "../registry-credentials"],
                "Invalid tenant id: ../registry-credentials",
            ),
            (
                &["redteam", "properties", "values", ".."],
                "Invalid property name: ..",
            ),
            (
                &["redteam", "list", "--limit", "0"],
                "--limit must be a positive integer",
            ),
            (
                &["redteam", "list", "--offset", "-1"],
                "--offset must be a non-negative integer",
            ),
            (
                &["redteam", "list", "--all", "--offset", "0"],
                "--all cannot be combined with --offset",
            ),
            (
                &["redteam", "list", "--status", "a\tb"],
                "--status must be at most 4096 bytes and contain no control characters",
            ),
            (
                &["redteam", "adapter", "list", "--limit", "2.5x"],
                "--limit: expected a positive integer, got \"2.5x\"",
            ),
            (
                &["redteam", "targets", "error-logs", id, "--limit", "0"],
                "--limit: expected a positive integer, got \"0\"",
            ),
            (
                &[
                    "redteam",
                    "network-broker",
                    "channels",
                    "list",
                    "--status",
                    "",
                ],
                "--status values must not be empty",
            ),
            (
                &[
                    "redteam",
                    "prompt-sets",
                    "download",
                    id,
                    "--output-file",
                    "",
                ],
                "--output-file needs a path",
            ),
            (
                &["redteam", "targets", "list", "--max", "x"],
                "--max must be a non-negative integer",
            ),
        ] {
            assert_eq!(usage(args), message, "{args:?}");
        }
    }

    /// Step 2: the D81 gates come in the section order (the id first, except for the
    /// target and adapter deletes, TS order), and the write plans carry their
    /// interruption contexts.
    #[test]
    fn write_plans_gate_in_order_and_carry_their_contexts() {
        let id = "00000000-0000-4000-8000-000000000102";
        assert_eq!(
            usage(&["redteam", "abort", "x"]),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: x"
        );
        assert_eq!(
            usage(&["redteam", "targets", "rm", "x"]),
            "refusing to delete target x without --force in non-interactive mode"
        );
        assert_eq!(
            usage(&["redteam", "adapter", "delete", "x"]),
            "refusing to delete adapter x without --force in non-interactive mode"
        );
        assert_eq!(
            usage(&["redteam", "eula", "accept"]),
            "refusing to accept the Red Team EULA without --force in non-interactive mode"
        );
        let abort = rt_plan(&["redteam", "abort", id, "--force"]);
        assert_eq!(abort.interrupt_context(), InterruptContext::NothingChanged);
        let scan = rt_plan(&[
            "redteam",
            "scan",
            "--target",
            id,
            "--name",
            "nightly",
            "--no-wait",
        ]);
        assert_eq!(
            scan.interrupt_context(),
            InterruptContext::Context("no scan was started".into())
        );
        let init = rt_plan(&["redteam", "targets", "init", "rest"]);
        assert_eq!(init.interrupt_context(), InterruptContext::NoFileWritten);
        assert!(matches!(
            rt_plan(&["redteam", "eula", "accept", "--confirm"]),
            RtPlan::EulaAccept { force: true, .. }
        ));
        assert!(matches!(
            rt_plan(&["redteam", "registry-credentials"]),
            RtPlan::RegistryCredentials(None)
        ));
    }

    #[test]
    fn plans_carry_their_formats_and_contexts() {
        let id = "00000000-0000-4000-8000-000000000301";
        assert_eq!(
            rt_plan(&["redteam", "ls", "--status", "COMPLETED", "--limit", "5"]),
            RtPlan::ScanList {
                filters: ScanFilters {
                    status: Some("COMPLETED".into()),
                    ..ScanFilters::default()
                },
                params: ListParams {
                    limit: Some(5),
                    offset: None,
                    all: false,
                    max: 10_000
                },
                format: None
            }
        );
        assert_eq!(
            rt_plan(&["redteam", "categories", "--output", "json"]),
            RtPlan::Categories(Format::Json)
        );
        assert_eq!(
            rt_plan(&["redteam", "eula", "status"]),
            RtPlan::EulaStatus(Format::Pretty)
        );
        let download = rt_plan(&["redteam", "prompt-sets", "download", id]);
        assert_eq!(
            download,
            RtPlan::Download {
                uuid: id.into(),
                destination: Destination::File(PathBuf::from(format!("{id}-template.csv")))
            }
        );
        assert_eq!(
            download.interrupt_context(),
            InterruptContext::NoFileWritten
        );
        assert_eq!(
            rt_plan(&[
                "redteam",
                "prompt-sets",
                "download",
                id,
                "--output-file",
                "-"
            ]),
            RtPlan::Download {
                uuid: id.into(),
                destination: Destination::Stdout
            }
        );
        let channels = rt_plan(&[
            "redteam",
            "network-broker",
            "channels",
            "ls",
            "--status",
            "ONLINE",
            "OFFLINE",
            "--search",
            "s",
        ]);
        assert_eq!(
            channels,
            RtPlan::ChannelList {
                params: ListParams::none(),
                search: Some("s".into()),
                statuses: vec!["ONLINE".into(), "OFFLINE".into()],
                format: None
            }
        );
        assert_eq!(
            channels.interrupt_context(),
            InterruptContext::NoDataWritten
        );
        for group in [
            &["redteam"][..],
            &["redteam", "eula"],
            &["redteam", "targets"],
            &["redteam", "network-broker", "channels"],
        ] {
            assert!(
                matches!(plan_of(group), Ok(Plan::GroupHelp(_))),
                "{group:?}"
            );
        }
    }
}
