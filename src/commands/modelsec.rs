//! `model-security` planning and dispatch (DESIGN §17). Planning runs every argument
//! check of §17.3 before the tenant is read (D184); dispatch connects the model-security
//! client from the tenant's `modelSecDataEndpoint` and `modelSecMgmtEndpoint` and runs the
//! command.
//!
//! Step 1 (§17.1) plans the reads: the lists and gets of groups, rules, rule instances,
//! scans (with their evaluations, violations and files), models and their versions, and
//! the label keys and values. Step 2 plans the writes: `groups create|update|delete`,
//! `rule-instances update`, `scans create` and `labels add|set|delete`, with their
//! bodies built from arguments and their non-interactive confirmation refusals (D185)
//! checked here; `--config` files are read at dispatch, after the debug log and before the
//! tenant (D188). Step 3 plans `pypi-auth` (the `--url-file` argument checks) and
//! `install` (`--extras`, `--dir` and the debug-build `--fetch-uv` test hook).

use super::{Invocation, Plan};
use crate::cli::{
    ModelSecCommand, ModelSecGroup, MsGroupsCommand, MsLabelsCommand, MsModelsCommand,
    MsRuleInstancesCommand, MsRulesCommand, MsScansCommand,
};
use crate::clients::{ModelSecurityClients, TOKEN_BUDGET, WALK_BUDGET};
use crate::error::{CliError, InterruptContext};
use crate::modelsec::{self, Paging, Window};
use crate::output::{self, Format};
use crate::walk::ListParams;
use std::ffi::OsString;

/// A model-security list (§17.4–§17.7) and its filters, validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsList {
    Groups {
        source_types: Option<Vec<String>>,
        search: Option<String>,
        sort_field: Option<String>,
        sort_dir: Option<String>,
        enabled_rules: Option<Vec<String>>,
    },
    Rules {
        source_type: Option<String>,
        search: Option<String>,
    },
    RuleInstances {
        group: String,
        security_rule_uuid: Option<String>,
        state: Option<String>,
    },
    Scans {
        window: Window,
        eval_outcome: Option<String>,
        source_type: Option<String>,
        /// A non-empty `--scan-origin`: the client-filtered list (D181).
        scan_origin: Option<String>,
        search: Option<String>,
    },
    Evaluations {
        scan: String,
    },
    Violations {
        scan: String,
    },
    Files {
        scan: String,
        file_type: Option<String>,
        result: Option<String>,
    },
    Models {
        window: Window,
        search: Option<String>,
        search_query: Option<String>,
        sort_field: Option<String>,
        sort_order: Option<String>,
    },
    Versions {
        model: String,
        sort_order: Option<String>,
    },
    ModelFiles {
        version: String,
    },
    LabelKeys,
    LabelValues {
        key: String,
    },
}

impl MsList {
    /// How a single page sends `skip` and `limit` (§17.3).
    pub fn paging(&self) -> Paging {
        match self {
            Self::Groups { .. } | Self::Rules { .. } | Self::Scans { .. } => Paging::Always,
            Self::RuleInstances { .. }
            | Self::Evaluations { .. }
            | Self::Violations { .. }
            | Self::Files { .. }
            | Self::LabelKeys
            | Self::LabelValues { .. } => Paging::LimitAlways,
            Self::Models { .. } | Self::Versions { .. } | Self::ModelFiles { .. } => {
                Paging::WhenGiven
            }
        }
    }

    /// Whether the tenant's `defaultOutput` applies (TypeScript's class A, choice 19).
    pub fn tenant_default(&self) -> bool {
        !matches!(
            self,
            Self::Evaluations { .. }
                | Self::Violations { .. }
                | Self::Files { .. }
                | Self::LabelKeys
                | Self::LabelValues { .. }
        )
    }
}

/// A model-security get (§17.4–§17.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsGet {
    Group(String),
    Rule(String),
    RuleInstance { group: String, instance: String },
    Scan(String),
    Evaluation(String),
    Violation(String),
    Model(String),
    Version(String),
}

impl MsGet {
    /// Whether the tenant's `defaultOutput` applies (TypeScript's class A, choice 19).
    pub fn tenant_default(&self) -> bool {
        !matches!(self, Self::Evaluation(_) | Self::Violation(_))
    }
}

/// A model-security write (§17.8–§17.11). Bodies built from arguments are validated
/// already (kept as their wire JSON); `--config` paths are read at dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsWrite {
    GroupCreate {
        config: OsString,
    },
    GroupUpdate {
        uuid: String,
        body: serde_json::Value,
    },
    GroupDelete {
        uuid: String,
        force: bool,
    },
    InstanceUpdate {
        group: String,
        instance: String,
        config: OsString,
    },
    ScanCreate {
        config: OsString,
    },
    LabelsAdd {
        scan: String,
        body: serde_json::Value,
    },
    LabelsSet {
        scan: String,
        body: serde_json::Value,
        force: bool,
    },
    LabelsDelete {
        scan: String,
        keys: Vec<String>,
        force: bool,
    },
}

/// A validated `model-security` invocation. `format` is the explicit `--output`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsPlan {
    List {
        list: MsList,
        params: ListParams,
        format: Option<Format>,
    },
    Get {
        get: MsGet,
        format: Option<Format>,
    },
    /// A write; the tenant's `defaultOutput` never applies (choice 19), and the writes
    /// with an empty stdout validate `--output`, then ignore it (D189).
    Write {
        write: MsWrite,
        format: Option<Format>,
    },
    /// `pypi-auth` (§17.12): `--output` honoured, the tenant default ignored (choice 19).
    PypiAuth {
        url_file: Option<OsString>,
        format: Option<Format>,
    },
    /// `install` (§17.13): `--output` validated, then ignored (choice 32).
    Install(super::modelsec_install::InstallPlan),
}

impl MsPlan {
    /// What an interruption reports (§17.3 "Interruption"): the reads write no data; a
    /// write changed nothing until it is sent (its own contexts take over from there).
    pub fn interrupt_context(&self) -> InterruptContext {
        match self {
            Self::List { .. } | Self::Get { .. } | Self::PypiAuth { .. } => {
                InterruptContext::NoDataWritten
            }
            Self::Write { .. } => InterruptContext::NothingChanged,
            Self::Install(_) => crate::modelsec::uv::nothing_installed(),
        }
    }

    /// The `--debug` policy (§2.9): every model-security command logs (status and headers
    /// only, D64).
    pub fn debug_policy(&self) -> crate::debug::DebugPolicy {
        crate::debug::DebugPolicy::Log
    }
}

fn uuid(field: &str, value: &str) -> Result<String, CliError> {
    modelsec::check_uuid(field, value)?;
    Ok(value.to_owned())
}

/// The wire JSON of a validated SDK body.
fn wire<T: serde::Serialize>(body: &T) -> Result<serde_json::Value, CliError> {
    serde_json::to_value(body)
        .map_err(|_| CliError::operational("AISEC_SDK_ERROR:The request body could not be built"))
}

/// The D81 refusal without `--force` when stdin or stderr is not a terminal (exit 2).
fn gate(force: bool, action: &str) -> Result<(), CliError> {
    super::write_common::gate_on_terminals(force, action)
}

fn filter(flag: &str, value: Option<&String>) -> Result<Option<String>, CliError> {
    modelsec::filter(flag, value.map(String::as_str))
}

fn paging(
    flags_limit: Option<&String>,
    flags_offset: Option<&String>,
    all: bool,
    max: Option<&String>,
) -> Result<ListParams, CliError> {
    modelsec::list_params(
        flags_limit.map(String::as_str),
        flags_offset.map(String::as_str),
        all,
        max.map(String::as_str),
    )
}

/// Plan a `model-security` command line; `--output` and `--tenant` were validated already
/// (§17.3 "Validation order").
pub fn plan(group: &ModelSecGroup, explicit: Option<&str>) -> Result<Plan, CliError> {
    let format = output::validate_explicit(explicit)?;
    let Some(command) = &group.command else {
        return Ok(Plan::GroupHelp(&["model-security"]));
    };
    let list = |list: MsList, params: ListParams| MsPlan::List {
        list,
        params,
        format,
    };
    let get = |get: MsGet| MsPlan::Get { get, format };
    let write = |write: MsWrite| MsPlan::Write { write, format };
    let plan = match command {
        ModelSecCommand::PypiAuth(args) => {
            if let Some(path) = &args.url_file {
                if path.is_empty() {
                    return Err(CliError::usage("--url-file needs a path"));
                }
                if path == "-" {
                    return Err(CliError::usage(
                        "--url-file - would print the credential; give a file path",
                    ));
                }
            }
            MsPlan::PypiAuth {
                url_file: args.url_file.clone(),
                format,
            }
        }
        ModelSecCommand::Install(args) => {
            let extras = args
                .extras
                .clone()
                .unwrap_or_else(|| modelsec::uv::DEFAULT_EXTRAS.to_owned());
            modelsec::uv::check_extras(&extras)?;
            let dir = args
                .dir
                .clone()
                .unwrap_or_else(|| OsString::from(modelsec::uv::DEFAULT_DIR));
            if dir.is_empty() {
                return Err(CliError::usage("--dir needs a path"));
            }
            let hook = if args.fetch_uv {
                modelsec::fetch::test_hook()?
            } else {
                None
            };
            MsPlan::Install(super::modelsec_install::InstallPlan {
                extras,
                dir,
                dry_run: args.dry_run,
                fetch_uv: args.fetch_uv,
                hook,
            })
        }
        ModelSecCommand::Groups(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["model-security", "groups"])),
            Some(MsGroupsCommand::Create(args)) => write(MsWrite::GroupCreate {
                config: args.config.clone(),
            }),
            Some(MsGroupsCommand::Update(args)) => {
                let uuid = uuid("security group uuid", &args.uuid)?;
                let body = modelsec::body::group_update(
                    &uuid,
                    args.name.as_deref(),
                    args.description.as_deref(),
                )?;
                write(MsWrite::GroupUpdate {
                    body: wire(&body)?,
                    uuid,
                })
            }
            Some(MsGroupsCommand::Delete(args)) => {
                let uuid = uuid("security group uuid", &args.uuid)?;
                gate(args.force, &format!("delete security group {uuid}"))?;
                write(MsWrite::GroupDelete {
                    uuid,
                    force: args.force,
                })
            }
            Some(MsGroupsCommand::Get(args)) => {
                get(MsGet::Group(uuid("security group uuid", &args.uuid)?))
            }
            Some(MsGroupsCommand::List(args)) => {
                let source_types =
                    modelsec::comma_list("--source-types", args.source_types.as_deref())?;
                let search = filter("--search", args.search.as_ref())?;
                let sort_field = filter("--sort-field", args.sort_field.as_ref())?;
                let sort_dir = filter("--sort-dir", args.sort_dir.as_ref())?;
                let enabled_rules =
                    modelsec::comma_list("--enabled-rules", args.enabled_rules.as_deref())?;
                let others = 2
                    + usize::from(search.is_some())
                    + usize::from(sort_field.is_some())
                    + usize::from(sort_dir.is_some());
                modelsec::check_query_values(
                    &[
                        ("--source-types", source_types.as_ref()),
                        ("--enabled-rules", enabled_rules.as_ref()),
                    ],
                    others,
                )?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(
                    MsList::Groups {
                        source_types,
                        search,
                        sort_field,
                        sort_dir,
                        enabled_rules,
                    },
                    params,
                )
            }
        },
        ModelSecCommand::Rules(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["model-security", "rules"])),
            Some(MsRulesCommand::Get(args)) => {
                get(MsGet::Rule(uuid("security rule uuid", &args.uuid)?))
            }
            Some(MsRulesCommand::List(args)) => {
                let source_type = filter("--source-type", args.source_type.as_ref())?;
                let search = filter("--search", args.search.as_ref())?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(
                    MsList::Rules {
                        source_type,
                        search,
                    },
                    params,
                )
            }
        },
        ModelSecCommand::RuleInstances(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["model-security", "rule-instances"])),
            Some(MsRuleInstancesCommand::Get(args)) => {
                let group = uuid("security group uuid", &args.group_uuid)?;
                let instance = uuid("rule instance uuid", &args.instance_uuid)?;
                get(MsGet::RuleInstance { group, instance })
            }
            Some(MsRuleInstancesCommand::Update(args)) => {
                let group = uuid("security group uuid", &args.group_uuid)?;
                let instance = uuid("rule instance uuid", &args.instance_uuid)?;
                write(MsWrite::InstanceUpdate {
                    group,
                    instance,
                    config: args.config.clone(),
                })
            }
            Some(MsRuleInstancesCommand::List(args)) => {
                let group = uuid("security group uuid", &args.group_uuid)?;
                let security_rule_uuid =
                    filter("--security-rule-uuid", args.security_rule_uuid.as_ref())?;
                let state = filter("--state", args.state.as_ref())?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(
                    MsList::RuleInstances {
                        group,
                        security_rule_uuid,
                        state,
                    },
                    params,
                )
            }
        },
        ModelSecCommand::Scans(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["model-security", "scans"])),
            Some(MsScansCommand::Get(args)) => get(MsGet::Scan(uuid("scan uuid", &args.uuid)?)),
            Some(MsScansCommand::Create(args)) => write(MsWrite::ScanCreate {
                config: args.config.clone(),
            }),
            Some(MsScansCommand::Evaluation(args)) => {
                get(MsGet::Evaluation(uuid("evaluation uuid", &args.uuid)?))
            }
            Some(MsScansCommand::Violation(args)) => {
                get(MsGet::Violation(uuid("violation uuid", &args.uuid)?))
            }
            Some(MsScansCommand::Evaluations(args)) => {
                let scan = uuid("scan uuid", &args.scan_uuid)?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(MsList::Evaluations { scan }, params)
            }
            Some(MsScansCommand::Violations(args)) => {
                let scan = uuid("scan uuid", &args.scan_uuid)?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(MsList::Violations { scan }, params)
            }
            Some(MsScansCommand::Files(args)) => {
                let scan = uuid("scan uuid", &args.scan_uuid)?;
                let file_type = filter("--type", args.file_type.as_ref())?;
                let result = filter("--result", args.result.as_ref())?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(
                    MsList::Files {
                        scan,
                        file_type,
                        result,
                    },
                    params,
                )
            }
            Some(MsScansCommand::List(args)) => {
                let window = modelsec::window(
                    args.start.as_deref(),
                    args.end.as_deref(),
                    args.model_version.as_deref(),
                )?;
                let eval_outcome = filter("--eval-outcome", args.eval_outcome.as_ref())?;
                let source_type = filter("--source-type", args.source_type.as_ref())?;
                let scan_origin = filter("--scan-origin", args.scan_origin.as_ref())?;
                let search = filter("--search", args.search.as_ref())?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(
                    MsList::Scans {
                        window,
                        eval_outcome,
                        source_type,
                        scan_origin,
                        search,
                    },
                    params,
                )
            }
        },
        ModelSecCommand::Models(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["model-security", "models"])),
            Some(MsModelsCommand::Get(args)) => get(MsGet::Model(uuid("model uuid", &args.uuid)?)),
            Some(MsModelsCommand::Version(args)) => {
                get(MsGet::Version(uuid("model version uuid", &args.uuid)?))
            }
            Some(MsModelsCommand::List(args)) => {
                let window = modelsec::window(args.start.as_deref(), args.end.as_deref(), None)?;
                let search = filter("--search", args.search.as_ref())?;
                let search_query = filter("--search-query", args.search_query.as_ref())?;
                let sort_field = filter("--sort-field", args.sort_field.as_ref())?;
                let sort_order = filter("--sort-order", args.sort_order.as_ref())?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(
                    MsList::Models {
                        window,
                        search,
                        search_query,
                        sort_field,
                        sort_order,
                    },
                    params,
                )
            }
            Some(MsModelsCommand::Versions(args)) => {
                let model = uuid("model uuid", &args.model_uuid)?;
                let sort_order = filter("--sort-order", args.sort_order.as_ref())?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(MsList::Versions { model, sort_order }, params)
            }
            Some(MsModelsCommand::Files(args)) => {
                let version = uuid("model version uuid", &args.model_version_uuid)?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(MsList::ModelFiles { version }, params)
            }
        },
        ModelSecCommand::Labels(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["model-security", "labels"])),
            Some(MsLabelsCommand::Add(args)) => {
                let scan = uuid("scan uuid", &args.scan_uuid)?;
                let body = wire(&modelsec::body::labels(&args.labels)?)?;
                write(MsWrite::LabelsAdd { scan, body })
            }
            Some(MsLabelsCommand::Set(args)) => {
                let scan = uuid("scan uuid", &args.scan_uuid)?;
                let body = wire(&modelsec::body::labels(&args.labels)?)?;
                gate(args.force, &format!("replace the labels of scan {scan}"))?;
                write(MsWrite::LabelsSet {
                    scan,
                    body,
                    force: args.force,
                })
            }
            Some(MsLabelsCommand::Delete(args)) => {
                let scan = uuid("scan uuid", &args.scan_uuid)?;
                let keys = modelsec::body::keys(&args.keys)?;
                gate(args.force, &format!("delete labels from scan {scan}"))?;
                write(MsWrite::LabelsDelete {
                    scan,
                    keys,
                    force: args.force,
                })
            }
            Some(MsLabelsCommand::Keys(args)) => {
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(MsList::LabelKeys, params)
            }
            Some(MsLabelsCommand::Values(args)) => {
                modelsec::check_label_key(&args.key)?;
                let p = &args.paging;
                let params = paging(p.limit.as_ref(), p.offset.as_ref(), p.all, p.max.as_ref())?;
                list(
                    MsList::LabelValues {
                        key: args.key.clone(),
                    },
                    params,
                )
            }
        },
    };
    Ok(Plan::ModelSecurity(Box::new(plan)))
}

/// Run a model-security plan.
pub async fn dispatch(invocation: &mut Invocation, plan: MsPlan) -> Result<(), CliError> {
    use super::modelsec_reads as reads;
    match plan {
        MsPlan::List {
            list,
            params,
            format,
        } => reads::list(invocation, &list, &params, format).await,
        MsPlan::Get { get, format } => reads::get(invocation, &get, format).await,
        MsPlan::Write { write, format } => write_dispatch(invocation, write, format).await,
        MsPlan::PypiAuth { url_file, format } => {
            super::modelsec_install::pypi_auth(invocation, url_file.as_ref(), format).await
        }
        MsPlan::Install(plan) => super::modelsec_install::install(invocation, &plan).await,
    }
}

/// Run a model-security write (§17.8–§17.11).
async fn write_dispatch(
    invocation: &mut Invocation,
    write: MsWrite,
    format: Option<Format>,
) -> Result<(), CliError> {
    use super::{modelsec_groups as groups, modelsec_labels as labels};
    match write {
        MsWrite::GroupCreate { config } => groups::create(invocation, &config, format).await,
        MsWrite::GroupUpdate { uuid, body } => {
            groups::update(invocation, &uuid, body, format).await
        }
        MsWrite::GroupDelete { uuid, force } => groups::delete(invocation, &uuid, force).await,
        MsWrite::InstanceUpdate {
            group,
            instance,
            config,
        } => {
            super::modelsec_rules::update_instance(invocation, &group, &instance, &config, format)
                .await
        }
        MsWrite::ScanCreate { config } => {
            super::modelsec_scans::create(invocation, &config, format).await
        }
        MsWrite::LabelsAdd { scan, body } => labels::add(invocation, &scan, body).await,
        MsWrite::LabelsSet { scan, body, force } => {
            labels::set(invocation, &scan, body, force).await
        }
        MsWrite::LabelsDelete { scan, keys, force } => {
            labels::delete(invocation, &scan, &keys, force).await
        }
    }
}

/// A connected model-security client and the tenant's `defaultOutput`.
pub struct Connected {
    pub client: scm::airs::model_security::ModelSecurityClient,
    pub default_output: Option<String>,
}

impl Connected {
    /// The format of a command: the tenant's `defaultOutput` applies only to the reads
    /// TypeScript resolves it for (choice 19).
    pub fn format(&self, explicit: Option<Format>, tenant_default: bool) -> Format {
        if tenant_default {
            output::resolve_tenant_default(explicit, self.default_output.as_deref())
        } else {
            explicit.unwrap_or(Format::Pretty)
        }
    }
}

impl Invocation {
    /// Load the tenant, check the management credentials (§3.5), build the
    /// model-security client from the tenant's endpoints (§17.3) and fetch the OAuth
    /// token under `options` (a walk's shared deadline; `None`: the SDK's token budget).
    pub async fn connect_model_security(
        &mut self,
        options: Option<&scm::RequestOptions>,
    ) -> Result<Connected, CliError> {
        let context = self.load_tenant()?;
        let default_output = context.config.default_output().map(str::to_owned);
        crate::tenant::config::require_management(&context.config, Some(context.name()))?;
        let clients = ModelSecurityClients::build(
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
            client: clients.model_security,
            default_output,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::FromArgMatches;

    fn plan_of(args: &[&str]) -> Result<Plan, CliError> {
        let mut full = vec!["airs", "model-security"];
        full.extend_from_slice(args);
        let matches = crate::cli::command().try_get_matches_from(&full).unwrap();
        crate::commands::plan(&Cli::from_arg_matches(&matches).unwrap())
    }

    fn ms_plan(args: &[&str]) -> MsPlan {
        match plan_of(args) {
            Ok(Plan::ModelSecurity(plan)) => *plan,
            Ok(_) => panic!("not a model-security plan: {args:?}"),
            Err(error) => panic!("{args:?}: {error:?}"),
        }
    }

    fn usage(args: &[&str]) -> String {
        match plan_of(args) {
            Err(CliError::Usage(message)) => message,
            Err(other) => panic!("expected a usage error, got {other:?}"),
            Ok(_) => panic!("expected a usage error: {args:?}"),
        }
    }

    const U: &str = "11111111-1111-4111-8111-000000000001";

    /// §17.3 "Validation order": `--output`, then `--tenant`, then the arguments.
    #[test]
    fn output_is_checked_before_the_tenant_flag_and_the_arguments() {
        let parse = |args: &[&str]| {
            let matches = crate::cli::command().try_get_matches_from(args).unwrap();
            crate::commands::plan(&Cli::from_arg_matches(&matches).unwrap())
        };
        assert!(matches!(
            parse(&["airs", "--tenant", "-bad", "model-security", "groups", "get", "x", "--output", "yaml"]),
            Err(CliError::Usage(message)) if message == "Invalid output format 'yaml'. Expected: pretty, table, json"
        ));
        assert!(matches!(
            parse(&["airs", "--tenant", "-bad", "model-security", "groups", "get", "x"]),
            Err(CliError::Usage(message)) if message.starts_with("Tenant name must be")
        ));
        for (args, message) in [
            (
                &["groups", "get", "x"][..],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: x",
            ),
            (
                &["rules", "get", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security rule uuid: x",
            ),
            (
                &["rule-instances", "list", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: x",
            ),
            (
                &["rule-instances", "get", U, "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid rule instance uuid: x",
            ),
            (
                &["scans", "get", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid scan uuid: x",
            ),
            (
                &["scans", "evaluations", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid scan uuid: x",
            ),
            (
                &["scans", "violations", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid scan uuid: x",
            ),
            (
                &["scans", "files", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid scan uuid: x",
            ),
            (
                &["scans", "evaluation", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid evaluation uuid: x",
            ),
            (
                &["scans", "violation", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid violation uuid: x",
            ),
            (
                &["models", "get", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid model uuid: x",
            ),
            (
                &["models", "versions", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid model uuid: x",
            ),
            (
                &["models", "version", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid model version uuid: x",
            ),
            (
                &["models", "files", "x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid model version uuid: x",
            ),
            (&["labels", "values", ".."], "Invalid label key: .."),
            (
                &["scans", "list", "--start", "2026-01-01"],
                modelsec::WINDOW_MESSAGE,
            ),
            (
                &["models", "list", "--end", "nope"],
                modelsec::WINDOW_MESSAGE,
            ),
            (
                &["groups", "list", "--source-types", "LOCAL,,S3"],
                "--source-types values must not be empty",
            ),
            (
                &["groups", "list", "--limit", "0"],
                "--limit must be a positive integer",
            ),
            (
                &["rule-instances", "ls", U, "--all", "--offset", "0"],
                "--all cannot be combined with --offset",
            ),
            (
                &["labels", "keys", "--max", "abc"],
                "--max must be a non-negative integer",
            ),
            (
                &["scans", "files", U, "--type", "a\u{1}"],
                "--type must be at most 4096 bytes and contain no control characters",
            ),
            // The id comes before the numbers.
            (
                &["scans", "evaluations", "x", "--limit", "0"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid scan uuid: x",
            ),
        ] {
            assert_eq!(usage(args), message, "{args:?}");
        }
    }

    #[test]
    fn plans_carry_their_filters_formats_and_contexts() {
        let plan = ms_plan(&[
            "groups",
            "ls",
            "--source-types",
            "LOCAL, S3",
            "--search",
            "",
            "--output",
            "json",
        ]);
        assert_eq!(plan.interrupt_context(), InterruptContext::NoDataWritten);
        assert_eq!(plan.debug_policy(), crate::debug::DebugPolicy::Log);
        let MsPlan::List {
            list,
            params,
            format,
        } = plan
        else {
            panic!("a list");
        };
        assert_eq!(format, Some(Format::Json));
        assert_eq!(params, ListParams::none());
        assert!(matches!(
            &list,
            MsList::Groups { source_types: Some(types), search: None, .. } if types == &["LOCAL", "S3"]
        ));
        assert!(list.tenant_default());
        assert_eq!(list.paging(), Paging::Always);
        let MsPlan::List { list, .. } = ms_plan(&["scans", "files", U, "--type", "FILE"]) else {
            panic!("a list");
        };
        assert!(!list.tenant_default());
        assert_eq!(list.paging(), Paging::LimitAlways);
        let MsPlan::List { list, .. } = ms_plan(&["scans", "violations", U]) else {
            panic!("a list");
        };
        assert!(matches!(list, MsList::Violations { .. }));
        let MsPlan::List { list, .. } = ms_plan(&["scans", "evaluations", U]) else {
            panic!("a list");
        };
        assert!(matches!(list, MsList::Evaluations { .. }));
        let MsPlan::List { list, .. } = ms_plan(&["models", "files", U]) else {
            panic!("a list");
        };
        assert_eq!(list.paging(), Paging::WhenGiven);
        assert!(matches!(
            ms_plan(&["scans", "evaluation", U]),
            MsPlan::Get { get, format: None } if !get.tenant_default()
        ));
        assert!(matches!(
            ms_plan(&["models", "version", U]),
            MsPlan::Get { get, .. } if get.tenant_default()
        ));
        assert!(matches!(
            ms_plan(&["scans", "list", "--scan-origin", "", "--all"]),
            MsPlan::List {
                list: MsList::Scans {
                    scan_origin: None,
                    ..
                },
                params: ListParams { all: true, .. },
                ..
            }
        ));
    }

    #[test]
    fn groups_without_a_subcommand_render_help() {
        for (args, path) in [
            (&[][..], &["model-security"][..]),
            (&["groups"], &["model-security", "groups"]),
            (&["rules"], &["model-security", "rules"]),
            (&["rule-instances"], &["model-security", "rule-instances"]),
            (&["scans"], &["model-security", "scans"]),
            (&["models"], &["model-security", "models"]),
            (&["labels"], &["model-security", "labels"]),
        ] {
            match plan_of(args) {
                Ok(Plan::GroupHelp(found)) => assert_eq!(found, path),
                _ => panic!("expected group help for {args:?}"),
            }
        }
    }

    /// Step 3 (§17.12, §17.13): the `pypi-auth` and `install` argument checks run during
    /// planning; `--output` is validated for both.
    #[test]
    fn pypi_auth_and_install_check_their_arguments_first() {
        assert_eq!(
            ms_plan(&["pypi-auth", "--url-file", "u.txt", "--output", "json"]),
            MsPlan::PypiAuth {
                url_file: Some(OsString::from("u.txt")),
                format: Some(Format::Json),
            }
        );
        assert_eq!(
            ms_plan(&["pypi-auth"]).interrupt_context(),
            InterruptContext::NoDataWritten
        );
        let plan = ms_plan(&["install", "--dry-run"]);
        assert_eq!(
            plan.interrupt_context(),
            InterruptContext::Context("nothing was installed".to_owned())
        );
        assert_eq!(plan.debug_policy(), crate::debug::DebugPolicy::Log);
        assert_eq!(
            plan,
            MsPlan::Install(super::super::modelsec_install::InstallPlan {
                extras: "all".to_owned(),
                dir: OsString::from("model-security"),
                dry_run: true,
                fetch_uv: false,
                hook: None,
            })
        );
        assert!(matches!(
            ms_plan(&["install", "--extras", "gcp", "--dir", "-x", "--output", "table"]),
            MsPlan::Install(plan) if plan.extras == "gcp" && plan.dir == "-x"
        ));
        for (args, message) in [
            (
                &["pypi-auth", "--url-file", ""][..],
                "--url-file needs a path",
            ),
            (
                &["pypi-auth", "--url-file", "-"],
                "--url-file - would print the credential; give a file path",
            ),
            (
                &["pypi-auth", "--output", "yaml"],
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            ),
            (
                &["install", "--extras", "ALL"],
                "Invalid extras \"ALL\". Valid: all, aws, gcp, azure, artifactory, gitlab",
            ),
            (&["install", "--dir", ""], "--dir needs a path"),
            (
                &["install", "--output", "csv"],
                "Invalid output format 'csv'. Expected: pretty, table, json",
            ),
        ] {
            assert_eq!(usage(args), message, "{args:?}");
        }
    }

    /// The write plans (§17.8–§17.11): ids, bodies and keys checked during planning, the
    /// D187 refusals, the plan's interruption context and the explicit format only.
    #[test]
    fn write_plans_check_their_arguments_first() {
        let plan = ms_plan(&[
            "groups",
            "update",
            U,
            "--description",
            "",
            "--output",
            "json",
        ]);
        assert_eq!(plan.interrupt_context(), InterruptContext::NothingChanged);
        assert_eq!(plan.debug_policy(), crate::debug::DebugPolicy::Log);
        assert_eq!(
            plan,
            MsPlan::Write {
                write: MsWrite::GroupUpdate {
                    uuid: U.to_owned(),
                    body: serde_json::json!({"description": ""}),
                },
                format: Some(Format::Json),
            }
        );
        assert!(matches!(
            ms_plan(&["groups", "rm", U, "--force"]),
            MsPlan::Write {
                write: MsWrite::GroupDelete { force: true, .. },
                format: None
            }
        ));
        assert!(matches!(
            ms_plan(&["groups", "create", "--config", "g.json"]),
            MsPlan::Write {
                write: MsWrite::GroupCreate { .. },
                ..
            }
        ));
        assert!(matches!(
            ms_plan(&["scans", "create", "--config", "s.json"]),
            MsPlan::Write {
                write: MsWrite::ScanCreate { .. },
                ..
            }
        ));
        assert!(matches!(
            ms_plan(&["rule-instances", "update", U, U, "--config", "r.json"]),
            MsPlan::Write {
                write: MsWrite::InstanceUpdate { .. },
                ..
            }
        ));
        assert_eq!(
            ms_plan(&["labels", "rm", U, "--keys", "env, team", "--force"]),
            MsPlan::Write {
                write: MsWrite::LabelsDelete {
                    scan: U.to_owned(),
                    keys: vec!["env".to_owned(), "team".to_owned()],
                    force: true,
                },
                format: None,
            }
        );
        assert!(matches!(
            ms_plan(&[
                "labels",
                "add",
                U,
                "--labels",
                r#"[{"key":"k","value":"v"}]"#
            ]),
            MsPlan::Write {
                write: MsWrite::LabelsAdd { .. },
                ..
            }
        ));
        for (args, message) in [
            (
                &["groups", "update", "x", "--name", "n"][..],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: x",
            ),
            (
                &["groups", "update", U],
                "groups update needs --name or --description",
            ),
            (
                &["groups", "rm", "x", "--force"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: x",
            ),
            (
                &["rule-instances", "update", U, "x", "--config", "r.json"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid rule instance uuid: x",
            ),
            (
                &["labels", "add", "x", "--labels", "[]"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid scan uuid: x",
            ),
            (
                &["labels", "add", U, "--labels", "nope"],
                "--labels is not valid JSON",
            ),
            (
                &["labels", "set", U, "--labels", "[]", "--force"],
                modelsec::body::LABELS_SHAPE,
            ),
            (
                &["labels", "delete", U, "--keys", "a,,b", "--force"],
                "--keys values must not be empty",
            ),
            (
                &[
                    "labels", "delete", U, "--keys", "a", "--output", "csv", "--force",
                ],
                "Invalid output format 'csv'. Expected: pretty, table, json",
            ),
        ] {
            assert_eq!(usage(args), message, "{args:?}");
        }
    }
}
