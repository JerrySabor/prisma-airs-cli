//! `gateway` inventory and admin-guardrail reads (DESIGN §19.9, §19.13; chunk 2):
//! `api-keys`, `audit-logs`, `configs`, `deployments`, `guardrails`, `integrations`,
//! `mcp integrations`, `organisations`, `plugins`, `providers` and `admin-guardrails`.
//!
//! Planning runs every check before the tenant (D232); dispatch sends one read (the SDK
//! read retries, D10), withholds the answer (§19.3 policy, the audit-log rule) and prints
//! it through the generic list and detail renderers, with the G39 warning or the paged
//! status line after it.

use super::gateway::{GwPlan, incomplete_warning};
use super::{Invocation, Plan};
use crate::cli::{
    GatewayCommand, GwAdminGuardrailsCommand, GwAdminMcpServersCommand, GwApiKeyGetArgs,
    GwApiKeyListArgs, GwApiKeysCommand, GwAuditLogsCommand, GwAuthSettingsCommand,
    GwConfigsCommand, GwDeploymentsCommand, GwGuardrailsCommand, GwIntegrationModelsCommand,
    GwIntegrationWorkspacesCommand, GwIntegrationsCommand, GwMcpCapabilitiesCommand, GwMcpCommand,
    GwMcpIntegrationsCommand, GwMcpWorkspacesCommand, GwOrganisationSelfCommand,
    GwOrganisationsCommand, GwPluginsCommand, GwProvidersCommand, GwRefusedRevealArgs,
    GwServiceKeysCommand, GwUserKeysCommand,
};
use crate::clients::SINGLE_REQUEST_BUDGET;
use crate::error::CliError;
use crate::gateway::inventory::{self, AdminPaging, InventoryRead, KeyKind, Shape};
use crate::gateway::window;
use crate::gateway::{self, MAX_SAFE_INTEGER, views, withhold};
use crate::json::{OValue, page_value};
use crate::output::Format;
use scm::airs::gateway::models::GatewayAdminGuardrailListOptions;
use scm::airs::gateway::{
    AIGatewayAuditLogListOptions, AIGatewayClient, AIGatewayWorkspaceScopedListOptions,
};
use scm::validation::NativeDate;

/// `--reveal-sensitive` where airs refuses it (D238).
const REVEAL_REFUSED: &str =
    "--reveal-sensitive is not supported here: airs never prints credentials";

fn refuse_reveal(args: &GwRefusedRevealArgs) -> Result<(), CliError> {
    if args.reveal_sensitive {
        Err(CliError::usage(REVEAL_REFUSED))
    } else {
        Ok(())
    }
}

fn id(field: &str, value: &str) -> Result<String, CliError> {
    gateway::check_uuid(field, value)?;
    Ok(value.to_owned())
}

fn tsg(value: Option<&String>) -> Result<Option<String>, CliError> {
    value
        .map(|value| gateway::check_tsg("tsgId", value).map(|()| value.clone()))
        .transpose()
}

fn key_list(kind: KeyKind, args: &GwApiKeyListArgs) -> Result<InventoryRead, CliError> {
    refuse_reveal(&args.reveal)?;
    Ok(InventoryRead::ApiKeysList {
        kind,
        workspace: id("workspaceId", &args.workspace.workspace)?,
    })
}

fn key_get(kind: KeyKind, args: &GwApiKeyGetArgs) -> Result<InventoryRead, CliError> {
    refuse_reveal(&args.reveal)?;
    Ok(InventoryRead::ApiKeysGet {
        kind,
        id: id("keyId", &args.id)?,
    })
}

/// Plan an inventory or admin-guardrail command (`None` for the commands of other
/// chunks); a group without a subcommand renders its help (D1).
pub fn plan(command: &GatewayCommand, format: Option<Format>) -> Option<Result<Plan, CliError>> {
    let read = match plan_read(command)? {
        Ok(Ok(read)) => read,
        Ok(Err(help)) => return Some(Ok(Plan::GroupHelp(help))),
        Err(error) => return Some(Err(error)),
    };
    Some(Ok(Plan::Gateway(Box::new(GwPlan::Inventory {
        read,
        format,
    }))))
}

type Planned = Result<Result<InventoryRead, &'static [&'static str]>, CliError>;

fn plan_read(command: &GatewayCommand) -> Option<Planned> {
    use GatewayCommand as G;
    let help = |path: &'static [&'static str]| Ok(Err(path));
    Some(match command {
        G::ApiKeys(group) => match &group.command {
            None => help(&["gateway", "api-keys"]),
            Some(GwApiKeysCommand::Service(group)) => match &group.command {
                None => help(&["gateway", "api-keys", "service"]),
                Some(GwServiceKeysCommand::List(args)) => key_list(KeyKind::Service, args).map(Ok),
                Some(GwServiceKeysCommand::Get(args)) => key_get(KeyKind::Service, args).map(Ok),
                Some(_) => return None,
            },
            Some(GwApiKeysCommand::User(group)) => match &group.command {
                None => help(&["gateway", "api-keys", "user"]),
                Some(GwUserKeysCommand::List(args)) => key_list(KeyKind::User, args).map(Ok),
                Some(GwUserKeysCommand::Get(args)) => key_get(KeyKind::User, args).map(Ok),
                Some(_) => return None,
            },
        },
        G::AuditLogs(group) => match &group.command {
            None => help(&["gateway", "audit-logs"]),
            Some(GwAuditLogsCommand::List(args)) => window::window(
                args.days.as_deref(),
                args.start.as_deref(),
                args.end.as_deref(),
                window::now_ms(),
            )
            .map(|window| {
                Ok(InventoryRead::AuditLogs {
                    window,
                    reveal: args.reveal_sensitive,
                })
            }),
        },
        G::Configs(group) => match &group.command {
            None => help(&["gateway", "configs"]),
            Some(GwConfigsCommand::List(args)) => id("workspaceId", &args.workspace)
                .map(|workspace| Ok(InventoryRead::ConfigsList { workspace })),
            Some(GwConfigsCommand::Get(args)) => {
                id("configId", &args.id).map(|id| Ok(InventoryRead::ConfigsGet { id }))
            }
            Some(GwConfigsCommand::Versions(args)) => {
                id("configId", &args.id).map(|id| Ok(InventoryRead::ConfigsVersions { id }))
            }
            Some(_) => return None,
        },
        G::Deployments(group) => match &group.command {
            None => help(&["gateway", "deployments"]),
            Some(GwDeploymentsCommand::List) => Ok(Ok(InventoryRead::DeploymentsList)),
            Some(GwDeploymentsCommand::Get(args)) => {
                id("deploymentId", &args.id).map(|id| Ok(InventoryRead::DeploymentsGet { id }))
            }
            Some(GwDeploymentsCommand::Ping(args)) => {
                id("deploymentId", &args.id).map(|id| Ok(InventoryRead::DeploymentsPing { id }))
            }
            Some(_) => return None,
        },
        G::Guardrails(group) => match &group.command {
            None => help(&["gateway", "guardrails"]),
            Some(GwGuardrailsCommand::List(args)) => id("workspaceId", &args.workspace)
                .map(|workspace| Ok(InventoryRead::GuardrailsList { workspace })),
            Some(GwGuardrailsCommand::Get(args)) => {
                id("guardrailId", &args.id).map(|id| Ok(InventoryRead::GuardrailsGet { id }))
            }
            Some(GwGuardrailsCommand::Catalog) => Ok(Ok(InventoryRead::GuardrailsCatalog)),
            Some(_) => return None,
        },
        G::Integrations(group) => match &group.command {
            None => help(&["gateway", "integrations"]),
            Some(GwIntegrationsCommand::List) => Ok(Ok(InventoryRead::IntegrationsList)),
            Some(GwIntegrationsCommand::Get(args)) => {
                id("integrationId", &args.id).map(|id| Ok(InventoryRead::IntegrationsGet { id }))
            }
            Some(GwIntegrationsCommand::Providers) => Ok(Ok(InventoryRead::IntegrationsProviders)),
            Some(GwIntegrationsCommand::Models(group)) => match &group.command {
                None => help(&["gateway", "integrations", "models"]),
                Some(GwIntegrationModelsCommand::List(args)) => id("integrationId", &args.id)
                    .map(|id| Ok(InventoryRead::IntegrationModels { id })),
                Some(_) => return None,
            },
            Some(GwIntegrationsCommand::Workspaces(group)) => match &group.command {
                None => help(&["gateway", "integrations", "workspaces"]),
                Some(GwIntegrationWorkspacesCommand::List(args)) => id("integrationId", &args.id)
                    .map(|id| Ok(InventoryRead::IntegrationWorkspaces { id })),
                Some(_) => return None,
            },
            Some(_) => return None,
        },
        G::Mcp(group) => match &group.command {
            None => help(&["gateway", "mcp"]),
            Some(GwMcpCommand::Integrations(group)) => plan_mcp(group.command.as_ref())?,
        },
        G::Organisations(group) => match &group.command {
            None => help(&["gateway", "organisations"]),
            Some(GwOrganisationsCommand::Info(args)) => {
                tsg(args.tsg_id.as_ref()).map(|tsg| Ok(InventoryRead::OrganisationInfo { tsg }))
            }
            Some(GwOrganisationsCommand::SelfOrg(group)) => match &group.command {
                None => help(&["gateway", "organisations", "self"]),
                Some(GwOrganisationSelfCommand::Get) => Ok(Ok(InventoryRead::OrganisationSelf)),
                Some(_) => return None,
            },
            Some(GwOrganisationsCommand::AuthSettings(group)) => match &group.command {
                None => help(&["gateway", "organisations", "auth-settings"]),
                Some(GwAuthSettingsCommand::Get(args)) => refuse_reveal(&args.reveal)
                    .and_then(|()| tsg(args.tsg.tsg_id.as_ref()))
                    .map(|tsg| Ok(InventoryRead::AuthSettings { tsg })),
                Some(_) => return None,
            },
        },
        G::Plugins(group) => match &group.command {
            None => help(&["gateway", "plugins"]),
            Some(GwPluginsCommand::List) => Ok(Ok(InventoryRead::PluginsList)),
            Some(_) => return None,
        },
        G::Providers(group) => match &group.command {
            None => help(&["gateway", "providers"]),
            Some(GwProvidersCommand::List(args)) => id("workspaceId", &args.workspace)
                .map(|workspace| Ok(InventoryRead::ProvidersList { workspace })),
            Some(GwProvidersCommand::Get(args)) => refuse_reveal(&args.reveal)
                .and_then(|()| id("providerId", &args.id))
                .map(|id| Ok(InventoryRead::ProvidersGet { id })),
            Some(_) => return None,
        },
        G::AdminGuardrails(group) => {
            match &group.command {
                None => help(&["gateway", "admin-guardrails"]),
                Some(GwAdminGuardrailsCommand::List(args)) => (|| {
                    let page_size = args
                        .page_size
                        .as_deref()
                        .map(|value| gateway::paging_integer("--page-size", value, 1, 1000))
                        .transpose()?;
                    let current_page = args
                        .current_page
                        .as_deref()
                        .map(|value| {
                            gateway::paging_integer("--current-page", value, 0, MAX_SAFE_INTEGER)
                        })
                        .transpose()?;
                    let workspace = args
                        .workspace
                        .as_deref()
                        .map(|value| id("workspaceId", value))
                        .transpose()?;
                    Ok(Ok(InventoryRead::AdminGuardrailsList(AdminPaging {
                        workspace,
                        page_size,
                        current_page,
                    })))
                })(),
                Some(GwAdminGuardrailsCommand::Get(args)) => id("guardrailId", &args.id)
                    .map(|id| Ok(InventoryRead::AdminGuardrailsGet { id })),
                Some(GwAdminGuardrailsCommand::McpServers(group)) => match &group.command {
                    None => help(&["gateway", "admin-guardrails", "mcp-servers"]),
                    Some(GwAdminMcpServersCommand::List(args)) => id("guardrailId", &args.id)
                        .map(|id| Ok(InventoryRead::AdminMcpMappings { id })),
                    Some(_) => return None,
                },
                Some(_) => return None,
            }
        }
        G::Scopes(_) | G::Telemetry(_) | G::Workspaces(_) | G::Inference(_) | G::Report(_) => {
            return None;
        }
    })
}

fn plan_mcp(command: Option<&GwMcpIntegrationsCommand>) -> Option<Planned> {
    let field = "mcpIntegrationId";
    Some(match command {
        None => Ok(Err(&["gateway", "mcp", "integrations"])),
        Some(GwMcpIntegrationsCommand::List) => Ok(Ok(InventoryRead::McpList)),
        Some(GwMcpIntegrationsCommand::Get(args)) => {
            id(field, &args.id).map(|id| Ok(InventoryRead::McpGet { id }))
        }
        Some(GwMcpIntegrationsCommand::Metadata(args)) => {
            id(field, &args.id).map(|id| Ok(InventoryRead::McpMetadata { id }))
        }
        Some(GwMcpIntegrationsCommand::Capabilities(group)) => match &group.command {
            None => Ok(Err(&["gateway", "mcp", "integrations", "capabilities"])),
            Some(GwMcpCapabilitiesCommand::List(args)) => {
                id(field, &args.id).map(|id| Ok(InventoryRead::McpCapabilities { id }))
            }
            Some(_) => return None,
        },
        Some(GwMcpIntegrationsCommand::Workspaces(group)) => match &group.command {
            None => Ok(Err(&["gateway", "mcp", "integrations", "workspaces"])),
            Some(GwMcpWorkspacesCommand::List(args)) => {
                id(field, &args.id).map(|id| Ok(InventoryRead::McpWorkspaces { id }))
            }
            Some(_) => return None,
        },
        Some(_) => return None,
    })
}

/// The one SDK read of `read`, as an ordered document.
async fn fetch(
    gateway: &AIGatewayClient,
    read: &InventoryRead,
    tsg: &str,
) -> Result<Result<OValue, scm::Error>, CliError> {
    use InventoryRead as R;
    let options = gateway::options(SINGLE_REQUEST_BUDGET)?;
    let options = Some(&options);
    let scoped = AIGatewayWorkspaceScopedListOptions::new;
    Ok(match read {
        R::ApiKeysList { kind, workspace } => {
            let keys = gateway.api_keys();
            match kind {
                KeyKind::Service => {
                    keys.list_service(&scoped(workspace.as_str()), options)
                        .await
                }
                KeyKind::User => keys.list_user(&scoped(workspace.as_str()), options).await,
            }
            .and_then(|a| page_value(&a))
        }
        R::ApiKeysGet { kind, id } => {
            let keys = gateway.api_keys();
            match kind {
                KeyKind::Service => keys.get_service(id, options).await,
                KeyKind::User => keys.get_user(id, options).await,
            }
            .and_then(|a| page_value(&a))
        }
        R::AuditLogs { window, .. } => {
            let date = |ms: i64| {
                NativeDate::from_epoch_millis(ms).map_err(|_| CliError::usage(window::WINDOW_ERROR))
            };
            let query =
                AIGatewayAuditLogListOptions::new(date(window.start_ms)?, date(window.end_ms)?);
            gateway
                .audit_logs()
                .list(&query, options)
                .await
                .and_then(|a| page_value(&a))
        }
        R::ConfigsList { workspace } => gateway
            .configs()
            .list(&scoped(workspace.as_str()), options)
            .await
            .and_then(|a| page_value(&a)),
        R::ConfigsGet { id } => gateway
            .configs()
            .get(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::ConfigsVersions { id } => gateway
            .configs()
            .list_versions(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::DeploymentsList => gateway
            .deployments()
            .list(options)
            .await
            .and_then(|a| page_value(&a)),
        R::DeploymentsGet { id } => gateway
            .deployments()
            .get(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::DeploymentsPing { id } => gateway
            .deployments()
            .ping(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::GuardrailsList { workspace } => gateway
            .guardrails()
            .list(&scoped(workspace.as_str()), options)
            .await
            .and_then(|a| page_value(&a)),
        R::GuardrailsGet { id } => gateway
            .guardrails()
            .get(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::GuardrailsCatalog => gateway
            .guardrails()
            .get_catalog(options)
            .await
            .and_then(|a| page_value(&a)),
        R::IntegrationsList => gateway
            .integrations()
            .list(options)
            .await
            .and_then(|a| page_value(&a)),
        R::IntegrationsGet { id } => gateway
            .integrations()
            .get(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::IntegrationsProviders => gateway
            .integrations()
            .catalog(options)
            .await
            .and_then(|a| page_value(&a)),
        R::IntegrationModels { id } => gateway
            .integrations()
            .get_models(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::IntegrationWorkspaces { id } => gateway
            .integrations()
            .get_workspaces(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::McpList => gateway
            .mcp_integrations()
            .list(options)
            .await
            .and_then(|a| page_value(&a)),
        // `mcp integrations workspaces list` reads the integration detail (TS; choice 37).
        R::McpGet { id } | R::McpWorkspaces { id } => gateway
            .mcp_integrations()
            .get(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::McpCapabilities { id } => gateway
            .mcp_integrations()
            .get_capabilities(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::McpMetadata { id } => gateway
            .mcp_integrations()
            .get_metadata(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::OrganisationInfo { .. } => gateway
            .organisations()
            .get_info(tsg, options)
            .await
            .and_then(|a| page_value(&a)),
        R::OrganisationSelf => gateway
            .organisations()
            .get_self(options)
            .await
            .and_then(|a| page_value(&a)),
        R::AuthSettings { .. } => gateway
            .organisations()
            .get_auth_settings(tsg, options)
            .await
            .and_then(|a| page_value(&a)),
        R::PluginsList => gateway
            .plugins()
            .list(options)
            .await
            .and_then(|a| page_value(&a)),
        R::ProvidersList { workspace } => gateway
            .providers()
            .list(&scoped(workspace.as_str()), options)
            .await
            .and_then(|a| page_value(&a)),
        R::ProvidersGet { id } => gateway
            .providers()
            .get(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::AdminGuardrailsList(paging) => {
            let mut query = serde_json::Map::new();
            if let Some(workspace) = &paging.workspace {
                query.insert("workspaceId".into(), workspace.clone().into());
            }
            if let Some(size) = paging.page_size {
                query.insert("pageSize".into(), size.into());
            }
            if let Some(page) = paging.current_page {
                query.insert("currentPage".into(), page.into());
            }
            let query = GatewayAdminGuardrailListOptions::parse(
                serde_json::Value::Object(query),
                scm::validation::Mode::Request,
            )
            .map_err(|_| {
                CliError::operational("AISEC_SDK_ERROR:The request options could not be configured")
            })?;
            gateway
                .admin_guardrails()
                .list(&query, options)
                .await
                .and_then(|a| page_value(&a))
        }
        R::AdminGuardrailsGet { id } => gateway
            .admin_guardrails()
            .get(id, options)
            .await
            .and_then(|a| page_value(&a)),
        R::AdminMcpMappings { id } => gateway
            .admin_guardrails()
            .get_mcp_servers(id, options)
            .await
            .and_then(|a| page_value(&a)),
    })
}

/// `has_more: true` of an answer.
fn has_more(answer: &OValue) -> bool {
    matches!(answer.get("has_more"), Some(OValue::Bool(true)))
}

/// Run an inventory or admin-guardrail read (§19.9, §19.13).
pub async fn read(
    invocation: &mut Invocation,
    read: &InventoryRead,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let flag = read.tsg().map(|value| ("--tsg-id", value));
    let (gateway, format, tenant_tsg) = invocation.connect_gateway_tsg(explicit, flag).await?;
    let mut answer = match fetch(&gateway, read, &tenant_tsg).await? {
        Ok(answer) => answer,
        Err(error) => return Err(invocation.gateway_error(&error, read.plane())),
    };
    let secrets = invocation.secrets.clone();
    match read.shape() {
        Shape::List(label) | Shape::Models(label) => {
            let source = match read.shape() {
                Shape::Models(_) => answer
                    .get("models")
                    .cloned()
                    .unwrap_or(OValue::Array(Vec::new())),
                _ => answer.clone(),
            };
            let shape = views::response_items(&source);
            let mut rows = OValue::Array(shape.clone());
            match read {
                InventoryRead::AuditLogs { reveal, .. } => {
                    withhold::apply_audit(&mut rows, *reveal, &secrets);
                }
                _ => withhold::apply(&mut rows, read.policy(), &secrets),
            }
            let rows = match rows {
                OValue::Array(rows) => rows,
                _ => Vec::new(),
            };
            views::render_list(&mut invocation.output, &rows, &shape, format, label)?;
            let total = crate::json::number(&answer, "total");
            if let InventoryRead::AdminGuardrailsList(paging) = read {
                if let Some(status) = inventory::admin_status(rows.len(), total, paging) {
                    invocation.output.status(&status);
                }
            } else if let Some(warning) =
                incomplete_warning(rows.len(), answer.get("total"), has_more(&answer), label)
            {
                invocation.output.warning(&warning);
            }
        }
        Shape::Detail => {
            let warning = read.detail_rows().and_then(|member| {
                let rows = answer
                    .get(member)
                    .and_then(OValue::as_array)
                    .map_or(0, <[OValue]>::len);
                incomplete_warning(
                    rows,
                    answer.get("total"),
                    has_more(&answer),
                    read.detail_label(),
                )
            });
            withhold::apply(&mut answer, read.policy(), &secrets);
            views::render_detail(&mut invocation.output, &answer, format)?;
            if let Some(warning) = warning {
                invocation.output.warning(&warning);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::FromArgMatches;

    fn plan_of(args: &[&str]) -> Result<Plan, CliError> {
        let mut full = vec!["airs", "gateway"];
        full.extend_from_slice(args);
        let matches = crate::cli::command().try_get_matches_from(&full).unwrap();
        crate::commands::plan(&Cli::from_arg_matches(&matches).unwrap())
    }

    fn read_of(args: &[&str]) -> InventoryRead {
        match plan_of(args) {
            Ok(Plan::Gateway(plan)) => match *plan {
                GwPlan::Inventory { read, .. } => read,
                _ => panic!("not an inventory read: {args:?}"),
            },
            Ok(_) => panic!("not a gateway plan: {args:?}"),
            Err(error) => panic!("{args:?}: {error:?}"),
        }
    }

    fn usage(args: &[&str]) -> String {
        match plan_of(args) {
            Err(CliError::Usage(message)) => message,
            other => panic!(
                "expected a usage error for {args:?}, got {:?}",
                other.is_ok()
            ),
        }
    }

    const U: &str = "11111111-1111-4111-8111-000000000001";

    #[test]
    fn reads_plan_with_their_ids() {
        assert_eq!(
            read_of(&["api-keys", "user", "ls", "--workspace", U]),
            InventoryRead::ApiKeysList {
                kind: KeyKind::User,
                workspace: U.to_owned()
            }
        );
        assert_eq!(
            read_of(&["mcp", "integrations", "workspaces", "list", U]),
            InventoryRead::McpWorkspaces { id: U.to_owned() }
        );
        assert_eq!(
            read_of(&["organisations", "info"]),
            InventoryRead::OrganisationInfo { tsg: None }
        );
        assert_eq!(
            read_of(&["admin-guardrails", "list", "--current-page", "0"]),
            InventoryRead::AdminGuardrailsList(AdminPaging {
                current_page: Some(0),
                ..AdminPaging::default()
            })
        );
        assert!(matches!(
            read_of(&["audit-logs", "ls", "--reveal-sensitive"]),
            InventoryRead::AuditLogs { reveal: true, .. }
        ));
    }

    /// D232, D238: every check is a usage error during planning.
    #[test]
    fn checks_come_first() {
        for (args, message) in [
            (
                &["configs", "get", "config-1"][..],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid configId: config-1",
            ),
            (
                &["api-keys", "service", "list", "--workspace", "workspace-1"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid workspaceId: workspace-1",
            ),
            (
                &["api-keys", "service", "get", "x", "--reveal-sensitive"],
                REVEAL_REFUSED,
            ),
            (
                &["providers", "get", U, "--reveal-sensitive"],
                REVEAL_REFUSED,
            ),
            (
                &[
                    "organisations",
                    "auth-settings",
                    "get",
                    "--reveal-sensitive",
                ],
                REVEAL_REFUSED,
            ),
            (
                &["organisations", "info", "--tsg-id", "12x"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid tsgId: 12x",
            ),
            (
                &["admin-guardrails", "list", "--page-size", "1001"],
                "--page-size must be an integer from 1 to 1000",
            ),
            (
                &["admin-guardrails", "list", "--current-page", "1.5"],
                "Expected an integer",
            ),
            (
                &["admin-guardrails", "list", "--workspace", "w"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid workspaceId: w",
            ),
            (
                &["audit-logs", "list", "--end", "not-a-date"],
                "Invalid --end: Expected an ISO-8601 timestamp",
            ),
            (
                &[
                    "audit-logs",
                    "list",
                    "--days",
                    "1",
                    "--start",
                    "2026-10-01T00:00:00Z",
                ],
                "Use --days or --start/--end, not both",
            ),
            (
                &["mcp", "integrations", "metadata", "mcp-1"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid mcpIntegrationId: mcp-1",
            ),
            (
                &["deployments", "ping", "deployment-1"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid deploymentId: deployment-1",
            ),
            (
                &["admin-guardrails", "mcp-servers", "list", "g"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid guardrailId: g",
            ),
        ] {
            assert_eq!(usage(args), message, "{args:?}");
        }
    }

    #[test]
    fn groups_without_a_subcommand_render_help() {
        for (args, path) in [
            (&["api-keys"][..], &["gateway", "api-keys"][..]),
            (&["api-keys", "user"], &["gateway", "api-keys", "user"]),
            (&["mcp"], &["gateway", "mcp"]),
            (
                &["mcp", "integrations", "capabilities"],
                &["gateway", "mcp", "integrations", "capabilities"],
            ),
            (
                &["organisations", "auth-settings"],
                &["gateway", "organisations", "auth-settings"],
            ),
            (
                &["admin-guardrails", "mcp-servers"],
                &["gateway", "admin-guardrails", "mcp-servers"],
            ),
        ] {
            match plan_of(args) {
                Ok(Plan::GroupHelp(found)) => assert_eq!(found, path),
                _ => panic!("expected group help for {args:?}"),
            }
        }
    }
}
