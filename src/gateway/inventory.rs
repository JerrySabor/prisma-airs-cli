//! The inventory and admin-guardrail reads of `gateway` (DESIGN §19.9, §19.13; chunk 2):
//! what each read sends, on which plane, how it is printed and what it withholds.
//!
//! A read is planned completely before the tenant is read (D232): its ids are checked
//! with the TypeScript SDK texts, the audit window is fixed, the admin-guardrail paging
//! flags are parsed. Dispatch (`commands::gateway_inventory`) only sends it.

use super::GwPlane;
use super::window::Window;
use super::withhold::{self, Policy};

/// `api-keys service` or `api-keys user`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Service,
    User,
}

/// One inventory or admin-guardrail read (§19.9, §19.13).
#[derive(Clone, Debug, PartialEq)]
pub enum InventoryRead {
    ApiKeysList {
        kind: KeyKind,
        workspace: String,
    },
    ApiKeysGet {
        kind: KeyKind,
        id: String,
    },
    AuditLogs {
        window: Window,
        reveal: bool,
    },
    ConfigsList {
        workspace: String,
    },
    ConfigsGet {
        id: String,
    },
    ConfigsVersions {
        id: String,
    },
    DeploymentsList,
    DeploymentsGet {
        id: String,
    },
    DeploymentsPing {
        id: String,
    },
    GuardrailsList {
        workspace: String,
    },
    GuardrailsGet {
        id: String,
    },
    GuardrailsCatalog,
    IntegrationsList,
    IntegrationsGet {
        id: String,
    },
    IntegrationsProviders,
    IntegrationModels {
        id: String,
    },
    IntegrationWorkspaces {
        id: String,
    },
    McpList,
    McpGet {
        id: String,
    },
    McpCapabilities {
        id: String,
    },
    McpMetadata {
        id: String,
    },
    McpWorkspaces {
        id: String,
    },
    /// `organisations info`; `tsg` is an explicit `--tsg-id` (checked against the tenant).
    OrganisationInfo {
        tsg: Option<String>,
    },
    OrganisationSelf,
    AuthSettings {
        tsg: Option<String>,
    },
    PluginsList,
    ProvidersList {
        workspace: String,
    },
    ProvidersGet {
        id: String,
    },
    AdminGuardrailsList(AdminPaging),
    AdminGuardrailsGet {
        id: String,
    },
    AdminMcpMappings {
        id: String,
    },
}

/// The query of `admin-guardrails list` (only the given keys are sent, TS).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminPaging {
    pub workspace: Option<String>,
    pub page_size: Option<u64>,
    pub current_page: Option<u64>,
}

/// How a read's answer is printed (§19.3 "Generic list and detail renderers").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// The generic list of TS `responseItems`, with its empty-list label.
    List(&'static str),
    /// `integrations models list`: the generic list of the answer's `models` (TS's
    /// `responseItems` finds no rows in `{models: […]}`; choice 77, D253).
    Models(&'static str),
    /// The generic `Field │ Value` detail.
    Detail,
}

impl InventoryRead {
    /// The plane the read goes to (§19.3 "Clients and planes"; the grant hint).
    pub fn plane(&self) -> GwPlane {
        match self {
            Self::ApiKeysList { .. }
            | Self::ApiKeysGet { .. }
            | Self::ConfigsList { .. }
            | Self::ConfigsGet { .. }
            | Self::ConfigsVersions { .. }
            | Self::GuardrailsList { .. }
            | Self::GuardrailsGet { .. }
            | Self::ProvidersList { .. }
            | Self::ProvidersGet { .. } => GwPlane::Data,
            _ => GwPlane::Admin,
        }
    }

    /// The renderer and the empty-list label (TS labels, GW§2.9).
    pub fn shape(&self) -> Shape {
        match self {
            Self::ApiKeysList {
                kind: KeyKind::Service,
                ..
            } => Shape::List("service API keys"),
            Self::ApiKeysList {
                kind: KeyKind::User,
                ..
            } => Shape::List("user API keys"),
            Self::AuditLogs { .. } => Shape::List("audit logs"),
            Self::ConfigsList { .. } => Shape::List("configs"),
            Self::ConfigsVersions { .. } => Shape::List("config versions"),
            Self::DeploymentsList => Shape::List("deployments"),
            Self::GuardrailsList { .. } => Shape::List("guardrails"),
            Self::IntegrationsList => Shape::List("integrations"),
            Self::IntegrationsProviders => Shape::List("catalog providers"),
            Self::IntegrationModels { .. } => Shape::Models("integration models"),
            Self::McpList => Shape::List("MCP integrations"),
            Self::PluginsList => Shape::List("plugins"),
            Self::ProvidersList { .. } => Shape::List("providers"),
            Self::AdminGuardrailsList(_) => Shape::List("Admin guardrails"),
            Self::AdminMcpMappings { .. } => Shape::List("MCP mappings"),
            _ => Shape::Detail,
        }
    }

    /// The resource's withholding policy (§19.3 rules 1 and 2; the audit-log rule is
    /// applied by dispatch). The config reads have none: rule 3 withholds inside the
    /// `config` JSON text (choice 81).
    pub fn policy(&self) -> &'static Policy {
        match self {
            Self::ApiKeysList { .. } | Self::ApiKeysGet { .. } => &withhold::API_KEYS,
            Self::DeploymentsList | Self::DeploymentsGet { .. } | Self::DeploymentsPing { .. } => {
                &withhold::DEPLOYMENTS
            }
            Self::IntegrationsList | Self::IntegrationsGet { .. } => &withhold::INTEGRATIONS,
            Self::McpList
            | Self::McpGet { .. }
            | Self::McpCapabilities { .. }
            | Self::McpMetadata { .. }
            | Self::McpWorkspaces { .. } => &withhold::MCP,
            Self::OrganisationInfo { .. } => &withhold::ORGANISATION_INFO,
            Self::AuthSettings { .. } => &withhold::AUTH_SETTINGS,
            Self::PluginsList => &withhold::PLUGINS,
            Self::ProvidersList { .. } | Self::ProvidersGet { .. } => &withhold::PROVIDERS,
            _ => &withhold::PLAIN,
        }
    }

    /// The explicit `--tsg-id` of the organisation reads (D245).
    pub fn tsg(&self) -> Option<&str> {
        match self {
            Self::OrganisationInfo { tsg } | Self::AuthSettings { tsg } => tsg.as_deref(),
            _ => None,
        }
    }

    /// The member of a detail answer that lists rows, for the G39 warning of the reads
    /// rendered as details (choice 78): `mcp integrations capabilities list` (`data`) and
    /// `integrations workspaces list` (`workspaces`).
    pub fn detail_rows(&self) -> Option<&'static str> {
        match self {
            Self::McpCapabilities { .. } => Some("data"),
            Self::IntegrationWorkspaces { .. } => Some("workspaces"),
            _ => None,
        }
    }

    /// The label of the G39 warning of a detail-rendered list.
    pub fn detail_label(&self) -> &'static str {
        match self {
            Self::McpCapabilities { .. } => "MCP capabilities",
            _ => "workspace bindings",
        }
    }
}

/// The `admin-guardrails list` status line (choice 64, §19.13): when the answer's `total`
/// (a safe non-negative integer) exceeds the rows up to this page, `p × s + n` with `s` the
/// given `--page-size`, else the rows of this page.
pub fn admin_status(rows: usize, total: Option<f64>, paging: &AdminPaging) -> Option<String> {
    let total = crate::walk::total_of(total)?;
    let returned = u128::try_from(rows).unwrap_or(u128::MAX);
    let page = paging.current_page.unwrap_or(0);
    let size = paging.page_size.map_or(returned, u128::from);
    let seen = u128::from(page)
        .saturating_mul(size)
        .saturating_add(returned);
    (u128::from(total) > seen).then(|| {
        format!("Returned {rows} of {total} admin guardrails (page {page}); this is one page.")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planes_shapes_and_policies() {
        let id = || "11111111-1111-4111-8111-000000000001".to_owned();
        assert_eq!(
            InventoryRead::ApiKeysGet {
                kind: KeyKind::User,
                id: id()
            }
            .plane(),
            GwPlane::Data
        );
        assert_eq!(InventoryRead::PluginsList.plane(), GwPlane::Admin);
        assert_eq!(InventoryRead::GuardrailsCatalog.plane(), GwPlane::Admin);
        assert_eq!(
            InventoryRead::AdminGuardrailsList(AdminPaging::default()).shape(),
            Shape::List("Admin guardrails")
        );
        assert_eq!(
            InventoryRead::IntegrationModels { id: id() }.shape(),
            Shape::Models("integration models")
        );
        assert_eq!(
            InventoryRead::McpWorkspaces { id: id() }.shape(),
            Shape::Detail
        );
        assert_eq!(
            InventoryRead::McpWorkspaces { id: id() }.policy(),
            &withhold::MCP
        );
        assert_eq!(
            InventoryRead::AuthSettings {
                tsg: Some("100".into())
            }
            .tsg(),
            Some("100")
        );
    }

    #[test]
    fn admin_status_lines() {
        let paging = AdminPaging {
            page_size: Some(2),
            current_page: Some(1),
            ..AdminPaging::default()
        };
        assert_eq!(
            admin_status(2, Some(10.0), &paging).unwrap(),
            "Returned 2 of 10 admin guardrails (page 1); this is one page."
        );
        assert_eq!(admin_status(2, Some(4.0), &paging), None, "the last page");
        assert_eq!(admin_status(1, Some(1.0), &AdminPaging::default()), None);
        assert_eq!(
            admin_status(1, Some(3.0), &AdminPaging::default()).unwrap(),
            "Returned 1 of 3 admin guardrails (page 0); this is one page."
        );
        assert_eq!(admin_status(1, Some(2.5), &AdminPaging::default()), None);
    }
}
