//! The gateway fixture routes (DESIGN §10 M6e, chunk 1; the inference runtime of chunk 4
//! is `server/inference.rs`): the data plane under
//! `/ai_gw/v2` (workspaces, the telemetry charts, groups, logs and filter boundaries),
//! the admin plane under `/ai_gw/admin/v2` (workspaces) and IAM under `/iam` (scopes),
//! bearer- and `x-tsg-id`-checked, over a per-server dataset ([`GatewayData`]).
//!
//! The unseeded dataset answers the data-plane workspace list with an empty list (the
//! TypeScript doctor's probe, which this route family absorbs). Knobs: a reported `total`
//! other than the count and `has_more` on the workspace lists, a `count` other than the
//! number of scopes, a logs `total`. Any other method or path under these bases is an
//! unknown route.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::plan::Planned;
use super::record::{AuthIdentity, RecordedRequest};
use super::redteam::percent_decode;
use crate::fixtures::gateway as fx;

/// The data-plane prefix (`gatewayDataEndpoint = <base>/ai_gw/v2`).
pub const DATA_PREFIX: &str = "/ai_gw/v2";
/// The admin-plane prefix (`gatewayAdminEndpoint = <base>/ai_gw/admin/v2`).
pub const ADMIN_PREFIX: &str = "/ai_gw/admin/v2";
/// The IAM prefix (`iamEndpoint = <base>/iam`).
pub const IAM_PREFIX: &str = "/iam";

/// A gateway fixture route (`Route::Gateway`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Gw {
    /// `GET <data>/workspaces` (also the TypeScript doctor's probe).
    DataWorkspaces,
    /// `GET <admin>/workspaces[?status=]`.
    AdminWorkspaces,
    /// `GET <data>/workspaces/{ref}`.
    DataWorkspaceGet,
    /// `GET <admin>/workspaces/{ref}`.
    AdminWorkspaceGet,
    /// `GET <iam>/scopes`.
    ScopeList,
    /// `GET <iam>/scopes/{name}`.
    ScopeGet,
    /// `GET <data>/logs/charts/{metric}`.
    Chart,
    /// `GET <data>/logs/groups/{dimension}`.
    Group,
    /// `GET <data>/logs`.
    Logs,
    /// `GET <data>/analytics/filter-boundaries`.
    FilterBoundaries,
    /// `GET <data>/api-keys/service?workspace_id=` (chunk 2 from here on).
    ServiceKeys,
    /// `GET <data>/api-keys/service/{id}`.
    ServiceKeyGet,
    /// `GET <data>/api-keys/user?workspace_id=`.
    UserKeys,
    /// `GET <data>/api-keys/user/{id}`.
    UserKeyGet,
    /// `GET <admin>/audit-logs?start_time=&end_time=`.
    AuditLogs,
    /// `GET <data>/configs?workspace_id=`.
    Configs,
    /// `GET <data>/configs/{id}`.
    ConfigGet,
    /// `GET <data>/configs/{id}/versions`.
    ConfigVersions,
    /// `GET <admin>/deployments`.
    Deployments,
    /// `GET <admin>/deployments/{id}`.
    DeploymentGet,
    /// `GET <admin>/deployments/{id}/ping`.
    DeploymentPing,
    /// `GET <data>/guardrails?workspace_id=`.
    Guardrails,
    /// `GET <data>/guardrails/{id}`.
    GuardrailGet,
    /// `GET <admin>/utils/static-resources/schema?resource=guardrails`.
    GuardrailCatalog,
    /// `GET <admin>/integrations`.
    Integrations,
    /// `GET <admin>/integrations/{id}`.
    IntegrationGet,
    /// `GET <admin>/utils/static-resources/ai-providers`.
    CatalogProviders,
    /// `GET <admin>/integrations/{id}/models`.
    IntegrationModels,
    /// `GET <admin>/integrations/{id}/workspaces`.
    IntegrationWorkspaces,
    /// `GET <admin>/mcp-integrations`.
    McpIntegrations,
    /// `GET <admin>/mcp-integrations/{id}`.
    McpIntegrationGet,
    /// `GET <admin>/mcp-integrations/{id}/capabilities`.
    McpCapabilities,
    /// `GET <admin>/mcp-integrations/{id}/metadata`.
    McpMetadata,
    /// `GET <admin>/organisations/{tsg}/info`.
    OrganisationInfo,
    /// `GET <admin>/organisations/self`.
    OrganisationSelf,
    /// `GET <admin>/organisations/{tsg}/auth-settings`.
    AuthSettings,
    /// `GET <admin>/plugins`.
    Plugins,
    /// `GET <data>/providers?workspace_id=`.
    Providers,
    /// `GET <data>/providers/{id}`.
    ProviderGet,
    /// `GET <admin>/guardrails[?workspace_id=&page_size=&current_page=]`.
    AdminGuardrails,
    /// `GET <admin>/guardrails/{id}`.
    AdminGuardrailGet,
    /// `GET <admin>/guardrails/{id}/mcp-servers`.
    AdminMcpMappings,
    /// `POST <admin>/workspaces` (chunk 3 write).
    WorkspaceCreate,
    /// `PUT <admin>/workspaces/{ref}` (chunk 3 write).
    WorkspaceUpdate,
    /// `DELETE <admin>/workspaces/{ref}` (chunk 3 write).
    WorkspaceArchive,
    /// `POST <iam>/scopes` (chunk 3 write).
    ScopeCreate,
    /// `PUT <iam>/scopes/{name}` (chunk 3 write).
    ScopeUpdate,
    /// `DELETE <iam>/scopes/{name}` (chunk 3 write).
    ScopeDelete,
    /// `POST <data>/configs` (chunk 3 write).
    ConfigCreate,
    /// `PUT <data>/configs/{id}` (chunk 3 write).
    ConfigUpdate,
    /// `DELETE <data>/configs/{id}` (chunk 3 write).
    ConfigDelete,
    /// `POST <data>/guardrails` (chunk 3 write).
    GuardrailCreate,
    /// `PUT <data>/guardrails/{id}` (chunk 3 write).
    GuardrailUpdate,
    /// `DELETE <data>/guardrails/{id}` (chunk 3 write).
    GuardrailDelete,
    /// `POST <data>/providers` (chunk 3 write).
    ProviderCreate,
    /// `PUT <data>/providers/{id}` (chunk 3 write).
    ProviderUpdate,
    /// `DELETE <data>/providers/{id}` (chunk 3 write).
    ProviderDelete,
    /// `POST <data>/api-keys/{kind}` (chunk 3 write).
    KeyCreate,
    /// `PUT <data>/api-keys/{kind}/{id}` (chunk 3 write).
    KeyUpdate,
    /// `POST <data>/api-keys/{kind}/{id}/rotate` (chunk 3 write).
    KeyRotate,
    /// `DELETE <data>/api-keys/{kind}/{id}` (chunk 3 write).
    KeyDelete,
    /// `POST <admin>/deployments` (chunk 3 write).
    DeploymentCreate,
    /// `PUT <admin>/deployments/{id}` (chunk 3 write).
    DeploymentUpdate,
    /// `DELETE <admin>/deployments/{id}?organisation_id=` (chunk 3 write).
    DeploymentArchive,
    /// `POST <admin>/integrations` (chunk 3 write).
    IntegrationCreate,
    /// `PUT <admin>/integrations/{id}` (chunk 3 write).
    IntegrationUpdate,
    /// `DELETE <admin>/integrations/{id}?organisation_id=` (chunk 3 write).
    IntegrationDelete,
    /// `PUT <admin>/integrations/{id}/models` (chunk 3 write).
    ModelsSet,
    /// `PUT <admin>/integrations/{id}/workspaces` (chunk 3 write).
    IntegrationWorkspacesSet,
    /// `POST <admin>/mcp-integrations` (chunk 3 write).
    McpCreate,
    /// `PUT <admin>/mcp-integrations/{id}` (chunk 3 write).
    McpUpdate,
    /// `DELETE <admin>/mcp-integrations/{id}` (chunk 3 write).
    McpDelete,
    /// `PUT <admin>/mcp-integrations/{id}/capabilities` (chunk 3 write).
    CapabilitiesSet,
    /// `PUT <admin>/mcp-integrations/{id}/workspaces` (chunk 3 write).
    McpWorkspacesSet,
    /// `PUT <admin>/organisations/self` (chunk 3 write).
    OrganisationUpdate,
    /// `PUT <admin>/organisations/{tsg}/auth-settings` (chunk 3 write).
    AuthSettingsUpdate,
    /// `POST <admin>/plugins` (chunk 3 write).
    PluginCreate,
    /// `POST <admin>/guardrails` (chunk 3 write).
    AdminGuardrailCreate,
    /// `PUT <admin>/guardrails/{id}` (chunk 3 write).
    AdminGuardrailUpdate,
    /// `DELETE <admin>/guardrails/{id}` (chunk 3 write).
    AdminGuardrailDelete,
    /// `PUT <admin>/guardrails/{id}/mcp-servers` (chunk 3 write).
    McpSync,
    /// `PUT <admin>/guardrails/{id}/mcp-servers/{server}` (chunk 3 write).
    McpUpsert,
    /// `POST <inference>/chat/completions` (chunk 4, the runtime plane).
    InferenceChat,
    /// `POST <inference>/responses` (chunk 4).
    InferenceResponses,
    /// `POST <inference>/embeddings` (chunk 4).
    InferenceEmbeddings,
}

impl Gw {
    /// A short stable label (`gw-data-workspaces`, ...).
    pub fn label(self) -> &'static str {
        match self {
            Gw::DataWorkspaces => "gw-data-workspaces",
            Gw::AdminWorkspaces => "gw-admin-workspaces",
            Gw::DataWorkspaceGet => "gw-data-workspace-get",
            Gw::AdminWorkspaceGet => "gw-admin-workspace-get",
            Gw::ScopeList => "gw-scopes-list",
            Gw::ScopeGet => "gw-scopes-get",
            Gw::Chart => "gw-chart",
            Gw::Group => "gw-group",
            Gw::Logs => "gw-logs",
            Gw::FilterBoundaries => "gw-filter-boundaries",
            Gw::ServiceKeys => "gw-service-keys",
            Gw::ServiceKeyGet => "gw-service-key-get",
            Gw::UserKeys => "gw-user-keys",
            Gw::UserKeyGet => "gw-user-key-get",
            Gw::AuditLogs => "gw-audit-logs",
            Gw::Configs => "gw-configs",
            Gw::ConfigGet => "gw-config-get",
            Gw::ConfigVersions => "gw-config-versions",
            Gw::Deployments => "gw-deployments",
            Gw::DeploymentGet => "gw-deployment-get",
            Gw::DeploymentPing => "gw-deployment-ping",
            Gw::Guardrails => "gw-guardrails",
            Gw::GuardrailGet => "gw-guardrail-get",
            Gw::GuardrailCatalog => "gw-guardrail-catalog",
            Gw::Integrations => "gw-integrations",
            Gw::IntegrationGet => "gw-integration-get",
            Gw::CatalogProviders => "gw-catalog-providers",
            Gw::IntegrationModels => "gw-integration-models",
            Gw::IntegrationWorkspaces => "gw-integration-workspaces",
            Gw::McpIntegrations => "gw-mcp-integrations",
            Gw::McpIntegrationGet => "gw-mcp-integration-get",
            Gw::McpCapabilities => "gw-mcp-capabilities",
            Gw::McpMetadata => "gw-mcp-metadata",
            Gw::OrganisationInfo => "gw-organisation-info",
            Gw::OrganisationSelf => "gw-organisation-self",
            Gw::AuthSettings => "gw-auth-settings",
            Gw::Plugins => "gw-plugins",
            Gw::Providers => "gw-providers",
            Gw::ProviderGet => "gw-provider-get",
            Gw::AdminGuardrails => "gw-admin-guardrails",
            Gw::AdminGuardrailGet => "gw-admin-guardrail-get",
            Gw::AdminMcpMappings => "gw-admin-mcp-mappings",
            Gw::WorkspaceCreate => "gw-workspace-create",
            Gw::WorkspaceUpdate => "gw-workspace-update",
            Gw::WorkspaceArchive => "gw-workspace-archive",
            Gw::ScopeCreate => "gw-scope-create",
            Gw::ScopeUpdate => "gw-scope-update",
            Gw::ScopeDelete => "gw-scope-delete",
            Gw::ConfigCreate => "gw-config-create",
            Gw::ConfigUpdate => "gw-config-update",
            Gw::ConfigDelete => "gw-config-delete",
            Gw::GuardrailCreate => "gw-guardrail-create",
            Gw::GuardrailUpdate => "gw-guardrail-update",
            Gw::GuardrailDelete => "gw-guardrail-delete",
            Gw::ProviderCreate => "gw-provider-create",
            Gw::ProviderUpdate => "gw-provider-update",
            Gw::ProviderDelete => "gw-provider-delete",
            Gw::KeyCreate => "gw-key-create",
            Gw::KeyUpdate => "gw-key-update",
            Gw::KeyRotate => "gw-key-rotate",
            Gw::KeyDelete => "gw-key-delete",
            Gw::DeploymentCreate => "gw-deployment-create",
            Gw::DeploymentUpdate => "gw-deployment-update",
            Gw::DeploymentArchive => "gw-deployment-archive",
            Gw::IntegrationCreate => "gw-integration-create",
            Gw::IntegrationUpdate => "gw-integration-update",
            Gw::IntegrationDelete => "gw-integration-delete",
            Gw::ModelsSet => "gw-models-set",
            Gw::IntegrationWorkspacesSet => "gw-integration-workspaces-set",
            Gw::McpCreate => "gw-mcp-create",
            Gw::McpUpdate => "gw-mcp-update",
            Gw::McpDelete => "gw-mcp-delete",
            Gw::CapabilitiesSet => "gw-capabilities-set",
            Gw::McpWorkspacesSet => "gw-mcp-workspaces-set",
            Gw::OrganisationUpdate => "gw-organisation-update",
            Gw::AuthSettingsUpdate => "gw-auth-settings-update",
            Gw::PluginCreate => "gw-plugin-create",
            Gw::AdminGuardrailCreate => "gw-admin-guardrail-create",
            Gw::AdminGuardrailUpdate => "gw-admin-guardrail-update",
            Gw::AdminGuardrailDelete => "gw-admin-guardrail-delete",
            Gw::McpSync => "gw-mcp-sync",
            Gw::McpUpsert => "gw-mcp-upsert",
            Gw::InferenceChat => "gw-inference-chat",
            Gw::InferenceResponses => "gw-inference-responses",
            Gw::InferenceEmbeddings => "gw-inference-embeddings",
        }
    }

    /// Every chunk-2 inventory and admin read route, in declaration order.
    pub const INVENTORY: [Gw; 32] = [
        Gw::ServiceKeys,
        Gw::ServiceKeyGet,
        Gw::UserKeys,
        Gw::UserKeyGet,
        Gw::AuditLogs,
        Gw::Configs,
        Gw::ConfigGet,
        Gw::ConfigVersions,
        Gw::Deployments,
        Gw::DeploymentGet,
        Gw::DeploymentPing,
        Gw::Guardrails,
        Gw::GuardrailGet,
        Gw::GuardrailCatalog,
        Gw::Integrations,
        Gw::IntegrationGet,
        Gw::CatalogProviders,
        Gw::IntegrationModels,
        Gw::IntegrationWorkspaces,
        Gw::McpIntegrations,
        Gw::McpIntegrationGet,
        Gw::McpCapabilities,
        Gw::McpMetadata,
        Gw::OrganisationInfo,
        Gw::OrganisationSelf,
        Gw::AuthSettings,
        Gw::Plugins,
        Gw::Providers,
        Gw::ProviderGet,
        Gw::AdminGuardrails,
        Gw::AdminGuardrailGet,
        Gw::AdminMcpMappings,
    ];

    /// The resource id a single-resource route expects in its path (`None` for the
    /// lists and the organisation routes).
    fn expected_id(self) -> Option<u64> {
        Some(match self {
            Gw::ServiceKeyGet => fx::SERVICE_KEY,
            Gw::UserKeyGet => fx::USER_KEY,
            Gw::ConfigGet | Gw::ConfigVersions => fx::CONFIG,
            Gw::DeploymentGet | Gw::DeploymentPing => fx::DEPLOYMENT,
            Gw::GuardrailGet => fx::GUARDRAIL,
            Gw::IntegrationGet | Gw::IntegrationModels | Gw::IntegrationWorkspaces => {
                fx::INTEGRATION
            }
            Gw::McpIntegrationGet | Gw::McpCapabilities | Gw::McpMetadata => fx::MCP_INTEGRATION,
            Gw::ProviderGet => fx::PROVIDER,
            Gw::AdminGuardrailGet | Gw::AdminMcpMappings => fx::ADMIN_GUARDRAIL,
            _ => return None,
        })
    }

    /// Every chunk-3 write route, in declaration order.
    pub const WRITES: [Gw; 40] = [
        Gw::WorkspaceCreate,
        Gw::WorkspaceUpdate,
        Gw::WorkspaceArchive,
        Gw::ScopeCreate,
        Gw::ScopeUpdate,
        Gw::ScopeDelete,
        Gw::ConfigCreate,
        Gw::ConfigUpdate,
        Gw::ConfigDelete,
        Gw::GuardrailCreate,
        Gw::GuardrailUpdate,
        Gw::GuardrailDelete,
        Gw::ProviderCreate,
        Gw::ProviderUpdate,
        Gw::ProviderDelete,
        Gw::KeyCreate,
        Gw::KeyUpdate,
        Gw::KeyRotate,
        Gw::KeyDelete,
        Gw::DeploymentCreate,
        Gw::DeploymentUpdate,
        Gw::DeploymentArchive,
        Gw::IntegrationCreate,
        Gw::IntegrationUpdate,
        Gw::IntegrationDelete,
        Gw::ModelsSet,
        Gw::IntegrationWorkspacesSet,
        Gw::McpCreate,
        Gw::McpUpdate,
        Gw::McpDelete,
        Gw::CapabilitiesSet,
        Gw::McpWorkspacesSet,
        Gw::OrganisationUpdate,
        Gw::AuthSettingsUpdate,
        Gw::PluginCreate,
        Gw::AdminGuardrailCreate,
        Gw::AdminGuardrailUpdate,
        Gw::AdminGuardrailDelete,
        Gw::McpSync,
        Gw::McpUpsert,
    ];

    /// Whether the route is a write (every POST, PUT and DELETE, chunk 3).
    pub fn is_write(self) -> bool {
        Self::WRITES.contains(&self)
    }

    /// The three inference runtime routes (chunk 4).
    pub const INFERENCE: [Gw; 3] = [
        Gw::InferenceChat,
        Gw::InferenceResponses,
        Gw::InferenceEmbeddings,
    ];

    /// Whether the route is on the inference runtime plane (billed model calls; never
    /// reached by the live tier).
    pub fn is_inference(self) -> bool {
        Self::INFERENCE.contains(&self)
    }

    /// Which plane the route belongs to: `data`, `admin`, `iam` or `runtime`.
    pub fn plane(self) -> &'static str {
        match self {
            Gw::InferenceChat | Gw::InferenceResponses | Gw::InferenceEmbeddings => "runtime",
            Gw::ScopeList | Gw::ScopeGet | Gw::ScopeCreate | Gw::ScopeUpdate | Gw::ScopeDelete => {
                "iam"
            }
            Gw::DataWorkspaces
            | Gw::DataWorkspaceGet
            | Gw::Chart
            | Gw::Group
            | Gw::Logs
            | Gw::FilterBoundaries
            | Gw::ServiceKeys
            | Gw::ServiceKeyGet
            | Gw::UserKeys
            | Gw::UserKeyGet
            | Gw::Configs
            | Gw::ConfigGet
            | Gw::ConfigVersions
            | Gw::Guardrails
            | Gw::GuardrailGet
            | Gw::Providers
            | Gw::ProviderGet
            | Gw::ConfigCreate
            | Gw::ConfigUpdate
            | Gw::ConfigDelete
            | Gw::GuardrailCreate
            | Gw::GuardrailUpdate
            | Gw::GuardrailDelete
            | Gw::ProviderCreate
            | Gw::ProviderUpdate
            | Gw::ProviderDelete
            | Gw::KeyCreate
            | Gw::KeyUpdate
            | Gw::KeyRotate
            | Gw::KeyDelete => "data",
            _ => "admin",
        }
    }

    /// Classifies a request under the gateway bases; `None` for anything else.
    pub fn classify(method: &str, path: &str) -> Option<Gw> {
        if let Some(route) = super::inference::classify(method, path) {
            return Some(route);
        }
        if method != "GET" {
            return Self::classify_write(method, path);
        }
        let segments = |prefix: &str| -> Option<Vec<&str>> {
            let rest = path.strip_prefix(prefix)?;
            Some(rest.strip_prefix('/')?.split('/').collect())
        };
        let item = |segment: &&str| !segment.is_empty();
        if let Some(parts) = segments(ADMIN_PREFIX) {
            return match parts.as_slice() {
                ["workspaces"] => Some(Gw::AdminWorkspaces),
                ["workspaces", id] if item(id) => Some(Gw::AdminWorkspaceGet),
                ["audit-logs"] => Some(Gw::AuditLogs),
                ["deployments"] => Some(Gw::Deployments),
                ["deployments", id] if item(id) => Some(Gw::DeploymentGet),
                ["deployments", id, "ping"] if item(id) => Some(Gw::DeploymentPing),
                ["utils", "static-resources", "schema"] => Some(Gw::GuardrailCatalog),
                ["utils", "static-resources", "ai-providers"] => Some(Gw::CatalogProviders),
                ["integrations"] => Some(Gw::Integrations),
                ["integrations", id] if item(id) => Some(Gw::IntegrationGet),
                ["integrations", id, "models"] if item(id) => Some(Gw::IntegrationModels),
                ["integrations", id, "workspaces"] if item(id) => Some(Gw::IntegrationWorkspaces),
                ["mcp-integrations"] => Some(Gw::McpIntegrations),
                ["mcp-integrations", id] if item(id) => Some(Gw::McpIntegrationGet),
                ["mcp-integrations", id, "capabilities"] if item(id) => Some(Gw::McpCapabilities),
                ["mcp-integrations", id, "metadata"] if item(id) => Some(Gw::McpMetadata),
                ["organisations", "self"] => Some(Gw::OrganisationSelf),
                ["organisations", tsg, "info"] if item(tsg) => Some(Gw::OrganisationInfo),
                ["organisations", tsg, "auth-settings"] if item(tsg) => Some(Gw::AuthSettings),
                ["plugins"] => Some(Gw::Plugins),
                ["guardrails"] => Some(Gw::AdminGuardrails),
                ["guardrails", id] if item(id) => Some(Gw::AdminGuardrailGet),
                ["guardrails", id, "mcp-servers"] if item(id) => Some(Gw::AdminMcpMappings),
                _ => None,
            };
        }
        if let Some(parts) = segments(DATA_PREFIX) {
            return match parts.as_slice() {
                ["workspaces"] => Some(Gw::DataWorkspaces),
                ["workspaces", id] if item(id) => Some(Gw::DataWorkspaceGet),
                ["logs"] => Some(Gw::Logs),
                ["logs", "charts", metric] if item(metric) => Some(Gw::Chart),
                ["logs", "groups", dimension] if item(dimension) => Some(Gw::Group),
                ["analytics", "filter-boundaries"] => Some(Gw::FilterBoundaries),
                ["api-keys", "service"] => Some(Gw::ServiceKeys),
                ["api-keys", "service", id] if item(id) => Some(Gw::ServiceKeyGet),
                ["api-keys", "user"] => Some(Gw::UserKeys),
                ["api-keys", "user", id] if item(id) => Some(Gw::UserKeyGet),
                ["configs"] => Some(Gw::Configs),
                ["configs", id] if item(id) => Some(Gw::ConfigGet),
                ["configs", id, "versions"] if item(id) => Some(Gw::ConfigVersions),
                ["guardrails"] => Some(Gw::Guardrails),
                ["guardrails", id] if item(id) => Some(Gw::GuardrailGet),
                ["providers"] => Some(Gw::Providers),
                ["providers", id] if item(id) => Some(Gw::ProviderGet),
                _ => None,
            };
        }
        let parts = segments(IAM_PREFIX)?;
        match parts.as_slice() {
            ["scopes"] => Some(Gw::ScopeList),
            ["scopes", name] if item(name) => Some(Gw::ScopeGet),
            _ => None,
        }
    }
}

impl Gw {
    /// Classifies a write (`POST`, `PUT`, `DELETE`) under the gateway bases.
    fn classify_write(method: &str, path: &str) -> Option<Gw> {
        let segments = |prefix: &str| -> Option<Vec<&str>> {
            let rest = path.strip_prefix(prefix)?;
            Some(rest.strip_prefix('/')?.split('/').collect())
        };
        let item = |segment: &&str| !segment.is_empty();
        let kind = |segment: &&str| matches!(*segment, "service" | "user");
        if let Some(parts) = segments(ADMIN_PREFIX) {
            return match (method, parts.as_slice()) {
                ("POST", ["workspaces"]) => Some(Gw::WorkspaceCreate),
                ("PUT", ["workspaces", r]) if item(r) => Some(Gw::WorkspaceUpdate),
                ("DELETE", ["workspaces", r]) if item(r) => Some(Gw::WorkspaceArchive),
                ("POST", ["deployments"]) => Some(Gw::DeploymentCreate),
                ("PUT", ["deployments", id]) if item(id) => Some(Gw::DeploymentUpdate),
                ("DELETE", ["deployments", id]) if item(id) => Some(Gw::DeploymentArchive),
                ("POST", ["integrations"]) => Some(Gw::IntegrationCreate),
                ("PUT", ["integrations", id]) if item(id) => Some(Gw::IntegrationUpdate),
                ("DELETE", ["integrations", id]) if item(id) => Some(Gw::IntegrationDelete),
                ("PUT", ["integrations", id, "models"]) if item(id) => Some(Gw::ModelsSet),
                ("PUT", ["integrations", id, "workspaces"]) if item(id) => {
                    Some(Gw::IntegrationWorkspacesSet)
                }
                ("POST", ["mcp-integrations"]) => Some(Gw::McpCreate),
                ("PUT", ["mcp-integrations", id]) if item(id) => Some(Gw::McpUpdate),
                ("DELETE", ["mcp-integrations", id]) if item(id) => Some(Gw::McpDelete),
                ("PUT", ["mcp-integrations", id, "capabilities"]) if item(id) => {
                    Some(Gw::CapabilitiesSet)
                }
                ("PUT", ["mcp-integrations", id, "workspaces"]) if item(id) => {
                    Some(Gw::McpWorkspacesSet)
                }
                ("PUT", ["organisations", "self"]) => Some(Gw::OrganisationUpdate),
                ("PUT", ["organisations", tsg, "auth-settings"]) if item(tsg) => {
                    Some(Gw::AuthSettingsUpdate)
                }
                ("POST", ["plugins"]) => Some(Gw::PluginCreate),
                ("POST", ["guardrails"]) => Some(Gw::AdminGuardrailCreate),
                ("PUT", ["guardrails", id]) if item(id) => Some(Gw::AdminGuardrailUpdate),
                ("DELETE", ["guardrails", id]) if item(id) => Some(Gw::AdminGuardrailDelete),
                ("PUT", ["guardrails", id, "mcp-servers"]) if item(id) => Some(Gw::McpSync),
                ("PUT", ["guardrails", id, "mcp-servers", server]) if item(id) && item(server) => {
                    Some(Gw::McpUpsert)
                }
                _ => None,
            };
        }
        if let Some(parts) = segments(DATA_PREFIX) {
            return match (method, parts.as_slice()) {
                ("POST", ["configs"]) => Some(Gw::ConfigCreate),
                ("PUT", ["configs", id]) if item(id) => Some(Gw::ConfigUpdate),
                ("DELETE", ["configs", id]) if item(id) => Some(Gw::ConfigDelete),
                ("POST", ["guardrails"]) => Some(Gw::GuardrailCreate),
                ("PUT", ["guardrails", id]) if item(id) => Some(Gw::GuardrailUpdate),
                ("DELETE", ["guardrails", id]) if item(id) => Some(Gw::GuardrailDelete),
                ("POST", ["providers"]) => Some(Gw::ProviderCreate),
                ("PUT", ["providers", id]) if item(id) => Some(Gw::ProviderUpdate),
                ("DELETE", ["providers", id]) if item(id) => Some(Gw::ProviderDelete),
                ("POST", ["api-keys", k]) if kind(k) => Some(Gw::KeyCreate),
                ("PUT", ["api-keys", k, id]) if kind(k) && item(id) => Some(Gw::KeyUpdate),
                ("DELETE", ["api-keys", k, id]) if kind(k) && item(id) => Some(Gw::KeyDelete),
                ("POST", ["api-keys", k, id, "rotate"]) if kind(k) && item(id) => {
                    Some(Gw::KeyRotate)
                }
                _ => None,
            };
        }
        let parts = segments(IAM_PREFIX)?;
        match (method, parts.as_slice()) {
            ("POST", ["scopes"]) => Some(Gw::ScopeCreate),
            ("PUT", ["scopes", name]) if item(name) => Some(Gw::ScopeUpdate),
            ("DELETE", ["scopes", name]) if item(name) => Some(Gw::ScopeDelete),
            _ => None,
        }
    }
}

/// The gateway dataset of one fixture server. Tests seed it with [`GatewayData::seeded`]
/// (through `FixtureServer::seed_gateway`) and edit its public fields
/// (`FixtureServer::gateway`).
#[derive(Clone, Debug, Default)]
pub struct GatewayData {
    /// Workspace list rows (`status` `active` or `archived`).
    pub workspaces: Vec<Value>,
    /// The ids of the workspaces the data plane lists (the service account's scope).
    pub data_plane: BTreeSet<String>,
    /// Workspace details by id (else derived from the row, [`fx::detail_of`]).
    pub details: BTreeMap<String, Value>,
    /// Report this `total` on every workspace list instead of the count.
    pub list_total: Option<Value>,
    /// Add `has_more` to every workspace list.
    pub has_more: Option<bool>,
    /// IAM scopes.
    pub scopes: Vec<Value>,
    /// Report this `count` on the scope list instead of the number of scopes.
    pub scope_count: Option<Value>,
    /// Chart bodies by metric (`/logs/charts/<metric>`); a missing metric answers 404.
    pub charts: BTreeMap<String, Value>,
    /// The `/logs/groups/<dimension>` body of every dimension but `users`.
    pub group: Option<Value>,
    /// The `/logs/groups/users` body.
    pub user_group: Option<Value>,
    /// Request log rows, paged by `pageSize` and `currentPage`.
    pub logs: Vec<Value>,
    /// Report this logs `total` instead of the number of rows.
    pub logs_total: Option<u64>,
    /// Flag every logs page `isQuotaExceeded`.
    pub logs_quota: bool,
    /// The `/analytics/filter-boundaries` body.
    pub filter_boundaries: Option<Value>,
    /// The answer of every chunk-2 inventory and admin read route ([`Gw::INVENTORY`]); a
    /// missing route answers 404. A single-resource route answers only for its fixture id
    /// (`fixtures::gateway::SERVICE_KEY`, ...), an organisation route only for the
    /// bearer's TSG (403 otherwise), and a workspace-scoped list only with
    /// `workspace_id=U(1)` (else an empty list).
    pub inventory: BTreeMap<Gw, Value>,
    /// The workspaces `POST <admin>/workspaces` created so far (their ids are `U(4 + n)`).
    pub workspaces_created: u64,
    /// The answer of each chunk-3 write route (`fixtures::gateway::write_answers`); the
    /// workspace and scope writes change the dataset instead.
    pub write_answers: BTreeMap<Gw, Value>,
    /// Ignore the next scope `PUT` (`ScopeUpdate`): the answer says it bound, the stored
    /// scope does not change (a concurrent writer replaced it, D236).
    pub scope_put_lost: bool,
    /// The JSON answer of each inference route (chunk 4; `fixtures::gateway`).
    pub inference: BTreeMap<Gw, Value>,
    /// The SSE body of each streaming inference route (`"stream": true` bodies).
    pub inference_streams: BTreeMap<Gw, Vec<u8>>,
}

impl GatewayData {
    /// The standard dataset (`fixtures::gateway`): three workspaces (one data-plane
    /// visible), two details, three scopes, every chart, the groups, three log rows and
    /// the filter boundaries.
    pub fn seeded() -> Self {
        let mut data = Self {
            workspaces: fx::workspaces(),
            data_plane: BTreeSet::from([fx::uuid(1)]),
            details: fx::details()
                .into_iter()
                .map(|detail| (detail["id"].as_str().unwrap_or_default().to_owned(), detail))
                .collect(),
            scopes: fx::scopes(),
            charts: fx::charts()
                .into_iter()
                .map(|(metric, body)| (metric.to_owned(), body))
                .collect(),
            group: Some(fx::group()),
            user_group: Some(fx::user_group()),
            logs: (1..=3).map(fx::log).collect(),
            filter_boundaries: Some(fx::filter_boundaries()),
            inventory: Self::seeded_inventory(),
            write_answers: fx::write_answers(),
            ..Self::default()
        };
        super::inference::seeded(&mut data);
        data
    }

    /// The chunk-2 inventory bodies (`fixtures::gateway`).
    pub fn seeded_inventory() -> BTreeMap<Gw, Value> {
        BTreeMap::from([
            (Gw::ServiceKeys, fx::service_keys()),
            (
                Gw::ServiceKeyGet,
                fx::api_key(fx::SERVICE_KEY, "service", &fx::marker(10)),
            ),
            (Gw::UserKeys, fx::user_keys()),
            (
                Gw::UserKeyGet,
                fx::api_key(fx::USER_KEY, "user", &fx::marker(11)),
            ),
            (Gw::AuditLogs, fx::audit_logs()),
            (Gw::Configs, fx::configs()),
            (Gw::ConfigGet, fx::config_detail()),
            (Gw::ConfigVersions, fx::config_versions()),
            (Gw::Deployments, fx::deployments()),
            (Gw::DeploymentGet, fx::deployment_detail()),
            (Gw::DeploymentPing, fx::deployment_ping()),
            (Gw::Guardrails, fx::guardrails()),
            (Gw::GuardrailGet, fx::guardrail_detail()),
            (Gw::GuardrailCatalog, fx::guardrail_catalog()),
            (Gw::Integrations, fx::list_of_integrations()),
            (Gw::IntegrationGet, fx::integration(true)),
            (Gw::CatalogProviders, fx::catalog_providers()),
            (Gw::IntegrationModels, fx::integration_models()),
            (Gw::IntegrationWorkspaces, fx::integration_workspaces()),
            (Gw::McpIntegrations, fx::mcp_integrations()),
            (Gw::McpIntegrationGet, fx::mcp_detail()),
            (Gw::McpCapabilities, fx::mcp_capabilities()),
            (Gw::McpMetadata, fx::mcp_metadata()),
            (Gw::OrganisationInfo, fx::organisation_info()),
            (Gw::OrganisationSelf, fx::organisation_self()),
            (Gw::AuthSettings, fx::auth_settings()),
            (Gw::Plugins, fx::plugins()),
            (Gw::Providers, fx::providers()),
            (Gw::ProviderGet, fx::provider_detail()),
            (Gw::AdminGuardrails, fx::admin_guardrails()),
            (Gw::AdminGuardrailGet, fx::admin_guardrail_detail()),
            (Gw::AdminMcpMappings, fx::admin_mcp_mappings()),
        ])
    }

    /// The answer of an inventory route (see [`GatewayData::inventory`]).
    fn inventory_answer(&self, route: Gw, request: &RecordedRequest, tsg: &str) -> Planned {
        let Some(body) = self.inventory.get(&route) else {
            return Planned::json(404, &json!({"message": "Not found"}));
        };
        let segments: Vec<String> = request.path.split('/').map(percent_decode).collect();
        if let Some(id) = route.expected_id() {
            let found = match route {
                Gw::ConfigVersions
                | Gw::DeploymentPing
                | Gw::IntegrationModels
                | Gw::IntegrationWorkspaces
                | Gw::McpCapabilities
                | Gw::McpMetadata
                | Gw::AdminMcpMappings => segments.iter().rev().nth(1),
                _ => segments.last(),
            };
            if found.map(String::as_str) != Some(fx::uuid(id).as_str()) {
                return Planned::json(404, &json!({"message": "Not found"}));
            }
        }
        if matches!(route, Gw::OrganisationInfo | Gw::AuthSettings)
            && segments.iter().rev().nth(1).map(String::as_str) != Some(tsg)
        {
            return Planned::json(403, &json!({"message": "Forbidden"}));
        }
        if matches!(
            route,
            Gw::ServiceKeys | Gw::UserKeys | Gw::Configs | Gw::Guardrails | Gw::Providers
        ) && request.query_value("workspace_id") != Some(fx::uuid(1).as_str())
        {
            return Planned::json(200, &json!({"object": "list", "total": 0, "data": []}));
        }
        if route == Gw::GuardrailCatalog {
            // The service's own member order, not serde_json's sorted one (D35).
            return Planned::raw(200, "application/json", fx::service_order(body));
        }
        Planned::json(200, body)
    }

    /// The rows the list of `plane` shows for `status` (none: active only).
    fn listed(&self, data: bool, status: Option<&str>) -> Vec<Value> {
        let wanted = status.unwrap_or("active");
        self.workspaces
            .iter()
            .filter(|row| row.get("status").and_then(Value::as_str) == Some(wanted))
            .filter(|row| {
                !data
                    || row
                        .get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| self.data_plane.contains(id))
            })
            .cloned()
            .collect()
    }

    fn list(&self, data: bool, status: Option<&str>) -> Planned {
        let rows = self.listed(data, status);
        let mut body = json!({
            "object": "list",
            "total": self.list_total.clone().unwrap_or_else(|| json!(rows.len())),
            "data": rows,
        });
        if let Some(more) = self.has_more {
            body["has_more"] = json!(more);
        }
        Planned::json(200, &body)
    }

    fn detail(&self, data: bool, reference: &str) -> Planned {
        let rows = self.listed(data, None);
        let found = rows.iter().find(|row| {
            row.get("id").and_then(Value::as_str) == Some(reference)
                || row.get("slug").and_then(Value::as_str) == Some(reference)
        });
        match found {
            Some(row) => {
                let id = row.get("id").and_then(Value::as_str).unwrap_or_default();
                let detail = self
                    .details
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| fx::detail_of(row));
                Planned::json(200, &detail)
            }
            None => Planned::json(
                404,
                &json!({"message": "Workspace not found", "errorCode": "AB08"}),
            ),
        }
    }
}

/// The answer of a gateway route.
pub(crate) fn answer(data: &mut GatewayData, route: Gw, request: &RecordedRequest) -> Planned {
    if route.is_inference() {
        return super::inference::answer(data, route, request);
    }
    let AuthIdentity::Bearer { tsg: Some(tsg) } = &request.auth else {
        return Planned::empty_json(401);
    };
    if request.header("x-tsg-id") != Some(tsg.as_str()) {
        return Planned::json(403, &json!({"message": "Forbidden"}));
    }
    let last = request
        .path
        .rsplit('/')
        .next()
        .map(percent_decode)
        .unwrap_or_default();
    if route.is_write() {
        return super::gateway_writes::answer(data, route, request, tsg);
    }
    match route {
        Gw::DataWorkspaces => data.list(true, None),
        Gw::AdminWorkspaces => match request.query_value("status") {
            Some(status @ ("active" | "archived")) => data.list(false, Some(status)),
            Some(_) => Planned::json(400, &json!({"message": "Invalid status"})),
            None => data.list(false, None),
        },
        Gw::DataWorkspaceGet => data.detail(true, &last),
        Gw::AdminWorkspaceGet => data.detail(false, &last),
        Gw::ScopeList => Planned::json(
            200,
            &json!({
                "count": data.scope_count.clone().unwrap_or_else(|| json!(data.scopes.len())),
                "items": data.scopes,
            }),
        ),
        Gw::ScopeGet => data
            .scopes
            .iter()
            .find(|scope| scope.get("name").and_then(Value::as_str) == Some(last.as_str()))
            .map_or_else(
                || Planned::json(404, &json!({"message": "Scope not found"})),
                |scope| Planned::json(200, scope),
            ),
        Gw::Chart => data.charts.get(&last).map_or_else(
            || Planned::json(404, &json!({"message": "Unknown chart"})),
            |body| Planned::json(200, body),
        ),
        Gw::Group => {
            let body = if last == "users" {
                data.user_group.clone()
            } else {
                data.group.clone()
            };
            body.map_or_else(
                || Planned::json(404, &json!({"message": "Unknown group"})),
                |body| Planned::json(200, &body),
            )
        }
        Gw::Logs => {
            let number = |key: &str, default: usize| {
                request
                    .query_value(key)
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(default)
            };
            let size = number("pageSize", 50);
            let page = number("currentPage", 0);
            let rows: Vec<Value> = data
                .logs
                .iter()
                .skip(page.saturating_mul(size))
                .take(size)
                .cloned()
                .collect();
            Planned::json(
                200,
                &json!({
                    "success": true,
                    "data": {
                        "records": rows,
                        "total": data.logs_total.unwrap_or(data.logs.len() as u64),
                        "capturedTotal": data.logs.len(),
                        "isQuotaExceeded": data.logs_quota,
                    },
                }),
            )
        }
        Gw::FilterBoundaries => data.filter_boundaries.as_ref().map_or_else(
            || Planned::json(404, &json!({"message": "Not found"})),
            |body| Planned::json(200, body),
        ),
        _ => data.inventory_answer(route, request, tsg),
    }
}
