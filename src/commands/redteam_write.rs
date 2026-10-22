//! The red team wrapper of the shared write machinery (DESIGN §15.3): the
//! unauthenticated client (a confirmation is asked before the token is fetched), the
//! token, the credential registration of user-supplied documents (§15.4) and the answer
//! fields. The D81 gate and confirmation, the one-attempt write with its outcome and hint
//! lines (D133), the interruption contexts, the bounded input files (D143) and the
//! request-body validation (D116) are `write_common`'s, re-exported here for the red team
//! command modules.

use super::Invocation;
pub use super::write_common::{Contexts, body, config_object, confirm, gate, send};
use crate::clients::{RedTeamClients, TOKEN_BUDGET};
use crate::error::CliError;
use crate::json::OValue;
use scm::airs::red_team::RedTeamClient;

/// The red team client of the selected tenant, not yet authenticated, and the tenant's
/// `defaultOutput`.
pub struct Unauthenticated {
    pub clients: RedTeamClients,
    pub default_output: Option<String>,
    /// The selected tenant's store name and `mgmtTsgId` (backups, §15.18).
    pub tenant: String,
    pub tsg: String,
}

impl Unauthenticated {
    pub fn client(&self) -> &RedTeamClient {
        &self.clients.red_team
    }
}

impl Invocation {
    /// Load the tenant, check the management credentials (§3.5) and build the red team
    /// client, without any request (a confirmation may follow, §15.3).
    pub fn red_team_unauthenticated(&mut self) -> Result<Unauthenticated, CliError> {
        let context = self.load_tenant()?;
        let default_output = context.config.default_output().map(str::to_owned);
        crate::tenant::config::require_management(&context.config, Some(context.name()))?;
        let clients = RedTeamClients::build(
            &context.config,
            &self.session,
            &self.secrets,
            self.debug.as_ref(),
        )?;
        Ok(Unauthenticated {
            clients,
            default_output,
            tenant: context.name().to_owned(),
            tsg: crate::tenant::config::js_trim(
                context
                    .config
                    .effective_str("mgmtTsgId")
                    .unwrap_or_default(),
            )
            .to_owned(),
        })
    }
}

/// Fetch the OAuth token of a write (the SDK's token budget); an interruption reports
/// `contexts.not_sent`.
pub async fn authenticate(prepared: &Unauthenticated, contexts: &Contexts) -> Result<(), CliError> {
    prepared
        .clients
        .authenticate(None, TOKEN_BUDGET)
        .await
        .map_err(|error| contexts.before(error))
}

/// The tenant, the client and the token of a write that asks nothing first.
pub async fn connect(
    invocation: &mut Invocation,
    contexts: &Contexts,
) -> Result<Unauthenticated, CliError> {
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    authenticate(&prepared, contexts).await?;
    Ok(prepared)
}

/// Register the credential values of a document the user supplied (§15.4: the same
/// rules as for printed documents), without changing it.
pub fn register_secrets(
    invocation: &Invocation,
    value: &serde_json::Value,
    shape: crate::redteam::secrets::Shape,
) {
    if let Ok(mut copy) = crate::json::to_ordered(value) {
        crate::redteam::secrets::redact(&mut copy, shape, &invocation.secrets);
    }
}

/// A string field of an answer (`""` when absent).
pub fn field(doc: &OValue, key: &str) -> String {
    doc.get(key)
        .and_then(OValue::as_str)
        .unwrap_or_default()
        .to_owned()
}
