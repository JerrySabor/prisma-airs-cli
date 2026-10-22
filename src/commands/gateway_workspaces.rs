//! `gateway workspaces list|get` and `gateway scopes list|get` (DESIGN §19.5, §19.7).
//!
//! Every read is one SDK call (the SDK read retries, D10) with its own options; every
//! document is withheld (`gateway::withhold`) before it is projected and printed.

use super::Invocation;
use super::gateway::{WorkspaceList, incomplete_warning};
use crate::clients::SINGLE_REQUEST_BUDGET;
use crate::error::CliError;
use crate::gateway::resolve::{self, ListRead, Resolved};
use crate::gateway::views;
use crate::gateway::withhold::{self, PLAIN};
use crate::gateway::{self, GwPlane};
use crate::json::OValue;
use crate::output::Format;
use scm::airs::gateway::{AIGatewayClient, AIGatewayWorkspaceGetOptions};

/// The data-plane status line of `workspaces list` (TS text; every format, choice 8).
const DATA_PLANE_NOTE: &str = "Data-plane list shows only active workspaces you are scoped to — use --plane admin or --all for the whole tenant.";

/// One workspace list as withheld rows, with its G39 warning.
async fn list_rows(
    invocation: &mut Invocation,
    gateway: &AIGatewayClient,
    read: ListRead,
) -> Result<(Vec<OValue>, Option<String>), CliError> {
    let mut answer = match resolve::read_list(gateway, read).await {
        Ok(answer) => answer,
        Err(failure) => return Err(invocation.gateway_error(&failure.error, failure.plane)),
    };
    withhold::apply(&mut answer, &PLAIN, &invocation.secrets);
    let rows = answer
        .get("data")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .to_vec();
    let warning = incomplete_warning(
        rows.len(),
        answer.get("total"),
        matches!(answer.get("has_more"), Some(OValue::Bool(true))),
        "workspaces",
    );
    Ok((rows, warning))
}

/// `workspaces list|ls` (§19.5).
pub async fn list(
    invocation: &mut Invocation,
    list: WorkspaceList,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (gateway, format) = invocation.connect_gateway(explicit).await?;
    let reads: Vec<ListRead> = match list {
        WorkspaceList::One { plane, status } => vec![ListRead { plane, status }],
        WorkspaceList::All => resolve::TELEMETRY[1..].to_vec(),
    };
    let mut rows = Vec::new();
    let mut warnings = Vec::new();
    for read in reads {
        let (found, warning) = list_rows(invocation, &gateway, read).await?;
        rows.extend(found);
        warnings.extend(warning);
    }
    let records: Vec<OValue> = rows.iter().map(views::workspace).collect();
    views::render_workspace_list(&mut invocation.output, &records, format)?;
    for warning in warnings {
        invocation.output.warning(&warning);
    }
    if matches!(
        list,
        WorkspaceList::One {
            plane: GwPlane::Data,
            ..
        }
    ) {
        invocation.output.status(DATA_PLANE_NOTE);
    }
    Ok(())
}

/// One `GET <plane>/workspaces/<ref>` as an ordered document.
pub(super) async fn read_detail(
    gateway: &AIGatewayClient,
    reference: &str,
    plane: GwPlane,
) -> Result<OValue, scm::Error> {
    let options = gateway::sdk_options(SINGLE_REQUEST_BUDGET)?;
    let mut query = AIGatewayWorkspaceGetOptions::default();
    query.plane = plane.sdk();
    let detail = gateway
        .workspaces()
        .get(reference, &query, Some(&options))
        .await?;
    crate::json::page_value(&detail)
}

/// `workspaces get <ref>` (§19.5): one read; on a 404 only, the name on the requested
/// plane's active list, read again by its slug (choice 14).
pub async fn get(
    invocation: &mut Invocation,
    reference: &str,
    plane: GwPlane,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (gateway, format) = invocation.connect_gateway(explicit).await?;
    let mut detail = match read_detail(&gateway, reference, plane).await {
        Ok(detail) => detail,
        Err(error) if error.kind() == scm::ErrorKind::Http && error.status() == Some(404) => {
            let read = ListRead {
                plane,
                status: None,
            };
            let found = match resolve::resolve(&gateway, reference, &[read]).await {
                Ok(found) => found,
                Err(failure) => {
                    return Err(invocation.gateway_error(&failure.error, failure.plane));
                }
            };
            match found {
                Resolved::ByName(slug) if slug != reference => {
                    match read_detail(&gateway, &slug, plane).await {
                        Ok(detail) => detail,
                        Err(error) => return Err(invocation.gateway_error(&error, plane)),
                    }
                }
                Resolved::Ambiguous(slugs) => {
                    return Err(CliError::operational(resolve::ambiguous_message(
                        reference, &slugs,
                    )));
                }
                Resolved::Incomplete => {
                    return Err(CliError::operational(resolve::incomplete_message(
                        reference, false,
                    )));
                }
                Resolved::NoSlug => {
                    return Err(CliError::operational(resolve::no_slug_message(
                        reference, false,
                    )));
                }
                _ => return Err(invocation.gateway_error(&error, plane)),
            }
        }
        Err(error) => return Err(invocation.gateway_error(&error, plane)),
    };
    withhold::apply(&mut detail, &PLAIN, &invocation.secrets);
    views::render_workspace_detail(
        &mut invocation.output,
        &views::workspace_detail(&detail),
        format,
    )
}

/// `scopes list|ls` (§19.7).
pub async fn scopes_list(
    invocation: &mut Invocation,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (gateway, format) = invocation.connect_gateway(explicit).await?;
    let options = gateway::options(SINGLE_REQUEST_BUDGET)?;
    let answer = match gateway.iam_scopes().list(Some(&options)).await {
        Ok(answer) => answer,
        Err(error) => return Err(invocation.gateway_error(&error, GwPlane::Iam)),
    };
    let mut answer = crate::json::model_value(&answer)?;
    withhold::apply(&mut answer, &PLAIN, &invocation.secrets);
    let items = answer
        .get("items")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    let scopes: Vec<OValue> = items.iter().map(views::scope).collect();
    views::render_scope_list(&mut invocation.output, &scopes, format)?;
    if let Some(warning) =
        incomplete_warning(scopes.len(), answer.get("count"), false, "IAM scopes")
    {
        invocation.output.warning(&warning);
    }
    Ok(())
}

/// `scopes get <name>` (§19.7).
pub async fn scopes_get(
    invocation: &mut Invocation,
    name: &str,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (gateway, format) = invocation.connect_gateway(explicit).await?;
    let options = gateway::options(SINGLE_REQUEST_BUDGET)?;
    let scope = match gateway.iam_scopes().get(name, Some(&options)).await {
        Ok(scope) => scope,
        Err(error) => return Err(invocation.gateway_error(&error, GwPlane::Iam)),
    };
    let mut scope = crate::json::model_value(&scope)?;
    withhold::apply(&mut scope, &PLAIN, &invocation.secrets);
    views::render_scope_detail(&mut invocation.output, &views::scope(&scope), format)
}
