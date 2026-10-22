//! The gateway write routes of the fixture (DESIGN §10 M6e, chunk 3).
//!
//! - The workspace and scope writes change the dataset, so the read-backs and later reads
//!   see the change: `POST <admin>/workspaces` adds `U(4 + n)` (slug
//!   `ws-<name stem>-<n, 6 digits>`, active, admin plane only, its scope and description
//!   as sent; `name` and `scope_name` required, else 422); `PUT <admin>/workspaces/{ref}`
//!   updates `name`, `description`, `icon` and the blocks of the active row (404 for any
//!   other ref) and answers `{}`; `DELETE` archives it (204); `POST <iam>/scopes` adds an
//!   unbound scope (409 when the name exists); `PUT <iam>/scopes/{name}` replaces its
//!   description and resources (ignored once with [`GatewayData::scope_put_lost`]);
//!   `DELETE <iam>/scopes/{name}` removes it (204).
//! - Every other write answers [`GatewayData::write_answers`] for its fixture id (404 for
//!   another id): a key create its one-time key, a rotate its new key, a deployment create
//!   its credentials, a rotating deployment update (`rotate_auth: true`) new credentials;
//!   a delete 204. The deployment and integration deletes need `organisation_id` = the
//!   bearer's TSG (400 otherwise), the auth-settings update the bearer's TSG in the path
//!   (403 otherwise).

use serde_json::{Value, json};

use super::gateway::{GatewayData, Gw};
use super::plan::Planned;
use super::record::RecordedRequest;
use super::redteam::percent_decode;
use crate::fixtures::gateway as fx;

fn not_found() -> Planned {
    Planned::json(404, &json!({"message": "Not found"}))
}

fn text<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str)
}

/// The answer of a gateway write route (credentials and `x-tsg-id` already checked).
pub(crate) fn answer(
    data: &mut GatewayData,
    route: Gw,
    request: &RecordedRequest,
    tsg: &str,
) -> Planned {
    let body = request.body_json().unwrap_or(Value::Null);
    let segments: Vec<String> = request.path.split('/').map(percent_decode).collect();
    let last = segments.last().cloned().unwrap_or_default();
    // The id segment of an `…/<id>/<action>` route.
    let parent = segments.iter().rev().nth(1).cloned().unwrap_or_default();
    let is = |id: &str, n: u64| id == fx::uuid(n);
    match route {
        Gw::WorkspaceCreate => workspace_create(data, &body),
        Gw::WorkspaceUpdate => workspace_update(data, &last, &body),
        Gw::WorkspaceArchive => {
            match data.workspaces.iter_mut().find(|row| {
                row["status"] == "active"
                    && (row["id"] == last.as_str() || row["slug"] == last.as_str())
            }) {
                Some(row) => {
                    row["status"] = json!("archived");
                    Planned::status(204)
                }
                None => Planned::json(
                    404,
                    &json!({"message": "Workspace not found", "errorCode": "AB08"}),
                ),
            }
        }
        Gw::ScopeCreate => {
            let Some(name) = text(&body, "name") else {
                return Planned::json(422, &json!({"message": "name is required"}));
            };
            if data.scopes.iter().any(|scope| scope["name"] == name) {
                return Planned::json(409, &json!({"message": "Scope exists"}));
            }
            let scope = fx::scope(name, text(&body, "description").unwrap_or_default(), &[]);
            data.scopes.push(scope.clone());
            Planned::json(200, &scope)
        }
        Gw::ScopeUpdate => {
            let lost = std::mem::take(&mut data.scope_put_lost);
            let Some(scope) = data
                .scopes
                .iter_mut()
                .find(|scope| scope["name"] == last.as_str())
            else {
                return Planned::json(404, &json!({"message": "Scope not found"}));
            };
            let mut updated = scope.clone();
            updated["description"] = body.get("description").cloned().unwrap_or(json!(""));
            updated["resources"] = body.get("resources").cloned().unwrap_or(json!([]));
            if !lost {
                *scope = updated.clone();
            }
            Planned::json(200, &updated)
        }
        Gw::ScopeDelete => {
            let before = data.scopes.len();
            data.scopes.retain(|scope| scope["name"] != last.as_str());
            if data.scopes.len() == before {
                Planned::json(404, &json!({"message": "Scope not found"}))
            } else {
                Planned::status(204)
            }
        }
        Gw::ConfigDelete
        | Gw::GuardrailDelete
        | Gw::ProviderDelete
        | Gw::KeyDelete
        | Gw::McpDelete
        | Gw::AdminGuardrailDelete => {
            let expected = match route {
                Gw::ConfigDelete => fx::CONFIG,
                Gw::GuardrailDelete => fx::GUARDRAIL,
                Gw::ProviderDelete => fx::PROVIDER,
                Gw::McpDelete => fx::MCP_INTEGRATION,
                Gw::AdminGuardrailDelete => fx::ADMIN_GUARDRAIL,
                _ if parent == "user" => fx::USER_KEY,
                _ => fx::SERVICE_KEY,
            };
            if is(&last, expected) {
                Planned::status(204)
            } else {
                not_found()
            }
        }
        Gw::DeploymentArchive | Gw::IntegrationDelete => {
            let expected = if route == Gw::DeploymentArchive {
                fx::DEPLOYMENT
            } else {
                fx::INTEGRATION
            };
            if !is(&last, expected) {
                return not_found();
            }
            if request.query_value("organisation_id") != Some(tsg) {
                return Planned::json(
                    400,
                    &json!({"message": "organisation_id must be the caller's organisation"}),
                );
            }
            Planned::status(204)
        }
        Gw::KeyCreate => Planned::json(200, &fx::key_created(&last)),
        Gw::KeyRotate => {
            let expected = if segments.iter().rev().nth(2).map(String::as_str) == Some("user") {
                fx::USER_KEY
            } else {
                fx::SERVICE_KEY
            };
            if is(&parent, expected) {
                Planned::json(200, &fx::key_rotated(&parent))
            } else {
                not_found()
            }
        }
        Gw::DeploymentCreate => Planned::json(200, &fx::deployment_created()),
        Gw::DeploymentUpdate if body.get("rotate_auth") == Some(&Value::Bool(true)) => {
            if is(&last, fx::DEPLOYMENT) {
                Planned::json(200, &fx::deployment_rotated())
            } else {
                not_found()
            }
        }
        Gw::AuthSettingsUpdate if parent != tsg => {
            Planned::json(403, &json!({"message": "Forbidden"}))
        }
        _ => {
            let expected = match route {
                Gw::ConfigUpdate => Some((last.as_str(), fx::CONFIG)),
                Gw::GuardrailUpdate => Some((last.as_str(), fx::GUARDRAIL)),
                Gw::ProviderUpdate => Some((last.as_str(), fx::PROVIDER)),
                Gw::KeyUpdate if parent == "user" => Some((last.as_str(), fx::USER_KEY)),
                Gw::KeyUpdate => Some((last.as_str(), fx::SERVICE_KEY)),
                Gw::DeploymentUpdate => Some((last.as_str(), fx::DEPLOYMENT)),
                Gw::IntegrationUpdate => Some((last.as_str(), fx::INTEGRATION)),
                Gw::ModelsSet | Gw::IntegrationWorkspacesSet => {
                    Some((parent.as_str(), fx::INTEGRATION))
                }
                Gw::McpUpdate => Some((last.as_str(), fx::MCP_INTEGRATION)),
                Gw::CapabilitiesSet | Gw::McpWorkspacesSet => {
                    Some((parent.as_str(), fx::MCP_INTEGRATION))
                }
                Gw::AdminGuardrailUpdate => Some((last.as_str(), fx::ADMIN_GUARDRAIL)),
                Gw::McpSync => Some((parent.as_str(), fx::ADMIN_GUARDRAIL)),
                Gw::McpUpsert => {
                    let guardrail = segments.iter().rev().nth(2).cloned().unwrap_or_default();
                    if !is(&guardrail, fx::ADMIN_GUARDRAIL) {
                        return not_found();
                    }
                    Some((last.as_str(), fx::MCP_SERVER))
                }
                _ => None,
            };
            if let Some((id, n)) = expected
                && !is(id, n)
            {
                return not_found();
            }
            data.write_answers
                .get(&route)
                .map_or_else(not_found, |answer| Planned::json(200, answer))
        }
    }
}

/// `POST <admin>/workspaces`: a new active workspace (admin plane only).
fn workspace_create(data: &mut GatewayData, body: &Value) -> Planned {
    let (Some(name), Some(scope)) = (text(body, "name"), text(body, "scope_name")) else {
        return Planned::json(422, &json!({"message": "name and scope_name are required"}));
    };
    data.workspaces_created += 1;
    let n = 3 + data.workspaces_created;
    let stem: String = name
        .to_ascii_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(6)
        .collect();
    let slug = format!("ws-{stem}-{n:06}");
    let mut row = fx::workspace(n, &slug, name, "active", false, scope);
    row["description"] = body.get("description").cloned().unwrap_or(Value::Null);
    if let Some(icon) = body.get("icon") {
        row["icon"] = icon.clone();
    }
    let mut detail = fx::detail_of(&row);
    for key in ["defaults", "usage_limits", "rate_limits"] {
        if let Some(block) = body.get(key) {
            detail[key] = block.clone();
        }
    }
    detail["scope_name"] = json!(scope);
    data.details.insert(fx::uuid(n), detail);
    data.workspaces.push(row.clone());
    let mut answer = json!({
        "created_at": row["created_at"],
        "description": row["description"],
        "id": row["id"],
        "last_updated_at": row["last_updated_at"],
        "name": name,
        "object": "workspace",
        "scope_name": scope,
        "slug": slug,
    });
    if let Some(users) = body.get("users") {
        answer["users"] = users.clone();
    }
    Planned::json(200, &answer)
}

/// `PUT <admin>/workspaces/{ref}`: the fields and blocks sent replace the stored ones.
fn workspace_update(data: &mut GatewayData, reference: &str, body: &Value) -> Planned {
    let Some(row) = data.workspaces.iter_mut().find(|row| {
        row["status"] == "active" && (row["id"] == reference || row["slug"] == reference)
    }) else {
        return Planned::json(
            404,
            &json!({"message": "Workspace not found", "errorCode": "AB08"}),
        );
    };
    for key in ["name", "description", "icon"] {
        if let Some(value) = body.get(key) {
            row[key] = value.clone();
        }
    }
    let id = row["id"].as_str().unwrap_or_default().to_owned();
    let row = row.clone();
    let detail = data
        .details
        .entry(id)
        .or_insert_with(|| fx::detail_of(&row));
    for key in [
        "name",
        "description",
        "icon",
        "defaults",
        "usage_limits",
        "rate_limits",
    ] {
        if let Some(value) = body.get(key) {
            detail[key] = value.clone();
        }
    }
    Planned::json(200, &json!({}))
}
