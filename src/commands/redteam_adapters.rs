//! `redteam adapter list|get` (DESIGN §15.14). `SECRET` variable values are always
//! redacted, even when the server sent them unmasked (D140).

use super::Invocation;
use super::redteam::{page_of, page_value, read, value, walk_all, walk_deadline};
use crate::error::CliError;
use crate::json::OValue;
use crate::output::Format;
use crate::redteam::ListParams;
use crate::redteam::secrets::{self, Shape};
use crate::redteam::views;
use scm::airs::red_team::AdapterListOptions;

/// `adapter list|ls`: one page (`skip`, `limit`, `search` only when given; the
/// `<n> total` line when the page carried `pagination.total_items`), or the `--all` walk
/// with page size `--limit`, else 50.
pub async fn list(
    invocation: &mut Invocation,
    params: &ListParams,
    search: Option<String>,
    format: Option<Format>,
) -> Result<(), CliError> {
    let mut options = AdapterListOptions::default();
    options.search = search;
    let (rows, total, format) = if params.all {
        let deadline = walk_deadline()?;
        let connected = invocation.connect_red_team(Some(&deadline)).await?;
        let format = connected.format(format);
        let adapters = connected.client.adapters();
        let rows = walk_all(
            invocation,
            params.limit.unwrap_or(50),
            params.max,
            true,
            |skip, limit| {
                let mut page = options.clone();
                page.skip = Some(skip);
                page.limit = Some(limit);
                let adapters = adapters.clone();
                let deadline = deadline.clone();
                async move {
                    let answer = adapters.list(&page, Some(&deadline)).await?;
                    Ok(page_of(&page_value(&answer)?))
                }
            },
        )
        .await?;
        (rows, None, format)
    } else {
        let connected = invocation.connect_red_team(None).await?;
        let format = connected.format(format);
        options.skip = params.offset;
        options.limit = params.limit;
        let answer = read(invocation, connected.client.adapters().list(&options, None)).await?;
        let answer = value(&answer)?;
        let total = answer
            .get("pagination")
            .and_then(|pagination| pagination.get("total_items"))
            .filter(|total| !matches!(total, OValue::Null))
            .cloned();
        (page_of(&answer).rows, total, format)
    };
    let mut rows: Vec<OValue> = rows.iter().map(views::adapter_row).collect();
    for row in &mut rows {
        views::withhold(row, &invocation.secrets);
    }
    views::list(
        &mut invocation.output,
        format,
        &rows,
        &views::ADAPTER_COLUMNS,
        "adapters",
        |out, rows| views::adapter_list_layout(out, rows, total.as_ref()),
    )
}

/// `adapter get <uuid>`: the TS normalised detail; `scriptB64` printed (TS parity).
pub async fn get(
    invocation: &mut Invocation,
    uuid: &str,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let answer = read(invocation, connected.client.adapters().get(uuid, None)).await?;
    let mut doc = views::adapter_detail(&value(&answer)?);
    secrets::redact(&mut doc, Shape::Adapter, &invocation.secrets);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::adapter_layout(out, &doc);
    })
}

// ---------------------------------------------------------------------------
// Writes (§15.14)
// ---------------------------------------------------------------------------

use super::redteam_write::{self as rw, Contexts};
use crate::redteam::args::{self, Script, Variables};
use crate::writes::Change;
use scm::airs::red_team::{AdapterOperationOptions, models as rtm};

/// A planned `adapter create|update|validate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterPlan {
    pub kind: AdapterKind,
    pub name: Option<String>,
    pub prompt: String,
    pub script: Script,
    pub description: Option<String>,
    pub channel: Option<String>,
    pub variables: Variables,
    pub draft: bool,
    pub format: Format,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterKind {
    Create,
    Update(String),
    /// `validate`, with `--adapter`.
    Validate(Option<String>),
}

/// The script and variables of a plan, read from their files (before the tenant); every
/// `SECRET` value joins the secret set.
fn inputs(
    invocation: &Invocation,
    plan: &AdapterPlan,
) -> Result<(Option<String>, Option<serde_json::Value>), CliError> {
    let script = match &plan.script {
        Script::None => None,
        Script::Base64(b64) => Some(b64.clone()),
        Script::File(path) => Some(args::base64(&crate::files::read_bytes(
            path,
            crate::files::SCRIPT_LIMIT,
        )?)),
    };
    let variables = match &plan.variables {
        Variables::None => None,
        Variables::Inline(value) => Some(value.clone()),
        Variables::File(path) => {
            let text = crate::files::read_text(path, crate::files::CONFIG_LIMIT)?;
            Some(args::variable_list(&text, "--variables-file").map_err(CliError::operational)?)
        }
    };
    if let Some(serde_json::Value::Array(items)) = &variables {
        for item in items {
            if item.get("type").and_then(serde_json::Value::as_str) == Some("SECRET")
                && let Some(value) = item.get("value").and_then(serde_json::Value::as_str)
            {
                invocation.secrets.add(value);
            }
        }
    }
    Ok((script, variables))
}

/// TS `assertChannelOnline`: a channel whose status is set and not `ONLINE` is refused
/// (exit 1, no write); a failing lookup is ignored (the service decides). An
/// interruption is not ignored.
async fn channel_online(
    invocation: &Invocation,
    client: &scm::airs::red_team::RedTeamClient,
    channel: &str,
    contexts: &Contexts,
) -> Result<(), CliError> {
    match client.network_broker().get_channel(channel, None).await {
        Ok(found) => {
            let status = value(&found)?
                .get("status")
                .and_then(OValue::as_str)
                .unwrap_or_default()
                .to_owned();
            if !status.is_empty() && status != "ONLINE" {
                return Err(CliError::operational(format!(
                    "network broker channel {channel} is {} — adapter validation requires an ONLINE channel (network broker v1.4.0+). Check 'airs redteam network-broker channels list'.",
                    crate::output::terminal_safe(&status)
                )));
            }
            Ok(())
        }
        Err(error) if error.kind() == scm::ErrorKind::Cancelled => Err(contexts
            .before(invocation.management_error(&error, crate::clients::SINGLE_REQUEST_BUDGET))),
        Err(_) => Ok(()),
    }
}

/// Register the credentials of a stored adapter that a read-modify-write sends back
/// (its `SECRET` variable values, which a server may return unmasked, §15.4), so script
/// output or an error that echoes one is withheld.
fn register_stored(invocation: &Invocation, current: &OValue) {
    let mut copy = current.clone();
    secrets::redact(&mut copy, Shape::Adapter, &invocation.secrets);
}

/// The redacted adapter detail in `format`.
fn render_detail(
    invocation: &mut Invocation,
    format: Format,
    raw: &OValue,
) -> Result<(), CliError> {
    let mut doc = views::adapter_detail(raw);
    secrets::redact(&mut doc, Shape::Adapter, &invocation.secrets);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::adapter_layout(out, &doc);
    })
}

/// `adapter create|update|validate`.
pub async fn write(invocation: &mut Invocation, plan: &AdapterPlan) -> Result<(), CliError> {
    let (script, variables) = inputs(invocation, plan)?;
    let contexts = Contexts::plain();
    // A create body is built from arguments and files only: validated before the tenant.
    let create = match &plan.kind {
        AdapterKind::Create => {
            let mut body = serde_json::json!({
                "name": plan.name.clone().unwrap_or_default(),
                "script_b64": script.clone().unwrap_or_default(),
                "prompt": plan.prompt,
            });
            if let Some(description) = &plan.description {
                body["description"] = serde_json::json!(description);
            }
            if let Some(channel) = &plan.channel {
                body["network_broker_channel_uuid"] = serde_json::json!(channel);
            }
            if let Some(variables) = &variables {
                body["variables"] = variables.clone();
            }
            Some(rw::body(
                body,
                "POST",
                "/v1/adapters",
                rtm::AdapterCreateRequest::parse,
            )?)
        }
        _ => None,
    };
    let prepared = rw::connect(invocation, &contexts).await?;
    let client = prepared.client().clone();
    let adapters = client.adapters();
    let check_channel = match &plan.kind {
        AdapterKind::Validate(_) => plan.channel.as_deref(),
        _ if plan.draft => None,
        _ => plan.channel.as_deref(),
    };
    if let Some(channel) = check_channel {
        channel_online(invocation, &client, channel, &contexts).await?;
    }
    let mut operation = AdapterOperationOptions::default();
    operation.validate = Some(!plan.draft);
    match &plan.kind {
        AdapterKind::Create => {
            let Some(body) = create else {
                return Ok(());
            };
            let answer = rw::send(
                invocation,
                Change::Words("adapter", "created"),
                None,
                &contexts,
                async || adapters.create(&body, Some(&operation), None).await,
            )
            .await?;
            invocation.committed = true;
            let answer = value(&answer)?;
            invocation
                .output
                .success(&format!("Adapter created: {}", rw::field(&answer, "uuid")));
            render_detail(invocation, plan.format, &answer)
        }
        AdapterKind::Update(uuid) => {
            let current = read(invocation, adapters.get(uuid, None))
                .await
                .map_err(|error| contexts.before(error))?;
            let current = value(&current)?;
            register_stored(invocation, &current);
            let string = |key: &str| current.get(key).and_then(OValue::as_str).map(str::to_owned);
            let mut body = serde_json::json!({
                "name": plan.name.clone().or_else(|| string("name")).unwrap_or_default(),
                "script_b64": script.clone().or_else(|| string("script_b64")).unwrap_or_default(),
                "prompt": plan.prompt,
                "variables": variables.clone().unwrap_or_else(|| args::preserve_variables(&current)),
            });
            if let Some(description) = plan.description.clone().or_else(|| string("description")) {
                body["description"] = serde_json::json!(description);
            }
            if let Some(channel) = carried_channel(plan.channel.clone(), &current)? {
                body["network_broker_channel_uuid"] = serde_json::json!(channel);
            }
            let body = rw::body(
                body,
                "PUT",
                &format!("/v1/adapters/{uuid}"),
                rtm::AdapterUpdateRequest::parse,
            )?;
            let answer = rw::send(
                invocation,
                Change::Words("adapter", "updated"),
                None,
                &contexts,
                async || adapters.update(uuid, &body, Some(&operation), None).await,
            )
            .await?;
            invocation.committed = true;
            let answer = value(&answer)?;
            invocation
                .output
                .success(&format!("Adapter updated: {}", rw::field(&answer, "uuid")));
            render_detail(invocation, plan.format, &answer)
        }
        AdapterKind::Validate(adapter) => {
            let variables = match (&variables, adapter) {
                (None, Some(adapter)) => {
                    let current = read(invocation, adapters.get(adapter, None))
                        .await
                        .map_err(|error| contexts.before(error))?;
                    let current = value(&current)?;
                    register_stored(invocation, &current);
                    Some(args::preserve_variables(&current))
                }
                (variables, _) => variables.clone(),
            };
            let mut body = serde_json::json!({
                "script_b64": script.clone().unwrap_or_default(),
                "network_broker_channel_uuid": plan.channel.clone().unwrap_or_default(),
                "prompt": plan.prompt,
            });
            if let Some(variables) = variables {
                body["variables"] = variables;
            }
            if let Some(adapter) = adapter {
                body["adapter_uuid"] = serde_json::json!(adapter);
            }
            let body = rw::body(
                body,
                "POST",
                "/v1/adapters/validate",
                rtm::AdapterValidateRequest::parse,
            )?;
            let answer = rw::send(
                invocation,
                Change::Words("adapter script", "run"),
                None,
                &contexts,
                async || adapters.validate(&body, None).await,
            )
            .await?;
            let mut doc = views::adapter_validation(&value(&answer)?);
            views::withhold_outputs(&mut doc, &invocation.secrets);
            let validated = matches!(doc.get("validated"), Some(OValue::Bool(true)));
            views::detail(&mut invocation.output, plan.format, &doc, |out| {
                views::adapter_validation_layout(out, &doc);
            })?;
            if validated {
                invocation.output.success("Adapter script validated");
                return Ok(());
            }
            let _ = invocation.output.commit();
            let line = invocation.output.paint_err(
                crate::render::style::Style::Red,
                "✗ Adapter script validation FAILED",
            );
            invocation.output.write_stderr(&format!("  {line}\n"));
            Err(CliError::Reported(crate::error::EXIT_OPERATIONAL))
        }
    }
}

/// The channel an update sends: `--channel` (checked before the tenant, D141), else the
/// stored adapter's. scm-sdk 0.2.2 reads a stored channel that is not a UUID (D306) but
/// refuses it in the PUT body, so it is refused here, after the read and before the
/// write, naming the field and the way out instead of the body (D307, §15.23).
fn carried_channel(given: Option<String>, current: &OValue) -> Result<Option<String>, CliError> {
    if given.is_some() {
        return Ok(given);
    }
    match current
        .get("network_broker_channel_uuid")
        .and_then(OValue::as_str)
    {
        Some(stored) if !crate::pagination::is_uuid(stored) => {
            Err(CliError::operational(STORED_CHANNEL_NOT_UUID))
        }
        stored => Ok(stored.map(str::to_owned)),
    }
}

/// D307: the stored channel of `adapter update` is not a UUID.
const STORED_CHANNEL_NOT_UUID: &str = "The stored adapter's network_broker_channel_uuid is not a UUID, so the update cannot send it back; pass --channel <channelId> to replace it";

/// `adapter delete|rm <uuid> [--force]` (D137).
pub async fn delete(invocation: &mut Invocation, uuid: &str, force: bool) -> Result<(), CliError> {
    let contexts = Contexts::plain();
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    if !force && !rw::confirm(invocation, &format!("Delete adapter {uuid}?"))? {
        return Ok(());
    }
    rw::authenticate(&prepared, &contexts).await?;
    let adapters = prepared.client().adapters();
    rw::send(
        invocation,
        Change::Words("adapter", "deleted"),
        None,
        &contexts,
        async || adapters.delete(uuid, None).await,
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("Adapter {uuid} deleted."));
    Ok(())
}
