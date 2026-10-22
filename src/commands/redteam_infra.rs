//! `redteam eula status|content`, `instances get` and `network-broker channels
//! list|get`, `network-broker stats` (DESIGN §15.7, §15.8, §15.15).

use super::Invocation;
use super::redteam::{page_of, page_value, read, value, walk_all, walk_deadline};
use crate::error::CliError;
use crate::json::OValue;
use crate::output::Format;
use crate::redteam::ListParams;
use crate::redteam::views;
use scm::airs::red_team::ChannelListOptions;

/// `redteam eula status`: `GET <mgmt>/v1/eula/status`.
pub async fn eula_status(invocation: &mut Invocation, format: Format) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let answer = read(invocation, connected.client.eula().get_status(None)).await?;
    let doc = views::eula_status(&value(&answer)?);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::eula_status_layout(out, &doc);
    })
}

/// `redteam eula content`: `GET <mgmt>/v1/eula/content` (the document, not cut).
pub async fn eula_content(invocation: &mut Invocation, format: Format) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let answer = read(invocation, connected.client.eula().get_content(None)).await?;
    let raw = value(&answer)?;
    let mut doc = OValue::Object(vec![(
        "content".to_owned(),
        raw.get("content").cloned().unwrap_or(OValue::Null),
    )]);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::eula_content_layout(out, &doc);
    })
}

/// `redteam instances get <tenantId>`: one encoded path segment (D141).
pub async fn instance_get(
    invocation: &mut Invocation,
    tenant_id: &str,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let answer = read(
        invocation,
        connected.client.instances().get_instance(tenant_id, None),
    )
    .await?;
    let doc = views::instance(&value(&answer)?);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::instance_layout(out, &doc);
    })
}

/// `redteam network-broker channels list|ls`: one page (each query value only when
/// given, `status` repeated in argument order), or the CLI walk with page size
/// `--limit`, else 100.
pub async fn channel_list(
    invocation: &mut Invocation,
    params: &ListParams,
    search: Option<String>,
    statuses: Vec<String>,
    format: Option<Format>,
) -> Result<(), CliError> {
    let mut options = ChannelListOptions::default();
    options.search = search;
    options.status = statuses;
    let (rows, format) = if params.all {
        let deadline = walk_deadline()?;
        let connected = invocation.connect_red_team(Some(&deadline)).await?;
        let format = connected.format(format);
        let broker = connected.client.network_broker();
        let rows = walk_all(
            invocation,
            params.limit.unwrap_or(100),
            params.max,
            true,
            |skip, limit| {
                let mut page = options.clone();
                page.skip = Some(skip);
                page.limit = Some(limit);
                let broker = broker.clone();
                let deadline = deadline.clone();
                async move {
                    let answer = broker.list_channels(&page, Some(&deadline)).await?;
                    Ok(page_of(&page_value(&answer)?))
                }
            },
        )
        .await?;
        (rows, format)
    } else {
        let connected = invocation.connect_red_team(None).await?;
        let format = connected.format(format);
        options.skip = params.offset;
        options.limit = params.limit;
        let answer = read(
            invocation,
            connected
                .client
                .network_broker()
                .list_channels(&options, None),
        )
        .await?;
        (page_of(&value(&answer)?).rows, format)
    };
    let mut channels: Vec<OValue> = rows.iter().map(views::channel).collect();
    for channel in &mut channels {
        views::withhold(channel, &invocation.secrets);
    }
    let out = &mut invocation.output;
    match format {
        Format::Pretty => views::list(
            out,
            format,
            &channels,
            &[],
            "channels",
            views::channel_list_layout,
        ),
        _ => {
            let rows: Vec<OValue> = channels.iter().map(views::channel_row).collect();
            views::list(
                out,
                format,
                &rows,
                &views::CHANNEL_COLUMNS,
                "channels",
                |_, _| {},
            )
        }
    }
}

/// `redteam network-broker channels get <channelId>`.
pub async fn channel_get(
    invocation: &mut Invocation,
    id: &str,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let answer = read(
        invocation,
        connected.client.network_broker().get_channel(id, None),
    )
    .await?;
    let mut doc = views::channel(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::channel_layout(out, &doc);
    })
}

/// `redteam network-broker stats`: `GET <broker>/v1/channels/stats`.
pub async fn stats(invocation: &mut Invocation, format: Option<Format>) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let answer = read(
        invocation,
        connected.client.network_broker().get_channel_stats(None),
    )
    .await?;
    let doc = views::channel_stats(&value(&answer)?);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::channel_stats_layout(out, &doc);
    })
}

// ---------------------------------------------------------------------------
// Writes: `eula accept`, `registry-credentials`, `instances`, `devices` and channels
// (§15.7, §15.8, §15.15)
// ---------------------------------------------------------------------------

use super::redteam_write::{self as rw, Contexts};
use crate::output::terminal_safe;
use crate::render::style::Style;
use crate::writes::Change;
use scm::airs::red_team::models as rtm;

/// `redteam eula accept [--force]` (D138): the content (an empty one is refused, D159),
/// then (without `--force`) the content on stderr and the prompt, then one
/// `POST /v1/eula/accept` that is never re-sent.
pub async fn eula_accept(
    invocation: &mut Invocation,
    force: bool,
    format: Format,
) -> Result<(), CliError> {
    let contexts = Contexts::sent("the EULA may already have been accepted (outcome unknown)");
    let prepared = rw::connect(invocation, &contexts).await?;
    let eula = prepared.client().eula();
    let content = read(invocation, eula.get_content(None))
        .await
        .map_err(|error| contexts.before(error))?;
    let content = value(&content)?
        .get("content")
        .and_then(OValue::as_str)
        .unwrap_or_default()
        .to_owned();
    // Nothing to show or to accept (D159): refused before the prompt and the POST.
    if content.trim().is_empty() {
        return Err(CliError::operational(
            "The service returned no EULA content, so there is nothing to accept",
        ));
    }
    if !force {
        // The user must see what they accept: never quiet-suppressed.
        let safe: Vec<String> = content
            .split('\n')
            .map(|line| terminal_safe(line).into_owned())
            .collect();
        let shown = if invocation.secrets.taints(&content) {
            crate::error::WITHHELD.to_owned()
        } else {
            safe.join("\n")
        };
        let label = invocation.output.paint_err(Style::Bold, "EULA Content:");
        invocation
            .output
            .write_stderr(&format!("\n  {label}\n\n  {shown}\n\n"));
        if !rw::confirm(invocation, "Accept the Red Team EULA shown above?")? {
            return Ok(());
        }
    }
    let body = rw::body(
        serde_json::json!({
            "eula_content": content,
            "accepted_at": crate::debug::iso_timestamp(std::time::SystemTime::now()),
        }),
        "POST",
        "/v1/eula/accept",
        rtm::EulaAcceptRequest::parse,
    )?;
    let accepted = rw::send(
        invocation,
        Change::Words("EULA", "accepted"),
        Some("Check it with 'airs redteam eula status' before accepting again."),
        &contexts,
        async || eula.accept(&body, None).await,
    )
    .await?;
    invocation.committed = true;
    let doc = views::eula_status(&value(&accepted)?);
    invocation.output.success("EULA accepted.");
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::eula_status_layout(out, &doc);
    })
}

/// `redteam registry-credentials` (D133, D139): one `POST /v1/registry-credentials`
/// (it may mint a credential); the token joins the secret set at once.
pub async fn registry_credentials(
    invocation: &mut Invocation,
    format: Option<Format>,
) -> Result<(), CliError> {
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let format = crate::output::resolve_tenant_default(format, prepared.default_output.as_deref());
    let instances = prepared.client().instances();
    let credentials = rw::send(
        invocation,
        Change::Words("registry credentials", "issued"),
        None,
        &contexts,
        async || instances.get_registry_credentials(None).await,
    )
    .await?;
    invocation.secrets.add(&credentials.token);
    invocation.committed = true;
    let doc = OValue::Object(vec![
        (
            "token".to_owned(),
            OValue::String(credentials.token.clone()),
        ),
        (
            "expiry".to_owned(),
            OValue::String(credentials.expiry.clone()),
        ),
    ]);
    views::render_registry(&mut invocation.output, format, &doc)
}

/// Which instance write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstanceWrite {
    Create,
    Update(String),
}

/// `redteam instances create|update`: one write of the planned body; stdout the
/// response.
pub async fn instance_write(
    invocation: &mut Invocation,
    kind: &InstanceWrite,
    body: &serde_json::Value,
    format: Format,
) -> Result<(), CliError> {
    let (method, path, done) = match kind {
        InstanceWrite::Create => ("POST", "/v1/instances".to_owned(), "created"),
        InstanceWrite::Update(id) => ("PUT", format!("/v1/instances/{id}"), "updated"),
    };
    let request = rw::body(body.clone(), method, &path, rtm::InstanceRequest::parse)?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let instances = prepared.client().instances();
    let answer = rw::send(
        invocation,
        Change::Words("instance", done),
        None,
        &contexts,
        async || match kind {
            InstanceWrite::Create => instances.create_instance(&request, None).await,
            InstanceWrite::Update(id) => instances.update_instance(id, &request, None).await,
        },
    )
    .await?;
    invocation.committed = true;
    render_instance(invocation, format, &value(&answer)?)
}

fn render_instance(
    invocation: &mut Invocation,
    format: Format,
    raw: &OValue,
) -> Result<(), CliError> {
    let mut doc = views::instance_response(raw);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::instance_response_layout(out, &doc);
    })
}

/// `redteam instances delete|rm <tenantId> [--force]` (D137).
pub async fn instance_delete(
    invocation: &mut Invocation,
    tenant_id: &str,
    force: bool,
    format: Format,
) -> Result<(), CliError> {
    let contexts = Contexts::plain();
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    if !force
        && !rw::confirm(
            invocation,
            &format!("Delete Red Team instance {tenant_id}?"),
        )?
    {
        return Ok(());
    }
    rw::authenticate(&prepared, &contexts).await?;
    let instances = prepared.client().instances();
    let answer = rw::send(
        invocation,
        Change::Words("instance", "deleted"),
        None,
        &contexts,
        async || instances.delete_instance(tenant_id, None).await,
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("Instance {tenant_id} deleted."));
    render_instance(invocation, format, &value(&answer)?)
}

/// Which device write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceWrite {
    Create,
    Update,
}

/// The device response in `format`: pretty its `JSON.stringify(x, null, 2)` (TS bytes),
/// json the document, table `Key │ Value`.
fn render_devices(
    invocation: &mut Invocation,
    format: Format,
    raw: &OValue,
) -> Result<(), CliError> {
    let mut doc = raw.clone();
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::json_layout(out, &doc);
    })
}

/// `redteam devices create|update <tenantId> --config <path>`.
pub async fn devices(
    invocation: &mut Invocation,
    kind: DeviceWrite,
    tenant_id: &str,
    config: &std::ffi::OsStr,
    format: Format,
) -> Result<(), CliError> {
    let value_in = rw::config_object(config)?;
    let (method, done, line) = match kind {
        DeviceWrite::Create => ("POST", "created", "Devices created:"),
        DeviceWrite::Update => ("PATCH", "updated", "Devices updated:"),
    };
    let request = rw::body(
        value_in.clone(),
        method,
        &format!("/v1/instances/{tenant_id}/devices"),
        rtm::DeviceRequest::parse,
    )?;
    rw::register_secrets(
        invocation,
        &value_in,
        crate::redteam::secrets::Shape::Generic,
    );
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let instances = prepared.client().instances();
    let answer = rw::send(
        invocation,
        Change::Words("devices", done),
        None,
        &contexts,
        async || match kind {
            DeviceWrite::Create => instances.create_devices(tenant_id, &request, None).await,
            DeviceWrite::Update => instances.update_devices(tenant_id, &request, None).await,
        },
    )
    .await?;
    invocation.committed = true;
    invocation.output.success(line);
    render_devices(invocation, format, &value(&answer)?)
}

/// `redteam devices delete|rm <tenantId> --serial-numbers <list> [--force]` (D137; the
/// list names a serial number, checked during planning, D158).
pub async fn devices_delete(
    invocation: &mut Invocation,
    tenant_id: &str,
    serials: &str,
    force: bool,
    format: Format,
) -> Result<(), CliError> {
    let contexts = Contexts::plain();
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    if !force
        && !rw::confirm(
            invocation,
            &format!("Delete devices {serials} from instance {tenant_id}?"),
        )?
    {
        return Ok(());
    }
    rw::authenticate(&prepared, &contexts).await?;
    let instances = prepared.client().instances();
    let answer = rw::send(
        invocation,
        Change::Words("devices", "deleted"),
        None,
        &contexts,
        async || instances.delete_devices(tenant_id, serials, None).await,
    )
    .await?;
    invocation.committed = true;
    invocation.output.success("Devices deleted:");
    render_devices(invocation, format, &value(&answer)?)
}

/// `redteam network-broker channels create|update`: one write; stdout the channel.
pub async fn channel_write(
    invocation: &mut Invocation,
    id: Option<&str>,
    body: &serde_json::Value,
    format: Format,
) -> Result<(), CliError> {
    let contexts = Contexts::plain();
    let (done, line) = if id.is_some() {
        ("updated", "Channel updated")
    } else {
        ("created", "Channel created")
    };
    let create = match id {
        None => Some(rw::body(
            body.clone(),
            "POST",
            "/v1/channels",
            rtm::CreateChannelRequest::parse,
        )?),
        Some(_) => None,
    };
    let update = match id {
        Some(id) => Some(rw::body(
            body.clone(),
            "PATCH",
            &format!("/v1/channels/{id}"),
            rtm::UpdateChannelRequest::parse,
        )?),
        None => None,
    };
    let prepared = rw::connect(invocation, &contexts).await?;
    let broker = prepared.client().network_broker();
    let answer = rw::send(
        invocation,
        Change::Words("channel", done),
        None,
        &contexts,
        async || match (&create, &update, id) {
            (Some(create), _, _) => broker.create_channel(create, None).await,
            (_, Some(update), Some(id)) => broker.update_channel(id, update, None).await,
            _ => Err(scm::Error::new(scm::ErrorKind::Validation)),
        },
    )
    .await?;
    invocation.committed = true;
    let mut doc = views::channel(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    let uuid = rw::field(&doc, "uuid");
    invocation.output.success(&format!("{line}: {uuid}"));
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::channel_layout(out, &doc);
    })
}
