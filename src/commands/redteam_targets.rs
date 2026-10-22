//! `redteam targets list|get|profile|metadata|templates|error-logs` (DESIGN §15.12).
//! Every printed target document is redacted first (§15.4, D140).

use super::Invocation;
use super::redteam::{page_of, page_value, read, target_options, value, walk_all, walk_deadline};
use crate::error::CliError;
use crate::json::OValue;
use crate::output::Format;
use crate::redteam::ListParams;
use crate::redteam::secrets::{self, Shape};
use crate::redteam::views;
use crate::walk;
use scm::airs::red_team::{RedTeamListOptions, TargetListOptions};

/// `targets list|ls`: the complete walk (`skip`, `limit=100`), then the client-side slice
/// (D147; TS stops silently at 10,000 rows).
pub async fn list(
    invocation: &mut Invocation,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let deadline = walk_deadline()?;
    let connected = invocation.connect_red_team(Some(&deadline)).await?;
    let format = connected.format(format);
    let targets = connected.client.targets();
    // The rows as the server sent them (D153); the token keeps the plain deadline.
    let pages = deadline.clone().without_response_defaults();
    let rows = walk_all(invocation, 100, 0, false, |skip, limit| {
        let mut page = TargetListOptions::default();
        page.skip = Some(skip);
        page.limit = Some(limit);
        let targets = targets.clone();
        let pages = pages.clone();
        async move {
            let answer = targets.list(&page, Some(&pages)).await?;
            Ok(page_of(&page_value(&answer)?))
        }
    })
    .await?;
    let (rows, cut) = walk::slice(rows, params);
    if cut {
        invocation
            .output
            .status(&crate::pagination::showing_first(rows.len(), params.max));
    }
    let mut rows: Vec<OValue> = rows.iter().map(views::target_row).collect();
    for row in &mut rows {
        views::withhold(row, &invocation.secrets);
    }
    views::list(
        &mut invocation.output,
        format,
        &rows,
        &views::TARGET_COLUMNS,
        "targets",
        views::target_list_layout,
    )
}

/// `targets get <uuid>`: the TS normalised detail, redacted (D140), of only the fields
/// the server sent (no schema defaults such as `ws_response_timeout: 110`, D153).
pub async fn get(
    invocation: &mut Invocation,
    uuid: &str,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let targets = connected.client.targets();
    let answer = read(invocation, async {
        targets.get(uuid, Some(&target_options()?)).await
    })
    .await?;
    let mut doc = views::target_detail(&value(&answer)?);
    secrets::redact(&mut doc, Shape::Target, &invocation.secrets);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::target_layout(out, &doc);
    })
}

/// `targets profile <uuid>`: the dim label (decoration) and the profile JSON (data).
pub async fn profile(
    invocation: &mut Invocation,
    uuid: &str,
    format: Format,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let answer = read(
        invocation,
        connected.client.targets().get_profile(uuid, None),
    )
    .await?;
    let mut doc = value(&answer)?;
    secrets::redact(&mut doc, Shape::Generic, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        crate::render::pretty::dim(out, "Target Profile:");
        views::json_layout(out, &doc);
    })
}

/// `targets metadata`: the document as JSON in pretty and json (no banner, TS).
pub async fn metadata(invocation: &mut Invocation, format: Format) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let answer = read(
        invocation,
        connected.client.targets().get_target_metadata(None),
    )
    .await?;
    let mut doc = value(&answer)?;
    secrets::redact(&mut doc, Shape::Generic, &invocation.secrets);
    match format {
        Format::Table => {
            views::detail_table(&mut invocation.output, &doc);
            Ok(())
        }
        Format::Pretty | Format::Json => invocation.output.json(&doc),
    }
}

/// `targets templates`: per provider its name and the dim indented JSON.
pub async fn templates(invocation: &mut Invocation, format: Format) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let answer = read(
        invocation,
        connected.client.targets().get_target_templates(None),
    )
    .await?;
    let mut doc = value(&answer)?;
    secrets::redact(&mut doc, Shape::Generic, &invocation.secrets);
    match format {
        Format::Json => invocation.output.json(&doc),
        Format::Table => {
            views::templates_table(&mut invocation.output, &doc);
            Ok(())
        }
        Format::Pretty => {
            views::banner(&mut invocation.output);
            views::templates_layout(&mut invocation.output, &doc);
            Ok(())
        }
    }
}

/// `targets error-logs <targetId>`: one page (`limit` only when given); `targetObject`
/// and `extraInfo` redacted.
pub async fn error_logs(
    invocation: &mut Invocation,
    target: &str,
    limit: Option<u32>,
    format: Format,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    // Only `limit`: the API refuses `skip` and `search` here (D300, §15.23).
    let mut options = RedTeamListOptions::default();
    options.limit = limit;
    let answer = read(
        invocation,
        connected
            .client
            .get_target_profile_error_logs(target, &options, None),
    )
    .await?;
    let mut logs: Vec<OValue> = page_of(&value(&answer)?)
        .rows
        .iter()
        .map(views::error_log)
        .collect();
    for log in &mut logs {
        secrets::redact(log, Shape::ErrorLog, &invocation.secrets);
    }
    for log in &mut logs {
        views::withhold(log, &invocation.secrets);
    }
    views::render_error_logs(&mut invocation.output, format, &logs)
}

// ---------------------------------------------------------------------------
// Writes (§15.13)
// ---------------------------------------------------------------------------

use super::redteam_write::{self as rw, Contexts};
use crate::writes::Change;
use scm::airs::red_team::{TargetOperationOptions, models as rtm};

/// Which target write a `--config` file feeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetWrite {
    Create,
    Update(String),
    Probe,
    UpdateProfile(String),
}

/// `targets create|update|probe|update-profile --config <path>`: the file is the body
/// (validated with its SDK schema, its credentials registered as secrets), one write,
/// stdout the redacted answer.
pub async fn write(
    invocation: &mut Invocation,
    kind: &TargetWrite,
    config: &std::ffi::OsStr,
    validate: bool,
    format: Format,
) -> Result<(), CliError> {
    let raw = rw::config_object(config)?;
    let operation = {
        let mut operation = TargetOperationOptions::default();
        operation.validate = validate.then_some(true);
        operation
    };
    enum Body {
        Create(rtm::TargetCreateRequest),
        Update(rtm::TargetUpdateRequest),
        Probe(rtm::TargetProbeRequest),
        Profile(rtm::TargetContextUpdate),
    }
    let body = match kind {
        TargetWrite::Create => Body::Create(rw::body(
            raw.clone(),
            "POST",
            "/v1/target",
            rtm::TargetCreateRequest::parse,
        )?),
        TargetWrite::Update(uuid) => Body::Update(rw::body(
            raw.clone(),
            "PUT",
            &format!("/v1/target/{uuid}"),
            rtm::TargetUpdateRequest::parse,
        )?),
        TargetWrite::Probe => Body::Probe(rw::body(
            raw.clone(),
            "POST",
            "/v1/target/probe",
            rtm::TargetProbeRequest::parse,
        )?),
        TargetWrite::UpdateProfile(uuid) => Body::Profile(rw::body(
            raw.clone(),
            "PUT",
            &format!("/v1/target/{uuid}/profile"),
            rtm::TargetContextUpdate::parse,
        )?),
    };
    rw::register_secrets(invocation, &raw, Shape::Target);
    let change = match kind {
        TargetWrite::Create => Change::Words("target", "created"),
        TargetWrite::Update(_) => Change::Words("target", "updated"),
        TargetWrite::Probe => Change::Words("target", "contacted"),
        TargetWrite::UpdateProfile(_) => Change::Words("target profile", "updated"),
    };
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let targets = prepared.client().targets();
    // Each attempt with its own per-request budget, as `None` gives; the answer is the
    // target as the server sent it (D153).
    let answer = rw::send(invocation, change, None, &contexts, async || {
        let options = target_options()?;
        match &body {
            Body::Create(body) => targets.create(body, Some(&operation), Some(&options)).await,
            Body::Update(body) => {
                let TargetWrite::Update(uuid) = kind else {
                    return Err(scm::Error::new(scm::ErrorKind::Validation));
                };
                targets
                    .update(uuid, body, Some(&operation), Some(&options))
                    .await
            }
            Body::Probe(body) => targets.probe(body, Some(&options)).await,
            Body::Profile(body) => {
                let TargetWrite::UpdateProfile(uuid) = kind else {
                    return Err(scm::Error::new(scm::ErrorKind::Validation));
                };
                targets.update_profile(uuid, body, Some(&options)).await
            }
        }
    })
    .await?;
    invocation.committed = true;
    let answer = value(&answer)?;
    match kind {
        TargetWrite::Create | TargetWrite::Update(_) => {
            let mut doc = views::target_detail(&answer);
            secrets::redact(&mut doc, Shape::Target, &invocation.secrets);
            views::withhold(&mut doc, &invocation.secrets);
            let verb = if *kind == TargetWrite::Create {
                "created"
            } else {
                "updated"
            };
            invocation
                .output
                .success(&format!("Target {verb}: {}", rw::field(&doc, "uuid")));
            views::detail(&mut invocation.output, format, &doc, |out| {
                views::target_layout(out, &doc);
            })
        }
        TargetWrite::Probe | TargetWrite::UpdateProfile(_) => {
            let mut doc = answer;
            if *kind == TargetWrite::Probe
                && let OValue::Object(entries) = &mut doc
            {
                for (key, value) in entries.iter_mut() {
                    if key == "target_metadata" {
                        *value =
                            views::sanitize_metadata(Some(value.clone())).unwrap_or(OValue::Null);
                    }
                }
            }
            secrets::redact(&mut doc, Shape::Target, &invocation.secrets);
            views::withhold(&mut doc, &invocation.secrets);
            let probe = *kind == TargetWrite::Probe;
            if !probe {
                invocation.output.success("Profile updated:");
            }
            views::detail(&mut invocation.output, format, &doc, |out| {
                if probe {
                    crate::render::pretty::dim(out, "Probe result:");
                }
                views::json_layout(out, &doc);
            })
        }
    }
}

/// `targets delete|rm <uuid> [--force]` (D137): the prompt (no existence read, TS),
/// then one `DELETE`.
pub async fn delete(invocation: &mut Invocation, uuid: &str, force: bool) -> Result<(), CliError> {
    let contexts = Contexts::plain();
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    if !force && !rw::confirm(invocation, &format!("Delete red team target {uuid}?"))? {
        return Ok(());
    }
    rw::authenticate(&prepared, &contexts).await?;
    let targets = prepared.client().targets();
    rw::send(
        invocation,
        Change::Words("target", "deleted"),
        None,
        &contexts,
        async || targets.delete(uuid, None).await,
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("Target {uuid} deleted."));
    Ok(())
}

/// `targets validate-auth --auth-type <type> --config <path> [--target-id <uuid>]`:
/// the file is the `auth_config` object; the token preview is withheld (D140).
pub async fn validate_auth(
    invocation: &mut Invocation,
    auth_type: &str,
    config: &std::ffi::OsStr,
    target_id: Option<&str>,
    format: Format,
) -> Result<(), CliError> {
    let auth_config = rw::config_object(config)?;
    let mut raw = serde_json::json!({ "auth_type": auth_type, "auth_config": auth_config });
    if let Some(target_id) = target_id {
        raw["target_id"] = serde_json::Value::String(target_id.to_owned());
    }
    let body = rw::body(
        raw.clone(),
        "POST",
        "/v1/target/validate-auth",
        rtm::TargetAuthValidationRequest::parse,
    )?;
    rw::register_secrets(invocation, &raw, Shape::Target);
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let targets = prepared.client().targets();
    let answer = rw::send(
        invocation,
        Change::Words("target's auth endpoint", "contacted"),
        None,
        &contexts,
        async || targets.validate_auth(&body, None).await,
    )
    .await?;
    let mut doc = views::auth_validation(&value(&answer)?);
    if let OValue::Object(entries) = &mut doc {
        for (key, value) in entries.iter_mut() {
            if key == "tokenPreview"
                && let OValue::String(text) = value
                && !text.is_empty()
            {
                invocation.secrets.add(text);
                *text = secrets::REDACTED.to_owned();
            }
        }
    }
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::auth_validation_layout(out, &doc);
    })
}

/// `targets init <provider> [--output-file <file>]` (D150): the existence refusal before
/// the tenant, the templates read, then the scaffold published exclusively at 0600.
pub async fn init(
    invocation: &mut Invocation,
    key: &str,
    path: &std::path::Path,
    given: &str,
    format: Format,
) -> Result<(), CliError> {
    let shown_path = crate::files::shown(path.as_os_str());
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(CliError::usage(format!(
            "File already exists: {shown_path} (use --output-file to specify a different path)"
        )));
    }
    let no_file = |error: CliError| match error {
        CliError::Interrupted(
            crate::error::InterruptContext::NoDataWritten
            | crate::error::InterruptContext::NothingChanged,
        ) => CliError::Interrupted(crate::error::InterruptContext::NoFileWritten),
        other => other,
    };
    let connected = invocation.connect_red_team(None).await.map_err(no_file)?;
    let templates = read(
        invocation,
        connected.client.targets().get_target_templates(None),
    )
    .await
    .map_err(no_file)?;
    let scaffold = crate::redteam::args::scaffold(key, &value(&templates)?);
    let mut text = crate::json::to_pretty(&scaffold).map_err(|_| {
        CliError::operational("AISEC_SDK_ERROR:Output could not be serialized as JSON")
    })?;
    text.push('\n');
    if invocation.output.pending_signal().is_some() {
        return Err(CliError::Interrupted(
            crate::error::InterruptContext::NoFileWritten,
        ));
    }
    let published = crate::files::publish_new(path, text.as_bytes(), "--output-file")?;
    invocation.committed = true;
    if published == crate::files::Published::DirectoryNotSynced {
        invocation
            .output
            .warning(&crate::store::atomic::dir_sync_warning(path));
    }
    invocation.output.success("Target config scaffolded");
    let doc = OValue::Object(vec![
        ("file".to_owned(), OValue::String(shown_path.clone())),
        ("provider".to_owned(), OValue::String(key.to_owned())),
    ]);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::key_values(
            out,
            &views::pairs([
                (
                    "File",
                    crate::output::terminal_safe(&shown_path).into_owned(),
                ),
                ("Provider", key.to_owned()),
            ]),
        );
    })?;
    invocation
        .output
        .status("Next steps: edit the file to fill in name and credentials, then run:");
    invocation.output.status(&format!(
        "  airs redteam targets create --config {} --validate",
        crate::output::terminal_safe(given)
    ));
    Ok(())
}
