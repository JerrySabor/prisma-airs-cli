//! `model-security groups create|update|delete` (DESIGN §17.8): the config body (D188),
//! the update body (D187), one attempt per write (D179), the delete prompt (D185) and
//! the delete verification (D186).

use super::Invocation;
use super::modelsec_write as w;
use super::redteam::value;
use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::modelsec::change::{self, GROUP_CREATED, GROUP_DELETED, GROUP_UPDATED};
use crate::modelsec::views::{self, Kind};
use crate::modelsec::{self, body};
use crate::output::{Format, terminal_safe};
use scm::airs::model_security::models as msm;
use scm::validation::Mode;
use std::ffi::OsStr;

/// What an interruption during the verification read reports (§17.3).
pub const DELETE_UNVERIFIED: &str = "the delete request was accepted; its result was not verified";

/// `groups create --config <path>`: the file and its body before the tenant, the token,
/// one `POST`, then the group.
pub async fn create(
    invocation: &mut Invocation,
    config: &OsStr,
    format: Option<Format>,
) -> Result<(), CliError> {
    let (object, path) = w::config(config)?;
    let request = body::group_create(&path, object)?;
    let (ms, format) = w::connect(invocation, format).await?;
    let groups = ms.security_groups();
    let answer = w::send(
        invocation,
        GROUP_CREATED,
        Some(change::GROUP_CREATE_HINT),
        async || groups.create(&request, Some(&w::options()?)).await,
    )
    .await?;
    invocation.committed = true;
    w::ack(
        invocation,
        Kind::Group,
        format,
        "Group created",
        &value(&answer)?,
    )
}

/// `groups update <uuid> [--name] [--description]`: the body built during planning, the
/// token, one `PUT`, then the group.
pub async fn update(
    invocation: &mut Invocation,
    uuid: &str,
    body: serde_json::Value,
    format: Option<Format>,
) -> Result<(), CliError> {
    let request = msm::ModelSecurityGroupUpdateRequest::parse(body, Mode::Request)
        .map_err(|_| crate::writes::invalid_body("PUT", &format!("/v1/security-groups/{uuid}")))?;
    let (ms, format) = w::connect(invocation, format).await?;
    let groups = ms.security_groups();
    let answer = w::send(invocation, GROUP_UPDATED, None, async || {
        groups.update(uuid, &request, Some(&w::options()?)).await
    })
    .await?;
    invocation.committed = true;
    w::ack(
        invocation,
        Kind::Group,
        format,
        "Group updated",
        &value(&answer)?,
    )
}

/// ` (<name>)` of the prompt (withheld when it carries a secret); empty without a name.
fn name_part(invocation: &Invocation, record: &OValue) -> String {
    let mut shown = record.clone();
    views::withhold(&mut shown, &invocation.secrets);
    match shown.get("name").and_then(OValue::as_str) {
        Some(name) if !name.is_empty() => format!(" ({name})"),
        _ => String::new(),
    }
}

/// `groups delete|rm <uuid> [--force]` (D185, D186): with a prompt the token, the read
/// that names the group, the prompt; then one `DELETE` and one verification read.
pub async fn delete(invocation: &mut Invocation, uuid: &str, force: bool) -> Result<(), CliError> {
    let (ms, _) = w::connect(invocation, None).await?;
    let groups = ms.security_groups();
    if !force {
        let options = modelsec::options(crate::clients::SINGLE_REQUEST_BUDGET)?;
        let record = w::read_first(invocation, groups.get(uuid, Some(&options))).await?;
        let message = format!(
            "Delete security group {uuid}{}?",
            name_part(invocation, &record)
        );
        if !w::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let hint = change::group_delete_hint(uuid);
    w::send(invocation, GROUP_DELETED, Some(&hint), async || {
        groups.delete(uuid, Some(&w::options()?)).await
    })
    .await?;
    invocation.interrupt = Some(InterruptContext::Context(DELETE_UNVERIFIED.to_owned()));
    verify(invocation, &ms, uuid).await
}

/// The verification read after an accepted `DELETE` (§17.8): a 404 or `is_tombstone:
/// true` confirms it; a group still present is TS's warning and the re-check hint; any
/// other failure says the result could not be verified. Exit 0 in every case.
async fn verify(
    invocation: &mut Invocation,
    ms: &scm::airs::model_security::ModelSecurityClient,
    uuid: &str,
) -> Result<(), CliError> {
    let recheck = format!("re-check with 'airs model-security groups get {uuid}'");
    let options = modelsec::options(crate::clients::SINGLE_REQUEST_BUDGET)?;
    let read = ms.security_groups().get(uuid, Some(&options)).await;
    let record = match read {
        Ok(record) => value(&record).ok(),
        Err(error) if error.kind() == scm::ErrorKind::Cancelled => {
            return Err(CliError::Interrupted(InterruptContext::Context(
                DELETE_UNVERIFIED.to_owned(),
            )));
        }
        Err(error) if error.kind() == scm::ErrorKind::Http && error.status() == Some(404) => {
            invocation.output.success(&format!("Group {uuid} deleted."));
            return Ok(());
        }
        Err(_) => None,
    };
    match record {
        Some(record) if matches!(record.get("is_tombstone"), Some(OValue::Bool(true))) => {
            invocation.output.success(&format!(
                "Group {uuid} deleted (the service is removing it)."
            ));
        }
        Some(record) => {
            let state = record
                .get("state")
                .and_then(OValue::as_str)
                .unwrap_or_default();
            invocation.output.warning(&format!(
                "⚠ Delete request accepted, but group {uuid} still reports state '{}'.",
                terminal_safe(state)
            ));
            invocation.output.status(&format!(
                "Deletion is asynchronous (soft-delete) — {recheck}."
            ));
        }
        None => {
            invocation.output.warning(&format!(
                "⚠ Delete request accepted, but its result could not be verified; {recheck}."
            ));
        }
    }
    Ok(())
}
