//! `model-security rule-instances update` (DESIGN §17.9): the config body with its group
//! and field rules (D187, D188), one `PUT` (D179), then the instance.

use super::Invocation;
use super::modelsec_write as w;
use super::redteam::value;
use crate::error::CliError;
use crate::modelsec::body;
use crate::modelsec::change::INSTANCE_UPDATED;
use crate::modelsec::views::Kind;
use crate::output::Format;
use std::ffi::OsStr;

/// `rule-instances update <groupUuid> <instanceUuid> --config <path>`: the file and its
/// body before the tenant, the token, one `PUT`, then the instance. No confirmation
/// (choice 9) and no read-modify-write (choice 14).
pub async fn update_instance(
    invocation: &mut Invocation,
    group: &str,
    instance: &str,
    config: &OsStr,
    format: Option<Format>,
) -> Result<(), CliError> {
    let (object, path) = w::config(config)?;
    let request = body::rule_instance_update(&path, group, instance, object)?;
    let (ms, format) = w::connect(invocation, format).await?;
    let groups = ms.security_groups();
    let answer = w::send(invocation, INSTANCE_UPDATED, None, async || {
        groups
            .update_rule_instance(group, instance, &request, Some(&w::options()?))
            .await
    })
    .await?;
    invocation.committed = true;
    w::ack(
        invocation,
        Kind::RuleInstance,
        format,
        "Rule instance updated",
        &value(&answer)?,
    )
}
