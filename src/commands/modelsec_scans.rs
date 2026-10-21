//! `model-security scans create` (DESIGN §17.10): the whole config is the body (TS), its
//! model URI's withheld parts join the secret set first (D191); one billed `POST`, never
//! re-sent and never followed by a read after an unknown outcome (D179).

use super::Invocation;
use super::modelsec_write as w;
use super::redteam::value;
use crate::error::CliError;
use crate::modelsec::body;
use crate::modelsec::change::{SCAN_CREATE_HINT, SCAN_CREATED};
use crate::modelsec::views::{self, Kind};
use crate::output::Format;
use std::ffi::OsStr;

/// `scans create --config <path>`: the file and its body before the tenant, the token,
/// one `POST`, then the scan (validated without response defaults, so a pending scan
/// shows no `Rules` line, D180).
pub async fn create(
    invocation: &mut Invocation,
    config: &OsStr,
    format: Option<Format>,
) -> Result<(), CliError> {
    let (object, _) = w::config(config)?;
    if let Some(uri) = object.get("model_uri").and_then(serde_json::Value::as_str) {
        for part in views::uri_secrets(uri) {
            invocation.secrets.add(&part);
        }
    }
    let request = body::scan_create(object)?;
    let (ms, format) = w::connect(invocation, format).await?;
    let scans = ms.scans();
    let answer = w::send(
        invocation,
        SCAN_CREATED,
        Some(SCAN_CREATE_HINT),
        async || scans.create(&request, Some(&w::options()?)).await,
    )
    .await?;
    invocation.committed = true;
    w::ack(
        invocation,
        Kind::Scan,
        format,
        "Scan created",
        &value(&answer)?,
    )
}
