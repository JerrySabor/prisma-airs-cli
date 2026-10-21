//! `model-security labels add|set|delete` (DESIGN §17.11): one write each (D179); `set`
//! reads the scan's labels first and names the ones it drops, in the prompt or a `--force`
//! warning; `delete` asks first (D185). stdout stays empty (D189).

use super::Invocation;
use super::modelsec_write as w;
use crate::error::CliError;
use crate::modelsec::body;
use crate::modelsec::change::{LABELS_ADDED, LABELS_DELETED, LABELS_REPLACED};
use crate::modelsec::views;
use scm::airs::model_security::models as msm;
use scm::validation::Mode;

/// The body checked during planning, as the SDK model.
fn request(scan: &str, body: serde_json::Value) -> Result<msm::LabelsCreateRequest, CliError> {
    msm::LabelsCreateRequest::parse(body, Mode::Request)
        .map_err(|_| crate::writes::invalid_body("POST", &format!("/v1/scans/{scan}/labels")))
}

/// `labels add <scanUuid> --labels <json>`: the token, one `POST`, `  ✓ Labels added.`
pub async fn add(
    invocation: &mut Invocation,
    scan: &str,
    body: serde_json::Value,
) -> Result<(), CliError> {
    let request = request(scan, body)?;
    let (ms, _) = w::connect(invocation, None).await?;
    let scans = ms.scans();
    w::send(invocation, LABELS_ADDED, None, async || {
        scans.add_labels(scan, &request, Some(&w::options()?)).await
    })
    .await?;
    invocation.committed = true;
    invocation.output.success("Labels added.");
    Ok(())
}

/// `labels set <scanUuid> --labels <json> [--force]`: the token, the scan read (its
/// current labels), the prompt or the `--force` warning naming the dropped keys, one
/// `PUT`, `  ✓ Labels set.`
pub async fn set(
    invocation: &mut Invocation,
    scan: &str,
    body: serde_json::Value,
    force: bool,
) -> Result<(), CliError> {
    let request = request(scan, body)?;
    let (ms, _) = w::connect(invocation, None).await?;
    let scans = ms.scans();
    let options = crate::modelsec::options(crate::clients::SINGLE_REQUEST_BUDGET)?;
    let record = w::read_first(invocation, scans.get(scan, Some(&options))).await?;
    views::register_uris(std::slice::from_ref(&record), &invocation.secrets);
    let mut dropped = body::dropped_keys(&body::label_keys(&record), &request);
    views::withhold_strings(&mut dropped, &invocation.secrets);
    let listed = body::key_list(&dropped);
    if force {
        if !dropped.is_empty() {
            invocation.output.warning(&format!(
                "⚠ The replacement drops {} label(s) the scan has now: {listed}",
                dropped.len()
            ));
        }
    } else {
        let mut message = format!("Replace all labels on scan {scan}?");
        if !dropped.is_empty() {
            message.push_str(&format!(
                " It drops {} label(s) the scan has now: {listed}.",
                dropped.len()
            ));
        }
        if !w::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    w::send(invocation, LABELS_REPLACED, None, async || {
        scans.set_labels(scan, &request, Some(&w::options()?)).await
    })
    .await?;
    invocation.committed = true;
    invocation.output.success("Labels set.");
    Ok(())
}

/// `labels delete|rm <scanUuid> --keys <keys> [--force]`: the token, the prompt, one
/// `DELETE …/labels?keys=…` (keys in the given order), `  ✓ Labels deleted.`
pub async fn delete(
    invocation: &mut Invocation,
    scan: &str,
    keys: &[String],
    force: bool,
) -> Result<(), CliError> {
    let (ms, _) = w::connect(invocation, None).await?;
    if !force {
        let mut shown = keys.to_vec();
        views::withhold_strings(&mut shown, &invocation.secrets);
        let message = format!(
            "Delete label(s) {} from scan {scan}?",
            body::key_list(&shown)
        );
        if !w::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let scans = ms.scans();
    w::send(invocation, LABELS_DELETED, None, async || {
        scans.delete_labels(scan, keys, Some(&w::options()?)).await
    })
    .await?;
    invocation.committed = true;
    invocation.output.success("Labels deleted.");
    Ok(())
}
