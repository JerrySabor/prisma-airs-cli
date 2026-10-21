//! The shared machinery of the model-security writes (DESIGN §17.3): the `--config`
//! reads before the tenant (D188), the tenant and token of a write, the reads a write
//! makes first (an interruption there changed nothing), the D81 prompt (D185), the
//! one-attempt send with its outcome and hint lines (D179), and the record a write
//! answered, printed in the chosen format (D189) under its outcome line on stderr (D190).

use super::Invocation;
use super::redteam::value;
use super::write_common::{self as wc, Contexts};
use crate::clients::SINGLE_REQUEST_BUDGET;
use crate::error::CliError;
use crate::json::OValue;
use crate::modelsec::views::{self, Kind};
use crate::output::Format;
use crate::writes::Change;
use scm::airs::model_security::ModelSecurityClient;
use std::ffi::OsStr;

/// A `--config` file (§17.3 "Input files"): the §13.2 rules (a regular file of at most
/// 1 MiB, UTF-8, one JSON object), read after the debug log and before the tenant; and
/// the path as its messages show it.
pub fn config(
    path: &OsStr,
) -> Result<(serde_json::Map<String, serde_json::Value>, String), CliError> {
    let object = crate::files::read_config(path)?;
    Ok((object, crate::files::shown(path)))
}

/// The tenant, the model-security client and the token of a write, and the format it
/// prints in (the explicit `--output`, else pretty: the tenant's `defaultOutput` does not
/// apply, choice 19). An interruption reports `nothing was changed`.
pub async fn connect(
    invocation: &mut Invocation,
    format: Option<Format>,
) -> Result<(ModelSecurityClient, Format), CliError> {
    let connected = invocation
        .connect_model_security(None)
        .await
        .map_err(super::nothing_changed)?;
    let format = connected.format(format, false);
    Ok((connected.client, format))
}

/// The options of one model-security request (G20: no response defaults), with its own
/// budget: each attempt of a write builds its own.
pub fn options() -> scm::Result<scm::RequestOptions> {
    scm::RequestOptions::with_timeout(SINGLE_REQUEST_BUDGET)
        .map(scm::RequestOptions::without_response_defaults)
}

/// A read a write makes before it sends anything (the record named in a prompt, the
/// current labels): the SDK read retries; its failure is its §6 error; an interruption
/// changed nothing.
pub async fn read_first<T: serde::Serialize>(
    invocation: &Invocation,
    call: impl Future<Output = scm::Result<T>>,
) -> Result<OValue, CliError> {
    let answer = super::redteam::read(invocation, call)
        .await
        .map_err(super::nothing_changed)?;
    value(&answer)
}

/// The D81 prompt (`? <message> (y/N) ` on stderr, terminal-safe); `false` after
/// `  ℹ Aborted` (exit 0, nothing sent).
pub fn confirm(invocation: &mut Invocation, message: &str) -> Result<bool, CliError> {
    wc::confirm(invocation, message)
}

/// One model-security write (D179): one attempt with the single 401 replay; an unknown
/// or unreadable outcome adds its outcome line and `hint`; an interruption before the
/// write reports `nothing was changed`, after it `the change may already have been
/// applied (outcome unknown)`.
pub async fn send<T>(
    invocation: &Invocation,
    change: Change,
    hint: Option<&str>,
    call: impl AsyncFnMut() -> scm::Result<T>,
) -> Result<T, CliError> {
    wc::send(invocation, change, hint, &Contexts::plain(), call).await
}

/// The record a write answered (`groups create|update`, `rule-instances update`,
/// `scans create`): the outcome line `  ✓ <done>: <uuid>` on stderr, then the record on
/// stdout in `format` (pretty: the banner and the §17.4/§17.5 detail; json: the
/// projection; table: `Key │ Value`).
pub fn ack(
    invocation: &mut Invocation,
    kind: Kind,
    format: Format,
    done: &str,
    record: &OValue,
) -> Result<(), CliError> {
    if kind == Kind::Scan {
        views::register_uris(std::slice::from_ref(record), &invocation.secrets);
    }
    let mut doc = views::project(kind, record);
    views::withhold(&mut doc, &invocation.secrets);
    let uuid = doc
        .get("uuid")
        .and_then(OValue::as_str)
        .unwrap_or_default()
        .to_owned();
    invocation.output.success(&format!("{done}: {uuid}"));
    views::render_get(&mut invocation.output, kind, format, &doc)
}
