//! The shared machinery of the DLP writes (DESIGN §16.3): the body read before the
//! tenant, the tenant and token, the predefined guard read (D166), the omitted-fields
//! prompt or warning of a replace (D168) and the D81 confirmation (D167), the one-attempt
//! send with its outcome and hint lines (D160), the acks (D172) and the deletes.

use super::Invocation;
use super::dlp::{BodyWrite, check_body};
use super::redteam::{read, value};
use super::write_common::{self as wc, Contexts};
use crate::dlp::body::{self, Input, Write};
use crate::dlp::{self, Kind, views};
use crate::error::CliError;
use crate::json::OValue;
use crate::output::{Format, terminal_safe};
use crate::writes::{self, Change};
use scm::dlp::DlpClient;

/// The tenant, the DLP client and the token of a write, and the format it prints in.
/// An interruption reports `nothing was changed`.
pub async fn connect(
    invocation: &mut Invocation,
    format: Option<Format>,
) -> Result<(DlpClient, Format), CliError> {
    let connected = invocation
        .connect_dlp(None)
        .await
        .map_err(super::nothing_changed)?;
    let format = connected.format(format);
    Ok((connected.client, format))
}

/// The record of `kind` with `id` (a replay-safe read; dictionaries without keywords).
pub async fn fetch(
    invocation: &Invocation,
    dlp: &DlpClient,
    kind: Kind,
    id: &str,
) -> Result<OValue, CliError> {
    match kind {
        Kind::FilteringProfile => {
            value(&read(invocation, dlp.data_filtering_profiles().get(id, None)).await?)
        }
        Kind::Pattern => value(&read(invocation, dlp.data_patterns().get(id, None)).await?),
        Kind::Profile => value(&read(invocation, dlp.data_profiles().get(id, None)).await?),
        Kind::Dictionary => value(&read(invocation, dlp.dictionaries().get(id, None, None)).await?),
    }
}

/// The record of `kind` with `id` as the service holds it now, checked by the
/// predefined guard (D166). An interruption reports `nothing was changed`.
pub async fn current(
    invocation: &Invocation,
    dlp: &DlpClient,
    kind: Kind,
    id: &str,
) -> Result<OValue, CliError> {
    let record = fetch(invocation, dlp, kind, id)
        .await
        .map_err(super::nothing_changed)?;
    dlp::guard(kind, id, &record)?;
    Ok(record)
}

/// ` (<name>)` of a prompt, from the record's name (withheld when it carries a secret);
/// empty when the record has none.
fn name_part(invocation: &Invocation, record: &OValue) -> String {
    let mut shown = record.clone();
    views::withhold(&mut shown, &invocation.secrets);
    match shown.get("name").and_then(OValue::as_str) {
        Some(name) if !name.is_empty() => format!(" ({name})"),
        _ => String::new(),
    }
}

/// The confirmation of a replace (D167, D168): the prompt names the fields the
/// replacement drops; with `--force` they are a warning before the write. `false`: the
/// user declined (`  ℹ Aborted`, exit 0, nothing sent).
pub fn confirm_replace(
    invocation: &mut Invocation,
    kind: Kind,
    id: &str,
    current: &OValue,
    body: &serde_json::Value,
    force: bool,
) -> Result<bool, CliError> {
    let omitted = body::omitted_fields(kind, current, body);
    let resource = kind.resource();
    let fields = omitted.join(", ");
    if force {
        if !omitted.is_empty() {
            invocation.output.warning(&format!(
                "⚠ The replacement omits {} field(s) the {resource} has now: {fields}",
                omitted.len()
            ));
        }
        return Ok(true);
    }
    let mut message = format!("Replace {resource} {id}{}?", name_part(invocation, current));
    if !omitted.is_empty() {
        message.push_str(&format!(
            " The replacement omits {} field(s) it has now: {fields}.",
            omitted.len()
        ));
    }
    wc::confirm(invocation, &message)
}

/// The `Dictionary upload rejected …` hint (TS `uploadFailure`): a 400 whose problem has
/// no `detail` and no `errors`.
pub const REGION_HINT: &str = "Dictionary upload rejected. Verify the SCM region display name (for example, --region \"United States\"); region codes such as GLOBAL or us-west-2 are not equivalent.";

fn region_rejected(error: &scm::Error) -> bool {
    error.kind() == scm::ErrorKind::Http
        && error.status() == Some(400)
        && error.problem().is_none_or(|problem| {
            problem.detail().is_none() && problem.errors().is_none_or(<[_]>::is_empty)
        })
}

/// One DLP write (D160): one attempt with the single 401 replay; an unknown or unreadable
/// outcome gets its outcome line and, for a create, the `Check '… list'` hint; an
/// interruption reports `nothing was changed` before the write and `the change may
/// already have been applied (outcome unknown)` once it was sent. `upload`: print the
/// region hint before the error of a rejected dictionary upload.
pub async fn send<T>(
    invocation: &mut Invocation,
    change: Change,
    hint: Option<&str>,
    upload: bool,
    call: impl AsyncFnMut() -> scm::Result<T>,
) -> Result<T, CliError> {
    let contexts = Contexts::plain();
    let error = match writes::attempt(call).await {
        Ok(answer) => return Ok(answer),
        Err(error) => error,
    };
    if upload && region_rejected(&error) {
        invocation.output.write_stderr(&format!("{REGION_HINT}\n"));
    }
    Err(writes::in_contexts(
        writes::describe(&error, writes::Hinted(change, hint), &invocation.secrets),
        &contexts.not_sent,
        &contexts.sent,
    ))
}

/// The ack of a write that answered `record` (withheld first).
pub fn ack(
    invocation: &mut Invocation,
    format: Format,
    action: &str,
    mut record: OValue,
) -> Result<(), CliError> {
    views::withhold(&mut record, &invocation.secrets);
    views::render_ack(&mut invocation.output, format, action, &record)
}

/// The words of a write.
pub fn done(write: Write) -> &'static str {
    match write {
        Write::Create => "created",
        Write::Replace => "replaced",
        Write::Patch => "patched",
    }
}

/// A JSON-body create, replace or patch (§16.5–§16.8): the body (read now when it is a
/// file or stdin, then checked), the tenant and token, the guard read, the completions
/// that need server data (D169, the profile pattern reads; checked again, exit 1), the
/// confirmation of a replace, one write and the ack.
pub async fn body_write(invocation: &mut Invocation, plan: &BodyWrite) -> Result<(), CliError> {
    let mut request = body::read_input(&plan.input, plan.texts, &invocation.output)?;
    if !matches!(plan.input, Input::Ready(_)) {
        check_body(plan, &request)?;
    }
    let (dlp, format) = connect(invocation, plan.format).await?;
    let id = plan.id.as_deref();
    let record = match id {
        Some(id) => Some(current(invocation, &dlp, plan.kind, id).await?),
        None => None,
    };
    if (plan.fill_type || plan.fill_technique)
        && let Some(record) = &record
    {
        body::complete_pattern(&mut request, record, plan.fill_type, plan.fill_technique);
        body::check(plan.kind, plan.write, id, &request, false)?;
    }
    if let Some(rules) = &plan.rules {
        let patterns = super::dlp_profiles::resolve(invocation, &dlp, &rules.pattern_ids).await?;
        request["detection_rules"] =
            body::profile_rules(&patterns, &rules.combinator, &rules.confidence)?;
        body::check(plan.kind, plan.write, id, &request, false)?;
    }
    if plan.write == Write::Replace
        && let (Some(id), Some(record)) = (id, &record)
        && !confirm_replace(invocation, plan.kind, id, record, &request, plan.force)?
    {
        return Ok(());
    }
    let answer = match plan.kind {
        Kind::Pattern => {
            super::dlp_patterns::send(invocation, &dlp, plan.write, id, &request).await?
        }
        Kind::Profile => {
            super::dlp_profiles::send(invocation, &dlp, plan.write, id, &request).await?
        }
        Kind::FilteringProfile => {
            super::dlp_filtering::send(invocation, &dlp, id.unwrap_or_default(), &request).await?
        }
        Kind::Dictionary => {
            super::dlp_dictionaries::patch(invocation, &dlp, id.unwrap_or_default(), &request)
                .await?
        }
    };
    invocation.committed = true;
    ack(invocation, format, done(plan.write), answer)
}

/// `patterns|dictionaries delete|rm <id>` (§16.6, §16.8): the tenant and token, the
/// guard read, the confirmation, one `DELETE`, then `  ✓ archived <id>` (patterns) or
/// `  ✓ deleted <id>` (dictionaries) on stderr; stdout stays empty.
pub async fn delete(
    invocation: &mut Invocation,
    kind: Kind,
    id: &str,
    force: bool,
) -> Result<(), CliError> {
    let (dlp, _) = connect(invocation, None).await?;
    let record = current(invocation, &dlp, kind, id).await?;
    if !force {
        let message = format!(
            "Delete {} {id}{}?",
            kind.resource(),
            name_part(invocation, &record)
        );
        if !wc::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let change = kind.change("deleted");
    match kind {
        Kind::Pattern => {
            let patterns = dlp.data_patterns();
            send(invocation, change, None, false, async || {
                patterns.delete(id, None).await
            })
            .await?;
        }
        _ => {
            let dictionaries = dlp.dictionaries();
            send(invocation, change, None, false, async || {
                dictionaries.delete(id, None).await
            })
            .await?;
        }
    }
    invocation.committed = true;
    let verb = if kind == Kind::Pattern {
        "archived"
    } else {
        "deleted"
    };
    invocation
        .output
        .success(&format!("{verb} {}", terminal_safe(id)));
    Ok(())
}
