//! `runtime dlp profiles create|replace|patch|delete` (DESIGN §16.7): the SDK calls of
//! the profile writes, the `--pattern-id` reads (TD§10.2) and the `profiles delete`
//! refusal (no tenant, no request; the API has no profile DELETE, G11).

use super::Invocation;
use super::dlp_write::{done, send as send_write};
use super::redteam::{read, value};
use crate::dlp::Kind;
use crate::dlp::body::{self, Referenced, Write};
use crate::error::CliError;
use crate::json::OValue;
use crate::output::terminal_safe;
use crate::render::style::Style;
use scm::dlp::DlpClient;
use scm::dlp::models as m;

/// Read and check every `--pattern-id` in order (reads with the SDK retries; any failure
/// stops before the write).
pub async fn resolve(
    invocation: &Invocation,
    dlp: &DlpClient,
    ids: &[String],
) -> Result<Vec<Referenced>, CliError> {
    let patterns = dlp.data_patterns();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let record = read(invocation, patterns.get(id, None))
            .await
            .map_err(super::nothing_changed)?;
        out.push(body::referenced(id, &value(&record)?)?);
    }
    Ok(out)
}

/// One profile write of `body` (already checked with its schema).
pub async fn send(
    invocation: &mut Invocation,
    dlp: &DlpClient,
    write: Write,
    id: Option<&str>,
    request: &serde_json::Value,
) -> Result<OValue, CliError> {
    let kind = Kind::Profile;
    let text = body::schema_text(kind, write.method(), id);
    let change = kind.change(done(write));
    let profiles = dlp.data_profiles();
    let id = id.unwrap_or_default();
    let answer = match write {
        Write::Create => {
            let request =
                body::schema(request, m::AdvancedDataProfileRequest::parse, &text, false)?;
            let hint = kind.create_hint();
            send_write(invocation, change, hint.as_deref(), false, async || {
                profiles.create(&request, None).await
            })
            .await?
        }
        Write::Replace => {
            let request =
                body::schema(request, m::AdvancedDataProfileRequest::parse, &text, false)?;
            send_write(invocation, change, None, false, async || {
                profiles.replace(id, &request, None).await
            })
            .await?
        }
        Write::Patch => {
            let request = body::schema(request, m::DataProfilePatchRequest::parse, &text, false)?;
            send_write(invocation, change, None, false, async || {
                profiles.patch(id, &request, None).await
            })
            .await?
        }
    };
    value(&answer)
}

/// The `profiles delete` refusal (TS text, the program name `airs`, D73).
pub fn refusal(id: &str) -> String {
    format!(
        "This DLP API has no DELETE for data profiles.\n  Status-based retirement is not live-verified: the latest owned-fixture\n  PATCH/PUT returned HTTP 500; an advertised DELETE returned HTTP 501.\n  No API request was sent by this command. Do not assume the profile was removed.\n  Inspect current state with: airs runtime dlp profiles get {} --output json",
        terminal_safe(id)
    )
}

/// `profiles delete|rm <id>`: the refusal on stderr (red, as TS `usageError`), exit 2;
/// no tenant, no client, no request.
pub fn refuse_delete(invocation: &mut Invocation, id: &str) -> Result<(), CliError> {
    let text = invocation
        .output
        .paint_err(Style::Red, &format!("\n  ✗ {}\n", refusal(id)));
    invocation.output.write_stderr(&format!("{text}\n"));
    Err(CliError::Reported(crate::error::EXIT_USAGE))
}
