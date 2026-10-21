//! `runtime dlp patterns create|replace|patch` (DESIGN §16.6): the SDK calls of the
//! JSON-body pattern writes (the flow is `dlp_write::body_write`; the delete is
//! `dlp_write::delete`).

use super::Invocation;
use super::dlp_write::{done, send as send_write};
use super::redteam::value;
use crate::dlp::Kind;
use crate::dlp::body::{self, Write};
use crate::error::CliError;
use crate::json::OValue;
use scm::dlp::DlpClient;
use scm::dlp::models as m;

/// One pattern write of `body` (already checked with its schema).
pub async fn send(
    invocation: &mut Invocation,
    dlp: &DlpClient,
    write: Write,
    id: Option<&str>,
    request: &serde_json::Value,
) -> Result<OValue, CliError> {
    let kind = Kind::Pattern;
    let text = body::schema_text(kind, write.method(), id);
    let change = kind.change(done(write));
    let patterns = dlp.data_patterns();
    let id = id.unwrap_or_default();
    let answer = match write {
        Write::Create => {
            let request = body::schema(request, m::DataPatternRequest::parse, &text, false)?;
            let hint = kind.create_hint();
            send_write(invocation, change, hint.as_deref(), false, async || {
                patterns.create(&request, None).await
            })
            .await?
        }
        Write::Replace => {
            let request = body::schema(request, m::DataPatternRequest::parse, &text, false)?;
            send_write(invocation, change, None, false, async || {
                patterns.replace(id, &request, None).await
            })
            .await?
        }
        Write::Patch => {
            let request = body::schema(request, m::DataPatternPatchRequest::parse, &text, false)?;
            send_write(invocation, change, None, false, async || {
                patterns.patch(id, &request, None).await
            })
            .await?
        }
    };
    value(&answer)
}
