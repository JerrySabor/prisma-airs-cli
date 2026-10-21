//! `runtime dlp dictionaries create|replace|patch` (DESIGN §16.8): the multipart upload
//! (the metadata and the keyword file read before the tenant, D164, D173), the region
//! hint, the replace answered without a body (D172), and the patch call (the delete is
//! `dlp_write::delete`).

use super::Invocation;
use super::dlp::{Upload, check_metadata};
use super::dlp_write::{self as dw, send as send_write};
use super::redteam::value;
use crate::dlp::body::{self, Input, Texts, Write};
use crate::dlp::{Kind, views};
use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::output::terminal_safe;
use scm::dlp::models as m;
use scm::dlp::{DictionaryUpload, DlpClient};

/// The one `PATCH` of a dictionary patch.
pub async fn patch(
    invocation: &mut Invocation,
    dlp: &DlpClient,
    id: &str,
    request: &serde_json::Value,
) -> Result<OValue, CliError> {
    let kind = Kind::Dictionary;
    let text = body::schema_text(kind, Write::Patch.method(), Some(id));
    let request = body::schema(request, m::DictionaryPatchRequest::parse, &text, false)?;
    let dictionaries = dlp.dictionaries();
    let answer = send_write(
        invocation,
        kind.change("patched"),
        None,
        false,
        async || dictionaries.patch(id, &request, None).await,
    )
    .await?;
    value(&answer)
}

/// `dictionaries create|replace`: the metadata (a `--metadata-file` read and checked
/// now) and the keyword file (7 MiB, sent as read), the 8 MiB body budget, then the
/// tenant and token; a replace reads the record (the guard), names the fields it drops
/// and confirms; one upload; the ack.
pub async fn upload(invocation: &mut Invocation, plan: &Upload) -> Result<(), CliError> {
    let metadata = match &plan.metadata {
        Input::File(path) => {
            let metadata = body::read_object_file(path, Texts::Dictionary)?;
            check_metadata(&metadata)?;
            metadata
        }
        other => body::read_input(other, Texts::Dictionary, &invocation.output)?,
    };
    let bytes = crate::files::read_bytes(&plan.file, crate::files::UPLOAD_LIMIT)?;
    let metadata_len = serde_json::to_vec(&metadata).map_or(0, |text| text.len());
    if bytes.len().saturating_add(metadata_len) > body::UPLOAD_BUDGET {
        return Err(CliError::operational(format!(
            "{} and its metadata exceed the 8 MiB upload limit",
            crate::files::shown(&plan.file)
        )));
    }
    let kind = Kind::Dictionary;
    let invalid = || CliError::usage(body::DICTIONARY_METADATA);
    let request = m::DictionaryRequest::parse(metadata.clone(), scm::validation::Mode::Request)
        .map_err(|_| invalid())?;
    let file = m::BinaryFile::new(bytes).map_err(|_| invalid())?;
    let mut upload = DictionaryUpload::new(request, file);
    if plan.include_keywords {
        upload = upload.include_keywords(true);
    }
    let (dlp, format) = dw::connect(invocation, plan.format).await?;
    let dictionaries = dlp.dictionaries();
    let Some(id) = plan.id.as_deref() else {
        let hint = kind.create_hint();
        let answer = send_write(
            invocation,
            kind.change("created"),
            hint.as_deref(),
            true,
            async || dictionaries.create(&upload, None).await,
        )
        .await?;
        invocation.committed = true;
        return dw::ack(invocation, format, "created", value(&answer)?);
    };
    let record = dw::current(invocation, &dlp, kind, id).await?;
    if !dw::confirm_replace(invocation, kind, id, &record, &metadata, plan.force)? {
        return Ok(());
    }
    let answer = send_write(
        invocation,
        kind.change("replaced"),
        None,
        true,
        async || dictionaries.replace(id, &upload, None).await,
    )
    .await?;
    invocation.committed = true;
    if let Some(answer) = answer {
        return dw::ack(invocation, format, "replaced", value(&answer)?);
    }
    // A 2xx without a body: the new state is read back once (TS); when that read fails
    // the replace still succeeded (exit 0) and says so.
    match dw::fetch(invocation, &dlp, kind, id).await {
        Ok(record) => dw::ack(invocation, format, "replaced", record),
        Err(CliError::Interrupted(_)) => Err(CliError::Interrupted(InterruptContext::ChangeSaved)),
        Err(_) => {
            invocation.output.warning(&format!(
                "⚠ replaced {}; the service did not return the new state",
                terminal_safe(id)
            ));
            let doc = OValue::Object(vec![
                ("action".to_owned(), OValue::String("replaced".to_owned())),
                ("id".to_owned(), OValue::String(id.to_owned())),
            ]);
            views::render_ack_doc(&mut invocation.output, format, &doc)
        }
    }
}
