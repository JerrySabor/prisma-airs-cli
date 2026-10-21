//! `redteam prompt-sets list|get|download`, `prompts list|get` and `properties
//! list|values` (DESIGN §15.9–§15.11).

use super::Invocation;
use super::redteam::{Destination, page_of, page_value, read, value, walk_all, walk_deadline};
use crate::error::CliError;
use crate::json::OValue;
use crate::output::Format;
use crate::redteam::ListParams;
use crate::redteam::views;
use crate::walk;
use scm::airs::red_team::{PromptListOptions, PromptSetListOptions};

/// Print the `--max` status line of a client-sliced `--all` list that `--max` cut.
fn sliced_status(invocation: &mut Invocation, rows: usize, cut: bool, max: u64) {
    if cut {
        invocation
            .output
            .status(&crate::pagination::showing_first(rows, max));
    }
}

/// `prompt-sets list|ls`: the complete walk (`skip`, `limit=50`), then the client-side
/// slice (D147; TS reads one page).
pub async fn prompt_set_list(
    invocation: &mut Invocation,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let deadline = walk_deadline()?;
    let connected = invocation.connect_red_team(Some(&deadline)).await?;
    let format = connected.format(format);
    let custom = connected.client.custom_attacks();
    let rows = walk_all(invocation, 50, 0, false, |skip, limit| {
        let mut page = PromptSetListOptions::default();
        page.skip = Some(skip);
        page.limit = Some(limit);
        let custom = custom.clone();
        let deadline = deadline.clone();
        async move {
            let answer = custom.list_prompt_sets(&page, Some(&deadline)).await?;
            Ok(page_of(&page_value(&answer)?))
        }
    })
    .await?;
    let (rows, cut) = walk::slice(rows, params);
    sliced_status(invocation, rows.len(), cut, params.max);
    let mut rows: Vec<OValue> = rows.iter().map(views::prompt_set_row).collect();
    for row in &mut rows {
        views::withhold(row, &invocation.secrets);
    }
    views::list(
        &mut invocation.output,
        format,
        &rows,
        &views::PROMPT_SET_COLUMNS,
        "prompt sets",
        views::prompt_set_list_layout,
    )
}

/// `prompt-sets get <uuid>`: the set, then its version info (a failure is swallowed, TS).
pub async fn prompt_set_get(
    invocation: &mut Invocation,
    uuid: &str,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let custom = connected.client.custom_attacks();
    let set = read(invocation, custom.get_prompt_set(uuid, None)).await?;
    let info = custom
        .get_prompt_set_version_info(uuid, None, None)
        .await
        .ok()
        .map(|info| value(&info))
        .transpose()?;
    let mut doc = views::prompt_set_detail(
        views::prompt_set(&value(&set)?),
        info.as_ref().map(views::version_info),
    );
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::prompt_set_layout(out, &doc, true);
    })
}

/// `prompt-sets download <uuid> [--output-file <path>]` (D142): the destination is
/// checked before the tenant; the template is published exclusively at 0600, or written
/// to stdout with `-`.
pub async fn download(
    invocation: &mut Invocation,
    uuid: &str,
    destination: &Destination,
) -> Result<(), CliError> {
    if let Destination::File(path) = destination {
        crate::files::refuse_existing(path, "--output-file")?;
    }
    // A signal before the file is published writes no file (§15.9).
    let no_file = |error: CliError| match error {
        CliError::Interrupted(crate::error::InterruptContext::NoDataWritten) => {
            CliError::Interrupted(crate::error::InterruptContext::NoFileWritten)
        }
        other => other,
    };
    let connected = invocation.connect_red_team(None).await.map_err(no_file)?;
    let csv = read(
        invocation,
        connected
            .client
            .custom_attacks()
            .download_template(uuid, None),
    )
    .await
    .map_err(no_file)?;
    match destination {
        Destination::Stdout => {
            invocation.output.data(&csv);
            // A signal from here on interrupts the output, not a file write.
            invocation.interrupt = Some(crate::error::InterruptContext::OutputIncomplete);
        }
        Destination::File(path) => {
            if invocation.output.pending_signal().is_some() {
                return Err(CliError::Interrupted(
                    crate::error::InterruptContext::NoFileWritten,
                ));
            }
            let published = publish_template(&mut invocation.interrupt, path, &csv)?;
            if published == crate::files::Published::DirectoryNotSynced {
                invocation
                    .output
                    .warning(&crate::store::atomic::dir_sync_warning(path));
            }
            invocation.output.success(&format!(
                "Template saved to {}",
                crate::files::shown(path.as_os_str())
            ));
        }
    }
    Ok(())
}

/// Publish the template at `path`; from the moment it is linked an interruption reports
/// `the template was saved in <path>` (not the plan's `no file was written`).
fn publish_template(
    interrupt: &mut Option<crate::error::InterruptContext>,
    path: &std::path::Path,
    csv: &str,
) -> Result<crate::files::Published, CliError> {
    let published = crate::files::publish_new(path, csv.as_bytes(), "--output-file")?;
    *interrupt = Some(crate::error::InterruptContext::Context(format!(
        "the template was saved in {}",
        crate::output::terminal_safe(&crate::files::shown(path.as_os_str()))
    )));
    Ok(published)
}

/// `prompts list|ls <setUuid>` (D147): one page (`limit` always, `skip` when `--offset`
/// is given), or the `--all` walk with page size `--limit` (default 50).
pub async fn prompt_list(
    invocation: &mut Invocation,
    set: &str,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let limit = params.limit.unwrap_or(50);
    let (rows, format) = if params.all {
        let deadline = walk_deadline()?;
        let connected = invocation.connect_red_team(Some(&deadline)).await?;
        let format = connected.format(format);
        let custom = connected.client.custom_attacks();
        let rows = walk_all(invocation, limit, params.max, true, |skip, limit| {
            let mut page = PromptListOptions::default();
            page.skip = Some(skip);
            page.limit = Some(limit);
            let custom = custom.clone();
            let deadline = deadline.clone();
            let set = set.to_owned();
            async move {
                let answer = custom.list_prompts(&set, &page, Some(&deadline)).await?;
                Ok(page_of(&page_value(&answer)?))
            }
        })
        .await?;
        (rows, format)
    } else {
        let connected = invocation.connect_red_team(None).await?;
        let format = connected.format(format);
        let mut page = PromptListOptions::default();
        page.skip = params.offset;
        page.limit = Some(limit);
        let answer = read(
            invocation,
            connected
                .client
                .custom_attacks()
                .list_prompts(set, &page, None),
        )
        .await?;
        (page_of(&value(&answer)?).rows, format)
    };
    let mut prompts: Vec<OValue> = rows.iter().map(views::prompt).collect();
    for prompt in &mut prompts {
        views::withhold(prompt, &invocation.secrets);
    }
    views::render_prompt_list(&mut invocation.output, format, &prompts)
}

/// `prompts get <setUuid> <promptUuid>`.
pub async fn prompt_get(
    invocation: &mut Invocation,
    set: &str,
    prompt: &str,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let answer = read(
        invocation,
        connected
            .client
            .custom_attacks()
            .get_prompt(set, prompt, None),
    )
    .await?;
    let mut doc = views::prompt(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::prompt_layout(out, &doc);
    })
}

/// `properties list|ls`: one unpaged answer (`data ?? []`), then the client-side slice.
pub async fn property_list(
    invocation: &mut Invocation,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let answer = read(
        invocation,
        connected.client.custom_attacks().get_property_names(None),
    )
    .await?;
    let names = page_of(&value(&answer)?).rows;
    let (names, cut) = walk::slice(names, params);
    sliced_status(invocation, names.len(), cut, params.max);
    let names: Vec<OValue> = names
        .into_iter()
        .map(|name| match name {
            OValue::String(text) if invocation.secrets.taints(&text) => {
                OValue::String(crate::error::WITHHELD.to_owned())
            }
            other => other,
        })
        .collect();
    views::render_property_names(&mut invocation.output, format, &names)
}

/// `properties values <name>`: one encoded path segment; `{name: raw.name ?? name,
/// values: raw.values ?? []}`.
pub async fn property_values(
    invocation: &mut Invocation,
    name: &str,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let answer = read(
        invocation,
        connected
            .client
            .custom_attacks()
            .get_property_values(name, None),
    )
    .await?;
    let raw = value(&answer)?;
    let shown_name = match raw.get("name") {
        None | Some(OValue::Null) => OValue::String(name.to_owned()),
        Some(value) => value.clone(),
    };
    let values = match raw.get("values") {
        None | Some(OValue::Null) => OValue::Array(Vec::new()),
        Some(value) => value.clone(),
    };
    let mut doc = OValue::Object(vec![
        ("name".to_owned(), shown_name),
        ("values".to_owned(), values),
    ]);
    views::withhold(&mut doc, &invocation.secrets);
    views::render_property_values(&mut invocation.output, format, &doc)
}

// ---------------------------------------------------------------------------
// Writes: prompt sets, prompts and properties (§15.9–§15.11)
// ---------------------------------------------------------------------------

use super::redteam_write::{self as rw, Contexts};
use crate::writes::Change;
use scm::airs::red_team::models as rtm;

/// `prompt-sets create --name [--description]`: stdout pretty `  Name  <name>`, json
/// and table the normalised set.
pub async fn prompt_set_create(
    invocation: &mut Invocation,
    body: &serde_json::Value,
    format: Format,
) -> Result<(), CliError> {
    let request = rw::body(
        body.clone(),
        "POST",
        "/v1/custom-attack/custom-prompt-set",
        rtm::CustomPromptSetCreateRequest::parse,
    )?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    let answer = rw::send(
        invocation,
        Change::Words("prompt set", "created"),
        None,
        &contexts,
        async || custom.create_prompt_set(&request, None).await,
    )
    .await?;
    invocation.committed = true;
    let mut doc = views::prompt_set(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    invocation
        .output
        .success(&format!("Prompt set created: {}", rw::field(&doc, "uuid")));
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::name_line(out, &doc);
    })
}

/// `prompt-sets update <uuid>`: the non-empty flags; stdout the set detail.
pub async fn prompt_set_update(
    invocation: &mut Invocation,
    uuid: &str,
    body: &serde_json::Value,
    format: Format,
) -> Result<(), CliError> {
    let request = rw::body(
        body.clone(),
        "PUT",
        &format!("/v1/custom-attack/custom-prompt-set/{uuid}"),
        rtm::CustomPromptSetUpdateRequest::parse,
    )?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    let answer = rw::send(
        invocation,
        Change::Words("prompt set", "updated"),
        None,
        &contexts,
        async || custom.update_prompt_set(uuid, &request, None).await,
    )
    .await?;
    invocation.committed = true;
    let mut doc = views::prompt_set(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::prompt_set_layout(out, &doc, false);
    })
}

/// `prompt-sets archive <uuid> [--unarchive]`: stdout empty.
pub async fn prompt_set_archive(
    invocation: &mut Invocation,
    uuid: &str,
    archive: bool,
) -> Result<(), CliError> {
    let done = if archive { "archived" } else { "unarchived" };
    let request = rw::body(
        serde_json::json!({ "archive": archive }),
        "PUT",
        &format!("/v1/custom-attack/custom-prompt-set/{uuid}/archive"),
        rtm::CustomPromptSetArchiveRequest::parse,
    )?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    rw::send(
        invocation,
        Change::Words("prompt set", done),
        None,
        &contexts,
        async || custom.archive_prompt_set(uuid, &request, None).await,
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("Prompt set {uuid} {done}."));
    Ok(())
}

/// `prompt-sets upload <uuid> <file>` (D143): the bytes as read (7 MiB) in one multipart
/// part `file` named `prompts.csv`, `text/csv`; one attempt; stderr the server message.
pub async fn upload(
    invocation: &mut Invocation,
    uuid: &str,
    file: &std::ffi::OsStr,
) -> Result<(), CliError> {
    let bytes = crate::files::read_bytes(file, crate::files::UPLOAD_LIMIT)?;
    let part = scm::validation::BinaryPart::new(bytes)
        .and_then(|part| part.with_content_type("text/csv"))
        .map_err(|_| {
            CliError::operational(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:The upload could not be prepared",
            )
        })?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    let hint = format!(
        "Check the prompt set with 'airs redteam prompts list {uuid}' before uploading again."
    );
    let answer = rw::send(
        invocation,
        Change::Words("prompts", "uploaded"),
        Some(&hint),
        &contexts,
        async || custom.upload_prompts_csv(uuid, &part, None).await,
    )
    .await?;
    invocation.committed = true;
    let message = withheld(invocation, &answer.message);
    invocation.output.success(&message);
    Ok(())
}

/// Server text for an outcome line: `[withheld]` when it carries a known secret.
fn withheld(invocation: &Invocation, text: &str) -> String {
    if invocation.secrets.taints(text) {
        crate::error::WITHHELD.to_owned()
    } else {
        text.to_owned()
    }
}

/// `prompts add <setUuid> --prompt [--goal]`: stdout json and table the normalised
/// prompt, pretty nothing (TS prints only the outcome line).
pub async fn prompt_add(
    invocation: &mut Invocation,
    body: &serde_json::Value,
    format: Format,
) -> Result<(), CliError> {
    let request = rw::body(
        body.clone(),
        "POST",
        "/v1/custom-attack/custom-prompt-set/custom-prompt",
        rtm::CustomPromptCreateRequest::parse,
    )?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    let answer = rw::send(
        invocation,
        Change::Words("prompt", "added"),
        None,
        &contexts,
        async || custom.create_prompt(&request, None).await,
    )
    .await?;
    invocation.committed = true;
    let mut doc = views::prompt(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    invocation
        .output
        .success(&format!("Prompt added: {}", rw::field(&doc, "uuid")));
    match format {
        Format::Pretty => Ok(()),
        _ => views::detail(&mut invocation.output, format, &doc, |_| {}),
    }
}

/// `prompts update <setUuid> <promptUuid>`: stdout the prompt detail.
pub async fn prompt_update(
    invocation: &mut Invocation,
    set: &str,
    prompt: &str,
    body: &serde_json::Value,
    format: Format,
) -> Result<(), CliError> {
    let request = rw::body(
        body.clone(),
        "PUT",
        &format!("/v1/custom-attack/custom-prompt-set/{set}/custom-prompt/{prompt}"),
        rtm::CustomPromptUpdateRequest::parse,
    )?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    let answer = rw::send(
        invocation,
        Change::Words("prompt", "updated"),
        None,
        &contexts,
        async || custom.update_prompt(set, prompt, &request, None).await,
    )
    .await?;
    invocation.committed = true;
    let mut doc = views::prompt(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    views::detail(&mut invocation.output, format, &doc, |out| {
        views::prompt_layout(out, &doc);
    })
}

/// `prompts delete|rm <setUuid> <promptUuid> [--force]` (D137).
pub async fn prompt_delete(
    invocation: &mut Invocation,
    set: &str,
    prompt: &str,
    force: bool,
) -> Result<(), CliError> {
    let contexts = Contexts::plain();
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    if !force
        && !rw::confirm(
            invocation,
            &format!("Delete prompt {prompt} from prompt set {set}?"),
        )?
    {
        return Ok(());
    }
    rw::authenticate(&prepared, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    rw::send(
        invocation,
        Change::Words("prompt", "deleted"),
        None,
        &contexts,
        async || custom.delete_prompt(set, prompt, None).await,
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("Prompt {prompt} deleted."));
    Ok(())
}

/// `properties create --name`: stderr the server message, or `Property name created`
/// when the 2xx body is empty or carries none (D149).
pub async fn property_create(
    invocation: &mut Invocation,
    body: &serde_json::Value,
) -> Result<(), CliError> {
    let request = rw::body(
        body.clone(),
        "POST",
        "/v1/custom-attack/property-names",
        rtm::PropertyNameCreateRequest::parse,
    )?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    let answer = rw::send(
        invocation,
        Change::Words("property", "created"),
        None,
        &contexts,
        async || custom.create_property_name(&request, None).await,
    )
    .await?;
    invocation.committed = true;
    let message = match answer.as_ref().map(value).transpose()? {
        Some(doc) => doc
            .get("message")
            .and_then(OValue::as_str)
            .map(str::to_owned),
        None => None,
    };
    let message = message.map_or_else(
        || "Property name created".to_owned(),
        |message| withheld(invocation, &message),
    );
    invocation.output.success(&message);
    Ok(())
}

/// `properties add-value --name --value`: stderr the server message.
pub async fn property_add_value(
    invocation: &mut Invocation,
    body: &serde_json::Value,
) -> Result<(), CliError> {
    let request = rw::body(
        body.clone(),
        "POST",
        "/v1/custom-attack/property-values",
        rtm::PropertyValueCreateRequest::parse,
    )?;
    let contexts = Contexts::plain();
    let prepared = rw::connect(invocation, &contexts).await?;
    let custom = prepared.client().custom_attacks();
    let answer = rw::send(
        invocation,
        Change::Words("property value", "added"),
        None,
        &contexts,
        async || custom.create_property_value(&request, None).await,
    )
    .await?;
    invocation.committed = true;
    let message = withheld(invocation, &answer.message);
    invocation.output.success(&message);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::InterruptContext;

    #[test]
    fn a_published_template_changes_the_interrupt_context() {
        let dir = std::env::temp_dir().join(format!(
            "airs-rs-template-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("template.csv");
        let mut interrupt = None;
        publish_template(&mut interrupt, &path, "prompt,goal\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "prompt,goal\n");
        assert_eq!(
            interrupt,
            Some(InterruptContext::Context(format!(
                "the template was saved in {}",
                path.display()
            )))
        );
        // A failed publish keeps the plan's context.
        let mut interrupt = None;
        assert!(publish_template(&mut interrupt, &path, "x").is_err());
        assert_eq!(interrupt, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
