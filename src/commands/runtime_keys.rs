//! `runtime api-keys list|ls` (DESIGN §18.4): one page with the D12 status line, or the
//! SDK's `list_all` walk (D46) plus the repeated-row check (G28, D219), through the
//! offset-list machinery of `runtime::list`; and the key writes `create` and `regenerate`
//! (§18.5: the `--key-file` reservation and the G26 raw POST, the answer handled by
//! `runtime::keys`) and `delete|rm` (§18.6).

use super::Invocation;
use super::runtime_write as w;
use crate::clients::{Planes, SINGLE_REQUEST_BUDGET};
use crate::error::CliError;
use crate::files::Reservation;
use crate::output::{Format, terminal_safe};
use crate::pagination::ListParams;
use crate::runtime::keys::{self, KeyWrite};
use crate::runtime::list::{Listed, OffsetList, more_rows};
use crate::runtime::{self, views};
use crate::writes::Change;
use scm::airs::management::ApiKeyListAllOptions;
use std::ffi::OsStr;
use std::path::Path;

/// `runtime api-keys list|ls` (§18.4): the `api_keys()` page and walk through
/// [`OffsetList`].
pub async fn list(
    invocation: &mut Invocation,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_runtime(Planes::default())?;
    let format = connected.format(format);
    let keys = connected.clients.management.api_keys();
    let listing = OffsetList {
        id_key: "api_key_id",
        page: async |page, options: &scm::RequestOptions| {
            let response = keys.list(page, Some(options)).await?;
            Ok(Listed {
                more: more_rows(response.next_offset.as_ref().into_option()),
                items: response.api_keys.into_option().unwrap_or_default(),
            })
        },
        all: async |limit, collect, options: &scm::RequestOptions| {
            let mut all = ApiKeyListAllOptions::default();
            all.limit = limit;
            all.collect = collect;
            keys.list_all(all, Some(options)).await
        },
        project: views::api_key,
    }
    .read(
        &connected.clients,
        params,
        &invocation.secrets,
        |error, budget| invocation.management_error(error, budget),
    )
    .await?;
    invocation.output.status(&listing.status);
    views::render_api_keys(&mut invocation.output, &listing.docs, format)
}

// ---------------------------------------------------------------------------
// The key writes (§18.5, §18.6)
// ---------------------------------------------------------------------------

/// The largest body the two raw key POSTs send (a `--config` file is at most 1 MiB).
const BODY_LIMIT: usize = 2 * 1_048_576;

/// The 2xx answer of a key write: the key in the key file, then the outcome lines on
/// stderr and the record (never the key) on stdout (§18.5 "Output", D204, D223). A key
/// file that is not durable gets its warning also when the rest of the answer could not
/// be read (step 3, choice 75).
fn finish(
    invocation: &mut Invocation,
    write: KeyWrite,
    answer: serde_json::Value,
    reservation: Reservation,
    path: &Path,
    format: Option<Format>,
) -> Result<(), CliError> {
    // From the 2xx answer on, an interruption never reports "nothing was changed".
    invocation.interrupt = Some(keys::not_saved_context(write));
    let mut interrupt = None;
    let saved = keys::save_answer(
        answer,
        reservation,
        path,
        write,
        &invocation.secrets,
        &mut interrupt,
    );
    if interrupt.is_some() {
        invocation.interrupt = interrupt;
    }
    let saved = saved?;
    let warning = keys::durability_warning(saved.published, path);
    let mut record = match saved.record {
        Ok(record) => record,
        Err(error) => {
            if let Some(warning) = &warning {
                invocation.output.warning(warning);
            }
            return Err(error);
        }
    };
    views::sanitize(&mut record, &invocation.secrets);
    let doc = views::api_key(&record);
    let typed = keys::shown_path(path);
    let id = views::text(&doc, "id").unwrap_or_default().to_owned();
    invocation
        .output
        .success(&format!("API key {}: {}", write.done(), terminal_safe(&id)));
    if let Some(warning) = &warning {
        invocation.output.warning(warning);
    }
    invocation.output.success(&format!(
        "Wrote the API key to {typed} (mode 0600); it is shown only once."
    ));
    views::render_api_key_detail(
        &mut invocation.output,
        &doc,
        &crate::files::shown(path.as_os_str()),
        w::format(format),
    )
}

/// One raw key POST (G26): the SDK's path and body schema, sent with `send_json` so the
/// key is read before the rest of the answer is validated; never re-sent by the SDK.
async fn post_key(
    invocation: &Invocation,
    clients: &crate::clients::ManagementClients,
    write: KeyWrite,
    request: impl Fn() -> scm::Result<scm::RawRequest>,
) -> Result<serde_json::Value, CliError> {
    let client = clients.management.client();
    w::send(invocation, write.change(), write.hint(), async || {
        client
            .send_json::<serde_json::Value>(
                request()?,
                Some(&runtime::request_options(SINGLE_REQUEST_BUDGET)?),
            )
            .await
    })
    .await
}

/// `runtime api-keys create --config <path> --key-file <path>` (§18.5): the file, the
/// key-file path and the body before the tenant; the tenant, the reservation, the token,
/// one `POST /v1/mgmt/apikey`, then the key file and the record.
pub async fn create(
    invocation: &mut Invocation,
    config: &OsStr,
    key_file: &Path,
    format: Option<Format>,
) -> Result<(), CliError> {
    let object = crate::files::read_config(config)?;
    keys::check_key_file(key_file)?;
    let request = w::body(
        serde_json::Value::Object(object),
        "POST",
        "/v1/mgmt/apikey",
        scm::airs::management::models::ApiKeyCreateRequest::parse,
    )?;
    let body = serde_json::to_value(&request)
        .map_err(|_| crate::writes::invalid_body("POST", "/v1/mgmt/apikey"))?;
    let clients = w::prepare(invocation)?;
    let reservation = Reservation::reserve_new(key_file)?;
    w::authenticate(&clients).await?;
    let answer = post_key(invocation, &clients, KeyWrite::Create, || {
        scm::RawRequest::new(reqwest::Method::POST, "/v1/mgmt/apikey").json_value(&body, BODY_LIMIT)
    })
    .await?;
    finish(
        invocation,
        KeyWrite::Create,
        answer,
        reservation,
        key_file,
        format,
    )
}

/// A validated `regenerate` (§18.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegeneratePlan {
    pub id: String,
    /// `{rotation_time_interval, rotation_time_unit, updated_by?}`, validated with
    /// `ApiKeyRegenerateRequest` during planning.
    pub body: serde_json::Value,
    pub key_file: std::path::PathBuf,
    pub force: bool,
    pub format: Option<Format>,
}

/// `runtime api-keys regenerate <apiKeyId>` (§18.5): the key-file path before the tenant;
/// the tenant, the prompt, the reservation, the token, one `POST
/// /v1/mgmt/apikey/regenerate/<id>`, then the key file and the record.
pub async fn regenerate(
    invocation: &mut Invocation,
    plan: &RegeneratePlan,
) -> Result<(), CliError> {
    keys::check_key_file(&plan.key_file)?;
    let clients = w::prepare(invocation)?;
    if !plan.force {
        let message = format!(
            "Regenerate API key {}? The current key stops working; the new key is written to {}.",
            plan.id,
            keys::shown_path(&plan.key_file)
        );
        if !w::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let reservation = Reservation::reserve_new(&plan.key_file)?;
    w::authenticate(&clients).await?;
    let answer = post_key(invocation, &clients, KeyWrite::Regenerate, || {
        scm::RawRequest::new(reqwest::Method::POST, "/v1/mgmt/apikey/regenerate")
            .segment(&plan.id)?
            .json_value(&plan.body, BODY_LIMIT)
    })
    .await?;
    finish(
        invocation,
        KeyWrite::Regenerate,
        answer,
        reservation,
        &plan.key_file,
        plan.format,
    )
}

/// `runtime api-keys delete|rm <apiKeyName> --updated-by <email>` (§18.6): the tenant,
/// the prompt, the token, one `DELETE`, then the fixed acknowledgement (D208).
pub async fn delete(
    invocation: &mut Invocation,
    name: &str,
    updated_by: &str,
    force: bool,
) -> Result<(), CliError> {
    let clients = w::prepare(invocation)?;
    if !force
        && !w::confirm(
            invocation,
            &format!("Delete API key {name}? Integrations that use it stop working."),
        )?
    {
        return Ok(());
    }
    w::authenticate(&clients).await?;
    let keys = clients.management.api_keys();
    w::send(
        invocation,
        Change::Words("API key", "deleted"),
        "Check it with 'airs runtime api-keys list'.",
        async || {
            let options = runtime::request_options(SINGLE_REQUEST_BUDGET)?;
            keys.delete(name, updated_by, Some(&options)).await
        },
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("API key {} deleted.", terminal_safe(name)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing::capture;
    use serde_json::json;

    use crate::test_support::TempDir;

    fn answer(valid: bool) -> serde_json::Value {
        let mut answer = json!({
            "api_key": "SECRET-FINISH-KEY",
            "api_key_id": "id-1",
            "api_key_last8": "LAST8-01",
            "auth_code": "a",
            "expiration": "2027-01-01T00:00:00Z",
            "revoked": false,
        });
        if !valid {
            answer.as_object_mut().unwrap().remove("auth_code");
        }
        answer
    }

    /// `finish` with a key file whose fsync failed (`Published::FileNotSynced`): the sync
    /// warning is printed on stderr after the created line, before the key-file line, and
    /// also before a step-3 schema error (choice 67, choice 75). The key is never printed.
    #[test]
    fn a_key_file_that_is_not_synced_is_warned_about() {
        for valid in [true, false] {
            let dir = TempDir::new("keys-finish");
            let path = dir.join("key.txt");
            let (output, stdout, stderr) = capture(false);
            let mut invocation = Invocation::new(output, None);
            let mut reservation = Reservation::reserve_new(&path).unwrap();
            reservation.fail_sync_for_test();
            let result = finish(
                &mut invocation,
                KeyWrite::Create,
                answer(valid),
                reservation,
                &path,
                Some(Format::Json),
            );
            let warning = format!(
                "  ⚠ {} was saved, but it could not be synced; the key may not survive a system crash\n",
                path.display()
            );
            let _ = invocation.output.commit();
            let err = stderr.text();
            assert!(!err.contains("SECRET-FINISH-KEY"), "{err}");
            assert!(!stdout.text().contains("SECRET-FINISH-KEY"));
            if valid {
                result.unwrap();
                assert_eq!(
                    err,
                    format!(
                        "  ✓ API key created: id-1\n{warning}  ✓ Wrote the API key to {} (mode 0600); it is shown only once.\n",
                        path.display()
                    )
                );
                assert!(stdout.text().contains("\"keyFile\""), "{}", stdout.text());
            } else {
                let error = result.unwrap_err();
                assert!(
                    matches!(&error, CliError::Operational(failure) if failure.message.starts_with("AISEC_RESPONSE_VALIDATION")),
                    "{error:?}"
                );
                assert_eq!(err, warning);
                assert_eq!(stdout.text(), "");
            }
            assert!(
                matches!(&invocation.interrupt, Some(crate::error::InterruptContext::Context(text)) if text.starts_with("the API key was saved in ")),
                "{:?}",
                invocation.interrupt
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "SECRET-FINISH-KEY\n"
            );
        }
    }
}
