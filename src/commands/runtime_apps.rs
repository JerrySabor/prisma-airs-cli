//! `runtime customer-apps list|ls`, `get <appName>` and `consumption [appName]` (DESIGN
//! §18.7, §18.9), and the customer-app writes `update` and `delete` (§18.8).

use super::Invocation;
use super::runtime_write as w;
use crate::clients::{Planes, SINGLE_REQUEST_BUDGET, TOKEN_BUDGET, WALK_BUDGET};
use crate::error::{CliError, InterruptContext, SecretSet};
use crate::json::OValue;
use crate::output::{Format, terminal_safe};
use crate::pagination::{self, ListParams};
use crate::render::style::Style;
use crate::runtime::consumption::{self, Bucket};
use crate::runtime::list::{Listed, OffsetList, more_rows, sanitize_all, unique_rows};
use crate::runtime::{self, views};
use crate::writes::Change;
use scm::airs::management::CustomerAppListAllOptions;
use std::ffi::OsString;

/// `runtime customer-apps list|ls` (§18.7): the `customer_apps()` page and walk through
/// [`OffsetList`].
pub async fn list(
    invocation: &mut Invocation,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_runtime(Planes::default())?;
    let format = connected.format(format);
    let apps = connected.clients.management.customer_apps();
    let listing = OffsetList {
        id_key: "customer_appId",
        page: async |page, options: &scm::RequestOptions| {
            let response = apps.list(page, Some(options)).await?;
            Ok(Listed {
                more: more_rows(response.next_offset.as_ref().into_option()),
                items: response.customer_apps.into_option().unwrap_or_default(),
            })
        },
        all: async |limit, collect, options: &scm::RequestOptions| {
            let mut all = CustomerAppListAllOptions::default();
            all.limit = limit;
            all.collect = collect;
            apps.list_all(all, Some(options)).await
        },
        project: views::customer_app,
    }
    .read(
        &connected.clients,
        params,
        &invocation.secrets,
        |error, budget| invocation.management_error(error, budget),
    )
    .await?;
    invocation.output.status(&listing.status);
    views::render_customer_apps(&mut invocation.output, &listing.docs, format)
}

/// `runtime customer-apps get <appName>` (§18.7): `GET …/customerapp?app_name=`.
pub async fn get(
    invocation: &mut Invocation,
    name: &str,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_runtime(Planes::default())?;
    let format = connected.format(format);
    connected.clients.authenticate(None, TOKEN_BUDGET).await?;
    let app = connected
        .clients
        .management
        .customer_apps()
        .get(name, Some(&runtime::options(SINGLE_REQUEST_BUDGET)?))
        .await
        .and_then(|app| views::ordered(&app))
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
    let mut rows = vec![app];
    sanitize_all(&mut rows, &invocation.secrets);
    let doc = views::customer_app(&rows[0]);
    views::render_customer_app(&mut invocation.output, &doc, format)
}

/// `runtime customer-apps consumption [appName] [--time-interval 7|30|60]` (§18.9): one
/// overview walk over the window (D211) under one `WALK_BUDGET` with the token, then the
/// two reads of the named app or of every app in overview order (D210), each read under
/// its own `SINGLE_REQUEST_BUDGET` from when it is sent (§18.3).
pub async fn consumption(
    invocation: &mut Invocation,
    app: Option<&str>,
    interval: u64,
    format: Option<Format>,
) -> Result<(), CliError> {
    let walk = runtime::options(WALK_BUDGET)?;
    let connected = invocation.connect_runtime(Planes {
        dashboard: true,
        dlp: false,
    })?;
    let format = connected.format(format);
    connected
        .clients
        .authenticate(Some(&walk), WALK_BUDGET)
        .await?;
    let dash = connected.clients.management.dashboard();
    let overview = consumption::overview(&dash, interval, &walk)
        .await
        .map_err(|error| invocation.management_error(&error, WALK_BUDGET))?;
    if overview.skipped > 0 {
        invocation
            .output
            .warning(&consumption::skipped_warning(overview.skipped));
    }
    if let Some(name) = app {
        let bucket = consumption::lookup(&overview.buckets, name, &invocation.secrets)?.clone();
        let data = consumption::read(
            &dash,
            &bucket,
            interval,
            SINGLE_REQUEST_BUDGET,
            &invocation.secrets,
        )
        .await
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
        return views::render_consumption(&mut invocation.output, &[data], format, false);
    }
    let mut apps = Vec::new();
    let mut failed = false;
    for bucket in &overview.buckets {
        let read = consumption::read(
            &dash,
            bucket,
            interval,
            SINGLE_REQUEST_BUDGET,
            &invocation.secrets,
        );
        match read.await {
            Ok(data) => apps.push(data),
            Err(error) if error.kind() == scm::ErrorKind::Cancelled => {
                return Err(CliError::Interrupted(InterruptContext::NoDataWritten));
            }
            Err(error) => {
                failed = true;
                let failure = invocation.management_error(&error, SINGLE_REQUEST_BUDGET);
                app_failure(invocation, bucket, &failure);
            }
        }
    }
    // §18.9: the empty-overview phrase only when the overview had no app, never when
    // every app's reads failed.
    let empty = overview.buckets.is_empty();
    views::render_consumption(&mut invocation.output, &apps, format, empty)?;
    if failed {
        // D210: the apps that succeeded are printed; a partial result is not a success.
        let _ = invocation.output.commit();
        return Err(CliError::Reported(crate::error::EXIT_OPERATIONAL));
    }
    Ok(())
}

/// `  ✗ [<name>] <message>[ (HTTP <s>)]` on stderr (red, never suppressed; TS shape).
fn app_failure(invocation: &mut Invocation, bucket: &Bucket, failure: &CliError) {
    let (message, status) = match failure {
        CliError::Operational(failure) => (failure.message.clone(), failure.status),
        other => (other.message(), None),
    };
    let first = message.lines().next().unwrap_or_default().to_owned();
    let status = status.map_or_else(String::new, |status| format!(" (HTTP {status})"));
    let line = invocation.output.paint_err(
        Style::Red,
        &format!(
            "✗ [{}] {}{status}",
            runtime::shown(&bucket.name, &invocation.secrets),
            crate::output::terminal_safe(&first)
        ),
    );
    invocation.output.write_stderr(&format!("  {line}\n"));
}

// ---------------------------------------------------------------------------
// The customer-app writes (§18.8)
// ---------------------------------------------------------------------------

/// A validated `customer-apps update` (§18.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePlan {
    pub id: String,
    pub config: OsString,
    pub force: bool,
    pub format: Option<Format>,
}

/// The members of the current record a replacement does not count as dropped: ids,
/// ownership, the key associations and timestamps (§18.8).
fn kept_by_service(key: &str) -> bool {
    matches!(
        key,
        "customer_appId" | "tsg_id" | "api_keys_dp_info" | "created_by" | "updated_by"
    ) || key.ends_with("_ts")
        || key.ends_with("_at")
}

/// The update prompt (§18.3 "Confirmations"): the app, the file, the fields the
/// replacement drops (at most 20 named; a name that carries a secret is left out, as
/// [`views::withhold`] drops it, choice 81) and a rename.
fn update_prompt(
    id: &str,
    current: &OValue,
    file: &str,
    named: &[String],
    new_name: Option<&str>,
    secrets: &SecretSet,
) -> String {
    let name = views::text(current, "app_name").unwrap_or_default();
    let mut message = format!("Replace customer app {name} ({id}) with the settings in {file}?");
    let dropped: Vec<&str> = current
        .as_object()
        .unwrap_or_default()
        .iter()
        .filter(|(key, value)| {
            *value != OValue::Null
                && !kept_by_service(key)
                && !named.iter().any(|n| n == key)
                && !secrets.carried_by(key)
        })
        .map(|(key, _)| key.as_str())
        .collect();
    if !dropped.is_empty() {
        let mut list = dropped
            .iter()
            .take(20)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if dropped.len() > 20 {
            list.push_str(&format!(", and {} more", dropped.len() - 20));
        }
        message.push_str(&format!(
            " It drops {} field(s) the app has now: {list}.",
            dropped.len()
        ));
    }
    if let Some(new_name) = new_name
        && new_name != name
    {
        message.push_str(&format!(" It renames the app to {new_name}."));
    }
    message
}

/// The current record of `id` for the update prompt: the complete list walk (G30: there
/// is no read by id) with the row check (D219); `None` when it is not listed.
async fn current_record(
    invocation: &Invocation,
    clients: &crate::clients::ManagementClients,
    id: &str,
) -> Result<Option<OValue>, CliError> {
    let options = runtime::options(WALK_BUDGET)?;
    let fail = |error: &scm::Error| {
        super::nothing_changed(invocation.management_error(error, WALK_BUDGET))
    };
    let mut all = CustomerAppListAllOptions::default();
    all.limit = 100;
    all.collect = pagination::collect_options(0).map_err(|error| fail(&error))?;
    let collection = clients
        .management
        .customer_apps()
        .list_all(all, Some(&options))
        .await
        .map_err(|error| fail(error.error()))?;
    if pagination::walk_end(collection.completion, 0).is_none() {
        return Err(fail(&pagination::incomplete_walk()));
    }
    let mut rows =
        unique_rows(&collection.items, "customer_appId").map_err(|error| fail(&error))?;
    sanitize_all(&mut rows, &invocation.secrets);
    Ok(rows
        .into_iter()
        .find(|row| views::text(row, "customer_appId") == Some(id)))
}

/// `runtime customer-apps update <appId> --config <path>` (§18.8, D206, D221): the file
/// and its body before the tenant; the token; with a prompt the list walk that names what
/// the replacement drops; one `PUT`, then the record.
pub async fn update(invocation: &mut Invocation, plan: &UpdatePlan) -> Result<(), CliError> {
    let object = crate::files::read_config(&plan.config)?;
    let file = terminal_safe(&crate::files::shown(&plan.config)).into_owned();
    if object
        .get("customer_appId")
        .is_some_and(|named| named.as_str() != Some(plan.id.as_str()))
    {
        return Err(CliError::operational(format!(
            "{file} names another customer app than {}",
            terminal_safe(&plan.id)
        )));
    }
    let named: Vec<String> = object.keys().cloned().collect();
    let new_name = object
        .get("app_name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let request = w::body(
        serde_json::Value::Object(object),
        "PUT",
        "/v1/mgmt/customerapp",
        scm::airs::management::models::CustomerApp::parse,
    )?;
    let clients = w::prepare(invocation)?;
    w::authenticate(&clients).await?;
    if !plan.force {
        let Some(current) = current_record(invocation, &clients, &plan.id).await? else {
            return Err(CliError::operational(format!(
                "Customer app {} was not found; nothing was sent",
                terminal_safe(&plan.id)
            )));
        };
        let message = update_prompt(
            &plan.id,
            &current,
            &file,
            &named,
            new_name.as_deref(),
            &invocation.secrets,
        );
        if !w::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let hint = format!(
        "Check it with 'airs runtime customer-apps get {}'.",
        terminal_safe(new_name.as_deref().unwrap_or_default())
    );
    let apps = clients.management.customer_apps();
    let answer = w::send(
        invocation,
        Change::Words("customer app", "updated"),
        &hint,
        async || {
            let options = runtime::request_options(SINGLE_REQUEST_BUDGET)?;
            apps.update(&plan.id, &request, Some(&options)).await
        },
    )
    .await?;
    invocation.committed = true;
    let mut rows = vec![views::ordered(&answer).map_err(|error| {
        crate::writes::describe(
            &error,
            Change::Words("customer app", "updated"),
            &invocation.secrets,
        )
    })?];
    sanitize_all(&mut rows, &invocation.secrets);
    let doc = views::customer_app(&rows[0]);
    let name = views::text(&doc, "name").unwrap_or_default().to_owned();
    invocation
        .output
        .success(&format!("Customer app updated: {}", terminal_safe(&name)));
    views::render_customer_app(&mut invocation.output, &doc, w::format(plan.format))
}

/// `runtime customer-apps delete|rm <appName> --updated-by <email>` (§18.8, D206, D208):
/// the tenant, the prompt, the token, one `DELETE`, then the fixed acknowledgement.
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
            &format!("Delete customer app {name} and its API keys?"),
        )?
    {
        return Ok(());
    }
    w::authenticate(&clients).await?;
    let apps = clients.management.customer_apps();
    w::send(
        invocation,
        Change::Words("customer app", "deleted"),
        "Check 'airs runtime customer-apps list'; its API keys may have been deleted too.",
        async || {
            let options = runtime::request_options(SINGLE_REQUEST_BUDGET)?;
            apps.delete(name, updated_by, Some(&options)).await
        },
    )
    .await?;
    invocation.committed = true;
    invocation.output.success(&format!(
        "Customer app \"{}\" deleted.",
        terminal_safe(name)
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(value: serde_json::Value) -> OValue {
        crate::json::to_ordered(&value).unwrap()
    }

    /// The update prompt names the dropped fields (not ids, ownership, keys or
    /// timestamps), at most 20, and a rename.
    #[test]
    fn the_update_prompt_names_dropped_fields_and_a_rename() {
        let none = SecretSet::default();
        let current = record(serde_json::json!({
            "customer_appId": "id", "tsg_id": "100", "app_name": "app-1", "model_name": "gpt",
            "cloud_provider": "aws", "environment": "prod", "ai_agent_framework": "none",
            "api_keys_dp_info": [], "created_by": "a", "last_modified_ts": "t", "status": null
        }));
        let named: Vec<String> = ["app_name", "cloud_provider", "environment"]
            .map(str::to_owned)
            .to_vec();
        assert_eq!(
            update_prompt("id", &current, "a.json", &named, Some("app-1"), &none),
            "Replace customer app app-1 (id) with the settings in a.json? It drops 2 field(s) the app has now: ai_agent_framework, model_name."
        );
        let mut all = named.clone();
        all.extend(["model_name", "ai_agent_framework"].map(str::to_owned));
        assert_eq!(
            update_prompt("id", &current, "a.json", &all, Some("app-2"), &none),
            "Replace customer app app-1 (id) with the settings in a.json? It renames the app to app-2."
        );
        let many = record(serde_json::Value::Object(
            (0..23)
                .map(|n| (format!("f{n:02}"), serde_json::json!(n)))
                .collect(),
        ));
        assert!(
            update_prompt("id", &many, "a.json", &[], None, &none)
                .ends_with("It drops 23 field(s) the app has now: f00, f01, f02, f03, f04, f05, f06, f07, f08, f09, f10, f11, f12, f13, f14, f15, f16, f17, f18, f19, and 3 more.")
        );
    }

    /// Choice 81: a field whose name carries a secret is never named in the prompt.
    #[test]
    fn the_update_prompt_never_names_a_secret_field() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-K1-SECRET");
        let current = record(serde_json::json!({
            "app_name": "app-1", "model_name": "gpt", "FAKE-K1-SECRET": "v", "x-FAKE-K1-SECRET-y": 1
        }));
        let named = vec!["app_name".to_owned()];
        assert_eq!(
            update_prompt("id", &current, "a.json", &named, None, &secrets),
            "Replace customer app app-1 (id) with the settings in a.json? It drops 1 field(s) the app has now: model_name."
        );
    }
}
