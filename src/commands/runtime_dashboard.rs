//! `runtime dashboard *` and `runtime sessions *` (DESIGN §18.12, §18.13): one GET each on
//! the dashboard base (`x-tsg-id`, the SDK's dashboard client), `with_retries(0)` and the
//! G7 re-read, the response envelope as JSON text with C1 escapes (D212), `sessions list
//! --all` through `walk_with` with TypeScript's page checks (choice 14), and
//! `scan-content` to stdout or a new private file (D225).
//!
//! Every failure after the client is built prints TypeScript's one dashboard line (choice
//! 13); tenant, store and credential errors keep their own messages (D212).

use super::Invocation;
use super::runtime_extras::{DashRead, SessionsList, TimeRead};
use crate::clients::{Planes, SINGLE_REQUEST_BUDGET, WALK_BUDGET};
use crate::error::{CliError, InterruptContext};
use crate::files::{self, Published, shown};
use crate::json::OValue;
use crate::output::{Format, terminal_safe};
use crate::runtime::views::{self, DashTable};
use crate::runtime::{self, reread};
use crate::walk::{self, Page, Spec};
use scm::airs::management::{
    DashboardAppQuery, DashboardApplicationsOverviewQuery, DashboardClient,
    DashboardScanContentQuery, DashboardSessionQuery, DashboardSessionTransactionQuery,
    DashboardSessionsOverviewQuery, DashboardTimeRangeQuery,
};
use std::path::Path;

/// The `sessions list --all` page bound (TS).
const SESSION_PAGES: usize = 100;

/// Load the tenant and build the dashboard client (their errors keep their messages),
/// then fetch the token under its own dashboard options of `budget` (a failure is the
/// dashboard line). The caller builds the read's options after this, so the token does
/// not shorten the read's budget (§18.3).
async fn connect(
    invocation: &mut Invocation,
    explicit: Option<Format>,
    budget: std::time::Duration,
) -> Result<(DashboardClient, Format), CliError> {
    let options = runtime::dashboard_options(budget)?;
    let connected = invocation.connect_runtime(Planes {
        dashboard: true,
        dlp: false,
    })?;
    let format = connected.format(explicit);
    if let Err(error) = connected.clients.provider.get_token(Some(&options)).await {
        return Err(runtime::dashboard_failure(&mut invocation.output, &error));
    }
    Ok((connected.clients.management.dashboard(), format))
}

fn time_query(interval: u64, unit: &str) -> DashboardTimeRangeQuery {
    let mut query = DashboardTimeRangeQuery::default();
    query.time_interval = Some(interval);
    query.time_unit = Some(unit.to_owned());
    query
}

/// One dashboard read as ordered JSON, re-read once after a 401 or 403 (G7).
async fn fetch(
    dash: &DashboardClient,
    read: &DashRead,
    options: &scm::RequestOptions,
) -> scm::Result<OValue> {
    let options = Some(options);
    match read {
        DashRead::Applications {
            interval,
            unit,
            limit,
            offset,
        } => {
            let mut query = DashboardApplicationsOverviewQuery::default();
            query.time_interval = Some(*interval);
            query.time_unit = Some(unit.clone());
            query.limit = Some(*limit);
            query.offset = Some(*offset);
            views::ordered(&reread(|| dash.applications_overview(&query, options)).await?)
        }
        DashRead::Application {
            violations,
            app_id,
            app_name,
            interval,
        } => {
            let mut query = DashboardAppQuery::new(app_id.clone(), app_name.clone());
            query.time_interval = Some(*interval);
            query.time_unit = Some("days".to_owned());
            if *violations {
                views::ordered(
                    &reread(|| dash.application_violation_breakdown(&query, options)).await?,
                )
            } else {
                views::ordered(&reread(|| dash.application(&query, options)).await?)
            }
        }
        DashRead::TimeRange {
            read,
            interval,
            unit,
        } => {
            let query = time_query(*interval, unit);
            match read {
                TimeRead::TopApplications => views::ordered(
                    &reread(|| dash.top_applications_violations(&query, options)).await?,
                ),
                TimeRead::ViolationsTrend => views::ordered(
                    &reread(|| dash.applications_violations_trend(&query, options)).await?,
                ),
                TimeRead::AppsList => {
                    views::ordered(&reread(|| dash.apps_list(&query, options)).await?)
                }
                TimeRead::SessionsChart => {
                    views::ordered(&reread(|| dash.sessions_chart(&query, options)).await?)
                }
            }
        }
        DashRead::Session {
            identity,
            limit,
            offset,
        } => {
            let mut query = DashboardSessionQuery::new(
                identity.session_id.clone(),
                identity.app_id.clone(),
                identity.app_name.clone(),
            );
            query.time_interval = Some(identity.interval);
            query.time_unit = Some(identity.unit.clone());
            query.limit = Some(*limit);
            query.offset = Some(*offset);
            views::ordered(&reread(|| dash.session(&query, options)).await?)
        }
        DashRead::Transaction {
            identity,
            scan_id,
            sub_request,
        } => {
            let mut query = DashboardSessionTransactionQuery::new(
                identity.session_id.clone(),
                identity.app_id.clone(),
                identity.app_name.clone(),
                scan_id.clone(),
                *sub_request,
            );
            query.time_interval = Some(identity.interval);
            query.time_unit = Some(identity.unit.clone());
            views::ordered(&reread(|| dash.session_transaction(&query, options)).await?)
        }
    }
}

fn layout(read: &DashRead) -> DashTable {
    match read {
        DashRead::Applications { .. } => DashTable::Applications,
        DashRead::TimeRange {
            read: TimeRead::TopApplications,
            ..
        } => DashTable::TopApplications,
        DashRead::TimeRange {
            read: TimeRead::AppsList,
            ..
        } => DashTable::AppsList,
        _ => DashTable::Envelope,
    }
}

/// `runtime dashboard *`, `sessions chart|get|transaction` (§18.12, §18.13).
pub async fn read(
    invocation: &mut Invocation,
    read: &DashRead,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (dash, format) = connect(invocation, explicit, SINGLE_REQUEST_BUDGET).await?;
    let options = runtime::dashboard_options(SINGLE_REQUEST_BUDGET)?;
    let mut doc = match fetch(&dash, read, &options).await {
        Ok(doc) => doc,
        Err(error) => return Err(runtime::dashboard_failure(&mut invocation.output, &error)),
    };
    views::sanitize(&mut doc, &invocation.secrets);
    views::render_dashboard(&mut invocation.output, &doc, format, layout(read))
}

/// One `sessionsoverview` page as ordered JSON.
async fn overview_page(
    dash: &DashboardClient,
    list: &SessionsList,
    offset: u64,
    options: &scm::RequestOptions,
) -> scm::Result<OValue> {
    let mut query = DashboardSessionsOverviewQuery::default();
    query.time_interval = Some(list.interval);
    query.time_unit = Some(list.unit.clone());
    query.limit = Some(list.limit);
    query.offset = Some(offset);
    views::ordered(&reread(|| dash.sessions_overview(&query, Some(options))).await?)
}

fn items(page: &OValue) -> Vec<OValue> {
    page.get("items")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .to_vec()
}

fn pagination_number(page: &OValue, key: &str) -> Option<f64> {
    page.get("pagination")
        .and_then(|pagination| crate::json::number(pagination, key))
}

fn unstable() -> scm::Error {
    scm::Error::new(scm::ErrorKind::Pagination)
}

/// The identity TypeScript checks for overlap (`[application_id, application_name,
/// session_id]`).
fn session_key(item: &OValue) -> String {
    let member = |key: &str| item.get(key).cloned().unwrap_or(OValue::Null);
    crate::json::to_compact(&OValue::Array(vec![
        member("application_id"),
        member("application_name"),
        member("session_id"),
    ]))
    .unwrap_or_default()
}

/// `runtime sessions list|ls` (§18.13): one page and its status line, or `--all`.
pub async fn sessions_list(
    invocation: &mut Invocation,
    list: &SessionsList,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let budget = if list.all {
        WALK_BUDGET
    } else {
        SINGLE_REQUEST_BUDGET
    };
    let (dash, format) = connect(invocation, explicit, budget).await?;
    // One page: its own budget; `--all`: one `WALK_BUDGET` across every page (§18.3).
    let options = runtime::dashboard_options(budget)?;
    if !list.all {
        let page = match overview_page(&dash, list, list.offset, &options).await {
            Ok(page) => page,
            Err(error) => return Err(runtime::dashboard_failure(&mut invocation.output, &error)),
        };
        let total = match page.get("pagination").and_then(|p| p.get("total_items")) {
            Some(OValue::Number(number)) => crate::render::js_json_number(number),
            Some(OValue::Null) | None => "unknown".to_owned(),
            Some(other) => crate::render::cell_text(Some(other)),
        };
        let mut rows = OValue::Array(items(&page));
        views::sanitize(&mut rows, &invocation.secrets);
        let returned = rows.as_array().map_or(0, <[OValue]>::len);
        invocation.output.status(&format!(
            "Returned {returned} of {total} sessions; this is one page."
        ));
        return views::render_dashboard(&mut invocation.output, &rows, format, DashTable::Sessions);
    }
    // TS `rd.ts:234-299`: the echo, total and overlap checks per page, then the walk.
    let expected_total = std::cell::Cell::new(None::<u64>);
    let seen = std::cell::RefCell::new(std::collections::HashSet::<String>::new());
    let limit = list.limit;
    let walked = walk::walk_with(
        Spec {
            start: list.offset,
            max_pages: SESSION_PAGES,
            page_cap_partial: true,
            shrink_last_page: false,
        },
        u32::try_from(limit).unwrap_or(u32::MAX),
        list.max,
        |offset, _| {
            let dash = &dash;
            let options = &options;
            async move {
                let page = overview_page(dash, list, offset, options).await?;
                #[allow(clippy::cast_precision_loss)]
                let echoed = pagination_number(&page, "skip") == Some(offset as f64)
                    && pagination_number(&page, "limit") == Some(limit as f64);
                if !echoed {
                    return Err(unstable());
                }
                let total = walk::total_of(pagination_number(&page, "total_items"));
                Ok(Page::new(items(&page), total))
            }
        },
        |row| crate::json::to_compact(row).map_or(0, |text| text.len()),
        |_| None,
        |offset, _, page| {
            let Some(total) = page.total else {
                return Err(unstable());
            };
            let received = u64::try_from(page.rows.len()).map_err(|_| unstable())?;
            if received > limit || expected_total.get().is_some_and(|first| first != total) {
                return Err(unstable());
            }
            expected_total.set(Some(total));
            let mut seen = seen.borrow_mut();
            for item in &page.rows {
                if !seen.insert(session_key(item)) {
                    return Err(unstable());
                }
            }
            if offset.saturating_add(received) > total {
                return Err(unstable());
            }
            Ok(())
        },
    )
    .await;
    let walked = match walked {
        Ok(walked) => walked,
        Err(error) => return Err(runtime::dashboard_failure(&mut invocation.output, &error)),
    };
    let partial = walked.stopped_at_max || walked.stopped_at_pages;
    let status = if walked.stopped_at_max {
        "Session item cap reached; output is partial.".to_owned()
    } else if walked.stopped_at_pages {
        "Session page cap reached; output is partial.".to_owned()
    } else {
        format!(
            "Retrieved {} sessions from offset {}; pagination complete.",
            walked.rows.len(),
            list.offset
        )
    };
    invocation.output.status(&status);
    let mut rows = OValue::Array(walked.rows);
    views::sanitize(&mut rows, &invocation.secrets);
    views::render_dashboard(&mut invocation.output, &rows, format, DashTable::Sessions)?;
    if partial {
        // TS: the first items are printed and the run exits 1 (choice 14); a signal or a
        // failed write is reported instead (§2.5, §20.17 choice 78).
        invocation.output.commit_data()?;
        return Err(CliError::Reported(crate::error::EXIT_OPERATIONAL));
    }
    Ok(())
}

/// `runtime sessions scan-content` (§18.13, D225): `--show-content` prints the envelope;
/// `--output-file` publishes its JSON text at 0600 (never overwriting), its path and
/// directory checked before the tenant.
pub async fn scan_content(
    invocation: &mut Invocation,
    scan_id: &str,
    sub_request: u64,
    file: Option<&Path>,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    if let Some(path) = file {
        files::check_new(path, "--output-file")?;
    }
    let (dash, format) = connect(invocation, explicit, SINGLE_REQUEST_BUDGET).await?;
    let options = runtime::dashboard_options(SINGLE_REQUEST_BUDGET)?;
    let query = DashboardScanContentQuery::new(scan_id.to_owned(), sub_request);
    let mut doc = match reread(|| dash.scan_content(&query, Some(&options)))
        .await
        .and_then(|answer| views::ordered(&answer))
    {
        Ok(doc) => doc,
        Err(error) => return Err(runtime::dashboard_failure(&mut invocation.output, &error)),
    };
    views::sanitize(&mut doc, &invocation.secrets);
    let Some(path) = file else {
        return views::render_dashboard(&mut invocation.output, &doc, format, DashTable::Envelope);
    };
    // The file holds the JSON text in every format (choice 16).
    let text = crate::json::json_text(&doc)?;
    if invocation.output.pending_signal().is_some() {
        return Err(CliError::Interrupted(InterruptContext::NoDataWritten));
    }
    let published = files::publish_new(path, format!("{text}\n").as_bytes(), "--output-file")?;
    let typed = terminal_safe(&shown(path.as_os_str())).into_owned();
    invocation.interrupt = Some(InterruptContext::Context(format!("{typed} was written")));
    if published == Published::DirectoryNotSynced {
        invocation
            .output
            .warning(&crate::store::atomic::dir_sync_warning(path));
    }
    invocation
        .output
        .status("Scan content exported to the requested private file (0600).");
    Ok(())
}
