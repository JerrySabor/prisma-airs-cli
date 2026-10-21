//! `gateway telemetry …` (DESIGN §19.8): `cost` and every other telemetry read.
//!
//! Every leaf resolves `--workspace` over data active, admin active and admin archived
//! (§19.4, D235), then sends one read on the data plane with the window fixed during
//! planning (UTC, G41). The answer is withheld (`filter-boundaries` `data` whole, choice
//! 18; log rows by the name and URL rules, D251), a quota flag is a stderr warning on every
//! leaf (choice 10), and `logs list` says when more pages exist (choice 64).

use super::Invocation;
use super::gateway::{Chart, FilteredChart, TelemetryRead};
use crate::clients::SINGLE_REQUEST_BUDGET;
use crate::error::CliError;
use crate::gateway::resolve::{self, Resolved};
use crate::gateway::window::{Dimension, Filters, Window};
use crate::gateway::withhold::{self, FILTER_BOUNDARIES, PLAIN};
use crate::gateway::{self, GwPlane, views};
use crate::json::{OValue, page_value};
use crate::output::Format;
use scm::airs::gateway::{AIGatewayClient, AIGatewayGroupOptions, AIGatewayLogsOptions};

/// TS's quota text (`rgw.ts:222`), a stderr warning here (D230).
const QUOTA_WARNING: &str = "⚠ Telemetry quota exceeded — data may be truncated";

/// Resolve `--workspace` to its slug (§19.4: data active, admin active, admin archived).
async fn resolve_slug(
    invocation: &mut Invocation,
    gateway: &AIGatewayClient,
    workspace: &str,
) -> Result<String, CliError> {
    let found = match resolve::resolve(gateway, workspace, resolve::TELEMETRY).await {
        Ok(found) => found,
        Err(failure) => {
            let error = invocation.gateway_error(&failure.error, failure.plane);
            // An answer refused by the later list (an access gap), not an interruption or
            // a transport failure (choice 134).
            if failure.after_unmatched && failure.error.kind() == scm::ErrorKind::Http {
                invocation
                    .output
                    .warning(&resolve::later_list_hint(workspace));
            }
            return Err(error);
        }
    };
    match found {
        Resolved::ByRef(slug) | Resolved::ByName(slug) => Ok(slug),
        Resolved::Ambiguous(slugs) => Err(CliError::operational(resolve::ambiguous_message(
            workspace, &slugs,
        ))),
        Resolved::Incomplete => Err(CliError::operational(resolve::incomplete_message(
            workspace, true,
        ))),
        Resolved::NoSlug => Err(CliError::operational(resolve::no_slug_message(
            workspace, true,
        ))),
        Resolved::NotFound => Err(CliError::operational(resolve::not_found_message(
            workspace,
            resolve::TELEMETRY,
        ))),
    }
}

/// Whether the answer says its data is truncated (`data.isQuotaExceeded`, or a group
/// list's `is_quota_exceeded`).
fn quota_exceeded(doc: &OValue) -> bool {
    let flag = |value: Option<&OValue>| matches!(value, Some(OValue::Bool(true)));
    flag(doc.get("data").and_then(|data| data.get("isQuotaExceeded")))
        || flag(doc.get("is_quota_exceeded"))
}

/// `telemetry cost` (§19.8).
pub async fn cost(
    invocation: &mut Invocation,
    workspace: &str,
    days: u64,
    window: &Window,
    filters: &Filters,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (gateway, format) = invocation.connect_gateway(explicit).await?;
    let slug = resolve_slug(invocation, &gateway, workspace).await?;
    let chart = filters.chart(window, &slug)?;
    let options = gateway::options(SINGLE_REQUEST_BUDGET)?;
    let answer = match gateway.telemetry().cost(&chart, Some(&options)).await {
        Ok(answer) => answer,
        Err(error) => return Err(invocation.gateway_error(&error, GwPlane::Data)),
    };
    let mut doc = crate::json::model_value(&answer)?;
    withhold::apply(&mut doc, &PLAIN, &invocation.secrets);
    let record = views::cost_record(&slug, days, &doc);
    views::render_cost(&mut invocation.output, &record, format)?;
    if quota_exceeded(&doc) {
        invocation.output.warning(QUOTA_WARNING);
    }
    Ok(())
}

/// The one data-plane read of a telemetry leaf, as an ordered document.
async fn fetch(
    gateway: &AIGatewayClient,
    read: &TelemetryRead,
    slug: &str,
    window: &Window,
) -> Result<Result<OValue, scm::Error>, CliError> {
    let telemetry = gateway.telemetry();
    let options = gateway::options(SINGLE_REQUEST_BUDGET)?;
    let options = Some(&options);
    let range = window.options(slug)?;
    Ok(match read {
        TelemetryRead::Chart(chart) => match chart {
            Chart::Errors => telemetry
                .errors(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::Users => telemetry
                .users(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::ErrorTrends => telemetry
                .error_trends(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::ErrorCategoryTrends => telemetry
                .error_category_trends(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::GroupedErrors => telemetry
                .grouped_errors(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::RescuedRetries => telemetry
                .rescued_retries(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::UserTrends => telemetry
                .user_trends(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::CacheSummary => telemetry
                .cache_summary(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::CacheTrend => telemetry
                .cache_hit_trend(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::FeedbackDistribution => telemetry
                .feedback_score_distribution(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::FeedbackModels => telemetry
                .feedback_models(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::FeedbackTrend => telemetry
                .feedback_trend(&range, options)
                .await
                .and_then(|a| page_value(&a)),
            Chart::FeedbackWeighted => telemetry
                .feedback_weighted(&range, options)
                .await
                .and_then(|a| page_value(&a)),
        },
        TelemetryRead::Filtered(chart, filters) => {
            let chart_options = filters.chart(window, slug)?;
            match chart {
                FilteredChart::Latency => telemetry
                    .latency(&chart_options, options)
                    .await
                    .and_then(|a| page_value(&a)),
                FilteredChart::Requests => telemetry
                    .requests(&chart_options, options)
                    .await
                    .and_then(|a| page_value(&a)),
                FilteredChart::Tokens => telemetry
                    .tokens(&chart_options, options)
                    .await
                    .and_then(|a| page_value(&a)),
            }
        }
        TelemetryRead::FilterBoundaries => telemetry
            .filter_boundaries(&range, options)
            .await
            .and_then(|a| page_value(&a)),
        TelemetryRead::GroupBy {
            dimension,
            columns,
            filters,
        } => {
            let chart_options = filters.chart(window, slug)?;
            match dimension {
                Dimension::Users => telemetry
                    .by_user(&chart_options, options)
                    .await
                    .and_then(|a| page_value(&a)),
                Dimension::StatusCode | Dimension::Grouped(_) => {
                    let mut group = AIGatewayGroupOptions::new(chart_options);
                    group.columns = columns.clone();
                    match dimension {
                        Dimension::Grouped(dimension) => telemetry
                            .group_by(*dimension, &group, options)
                            .await
                            .and_then(|a| page_value(&a)),
                        _ => telemetry
                            .by_status_code(&group, options)
                            .await
                            .and_then(|a| page_value(&a)),
                    }
                }
            }
        }
        TelemetryRead::Logs(paging) => {
            let mut logs = AIGatewayLogsOptions::new(range);
            logs.page_size = Some(paging.page_size);
            logs.current_page = Some(paging.current_page);
            logs.trace_id = paging.trace_id.clone();
            logs.status_code = paging.status_code;
            telemetry
                .logs(&logs, options)
                .await
                .and_then(|a| page_value(&a))
        }
    })
}

/// The `logs list` status line (choice 64): when the server's `total` says more pages
/// exist after this one.
fn logs_status(doc: &OValue, page: u64, size: u64) -> Option<String> {
    let data = doc.get("data")?;
    let returned = data
        .get("records")
        .and_then(OValue::as_array)
        .map_or(0, <[OValue]>::len);
    let total = crate::walk::total_of(crate::json::number(data, "total"))?;
    let seen = u128::from(page)
        .saturating_mul(u128::from(size))
        .saturating_add(u128::try_from(returned).unwrap_or(u128::MAX));
    (u128::from(total) > seen).then(|| {
        format!(
            "Returned {returned} of {total} request logs (page {page}, {size} per page); this is one page."
        )
    })
}

/// Every telemetry leaf except `cost` (§19.8).
pub async fn read(
    invocation: &mut Invocation,
    read: &TelemetryRead,
    workspace: &str,
    window: &Window,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (gateway, format) = invocation.connect_gateway(explicit).await?;
    let slug = resolve_slug(invocation, &gateway, workspace).await?;
    let mut doc = match fetch(&gateway, read, &slug, window).await? {
        Ok(doc) => doc,
        Err(error) => return Err(invocation.gateway_error(&error, GwPlane::Data)),
    };
    let policy = if matches!(read, TelemetryRead::FilterBoundaries) {
        &FILTER_BOUNDARIES
    } else {
        &PLAIN
    };
    let quota = quota_exceeded(&doc);
    withhold::apply(&mut doc, policy, &invocation.secrets);
    views::render_detail(&mut invocation.output, &doc, format)?;
    if quota {
        invocation.output.warning(QUOTA_WARNING);
    }
    if let TelemetryRead::Logs(paging) = read
        && let Some(status) = logs_status(&doc, paging.current_page, paging.page_size)
    {
        invocation.output.status(&status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn quota_flags_and_log_pages() {
        assert!(quota_exceeded(
            &parse(r#"{"success":true,"data":{"isQuotaExceeded":true}}"#).unwrap()
        ));
        assert!(quota_exceeded(
            &parse(r#"{"object":"list","is_quota_exceeded":true}"#).unwrap()
        ));
        assert!(!quota_exceeded(
            &parse(r#"{"data":{"isQuotaExceeded":false}}"#).unwrap()
        ));
        let doc = parse(r#"{"data":{"records":[{},{}],"total":10}}"#).unwrap();
        assert_eq!(
            logs_status(&doc, 1, 2).unwrap(),
            "Returned 2 of 10 request logs (page 1, 2 per page); this is one page."
        );
        assert_eq!(logs_status(&doc, 4, 2), None, "the last page");
        let doc = parse(r#"{"data":{"records":[],"total":2.5}}"#).unwrap();
        assert_eq!(logs_status(&doc, 0, 50), None);
    }
}
