//! `gateway report|dashboard` (DESIGN §19.15): the gateway environment report's planning,
//! reader and collection. The 25 sources are read one after the other, each under its own
//! budget with `with_retries(0)`, no response defaults (G47) and the G7 re-read. The
//! destination checks before the tenant (anything at the path, and its parent directory,
//! D214), the publishing (one new 0600 file, or stdout with `--output-file -`), the exit
//! code and the single failure line are `report_command`'s, shared with the red team and
//! runtime reports; the HTML is the shared environment template with the gateway profile.

use super::Invocation;
use super::report_command::{self as rc, ParentCheck, ReportDestination, SourceBudget, Verdict};
use crate::clients::WALK_BUDGET;
use crate::error::CliError;
use crate::json::{OValue, page_value};
use crate::output::Format;
use crate::report::gateway::{self, Chart, LOG_PAGE_SIZE, Reader};
use crate::report::{Health, ReadError, html};
use crate::tenant::config::js_trim;
use scm::airs::gateway::{
    AIGatewayChartOptions, AIGatewayClient, AIGatewayLogsOptions, AIGatewayPlane,
    AIGatewayWindowOptions, AIGatewayWorkspaceListOptions, AIGatewayWorkspaceScopedListOptions,
};
use scm::validation::NativeDate;
use std::path::PathBuf;

/// The window error (TS text, §19.15 check 7).
pub const WINDOW_ERROR: &str = "Provide a valid increasing ISO-8601 window with timezone";

/// `0000-01-01T00:00:00Z` and `9999-12-31T23:59:59.999Z` in epoch milliseconds (D249).
const FIRST_MS: i64 = -62_167_219_200_000;
const LAST_MS: i64 = 253_402_300_799_999;

/// A validated `gateway report`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayReportPlan {
    pub destination: ReportDestination,
    pub workspace: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub title: String,
    pub max_pages: u32,
    pub strict: bool,
}

/// `airs-gateway-report-<ISO time, ':' → '-'>-<8 hex>.html` (TS `airs-aigateway-report-…`,
/// D227).
pub fn default_name(now: std::time::SystemTime) -> String {
    format!(
        "airs-gateway-report-{}-{}.html",
        crate::debug::iso_timestamp(now).replace(':', "-"),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )
}

/// `^[1-9][0-9]*$` and a safe integer (TS).
fn positive(value: &str) -> Option<u64> {
    (!value.is_empty() && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse::<u64>().ok())
        .flatten()
        .filter(|n| *n <= 9_007_199_254_740_991)
}

/// The window of the report (§19.15 check 7), fixed at the time of the check (`now`):
/// `--start`/`--end` in the zod offset grammar, else the `days × 24 h` before `now`;
/// `start < end`, both within the years 0000–9999 (D249).
pub fn report_window(
    days: u64,
    start: Option<&str>,
    end: Option<&str>,
    now: i64,
) -> Result<(i64, i64), CliError> {
    let failed = || CliError::usage(WINDOW_ERROR);
    let (start_ms, end_ms) = match (start, end) {
        (Some(start), Some(end)) => (
            crate::modelsec::datetime_millis(start).ok_or_else(failed)?,
            crate::modelsec::datetime_millis(end).ok_or_else(failed)?,
        ),
        _ => {
            let start = i128::from(now) - i128::from(days) * 86_400_000;
            (i64::try_from(start).map_err(|_| failed())?, now)
        }
    };
    if start_ms >= end_ms || start_ms < FIRST_MS || end_ms > LAST_MS {
        return Err(failed());
    }
    Ok((start_ms, end_ms))
}

/// The checks of `gateway report` (§19.15, in TS order; `--workspace` is required by clap).
pub fn plan(
    args: &crate::cli::GwReportArgs,
    explicit: Option<Format>,
    debug: bool,
    now: i64,
) -> Result<GatewayReportPlan, CliError> {
    if debug {
        return Err(CliError::usage(
            "Disable --debug for environment reports to avoid persisting sensitive traffic content",
        ));
    }
    if explicit.is_some() {
        return Err(CliError::usage(
            "The environment report is written as HTML; omit --output",
        ));
    }
    crate::gateway::check_resolved_ref("--workspace", &args.workspace)?;
    let days = positive(args.days.as_deref().unwrap_or("1"))
        .ok_or_else(|| CliError::usage("--days must be a positive integer"))?;
    // An empty value counts as absent (TS truthiness).
    let start = args.start.as_deref().filter(|value| !value.is_empty());
    let end = args.end.as_deref().filter(|value| !value.is_empty());
    if start.is_some() != end.is_some() {
        return Err(CliError::usage(
            "--start and --end must be supplied together",
        ));
    }
    if start.is_some() && args.days.is_some() {
        return Err(CliError::usage("Use --days or --start/--end, not both"));
    }
    let (start_ms, end_ms) = report_window(days, start, end, now)?;
    let max_pages = positive(args.max_pages.as_deref().unwrap_or("40"))
        .filter(|pages| (1..=100).contains(pages))
        .and_then(|pages| u32::try_from(pages).ok())
        .ok_or_else(|| CliError::usage("--max-pages must be an integer from 1 to 100"))?;
    let title = args
        .title
        .clone()
        .unwrap_or_else(|| "AI Gateway environment report".to_owned());
    if js_trim(&title).is_empty() || title.encode_utf16().count() > 240 {
        return Err(CliError::usage("--title must contain 1–240 characters"));
    }
    let destination = match &args.output_file {
        Some(path) if js_trim(&path.to_string_lossy()).is_empty() => {
            return Err(CliError::usage("--output-file cannot be empty"));
        }
        Some(path) if path == "-" => ReportDestination::Stdout,
        Some(path) => ReportDestination::File(PathBuf::from(path)),
        None => ReportDestination::File(PathBuf::from(default_name(std::time::SystemTime::now()))),
    };
    Ok(GatewayReportPlan {
        destination,
        workspace: args.workspace.clone(),
        start_ms,
        end_ms,
        title,
        max_pages,
        strict: args.strict,
    })
}

/// The report read options: `with_retries(0)` under one `WALK_BUDGET`, no response
/// defaults (G47).
fn read_options() -> scm::Result<scm::RequestOptions> {
    scm::RequestOptions::with_timeout(WALK_BUDGET)
        .and_then(|options| options.with_retries(0))
        .map(scm::RequestOptions::without_response_defaults)
}

/// The SDK behind the collector.
struct SdkReader<'a> {
    gateway: &'a AIGatewayClient,
    budget: SourceBudget,
    tsg: String,
    start_ms: i64,
    end_ms: i64,
}

impl SdkReader<'_> {
    /// The report window for `slug` (UTC, seconds on the wire; G41). An instant the SDK
    /// cannot represent fails the source (a validation failure, no request).
    fn window(&self, slug: &str) -> Result<AIGatewayWindowOptions, ReadError> {
        let mut window = AIGatewayWindowOptions::new(slug);
        window.start =
            Some(NativeDate::from_epoch_millis(self.start_ms).map_err(|_| ReadError::Failed)?);
        window.end =
            Some(NativeDate::from_epoch_millis(self.end_ms).map_err(|_| ReadError::Failed)?);
        Ok(window)
    }

    fn chart_options(&self, slug: &str) -> Result<AIGatewayChartOptions, ReadError> {
        AIGatewayChartOptions::new(self.window(slug)?).map_err(|_| ReadError::Failed)
    }
}

/// Read the typed answer of one call as ordered JSON (a serialisation failure is a
/// failed source).
macro_rules! read {
    ($self:ident, $source:expr, |$options:ident| $call:expr) => {
        $self
            .budget
            .read($source, async |$options| {
                $call.await.and_then(|answer| page_value(&answer))
            })
            .await
    };
}

impl Reader for SdkReader<'_> {
    async fn workspaces(&self) -> Result<OValue, ReadError> {
        let mut list = AIGatewayWorkspaceListOptions::default();
        list.plane = AIGatewayPlane::Admin;
        read!(self, "workspaces.list", |options| self
            .gateway
            .workspaces()
            .list(&list, Some(&options)))
    }

    async fn chart(&self, chart: Chart, slug: &str) -> Result<OValue, ReadError> {
        let telemetry = self.gateway.telemetry();
        let window = self.window(slug)?;
        let source = chart.source();
        match chart {
            Chart::Requests | Chart::Cost | Chart::Latency | Chart::Tokens => {
                let filtered = self.chart_options(slug)?;
                match chart {
                    Chart::Requests => read!(self, source, |options| telemetry
                        .requests(&filtered, Some(&options))),
                    Chart::Cost => {
                        read!(self, source, |options| telemetry
                            .cost(&filtered, Some(&options)))
                    }
                    Chart::Latency => read!(self, source, |options| telemetry
                        .latency(&filtered, Some(&options))),
                    _ => read!(self, source, |options| telemetry
                        .tokens(&filtered, Some(&options))),
                }
            }
            Chart::Errors => {
                read!(self, source, |options| telemetry
                    .errors(&window, Some(&options)))
            }
            Chart::Users => {
                read!(self, source, |options| telemetry
                    .users(&window, Some(&options)))
            }
            Chart::CacheSummary => read!(self, source, |options| telemetry
                .cache_summary(&window, Some(&options))),
            Chart::CacheHitTrend => read!(self, source, |options| telemetry
                .cache_hit_trend(&window, Some(&options))),
            Chart::UserTrends => read!(self, source, |options| telemetry
                .user_trends(&window, Some(&options))),
            Chart::ErrorTrends => read!(self, source, |options| telemetry
                .error_trends(&window, Some(&options))),
            Chart::ErrorCategoryTrends => read!(self, source, |options| telemetry
                .error_category_trends(&window, Some(&options))),
            Chart::GroupedErrors => read!(self, source, |options| telemetry
                .grouped_errors(&window, Some(&options))),
            Chart::RescuedRetries => read!(self, source, |options| telemetry
                .rescued_retries(&window, Some(&options))),
            Chart::FeedbackTrend => read!(self, source, |options| telemetry
                .feedback_trend(&window, Some(&options))),
            Chart::FeedbackWeighted => read!(self, source, |options| telemetry
                .feedback_weighted(&window, Some(&options))),
            Chart::FeedbackScoreDistribution => read!(self, source, |options| telemetry
                .feedback_score_distribution(&window, Some(&options))),
            Chart::FeedbackModels => read!(self, source, |options| telemetry
                .feedback_models(&window, Some(&options))),
        }
    }

    async fn filter_boundaries(&self, slug: &str) -> Result<OValue, ReadError> {
        let window = self.window(slug)?;
        let telemetry = self.gateway.telemetry();
        read!(self, "telemetry.filterBoundaries", |options| telemetry
            .filter_boundaries(&window, Some(&options)))
    }

    async fn logs(&self, slug: &str, page: u32) -> Result<OValue, ReadError> {
        let mut logs = AIGatewayLogsOptions::new(self.window(slug)?);
        logs.page_size = Some(u64::from(LOG_PAGE_SIZE));
        logs.current_page = Some(u64::from(page));
        let telemetry = self.gateway.telemetry();
        read!(self, "telemetry.logs", |options| telemetry
            .logs(&logs, Some(&options)))
    }

    async fn configs(&self, workspace_id: &str) -> Result<OValue, ReadError> {
        let scope = AIGatewayWorkspaceScopedListOptions::new(workspace_id);
        read!(self, "configs.list", |options| self
            .gateway
            .configs()
            .list(&scope, Some(&options)))
    }

    async fn service_keys(&self, workspace_id: &str) -> Result<OValue, ReadError> {
        let scope = AIGatewayWorkspaceScopedListOptions::new(workspace_id);
        read!(self, "apiKeys.listService", |options| self
            .gateway
            .api_keys()
            .list_service(&scope, Some(&options)))
    }

    async fn user_keys(&self, workspace_id: &str) -> Result<OValue, ReadError> {
        let scope = AIGatewayWorkspaceScopedListOptions::new(workspace_id);
        read!(self, "apiKeys.listUser", |options| self
            .gateway
            .api_keys()
            .list_user(&scope, Some(&options)))
    }

    async fn organisation_info(&self) -> Result<OValue, ReadError> {
        read!(self, "organisations.getInfo", |options| self
            .gateway
            .organisations()
            .get_info(&self.tsg, Some(&options)))
    }

    async fn catalog(&self) -> Result<OValue, ReadError> {
        read!(self, "guardrails.getCatalog", |options| self
            .gateway
            .guardrails()
            .get_catalog(Some(&options)))
    }
}

/// `gateway report`. Any failure after the argument checks prints only
/// [`GENERATION_FAILED`](rc::GENERATION_FAILED) (exit 1); an interruption keeps its
/// context.
pub async fn run(invocation: &mut Invocation, plan: &GatewayReportPlan) -> Result<(), CliError> {
    let result = generate(invocation, plan).await;
    rc::conclude(invocation, result)
}

/// The report run; `Ok(exit code)`.
async fn generate(invocation: &mut Invocation, plan: &GatewayReportPlan) -> Result<i32, CliError> {
    let path = rc::check_destination(&plan.destination, ParentCheck::Checked)?;
    // The tenant's defaultOutput is ignored (TS); no upfront token (a token failure is a
    // failure of each source, GR§10).
    let (clients, _, tsg) = invocation
        .gateway_clients(None, None)
        .map_err(rc::before_report)?;
    invocation
        .output
        .status("Collecting AI Gateway statistics and current configuration (read-only)...");
    let reader = SdkReader {
        gateway: &clients.gateway,
        budget: SourceBudget::new(read_options),
        tsg,
        start_ms: plan.start_ms,
        end_ms: plan.end_ms,
    };
    let options = gateway::Options {
        title: &plan.title,
        max_pages: plan.max_pages,
        workspace: &plan.workspace,
        start_ms: plan.start_ms,
        end_ms: plan.end_ms,
        now: &rc::now_ms,
    };
    let collected = gateway::collect(&reader, &options)
        .await
        .map_err(|_| rc::no_report())?;
    let html = html::render(&collected, &html::GATEWAY);
    let verdict = Verdict {
        incomplete: collected.incomplete(),
        health_unknown: collected.health == Health::Unknown,
        strict: plan.strict,
    };
    rc::publish(invocation, path.as_deref(), &html, verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-02T00:00:00Z.
    const NOW: i64 = 1_790_899_200_000;

    #[test]
    fn windows_are_fixed_at_the_check_and_bounded() {
        assert_eq!(
            report_window(1, None, None, NOW).unwrap(),
            (NOW - 86_400_000, NOW)
        );
        assert_eq!(
            report_window(
                1,
                Some("2026-10-01T00:00:00.123456+0200"),
                Some("2026-10-02T00:00:00Z"),
                NOW
            )
            .unwrap(),
            (NOW - 86_400_000 - 7_200_000 + 123, NOW)
        );
        for (start, end) in [
            ("2026-10-02T00:00:00Z", "2026-10-02T00:00:00Z"),
            ("2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z"),
            ("2026-10-01T00:00:00", "2026-10-02T00:00:00Z"),
            ("2026-10-01t00:00:00z", "2026-10-02T00:00:00Z"),
            ("2026-02-30T00:00:00Z", "2026-10-02T00:00:00Z"),
            ("2026-10-01T24:00:00Z", "2026-10-02T00:00:00Z"),
            ("2026-10-01T00:00:00+24:00", "2026-10-02T00:00:00Z"),
        ] {
            assert!(
                report_window(1, Some(start), Some(end), NOW).is_err(),
                "{start} {end}"
            );
        }
        // D249: a window that leaves the years 0000–9999 is refused at the check.
        assert!(report_window(100_000_000, None, None, NOW).is_err());
        assert!(report_window(739_000, None, None, NOW).is_ok());
        assert_eq!(positive("01"), None);
        assert_eq!(positive("9007199254740993"), None);
        assert_eq!(positive("40"), Some(40));
    }

    #[test]
    fn default_names_name_the_gateway() {
        let name = default_name(std::time::UNIX_EPOCH);
        assert!(
            name.starts_with("airs-gateway-report-1970-01-01T00-00-00.000Z-"),
            "{name}"
        );
        assert!(
            name.ends_with(".html")
                && name.len() == "airs-gateway-report-1970-01-01T00-00-00.000Z-".len() + 13
        );
    }
}
