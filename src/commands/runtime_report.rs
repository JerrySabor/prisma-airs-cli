//! `runtime report` (DESIGN §18.14): the runtime environment report's reader and
//! collection. The seven sources are read one after the other, each under its own budget
//! with `with_retries(0)` and the G7 re-read. The destination checks before the tenant
//! (anything at the path, and its parent directory, D214), the publishing (one new 0600
//! file, or stdout with `--output-file -`), the exit code and the single failure line are
//! `report_command`'s, shared with `redteam report`.

use super::Invocation;
use super::report_command::{self as rc, ParentCheck, ReportDestination, SourceBudget, Verdict};
use crate::clients::{ManagementClients, Planes, WALK_BUDGET};
use crate::error::CliError;
use crate::json::OValue;
use crate::report::runtime::{self, PAGE_SIZE, Reader, SESSION_PAGE};
use crate::report::{Health, ReadError};
use scm::airs::management::{
    DashboardApplicationsOverviewQuery, DashboardClient, DashboardSessionsOverviewQuery,
    DashboardTimeRangeQuery, PaginationOptions,
};

/// A validated `runtime report`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeReportPlan {
    pub destination: ReportDestination,
    pub title: String,
    pub max_pages: u32,
    pub strict: bool,
}

/// `airs-runtime-report-<ISO time, ':' → '-'>-<8 hex>.html` (TS name).
pub fn default_name(now: std::time::SystemTime) -> String {
    format!(
        "airs-runtime-report-{}-{}.html",
        crate::debug::iso_timestamp(now).replace(':', "-"),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )
}

/// The SDK behind the collector: every read with `with_retries(0)` (TS `numRetries: 0`)
/// and no response defaults (G27) under one walk budget per source, and one re-read after
/// an HTTP 401 or 403 rejection (G7).
struct SdkReader<'a> {
    clients: &'a ManagementClients,
    dashboard: DashboardClient,
    budget: SourceBudget,
}

fn daily() -> DashboardTimeRangeQuery {
    let mut query = DashboardTimeRangeQuery::default();
    query.time_interval = Some(1);
    query.time_unit = Some("day".to_owned());
    query
}

impl Reader for SdkReader<'_> {
    async fn applications(&self, offset: u64) -> Result<OValue, ReadError> {
        let mut query = DashboardApplicationsOverviewQuery::default();
        query.time_interval = Some(1);
        query.time_unit = Some("day".to_owned());
        query.limit = Some(PAGE_SIZE);
        query.offset = Some(offset);
        self.budget
            .read("applications", async |options| {
                self.dashboard
                    .applications_overview(&query, Some(&options))
                    .await
            })
            .await
    }
    async fn profiles(&self, offset: u64) -> Result<OValue, ReadError> {
        let mut page = PaginationOptions::default();
        page.offset = offset;
        page.limit = 100;
        page.latest = Some(true);
        self.budget
            .read("profiles", async |options| {
                self.clients
                    .management
                    .profiles()
                    .list(page, Some(&options))
                    .await
            })
            .await
    }
    async fn customer_apps(&self, offset: u64) -> Result<OValue, ReadError> {
        let mut page = PaginationOptions::default();
        page.offset = offset;
        page.limit = 100;
        self.budget
            .read("customer apps", async |options| {
                self.clients
                    .management
                    .customer_apps()
                    .list(page, Some(&options))
                    .await
            })
            .await
    }
    async fn sessions(&self, offset: u64) -> Result<OValue, ReadError> {
        let mut query = DashboardSessionsOverviewQuery::default();
        query.time_interval = Some(1);
        query.time_unit = Some("day".to_owned());
        query.limit = Some(SESSION_PAGE);
        query.offset = Some(offset);
        self.budget
            .read("sessions", async |options| {
                self.dashboard
                    .sessions_overview(&query, Some(&options))
                    .await
            })
            .await
    }
    async fn sessions_chart(&self) -> Result<OValue, ReadError> {
        let query = daily();
        self.budget
            .read("chart", async |options| {
                self.dashboard.sessions_chart(&query, Some(&options)).await
            })
            .await
    }
    async fn top_applications(&self) -> Result<OValue, ReadError> {
        let query = daily();
        self.budget
            .read("top", async |options| {
                self.dashboard
                    .top_applications_violations(&query, Some(&options))
                    .await
            })
            .await
    }
    async fn violations_trend(&self) -> Result<OValue, ReadError> {
        let query = daily();
        self.budget
            .read("trend", async |options| {
                self.dashboard
                    .applications_violations_trend(&query, Some(&options))
                    .await
            })
            .await
    }
}

/// `runtime report`. Any failure after the argument checks prints only
/// [`GENERATION_FAILED`](rc::GENERATION_FAILED) (exit 1); an interruption keeps its
/// context.
pub async fn run(invocation: &mut Invocation, plan: &RuntimeReportPlan) -> Result<(), CliError> {
    let result = generate(invocation, plan).await;
    rc::conclude(invocation, result)
}

/// The report run; `Ok(exit code)`.
async fn generate(invocation: &mut Invocation, plan: &RuntimeReportPlan) -> Result<i32, CliError> {
    let path = rc::check_destination(&plan.destination, ParentCheck::Checked)?;
    let connected = invocation
        .connect_runtime(Planes {
            dashboard: true,
            dlp: false,
        })
        .map_err(rc::before_report)?;
    invocation
        .output
        .status("Collecting daily runtime activity and current configuration (read-only)...");
    let reader = SdkReader {
        dashboard: connected.clients.management.dashboard(),
        clients: &connected.clients,
        budget: SourceBudget::new(|| crate::runtime::dashboard_read_options(WALK_BUDGET)),
    };
    let options = runtime::Options {
        title: &plan.title,
        max_pages: plan.max_pages,
        now: &rc::now_ms,
    };
    let collected = runtime::collect_report(&reader, &options)
        .await
        .map_err(|_| rc::no_report())?;
    let html = crate::report::runtime_html::render(&collected);
    let verdict = Verdict {
        incomplete: collected.incomplete(),
        health_unknown: collected.health == Health::Unknown,
        strict: plan.strict,
    };
    rc::publish(invocation, path.as_deref(), &html, verdict)
}
