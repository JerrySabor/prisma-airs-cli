//! `redteam report|dashboard [jobId]` (DESIGN §15.16, §15.17): the report of one scan job
//! in pretty, table or json, and the self-contained HTML environment report (its reader
//! and collector; the destination, publishing and exit stages are `report_command`'s).

use super::Invocation;
use super::redteam::{read, value};
use super::report_command::{self as rc, ParentCheck, ReportDestination, SourceBudget, Verdict};
use crate::clients::WALK_BUDGET;
use crate::error::CliError;
use crate::json::OValue;
use crate::output::Format;
use crate::redteam::views;
use crate::report::{self, ReadError};
use scm::airs::red_team::{
    AdapterListOptions, AttackListOptions, CustomAttacksReportListOptions, RedTeamClient,
    RedTeamScanListOptions, TargetListOptions,
};

// ---------------------------------------------------------------------------
// One scan job (§15.16)
// ---------------------------------------------------------------------------

/// The `pagination.total_items` of a list answer.
fn total_items(answer: &OValue) -> Option<OValue> {
    answer
        .get("pagination")
        .and_then(|pagination| pagination.get("total_items"))
        .filter(|total| views::present(Some(total)))
        .cloned()
}

/// `redteam report <jobId>`: the job, then the report of its type and, with `--attacks`,
/// its attack list (static and custom jobs).
pub async fn job_report(
    invocation: &mut Invocation,
    job_id: &str,
    attacks: bool,
    severity: Option<&str>,
    limit: u32,
    format: Format,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let client = &connected.client;
    let answer = read(invocation, client.scans().get(job_id, None)).await?;
    let mut job = views::job(&value(&answer)?);
    views::withhold(&mut job, &invocation.secrets);
    let kind = views::text(&job, "jobType").unwrap_or_default().to_owned();
    let (mut report, mut list) = match kind.as_str() {
        "CUSTOM" => {
            let answer = read(
                invocation,
                client.custom_attack_reports().get_report(job_id, None),
            )
            .await?;
            let report = views::custom_report(&value(&answer)?);
            let list = if attacks {
                let mut options = CustomAttacksReportListOptions::default();
                options.limit = Some(limit);
                let answer = read(
                    invocation,
                    client
                        .custom_attack_reports()
                        .list_custom_attacks(job_id, &options, None),
                )
                .await?;
                let answer = value(&answer)?;
                Some((
                    attack_rows(&answer, views::custom_attack),
                    total_items(&answer),
                ))
            } else {
                None
            };
            (report, list)
        }
        "DYNAMIC" => {
            let answer = read(
                invocation,
                client.reports().get_dynamic_report(job_id, None),
            )
            .await?;
            (views::dynamic_report(&value(&answer)?), None)
        }
        _ => {
            let answer = read(invocation, client.reports().get_static_report(job_id, None)).await?;
            let report = views::static_report(&value(&answer)?);
            let list = if attacks {
                let mut options = AttackListOptions::default();
                options.limit = Some(limit);
                options.severity = severity.map(str::to_owned);
                let answer = read(
                    invocation,
                    client.reports().list_attacks(job_id, &options, None),
                )
                .await?;
                let answer = value(&answer)?;
                Some((attack_rows(&answer, views::attack), total_items(&answer)))
            } else {
                None
            };
            (report, list)
        }
    };
    views::withhold(&mut report, &invocation.secrets);
    if let Some((rows, _)) = &mut list {
        for row in rows.iter_mut() {
            views::withhold(row, &invocation.secrets);
        }
    }
    let out = &mut invocation.output;
    match format {
        Format::Json | Format::Table => {
            let mut doc = vec![
                ("job".to_owned(), job.clone()),
                ("report".to_owned(), report.clone()),
            ];
            if let Some((rows, total)) = &list {
                let mut attacks = vec![("items".to_owned(), OValue::Array(rows.clone()))];
                if let Some(total) = total {
                    attacks.push(("totalItems".to_owned(), total.clone()));
                }
                doc.push(("attacks".to_owned(), OValue::Object(attacks)));
            }
            let doc = OValue::Object(doc);
            if format == Format::Json {
                out.json(&doc)
            } else {
                views::detail_table(out, &doc);
                Ok(())
            }
        }
        Format::Pretty => {
            views::banner(out);
            views::scan_status_layout(out, &job);
            match kind.as_str() {
                "CUSTOM" => {
                    views::custom_report_layout(out, &report);
                    if let Some((rows, _)) = &list {
                        views::custom_attack_list_layout(out, rows);
                    }
                }
                "DYNAMIC" => views::dynamic_report_layout(out, &report),
                _ => {
                    views::static_report_layout(out, &report);
                    if let Some((rows, total)) = &list {
                        let total = total.as_ref().and_then(|total| match total {
                            OValue::Number(number) => number.as_f64(),
                            _ => None,
                        });
                        let footnote = views::attack_footnote(severity, total, &report);
                        views::attack_list_layout(out, rows, footnote.as_deref());
                    }
                }
            }
            Ok(())
        }
    }
}

/// The normalised `data` rows of a list answer.
fn attack_rows(answer: &OValue, normalise: fn(&OValue) -> OValue) -> Vec<OValue> {
    answer
        .get("data")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .map(normalise)
        .collect()
}

// ---------------------------------------------------------------------------
// The environment report (§15.17)
// ---------------------------------------------------------------------------

/// A validated environment report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvReportPlan {
    pub destination: ReportDestination,
    pub title: String,
    pub max_pages: u32,
    pub strict: bool,
}

/// `airs-redteam-report-<ISO time, ':' → '-'>-<8 hex>.html` (TS name).
pub fn default_name(now: std::time::SystemTime) -> String {
    format!(
        "airs-redteam-report-{}-{}.html",
        crate::debug::iso_timestamp(now).replace(':', "-"),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )
}

/// The SDK behind the collector: every read with `with_retries(0)` (TS `numRetries: 0`)
/// under one walk budget per source, and one re-read after an HTTP 401 or 403 rejection
/// (G7: TypeScript's free token replay).
struct SdkReader<'a> {
    client: &'a RedTeamClient,
    budget: SourceBudget,
}

/// The red team read options: `with_retries(0)` under one `WALK_BUDGET` (the response
/// defaults stay on, §15.17).
fn read_options() -> scm::Result<scm::RequestOptions> {
    scm::RequestOptions::with_timeout(WALK_BUDGET).and_then(|options| options.with_retries(0))
}

impl report::Reader for SdkReader<'_> {
    async fn overview(&self) -> Result<OValue, ReadError> {
        self.budget
            .read("overview", async |options| {
                self.client.get_dashboard_overview(Some(&options)).await
            })
            .await
    }
    async fn statistics(&self) -> Result<OValue, ReadError> {
        self.budget
            .read("statistics", async |options| {
                self.client
                    .get_scan_statistics(&Default::default(), Some(&options))
                    .await
            })
            .await
    }
    async fn targets(&self, skip: u64) -> Result<OValue, ReadError> {
        let mut page = TargetListOptions::default();
        page.skip = Some(skip);
        page.limit = Some(report::PAGE_SIZE);
        self.budget
            .read("targets", async |options| {
                self.client.targets().list(&page, Some(&options)).await
            })
            .await
    }
    async fn quota(&self) -> Result<OValue, ReadError> {
        self.budget
            .read("quota", async |options| {
                self.client.get_quota_summary(Some(&options)).await
            })
            .await
    }
    async fn scans(&self, skip: u64) -> Result<OValue, ReadError> {
        let mut page = RedTeamScanListOptions::default();
        page.skip = Some(skip);
        page.limit = Some(report::PAGE_SIZE);
        self.budget
            .read("scans", async |options| {
                self.client.scans().list(&page, Some(&options)).await
            })
            .await
    }
    async fn channel_stats(&self) -> Result<OValue, ReadError> {
        self.budget
            .read("broker", async |options| {
                self.client
                    .network_broker()
                    .get_channel_stats(Some(&options))
                    .await
            })
            .await
    }
    async fn adapters(&self, skip: u64) -> Result<OValue, ReadError> {
        let mut page = AdapterListOptions::default();
        page.skip = Some(skip);
        page.limit = Some(report::PAGE_SIZE);
        page.include_target_count = Some(true);
        self.budget
            .read("adapters", async |options| {
                self.client.adapters().list(&page, Some(&options)).await
            })
            .await
    }
}

/// `redteam report` without a job id. Any failure after the argument checks prints only
/// [`GENERATION_FAILED`](super::report_command::GENERATION_FAILED) (exit 1); an
/// interruption keeps its context.
pub async fn environment_report(
    invocation: &mut Invocation,
    plan: &EnvReportPlan,
) -> Result<(), CliError> {
    let result = generate(invocation, plan).await;
    rc::conclude(invocation, result)
}

/// The report run; `Ok(exit code)`.
async fn generate(invocation: &mut Invocation, plan: &EnvReportPlan) -> Result<i32, CliError> {
    let path = rc::check_destination(&plan.destination, ParentCheck::AtWrite)?;
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(rc::before_report)?;
    invocation
        .output
        .status("Collecting Red Team statistics and current configuration (read-only)...");
    let reader = SdkReader {
        client: prepared.client(),
        budget: SourceBudget::new(read_options),
    };
    let options = report::Options {
        title: &plan.title,
        max_pages: plan.max_pages,
        now: &rc::now_ms,
    };
    let collected = report::collect(&reader, &options)
        .await
        .map_err(|_| rc::no_report())?;
    let html = report::html::render(&collected, &report::html::RED_TEAM);
    let verdict = Verdict {
        incomplete: collected.incomplete(),
        health_unknown: collected.health == report::Health::Unknown,
        strict: plan.strict,
    };
    rc::publish(invocation, path.as_deref(), &html, verdict)
}
