//! `supplychain report` (DESIGN §20.9; TypeScript `agentguard report`, renamed, D308): the
//! supplychain environment report's planning, reader and collection. The three sources
//! are read one after the other, each under its own 300 s budget with `with_retries(0)`,
//! no response defaults (choice 2) and the G63 re-read; the client fetches its token
//! lazily per source (a token failure is a failure of each source, TS). The destination
//! checks before the tenant (anything at the path, the last component, the parent, D214,
//! D226), the publishing (one new 0600 file, or stdout with `--output-file -`) and the exit
//! code are `report_command`'s; every failure after the checks prints only the report's
//! own line (D311). The HTML is the shared environment template with the supplychain
//! profile.

use super::Invocation;
use super::report_command::{self as rc, ParentCheck, ReportDestination, SourceBudget, Verdict};
use crate::clients::{SupplychainClients, WALK_BUDGET};
use crate::error::CliError;
use crate::output::Format;
use crate::report::supplychain::{
    self as collector, DEFAULT_MAX_PAGES, DEFAULT_TITLE, Metric, PAGE_SIZE, Page, Reader, RuleRow,
    ScanRow, Stats,
};
use crate::report::{Health, ReadError, html};
use crate::supplychain::count;
use crate::supplychain::scans::{self, Scan, ScanQuery};
use crate::tenant::config::js_trim;
use scm::airs::agentguard::models::{
    AgentGuardPageOptions, AgentGuardRule, AgentGuardScanStats,
    AgentGuardScanStatsUniqueSkillsScanned, AgentGuardStatsOptions,
    AgentGuardStatsOptionsTimePeriod, FiniteNumber, Nullable, Optional,
};
use std::path::PathBuf;

/// The report's only failure text (TS `AgentGuard report failed. …`, D311; no path, OS
/// error or server text).
pub const REPORT_FAILED: &str = "✗ Supply chain report failed. Check credentials and a writable, new output path. Existing files are never overwritten.";

/// The `--max-pages` text for every failure (TS's range text, D314, choice 8).
const MAX_PAGES_ERROR: &str = "--max-pages must be between 1 and 100";

/// A validated `supplychain report`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScReportPlan {
    pub destination: ReportDestination,
    pub title: String,
    pub max_pages: u32,
    pub strict: bool,
}

/// `airs-supplychain-report-<ISO time, ':' → '-'>-<8 hex>.html` (TS
/// `airs-agentguard-report-…`, D310).
pub fn default_name(now: std::time::SystemTime) -> String {
    format!(
        "airs-supplychain-report-{}-{}.html",
        crate::debug::iso_timestamp(now).replace(':', "-"),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )
}

/// The argument checks of `supplychain report` (§20.9, in this order, before the tenant):
/// `--debug` (D156), an explicit `--output` (D155), `--max-pages` (decimal digits, 1 to
/// 100), `--title` (1–240 UTF-16 units after JavaScript `trim()`), a blank `--output-file`.
pub fn plan(
    args: &crate::cli::ScReportArgs,
    explicit: Option<Format>,
    debug: bool,
) -> Result<ScReportPlan, CliError> {
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
    let max_pages = match args.max_pages.as_deref() {
        None => DEFAULT_MAX_PAGES,
        Some(value) => crate::supplychain::digits(value)
            .filter(|pages| (1..=100).contains(pages))
            .and_then(|pages| u32::try_from(pages).ok())
            .ok_or_else(|| CliError::usage(MAX_PAGES_ERROR))?,
    };
    let title = args
        .title
        .clone()
        .unwrap_or_else(|| DEFAULT_TITLE.to_owned());
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
    Ok(ScReportPlan {
        destination,
        title,
        max_pages,
        strict: args.strict,
    })
}

/// The report read options: `with_retries(0)` under one 300 s budget per source, no
/// response defaults (§20.3, choice 29).
fn read_options() -> scm::Result<scm::RequestOptions> {
    crate::supplychain::sdk_options(WALK_BUDGET)
}

/// What the collector reads of one scan (G71's tolerant scan, `None` for a `null`):
/// never its name, URL, fingerprint, device metadata, error text or evaluation details,
/// which the tolerant read does not even keep.
pub(crate) fn scan_row(scan: &Scan) -> ScanRow {
    ScanRow {
        uuid: scan.uuid.clone(),
        created_at: scan.created_at.clone(),
        artifact_type: scan.artifact_type.clone(),
        status: scan.status.clone(),
        eval_outcome: scan.eval_outcome.clone(),
        is_batch: scan.is_batch,
        children: scan.children,
    }
}

/// What the collector reads of one rule: its id and default state, never its text.
pub(crate) fn rule_row(rule: &AgentGuardRule) -> RuleRow {
    RuleRow {
        uuid: rule.uuid.clone(),
        default_state: Some(rule.default_state.clone()),
    }
}

fn metric(metric: &AgentGuardScanStatsUniqueSkillsScanned) -> Result<Metric, ReadError> {
    Ok(Metric {
        count: metric.count.as_f64().ok_or(ReadError::Failed)?,
        percent_change: match &metric.percent_change {
            Nullable::Value(change) => Some(change.as_f64().ok_or(ReadError::Failed)?),
            Nullable::Null => None,
        },
    })
}

/// What the collector reads of the statistics (`top_vulnerability` unused, TS).
pub(crate) fn stats_of(stats: &AgentGuardScanStats) -> Result<Stats, ReadError> {
    Ok(Stats {
        unique_skills_scanned: metric(&stats.unique_skills_scanned)?,
        total_vulnerabilities_found: metric(&stats.total_vulnerabilities_found)?,
    })
}

/// The SDK behind the collector.
struct SdkReader<'a> {
    clients: &'a SupplychainClients,
    budget: SourceBudget,
}

impl Reader for SdkReader<'_> {
    /// The G71 raw read and tolerant projection: an answer the projection refuses fails
    /// the page like any other failure (the generic note, no server text).
    async fn scans(&self, skip: u64, start: &str, end: &str) -> Result<Page<ScanRow>, ReadError> {
        let query = ScanQuery {
            skip,
            limit: PAGE_SIZE,
            start: Some(start),
            end: Some(end),
        };
        let clients = self.clients;
        let answer = self
            .budget
            .read_typed("Scans", async |options| {
                scans::send(clients, &query, &options).await
            })
            .await?;
        let page = scans::project(&answer).map_err(|_| ReadError::Failed)?;
        Ok(Page {
            rows: page.scans.iter().map(scan_row).collect(),
            // A non-negative safe integer (the projection's rule), so exact as a number.
            total: FiniteNumber::from(page.total).as_f64().unwrap_or(f64::NAN),
        })
    }

    async fn stats(&self) -> Result<Stats, ReadError> {
        let query = AgentGuardStatsOptions::builder()
            .time_period(Optional::Value(
                AgentGuardStatsOptionsTimePeriod::Model30DAYS,
            ))
            .build()
            .map_err(|_| ReadError::Failed)?;
        let client = &self.clients.agentguard;
        let stats = self
            .budget
            .read_typed("Statistics", async |options| {
                client.get_scan_stats(&query, Some(&options)).await
            })
            .await?;
        stats_of(&stats)
    }

    async fn rules(&self, skip: u64) -> Result<Page<RuleRow>, ReadError> {
        let query = AgentGuardPageOptions::builder()
            .skip(count(skip))
            .limit(count(u64::from(PAGE_SIZE)))
            .build()
            .map_err(|_| ReadError::Failed)?;
        let client = &self.clients.agentguard;
        let list = self
            .budget
            .read_typed("Rules", async |options| {
                client.list_rules(&query, Some(&options)).await
            })
            .await?;
        Ok(Page {
            rows: list.rules.iter().map(rule_row).collect(),
            total: list.pagination.total_items.as_f64().unwrap_or(f64::NAN),
        })
    }
}

/// `supplychain report`. Any failure after the argument checks prints only
/// [`REPORT_FAILED`] (exit 1); an interruption keeps its context.
pub async fn run(invocation: &mut Invocation, plan: &ScReportPlan) -> Result<(), CliError> {
    let result = generate(invocation, plan).await;
    rc::conclude_with(invocation, result, REPORT_FAILED)
}

/// The report run; `Ok(exit code)`.
async fn generate(invocation: &mut Invocation, plan: &ScReportPlan) -> Result<i32, CliError> {
    let path = rc::check_destination(&plan.destination, ParentCheck::Checked)?;
    // The tenant's defaultOutput is ignored (TS); no upfront token (a token failure is a
    // failure of each source, SC§9.3); no `Collecting …` line (choice 31).
    let context = invocation.load_tenant().map_err(rc::before_report)?;
    crate::tenant::config::require_management(&context.config, Some(context.name()))
        .map_err(rc::before_report)?;
    let clients = SupplychainClients::build(
        &context.config,
        &invocation.session,
        &invocation.secrets,
        invocation.debug.as_ref(),
    )
    .map_err(|error| rc::before_report(error.into()))?;
    let reader = SdkReader {
        clients: &clients,
        budget: SourceBudget::new(read_options),
    };
    let options = collector::Options {
        title: &plan.title,
        max_pages: plan.max_pages,
        now: &rc::now_ms,
    };
    let collected = collector::collect(&reader, &options)
        .await
        .map_err(|_| rc::no_report())?;
    let html = html::render(&collected, &html::SUPPLYCHAIN);
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
    use crate::cli::ScReportArgs;

    fn args(edit: impl FnOnce(&mut ScReportArgs)) -> ScReportArgs {
        let mut args = ScReportArgs::default();
        edit(&mut args);
        args
    }

    fn usage(result: Result<ScReportPlan, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    /// §20.9's checks in order (D155, D156, D314); TS `rejects invalid budget %s before
    /// I/O` (`0`, `-1`, `101`, `1.5`, `NaN`).
    #[test]
    fn the_checks_run_in_order() {
        let all = args(|a| {
            a.max_pages = Some("0".into());
            a.title = Some(" ".into());
            a.output_file = Some(" ".into());
        });
        assert_eq!(
            usage(plan(&all, Some(Format::Json), true)),
            "Disable --debug for environment reports to avoid persisting sensitive traffic content"
        );
        assert_eq!(
            usage(plan(&all, Some(Format::Json), false)),
            "The environment report is written as HTML; omit --output"
        );
        assert_eq!(usage(plan(&all, None, false)), MAX_PAGES_ERROR);
        for bad in [
            "0", "-1", "101", "1.5", "NaN", "abc", "", " 2", "0x2", "1e1",
        ] {
            let a = args(|a| a.max_pages = Some(bad.into()));
            assert_eq!(usage(plan(&a, None, false)), MAX_PAGES_ERROR, "{bad:?}");
        }
        for good in [("1", 1), ("100", 100), ("007", 7)] {
            let a = args(|a| a.max_pages = Some(good.0.into()));
            assert_eq!(plan(&a, None, false).unwrap().max_pages, good.1);
        }
        let a = args(|a| a.title = Some("\u{a0}\u{feff} ".into()));
        assert_eq!(
            usage(plan(&a, None, false)),
            "--title must contain 1–240 characters"
        );
        let a = args(|a| a.title = Some("x".repeat(241)));
        assert_eq!(
            usage(plan(&a, None, false)),
            "--title must contain 1–240 characters"
        );
        let a = args(|a| a.title = Some("😀".repeat(120)));
        assert_eq!(plan(&a, None, false).unwrap().title.chars().count(), 120);
        let a = args(|a| a.output_file = Some("\t".into()));
        assert_eq!(
            usage(plan(&a, None, false)),
            "--output-file cannot be empty"
        );
        let a = args(|a| a.output_file = Some("-".into()));
        let planned = plan(&a, None, false).unwrap();
        assert_eq!(planned.destination, ReportDestination::Stdout);
        assert_eq!(planned.title, DEFAULT_TITLE);
        assert_eq!(planned.max_pages, 40);
        assert!(!planned.strict);
    }

    /// D310: the default file names the supplychain report.
    #[test]
    fn default_names_name_the_supplychain_report() {
        let name = default_name(std::time::UNIX_EPOCH);
        let prefix = "airs-supplychain-report-1970-01-01T00-00-00.000Z-";
        assert!(name.starts_with(prefix), "{name}");
        assert!(name.ends_with(".html") && name.len() == prefix.len() + 13);
        let planned = plan(&ScReportArgs::default(), None, false).unwrap();
        match planned.destination {
            ReportDestination::File(path) => assert!(
                path.to_string_lossy()
                    .starts_with("airs-supplychain-report-")
            ),
            ReportDestination::Stdout => panic!("a file by default"),
        }
    }

    /// The reader maps only aggregate members: no name, URL, fingerprint, device metadata,
    /// error text or rule text reaches the collector.
    #[test]
    fn the_reader_keeps_only_aggregate_members() {
        let scan = scans::scan(&serde_json::json!({
            "uuid": "11111111-1111-4111-8111-000000000101",
            "tsg_id": "100",
            "created_at": "2026-10-19T01:57:59.751Z",
            "updated_at": "2026-10-19T01:57:59.751Z",
            "name": "PRIVATE-NAME",
            "git_url": "https://PRIVATE-USER:PRIVATE-TOKEN@git.example.invalid/r.git",
            "artifact_type": "SKILL",
            "status": "COMPLETED",
            "error_message": "PRIVATE-ERROR",
            "summary": {"vulnerability_count": 2, "attack_chain_count": 1},
            "eval_outcome": null,
            "eval_summary": null,
            "eval_details": null,
            "duration_seconds": 1,
            "fingerprint": "PRIVATE-FINGERPRINT",
            "scanner_version": null,
            "device_metadata": {"token": "PRIVATE-DEVICE"},
            "parent_uuid": null,
            "is_batch": false,
            "child_scan_uuids": ["a", "b"],
            "batch_summary": null,
            "zz_added": "PRIVATE-PASSTHROUGH"
        }))
        .unwrap();
        let row = scan_row(&scan);
        assert!(!format!("{row:?}").contains("PRIVATE"));
        assert_eq!(
            row,
            ScanRow {
                uuid: "11111111-1111-4111-8111-000000000101".into(),
                created_at: Some("2026-10-19T01:57:59.751Z".into()),
                artifact_type: Some("SKILL".into()),
                status: Some("COMPLETED".into()),
                eval_outcome: None,
                is_batch: Some(false),
                children: Some(2),
            }
        );
        // G71: the members the service sends as `null` read as unknown, never as a value.
        let nulls = scans::scan(&serde_json::json!({
            "uuid": "11111111-1111-4111-8111-000000000113", "created_at": null, "name": null,
            "artifact_type": null, "status": null, "fingerprint": null, "eval_outcome": null,
            "is_batch": null, "child_scan_uuids": null, "device_metadata": null
        }))
        .unwrap();
        assert_eq!(
            scan_row(&nulls),
            ScanRow {
                uuid: "11111111-1111-4111-8111-000000000113".into(),
                created_at: None,
                artifact_type: None,
                status: None,
                eval_outcome: None,
                is_batch: None,
                children: None,
            }
        );
        let rule: AgentGuardRule = serde_json::from_value(serde_json::json!({
            "uuid": "r", "name": "PRIVATE-RULE", "vulnerability_types": ["SECRET_EXPOSURE"],
            "default_state": "BLOCKING", "description": "PRIVATE-D", "remediation": "PRIVATE-R"
        }))
        .unwrap();
        assert_eq!(
            rule_row(&rule),
            RuleRow {
                uuid: "r".into(),
                default_state: Some("BLOCKING".into())
            }
        );
        let stats: AgentGuardScanStats = serde_json::from_value(serde_json::json!({
            "unique_skills_scanned": {"count": 4, "percent_change": 12.5},
            "total_vulnerabilities_found": {"count": 7, "percent_change": null},
            "top_vulnerability": {"vulnerability_type": "PRIVATE-TYPE", "finding_count": 3}
        }))
        .unwrap();
        let read = stats_of(&stats).unwrap();
        assert_eq!(
            (read.unique_skills_scanned, read.total_vulnerabilities_found),
            (
                Metric {
                    count: 4.0,
                    percent_change: Some(12.5)
                },
                Metric {
                    count: 7.0,
                    percent_change: None
                }
            )
        );
    }
}
