//! `supplychain` planning and dispatch (DESIGN §20; TypeScript `agentguard`, renamed with no
//! alias, D308). Planning runs every argument check of §20.3 and §20.9 before the tenant is
//! read (D314); dispatch loads the tenant (its errors keep their own messages, D316), builds
//! the AgentGuard client from the tenant's `supplychainDataEndpoint` and
//! `supplychainMgmtEndpoint`, fetches the token, and runs one of the four reads
//! (§20.5–§20.8); `report` is `supplychain_report` (§20.9). Every failure after the client
//! is built prints TypeScript's request failure line (choice 5), the size line (D320), for a
//! short finding list D319's line, or, for a scan page G71's tolerant read refuses, D325's
//! contract line (§20.16). The scan list is read raw (G71); the other reads are typed.

use super::{Invocation, Plan};
use crate::cli::{
    ScListFlags, ScRulesCommand, ScScansCommand, SupplychainCommand, SupplychainGroup,
};
use crate::clients::{SINGLE_REQUEST_BUDGET, SupplychainClients, WALK_BUDGET, reread};
use crate::debug::DebugPolicy;
use crate::error::{CliError, InterruptContext};
use crate::json::{OValue, page_value};
use crate::output::{self, Format};
use crate::secrets::withhold;
use crate::supplychain::scans::ScanQuery;
use crate::supplychain::{self as sc, Kind, ListPage, Paging, ScanWindow, count, member, views};
use crate::walk::total_of;
use scm::airs::agentguard::models::{
    AgentGuardPageOptions, AgentGuardStatsOptions, AgentGuardStatsOptionsTimePeriod, Optional,
};

/// A validated `supplychain` invocation (§20.2); `format` is the explicit `--output`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScPlan {
    /// `scans list|ls` (§20.5).
    Scans {
        paging: Paging,
        window: ScanWindow,
        format: Option<Format>,
    },
    /// `scans vulnerabilities <scanUuid>` (§20.6).
    Vulnerabilities {
        scan: String,
        include_content: bool,
        format: Option<Format>,
    },
    /// `stats` (§20.7).
    Stats { format: Option<Format> },
    /// `rules list|ls` (§20.8).
    Rules {
        paging: Paging,
        format: Option<Format>,
    },
    /// `report` (§20.9).
    Report(Box<super::supplychain_report::ScReportPlan>),
}

impl ScPlan {
    /// What an interruption reports (D323): the reads write no data; the report writes no
    /// report until it is saved (`report_command::publish` then names it).
    pub fn interrupt_context(&self) -> InterruptContext {
        match self {
            Self::Report(_) => {
                InterruptContext::Context(super::report_command::NO_REPORT.to_owned())
            }
            _ => InterruptContext::NoDataWritten,
        }
    }

    /// The `--debug` policy (§2.9, D64): the reads log status and headers only; the report
    /// refuses `--debug` during planning (D156).
    pub fn debug_policy(&self) -> DebugPolicy {
        match self {
            Self::Report(_) => DebugPolicy::Refused,
            _ => DebugPolicy::Log,
        }
    }
}

fn paging(flags: &ScListFlags) -> Result<Paging, CliError> {
    sc::paging(
        flags.limit.as_deref(),
        flags.offset.as_deref(),
        flags.all,
        flags.max.as_deref(),
    )
}

/// Plan a `supplychain` command line; `--output` and `--tenant` were validated already
/// (§20.3 "Validation order").
pub fn plan(
    group: &SupplychainGroup,
    explicit: Option<&str>,
    debug: bool,
) -> Result<Plan, CliError> {
    let format = output::validate_explicit(explicit)?;
    let Some(command) = &group.command else {
        return Ok(Plan::GroupHelp(&["supplychain"]));
    };
    let plan = match command {
        SupplychainCommand::Report(args) => ScPlan::Report(Box::new(
            super::supplychain_report::plan(args, format, debug)?,
        )),
        SupplychainCommand::Scans(scans) => match &scans.command {
            None => return Ok(Plan::GroupHelp(&["supplychain", "scans"])),
            Some(ScScansCommand::List(args)) => {
                let paging = paging(&args.paging)?;
                let window = sc::window(args.start.as_deref(), args.end.as_deref())?;
                ScPlan::Scans {
                    paging,
                    window,
                    format,
                }
            }
            Some(ScScansCommand::Vulnerabilities(args)) => ScPlan::Vulnerabilities {
                scan: sc::scan_uuid(&args.scan_uuid)?,
                include_content: args.include_content,
                format,
            },
        },
        SupplychainCommand::Stats(args) => {
            sc::time_period(args.time_period.as_deref())?;
            ScPlan::Stats { format }
        }
        SupplychainCommand::Rules(rules) => match &rules.command {
            None => return Ok(Plan::GroupHelp(&["supplychain", "rules"])),
            Some(ScRulesCommand::List(flags)) => ScPlan::Rules {
                paging: paging(flags)?,
                format,
            },
        },
    };
    Ok(Plan::Supplychain(Box::new(plan)))
}

/// Run a validated `supplychain` plan.
pub async fn dispatch(invocation: &mut Invocation, plan: ScPlan) -> Result<(), CliError> {
    match plan {
        ScPlan::Scans {
            paging,
            window,
            format,
        } => scans(invocation, &paging, &window, format).await,
        ScPlan::Vulnerabilities {
            scan,
            include_content,
            format,
        } => vulnerabilities(invocation, &scan, include_content, format).await,
        ScPlan::Stats { format } => stats(invocation, format).await,
        ScPlan::Rules { paging, format } => rules(invocation, &paging, format).await,
        ScPlan::Report(plan) => super::supplychain_report::run(invocation, &plan).await,
    }
}

impl Invocation {
    /// Prepare a supplychain read (§20.3): the tenant (§3.4, §3.7), the format (the explicit
    /// `--output`, else the tenant's `defaultOutput`, else `pretty`), the management
    /// credentials (§3.5), the endpoints and the client (their messages, D316), then the
    /// token under `options`; a token failure prints the request failure line with the
    /// token answer's status (choice 4).
    pub async fn connect_supplychain(
        &mut self,
        explicit: Option<Format>,
        options: &scm::RequestOptions,
    ) -> Result<(SupplychainClients, Format), CliError> {
        let context = self.load_tenant()?;
        let format = output::resolve_tenant_default(explicit, context.config.default_output());
        crate::tenant::config::require_management(&context.config, Some(context.name()))?;
        let clients = SupplychainClients::build(
            &context.config,
            &self.session,
            &self.secrets,
            self.debug.as_ref(),
        )?;
        if let Err(error) = clients.authenticate(Some(options)).await {
            return Err(sc::failure(&mut self.output, &error));
        }
        Ok((clients, format))
    }
}

/// The token's options and the first read's (§20.3): a single request has its own 60 s
/// for the token and for the read, built just before each is sent; a walk shares one
/// 300 s budget between the token and every page.
async fn connect(
    invocation: &mut Invocation,
    explicit: Option<Format>,
    walk: bool,
) -> Result<(SupplychainClients, Format, scm::RequestOptions), CliError> {
    let budget = if walk {
        WALK_BUDGET
    } else {
        SINGLE_REQUEST_BUDGET
    };
    let token = sc::options(budget)?;
    let (clients, format) = invocation.connect_supplychain(explicit, &token).await?;
    let options = if walk { token } else { sc::options(budget)? };
    Ok((clients, format, options))
}

/// TS `{skip, limit, start_time, end_time, isBackgroundRefresh: false}` (§20.5): the
/// bounds only when given, sent as typed.
fn scan_query(skip: u64, limit: u32, window: &ScanWindow) -> ScanQuery<'_> {
    ScanQuery {
        skip,
        limit,
        start: window.start.as_deref(),
        end: window.end.as_deref(),
    }
}

/// `supplychain scans list|ls` (§20.5): the walk of §20.4 over the 9-key projection, each
/// page read raw and through the tolerant projection (G71): a scan with `null` members
/// prints them as `null`; an answer the projection refuses is the contract line (D325).
async fn scans(
    invocation: &mut Invocation,
    paging: &Paging,
    window: &ScanWindow,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (clients, format, options) = connect(invocation, explicit, paging.all).await?;
    let listed = sc::inventory(Kind::Scans, paging, |skip, limit| {
        let clients = &clients;
        let options = &options;
        async move {
            let query = scan_query(skip, limit, window);
            let answer = reread(|| sc::scans::send(clients, &query, options)).await?;
            let page = sc::scans::project(&answer)?;
            Ok(ListPage {
                rows: page.scans.iter().map(views::scan).collect(),
                total: Some(page.total),
            })
        }
    })
    .await;
    let listed = listed.map_err(|failure| sc::read_failure(&mut invocation.output, &failure))?;
    let next = listed.pagination.next_offset;
    let mut document = OValue::Object(vec![
        member("pagination", listed.pagination.value()),
        member("scans", OValue::Array(listed.rows)),
    ]);
    withhold(&mut document, &invocation.secrets);
    views::render_records(&mut invocation.output, format, &document, "scans", next)
}

/// `supplychain scans vulnerabilities <scanUuid>` (§20.6): one unpaged read (G61); the
/// 4-key projection, or each finding whole with `--include-content` (stdout only, D321);
/// a `total_items` above the rows prints the rows and fails (D319).
async fn vulnerabilities(
    invocation: &mut Invocation,
    scan: &str,
    include_content: bool,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (clients, format, options) = connect(invocation, explicit, false).await?;
    let client = &clients.agentguard;
    let read = reread(|| client.list_scan_vulnerabilities(scan, Some(&options))).await;
    let failed = |invocation: &mut Invocation, error: scm::Error| {
        sc::failure(&mut invocation.output, &error)
    };
    let list = match read {
        Ok(list) => list,
        Err(error) => return Err(failed(invocation, error)),
    };
    let rows: scm::Result<Vec<OValue>> = if include_content {
        list.vulnerabilities.iter().map(page_value).collect()
    } else {
        Ok(list.vulnerabilities.iter().map(views::finding).collect())
    };
    let (rows, pagination) = match rows.and_then(|rows| Ok((rows, page_value(&list.pagination)?))) {
        Ok(parts) => parts,
        Err(error) => return Err(failed(invocation, error)),
    };
    let returned = rows.len();
    let mut document = OValue::Object(vec![
        member("pagination", pagination),
        member("vulnerabilities", OValue::Array(rows)),
        member("content_included", OValue::Bool(include_content)),
    ]);
    withhold(&mut document, &invocation.secrets);
    views::render_records(
        &mut invocation.output,
        format,
        &document,
        "vulnerabilities",
        None,
    )?;
    if include_content {
        invocation.output.status(views::CONTENT_NOTICE);
    }
    let reported = total_of(list.pagination.total_items.as_f64());
    if let Some(reported) = reported
        && reported > u64::try_from(returned).unwrap_or(u64::MAX)
    {
        // D319: the rows are printed, then the failure (as §18.13's session cap); the line
        // follows only rows that were written (a signal or a failed write is reported
        // instead, choice 78).
        invocation.output.commit_data()?;
        sc::fail_line(
            &mut invocation.output,
            &sc::incomplete_findings_text(returned, reported, scan),
        );
        return Err(CliError::Reported(crate::error::EXIT_OPERATIONAL));
    }
    Ok(())
}

/// `supplychain stats` (§20.7): `time_period=30_DAYS` always (G70); the model whole, the
/// field table in pretty and table (D318).
async fn stats(invocation: &mut Invocation, explicit: Option<Format>) -> Result<(), CliError> {
    let (clients, format, options) = connect(invocation, explicit, false).await?;
    let client = &clients.agentguard;
    let query = AgentGuardStatsOptions::builder()
        .time_period(Optional::Value(
            AgentGuardStatsOptionsTimePeriod::Model30DAYS,
        ))
        .build();
    let read = match query {
        Ok(query) => reread(|| client.get_scan_stats(&query, Some(&options)))
            .await
            .and_then(|stats| page_value(&stats)),
        Err(error) => Err(error),
    };
    let mut document = match read {
        Ok(document) => document,
        Err(error) => {
            return Err(sc::failure(&mut invocation.output, &error));
        }
    };
    withhold(&mut document, &invocation.secrets);
    views::render_fields(&mut invocation.output, format, &document)
}

/// `supplychain rules list|ls` (§20.8): the walk of §20.4 without a total (G62), each rule
/// whole.
async fn rules(
    invocation: &mut Invocation,
    paging: &Paging,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (clients, format, options) = connect(invocation, explicit, paging.all).await?;
    let listed = sc::inventory(Kind::Rules, paging, |skip, limit| {
        let client = &clients.agentguard;
        let options = &options;
        async move {
            let query = AgentGuardPageOptions::builder()
                .skip(count(skip))
                .limit(count(u64::from(limit)))
                .build()?;
            let page = reread(|| client.list_rules(&query, Some(options))).await?;
            let rows = page
                .rules
                .iter()
                .map(page_value)
                .collect::<scm::Result<Vec<OValue>>>()?;
            Ok(ListPage { rows, total: None })
        }
    })
    .await;
    let listed = listed.map_err(|failure| sc::read_failure(&mut invocation.output, &failure))?;
    let next = listed.pagination.next_offset;
    let mut document = OValue::Object(vec![
        member("pagination", listed.pagination.value()),
        member("rules", OValue::Array(listed.rows)),
    ]);
    withhold(&mut document, &invocation.secrets);
    views::render_records(&mut invocation.output, format, &document, "rules", next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::FromArgMatches;

    fn plan_of(args: &[&str]) -> Result<Plan, CliError> {
        let mut full = vec!["airs"];
        full.extend_from_slice(args);
        let matches = crate::cli::command().try_get_matches_from(full).unwrap();
        super::super::plan(&Cli::from_arg_matches(&matches).unwrap())
    }

    fn sc_plan(args: &[&str]) -> ScPlan {
        match plan_of(args) {
            Ok(Plan::Supplychain(plan)) => *plan,
            Ok(_) => panic!("not a supplychain plan"),
            Err(error) => panic!("{error:?}"),
        }
    }

    fn usage(args: &[&str]) -> String {
        match plan_of(args) {
            Err(CliError::Usage(message)) => message,
            Err(other) => panic!("expected a usage error, got {other:?}"),
            Ok(_) => panic!("expected a usage error"),
        }
    }

    /// §20.3 "Validation order": `--output`, then `--tenant`'s name, then the command's
    /// checks in their order; every one before the tenant (D314).
    #[test]
    fn planning_checks_everything_in_order() {
        assert_eq!(
            usage(&[
                "supplychain",
                "scans",
                "list",
                "--output",
                "yaml",
                "--limit",
                "0"
            ]),
            "Invalid output format 'yaml'. Expected: pretty, table, json"
        );
        assert_eq!(
            usage(&[
                "--tenant",
                "../x",
                "supplychain",
                "stats",
                "--time-period",
                "week"
            ]),
            crate::tenant::NAME_RULE,
            "the tenant name before the command's checks"
        );
        assert_eq!(
            usage(&[
                "supplychain",
                "scans",
                "list",
                "--start",
                "bad",
                "--limit",
                "0"
            ]),
            "--limit must be a positive integer"
        );
        assert_eq!(
            usage(&[
                "supplychain",
                "scans",
                "list",
                "--max",
                "x",
                "--start",
                "bad"
            ]),
            "--max must be a safe nonnegative integer"
        );
        assert_eq!(
            sc_plan(&[
                "supplychain",
                "scans",
                "ls",
                "--all",
                "--offset",
                "3",
                "--output",
                "table"
            ]),
            ScPlan::Scans {
                paging: Paging {
                    limit: 10,
                    offset: 3,
                    all: true,
                    max: 10_000
                },
                window: ScanWindow::default(),
                format: Some(Format::Table),
            }
        );
        let id = "11111111-1111-4111-8111-00000000010A";
        assert_eq!(
            sc_plan(&[
                "supplychain",
                "scans",
                "vulnerabilities",
                id,
                "--include-content"
            ]),
            ScPlan::Vulnerabilities {
                scan: id.to_owned(),
                include_content: true,
                format: None,
            }
        );
        assert_eq!(
            sc_plan(&["supplychain", "stats"]),
            ScPlan::Stats { format: None }
        );
        assert!(matches!(
            sc_plan(&["supplychain", "rules", "list", "--max", "0"]),
            ScPlan::Rules {
                paging: Paging { max: 0, .. },
                ..
            }
        ));
        for (args, path) in [
            (&["supplychain"][..], &["supplychain"][..]),
            (&["supplychain", "scans"], &["supplychain", "scans"]),
            (&["supplychain", "rules"], &["supplychain", "rules"]),
        ] {
            match plan_of(args) {
                Ok(Plan::GroupHelp(shown)) => assert_eq!(shown, path),
                _ => panic!("{args:?}: group help expected"),
            }
        }
    }

    /// D323, D64: the reads write no data when interrupted and log status and headers.
    #[test]
    fn interrupt_and_debug_policies() {
        let plan = sc_plan(&["supplychain", "stats"]);
        assert_eq!(plan.interrupt_context(), InterruptContext::NoDataWritten);
        assert_eq!(plan.debug_policy(), DebugPolicy::Log);
    }

    /// TS `{skip, limit, start_time, end_time, isBackgroundRefresh: false}`: the bounds only
    /// when given, as typed, in the SDK's key order (G71's raw read sends these pairs).
    #[test]
    fn the_scan_query_is_the_typescript_shape() {
        let pairs = |query: ScanQuery<'_>| {
            query
                .pairs()
                .into_iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            pairs(scan_query(5, 7, &ScanWindow::default())),
            ["skip=5", "limit=7", "isBackgroundRefresh=false"]
        );
        let window = ScanWindow {
            start: Some("2026-10-01T00:00+02:00".to_owned()),
            end: Some("2026-10-02T00:00:00Z".to_owned()),
        };
        assert_eq!(
            pairs(scan_query(0, 10, &window)),
            [
                "skip=0",
                "limit=10",
                "isBackgroundRefresh=false",
                "start_time=2026-10-01T00:00+02:00",
                "end_time=2026-10-02T00:00:00Z"
            ]
        );
        // The SDK's 16 KiB query bound is the engine's (no local copy): a long bound is
        // sent to it as typed; `failures::failures_print_the_typescript_line_only` pins
        // the engine's refusal (the request line, nothing sent).
        let long = format!("2026-10-01T00:00:00.{}Z", "1".repeat(20_000));
        let window = ScanWindow {
            start: Some(long.clone()),
            end: None,
        };
        assert_eq!(
            scan_query(0, 10, &window).pairs()[3],
            ("start_time".to_owned(), long)
        );
    }
}
