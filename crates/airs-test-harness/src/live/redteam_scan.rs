//! The M6a live red team scan flow (DESIGN §10, "M6a red team", Scan).
//!
//! Red team scans are billed and long-running, so [`run_live_redteam_scan`] runs only
//! with `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT`, `AIRS_RS_LIVE_REDTEAM_SCAN=1` and
//! `AIRS_E2E_REDTEAM_TARGET=<uuid of an existing target the user names>` ([`ScanGate`]),
//! never by default: the orchestrator asks the user first.
//!
//! # Gates, before anything is opened
//!
//! Both variables set; the target of the UUID shape; `AIRS_RS_LIVE_REDTEAM_SCAN_MINUTES`
//! (default [`DEFAULT_SCAN_MINUTES`]) an integer 1–60; the scan budget, the constant
//! [`SCAN_BUDGET`] (no override), not yet used. A violation fails the run with a fixed
//! message naming the variable, never its value; no store is created and no request sent.
//!
//! # The one scan
//!
//! A read-only preflight (the target must be listed; the first category and its first
//! sub-category that is not `MULTI_TURN`), then the smallest kind: one STATIC
//! sub-category, `--no-wait`, journalled `pending` first. TypeScript never starts a scan
//! (it would re-send the POST on a 5xx, D133). An unknown outcome is resolved read-only by
//! the exact run name on the target, with up to [`RESOLVE_ATTEMPTS`] complete listings
//! (`--all --max` [`RESOLVE_MAX_JOBS`]) a poll interval apart; a failing listing is
//! unresolved, never "not found". Still unresolved, the run fails with
//! [`LiveAbort::Setup`] naming the scan, which may be running and billed, so it is
//! aborted by hand; a second scan is never started. Polling is bounded
//! by the deadline; a scan still running at the deadline, or after a failure or a panic
//! that followed the create, is aborted with the Rust `redteam abort <id> --force` (the
//! run's own id only) and read once more.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::ledger::{Entry, Kind, Ledger, Outcome, Phase, is_uuid};
use super::writes::RESOURCE_PREFIX;
use super::{
    Exec, LiveAbort, LiveGate, LivePlan, LiveReport, LiveRow, LiveSettings, ScanBudget, Session,
};

/// The scans one run may start: one, with no override.
pub const SCAN_BUDGET: u32 = 1;

/// The default deadline of the scan flow, in minutes.
pub const DEFAULT_SCAN_MINUTES: u32 = 20;

/// The pause between two status reads.
pub const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// The listings that look for the run's scan after an unknown start.
pub const RESOLVE_ATTEMPTS: u32 = 5;

/// The newest jobs of the target each of those listings reads.
pub const RESOLVE_MAX_JOBS: &str = "200";

/// The statuses that end a scan.
pub const TERMINAL: [&str; 4] = ["COMPLETED", "PARTIALLY_COMPLETE", "FAILED", "ABORTED"];

/// What the scan flow was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanSettings {
    pub live: LiveSettings,
    /// `AIRS_E2E_REDTEAM_TARGET`.
    pub target: String,
    /// The polling deadline (`AIRS_RS_LIVE_REDTEAM_SCAN_MINUTES`).
    pub deadline: Duration,
    /// The pause between two status reads ([`POLL_INTERVAL`]; the self-tests inject a
    /// shorter one).
    pub interval: Duration,
}

/// Whether the scan flow runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanGate {
    Skip(String),
    Run(ScanSettings),
}

impl ScanGate {
    /// The gates of the scan flow over any variable source (see the module docs).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let live = match LiveGate::from_lookup(&lookup)? {
            LiveGate::Skip(reason) => return Ok(Self::Skip(reason)),
            LiveGate::Run(settings) => settings,
        };
        if lookup("AIRS_RS_LIVE_REDTEAM_SCAN").as_deref() != Some("1") {
            return Ok(Self::Skip(
                "AIRS_RS_LIVE_REDTEAM_SCAN is not 1; redteam scan skipped".into(),
            ));
        }
        let target = lookup("AIRS_E2E_REDTEAM_TARGET")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "AIRS_E2E_REDTEAM_TARGET must name an existing red team target (a UUID) for the scan flow"
                    .to_owned()
            })?;
        if !is_uuid(&target) {
            return Err("AIRS_E2E_REDTEAM_TARGET must be a target UUID".into());
        }
        let minutes = match lookup("AIRS_RS_LIVE_REDTEAM_SCAN_MINUTES")
            .filter(|value| !value.is_empty())
        {
            None => DEFAULT_SCAN_MINUTES,
            Some(text) => text
                .parse::<u32>()
                .ok()
                .filter(|minutes| {
                    (1..=60).contains(minutes) && text.bytes().all(|b| b.is_ascii_digit())
                })
                .ok_or_else(|| {
                    "AIRS_RS_LIVE_REDTEAM_SCAN_MINUTES must be an integer from 1 to 60".to_owned()
                })?,
        };
        Ok(Self::Run(ScanSettings {
            live,
            target,
            deadline: Duration::from_secs(u64::from(minutes) * 60),
            interval: POLL_INTERVAL,
        }))
    }
}

/// The first category and its first sub-category that is not `MULTI_TURN` of a Rust
/// `redteam categories --output json` document.
pub fn smallest_categories(categories: &Value) -> Option<(String, String)> {
    let category = categories.as_array()?.first()?;
    let id = category.get("id")?.as_str()?.to_owned();
    let sub = category
        .get("subCategories")?
        .as_array()?
        .iter()
        .filter_map(|sub| sub.get("id")?.as_str())
        .find(|sub| *sub != "MULTI_TURN")?
        .to_owned();
    Some((id, sub))
}

/// The id of the job named `name` in a Rust `redteam list --output json` listing.
pub fn job_named(listing: &Value, name: &str) -> Option<String> {
    listing
        .as_array()?
        .iter()
        .find(|row| row.get("name").and_then(Value::as_str) == Some(name))?
        .get("id")?
        .as_str()
        .filter(|id| is_uuid(id))
        .map(str::to_owned)
}

/// Whether a Rust `targets list --output json` lists `target`.
pub fn lists_target(listing: &Value, target: &str) -> bool {
    listing.as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row.get("id").and_then(Value::as_str) == Some(target))
    })
}

struct Flow<'s, 'p> {
    session: &'s mut Session<'p>,
    ledger: Ledger,
    settings: &'s ScanSettings,
    name: String,
    budget: ScanBudget,
    /// The run's own scan, once known (from the create output or the exact name match).
    job: Option<String>,
    /// The last status read.
    status: Option<String>,
    started: bool,
}

/// Runs the scan flow and its end (always). The gates were checked by [`ScanGate`].
pub fn run_live_redteam_scan(
    plan: &LivePlan,
    settings: &ScanSettings,
) -> Result<LiveReport, LiveAbort> {
    let mut session = Session::open(plan)?;
    let run_id = session.store.run_id().to_owned();
    let ledger = Ledger::open(&plan.store_root, &run_id).map_err(LiveAbort::Setup)?;
    let mut flow = Flow {
        session: &mut session,
        ledger,
        settings,
        name: format!("{RESOURCE_PREFIX}{run_id}-scan"),
        budget: ScanBudget::new(SCAN_BUDGET),
        job: None,
        status: None,
        started: false,
    };
    let steps = catch_unwind(AssertUnwindSafe(|| flow.steps()));
    let end = catch_unwind(AssertUnwindSafe(|| flow.end()));
    let final_status = flow.status.clone();
    drop(flow);
    session.report.store_removed = Some(session.store.remove());
    let steps = steps.unwrap_or_else(|panic| resume_unwind(panic));
    let end = end.unwrap_or_else(|panic| resume_unwind(panic));
    session.report.notices.push(format!(
        "scan final status: {}",
        final_status
            .as_deref()
            .filter(|status| status.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
            .unwrap_or("unknown")
    ));
    steps?;
    end?;
    session.report.scan_invocations = 1;
    session.report.max_scans = SCAN_BUDGET;
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

impl Flow<'_, '_> {
    fn journal(
        &mut self,
        phase: Phase,
        op: &'static str,
        id: Option<&str>,
        (outcome, exit): (Outcome, Option<i32>),
    ) -> Result<(), LiveAbort> {
        let name = self.name.clone();
        self.ledger
            .record(&Entry {
                phase,
                cli: "rs",
                op,
                kind: Kind::Scan,
                name: &name,
                id,
                outcome,
                exit,
                note: "",
            })
            .map_err(LiveAbort::Setup)
    }

    fn rust(&self, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        self.session.exec(&self.session.plan.rust, check, args)
    }

    fn row(&mut self, check: &str, rust: &Exec, ts: Option<&Exec>, agree: bool, note: &str) {
        self.session.report.rows.push(LiveRow {
            check: check.to_owned(),
            rust_exit: rust.exit_cell(),
            ts_exit: ts.map_or_else(|| "-".to_owned(), Exec::exit_cell),
            agree: agree && rust.code.is_some() && ts.is_none_or(|ts| ts.code.is_some()),
            rust_verdict: None,
            ts_verdict: None,
            note: note.to_owned(),
        });
    }

    /// The Rust `redteam status <id> --output json` status.
    fn status_of(&mut self, id: &str) -> Result<Option<String>, LiveAbort> {
        let exec = self.rust(
            "redteam status",
            &["redteam", "status", id, "--output", "json"],
        )?;
        let status = (exec.code == Some(0))
            .then(|| {
                exec.json()
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten();
        if status.is_some() {
            self.status.clone_from(&status);
        }
        Ok(status)
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        let target = self.settings.target.clone();
        let listing = self.rust(
            "preflight targets list",
            &["redteam", "targets", "list", "--all", "--output", "json"],
        )?;
        if listing.code != Some(0) || !lists_target(&listing.json(), &target) {
            return Err(LiveAbort::Setup(
                "AIRS_E2E_REDTEAM_TARGET is not listed by the tenant; no scan was started".into(),
            ));
        }
        let categories = self.rust(
            "preflight categories",
            &["redteam", "categories", "--output", "json"],
        )?;
        let Some((category, sub)) = smallest_categories(&categories.json()) else {
            return Err(LiveAbort::Setup(
                "the tenant lists no category with a single-turn sub-category; no scan was started"
                    .into(),
            ));
        };
        // The budget is checked before the request.
        self.budget.reserve()?;
        let selection = serde_json::json!({ category.as_str(): [sub] }).to_string();
        let name = self.name.clone();
        self.journal(Phase::Flow, "redteam scan", None, (Outcome::Pending, None))?;
        self.started = true;
        let exec = self.rust(
            "redteam scan",
            &[
                "redteam",
                "scan",
                "--target",
                &target,
                "--name",
                &name,
                "--type",
                "STATIC",
                "--categories",
                &selection,
                "--no-wait",
                "--output",
                "json",
            ],
        )?;
        let id = (exec.code == Some(0))
            .then(|| {
                exec.json()
                    .get("uuid")
                    .and_then(Value::as_str)
                    .filter(|id| is_uuid(id))
                    .map(str::to_owned)
            })
            .flatten();
        let outcome = match (exec.code, &id) {
            (Some(0), Some(_)) => Outcome::Ok,
            (Some(2), _) => Outcome::Failed,
            (Some(1), _)
                if !exec.stderr.contains("Check 'airs redteam list --target")
                    && !exec.stderr.contains("outcome unknown") =>
            {
                Outcome::Failed
            }
            _ => Outcome::Unknown,
        };
        self.journal(
            Phase::Flow,
            "redteam scan",
            id.as_deref(),
            (outcome, exec.code),
        )?;
        self.row(
            "redteam scan (rs, one STATIC sub-category)",
            &exec,
            None,
            outcome == Outcome::Ok,
            "D133: never re-sent",
        );
        match outcome {
            Outcome::Ok => self.job = id,
            Outcome::Unknown => {
                // Resolve read-only by the exact run name; never a second scan.
                self.job = self.resolve(&target, &name)?;
                let Some(_) = self.job else {
                    return Err(LiveAbort::Setup(format!(
                        "the scan start's outcome is unknown and no listing showed it: a billed scan named {name} may be running on the target; abort it manually ('airs redteam list --target <target>', then 'airs redteam abort <id>')"
                    )));
                };
                self.session.report.notices.push(
                    "scan outcome unknown; the run's scan was found by its exact name".into(),
                );
            }
            _ => {
                self.started = false;
                self.session
                    .report
                    .notices
                    .push("the scan was refused; nothing to clean up".into());
                return Ok(());
            }
        }
        let Some(job) = self.job.clone() else {
            return Ok(());
        };
        // Bounded polling.
        let began = Instant::now();
        let terminal = loop {
            if let Some(status) = self.status_of(&job)?
                && TERMINAL.contains(&status.as_str())
            {
                break Some(status);
            }
            if began.elapsed() >= self.settings.deadline {
                break None;
            }
            std::thread::sleep(
                self.settings
                    .interval
                    .min(self.settings.deadline.saturating_sub(began.elapsed())),
            );
        };
        let Some(status) = terminal else {
            self.session
                .report
                .notices
                .push("the scan did not finish before the deadline; it is aborted".into());
            return Ok(());
        };
        let (rust, ts) = self
            .session
            .both("redteam status <scan>", &["redteam", "status", &job])?;
        let agree = rust.code == ts.code && rust.stdout == ts.stdout;
        self.row(
            "redteam status <scan>",
            &rust,
            Some(&ts),
            agree,
            "pretty stdout equal",
        );
        if matches!(status.as_str(), "COMPLETED" | "PARTIALLY_COMPLETE") {
            for (check, args) in [
                (
                    "redteam report <scan>",
                    vec!["redteam", "report", job.as_str()],
                ),
                (
                    "redteam report <scan> --attacks",
                    vec![
                        "redteam",
                        "report",
                        job.as_str(),
                        "--attacks",
                        "--limit",
                        "5",
                    ],
                ),
            ] {
                let (rust, ts) = self.session.both(check, &args)?;
                let agree = rust.code == ts.code && rust.stdout == ts.stdout;
                self.row(check, &rust, Some(&ts), agree, "pretty stdout equal");
            }
        }
        Ok(())
    }

    /// The id of the run's scan after an unknown start: up to [`RESOLVE_ATTEMPTS`] complete
    /// listings of the target, a poll interval apart; a failing listing counts as
    /// unresolved, not as "not found".
    fn resolve(&mut self, target: &str, name: &str) -> Result<Option<String>, LiveAbort> {
        for attempt in 0..RESOLVE_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(self.settings.interval);
            }
            let found = self.rust(
                "redteam list --target",
                &[
                    "redteam",
                    "list",
                    "--target",
                    target,
                    "--all",
                    "--max",
                    RESOLVE_MAX_JOBS,
                    "--output",
                    "json",
                ],
            )?;
            if found.code != Some(0) {
                continue;
            }
            if let Some(id) = job_named(&found.json(), name) {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Aborts the run's own scan when it is not known to be terminal.
    fn end(&mut self) -> Result<(), LiveAbort> {
        let Some(job) = self.job.clone() else {
            return Ok(());
        };
        if !self.started
            || self
                .status
                .as_deref()
                .is_some_and(|status| TERMINAL.contains(&status))
        {
            return Ok(());
        }
        self.journal(
            Phase::Teardown,
            "redteam abort",
            Some(&job),
            (Outcome::Pending, None),
        )?;
        let exec = self.rust("redteam abort", &["redteam", "abort", &job, "--force"])?;
        let outcome = match exec.code {
            Some(0) => Outcome::Ok,
            Some(2) => Outcome::Failed,
            _ if exec.stderr.contains("outcome unknown")
                || exec.stderr.contains("Outcome unknown") =>
            {
                Outcome::Unknown
            }
            _ => Outcome::Failed,
        };
        self.journal(
            Phase::Teardown,
            "redteam abort",
            Some(&job),
            (outcome, exec.code),
        )?;
        self.row(
            "teardown redteam abort (rs)",
            &exec,
            None,
            outcome == Outcome::Ok,
            "the run's own scan only",
        );
        let status = self.status_of(&job)?;
        let aborted = status.as_deref() == Some("ABORTED");
        self.session.report.notices.push(format!(
            "after the abort the scan {} ABORTED",
            if aborted { "reads" } else { "does not read" }
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    const TARGET: &str = "00000000-0000-4000-8000-000000000201";

    #[test]
    fn every_gate_is_checked_before_anything_runs() {
        assert!(matches!(
            ScanGate::from_lookup(lookup(&[])),
            Ok(ScanGate::Skip(_))
        ));
        assert!(matches!(
            ScanGate::from_lookup(lookup(&[("AIRS_RS_LIVE", "1"), ("AIRS_E2E_TENANT", "dev")])),
            Ok(ScanGate::Skip(reason)) if reason.contains("redteam scan skipped")
        ));
        static BASE: [(&str, &str); 3] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "dev"),
            ("AIRS_RS_LIVE_REDTEAM_SCAN", "1"),
        ];
        assert_eq!(
            ScanGate::from_lookup(lookup(&BASE)).unwrap_err(),
            "AIRS_E2E_REDTEAM_TARGET must name an existing red team target (a UUID) for the scan flow"
        );
        static BAD: [(&str, &str); 4] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "dev"),
            ("AIRS_RS_LIVE_REDTEAM_SCAN", "1"),
            ("AIRS_E2E_REDTEAM_TARGET", "not-a-uuid"),
        ];
        let error = ScanGate::from_lookup(lookup(&BAD)).unwrap_err();
        assert!(!error.contains("not-a-uuid"), "the value is never echoed");
        for minutes in ["0", "61", "1.5", "x"] {
            let pairs: &'static [(&'static str, &'static str)] = Box::leak(Box::new([
                ("AIRS_RS_LIVE", "1"),
                ("AIRS_E2E_TENANT", "dev"),
                ("AIRS_RS_LIVE_REDTEAM_SCAN", "1"),
                ("AIRS_E2E_REDTEAM_TARGET", TARGET),
                ("AIRS_RS_LIVE_REDTEAM_SCAN_MINUTES", minutes),
            ]));
            assert_eq!(
                ScanGate::from_lookup(lookup(pairs)).unwrap_err(),
                "AIRS_RS_LIVE_REDTEAM_SCAN_MINUTES must be an integer from 1 to 60",
                "{minutes}"
            );
        }
        static OK: [(&str, &str); 4] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "dev"),
            ("AIRS_RS_LIVE_REDTEAM_SCAN", "1"),
            ("AIRS_E2E_REDTEAM_TARGET", TARGET),
        ];
        let Ok(ScanGate::Run(settings)) = ScanGate::from_lookup(lookup(&OK)) else {
            panic!("expected a run");
        };
        assert_eq!(settings.deadline, Duration::from_secs(20 * 60));
        assert_eq!(settings.interval, POLL_INTERVAL);
    }

    #[test]
    fn the_budget_is_one_scan() {
        let mut budget = ScanBudget::new(SCAN_BUDGET);
        budget.reserve().unwrap();
        assert!(matches!(budget.reserve(), Err(LiveAbort::Budget(_))));
    }

    #[test]
    fn categories_names_and_targets() {
        let categories = json!([{"id": "SECURITY", "subCategories": [{"id": "MULTI_TURN"}, {"id": "JAILBREAK"}]}]);
        assert_eq!(
            smallest_categories(&categories),
            Some(("SECURITY".into(), "JAILBREAK".into()))
        );
        assert_eq!(
            smallest_categories(&json!([{"id": "S", "subCategories": [{"id": "MULTI_TURN"}]}])),
            None
        );
        let listing =
            json!([{"id": TARGET, "name": "airs-rs-e2e-1-2-3-scan"}, {"id": "x", "name": "other"}]);
        assert_eq!(
            job_named(&listing, "airs-rs-e2e-1-2-3-scan"),
            Some(TARGET.to_owned())
        );
        assert_eq!(job_named(&listing, "airs-rs-e2e-1-2-3"), None);
        assert!(lists_target(&listing, TARGET));
        assert!(!lists_target(
            &listing,
            "00000000-0000-4000-8000-000000000999"
        ));
    }
}
