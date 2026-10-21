//! The live eval flow (DESIGN §10, "Eval"; MILESTONES: billed work needs its own
//! opt-in and a per-run budget).
//!
//! [`run_live_eval`] runs only when `tests/live.rs` passes [`EvalGate::from_lookup`]
//! (`AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT`, `AIRS_RS_LIVE_EVAL=1` and
//! `AIRS_E2E_PROFILE="Prisma AIRS Harness"`), or against the loopback fixture server. It
//! creates nothing and applies no topic: the CSV is the Rust `topics sample` output (2
//! rows, D113), and both CLIs run `topics eval --profile "Prisma AIRS Harness" --prompts
//! <csv> --concurrency 1 --rate 1` (Rust with `--output json`, TypeScript pretty). The
//! scan budget (`AIRS_RS_LIVE_EVAL_MAX_SCANS`, default [`DEFAULT_EVAL_MAX_SCANS`], range
//! [`MIN_EVAL_SCANS`]–[`MAX_EVAL_SCANS`]) counts CSV rows × CLIs: the planned total is
//! checked before the flow opens anything, and each eval run reserves its rows before it
//! starts. The flow is its own run, so the 8-scan cap per run holds.

use super::writes::gate_with;
use super::{LiveAbort, LiveGate, LivePlan, LiveReport, LiveRow, ScanBudget, Session};
use serde_json::Value;

/// The only profile live scans may use (MILESTONES).
pub const EVAL_PROFILE: &str = "Prisma AIRS Harness";

/// Scan budget of the eval flow when `AIRS_RS_LIVE_EVAL_MAX_SCANS` is unset.
pub const DEFAULT_EVAL_MAX_SCANS: u32 = 4;

/// The smallest accepted eval budget (the plan needs 2 rows × 2 CLIs).
pub const MIN_EVAL_SCANS: u32 = 4;

/// The largest accepted eval budget (the per-run cap of live scans).
pub const MAX_EVAL_SCANS: u32 = 8;

/// Rows of the `topics sample` CSV (D113).
pub const SAMPLE_ROWS: u32 = 2;

/// What the eval flow was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalSettings {
    pub tenant: String,
    pub max_scans: u32,
}

/// Whether the eval flow runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalGate {
    Skip(String),
    Run(EvalSettings),
}

impl EvalGate {
    /// The process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and `AIRS_RS_LIVE_EVAL=1`, else a skip; then
    /// `AIRS_E2E_PROFILE` must be [`EVAL_PROFILE`] and the budget in range, else the run
    /// fails before anything starts.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let settings = match gate_with(&lookup, "AIRS_RS_LIVE_EVAL", "eval skipped")? {
            LiveGate::Skip(reason) => return Ok(Self::Skip(reason)),
            LiveGate::Run(settings) => settings,
        };
        if settings.profile.as_deref() != Some(EVAL_PROFILE) {
            return Err(format!(
                "the live eval scans only the profile \"{EVAL_PROFILE}\" (AIRS_E2E_PROFILE)"
            ));
        }
        let max_scans = match lookup("AIRS_RS_LIVE_EVAL_MAX_SCANS").filter(|v| !v.is_empty()) {
            None => DEFAULT_EVAL_MAX_SCANS,
            Some(text) => text
                .parse::<u32>()
                .ok()
                .filter(|value| {
                    (MIN_EVAL_SCANS..=MAX_EVAL_SCANS).contains(value)
                        && text.bytes().all(|b| b.is_ascii_digit())
                })
                .ok_or_else(|| {
                    format!(
                        "AIRS_RS_LIVE_EVAL_MAX_SCANS must be an integer from {MIN_EVAL_SCANS} to {MAX_EVAL_SCANS}"
                    )
                })?,
        };
        Ok(Self::Run(EvalSettings {
            tenant: settings.tenant,
            max_scans,
        }))
    }
}

/// The confusion counts `(tp, tn, fp, fn)`.
pub type Counts = (u64, u64, u64, u64);

/// From the Rust `--output json` document.
pub fn counts_from_json(value: &Value) -> Option<Counts> {
    let metrics = value.get("metrics")?;
    let count = |key: &str| metrics.get(key)?.as_u64();
    Some((count("tp")?, count("tn")?, count("fp")?, count("fn")?))
}

/// From the TypeScript pretty `TP: <a>  TN: <b>  FP: <c>  FN: <d>  Total: <n>` line.
pub fn counts_from_pretty(stdout: &str) -> Option<Counts> {
    let line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("TP: "))?;
    let mut values = line.split_whitespace().collect::<Vec<_>>().into_iter();
    let mut take = |label: &str| -> Option<u64> {
        if values.next()? != label {
            return None;
        }
        values.next()?.parse().ok()
    };
    Some((take("TP:")?, take("TN:")?, take("FP:")?, take("FN:")?))
}

/// The eval comparison: both exit 0 with equal counts, or airs-cli-rs failed closed
/// (exit 1, `no metrics were computed`) where TypeScript counted (D111).
pub fn compare_eval(
    rust: (Option<i32>, Option<Counts>, &str),
    ts: (Option<i32>, Option<Counts>),
) -> (bool, String) {
    match (rust, ts) {
        ((Some(0), Some(r), _), (Some(0), Some(t))) if r == t => (true, "equal TP/TN/FP/FN".into()),
        ((Some(0), Some(_), _), (Some(0), Some(_))) => (false, "the counts differ".into()),
        ((Some(1), _, stderr), (Some(0), Some(_)))
            if stderr.contains("no metrics were computed") =>
        {
            (
                true,
                "D111: a scan did not complete; airs-cli-rs computed no metrics".into(),
            )
        }
        _ => (false, "expected both to complete, or the D111 stop".into()),
    }
}

/// Runs the eval flow with a budget of `max_scans` (CSV rows × CLIs).
pub fn run_live_eval(plan: &LivePlan, max_scans: u32) -> Result<LiveReport, LiveAbort> {
    if plan.scan_profile.as_deref() != Some(EVAL_PROFILE) {
        return Err(LiveAbort::Setup(format!(
            "the live eval scans only the profile \"{EVAL_PROFILE}\"; nothing was run"
        )));
    }
    if !(MIN_EVAL_SCANS..=MAX_EVAL_SCANS).contains(&max_scans) {
        return Err(LiveAbort::Budget(format!(
            "the eval budget must be from {MIN_EVAL_SCANS} to {MAX_EVAL_SCANS}; nothing was run"
        )));
    }
    if SAMPLE_ROWS * 2 > max_scans {
        return Err(LiveAbort::Budget(format!(
            "the eval sends {} scans but the budget is {max_scans}; nothing was run",
            SAMPLE_ROWS * 2
        )));
    }
    let mut session = Session::open(plan)?;
    session.budget = ScanBudget::new(max_scans);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| eval(&mut session)));
    session.report.store_removed = Some(session.store.remove());
    match outcome {
        Err(panic) => std::panic::resume_unwind(panic),
        Ok(result) => result?,
    }
    session.report.scan_invocations = session.budget.used();
    session.report.max_scans = max_scans;
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

fn eval(session: &mut Session<'_>) -> Result<(), LiveAbort> {
    let rust = session.plan.rust.clone();
    let ts = session.plan.ts.clone();
    let sample = session.exec(&rust, "topics sample", &["runtime", "topics", "sample"])?;
    let rows = sample
        .stdout
        .lines()
        .skip(1)
        .filter(|l| !l.is_empty())
        .count();
    if sample.code != Some(0) || rows == 0 {
        return Err(LiveAbort::Setup(
            "topics sample did not print the CSV".into(),
        ));
    }
    let rows = u32::try_from(rows).unwrap_or(u32::MAX);
    let csv = session.sandbox.tmp().join("eval.csv");
    std::fs::write(&csv, &sample.stdout)
        .map_err(|err| LiveAbort::Setup(format!("cannot write the eval CSV: {err}")))?;
    let csv = csv.display().to_string();
    let base = [
        "runtime",
        "topics",
        "eval",
        "--profile",
        EVAL_PROFILE,
        "--prompts",
        &csv,
        "--concurrency",
        "1",
        "--rate",
        "1",
    ];
    let mut rust_args = base.to_vec();
    rust_args.extend(["--output", "json"]);
    for _ in 0..rows {
        session.budget.reserve()?;
    }
    let rust_exec = session.exec(&rust, "topics eval", &rust_args)?;
    for _ in 0..rows {
        session.budget.reserve()?;
    }
    let ts_exec = session.exec(&ts, "topics eval", &base)?;
    let (agree, note) = compare_eval(
        (
            rust_exec.code,
            counts_from_json(&rust_exec.json()),
            &rust_exec.stderr,
        ),
        (ts_exec.code, counts_from_pretty(&ts_exec.stdout)),
    );
    session.report.rows.push(LiveRow {
        check: "topics eval (sample CSV)".into(),
        rust_exit: rust_exec.exit_cell(),
        ts_exit: ts_exec.exit_cell(),
        agree: agree && rust_exec.code.is_some() && ts_exec.code.is_some(),
        rust_verdict: None,
        ts_verdict: None,
        note,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    const BASE: [(&str, &str); 3] = [
        ("AIRS_RS_LIVE", "1"),
        ("AIRS_E2E_TENANT", "dev"),
        ("AIRS_RS_LIVE_EVAL", "1"),
    ];

    #[test]
    fn the_gate_needs_its_opt_in_the_harness_profile_and_a_bounded_budget() {
        assert!(matches!(
            EvalGate::from_lookup(lookup(&BASE[..2])),
            Ok(EvalGate::Skip(reason)) if reason.contains("eval skipped")
        ));
        let mut pairs = BASE.to_vec();
        pairs.push(("AIRS_E2E_PROFILE", "Other"));
        assert!(EvalGate::from_lookup(lookup(&pairs)).is_err());
        let mut pairs = BASE.to_vec();
        pairs.push(("AIRS_E2E_PROFILE", EVAL_PROFILE));
        assert_eq!(
            EvalGate::from_lookup(lookup(&pairs)),
            Ok(EvalGate::Run(EvalSettings {
                tenant: "dev".into(),
                max_scans: 4
            }))
        );
        for bad in ["3", "9", "x", "-4", "+5"] {
            let mut with = pairs.clone();
            with.push(("AIRS_RS_LIVE_EVAL_MAX_SCANS", bad));
            assert!(EvalGate::from_lookup(lookup(&with)).is_err(), "{bad}");
        }
        pairs.push(("AIRS_RS_LIVE_EVAL_MAX_SCANS", "8"));
        assert!(matches!(
            EvalGate::from_lookup(lookup(&pairs)),
            Ok(EvalGate::Run(EvalSettings { max_scans: 8, .. }))
        ));
    }

    #[test]
    fn counts_parse_from_both_outputs() {
        let json = serde_json::json!({"metrics": {"tp": 1, "tn": 1, "fp": 0, "fn": 0, "total": 2}});
        assert_eq!(counts_from_json(&json), Some((1, 1, 0, 0)));
        assert_eq!(
            counts_from_pretty("\n  Metrics:\n\n  TP: 1  TN: 1  FP: 0  FN: 0  Total: 2\n"),
            Some((1, 1, 0, 0))
        );
        assert_eq!(counts_from_pretty("TP: x"), None);
    }

    #[test]
    fn the_comparison_accepts_equal_counts_or_the_d111_stop() {
        let c = Some((1, 1, 0, 0));
        assert!(compare_eval((Some(0), c, ""), (Some(0), c)).0);
        assert!(!compare_eval((Some(0), Some((0, 1, 0, 1)), ""), (Some(0), c)).0);
        assert!(
            compare_eval(
                (
                    Some(1),
                    None,
                    "Scans: 1 of 2 sent, 0 completed; no metrics were computed."
                ),
                (Some(0), c)
            )
            .0
        );
        assert!(!compare_eval((Some(1), None, "other"), (Some(0), c)).0);
        assert!(!compare_eval((Some(0), c, ""), (Some(1), None)).0);
    }
}
