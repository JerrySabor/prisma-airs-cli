//! The M6c live model-security scan flow (DESIGN §10, "M6c Model Security", Scan).
//!
//! Model-security scans are billed and long-running, so [`run_live_modelsec_scan`] runs
//! only with `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT`, `AIRS_RS_LIVE_MS_WRITES=1` (the flow
//! creates and deletes a group and writes labels), `AIRS_RS_LIVE_MS_SCAN=1` (the extra
//! opt-in of the billed scan) and `AIRS_E2E_MS_MODEL_URI=<a model URI the user names>`
//! ([`MsScanGate`]), never by default: the orchestrator asks the user first.
//!
//! # Gates, before anything is opened
//!
//! All the variables set (`AIRS_RS_LIVE_MS_WRITES` or `AIRS_RS_LIVE_MS_SCAN` not `1`:
//! `model-security scan skipped`); the URI at most 2,048 bytes, without control characters, and
//! without userinfo, query or fragment when it parses as a URL (a credential-bearing URI
//! is refused; the value is never printed); `AIRS_RS_LIVE_MS_SCAN_MINUTES` (default
//! [`DEFAULT_SCAN_MINUTES`]) an integer 1–60; the scan budget, the constant
//! [`SCAN_BUDGET`] (no override), not yet used. A violation fails the run with a fixed
//! message naming the variable, never its value; no store is created and no request sent.
//!
//! # The one scan
//!
//! One group `airs-rs-e2e-<run id>-group-sc` (Rust) and one scan, created by **Rust
//! only** (TypeScript re-sends the POST on a 5xx, D179), journalled `pending` first. An
//! unknown outcome is resolved read-only with up to [`RESOLVE_ATTEMPTS`] listings; still
//! unresolved, the run fails naming the group, and a second scan is never created. Label
//! writes happen only on that scan (keys and values `airs-rs-e2e-<run id>-…`). A bounded
//! wait reads the scan until its outcome is not `PENDING`; when it ended, both CLIs read
//! its evaluations, violations and files. The end removes the run's labels, then deletes
//! the group as the write flow does; the scan itself stays (the API has no scan delete),
//! journalled with the note `undeletable` and not counted in `resourcesLeft`.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::ledger::{Kind, Outcome, Phase, is_uuid, now_unix, utc};
use super::modelsec::pretty_body;
use super::modelsec_writes::{Groups, MsWriteSettings};
use super::writes::{Side, write_outcome};
use super::{
    Exec, LiveAbort, LiveGate, LivePlan, LiveReport, LiveSettings, ResourceCounts, ScanBudget,
    Session, opt_in,
};

/// The scans one run may create: one, with no override.
pub const SCAN_BUDGET: u32 = 1;

/// The default deadline of the bounded wait, in minutes.
pub const DEFAULT_SCAN_MINUTES: u32 = 15;

/// The pause between two scan reads.
pub const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// The read-only listings that look for the scan after an unknown create.
pub const RESOLVE_ATTEMPTS: u32 = 5;

/// The longest model URI the gate accepts.
pub const MAX_URI_BYTES: usize = 2048;

/// What the scan flow was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsScanSettings {
    pub live: LiveSettings,
    /// `AIRS_E2E_MS_MODEL_URI` (never printed).
    pub model_uri: String,
    /// The bounded wait (`AIRS_RS_LIVE_MS_SCAN_MINUTES`).
    pub deadline: Duration,
    /// The pause between two scan reads and between two resolving listings
    /// ([`POLL_INTERVAL`]; the self-tests inject a shorter one).
    pub interval: Duration,
    /// The group re-check pause of the end.
    pub groups: MsWriteSettings,
}

/// Whether the scan flow runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsScanGate {
    Skip(String),
    Run(MsScanSettings),
}

/// The gate's URI rule: at most 2,048 bytes, no control character, and no userinfo,
/// query or fragment when it parses as a URL.
pub fn usable_model_uri(uri: &str) -> bool {
    if uri.is_empty() || uri.len() > MAX_URI_BYTES || uri.chars().any(char::is_control) {
        return false;
    }
    match url::Url::parse(uri) {
        Ok(url) => {
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && !uri.contains('@')
        }
        Err(_) => !uri.contains('@') && !uri.contains('?') && !uri.contains('#'),
    }
}

impl MsScanGate {
    /// The gates of the scan flow over any variable source (see the module docs).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let live = match LiveGate::from_lookup(&lookup)? {
            LiveGate::Skip(reason) => return Ok(Self::Skip(reason)),
            LiveGate::Run(settings) => settings,
        };
        // The flow writes (a group, labels): the write opt-in first, the scan's own after.
        if opt_in(lookup("AIRS_RS_LIVE_MS_WRITES").as_deref()).is_err() {
            return Ok(Self::Skip(
                "AIRS_RS_LIVE_MS_WRITES is not 1; model-security scan skipped".into(),
            ));
        }
        if opt_in(lookup("AIRS_RS_LIVE_MS_SCAN").as_deref()).is_err() {
            return Ok(Self::Skip(
                "AIRS_RS_LIVE_MS_SCAN is not 1; model-security scan skipped".into(),
            ));
        }
        let model_uri = lookup("AIRS_E2E_MS_MODEL_URI")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "AIRS_E2E_MS_MODEL_URI must name the model URI the scan flow scans".to_owned()
            })?;
        if !usable_model_uri(&model_uri) {
            return Err(
                "AIRS_E2E_MS_MODEL_URI must be at most 2048 bytes, without control characters, credentials, a query or a fragment"
                    .into(),
            );
        }
        let minutes = match lookup("AIRS_RS_LIVE_MS_SCAN_MINUTES").filter(|value| !value.is_empty())
        {
            None => DEFAULT_SCAN_MINUTES,
            Some(text) => text
                .parse::<u32>()
                .ok()
                .filter(|minutes| {
                    (1..=60).contains(minutes) && text.bytes().all(|b| b.is_ascii_digit())
                })
                .ok_or_else(|| {
                    "AIRS_RS_LIVE_MS_SCAN_MINUTES must be an integer from 1 to 60".to_owned()
                })?,
        };
        Ok(Self::Run(MsScanSettings {
            live,
            model_uri,
            deadline: Duration::from_secs(u64::from(minutes) * 60),
            interval: POLL_INTERVAL,
            groups: MsWriteSettings::default(),
        }))
    }
}

/// The source type of the run's group: `HUGGING_FACE` for an `hf://` or
/// `https://huggingface.co/` URI, else `ALL`.
pub fn source_type_of(uri: &str) -> &'static str {
    if uri.starts_with("hf://") || uri.starts_with("https://huggingface.co/") {
        "HUGGING_FACE"
    } else {
        "ALL"
    }
}

/// The last path segment of a URI (the `--search` of the resolving listing).
pub fn last_segment(uri: &str) -> String {
    uri.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(uri)
        .to_owned()
}

/// The uuid of the run's scan in a Rust `scans list --output json` listing: the row of
/// the run's group created at or after `started` (`YYYY-MM-DDTHH:MM:SSZ`, compared on
/// the first 19 characters, UTC).
pub fn scan_of(listing: &Value, group: &str, started: &str) -> Option<String> {
    let start = started.get(..19)?;
    listing.as_array()?.iter().find_map(|row| {
        let named = row.get("securityGroupName").and_then(Value::as_str) == Some(group);
        let created = row
            .get("createdAt")
            .and_then(Value::as_str)
            .and_then(|at| at.get(..19))
            .is_some_and(|at| at >= start);
        let id = row
            .get("uuid")
            .and_then(Value::as_str)
            .filter(|id| is_uuid(id));
        (named && created).then(|| id.map(str::to_owned)).flatten()
    })
}

/// The `(key, value)` labels of a scan document that carry the run's prefix.
pub fn run_labels(scan: &Value, prefix: &str) -> BTreeSet<(String, String)> {
    scan.get("labels")
        .and_then(Value::as_array)
        .map(|labels| {
            labels
                .iter()
                .filter_map(|label| {
                    let key = label.get("key")?.as_str()?;
                    let value = label.get("value")?.as_str()?;
                    key.starts_with(prefix)
                        .then(|| (key.to_owned(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

struct Flow<'s, 'p> {
    groups: Groups<'s, 'p>,
    settings: MsScanSettings,
    budget: ScanBudget,
    group: Option<String>,
    group_name: String,
    scan_name: String,
    scan: Option<String>,
    started: String,
}

impl Flow<'_, '_> {
    fn key(&self, n: u32) -> String {
        format!("{}k{n}", self.groups.prefix)
    }

    fn value(&self, n: u32) -> String {
        format!("{}v{n}", self.groups.prefix)
    }

    fn labels_json(&self, numbers: &[u32]) -> String {
        Value::Array(
            numbers
                .iter()
                .map(|n| json!({"key": self.key(*n), "value": self.value(*n)}))
                .collect(),
        )
        .to_string()
    }

    fn get_scan(&self, side: Side, check: &str) -> Result<Exec, LiveAbort> {
        let scan = self.scan.clone().unwrap_or_default();
        self.groups.exec(
            side,
            check,
            &["model-security", "scans", "get", &scan, "--output", "json"],
        )
    }

    /// One journalled label write on the run's scan.
    fn label_write(
        &mut self,
        side: Side,
        op: &'static str,
        args: &[&str],
        phase: Phase,
    ) -> Result<Exec, LiveAbort> {
        let scan = self.scan.clone().unwrap_or_default();
        let name = self.scan_name.clone();
        self.groups.journal(
            phase,
            side,
            op,
            (Kind::ModelScan, &name),
            Some(&scan),
            (Outcome::Pending, None),
            "",
        )?;
        let exec = self.groups.exec(side, op, args)?;
        let outcome = write_outcome(&exec, side);
        self.groups.journal(
            phase,
            side,
            op,
            (Kind::ModelScan, &name),
            Some(&scan),
            (outcome, exec.code),
            "",
        )?;
        Ok(exec)
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        let Some(existing) = self.groups.own_groups("preflight listing")? else {
            self.groups.session.report.notices.push(
                "model-security unavailable: the tenant has no model-security access (HTTP 401, 403 or 404); the model-security scan was not run".into(),
            );
            return Ok(());
        };
        if existing.iter().any(|(_, name)| *name == self.group_name) {
            return Err(LiveAbort::Setup(
                "the planned model-security group name already exists; nothing was created".into(),
            ));
        }
        self.groups.owned = true;
        let source = source_type_of(&self.settings.model_uri);
        let name = self.group_name.clone();
        self.group = self.groups.create(Side::Rust, &name, source)?;
        let Some(group) = self.group.clone() else {
            return Ok(());
        };
        self.create_scan(&group)?;
        if self.scan.is_none() {
            return Ok(());
        }
        self.labels()?;
        self.wait()
    }

    fn create_scan(&mut self, group: &str) -> Result<(), LiveAbort> {
        self.budget.reserve()?;
        self.groups.budget.reserve()?;
        let path = self.groups.session.sandbox.tmp().join("scan.json");
        let config = json!({"model_uri": self.settings.model_uri, "security_group_uuid": group});
        std::fs::write(&path, config.to_string())
            .map_err(|err| LiveAbort::Setup(format!("cannot write the scan config: {err}")))?;
        let path = path.display().to_string();
        let name = self.scan_name.clone();
        self.groups.journal(
            Phase::Flow,
            Side::Rust,
            "scans create",
            (Kind::ModelScan, &name),
            None,
            (Outcome::Pending, None),
            "billed",
        )?;
        let exec = self.groups.exec(
            Side::Rust,
            "scans create",
            &[
                "model-security",
                "scans",
                "create",
                "--config",
                &path,
                "--output",
                "json",
            ],
        )?;
        let outcome = write_outcome(&exec, Side::Rust);
        let mut id = exec
            .json()
            .get("uuid")
            .and_then(Value::as_str)
            .filter(|id| is_uuid(id))
            .map(str::to_owned);
        self.groups.journal(
            Phase::Flow,
            Side::Rust,
            "scans create",
            (Kind::ModelScan, &name),
            id.as_deref(),
            (outcome, exec.code),
            "billed",
        )?;
        if id.is_none() && outcome != Outcome::Failed {
            id = self.resolve()?;
            if id.is_none() {
                return Err(LiveAbort::Setup(format!(
                    "a billed model-security scan may have been created in group {}; check it manually",
                    self.group_name
                )));
            }
            for outcome in [Outcome::Pending, Outcome::Ok] {
                self.groups.journal(
                    Phase::Flow,
                    Side::Rust,
                    "scans lookup",
                    (Kind::ModelScan, &name),
                    id.as_deref(),
                    (outcome, None),
                    "resolved by listing",
                )?;
            }
        }
        self.groups.row(
            "model-security scans create (rs, budget 1)",
            Some(&exec),
            None,
            id.is_some(),
            "D179: one attempt",
        );
        self.scan = id;
        Ok(())
    }

    /// The read-only lookup of a scan whose create outcome is unknown.
    fn resolve(&mut self) -> Result<Option<String>, LiveAbort> {
        let search = last_segment(&self.settings.model_uri);
        for attempt in 0..RESOLVE_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(self.settings.interval);
            }
            let exec = self.groups.exec(
                Side::Rust,
                "scans lookup",
                &[
                    "model-security",
                    "scans",
                    "list",
                    "--search",
                    &search,
                    "--all",
                    "--max",
                    "200",
                    "--output",
                    "json",
                ],
            )?;
            if exec.code != Some(0) {
                continue; // unresolved, never "not found"
            }
            if let Some(id) = scan_of(&exec.json(), &self.group_name, &self.started) {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    fn labels(&mut self) -> Result<(), LiveAbort> {
        let scan = self.scan.clone().unwrap_or_default();
        let prefix = self.groups.prefix.clone();
        let one = self.labels_json(&[1]);
        let add_rs = self.label_write(
            Side::Rust,
            "labels add",
            &["model-security", "labels", "add", &scan, "--labels", &one],
            Phase::Flow,
        )?;
        let two = self.labels_json(&[2]);
        let add_ts = self.label_write(
            Side::Ts,
            "labels add",
            &["model-security", "labels", "add", &scan, "--labels", &two],
            Phase::Flow,
        )?;
        let r = self.get_scan(Side::Rust, "scans get after add")?;
        let t = self.get_scan(Side::Ts, "scans get after add")?;
        let expected: BTreeSet<(String, String)> = [1, 2]
            .into_iter()
            .map(|n| (self.key(n), self.value(n)))
            .collect();
        let agree = add_rs.code == Some(0)
            && add_ts.code == Some(0)
            && run_labels(&r.json(), &prefix) == expected
            && run_labels(&t.json(), &prefix) == expected;
        self.groups.row(
            "model-security labels add (rs, ts) and scans get",
            Some(&r),
            Some(&t),
            agree,
            "equal run label sets",
        );
        let three = self.labels_json(&[3]);
        let set_rs = self.label_write(
            Side::Rust,
            "labels set",
            &[
                "model-security",
                "labels",
                "set",
                &scan,
                "--labels",
                &three,
                "--force",
            ],
            Phase::Flow,
        )?;
        let warned = set_rs.stderr.contains(&self.key(1)) && set_rs.stderr.contains(&self.key(2));
        self.groups.row(
            "model-security labels set --force (rs)",
            Some(&set_rs),
            None,
            set_rs.code == Some(0) && warned,
            "the warning names the dropped keys (D185)",
        );
        let four_five = self.labels_json(&[4, 5]);
        let set_ts = self.label_write(
            Side::Ts,
            "labels set",
            &[
                "model-security",
                "labels",
                "set",
                &scan,
                "--labels",
                &four_five,
            ],
            Phase::Flow,
        )?;
        let after_set = self.get_scan(Side::Rust, "scans get after set")?;
        let expected: BTreeSet<(String, String)> = [4, 5]
            .into_iter()
            .map(|n| (self.key(n), self.value(n)))
            .collect();
        self.groups.row(
            "model-security labels set (ts) and scans get (rs)",
            Some(&after_set),
            Some(&set_ts),
            set_ts.code == Some(0) && run_labels(&after_set.json(), &prefix) == expected,
            "exactly the replaced labels",
        );
        let k4 = self.key(4);
        let delete_ts = self.label_write(
            Side::Ts,
            "labels delete",
            &["model-security", "labels", "delete", &scan, "--keys", &k4],
            Phase::Flow,
        )?;
        let k5 = self.key(5);
        let delete_rs = self.label_write(
            Side::Rust,
            "labels delete",
            &[
                "model-security",
                "labels",
                "delete",
                &scan,
                "--keys",
                &k5,
                "--force",
            ],
            Phase::Flow,
        )?;
        let after_delete = self.get_scan(Side::Rust, "scans get after delete")?;
        self.groups.row(
            "model-security labels delete (ts, rs) and scans get (rs)",
            Some(&delete_rs),
            Some(&delete_ts),
            delete_rs.code == Some(0)
                && delete_ts.code == Some(0)
                && run_labels(&after_delete.json(), &prefix).is_empty(),
            "no run label left",
        );
        let keys = self.groups.exec(
            Side::Rust,
            "labels keys",
            &[
                "model-security",
                "labels",
                "keys",
                "--all",
                "--output",
                "json",
            ],
        )?;
        let lagging = keys.json().as_array().is_some_and(|keys| {
            keys.iter()
                .filter_map(Value::as_str)
                .any(|key| key.starts_with(&prefix))
        });
        if lagging {
            self.groups.session.report.notices.push(
                "model-security labels keys still lists a run key (a tenant-wide index may lag)"
                    .into(),
            );
        }
        Ok(())
    }

    /// The bounded wait; when the scan ended, both CLIs read its sub-lists.
    fn wait(&mut self) -> Result<(), LiveAbort> {
        let started = Instant::now();
        let mut outcome = String::from("PENDING");
        loop {
            let exec = self.get_scan(Side::Rust, "scans get (wait)")?;
            if let Some(found) = exec.json().get("evalOutcome").and_then(Value::as_str) {
                outcome = found.to_owned();
            }
            if outcome != "PENDING" || started.elapsed() >= self.settings.deadline {
                break;
            }
            std::thread::sleep(self.settings.interval);
        }
        let token: String = outcome
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(32)
            .collect();
        self.groups
            .session
            .report
            .notices
            .push(format!("model-security scan final outcome: {token}"));
        if outcome == "PENDING" {
            self.groups.session.report.notices.push(
                "model-security scan still PENDING at the deadline; its sub-lists were not compared".into(),
            );
            return Ok(());
        }
        let scan = self.scan.clone().unwrap_or_default();
        for sub in ["evaluations", "violations", "files"] {
            let check = format!("model-security scans {sub} <run scan>");
            let args = ["model-security", "scans", sub, &scan, "--limit", "20"];
            let r = self.groups.exec(Side::Rust, &check, &args)?;
            let t = self.groups.exec(Side::Ts, &check, &args)?;
            let agree = r.code == Some(0)
                && t.code == Some(0)
                && pretty_body(&r.stdout, false) == pretty_body(&t.stdout, true);
            self.groups.row(
                &check,
                Some(&r),
                Some(&t),
                agree,
                "pretty equal after the banner (D52)",
            );
        }
        Ok(())
    }

    /// The end, always: the run's labels removed, the scan journalled `undeletable`,
    /// the group deleted and confirmed.
    fn end(&mut self) -> Result<ResourceCounts, LiveAbort> {
        let mut problem = None;
        if let Some(scan) = self.scan.clone() {
            let prefix = self.groups.prefix.clone();
            match self.get_scan(Side::Rust, "scans get (end)") {
                Ok(exec) => {
                    let keys: Vec<String> = run_labels(&exec.json(), &prefix)
                        .into_iter()
                        .map(|(key, _)| key)
                        .collect();
                    if !keys.is_empty() {
                        let joined = keys.join(",");
                        if let Err(abort) = self.label_write(
                            Side::Rust,
                            "labels delete",
                            &[
                                "model-security",
                                "labels",
                                "delete",
                                &scan,
                                "--keys",
                                &joined,
                                "--force",
                            ],
                            Phase::Teardown,
                        ) {
                            problem.get_or_insert(abort);
                        }
                    }
                }
                Err(abort) => {
                    problem.get_or_insert(abort);
                }
            }
            let name = self.scan_name.clone();
            if let Err(abort) = self.groups.journal(
                Phase::Teardown,
                Side::Rust,
                "scan kept",
                (Kind::ModelScan, &name),
                Some(&scan),
                (Outcome::Skipped, None),
                "undeletable",
            ) {
                problem.get_or_insert(abort);
            }
            self.groups.session.report.notices.push(
                "the run's model-security scan stays in the tenant: the API has no scan delete"
                    .into(),
            );
        }
        let counts = self.groups.teardown();
        match (counts, problem) {
            (Ok(counts), None) => Ok(counts),
            (Ok(counts), Some(abort)) => {
                self.groups.session.report.resources = Some(counts);
                Err(abort)
            }
            (Err(abort), _) => Err(abort),
        }
    }
}

/// Runs the scan flow (see the module docs) and returns the summary.
pub fn run_live_modelsec_scan(
    plan: &LivePlan,
    settings: &MsScanSettings,
) -> Result<LiveReport, LiveAbort> {
    if !usable_model_uri(&settings.model_uri) {
        return Err(LiveAbort::Setup(
            "AIRS_E2E_MS_MODEL_URI must be at most 2048 bytes, without control characters, credentials, a query or a fragment".into(),
        ));
    }
    let mut session = Session::open(plan)?;
    let run_id = session.store.run_id().to_owned();
    let groups = Groups::new(&mut session, plan, settings.groups)?;
    let prefix = groups.prefix.clone();
    let mut flow = Flow {
        groups,
        settings: settings.clone(),
        budget: ScanBudget::new(SCAN_BUDGET),
        group: None,
        group_name: format!("{prefix}group-sc"),
        scan_name: format!("{prefix}scan-sc"),
        scan: None,
        started: utc(now_unix()),
    };
    let _ = run_id;
    let steps = catch_unwind(AssertUnwindSafe(|| flow.steps()));
    let end = catch_unwind(AssertUnwindSafe(|| flow.end()));
    let owned = flow.groups.owned;
    drop(flow);
    let summary = session.summary_check();
    session.report.store_removed = Some(session.store.remove());
    let steps = steps.unwrap_or_else(|panic| resume_unwind(panic));
    let counts = end.unwrap_or_else(|panic| resume_unwind(panic));
    steps?;
    let counts = counts?;
    summary?;
    if owned {
        session.report.resources = Some(counts);
    }
    session.report.scan_invocations = u32::from(owned);
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn the_gate_refuses_before_anything_runs() {
        const BASE: [(&str, &str); 3] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "prod"),
            ("AIRS_RS_LIVE_MS_WRITES", "1"),
        ];
        assert!(matches!(
            MsScanGate::from_lookup(lookup(&BASE)),
            Ok(MsScanGate::Skip(reason)) if reason.contains("model-security scan skipped")
        ));
        // Every scan variable but the write opt-in: skipped, never run.
        const NO_WRITES: [(&str, &str); 4] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "prod"),
            ("AIRS_RS_LIVE_MS_SCAN", "1"),
            ("AIRS_E2E_MS_MODEL_URI", "hf://org/model"),
        ];
        assert!(matches!(
            MsScanGate::from_lookup(lookup(&NO_WRITES)),
            Ok(MsScanGate::Skip(reason))
                if reason == "AIRS_RS_LIVE_MS_WRITES is not 1; model-security scan skipped"
        ));
        const NO_URI: [(&str, &str); 4] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "prod"),
            ("AIRS_RS_LIVE_MS_WRITES", "1"),
            ("AIRS_RS_LIVE_MS_SCAN", "1"),
        ];
        assert!(
            MsScanGate::from_lookup(lookup(&NO_URI))
                .unwrap_err()
                .contains("AIRS_E2E_MS_MODEL_URI")
        );
        const SECRET: [(&str, &str); 5] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "prod"),
            ("AIRS_RS_LIVE_MS_WRITES", "1"),
            ("AIRS_RS_LIVE_MS_SCAN", "1"),
            (
                "AIRS_E2E_MS_MODEL_URI",
                "https://u:FAKE-MS-SECRET-01@h.example/m",
            ),
        ];
        let message = MsScanGate::from_lookup(lookup(&SECRET)).unwrap_err();
        assert!(!message.contains("FAKE-MS-SECRET"), "never the value");
        const MINUTES: [(&str, &str); 6] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "prod"),
            ("AIRS_RS_LIVE_MS_WRITES", "1"),
            ("AIRS_RS_LIVE_MS_SCAN", "1"),
            ("AIRS_E2E_MS_MODEL_URI", "hf://org/model"),
            ("AIRS_RS_LIVE_MS_SCAN_MINUTES", "61"),
        ];
        assert!(
            MsScanGate::from_lookup(lookup(&MINUTES))
                .unwrap_err()
                .contains("MINUTES")
        );
        const OK: [(&str, &str); 5] = [
            ("AIRS_RS_LIVE", "1"),
            ("AIRS_E2E_TENANT", "prod"),
            ("AIRS_RS_LIVE_MS_WRITES", "1"),
            ("AIRS_RS_LIVE_MS_SCAN", "1"),
            ("AIRS_E2E_MS_MODEL_URI", "hf://org/model"),
        ];
        assert!(matches!(
            MsScanGate::from_lookup(lookup(&OK)),
            Ok(MsScanGate::Run(settings)) if settings.deadline == Duration::from_secs(900)
        ));
    }

    #[test]
    fn uris_sources_and_lookups() {
        for good in [
            "hf://org/model",
            "s3://bucket/path/m.bin",
            "https://huggingface.co/org/m",
            "/local/path",
        ] {
            assert!(usable_model_uri(good), "{good}");
        }
        for bad in [
            "",
            "https://u:p@h/m",
            "s3://b/m?X-Amz-Signature=1",
            "hf://org/m#x",
            "a\u{1}b",
            "u@host:path",
        ] {
            assert!(!usable_model_uri(bad), "{bad:?}");
        }
        assert!(!usable_model_uri(&"a".repeat(MAX_URI_BYTES + 1)));
        assert_eq!(source_type_of("hf://org/m"), "HUGGING_FACE");
        assert_eq!(
            source_type_of("https://huggingface.co/org/m"),
            "HUGGING_FACE"
        );
        assert_eq!(source_type_of("s3://b/m"), "ALL");
        assert_eq!(last_segment("hf://org/model/"), "model");
        let listing = json!([
            {"uuid": "11111111-1111-4111-8111-000000000401", "securityGroupName": "g", "createdAt": "2026-01-01T00:00:00Z"},
            {"uuid": "11111111-1111-4111-8111-000000000451", "securityGroupName": "g", "createdAt": "2026-10-18T10:00:05.123Z"}
        ]);
        assert_eq!(
            scan_of(&listing, "g", "2026-10-18T10:00:00Z").as_deref(),
            Some("11111111-1111-4111-8111-000000000451")
        );
        assert_eq!(scan_of(&listing, "other", "2026-10-18T10:00:00Z"), None);
        let mut budget = ScanBudget::new(SCAN_BUDGET);
        assert!(budget.reserve().is_ok());
        assert!(
            budget.reserve().is_err(),
            "a second scan in one run is refused"
        );
    }
}
