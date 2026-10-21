//! The M6c live model-security write flow (DESIGN §10, "M6c Model Security", Writes).
//!
//! [`run_live_modelsec_writes`] runs only when `tests/live.rs` passes
//! [`modelsec_writes_gate`] (`AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and
//! `AIRS_RS_LIVE_MS_WRITES=1`), or against the loopback fixture server. The only resource
//! type is the **security group** the run creates (`source_type: LOCAL`, no rule
//! configurations), and the rule instances the service creates inside it: per CLI
//! `airs-rs-e2e-<run id>-group-<rs|ts>` ([`GroupNames`]); a [`ResourceBudget`] of
//! [`MAX_RESOURCES`] is checked before each create, and every write is journalled.
//!
//! A read-only preflight (the Rust prefixed listing) proves no planned name exists. Each
//! CLI creates, reads, updates and deletes its own group and lists, reads and updates the
//! rule instances inside it. The teardown always runs (also after an abort or a panic):
//! every id seen under a planned name that is not yet confirmed deleted is deleted with
//! the Rust `groups delete <id> --force` (never twice), and a group counts as deleted on a
//! 404, on the Rust delete's own verification line, or on its absence from the prefixed
//! listing, re-checked up to [`RECHECK_TRIES`] times (the service deletes
//! asynchronously). A write to a group the run did not create, `labels` writes, `scans
//! create`, `install` and anything tenant-wide are never run here.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::Duration;

use serde_json::{Value, json};

use super::ledger::{Entry, Kind, Ledger, Outcome, Phase, is_uuid};
use super::modelsec::{first_uuid, ms_json_equal};
use super::writes::{
    MAX_RESOURCES, RESOURCE_PREFIX, ResourceBudget, Side, gate_with, id_after, listed,
    write_outcome,
};
use super::{Exec, LiveAbort, LiveGate, LivePlan, LiveReport, LiveRow, ResourceCounts, Session};

/// Creates the planned flow runs (one group per CLI).
pub const PLANNED_CREATES: u32 = 2;

/// How often a group still present after its delete is looked at again.
pub const RECHECK_TRIES: u32 = 6;

/// The pause between two of those looks.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(10);

/// The description of every run-created group (fixed text; never a summary value).
pub const GROUP_DESCRIPTION: &str = "airs-rs-e2e live check";

/// The updated description.
pub const UPDATED_DESCRIPTION: &str = "e2e-updated";

/// The rule-instance states a run may set.
pub const STATES: [&str; 3] = ["DISABLED", "ALLOWING", "BLOCKING"];

/// The write flow's gate: `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and
/// `AIRS_RS_LIVE_MS_WRITES=1`; otherwise `model-security writes skipped`.
pub fn modelsec_writes_gate(lookup: impl Fn(&str) -> Option<String>) -> Result<LiveGate, String> {
    gate_with(
        lookup,
        "AIRS_RS_LIVE_MS_WRITES",
        "model-security writes skipped",
    )
}

/// What the write flow may be told (the self-tests shorten the re-check pause).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsWriteSettings {
    pub recheck_interval: Duration,
}

impl Default for MsWriteSettings {
    fn default() -> Self {
        Self {
            recheck_interval: RECHECK_INTERVAL,
        }
    }
}

/// The two planned group names of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupNames {
    pub rs: String,
    pub ts: String,
}

impl GroupNames {
    /// `airs-rs-e2e-<run id>-group-<rs|ts>`.
    pub fn new(run_id: &str) -> Self {
        Self {
            rs: format!("{RESOURCE_PREFIX}{run_id}-group-rs"),
            ts: format!("{RESOURCE_PREFIX}{run_id}-group-ts"),
        }
    }

    pub fn contains(&self, name: &str) -> bool {
        name == self.rs || name == self.ts
    }
}

/// The prefix of the run's own names (`airs-rs-e2e-<run id>-`).
pub fn run_prefix(run_id: &str) -> String {
    format!("{RESOURCE_PREFIX}{run_id}-")
}

/// A state of [`STATES`] other than `current`.
pub fn other_state(current: &str) -> &'static str {
    STATES
        .into_iter()
        .find(|state| *state != current)
        .unwrap_or("DISABLED")
}

/// Whether the Rust `groups delete` output confirms the delete (D186): the group is gone
/// (`deleted.`) or tombstoned (`the service is removing it`).
pub(super) fn delete_confirmed(exec: &Exec) -> bool {
    exec.code == Some(0)
        && exec.stderr.lines().any(|line| {
            let line = line.trim();
            line.starts_with("✓ Group ")
                && (line.ends_with(" deleted.") || line.ends_with("(the service is removing it)."))
        })
}

/// Whether a Rust `groups get` answered 404.
pub(super) fn answered_404(exec: &Exec) -> bool {
    exec.code == Some(1) && exec.stderr.lines().any(|line| line.trim() == "HTTP 404")
}

/// The shared group machinery of the write and the scan flows.
pub(super) struct Groups<'s, 'p> {
    pub session: &'s mut Session<'p>,
    pub ledger: Ledger,
    pub budget: ResourceBudget,
    /// Every id seen under a planned name, with its name.
    pub ids: BTreeMap<String, String>,
    /// Ids whose delete was sent (never sent twice).
    pub delete_sent: BTreeSet<String>,
    /// Ids confirmed deleted.
    pub confirmed: BTreeSet<String>,
    /// The run's own name prefix.
    pub prefix: String,
    pub settings: MsWriteSettings,
    /// Set once the preflight proved that no planned name existed.
    pub owned: bool,
}

impl<'s, 'p> Groups<'s, 'p> {
    pub fn new(
        session: &'s mut Session<'p>,
        plan: &LivePlan,
        settings: MsWriteSettings,
    ) -> Result<Self, LiveAbort> {
        let run_id = session.store.run_id().to_owned();
        let ledger = Ledger::open(&plan.store_root, &run_id).map_err(LiveAbort::Setup)?;
        Ok(Self {
            session,
            ledger,
            budget: ResourceBudget::default(),
            ids: BTreeMap::new(),
            delete_sent: BTreeSet::new(),
            confirmed: BTreeSet::new(),
            prefix: run_prefix(&run_id),
            settings,
            owned: false,
        })
    }

    pub fn exec(&self, side: Side, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        let cli = match side {
            Side::Rust => &self.session.plan.rust,
            Side::Ts => &self.session.plan.ts,
        };
        self.session.exec(cli, check, args)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn journal(
        &mut self,
        phase: Phase,
        side: Side,
        op: &'static str,
        (kind, name): (Kind, &str),
        id: Option<&str>,
        (outcome, exit): (Outcome, Option<i32>),
        note: &str,
    ) -> Result<(), LiveAbort> {
        self.ledger
            .record(&Entry {
                phase,
                cli: side.ledger(),
                op,
                kind,
                name,
                id,
                outcome,
                exit,
                note,
            })
            .map_err(LiveAbort::Setup)
    }

    pub fn row(
        &mut self,
        check: &str,
        rust: Option<&Exec>,
        ts: Option<&Exec>,
        agree: bool,
        note: &str,
    ) {
        let ran = rust.is_none_or(|exec| exec.code.is_some())
            && ts.is_none_or(|exec| exec.code.is_some());
        self.session.report.rows.push(LiveRow {
            check: check.to_owned(),
            rust_exit: rust.map_or_else(|| "-".to_owned(), Exec::exit_cell),
            ts_exit: ts.map_or_else(|| "-".to_owned(), Exec::exit_cell),
            agree: agree && ran,
            rust_verdict: None,
            ts_verdict: None,
            note: note.to_owned(),
        });
    }

    /// The Rust prefixed listing: `(id, name)` of the run's own groups; `None` for a
    /// tenant without model-security access (401, 403, 404).
    pub fn own_groups(&self, check: &str) -> Result<Option<Vec<(String, String)>>, LiveAbort> {
        let exec = self.exec(
            Side::Rust,
            check,
            &[
                "model-security",
                "groups",
                "list",
                "--search",
                &self.prefix,
                "--all",
                "--max",
                "0",
                "--output",
                "json",
            ],
        )?;
        if super::redteam::no_access(exec.code, &exec.stderr) {
            return Ok(None);
        }
        match (exec.code, listed(&exec.json(), Kind::Group)) {
            (Some(0), Some(rows)) => Ok(Some(
                rows.into_iter()
                    .filter(|(id, name)| name.starts_with(&self.prefix) && is_uuid(id))
                    .collect(),
            )),
            _ => Err(LiveAbort::Setup(format!(
                "the model-security groups listing did not complete (exit {})",
                exec.exit_cell()
            ))),
        }
    }

    /// One journalled `groups create` by `side`: the config file in the run's `tmp/`, the
    /// uuid from the Rust json or the TypeScript `✓ Group created: <uuid>` line.
    pub fn create(
        &mut self,
        side: Side,
        name: &str,
        source_type: &str,
    ) -> Result<Option<String>, LiveAbort> {
        self.budget.reserve()?;
        let path = self
            .session
            .sandbox
            .tmp()
            .join(format!("group-{}.json", side.ledger()));
        let config =
            json!({"name": name, "source_type": source_type, "description": GROUP_DESCRIPTION});
        std::fs::write(&path, config.to_string())
            .map_err(|err| LiveAbort::Setup(format!("cannot write the group config: {err}")))?;
        let path = path.display().to_string();
        self.journal(
            Phase::Flow,
            side,
            "groups create",
            (Kind::Group, name),
            None,
            (Outcome::Pending, None),
            "",
        )?;
        let mut args = vec!["model-security", "groups", "create", "--config", &path];
        if side == Side::Rust {
            args.extend(["--output", "json"]);
        }
        let exec = self.exec(side, "groups create", &args)?;
        let id = match side {
            Side::Rust => exec
                .json()
                .get("uuid")
                .and_then(Value::as_str)
                .filter(|id| is_uuid(id))
                .map(str::to_owned),
            Side::Ts => id_after(&exec.stdout, "Group created:"),
        };
        if let Some(id) = &id {
            self.ids.insert(id.clone(), name.to_owned());
        }
        let outcome = write_outcome(&exec, side);
        self.journal(
            Phase::Flow,
            side,
            "groups create",
            (Kind::Group, name),
            id.as_deref(),
            (outcome, exec.code),
            "D179",
        )?;
        let check = format!("model-security groups create ({})", side.ledger());
        let (rust, ts) = match side {
            Side::Rust => (Some(&exec), None),
            Side::Ts => (None, Some(&exec)),
        };
        self.row(
            &check,
            rust,
            ts,
            id.is_some() && exec.code == Some(0),
            "uuid captured",
        );
        Ok(id)
    }

    /// One journalled delete of the run's own group by `side` (Rust with `--force`;
    /// TypeScript never prompts); a Rust delete confirmed by its own verification line.
    pub fn delete(&mut self, phase: Phase, side: Side, id: &str) -> Result<(), LiveAbort> {
        if self.delete_sent.contains(id) || self.confirmed.contains(id) {
            return Ok(());
        }
        let Some(name) = self.ids.get(id).cloned() else {
            return Ok(());
        };
        self.journal(
            phase,
            side,
            "groups delete",
            (Kind::Group, &name),
            Some(id),
            (Outcome::Pending, None),
            "",
        )?;
        self.delete_sent.insert(id.to_owned());
        let mut args = vec!["model-security", "groups", "delete", id];
        if side == Side::Rust {
            args.push("--force");
        }
        let exec = self.exec(side, "groups delete", &args)?;
        let confirmed = side == Side::Rust && delete_confirmed(&exec);
        if confirmed {
            self.confirmed.insert(id.to_owned());
        }
        // TypeScript reports `deleted` even when its re-read failed (D186): unknown until
        // the Rust check confirms it.
        let outcome = match (side, write_outcome(&exec, side)) {
            (Side::Ts, Outcome::Ok) => Outcome::Unknown,
            (_, outcome) => outcome,
        };
        self.journal(
            phase,
            side,
            "groups delete",
            (Kind::Group, &name),
            Some(id),
            (outcome, exec.code),
            "D186",
        )?;
        let check = format!(
            "{} model-security groups delete ({})",
            phase.name(),
            side.ledger()
        );
        let (rust, ts) = match side {
            Side::Rust => (Some(&exec), None),
            Side::Ts => (None, Some(&exec)),
        };
        self.row(&check, rust, ts, exec.code == Some(0), "D186");
        Ok(())
    }

    /// The teardown (see the module docs); the resource counts.
    pub fn teardown(&mut self) -> Result<ResourceCounts, LiveAbort> {
        if !self.owned {
            return Ok(ResourceCounts::default());
        }
        let mut problem = None;
        match self.own_groups("teardown listing") {
            Ok(Some(rows)) => {
                for (id, name) in rows {
                    self.ids.entry(id).or_insert(name);
                }
            }
            Ok(None) => {}
            Err(abort) => {
                problem.get_or_insert(abort);
            }
        }
        let ids: Vec<String> = self.ids.keys().cloned().collect();
        // One delete that aborts (a spawn failure, a leak or integrity check on its output)
        // never stops the others: every later id is still deleted. A ledger failure needs
        // no stop either: `delete` journals `pending` before it sends anything, so an id
        // whose journal fails is never deleted unjournalled.
        for id in &ids {
            if let Err(abort) = self.delete(Phase::Teardown, Side::Rust, id) {
                problem.get_or_insert(abort);
            }
        }
        let mut listed_left = BTreeSet::new();
        for attempt in 0..RECHECK_TRIES {
            let pending: Vec<String> = self
                .ids
                .keys()
                .filter(|id| !self.confirmed.contains(*id))
                .cloned()
                .collect();
            if pending.is_empty() {
                listed_left.clear();
                break;
            }
            if attempt > 0 {
                std::thread::sleep(self.settings.recheck_interval);
            }
            for id in &pending {
                match self.exec(
                    Side::Rust,
                    "teardown check",
                    &["model-security", "groups", "get", id, "--output", "json"],
                ) {
                    Ok(exec) if answered_404(&exec) => {
                        self.confirmed.insert(id.clone());
                    }
                    Ok(_) => {}
                    Err(abort) => {
                        problem.get_or_insert(abort);
                    }
                }
            }
            match self.own_groups("teardown check listing") {
                Ok(Some(rows)) => {
                    let still: BTreeSet<String> = rows.into_iter().map(|(id, _)| id).collect();
                    for id in self.ids.keys() {
                        if !still.contains(id) {
                            self.confirmed.insert(id.clone());
                        }
                    }
                    listed_left = still;
                }
                Ok(None) => {}
                Err(abort) => {
                    problem.get_or_insert(abort);
                }
            }
        }
        let unconfirmed: BTreeSet<&String> = self
            .ids
            .keys()
            .filter(|id| !self.confirmed.contains(*id))
            .chain(listed_left.iter())
            .collect();
        let counts = ResourceCounts {
            created: self.ids.len(),
            deleted: self.confirmed.len(),
            left: unconfirmed.len(),
        };
        for id in self.confirmed.clone() {
            let name = self.ids.get(&id).cloned().unwrap_or_default();
            if !name.is_empty() {
                for outcome in [Outcome::Pending, Outcome::Ok] {
                    self.journal(
                        Phase::Teardown,
                        Side::Rust,
                        "groups check",
                        (Kind::Group, &name),
                        Some(&id),
                        (outcome, None),
                        "confirmed deleted",
                    )?;
                }
            }
        }
        let agree = counts.left == 0;
        self.row(
            "teardown every created model-security group is gone",
            None,
            None,
            agree,
            &format!(
                "{} created, {} confirmed deleted",
                counts.created, counts.deleted
            ),
        );
        match problem {
            Some(abort) => {
                self.session.report.resources = Some(counts);
                Err(abort)
            }
            None => Ok(counts),
        }
    }
}

struct Flow<'s, 'p> {
    groups: Groups<'s, 'p>,
    names: GroupNames,
}

impl Flow<'_, '_> {
    fn steps(&mut self) -> Result<(), LiveAbort> {
        let Some(existing) = self.groups.own_groups("preflight listing")? else {
            self.groups.session.report.notices.push(
                "model-security unavailable: the tenant has no model-security access (HTTP 401, 403 or 404); the model-security writes were not run".into(),
            );
            return Ok(());
        };
        if existing.iter().any(|(_, name)| self.names.contains(name)) {
            return Err(LiveAbort::Setup(
                "a planned model-security group name already exists; nothing was created".into(),
            ));
        }
        self.groups.owned = true;
        let mut own: Vec<(Side, String)> = Vec::new();
        for (side, name) in [
            (Side::Rust, self.names.rs.clone()),
            (Side::Ts, self.names.ts.clone()),
        ] {
            if let Some(id) = self.groups.create(side, &name, "LOCAL")? {
                own.push((side, id));
            }
        }
        for (side, id) in &own {
            let check = format!("model-security groups get ({} group)", side.ledger());
            let args = ["model-security", "groups", "get", id, "--output", "json"];
            let rust = self.groups.exec(Side::Rust, &check, &args)?;
            let ts = self.groups.exec(Side::Ts, &check, &args)?;
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && ms_json_equal(&rust.json(), &ts.json());
            self.groups
                .row(&check, Some(&rust), Some(&ts), agree, "json equal (D180)");
        }
        for (side, id) in own.clone() {
            self.update(side, &id)?;
            self.instances(side, &id)?;
        }
        for (side, id) in &own {
            self.groups.delete(Phase::Flow, *side, id)?;
        }
        Ok(())
    }

    fn update(&mut self, side: Side, id: &str) -> Result<(), LiveAbort> {
        let name = self.groups.ids.get(id).cloned().unwrap_or_default();
        self.groups.journal(
            Phase::Flow,
            side,
            "groups update",
            (Kind::Group, &name),
            Some(id),
            (Outcome::Pending, None),
            "",
        )?;
        let exec = self.groups.exec(
            side,
            "groups update",
            &[
                "model-security",
                "groups",
                "update",
                id,
                "--description",
                UPDATED_DESCRIPTION,
            ],
        )?;
        let outcome = write_outcome(&exec, side);
        self.groups.journal(
            Phase::Flow,
            side,
            "groups update",
            (Kind::Group, &name),
            Some(id),
            (outcome, exec.code),
            "",
        )?;
        let get = self.groups.exec(
            Side::Rust,
            "groups get after update",
            &["model-security", "groups", "get", id, "--output", "json"],
        )?;
        let shown =
            get.json().get("description").and_then(Value::as_str) == Some(UPDATED_DESCRIPTION);
        let check = format!("model-security groups update ({})", side.ledger());
        let (rust, ts) = match side {
            Side::Rust => (Some(&exec), None),
            Side::Ts => (None, Some(&exec)),
        };
        self.groups.row(
            &check,
            rust,
            ts,
            exec.code == Some(0) && shown,
            "a Rust get shows it",
        );
        Ok(())
    }

    fn instances(&mut self, side: Side, id: &str) -> Result<(), LiveAbort> {
        let check = format!(
            "model-security rule-instances list ({} group)",
            side.ledger()
        );
        let args = [
            "model-security",
            "rule-instances",
            "list",
            id,
            "--output",
            "json",
        ];
        let rust = self.groups.exec(Side::Rust, &check, &args)?;
        let ts = self.groups.exec(Side::Ts, &check, &args)?;
        let pairs = |value: &Value| -> Option<BTreeSet<(String, String)>> {
            Some(
                value
                    .as_array()?
                    .iter()
                    .map(|row| {
                        let text = |key: &str| {
                            row.get(key)
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned()
                        };
                        (text("securityRuleUuid"), text("state"))
                    })
                    .collect(),
            )
        };
        let agree = rust.code == Some(0)
            && ts.code == Some(0)
            && pairs(&rust.json()).is_some()
            && pairs(&rust.json()) == pairs(&ts.json());
        self.groups.row(
            &check,
            Some(&rust),
            Some(&ts),
            agree,
            "equal (rule, state) sets",
        );
        let Some(instance) = first_uuid(&rust.json()) else {
            self.groups.session.report.notices.push(format!(
                "model-security rule-instances get and update skipped: the {} group has no instance",
                side.ledger()
            ));
            return Ok(());
        };
        let check = format!(
            "model-security rule-instances get ({} group)",
            side.ledger()
        );
        let args = [
            "model-security",
            "rule-instances",
            "get",
            id,
            &instance,
            "--output",
            "json",
        ];
        let r = self.groups.exec(Side::Rust, &check, &args)?;
        let t = self.groups.exec(Side::Ts, &check, &args)?;
        let current = r
            .json()
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let agree = r.code == Some(0) && t.code == Some(0) && ms_json_equal(&r.json(), &t.json());
        self.groups
            .row(&check, Some(&r), Some(&t), agree, "json equal (D180, D192)");
        let target = other_state(&current);
        let path = self
            .groups
            .session
            .sandbox
            .tmp()
            .join(format!("ri-{}.json", side.ledger()));
        std::fs::write(&path, json!({"state": target}).to_string()).map_err(|err| {
            LiveAbort::Setup(format!("cannot write the rule-instance config: {err}"))
        })?;
        let path = path.display().to_string();
        let name = self.groups.ids.get(id).cloned().unwrap_or_default();
        self.groups.journal(
            Phase::Flow,
            side,
            "rule-instance update",
            (Kind::Group, &name),
            Some(&instance),
            (Outcome::Pending, None),
            "",
        )?;
        let exec = self.groups.exec(
            side,
            "rule-instances update",
            &[
                "model-security",
                "rule-instances",
                "update",
                id,
                &instance,
                "--config",
                &path,
            ],
        )?;
        let outcome = write_outcome(&exec, side);
        self.groups.journal(
            Phase::Flow,
            side,
            "rule-instance update",
            (Kind::Group, &name),
            Some(&instance),
            (outcome, exec.code),
            "",
        )?;
        let after = self.groups.exec(
            Side::Rust,
            "rule-instances get after update",
            &[
                "model-security",
                "rule-instances",
                "get",
                id,
                &instance,
                "--output",
                "json",
            ],
        )?;
        let shown = after.json().get("state").and_then(Value::as_str) == Some(target);
        let check = format!("model-security rule-instances update ({})", side.ledger());
        let (rust, ts) = match side {
            Side::Rust => (Some(&exec), None),
            Side::Ts => (None, Some(&exec)),
        };
        self.groups.row(
            &check,
            rust,
            ts,
            exec.code == Some(0) && shown,
            "a Rust get shows the state",
        );
        Ok(())
    }
}

/// Runs the write flow, then the teardown (always), and returns the summary with its
/// resource counts.
pub fn run_live_modelsec_writes(
    plan: &LivePlan,
    settings: &MsWriteSettings,
) -> Result<LiveReport, LiveAbort> {
    if PLANNED_CREATES > MAX_RESOURCES {
        return Err(LiveAbort::Budget(
            "the planned flow creates more than a live run may".into(),
        ));
    }
    let mut session = Session::open(plan)?;
    let run_id = session.store.run_id().to_owned();
    let groups = Groups::new(&mut session, plan, *settings)?;
    let mut flow = Flow {
        groups,
        names: GroupNames::new(&run_id),
    };
    let steps = catch_unwind(AssertUnwindSafe(|| flow.steps()));
    let teardown = catch_unwind(AssertUnwindSafe(|| flow.groups.teardown()));
    let owned = flow.groups.owned;
    drop(flow);
    let summary = session.summary_check();
    session.report.store_removed = Some(session.store.remove());
    let steps = steps.unwrap_or_else(|panic| resume_unwind(panic));
    let counts = teardown.unwrap_or_else(|panic| resume_unwind(panic));
    steps?;
    let counts = counts?;
    summary?;
    if owned {
        session.report.resources = Some(counts);
    }
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_states_and_the_gate() {
        let names = GroupNames::new("1792281599-7-0");
        assert_eq!(names.rs, "airs-rs-e2e-1792281599-7-0-group-rs");
        assert!(names.contains("airs-rs-e2e-1792281599-7-0-group-ts"));
        assert!(!names.contains("airs-rs-e2e-1792281599-7-0-group-sc"));
        assert_eq!(other_state("DISABLED"), "ALLOWING");
        assert_eq!(other_state("ALLOWING"), "DISABLED");
        let lookup = |name: &str| match name {
            "AIRS_RS_LIVE" => Some("1".to_owned()),
            "AIRS_E2E_TENANT" => Some("prod".to_owned()),
            _ => None,
        };
        assert!(matches!(
            modelsec_writes_gate(lookup),
            Ok(LiveGate::Skip(reason)) if reason.contains("model-security writes skipped")
        ));
    }

    #[test]
    fn deletes_are_confirmed_by_the_verification_line() {
        let exec = |code: i32, stderr: &str| Exec {
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.to_owned(),
            elapsed: Duration::ZERO,
        };
        let u = "11111111-1111-4111-8111-000000000101";
        assert!(delete_confirmed(&exec(
            0,
            &format!("  ✓ Group {u} deleted.\n")
        )));
        assert!(delete_confirmed(&exec(
            0,
            &format!("  ✓ Group {u} deleted (the service is removing it).\n")
        )));
        assert!(!delete_confirmed(&exec(
            0,
            &format!("  ⚠ Delete request accepted, but group {u} still reports state 'ACTIVE'.\n")
        )));
        assert!(answered_404(&exec(1, "\n  ✗ Error: x\n    HTTP 404\n")));
        assert!(!answered_404(&exec(1, "\n  ✗ Error: x\n    HTTP 500\n")));
    }
}
