//! The M6a live red team write flow (DESIGN §10, "M6a red team", Writes).
//!
//! [`run_live_redteam_writes`] runs only when `tests/live.rs` passes
//! [`redteam_writes_gate`] (`AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and
//! `AIRS_RS_LIVE_REDTEAM_WRITES=1`), or against the loopback fixture server.
//!
//! # The only resource type: draft adapters
//!
//! A draft adapter (`--draft`: `validate=false`, no channel, a placeholder script and one
//! `VAR` variable) is fully deletable, not tenant-wide, and makes the service run no
//! script. The flow plans two, `airs-rs-e2e-<run id>-adapter-rs` and `-adapter-ts`
//! ([`AdapterNames`]); a [`ResourceBudget`] of [`MAX_RESOURCES`] is checked before each
//! create; every create and delete is journalled to the [`super::ledger`]. Excluded,
//! with the reasons of DESIGN §10: targets (the service contacts an external endpoint and
//! they carry credentials), prompt sets (only archivable), prompts, properties,
//! instances, devices, channels, registry credentials, `adapter validate`, `eula accept`,
//! `abort` of any scan the run did not start and `restore`.
//!
//! # Teardown
//!
//! Always, also after an abort or a panic: every adapter listed under a planned name is
//! deleted with the Rust `redteam adapter delete <id> --force` (no TypeScript delete);
//! then every id captured from a create output that the listing did not show is deleted
//! by its id, journalled the same way, and the listing's miss is a failed row (a listing
//! that has not indexed the new rows, or a search that ignores names, must not leave the
//! drafts behind). What is left is counted (`resourcesLeft`: every created id not
//! confirmed deleted plus every planned name still listed, which fails the live test).

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use serde_json::{Value, json};

use super::ledger::{Entry, Kind, Ledger, Outcome, Phase, is_uuid};
use super::writes::{
    MAX_RESOURCES, RESOURCE_PREFIX, ResourceBudget, gate_with, journalled_delete, listed,
};
use super::{Exec, LiveAbort, LiveGate, LivePlan, LiveReport, LiveRow, ResourceCounts, Session};
use crate::compare::json_semantic_eq;

/// Creates the flow runs (one draft adapter per CLI).
pub const PLANNED_ADAPTERS: u32 = 2;

/// The placeholder script of a draft adapter.
pub const PLACEHOLDER_SCRIPT: &str = "# airs-rs-e2e placeholder\n";

/// The variables of a draft adapter (no `SECRET`, D154).
pub const VARIABLES: &str = r#"[{"key":"E2E","value":"1","type":"VAR"}]"#;

/// The write flow's gate: `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and
/// `AIRS_RS_LIVE_REDTEAM_WRITES=1`; otherwise `redteam writes skipped`.
pub fn redteam_writes_gate(lookup: impl Fn(&str) -> Option<String>) -> Result<LiveGate, String> {
    gate_with(
        lookup,
        "AIRS_RS_LIVE_REDTEAM_WRITES",
        "redteam writes skipped",
    )
}

/// The two planned adapter names of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterNames {
    pub rs: String,
    pub ts: String,
}

impl AdapterNames {
    /// `airs-rs-e2e-<run id>-adapter-<cli>`.
    pub fn new(run_id: &str) -> Self {
        Self {
            rs: format!("{RESOURCE_PREFIX}{run_id}-adapter-rs"),
            ts: format!("{RESOURCE_PREFIX}{run_id}-adapter-ts"),
        }
    }

    /// Whether `name` is one of them.
    pub fn planned(&self, name: &str) -> bool {
        name == self.rs || name == self.ts
    }
}

/// The run-independent fields of an adapter detail (`--output json`): ids, names,
/// timestamps and user ids dropped; the script compared as a hash only.
pub fn adapter_projection(detail: &Value) -> Option<Value> {
    let map = detail.as_object()?;
    let mut out = serde_json::Map::new();
    for (key, value) in map {
        if matches!(
            key.as_str(),
            "uuid"
                | "tsgId"
                | "name"
                | "createdAt"
                | "updatedAt"
                | "createdByUserId"
                | "updatedByUserId"
        ) {
            continue;
        }
        out.insert(key.clone(), value.clone());
    }
    Some(Value::Object(out))
}

/// Whether the variables of an adapter detail keep `E2E` (the read-modify-write rule).
pub fn keeps_variable(detail: &Value) -> bool {
    detail
        .get("variables")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("key").and_then(Value::as_str) == Some("E2E"))
        })
}

/// The UUID at the end of TypeScript's `✓ Adapter created: <uuid>` line.
pub fn ts_created_id(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let rest = line.split_once("Adapter created:")?.1.trim();
        is_uuid(rest).then(|| rest.to_owned())
    })
}

/// The outcome of a write from its exit and stderr (airs-cli-rs prints the D133 lines;
/// TypeScript fails closed: any non-zero exit but a usage error is `unknown`).
fn outcome(exec: &Exec, rust: bool) -> Outcome {
    match exec.code {
        Some(0) => Outcome::Ok,
        None | Some(130 | 143) => Outcome::Unknown,
        Some(2) => Outcome::Failed,
        Some(_) if rust && !exec.stderr.to_ascii_lowercase().contains("outcome unknown") => {
            if exec
                .stderr
                .lines()
                .any(|line| line.trim_start().starts_with("Outcome: the "))
            {
                Outcome::Ok
            } else {
                Outcome::Failed
            }
        }
        Some(_) => Outcome::Unknown,
    }
}

struct Flow<'s, 'p> {
    session: &'s mut Session<'p>,
    ledger: Ledger,
    names: AdapterNames,
    budget: ResourceBudget,
    /// Every adapter id the run knows it created (or found under a planned name), with
    /// its name.
    ids: BTreeMap<String, String>,
    /// The ids whose delete is confirmed.
    deleted: BTreeSet<String>,
    owned: bool,
}

/// Runs the write flow, then the teardown (always), and returns the summary with its
/// resource counts.
pub fn run_live_redteam_writes(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
    if PLANNED_ADAPTERS > MAX_RESOURCES {
        return Err(LiveAbort::Budget(
            "the planned flow creates more than a live run may".into(),
        ));
    }
    let mut session = Session::open(plan)?;
    let run_id = session.store.run_id().to_owned();
    let ledger = Ledger::open(&plan.store_root, &run_id).map_err(LiveAbort::Setup)?;
    let mut flow = Flow {
        session: &mut session,
        ledger,
        names: AdapterNames::new(&run_id),
        budget: ResourceBudget::default(),
        ids: BTreeMap::new(),
        deleted: BTreeSet::new(),
        owned: false,
    };
    let steps = catch_unwind(AssertUnwindSafe(|| flow.steps()));
    let teardown = catch_unwind(AssertUnwindSafe(|| flow.teardown()));
    drop(flow);
    session.report.store_removed = Some(session.store.remove());
    let steps = steps.unwrap_or_else(|panic| resume_unwind(panic));
    let counts = teardown.unwrap_or_else(|panic| resume_unwind(panic));
    steps?;
    session.report.resources = Some(counts?);
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

impl Flow<'_, '_> {
    fn journal(
        &mut self,
        phase: Phase,
        cli: &'static str,
        op: &'static str,
        name: &str,
        id: Option<&str>,
        (outcome, exit): (Outcome, Option<i32>),
    ) -> Result<(), LiveAbort> {
        self.ledger
            .record(&Entry {
                phase,
                cli,
                op,
                kind: Kind::Adapter,
                name,
                id,
                outcome,
                exit,
                note: "",
            })
            .map_err(LiveAbort::Setup)
    }

    fn row(
        &mut self,
        check: &str,
        rust: Option<&Exec>,
        ts: Option<&Exec>,
        agree: bool,
        note: &str,
    ) {
        let cell = |exec: Option<&Exec>| exec.map_or_else(|| "-".to_owned(), Exec::exit_cell);
        let ran = rust.is_none_or(|exec| exec.code.is_some())
            && ts.is_none_or(|exec| exec.code.is_some());
        self.session.report.rows.push(LiveRow {
            check: check.to_owned(),
            rust_exit: cell(rust),
            ts_exit: cell(ts),
            agree: agree && ran,
            rust_verdict: None,
            ts_verdict: None,
            note: note.to_owned(),
        });
    }

    /// Rust listing of the run's adapters (complete, or the flow stops).
    fn list(&self, check: &str) -> Result<Vec<(String, String)>, LiveAbort> {
        let search = format!("{RESOURCE_PREFIX}{}", self.session.store.run_id());
        let exec = self.session.exec(
            &self.session.plan.rust,
            check,
            &[
                "redteam", "adapter", "list", "--search", &search, "--all", "--max", "0",
                "--output", "json",
            ],
        )?;
        match (exec.code, listed(&exec.json(), Kind::Adapter)) {
            (Some(0), Some(rows)) => Ok(rows),
            _ => Err(LiveAbort::Setup(format!(
                "the adapter listing did not complete (exit {})",
                exec.exit_cell()
            ))),
        }
    }

    fn create(&mut self, rust: bool) -> Result<(Exec, Option<String>), LiveAbort> {
        let name = if rust {
            self.names.rs.clone()
        } else {
            self.names.ts.clone()
        };
        let cli_label = if rust { "rs" } else { "ts" };
        self.budget.reserve()?;
        self.journal(
            Phase::Flow,
            cli_label,
            "adapter create",
            &name,
            None,
            (Outcome::Pending, None),
        )?;
        let script = crate::encoding::base64_encode(PLACEHOLDER_SCRIPT.as_bytes());
        let mut args = vec![
            "redteam",
            "adapter",
            "create",
            "--draft",
            "--name",
            &name,
            "--script-b64",
            &script,
            "--prompt",
            "e2e",
            "--variables",
            VARIABLES,
        ];
        if rust {
            args.extend(["--output", "json"]);
        }
        let cli = if rust {
            &self.session.plan.rust
        } else {
            &self.session.plan.ts
        };
        let exec = self.session.exec(cli, "adapter create", &args)?;
        let id = if rust {
            exec.json()
                .get("uuid")
                .and_then(Value::as_str)
                .filter(|id| is_uuid(id))
                .map(str::to_owned)
        } else {
            ts_created_id(&exec.stdout)
        };
        if let Some(id) = &id {
            self.ids.insert(id.clone(), name.clone());
        }
        self.journal(
            Phase::Flow,
            cli_label,
            "adapter create",
            &name,
            id.as_deref(),
            (outcome(&exec, rust), exec.code),
        )?;
        Ok((exec, id))
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        let existing = self.list("preflight adapter list")?;
        if existing.iter().any(|(_, name)| self.names.planned(name)) {
            return Err(LiveAbort::Setup(
                "a planned adapter name already exists; nothing was created".into(),
            ));
        }
        self.owned = true;
        let (rust_exec, rust_id) = self.create(true)?;
        self.row(
            "adapter create --draft (rs)",
            Some(&rust_exec),
            None,
            rust_exec.code == Some(0) && rust_id.is_some(),
            "draft, no channel",
        );
        let (ts_exec, ts_id) = self.create(false)?;
        self.row(
            "adapter create --draft (ts)",
            None,
            Some(&ts_exec),
            ts_exec.code == Some(0) && ts_id.is_some(),
            "draft, no channel",
        );
        let (Some(rust_id), Some(ts_id)) = (rust_id, ts_id) else {
            return Ok(());
        };
        // Both CLIs read both adapters; the projections agree.
        let mut details = Vec::new();
        for id in [&rust_id, &ts_id] {
            let (rust, ts) = self.session.both(
                "adapter get",
                &["redteam", "adapter", "get", id, "--output", "json"],
            )?;
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && match (
                    adapter_projection(&rust.json()),
                    adapter_projection(&ts.json()),
                ) {
                    (Some(r), Some(t)) => json_semantic_eq(&r, &t),
                    _ => false,
                };
            details.push(adapter_projection(&rust.json()));
            let check = if *id == rust_id {
                "adapter get (rs adapter)"
            } else {
                "adapter get (ts adapter)"
            };
            self.row(
                check,
                Some(&rust),
                Some(&ts),
                agree,
                "projection equal apart from ids, names and times",
            );
        }
        let same_shape =
            matches!((&details[0], &details[1]), (Some(a), Some(b)) if json_semantic_eq(a, b));
        self.session.report.notices.push(format!(
            "the two drafts {} the same projection",
            if same_shape { "have" } else { "do not have" }
        ));
        // Each CLI updates its own draft; the variables are kept (read-modify-write).
        for (rust, id) in [(true, &rust_id), (false, &ts_id)] {
            let cli_label = if rust { "rs" } else { "ts" };
            let name = if rust {
                self.names.rs.clone()
            } else {
                self.names.ts.clone()
            };
            self.journal(
                Phase::Flow,
                cli_label,
                "adapter update",
                &name,
                Some(id),
                (Outcome::Pending, None),
            )?;
            let cli = if rust {
                &self.session.plan.rust
            } else {
                &self.session.plan.ts
            };
            let exec = self.session.exec(
                cli,
                "adapter update",
                &[
                    "redteam",
                    "adapter",
                    "update",
                    id,
                    "--draft",
                    "--description",
                    "e2e-updated",
                    "--prompt",
                    "e2e",
                ],
            )?;
            self.journal(
                Phase::Flow,
                cli_label,
                "adapter update",
                &name,
                Some(id),
                (outcome(&exec, rust), exec.code),
            )?;
            let check = if rust {
                "adapter update (rs)"
            } else {
                "adapter update (ts)"
            };
            if rust {
                self.row(check, Some(&exec), None, exec.code == Some(0), "");
            } else {
                self.row(check, None, Some(&exec), exec.code == Some(0), "");
            }
            let read = self.session.exec(
                &self.session.plan.rust,
                "adapter get after update",
                &["redteam", "adapter", "get", id, "--output", "json"],
            )?;
            let detail = read.json();
            let agree = read.code == Some(0)
                && keeps_variable(&detail)
                && detail.get("description") == Some(&json!("e2e-updated"));
            let check = if rust {
                "adapter get after update (rs)"
            } else {
                "adapter get after update (ts)"
            };
            self.row(
                check,
                Some(&read),
                None,
                agree,
                "variables kept, description updated",
            );
        }
        Ok(())
    }

    fn delete(&mut self, id: &str, name: &str) -> Result<(), LiveAbort> {
        if journalled_delete(
            self.session,
            &mut self.ledger,
            Phase::Teardown,
            (Kind::Adapter, name),
            id,
        )? == Outcome::Ok
        {
            self.deleted.insert(id.to_owned());
        }
        Ok(())
    }

    fn teardown(&mut self) -> Result<ResourceCounts, LiveAbort> {
        if !self.owned {
            return Ok(ResourceCounts::default());
        }
        let mut problem = None;
        let mut listed_ids = BTreeSet::new();
        match self.list("teardown adapter list") {
            Ok(rows) => {
                for (id, name) in rows {
                    if !self.names.planned(&name) || !is_uuid(&id) {
                        continue;
                    }
                    listed_ids.insert(id.clone());
                    self.ids.insert(id.clone(), name.clone());
                    if let Err(abort) = self.delete(&id, &name) {
                        problem.get_or_insert(abort);
                        break;
                    }
                }
            }
            Err(abort) => {
                problem.get_or_insert(abort);
            }
        }
        // The created ids the listing did not show are deleted by their id.
        let missed: Vec<(String, String)> = self
            .ids
            .iter()
            .filter(|(id, _)| !listed_ids.contains(*id) && !self.deleted.contains(*id))
            .map(|(id, name)| (id.clone(), name.clone()))
            .collect();
        if !missed.is_empty() {
            self.session.report.rows.push(LiveRow {
                check: "teardown listing shows every created adapter".to_owned(),
                rust_exit: "-".to_owned(),
                ts_exit: "-".to_owned(),
                agree: false,
                rust_verdict: None,
                ts_verdict: None,
                note: format!("{} not listed; deleted by id", missed.len()),
            });
            if problem.is_none() {
                for (id, name) in &missed {
                    if let Err(abort) = self.delete(id, name) {
                        problem.get_or_insert(abort);
                        break;
                    }
                }
            }
        }
        let mut left: BTreeSet<String> = self
            .ids
            .keys()
            .filter(|id| !self.deleted.contains(*id))
            .cloned()
            .collect();
        match self.list("teardown check") {
            Ok(rows) => {
                for (id, name) in rows {
                    if self.names.planned(&name) {
                        left.insert(id);
                    }
                }
            }
            Err(abort) => {
                problem.get_or_insert(abort);
                if left.is_empty() {
                    // Unverified: never reported as clean.
                    left.insert(String::new());
                }
            }
        }
        let counts = ResourceCounts {
            created: self.ids.len(),
            deleted: self.deleted.len(),
            left: left.len(),
        };
        match problem {
            Some(abort) => {
                self.session.report.resources = Some(counts);
                Err(abort)
            }
            None => Ok(counts),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_carry_the_run_id_and_parse_for_the_sweeper() {
        let names = AdapterNames::new("1792281599-42-0");
        assert_eq!(names.rs, "airs-rs-e2e-1792281599-42-0-adapter-rs");
        assert!(names.planned(&names.ts));
        assert!(!names.planned("airs-rs-e2e-1792281599-42-1-adapter-rs"));
        let parsed = super::super::cleanup::parse_name(&names.ts).unwrap();
        assert_eq!(parsed.kind, Kind::Adapter);
        const { assert!(PLANNED_ADAPTERS <= MAX_RESOURCES) };
    }

    #[test]
    fn the_gate_needs_its_own_opt_in() {
        let lookup = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            }
        };
        assert!(matches!(
            redteam_writes_gate(lookup(&[("AIRS_RS_LIVE", "1"), ("AIRS_E2E_TENANT", "dev")])),
            Ok(LiveGate::Skip(reason)) if reason.contains("redteam writes skipped")
        ));
        assert!(matches!(
            redteam_writes_gate(lookup(&[
                ("AIRS_RS_LIVE", "1"),
                ("AIRS_E2E_TENANT", "dev"),
                ("AIRS_RS_LIVE_REDTEAM_WRITES", "1")
            ])),
            Ok(LiveGate::Run(_))
        ));
    }

    #[test]
    fn projections_and_ids() {
        let a = json!({"uuid": "x", "name": "a", "status": "DRAFT", "createdAt": "t", "variables": [{"key": "E2E"}]});
        let b = json!({"uuid": "y", "name": "b", "status": "DRAFT", "createdAt": "u", "variables": [{"key": "E2E"}]});
        assert_eq!(adapter_projection(&a), adapter_projection(&b));
        assert!(keeps_variable(&a));
        let id = "00000000-0000-4000-8000-000000000581";
        assert_eq!(
            ts_created_id(&format!("\n  ✓ Adapter created: {id}\n")),
            Some(id.to_owned())
        );
        assert_eq!(ts_created_id("  ✓ Adapter created: nope\n"), None);
    }
}
