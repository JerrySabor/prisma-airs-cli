//! The M6d live profile-transfer write flow (DESIGN §10, "M6d Runtime extras", Profile
//! transfer).
//!
//! [`run_live_profile_transfer`] runs only when `tests/live.rs` passes
//! [`profile_transfer_gate`] (`AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and
//! `AIRS_RS_LIVE_PROFILE_TRANSFER=1`), or against the loopback fixture server.
//!
//! # Own resources only
//!
//! The flow creates at most four resources (choice 36 of DESIGN §18.20): the custom topic
//! `airs-rs-e2e-<run id>-topic-rs` (T) and the security profile
//! `airs-rs-e2e-<run id>-profile-rs` (P), created with the Rust `topics create` and
//! `profiles create`, and their two restored copies under the same names (restores never
//! take `--name-prefix`, so the sweeper's topic and profile kinds cover every name). A
//! read-only preflight proves no planned name exists; a [`ResourceBudget`] of
//! [`MAX_RESOURCES`] is checked before each create; every create, apply, restore and
//! delete is journalled to the [`super::ledger`]. Every restore that is not a dry run is a
//! write whatever an earlier dry run planned (it replans on its own): before it runs, a
//! `pending` line and a budget reservation for both copies (T and P), then each copy's
//! outcome from the run's own json rows ([`restore_outcomes`], choice 69), so
//! [`PLANNED_TRANSFER_CREATES`] counts six reservations.
//!
//! # The flow
//!
//! T and P are created, T applied to P; both CLIs back P up into the run's sandbox
//! (read-only on the tenant; the files compared as in the reads); P (every revision) and
//! T are deleted; the Rust restore of the Rust file must plan exactly one topic create and
//! one profile create (T may be reused when it could not be deleted), then restores them
//! with `--expect-tsg <the file's TSG> --force`; the copies are verified; a `--on-conflict
//! verify --dry-run` must plan only `verify` and `reuse`, and only then the real verify
//! re-run (journalled as a write) must create nothing; the Rust restore of the TypeScript
//! file must be refused (D216). The TypeScript restore never runs (choice 35).
//!
//! # Teardown
//!
//! Always, also after an abort or a panic: every id listed under a planned name (all
//! revisions; profiles first) and every id captured from a create or a restore result is
//! deleted with the Rust plain `delete` answered on a pty, journalled. `resourcesLeft`
//! counts every planned name the final listing still shows.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use serde_json::{Value, json};

use super::ledger::{Entry, Kind, Ledger, Outcome, Phase, is_uuid};
use super::writes::{
    MAX_RESOURCES, Names, ResourceBudget, gate_with, journalled_delete, listed, write_outcome,
};
use super::{Exec, LiveAbort, LiveGate, LivePlan, LiveReport, LiveRow, ResourceCounts, Session};
use crate::compare::json_semantic_eq;

/// The creates the flow reserves: T, P, and both copies for each of the two restores
/// that are not dry runs (the restore and the verify re-run, choice 69).
pub const PLANNED_TRANSFER_CREATES: u32 = 6;

const TOPIC_DESCRIPTION: &str = "airs-cli-rs live profile transfer check";
const EXAMPLES: [&str; 2] = [
    "airs-cli-rs live profile transfer example one",
    "airs-cli-rs live profile transfer example two",
];

/// The flow's gate: `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and
/// `AIRS_RS_LIVE_PROFILE_TRANSFER=1`; otherwise `profile transfer skipped`.
pub fn profile_transfer_gate(lookup: impl Fn(&str) -> Option<String>) -> Result<LiveGate, String> {
    gate_with(
        lookup,
        "AIRS_RS_LIVE_PROFILE_TRANSFER",
        "profile transfer skipped",
    )
}

/// Test hooks of the loopback self-tests (none in a live run).
#[derive(Clone, Copy, Debug, Default)]
pub struct TransferHooks {
    /// Called once T and P exist (a self-test panics here to prove the teardown).
    pub after_creates: Option<fn()>,
}

/// Whether a restore's dry-run json plans exactly the run's copies: one profile `create`
/// and one topic `create` (a topic that could not be deleted, `topic_kept`, may also be
/// `reuse`), no DLP mapping or fallback.
pub fn planned_creates(result: &Value, topic_kept: bool) -> bool {
    let topic = actions(result, "topics");
    actions(result, "profiles") == Some(vec!["create".to_owned()])
        && (topic == Some(vec!["create".to_owned()])
            || (topic_kept && topic == Some(vec!["reuse".to_owned()])))
        && rows(result, "dlpMappings").is_some_and(Vec::is_empty)
        && rows(result, "dlpFallbacks").is_some_and(Vec::is_empty)
}

/// Whether a `--on-conflict verify --dry-run` json plans no write: the profile `verify`
/// and the topic `reuse`, nothing else.
pub fn planned_verify(result: &Value) -> bool {
    actions(result, "profiles") == Some(vec!["verify".to_owned()])
        && actions(result, "topics") == Some(vec!["reuse".to_owned()])
        && rows(result, "dlpMappings").is_some_and(Vec::is_empty)
        && rows(result, "dlpFallbacks").is_some_and(Vec::is_empty)
}

fn rows<'v>(result: &'v Value, key: &str) -> Option<&'v Vec<Value>> {
    result.get(key).and_then(Value::as_array)
}

fn actions(result: &Value, key: &str) -> Option<Vec<String>> {
    rows(result, key)?
        .iter()
        .map(|row| row.get("action").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// What one restore run did to one copy, from its json result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyOutcome {
    /// A `created` (or `updated`) row: the copy exists; its UUID when the row has one.
    Created(Option<String>),
    /// A `reused`, `verified` or `skipped` row: the run did not create it.
    NotCreated,
    /// The run certainly did not create it: listed in `notAttempted`, or a run that
    /// exited and wrote nothing.
    Refused,
    /// Anything else: named by `outcomeUnknown`, a run that did not exit, a missing row
    /// in a run that wrote something, or an unreadable result.
    Unknown,
}

/// The outcome of each copy from a restore's json result (`result` is its first element)
/// and exit code. Only a copy the restore definitely did not create is
/// [`CopyOutcome::Refused`]; every doubt is [`CopyOutcome::Unknown`].
pub fn restore_outcomes(
    result: &Value,
    code: Option<i32>,
    copies: &[(Kind, &str)],
) -> Vec<CopyOutcome> {
    let named = |item: &Value, kind: Kind, name: &str| {
        item.get("kind").and_then(Value::as_str) == Some(kind.name())
            && item.get("name").and_then(Value::as_str) == Some(name)
    };
    let wrote = ["topics", "profiles"].iter().any(|key| {
        rows(result, key).is_none_or(|rows| {
            rows.iter().any(|row| {
                matches!(
                    row.get("action").and_then(Value::as_str),
                    Some("created" | "updated")
                )
            })
        })
    }) || !result.get("outcomeUnknown").is_some_and(Value::is_null);
    copies
        .iter()
        .map(|(kind, name)| {
            let key = if *kind == Kind::Topic {
                "topics"
            } else {
                "profiles"
            };
            let row = rows(result, key).and_then(|rows| {
                rows.iter()
                    .find(|row| row.get("name").and_then(Value::as_str) == Some(name))
            });
            if let Some(row) = row {
                return match row.get("action").and_then(Value::as_str) {
                    Some("created" | "updated") => CopyOutcome::Created(
                        row.get("id")
                            .and_then(Value::as_str)
                            .filter(|id| is_uuid(id))
                            .map(str::to_owned),
                    ),
                    Some("reused" | "verified" | "skipped") => CopyOutcome::NotCreated,
                    _ => CopyOutcome::Unknown,
                };
            }
            let unknown = result
                .get("outcomeUnknown")
                .is_some_and(|item| named(item, *kind, name));
            let not_attempted = rows(result, "notAttempted")
                .is_some_and(|items| items.iter().any(|item| named(item, *kind, name)));
            if unknown || code.is_none() {
                CopyOutcome::Unknown
            } else if not_attempted || !wrote {
                CopyOutcome::Refused
            } else {
                CopyOutcome::Unknown
            }
        })
        .collect()
}

/// `policy` with every topic reference to `from` (id) rewritten to `to` (`topic_id`,
/// `revision`).
pub fn rebind_topic(policy: &Value, from: &str, to: (&str, &Value)) -> Value {
    match policy {
        Value::Object(map) => {
            let mut out: serde_json::Map<String, Value> = map
                .iter()
                .map(|(key, child)| (key.clone(), rebind_topic(child, from, to)))
                .collect();
            if map.get("topic_id").and_then(Value::as_str) == Some(from) {
                out.insert("topic_id".into(), json!(to.0));
                out.insert("revision".into(), to.1.clone());
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| rebind_topic(item, from, to))
                .collect(),
        ),
        other => other.clone(),
    }
}

struct Flow<'s, 'p> {
    session: &'s mut Session<'p>,
    ledger: Ledger,
    names: Names,
    budget: ResourceBudget,
    /// Every id seen under a planned name or captured from a create or restore.
    ids: BTreeSet<String>,
    deleted: BTreeSet<String>,
    owned: bool,
    hooks: TransferHooks,
}

/// Runs the flow, then the teardown (always), and returns the summary with its resource
/// counts.
pub fn run_live_profile_transfer(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
    run_live_profile_transfer_with(plan, TransferHooks::default())
}

/// [`run_live_profile_transfer`] with test hooks.
pub fn run_live_profile_transfer_with(
    plan: &LivePlan,
    hooks: TransferHooks,
) -> Result<LiveReport, LiveAbort> {
    if PLANNED_TRANSFER_CREATES > MAX_RESOURCES {
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
        names: Names::new(&run_id),
        budget: ResourceBudget::default(),
        ids: BTreeSet::new(),
        deleted: BTreeSet::new(),
        owned: false,
        hooks,
    };
    let steps = catch_unwind(AssertUnwindSafe(|| flow.steps()));
    let teardown = catch_unwind(AssertUnwindSafe(|| flow.teardown()));
    drop(flow);
    for label in ["rs", "ts"] {
        let _ = std::fs::remove_dir_all(session.sandbox.tmp().join(label));
    }
    session.report.store_removed = Some(session.store.remove());
    let steps = steps.unwrap_or_else(|panic| resume_unwind(panic));
    let counts = teardown.unwrap_or_else(|panic| resume_unwind(panic));
    steps?;
    session.report.resources = Some(counts?);
    session.summary_check()?;
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

impl Flow<'_, '_> {
    fn journal(
        &mut self,
        op: &'static str,
        (kind, name): (Kind, &str),
        id: Option<&str>,
        (outcome, exit): (Outcome, Option<i32>),
    ) -> Result<(), LiveAbort> {
        self.ledger
            .record(&Entry {
                phase: Phase::Flow,
                cli: "rs",
                op,
                kind,
                name,
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
        let ran = rust.code.is_some() && ts.is_none_or(|ts| ts.code.is_some());
        self.session.report.rows.push(LiveRow {
            check: check.to_owned(),
            rust_exit: rust.exit_cell(),
            ts_exit: ts.map_or_else(|| "-".to_owned(), Exec::exit_cell),
            agree: agree && ran,
            rust_verdict: None,
            ts_verdict: None,
            note: note.to_owned(),
        });
    }

    /// The Rust listing of every revision of `kind` (complete, or the flow stops).
    fn list(&self, kind: Kind, check: &str) -> Result<Vec<(String, String)>, LiveAbort> {
        let group = if kind == Kind::Topic {
            "topics"
        } else {
            "profiles"
        };
        let exec = self.rust(
            check,
            &[
                "runtime",
                group,
                "list",
                "--all-versions",
                "--all",
                "--max",
                "0",
                "--output",
                "json",
            ],
        )?;
        match (exec.code, listed(&exec.json(), kind)) {
            (Some(0), Some(rows)) => Ok(rows),
            _ => Err(LiveAbort::Setup(format!(
                "the {group} listing did not complete (exit {})",
                exec.exit_cell()
            ))),
        }
    }

    /// The ids listed under `name`.
    fn ids_named(&self, kind: Kind, name: &str, check: &str) -> Result<Vec<String>, LiveAbort> {
        Ok(self
            .list(kind, check)?
            .into_iter()
            .filter(|(id, listed)| listed == name && is_uuid(id))
            .map(|(id, _)| id)
            .collect())
    }

    /// One journalled Rust write: `pending`, the run, the result line with the id.
    fn write(
        &mut self,
        op: &'static str,
        target: (Kind, &str),
        args: &[&str],
        id_of: fn(&Value) -> Option<String>,
    ) -> Result<(Exec, Option<String>), LiveAbort> {
        self.journal(op, target, None, (Outcome::Pending, None))?;
        let exec = self.rust(op, args)?;
        let id = id_of(&exec.json()).filter(|id| is_uuid(id));
        if let Some(id) = &id {
            self.ids.insert(id.clone());
        }
        self.journal(
            op,
            target,
            id.as_deref(),
            (write_outcome(&exec, super::writes::Side::Rust), exec.code),
        )?;
        Ok((exec, id))
    }

    /// One restore that is not a dry run, journalled as a write whatever an earlier dry
    /// run planned (it replans on its own, choice 69): a budget reservation and a
    /// `pending` line for both copies first; then each copy's outcome from the run's json
    /// rows, a missing UUID resolved from the listing that follows (the teardown deletes
    /// every listed id anyway).
    fn restore_write(
        &mut self,
        op: &'static str,
        check: &str,
        args: &[&str],
    ) -> Result<(Exec, Value), LiveAbort> {
        let names = self.names.clone();
        let copies: [(Kind, &str); 2] = [
            (Kind::Topic, names.topic_rs.as_str()),
            (Kind::Profile, names.profile_rs.as_str()),
        ];
        for (kind, name) in copies {
            self.budget.reserve()?;
            self.journal(op, (kind, name), None, (Outcome::Pending, None))?;
        }
        let exec = self.rust(check, args)?;
        let result = exec.json().get(0).cloned().unwrap_or(Value::Null);
        let outcomes = restore_outcomes(&result, exec.code, &copies);
        for ((kind, name), outcome) in copies.into_iter().zip(outcomes) {
            // The listing after the run: every id under the name is the teardown's.
            let listed = self
                .ids_named(kind, name, "listing after a restore")
                .unwrap_or_default();
            self.ids.extend(listed.iter().cloned());
            let only = || (listed.len() == 1).then(|| listed[0].clone());
            let (id, outcome) = match outcome {
                CopyOutcome::Created(Some(id)) => (Some(id), Outcome::Ok),
                CopyOutcome::Created(None) => match only() {
                    Some(id) => (Some(id), Outcome::Ok),
                    None => (None, Outcome::Unknown),
                },
                CopyOutcome::NotCreated => (None, Outcome::Skipped),
                CopyOutcome::Refused => (None, Outcome::Failed),
                CopyOutcome::Unknown => (only(), Outcome::Unknown),
            };
            if let Some(id) = &id {
                self.ids.insert(id.clone());
            }
            self.journal(op, (kind, name), id.as_deref(), (outcome, exec.code))?;
        }
        Ok((exec, result))
    }

    /// `<sandbox>/tmp/<label>/<file>`.
    fn file_in(&self, label: &str, file: &str) -> Result<String, LiveAbort> {
        let dir = self.session.sandbox.tmp().join(label);
        std::fs::create_dir_all(&dir)
            .map_err(|err| LiveAbort::Setup(format!("cannot create a run directory: {err}")))?;
        Ok(dir.join(file).display().to_string())
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        let names = self.names.clone();
        let (topic, profile) = (names.topic_rs.clone(), names.profile_rs.clone());
        // Preflight (read-only): no planned name exists.
        let topics = self.list(Kind::Topic, "preflight topics list")?;
        let profiles = self.list(Kind::Profile, "preflight profiles list")?;
        if topics
            .iter()
            .chain(&profiles)
            .any(|(_, name)| *name == topic || *name == profile)
        {
            return Err(LiveAbort::Setup(
                "a planned resource name already exists; nothing was created".into(),
            ));
        }
        self.owned = true;
        // T and P, T applied to P.
        self.budget.reserve()?;
        let (exec, topic_id) = self.write(
            "topics create",
            (Kind::Topic, &topic),
            &[
                "runtime",
                "topics",
                "create",
                "--name",
                &topic,
                "--description",
                TOPIC_DESCRIPTION,
                "--examples",
                EXAMPLES[0],
                EXAMPLES[1],
                "--output",
                "json",
            ],
            |doc| {
                doc.get("topicId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            },
        )?;
        self.row(
            "topics create (rs)",
            &exec,
            None,
            exec.code == Some(0) && topic_id.is_some(),
            "run-created name",
        );
        self.budget.reserve()?;
        let (exec, profile_id) = self.write(
            "profiles create",
            (Kind::Profile, &profile),
            &[
                "runtime",
                "profiles",
                "create",
                "--name",
                &profile,
                "--prompt-injection",
                "block",
                "--output",
                "json",
            ],
            |doc| {
                doc.get("profileId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            },
        )?;
        self.row(
            "profiles create (rs)",
            &exec,
            None,
            exec.code == Some(0) && profile_id.is_some(),
            "run-created name",
        );
        let (Some(_), Some(_)) = (topic_id.clone(), profile_id) else {
            return Ok(());
        };
        let (exec, _) = self.write(
            "topics apply",
            (Kind::Profile, &profile),
            &[
                "runtime",
                "topics",
                "apply",
                "--profile",
                &profile,
                "--name",
                &topic,
                "--output",
                "json",
            ],
            |doc| {
                doc.get("profileId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            },
        )?;
        self.row(
            "topics apply (rs)",
            &exec,
            None,
            exec.code == Some(0),
            "own profile",
        );
        if let Some(hook) = self.hooks.after_creates {
            hook();
        }
        // Both CLIs back P up (read-only on the tenant).
        let rust_file = self.file_in("rs", "backup.json")?;
        let ts_file = self.file_in("ts", "backup.json")?;
        let rust = self.rust(
            "profiles backup <own profile> (rs)",
            &[
                "runtime",
                "profiles",
                "backup",
                &profile,
                "--output-file",
                &rust_file,
            ],
        )?;
        let ts = self.session.exec(
            &self.session.plan.ts,
            "profiles backup <own profile> (ts)",
            &[
                "runtime",
                "profiles",
                "backup",
                &profile,
                "--output-file",
                &ts_file,
            ],
        )?;
        let read = |path: &str| -> Option<Value> {
            serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
        };
        let (rust_doc, ts_doc) = (read(&rust_file), read(&ts_file));
        let mode = |path: &str| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path)
                .ok()
                .map(|metadata| metadata.permissions().mode() & 0o777)
        };
        let agree = rust.code == Some(0)
            && ts.code == Some(0)
            && mode(&rust_file) == Some(0o600)
            && mode(&ts_file) == Some(0o600)
            && rust_doc
                .as_ref()
                .zip(ts_doc.as_ref())
                .is_some_and(|(r, t)| super::runtime::backups_agree(r, t));
        self.row(
            "profiles backup <own profile>",
            &rust,
            Some(&ts),
            agree,
            "0600 files; the record and topic keys equal (D215)",
        );
        let Some(backup) = rust_doc.filter(|_| rust.code == Some(0)) else {
            return Ok(());
        };
        let tsg = backup
            .get("tsgId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        // Delete P (every revision), then T.
        for id in self.ids_named(Kind::Profile, &profile, "profiles list before the restore")? {
            self.ids.insert(id.clone());
            self.delete(Kind::Profile, &id, &profile)?;
        }
        let mut topic_kept = false;
        for id in self.ids_named(Kind::Topic, &topic, "topics list before the restore")? {
            self.ids.insert(id.clone());
            self.delete(Kind::Topic, &id, &topic)?;
            if !self.deleted.contains(&id) {
                topic_kept = true;
                self.session.report.notices.push(
                    "the run's topic could not be deleted before the restore; the restore may reuse it".into(),
                );
            }
        }
        // The dry run must plan exactly the copies.
        let dry = self.rust(
            "profiles restore --dry-run (rs)",
            &[
                "runtime",
                "profiles",
                "restore",
                &rust_file,
                "--dry-run",
                "--output",
                "json",
            ],
        )?;
        let planned = dry.code == Some(0)
            && dry
                .json()
                .get(0)
                .is_some_and(|plan| planned_creates(plan, topic_kept));
        self.row(
            "profiles restore --dry-run (rs)",
            &dry,
            None,
            planned,
            if planned {
                "plans exactly the run's copies"
            } else {
                "another plan; nothing restored"
            },
        );
        if !planned {
            return Ok(());
        }
        // The restore: a write for both copies whatever the dry run planned.
        let (restore, result) = self.restore_write(
            "profiles restore",
            "profiles restore (rs)",
            &[
                "runtime",
                "profiles",
                "restore",
                &rust_file,
                "--expect-tsg",
                &tsg,
                "--force",
                "--output",
                "json",
            ],
        )?;
        let complete = restore.code == Some(0) && result.get("complete") == Some(&json!(true));
        self.row(
            "profiles restore (rs)",
            &restore,
            None,
            complete,
            if complete {
                "created once each (D217)"
            } else {
                "the restore did not complete"
            },
        );
        if !complete {
            return Ok(());
        }
        // Verification: one record per name; the policy equal to the backup's apart
        // from the rebound topic.
        let topic_ids = self.ids_named(Kind::Topic, &topic, "topics list after the restore")?;
        let profile_ids =
            self.ids_named(Kind::Profile, &profile, "profiles list after the restore")?;
        self.ids.extend(topic_ids.iter().cloned());
        self.ids.extend(profile_ids.iter().cloned());
        let got_topic = self.rust(
            "topics get <restored>",
            &["runtime", "topics", "get", &topic, "--output", "json"],
        )?;
        let got_profile = self.rust(
            "profiles get <restored>",
            &["runtime", "profiles", "get", &profile, "--output", "json"],
        )?;
        let (topic_doc, profile_doc) = (got_topic.json(), got_profile.json());
        let old_topic = topic_id.unwrap_or_default();
        let expected = backup
            .pointer("/profiles/0/record/policy")
            .zip(topic_doc.get("topicId").and_then(Value::as_str))
            .zip(topic_doc.get("revision"))
            .map(|((policy, id), revision)| rebind_topic(policy, &old_topic, (id, revision)));
        let verified = topic_ids.len() == 1
            && profile_ids.len() == 1
            && got_profile.code == Some(0)
            && expected
                .zip(profile_doc.get("policy"))
                .is_some_and(|(expected, got)| json_semantic_eq(&expected, got));
        self.row(
            "profiles get <restored>",
            &got_profile,
            None,
            verified,
            if verified {
                "one record per name; the policy restored"
            } else {
                "the restored profile differs"
            },
        );
        // A verify re-run creates nothing: its dry run must plan no write before the real
        // run, which is still journalled as a write (it replans on its own).
        let before = (topic_ids.clone(), profile_ids.clone());
        let preview = self.rust(
            "profiles restore --on-conflict verify --dry-run (rs)",
            &[
                "runtime",
                "profiles",
                "restore",
                &rust_file,
                "--on-conflict",
                "verify",
                "--dry-run",
                "--output",
                "json",
            ],
        )?;
        let no_write = preview.code == Some(0) && preview.json().get(0).is_some_and(planned_verify);
        self.row(
            "profiles restore --on-conflict verify --dry-run (rs)",
            &preview,
            None,
            no_write,
            if no_write {
                "plans verify and reuse only"
            } else {
                "another plan; the verify re-run was not run"
            },
        );
        if no_write {
            let (again, doc) = self.restore_write(
                "profiles restore verify",
                "profiles restore --on-conflict verify (rs)",
                &[
                    "runtime",
                    "profiles",
                    "restore",
                    &rust_file,
                    "--on-conflict",
                    "verify",
                    "--expect-tsg",
                    &tsg,
                    "--force",
                    "--output",
                    "json",
                ],
            )?;
            let after = (
                self.ids_named(Kind::Topic, &topic, "topics list after verify")?,
                self.ids_named(Kind::Profile, &profile, "profiles list after verify")?,
            );
            let verify_ok = again.code == Some(0)
                && doc.pointer("/profiles/0/action") == Some(&json!("verified"))
                && doc.pointer("/topics/0/action") == Some(&json!("reused"))
                && before == after;
            self.row(
                "profiles restore --on-conflict verify (rs)",
                &again,
                None,
                verify_ok,
                if verify_ok {
                    "verified and reused; nothing created"
                } else {
                    "the verify re-run changed something"
                },
            );
        }
        // The TypeScript file is refused before the tenant (D216).
        let refused = self.rust(
            "profiles restore <typescript file> (rs)",
            &["runtime", "profiles", "restore", &ts_file, "--dry-run"],
        )?;
        let ok = refused.code == Some(1)
            && refused
                .stderr
                .contains("is a TypeScript airs-cli backup; airs cannot restore it.");
        self.row(
            "profiles restore <typescript file> (rs)",
            &refused,
            None,
            ok,
            "refused (D216)",
        );
        Ok(())
    }

    fn delete(&mut self, kind: Kind, id: &str, name: &str) -> Result<(), LiveAbort> {
        let name = name.to_owned();
        if journalled_delete(
            self.session,
            &mut self.ledger,
            Phase::Flow,
            (kind, &name),
            id,
        )? == Outcome::Ok
        {
            self.deleted.insert(id.to_owned());
        }
        Ok(())
    }

    /// Deletes every id listed under a planned name (profiles first) or captured by the
    /// run, then counts what is left.
    fn teardown(&mut self) -> Result<ResourceCounts, LiveAbort> {
        if !self.owned {
            return Ok(ResourceCounts::default());
        }
        let names = self.names.clone();
        let mut problem = None;
        for (kind, name) in [
            (Kind::Profile, names.profile_rs.clone()),
            (Kind::Topic, names.topic_rs.clone()),
        ] {
            let listed = match self.ids_named(kind, &name, "teardown listing") {
                Ok(ids) => ids,
                Err(abort) => {
                    problem.get_or_insert(abort);
                    continue;
                }
            };
            for id in listed {
                self.ids.insert(id.clone());
                if self.deleted.contains(&id) {
                    continue;
                }
                let phase_name = name.clone();
                match journalled_delete(
                    self.session,
                    &mut self.ledger,
                    Phase::Teardown,
                    (kind, &phase_name),
                    &id,
                ) {
                    Ok(Outcome::Ok) => {
                        self.deleted.insert(id);
                    }
                    Ok(_) => {}
                    Err(abort) => {
                        problem.get_or_insert(abort);
                    }
                }
            }
        }
        let mut left = 0;
        for (kind, name) in [
            (Kind::Profile, names.profile_rs.clone()),
            (Kind::Topic, names.topic_rs.clone()),
        ] {
            match self.ids_named(kind, &name, "teardown check") {
                Ok(ids) => left += ids.len(),
                Err(abort) => {
                    problem.get_or_insert(abort);
                    left = self.ids.len().saturating_sub(self.deleted.len()).max(1);
                    break;
                }
            }
        }
        let counts = ResourceCounts {
            created: self.ids.len(),
            deleted: self.deleted.len(),
            left,
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
    fn the_gate_needs_its_own_opt_in() {
        let lookup = |extra: Option<&'static str>| {
            move |name: &str| match name {
                "AIRS_RS_LIVE" => Some("1".to_owned()),
                "AIRS_E2E_TENANT" => Some("prod".to_owned()),
                "AIRS_RS_LIVE_PROFILE_TRANSFER" => extra.map(str::to_owned),
                _ => None,
            }
        };
        assert!(matches!(
            profile_transfer_gate(lookup(None)),
            Ok(LiveGate::Skip(reason)) if reason.contains("profile transfer skipped")
        ));
        assert!(matches!(
            profile_transfer_gate(lookup(Some("1"))),
            Ok(LiveGate::Run(_))
        ));
        assert!(matches!(
            profile_transfer_gate(lookup(Some("yes"))),
            Ok(LiveGate::Skip(_))
        ));
        const { assert!(PLANNED_TRANSFER_CREATES <= MAX_RESOURCES) };
    }

    #[test]
    fn plans_and_outcomes() {
        let plan = json!({"profiles": [{"name": "p", "action": "create"}],
            "topics": [{"name": "t", "action": "create"}], "dlpMappings": [], "dlpFallbacks": []});
        assert!(planned_creates(&plan, false));
        assert!(
            planned_creates(&plan, true),
            "a kept topic may be gone after all"
        );
        let mut reuse = plan.clone();
        reuse["topics"][0]["action"] = json!("reuse");
        assert!(!planned_creates(&reuse, false));
        assert!(planned_creates(&reuse, true));
        let verify = json!({"profiles": [{"name": "p", "action": "verify"}],
            "topics": [{"name": "t", "action": "reuse"}], "dlpMappings": [], "dlpFallbacks": []});
        assert!(planned_verify(&verify));
        assert!(
            !planned_verify(&plan),
            "a verify run that would create is not run"
        );
        let id = "00000000-0000-4000-8000-000000000901";
        let copies = [(Kind::Topic, "t"), (Kind::Profile, "p")];
        let result = json!({"topics": [{"name": "t", "id": id, "action": "created"}],
            "profiles": [], "outcomeUnknown": {"kind": "profile", "name": "p", "action": "create"},
            "notAttempted": []});
        assert_eq!(
            restore_outcomes(&result, Some(1), &copies),
            [
                CopyOutcome::Created(Some(id.to_owned())),
                CopyOutcome::Unknown
            ]
        );
        // A created row without a UUID still exists (resolved from the listing).
        let result = json!({"topics": [{"name": "t", "action": "created"}],
            "profiles": [{"name": "p", "action": "created", "id": "not-a-uuid"}],
            "outcomeUnknown": null, "notAttempted": []});
        assert_eq!(
            restore_outcomes(&result, Some(0), &copies),
            [CopyOutcome::Created(None), CopyOutcome::Created(None)]
        );
        // A run that wrote the topic and stopped without a row for the profile: unknown;
        // a later item in notAttempted: refused.
        let result = json!({"topics": [{"name": "t", "id": id, "action": "created"}],
            "profiles": [], "outcomeUnknown": null, "notAttempted": []});
        assert_eq!(
            restore_outcomes(&result, Some(1), &copies)[1],
            CopyOutcome::Unknown
        );
        let result = json!({"topics": [], "profiles": [], "outcomeUnknown": null,
            "notAttempted": [{"kind": "profile", "name": "p"}]});
        assert_eq!(
            restore_outcomes(&result, Some(1), &copies),
            [CopyOutcome::Refused, CopyOutcome::Refused],
            "a run that wrote nothing"
        );
        // Reused and verified rows were not created by the run.
        let result = json!({"topics": [{"name": "t", "id": id, "action": "reused"}],
            "profiles": [{"name": "p", "id": id, "action": "verified"}],
            "outcomeUnknown": null, "notAttempted": []});
        assert_eq!(
            restore_outcomes(&result, Some(0), &copies),
            [CopyOutcome::NotCreated, CopyOutcome::NotCreated]
        );
        // An unreadable result or a run that did not exit: unknown.
        assert_eq!(
            restore_outcomes(&Value::Null, Some(1), &copies),
            [CopyOutcome::Unknown, CopyOutcome::Unknown]
        );
        let empty =
            json!({"topics": [], "profiles": [], "outcomeUnknown": null, "notAttempted": []});
        assert_eq!(
            restore_outcomes(&empty, None, &copies),
            [CopyOutcome::Unknown, CopyOutcome::Unknown]
        );
    }

    #[test]
    fn topics_are_rebound_by_id() {
        let policy = json!({"x": [{"topic_id": "old", "topic_name": "t", "revision": 1}, {"topic_id": "other", "revision": 1}]});
        let rebound = rebind_topic(&policy, "old", ("new", &json!(4)));
        assert_eq!(
            rebound["x"][0],
            json!({"topic_id": "new", "topic_name": "t", "revision": 4})
        );
        assert_eq!(rebound["x"][1], policy["x"][1]);
    }
}
