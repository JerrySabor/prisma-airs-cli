//! The M6b live DLP write flow (DESIGN §10, "M6b DLP", Writes).
//!
//! [`run_live_dlp_writes`] runs only when `tests/live.rs` passes [`dlp_writes_gate`]
//! (`AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and `AIRS_RS_LIVE_DLP_WRITES=1`), or against the
//! loopback fixture server.
//!
//! # Own resources only
//!
//! The resource types are the custom data pattern and the custom dictionary: both are
//! deletable and not tenant-wide. Data profiles are never written live (G11: no API can
//! delete one, and a deleted name stays reserved), nor filtering profiles (tenant
//! configuration), nor anything predefined or pre-existing. The flow plans at most six
//! resources ([`DlpNames`]): per CLI `airs-rs-e2e-<run id>-pattern-<rs|ts>` and
//! `-dictionary-<rs|ts>`, and the two Rust-restored copies `-pattern-rr` and
//! `-dictionary-rr`. A [`ResourceBudget`] of [`MAX_RESOURCES`] is checked before each
//! create; every create, patch, replace, restore and delete is journalled to the
//! [`super::ledger`].
//!
//! # The restore
//!
//! Rust only (DESIGN §16.15, choice 26): a read-only `backup --resources
//! dictionaries,patterns` into the run's sandbox, from which the flow composes a backup
//! holding only the run's own Rust pattern and dictionary renamed `pattern-rr` and
//! `dictionary-rr` (the full file is removed at once); a `--dry-run` that must plan
//! exactly their creates; then the restore with `--name-prefix airs-rs-e2e-<run id>-
//! --expect-tsg <the backup's TSG> --force`. Any other plan ends the step with a mismatch
//! and writes nothing.
//!
//! # Teardown
//!
//! Always, also after an abort or a panic: every id listed under a planned name and every
//! id captured from a create or the restore is deleted with the Rust `runtime dlp
//! <group> delete <id> --force`; a Rust `get` of each must then show `status: deleted`
//! or answer 404 (pattern deletes are soft, choice 27). A listing that misses a created id
//! is a mismatch row, and the id is still deleted. `resourcesLeft` counts every created id
//! not confirmed deleted.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use serde_json::{Value, json};

use super::ledger::{Entry, Kind, Ledger, Outcome, Phase, is_dlp_id};
use super::writes::{
    MAX_RESOURCES, RESOURCE_PREFIX, ResourceBudget, gate_with, journalled_delete, listed,
    ts_rejected,
};
use super::{Exec, LiveAbort, LiveGate, LivePlan, LiveReport, LiveRow, ResourceCounts, Session};
use crate::compare::{json_semantic_eq, split_outcome_lines};

/// Creates the flow plans (a pattern and a dictionary per CLI, two restored copies).
pub const PLANNED_DLP_CREATES: u32 = 6;

/// The synthetic regex of the created patterns, and the one their replace sets.
pub const REGEX: &str = "airs-rs-e2e-[0-9]{6}";
pub const REPLACED_REGEX: &str = "airs-rs-e2e-[0-9]{7}";

/// The synthetic keyword files.
pub const KEYWORDS: &str = "airs-rs-e2e-kw-1\nairs-rs-e2e-kw-2\n";
pub const REPLACED_KEYWORDS: &str = "airs-rs-e2e-kw-3\nairs-rs-e2e-kw-4\n";

/// The write flow's gate: `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and
/// `AIRS_RS_LIVE_DLP_WRITES=1`; otherwise `dlp writes skipped`.
pub fn dlp_writes_gate(lookup: impl Fn(&str) -> Option<String>) -> Result<LiveGate, String> {
    gate_with(lookup, "AIRS_RS_LIVE_DLP_WRITES", "dlp writes skipped")
}

/// The planned resource names of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DlpNames {
    pub pattern_rs: String,
    pub pattern_ts: String,
    pub dictionary_rs: String,
    pub dictionary_ts: String,
    pub pattern_rr: String,
    pub dictionary_rr: String,
    /// `airs-rs-e2e-<run id>-` (the restore's `--name-prefix`).
    pub prefix: String,
}

impl DlpNames {
    /// `airs-rs-e2e-<run id>-<kind>-<cli>`.
    pub fn new(run_id: &str) -> Self {
        let prefix = format!("{RESOURCE_PREFIX}{run_id}-");
        let name = |suffix: &str| format!("{prefix}{suffix}");
        Self {
            pattern_rs: name("pattern-rs"),
            pattern_ts: name("pattern-ts"),
            dictionary_rs: name("dictionary-rs"),
            dictionary_ts: name("dictionary-ts"),
            pattern_rr: name("pattern-rr"),
            dictionary_rr: name("dictionary-rr"),
            prefix,
        }
    }

    /// The kind of a planned name.
    pub fn kind_of(&self, name: &str) -> Option<Kind> {
        if [&self.pattern_rs, &self.pattern_ts, &self.pattern_rr].contains(&&name.to_owned()) {
            Some(Kind::Pattern)
        } else if [
            &self.dictionary_rs,
            &self.dictionary_ts,
            &self.dictionary_rr,
        ]
        .contains(&&name.to_owned())
        {
            Some(Kind::Dictionary)
        } else {
            None
        }
    }
}

/// The `regionName` of the first row of a dictionaries listing.
pub fn region_of(listing: &Value) -> Option<String> {
    listing
        .as_array()?
        .first()?
        .get("regionName")?
        .as_str()
        .filter(|region| !region.trim().is_empty())
        .map(str::to_owned)
}

/// The JSON document of a run's stdout without TypeScript's outcome lines (D172).
fn document(exec: &Exec) -> Value {
    let (_, rest) = split_outcome_lines(&exec.stdout);
    serde_json::from_str(&rest).unwrap_or(Value::Null)
}

/// The run-independent fields of a pattern or dictionary record (`--output json`): ids,
/// names, versions, timestamps and user ids dropped.
pub fn record_projection(record: &Value) -> Option<Value> {
    let map = record.as_object()?;
    Some(Value::Object(
        map.iter()
            .filter(|(key, _)| !matches!(key.as_str(), "id" | "name" | "version" | "auditMetadata"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}

/// Composes the restore's backup from a Rust `backup` file: only the entries with the
/// given ids, renamed (entry and record) to the given bare names, complete, without
/// profiles. `None` when an id is not in the file.
pub fn own_backup(full: &Value, wanted: &[(&str, Kind, &str)]) -> Option<Value> {
    let mut doc = full.clone();
    let mut dictionaries = Vec::new();
    let mut patterns = Vec::new();
    for (id, kind, name) in wanted {
        let key = if *kind == Kind::Pattern {
            "patterns"
        } else {
            "dictionaries"
        };
        let mut entry = full
            .get(key)?
            .as_array()?
            .iter()
            .find(|entry| entry.get("id").and_then(Value::as_str) == Some(id))?
            .clone();
        entry["name"] = json!(name);
        entry["record"]["name"] = json!(name);
        if *kind == Kind::Pattern {
            patterns.push(entry);
        } else {
            dictionaries.push(entry);
        }
    }
    doc["dictionaries"] = Value::Array(dictionaries);
    doc["patterns"] = Value::Array(patterns);
    doc["profiles"] = json!([]);
    doc["skipped"] = json!([]);
    doc["failed"] = json!([]);
    doc["complete"] = json!(true);
    doc["resources"] = json!(["dictionaries", "patterns"]);
    Some(doc)
}

/// Whether a dry-run result plans exactly `creates` creates and nothing else.
pub fn only_creates(result: &Value, dictionaries: usize, patterns: usize) -> bool {
    let rows = |key: &str| result.get(key).and_then(Value::as_array).cloned();
    let all_create = |rows: &[Value]| {
        rows.iter()
            .all(|row| row.get("action") == Some(&json!("create")))
    };
    match (
        rows("dictionaries"),
        rows("patterns"),
        rows("profiles"),
        rows("unresolved"),
    ) {
        (Some(d), Some(p), Some(f), Some(u)) => {
            d.len() == dictionaries
                && p.len() == patterns
                && f.is_empty()
                && u.is_empty()
                && all_create(&d)
                && all_create(&p)
        }
        _ => false,
    }
}

/// The outcome of a write from its exit and stderr. airs-cli-rs prints the D160 lines,
/// and its exit 2 is a usage error refused before any request. TypeScript fails closed:
/// its `patterns create|replace|patch` exit 2 for every failure, HTTP 5xx and network
/// errors included (TD§2.4), so a non-zero exit is `failed` only when stderr names a
/// definite rejection ([`ts_definitely_rejected`]), else `unknown`.
fn outcome(exec: &Exec, rust: bool) -> Outcome {
    match exec.code {
        Some(0) => Outcome::Ok,
        None | Some(130 | 143) => Outcome::Unknown,
        Some(2) if rust => Outcome::Failed,
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
        Some(_) if !rust && ts_definitely_rejected(&exec.stderr) => Outcome::Failed,
        Some(_) => Outcome::Unknown,
    }
}

/// Whether TypeScript's stderr names a definite rejection: the `HTTP <4xx>` line of its
/// error block ([`ts_rejected`]) or, for the commands that print the bare SDK message,
/// `API error <4xx>`; 404, 408, 409 and 429 excepted in both.
fn ts_definitely_rejected(stderr: &str) -> bool {
    const MARK: &str = "API error ";
    ts_rejected(stderr)
        || stderr.match_indices(MARK).any(|(at, _)| {
            let rest = &stderr[at + MARK.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.len() == 3
                && digits.parse::<u16>().is_ok_and(|status| {
                    (400..500).contains(&status) && !matches!(status, 404 | 408 | 409 | 429)
                })
        })
}

/// The journal of each restored copy from the restore's json result: a `created` row
/// with its id is `ok`; a copy in `unverifiedCreates` (created, its read-back failed) or
/// in `outcomeUnknown`, or any copy of a run that did not exit, is `unknown` (with the id
/// when one is known); anything else was not created (`failed`).
pub fn restore_outcomes(
    result: &Value,
    code: Option<i32>,
    copies: &[(Kind, String)],
) -> Vec<(Option<String>, Outcome)> {
    let unknown = result
        .get("outcomeUnknown")
        .and_then(|item| item.get("name"))
        .and_then(Value::as_str);
    let with_name = |rows: Option<&Value>, name: &str| -> Option<String> {
        rows.and_then(Value::as_array)?
            .iter()
            .find(|row| row.get("name").and_then(Value::as_str) == Some(name))?
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_dlp_id(id))
            .map(str::to_owned)
    };
    copies
        .iter()
        .map(|(kind, name)| {
            if let Some(id) = with_name(result.get(group(*kind)), name) {
                return (Some(id), Outcome::Ok);
            }
            let unverified = result
                .get("unverifiedCreates")
                .and_then(Value::as_array)
                .and_then(|rows| {
                    rows.iter().find(|row| {
                        row.get("kind").and_then(Value::as_str) == Some(group(*kind))
                            && row.get("name").and_then(Value::as_str) == Some(name.as_str())
                    })
                })
                .and_then(|row| row.get("id"))
                .and_then(Value::as_str)
                .filter(|id| is_dlp_id(id))
                .map(str::to_owned);
            match unverified {
                Some(id) => (Some(id), Outcome::Unknown),
                None if unknown == Some(name.as_str()) || code.is_none() => {
                    (None, Outcome::Unknown)
                }
                None => (None, Outcome::Failed),
            }
        })
        .collect()
}

/// Settings of the write flow: the dictionary region when no dictionary lists one
/// (`AIRS_E2E_DLP_REGION`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DlpWriteSettings {
    pub region: Option<String>,
}

struct Flow<'s, 'p> {
    session: &'s mut Session<'p>,
    ledger: Ledger,
    names: DlpNames,
    budget: ResourceBudget,
    /// Every id the run knows it created (or found under a planned name).
    ids: BTreeMap<String, (Kind, String)>,
    /// The ids whose delete is confirmed.
    deleted: BTreeSet<String>,
    owned: bool,
}

/// Runs the write flow, then the teardown (always), and returns the summary with its
/// resource counts.
pub fn run_live_dlp_writes(
    plan: &LivePlan,
    settings: &DlpWriteSettings,
) -> Result<LiveReport, LiveAbort> {
    if PLANNED_DLP_CREATES > MAX_RESOURCES {
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
        names: DlpNames::new(&run_id),
        budget: ResourceBudget::default(),
        ids: BTreeMap::new(),
        deleted: BTreeSet::new(),
        owned: false,
    };
    let steps = catch_unwind(AssertUnwindSafe(|| flow.steps(settings)));
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

fn group(kind: Kind) -> &'static str {
    if kind == Kind::Pattern {
        "patterns"
    } else {
        "dictionaries"
    }
}

impl Flow<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    fn journal(
        &mut self,
        phase: Phase,
        cli: &'static str,
        op: &'static str,
        kind: Kind,
        name: &str,
        id: Option<&str>,
        (outcome, exit): (Outcome, Option<i32>),
    ) -> Result<(), LiveAbort> {
        self.ledger
            .record(&Entry {
                phase,
                cli,
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

    fn rust(&self, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        self.session.exec(&self.session.plan.rust, check, args)
    }

    /// The Rust custom-only listing of `kind`, every page: `(id, name, status)`.
    fn list(&self, kind: Kind, check: &str) -> Result<Vec<(String, String, String)>, LiveAbort> {
        let exec = self.rust(
            check,
            &[
                "runtime",
                "dlp",
                group(kind),
                "list",
                "--all",
                "--max",
                "0",
                "--output",
                "json",
            ],
        )?;
        let json = exec.json();
        match (exec.code, listed(&json, kind)) {
            (Some(0), Some(rows)) => Ok(rows
                .into_iter()
                .enumerate()
                .map(|(index, (id, name))| {
                    let status = json[index]
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    (id, name, status)
                })
                .collect()),
            _ => Err(LiveAbort::Setup(format!(
                "the {} listing did not complete (exit {})",
                group(kind),
                exec.exit_cell()
            ))),
        }
    }

    /// One create on `rust` or TypeScript; the id from its JSON ack.
    fn create(
        &mut self,
        kind: Kind,
        rust: bool,
        name: &str,
        args: &[&str],
    ) -> Result<(Exec, Option<String>), LiveAbort> {
        let cli_label = if rust { "rs" } else { "ts" };
        let op = if kind == Kind::Pattern {
            "patterns create"
        } else {
            "dictionaries create"
        };
        self.budget.reserve()?;
        self.journal(
            Phase::Flow,
            cli_label,
            op,
            kind,
            name,
            None,
            (Outcome::Pending, None),
        )?;
        let cli = if rust {
            &self.session.plan.rust
        } else {
            &self.session.plan.ts
        };
        let exec = self.session.exec(cli, op, args)?;
        let id = document(&exec)
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_dlp_id(id))
            .map(str::to_owned);
        if let Some(id) = &id {
            self.ids.insert(id.clone(), (kind, name.to_owned()));
        }
        self.journal(
            Phase::Flow,
            cli_label,
            op,
            kind,
            name,
            id.as_deref(),
            (outcome(&exec, rust), exec.code),
        )?;
        let check = format!("dlp {op} ({cli_label})");
        if rust {
            self.row(
                &check,
                Some(&exec),
                None,
                exec.code == Some(0) && id.is_some(),
                "run-created name",
            );
        } else {
            self.row(
                &check,
                None,
                Some(&exec),
                exec.code == Some(0) && id.is_some(),
                "run-created name",
            );
        }
        Ok((exec, id))
    }

    /// A journalled patch or replace of the run's own record on one CLI.
    #[allow(clippy::too_many_arguments)]
    fn change(
        &mut self,
        kind: Kind,
        rust: bool,
        op: &'static str,
        name: &str,
        id: &str,
        args: &[&str],
    ) -> Result<Exec, LiveAbort> {
        let cli_label = if rust { "rs" } else { "ts" };
        self.journal(
            Phase::Flow,
            cli_label,
            op,
            kind,
            name,
            Some(id),
            (Outcome::Pending, None),
        )?;
        let cli = if rust {
            &self.session.plan.rust
        } else {
            &self.session.plan.ts
        };
        let exec = self.session.exec(cli, op, args)?;
        self.journal(
            Phase::Flow,
            cli_label,
            op,
            kind,
            name,
            Some(id),
            (outcome(&exec, rust), exec.code),
        )?;
        let check = format!("dlp {op} ({cli_label})");
        if rust {
            self.row(
                &check,
                Some(&exec),
                None,
                exec.code == Some(0),
                "own record",
            );
        } else {
            self.row(
                &check,
                None,
                Some(&exec),
                exec.code == Some(0),
                "own record",
            );
        }
        Ok(exec)
    }

    /// The Rust `get` of an own record (`--output json`).
    fn get(&self, kind: Kind, id: &str, keywords: bool) -> Result<(Exec, Value), LiveAbort> {
        let mut args = vec!["runtime", "dlp", group(kind), "get", id];
        if keywords {
            args.push("--keywords");
        }
        args.extend(["--output", "json"]);
        let exec = self.rust("dlp get (own)", &args)?;
        let json = exec.json();
        Ok((exec, json))
    }

    fn file(&self, name: &str, text: &str) -> Result<String, LiveAbort> {
        let path = self.session.sandbox.tmp().join(name);
        std::fs::write(&path, text)
            .map_err(|err| LiveAbort::Setup(format!("cannot write a flow file: {err}")))?;
        Ok(path.display().to_string())
    }

    fn steps(&mut self, settings: &DlpWriteSettings) -> Result<(), LiveAbort> {
        // Preflight (read-only): DLP access, no planned name exists, the region.
        let probe = self.rust(
            "preflight dlp patterns list",
            &[
                "runtime", "dlp", "patterns", "list", "--all", "--max", "0", "--output", "json",
            ],
        )?;
        if super::redteam::no_access(probe.code, &probe.stderr) {
            self.session.report.notices.push(
                "dlp unavailable: the tenant has no DLP access (HTTP 401, 403 or 404); the DLP writes were not run".into(),
            );
            return Ok(());
        }
        for kind in [Kind::Pattern, Kind::Dictionary] {
            let rows = self.list(kind, "preflight dlp listing")?;
            if rows
                .iter()
                .any(|(_, name, _)| self.names.kind_of(name).is_some())
            {
                return Err(LiveAbort::Setup(
                    "a planned DLP name already exists; nothing was created".into(),
                ));
            }
        }
        let regions = self.rust(
            "dlp dictionaries list --include-predefined --limit 1",
            &[
                "runtime",
                "dlp",
                "dictionaries",
                "list",
                "--include-predefined",
                "--limit",
                "1",
                "--output",
                "json",
            ],
        )?;
        let region = region_of(&regions.json()).or_else(|| settings.region.clone());
        self.owned = true;
        let mut own: Vec<(String, Kind, &'static str)> = Vec::new();
        for rust in [true, false] {
            if let Some(id) = self.pattern_steps(rust)?
                && rust
            {
                own.push((id, Kind::Pattern, "pattern-rr"));
            }
        }
        match &region {
            Some(region) => {
                for rust in [true, false] {
                    if let Some(id) = self.dictionary_steps(rust, region)?
                        && rust
                    {
                        own.push((id, Kind::Dictionary, "dictionary-rr"));
                    }
                }
            }
            None => {
                self.session
                    .report
                    .notices
                    .push("no DLP region known; dictionary writes skipped".into());
            }
        }
        if own.is_empty() {
            self.session
                .report
                .notices
                .push("the restore step was skipped: no own Rust record was created".into());
            return Ok(());
        }
        self.restore_step(&own)
    }

    fn pattern_steps(&mut self, rust: bool) -> Result<Option<String>, LiveAbort> {
        let cli_label = if rust { "rs" } else { "ts" };
        let name = if rust {
            self.names.pattern_rs.clone()
        } else {
            self.names.pattern_ts.clone()
        };
        let (_, id) = self.create(
            Kind::Pattern,
            rust,
            &name,
            &[
                "runtime",
                "dlp",
                "patterns",
                "create",
                "--name",
                &name,
                "--regex",
                REGEX,
                "--description",
                "e2e",
                "--output",
                "json",
            ],
        )?;
        let Some(id) = id else {
            return Ok(None);
        };
        // Both CLIs read it; the documents agree (D171 data keys).
        let (r, t) = self.session.both(
            "dlp patterns get",
            &["runtime", "dlp", "patterns", "get", &id, "--output", "json"],
        )?;
        let agree = r.code == Some(0)
            && t.code == Some(0)
            && json_semantic_eq(&super::dlp::ts_camel_data_keys(&r.json()), &t.json());
        self.row(
            &format!("dlp patterns get ({cli_label} pattern)"),
            Some(&r),
            Some(&t),
            agree,
            "json equal (D171 data keys)",
        );
        let set_name = format!("name={name}");
        self.change(
            Kind::Pattern,
            rust,
            "patterns patch",
            &name,
            &id,
            &[
                "runtime",
                "dlp",
                "patterns",
                "patch",
                &id,
                "--set",
                &set_name,
                "--set",
                "type=custom",
                "--set",
                r#"detection_config={"technique":"regex"}"#,
                "--set",
                "description=e2e-patched",
            ],
        )?;
        let (exec, record) = self.get(Kind::Pattern, &id, false)?;
        let patched = record.get("description") == Some(&json!("e2e-patched"));
        self.row(
            &format!("dlp patterns get after patch ({cli_label})"),
            Some(&exec),
            None,
            exec.code == Some(0) && patched,
            "description patched",
        );
        let body = json!({"name": name, "type": "custom", "description": "e2e-replaced",
            "detection_config": {"technique": "regex"},
            "matching_rules": {"regexes": [{"regex": REPLACED_REGEX, "weight": 1}]}});
        let body_file = self.file(&format!("pattern-{cli_label}.json"), &body.to_string())?;
        let mut args = vec![
            "runtime",
            "dlp",
            "patterns",
            "replace",
            id.as_str(),
            "--body-file",
            body_file.as_str(),
        ];
        if rust {
            args.push("--force");
        }
        self.change(Kind::Pattern, rust, "patterns replace", &name, &id, &args)?;
        let (exec, record) = self.get(Kind::Pattern, &id, false)?;
        let replaced = record.get("description") == Some(&json!("e2e-replaced"))
            && record
                .pointer("/matchingRules/regexes/0/regex")
                .and_then(Value::as_str)
                == Some(REPLACED_REGEX);
        self.row(
            &format!("dlp patterns get after replace ({cli_label})"),
            Some(&exec),
            None,
            exec.code == Some(0) && replaced,
            "both changes",
        );
        Ok(Some(id))
    }

    fn dictionary_steps(&mut self, rust: bool, region: &str) -> Result<Option<String>, LiveAbort> {
        let cli_label = if rust { "rs" } else { "ts" };
        let name = if rust {
            self.names.dictionary_rs.clone()
        } else {
            self.names.dictionary_ts.clone()
        };
        let keywords = self.file("kw.txt", KEYWORDS)?;
        let replaced = self.file("kw2.txt", REPLACED_KEYWORDS)?;
        let (_, id) = self.create(
            Kind::Dictionary,
            rust,
            &name,
            &[
                "runtime",
                "dlp",
                "dictionaries",
                "create",
                "--name",
                &name,
                "--category",
                "Confidential",
                "--region",
                region,
                "--file",
                &keywords,
                "--output",
                "json",
            ],
        )?;
        let Some(id) = id else {
            return Ok(None);
        };
        // Rust only: the keyword count (TypeScript would print the list too).
        let (exec, record) = self.get(Kind::Dictionary, &id, true)?;
        let count = record
            .get("keywords")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        self.row(
            &format!("dlp dictionaries get --keywords ({cli_label} dictionary)"),
            Some(&exec),
            None,
            exec.code == Some(0) && count == 2,
            "keyword count 2 (in memory)",
        );
        let set_name = format!("name={name}");
        self.change(
            Kind::Dictionary,
            rust,
            "dictionaries patch",
            &name,
            &id,
            &[
                "runtime",
                "dlp",
                "dictionaries",
                "patch",
                &id,
                "--set",
                &set_name,
                "--set",
                "category=Confidential",
                "--set",
                "original_file_name=kw.txt",
                "--set",
                "description=e2e-patched",
            ],
        )?;
        let mut args = vec![
            "runtime",
            "dlp",
            "dictionaries",
            "replace",
            id.as_str(),
            "--name",
            name.as_str(),
            "--category",
            "Confidential",
            "--region",
            region,
            "--file",
            replaced.as_str(),
        ];
        if rust {
            args.push("--force");
        }
        self.change(
            Kind::Dictionary,
            rust,
            "dictionaries replace",
            &name,
            &id,
            &args,
        )?;
        Ok(Some(id))
    }

    fn restore_step(&mut self, own: &[(String, Kind, &'static str)]) -> Result<(), LiveAbort> {
        let full = self.session.sandbox.tmp().join("full.json");
        let full_text = full.display().to_string();
        let exec = self.rust(
            "dlp backup (rs)",
            &[
                "runtime",
                "dlp",
                "backup",
                "--resources",
                "dictionaries,patterns",
                "--output-file",
                &full_text,
            ],
        )?;
        let doc: Value = std::fs::read_to_string(&full)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(Value::Null);
        let _ = std::fs::remove_file(&full);
        let wanted: Vec<(&str, Kind, &str)> = own
            .iter()
            .map(|(id, kind, name)| (id.as_str(), *kind, *name))
            .collect();
        let composed = own_backup(&doc, &wanted);
        self.row(
            "dlp backup --resources dictionaries,patterns (rs)",
            Some(&exec),
            None,
            matches!(exec.code, Some(0 | 1)) && composed.is_some(),
            "read-only; holds the run's own records",
        );
        let Some(composed) = composed else {
            return Ok(());
        };
        let tsg = doc
            .get("tsgId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let own_file = self.file("own.json", &composed.to_string())?;
        let prefix = self.names.prefix.clone();
        let dictionaries = own
            .iter()
            .filter(|(_, kind, _)| *kind == Kind::Dictionary)
            .count();
        let patterns = own.len() - dictionaries;
        let dry = self.rust(
            "dlp restore --dry-run (rs)",
            &[
                "runtime",
                "dlp",
                "restore",
                &own_file,
                "--name-prefix",
                &prefix,
                "--dry-run",
                "--output",
                "json",
            ],
        )?;
        let planned = dry.code == Some(0) && only_creates(&dry.json()[0], dictionaries, patterns);
        self.row(
            "dlp restore --dry-run (rs)",
            Some(&dry),
            None,
            planned,
            "plans exactly the creates of the run's own copies",
        );
        if !planned {
            return Ok(());
        }
        let copies: Vec<(Kind, String)> = own
            .iter()
            .map(|(_, kind, name)| (*kind, format!("{prefix}{name}")))
            .collect();
        for (kind, name) in &copies {
            self.budget.reserve()?;
            self.journal(
                Phase::Flow,
                "rs",
                "dlp restore",
                *kind,
                name,
                None,
                (Outcome::Pending, None),
            )?;
        }
        let exec = self.rust(
            "dlp restore (rs)",
            &[
                "runtime",
                "dlp",
                "restore",
                &own_file,
                "--name-prefix",
                &prefix,
                "--expect-tsg",
                &tsg,
                "--force",
                "--output",
                "json",
            ],
        )?;
        let result = exec.json()[0].clone();
        let outcomes = restore_outcomes(&result, exec.code, &copies);
        let mut created = 0;
        for ((kind, name), (id, state)) in copies.iter().zip(outcomes) {
            if state == Outcome::Ok {
                created += 1;
            }
            if let Some(id) = &id {
                self.ids.insert(id.clone(), (*kind, name.clone()));
            }
            self.journal(
                Phase::Flow,
                "rs",
                "dlp restore",
                *kind,
                name,
                id.as_deref(),
                (state, exec.code),
            )?;
        }
        self.row(
            "dlp restore (rs)",
            Some(&exec),
            None,
            exec.code == Some(0) && created == copies.len(),
            "prefixed copies of the run's own records",
        );
        Ok(())
    }

    fn delete(&mut self, kind: Kind, id: &str, name: &str) -> Result<(), LiveAbort> {
        journalled_delete(
            self.session,
            &mut self.ledger,
            Phase::Teardown,
            (kind, name),
            id,
        )?;
        Ok(())
    }

    /// A Rust `get` shows the id deleted (`status: deleted`) or gone (HTTP 404).
    fn confirmed_deleted(&self, kind: Kind, id: &str) -> Result<bool, LiveAbort> {
        let (exec, record) = self.get(kind, id, false)?;
        Ok(match exec.code {
            Some(0) => record.get("status") == Some(&json!("deleted")),
            Some(1) => exec.stderr.lines().any(|line| line.trim() == "HTTP 404"),
            _ => false,
        })
    }

    fn teardown(&mut self) -> Result<ResourceCounts, LiveAbort> {
        if !self.owned {
            return Ok(ResourceCounts::default());
        }
        let mut problem: Option<LiveAbort> = None;
        let mut listed_ids = BTreeSet::new();
        for kind in [Kind::Pattern, Kind::Dictionary] {
            match self.list(kind, "teardown dlp listing") {
                Ok(rows) => {
                    for (id, name, status) in rows {
                        if self.names.kind_of(&name) != Some(kind) || !is_dlp_id(&id) {
                            continue;
                        }
                        listed_ids.insert(id.clone());
                        self.ids.entry(id.clone()).or_insert((kind, name.clone()));
                        if status == "deleted" {
                            continue;
                        }
                        if let Err(abort) = self.delete(kind, &id, &name) {
                            problem.get_or_insert(abort);
                        }
                    }
                }
                Err(abort) => {
                    problem.get_or_insert(abort);
                }
            }
        }
        let missed: Vec<(String, Kind, String)> = self
            .ids
            .iter()
            .filter(|(id, _)| !listed_ids.contains(*id))
            .map(|(id, (kind, name))| (id.clone(), *kind, name.clone()))
            .collect();
        if !missed.is_empty() {
            self.session.report.rows.push(LiveRow {
                check: "teardown listing shows every created DLP record".to_owned(),
                rust_exit: "-".to_owned(),
                ts_exit: "-".to_owned(),
                agree: false,
                rust_verdict: None,
                ts_verdict: None,
                note: format!("{} not listed; deleted by id", missed.len()),
            });
            for (id, kind, name) in &missed {
                if let Err(abort) = self.delete(*kind, id, name) {
                    problem.get_or_insert(abort);
                }
            }
        }
        let known: Vec<(String, Kind)> = self
            .ids
            .iter()
            .map(|(id, (kind, _))| (id.clone(), *kind))
            .collect();
        for (id, kind) in known {
            match self.confirmed_deleted(kind, &id) {
                Ok(true) => {
                    self.deleted.insert(id);
                }
                Ok(false) => {}
                Err(abort) => {
                    problem.get_or_insert(abort);
                }
            }
        }
        let left = self.ids.len() - self.deleted.len();
        self.session.report.rows.push(LiveRow {
            check: "teardown every created DLP record reads back deleted".to_owned(),
            rust_exit: "-".to_owned(),
            ts_exit: "-".to_owned(),
            agree: left == 0,
            rust_verdict: None,
            ts_verdict: None,
            note: format!(
                "{} of {} confirmed (status deleted or 404)",
                self.deleted.len(),
                self.ids.len()
            ),
        });
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
    fn names_carry_the_run_id_and_parse_for_the_sweeper() {
        let names = DlpNames::new("1792281599-42-0");
        assert_eq!(names.pattern_rs, "airs-rs-e2e-1792281599-42-0-pattern-rs");
        assert_eq!(names.prefix, "airs-rs-e2e-1792281599-42-0-");
        assert_eq!(names.kind_of(&names.dictionary_rr), Some(Kind::Dictionary));
        assert_eq!(names.kind_of(&names.pattern_ts), Some(Kind::Pattern));
        assert_eq!(
            names.kind_of("airs-rs-e2e-1792281599-42-1-pattern-rs"),
            None
        );
        for name in [&names.pattern_rr, &names.dictionary_ts] {
            assert!(super::super::cleanup::parse_name(name).is_some(), "{name}");
        }
        const { assert!(PLANNED_DLP_CREATES <= MAX_RESOURCES) };
    }

    fn exec(code: Option<i32>, stderr: &str) -> Exec {
        Exec {
            code,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            elapsed: std::time::Duration::ZERO,
        }
    }

    /// The ledger records `failed` only for a write certainly not applied: TypeScript's
    /// exit 2 covers 5xx and network failures of the pattern writes (TD§2.4).
    #[test]
    fn write_outcomes_fail_closed() {
        fn ts(code: Option<i32>, stderr: &str) -> Outcome {
            outcome(&exec(code, stderr), false)
        }
        fn rs(code: Option<i32>, stderr: &str) -> Outcome {
            outcome(&exec(code, stderr), true)
        }
        assert_eq!(ts(Some(0), ""), Outcome::Ok);
        assert_eq!(
            ts(
                Some(2),
                "\n  ✗ AISEC_SERVER_SIDE_ERROR:API error 500; Internal Server Error; [withheld]\n\n"
            ),
            Outcome::Unknown
        );
        assert_eq!(ts(Some(2), "\n  ✗ fetch failed\n\n"), Outcome::Unknown);
        assert_eq!(
            ts(
                Some(2),
                "\n  ✗ AISEC_CLIENT_SIDE_ERROR:API error 400; Bad Request\n\n"
            ),
            Outcome::Failed
        );
        for status in [404, 408, 409, 429] {
            assert_eq!(
                ts(
                    Some(2),
                    &format!("\n  ✗ AISEC_CLIENT_SIDE_ERROR:API error {status}\n\n")
                ),
                Outcome::Unknown,
                "{status}"
            );
        }
        assert_eq!(
            ts(Some(1), "\n  ✗ Error: x\n    HTTP 400\n\n"),
            Outcome::Failed
        );
        assert_eq!(
            ts(Some(1), "\n  ✗ Error: x\n    HTTP 502\n\n"),
            Outcome::Unknown
        );
        assert_eq!(ts(None, ""), Outcome::Unknown);
        assert_eq!(ts(Some(143), ""), Outcome::Unknown);
        assert_eq!(rs(Some(2), "\n  ✗ --name is required\n\n"), Outcome::Failed);
        assert_eq!(
            rs(
                Some(1),
                "\n  ✗ Error: x\n    Outcome unknown: the data pattern may have been created.\n"
            ),
            Outcome::Unknown
        );
        assert_eq!(
            rs(Some(1), "\n  ✗ Error: x\n    HTTP 400\n"),
            Outcome::Failed
        );
    }

    /// A restored copy left in `unverifiedCreates` (created, read-back failed) is
    /// journalled `unknown` with its id, never `failed`.
    #[test]
    fn restore_outcomes_keep_unverified_ids() {
        let copies = vec![
            (Kind::Dictionary, "airs-rs-e2e-1-dictionary-rr".to_owned()),
            (Kind::Pattern, "airs-rs-e2e-1-pattern-rr".to_owned()),
        ];
        let dictionary = "11111111-1111-4111-8111-111111111111";
        let pattern = "22222222-2222-4222-8222-222222222222";
        assert!(is_dlp_id(dictionary) && is_dlp_id(pattern));
        let result = json!({
            "dictionaries": [{"name": copies[0].1, "action": "created", "id": dictionary}],
            "patterns": [],
            "unverifiedCreates": [{"kind": "patterns", "name": copies[1].1, "id": pattern}],
            "outcomeUnknown": null
        });
        assert_eq!(
            restore_outcomes(&result, Some(1), &copies),
            [
                (Some(dictionary.to_owned()), Outcome::Ok),
                (Some(pattern.to_owned()), Outcome::Unknown)
            ]
        );
        let result = json!({"dictionaries": [], "patterns": [], "unverifiedCreates": [],
            "outcomeUnknown": {"kind": "dictionaries", "name": copies[0].1}});
        assert_eq!(
            restore_outcomes(&result, Some(1), &copies),
            [(None, Outcome::Unknown), (None, Outcome::Failed)]
        );
        assert_eq!(
            restore_outcomes(&Value::Null, None, &copies),
            [(None, Outcome::Unknown), (None, Outcome::Unknown)]
        );
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
            dlp_writes_gate(lookup(&[("AIRS_RS_LIVE", "1"), ("AIRS_E2E_TENANT", "dev")])),
            Ok(LiveGate::Skip(reason)) if reason.contains("dlp writes skipped")
        ));
        assert!(matches!(
            dlp_writes_gate(lookup(&[
                ("AIRS_RS_LIVE", "1"),
                ("AIRS_E2E_TENANT", "dev"),
                ("AIRS_RS_LIVE_DLP_WRITES", "1")
            ])),
            Ok(LiveGate::Run(_))
        ));
    }

    #[test]
    fn the_own_backup_holds_only_the_run_records() {
        let full = json!({"format": "airs-cli-rs.dlp-resources", "tsgId": "1",
            "dictionaries": [{"id": "d1", "name": "x", "predefined": false, "record": {"id": "d1", "name": "x"}},
                             {"id": "d2", "name": "foreign", "predefined": false, "record": {"id": "d2", "name": "foreign"}}],
            "patterns": [{"id": "p1", "name": "y", "predefined": false, "record": {"id": "p1", "name": "y"}}],
            "profiles": [{"id": "f"}], "skipped": [], "failed": [{"kind": "dictionary"}], "complete": false});
        let own = own_backup(
            &full,
            &[
                ("p1", Kind::Pattern, "pattern-rr"),
                ("d1", Kind::Dictionary, "dictionary-rr"),
            ],
        )
        .unwrap();
        assert_eq!(own["dictionaries"].as_array().unwrap().len(), 1);
        assert_eq!(own["dictionaries"][0]["record"]["name"], "dictionary-rr");
        assert_eq!(own["patterns"][0]["name"], "pattern-rr");
        assert_eq!(own["profiles"], json!([]));
        assert_eq!(own["complete"], true);
        assert_eq!(own["failed"], json!([]));
        assert!(own_backup(&full, &[("gone", Kind::Pattern, "x")]).is_none());
        assert!(only_creates(
            &json!({"dictionaries": [{"action": "create"}], "patterns": [{"action": "create"}], "profiles": [], "unresolved": []}),
            1,
            1
        ));
        assert!(!only_creates(
            &json!({"dictionaries": [{"action": "reuse"}], "patterns": [{"action": "create"}], "profiles": [], "unresolved": []}),
            1,
            1
        ));
        assert_eq!(
            region_of(&json!([{"regionName": "United States"}])),
            Some("United States".into())
        );
        assert_eq!(region_of(&json!([])), None);
        assert!(
            record_projection(&json!({"id": "a", "name": "n", "type": "custom"}))
                .unwrap()
                .get("id")
                .is_none()
        );
    }
}
