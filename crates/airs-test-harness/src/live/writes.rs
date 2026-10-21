//! The M4 live write flow (DESIGN §10, "M4 write flow"; MILESTONES live rules).
//!
//! [`run_live_writes`] runs only when `tests/live.rs` passes [`writes_gate`]
//! (`AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and `AIRS_RS_LIVE_WRITES=1`), or against the
//! loopback fixture server through [`super::LiveTarget::loopback`]. It is its own flow:
//! its own [`super::LiveStore`] (whose run id names the resources), the isolation,
//! integrity and leak checks of every live run, and a 90 s timeout per run.
//!
//! # Own resources only
//!
//! The flow plans four resources, `airs-rs-e2e-<run id>-topic-rs`, `-topic-ts`,
//! `-profile-rs` and `-profile-ts` ([`Names`]), and touches nothing else: a read-only
//! preflight proves no planned name exists, updates, applies and reverts name only
//! them, and the teardown deletes only the ids listed under them. A [`ResourceBudget`]
//! of [`MAX_RESOURCES`] (a constant: it cannot be raised) is checked before every create
//! command. Every write is journalled to the [`super::ledger`] before and after.
//!
//! # TypeScript `topics create|apply|revert`
//!
//! They ignore the tenant's `mgmtEndpoint` (D93), so they run only for a real tenant
//! that uses the default management host; otherwise they are skipped with a D93 note
//! (always for a loopback target), and [`super::Session`] refuses to start one anyway.
//! The flow never adds a `PANW_*` variable.
//!
//! # Teardown
//!
//! Always, also after an abort or a panic: every id listed under a planned name
//! (profiles first, then topics) is deleted with the Rust CLI's plain `delete`,
//! answered `y` on a pty. It never uses `--force`. What is left is counted
//! (`resourcesLeft`, which fails the live test) and left to the sweeper
//! ([`super::cleanup`]).

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::Duration;

use serde_json::{Value, json};

use super::ledger::{Entry, Kind, Ledger, Outcome, Phase, is_uuid};
use super::{
    Exec, LiveAbort, LiveGate, LivePlan, LiveReport, LiveRow, ResourceCounts, Session, opt_in,
};

/// The prefix of every resource a live run creates.
pub const RESOURCE_PREFIX: &str = "airs-rs-e2e-";

/// The most resources one run may create (MILESTONES). A constant: no setting raises
/// it.
pub const MAX_RESOURCES: u32 = 10;

/// Create commands the planned flow runs (`topics create` twice on `topic-rs`, once on
/// `topic-ts`, and one `profiles create` per CLI); each is checked against the budget.
pub const PLANNED_CREATES: u32 = 5;

/// How often a created topic is looked up before the flow gives up on it.
pub const POLL_TRIES: u32 = 5;

/// The pause between two lookups of a created topic.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

const TOPIC_DESCRIPTION: &str = "airs-cli-rs live write check";
const TOPIC_UPDATED: &str = "airs-cli-rs live write check (updated)";
const EXAMPLES: [&str; 2] = [
    "airs-cli-rs live check example one",
    "airs-cli-rs live check example two",
];

/// A live gate with one more opt-in variable: [`LiveGate::from_lookup`], then
/// `variable` must be `1`, else the flow is skipped with `skip` as the reason.
pub fn gate_with(
    lookup: impl Fn(&str) -> Option<String>,
    variable: &str,
    skip: &str,
) -> Result<LiveGate, String> {
    let gate = LiveGate::from_lookup(&lookup)?;
    match gate {
        LiveGate::Skip(reason) => Ok(LiveGate::Skip(reason)),
        LiveGate::Run(_) if opt_in(lookup(variable).as_deref()).is_err() => {
            Ok(LiveGate::Skip(format!("{variable} is not 1; {skip}")))
        }
        run @ LiveGate::Run(_) => Ok(run),
    }
}

/// The write flow's gate: `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and
/// `AIRS_RS_LIVE_WRITES=1`; otherwise `writes skipped`.
pub fn writes_gate(lookup: impl Fn(&str) -> Option<String>) -> Result<LiveGate, String> {
    gate_with(lookup, "AIRS_RS_LIVE_WRITES", "writes skipped")
}

/// Create commands allowed in one run, checked before each.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceBudget {
    used: u32,
}

impl ResourceBudget {
    /// Takes one create, or fails when [`MAX_RESOURCES`] were taken.
    pub fn reserve(&mut self) -> Result<(), LiveAbort> {
        if self.used >= MAX_RESOURCES {
            return Err(LiveAbort::Budget(format!(
                "another create would exceed the {MAX_RESOURCES} resources a live run may create"
            )));
        }
        self.used += 1;
        Ok(())
    }

    /// Creates taken so far.
    pub fn used(&self) -> u32 {
        self.used
    }
}

/// The four planned resource names of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    pub topic_rs: String,
    pub topic_ts: String,
    pub profile_rs: String,
    pub profile_ts: String,
}

impl Names {
    /// `airs-rs-e2e-<run id>-<kind>-<cli>`.
    pub fn new(run_id: &str) -> Self {
        let name = |suffix: &str| format!("{RESOURCE_PREFIX}{run_id}-{suffix}");
        Self {
            topic_rs: name("topic-rs"),
            topic_ts: name("topic-ts"),
            profile_rs: name("profile-rs"),
            profile_ts: name("profile-ts"),
        }
    }

    /// The kind of a planned name.
    pub fn kind_of(&self, name: &str) -> Option<Kind> {
        if name == self.topic_rs || name == self.topic_ts {
            Some(Kind::Topic)
        } else if name == self.profile_rs || name == self.profile_ts {
            Some(Kind::Profile)
        } else {
            None
        }
    }
}

/// `(id, name)` of every listed row (`topicId`/`topicName` or `profileId`/`profileName`
/// of a Rust `--output json` listing); `None` unless the listing is an array.
pub fn listed(value: &Value, kind: Kind) -> Option<Vec<(String, String)>> {
    let (id_key, name_key) = match kind {
        Kind::Topic => ("topicId", "topicName"),
        Kind::Profile => ("profileId", "profileName"),
        Kind::Adapter | Kind::Scan | Kind::Group | Kind::ModelScan => ("uuid", "name"),
        Kind::Pattern | Kind::Dictionary => ("id", "name"),
    };
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
                (text(id_key), text(name_key))
            })
            .collect(),
    )
}

/// The outcome of a write command from its exit and stderr. Only a write that was
/// certainly not applied is `failed`:
/// - exit 0: `ok`; a timeout or an interrupt (130, 143): `unknown`;
/// - airs-cli-rs: `Outcome unknown: …` or `(outcome unknown)` is `unknown`; `Outcome:
///   the <thing> was <done>, but …` (applied, the answer unreadable or without an id) is
///   `ok`; any other failure is a rejection (DESIGN §13.2), `failed`;
/// - TypeScript prints no outcome line, so a failure is `unknown` unless it is a usage
///   error (exit 2, nothing sent) or a definite 4xx rejection (`HTTP 4xx`), except 404,
///   408, 409 and 429, which can follow a retried attempt that was applied (D95).
pub(super) fn write_outcome(exec: &Exec, side: Side) -> Outcome {
    match exec.code {
        Some(0) => Outcome::Ok,
        None | Some(130 | 143) => Outcome::Unknown,
        Some(code) => match side {
            Side::Rust => {
                let lowered = exec.stderr.to_ascii_lowercase();
                if lowered.contains("outcome unknown") {
                    Outcome::Unknown
                } else if exec
                    .stderr
                    .lines()
                    .any(|line| line.trim_start().starts_with("Outcome: the "))
                {
                    Outcome::Ok
                } else {
                    Outcome::Failed
                }
            }
            Side::Ts if code == 2 || ts_rejected(&exec.stderr) => Outcome::Failed,
            Side::Ts => Outcome::Unknown,
        },
    }
}

/// Whether TypeScript's error block names a definite rejection: `HTTP <4xx>` other than
/// 404, 408, 409 and 429.
pub(super) fn ts_rejected(stderr: &str) -> bool {
    stderr.lines().any(|line| {
        line.trim()
            .strip_prefix("HTTP ")
            .and_then(|status| status.parse::<u16>().ok())
            .is_some_and(|status| {
                (400..500).contains(&status) && !matches!(status, 404 | 408 | 409 | 429)
            })
    })
}

/// The first JSON object in `stdout` (TypeScript may print text before it).
fn json_in(stdout: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|_| {
        stdout
            .find('{')
            .and_then(|start| serde_json::from_str(&stdout[start..]).ok())
            .unwrap_or(Value::Null)
    })
}

/// The UUID at the end of an outcome line `✓ <label>: <id>` on stdout or stderr.
pub(super) fn id_after(text: &str, label: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let rest = line.split_once(label)?.1.trim();
        is_uuid(rest).then(|| rest.to_owned())
    })
}

/// A UUID-shaped string field of a JSON object.
fn uuid_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|id| is_uuid(id))
        .map(str::to_owned)
}

/// The topic-guardrails shape of a §7.5 profile object, the run's topic name replaced
/// by `<topic>`: the item's action, each group's action and names, and whether every
/// ref pins `revision`.
pub fn guardrail_shape(profile: &Value, topic: &str, revision: Option<&Value>) -> Option<Value> {
    let protection = profile
        .get("policy")?
        .get("ai-security-profiles")?
        .get(0)?
        .get("model-configuration")?
        .get("model-protection")?
        .as_array()?;
    let item = protection
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some("topic-guardrails"))?;
    let mut pinned = true;
    let groups: Vec<Value> = item
        .get("topic-list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|group| {
            let names: Vec<Value> = group
                .get("topic")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|reference| {
                    let name = reference.get("topic_name").and_then(Value::as_str);
                    if name == Some(topic) {
                        let same = match (reference.get("revision"), revision) {
                            (Some(a), Some(b)) => crate::compare::json_semantic_eq(a, b),
                            _ => false,
                        };
                        pinned &= same;
                        json!("<topic>")
                    } else {
                        json!("<other>")
                    }
                })
                .collect();
            json!({"action": group.get("action").cloned().unwrap_or(Value::Null), "names": names})
        })
        .collect();
    Some(json!({
        "action": item.get("action").cloned().unwrap_or(Value::Null),
        "groups": groups,
        "pinnedCurrent": pinned,
    }))
}

/// What `topics apply --intent block` must leave (§13.4).
pub fn expected_block_shape() -> Value {
    json!({
        "action": "allow",
        "groups": [{"action": "block", "names": ["<topic>"]}],
        "pinnedCurrent": true,
    })
}

/// Which CLI a step runs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    Rust,
    Ts,
}

impl Side {
    pub(super) fn ledger(self) -> &'static str {
        match self {
            Self::Rust => "rs",
            Self::Ts => "ts",
        }
    }
}

struct Flow<'s, 'p> {
    session: &'s mut Session<'p>,
    ledger: Ledger,
    names: Names,
    budget: ResourceBudget,
    /// Every id seen under a planned name.
    ids: BTreeSet<String>,
    deleted: usize,
    /// Set once the preflight proved that no planned name existed: only then may the
    /// teardown delete what is listed under them.
    owned: bool,
}

/// Runs the write flow, then the teardown (always), and returns the summary with its
/// resource counts. A budget overrun, a leak, a changed tenant file or a setup failure
/// stops the flow (the teardown still runs); mismatches are collected in the report.
pub fn run_live_writes(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
    if PLANNED_CREATES > MAX_RESOURCES {
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
        deleted: 0,
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
    #[allow(clippy::too_many_arguments)]
    fn journal(
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

    fn exec(&self, side: Side, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        let cli = match side {
            Side::Rust => &self.session.plan.rust,
            Side::Ts => &self.session.plan.ts,
        };
        self.session.exec(cli, check, args)
    }

    /// One journalled write: `pending`, the run, the result line with the id `id_of`
    /// finds (else `known`).
    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        side: Side,
        op: &'static str,
        target: (Kind, &str),
        known: Option<&str>,
        args: &[&str],
        id_of: &dyn Fn(&Exec) -> Option<String>,
        note: &str,
    ) -> Result<(Exec, Option<String>), LiveAbort> {
        self.journal(
            Phase::Flow,
            side,
            op,
            target,
            known,
            (Outcome::Pending, None),
            note,
        )?;
        let exec = self.exec(side, op, args)?;
        let id = id_of(&exec).or_else(|| known.map(str::to_owned));
        if let Some(id) = &id {
            self.ids.insert(id.clone());
        }
        self.journal(
            Phase::Flow,
            side,
            op,
            target,
            id.as_deref(),
            (write_outcome(&exec, side), exec.code),
            note,
        )?;
        Ok((exec, id))
    }

    fn row(&mut self, check: &str, side: Side, exec: &Exec, agree: bool, note: &str) {
        let (rust_exit, ts_exit) = match side {
            Side::Rust => (exec.exit_cell(), "-".to_owned()),
            Side::Ts => ("-".to_owned(), exec.exit_cell()),
        };
        self.session.report.rows.push(LiveRow {
            check: check.to_owned(),
            rust_exit,
            ts_exit,
            agree: agree && exec.code.is_some(),
            rust_verdict: None,
            ts_verdict: None,
            note: note.to_owned(),
        });
    }

    fn skip(&mut self, op: &'static str, target: (Kind, &str)) -> Result<(), LiveAbort> {
        self.journal(
            Phase::Flow,
            Side::Ts,
            op,
            target,
            None,
            (Outcome::Skipped, None),
            "D93",
        )?;
        self.session.report.notices.push(format!(
            "typescript {op} skipped (D93): it would ignore the tenant's mgmtEndpoint"
        ));
        Ok(())
    }

    /// Rust listing of every revision of one kind (complete, or the flow stops).
    fn list(&self, kind: Kind, check: &str) -> Result<Vec<(String, String)>, LiveAbort> {
        let group = match kind {
            Kind::Topic => "topics",
            Kind::Profile => "profiles",
            Kind::Adapter
            | Kind::Scan
            | Kind::Pattern
            | Kind::Dictionary
            | Kind::Group
            | Kind::ModelScan => {
                return Err(LiveAbort::Setup(
                    "the M4 write flow lists topics and profiles only".into(),
                ));
            }
        };
        let args = [
            "runtime",
            group,
            "list",
            "--all",
            "--all-versions",
            "--max",
            "0",
            "--output",
            "json",
        ];
        let exec = self.exec(Side::Rust, check, &args)?;
        match (exec.code, listed(&exec.json(), kind)) {
            (Some(0), Some(rows)) => Ok(rows),
            _ => Err(LiveAbort::Setup(format!(
                "the {group} listing did not complete (exit {})",
                exec.exit_cell()
            ))),
        }
    }

    /// Rust `topics get <name> --output json`, up to [`POLL_TRIES`] times.
    fn poll_topic(&mut self, name: &str, check: &str) -> Result<Option<Value>, LiveAbort> {
        for attempt in 0..POLL_TRIES {
            let exec = self.exec(
                Side::Rust,
                check,
                &["runtime", "topics", "get", name, "--output", "json"],
            )?;
            if exec.code == Some(0) {
                return Ok(Some(exec.json()));
            }
            if attempt + 1 < POLL_TRIES {
                std::thread::sleep(POLL_INTERVAL);
            }
        }
        Ok(None)
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        // Preflight: no planned name may exist.
        let topics = self.list(Kind::Topic, "preflight topics list")?;
        let profiles = self.list(Kind::Profile, "preflight profiles list")?;
        let names = self.names.clone();
        if topics
            .iter()
            .chain(&profiles)
            .any(|(_, name)| names.kind_of(name).is_some())
        {
            return Err(LiveAbort::Setup(
                "a planned resource name already exists; nothing was created".into(),
            ));
        }
        self.owned = true;
        let ts_b = self.session.ts_family_b;
        let examples = EXAMPLES;
        let create_topic = |name: &str, side: Side| -> Vec<String> {
            let mut args: Vec<String> = [
                "runtime",
                "topics",
                "create",
                "--name",
                name,
                "--description",
                TOPIC_DESCRIPTION,
                "--examples",
            ]
            .iter()
            .map(|arg| (*arg).to_owned())
            .chain(examples.iter().map(|arg| (*arg).to_owned()))
            .collect();
            args.extend(match side {
                Side::Rust => ["--output".to_owned(), "json".to_owned()],
                Side::Ts => ["--format".to_owned(), "json".to_owned()],
            });
            args
        };
        let topic_id = |exec: &Exec| uuid_field(&json_in(&exec.stdout), "topicId");

        // topics create on both CLIs.
        self.budget.reserve()?;
        let args = create_topic(&names.topic_rs, Side::Rust);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (exec, topic_rs) = self.write(
            Side::Rust,
            "topics create",
            (Kind::Topic, &names.topic_rs),
            None,
            &args,
            &topic_id,
            "",
        )?;
        self.row(
            "topics create (rs)",
            Side::Rust,
            &exec,
            exec.code == Some(0) && topic_rs.is_some(),
            "",
        );
        let mut topic_ts = None;
        if ts_b {
            self.budget.reserve()?;
            let args = create_topic(&names.topic_ts, Side::Ts);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let (exec, id) = self.write(
                Side::Ts,
                "topics create",
                (Kind::Topic, &names.topic_ts),
                None,
                &args,
                &topic_id,
                "D94",
            )?;
            self.row(
                "topics create (ts)",
                Side::Ts,
                &exec,
                exec.code == Some(0),
                "D94 --format json",
            );
            topic_ts = id;
        } else {
            self.skip("topics create", (Kind::Topic, &names.topic_ts))?;
        }
        for (name, label, present) in [
            (&names.topic_rs, "topics get after create (rs)", true),
            (&names.topic_ts, "topics get after create (ts)", ts_b),
        ] {
            if !present {
                continue;
            }
            let found = self.poll_topic(name, label)?;
            let agree = found.is_some();
            self.session.report.rows.push(LiveRow {
                check: label.to_owned(),
                rust_exit: if agree { "0" } else { "1" }.to_owned(),
                ts_exit: "-".to_owned(),
                agree,
                rust_verdict: None,
                ts_verdict: None,
                note: format!("at most {POLL_TRIES} lookups"),
            });
            if let Some(found) = found
                .as_ref()
                .and_then(|value| uuid_field(value, "topicId"))
            {
                self.ids.insert(found.clone());
                if name == &names.topic_ts && topic_ts.is_none() {
                    topic_ts = Some(found);
                }
            }
        }

        // The update path of topics create, then topics update --config.
        self.budget.reserve()?;
        let args = create_topic(&names.topic_rs, Side::Rust);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let before = topic_rs.clone();
        let (exec, again) = self.write(
            Side::Rust,
            "topics create",
            (Kind::Topic, &names.topic_rs),
            before.as_deref(),
            &args,
            &topic_id,
            "update path",
        )?;
        let changed = before != again;
        self.row(
            "topics create again (rs)",
            Side::Rust,
            &exec,
            exec.code == Some(0) && json_in(&exec.stdout).get("created") == Some(&json!(false)),
            if changed { "id changed" } else { "id kept" },
        );
        let topic_rs = again.or(topic_rs);
        if let Some(id) = topic_rs.clone() {
            let config = self.session.sandbox.tmp().join("topic-update.json");
            let body = json!({
                "topic_name": names.topic_rs,
                "description": TOPIC_UPDATED,
                "examples": EXAMPLES,
            });
            std::fs::write(&config, body.to_string())
                .map_err(|err| LiveAbort::Setup(format!("cannot write the update file: {err}")))?;
            let config = config.display().to_string();
            let args = [
                "runtime", "topics", "update", &id, "--config", &config, "--output", "json",
            ];
            let (exec, _) = self.write(
                Side::Rust,
                "topics update",
                (Kind::Topic, &names.topic_rs),
                Some(&id),
                &args,
                &|exec: &Exec| uuid_field(&exec.json(), "topicId"),
                "",
            )?;
            let updated = exec.json().get("description") == Some(&json!(TOPIC_UPDATED));
            self.row("topics update (rs)", Side::Rust, &exec, updated, "");
        }

        // profiles create and update on both CLIs.
        let mut profile_ids = [None, None];
        for (index, (side, name)) in [
            (Side::Rust, &names.profile_rs),
            (Side::Ts, &names.profile_ts),
        ]
        .into_iter()
        .enumerate()
        {
            self.budget.reserve()?;
            let mut args = vec![
                "runtime",
                "profiles",
                "create",
                "--name",
                name,
                "--prompt-injection",
                "block",
            ];
            if side == Side::Rust {
                args.extend(["--output", "json"]);
            }
            let id_of = |exec: &Exec| {
                uuid_field(&exec.json(), "profileId")
                    .or_else(|| id_after(&exec.stdout, "Profile created:"))
                    .or_else(|| id_after(&exec.stderr, "Profile created:"))
            };
            let (exec, id) = self.write(
                side,
                "profiles create",
                (Kind::Profile, name),
                None,
                &args,
                &id_of,
                "",
            )?;
            let label = match side {
                Side::Rust => "profiles create (rs)",
                Side::Ts => "profiles create (ts)",
            };
            self.row(label, side, &exec, exec.code == Some(0) && id.is_some(), "");
            let mut args = vec![
                "runtime",
                "profiles",
                "update",
                name,
                "--prompt-injection",
                "alert",
            ];
            if side == Side::Rust {
                args.extend(["--output", "json"]);
            }
            let id_of = |exec: &Exec| {
                uuid_field(&exec.json(), "profileId")
                    .or_else(|| id_after(&exec.stdout, "Profile updated:"))
                    .or_else(|| id_after(&exec.stderr, "Profile updated:"))
            };
            let (exec, updated) = self.write(
                side,
                "profiles update",
                (Kind::Profile, name),
                id.as_deref(),
                &args,
                &id_of,
                "",
            )?;
            let label = match side {
                Side::Rust => "profiles update (rs)",
                Side::Ts => "profiles update (ts)",
            };
            let note = if updated == id {
                "id kept"
            } else {
                "id changed"
            };
            self.row(label, side, &exec, exec.code == Some(0), note);
            profile_ids[index] = updated;
        }

        // topics apply, then the guardrails of each profile.
        let pairs = [
            (
                Side::Rust,
                &names.topic_rs,
                &names.profile_rs,
                &profile_ids[0],
                topic_rs.is_some(),
            ),
            (
                Side::Ts,
                &names.topic_ts,
                &names.profile_ts,
                &profile_ids[1],
                ts_b && topic_ts.is_some(),
            ),
        ];
        let mut shapes: Vec<Option<Value>> = Vec::new();
        for (side, topic, profile, profile_id, allowed) in pairs {
            if side == Side::Ts && !ts_b {
                self.skip("topics apply", (Kind::Profile, profile))?;
                shapes.push(None);
                continue;
            }
            if !allowed {
                shapes.push(None);
                continue;
            }
            let format = if side == Side::Rust {
                "--output"
            } else {
                "--format"
            };
            let args = [
                "runtime",
                "topics",
                "apply",
                "--profile",
                profile,
                "--name",
                topic,
                format,
                "json",
            ];
            let (exec, _) = self.write(
                side,
                "topics apply",
                (Kind::Profile, profile),
                profile_id.as_deref(),
                &args,
                &|_| None,
                "",
            )?;
            let label = match side {
                Side::Rust => "topics apply (rs)",
                Side::Ts => "topics apply (ts)",
            };
            self.row(label, side, &exec, exec.code == Some(0), "");
            let cli = match side {
                Side::Rust => self.session.plan.rust.clone(),
                Side::Ts => self.session.plan.ts.clone(),
            };
            let got = self.session.exec(
                &cli,
                "profiles get after apply",
                &["runtime", "profiles", "get", profile, "--output", "json"],
            )?;
            let revision = self
                .poll_topic(topic, "topics get revision")?
                .and_then(|value| value.get("revision").cloned());
            if let Some(id) = uuid_field(&got.json(), "profileId") {
                self.ids.insert(id);
            }
            shapes.push(guardrail_shape(&got.json(), topic, revision.as_ref()));
        }
        let expected = expected_block_shape();
        let rust_ok = shapes[0].as_ref() == Some(&expected);
        let (agree, note) = match &shapes[1] {
            Some(ts) => (
                rust_ok && crate::compare::json_semantic_eq(ts, &expected),
                "action, names and pinned revision on both; D98 tolerated".to_owned(),
            ),
            None => (rust_ok, "rust only (D93)".to_owned()),
        };
        self.session.report.rows.push(LiveRow {
            check: "topics apply guardrails".into(),
            rust_exit: if rust_ok { "0" } else { "1" }.into(),
            ts_exit: if shapes[1].is_some() { "0" } else { "-" }.into(),
            agree,
            rust_verdict: None,
            ts_verdict: None,
            note,
        });

        // topics revert --force.
        if let Some(id) = topic_rs.clone() {
            let args = [
                "runtime",
                "topics",
                "revert",
                "--profile",
                &names.profile_rs,
                "--name",
                &names.topic_rs,
                "--force",
                "--output",
                "json",
            ];
            let (exec, _) = self.write(
                Side::Rust,
                "topics revert",
                (Kind::Topic, &names.topic_rs),
                Some(&id),
                &args,
                &|_| None,
                "D99",
            )?;
            // The revision the revert deleted (its record names it), gone from the
            // listing of every revision (the service may keep older revisions as ids of
            // their own; the teardown deletes those).
            let removed = exec
                .json()
                .get("deleted")
                .and_then(|deleted| deleted.get(0))
                .and_then(Value::as_str)
                .filter(|removed| is_uuid(removed))
                .map_or_else(|| id.clone(), str::to_owned);
            let gone = !self
                .list(Kind::Topic, "topics list after revert")?
                .iter()
                .any(|(listed, _)| *listed == removed);
            let kept = exec.code == Some(0) && exec.stderr.contains("so it was kept");
            if exec.code == Some(0) && gone {
                self.deleted += 1;
            }
            let (agree, note) = match (exec.code, gone, kept) {
                (Some(0), true, false) => (true, "topic deleted"),
                (Some(0), false, true) => (
                    true,
                    "D99: the service still references the topic, so it was kept",
                ),
                _ => (
                    false,
                    "expected exit 0 with the topic deleted, or kept with the D99 warning",
                ),
            };
            self.row("topics revert --force (rs)", Side::Rust, &exec, agree, note);
        }
        if !ts_b {
            self.skip("topics revert", (Kind::Topic, &names.topic_ts))?;
        } else if let Some(id) = topic_ts.clone() {
            let args = [
                "runtime",
                "topics",
                "revert",
                "--profile",
                &names.profile_ts,
                "--name",
                &names.topic_ts,
                "--force",
            ];
            let (exec, _) = self.write(
                Side::Ts,
                "topics revert",
                (Kind::Topic, &names.topic_ts),
                Some(&id),
                &args,
                &|_| None,
                "D99",
            )?;
            let present = self
                .exec(
                    Side::Rust,
                    "topics get after ts revert",
                    &[
                        "runtime",
                        "topics",
                        "get",
                        &names.topic_ts,
                        "--output",
                        "json",
                    ],
                )?
                .code
                == Some(0);
            let expected = exec.code == Some(1)
                && format!("{}{}", exec.stdout, exec.stderr).contains("updatedBy is required")
                && present;
            self.row(
                "topics revert --force (ts)",
                Side::Ts,
                &exec,
                true,
                if expected {
                    "D99 evidence: updatedBy is required, the topic is kept"
                } else {
                    "D99 evidence not observed"
                },
            );
        }
        Ok(())
    }

    /// Deletes every id listed under a planned name, profiles first, with the plain Rust
    /// delete answered on a pty; then counts what is left.
    fn teardown(&mut self) -> Result<ResourceCounts, LiveAbort> {
        if !self.owned {
            // The preflight did not pass: nothing was created, and what is listed under
            // the planned names (if anything) is not the run's to delete.
            return Ok(ResourceCounts::default());
        }
        let mut problem = None;
        for kind in [Kind::Profile, Kind::Topic] {
            let rows = match self.list(kind, "teardown listing") {
                Ok(rows) => rows,
                Err(abort) => {
                    problem.get_or_insert(abort);
                    continue;
                }
            };
            for (id, name) in rows {
                if self.names.kind_of(&name) != Some(kind) || !is_uuid(&id) {
                    continue;
                }
                self.ids.insert(id.clone());
                if let Err(abort) = self.delete(Phase::Teardown, kind, &id, &name) {
                    problem.get_or_insert(abort);
                    break;
                }
            }
        }
        let mut left = 0;
        for kind in [Kind::Profile, Kind::Topic] {
            match self.list(kind, "teardown check") {
                Ok(rows) => {
                    left += rows
                        .iter()
                        .filter(|(_, name)| self.names.kind_of(name) == Some(kind))
                        .count();
                }
                // Unknown: count everything not deleted as left.
                Err(abort) => {
                    problem.get_or_insert(abort);
                    left = self.ids.len().saturating_sub(self.deleted).max(1);
                    break;
                }
            }
        }
        let counts = ResourceCounts {
            created: self.ids.len(),
            deleted: self.deleted,
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

    /// One journalled plain delete on the pty.
    fn delete(&mut self, phase: Phase, kind: Kind, id: &str, name: &str) -> Result<(), LiveAbort> {
        if journalled_delete(self.session, &mut self.ledger, phase, (kind, name), id)?
            == Outcome::Ok
        {
            self.deleted += 1;
        }
        Ok(())
    }
}

/// Deletes one run-created resource with the Rust CLI's plain `delete` answered `y` on
/// a pty (never `--force`), journalled before and after, with a summary row. Used by
/// the teardown and the sweeper. A red team adapter is deleted with `redteam adapter
/// delete <id> --force` (its D137 confirmation needs a terminal or `--force`), a DLP
/// pattern or dictionary with `runtime dlp <group> delete <id> --force` (D167).
pub(super) fn journalled_delete(
    session: &mut Session<'_>,
    ledger: &mut Ledger,
    phase: Phase,
    (kind, name): (Kind, &str),
    id: &str,
) -> Result<Outcome, LiveAbort> {
    let (group, op) = match kind {
        Kind::Topic => ("topics", "topics delete"),
        Kind::Profile => ("profiles", "profiles delete"),
        Kind::Adapter => ("adapter", "adapter delete"),
        Kind::Pattern => ("patterns", "patterns delete"),
        Kind::Dictionary => ("dictionaries", "dictionaries delete"),
        Kind::Group => ("groups", "groups delete"),
        Kind::Scan | Kind::ModelScan => {
            return Err(LiveAbort::Setup(
                "a scan cannot be deleted; the scan flow aborts its own scan".into(),
            ));
        }
    };
    let entry = |outcome, exit| Entry {
        phase,
        cli: "rs",
        op,
        kind,
        name,
        id: Some(id),
        outcome,
        exit,
        note: "",
    };
    ledger
        .record(&entry(Outcome::Pending, None))
        .map_err(LiveAbort::Setup)?;
    let exec = if kind == Kind::Adapter {
        session.exec(
            &session.plan.rust,
            op,
            &["redteam", group, "delete", id, "--force"],
        )?
    } else if kind.is_dlp() {
        session.exec(
            &session.plan.rust,
            op,
            &["runtime", "dlp", group, "delete", id, "--force"],
        )?
    } else if kind == Kind::Group {
        session.exec(
            &session.plan.rust,
            op,
            &["model-security", group, "delete", id, "--force"],
        )?
    } else {
        session.run_pty_yes(op, &["runtime", group, "delete", id])?
    };
    let outcome = write_outcome(&exec, Side::Rust);
    ledger
        .record(&entry(outcome, exec.code))
        .map_err(LiveAbort::Setup)?;
    session.report.rows.push(LiveRow {
        check: format!("{} {op}", phase.name()),
        rust_exit: exec.exit_cell(),
        ts_exit: "-".to_owned(),
        agree: outcome == Outcome::Ok,
        rust_verdict: None,
        ts_verdict: None,
        note: if kind == Kind::Adapter || kind == Kind::Group || kind.is_dlp() {
            "--force delete".to_owned()
        } else {
            "plain delete".to_owned()
        },
    });
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_resource_budget_refuses_the_eleventh_create() {
        let mut budget = ResourceBudget::default();
        for _ in 0..MAX_RESOURCES {
            budget.reserve().unwrap();
        }
        assert!(matches!(budget.reserve(), Err(LiveAbort::Budget(_))));
        assert_eq!(budget.used(), MAX_RESOURCES);
        const { assert!(PLANNED_CREATES <= MAX_RESOURCES) };
    }

    #[test]
    fn names_carry_the_run_id_and_kind() {
        let names = Names::new("1792281599-42-0");
        assert_eq!(names.topic_rs, "airs-rs-e2e-1792281599-42-0-topic-rs");
        assert_eq!(names.profile_ts, "airs-rs-e2e-1792281599-42-0-profile-ts");
        assert_eq!(names.kind_of(&names.topic_ts), Some(Kind::Topic));
        assert_eq!(names.kind_of(&names.profile_rs), Some(Kind::Profile));
        assert_eq!(names.kind_of("airs-rs-e2e-1792281599-42-1-topic-rs"), None);
        for name in [
            &names.topic_rs,
            &names.topic_ts,
            &names.profile_rs,
            &names.profile_ts,
        ] {
            assert!(super::super::cleanup::parse_name(name).is_some(), "{name}");
        }
    }

    #[test]
    fn the_write_gate_needs_its_own_opt_in() {
        let lookup = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            }
        };
        assert!(matches!(
            writes_gate(lookup(&[("AIRS_RS_LIVE", "1"), ("AIRS_E2E_TENANT", "dev")])),
            Ok(LiveGate::Skip(reason)) if reason.contains("writes skipped")
        ));
        assert!(matches!(
            writes_gate(lookup(&[
                ("AIRS_RS_LIVE_WRITES", "1"),
                ("AIRS_E2E_TENANT", "dev")
            ])),
            Ok(LiveGate::Skip(_))
        ));
        assert!(matches!(
            writes_gate(lookup(&[
                ("AIRS_RS_LIVE", "1"),
                ("AIRS_E2E_TENANT", "dev"),
                ("AIRS_RS_LIVE_WRITES", "1")
            ])),
            Ok(LiveGate::Run(_))
        ));
    }

    #[test]
    fn guardrail_shapes() {
        let profile = |action: &str, group: &str, revision: u64| {
            json!({"policy": {"ai-security-profiles": [{"model-configuration": {"model-protection": [
                {"name": "prompt-injection", "action": "block"},
                {"name": "topic-guardrails", "action": action, "options": [], "topic-list": [
                    {"action": group, "topic": [{"topic_id": "x", "topic_name": "t-rs", "revision": revision}]}
                ]}
            ]}}]}})
        };
        assert_eq!(
            guardrail_shape(&profile("allow", "block", 3), "t-rs", Some(&json!(3))),
            Some(expected_block_shape())
        );
        assert_ne!(
            guardrail_shape(&profile("allow", "block", 2), "t-rs", Some(&json!(3))),
            Some(expected_block_shape()),
            "a stale pin"
        );
        assert_ne!(
            guardrail_shape(&profile("block", "allow", 3), "t-rs", Some(&json!(3))),
            Some(expected_block_shape())
        );
        assert_eq!(guardrail_shape(&json!({"policy": {}}), "t-rs", None), None);
    }

    #[test]
    fn outcomes_are_failed_only_when_nothing_was_applied() {
        let exec = |code: Option<i32>, stderr: &str| Exec {
            code,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            elapsed: Duration::ZERO,
        };
        for side in [Side::Rust, Side::Ts] {
            assert_eq!(write_outcome(&exec(Some(0), ""), side), Outcome::Ok);
            for code in [None, Some(130), Some(143)] {
                assert_eq!(write_outcome(&exec(code, ""), side), Outcome::Unknown);
            }
        }
        let rust = |stderr: &str| write_outcome(&exec(Some(1), stderr), Side::Rust);
        assert_eq!(
            rust("\n  ✗ Error: x\n    Outcome unknown: the topic may have been created.\n"),
            Outcome::Unknown
        );
        assert_eq!(
            rust(
                "\n  ✗ Error: x\n    Outcome: the topic was created, but the response could not be read.\n"
            ),
            Outcome::Ok
        );
        assert_eq!(
            rust(
                "\n  ✗ Error: x\n    Outcome: the topic was created, but the response carried no topic_id.\n"
            ),
            Outcome::Ok
        );
        assert_eq!(
            rust(
                "\n  ✗ Error: x\n    Outcome: the profile was deleted, but the response could not be read.\n"
            ),
            Outcome::Ok
        );
        assert_eq!(
            rust("  ✗ Interrupted: the change may already have been applied (outcome unknown)\n"),
            Outcome::Unknown
        );
        assert_eq!(rust("\n  ✗ Error: rejected\n"), Outcome::Failed);
        assert_eq!(
            write_outcome(&exec(Some(2), "\n  ✗ usage\n\n"), Side::Rust),
            Outcome::Failed
        );
        let ts = |code: i32, stderr: &str| write_outcome(&exec(Some(code), stderr), Side::Ts);
        assert_eq!(ts(1, "\n  ✗ Error: timeout\n\n"), Outcome::Unknown);
        assert_eq!(
            ts(1, "\n  ✗ Error: x\n    HTTP 503\n    Re-run with --debug\n"),
            Outcome::Unknown
        );
        for status in [404, 408, 409, 429] {
            assert_eq!(
                ts(1, &format!("\n  ✗ Error: x\n    HTTP {status}\n")),
                Outcome::Unknown,
                "{status}"
            );
        }
        for status in [400, 401, 403, 422] {
            assert_eq!(
                ts(1, &format!("\n  ✗ Error: x\n    HTTP {status}\n")),
                Outcome::Failed,
                "{status}"
            );
        }
        assert_eq!(ts(2, "\n  ✗ usage\n\n"), Outcome::Failed);
    }

    #[test]
    fn ids_come_from_json_or_outcome_lines() {
        let id = "00000000-0000-4000-8000-000000000901";
        assert_eq!(
            id_after(
                &format!("\n  ✓ Profile created: {id}\n"),
                "Profile created:"
            ),
            Some(id.to_owned())
        );
        assert_eq!(
            id_after("  ✓ Profile created: nope\n", "Profile created:"),
            None
        );
        assert_eq!(
            uuid_field(
                &json_in(&format!("banner\n{{\"topicId\": \"{id}\"}}\n")),
                "topicId"
            ),
            Some(id.to_owned())
        );
    }
}
