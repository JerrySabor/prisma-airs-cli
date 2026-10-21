//! The live sweeper (DESIGN §10, "Sweeper"; MILESTONES: "a cleanup command that is safe
//! to re-run deletes only prefixed resources older than 1 hour").
//!
//! [`run_live_cleanup`] runs only when `tests/live.rs` passes [`cleanup_gate`]
//! (`AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and `AIRS_RS_LIVE_CLEANUP=1`), or against the
//! loopback fixture server. It lists every topic and profile revision, every red team
//! adapter, every custom DLP pattern and dictionary and every prefixed model-security
//! group (DESIGN §10 M6c; each checked with a Rust `groups get` first, a 404 skipped)
//! with the Rust CLI (a listing that
//! does not complete deletes nothing; a tenant without red team or DLP access has none of
//! those), selects only names that fully match
//! `^airs-rs-e2e-([0-9]{10})-[0-9]+-[0-9]+-(topic|profile|adapter)-(rs|ts)$` or
//! `^airs-rs-e2e-([0-9]{10})-[0-9]+-[0-9]+-(pattern|dictionary)-(rs|ts|rr)$` whose kind
//! matches the listing, whose embedded Unix time is at least [`MIN_AGE_SECS`] old
//! (younger ones may belong to a flow running now) and, for DLP records, whose `status`
//! is not `deleted` (pattern deletes are soft), and deletes at most [`MAX_DELETES`] of
//! them (the oldest first; the rest are reported), profiles first, with the plain Rust
//! delete on a pty (an adapter with `redteam adapter delete <id> --force`, a DLP record
//! with `runtime dlp <group> delete <id> --force`). A failed delete (a 409 for a
//! referenced topic)
//! is reported and skipped. Every delete is journalled with phase `cleanup`. A re-run
//! finds only what is left. It never runs `profiles cleanup` (tenant-wide).

use super::ledger::{Kind, Ledger, Outcome, Phase, now_unix};
use super::writes::{RESOURCE_PREFIX, gate_with, journalled_delete, listed};
use super::{LiveAbort, LiveGate, LivePlan, LiveReport, Session};

/// The youngest a resource may be to be swept (1 hour).
pub const MIN_AGE_SECS: u64 = 3600;

/// The most deletions of one sweep.
pub const MAX_DELETES: usize = 20;

/// The sweeper's gate: `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT` and `AIRS_RS_LIVE_CLEANUP=1`.
pub fn cleanup_gate(lookup: impl Fn(&str) -> Option<String>) -> Result<LiveGate, String> {
    gate_with(lookup, "AIRS_RS_LIVE_CLEANUP", "the sweeper is skipped")
}

/// A run-created resource name, parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceName {
    /// The Unix time of the run that created it.
    pub created: u64,
    pub kind: Kind,
}

/// Parses `airs-rs-e2e-<10 digits>-<digits>-<digits>-<topic|profile>-<rs|ts>` exactly.
pub fn parse_name(name: &str) -> Option<ResourceName> {
    let rest = name.strip_prefix(RESOURCE_PREFIX)?;
    let parts: Vec<&str> = rest.split('-').collect();
    let [unix, pid, counter, kind, cli] = parts.as_slice() else {
        return None;
    };
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if unix.len() != 10 || !digits(unix) || !digits(pid) || !digits(counter) {
        return None;
    }
    let kind = match *kind {
        "topic" => Kind::Topic,
        "profile" => Kind::Profile,
        "adapter" => Kind::Adapter,
        "pattern" => Kind::Pattern,
        "dictionary" => Kind::Dictionary,
        "group" => Kind::Group,
        _ => return None,
    };
    // `rr`: the DLP write flow's restored copies (DESIGN §10 M6b); `sc`: the M6c scan
    // flow's group.
    let clis: &[&str] = if kind.is_dlp() {
        &["rs", "ts", "rr"]
    } else if kind == Kind::Group {
        &["rs", "ts", "sc"]
    } else {
        &["rs", "ts"]
    };
    if !clis.contains(cli) {
        return None;
    }
    Some(ResourceName {
        created: unix.parse().ok()?,
        kind,
    })
}

/// One resource the sweeper may delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub kind: Kind,
    pub id: String,
    pub name: String,
    pub created: u64,
}

/// What a sweep selects from the two listings at `now`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// At most [`MAX_DELETES`], the oldest first, then ordered profiles first.
    pub delete: Vec<Candidate>,
    /// Old enough but over the cap (left for the next run).
    pub deferred: usize,
    /// Prefixed and well-formed, but younger than [`MIN_AGE_SECS`].
    pub too_young: usize,
}

/// Selects from `(id, name)` rows of each kind (pure; unit-tested).
pub fn select(topics: &[(String, String)], profiles: &[(String, String)], now: u64) -> Selection {
    select_all(topics, profiles, &[], now)
}

/// [`select`] over the red team draft adapters too (M6a, DESIGN §10).
pub fn select_all(
    topics: &[(String, String)],
    profiles: &[(String, String)],
    adapters: &[(String, String)],
    now: u64,
) -> Selection {
    select_lists(
        &[
            (Kind::Profile, profiles),
            (Kind::Topic, topics),
            (Kind::Adapter, adapters),
        ],
        now,
    )
}

/// [`select`] over any listings (the DLP patterns and dictionaries of M6b included; their
/// rows already without `status: deleted`).
pub fn select_lists(lists: &[(Kind, &[(String, String)])], now: u64) -> Selection {
    let mut selection = Selection::default();
    let mut old = Vec::new();
    for (kind, rows) in lists {
        let kind = *kind;
        for (id, name) in *rows {
            let Some(parsed) = parse_name(name) else {
                continue;
            };
            if parsed.kind != kind || !super::ledger::is_resource_id(kind, id) {
                continue;
            }
            if now.saturating_sub(parsed.created) < MIN_AGE_SECS || parsed.created > now {
                selection.too_young += 1;
                continue;
            }
            old.push(Candidate {
                kind,
                id: id.clone(),
                name: name.clone(),
                created: parsed.created,
            });
        }
    }
    // The oldest first (stable: profiles before topics of the same age).
    old.sort_by_key(|candidate| candidate.created);
    selection.deferred = old.len().saturating_sub(MAX_DELETES);
    old.truncate(MAX_DELETES);
    // Profiles first: a profile may reference a topic.
    old.sort_by_key(|candidate| candidate.kind);
    selection.delete = old;
    selection
}

/// One sweep. Returns the summary (rows per deletion, counts in notices).
pub fn run_live_cleanup(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
    run_live_cleanup_at(plan, now_unix())
}

/// [`run_live_cleanup`] with an explicit "now" (Unix seconds).
pub fn run_live_cleanup_at(plan: &LivePlan, now: u64) -> Result<LiveReport, LiveAbort> {
    let mut session = Session::open(plan)?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sweep(&mut session, plan, now)
    }));
    session.report.store_removed = Some(session.store.remove());
    match outcome {
        Err(panic) => std::panic::resume_unwind(panic),
        Ok(result) => result?,
    }
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

fn listing(session: &Session<'_>, kind: Kind) -> Result<Vec<(String, String)>, LiveAbort> {
    let (group, args): (&str, Vec<&str>) = match kind {
        Kind::Topic | Kind::Profile => {
            let group = if kind == Kind::Topic {
                "topics"
            } else {
                "profiles"
            };
            (
                group,
                vec![
                    "runtime",
                    group,
                    "list",
                    "--all",
                    "--all-versions",
                    "--max",
                    "0",
                    "--output",
                    "json",
                ],
            )
        }
        Kind::Adapter => (
            "adapter",
            vec![
                "redteam", "adapter", "list", "--all", "--max", "0", "--output", "json",
            ],
        ),
        Kind::Pattern | Kind::Dictionary => {
            let group = if kind == Kind::Pattern {
                "patterns"
            } else {
                "dictionaries"
            };
            (
                group,
                vec![
                    "runtime", "dlp", group, "list", "--all", "--max", "0", "--output", "json",
                ],
            )
        }
        Kind::Group => (
            "groups",
            vec![
                "model-security",
                "groups",
                "list",
                "--search",
                RESOURCE_PREFIX,
                "--all",
                "--max",
                "0",
                "--output",
                "json",
            ],
        ),
        Kind::Scan | Kind::ModelScan => {
            return Err(LiveAbort::Setup("scans are never swept".into()));
        }
    };
    let exec = session.exec(&session.plan.rust, "cleanup listing", &args)?;
    let json = exec.json();
    match (exec.code, listed(&json, kind)) {
        (Some(0), Some(rows)) if kind.is_dlp() => Ok(live_dlp_rows(&json, rows)),
        (Some(0), Some(rows)) => Ok(rows),
        // A tenant without red team, DLP or model-security access has none to sweep.
        _ if matches!(
            kind,
            Kind::Adapter | Kind::Pattern | Kind::Dictionary | Kind::Group
        ) && super::redteam::no_access(exec.code, &exec.stderr) =>
        {
            Ok(Vec::new())
        }
        _ => Err(LiveAbort::Setup(format!(
            "the {group} listing did not complete (exit {}); nothing was deleted",
            exec.exit_cell()
        ))),
    }
}

/// Whether the Rust `model-security groups get <id>` answers 404 (the group is gone).
fn group_gone(session: &Session<'_>, id: &str) -> Result<bool, LiveAbort> {
    let exec = session.exec(
        &session.plan.rust,
        "cleanup group check",
        &["model-security", "groups", "get", id, "--output", "json"],
    )?;
    Ok(exec.code == Some(1) && exec.stderr.lines().any(|line| line.trim() == "HTTP 404"))
}

/// The rows of a DLP listing whose `status` is not `deleted` (a soft-deleted pattern
/// stays listed and is never deleted again).
fn live_dlp_rows(json: &serde_json::Value, rows: Vec<(String, String)>) -> Vec<(String, String)> {
    let deleted: Vec<&str> = json
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|row| {
                    row.get("status").and_then(serde_json::Value::as_str) == Some("deleted")
                })
                .filter_map(|row| row.get("id").and_then(serde_json::Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    rows.into_iter()
        .filter(|(id, _)| !deleted.contains(&id.as_str()))
        .collect()
}

fn sweep(session: &mut Session<'_>, plan: &LivePlan, now: u64) -> Result<(), LiveAbort> {
    let profiles = listing(session, Kind::Profile)?;
    let topics = listing(session, Kind::Topic)?;
    let adapters = listing(session, Kind::Adapter)?;
    let patterns = listing(session, Kind::Pattern)?;
    let dictionaries = listing(session, Kind::Dictionary)?;
    let groups = listing(session, Kind::Group)?;
    let selection = select_lists(
        &[
            (Kind::Profile, &profiles),
            (Kind::Topic, &topics),
            (Kind::Adapter, &adapters),
            (Kind::Pattern, &patterns),
            (Kind::Dictionary, &dictionaries),
            (Kind::Group, &groups),
        ],
        now,
    );
    let run_id = session.store.run_id().to_owned();
    let mut ledger = Ledger::open(&plan.store_root, &run_id).map_err(LiveAbort::Setup)?;
    let mut deleted = 0;
    let mut failed = 0;
    for candidate in &selection.delete {
        // A group already gone (a 404 on the Rust get) is not deleted again (§10 M6c).
        if candidate.kind == Kind::Group && group_gone(session, &candidate.id)? {
            continue;
        }
        match journalled_delete(
            session,
            &mut ledger,
            Phase::Cleanup,
            (candidate.kind, &candidate.name),
            &candidate.id,
        )? {
            Outcome::Ok => deleted += 1,
            _ => failed += 1,
        }
    }
    session.report.notices.push(format!(
        "sweeper: {} selected, {deleted} deleted, {failed} failed or referenced (kept), {} over the cap of {MAX_DELETES} left for the next run, {} younger than 1 hour kept",
        selection.delete.len(),
        selection.deferred,
        selection.too_young
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u64) -> String {
        format!("00000000-0000-4000-8000-{n:012}")
    }

    #[test]
    fn only_exact_names_parse() {
        assert_eq!(
            parse_name("airs-rs-e2e-1792281599-42-0-topic-rs"),
            Some(ResourceName {
                created: 1_792_281_599,
                kind: Kind::Topic
            })
        );
        assert!(parse_name("airs-rs-e2e-1792281599-42-0-profile-ts").is_some());
        for bad in [
            "alpha",
            "airs-rs-e2e-",
            "airs-rs-e2e-179228159-42-0-topic-rs",
            "airs-rs-e2e-17922815999-42-0-topic-rs",
            "airs-rs-e2e-1792281599-42-0-topic-go",
            "airs-rs-e2e-1792281599-42-0-dlp-rs",
            "airs-rs-e2e-1792281599-42-0-pattern-go",
            "airs-rs-e2e-1792281599-42-0-topic-rs-x",
            "airs-rs-e2e-1792281599--0-topic-rs",
            "airs-rs-e2e-1792281599-4a-0-topic-rs",
            "xairs-rs-e2e-1792281599-42-0-topic-rs",
            "AIRS-RS-E2E-1792281599-42-0-topic-rs",
            "airs-rs-e2e-1792281599-42-0-topic-rs\n",
        ] {
            assert_eq!(parse_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn dlp_names_parse_with_the_restored_copies() {
        for (name, kind) in [
            ("airs-rs-e2e-1792281599-42-0-pattern-rs", Kind::Pattern),
            ("airs-rs-e2e-1792281599-42-0-pattern-rr", Kind::Pattern),
            (
                "airs-rs-e2e-1792281599-42-0-dictionary-ts",
                Kind::Dictionary,
            ),
        ] {
            assert_eq!(
                parse_name(name).map(|parsed| parsed.kind),
                Some(kind),
                "{name}"
            );
        }
        assert_eq!(parse_name("airs-rs-e2e-1792281599-42-0-topic-rr"), None);
        assert_eq!(parse_name("airs-rs-e2e-1792281599-42-0-pattern-xx"), None);
        let now = 1_800_000_000;
        let old = format!("airs-rs-e2e-{}-1-0-pattern-rr", now - 7200);
        let rows = vec![
            ("p-new-1".to_owned(), old.clone()),
            ("not an id".to_owned(), old),
        ];
        let selection = select_lists(&[(Kind::Pattern, &rows)], now);
        assert_eq!(selection.delete.len(), 1);
        assert_eq!(selection.delete[0].id, "p-new-1");
    }

    #[test]
    fn selection_filters_prefix_kind_and_age_and_caps() {
        let now = 1_800_000_000;
        let old = |n: u64| format!("airs-rs-e2e-{}-1-0-topic-rs", now - 3600 - n);
        let mut topics: Vec<(String, String)> = (0..25).map(|n| (uuid(n), old(n))).collect();
        topics.push((uuid(100), "airs-rs-e2e-precious".into()));
        topics.push((uuid(101), "customer-topic".into()));
        topics.push((
            uuid(102),
            format!("airs-rs-e2e-{}-1-0-topic-rs", now - 3599),
        ));
        topics.push((
            uuid(103),
            format!("airs-rs-e2e-{}-1-0-profile-rs", now - 9000),
        ));
        topics.push(("not-a-uuid".into(), old(0)));
        topics.push((uuid(104), format!("airs-rs-e2e-{}-1-0-topic-rs", now + 10)));
        let profiles = vec![
            (
                uuid(200),
                format!("airs-rs-e2e-{}-1-0-profile-ts", now - 4000),
            ),
            (uuid(201), "airs-rs-e2e-1-1-0-profile-ts".into()),
        ];
        let selection = select(&topics, &profiles, now);
        assert_eq!(selection.too_young, 2);
        assert_eq!(selection.delete.len(), MAX_DELETES);
        assert_eq!(selection.deferred, 6);
        assert_eq!(selection.delete[0].id, uuid(200), "profiles first");
        assert!(selection.delete[1..].iter().all(|c| c.kind == Kind::Topic));
        // The oldest topics (largest n) were kept within the cap.
        assert!(selection.delete.iter().any(|c| c.id == uuid(24)));
        assert!(!selection.delete.iter().any(|c| c.id == uuid(0)));
        for kept in [100, 101, 102, 103, 104, 201] {
            assert!(
                !selection.delete.iter().any(|c| c.id == uuid(kept)),
                "{kept}"
            );
        }
    }
}
