//! `runtime profiles cleanup` (DESIGN §13.15, D105, D108–D110).
//!
//! The listing is the SDK walk (no `latest`, 200 per page, the `--all` bounds): nothing
//! is deleted unless it completed. Records are grouped by exact name; a group whose
//! revisions or ids are missing, whose highest revision is tied, or one of whose ids
//! occurs more than once in the listing, is skipped. The
//! preview is shown (pretty: on stdout, before anything else happens), then `--dry-run`
//! stops, a confirmation is asked (and the listing re-checked after it), or `--force`
//! proceeds. Deletions are sequential plain deletes, or force deletes with
//! `--updated-by`; the first one with an unknown outcome stops the run.

use super::{Invocation, confirm, nothing_changed, profile_walk_options, walk_options};
use crate::cli::ProfileCleanupArgs;
use crate::clients::WALK_BUDGET;
use crate::error::{CliError, InterruptContext};
use crate::output::{Format, terminal_safe};
use crate::pagination;
use crate::render::js_json_number;
use crate::render::pretty;
use crate::render::style::Style;
use crate::render::table;
use crate::writes::{self, Change};
use scm::airs::management::models::SecurityProfile;
use scm::airs::management::{ManagementClient, ProfileListAllOptions};
use scm::{ErrorKind, RemoteOutcome};
use serde::Serialize;
use serde_json::Number;
use std::collections::HashMap;

/// Page size of the cleanup listing (TS `pageSize`).
const PAGE: u32 = 200;

/// Why a group was skipped (D110).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Skip {
    /// A record without revision or id, or a tied highest revision.
    MissingOrTied,
    /// One of the group's ids occurs more than once in the listing: deleting an older
    /// revision could delete the kept one.
    SharedId,
}

impl Skip {
    /// The `skipped[].reason` of the JSON document.
    fn reason(self) -> &'static str {
        match self {
            Self::MissingOrTied => "missing or tied revisions",
            Self::SharedId => "shared profile ids",
        }
    }

    /// The warning line (without the `⚠ Skipped <name>: ` prefix).
    fn warning(self) -> &'static str {
        match self {
            Self::MissingOrTied => "its revisions are missing or tied; nothing was deleted for it",
            Self::SharedId => "its revisions share a profile id; nothing was deleted for it",
        }
    }
}

/// A validated `profiles cleanup`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupPlan {
    pub force: bool,
    /// `Some(email)`: the force endpoint with that audit email (D109).
    pub updated_by: Option<String>,
    pub dry_run: bool,
    pub format: Format,
}

pub fn plan_cleanup(
    args: &ProfileCleanupArgs,
    format: Format,
    interactive: bool,
) -> Result<CleanupPlan, CliError> {
    if args.force && args.dry_run {
        return Err(CliError::usage("--dry-run cannot be combined with --force"));
    }
    let updated_by = match args.updated_by.as_deref() {
        None => None,
        Some(value) if crate::tenant::config::js_trim(value).is_empty() => {
            return Err(CliError::usage("--updated-by <email> must not be blank"));
        }
        Some(value) if super::topic_write::has_control(value) => {
            return Err(CliError::usage(super::topic_write::UPDATED_BY_CONTROL));
        }
        Some(value) => Some(value.to_owned()),
    };
    if !args.force && !args.dry_run && !interactive {
        return Err(CliError::usage(
            "refusing to delete profile revisions without --force in non-interactive mode",
        ));
    }
    Ok(CleanupPlan {
        force: args.force,
        updated_by,
        dry_run: args.dry_run,
        format,
    })
}

/// One revision to delete.
#[derive(Clone, Debug, PartialEq)]
struct Entry {
    id: String,
    revision: Number,
}

/// A name with more than one revision and a unique highest one.
#[derive(Clone, Debug, PartialEq)]
struct Group {
    name: String,
    size: usize,
    keep_id: String,
    keep_revision: Number,
    /// Highest revision first (stable for equal lower revisions).
    delete: Vec<Entry>,
}

/// What a listing selects: the groups to delete from and the names skipped (D110).
#[derive(Clone, Debug, Default, PartialEq)]
struct Selection {
    groups: Vec<Group>,
    skipped: Vec<(String, Skip)>,
}

impl Selection {
    fn total(&self) -> usize {
        self.groups.iter().map(|group| group.delete.len()).sum()
    }
}

/// Groups by exact `profile_name` in first-seen order and selects the old revisions of
/// each group with a unique highest revision, every revision and id present, and no id
/// that occurs more than once in the whole listing (a service that kept the id across
/// revisions would otherwise have the kept revision deleted).
fn select(records: &[SecurityProfile]) -> Selection {
    let mut order: Vec<(&str, Vec<&SecurityProfile>)> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut id_counts: HashMap<&str, usize> = HashMap::new();
    for record in records {
        if let Some(id) = crate::views::non_empty_id(record.profile_id.as_ref().into_option()) {
            *id_counts.entry(id).or_default() += 1;
        }
        let name = record.profile_name.as_str();
        match index.get(name) {
            Some(&at) => order[at].1.push(record),
            None => {
                index.insert(name, order.len());
                order.push((name, vec![record]));
            }
        }
    }
    let mut selection = Selection::default();
    for (name, members) in order {
        if members.len() < 2 {
            continue;
        }
        let complete: Option<Vec<(f64, Entry)>> = members
            .iter()
            .map(|record| {
                let id = crate::views::non_empty_id(record.profile_id.as_ref().into_option())?;
                let revision = record.revision.as_ref().into_option()?;
                Some((
                    revision.as_f64()?,
                    Entry {
                        id: id.to_owned(),
                        revision: revision.as_number().clone(),
                    },
                ))
            })
            .collect();
        let Some(mut entries) = complete else {
            selection
                .skipped
                .push((name.to_owned(), Skip::MissingOrTied));
            continue;
        };
        let highest = entries
            .iter()
            .map(|(value, _)| *value)
            .fold(f64::NEG_INFINITY, f64::max);
        if entries
            .iter()
            .filter(|(value, _)| *value == highest)
            .count()
            > 1
        {
            selection
                .skipped
                .push((name.to_owned(), Skip::MissingOrTied));
            continue;
        }
        if entries
            .iter()
            .any(|(_, entry)| id_counts.get(entry.id.as_str()).copied().unwrap_or(0) > 1)
        {
            selection.skipped.push((name.to_owned(), Skip::SharedId));
            continue;
        }
        entries.sort_by(|(a, _), (b, _)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        let mut entries = entries.into_iter().map(|(_, entry)| entry);
        let Some(keep) = entries.next() else {
            continue;
        };
        selection.groups.push(Group {
            name: name.to_owned(),
            size: members.len(),
            keep_id: keep.id,
            keep_revision: keep.revision,
            delete: entries.collect(),
        });
    }
    selection
}

/// How one deletion ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Failed,
    Unknown,
    NotAttempted,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::NotAttempted => "notAttempted",
        }
    }
}

/// One `details[]` entry.
struct Outcome<'a> {
    group: &'a Group,
    entry: &'a Entry,
    status: Status,
    error: Option<String>,
}

#[derive(Default)]
struct Counts {
    deleted: usize,
    failed: usize,
    unknown: usize,
    not_attempted: usize,
}

impl Counts {
    fn of(outcomes: &[Outcome<'_>]) -> Self {
        let mut counts = Self::default();
        for outcome in outcomes {
            match outcome.status {
                Status::Ok => counts.deleted += 1,
                Status::Failed => counts.failed += 1,
                Status::Unknown => counts.unknown += 1,
                Status::NotAttempted => counts.not_attempted += 1,
            }
        }
        counts
    }

    fn clean(&self) -> bool {
        self.failed == 0 && self.unknown == 0 && self.not_attempted == 0
    }

    /// The interrupt context once deletions have started (`nothing was changed` while
    /// nothing was deleted or possibly deleted).
    fn interrupt(&self) -> InterruptContext {
        if self.deleted == 0 && self.failed == 0 && self.unknown == 0 {
            InterruptContext::NothingChanged
        } else {
            InterruptContext::CleanupStopped {
                deleted: self.deleted,
                failed: self.failed,
                unknown: self.unknown,
                not_attempted: self.not_attempted,
            }
        }
    }
}

#[derive(Serialize)]
struct DuplicateRow<'a> {
    name: &'a str,
    revisions: usize,
    keeping: &'a Number,
    deleting: usize,
}

#[derive(Serialize)]
struct SkippedRow<'a> {
    name: &'a str,
    reason: &'static str,
}

#[derive(Serialize)]
struct DetailRow<'a> {
    id: &'a str,
    revision: &'a Number,
    name: &'a str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// The one JSON document of §13.15.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Document<'a> {
    duplicates: Vec<DuplicateRow<'a>>,
    total: usize,
    skipped: Vec<SkippedRow<'a>>,
    deleted: usize,
    failed: usize,
    unknown: usize,
    not_attempted: usize,
    details: Vec<DetailRow<'a>>,
}

/// The preview table's rows (cells terminal-safe).
fn preview_rows(selection: &Selection) -> Vec<Vec<String>> {
    selection
        .groups
        .iter()
        .map(|group| {
            vec![
                terminal_safe(&group.name).into_owned(),
                group.size.to_string(),
                format!("rev {}", js_json_number(&group.keep_revision)),
                group.delete.len().to_string(),
            ]
        })
        .collect()
}

const PREVIEW_LABELS: [&str; 4] = ["Profile", "Revisions", "Keeping", "Deleting"];

/// The pretty preview (data, except the banner and section): TS `renderCleanupPreview`.
fn render_pretty_preview(invocation: &mut Invocation, selection: &Selection) {
    let out = &mut invocation.output;
    crate::views::runtime_banner(out);
    pretty::section(out, "Duplicate Profiles:");
    let text = table::table(&PREVIEW_LABELS, &preview_rows(selection));
    for line in text.split('\n') {
        out.data_line(&format!("  {line}"));
    }
    out.data(&format!(
        "\n  Total: {} old revisions to delete across {} profiles\n\n",
        selection.total(),
        selection.groups.len()
    ));
}

/// The table or json document, printed once after the run.
fn render_document(
    invocation: &mut Invocation,
    format: Format,
    selection: &Selection,
    outcomes: &[Outcome<'_>],
) -> Result<(), CliError> {
    match format {
        Format::Pretty => Ok(()),
        Format::Table => {
            let text = table::table(&PREVIEW_LABELS, &preview_rows(selection));
            if !text.is_empty() {
                invocation.output.data_line(&text);
            }
            Ok(())
        }
        Format::Json => {
            let counts = Counts::of(outcomes);
            let document = Document {
                duplicates: selection
                    .groups
                    .iter()
                    .map(|group| DuplicateRow {
                        name: &group.name,
                        revisions: group.size,
                        keeping: &group.keep_revision,
                        deleting: group.delete.len(),
                    })
                    .collect(),
                total: selection.total(),
                skipped: selection
                    .skipped
                    .iter()
                    .map(|(name, skip)| SkippedRow {
                        name,
                        reason: skip.reason(),
                    })
                    .collect(),
                deleted: counts.deleted,
                failed: counts.failed,
                unknown: counts.unknown,
                not_attempted: counts.not_attempted,
                details: outcomes
                    .iter()
                    .map(|outcome| DetailRow {
                        id: &outcome.entry.id,
                        revision: &outcome.entry.revision,
                        name: &outcome.group.name,
                        status: outcome.status.name(),
                        error: outcome.error.as_deref(),
                    })
                    .collect(),
            };
            invocation.output.json(&document)
        }
    }
}

/// A `ui.bullet` on stderr: only the glyph is coloured. Success bullets are
/// quiet-suppressed (and not printed after a signal); failure bullets never are.
fn bullet(invocation: &mut Invocation, success: bool, text: &str) {
    let out = &mut invocation.output;
    if success && (out.quiet() || out.pending_signal().is_some()) {
        return;
    }
    let glyph = if success {
        out.paint_err(Style::Green, "✓")
    } else {
        out.paint_err(Style::Red, "✗")
    };
    out.write_stderr(&format!("  {glyph} {}\n", terminal_safe(text)));
}

/// `<name> rev <r>[: <message>][ (outcome unknown)]`.
fn bullet_text(outcome: &Outcome<'_>) -> String {
    let mut text = format!(
        "{} rev {}",
        outcome.group.name,
        js_json_number(&outcome.entry.revision)
    );
    if let Some(error) = &outcome.error {
        text.push_str(&format!(": {error}"));
    }
    if outcome.status == Status::Unknown {
        text.push_str(" (outcome unknown)");
    }
    text
}

/// The complete listing (D108): the SDK walk, every revision, nothing below the
/// 1,000,000-row ceiling cut off. Each listing (the first and the re-check) has its own
/// 300 s deadline and reads without the response defaults (§15.25).
async fn listing(
    invocation: &Invocation,
    management: &ManagementClient,
) -> Result<Vec<SecurityProfile>, CliError> {
    let options = profile_walk_options()?;
    let mut all = ProfileListAllOptions::default();
    all.limit = PAGE;
    all.latest = None;
    all.collect = pagination::collect_options(0)
        .map_err(|error| invocation.management_error(&error, WALK_BUDGET))?;
    let collection = management
        .profiles()
        .list_all(all, Some(&options))
        .await
        .map_err(|error| {
            nothing_changed(invocation.management_error(error.error(), WALK_BUDGET))
        })?;
    pagination::walk_end(collection.completion, 0).ok_or_else(|| {
        nothing_changed(invocation.management_error(&pagination::incomplete_walk(), WALK_BUDGET))
    })?;
    Ok(collection.items)
}

pub async fn cleanup(invocation: &mut Invocation, plan: &CleanupPlan) -> Result<(), CliError> {
    let options = walk_options()?;
    let (management, format) = invocation
        .connect_management(Some(plan.format), Some(&options))
        .await
        .map_err(nothing_changed)?;
    let records = listing(invocation, &management).await?;
    let selection = select(&records);
    drop(records);
    for (name, skip) in &selection.skipped {
        invocation.output.warning(&format!(
            "⚠ Skipped {}: {}",
            terminal_safe(name),
            skip.warning()
        ));
    }
    let total = selection.total();
    if total == 0 {
        render_document(invocation, format, &selection, &[])?;
        invocation.output.success("No duplicate profiles found.");
        return Ok(());
    }
    if format == Format::Pretty {
        render_pretty_preview(invocation, &selection);
        // The preview is shown before the question and before any deletion (§13.15).
        let _ = invocation.output.commit();
    }
    if plan.dry_run {
        render_document(invocation, format, &selection, &[])?;
        invocation
            .output
            .status("Pass --force to delete these revisions.");
        return Ok(());
    }
    if !plan.force {
        let plural = if total == 1 { "" } else { "s" };
        if !confirm(
            invocation,
            &format!("Delete {total} old profile revision{plural}?"),
        )? {
            invocation.output.info("Aborted");
            return Ok(());
        }
        // Delete only what was shown (D105).
        let again = select(&listing(invocation, &management).await?);
        if again != selection {
            return Err(CliError::operational(
                "The profile list changed while waiting for confirmation; nothing was deleted. Run the command again.",
            ));
        }
    }
    let outcomes = delete_all(invocation, &management, plan, &selection).await?;
    render_document(invocation, format, &selection, &outcomes)?;
    let counts = Counts::of(&outcomes);
    summarise(invocation, &outcomes, &counts);
    if counts.clean() {
        Ok(())
    } else {
        // The document first, then exit 1 without an error block (TS parity).
        let _ = invocation.output.commit();
        Err(CliError::Reported(crate::error::EXIT_OPERATIONAL))
    }
}

/// The sequential deletion loop (D109, D110).
async fn delete_all<'a>(
    invocation: &mut Invocation,
    management: &ManagementClient,
    plan: &CleanupPlan,
    selection: &'a Selection,
) -> Result<Vec<Outcome<'a>>, CliError> {
    let profiles = management.profiles();
    let secrets = invocation.secrets.clone();
    let mut outcomes: Vec<Outcome<'a>> = selection
        .groups
        .iter()
        .flat_map(|group| {
            group.delete.iter().map(move |entry| Outcome {
                group,
                entry,
                status: Status::NotAttempted,
                error: None,
            })
        })
        .collect();
    for index in 0..outcomes.len() {
        let counts = Counts::of(&outcomes);
        invocation.interrupt = Some(counts.interrupt());
        if invocation.output.pending_signal().is_some() {
            return Err(CliError::Interrupted(counts.interrupt()));
        }
        let id = outcomes[index].entry.id.clone();
        let result = writes::attempt(async || match &plan.updated_by {
            Some(updated_by) => profiles.force_delete(&id, updated_by, None).await,
            None => profiles.delete(&id, None).await,
        })
        .await;
        let (status, error) = match result {
            Ok(_) => (Status::Ok, None),
            // A 2xx whose body could not be read: the revision was deleted (G4).
            Err(error)
                if error.kind() == ErrorKind::Decode
                    && error
                        .status()
                        .is_some_and(|code| (200..300).contains(&code)) =>
            {
                (Status::Ok, None)
            }
            Err(error) => match writes::describe(&error, Change::ProfileDeleted, &secrets) {
                CliError::Interrupted(context) => {
                    let mut counts = Counts::of(&outcomes);
                    if context != InterruptContext::NothingChanged {
                        counts.unknown += 1;
                        counts.not_attempted -= 1;
                    }
                    return Err(CliError::Interrupted(counts.interrupt()));
                }
                failure => {
                    let unknown = error.remote_outcome() == RemoteOutcome::Unknown;
                    (
                        if unknown {
                            Status::Unknown
                        } else {
                            Status::Failed
                        },
                        Some(failure.message()),
                    )
                }
            },
        };
        outcomes[index].status = status;
        outcomes[index].error = error;
        let text = bullet_text(&outcomes[index]);
        bullet(invocation, status == Status::Ok, &text);
        if status == Status::Unknown {
            let left = outcomes.len() - index - 1;
            invocation.output.warning(&format!(
                "⚠ Stopped after a deletion with an unknown outcome; {left} not attempted"
            ));
            break;
        }
    }
    invocation.interrupt = Some(Counts::of(&outcomes).interrupt());
    Ok(outcomes)
}

/// The `Failures:` section and the summary line (TS `renderCleanupResult`), on stderr.
fn summarise(invocation: &mut Invocation, outcomes: &[Outcome<'_>], counts: &Counts) {
    let failures: Vec<String> = outcomes
        .iter()
        .filter(|outcome| matches!(outcome.status, Status::Failed | Status::Unknown))
        .map(bullet_text)
        .collect();
    if !failures.is_empty() {
        if !invocation.output.quiet() {
            let label = invocation.output.paint_err(Style::Bold, "Failures:");
            invocation.output.write_stderr(&format!("\n  {label}\n\n"));
        }
        for text in &failures {
            bullet(invocation, false, text);
        }
    }
    if counts.clean() {
        if invocation.output.quiet() || invocation.output.pending_signal().is_some() {
            return;
        }
        invocation.output.write_stderr("\n");
        invocation.output.success(&format!(
            "Cleanup complete: {} deleted, 0 failed",
            counts.deleted
        ));
        invocation.output.write_stderr("\n");
    } else {
        let mut text = format!(
            "⚠ Cleanup complete: {} deleted, {} failed",
            counts.deleted, counts.failed
        );
        if counts.unknown > 0 {
            text.push_str(&format!(", {} outcome unknown", counts.unknown));
        }
        if counts.not_attempted > 0 {
            text.push_str(&format!(", {} not attempted", counts.not_attempted));
        }
        invocation.output.write_stderr("\n");
        invocation.output.warning(&text);
        invocation.output.write_stderr("\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(
        id: Option<&str>,
        name: &str,
        revision: Option<serde_json::Value>,
    ) -> SecurityProfile {
        let mut value = json!({"profile_name": name});
        if let Some(id) = id {
            value["profile_id"] = json!(id);
        }
        if let Some(revision) = revision {
            value["revision"] = revision;
        }
        serde_json::from_value(value).expect("a profile record")
    }

    fn args(force: bool, updated_by: Option<&str>, dry_run: bool) -> ProfileCleanupArgs {
        ProfileCleanupArgs {
            force,
            updated_by: updated_by.map(str::to_owned),
            dry_run,
        }
    }

    #[test]
    fn argument_checks_run_in_order() {
        let usage = |a: ProfileCleanupArgs, interactive: bool| match plan_cleanup(
            &a,
            Format::Pretty,
            interactive,
        ) {
            Err(CliError::Usage(message)) => Some(message),
            Err(other) => panic!("not a usage error: {other:?}"),
            Ok(_) => None,
        };
        assert_eq!(
            usage(args(true, Some(" "), true), false).as_deref(),
            Some("--dry-run cannot be combined with --force")
        );
        assert_eq!(
            usage(args(false, Some("\u{feff} "), false), false).as_deref(),
            Some("--updated-by <email> must not be blank")
        );
        assert_eq!(
            usage(args(true, Some("a\u{1b}b"), false), true).as_deref(),
            Some("--updated-by <email> must not contain control characters")
        );
        assert_eq!(
            usage(args(false, None, false), false).as_deref(),
            Some("refusing to delete profile revisions without --force in non-interactive mode")
        );
        assert_eq!(usage(args(false, None, false), true), None);
        assert_eq!(usage(args(false, None, true), false), None, "dry run");
        let plan = plan_cleanup(&args(true, Some("a@b"), false), Format::Json, false).unwrap();
        assert_eq!(plan.updated_by.as_deref(), Some("a@b"));
        assert!(plan.force && !plan.dry_run);
    }

    #[test]
    fn selection_keeps_the_unique_highest_revision_d110() {
        let records = [
            record(Some("a1"), "a", Some(json!(1))),
            record(Some("solo"), "solo", None),
            record(Some("a3"), "a", Some(json!(3))),
            record(Some("t1"), "tied", Some(json!(2))),
            record(Some("a2"), "a", Some(json!(2))),
            record(Some("t2"), "tied", Some(json!(2))),
            record(None, "noid", Some(json!(1))),
            record(Some("n2"), "noid", Some(json!(2))),
            record(Some("r1"), "norev", None),
            record(Some("r2"), "norev", Some(json!(2))),
            record(Some("l1"), "lower-tie", Some(json!(1))),
            record(Some("l3"), "lower-tie", Some(json!(3))),
            record(Some("l1b"), "lower-tie", Some(json!(1))),
        ];
        let selection = select(&records);
        let skipped: Vec<(&str, Skip)> = selection
            .skipped
            .iter()
            .map(|(name, skip)| (name.as_str(), *skip))
            .collect();
        assert_eq!(
            skipped,
            [
                ("tied", Skip::MissingOrTied),
                ("noid", Skip::MissingOrTied),
                ("norev", Skip::MissingOrTied)
            ]
        );
        let summary: Vec<(String, usize, String, Vec<String>)> = selection
            .groups
            .iter()
            .map(|group| {
                (
                    group.name.clone(),
                    group.size,
                    group.keep_id.clone(),
                    group.delete.iter().map(|entry| entry.id.clone()).collect(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "a".to_owned(),
                    3,
                    "a3".to_owned(),
                    vec!["a2".to_owned(), "a1".to_owned()]
                ),
                (
                    "lower-tie".to_owned(),
                    3,
                    "l3".to_owned(),
                    vec!["l1".to_owned(), "l1b".to_owned()]
                ),
            ]
        );
        assert_eq!(selection.total(), 4);
        assert_eq!(
            select(&records[..2]),
            Selection::default(),
            "groups of one are left alone"
        );
    }

    /// D110: an id that occurs more than once in the listing (revisions that kept their
    /// id, a repeated row, or an id under two names) skips every group holding it, so
    /// the kept revision can never be among the deletions.
    #[test]
    fn shared_ids_skip_the_group_d110() {
        let records = [
            record(Some("p1"), "kept-id", Some(json!(1))),
            record(Some("p1"), "kept-id", Some(json!(2))),
            record(Some("d1"), "dup-old", Some(json!(1))),
            record(Some("d1"), "dup-old", Some(json!(1))),
            record(Some("d2"), "dup-old", Some(json!(2))),
            record(Some("x1"), "renamed", Some(json!(1))),
            record(Some("x2"), "renamed", Some(json!(2))),
            record(Some("x1"), "new-name", Some(json!(3))),
            record(Some("o1"), "ok", Some(json!(1))),
            record(Some("o2"), "ok", Some(json!(2))),
        ];
        let selection = select(&records);
        assert_eq!(
            selection.skipped,
            [
                ("kept-id".to_owned(), Skip::SharedId),
                ("dup-old".to_owned(), Skip::SharedId),
                ("renamed".to_owned(), Skip::SharedId),
            ]
        );
        assert_eq!(selection.groups.len(), 1);
        assert_eq!(selection.groups[0].name, "ok");
        assert_eq!(selection.groups[0].keep_id, "o2");
        assert_eq!(
            selection.groups[0].delete,
            [Entry {
                id: "o1".into(),
                revision: 1.into()
            }]
        );
        for group in &selection.groups {
            assert!(group.delete.iter().all(|entry| entry.id != group.keep_id));
        }
    }

    #[test]
    fn interrupt_contexts_name_what_happened() {
        assert_eq!(
            InterruptContext::CleanupStopped {
                deleted: 2,
                failed: 0,
                unknown: 0,
                not_attempted: 3
            }
            .text(),
            "2 deleted, 3 not attempted"
        );
        assert_eq!(
            InterruptContext::CleanupStopped {
                deleted: 1,
                failed: 1,
                unknown: 1,
                not_attempted: 0
            }
            .text(),
            "1 deleted, 1 failed, 1 outcome unknown, 0 not attempted"
        );
        assert_eq!(
            Counts {
                not_attempted: 4,
                ..Counts::default()
            }
            .interrupt(),
            InterruptContext::NothingChanged
        );
    }
}
