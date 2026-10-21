//! `runtime profiles backup [profile]` (DESIGN §18.15, D215, D218).
//!
//! The destination is checked before the tenant is read (its directory must exist and
//! nothing may be at the path); the profile inventory (`latest=true`) and, only when a
//! selected policy references a topic, the topic inventory are walked with the TypeScript
//! page rules (an absent collection is an error, never an empty inventory); the selection
//! follows TypeScript; the Rust format is published exclusively at 0600 after every read.
//! `--debug` is refused during planning.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;

use super::Invocation;
use crate::cli::ProfileBackupArgs;
use crate::clients::{ManagementClients, Planes, WALK_BUDGET};
use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::output::{Format, terminal_safe};
use crate::render::table;
use crate::runtime::transfer::plan::{self as pl, Collection, OffsetWalk, Refusal, Step};
use crate::runtime::transfer::{self, Backup, Entry};
use scm::airs::management::{PaginationOptions, TopicListOptions};
use serde_json::Value;

/// The `--debug` refusal of both transfer commands (D156 extended).
pub const DEBUG_REFUSED: &str =
    "Disable --debug for profile transfer; backups can contain sensitive policy configuration";

/// What an interruption before the file exists reports.
pub const NO_BACKUP_WRITTEN: &str = "no backup file was written";

/// The default `--max-pages`.
pub const DEFAULT_MAX_PAGES: u64 = 100;

/// A validated `runtime profiles backup`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupPlan {
    /// The selector (`profile_id` or `profile_name`, exact); `None`: every profile.
    pub selector: Option<String>,
    /// `--output-file` (else the default name in the current directory).
    pub output_file: Option<OsString>,
    pub max_pages: u64,
    pub format: Option<Format>,
}

/// `--max-pages` of the transfer commands (TS: `^\d+$`, 1–1000).
pub fn max_pages(value: Option<&str>) -> Result<u64, CliError> {
    value
        .map(crate::pagination::parse_max_pages)
        .transpose()
        .map(|pages| pages.unwrap_or(DEFAULT_MAX_PAGES))
}

/// The argument checks of §18.15, in order (exit 2, before the tenant).
pub fn plan(
    args: &ProfileBackupArgs,
    format: Option<Format>,
    debug: bool,
) -> Result<BackupPlan, CliError> {
    if debug {
        return Err(CliError::usage(DEBUG_REFUSED));
    }
    let max_pages = max_pages(args.max_pages.as_deref())?;
    if args.all && args.profile.is_some() {
        return Err(CliError::usage("Choose either a profile selector or --all"));
    }
    if args
        .file_format
        .as_deref()
        .is_some_and(|format| format != "json")
    {
        return Err(CliError::usage(
            "--file-format must be json (yaml was dropped)",
        ));
    }
    if let Some(path) = &args.output_file {
        if path == "-" {
            return Err(CliError::usage(
                "Backups require a private file destination, not stdout",
            ));
        }
        if path.is_empty() {
            return Err(CliError::usage("--output-file needs a path"));
        }
        let json = std::path::Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
        if !json {
            return Err(CliError::usage(
                "Backup filename extension must match --file-format",
            ));
        }
    }
    if args
        .profile
        .as_deref()
        .is_some_and(|profile| crate::tenant::config::js_trim(profile).is_empty())
    {
        return Err(CliError::usage("Profile selector must not be empty"));
    }
    Ok(BackupPlan {
        selector: args.profile.clone(),
        output_file: args.output_file.clone(),
        max_pages,
        format,
    })
}

/// An interruption reports `context`; other errors pass.
pub(super) fn within(context: &InterruptContext) -> impl Fn(CliError) -> CliError + '_ {
    move |error| match error {
        CliError::Interrupted(_) => CliError::Interrupted(context.clone()),
        other => other,
    }
}

/// Why an inventory walk stopped.
pub(super) enum WalkError {
    /// The SDK read failed.
    Sdk(scm::Error),
    /// A TypeScript page rule (or D218) refused the answer.
    Rule(Refusal),
}

impl WalkError {
    /// The planning error: the §6 message of an SDK failure, the rule's text otherwise.
    pub(super) fn into_cli(self, invocation: &Invocation) -> CliError {
        match self {
            Self::Sdk(error) => invocation.management_error(&error, WALK_BUDGET),
            Self::Rule(refusal) => CliError::operational(crate::runtime::shown(
                refusal.message(),
                &invocation.secrets,
            )),
        }
    }
}

/// One inventory walk (TS `offsetPages`) under one walk budget with the SDK read retries
/// and no response defaults (G27); `absent` is the D218 message.
pub(super) async fn inventory(
    clients: &ManagementClients,
    collection: Collection,
    max_pages: u64,
    absent: String,
) -> Result<Vec<OValue>, WalkError> {
    let options = crate::runtime::options(WALK_BUDGET)
        .map_err(|error| WalkError::Rule(Refusal::Withheld(error.message())))?;
    let mut walk = OffsetWalk::new(collection, max_pages, absent);
    let mut offset = walk.start();
    loop {
        let answer = match collection {
            Collection::Profiles => {
                let mut page = PaginationOptions::default();
                page.offset = offset;
                page.limit = pl::PAGE_LIMIT;
                page.latest = Some(true);
                let answer = clients
                    .management
                    .profiles()
                    .list(page, Some(&options))
                    .await
                    .map_err(WalkError::Sdk)?;
                crate::json::page_value(&answer).map_err(WalkError::Sdk)?
            }
            Collection::Topics => {
                let mut page = TopicListOptions::default();
                page.offset = offset;
                page.limit = pl::PAGE_LIMIT;
                let answer = clients
                    .management
                    .topics()
                    .list(page, Some(&options))
                    .await
                    .map_err(WalkError::Sdk)?;
                crate::json::page_value(&answer).map_err(WalkError::Sdk)?
            }
        };
        match walk.accept(&answer).map_err(WalkError::Rule)? {
            Step::Next(next) => offset = next,
            Step::Done => return Ok(walk.into_items()),
        }
    }
}

/// `./airs-runtime-profiles-backup-<ISO time, ':' and '.' → '-'>-<8 hex>.json` (TS name).
pub fn default_path(exported_at: &str) -> PathBuf {
    PathBuf::from(".").join(format!(
        "airs-runtime-profiles-backup-{}-{}.json",
        transfer::stamp(exported_at),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ))
}

/// `runtime profiles backup` (§18.15).
pub async fn run(invocation: &mut Invocation, plan: &BackupPlan) -> Result<(), CliError> {
    // The location, before the tenant and any request.
    let exported_at = crate::debug::iso_timestamp(std::time::SystemTime::now());
    let path = plan
        .output_file
        .as_ref()
        .map_or_else(|| default_path(&exported_at), PathBuf::from);
    let dir = crate::files::parent_dir(&path);
    if !std::fs::metadata(&dir).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(CliError::operational(format!(
            "Cannot write a backup into {}; it must be an existing directory",
            terminal_safe(&crate::files::shown(dir.as_os_str()))
        )));
    }
    crate::files::refuse_existing(&path, "--output-file")?;
    let context = InterruptContext::Context(NO_BACKUP_WRITTEN.to_owned());
    let tenant = invocation.runtime_tenant().map_err(within(&context))?;
    let connected = invocation
        .connect_tenant(&tenant, Planes::default())
        .map_err(within(&context))?;
    let format = connected.format(plan.format);
    let clients = &connected.clients;
    let deadline = crate::runtime::options(WALK_BUDGET)?;
    clients
        .authenticate(Some(&deadline), WALK_BUDGET)
        .await
        .map_err(within(&context))?;
    let rule = |message: String| CliError::operational(terminal_safe(&message).into_owned());
    let refused = |refusal: Refusal| rule(refusal.into());
    let items = inventory(
        clients,
        Collection::Profiles,
        plan.max_pages,
        "Inventory of security profiles was not returned; retry the operation".to_owned(),
    )
    .await
    .map_err(|error| error.into_cli(invocation))
    .map_err(within(&context))?;
    let values: Vec<Value> = items.iter().map(crate::json::value_of).collect();
    let kept = pl::latest_profiles(&values).map_err(refused)?;
    pl::assert_tenant(kept.iter().map(|index| &values[*index]), tenant.tsg()).map_err(refused)?;
    let selected: Vec<usize> = match &plan.selector {
        None => kept,
        Some(selector) => kept
            .into_iter()
            .filter(|index| {
                let record = &values[*index];
                pl::text(record, "profile_id") == Some(selector.as_str())
                    || pl::text(record, "profile_name") == Some(selector.as_str())
            })
            .collect(),
    };
    if selected.is_empty() {
        return Err(CliError::operational("No matching profiles to back up"));
    }
    if plan.selector.is_some() && selected.len() != 1 {
        return Err(CliError::operational("Ambiguous profile selector"));
    }
    let mut refs = Vec::new();
    for index in &selected {
        let record = &values[*index];
        let policy = record.get("policy").filter(|policy| !policy.is_null());
        if policy.is_none() {
            return Err(rule(format!(
                "Profile has no policy: {}",
                pl::text(record, "profile_name").unwrap_or_default()
            )));
        }
        refs.extend(pl::topic_references(policy).map_err(refused)?);
    }
    let definitions = if refs.is_empty() {
        Vec::new()
    } else {
        inventory(
            clients,
            Collection::Topics,
            plan.max_pages,
            "Inventory of custom topics was not returned; retry the operation".to_owned(),
        )
        .await
        .map_err(|error| error.into_cli(invocation))
        .map_err(within(&context))?
    };
    let topic_values: Vec<Value> = definitions.iter().map(crate::json::value_of).collect();
    // The inventory indexed once by record key (the indices in inventory order).
    let mut by_key: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, topic) in topic_values.iter().enumerate() {
        by_key.entry(pl::record_key(topic)).or_default().push(index);
    }
    // The topics to export, in first-reference order; `seen` holds their keys.
    let mut needed: Vec<usize> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for reference in &refs {
        let key = reference.key();
        let matches = by_key.get(&key).map_or(&[][..], Vec::as_slice);
        let exact = matches.len() == 1
            && pl::text(&topic_values[matches[0]], "topic_name")
                == Some(reference.topic_name.as_str());
        if !exact {
            return Err(rule(format!(
                "Cannot export the exact referenced topic revision: {} revision {}",
                reference.topic_name,
                crate::render::js_number(reference.revision)
            )));
        }
        if seen.insert(key) {
            needed.push(matches[0]);
        }
    }
    let document = Backup {
        exported_at,
        tenant: tenant.name().to_owned(),
        tsg_id: tenant.tsg().to_owned(),
        selector: plan.selector.clone(),
        profiles: selected
            .iter()
            .map(|index| Entry {
                record: items[*index].clone(),
            })
            .collect(),
        topics: needed
            .iter()
            .map(|index| Entry {
                record: definitions[*index].clone(),
            })
            .collect(),
    };
    let text = document.to_text();
    if text.len() > transfer::MAX_BACKUP_BYTES {
        return Err(CliError::operational(
            "Backup exceeds the 20 MiB size limit; select individual profiles",
        ));
    }
    if invocation.output.pending_signal().is_some() {
        return Err(CliError::Interrupted(context));
    }
    let published = crate::files::publish_new(&path, text.as_bytes(), "--output-file")?;
    let shown_path = crate::files::shown(path.as_os_str());
    invocation.interrupt = Some(InterruptContext::Context(format!(
        "the backup was saved in {}",
        terminal_safe(&shown_path)
    )));
    if published == crate::files::Published::DirectoryNotSynced {
        invocation
            .output
            .warning(&crate::store::atomic::dir_sync_warning(&path));
    }
    invocation.output.warning(&format!(
        "⚠ {} contains security profile policies and topic definitions; keep it private (mode 0600)",
        terminal_safe(&shown_path)
    ));
    render(invocation, format, &shown_path, &document)
}

/// The TS one-row summary (not indented) or its one-element JSON array.
fn render(
    invocation: &mut Invocation,
    format: Format,
    file: &str,
    document: &Backup,
) -> Result<(), CliError> {
    match format {
        Format::Json => {
            let number = |n: usize| OValue::Number((n as u64).into());
            let doc = OValue::Array(vec![OValue::Object(vec![
                (
                    "file".into(),
                    OValue::String(terminal_safe(file).into_owned()),
                ),
                (
                    "sourceTsgId".into(),
                    OValue::String(document.tsg_id.clone()),
                ),
                ("profiles".into(), number(document.profiles.len())),
                ("topics".into(), number(document.topics.len())),
            ])]);
            invocation.output.json(&doc)
        }
        Format::Pretty | Format::Table => {
            let row = vec![
                terminal_safe(file).into_owned(),
                terminal_safe(&document.tsg_id).into_owned(),
                document.profiles.len().to_string(),
                document.topics.len().to_string(),
            ];
            invocation.output.data_line(&table::table(
                &["Backup file", "Source TSG", "Profiles", "Topics"],
                &[row],
            ));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_names_follow_typescript() {
        let path = default_path("2026-10-19T00:25:46.303Z");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("airs-runtime-profiles-backup-2026-10-19T00-25-46-303Z-"),
            "{name}"
        );
        assert!(
            name.ends_with(".json")
                && name.len()
                    == "airs-runtime-profiles-backup-2026-10-19T00-25-46-303Z-".len() + 13
        );
        assert!(path.starts_with("."));
    }
}
