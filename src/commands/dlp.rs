//! `runtime dlp` planning and dispatch (DESIGN §16). Planning runs every argument check
//! of §16.3 before the tenant is read (D162); dispatch connects the DLP client from the
//! tenant's `dlpEndpoint` and runs the command.
//!
//! Every command of §16.1 is planned here (the reads, the writes, backup and restore).
//! `runtime dlp generate` is dropped (MILESTONES): clap reports it as an unrecognised
//! subcommand.

use super::{Invocation, Plan};
use crate::cli::{
    DlpCommand, DlpDictionariesCommand, DlpFilteringCommand, DlpGroup, DlpListFlags,
    DlpPatternsCommand, DlpProfilesCommand,
};
use crate::clients::{DlpClients, TOKEN_BUDGET, WALK_BUDGET};
use crate::dlp::body::{self, Input, Texts, Write};
use crate::dlp::{self, Kind, ListParams};
use crate::error::{CliError, InterruptContext};
use crate::output::{self, Format};
use std::ffi::OsString;

/// A create, replace or patch whose body is JSON (every write but the dictionary
/// uploads and the deletes).
#[derive(Clone, Debug, PartialEq)]
pub struct BodyWrite {
    pub kind: Kind,
    pub write: Write,
    /// The `<id>` of a replace or patch.
    pub id: Option<String>,
    /// The body, or where to read it (`--body-file`, `--body -`).
    pub input: Input,
    /// The parse texts of a file or stdin body.
    pub texts: Texts,
    /// `patterns replace` without `--type` / `--technique`: take them from the current
    /// record (D169).
    pub fill_type: bool,
    pub fill_technique: bool,
    /// `profiles create|replace --pattern-id`: the rules are built after the pattern
    /// reads.
    pub rules: Option<ProfileRules>,
    /// `--force` (replaces).
    pub force: bool,
    pub format: Option<Format>,
}

/// The `--pattern-id` rule of a flag-built profile body (§16.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRules {
    pub pattern_ids: Vec<String>,
    pub combinator: String,
    pub confidence: String,
}

/// A dictionary create or replace (the multipart upload, §16.8).
#[derive(Clone, Debug, PartialEq)]
pub struct Upload {
    /// The `<id>` of a replace.
    pub id: Option<String>,
    /// The metadata, or the `--metadata-file` to read.
    pub metadata: Input,
    /// The keyword file.
    pub file: OsString,
    pub include_keywords: bool,
    pub force: bool,
    pub format: Option<Format>,
}

/// A validated `runtime dlp` invocation. `format` is the explicit `--output`; every DLP
/// command that prints data honours the tenant's `defaultOutput` (§16.3).
#[derive(Clone, Debug, PartialEq)]
pub enum DlpPlan {
    /// `filtering-profiles|patterns|profiles|dictionaries list|ls` (§16.4).
    List {
        kind: Kind,
        params: ListParams,
        format: Option<Format>,
    },
    /// `filtering-profiles|patterns|profiles|dictionaries get <id>` (§16.4).
    Get {
        kind: Kind,
        id: String,
        /// `dictionaries get --keywords|--include-keywords`.
        keywords: bool,
        format: Option<Format>,
    },
    /// A JSON-body create, replace or patch (§16.5–§16.8).
    Body(Box<BodyWrite>),
    /// `dictionaries create|replace` (§16.8).
    Upload(Box<Upload>),
    /// `patterns|dictionaries delete|rm <id>` (§16.6, §16.8).
    Delete { kind: Kind, id: String, force: bool },
    /// `profiles delete|rm <id>`: the refusal, with no tenant and no request (§16.7).
    ProfileDeleteRefused { id: String },
    /// `runtime dlp backup` (§16.10).
    Backup(Box<BackupRun>),
    /// `runtime dlp restore <file>` (§16.11).
    Restore(Box<RestoreRun>),
}

/// A validated `runtime dlp backup`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRun {
    /// `--output-file` (else the default name in the current directory).
    pub output_file: Option<OsString>,
    pub resources: Vec<dlp::backup::Resource>,
    pub skip_unsupported: bool,
    pub max_pages: u64,
    pub format: Option<Format>,
}

/// A validated `runtime dlp restore <file>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreRun {
    pub file: OsString,
    pub dry_run: bool,
    pub expect_tsg: Option<String>,
    pub force: bool,
    pub allow_other_tenant: bool,
    pub max_pages: u64,
    pub options: dlp::plan::Options,
    pub format: Option<Format>,
}

/// `backup` interrupted before its file was linked.
pub const NO_BACKUP_WRITTEN: &str = "no backup file was written";

impl DlpPlan {
    /// What an interruption reports (§16.3 "Interruption"): the reads write no data; a
    /// write reports `nothing was changed` until it is sent.
    pub fn interrupt_context(&self) -> InterruptContext {
        match self {
            Self::List { .. } | Self::Get { .. } | Self::ProfileDeleteRefused { .. } => {
                InterruptContext::NoDataWritten
            }
            Self::Body(_) | Self::Upload(_) | Self::Delete { .. } | Self::Restore(_) => {
                InterruptContext::NothingChanged
            }
            Self::Backup(_) => InterruptContext::Context(NO_BACKUP_WRITTEN.to_owned()),
        }
    }

    /// The `--debug` policy (§2.9): every command that sends requests logs; the
    /// `profiles delete` refusal sends none and opens no log.
    pub fn debug_policy(&self) -> crate::debug::DebugPolicy {
        match self {
            Self::ProfileDeleteRefused { .. } => crate::debug::DebugPolicy::None,
            _ => crate::debug::DebugPolicy::Log,
        }
    }
}

/// The list flags of the `runtime dlp` list the command line runs, if any.
fn list_flags(group: &DlpGroup) -> Option<&DlpListFlags> {
    match group.command.as_ref()? {
        DlpCommand::FilteringProfiles(group) => match group.command.as_ref()? {
            DlpFilteringCommand::List(args) => Some(&args.paging),
            _ => None,
        },
        DlpCommand::Patterns(group) => match group.command.as_ref()? {
            DlpPatternsCommand::List(args) => Some(&args.paging),
            _ => None,
        },
        DlpCommand::Profiles(group) => match group.command.as_ref()? {
            DlpProfilesCommand::List(args) => Some(&args.paging),
            _ => None,
        },
        DlpCommand::Dictionaries(group) => match group.command.as_ref()? {
            DlpDictionariesCommand::List(args) => Some(&args.paging),
            _ => None,
        },
        DlpCommand::Backup(_) | DlpCommand::Restore(_) => None,
    }
}

/// The deprecation warnings of the hidden `--size` and `--page` (§16.3 "Validation
/// order"), printed before any other check and never quiet-suppressed.
pub fn deprecation_warnings(group: &DlpGroup) -> Vec<&'static str> {
    list_flags(group)
        .map(dlp::deprecation_warnings)
        .unwrap_or_default()
}

fn get(kind: Kind, id: &str, keywords: bool, format: Option<Format>) -> Result<DlpPlan, CliError> {
    dlp::check_id(kind, id)?;
    Ok(DlpPlan::Get {
        kind,
        id: id.to_owned(),
        keywords,
        format,
    })
}

// ---------------------------------------------------------------------------
// Write planning (§16.3, §16.5–§16.8)
// ---------------------------------------------------------------------------

/// Which streams are terminals (stdin alone decides `--body -`).
fn terminals() -> crate::input::Terminals {
    crate::input::Terminals::detect()
}

/// The D81 gate of a confirming command (exit 2 before the tenant).
fn gate(force: bool, action: &str) -> Result<(), CliError> {
    super::write_common::gate_on_terminals(force, action)
}

/// The checks of a body that is known during planning (a flag-built body or
/// `--body <json>`) or read before the tenant (a file or stdin): `type: predefined`
/// (D166), the profile name and type (TS `validateBodyType`), then the SDK request schema
/// (exit 2). A pattern replace that fills its type and technique, and a profile body whose
/// rules are built after the pattern reads, are checked again after their reads.
pub fn check_body(plan: &BodyWrite, body: &serde_json::Value) -> Result<(), CliError> {
    body::refuse_predefined(plan.kind, body)?;
    if plan.kind == Kind::Profile {
        body::check_profile_body(body)?;
    }
    if plan.rules.is_some() {
        return Ok(());
    }
    body::check(plan.kind, plan.write, plan.id.as_deref(), body, true)
}

/// Check a planned body now when it is already known.
fn checked(plan: BodyWrite) -> Result<DlpPlan, CliError> {
    if let Input::Ready(body) = &plan.input {
        check_body(&plan, body)?;
    }
    Ok(DlpPlan::Body(Box::new(plan)))
}

fn plan_filtering_replace(
    args: &crate::cli::DlpFilteringReplaceArgs,
    format: Option<Format>,
) -> Result<DlpPlan, CliError> {
    dlp::check_id(Kind::FilteringProfile, &args.id)?;
    let flags = body::FilteringFlags {
        file_based: args.file_based,
        non_file_based: args.non_file_based,
        description: args.description.clone(),
        direction: args.direction.clone(),
        log_severity: args.log_severity.clone(),
        scan_type: args.scan_type.clone(),
        data_profile_id: args.data_profile_id.clone(),
        euc_template_id: args.euc_template_id.clone(),
        end_user_coaching: args.end_user_coaching,
        granular: args.granular,
        file_type: args.file_type.clone(),
    };
    let input = match body::hatch(
        args.body.body.as_deref(),
        args.body_file.as_deref(),
        flags.first_given(),
        Texts::Body,
        terminals().stdin,
    )? {
        Some(input) => input,
        None => Input::Ready(body::filtering_body(&flags)?),
    };
    gate(
        args.force,
        &format!("replace {} {}", Kind::FilteringProfile.resource(), args.id),
    )?;
    checked(BodyWrite {
        kind: Kind::FilteringProfile,
        write: Write::Replace,
        id: Some(args.id.clone()),
        input,
        texts: Texts::Body,
        fill_type: false,
        fill_technique: false,
        rules: None,
        force: args.force,
        format,
    })
}

fn plan_pattern(
    id: Option<&str>,
    args: &crate::cli::DlpPatternFlags,
    kind_flag: Option<String>,
    technique: Option<String>,
    force: bool,
    format: Option<Format>,
) -> Result<DlpPlan, CliError> {
    if let Some(id) = id {
        dlp::check_id(Kind::Pattern, id)?;
    }
    let flags = body::PatternFlags {
        name: args.name.clone(),
        r#type: kind_flag,
        description: args.description.clone(),
        technique,
        confidence_levels: args.confidence_levels.clone(),
        regex: args.regex.clone(),
        weighted_regex: args.weighted_regex.clone(),
        delimiter: args.delimiter.clone(),
        proximity_distance: args.proximity_distance.clone(),
        proximity_keyword: args.proximity_keyword.clone(),
        tag: args.tag.clone(),
    };
    let hatch = body::hatch(
        args.body.body.as_deref(),
        args.body_file.as_deref(),
        flags.first_given(),
        Texts::Body,
        terminals().stdin,
    )?;
    let replace = id.is_some();
    let (input, fill_type, fill_technique) = match hatch {
        Some(input) => (input, false, false),
        None => (
            Input::Ready(body::pattern_body(&flags)?),
            replace && flags.r#type.is_none(),
            replace && flags.technique.is_none(),
        ),
    };
    if let Some(id) = id {
        gate(force, &format!("replace {} {id}", Kind::Pattern.resource()))?;
    }
    checked(BodyWrite {
        kind: Kind::Pattern,
        write: if replace {
            Write::Replace
        } else {
            Write::Create
        },
        id: id.map(str::to_owned),
        input,
        texts: Texts::Body,
        fill_type,
        fill_technique,
        rules: None,
        force,
        format,
    })
}

fn plan_profile(
    id: Option<&str>,
    args: &crate::cli::DlpProfileFlags,
    force: bool,
    format: Option<Format>,
) -> Result<DlpPlan, CliError> {
    if let Some(id) = id {
        dlp::check_id(Kind::Profile, id)?;
    }
    let flags = body::ProfileFlags {
        name: args.name.clone(),
        profile_type: args.profile_type.clone(),
        description: args.description.clone(),
        granular: args.granular,
        pattern_id: args.pattern_id.clone(),
        combinator: args.combinator.clone(),
        confidence: args.confidence.clone(),
    };
    // TS checks `--profile-type` first, even with a body.
    body::check_profile_type(
        flags
            .profile_type
            .as_ref()
            .map(|kind| serde_json::Value::String(kind.clone()))
            .as_ref(),
    )?;
    let hatch = body::hatch(
        args.body.body.as_deref(),
        args.body_file.as_deref(),
        flags.first_given(),
        Texts::Profile,
        terminals().stdin,
    )?;
    let (input, rules) = match hatch {
        Some(input) => (input, None),
        None => {
            let (combinator, confidence) = body::check_profile_flags(&flags)?;
            let rules = (!flags.pattern_id.is_empty()).then(|| ProfileRules {
                pattern_ids: flags.pattern_id.clone(),
                combinator,
                confidence,
            });
            (Input::Ready(body::profile_base(&flags)), rules)
        }
    };
    if let Some(id) = id {
        gate(force, &format!("replace {} {id}", Kind::Profile.resource()))?;
    }
    checked(BodyWrite {
        kind: Kind::Profile,
        write: if id.is_some() {
            Write::Replace
        } else {
            Write::Create
        },
        id: id.map(str::to_owned),
        input,
        texts: Texts::Profile,
        fill_type: false,
        fill_technique: false,
        rules,
        force,
        format,
    })
}

fn plan_patch(
    kind: Kind,
    id: &str,
    body_file: Option<&std::ffi::OsStr>,
    set: &[String],
    clear: &[String],
    format: Option<Format>,
) -> Result<DlpPlan, CliError> {
    dlp::check_id(kind, id)?;
    if body_file.is_some() && (!set.is_empty() || !clear.is_empty()) {
        return Err(CliError::usage(
            "--body-file is mutually exclusive with --set/--clear",
        ));
    }
    let texts = match kind {
        Kind::Profile => Texts::ProfilePatch,
        Kind::Dictionary => Texts::Dictionary,
        Kind::Pattern | Kind::FilteringProfile => Texts::Body,
    };
    let input = match body_file {
        Some(path) if path.is_empty() => return Err(CliError::usage("--body-file needs a path")),
        Some(path) => Input::File(path.to_owned()),
        None => {
            let patch = dlp::patch::merge_patch(set, clear).map_err(|error| match kind {
                Kind::Profile => CliError::usage(body::PROFILE_PATCH),
                Kind::Dictionary => CliError::usage(body::DICTIONARY_PATCH),
                Kind::Pattern | Kind::FilteringProfile => CliError::usage(error.message()),
            })?;
            Input::Ready(serde_json::Value::Object(patch))
        }
    };
    checked(BodyWrite {
        kind,
        write: Write::Patch,
        id: Some(id.to_owned()),
        input,
        texts,
        fill_type: false,
        fill_technique: false,
        rules: None,
        force: false,
        format,
    })
}

fn plan_delete(kind: Kind, id: &str, force: bool) -> Result<DlpPlan, CliError> {
    dlp::check_id(kind, id)?;
    gate(force, &format!("delete {} {id}", kind.resource()))?;
    Ok(DlpPlan::Delete {
        kind,
        id: id.to_owned(),
        force,
    })
}

/// Check the metadata of a dictionary upload (`type: predefined`, the SDK schema and the
/// multipart file name; exit 2).
pub fn check_metadata(metadata: &serde_json::Value) -> Result<(), CliError> {
    body::refuse_predefined(Kind::Dictionary, metadata)?;
    body::check(Kind::Dictionary, Write::Create, None, metadata, true)
}

fn plan_upload(
    id: Option<&str>,
    flags: &crate::cli::DlpDictionaryFlags,
    file: Option<&std::ffi::OsStr>,
    metadata_file: Option<&std::ffi::OsStr>,
    include_keywords: bool,
    force: bool,
    format: Option<Format>,
) -> Result<DlpPlan, CliError> {
    if let Some(id) = id {
        dlp::check_id(Kind::Dictionary, id)?;
    }
    let flags = body::DictionaryFlags {
        name: flags.name.clone(),
        category: flags.category.clone(),
        description: flags.description.clone(),
        region: flags.region.clone(),
        classification: flags.classification.clone(),
    };
    let metadata = match metadata_file {
        Some(path) => {
            if let Some(flag) = flags.first_given() {
                return Err(CliError::usage(format!(
                    "--metadata-file cannot be combined with --{flag}"
                )));
            }
            if path.is_empty() {
                return Err(CliError::usage("--metadata-file needs a path"));
            }
            Input::File(path.to_owned())
        }
        None => Input::Ready(body::dictionary_metadata(&flags, file)?),
    };
    let Some(file) = file.filter(|file| !file.is_empty()) else {
        return Err(CliError::usage("--file is required (multipart upload)"));
    };
    if let Input::Ready(metadata) = &metadata {
        check_metadata(metadata)?;
    }
    if let Some(id) = id {
        gate(
            force,
            &format!("replace {} {id}", Kind::Dictionary.resource()),
        )?;
    }
    Ok(DlpPlan::Upload(Box::new(Upload {
        id: id.map(str::to_owned),
        metadata,
        file: file.to_owned(),
        include_keywords,
        force,
        format,
    })))
}

/// `runtime dlp backup` (§16.10 "Argument checks", in order).
fn plan_backup(
    args: &crate::cli::DlpBackupArgs,
    format: Option<Format>,
) -> Result<DlpPlan, CliError> {
    if args
        .file_format
        .as_deref()
        .is_some_and(|format| format != "json")
    {
        return Err(CliError::usage(
            "--file-format must be json (yaml was dropped)",
        ));
    }
    let resources = match &args.resources {
        Some(list) => dlp::backup::parse_resources(list)?,
        None => dlp::backup::Resource::ALL.to_vec(),
    };
    let max_pages = args
        .max_pages
        .as_deref()
        .map(dlp::backup::parse_max_pages)
        .transpose()?
        .unwrap_or(dlp::backup::DEFAULT_MAX_PAGES);
    if let Some(path) = &args.output_file {
        if path == "-" {
            return Err(CliError::usage(
                "Backups contain dictionary keywords and require a private file destination, not stdout",
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
    Ok(DlpPlan::Backup(Box::new(BackupRun {
        output_file: args.output_file.clone(),
        resources,
        skip_unsupported: args.skip_unsupported,
        max_pages,
        format,
    })))
}

/// `--pattern-map` (TS `patternMap`): split at the first `=`, neither side empty;
/// sources unique.
fn pattern_map(values: &[String]) -> Result<Vec<(String, String)>, CliError> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for value in values {
        match value.find('=') {
            Some(at) if at > 0 && at + 1 < value.len() => {
                entries.push((value[..at].to_owned(), value[at + 1..].to_owned()));
            }
            _ => {
                return Err(CliError::usage(
                    "--pattern-map requires source-name=destination-name",
                ));
            }
        }
    }
    let mut sources: Vec<&str> = entries.iter().map(|(source, _)| source.as_str()).collect();
    sources.sort_unstable();
    sources.dedup();
    if sources.len() != entries.len() {
        return Err(CliError::usage("Duplicate source names in --pattern-map"));
    }
    Ok(entries)
}

/// `runtime dlp restore <file>` (§16.11 "Argument checks", in order).
fn plan_restore(
    args: &crate::cli::DlpRestoreArgs,
    format: Option<Format>,
) -> Result<DlpPlan, CliError> {
    let conflict = match args.on_conflict.as_deref() {
        None => dlp::plan::Conflict::Error,
        Some(text) => dlp::plan::Conflict::parse(text).ok_or_else(|| {
            CliError::usage("--on-conflict must be error, verify, skip or reconcile")
        })?,
    };
    if args.force && args.expect_tsg.is_none() {
        return Err(CliError::usage(
            "--force requires --expect-tsg <destination-tsg>",
        ));
    }
    if args.dry_run && args.force {
        return Err(CliError::usage("--dry-run cannot be combined with --force"));
    }
    let pattern_map = pattern_map(&args.pattern_map)?;
    let prefix = args.name_prefix.clone().unwrap_or_default();
    if prefix.encode_utf16().count() > 64
        || prefix.chars().any(|c| (c as u32) < 32 || c as u32 == 127)
    {
        return Err(CliError::usage("Invalid --name-prefix"));
    }
    let max_pages = args
        .max_pages
        .as_deref()
        .map(dlp::backup::parse_max_pages)
        .transpose()?
        .unwrap_or(dlp::backup::DEFAULT_MAX_PAGES);
    if let Some(tsg) = &args.expect_tsg
        && (tsg.is_empty() || tsg.len() > 32 || !tsg.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(CliError::usage(
            "--expect-tsg must be a TSG ID (1-32 digits)",
        ));
    }
    if !args.dry_run {
        gate(args.force, "restore DLP resources")?;
    }
    Ok(DlpPlan::Restore(Box::new(RestoreRun {
        file: args.file.clone(),
        dry_run: args.dry_run,
        expect_tsg: args.expect_tsg.clone(),
        force: args.force,
        allow_other_tenant: args.allow_other_tenant,
        max_pages,
        options: dlp::plan::Options {
            prefix,
            conflict,
            pattern_map,
            skip_unresolved: args.skip_unresolved,
        },
        format,
    })))
}

/// Plan a `runtime dlp` command line; `--output` was validated already (§16.3 order).
pub fn plan(group: &DlpGroup, explicit: Option<&str>) -> Result<Plan, CliError> {
    let format = output::validate_explicit(explicit)?;
    let list = |kind: Kind, params: ListParams| DlpPlan::List {
        kind,
        params,
        format,
    };
    let Some(command) = &group.command else {
        return Ok(Plan::GroupHelp(&["runtime", "dlp"]));
    };
    let plan = match command {
        DlpCommand::Backup(args) => plan_backup(args, format)?,
        DlpCommand::Restore(args) => plan_restore(args, format)?,
        DlpCommand::FilteringProfiles(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["runtime", "dlp", "filtering-profiles"])),
            Some(DlpFilteringCommand::List(args)) => list(
                Kind::FilteringProfile,
                dlp::list_params(&args.paging, &args.sort, false, false)?,
            ),
            Some(DlpFilteringCommand::Get(args)) => {
                get(Kind::FilteringProfile, &args.id, false, format)?
            }
            Some(DlpFilteringCommand::Replace(args)) => plan_filtering_replace(args, format)?,
        },
        DlpCommand::Patterns(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["runtime", "dlp", "patterns"])),
            Some(DlpPatternsCommand::List(args)) => list(
                Kind::Pattern,
                dlp::list_params(&args.paging, &args.sort, args.include_predefined, false)?,
            ),
            Some(DlpPatternsCommand::Get(args)) => get(Kind::Pattern, &args.id, false, format)?,
            Some(DlpPatternsCommand::Create(args)) => plan_pattern(
                None,
                &args.flags,
                args.r#type.clone(),
                args.technique.clone(),
                false,
                format,
            )?,
            Some(DlpPatternsCommand::Replace(args)) => plan_pattern(
                Some(&args.id),
                &args.flags,
                args.r#type.clone(),
                args.technique.clone(),
                args.force,
                format,
            )?,
            Some(DlpPatternsCommand::Patch(args)) => plan_patch(
                Kind::Pattern,
                &args.id,
                args.body_file.as_deref(),
                &args.set,
                &args.clear,
                format,
            )?,
            Some(DlpPatternsCommand::Delete(args)) => {
                plan_delete(Kind::Pattern, &args.id, args.force)?
            }
        },
        DlpCommand::Profiles(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["runtime", "dlp", "profiles"])),
            Some(DlpProfilesCommand::List(args)) => list(
                Kind::Profile,
                dlp::list_params(&args.paging, &args.sort, args.include_predefined, false)?,
            ),
            Some(DlpProfilesCommand::Get(args)) => get(Kind::Profile, &args.id, false, format)?,
            Some(DlpProfilesCommand::Create(args)) => {
                plan_profile(None, &args.flags, false, format)?
            }
            Some(DlpProfilesCommand::Replace(args)) => {
                plan_profile(Some(&args.id), &args.flags, args.force, format)?
            }
            Some(DlpProfilesCommand::Patch(args)) => plan_patch(
                Kind::Profile,
                &args.id,
                args.body_file.as_deref(),
                &args.set,
                &args.clear,
                format,
            )?,
            Some(DlpProfilesCommand::Delete(args)) => DlpPlan::ProfileDeleteRefused {
                id: args.id.clone(),
            },
        },
        DlpCommand::Dictionaries(group) => match &group.command {
            None => return Ok(Plan::GroupHelp(&["runtime", "dlp", "dictionaries"])),
            Some(DlpDictionariesCommand::List(args)) => list(
                Kind::Dictionary,
                dlp::list_params(
                    &args.paging,
                    &args.sort,
                    args.include_predefined,
                    args.keywords || args.include_keywords,
                )?,
            ),
            Some(DlpDictionariesCommand::Get(args)) => get(
                Kind::Dictionary,
                &args.id,
                args.keywords || args.include_keywords,
                format,
            )?,
            Some(DlpDictionariesCommand::Create(args)) => plan_upload(
                None,
                &args.flags,
                args.file.as_deref(),
                args.metadata_file.as_deref(),
                args.include_keywords,
                false,
                format,
            )?,
            Some(DlpDictionariesCommand::Replace(args)) => plan_upload(
                Some(&args.id),
                &args.flags,
                args.file.as_deref(),
                args.metadata_file.as_deref(),
                args.include_keywords,
                args.force,
                format,
            )?,
            Some(DlpDictionariesCommand::Patch(args)) => plan_patch(
                Kind::Dictionary,
                &args.id,
                args.body_file.as_deref(),
                &args.set,
                &args.clear,
                format,
            )?,
            Some(DlpDictionariesCommand::Delete(args)) => {
                plan_delete(Kind::Dictionary, &args.id, args.force)?
            }
        },
    };
    Ok(Plan::Dlp(Box::new(plan)))
}

/// Run a DLP plan.
pub async fn dispatch(invocation: &mut Invocation, plan: DlpPlan) -> Result<(), CliError> {
    use super::dlp_reads as reads;
    match plan {
        DlpPlan::List {
            kind,
            params,
            format,
        } => reads::list(invocation, kind, &params, format).await,
        DlpPlan::Get {
            kind,
            id,
            keywords,
            format,
        } => reads::get(invocation, kind, &id, keywords, format).await,
        DlpPlan::Body(plan) => super::dlp_write::body_write(invocation, &plan).await,
        DlpPlan::Upload(plan) => super::dlp_dictionaries::upload(invocation, &plan).await,
        DlpPlan::Delete { kind, id, force } => {
            super::dlp_write::delete(invocation, kind, &id, force).await
        }
        DlpPlan::ProfileDeleteRefused { id } => super::dlp_profiles::refuse_delete(invocation, &id),
        DlpPlan::Backup(run) => super::dlp_backup::backup(invocation, &run).await,
        DlpPlan::Restore(run) => super::dlp_backup::restore(invocation, &run).await,
    }
}

/// A connected DLP client and the tenant's `defaultOutput`.
pub struct Connected {
    pub client: scm::dlp::DlpClient,
    pub default_output: Option<String>,
}

impl Connected {
    /// The format of a command that honours `defaultOutput`.
    pub fn format(&self, explicit: Option<Format>) -> Format {
        output::resolve_tenant_default(explicit, self.default_output.as_deref())
    }
}

impl Invocation {
    /// Load the tenant, check the management credentials (§3.5), build the DLP client
    /// from the tenant's `dlpEndpoint` (§16.3) and fetch the OAuth token under `options`
    /// (a walk's shared deadline; `None`: the SDK's token budget).
    pub async fn connect_dlp(
        &mut self,
        options: Option<&scm::RequestOptions>,
    ) -> Result<Connected, CliError> {
        let context = self.load_tenant()?;
        let default_output = context.config.default_output().map(str::to_owned);
        crate::tenant::config::require_management(&context.config, Some(context.name()))?;
        let clients = DlpClients::build(
            &context.config,
            &self.session,
            &self.secrets,
            self.debug.as_ref(),
        )?;
        let budget = if options.is_some() {
            WALK_BUDGET
        } else {
            TOKEN_BUDGET
        };
        clients.authenticate(options, budget).await?;
        Ok(Connected {
            client: clients.dlp,
            default_output,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::FromArgMatches;

    fn plan_of(args: &[&str]) -> Result<Plan, CliError> {
        let mut full = vec!["airs", "runtime", "dlp"];
        full.extend_from_slice(args);
        let matches = crate::cli::command().try_get_matches_from(&full).unwrap();
        crate::commands::plan(&Cli::from_arg_matches(&matches).unwrap())
    }

    fn dlp_plan(args: &[&str]) -> DlpPlan {
        match plan_of(args) {
            Ok(Plan::Dlp(plan)) => *plan,
            Ok(_) => panic!("not a DLP plan: {args:?}"),
            Err(error) => panic!("{args:?}: {error:?}"),
        }
    }

    fn usage(args: &[&str]) -> String {
        match plan_of(args) {
            Err(CliError::Usage(message)) => message,
            Err(other) => panic!("expected a usage error, got {other:?}"),
            Ok(_) => panic!("expected a usage error: {args:?}"),
        }
    }

    #[test]
    fn output_is_checked_before_the_tenant_flag_and_the_arguments() {
        let matches = crate::cli::command()
            .try_get_matches_from([
                "airs", "--tenant", "-bad", "runtime", "dlp", "patterns", "get", "..", "--output",
                "yaml",
            ])
            .unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();
        assert!(matches!(
            crate::commands::plan(&cli),
            Err(CliError::Usage(message)) if message == "Invalid output format 'yaml'. Expected: pretty, table, json"
        ));
        let matches = crate::cli::command()
            .try_get_matches_from([
                "airs", "--tenant", "-bad", "runtime", "dlp", "patterns", "get", "..",
            ])
            .unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();
        assert!(matches!(
            crate::commands::plan(&cli),
            Err(CliError::Usage(message)) if message.starts_with("Tenant name must be")
        ));
        assert_eq!(
            usage(&["patterns", "get", ".."]),
            "Invalid data pattern id: .."
        );
        assert_eq!(
            usage(&["filtering-profiles", "get", ""]),
            "Invalid filtering profile id: "
        );
        assert_eq!(
            usage(&["profiles", "get", "a/../b"]),
            "Invalid data profile id: a/../b"
        );
        assert_eq!(
            usage(&["dictionaries", "get", "%2e%2e"]),
            "Invalid dictionary id: %2e%2e"
        );
        assert_eq!(
            usage(&["patterns", "ls", "--limit", "0"]),
            "--limit must be a positive integer"
        );
    }

    #[test]
    fn plans_carry_their_flags_formats_and_contexts() {
        let plan = dlp_plan(&[
            "dictionaries",
            "ls",
            "--include-keywords",
            "--output",
            "json",
        ]);
        assert_eq!(plan.interrupt_context(), InterruptContext::NoDataWritten);
        let DlpPlan::List {
            kind,
            params,
            format,
        } = plan
        else {
            panic!("a list");
        };
        assert_eq!(kind, Kind::Dictionary);
        assert!(params.keywords && !params.include_predefined);
        assert_eq!(format, Some(Format::Json));
        assert!(matches!(
            dlp_plan(&["dictionaries", "get", "d1", "--keywords"]),
            DlpPlan::Get {
                kind: Kind::Dictionary,
                keywords: true,
                format: None,
                ..
            }
        ));
        assert!(matches!(
            dlp_plan(&["patterns", "list", "--include-predefined", "--sort", "id,desc"]),
            DlpPlan::List { kind: Kind::Pattern, params: ListParams { include_predefined: true, ref sort, .. }, .. } if sort == &["id,desc"]
        ));
        assert!(matches!(
            dlp_plan(&["filtering-profiles", "get", "fp 1"]),
            DlpPlan::Get {
                kind: Kind::FilteringProfile,
                ..
            }
        ));
        let plan = plan_of(&["profiles", "ls"]).ok().unwrap();
        assert_eq!(plan.debug_policy(), crate::debug::DebugPolicy::Log);
    }

    #[test]
    fn groups_without_a_subcommand_render_help() {
        for (args, path) in [
            (&[][..], &["runtime", "dlp"][..]),
            (&["patterns"], &["runtime", "dlp", "patterns"]),
            (&["profiles"], &["runtime", "dlp", "profiles"]),
            (&["dictionaries"], &["runtime", "dlp", "dictionaries"]),
            (
                &["filtering-profiles"],
                &["runtime", "dlp", "filtering-profiles"],
            ),
        ] {
            match plan_of(args) {
                Ok(Plan::GroupHelp(found)) => assert_eq!(found, path),
                _ => panic!("expected group help for {args:?}"),
            }
        }
    }

    #[test]
    fn dropped_and_unregistered_commands_are_parse_errors() {
        for args in [
            &["airs", "runtime", "dlp", "generate"][..],
            &[
                "airs",
                "runtime",
                "dlp",
                "filtering-profiles",
                "list",
                "--include-predefined",
            ],
            &[
                "airs",
                "runtime",
                "dlp",
                "patterns",
                "get",
                "x",
                "--keywords",
            ],
        ] {
            let error = crate::cli::command()
                .try_get_matches_from(args)
                .err()
                .unwrap();
            assert_eq!(error.exit_code(), 2, "{args:?}");
        }
    }

    #[test]
    fn deprecated_aliases_warn() {
        let matches = crate::cli::command()
            .try_get_matches_from([
                "airs", "runtime", "dlp", "patterns", "list", "--size", "5", "--page", "1",
            ])
            .unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let Some(crate::cli::TopCommand::Runtime(crate::cli::RuntimeGroup {
            command: Some(crate::cli::RuntimeCommand::Dlp(group)),
        })) = &cli.command
        else {
            panic!("a DLP command");
        };
        assert_eq!(
            deprecation_warnings(group),
            [dlp::SIZE_DEPRECATED, dlp::PAGE_DEPRECATED]
        );
    }

    /// The write plans: their bodies, contexts and debug policies (§16.3).
    #[test]
    fn write_plans_carry_their_bodies_contexts_and_policies() {
        let plan = dlp_plan(&["patterns", "create", "--name", "P"]);
        assert_eq!(plan.interrupt_context(), InterruptContext::NothingChanged);
        assert_eq!(plan.debug_policy(), crate::debug::DebugPolicy::Log);
        let DlpPlan::Body(body) = plan else {
            panic!("a body write");
        };
        assert_eq!(body.write, Write::Create);
        assert!(!body.fill_type && !body.fill_technique);
        assert!(matches!(&body.input, Input::Ready(value) if value["name"] == "P"));
        let DlpPlan::Body(body) = dlp_plan(&[
            "patterns", "replace", "p", "--name", "P", "--type", "custom", "--force",
        ]) else {
            panic!("a body write");
        };
        assert!(!body.fill_type && body.fill_technique, "D169");
        let DlpPlan::Body(body) = dlp_plan(&[
            "profiles",
            "create",
            "--name",
            "P",
            "--pattern-id",
            "a",
            "--combinator",
            "AND",
        ]) else {
            panic!("a body write");
        };
        assert_eq!(
            body.rules,
            Some(ProfileRules {
                pattern_ids: vec!["a".to_owned()],
                combinator: "and".to_owned(),
                confidence: "high".to_owned()
            })
        );
        let refused = plan_of(&["profiles", "rm", "x"]).ok().unwrap();
        assert_eq!(refused.debug_policy(), crate::debug::DebugPolicy::None);
        assert!(matches!(
            dlp_plan(&["dictionaries", "rm", "d", "--force"]),
            DlpPlan::Delete {
                kind: Kind::Dictionary,
                force: true,
                ..
            }
        ));
        assert!(matches!(
            dlp_plan(&["dictionaries", "create", "--metadata-file", "m.json", "--file", "k.txt"]),
            DlpPlan::Upload(upload) if matches!(upload.metadata, Input::File(_))
        ));
        // The gate is the last argument check: a bad id is reported first.
        assert_eq!(
            usage(&["patterns", "rm", ".."]),
            "Invalid data pattern id: .."
        );
    }
}
