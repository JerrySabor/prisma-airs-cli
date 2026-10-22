//! `runtime profiles create`, `update <nameOrId>` and `delete|rm <nameOrId>` (DESIGN
//! §13.12–§13.14, §13.17).
//!
//! Argument checks run in planning (exit 2); `--config` files and the flag-built body are
//! read and validated before the tenant (a body that fails the request schema is a usage
//! error, as in TypeScript 7.3.0); `update` reads the profile once, last, and writes the
//! body computed from that read (§13.4). A directional layout refusal after the read is
//! a usage error too, and nothing is written.

use super::{Invocation, confirm, nothing_changed, profile_walk_options};
use crate::cli::{ProfileCreateArgs, ProfileDeleteArgs, ProfileUpdateArgs};
use crate::clients::{SINGLE_REQUEST_BUDGET, WALK_BUDGET};
use crate::error::{CliError, Failure};
use crate::output::{Format, terminal_safe};
use crate::policy::{self, Flags, Patch};
use crate::profile_policy::Selector;
use crate::views;
use crate::writes::{self, Change};
use scm::ErrorKind;
use scm::airs::management::ProfilesClient;
use scm::airs::management::models::{CreateSecurityProfileRequest, SecurityProfile};
use serde_json::{Value, json};
use std::ffi::OsString;

/// Where a `profiles create` body comes from.
#[derive(Clone, Debug, PartialEq)]
pub enum CreateBody {
    /// Built from the flags (TS 7.3.0 `buildProfileRequest`), already validated.
    Flags(Value),
    /// The `--config` file's object, as is (its `profile_name` names the profile).
    Config(OsString),
}

/// A validated `profiles create`.
#[derive(Clone, Debug, PartialEq)]
pub struct CreatePlan {
    pub body: CreateBody,
    /// The explicit `--output`; `None` uses the tenant's `defaultOutput` (§13.17).
    pub format: Option<Format>,
}

/// A validated `profiles update`.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdatePlan {
    pub name_or_id: String,
    pub rename: Option<String>,
    /// `--active` / `--no-active`; `None` keeps the read value (D100).
    pub active: Option<bool>,
    /// The protection and shared-setting flags; `None` without any.
    pub patch: Option<Patch>,
    pub selector: Selector,
    pub config: Option<OsString>,
    pub format: Option<Format>,
}

/// A validated `profiles delete`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletePlan {
    pub name_or_id: String,
    /// `Some(email)` with `--force` (the force endpoint).
    pub force: Option<String>,
}

/// TS 7.3.0 `assertProfileConfigFlags`.
const CONFIG_CONFLICT: &str = "--config cannot be combined with profile write flags or selectors";

const CREATE_PATH: &str = "/v1/mgmt/profile";

/// D336: a directional flag create whose flags fill no direction (TS 7.3.0 refuses only
/// the create with no flag, pointing at `--config` for an empty policy, which the service
/// refuses too).
const DIRECTIONAL_WITHOUT_PROTECTION: &str = "Directional flag creation requires at least one protection flag, not only shared settings: the service refuses a directional policy with no protection in any direction";

pub fn plan_create(
    args: &ProfileCreateArgs,
    format: Option<Format>,
) -> Result<CreatePlan, CliError> {
    if args.config.is_some()
        && (args.name.is_some()
            || args.no_active
            || args.direction.is_some()
            || Flags::raw_any(&args.policy))
    {
        return Err(CliError::usage(CONFIG_CONFLICT));
    }
    if let Some(path) = &args.config {
        return Ok(CreatePlan {
            body: CreateBody::Config(path.clone()),
            format,
        });
    }
    let Some(name) = &args.name else {
        return Err(CliError::usage(
            "--name is required unless --config is supplied",
        ));
    };
    let selector = Selector::parse(args.direction.as_deref(), None)?;
    let flags = Flags::read(&args.policy);
    if selector.direction.is_some() {
        // D336: the service refuses a directional policy whose four directions are all
        // empty, so a create whose flags fill no direction is refused before OAuth.
        if !flags.fills_a_direction() {
            return Err(CliError::usage(DIRECTIONAL_WITHOUT_PROTECTION));
        }
    } else if !flags.any_protection() {
        return Err(CliError::usage(
            "Specify at least one policy flag (for example --prompt-injection block) or --config <path>",
        ));
    }
    flags.check()?;
    if flags.dlp_without_action() {
        return Err(CliError::usage(
            "--dlp-profiles and --[no-]mask-data-inline require --dlp-action when creating a profile",
        ));
    }
    let value = policy::create_request(name, !args.no_active, &flags, selector.direction);
    profile_body(value.clone(), "POST", CREATE_PATH)?;
    Ok(CreatePlan {
        body: CreateBody::Flags(value),
        format,
    })
}

pub fn plan_update(
    args: &ProfileUpdateArgs,
    format: Option<Format>,
) -> Result<UpdatePlan, CliError> {
    if args.config.is_some()
        && (args.name.is_some()
            || args.active
            || args.no_active
            || args.direction.is_some()
            || args.ai_profile_index.is_some()
            || Flags::raw_any(&args.policy))
    {
        return Err(CliError::usage(CONFIG_CONFLICT));
    }
    let selector = Selector::parse(args.direction.as_deref(), args.ai_profile_index.as_deref())?;
    let flags = Flags::read(&args.policy);
    if args.config.is_none()
        && args.name.is_none()
        && !args.active
        && !args.no_active
        && !flags.any_protection()
    {
        return Err(CliError::usage(
            "Nothing to update: pass --name, --active, --no-active, a policy flag or --config",
        ));
    }
    flags.check()?;
    let active = match (args.active, args.no_active) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    };
    Ok(UpdatePlan {
        name_or_id: args.name_or_id.clone(),
        rename: args.name.clone(),
        active,
        patch: Patch::new(&flags, selector.direction),
        selector,
        config: args.config.clone(),
        format,
    })
}

pub fn plan_delete(args: &ProfileDeleteArgs, interactive: bool) -> Result<DeletePlan, CliError> {
    let force = if args.force {
        Some(super::topic_write::force_audit(args.updated_by.as_deref())?)
    } else {
        None
    };
    if force.is_none() && !interactive {
        return Err(CliError::usage(format!(
            "refusing to delete profile \"{}\" without --force in non-interactive mode",
            args.name_or_id
        )));
    }
    Ok(DeletePlan {
        name_or_id: args.name_or_id.clone(),
        force,
    })
}

/// The body for `<METHOD> <path>`, validated with the SDK's TypeScript 0.35.0 request
/// schema (§13.17). A mismatch is the D116 text as a usage error (exit 2), as in
/// TypeScript 7.3.0.
fn profile_body(
    value: Value,
    method: &str,
    path: &str,
) -> Result<CreateSecurityProfileRequest, CliError> {
    policy::request_body(value)
        .ok_or_else(|| CliError::usage(writes::invalid_body(method, path).message()))
}

/// The file's `profile_name`, when it is a string.
fn file_profile_name(config: &serde_json::Map<String, Value>) -> Option<&str> {
    config.get("profile_name").and_then(Value::as_str)
}

pub async fn create(invocation: &mut Invocation, plan: &CreatePlan) -> Result<(), CliError> {
    let value = match &plan.body {
        CreateBody::Flags(value) => value.clone(),
        CreateBody::Config(path) => Value::Object(crate::files::read_config(path)?),
    };
    let name = value
        .get("profile_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let body = profile_body(value, "POST", CREATE_PATH)?;
    let (management, format) = invocation
        .connect_management(plan.format, None)
        .await
        .map_err(nothing_changed)?;
    let profiles = management.profiles();
    // Options per attempt: the SDK's 60 s budget that `None` gives, without the response
    // defaults (§15.25); the attempt rules stay D95's.
    let result = writes::attempt(async || {
        let options = crate::runtime::request_options(SINGLE_REQUEST_BUDGET)?;
        profiles.create(&body, Some(&options)).await
    })
    .await;
    let profile = match result {
        Ok(profile) => profile,
        // D101: a 409 is an error naming the profile, never a lookup or a false success.
        Err(error) if error.status() == Some(409) && error.kind() == ErrorKind::Http => {
            let failure = writes::describe(&error, Change::ProfileCreated, &invocation.secrets);
            let details = match failure {
                CliError::Operational(failure) => failure.details,
                _ => Vec::new(),
            };
            return Err(CliError::Operational(Failure {
                message: format!(
                    "Profile \"{name}\" already exists. Use 'profiles update' to modify it."
                ),
                status: Some(409),
                details,
            }));
        }
        Err(error) => {
            return Err(writes::describe(
                &error,
                Change::ProfileCreated,
                &invocation.secrets,
            ));
        }
    };
    invocation.committed = true;
    let id = views::non_empty_id(profile.profile_id.as_ref().into_option())
        .unwrap_or(&profile.profile_name);
    invocation
        .output
        .status(&format!("Profile created: {}", terminal_safe(id)));
    views::render_written_profile(&mut invocation.output, &profile, format)
}

/// The §13.2 profile lookup: the first record with an id-shaped value's exact id, else
/// the highest revision of the name.
async fn lookup(
    invocation: &Invocation,
    profiles: &ProfilesClient,
    name_or_id: &str,
    options: &scm::RequestOptions,
) -> Result<SecurityProfile, CliError> {
    let found = if crate::pagination::is_uuid(name_or_id) {
        profiles.get(name_or_id, Some(options)).await
    } else {
        profiles.get_by_name(name_or_id, Some(options)).await
    };
    match found {
        Ok(profile) => Ok(profile),
        // A complete walk without a match; an incomplete one is `Limit` (D15).
        Err(error) if error.kind() == ErrorKind::Validation => Err(CliError::operational(format!(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: {name_or_id}"
        ))),
        Err(error) => Err(nothing_changed(
            invocation.management_error(&error, WALK_BUDGET),
        )),
    }
}

/// The resolved profile's id, or the D115 error.
fn profile_id<'a>(profile: &'a SecurityProfile, name_or_id: &str) -> Result<&'a str, CliError> {
    views::non_empty_id(profile.profile_id.as_ref().into_option())
        .ok_or_else(|| CliError::operational(format!("Profile {name_or_id} has no profile_id")))
}

/// The path of the `PUT` that updates `name_or_id`: the id when it has the id shape, a
/// placeholder before the lookup has resolved a name.
fn update_path(id: &str) -> String {
    format!("/v1/mgmt/profile/uuid/{id}")
}

pub async fn update(invocation: &mut Invocation, plan: &UpdatePlan) -> Result<(), CliError> {
    // A complete replacement is read and validated before the tenant (§13.17).
    let config = match &plan.config {
        Some(path) => {
            let config = crate::files::read_config(path)?;
            let shown = if crate::pagination::is_uuid(&plan.name_or_id) {
                plan.name_or_id.as_str()
            } else {
                "<profile_id>"
            };
            let body = profile_body(Value::Object(config.clone()), "PUT", &update_path(shown))?;
            Some((path, config, body))
        }
        None => None,
    };
    let options = profile_walk_options()?;
    let (management, format) = invocation
        .connect_management(plan.format, Some(&options))
        .await
        .map_err(nothing_changed)?;
    let profiles = management.profiles();
    // The one read the new body is computed from; nothing lies between it and the PUT.
    let current = lookup(invocation, &profiles, &plan.name_or_id, &options).await?;
    let id = profile_id(&current, &plan.name_or_id)?;
    let body = match config {
        Some((path, config, body)) => {
            if file_profile_name(&config) != Some(current.profile_name.as_str()) {
                return Err(CliError::operational(format!(
                    "profile_name in {} differs from the profile being updated; rename with --name instead",
                    crate::files::shown(path)
                )));
            }
            body
        }
        None => {
            let read_policy = current
                .policy
                .as_ref()
                .into_option()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| writes::invalid_body("PUT", &update_path(id)))?;
            let active = plan
                .active
                .or_else(|| current.active.as_ref().into_option().copied())
                .unwrap_or(true);
            let policy = policy::merge(read_policy, plan.patch.as_ref(), &plan.selector)?;
            profile_body(
                json!({
                    "profile_name": plan.rename.as_deref().unwrap_or(&current.profile_name),
                    "active": active,
                    "policy": policy,
                }),
                "PUT",
                &update_path(id),
            )?
        }
    };
    let secrets = invocation.secrets.clone();
    let profile = writes::send(&secrets, Change::ProfileUpdated, async || {
        let options = crate::runtime::request_options(SINGLE_REQUEST_BUDGET)?;
        profiles.update(id, &body, Some(&options)).await
    })
    .await?;
    invocation.committed = true;
    let shown = views::non_empty_id(profile.profile_id.as_ref().into_option()).unwrap_or(id);
    invocation
        .output
        .status(&format!("Profile updated: {}", terminal_safe(shown)));
    views::render_written_profile(&mut invocation.output, &profile, format)
}

pub async fn delete(invocation: &mut Invocation, plan: &DeletePlan) -> Result<(), CliError> {
    let options = profile_walk_options()?;
    let (management, _) = invocation
        .connect_management(Some(Format::Pretty), Some(&options))
        .await
        .map_err(nothing_changed)?;
    let profiles = management.profiles();
    let current = lookup(invocation, &profiles, &plan.name_or_id, &options).await?;
    let id = if crate::pagination::is_uuid(&plan.name_or_id) {
        plan.name_or_id.clone()
    } else {
        profile_id(&current, &plan.name_or_id)?.to_owned()
    };
    let name = current.profile_name.clone();
    if plan.force.is_none()
        && !confirm(
            invocation,
            &format!(
                "Delete security profile \"{}\" ({})?",
                crate::output::terminal_safe(&name),
                crate::output::terminal_safe(&id)
            ),
        )?
    {
        invocation.output.info("Aborted");
        return Ok(());
    }
    let secrets = invocation.secrets.clone();
    writes::send(&secrets, Change::ProfileDeleted, async || {
        match &plan.force {
            Some(updated_by) => profiles.force_delete(&id, updated_by, None).await,
            None => profiles.delete(&id, None).await,
        }
    })
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("Profile deleted: {name} ({id})"));
    Ok(())
}
