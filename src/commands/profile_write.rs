//! `runtime profiles create`, `update <nameOrId>` and `delete|rm <nameOrId>` (DESIGN
//! §13.12–§13.14).
//!
//! Argument checks run in planning (exit 2); `--config` files and the flag-built body are
//! read and validated before the tenant; `update` reads the profile once, last, and
//! writes the body computed from that read (§13.4).

use super::{Invocation, confirm, nothing_changed, walk_options};
use crate::cli::{ProfileCreateArgs, ProfileDeleteArgs, ProfileUpdateArgs};
use crate::clients::WALK_BUDGET;
use crate::error::{CliError, Failure};
use crate::output::Format;
use crate::policy::{self, Flags};
use crate::views;
use crate::writes::{self, Change};
use scm::ErrorKind;
use scm::airs::management::ProfilesClient;
use scm::airs::management::models::{CreateSecurityProfileRequest, SecurityProfile};
use scm::validation::Mode;
use serde_json::{Value, json};
use std::ffi::OsString;

/// Where a `profiles create` body comes from.
#[derive(Clone, Debug, PartialEq)]
pub enum CreateBody {
    /// Built from the flags (TS `buildProfileRequest`).
    Flags(Value),
    /// The `--config` file's object, as is.
    Config(OsString),
}

/// A validated `profiles create`.
#[derive(Clone, Debug, PartialEq)]
pub struct CreatePlan {
    pub name: String,
    pub body: CreateBody,
    pub format: Format,
}

/// A validated `profiles update`.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdatePlan {
    pub name_or_id: String,
    pub rename: Option<String>,
    /// `--active` / `--no-active`; `None` keeps the read value (D100).
    pub active: Option<bool>,
    pub flags: Flags,
    pub config: Option<OsString>,
    pub format: Format,
}

/// A validated `profiles delete`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletePlan {
    pub name_or_id: String,
    /// `Some(email)` with `--force` (the force endpoint).
    pub force: Option<String>,
}

pub fn plan_create(args: &ProfileCreateArgs, format: Format) -> Result<CreatePlan, CliError> {
    if args.config.is_some() && (args.no_active || Flags::raw_any(&args.policy)) {
        return Err(CliError::usage(
            "--config cannot be combined with --no-active or policy flags",
        ));
    }
    let flags = Flags::read(&args.policy);
    if args.config.is_none() && !flags.any_protection() {
        return Err(CliError::usage(
            "Specify at least one policy flag (for example --prompt-injection block) or --config <path>",
        ));
    }
    flags.check()?;
    let body = match &args.config {
        Some(path) => CreateBody::Config(path.clone()),
        None => CreateBody::Flags(policy::create_request(&args.name, !args.no_active, &flags)),
    };
    Ok(CreatePlan {
        name: args.name.clone(),
        body,
        format,
    })
}

pub fn plan_update(args: &ProfileUpdateArgs, format: Format) -> Result<UpdatePlan, CliError> {
    if args.config.is_some()
        && (args.name.is_some() || args.active || args.no_active || Flags::raw_any(&args.policy))
    {
        return Err(CliError::usage(
            "--config cannot be combined with --name, --active, --no-active or policy flags",
        ));
    }
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
        flags,
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

/// The body for `<METHOD> <path>`, validated with the SDK's request schema (D116).
fn profile_body(
    value: Value,
    method: &str,
    path: &str,
) -> Result<CreateSecurityProfileRequest, CliError> {
    CreateSecurityProfileRequest::parse(value, Mode::Request)
        .map_err(|_| writes::invalid_body(method, path))
}

/// The file's `profile_name`, when it is a string.
fn file_profile_name(config: &serde_json::Map<String, Value>) -> Option<&str> {
    config.get("profile_name").and_then(Value::as_str)
}

pub async fn create(invocation: &mut Invocation, plan: &CreatePlan) -> Result<(), CliError> {
    let value = match &plan.body {
        CreateBody::Flags(value) => value.clone(),
        CreateBody::Config(path) => {
            let config = crate::files::read_config(path)?;
            if file_profile_name(&config) != Some(plan.name.as_str()) {
                return Err(CliError::operational(format!(
                    "profile_name in {} does not match --name {}",
                    crate::files::shown(path),
                    plan.name
                )));
            }
            Value::Object(config)
        }
    };
    let body = profile_body(value, "POST", "/v1/mgmt/profile")?;
    let (management, format) = invocation
        .connect_management(Some(plan.format), None)
        .await
        .map_err(nothing_changed)?;
    let profiles = management.profiles();
    let result = writes::attempt(async || profiles.create(&body, None).await).await;
    let profile = match result {
        Ok(profile) => profile,
        // D101: a 409 is an error, never a lookup or a false success.
        Err(error) if error.status() == Some(409) && error.kind() == ErrorKind::Http => {
            let failure = writes::describe(&error, Change::ProfileCreated, &invocation.secrets);
            let details = match failure {
                CliError::Operational(failure) => failure.details,
                _ => Vec::new(),
            };
            return Err(CliError::Operational(Failure {
                message: format!(
                    "Profile \"{}\" already exists. Use 'profiles update' to modify it.",
                    plan.name
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
    invocation.output.success(&format!("Profile created: {id}"));
    views::render_profile_detail(&mut invocation.output, &profile, format)
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

pub async fn update(invocation: &mut Invocation, plan: &UpdatePlan) -> Result<(), CliError> {
    let config = match &plan.config {
        Some(path) => Some((path, crate::files::read_config(path)?)),
        None => None,
    };
    let options = walk_options()?;
    let (management, format) = invocation
        .connect_management(Some(plan.format), Some(&options))
        .await
        .map_err(nothing_changed)?;
    let profiles = management.profiles();
    // The one read the new body is computed from; nothing lies between it and the PUT.
    let current = lookup(invocation, &profiles, &plan.name_or_id, &options).await?;
    let id = profile_id(&current, &plan.name_or_id)?;
    let value = match config {
        Some((path, config)) => {
            if file_profile_name(&config) != Some(current.profile_name.as_str()) {
                return Err(CliError::operational(format!(
                    "profile_name in {} differs from the profile being updated; rename with --name instead",
                    crate::files::shown(path)
                )));
            }
            Value::Object(config)
        }
        None => {
            let read_policy = current
                .policy
                .as_ref()
                .into_option()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| writes::invalid_body("PUT", &format!("/v1/mgmt/profile/uuid/{id}")))?;
            let active = plan
                .active
                .or_else(|| current.active.as_ref().into_option().copied())
                .unwrap_or(true);
            json!({
                "profile_name": plan.rename.as_deref().unwrap_or(&current.profile_name),
                "active": active,
                "policy": policy::merge(read_policy, &plan.flags),
            })
        }
    };
    let body = profile_body(value, "PUT", &format!("/v1/mgmt/profile/uuid/{id}"))?;
    let secrets = invocation.secrets.clone();
    let profile = writes::send(&secrets, Change::ProfileUpdated, async || {
        profiles.update(id, &body, None).await
    })
    .await?;
    invocation.committed = true;
    let shown = views::non_empty_id(profile.profile_id.as_ref().into_option()).unwrap_or(id);
    invocation
        .output
        .success(&format!("Profile updated: {shown}"));
    views::render_profile_detail(&mut invocation.output, &profile, format)
}

pub async fn delete(invocation: &mut Invocation, plan: &DeletePlan) -> Result<(), CliError> {
    let options = walk_options()?;
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
