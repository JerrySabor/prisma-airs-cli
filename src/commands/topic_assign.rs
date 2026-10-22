//! `runtime topics apply` and `runtime topics revert` (DESIGN §13.4, §13.8, §13.9,
//! §13.17).
//!
//! Both read the topics first and the profile last: the new policy is computed from that
//! one profile read, with no request and no prompt between it and the PUT (D97). The
//! topic-guardrails edits are the pure functions of [`crate::policy`]; an unchanged
//! policy is not written. Both act on one protection block, chosen by `--direction` and
//! `--ai-profile-index` under the §13.17 layout rules (a refusal is a usage error and
//! nothing is written). `revert` then deletes the topic with a plain delete (D99) and
//! reports a partial completion when the delete fails after the profile was updated.

use super::{
    Invocation, confirm, nothing_changed, profile_walk_options, topics::complete_walk, walk_options,
};
use crate::cli::{TopicApplyArgs, TopicRevertArgs};
use crate::clients::{SINGLE_REQUEST_BUDGET, WALK_BUDGET};
use crate::error::{CliError, InterruptContext};
use crate::output::{Format, terminal_safe};
use crate::policy::{self, TopicIdentity};
use crate::profile_policy::Selector;
use crate::views;
use crate::writes::{self, Change};
use scm::ErrorKind;
use scm::airs::management::models::{CreateSecurityProfileRequest, CustomTopic, SecurityProfile};
use scm::airs::management::{ProfilesClient, TopicsClient};
use scm::pagination::CollectOptions;
use serde::Serialize;
use serde_json::{Map, Value, json};

/// A validated `topics apply`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyPlan {
    pub profile: String,
    pub name: String,
    /// `block` or `allow`.
    pub intent: String,
    pub selector: Selector,
    pub format: Format,
}

/// A validated `topics revert`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevertPlan {
    pub profile: String,
    pub name: String,
    pub force: bool,
    pub selector: Selector,
    pub format: Format,
}

pub fn plan_apply(args: &TopicApplyArgs, format: Format) -> Result<ApplyPlan, CliError> {
    if args.intent != "block" && args.intent != "allow" {
        return Err(CliError::usage(format!(
            "--intent must be \"allow\" or \"block\", got: \"{}\"",
            args.intent
        )));
    }
    let selector = Selector::parse(args.direction.as_deref(), args.ai_profile_index.as_deref())?;
    Ok(ApplyPlan {
        profile: args.profile.clone(),
        name: args.name.clone(),
        intent: args.intent.clone(),
        selector,
        format,
    })
}

pub fn plan_revert(
    args: &TopicRevertArgs,
    format: Format,
    interactive: bool,
) -> Result<RevertPlan, CliError> {
    let selector = Selector::parse(args.direction.as_deref(), args.ai_profile_index.as_deref())?;
    if !args.force && !interactive {
        return Err(CliError::usage(format!(
            "refusing to revert topic \"{}\" without --force in non-interactive mode",
            args.name
        )));
    }
    Ok(RevertPlan {
        profile: args.profile.clone(),
        name: args.name.clone(),
        force: args.force,
        selector,
        format,
    })
}

/// The topic a command acts on: the highest revision of the name (first on ties, D96)
/// and the ids of every listed revision with that name (§13.4).
struct ResolvedTopic {
    id: String,
    name: String,
    revision: Value,
    ids: Vec<String>,
}

impl ResolvedTopic {
    fn identity(&self) -> TopicIdentity<'_> {
        TopicIdentity {
            name: &self.name,
            ids: &self.ids,
        }
    }
}

/// The §13.2 topic lookup by name over one complete walk. `None`: no record, or the
/// selected record has no `topic_id`.
async fn resolve_topic(
    invocation: &Invocation,
    topics: &TopicsClient,
    name: &str,
    options: &scm::RequestOptions,
) -> Result<Option<ResolvedTopic>, CliError> {
    let rows: Vec<CustomTopic> = complete_walk(topics, 100, CollectOptions::default(), options)
        .await
        .map_err(|error| nothing_changed(invocation.management_error(&error, WALK_BUDGET)))?;
    let named: Vec<&CustomTopic> = rows.iter().filter(|row| row.topic_name == name).collect();
    let mut best: Option<&CustomTopic> = None;
    for row in &named {
        if best.is_none_or(|current| views::revision_value(*row) > views::revision_value(current)) {
            best = Some(row);
        }
    }
    let Some(best) = best else {
        return Ok(None);
    };
    let Some(id) = views::non_empty_id(best.topic_id.as_ref().into_option()) else {
        return Ok(None);
    };
    let ids = named
        .iter()
        .filter_map(|row| views::non_empty_id(row.topic_id.as_ref().into_option()))
        .map(str::to_owned)
        .collect();
    Ok(Some(ResolvedTopic {
        id: id.to_owned(),
        name: best.topic_name.clone(),
        revision: serde_json::to_value(&best.revision).unwrap_or_else(|_| json!(0)),
        ids,
    }))
}

/// The profile read last (§13.4): the highest revision of the name.
async fn read_profile(
    invocation: &Invocation,
    profiles: &ProfilesClient,
    name: &str,
    options: &scm::RequestOptions,
) -> Result<(SecurityProfile, String), CliError> {
    let profile = match profiles.get_by_name(name, Some(options)).await {
        Ok(profile) => profile,
        // A complete walk without a match; an incomplete one is `Limit` (D15).
        Err(error) if error.kind() == ErrorKind::Validation => {
            return Err(CliError::operational(format!(
                "Profile \"{name}\" not found"
            )));
        }
        Err(error) => {
            return Err(nothing_changed(
                invocation.management_error(&error, WALK_BUDGET),
            ));
        }
    };
    let id = views::non_empty_id(profile.profile_id.as_ref().into_option())
        .ok_or_else(|| CliError::operational(format!("Profile {name} has no profile_id")))?
        .to_owned();
    if !crate::pagination::is_uuid(&id) {
        return Err(CliError::operational(format!(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid profile_id: {id}"
        )));
    }
    Ok((profile, id))
}

/// The read policy as JSON (unknown keys and number forms kept, S§4).
fn read_policy(profile: &SecurityProfile, id: &str) -> Result<Option<Value>, CliError> {
    profile
        .policy
        .as_ref()
        .into_option()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| writes::invalid_body("PUT", &format!("/v1/mgmt/profile/uuid/{id}")))
}

/// The PUT body `{profile_name, active, policy}` from the read record (`active` omitted
/// when the record has none), validated for `PUT /v1/mgmt/profile/uuid/<id>` (§13.2, §13.17).
fn profile_body(
    profile: &SecurityProfile,
    id: &str,
    policy: Value,
) -> Result<CreateSecurityProfileRequest, CliError> {
    let mut body = Map::new();
    body.insert("profile_name".into(), json!(profile.profile_name));
    if let Some(active) = profile.active.as_ref().into_option() {
        body.insert("active".into(), json!(active));
    }
    body.insert("policy".into(), policy);
    // The TypeScript 0.35.0 request root (§13.17); a mismatch stays exit 1 here, as in
    // TypeScript 7.3.0, whose topic writes report a schema failure as an operational error.
    policy::request_body(Value::Object(body))
        .ok_or_else(|| writes::invalid_body("PUT", &format!("/v1/mgmt/profile/uuid/{id}")))
}

/// The `topics apply` record (TS `--format json` shape and order).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyRecord<'a> {
    topic_id: &'a str,
    topic_name: &'a str,
    profile_name: &'a str,
    intent: &'a str,
}

pub async fn apply(invocation: &mut Invocation, plan: &ApplyPlan) -> Result<(), CliError> {
    let options = walk_options()?;
    let (management, format) = invocation
        .connect_management(Some(plan.format), Some(&options))
        .await
        .map_err(nothing_changed)?;
    let topics = management.topics();
    let topic = resolve_topic(invocation, &topics, &plan.name, &options)
        .await?
        .ok_or_else(|| {
            CliError::operational(format!(
                "Topic \"{}\" not found. Create it first with \"topics create\".",
                plan.name
            ))
        })?;
    // The profile is read last; nothing lies between this read and the PUT (D97).
    let profiles = management.profiles();
    let options = profile_walk_options()?;
    let (current, id) = read_profile(invocation, &profiles, &plan.profile, &options).await?;
    let before = read_policy(&current, &id)?;
    let new_ref = json!({
        "topic_id": topic.id,
        "topic_name": topic.name,
        "revision": topic.revision,
    });
    let after = policy::apply_topic(
        before.clone(),
        &plan.selector,
        topic.identity(),
        new_ref,
        &plan.intent,
    )?;
    if before.as_ref() == Some(&after) {
        invocation.output.status(&format!(
            "Profile {} already has {} with intent {}; nothing was written",
            terminal_safe(&plan.profile),
            terminal_safe(&plan.name),
            plan.intent
        ));
    } else {
        let body = profile_body(&current, &id, after)?;
        let secrets = invocation.secrets.clone();
        writes::send(&secrets, Change::ProfileUpdated, async || {
            let options = crate::runtime::request_options(SINGLE_REQUEST_BUDGET)?;
            profiles.update(&id, &body, Some(&options)).await
        })
        .await?;
        invocation.committed = true;
    }
    let record = ApplyRecord {
        topic_id: &topic.id,
        topic_name: &topic.name,
        profile_name: &plan.profile,
        intent: &plan.intent,
    };
    let pairs = [
        ("Applied", terminal_safe(&topic.name).into_owned()),
        ("Profile", terminal_safe(&plan.profile).into_owned()),
        ("Intent", plan.intent.clone()),
    ];
    views::render_record(&mut invocation.output, &record, &pairs, format)
}

/// The `topics revert` record (TS `--format json` shape and order).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevertRecord<'a> {
    profile_name: &'a str,
    deleted: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    kept: Vec<&'a str>,
}

/// An error with one more detail line.
fn with_detail(error: CliError, line: String) -> CliError {
    match error {
        CliError::Operational(mut failure) => {
            failure.details.push(line);
            CliError::Operational(failure)
        }
        other => other,
    }
}

pub async fn revert(invocation: &mut Invocation, plan: &RevertPlan) -> Result<(), CliError> {
    let options = walk_options()?;
    let (management, format) = invocation
        .connect_management(Some(plan.format), Some(&options))
        .await
        .map_err(nothing_changed)?;
    let topics = management.topics();
    let topic = resolve_topic(invocation, &topics, &plan.name, &options)
        .await?
        .ok_or_else(|| CliError::operational(format!("Topic \"{}\" not found", plan.name)))?;
    if !crate::pagination::is_uuid(&topic.id) {
        return Err(CliError::operational(format!(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid topic_id: {}",
            topic.id
        )));
    }
    // After the topic lookup, so a typo is reported before the question (D105).
    if !plan.force
        && !confirm(
            invocation,
            &format!(
                "Remove topic \"{}\" from profile \"{}\" and delete it?",
                terminal_safe(&plan.name),
                terminal_safe(&plan.profile)
            ),
        )?
    {
        invocation.output.info("Aborted");
        return Ok(());
    }
    let profiles = management.profiles();
    let options = profile_walk_options()?;
    let (current, id) = read_profile(invocation, &profiles, &plan.profile, &options).await?;
    let before = read_policy(&current, &id)?;
    // A topic the selected block does not reference, or that another block still
    // references, is refused here: nothing is written or deleted (§13.17).
    let after = policy::revert_topic(before.as_ref(), &plan.selector, topic.identity())?;
    let secrets = invocation.secrets.clone();
    let body = profile_body(&current, &id, after)
        .map_err(|error| with_detail(error, "The topic was not deleted.".into()))?;
    writes::send(&secrets, Change::ProfileUpdated, async || {
        let options = crate::runtime::request_options(SINGLE_REQUEST_BUDGET)?;
        profiles.update(&id, &body, Some(&options)).await
    })
    .await
    .map_err(|error| with_detail(error, "The topic was not deleted.".into()))?;
    // An interruption from here on names the completed step first (§13.2).
    invocation.interrupt = Some(InterruptContext::ProfileUpdatedTopicKept);
    let deleted = writes::attempt(async || topics.delete(&topic.id, None).await).await;
    // D99 (0.4.1): a 409 means the topic is still referenced (by another profile, or by
    // an older revision of this one: every profile PUT mints a new revision). The
    // profile no longer references it, so the revert succeeded and the topic is kept.
    let kept = match deleted {
        Ok(_) => false,
        Err(error) if error.kind() == ErrorKind::Http && error.status() == Some(409) => true,
        Err(error) => {
            let error = writes::describe(&error, Change::TopicDeleted, &secrets);
            return Err(match error {
                CliError::Interrupted(InterruptContext::NothingChanged) => {
                    CliError::Interrupted(InterruptContext::ProfileUpdatedTopicKept)
                }
                CliError::Interrupted(_) => {
                    CliError::Interrupted(InterruptContext::ProfileUpdatedTopicUnknown)
                }
                other => with_detail(
                    other,
                    format!(
                        "Profile {} was updated ({} removed); the topic was not deleted.",
                        plan.profile, plan.name
                    ),
                ),
            });
        }
    };
    invocation.committed = true;
    if kept {
        invocation.output.warning(&format!(
            "⚠ Topic {} is still referenced (by another profile or an older profile revision), so it was kept. Run `runtime profiles cleanup`, then `runtime topics delete {}`.",
            terminal_safe(&plan.name),
            terminal_safe(&topic.id)
        ));
    }
    let (deleted, kept) = if kept {
        (Vec::new(), vec![topic.id.as_str()])
    } else {
        (vec![topic.id.as_str()], Vec::new())
    };
    let label = if kept.is_empty() { "Deleted" } else { "Kept" };
    let record = RevertRecord {
        profile_name: &plan.profile,
        deleted,
        kept,
    };
    let pairs = [
        ("Reverted", terminal_safe(&plan.name).into_owned()),
        ("Profile", terminal_safe(&plan.profile).into_owned()),
        (label, terminal_safe(&topic.id).into_owned()),
    ];
    views::render_record(&mut invocation.output, &record, &pairs, format)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_args(intent: &str) -> TopicApplyArgs {
        TopicApplyArgs {
            profile: "p".into(),
            name: "n".into(),
            intent: intent.into(),
            direction: None,
            ai_profile_index: None,
            format: None,
        }
    }

    #[test]
    fn intent_must_be_exactly_block_or_allow() {
        for good in ["block", "allow"] {
            assert_eq!(
                plan_apply(&apply_args(good), Format::Pretty)
                    .unwrap()
                    .intent,
                good
            );
        }
        for bad in ["Block", "", " allow", "deny"] {
            assert_eq!(
                plan_apply(&apply_args(bad), Format::Pretty),
                Err(CliError::usage(format!(
                    "--intent must be \"allow\" or \"block\", got: \"{bad}\""
                )))
            );
        }
    }

    #[test]
    fn revert_needs_force_without_a_terminal() {
        let args = TopicRevertArgs {
            profile: "p".into(),
            name: "fin".into(),
            force: false,
            direction: None,
            ai_profile_index: None,
            format: None,
        };
        assert_eq!(
            plan_revert(&args, Format::Json, false),
            Err(CliError::usage(
                "refusing to revert topic \"fin\" without --force in non-interactive mode"
            ))
        );
        assert!(plan_revert(&args, Format::Json, true).is_ok());
        let forced = TopicRevertArgs {
            force: true,
            ..args
        };
        assert!(plan_revert(&forced, Format::Json, false).unwrap().force);
    }
}
