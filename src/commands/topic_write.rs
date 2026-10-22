//! `runtime topics create`, `update <topicId>` and `delete|rm <topicId>` (DESIGN §13.5–
//! §13.7).
//!
//! Every argument check runs in planning (exit 2, before the tenant is read); input
//! files are read before the tenant; each write is one SDK call with the single 401
//! replay of [`crate::writes`].

use super::{Invocation, confirm, nothing_changed, walk_options};
use crate::cli::{TopicCreateArgs, TopicDeleteArgs, TopicUpdateArgs};
use crate::clients::WALK_BUDGET;
use crate::error::CliError;
use crate::output::{Format, terminal_safe};
use crate::render::js_json_number;
use crate::views;
use crate::writes::{self, Change};
use scm::ErrorKind;
use scm::airs::management::models::{CreateCustomTopicRequest, CustomTopic, FiniteNumber};
use scm::validation::Mode;
use serde::Serialize;
use std::ffi::OsString;

const MAX_NAME: usize = 100;
const MAX_DESCRIPTION: usize = 250;
const MAX_EXAMPLE: usize = 250;
const MIN_EXAMPLES: usize = 2;
const MAX_EXAMPLES: usize = 5;
const MAX_COMBINED: usize = 1000;

/// A validated `topics create`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatePlan {
    pub name: String,
    pub description: String,
    pub examples: Vec<String>,
    pub format: Format,
}

/// A validated `topics update`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePlan {
    pub topic_id: String,
    pub config: OsString,
    pub format: Format,
}

/// A validated `topics delete`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletePlan {
    pub topic_id: String,
    /// `Some(email)` with `--force` (the force endpoint), `None` for the plain delete.
    pub force: Option<String>,
}

/// The TypeScript `validateTopic` rules on UTF-8 byte lengths (`core/constraints.ts`),
/// every failure in order as `<field>: <message>` (§13.5).
pub fn constraint_errors(name: &str, description: &str, examples: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    if name.is_empty() {
        errors.push("name: Name is required".to_owned());
    } else if name.len() > MAX_NAME {
        errors.push(format!("name: Name must be at most {MAX_NAME} bytes"));
    }
    if description.is_empty() {
        errors.push("description: Description is required".to_owned());
    } else if description.len() > MAX_DESCRIPTION {
        errors.push(format!(
            "description: Description must be at most {MAX_DESCRIPTION} bytes"
        ));
    }
    if examples.len() < MIN_EXAMPLES {
        errors.push(format!(
            "examples: At least {MIN_EXAMPLES} examples required"
        ));
    }
    if examples.len() > MAX_EXAMPLES {
        errors.push(format!("examples: At most {MAX_EXAMPLES} examples allowed"));
    }
    for (index, example) in examples.iter().enumerate() {
        if example.is_empty() {
            errors.push(format!("examples[{index}]: Example {index} is required"));
        } else if example.len() > MAX_EXAMPLE {
            errors.push(format!(
                "examples[{index}]: Example {index} must be at most {MAX_EXAMPLE} bytes"
            ));
        }
    }
    let combined = name.len() + description.len() + examples.iter().map(String::len).sum::<usize>();
    if combined > MAX_COMBINED {
        errors.push(format!(
            "topic: Combined length ({combined}) exceeds {MAX_COMBINED} bytes"
        ));
    }
    errors
}

pub fn plan_create(args: &TopicCreateArgs, format: Format) -> Result<CreatePlan, CliError> {
    let errors = constraint_errors(&args.name, &args.description, &args.examples);
    if !errors.is_empty() {
        return Err(CliError::usage(errors.join("; ")));
    }
    Ok(CreatePlan {
        name: args.name.clone(),
        description: args.description.clone(),
        examples: args.examples.clone(),
        format,
    })
}

/// `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid topic_id: <id>` (the SDK text).
fn invalid_topic_id(id: &str) -> String {
    format!("AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid topic_id: {id}")
}

pub fn plan_update(args: &TopicUpdateArgs, format: Format) -> Result<UpdatePlan, CliError> {
    if !crate::pagination::is_uuid(&args.topic_id) {
        return Err(CliError::usage(invalid_topic_id(&args.topic_id)));
    }
    Ok(UpdatePlan {
        topic_id: args.topic_id.clone(),
        config: args.config.clone(),
        format,
    })
}

/// The usage error for an `--updated-by` value with a control character (D104).
pub const UPDATED_BY_CONTROL: &str = "--updated-by <email> must not contain control characters";

/// Whether an `--updated-by` value carries a control character (refused, D104).
pub fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// The `--updated-by` rule of a force delete (§13.7): present, not blank (JavaScript
/// trim) and free of control characters.
pub fn force_audit(updated_by: Option<&str>) -> Result<String, CliError> {
    let value = updated_by
        .filter(|value| !crate::tenant::config::js_trim(value).is_empty())
        .ok_or_else(|| CliError::usage("--updated-by <email> is required with --force"))?;
    if has_control(value) {
        return Err(CliError::usage(UPDATED_BY_CONTROL));
    }
    Ok(value.to_owned())
}

pub fn plan_delete(args: &TopicDeleteArgs, interactive: bool) -> Result<DeletePlan, CliError> {
    if !args.force && !interactive {
        return Err(CliError::usage(format!(
            "refusing to delete topic {} without --force in non-interactive mode",
            args.topic_id
        )));
    }
    if !crate::pagination::is_uuid(&args.topic_id) {
        return Err(CliError::usage(invalid_topic_id(&args.topic_id)));
    }
    let force = if args.force {
        Some(force_audit(args.updated_by.as_deref())?)
    } else {
        None
    };
    Ok(DeletePlan {
        topic_id: args.topic_id.clone(),
        force,
    })
}

/// A request body for `<METHOD> <path>`, validated with the SDK's request schema.
fn topic_body(
    value: serde_json::Value,
    method: &str,
    path: &str,
) -> Result<CreateCustomTopicRequest, CliError> {
    CreateCustomTopicRequest::parse(value, Mode::Request)
        .map_err(|_| writes::invalid_body(method, path))
}

/// The `topics create` record (TS `--format json` shape and order).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateRecord<'a> {
    topic_id: &'a str,
    topic_name: &'a str,
    revision: &'a FiniteNumber,
    created: bool,
}

pub async fn create(invocation: &mut Invocation, plan: &CreatePlan) -> Result<(), CliError> {
    let options = walk_options()?;
    let (management, format) = invocation
        .connect_management(Some(plan.format), Some(&options))
        .await
        .map_err(nothing_changed)?;
    let topics = management.topics();
    let existing = match topics.get_by_name(&plan.name, Some(&options)).await {
        Ok(topic) => Some(topic),
        // A complete walk without a match; an incomplete one is `Limit` (D15).
        Err(error) if error.kind() == ErrorKind::Validation => None,
        Err(error) => {
            return Err(nothing_changed(
                invocation.management_error(&error, WALK_BUDGET),
            ));
        }
    };
    let value = serde_json::json!({
        "topic_name": plan.name,
        "description": plan.description,
        "examples": plan.examples,
    });
    let secrets = invocation.secrets.clone();
    let (change, result) = match &existing {
        Some(topic) => {
            let id =
                views::non_empty_id(topic.topic_id.as_ref().into_option()).ok_or_else(|| {
                    CliError::operational(format!("Existing topic '{}' has no topic_id", plan.name))
                })?;
            if !crate::pagination::is_uuid(id) {
                return Err(CliError::operational(invalid_topic_id(id)));
            }
            let body = topic_body(value, "PUT", &format!("/v1/mgmt/topic/uuid/{id}"))?;
            let change = Change::TopicUpdated;
            let result = writes::send(&secrets, change, async || {
                topics.update(id, &body, None).await
            })
            .await;
            (change, result)
        }
        None => {
            let body = topic_body(value, "POST", "/v1/mgmt/topic")?;
            let change = Change::TopicCreated;
            let result =
                writes::send(&secrets, change, async || topics.create(&body, None).await).await;
            (change, result)
        }
    };
    let topic = result?;
    invocation.committed = true;
    let Some(topic_id) = views::non_empty_id(topic.topic_id.as_ref().into_option()) else {
        let (_, done) = change.words();
        return Err(CliError::Operational(crate::error::Failure {
            message: "API response missing topic_id".into(),
            status: None,
            details: vec![format!(
                "Outcome: the topic was {done}, but the response carried no topic_id."
            )],
        }));
    };
    let record = CreateRecord {
        topic_id,
        topic_name: &topic.topic_name,
        revision: &topic.revision,
        created: existing.is_none(),
    };
    let (_, done) = change.words();
    invocation
        .output
        .success(&format!("Topic {done}: {}", topic.topic_name));
    let pairs = [
        ("ID", terminal_safe(topic_id).into_owned()),
        ("Revision", js_json_number(topic.revision.as_number())),
    ];
    views::render_record(&mut invocation.output, &record, &pairs, format)
}

pub async fn update(invocation: &mut Invocation, plan: &UpdatePlan) -> Result<(), CliError> {
    let config = crate::files::read_config(&plan.config)?;
    let body = topic_body(
        serde_json::Value::Object(config),
        "PUT",
        &format!("/v1/mgmt/topic/uuid/{}", plan.topic_id),
    )?;
    let (management, format) = invocation
        .connect_management(Some(plan.format), None)
        .await
        .map_err(nothing_changed)?;
    let topics = management.topics();
    let secrets = invocation.secrets.clone();
    let topic: CustomTopic = writes::send(&secrets, Change::TopicUpdated, async || {
        topics.update(&plan.topic_id, &body, None).await
    })
    .await?;
    invocation.committed = true;
    let id = views::non_empty_id(topic.topic_id.as_ref().into_option()).unwrap_or(&plan.topic_id);
    invocation.output.success(&format!("Topic updated: {id}"));
    views::render_topic_detail(&mut invocation.output, &topic, format)
}

pub async fn delete(invocation: &mut Invocation, plan: &DeletePlan) -> Result<(), CliError> {
    let clients = invocation.management_clients()?;
    if plan.force.is_none() && !confirm(invocation, &format!("Delete topic {}?", plan.topic_id))? {
        invocation.output.info("Aborted");
        return Ok(());
    }
    clients
        .authenticate(None, crate::clients::TOKEN_BUDGET)
        .await
        .map_err(nothing_changed)?;
    let topics = clients.management.topics();
    let secrets = invocation.secrets.clone();
    let id = plan.topic_id.as_str();
    writes::send(&secrets, Change::TopicDeleted, async || match &plan.force {
        Some(updated_by) => topics.force_delete_with_audit(id, updated_by, None).await,
        None => topics.delete(id, None).await,
    })
    .await?;
    invocation.committed = true;
    // D107: a fixed line, never the server's message.
    let line = if plan.force.is_some() {
        format!("Topic {id} force-deleted.")
    } else {
        format!("Topic {id} deleted.")
    };
    invocation.output.success(&line);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn constraints_follow_the_typescript_order_and_byte_lengths() {
        assert!(constraint_errors("n", "d", &strings(&["a", "b"])).is_empty());
        assert_eq!(
            constraint_errors("", "", &strings(&["a"])),
            [
                "name: Name is required",
                "description: Description is required",
                "examples: At least 2 examples required"
            ]
        );
        let long = "é".repeat(51); // 102 bytes, 51 characters
        assert_eq!(
            constraint_errors(&long, "d", &strings(&["a", "", "c", "d", "e", "f"])),
            [
                "name: Name must be at most 100 bytes",
                "examples: At most 5 examples allowed",
                "examples[1]: Example 1 is required"
            ]
        );
        let example = "x".repeat(251);
        assert_eq!(
            constraint_errors("n", &"d".repeat(251), &[example.clone(), "y".into()]),
            [
                "description: Description must be at most 250 bytes",
                "examples[0]: Example 0 must be at most 250 bytes"
            ]
        );
        let full = "x".repeat(250);
        assert_eq!(
            constraint_errors(
                &"n".repeat(100),
                &"d".repeat(250),
                &[full.clone(), full.clone(), full.clone()]
            ),
            ["topic: Combined length (1100) exceeds 1000 bytes"]
        );
        assert!(
            constraint_errors(
                &"n".repeat(100),
                &"d".repeat(150),
                &[full.clone(), full.clone(), full.clone()]
            )
            .is_empty(),
            "exactly 1000 bytes"
        );
    }

    #[test]
    fn force_needs_a_usable_audit_email() {
        for bad in [None, Some(""), Some(" \u{a0}\t")] {
            assert_eq!(
                force_audit(bad),
                Err(CliError::usage(
                    "--updated-by <email> is required with --force"
                )),
                "{bad:?}"
            );
        }
        for bad in ["a\u{7}b", "ops\tteam@x", "a@b\u{9b}"] {
            assert_eq!(
                force_audit(Some(bad)),
                Err(CliError::usage(UPDATED_BY_CONTROL)),
                "{bad:?}"
            );
        }
        assert_eq!(force_audit(Some(" a@b ")).unwrap(), " a@b ");
    }
}
