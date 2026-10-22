//! `gateway workspaces create|update|archive` (and the hidden `delete`) and `gateway scopes
//! create|bind|delete` (DESIGN §19.6, §19.7; D229, D235, D236, D243).
//!
//! `workspaces create` composes the provisioning from the public steps (G37): the IAM
//! scope create, the workspace create, the scope bind and the read-back, each write one
//! attempt (D228), the scope deleted again only after a **rejected** workspace create, and
//! every partial outcome named with an `airs` remedy.

use super::Invocation;
use super::gateway_writes::attempt;
use super::write_common as wc;
use crate::clients::{SINGLE_REQUEST_BUDGET, TOKEN_BUDGET};
use crate::error::{CliError, Failure, InterruptContext};
use crate::gateway::provision::{self, Hints};
use crate::gateway::resolve::{self, ListRead, Resolved};
use crate::gateway::{self, GwPlane, views, withhold};
use crate::json::OValue;
use crate::output::{Format, terminal_safe};
use crate::store::PROGRAM;
use crate::writes::Lines;
use scm::airs::gateway::AIGatewayClient;
use scm::airs::gateway::models::GatewayWorkspaceCreateRequest;
use scm::shared::iam::models::IamScopeCreateInput;
use scm::validation::Mode;
use serde_json::{Map, Value, json};

/// A planned `workspaces create` (§19.6).
#[derive(Clone, Debug, PartialEq)]
pub struct ProvisionPlan {
    pub name: String,
    /// `--scope-name` (else a generated `ws_<stem>_<suffix>`).
    pub scope: Option<String>,
    pub existing: bool,
    pub description: Option<String>,
    /// The workspace create body without `scope_name`.
    pub body: Map<String, Value>,
    pub warnings: Vec<String>,
    pub format: Option<Format>,
}

/// A planned `workspaces update <ref>` (§19.6).
#[derive(Clone, Debug, PartialEq)]
pub struct UpdatePlan {
    pub reference: String,
    pub body: Map<String, Value>,
    pub force: bool,
    pub format: Option<Format>,
}

/// The admin active list (`workspaces update|archive|delete`, `scopes bind`).
const ADMIN: &[ListRead] = &[ListRead {
    plane: GwPlane::Admin,
    status: None,
}];

fn context(text: String) -> InterruptContext {
    InterruptContext::Context(text)
}

/// A read's error with a context for an interruption.
fn read_failure(
    invocation: &mut Invocation,
    error: &scm::Error,
    plane: GwPlane,
    interrupted: InterruptContext,
) -> CliError {
    match invocation.gateway_error(error, plane) {
        CliError::Interrupted(_) => CliError::Interrupted(interrupted),
        other => other,
    }
}

fn with_detail(error: CliError, lines: &[String]) -> CliError {
    match error {
        CliError::Operational(mut failure) => {
            failure.details.extend(lines.iter().cloned());
            CliError::Operational(failure)
        }
        other => other,
    }
}

/// Resolve a workspace reference on the admin plane (§19.4): the slug and the row's id.
async fn resolve_admin(
    invocation: &mut Invocation,
    gateway: &AIGatewayClient,
    reference: &str,
) -> Result<(String, Option<String>), CliError> {
    let answer = match resolve::read_list(gateway, ADMIN[0]).await {
        Ok(answer) => answer,
        Err(failure) => {
            return Err(read_failure(
                invocation,
                &failure.error,
                failure.plane,
                InterruptContext::NothingChanged,
            ));
        }
    };
    let rows = answer
        .get("data")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    let slug = match resolve::match_answer(&answer, reference) {
        Resolved::ByRef(slug) | Resolved::ByName(slug) => slug,
        Resolved::Incomplete => {
            return Err(CliError::operational(resolve::incomplete_message(
                reference, true,
            )));
        }
        Resolved::Ambiguous(slugs) => {
            return Err(CliError::operational(resolve::ambiguous_message(
                reference, &slugs,
            )));
        }
        Resolved::NotFound => {
            return Err(CliError::operational(resolve::not_found_message(
                reference, ADMIN,
            )));
        }
        Resolved::NoSlug => {
            return Err(CliError::operational(resolve::no_slug_message(
                reference, true,
            )));
        }
    };
    let id = rows
        .iter()
        .find(|row| row.get("slug").and_then(OValue::as_str) == Some(slug.as_str()))
        .and_then(|row| row.get("id"))
        .and_then(OValue::as_str)
        .map(str::to_owned);
    Ok((slug, id))
}

/// Connect (tenant, credentials, client) and fetch the token; an interruption changed
/// nothing.
async fn connect(
    invocation: &mut Invocation,
    explicit: Option<Format>,
) -> Result<(crate::clients::GatewayClients, Format), CliError> {
    let (clients, format, _) = invocation
        .gateway_clients(explicit, None)
        .map_err(super::nothing_changed)?;
    clients
        .authenticate(None, TOKEN_BUDGET)
        .await
        .map_err(super::nothing_changed)?;
    Ok((clients, format))
}

/// The admin-plane workspace detail as a §19.5 record.
async fn read_back(gateway: &AIGatewayClient, reference: &str) -> Result<OValue, scm::Error> {
    super::gateway_workspaces::read_detail(gateway, reference, GwPlane::Admin).await
}

fn options() -> scm::Result<scm::RequestOptions> {
    gateway::sdk_options(SINGLE_REQUEST_BUDGET)
}

/// The scope of one `workspaces create` run, shared by its steps.
struct Provisioning<'a> {
    gateway: &'a AIGatewayClient,
    /// The scope name as sent.
    scope: String,
    /// The scope name through `terminal_safe` (every message).
    shown_scope: String,
    /// Step 1 creates the scope (no `--existing-scope`), so a rejected step 2 deletes it.
    created: bool,
    existing: bool,
}

/// The workspace step 2 created: its `slug` and `id` as sent and as shown.
struct Created {
    raw_slug: String,
    raw_id: String,
    slug: String,
    id: String,
}

/// `workspaces create` (§19.6): the provisioning steps and their outcomes (D229), in
/// order: the request built and checked, the tenant and token, step 1 the IAM scope
/// (unless `--existing-scope`), step 2 the workspace (a rejection deletes a created scope
/// again), step 3 the binding, step 4 the read-back and the record.
pub async fn create(invocation: &mut Invocation, plan: &ProvisionPlan) -> Result<(), CliError> {
    for warning in &plan.warnings {
        invocation.output.warning(warning);
    }
    let (clients, format) = connect(invocation, plan.format).await?;
    let scope = match &plan.scope {
        Some(scope) => scope.clone(),
        None => scm::airs::gateway::generate_workspace_scope_name(&plan.name).map_err(|_| {
            CliError::operational("AISEC_SDK_ERROR:The workspace scope name could not be generated")
        })?,
    };
    let mut body = plan.body.clone();
    body.insert("scope_name".into(), Value::String(scope.clone()));
    let request = GatewayWorkspaceCreateRequest::parse(Value::Object(body), Mode::Request)
        .map_err(|_| crate::gateway::body::schema_error("POST", "/workspaces"))?;
    let run = Provisioning {
        gateway: &clients.gateway,
        shown_scope: terminal_safe(&scope).into_owned(),
        scope,
        created: !plan.existing,
        existing: plan.existing,
    };
    if run.created {
        create_scope(invocation, &run, plan.description.as_deref()).await?;
    }
    let created = create_workspace(invocation, &run, &request).await?;
    bind_scope(invocation, &run, &created).await?;
    read_back_created(invocation, &run, &created, format).await
}

/// Step 1: `POST <iam>/scopes`, one attempt.
async fn create_scope(
    invocation: &mut Invocation,
    run: &Provisioning<'_>,
    description: Option<&str>,
) -> Result<(), CliError> {
    let shown_scope = &run.shown_scope;
    let input = serde_json::from_value::<IamScopeCreateInput>(json!({
        "name": run.scope,
        "description": description.unwrap_or_default(),
        "resources": [],
    }))
    .map_err(|_| crate::gateway::body::schema_error("POST", "/scopes"))?;
    let iam = run.gateway.iam_scopes();
    attempt(
        invocation,
        GwPlane::Iam,
        &Lines {
            unknown: format!("Outcome unknown: the IAM scope {shown_scope} may have been created."),
            unreadable: format!(
                "Outcome: the IAM scope {shown_scope} was created, but the response could not be read."
            ),
            hint: Some(Hints::scope_unknown(shown_scope)),
        },
        &InterruptContext::NothingChanged,
        &context(format!(
            "the IAM scope {shown_scope} may have been created (outcome unknown)"
        )),
        async || iam.create(&input, Some(&options()?)).await,
    )
    .await?;
    invocation.interrupt = Some(context(format!(
        "IAM scope {shown_scope} was created; the workspace was not"
    )));
    Ok(())
}

/// Step 2: `POST <admin>/workspaces`, one attempt; a refused or unsent create deletes the
/// scope step 1 created ([`rollback_scope`], choice 125).
async fn create_workspace(
    invocation: &mut Invocation,
    run: &Provisioning<'_>,
    request: &GatewayWorkspaceCreateRequest,
) -> Result<Created, CliError> {
    let shown_scope = &run.shown_scope;
    let workspaces = run.gateway.workspaces();
    let not_sent = if run.created {
        context(format!(
            "IAM scope {shown_scope} was created; the workspace was not"
        ))
    } else {
        InterruptContext::NothingChanged
    };
    let sent = if run.created {
        context(format!(
            "IAM scope {shown_scope} was created; the workspace may have been created (outcome unknown)"
        ))
    } else {
        context("the workspace may have been created (outcome unknown)".to_owned())
    };
    let answer = match crate::writes::attempt(async || {
        workspaces.create(request, Some(&options()?)).await
    })
    .await
    {
        Ok(answer) => answer,
        Err(error) => {
            if let Some(hint) = gateway::grant_hint(&error, GwPlane::Admin) {
                invocation.output.warning(&hint);
            }
            // The workspace was not created whenever the request was refused (any 3xx or
            // 4xx, whatever its kind: a redirect is a `Destination` error) or never sent (a
            // local failure); only an unknown outcome and an unreadable 2xx keep the scope.
            let rejected = error.kind() != scm::ErrorKind::Cancelled
                && matches!(
                    error.remote_outcome(),
                    scm::RemoteOutcome::Rejected | scm::RemoteOutcome::NotSent
                )
                && !matches!(
                    crate::writes::classify(&error),
                    crate::writes::Failure::Unreadable
                );
            let failure = crate::writes::in_contexts(
                crate::writes::describe(
                    &error,
                    &Lines {
                        unknown: format!(
                            "Outcome unknown: the workspace may have been created; IAM scope {shown_scope} is kept."
                        ),
                        unreadable: format!(
                            "Outcome: the workspace was created, but the response could not be read; IAM scope {shown_scope} is not bound to it yet."
                        ),
                        hint: Some(Hints::workspace_unknown(shown_scope, run.existing)),
                    },
                    &invocation.secrets,
                ),
                &not_sent,
                &sent,
            );
            if !(rejected && run.created) {
                return Err(failure);
            }
            return Err(rollback_scope(invocation, run, failure, not_sent).await);
        }
    };
    let answer = crate::json::model_value(&answer)?;
    let raw = |key: &str| {
        answer
            .get(key)
            .and_then(OValue::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let shown = |key: &str| terminal_safe(invocation.secrets.scrub(&raw(key))).into_owned();
    Ok(Created {
        slug: shown("slug"),
        id: shown("id"),
        raw_slug: raw("slug"),
        raw_id: raw("id"),
    })
}

/// After a rejected step 2: `DELETE <iam>/scopes/<scope>` once (never after a signal), its
/// outcome added to the step-2 `failure`.
async fn rollback_scope(
    invocation: &mut Invocation,
    run: &Provisioning<'_>,
    failure: CliError,
    not_sent: InterruptContext,
) -> CliError {
    let shown_scope = &run.shown_scope;
    if invocation.output.pending_signal().is_some() {
        return CliError::Interrupted(not_sent);
    }
    let iam = run.gateway.iam_scopes();
    let deleted =
        crate::writes::attempt(async || iam.delete(&run.scope, Some(&options()?)).await).await;
    let lines = match deleted {
        Ok(()) => vec![format!(
            "Outcome: the workspace was not created; IAM scope {shown_scope} was deleted again."
        )],
        Err(error) if error.kind() == scm::ErrorKind::Cancelled => {
            return CliError::Interrupted(context(format!(
                "the workspace was not created; IAM scope {shown_scope} may still be present"
            )));
        }
        Err(_) => vec![
            format!(
                "Outcome: the workspace was not created; IAM scope {shown_scope} was created and is still present."
            ),
            Hints::scope_still_present(shown_scope),
        ],
    };
    with_detail(failure, &lines)
}

/// Step 3: `PUT <iam>/scopes/<scope>` binding the new workspace, one attempt.
async fn bind_scope(
    invocation: &mut Invocation,
    run: &Provisioning<'_>,
    created: &Created,
) -> Result<(), CliError> {
    let (shown_scope, slug, id) = (&run.shown_scope, &created.slug, &created.id);
    let binding = context(format!(
        "the workspace {slug} was created; IAM scope {shown_scope} may not bind it yet"
    ));
    invocation.interrupt = Some(binding.clone());
    let iam = run.gateway.iam_scopes();
    let bound = crate::writes::attempt(async || {
        iam.bind_workspace(&run.scope, &created.raw_slug, Some(&options()?))
            .await
    })
    .await;
    let Err(error) = bound else {
        return Ok(());
    };
    let rejected = matches!(
        crate::writes::classify(&error),
        crate::writes::Failure::Rejected(_) | crate::writes::Failure::Local
    );
    let failure = crate::writes::in_contexts(
        crate::writes::describe(
            &error,
            &Lines {
                unknown: format!(
                    "Outcome unknown: IAM scope {shown_scope} may now bind workspace {slug} ({id})."
                ),
                unreadable: format!(
                    "Outcome: IAM scope {shown_scope} was bound to workspace {slug} ({id}), but the response could not be read."
                ),
                hint: Some(Hints::bind_unknown(shown_scope, slug)),
            },
            &invocation.secrets,
        ),
        &binding,
        &binding,
    );
    Err(if rejected {
        with_detail(
            failure,
            &[
                format!(
                    "The workspace {slug} ({id}) was created, but IAM scope {shown_scope} could not be bound to it."
                ),
                Hints::bind(shown_scope, slug),
            ],
        )
    } else {
        failure
    })
}

/// Step 4: the admin-plane read-back (one read), the `✓` and status lines and the record.
async fn read_back_created(
    invocation: &mut Invocation,
    run: &Provisioning<'_>,
    created: &Created,
    format: Format,
) -> Result<(), CliError> {
    let (shown_scope, slug, id) = (&run.shown_scope, &created.slug, &created.id);
    let bound_context = context(format!(
        "the workspace {slug} was created and bound to IAM scope {shown_scope}"
    ));
    invocation.interrupt = Some(bound_context.clone());
    let status = provision::provisioned_status(shown_scope, slug, run.created);
    let mut detail = match read_back(run.gateway, &created.raw_id).await {
        Ok(detail) => detail,
        Err(error) => {
            invocation
                .output
                .success(&format!("Workspace created: {id}"));
            invocation.output.status(&status);
            let failure = read_failure(invocation, &error, GwPlane::Admin, bound_context);
            return Err(with_detail(
                failure,
                &[format!(
                    "Outcome: the workspace {slug} ({id}) was created and bound to IAM scope {shown_scope}, but reading it back failed."
                )],
            ));
        }
    };
    invocation.committed = true;
    withhold::apply(&mut detail, &withhold::PLAIN, &invocation.secrets);
    let record = views::workspace_detail(&detail);
    let shown_id = record
        .get("id")
        .and_then(OValue::as_str)
        .map_or(id.clone(), |text| terminal_safe(text).into_owned());
    invocation
        .output
        .success(&format!("Workspace created: {shown_id}"));
    invocation.output.status(&status);
    views::render_workspace_detail(&mut invocation.output, &record, format)
}

/// `workspaces update <ref>` (§19.6).
pub async fn update(invocation: &mut Invocation, plan: &UpdatePlan) -> Result<(), CliError> {
    let (clients, format) = connect(invocation, plan.format).await?;
    let gateway = &clients.gateway;
    let (slug, row_id) = resolve_admin(invocation, gateway, &plan.reference).await?;
    let blocks = provision::replaced_blocks(&plan.body);
    if !blocks.is_empty() && !plan.force {
        let message = format!(
            "Replace the {} of workspace {}? The service replaces each named block whole.",
            crate::render::join_and(&blocks),
            plan.reference
        );
        if !wc::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let request = scm::airs::gateway::models::GatewayWorkspaceUpdateRequest::parse(
        Value::Object(plan.body.clone()),
        Mode::Request,
    )
    .map_err(|_| crate::gateway::body::schema_error("PUT", &format!("/workspaces/{slug}")))?;
    let shown_slug = terminal_safe(&slug).into_owned();
    let workspaces = gateway.workspaces();
    attempt(
        invocation,
        GwPlane::Admin,
        &Lines {
            unknown: format!("Outcome unknown: the workspace {shown_slug} may have been updated."),
            unreadable: format!(
                "Outcome: the workspace {shown_slug} was updated, but the response could not be read."
            ),
            hint: Some(format!(
                "Check it with '{PROGRAM} gateway workspaces get {shown_slug} --plane admin'."
            )),
        },
        &InterruptContext::NothingChanged,
        &InterruptContext::ChangeMayBeApplied,
        async || workspaces.update(&slug, &request, Some(&options()?)).await,
    )
    .await?;
    invocation.committed = true;
    let detail = match read_back(gateway, &slug).await {
        Ok(detail) => detail,
        Err(error) => {
            let id = row_id
                .as_deref()
                .map_or_else(|| shown_slug.clone(), |id| terminal_safe(id).into_owned());
            invocation
                .output
                .success(&format!("Workspace updated: {id}"));
            let failure = read_failure(
                invocation,
                &error,
                GwPlane::Admin,
                InterruptContext::ChangeSaved,
            );
            return Err(with_detail(
                failure,
                &[format!(
                    "Outcome: the workspace {shown_slug} was updated, but reading it back failed."
                )],
            ));
        }
    };
    let mut detail = detail;
    withhold::apply(&mut detail, &withhold::PLAIN, &invocation.secrets);
    let record = views::workspace_detail(&detail);
    let id = record
        .get("id")
        .and_then(OValue::as_str)
        .map(|text| terminal_safe(text).into_owned())
        .unwrap_or_default();
    invocation
        .output
        .success(&format!("Workspace updated: {id}"));
    views::render_workspace_detail(&mut invocation.output, &record, format)
}

/// `workspaces archive <ref>` and the hidden `delete <ref>` (§19.6).
pub async fn archive(
    invocation: &mut Invocation,
    reference: &str,
    force: bool,
    deprecated: bool,
) -> Result<(), CliError> {
    if deprecated {
        invocation.output.warning(provision::DELETE_DEPRECATED);
    }
    let (clients, _, _) = invocation
        .gateway_clients(None, None)
        .map_err(super::nothing_changed)?;
    if !force {
        let message = format!(
            "Archive workspace {reference}? (soft delete — the row remains under --status archived)"
        );
        if !wc::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    clients
        .authenticate(None, TOKEN_BUDGET)
        .await
        .map_err(super::nothing_changed)?;
    let gateway = &clients.gateway;
    let (slug, _) = resolve_admin(invocation, gateway, reference).await?;
    let shown = terminal_safe(reference).into_owned();
    let workspaces = gateway.workspaces();
    attempt(
        invocation,
        GwPlane::Admin,
        &Lines {
            unknown: format!("Outcome unknown: the workspace {shown} may have been archived."),
            unreadable: format!(
                "Outcome: the workspace {shown} was archived, but the response could not be read."
            ),
            hint: Some(format!(
                "Check it with '{PROGRAM} gateway workspaces list --plane admin --status archived'."
            )),
        },
        &InterruptContext::NothingChanged,
        &InterruptContext::ChangeMayBeApplied,
        async || workspaces.delete(&slug, Some(&options()?)).await,
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("Workspace archived: {shown}"));
    invocation.output.status(provision::ARCHIVE_STATUS);
    Ok(())
}

/// `scopes create --name <n>` (§19.7).
pub async fn scope_create(
    invocation: &mut Invocation,
    name: &str,
    description: Option<&str>,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (clients, format) = connect(invocation, explicit).await?;
    let input = serde_json::from_value::<IamScopeCreateInput>(
        json!({"name": name, "description": description.unwrap_or_default(), "resources": []}),
    )
    .map_err(|_| crate::gateway::body::schema_error("POST", "/scopes"))?;
    let shown = terminal_safe(name).into_owned();
    let iam = clients.gateway.iam_scopes();
    let answer = attempt(
        invocation,
        GwPlane::Iam,
        &Lines {
            unknown: format!("Outcome unknown: the IAM scope {shown} may have been created."),
            unreadable: format!(
                "Outcome: the IAM scope {shown} was created, but the response could not be read."
            ),
            hint: Some(format!(
                "Check it with '{PROGRAM} gateway scopes get {shown}'."
            )),
        },
        &InterruptContext::NothingChanged,
        &InterruptContext::ChangeMayBeApplied,
        async || iam.create(&input, Some(&options()?)).await,
    )
    .await?;
    invocation.committed = true;
    let mut scope = crate::json::model_value(&answer)?;
    withhold::apply(&mut scope, &withhold::PLAIN, &invocation.secrets);
    invocation
        .output
        .success(&format!("IAM scope created: {shown}"));
    invocation.output.status(provision::SCOPE_CREATED_STATUS);
    views::render_scope_detail(&mut invocation.output, &views::scope(&scope), format)
}

/// Whether `scope` binds workspace `slug`.
fn binds(scope: &OValue, slug: &str) -> bool {
    scope
        .get("resources")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .iter()
        .any(|resource| {
            resource.get("resource_type").and_then(OValue::as_str) == Some("workspace")
                && resource.get("resource_id").and_then(OValue::as_str) == Some(slug)
        })
}

/// `scopes bind <name> --workspace <ref>` (§19.7, D235, D236).
pub async fn scope_bind(
    invocation: &mut Invocation,
    name: &str,
    workspace: &str,
    explicit: Option<Format>,
) -> Result<(), CliError> {
    let (clients, format) = connect(invocation, explicit).await?;
    let gateway = &clients.gateway;
    let (slug, _) = resolve_admin(invocation, gateway, workspace).await?;
    let shown = terminal_safe(name).into_owned();
    let shown_slug = terminal_safe(&slug).into_owned();
    let iam = gateway.iam_scopes();
    let check = format!("Check it with '{PROGRAM} gateway scopes get {shown}'.");
    attempt(
        invocation,
        GwPlane::Iam,
        &Lines {
            unknown: format!("Outcome unknown: IAM scope {shown} may now bind workspace {shown_slug}."),
            unreadable: format!(
                "Outcome: IAM scope {shown} was updated to bind workspace {shown_slug}, but the response could not be read."
            ),
            hint: Some(check.clone()),
        },
        &InterruptContext::NothingChanged,
        &InterruptContext::ChangeMayBeApplied,
        async || iam.bind_workspace(name, &slug, Some(&options()?)).await,
    )
    .await?;
    invocation.committed = true;
    let read = match gateway
        .iam_scopes()
        .get(name, Some(&gateway::options(SINGLE_REQUEST_BUDGET)?))
        .await
    {
        Ok(scope) => scope,
        Err(error) => {
            let failure = read_failure(
                invocation,
                &error,
                GwPlane::Iam,
                InterruptContext::ChangeSaved,
            );
            return Err(with_detail(
                failure,
                &[format!(
                    "Outcome: IAM scope {shown} was updated, but reading it back failed."
                )],
            ));
        }
    };
    let mut scope = crate::json::model_value(&read)?;
    if !binds(&scope, &slug) {
        return Err(CliError::Operational(Failure {
            message: format!(
                "IAM scope {shown} was updated, but it does not bind workspace {shown_slug}; another change may have replaced it. {check}"
            ),
            status: None,
            details: Vec::new(),
        }));
    }
    withhold::apply(&mut scope, &withhold::PLAIN, &invocation.secrets);
    let count = scope
        .get("resources")
        .and_then(OValue::as_array)
        .map_or(0, <[OValue]>::len);
    invocation
        .output
        .success(&format!("IAM scope {shown} now binds {count} resource(s)"));
    views::render_scope_detail(&mut invocation.output, &views::scope(&scope), format)
}

/// `scopes delete|rm <name>` (§19.7, D236).
pub async fn scope_delete(
    invocation: &mut Invocation,
    name: &str,
    force: bool,
) -> Result<(), CliError> {
    let (clients, _) = connect(invocation, None).await?;
    let gateway = &clients.gateway;
    if !force {
        let scope = match gateway
            .iam_scopes()
            .get(name, Some(&gateway::options(SINGLE_REQUEST_BUDGET)?))
            .await
        {
            Ok(scope) => crate::json::model_value(&scope)?,
            Err(error) => {
                return Err(read_failure(
                    invocation,
                    &error,
                    GwPlane::Iam,
                    InterruptContext::NothingChanged,
                ));
            }
        };
        let mut scope = scope;
        withhold::apply(&mut scope, &withhold::PLAIN, &invocation.secrets);
        let message = provision::scope_delete_prompt(name, Some(&scope));
        if !wc::confirm(invocation, &message)? {
            return Ok(());
        }
    }
    let shown = terminal_safe(name).into_owned();
    let iam = gateway.iam_scopes();
    attempt(
        invocation,
        GwPlane::Iam,
        &Lines {
            unknown: format!("Outcome unknown: the IAM scope {shown} may have been deleted."),
            unreadable: format!(
                "Outcome: the IAM scope {shown} was deleted, but the response could not be read."
            ),
            hint: Some(format!(
                "Check it with '{PROGRAM} gateway scopes get {shown}'."
            )),
        },
        &InterruptContext::NothingChanged,
        &InterruptContext::ChangeMayBeApplied,
        async || iam.delete(name, Some(&options()?)).await,
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("IAM scope deleted: {shown}"));
    Ok(())
}
