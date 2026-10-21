//! `gateway inference chat|responses|embeddings [prompt]` (DESIGN §19.14): planning, the
//! request file, the runtime client (`clients::GatewayRuntime`) and the output, streamed
//! or whole.
//!
//! Billed model calls: never run by the live tier. One attempt (`RuntimeReplay::Never`),
//! `--timeout` the deadline of the whole request including the stream. The key is the
//! tenant's only (D240); the prompt and the model output reach stdout only.

use super::Invocation;
use crate::cli::{GwEmbeddingArgs, GwGenerateArgs, GwInferenceCommand, GwInferenceCommon};
use crate::clients::GatewayRuntime;
use crate::error::{CliError, InterruptContext, Operation, Phase, Plane, SdkContext};
use crate::gateway::inference::{self as inf, BodyFlags, Kind, Model, StreamText};
use crate::json::OValue;
use crate::output::Format;
use scm::airs::gateway::models::{
    GatewayChatCompletionRequest, GatewayEmbeddingRequest, GatewayInferenceInputCreateResponse,
};
use serde_json::{Map, Value};
use std::time::Duration;

/// Before the request leaves the CLI.
pub const NOTHING_SENT: &str = "nothing was sent";
/// After it was sent (choice 68).
pub const MAYBE_BILLED: &str =
    "the model request was sent and may have been processed (and billed)";

/// A validated `gateway inference` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferencePlan {
    pub kind: Kind,
    pub flags: BodyFlags,
    pub file: Option<std::ffi::OsString>,
    /// The admitted `--endpoint` (its URL text).
    pub endpoint: Option<String>,
    pub timeout: Duration,
    pub format: Option<Format>,
}

/// The checks of §19.14 (exit 2, before the tenant, in order).
pub fn plan(
    command: &GwInferenceCommand,
    format: Option<Format>,
) -> Result<InferencePlan, CliError> {
    let (kind, common, generate, embedding): (
        Kind,
        &GwInferenceCommon,
        Option<&GwGenerateArgs>,
        Option<&GwEmbeddingArgs>,
    ) = match command {
        GwInferenceCommand::Chat(args) => (Kind::Chat, &args.common, Some(args), None),
        GwInferenceCommand::Responses(args) => (Kind::Responses, &args.common, Some(args), None),
        GwInferenceCommand::Embeddings(args) => (Kind::Embeddings, &args.common, None, Some(args)),
    };
    if common.prompt.is_some() && common.file.is_some() {
        return Err(CliError::usage("Pass a prompt or --file, not both"));
    }
    if common.prompt.is_none() && common.file.is_none() {
        return Err(CliError::usage("A prompt or --file is required"));
    }
    let max_tokens = generate
        .and_then(|args| args.max_tokens.as_deref())
        .map(|value| inf::positive("--max-tokens", value))
        .transpose()?;
    let dimensions = embedding
        .and_then(|args| args.dimensions.as_deref())
        .map(|value| inf::positive("--dimensions", value))
        .transpose()?;
    let encoding = embedding.and_then(|args| args.encoding.clone());
    if let Some(encoding) = &encoding
        && !matches!(encoding.as_str(), "float" | "base64")
    {
        return Err(CliError::usage("--encoding must be float or base64"));
    }
    let timeout = inf::positive("--timeout", common.timeout.as_deref().unwrap_or("60000"))?;
    let stream = generate.is_some_and(|args| args.stream);
    if stream && format == Some(Format::Table) {
        return Err(CliError::usage(inf::STREAM_TABLE));
    }
    let endpoint = match &common.endpoint {
        Some(url) => {
            crate::clients::admit("gatewayInferenceEndpoint", Some(url), "")
                .map_err(|_| CliError::usage(inf::ENDPOINT_REFUSED))?;
            Some(url.clone())
        }
        None => None,
    };
    Ok(InferencePlan {
        kind,
        flags: BodyFlags {
            prompt: common.prompt.clone(),
            model: common.model.clone(),
            stream,
            max_tokens,
            dimensions,
            encoding,
        },
        file: common.file.clone(),
        endpoint,
        timeout: Duration::from_millis(timeout),
        format,
    })
}

/// The SDK request schema of `kind` (the D116 text naming the route).
fn validate(kind: Kind, body: &Map<String, Value>, usage: bool) -> Result<Typed, CliError> {
    let value = Value::Object(body.clone());
    let mode = scm::validation::Mode::Request;
    let parsed = match kind {
        Kind::Chat => GatewayChatCompletionRequest::parse(value, mode).map(Typed::Chat),
        Kind::Responses => {
            GatewayInferenceInputCreateResponse::parse(value, mode).map(Typed::Responses)
        }
        Kind::Embeddings => GatewayEmbeddingRequest::parse(value, mode).map(Typed::Embeddings),
    };
    parsed.map_err(|_| {
        let message = format!(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST {} did not match schema",
            kind.path()
        );
        if usage {
            CliError::usage(message)
        } else {
            CliError::operational(message)
        }
    })
}

/// The typed request of each call.
enum Typed {
    Chat(GatewayChatCompletionRequest),
    Responses(GatewayInferenceInputCreateResponse),
    Embeddings(GatewayEmbeddingRequest),
}

/// The failure of a runtime request: the §6 message (no provider text).
fn runtime_error(invocation: &Invocation, error: &scm::Error, timeout: Duration) -> CliError {
    if error.kind() == scm::ErrorKind::Cancelled {
        return CliError::Interrupted(InterruptContext::Context(MAYBE_BILLED.to_owned()));
    }
    crate::error::from_sdk(
        error,
        &SdkContext {
            plane: Plane::Management,
            phase: Phase::Api,
            operation: Operation::Read,
            timeout,
            secrets: &invocation.secrets,
        },
    )
}

/// The JSON text of a document after the model-output policy (§19.3, §19.14), C1 controls
/// escaped (choice 43); `pretty`: 2-space indent, else compact (one JSONL event).
fn json_text(invocation: &Invocation, value: &OValue, pretty: bool) -> Result<String, CliError> {
    let mut value = value.clone();
    crate::gateway::withhold::apply_model_output(&mut value, &invocation.secrets);
    if pretty {
        crate::json::json_text(&value)
    } else {
        Ok(crate::json::escape_c1(
            &crate::json::to_compact(&value).map_err(|_| {
                CliError::operational("AISEC_SDK_ERROR:Output could not be serialized as JSON")
            })?,
        ))
    }
}

/// The JSONL lines of `events` (one compact, withheld event per line).
fn events_text(invocation: &Invocation, events: Vec<OValue>) -> Result<String, CliError> {
    let mut out = String::new();
    for event in events {
        out.push_str(&json_text(invocation, &event, false)?);
        out.push('\n');
    }
    Ok(out)
}

/// Write `text` to stdout now (the stream's exception to §2.2's single commit). A closed
/// pipe ends the command quietly (`Ok(false)`, TS exits 0 on EPIPE).
fn emit(invocation: &mut Invocation, text: &str) -> Result<bool, CliError> {
    if text.is_empty() {
        return Ok(true);
    }
    invocation.output.data(text);
    match invocation.output.commit() {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(_) if invocation.output.pending_signal().is_some() => Err(CliError::Interrupted(
            InterruptContext::Context(MAYBE_BILLED.to_owned()),
        )),
        Err(_) => Err(CliError::operational(
            "AISEC_SDK_ERROR:Output could not be written to stdout",
        )),
    }
}

/// Run an inference plan.
pub async fn run(invocation: &mut Invocation, plan: &InferencePlan) -> Result<(), CliError> {
    invocation.interrupt = Some(InterruptContext::Context(NOTHING_SENT.to_owned()));
    // The request file (after the debug log, before the tenant).
    let file = plan.file.as_deref().map(inf::read_file).transpose()?;
    let (mut body, model) = inf::body(plan.kind, &plan.flags, file)?;
    if inf::streams(&body) && plan.format == Some(Format::Table) {
        return Err(CliError::usage(inf::STREAM_TABLE));
    }
    if model == Model::Given {
        validate(plan.kind, &body, true)?;
    }
    let context = invocation.load_tenant()?;
    let format =
        crate::output::resolve_tenant_default(plan.format, context.config.default_output());
    let streaming = inf::streams(&body);
    if streaming && format == Format::Table {
        return Err(CliError::operational(
            "The tenant's defaultOutput table cannot stream; pass --output pretty or --output json",
        ));
    }
    if model == Model::FromTenant {
        inf::with_tenant_model(
            &mut body,
            context.config.effective_str(plan.kind.model_key()),
        )?;
    }
    let typed = validate(plan.kind, &body, false)?;
    let endpoint = plan
        .endpoint
        .as_deref()
        .map(|url| crate::clients::admit("gatewayInferenceEndpoint", Some(url), ""))
        .transpose()?;
    let client = GatewayRuntime::build(
        &context.config,
        context.name(),
        endpoint.as_ref(),
        &invocation.session,
        &invocation.secrets,
        invocation.debug.as_ref(),
    )?;
    let options = scm::RequestOptions::with_timeout(plan.timeout)
        .map(scm::RequestOptions::without_response_defaults)
        .map_err(|_| CliError::usage("--timeout must be a positive integer"))?;
    let runtime = &client.runtime;
    // From here on the request may have left the CLI.
    invocation.interrupt = Some(InterruptContext::Context(MAYBE_BILLED.to_owned()));
    if streaming {
        return stream(invocation, plan, runtime, &typed, &options, format).await;
    }
    let answer = match &typed {
        Typed::Chat(request) => runtime
            .create_chat_completion(request, Some(&options))
            .await
            .and_then(|answer| crate::json::page_value(&answer)),
        Typed::Responses(request) => runtime
            .create_response(request, Some(&options))
            .await
            .and_then(|answer| crate::json::page_value(&answer)),
        Typed::Embeddings(request) => runtime
            .create_embedding(request, Some(&options))
            .await
            .and_then(|answer| crate::json::page_value(&answer)),
    };
    let answer = answer.map_err(|error| runtime_error(invocation, &error, plan.timeout))?;
    let text = match format {
        Format::Pretty if plan.kind != Kind::Embeddings => {
            format!(
                "{}\n",
                inf::printable(&invocation.secrets, &inf::text(&answer))
            )
        }
        Format::Table => {
            let mut shown = answer.clone();
            crate::gateway::withhold::apply_model_output(&mut shown, &invocation.secrets);
            crate::gateway::views::pairs_text(["Key", "Value"], &shown)
        }
        _ => format!("{}\n", json_text(invocation, &answer, true)?),
    };
    if !emit(invocation, &text)? {
        return Ok(());
    }
    match inf::failed_status(&answer, false) {
        Some(status) => Err(inf::generation_failed(&status)),
        None => Ok(()),
    }
}

/// The streamed answer: pretty text as it arrives (then `\n`), or one compact JSON event
/// per line. A `response.failed` / `response.incomplete` event ends it with exit 1 (no
/// final newline); the stream is closed before the command returns.
async fn stream(
    invocation: &mut Invocation,
    plan: &InferencePlan,
    runtime: &scm::airs::gateway::RuntimeClient,
    typed: &Typed,
    options: &scm::RequestOptions,
    format: Format,
) -> Result<(), CliError> {
    enum Events {
        Chat(
            scm::streaming::ContractStream<scm::airs::gateway::models::GatewayChatCompletionChunk>,
        ),
        Responses(
            scm::streaming::ContractStream<
                scm::airs::gateway::models::GatewayInferenceResponseStreamEvent,
            >,
        ),
    }
    let opened = match typed {
        Typed::Chat(request) => runtime
            .create_chat_completion_stream(request, Some(options))
            .await
            .map(Events::Chat),
        Typed::Responses(request) => runtime
            .create_response_stream(request, Some(options))
            .await
            .map(Events::Responses),
        Typed::Embeddings(_) => {
            return Err(CliError::operational(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /embeddings did not match schema",
            ));
        }
    };
    let mut events = opened.map_err(|error| runtime_error(invocation, &error, plan.timeout))?;
    let mut text = StreamText::default();
    let mut held = inf::StreamEvents::default();
    let result: Result<(), CliError> = async {
        loop {
            let next = match &mut events {
                Events::Chat(stream) => stream
                    .next()
                    .await
                    .and_then(|event| event.map(|e| crate::json::page_value(&e)).transpose()),
                Events::Responses(stream) => stream
                    .next()
                    .await
                    .and_then(|event| event.map(|e| crate::json::page_value(&e)).transpose()),
            };
            let event = match next {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => {
                    // The text so far stays on stdout.
                    let rest = if format == Format::Json {
                        events_text(invocation, held.finish())?
                    } else {
                        text.finish(&invocation.secrets)
                    };
                    let _ = emit(invocation, &rest);
                    return Err(runtime_error(invocation, &error, plan.timeout));
                }
            };
            let failed = inf::failed_status(&event, true);
            let out = if format == Format::Json {
                let mut ready = held.push(&invocation.secrets, event);
                if failed.is_some() {
                    ready.extend(held.finish());
                }
                events_text(invocation, ready)?
            } else {
                text.push(&invocation.secrets, &inf::text(&event))
            };
            if !emit(invocation, &out)? {
                return Ok(());
            }
            if let Some(status) = failed {
                if format != Format::Json {
                    emit(invocation, &text.finish(&invocation.secrets))?;
                }
                return Err(inf::generation_failed(&status));
            }
        }
        if format == Format::Json {
            let rest = events_text(invocation, held.finish())?;
            emit(invocation, &rest)?;
        } else {
            let rest = text.finish(&invocation.secrets);
            emit(invocation, &format!("{rest}\n"))?;
        }
        Ok(())
    }
    .await;
    match &mut events {
        Events::Chat(stream) => stream.close(),
        Events::Responses(stream) => stream.close(),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::FromArgMatches;

    fn plan_of(args: &[&str]) -> Result<crate::commands::Plan, CliError> {
        let mut full = vec!["airs", "gateway", "inference"];
        full.extend_from_slice(args);
        let matches = crate::cli::command().try_get_matches_from(&full).unwrap();
        crate::commands::plan(&Cli::from_arg_matches(&matches).unwrap())
    }

    fn usage(args: &[&str]) -> String {
        match plan_of(args) {
            Err(CliError::Usage(message)) => message,
            Err(other) => panic!("expected a usage error, got {other:?}"),
            Ok(_) => panic!("expected a usage error: {args:?}"),
        }
    }

    /// TS `aigateway-inference.spec.ts` "fails usage before sending a request", in the
    /// order of §19.14.
    #[test]
    fn checks_come_first() {
        for (args, message) in [
            (&["chat"][..], "A prompt or --file is required"),
            (
                &["chat", "hi", "--file", "r.json"],
                "Pass a prompt or --file, not both",
            ),
            (
                &["chat", "hello", "--max-tokens", "-1"],
                "--max-tokens must be a positive integer",
            ),
            (
                &["embeddings", "hello", "--dimensions", "0"],
                "--dimensions must be a positive integer",
            ),
            (
                &["embeddings", "hello", "--encoding", "invalid"],
                "--encoding must be float or base64",
            ),
            (
                &["chat", "hello", "--timeout", "NaN"],
                "--timeout must be a positive integer",
            ),
            (
                &["chat", "hello", "--stream", "--output", "table"],
                inf::STREAM_TABLE,
            ),
            (
                &["chat", "hello", "--endpoint", "http://gateway.test/v1"],
                inf::ENDPOINT_REFUSED,
            ),
            (
                &["chat", "hello", "--endpoint", "https://u:p@gateway.test/v1"],
                inf::ENDPOINT_REFUSED,
            ),
            (
                &[
                    "chat",
                    "hello",
                    "--endpoint",
                    "https://gateway.test/v1?key=x",
                ],
                inf::ENDPOINT_REFUSED,
            ),
            (
                &["chat", "hello", "--output", "yaml"],
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            ),
        ] {
            assert_eq!(usage(args), message, "{args:?}");
        }
        match plan_of(&[
            "responses",
            "hi",
            "--stream",
            "--max-tokens",
            "128",
            "--endpoint",
            "http://127.0.0.1:9/v1",
        ]) {
            Ok(crate::commands::Plan::Gateway(plan)) => match *plan {
                crate::commands::gateway::GwPlan::Inference(plan) => {
                    assert_eq!(plan.kind, Kind::Responses);
                    assert!(plan.flags.stream);
                    assert_eq!(plan.flags.max_tokens, Some(128));
                    assert_eq!(plan.timeout, Duration::from_millis(60_000));
                }
                _ => panic!("not an inference plan"),
            },
            _ => panic!("not a gateway plan"),
        }
    }
}
