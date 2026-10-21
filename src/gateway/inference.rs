//! `gateway inference chat|responses|embeddings` (DESIGN §19.14): the request body
//! (TS `inferenceBody`), the text of an answer or event (TS `responseText`), the terminal
//! statuses and the stream writer that keeps a secret split across two deltas withheld.
//!
//! Nothing here reads the environment (D240, G48): the endpoint is `--endpoint` or the
//! tenant's, the key the tenant's.

use crate::error::{CliError, SecretSet};
use crate::json::OValue;
use serde_json::{Map, Value};

/// The three runtime calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Chat,
    Responses,
    Embeddings,
}

impl Kind {
    /// The request path below the endpoint.
    pub fn path(self) -> &'static str {
        match self {
            Kind::Chat => "/chat/completions",
            Kind::Responses => "/responses",
            Kind::Embeddings => "/embeddings",
        }
    }

    /// The tenant key of the default model.
    pub fn model_key(self) -> &'static str {
        match self {
            Kind::Embeddings => "gatewayEmbeddingModel",
            _ => "gatewayInferenceModel",
        }
    }
}

/// The model error (TS: `… or the matching inference model config`).
pub const MODEL_MISSING: &str = "Set --model, the request model, or gatewayInferenceModel in the tenant (gatewayEmbeddingModel for embeddings)";
/// TS `inferenceBody`'s file texts (no content is echoed).
pub const FILE_UNREADABLE: &str = "--file must name a readable JSON request file";
pub const FILE_NOT_OBJECT: &str = "--file must contain a JSON object";
/// The `--endpoint` refusal (TS SDK text; the value is never echoed).
pub const ENDPOINT_REFUSED: &str = "AISEC_USER_REQUEST_PAYLOAD_ERROR:Inference endpoint requires HTTPS (HTTP is allowed only on loopback), without credentials, query or fragment";
/// The streaming format refusal (TS's yaml text, for table; D50).
pub const STREAM_TABLE: &str = "Streaming supports --output pretty or json (JSONL), not table";

/// The flags that shape the body (validated during planning).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BodyFlags {
    pub prompt: Option<String>,
    pub model: Option<String>,
    pub stream: bool,
    pub max_tokens: Option<u64>,
    pub dimensions: Option<u64>,
    pub encoding: Option<String>,
}

/// A positive safe integer in decimal digits, else `<flag> must be a positive integer`
/// (TS text).
pub fn positive(flag: &str, value: &str) -> Result<u64, CliError> {
    let refused = || CliError::usage(format!("{flag} must be a positive integer"));
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refused());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| (1..=9_007_199_254_740_991).contains(n))
        .ok_or_else(refused)
}

/// Read `--file`: at most 1 MiB, UTF-8, one JSON object (TS texts, exit 2, nothing of
/// the file or the OS error echoed).
pub fn read_file(path: &std::ffi::OsStr) -> Result<Map<String, Value>, CliError> {
    let text = crate::files::read_text(path, crate::files::CONFIG_LIMIT)
        .map_err(|_| CliError::usage(FILE_UNREADABLE))?;
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(CliError::usage(FILE_NOT_OBJECT)),
        Err(_) => Err(CliError::usage(FILE_UNREADABLE)),
    }
}

/// What the body knows about its model before the tenant is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Model {
    /// `--model` or the file's `model` (a non-blank string).
    Given,
    /// Neither: the tenant's default model is needed.
    FromTenant,
}

/// TS `inferenceBody` without the tenant default: the prompt or the file base, `model`
/// from `--model` or the file, `stream`, the token limit, `dimensions`,
/// `encoding_format`, and `store: false` for `responses` unless the body sets `store`.
/// A `--model` or file `model` that is not a non-blank string is [`MODEL_MISSING`]
/// (exit 2, TS: `??` keeps it and then refuses it).
pub fn body(
    kind: Kind,
    flags: &BodyFlags,
    file: Option<Map<String, Value>>,
) -> Result<(Map<String, Value>, Model), CliError> {
    let mut body = match (file, &flags.prompt) {
        (Some(file), _) => file,
        (None, Some(prompt)) => {
            let mut body = Map::new();
            match kind {
                Kind::Chat => {
                    body.insert(
                        "messages".into(),
                        serde_json::json!([{"role": "user", "content": prompt}]),
                    );
                }
                _ => {
                    body.insert("input".into(), Value::String(prompt.clone()));
                }
            }
            body
        }
        (None, None) => Map::new(),
    };
    let model = match (&flags.model, body.get("model")) {
        (Some(model), _) => Some(Value::String(model.clone())),
        (None, None | Some(Value::Null)) => None,
        (None, Some(model)) => Some(model.clone()),
    };
    let known = match model {
        Some(Value::String(model)) if !crate::tenant::config::js_trim(&model).is_empty() => {
            body.insert("model".into(), Value::String(model));
            Model::Given
        }
        Some(_) => return Err(CliError::usage(MODEL_MISSING)),
        None => Model::FromTenant,
    };
    finish(kind, flags, &mut body);
    Ok((body, known))
}

/// The members after `model` (TS order of assignment).
fn finish(kind: Kind, flags: &BodyFlags, body: &mut Map<String, Value>) {
    if flags.stream {
        body.insert("stream".into(), Value::Bool(true));
    }
    if let Some(tokens) = flags.max_tokens {
        let key = match kind {
            Kind::Responses => "max_output_tokens",
            _ => "max_completion_tokens",
        };
        body.insert(key.into(), Value::from(tokens));
    }
    if let Some(dimensions) = flags.dimensions {
        body.insert("dimensions".into(), Value::from(dimensions));
    }
    if let Some(encoding) = &flags.encoding {
        body.insert("encoding_format".into(), Value::String(encoding.clone()));
    }
    if kind == Kind::Responses && !body.contains_key("store") {
        body.insert("store".into(), Value::Bool(false));
    }
}

/// The tenant's default model, set into a body whose model came from neither `--model`
/// nor the file (a blank or absent tenant value is [`MODEL_MISSING`], exit 1).
pub fn with_tenant_model(
    body: &mut Map<String, Value>,
    model: Option<&str>,
) -> Result<(), CliError> {
    match model.filter(|model| !crate::tenant::config::js_trim(model).is_empty()) {
        Some(model) => {
            body.insert("model".into(), Value::String(model.to_owned()));
            Ok(())
        }
        None => Err(CliError::operational(MODEL_MISSING)),
    }
}

/// Whether the body asks for a stream (`"stream": true`, from `--stream` or the file).
pub fn streams(body: &Map<String, Value>) -> bool {
    body.get("stream") == Some(&Value::Bool(true))
}

/// The text of a member as JavaScript joins it (`undefined`/`null` empty).
fn joined(value: Option<&OValue>) -> String {
    match value {
        Some(OValue::String(text)) => text.clone(),
        Some(OValue::Number(number)) => crate::render::js_json_number(number),
        Some(OValue::Bool(flag)) => flag.to_string(),
        _ => String::new(),
    }
}

/// TS `responseText`: a `response.output_text.delta` event's `delta`, the joined
/// `choices[].message.content` (else `delta.content`), or the joined `output_text` parts
/// of `output[].content[]`; otherwise empty.
pub fn text(value: &OValue) -> String {
    if !matches!(value, OValue::Object(_)) {
        return String::new();
    }
    if value.get("type").and_then(OValue::as_str) == Some("response.output_text.delta")
        && let Some(OValue::String(delta)) = value.get("delta")
    {
        return delta.clone();
    }
    if let Some(choices) = value.get("choices").and_then(OValue::as_array) {
        return choices
            .iter()
            .map(|choice| {
                let content = |key: &str| {
                    choice
                        .get(key)
                        .and_then(|part| part.get("content"))
                        .filter(|content| !matches!(content, OValue::Null))
                };
                joined(content("message").or_else(|| content("delta")))
            })
            .collect();
    }
    if let Some(output) = value.get("output").and_then(OValue::as_array) {
        return output
            .iter()
            .filter_map(|item| item.get("content").and_then(OValue::as_array))
            .flatten()
            .filter(|part| part.get("type").and_then(OValue::as_str) == Some("output_text"))
            .map(|part| joined(part.get("text")))
            .collect();
    }
    String::new()
}

/// The status that ends a generation as a failure: an answer whose `status` is
/// `failed` or `incomplete`, or a `response.failed` / `response.incomplete` event.
pub fn failed_status(value: &OValue, stream: bool) -> Option<String> {
    let (key, failed): (&str, [&str; 2]) = if stream {
        ("type", ["response.failed", "response.incomplete"])
    } else {
        ("status", ["failed", "incomplete"])
    };
    value
        .get(key)
        .and_then(OValue::as_str)
        .filter(|status| failed.contains(status))
        .map(str::to_owned)
}

/// `Gateway generation ended with <status>` (TS text, exit 1).
pub fn generation_failed(status: &str) -> CliError {
    CliError::operational(format!("Gateway generation ended with {status}"))
}

/// Pretty model text as it is printed: secrets withheld in place, then
/// `terminal_safe_lines` (line breaks and tabs kept, D241).
pub fn printable(secrets: &SecretSet, text: &str) -> String {
    crate::output::terminal_safe_lines(&secrets.redact(text)).into_owned()
}

/// The pretty stream writer (choice 42): each delta is written as it arrives, except the
/// last `longest secret form − 1` bytes (and a trailing CR), held until the next delta or
/// the end, so a secret split across two deltas is still withheld. A registered form
/// that straddles the cut is held whole.
#[derive(Default)]
pub struct StreamText {
    pending: String,
}

impl StreamText {
    /// Add `delta`; the text that can be written now.
    pub fn push(&mut self, secrets: &SecretSet, delta: &str) -> String {
        self.pending.push_str(delta);
        let forms = secrets.snapshot();
        let hold = forms
            .iter()
            .map(String::len)
            .max()
            .unwrap_or(0)
            .saturating_sub(1);
        let mut cut = self.pending.len().saturating_sub(hold);
        loop {
            while !self.pending.is_char_boundary(cut) {
                cut -= 1;
            }
            let straddling = forms
                .iter()
                .filter(|form| !form.is_empty())
                .flat_map(|form| {
                    self.pending
                        .match_indices(form.as_str())
                        .map(|(start, found)| (start, start + found.len()))
                        .collect::<Vec<_>>()
                })
                .filter(|(start, end)| *start < cut && *end > cut)
                .map(|(start, _)| start)
                .min();
            match straddling {
                Some(start) => cut = start,
                None => break,
            }
        }
        if self.pending[..cut].ends_with('\r') {
            cut -= 1;
        }
        let ready: String = self.pending.drain(..cut).collect();
        printable(secrets, &ready)
    }

    /// The text still held, at the end of the stream.
    pub fn finish(&mut self, secrets: &SecretSet) -> String {
        let rest = std::mem::take(&mut self.pending);
        printable(secrets, &rest)
    }
}

/// The JSON stream writer (§19.14): events are printed whole, one per line, but an event
/// is held while the text of the held events ends with the start of a registered secret
/// form, so a secret split across two deltas is still withheld. When the held text
/// carries a whole form, the text of every held event is withheld before they are
/// released (each event is also withheld on its own when printed).
#[derive(Default)]
pub struct StreamEvents {
    held: Vec<OValue>,
    text: String,
}

impl StreamEvents {
    /// Add `event`; the events that can be printed now, in order.
    pub fn push(&mut self, secrets: &SecretSet, event: OValue) -> Vec<OValue> {
        self.text.push_str(&text(&event));
        self.held.push(event);
        let forms: Vec<String> = secrets
            .snapshot()
            .into_iter()
            .filter(|form| !form.is_empty())
            .collect();
        if forms.iter().any(|form| self.text.contains(form.as_str())) {
            return self.release(true);
        }
        let open = forms.iter().any(|form| {
            form.char_indices()
                .skip(1)
                .any(|(at, _)| self.text.ends_with(&form[..at]))
        });
        if open {
            Vec::new()
        } else {
            self.release(false)
        }
    }

    /// The events still held, at the end of the stream (or before a failure).
    pub fn finish(&mut self) -> Vec<OValue> {
        self.release(false)
    }

    fn release(&mut self, withhold: bool) -> Vec<OValue> {
        self.text.clear();
        let mut events = std::mem::take(&mut self.held);
        if withhold {
            events.iter_mut().for_each(withhold_text);
        }
        events
    }
}

/// Replace the model text of a stream event (the members [`text`] reads) by `[withheld]`.
fn withhold_text(event: &mut OValue) {
    let withheld = || OValue::String(crate::error::WITHHELD.to_owned());
    let OValue::Object(entries) = event else {
        return;
    };
    let delta_event = entries.iter().any(|(name, value)| {
        name == "type" && value.as_str() == Some("response.output_text.delta")
    });
    for (name, member) in entries.iter_mut() {
        match (name.as_str(), member) {
            ("delta", member @ OValue::String(_)) if delta_event => *member = withheld(),
            ("choices", OValue::Array(choices)) => {
                for choice in choices {
                    let OValue::Object(parts) = choice else {
                        continue;
                    };
                    for (part, value) in parts.iter_mut() {
                        if (part == "delta" || part == "message")
                            && let OValue::Object(fields) = value
                        {
                            for (field, content) in fields.iter_mut() {
                                if field == "content" && !matches!(content, OValue::Null) {
                                    *content = withheld();
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn flags(prompt: Option<&str>) -> BodyFlags {
        BodyFlags {
            prompt: prompt.map(str::to_owned),
            ..BodyFlags::default()
        }
    }

    fn v(text: &str) -> OValue {
        crate::json::parse(text).unwrap()
    }

    fn usage(result: Result<impl std::fmt::Debug, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    /// TS `aigateway-inference.spec.ts`: "honors file input and explicit overrides"; the
    /// prompt bodies (GW§8.3) and `store: false`.
    #[test]
    fn bodies_follow_typescript() {
        let (body, model) = body(Kind::Chat, &flags(Some("Hello there")), None).unwrap();
        assert_eq!(model, Model::FromTenant);
        assert_eq!(
            Value::Object(body),
            json!({"messages": [{"content": "Hello there", "role": "user"}]})
        );
        let mut responses = flags(Some("Hi"));
        responses.model = Some("openai__gpt-x".into());
        responses.max_tokens = Some(128);
        responses.stream = true;
        let (body, model) = super::body(Kind::Responses, &responses, None).unwrap();
        assert_eq!(model, Model::Given);
        assert_eq!(
            Value::Object(body),
            json!({"input": "Hi", "model": "openai__gpt-x", "stream": true, "max_output_tokens": 128, "store": false})
        );
        let mut embed = flags(Some("text"));
        embed.dimensions = Some(32);
        embed.encoding = Some("base64".into());
        let (mut body, _) = super::body(Kind::Embeddings, &embed, None).unwrap();
        with_tenant_model(&mut body, Some("@provider/embed")).unwrap();
        assert_eq!(
            Value::Object(body),
            json!({"model": "@provider/embed", "input": "text", "dimensions": 32, "encoding_format": "base64"})
        );
        let file = json!({"model": "@file/model", "messages": [{"role": "user", "content": "private"}], "temperature": 0, "store": null});
        let mut overrides = flags(None);
        overrides.model = Some("@flag/model".into());
        overrides.max_tokens = Some(64);
        let (body, _) = super::body(
            Kind::Chat,
            &overrides,
            Some(file.as_object().unwrap().clone()),
        )
        .unwrap();
        assert_eq!(body["model"], "@flag/model");
        assert_eq!(body["temperature"], 0);
        assert_eq!(body["max_completion_tokens"], 64);
        // The file's model is used before the tenant's; a stored `store` is kept.
        let (body, model) = super::body(
            Kind::Responses,
            &flags(None),
            Some(
                json!({"model": "@file/model", "input": "x", "store": null})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .unwrap();
        assert_eq!(
            (body["model"].clone(), model),
            (json!("@file/model"), Model::Given)
        );
        assert_eq!(body["store"], Value::Null);
    }

    #[test]
    fn models_must_be_non_blank_strings() {
        let mut blank = flags(Some("x"));
        blank.model = Some("  ".into());
        assert_eq!(usage(body(Kind::Chat, &blank, None)), MODEL_MISSING);
        let file = json!({"model": 5}).as_object().unwrap().clone();
        assert_eq!(
            usage(body(Kind::Chat, &flags(None), Some(file))),
            MODEL_MISSING
        );
        let mut body = Map::new();
        assert_eq!(
            with_tenant_model(&mut body, Some(" ")).unwrap_err(),
            CliError::operational(MODEL_MISSING)
        );
        assert!(with_tenant_model(&mut body, None).is_err());
    }

    #[test]
    fn integers_are_positive_and_safe() {
        assert_eq!(positive("--max-tokens", "64").unwrap(), 64);
        for value in ["0", "-1", "1.5", "NaN", "", " 5", "9007199254740992"] {
            assert_eq!(
                usage(positive("--max-tokens", value)),
                "--max-tokens must be a positive integer",
                "{value}"
            );
        }
    }

    /// TS `responseText` over the three answers and the stream events.
    #[test]
    fn texts_are_extracted_as_typescript_does() {
        assert_eq!(
            text(&v(
                r#"{"choices":[{"message":{"content":"READY"}},{"message":{"content":null},"delta":{"content":"!"}}]}"#
            )),
            "READY!"
        );
        assert_eq!(
            text(&v(r#"{"choices":[{"delta":{"content":"one"}}]}"#)),
            "one"
        );
        assert_eq!(
            text(&v(
                r#"{"status":"completed","output":[{"content":[{"type":"output_text","text":"Hi"},{"type":"refusal","refusal":"x"},{"type":"output_text","text":" there"}]},{"type":"reasoning"}]}"#
            )),
            "Hi there"
        );
        assert_eq!(
            text(&v(r#"{"type":"response.output_text.delta","delta":"Hel"}"#)),
            "Hel"
        );
        assert_eq!(text(&v(r#"{"type":"response.completed"}"#)), "");
        assert_eq!(text(&v(r#"{"data":[{"embedding":[1,2]}]}"#)), "");
        assert_eq!(
            failed_status(&v(r#"{"status":"incomplete"}"#), false).as_deref(),
            Some("incomplete")
        );
        assert_eq!(
            failed_status(&v(r#"{"type":"response.failed"}"#), true).as_deref(),
            Some("response.failed")
        );
        assert_eq!(failed_status(&v(r#"{"status":"completed"}"#), false), None);
    }

    /// Choice 42: a secret split across two deltas is withheld; control characters are
    /// replaced, line breaks and tabs kept; a CR LF pair split across deltas stays a pair.
    #[test]
    fn streamed_text_withholds_a_split_secret() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-GW-INFERENCE-KEY");
        let mut stream = StreamText::default();
        let mut out = String::new();
        for delta in [
            "Your key is FAKE-GW-",
            "INFERENCE-KEY, ok\r",
            "\nnext\tline\u{1b}[2J",
        ] {
            out.push_str(&stream.push(&secrets, delta));
        }
        out.push_str(&stream.finish(&secrets));
        assert_eq!(out, "Your key is [withheld], ok\r\nnext\tline\u{fffd}[2J");
        let empty = SecretSet::default();
        let mut stream = StreamText::default();
        assert_eq!(stream.push(&empty, "Hello"), "Hello", "nothing to hold");
        assert_eq!(stream.finish(&empty), "");
        assert_eq!(
            printable(&secrets, "a FAKE-GW-INFERENCE-KEY b\n"),
            "a [withheld] b\n"
        );
    }

    /// The JSON stream holds an event whose text ends with the start of a secret form and
    /// withholds the held text when the next event completes it.
    #[test]
    fn streamed_events_withhold_a_split_secret() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-GW-INFERENCE-KEY");
        let chunk = |text: &str| {
            v(&json!({"choices": [{"index": 0, "delta": {"content": text}}]}).to_string())
        };
        let mut stream = StreamEvents::default();
        assert_eq!(
            stream.push(&secrets, chunk("Hello ")).len(),
            1,
            "nothing to hold"
        );
        assert!(
            stream.push(&secrets, chunk("key: FAKE-GW-I")).is_empty(),
            "held"
        );
        let out = stream.push(&secrets, chunk("NFERENCE-KEY done"));
        assert_eq!(out.len(), 2);
        for event in &out {
            assert_eq!(text(event), "[withheld]");
        }
        assert!(stream.push(&secrets, chunk("key: FAKE")).is_empty());
        let out = stream.push(&secrets, chunk("book"));
        assert_eq!(
            out.iter().map(text).collect::<String>(),
            "key: FAKEbook",
            "a false start"
        );
        assert!(stream.push(&secrets, chunk("FAKE-GW")).is_empty());
        assert_eq!(
            stream.finish().iter().map(text).collect::<String>(),
            "FAKE-GW"
        );
        let delta = v(r#"{"type":"response.output_text.delta","delta":"FAKE-GW-INF"}"#);
        assert!(stream.push(&secrets, delta).is_empty());
        let out = stream.push(
            &secrets,
            v(r#"{"type":"response.output_text.delta","delta":"ERENCE-KEY"}"#),
        );
        assert_eq!(
            out.iter().map(text).collect::<String>(),
            "[withheld][withheld]"
        );
    }
}
