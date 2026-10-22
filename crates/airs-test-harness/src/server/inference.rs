//! The gateway inference runtime routes of the fixture (DESIGN §10 M6e, chunk 4):
//! `POST <inference>/chat/completions`, `/responses` and `/embeddings` under
//! `/ai_gw/inference` (`gatewayInferenceEndpoint`). Each checks `x-portkey-api-key`
//! against [`fx::INFERENCE_KEY`] and refuses any `Authorization` header (401): the runtime
//! plane never sees OAuth. A body with `"stream": true` gets the route's SSE stream
//! ([`GatewayData::inference_streams`]), any other its JSON answer
//! ([`GatewayData::inference`]).

use serde_json::{Value, json};

use super::gateway::{GatewayData, Gw};
use super::plan::Planned;
use super::record::RecordedRequest;
use crate::fixtures::gateway as fx;

/// The inference prefix (`gatewayInferenceEndpoint = <base>/ai_gw/inference`).
pub const INFERENCE_PREFIX: &str = "/ai_gw/inference";

/// Classifies `POST <inference>/<path>`.
pub fn classify(method: &str, path: &str) -> Option<Gw> {
    if method != "POST" {
        return None;
    }
    match path.strip_prefix(INFERENCE_PREFIX)? {
        "/chat/completions" => Some(Gw::InferenceChat),
        "/responses" => Some(Gw::InferenceResponses),
        "/embeddings" => Some(Gw::InferenceEmbeddings),
        _ => None,
    }
}

/// The standard answers and streams.
pub fn seeded(data: &mut GatewayData) {
    data.inference = [
        (
            Gw::InferenceChat,
            fx::chat_completion("Hello from the fixture"),
        ),
        (
            Gw::InferenceResponses,
            fx::response("completed", "Hi there"),
        ),
        (Gw::InferenceEmbeddings, fx::embedding()),
    ]
    .into_iter()
    .collect();
    data.inference_streams = [
        (Gw::InferenceChat, fx::chat_stream()),
        (Gw::InferenceResponses, fx::response_stream()),
    ]
    .into_iter()
    .collect();
}

/// The answer of an inference route.
pub(crate) fn answer(data: &GatewayData, route: Gw, request: &RecordedRequest) -> Planned {
    if request.header("authorization").is_some()
        || request.header("x-portkey-api-key") != Some(fx::INFERENCE_KEY)
    {
        return Planned::json(401, &json!({"error": {"message": "Invalid API key"}}));
    }
    let streams = request
        .body_json()
        .is_some_and(|body| body.get("stream") == Some(&Value::Bool(true)));
    if streams && let Some(body) = data.inference_streams.get(&route) {
        return Planned::raw(200, "text/event-stream", body.clone());
    }
    match data.inference.get(&route) {
        Some(body) => Planned::json(200, body),
        None => Planned::json(404, &json!({"error": {"message": "Not found"}})),
    }
}
