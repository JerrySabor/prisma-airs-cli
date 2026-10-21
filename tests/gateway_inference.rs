//! Executable acceptance tests for `gateway inference chat|responses|embeddings`
//! (DESIGN §19.14, chunk 4): the TypeScript `tests/unit/cli/aigateway-inference.spec.ts`
//! cases (adjusted by D232, D240, D241, D50) and the Rust additions of §19.19 (the stream
//! with a secret split across deltas, the runtime-plane headers, one attempt, the debug
//! log, interruption).
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture's inference routes
//! (`/ai_gw/inference`, `x-portkey-api-key`-checked). The tenant's runtime key
//! (`FAKE-GW-INFERENCE-KEY`) is a config secret, so the runner's leak check forbids it on
//! every stream.

use std::time::Duration;

use airs_test_harness::fixtures::gateway as fx;
use airs_test_harness::{
    Cli, FixtureConfig, FixtureServer, Gw, Planned, RecordedRequest, Route, Run, RunOptions,
    Sandbox, debug_log, run, spawn,
};
use serde_json::{Value, json};

const TSG: &str = "100";
const CHAT: Gw = Gw::InferenceChat;
const RESPONSES: Gw = Gw::InferenceResponses;
const EMBEDDINGS: Gw = Gw::InferenceEmbeddings;

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seeded dataset and tenant `prod` with the runtime key and both default models.
fn fx() -> Fx {
    fx_with(|_| {})
}

fn fx_with(edit: impl FnOnce(&mut FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    server.seed_gateway();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
        config
            .set("aiGwInferenceApiKey", fx::INFERENCE_KEY)
            .set("aiGwInferenceModel", fx::INFERENCE_MODEL)
            .set("aiGwEmbeddingModel", fx::EMBEDDING_MODEL);
        edit(config);
    });
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

impl Fx {
    fn run_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let before = self.sandbox.snapshot();
        let mut full = vec!["gateway", "inference"];
        full.extend_from_slice(args);
        let out = run(&rust(), &self.sandbox, &full, options);
        self.sandbox.assert_unchanged(&before);
        self.server.assert_no_unknown_routes();
        out
    }

    fn inf(&self, args: &[&str]) -> Run {
        self.run_with(args, &RunOptions::new())
    }

    fn requests(&self, route: Gw) -> Vec<RecordedRequest> {
        self.server.requests_for(Route::Gateway(route))
    }

    /// Every request the run sent (any route).
    fn all(&self) -> Vec<RecordedRequest> {
        self.server.requests()
    }

    fn body(&self, route: Gw) -> Value {
        let requests = self.requests(route);
        assert_eq!(requests.len(), 1, "one request: {requests:?}");
        requests[0].body_json().unwrap()
    }

    fn data(&self, edit: impl FnOnce(&mut airs_test_harness::GatewayData)) {
        self.server.gateway(edit);
    }

    fn file(&self, name: &str, text: &str) -> String {
        self.sandbox
            .write_file(&format!("tmp/{name}"), text.as_bytes(), 0o600)
            .display()
            .to_string()
    }
}

fn usage_line(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
}

// ---------------------------------------------------------------------------
// The command tree
// ---------------------------------------------------------------------------

mod tree {
    use super::*;

    #[test]
    fn the_group_lists_its_three_leaves() {
        let f = fx();
        let help = f.inf(&["--help"]);
        help.assert_success();
        assert!(
            help.stdout
                .contains("Call the gateway runtime (separate API key; no SCM OAuth required)")
        );
        for leaf in ["chat", "embeddings", "responses"] {
            assert!(help.stdout.contains(&format!("  {leaf} ")), "{leaf}");
        }
        let group = f.inf(&[]);
        group.assert_code(2);
        assert!(group.stdout.is_empty());
        assert!(group.stderr.contains("Usage: airs gateway inference"));
        let chat = f.inf(&["chat", "--help"]);
        assert!(chat.stdout.contains(
            "Output format: pretty, table, json; streaming json emits one event per line (JSONL)"
        ));
        assert!(chat.stdout.contains("--max-tokens <n>") && chat.stdout.contains("--stream"));
        let embeddings = f.inf(&["embeddings", "--help"]);
        assert!(embeddings.stdout.contains("--dimensions <n>"));
        assert!(!embeddings.stdout.contains("--stream"));
        assert!(f.all().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Requests and output (TS aigateway-inference.spec.ts, GW§8.3–§8.4)
// ---------------------------------------------------------------------------

mod requests {
    use super::*;

    /// TS "prints the non-streaming SDK response as JSON without exposing credentials":
    /// the runtime plane only (no OAuth token, no `Authorization`, no `x-tsg-id`).
    #[test]
    fn chat_sends_the_runtime_key_only_and_prints_the_answer() {
        let f = fx();
        let out = f.inf(&["chat", "Hello there", "--output", "json"]);
        out.assert_success();
        assert_eq!(out.json(), fx::chat_completion("Hello from the fixture"));
        assert_eq!(out.stderr, "");
        let all = f.all();
        assert_eq!(all.len(), 1, "no token request: {all:?}");
        let request = &all[0];
        assert_eq!(request.line(), "POST /ai_gw/inference/chat/completions");
        assert_eq!(request.header("x-portkey-api-key"), Some(fx::INFERENCE_KEY));
        assert_eq!(request.header("authorization"), None);
        assert_eq!(request.header("x-tsg-id"), None);
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            request.body_json().unwrap(),
            json!({"messages": [{"content": "Hello there", "role": "user"}], "model": fx::INFERENCE_MODEL})
        );
    }

    #[test]
    fn pretty_prints_the_text_and_table_the_top_level() {
        let f = fx();
        let pretty = f.inf(&["chat", "hi"]);
        pretty.assert_success();
        assert_eq!(pretty.stdout, "Hello from the fixture\n");
        let table = f.inf(&["chat", "hi", "--output", "table"]);
        table.assert_success();
        let lines: Vec<&str> = table.stdout.lines().collect();
        assert_eq!(
            lines[0].split('│').map(str::trim).collect::<Vec<_>>(),
            ["Key", "Value"]
        );
        assert!(table.stdout.contains(" model "), "{}", table.stdout);
        assert!(table.stdout.contains("chat.completion"));
    }

    /// TS "uses the configured embedding model and numeric dimensions".
    #[test]
    fn embeddings_use_the_embedding_model_and_numeric_dimensions() {
        let f = fx();
        let out = f.inf(&[
            "embeddings",
            "hello",
            "--dimensions",
            "32",
            "--encoding",
            "base64",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            f.body(EMBEDDINGS),
            json!({"model": fx::EMBEDDING_MODEL, "input": "hello", "dimensions": 32, "encoding_format": "base64"})
        );
        assert_eq!(out.json(), fx::embedding());
        // Pretty prints the answer's JSON (TS).
        let pretty = f.inf(&["embeddings", "hello"]);
        assert_eq!(
            serde_json::from_str::<Value>(&pretty.stdout).unwrap(),
            fx::embedding()
        );
        assert!(
            pretty.stdout.starts_with("{\n  \"data\""),
            "{}",
            pretty.stdout
        );
    }

    /// TS "defaults ordinary Responses calls to non-persistent storage".
    #[test]
    fn responses_default_to_no_storage() {
        let f = fx();
        let out = f.inf(&["responses", "hello", "--max-tokens", "128"]);
        out.assert_success();
        assert_eq!(out.stdout, "Hi there\n");
        assert_eq!(
            f.body(RESPONSES),
            json!({"input": "hello", "model": fx::INFERENCE_MODEL, "max_output_tokens": 128, "store": false})
        );
    }

    /// TS "honors file input and explicit overrides without mutating stored settings".
    #[test]
    fn file_input_takes_flag_overrides() {
        let f = fx();
        let path = f.file(
            "request.json",
            r#"{"model": "@file/model", "messages": [{"role": "user", "content": "private"}], "temperature": 0}"#,
        );
        let out = f.inf(&[
            "chat",
            "--file",
            &path,
            "--model",
            "@flag/model",
            "--max-tokens",
            "64",
        ]);
        out.assert_success();
        assert_eq!(
            f.body(CHAT),
            json!({"messages": [{"content": "private", "role": "user"}], "model": "@flag/model", "temperature": 0, "max_completion_tokens": 64})
        );
        // The file's model comes before the tenant's.
        let f = fx();
        let path = f.file("r.json", r#"{"model": "@file/model", "input": "x"}"#);
        f.inf(&["responses", "--file", &path]).assert_success();
        assert_eq!(f.body(RESPONSES)["model"], "@file/model");
    }

    /// `--endpoint` overrides the tenant (the tenant may have none).
    #[test]
    fn the_endpoint_flag_overrides_the_tenant() {
        let closed = airs_test_harness::ClosedPort::new();
        let elsewhere = format!("http://127.0.0.1:{}/v1", closed.port());
        let f = fx_with(|config| {
            config.set("aiGwInferenceEndpoint", elsewhere.as_str());
        });
        let endpoint = f.server.url("/ai_gw/inference");
        let out = f.inf(&["chat", "hi", "--endpoint", &endpoint]);
        out.assert_success();
        assert_eq!(f.requests(CHAT).len(), 1);
    }

    /// The tenant's `defaultOutput` is honoured (TS).
    #[test]
    fn the_tenant_default_output_is_honoured() {
        let f = fx_with(|config| {
            config.set("defaultOutput", "json");
        });
        let out = f.inf(&["chat", "hi"]);
        out.assert_success();
        assert_eq!(out.json()["object"], "chat.completion");
    }

    /// D241: model text through `terminal_safe_lines` (line breaks and tabs kept); a
    /// registered secret in it is withheld.
    #[test]
    fn model_text_is_terminal_safe_and_withholds_secrets() {
        let f = fx();
        f.data(|data| {
            data.inference.insert(
                CHAT,
                fx::chat_completion(&format!(
                    "line one\n\tline two\u{1b}[31m red\u{7} key {}",
                    fx::INFERENCE_KEY
                )),
            );
        });
        let out = f.inf(&["chat", "hi"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            "line one\n\tline two\u{fffd}[31m red\u{fffd} key [withheld]\n"
        );
        let json = f.inf(&["chat", "hi", "--output", "json"]);
        assert!(!json.stdout.contains(fx::INFERENCE_KEY));
        assert!(json.stdout.contains("[withheld]"));
    }

    /// Model output is not a service resource: a logprobs `token` is a word of the answer,
    /// so the credential-name rule never withholds it and never registers it (which would
    /// withhold the answer's text that carries it), in json and table.
    #[test]
    fn logprob_tokens_keep_the_answer() {
        let f = fx();
        let mut answer = fx::chat_completion("Hello world, how are you?");
        answer["choices"][0]["logprobs"] = json!({
            "content": [
                {"token": "Hello", "logprob": -0.1, "bytes": null, "top_logprobs": []},
                {"token": " world", "logprob": -0.2, "bytes": null, "top_logprobs": []}
            ],
            "refusal": null
        });
        f.data(|data| {
            data.inference.insert(CHAT, answer);
        });
        let out = f.inf(&["chat", "hi", "--output", "json"]);
        out.assert_success();
        let json = out.json();
        assert_eq!(
            json["choices"][0]["message"]["content"],
            "Hello world, how are you?"
        );
        assert_eq!(
            json["choices"][0]["logprobs"]["content"][0]["token"],
            "Hello"
        );
        assert!(!out.stdout.contains("[withheld]"), "{}", out.stdout);
        let table = f.inf(&["chat", "hi", "--output", "table"]);
        table.assert_success();
        assert!(
            table.stdout.contains("Hello world, how are you?"),
            "{}",
            table.stdout
        );
        assert!(!table.stdout.contains("[withheld]"), "{}", table.stdout);
    }

    /// An answer whose status is `incomplete` prints its text, then fails (TS text).
    #[test]
    fn an_incomplete_answer_exits_1() {
        let f = fx();
        f.data(|data| {
            data.inference
                .insert(RESPONSES, fx::response("incomplete", "Partial"));
        });
        let out = f.inf(&["responses", "hi"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "Partial\n");
        assert_eq!(
            out.error_line().as_deref(),
            Some("Gateway generation ended with incomplete")
        );
    }
}

// ---------------------------------------------------------------------------
// Streams (TS "emits JSONL chunks", "an incomplete Responses lifecycle", choice 42)
// ---------------------------------------------------------------------------

mod streams {
    use super::*;

    #[test]
    fn chat_streams_text_and_jsonl() {
        let f = fx();
        let pretty = f.inf(&["chat", "hello", "--stream"]);
        pretty.assert_success();
        assert_eq!(pretty.stdout, "Hello\n");
        assert_eq!(f.body(CHAT)["stream"], true);
        let json = f.inf(&["chat", "hello", "--stream", "--output", "json"]);
        json.assert_success();
        let events: Vec<Value> = json
            .stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events, [fx::chat_chunk("Hel"), fx::chat_chunk("lo")]);
        assert!(!json.stdout.contains("[DONE]"));
    }

    #[test]
    fn responses_stream_until_the_terminal_event() {
        let f = fx();
        let pretty = f.inf(&["responses", "hello", "--stream"]);
        pretty.assert_success();
        assert_eq!(pretty.stdout, "Hi there\n");
        let json = f.inf(&["responses", "hello", "--stream", "--output", "json"]);
        json.assert_success();
        assert_eq!(json.stdout.lines().count(), 3);
        assert!(
            json.stdout
                .lines()
                .last()
                .unwrap()
                .contains("\"response.completed\"")
        );
    }

    /// TS "treats an incomplete Responses lifecycle as an operational failure": the text
    /// so far without the final newline, then the TS text.
    #[test]
    fn a_failed_lifecycle_exits_1_after_the_text() {
        for (kind, format) in [
            ("response.failed", "pretty"),
            ("response.incomplete", "json"),
        ] {
            let f = fx();
            f.data(|data| {
                data.inference_streams.insert(
                    RESPONSES,
                    fx::sse(
                        &[fx::response_delta("Hi", 1), fx::response_terminal(kind, 2)],
                        false,
                    ),
                );
            });
            let out = f.inf(&["responses", "hello", "--stream", "--output", format]);
            out.assert_code(1);
            if format == "pretty" {
                assert_eq!(out.stdout, "Hi");
            } else {
                assert_eq!(out.stdout.lines().count(), 2);
            }
            assert_eq!(
                out.error_line(),
                Some(format!("Gateway generation ended with {kind}"))
            );
        }
    }

    /// Choice 42: a secret split across two deltas never reaches stdout.
    #[test]
    fn a_secret_split_across_deltas_is_withheld() {
        let f = fx();
        let (head, tail) = fx::INFERENCE_KEY.split_at(9);
        f.data(|data| {
            data.inference_streams.insert(
                CHAT,
                fx::sse(
                    &[
                        fx::chat_chunk(&format!("key: {head}")),
                        fx::chat_chunk(&format!("{tail} done")),
                    ],
                    true,
                ),
            );
        });
        let out = f.inf(&["chat", "hello", "--stream"]);
        out.assert_success();
        assert_eq!(out.stdout, "key: [withheld] done\n");
    }

    /// The JSON variant (§19.14): an event whose text ends with the start of a secret is
    /// held until the next one; when they complete the secret, both texts are withheld,
    /// so no line, and no join of the deltas, carries any part of it.
    #[test]
    fn a_secret_split_across_json_events_is_withheld() {
        let f = fx();
        let (head, tail) = fx::INFERENCE_KEY.split_at(9);
        f.data(|data| {
            data.inference_streams.insert(
                CHAT,
                fx::sse(
                    &[
                        fx::chat_chunk("Hello "),
                        fx::chat_chunk(&format!("key: {head}")),
                        fx::chat_chunk(&format!("{tail} done")),
                        fx::chat_chunk(" bye"),
                    ],
                    true,
                ),
            );
        });
        let out = f.inf(&["chat", "hello", "--stream", "--output", "json"]);
        out.assert_success();
        assert!(!out.stdout.contains(head), "{}", out.stdout);
        assert!(!out.stdout.contains(tail), "{}", out.stdout);
        let deltas: Vec<String> = out
            .stdout
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter_map(|event| {
                event["choices"][0]["delta"]["content"]
                    .as_str()
                    .map(str::to_owned)
            })
            .collect();
        assert_eq!(deltas, ["Hello ", "[withheld]", "[withheld]", " bye"]);
    }

    /// TS "cleans up a failed stream": an event that fails its schema ends the command
    /// with the §6 message after the text so far.
    #[test]
    fn a_broken_stream_fails_after_its_text() {
        let f = fx();
        let mut body = fx::sse(&[fx::chat_chunk("one")], false);
        body.extend_from_slice(b"data: {\"choices\": 5}\n\n");
        f.data(|data| {
            data.inference_streams.insert(CHAT, body);
        });
        let out = f.inf(&["chat", "hello", "--stream"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "one");
        assert!(out.error_line().is_some(), "{}", out.stderr);
    }

    /// Choice 41: a tenant `defaultOutput` of table cannot stream (exit 1, no request).
    #[test]
    fn a_table_default_cannot_stream() {
        let f = fx_with(|config| {
            config.set("defaultOutput", "table");
        });
        let out = f.inf(&["chat", "hello", "--stream"]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "The tenant's defaultOutput table cannot stream; pass --output pretty or --output json"
            )
        );
        assert!(f.all().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Checks (D232; TS "fails usage before sending a request", "rejects unreadable, malformed
// and nonobject files")
// ---------------------------------------------------------------------------

mod checks {
    use super::*;

    #[test]
    fn argument_checks_send_nothing() {
        let f = fx();
        for (args, message) in [
            (&["chat"][..], "A prompt or --file is required"),
            (
                &["chat", "hello", "--max-tokens", "-1"],
                "--max-tokens must be a positive integer",
            ),
            (
                &["chat", "hello", "--stream", "--output", "table"],
                "Streaming supports --output pretty or json (JSONL), not table",
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
                &["chat", "hello", "--model", " "],
                "Set --model, the request model, or gatewayInferenceModel in the tenant (gatewayEmbeddingModel for embeddings)",
            ),
            (
                &["chat", "hello", "--endpoint", "http://gateway.test/v1"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Inference endpoint requires HTTPS (HTTP is allowed only on loopback), without credentials, query or fragment",
            ),
            (
                &["chat", "hello", "--output", "yaml"],
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            ),
        ] {
            let out = f.inf(args);
            out.assert_code(2);
            assert_eq!(out.stderr, usage_line(message), "{args:?}");
            assert!(!out.stderr.contains("gateway.test"));
        }
        assert!(f.all().is_empty());
    }

    #[test]
    fn request_files_are_checked_without_echoing_them() {
        let f = fx();
        for (text, message) in [
            (
                "{secret-invalid",
                "--file must name a readable JSON request file",
            ),
            ("[]", "--file must contain a JSON object"),
            ("null", "--file must contain a JSON object"),
            ("42", "--file must contain a JSON object"),
        ] {
            let path = f.file("bad.json", text);
            let out = f.inf(&["chat", "--file", &path]);
            out.assert_code(2);
            assert_eq!(out.stderr, usage_line(message), "{text}");
        }
        let missing = f.sandbox.tmp().join("missing.json").display().to_string();
        let out = f.inf(&["chat", "--file", &missing]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_line("--file must name a readable JSON request file")
        );
        // A file whose model is known is checked against the request schema before the
        // tenant (exit 2, the D116 text).
        let path = f.file("schema.json", r#"{"model": "m", "messages": "not a list"}"#);
        let out = f.inf(&["chat", "--file", &path]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_line(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /chat/completions did not match schema"
            )
        );
        assert!(f.all().is_empty());
    }

    /// The runtime configuration comes from the tenant only (exit 1, no request).
    #[test]
    fn missing_configuration_is_named() {
        let f = fx_with(|config| {
            config.remove("aiGwInferenceApiKey");
        });
        let out = f.inf(&["chat", "hi"]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "gatewayInferenceApiKey is not configured; set it with 'airs tenant set prod gatewayInferenceApiKey' (secrets prompt hidden, or use --stdin)"
            )
        );
        let f = fx_with(|config| {
            config.remove("aiGwInferenceModel");
        });
        let out = f.inf(&["chat", "hi"]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "Set --model, the request model, or gatewayInferenceModel in the tenant (gatewayEmbeddingModel for embeddings)"
            )
        );
        assert!(f.all().is_empty());
    }

    /// D240: `PANW_AI_GW_INFERENCE_*` are never read.
    #[test]
    fn d240_the_environment_is_never_read() {
        let f = fx_with(|config| {
            config.remove("aiGwInferenceApiKey");
        });
        let options = RunOptions::new()
            .env("PANW_AI_GW_INFERENCE_API_KEY", fx::INFERENCE_KEY)
            .env(
                "PANW_AI_GW_INFERENCE_ENDPOINT",
                f.server.url("/ai_gw/inference"),
            )
            .secret(fx::INFERENCE_KEY);
        let out = f.run_with(&["chat", "hi"], &options);
        out.assert_code(1);
        assert!(
            out.error_line()
                .unwrap()
                .starts_with("gatewayInferenceApiKey is not configured")
        );
        assert!(f.all().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Failures (one attempt, §6 messages)
// ---------------------------------------------------------------------------

mod failures {
    use super::*;

    /// One attempt (`RuntimeReplay::Never`): a 500 and a 401 are reported at once with the
    /// §6 message, never the provider's text.
    #[test]
    fn errors_are_sent_once_without_provider_text() {
        for status in [500, 401, 429] {
            let f = fx();
            f.server.set_default(
                Route::Gateway(CHAT),
                Planned::json(status, &json!({"error": {"message": "PROVIDER-TEXT"}}))
                    .with_retry_after(0),
            );
            let out = f.inf(&["chat", "hi"]);
            out.assert_code(1);
            assert_eq!(f.requests(CHAT).len(), 1, "{status}");
            assert_eq!(out.http_status(), Some(status));
            assert!(!out.stderr.contains("PROVIDER-TEXT"), "{}", out.stderr);
            assert_eq!(out.stdout, "");
        }
    }

    /// `--timeout` bounds the whole request.
    #[test]
    fn the_timeout_bounds_the_request() {
        let f = fx();
        f.server.set_default(Route::Gateway(CHAT), Planned::hang());
        let out = f.inf(&["chat", "hi", "--timeout", "300"]);
        out.assert_code(1);
        assert!(out.elapsed < Duration::from_secs(20));
        assert_eq!(f.requests(CHAT).len(), 1);
        assert!(out.error_line().is_some());
    }
}

// ---------------------------------------------------------------------------
// The debug log (D64: status and headers only)
// ---------------------------------------------------------------------------

mod debug {
    use super::*;

    #[test]
    fn the_log_records_no_key_prompt_or_output() {
        for (args, operation) in [
            (vec!["chat", "PROMPT-CANARY"], "airs.gateway.chat"),
            (
                vec!["chat", "PROMPT-CANARY", "--stream"],
                "airs.gateway.chat_stream",
            ),
            (vec!["responses", "PROMPT-CANARY"], "gateway.response"),
            (
                vec!["responses", "PROMPT-CANARY", "--stream"],
                "gateway.response_stream",
            ),
            (vec!["embeddings", "PROMPT-CANARY"], "gateway.embedding"),
        ] {
            let f = fx();
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec!["--debug", "gateway", "inference"];
            full.extend(args.iter().copied());
            let before = f.sandbox.snapshot();
            let out = run(
                &rust(),
                &f.sandbox,
                &full,
                &RunOptions::new().env("XDG_STATE_HOME", &state),
            );
            f.sandbox.assert_unchanged(&before);
            out.assert_success();
            let (path, records) = debug_log::only_log(&f.sandbox);
            let text = std::fs::read_to_string(&path).unwrap();
            // The runtime key header is recorded masked, never its value.
            assert!(text.contains("\"x-portkey-api-key\":\"***\""), "{args:?}");
            for needle in ["PROMPT-CANARY", "Hello", "Hi there", fx::INFERENCE_KEY] {
                assert!(
                    !text
                        .to_ascii_lowercase()
                        .contains(&needle.to_ascii_lowercase()),
                    "{args:?}: {needle}"
                );
            }
            let found: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .collect();
            assert_eq!(found, [operation], "{args:?}");
            debug_log::assert_logs_clean(
                &f.sandbox,
                &f.server,
                &[debug_log::log_dir(&f.sandbox)],
                &[],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Interruption (D241)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    /// A signal once the request was sent names the possible billing (exit 130/143; TS
    /// exits 1 with `Inference interrupted`).
    #[test]
    fn a_signal_after_the_request_names_the_billing() {
        for (signal, code) in [("INT", 130), ("TERM", 143)] {
            let f = fx();
            f.server.push_once(Route::Gateway(CHAT), Planned::hang());
            let running = spawn(
                &rust(),
                &f.sandbox,
                &["gateway", "inference", "chat", "hi"],
                &RunOptions::new().expect_signal(),
            );
            assert!(
                f.server
                    .wait_for_route(Route::Gateway(CHAT), 1, Duration::from_secs(10))
            );
            running.send_signal(signal);
            let out = running.wait();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "\n  ✗ Error: Interrupted; the model request was sent and may have been processed (and billed)\n\n"
            );
        }
    }
}
