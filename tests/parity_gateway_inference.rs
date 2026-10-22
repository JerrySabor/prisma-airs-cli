//! TS-vs-Rust parity for `gateway inference chat|responses|embeddings` (DESIGN §19.14;
//! TS `aigateway inference`, renamed, D227).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript reference,
//! each on a fresh [`FixtureServer`] seeded with the gateway dataset (its inference routes
//! under `/ai_gw/inference`) and a fresh [`Sandbox`] whose tenant carries the runtime key
//! and both default models. The `parity` tests compare exit codes, stdout (text bytes, or
//! JSON as JSON, D35), the request bodies as JSON and the runtime headers; the
//! `divergence` tests pin both sides of each §12 row of §19.14. Model calls are billed:
//! nothing here leaves the loopback fixture, and the live tier never runs inference.

use std::time::Duration;

use airs_test_harness::fixtures::gateway as fx;
use airs_test_harness::{
    Cli, FixtureConfig, FixtureServer, GatewayData, Gw, Planned, RecordedRequest, Route, Run,
    RunOptions, Sandbox, assert_json_semantic_eq, require_ts, run, spawn,
};
use serde_json::{Value, json};

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
}

impl Side {
    /// The inference requests (no other route may be reached).
    fn inference(&self) -> Vec<&RecordedRequest> {
        self.requests
            .iter()
            .filter(|request| matches!(request.route, Route::Gateway(gw) if gw.is_inference()))
            .collect()
    }

    fn body(&self) -> Value {
        let requests = self.inference();
        assert_eq!(requests.len(), 1, "{:?}", self.run);
        requests[0].body_json().unwrap()
    }
}

/// A scenario: the dataset edit, the tenant edit, a planned answer and files written
/// into the sandbox before the run.
#[derive(Clone, Copy)]
struct Setup<'a> {
    seed: &'a dyn Fn(&mut GatewayData),
    tenant: &'a dyn Fn(&mut FixtureConfig),
    plan: &'a dyn Fn(&FixtureServer),
    files: &'a dyn Fn(&Sandbox),
}

const PLAIN: Setup<'static> = Setup {
    seed: &|_| {},
    tenant: &|_| {},
    plan: &|_| {},
    files: &|_| {},
};

fn exec_with(cli: &Cli, args: &[&str], setup: Setup<'_>, options: &RunOptions) -> Side {
    let server = FixtureServer::start();
    server.seed_gateway();
    server.gateway(|data| (setup.seed)(data));
    (setup.plan)(&server);
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
        config
            .set("aiGwInferenceApiKey", fx::INFERENCE_KEY)
            .set("aiGwInferenceModel", fx::INFERENCE_MODEL)
            .set("aiGwEmbeddingModel", fx::EMBEDDING_MODEL);
        (setup.tenant)(config);
    });
    sandbox.register(&[&tenant], Some("prod"));
    (setup.files)(&sandbox);
    let mut full = vec![
        if cli.is_ts() { "aigateway" } else { "gateway" },
        "inference",
    ];
    full.extend_from_slice(args);
    let out = run(cli, &sandbox, &full, options);
    server.assert_no_unknown_routes();
    Side {
        run: out,
        requests: server.requests(),
    }
}

fn exec(cli: &Cli, args: &[&str], setup: Setup<'_>) -> Side {
    exec_with(cli, args, setup, &RunOptions::new())
}

fn sides_with(name: &str, args: &[&str], setup: Setup<'_>) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((exec(&rust(), args, setup), exec(&ts, args, setup)))
}

fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_with(name, args, PLAIN)
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// The runtime plane on both: the key header, JSON, no OAuth, no `x-tsg-id`.
fn assert_runtime_headers(side: &Side) {
    for request in side.inference() {
        assert_eq!(request.header("x-portkey-api-key"), Some(fx::INFERENCE_KEY));
        assert_eq!(request.header("authorization"), None);
        assert_eq!(request.header("x-tsg-id"), None);
        assert!(
            request
                .header("content-type")
                .is_some_and(|value| value.starts_with("application/json"))
        );
    }
    assert!(
        side.requests
            .iter()
            .all(|request| request.route != Route::Token),
        "no OAuth token"
    );
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// TS `aigateway-inference.spec.ts` (requests and outputs): the bodies are equal as
    /// JSON (D35), text output byte for byte, JSON output as JSON.
    #[test]
    fn requests_and_output_match_typescript() {
        for (args, json_out) in [
            (vec!["chat", "Hello there"], false),
            (vec!["chat", "Hello there", "--output", "json"], true),
            (
                vec![
                    "chat",
                    "hi",
                    "--max-tokens",
                    "50",
                    "--model",
                    "openai__gpt-y",
                ],
                false,
            ),
            (vec!["responses", "Hi", "--max-tokens", "128"], false),
            (vec!["responses", "Hi", "--output", "json"], true),
            (
                vec![
                    "embeddings",
                    "text",
                    "--dimensions",
                    "2",
                    "--encoding",
                    "float",
                    "--output",
                    "json",
                ],
                true,
            ),
            (vec!["embeddings", "text"], true),
        ] {
            let Some((r, t)) = sides("requests_and_output_match_typescript", &args) else {
                return;
            };
            assert_eq!(r.run.code, 0, "{args:?}{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{args:?}{}", context(&r, &t));
            assert_json_semantic_eq(&r.body(), &t.body());
            if json_out {
                assert_json_semantic_eq(&r.run.json(), &t.run.json());
            } else {
                assert_eq!(r.run.stdout, t.run.stdout, "{args:?}");
            }
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}");
            assert_runtime_headers(&r);
            assert_runtime_headers(&t);
            assert_eq!(r.inference()[0].line(), t.inference()[0].line());
        }
    }

    #[test]
    fn file_input_matches_typescript() {
        let request = |sandbox: &Sandbox| {
            std::fs::write(
                sandbox.cwd().join("request.json"),
                r#"{"model": "@file/model", "messages": [{"role": "user", "content": "private"}], "temperature": 0}"#,
            )
            .unwrap();
        };
        let setup = Setup {
            files: &request,
            ..PLAIN
        };
        let Some((r, t)) = sides_with(
            "file_input_matches_typescript",
            &[
                "chat",
                "--file",
                "request.json",
                "--model",
                "@flag/model",
                "--max-tokens",
                "64",
            ],
            setup,
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (0, 0), "{}", context(&r, &t));
        assert_json_semantic_eq(&r.body(), &t.body());
        assert_eq!(r.body()["model"], "@flag/model");
        // A missing file: both refuse with TS's text (exit 2) and send nothing.
        let Some((r, t)) = sides(
            "file_input_matches_typescript",
            &["chat", "--file", "missing.json"],
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (2, 2));
        for side in [&r, &t] {
            assert!(
                side.run
                    .stderr
                    .contains("✗ --file must name a readable JSON request file"),
                "{}",
                side.run.stderr
            );
            assert!(side.inference().is_empty());
        }
    }

    /// Streams: the pretty text byte for byte, the JSONL events as JSON line by line.
    #[test]
    fn streams_match_typescript() {
        for args in [
            vec!["chat", "hello", "--stream"],
            vec!["chat", "hello", "--stream", "--output", "json"],
            vec!["responses", "hello", "--stream"],
            vec!["responses", "hello", "--stream", "--output", "json"],
        ] {
            let Some((r, t)) = sides("streams_match_typescript", &args) else {
                return;
            };
            assert_eq!(
                (r.run.code, t.run.code),
                (0, 0),
                "{args:?}{}",
                context(&r, &t)
            );
            assert_json_semantic_eq(&r.body(), &t.body());
            if args.contains(&"json") {
                let lines = |side: &Side| -> Vec<Value> {
                    side.run
                        .stdout
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect()
                };
                let (rl, tl) = (lines(&r), lines(&t));
                assert_eq!(rl.len(), tl.len(), "{args:?}");
                for (a, b) in rl.iter().zip(&tl) {
                    assert_json_semantic_eq(a, b);
                }
            } else {
                assert_eq!(r.run.stdout, t.run.stdout, "{args:?}");
            }
        }
    }

    /// A failed lifecycle and an incomplete answer: the text, then TS's error text, exit 1
    /// on both.
    #[test]
    fn failed_generations_match_typescript() {
        let failed = |data: &mut GatewayData| {
            data.inference_streams.insert(
                Gw::InferenceResponses,
                fx::sse(
                    &[
                        fx::response_delta("Hi", 1),
                        fx::response_terminal("response.failed", 2),
                    ],
                    false,
                ),
            );
            data.inference.insert(
                Gw::InferenceResponses,
                fx::response("incomplete", "Partial"),
            );
        };
        let setup = Setup {
            seed: &failed,
            ..PLAIN
        };
        for args in [vec!["responses", "hi", "--stream"], vec!["responses", "hi"]] {
            let Some((r, t)) = sides_with("failed_generations_match_typescript", &args, setup)
            else {
                return;
            };
            assert_eq!(
                (r.run.code, t.run.code),
                (1, 1),
                "{args:?}{}",
                context(&r, &t)
            );
            assert_eq!(r.run.stdout, t.run.stdout, "{args:?}");
            assert_eq!(r.run.error_line(), t.run.error_line(), "{args:?}");
        }
    }

    /// The usage checks both CLIs share (TS texts, exit 2, nothing sent).
    #[test]
    fn shared_checks_match_typescript() {
        for (args, message) in [
            (vec!["chat"], "A prompt or --file is required"),
            (
                vec!["chat", "hi", "--file", "x.json"],
                "Pass a prompt or --file, not both",
            ),
            (
                vec!["chat", "hello", "--max-tokens", "-1"],
                "--max-tokens must be a positive integer",
            ),
            (
                vec!["chat", "hello", "--timeout", "NaN"],
                "--timeout must be a positive integer",
            ),
            (
                vec!["chat", "hello", "--endpoint", "http://gateway.test/v1"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Inference endpoint requires HTTPS (HTTP is allowed only on loopback), without credentials, query or fragment",
            ),
        ] {
            let Some((r, t)) = sides("shared_checks_match_typescript", &args) else {
                return;
            };
            assert_eq!(
                (r.run.code, t.run.code),
                (2, 2),
                "{args:?}{}",
                context(&r, &t)
            );
            for side in [&r, &t] {
                assert!(
                    side.run.stderr.contains(&format!("✗ {message}")),
                    "{} {args:?}: {}",
                    side.run.cli,
                    side.run.stderr
                );
                assert!(side.inference().is_empty());
            }
        }
    }

    /// Help: TS's descriptions and options, the Rust `--output` line (D50).
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        for leaf in ["chat", "responses", "embeddings"] {
            let help = |cli: &Cli| exec(cli, &[leaf, "--help"], PLAIN).run.stdout;
            let (r, t) = (squash(&help(&rust())), squash(&help(&ts)));
            let mut options = vec![
                (
                    "--endpoint <url>",
                    "Runtime base URL including /v1; overrides config",
                ),
                (
                    "--file <path>",
                    "JSON request file (mutually exclusive with prompt)",
                ),
                (
                    "--model <id>",
                    "Provider-prefixed model ID; overrides request file and config",
                ),
                (
                    "--timeout <ms>",
                    "Total deadline including streaming, in milliseconds (default: \"60000\")",
                ),
            ];
            if leaf == "embeddings" {
                options.push(("--dimensions <n>", "Embedding dimensions"));
                options.push(("--encoding <format>", "float or base64"));
            } else {
                options.push(("--max-tokens <n>", "Maximum completion/output tokens"));
                options.push((
                    "--stream",
                    "Stream text (pretty) or validated events (json/JSONL)",
                ));
            }
            for (flag, description) in options {
                for (side, text) in [("rust", &r), ("ts", &t)] {
                    assert!(
                        text.contains(&format!("{flag} {description}")),
                        "{side} {leaf} {flag}: {text}"
                    );
                }
            }
            assert!(r.contains(
                "--output <format> Output format: pretty, table, json; streaming json emits one event per line (JSONL)"
            ));
            let about = if leaf == "embeddings" {
                "Create embeddings through your runtime gateway"
            } else {
                "Generate a model response through your runtime gateway"
            };
            assert!(r.contains(about) && t.contains(about), "{leaf}");
        }
        let group = |cli: &Cli| squash(&exec(cli, &["--help"], PLAIN).run.stdout);
        let about = "Call the gateway runtime (separate API key; no SCM OAuth required)";
        assert!(group(&rust()).contains(about) && group(&ts).contains(about));
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D240: the environment trap. With a tenant that has no runtime key, TypeScript reads
    /// `PANW_AI_GW_INFERENCE_API_KEY` (and would read the endpoint variable) and sends the
    /// request; airs-cli-rs never reads them and refuses before any request.
    #[test]
    fn d240_the_environment_is_never_read() {
        let Some(ts) = require_ts("d240_the_environment_is_never_read") else {
            return;
        };
        let keyless = |config: &mut FixtureConfig| {
            config.remove("aiGwInferenceApiKey");
        };
        let setup = Setup {
            tenant: &keyless,
            ..PLAIN
        };
        let trap = FixtureServer::start();
        let options = RunOptions::new()
            .env("PANW_AI_GW_INFERENCE_API_KEY", fx::INFERENCE_KEY)
            .env(
                "PANW_AI_GW_INFERENCE_ENDPOINT",
                trap.url("/ai_gw/inference"),
            );
        let r = exec_with(
            &rust(),
            &["chat", "hi"],
            setup,
            &options.clone().secret(fx::INFERENCE_KEY),
        );
        let t = exec_with(&ts, &["chat", "hi"], setup, &options.allow_secret_output());
        r.run.assert_code(1);
        assert!(
            r.run
                .error_line()
                .unwrap()
                .starts_with("gatewayInferenceApiKey is not configured"),
            "{}",
            r.run.stderr
        );
        assert!(r.requests.is_empty());
        t.run.assert_success();
        let sent = t.inference();
        assert_eq!(
            sent.len(),
            1,
            "TS sent the request with the environment key"
        );
        assert_eq!(sent[0].header("x-portkey-api-key"), Some(fx::INFERENCE_KEY));
        assert_eq!(
            trap.request_count(),
            0,
            "the tenant's endpoint wins on both"
        );
    }

    /// D241, D11, D52: model text through `terminal_safe_lines` (TS raw); a provider error
    /// is the §6 message (TS prints the provider's text); `table` renders (TS refuses it);
    /// a signal exits 130 with the billing context (TS exit 1, `Inference interrupted`).
    #[test]
    fn d241_text_errors_formats_and_interruption() {
        let raw = |data: &mut GatewayData| {
            data.inference.insert(
                Gw::InferenceChat,
                fx::chat_completion("line one\n\tred\u{1b}[31m bell\u{7}"),
            );
        };
        let setup = Setup {
            seed: &raw,
            ..PLAIN
        };
        let Some((r, t)) = sides_with("d241_text", &["chat", "hi"], setup) else {
            return;
        };
        assert_eq!(r.run.stdout, "line one\n\tred\u{fffd}[31m bell\u{fffd}\n");
        assert_eq!(t.run.stdout, "line one\n\tred\u{1b}[31m bell\u{7}\n");
        let provider = |server: &FixtureServer| {
            server.set_default(
                Route::Gateway(Gw::InferenceChat),
                Planned::json(
                    400,
                    &json!({"error": {"message": "PROVIDER-TEXT model refused"}}),
                ),
            );
        };
        let setup = Setup {
            plan: &provider,
            ..PLAIN
        };
        let Some((r, t)) = sides_with("d241_errors", &["chat", "hi"], setup) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert!(!r.run.stderr.contains("PROVIDER-TEXT"), "{}", r.run.stderr);
        assert!(t.run.stderr.contains("PROVIDER-TEXT"), "{}", t.run.stderr);
        assert_eq!(r.run.http_status(), Some(400));
        let Some((r, t)) = sides("d241_table", &["chat", "hi", "--output", "table"]) else {
            return;
        };
        r.run.assert_success();
        assert!(r.run.stdout.contains("Key") && r.run.stdout.contains("chat.completion"));
        assert_ne!(t.run.code, 0, "TS offers pretty, json and yaml only");
        assert!(t.inference().is_empty());
        // Interruption once the request was sent.
        let Some(ts) = require_ts("d241_interrupt") else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_gateway();
            server.push_once(Route::Gateway(Gw::InferenceChat), Planned::hang());
            let sandbox = Sandbox::new();
            let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
                config
                    .set("aiGwInferenceApiKey", fx::INFERENCE_KEY)
                    .set("aiGwInferenceModel", fx::INFERENCE_MODEL);
            });
            sandbox.register(&[&tenant], Some("prod"));
            let group = if cli.is_ts() { "aigateway" } else { "gateway" };
            let running = spawn(
                &cli,
                &sandbox,
                &[group, "inference", "chat", "hi"],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Gateway(Gw::InferenceChat),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal("INT");
            let out = running.wait();
            if cli.is_ts() {
                out.assert_code(1);
                assert!(
                    out.stderr.contains("Inference interrupted"),
                    "{}",
                    out.stderr
                );
            } else {
                out.assert_code(130);
                assert_eq!(
                    out.stderr,
                    "\n  ✗ Error: Interrupted; the model request was sent and may have been processed (and billed)\n\n"
                );
            }
        }
    }

    /// D50: `yaml` is a usage error (TS renders it; its streaming refusal names yaml, the
    /// Rust one table).
    #[test]
    fn d50_inference_formats() {
        let Some((r, t)) = sides("d50_inference", &["chat", "hi", "--output", "yaml"]) else {
            return;
        };
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Invalid output format 'yaml'. Expected: pretty, table, json\n\n"
        );
        t.run.assert_success();
        assert!(t.run.stdout.contains("object: chat.completion"));
        let Some((r, t)) = sides(
            "d50_stream",
            &["chat", "hi", "--stream", "--output", "yaml"],
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (2, 2));
        assert!(
            t.run
                .stderr
                .contains("Streaming supports --output pretty or json (JSONL), not yaml")
        );
        let r = exec(
            &rust(),
            &["chat", "hi", "--stream", "--output", "table"],
            PLAIN,
        );
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Streaming supports --output pretty or json (JSONL), not table\n\n"
        );
    }

    /// D232, D233: the checks run before the tenant (TS reads it first), and a request that
    /// fails the schema names the route without echoing values (TS: the zod path and code).
    #[test]
    fn d232_d233_inference_checks_come_before_the_tenant() {
        let Some(ts) = require_ts("d232_inference") else {
            return;
        };
        // No tenant at all: airs-cli-rs refuses the encoding first (exit 2), TS fails at the
        // tenant (exit 1).
        for cli in [rust(), ts.clone()] {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            let group = if cli.is_ts() { "aigateway" } else { "gateway" };
            let out = run(
                &cli,
                &sandbox,
                &[
                    group,
                    "inference",
                    "embeddings",
                    "hi",
                    "--encoding",
                    "invalid",
                ],
                &RunOptions::new(),
            );
            if cli.is_ts() {
                out.assert_code(1);
            } else {
                out.assert_code(2);
                assert_eq!(out.stderr, "\n  ✗ --encoding must be float or base64\n\n");
            }
            assert_eq!(server.request_count(), 0);
        }
        // TS checks the encoding with the request schema after the tenant.
        let t = exec(&ts, &["embeddings", "hi", "--encoding", "invalid"], PLAIN);
        t.run.assert_code(2);
        assert!(
            t.run
                .stderr
                .contains("Invalid inference request: encoding_format: invalid_union"),
            "{}",
            t.run.stderr
        );
        // D233: a request file that fails the schema: the route, never a value.
        let bad = |sandbox: &Sandbox| {
            std::fs::write(
                sandbox.cwd().join("bad.json"),
                r#"{"model": "m", "messages": "PRIVATE-VALUE"}"#,
            )
            .unwrap();
        };
        let setup = Setup {
            files: &bad,
            ..PLAIN
        };
        let Some((r, t)) = sides_with("d233_inference", &["chat", "--file", "bad.json"], setup)
        else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (2, 2));
        assert_eq!(
            r.run.stderr,
            "\n  ✗ AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /chat/completions did not match schema\n\n"
        );
        assert!(
            t.run
                .stderr
                .contains("Invalid inference request: messages: "),
            "{}",
            t.run.stderr
        );
        assert!(!r.run.stderr.contains("PRIVATE-VALUE"));
        assert!(r.inference().is_empty() && t.inference().is_empty());
    }

    /// D178 (G40): an unfamiliar `finish_reason` is printed; TypeScript fails the answer's
    /// schema.
    #[test]
    fn d178_an_unfamiliar_finish_reason_is_printed() {
        let paused = |data: &mut GatewayData| {
            let mut answer = fx::chat_completion("Hello");
            answer["choices"][0]["finish_reason"] = json!("paused");
            data.inference.insert(Gw::InferenceChat, answer);
        };
        let setup = Setup {
            seed: &paused,
            ..PLAIN
        };
        let Some((r, t)) = sides_with(
            "d178_finish_reason",
            &["chat", "hi", "--output", "json"],
            setup,
        ) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(r.run.json()["choices"][0]["finish_reason"], "paused");
        t.run.assert_code(1);
        assert!(
            t.run.stderr.contains("AISEC_RESPONSE_VALIDATION"),
            "{}",
            t.run.stderr
        );
    }
}
