//! TS-vs-Rust parity for the M6e chunk-3 gateway writes (DESIGN §19.3, §19.6, §19.7,
//! §19.10–§19.13; TS `aigateway …`, renamed, D227).
//!
//! Each scenario runs once against airs-cli-rs (`gateway …`) and once against the
//! TypeScript reference (`aigateway …`), each on a fresh [`FixtureServer`] seeded with the
//! gateway dataset and a fresh [`Sandbox`]. Both sides pass `--force` (TypeScript refuses
//! every confirmed write off a terminal) and the organisation flags TypeScript requires.
//! `parity` tests compare exit codes, the request lines and bodies (JSON equality; the
//! Rust bodies are sent with sorted keys, D35), and stdout (pretty bytes, json documents);
//! `divergence` tests pin both sides of each §12 row this chunk implements (named by its
//! D#). The TypeScript side prints the fixture markers (D237, D238), so its runs disable
//! the marker check; the airs-cli-rs runs keep it.

use std::time::Duration;

use airs_test_harness::fixtures::gateway as fx;
use airs_test_harness::{
    Cli, FixtureServer, GatewayData, Gw, Planned, RecordedRequest, Route, Run, RunOptions, Sandbox,
    require_ts, run, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn u(n: u64) -> String {
    fx::uuid(n)
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    data: GatewayData,
}

impl Side {
    /// `METHOD path?query` of every API request (the token request left out).
    fn api(&self) -> Vec<String> {
        self.requests
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    /// The bodies of the writes, in order.
    fn bodies(&self) -> Vec<Value> {
        self.requests
            .iter()
            .filter(|request| request.route.is_write())
            .map(|request| request.body_json().unwrap_or(Value::Null))
            .collect()
    }

    fn count(&self, gw: Gw) -> usize {
        self.requests
            .iter()
            .filter(|request| request.route == Route::Gateway(gw))
            .count()
    }
}

/// How a scenario is prepared on each side.
struct Setup<'a> {
    /// Edits the dataset.
    seed: &'a dyn Fn(&mut GatewayData),
    /// Plans responses on the server.
    plan: &'a dyn Fn(&FixtureServer),
    /// Files to create under `tmp/` (name, bytes); `{tmp}` in arguments names the dir.
    files: &'a [(&'a str, &'a [u8])],
    options: &'a dyn Fn(RunOptions) -> RunOptions,
}

fn nothing(_: &mut GatewayData) {}
fn no_plan(_: &FixtureServer) {}
fn same(options: RunOptions) -> RunOptions {
    options
}

const PLAIN: Setup<'static> = Setup {
    seed: &nothing,
    plan: &no_plan,
    files: &[],
    options: &same,
};

fn exec(cli: &Cli, args: &[&str], setup: &Setup<'_>) -> Side {
    let server = FixtureServer::start();
    server.seed_gateway();
    server.gateway(|data| (setup.seed)(data));
    (setup.plan)(&server);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    let tmp = sandbox.tmp().display().to_string();
    for (name, bytes) in setup.files {
        std::fs::write(sandbox.tmp().join(name), bytes).unwrap();
    }
    let args: Vec<String> = args.iter().map(|arg| arg.replace("{tmp}", &tmp)).collect();
    let mut full = vec![if cli.is_ts() { "aigateway" } else { "gateway" }];
    full.extend(args.iter().map(String::as_str));
    let options = if cli.is_ts() {
        RunOptions::new().allow_secret_output()
    } else {
        RunOptions::new()
    };
    let out = run(cli, &sandbox, &full, &(setup.options)(options));
    server.assert_no_unknown_routes();
    Side {
        run: out,
        requests: server.requests(),
        data: server.gateway_data(),
    }
}

fn sides_with(
    name: &str,
    rust_args: &[&str],
    ts_args: &[&str],
    setup: &Setup<'_>,
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((exec(&rust(), rust_args, setup), exec(&ts, ts_args, setup)))
}

fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_with(name, args, args, &PLAIN)
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// Request parity: exit codes, request lines and bodies.
fn assert_requests(r: &Side, t: &Side) {
    assert_eq!(r.run.code, t.run.code, "exit codes differ{}", context(r, t));
    assert_eq!(r.api(), t.api(), "requests differ{}", context(r, t));
    assert_eq!(r.bodies(), t.bodies(), "bodies differ{}", context(r, t));
}

/// `TS stdout` without TypeScript's stdout acknowledgement and warning lines (`  ✓ …`,
/// `  ⚠ …`, D230).
fn without_acks(text: &str) -> String {
    text.split_inclusive('\n')
        .filter(|line| !line.starts_with("  ✓ ") && !line.starts_with("  ⚠ "))
        .collect()
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

fn refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// How a write's stdout compares.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stdout {
    /// Byte parity (the generic detail of the answer).
    Bytes,
    /// Rust prints nothing, TS a fabricated or empty document (D244, D231).
    Divergent,
}

/// The generic writes with TS-valid arguments: `(rust args, ts args, stdout)`.
#[allow(clippy::too_many_lines)]
fn generic_writes() -> Vec<(Vec<String>, Vec<String>, Stdout)> {
    let both = |args: &[&str], out: Stdout| (strings(args), strings(args), out);
    let ws = u(1);
    let config = u(fx::CONFIG);
    let guardrail = u(fx::GUARDRAIL);
    let provider = u(fx::PROVIDER);
    let catalog = u(fx::CATALOG_PROVIDER);
    let integration = u(fx::INTEGRATION);
    let mcp = u(fx::MCP_INTEGRATION);
    let deployment = u(fx::DEPLOYMENT);
    let admin = u(fx::ADMIN_GUARDRAIL);
    let server = u(fx::MCP_SERVER);
    let sync = format!("mcp_servers.{server}.run_on=[\"input\"]");
    vec![
        both(
            &[
                "configs",
                "create",
                "--name",
                "c",
                "--workspace",
                &ws,
                "--set",
                "config.retry.attempts=3",
            ],
            Stdout::Bytes,
        ),
        both(
            &[
                "configs", "update", &config, "--name", "n", "--status", "active",
            ],
            Stdout::Bytes,
        ),
        both(
            &["configs", "delete", &config, "--force"],
            Stdout::Divergent,
        ),
        both(
            &[
                "guardrails",
                "create",
                "--workspace",
                &ws,
                "--name",
                "g",
                "--checks",
                "[{\"id\":\"default.jwt\",\"is_enabled\":true}]",
                "--actions",
                "{\"deny\":true}",
            ],
            Stdout::Bytes,
        ),
        both(
            &["guardrails", "update", &guardrail, "--name", "g2"],
            Stdout::Bytes,
        ),
        both(
            &["guardrails", "rm", &guardrail, "--force"],
            Stdout::Divergent,
        ),
        both(
            &[
                "providers",
                "create",
                "--workspace",
                &ws,
                "--ai-provider-id",
                &catalog,
                "--integration-id",
                &integration,
                "--name",
                "p",
                "--slug",
                "p",
                "--note",
                "n",
                "--usage-limit",
                "{\"type\":\"cost\",\"credit_limit\":5}",
            ],
            Stdout::Bytes,
        ),
        both(
            &[
                "providers",
                "update",
                &provider,
                "--note",
                "x",
                "--rate-limit",
                "{\"type\":\"requests\",\"unit\":\"rpm\",\"value\":5}",
            ],
            Stdout::Bytes,
        ),
        both(
            &[
                "api-keys",
                "service",
                "update",
                &u(fx::SERVICE_KEY),
                "--scopes",
                "mcp.invoke",
                "--description",
                "d",
            ],
            Stdout::Bytes,
        ),
        both(
            &["api-keys", "user", "delete", &u(fx::USER_KEY), "--force"],
            Stdout::Divergent,
        ),
        both(
            &[
                "deployments",
                "archive",
                &deployment,
                "--organisation-id",
                TSG,
                "--force",
            ],
            Stdout::Divergent,
        ),
        both(
            &[
                "integrations",
                "create",
                "--organisation-id",
                TSG,
                "--ai-provider-id",
                &catalog,
                "--name",
                "i1",
                "--slug",
                "i1",
                "--key-file",
                "{tmp}/provider.key",
                "--set",
                "configurations.vertex_project_id=project-1",
            ],
            Stdout::Bytes,
        ),
        both(
            &["integrations", "update", &integration, "--description", "d"],
            Stdout::Bytes,
        ),
        both(
            &[
                "integrations",
                "delete",
                &integration,
                "--organisation-id",
                TSG,
                "--force",
            ],
            Stdout::Divergent,
        ),
        both(
            &[
                "integrations",
                "models",
                "set",
                &integration,
                "--model",
                "gpt-4o=true",
                "--allow-all-models",
                "false",
                "--force",
            ],
            Stdout::Bytes,
        ),
        both(
            &[
                "integrations",
                "workspaces",
                "set",
                &integration,
                "--workspace-binding",
                "ws-main-a-349e0e=true",
                "--global-access",
                "false",
                "--force",
            ],
            Stdout::Bytes,
        ),
        both(
            &[
                "mcp",
                "integrations",
                "create",
                "--name",
                "m1",
                "--organisation-id",
                TSG,
                "--slug",
                "m1",
                "--url",
                "https://mcp.example.test/sse",
                "--auth-type",
                "none",
                "--transport",
                "sse",
            ],
            Stdout::Bytes,
        ),
        both(
            &["mcp", "integrations", "update", &mcp, "--description", "d"],
            Stdout::Bytes,
        ),
        both(
            &["mcp", "integrations", "delete", &mcp, "--force"],
            Stdout::Divergent,
        ),
        both(
            &[
                "mcp",
                "integrations",
                "capabilities",
                "set",
                &mcp,
                "--capability",
                "tool:search=true",
                "--force",
            ],
            Stdout::Bytes,
        ),
        both(
            &[
                "mcp",
                "integrations",
                "workspaces",
                "set",
                &mcp,
                "--workspace-binding",
                "ws-a=true",
                "--preserve-existing",
                "--force",
            ],
            Stdout::Divergent,
        ),
        (
            strings(&[
                "organisations",
                "self",
                "update",
                "--name",
                "Development",
                "--force",
            ]),
            strings(&["organisations", "self", "update", "--name", "Development"]),
            Stdout::Bytes,
        ),
        (
            strings(&[
                "organisations",
                "auth-settings",
                "update",
                "--tsg-id",
                TSG,
                "--domains",
                "a.test,b.test",
                "--force",
            ]),
            strings(&[
                "organisations",
                "auth-settings",
                "update",
                "--tsg-id",
                TSG,
                "--domains",
                "a.test,b.test",
            ]),
            Stdout::Bytes,
        ),
        both(
            &[
                "plugins",
                "create",
                "--organisation-id",
                TSG,
                "--integration-id",
                &integration,
                "--credential",
                "region=us",
            ],
            Stdout::Bytes,
        ),
        both(
            &[
                "admin-guardrails",
                "create",
                "--name",
                "Org",
                "--target",
                "mcp_tools",
                "--organisation",
                &u(fx::ORGANISATION),
            ],
            Stdout::Bytes,
        ),
        both(
            &["admin-guardrails", "update", &admin, "--name", "n"],
            Stdout::Bytes,
        ),
        both(
            &["admin-guardrails", "delete", &admin, "--force"],
            Stdout::Divergent,
        ),
        both(
            &[
                "admin-guardrails",
                "mcp-servers",
                "sync",
                &admin,
                "--set",
                &sync,
                "--force",
            ],
            Stdout::Bytes,
        ),
        both(
            &[
                "admin-guardrails",
                "mcp-servers",
                "upsert",
                &admin,
                &server,
                "--set",
                "run_on=[\"output\"]",
            ],
            Stdout::Bytes,
        ),
    ]
}

const KEY_FILE: Setup<'static> = Setup {
    seed: &nothing,
    plan: &no_plan,
    files: &[("provider.key", b"FAKE-GW-SECRET-38\n")],
    options: &same,
};

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// Every generic write (TS `aigateway-mutation-commands.spec.ts` "builds each
    /// configuration resource from named SDK-backed flags"): the same request lines and
    /// bodies, the same exit code, and the same pretty stdout (the answer's `Field │ Value`
    /// table) where TypeScript prints the answer.
    #[test]
    fn write_requests_and_answers_match_typescript() {
        for (rust_args, ts_args, stdout) in generic_writes() {
            let Some((r, t)) = sides_with(
                "write_requests_and_answers_match_typescript",
                &refs(&rust_args),
                &refs(&ts_args),
                &KEY_FILE,
            ) else {
                return;
            };
            r.run.assert_success();
            assert_requests(&r, &t);
            if stdout == Stdout::Bytes {
                assert_eq!(
                    r.run.stdout,
                    t.run.stdout,
                    "stdout differs{}",
                    context(&r, &t)
                );
            }
        }
    }

    /// D228 (§19.19): a write answered 401 once is replayed once after a fresh token on
    /// both sides (`token, write, token, write`), and both then succeed with the same
    /// request bodies.
    #[test]
    fn a_401_is_replayed_once_after_a_fresh_token() {
        let plan = |server: &FixtureServer| {
            server.push_once(Route::Gateway(Gw::ConfigCreate), Planned::empty_json(401));
        };
        let setup = Setup {
            plan: &plan,
            ..PLAIN
        };
        let args = strings(&[
            "configs",
            "create",
            "--name",
            "c",
            "--workspace",
            &u(1),
            "--set",
            "config.retry.attempts=1",
        ]);
        let Some((r, t)) = sides_with(
            "a_401_is_replayed_once_after_a_fresh_token",
            &refs(&args),
            &refs(&args),
            &setup,
        ) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(r.run.code, t.run.code, "{}", context(&r, &t));
        let order = |side: &Side| -> Vec<Route> {
            side.requests
                .iter()
                .map(|request| request.route)
                .filter(|route| {
                    *route == Route::Token || *route == Route::Gateway(Gw::ConfigCreate)
                })
                .collect()
        };
        let expected = [
            Route::Token,
            Route::Gateway(Gw::ConfigCreate),
            Route::Token,
            Route::Gateway(Gw::ConfigCreate),
        ];
        assert_eq!(order(&r), expected, "rust{}", context(&r, &t));
        assert_eq!(order(&t), expected, "typescript{}", context(&r, &t));
        assert_eq!(r.bodies(), t.bodies());
    }

    /// Numbers in `--set` values and the JSON flags go out in TypeScript's
    /// `JSON.stringify` form, compared as bytes (no JSON normalisation): `1e2` is `100`,
    /// `1.0` is `1`, `-0` is `0`; an overflowing literal is TS's finite-JSON refusal on
    /// both sides (exit 2, nothing sent), never the literal string.
    #[test]
    fn numbers_go_out_in_the_typescript_form() {
        let provider = u(fx::PROVIDER);
        let cases: Vec<Vec<String>> = vec![
            strings(&["organisations", "self", "update", "--set", "n=1e2"]),
            strings(&["organisations", "self", "update", "--set", "n=1.0"]),
            strings(&["organisations", "self", "update", "--set", "n=-0"]),
            strings(&["organisations", "self", "update", "--set", "n=[2.50,1E1]"]),
            strings(&[
                "providers",
                "update",
                &provider,
                "--rate-limit",
                "{\"type\":\"requests\",\"unit\":\"rpm\",\"value\":5.0}",
            ]),
        ];
        for args in cases {
            // Rust confirms the tenant-wide update (`--force`, D243); TS has no flag.
            let mut rust_args = args.clone();
            if args[0] == "organisations" {
                rust_args.push("--force".to_owned());
            }
            let Some((r, t)) = sides_with(
                "numbers_go_out_in_the_typescript_form",
                &refs(&rust_args),
                &refs(&args),
                &PLAIN,
            ) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
            let raw = |side: &Side| -> Vec<String> {
                side.requests
                    .iter()
                    .filter(|request| request.route.is_write())
                    .map(RecordedRequest::body_text)
                    .collect()
            };
            assert_eq!(raw(&r), raw(&t), "{args:?}");
        }
        for args in [
            strings(&["organisations", "self", "update", "--set", "n=1e400"]),
            strings(&[
                "providers",
                "update",
                &provider,
                "--rate-limit",
                "{\"type\":\"requests\",\"unit\":\"rpm\",\"value\":1e400}",
            ]),
        ] {
            // Rust confirms the tenant-wide update (`--force`, D243); TS has no flag.
            let mut rust_args = args.clone();
            if args[0] == "organisations" {
                rust_args.push("--force".to_owned());
            }
            let Some((r, t)) = sides_with(
                "numbers_go_out_in_the_typescript_form",
                &refs(&rust_args),
                &refs(&args),
                &PLAIN,
            ) else {
                return;
            };
            r.run.assert_code(2);
            assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
            assert!(r.bodies().is_empty() && t.bodies().is_empty(), "{args:?}");
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}");
        }
    }

    /// The non-empty array refinements print zod's texts: `Required` for an omitted
    /// member, the `Array must contain` text for an explicit `[]`, the type text for
    /// another value (exit 2, nothing sent).
    #[test]
    fn array_refinements_match_typescript() {
        let integration = u(fx::INTEGRATION);
        let mcp = u(fx::MCP_INTEGRATION);
        for extra in [&[][..], &["--set", "models=[]"], &["--set", "models=\"x\""]] {
            for (base, member) in [
                (
                    vec!["integrations", "models", "set", integration.as_str()],
                    "models",
                ),
                (
                    vec!["mcp", "integrations", "capabilities", "set", mcp.as_str()],
                    "capabilities",
                ),
            ] {
                let mut args = strings(&base);
                for arg in extra {
                    args.push(arg.replace("models", member));
                }
                args.push("--force".to_owned());
                let Some((r, t)) = sides("array_refinements_match_typescript", &refs(&args)) else {
                    return;
                };
                r.run.assert_code(2);
                assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
                assert_eq!(r.run.stderr, t.run.stderr, "{args:?}");
                assert!(r.bodies().is_empty() && t.bodies().is_empty());
            }
        }
    }

    /// `--output json` prints the same answer documents.
    #[test]
    fn json_answers_match_typescript() {
        for (rust_args, ts_args, stdout) in generic_writes() {
            if stdout != Stdout::Bytes {
                continue;
            }
            let mut rust_args = rust_args;
            let mut ts_args = ts_args;
            for args in [&mut rust_args, &mut ts_args] {
                args.extend(["--output".to_owned(), "json".to_owned()]);
            }
            let Some((r, t)) = sides_with(
                "json_answers_match_typescript",
                &refs(&rust_args),
                &refs(&ts_args),
                &KEY_FILE,
            ) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(
                r.run.json(),
                t.run.json(),
                "{rust_args:?}{}",
                context(&r, &t)
            );
        }
    }

    /// The one-time credential writes with `--secret-output`: the same request and body,
    /// the same saved document, the same `{saved_to}` answer (TS writes the whole answer).
    #[test]
    fn secret_writes_match_typescript() {
        let ws = u(1);
        for args in [
            strings(&[
                "api-keys",
                "service",
                "create",
                "--name",
                "ci-bot",
                "--scopes",
                "completions.write",
                "--type",
                "service",
                "--workspace",
                &ws,
                "--organisation-id",
                TSG,
                "--expires-at",
                "2027-01-01T00:00:00Z",
                "--secret-output",
                "{tmp}/key.json",
                "--output",
                "json",
            ]),
            strings(&[
                "api-keys",
                "user",
                "create",
                "--name",
                "me",
                "--scopes",
                "mcp.invoke",
                "--type",
                "user",
                "--workspace",
                &ws,
                "--organisation-id",
                TSG,
                "--user-id",
                &u(1501),
                "--secret-output",
                "{tmp}/key.json",
                "--output",
                "json",
            ]),
            strings(&[
                "api-keys",
                "service",
                "rotate",
                &u(fx::SERVICE_KEY),
                "--transition-ms",
                "1800000",
                "--force",
                "--secret-output",
                "{tmp}/key.json",
                "--output",
                "json",
            ]),
            strings(&[
                "deployments",
                "create",
                "--name",
                "edge",
                "--type",
                "production",
                "--organisation-id",
                TSG,
                "--is-default",
                "false",
                "--secret-output",
                "{tmp}/key.json",
                "--output",
                "json",
            ]),
            strings(&[
                "deployments",
                "update",
                &u(fx::DEPLOYMENT),
                "--rotate-auth",
                "true",
                "--secret-output",
                "{tmp}/key.json",
                "--output",
                "json",
            ]),
        ] {
            let ts = require_ts("secret_writes_match_typescript");
            let Some(ts) = ts else { return };
            let mut rust_args = args.clone();
            if rust_args[0] == "deployments" && rust_args[1] == "update" {
                rust_args.push("--force".into());
            }
            let side = |cli: &Cli, args: &[String]| {
                let server = FixtureServer::start();
                server.seed_gateway();
                let sandbox = Sandbox::new();
                sandbox.single_tenant(&server, "prod", TSG);
                let tmp = sandbox.tmp().display().to_string();
                let args: Vec<String> = args.iter().map(|arg| arg.replace("{tmp}", &tmp)).collect();
                let mut full = vec![if cli.is_ts() { "aigateway" } else { "gateway" }];
                full.extend(args.iter().map(String::as_str));
                let options = if cli.is_ts() {
                    RunOptions::new().allow_secret_output()
                } else {
                    RunOptions::new()
                };
                let out = run(cli, &sandbox, &full, &options);
                let saved: Value = serde_json::from_str(
                    &std::fs::read_to_string(sandbox.tmp().join("key.json")).unwrap(),
                )
                .unwrap();
                let mut answer = out.json();
                answer["saved_to"] =
                    json!(answer["saved_to"].as_str().unwrap().replace(&tmp, "{tmp}"));
                let bodies: Vec<Value> = server
                    .requests()
                    .iter()
                    .filter(|request| request.route.is_write())
                    .map(|request| request.body_json().unwrap_or(Value::Null))
                    .collect();
                (out.code, saved, answer, bodies)
            };
            let r = side(&rust(), &rust_args);
            let t = side(&ts, &args);
            assert_eq!(r, t, "{args:?}");
            assert_eq!(r.0, 0);
        }
    }

    /// `workspaces create|update|archive` and `scopes create|delete`: the same requests
    /// and bodies; stdout equal once TypeScript's stdout acknowledgement is removed (D230).
    #[test]
    fn workspace_and_scope_writes_match_typescript() {
        for (args, pretty) in [
            (
                strings(&[
                    "workspaces",
                    "create",
                    "--name",
                    "Truffles",
                    "--scope-name",
                    "ws_truffles_bx7qw1",
                    "--description",
                    "Recipes",
                    "--icon",
                    "pan",
                    "--metadata",
                    "{\"env\":\"production\"}",
                    "--users",
                    "u1, u2",
                    "--rate-limits",
                    "[{\"type\":\"requests\",\"unit\":\"rpm\",\"value\":100}]",
                ]),
                Some(true),
            ),
            (
                strings(&[
                    "workspaces",
                    "create",
                    "--name",
                    "Staging",
                    "--scope-name",
                    "ws_orphan_zzzzzz",
                    "--existing-scope",
                    "--output",
                    "json",
                ]),
                Some(false),
            ),
            (
                strings(&[
                    "workspaces",
                    "update",
                    "ws-produc-985697",
                    "--description",
                    "Production workloads, us-east",
                ]),
                Some(true),
            ),
            (
                strings(&[
                    "workspaces",
                    "update",
                    "Production",
                    "--name",
                    "Prod",
                    "--output",
                    "json",
                ]),
                Some(false),
            ),
            (
                strings(&["workspaces", "archive", "ws-produc-985697", "--force"]),
                None,
            ),
            (
                strings(&[
                    "scopes",
                    "create",
                    "--name",
                    "ws_new_aaaaaa",
                    "--description",
                    "New",
                ]),
                Some(true),
            ),
            (
                strings(&[
                    "scopes",
                    "create",
                    "--name",
                    "ws_new_aaaaaa",
                    "--output",
                    "json",
                ]),
                Some(false),
            ),
            (
                strings(&["scopes", "delete", "ws_orphan_zzzzzz", "--force"]),
                None,
            ),
        ] {
            let Some((r, t)) = sides("workspace_and_scope_writes_match_typescript", &refs(&args))
            else {
                return;
            };
            r.run.assert_success();
            assert_requests(&r, &t);
            match pretty {
                Some(true) => assert_eq!(
                    r.run.stdout,
                    without_acks(&t.run.stdout),
                    "{args:?}{}",
                    context(&r, &t)
                ),
                Some(false) => {
                    let ts_json: Value =
                        serde_json::from_str(&without_acks(&t.run.stdout)).unwrap();
                    assert_eq!(r.run.json(), ts_json, "{args:?}");
                }
                // Archives and deletes: the same status lines (TS prints the banner, D230).
                None => assert!(
                    r.run.stderr.ends_with(&t.run.stderr),
                    "{args:?}{}",
                    context(&r, &t)
                ),
            }
        }
    }

    /// The tenant's `defaultOutput` applies to writes on both sides (choice 5).
    #[test]
    fn the_tenant_default_output_applies_to_writes() {
        let Some(ts) = require_ts("the_tenant_default_output_applies_to_writes") else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_gateway();
            let sandbox = Sandbox::new();
            let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
                config.set("defaultOutput", "json");
            });
            sandbox.register(&[&tenant], Some("prod"));
            let root = if cli.is_ts() { "aigateway" } else { "gateway" };
            let out = run(
                &cli,
                &sandbox,
                &[
                    root,
                    "guardrails",
                    "update",
                    &u(fx::GUARDRAIL),
                    "--name",
                    "g",
                ],
                &RunOptions::new().allow_secret_output(),
            );
            out.assert_success();
            assert_eq!(out.json(), json!({"success": true}), "{}", cli.label());
        }
    }

    /// Every chunk-3 leaf carries TypeScript's description and option texts, apart from
    /// the options §19.2 changes: the global `--output`, `--file` (JSON only, D246),
    /// `--secret-output` and the hidden `--show-secret` (D237), the optional organisation
    /// flags (D245), the Rust `--force` of the new confirmations (D243), and `providers
    /// create` without `--reset-usage` (D245).
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let help = |cli: &Cli, path: &[&str]| {
            let mut args = vec![if cli.is_ts() { "aigateway" } else { "gateway" }];
            args.extend_from_slice(path);
            args.push("--help");
            let out = run(cli, &sandbox, &args, &RunOptions::new());
            out.assert_success();
            out.stdout
        };
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let options = |text: &str| -> Vec<(String, String)> {
            let mut lines = text.lines();
            if !lines.any(|line| line == "Options:") {
                return Vec::new();
            }
            let mut out: Vec<(String, String)> = Vec::new();
            for line in lines.take_while(|line| !line.trim().is_empty()) {
                let trimmed = line.trim_start();
                let indent = line.len() - trimmed.len();
                if indent <= 6 {
                    let (spec, description) = trimmed.split_once("  ").unwrap_or((trimmed, ""));
                    let name = spec
                        .split([',', ' '])
                        .find(|part| part.starts_with("--"))
                        .unwrap_or(spec)
                        .to_owned();
                    out.push((name, squash(description)));
                } else if let Some((_, description)) = out.last_mut() {
                    *description = squash(&format!("{description} {trimmed}"));
                }
            }
            out
        };
        let org_help =
            "Numeric TSG id (default: the selected tenant's mgmtTsgId; another value is refused)";
        let leaves: [&[&str]; 45] = [
            &["workspaces", "create"],
            &["workspaces", "update"],
            &["workspaces", "archive"],
            &["workspaces", "delete"],
            &["scopes", "create"],
            &["scopes", "bind"],
            &["scopes", "delete"],
            &["configs", "create"],
            &["configs", "update"],
            &["configs", "delete"],
            &["guardrails", "create"],
            &["guardrails", "update"],
            &["guardrails", "delete"],
            &["providers", "create"],
            &["providers", "update"],
            &["providers", "delete"],
            &["api-keys", "service", "create"],
            &["api-keys", "service", "update"],
            &["api-keys", "service", "rotate"],
            &["api-keys", "service", "delete"],
            &["api-keys", "user", "create"],
            &["api-keys", "user", "update"],
            &["api-keys", "user", "rotate"],
            &["api-keys", "user", "delete"],
            &["deployments", "create"],
            &["deployments", "update"],
            &["deployments", "archive"],
            &["integrations", "create"],
            &["integrations", "update"],
            &["integrations", "delete"],
            &["integrations", "models", "set"],
            &["integrations", "workspaces", "set"],
            &["mcp", "integrations", "create"],
            &["mcp", "integrations", "update"],
            &["mcp", "integrations", "delete"],
            &["mcp", "integrations", "capabilities", "set"],
            &["mcp", "integrations", "workspaces", "set"],
            &["organisations", "self", "update"],
            &["organisations", "auth-settings", "update"],
            &["plugins", "create"],
            &["admin-guardrails", "create"],
            &["admin-guardrails", "update"],
            &["admin-guardrails", "delete"],
            &["admin-guardrails", "mcp-servers", "sync"],
            &["admin-guardrails", "mcp-servers", "upsert"],
        ];
        let secret_help = "New private file (mode 0600) that receives the one-time credential; never overwritten (the credential is never printed)";
        let mut problems = Vec::new();
        for path in leaves {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let command = path.join(" ");
            let rust_options = options(&r);
            for (flag, description) in options(&t) {
                let expected = match flag.as_str() {
                    "--help" | "--output" => continue,
                    "--file" => {
                        Some("Advanced JSON request base; named flags override it".to_owned())
                    }
                    "--secret-output" => Some(secret_help.to_owned()),
                    "--show-secret" => None,
                    "--organisation-id" | "--tsg-id" => Some(org_help.to_owned()),
                    "--reset-usage" if command == "providers create" => None,
                    _ => Some(description),
                };
                let found = rust_options.iter().find(|(f, _)| *f == flag);
                match (expected, found) {
                    (Some(expected), Some((_, actual))) if *actual == expected => {}
                    (None, None) => {}
                    (expected, found) => {
                        problems.push(format!("{command} {flag}: {found:?} vs {expected:?}"));
                    }
                }
            }
            let ts_about = squash(t.split("\n\n").nth(1).unwrap_or_default());
            if !squash(&r).contains(&ts_about) {
                problems.push(format!("{command} description: {ts_about:?}"));
            }
        }
        assert!(
            problems.is_empty(),
            "help differs:\n{}",
            problems.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    fn create_config() -> Vec<String> {
        strings(&[
            "configs",
            "create",
            "--name",
            "c",
            "--workspace",
            &u(1),
            "--set",
            "config.retry.attempts=1",
        ])
    }

    /// D228: a write answered 503 is sent once by airs-cli-rs, with the outcome line and
    /// hint; TypeScript re-sends it (up to 5 more times).
    #[test]
    fn d228_writes_are_sent_once() {
        let plan = |server: &FixtureServer| {
            server.set_default(
                Route::Gateway(Gw::ConfigCreate),
                Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
            );
        };
        let setup = Setup {
            plan: &plan,
            ..PLAIN
        };
        let args = create_config();
        let Some((r, t)) = sides_with(
            "d228_writes_are_sent_once",
            &refs(&args),
            &refs(&args),
            &setup,
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert_eq!(r.count(Gw::ConfigCreate), 1);
        assert!(
            r.run
                .stderr
                .contains("    Outcome unknown: the config may have been created.\n")
        );
        assert!(
            t.count(Gw::ConfigCreate) > 1,
            "TS re-sends: {}",
            t.count(Gw::ConfigCreate)
        );
        assert!(!t.run.stderr.contains("Outcome"));
    }

    /// D229: a workspace create that fails with a 5xx keeps the new scope (the workspace
    /// may reference it); TypeScript retries the create and then deletes the scope.
    #[test]
    fn d229_an_unknown_workspace_create_keeps_its_scope() {
        let plan = |server: &FixtureServer| {
            server.set_default(
                Route::Gateway(Gw::WorkspaceCreate),
                Planned::json(503, &json!({})).with_retry_after(0),
            );
        };
        let setup = Setup {
            plan: &plan,
            ..PLAIN
        };
        let args = strings(&[
            "workspaces",
            "create",
            "--name",
            "Truffles",
            "--scope-name",
            "ws_truffles_bx7qw1",
        ]);
        let Some((r, t)) = sides_with(
            "d229_an_unknown_workspace_create_keeps_its_scope",
            &refs(&args),
            &refs(&args),
            &setup,
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert_eq!(r.count(Gw::ScopeDelete), 0);
        assert_eq!(r.count(Gw::WorkspaceCreate), 1);
        assert!(
            r.run
                .stderr
                .contains("IAM scope ws_truffles_bx7qw1 is kept.")
        );
        assert!(
            r.data
                .scopes
                .iter()
                .any(|scope| scope["name"] == "ws_truffles_bx7qw1")
        );
        assert_eq!(t.count(Gw::ScopeDelete), 1, "TS deletes the scope");
        assert!(t.count(Gw::WorkspaceCreate) > 1);
    }

    /// D230: acknowledgements and warnings on stderr, the banner only above successful
    /// pretty data; TypeScript writes them on stdout (before a JSON document; the banner
    /// on archives).
    #[test]
    fn d230_acknowledgements_and_warnings_on_stderr() {
        let args = strings(&[
            "workspaces",
            "create",
            "--name",
            "Truffles",
            "--scope-name",
            "ws_orphan_zzzzzz",
            "--existing-scope",
            "--output",
            "json",
        ]);
        let Some((r, t)) = sides("d230_acknowledgements_and_warnings_on_stderr", &refs(&args))
        else {
            return;
        };
        r.run.assert_success();
        assert!(r.run.json().is_object());
        assert!(
            r.run
                .stderr
                .contains("  ⚠ --scope-name 'ws_orphan_zzzzzz' shares no token")
        );
        assert!(r.run.stderr.contains("  ✓ Workspace created: "));
        assert!(
            t.run
                .stdout
                .starts_with("  ⚠ --scope-name 'ws_orphan_zzzzzz' shares no token")
        );
        assert!(t.run.stdout.contains("  ✓ Workspace created: "));
        let args = strings(&["workspaces", "archive", "ws-produc-985697", "--force"]);
        let Some((r, t)) = sides("d230_acknowledgements_and_warnings_on_stderr", &refs(&args))
        else {
            return;
        };
        assert_eq!(r.run.stdout, "");
        assert!(t.run.stdout.starts_with("\n  Prisma AIRS — AI Gateway\n"));
    }

    /// D231: an empty `{}` answer prints `No fields returned` in pretty; TypeScript prints
    /// nothing at all (both print `{}` in json).
    #[test]
    fn d231_empty_write_answers() {
        for (format, expected, ts) in [
            ("pretty", "  No fields returned\n", ""),
            ("json", "{}\n", "{}\n"),
        ] {
            let args = strings(&[
                "mcp",
                "integrations",
                "workspaces",
                "set",
                &u(fx::MCP_INTEGRATION),
                "--workspace-binding",
                "ws-a=true",
                "--force",
                "--output",
                format,
            ]);
            let Some((r, t)) = sides("d231_empty_write_answers", &refs(&args)) else {
                return;
            };
            assert_eq!(r.run.stdout, expected);
            assert_eq!(t.run.stdout, ts);
        }
    }

    /// D232: a write's id is checked before the tenant (exit 2); TypeScript checks it after
    /// the tenant and the client (exit 1). Neither sends the write.
    #[test]
    fn d232_write_checks_come_before_the_tenant() {
        let args = strings(&["configs", "delete", "config-1", "--force"]);
        let Some((r, t)) = sides("d232_write_checks_come_before_the_tenant", &refs(&args)) else {
            return;
        };
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid configId: config-1\n\n"
        );
        assert!(r.requests.is_empty());
        t.run.assert_code(1);
        assert!(t.run.stderr.contains("Invalid configId: config-1"));
        assert_eq!(t.count(Gw::ConfigDelete), 0);
        // The order of the exit-2 checks (§19.3, §19.11, choice 88): the planning checks
        // (the destination rule, the ids, the flags, the refusal of an always-confirming
        // write) come before the body and its refinements, which need the debug log and
        // the input files; TypeScript builds the body first and refuses a delete before
        // checking its id.
        let key = u(fx::SERVICE_KEY);
        let integration = u(fx::INTEGRATION);
        let cases: [(Vec<String>, &str, &str); 3] = [
            (
                strings(&[
                    "api-keys",
                    "service",
                    "rotate",
                    &key,
                    "--transition-ms",
                    "5",
                ]),
                "A one-time credential needs --secret-output <new file>; airs never prints it",
                "key_transition_period_ms: Number must be greater than or equal to 1800000",
            ),
            (
                strings(&["integrations", "models", "set", &integration]),
                "without --force in non-interactive mode",
                "models: Required",
            ),
            (
                strings(&["configs", "delete", "not-uuid"]),
                "Invalid configId: not-uuid",
                "without --force in non-interactive mode",
            ),
        ];
        for (args, rust_text, ts_text) in cases {
            let Some((r, t)) = sides("d232_write_checks_come_before_the_tenant", &refs(&args))
            else {
                return;
            };
            r.run.assert_code(2);
            assert!(
                r.run.stderr.contains(rust_text),
                "{args:?}: {}",
                r.run.stderr
            );
            assert!(r.requests.is_empty(), "{args:?}");
            assert!(t.run.stderr.contains(ts_text), "{args:?}: {}", t.run.stderr);
            assert!(t.bodies().is_empty(), "{args:?}");
        }
    }

    /// D233: `--set` without `=` names the flag only; TypeScript echoes the argument.
    #[test]
    fn d233_errors_echo_no_values() {
        let marker = fx::marker(37);
        let args = strings(&["configs", "create", "--set", &marker]);
        let Some((r, t)) = sides("d233_errors_echo_no_values", &refs(&args)) else {
            return;
        };
        r.run.assert_code(2);
        assert_eq!(r.run.stderr, "\n  ✗ Invalid --set: Expected path=value\n\n");
        assert!(t.run.stderr.contains(&marker));
    }

    /// D234 (writes): a data-plane write answered 403 with `AB03` in the body gets the
    /// data-plane hint on stderr; TypeScript prints the admin-plane hint on stdout.
    #[test]
    fn d234_write_grant_hints() {
        let plan = |server: &FixtureServer| {
            server.set_default(
                Route::Gateway(Gw::ConfigCreate),
                Planned::json(403, &json!({"message": "Forbidden", "errorCode": "AB03"}))
                    .with_header("x-opa-decision", "false"),
            );
        };
        let setup = Setup {
            plan: &plan,
            ..PLAIN
        };
        let args = create_config();
        let Some((r, t)) = sides_with("d234_write_grant_hints", &refs(&args), &refs(&args), &setup)
        else {
            return;
        };
        r.run.assert_code(1);
        assert!(r.run.stderr.starts_with("  ⚠ 403: the service account is missing a workspace-scope grant (data plane, /ai_gw/v2)."));
        assert_eq!(r.run.stdout, "");
        assert!(t.run.stdout.contains("tenant-root admin grant"));
    }

    /// D235 (writes): `scopes bind --workspace NoSuch` is refused with nothing sent;
    /// TypeScript binds the non-existent slug.
    #[test]
    fn d235_bind_refuses_an_unknown_workspace() {
        let args = strings(&[
            "scopes",
            "bind",
            "ws_orphan_zzzzzz",
            "--workspace",
            "NoSuch",
        ]);
        let Some((r, t)) = sides("d235_bind_refuses_an_unknown_workspace", &refs(&args)) else {
            return;
        };
        r.run.assert_code(1);
        assert_eq!(r.count(Gw::ScopeUpdate), 0);
        t.run.assert_success();
        assert_eq!(t.bodies()[0]["resources"][0]["resource_id"], "NoSuch");
    }

    /// D254: an incomplete admin list (`has_more: true`) resolves no display name, so
    /// `workspaces archive Production` sends nothing; TypeScript archives the visible row.
    #[test]
    fn d254_an_incomplete_list_resolves_no_name() {
        let seed = |data: &mut GatewayData| data.has_more = Some(true);
        let setup = Setup {
            seed: &seed,
            ..PLAIN
        };
        let args = strings(&["workspaces", "archive", "Production", "--force"]);
        let Some((r, t)) = sides_with(
            "d254_an_incomplete_list_resolves_no_name",
            &refs(&args),
            &refs(&args),
            &setup,
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert_eq!(r.count(Gw::WorkspaceArchive), 0);
        assert!(r.run.stderr.contains("the workspace list is incomplete"));
        t.run.assert_success();
        assert_eq!(
            t.count(Gw::WorkspaceArchive),
            1,
            "TS archives the visible row"
        );
    }

    /// D236: `scopes create` checks the name (TypeScript sends any); `scopes bind` reads
    /// the scope back to verify (TypeScript trusts its PUT).
    #[test]
    fn d236_scope_writes() {
        let args = strings(&["scopes", "create", "--name", "bad name"]);
        let Some((r, t)) = sides("d236_scope_writes", &refs(&args)) else {
            return;
        };
        r.run.assert_code(2);
        assert!(r.requests.is_empty());
        t.run.assert_success();
        assert_eq!(t.count(Gw::ScopeCreate), 1);
        let args = strings(&[
            "scopes",
            "bind",
            "ws_orphan_zzzzzz",
            "--workspace",
            "Main A",
        ]);
        let Some((r, t)) = sides("d236_scope_writes", &refs(&args)) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(
            r.count(Gw::ScopeGet),
            2,
            "the bind's read and the verification"
        );
        assert_eq!(t.count(Gw::ScopeGet), 1);
    }

    /// D237: `--show-secret` is refused before any request; TypeScript prints the
    /// one-time key on stdout.
    #[test]
    fn d237_one_time_credentials_never_reach_stdout() {
        let args = strings(&[
            "api-keys",
            "service",
            "create",
            "--name",
            "k",
            "--scopes",
            "mcp.invoke",
            "--type",
            "service",
            "--workspace",
            &u(1),
            "--organisation-id",
            TSG,
            "--show-secret",
        ]);
        let Some((r, t)) = sides("d237_one_time_credentials_never_reach_stdout", &refs(&args))
        else {
            return;
        };
        r.run.assert_code(2);
        assert!(r.requests.is_empty());
        t.run.assert_success();
        assert!(t.run.stdout.contains(&fx::marker(30)));
    }

    /// D238 (write answers): an answer that echoes a credential prints it `[withheld]`;
    /// TypeScript prints write answers as received.
    #[test]
    fn d238_write_answers_are_withheld() {
        let plan = |server: &FixtureServer| {
            server.set_default(
                Route::Gateway(Gw::ProviderUpdate),
                Planned::json(200, &json!({"success": true, "key": fx::marker(37)})),
            );
        };
        let setup = Setup {
            plan: &plan,
            ..PLAIN
        };
        let args = strings(&[
            "providers",
            "update",
            &u(fx::PROVIDER),
            "--name",
            "p",
            "--output",
            "json",
        ]);
        let Some((r, t)) = sides_with(
            "d238_write_answers_are_withheld",
            &refs(&args),
            &refs(&args),
            &setup,
        ) else {
            return;
        };
        assert_eq!(r.run.json(), json!({"success": true, "key": "[withheld]"}));
        assert_eq!(t.run.json()["key"], fx::marker(37).as_str());
    }

    /// D243: the new confirmations refuse off a terminal without `--force`; TypeScript
    /// sends these writes unasked.
    #[test]
    fn d243_new_confirmations() {
        for args in [
            strings(&[
                "providers",
                "update",
                &u(fx::PROVIDER),
                "--reset-usage",
                "true",
            ]),
            strings(&["organisations", "self", "update", "--name", "Dev"]),
        ] {
            let Some((r, t)) = sides("d243_new_confirmations", &refs(&args)) else {
                return;
            };
            r.run.assert_code(2);
            assert!(
                r.run
                    .stderr
                    .contains("without --force in non-interactive mode")
            );
            assert!(r.requests.is_empty());
            t.run.assert_success();
            assert_eq!(t.bodies().len(), 1);
        }
    }

    /// D244: removals leave stdout empty and acknowledge on stderr; TypeScript prints a
    /// fabricated `{"success": true}`.
    #[test]
    fn d244_removals_leave_stdout_empty() {
        let args = strings(&[
            "configs",
            "delete",
            &u(fx::CONFIG),
            "--force",
            "--output",
            "json",
        ]);
        let Some((r, t)) = sides("d244_removals_leave_stdout_empty", &refs(&args)) else {
            return;
        };
        assert_eq!(r.run.stdout, "");
        assert_eq!(
            r.run.stderr,
            format!("  ✓ Config deleted: {}\n", u(fx::CONFIG))
        );
        assert_eq!(t.run.json(), json!({"success": true}));
        assert_eq!(t.run.stderr, "");
    }

    /// D245: `--organisation-id` defaults to the tenant's TSG (TypeScript requires it) and
    /// another `--tsg-id` is refused (TypeScript sends it under the tenant's `x-tsg-id`).
    #[test]
    fn d245_organisation_ids() {
        let args = strings(&["deployments", "archive", &u(fx::DEPLOYMENT), "--force"]);
        let Some((r, t)) = sides("d245_organisation_ids", &refs(&args)) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(
            r.api(),
            [format!(
                "DELETE /ai_gw/admin/v2/deployments/{}?organisation_id={TSG}",
                u(fx::DEPLOYMENT)
            )]
        );
        t.run.assert_code(1);
        assert!(
            t.run
                .stderr
                .contains("required option '--organisation-id <tsg>' not specified")
        );
        let rust_args = strings(&[
            "organisations",
            "auth-settings",
            "update",
            "--tsg-id",
            "999",
            "--domains",
            "a.test",
            "--force",
        ]);
        let ts_args = strings(&[
            "organisations",
            "auth-settings",
            "update",
            "--tsg-id",
            "999",
            "--domains",
            "a.test",
        ]);
        let Some((r, t)) = sides_with(
            "d245_organisation_ids",
            &refs(&rust_args),
            &refs(&ts_args),
            &PLAIN,
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert!(r.requests.is_empty());
        assert!(!t.api().is_empty());
        assert!(
            t.api()
                .iter()
                .all(|line| line == "PUT /ai_gw/admin/v2/organisations/999/auth-settings"),
            "{:?}",
            t.api()
        );
    }

    /// D246: a YAML request file is refused before the tenant; TypeScript parses it.
    #[test]
    fn d246_request_files_are_json_only() {
        let setup = Setup {
            files: &[("request.yaml", b"name: from-yaml\nworkspace_id: 11111111-1111-4111-8111-000000000001\nconfig:\n  retry:\n    attempts: 2\n")],
            ..PLAIN
        };
        let args = strings(&["configs", "create", "--file", "{tmp}/request.yaml"]);
        let Some((r, t)) = sides_with(
            "d246_request_files_are_json_only",
            &refs(&args),
            &refs(&args),
            &setup,
        ) else {
            return;
        };
        r.run.assert_code(2);
        assert!(r.requests.is_empty());
        t.run.assert_success();
        assert_eq!(t.bodies()[0]["name"], "from-yaml");
    }

    /// D247: a credential-less integration create is refused before any request;
    /// TypeScript reads the provider catalog first.
    #[test]
    fn d247_credential_checks_come_first() {
        let args = strings(&[
            "integrations",
            "create",
            "--organisation-id",
            TSG,
            "--ai-provider",
            "openai",
            "--name",
            "i",
            "--slug",
            "i",
        ]);
        let Some((r, t)) = sides("d247_credential_checks_come_first", &refs(&args)) else {
            return;
        };
        r.run.assert_code(2);
        assert!(r.requests.is_empty());
        t.run.assert_code(2);
        assert_eq!(t.count(Gw::CatalogProviders), 1);
    }

    /// D252: a signal during a held write reports that the change may have been applied;
    /// TypeScript exits 130 printing nothing.
    #[test]
    fn d252_an_interrupted_write_says_what_may_have_changed() {
        let Some(ts) = require_ts("d252_an_interrupted_write_says_what_may_have_changed") else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_gateway();
            server.push_once(Route::Gateway(Gw::ConfigUpdate), Planned::held());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let root = if cli.is_ts() { "aigateway" } else { "gateway" };
            let config = u(fx::CONFIG);
            let running = spawn(
                &cli,
                &sandbox,
                &[root, "configs", "update", &config, "--name", "n"],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Gateway(Gw::ConfigUpdate),
                1,
                Duration::from_secs(30)
            ));
            running.send_signal("INT");
            let out = running.wait();
            server.release_held();
            if cli.is_ts() {
                assert_eq!(out.stderr, "", "TS prints nothing");
            } else {
                out.assert_code(130);
                assert_eq!(
                    out.stderr,
                    "\n  ✗ Error: Interrupted; the change may already have been applied (outcome unknown)\n\n"
                );
            }
        }
    }
}
