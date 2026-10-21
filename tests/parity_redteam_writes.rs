//! TS-vs-Rust parity for the M6a step-2 red team writes and the scan (DESIGN §15.5–
//! §15.15).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh [`FixtureServer`] seeded with the red team dataset (whose
//! write routes change it) and a fresh [`Sandbox`]. `parity` tests compare exit codes,
//! the normalised requests and the output with the D145 move applied: TypeScript writes
//! its outcome lines and hints on stdout, airs-cli-rs on stderr (with the program name
//! `airs`, D73), and airs-cli-rs prints the banner only above data. `divergence`
//! tests pin both sides of each §12 row this step implements (named by its D#). The
//! TypeScript side prints the fixture credentials (D140), so its runs disable the marker
//! check; the airs-cli-rs runs keep it.

use airs_test_harness::fixtures::redteam as fx;
use airs_test_harness::{
    Cli, FixtureServer, NormalizedBody, NormalizedRequest, Planned, Route, Rt, Run, RunOptions,
    Sandbox, normalize_all, require_ts, run, split_outcome_lines,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    lines: Vec<String>,
    server: FixtureServer,
    #[allow(dead_code)]
    sandbox: Sandbox,
}

type Seed<'a> = &'a dyn Fn(&mut airs_test_harness::RedTeamData);
type Files<'a> = &'a [(&'a str, &'a [u8])];

/// Runs `cli` on a fresh seeded server and sandbox; `files` are written under `tmp/`
/// and `@name` in `args` is replaced by the absolute path of file `name`.
fn exec(cli: &Cli, args: &[&str], seed: Seed<'_>, files: Files<'_>, options: &RunOptions) -> Side {
    let server = FixtureServer::start();
    server.seed_redteam();
    server.redteam(|data| seed(data));
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    for (name, bytes) in files {
        std::fs::write(sandbox.tmp().join(name), bytes).unwrap();
    }
    let args: Vec<String> = std::iter::once("redteam".to_owned())
        .chain(args.iter().map(|arg| match arg.strip_prefix('@') {
            Some(name) => sandbox.tmp().join(name).display().to_string(),
            None => (*arg).to_owned(),
        }))
        .collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let options = if cli.is_ts() {
        options.clone().allow_secret_output()
    } else {
        options.clone()
    };
    let out = run(cli, &sandbox, &args, &options);
    let raw = server.requests();
    Side {
        run: out,
        requests: normalize_all(&raw),
        lines: raw.iter().map(|request| request.line()).collect(),
        server,
        sandbox,
    }
}

fn unchanged(_: &mut airs_test_harness::RedTeamData) {}

/// Both sides with their own arguments (`None` after a `PARITY SKIPPED` notice).
fn pair(
    name: &str,
    rust_args: &[&str],
    ts_args: &[&str],
    seed: Seed<'_>,
    files: Files<'_>,
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    let options = RunOptions::new();
    Some((
        exec(&rust(), rust_args, seed, files, &options),
        exec(&ts, ts_args, seed, files, &options),
    ))
}

fn sides(name: &str, args: &[&str], seed: Seed<'_>, files: Files<'_>) -> Option<(Side, Side)> {
    pair(name, args, args, seed, files)
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// The TypeScript stdout split into what airs-cli-rs writes on stderr (outcome lines and
/// the `ui.dim` hints, program name mapped, D73) and the data it writes on stdout (the
/// banner dropped when no data follows it, D145).
fn ts_moved(stdout: &str) -> (String, String) {
    let (outcome, rest) = split_outcome_lines(stdout);
    let mut moved = outcome;
    let mut data = String::new();
    for line in rest.split_inclusive('\n') {
        let hint = [
            "  Run `airs-cli ",
            "  Next steps: ",
            "    airs-cli redteam ",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix));
        if hint {
            moved.push_str(&line.replace("airs-cli ", "airs "));
        } else {
            data.push_str(line);
        }
    }
    if data == BANNER {
        data.clear();
    }
    (moved, data)
}

/// Bodies with the client clock (`accepted_at`) replaced.
fn without_clock(requests: &[NormalizedRequest]) -> Vec<NormalizedRequest> {
    requests
        .iter()
        .cloned()
        .map(|mut request| {
            if let NormalizedBody::Json(Value::Object(map)) = &mut request.body
                && map.contains_key("accepted_at")
            {
                map.insert("accepted_at".into(), json!("<now>"));
            }
            request
        })
        .collect()
}

/// D145 parity: the exit code, the requests, the TypeScript data bytes on Rust stdout
/// and the TypeScript outcome lines and hints in Rust stderr (after its status lines).
fn assert_moved(r: &Side, t: &Side) {
    assert_eq!(r.run.code, t.run.code, "exit codes differ{}", context(r, t));
    let (moved, data) = ts_moved(&t.run.stdout);
    assert_eq!(r.run.stdout, data, "stdout differs{}", context(r, t));
    assert_eq!(
        r.run.stderr,
        format!("{}{moved}", t.run.stderr),
        "stderr differs{}",
        context(r, t)
    );
    assert_eq!(
        without_clock(&r.requests),
        without_clock(&t.requests),
        "requests differ{}",
        context(r, t)
    );
}

fn api(side: &Side) -> Vec<String> {
    side.lines
        .iter()
        .filter(|line| !line.starts_with("POST /oauth/token"))
        .cloned()
        .collect()
}

/// A credential-free target body. Both CLIs print the same answer when it sets
/// `ws_response_timeout` (which the fixture echoes); without it TypeScript prints its
/// schema default `110` and airs-cli-rs nothing (D153).
fn plain_target(name: &str, ws_response_timeout: Option<u64>) -> Vec<u8> {
    let mut body = json!({
        "name": name,
        "target_type": "APPLICATION",
        "connection_type": "CUSTOM",
        "api_endpoint_type": "PUBLIC",
        "response_mode": "REST",
        "connection_params": {
            "api_endpoint": "https://x.invalid/v1",
            "request_headers": {"Content-Type": "application/json"},
            "request_json": {"m": "{INPUT}"},
            "response_json": {"r": "{RESPONSE}"},
            "response_key": "r"
        },
        "auth_type": "HEADERS"
    });
    if let Some(timeout) = ws_response_timeout {
        body["connection_params"]["ws_response_timeout"] = json!(timeout);
    }
    serde_json::to_vec(&body).unwrap()
}

const DEVICES: &[u8] = br#"{"instance":{"app_id":"a","region":"r","tenant_id":"ten-1","tsg_id":"100"},"devices":[{"serial_number":"SN1"}]}"#;

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// Every write whose output and requests TypeScript shares, with the D145 move: the
    /// same bodies, paths and queries, the same data bytes and the same outcome lines.
    #[test]
    fn write_outputs_and_requests_match_typescript() {
        let set = fx::prompt_set_id(1);
        let prompt = fx::prompt_id(1);
        let target = fx::target_id(1);
        let adapter = fx::adapter_id(1);
        let channel = fx::channel_id(1);
        let target_body = plain_target("plain", Some(110));
        let files: Files<'_> = &[("t.json", &target_body), ("d.json", DEVICES)];
        for args in [
            vec![
                "instances",
                "create",
                "--tsg-id",
                "100",
                "--tenant-id",
                "ten-2",
                "--app-id",
                "app-2",
                "--region",
                "eu",
            ],
            vec![
                "instances",
                "update",
                "ten-1",
                "--tsg-id",
                "100",
                "--app-id",
                "app-3",
                "--region",
                "us",
            ],
            vec!["devices", "create", "ten-1", "--config", "@d.json"],
            vec!["devices", "update", "ten-1", "--config", "@d.json"],
            vec![
                "prompt-sets",
                "create",
                "--name",
                "fresh",
                "--description",
                "d",
            ],
            vec!["prompt-sets", "update", &set, "--name", "renamed"],
            vec!["prompt-sets", "archive", &set],
            vec!["prompt-sets", "archive", &set, "--unarchive"],
            vec!["prompts", "add", &set, "--prompt", "hi", "--goal", "g"],
            vec!["prompts", "update", &set, &prompt, "--goal", "g2"],
            vec!["properties", "create", "--name", "tone"],
            vec![
                "properties",
                "add-value",
                "--name",
                "tone",
                "--value",
                "angry",
            ],
            vec!["targets", "create", "--config", "@t.json", "--validate"],
            vec!["targets", "update", &target, "--config", "@t.json"],
            vec!["targets", "probe", "--config", "@t.json"],
            vec!["targets", "delete", &target, "--force"],
            vec![
                "adapter",
                "create",
                "--name",
                "fresh",
                "--prompt",
                "Hello",
                "--script-b64",
                "eA==",
                "--channel",
                &channel,
                "--variables",
                r#"[{"key":"e","value":"v","type":"VAR"}]"#,
            ],
            vec![
                "adapter",
                "update",
                &adapter,
                "--prompt",
                "Hi",
                "--description",
                "new",
            ],
            vec![
                "adapter",
                "validate",
                "--channel",
                &channel,
                "--prompt",
                "Hi",
                "--script-b64",
                "eA==",
                "--adapter",
                &adapter,
            ],
            vec!["adapter", "delete", &adapter, "--force"],
            vec!["network-broker", "channels", "create", "--name", "edge"],
            vec![
                "network-broker",
                "channels",
                "update",
                &channel,
                "--name",
                "x",
            ],
            vec!["eula", "accept", "--force"],
            vec![
                "scan",
                "--target",
                &target,
                "--name",
                "nightly",
                "--no-wait",
            ],
        ] {
            let Some((r, t)) = sides(
                "write_outputs_and_requests_match_typescript",
                &args,
                &unchanged,
                files,
            ) else {
                return;
            };
            assert_moved(&r, &t);
        }
    }

    /// `targets init`: the same scaffold bytes, outputs and requests (D145 move).
    #[test]
    fn init_scaffolds_match_typescript() {
        for provider in ["rest", "openai", "custom_target_adapter", "STREAMING"] {
            let Some(ts) = require_ts("init_scaffolds_match_typescript") else {
                return;
            };
            let options = RunOptions::new().allow_writes_under("cwd");
            let r = exec(
                &rust(),
                &["targets", "init", provider],
                &unchanged,
                &[],
                &options,
            );
            let t = exec(
                &ts,
                &["targets", "init", provider],
                &unchanged,
                &[],
                &options,
            );
            let name = format!("{}-target.json", provider.to_lowercase());
            let read =
                |side: &Side| std::fs::read_to_string(side.sandbox.cwd().join(&name)).unwrap();
            assert_eq!(read(&r), read(&t), "{provider}");
            let path = |side: &Side| side.sandbox.cwd().join(&name).display().to_string();
            // The absolute paths differ by sandbox only.
            let (moved, data) = ts_moved(&t.run.stdout.replace(&path(&t), &path(&r)));
            assert_eq!(r.run.stdout, data, "{provider}");
            assert_eq!(r.run.stderr, moved, "{provider}");
            assert_eq!(api(&r), api(&t));
        }
    }

    /// The scan wait: the same requests and the same data blocks (the progress moved to
    /// stderr, D135).
    #[test]
    fn the_scan_wait_matches_typescript_but_for_the_progress() {
        let target = fx::target_id(1);
        let Some((r, t)) = sides(
            "the_scan_wait_matches_typescript_but_for_the_progress",
            &[
                "scan",
                "--target",
                &target,
                "--name",
                "waited",
                "--categories",
                r#"{"A":["B"]}"#,
            ],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, t.run.code);
        assert_eq!(without_clock(&r.requests), without_clock(&t.requests));
        let progress = "\r  COMPLETED ████████████████████ 100% (40/40)\n\n";
        let (moved, data) = ts_moved(&t.run.stdout.replace(progress, ""));
        assert_eq!(r.run.stdout, data);
        assert_eq!(
            r.run.stderr,
            format!(
                "{}  COMPLETED ████████████████████ 100% (40/40)\n{moved}",
                t.run.stderr
            )
        );
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D133: a write answered 5xx is one airs-cli-rs request with the unknown-outcome
    /// line; TypeScript re-sends it (at least once more).
    #[test]
    fn d133_red_team_writes_are_one_attempt() {
        let target = fx::target_id(1);
        for (args, route) in [
            (
                vec![
                    "scan",
                    "--target",
                    &target,
                    "--name",
                    "busy",
                    "--categories",
                    r#"{"A":["B"]}"#,
                    "--no-wait",
                ],
                Rt::ScanCreate,
            ),
            (vec!["registry-credentials"], Rt::RegistryCredentials),
            (vec!["eula", "accept", "--force"], Rt::EulaAccept),
        ] {
            let Some(ts) = require_ts("d133_red_team_writes_are_one_attempt") else {
                return;
            };
            let busy = |side: &Side| side.server.rt_requests(route).len();
            let run_side = |cli: &Cli| {
                let server = FixtureServer::start();
                server.seed_redteam();
                server.set_default(
                    Route::RedTeam(route),
                    Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
                );
                let sandbox = Sandbox::new();
                sandbox.single_tenant(&server, "prod", TSG);
                let mut full = vec!["redteam"];
                full.extend(args.iter().copied());
                let options = if cli.is_ts() {
                    RunOptions::new().allow_secret_output()
                } else {
                    RunOptions::new()
                };
                let out = run(cli, &sandbox, &full, &options);
                Side {
                    run: out,
                    requests: Vec::new(),
                    lines: Vec::new(),
                    server,
                    sandbox,
                }
            };
            let r = run_side(&rust());
            let t = run_side(&ts);
            assert_eq!(r.run.code, 1);
            assert_eq!(busy(&r), 1, "{route:?}: airs sends one write");
            assert!(r.run.stderr.contains("Outcome unknown: the "), "{route:?}");
            assert_eq!(t.run.code, 1);
            assert!(busy(&t) > 1, "{route:?}: TypeScript re-sends the write");
        }
    }

    /// D134: a scan argument error is exit 2 before the tenant with no request; TypeScript
    /// reads the categories and fails in the SDK with exit 1.
    #[test]
    fn d134_scan_argument_checks_come_before_the_tenant() {
        let target = fx::target_id(1);
        let Some((r, t)) = sides(
            "d134_scan_argument_checks_come_before_the_tenant",
            &["scan", "--target", &target, "--name", "ab"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert!(r.requests.is_empty());
        assert_eq!(
            r.run.stderr,
            "\n  ✗ AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema: name: too_small\n\n"
        );
        assert_eq!(t.run.code, 1);
        assert_eq!(api(&t), ["GET /redteam/data/v1/categories"]);
        assert!(t.run.stderr.contains("name"), "{}", t.run.stderr);
        let Some((r, t)) = sides(
            "d134_scan_argument_checks_come_before_the_tenant",
            &[
                "scan",
                "--target",
                &target,
                "--name",
                "abc",
                "--depth",
                "3",
                "--no-wait",
            ],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2, "--depth applies only to DYNAMIC");
        assert_eq!(t.run.code, 0, "TypeScript ignores it and starts a scan");
        assert_eq!(t.server.rt_requests(Rt::ScanCreate).len(), 1);
    }

    /// D135: the progress goes to stderr (one line per change off a terminal); TypeScript
    /// writes it to stdout with `\r`.
    #[test]
    fn d135_scan_progress_goes_to_stderr() {
        let target = fx::target_id(1);
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.scan_polls
                .push_back(json!({"status": "RUNNING", "completed": 10}));
        };
        let Some((r, t)) = sides(
            "d135_scan_progress_goes_to_stderr",
            &[
                "scan",
                "--target",
                &target,
                "--name",
                "progress",
                "--categories",
                r#"{"A":["B"]}"#,
            ],
            &seed,
            &[],
        ) else {
            return;
        };
        let line = "RUNNING █████░░░░░░░░░░░░░░░ 25% (10/40)";
        assert!(
            r.run.stderr.contains(&format!("  {line}\n")),
            "{}",
            r.run.stderr
        );
        assert!(!r.run.stdout.contains(line));
        assert!(
            t.run.stdout.contains(&format!("\r  {line}")),
            "{}",
            t.run.stdout
        );
        assert!(!t.run.stderr.contains(line));
    }

    /// D136: an aborted scan exits 1 with the error and empty stdout; TypeScript prints
    /// the completion block and exits 0.
    #[test]
    fn d136_an_aborted_scan_exits_1() {
        let target = fx::target_id(1);
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.scan_polls.push_back(json!({"status": "ABORTED"}));
        };
        let Some((r, t)) = sides(
            "d136_an_aborted_scan_exits_1",
            &[
                "scan",
                "--target",
                &target,
                "--name",
                "stopped",
                "--categories",
                r#"{"A":["B"]}"#,
            ],
            &seed,
            &[],
        ) else {
            return;
        };
        let id = fixtures_uuid(181);
        assert_eq!(r.run.code, 1);
        assert_eq!(r.run.stdout, "");
        assert!(
            r.run
                .stderr
                .contains(&format!("✗ Error: Scan {id} was aborted"))
        );
        assert_eq!(t.run.code, 0);
        assert!(t.run.stdout.contains("Status    ABORTED"));
    }

    fn fixtures_uuid(n: u64) -> String {
        airs_test_harness::fixtures::uuid(n)
    }

    /// D137: `abort`, `prompts delete`, `instances delete` and `devices delete` confirm:
    /// without a terminal and `--force` they are exit 2 with no request; TypeScript sends
    /// the write at once (it has no `--force` for them).
    #[test]
    fn d137_destructive_commands_confirm() {
        let job = fx::job_id(2);
        let set = fx::prompt_set_id(1);
        let prompt = fx::prompt_id(1);
        for (args, route) in [
            (vec!["abort", &job], Rt::ScanAbort),
            (vec!["prompts", "delete", &set, &prompt], Rt::PromptDelete),
            (vec!["instances", "delete", "ten-1"], Rt::InstanceDelete),
            (
                vec!["devices", "delete", "ten-1", "--serial-numbers", "SN1"],
                Rt::DevicesDelete,
            ),
        ] {
            let Some((r, t)) = sides("d137_destructive_commands_confirm", &args, &unchanged, &[])
            else {
                return;
            };
            assert_eq!(r.run.code, 2, "{args:?}");
            assert!(
                r.run
                    .stderr
                    .contains("without --force in non-interactive mode")
            );
            assert!(r.requests.is_empty());
            assert_eq!(t.run.code, 0, "{args:?}");
            assert_eq!(t.server.rt_requests(route).len(), 1, "{args:?}");
        }
    }

    /// D138: `eula accept` without a terminal and without `--force` is exit 2 before the
    /// tenant; TypeScript prints the EULA and `Pass --force to accept.` and exits 0.
    #[test]
    fn d138_eula_accept_needs_force_without_a_terminal() {
        let Some((r, t)) = sides(
            "d138_eula_accept_needs_force_without_a_terminal",
            &["eula", "accept"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ refusing to accept the Red Team EULA without --force in non-interactive mode\n\n"
        );
        assert!(r.requests.is_empty());
        assert_eq!(t.run.code, 0);
        assert!(t.run.stdout.contains("FIXTURE EULA TEXT v1"));
        assert!(t.run.stdout.contains("Pass --force to accept."));
        assert!(t.server.rt_requests(Rt::EulaAccept).is_empty());
    }

    /// D158: a `--serial-numbers` list that names no serial number is exit 2 with no
    /// request; TypeScript sends the delete with that list (`serial_numbers=` for `""`).
    #[test]
    fn d158_an_empty_serial_list_is_refused() {
        for (list, query) in [("", ""), (" , ", "+%2C+")] {
            let Some((r, t)) = pair(
                "d158_an_empty_serial_list_is_refused",
                &[
                    "devices",
                    "delete",
                    "ten-1",
                    "--serial-numbers",
                    list,
                    "--force",
                ],
                &["devices", "delete", "ten-1", "--serial-numbers", list],
                &unchanged,
                &[],
            ) else {
                return;
            };
            assert_eq!(r.run.code, 2, "{list:?}");
            assert_eq!(
                r.run.stderr,
                "\n  ✗ --serial-numbers needs at least one serial number\n\n"
            );
            assert!(r.requests.is_empty());
            assert_eq!(t.run.code, 0, "{list:?}{}", context(&r, &t));
            assert_eq!(
                api(&t),
                [format!(
                    "DELETE /redteam/mgmt/v1/instances/ten-1/devices?serial_numbers={query}"
                )],
                "{list:?}"
            );
        }
    }

    /// D159: an empty EULA is refused after the content read (exit 1, no accept);
    /// TypeScript accepts it with `--force` (`eula_content: ""`).
    #[test]
    fn d159_an_empty_eula_is_not_accepted() {
        let empty = |data: &mut airs_test_harness::RedTeamData| {
            data.eula_content = fx::eula_content("");
        };
        let Some((r, t)) = sides(
            "d159_an_empty_eula_is_not_accepted",
            &["eula", "accept", "--force"],
            &empty,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert_eq!(
            r.run.error_line().as_deref(),
            Some("The service returned no EULA content, so there is nothing to accept")
        );
        assert_eq!(api(&r), ["GET /redteam/mgmt/v1/eula/content"]);
        assert_eq!(t.run.code, 0, "{}", context(&r, &t));
        let accepted = t.server.rt_requests(Rt::EulaAccept);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].body_json().unwrap()["eula_content"], "");
    }

    /// D139: the registry token is withheld in pretty (TypeScript prints its first 20
    /// characters).
    #[test]
    fn d139_the_registry_token_is_withheld() {
        let Some((r, t)) = sides(
            "d139_the_registry_token_is_withheld",
            &["registry-credentials"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        let token = airs_test_harness::REGISTRY_TOKEN;
        assert!(
            r.run
                .stdout
                .contains("Token   (withheld; use --output json to print it)")
        );
        assert!(!r.run.stdout.contains(&token[..20]));
        assert!(
            t.run
                .stdout
                .contains(&format!("Token   {}...", &token[..20]))
        );
    }

    /// D140 (writes): the validate-auth token preview and the credentials an
    /// update-profile answer carries are redacted; TypeScript prints them.
    #[test]
    fn d140_write_answers_are_redacted() {
        let auth: &[u8] = br#"{"auth_header":{"X-Org":"acme"}}"#;
        let profile: &[u8] = br#"{"target_background":{"industry":"Finance"}}"#;
        let target = fx::target_id(1);
        for args in [
            vec![
                "targets",
                "validate-auth",
                "--auth-type",
                "HEADERS",
                "--config",
                "@a.json",
            ],
            vec!["targets", "update-profile", &target, "--config", "@p.json"],
        ] {
            let Some((r, t)) = sides(
                "d140_write_answers_are_redacted",
                &args,
                &unchanged,
                &[("a.json", auth), ("p.json", profile)],
            ) else {
                return;
            };
            assert_eq!(r.run.code, 0);
            assert!(r.run.stdout.contains("[REDACTED]"), "{args:?}");
            assert!(!r.run.stdout.contains("FAKE-TARGET-SECRET"));
            assert!(t.run.stdout.contains("FAKE-TARGET-SECRET"), "{args:?}");
            assert_eq!(without_clock(&r.requests), without_clock(&t.requests));
        }
    }

    /// D141 (writes): a traversing tenant id is refused before the tenant (TypeScript
    /// sends `DELETE /v1/registry-credentials`); an update without a field is a usage
    /// error (TypeScript sends `{}`).
    #[test]
    fn d141_write_arguments_are_checked_before_the_tenant() {
        let Some((r, t)) = pair(
            "d141_write_arguments_are_checked_before_the_tenant",
            &["instances", "delete", "../registry-credentials", "--force"],
            &["instances", "delete", "../registry-credentials"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert!(r.requests.is_empty());
        assert_eq!(api(&t), ["DELETE /redteam/mgmt/v1/registry-credentials"]);
        let set = fx::prompt_set_id(1);
        let Some((r, t)) = sides(
            "d141_write_arguments_are_checked_before_the_tenant",
            &["prompt-sets", "update", &set],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Specify --name and/or --description to update\n\n"
        );
        assert_eq!(t.run.code, 0);
        assert_eq!(
            serde_json::from_slice::<Value>(&t.server.rt_requests(Rt::PromptSetUpdate)[0].body)
                .unwrap(),
            json!({})
        );
    }

    /// D143: input files are read before the tenant with fixed messages, and script
    /// bytes are encoded as read (TypeScript decodes them as UTF-8 first).
    #[test]
    fn d143_input_files_are_read_before_the_tenant() {
        let Some((r, t)) = sides(
            "d143_input_files_are_read_before_the_tenant",
            &["targets", "create", "--config", "@missing.json"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert!(r.requests.is_empty());
        assert!(
            r.run
                .stderr
                .contains("(missing, not a regular file, unreadable or larger than 1 MiB)")
        );
        assert_eq!(t.run.code, 1);
        assert!(t.run.stderr.contains("ENOENT"), "{}", t.run.stderr);
        let script: &[u8] = b"print('hi')\n\xff";
        let Some((r, t)) = sides(
            "d143_input_files_are_read_before_the_tenant",
            &[
                "adapter",
                "create",
                "--name",
                "n",
                "--prompt",
                "p",
                "--script-file",
                "@a.py",
                "--draft",
            ],
            &unchanged,
            &[("a.py", script)],
        ) else {
            return;
        };
        let sent = |side: &Side| {
            serde_json::from_slice::<Value>(&side.server.rt_requests(Rt::AdapterCreate)[0].body)
                .unwrap()["script_b64"]
                .clone()
        };
        assert_eq!(sent(&r), "cHJpbnQoJ2hpJykK/w==");
        assert_eq!(sent(&t), "cHJpbnQoJ2hpJykK77+9");
    }

    /// D144 (writes): `--output json` and `table` are honoured by the writes; TypeScript
    /// prints pretty whatever the value.
    #[test]
    fn d144_writes_honour_output() {
        let set = fx::prompt_set_id(1);
        let Some((r, t)) = sides(
            "d144_writes_honour_output",
            &["prompts", "add", &set, "--prompt", "hi", "--output", "json"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.json()["prompt"], "hi");
        assert!(t.run.stdout.starts_with(BANNER), "{}", t.run.stdout);
    }

    /// D145 (writes): outcome lines go to stderr and `--quiet` drops them; the banner
    /// appears only above data. TypeScript prints both on stdout, also under `--quiet`.
    #[test]
    fn d145_write_outcome_lines_go_to_stderr() {
        let set = fx::prompt_set_id(1);
        let Some((r, t)) = sides(
            "d145_write_outcome_lines_go_to_stderr",
            &["prompt-sets", "archive", &set, "--quiet"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, "");
        assert_eq!(r.run.stderr, "");
        assert_eq!(t.run.stdout, format!("  ✓ Prompt set {set} archived.\n"));
    }

    /// D149: an empty 2xx body from `properties create` is a success; TypeScript fails
    /// with exit 1 after the property was created.
    #[test]
    fn d149_an_empty_property_create_answer_succeeds() {
        let seed = |data: &mut airs_test_harness::RedTeamData| data.empty_property_create = true;
        let Some((r, t)) = sides(
            "d149_an_empty_property_create_answer_succeeds",
            &["properties", "create", "--name", "tone"],
            &seed,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 0);
        assert_eq!(r.run.stderr, "  ✓ Property name created\n");
        assert_eq!(t.run.code, 1);
        assert!(t.run.stderr.contains("Cannot read properties of undefined"));
    }

    /// D150: the scaffold is created at 0600 (TypeScript 0644).
    #[test]
    fn d150_init_creates_the_scaffold_privately() {
        use std::os::unix::fs::PermissionsExt;
        let Some(ts) = require_ts("d150_init_creates_the_scaffold_privately") else {
            return;
        };
        let options = RunOptions::new().allow_writes_under("cwd");
        let mode = |side: &Side| {
            std::fs::metadata(side.sandbox.cwd().join("rest-target.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        let r = exec(
            &rust(),
            &["targets", "init", "rest"],
            &unchanged,
            &[],
            &options,
        );
        let t = exec(&ts, &["targets", "init", "rest"], &unchanged, &[], &options);
        assert_eq!(mode(&r), 0o600);
        // TypeScript's `writeFileSync` creates with 0666 minus the umask, like any file.
        let probe = t.sandbox.tmp().join("umask-probe");
        std::fs::write(&probe, b"").unwrap();
        let default_mode = std::fs::metadata(&probe).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&t), default_mode);
    }

    /// D154: an argv `SECRET` variable value is refused; TypeScript sends it.
    #[test]
    fn d154_secret_variables_are_refused_on_argv() {
        let variables = r#"[{"key":"t","value":"FAKE-ARGV-VALUE","type":"SECRET"}]"#;
        let Some((r, t)) = sides(
            "d154_secret_variables_are_refused_on_argv",
            &[
                "adapter",
                "create",
                "--name",
                "n",
                "--prompt",
                "p",
                "--script-b64",
                "eA==",
                "--variables",
                variables,
                "--draft",
            ],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert!(r.requests.is_empty());
        assert_eq!(t.run.code, 0);
        assert_eq!(t.server.rt_requests(Rt::AdapterCreate).len(), 1);
    }

    /// D11 (writes): a failed write prints `API error <status>`, never the server's
    /// message; TypeScript echoes it.
    #[test]
    fn d11_red_team_write_errors_never_echo_server_text() {
        let unknown = airs_test_harness::fixtures::uuid(399);
        let Some((r, t)) = sides(
            "d11_red_team_write_errors_never_echo_server_text",
            &["prompt-sets", "update", &unknown, "--name", "x"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert_eq!(
            r.run.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 404")
        );
        assert!(!r.run.stderr.contains("Prompt set not found"));
        assert_eq!(t.run.code, 1);
        assert!(
            t.run.stderr.contains("Prompt set not found"),
            "{}",
            t.run.stderr
        );
    }

    /// D52 (writes): server text in an outcome line is terminal-safe; TypeScript writes
    /// the escape sequence raw.
    #[test]
    fn d52_write_outcome_lines_are_terminal_safe() {
        let Some(ts) = require_ts("d52_write_outcome_lines_are_terminal_safe") else {
            return;
        };
        let run_side = |cli: &Cli| {
            let server = FixtureServer::start();
            server.seed_redteam();
            server.push_once(
                Route::RedTeam(Rt::PropertyCreate),
                Planned::json(
                    200,
                    &json!({"message": "made\u{1b}[31m red", "status": 200}),
                ),
            );
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            run(
                cli,
                &sandbox,
                &["redteam", "properties", "create", "--name", "tone"],
                &RunOptions::new().allow_secret_output(),
            )
        };
        let r = run_side(&rust());
        let t = run_side(&ts);
        assert_eq!(r.stderr, "  ✓ made\u{fffd}[31m red\n");
        assert!(t.stdout.contains("made\u{1b}[31m red"));
    }

    /// D116 (red team bodies): a body that fails its schema is refused without the field
    /// list; TypeScript names the fields.
    #[test]
    fn d116_red_team_body_text_without_field_paths() {
        let Some((r, t)) = sides(
            "d116_red_team_body_text_without_field_paths",
            &["devices", "create", "ten-1", "--config", "@d.json"],
            &unchanged,
            &[("d.json", br#"{"devices":[]}"#)],
        ) else {
            return;
        };
        let message = "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/instances/ten-1/devices did not match schema";
        assert_eq!(r.run.code, 1);
        assert_eq!(r.run.error_line().as_deref(), Some(message));
        assert!(r.requests.is_empty());
        assert_eq!(t.run.code, 1);
        let ts_line = t.run.error_line().unwrap_or_default();
        assert!(ts_line.starts_with(&format!("{message}: ")), "{ts_line}");
    }

    /// D153 (writes): the create, update, probe and update-profile answers are printed
    /// as the server sent them; TypeScript adds its schema default
    /// `ws_response_timeout: 110` to each and prints it. The requests and the outcome
    /// lines are the same, and the airs-cli-rs json document has no such key either.
    #[test]
    fn d153_write_answers_print_only_the_fields_the_server_sent() {
        let target = fx::target_id(1);
        let body = plain_target("plain", None);
        let profile: &[u8] = br#"{"target_background":{"industry":"Finance"}}"#;
        let files: Files<'_> = &[("t.json", &body), ("p.json", profile)];
        for (args, settings) in [
            (
                vec!["targets", "create", "--config", "@t.json"],
                "connectionParams",
            ),
            (
                vec!["targets", "update", &target, "--config", "@t.json"],
                "connectionParams",
            ),
            (
                vec!["targets", "probe", "--config", "@t.json"],
                "connection_params",
            ),
            (
                vec!["targets", "update-profile", &target, "--config", "@p.json"],
                "connection_params",
            ),
        ] {
            let Some((r, t)) = sides(
                "d153_write_answers_print_only_the_fields_the_server_sent",
                &args,
                &unchanged,
                files,
            ) else {
                return;
            };
            assert_eq!(r.run.code, 0, "{args:?}{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{args:?}{}", context(&r, &t));
            assert!(
                t.run.stdout.contains("  ws_response_timeout  110\n")
                    || t.run.stdout.contains("\"ws_response_timeout\": 110"),
                "{args:?}{}",
                context(&r, &t)
            );
            assert!(!r.run.stdout.contains("ws_response_timeout"), "{args:?}");
            let (moved, _) = ts_moved(&t.run.stdout);
            assert_eq!(r.run.stderr, format!("{}{moved}", t.run.stderr), "{args:?}");
            assert_eq!(without_clock(&r.requests), without_clock(&t.requests));
            let mut json_args = args.clone();
            json_args.extend(["--output", "json"]);
            let doc = exec(&rust(), &json_args, &unchanged, files, &RunOptions::new());
            doc.run.assert_success();
            let doc = doc.run.json();
            assert!(doc[settings].is_object(), "{args:?}: {doc}");
            assert!(
                doc[settings].get("ws_response_timeout").is_none(),
                "{args:?}"
            );
        }
    }

    /// D304: TypeScript sends `--depth`/`--breadth` above 20 in the scan body (the
    /// service decides); airs-cli-rs refuses them before the tenant, as the vendor body
    /// allows 1 to 20, and both send 20.
    #[test]
    fn d304_scan_streams_are_at_most_20() {
        let target = fx::target_id(1);
        for (flag, key) in [("--depth", "stream_depth"), ("--breadth", "stream_breadth")] {
            let Some((r, t)) = sides(
                "d304_scan_streams_are_at_most_20",
                &[
                    "scan",
                    "--target",
                    &target,
                    "--name",
                    "deep",
                    "--type",
                    "DYNAMIC",
                    flag,
                    "21",
                    "--no-wait",
                ],
                &unchanged,
                &[],
            ) else {
                return;
            };
            assert_eq!(r.run.code, 2, "{}", context(&r, &t));
            assert_eq!(r.run.stdout, "");
            assert_eq!(
                r.run.stderr,
                format!("\n  ✗ {flag} must be at most 20 (the red team API maximum)\n\n")
            );
            assert!(r.requests.is_empty());
            t.run.assert_success();
            let sent = t.server.rt_requests(Rt::ScanCreate);
            assert_eq!(sent.len(), 1, "TypeScript starts the scan");
            let body: Value = serde_json::from_slice(&sent[0].body).unwrap();
            assert_eq!(body["job_metadata"][key], 21);
        }
        let args = [
            "scan",
            "--target",
            &target,
            "--name",
            "deep",
            "--type",
            "DYNAMIC",
            "--depth",
            "20",
            "--breadth",
            "20",
            "--no-wait",
        ];
        let Some((r, t)) = sides("d304_scan_streams_are_at_most_20", &args, &unchanged, &[]) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let bodies: Vec<Value> = [&r, &t]
            .iter()
            .map(|side| {
                let sent = side.server.rt_requests(Rt::ScanCreate);
                assert_eq!(sent.len(), 1);
                serde_json::from_slice::<Value>(&sent[0].body).unwrap()["job_metadata"].clone()
            })
            .collect();
        assert_eq!(bodies[0], json!({"stream_breadth": 20, "stream_depth": 20}));
        assert_eq!(bodies[0], bodies[1]);
    }

    /// D305: a name of three UTF-16 units but two code points passes the TypeScript
    /// schema and is sent; airs-cli-rs refuses it before the tenant with the TS text,
    /// as the vendor body counts code points.
    #[test]
    fn d305_scan_names_need_three_code_points() {
        let target = fx::target_id(1);
        let name = "\u{1F600}a";
        let Some((r, t)) = sides(
            "d305_scan_names_need_three_code_points",
            &["scan", "--target", &target, "--name", name, "--no-wait"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2, "{}", context(&r, &t));
        assert_eq!(r.run.stdout, "");
        assert_eq!(
            r.run.stderr,
            "\n  ✗ AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema: name: too_small\n\n"
        );
        assert!(r.requests.is_empty());
        t.run.assert_success();
        let sent = t.server.rt_requests(Rt::ScanCreate);
        assert_eq!(sent.len(), 1, "TypeScript starts the scan");
        let body: Value = serde_json::from_slice(&sent[0].body).unwrap();
        assert_eq!(body["name"], name);
        // Three code points are sent by both.
        let name = "\u{1F600}\u{1F600}a";
        let Some((r, t)) = sides(
            "d305_scan_names_need_three_code_points",
            &["scan", "--target", &target, "--name", name, "--no-wait"],
            &unchanged,
            &[],
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        assert_eq!(r.requests, t.requests, "{}", context(&r, &t));
    }

    /// D307: an adapter whose stored channel is not a UUID. TypeScript's response schema
    /// refuses the read inside `adapter update` (`AISEC_RESPONSE_VALIDATION`, exit 1), as
    /// 0.9.0 did; scm-sdk 0.2.2 accepts the read (D306), so airs-cli-rs refuses the
    /// carried value before the PUT with a message that names the field and `--channel`.
    /// Both send only the read, and with `--channel` airs-cli-rs sends the update.
    #[test]
    fn d307_a_stored_channel_that_is_not_a_uuid_is_named() {
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.adapters[0]["network_broker_channel_uuid"] = json!("chan-1");
        };
        let adapter = fx::adapter_id(1);
        let get = format!("GET /redteam/mgmt/v1/adapters/{adapter}");
        let Some((r, t)) = sides(
            "d307_a_stored_channel_that_is_not_a_uuid_is_named",
            &[
                "adapter", "update", &adapter, "--name", "renamed", "--prompt", "hello",
            ],
            &seed,
            &[],
        ) else {
            return;
        };
        assert_eq!(t.run.code, 1, "{}", context(&r, &t));
        assert!(
            t.run.stderr.contains(
                "AISEC_RESPONSE_VALIDATION:Response did not match schema: network_broker_channel_uuid: invalid_string"
            ),
            "{}",
            t.run.stderr
        );
        assert_eq!(api(&t), std::slice::from_ref(&get));
        assert_eq!(r.run.code, 1, "{}", context(&r, &t));
        assert_eq!(r.run.stdout, "");
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Error: The stored adapter's network_broker_channel_uuid is not a UUID, so \
             the update cannot send it back; pass --channel <channelId> to replace it\n\n"
        );
        assert_eq!(api(&r), [get]);
        let channel = fx::channel_id(1);
        let Some((r, t)) = sides(
            "d307_a_stored_channel_that_is_not_a_uuid_is_named",
            &[
                "adapter",
                "update",
                &adapter,
                "--name",
                "renamed",
                "--prompt",
                "hello",
                "--channel",
                &channel,
                "--draft",
            ],
            &seed,
            &[],
        ) else {
            return;
        };
        assert_eq!(t.run.code, 1, "{}", context(&r, &t));
        r.run.assert_success();
        assert_eq!(r.server.rt_requests(Rt::AdapterUpdate).len(), 1);
    }

    /// D328: the management 0.86.0 request values (scm-sdk 0.2.3) are sent by
    /// airs-cli-rs and refused by the frozen TypeScript request schema with its field
    /// list (exit 1, nothing sent): `connection_type` `VERTEX_AI` and `N8N`,
    /// `response_mode` `REALTIME`, the `client_session` multi-turn config and a Vertex AI
    /// connection config. The pass-through additions (`audio_request_json`,
    /// `audio_curl`, `basic_username`, `basic_password`) are sent by both, the same body.
    #[test]
    fn d328_management_0_86_request_values_are_sent() {
        let base: Value =
            serde_json::from_slice(&plain_target("Vertex Realtime", Some(110))).unwrap();
        // (the field TypeScript names, the settings key or none, the key, the value)
        let edits = [
            (
                "connection_type",
                None,
                "connection_type",
                json!("VERTEX_AI"),
            ),
            ("connection_type", None, "connection_type", json!("N8N")),
            ("response_mode", None, "response_mode", json!("REALTIME")),
            (
                "connection_params",
                Some("connection_params"),
                "multi_turn_config",
                json!({"type": "client_session"}),
            ),
            (
                "connection_params",
                Some("connection_params"),
                "target_connection_config",
                fx::vertex_connection_config(),
            ),
        ];
        for (field, settings, key, value) in edits {
            let mut body = base.clone();
            match settings {
                Some(settings) => body[settings][key] = value,
                None => body[key] = value,
            }
            let bytes = serde_json::to_vec(&body).unwrap();
            let Some((r, t)) = sides(
                "d328_management_0_86_request_values_are_sent",
                &["targets", "create", "--config", "@t.json"],
                &unchanged,
                &[("t.json", &bytes)],
            ) else {
                return;
            };
            assert_eq!(t.run.code, 1, "{body}{}", context(&r, &t));
            let ts_line = t.run.error_line().unwrap_or_default();
            assert!(
                ts_line.starts_with(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/target did not match schema: "
                ) && ts_line.contains(field),
                "{body}: {ts_line}"
            );
            assert!(api(&t).is_empty(), "{:?}", api(&t));
            r.run.assert_success();
            assert_eq!(api(&r), ["POST /redteam/mgmt/v1/target"], "{body}");
            let sent: Value =
                serde_json::from_slice(&r.server.rt_requests(Rt::TargetCreate)[0].body).unwrap();
            assert_eq!(sent, body);
        }
        // The pass-through additions: both CLIs send the same body.
        let mut body = base;
        body["connection_params"]["audio_request_json"] = json!({"audio": "{AUDIO}"});
        body["connection_params"]["audio_curl"] = json!("curl https://x.invalid/v1/audio");
        body["auth_type"] = json!("BASIC_AUTH");
        body["auth_config"] = json!({"basic_auth_location": "HEADER", "basic_username": "svc", "basic_password": fx::secret(27)});
        let bytes = serde_json::to_vec(&body).unwrap();
        let Some((r, t)) = sides(
            "d328_management_0_86_request_values_are_sent",
            &[
                "targets", "create", "--config", "@t.json", "--output", "json",
            ],
            &unchanged,
            &[("t.json", &bytes)],
        ) else {
            return;
        };
        assert_eq!(t.run.code, 0, "{}", context(&r, &t));
        r.run.assert_success();
        assert_eq!(without_clock(&r.requests), without_clock(&t.requests));
        assert_eq!(r.run.json()["connectionParams"]["audio_curl"], "[REDACTED]");
        // TypeScript prints the template raw (its `--output` is ignored for writes, D144).
        assert!(
            t.run.stdout.contains("curl https://x.invalid/v1/audio"),
            "{}",
            t.run.stdout
        );
        let sent: Value =
            serde_json::from_slice(&r.server.rt_requests(Rt::TargetCreate)[0].body).unwrap();
        assert_eq!(sent, body);
    }
}
