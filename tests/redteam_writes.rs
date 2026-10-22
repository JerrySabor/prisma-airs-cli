//! Executable acceptance tests for the M6a step-2 red team writes and the scan (DESIGN
//! §15.1–§15.15): `redteam scan` (with its wait), `abort`, `eula accept`,
//! `registry-credentials`, `instances create|update|delete`, `devices
//! create|update|delete`, `prompt-sets create|update|archive|upload`, `prompts
//! add|update|delete`, `properties create|add-value`, `targets
//! create|update|delete|probe|update-profile|validate-auth|init`, `adapter
//! create|update|delete|validate` and `network-broker channels create|update`.
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server, whose
//! write routes change the seeded dataset (a later read sees the change) and record
//! every request, so each test proves how many writes were sent: one attempt, the
//! single 401 replay, never a 403 replay or a 5xx re-send (D133). The fixture
//! credentials and every credential the tests put in input files are
//! `FAKE-TARGET-SECRET-<n>` markers, which the runner's leak check treats as secrets
//! for airs-cli-rs runs (D140). The write cases of the TypeScript
//! `tests/unit/airs/redteam.spec.ts`, `redteam-adapters.spec.ts` and the
//! `redteam-scan-helpers`, `redteam-adapter-helpers` and `redteam-init` specs are
//! ported here (the pure helpers also as unit tests in `src/redteam/args.rs`).

use std::time::Duration;

use airs_test_harness::fixtures::redteam as fx;
use airs_test_harness::{
    Cli, FixtureServer, Planned, PtyRun, RecordedRequest, Route, Rt, Run, RunOptions, Sandbox,
    fixtures, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n";
const DEBUG_HINT: &str = "    Re-run with --debug to capture redacted API diagnostics.\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seeded red team dataset and one standard tenant `prod` (TSG 100).
fn fx() -> Fx {
    let server = FixtureServer::start();
    server.seed_redteam();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |_| {});
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

/// A sandbox with no tenant at all: usage errors must not need one.
fn bare() -> Fx {
    Fx {
        server: FixtureServer::start(),
        sandbox: Sandbox::new(),
    }
}

/// `["redteam", …args]`.
fn rt(args: &[&str]) -> Vec<String> {
    std::iter::once("redteam")
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect()
}

impl Fx {
    /// `redteam <args>`, with the loopback and no-stray-files checks.
    fn rt(&self, args: &[&str]) -> Run {
        self.rt_with(args, &RunOptions::new())
    }

    fn rt_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let args = rt(args);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run(&rust(), &self.sandbox, &args, options);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        out
    }

    /// The `METHOD /path?query` of every API request (the token request left out).
    fn api(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    /// The routes of every request, the token included.
    fn routes(&self) -> Vec<Route> {
        self.server.routes()
    }

    /// The JSON body of the only request on `route`.
    fn body(&self, route: Rt) -> Value {
        let requests = self.server.rt_requests(route);
        assert_eq!(requests.len(), 1, "{route:?}: {requests:?}");
        serde_json::from_slice(&requests[0].body).unwrap()
    }

    /// A file under the sandbox's `tmp/`; its absolute path.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.sandbox.tmp().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    }

    fn clear(&self) {
        self.server.clear_requests();
    }
}

/// The exact stderr error block (no `--debug`).
fn error_block(message: &str, status: Option<u16>, details: &[&str]) -> String {
    let mut text = format!("\n  ✗ Error: {message}\n");
    if let Some(status) = status {
        text.push_str(&format!("    HTTP {status}\n{DEBUG_HINT}"));
    }
    for line in details {
        text.push_str(&format!("    {line}\n"));
    }
    text.push('\n');
    text
}

fn usage_block(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
}

/// A usage error in a sandbox without any tenant: exit 2, the exact message, no
/// request, nothing on stdout.
fn assert_usage(args: &[&str], message: &str) {
    let f = bare();
    let out = f.rt(args);
    out.assert_code(2);
    assert_eq!(out.stdout, "", "{args:?}");
    assert_eq!(out.stderr, usage_block(message), "{args:?}");
    assert_eq!(f.server.request_count(), 0, "{args:?}");
}

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

/// A target create body whose credentials are markers 21–23.
fn target_config(name: &str) -> Value {
    json!({
        "name": name,
        "target_type": "APPLICATION",
        "connection_type": "CUSTOM",
        "api_endpoint_type": "PUBLIC",
        "response_mode": "REST",
        "connection_params": {
            "api_endpoint": "https://new.invalid/v1/chat",
            "request_headers": {"Content-Type": "application/json", "apikey": fx::secret(21)},
            "request_json": {"messages": [{"role": "user", "content": "{INPUT}"}]},
            "response_json": {"choices": [{"message": {"content": "{RESPONSE}"}}]},
            "response_key": "choices.0.message.content"
        },
        "auth_type": "HEADERS",
        "auth_config": {"auth_header": {"Authorization": format!("Bearer {}", fx::secret(22))}},
        "extra_info": {"token": fx::secret(23)}
    })
}

/// The id the fixture gives the `n`th record a write route creates.
fn created(base: u64, n: u64) -> String {
    fixtures::uuid(base + n)
}

// ---------------------------------------------------------------------------
// `redteam scan` (§15.6, D133–D136)
// ---------------------------------------------------------------------------

mod scan {
    use super::*;

    fn target() -> String {
        fx::target_id(1)
    }

    /// TS `createScan` STATIC without `--categories`: the categories read, the default
    /// (MULTI_TURN excluded) and its status line, one POST, then the wait.
    #[test]
    fn static_defaults_to_every_category_but_multi_turn() {
        let f = fx();
        let t = target();
        let out = f.rt(&["scan", "--target", &t, "--name", "nightly", "--no-wait"]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                "GET /redteam/data/v1/categories".to_owned(),
                "POST /redteam/data/v1/scan".to_owned()
            ]
        );
        assert_eq!(
            f.body(Rt::ScanCreate),
            json!({
                "name": "nightly",
                "target": {"uuid": t},
                "job_type": "STATIC",
                "job_metadata": {"categories": {"SECURITY": ["JAILBREAK", "PROMPT_INJECTION"], "SAFETY": ["TOXIC"]}}
            })
        );
        let id = created(180, 1);
        assert_eq!(
            out.stderr,
            "  No --categories given — defaulting to all 3 categories (MULTI_TURN excluded). Pass --categories to narrow the scan.\n  Creating STATIC scan \"nightly\"...\n  Run `airs redteam status <jobId>` to check progress.\n"
        );
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Scan Status:\n\n  ID        {id}\n  Name      nightly\n  Type      STATIC\n  Target    fixture-target\n  Status    QUEUED\n  Progress  0/40\n\n  Job ID  {id}\n"
            )
        );
    }

    /// Explicit categories, DYNAMIC goals (inline and from a file), CUSTOM prompt sets:
    /// the TS `job_metadata` per type.
    #[test]
    fn bodies_per_type() {
        let t = target();
        let f = fx();
        f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "st1",
            "--categories",
            r#"{"SECURITY":["JAILBREAK"]}"#,
            "--no-wait",
        ])
        .assert_success();
        assert_eq!(
            f.api(),
            ["POST /redteam/data/v1/scan"],
            "no categories read"
        );
        assert_eq!(
            f.body(Rt::ScanCreate)["job_metadata"],
            json!({"categories": {"SECURITY": ["JAILBREAK"]}})
        );
        let f = fx();
        f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "dy1",
            "--type",
            "DYNAMIC",
            "--goals",
            r#" ["leak", "jailbreak"]"#,
            "--depth",
            "3",
            "--no-wait",
        ])
        .assert_success();
        assert_eq!(
            f.body(Rt::ScanCreate)["job_metadata"],
            json!({"stream_breadth": 6, "stream_depth": 3, "attack_goals": ["leak", "jailbreak"]})
        );
        let f = fx();
        let goals = f.file("goals.json", br#"["from a file"]"#);
        f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "dy2",
            "--type",
            "DYNAMIC",
            "--goals",
            &goals,
            "--no-wait",
        ])
        .assert_success();
        assert_eq!(
            f.body(Rt::ScanCreate)["job_metadata"],
            json!({"stream_breadth": 6, "stream_depth": 10, "attack_goals": ["from a file"]})
        );
        let f = fx();
        let set = fx::prompt_set_id(1);
        f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "cu1",
            "--type",
            "CUSTOM",
            "--prompt-sets",
            &format!("{set}, {set}"),
            "--no-wait",
            "--output",
            "json",
        ])
        .assert_success();
        assert_eq!(
            f.body(Rt::ScanCreate)["job_metadata"],
            json!({"custom_prompt_sets": [set, set]})
        );
    }

    /// The wait polls at once and every 5 s; progress goes to stderr (one line per
    /// change off a terminal); the final block and the report hint (D135).
    #[test]
    fn the_wait_reports_progress_on_stderr_and_the_final_job() {
        let f = fx();
        f.server.redteam(|data| {
            data.scan_polls
                .push_back(json!({"status": "RUNNING", "completed": 10}));
        });
        let t = target();
        let out = f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "waited",
            "--categories",
            r#"{"SECURITY":["JAILBREAK"]}"#,
        ]);
        out.assert_success();
        let id = created(180, 1);
        assert_eq!(
            f.api(),
            [
                "POST /redteam/data/v1/scan".to_owned(),
                format!("GET /redteam/data/v1/scan/{id}"),
                format!("GET /redteam/data/v1/scan/{id}"),
            ]
        );
        assert_eq!(
            out.stderr,
            "  Creating STATIC scan \"waited\"...\n  Waiting for completion...\n  RUNNING █████░░░░░░░░░░░░░░░ 25% (10/40)\n  COMPLETED ████████████████████ 100% (40/40)\n  Run `airs redteam report <jobId>` to view results.\n"
        );
        let block = |status: &str, done: u32| {
            format!(
                "\n  Scan Status:\n\n  ID        {id}\n  Name      waited\n  Type      STATIC\n  Target    fixture-target\n  Status    {status}\n  Progress  {done}/40\n\n"
            )
        };
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}{}{}  Job ID  {id}\n",
                block("QUEUED", 0),
                block("COMPLETED", 40)
            )
        );
        let f = fx();
        let out = f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "quiet",
            "--categories",
            r#"{"A":["B"]}"#,
            "--quiet",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            out.stderr, "",
            "progress and status lines are quiet-suppressed"
        );
        assert_eq!(out.json()["status"], "COMPLETED");
        assert_eq!(out.json()["uuid"], created(180, 1));
    }

    /// D136: `PARTIALLY_COMPLETE` exits 0 with a warning; `FAILED` and `ABORTED` exit 1
    /// with empty stdout.
    #[test]
    fn terminal_statuses_d136() {
        let t = target();
        let id = created(180, 1);
        for (status, code, line) in [
            (
                "PARTIALLY_COMPLETE",
                0,
                format!("  ⚠ Scan {id} completed partially\n"),
            ),
            (
                "FAILED",
                1,
                error_block(&format!("Scan {id} failed"), None, &[]),
            ),
            (
                "ABORTED",
                1,
                error_block(&format!("Scan {id} was aborted"), None, &[]),
            ),
        ] {
            let f = fx();
            f.server.redteam(|data| {
                data.scan_polls.push_back(json!({"status": status}));
            });
            let out = f.rt(&[
                "scan",
                "--target",
                &t,
                "--name",
                "term",
                "--categories",
                r#"{"A":["B"]}"#,
                "--quiet",
            ]);
            out.assert_code(code);
            assert!(out.stderr.contains(&line), "{status}: {}", out.stderr);
            if code == 1 {
                assert_eq!(out.stdout, "", "{status}");
            } else {
                assert!(out.stdout.contains("PARTIALLY_COMPLETE"));
            }
            assert_eq!(f.server.rt_requests(Rt::ScanCreate).len(), 1);
        }
    }

    /// D135: a poll that fails after the SDK read retries ends the wait with the
    /// still-running detail line; the scan is not aborted.
    #[test]
    fn a_failed_poll_ends_the_wait_with_the_still_running_line_d135() {
        let f = fx();
        f.server.set_default(
            Route::RedTeam(Rt::ScanGet),
            Planned::json(404, &json!({"message": "gone"})),
        );
        let t = target();
        let out = f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "lost",
            "--categories",
            r#"{"A":["B"]}"#,
        ]);
        out.assert_code(1);
        let id = created(180, 1);
        assert_eq!(out.stdout, "");
        assert!(
            out.stderr.ends_with(&error_block(
                "AISEC_CLIENT_SIDE_ERROR:API error 404",
                Some(404),
                &[&format!(
                    "Scan {id} was started and may still be running on AIRS; it was not aborted. Check it with 'airs redteam status {id}'."
                )]
            )),
            "{}",
            out.stderr
        );
        assert!(f.server.rt_requests(Rt::ScanAbort).is_empty());
    }

    /// D133: a 5xx on the POST is never re-sent; the outcome is unknown and the hint
    /// points at `redteam list`; nothing is waited for.
    #[test]
    fn a_server_error_starts_no_second_scan_d133() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::ScanCreate),
            Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
        );
        let t = target();
        let out = f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "busy",
            "--categories",
            r#"{"A":["B"]}"#,
            "--quiet",
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 503",
                Some(503),
                &[
                    "Outcome unknown: the scan may have been started.",
                    &format!(
                        "Check 'airs redteam list --target {t}' before starting another scan."
                    )
                ]
            )
        );
        assert_eq!(f.api(), ["POST /redteam/data/v1/scan"]);
    }

    /// A 2xx whose body cannot be read: the scan was started; the same hint.
    #[test]
    fn an_unreadable_answer_says_the_scan_was_started() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::ScanCreate),
            Planned::raw(200, "application/json", "{not json"),
        );
        let t = target();
        let out = f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "garbled",
            "--categories",
            r#"{"A":["B"]}"#,
            "--quiet",
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema",
                None,
                &[
                    "Outcome: the scan was started, but the response could not be read.",
                    &format!(
                        "Check 'airs redteam list --target {t}' before starting another scan."
                    )
                ]
            )
        );
        assert_eq!(f.server.rt_requests(Rt::ScanCreate).len(), 1);
    }

    /// D133: a 401 is refreshed and replayed once (`token, write, token, write`); a 403
    /// is never replayed.
    #[test]
    fn a_401_is_replayed_once_and_a_403_never() {
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::ScanCreate), Planned::empty_json(401));
        let t = target();
        let args = [
            "scan",
            "--target",
            &t,
            "--name",
            "auth",
            "--categories",
            r#"{"A":["B"]}"#,
            "--no-wait",
        ];
        f.rt(&args).assert_success();
        assert_eq!(
            f.routes(),
            [
                Route::Token,
                Route::RedTeam(Rt::ScanCreate),
                Route::Token,
                Route::RedTeam(Rt::ScanCreate)
            ]
        );
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::ScanCreate), Planned::empty_json(403));
        let out = f.rt(&args);
        out.assert_code(1);
        assert_eq!(
            out.stderr.lines().last().map(str::to_owned),
            Some(String::new())
        );
        assert_eq!(out.http_status(), Some(403));
        assert_eq!(f.server.rt_requests(Rt::ScanCreate).len(), 1);
        assert!(
            !out.stderr.contains("Outcome"),
            "a rejection is not unknown"
        );
    }

    /// D134: every argument check is a usage error before the tenant, with no request.
    #[test]
    fn argument_checks_are_usage_errors_before_the_tenant_d134() {
        let t = target();
        let schema =
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema";
        for (args, message) in [
            (
                vec!["scan", "--target", &t, "--name", "nightly", "--type", "CLARA"],
                format!("{schema}: job_type: invalid_enum_value"),
            ),
            (
                vec!["scan", "--target", &t, "--name", "ab"],
                format!("{schema}: name: too_small"),
            ),
            (
                vec!["scan", "--target", "nope", "--name", "abc"],
                format!("{schema}: target.uuid: invalid_string"),
            ),
            (
                vec!["scan", "--target", &t, "--name", "abc", "--depth", "3"],
                "--depth applies only to --type DYNAMIC".to_owned(),
            ),
            (
                vec!["scan", "--target", &t, "--name", "abc", "--categories", "[1,2]"],
                "--categories: expected a JSON object of category IDs to arrays of sub-category IDs"
                    .to_owned(),
            ),
            (
                vec![
                    "scan", "--target", &t, "--name", "abc", "--type", "DYNAMIC", "--goals", "[x",
                ],
                "--goals: invalid JSON".to_owned(),
            ),
            (
                vec![
                    "scan", "--target", &t, "--name", "abc", "--type", "DYNAMIC", "--breadth",
                    "-1",
                ],
                "--breadth: expected a positive integer, got \"-1\"".to_owned(),
            ),
            (
                vec!["scan", "--target", &t, "--name", "abc", "--type", "CUSTOM"],
                "--prompt-sets is required with --type CUSTOM".to_owned(),
            ),
            (
                vec!["scan", "--target", &t, "--name", "abc", "--wait-timeout", "0"],
                "--wait-timeout must be an integer from 1 to 10080 minutes".to_owned(),
            ),
            (
                vec![
                    "scan",
                    "--target",
                    &t,
                    "--name",
                    "abc",
                    "--wait-timeout",
                    "5",
                    "--no-wait",
                ],
                "--wait-timeout cannot be combined with --no-wait".to_owned(),
            ),
        ] {
            assert_usage(&args, &message);
        }
    }

    /// D143: a `--goals` file is read before the tenant; its errors are exit 1 with no
    /// request.
    #[test]
    fn goals_files_are_checked_before_the_tenant_d143() {
        let t = target();
        let f = bare();
        let bad = f.file("bad.json", b"{not json");
        let numbers = f.file("numbers.json", b"[1]");
        let missing = f.sandbox.tmp().join("missing.json").display().to_string();
        for (path, message) in [
            (bad, "--goals: invalid JSON".to_owned()),
            (
                numbers,
                "--goals: expected a JSON array of non-empty strings".to_owned(),
            ),
            (
                missing.clone(),
                format!(
                    "Cannot read {missing} (missing, not a regular file, unreadable or larger than 1 MiB)"
                ),
            ),
        ] {
            let out = f.rt(&[
                "scan", "--target", &t, "--name", "abc", "--type", "DYNAMIC", "--goals", &path,
            ]);
            out.assert_code(1);
            assert_eq!(out.stderr, error_block(&message, None, &[]));
            assert_eq!(f.server.request_count(), 0);
        }
    }
}

// ---------------------------------------------------------------------------
// `abort` (§15.5, D133, D137)
// ---------------------------------------------------------------------------

mod abort {
    use super::*;

    /// `--force` sends one POST; stdout stays empty; the outcome line on stderr.
    #[test]
    fn force_aborts_with_one_post() {
        let f = fx();
        let id = fx::job_id(2);
        let out = f.rt(&["abort", &id, "--force", "--output", "json"]);
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, format!("  ✓ Scan {id} aborted.\n"));
        assert_eq!(f.api(), [format!("POST /redteam/data/v1/scan/{id}/abort")]);
        assert_eq!(f.server.rt_requests(Rt::ScanAbort)[0].body, b"");
        f.clear();
        let status = f.rt(&["status", &id, "--output", "json"]);
        assert_eq!(status.json()["status"], "ABORTED");
    }

    /// D137: without a terminal and without `--force`, the usage error before the
    /// tenant; the id is checked first.
    #[test]
    fn the_gate_is_a_usage_error_before_the_tenant_d137() {
        let id = fx::job_id(1);
        assert_usage(
            &["abort", &id],
            &format!("refusing to abort scan {id} without --force in non-interactive mode"),
        );
        assert_usage(
            &["abort", "nope"],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: nope",
        );
    }

    /// D133: a 5xx is never re-sent; the hint names `redteam status`.
    #[test]
    fn an_unknown_outcome_is_not_re_sent_d133() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::ScanAbort),
            Planned::json(502, &json!({})).with_retry_after(0),
        );
        let id = fx::job_id(2);
        let out = f.rt(&["abort", &id, "--force"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_SERVER_SIDE_ERROR:API error 502",
                Some(502),
                &[
                    "Outcome unknown: the scan may have been aborted.",
                    &format!("Check it with 'airs redteam status {id}'.")
                ]
            )
        );
        assert_eq!(f.server.rt_requests(Rt::ScanAbort).len(), 1);
    }

    fn pty_abort(f: &Fx, answer: &[u8]) -> PtyRun {
        let id = fx::job_id(2);
        let args = rt(&["abort", &id]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut session = spawn_pty(&rust(), &f.sandbox, &args, &RunOptions::new());
        session.expect(&format!("? Abort scan {id}? (y/N) "));
        assert!(
            f.server.requests().is_empty(),
            "no request while the prompt waits"
        );
        session.send(answer);
        session.wait()
    }

    /// D137: `y`/`yes` abort; `n`, Enter and EOF decline with nothing sent.
    #[test]
    fn the_confirmation_on_a_terminal_d137() {
        for answer in [&b"y\n"[..], b"YES\n"] {
            let f = fx();
            let out = pty_abort(&f, answer);
            out.run.assert_success();
            assert!(transcript(&out).contains("✓ Scan"), "{}", transcript(&out));
            assert_eq!(f.server.rt_requests(Rt::ScanAbort).len(), 1);
        }
        for answer in [&b"n\n"[..], b"\n", b"\x04"] {
            let f = fx();
            let out = pty_abort(&f, answer);
            out.run.assert_success();
            assert!(transcript(&out).contains("  ℹ Aborted\n"), "{answer:?}");
            assert_eq!(f.server.request_count(), 0, "{answer:?}");
        }
    }

    /// Ctrl-C at the prompt: `Cancelled; nothing was changed.`, exit 130.
    #[test]
    fn ctrl_c_at_the_prompt_changes_nothing() {
        let f = fx();
        let id = fx::job_id(2);
        let args = rt(&["abort", &id]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut session = spawn_pty(&rust(), &f.sandbox, &args, &RunOptions::new());
        session.expect("(y/N) ");
        session.signal("INT");
        let out = session.wait();
        out.run.assert_code(130);
        assert!(
            transcript(&out).contains("\n  Cancelled; nothing was changed.\n"),
            "{}",
            transcript(&out)
        );
        assert_eq!(f.server.request_count(), 0);
    }
}

// ---------------------------------------------------------------------------
// `eula accept` (§15.7, D138)
// ---------------------------------------------------------------------------

mod eula {
    use super::*;

    /// `--force`: the content read, then one POST carrying it and the ISO time; stdout
    /// the status document; stderr the outcome.
    #[test]
    fn force_accepts_the_content_as_fetched() {
        let f = fx();
        let out = f.rt(&["eula", "accept", "--force"]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                "GET /redteam/mgmt/v1/eula/content",
                "POST /redteam/mgmt/v1/eula/accept"
            ]
        );
        let body = f.body(Rt::EulaAccept);
        assert_eq!(body["eula_content"], "FIXTURE EULA TEXT v1");
        let at = body["accepted_at"].as_str().unwrap();
        assert_eq!(at.len(), 24, "{at}");
        assert!(at.ends_with('Z') && at.as_bytes()[10] == b'T', "{at}");
        assert_eq!(out.stderr, "  ✓ EULA accepted.\n");
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  EULA Status:\n\n  Accepted     yes\n  Accepted At  2026-10-17T12:00:00.000Z\n  Accepted By  u@example.com\n\n"
            )
        );
        let f = fx();
        let out = f.rt(&["eula", "accept", "--force", "--output", "json"]);
        assert_eq!(out.json()["isAccepted"], true);
        assert_eq!(out.json()["acceptedByUserId"], "u@example.com");
    }

    /// The deprecated `--confirm` warns (never quiet-suppressed) and accepts.
    #[test]
    fn the_deprecated_confirm_alias_warns_and_accepts() {
        let f = fx();
        let out = f.rt(&["eula", "accept", "--confirm", "--quiet"]);
        out.assert_success();
        assert_eq!(
            out.stderr,
            "  ⚠ --confirm is deprecated and will be removed in v4 — use --force\n"
        );
        assert_eq!(f.server.rt_requests(Rt::EulaAccept).len(), 1);
    }

    /// D138: no terminal and no `--force` is exit 2 before the tenant.
    #[test]
    fn no_terminal_and_no_force_is_a_usage_error_d138() {
        assert_usage(
            &["eula", "accept"],
            "refusing to accept the Red Team EULA without --force in non-interactive mode",
        );
    }

    /// D138: on a terminal the content is shown on stderr, then the prompt; declining
    /// sends no accept.
    #[test]
    fn the_terminal_shows_the_content_and_asks_d138() {
        for (answer, accepted) in [(&b"y\n"[..], true), (b"n\n", false)] {
            let f = fx();
            let mut session = spawn_pty(
                &rust(),
                &f.sandbox,
                &["redteam", "eula", "accept"],
                &RunOptions::new(),
            );
            session.expect("? Accept the Red Team EULA shown above? (y/N) ");
            assert_eq!(f.server.rt_requests(Rt::EulaAccept).len(), 0);
            session.send(answer);
            let out = session.wait();
            out.run.assert_success();
            let text = transcript(&out);
            assert!(
                text.contains("\n  EULA Content:\n\n  FIXTURE EULA TEXT v1\n\n? Accept"),
                "{text}"
            );
            assert_eq!(
                f.server.rt_requests(Rt::EulaAccept).len(),
                usize::from(accepted)
            );
            if accepted {
                assert!(out.run.stdout.contains("Accepted     yes"));
            } else {
                assert!(text.contains("ℹ Aborted"));
                assert_eq!(out.run.stdout, "");
            }
        }
    }

    /// D159: an empty or whitespace-only EULA is refused after the content read, before
    /// the prompt and the POST (exit 1), with `--force` and on a terminal alike.
    #[test]
    fn empty_content_is_refused_before_any_write_d159() {
        let message = "The service returned no EULA content, so there is nothing to accept";
        for content in ["", "  \n\t \r\n"] {
            let f = fx();
            f.server.redteam(|data| {
                data.eula_content = fx::eula_content(content);
            });
            let out = f.rt(&["eula", "accept", "--force"]);
            out.assert_code(1);
            assert_eq!(out.stdout, "", "{content:?}");
            assert_eq!(out.stderr, error_block(message, None, &[]), "{content:?}");
            assert_eq!(
                f.api(),
                ["GET /redteam/mgmt/v1/eula/content"],
                "{content:?}"
            );
            f.clear();
            let session = spawn_pty(
                &rust(),
                &f.sandbox,
                &["redteam", "eula", "accept"],
                &RunOptions::new(),
            );
            let out = session.wait();
            out.run.assert_code(1);
            let text = transcript(&out);
            assert!(text.contains(message), "{text}");
            assert!(!text.contains("Accept the Red Team EULA"), "{text}");
            assert!(!text.contains("EULA Content:"), "{text}");
            assert!(f.server.rt_requests(Rt::EulaAccept).is_empty());
        }
    }

    /// D133: a timeout or 5xx is never re-sent; the hint names `eula status`.
    #[test]
    fn an_unknown_outcome_is_never_re_sent() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::EulaAccept),
            Planned::json(500, &json!({})),
        );
        let out = f.rt(&["eula", "accept", "--force"]);
        out.assert_code(1);
        assert!(out.stderr.ends_with(
            "    Outcome unknown: the EULA may have been accepted.\n    Check it with 'airs redteam eula status' before accepting again.\n\n"
        ));
        assert_eq!(f.server.rt_requests(Rt::EulaAccept).len(), 1);
    }
}

// ---------------------------------------------------------------------------
// `registry-credentials`, `instances`, `devices` (§15.8, D139)
// ---------------------------------------------------------------------------

mod infra {
    use super::*;
    use airs_test_harness::{REGISTRY_EXPIRY, REGISTRY_TOKEN};

    /// D139: the token only in json; pretty and table withhold it; one POST.
    #[test]
    fn the_registry_token_is_withheld_but_in_json_d139() {
        let f = fx();
        let out = f.rt_with(
            &["registry-credentials"],
            &RunOptions::new().secret(REGISTRY_TOKEN),
        );
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Registry Credentials:\n\n  Token   (withheld; use --output json to print it)\n  Expiry  {REGISTRY_EXPIRY}\n\n"
            )
        );
        let out = f.rt_with(
            &["registry-credentials", "--output", "table"],
            &RunOptions::new().secret(REGISTRY_TOKEN),
        );
        out.assert_success();
        assert!(
            out.stdout
                .contains("(withheld; use --output json to print it)")
        );
        let out = f.rt(&["registry-credentials", "--output", "json"]);
        assert_eq!(
            out.json(),
            json!({"token": REGISTRY_TOKEN, "expiry": REGISTRY_EXPIRY})
        );
        assert_eq!(f.server.rt_requests(Rt::RegistryCredentials).len(), 3);
        assert!(
            f.server.rt_requests(Rt::RegistryCredentials)[0]
                .body
                .is_empty()
        );
    }

    /// D133: a 5xx mints at most one credential.
    #[test]
    fn a_server_error_mints_once() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::RegistryCredentials),
            Planned::json(503, &json!({})).with_retry_after(0),
        );
        let out = f.rt(&["registry-credentials"]);
        out.assert_code(1);
        assert!(
            out.stderr
                .contains("Outcome unknown: the registry credentials may have been issued.")
        );
        assert_eq!(f.server.rt_requests(Rt::RegistryCredentials).len(), 1);
    }

    /// `instances create|update|delete`: the TS bodies, the `Instance:` block, one
    /// encoded segment; delete confirms (D137).
    #[test]
    fn instances_create_update_delete() {
        let f = fx();
        let out = f.rt(&[
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
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Rt::InstanceCreate),
            json!({"tsg_id": "100", "tenant_id": "ten-2", "app_id": "app-2", "region": "eu"})
        );
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Instance:\n\n  TSG ID     100\n  Tenant ID  ten-2\n  App ID     app-2\n  Success    yes\n\n"
            )
        );
        assert_eq!(out.stderr, "");
        let out = f.rt(&[
            "instances",
            "update",
            "ten-2",
            "--tsg-id",
            "100",
            "--app-id",
            "app-3",
            "--region",
            "us",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({"tsgId": "100", "tenantId": "ten-2", "appId": "app-3", "isSuccess": true})
        );
        assert_eq!(f.body(Rt::InstanceUpdate)["tenant_id"], "ten-2");
        let out = f.rt(&["instances", "rm", "ten-2", "--force", "--output", "table"]);
        out.assert_success();
        assert_eq!(out.stderr, "  ✓ Instance ten-2 deleted.\n");
        assert!(out.stdout.contains("tenantId"), "{}", out.stdout);
        assert!(
            f.api()
                .contains(&"DELETE /redteam/mgmt/v1/instances/ten-2".to_owned())
        );
        assert_usage(
            &["instances", "rm", "../registry-credentials", "--force"],
            "Invalid tenant id: ../registry-credentials",
        );
        assert_usage(
            &["instances", "delete", "ten-1"],
            "refusing to delete instance ten-1 without --force in non-interactive mode",
        );
    }

    /// An empty 2xx body after a delete: applied, but unreadable (G4).
    #[test]
    fn an_empty_delete_answer_was_applied() {
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::InstanceDelete), Planned::status(200));
        let out = f.rt(&["instances", "delete", "ten-1", "--force"]);
        out.assert_code(1);
        assert!(
            out.stderr
                .contains("Outcome: the instance was deleted, but the response could not be read."),
            "{}",
            out.stderr
        );
    }

    /// `devices create|update|delete`: the file is the body (validated, D116), the TS
    /// outcome lines with their colon, the response as JSON.
    #[test]
    fn devices_writes() {
        let f = fx();
        let config = f.file(
            "devices.json",
            br#"{"instance":{"app_id":"app-1","region":"us","tenant_id":"ten-1","tsg_id":"100"},"devices":[{"serial_number":"SN1"}]}"#,
        );
        let out = f.rt(&["devices", "create", "ten-1", "--config", &config]);
        out.assert_success();
        assert_eq!(out.stderr, "  ✓ Devices created:\n");
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}{{\n  \"devices\": [\n    {{\n      \"status\": \"SUCCESS\",\n      \"serial_number\": \"SN1\"\n    }}\n  ],\n  \"status\": \"SUCCESS\"\n}}\n"
            )
        );
        let out = f.rt(&["devices", "update", "ten-1", "--config", &config, "--quiet"]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert_eq!(f.server.rt_requests(Rt::DevicesUpdate)[0].method, "PATCH");
        let out = f.rt(&[
            "devices",
            "rm",
            "ten-1",
            "--serial-numbers",
            "SN1,SN2",
            "--force",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(out.stderr, "  ✓ Devices deleted:\n");
        assert_eq!(out.json()["devices"][1]["serial_number"], "SN2");
        assert_eq!(
            f.api().last().unwrap(),
            "DELETE /redteam/mgmt/v1/instances/ten-1/devices?serial_numbers=SN1%2CSN2"
        );
        let invalid = f.file("invalid.json", br#"{"devices":[]}"#);
        f.clear();
        let out = f.rt(&["devices", "create", "ten-1", "--config", &invalid]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/instances/ten-1/devices did not match schema",
                None,
                &[]
            )
        );
        assert_eq!(f.server.request_count(), 0, "D116: nothing is sent");
        assert_usage(
            &["devices", "delete", "ten-1", "--serial-numbers", "SN1"],
            "refusing to delete devices without --force in non-interactive mode",
        );
    }

    /// D158: a `--serial-numbers` list that names no serial number (empty, whitespace,
    /// only commas) is a usage error before the tenant and the confirmation gate, with
    /// or without `--force`; a list with empty items between serials is sent as given.
    #[test]
    fn an_empty_serial_list_is_a_usage_error_d158() {
        for list in ["", "   ", ",", " , ,"] {
            for force in [false, true] {
                let mut args = vec!["devices", "delete", "ten-1", "--serial-numbers", list];
                if force {
                    args.push("--force");
                }
                assert_usage(&args, "--serial-numbers needs at least one serial number");
            }
        }
        let f = fx();
        f.rt(&[
            "devices",
            "rm",
            "ten-1",
            "--serial-numbers",
            "SN1,,SN2",
            "--force",
        ])
        .assert_success();
        assert_eq!(
            f.api(),
            ["DELETE /redteam/mgmt/v1/instances/ten-1/devices?serial_numbers=SN1%2C%2CSN2"]
        );
    }
}

// ---------------------------------------------------------------------------
// Prompt sets, prompts and properties (§15.9–§15.11)
// ---------------------------------------------------------------------------

mod custom {
    use super::*;

    /// `prompt-sets create`: an empty description is omitted (TS); pretty `Name`; json
    /// the normalised set.
    #[test]
    fn prompt_set_create_and_update() {
        let f = fx();
        let out = f.rt(&[
            "prompt-sets",
            "create",
            "--name",
            "fresh",
            "--description",
            "",
        ]);
        out.assert_success();
        assert_eq!(f.body(Rt::PromptSetCreate), json!({"name": "fresh"}));
        let id = created(380, 1);
        assert_eq!(out.stderr, format!("  ✓ Prompt set created: {id}\n"));
        assert_eq!(out.stdout, format!("{BANNER}  Name  fresh\n"));
        let out = f.rt(&[
            "prompt-sets",
            "update",
            &id,
            "--name",
            "renamed",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(f.body(Rt::PromptSetUpdate), json!({"name": "renamed"}));
        assert_eq!(out.json()["name"], "renamed");
        assert_eq!(out.stderr, "");
        assert_usage(
            &["prompt-sets", "update", &id, "--name", ""],
            "Specify --name and/or --description to update",
        );
    }

    /// `archive` and `--unarchive`: the body, the outcome line, empty stdout.
    #[test]
    fn archive_and_unarchive() {
        let f = fx();
        let id = fx::prompt_set_id(2);
        let out = f.rt(&["prompt-sets", "archive", &id, "--output", "json"]);
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, format!("  ✓ Prompt set {id} archived.\n"));
        assert_eq!(f.body(Rt::PromptSetArchive), json!({"archive": true}));
        f.clear();
        let out = f.rt(&["prompt-sets", "archive", &id, "--unarchive"]);
        assert_eq!(out.stderr, format!("  ✓ Prompt set {id} unarchived.\n"));
        assert_eq!(f.body(Rt::PromptSetArchive), json!({"archive": false}));
    }

    /// D143: the CSV bytes as read in one multipart part `file` (`prompts.csv`,
    /// `text/csv`); the server message on stderr; the 7 MiB cap before the tenant.
    #[test]
    fn upload_sends_the_bytes_as_read_d143() {
        let f = fx();
        let id = fx::prompt_set_id(1);
        let bytes = b"prompt,goal\n\"caf\xc3\xa9\",\xff\xfe\n";
        let path = f.file("prompts.csv", bytes);
        let out = f.rt(&["prompt-sets", "upload", &id, &path]);
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "  ✓ Prompts uploaded successfully\n");
        let request = &f.server.rt_requests(Rt::PromptUpload)[0];
        assert_eq!(
            request.line(),
            format!(
                "POST /redteam/mgmt/v1/custom-attack/upload-custom-prompts-csv?prompt_set_uuid={id}"
            )
        );
        let body = &request.body;
        let needle = |text: &[u8]| body.windows(text.len()).any(|window| window == text);
        assert!(needle(bytes), "the bytes are sent unchanged");
        assert!(needle(b"filename=\"prompts.csv\""));
        assert!(needle(b"Content-Type: text/csv") || needle(b"content-type: text/csv"));
        let big = f.sandbox.tmp().join("big.csv");
        std::fs::write(&big, vec![b'x'; 7 * 1_048_576 + 1]).unwrap();
        f.clear();
        let big = big.display().to_string();
        let out = f.rt(&["prompt-sets", "upload", &id, &big]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                &format!(
                    "Cannot read {big} (missing, not a regular file, unreadable or larger than 7 MiB)"
                ),
                None,
                &[]
            )
        );
        assert_eq!(f.server.request_count(), 0);
    }

    /// D133: an upload answered 5xx is not re-sent; the hint names `prompts list`.
    #[test]
    fn an_unknown_upload_is_not_re_sent() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::PromptUpload),
            Planned::json(504, &json!({})).with_retry_after(0),
        );
        let id = fx::prompt_set_id(1);
        let path = f.file("p.csv", b"prompt\nx\n");
        let out = f.rt(&["prompt-sets", "upload", &id, &path]);
        out.assert_code(1);
        assert!(out.stderr.ends_with(&format!(
            "    Outcome unknown: the prompts may have been uploaded.\n    Check the prompt set with 'airs redteam prompts list {id}' before uploading again.\n\n"
        )));
        assert_eq!(f.server.rt_requests(Rt::PromptUpload).len(), 1);
    }

    /// `prompts add|update|delete`: the TS bodies, outcome lines, outputs; delete
    /// confirms (D137).
    #[test]
    fn prompt_writes() {
        let f = fx();
        let set = fx::prompt_set_id(1);
        let out = f.rt(&[
            "prompts", "add", &set, "--prompt", "hello", "--goal", "leak",
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Rt::PromptCreate),
            json!({"prompt": "hello", "prompt_set_id": set, "goal": "leak"})
        );
        let id = created(480, 1);
        assert_eq!(out.stderr, format!("  ✓ Prompt added: {id}\n"));
        assert_eq!(out.stdout, "", "pretty prints only the outcome line (TS)");
        let out = f.rt(&[
            "prompts", "add", &set, "--prompt", "two", "--output", "json",
        ]);
        assert_eq!(out.json()["prompt"], "two");
        assert!(out.json().get("goal").is_some());
        let out = f.rt(&["prompts", "update", &set, &id, "--goal", "new goal"]);
        out.assert_success();
        assert_eq!(f.body(Rt::PromptUpdate), json!({"goal": "new goal"}));
        assert!(out.stdout.contains("  Prompt Detail:"));
        assert!(out.stdout.contains("new goal"));
        let out = f.rt(&["prompts", "rm", &set, &id, "--force"]);
        out.assert_success();
        assert_eq!(out.stderr, format!("  ✓ Prompt {id} deleted.\n"));
        assert_usage(
            &["prompts", "update", &set, &id],
            "Specify --prompt and/or --goal to update",
        );
        assert_usage(
            &["prompts", "delete", &set, &id],
            &format!("refusing to delete prompt {id} without --force in non-interactive mode"),
        );
        assert_usage(
            &["prompts", "add", "nope", "--prompt", "x"],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid prompt set uuid: nope",
        );
    }

    /// `properties create|add-value`: the bodies and the server messages; D149: an empty
    /// 2xx body is a success.
    #[test]
    fn property_writes_d149() {
        let f = fx();
        let out = f.rt(&["properties", "create", "--name", "tone"]);
        out.assert_success();
        assert_eq!(f.body(Rt::PropertyCreate), json!({"name": "tone"}));
        assert_eq!(out.stderr, "  ✓ Property name created successfully\n");
        assert_eq!(out.stdout, "");
        let out = f.rt(&[
            "properties",
            "add-value",
            "--name",
            "tone",
            "--value",
            "angry",
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Rt::PropertyValueCreate),
            json!({"property_name": "tone", "property_value": "angry"})
        );
        assert_eq!(out.stderr, "  ✓ Property value created successfully\n");
        let f = fx();
        f.server.redteam(|data| data.empty_property_create = true);
        let out = f.rt(&["properties", "create", "--name", "tone"]);
        out.assert_success();
        assert_eq!(out.stderr, "  ✓ Property name created\n");
    }
}

// ---------------------------------------------------------------------------
// Targets (§15.13, D140, D150)
// ---------------------------------------------------------------------------

mod targets {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// `targets create --config [--validate]`: the file is the body; the answer's
    /// credentials (the file's own, echoed) are redacted in every format (D140).
    #[test]
    fn create_sends_the_file_and_redacts_the_answer_d140() {
        let f = fx();
        let config = f.file(
            "target.json",
            serde_json::to_string(&target_config("new-target"))
                .unwrap()
                .as_bytes(),
        );
        let out = f.rt(&["targets", "create", "--config", &config, "--validate"]);
        out.assert_success();
        assert_eq!(f.body(Rt::TargetCreate), target_config("new-target"));
        assert_eq!(
            f.server.rt_requests(Rt::TargetCreate)[0]
                .raw_query
                .as_deref(),
            Some("validate=true")
        );
        let id = created(280, 1);
        assert_eq!(out.stderr, format!("  ✓ Target created: {id}\n"));
        assert!(out.stdout.contains("  Target Detail:"));
        assert!(
            out.stdout.contains("\"apikey\": \"[REDACTED]\""),
            "{}",
            out.stdout
        );
        for format in ["json", "table"] {
            let f = fx();
            let config = f.file(
                "target.json",
                serde_json::to_string(&target_config("new-target"))
                    .unwrap()
                    .as_bytes(),
            );
            let out = f.rt(&["targets", "create", "--config", &config, "--output", format]);
            out.assert_success();
            assert!(out.stdout.contains("[REDACTED]"), "{format}");
            assert_eq!(
                f.server.rt_requests(Rt::TargetCreate)[0].raw_query,
                None,
                "validate=false is never sent"
            );
        }
    }

    /// D153: a target write answer is printed as the server sent it (the fixture echoes
    /// the body): no `ws_response_timeout` or `basic_auth_location` it omitted, and the
    /// values it sent unchanged.
    #[test]
    fn write_answers_print_only_the_fields_the_server_sent_d153() {
        for sent in [false, true] {
            let f = fx();
            let mut body = target_config("t");
            body["auth_type"] = json!("BASIC_AUTH");
            body["auth_config"] = json!({
                "basic_auth_header": {"Authorization": format!("Basic {}", fx::secret(22))}
            });
            if sent {
                body["connection_params"]["ws_response_timeout"] = json!(45);
                body["auth_config"]["basic_auth_location"] = json!("QUERY");
            }
            let config = f.file("t.json", body.to_string().as_bytes());
            let id = fx::target_id(1);
            for (args, params, auth) in [
                (
                    vec!["targets", "create", "--config", &config],
                    "connectionParams",
                    "authConfig",
                ),
                (
                    vec!["targets", "update", &id, "--config", &config],
                    "connectionParams",
                    "authConfig",
                ),
                (
                    vec!["targets", "probe", "--config", &config],
                    "connection_params",
                    "auth_config",
                ),
            ] {
                let mut json_args = args.clone();
                json_args.extend(["--output", "json"]);
                let out = f.rt(&json_args);
                out.assert_success();
                let doc = out.json();
                let timeout = doc[params].get("ws_response_timeout");
                let location = doc[auth].get("basic_auth_location");
                if sent {
                    assert_eq!(timeout, Some(&json!(45)), "{args:?}: {doc}");
                    assert_eq!(location, Some(&json!("QUERY")), "{args:?}: {doc}");
                } else {
                    assert_eq!((timeout, location), (None, None), "{args:?}: {doc}");
                }
                let pretty = f.rt(&args);
                pretty.assert_success();
                assert_eq!(
                    pretty.stdout.contains("ws_response_timeout"),
                    sent,
                    "{args:?}: {}",
                    pretty.stdout
                );
            }
        }
    }

    /// D116: a body the strict create schema refuses (an unknown key) is not sent.
    #[test]
    fn an_unknown_key_is_refused_before_any_request_d116() {
        let f = fx();
        let mut config = target_config("x");
        config["surprise"] = json!(true);
        let path = f.file("bad.json", config.to_string().as_bytes());
        let out = f.rt(&["targets", "create", "--config", &path]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/target did not match schema",
                None,
                &[]
            )
        );
        assert_eq!(f.server.request_count(), 0);
        let not_object = f.file("array.json", b"[]");
        let out = f.rt(&["targets", "create", "--config", &not_object]);
        out.assert_code(1);
        assert_eq!(
            out.error_line(),
            Some(format!("{not_object} must contain a JSON object"))
        );
    }

    /// `update`, `probe` and `update-profile`: their paths, bodies and outputs.
    #[test]
    fn update_probe_and_update_profile() {
        let f = fx();
        let id = fx::target_id(1);
        let config = f.file(
            "update.json",
            serde_json::to_string(&target_config("renamed"))
                .unwrap()
                .as_bytes(),
        );
        let out = f.rt(&["targets", "update", &id, "--config", &config]);
        out.assert_success();
        assert_eq!(out.stderr, format!("  ✓ Target updated: {id}\n"));
        assert_eq!(
            f.server.rt_requests(Rt::TargetUpdate)[0].line(),
            format!("PUT /redteam/mgmt/v1/target/{id}")
        );
        let out = f.rt(&["targets", "probe", "--config", &config]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert!(
            out.stdout
                .starts_with(&format!("{BANNER}  Probe result:\n{{\n"))
        );
        assert!(!out.stdout.contains("multi_turn_error_message"));
        assert!(out.stdout.contains("[REDACTED]"));
        let profile = f.file(
            "profile.json",
            br#"{"target_background":{"industry":"Finance"},"extra_field":1}"#,
        );
        let out = f.rt(&["targets", "update-profile", &id, "--config", &profile]);
        out.assert_success();
        assert_eq!(out.stderr, "  ✓ Profile updated:\n");
        assert_eq!(
            f.body(Rt::TargetProfileUpdate),
            json!({"target_background": {"industry": "Finance"}, "extra_field": 1})
        );
        assert!(out.stdout.contains("\"industry\": \"Finance\""));
        assert!(
            !out.stdout.contains("FAKE-TARGET-SECRET"),
            "the stored target's credentials are redacted"
        );
    }

    /// A credential the CLI redacted at one path is withheld at every other key of the
    /// printed document (§15.4): the probe echoes a body template carrying the header's
    /// key, in json and pretty alike.
    #[test]
    fn credentials_echoed_under_any_key_are_withheld_d140() {
        let f = fx();
        let mut config = target_config("probe-me");
        config["connection_params"]["request_headers"] =
            json!({"Content-Type": "application/json", "X-Auth": fx::secret(24)});
        config["connection_params"]["request_json"] =
            json!({"input": "{INPUT}", "auth": fx::secret(24)});
        config["extra_info"] = json!({"note": format!("key {}", fx::secret(24))});
        let path = f.file(
            "probe.json",
            serde_json::to_string(&config).unwrap().as_bytes(),
        );
        let out = f.rt(&["targets", "probe", "--config", &path, "--output", "json"]);
        out.assert_success();
        let doc = out.json();
        assert_eq!(
            doc["connection_params"]["request_headers"]["X-Auth"],
            "[REDACTED]"
        );
        assert_eq!(
            doc["connection_params"]["request_json"]["auth"],
            "[withheld]"
        );
        assert_eq!(
            doc["connection_params"]["request_json"]["input"], "{INPUT}",
            "other values are kept"
        );
        assert_eq!(doc["extra_info"]["note"], "[withheld]");
        let out = f.rt(&["targets", "probe", "--config", &path]);
        out.assert_success();
        assert!(
            out.stdout.contains("\"auth\": \"[withheld]\""),
            "{}",
            out.stdout
        );
    }

    /// Short or non-credential values under a credential path are redacted where they
    /// stand but do not withhold names and descriptions that happen to contain them.
    #[test]
    fn short_header_values_do_not_withhold_names() {
        let f = fx();
        let id = fx::target_id(1);
        f.server.redteam(|data| {
            let target = &mut data.targets[0];
            target["name"] = json!("prod chatbot");
            target["description"] = json!("Production chatbot v1");
            target["connection_params"]["request_headers"] = json!({
                "Content-Type": "application/json",
                "X-Env": "prod",
                "X-Api-Version": "1",
                "apikey": fx::secret(2)
            });
            let openai = &mut data.targets[1];
            openai["name"] = json!("Acid target");
            openai["description"] = json!("Uses client_credentials grant");
            openai["auth_config"]["oauth2_body_params"]["grant_type"] = json!("client_credentials");
        });
        let out = f.rt(&["targets", "get", &id, "--output", "json"]);
        out.assert_success();
        let doc = out.json();
        assert_eq!(doc["name"], "prod chatbot");
        assert_eq!(doc["description"], "Production chatbot v1");
        assert_eq!(
            doc["connectionParams"]["request_headers"]["X-Api-Version"],
            "[REDACTED]"
        );
        let out = f.rt(&["targets", "get", &fx::target_id(2), "--output", "json"]);
        out.assert_success();
        let doc = out.json();
        assert_eq!(doc["name"], "Acid target");
        assert_eq!(doc["description"], "Uses client_credentials grant");
        let out = f.rt_with(
            &["targets", "backup", "--output", "json"],
            &RunOptions::new().allow_writes_under("cwd"),
        );
        out.assert_success();
        let doc = out.json();
        let names: Vec<&str> = doc["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap())
            .collect();
        assert_eq!(names[..2], ["prod chatbot", "Acid target"]);
    }

    /// D137: the delete gate comes first (TS order); `--force` sends one DELETE.
    #[test]
    fn delete_confirms_d137() {
        let f = fx();
        let id = fx::target_id(3);
        let out = f.rt(&["targets", "rm", &id, "--force"]);
        out.assert_success();
        assert_eq!(out.stderr, format!("  ✓ Target {id} deleted.\n"));
        assert_eq!(f.api(), [format!("DELETE /redteam/mgmt/v1/target/{id}")]);
        assert_usage(
            &["targets", "delete", "nope"],
            "refusing to delete target nope without --force in non-interactive mode",
        );
        assert_usage(
            &["targets", "delete", "nope", "--force"],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid target uuid: nope",
        );
    }

    /// `validate-auth`: the body (with and without `--target-id`), the token preview
    /// withheld (D140), the auth type checked before the tenant.
    #[test]
    fn validate_auth_withholds_the_token_preview_d140() {
        let f = fx();
        let config = f.file(
            "auth.json",
            format!(
                r#"{{"auth_header":{{"Authorization":"Bearer {}"}}}}"#,
                fx::secret(24)
            )
            .as_bytes(),
        );
        let target = fx::target_id(1);
        let out = f.rt(&[
            "targets",
            "validate-auth",
            "--auth-type",
            "HEADERS",
            "--config",
            &config,
            "--target-id",
            &target,
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Rt::TargetValidateAuth),
            json!({
                "auth_type": "HEADERS",
                "auth_config": {"auth_header": {"Authorization": format!("Bearer {}", fx::secret(24))}},
                "target_id": target
            })
        );
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Auth Validation:\n\n  Validated   yes\n  Token       [REDACTED]\n  Expires In  3600s\n\n"
            )
        );
        let out = f.rt(&[
            "targets",
            "validate-auth",
            "--auth-type",
            "HEADERS",
            "--config",
            &config,
            "--output",
            "json",
        ]);
        assert_eq!(
            out.json(),
            json!({"validated": true, "tokenPreview": "[REDACTED]", "expiresIn": 3600})
        );
        assert_usage(
            &[
                "targets",
                "validate-auth",
                "--auth-type",
                "KERBEROS",
                "--config",
                "x.json",
            ],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/target/validate-auth did not match schema: auth_type: invalid_enum_value",
        );
    }

    /// D150: the scaffold in the working directory at 0600 (the TS bytes), the outputs
    /// and hints; an existing path is refused before any request (exit 2).
    #[test]
    fn init_scaffolds_exclusively_at_0600_d150() {
        let f = fx();
        let out = f.rt_with(
            &["targets", "init", "rest"],
            &RunOptions::new().allow_writes_under("cwd"),
        );
        out.assert_success();
        let path = f.sandbox.cwd().join("rest-target.json");
        let abs = path.display().to_string();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\n  \"name\": \"\",\n  \"target_type\": \"APPLICATION\""));
        assert!(text.contains("\"api_endpoint\": \"https://api.example.com/v1/chat\""));
        assert!(text.ends_with("}\n"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            out.stdout,
            format!("{BANNER}  File      {abs}\n  Provider  REST\n")
        );
        assert_eq!(
            out.stderr,
            "  ✓ Target config scaffolded\n  Next steps: edit the file to fill in name and credentials, then run:\n    airs redteam targets create --config rest-target.json --validate\n"
        );
        assert_eq!(f.api(), ["GET /redteam/mgmt/v1/template/target-templates"]);
        f.clear();
        let out = f.rt(&["targets", "init", "REST"]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            usage_block(&format!(
                "File already exists: {abs} (use --output-file to specify a different path)"
            ))
        );
        assert_eq!(f.server.request_count(), 0);
        let link = f.sandbox.tmp().join("dangling.json");
        std::os::unix::fs::symlink(f.sandbox.tmp().join("nowhere"), &link).unwrap();
        let link = link.display().to_string();
        let out = f.rt(&["targets", "init", "openai", "--output-file", &link]);
        out.assert_code(2);
        assert!(out.stderr.contains("File already exists"));
        let json_path = f.sandbox.tmp().join("bedrock.json").display().to_string();
        let out = f.rt(&[
            "targets",
            "init",
            "bedrock",
            "--output-file",
            &json_path,
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({"file": json_path, "provider": "BEDROCK"})
        );
        assert_usage(
            &["targets", "init", "nope"],
            "Unknown provider \"nope\". Valid providers: OPENAI, HUGGING_FACE, DATABRICKS, BEDROCK, REST, STREAMING, WEBSOCKET, CUSTOM_TARGET_ADAPTER",
        );
        assert_usage(
            &["targets", "init", "rest", "--output-file", ""],
            "--output-file needs a path",
        );
    }

    /// D140: credentials the user supplies join the secret set: a server that echoes one
    /// in a name gets `[withheld]`.
    #[test]
    fn supplied_credentials_are_withheld_when_echoed_d140() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::TargetCreate),
            Planned::json(
                200,
                &json!({
                    "uuid": created(280, 1), "tsg_id": TSG,
                    "name": format!("echo {}", fx::secret(22)), "status": "ACTIVE", "active": true,
                    "validated": false, "created_at": fx::CREATED, "updated_at": fx::UPDATED
                }),
            ),
        );
        let config = f.file(
            "t.json",
            serde_json::to_string(&target_config("x"))
                .unwrap()
                .as_bytes(),
        );
        let out = f.rt(&["targets", "create", "--config", &config, "--output", "json"]);
        out.assert_success();
        assert_eq!(out.json()["name"], "[withheld]");
    }
}

// ---------------------------------------------------------------------------
// Adapters (§15.14, D154)
// ---------------------------------------------------------------------------

mod adapters {
    use super::*;

    /// TS `createAdapter`: the body, `validate=true` unless `--draft`; the script file
    /// base64-encoded as read (D143); SECRET values from `--variables-file` (D154).
    #[test]
    fn create_encodes_the_script_and_reads_variables_from_a_file() {
        let f = fx();
        let script = f.file("adapter.py", b"print('hi')\n\xff");
        let variables = f.file(
            "vars.json",
            format!(
                r#"[{{"key":"endpoint","value":"http://agent","type":"VAR"}},{{"key":"api_token","value":"{}","type":"SECRET"}}]"#,
                fx::secret(25)
            )
            .as_bytes(),
        );
        let channel = fx::channel_id(1);
        let out = f.rt(&[
            "adapter",
            "create",
            "--name",
            "fresh",
            "--prompt",
            "Hello",
            "--script-file",
            &script,
            "--channel",
            &channel,
            "--variables-file",
            &variables,
            "--description",
            "",
        ]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET /redteam/broker/v1/channels/{channel}"),
                "POST /redteam/mgmt/v1/adapters?validate=true".to_owned()
            ]
        );
        assert_eq!(
            f.body(Rt::AdapterCreate),
            json!({
                "name": "fresh",
                "description": "",
                "script_b64": "cHJpbnQoJ2hpJykK/w==",
                "network_broker_channel_uuid": channel,
                "variables": [
                    {"key": "endpoint", "value": "http://agent", "type": "VAR"},
                    {"key": "api_token", "value": fx::secret(25), "type": "SECRET"}
                ],
                "prompt": "Hello"
            })
        );
        let id = created(580, 1);
        assert_eq!(out.stderr, format!("  ✓ Adapter created: {id}\n"));
        assert!(out.stdout.contains("  Adapter Detail:"));
        let f = fx();
        f.rt(&[
            "adapter",
            "create",
            "--name",
            "draft",
            "--prompt",
            "p",
            "--script-b64",
            "cHJpbnQ=",
            "--channel",
            &fx::channel_id(2),
            "--draft",
        ])
        .assert_success();
        assert_eq!(
            f.api(),
            ["POST /redteam/mgmt/v1/adapters?validate=false"],
            "a draft skips the channel check"
        );
    }

    /// TS `assertChannelOnline`: an offline channel refuses the write; a failing lookup
    /// is ignored.
    #[test]
    fn an_offline_channel_refuses_the_write() {
        let f = fx();
        let channel = fx::channel_id(2);
        let out = f.rt(&[
            "adapter",
            "create",
            "--name",
            "n",
            "--prompt",
            "p",
            "--script-b64",
            "eA==",
            "--channel",
            &channel,
        ]);
        out.assert_code(1);
        assert_eq!(
            out.error_line(),
            Some(format!(
                "network broker channel {channel} is OFFLINE — adapter validation requires an ONLINE channel (network broker v1.4.0+). Check 'airs redteam network-broker channels list'."
            ))
        );
        assert!(f.server.rt_requests(Rt::AdapterCreate).is_empty());
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::ChannelGet),
            Planned::json(500, &json!({})),
        );
        f.rt(&[
            "adapter",
            "create",
            "--name",
            "n",
            "--prompt",
            "p",
            "--script-b64",
            "eA==",
            "--channel",
            &channel,
        ])
        .assert_success();
        assert_eq!(f.server.rt_requests(Rt::AdapterCreate).len(), 1);
    }

    /// TS `updateAdapter`: the read-modify-write keeps the stored fields and sends the
    /// redacted variables as `null` (keep stored); `--variables` replaces them.
    #[test]
    fn update_is_a_read_modify_write() {
        let f = fx();
        let id = fx::adapter_id(1);
        let out = f.rt(&[
            "adapter",
            "update",
            &id,
            "--prompt",
            "Hello",
            "--description",
            "new",
            "--draft",
        ]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET /redteam/mgmt/v1/adapters/{id}"),
                format!("PUT /redteam/mgmt/v1/adapters/{id}?validate=false")
            ]
        );
        assert_eq!(
            f.body(Rt::AdapterUpdate),
            json!({
                "name": "adapter-one",
                "description": "new",
                "script_b64": "cHJpbnQoJ2hpJykK",
                "network_broker_channel_uuid": fx::channel_id(1),
                "variables": [
                    {"key": "endpoint", "value": "http://agent.svc:8080", "type": "VAR"},
                    {"key": "api_token", "value": null, "type": "SECRET"}
                ],
                "prompt": "Hello"
            })
        );
        assert_eq!(out.stderr, format!("  ✓ Adapter updated: {id}\n"));
        let f = fx();
        f.rt(&[
            "adapter",
            "update",
            &id,
            "--prompt",
            "Hello",
            "--variables",
            r#"[{"key":"only","value":"v","type":"VAR"}]"#,
            "--draft",
        ])
        .assert_success();
        assert_eq!(
            f.body(Rt::AdapterUpdate)["variables"],
            json!([{"key": "only", "value": "v", "type": "VAR"}])
        );
    }

    /// TS `validateAdapter`: `--adapter` fills the variables; script output that echoes a
    /// secret is withheld; `validated: false` exits 1 after the data.
    #[test]
    fn validate_fills_variables_withholds_echoes_and_fails_closed() {
        let f = fx();
        let channel = fx::channel_id(1);
        let adapter = fx::adapter_id(1);
        let out = f.rt(&[
            "adapter",
            "validate",
            "--channel",
            &channel,
            "--prompt",
            "Hello",
            "--script-b64",
            "eA==",
            "--adapter",
            &adapter,
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Rt::AdapterValidate),
            json!({
                "script_b64": "eA==",
                "network_broker_channel_uuid": channel,
                "prompt": "Hello",
                "variables": [
                    {"key": "endpoint", "value": "http://agent.svc:8080", "type": "VAR"},
                    {"key": "api_token", "value": null, "type": "SECRET"}
                ],
                "adapter_uuid": adapter
            })
        );
        assert_eq!(out.stderr, "  ✓ Adapter script validated\n");
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  stdout:\n\nprompt=Hello\nvars: endpoint=http://agent.svc:8080,api_token=null\n\n"
            )
        );
        let f = fx();
        let vars = f.file(
            "v.json",
            format!(
                r#"[{{"key":"k","value":"{}","type":"SECRET"}}]"#,
                fx::secret(26)
            )
            .as_bytes(),
        );
        let out = f.rt(&[
            "adapter",
            "validate",
            "--channel",
            &channel,
            "--prompt",
            "Hello",
            "--script-b64",
            "eA==",
            "--variables-file",
            &vars,
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(out.json()["stdout"], "[withheld]");
        let f = fx();
        f.server
            .redteam(|data| data.adapter_validation_fails = true);
        let out = f.rt(&[
            "adapter",
            "validate",
            "--channel",
            &channel,
            "--prompt",
            "Hello",
            "--script-b64",
            "eA==",
        ]);
        out.assert_code(1);
        assert!(out.stdout.contains("\n  stderr:\n\nboom\n"));
        assert!(out.stdout.contains("\n  traceback:\n\nTraceback"));
        assert_eq!(out.stderr, "  ✗ Adapter script validation FAILED\n");
    }

    /// A stored adapter whose `SECRET` value comes back unmasked (adapter 2, §15.4): the
    /// read-modify-write of `validate --adapter` and `update` sends it back, so it joins
    /// the secret set first; script output and an error code that echo it are withheld.
    #[test]
    fn re_sent_stored_secrets_are_withheld_when_echoed_d140() {
        let f = fx();
        let channel = fx::channel_id(1);
        let adapter = fx::adapter_id(2);
        let out = f.rt(&[
            "adapter",
            "validate",
            "--channel",
            &channel,
            "--prompt",
            "Hello",
            "--script-b64",
            "eA==",
            "--adapter",
            &adapter,
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Rt::AdapterValidate)["variables"][0]["value"],
            fx::secret(19),
            "the stored value is sent back"
        );
        assert_eq!(out.json()["stdout"], "[withheld]");
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::AdapterUpdate),
            Planned::json(400, &json!({"code": fx::secret(19)})),
        );
        let out = f.rt(&["adapter", "update", &adapter, "--prompt", "x", "--draft"]);
        out.assert_code(1);
        assert_eq!(
            f.body(Rt::AdapterUpdate)["variables"][0]["value"],
            fx::secret(19)
        );
        assert!(!out.stderr.contains("FAKE-TARGET-SECRET"), "{}", out.stderr);
    }

    /// D141, D154: the script and variables checks before the tenant.
    #[test]
    fn script_and_variable_checks_d154() {
        assert_usage(
            &["adapter", "create", "--name", "n", "--prompt", "p"],
            "one of --script-file or --script-b64 is required",
        );
        assert_usage(
            &[
                "adapter",
                "create",
                "--name",
                "n",
                "--prompt",
                "p",
                "--script-b64",
                "x",
                "--script-file",
                "a.py",
            ],
            "--script-file and --script-b64 are mutually exclusive",
        );
        assert_usage(
            &[
                "adapter",
                "create",
                "--name",
                "n",
                "--prompt",
                "p",
                "--script-b64",
                "x",
                "--variables",
                r#"[{"key":"t","value":"FAKE-ARGV","type":"SECRET"}]"#,
            ],
            "Do not pass SECRET values as arguments; put the variables in a file and use --variables-file <path>",
        );
        assert_usage(
            &[
                "adapter",
                "validate",
                "--channel",
                "nope",
                "--prompt",
                "p",
                "--script-b64",
                "x",
            ],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid channel id: nope",
        );
        assert_usage(
            &["adapter", "delete", "x"],
            "refusing to delete adapter x without --force in non-interactive mode",
        );
    }

    /// `delete --force`: one DELETE, the outcome line.
    #[test]
    fn delete_with_force() {
        let f = fx();
        let id = fx::adapter_id(2);
        let out = f.rt(&["adapter", "rm", &id, "--force"]);
        out.assert_success();
        assert_eq!(out.stderr, format!("  ✓ Adapter {id} deleted.\n"));
        assert_eq!(f.api(), [format!("DELETE /redteam/mgmt/v1/adapters/{id}")]);
    }

    /// D307: a stored channel that is not a UUID (read since scm-sdk 0.2.2, D306) is
    /// refused after the read and before the PUT, with a message that names the field and
    /// `--channel`, not the request body. `--channel` replaces it and the update is sent;
    /// `validate --adapter` reuses only the stored variables, so it is unaffected.
    #[test]
    fn update_refuses_a_stored_channel_that_is_not_a_uuid_d307() {
        let f = fx();
        f.server.redteam(|data| {
            data.adapters[0]["network_broker_channel_uuid"] = json!("chan-1");
        });
        let id = fx::adapter_id(1);
        let out = f.rt(&[
            "adapter", "update", &id, "--name", "renamed", "--prompt", "hello",
        ]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: The stored adapter's network_broker_channel_uuid is not a UUID, so \
             the update cannot send it back; pass --channel <channelId> to replace it\n\n"
        );
        assert!(!out.stderr.contains("chan-1"), "{}", out.stderr);
        assert_eq!(f.api(), [format!("GET /redteam/mgmt/v1/adapters/{id}")]);
        f.clear();
        let channel = fx::channel_id(1);
        let out = f.rt(&[
            "adapter",
            "update",
            &id,
            "--name",
            "renamed",
            "--prompt",
            "hello",
            "--channel",
            &channel,
            "--draft",
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Rt::AdapterUpdate)["network_broker_channel_uuid"],
            json!(channel)
        );
        f.clear();
        let out = f.rt(&[
            "adapter",
            "validate",
            "--channel",
            &channel,
            "--prompt",
            "Hello",
            "--script-b64",
            "eA==",
            "--adapter",
            &id,
        ]);
        out.assert_success();
        assert_eq!(
            f.body(Rt::AdapterValidate)["network_broker_channel_uuid"],
            json!(channel)
        );
    }
}

// ---------------------------------------------------------------------------
// Network broker channels (§15.15)
// ---------------------------------------------------------------------------

mod channels {
    use super::*;

    #[test]
    fn create_and_update() {
        let f = fx();
        let out = f.rt(&["network-broker", "channels", "create", "--name", "edge"]);
        out.assert_success();
        assert_eq!(f.body(Rt::ChannelCreate), json!({"name": "edge"}));
        let id = created(680, 1);
        assert_eq!(out.stderr, format!("  ✓ Channel created: {id}\n"));
        assert!(out.stdout.contains("  Channel Detail:"));
        let out = f.rt(&[
            "network-broker",
            "channels",
            "update",
            &id,
            "--description",
            "",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(f.body(Rt::ChannelUpdate), json!({"description": ""}));
        assert_eq!(out.json()["description"], "");
        assert_eq!(out.stderr, format!("  ✓ Channel updated: {id}\n"));
        assert_usage(
            &["network-broker", "channels", "update", "nope"],
            "Specify --name and/or --description to update",
        );
        assert_usage(
            &[
                "network-broker",
                "channels",
                "create",
                "--name",
                &"n".repeat(65),
            ],
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/channels did not match schema: name: too_big",
        );
    }
}

// ---------------------------------------------------------------------------
// D133 across every write
// ---------------------------------------------------------------------------

mod attempts {
    use super::*;

    /// Each write, its route, and an argument list (`--force` where it confirms).
    fn writes(f: &Fx) -> Vec<(Rt, Vec<String>)> {
        let target = f.file(
            "t.json",
            serde_json::to_string(&target_config("x"))
                .unwrap()
                .as_bytes(),
        );
        let devices = f.file(
            "d.json",
            br#"{"instance":{"app_id":"a","region":"r","tenant_id":"ten-1","tsg_id":"100"}}"#,
        );
        let csv = f.file("p.csv", b"prompt\nx\n");
        let set = fx::prompt_set_id(1);
        let s = |args: &[&str]| args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        vec![
            (Rt::ScanAbort, s(&["abort", &fx::job_id(2), "--force"])),
            (Rt::EulaAccept, s(&["eula", "accept", "--force"])),
            (Rt::RegistryCredentials, s(&["registry-credentials"])),
            (
                Rt::InstanceCreate,
                s(&[
                    "instances",
                    "create",
                    "--tsg-id",
                    "1",
                    "--tenant-id",
                    "t",
                    "--app-id",
                    "a",
                    "--region",
                    "r",
                ]),
            ),
            (
                Rt::InstanceDelete,
                s(&["instances", "rm", "ten-1", "--force"]),
            ),
            (
                Rt::DevicesCreate,
                s(&["devices", "create", "ten-1", "--config", &devices]),
            ),
            (
                Rt::PromptSetCreate,
                s(&["prompt-sets", "create", "--name", "n"]),
            ),
            (Rt::PromptSetArchive, s(&["prompt-sets", "archive", &set])),
            (Rt::PromptUpload, s(&["prompt-sets", "upload", &set, &csv])),
            (
                Rt::PromptCreate,
                s(&["prompts", "add", &set, "--prompt", "p"]),
            ),
            (
                Rt::PromptDelete,
                s(&["prompts", "rm", &set, &fx::prompt_id(1), "--force"]),
            ),
            (
                Rt::PropertyCreate,
                s(&["properties", "create", "--name", "n"]),
            ),
            (
                Rt::TargetCreate,
                s(&["targets", "create", "--config", &target]),
            ),
            (
                Rt::TargetProbe,
                s(&["targets", "probe", "--config", &target]),
            ),
            (
                Rt::TargetDelete,
                s(&["targets", "rm", &fx::target_id(1), "--force"]),
            ),
            (
                Rt::AdapterDelete,
                s(&["adapter", "rm", &fx::adapter_id(1), "--force"]),
            ),
            (
                Rt::AdapterValidate,
                s(&[
                    "adapter",
                    "validate",
                    "--channel",
                    &fx::channel_id(1),
                    "--prompt",
                    "p",
                    "--script-b64",
                    "eA==",
                ]),
            ),
            (
                Rt::ChannelCreate,
                s(&["network-broker", "channels", "create", "--name", "n"]),
            ),
        ]
    }

    /// D133: a 5xx with `Retry-After: 0` is one request and an unknown outcome; a 401 is
    /// `token, write, token, write`; a 403 is one request.
    #[test]
    fn every_write_is_one_attempt_d133() {
        let probe = fx();
        for (route, args) in writes(&probe) {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let f = fx();
            for (name, bytes) in [
                ("t.json", "t.json"),
                ("d.json", "d.json"),
                ("p.csv", "p.csv"),
            ] {
                let from = probe.sandbox.tmp().join(name);
                std::fs::copy(&from, f.sandbox.tmp().join(bytes)).unwrap();
            }
            let args: Vec<String> = args
                .iter()
                .map(|arg| {
                    arg.replace(
                        &probe.sandbox.tmp().display().to_string(),
                        &f.sandbox.tmp().display().to_string(),
                    )
                })
                .collect();
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            f.server.push_once(
                Route::RedTeam(route),
                Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
            );
            let out = f.rt(&args);
            out.assert_code(1);
            assert_eq!(f.server.rt_requests(route).len(), 1, "{route:?} 5xx");
            assert!(
                out.stderr.contains("    Outcome unknown: the "),
                "{route:?}: {}",
                out.stderr
            );
            f.clear();
            f.server
                .push_once(Route::RedTeam(route), Planned::empty_json(401));
            f.rt(&args);
            assert_eq!(f.server.rt_requests(route).len(), 2, "{route:?} 401");
            let tokens = f
                .routes()
                .iter()
                .filter(|seen| **seen == Route::Token)
                .count();
            assert_eq!(tokens, 2, "{route:?}: a fresh token for the replay");
            f.clear();
            f.server
                .push_once(Route::RedTeam(route), Planned::empty_json(403));
            let out = f.rt(&args);
            out.assert_code(1);
            assert_eq!(f.server.rt_requests(route).len(), 1, "{route:?} 403");
            assert!(!out.stderr.contains("Outcome"), "{route:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Interruption (§15.3, §15.6, §15.20)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    fn spawn_rt(f: &Fx, args: &[&str]) -> airs_test_harness::Running {
        let args = rt(args);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        spawn(
            &rust(),
            &f.sandbox,
            &args,
            &RunOptions::new().expect_signal(),
        )
    }

    /// A signal while the scan POST is held: the service started the scan; the CLI says
    /// so, exits 130 and sends nothing else (no second POST, no wait, no abort).
    #[test]
    fn a_signal_during_the_scan_start_reports_an_unknown_outcome() {
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::ScanCreate), Planned::held());
        let t = fx::target_id(1);
        let running = spawn_rt(
            &f,
            &[
                "scan",
                "--target",
                &t,
                "--name",
                "held",
                "--categories",
                r#"{"A":["B"]}"#,
            ],
        );
        assert!(f.server.wait_for_route(
            Route::RedTeam(Rt::ScanCreate),
            1,
            Duration::from_secs(20)
        ));
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert_eq!(out.stdout, "");
        assert!(
            out.stderr.ends_with(&format!(
                "\n  ✗ Error: Interrupted; the scan may already have been started (outcome unknown); check 'airs redteam list --target {t}' before starting another\n\n"
            )),
            "{}",
            out.stderr
        );
        assert_eq!(f.server.rt_requests(Rt::ScanCreate).len(), 1);
        assert!(f.server.rt_requests(Rt::ScanGet).is_empty());
        assert!(f.server.rt_requests(Rt::ScanAbort).is_empty());
        assert_eq!(
            f.server.redteam_data().created_scans.len(),
            1,
            "the service holds the scan"
        );
    }

    /// A signal during the wait: the scan keeps running; it is never aborted (exit 143).
    #[test]
    fn a_signal_during_the_wait_leaves_the_scan_running() {
        let f = fx();
        f.server.redteam(|data| {
            for _ in 0..20 {
                data.scan_polls.push_back(json!({"status": "RUNNING"}));
            }
        });
        let t = fx::target_id(1);
        let running = spawn_rt(
            &f,
            &[
                "scan",
                "--target",
                &t,
                "--name",
                "waits",
                "--categories",
                r#"{"A":["B"]}"#,
            ],
        );
        assert!(
            f.server
                .wait_for_route(Route::RedTeam(Rt::ScanGet), 1, Duration::from_secs(20))
        );
        running.send_signal("TERM");
        let out = running.wait();
        out.assert_code(143);
        let id = created(180, 1);
        assert!(
            out.stderr.ends_with(&format!(
                "\n  ✗ Error: Interrupted; scan {id} was started and may still be running on AIRS; it was not aborted\n\n"
            )),
            "{}",
            out.stderr
        );
        assert_eq!(f.server.rt_requests(Rt::ScanCreate).len(), 1);
        assert!(f.server.rt_requests(Rt::ScanAbort).is_empty());
    }

    /// A signal while the abort is held: the abort may have been applied; never re-sent.
    #[test]
    fn a_signal_during_the_abort_reports_an_unknown_outcome() {
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::ScanAbort), Planned::held());
        let id = fx::job_id(2);
        let running = spawn_rt(&f, &["abort", &id, "--force"]);
        assert!(
            f.server
                .wait_for_route(Route::RedTeam(Rt::ScanAbort), 1, Duration::from_secs(20))
        );
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert!(
            out.stderr.ends_with(
                "\n  ✗ Error: Interrupted; the scan may already have been aborted (outcome unknown)\n\n"
            ),
            "{}",
            out.stderr
        );
        assert_eq!(f.server.rt_requests(Rt::ScanAbort).len(), 1);
    }

    /// A signal while the upload is held: the change may have been applied; one upload.
    #[test]
    fn a_signal_during_an_upload_reports_an_unknown_outcome() {
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::PromptUpload), Planned::held());
        let set = fx::prompt_set_id(1);
        let csv = f.file("p.csv", b"prompt\nx\n");
        let running = spawn_rt(&f, &["prompt-sets", "upload", &set, &csv]);
        assert!(f.server.wait_for_route(
            Route::RedTeam(Rt::PromptUpload),
            1,
            Duration::from_secs(20)
        ));
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert!(
            out.stderr.ends_with(
                "\n  ✗ Error: Interrupted; the change may already have been applied (outcome unknown)\n\n"
            ),
            "{}",
            out.stderr
        );
        assert_eq!(f.server.rt_requests(Rt::PromptUpload).len(), 1);
    }

    /// A signal before the scan POST (the categories read): no scan was started.
    #[test]
    fn a_signal_before_the_scan_start_starts_none() {
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::Categories), Planned::hang());
        let t = fx::target_id(1);
        let running = spawn_rt(&f, &["scan", "--target", &t, "--name", "early"]);
        assert!(f.server.wait_for_route(
            Route::RedTeam(Rt::Categories),
            1,
            Duration::from_secs(20)
        ));
        running.send_signal("INT");
        let out = running.wait();
        out.assert_code(130);
        assert!(
            out.stderr
                .ends_with("\n  ✗ Error: Interrupted; no scan was started\n\n"),
            "{}",
            out.stderr
        );
        assert!(f.server.rt_requests(Rt::ScanCreate).is_empty());
    }
}

// ---------------------------------------------------------------------------
// Secrets in the debug log (§15.4)
// ---------------------------------------------------------------------------

mod debug {
    use super::*;
    use airs_test_harness::debug_log;

    /// The debug log of a write records statuses and headers only: no credential from
    /// the input file and no minted token, with the SDK operation names (G9).
    #[test]
    fn write_debug_logs_hold_no_credential() {
        for (args, operation) in [
            (
                vec!["targets", "create", "--config"],
                "red_team.targets.create",
            ),
            (
                vec!["registry-credentials", "--output", "json"],
                "airs.red_team.instances.get_registry_credentials",
            ),
        ] {
            let f = fx();
            let config = f.file(
                "t.json",
                serde_json::to_string(&target_config("logged"))
                    .unwrap()
                    .as_bytes(),
            );
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec!["--debug"];
            full.extend(args.iter().copied());
            if args[0] == "targets" {
                full.push(&config);
            }
            let options = RunOptions::new().env("XDG_STATE_HOME", &state);
            let options = if args[0] == "registry-credentials" {
                options.allow_secret_output()
            } else {
                options
            };
            f.rt_with(&full, &options).assert_success();
            let (path, records) = debug_log::only_log(&f.sandbox);
            let text = std::fs::read_to_string(path).unwrap();
            for marker in fx::markers() {
                assert!(!text.contains(&marker), "{marker} in the debug log");
            }
            assert!(!text.contains(airs_test_harness::REGISTRY_TOKEN));
            let operations: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .collect();
            assert_eq!(operations, ["oauth.token", operation]);
        }
    }
}

// ---------------------------------------------------------------------------
// Every confirmation text (§15.3, D137)
// ---------------------------------------------------------------------------

mod confirmations {
    use super::*;

    /// Each confirming command asks its §15.3 question on the terminal, sends nothing
    /// while it waits, and sends its one write after `y`.
    #[test]
    fn every_prompt_text_d137() {
        let set = fx::prompt_set_id(1);
        let prompt = fx::prompt_id(1);
        let target = fx::target_id(1);
        let adapter = fx::adapter_id(1);
        for (args, question, route) in [
            (
                vec!["instances", "delete", "ten-1"],
                "? Delete Red Team instance ten-1? (y/N) ".to_owned(),
                Rt::InstanceDelete,
            ),
            (
                vec!["devices", "rm", "ten-1", "--serial-numbers", "SN1,SN2"],
                "? Delete devices SN1,SN2 from instance ten-1? (y/N) ".to_owned(),
                Rt::DevicesDelete,
            ),
            (
                vec!["prompts", "delete", &set, &prompt],
                format!("? Delete prompt {prompt} from prompt set {set}? (y/N) "),
                Rt::PromptDelete,
            ),
            (
                vec!["targets", "delete", &target],
                format!("? Delete red team target {target}? (y/N) "),
                Rt::TargetDelete,
            ),
            (
                vec!["adapter", "delete", &adapter],
                format!("? Delete adapter {adapter}? (y/N) "),
                Rt::AdapterDelete,
            ),
        ] {
            let f = fx();
            let full = rt(&args);
            let full: Vec<&str> = full.iter().map(String::as_str).collect();
            let mut session = spawn_pty(&rust(), &f.sandbox, &full, &RunOptions::new());
            session.expect(&question);
            assert!(f.server.requests().is_empty(), "{args:?}");
            session.send(b"y\n");
            let out = session.wait();
            out.run.assert_success();
            assert_eq!(f.server.rt_requests(route).len(), 1, "{args:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// The vendor 0.93.0 scan body of scm-sdk 0.2.2 (D304, D305, DESIGN §15.23)
// ---------------------------------------------------------------------------

mod contract {
    use super::*;

    fn target() -> String {
        fx::target_id(1)
    }

    /// `--depth`/`--breadth` above 20 and a name of fewer than 3 code points are usage
    /// errors before the tenant: no tenant, no request (D304, D305).
    #[test]
    fn scan_body_bounds_are_checked_before_the_tenant() {
        let t = target();
        let schema =
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan did not match schema";
        for (args, message) in [
            (
                vec![
                    "scan", "--target", &t, "--name", "abc", "--type", "DYNAMIC", "--depth", "21",
                ],
                "--depth must be at most 20 (the red team API maximum)".to_owned(),
            ),
            (
                vec![
                    "scan",
                    "--target",
                    &t,
                    "--name",
                    "abc",
                    "--type",
                    "DYNAMIC",
                    "--breadth",
                    "4294967295",
                ],
                "--breadth must be at most 20 (the red team API maximum)".to_owned(),
            ),
            (
                // Three UTF-16 units, two code points.
                vec!["scan", "--target", &t, "--name", "\u{1F600}a"],
                format!("{schema}: name: too_small"),
            ),
            (
                // The name is checked before the target id (§15.6 order).
                vec!["scan", "--target", "t-1", "--name", "\u{1F600}a"],
                format!("{schema}: name: too_small"),
            ),
        ] {
            assert_usage(&args, &message);
        }
    }

    /// The boundaries are sent: `--depth 20 --breadth 20` and a three-emoji name (three
    /// code points, six UTF-16 units).
    #[test]
    fn the_scan_body_boundaries_are_sent() {
        let t = target();
        let f = fx();
        f.rt(&[
            "scan",
            "--target",
            &t,
            "--name",
            "deep",
            "--type",
            "DYNAMIC",
            "--depth",
            "20",
            "--breadth",
            "20",
            "--no-wait",
        ])
        .assert_success();
        assert_eq!(
            f.body(Rt::ScanCreate)["job_metadata"],
            json!({"stream_breadth": 20, "stream_depth": 20})
        );
        let f = fx();
        let name = "\u{1F600}\u{1F600}\u{1F600}";
        f.rt(&["scan", "--target", &t, "--name", name, "--no-wait"])
            .assert_success();
        assert_eq!(f.body(Rt::ScanCreate)["name"], name);
    }
}

// ---------------------------------------------------------------------------
// Management 0.86.0 (scm-sdk 0.2.3, DESIGN §15.24)
// ---------------------------------------------------------------------------

mod management_0_86 {
    use super::*;

    /// A create body in the management 0.86.0 shape (the SDK example's): `VERTEX_AI`,
    /// `REALTIME`, the Vertex AI connection config, `client_session`, the audio
    /// templates and basic credentials (markers 24–26).
    fn vertex_config(name: &str) -> Value {
        json!({
            "name": name,
            "target_type": "AGENT",
            "connection_type": "VERTEX_AI",
            "api_endpoint_type": "PUBLIC",
            "response_mode": "REALTIME",
            "connection_params": {
                "api_endpoint": "wss://vertex.invalid/ws",
                "target_connection_config": fx::vertex_connection_config(),
                "multi_turn_config": {"type": "client_session"},
                "audio_request_json": {"audio": "{AUDIO}"},
                "audio_curl": format!("curl https://vertex.invalid/v1/audio -H 'Authorization: Bearer {}'", fx::secret(24))
            },
            "auth_type": "BASIC_AUTH",
            "auth_config": {"basic_username": fx::secret(25), "basic_password": fx::secret(26)}
        })
    }

    /// D328: `targets create`, `update` and `probe` send the 0.86.0 values the frozen
    /// TypeScript schema refuses (`VERTEX_AI`, `N8N`, `REALTIME`, `client_session`, a
    /// Vertex AI config), the body as given; the answer is printed redacted (D327, rule
    /// 1, rule 4), and every credential of the file joins the secret set: the bearer
    /// extracted from `audio_curl` withholds the description that echoes it, and the
    /// runner's fixture-marker check fails the test if any marker (24–26) prints.
    #[test]
    fn create_update_and_probe_send_the_0_86_values_d328() {
        let f = fx();
        let mut config = vertex_config("Vertex Realtime");
        config["description"] = json!(format!("audio bearer {}", fx::secret(24)));
        let path = f.file("v.json", &serde_json::to_vec(&config).unwrap());
        let out = f.rt(&["targets", "create", "--config", &path, "--output", "json"]);
        out.assert_success();
        assert_eq!(f.body(Rt::TargetCreate), config);
        let doc = out.json();
        assert_eq!(doc["description"], "[withheld]");
        assert_eq!(doc["connectionType"], "VERTEX_AI");
        assert_eq!(doc["responseMode"], "REALTIME");
        assert_eq!(doc["connectionParams"]["audio_curl"], "[REDACTED]");
        assert_eq!(
            doc["connectionParams"]["target_connection_config"]["project_id"],
            "[REDACTED]"
        );
        assert_eq!(doc["authConfig"]["basic_password"], "[REDACTED]");
        assert!(out.stderr.contains("✓ Target created: "), "{}", out.stderr);

        let target = fx::target_id(1);
        let mut n8n = vertex_config("Rest Target One");
        n8n["connection_type"] = json!("N8N");
        n8n["response_mode"] = json!("REST");
        let path = f.file("n.json", &serde_json::to_vec(&n8n).unwrap());
        f.clear();
        let out = f.rt(&["targets", "update", &target, "--config", &path]);
        out.assert_success();
        assert_eq!(f.body(Rt::TargetUpdate), n8n);
        assert_eq!(f.api(), [format!("PUT /redteam/mgmt/v1/target/{target}")]);

        f.clear();
        let out = f.rt(&["targets", "probe", "--config", &path, "--output", "json"]);
        out.assert_success();
        assert_eq!(f.body(Rt::TargetProbe), n8n);
        assert_eq!(out.json()["connection_params"]["audio_curl"], "[REDACTED]");
    }

    /// The Vertex AI request patterns of management 0.86.0 bound what is sent: a
    /// `project_id`, `location` or `engine_id` outside its pattern (a server mask
    /// included) fails the body check with the D116 text before the tenant is used
    /// (exit 1, no request), as every other `--config` body does.
    #[test]
    fn a_vertex_config_outside_the_vendor_patterns_is_refused() {
        for (field, value) in [
            ("project_id", "Example_Project"),
            ("project_id", "****"),
            ("location", "US Central"),
            ("engine_id", "engine-1"),
        ] {
            let f = fx();
            let mut config = vertex_config("Vertex Realtime");
            config["connection_params"]["target_connection_config"][field] = json!(value);
            let path = f.file("v.json", &serde_json::to_vec(&config).unwrap());
            let out = f.rt(&["targets", "create", "--config", &path]);
            out.assert_code(1);
            assert_eq!(
                out.error_line().as_deref(),
                Some(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/target did not match schema"
                ),
                "{field}={value}"
            );
            assert_eq!(out.stdout, "");
            assert_eq!(f.server.request_count(), 0, "{field}={value}");
        }
    }
}
