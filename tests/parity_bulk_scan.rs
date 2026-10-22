//! TS-vs-Rust parity for `runtime bulk-scan` and `runtime resume-poll` (DESIGN §14;
//! divergences D30, D118–D131). A resume is a second run of each side on its own
//! sandbox and server (`Side::resume`).
//!
//! Every scenario runs once per CLI, each on a fresh fixture server (so both get the
//! same receipt ids) and a fresh sandbox with the same tenant (`prod`, TSG 100). The
//! TypeScript config carries `dataDir: <sandbox>/tmp/ts-data/runs`, so its state lands
//! in `tmp/ts-data/bulk-scans/`; the Rust state goes to `$XDG_STATE_HOME` under `tmp/`.
//! Both get `--output-file` under `tmp/` and `--session-id s1`, so request bodies are
//! compared as JSON (D35) and the CSV bytes exactly. Divergence tests assert both
//! sides and name their §12 row. A missing reference fails each test
//! (`AIRS_ALLOW_PARITY_SKIP=1` skips it with a notice).

use std::path::PathBuf;
use std::time::Duration;

use airs_test_harness::{
    AsyncRule, AuthIdentity, Cli, FixtureServer, Planned, RecordedRequest, Route, Run, RunOptions,
    Sandbox, fixtures, require_ts,
};
use serde_json::{Value, json};

const PROFILE: &str = "bulk-profile";
const SESSION: &str = "s1";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// What one CLI did in one fresh scenario.
struct Side {
    cli: Cli,
    server: FixtureServer,
    sandbox: Sandbox,
    run: Run,
}

impl Side {
    fn state_dir(&self) -> PathBuf {
        if self.cli.is_ts() {
            self.sandbox.tmp().join("ts-data/bulk-scans")
        } else {
            self.sandbox.tmp().join("xdg/airs-cli/bulk-scans")
        }
    }

    fn state_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(self.state_dir())
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| path.to_string_lossy().ends_with(".bulk-scan.json"))
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        files
    }

    fn state_path(&self) -> PathBuf {
        let files = self.state_files();
        assert_eq!(files.len(), 1, "{}: one state: {files:?}", self.run.cli);
        files[0].clone()
    }

    fn state(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.state_path()).unwrap()).unwrap()
    }

    fn statuses(&self) -> Vec<String> {
        self.state()["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["status"].as_str().unwrap().to_owned())
            .collect()
    }

    fn out_path(&self) -> String {
        out_path(&self.sandbox)
    }

    fn csv(&self) -> String {
        std::fs::read_to_string(self.out_path()).unwrap()
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.server.requests()
    }

    fn posts(&self) -> Vec<RecordedRequest> {
        self.server.requests_for(Route::ScanAsync)
    }

    /// `P[ids]` per POST, `G` per poll, `R` per report query.
    fn sequence(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| match request.route {
                Route::ScanAsync => {
                    let ids: Vec<String> = request
                        .body_json()
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|object| object["req_id"].to_string())
                        .collect();
                    format!("P[{}]", ids.join(","))
                }
                Route::ScanResults => "G".to_owned(),
                Route::ScanReports => "R".to_owned(),
                other => other.label().to_owned(),
            })
            .collect()
    }

    /// `runtime resume-poll <state> <extra>` on this side's sandbox and server.
    fn resume_at(&self, state: &str, extra: &[&str], options: RunOptions) -> Run {
        let mut args = vec!["runtime", "resume-poll", state];
        args.extend_from_slice(extra);
        let options = options.env(
            "XDG_STATE_HOME",
            self.sandbox.tmp().join("xdg").display().to_string(),
        );
        let run = airs_test_harness::run(&self.cli, &self.sandbox, &args, &options);
        self.server.assert_no_unknown_routes();
        run
    }

    /// `runtime resume-poll <this side's state> <extra>`.
    fn resume(&self, extra: &[&str]) -> Run {
        let state = self.state_path().display().to_string();
        self.resume_at(&state, extra, RunOptions::new())
    }

    /// The request sequence after the first `mark` requests.
    fn sequence_since(&self, mark: usize) -> Vec<String> {
        self.sequence().split_off(mark)
    }

    /// stdout and stderr with this side's state and output paths replaced.
    fn normalised(&self, text: &str) -> String {
        let mut text = text.replace(&self.out_path(), "<OUTPUT>");
        if let Some(state) = self.state_files().first() {
            text = text.replace(&state.display().to_string(), "<STATE>");
        }
        text
    }
}

fn out_path(sandbox: &Sandbox) -> String {
    sandbox.tmp().join("out.csv").display().to_string()
}

/// Prepares the fixture server and the sandbox before a run.
type Prepare<'a> = Box<dyn Fn(&FixtureServer, &Sandbox) + 'a>;
/// The run options of one CLI in its sandbox.
type Options<'a> = Box<dyn Fn(&Cli, &Sandbox) -> RunOptions + 'a>;

/// One scenario, run once per CLI.
struct Scenario<'a> {
    prompts: Vec<String>,
    file_name: &'a str,
    raw_input: Option<Vec<u8>>,
    extra: Vec<String>,
    prepare: Prepare<'a>,
    output_file: bool,
    options: Options<'a>,
}

impl<'a> Scenario<'a> {
    fn new(prompts: &[&str]) -> Self {
        Self {
            prompts: prompts.iter().map(|p| (*p).to_owned()).collect(),
            file_name: "prompts.txt",
            raw_input: None,
            extra: Vec::new(),
            prepare: Box::new(|_, _| {}),
            output_file: true,
            options: Box::new(|_, _| RunOptions::new()),
        }
    }

    fn numbered(count: usize) -> Self {
        let prompts: Vec<String> = (0..count).map(|n| format!("distinct prompt {n}")).collect();
        let mut scenario = Self::new(&[]);
        scenario.prompts = prompts;
        scenario
    }

    fn input(mut self, name: &'a str, bytes: &[u8]) -> Self {
        self.file_name = name;
        self.raw_input = Some(bytes.to_vec());
        self
    }

    fn args(mut self, extra: &[&str]) -> Self {
        self.extra = extra.iter().map(|a| (*a).to_owned()).collect();
        self
    }

    fn prepare(mut self, prepare: impl Fn(&FixtureServer, &Sandbox) + 'a) -> Self {
        self.prepare = Box::new(prepare);
        self
    }

    fn without_output_file(mut self) -> Self {
        self.output_file = false;
        self
    }

    fn options(mut self, options: impl Fn(&Cli, &Sandbox) -> RunOptions + 'a) -> Self {
        self.options = Box::new(options);
        self
    }

    fn setup(&self) -> (FixtureServer, Sandbox, Vec<String>) {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let data = sandbox.tmp().join("ts-data/runs").display().to_string();
        let tenant = sandbox.add_fixture_tenant_with(&server, "prod", "100", |config| {
            config.set("dataDir", data.clone());
        });
        sandbox.register(&[&tenant], Some("prod"));
        let input = sandbox.tmp().join(self.file_name);
        let bytes = self
            .raw_input
            .clone()
            .unwrap_or_else(|| self.prompts.join("\n").into_bytes());
        std::fs::write(&input, bytes).unwrap();
        (self.prepare)(&server, &sandbox);
        let mut args = vec![
            "runtime".to_owned(),
            "bulk-scan".to_owned(),
            "--profile".to_owned(),
            PROFILE.to_owned(),
            "--file".to_owned(),
            input.display().to_string(),
            "--session-id".to_owned(),
            SESSION.to_owned(),
        ];
        if self.output_file {
            args.extend(["--output-file".to_owned(), out_path(&sandbox)]);
        }
        args.extend(self.extra.iter().cloned());
        (server, sandbox, args)
    }

    fn exec(&self, cli: &Cli) -> Side {
        let (server, sandbox, args) = self.setup();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let options = (self.options)(cli, &sandbox).env(
            "XDG_STATE_HOME",
            sandbox.tmp().join("xdg").display().to_string(),
        );
        let run = airs_test_harness::run(cli, &sandbox, &args, &options);
        server.assert_no_unknown_routes();
        Side {
            cli: cli.clone(),
            server,
            sandbox,
            run,
        }
    }

    /// Start the CLI, call `during` once the fixture saw `route` (an event), then wait.
    fn exec_interrupted(
        &self,
        cli: &Cli,
        route: Route,
        during: impl Fn(&airs_test_harness::Running),
    ) -> Side {
        let (server, sandbox, args) = self.setup();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let options = (self.options)(cli, &sandbox).env(
            "XDG_STATE_HOME",
            sandbox.tmp().join("xdg").display().to_string(),
        );
        let running = airs_test_harness::spawn(cli, &sandbox, &args, &options);
        assert!(server.wait_for_route(route, 1, Duration::from_secs(30)));
        during(&running);
        let run = running.wait();
        server.release_held();
        Side {
            cli: cli.clone(),
            server,
            sandbox,
            run,
        }
    }

    /// Start the CLI, call `during` on the running process (which waits for its own
    /// event), then wait.
    fn exec_watched(&self, cli: &Cli, during: impl Fn(&mut airs_test_harness::Running)) -> Side {
        let (server, sandbox, args) = self.setup();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let options = (self.options)(cli, &sandbox).env(
            "XDG_STATE_HOME",
            sandbox.tmp().join("xdg").display().to_string(),
        );
        let mut running = airs_test_harness::spawn(cli, &sandbox, &args, &options);
        during(&mut running);
        let run = running.wait();
        server.release_held();
        Side {
            cli: cli.clone(),
            server,
            sandbox,
            run,
        }
    }

    /// Both sides, or `None` (skip notice) without the reference.
    fn both(&self, test: &str) -> Option<(Side, Side)> {
        let ts = require_ts(test)?;
        Some((self.exec(&rust()), self.exec(&ts)))
    }
}

fn block_rule(server: &FixtureServer) {
    let mut verdict = fixtures::scan_block(PROFILE);
    verdict["prompt_detected"] = json!({"injection": true, "agent": false});
    server.add_async_rule("BLOCK", AsyncRule::verdict(verdict));
}

fn bodies(side: &Side) -> Vec<Value> {
    side.posts()
        .iter()
        .map(|post| post.body_json().unwrap())
        .collect()
}

fn assert_hashes_valid(side: &Side) {
    for post in side.posts() {
        assert!(
            matches!(
                post.auth,
                AuthIdentity::ApiKey {
                    hash_valid: true,
                    ..
                }
            ),
            "{}: {:?}",
            side.run.cli,
            post.auth
        );
    }
}

// ---------------------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The happy path: exit code, stdout and stderr bytes (paths normalised), the CSV
    /// bytes, the request sequence and bodies.
    #[test]
    fn a_completed_job_matches() {
        let scenario = Scenario::new(&["hello one", "please BLOCK me", "third, \"quoted\""])
            .prepare(|server, _| block_rule(server));
        let Some((rs, ts)) = scenario.both("a_completed_job_matches") else {
            return;
        };
        rs.run.assert_success();
        ts.run.assert_success();
        assert_eq!(rs.normalised(&rs.run.stdout), ts.normalised(&ts.run.stdout));
        assert_eq!(rs.normalised(&rs.run.stderr), ts.normalised(&ts.run.stderr));
        assert_eq!(rs.csv(), ts.csv());
        assert_eq!(rs.sequence(), ts.sequence());
        assert_eq!(bodies(&rs), bodies(&ts));
        assert_hashes_valid(&rs);
        assert_hashes_valid(&ts);
        assert_eq!(rs.statuses(), ts.statuses());
    }

    /// Batching and request order (B§5 sequences).
    #[test]
    fn batches_and_request_order_match() {
        for (count, size) in [(45, "25"), (7, "5"), (3, "2")] {
            let scenario = Scenario::numbered(count).args(&["--batch-size", size, "--quiet"]);
            let Some((rs, ts)) = scenario.both("batches_and_request_order_match") else {
                return;
            };
            rs.run.assert_success();
            ts.run.assert_success();
            assert_eq!(rs.sequence(), ts.sequence(), "{count}/{size}");
            assert_eq!(rs.csv(), ts.csv());
            assert_eq!(
                rs.run.stdout.replace(&rs.out_path(), "<O>"),
                ts.run.stdout.replace(&ts.out_path(), "<O>")
            );
        }
    }

    /// A failed row: both rows written, the summary, the failure line, exit 1.
    #[test]
    fn a_failed_row_matches() {
        let scenario = Scenario::new(&["a ok", "b FAILROW", "c timeout"]).prepare(|server, _| {
            server.add_async_rule("FAILROW", AsyncRule::failed());
            let mut timeout = fixtures::scan_allow(PROFILE);
            timeout["timeout"] = json!(true);
            server.add_async_rule("timeout", AsyncRule::verdict(timeout));
        });
        let Some((rs, ts)) = scenario.both("a_failed_row_matches") else {
            return;
        };
        rs.run.assert_code(1);
        ts.run.assert_code(1);
        assert_eq!(rs.normalised(&rs.run.stdout), ts.normalised(&ts.run.stdout));
        assert_eq!(rs.normalised(&rs.run.stderr), ts.normalised(&ts.run.stderr));
        assert_eq!(rs.csv(), ts.csv());
    }

    /// Rate-limited submissions and polls: the retries, their status lines, the order.
    #[test]
    fn rate_limit_retries_match() {
        let scenario = Scenario::numbered(2).prepare(|server, _| {
            for _ in 0..2 {
                server.push_once(
                    Route::ScanAsync,
                    Planned::json(429, &json!({})).with_retry_after(0),
                );
            }
            server.push_once(
                Route::ScanResults,
                Planned::json(429, &json!({})).with_retry_after(0),
            );
        });
        let Some((rs, ts)) = scenario.both("rate_limit_retries_match") else {
            return;
        };
        rs.run.assert_success();
        ts.run.assert_success();
        assert_eq!(rs.sequence(), ["P[0,1]", "P[0,1]", "P[0,1]", "G", "G"]);
        assert_eq!(rs.sequence(), ts.sequence());
        assert_eq!(rs.normalised(&rs.run.stderr), ts.normalised(&ts.run.stderr));
        assert!(
            rs.run
                .stderr
                .contains("  ⚠ Rate limited while submitting — retry 2 in 0s...\n")
        );
        assert!(
            rs.run
                .stderr
                .contains("  ⚠ Rate limited — retry 1 in 0s...\n")
        );
        assert_eq!(rs.csv(), ts.csv());
    }

    /// The report fallback of a terminal batch row.
    #[test]
    fn the_report_fallback_matches() {
        let scenario = Scenario::numbered(2).prepare(|server, _| {
            let id = fixtures::async_scan_id(1);
            let report = fixtures::async_report_id(1);
            server.push_once(
                Route::ScanResults,
                Planned::json(200, &json!([{"status": "completed", "scan_id": id}])),
            );
            server.push_once(
                Route::ScanReports,
                Planned::json(200, &json!([
                    {"report_id": report, "scan_id": id, "req_id": 1, "detection_results": [{"detection_service": "dlp", "verdict": "malicious", "action": "allow"}]},
                    {"report_id": report, "scan_id": id, "req_id": 0, "detection_results": [{"detection_service": "pi", "verdict": "benign", "action": "block"}]}
                ])),
            );
        });
        let Some((rs, ts)) = scenario.both("the_report_fallback_matches") else {
            return;
        };
        rs.run.assert_success();
        ts.run.assert_success();
        assert_eq!(rs.sequence(), ["P[0,1]", "G", "R"]);
        assert_eq!(rs.sequence(), ts.sequence());
        assert_eq!(rs.csv(), ts.csv());
    }

    /// A correlation error partway through a poll response: both CLIs keep the rows
    /// resolved before it (state and CSV) and exit 1.
    #[test]
    fn a_correlation_error_keeps_earlier_rows_matches() {
        let scenario = Scenario::numbered(2)
            .args(&["--quiet"])
            .prepare(|server, _| {
                let id = fixtures::async_scan_id(1);
                let mut good = fixtures::scan_allow(PROFILE);
                good["scan_id"] = json!(id);
                good["report_id"] = json!(fixtures::async_report_id(1));
                let mut bad = good.clone();
                bad["scan_id"] = json!("00000000-0000-4000-8000-00000000ffff");
                server.push_once(
                    Route::ScanResults,
                    Planned::json(
                        200,
                        &json!([
                            {"req_id": 0, "status": "complete", "scan_id": id, "result": good},
                            {"req_id": 1, "status": "complete", "scan_id": id, "result": bad}
                        ]),
                    ),
                );
            });
        let Some((rs, ts)) = scenario.both("a_correlation_error_keeps_earlier_rows_matches") else {
            return;
        };
        rs.run.assert_code(1);
        ts.run.assert_code(1);
        let message = "AIRS result correlation mismatch: nested scan ID 00000000-0000-4000-8000-00000000ffff does not match ";
        assert!(rs.run.stderr.contains(message), "{}", rs.run.stderr);
        assert!(ts.run.stderr.contains(message), "{}", ts.run.stderr);
        assert_eq!(rs.csv(), ts.csv());
        assert_eq!(rs.csv().split('\n').count(), 2, "the header and row 0");
        assert_eq!(rs.statuses(), ["complete", "submitted"]);
        assert_eq!(rs.statuses(), ts.statuses());
    }

    /// `--quiet`, and `--session-id ""` (no session on any object).
    #[test]
    fn quiet_and_an_empty_session_match() {
        let scenario = Scenario::numbered(2);
        let mut scenario = scenario.args(&["--quiet"]);
        scenario
            .extra
            .extend(["--session-id".to_owned(), String::new()]);
        let Some((rs, ts)) = scenario.both("quiet_and_an_empty_session_match") else {
            return;
        };
        rs.run.assert_success();
        ts.run.assert_success();
        assert_eq!(rs.normalised(&rs.run.stdout), ts.normalised(&ts.run.stdout));
        assert_eq!(rs.run.stderr, "");
        assert_eq!(ts.run.stderr, "");
        assert_eq!(bodies(&rs), bodies(&ts));
        assert!(bodies(&rs)[0][0]["scan_req"].get("session_id").is_none());
    }

    /// The input parsers' quirks (B§3) give the same prompts.
    #[test]
    fn the_input_quirks_match() {
        for (name, bytes) in [
            ("bom.csv", &b"\xef\xbb\xbfprompt\nhi\n"[..]),
            ("cr.csv", b"prompt\ra\rb"),
            ("multiline.csv", b"prompt,x\n\"line1\nline2\",1\n"),
            ("afterquote.csv", b"prompt,x\n\"ab\"cd,1\n"),
            ("spacequote.csv", b"prompt,x\n \"a,b\",1\n"),
            ("shortrow.csv", b"id,prompt\n1\n2,two\n"),
            ("hdrspace.CSV", b"id, PROMPT \n1,  padded  \n"),
            ("crlf.txt", b"a\r\n\r\n b\t\r\n"),
            ("dup", b"same\nsame\n"),
        ] {
            let scenario = Scenario::new(&[]).input(name, bytes).args(&["--quiet"]);
            let Some((rs, ts)) = scenario.both("the_input_quirks_match") else {
                return;
            };
            rs.run.assert_success();
            ts.run.assert_success();
            assert_eq!(bodies(&rs), bodies(&ts), "{name}");
            assert_eq!(rs.csv(), ts.csv(), "{name}");
        }
    }

    /// Usage errors: `--file` missing and an invalid `--batch-size` exit 2 with the TS
    /// texts and no request.
    #[test]
    fn usage_errors_match() {
        let Some(ts) = require_ts("usage_errors_match") else {
            return;
        };
        for extra in [&["--batch-size", "007"][..], &["--batch-size", "0"]] {
            let scenario = Scenario::numbered(1).args(extra);
            let (rs, ts) = (scenario.exec(&rust()), scenario.exec(&ts));
            rs.run.assert_code(2);
            ts.run.assert_code(2);
            assert_eq!(rs.run.stderr, ts.run.stderr);
            assert_eq!(rs.server.request_count() + ts.server.request_count(), 0);
        }
        let sandbox = Sandbox::new();
        for cli in [rust(), ts] {
            let out = airs_test_harness::run(
                &cli,
                &sandbox,
                &["runtime", "bulk-scan", "--profile", "p"],
                &RunOptions::new(),
            );
            out.assert_code(2);
            assert_eq!(
                out.stderr, "\n  ✗ --file <file> is required\n\n",
                "{}",
                out.cli
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D118: TypeScript keeps a version-2 state under `<dataDir>/../bulk-scans`; Rust a
    /// versioned Rust-only state under `$XDG_STATE_HOME/airs-cli/bulk-scans`.
    #[test]
    fn d118_state_location_and_format() {
        let scenario = Scenario::numbered(1).args(&["--quiet"]);
        let Some((rs, ts)) = scenario.both("d118_state_location_and_format") else {
            return;
        };
        rs.run.assert_success();
        ts.run.assert_success();
        let ts_state = ts.state();
        assert_eq!(ts_state["version"], 2);
        assert!(ts_state.get("format").is_none());
        assert!(
            ts.sandbox.tmp().join("xdg").read_dir().is_err(),
            "TS ignores XDG_STATE_HOME"
        );
        let rs_state = rs.state();
        assert_eq!(rs_state["format"], "airs-cli-rs.bulk-scan");
        assert_eq!(rs_state["version"], 1);
        assert!(rs_state["attempts"].is_array());
        assert!(
            !rs.sandbox.tmp().join("ts-data/bulk-scans").exists(),
            "Rust ignores dataDir"
        );
        let name = rs
            .state_path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(name.len(), 33 + ".bulk-scan.json".len());
    }

    /// D120: a session id over 100 characters: TypeScript records the chunk as
    /// ambiguous though nothing was sent; Rust refuses it as a usage error first.
    #[test]
    fn d120_a_long_session_id() {
        let long = "s".repeat(101);
        let scenario = Scenario::numbered(1).args(&["--session-id", &long]);
        let Some((rs, ts)) = scenario.both("d120_a_long_session_id") else {
            return;
        };
        ts.run.assert_code(1);
        assert!(
            ts.run
                .stderr
                .contains("did not match schema: 0.scan_req.session_id: too_big"),
            "{}",
            ts.run.stderr
        );
        assert_eq!(ts.statuses(), ["ambiguous"]);
        assert_eq!(ts.server.request_count(), 0);
        rs.run.assert_code(2);
        assert_eq!(
            rs.run.stderr,
            "\n  ✗ AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/async/request did not match schema: scan_req.session_id: too_big\n\n"
        );
        assert!(rs.state_files().is_empty());
        assert_eq!(rs.server.request_count(), 0);
    }

    /// D121: an existing output: TypeScript replaces it; Rust refuses before anything.
    #[test]
    fn d121_an_existing_output() {
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(|_, sandbox| {
                std::fs::write(out_path(sandbox), "precious").unwrap();
            });
        let Some((rs, ts)) = scenario.both("d121_an_existing_output") else {
            return;
        };
        ts.run.assert_success();
        assert!(ts.csv().starts_with("prompt,action"));
        rs.run.assert_code(1);
        assert_eq!(
            rs.run.stderr,
            format!(
                "\n  ✗ Error: {} already exists; choose another --output-file\n\n",
                rs.out_path()
            )
        );
        assert_eq!(rs.csv(), "precious");
        assert_eq!(rs.server.request_count(), 0);
    }

    /// D122: a profile name with `/`: TypeScript makes it a path (creating a
    /// directory); Rust maps it to `-` and stays in the working directory.
    #[test]
    fn d122_the_default_name() {
        let scenario = Scenario::new(&["x"])
            .without_output_file()
            .args(&["--quiet", "--profile", "a/b c"])
            .options(|_, _| RunOptions::new().allow_writes_under("cwd"));
        let Some((rs, ts)) = scenario.both("d122_the_default_name") else {
            return;
        };
        rs.run.assert_success();
        ts.run.assert_success();
        assert!(ts.sandbox.cwd().join("a/b-c-bulk-scan.csv").is_file());
        assert!(rs.sandbox.cwd().join("a-b-c-bulk-scan.csv").is_file());
        assert_eq!(rs.sandbox.cwd_listing().len(), 1);
    }

    /// D123: an output path that is a directory: TypeScript fails after it created an
    /// all-pending state; Rust refuses first and leaves no job.
    #[test]
    fn d123_no_orphan_job() {
        let scenario = Scenario::numbered(1).prepare(|_, sandbox| {
            std::fs::create_dir(out_path(sandbox)).unwrap();
        });
        let Some((rs, ts)) = scenario.both("d123_no_orphan_job") else {
            return;
        };
        ts.run.assert_code(1);
        assert_eq!(
            ts.statuses(),
            ["pending"],
            "an orphan state resume-poll would submit"
        );
        rs.run.assert_code(1);
        assert!(rs.state_files().is_empty());
        assert_eq!(rs.server.request_count() + ts.server.request_count(), 0);
    }

    /// D124: a `Retry-After: 120` on the submission: TypeScript announces (and would
    /// sleep) the full 120 s; Rust caps the wait at 60 s. Each status line is printed
    /// before its wait, so the test waits for the line (an event), then interrupts.
    #[test]
    fn d124_retry_after_is_capped() {
        let Some(ts) = require_ts("d124_retry_after_is_capped") else {
            return;
        };
        let scenario = Scenario::numbered(1)
            .prepare(|server, _| {
                server.push_once(
                    Route::ScanAsync,
                    Planned::json(429, &json!({})).with_header("retry-after", "120"),
                );
            })
            .options(|cli, _| {
                let options = RunOptions::new();
                if cli.is_ts() {
                    options.expect_signal()
                } else {
                    options
                }
            });
        let interrupt_after = |line: &'static str| {
            move |running: &mut airs_test_harness::Running| {
                assert!(
                    running.wait_for_stderr(line, Duration::from_secs(30)),
                    "the status line was printed"
                );
                running.send_signal("INT");
            }
        };
        let ts = scenario.exec_watched(
            &ts,
            interrupt_after("⚠ Rate limited while submitting — retry 1 in 120s..."),
        );
        let rs = scenario.exec_watched(
            &rust(),
            interrupt_after("⚠ Rate limited while submitting — retry 1 in 60s..."),
        );
        assert_eq!(ts.run.code, 130);
        assert!(
            !ts.run.stderr.contains("retry 1 in 60s"),
            "{}",
            ts.run.stderr
        );
        rs.run.assert_code(130);
        assert!(
            !rs.run.stderr.contains("retry 1 in 120s"),
            "{}",
            rs.run.stderr
        );
        assert_eq!(ts.posts().len(), 1);
        assert_eq!(rs.posts().len(), 1);
        assert_eq!(rs.statuses(), ["pending"]);
    }

    /// D132: a prompt within the 2 MiB content limit whose control characters
    /// JSON-encode past the request budget: TypeScript sends the body; Rust refuses the
    /// prompt at planning with its index, sends nothing and creates no job.
    #[test]
    fn d132_a_prompt_too_large_once_encoded() {
        let mut bytes = b"a".to_vec();
        bytes.extend(std::iter::repeat_n(0x01u8, 2_000_000));
        bytes.push(b'b');
        let scenario = Scenario::new(&[])
            .input("prompts.txt", &bytes)
            .args(&["--quiet"]);
        let Some((rs, ts)) = scenario.both("d132_a_prompt_too_large_once_encoded") else {
            return;
        };
        assert_eq!(ts.posts().len(), 1, "TypeScript sent it: {}", ts.run.stderr);
        assert!(ts.posts()[0].body.len() > 8 * 1024 * 1024);
        rs.run.assert_code(1);
        assert!(
            rs.run.stderr.starts_with(
                "\n  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:prompt exceeds the request size limit of "
            ),
            "{}",
            rs.run.stderr
        );
        assert!(rs.run.stderr.contains("\n    Prompt index 0\n"));
        assert_eq!(rs.server.request_count(), 0);
        assert!(rs.state_files().is_empty());
    }

    /// D125: a poll 500 whose message mentions a rate limit: TypeScript retries it;
    /// Rust stops (only HTTP 429 is a rate limit). Asserted by outcome.
    #[test]
    fn d125_only_429_is_a_rate_limit() {
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(|server, _| {
                server.push_once(
                    Route::ScanResults,
                    Planned::json(500, &json!({"message": "rate limit exceeded"}))
                        .with_retry_after(0),
                );
            });
        let Some((rs, ts)) = scenario.both("d125_only_429_is_a_rate_limit") else {
            return;
        };
        ts.run.assert_success();
        assert_eq!(ts.server.route_count(Route::ScanResults), 2);
        rs.run.assert_code(1);
        assert_eq!(rs.server.route_count(Route::ScanResults), 1);
        assert_eq!(rs.statuses(), ["submitted"]);
    }

    /// D126: a receipt whose scan id is not a UUID: TypeScript saves it as submitted
    /// and every poll fails; Rust records the chunk as ambiguous at once.
    #[test]
    fn d126_an_unusable_receipt() {
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(|server, _| {
                server.push_once(
                    Route::ScanAsync,
                    Planned::json(
                        200,
                        &json!({"received": "2026-10-17T00:00:00Z", "scan_id": "not-a-uuid"}),
                    ),
                );
            });
        let Some((rs, ts)) = scenario.both("d126_an_unusable_receipt") else {
            return;
        };
        ts.run.assert_code(1);
        assert!(
            ts.run.stderr.contains("Invalid scan_id"),
            "{}",
            ts.run.stderr
        );
        assert_eq!(ts.statuses(), ["submitted"]);
        rs.run.assert_code(1);
        assert!(
            rs.run
                .stderr
                .contains("AIRS accepted prompts 0, but its receipt has no usable scan id")
        );
        assert_eq!(rs.statuses(), ["ambiguous"]);
        assert_eq!(
            rs.server.route_count(Route::ScanResults) + ts.server.route_count(Route::ScanResults),
            0
        );
    }

    /// D128: an unterminated quote and invalid UTF-8: TypeScript sends what it read;
    /// Rust refuses the file before the tenant.
    #[test]
    fn d128_the_input_file_rules() {
        for (name, bytes, sent) in [
            ("unterminated.csv", &b"prompt\n\"abc\ndef\n"[..], "abc\ndef"),
            ("latin1.txt", b"caf\xe9\n", "caf\u{fffd}"),
        ] {
            let scenario = Scenario::new(&[]).input(name, bytes).args(&["--quiet"]);
            let Some((rs, ts)) = scenario.both("d128_the_input_file_rules") else {
                return;
            };
            ts.run.assert_success();
            assert_eq!(bodies(&ts)[0][0]["scan_req"]["contents"][0]["prompt"], sent);
            rs.run.assert_code(1);
            assert_eq!(rs.server.request_count(), 0);
            assert!(rs.state_files().is_empty());
        }
    }

    /// D129: SIGINT while the submission is in flight: TypeScript dies and leaves the
    /// chunk `submitting`; Rust cancels it, records it as ambiguous and names the job.
    #[test]
    fn d129_an_interrupted_submission() {
        let Some(ts) = require_ts("d129_an_interrupted_submission") else {
            return;
        };
        let scenario = Scenario::numbered(2)
            .args(&["--quiet"])
            .prepare(|server, _| server.push_once(Route::ScanAsync, Planned::held()))
            .options(|cli, _| {
                let options = RunOptions::new();
                if cli.is_ts() {
                    options.expect_signal()
                } else {
                    options
                }
            });
        let ts =
            scenario.exec_interrupted(&ts, Route::ScanAsync, |running| running.send_signal("INT"));
        assert_eq!(ts.run.code, 130);
        assert_eq!(ts.statuses(), ["submitting", "submitting"]);
        assert!(!ts.run.stderr.contains("Interrupted"));
        let rs = scenario.exec_interrupted(&rust(), Route::ScanAsync, |running| {
            running.send_signal("INT")
        });
        rs.run.assert_code(130);
        assert_eq!(rs.statuses(), ["ambiguous", "ambiguous"]);
        assert!(rs.run.stderr.contains("Interrupted; prompts 0-1 may already have been submitted (outcome unknown); the job was saved in "));
    }

    /// D130: `--output json`: TypeScript ignores it (pretty text); Rust prints the JSON
    /// summary. The CSV is the same.
    #[test]
    fn d130_output_formats() {
        let scenario = Scenario::numbered(1).args(&["--output", "json", "--quiet"]);
        let Some((rs, ts)) = scenario.both("d130_output_formats") else {
            return;
        };
        rs.run.assert_success();
        ts.run.assert_success();
        assert!(
            ts.run.stdout.starts_with("  Total    1\n"),
            "{}",
            ts.run.stdout
        );
        assert_eq!(rs.run.json()["total"], 1);
        assert_eq!(rs.csv(), ts.csv());
    }

    /// D131: a 400 with a server message: TypeScript prints and stores the server text;
    /// Rust prints the §6 message, stores none of it and names the job.
    #[test]
    fn d131_no_server_text() {
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(|server, _| {
                server.push_once(
                    Route::ScanAsync,
                    Planned::json(400, &json!({"message": "profile not found"})),
                );
            });
        let Some((rs, ts)) = scenario.both("d131_no_server_text") else {
            return;
        };
        ts.run.assert_code(1);
        assert!(
            ts.run
                .stderr
                .contains("AISEC_CLIENT_SIDE_ERROR:profile not found"),
            "{}",
            ts.run.stderr
        );
        assert!(
            std::fs::read_to_string(ts.state_path())
                .unwrap()
                .contains("profile not found")
        );
        assert_eq!(ts.statuses(), ["pending"]);
        rs.run.assert_code(1);
        assert!(
            rs.run
                .stderr
                .starts_with("\n  ✗ Error: AISEC_CLIENT_SIDE_ERROR:API error 400\n    HTTP 400\n")
        );
        assert!(
            rs.run
                .stderr
                .contains("The job was saved; resume it with 'airs runtime resume-poll ")
        );
        assert!(!rs.run.stderr.contains("profile not found"));
        assert!(
            !std::fs::read_to_string(rs.state_path())
                .unwrap()
                .contains("profile not found")
        );
        assert_eq!(rs.statuses(), ["pending"]);
    }

    /// D30 (0.5): a redirected submission: TypeScript follows it and re-sends the
    /// prompts; Rust does not follow, and the prompts stay pending.
    #[test]
    fn d30_a_redirected_submission() {
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(|server, _| {
                let location = server.url("/scan/v1/scan/async/request");
                server.push_once(Route::ScanAsync, Planned::redirect(307, &location));
            });
        let Some((rs, ts)) = scenario.both("d30_a_redirected_submission") else {
            return;
        };
        ts.run.assert_success();
        assert_eq!(ts.posts().len(), 2, "the body was sent twice");
        rs.run.assert_code(1);
        assert_eq!(rs.posts().len(), 1);
        assert_eq!(rs.statuses(), ["pending"]);
    }
}

// ---------------------------------------------------------------------------------------
// `runtime resume-poll`: parity and divergences
// ---------------------------------------------------------------------------------------

mod resume_parity {
    use super::*;

    /// TypeScript's order: the state path is resolved (and the job locked) before the
    /// tenant is loaded, so a missing state with no tenant selected fails on the path
    /// in both CLIs (the texts differ: TypeScript prints the raw `realpath` error, D128's
    /// style; airs-cli-rs its `Cannot read` message).
    #[test]
    fn the_state_path_comes_before_the_tenant_matches() {
        let Some(ts) = require_ts("the_state_path_comes_before_the_tenant_matches") else {
            return;
        };
        for cli in [rust(), ts] {
            let sandbox = Sandbox::new();
            let options = RunOptions::new().env(
                "XDG_STATE_HOME",
                sandbox.tmp().join("xdg").display().to_string(),
            );
            let run = airs_test_harness::run(
                &cli,
                &sandbox,
                &["runtime", "resume-poll", "nope.json"],
                &options,
            );
            run.assert_code(1);
            assert!(
                !run.stderr.to_ascii_lowercase().contains("tenant"),
                "{}: {}",
                run.cli,
                run.stderr
            );
            if cli.is_ts() {
                assert!(
                    run.stderr.contains("ENOENT") && run.stderr.contains("realpath"),
                    "{}",
                    run.stderr
                );
            } else {
                assert_eq!(
                    run.stderr,
                    "\n  ✗ Error: Cannot read nope.json (missing, not a regular file, unreadable or larger than 128 MiB)\n\n"
                );
            }
        }
    }

    /// int-spec #10: a poll failure, then a resume that completes the job: the same
    /// status lines, summary, CSV bytes and requests.
    #[test]
    fn a_poll_failure_then_resume_matches() {
        let scenario = Scenario::numbered(2)
            .args(&["--quiet"])
            .prepare(|server, _| {
                server.push_once(Route::ScanResults, Planned::json(500, &json!({})));
            });
        let Some((rs, ts)) = scenario.both("a_poll_failure_then_resume_matches") else {
            return;
        };
        rs.run.assert_code(1);
        ts.run.assert_code(1);
        let (rs_mark, ts_mark) = (rs.server.request_count(), ts.server.request_count());
        let (rs_out, ts_out) = (rs.resume(&[]), ts.resume(&[]));
        rs_out.assert_success();
        ts_out.assert_success();
        assert_eq!(rs.normalised(&rs_out.stdout), ts.normalised(&ts_out.stdout));
        assert_eq!(rs.normalised(&rs_out.stderr), ts.normalised(&ts_out.stderr));
        assert_eq!(rs.sequence_since(rs_mark), ["G"]);
        assert_eq!(rs.sequence_since(rs_mark), ts.sequence_since(ts_mark));
        assert_eq!(rs.csv(), ts.csv());
        assert_eq!(rs.statuses(), ts.statuses());
    }

    /// int-spec #13: a rejected chunk stays pending and the resume submits it once.
    #[test]
    fn a_rejected_chunk_then_resume_matches() {
        let scenario = Scenario::numbered(2)
            .args(&["--quiet"])
            .prepare(|server, _| {
                server.push_once(Route::ScanAsync, Planned::json(400, &json!({})));
            });
        let Some((rs, ts)) = scenario.both("a_rejected_chunk_then_resume_matches") else {
            return;
        };
        let (rs_mark, ts_mark) = (rs.server.request_count(), ts.server.request_count());
        let (rs_out, ts_out) = (rs.resume(&[]), ts.resume(&[]));
        rs_out.assert_success();
        ts_out.assert_success();
        assert_eq!(rs.sequence_since(rs_mark), ["P[0,1]", "G"]);
        assert_eq!(rs.sequence_since(rs_mark), ts.sequence_since(ts_mark));
        assert_eq!(bodies(&rs), bodies(&ts));
        assert_eq!(rs.normalised(&rs_out.stderr), ts.normalised(&ts_out.stderr));
        assert_eq!(rs.csv(), ts.csv());
    }

    /// int-spec #19: a completed job resumes with no request and the same bytes; a
    /// failed row exits 1 again (int-spec #14).
    #[test]
    fn a_completed_job_resumes_identically() {
        let scenario = Scenario::new(&["a ok", "b FAILROW"])
            .args(&["--quiet"])
            .prepare(|server, _| server.add_async_rule("FAILROW", AsyncRule::failed()));
        let Some((rs, ts)) = scenario.both("a_completed_job_resumes_identically") else {
            return;
        };
        let (rs_csv, ts_csv) = (rs.csv(), ts.csv());
        assert_eq!(rs_csv, ts_csv);
        let (rs_mark, ts_mark) = (rs.server.request_count(), ts.server.request_count());
        let (rs_out, ts_out) = (rs.resume(&[]), ts.resume(&[]));
        rs_out.assert_code(1);
        ts_out.assert_code(1);
        assert_eq!(rs.server.request_count(), rs_mark);
        assert_eq!(ts.server.request_count(), ts_mark);
        assert_eq!(rs.csv(), rs_csv);
        assert_eq!(ts.csv(), ts_csv);
        assert_eq!(rs.normalised(&rs_out.stdout), ts.normalised(&ts_out.stdout));
        assert_eq!(rs.normalised(&rs_out.stderr), ts.normalised(&ts_out.stderr));
    }

    /// int-spec #22: the resume keeps the stored batch size (poll, submit, poll per
    /// logical batch).
    #[test]
    fn resume_keeps_the_stored_batch_size() {
        let scenario = Scenario::numbered(6)
            .args(&["--quiet", "--batch-size", "2"])
            .prepare(|server, _| {
                server.push_once(Route::ScanResults, Planned::json(500, &json!({})));
            });
        let Some((rs, ts)) = scenario.both("resume_keeps_the_stored_batch_size") else {
            return;
        };
        let (rs_mark, ts_mark) = (rs.server.request_count(), ts.server.request_count());
        rs.resume(&["--quiet"]).assert_success();
        ts.resume(&["--quiet"]).assert_success();
        assert_eq!(
            rs.sequence_since(rs_mark),
            ["G", "P[2,3]", "G", "P[4,5]", "G"]
        );
        assert_eq!(rs.sequence_since(rs_mark), ts.sequence_since(ts_mark));
        assert_eq!(rs.csv(), ts.csv());
    }
}

mod resume_divergence {
    use super::*;

    fn poll_failure(server: &FixtureServer, _: &Sandbox) {
        server.push_once(Route::ScanResults, Planned::json(500, &json!({})));
    }

    /// Run airs-cli-rs `resume-poll <state>` in `side`'s sandbox against its server.
    fn rust_resume(side: &Side, state: &str, extra: &[&str]) -> Run {
        let mut args = vec!["runtime", "resume-poll", state];
        args.extend_from_slice(extra);
        let options = RunOptions::new().env(
            "XDG_STATE_HOME",
            side.sandbox.tmp().join("xdg").display().to_string(),
        );
        let run = airs_test_harness::run(&rust(), &side.sandbox, &args, &options);
        side.server.assert_no_unknown_routes();
        run
    }

    /// D118: a TypeScript job's state: TypeScript resumes it; airs-cli-rs refuses it
    /// with its own message, sends nothing and changes nothing.
    #[test]
    fn d118_a_typescript_state_is_refused() {
        let Some(ts) = require_ts("d118_a_typescript_state_is_refused") else {
            return;
        };
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(poll_failure);
        let ts = scenario.exec(&ts);
        ts.run.assert_code(1);
        let state = ts.state_path().display().to_string();
        let bytes = std::fs::read(ts.state_path()).unwrap();
        let mark = ts.server.request_count();
        let rs_out = rust_resume(&ts, &state, &[]);
        rs_out.assert_code(1);
        assert_eq!(
            rs_out.stderr,
            format!(
                "\n  ✗ Error: {state} is a TypeScript airs-cli bulk-scan state; airs cannot resume it. Resume it with the TypeScript airs-cli, or start a new job with 'airs runtime bulk-scan'.\n\n"
            )
        );
        assert_eq!(ts.server.request_count(), mark);
        assert_eq!(std::fs::read(ts.state_path()).unwrap(), bytes);
        let ts_out = ts.resume(&["--quiet"]);
        ts_out.assert_success();
        assert_eq!(ts.statuses(), ["complete"]);
    }

    /// D119: the job lock. A live owner is refused at once on both sides (TypeScript
    /// names its pid, airs-cli-rs its pid, host and start time). A malformed record
    /// blocks TypeScript until it is removed by hand; airs-cli-rs decides by `flock`
    /// alone, so once the holder is gone it proceeds.
    #[test]
    fn d119_the_job_lock() {
        let Some(ts) = require_ts("d119_the_job_lock") else {
            return;
        };
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(poll_failure);
        let ts = scenario.exec(&ts);
        let rs = scenario.exec(&rust());
        let ts_state = ts.state_path().display().to_string();
        let ts_lock = PathBuf::from(format!("{ts_state}.lock"));
        let write_lock = |path: &std::path::Path, bytes: &[u8]| {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
        };
        let (ts_mark, rs_mark) = (ts.server.request_count(), rs.server.request_count());
        // A live owner.
        let pid = std::process::id();
        write_lock(
            &ts_lock,
            json!({"version": 1, "pid": pid, "createdAt": "2026-10-17T00:00:00.000Z", "token": "00000000-0000-4000-8000-000000000001"})
                .to_string()
                .as_bytes(),
        );
        let ts_out = ts.resume(&[]);
        ts_out.assert_code(1);
        assert_eq!(
            ts_out.stderr,
            format!(
                "\n  ✗ Error: Bulk-scan job is already active in process {pid}. Wait for it to finish before resuming {ts_state}.\n\n"
            )
        );
        let rs_state = rs.state_path();
        let rs_name = rs_state.file_name().unwrap().to_string_lossy().into_owned();
        let rs_lock = rs_state.with_file_name(format!(
            "{}.lock",
            rs_name.strip_suffix(".bulk-scan.json").unwrap()
        ));
        let holder = airs_test_harness::lock_holder::spawn_file(
            "resume_divergence::lock_holder_helper",
            &rs_lock,
            Duration::from_secs(60),
        );
        let rs_out = rs.resume(&[]);
        rs_out.assert_code(1);
        assert!(
            rs_out.stderr.starts_with(&format!(
                "\n  ✗ Error: Bulk-scan job is already active in process {} on {} since ",
                holder.pid(),
                airs_test_harness::lock_holder::host_name()
            )),
            "{}",
            rs_out.stderr
        );
        assert!(rs_out.stderr.ends_with(&format!(
            ". Wait for it to finish before resuming {}.\n\n",
            rs_state.display()
        )));
        // A malformed record.
        write_lock(&ts_lock, b"garbage");
        let ts_out = ts.resume(&[]);
        ts_out.assert_code(1);
        assert!(
            ts_out
                .stderr
                .contains("is malformed. If no bulk-scan process is running, remove it manually."),
            "{}",
            ts_out.stderr
        );
        holder.kill();
        write_lock(&rs_lock, b"garbage");
        rs.resume(&["--quiet"]).assert_success();
        assert_eq!(
            ts.server.request_count(),
            ts_mark,
            "TypeScript sent nothing"
        );
        assert_eq!(rs.server.request_count(), rs_mark + 1, "one poll");
        assert!(rs_lock.exists());
    }

    /// The lock-holder helper process (`lock_holder::spawn_file`).
    #[test]
    #[ignore = "helper process for the lock tests"]
    fn lock_holder_helper() {
        airs_test_harness::lock_holder::run_from_env();
    }

    /// D121: `resume-poll --output-file` to an existing file: TypeScript overwrites it
    /// and re-points the job; airs-cli-rs refuses before anything is sent.
    #[test]
    fn d121_resume_to_an_existing_file() {
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(poll_failure);
        let Some((rs, ts)) = scenario.both("d121_resume_to_an_existing_file") else {
            return;
        };
        let precious = |side: &Side| {
            let path = side.sandbox.tmp().join("precious.csv");
            std::fs::write(&path, "precious").unwrap();
            path
        };
        let (rs_path, ts_path) = (precious(&rs), precious(&ts));
        let rs_mark = rs.server.request_count();
        let ts_out = ts.resume(&["--output-file", &ts_path.display().to_string()]);
        ts_out.assert_success();
        assert!(
            std::fs::read_to_string(&ts_path)
                .unwrap()
                .starts_with("prompt,action")
        );
        let rs_out = rs.resume(&["--output-file", &rs_path.display().to_string()]);
        rs_out.assert_code(1);
        assert_eq!(
            rs_out.stderr,
            format!(
                "\n  ✗ Error: {} already exists; choose another --output-file\n\n",
                rs_path.display()
            )
        );
        assert_eq!(std::fs::read_to_string(&rs_path).unwrap(), "precious");
        assert_eq!(rs.server.request_count(), rs_mark);
    }

    /// D127: a copy of a job's state with pending prompts: TypeScript resumes the copy
    /// and submits them again; airs-cli-rs resumes only the job in its state directory.
    #[test]
    fn d127_a_copied_state() {
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(|server, _| {
                server.push_once(Route::ScanAsync, Planned::json(400, &json!({})));
            });
        let Some((rs, ts)) = scenario.both("d127_a_copied_state") else {
            return;
        };
        let copy = |side: &Side| {
            let path = side.sandbox.tmp().join("copy.bulk-scan.json");
            std::fs::copy(side.state_path(), &path).unwrap();
            path.display().to_string()
        };
        let (rs_copy, ts_copy) = (copy(&rs), copy(&ts));
        let ts_out = ts.resume_at(&ts_copy, &["--quiet"], RunOptions::new());
        ts_out.assert_success();
        assert_eq!(ts.posts().len(), 2, "the copy submitted the prompt again");
        let rs_out = rs.resume_at(&rs_copy, &[], RunOptions::new());
        rs_out.assert_code(1);
        assert_eq!(
            rs_out.stderr,
            format!(
                "\n  ✗ Error: {rs_copy} is not an airs bulk-scan job in {}; resume-poll resumes only jobs in its state directory (a moved or copied state cannot be resumed)\n\n",
                rs.state_dir().canonicalize().unwrap().display()
            )
        );
        assert_eq!(rs.posts().len(), 1);
    }

    /// D131: the ambiguous refusal: the same TypeScript message on both sides; airs-cli-rs
    /// adds a counts line. Neither sends anything.
    #[test]
    fn d131_the_ambiguous_refusal_adds_counts() {
        let scenario = Scenario::numbered(1)
            .args(&["--quiet"])
            .prepare(|server, _| {
                server.push_once(Route::ScanAsync, Planned::json(500, &json!({})));
            });
        let Some((rs, ts)) = scenario.both("d131_the_ambiguous_refusal_adds_counts") else {
            return;
        };
        assert_eq!(rs.statuses(), ["ambiguous"]);
        assert_eq!(ts.statuses(), ["ambiguous"]);
        let (rs_mark, ts_mark) = (rs.server.request_count(), ts.server.request_count());
        let (rs_out, ts_out) = (rs.resume(&[]), ts.resume(&[]));
        rs_out.assert_code(1);
        ts_out.assert_code(1);
        let message = "\n  ✗ Error: Cannot safely resubmit prompt 0: its submission outcome is ambiguous. Known accepted results were preserved; inspect <STATE> before taking manual action.\n";
        assert_eq!(ts.normalised(&ts_out.stderr), format!("{message}\n"));
        assert_eq!(
            rs.normalised(&rs_out.stderr),
            format!(
                "{message}    1 prompt(s) have an unknown submission outcome and 0 were not submitted; nothing will be resubmitted automatically.\n\n"
            )
        );
        assert_eq!(rs.server.request_count(), rs_mark);
        assert_eq!(ts.server.request_count(), ts_mark);
    }
}
