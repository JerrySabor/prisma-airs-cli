//! Parity tests for the `--debug` API log: the D61–D69 differences, each asserted on
//! both CLIs against the loopback fixture.
//!
//! The TypeScript reference writes `./debug-api-<ms>-<8 hex>.jsonl` in its working
//! directory and logs only five production host names, so against loopback its file
//! stays empty (L§1.5). These tests therefore assert TS's empty cwd file next to the
//! Rust records. TS runs get `allow_writes_under("cwd")`; every log file, in either
//! place, is leak-checked by the runner and by `debug_log::assert_logs_clean`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use airs_test_harness::debug_log::{self, log_dir, log_files, xdg_state_home};
use airs_test_harness::{
    Cli, FixtureServer, Planned, Route, Run, RunOptions, Sandbox, assert_json_semantic_eq,
    fixtures, require_ts, run,
};
use serde_json::Value;

const TSG: &str = "100";
const LIST: &[&str] = &["--debug", "runtime", "profiles", "list", "--output", "json"];
const HINT: &str = "    Re-run with --debug to capture redacted API diagnostics.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

fn fx() -> Fx {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    server.set_profiles(
        TSG,
        vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(2, "beta", 1),
        ],
    );
    Fx { server, sandbox }
}

impl Fx {
    /// Rust: `XDG_STATE_HOME=<sandbox>/tmp/xdg`.
    fn rust_options(&self) -> RunOptions {
        RunOptions::new().env(
            "XDG_STATE_HOME",
            xdg_state_home(&self.sandbox).display().to_string(),
        )
    }

    /// Runs one CLI and returns the run plus the requests it sent; TS may write its log
    /// into the working directory, nothing else may change.
    fn run(&self, cli: &Cli, args: &[&str]) -> (Run, usize) {
        let options = if cli.is_ts() {
            RunOptions::new().allow_writes_under("cwd")
        } else {
            self.rust_options()
        };
        self.run_with(cli, args, options)
    }

    fn run_with(&self, cli: &Cli, args: &[&str], options: RunOptions) -> (Run, usize) {
        self.server.clear_requests();
        let before = self.sandbox.snapshot();
        let out = run(cli, &self.sandbox, args, &options);
        self.sandbox.assert_unchanged(&before);
        self.server.assert_no_unknown_routes();
        debug_log::assert_logs_clean(
            &self.sandbox,
            &self.server,
            &[log_dir(&self.sandbox), self.sandbox.cwd()],
            &[],
        );
        (out, self.server.requests().len())
    }

    /// The TS log files in the working directory.
    fn ts_logs(&self) -> Vec<PathBuf> {
        log_files(&self.sandbox.cwd())
    }

    fn rust_logs(&self) -> Vec<PathBuf> {
        log_files(&log_dir(&self.sandbox))
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

fn notice(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("  Debug: API log → "))
}

fn rust_records(f: &Fx) -> Vec<Value> {
    let logs = f.rust_logs();
    assert_eq!(logs.len(), 1, "{logs:?}");
    debug_log::records(&logs[0])
}

/// TS's log: exactly one file in its cwd, 0600, empty against loopback.
fn assert_ts_empty_log(f: &Fx, ts: &Run) -> PathBuf {
    let logs = f.ts_logs();
    assert_eq!(logs.len(), 1, "{logs:?}");
    assert_eq!(
        fs::read(&logs[0]).unwrap(),
        b"",
        "TS logs nothing for loopback hosts"
    );
    assert_eq!(mode(&logs[0]), 0o600);
    assert_eq!(notice(&ts.stderr), Some(logs[0].to_str().unwrap()));
    logs[0].clone()
}

/// D61: TS writes `./debug-api-…jsonl` in the working directory and never prunes; Rust
/// writes under `$XDG_STATE_HOME/airs-cli/debug/` (0700 / 0600) and keeps the newest 20.
#[test]
fn d61_log_location_permissions_retention() {
    let Some(ts) = require_ts("d61_log_location_permissions_retention") else {
        return;
    };
    let f = fx();
    let dir = log_dir(&f.sandbox);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    for index in 0..25u64 {
        let name = format!("debug-api-{}-0000000a.jsonl", 1_000_000_000_000 + index);
        fs::write(dir.join(&name), b"").unwrap();
        fs::write(f.sandbox.cwd().join(&name), b"").unwrap();
    }
    let (rust_run, _) = f.run(&rust(), LIST);
    let (ts_run, _) = f.run(&ts, LIST);
    rust_run.assert_success();
    ts_run.assert_success();
    assert_json_semantic_eq(&rust_run.json(), &ts_run.json());
    // TS: one more file in the cwd, nothing pruned.
    assert_eq!(f.ts_logs().len(), 26);
    let ts_log = PathBuf::from(notice(&ts_run.stderr).unwrap());
    assert_eq!(ts_log.parent().unwrap(), f.sandbox.cwd());
    assert_eq!(mode(&ts_log), 0o600);
    // Rust: the state directory, the newest 20 kept, this run's file among them.
    let rust_log = PathBuf::from(notice(&rust_run.stderr).unwrap());
    assert_eq!(rust_log.parent().unwrap(), dir);
    assert_eq!(f.rust_logs().len(), 20);
    assert!(f.rust_logs().contains(&rust_log));
    assert_eq!(mode(&rust_log), 0o600);
}

/// D62: TS logs only five production host names, so a loopback run leaves an empty
/// file; Rust records every attempt of every client, whatever the host.
#[test]
fn d62_every_host_is_logged() {
    let Some(ts) = require_ts("d62_every_host_is_logged") else {
        return;
    };
    let f = fx();
    let doctor = ["--debug", "doctor", "--output", "json"];
    let (rust_run, rust_sent) = f.run(&rust(), &doctor);
    let (ts_run, ts_sent) = f.run(&ts, &doctor);
    assert!(ts_sent > 0, "TS sent requests");
    assert_ts_empty_log(&f, &ts_run);
    let records = rust_records(&f);
    assert_eq!(records.len(), rust_sent, "one record per request");
    let operations: Vec<&str> = records
        .iter()
        .map(|record| record["operation"].as_str().unwrap())
        .collect();
    for expected in [
        "oauth.token",
        "airs.management.topics.list",
        "airs.scan.results",
    ] {
        assert!(operations.contains(&expected), "{operations:?}");
    }
    assert_eq!(rust_run.code, ts_run.code);
}

/// D63: TS opens a log for every action command (an empty file for `tenant list` and
/// for in-action validation failures); Rust only for commands that can send requests,
/// after all usage validation.
#[test]
fn d63_which_runs_create_a_log() {
    let Some(ts) = require_ts("d63_which_runs_create_a_log") else {
        return;
    };
    let f = fx();
    let (rust_run, _) = f.run(&rust(), &["--debug", "tenant", "list"]);
    let (ts_run, _) = f.run(&ts, &["--debug", "tenant", "list"]);
    rust_run.assert_success();
    ts_run.assert_success();
    assert_ts_empty_log(&f, &ts_run);
    assert!(!xdg_state_home(&f.sandbox).exists(), "Rust created nothing");
    assert_eq!(notice(&rust_run.stderr), None);

    // An empty prompt: TS fails inside the action after creating its file; Rust
    // rejects it during planning and creates nothing.
    fs::remove_file(&f.ts_logs()[0]).unwrap();
    let empty = ["--debug", "runtime", "scan", "--profile", "p", ""];
    let (rust_run, rust_sent) = f.run(&rust(), &empty);
    let (ts_run, ts_sent) = f.run(&ts, &empty);
    rust_run.assert_code(2);
    assert_ne!(ts_run.code, 0);
    assert_eq!((rust_sent, ts_sent), (0, 0));
    assert_eq!(f.ts_logs().len(), 1);
    assert!(!xdg_state_home(&f.sandbox).exists());

    // A bad --output: neither creates a file.
    fs::remove_file(&f.ts_logs()[0]).unwrap();
    let xml = ["--debug", "runtime", "profiles", "list", "--output", "xml"];
    f.run(&rust(), &xml).0.assert_code(2);
    f.run(&ts, &xml).0.assert_code(2);
    assert!(f.ts_logs().is_empty());
    assert!(!xdg_state_home(&f.sandbox).exists());
}

/// D64: TS records bodies and the URL with its query (for production hosts; empty
/// here); Rust records status and headers only: no body key, no query.
#[test]
fn d64_no_bodies_or_queries() {
    let Some(ts) = require_ts("d64_no_bodies_or_queries") else {
        return;
    };
    let f = fx();
    let doctor = ["--debug", "doctor", "--output", "json"];
    let (_, _) = f.run(&rust(), &doctor);
    let queries: Vec<String> = f
        .server
        .requests()
        .iter()
        .filter_map(|request| request.raw_query.clone())
        .collect();
    assert!(!queries.is_empty(), "the doctor probes carry queries");
    let (ts_run, _) = f.run(&ts, &doctor);
    assert_ts_empty_log(&f, &ts_run);
    let text = fs::read_to_string(&f.rust_logs()[0]).unwrap();
    assert!(!text.contains("\"body\""));
    assert!(!text.contains('?'));
    for query in &queries {
        assert!(!text.contains(query.as_str()));
    }
    for record in rust_records(&f) {
        let url = record["request"]["url"].as_str().unwrap();
        assert!(url.starts_with(&f.server.base_url()), "{url}");
    }
}

/// D65: TS masks headers by a name denylist (`x-payload-hash`, `location` and unknown
/// headers verbatim); Rust writes values only for an allow-list.
#[test]
fn d65_header_allow_list() {
    let Some(ts) = require_ts("d65_header_allow_list") else {
        return;
    };
    let f = fx();
    let scan = [
        "--debug",
        "runtime",
        "scan",
        "--profile",
        "fixture-profile",
        "hello",
    ];
    let (rust_run, _) = f.run(&rust(), &scan);
    let (ts_run, _) = f.run(&ts, &scan);
    rust_run.assert_success();
    ts_run.assert_success();
    assert_ts_empty_log(&f, &ts_run);
    let records = rust_records(&f);
    assert_eq!(records.len(), 1);
    let headers = records[0]["request"]["headers"].as_object().unwrap();
    assert_eq!(headers["x-payload-hash"], "***");
    assert_eq!(headers["x-pan-token"], "***");
    assert_eq!(headers["user-agent"], "PAN-AIRS/0.2.3-rust-sdk");
}

/// D66: Rust records add `operation`, use lowercase sorted header names and the
/// canonical status text; TS writes no record for loopback.
#[test]
fn d66_record_fields() {
    let Some(ts) = require_ts("d66_record_fields") else {
        return;
    };
    let f = fx();
    f.server
        .push_once(Route::Profiles, Planned::empty_json(401));
    let (rust_run, _) = f.run(&rust(), LIST);
    f.server
        .push_once(Route::Profiles, Planned::empty_json(401));
    let (ts_run, _) = f.run(&ts, LIST);
    rust_run.assert_success();
    ts_run.assert_success();
    assert_ts_empty_log(&f, &ts_run);
    let text = fs::read_to_string(&f.rust_logs()[0]).unwrap();
    let records = rust_records(&f);
    let statuses: Vec<(String, String)> = records
        .iter()
        .map(|record| {
            (
                record["operation"].as_str().unwrap().to_owned(),
                record["response"]["statusText"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect();
    assert_eq!(
        statuses,
        [
            ("oauth.token", "OK"),
            ("airs.management.profiles.list", "Unauthorized"),
            ("oauth.token", "OK"),
            ("airs.management.profiles.list", "OK"),
        ]
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
    );
    for line in text.lines() {
        assert!(
            line.starts_with("{\"timestamp\":\"")
                && line.find("\"durationMs\"") < line.find("\"operation\"")
                && line.find("\"operation\"") < line.find("\"request\"")
                && line.find("\"request\"") < line.find("\"response\""),
            "{line}"
        );
    }
}

/// D67: a log write that fails mid-run (EFBIG under a zero file-size limit) never
/// changes the Rust outcome: one warning, same stdout and exit code. TS writes nothing
/// for loopback, so the same limit leaves its run unchanged too (for production hosts
/// its patched `fetch` would throw instead).
#[test]
fn d67_write_failure_keeps_the_outcome() {
    let Some(ts) = require_ts("d67_write_failure_keeps_the_outcome") else {
        return;
    };
    let f = fx();
    let limited = |program: &Path, name: &str| {
        let wrapper = f.sandbox.tmp().join(name);
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\ntrap '' XFSZ\nulimit -f 0\nexec '{}' \"$@\"\n",
                program.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        wrapper
    };
    let rust_limited = Cli::rust(limited(Path::new(env!("CARGO_BIN_EXE_airs")), "rust.sh"));
    let ts_limited = match &ts {
        Cli::Ts { node, entry } => Cli::Ts {
            node: limited(node, "node.sh"),
            entry: entry.clone(),
        },
        Cli::Rust(_) => unreachable!(),
    };
    let (rust_run, rust_sent) = f.run(&rust_limited, LIST);
    let (ts_run, ts_sent) = f.run(&ts_limited, LIST);
    rust_run.assert_success();
    ts_run.assert_success();
    assert_eq!(rust_sent, ts_sent);
    assert_json_semantic_eq(&rust_run.json(), &ts_run.json());
    assert!(
        rust_run
            .stderr
            .contains("  ⚠ Debug: the API log could not be written; it is incomplete\n")
    );
    assert!(!ts_run.stderr.contains("could not be written"));
    assert_eq!(fs::read(&f.rust_logs()[0]).unwrap(), b"");
}

/// D68: the setup failure. TS: `✗ Cannot create the debug log in the current working
/// directory…` without `Error:` or blank lines; Rust: the standard error block naming
/// the directory. Both exit 1 with zero requests.
#[test]
fn d68_setup_failure_text() {
    let Some(ts) = require_ts("d68_setup_failure_text") else {
        return;
    };
    let f = fx();
    let dir = log_dir(&f.sandbox);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(f.sandbox.cwd(), fs::Permissions::from_mode(0o555)).unwrap();
    let (rust_run, rust_sent) = f.run(&rust(), LIST);
    let (ts_run, ts_sent) = f.run(&ts, LIST);
    fs::set_permissions(f.sandbox.cwd(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!((rust_run.code, ts_run.code), (1, 1));
    assert_eq!((rust_sent, ts_sent), (0, 0));
    assert_eq!(rust_run.stdout, "");
    assert_eq!(ts_run.stdout, "");
    assert_eq!(
        ts_run.stderr,
        "  ✗ Cannot create the debug log in the current working directory. Run from a writable directory or omit --debug.\n"
    );
    assert_eq!(
        rust_run.stderr,
        format!(
            "\n  ✗ Error: Cannot create the debug log in {}; fix that directory or omit --debug\n\n",
            dir.display()
        )
    );
}

/// D69: TS prints the `Re-run with --debug` hint after `HTTP <status>` even under
/// `--debug`; Rust omits it there (the notice already named the log). Without
/// `--debug` both print it.
#[test]
fn d69_hint_under_debug() {
    let Some(ts) = require_ts("d69_hint_under_debug") else {
        return;
    };
    let f = fx();
    f.server
        .set_default(Route::Profiles, Planned::empty_json(404));
    let (rust_run, _) = f.run(&rust(), LIST);
    let (ts_run, _) = f.run(&ts, LIST);
    assert_eq!((rust_run.code, ts_run.code), (1, 1));
    assert_eq!(rust_run.error_line(), ts_run.error_line());
    assert_eq!(rust_run.http_status(), Some(404));
    assert_eq!(ts_run.http_status(), Some(404));
    assert!(ts_run.stderr.contains(HINT));
    assert!(!rust_run.stderr.contains(HINT));
    let (rust_plain, _) = f.run(&rust(), &LIST[1..]);
    let (ts_plain, _) = f.run(&ts, &LIST[1..]);
    assert_eq!(rust_plain.stderr, ts_plain.stderr);
    assert!(rust_plain.stderr.contains(HINT));
}
