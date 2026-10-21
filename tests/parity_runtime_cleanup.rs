//! TS-vs-Rust parity for `runtime profiles cleanup` (DESIGN §13.15, §10 M4).
//!
//! Each scenario runs once on each CLI, on a fresh sandbox and fixture server seeded
//! with the same profiles. Parity compares exit codes, the preview data (TypeScript
//! stdout without its outcome lines against Rust stdout), the per-revision and summary
//! lines (TypeScript stdout against Rust stderr, D106), the deletion requests and the
//! resulting state. `dNN_` tests pin both sides of a DESIGN §12 row.
//!
//! Every TypeScript run passes `--updated-by` except the one D109 test, which runs its
//! `git config user.email` against a sandboxed git configuration. No test serves
//! TypeScript an unbounded `next_offset: 0` listing (it would re-fetch forever, D108):
//! the D108 test answers its first two pages explicitly.

use airs_test_harness::{
    Cli, FixtureServer, Planned, PtyRun, RUNTIME_BANNER, RecordedRequest, Route, Run, RunOptions,
    Sandbox, fixtures, require_ts, run, spawn_pty, spawn_pty_all, split_outcome_lines, usage_line,
};
use serde_json::{Value, json};

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn id(n: u64) -> String {
    fixtures::uuid(n)
}

/// `beta` revisions 1 (id 2) and 3 (id 4), `gamma` revisions 2 (id 6), 1 (id 5) and
/// 3 (id 7), and `alpha` (id 1) alone.
fn standard_rows() -> Vec<Value> {
    vec![
        fixtures::profile(1, "alpha", 1),
        fixtures::profile(2, "beta", 1),
        fixtures::profile(4, "beta", 3),
        fixtures::profile(6, "gamma", 2),
        fixtures::profile(5, "gamma", 1),
        fixtures::profile(7, "gamma", 3),
    ]
}

struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    profiles: Vec<Value>,
}

impl Side {
    fn deletes(&self) -> Vec<String> {
        self.requests
            .iter()
            .filter(|request| request.route.is_write())
            .map(RecordedRequest::line)
            .collect()
    }

    fn ids(&self) -> Vec<String> {
        self.profiles
            .iter()
            .map(|row| row["profile_id"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    fn count(&self, route: Route) -> usize {
        self.requests.iter().filter(|r| r.route == route).count()
    }
}

/// Runs `args` on a fresh world seeded with `rows`; `prepare` may plan answers and
/// adjust the options (it sees the sandbox).
fn exec(
    cli: &Cli,
    rows: &[Value],
    args: &[&str],
    prepare: &dyn Fn(&Cli, &FixtureServer, &Sandbox, RunOptions) -> RunOptions,
) -> Side {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    server.set_profiles(TSG, rows.to_vec());
    let options = prepare(cli, &server, &sandbox, RunOptions::new());
    let out = run(cli, &sandbox, args, &options);
    server.assert_no_unknown_routes();
    assert!(
        sandbox.home_listing().is_empty(),
        "{} wrote into HOME",
        cli.label()
    );
    assert!(
        sandbox.cwd_listing().is_empty(),
        "{} wrote into cwd",
        cli.label()
    );
    Side {
        run: out,
        requests: server.requests(),
        profiles: server.profiles(TSG),
    }
}

fn nothing(_: &Cli, _: &FixtureServer, _: &Sandbox, options: RunOptions) -> RunOptions {
    options
}

fn both(
    test: &str,
    rows: &[Value],
    args: &[&str],
    prepare: &dyn Fn(&Cli, &FixtureServer, &Sandbox, RunOptions) -> RunOptions,
) -> Option<(Side, Side)> {
    let ts = require_ts(test)?;
    Some((
        exec(&rust(), rows, args, prepare),
        exec(&ts, rows, args, prepare),
    ))
}

/// Text without its empty lines (TypeScript writes them on stdout around its summary,
/// airs-cli-rs on stderr around its own).
fn without_blank_lines(text: &str) -> String {
    text.split_inclusive('\n')
        .filter(|line| *line != "\n")
        .collect()
}

/// The pretty preview of the standard rows.
fn preview() -> String {
    let table = " Profile │ Revisions │ Keeping │ Deleting \n─────────┼───────────┼─────────┼──────────\n beta    │ 2         │ rev 3   │ 1        \n gamma   │ 3         │ rev 3   │ 2        ";
    let indented: String = table
        .split('\n')
        .map(|line| format!("  {line}\n"))
        .collect();
    format!(
        "{RUNTIME_BANNER}\n  Duplicate Profiles:\n\n{indented}\n  Total: 3 old revisions to delete across 2 profiles\n\n"
    )
}

const FORCE: [&str; 6] = [
    "runtime",
    "profiles",
    "cleanup",
    "--force",
    "--updated-by",
    "a@b",
];

fn force_delete(n: u64, email: &str) -> String {
    format!(
        "DELETE /aisec/v1/mgmt/profile/{}/force?updated_by={email}",
        id(n)
    )
}

mod parity {
    use super::*;

    /// The preview, the per-revision lines, the summary, the force deletions with the
    /// audit email and the resulting state agree.
    #[test]
    fn cleanup_force_with_updated_by() {
        let Some((rust, ts)) = both("cleanup_force", &standard_rows(), &FORCE, &nothing) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        let (outcome, rest) = split_outcome_lines(&ts.run.stdout);
        assert_eq!(
            without_blank_lines(&rust.run.stderr),
            outcome,
            "per-revision and summary lines (D106)"
        );
        assert_eq!(rust.run.stdout, preview());
        assert_eq!(
            rest,
            format!("{}\n\n", preview()),
            "TS blank lines around its summary"
        );
        let expected = [2, 6, 5].map(|n| force_delete(n, "a%40b"));
        assert_eq!(rust.deletes(), expected);
        assert_eq!(ts.deletes(), expected);
        assert_eq!(rust.ids(), ts.ids());
        assert_eq!(rust.ids(), [id(1), id(4), id(7)]);
    }

    /// Nothing to delete: the same success line, no deletion.
    #[test]
    fn nothing_to_delete() {
        let rows = [fixtures::profile(1, "alpha", 1)];
        let Some((rust, ts)) = both("cleanup_none", &rows, &FORCE, &nothing) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        let (outcome, rest) = split_outcome_lines(&ts.run.stdout);
        assert_eq!(rust.run.stderr, outcome);
        assert_eq!(outcome, "  ✓ No duplicate profiles found.\n");
        assert_eq!(rest, RUNTIME_BANNER, "TS prints its banner first (D106)");
        assert_eq!(rust.run.stdout, "");
        assert!(rust.deletes().is_empty() && ts.deletes().is_empty());
    }
}

mod divergence {
    use super::*;

    /// D94: TypeScript's root parser takes `--output`, so its cleanup is pretty;
    /// airs-cli-rs prints one JSON document.
    #[test]
    fn d94_cleanup_json() {
        let mut args = FORCE.to_vec();
        args.extend(["--output", "json"]);
        let Some((rust, ts)) = both("d94_cleanup", &standard_rows(), &args, &nothing) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.run.json()["deleted"], 3);
        assert_eq!(rust.run.json()["details"].as_array().map(Vec::len), Some(3));
        assert!(
            ts.run.stdout.starts_with(RUNTIME_BANNER),
            "{}",
            ts.run.stdout
        );
        assert!(serde_json::from_str::<Value>(&ts.run.stdout).is_err());
    }

    /// D105: without `--force` and without a terminal TypeScript previews and exits 0;
    /// airs-cli-rs refuses before the tenant, and `--dry-run` is that preview.
    #[test]
    fn d105_cleanup_without_force() {
        let args = ["runtime", "profiles", "cleanup", "--updated-by", "a@b"];
        let Some((rust, ts)) = both("d105_cleanup", &standard_rows(), &args, &nothing) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (2, 0));
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("refusing to delete profile revisions without --force in non-interactive mode")
        );
        assert!(rust.requests.is_empty());
        assert_eq!(
            ts.run.stdout,
            format!("{}  Pass --force to delete these revisions.\n", preview())
        );
        assert!(ts.deletes().is_empty());
        let dry = ["runtime", "profiles", "cleanup", "--dry-run"];
        let dry_run = exec(&super::rust(), &standard_rows(), &dry, &nothing);
        dry_run.run.assert_success();
        assert_eq!(dry_run.run.stdout, preview(), "the TypeScript preview");
        assert_eq!(
            dry_run.run.stderr,
            "  Pass --force to delete these revisions.\n"
        );
        assert!(dry_run.deletes().is_empty());
    }

    fn visible(out: &PtyRun) -> String {
        let mut plain = String::new();
        let mut chars = out.transcript.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                continue;
            }
            if c != '\r' {
                plain.push(c);
            }
        }
        plain
    }

    /// D105: both CLIs ask on a terminal (TypeScript when stdout is one, airs-cli-rs when
    /// stdin and stderr are); declining deletes nothing on either.
    #[test]
    fn d105_cleanup_prompt() {
        let Some(ts) = require_ts("d105_cleanup_prompt") else {
            return;
        };
        let args = FORCE[..3]
            .iter()
            .copied()
            .chain(["--updated-by", "a@b"])
            .collect::<Vec<_>>();
        let world = |cli: &Cli| -> (PtyRun, Vec<RecordedRequest>) {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            server.set_profiles(TSG, standard_rows());
            let mut session = if cli.is_ts() {
                spawn_pty_all(cli, &sandbox, &args, &RunOptions::new())
            } else {
                spawn_pty(cli, &sandbox, &args, &RunOptions::new())
            };
            session.expect("Delete 3 old profile revisions?");
            std::thread::sleep(std::time::Duration::from_millis(150));
            session.send(if cli.is_ts() { b"n\r" } else { b"n\n" });
            (session.wait(), server.requests())
        };
        let (rust_out, rust_requests) = world(&rust());
        let (ts_out, ts_requests) = world(&ts);
        rust_out.run.assert_success();
        ts_out.run.assert_success();
        for out in [&rust_out, &ts_out] {
            assert!(visible(out).contains("ℹ Aborted"), "{:?}", visible(out));
        }
        assert_eq!(rust_out.run.stdout, preview());
        assert!(visible(&ts_out).contains("Total: 3 old revisions to delete across 2 profiles"));
        assert!(rust_requests.iter().all(|r| !r.route.is_write()));
        assert!(ts_requests.iter().all(|r| !r.route.is_write()));
    }

    /// D106: TypeScript prints the per-revision lines and the summary on stdout, also
    /// under `--quiet`; airs-cli-rs prints them on stderr and `--quiet` drops the
    /// success lines.
    #[test]
    fn d106_cleanup_lines_on_stderr() {
        let mut args = FORCE.to_vec();
        args.push("--quiet");
        let Some((rust, ts)) = both("d106_cleanup", &standard_rows(), &args, &nothing) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.run.stderr, "");
        assert!(ts.run.stdout.contains("  ✓ beta rev 1\n"));
        assert!(
            ts.run
                .stdout
                .contains("  ✓ Cleanup complete: 3 deleted, 0 failed\n")
        );
        assert!(!rust.run.stdout.contains('✓'));
    }

    /// D108: `next_offset: 0` ends the airs-cli-rs walk. TypeScript re-fetches offset 0,
    /// so it sees the only revision of `solo` twice and force-deletes it. (Its second page
    /// is answered without `next_offset`, which bounds the TypeScript loop.)
    #[test]
    fn d108_next_offset_zero() {
        let rows = [fixtures::profile(9, "solo", 1)];
        let pages = |_: &Cli, server: &FixtureServer, _: &Sandbox, options: RunOptions| {
            let solo = fixtures::profile(9, "solo", 1);
            server.push_once(
                Route::Profiles,
                Planned::json(200, &json!({"ai_profiles": [solo], "next_offset": 0})),
            );
            server.push_once(
                Route::Profiles,
                Planned::json(200, &json!({"ai_profiles": [solo]})),
            );
            options
        };
        let Some((rust, ts)) = both("d108_cleanup", &rows, &FORCE, &pages) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.count(Route::Profiles), 1);
        assert_eq!(rust.run.stderr, "  ✓ No duplicate profiles found.\n");
        assert!(rust.deletes().is_empty());
        assert_eq!(rust.ids(), [id(9)]);
        assert_eq!(
            ts.count(Route::Profiles),
            2,
            "TypeScript fetched offset 0 again"
        );
        assert_eq!(ts.deletes(), [force_delete(9, "a%40b")]);
        assert!(ts.ids().is_empty(), "TypeScript deleted the only revision");
    }

    /// D109: `--force` alone makes plain deletes on airs-cli-rs; TypeScript force-deletes
    /// with the `git config user.email` of the current directory (sandboxed here).
    #[test]
    fn d109_cleanup_deletes_and_audit_identity() {
        let args = ["runtime", "profiles", "cleanup", "--force"];
        let git = |cli: &Cli, _: &FixtureServer, sandbox: &Sandbox, options: RunOptions| {
            if !cli.is_ts() {
                return options;
            }
            let config = sandbox.tmp().join("gitconfig");
            std::fs::write(&config, "[user]\n\temail = git-user@example.com\n").unwrap();
            options
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", config.display().to_string())
                .env(
                    "GIT_CEILING_DIRECTORIES",
                    sandbox.root().display().to_string(),
                )
        };
        let Some((rust, ts)) = both("d109_cleanup", &standard_rows(), &args, &git) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(
            rust.deletes(),
            [2, 6, 5].map(|n| format!("DELETE /aisec/v1/mgmt/profile/{}", id(n)))
        );
        assert_eq!(
            ts.deletes(),
            [2, 6, 5].map(|n| force_delete(n, "git-user%40example.com"))
        );
        assert_eq!(rust.ids(), ts.ids());
    }

    /// D110: a tied highest revision is skipped by airs-cli-rs and resolved by list order
    /// in TypeScript; revisions sharing an id are skipped by airs-cli-rs, while TypeScript
    /// deletes the kept id; an unknown outcome stops airs-cli-rs, while TypeScript goes on.
    #[test]
    fn d110_cleanup_ties_and_unknown_outcomes() {
        let rows = [
            fixtures::profile(10, "tied", 2),
            fixtures::profile(11, "tied", 2),
        ];
        let Some((rust, ts)) = both("d110_tied", &rows, &FORCE, &nothing) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(
            rust.run.stderr,
            "  ⚠ Skipped tied: its revisions are missing or tied; nothing was deleted for it\n  ✓ No duplicate profiles found.\n"
        );
        assert!(rust.deletes().is_empty());
        assert_eq!(
            ts.deletes(),
            [force_delete(11, "a%40b")],
            "TS keeps the first listed"
        );
        // Two listed revisions under one id: TypeScript deletes the id it keeps, the
        // active profile; airs-cli-rs skips the group.
        let rows = [
            fixtures::profile(1, "prod-guard", 1),
            fixtures::profile(1, "prod-guard", 2),
        ];
        let Some((rust, ts)) = both("d110_shared_id", &rows, &FORCE, &nothing) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(
            rust.run.stderr,
            "  ⚠ Skipped prod-guard: its revisions share a profile id; nothing was deleted for it\n  ✓ No duplicate profiles found.\n"
        );
        assert!(rust.deletes().is_empty());
        assert_eq!(
            ts.deletes(),
            [force_delete(1, "a%40b")],
            "TS deletes the kept revision's id"
        );
        let failing = |_: &Cli, server: &FixtureServer, _: &Sandbox, options: RunOptions| {
            server.push_once(
                Route::ProfileForceDelete,
                Planned::json(503, &json!({})).with_retry_after(0),
            );
            options
        };
        let Some((rust, ts)) = both("d110_unknown", &standard_rows(), &FORCE, &failing) else {
            return;
        };
        rust.run.assert_code(1);
        assert_eq!(
            rust.deletes(),
            [force_delete(2, "a%40b")],
            "one attempt, then stop"
        );
        assert!(
            rust.run.stderr.contains(
                "  ⚠ Stopped after a deletion with an unknown outcome; 2 not attempted\n"
            )
        );
        let ts_deletes = ts.deletes();
        for n in [2, 6, 5] {
            assert!(
                ts_deletes.contains(&force_delete(n, "a%40b")),
                "TypeScript attempted every revision: {ts_deletes:?}"
            );
        }
    }
}
