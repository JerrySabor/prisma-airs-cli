//! Executable acceptance tests for the M6f chunk-1 supplychain reads (DESIGN §20.3–§20.8):
//! `supplychain scans list|ls`, `scans vulnerabilities <scanUuid> [--include-content]`,
//! `stats` and `rules list|ls`, with the cases of the TypeScript
//! `tests/integration/cli/agentguard.spec.ts` ported (§20.14; TS `agentguard`, D308).
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server seeded with
//! the supplychain dataset, whose bodies keep the service's member order, nested objects,
//! nulls and passthrough members (§20.13). The runner's leak check forbids the `PRIVATE-`
//! marker in every output of these runs, and on stderr and in the debug log of a run with
//! `--include-content` (DESIGN §10 M6f).

use std::time::Duration;

use airs_test_harness::fixtures::supplychain::{self as fx, Wire, obj, w};
use airs_test_harness::{
    Cli, ClosedPort, FixtureConfig, FixtureServer, Planned, RecordedRequest, Route, Run,
    RunOptions, Sandbox, Sc, SupplychainData, debug_log, run, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const DATA: &str = "/agentguard/data/v1";
const MGMT: &str = "/agentguard/mgmt/v1";
const TAIL: &str =
    "Check credentials, query options and service availability. No upstream body is included.";
const NOTICE: &str = "  Finding content included: source code, file paths and finding text can contain secrets from the scanned artifacts; keep this output private.\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

fn fx() -> Fx {
    fx_with(|_| {}, |_| {})
}

fn seeded(seed: impl FnOnce(&mut SupplychainData)) -> Fx {
    fx_with(seed, |_| {})
}

fn fx_with(seed: impl FnOnce(&mut SupplychainData), edit: impl FnOnce(&mut FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    server.seed_supplychain();
    server.supplychain(seed);
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

impl Fx {
    fn sc_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let mut full = vec!["supplychain"];
        full.extend_from_slice(args);
        let before = self.sandbox.snapshot();
        let out = run(&rust(), &self.sandbox, &full, options);
        self.sandbox.assert_unchanged(&before);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        out
    }

    fn sc(&self, args: &[&str]) -> Run {
        self.sc_with(args, &RunOptions::new())
    }

    /// `METHOD path?query` of every API request (the token request left out).
    fn api(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    fn clear(&self) {
        self.server.clear_requests();
    }
}

/// TypeScript's request failure line (`ag.ts:81-92`).
fn failure(status: Option<u16>) -> String {
    let status = status.map_or_else(String::new, |status| format!(" (HTTP {status})"));
    format!("  ✗ AgentGuard request failed{status}. {TAIL}\n")
}

fn usage(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
}

fn scans_line(query: &str) -> String {
    format!("GET {DATA}/scans?{query}")
}

fn rules_line(skip: u64, limit: u64) -> String {
    format!("GET {MGMT}/rules?skip={skip}&limit={limit}")
}

fn vulnerabilities_args(extra: &[&'static str]) -> Vec<&'static str> {
    let id: &'static str = Box::leak(fx::uuid(fx::SCAN_WITH_FINDINGS).into_boxed_str());
    let mut args = vec!["scans", "vulnerabilities", id];
    args.extend_from_slice(extra);
    args
}

fn pagination(out: &Run) -> Value {
    out.json()["pagination"].clone()
}

fn doc(total: Option<u64>, returned: u64, skip: u64, next: Option<u64>, truncated: bool) -> Value {
    json!({"total_items": total, "returned": returned, "skip": skip, "next_offset": next, "truncated": truncated})
}

/// A test's planned answers for one case.
type Plan<'a> = Box<dyn Fn(&Fx) + 'a>;

/// The first `n` seeded scans.
fn first_scans(n: usize) -> impl FnOnce(&mut SupplychainData) {
    move |data: &mut SupplychainData| data.scans.truncate(n)
}

// ---------------------------------------------------------------------------
// Requests and walks (TS `agentguard.spec.ts:58-114`, §20.4)
// ---------------------------------------------------------------------------

mod requests {
    use super::*;

    /// §20.4, §20.6, §20.7: every read's request (TS keys and order, values as typed and
    /// form-encoded, explicit zeros and `false` kept), one token first, the bearer and
    /// `x-tsg-id` on every API request, and only `GET`s.
    #[test]
    fn every_read_sends_the_typescript_request() {
        let upper = fx::uuid(101).to_uppercase();
        for (args, line) in [
            (
                vec!["scans", "list"],
                scans_line("skip=0&limit=10&isBackgroundRefresh=false"),
            ),
            (
                vec![
                    "scans",
                    "ls",
                    "--limit",
                    "007",
                    "--offset",
                    "1",
                    "--start",
                    "2026-10-01T00:00:00+02:00",
                    "--end",
                    "2026-10-30T00:00:00.123456789Z",
                ],
                scans_line(
                    "skip=1&limit=7&isBackgroundRefresh=false&start_time=2026-10-01T00%3A00%3A00%2B02%3A00&end_time=2026-10-30T00%3A00%3A00.123456789Z",
                ),
            ),
            (
                vec!["scans", "list", "--end", "2026-10-30T00:00Z"],
                scans_line(
                    "skip=0&limit=10&isBackgroundRefresh=false&end_time=2026-10-30T00%3A00Z",
                ),
            ),
            (
                vec!["scans", "vulnerabilities", upper.as_str()],
                format!("GET {DATA}/scans/{upper}/vulnerabilities"),
            ),
            (
                vec!["stats"],
                format!("GET {DATA}/stats/scans?time_period=30_DAYS"),
            ),
            (
                vec!["stats", "--time-period", "30_DAYS"],
                format!("GET {DATA}/stats/scans?time_period=30_DAYS"),
            ),
            (vec!["rules", "list"], rules_line(0, 10)),
            (
                vec!["rules", "ls", "--offset", "3", "--limit", "4"],
                rules_line(3, 4),
            ),
        ] {
            let f = fx();
            let out = f.sc(&args);
            out.assert_success();
            assert_eq!(f.api(), [line], "{args:?}");
            let requests = f.server.requests();
            assert_eq!(requests[0].route, Route::Token);
            assert_eq!(requests.len(), 2, "one token, one read: {args:?}");
            let read = &requests[1];
            assert_eq!(read.method, "GET");
            assert_eq!(read.header("authorization"), Some("Bearer mock-token-100"));
            assert_eq!(read.header("x-tsg-id"), Some(TSG));
            assert!(read.body.is_empty());
        }
    }

    /// TS `walks --all pages and exposes cap/truncation metadata` (`it.spec:58-76`), and
    /// §20.4's shrunk last page on the wire.
    #[test]
    fn all_walks_report_their_truncation() {
        let f = seeded(first_scans(2));
        let out = f.sc(&["scans", "list", "--all", "--limit", "1", "--output", "json"]);
        out.assert_success();
        assert_eq!(pagination(&out), doc(Some(2), 2, 0, None, false));
        assert_eq!(
            f.api(),
            [
                scans_line("skip=0&limit=1&isBackgroundRefresh=false"),
                scans_line("skip=1&limit=1&isBackgroundRefresh=false"),
            ]
        );
        let f = seeded(first_scans(2));
        let out = f.sc(&["scans", "list", "--all", "--max", "1", "--output", "json"]);
        assert_eq!(pagination(&out), doc(Some(2), 1, 0, Some(1), true));
        assert_eq!(
            f.api(),
            [scans_line("skip=0&limit=1&isBackgroundRefresh=false")]
        );
        // `--all --max 2 --limit 1` over 3 (SC§3).
        let f = seeded(first_scans(3));
        let out = f.sc(&[
            "scans", "list", "--all", "--max", "2", "--limit", "1", "--output", "json",
        ]);
        assert_eq!(pagination(&out), doc(Some(3), 2, 0, Some(2), true));
        // `rules ls --all --offset 5 --max 12` sends `skip=5&limit=10`, then
        // `skip=15&limit=2` (choice 10: the offset is honoured with --all).
        let f = fx();
        let out = f.sc(&[
            "rules", "ls", "--all", "--offset", "5", "--max", "12", "--output", "json",
        ]);
        out.assert_success();
        assert_eq!(f.api(), [rules_line(5, 10), rules_line(15, 2)]);
        assert_eq!(pagination(&out), doc(None, 12, 5, Some(17), true));
        // `--max 0` removes the cap (D317).
        let f = fx();
        let out = f.sc(&["rules", "list", "--all", "--max", "0", "--output", "json"]);
        assert_eq!(pagination(&out), doc(Some(25), 25, 0, None, false));
    }

    /// The captured outcomes of §20.4 (SC§3) on a single page and the rules walk.
    #[test]
    fn captured_pagination_outcomes() {
        let json = |f: &Fx, args: &[&str]| {
            let mut full = args.to_vec();
            full.extend(["--output", "json"]);
            let out = f.sc(&full);
            out.assert_success();
            pagination(&out)
        };
        let f = seeded(first_scans(3));
        assert_eq!(
            json(&f, &["scans", "list", "--limit", "2"]),
            doc(Some(3), 2, 0, Some(2), true)
        );
        assert_eq!(
            json(&f, &["scans", "list", "--offset", "2"]),
            doc(Some(3), 1, 2, None, false)
        );
        let f = seeded(first_scans(2));
        assert_eq!(
            json(&f, &["scans", "list", "--offset", "5"]),
            doc(Some(2), 0, 5, None, false)
        );
        // An empty first page while the total says more: printed as truncated, exit 0
        // (choice 12); with --all it fails.
        let f = seeded(|data| {
            data.scans.clear();
            data.scan_total = Some(5);
        });
        assert_eq!(
            json(&f, &["scans", "list"]),
            doc(Some(5), 0, 0, Some(0), true)
        );
        let out = f.sc(&["scans", "list", "--all"]);
        out.assert_code(1);
        assert_eq!(
            (out.stdout.as_str(), out.stderr.clone()),
            ("", failure(None))
        );
        // Rules: a full first page is truncated with no total (G62, choice 13).
        let f = fx();
        assert_eq!(
            json(&f, &["rules", "list"]),
            doc(None, 10, 0, Some(10), true)
        );
        f.clear();
        assert_eq!(
            json(&f, &["rules", "list", "--all"]),
            doc(Some(25), 25, 0, None, false)
        );
        assert_eq!(
            f.api(),
            [rules_line(0, 10), rules_line(10, 10), rules_line(20, 10)]
        );
        // 20 rules: the third page is empty and completes the walk.
        let f = seeded(|data| data.rules.truncate(20));
        assert_eq!(
            json(&f, &["rules", "list", "--all"]),
            doc(Some(20), 20, 0, None, false)
        );
        assert_eq!(
            f.api(),
            [rules_line(0, 10), rules_line(10, 10), rules_line(20, 10)]
        );
        // A complete walk from an offset has no total (TS).
        let f = fx();
        assert_eq!(
            json(&f, &["rules", "list", "--all", "--offset", "20"]),
            doc(None, 5, 20, None, false)
        );
        // A short single page is complete.
        assert_eq!(
            json(&f, &["rules", "list", "--offset", "20"]),
            doc(None, 5, 20, None, false)
        );
    }

    /// TS `walks rules until a short page, ignoring the server page-count total`
    /// (`it.spec:103-114`) and `reads statistics and rule catalog` (`it.spec:92-102`).
    #[test]
    fn rules_walk_until_a_short_page() {
        let f = seeded(|data| data.rules.truncate(3));
        let out = f.sc(&["rules", "list", "--all", "--limit", "2", "--output", "json"]);
        out.assert_success();
        assert_eq!(out.json()["rules"].as_array().unwrap().len(), 3);
        assert_eq!(pagination(&out), doc(Some(3), 3, 0, None, false));
        assert_eq!(f.api(), [rules_line(0, 2), rules_line(2, 2)]);
    }

    /// TS `refuses duplicate pages instead of silently claiming --all succeeded`
    /// (`it.spec:77-82`) and the other §20.4 page checks: each is the request failure line,
    /// exit 1, nothing on stdout, with or without --all.
    #[test]
    fn page_checks_fail_closed() {
        let page = |rows: &[Wire], total: u64| {
            Planned::raw(200, "application/json", fx::scan_list_body(rows, total))
        };
        let seed = fx::scans();
        let cases: Vec<(&str, Vec<&str>, Plan<'_>)> = vec![
            (
                "a repeated row on page 2",
                vec!["scans", "list", "--all", "--limit", "1"],
                Box::new(|f: &Fx| {
                    f.server.supplychain(|data| {
                        let first = data.scans[0].clone();
                        data.scans[1] = first;
                    })
                }),
            ),
            (
                "the total changes between pages",
                vec!["scans", "list", "--all", "--limit", "1"],
                Box::new(|f: &Fx| {
                    f.server
                        .push_once(Route::Supplychain(Sc::Scans), page(&seed[..1], 12));
                    f.server
                        .push_once(Route::Supplychain(Sc::Scans), page(&seed[1..2], 11));
                }),
            ),
            (
                "an empty page while more rows are expected",
                vec!["scans", "list", "--all"],
                Box::new(|f: &Fx| {
                    f.server
                        .push_once(Route::Supplychain(Sc::Scans), page(&seed[..10], 12));
                    f.server
                        .push_once(Route::Supplychain(Sc::Scans), page(&[], 12));
                }),
            ),
            (
                "more rows than the limit (no --all)",
                vec!["scans", "list", "--limit", "1"],
                Box::new(|f: &Fx| {
                    f.server
                        .push_once(Route::Supplychain(Sc::Scans), page(&seed[..2], 12));
                }),
            ),
            (
                "rows beyond the total",
                vec!["scans", "list"],
                Box::new(|f: &Fx| {
                    f.server
                        .push_once(Route::Supplychain(Sc::Scans), page(&seed[..2], 1));
                }),
            ),
            (
                "an empty uuid",
                vec!["scans", "list"],
                Box::new(|f: &Fx| {
                    f.server
                        .supplychain(|data| data.scans[0].set("uuid", json!("")))
                }),
            ),
            (
                "a repeated uuid within one page",
                vec!["scans", "list"],
                Box::new(|f: &Fx| {
                    f.server.supplychain(|data| {
                        let first = data.scans[0].clone();
                        data.scans[2] = first;
                    })
                }),
            ),
            (
                "a repeated rule",
                vec!["rules", "list", "--all"],
                Box::new(|f: &Fx| {
                    f.server.supplychain(|data| {
                        let first = data.rules[0].clone();
                        data.rules[12] = first;
                    })
                }),
            ),
            (
                "more rules than the limit",
                vec!["rules", "list", "--limit", "3"],
                Box::new(|f: &Fx| {
                    let rows: Vec<Wire> = (201..205).map(fx::rule).collect();
                    f.server.push_once(
                        Route::Supplychain(Sc::Rules),
                        Planned::raw(200, "application/json", fx::rule_list_body(&rows)),
                    );
                }),
            ),
        ];
        for (name, args, plan) in cases {
            let f = fx();
            plan(&f);
            let out = f.sc(&args);
            out.assert_code(1);
            assert_eq!(out.stdout, "", "{name}");
            assert_eq!(out.stderr, failure(None), "{name}");
        }
    }
}

// ---------------------------------------------------------------------------
// Argument checks (TS `it.spec:175-190`, D314, D315)
// ---------------------------------------------------------------------------

mod arguments {
    use super::*;

    /// D314: every argument check runs before the tenant is read (an empty sandbox has
    /// none, so a later check would fail on the tenant), with a flag-specific message,
    /// exit 2, no request and no debug log.
    #[test]
    fn argument_errors_come_before_the_tenant() {
        let start_text = "--start must be an ISO-8601 timestamp with a timezone (for example 2026-10-01T00:00:00Z)";
        let end_text = "--end must be an ISO-8601 timestamp with a timezone (for example 2026-10-01T00:00:00Z)";
        let limit_text = "--limit must be a positive integer";
        let offset_text = "--offset must be a non-negative integer";
        let max_text = "--max must be a safe nonnegative integer";
        let long = "x".repeat(300);
        let long_message = format!("Invalid scanUuid: {}… (expected a UUID)", "x".repeat(200));
        let cases: Vec<(Vec<&str>, String)> = vec![
            (vec!["scans", "list", "--limit", "0"], limit_text.into()),
            (vec!["scans", "list", "--limit", "abc"], limit_text.into()),
            (vec!["scans", "list", "--limit", "1.5"], limit_text.into()),
            (vec!["scans", "list", "--limit", "-1"], limit_text.into()),
            (
                vec!["scans", "list", "--limit", "4294967296"],
                limit_text.into(),
            ),
            (vec!["rules", "list", "--limit", ""], limit_text.into()),
            (vec!["scans", "list", "--offset", "-1"], offset_text.into()),
            (
                vec!["rules", "list", "--offset", "9007199254740992"],
                offset_text.into(),
            ),
            (vec!["scans", "list", "--max", "0x2"], max_text.into()),
            (vec!["scans", "list", "--max", "1e0"], max_text.into()),
            (vec!["rules", "ls", "--max", " 2 "], max_text.into()),
            (vec!["rules", "ls", "--all", "--max", ""], max_text.into()),
            (vec!["scans", "list", "--start", "bad"], start_text.into()),
            (vec!["scans", "list", "--start", ""], start_text.into()),
            (
                vec!["scans", "list", "--start", "2026-10-01"],
                start_text.into(),
            ),
            (
                vec!["scans", "list", "--start", "2026-10-01T00:00:00"],
                start_text.into(),
            ),
            (
                vec!["scans", "list", "--start", "2026-10-01T00:00:00z"],
                start_text.into(),
            ),
            (
                vec!["scans", "list", "--start", "2026-02-29T00:00:00Z"],
                start_text.into(),
            ),
            (vec!["scans", "list", "--end", "soon"], end_text.into()),
            (
                vec![
                    "scans",
                    "list",
                    "--start",
                    "2026-10-02T00:00:00Z",
                    "--end",
                    "2026-10-01T00:00:00Z",
                ],
                "--start must not be after --end".into(),
            ),
            (
                vec![
                    "scans",
                    "list",
                    "--start",
                    "2026-10-01T00:00:00+24:00",
                    "--end",
                    "2026-10-30T00:00:00Z",
                ],
                "--start must not be after --end".into(),
            ),
            (
                vec!["scans", "vulnerabilities", "../escape"],
                "Invalid scanUuid: ../escape (expected a UUID)".into(),
            ),
            (
                vec!["scans", "vulnerabilities", "bad\u{1b}[31m"],
                "Invalid scanUuid: bad\u{fffd}[31m (expected a UUID)".into(),
            ),
            (
                vec!["scans", "vulnerabilities", long.as_str()],
                long_message,
            ),
            (
                vec!["stats", "--time-period", "week"],
                "--time-period must be 30_DAYS (the only period the service supports)".into(),
            ),
            (
                vec!["stats", "--time-period", "30_days"],
                "--time-period must be 30_DAYS (the only period the service supports)".into(),
            ),
            (
                vec!["stats", "--output", "yaml"],
                "Invalid output format 'yaml'. Expected: pretty, table, json".into(),
            ),
            (
                vec!["scans", "list", "--output", "markdown"],
                "Invalid output format 'markdown'. Expected: pretty, table, json".into(),
            ),
            (
                vec!["rules", "list", "--output", "csv", "--limit", "0"],
                "Invalid output format 'csv'. Expected: pretty, table, json".into(),
            ),
        ];
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let state = debug_log::xdg_state_home(&sandbox).display().to_string();
        for (args, message) in cases {
            let mut full = vec!["--debug", "supplychain"];
            full.extend(args.iter().copied());
            let out = run(
                &rust(),
                &sandbox,
                &full,
                &RunOptions::new().env("XDG_STATE_HOME", &state),
            );
            out.assert_code(2);
            assert_eq!(out.stdout, "", "{args:?}");
            assert_eq!(out.stderr, usage(&message), "{args:?}");
            assert_eq!(server.request_count(), 0);
            assert!(
                debug_log::log_files(&debug_log::log_dir(&sandbox)).is_empty(),
                "{args:?} opened a debug log"
            );
        }
    }

    /// The values the checks accept (§20.3): leading zeros, `--max 0`, a leap day, equal
    /// bounds, an offset form without a colon, and an offset beyond ±23:59 alone (sent as
    /// typed, TS).
    #[test]
    fn edge_values_pass() {
        for (args, query) in [
            (
                vec!["--max", "0", "--limit", "0010"],
                "skip=0&limit=10&isBackgroundRefresh=false",
            ),
            (
                vec!["--start", "2028-02-29T00:00Z", "--end", "2028-02-29T00:00Z"],
                "skip=0&limit=10&isBackgroundRefresh=false&start_time=2028-02-29T00%3A00Z&end_time=2028-02-29T00%3A00Z",
            ),
            (
                vec!["--start", "2026-10-01T00:00:00+0200"],
                "skip=0&limit=10&isBackgroundRefresh=false&start_time=2026-10-01T00%3A00%3A00%2B0200",
            ),
            (
                vec!["--start", "2026-10-01T00:00:00+24:00"],
                "skip=0&limit=10&isBackgroundRefresh=false&start_time=2026-10-01T00%3A00%3A00%2B24%3A00",
            ),
            (
                vec!["--limit", "4294967295"],
                "skip=0&limit=4294967295&isBackgroundRefresh=false",
            ),
        ] {
            let f = fx();
            let mut full = vec!["scans", "list"];
            full.extend(args.iter().copied());
            f.sc(&full).assert_success();
            assert_eq!(f.api(), [scans_line(query)], "{args:?}");
        }
    }

    /// D1: a group without a subcommand prints its help on stderr, exit 2; D308: there is
    /// no `agentguard` alias.
    #[test]
    fn bare_groups_and_the_old_name_are_usage_errors() {
        let f = fx();
        for (path, usage_line) in [
            (vec![], "Usage: airs supplychain [OPTIONS] [COMMAND]"),
            (
                vec!["scans"],
                "Usage: airs supplychain scans [OPTIONS] [COMMAND]",
            ),
            (
                vec!["rules"],
                "Usage: airs supplychain rules [OPTIONS] [COMMAND]",
            ),
        ] {
            let out = f.sc(&path);
            out.assert_code(2);
            assert_eq!(out.stdout, "");
            assert!(out.stderr.contains(usage_line), "{path:?}: {}", out.stderr);
        }
        let out = run(
            &rust(),
            &f.sandbox,
            &["agentguard", "scans", "list"],
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert!(
            out.stderr.contains("unrecognized subcommand 'agentguard'"),
            "{}",
            out.stderr
        );
        assert_eq!(f.server.request_count(), 0);
        // Help names the new tree; the leaves keep TypeScript's texts.
        let out = f.sc(&["scans", "list", "--help"]);
        out.assert_success();
        assert!(
            out.stdout
                .contains("Usage: airs supplychain scans list [OPTIONS]")
        );
        assert!(out.stdout.contains(
            "--max <n>          Maximum items with --all; 0 removes the cap (default: 10000)"
        ));
        let out = run(&rust(), &f.sandbox, &["--help"], &RunOptions::new());
        assert!(
            out.stdout
                .contains("supplychain     AI Supply Chain agent and skill scan telemetry (experimental, OAuth)"),
            "{}",
            out.stdout
        );
    }
}

// ---------------------------------------------------------------------------
// Output (TS `it.spec:44-57`, `it.spec:83-91`, `it.spec:116-128`)
// ---------------------------------------------------------------------------

mod output {
    use super::*;

    const SCAN_KEYS: [&str; 9] = [
        "uuid",
        "artifact_type",
        "status",
        "eval_outcome",
        "created_at",
        "vulnerability_count",
        "attack_chain_count",
        "is_batch",
        "parent_uuid",
    ];

    /// TS `renders scans in %s without sensitive metadata` (`it.spec:44-57`; D50: json,
    /// pretty and table): no marker in any format (the runner's check too), `BLOCKED`
    /// shown, exactly the nine projected keys in TS order.
    #[test]
    fn scans_never_print_sensitive_metadata() {
        let f = fx();
        for format in ["json", "pretty", "table"] {
            let out = f.sc(&["scans", "list", "--output", format]);
            out.assert_success();
            assert!(!out.stdout.contains(fx::MARKER), "{format}");
            assert!(out.stdout.contains("BLOCKED"), "{format}");
        }
        let out = f.sc(&["scans", "list", "--all", "--output", "json"]);
        let scans = out.json()["scans"].clone();
        let text = out.stdout.clone();
        let first = text.find("\"uuid\"").unwrap();
        let keys: Vec<usize> = SCAN_KEYS
            .iter()
            .map(|key| text[first..].find(&format!("\"{key}\"")).unwrap())
            .collect();
        assert!(
            keys.windows(2).all(|pair| pair[0] < pair[1]),
            "TS key order"
        );
        for scan in scans.as_array().unwrap() {
            assert_eq!(scan.as_object().unwrap().len(), 9);
        }
        assert_eq!(scans.as_array().unwrap().len(), 12);
        assert_eq!(scans[3]["is_batch"], true);
        assert_eq!(scans[4]["parent_uuid"], json!(fx::uuid(104)));
        assert_eq!(scans[5]["artifact_type"], "UNLISTED<b>");
    }

    /// TS `preserves unavailable scan metrics as null` (`it.spec:116-128`): `null`, never
    /// `0`, in JSON; empty cells in the tables.
    #[test]
    fn unavailable_metrics_stay_null() {
        let f = seeded(|data| {
            data.scans.drain(..2);
            data.scans.truncate(1);
        });
        let out = f.sc(&["scans", "list", "--output", "json"]);
        let scan = &out.json()["scans"][0];
        assert_eq!(scan["status"], "RUNNING");
        assert_eq!(scan["vulnerability_count"], Value::Null);
        assert_eq!(scan["attack_chain_count"], Value::Null);
        assert_eq!(scan["eval_outcome"], Value::Null);
        let table = f.sc(&["scans", "list", "--output", "table"]);
        assert!(
            table.stdout.contains(
                "│ SKILL         │ RUNNING │              │ 2026-10-19T02:00:00Z │                     │                    │ false    │             \n"
            ),
            "{}",
            table.stdout
        );
    }

    /// The table layout (§20.3): TS's bytes, `pretty` identical to `table`, the status line
    /// (D313) on stderr and quiet-suppressed while the data stays (`--quiet` never drops
    /// data).
    #[test]
    fn tables_and_status_lines() {
        let f = seeded(first_scans(2));
        let table = f.sc(&["scans", "list", "--output", "table"]);
        let pretty = f.sc(&["scans", "list"]);
        assert_eq!(table.stdout, pretty.stdout);
        assert_eq!(
            table.stdout,
            " uuid                                 │ artifact type │ status    │ eval outcome │ created at               │ vulnerability count │ attack chain count │ is batch │ parent uuid \n\
             ──────────────────────────────────────┼───────────────┼───────────┼──────────────┼──────────────────────────┼─────────────────────┼────────────────────┼──────────┼─────────────\n \
             11111111-1111-4111-8111-000000000101 │ SKILL         │ COMPLETED │ BLOCKED      │ 2026-10-19T01:57:59.751Z │ 2                   │ 1                  │ false    │             \n \
             11111111-1111-4111-8111-000000000102 │ AGENT         │ COMPLETED │ ALLOWED      │ 2026-10-19T01:57:59.751Z │ 0                   │ 0                  │ false    │             \n"
        );
        assert_eq!(
            table.stderr,
            "  Returned 2 records; see JSON for pagination metadata.\n"
        );
        let quiet = f.sc(&["--quiet", "scans", "list"]);
        assert_eq!(
            (quiet.stdout.as_str(), quiet.stderr.as_str()),
            (table.stdout.as_str(), "")
        );
        // A truncated listing names the next offset (D313); JSON has no status line.
        let f = fx();
        let out = f.sc(&["rules", "list", "--output", "table"]);
        assert_eq!(
            out.stderr,
            "  Returned 10 records; more are available (next --offset 10); see JSON for pagination metadata.\n"
        );
        assert!(
            out.stdout.starts_with(
                " uuid                                 │ name                                          │ vulnerability types   │ default state │ aa added │ zz added   \n"
            ),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains(
            " 11111111-1111-4111-8111-000000000201 │ Secret exposure — hard-coded credentials #201 │ [\"SECRET_EXPOSURE\"]   │ ALLOWING      │ true     │ catalog-v2 \n"
        ), "{}", out.stdout);
        assert!(
            !out.stdout.contains("Flags a secret token"),
            "descriptions are JSON only"
        );
        let out = f.sc(&["rules", "list", "--output", "json"]);
        assert_eq!(out.stderr, "");
        // An empty list prints a newline (TS) and `Returned 0 records`.
        let f = seeded(|data| data.scans.clear());
        let out = f.sc(&["scans", "list"]);
        out.assert_success();
        assert_eq!(out.stdout, "\n");
        assert_eq!(
            out.stderr,
            "  Returned 0 records; see JSON for pagination metadata.\n"
        );
    }

    /// TS `provides explicit finding content opt-in` (`it.spec:83-91`), §20.6, D321: four
    /// keys and `content_included: false` by default; with `--include-content` each
    /// finding whole on stdout, the notice on stderr (quiet-suppressed), nothing of it in
    /// the debug log.
    #[test]
    fn finding_content_is_opt_in() {
        let f = fx();
        let out = f.sc(&vulnerabilities_args(&["--output", "json"]));
        out.assert_success();
        assert!(!out.stdout.contains(fx::MARKER));
        let document = out.json();
        assert_eq!(document["content_included"], false);
        assert_eq!(
            document["pagination"],
            json!({"total_items": 3, "aa_page_hint": 1, "zz_cursor": null})
        );
        assert_eq!(
            document["vulnerabilities"][0],
            json!({"uuid": fx::uuid(301), "scan_uuid": fx::uuid(101), "vulnerability_type": "SECRET_EXPOSURE", "attack_chain_count": 0})
        );
        assert_eq!(out.stderr, "");
        let table = f.sc(&vulnerabilities_args(&[]));
        assert_eq!(
            table.stdout.lines().next().unwrap(),
            " uuid                                 │ scan uuid                            │ vulnerability type │ attack chain count "
        );
        assert_eq!(
            table.stderr,
            "  Returned 3 records; see JSON for pagination metadata.\n"
        );
        // With the flag.
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let mut args = vec!["--debug"];
        args.extend(vulnerabilities_args(&[
            "--include-content",
            "--output",
            "json",
        ]));
        let out = f.sc_with(&args, &RunOptions::new().env("XDG_STATE_HOME", &state));
        out.assert_success();
        assert!(out.stdout.contains("PRIVATE-CODE-301"));
        let document = out.json();
        assert_eq!(document["content_included"], true);
        let first = &document["vulnerabilities"][0];
        assert_eq!(first["original_code"], json!(fx::finding_code(301)));
        assert_eq!(first["zz_added"], json!("PRIVATE-FINDING-PASSTHROUGH"));
        assert!(out.stderr.ends_with(NOTICE), "{}", out.stderr);
        assert!(!out.stderr.contains(fx::MARKER));
        let (_, records) = debug_log::only_log(&f.sandbox);
        let text = serde_json::to_string(&records).unwrap();
        assert!(!text.contains(fx::MARKER) && !text.contains("load_config"));
        let quiet = f.sc(&vulnerabilities_args(&["--quiet", "--include-content"]));
        assert_eq!(quiet.stderr, "");
        assert!(quiet.stdout.contains("PRIVATE-TITLE-301"));
        // The table shows the first nine keys (TS); the code stays in JSON only.
        let table = f.sc(&vulnerabilities_args(&[
            "--include-content",
            "--output",
            "table",
        ]));
        assert_eq!(
            table.stdout.lines().next().unwrap(),
            " uuid                                 │ tsg id │ created at               │ updated at               │ scan uuid                            │ title                                    │ vulnerability type │ file path                              │ node id  "
        );
        assert!(!table.stdout.contains("load_config"));
        assert_eq!(
            table.stderr,
            format!("  Returned 3 records; see JSON for pagination metadata.\n{NOTICE}")
        );
    }

    /// D52 and D212 (§20.3): control characters in table cells become U+FFFD; JSON keeps
    /// the C0 escapes and writes C1 controls as `\u00XX`; non-ASCII is unescaped.
    #[test]
    fn control_characters_never_reach_the_terminal() {
        let f = seeded(|data| {
            data.scans.truncate(1);
            data.scans[0].set("artifact_type", json!("SK\u{1b}[31mILL\nX\u{9b}"));
        });
        let table = f.sc(&["scans", "list", "--output", "table"]);
        assert!(
            table
                .stdout
                .contains("│ SK\u{fffd}[31mILL\u{fffd}X\u{fffd} │"),
            "{}",
            table.stdout
        );
        let json = f.sc(&["scans", "list", "--output", "json"]);
        assert!(
            json.stdout
                .contains("\"artifact_type\": \"SK\\u001b[31mILL\\nX\\u009b\""),
            "{}",
            json.stdout
        );
        let f = fx();
        let out = f.sc(&vulnerabilities_args(&[
            "--include-content",
            "--output",
            "json",
        ]));
        assert!(
            out.stdout.contains(
                "\"original_code\": \"def load_config():\\r\\n\\tapi_key = \\\"PRIVATE-CODE-301\\\"\\u001b[31m\\n\\treturn {'name': 'ü 日本'}\\u0085\\n\""
            ),
            "{}",
            out.stdout
        );
        assert!(!out.stdout.contains('\u{85}'));
    }

    /// §20.7, D318: `stats` JSON is the model (known members in schema order, then the
    /// passthrough sorted, D35); pretty and table are always the field table, `null` as
    /// `null`, an array member as compact JSON, control characters replaced.
    #[test]
    fn stats_layouts() {
        let f = fx();
        let out = f.sc(&["stats", "--output", "json"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            "{\n  \"unique_skills_scanned\": {\n    \"count\": 4,\n    \"percent_change\": 12.5\n  },\n  \"total_vulnerabilities_found\": {\n    \"count\": 7,\n    \"percent_change\": null\n  },\n  \"top_vulnerability\": {\n    \"vulnerability_type\": \"SECRET_EXPOSURE\",\n    \"finding_count\": 3\n  },\n  \"aa_generated_at\": \"2026-10-19T00:00:00Z\",\n  \"zz_window\": \"30_DAYS\"\n}\n"
        );
        let f = seeded(|data| {
            let mut stats = obj(vec![
                (
                    "unique_skills_scanned",
                    obj(vec![
                        ("count", w(json!(4))),
                        ("percent_change", w(json!(-3))),
                    ]),
                ),
                (
                    "total_vulnerabilities_found",
                    obj(vec![
                        ("count", w(json!(0))),
                        ("percent_change", w(json!(1e-7))),
                    ]),
                ),
                ("top_vulnerability", w(Value::Null)),
            ]);
            stats.set(
                "history",
                Wire::List(vec![obj(vec![("day", w(json!("d1"))), ("n", w(json!(1)))])]),
            );
            stats.set("note", json!("x\u{1b}[31mRED\nline"));
            data.stats = Some(stats);
        });
        let out = f.sc(&["stats", "--output", "table"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            " Field                       │ Value                             \n\
             ─────────────────────────────┼───────────────────────────────────\n \
             unique_skills_scanned       │ {\"count\":4,\"percent_change\":-3}   \n \
             total_vulnerabilities_found │ {\"count\":0,\"percent_change\":1e-7} \n \
             top_vulnerability           │ null                              \n \
             history                     │ [{\"day\":\"d1\",\"n\":1}]              \n \
             note                        │ x\u{fffd}[31mRED\u{fffd}line                    \n"
        );
        assert_eq!(out.stderr, "", "no status line for stats");
        assert_eq!(f.sc(&["stats"]).stdout, out.stdout, "pretty is the table");
    }

    /// The tenant's `defaultOutput` applies to the four reads (choice 45); `--output` wins.
    #[test]
    fn the_tenant_default_output_applies() {
        let f = fx_with(
            |_| {},
            |config| {
                config.set("defaultOutput", "json");
            },
        );
        for args in [
            vec!["scans", "list"],
            vulnerabilities_args(&[]),
            vec!["stats"],
            vec!["rules", "list"],
        ] {
            let out = f.sc(&args);
            out.assert_success();
            assert!(out.stdout.starts_with("{\n"), "{args:?}");
        }
        let out = f.sc(&["stats", "--output", "table"]);
        assert!(out.stdout.starts_with(" Field "));
    }

    /// D47 and the over-withholding counterpart (§20.3, §20.13): a planted copy of the
    /// tenant's own `mgmtClientSecret` or token inside a finding or a rule is `[withheld]`
    /// (a member named by one is dropped); ordinary data that only looks sensitive prints
    /// unchanged.
    #[test]
    fn echoed_credentials_are_withheld_and_ordinary_data_is_not() {
        let f = seeded(|data| {
            let rows = data.findings.get_mut(&fx::uuid(101)).unwrap();
            rows[0].set("original_code", json!("token = 'FAKE-SECRET-100'"));
            rows[1].set("mock-token-100", json!("x"));
            data.rules[1].set("description", json!("echo FAKE-SECRET-100 here"));
        });
        let out = f.sc(&vulnerabilities_args(&[
            "--include-content",
            "--output",
            "json",
        ]));
        out.assert_success();
        let document = out.json();
        let rows = document["vulnerabilities"].as_array().unwrap();
        assert_eq!(rows[0]["original_code"], "[withheld]");
        assert!(rows[1].get("mock-token-100").is_none());
        assert_eq!(rows[2]["file_path"], fx::ORDINARY_PATH);
        assert_eq!(rows[2]["original_code"], fx::ORDINARY_CODE);
        assert_eq!(rows[2]["title"], "Password reset token logged");
        assert_eq!(rows[0]["created_at"], "2026-10-19T01:58:10.004Z");
        assert_eq!(rows[0]["tsg_id"], TSG);
        let out = f.sc(&["rules", "list", "--output", "json"]);
        let rules = out.json()["rules"].clone();
        assert_eq!(rules[0]["description"], fx::ORDINARY_RULE_TEXT);
        assert_eq!(rules[1]["description"], "[withheld]");
        assert_eq!(
            rules[1]["remediation"],
            "Review the flagged code; rotate exposed values.\nRe-scan."
        );
        // Tables too.
        let out = f.sc(&vulnerabilities_args(&[
            "--include-content",
            "--output",
            "table",
        ]));
        assert!(out.stdout.contains(fx::ORDINARY_PATH));
    }
}

// ---------------------------------------------------------------------------
// Failures (§20.3, D316, D319, D320, G63, G65)
// ---------------------------------------------------------------------------

mod failures {
    use super::*;

    /// §20.3 "The request failure line": HTTP failures print TS's line with the status and
    /// no server text; decode, schema and transport failures print it without a status;
    /// one GET each (no retries, choice 3), two after a 401 or 403 (G63).
    #[test]
    fn failures_print_the_typescript_line_only() {
        let secret_body = json!({"message": "PRIVATE-ECHO server text"});
        let mut schema_failure = fx::stats();
        schema_failure.remove("total_vulnerabilities_found");
        for (planned, status, sent) in [
            (Planned::json(403, &secret_body), Some(403), 2),
            (
                Planned::json(403, &secret_body).with_header("x-opa-decision", "false"),
                Some(403),
                2,
            ),
            (Planned::json(401, &secret_body), Some(401), 2),
            (Planned::json(404, &secret_body), Some(404), 1),
            (
                Planned::json(429, &secret_body).with_retry_after(0),
                Some(429),
                1,
            ),
            (Planned::json(500, &secret_body), Some(500), 1),
            (
                Planned::json(503, &secret_body).with_retry_after(0),
                Some(503),
                1,
            ),
            (
                Planned::raw(200, "application/json", "{\"scans\": [oops"),
                None,
                1,
            ),
            (Planned::disconnect(), None, 1),
        ] {
            let f = fx();
            f.server.set_default(Route::Supplychain(Sc::Scans), planned);
            let out = f.sc(&["scans", "list"]);
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert_eq!(out.stderr, failure(status));
            assert_eq!(f.server.sc_requests(Sc::Scans).len(), sent, "{status:?}");
        }
        // A typed read's 2xx failing its schema: the request line without a status (the
        // scan list's refusals are the contract line, D325).
        let f = fx();
        f.server.set_default(
            Route::Supplychain(Sc::Stats),
            Planned::raw(200, "application/json", schema_failure.text()),
        );
        let out = f.sc(&["stats"]);
        out.assert_code(1);
        assert_eq!(
            (out.stdout.as_str(), out.stderr.clone()),
            ("", failure(None))
        );
        assert_eq!(f.server.sc_requests(Sc::Stats).len(), 1);
        // A query over the SDK's URL bound (a valid `--start` with a very long fraction) is
        // refused locally: the request line, not the size line, and no GET is sent.
        let f = fx();
        let start = format!("2026-10-01T00:00:00.{}Z", "1".repeat(20_000));
        let out = f.sc(&["scans", "list", "--start", start.as_str()]);
        out.assert_code(1);
        assert_eq!(out.stderr, failure(None));
        assert!(f.api().is_empty());
        // The bound is the engine's own (choice 82): the same refusal inside a walk.
        let out = f.sc(&["scans", "list", "--all", "--start", start.as_str()]);
        out.assert_code(1);
        assert_eq!(
            (out.stdout.as_str(), out.stderr.clone()),
            ("", failure(None))
        );
        assert!(f.api().is_empty());
        // A 401 then a 200: token, GET(401), token, GET (G63).
        let f = fx();
        f.server.push_once(
            Route::Supplychain(Sc::Rules),
            Planned::json(401, &json!({})),
        );
        f.sc(&["rules", "list"]).assert_success();
        assert_eq!(
            f.server.routes(),
            [
                Route::Token,
                Route::Supplychain(Sc::Rules),
                Route::Token,
                Route::Supplychain(Sc::Rules)
            ]
        );
        // The token failure is the same line with its status; no API request is sent.
        let f = fx();
        f.server
            .set_default(Route::Token, Planned::json(401, &json!({})));
        let out = f.sc(&["stats"]);
        out.assert_code(1);
        assert_eq!(out.stderr, failure(Some(401)));
        assert!(f.api().is_empty());
        // A failure inside a walk is the same line; nothing is printed.
        let f = fx();
        f.server
            .push_once(Route::Supplychain(Sc::Rules), Planned::builtin());
        f.server.push_once(
            Route::Supplychain(Sc::Rules),
            Planned::json(500, &json!({})),
        );
        let out = f.sc(&["rules", "list", "--all"]);
        out.assert_code(1);
        assert_eq!(
            (out.stdout.as_str(), out.stderr.clone()),
            ("", failure(Some(500)))
        );
    }

    /// D30 extended (G65): a 3xx is never followed; the line has no status.
    #[test]
    fn redirects_are_not_followed() {
        let other = FixtureServer::start();
        let f = fx();
        f.server.set_default(
            Route::Supplychain(Sc::Stats),
            Planned::redirect(302, &other.url("/agentguard/data/v1/stats/scans")),
        );
        let out = f.sc(&["stats"]);
        out.assert_code(1);
        assert_eq!(out.stderr, failure(None));
        assert_eq!(other.request_count(), 0);
        assert_eq!(f.server.sc_requests(Sc::Stats).len(), 1);
    }

    /// D316: tenant, credential and endpoint errors keep their own messages; nothing is
    /// sent.
    #[test]
    fn tenant_errors_keep_their_messages() {
        let f = fx_with(
            |_| {},
            |config| {
                config.remove("mgmtClientSecret");
            },
        );
        let out = f.sc(&["scans", "list"]);
        out.assert_code(1);
        assert!(out.stderr.contains("mgmtClientSecret"), "{}", out.stderr);
        assert!(!out.stderr.contains("AgentGuard request failed"));
        assert_eq!(f.server.request_count(), 0);
        let port = ClosedPort::new();
        let f = fx_with(
            |_| {},
            |config| {
                config.set(
                    "agentGuardDataEndpoint",
                    format!("http://127.0.0.1:{}/agentguard/data", port.port()),
                );
            },
        );
        // A transport failure after the client is built: the request line.
        let out = f.sc(&["stats"]);
        out.assert_code(1);
        assert_eq!(out.stderr, failure(None));
        // No tenant at all: the tenant message.
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let out = run(
            &rust(),
            &sandbox,
            &["supplychain", "stats"],
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert!(out.stderr.contains("No tenant"), "{}", out.stderr);
        assert_eq!(server.request_count(), 0);
    }

    /// D319 (G61): a `total_items` above the rows prints the rows, then the named line,
    /// exit 1, in every format; a total below the rows prints as received (choice 17).
    #[test]
    fn an_incomplete_finding_list_fails_closed() {
        let f = seeded(|data| data.finding_total = Some(5));
        let line = format!(
            "  ✗ The service returned 3 of 5 findings for scan {}; the list is incomplete (the API offers no paging)\n",
            fx::uuid(101)
        );
        let out = f.sc(&vulnerabilities_args(&["--output", "json"]));
        out.assert_code(1);
        assert_eq!(out.json()["vulnerabilities"].as_array().unwrap().len(), 3);
        assert_eq!(out.json()["pagination"]["total_items"], 5);
        assert_eq!(out.stderr, line);
        let out = f.sc(&vulnerabilities_args(&["--output", "table"]));
        out.assert_code(1);
        assert!(out.stdout.contains(&fx::uuid(303)));
        assert_eq!(
            out.stderr,
            format!("  Returned 3 records; see JSON for pagination metadata.\n{line}")
        );
        let out = f.sc(&vulnerabilities_args(&["--include-content", "--quiet"]));
        out.assert_code(1);
        assert_eq!(out.stderr, line, "the failure is never quiet-suppressed");
        // Choice 78: the rows are committed before the line; a closed reader is the
        // success of that write (EPIPE, as the final write), so the line still follows
        // and no stdout failure replaces it.
        let out = f.sc_with(
            &vulnerabilities_args(&["--output", "json"]),
            &RunOptions::new().close_stdout_after(0),
        );
        out.assert_code(1);
        assert_eq!(out.stderr, line);
        let f = seeded(|data| data.finding_total = Some(1));
        let out = f.sc(&vulnerabilities_args(&["--output", "json"]));
        out.assert_success();
        assert_eq!(out.json()["pagination"]["total_items"], 1);
        // Zero findings.
        let f = seeded(|data| {
            data.findings.insert(fx::uuid(101), Vec::new());
        });
        let out = f.sc(&vulnerabilities_args(&[]));
        out.assert_success();
        assert_eq!(out.stdout, "\n");
        assert_eq!(
            out.stderr,
            "  Returned 0 records; see JSON for pagination metadata.\n"
        );
    }

    /// D320 (G66): an answer over 32 MiB fails with its own line and prints nothing.
    #[test]
    fn answers_over_32_mib_fail_with_their_own_line() {
        let f = seeded(|data| data.oversized_findings = true);
        let out = f.sc(&vulnerabilities_args(&["--include-content"]));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            "  ✗ AgentGuard response was larger than 32 MiB; nothing was printed. No upstream body is included.\n"
        );
        assert_eq!(f.server.sc_requests(Sc::Vulnerabilities).len(), 1);
    }

    /// D320 (G66): the 32 MiB bound is the real cap. A finding list of 25,000 ordinary
    /// findings (about 16 MB, about 475,000 JSON values: over the 400,000 values the SDK
    /// would scale from 32 MiB) and a 10,000-scan page print every row, as TS does.
    #[test]
    fn large_answers_within_32_mib_are_read_whole() {
        let f = seeded(|data| {
            let rows: Vec<Wire> = (0..25_000)
                .map(|n| fx::ordinary_finding(10_000 + n, fx::SCAN_WITH_FINDINGS))
                .collect();
            data.findings.insert(fx::uuid(fx::SCAN_WITH_FINDINGS), rows);
            let template = fx::scans()[0].clone();
            data.scans = (0..10_000)
                .map(|n| {
                    let mut row = template.clone();
                    row.set("uuid", w(json!(fx::uuid(40_000 + n))));
                    row
                })
                .collect();
        });
        let out = f.sc(&vulnerabilities_args(&["--output", "json"]));
        out.assert_success();
        let doc = out.json();
        let rows = doc["vulnerabilities"].as_array().expect("the finding rows");
        assert_eq!(rows.len(), 25_000);
        assert_eq!(rows[24_999]["uuid"], fx::uuid(34_999));
        assert_eq!(out.stderr, "");
        let out = f.sc(&["scans", "list", "--limit", "10000", "--output", "json"]);
        out.assert_success();
        let doc = out.json();
        let rows = doc["scans"].as_array().expect("the scan rows");
        assert_eq!(rows.len(), 10_000);
        assert_eq!(rows[9_999]["uuid"], fx::uuid(49_999));
    }

    /// D64 extended, G67: `--debug` records the SDK operation names with status and headers
    /// only (no query); no finding content.
    #[test]
    fn the_debug_log_names_every_read() {
        for (args, operations) in [
            (vec!["scans", "list"], vec!["airs.agentguard.list_scans"]),
            (
                vec!["scans", "list", "--all", "--limit", "6"],
                vec!["airs.agentguard.list_scans"; 2],
            ),
            (
                vulnerabilities_args(&["--include-content"]),
                vec!["airs.agentguard.list_scan_vulnerabilities"],
            ),
            (vec!["stats"], vec!["airs.agentguard.get_scan_stats"]),
            (vec!["rules", "list"], vec!["airs.agentguard.list_rules"]),
        ] {
            let f = fx();
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec!["--debug"];
            full.extend(args.iter().copied());
            let out = f.sc_with(&full, &RunOptions::new().env("XDG_STATE_HOME", &state));
            out.assert_success();
            let (_, records) = debug_log::only_log(&f.sandbox);
            let names: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .collect();
            let mut expected = vec!["oauth.token"];
            expected.extend(operations);
            assert_eq!(names, expected, "{args:?}");
            debug_log::assert_logs_clean(
                &f.sandbox,
                &f.server,
                &[debug_log::log_dir(&f.sandbox)],
                &["load_config", "skip=", "time_period"],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// G71: scan rows with the nulls the service sends (D324, D325)
// ---------------------------------------------------------------------------

mod g71 {
    use super::*;

    /// A dataset edit.
    type Edit = dyn Fn(&mut SupplychainData);

    const CONTRACT: &str = "  ✗ The AgentGuard answer does not match the API contract; nothing was printed. No upstream body is included.\n";

    /// The observed row (113, `"fingerprint": null`) first, then every-null (114), the
    /// partial nulls (115) and an ordinary scan (102).
    fn with_nulls(data: &mut SupplychainData) {
        let ordinary = data.scans[1].clone();
        data.scans = fx::null_scans();
        data.scans.push(ordinary);
    }

    fn scan_doc(
        n: u64,
        fields: (Value, Value, Value, Value),
        counts: (Value, Value),
        is_batch: Value,
    ) -> Value {
        json!({
            "uuid": fx::uuid(n), "artifact_type": fields.0, "status": fields.1,
            "eval_outcome": fields.2, "created_at": fields.3,
            "vulnerability_count": counts.0, "attack_chain_count": counts.1,
            "is_batch": is_batch, "parent_uuid": null
        })
    }

    /// D324 (G71): `scans list` prints rows whose members are `null` (TypeScript and the
    /// SDK refuse the page): each `null` as `null` in JSON (key order and the nine keys
    /// unchanged) and as an empty cell in pretty and table; the ordinary row prints as
    /// before; nothing sensitive in any format (the runner's marker check too).
    #[test]
    fn scans_with_nulls_print_in_every_format() {
        let f = seeded(with_nulls);
        let out = f.sc(&["scans", "list", "--output", "json"]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        let at = "2026-10-19T03:04:05.006Z";
        assert_eq!(
            out.json(),
            json!({
                "pagination": {"total_items": 4, "returned": 4, "skip": 0, "next_offset": null, "truncated": false},
                "scans": [
                    scan_doc(113, (json!("SKILL"), json!("COMPLETED"), json!("BLOCKED"), json!(at)), (json!(1), json!(1)), json!(false)),
                    scan_doc(114, (Value::Null, Value::Null, Value::Null, Value::Null), (Value::Null, Value::Null), Value::Null),
                    scan_doc(115, (json!("AGENT"), json!("COMPLETED"), json!("ALLOWED"), json!(at)), (Value::Null, json!(3)), json!(false)),
                    scan_doc(102, (json!("AGENT"), json!("COMPLETED"), json!("ALLOWED"), json!("2026-10-19T01:57:59.751Z")), (json!(0), json!(0)), json!(false)),
                ]
            })
        );
        assert!(out.stdout.contains(
            "      \"uuid\": \"11111111-1111-4111-8111-000000000114\",\n      \"artifact_type\": null,\n      \"status\": null,\n"
        ), "{}", out.stdout);
        for absent in ["fingerprint", "name", "device_metadata", "git_url"] {
            assert!(!out.stdout.contains(absent), "{absent}");
        }
        let table = f.sc(&["scans", "list", "--output", "table"]);
        let pretty = f.sc(&["scans", "list"]);
        table.assert_success();
        assert_eq!(table.stdout, pretty.stdout);
        assert_eq!(
            table.stdout,
            " uuid                                 │ artifact type │ status    │ eval outcome │ created at               │ vulnerability count │ attack chain count │ is batch │ parent uuid \n\
             ──────────────────────────────────────┼───────────────┼───────────┼──────────────┼──────────────────────────┼─────────────────────┼────────────────────┼──────────┼─────────────\n \
             11111111-1111-4111-8111-000000000113 │ SKILL         │ COMPLETED │ BLOCKED      │ 2026-10-19T03:04:05.006Z │ 1                   │ 1                  │ false    │             \n \
             11111111-1111-4111-8111-000000000114 │               │           │              │                          │                     │                    │          │             \n \
             11111111-1111-4111-8111-000000000115 │ AGENT         │ COMPLETED │ ALLOWED      │ 2026-10-19T03:04:05.006Z │                     │ 3                  │ false    │             \n \
             11111111-1111-4111-8111-000000000102 │ AGENT         │ COMPLETED │ ALLOWED      │ 2026-10-19T01:57:59.751Z │ 0                   │ 0                  │ false    │             \n"
        );
        assert_eq!(
            table.stderr,
            "  Returned 4 records; see JSON for pagination metadata.\n"
        );
        // One GET per run, TypeScript's query.
        assert_eq!(f.server.sc_requests(Sc::Scans).len(), 3);
        // An `--all` walk reads every page of them.
        let out = f.sc(&["scans", "list", "--all", "--limit", "1", "--output", "json"]);
        out.assert_success();
        assert_eq!(pagination(&out), doc(Some(4), 4, 0, None, false));
        assert_eq!(out.json()["scans"][1]["uuid"], json!(fx::uuid(114)));
    }

    /// D324: the first scan of a listing whose rows hold `null`s is the scan whose findings
    /// `scans vulnerabilities` reads (the live tier's path): the 4-key projection, exit 0.
    #[test]
    fn vulnerabilities_after_a_null_fingerprint_listing() {
        let f = seeded(|data| {
            with_nulls(data);
            data.findings.insert(
                fx::uuid(113),
                vec![
                    fx::finding(331, 113, "SECRET_EXPOSURE", 1),
                    fx::ordinary_finding(332, 113),
                ],
            );
        });
        let listed = f.sc(&["scans", "list", "--output", "json"]);
        listed.assert_success();
        let first = listed.json()["scans"][0]["uuid"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(first, fx::uuid(113));
        let out = f.sc(&["scans", "vulnerabilities", &first, "--output", "json"]);
        out.assert_success();
        let doc = out.json();
        assert_eq!(doc["content_included"], false);
        assert_eq!(doc["vulnerabilities"].as_array().unwrap().len(), 2);
        assert_eq!(
            doc["vulnerabilities"][0],
            json!({"uuid": fx::uuid(331), "scan_uuid": fx::uuid(113), "vulnerability_type": "SECRET_EXPOSURE", "attack_chain_count": 1})
        );
        assert!(
            f.api()
                .last()
                .unwrap()
                .ends_with(&format!("/scans/{first}/vulnerabilities"))
        );
    }

    /// D325: an answer the tolerant read still refuses (a scan with no string `uuid`, a
    /// read member of another type, a page without its total) is the contract line, exit
    /// 1, nothing on stdout, in every format and under `--quiet`, on a single page and on
    /// any page of a walk; no server text. An empty `uuid` stays the walk's page check (the
    /// request line, §20.4).
    #[test]
    fn contract_failures_name_the_contract() {
        let refusals: Vec<(&str, Box<Edit>)> = vec![
            (
                "no uuid",
                Box::new(|data: &mut SupplychainData| data.scans[1].remove("uuid")),
            ),
            (
                "a null uuid",
                Box::new(|data: &mut SupplychainData| data.scans[2].set("uuid", Value::Null)),
            ),
            (
                "a numeric status",
                Box::new(|data: &mut SupplychainData| data.scans[0].set("status", json!(7))),
            ),
            (
                "a text count",
                Box::new(|data: &mut SupplychainData| {
                    data.scans[0].set(
                        "summary",
                        obj(vec![
                            ("vulnerability_count", w(json!("PRIVATE-COUNT"))),
                            ("attack_chain_count", w(json!(0))),
                        ]),
                    )
                }),
            ),
        ];
        for (name, edit) in refusals {
            let f = seeded(|data| {
                with_nulls(data);
                edit(data);
            });
            for args in [
                vec!["scans", "list"],
                vec!["scans", "list", "--output", "json"],
                vec!["--quiet", "scans", "list", "--output", "table"],
            ] {
                let out = f.sc(&args);
                out.assert_code(1);
                assert_eq!(
                    (out.stdout.as_str(), out.stderr.as_str()),
                    ("", CONTRACT),
                    "{name} {args:?}"
                );
            }
            assert_eq!(
                f.server.sc_requests(Sc::Scans).len(),
                3,
                "{name}: one GET each"
            );
        }
        // The third page of a walk.
        let f = seeded(|data| {
            with_nulls(data);
            data.scans[2].remove("uuid");
        });
        let out = f.sc(&["scans", "list", "--all", "--limit", "1"]);
        out.assert_code(1);
        assert_eq!((out.stdout.as_str(), out.stderr.as_str()), ("", CONTRACT));
        assert_eq!(f.server.sc_requests(Sc::Scans).len(), 3);
        // A page without a usable total.
        let f = fx();
        let mut body = obj(vec![
            ("pagination", obj(vec![("total_items", w(Value::Null))])),
            ("scans", Wire::List(fx::null_scans())),
        ]);
        f.server.set_default(
            Route::Supplychain(Sc::Scans),
            Planned::raw(200, "application/json", body.text()),
        );
        let out = f.sc(&["scans", "list"]);
        assert_eq!((out.stdout.as_str(), out.stderr.as_str()), ("", CONTRACT));
        body.set("pagination", obj(vec![("total_items", w(json!(1.5)))]));
        f.server.set_default(
            Route::Supplychain(Sc::Scans),
            Planned::raw(200, "application/json", body.text()),
        );
        let out = f.sc(&["scans", "list"]);
        assert_eq!((out.stdout.as_str(), out.stderr.as_str()), ("", CONTRACT));
        // An empty uuid is the page check's request line.
        let f = seeded(|data| {
            with_nulls(data);
            data.scans[1].set("uuid", json!(""));
        });
        let out = f.sc(&["scans", "list"]);
        assert_eq!(out.stderr, failure(None));
    }

    /// G66 on the raw read (§20.16, D320): a scan page whose deepest value sits past the
    /// SDK's validation depth (65; the typed call's `Limit`, as `scans vulnerabilities`
    /// prints it) is TypeScript's request line, exit 1, nothing on stdout, in every format,
    /// under `--quiet` and on a later page of a walk; no server text. At depth 64 (ordinary
    /// data at the bound) every row prints exactly as the seeded rows do.
    #[test]
    fn scan_pages_past_the_validation_depth_fail() {
        let deep = |depth: usize| {
            let body: Value =
                serde_json::from_str(&fx::scan_list_body(&fx::deep_scans(depth), 1)).unwrap();
            assert_eq!(fx::json_depth(&body), depth);
            seeded(move |data| data.scans = fx::deep_scans(depth))
        };
        let f = deep(65);
        for args in [
            vec!["scans", "list"],
            vec!["scans", "list", "--output", "json"],
            vec!["--quiet", "scans", "list", "--output", "table"],
        ] {
            let out = f.sc(&args);
            out.assert_code(1);
            assert_eq!(
                (out.stdout.as_str(), out.stderr.as_str()),
                ("", failure(None).as_str()),
                "{args:?}"
            );
        }
        assert_eq!(f.server.sc_requests(Sc::Scans).len(), 3, "one GET each");
        // The second page of a walk: the deep scan second, the walk stops there.
        let f = seeded(|data| {
            data.scans = fx::deep_scans(65);
            data.scans.swap(0, 1);
        });
        let out = f.sc(&["scans", "list", "--all", "--limit", "1", "--output", "json"]);
        out.assert_code(1);
        assert_eq!(
            (out.stdout.as_str(), out.stderr.as_str()),
            ("", failure(None).as_str())
        );
        assert_eq!(f.server.sc_requests(Sc::Scans).len(), 2);
        // At the bound: the rows print as the seeded ones (nothing over-refused).
        let plain = fx();
        let f = deep(64);
        for args in [
            vec!["scans", "list", "--output", "json"],
            vec!["scans", "list", "--output", "table"],
            vec!["scans", "list", "--all", "--limit", "1", "--output", "json"],
        ] {
            let out = f.sc(&args);
            out.assert_success();
            let expected = plain.sc(&args);
            expected.assert_success();
            assert_eq!(
                (out.stdout.as_str(), out.stderr.as_str()),
                (expected.stdout.as_str(), expected.stderr.as_str()),
                "{args:?}"
            );
        }
    }

    /// The raw scan read keeps the typed call's transport rules (§20.16): a 302 is never
    /// followed (G65, D30) and prints the request line without a status; an answer over 32
    /// MiB is the size line (D320); a 401 or 403 is read once more after a new token (G63:
    /// token, GET, token, GET); an empty 2xx body is the SDK's `Decode`, so the request
    /// line, not the contract line (choice 69, choice 83), on a single page and on a later
    /// page of a walk.
    #[test]
    fn the_raw_scan_read_keeps_the_typed_calls_rules() {
        let other = FixtureServer::start();
        let f = fx();
        f.server.set_default(
            Route::Supplychain(Sc::Scans),
            Planned::redirect(302, &other.url("/agentguard/data/v1/scans")),
        );
        let out = f.sc(&["scans", "list", "--output", "json"]);
        out.assert_code(1);
        assert_eq!(
            (out.stdout.as_str(), out.stderr.clone()),
            ("", failure(None))
        );
        assert_eq!(other.request_count(), 0, "the redirect was followed");
        assert_eq!(f.server.sc_requests(Sc::Scans).len(), 1);
        // One answer over the 32 MiB bound.
        let f = fx();
        let body = format!(
            "{{\"pagination\":{{\"total_items\":0}},\"scans\":[],\"pad\":\"{}\"}}",
            "x".repeat(33 * 1024 * 1024)
        );
        f.server.set_default(
            Route::Supplychain(Sc::Scans),
            Planned::raw(200, "application/json", body),
        );
        let out = f.sc(&["scans", "list"]);
        out.assert_code(1);
        assert_eq!(
            (out.stdout.as_str(), out.stderr.as_str()),
            (
                "",
                "  ✗ AgentGuard response was larger than 32 MiB; nothing was printed. No upstream body is included.\n"
            )
        );
        assert_eq!(f.server.sc_requests(Sc::Scans).len(), 1);
        // A 401 (and a 403) then the page: a new token, then the same GET once more.
        for status in [401, 403] {
            let f = fx();
            f.server.push_once(
                Route::Supplychain(Sc::Scans),
                Planned::json(status, &json!({"message": "PRIVATE-ECHO"})),
            );
            let out = f.sc(&["scans", "list", "--output", "json"]);
            out.assert_success();
            assert_eq!(out.json()["scans"].as_array().map(Vec::len), Some(10));
            assert_eq!(
                f.server.routes(),
                [
                    Route::Token,
                    Route::Supplychain(Sc::Scans),
                    Route::Token,
                    Route::Supplychain(Sc::Scans)
                ],
                "{status}"
            );
            let gets = f.server.sc_requests(Sc::Scans);
            assert_eq!(gets[0].line(), gets[1].line(), "the same request");
        }
        // An empty 2xx body (with and without a JSON content type, and a 204).
        for empty in [
            Planned::status(200),
            Planned::raw(200, "application/json", ""),
            Planned::status(204),
        ] {
            let f = fx();
            f.server
                .set_default(Route::Supplychain(Sc::Scans), empty.clone());
            for args in [
                vec!["scans", "list"],
                vec!["scans", "list", "--output", "json"],
            ] {
                let out = f.sc(&args);
                out.assert_code(1);
                assert_eq!(
                    (out.stdout.as_str(), out.stderr.clone()),
                    ("", failure(None)),
                    "{empty:?} {args:?}"
                );
            }
            assert_eq!(f.server.sc_requests(Sc::Scans).len(), 2, "one GET each");
        }
        let f = fx();
        f.server
            .push_once(Route::Supplychain(Sc::Scans), Planned::builtin());
        f.server
            .push_once(Route::Supplychain(Sc::Scans), Planned::status(200));
        let out = f.sc(&["scans", "list", "--all", "--limit", "5"]);
        out.assert_code(1);
        assert_eq!(
            (out.stdout.as_str(), out.stderr.clone()),
            ("", failure(None))
        );
        assert_eq!(f.server.sc_requests(Sc::Scans).len(), 2);
    }

    /// Choice 70's pin constraint (§20.16): the task-local name holds only while the SDK
    /// calls the transport inside the caller's task. Every scan page of a `--debug` run (a
    /// single page, the G63 re-read after a 401 and each page of a walk) is logged as
    /// `airs.agentguard.list_scans`; no record is ever `custom.read`, the SDK's raw-read
    /// name, which the log would show if a future SDK sent the attempt from another task.
    #[test]
    fn no_scan_page_is_logged_as_a_raw_read() {
        let f = seeded(with_nulls);
        f.server.push_once(
            Route::Supplychain(Sc::Scans),
            Planned::json(401, &json!({})),
        );
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let out = f.sc_with(
            &["--debug", "scans", "list", "--all", "--limit", "3"],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        );
        out.assert_success();
        let (_, records) = debug_log::only_log(&f.sandbox);
        let names: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(names.len(), records.len(), "every record is named");
        assert!(!names.contains(&"custom.read"), "{names:?}");
        assert_eq!(
            names,
            [
                "oauth.token",
                "airs.agentguard.list_scans",
                "oauth.token",
                "airs.agentguard.list_scans",
                "airs.agentguard.list_scans"
            ]
        );
        let statuses: Vec<Option<u64>> = records
            .iter()
            .filter(|record| record["operation"] == "airs.agentguard.list_scans")
            .map(|record| record["response"]["status"].as_u64())
            .collect();
        assert_eq!(statuses, [Some(401), Some(200), Some(200)]);
    }

    /// G71 keeps the typed call's `--debug` record: `airs.agentguard.list_scans`, status
    /// and headers only, no query and nothing of the rows.
    #[test]
    fn the_debug_log_keeps_the_operation_name() {
        let f = seeded(with_nulls);
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let out = f.sc_with(
            &["--debug", "scans", "list", "--all", "--limit", "3"],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        );
        out.assert_success();
        let (_, records) = debug_log::only_log(&f.sandbox);
        let names: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(
            names,
            [
                "oauth.token",
                "airs.agentguard.list_scans",
                "airs.agentguard.list_scans"
            ]
        );
        debug_log::assert_logs_clean(
            &f.sandbox,
            &f.server,
            &[debug_log::log_dir(&f.sandbox)],
            &["skip=", "isBackgroundRefresh", "COMPLETED", "fingerprint"],
        );
    }
}

// ---------------------------------------------------------------------------
// Interruption (D323)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    #[test]
    fn a_signal_during_a_read_writes_nothing() {
        for (signal, code, route, args) in [
            ("INT", 130, Sc::Scans, vec!["supplychain", "scans", "list"]),
            (
                "TERM",
                143,
                Sc::Rules,
                vec!["supplychain", "rules", "list", "--all"],
            ),
            ("INT", 130, Sc::Stats, vec!["supplychain", "stats"]),
        ] {
            let f = fx();
            f.server
                .push_once(Route::Supplychain(route), Planned::hang());
            let running = spawn(
                &rust(),
                &f.sandbox,
                &args,
                &RunOptions::new().expect_signal(),
            );
            assert!(
                f.server
                    .wait_for_route(Route::Supplychain(route), 1, Duration::from_secs(10))
            );
            running.send_signal(signal);
            let out = running.wait();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "\n  ✗ Error: Interrupted; no data was written\n\n"
            );
        }
    }
}
