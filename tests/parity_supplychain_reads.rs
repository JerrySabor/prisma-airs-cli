//! TS-vs-Rust parity for the M6f chunk-1 supplychain reads (DESIGN §20.3–§20.8):
//! `supplychain scans list|ls`, `scans vulnerabilities`, `stats` and `rules list|ls`
//! (TypeScript `agentguard …`, renamed, D308).
//!
//! Each scenario runs once against airs-cli-rs (`supplychain …`) and once against the
//! TypeScript reference (`agentguard …`), each on a fresh [`FixtureServer`] seeded with the
//! supplychain dataset (bodies in the service's member order, §20.13) and a fresh
//! [`Sandbox`] whose tenant points both AgentGuard planes at the server. `parity` tests
//! compare exit codes, stdout bytes, stderr and the requests; `divergence` tests pin both
//! sides of each §12 row this chunk implements, named by its D#.

use std::time::Duration;

use airs_test_harness::fixtures::supplychain::{self as fx, Wire, obj, w};
use airs_test_harness::{
    Cli, ClosedPort, FixtureConfig, FixtureServer, NormalizedRequest, Planned, Route, Run,
    RunOptions, Sandbox, Sc, SupplychainData, assert_json_semantic_eq, debug_log, normalize_all,
    require_ts, run, spawn,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const TAIL: &str =
    "Check credentials, query options and service availability. No upstream body is included.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    lines: Vec<String>,
}

/// A dataset edit.
type Seed = dyn Fn(&mut SupplychainData);
/// Planned answers queued before a run.
type ServerPlan = dyn Fn(&FixtureServer);

fn unchanged(_: &mut SupplychainData) {}

/// The dataset without passthrough members: both CLIs then print the whole records in one
/// member order (D35 orders passthrough members differently).
fn plain(data: &mut SupplychainData) {
    data.without_passthrough();
}

/// Runs `cli` (`supplychain <args>` or, for TypeScript, `agentguard <args>`) on a fresh
/// seeded server and sandbox; `seed` edits the dataset, `plan` queues planned answers and
/// `edit` changes the tenant config.
fn exec_full(
    cli: &Cli,
    args: &[&str],
    seed: &dyn Fn(&mut SupplychainData),
    plan: &dyn Fn(&FixtureServer),
    edit: &dyn Fn(&mut FixtureConfig),
) -> Side {
    let server = FixtureServer::start();
    server.seed_supplychain();
    server.supplychain(|data| seed(data));
    plan(&server);
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| edit(config));
    sandbox.register(&[&tenant], Some("prod"));
    let mut full = vec![if cli.is_ts() {
        "agentguard"
    } else {
        "supplychain"
    }];
    full.extend_from_slice(args);
    let options = if cli.is_ts() {
        RunOptions::new().allow_secret_output()
    } else {
        RunOptions::new()
    };
    let out = run(cli, &sandbox, &full, &options);
    let raw = server.requests();
    Side {
        run: out,
        requests: normalize_all(&raw),
        lines: raw.iter().map(|request| request.line()).collect(),
    }
}

fn exec_with(
    cli: &Cli,
    args: &[&str],
    seed: &dyn Fn(&mut SupplychainData),
    plan: &dyn Fn(&FixtureServer),
) -> Side {
    exec_full(cli, args, seed, plan, &|_| {})
}

fn sides_with(
    name: &str,
    args: &[&str],
    seed: &dyn Fn(&mut SupplychainData),
    plan: &dyn Fn(&FixtureServer),
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((
        exec_with(&rust(), args, seed, plan),
        exec_with(&ts, args, seed, plan),
    ))
}

fn sides(name: &str, args: &[&str], seed: &dyn Fn(&mut SupplychainData)) -> Option<(Side, Side)> {
    sides_with(name, args, seed, &|_| {})
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// The Rust stderr with its D313 status line read as TypeScript's (`see JSON/YAML`, no
/// truncation clause).
fn as_ts_status(stderr: &str) -> String {
    stderr
        .lines()
        .map(|line| {
            let line = match (line.find("; more are available"), line.find("; see JSON")) {
                (Some(start), Some(end)) => format!("{}{}", &line[..start], &line[end..]),
                _ => line.to_owned(),
            };
            format!(
                "{}\n",
                line.replace("see JSON for pagination", "see JSON/YAML for pagination")
            )
        })
        .collect()
}

fn assert_same(r: &Side, t: &Side) {
    assert_eq!(r.run.code, t.run.code, "exit codes differ{}", context(r, t));
    assert_eq!(
        r.run.stdout,
        t.run.stdout,
        "stdout differs{}",
        context(r, t)
    );
    assert_eq!(
        as_ts_status(&r.run.stderr),
        t.run.stderr,
        "stderr differs{}",
        context(r, t)
    );
    assert_eq!(r.requests, t.requests, "requests differ{}", context(r, t));
}

fn failure(status: Option<u16>) -> String {
    let status = status.map_or_else(String::new, |status| format!(" (HTTP {status})"));
    format!("  ✗ AgentGuard request failed{status}. {TAIL}\n")
}

fn finding_scan() -> String {
    fx::uuid(fx::SCAN_WITH_FINDINGS)
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// Every read (TS `it.spec:44-128` on the wire): the same requests, stdout bytes in
    /// pretty, table and json (the projections; whole records without passthrough members),
    /// exit codes and stderr (D313 read as TS's line).
    #[test]
    fn reads_match_typescript() {
        let scan = finding_scan();
        let upper = scan.to_uppercase();
        let reads: Vec<(Vec<&str>, &[&str])> = vec![
            (vec!["scans", "list"], &["pretty", "table", "json"]),
            (
                vec!["scans", "ls", "--limit", "3", "--offset", "2"],
                &["pretty", "json"],
            ),
            (vec!["scans", "list", "--all", "--limit", "5"], &["json"]),
            (
                vec![
                    "scans",
                    "list",
                    "--start",
                    "2026-10-01T00:00:00+02:00",
                    "--end",
                    "2026-10-30T00:00Z",
                    "--limit",
                    "007",
                ],
                &["json"],
            ),
            (
                vec!["scans", "list", "--all", "--max", "2", "--limit", "1"],
                &["json"],
            ),
            (
                vec!["scans", "vulnerabilities", scan.as_str()],
                &["pretty", "table", "json"],
            ),
            (vec!["scans", "vulnerabilities", upper.as_str()], &["json"]),
            (vec!["stats"], &["pretty", "table", "json"]),
            (vec!["rules", "list"], &["pretty", "json"]),
            (vec!["rules", "ls", "--all"], &["json"]),
            (
                vec!["rules", "list", "--all", "--offset", "5", "--max", "12"],
                &["table"],
            ),
        ];
        for (args, formats) in reads {
            for format in formats {
                let mut full = args.clone();
                full.extend(["--output", format]);
                let Some((r, t)) = sides("reads_match_typescript", &full, &plain) else {
                    return;
                };
                assert_same(&r, &t);
            }
        }
    }

    /// `null` metrics (TS `it.spec:116-128`), an empty first page with a larger total
    /// (choice 12), an offset past the total and an empty finding list: the same bytes.
    #[test]
    fn edge_documents_match_typescript() {
        let empty_findings = |data: &mut SupplychainData| {
            data.without_passthrough();
            data.findings.insert(fx::uuid(101), Vec::new());
        };
        let empty_page = |data: &mut SupplychainData| {
            data.scans.clear();
            data.scan_total = Some(5);
        };
        let scan = finding_scan();
        let cases: Vec<(Vec<&str>, &Seed)> = vec![
            (
                vec!["scans", "list", "--limit", "1", "--offset", "2"],
                &plain,
            ),
            (
                vec![
                    "scans", "list", "--limit", "1", "--offset", "2", "--output", "json",
                ],
                &plain,
            ),
            (
                vec!["scans", "list", "--offset", "50", "--output", "json"],
                &plain,
            ),
            (vec!["scans", "list", "--output", "json"], &empty_page),
            (vec!["scans", "list"], &empty_page),
            (
                vec!["scans", "vulnerabilities", scan.as_str()],
                &empty_findings,
            ),
            (
                vec![
                    "scans",
                    "vulnerabilities",
                    scan.as_str(),
                    "--output",
                    "json",
                ],
                &empty_findings,
            ),
        ];
        for (args, seed) in cases {
            let Some((r, t)) = sides("edge_documents_match_typescript", &args, seed) else {
                return;
            };
            assert_same(&r, &t);
        }
    }

    /// Failures (§20.3): TS's line with at most the status, empty stdout, the same request
    /// sequence (one GET, two after a 401 or 403, choice 3, G63), the page checks of §20.4.
    #[test]
    fn failures_match_typescript() {
        let secret = json!({"message": "PRIVATE-ECHO server text"});
        // A typed read's 2xx failing its schema (the scan list is G71's tolerant read:
        // `d324_`, `d325_`).
        let mut invalid = fx::stats();
        invalid.remove("unique_skills_scanned");
        let invalid_body = invalid.text();
        let rows = fx::scans();
        let cases: Vec<(Vec<&str>, Box<ServerPlan>, Option<u16>)> = vec![
            (
                vec!["scans", "list"],
                Box::new(move |server: &FixtureServer| {
                    server.set_default(
                        Route::Supplychain(Sc::Scans),
                        Planned::json(403, &json!({"message": "x"})),
                    )
                }),
                Some(403),
            ),
            (
                vec!["stats"],
                Box::new({
                    let secret = secret.clone();
                    move |server: &FixtureServer| {
                        server
                            .set_default(Route::Supplychain(Sc::Stats), Planned::json(500, &secret))
                    }
                }),
                Some(500),
            ),
            (
                vec!["rules", "list"],
                Box::new(|server: &FixtureServer| {
                    server.set_default(
                        Route::Supplychain(Sc::Rules),
                        Planned::json(429, &json!({})).with_retry_after(0),
                    )
                }),
                Some(429),
            ),
            (
                vec![
                    "scans",
                    "vulnerabilities",
                    "11111111-1111-4111-8111-000000000102",
                ],
                Box::new(|_: &FixtureServer| {}),
                Some(404),
            ),
            (
                vec!["scans", "list"],
                Box::new(|server: &FixtureServer| {
                    server.set_default(
                        Route::Supplychain(Sc::Scans),
                        Planned::raw(200, "application/json", "{\"scans\": [oops"),
                    )
                }),
                None,
            ),
            // An empty 2xx body: TS's line without a status on both (choice 83; the
            // tolerant read does not read it as `{}`).
            (
                vec!["scans", "list"],
                Box::new(|server: &FixtureServer| {
                    server.set_default(Route::Supplychain(Sc::Scans), Planned::status(200))
                }),
                None,
            ),
            (
                vec!["stats"],
                Box::new(move |server: &FixtureServer| {
                    server.set_default(
                        Route::Supplychain(Sc::Stats),
                        Planned::raw(200, "application/json", invalid_body.clone()),
                    )
                }),
                None,
            ),
            (
                vec!["scans", "list", "--all", "--limit", "1"],
                Box::new(move |server: &FixtureServer| {
                    let page = |rows: &[Wire], total| {
                        Planned::raw(200, "application/json", fx::scan_list_body(rows, total))
                    };
                    server.push_once(Route::Supplychain(Sc::Scans), page(&rows[..1], 12));
                    server.push_once(Route::Supplychain(Sc::Scans), page(&rows[..1], 12));
                }),
                None,
            ),
            (
                vec!["scans", "list", "--limit", "1"],
                Box::new(|server: &FixtureServer| {
                    server.push_once(
                        Route::Supplychain(Sc::Scans),
                        Planned::raw(
                            200,
                            "application/json",
                            fx::scan_list_body(&fx::scans()[..2], 12),
                        ),
                    )
                }),
                None,
            ),
            (
                vec!["stats"],
                Box::new(|server: &FixtureServer| {
                    server.set_default(Route::Token, Planned::json(401, &json!({})))
                }),
                Some(401),
            ),
        ];
        for (args, plan, status) in cases {
            let Some((r, t)) = sides_with("failures_match_typescript", &args, &unchanged, &*plan)
            else {
                return;
            };
            assert_eq!(r.run.code, 1, "{args:?}{}", context(&r, &t));
            assert_eq!(t.run.code, 1, "{args:?}{}", context(&r, &t));
            assert_eq!((r.run.stdout.as_str(), t.run.stdout.as_str()), ("", ""));
            assert_eq!(r.run.stderr, failure(status), "{args:?}");
            assert_eq!(t.run.stderr, failure(status), "{args:?}");
            assert_eq!(r.lines, t.lines, "{args:?}");
        }
        // A 401 once: token, GET(401), token, GET(200) on both sides, then the same data.
        let once = |server: &FixtureServer| {
            server.push_once(
                Route::Supplychain(Sc::Rules),
                Planned::json(401, &json!({})),
            );
        };
        let Some((r, t)) = sides_with(
            "failures_match_typescript",
            &["rules", "list", "--output", "json"],
            &plain,
            &once,
        ) else {
            return;
        };
        assert_same(&r, &t);
        assert_eq!(r.lines.len(), 4);
        // G63: a 403 with `x-opa-decision: false` is sent once by TypeScript; the CLI
        // cannot see the header and re-reads once (harmless for a read).
        let opa = |server: &FixtureServer| {
            server.set_default(
                Route::Supplychain(Sc::Stats),
                Planned::json(403, &json!({})).with_header("x-opa-decision", "false"),
            );
        };
        let Some((r, t)) = sides_with("failures_match_typescript", &["stats"], &unchanged, &opa)
        else {
            return;
        };
        assert_eq!(
            (r.run.stderr.clone(), t.run.stderr.clone()),
            (failure(Some(403)), failure(Some(403)))
        );
        let gets = |side: &Side| {
            side.lines
                .iter()
                .filter(|line| line.starts_with("GET"))
                .count()
        };
        assert_eq!((gets(&r), gets(&t)), (2, 1));
    }

    /// §20.2: every group's subcommands and every leaf's options and descriptions are
    /// TypeScript's (the TypeScript side under `agentguard`; `report` is chunk 2).
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let help = |cli: &Cli, path: &[&str]| {
            let mut args = vec![if cli.is_ts() {
                "agentguard"
            } else {
                "supplychain"
            }];
            args.extend_from_slice(path);
            args.push("--help");
            let out = run(cli, &sandbox, &args, &RunOptions::new());
            out.assert_success();
            out.stdout
        };
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let section = |text: &str, title: &str| -> Vec<String> {
            let mut lines = text.lines();
            if !lines.any(|line| line == title) {
                return Vec::new();
            }
            lines
                .take_while(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect()
        };
        let entries = |text: &str, title: &str| -> Vec<(String, String)> {
            let mut out: Vec<(String, String)> = Vec::new();
            for line in section(text, title) {
                let trimmed = line.trim_start();
                let indent = line.len() - trimmed.len();
                if indent <= 6 {
                    let (spec, description) = trimmed.split_once("  ").unwrap_or((trimmed, ""));
                    let name = spec
                        .split([',', ' '])
                        .find(|part| {
                            if title == "Options:" {
                                part.starts_with("--")
                            } else {
                                !part.is_empty()
                            }
                        })
                        .unwrap_or(spec);
                    let name = name.split('|').next().unwrap_or(name).to_owned();
                    out.push((name, squash(description)));
                } else if let Some((_, description)) = out.last_mut() {
                    *description = squash(&format!("{description} {trimmed}"));
                }
            }
            out
        };
        let mut problems = Vec::new();
        for path in [&[][..], &["scans"], &["rules"]] {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            // D155: the report's description drops `/Markdown`.
            let ts_subs: Vec<(String, String)> = entries(&t, "Commands:")
                .into_iter()
                .filter(|(name, _)| name != "help")
                .map(|(name, text)| (name, text.replace("HTML/Markdown", "HTML")))
                .collect();
            let rust_subs: Vec<(String, String)> = entries(&r, "Commands:")
                .into_iter()
                .filter(|(name, _)| name != "help")
                .map(|(name, text)| {
                    let text = text
                        .split(" [aliases:")
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    (name, text)
                })
                .collect();
            if ts_subs != rust_subs {
                problems.push(format!("{path:?}: {rust_subs:?} vs {ts_subs:?}"));
            }
            let ts_about = t.lines().nth(2).unwrap_or_default().to_owned();
            if !r.contains(&ts_about) {
                problems.push(format!("{path:?} description: {ts_about:?}"));
            }
        }
        for path in [
            &["scans", "list"][..],
            &["scans", "vulnerabilities"],
            &["stats"],
            &["rules", "list"],
        ] {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let rust_options = entries(&r, "Options:");
            for (flag, description) in entries(&t, "Options:") {
                if matches!(flag.as_str(), "--help" | "--output") {
                    continue;
                }
                match rust_options.iter().find(|(f, _)| *f == flag) {
                    Some((_, actual)) if *actual == description => {}
                    other => {
                        problems.push(format!("{path:?} {flag}: {other:?} vs {description:?}"))
                    }
                }
            }
            // §20.2 (choice 81): the leaf options in TypeScript's sorted order; the
            // global options (`--output`, `--quiet`, `--debug`, `--tenant`) and `--help`
            // are not leaf options.
            let leaf_order = |options: &[(String, String)]| -> Vec<String> {
                options
                    .iter()
                    .map(|(flag, _)| flag.clone())
                    .filter(|flag| {
                        !matches!(
                            flag.as_str(),
                            "--help" | "--output" | "--quiet" | "--debug" | "--tenant"
                        )
                    })
                    .collect()
            };
            let (rust_order, ts_order) = (
                leaf_order(&rust_options),
                leaf_order(&entries(&t, "Options:")),
            );
            if rust_order != ts_order {
                problems.push(format!("{path:?}: order {rust_order:?} vs {ts_order:?}"));
            }
            if rust_options.len() != entries(&t, "Options:").len() + 3 {
                problems.push(format!("{path:?}: options {rust_options:?}"));
            }
            let ts_about = t.lines().nth(2).unwrap_or_default().to_owned();
            if !r.contains(&ts_about) {
                problems.push(format!("{path:?} description: {ts_about:?}"));
            }
            let usage = t
                .lines()
                .next()
                .unwrap_or_default()
                .replace("Usage: airs-cli agentguard ", "Usage: airs supplychain ");
            let leaf = usage
                .split(['|', ' '])
                .nth(3)
                .unwrap_or_default()
                .to_owned();
            if !r.contains(&leaf) {
                problems.push(format!("{path:?} usage: {usage:?}"));
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
// Divergences (§12 rows of chunk 1)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D308: TypeScript's `agentguard` tree is `supplychain`, with no `agentguard` alias;
    /// the same data under the new name.
    #[test]
    fn d308_the_tree_is_supplychain_without_an_agentguard_alias() {
        let Some((r, t)) = sides("d308", &["scans", "list", "--output", "json"], &plain) else {
            return;
        };
        assert_same(&r, &t);
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let out = run(
            &rust(),
            &sandbox,
            &["agentguard", "scans", "list"],
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert!(out.stderr.contains("unrecognized subcommand 'agentguard'"));
        assert_eq!(server.request_count(), 0);
        // The request failure line keeps the API's name (§20.2).
        let fail = |server: &FixtureServer| {
            server.set_default(
                Route::Supplychain(Sc::Stats),
                Planned::json(500, &json!({})),
            );
        };
        let Some((r, t)) = sides_with("d308", &["stats"], &unchanged, &fail) else {
            return;
        };
        assert_eq!(r.run.stderr, t.run.stderr);
        assert!(
            r.run
                .stderr
                .contains("AgentGuard request failed (HTTP 500)")
        );
    }

    /// D313: the record-table status line names JSON only, and a truncated listing names
    /// the next offset; TypeScript names YAML and reads the same either way.
    #[test]
    fn d313_the_status_line_names_json_and_truncation() {
        let Some((r, t)) = sides("d313", &["rules", "list"], &plain) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout);
        assert_eq!(
            r.run.stderr,
            "  Returned 10 records; more are available (next --offset 10); see JSON for pagination metadata.\n"
        );
        assert_eq!(
            t.run.stderr,
            "  Returned 10 records; see JSON/YAML for pagination metadata.\n"
        );
        let Some((r, t)) = sides(
            "d313",
            &["scans", "vulnerabilities", &finding_scan()],
            &plain,
        ) else {
            return;
        };
        assert_eq!(
            r.run.stderr,
            "  Returned 3 records; see JSON for pagination metadata.\n"
        );
        assert_eq!(
            t.run.stderr,
            "  Returned 3 records; see JSON/YAML for pagination metadata.\n"
        );
    }

    /// D314: every argument check runs before the tenant with a flag-specific text; TS reads
    /// the tenant first and words most checks as one query error.
    #[test]
    fn d314_argument_checks_come_before_the_tenant() {
        let Some(ts) = require_ts("d314") else {
            return;
        };
        // No tenant: Rust names the flag (exit 2); TS fails on the tenant (exit 1).
        let sandbox = Sandbox::new();
        let r = run(
            &rust(),
            &sandbox,
            &["supplychain", "scans", "list", "--limit", "0"],
            &RunOptions::new(),
        );
        let t = run(
            &ts,
            &sandbox,
            &["agentguard", "scans", "list", "--limit", "0"],
            &RunOptions::new(),
        );
        assert_eq!(r.code, 2);
        assert_eq!(r.stderr, "\n  ✗ --limit must be a positive integer\n\n");
        assert_eq!(t.code, 1);
        assert!(t.stderr.contains("No tenant selected"), "{}", t.stderr);
        // With a tenant: both refuse before any request; TS's one query text.
        for (args, rust_text) in [
            (
                vec!["stats", "--time-period", "week"],
                "--time-period must be 30_DAYS (the only period the service supports)",
            ),
            (
                vec!["scans", "vulnerabilities", "../escape"],
                "Invalid scanUuid: ../escape (expected a UUID)",
            ),
            (
                vec!["scans", "list", "--start", "bad"],
                "--start must be an ISO-8601 timestamp with a timezone (for example 2026-10-01T00:00:00Z)",
            ),
        ] {
            let r = exec_with(&rust(), &args, &unchanged, &|_| {});
            let t = exec_with(&ts, &args, &unchanged, &|_| {});
            assert_eq!((r.run.code, t.run.code), (2, 2), "{args:?}");
            assert_eq!(r.run.stderr, format!("\n  ✗ {rust_text}\n\n"));
            assert_eq!(
                t.run.stderr,
                "\n  ✗ Invalid AgentGuard query. Check pagination, UUID and ISO timestamps; statistics support 30_DAYS only.\n\n"
            );
            assert!(r.lines.is_empty() && t.lines.is_empty(), "{args:?}");
        }
        // `--max-pages`-style parse text: TS words `--offset` as a pagination error.
        let r = exec_with(
            &rust(),
            &["rules", "list", "--offset", "-1"],
            &unchanged,
            &|_| {},
        );
        let t = exec_with(
            &ts,
            &["rules", "list", "--offset", "-1"],
            &unchanged,
            &|_| {},
        );
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --offset must be a non-negative integer\n\n"
        );
        assert!(
            t.run
                .stderr
                .contains("Pagination requires a safe nonnegative integer")
        );
        assert_eq!((r.run.code, t.run.code), (2, 2));
    }

    /// D315: `--max` takes decimal digits only; TS's `Number()` accepts `0x2`.
    #[test]
    fn d315_max_takes_decimal_digits_only() {
        let args = [
            "scans", "list", "--all", "--limit", "1", "--max", "0x2", "--output", "json",
        ];
        let Some((r, t)) = sides("d315", &args, &plain) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --max must be a safe nonnegative integer\n\n"
        );
        assert!(r.lines.is_empty());
        t.run.assert_success();
        assert_eq!(t.run.json()["pagination"]["returned"], 2);
    }

    /// D316: a missing credential keeps its own message; TS prints its request line.
    #[test]
    fn d316_credential_errors_keep_their_messages() {
        let Some(ts) = require_ts("d316") else {
            return;
        };
        let edit = |config: &mut FixtureConfig| {
            config.remove("mgmtClientSecret");
        };
        let r = exec_full(&rust(), &["stats"], &unchanged, &|_| {}, &edit);
        let t = exec_full(&ts, &["stats"], &unchanged, &|_| {}, &edit);
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert!(
            r.run.stderr.contains("mgmtClientSecret"),
            "{}",
            r.run.stderr
        );
        assert_eq!(t.run.stderr, failure(None));
        assert!(r.lines.is_empty() && t.lines.is_empty());
    }

    /// D317: `--max 0` has no item cap; TS stops after 1,000 pages and fails.
    #[test]
    fn d317_max_zero_walks_past_a_thousand_pages() {
        let seed = |data: &mut SupplychainData| {
            data.rules = (1..=1001).map(|n| fx::rule(1000 + n)).collect();
        };
        let args = [
            "rules", "list", "--all", "--limit", "1", "--max", "0", "--output", "json",
        ];
        let Some((r, t)) = sides("d317", &args, &seed) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(r.run.json()["pagination"]["returned"], 1001);
        assert_eq!(
            r.lines.len(),
            1 + 1002,
            "1,001 full pages and the empty one"
        );
        assert_eq!(t.run.code, 1);
        assert_eq!(t.run.stderr, failure(None));
        assert_eq!(t.lines.len(), 1 + 1000);
    }

    /// D318: an array the server adds to `stats` keeps the field table; TS shows only that
    /// array's record table.
    #[test]
    fn d318_stats_keeps_the_field_table() {
        let seed = |data: &mut SupplychainData| {
            let mut stats = fx::stats();
            stats.remove("zz_window");
            stats.remove("aa_generated_at");
            stats.set(
                "history",
                Wire::List(vec![obj(vec![("day", w(json!("d1"))), ("n", w(json!(1)))])]),
            );
            data.stats = Some(stats);
        };
        let Some((r, t)) = sides("d318", &["stats", "--output", "table"], &seed) else {
            return;
        };
        assert_eq!(t.run.stdout, " day │ n \n─────┼───\n d1  │ 1 \n");
        assert_eq!(
            t.run.stderr,
            "  Returned 1 records; see JSON/YAML for pagination metadata.\n"
        );
        assert!(r.run.stdout.starts_with(" Field "), "{}", r.run.stdout);
        assert!(
            r.run
                .stdout
                .contains(" unique_skills_scanned       │ {\"count\":4,\"percent_change\":12.5} ")
        );
        assert!(
            r.run
                .stdout
                .contains(" history                     │ [{\"day\":\"d1\",\"n\":1}] ")
        );
        assert_eq!(r.run.stderr, "");
    }

    /// D319: a finding list shorter than its `total_items` prints its rows and fails with a
    /// named line; TS prints the rows silently, exit 0.
    #[test]
    fn d319_a_short_finding_list_fails_closed() {
        let seed = |data: &mut SupplychainData| {
            data.without_passthrough();
            data.finding_total = Some(5);
        };
        let scan = finding_scan();
        let Some((r, t)) = sides(
            "d319",
            &["scans", "vulnerabilities", &scan, "--output", "json"],
            &seed,
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout, "the same rows");
        assert_eq!((r.run.code, t.run.code), (1, 0));
        assert_eq!(
            r.run.stderr,
            format!(
                "  ✗ The service returned 3 of 5 findings for scan {scan}; the list is incomplete (the API offers no paging)\n"
            )
        );
        assert_eq!(t.run.stderr, "");
    }

    /// D320: an answer over 32 MiB fails with its own line; TS reads it whole.
    #[test]
    fn d320_answers_over_32_mib_fail() {
        let seed = |data: &mut SupplychainData| data.oversized_findings = true;
        let scan = finding_scan();
        let Some((r, t)) = sides(
            "d320",
            &["scans", "vulnerabilities", &scan, "--output", "json"],
            &seed,
        ) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert_eq!(r.run.stdout, "");
        assert_eq!(
            r.run.stderr,
            "  ✗ AgentGuard response was larger than 32 MiB; nothing was printed. No upstream body is included.\n"
        );
        t.run.assert_success();
        assert_eq!(t.run.json()["vulnerabilities"][0]["uuid"], fx::uuid(399));
    }

    /// D321: `--include-content` prints the same content and, in Rust, a sensitivity notice
    /// on stderr.
    #[test]
    fn d321_include_content_prints_a_notice() {
        let scan = finding_scan();
        let Some((r, t)) = sides(
            "d321",
            &[
                "scans",
                "vulnerabilities",
                &scan,
                "--include-content",
                "--output",
                "table",
            ],
            &plain,
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout);
        assert!(r.run.stdout.contains("PRIVATE-TITLE-301"));
        assert_eq!(
            r.run.stderr,
            "  Returned 3 records; see JSON for pagination metadata.\n  Finding content included: source code, file paths and finding text can contain secrets from the scanned artifacts; keep this output private.\n"
        );
        assert_eq!(
            t.run.stderr,
            "  Returned 3 records; see JSON/YAML for pagination metadata.\n"
        );
    }

    /// D323: an interrupted read prints its context; TS dies by the signal silently.
    #[test]
    fn d323_an_interrupted_read_prints_its_context() {
        let Some(ts) = require_ts("d323") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_supplychain();
            server.push_once(Route::Supplychain(Sc::Scans), Planned::hang());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let name = if cli.is_ts() {
                "agentguard"
            } else {
                "supplychain"
            };
            let running = spawn(
                &cli,
                &sandbox,
                &[name, "scans", "list"],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Supplychain(Sc::Scans),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal("INT");
            outs.push(running.wait());
        }
        assert_eq!(outs[0].code, 130);
        assert_eq!(
            outs[0].stderr,
            "\n  ✗ Error: Interrupted; no data was written\n\n"
        );
        assert_eq!(outs[1].code, 130);
        assert_eq!(outs[1].stderr, "");
        assert_eq!((outs[0].stdout.as_str(), outs[1].stdout.as_str()), ("", ""));
    }

    /// D324 (G71): scan rows with the `null`s the service sends (the observed
    /// `"fingerprint": null`, every member the tolerant read accepts as `null`) are printed
    /// by airs-cli-rs in every format; TypeScript's zod schema refuses the whole answer with
    /// its generic line. The same GET on both sides; the rows the SDK accepts print as
    /// before.
    #[test]
    fn d324_scan_rows_with_nulls_are_printed() {
        let seed = |data: &mut SupplychainData| {
            let ordinary = data.scans[1].clone();
            data.scans = fx::null_scans();
            data.scans.push(ordinary);
        };
        for format in ["json", "pretty", "table"] {
            let Some((r, t)) = sides("d324", &["scans", "list", "--output", format], &seed) else {
                return;
            };
            r.run.assert_success();
            assert!(!r.run.stdout.contains(fx::MARKER), "{format}");
            assert!(r.run.stdout.contains("000000000113"), "{format}");
            assert_eq!(t.run.code, 1, "{format}");
            assert_eq!(
                (t.run.stdout.as_str(), t.run.stderr.clone()),
                ("", failure(None))
            );
            assert_eq!(r.lines, t.lines, "{format}: the same requests");
            if format == "json" {
                let scans = r.run.json()["scans"].clone();
                assert_eq!(scans.as_array().unwrap().len(), 4);
                assert_eq!(scans[1]["artifact_type"], serde_json::Value::Null);
                assert_eq!(scans[2]["vulnerability_count"], serde_json::Value::Null);
            }
        }
        // Only the observed row: TypeScript still refuses it.
        let observed = |data: &mut SupplychainData| data.scans = fx::null_scans()[..1].to_vec();
        let Some((r, t)) = sides("d324", &["scans", "list", "--output", "json"], &observed) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(r.run.json()["scans"][0]["uuid"], fx::uuid(113));
        assert_eq!(t.run.stderr, failure(None));
    }

    /// D325: an answer the tolerant read still refuses (here a scan without a `uuid`) is
    /// the contract line in airs-cli-rs; TypeScript prints its generic request line. Both
    /// print nothing on stdout and exit 1; no server text on either side.
    #[test]
    fn d325_contract_failures_name_the_contract() {
        let seed = |data: &mut SupplychainData| data.scans[1].remove("uuid");
        let Some((r, t)) = sides("d325", &["scans", "list"], &seed) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!((r.run.stdout.as_str(), t.run.stdout.as_str()), ("", ""));
        assert_eq!(
            r.run.stderr,
            "  ✗ The AgentGuard answer does not match the API contract; nothing was printed. No upstream body is included.\n"
        );
        assert_eq!(t.run.stderr, failure(None));
        assert_eq!(r.lines, t.lines);
    }

    /// D1 extended: a bare group exits 2 with its help on stderr; TS exits 1.
    #[test]
    fn d1_supplychain_groups_and_parse_errors() {
        for (args, rust_line) in [
            (vec![], "Usage: airs supplychain [OPTIONS] [COMMAND]"),
            (
                vec!["scans"],
                "Usage: airs supplychain scans [OPTIONS] [COMMAND]",
            ),
            (
                vec!["scans", "list", "--bogus"],
                "unexpected argument '--bogus'",
            ),
            (vec!["scans", "vulnerabilities"], "<scanUuid>"),
        ] {
            let Some((r, t)) = sides("d1", &args, &unchanged) else {
                return;
            };
            assert_eq!((r.run.code, t.run.code), (2, 1), "{args:?}");
            assert!(
                r.run.stderr.contains(rust_line),
                "{args:?}: {}",
                r.run.stderr
            );
            assert!(r.lines.is_empty() && t.lines.is_empty());
        }
    }

    /// D30 extended (G65): a 3xx is never followed; TS follows it with `x-tsg-id` (and the
    /// bearer, to the same origin).
    #[test]
    fn d30_supplychain_redirects_are_not_followed() {
        let Some(ts) = require_ts("d30") else {
            return;
        };
        let mut seen = Vec::new();
        for cli in [rust(), ts.clone()] {
            let other = FixtureServer::start();
            let target = other.url("/elsewhere");
            let plan = move |server: &FixtureServer| {
                server.set_default(
                    Route::Supplychain(Sc::Stats),
                    Planned::redirect(302, &target),
                );
            };
            let side = exec_with(&cli, &["stats"], &unchanged, &plan);
            seen.push((side.run.code, side.run.stderr.clone(), other.requests()));
        }
        assert_eq!(seen[0].0, 1);
        assert_eq!(seen[0].1, failure(None));
        assert!(seen[0].2.is_empty(), "Rust never contacts the target");
        assert_eq!(seen[1].0, 1);
        assert_eq!(seen[1].1, failure(Some(404)));
        assert_eq!(seen[1].2.len(), 1, "TS follows the redirect");
        assert_eq!(
            seen[1].2[0].header("x-tsg-id"),
            Some(TSG),
            "TS forwards x-tsg-id"
        );
        // To the same origin TS forwards the bearer too; Rust sends one GET only.
        for cli in [rust(), ts] {
            let plan = |server: &FixtureServer| {
                server.set_default(
                    Route::Supplychain(Sc::Stats),
                    Planned::redirect(302, &server.url("/elsewhere")),
                );
            };
            let side = exec_with(&cli, &["stats"], &unchanged, &plan);
            let followed: Vec<&NormalizedRequest> = side
                .requests
                .iter()
                .filter(|request| request.route == Route::Unknown)
                .collect();
            if cli.is_ts() {
                assert_eq!(followed.len(), 1);
                assert_eq!(
                    followed[0].auth,
                    airs_test_harness::AuthIdentity::Bearer {
                        tsg: Some(TSG.into())
                    },
                    "TS forwards the bearer"
                );
            } else {
                assert!(followed.is_empty());
                assert_eq!(side.lines.len(), 2);
            }
        }
    }

    /// D35 extended (G64): passthrough members print after the known keys, sorted; TS keeps
    /// the server's order (JSON otherwise equal, the rules table columns and the stats rows
    /// in that order).
    #[test]
    fn d35_passthrough_members_are_sorted() {
        let Some((r, t)) = sides("d35", &["rules", "list", "--output", "json"], &unchanged) else {
            return;
        };
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        assert!(
            r.run
                .stdout
                .contains("\"aa_added\": true,\n      \"zz_added\": \"catalog-v2\"")
        );
        assert!(
            t.run
                .stdout
                .contains("\"zz_added\": \"catalog-v2\",\n      \"aa_added\": true")
        );
        let Some((r, t)) = sides("d35", &["rules", "list", "--output", "table"], &unchanged) else {
            return;
        };
        assert!(
            r.run
                .stdout
                .lines()
                .next()
                .unwrap()
                .ends_with("│ aa added │ zz added   ")
        );
        assert!(
            t.run
                .stdout
                .lines()
                .next()
                .unwrap()
                .ends_with("│ zz added   │ aa added ")
        );
        let Some((r, t)) = sides("d35", &["stats", "--output", "table"], &unchanged) else {
            return;
        };
        let rows = |side: &Side| -> Vec<String> {
            side.run
                .stdout
                .lines()
                .skip(5)
                .map(|line| line.split('│').next().unwrap().trim().to_owned())
                .collect()
        };
        assert_eq!(rows(&r), ["aa_generated_at", "zz_window"]);
        assert_eq!(rows(&t), ["zz_window", "aa_generated_at"]);
        let scan = finding_scan();
        let Some((r, t)) = sides(
            "d35",
            &["scans", "vulnerabilities", &scan, "--output", "json"],
            &unchanged,
        ) else {
            return;
        };
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        assert!(
            r.run
                .stdout
                .contains("\"total_items\": 3,\n    \"aa_page_hint\": 1,\n    \"zz_cursor\": null")
        );
        assert!(
            t.run
                .stdout
                .contains("\"total_items\": 3,\n    \"zz_cursor\": null,\n    \"aa_page_hint\": 1")
        );
    }

    /// D47 extended: a copy of the tenant's own secret in a finding or a rule prints as
    /// `[withheld]`; TS prints it.
    #[test]
    fn d47_echoed_credentials_are_withheld() {
        let seed = |data: &mut SupplychainData| {
            data.without_passthrough();
            data.rules[0].set("description", json!("echo FAKE-SECRET-100"));
        };
        let Some((r, t)) = sides("d47", &["rules", "list", "--output", "json"], &seed) else {
            return;
        };
        assert_eq!(r.run.json()["rules"][0]["description"], "[withheld]");
        assert_eq!(
            t.run.json()["rules"][0]["description"],
            "echo FAKE-SECRET-100"
        );
        assert_eq!(
            r.run.json()["rules"][1],
            t.run.json()["rules"][1],
            "ordinary rules unchanged"
        );
    }

    /// D50 extended: `markdown`, `csv` and `yaml` are usage errors; TS renders them.
    #[test]
    fn d50_dropped_formats_are_usage_errors_on_supplychain_reads() {
        for format in ["yaml", "csv", "markdown"] {
            let Some((r, t)) = sides("d50", &["stats", "--output", format], &plain) else {
                return;
            };
            assert_eq!(r.run.code, 2);
            assert_eq!(
                r.run.stderr,
                format!(
                    "\n  ✗ Invalid output format '{format}'. Expected: pretty, table, json\n\n"
                )
            );
            assert!(r.lines.is_empty());
            t.run.assert_success();
            assert!(!t.run.stdout.is_empty());
        }
    }

    /// D52 extended: control characters in table cells become U+FFFD; TS writes them raw.
    #[test]
    fn d52_supplychain_control_characters_are_replaced() {
        let seed = |data: &mut SupplychainData| {
            data.without_passthrough();
            data.scans.truncate(1);
            data.scans[0].set("artifact_type", json!("SK\u{1b}[31mILL\nX"));
        };
        let Some((r, t)) = sides("d52", &["scans", "list", "--output", "table"], &seed) else {
            return;
        };
        assert!(r.run.stdout.contains("SK\u{fffd}[31mILL\u{fffd}X"));
        assert!(t.run.stdout.contains("SK\u{1b}[31mILL\nX"));
    }

    /// D53 extended: tables pad by display width; TS pads by UTF-16 units.
    #[test]
    fn d53_supplychain_tables_pad_by_display_width() {
        let seed = |data: &mut SupplychainData| {
            data.without_passthrough();
            data.scans.truncate(2);
            data.scans[0].set("artifact_type", json!("技能"));
        };
        let Some((r, t)) = sides("d53", &["scans", "list", "--output", "table"], &seed) else {
            return;
        };
        let cell = |side: &Side, row: usize| -> String {
            side.run
                .stdout
                .lines()
                .nth(row)
                .unwrap()
                .split('│')
                .nth(1)
                .unwrap()
                .to_owned()
        };
        assert_eq!(cell(&r, 2), " 技能          ");
        assert_eq!(cell(&r, 3), " AGENT         ");
        assert_eq!(cell(&t, 2), " 技能            ");
        assert_eq!(cell(&t, 3), " AGENT         ");
    }

    /// D64 extended: Rust's log holds status and headers under the SDK operation names, no
    /// query; TS writes its log in the working directory (empty for loopback hosts).
    #[test]
    fn d64_supplychain_debug_logs_hold_no_query() {
        let Some(ts) = require_ts("d64") else {
            return;
        };
        let server = FixtureServer::start();
        server.seed_supplychain();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let state = debug_log::xdg_state_home(&sandbox).display().to_string();
        let options = RunOptions::new().env("XDG_STATE_HOME", &state);
        run(
            &rust(),
            &sandbox,
            &["--debug", "supplychain", "scans", "list"],
            &options,
        )
        .assert_success();
        let (_, records) = debug_log::only_log(&sandbox);
        let names: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(names, ["oauth.token", "airs.agentguard.list_scans"]);
        let text = serde_json::to_string(&records).unwrap();
        assert!(!text.contains("skip=") && !text.contains("isBackgroundRefresh"));
        let out = run(
            &ts,
            &sandbox,
            &["--debug", "agentguard", "scans", "list"],
            &RunOptions::new()
                .allow_secret_output()
                .allow_writes_under("cwd"),
        );
        out.assert_success();
        let logs = debug_log::log_files(&sandbox.cwd());
        assert_eq!(logs.len(), 1, "{logs:?}");
        assert_eq!(
            std::fs::read(&logs[0]).unwrap(),
            b"",
            "TS logs nothing for loopback"
        );
    }

    /// D212 extended: C1 controls in a supplychain JSON document are `\u00XX`; TS writes
    /// them raw (the JSON is otherwise the same document).
    #[test]
    fn d212_c1_controls_are_escaped_in_supplychain_json() {
        let scan = finding_scan();
        let Some((r, t)) = sides(
            "d212",
            &[
                "scans",
                "vulnerabilities",
                &scan,
                "--include-content",
                "--output",
                "json",
            ],
            &plain,
        ) else {
            return;
        };
        assert!(r.run.stdout.contains("'ü 日本'}\\u0085\\n"));
        assert!(t.run.stdout.contains("'ü 日本'}\u{85}\\n"));
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
    }

    /// The transport failure line (no status) on both sides.
    #[test]
    fn a_closed_port_prints_the_request_line_on_both_sides() {
        let port = ClosedPort::new();
        let Some(ts) = require_ts("closed_port") else {
            return;
        };
        let edit = |config: &mut FixtureConfig| {
            config.set(
                "agentGuardMgmtEndpoint",
                format!("http://127.0.0.1:{}/agentguard/mgmt", port.port()),
            );
        };
        let r = exec_full(&rust(), &["rules", "list"], &unchanged, &|_| {}, &edit);
        let t = exec_full(&ts, &["rules", "list"], &unchanged, &|_| {}, &edit);
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(r.run.stderr, failure(None));
        assert_eq!(t.run.stderr, failure(None));
    }
}
