//! TS-vs-Rust parity for the M6c step-1 model-security reads (DESIGN §17.1–§17.7).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh [`FixtureServer`] seeded with the model-security dataset
//! and a fresh [`Sandbox`] whose tenant points every endpoint at the server (the
//! TypeScript client passes `modelSecDataEndpoint` and `modelSecMgmtEndpoint` explicitly
//! and reads no environment fallback, MS§0). `parity` tests compare exit codes, stdout
//! bytes (pretty and table) or JSON (json), stderr and the normalised requests.
//! `divergence` tests pin both sides of each §12 row this step implements (named by its
//! D#). The TypeScript side prints the fixture markers raw (D191), so its runs disable the
//! marker check; the airs-cli-rs runs keep it.

use airs_test_harness::fixtures::modelsec as fx;
use airs_test_harness::{
    Cli, FixtureServer, ModelSecData, Ms, NormalizedRequest, Planned, Route, Run, RunOptions,
    Sandbox, assert_json_semantic_eq, normalize_all, require_ts, run, spawn,
};
use serde_json::{Value, json};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn u(n: u64) -> String {
    fx::uuid(n)
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    lines: Vec<String>,
}

/// Runs `cli` (`model-security <args>`) on a fresh seeded server and sandbox; `seed`
/// edits the dataset; `plan` queues planned answers before the run.
fn exec_with(
    cli: &Cli,
    args: &[&str],
    seed: &dyn Fn(&mut ModelSecData),
    plan: &dyn Fn(&FixtureServer),
    options: &RunOptions,
) -> Side {
    let server = FixtureServer::start();
    server.seed_modelsec();
    server.modelsec(|data| seed(data));
    plan(&server);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    let mut full = vec!["model-security"];
    full.extend_from_slice(args);
    let options = if cli.is_ts() {
        options.clone().allow_secret_output()
    } else {
        options.clone()
    };
    let out = run(cli, &sandbox, &full, &options);
    let raw = server.requests();
    Side {
        run: out,
        requests: normalize_all(&raw),
        lines: raw.iter().map(|request| request.line()).collect(),
    }
}

fn exec(cli: &Cli, args: &[&str], seed: &dyn Fn(&mut ModelSecData)) -> Side {
    exec_with(cli, args, seed, &|_| {}, &RunOptions::new())
}

fn unchanged(_: &mut ModelSecData) {}

/// Both sides (`None` after a `PARITY SKIPPED` notice).
fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_seeded(name, args, &unchanged)
}

fn sides_seeded(
    name: &str,
    args: &[&str],
    seed: &dyn Fn(&mut ModelSecData),
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((exec(&rust(), args, seed), exec(&ts, args, seed)))
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// Byte parity: exit code, stdout, stderr and the requests.
fn assert_bytes(r: &Side, t: &Side) {
    assert_eq!(r.run.code, t.run.code, "exit codes differ{}", context(r, t));
    assert_eq!(
        r.run.stdout,
        t.run.stdout,
        "stdout differs{}",
        context(r, t)
    );
    assert_eq!(
        r.run.stderr,
        t.run.stderr,
        "stderr differs{}",
        context(r, t)
    );
    assert_eq!(r.requests, t.requests, "requests differ{}", context(r, t));
}

/// The API requests of a side (the token request left out).
fn api(side: &Side) -> Vec<String> {
    side.lines
        .iter()
        .filter(|line| !line.starts_with("POST /oauth/token"))
        .cloned()
        .collect()
}

/// D180: what TypeScript invents for a record the server sent without it (a scan's
/// `labels: []`, a file's `formats: []`, a rule instance's `fieldValues: {}`), added to
/// the Rust document so the rest compares.
fn ts_invented(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(ts_invented),
        Value::Object(map) => {
            if map.contains_key("evalOutcome") && !map.contains_key("labels") {
                map.insert("labels".to_owned(), json!([]));
            }
            if map.contains_key("result")
                && map.contains_key("path")
                && !map.contains_key("formats")
            {
                map.insert("formats".to_owned(), json!([]));
            }
            if map.contains_key("securityGroupUuid") && !map.contains_key("fieldValues") {
                map.insert("fieldValues".to_owned(), json!({}));
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The pretty layouts are the TypeScript bytes (requests included) wherever no §12
    /// row applies (MS§5–§10).
    #[test]
    fn pretty_layouts_match_typescript_byte_for_byte() {
        let (g, ri1, ri2, r1, r2) = (u(1), u(301), u(302), u(201), u(202));
        let (s, e, v, m1, m2, mv) = (u(401), u(501), u(601), u(801), u(802), u(901));
        for args in [
            vec!["groups", "list"],
            vec!["groups", "get", &g],
            vec!["rules", "list"],
            vec!["rules", "get", &r1],
            vec!["rules", "get", &r2],
            vec!["rule-instances", "list", &g],
            vec!["rule-instances", "get", &g, &ri1],
            vec!["rule-instances", "get", &g, &ri2],
            vec!["scans", "list"],
            vec!["scans", "get", &s],
            vec!["scans", "evaluations", &s],
            vec!["scans", "evaluation", &e],
            vec!["scans", "violations", &s],
            vec!["scans", "violation", &v],
            vec!["scans", "files", &s],
            vec!["models", "list"],
            vec!["models", "get", &m1],
            vec!["models", "get", &m2],
            vec!["models", "versions", &m1],
            vec!["models", "version", &mv],
            vec!["models", "files", &mv],
            vec!["labels", "keys"],
            vec!["labels", "values", "env"],
        ] {
            let Some((r, t)) = sides("pretty_layouts_match_typescript_byte_for_byte", &args) else {
                return;
            };
            assert!(r.run.stdout.starts_with(BANNER), "{args:?}");
            assert_bytes(&r, &t);
        }
    }

    /// Forced colour on both sides (`CLICOLOR_FORCE` for Rust, `FORCE_COLOR` for TS): the
    /// TS spans of every pretty list and get (the dim id lines, the state and outcome
    /// colours, the bold headings) byte for byte.
    #[test]
    fn forced_colour_matches_typescript() {
        let Some(ts) = require_ts("forced_colour_matches_typescript") else {
            return;
        };
        let (g, ri1, ri2, r1, r2) = (u(1), u(301), u(302), u(201), u(202));
        let (s, e, v, m1, m2, mv) = (u(401), u(501), u(601), u(801), u(802), u(901));
        for args in [
            vec!["groups", "list"],
            vec!["groups", "get", &g],
            vec!["rules", "list"],
            vec!["rules", "get", &r1],
            vec!["rules", "get", &r2],
            vec!["rule-instances", "list", &g],
            vec!["rule-instances", "get", &g, &ri1],
            vec!["rule-instances", "get", &g, &ri2],
            vec!["scans", "list"],
            vec!["scans", "get", &s],
            vec!["scans", "evaluations", &s],
            vec!["scans", "evaluation", &e],
            vec!["scans", "violations", &s],
            vec!["scans", "violation", &v],
            vec!["scans", "files", &s],
            vec!["models", "list"],
            vec!["models", "get", &m1],
            vec!["models", "get", &m2],
            vec!["models", "versions", &m1],
            vec!["models", "version", &mv],
            vec!["models", "files", &mv],
            vec!["labels", "keys"],
            vec!["labels", "values", "env"],
        ] {
            let colour = RunOptions::new().without_env("NO_COLOR");
            let r = exec_with(
                &rust(),
                &args,
                &unchanged,
                &|_| {},
                &colour.clone().env("CLICOLOR_FORCE", "1"),
            );
            let t = exec_with(
                &ts,
                &args,
                &unchanged,
                &|_| {},
                &colour.env("FORCE_COLOR", "1"),
            );
            assert_bytes(&r, &t);
            assert!(r.run.stdout.contains("\u{1b}["), "{args:?}: no colour");
        }
    }

    /// `--quiet` drops the banner and the section headings on both sides; the empty-list
    /// phrases are data on both.
    #[test]
    fn empty_lists_match_typescript() {
        let empty = |data: &mut ModelSecData| *data = ModelSecData::default();
        let (g, s, m, mv) = (u(1), u(401), u(801), u(901));
        for args in [
            vec!["groups", "list"],
            vec!["rules", "list"],
            vec!["scans", "list"],
            vec!["scans", "evaluations", &s],
            vec!["scans", "violations", &s],
            vec!["scans", "files", &s],
            vec!["models", "list"],
            vec!["models", "versions", &m],
            vec!["models", "files", &mv],
            vec!["labels", "keys"],
            vec!["labels", "values", "env"],
            vec!["groups", "list", "--output", "json"],
        ] {
            let Some((r, t)) = sides_seeded("empty_lists_match_typescript", &args, &empty) else {
                return;
            };
            assert_bytes(&r, &t);
        }
        let groups_only = |data: &mut ModelSecData| {
            *data = ModelSecData::seeded();
            data.rule_instances.clear();
        };
        let Some((r, t)) = sides_seeded(
            "empty_lists_match_typescript",
            &["rule-instances", "list", &g],
            &groups_only,
        ) else {
            return;
        };
        assert_bytes(&r, &t);
    }

    /// The TypeScript tables of the class A lists and the `Key │ Value` details.
    #[test]
    fn table_layouts_match_typescript() {
        let (g, ri, s, m, mv, r1) = (u(1), u(302), u(401), u(801), u(901), u(201));
        for args in [
            vec!["groups", "list", "--output", "table"],
            vec!["groups", "get", &g, "--output", "table"],
            vec!["rules", "list", "--output", "table"],
            vec!["rules", "get", &r1, "--output", "table"],
            vec!["rule-instances", "list", &g, "--output", "table"],
            vec!["rule-instances", "get", &g, &ri, "--output", "table"],
            vec!["scans", "list", "--output", "table"],
            vec!["scans", "get", &s, "--output", "table"],
            vec!["models", "list", "--output", "table"],
            vec!["models", "get", &m, "--output", "table"],
            vec!["models", "versions", &m, "--output", "table"],
            vec!["models", "version", &mv, "--output", "table"],
            vec!["models", "files", &mv, "--output", "table"],
        ] {
            let Some((r, t)) = sides("table_layouts_match_typescript", &args) else {
                return;
            };
            assert_bytes(&r, &t);
        }
    }

    /// The JSON documents of the class A reads (`modelsecurity-groupdetail-output.spec.ts`:
    /// the full projection, a bare array for lists), with the D180 tolerance applied.
    #[test]
    fn json_documents_match_typescript() {
        let (g, ri1, ri2, s, m1, m2, mv1, mv2, r1) = (
            u(1),
            u(301),
            u(302),
            u(401),
            u(801),
            u(802),
            u(901),
            u(902),
            u(201),
        );
        for args in [
            vec!["groups", "list", "--output", "json"],
            vec!["groups", "get", &g, "--output", "json"],
            vec!["rules", "list", "--output", "json"],
            vec!["rules", "get", &r1, "--output", "json"],
            vec!["rule-instances", "list", &g, "--output", "json"],
            vec!["rule-instances", "get", &g, &ri1, "--output", "json"],
            vec!["rule-instances", "get", &g, &ri2, "--output", "json"],
            vec!["scans", "list", "--output", "json"],
            vec!["scans", "get", &s, "--output", "json"],
            vec!["models", "list", "--output", "json"],
            vec!["models", "get", &m1, "--output", "json"],
            vec!["models", "get", &m2, "--output", "json"],
            vec!["models", "versions", &m1, "--output", "json"],
            vec!["models", "version", &mv1, "--output", "json"],
            vec!["models", "version", &mv2, "--output", "json"],
            vec!["models", "files", &mv1, "--output", "json"],
        ] {
            let Some((r, t)) = sides("json_documents_match_typescript", &args) else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{}", context(&r, &t));
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            let mut rust_json = r.run.json();
            ts_invented(&mut rust_json);
            assert_json_semantic_eq(&rust_json, &t.run.json());
            assert_eq!(r.run.stderr, t.run.stderr, "{}", context(&r, &t));
            assert_eq!(r.requests, t.requests, "{}", context(&r, &t));
        }
    }

    /// The request shapes of every list (`unit/airs/modelsecurity.spec.ts`): skip and
    /// limit as TypeScript sends them, the filters in the SDK order, the comma lists
    /// split and trimmed, the single-value scan filters as one-element arrays, unset model
    /// filters omitted.
    #[test]
    fn filters_and_paging_send_the_typescript_requests() {
        let (g, s, m, mv) = (u(1), u(401), u(801), u(901));
        let rule = u(201);
        let version = u(901);
        for args in [
            vec![
                "groups",
                "list",
                "--source-types",
                "LOCAL, S3",
                "--search",
                "Default",
                "--sort-field",
                "created_at",
                "--sort-dir",
                "desc",
                "--enabled-rules",
                &rule,
                "--limit",
                "5",
                "--offset",
                "1",
                "--output",
                "json",
            ],
            vec![
                "rules",
                "list",
                "--source-type",
                "LOCAL",
                "--search",
                "Load",
                "--limit",
                "1",
                "--output",
                "json",
            ],
            vec![
                "rule-instances",
                "list",
                &g,
                "--security-rule-uuid",
                &rule,
                "--state",
                "BLOCKING",
                "--limit",
                "5",
                "--output",
                "json",
            ],
            vec![
                "scans",
                "list",
                "--model-version",
                &version,
                "--eval-outcome",
                "BLOCKED",
                "--source-type",
                "LOCAL",
                "--search",
                "s1",
                "--start",
                "2026-01-01T00:00:00Z",
                "--end",
                "2026-02-01T00:00:00+01:00",
                "--limit",
                "2",
                "--offset",
                "1",
                "--output",
                "json",
            ],
            vec!["scans", "evaluations", &s, "--limit", "1"],
            vec!["scans", "violations", &s, "--limit", "1"],
            vec![
                "scans", "files", &s, "--type", "FILE", "--result", "FAILED", "--limit", "5",
            ],
            vec!["models", "list", "--output", "json"],
            vec![
                "models",
                "list",
                "--search",
                "a",
                "--search-query",
                "b",
                "--sort-field",
                "created_at",
                "--sort-order",
                "desc",
                "--limit",
                "1",
                "--offset",
                "1",
                "--start",
                "2026-01-01T00:00:00Z",
                "--end",
                "2026-02-01T00:00:00Z",
                "--output",
                "json",
            ],
            vec![
                "models",
                "versions",
                &m,
                "--sort-order",
                "asc",
                "--limit",
                "1",
                "--offset",
                "0",
                "--output",
                "json",
            ],
            vec![
                "models", "files", &mv, "--limit", "2", "--offset", "1", "--output", "json",
            ],
            vec!["labels", "keys", "--limit", "5"],
            vec!["labels", "values", "a/b c?d", "--limit", "5"],
        ] {
            let Some((r, t)) = sides("filters_and_paging_send_the_typescript_requests", &args)
            else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{}", context(&r, &t));
            assert_eq!(api(&r), api(&t), "{}", context(&r, &t));
        }
    }

    /// `--all` walks from `skip=0` with `--limit` as the page size (TS `collectSkipPages`).
    #[test]
    fn walks_send_the_typescript_requests() {
        let seed = |data: &mut ModelSecData| {
            data.groups = (1..=5)
                .map(|n| fx::group(n, &format!("group {n}"), "", "LOCAL", "ACTIVE"))
                .collect();
            data.models = (801..=805)
                .map(|n| json!({"uuid": u(n), "tsg_id": TSG, "created_at": fx::AT, "updated_at": fx::AT, "name": format!("model {n}")}))
                .collect();
        };
        for args in [
            vec![
                "groups", "list", "--all", "--limit", "2", "--output", "json",
            ],
            vec!["groups", "list", "--all", "--output", "json"],
            vec!["rules", "list", "--all", "--limit", "1", "--output", "json"],
            vec![
                "scans", "list", "--all", "--limit", "1", "--search", "x", "--output", "json",
            ],
            vec!["models", "list", "--all", "--output", "json"],
            vec![
                "models", "list", "--all", "--limit", "2", "--output", "json",
            ],
        ] {
            let Some((r, t)) = sides_seeded("walks_send_the_typescript_requests", &args, &seed)
            else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{}", context(&r, &t));
            assert_eq!(api(&r), api(&t), "{}", context(&r, &t));
            let mut rust_json = r.run.json();
            ts_invented(&mut rust_json);
            assert_json_semantic_eq(&rust_json, &t.run.json());
        }
    }

    /// A 404 fails both reads with exit 1 and the HTTP line, stdout empty on the Rust
    /// side (TS leaves its banner, D190).
    #[test]
    fn http_errors_exit_1_with_the_status() {
        let missing = u(99);
        let Some((r, t)) = sides(
            "http_errors_exit_1_with_the_status",
            &["groups", "get", &missing, "--output", "json"],
        ) else {
            return;
        };
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert_eq!(r.run.http_status(), Some(404));
        assert_eq!(t.run.http_status(), Some(404));
        assert_eq!(r.run.stdout, "");
        assert_eq!(t.run.stdout, "");
    }

    /// The tenant's `defaultOutput` applies to the class A reads on both sides.
    #[test]
    fn default_output_applies_to_class_a_reads() {
        let ts = match require_ts("default_output_applies_to_class_a_reads") {
            Some(ts) => ts,
            None => return,
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_modelsec();
            let sandbox = Sandbox::new();
            let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
                config.set("defaultOutput", "json");
            });
            sandbox.register(&[&tenant], Some("prod"));
            let options = if cli.is_ts() {
                RunOptions::new().allow_secret_output()
            } else {
                RunOptions::new()
            };
            let out = run(
                &cli,
                &sandbox,
                &["model-security", "rules", "list"],
                &options,
            );
            out.assert_success();
            assert_eq!(out.json()[0]["uuid"], json!(u(201)), "{}", cli.label());
        }
    }

    /// Every model-security group and read leaf carries TypeScript's descriptions and
    /// option texts (the §17.2 Rust options added); the groups list the step-1 commands in
    /// TypeScript's order.
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let help = |cli: &Cli, path: &[&str]| {
            let mut args = path.to_vec();
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
        // Every model-security command (§17.1 steps 1–3).
        let built = [
            "install",
            "pypi-auth",
            "create",
            "update",
            "delete",
            "add",
            "set",
            "groups",
            "labels",
            "models",
            "rule-instances",
            "rules",
            "scans",
            "get",
            "list",
            "evaluation",
            "evaluations",
            "files",
            "violation",
            "violations",
            "version",
            "versions",
            "keys",
            "values",
        ];
        let mut problems = Vec::new();
        let groups: [&[&str]; 7] = [
            &["model-security"],
            &["model-security", "groups"],
            &["model-security", "rules"],
            &["model-security", "rule-instances"],
            &["model-security", "scans"],
            &["model-security", "models"],
            &["model-security", "labels"],
        ];
        for path in groups {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let ts_subs: Vec<(String, String)> = entries(&t, "Commands:")
                .into_iter()
                .filter(|(name, _)| built.contains(&name.as_str()))
                .collect();
            // clap appends ` [aliases: ls]`; commander shows `list|ls` in the name column.
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
        let leaves: [&[&str]; 30] = [
            &["model-security", "install"],
            &["model-security", "pypi-auth"],
            &["model-security", "groups", "create"],
            &["model-security", "groups", "update"],
            &["model-security", "groups", "delete"],
            &["model-security", "rule-instances", "update"],
            &["model-security", "scans", "create"],
            &["model-security", "labels", "add"],
            &["model-security", "labels", "set"],
            &["model-security", "labels", "delete"],
            &["model-security", "groups", "list"],
            &["model-security", "groups", "get"],
            &["model-security", "rules", "list"],
            &["model-security", "rules", "get"],
            &["model-security", "rule-instances", "list"],
            &["model-security", "rule-instances", "get"],
            &["model-security", "scans", "list"],
            &["model-security", "scans", "get"],
            &["model-security", "scans", "evaluations"],
            &["model-security", "scans", "evaluation"],
            &["model-security", "scans", "violations"],
            &["model-security", "scans", "violation"],
            &["model-security", "scans", "files"],
            &["model-security", "models", "list"],
            &["model-security", "models", "get"],
            &["model-security", "models", "versions"],
            &["model-security", "models", "version"],
            &["model-security", "models", "files"],
            &["model-security", "labels", "keys"],
            &["model-security", "labels", "values"],
        ];
        for path in leaves {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let command = path.join(" ");
            let rust_options = entries(&r, "Options:");
            for (flag, description) in entries(&t, "Options:") {
                if matches!(flag.as_str(), "--help" | "--output") {
                    continue;
                }
                match rust_options.iter().find(|(f, _)| *f == flag) {
                    Some((_, actual)) if *actual == description => {}
                    other => {
                        problems.push(format!("{command} {flag}: {other:?} vs {description:?}"))
                    }
                }
            }
            let ts_about = t.lines().nth(2).unwrap_or_default().to_owned();
            if !r.contains(&ts_about) {
                problems.push(format!("{command} description: {ts_about:?}"));
            }
            // TS examples carry the program name `airs-cli`.
            if let Some(examples) = t.split("Examples:\n").nth(1) {
                let expected = examples.trim_end().replace("airs-cli ", "airs ");
                if !r.contains(&expected) {
                    problems.push(format!("{command} examples: {expected:?}"));
                }
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
// Divergences (§12 rows of step 1)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D180: a pending scan whose summary carries no counts: TypeScript prints
    /// `0 passed  0 failed  / 0 total` and json zeros; airs-cli-rs prints no `Rules` line
    /// and json `null` counts. A file without `formats`: TS `[]`, Rust omitted.
    #[test]
    fn d180_nothing_the_server_did_not_send_is_printed() {
        let seed = |data: &mut ModelSecData| {
            data.scans = vec![fx::pending_scan(403)];
            data.files = vec![fx::file(704, "x.bin", "FILE", "SUCCESS", None, 403, 901)];
            data.versions = vec![fx::uncounted_version(903)];
        };
        let Some((r, t)) = sides_seeded(
            "d180_nothing_the_server_did_not_send_is_printed",
            &["scans", "list"],
            &seed,
        ) else {
            return;
        };
        assert!(
            t.run
                .stdout
                .contains("Rules: 0 passed  0 failed  / 0 total"),
            "{}",
            t.run.stdout
        );
        assert!(!r.run.stdout.contains("Rules:"), "{}", r.run.stdout);
        let Some((r, t)) = sides_seeded(
            "d180_nothing_the_server_did_not_send_is_printed",
            &["scans", "get", &u(403), "--output", "json"],
            &seed,
        ) else {
            return;
        };
        assert_eq!(
            t.run.json()["evalSummary"],
            json!({"rulesFailed": 0, "rulesPassed": 0, "totalRules": 0})
        );
        assert_eq!(
            r.run.json()["evalSummary"],
            json!({"rulesFailed": null, "rulesPassed": null, "totalRules": null})
        );
        assert_eq!(t.run.json()["labels"], json!([]));
        assert!(r.run.json().get("labels").is_none());
        let Some((r, t)) = sides_seeded(
            "d180_nothing_the_server_did_not_send_is_printed",
            &["scans", "files", &u(403), "--output", "json"],
            &seed,
        ) else {
            return;
        };
        // TS prints pretty for class B (D189); its record would say `formats: []`.
        assert!(
            t.run.stdout.contains("SUCCESS  FILE  x.bin\n"),
            "{}",
            t.run.stdout
        );
        assert!(r.run.json()[0].get("formats").is_none());
        let Some((r, t)) = sides_seeded(
            "d180_nothing_the_server_did_not_send_is_printed",
            &["models", "version", &u(903)],
            &seed,
        ) else {
            return;
        };
        assert!(
            t.run
                .stdout
                .contains("  Last Eval Summary:\n\n  Passed  0\n  Failed  0\n  Total   0\n"),
            "{}",
            t.run.stdout
        );
        assert!(
            !r.run.stdout.contains("Last Eval Summary"),
            "{}",
            r.run.stdout
        );
    }

    /// D181: `--scan-origin` is never sent by TypeScript, which lists every origin;
    /// airs-cli-rs walks every page and keeps that origin only.
    #[test]
    fn d181_scan_origin_filters_locally() {
        let Some((r, t)) = sides(
            "d181_scan_origin_filters_locally",
            &[
                "scans",
                "list",
                "--scan-origin",
                "MODEL_SECURITY_API",
                "--output",
                "json",
            ],
        ) else {
            return;
        };
        let uuids = |side: &Side| -> Vec<Value> {
            side.run
                .json()
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["uuid"].clone())
                .collect()
        };
        assert_eq!(uuids(&t), [json!(u(401)), json!(u(402))]);
        assert_eq!(uuids(&r), [json!(u(402))]);
        assert_eq!(api(&t), ["GET /aims/data/v1/scans?skip=0&limit=20"]);
        assert_eq!(api(&r), ["GET /aims/data/v1/scans?skip=0&limit=100"]);
        assert_eq!(r.run.stderr, "  Showing 1 of 1\n");
    }

    /// D182: a page that says `count_capped: true` reports a cap: TypeScript stops the
    /// `--all` walk at it; airs-cli-rs walks on to the short page.
    #[test]
    fn d182_a_capped_count_does_not_end_the_walk() {
        let seed = |data: &mut ModelSecData| {
            data.scans = (401..=405)
                .map(|n| fx::scan(n, "ALLOWED", "", "MODEL_SECURITY_SDK", None))
                .collect();
            data.count_capped = Some(2);
        };
        let Some((r, t)) = sides_seeded(
            "d182_a_capped_count_does_not_end_the_walk",
            &["scans", "list", "--all", "--limit", "2", "--output", "json"],
            &seed,
        ) else {
            return;
        };
        assert_eq!(t.run.json().as_array().unwrap().len(), 2);
        assert_eq!(r.run.json().as_array().unwrap().len(), 5);
        assert_eq!(api(&t).len(), 1);
        assert_eq!(api(&r).len(), 3);
    }

    /// D183: `rule-instances list` honours `--offset`, `--all` and `--max` (TS ignores
    /// them); the scan sub-lists gain them; a page that does not show everything says so.
    #[test]
    fn d183_every_paging_flag_is_honoured() {
        let seed = |data: &mut ModelSecData| {
            data.rule_instances = (301..=305)
                .map(|n| {
                    let mut row = fx::rule_instances()[1].clone();
                    row["uuid"] = json!(u(n));
                    row
                })
                .collect();
        };
        let g = u(1);
        let Some((r, t)) = sides_seeded(
            "d183_every_paging_flag_is_honoured",
            &[
                "rule-instances",
                "list",
                &g,
                "--limit",
                "2",
                "--offset",
                "2",
                "--output",
                "json",
            ],
            &seed,
        ) else {
            return;
        };
        let path = format!("/aims/mgmt/v1/security-groups/{g}/rule-instances");
        assert_eq!(api(&t), [format!("GET {path}?limit=2")]);
        assert_eq!(api(&r), [format!("GET {path}?skip=2&limit=2")]);
        assert_eq!(r.run.stderr, "  Showing 2 of 5 (next --offset 4)\n");
        assert_eq!(t.run.stderr, "");
        let Some((r, t)) = sides_seeded(
            "d183_every_paging_flag_is_honoured",
            &[
                "rule-instances",
                "list",
                &g,
                "--all",
                "--limit",
                "2",
                "--max",
                "3",
                "--output",
                "json",
            ],
            &seed,
        ) else {
            return;
        };
        assert_eq!(t.run.json().as_array().unwrap().len(), 2);
        assert_eq!(r.run.json().as_array().unwrap().len(), 3);
        assert_eq!(
            r.run.stderr,
            "  Showing first 3 (stopped at --max 3; more available)\n"
        );
        // A Rust-only flag on a sub-list: TS refuses the unknown option.
        let s = u(401);
        let Some((r, t)) = sides(
            "d183_every_paging_flag_is_honoured",
            &["scans", "evaluations", &s, "--all", "--output", "json"],
        ) else {
            return;
        };
        r.run.assert_success();
        assert_eq!(r.run.json().as_array().unwrap().len(), 2);
        assert_ne!(t.run.code, 0);
    }

    /// D184: argument errors are usage errors before the tenant (exit 2, no request);
    /// TypeScript reports them after the banner and the tenant read (exit 1, or 2 after
    /// the tenant for the window), and sends `limit=0` and `labels values ..` to another
    /// endpoint.
    #[test]
    fn d184_argument_checks_come_before_the_tenant() {
        for (args, ts_code) in [
            (vec!["groups", "get", "not-a-uuid"], 1),
            (vec!["scans", "evaluation", "x"], 1),
            (vec!["scans", "list", "--start", "2026-01-01"], 2),
        ] {
            let Some((r, t)) = sides("d184_argument_checks_come_before_the_tenant", &args) else {
                return;
            };
            assert_eq!(r.run.code, 2, "{args:?}: {}", context(&r, &t));
            assert_eq!(t.run.code, ts_code, "{args:?}: {}", context(&r, &t));
            assert!(r.requests.is_empty(), "{args:?}");
            assert_eq!(r.run.stdout, "");
            assert!(t.run.stdout.starts_with(BANNER));
            assert_eq!(
                airs_test_harness::usage_line(&r.run.stderr),
                airs_test_harness::error_line(&t.run.stderr)
                    .or_else(|| airs_test_harness::usage_line(&t.run.stderr)),
                "{args:?}"
            );
        }
        let Some((r, t)) = sides(
            "d184_argument_checks_come_before_the_tenant",
            &["groups", "list", "--limit", "0"],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert!(r.requests.is_empty());
        assert_eq!(
            api(&t),
            ["GET /aims/mgmt/v1/security-groups?skip=0&limit=0"]
        );
        let Some((r, t)) = sides(
            "d184_argument_checks_come_before_the_tenant",
            &["labels", "values", ".."],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert!(r.requests.is_empty());
        assert_eq!(api(&t), ["GET /aims/data/v1/scans/values?limit=20"]);
    }

    /// D202: `labels values <key>` sends the key as one segment percent-encoded by the SDK
    /// segment rule, which also encodes the sub-delimiters `( ) ! * '` that JavaScript's
    /// `encodeURIComponent` leaves as they are (the raw request lines differ; the decoded
    /// key is the same).
    #[test]
    fn d202_a_label_key_segment_encodes_sub_delimiters() {
        let Some((r, t)) = sides(
            "d202_a_label_key_segment_encodes_sub_delimiters",
            &["labels", "values", "a(b)!*'~ é/x?y#z+%", "--output", "json"],
        ) else {
            return;
        };
        assert_eq!(
            api(&r),
            [
                "GET /aims/data/v1/scans/label-keys/a%28b%29%21%2A%27~%20%C3%A9%2Fx%3Fy%23z%2B%25/values?limit=20"
            ],
            "{}",
            context(&r, &t)
        );
        assert_eq!(
            api(&t),
            [
                "GET /aims/data/v1/scans/label-keys/a(b)!*'~%20%C3%A9%2Fx%3Fy%23z%2B%25/values?limit=20"
            ],
            "{}",
            context(&r, &t)
        );
        assert_eq!(r.run.code, 0, "{}", context(&r, &t));
    }

    /// D189: `--output` is honoured by the reads TypeScript prints in pretty only.
    #[test]
    fn d189_class_b_reads_honour_output() {
        let s = u(401);
        for args in [
            vec!["scans", "evaluations", &s, "--output", "json"],
            vec!["labels", "keys", "--output", "json"],
        ] {
            let Some((r, t)) = sides("d189_class_b_reads_honour_output", &args) else {
                return;
            };
            assert!(t.run.stdout.starts_with(BANNER), "{args:?}");
            assert!(r.run.json().is_array(), "{args:?}");
        }
        let Some((r, _)) = sides(
            "d189_class_b_reads_honour_output",
            &["labels", "keys", "--output", "json"],
        ) else {
            return;
        };
        assert_eq!(r.run.json(), json!(["env", "team"]));
    }

    /// D190: `--quiet` keeps the pretty ids (TS drops them); a failing read leaves stdout
    /// empty (TS leaves the banner of a class B read).
    #[test]
    fn d190_quiet_keeps_data_and_the_banner_needs_success() {
        let Some((r, t)) = sides(
            "d190_quiet_keeps_data_and_the_banner_needs_success",
            &["--quiet", "groups", "list"],
        ) else {
            return;
        };
        assert_eq!(
            t.run.stdout,
            "    Default LOCAL  ACTIVE  source: LOCAL\n    Pending S3  PENDING  source: S3\n\n"
        );
        assert_eq!(
            r.run.stdout,
            format!(
                "  {}\n    Default LOCAL  ACTIVE  source: LOCAL\n  {}\n    Pending S3  PENDING  source: S3\n\n",
                u(1),
                u(2)
            )
        );
        let missing = u(599);
        let Some((r, t)) = sides(
            "d190_quiet_keeps_data_and_the_banner_needs_success",
            &["scans", "evaluation", &missing],
        ) else {
            return;
        };
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert_eq!(t.run.stdout, BANNER);
        assert_eq!(r.run.stdout, "");
    }

    /// D191: a model URI with userinfo and a signed query: TypeScript prints it raw;
    /// airs-cli-rs withholds them in every format, and neither part reaches stderr.
    #[test]
    fn d191_model_uris_are_withheld() {
        let seed = |data: &mut ModelSecData| data.scans = vec![fx::credential_uri_scan(403)];
        let shown = "https://[withheld]@models.example.invalid/org/model.bin?[withheld]#[withheld]";
        for args in [
            vec!["scans", "list"],
            vec!["scans", "list", "--output", "json"],
            vec!["scans", "list", "--output", "table"],
        ] {
            let Some((r, t)) = sides_seeded("d191_model_uris_are_withheld", &args, &seed) else {
                return;
            };
            r.run.assert_success();
            assert!(t.run.stdout.contains(&fx::secret(1)), "{args:?}");
            for n in 1..=4 {
                assert!(!r.run.stdout.contains(&fx::secret(n)), "{args:?}");
            }
            assert!(r.run.stdout.contains(shown), "{args:?}: {}", r.run.stdout);
        }
    }

    /// D192: a custom-rule instance: TypeScript prints `undefined` and drops the custom
    /// rule from json; airs-cli-rs names it and keeps `customRuleUuid` and `customRule`.
    #[test]
    fn d192_custom_rule_instances_are_named() {
        let seed =
            |data: &mut ModelSecData| data.rule_instances.push(fx::custom_rule_instance(303));
        let g = u(1);
        let Some((r, t)) = sides_seeded(
            "d192_custom_rule_instances_are_named",
            &["rule-instances", "list", &g],
            &seed,
        ) else {
            return;
        };
        assert!(
            t.run.stdout.contains("    undefined  BLOCKING\n"),
            "{}",
            t.run.stdout
        );
        assert!(
            r.run.stdout.contains("    Tenant Custom Rule  BLOCKING\n"),
            "{}",
            r.run.stdout
        );
        let Some((r, t)) = sides_seeded(
            "d192_custom_rule_instances_are_named",
            &["rule-instances", "get", &g, &u(303), "--output", "json"],
            &seed,
        ) else {
            return;
        };
        assert!(t.run.json().get("customRule").is_none());
        assert_eq!(r.run.json()["customRuleUuid"], json!(u(311)));
        assert_eq!(
            r.run.json()["customRule"]["name"],
            json!("Tenant Custom Rule")
        );
    }

    /// D193: a signal during a read: TypeScript dies by the signal with nothing printed;
    /// airs-cli-rs prints `Interrupted; no data was written`.
    #[test]
    fn d193_an_interrupted_read_prints_its_context() {
        let Some(ts) = require_ts("d193_an_interrupted_read_prints_its_context") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_modelsec();
            server.push_once(Route::ModelSecurity(Ms::GroupList), Planned::hang());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let running = spawn(
                &cli,
                &sandbox,
                &["model-security", "groups", "list"],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::ModelSecurity(Ms::GroupList),
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
        assert_eq!(outs[0].stdout, "");
        assert_eq!(outs[1].code, 130);
        assert_eq!(outs[1].stderr, "");
    }

    /// D50 (extended to model security): `markdown`, `csv` and `yaml` are usage errors
    /// before the tenant; TypeScript renders them.
    #[test]
    fn d50_dropped_formats_are_usage_errors_on_model_security_reads() {
        for format in ["markdown", "csv", "yaml"] {
            let Some((r, t)) = sides(
                "d50_dropped_formats_are_usage_errors_on_model_security_reads",
                &["groups", "list", "--output", format],
            ) else {
                return;
            };
            assert_eq!(r.run.code, 2);
            assert!(r.requests.is_empty());
            t.run.assert_success();
        }
    }

    /// D11 and D52 (extended): a non-problem error body is not echoed, and control
    /// characters in server text are replaced; TypeScript prints both raw.
    #[test]
    fn d11_d52_server_text_is_neither_echoed_nor_raw() {
        let plan = |server: &FixtureServer| {
            server.push_once(
                Route::ModelSecurity(Ms::GroupGet),
                Planned::json(400, &json!({"message": "bad \u{1b}[31mECHOED value"})),
            );
        };
        let ts = match require_ts("d11_d52_server_text_is_neither_echoed_nor_raw") {
            Some(ts) => ts,
            None => return,
        };
        let g = u(1);
        let args = ["groups", "get", g.as_str()];
        let r = exec_with(&rust(), &args, &unchanged, &plan, &RunOptions::new());
        let t = exec_with(&ts, &args, &unchanged, &plan, &RunOptions::new());
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert!(
            t.run.stderr.contains("bad \u{1b}[31mECHOED value"),
            "{}",
            t.run.stderr
        );
        assert!(!r.run.stderr.contains("ECHOED"), "{}", r.run.stderr);
        let seed = |data: &mut ModelSecData| data.groups[0]["name"] = json!("Evil\u{1b}[31mRED");
        let r = exec(&rust(), &["groups", "list"], &seed);
        let t = exec(&ts, &["groups", "list"], &seed);
        assert!(t.run.stdout.contains("Evil\u{1b}[31mRED"));
        assert!(r.run.stdout.contains("Evil\u{fffd}[31mRED"));
    }
}
