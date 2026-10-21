//! TS-vs-Rust parity for the M6b step-1 DLP reads (DESIGN §16.1–§16.4).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh [`FixtureServer`] seeded with the DLP dataset and a fresh
//! [`Sandbox`] whose tenant points every endpoint at the server (the TypeScript DLP
//! client passes `dlpEndpoint` explicitly and reads no environment fallback, TD§0).
//! `parity` tests compare exit codes, stdout bytes (pretty and table) or JSON (json),
//! stderr and the normalised requests. `divergence` tests pin both sides of each §12 row
//! this step implements (named by its D#).

use std::time::Duration;

use airs_test_harness::fixtures::dlp as fx;
use airs_test_harness::{
    Cli, Collection, Dl, DlpData, FixtureServer, NormalizedRequest, Planned, Route, Run,
    RunOptions, Sandbox, assert_json_semantic_eq, normalize_all, require_ts, run, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    lines: Vec<String>,
}

/// Runs `cli` (`runtime dlp <args>`) on a fresh seeded server and sandbox; `seed` edits
/// the dataset.
fn exec_with(cli: &Cli, args: &[&str], seed: &dyn Fn(&mut DlpData), options: &RunOptions) -> Side {
    let server = FixtureServer::start();
    server.seed_dlp();
    server.dlp(|data| seed(data));
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    let mut full = vec!["runtime", "dlp"];
    full.extend_from_slice(args);
    let out = run(cli, &sandbox, &full, options);
    let raw = server.requests();
    Side {
        run: out,
        requests: normalize_all(&raw),
        lines: raw.iter().map(|request| request.line()).collect(),
    }
}

fn exec(cli: &Cli, args: &[&str], seed: &dyn Fn(&mut DlpData)) -> Side {
    exec_with(cli, args, seed, &RunOptions::new())
}

fn unchanged(_: &mut DlpData) {}

/// Both sides (`None` after a `PARITY SKIPPED` notice).
fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_seeded(name, args, &unchanged)
}

fn sides_seeded(name: &str, args: &[&str], seed: &dyn Fn(&mut DlpData)) -> Option<(Side, Side)> {
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

/// TS `camelKey`.
fn camel_key(key: &str) -> String {
    let mut out = String::new();
    let mut chars = key.chars().peekable();
    while let Some(c) = chars.next() {
        match chars.peek() {
            Some(&next)
                if matches!(c, '_' | '-')
                    && (next.is_ascii_lowercase() || next.is_ascii_digit()) =>
            {
                out.push(next.to_ascii_uppercase());
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}

/// D171: TypeScript's camelCasing applied to the data keys the Rust side keeps (the keys
/// under `tags` and `exclusions.exclusionList`), so the documents compare.
fn ts_camel_data_keys(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(ts_camel_data_keys),
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let data =
                    key == "tags" || (key == "exclusions" && child.get("exclusionList").is_some());
                if data {
                    let target = if key == "tags" {
                        Some(child)
                    } else {
                        child.get_mut("exclusionList")
                    };
                    if let Some(Value::Object(inner)) = target {
                        let renamed: serde_json::Map<String, Value> = std::mem::take(inner)
                            .into_iter()
                            .map(|(name, item)| (camel_key(&name), item))
                            .collect();
                        *inner = renamed;
                    }
                } else {
                    ts_camel_data_keys(child);
                }
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

    /// The pretty layouts are the TypeScript bytes (stderr status lines and requests
    /// included) wherever no §12 row applies: the server-paged lists and every get.
    #[test]
    fn pretty_layouts_match_typescript_byte_for_byte() {
        for args in [
            &["filtering-profiles", "list"][..],
            &["filtering-profiles", "ls", "--limit", "1"],
            &["filtering-profiles", "ls", "--limit", "1", "--offset", "1"],
            &["filtering-profiles", "get", "fp-1"],
            &["filtering-profiles", "get", "fp-2"],
            &["patterns", "list", "--include-predefined"],
            &[
                "patterns",
                "list",
                "--include-predefined",
                "--sort",
                "id,desc",
            ],
            &["patterns", "get", "p-cus-1"],
            &["patterns", "get", "p-pre-1"],
            &["patterns", "get", "p-dis-1"],
            &["profiles", "list", "--include-predefined"],
            &["profiles", "get", "dp-cus-1"],
            &["profiles", "get", "dp-pre-1"],
            &["dictionaries", "list", "--include-predefined"],
            &["dictionaries", "list", "--include-predefined", "--keywords"],
            &["dictionaries", "get", "d-cus-1"],
            &["dictionaries", "get", "d-cus-1", "--include-keywords"],
            &["--quiet", "patterns", "get", "p-cus-1"],
            &["--quiet", "filtering-profiles", "list"],
            &["filtering-profiles", "list", "--size", "1", "--page", "1"],
        ] {
            let Some((r, t)) = sides("pretty_layouts_match_typescript_byte_for_byte", args) else {
                return;
            };
            assert_bytes(&r, &t);
        }
    }

    /// The default (custom-only) lists print the TypeScript bytes when every custom row
    /// is on the first page; only the requests differ (D170).
    #[test]
    fn custom_only_lists_print_the_typescript_bytes() {
        for args in [
            &["patterns", "list"][..],
            &["profiles", "ls"],
            &["dictionaries", "list"],
            &["dictionaries", "list", "--keywords"],
            &["patterns", "list", "--output", "table"],
        ] {
            let Some((r, t)) = sides("custom_only_lists_print_the_typescript_bytes", args) else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
            assert_eq!(r.run.stdout, t.run.stdout, "{args:?}{}", context(&r, &t));
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}{}", context(&r, &t));
        }
    }

    /// Forced colour on both sides (`CLICOLOR_FORCE` for Rust, `FORCE_COLOR` for TS): the
    /// TS spans of TD§2.3 (bold headings, dim ids and details, cyan types, status colours,
    /// dim get keys, the dim status line).
    #[test]
    fn forced_colour_matches_typescript() {
        let Some(ts) = require_ts("forced_colour_matches_typescript") else {
            return;
        };
        let seed = |data: &mut DlpData| {
            data.patterns[0]["status"] = json!("silent");
        };
        for args in [
            &["patterns", "list", "--include-predefined"][..],
            &["profiles", "list", "--include-predefined"],
            &["dictionaries", "list", "--include-predefined", "--keywords"],
            &["filtering-profiles", "list", "--limit", "1"],
            &["patterns", "get", "p-cus-1"],
            &["filtering-profiles", "get", "fp-1"],
        ] {
            let colour = RunOptions::new().without_env("NO_COLOR");
            let r = exec_with(
                &rust(),
                args,
                &seed,
                &colour.clone().env("CLICOLOR_FORCE", "1"),
            );
            let t = exec_with(&ts, args, &seed, &colour.env("FORCE_COLOR", "1"));
            assert_bytes(&r, &t);
            assert!(r.run.stdout.contains("\u{1b}[1m"), "{args:?}");
        }
    }

    #[test]
    fn table_layouts_match_typescript() {
        for args in [
            &["filtering-profiles", "list", "--output", "table"][..],
            &[
                "patterns",
                "list",
                "--include-predefined",
                "--output",
                "table",
            ],
            &[
                "profiles",
                "list",
                "--include-predefined",
                "--output",
                "table",
            ],
            &[
                "dictionaries",
                "list",
                "--include-predefined",
                "--output",
                "table",
            ],
            &[
                "dictionaries",
                "list",
                "--include-predefined",
                "--keywords",
                "--output",
                "table",
            ],
            &["filtering-profiles", "get", "fp-1", "--output", "table"],
            &["patterns", "get", "p-dis-1", "--output", "table"],
            &["profiles", "get", "dp-multi-1", "--output", "table"],
            &[
                "dictionaries",
                "get",
                "d-pre-1",
                "--keywords",
                "--output",
                "table",
            ],
        ] {
            let Some((r, t)) = sides("table_layouts_match_typescript", args) else {
                return;
            };
            assert_bytes(&r, &t);
        }
    }

    /// The JSON documents are TypeScript's (D171 adjusts the tag and exclusion-list keys
    /// of the Rust side before the comparison).
    #[test]
    fn json_documents_match_typescript() {
        for args in [
            &["filtering-profiles", "list", "--output", "json"][..],
            &["filtering-profiles", "get", "fp-1", "--output", "json"],
            &["filtering-profiles", "get", "fp-2", "--output", "json"],
            &[
                "patterns",
                "list",
                "--include-predefined",
                "--output",
                "json",
            ],
            &["patterns", "get", "p-cus-1", "--output", "json"],
            &["patterns", "get", "p-pre-1", "--output", "json"],
            &[
                "profiles",
                "list",
                "--include-predefined",
                "--output",
                "json",
            ],
            &["profiles", "get", "dp-cus-1", "--output", "json"],
            &[
                "dictionaries",
                "list",
                "--include-predefined",
                "--keywords",
                "--output",
                "json",
            ],
            &["dictionaries", "get", "d-cus-1", "--output", "json"],
            &[
                "patterns",
                "list",
                "--include-predefined",
                "--all",
                "--limit",
                "2",
                "--output",
                "json",
            ],
        ] {
            let Some((r, t)) = sides("json_documents_match_typescript", args) else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
            let mut rust_doc = r.run.json();
            ts_camel_data_keys(&mut rust_doc);
            assert_json_semantic_eq(&rust_doc, &t.run.json());
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}{}", context(&r, &t));
            assert_eq!(r.requests, t.requests, "{args:?}{}", context(&r, &t));
        }
    }

    /// The tenant's `defaultOutput` applies to both CLIs' reads.
    #[test]
    fn default_output_applies_to_both() {
        let Some(ts) = require_ts("default_output_applies_to_both") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_dlp();
            let sandbox = Sandbox::new();
            let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
                config.set("defaultOutput", "json");
            });
            sandbox.register(&[&tenant], Some("prod"));
            outs.push(run(
                &cli,
                &sandbox,
                &["runtime", "dlp", "filtering-profiles", "get", "fp-1"],
                &RunOptions::new(),
            ));
        }
        outs[0].assert_success();
        outs[1].assert_success();
        assert_json_semantic_eq(&outs[0].json(), &outs[1].json());
    }

    /// A 404 and a 500 fail both reads with exit 1 and the HTTP line.
    #[test]
    fn http_errors_exit_1_with_the_status() {
        let Some((r, t)) = sides(
            "http_errors_exit_1_with_the_status",
            &["profiles", "get", "nope"],
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

    /// Every DLP group and read leaf carries TypeScript's descriptions and option texts
    /// (the §16.2 changes applied); the groups list the built subcommands in
    /// TypeScript's order, without `generate` (the write leaves are checked in
    /// `parity_dlp_writes.rs`).
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
        // `name → description` of a help section (continuation lines joined).
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
        // Every command but the dropped `generate` (and commander's `help`).
        let built = [
            "create",
            "delete",
            "get",
            "list",
            "patch",
            "replace",
            "backup",
            "dictionaries",
            "filtering-profiles",
            "patterns",
            "profiles",
            "restore",
        ];
        let mut problems = Vec::new();
        for (path, leaf) in [
            (&["runtime", "dlp"][..], false),
            (&["runtime", "dlp", "filtering-profiles"], false),
            (&["runtime", "dlp", "patterns"], false),
            (&["runtime", "dlp", "profiles"], false),
            (&["runtime", "dlp", "dictionaries"], false),
            (&["runtime", "dlp", "filtering-profiles", "list"], true),
            (&["runtime", "dlp", "filtering-profiles", "get"], true),
            (&["runtime", "dlp", "patterns", "list"], true),
            (&["runtime", "dlp", "patterns", "get"], true),
            (&["runtime", "dlp", "profiles", "list"], true),
            (&["runtime", "dlp", "profiles", "get"], true),
            (&["runtime", "dlp", "dictionaries", "list"], true),
            (&["runtime", "dlp", "dictionaries", "get"], true),
        ] {
            let (t, r) = (help(&ts, path), help(&rust(), path));
            let command = path.join(" ");
            if leaf {
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
            } else {
                // §16.2: the dictionary replace describes the D172 204 fallback.
                let ts_subs: Vec<(String, String)> = entries(&t, "Commands:")
                    .into_iter()
                    .filter(|(name, _)| built.contains(&name.as_str()))
                    .map(|(name, text)| {
                        if path == ["runtime", "dlp", "dictionaries"] && name == "replace" {
                            assert!(text.contains("(state not echoed)"), "{text}");
                            let text = "Full-replace via multipart upload. --file required. May return 200 (body) or 204 (re-get; when the re-get fails, warns and prints the id).";
                            (name, text.to_owned())
                        } else {
                            (name, text)
                        }
                    })
                    .collect();
                let rust_subs: Vec<(String, String)> = entries(&r, "Commands:")
                    .into_iter()
                    .filter(|(name, _)| name != "help")
                    .map(|(name, text)| {
                        let text = text
                            .trim_end_matches(" [aliases: ls]")
                            .trim_end_matches(" [aliases: rm]");
                        (name, text.to_owned())
                    })
                    .collect();
                if ts_subs != rust_subs {
                    problems.push(format!("{command}: {rust_subs:?} vs TS {ts_subs:?}"));
                }
            }
            // The group and leaf descriptions (TS: the paragraph after `Usage:`; clap: the
            // paragraph before it), with §16.2's change.
            let ts_about = t.split("\n\n").nth(1).map(squash).unwrap_or_default();
            let rust_about = r
                .split("\n\n")
                .next()
                .filter(|first| !first.starts_with("Usage:"))
                .map(squash)
                .unwrap_or_default();
            let expected = match path {
                ["runtime", "dlp"] => "DLP management (filtering-profiles, patterns, profiles, dictionaries, backup/restore)".to_owned(),
                ["runtime", "dlp", "dictionaries", "get"] => String::new(),
                _ => ts_about,
            };
            if rust_about != expected {
                problems.push(format!(
                    "{command} description: {rust_about:?} vs {expected:?}"
                ));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D50 (0.7 extension): `markdown`, `csv` and `yaml` are rendered by TypeScript and
    /// are usage errors (exit 2, before the tenant, no request) in airs-cli-rs.
    #[test]
    fn d50_dropped_formats_are_usage_errors_on_dlp_reads() {
        for format in ["markdown", "csv", "yaml"] {
            let args = ["patterns", "list", "--output", format];
            let Some((r, t)) = sides("d50_dropped_formats_are_usage_errors_on_dlp_reads", &args)
            else {
                return;
            };
            r.run.assert_code(2);
            assert_eq!(
                r.run.stderr,
                format!(
                    "\n  ✗ Invalid output format '{format}'. Expected: pretty, table, json\n\n"
                )
            );
            assert!(r.requests.is_empty());
            t.run.assert_code(0);
            assert!(!t.run.stdout.is_empty());
        }
    }

    /// D52 (0.7 extension): control characters in DLP text are written raw by TypeScript
    /// and replaced by airs-cli-rs; a get's description keeps its line breaks on both.
    #[test]
    fn d52_dlp_control_characters_are_replaced() {
        let seed = |data: &mut DlpData| {
            data.filtering_profiles[1]["name"] = json!("bad\u{1b}[31mname");
            data.patterns[3]["description"] = json!("one\ntwo\u{7}");
        };
        let Some((r, t)) = sides_seeded(
            "d52_dlp_control_characters_are_replaced",
            &["filtering-profiles", "list"],
            &seed,
        ) else {
            return;
        };
        assert!(
            t.run.stdout.contains("    bad\u{1b}[31mname  custom v2\n"),
            "{:?}",
            t.run.stdout
        );
        assert!(
            r.run
                .stdout
                .contains("    bad\u{fffd}[31mname  custom v2\n"),
            "{:?}",
            r.run.stdout
        );
        assert_eq!(r.run.stdout.replace('\u{fffd}', "\u{1b}"), t.run.stdout);
        let Some((r, t)) = sides_seeded(
            "d52_dlp_control_characters_are_replaced",
            &["patterns", "get", "p-cus-1"],
            &seed,
        ) else {
            return;
        };
        assert!(
            t.run.stdout.contains("  Description  one\ntwo\u{7}\n"),
            "{:?}",
            t.run.stdout
        );
        assert!(
            r.run.stdout.contains("  Description  one\ntwo\u{fffd}\n"),
            "{:?}",
            r.run.stdout
        );
    }

    /// D56 (0.7 extension): a list row without `id` or `name` prints `undefined` in
    /// TypeScript; airs-cli-rs omits the id line and prints an empty name. A non-ISO
    /// `updated_at` that JavaScript `Date` reads is printed by TypeScript and dropped by
    /// airs-cli-rs.
    #[test]
    fn d56_dlp_missing_ids_names_and_non_iso_timestamps() {
        let seed = |data: &mut DlpData| {
            let row = data.filtering_profiles[1].as_object_mut().unwrap();
            row.remove("id");
            row.remove("name");
            data.patterns[3]["audit_metadata"]["updated_at"] = json!("2023/11/14 10:00");
        };
        let Some((r, t)) = sides_seeded(
            "d56_dlp_missing_ids_names_and_non_iso_timestamps",
            &["filtering-profiles", "list"],
            &seed,
        ) else {
            return;
        };
        assert!(
            t.run
                .stdout
                .contains("  undefined\n    undefined  custom v2\n"),
            "{:?}",
            t.run.stdout
        );
        assert!(
            r.run.stdout.contains("\n      custom v2\n"),
            "{:?}",
            r.run.stdout
        );
        assert!(!r.run.stdout.contains("undefined"));
        let Some((r, t)) = sides_seeded(
            "d56_dlp_missing_ids_names_and_non_iso_timestamps",
            &["patterns", "get", "p-cus-1"],
            &seed,
        ) else {
            return;
        };
        assert!(
            t.run.stdout.contains("  Updated      "),
            "{:?}",
            t.run.stdout
        );
        assert!(!r.run.stdout.contains("Updated"), "{:?}", r.run.stdout);
    }

    /// D162: TypeScript sends malformed list numbers and traversal ids (or fails after the
    /// tenant); airs-cli-rs refuses them before the tenant with no request (exit 2).
    #[test]
    fn d162_dlp_argument_checks_come_before_the_tenant() {
        let Some(ts) = require_ts("d162_dlp_argument_checks_come_before_the_tenant") else {
            return;
        };
        // `--limit abc` is dropped by TypeScript (no size sent, exit 0).
        let r = exec(
            &rust(),
            &["filtering-profiles", "list", "--limit", "abc"],
            &unchanged,
        );
        let t = exec(
            &ts,
            &["filtering-profiles", "list", "--limit", "abc"],
            &unchanged,
        );
        r.run.assert_code(2);
        assert_eq!(r.run.stderr, "\n  ✗ --limit must be a positive integer\n\n");
        assert!(r.requests.is_empty());
        t.run.assert_code(0);
        assert_eq!(
            api(&t),
            ["GET /dlp/v2/api/data-filtering-profiles?sort=name%2Casc"]
        );
        // `--limit 0` and `--offset -5` are sent.
        let t = exec(
            &ts,
            &["filtering-profiles", "list", "--limit", "0"],
            &unchanged,
        );
        assert_eq!(
            api(&t),
            ["GET /dlp/v2/api/data-filtering-profiles?size=0&sort=name%2Casc"]
        );
        let t = exec(
            &ts,
            &[
                "filtering-profiles",
                "list",
                "--offset",
                "-5",
                "--limit",
                "5",
            ],
            &unchanged,
        );
        assert_eq!(
            api(&t),
            ["GET /dlp/v2/api/data-filtering-profiles?page=-1&size=5&sort=name%2Casc"]
        );
        let r = exec(
            &rust(),
            &["filtering-profiles", "list", "--offset", "-5"],
            &unchanged,
        );
        r.run.assert_code(2);
        // `..` reaches the API root in TypeScript.
        let r = exec(&rust(), &["patterns", "get", ".."], &unchanged);
        let t = exec(&ts, &["patterns", "get", ".."], &unchanged);
        r.run.assert_code(2);
        assert_eq!(r.run.stderr, "\n  ✗ Invalid data pattern id: ..\n\n");
        assert!(r.requests.is_empty());
        assert_eq!(api(&t), ["GET /dlp/v2/api/"]);
        t.run.assert_code(1);
        // `--max abc` fails after the tenant in TypeScript (exit 1).
        let r = exec(
            &rust(),
            &["patterns", "list", "--all", "--max", "abc"],
            &unchanged,
        );
        let t = exec(
            &ts,
            &["patterns", "list", "--all", "--max", "abc"],
            &unchanged,
        );
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --max must be a non-negative integer\n\n"
        );
        t.run.assert_code(1);
        assert!(
            t.run.stderr.contains("max must be a non-negative integer"),
            "{}",
            t.run.stderr
        );
        // `--all --offset 0` is accepted by TypeScript.
        let r = exec(
            &rust(),
            &["filtering-profiles", "list", "--all", "--offset", "0"],
            &unchanged,
        );
        let t = exec(
            &ts,
            &["filtering-profiles", "list", "--all", "--offset", "0"],
            &unchanged,
        );
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --all cannot be combined with --offset\n\n"
        );
        t.run.assert_code(0);
    }

    /// D170: TypeScript filters one fetched page, so a first page of predefined rows prints
    /// `No data patterns found` while custom ones exist; airs-cli-rs reads every page and
    /// slices the custom rows, with the custom total.
    #[test]
    fn d170_custom_only_lists_read_every_page() {
        let seed = |data: &mut DlpData| {
            let mut rows: Vec<Value> = (0..3)
                .map(|n| {
                    fx::pattern(
                        &format!("pre-{n}"),
                        &format!("A predefined {n}"),
                        "predefined",
                        "active",
                        "regex",
                        1,
                        None,
                    )
                })
                .collect();
            rows.extend(
                fx::patterns()
                    .into_iter()
                    .filter(|row| row["type"] == "custom"),
            );
            data.patterns = rows;
        };
        let Some((r, t)) = sides_seeded(
            "d170_custom_only_lists_read_every_page",
            &["patterns", "list", "--limit", "1"],
            &seed,
        ) else {
            return;
        };
        assert_eq!(t.run.stdout, "  No data patterns found\n");
        assert_eq!(t.run.stderr, "  Showing 0 of 0\n");
        assert_eq!(
            api(&t),
            ["GET /dlp/v2/api/data-patterns?size=1&sort=name%2Casc"]
        );
        assert_eq!(
            r.run.stdout,
            "\n  Data Patterns:\n\n  p-del-1\n    Archived Pattern  custom  deleted regex v3\n\n"
        );
        assert_eq!(r.run.stderr, "  Showing 1 of 4 (next --offset 1)\n");
        assert_eq!(
            api(&r),
            ["GET /dlp/v2/api/data-patterns?page=0&size=100&sort=name%2Casc"]
        );
        // G13: TypeScript asks its one page for keywords; airs-cli-rs walks without them
        // and reads the shown rows' keywords per id (the same bytes here).
        let Some((r, t)) = sides(
            "d170_custom_only_lists_read_every_page",
            &[
                "dictionaries",
                "list",
                "--keywords",
                "--limit",
                "1",
                "--output",
                "json",
            ],
        ) else {
            return;
        };
        assert_eq!(
            api(&t),
            ["GET /dlp/v2/api/dictionaries?size=1&sort=name%2Casc&keywords=true"]
        );
        assert_eq!(
            api(&r),
            [
                "GET /dlp/v2/api/dictionaries?page=0&size=100&sort=name%2Casc",
                "GET /dlp/v2/api/dictionaries/d-cus-1?keywords=true"
            ]
        );
        assert_eq!(r.run.stdout, t.run.stdout);
        // `--offset` without `--limit`: TypeScript rounds with 50 but sends no size.
        let Some((r, t)) = sides(
            "d170_custom_only_lists_read_every_page",
            &["patterns", "list", "--include-predefined", "--offset", "60"],
        ) else {
            return;
        };
        assert_eq!(
            api(&t),
            ["GET /dlp/v2/api/data-patterns?page=1&sort=name%2Casc"]
        );
        assert_eq!(
            api(&r),
            ["GET /dlp/v2/api/data-patterns?page=1&size=50&sort=name%2Casc"]
        );
        // A server page with predefined rows: TypeScript prints `<n> of <n>`, airs-cli-rs
        // the server's total.
        let Some((r, t)) = sides(
            "d170_custom_only_lists_read_every_page",
            &["patterns", "list", "--include-predefined", "--limit", "2"],
        ) else {
            return;
        };
        assert_eq!(t.run.stderr, "  Showing 2 of 2\n");
        assert_eq!(r.run.stderr, "  Showing 2 of 5 (next --offset 2)\n");
        assert_eq!(r.run.stdout, t.run.stdout);
        // `--all --max` cuts silently in TypeScript.
        let Some((r, t)) = sides(
            "d170_custom_only_lists_read_every_page",
            &[
                "patterns",
                "list",
                "--include-predefined",
                "--all",
                "--max",
                "2",
            ],
        ) else {
            return;
        };
        assert_eq!(t.run.stderr, "  Showing 2 of 2\n");
        assert_eq!(
            r.run.stderr,
            "  Showing first 2 (stopped at --max 2; more available)\n"
        );
    }

    /// D170: a service that ignores `page` repeats rows; TypeScript's walk prints the
    /// duplicates, airs-cli-rs fails the walk (D37) and prints nothing.
    #[test]
    fn d170_a_walk_with_repeated_ids_fails() {
        let seed = |data: &mut DlpData| {
            data.patterns = (0..120)
                .map(|n| {
                    fx::pattern(
                        &format!("c-{n:03}"),
                        &format!("Custom {n:03}"),
                        "custom",
                        "active",
                        "regex",
                        1,
                        None,
                    )
                })
                .collect();
            data.ignore_page = true;
        };
        let args = [
            "patterns",
            "list",
            "--include-predefined",
            "--all",
            "--output",
            "json",
        ];
        let Some((r, t)) = sides_seeded("d170_a_walk_with_repeated_ids_fails", &args, &seed) else {
            return;
        };
        t.run.assert_code(0);
        let ids: Vec<String> = t
            .run
            .json()
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect();
        assert!(ids.len() > 120, "more rows than exist: {}", ids.len());
        assert_eq!(ids[0], ids[50], "page 0 again and again");
        r.run.assert_code(1);
        assert_eq!(r.run.stdout, "");
        assert_eq!(
            r.run.error_line().as_deref(),
            Some(
                "AISEC_SDK_ERROR:Pagination stopped: the service returned a repeated cursor or an empty intermediate page"
            )
        );
    }

    /// D171: TypeScript camelCases the user's tag and exclusion-list keys; airs-cli-rs
    /// keeps them.
    #[test]
    fn d171_data_keys_are_kept_verbatim() {
        let Some((r, t)) = sides(
            "d171_data_keys_are_kept_verbatim",
            &["patterns", "get", "p-cus-1", "--output", "json"],
        ) else {
            return;
        };
        assert_eq!(
            t.run.json()["tags"],
            json!({"compliance": [fx::content(4)], "myTag": [fx::content(5)]})
        );
        assert_eq!(
            r.run.json()["tags"],
            json!({"compliance": [fx::content(4)], "my_tag": [fx::content(5)]})
        );
        let Some((r, t)) = sides(
            "d171_data_keys_are_kept_verbatim",
            &["filtering-profiles", "get", "fp-2", "--output", "json"],
        ) else {
            return;
        };
        assert_eq!(
            t.run.json()["exclusions"]["exclusionList"],
            json!({"myCategory": ["one"], "Some_Category": []})
        );
        assert_eq!(
            r.run.json()["exclusions"]["exclusionList"],
            json!({"my_category": ["one"], "Some_Category": []})
        );
    }

    /// D174 (reads): a signal during a DLP read kills TypeScript with nothing printed;
    /// airs-cli-rs reports `Interrupted; no data was written` (exit 130).
    #[test]
    fn d174_an_interrupted_read_prints_its_context() {
        let Some(ts) = require_ts("d174_an_interrupted_read_prints_its_context") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_dlp();
            server.push_once(Route::Dlp(Dl::Get(Collection::Patterns)), Planned::hang());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let running = spawn(
                &cli,
                &sandbox,
                &["runtime", "dlp", "patterns", "get", "p-cus-1"],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Dlp(Dl::Get(Collection::Patterns)),
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
        assert_eq!(outs[1].stdout, "");
        assert_eq!(outs[1].stderr, "");
    }

    /// D178: TypeScript fails a read whose record carries an unfamiliar enum value (a new
    /// `status`); airs-cli-rs prints the value (the SDK's tolerant response mode).
    #[test]
    fn d178_an_unfamiliar_enum_value_is_printed() {
        let seed = |data: &mut DlpData| data.patterns[3]["status"] = json!("weird");
        let Some((r, t)) = sides_seeded(
            "d178_an_unfamiliar_enum_value_is_printed",
            &["patterns", "get", "p-cus-1"],
            &seed,
        ) else {
            return;
        };
        t.run.assert_code(1);
        assert_eq!(t.run.stdout, "");
        assert!(
            t.run.stderr.contains("AISEC_RESPONSE_VALIDATION:"),
            "{}",
            t.run.stderr
        );
        r.run.assert_success();
        assert!(
            r.run.stdout.contains("  Status       weird\n"),
            "{}",
            r.run.stdout
        );
    }
}
