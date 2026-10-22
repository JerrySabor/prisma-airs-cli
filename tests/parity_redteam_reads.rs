//! TS-vs-Rust parity for the M6a step-1 red team reads (DESIGN §15.1–§15.15).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh [`FixtureServer`] seeded with the red team dataset and a
//! fresh [`Sandbox`] whose tenant points every endpoint at the server (the TypeScript
//! red team client passes every endpoint explicitly, so no environment trap is needed).
//! `parity` tests compare exit codes, stdout bytes (pretty and table) or JSON (json),
//! stderr and the normalised requests. `divergence` tests pin both sides of each §12 row
//! this step implements (named by its D#). The TypeScript side prints the fixture
//! credentials (D140), so its runs disable the marker check; the airs-cli-rs runs keep it.

use airs_test_harness::fixtures::redteam as fx;
use airs_test_harness::{
    Cli, FixtureServer, NormalizedRequest, Planned, Route, Rt, Run, RunOptions, Sandbox,
    assert_json_semantic_eq, normalise_program, normalize_all, require_ts, run,
    strip_ts_target_defaults,
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
    sandbox: Sandbox,
}

/// Runs `cli` on a fresh seeded server and sandbox; `seed` edits the dataset and
/// `prepare` the sandbox before the run.
fn exec_with(
    cli: &Cli,
    args: &[&str],
    seed: &dyn Fn(&mut airs_test_harness::RedTeamData),
    prepare: &dyn Fn(&Sandbox),
    options: &RunOptions,
) -> Side {
    let server = FixtureServer::start();
    server.seed_redteam();
    server.redteam(|data| seed(data));
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    prepare(&sandbox);
    let mut full = vec!["redteam"];
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
        sandbox,
    }
}

fn exec(cli: &Cli, args: &[&str], seed: &dyn Fn(&mut airs_test_harness::RedTeamData)) -> Side {
    exec_with(cli, args, seed, &|_| {}, &RunOptions::new())
}

fn unchanged(_: &mut airs_test_harness::RedTeamData) {}

/// Both sides (`None` after a `PARITY SKIPPED` notice).
fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_seeded(name, args, &unchanged)
}

fn sides_seeded(
    name: &str,
    args: &[&str],
    seed: &dyn Fn(&mut airs_test_harness::RedTeamData),
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

/// JSON parity: exit code, semantically equal stdout JSON, stderr and the requests.
fn assert_json(r: &Side, t: &Side) {
    assert_eq!(r.run.code, t.run.code, "exit codes differ{}", context(r, t));
    assert_json_semantic_eq(&r.run.json(), &t.run.json());
    assert_eq!(
        r.run.stderr,
        t.run.stderr,
        "stderr differs{}",
        context(r, t)
    );
    assert_eq!(r.requests, t.requests, "requests differ{}", context(r, t));
}

fn api(side: &Side) -> Vec<String> {
    side.lines
        .iter()
        .filter(|line| !line.starts_with("POST /oauth/token"))
        .cloned()
        .collect()
}

/// The dataset with the management 0.86.0 targets (scm-sdk 0.2.3, DESIGN §15.24) in
/// place of the seeded ones: target 1 the Vertex AI realtime target, target 2 the n8n
/// target with audio templates.
fn management_0_86(data: &mut airs_test_harness::RedTeamData) {
    data.targets = vec![
        fx::vertex_target(1, "Vertex Realtime"),
        fx::audio_target(2, "n8n Audio"),
    ];
    data.targets[0]["profiling_status"] = json!("PARTIALLY_COMPLETE");
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The pretty layouts are the TypeScript bytes (requests included) wherever no §12
    /// row applies.
    #[test]
    fn pretty_layouts_match_typescript_byte_for_byte() {
        let job = fx::job_id(1);
        let set = fx::prompt_set_id(1);
        let prompt = fx::prompt_id(1);
        let adapter_target = fx::target_id(4);
        let rest_target = fx::target_id(1);
        let adapter = fx::adapter_id(1);
        let channel = fx::channel_id(1);
        for args in [
            vec!["list"],
            vec!["ls", "--status", "RUNNING"],
            vec!["status", &job],
            vec!["categories"],
            vec!["languages"],
            vec!["languages", "--management"],
            vec!["eula", "status"],
            vec!["eula", "content"],
            vec!["instances", "get", "ten-1"],
            vec!["prompts", "list", &set],
            vec!["prompts", "get", &set, &prompt],
            vec!["properties", "list"],
            vec!["properties", "values", "language"],
            vec!["properties", "values", "persona"],
            vec!["targets", "list"],
            vec!["targets", "ls", "--limit", "2", "--offset", "1"],
            vec!["targets", "get", &adapter_target],
            vec!["targets", "profile", &rest_target],
            vec!["targets", "metadata"],
            vec!["targets", "templates"],
            vec!["targets", "error-logs", &rest_target],
            vec!["adapter", "list"],
            vec!["adapter", "get", &adapter],
            vec!["network-broker", "channels", "list"],
            vec!["network-broker", "channels", "get", &channel],
            vec!["network-broker", "stats"],
        ] {
            let Some((r, t)) = sides("pretty_layouts_match_typescript_byte_for_byte", &args) else {
                return;
            };
            assert_bytes(&r, &t);
        }
    }

    /// Multi-line server text (descriptions, prompts, goals, EULA content, error-log
    /// messages) is printed on several lines as TypeScript prints it: line feeds, blank
    /// lines, CR LF pairs and tabs are the TypeScript bytes (§15.3 "Multi-line server text").
    #[test]
    fn multi_line_server_text_matches_typescript_byte_for_byte() {
        const TEXT: &str = "First line\n\n### Heading\n- bullet one\r\n-\tbullet two\n";
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.categories[0]["description"] = json!(TEXT);
            data.categories[0]["sub_categories"][0]["description"] = json!(TEXT);
            data.eula_content = json!({"content": TEXT});
            data.prompts[0]["prompt"] = json!(TEXT);
            data.prompts[0]["goal"] = json!(TEXT);
            for log in &mut data.error_logs {
                log["error_message"] = json!(TEXT);
            }
            data.adapters[0]["description"] = json!(TEXT);
            data.channels[0]["description"] = json!(TEXT);
        };
        let set = fx::prompt_set_id(1);
        let prompt = fx::prompt_id(1);
        let rest_target = fx::target_id(1);
        let adapter = fx::adapter_id(1);
        let channel = fx::channel_id(1);
        for args in [
            vec!["categories"],
            vec!["eula", "content"],
            vec!["prompts", "list", &set],
            vec!["prompts", "get", &set, &prompt],
            vec!["targets", "error-logs", &rest_target],
            vec!["adapter", "get", &adapter],
            vec!["network-broker", "channels", "get", &channel],
        ] {
            let Some((r, t)) = sides_seeded(
                "multi_line_server_text_matches_typescript_byte_for_byte",
                &args,
                &seed,
            ) else {
                return;
            };
            assert!(
                r.run
                    .stdout
                    .contains("### Heading\n- bullet one\r\n-\tbullet two\n"),
                "{args:?}: {:?}",
                r.run.stdout
            );
            assert_bytes(&r, &t);
        }
    }

    /// The JSON documents where TypeScript honours `--output json`.
    #[test]
    fn json_documents_match_typescript() {
        let set = fx::prompt_set_id(1);
        let prompt = fx::prompt_id(1);
        let channel = fx::channel_id(1);
        for args in [
            vec!["list", "--output", "json"],
            vec!["languages", "--output", "json"],
            vec!["languages", "--management", "--output", "json"],
            vec!["instances", "get", "ten-1", "--output", "json"],
            vec!["prompt-sets", "get", &set, "--output", "json"],
            vec!["prompts", "list", &set, "--output", "json"],
            vec!["prompts", "get", &set, &prompt, "--output", "json"],
            vec!["properties", "list", "--output", "json"],
            vec!["properties", "values", "language", "--output", "json"],
            vec!["targets", "list", "--output", "json"],
            vec!["adapter", "list", "--output", "json"],
            vec!["network-broker", "channels", "list", "--output", "json"],
            vec![
                "network-broker",
                "channels",
                "get",
                &channel,
                "--output",
                "json",
            ],
            vec!["network-broker", "stats", "--output", "json"],
        ] {
            let Some((r, t)) = sides("json_documents_match_typescript", &args) else {
                return;
            };
            assert_json(&r, &t);
        }
    }

    /// The TypeScript tables (lists and the languages table).
    #[test]
    fn table_layouts_match_typescript() {
        for args in [
            vec!["list", "--output", "table"],
            vec!["languages", "--output", "table"],
            vec!["properties", "list", "--output", "table"],
            vec!["targets", "list", "--output", "table"],
            vec!["adapter", "list", "--output", "table"],
            vec!["network-broker", "channels", "list", "--output", "table"],
        ] {
            let Some((r, t)) = sides("table_layouts_match_typescript", &args) else {
                return;
            };
            assert_bytes(&r, &t);
        }
    }

    /// Server-paged walks send the TypeScript requests: `list --all`, `adapter list
    /// --all`, `channels list --all` and their filters.
    #[test]
    fn walks_and_filters_send_the_typescript_requests() {
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.scans = (1..=25)
                .map(|n| fx::job(n, &format!("scan-{n}"), "COMPLETED", "STATIC"))
                .collect();
        };
        let target = fx::target_id(1);
        for args in [
            vec!["list", "--all", "--limit", "10", "--output", "json"],
            vec![
                "list",
                "--status",
                "COMPLETED",
                "--type",
                "STATIC",
                "--target",
                &target,
                "--limit",
                "3",
                "--output",
                "json",
            ],
            vec!["adapter", "list", "--all", "--output", "json"],
            vec![
                "adapter", "list", "--offset", "1", "--limit", "5", "--search", "adapter",
                "--output", "json",
            ],
            vec![
                "network-broker",
                "channels",
                "list",
                "--all",
                "--output",
                "json",
            ],
            vec![
                "network-broker",
                "channels",
                "list",
                "--status",
                "ONLINE",
                "OFFLINE",
                "--search",
                "chan",
                "--output",
                "json",
            ],
            // `--limit` only: `--offset` and `--search` are D300.
            vec!["targets", "error-logs", &target, "--limit", "1"],
        ] {
            let Some((r, t)) = sides_seeded(
                "walks_and_filters_send_the_typescript_requests",
                &args,
                &seed,
            ) else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{}", context(&r, &t));
            assert_eq!(r.run.stdout, t.run.stdout, "{}", context(&r, &t));
            assert_eq!(r.requests, t.requests, "{}", context(&r, &t));
        }
    }

    /// An empty filter sends no parameter on both CLIs (TypeScript skips a falsy filter;
    /// `--target ""` lists every scan, not none). `targets error-logs --search ""` is
    /// refused from 0.9.1 (D300, `d300_`).
    #[test]
    fn empty_filters_send_no_parameter() {
        for args in [
            vec!["list", "--target", "", "--output", "json"],
            vec!["list", "--status", "", "--type", "", "--output", "json"],
            vec!["adapter", "list", "--search", "", "--output", "json"],
            vec![
                "network-broker",
                "channels",
                "list",
                "--search",
                "",
                "--output",
                "json",
            ],
        ] {
            let Some((r, t)) = sides("empty_filters_send_no_parameter", &args) else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
            assert_eq!(api(&r), api(&t), "{args:?}{}", context(&r, &t));
            assert!(
                api(&r)
                    .iter()
                    .all(|line| !line.contains("=&") && !line.ends_with('=')),
                "{args:?}: {:?}",
                api(&r)
            );
        }
        let Some((r, _)) = sides(
            "empty_filters_send_no_parameter",
            &["list", "--target", "", "--output", "json"],
        ) else {
            return;
        };
        assert_eq!(r.run.json().as_array().map(Vec::len), Some(2), "every scan");
    }

    /// A read answered 401 is refreshed and replayed once on both CLIs.
    #[test]
    fn a_401_read_is_replayed_once_on_both() {
        let Some(ts) = require_ts("a_401_read_is_replayed_once_on_both") else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_redteam();
            server.push_once(Route::RedTeam(Rt::TargetList), Planned::empty_json(401));
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let options = if cli.is_ts() {
                RunOptions::new().allow_secret_output()
            } else {
                RunOptions::new()
            };
            run(&cli, &sandbox, &["redteam", "targets", "list"], &options).assert_success();
            assert_eq!(
                server.routes(),
                [
                    Route::Token,
                    Route::RedTeam(Rt::TargetList),
                    Route::Token,
                    Route::RedTeam(Rt::TargetList)
                ],
                "{}",
                cli.label()
            );
        }
    }

    /// G25 closed: answers with a non-UUID id, a timestamp that is not RFC 3339 and a
    /// status or error type outside the vendor enums are read alike by both CLIs (stdout,
    /// stderr, exit code and requests), in pretty and (for `list`) json (scm-sdk 0.2.2).
    #[test]
    fn g25_opaque_response_values_match_typescript() {
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            let mut job = fx::job(1, "opaque-scan", "PROFILING", "STATIC");
            job["uuid"] = json!("job-1");
            job["target_id"] = json!("t-1");
            job["created_at"] = json!("2026-10-17 10:00:00");
            data.scans = vec![job];
            let mut log = data.error_logs[0].clone();
            log["job_id"] = json!("job-1");
            log["created_at"] = json!("2026-01-05 00:00:00");
            log["error_type"] = json!("SOMETHING_NEW");
            data.error_logs = vec![log];
        };
        let target = fx::target_id(1);
        for args in [vec!["list"], vec!["targets", "error-logs", &target]] {
            let Some((r, t)) =
                sides_seeded("g25_opaque_response_values_match_typescript", &args, &seed)
            else {
                return;
            };
            r.run.assert_success();
            assert_bytes(&r, &t);
            assert!(r.run.stdout.contains("job-1"), "{}", r.run.stdout);
        }
        // TypeScript ignores `--output` for error logs, so json is compared for `list`.
        let Some((r, t)) = sides_seeded(
            "g25_opaque_response_values_match_typescript",
            &["list", "--output", "json"],
            &seed,
        ) else {
            return;
        };
        r.run.assert_success();
        assert_json(&r, &t);
        assert_eq!(r.run.json()[0]["id"], "job-1");
        assert_eq!(r.run.json()[0]["status"], "PROFILING");
    }

    /// No other output changes with scm-sdk 0.2.3: the listing of the 0.86.0 targets
    /// (`VERTEX_AI`, `N8N`, `REALTIME`, `PARTIALLY_COMPLETE` are plain strings in both
    /// list schemas) is TypeScript's, byte for byte in pretty and table and as JSON.
    #[test]
    fn management_0_86_listings_match_typescript() {
        for args in [
            vec!["targets", "list"],
            vec!["targets", "list", "--output", "table"],
        ] {
            let Some((r, t)) = sides_seeded(
                "management_0_86_listings_match_typescript",
                &args,
                &management_0_86,
            ) else {
                return;
            };
            assert_bytes(&r, &t);
        }
        let Some((r, t)) = sides_seeded(
            "management_0_86_listings_match_typescript",
            &["targets", "list", "--output", "json"],
            &management_0_86,
        ) else {
            return;
        };
        assert_json(&r, &t);
    }
}

// ---------------------------------------------------------------------------
// Help texts (§15.2)
// ---------------------------------------------------------------------------

mod help {
    use super::*;

    /// Collapses whitespace runs (TypeScript wraps help at 80 columns).
    fn squash(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The lines of a help section (`Commands:`, `Options:`), up to the next blank line.
    fn section<'a>(help: &'a str, title: &str) -> Vec<&'a str> {
        let mut lines = help.lines();
        if !lines.any(|line| line == title) {
            return Vec::new();
        }
        lines.take_while(|line| !line.trim().is_empty()).collect()
    }

    /// The subcommand names of a group's help, in order (`help` left out).
    fn subcommands(help: &str) -> Vec<String> {
        section(help, "Commands:")
            .iter()
            .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
            .map(|line| {
                let name = line.split_whitespace().next().unwrap_or_default();
                name.split('|').next().unwrap_or_default().to_owned()
            })
            .filter(|name| name != "help")
            .collect()
    }

    /// `flag → description` of a help's options (continuation lines joined).
    fn options(help: &str) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for line in section(help, "Options:") {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            if trimmed.starts_with('-') && indent <= 6 {
                let (spec, description) = trimmed.split_once("  ").unwrap_or((trimmed, ""));
                let flag = spec
                    .split([',', ' '])
                    .find(|part| part.starts_with("--"))
                    .unwrap_or(spec)
                    .to_owned();
                out.push((flag, squash(description)));
            } else if let Some((_, description)) = out.last_mut() {
                *description = squash(&format!("{description} {trimmed}"));
            }
        }
        out
    }

    /// The `Examples:` lines with the program name made TypeScript's.
    fn examples(help: &str) -> Vec<String> {
        let Some((_, rest)) = help.split_once("Examples:\n") else {
            return Vec::new();
        };
        rest.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(normalise_program)
            .collect()
    }

    /// The §15.2 option changes: `(command, flag) → the airs-cli-rs description`.
    const OPTION_CHANGES: &[(&str, &str, &str)] = &[
        (
            "redteam adapter create",
            "--variables",
            "JSON array of { key, value, type: VAR|SECRET } (no SECRET values; use --variables-file)",
        ),
        (
            "redteam prompt-sets download",
            "--output-file",
            "Output file path; - for stdout; never overwrite",
        ),
        (
            "redteam targets init",
            "--output-file",
            "Output file path; never overwrite",
        ),
        (
            "redteam targets backup",
            "--file-format",
            "Backup file format: json (default: \"json\")",
        ),
        (
            "redteam targets backup",
            "--name",
            "Back up the targets with this name",
        ),
        (
            "redteam targets backup",
            "--output-dir",
            "Existing directory for the backup file (default: the current directory)",
        ),
        (
            "redteam targets restore",
            "--file",
            "Backup file to restore",
        ),
        // D300: the red team API refuses both (§15.23).
        (
            "redteam targets error-logs",
            "--offset",
            "Not supported by the red team API (refused; use --limit)",
        ),
        (
            "redteam targets error-logs",
            "--search",
            "Not supported by the red team API (refused)",
        ),
    ];

    /// The §15.2 `Examples:` changes: `command → (dropped TS lines, added Rust lines)`.
    fn example_change(command: &str) -> (Vec<&'static str>, Vec<&'static str>) {
        match command {
            "redteam adapter create" => (
                vec![],
                vec![
                    "$ airs-cli redteam adapter create --name my-adapter --script-file ./adapter.py --channel 550e8400-... --prompt 'Hello' --variables-file variables.json",
                ],
            ),
            "redteam report" => (
                vec!["$ airs-cli redteam report --output markdown --output-file ./airs-daily.md"],
                vec![],
            ),
            "redteam targets backup" => (
                vec![],
                vec![
                    "$ airs-cli redteam targets backup",
                    "$ airs-cli redteam targets backup --output-dir ./backups --name \"Production chatbot\"",
                ],
            ),
            "redteam targets restore" => (
                vec![],
                vec![
                    "$ airs-cli redteam targets restore --file airs-redteam-targets-20261017T120000Z-0a1b2c3d.json --dry-run",
                    "$ airs-cli redteam targets restore --file airs-redteam-targets-20261017T120000Z-0a1b2c3d.json --overwrite",
                ],
            ),
            _ => (vec![], vec![]),
        }
    }

    /// Every red team group lists TypeScript's subcommands in TypeScript's order (no
    /// `judge`), and every leaf carries TypeScript's option descriptions and `Examples:`
    /// apart from the §15.2 changes.
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let help = |cli: &Cli, path: &[String]| {
            let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
            args.push("--help");
            let out = run(cli, &sandbox, &args, &RunOptions::new());
            out.assert_success();
            out.stdout
        };
        let mut pending = vec![vec!["redteam".to_owned()]];
        let mut leaves = 0;
        let mut problems = Vec::new();
        while let Some(path) = pending.pop() {
            let command = path.join(" ");
            let (t, r) = (help(&ts, &path), help(&rust(), &path));
            let ts_subs: Vec<String> = subcommands(&t)
                .into_iter()
                .filter(|name| name != "judge")
                .collect();
            if !ts_subs.is_empty() {
                if subcommands(&r) != ts_subs {
                    problems.push(format!(
                        "{command}: order {:?} vs TS {ts_subs:?}",
                        subcommands(&r)
                    ));
                }
                for sub in ts_subs {
                    let mut next = path.clone();
                    next.push(sub);
                    pending.push(next);
                }
                continue;
            }
            leaves += 1;
            let rust_options = options(&r);
            for (flag, description) in options(&t) {
                if matches!(flag.as_str(), "--help" | "--output") {
                    continue;
                }
                let expected = OPTION_CHANGES
                    .iter()
                    .find(|(c, f, _)| *c == command && *f == flag)
                    .map_or(description.clone(), |(_, _, text)| (*text).to_owned());
                match rust_options.iter().find(|(f, _)| *f == flag) {
                    Some((_, actual)) if *actual == expected => {}
                    Some((_, actual)) => {
                        problems.push(format!("{command} {flag}: {actual:?} vs {expected:?}"));
                    }
                    // The hidden TS alias `--input-dir` is refused, not listed (§15.19).
                    None if command == "redteam targets restore" && flag == "--input-dir" => {}
                    None => problems.push(format!("{command} {flag}: missing")),
                }
            }
            let (dropped, added) = example_change(&command);
            let mut expected: Vec<String> = examples(&t)
                .into_iter()
                .filter(|line| !dropped.contains(&line.as_str()))
                .collect();
            expected.extend(added.iter().map(|line| (*line).to_owned()));
            if examples(&r) != expected {
                problems.push(format!(
                    "{command} examples: {:?} vs {expected:?}",
                    examples(&r)
                ));
            }
        }
        assert!(leaves >= 55, "walked {leaves} leaves");
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D11 (0.6 extension): TypeScript echoes a non-JSON error body; airs-cli-rs prints
    /// the status from SDK metadata only. Both exit 1 with `HTTP 500`.
    #[test]
    fn d11_red_team_server_text_is_not_echoed() {
        let Some(ts) = require_ts("d11_red_team_server_text_is_not_echoed") else {
            return;
        };
        let job = fx::job_id(1);
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_redteam();
            server.set_default(
                Route::RedTeam(Rt::ScanGet),
                Planned::raw(500, "text/plain", "internal: upstream body"),
            );
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            outs.push(run(
                &cli,
                &sandbox,
                &["redteam", "status", &job],
                &RunOptions::new().allow_secret_output(),
            ));
        }
        let (r, t) = (&outs[0], &outs[1]);
        r.assert_code(1);
        t.assert_code(1);
        assert_eq!(
            r.error_line().as_deref(),
            Some("AISEC_SERVER_SIDE_ERROR:API error 500")
        );
        assert_eq!(
            t.error_line().as_deref(),
            Some("AISEC_SERVER_SIDE_ERROR:API error 500: internal: upstream body")
        );
        assert_eq!(r.http_status(), Some(500));
        assert_eq!(t.http_status(), Some(500));
    }

    /// D52 (0.6 extension): control characters in red team text are written raw by
    /// TypeScript and replaced by airs-cli-rs.
    #[test]
    fn d52_red_team_control_characters_are_replaced() {
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.prompt_sets[0]["name"] = json!("bad\u{1b}[31mname");
        };
        let Some((r, t)) = sides_seeded(
            "d52_red_team_control_characters_are_replaced",
            &["prompt-sets", "list"],
            &seed,
        ) else {
            return;
        };
        assert!(
            t.run.stdout.contains("    bad\u{1b}[31mname  active\n"),
            "{:?}",
            t.run.stdout
        );
        assert!(
            r.run.stdout.contains("    bad\u{fffd}[31mname  active\n"),
            "{:?}",
            r.run.stdout
        );
        assert_eq!(
            r.run.stdout.replace('\u{fffd}', "\u{1b}"),
            t.run.stdout,
            "only the control character differs"
        );
    }

    /// D54 (0.6 extension): a prompt preview whose 77th UTF-16 unit splits a surrogate
    /// pair keeps the lone half in TypeScript (written as U+FFFD); airs-cli-rs drops the
    /// character.
    #[test]
    fn d54_red_team_prompt_previews_never_split_a_character() {
        let text = format!("{}🚀{}", "a".repeat(76), "b".repeat(10));
        let seed = move |data: &mut airs_test_harness::RedTeamData| {
            data.prompts[0]["prompt"] = json!(text.clone());
        };
        let set = fx::prompt_set_id(1);
        let Some((r, t)) = sides_seeded(
            "d54_red_team_prompt_previews_never_split_a_character",
            &["prompts", "list", &set],
            &seed,
        ) else {
            return;
        };
        let cut = "a".repeat(76);
        assert!(
            r.run.stdout.contains(&format!("\n    {cut}...\n")),
            "{:?}",
            r.run.stdout
        );
        assert!(
            t.run.stdout.contains(&format!("\n    {cut}\u{fffd}...\n")),
            "{:?}",
            t.run.stdout
        );
    }

    /// D140: TypeScript prints target, adapter and error-log credentials; airs-cli-rs
    /// replaces each one with `[REDACTED]` and leaves every other field equal.
    #[test]
    fn d140_credentials_are_redacted_in_every_printed_document() {
        let Some(ts) = require_ts("d140_credentials_are_redacted_in_every_printed_document") else {
            return;
        };
        for args in [
            vec![
                "targets".to_owned(),
                "get".into(),
                fx::target_id(1),
                "--output".into(),
                "json".into(),
            ],
            vec![
                "targets".into(),
                "get".into(),
                fx::target_id(2),
                "--output".into(),
                "json".into(),
            ],
            vec![
                "targets".into(),
                "get".into(),
                fx::target_id(3),
                "--output".into(),
                "json".into(),
            ],
            vec![
                "adapter".into(),
                "get".into(),
                fx::adapter_id(1),
                "--output".into(),
                "json".into(),
            ],
            vec![
                "adapter".into(),
                "get".into(),
                fx::adapter_id(2),
                "--output".into(),
                "json".into(),
            ],
        ] {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let r = exec(&rust(), &args, &unchanged);
            let t = exec(&ts, &args, &unchanged);
            r.run.assert_success();
            t.run.assert_success();
            let (rust_doc, mut ts_doc) = (r.run.json(), t.run.json());
            // The TypeScript schema defaults are D153's (pinned there).
            strip_ts_target_defaults(&mut ts_doc, &rust_doc);
            let mut redacted = Vec::new();
            compare_redacted(&rust_doc, &ts_doc, "", &mut redacted);
            assert!(!redacted.is_empty(), "{args:?}: something was redacted");
            // A marker, a server mask, or (rule 1) any string of the auth settings.
            for (path, value) in &redacted {
                assert!(
                    value.contains("FAKE-TARGET-SECRET-")
                        || value == "**********"
                        || path.starts_with(".authConfig."),
                    "{args:?}: {path} was redacted but TS printed {value:?}"
                );
            }
            assert_eq!(r.requests, t.requests);
        }
        // Pretty: the same layout with the values replaced (the server sends the
        // `ws_response_timeout` TypeScript would otherwise add, D153).
        let id = fx::target_id(1);
        let served = |data: &mut airs_test_harness::RedTeamData| {
            data.targets[0]["connection_params"]["ws_response_timeout"] = json!(110);
        };
        let r = exec(&rust(), &["targets", "get", &id], &served);
        let t = exec(&ts, &["targets", "get", &id], &served);
        assert!(t.run.stdout.contains(&fx::secret(3)));
        assert!(
            r.run.stdout.contains("  curl                 [REDACTED]\n"),
            "{}",
            r.run.stdout
        );
        assert_eq!(r.run.stdout.lines().count(), t.run.stdout.lines().count());
    }

    /// Walks `rust` against `ts`: equal everywhere except at strings airs-cli-rs printed
    /// as `[REDACTED]` (or with a `[REDACTED]` URL part), which are collected.
    fn compare_redacted(
        rust: &Value,
        ts: &Value,
        path: &str,
        redacted: &mut Vec<(String, String)>,
    ) {
        match (rust, ts) {
            (Value::Object(r), Value::Object(t)) => {
                let mut keys: Vec<&String> = r.keys().collect();
                keys.sort();
                let mut other: Vec<&String> = t.keys().collect();
                other.sort();
                assert_eq!(keys, other, "keys differ at {path}");
                for key in keys {
                    compare_redacted(&r[key], &t[key], &format!("{path}.{key}"), redacted);
                }
            }
            (Value::Array(r), Value::Array(t)) => {
                assert_eq!(r.len(), t.len(), "lengths differ at {path}");
                for (index, (r, t)) in r.iter().zip(t).enumerate() {
                    compare_redacted(r, t, &format!("{path}[{index}]"), redacted);
                }
            }
            (Value::String(r), Value::String(t)) if r != t && r.contains("[REDACTED]") => {
                redacted.push((path.to_owned(), t.clone()));
            }
            (r, t) => assert_eq!(r, t, "values differ at {path}"),
        }
    }

    /// D141: TypeScript reports a bad id after the banner and the tenant (exit 1) and
    /// interpolates instance ids raw (`../registry-credentials` reaches another route);
    /// airs-cli-rs refuses both before the tenant (exit 2, no request).
    #[test]
    fn d141_argument_checks_come_before_the_tenant() {
        let Some((r, t)) = sides(
            "d141_argument_checks_come_before_the_tenant",
            &["status", "not-a-uuid"],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(r.run.stdout, "");
        assert_eq!(
            r.run.stderr,
            "\n  ✗ AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: not-a-uuid\n\n"
        );
        assert!(r.requests.is_empty());
        assert_eq!(t.run.code, 1);
        assert_eq!(t.run.stdout, BANNER);
        assert_eq!(
            t.run.error_line().as_deref(),
            Some("AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: not-a-uuid")
        );
        let Some((r, t)) = sides(
            "d141_argument_checks_come_before_the_tenant",
            &["instances", "get", "../registry-credentials"],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert!(r.requests.is_empty());
        assert_eq!(api(&t), ["GET /redteam/mgmt/v1/registry-credentials"]);
        let Some((r, t)) = sides(
            "d141_argument_checks_come_before_the_tenant",
            &["list", "--limit", "0"],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(r.run.stderr, "\n  ✗ --limit must be a positive integer\n\n");
        t.run.assert_success();
        assert_eq!(api(&t), ["GET /redteam/data/v1/scan?skip=0"]);
    }

    /// D142: TypeScript writes the template after the request, overwrites an existing
    /// file at 0644 and turns `-` into a file; airs-cli-rs refuses an existing path before
    /// any request, writes 0600 and prints the CSV for `-`.
    #[test]
    fn d142_downloads_are_private_and_never_overwrite() {
        use std::os::unix::fs::PermissionsExt;
        let Some(ts) = require_ts("d142_downloads_are_private_and_never_overwrite") else {
            return;
        };
        let id = fx::prompt_set_id(1);
        let name = format!("{id}-template.csv");
        let existing = move |sandbox: &Sandbox| {
            std::fs::write(
                sandbox
                    .cwd()
                    .join(format!("{}-template.csv", fx::prompt_set_id(1))),
                "keep",
            )
            .unwrap();
        };
        let options = RunOptions::new().allow_writes_under("cwd");
        let r = exec_with(
            &rust(),
            &["prompt-sets", "download", &id],
            &unchanged,
            &existing,
            &options,
        );
        let t = exec_with(
            &ts,
            &["prompt-sets", "download", &id],
            &unchanged,
            &existing,
            &options,
        );
        r.run.assert_code(1);
        assert!(api(&r).is_empty());
        assert_eq!(
            std::fs::read_to_string(r.sandbox.cwd().join(&name)).unwrap(),
            "keep"
        );
        t.run.assert_success();
        assert_eq!(
            std::fs::read_to_string(t.sandbox.cwd().join(&name)).unwrap(),
            fx::TEMPLATE_CSV
        );
        let fresh = |_: &Sandbox| {};
        let r = exec_with(
            &rust(),
            &["prompt-sets", "download", &id],
            &unchanged,
            &fresh,
            &options,
        );
        let t = exec_with(
            &ts,
            &["prompt-sets", "download", &id],
            &unchanged,
            &fresh,
            &options,
        );
        let mode = |side: &Side| {
            std::fs::metadata(side.sandbox.cwd().join(&name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&r), 0o600);
        assert_eq!(mode(&t), 0o644);
        assert_eq!(r.run.stderr, format!("  ✓ Template saved to {name}\n"));
        assert_eq!(
            t.run.stdout,
            format!("{BANNER}  ✓ Template saved to {name}\n")
        );
        let r = exec_with(
            &rust(),
            &["prompt-sets", "download", &id, "--output-file", "-"],
            &unchanged,
            &fresh,
            &options,
        );
        let t = exec_with(
            &ts,
            &["prompt-sets", "download", &id, "--output-file", "-"],
            &unchanged,
            &fresh,
            &options,
        );
        assert_eq!(r.run.stdout, fx::TEMPLATE_CSV);
        assert!(
            t.sandbox.cwd().join("-").exists(),
            "TypeScript writes a file named -"
        );
        assert!(!r.sandbox.cwd().join("-").exists());
    }

    /// D144: TypeScript ignores `--output` outside its read leaves, prints nothing for
    /// some tables and YAML for others; airs-cli-rs honours every format.
    #[test]
    fn d144_every_red_team_read_honours_output() {
        let Some((r, t)) = sides(
            "d144_every_red_team_read_honours_output",
            &["categories", "--output", "json"],
        ) else {
            return;
        };
        assert_eq!(r.run.json()[0]["id"], "SECURITY");
        assert!(t.run.stdout.starts_with(BANNER), "TS prints pretty");
        let id = fx::target_id(4);
        let Some((r, t)) = sides(
            "d144_every_red_team_read_honours_output",
            &["targets", "get", &id, "--output", "table"],
        ) else {
            return;
        };
        assert!(r.run.stdout.starts_with(" Key "));
        assert_eq!(t.run.stdout, "", "TS prints no table");
        assert_eq!(t.run.code, 0);
        let adapter = fx::adapter_id(1);
        let Some((r, t)) = sides(
            "d144_every_red_team_read_honours_output",
            &["adapter", "get", &adapter, "--output", "table"],
        ) else {
            return;
        };
        assert!(r.run.stdout.starts_with(" Key "));
        assert!(
            t.run.stdout.starts_with("uuid: "),
            "TS prints YAML: {:?}",
            t.run.stdout
        );
        let Some((r, t)) = sides(
            "d144_every_red_team_read_honours_output",
            &[
                "targets",
                "error-logs",
                &fx::target_id(1),
                "--output",
                "json",
            ],
        ) else {
            return;
        };
        let _: Value = r.run.json();
        assert!(
            t.run.stdout.starts_with(BANNER),
            "TS ignores --output for error-logs"
        );
    }

    /// D145: TypeScript prints the banner before the tenant is read (a failing run keeps
    /// it on stdout) and `--quiet` drops the dim ID lines; airs-cli-rs prints the banner
    /// only above data and keeps every data line.
    #[test]
    fn d145_banner_only_above_data_and_quiet_keeps_data() {
        let Some(ts) = require_ts("d145_banner_only_above_data_and_quiet_keeps_data") else {
            return;
        };
        let missing = fx::job_id(9);
        let r = exec(&rust(), &["status", &missing], &unchanged);
        let t = exec(&ts, &["status", &missing], &unchanged);
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(r.run.stdout, "");
        assert_eq!(t.run.stdout, BANNER);
        let r = exec(&rust(), &["--quiet", "list"], &unchanged);
        let t = exec(&ts, &["--quiet", "list"], &unchanged);
        assert!(
            r.run
                .stdout
                .starts_with(&format!("  {}\n    fixture-scan", fx::job_id(1)))
        );
        assert!(
            t.run.stdout.starts_with("    fixture-scan"),
            "{:?}",
            t.run.stdout
        );
    }

    /// D146: empty lists print `  No … found` in every TypeScript format; airs-cli-rs
    /// prints `[]` for json and nothing for table.
    #[test]
    fn d146_empty_lists_print_json_and_nothing_for_table() {
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.scans.clear();
            data.targets.clear();
        };
        let Some((r, t)) = sides_seeded(
            "d146_empty_lists_print_json_and_nothing_for_table",
            &["list", "--output", "json"],
            &seed,
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, "[]\n");
        assert_eq!(t.run.stdout, "  No scans found\n");
        let Some((r, t)) = sides_seeded(
            "d146_empty_lists_print_json_and_nothing_for_table",
            &["targets", "list", "--output", "table"],
            &seed,
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, "");
        assert_eq!(t.run.stdout, "  No targets found\n");
        let Some((r, t)) = sides_seeded(
            "d146_empty_lists_print_json_and_nothing_for_table",
            &["targets", "list"],
            &seed,
        ) else {
            return;
        };
        assert_bytes(&r, &t);
    }

    /// D147: TypeScript reads one prompt-set page, ignores `prompts list --offset`, and
    /// ends an `--all` walk silently at an empty page; airs-cli-rs walks every page,
    /// honours the flags and fails closed.
    #[test]
    fn d147_walks_are_complete_or_an_error() {
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.prompt_sets = (1..=60)
                .map(|n| fx::prompt_set(n, &format!("set-{n}"), true))
                .collect();
        };
        let Some((r, t)) = sides_seeded(
            "d147_walks_are_complete_or_an_error",
            &["prompt-sets", "list", "--output", "json"],
            &seed,
        ) else {
            return;
        };
        assert_eq!(r.run.json().as_array().unwrap().len(), 60);
        assert_eq!(
            t.run.json().as_array().unwrap().len(),
            50,
            "TS reads the server's first page"
        );
        assert_eq!(
            api(&t),
            ["GET /redteam/mgmt/v1/custom-attack/list-custom-prompt-sets"]
        );
        let set = fx::prompt_set_id(1);
        let Some((r, t)) = sides(
            "d147_walks_are_complete_or_an_error",
            &["prompts", "list", &set, "--offset", "1", "--output", "json"],
        ) else {
            return;
        };
        assert_eq!(r.run.json().as_array().unwrap().len(), 1);
        assert_eq!(
            t.run.json().as_array().unwrap().len(),
            2,
            "TS ignores --offset"
        );
        let empty_page = |data: &mut airs_test_harness::RedTeamData| {
            data.scans = (1..=20)
                .map(|n| fx::job(n, &format!("scan-{n}"), "COMPLETED", "STATIC"))
                .collect();
            data.total_override = Some(30);
        };
        let Some((r, t)) = sides_seeded(
            "d147_walks_are_complete_or_an_error",
            &["list", "--all", "--limit", "10", "--output", "json"],
            &empty_page,
        ) else {
            return;
        };
        r.run.assert_code(1);
        assert_eq!(r.run.stdout, "");
        t.run.assert_success();
        assert_eq!(
            t.run.json().as_array().unwrap().len(),
            20,
            "TS reports a partial list"
        );
        assert_eq!(r.requests, t.requests, "the same pages were read");
        let Some((r, t)) = sides(
            "d147_walks_are_complete_or_an_error",
            &["list", "--all", "--offset", "5"],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --all cannot be combined with --offset\n\n"
        );
        t.run.assert_success();
    }

    /// D148: TypeScript prints empty version-info counts (it reads keys the API does not
    /// send); airs-cli-rs prints the counts.
    #[test]
    fn d148_prompt_set_version_counts_are_shown() {
        let set = fx::prompt_set_id(1);
        let Some((r, t)) = sides(
            "d148_prompt_set_version_counts_are_shown",
            &["prompt-sets", "get", &set],
        ) else {
            return;
        };
        assert!(
            r.run
                .stdout
                .ends_with("  Total     4\n  Active    3\n  Inactive  1\n\n")
        );
        assert!(
            t.run
                .stdout
                .ends_with("  Total     \n  Active    \n  Inactive  \n\n")
        );
        let strip = |text: &str| {
            text.lines()
                .filter(|line| {
                    !line.starts_with("  Total")
                        && !line.starts_with("  Active")
                        && !line.starts_with("  Inactive")
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip(&r.run.stdout), strip(&t.run.stdout));
    }

    /// D153 (printing): the TypeScript SDK adds `ws_response_timeout: 110` to every
    /// parsed `connection_params` and `basic_auth_location: "HEADER"` to an `auth_config`
    /// without `auth_header`, and TypeScript prints them; airs-cli-rs (scm-sdk 0.1.1,
    /// without response defaults) prints only the fields the server sent. A value the
    /// server sent is printed by both, unchanged. The listing rows carry neither key
    /// (`json_documents_match_typescript`).
    #[test]
    fn d153_targets_print_only_the_fields_the_server_sent() {
        let Some(ts) = require_ts("d153_targets_print_only_the_fields_the_server_sent") else {
            return;
        };
        let ws = "connectionParams.ws_response_timeout";
        let location = "authConfig.basic_auth_location";
        let served = |data: &mut airs_test_harness::RedTeamData| {
            data.targets[0]["connection_params"]["ws_response_timeout"] = json!(30);
            data.targets[1]["auth_config"]["basic_auth_location"] = json!("QUERY");
        };
        // (the server sends the two keys, target, what TypeScript adds); target 3
        // (Bedrock) sends `basic_auth_location: "HEADER"` itself, target 4 has no
        // connection settings.
        for (sends, n, added) in [
            (false, 1, vec![ws]),
            (false, 2, vec![ws, location]),
            (false, 3, vec![ws]),
            (false, 4, vec![]),
            (true, 1, vec![]),
            (true, 2, vec![ws]),
        ] {
            let seed: &dyn Fn(&mut airs_test_harness::RedTeamData) =
                if sends { &served } else { &unchanged };
            let id = fx::target_id(n);
            let args = ["targets", "get", &id, "--output", "json"];
            let r = exec(&rust(), &args, seed);
            let t = exec(&ts, &args, seed);
            r.run.assert_success();
            t.run.assert_success();
            let (rust_doc, mut ts_doc) = (r.run.json(), t.run.json());
            for path in &added {
                let (settings, key) = path.split_once('.').unwrap();
                assert!(rust_doc[settings].get(key).is_none(), "{id}: {path}");
            }
            assert_eq!(
                strip_ts_target_defaults(&mut ts_doc, &rust_doc),
                added,
                "{id}"
            );
            let mut redacted = Vec::new();
            compare_redacted(&rust_doc, &ts_doc, "", &mut redacted);
            assert_eq!(r.requests, t.requests);
        }
        let r = exec(
            &rust(),
            &["targets", "get", &fx::target_id(3), "--output", "json"],
            &unchanged,
        );
        assert_eq!(r.run.json()["authConfig"]["basic_auth_location"], "HEADER");
        let r = exec(
            &rust(),
            &["targets", "get", &fx::target_id(1), "--output", "json"],
            &served,
        );
        assert_eq!(r.run.json()["connectionParams"]["ws_response_timeout"], 30);
        // Pretty: TypeScript's Connection block has the extra line.
        let id = fx::target_id(1);
        let r = exec(&rust(), &["targets", "get", &id], &unchanged);
        let t = exec(&ts, &["targets", "get", &id], &unchanged);
        assert!(
            !r.run.stdout.contains("ws_response_timeout"),
            "{}",
            r.run.stdout
        );
        assert!(
            t.run.stdout.contains("  ws_response_timeout  110\n"),
            "{}",
            t.run.stdout
        );
    }

    /// airs-cli-rs refuses `args` before the tenant with `message` (exit 2, nothing on
    /// stdout, no request); TypeScript sends them and lists, with `ts_line` among its
    /// requests (§15.23).
    fn assert_refused_first(name: &str, args: &[&str], message: &str, ts_line: &str) {
        let Some((r, t)) = sides(name, args) else {
            return;
        };
        assert_eq!(r.run.code, 2, "{args:?}{}", context(&r, &t));
        assert_eq!(r.run.stdout, "", "{args:?}");
        assert_eq!(r.run.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
        assert!(r.requests.is_empty(), "{args:?}: {:?}", r.lines);
        t.run.assert_success();
        assert!(
            api(&t).iter().any(|line| line == ts_line),
            "{args:?}: {:?}",
            api(&t)
        );
    }

    /// D300: TypeScript sends `targets error-logs --offset`/`--search` as `skip` and
    /// `search` (`0` and `""` included); airs-cli-rs refuses either whenever given, as
    /// the red team API declares only `limit` (scm-sdk 0.2.2 refuses the others).
    #[test]
    fn d300_error_log_offset_and_search_are_refused() {
        let target = fx::target_id(1);
        let offset = "--offset is not supported for target error logs (the red team API accepts only --limit)";
        let search = "--search is not supported for target error logs (the red team API accepts only --limit)";
        let path = format!("GET /redteam/data/v1/error-log/target-profile/{target}");
        for (args, message, ts_line) in [
            (
                vec!["targets", "error-logs", &target, "--offset", "0"],
                offset,
                format!("{path}?skip=0"),
            ),
            (
                vec!["targets", "error-logs", &target, "--search", "upstream"],
                search,
                format!("{path}?search=upstream"),
            ),
            // TS skips a falsy filter and sends nothing for `--search ""`.
            (
                vec!["targets", "error-logs", &target, "--search", ""],
                search,
                path.clone(),
            ),
            (
                vec![
                    "targets",
                    "error-logs",
                    &target,
                    "--offset",
                    "0",
                    "--limit",
                    "1",
                    "--search",
                    "upstream",
                ],
                offset,
                format!("{path}?skip=0&limit=1&search=upstream"),
            ),
        ] {
            assert_refused_first(
                "d300_error_log_offset_and_search_are_refused",
                &args,
                message,
                &ts_line,
            );
        }
    }

    /// D301 (`list`, `targets error-logs`): TypeScript sends any positive `--limit`;
    /// airs-cli-rs refuses more than 100, the contract's page bound, and sends 100.
    #[test]
    fn d301_data_plane_limits_are_at_most_100() {
        let target = fx::target_id(1);
        let message = "--limit must be at most 100 (the red team API maximum)";
        for (args, ts_line) in [
            (
                vec!["list", "--limit", "101", "--output", "json"],
                "GET /redteam/data/v1/scan?skip=0&limit=101".to_owned(),
            ),
            (
                vec!["list", "--all", "--limit", "500", "--output", "json"],
                "GET /redteam/data/v1/scan?skip=0&limit=500".to_owned(),
            ),
            (
                vec!["targets", "error-logs", &target, "--limit", "101"],
                format!("GET /redteam/data/v1/error-log/target-profile/{target}?limit=101"),
            ),
        ] {
            assert_refused_first(
                "d301_data_plane_limits_are_at_most_100",
                &args,
                message,
                &ts_line,
            );
        }
        let Some((r, t)) = sides(
            "d301_data_plane_limits_are_at_most_100",
            &["list", "--limit", "100", "--output", "json"],
        ) else {
            return;
        };
        assert_json(&r, &t);
        assert_eq!(api(&r), ["GET /redteam/data/v1/scan?skip=0&limit=100"]);
    }

    /// D302: TypeScript sends any `list --status`, `--type` and `--target` text;
    /// airs-cli-rs refuses a non-empty value outside the API vocabulary. The vendor
    /// values TypeScript's help leaves out (`PARTIALLY_COMPLETE`, `CLARA`) are sent by
    /// both, and `""` still sends nothing on both.
    #[test]
    fn d302_list_filters_use_the_api_vocabulary() {
        let statuses = "--status must be one of QUEUED, RUNNING, COMPLETED, PARTIALLY_COMPLETE, FAILED, ABORTED";
        for (args, message, ts_line) in [
            (
                vec!["list", "--status", "completed", "--output", "json"],
                statuses,
                "GET /redteam/data/v1/scan?skip=0&limit=10&status=completed",
            ),
            (
                vec!["list", "--status", "PROFILING", "--output", "json"],
                statuses,
                "GET /redteam/data/v1/scan?skip=0&limit=10&status=PROFILING",
            ),
            (
                vec!["list", "--type", "static", "--output", "json"],
                "--type must be one of STATIC, DYNAMIC, CUSTOM, CLARA",
                "GET /redteam/data/v1/scan?skip=0&limit=10&job_type=static",
            ),
            (
                vec!["list", "--target", "t-1", "--output", "json"],
                "--target must be a target UUID",
                "GET /redteam/data/v1/scan?skip=0&limit=10&target_id=t-1",
            ),
        ] {
            assert_refused_first(
                "d302_list_filters_use_the_api_vocabulary",
                &args,
                message,
                ts_line,
            );
        }
        for args in [
            ["list", "--status", "PARTIALLY_COMPLETE", "--output", "json"],
            ["list", "--type", "CLARA", "--output", "json"],
            ["list", "--status", "", "--output", "json"],
        ] {
            let Some((r, t)) = sides("d302_list_filters_use_the_api_vocabulary", &args) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.run.code, t.run.code, "{args:?}{}", context(&r, &t));
            assert_eq!(r.requests, t.requests, "{args:?}{}", context(&r, &t));
        }
    }

    /// D306: scm-sdk 0.2.2 ignores string formats in every response schema, so an
    /// adapter whose `created_by_user_id`, `updated_by_user_id` or stored channel is not a
    /// UUID is read and printed by airs-cli-rs, while TypeScript's zod schema refuses the
    /// answer (`AISEC_RESPONSE_VALIDATION`, exit 1), as 0.9.0 did. Both send the same
    /// requests.
    #[test]
    fn d306_adapter_answers_are_read_without_format_checks() {
        let seed = |data: &mut airs_test_harness::RedTeamData| {
            data.adapters[0]["created_by_user_id"] = json!("system");
            data.adapters[0]["updated_by_user_id"] = json!("system");
            data.adapters[0]["network_broker_channel_uuid"] = json!("chan-1");
        };
        let adapter = fx::adapter_id(1);
        for (args, field) in [
            (
                vec!["adapter", "list", "--output", "json"],
                "data.0.created_by_user_id: invalid_string",
            ),
            (
                vec!["adapter", "get", &adapter, "--output", "json"],
                ": invalid_string",
            ),
        ] {
            let Some((r, t)) = sides_seeded(
                "d306_adapter_answers_are_read_without_format_checks",
                &args,
                &seed,
            ) else {
                return;
            };
            assert_eq!(t.run.code, 1, "{args:?}{}", context(&r, &t));
            assert!(
                t.run
                    .stderr
                    .contains("AISEC_RESPONSE_VALIDATION:Response did not match schema: "),
                "{args:?}: {}",
                t.run.stderr
            );
            assert!(t.run.stderr.contains(field), "{args:?}: {}", t.run.stderr);
            r.run.assert_success();
            assert_eq!(r.requests, t.requests, "{args:?}{}", context(&r, &t));
            let doc = r.run.json();
            if args[1] == "list" {
                assert_eq!(doc[0]["uuid"], json!(adapter), "{doc}");
            } else {
                assert_eq!(doc["uuid"], json!(adapter), "{doc}");
                assert_eq!(doc["createdByUserId"], "system", "{doc}");
                assert_eq!(doc["updatedByUserId"], "system", "{doc}");
                assert_eq!(doc["networkBrokerChannelUuid"], "chan-1", "{doc}");
            }
        }
    }

    /// D327: `audio_curl` (management 0.86.0) is a curl template; TypeScript prints it
    /// raw, credentials included, while airs-cli-rs redacts it whole like `curl` (§15.4
    /// rule 3). Both read the n8n target (the TypeScript schemas pass the 0.86.0
    /// additions through) with the same request, and its basic credentials are
    /// `[REDACTED]` by rule 1 as before.
    #[test]
    fn d327_audio_curl_is_redacted() {
        let target = fx::target_id(2);
        let Some((r, t)) = sides_seeded(
            "d327_audio_curl_is_redacted",
            &["targets", "get", &target, "--output", "json"],
            &management_0_86,
        ) else {
            return;
        };
        assert_eq!(t.run.code, 0, "{}", context(&r, &t));
        r.run.assert_success();
        assert_eq!(r.requests, t.requests, "{}", context(&r, &t));
        let ts = t.run.json();
        assert!(
            ts["connectionParams"]["audio_curl"]
                .as_str()
                .is_some_and(|curl| curl.contains(&fx::secret(36))),
            "{ts}"
        );
        assert_eq!(ts["authConfig"]["basic_password"], fx::secret(38));
        let rust = r.run.json();
        assert_eq!(rust["connectionParams"]["audio_curl"], "[REDACTED]");
        assert_eq!(rust["authConfig"]["basic_password"], "[REDACTED]");
        assert_eq!(
            rust["connectionParams"]["audio_request_json"],
            ts["connectionParams"]["audio_request_json"]
        );
        assert_eq!(rust["connectionType"], ts["connectionType"]);
    }

    /// D329: a target answer with a Vertex AI connection config and the `client_session`
    /// multi-turn config (management 0.86.0) fails TypeScript's response schema
    /// (`AISEC_RESPONSE_VALIDATION`, exit 1), as it failed scm-sdk 0.2.2; airs-cli-rs
    /// (scm-sdk 0.2.3) reads and prints it, redacted, with the same request. The Vertex
    /// AI identifiers are redacted but never registered (§15.24 choice 12), so the
    /// `aiplatform` endpoint that holds them prints, never `[withheld]`.
    #[test]
    fn d329_management_0_86_target_answers_are_read() {
        let target = fx::target_id(1);
        for args in [
            vec!["targets", "get", target.as_str(), "--output", "json"],
            vec!["targets", "get", target.as_str()],
        ] {
            let Some((r, t)) = sides_seeded(
                "d329_management_0_86_target_answers_are_read",
                &args,
                &management_0_86,
            ) else {
                return;
            };
            assert_eq!(t.run.code, 1, "{args:?}{}", context(&r, &t));
            assert!(
                t.run
                    .stderr
                    .contains(
                        "AISEC_RESPONSE_VALIDATION:Response did not match schema: connection_params: invalid_union",
                    ),
                "{args:?}: {}",
                t.run.stderr
            );
            r.run.assert_success();
            assert_eq!(r.requests, t.requests, "{args:?}{}", context(&r, &t));
            // The json document carries the routing fields; both layouts the settings.
            if args.contains(&"json") {
                assert_eq!(r.run.json()["connectionType"], "VERTEX_AI");
                assert_eq!(r.run.json()["responseMode"], "REALTIME");
            }
            assert!(r.run.stdout.contains("client_session"), "{}", r.run.stdout);
            for shown in [fx::VERTEX_ENDPOINT, r#""project_id": "[REDACTED]""#] {
                assert!(r.run.stdout.contains(shown), "{shown}: {}", r.run.stdout);
            }
            assert!(!r.run.stdout.contains("[withheld]"), "{}", r.run.stdout);
            assert!(!r.run.stdout.contains("service@example-project"));
        }
    }
}
