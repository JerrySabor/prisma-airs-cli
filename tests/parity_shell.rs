//! TS-vs-Rust parity for the process shell (DESIGN §2): version, help, parse errors,
//! bare groups, global `--output` / `--quiet`, hyphen-leading values, BrokenPipe and
//! signals. Every scenario runs on a fresh sandbox + fixture server per CLI.
//!
//! Where DESIGN §12 lists a divergence, the test asserts BOTH sides' actual behaviour
//! and names the D# so a change on either side is detected. A missing or unverified reference CLI fails each test (`AIRS_ALLOW_PARITY_SKIP=1`
//! skips it with a `PARITY SKIPPED` notice).

use std::time::Duration;

use airs_test_harness::{
    Cli, ENDPOINT_KEYS, FixtureServer, NormalizedRequest, Planned, Route, Run, RunOptions, Sandbox,
    assert_json_semantic_eq, fixtures, normalize_all, require_ts, run, spawn,
};
use serde_json::Value;

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// What a scenario needs before the CLI runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tenant {
    /// One standard tenant `prod` (TSG 100), active; every endpoint on the fixture.
    Prod,
    /// No registry file: no tenant selected (the CLIs make no request).
    None,
}

struct Outcome {
    run: Run,
    requests: Vec<NormalizedRequest>,
    routes: Vec<Route>,
}

/// Runs `cli` with `args` on a fresh server + sandbox prepared by `tenant` and `setup`.
fn scenario(cli: &Cli, tenant: Tenant, setup: &dyn Fn(&FixtureServer), args: &[&str]) -> Outcome {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    if tenant == Tenant::Prod {
        let prod = sandbox.single_tenant(&server, "prod", "100");
        for key in ENDPOINT_KEYS {
            assert!(
                prod.config
                    .get_str(key)
                    .is_some_and(|value| value.starts_with(&server.base_url())),
                "{key} must point at the fixture server"
            );
        }
    }
    setup(&server);
    let before = sandbox.snapshot();
    let out = run(cli, &sandbox, args, &RunOptions::new());
    sandbox.assert_unchanged(&before);
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
    Outcome {
        requests: normalize_all(&server.requests()),
        routes: server.routes(),
        run: out,
    }
}

fn no_setup(_: &FixtureServer) {}

fn both(
    ts: &Cli,
    tenant: Tenant,
    setup: &dyn Fn(&FixtureServer),
    args: &[&str],
) -> (Outcome, Outcome) {
    (
        scenario(ts, tenant, setup, args),
        scenario(&rust(), tenant, setup, args),
    )
}

fn seed_profiles(server: &FixtureServer) {
    server.set_profiles(
        "100",
        vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(2, "beta", 1),
        ],
    );
}

/// Method, path, query, body and client identity (headers are SDK-specific).
fn wire(requests: &[NormalizedRequest]) -> Vec<String> {
    requests
        .iter()
        .map(|r| {
            format!(
                "{} {} {:?} {:?} {:?}",
                r.method, r.path, r.query, r.body, r.auth
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Version (D26: different product versions, same bare format)
// ---------------------------------------------------------------------------

/// D26: TS prints `7.2.1-forgejo.0`, Rust `0.1.0`; both bare, stdout only, exit 0.
#[test]
fn version_format_parity_d26() {
    let Some(ts) = require_ts("version_format_parity_d26") else {
        return;
    };
    for args in [&["-V"][..], &["--version"]] {
        let (t, r) = both(&ts, Tenant::Prod, &no_setup, args);
        assert_eq!((t.run.code, r.run.code), (0, 0), "{args:?}");
        assert_eq!(t.run.stdout, "7.2.1-forgejo.0\n");
        assert_eq!(r.run.stdout, concat!(env!("CARGO_PKG_VERSION"), "\n"));
        assert_eq!((t.run.stderr.as_str(), r.run.stderr.as_str()), ("", ""));
        for out in [&t, &r] {
            let line = out.run.stdout.trim_end_matches('\n');
            assert!(
                !line.contains(' ') && !line.contains("airs"),
                "bare version: {line:?}"
            );
            assert!(out.routes.is_empty());
        }
    }
}

#[test]
fn version_anywhere_before_double_dash_parity() {
    let Some(ts) = require_ts("version_anywhere_before_double_dash_parity") else {
        return;
    };
    for args in [
        &["doctor", "--version"][..],
        &["runtime", "scan", "--profile", "p", "hi", "-V"],
        &["runtime", "scan", "--profile", "-V", "hi"],
        &["runtime", "profiles", "list", "--bogus", "-V"],
        &["bogus", "-V"],
    ] {
        let (t, r) = both(&ts, Tenant::Prod, &no_setup, args);
        assert_eq!((t.run.code, r.run.code), (0, 0), "{args:?}");
        assert_eq!(t.run.stdout, "7.2.1-forgejo.0\n", "{args:?}");
        assert_eq!(
            r.run.stdout,
            concat!(env!("CARGO_PKG_VERSION"), "\n"),
            "{args:?}"
        );
        assert_eq!(
            (t.run.stderr.as_str(), r.run.stderr.as_str()),
            ("", ""),
            "{args:?}"
        );
        assert!(t.routes.is_empty() && r.routes.is_empty(), "{args:?}");
    }
}

/// D41: a root `--output` swallows `--version` as its value in TS (then the bare root
/// shows help, exit 1); the Rust pre-scan prints the version.
#[test]
fn d41_version_as_root_output_value() {
    let Some(ts) = require_ts("d41_version_as_root_output_value") else {
        return;
    };
    let (t, r) = both(&ts, Tenant::Prod, &no_setup, &["--output", "--version"]);
    assert_eq!(t.run.code, 1);
    assert_eq!(t.run.stdout, "");
    assert!(
        t.run
            .stderr
            .starts_with("Usage: airs-cli [options] [command]"),
        "{:?}",
        t.run.stderr
    );
    r.run.assert_success();
    assert_eq!(r.run.stdout, concat!(env!("CARGO_PKG_VERSION"), "\n"));
    assert!(t.routes.is_empty() && r.routes.is_empty());
}

/// D326: the TypeScript CLI is `airs-cli`; the Rust CLI is `airs`, and its 1.x
/// compatibility binary `airs-cli-rs` prints the same bytes (usage lines and help
/// examples name `airs` under either name, DESIGN §21.2).
#[test]
fn d326_the_program_is_airs_with_a_compatibility_name() {
    let Some(ts) = require_ts("d326_the_program_is_airs_with_a_compatibility_name") else {
        return;
    };
    let compat = Cli::rust(env!("CARGO_BIN_EXE_airs-cli-rs"));
    for (args, ts_text, rust_text) in [
        (
            &["--help"][..],
            "Usage: airs-cli [options] [command]",
            "Usage: airs [OPTIONS] [COMMAND]",
        ),
        (
            &["doctor", "--help"],
            "  $ airs-cli doctor\n",
            "  $ airs doctor\n",
        ),
        (
            &["runtime", "scan", "--help"],
            "  $ airs-cli runtime scan --profile prod-guard",
            "  $ airs runtime scan --profile prod-guard",
        ),
    ] {
        let (t, r) = both(&ts, Tenant::Prod, &no_setup, args);
        let c = scenario(&compat, Tenant::Prod, &no_setup, args);
        assert_eq!((t.run.code, r.run.code, c.run.code), (0, 0, 0), "{args:?}");
        assert!(t.run.stdout.contains(ts_text), "{args:?}: {}", t.run.stdout);
        assert!(
            r.run.stdout.contains(rust_text),
            "{args:?}: {}",
            r.run.stdout
        );
        assert!(
            !r.run.stdout.contains("airs-cli ") && !r.run.stdout.contains("airs-cli-rs"),
            "{args:?}: {}",
            r.run.stdout
        );
        assert_eq!(
            (c.run.stdout.as_str(), c.run.stderr.as_str()),
            (r.run.stdout.as_str(), r.run.stderr.as_str()),
            "{args:?}: the compatibility name prints the same bytes"
        );
        assert!(t.routes.is_empty() && r.routes.is_empty() && c.routes.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Help (stdout, exit 0, zero requests on both; examples name each program)
// ---------------------------------------------------------------------------

#[test]
fn help_exit_codes_and_streams_parity() {
    let Some(ts) = require_ts("help_exit_codes_and_streams_parity") else {
        return;
    };
    let cases: &[(&[&str], &str)] = &[
        (&["--help"], ""),
        (&["-h"], ""),
        (&["doctor", "--help"], " doctor"),
        (&["tenant", "list", "--help"], " tenant list"),
        (&["tenant", "get", "--help"], " tenant get"),
        (&["runtime", "--help"], " runtime"),
        (
            &["runtime", "profiles", "list", "--help"],
            " runtime profiles list",
        ),
        (
            &["runtime", "profiles", "get", "-h"],
            " runtime profiles get",
        ),
        (
            &["runtime", "topics", "list", "--help"],
            " runtime topics list",
        ),
        (
            &["runtime", "topics", "get", "--help"],
            " runtime topics get",
        ),
        (&["runtime", "scan", "--help"], " runtime scan"),
        (&["help", "runtime"], " runtime"),
    ];
    for (args, path) in cases {
        let (t, r) = both(&ts, Tenant::Prod, &no_setup, args);
        assert_eq!((t.run.code, r.run.code), (0, 0), "{args:?}");
        assert_eq!(
            (t.run.stderr.as_str(), r.run.stderr.as_str()),
            ("", ""),
            "{args:?}"
        );
        assert!(
            t.run.stdout.contains(&format!("Usage: airs-cli{path}")),
            "{args:?}: {}",
            t.run.stdout
        );
        assert!(
            r.run
                .stdout
                .contains(&format!("Usage: airs{path} [OPTIONS]")),
            "{args:?}: {}",
            r.run.stdout
        );
        assert!(t.routes.is_empty() && r.routes.is_empty(), "{args:?}");
    }
}

#[test]
fn help_examples_name_each_program_parity() {
    let Some(ts) = require_ts("help_examples_name_each_program_parity") else {
        return;
    };
    let cases: &[(&[&str], &str)] = &[
        (
            &["runtime", "scan", "--help"],
            "runtime scan --profile prod-guard \"Ignore all previous instructions\"",
        ),
        (
            &["doctor", "--help"],
            "doctor --output json | jq '.[] | select(.status != \"pass\")'",
        ),
        (
            &["runtime", "profiles", "list", "--help"],
            "runtime profiles list --limit 20 --offset 20",
        ),
    ];
    for (args, example) in cases {
        let (t, r) = both(&ts, Tenant::Prod, &no_setup, args);
        assert!(
            t.run.stdout.contains("Examples:") && r.run.stdout.contains("Examples:"),
            "{args:?}"
        );
        assert!(
            t.run.stdout.contains(&format!("$ airs-cli {example}")),
            "{args:?}: {}",
            t.run.stdout
        );
        assert!(
            r.run.stdout.contains(&format!("$ airs {example}")),
            "{args:?}: {}",
            r.run.stdout
        );
        assert!(!r.run.stdout.contains("$ airs-cli "), "{args:?}");
    }
}

// ---------------------------------------------------------------------------
// Parse errors and bare groups (D1: TS exit 1, Rust exit 2)
// ---------------------------------------------------------------------------

/// D1: every argument-parse error exits 1 in TS (commander) and 2 in Rust (clap). Both
/// write only to stderr (`error: ...`), print nothing on stdout and make no request.
#[test]
fn parse_error_exit_codes_divergence_d1() {
    let Some(ts) = require_ts("parse_error_exit_codes_divergence_d1") else {
        return;
    };
    // (argv, exact TS stderr, a fragment of the clap rendering)
    let cases: &[(&[&str], &str, &str)] = &[
        (
            &["runtime", "profiles", "list", "--bogus"],
            "error: unknown option '--bogus'\n",
            "'--bogus'",
        ),
        (
            &["runtime", "bogus"],
            "error: unknown command 'bogus'\n",
            "'bogus'",
        ),
        (
            &["runtime", "profiles", "get"],
            "error: missing required argument 'nameOrId'\n",
            "<nameOrId>",
        ),
        (
            &["runtime", "topics", "get"],
            "error: missing required argument 'nameOrId'\n",
            "<nameOrId>",
        ),
        (
            &["tenant", "get", "prod"],
            "error: missing required argument 'key'\n",
            "<key>",
        ),
        (
            &["runtime", "scan", "q"],
            "error: required option '--profile <name>' not specified\n",
            "--profile <name>",
        ),
        (
            &["runtime", "profiles", "list", "extra"],
            "error: too many arguments for 'list'. Expected 0 arguments but got 1.\n",
            "'extra'",
        ),
        (
            &["doctor", "now"],
            "error: too many arguments for 'doctor'. Expected 0 arguments but got 1.\n",
            "'now'",
        ),
        (
            &["doctor", "--output"],
            "error: option '--output <format>' argument missing\n",
            "a value is required",
        ),
        (
            &["runtime", "scan", "--profile", "p", "-ignore"],
            "error: unknown option '-ignore'\n",
            "'-i'",
        ),
        (&["-v"], "error: unknown option '-v'\n", "'-v'"),
    ];
    for (args, ts_stderr, clap_fragment) in cases {
        let (t, r) = both(&ts, Tenant::Prod, &no_setup, args);
        assert_eq!(t.run.code, 1, "{args:?}: TS (commander) exit");
        assert_eq!(r.run.code, 2, "{args:?}: Rust (clap) exit");
        assert_eq!(
            (t.run.stdout.as_str(), r.run.stdout.as_str()),
            ("", ""),
            "{args:?}"
        );
        assert_eq!(t.run.stderr, *ts_stderr, "{args:?}");
        assert!(
            r.run.stderr.starts_with("error: "),
            "{args:?}: {:?}",
            r.run.stderr
        );
        assert!(
            r.run.stderr.contains(clap_fragment),
            "{args:?}: {:?}",
            r.run.stderr
        );
        assert!(t.routes.is_empty() && r.routes.is_empty(), "{args:?}");
    }
}

/// D1 (bare group): both print the group's help on stderr with empty stdout and no
/// request; TS exits 1, Rust 2.
#[test]
fn bare_group_divergence_d1() {
    let Some(ts) = require_ts("bare_group_divergence_d1") else {
        return;
    };
    let cases: &[(&[&str], &str)] = &[
        (&[], ""),
        (&["--quiet"], ""),
        (&["runtime"], " runtime"),
        (&["runtime", "profiles"], " runtime profiles"),
        (&["runtime", "topics"], " runtime topics"),
        (&["tenant"], " tenant"),
    ];
    for (args, path) in cases {
        let (t, r) = both(&ts, Tenant::Prod, &no_setup, args);
        assert_eq!((t.run.code, r.run.code), (1, 2), "{args:?}");
        assert_eq!(
            (t.run.stdout.as_str(), r.run.stdout.as_str()),
            ("", ""),
            "{args:?}"
        );
        assert!(
            t.run
                .stderr
                .starts_with(&format!("Usage: airs-cli{path} [options] [command]")),
            "{args:?}: {:?}",
            t.run.stderr
        );
        assert!(
            r.run
                .stderr
                .contains(&format!("Usage: airs{path} [OPTIONS] [COMMAND]")),
            "{args:?}: {:?}",
            r.run.stderr
        );
        assert!(t.routes.is_empty() && r.routes.is_empty(), "{args:?}");
    }
}

// ---------------------------------------------------------------------------
// Global --output: validation, D2 ordering, placement, last-wins, `=` form
// ---------------------------------------------------------------------------

const RUST_INVALID_XML: &str =
    "\n  ✗ Invalid output format 'xml'. Expected: pretty, table, json\n\n";
const TS_INVALID_XML: &str =
    "\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n";

#[test]
fn invalid_output_with_tenant_parity() {
    let Some(ts) = require_ts("invalid_output_with_tenant_parity") else {
        return;
    };
    for args in [
        &["runtime", "profiles", "list", "--output", "xml"][..],
        &["--output", "xml", "runtime", "topics", "list"],
        &["runtime", "profiles", "get", "alpha", "--output=xml"],
    ] {
        let (t, r) = both(&ts, Tenant::Prod, &no_setup, args);
        assert_eq!((t.run.code, r.run.code), (2, 2), "{args:?}");
        // The same usage error; TS lists its six names, airs-cli-rs the three (D50).
        assert_eq!(t.run.stderr, TS_INVALID_XML, "{args:?}");
        assert_eq!(r.run.stderr, RUST_INVALID_XML, "{args:?}");
        assert_eq!((t.run.stdout.as_str(), r.run.stdout.as_str()), ("", ""));
        assert!(t.routes.is_empty() && r.routes.is_empty(), "{args:?}");
    }
}

/// D2: TS loads the tenant before validating `--output`, so a bad format with no tenant
/// selected exits 1 with the no-tenant error; Rust validates usage first (exit 2).
#[test]
fn invalid_output_without_tenant_divergence_d2() {
    let Some(ts) = require_ts("invalid_output_without_tenant_divergence_d2") else {
        return;
    };
    let args = ["runtime", "profiles", "list", "--output", "xml"];
    let (t, r) = both(&ts, Tenant::None, &no_setup, &args);
    assert_eq!(t.run.code, 1);
    assert_eq!(
        t.run.stderr,
        "\n  ✗ Error: No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'\n\n"
    );
    assert_eq!(r.run.code, 2);
    assert_eq!(r.run.stderr, RUST_INVALID_XML);
    assert_eq!((t.run.stdout.as_str(), r.run.stdout.as_str()), ("", ""));
    assert!(t.routes.is_empty() && r.routes.is_empty());
}

#[test]
fn output_placement_last_wins_and_equals_form_parity() {
    let Some(ts) = require_ts("output_placement_last_wins_and_equals_form_parity") else {
        return;
    };
    for args in [
        &["--output", "json", "runtime", "profiles", "list"][..],
        &["runtime", "profiles", "list", "--output", "json"],
        &[
            "--output", "yaml", "runtime", "profiles", "list", "--output", "json",
        ],
        &["--output=json", "runtime", "profiles", "ls"],
    ] {
        let (t, r) = both(&ts, Tenant::Prod, &seed_profiles, args);
        assert_eq!(
            (t.run.code, r.run.code),
            (0, 0),
            "{args:?}\n{}\n{}",
            t.run.stderr,
            r.run.stderr
        );
        assert_json_semantic_eq(&t.run.json(), &r.run.json());
        assert_eq!(t.run.stderr, "  Showing 2\n", "{args:?}");
        assert_eq!(r.run.stderr, t.run.stderr, "{args:?}");
        assert_eq!(t.routes, vec![Route::Token, Route::Profiles], "{args:?}");
        assert_eq!(wire(&t.requests), wire(&r.requests), "{args:?}");
    }
}

#[test]
fn last_output_invalid_wins_parity() {
    let Some(ts) = require_ts("last_output_invalid_wins_parity") else {
        return;
    };
    let args = [
        "--output", "json", "runtime", "profiles", "list", "--output", "xml",
    ];
    let (t, r) = both(&ts, Tenant::Prod, &no_setup, &args);
    assert_eq!((t.run.code, r.run.code), (2, 2));
    assert_eq!(
        (t.run.stderr.as_str(), r.run.stderr.as_str()),
        (TS_INVALID_XML, RUST_INVALID_XML)
    );
    assert!(t.routes.is_empty() && r.routes.is_empty());
}

// ---------------------------------------------------------------------------
// --quiet and hyphen-leading values
// ---------------------------------------------------------------------------

#[test]
fn quiet_list_parity() {
    let Some(ts) = require_ts("quiet_list_parity") else {
        return;
    };
    for args in [
        &["--quiet", "runtime", "profiles", "list", "--output", "json"][..],
        &["runtime", "profiles", "list", "--output", "json", "--quiet"],
    ] {
        let (t, r) = both(&ts, Tenant::Prod, &seed_profiles, args);
        assert_eq!((t.run.code, r.run.code), (0, 0), "{args:?}");
        assert_eq!(
            (t.run.stderr.as_str(), r.run.stderr.as_str()),
            ("", ""),
            "{args:?}"
        );
        assert_json_semantic_eq(&t.run.json(), &r.run.json());
        assert_eq!(wire(&t.requests), wire(&r.requests));
    }
}

#[test]
fn quiet_scan_parity() {
    let Some(ts) = require_ts("quiet_scan_parity") else {
        return;
    };
    let args = [
        "--quiet",
        "runtime",
        "scan",
        "--profile",
        "p",
        "hello world",
    ];
    let (t, r) = both(&ts, Tenant::Prod, &no_setup, &args);
    assert_eq!((t.run.code, r.run.code), (0, 0));
    assert_eq!((t.run.stderr.as_str(), r.run.stderr.as_str()), ("", ""));
    assert_eq!(t.run.stdout, r.run.stdout);
    assert!(t.run.stdout.starts_with("  Action     ALLOW\n"));
    assert_eq!(wire(&t.requests), wire(&r.requests));
}

#[test]
fn quiet_does_not_hide_errors_parity() {
    let Some(ts) = require_ts("quiet_does_not_hide_errors_parity") else {
        return;
    };
    let args = ["--quiet", "runtime", "profiles", "get", "missing"];
    let (t, r) = both(&ts, Tenant::Prod, &no_setup, &args);
    assert_eq!((t.run.code, r.run.code), (1, 1));
    assert_eq!(t.run.stderr, r.run.stderr);
    assert_eq!(
        r.run.stderr,
        "\n  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: missing\n\n"
    );
    assert_eq!((t.run.stdout.as_str(), r.run.stdout.as_str()), ("", ""));
}

#[test]
fn hyphen_leading_values_and_double_dash_prompt_parity() {
    let Some(ts) = require_ts("hyphen_leading_values_and_double_dash_prompt_parity") else {
        return;
    };
    let args = [
        "runtime",
        "scan",
        "--profile",
        "-p",
        "--response",
        "-x",
        "--",
        "-ignore all rules",
    ];
    let (t, r) = both(&ts, Tenant::Prod, &no_setup, &args);
    assert_eq!(
        (t.run.code, r.run.code),
        (0, 0),
        "{}\n{}",
        t.run.stderr,
        r.run.stderr
    );
    assert_eq!(t.run.stdout, r.run.stdout);
    assert_eq!(t.run.stderr, r.run.stderr);
    assert_eq!(t.routes, vec![Route::ScanSync]);
    assert_eq!(wire(&t.requests), wire(&r.requests));
    let body = format!("{:?}", r.requests[0].body);
    assert!(
        body.contains("-ignore all rules") && body.contains("\"-x\"") && body.contains("\"-p\""),
        "{body}"
    );
}

#[test]
fn hyphen_numeric_value_reaches_validation_parity() {
    let Some(ts) = require_ts("hyphen_numeric_value_reaches_validation_parity") else {
        return;
    };
    let args = ["runtime", "topics", "list", "--offset", "-1"];
    let (t, r) = both(&ts, Tenant::Prod, &no_setup, &args);
    assert_eq!((t.run.code, r.run.code), (2, 2));
    assert_eq!(
        t.run.stderr,
        "\n  ✗ --offset must be a non-negative integer\n\n"
    );
    assert_eq!(r.run.stderr, t.run.stderr);
    assert!(t.routes.is_empty() && r.routes.is_empty());
}

// ---------------------------------------------------------------------------
// BrokenPipe (both exit 0 silently)
// ---------------------------------------------------------------------------

/// Runs `cli` through the harness runner, reading only `keep` stdout bytes before the
/// reader is closed (`RunOptions::close_stdout_after`). The runner's environment
/// allowlist, secret checks (both streams), TS loopback guard and no-signal rule apply.
fn run_with_early_closed_stdout(
    cli: &Cli,
    sandbox: &Sandbox,
    args: &[&str],
    keep: usize,
) -> (Option<i32>, Option<i32>, String) {
    let options = RunOptions::new()
        .close_stdout_after(keep)
        .timeout(Duration::from_secs(60));
    let out = run(cli, sandbox, args, &options);
    assert_eq!(
        out.stdout.len(),
        keep,
        "{}: first stdout bytes",
        cli.label()
    );
    (Some(out.code), out.signal, out.stderr)
}

#[test]
fn broken_pipe_exits_0_parity() {
    let Some(ts) = require_ts("broken_pipe_exits_0_parity") else {
        return;
    };
    let args = [
        "runtime", "profiles", "list", "--all", "--limit", "500", "--output", "json",
    ];
    let mut results = Vec::new();
    for cli in [&ts, &rust()] {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", "100");
        let rows: Vec<Value> = (1..=3000)
            .map(|n| fixtures::profile(n, &format!("profile-{n:05}"), 1))
            .collect();
        server.set_profiles("100", rows);
        let before = sandbox.snapshot();
        let (code, signal, stderr) = run_with_early_closed_stdout(cli, &sandbox, &args, 16);
        sandbox.assert_unchanged(&before);
        assert_eq!(
            (code, signal),
            (Some(0), None),
            "{}: {stderr:?}",
            cli.label()
        );
        assert!(
            !stderr.contains("EPIPE") && !stderr.contains("panicked"),
            "{}: {stderr:?}",
            cli.label()
        );
        results.push((stderr, server.routes()));
    }
    assert_eq!(
        results[0], results[1],
        "same status line and request sequence"
    );
}

// ---------------------------------------------------------------------------
// Signals (D32: TS dies by the signal with no output; Rust cancels, reports, 130/143)
// ---------------------------------------------------------------------------

fn interrupted(cli: &Cli, signal: &str) -> (Run, Vec<Route>, usize) {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", "100");
    server.push_once(Route::Profiles, Planned::hang());
    let before = sandbox.snapshot();
    let running = spawn(
        cli,
        &sandbox,
        &["runtime", "profiles", "list", "--output", "json"],
        &RunOptions::new()
            .expect_signal()
            .timeout(Duration::from_secs(30)),
    );
    assert!(
        server.wait_for_requests(2, Duration::from_secs(15)),
        "{}: {:?}",
        cli.label(),
        server.routes()
    );
    running.send_signal(signal);
    let out = running.wait();
    sandbox.assert_unchanged(&before);
    assert!(
        server.wait_for_disconnects(1, Duration::from_secs(10)),
        "{}: the fixture did not observe the disconnect",
        cli.label()
    );
    assert!(
        !server.wait_for_requests(3, Duration::from_millis(300)),
        "{}: requests after the signal",
        cli.label()
    );
    (out, server.routes(), server.disconnects())
}

/// D32: SIGINT during a hung profiles request.
#[test]
fn sigint_divergence_d32() {
    let Some(ts) = require_ts("sigint_divergence_d32") else {
        return;
    };
    let (t, t_routes, _) = interrupted(&ts, "INT");
    assert_eq!(
        (t.signal, t.code),
        (Some(2), 130),
        "TS dies by SIGINT: {t:?}"
    );
    assert_eq!((t.stdout.as_str(), t.stderr.as_str()), ("", ""));
    let (r, r_routes, _) = interrupted(&rust(), "INT");
    assert_eq!((r.signal, r.code), (None, 130), "{r:?}");
    assert_eq!(r.stdout, "");
    assert_eq!(
        r.stderr,
        "\n  ✗ Error: Interrupted; no data was written\n\n"
    );
    assert_eq!(t_routes, vec![Route::Token, Route::Profiles]);
    assert_eq!(r_routes, t_routes);
}

/// D32: SIGTERM during a hung profiles request.
#[test]
fn sigterm_divergence_d32() {
    let Some(ts) = require_ts("sigterm_divergence_d32") else {
        return;
    };
    let (t, t_routes, _) = interrupted(&ts, "TERM");
    assert_eq!(
        (t.signal, t.code),
        (Some(15), 143),
        "TS dies by SIGTERM: {t:?}"
    );
    assert_eq!((t.stdout.as_str(), t.stderr.as_str()), ("", ""));
    let (r, r_routes, _) = interrupted(&rust(), "TERM");
    assert_eq!((r.signal, r.code), (None, 143), "{r:?}");
    assert_eq!(r.stdout, "");
    assert_eq!(
        r.stderr,
        "\n  ✗ Error: Interrupted; no data was written\n\n"
    );
    assert_eq!(r_routes, t_routes);
}
