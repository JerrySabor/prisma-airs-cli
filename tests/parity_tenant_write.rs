//! TS-vs-Rust parity for the tenant write commands (DESIGN §3.9–§3.11, §10 "Write
//! parity") and the `dNN_` pins of the §12 rows they introduce or extend (D33, D51,
//! D52, D59, D73–D88).
//!
//! Each scenario runs both CLIs in the same sandbox. Each writes only its own files:
//! airs-cli-rs its TOML store under `store/`, the TypeScript CLI its registry and
//! managed configs under `state/` (`allow_writes_under`). Exit codes and outcome or
//! error text are compared after `normalise_tenant_output` (each side's paths as
//! `<REGISTRY>` / `<CONFIG:name>`, `airs` in hints as `airs-cli`). TypeScript
//! prints outcome lines on stdout and airs-cli-rs on stderr (D74), so those are
//! compared across streams. Then the resulting state is compared through `tenant list`,
//! `tenant read` and `tenant get` on both CLIs. A missing or unverified TypeScript
//! reference fails the tests (`AIRS_ALLOW_PARITY_SKIP=1` skips them with a notice).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use airs_test_harness::{
    Cli, FixtureConfig, FixtureServer, PtyRun, RegistryEntry, Run, RunOptions, Sandbox, error_line,
    normalise_tenant_output, require_ts, run, spawn_pty, ts_rows_as_rust, usage_line,
};
use serde_json::Value;

const SECRET: &str = "FAKE-SECRET-PW1";
const CANCELLED: &str = "  Cancelled; no configuration saved.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// The options for `cli`: airs-cli-rs may write `store/`, TypeScript `state/`.
fn writes(cli: &Cli) -> RunOptions {
    let options = RunOptions::new().secret(SECRET);
    if cli.is_ts() {
        options.allow_writes_under("state")
    } else {
        options.allow_writes_under("store")
    }
}

/// Text with each side's paths and program name normalised and the root as `<ROOT>`.
fn norm(sandbox: &Sandbox, text: &str) -> String {
    normalise_tenant_output(text, sandbox).replace(&sandbox.root().display().to_string(), "<ROOT>")
}

/// Runs `args` on airs-cli-rs, then on the TypeScript CLI, in the same sandbox.
fn both(
    sandbox: &Sandbox,
    ts: &Cli,
    args: &[&str],
    options: impl Fn(&Cli) -> RunOptions,
) -> (Run, Run) {
    let rust = run(&rust(), sandbox, args, &options(&rust()));
    let ts = run(ts, sandbox, args, &options(ts));
    (rust, ts)
}

/// Same exit code; airs-cli-rs's stdout empty; its stderr equal (normalised) to
/// TypeScript's outcome lines on stdout plus its stderr.
fn assert_same_outcome(sandbox: &Sandbox, rust: &Run, ts: &Run) {
    assert_eq!(rust.code, ts.code, "exit codes\nrust: {rust:?}\nts: {ts:?}");
    assert_eq!(rust.stdout, "", "airs prints no data: {rust:?}");
    assert_eq!(
        norm(sandbox, &rust.stderr),
        norm(sandbox, &format!("{}{}", ts.stdout, ts.stderr)),
        "\nrust: {rust:?}\nts: {ts:?}"
    );
}

/// The state both CLIs now see agrees: `tenant list --output json` (rows and status),
/// and for each name `tenant read <name> --output json` (TypeScript rows mapped through
/// the import conversion) and `tenant get <name> <key> --output json` for `keys`.
fn assert_same_state(sandbox: &Sandbox, ts: &Cli, names: &[&str], keys: &[&str]) {
    let read =
        |cli: &Cli, args: &[&str]| run(cli, sandbox, args, &RunOptions::new().secret(SECRET));
    let list = ["tenant", "list", "--output", "json"];
    let (r, t) = (read(&rust(), &list), read(ts, &list));
    assert_eq!(
        (r.code, norm(sandbox, &r.stdout), norm(sandbox, &r.stderr)),
        (t.code, norm(sandbox, &t.stdout), norm(sandbox, &t.stderr)),
        "tenant list"
    );
    for name in names {
        let args = ["tenant", "read", name, "--output", "json"];
        let (r, t) = (read(&rust(), &args), read(ts, &args));
        assert_eq!(r.code, t.code, "tenant read {name}: {r:?} {t:?}");
        assert_eq!(
            norm(sandbox, &r.stderr),
            norm(sandbox, &t.stderr),
            "tenant read {name}"
        );
        if r.code == 0 {
            assert_eq!(
                r.json(),
                ts_rows_as_rust(&t.json(), false),
                "tenant read {name}"
            );
        }
        for key in keys {
            let args = ["tenant", "get", name, key, "--output", "json"];
            let (r, t) = (read(&rust(), &args), read(ts, &args));
            assert_eq!(r.code, t.code, "tenant get {name} {key}");
            if r.code == 0 {
                assert_eq!(
                    r.json(),
                    ts_rows_as_rust(&t.json(), true),
                    "tenant get {name} {key}"
                );
            }
        }
    }
}

fn create_args<'a>(name: &'a str, tsg: &'a str, client: &'a str) -> Vec<&'a str> {
    vec![
        "tenant",
        "create",
        name,
        "--tsg-id",
        tsg,
        "--client-id",
        client,
        "--client-secret-stdin",
    ]
}

/// `tenant create <name>` on both CLIs through the stdin flags.
fn create_both(sandbox: &Sandbox, ts: &Cli, name: &str, tsg: &str) -> (Run, Run) {
    let client = format!("client-{tsg}");
    let (r, t) = both(sandbox, ts, &create_args(name, tsg, &client), |cli| {
        writes(cli).stdin(format!("{SECRET}\n"))
    });
    r.assert_success();
    t.assert_success();
    (r, t)
}

/// A TypeScript config both CLIs can rewrite (mode 0600), registered as `name` with the
/// registry TSG `registry_tsg`; the store is provisioned from it (DESIGN §10).
fn writable_tenant(
    sandbox: &Sandbox,
    server: &FixtureServer,
    name: &str,
    registry_tsg: &str,
    edit: impl Fn(&mut FixtureConfig),
) {
    let mut config = Sandbox::fixture_config(server, registry_tsg);
    edit(&mut config);
    let path = sandbox.write_file(
        &format!("configs/{name}.json"),
        config.to_json().as_bytes(),
        0o600,
    );
    sandbox.write_registry(&[RegistryEntry::new(name, &path, registry_tsg)], None);
}

fn pty_run(
    cli: &Cli,
    sandbox: &Sandbox,
    args: &[&str],
    options: RunOptions,
    script: &[(&str, &[u8])],
) -> PtyRun {
    let mut session = spawn_pty(cli, sandbox, args, &options);
    for (expect, send) in script {
        session.expect(expect);
        // Inquirer starts reading once its prompt is drawn; give it a moment.
        std::thread::sleep(std::time::Duration::from_millis(100));
        session.send(send);
    }
    session.wait()
}

/// A transcript without escape sequences, carriage returns or inquirer's redraws: the
/// visible prompt texts, in order (D88: rendering is not a parity surface).
fn visible_prompts(transcript: &str) -> Vec<String> {
    let mut plain = String::new();
    let mut chars = transcript.chars().peekable();
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
    let mut prompts: Vec<String> = Vec::new();
    for line in plain.split('\n') {
        let Some(rest) = line.rfind("? ").map(|index| &line[index + 2..]) else {
            continue;
        };
        let message = rest.split(':').next().unwrap_or_default().to_owned() + ":";
        if prompts.last() != Some(&message) {
            prompts.push(message);
        }
    }
    prompts
}

mod create {
    use super::*;

    #[test]
    fn stdin_flags_register_the_same_tenant() {
        let Some(ts) = require_ts("create_stdin_flags") else {
            return;
        };
        let sandbox = Sandbox::new();
        let (r, t) = create_both(&sandbox, &ts, "dev", "100");
        assert_same_outcome(&sandbox, &r, &t);
        assert_same_state(
            &sandbox,
            &ts,
            &["dev"],
            &[
                "mgmtClientSecret",
                "mgmtTsgId",
                "mgmtClientId",
                "scanConcurrency",
            ],
        );
    }

    #[test]
    fn guided_prompts_ask_the_same_questions() {
        let Some(ts) = require_ts("create_guided") else {
            return;
        };
        let sandbox = Sandbox::new();
        let script: [(&str, &[u8]); 3] = [
            ("(mgmtTsgId):", b"100\r"),
            ("(mgmtClientId):", b"client-100\r"),
            ("[input is masked]", b"FAKE-SECRET-PW1\r"),
        ];
        let r = pty_run(
            &rust(),
            &sandbox,
            &["tenant", "create", "dev"],
            writes(&rust()),
            &script,
        );
        let t = pty_run(
            &ts,
            &sandbox,
            &["tenant", "create", "dev"],
            writes(&ts),
            &script,
        );
        assert_eq!((r.run.code, t.run.code), (0, 0), "{r:?}\n{t:?}");
        let expected = [
            "Tenant service group ID (mgmtTsgId):",
            "OAuth client ID (mgmtClientId):",
            "OAuth client secret (mgmtClientSecret):",
        ];
        assert_eq!(visible_prompts(&r.transcript), expected);
        assert_eq!(visible_prompts(&t.transcript), expected);
        let outcome = "  ✓ Registered dev (TSG 100); private config created. Use airs-cli tenant switch dev.\n";
        assert_eq!(t.run.stdout, outcome);
        assert!(norm(&sandbox, &r.transcript.replace("\r\n", "\n")).ends_with(outcome));
        assert_same_state(&sandbox, &ts, &["dev"], &["mgmtClientId"]);
    }

    #[test]
    fn a_blank_answer_is_asked_again_on_both() {
        let Some(ts) = require_ts("create_blank_answer") else {
            return;
        };
        let sandbox = Sandbox::new();
        let script: [(&str, &[u8]); 4] = [
            ("(mgmtTsgId):", b"\r"),
            ("A nonempty value is required", b"100\r"),
            ("(mgmtClientId):", b"client-100\r"),
            ("[input is masked]", b"FAKE-SECRET-PW1\r"),
        ];
        let r = pty_run(
            &rust(),
            &sandbox,
            &["tenant", "create", "dev"],
            writes(&rust()),
            &script,
        );
        let t = pty_run(
            &ts,
            &sandbox,
            &["tenant", "create", "dev"],
            writes(&ts),
            &script,
        );
        assert_eq!((r.run.code, t.run.code), (0, 0), "{r:?}\n{t:?}");
        assert!(r.transcript.contains("> A nonempty value is required"));
        assert!(t.transcript.contains("> A nonempty value is required"));
        assert_same_state(&sandbox, &ts, &["dev"], &["mgmtTsgId"]);
    }

    #[test]
    fn ctrl_c_at_a_prompt_cancels_with_130_on_both() {
        let Some(ts) = require_ts("create_ctrl_c") else {
            return;
        };
        let sandbox = Sandbox::new();
        let mut session = spawn_pty(
            &rust(),
            &sandbox,
            &["tenant", "create", "dev"],
            &RunOptions::new(),
        );
        session.expect("(mgmtTsgId):");
        session.signal("INT");
        let r = session.wait();
        // TypeScript reads the terminal raw: Ctrl-C arrives as a byte.
        let t = pty_run(
            &ts,
            &sandbox,
            &["tenant", "create", "dev"],
            RunOptions::new(),
            &[("(mgmtTsgId):", b"\x03")],
        );
        assert_eq!((r.run.code, t.run.code), (130, 130));
        for out in [&r, &t] {
            assert!(out.transcript.contains(CANCELLED), "{:?}", out.transcript);
            assert_eq!(out.run.stdout, "");
            assert!(out.echo_restored());
        }
        assert_same_state(&sandbox, &ts, &[], &[]);
    }

    #[test]
    fn an_existing_name_is_refused_by_both() {
        let Some(ts) = require_ts("create_existing") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let (r, t) = both(&sandbox, &ts, &create_args("dev", "200", "c"), |_| {
            RunOptions::new()
                .secret(SECRET)
                .stdin(format!("{SECRET}\n"))
        });
        assert_same_outcome(&sandbox, &r, &t);
        assert_eq!(
            r.error_line().as_deref(),
            Some("Tenant name already exists")
        );
        assert_same_state(&sandbox, &ts, &["dev"], &["mgmtTsgId"]);
    }
}

mod set {
    use super::*;

    #[test]
    fn values_and_stdin_secrets_agree() {
        let Some(ts) = require_ts("set_values") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        for (key, value) in [
            ("defaultOutput", "json"),
            ("scanConcurrency", "7"),
            ("airsNumRetries", "3"),
            ("mgmtEndpoint", "http://127.0.0.1:9/mgmt"),
            ("mgmtClientId", "client-200"),
            ("mgmtTsgId", "100"),
        ] {
            let (r, t) = both(&sandbox, &ts, &["tenant", "set", "dev", key, value], writes);
            assert_same_outcome(&sandbox, &r, &t);
            r.assert_success();
        }
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "set", "dev", "airsApiKey", "--stdin"],
            |cli| writes(cli).stdin("FAKE-KEY-PW1\n").secret("FAKE-KEY-PW1"),
        );
        assert_same_outcome(&sandbox, &r, &t);
        assert_same_state(
            &sandbox,
            &ts,
            &["dev"],
            &[
                "defaultOutput",
                "scanConcurrency",
                "airsNumRetries",
                "mgmtEndpoint",
                "airsApiKey",
                "airsApiToken",
            ],
        );
    }

    #[test]
    fn a_prompted_value_agrees() {
        let Some(ts) = require_ts("set_prompt") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let script: [(&str, &[u8]); 2] = [
            ("scanConcurrency:", b"\r"),
            ("A nonempty value is required", b"7\r"),
        ];
        let args = ["tenant", "set", "dev", "scanConcurrency"];
        let r = pty_run(&rust(), &sandbox, &args, writes(&rust()), &script);
        let t = pty_run(&ts, &sandbox, &args, writes(&ts), &script);
        assert_eq!((r.run.code, t.run.code), (0, 0), "{r:?}\n{t:?}");
        assert_eq!(visible_prompts(&r.transcript), ["scanConcurrency:"]);
        assert_eq!(visible_prompts(&t.transcript), ["scanConcurrency:"]);
        let hidden = ["tenant", "set", "dev", "airsApiToken"];
        let script: [(&str, &[u8]); 1] = [("[input is masked]", b"FAKE-TOKEN-PW1\r")];
        let options = |cli: &Cli| writes(cli).secret("FAKE-TOKEN-PW1");
        let r = pty_run(&rust(), &sandbox, &hidden, options(&rust()), &script);
        let t = pty_run(&ts, &sandbox, &hidden, options(&ts), &script);
        assert_eq!((r.run.code, t.run.code), (0, 0));
        assert_same_state(
            &sandbox,
            &ts,
            &["dev"],
            &["scanConcurrency", "airsApiToken"],
        );
    }

    #[test]
    fn unknown_tenants_and_pin_mismatches_agree() {
        let Some(ts) = require_ts("set_failures") else {
            return;
        };
        let sandbox = Sandbox::new();
        let server = FixtureServer::start();
        writable_tenant(&sandbox, &server, "dev", "200", |config| {
            config.set("mgmtTsgId", "100");
        });
        for args in [
            &["tenant", "set", "nope", "defaultOutput", "json"][..],
            &["tenant", "set", "dev", "defaultOutput", "json"],
            &["tenant", "unset", "nope", "defaultOutput"],
            &["tenant", "unset", "dev", "defaultOutput"],
        ] {
            // unset reads the tenant file under the lock, so it may create config.lock.
            let (r, t) = both(&sandbox, &ts, args, writes);
            assert_same_outcome(&sandbox, &r, &t);
            r.assert_code(1);
        }
    }
}

mod unset {
    use super::*;

    #[test]
    fn present_and_absent_keys_agree() {
        let Some(ts) = require_ts("unset_keys") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        both(
            &sandbox,
            &ts,
            &["tenant", "set", "dev", "defaultOutput", "json"],
            writes,
        );
        for _ in 0..2 {
            let (r, t) = both(
                &sandbox,
                &ts,
                &["tenant", "unset", "dev", "defaultOutput"],
                writes,
            );
            assert_same_outcome(&sandbox, &r, &t);
            r.assert_success();
        }
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "unset", "dev", "scanConcurrency"],
            writes,
        );
        assert_same_outcome(&sandbox, &r, &t);
        assert_same_state(
            &sandbox,
            &ts,
            &["dev"],
            &["defaultOutput", "scanConcurrency"],
        );
    }
}

mod switch {
    use super::*;

    #[test]
    fn selecting_agrees() {
        let Some(ts) = require_ts("switch_selects") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        create_both(&sandbox, &ts, "prod", "200");
        for name in ["dev", "prod", "prod"] {
            let (r, t) = both(&sandbox, &ts, &["tenant", "switch", name], writes);
            assert_same_outcome(&sandbox, &r, &t);
            r.assert_success();
            assert_same_state(&sandbox, &ts, &[], &[]);
        }
        let (r, t) = both(&sandbox, &ts, &["tenant", "switch", "ghost"], |_| {
            RunOptions::new()
        });
        assert_same_outcome(&sandbox, &r, &t);
        assert_eq!(r.error_line().as_deref(), Some("Tenant not found"));
        assert_same_state(&sandbox, &ts, &["dev", "prod"], &[]);
    }

    #[test]
    fn unusable_and_credentialless_configs_agree() {
        let Some(ts) = require_ts("switch_configs") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let good = sandbox.add_fixture_tenant(&server, "good", "100");
        let bare = sandbox.add_fixture_tenant_with(&server, "bare", "300", |config| {
            config.remove("mgmtClientId");
            config.remove("mgmtClientSecret");
        });
        let mismatched = sandbox.add_fixture_tenant(&server, "pinned", "400");
        let missing = Path::new(&sandbox.configs_dir()).join("missing.json");
        // Byte order, so both lists agree (D86 pins the order difference).
        sandbox.write_registry(
            &[
                bare.entry(),
                RegistryEntry::new("gone", &missing, "500"),
                good.entry(),
                RegistryEntry::new("pinned", &mismatched.config_path, "401"),
            ],
            Some("good"),
        );
        for (name, code) in [("pinned", 1), ("gone", 1), ("bare", 0), ("good", 0)] {
            let (r, t) = both(&sandbox, &ts, &["tenant", "switch", name], writes);
            assert_same_outcome(&sandbox, &r, &t);
            r.assert_code(code);
        }
        assert_same_state(&sandbox, &ts, &["good", "bare"], &["mgmtTsgId"]);
    }
}

mod delete {
    use super::*;

    #[test]
    fn deleting_leaves_the_same_state() {
        let Some(ts) = require_ts("delete_state") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        create_both(&sandbox, &ts, "prod", "200");
        both(&sandbox, &ts, &["tenant", "switch", "dev"], writes);
        for name in ["prod", "dev"] {
            let (r, t) = both(
                &sandbox,
                &ts,
                &["tenant", "delete", name, "--force"],
                writes,
            );
            assert_eq!((r.code, t.code), (0, 0));
            assert_same_state(&sandbox, &ts, &[], &[]);
        }
        let (r, t) = both(&sandbox, &ts, &["tenant", "list"], |_| RunOptions::new());
        assert_eq!(
            (norm(&sandbox, &r.stdout), norm(&sandbox, &r.stderr)),
            (norm(&sandbox, &t.stdout), norm(&sandbox, &t.stderr))
        );
        for args in [
            &["tenant", "read"][..],
            &["tenant", "path"],
            &["tenant", "delete", "dev", "--force"],
        ] {
            let (r, t) = both(&sandbox, &ts, args, |_| RunOptions::new());
            assert_same_outcome(&sandbox, &r, &t);
            r.assert_code(1);
        }
    }
}

mod divergences {
    use super::*;

    #[test]
    fn d33_write_commands_refuse_the_tenant_flag() {
        let Some(ts) = require_ts("d33_write") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let (r, t) = both(
            &sandbox,
            &ts,
            &["--tenant", "dev", "tenant", "switch", "dev"],
            |_| RunOptions::new(),
        );
        t.assert_code(1);
        assert_eq!(t.stderr, "error: unknown option '--tenant'\n");
        r.assert_code(2);
        assert_eq!(
            usage_line(&r.stderr).as_deref(),
            Some("--tenant cannot be used with 'tenant switch'; name the tenant as an argument")
        );
    }

    #[test]
    fn d51_set_refuses_a_dead_default_output() {
        let Some(ts) = require_ts("d51_set") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        for format in ["markdown", "csv", "yaml"] {
            let (r, t) = both(
                &sandbox,
                &ts,
                &["tenant", "set", "dev", "defaultOutput", format],
                writes,
            );
            t.assert_success();
            assert_eq!(
                t.stdout,
                "  ✓ Updated defaultOutput for tenant dev; selection unchanged.\n"
            );
            r.assert_code(2);
            assert_eq!(
                usage_line(&r.stderr).as_deref(),
                Some("Invalid value for configuration setting")
            );
        }
    }

    #[test]
    fn d52_outcome_lines_are_terminal_safe() {
        let Some(ts) = require_ts("d52_write") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tsg = "1\u{1b}[31m";
        let tenant = sandbox.add_fixture_tenant_with(&server, "dev", tsg, |_| {});
        sandbox.register(&[&tenant], None);
        let (r, t) = both(&sandbox, &ts, &["tenant", "switch", "dev"], writes);
        assert_eq!(
            t.stdout, "  ✓ Selected dev (TSG 1\u{1b}[31m)\n",
            "TypeScript writes the ESC raw"
        );
        assert_eq!(r.stderr, "  ✓ Selected dev (TSG 1\u{fffd}[31m)\n");
    }

    #[test]
    fn d59_write_commands_reject_an_invalid_output() {
        let Some(ts) = require_ts("d59_write") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let (r, t) = both(
            &sandbox,
            &ts,
            &["--output", "xml", "tenant", "switch", "dev"],
            writes,
        );
        t.assert_success();
        r.assert_code(2);
        assert_eq!(
            usage_line(&r.stderr).as_deref(),
            Some("Invalid output format 'xml'. Expected: pretty, table, json")
        );
        let (r, t) = both(
            &sandbox,
            &ts,
            &["--output", "json", "tenant", "switch", "dev"],
            writes,
        );
        assert_same_outcome(&sandbox, &r, &t);
    }

    #[test]
    fn d73_success_lines_name_airs() {
        let Some(ts) = require_ts("d73_write") else {
            return;
        };
        let sandbox = Sandbox::new();
        let (r, t) = create_both(&sandbox, &ts, "dev", "100");
        assert_eq!(
            t.stdout,
            "  ✓ Registered dev (TSG 100); private config created. Use airs-cli tenant switch dev.\n"
        );
        assert_eq!(
            r.stderr,
            "  ✓ Registered dev (TSG 100); private config created. Use airs tenant switch dev.\n"
        );
    }

    #[test]
    fn d74_outcome_lines_go_to_stderr_and_respect_quiet() {
        let Some(ts) = require_ts("d74_streams") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let (r, t) = both(&sandbox, &ts, &["tenant", "switch", "dev"], writes);
        assert_eq!(
            (t.stdout.as_str(), t.stderr.as_str()),
            ("  ✓ Selected dev (TSG 100)\n", "")
        );
        assert_eq!(
            (r.stdout.as_str(), r.stderr.as_str()),
            ("", "  ✓ Selected dev (TSG 100)\n")
        );
        let (r, t) = both(
            &sandbox,
            &ts,
            &["--quiet", "tenant", "switch", "dev"],
            writes,
        );
        assert_eq!(
            t.stdout, "  ✓ Selected dev (TSG 100)\n",
            "TypeScript ignores --quiet for success"
        );
        assert_eq!((r.stdout.as_str(), r.stderr.as_str()), ("", ""));
        // Info lines: --quiet hides them on both.
        let (r, t) = both(
            &sandbox,
            &ts,
            &["--quiet", "tenant", "unset", "dev", "defaultOutput"],
            writes,
        );
        assert_eq!(
            (t.stdout.as_str(), r.stdout.as_str(), r.stderr.as_str()),
            ("", "", "")
        );
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "unset", "dev", "defaultOutput"],
            writes,
        );
        assert_eq!(
            t.stdout,
            "  ℹ defaultOutput is not set for tenant dev — nothing to do\n"
        );
        assert_eq!(
            (r.stdout.as_str(), r.stderr.as_str()),
            ("", t.stdout.as_str())
        );
    }

    #[test]
    fn d75_input_errors_are_usage_errors() {
        let Some(ts) = require_ts("d75_usage") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        for (args, stdin) in [
            (&["tenant", "create", "_x"][..], None),
            (
                &[
                    "tenant",
                    "create",
                    "x",
                    "--tsg-id",
                    "1",
                    "--client-id",
                    "c",
                    "--client-secret-stdin",
                ],
                Some(""),
            ),
            (
                &[
                    "tenant",
                    "create",
                    "x",
                    "--tsg-id",
                    "1",
                    "--client-id",
                    "c",
                    "--client-secret-stdin",
                ],
                Some("FAKE\nsecond"),
            ),
            (
                &["tenant", "set", "dev", "defaultOutput", "json", "--stdin"],
                None,
            ),
            (
                &["tenant", "set", "dev", "airsApiKey", "FAKE-ARG-PW1"],
                None,
            ),
            (
                &["tenant", "set", "dev", "airsApiKey", "--stdin"],
                Some("   \n"),
            ),
            (&["tenant", "unset", "dev", "mgmtClientId"], None),
            (&["tenant", "unset", "nope", "mgmtTsgId"], None),
        ] {
            let options = |_: &Cli| {
                let options = RunOptions::new().secret("FAKE-ARG-PW1");
                match stdin {
                    Some(bytes) => options.stdin(bytes),
                    None => options,
                }
            };
            let (r, t) = both(&sandbox, &ts, args, options);
            t.assert_code(1);
            r.assert_code(2);
            assert_eq!(usage_line(&r.stderr), error_line(&t.stderr), "{args:?}");
        }
        // `delete <unknown>` without --force: TypeScript looks the name up first.
        let (r, t) = both(&sandbox, &ts, &["tenant", "delete", "nope"], |_| {
            RunOptions::new()
        });
        t.assert_code(1);
        assert_eq!(t.error_line().as_deref(), Some("Tenant not found"));
        r.assert_code(2);
        assert_eq!(
            usage_line(&r.stderr).as_deref(),
            Some("refusing to delete tenant nope without --force in non-interactive mode")
        );
        assert_same_state(&sandbox, &ts, &["dev"], &["defaultOutput"]);
    }

    #[test]
    fn d76_values_are_validated_strictly() {
        let Some(ts) = require_ts("d76_values") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        for (key, value, message) in [
            (
                "scanConcurrency",
                "0x5",
                "Invalid value for configuration setting",
            ),
            (
                "scanConcurrency",
                " 7 ",
                "Invalid value for configuration setting",
            ),
            (
                "scanConcurrency",
                "1e1",
                "Invalid value for configuration setting",
            ),
            (
                "airsNumRetries",
                "",
                "Empty values are not stored; use 'airs tenant unset dev airsNumRetries' to remove a setting",
            ),
            (
                "mgmtEndpoint",
                "not a url",
                "Invalid mgmtEndpoint: endpoints must use https (http is allowed only for loopback hosts) and must not contain credentials, a query or a fragment",
            ),
            (
                "mgmtDashboardEndpoint",
                "localhost:8080",
                "Invalid mgmtDashboardEndpoint: endpoints must use https (http is allowed only for loopback hosts) and must not contain credentials, a query or a fragment",
            ),
            (
                "mgmtClientId",
                "a\u{1b}[31mb",
                "Invalid value for configuration setting",
            ),
        ] {
            let (r, t) = both(&sandbox, &ts, &["tenant", "set", "dev", key, value], writes);
            t.assert_success();
            r.assert_code(2);
            assert_eq!(
                usage_line(&r.stderr).as_deref(),
                Some(message),
                "{key} {value:?}"
            );
        }
        // A prompt: TypeScript accepts any nonblank answer and fails afterwards; airs-cli-rs
        // asks again with the reason.
        let args = ["tenant", "set", "dev", "defaultOutput"];
        let t = pty_run(
            &ts,
            &sandbox,
            &args,
            RunOptions::new(),
            &[("defaultOutput:", b"xml\r")],
        );
        t.run.assert_code(1);
        assert!(
            t.transcript
                .contains("✗ Error: Invalid value for configuration setting")
        );
        let r = pty_run(
            &rust(),
            &sandbox,
            &args,
            writes(&rust()),
            &[
                ("defaultOutput:", b"xml\n"),
                ("> Invalid value for configuration setting", b"table\n"),
            ],
        );
        r.run.assert_success();
    }

    #[test]
    fn d77_one_flock_lock_that_a_dead_writer_cannot_leave_behind() {
        let Some(ts) = require_ts("d77_lock") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        // A crashed writer's lock files: TypeScript's O_EXCL files block for good;
        // airs-cli-rs's config.lock is only a file until someone flocks it.
        fs::write(sandbox.state_dir().join("tenants.json.lock"), b"").unwrap();
        fs::write(
            sandbox.store_dir().join("config.lock"),
            b"pid=1\nhost=gone\nsince=2026-01-01T00:00:00Z\n",
        )
        .unwrap();
        let (r, t) = both(&sandbox, &ts, &["tenant", "switch", "dev"], writes);
        t.assert_code(1);
        assert_eq!(
            norm(&sandbox, &t.stderr),
            "\n  ✗ Error: Cannot lock tenant registry at <REGISTRY>.lock; another change may be in progress\n\n"
        );
        r.assert_success();
        assert_eq!(
            r.stderr, "  ✓ Selected dev (TSG 100)\n",
            "no wait: nobody holds the flock"
        );
        assert_eq!(
            fs::read(sandbox.store_dir().join("config.lock")).unwrap(),
            b""
        );
        // TypeScript's set takes no registry lock, so it races delete and switch.
        let t = run(
            &ts,
            &sandbox,
            &["tenant", "set", "dev", "scanConcurrency", "3"],
            &writes(&ts),
        );
        t.assert_success();
    }

    #[test]
    fn d78_stale_temporary_files_are_cleaned_up() {
        let Some(ts) = require_ts("d78_temps") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let ts_temp = sandbox
            .state_dir()
            .join(".airs-tenants-0d44b24e-fb74-4547-9ce7-10eb8b63bf1b.tmp");
        let rust_temp = sandbox
            .store_dir()
            .join(".config.toml.4242.0123456789abcdef.tmp");
        for path in [&ts_temp, &rust_temp] {
            fs::write(path, b"partial").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (r, t) = both(&sandbox, &ts, &["tenant", "switch", "dev"], writes);
        assert_same_outcome(&sandbox, &r, &t);
        assert!(
            ts_temp.exists(),
            "TypeScript never removes a leftover temporary file"
        );
        assert!(!rust_temp.exists(), "airs removes it under the lock");
    }

    #[test]
    fn d79_writers_refuse_a_read_only_index() {
        let Some(ts) = require_ts("d79_read_only") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        fs::set_permissions(sandbox.registry_path(), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(
            sandbox.store_index_path(),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        let (r, t) = both(&sandbox, &ts, &["tenant", "switch", "dev"], writes);
        t.assert_success();
        assert_eq!(
            mode(&sandbox.registry_path()),
            0o600,
            "TypeScript replaced the read-only registry"
        );
        r.assert_code(1);
        assert_eq!(
            r.error_line(),
            Some(format!(
                "{} is read-only; restore write permission (chmod 600) to change it",
                sandbox.store_index_path().display()
            ))
        );
        assert_eq!(mode(&sandbox.store_index_path()), 0o400);
    }

    /// D79: a no-op `unset` (the key is absent) on a read-only tenant file. TypeScript
    /// runs its writable check first and fails; airs-cli-rs writes nothing, so it
    /// reports the no-op and exits 0 (only a removal needs owner write).
    #[test]
    fn d79_a_no_op_unset_on_a_read_only_file() {
        let Some(ts) = require_ts("d79_unset_read_only") else {
            return;
        };
        let sandbox = Sandbox::new();
        let server = FixtureServer::start();
        writable_tenant(&sandbox, &server, "dev", "100", |config| {
            config.remove("scanConcurrency");
        });
        let read_only = fs::Permissions::from_mode(0o400);
        fs::set_permissions(sandbox.config_path("dev"), read_only.clone()).unwrap();
        fs::set_permissions(sandbox.store_tenant_path("dev"), read_only).unwrap();
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "unset", "dev", "scanConcurrency"],
            writes,
        );
        t.assert_code(1);
        assert_eq!(
            t.error_line().as_deref(),
            Some("Tenant config is not a writable regular file")
        );
        r.assert_success();
        assert_eq!(
            r.stderr,
            "  ℹ scanConcurrency is not set for tenant dev — nothing to do\n"
        );
    }

    #[test]
    fn d80_delete_removes_the_tenant_file() {
        let Some(ts) = require_ts("d80_delete") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        both(&sandbox, &ts, &["tenant", "switch", "dev"], writes);
        let ts_config: String = {
            let registry: Value =
                serde_json::from_slice(&fs::read(sandbox.registry_path()).unwrap()).unwrap();
            registry["tenants"][0]["configPath"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "delete", "dev", "--force"],
            writes,
        );
        assert_eq!(
            t.stdout,
            "  ✓ Unregistered dev; source config file retained; no tenant is selected\n"
        );
        assert!(
            Path::new(&ts_config).exists(),
            "TypeScript keeps the secret-holding config"
        );
        assert_eq!(
            r.stderr,
            "  ✓ Deleted dev and its config file; no tenant is selected\n"
        );
        assert!(!sandbox.store_tenant_path("dev").exists());
        assert_same_state(&sandbox, &ts, &[], &[]);
    }

    #[test]
    fn d81_the_confirmation_needs_stdin_and_stderr_terminals() {
        let Some(ts) = require_ts("d81_confirm") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        // stdin and stderr on a terminal, stdout piped (`tenant delete dev | cat`).
        let t = spawn_pty(
            &ts,
            &sandbox,
            &["tenant", "delete", "dev"],
            &RunOptions::new(),
        )
        .wait();
        t.run.assert_code(2);
        assert!(t.transcript.contains(
            "✗ refusing to unregister tenant dev without --force in non-interactive mode"
        ));
        let r = pty_run(
            &rust(),
            &sandbox,
            &["tenant", "delete", "dev"],
            RunOptions::new(),
            &[(
                "? Delete tenant dev? Its config file will be deleted. (y/N) ",
                b"yolo\n",
            )],
        );
        r.run.assert_success();
        assert!(
            r.transcript.ends_with("  ℹ Aborted\r\n"),
            "only y/yes confirm: {:?}",
            r.transcript
        );
        let r = pty_run(
            &rust(),
            &sandbox,
            &["tenant", "delete", "dev"],
            RunOptions::new(),
            &[("(y/N) ", b"\x04")],
        );
        r.run.assert_success();
        assert!(r.transcript.ends_with("  ℹ Aborted\r\n"), "EOF declines");
        let mut session = spawn_pty(
            &rust(),
            &sandbox,
            &["tenant", "delete", "dev"],
            &RunOptions::new(),
        );
        session.expect("(y/N) ");
        session.signal("INT");
        let r = session.wait();
        r.run.assert_code(130);
        assert!(r.transcript.contains(CANCELLED));
        // Without terminals both refuse, with their own wording.
        let (r, t) = both(&sandbox, &ts, &["tenant", "delete", "dev"], |_| {
            RunOptions::new()
        });
        assert_eq!((r.code, t.code), (2, 2));
        assert_eq!(
            usage_line(&t.stderr).as_deref(),
            Some("refusing to unregister tenant dev without --force in non-interactive mode")
        );
        assert_eq!(
            usage_line(&r.stderr).as_deref(),
            Some("refusing to delete tenant dev without --force in non-interactive mode")
        );
    }

    #[test]
    fn d82_tenants_without_management_credentials_can_be_edited() {
        let Some(ts) = require_ts("d82_scanner_only") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        writable_tenant(&sandbox, &server, "scan", "100", |config| {
            config.remove("mgmtClientId");
            config.remove("mgmtClientSecret");
        });
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "set", "scan", "scanConcurrency", "3"],
            writes,
        );
        t.assert_code(1);
        assert_eq!(
            t.error_line().as_deref(),
            Some("Tenant config requires nonempty mgmtTsgId, mgmtClientId and mgmtClientSecret")
        );
        r.assert_success();
        assert!(
            fs::read_to_string(sandbox.store_tenant_path("scan"))
                .unwrap()
                .contains("scanConcurrency = 3\n")
        );
    }

    #[test]
    fn d83_set_mgmt_tsg_id_changes_the_pin() {
        let Some(ts) = require_ts("d83_tsg") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "set", "dev", "mgmtTsgId", "200"],
            writes,
        );
        t.assert_code(1);
        assert_eq!(
            t.error_line().as_deref(),
            Some("TSG identity is pinned; create another tenant instead of changing mgmtTsgId")
        );
        r.assert_success();
        let list = run(
            &rust(),
            &sandbox,
            &["tenant", "list", "--output", "json"],
            &RunOptions::new(),
        );
        assert_eq!(list.json()[0]["tsgId"], "200");
        let get = run(
            &rust(),
            &sandbox,
            &["tenant", "get", "dev", "mgmtTsgId"],
            &RunOptions::new(),
        );
        assert_eq!(get.stdout, "200\n");
    }

    #[test]
    fn d84_create_config_is_dropped() {
        let Some(ts) = require_ts("d84_config") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tenant = sandbox.add_fixture_tenant(&server, "prod", "200");
        let path = tenant.config_path.display().to_string();
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "create", "prod", "--config", &path],
            writes,
        );
        t.assert_success();
        assert_eq!(
            t.stdout,
            "  ✓ Registered prod (TSG 200); config file unchanged. Use airs-cli tenant switch prod.\n"
        );
        r.assert_code(2);
        assert!(
            r.stderr.contains("unexpected argument '--config'"),
            "{}",
            r.stderr
        );
        let (r, t) = both(&sandbox, &ts, &["tenant", "create", "dev"], |_| {
            RunOptions::new()
        });
        assert_eq!(
            t.error_line().as_deref(),
            Some(
                "Interactive setup requires a terminal. Use --config, or --tsg-id and --client-id with --client-secret-stdin. For tenant set, pass a value or use --stdin."
            )
        );
        assert_eq!(
            usage_line(&r.stderr).as_deref(),
            Some(
                "Interactive setup requires a terminal. Use --tsg-id and --client-id with --client-secret-stdin. For tenant set, pass a value or use --stdin."
            )
        );
    }

    #[test]
    fn d85_create_refuses_names_differing_only_in_case() {
        let Some(ts) = require_ts("d85_create") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let (r, t) = both(&sandbox, &ts, &create_args("DEV", "200", "c"), |cli| {
            writes(cli).stdin(format!("{SECRET}\n"))
        });
        t.assert_success();
        r.assert_code(1);
        assert_eq!(
            r.error_line().as_deref(),
            Some(
                "Tenant name conflicts with existing tenant dev; names may not differ only in case"
            )
        );
    }

    #[test]
    fn d86_create_keeps_byte_order() {
        let Some(ts) = require_ts("d86_create") else {
            return;
        };
        let sandbox = Sandbox::new();
        for name in ["b", "A1", "a_b", "a-b", "10", "9", "Z"] {
            create_both(&sandbox, &ts, name, "1");
        }
        let names = |cli: &Cli| -> Vec<String> {
            run(
                cli,
                &sandbox,
                &["tenant", "list", "--output", "json"],
                &RunOptions::new(),
            )
            .json()
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap().to_owned())
            .collect()
        };
        assert_eq!(
            names(&ts),
            ["10", "9", "a_b", "a-b", "A1", "b", "Z"],
            "localeCompare"
        );
        assert_eq!(
            names(&rust()),
            ["10", "9", "A1", "Z", "a-b", "a_b", "b"],
            "byte order"
        );
    }

    #[test]
    fn d87_failed_writes_create_nothing_and_use_fixed_messages() {
        let Some(ts) = require_ts("d87_failed") else {
            return;
        };
        let sandbox = Sandbox::new();
        let ts_dir = sandbox.state_dir().join("sub");
        let rust_dir = sandbox.store_dir().join("sub");
        let options = |cli: &Cli| {
            RunOptions::new()
                .env(
                    "PRISMA_AIRS_TENANTS_PATH",
                    ts_dir.join("tenants.json").display().to_string(),
                )
                .env("AIRS_CLI_CONFIG_DIR", rust_dir.display().to_string())
                .allow_writes_under(if cli.is_ts() { "state" } else { "store" })
        };
        let (r, t) = both(&sandbox, &ts, &["tenant", "switch", "dev"], options);
        assert_eq!((r.code, t.code), (1, 1));
        assert_eq!(r.error_line(), t.error_line(), "Tenant not found on both");
        assert!(ts_dir.is_dir(), "TypeScript created its registry directory");
        assert!(!rust_dir.exists(), "airs created nothing");
        // A registered tenant whose config is missing: TypeScript leaks the raw OS error.
        create_both(&sandbox, &ts, "dev", "100");
        let registry: Value =
            serde_json::from_slice(&fs::read(sandbox.registry_path()).unwrap()).unwrap();
        fs::remove_file(registry["tenants"][0]["configPath"].as_str().unwrap()).unwrap();
        fs::remove_file(sandbox.store_tenant_path("dev")).unwrap();
        let (r, t) = both(
            &sandbox,
            &ts,
            &["tenant", "set", "dev", "scanConcurrency", "3"],
            writes,
        );
        assert_eq!((r.code, t.code), (1, 1));
        assert!(
            norm(&sandbox, &t.stderr).contains("ENOENT: no such file or directory, lstat"),
            "{}",
            t.stderr
        );
        assert_eq!(
            norm(&sandbox, &r.stderr),
            "\n  ✗ Error: Cannot read a valid tenant config at <CONFIG:dev>\n\n"
        );
    }

    #[test]
    fn d88_prompts_are_not_redrawn() {
        let Some(ts) = require_ts("d88_render") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let script: [(&str, &[u8]); 1] = [("defaultOutput:", b"json\r")];
        let args = ["tenant", "set", "dev", "defaultOutput"];
        let t = pty_run(&ts, &sandbox, &args, writes(&ts), &script);
        let r = pty_run(&rust(), &sandbox, &args, writes(&rust()), &script);
        assert_eq!((r.run.code, t.run.code), (0, 0));
        assert!(t.transcript.contains('\u{1b}') && t.transcript.contains("✔ defaultOutput: json"));
        assert!(!r.transcript.contains('\u{1b}') && !r.transcript.contains('✔'));
        assert!(
            r.transcript.starts_with("? defaultOutput: json\r\n"),
            "{:?}",
            r.transcript
        );
        assert_eq!(
            visible_prompts(&r.transcript),
            visible_prompts(&t.transcript)
        );
    }

    /// D91: the parse errors of `tenant create|set|unset` never quote an argument value
    /// (it may be a secret typed in the wrong place). TypeScript never quotes an excess
    /// positional either, and the texts agree; it does quote `--flag=value` and unknown
    /// options, which airs-cli-rs does not.
    #[test]
    fn d91_parse_errors_never_echo_argument_values() {
        let Some(ts) = require_ts("d91_parse_errors") else {
            return;
        };
        let sandbox = Sandbox::new();
        create_both(&sandbox, &ts, "dev", "100");
        let cases: [(&[&str], &[&str], bool); 6] = [
            (
                &[
                    "tenant",
                    "create",
                    "x",
                    "--tsg-id",
                    "1",
                    "--client-id",
                    "c",
                    "FAKE-D91-A",
                ],
                &["FAKE-D91-A"],
                false,
            ),
            (
                &[
                    "tenant",
                    "set",
                    "dev",
                    "airsApiKey",
                    "FAKE-D91-B",
                    "FAKE-D91-C",
                ],
                &["FAKE-D91-B", "FAKE-D91-C"],
                false,
            ),
            (
                &["tenant", "unset", "dev", "defaultOutput", "FAKE-D91-D"],
                &["FAKE-D91-D"],
                false,
            ),
            (
                &["tenant", "set", "dev", "airsApiKey", "--stdin=FAKE-D91-E"],
                &["FAKE-D91-E"],
                true,
            ),
            (
                &["tenant", "create", "x", "--client-secret-stdin=FAKE-D91-F"],
                &["FAKE-D91-F"],
                true,
            ),
            (
                &["tenant", "set", "dev", "airsApiKey", "--FAKE-D91-G"],
                &["FAKE-D91-G"],
                true,
            ),
        ];
        for (args, values, ts_echoes) in cases {
            let rust_options = values
                .iter()
                .fold(RunOptions::new(), |options, value| options.secret(value));
            let r = run(&rust(), &sandbox, args, &rust_options);
            let t = run(&ts, &sandbox, args, &RunOptions::new());
            r.assert_code(2);
            t.assert_code(1);
            for value in values {
                assert!(!r.stderr.contains(value), "{args:?}: {:?}", r.stderr);
            }
            assert_eq!(
                values.iter().any(|value| t.stderr.contains(value)),
                ts_echoes,
                "{args:?}: {:?}",
                t.stderr
            );
            if !ts_echoes {
                assert_eq!(r.stderr.lines().next(), t.stderr.lines().next(), "{args:?}");
            }
        }
        assert_same_state(&sandbox, &ts, &["dev"], &["airsApiKey", "defaultOutput"]);
    }

    /// D92: `tenant set <name> <key>` without a value on a tenant that cannot be
    /// changed (here a pin mismatch). TypeScript prompts first and reports the error
    /// after the answer; airs-cli-rs reports it before prompting, so nothing is typed
    /// for a tenant that cannot be changed.
    #[test]
    fn d92_set_checks_the_tenant_before_prompting() {
        let Some(ts) = require_ts("d92_set_order") else {
            return;
        };
        let sandbox = Sandbox::new();
        let server = FixtureServer::start();
        writable_tenant(&sandbox, &server, "dev", "200", |config| {
            config.set("mgmtTsgId", "100");
        });
        let args = ["tenant", "set", "dev", "defaultOutput"];
        let pin =
            "Tenant config TSG differs from its registered identity; register it under a new name";
        let script: [(&str, &[u8]); 1] = [("defaultOutput:", b"json\r")];
        let t = pty_run(&ts, &sandbox, &args, writes(&ts), &script);
        t.run.assert_code(1);
        assert_eq!(visible_prompts(&t.transcript), ["defaultOutput:"]);
        assert!(t.transcript.contains(pin), "{:?}", t.transcript);
        let r = spawn_pty(&rust(), &sandbox, &args, &writes(&rust())).wait();
        r.run.assert_code(1);
        assert!(
            visible_prompts(&r.transcript).is_empty(),
            "{:?}",
            r.transcript
        );
        assert_eq!(
            r.transcript.replace("\r\n", "\n"),
            format!("\n  ✗ Error: {pin}\n\n")
        );
    }
}
