//! TS-vs-Rust parity for the M6c step-3 commands `model-security pypi-auth` and
//! `model-security install` (DESIGN §17.12–§17.14).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh [`FixtureServer`] and a fresh [`Sandbox`] whose `PATH` is
//! only `<sandbox>/bin` (the fake uv, and for the TypeScript fallback the fake `python3`
//! and `pip`; the real uv and python are never run). `parity` tests compare exit codes,
//! the bytes and the normalised requests; `divergence` tests pin both sides of each §12
//! row this step implements (D194–D201, and the step-3 extensions of D11, D50, D52 and
//! D64). The TypeScript side prints the PyPI credential (D194), so its runs disable the
//! leak check; the airs-cli-rs runs keep it.

use airs_test_harness::fake_uv::{self, FakeUv, UvCall};
use airs_test_harness::fixtures::modelsec as fx;
use airs_test_harness::{
    Cli, FixtureServer, Ms, NormalizedRequest, Planned, Route, Run, RunOptions, Sandbox,
    normalize_all, require_ts, run, spawn,
};
use serde_json::json;
use std::path::Path;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n";
const WITHHELD_URL: &str = "https://[withheld]@pypi.invalid/airs/simple/";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn secret() -> String {
    fx::pypi_secret(TSG)
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    calls: Vec<UvCall>,
    sandbox: Sandbox,
    _server: FixtureServer,
}

/// What a scenario sets up before one CLI runs: the fake tools, files under `tmp/`.
type Setup<'a> = &'a dyn Fn(&Sandbox, &FixtureServer, bool);

/// Runs `cli` (`model-security <args>`, `{tmp}` in an argument replaced by the sandbox's
/// `tmp/`) with `PATH=<sandbox>/bin`.
fn exec(cli: &Cli, args: &[&str], setup: Setup<'_>) -> Side {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    setup(&sandbox, &server, cli.is_ts());
    let tmp = sandbox.tmp().display().to_string();
    let mut full = vec!["model-security".to_owned()];
    full.extend(args.iter().map(|arg| arg.replace("{tmp}", &tmp)));
    let full: Vec<&str> = full.iter().map(String::as_str).collect();
    let mut options = RunOptions::new().env("PATH", sandbox.bin_dir().display().to_string());
    if cli.is_ts() {
        options = options.allow_secret_output();
    }
    let out = run(cli, &sandbox, &full, &options);
    let raw = server.requests();
    Side {
        run: out,
        requests: normalize_all(&raw),
        calls: fake_uv::uv_calls(&sandbox),
        sandbox,
        _server: server,
    }
}

fn with_uv(sandbox: &Sandbox, _: &FixtureServer, _: bool) {
    fake_uv::fake_uv(sandbox, &FakeUv::default());
}

fn nothing(_: &Sandbox, _: &FixtureServer, _: bool) {}

/// Both sides (`None` after a `PARITY SKIPPED` notice).
fn sides(name: &str, args: &[&str], setup: Setup<'_>) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((exec(&rust(), args, setup), exec(&ts, args, setup)))
}

fn tmp(side: &Side, name: &str) -> String {
    side.sandbox.tmp().join(name).display().to_string()
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// MI§3: the TS pretty layout byte for byte once its URL is replaced by the withheld
    /// form; both send the token and the one GET.
    #[test]
    fn pypi_auth_layout_matches_typescript_apart_from_the_url() {
        let Some((r, t)) = sides(
            "pypi_auth_layout_matches_typescript_apart_from_the_url",
            &["pypi-auth"],
            &nothing,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        assert_eq!(
            t.run.stdout.replace(&fx::pypi_url(TSG), WITHHELD_URL),
            r.run.stdout
        );
        assert_eq!(r.requests, t.requests);
        assert_eq!(t.run.stderr, "");
    }

    /// MI§4.2: the `--extras` refusal (TS text and exit 2) and the uv steps' status and
    /// success lines (TS stdout ↔ Rust stderr, D199) with the fake uv.
    #[test]
    fn install_messages_match_typescript() {
        let Some((r, t)) = sides(
            "install_messages_match_typescript",
            &["install", "--extras", "nope"],
            &with_uv,
        ) else {
            return;
        };
        r.run.assert_code(2);
        t.run.assert_code(2);
        assert_eq!(r.run.stderr, t.run.stderr);
        assert_eq!(t.run.stdout, BANNER, "TS prints its banner first");
        assert_eq!(r.run.stdout, "");
        let Some((r, t)) = sides(
            "install_messages_match_typescript",
            &["install", "--dir", "{tmp}/proj"],
            &with_uv,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        for line in ["  → uv init\n", "  → uv add\n"] {
            assert!(
                t.run.stderr.contains(line) && r.run.stderr.contains(line),
                "{line}"
            );
        }
        let success = "  ✓ model-security-client installed successfully.\n";
        assert!(t.run.stdout.contains(success));
        assert!(r.run.stderr.contains(success));
        assert_eq!(r.requests, t.requests, "token, then the one PyPI GET");
        assert_eq!(
            r.requests
                .iter()
                .filter(|request| request.path.ends_with("/pypi/authenticate"))
                .count(),
            1
        );
    }
}

// ---------------------------------------------------------------------------
// Divergences (§12 rows of step 3)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D194: TS prints the credential-bearing URL in full (also under `--quiet`, and
    /// ignores `--output`); airs-cli-rs withholds it in every format.
    #[test]
    fn d194_pypi_auth_withholds_the_credential() {
        for args in [
            &["pypi-auth"][..],
            &["--quiet", "pypi-auth"],
            &["pypi-auth", "--output", "json"],
        ] {
            let Some((r, t)) = sides("d194_pypi_auth_withholds_the_credential", args, &nothing)
            else {
                return;
            };
            r.run.assert_success();
            t.run.assert_success();
            assert!(t.run.stdout.contains(&fx::pypi_url(TSG)), "{args:?}");
            assert!(!r.run.stdout.contains(&secret()), "{args:?}");
            assert!(r.run.stdout.contains(WITHHELD_URL), "{args:?}");
        }
        let Some((r, t)) = sides(
            "d194_pypi_auth_withholds_the_credential",
            &["pypi-auth", "--output", "json"],
            &nothing,
        ) else {
            return;
        };
        assert!(t.run.stdout.starts_with(BANNER), "TS: pretty only");
        assert_eq!(
            r.run.json(),
            json!({"url": WITHHELD_URL, "expiresAt": fx::PYPI_EXPIRES})
        );
    }

    /// D195: without uv, TS falls back to `python3 -m venv` and `pip install
    /// --extra-index-url <credential URL>`; airs-cli-rs is uv only and names `--fetch-uv`.
    #[test]
    fn d195_install_is_uv_only() {
        let Some((r, t)) = sides(
            "d195_install_is_uv_only",
            &["install", "--dir", "{tmp}/proj"],
            &|sandbox: &Sandbox, _: &FixtureServer, _: bool| {
                fake_uv::fake_python(sandbox);
            },
        ) else {
            return;
        };
        t.run.assert_success();
        let pip = t.calls.iter().find(|call| call.program == "pip").unwrap();
        assert!(pip.argv.contains(&"--extra-index-url".to_owned()));
        assert!(
            pip.argv.iter().any(|arg| arg.contains(&secret())),
            "TS: argv credential"
        );
        r.run.assert_code(1);
        assert!(r.run.stderr.contains("uv was not found on PATH."));
        assert!(r.run.stderr.contains("--fetch-uv"));
        assert!(r.calls.is_empty(), "Rust ran no tool");
        assert!(r.requests.is_empty(), "Rust sent nothing");
    }

    /// D196: TS passes `--index <URL with the credential>` in `uv add`'s argv; airs-cli-rs
    /// passes the credential-free named index and the credential in the environment.
    #[test]
    fn d196_the_credential_never_reaches_argv() {
        let Some((r, t)) = sides(
            "d196_the_credential_never_reaches_argv",
            &["install", "--dir", "{tmp}/proj"],
            &with_uv,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let add = |side: &Side| -> UvCall {
            side.calls
                .iter()
                .find(|call| call.argv.contains(&"add".to_owned()))
                .cloned()
                .unwrap()
        };
        let (ra, ta) = (add(&r), add(&t));
        assert!(ta.argv.contains(&fx::pypi_url(TSG)), "{:?}", ta.argv);
        assert_eq!(ta.password_sha, None);
        assert!(ra.argv.iter().all(|arg| !arg.contains(&secret())));
        assert!(
            ra.argv
                .contains(&format!("airs-model-security={}", fx::PYPI_INDEX))
        );
        assert_eq!(ra.password_sha, Some(fake_uv::sha256_text(&secret())));
        // Neither project file holds the credential (uv strips TS's userinfo; the fake
        // writes the URL it was given, so the TS project shows what TS handed over).
        let pyproject = |side: &Side| {
            std::fs::read_to_string(Path::new(&tmp(side, "proj")).join("pyproject.toml")).unwrap()
        };
        assert!(!pyproject(&r).contains(&secret()));
        assert!(pyproject(&t).contains(&secret()));
    }

    /// D203: TS runs `uv add` without `--no-build` (its credential is in uv's argv, D196,
    /// which build backends do not inherit); airs-cli-rs passes the credential in uv's
    /// environment, which every build backend inherits, so it passes `--no-build`.
    #[test]
    fn d203_uv_add_builds_nothing_while_the_credential_is_set() {
        let Some((r, t)) = sides(
            "d203_uv_add_builds_nothing_while_the_credential_is_set",
            &["install", "--dir", "{tmp}/proj"],
            &with_uv,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let add = |side: &Side| -> UvCall {
            side.calls
                .iter()
                .find(|call| call.argv.contains(&"add".to_owned()))
                .cloned()
                .unwrap()
        };
        let (ra, ta) = (add(&r), add(&t));
        assert!(ra.argv.contains(&"--no-build".to_owned()), "{:?}", ra.argv);
        assert!(
            ra.password_sha.is_some(),
            "the credential is set for that child"
        );
        assert!(!ta.argv.contains(&"--no-build".to_owned()), "{:?}", ta.argv);
    }

    /// D197: TS's dry run prints the credential, quotes only `[` and spaces, and prints
    /// nothing under `--quiet`; airs-cli-rs withholds it, quotes POSIX words and prints
    /// the plan as data under `--quiet` too.
    #[test]
    fn d197_the_dry_run_withholds_and_quotes() {
        let Some((r, t)) = sides(
            "d197_the_dry_run_withholds_and_quotes",
            &["install", "--dry-run", "--dir", "{tmp}/$(id)"],
            &with_uv,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        assert!(t.run.stdout.contains(&fx::pypi_url(TSG)));
        assert!(
            t.run
                .stdout
                .contains(&format!("$ uv init {}", tmp(&t, "$(id)")))
        );
        assert!(!r.run.stdout.contains(&secret()));
        assert!(
            r.run
                .stdout
                .contains(&format!("init --no-workspace -- '{}'", tmp(&r, "$(id)")))
        );
        assert!(
            r.run
                .stdout
                .contains("UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD=[withheld]")
        );
        let Some((r, t)) = sides(
            "d197_the_dry_run_withholds_and_quotes",
            &["--quiet", "install", "--dry-run", "--dir", "{tmp}/proj"],
            &with_uv,
        ) else {
            return;
        };
        assert_eq!(t.run.stdout, "");
        assert_eq!(t.run.stderr, "");
        assert_eq!(r.run.stdout.lines().count(), 2, "{}", r.run.stdout);
        assert!(r.run.stdout.starts_with("  $ "));
    }

    /// D198: TS hands an existing directory to `uv init` after minting a credential;
    /// airs-cli-rs refuses it before any request.
    #[test]
    fn d198_an_existing_dir_is_refused_first() {
        let setup = |sandbox: &Sandbox, server: &FixtureServer, ts: bool| {
            with_uv(sandbox, server, ts);
            std::fs::create_dir(sandbox.tmp().join("proj")).unwrap();
        };
        let Some((r, t)) = sides(
            "d198_an_existing_dir_is_refused_first",
            &["install", "--dir", "{tmp}/proj"],
            &setup,
        ) else {
            return;
        };
        t.run.assert_success();
        assert!(
            t.calls
                .iter()
                .any(|call| call.argv.first().map(String::as_str) == Some("init"))
        );
        assert!(!t.requests.is_empty());
        r.run.assert_code(1);
        assert!(
            r.run
                .stderr
                .contains("already exists; choose another --dir")
        );
        assert!(r.requests.is_empty());
        assert!(r.calls.is_empty());
    }

    /// D199: TS mixes uv's stdout into its own stdout and prints its success lines there;
    /// airs-cli-rs keeps stdout empty and writes uv's lines to stderr.
    #[test]
    fn d199_uv_output_goes_to_stderr() {
        let Some((r, t)) = sides(
            "d199_uv_output_goes_to_stderr",
            &["install", "--dir", "{tmp}/proj"],
            &with_uv,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        assert!(t.run.stdout.contains("fake uv stdout line"));
        assert!(t.run.stdout.contains("Activate:  cd "));
        assert_eq!(r.run.stdout, "");
        assert_eq!(r.run.stderr.matches("fake uv stdout line").count(), 2);
        assert!(r.run.stderr.contains("Activate:  cd "));
    }

    /// D200: a signal to TS ends it at once and leaves uv running (it finishes later, never
    /// signalled); airs-cli-rs forwards the signal to uv's group and waits for it.
    #[test]
    fn d200_a_signal_reaches_uv() {
        let Some(ts) = require_ts("d200_a_signal_reaches_uv") else {
            return;
        };
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            // The Rust side asserts that the signal reached the sleeping child, so it gets
            // the long default sleep (no race with a loaded machine); only the TS side,
            // whose orphan is waited for, sleeps briefly.
            fake_uv::fake_uv(
                &sandbox,
                &FakeUv {
                    sleep_in: Some("init"),
                    sleep_secs: if cli.is_ts() {
                        3
                    } else {
                        FakeUv::default().sleep_secs
                    },
                    ..FakeUv::default()
                },
            );
            let dir = sandbox.tmp().join("proj").display().to_string();
            let mut options = RunOptions::new()
                .env("PATH", sandbox.bin_dir().display().to_string())
                .expect_signal();
            if cli.is_ts() {
                options = options.allow_secret_output();
            }
            let mut running = spawn(
                &cli,
                &sandbox,
                &["model-security", "install", "--dir", &dir],
                &options,
            );
            assert!(running.wait_for_stderr("fake uv sleeping", Duration::from_secs(30)));
            running.send_signal("TERM");
            let out = running.wait();
            assert_eq!(out.code, 143, "{}", out.stderr);
            if cli.is_ts() {
                // The orphaned uv keeps running and finishes unsignalled.
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                while !fake_uv::uv_calls(&sandbox).iter().any(|call| {
                    call.finished && call.argv.first().map(String::as_str) == Some("init")
                }) {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the TS child never finished"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                let init = fake_uv::uv_calls(&sandbox)
                    .into_iter()
                    .find(|call| call.argv.first().map(String::as_str) == Some("init"))
                    .unwrap();
                assert!(init.signals.is_empty());
            } else {
                let init = fake_uv::uv_calls(&sandbox)
                    .into_iter()
                    .find(|call| call.argv.first().map(String::as_str) == Some("init"))
                    .unwrap();
                assert_eq!(init.signals, ["TERM"]);
                assert!(!init.finished);
                assert!(out.stderr.contains("Interrupted; uv init was stopped;"));
            }
        }
    }

    /// D201: TS hands an http index URL to uv; airs-cli-rs refuses it before uv runs.
    #[test]
    fn d201_an_unusable_index_url_never_reaches_uv() {
        let setup = |sandbox: &Sandbox, server: &FixtureServer, ts: bool| {
            with_uv(sandbox, server, ts);
            server.modelsec(|data| {
                data.pypi_url = Some(format!(
                    "http://oauth2accesstoken:{}@pypi.invalid/s/",
                    secret()
                ));
            });
        };
        let Some((r, t)) = sides(
            "d201_an_unusable_index_url_never_reaches_uv",
            &["install", "--dir", "{tmp}/proj"],
            &setup,
        ) else {
            return;
        };
        t.run.assert_success();
        assert!(
            t.calls
                .iter()
                .any(|call| call.argv.iter().any(|arg| arg.starts_with("http://")))
        );
        r.run.assert_code(1);
        assert!(
            r.run.stderr.contains(
                "The PyPI auth response is not a usable index URL; nothing was installed."
            )
        );
        assert!(r.calls.iter().all(|call| call.argv == ["--version"]));
    }

    /// D11 (step 3): TS prints the PyPI route's server text (which may carry the
    /// credential) in its error line; airs-cli-rs prints the §6 message only.
    #[test]
    fn d11_pypi_auth_errors_print_no_server_text() {
        let setup = |_: &Sandbox, server: &FixtureServer, _: bool| {
            server.set_default(
                Route::ModelSecurity(Ms::PypiAuth),
                Planned::json(
                    400,
                    &json!({"error": {"message": format!("FAKE-SERVER-MSG https://u:{}@x/", secret())}}),
                ),
            );
        };
        let Some((r, t)) = sides(
            "d11_pypi_auth_errors_print_no_server_text",
            &["pypi-auth"],
            &setup,
        ) else {
            return;
        };
        r.run.assert_code(1);
        t.run.assert_code(1);
        assert!(t.run.stderr.contains("FAKE-SERVER-MSG"));
        assert!(!r.run.stderr.contains("FAKE-SERVER-MSG"));
        assert!(r.run.stderr.contains("HTTP 400"));
    }

    /// D50 (step 3): TS ignores any `--output` of `pypi-auth` and `install`; airs-cli-rs
    /// refuses the dropped formats before the tenant.
    #[test]
    fn d50_pypi_auth_and_install_refuse_dropped_formats() {
        for args in [
            &["pypi-auth", "--output", "yaml"][..],
            &[
                "install",
                "--dry-run",
                "--dir",
                "{tmp}/proj",
                "--output",
                "csv",
            ],
        ] {
            let Some((r, t)) = sides(
                "d50_pypi_auth_and_install_refuse_dropped_formats",
                args,
                &with_uv,
            ) else {
                return;
            };
            t.run.assert_success();
            r.run.assert_code(2);
            assert!(r.run.stderr.contains("Invalid output format"));
            assert!(r.requests.is_empty());
        }
    }

    /// D52 (step 3): TS prints the PyPI answer's control characters raw; airs-cli-rs
    /// replaces them (and withholds the URL).
    #[test]
    fn d52_pypi_auth_text_is_terminal_safe() {
        let setup = |_: &Sandbox, server: &FixtureServer, _: bool| {
            server.set_default(
                Route::ModelSecurity(Ms::PypiAuth),
                Planned::json(
                    200,
                    &json!({"url": fx::pypi_url(TSG), "expires_at": "2026\u{1b}[31m\r\nX"}),
                ),
            );
        };
        let Some((r, t)) = sides(
            "d52_pypi_auth_text_is_terminal_safe",
            &["pypi-auth"],
            &setup,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        assert!(t.run.stdout.contains("2026\u{1b}[31m\r\nX"));
        assert!(
            r.run
                .stdout
                .contains("  Expires  2026\u{fffd}[31m\u{fffd}\u{fffd}X\n"),
            "{:?}",
            r.run.stdout
        );
    }

    /// D64 (step 3, the Rust side; the TypeScript debug log is empty on loopback): the
    /// `pypi-auth` record holds status and headers only, never the URL or its credential.
    #[test]
    fn d64_the_pypi_auth_debug_record_holds_no_credential() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let state = airs_test_harness::debug_log::xdg_state_home(&sandbox)
            .display()
            .to_string();
        let out = run(
            &rust(),
            &sandbox,
            &["--debug", "model-security", "pypi-auth"],
            &RunOptions::new()
                .env("XDG_STATE_HOME", &state)
                .secret(&fx::pypi_url(TSG)),
        );
        out.assert_success();
        let (log, _) = airs_test_harness::debug_log::only_log(&sandbox);
        let text = std::fs::read_to_string(log).unwrap();
        assert!(!text.contains("pypi.invalid") && !text.contains("FAKE-PYPI"));
        assert!(text.contains("airs.model_security.get_pypi_auth"));
    }
}
