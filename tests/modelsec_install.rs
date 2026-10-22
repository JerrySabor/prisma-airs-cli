//! Executable acceptance tests for the M6c step-3 commands (DESIGN §17.12–§17.14):
//! `model-security pypi-auth` (the withheld URL, `--url-file`) and `model-security
//! install` (uv only, the fake uv on `PATH`, `--dry-run`, `--fetch-uv` against the
//! fixture's loopback archive).
//!
//! The fixture's PyPI password is `FAKE-PYPI-SECRET-<tsg>`; the runner fails every
//! airs-cli-rs model-security run that shows it on stdout, stderr or in the debug log
//! (D194), so each test proves the credential stays withheld. The fake uv records each
//! invocation's argv, whether the credential variables are set (with the SHA-256 of their
//! values), its process group and the signals it trapped; the real uv is never run. The
//! TypeScript `getPyPIAuth` case (`modelsecurity.spec.ts:794-809`) is ported as the json
//! document `{url, expiresAt}` with the withheld URL (§17.17).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airs_test_harness::fake_uv::{self, FakeUv, TarEntry, UvCall};
use airs_test_harness::fixtures::modelsec as fx;
use airs_test_harness::{
    Cli, FixtureServer, Ms, Planned, RecordedRequest, Route, Run, RunOptions, Sandbox, debug_log,
    run, spawn,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n";
const WITHHELD_URL: &str = "https://[withheld]@pypi.invalid/airs/simple/";
const HINT: &str = "  The index credential is withheld; pass --url-file <path> to save the full URL in a new private file.\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn secret() -> String {
    fx::pypi_secret(TSG)
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// One standard tenant `prod` (TSG 100); the PyPI route answers the fixture URL.
fn fx() -> Fx {
    let server = FixtureServer::start();
    server.seed_modelsec();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |_| {});
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

/// No tenant: argument and path errors must not need one.
fn bare() -> Fx {
    Fx {
        server: FixtureServer::start(),
        sandbox: Sandbox::new(),
    }
}

impl Fx {
    fn ms(&self, args: &[&str]) -> Run {
        self.ms_with(args, &RunOptions::new())
    }

    fn ms_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let mut full = vec!["model-security"];
        full.extend_from_slice(args);
        let out = run(&rust(), &self.sandbox, &full, options);
        self.server.assert_no_unknown_routes();
        out
    }

    /// `install …` with `<sandbox>/bin` as the whole `PATH` (the fake tools only).
    fn install(&self, args: &[&str]) -> Run {
        self.install_with(args, RunOptions::new())
    }

    fn install_with(&self, args: &[&str], options: RunOptions) -> Run {
        let mut full = vec!["install"];
        full.extend_from_slice(args);
        self.ms_with(&full, &self.tools(options))
    }

    fn tools(&self, options: RunOptions) -> RunOptions {
        options.env("PATH", self.sandbox.bin_dir().display().to_string())
    }

    /// `<sandbox>/tmp/<name>` as a string.
    fn tmp(&self, name: &str) -> String {
        self.sandbox.tmp().join(name).display().to_string()
    }

    fn api(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    fn calls(&self) -> Vec<UvCall> {
        fake_uv::uv_calls(&self.sandbox)
    }

    fn uv(&self, fake: &FakeUv) -> PathBuf {
        fake_uv::fake_uv(&self.sandbox, fake)
    }

    /// Serve `archive` and point the debug-build hook at it (§17.14 "Test hook").
    fn hook(&self, archive: Vec<u8>) -> RunOptions {
        let sha = airs_test_harness::sha256_hex(&archive);
        self.server.set_uv_archive(archive);
        RunOptions::new()
            .env(
                "AIRS_CLI_TEST_UV_ARCHIVE_URL",
                self.server.uv_archive_url(&fake_uv::archive_file_name()),
            )
            .env("AIRS_CLI_TEST_UV_ARCHIVE_SHA256", sha)
            .allow_writes_under("data")
    }

    fn tools_dir(&self) -> PathBuf {
        self.sandbox.data_dir().join("airs-cli/tools")
    }

    fn managed_dir(&self) -> PathBuf {
        self.tools_dir()
            .join(format!("uv-0.12.17-{}", fake_uv::host_target()))
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn sha(text: &str) -> String {
    fake_uv::sha256_text(text)
}

// ---------------------------------------------------------------------------
// pypi-auth (§17.12, D194)
// ---------------------------------------------------------------------------

mod pypi_auth {
    use super::*;

    /// MI§3 with D194: the TS layout with the URL withheld; json is the service shape
    /// `{url, expiresAt}` (`modelsecurity.spec.ts:794-809`); table the two keys; the hint on
    /// stderr; the credential nowhere (the runner's leak check).
    #[test]
    fn every_format_withholds_the_credential() {
        let f = fx();
        let out = f.ms(&["pypi-auth"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  PyPI Authentication\n\n  URL      {WITHHELD_URL}\n  Expires  {}\n",
                fx::PYPI_EXPIRES
            )
        );
        assert_eq!(out.stderr, HINT);
        assert_eq!(f.api(), ["GET /aims/mgmt/v1/pypi/authenticate"]);
        let json = f.ms(&["pypi-auth", "--output", "json"]);
        json.assert_success();
        assert_eq!(
            json.json(),
            json!({"url": WITHHELD_URL, "expiresAt": fx::PYPI_EXPIRES})
        );
        let table = f.ms(&["pypi-auth", "--output", "table"]);
        table.assert_success();
        assert!(table.stdout.contains("url"), "{}", table.stdout);
        assert!(table.stdout.contains(WITHHELD_URL));
        assert!(table.stdout.contains("expiresAt"));
        // --quiet: the data stays, the banner, section and hint go.
        let quiet = f.ms(&["--quiet", "pypi-auth"]);
        quiet.assert_success();
        assert_eq!(
            quiet.stdout,
            format!(
                "  URL      {WITHHELD_URL}\n  Expires  {}\n",
                fx::PYPI_EXPIRES
            )
        );
        assert_eq!(quiet.stderr, "");
    }

    /// The tenant's `defaultOutput` is ignored (choice 19).
    #[test]
    fn the_tenant_default_output_is_ignored() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |config| {
            config.set("defaultOutput", "json");
        });
        sandbox.register(&[&tenant], Some("prod"));
        let out = run(
            &rust(),
            &sandbox,
            &["model-security", "pypi-auth"],
            &RunOptions::new(),
        );
        out.assert_success();
        assert!(out.stdout.starts_with(BANNER), "{}", out.stdout);
    }

    /// Every unusable or odd URL the service may send is printed only in its withheld form.
    #[test]
    fn odd_urls_are_withheld_too() {
        for (url, form) in [
            (
                "http://oauth2accesstoken:FAKE-PYPI-SECRET-100@pypi.invalid/s/",
                "http://[withheld]@pypi.invalid/s/",
            ),
            // A URL without a credential is still the registered URL: withheld whole (§17.12).
            ("https://pypi.invalid/open/simple/", "[withheld]"),
            (
                "https://FAKE-PYPI-SECRET-100@pypi.invalid/s/",
                "https://[withheld]@pypi.invalid/s/",
            ),
            (
                "https://oauth2accesstoken:@pypi.invalid/s/",
                "https://[withheld]@pypi.invalid/s/",
            ),
            (
                "https://u:FAKE-PYPI-SECRET-100@pypi.invalid/s/?token=FAKE-PYPI-SECRET-100x",
                "https://[withheld]@pypi.invalid/s/?[withheld]",
            ),
            (
                "https://u:FAKE-PYPI-SECRET-100@pypi.invalid/s/#FAKE-PYPI-SECRET-100",
                "https://[withheld]@pypi.invalid/s/#[withheld]",
            ),
            (
                "https://u:FAKE-PYPI-SECRET-100@pypi.invalid/s/\u{1b}[31m",
                "https://[withheld]@pypi.invalid/s/%1B[31m",
            ),
            ("not a url FAKE-PYPI-SECRET-100", "[withheld]"),
        ] {
            let f = fx();
            f.server
                .modelsec(|data| data.pypi_url = Some(url.to_owned()));
            let out = f.ms(&["pypi-auth", "--output", "json"]);
            out.assert_success();
            assert_eq!(out.json()["url"], form, "{url:?}");
        }
    }

    /// `--url-file`: a new 0600 file with the full URL and a newline, no temporary left,
    /// the success line on stderr; the json still withheld.
    #[test]
    fn the_url_file_is_the_only_channel_for_the_full_url() {
        let f = fx();
        let path = f.tmp("pypi.url");
        let out = f.ms(&["pypi-auth", "--url-file", &path, "--output", "json"]);
        out.assert_success();
        assert_eq!(out.json()["url"], WITHHELD_URL);
        assert_eq!(
            out.stderr,
            format!("  ✓ Wrote the PyPI index URL, credential included, to {path} (mode 0600).\n")
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", fx::pypi_url(TSG))
        );
        assert_eq!(mode(Path::new(&path)), 0o600);
        assert_eq!(listing(&f.sandbox.tmp()), ["pypi.url"], "no temporary left");
        // A relative path names the working directory.
        let f = fx();
        let out = f.ms_with(
            &["--quiet", "pypi-auth", "--url-file", "rel.url"],
            &RunOptions::new().allow_writes_under("cwd"),
        );
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert!(f.sandbox.cwd().join("rel.url").is_file());
    }

    /// The `--url-file` refusals come before the tenant and send nothing.
    #[test]
    fn url_file_refusals_come_first() {
        let f = bare();
        for (value, code, message) in [
            ("", 2, "\n  ✗ --url-file needs a path\n\n".to_owned()),
            (
                "-",
                2,
                "\n  ✗ --url-file - would print the credential; give a file path\n\n".to_owned(),
            ),
        ] {
            let out = f.ms(&["pypi-auth", "--url-file", value]);
            out.assert_code(code);
            assert_eq!(out.stderr, message);
            assert_eq!(out.stdout, "");
        }
        let existing = f.sandbox.tmp().join("taken.url");
        std::fs::write(&existing, "keep").unwrap();
        let dangling = f.sandbox.tmp().join("dangling.url");
        std::os::unix::fs::symlink(f.sandbox.tmp().join("nowhere"), &dangling).unwrap();
        for path in [&existing, &dangling] {
            let shown = path.display().to_string();
            let out = f.ms(&["pypi-auth", "--url-file", &shown]);
            out.assert_code(1);
            assert_eq!(
                out.stderr,
                format!("\n  ✗ Error: {shown} already exists; choose another --url-file\n\n")
            );
        }
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "keep");
        let missing = f.tmp("no/such/dir.url");
        let out = f.ms(&["pypi-auth", "--url-file", &missing]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            format!(
                "\n  ✗ Error: Cannot write {missing}; check that its directory exists and is writable\n\n"
            )
        );
        assert_eq!(f.server.request_count(), 0);
    }

    /// An unusable URL is never written (D201): nothing on disk, exit 1.
    #[test]
    fn an_unusable_url_is_not_written() {
        for url in [
            "http://u:FAKE-PYPI-SECRET-100@pypi.invalid/s/",
            "https://pypi.invalid/s/",
            "https://u:FAKE-PYPI-SECRET-100@pypi.invalid/s/?q=1",
        ] {
            let f = fx();
            f.server
                .modelsec(|data| data.pypi_url = Some(url.to_owned()));
            let path = f.tmp("pypi.url");
            let out = f.ms(&["pypi-auth", "--url-file", &path]);
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "\n  ✗ Error: The PyPI auth response is not a usable index URL; nothing was written\n\n"
            );
            assert!(listing(&f.sandbox.tmp()).is_empty(), "{url}");
        }
    }

    /// Errors are §6 messages: server text (which may carry the credential) is never
    /// printed; 5xx are read retries (choice 24); a body without `url` is a decode error.
    #[test]
    fn errors_never_print_server_text() {
        let body = json!({"error": {"message": format!("FAKE-SERVER-MSG https://oauth2accesstoken:{}@x/", secret())}});
        for (status, line) in [(400, "HTTP 400"), (403, "HTTP 403"), (404, "HTTP 404")] {
            let f = fx();
            f.server.set_default(
                Route::ModelSecurity(Ms::PypiAuth),
                Planned::json(status, &body),
            );
            let out = f.ms(&["pypi-auth"]);
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert!(out.stderr.contains(line), "{}", out.stderr);
            assert!(!out.stderr.contains("FAKE-SERVER-MSG"), "{}", out.stderr);
        }
        let f = fx();
        f.server.set_default(
            Route::ModelSecurity(Ms::PypiAuth),
            Planned::json(503, &body).with_retry_after(0),
        );
        let out = f.ms(&["pypi-auth"]);
        out.assert_code(1);
        assert!(out.stderr.contains("HTTP 503"));
        assert_eq!(f.server.ms_requests(Ms::PypiAuth).len(), 6, "read retries");
        let f = fx();
        f.server.set_default(
            Route::ModelSecurity(Ms::PypiAuth),
            Planned::json(200, &json!({"expires_at": "x"})),
        );
        let out = f.ms(&["pypi-auth"]);
        out.assert_code(1);
        assert!(
            out.stderr.contains("AISEC_RESPONSE_VALIDATION"),
            "{}",
            out.stderr
        );
    }

    /// The debug log records the operation name, status and headers only (D64): no
    /// credential (the runner checks the log for the marker).
    #[test]
    fn the_debug_log_holds_no_credential() {
        let f = fx();
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let path = f.tmp("pypi.url");
        let out = f.ms_with(
            &[
                "--debug",
                "pypi-auth",
                "--url-file",
                &path,
                "--output",
                "json",
            ],
            &RunOptions::new()
                .env("XDG_STATE_HOME", &state)
                .secret(&fx::pypi_url(TSG)),
        );
        out.assert_success();
        let (log, records) = debug_log::only_log(&f.sandbox);
        let text = std::fs::read_to_string(log).unwrap();
        assert!(!text.contains("pypi.invalid"), "no body");
        let operations: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(
            operations,
            ["oauth.token", "airs.model_security.get_pypi_auth"]
        );
    }

    /// A signal while the request is held: `no data was written`, nothing on disk.
    #[test]
    fn a_signal_before_the_answer_writes_nothing() {
        for (signal, code) in [("INT", 130), ("TERM", 143)] {
            let f = fx();
            f.server
                .push_once(Route::ModelSecurity(Ms::PypiAuth), Planned::held());
            let path = f.tmp("pypi.url");
            let running = spawn(
                &rust(),
                &f.sandbox,
                &["model-security", "pypi-auth", "--url-file", &path],
                &RunOptions::new().expect_signal(),
            );
            assert!(f.server.wait_for_route(
                Route::ModelSecurity(Ms::PypiAuth),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal(signal);
            let out = running.wait();
            f.server.release_held();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "\n  ✗ Error: Interrupted; no data was written\n\n"
            );
            assert!(listing(&f.sandbox.tmp()).is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// install (§17.13, D195–D201)
// ---------------------------------------------------------------------------

mod install {
    use super::*;

    /// The two steps with the fake uv: argv exactly, the credential only in `uv add`'s
    /// environment (decoded), no `UV_NO_CONFIG`, each child in its own process group,
    /// stdout empty, uv's lines and the status and success lines on stderr.
    #[test]
    fn the_credential_reaches_uv_add_through_its_environment_only() {
        let f = fx();
        let uv = f.uv(&FakeUv::default());
        let dir = f.tmp("proj");
        let out = f.install(&["--dir", &dir, "--extras", "aws"]);
        out.assert_success();
        assert_eq!(out.stdout, "", "stdout carries no data");
        // The two forwarding threads may interleave a step's stdout and stderr line.
        let forwarded = out
            .stderr
            .replace("fake uv stdout line\nfake uv stderr line\n", "FORWARDED\n")
            .replace("fake uv stderr line\nfake uv stdout line\n", "FORWARDED\n");
        assert_eq!(
            forwarded,
            format!(
                "  Using uv 0.12.17 ({})\n  → uv init\nFORWARDED\n  → uv add\nFORWARDED\n  ✓ model-security-client installed successfully.\n  Activate:  cd {dir}\n  Later uv commands that use the AIRS index need the credential again: set UV_INDEX_AIRS_MODEL_SECURITY_USERNAME and UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD from the URL that 'airs model-security pypi-auth --url-file <file>' saves.\n",
                uv.display()
            )
        );
        let calls = f.calls();
        let argv: Vec<Vec<String>> = calls.iter().map(|call| call.argv.clone()).collect();
        assert_eq!(
            argv,
            [
                vec!["--version".to_owned()],
                vec![
                    "init".to_owned(),
                    "--no-workspace".to_owned(),
                    "--".to_owned(),
                    dir.clone()
                ],
                vec![
                    "add".to_owned(),
                    "--no-build".to_owned(),
                    "--project".to_owned(),
                    dir.clone(),
                    "--index".to_owned(),
                    format!("airs-model-security={}", fx::PYPI_INDEX),
                    "--".to_owned(),
                    "model-security-client[aws]".to_owned()
                ]
            ]
        );
        let (init, add) = (&calls[1], &calls[2]);
        assert_eq!(
            (init.username_sha.as_ref(), init.password_sha.as_ref()),
            (None, None)
        );
        assert_eq!(add.username_sha, Some(sha("oauth2accesstoken")));
        assert_eq!(add.password_sha, Some(sha(&secret())));
        assert!(calls.iter().all(|call| !call.no_config));
        for call in &calls {
            assert_eq!(
                call.pgid, call.pid,
                "each child leads its own process group"
            );
        }
        // pyproject.toml records the named, credential-free index.
        let pyproject = std::fs::read_to_string(Path::new(&dir).join("pyproject.toml")).unwrap();
        assert!(pyproject.contains("name = \"airs-model-security\""));
        assert!(pyproject.contains(fx::PYPI_INDEX));
        assert_eq!(f.api(), ["GET /aims/mgmt/v1/pypi/authenticate"]);
    }

    /// A user's own credential variables never reach `uv init`, and are overridden for
    /// `uv add` (§17.13 "The credential channel").
    #[test]
    fn the_users_own_credential_variables_are_replaced() {
        let f = fx();
        f.uv(&FakeUv::default());
        let dir = f.tmp("proj");
        let out = f.install_with(
            &["--dir", &dir],
            RunOptions::new()
                .env("UV_INDEX_AIRS_MODEL_SECURITY_USERNAME", "mine")
                .env("UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD", "mine-too"),
        );
        out.assert_success();
        let calls = f.calls();
        assert_eq!(calls[1].username_sha, None);
        assert_eq!(calls[1].password_sha, None);
        assert_eq!(calls[2].password_sha, Some(sha(&secret())));
    }

    /// `--quiet` is passed to uv; the forwarded lines still print; the Rust lines go.
    #[test]
    fn quiet_is_passed_to_uv() {
        let f = fx();
        f.uv(&FakeUv::default());
        let dir = f.tmp("proj");
        let out = f.install(&["--quiet", "--dir", &dir]);
        out.assert_success();
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr.matches("fake uv").count(), 4, "{}", out.stderr);
        assert!(!out.stderr.contains("installed successfully"));
        let calls = f.calls();
        assert_eq!(calls[1].argv[0], "--quiet");
        assert_eq!(calls[2].argv[0], "--quiet");
    }

    /// uv's output is scrubbed of the credential (D199): the runner's leak check passes.
    #[test]
    fn uv_output_is_scrubbed() {
        let f = fx();
        f.uv(&FakeUv {
            echo_credential: true,
            ..FakeUv::default()
        });
        let dir = f.tmp("proj");
        let out = f.install(&["--dir", &dir]);
        out.assert_success();
        assert_eq!(out.stderr.matches("fake uv saw [withheld]").count(), 2);
    }

    /// A credential on a uv output line longer than 64 KiB, across the split point, is
    /// still withheld whole (review finding): no half of it is printed in clear.
    #[test]
    fn a_credential_across_a_long_line_split_is_withheld() {
        // `<padding>fake uv saw <password>`: the password starts 12 bytes after the
        // padding, so these put the 64 KiB split inside it.
        for padding in [65_536 - 12 - 6, 65_536 - 12 - 15] {
            let f = fx();
            f.uv(&FakeUv {
                echo_credential: true,
                echo_padding: padding,
                ..FakeUv::default()
            });
            let dir = f.tmp("proj");
            let out = f.install(&["--dir", &dir]);
            out.assert_success();
            let joined = out.stderr.replace('\n', "");
            assert!(!joined.contains(&secret()), "{padding}: split in clear");
            assert_eq!(
                out.stderr.matches("[withheld]").count(),
                2,
                "{padding}: both echoes withheld"
            );
        }
    }

    /// A `uv add` that wrote no `uv.lock` in the project (it locked elsewhere, such as a
    /// uv workspace above it) fails the install: the lock that was written is unchecked.
    #[test]
    fn a_missing_lock_fails_the_install() {
        let f = fx();
        f.uv(&FakeUv {
            skip_lock: true,
            ..FakeUv::default()
        });
        let dir = f.tmp("proj");
        let out = f.install(&["--dir", &dir]);
        out.assert_code(1);
        assert!(
            out.stderr.contains(&format!(
                "✗ Error: uv did not write {dir}/uv.lock; it may have locked a uv workspace above the project (or UV_FROZEN is set). Check any parent uv.lock for the PyPI index credential before sharing it.\n"
            )),
            "{}",
            out.stderr
        );
        assert!(!out.stderr.contains("installed successfully"));
    }

    /// The dry run (D197): the plan on stdout with the credential withheld and POSIX
    /// quoting, printed under `--quiet` too; uv runs only for `--version`; nothing is
    /// created; the PyPI request is still sent (choice 31).
    #[test]
    fn the_dry_run_prints_a_withheld_posix_plan() {
        let f = fx();
        let uv = f.uv(&FakeUv::default());
        let dir = f.tmp("$(id)");
        let quoted = format!("'{dir}'");
        for args in [
            vec!["--dry-run", "--dir", dir.as_str()],
            vec!["--dry-run", "--dir", dir.as_str(), "--output", "json"],
        ] {
            let out = f.install(&args);
            out.assert_success();
            assert_eq!(
                out.stdout,
                format!(
                    "{BANNER}\n  Commands that would be executed\n\n  $ {uv} init --no-workspace -- {quoted}\n  $ UV_INDEX_AIRS_MODEL_SECURITY_USERNAME=[withheld] UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD=[withheld] {uv} add --no-build --project {quoted} --index airs-model-security={index} -- 'model-security-client[all]'\n",
                    uv = uv.display(),
                    index = fx::PYPI_INDEX
                )
            );
        }
        let quiet = f.install(&["--quiet", "--dry-run", "--dir", &dir]);
        quiet.assert_success();
        assert_eq!(
            quiet.stdout,
            format!(
                "  $ {uv} --quiet init --no-workspace -- {quoted}\n  $ UV_INDEX_AIRS_MODEL_SECURITY_USERNAME=[withheld] UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD=[withheld] {uv} --quiet add --no-build --project {quoted} --index airs-model-security={index} -- 'model-security-client[all]'\n",
                uv = uv.display(),
                index = fx::PYPI_INDEX
            )
        );
        assert!(!Path::new(&dir).exists());
        assert!(f.calls().iter().all(|call| call.argv == ["--version"]));
        assert_eq!(f.server.ms_requests(Ms::PypiAuth).len(), 3);
    }

    /// The `--extras` and `--dir` usage errors come first (exit 2, no request).
    #[test]
    fn argument_errors_come_first() {
        let f = bare();
        for (args, message) in [
            (
                &["--extras", "ALL"][..],
                "Invalid extras \"ALL\". Valid: all, aws, gcp, azure, artifactory, gitlab",
            ),
            (&["--dir", ""], "--dir needs a path"),
            (
                &["--output", "yaml"],
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            ),
        ] {
            let out = f.install(args);
            out.assert_code(2);
            assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"));
            assert_eq!(out.stdout, "");
        }
        assert_eq!(f.server.request_count(), 0);
    }

    /// Every `--dir` refusal (D198) comes before uv runs and before any request.
    #[test]
    fn dir_refusals_come_before_any_request() {
        let f = fx();
        f.uv(&FakeUv::default());
        let taken = f.sandbox.tmp().join("taken");
        std::fs::create_dir(&taken).unwrap();
        let dangling = f.sandbox.tmp().join("dangling");
        std::os::unix::fs::symlink(f.sandbox.tmp().join("nowhere"), &dangling).unwrap();
        let file = f.sandbox.tmp().join("file");
        std::fs::write(&file, "x").unwrap();
        for path in [&taken, &dangling, &file] {
            let shown = path.display().to_string();
            let out = f.install(&["--dir", &shown]);
            out.assert_code(1);
            assert_eq!(
                out.stderr,
                format!("\n  ✗ Error: {shown} already exists; choose another --dir\n\n")
            );
        }
        let missing = f.tmp("no/such");
        let out = f.install(&["--dir", &missing]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            format!(
                "\n  ✗ Error: Cannot create {missing}; its parent directory does not exist\n\n"
            )
        );
        let under_file = f.tmp("file/sub");
        let out = f.install(&["--dir", &under_file]);
        out.assert_code(1);
        assert!(out.stderr.contains("its parent directory does not exist"));
        // A target inside a uv workspace (the parent pyproject.toml would be rewritten).
        let workspace = f.sandbox.tmp().join("ws");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(
            workspace.join("pyproject.toml"),
            "[project]\nname = \"ws\"\n\n[tool.uv.workspace]\nmembers = []\n",
        )
        .unwrap();
        std::fs::create_dir(workspace.join("pkgs")).unwrap();
        let inside = workspace.join("pkgs/new").display().to_string();
        let out = f.install(&["--dir", &inside]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            format!(
                "\n  ✗ Error: {inside} is inside the uv workspace at {}; choose a --dir outside it\n\n",
                workspace.display()
            )
        );
        std::fs::write(workspace.join("pyproject.toml"), "not = [toml").unwrap();
        let out = f.install(&["--dir", &inside]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            format!(
                "\n  ✗ Error: Cannot check {} for a uv workspace; choose a --dir outside it\n\n",
                workspace.join("pyproject.toml").display()
            )
        );
        // A leading dash is a path, never a uv option: refused as an existing path here.
        assert_eq!(f.server.request_count(), 0);
        assert!(f.calls().is_empty(), "uv did not run");
    }

    /// A `--dir` that starts with `-` is passed after `--` (D198).
    #[test]
    fn a_leading_dash_dir_stays_a_path() {
        let f = fx();
        f.uv(&FakeUv::default());
        let out = f.install_with(
            &["--dir", "-odd dir"],
            RunOptions::new().allow_writes_under("cwd"),
        );
        out.assert_success();
        let abs = f.sandbox.cwd().join("-odd dir").display().to_string();
        let calls = f.calls();
        assert_eq!(
            calls[1].argv,
            ["init", "--no-workspace", "--", abs.as_str()]
        );
        assert!(out.stderr.contains(&format!("Activate:  cd '{abs}'")));
    }

    /// No uv on `PATH` (D195): the hint naming `--fetch-uv`, no request; a uv older than
    /// 0.12.0 or one that does not answer `--version` is not usable.
    #[test]
    fn uv_must_be_present_and_recent() {
        let f = fx();
        let dir = f.tmp("proj");
        let out = f.install(&["--dir", &dir]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            format!(
                "\n  ✗ Error: uv was not found on PATH. Install uv (https://docs.astral.sh/uv/) or re-run with --fetch-uv to download uv 0.12.17 into {}.\n\n",
                f.tools_dir().display()
            )
        );
        for version in ["uv 0.11.9 (old)", "something else"] {
            let uv = f.uv(&FakeUv {
                version: version.to_owned(),
                ..FakeUv::default()
            });
            let out = f.install(&["--dir", &dir]);
            out.assert_code(1);
            assert_eq!(
                out.stderr,
                format!(
                    "\n  ✗ Error: {} is not a usable uv (model-security install needs uv 0.12.0 or later; re-run with --fetch-uv to use uv 0.12.17)\n\n",
                    uv.display()
                )
            );
        }
        assert_eq!(f.server.request_count(), 0);
        assert!(!Path::new(&dir).exists());
        // A non-executable uv is skipped on PATH.
        let uv = f.uv(&FakeUv::default());
        std::fs::set_permissions(&uv, std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = f.install(&["--dir", &dir]);
        out.assert_code(1);
        assert!(out.stderr.contains("uv was not found on PATH"));
    }

    /// The step failures (TS texts), the `add` follow-up line, a signalled child; the
    /// directory is never removed (choice 30).
    #[test]
    fn step_failures_name_the_step() {
        let cases: [(FakeUv, String, Option<&str>); 3] = [
            (
                FakeUv {
                    init_exit: 3,
                    ..FakeUv::default()
                },
                "uv init failed with exit code 3".to_owned(),
                None,
            ),
            (
                FakeUv {
                    add_exit: 4,
                    ..FakeUv::default()
                },
                "uv add failed with exit code 4".to_owned(),
                Some("add"),
            ),
            (
                FakeUv {
                    kill_self_in: Some("add"),
                    ..FakeUv::default()
                },
                "uv add was terminated by signal 9".to_owned(),
                Some("add"),
            ),
        ];
        for (fake, message, add) in cases {
            let f = fx();
            f.uv(&fake);
            let dir = f.tmp("proj");
            let out = f.install(&["--dir", &dir]);
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            let mut expected = format!("\n  ✗ Error: {message}\n");
            if add.is_some() {
                expected.push_str(&format!(
                    "    {dir} was created, but model-security-client was not added. Remove {dir} and re-run, or add it with uv yourself.\n    uv add runs with --no-build so that no package build code sees the index credential; if uv reports a dependency that needs building, build it yourself without the credential in the environment, then add model-security-client with uv.\n"
                ));
            }
            expected.push('\n');
            assert!(out.stderr.ends_with(&expected), "{}", out.stderr);
            assert!(Path::new(&dir).is_dir(), "the directory stays");
        }
    }

    /// The persistence check (D196): a uv that wrote the credential into `uv.lock` fails
    /// the install without showing it.
    #[test]
    fn a_persisted_credential_is_reported() {
        let f = fx();
        f.uv(&FakeUv {
            write_credential: true,
            ..FakeUv::default()
        });
        let dir = f.tmp("proj");
        let out = f.install(&["--dir", &dir]);
        out.assert_code(1);
        assert!(
            out.stderr.ends_with(&format!(
                "\n  ✗ Error: The PyPI index credential was written to {dir}/uv.lock; remove it from the file before sharing the project.\n\n"
            )),
            "{}",
            out.stderr
        );
    }

    /// An unusable index URL never reaches uv (D201).
    #[test]
    fn an_unusable_index_url_is_refused() {
        for url in [
            "http://oauth2accesstoken:FAKE-PYPI-SECRET-100@pypi.invalid/s/",
            "https://pypi.invalid/s/",
            "https://oauth2accesstoken:@pypi.invalid/s/",
            "https://u:FAKE-PYPI-SECRET-100@pypi.invalid/s/?q=1",
            "https://u:FAKE-PYPI-SECRET-100@pypi.invalid/s/#f",
            "https://u:FAKE-PYPI-SECRET-100@pypi.invalid/s/\u{7}",
            "not a url FAKE-PYPI-SECRET-100",
        ] {
            let f = fx();
            f.uv(&FakeUv::default());
            f.server
                .modelsec(|data| data.pypi_url = Some(url.to_owned()));
            let dir = f.tmp("proj");
            let out = f.install(&["--dir", &dir, "--dry-run"]);
            out.assert_code(1);
            assert_eq!(out.stdout, "");
            assert!(
                out.stderr.ends_with(
                    "\n  ✗ Error: The PyPI auth response is not a usable index URL; nothing was installed.\n\n"
                ),
                "{url}: {}",
                out.stderr
            );
            assert!(f.calls().iter().all(|call| call.argv == ["--version"]));
        }
    }

    /// D200: a signal while `uv init` runs is forwarded once to uv's own process group;
    /// the CLI waits for it and reports what may be incomplete; no child is left.
    #[test]
    fn a_signal_is_forwarded_to_the_child_and_waited_for() {
        for (signal, code, step) in [("TERM", 143, "init"), ("INT", 130, "add")] {
            let f = fx();
            f.uv(&FakeUv {
                sleep_in: Some(step),
                ..FakeUv::default()
            });
            let dir = f.tmp("proj");
            let mut running = spawn(
                &rust(),
                &f.sandbox,
                &["model-security", "install", "--dir", &dir],
                &f.tools(RunOptions::new().expect_signal()),
            );
            assert!(running.wait_for_stderr("fake uv sleeping", Duration::from_secs(20)));
            let cli_pid = running.pid();
            running.send_signal(signal);
            let out = running.wait();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert!(
                out.stderr.ends_with(&format!(
                    "\n  ✗ Error: Interrupted; uv {step} was stopped; {dir} may be incomplete\n\n"
                )),
                "{}",
                out.stderr
            );
            let calls = f.calls();
            let sleeper = calls.last().unwrap();
            assert_eq!(sleeper.signals, [signal], "forwarded exactly once");
            assert_ne!(sleeper.pgid, Some(cli_pid), "uv has its own process group");
            assert!(!sleeper.finished, "the child ended by the forwarded signal");
        }
    }
}

/// D200: a second signal while the forwarded one did not end uv kills uv's group; the
/// CLI still waits and reports; nothing is left running.
#[test]
fn a_second_signal_kills_a_stubborn_child() {
    let f = fx();
    f.uv(&FakeUv {
        sleep_in: Some("init"),
        stubborn: true,
        ..FakeUv::default()
    });
    let dir = f.tmp("proj");
    let mut running = spawn(
        &rust(),
        &f.sandbox,
        &["model-security", "install", "--dir", &dir],
        &f.tools(RunOptions::new().expect_signal()),
    );
    assert!(running.wait_for_stderr("fake uv sleeping", Duration::from_secs(20)));
    let started = std::time::Instant::now();
    running.send_signal("TERM");
    let signals = fake_uv::calls_dir(&f.sandbox).join("2/signals");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !std::fs::read_to_string(&signals).is_ok_and(|text| text.contains("TERM")) {
        assert!(
            std::time::Instant::now() < deadline,
            "the first signal was not forwarded"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    running.send_signal("TERM");
    let out = running.wait();
    out.assert_code(143);
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "uv was killed, not waited out"
    );
    assert!(
        out.stderr.ends_with(&format!(
            "\n  ✗ Error: Interrupted; uv init was stopped; {dir} may be incomplete\n\n"
        )),
        "{}",
        out.stderr
    );
    let calls = f.calls();
    assert_eq!(
        calls[1].signals,
        ["TERM"],
        "forwarded once; the second was SIGKILL"
    );
    assert!(!calls[1].finished);
}

// ---------------------------------------------------------------------------
// --fetch-uv (§17.14)
// ---------------------------------------------------------------------------

mod fetch_uv {
    use super::*;

    fn standard(f: &Fx) -> RunOptions {
        f.hook(fake_uv::uv_archive(&f.sandbox, &FakeUv::default()))
    }

    /// The download, the verified install (0700 / 0755 / 0600, no temporary), the install
    /// with the managed uv; a second run reuses it with no download.
    #[test]
    fn the_pinned_uv_is_downloaded_verified_and_reused() {
        let f = fx();
        let options = standard(&f);
        let dir = f.tmp("proj");
        let out = f.install_with(&["--fetch-uv", "--dir", &dir], options.clone());
        out.assert_success();
        let managed = f.managed_dir();
        let target = fake_uv::host_target();
        assert!(
            out.stderr.starts_with(&format!(
                "  → Downloading uv 0.12.17 ({target})\n  ✓ Installed uv 0.12.17 in {}\n  Using uv 0.12.17 ({}/uv)\n  → uv init\n",
                managed.display(),
                managed.display()
            )),
            "{}",
            out.stderr
        );
        assert_eq!(mode(&f.tools_dir()), 0o700);
        assert_eq!(mode(&managed), 0o700);
        assert_eq!(mode(&managed.join("uv")), 0o755);
        assert_eq!(mode(&managed.join("SHA256SUMS")), 0o600);
        assert_eq!(listing(&managed), ["SHA256SUMS", "uv"]);
        assert_eq!(
            listing(&f.tools_dir()),
            [format!("uv-0.12.17-{target}")],
            "no temporary left"
        );
        let sums = std::fs::read_to_string(managed.join("SHA256SUMS")).unwrap();
        assert!(sums.ends_with("  uv\n") && sums.contains(&format!("  uv-{target}.tar.gz\n")));
        assert_eq!(f.server.route_count(Route::UvRelease), 1);
        // The download names the program (DESIGN §21.4 family 14, choice 11).
        let download = f
            .server
            .requests()
            .into_iter()
            .find(|request| request.route == Route::UvRelease)
            .unwrap();
        let agent = download
            .headers
            .iter()
            .find(|(name, _)| name == "user-agent")
            .map(|(_, value)| value.as_str());
        assert_eq!(agent, Some(concat!("airs/", env!("CARGO_PKG_VERSION"))));
        assert_eq!(
            f.calls().len(),
            3,
            "--version once (after the install), init, add"
        );
        // Reuse: verified, no download.
        let second = f.tmp("proj2");
        let out = f.install_with(&["--fetch-uv", "--dir", &second], options);
        out.assert_success();
        assert!(
            out.stderr
                .starts_with(&format!("  Using uv 0.12.17 ({}/uv)\n", managed.display()))
        );
        assert_eq!(
            f.server.route_count(Route::UvRelease),
            1,
            "no second download"
        );
    }

    /// A dry run with no managed copy downloads nothing and creates nothing.
    #[test]
    fn a_dry_run_downloads_nothing() {
        let f = fx();
        let options = standard(&f);
        let dir = f.tmp("proj");
        let out = f.install_with(&["--fetch-uv", "--dry-run", "--dir", &dir], options);
        out.assert_success();
        let target = fake_uv::host_target();
        assert!(
            out.stdout.contains(&format!(
                "  # would download uv 0.12.17 (uv-{target}.tar.gz, sha256 "
            )),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains(&format!(
            "  $ {}/uv init --no-workspace -- {dir}\n",
            f.managed_dir().display()
        )));
        assert_eq!(f.server.route_count(Route::UvRelease), 0);
        assert!(!f.tools_dir().exists());
    }

    /// A wrong hash leaves nothing behind and mints no credential (before the tenant).
    #[test]
    fn a_hash_mismatch_installs_nothing() {
        let f = fx();
        let archive = fake_uv::uv_archive(&f.sandbox, &FakeUv::default());
        let options = f
            .hook(archive)
            .env("AIRS_CLI_TEST_UV_ARCHIVE_SHA256", "0".repeat(64));
        let out = f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options);
        out.assert_code(1);
        assert!(out.stderr.ends_with(
            "\n  ✗ Error: The downloaded uv archive does not match its pinned SHA-256; nothing was installed.\n\n"
        ));
        assert!(listing(&f.tools_dir()).is_empty());
        assert!(f.server.ms_requests(Ms::PypiAuth).is_empty());
        assert_eq!(f.server.route_count(Route::Token), 0);
    }

    /// Traversal, absolute and link entries are skipped without touching the filesystem;
    /// only `uv-<target>/uv` is installed.
    #[test]
    fn unexpected_entries_are_skipped() {
        let f = fx();
        let target = fake_uv::host_target();
        let script = fake_uv::fake_uv_script(&FakeUv::default(), &fake_uv::calls_dir(&f.sandbox));
        let mut entries = vec![
            TarEntry::file("../../escape", b"x"),
            TarEntry::file(&format!("{}/abs-escape", f.sandbox.tmp().display()), b"x"),
            TarEntry::link(&format!("uv-{target}/link"), b'2', "/etc/passwd"),
            TarEntry::link(&format!("uv-{target}/hard"), b'1', "/etc/passwd"),
        ];
        entries.extend(fake_uv::uv_archive_entries(&script));
        let options = f.hook(fake_uv::tar_gz(&entries));
        let out = f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options);
        out.assert_success();
        assert_eq!(listing(&f.managed_dir()), ["SHA256SUMS", "uv"]);
        assert!(!f.sandbox.tmp().join("abs-escape").exists());
        assert!(!f.sandbox.root().join("escape").exists());
    }

    /// The malformed archives: a symlink or hard link named `uv-<target>/uv`, a duplicate,
    /// a bad header checksum; and the archive without uv. Each leaves nothing.
    #[test]
    fn malformed_archives_are_refused() {
        let target = fake_uv::host_target();
        let name = format!("uv-{target}/uv");
        let malformed =
            "The uv archive is malformed or has an unexpected layout; nothing was installed.";
        let cases: Vec<(Vec<TarEntry>, String)> = vec![
            (
                vec![TarEntry::link(&name, b'2', "/bin/sh")],
                malformed.to_owned(),
            ),
            (
                vec![TarEntry::link(&name, b'1', "/bin/sh")],
                malformed.to_owned(),
            ),
            (
                vec![TarEntry::file(&name, b"a"), TarEntry::file(&name, b"b")],
                malformed.to_owned(),
            ),
            (
                vec![TarEntry {
                    bad_checksum: true,
                    ..TarEntry::file(&name, b"a")
                }],
                malformed.to_owned(),
            ),
            (
                vec![TarEntry::file(&format!("uv-{target}/uvx"), b"a")],
                format!("The uv archive does not contain uv-{target}/uv; nothing was installed."),
            ),
            (
                vec![
                    TarEntry::pax_path("elsewhere/uv"),
                    TarEntry::file(&name, b"a"),
                ],
                format!("The uv archive does not contain uv-{target}/uv; nothing was installed."),
            ),
        ];
        for (entries, message) in cases {
            let f = fx();
            let options = f.hook(fake_uv::tar_gz(&entries));
            let out = f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options);
            out.assert_code(1);
            assert!(
                out.stderr.ends_with(&format!("\n  ✗ Error: {message}\n\n")),
                "{}",
                out.stderr
            );
            assert!(listing(&f.tools_dir()).is_empty(), "{message}");
        }
        // A pax path or a GNU long name that names uv is taken.
        for prefix in [TarEntry::pax_path(&name), TarEntry::gnu_long_name(&name)] {
            let f = fx();
            let script =
                fake_uv::fake_uv_script(&FakeUv::default(), &fake_uv::calls_dir(&f.sandbox));
            let options = f.hook(fake_uv::tar_gz(&[
                prefix,
                TarEntry::file("short", script.as_bytes()),
            ]));
            let out = f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options);
            out.assert_success();
        }
    }

    /// The download failures name only the class.
    #[test]
    fn download_failures_name_the_class() {
        let f = fx();
        let options = standard(&f);
        f.server
            .push_once(Route::UvRelease, Planned::empty_json(404));
        let out = f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options.clone());
        out.assert_code(1);
        assert!(
            out.stderr
                .ends_with("\n  ✗ Error: Cannot download uv 0.12.17: HTTP 404\n\n")
        );
        // A redirect off the loopback hop is refused without following it.
        f.server.push_once(
            Route::UvRelease,
            Planned::redirect(
                302,
                &format!("http://localhost:{}/elsewhere", f.server.addr().port()),
            ),
        );
        let out = f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options.clone());
        out.assert_code(1);
        assert!(
            out.stderr
                .ends_with("\n  ✗ Error: Cannot download uv 0.12.17: redirect refused\n\n"),
            "{}",
            out.stderr
        );
        // A body over the 64 MiB cap.
        f.server.push_once(
            Route::UvRelease,
            Planned::raw(200, "application/gzip", vec![0u8; 64 * 1024 * 1024 + 1]),
        );
        let out = f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options);
        out.assert_code(1);
        assert!(
            out.stderr
                .ends_with("\n  ✗ Error: Cannot download uv 0.12.17: response too large\n\n")
        );
        assert!(listing(&f.tools_dir()).is_empty());
        assert!(f.server.ms_requests(Ms::PypiAuth).is_empty());
    }

    /// An existing copy is verified and never replaced: a tampered `uv`, a symlinked
    /// tools directory and a group-writable directory are refused and left unchanged.
    #[test]
    fn an_unverified_copy_is_refused_and_left_alone() {
        let f = fx();
        let options = standard(&f);
        f.install_with(
            &["--fetch-uv", "--dry-run", "--dir", &f.tmp("p")],
            options.clone(),
        )
        .assert_success();
        f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options.clone())
            .assert_success();
        let uv = f.managed_dir().join("uv");
        std::fs::write(&uv, "#!/bin/sh\necho tampered\n").unwrap();
        let out = f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj2")], options.clone());
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            format!(
                "\n  ✗ Error: {} exists but is not the verified uv 0.12.17; remove it to download again.\n\n",
                f.managed_dir().display()
            )
        );
        assert_eq!(
            std::fs::read_to_string(&uv).unwrap(),
            "#!/bin/sh\necho tampered\n"
        );
        // A group-writable tools directory.
        let g = fx();
        let options = standard(&g);
        std::fs::create_dir_all(g.tools_dir()).unwrap();
        std::fs::set_permissions(g.tools_dir(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let out = g.install_with(&["--fetch-uv", "--dir", &g.tmp("proj")], options);
        out.assert_code(1);
        assert!(out.stderr.contains("Refusing to use"), "{}", out.stderr);
        assert!(listing(&g.tools_dir()).is_empty());
        // A symlinked tools directory.
        let h = fx();
        let options = standard(&h);
        std::fs::create_dir_all(h.sandbox.data_dir().join("airs-cli")).unwrap();
        std::fs::create_dir(h.sandbox.tmp().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(h.sandbox.tmp().join("elsewhere"), h.tools_dir()).unwrap();
        let out = h.install_with(&["--fetch-uv", "--dir", &h.tmp("proj")], options);
        out.assert_code(1);
        assert!(out.stderr.contains("Refusing to use"), "{}", out.stderr);
        assert!(listing(&h.sandbox.tmp().join("elsewhere")).is_empty());
    }

    /// A signal while the archive is held: `uv was not installed`, nothing left.
    #[test]
    fn an_interrupted_download_installs_nothing() {
        let f = fx();
        let options = standard(&f);
        f.server.push_once(Route::UvRelease, Planned::held());
        let running = spawn(
            &rust(),
            &f.sandbox,
            &[
                "model-security",
                "install",
                "--fetch-uv",
                "--dir",
                &f.tmp("proj"),
            ],
            &f.tools(options.expect_signal()),
        );
        assert!(
            f.server
                .wait_for_route(Route::UvRelease, 1, Duration::from_secs(20))
        );
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert!(
            out.stderr
                .ends_with("\n  ✗ Error: Interrupted; uv was not installed\n\n"),
            "{}",
            out.stderr
        );
        assert!(listing(&f.tools_dir()).is_empty());
    }

    /// The debug-build hook takes only a loopback http URL with a hash (exit 2).
    #[test]
    fn the_test_hook_is_loopback_only() {
        let f = bare();
        let out = f.install_with(
            &["--fetch-uv"],
            RunOptions::new().env(
                "AIRS_CLI_TEST_UV_ARCHIVE_URL",
                "http://127.0.0.1:9/x.tar.gz",
            ),
        );
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            "\n  ✗ AIRS_CLI_TEST_UV_ARCHIVE_URL must be a loopback http URL with AIRS_CLI_TEST_UV_ARCHIVE_SHA256\n\n"
        );
        assert_eq!(f.server.request_count(), 0);
    }

    /// Nothing reaches the real data directory: every run's `XDG_DATA_HOME` is the
    /// sandbox's, and a `--fetch-uv` install leaves the real `~/.local/share/airs-cli` as
    /// it was (only its metadata is looked at).
    #[test]
    fn the_real_data_directory_is_untouched() {
        let real =
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share/airs-cli"));
        let before = real.as_ref().map(|path| {
            std::fs::symlink_metadata(path)
                .ok()
                .map(|m| m.modified().ok())
        });
        let f = fx();
        let env = airs_test_harness::child_environment(&f.sandbox, &RunOptions::new());
        assert_eq!(
            env.get("XDG_DATA_HOME").map(String::as_str),
            Some(f.sandbox.data_dir().to_str().unwrap())
        );
        let options = standard(&f);
        f.install_with(&["--fetch-uv", "--dir", &f.tmp("proj")], options)
            .assert_success();
        let after = real.as_ref().map(|path| {
            std::fs::symlink_metadata(path)
                .ok()
                .map(|m| m.modified().ok())
        });
        assert_eq!(before, after);
    }
}

/// The runner guards the new path flags (`--url-file`, `--dir`) and the hook variable.
#[test]
fn the_runner_guards_the_new_paths() {
    let f = bare();
    let env = airs_test_harness::child_environment(&f.sandbox, &RunOptions::new());
    for args in [
        &[
            "model-security",
            "pypi-auth",
            "--url-file",
            "../../outside.url",
        ][..],
        &["model-security", "install", "--dir", "../../outside"],
    ] {
        assert!(
            airs_test_harness::escape_violation(f.sandbox.root(), &f.sandbox.cwd(), &env, args)
                .is_some(),
            "{args:?}"
        );
    }
    let mut env = env;
    env.insert(
        "AIRS_CLI_TEST_UV_ARCHIVE_URL".to_owned(),
        "https://github.com/x".to_owned(),
    );
    assert!(airs_test_harness::uv_hook_violation(&env).is_some());
    env.insert(
        "AIRS_CLI_TEST_UV_ARCHIVE_URL".to_owned(),
        f.server.uv_archive_url("x.tar.gz"),
    );
    assert!(airs_test_harness::uv_hook_violation(&env).is_none());
}
