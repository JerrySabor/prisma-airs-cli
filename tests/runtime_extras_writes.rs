//! Executable acceptance tests for the M6d step-2 writes (DESIGN §18.1, §18.3, §18.5,
//! §18.6, §18.8): `runtime api-keys create|regenerate|delete|rm` and `runtime
//! customer-apps update|delete|rm`.
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server with the
//! seeded runtime extras dataset, whose write routes change the dataset. The runner's leak
//! check forbids every `FAKE-APIKEY-SECRET-*` marker on every stream and in the debug log
//! of each run (DESIGN §10 M6d): the key value reaches only the `--key-file` file, which
//! the tests read. The write cases of the TypeScript `tests/unit/airs/management.spec.ts`
//! (`createApiKey`, `regenerateApiKey`, `deleteApiKey`, `updateCustomerApp`,
//! `deleteCustomerApp`, `:1071-1170`) and `aliases.spec.ts:55-79` (`rm`) are ported here,
//! adjusted by the §12 rows (§18.19).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airs_test_harness::fixtures::runtime as fx;
use airs_test_harness::{
    Cli, FixtureServer, Planned, PtyRun, RecordedRequest, Route, Run, RunOptions, Rx, Sandbox,
    debug_log, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str =
    "\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n";
const DEBUG_HINT: &str = "    Re-run with --debug to capture redacted API diagnostics.\n";
const KEY: &str = "/aisec/v1/mgmt/apikey";
const APP: &str = "/aisec/v1/mgmt/customerapp";
const APPS: &str = "/aisec/v1/mgmt/customerapp/tsg/100";
const CREATE_HINT: &str = "Check 'airs runtime api-keys list' before creating another key; a key whose value was not saved cannot be shown again (regenerate or delete it).";
const REGENERATE_HINT: &str = "The old key may no longer work; check 'airs runtime api-keys list' and regenerate it again only if needed.";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seeded runtime dataset and one standard tenant `prod` (TSG 100).
fn fx() -> Fx {
    let server = FixtureServer::start();
    server.seed_runtime();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, |_| {});
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

/// A sandbox with no tenant at all: usage and file errors must not need one.
fn bare() -> Fx {
    Fx {
        server: FixtureServer::start(),
        sandbox: Sandbox::new(),
    }
}

fn rt_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    std::iter::once("runtime")
        .chain(args.iter().copied())
        .collect()
}

impl Fx {
    fn rt(&self, args: &[&str]) -> Run {
        self.rt_with(args, &RunOptions::new())
    }

    fn rt_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let out = run(&rust(), &self.sandbox, &rt_args(args), options);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.cwd_listing().is_empty(), "wrote into cwd");
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        out
    }

    /// The `METHOD /path?query` of every API request (the token request left out).
    fn api(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    fn writes(&self) -> Vec<RecordedRequest> {
        self.server
            .requests()
            .into_iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    fn tokens(&self) -> usize {
        self.server
            .routes()
            .iter()
            .filter(|route| **route == Route::Token)
            .count()
    }

    /// A file under the sandbox's `tmp/`; its absolute path.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.sandbox.tmp().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    }

    fn json_file(&self, name: &str, value: &Value) -> String {
        self.file(name, value.to_string().as_bytes())
    }

    /// A key-file path under `tmp/` (nothing there).
    fn key_path(&self, name: &str) -> String {
        self.sandbox.tmp().join(name).display().to_string()
    }

    fn key_config(&self) -> String {
        self.json_file("key.json", &key_config())
    }

    fn app_config(&self, value: &Value) -> String {
        self.json_file("app.json", value)
    }
}

/// A schema-valid `ApiKeyCreateRequest` with an unknown key (sent as TS does, choice 10).
fn key_config() -> Value {
    json!({
        "auth_code": "FAKE-AUTHCODE-1",
        "cust_app": "app-1",
        "created_by": "admin@example.com",
        "api_key_name": "new-key",
        "revoked": false,
        "rotation_time_interval": 30,
        "rotation_time_unit": "days",
        "extra": "kept"
    })
}

/// A full customer-app replacement for app 101.
fn app_config() -> Value {
    json!({
        "app_name": "app-1",
        "cloud_provider": "azure",
        "environment": "dev"
    })
}

fn error_block(message: &str, status: Option<u16>, details: &[&str]) -> String {
    let mut text = format!("\n  ✗ Error: {message}\n");
    if let Some(status) = status {
        text.push_str(&format!("    HTTP {status}\n{DEBUG_HINT}"));
    }
    for line in details {
        text.push_str(&format!("    {line}\n"));
    }
    text.push('\n');
    text
}

fn usage_block(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
}

/// A usage error in a sandbox without any tenant: exit 2, the exact message, no request.
fn assert_usage(args: &[&str], message: &str) {
    let f = bare();
    let out = f.rt(args);
    out.assert_code(2);
    assert_eq!(out.stdout, "", "{args:?}");
    assert_eq!(out.stderr, usage_block(message), "{args:?}");
    assert_eq!(f.server.request_count(), 0, "{args:?}");
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The `.airs-*.tmp` temporaries in `dir`.
fn temporaries(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".airs-")
        })
        .collect()
}

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

// ---------------------------------------------------------------------------
// api-keys create (§18.5)
// ---------------------------------------------------------------------------

mod create {
    use super::*;

    /// TS `management.spec.ts` `createApiKey`: the config is the body (one POST, its
    /// unknown key kept); the key goes only into the new 0600 key file (D204); stdout is
    /// the detail without the key; the outcome lines are on stderr (D222).
    #[test]
    fn posts_the_config_once_and_saves_the_key() {
        let f = fx();
        let config = f.key_config();
        let key_file = f.key_path("new.key");
        let out = f.rt(&[
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
        ]);
        out.assert_success();
        assert_eq!(f.api(), [format!("POST {KEY}")]);
        let request = &f.server.rx_requests(Rx::ApiKeyCreate)[0];
        assert_eq!(request.body_json().unwrap(), key_config());
        assert_eq!(
            std::fs::read_to_string(&key_file).unwrap(),
            format!("{}\n", fx::key_secret(TSG, "1"))
        );
        assert_eq!(mode(Path::new(&key_file)), 0o600);
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
        let id = fx::uuid(901);
        assert_eq!(
            out.stderr,
            format!(
                "  ✓ API key created: {id}\n  ✓ Wrote the API key to {key_file} (mode 0600); it is shown only once.\n"
            )
        );
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  API Key Detail:\n\n  ID        {id}\n  Name      new-key\n  Key       …NEW8-001\n  Created   {}\n  Expires   2027-06-01T00:00:00Z\n  Key file  {key_file}\n\n",
                fx::AT
            )
        );
        // The service holds the new key.
        assert!(
            f.server
                .runtime_data()
                .api_keys
                .iter()
                .any(|key| key["api_key_id"] == id)
        );
    }

    /// D223: `--output json` and `table` print the record (never the key) with `keyFile`.
    #[test]
    fn the_record_prints_in_every_format() {
        let f = fx();
        let config = f.key_config();
        let key_file = f.key_path("json.key");
        let out = f.rt(&[
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({
                "id": fx::uuid(901),
                "name": "new-key",
                "last8": "NEW8-001",
                "createdAt": fx::AT,
                "expiresAt": "2027-06-01T00:00:00Z",
                "keyFile": key_file
            })
        );
        let key_file = f.key_path("table.key");
        let out = f.rt(&[
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
            "--output",
            "table",
        ]);
        out.assert_success();
        assert!(out.stdout.contains(" Key "), "{}", out.stdout);
        assert!(out.stdout.contains(" keyFile "), "{}", out.stdout);
        assert!(out.stdout.contains(&key_file));
        // `--quiet` drops the outcome lines and the banner, never the record.
        let key_file = f.key_path("quiet.key");
        let out = f.rt(&[
            "--quiet",
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
        ]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert!(out.stdout.starts_with("  ID        "), "{}", out.stdout);
        assert!(out.stdout.contains("  Key file  "));
        assert!(!out.stdout.contains("Prisma AIRS"));
    }

    /// The key-file checks (§18.5): `""` and `-` are usage errors; an existing path, a
    /// dangling symlink and a missing directory are refused before the tenant, with no
    /// request.
    #[test]
    fn key_files_are_checked_before_the_tenant() {
        let f = bare();
        let config = f.key_config();
        for (value, message) in [
            ("", "--key-file needs a path"),
            ("-", "--key-file - would print the key; give a file path"),
        ] {
            assert_usage(
                &[
                    "api-keys",
                    "create",
                    "--config",
                    "c.json",
                    "--key-file",
                    value,
                ],
                message,
            );
        }
        let existing = f.file("existing.key", b"KEEP");
        let dangling = f.sandbox.tmp().join("dangling.key");
        std::os::unix::fs::symlink(f.sandbox.tmp().join("nowhere"), &dangling).unwrap();
        let dangling = dangling.display().to_string();
        let missing = f
            .sandbox
            .tmp()
            .join("nodir")
            .join("k.key")
            .display()
            .to_string();
        for (path, message) in [
            (
                &existing,
                format!("{existing} already exists; choose another --key-file"),
            ),
            (
                &dangling,
                format!("{dangling} already exists; choose another --key-file"),
            ),
            (
                &missing,
                format!("Cannot write {missing}; check that its directory exists and is writable"),
            ),
        ] {
            let out = f.rt(&[
                "api-keys",
                "create",
                "--config",
                &config,
                "--key-file",
                path,
            ]);
            out.assert_code(1);
            assert_eq!(out.stderr, error_block(&message, None, &[]), "{path}");
            assert_eq!(out.stdout, "");
            assert_eq!(f.server.request_count(), 0);
        }
        assert_eq!(std::fs::read(&existing).unwrap(), b"KEEP");
        assert!(!f.sandbox.tmp().join("nowhere").exists());
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
        // D226: a path that names no file (a trailing `/`, `.` or `..`) is refused before
        // the tenant: no key is created or rotated that cannot be stored.
        for name in ["newdir/", "k.key/", "sub/.", "sub/.."] {
            let path = format!("{}/{name}", f.sandbox.tmp().display());
            let message =
                format!("Cannot write {path}; check that its directory exists and is writable");
            for args in [
                vec![
                    "api-keys",
                    "create",
                    "--config",
                    config.as_str(),
                    "--key-file",
                    path.as_str(),
                ],
                vec![
                    "api-keys",
                    "regenerate",
                    "key-id-1",
                    "--interval",
                    "1",
                    "--unit",
                    "days",
                    "--key-file",
                    path.as_str(),
                    "--force",
                ],
            ] {
                let out = f.rt(&args);
                out.assert_code(1);
                assert_eq!(out.stderr, error_block(&message, None, &[]), "{name}");
                assert_eq!(out.stdout, "");
                assert_eq!(f.server.request_count(), 0, "{name}");
            }
        }
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
        assert!(!f.sandbox.tmp().join("newdir").exists());
    }

    /// D221: the `--config` file follows the §13.2 input rules before the tenant, echoes
    /// no content, and its body is checked with the SDK schema (D116 text).
    #[test]
    fn config_files_are_read_before_the_tenant() {
        let f = bare();
        let key_file = f.key_path("k.key");
        let cases: Vec<(String, String)> = vec![
            (
                f.file("bad.json", b"{\"api_key_name\": FAKE-AUTHCODE-9"),
                "is not valid JSON".to_owned(),
            ),
            (
                f.file("array.json", b"[1]"),
                "must contain a JSON object".to_owned(),
            ),
            (
                f.sandbox.tmp().join("missing.json").display().to_string(),
                "(missing, not a regular file, unreadable or larger than 1 MiB)".to_owned(),
            ),
        ];
        for (path, tail) in cases {
            let out = f.rt(&[
                "api-keys",
                "create",
                "--config",
                &path,
                "--key-file",
                &key_file,
            ]);
            out.assert_code(1);
            assert!(out.stderr.contains(&path), "{}", out.stderr);
            assert!(out.stderr.contains(&tail), "{}", out.stderr);
            assert!(!out.stderr.contains("FAKE-AUTHCODE-9"));
            assert_eq!(f.server.request_count(), 0);
        }
        let mut partial = key_config();
        partial.as_object_mut().unwrap().remove("auth_code");
        let path = f.json_file("partial.json", &partial);
        let out = f.rt(&[
            "api-keys",
            "create",
            "--config",
            &path,
            "--key-file",
            &key_file,
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/mgmt/apikey did not match schema",
                None,
                &[]
            )
        );
        assert!(!Path::new(&key_file).exists());
    }

    /// G26: a 2xx that fails the response schema still saves the key (exit 1); an answer
    /// without a key writes nothing; an undecodable 2xx is the unreadable outcome.
    #[test]
    fn answers_the_cli_cannot_fully_read() {
        let f = fx();
        f.server.runtime(|data| data.omit_auth_code = true);
        let config = f.key_config();
        let key_file = f.key_path("mismatch.key");
        let out = f.rt(&[
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
        ]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema",
                None,
                &[&format!(
                    "Outcome: the API key was created and its value was saved in {key_file}, but the rest of the response could not be read."
                )]
            )
        );
        assert_eq!(
            std::fs::read_to_string(&key_file).unwrap(),
            format!("{}\n", fx::key_secret(TSG, "1"))
        );
        let f = fx();
        f.server.runtime(|data| data.omit_key_value = true);
        let config = f.key_config();
        let key_file = f.key_path("none.key");
        let out = f.rt(&[
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                &format!(
                    "The service created API key {} but returned no key value; nothing was written to {key_file}. Regenerate the key to obtain a usable value.",
                    fx::uuid(901)
                ),
                None,
                &[]
            )
        );
        assert!(!Path::new(&key_file).exists());
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
        let f = fx();
        f.server.push_once(
            Route::Runtime(Rx::ApiKeyCreate),
            Planned::raw(200, "application/json", "{not json"),
        );
        let config = f.key_config();
        let key_file = f.key_path("unreadable.key");
        let out = f.rt(&[
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
        ]);
        out.assert_code(1);
        assert!(
            out.stderr.contains(&format!(
                "    Outcome: the API key was created, but the response could not be read.\n    {CREATE_HINT}\n"
            )),
            "{}",
            out.stderr
        );
        assert!(!Path::new(&key_file).exists());
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
    }

    /// The key file appeared while the request was in flight: the key is kept in the
    /// reserved temporary (never lost, never overwriting) and named.
    #[test]
    fn a_lost_race_keeps_the_key_in_the_temporary() {
        let f = fx();
        f.server
            .push_once(Route::Runtime(Rx::ApiKeyCreate), Planned::held());
        let config = f.key_config();
        let key_file = f.key_path("race.key");
        let args = rt_args(&[
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
        ]);
        let running = spawn(&rust(), &f.sandbox, &args, &RunOptions::new());
        assert!(f.server.wait_for_route(
            Route::Runtime(Rx::ApiKeyCreate),
            1,
            Duration::from_secs(20)
        ));
        std::fs::write(&key_file, "OTHER").unwrap();
        f.server.release_held();
        let out = running.wait();
        out.assert_code(1);
        let kept = temporaries(&f.sandbox.tmp());
        assert_eq!(kept.len(), 1, "the key is kept");
        assert_eq!(
            std::fs::read_to_string(&kept[0]).unwrap(),
            format!("{}\n", fx::key_secret(TSG, "1"))
        );
        assert_eq!(mode(&kept[0]), 0o600);
        assert_eq!(std::fs::read_to_string(&key_file).unwrap(), "OTHER");
        assert_eq!(
            out.stderr,
            error_block(
                &format!(
                    "The API key was created, but {key_file} now exists; the key is in {} (mode 0600). Move it before running again.",
                    kept[0].display()
                ),
                None,
                &[]
            )
        );
    }
}

// ---------------------------------------------------------------------------
// api-keys regenerate (§18.5)
// ---------------------------------------------------------------------------

mod regenerate {
    use super::*;

    /// TS `regenerateApiKey(id, body)`: `{rotation_time_interval, rotation_time_unit,
    /// updated_by?}` to `regenerate/<encoded id>`; the new key into the key file.
    #[test]
    fn sends_the_rotation_and_saves_the_new_key() {
        let f = fx();
        let id = fx::uuid(1);
        let key_file = f.key_path("rotated.key");
        let out = f.rt(&[
            "api-keys",
            "regenerate",
            &id,
            "--interval",
            "030",
            "--unit",
            "days",
            "--updated-by",
            "u@example.com",
            "--key-file",
            &key_file,
            "--force",
        ]);
        out.assert_success();
        assert_eq!(f.api(), [format!("POST {KEY}/regenerate/{id}")]);
        assert_eq!(
            f.server.rx_requests(Rx::ApiKeyRegenerate)[0]
                .body_json()
                .unwrap(),
            json!({"rotation_time_interval": 30, "rotation_time_unit": "days", "updated_by": "u@example.com"})
        );
        assert_eq!(
            std::fs::read_to_string(&key_file).unwrap(),
            format!("{}\n", fx::key_secret(TSG, "1"))
        );
        assert!(
            out.stderr
                .starts_with(&format!("  ✓ API key regenerated: {}\n", fx::uuid(901)))
        );
        // Without `--updated-by` the body has no `updated_by` (TS); the id is one
        // percent-encoded segment.
        let f = fx();
        f.server
            .runtime(|data| data.api_keys[0]["api_key_id"] = json!("a/b c"));
        let key_file = f.key_path("enc.key");
        f.rt(&[
            "api-keys",
            "regenerate",
            "a/b c",
            "--interval",
            "1",
            "--unit",
            "hours",
            "--key-file",
            &key_file,
            "--force",
        ])
        .assert_success();
        assert_eq!(f.api(), [format!("POST {KEY}/regenerate/a%2Fb%20c")]);
        assert_eq!(
            f.server.rx_requests(Rx::ApiKeyRegenerate)[0]
                .body_json()
                .unwrap(),
            json!({"rotation_time_interval": 1, "rotation_time_unit": "hours"})
        );
    }

    /// D220, D213: every argument check before the tenant (exit 2, no request).
    #[test]
    fn argument_errors_are_usage_errors_before_the_tenant() {
        let base = |id: &'static str, interval: &'static str, unit: &'static str| {
            vec![
                "api-keys",
                "regenerate",
                id,
                "--interval",
                interval,
                "--unit",
                unit,
                "--key-file",
                "k.key",
                "--force",
            ]
        };
        for (id, interval, unit, message) in [
            ("..", "1", "days", "Invalid API key id: .."),
            (".", "1", "days", "Invalid API key id: ."),
            ("a\\b", "1", "days", "Invalid API key id: a\\b"),
            ("%2e%2e", "1", "days", "Invalid API key id: %2e%2e"),
            ("id", "1.9", "days", "--interval must be a positive integer"),
            ("id", "-5", "days", "--interval must be a positive integer"),
            ("id", "0", "days", "--interval must be a positive integer"),
            ("id", "abc", "days", "--interval must be a positive integer"),
            ("id", "1", " ", "--unit must not be empty"),
        ] {
            assert_usage(&base(id, interval, unit), message);
        }
        let mut args = base("id", "1", "days");
        args.extend(["--updated-by", " "]);
        assert_usage(&args, "--updated-by must not be empty");
        // The non-interactive refusal (D206).
        assert_usage(
            &[
                "api-keys",
                "regenerate",
                "id",
                "--interval",
                "1",
                "--unit",
                "days",
                "--key-file",
                "k.key",
            ],
            "refusing to regenerate API key id without --force in non-interactive mode",
        );
    }
}

// ---------------------------------------------------------------------------
// api-keys delete (§18.6)
// ---------------------------------------------------------------------------

mod delete_key {
    use super::*;

    /// TS `deleteApiKey(name, updatedBy)`: `DELETE …/apikey/delete/<name>?updated_by=`;
    /// every 2xx JSON answer is the fixed acknowledgement (D208); `rm` is an alias.
    #[test]
    fn deletes_with_the_fixed_acknowledgement() {
        for answer in [None, Some(json!("plain string message")), Some(json!({}))] {
            let f = fx();
            f.server
                .runtime(|data| data.key_delete_answer = answer.clone());
            let out = f.rt(&[
                "api-keys",
                "rm",
                "key-1",
                "--updated-by",
                "u@example.com",
                "--force",
                "--output",
                "json",
            ]);
            out.assert_success();
            assert_eq!(out.stdout, "", "{answer:?}");
            assert_eq!(out.stderr, "  ✓ API key key-1 deleted.\n", "{answer:?}");
            assert_eq!(
                f.api(),
                [format!(
                    "DELETE {KEY}/delete/key-1?updated_by=u%40example.com"
                )]
            );
            assert!(
                !f.server
                    .runtime_data()
                    .api_keys
                    .iter()
                    .any(|key| key["api_key_name"] == "key-1")
            );
        }
    }

    #[test]
    fn argument_errors_are_usage_errors_before_the_tenant() {
        for (name, by, message) in [
            ("..", "u", "Invalid API key name: .."),
            ("a\\b", "u", "Invalid API key name: a\\b"),
            ("k", "", "--updated-by must not be empty"),
            ("k", "\t", "--updated-by must not be empty"),
        ] {
            assert_usage(
                &["api-keys", "delete", name, "--updated-by", by, "--force"],
                message,
            );
        }
        assert_usage(
            &["api-keys", "delete", "key-1", "--updated-by", "u"],
            "refusing to delete API key key-1 without --force in non-interactive mode",
        );
    }
}

// ---------------------------------------------------------------------------
// customer-apps update and delete (§18.8)
// ---------------------------------------------------------------------------

mod apps {
    use super::*;

    /// TS `updateCustomerApp(id, body)`: one `PUT …/customerapp?customer_app_id=` with the
    /// whole file; `--force` sends TS's single PUT (no read); the answer's detail on
    /// stdout and `✓ Customer app updated: <name>` on stderr.
    #[test]
    fn update_replaces_the_record() {
        let f = fx();
        let id = fx::uuid(101);
        let config = f.app_config(&app_config());
        let out = f.rt(&[
            "customer-apps",
            "update",
            &id,
            "--config",
            &config,
            "--force",
        ]);
        out.assert_success();
        assert_eq!(f.api(), [format!("PUT {APP}?customer_app_id={id}")]);
        assert_eq!(
            f.server.rx_requests(Rx::CustomerAppUpdate)[0]
                .body_json()
                .unwrap(),
            app_config()
        );
        assert_eq!(out.stderr, "  ✓ Customer app updated: app-1\n");
        assert!(out.stdout.starts_with(&format!(
            "{BANNER}\n  Customer App Detail:\n\n  ID    {id}\n  Name  app-1\n  Data  {{\n"
        )));
        let data = f.server.runtime_data();
        assert_eq!(data.customer_apps[0]["cloud_provider"], "azure");
        assert_eq!(
            data.customer_apps[0].get("model_name"),
            None,
            "a full replacement"
        );
        let out = f.rt(&[
            "customer-apps",
            "update",
            &id,
            "--config",
            &config,
            "--force",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(out.json()["name"], "app-1");
        assert_eq!(out.json()["raw"]["environment"], "dev");
    }

    /// D221: the file is checked before the tenant: another app's id, the schema (a
    /// patch-style file), the input rules.
    #[test]
    fn update_files_are_checked_before_the_tenant() {
        let f = bare();
        let id = fx::uuid(101);
        let mut other = app_config();
        other["customer_appId"] = json!(fx::uuid(102));
        let path = f.app_config(&other);
        let out = f.rt(&["customer-apps", "update", &id, "--config", &path, "--force"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                &format!("{path} names another customer app than {id}"),
                None,
                &[]
            )
        );
        let path = f.json_file("patch.json", &json!({"environment": "dev"}));
        let out = f.rt(&["customer-apps", "update", &id, "--config", &path, "--force"]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for PUT /v1/mgmt/customerapp did not match schema",
                None,
                &[]
            )
        );
        assert_eq!(f.server.request_count(), 0);
        // The same id in the file is accepted (and reaches the tenant check).
        let mut same = app_config();
        same["customer_appId"] = json!(id);
        let path = f.json_file("same.json", &same);
        let out = f.rt(&["customer-apps", "update", &id, "--config", &path, "--force"]);
        out.assert_code(1);
        assert!(out.stderr.contains("No tenant"), "{}", out.stderr);
        assert_usage(
            &[
                "customer-apps",
                "update",
                " ",
                "--config",
                "c.json",
                "--force",
            ],
            "Customer app id must not be empty",
        );
        assert_usage(
            &["customer-apps", "update", &id, "--config", "c.json"],
            &format!(
                "refusing to replace customer app {id} without --force in non-interactive mode"
            ),
        );
    }

    /// TS `deleteCustomerApp(name, updatedBy)`: the fixed acknowledgement names the
    /// argument (D208) for a message or a record answer; the app's keys go too.
    #[test]
    fn delete_acknowledges_the_argument() {
        for answer in [None, Some(json!("deleted")), Some(fx::customer_app(101))] {
            let f = fx();
            f.server
                .runtime(|data| data.app_delete_answer = answer.clone());
            let out = f.rt(&[
                "customer-apps",
                "rm",
                "app-1",
                "--updated-by",
                "u@example.com",
                "--force",
            ]);
            out.assert_success();
            assert_eq!(out.stdout, "");
            assert_eq!(out.stderr, "  ✓ Customer app \"app-1\" deleted.\n");
            assert_eq!(
                f.api(),
                [format!(
                    "DELETE {APP}?app_name=app-1&updated_by=u%40example.com"
                )]
            );
            let data = f.server.runtime_data();
            assert!(
                !data
                    .customer_apps
                    .iter()
                    .any(|app| app["app_name"] == "app-1")
            );
            assert!(!data.api_keys.iter().any(|key| key["cust_app"] == "app-1"));
        }
        for (name, by, message) in [
            (" ", "u", "Customer app name must not be empty"),
            ("a", " ", "--updated-by must not be empty"),
        ] {
            assert_usage(
                &[
                    "customer-apps",
                    "delete",
                    name,
                    "--updated-by",
                    by,
                    "--force",
                ],
                message,
            );
        }
        assert_usage(
            &["customer-apps", "delete", "app-1", "--updated-by", "u"],
            "refusing to delete customer app app-1 without --force in non-interactive mode",
        );
    }
}

// ---------------------------------------------------------------------------
// Confirmations (D206)
// ---------------------------------------------------------------------------

mod confirmations {
    use super::*;

    fn pty(f: &Fx, args: &[&str], prompt: &str, answer: &[u8]) -> PtyRun {
        let mut session = spawn_pty(&rust(), &f.sandbox, &rt_args(args), &RunOptions::new());
        session.expect(prompt);
        assert!(f.writes().is_empty(), "no write while the prompt waits");
        session.send(answer);
        session.wait()
    }

    /// The confirming commands of a sandbox: arguments, prompt, write route.
    fn cases(f: &Fx) -> Vec<(Vec<String>, String, Rx)> {
        let config = f.app_config(&app_config());
        let id = fx::uuid(1);
        let app = fx::uuid(101);
        let key_file = f.key_path("pty.key");
        let owned = |args: &[&str]| args.iter().map(|arg| (*arg).to_owned()).collect();
        vec![
            (
                owned(&[
                    "api-keys",
                    "regenerate",
                    &id,
                    "--interval",
                    "1",
                    "--unit",
                    "days",
                    "--key-file",
                    &key_file,
                ]),
                format!(
                    "? Regenerate API key {id}? The current key stops working; the new key is written to {key_file}. (y/N) "
                ),
                Rx::ApiKeyRegenerate,
            ),
            (
                owned(&["api-keys", "delete", "key-1", "--updated-by", "u"]),
                "? Delete API key key-1? Integrations that use it stop working. (y/N) ".to_owned(),
                Rx::ApiKeyDelete,
            ),
            (
                owned(&["customer-apps", "update", &app, "--config", &config]),
                format!(
                    "? Replace customer app app-1 ({app}) with the settings in {config}? It drops 2 field(s) the app has now: model_name, ai_agent_framework. (y/N) "
                ),
                Rx::CustomerAppUpdate,
            ),
            (
                owned(&["customer-apps", "delete", "app-1", "--updated-by", "u"]),
                "? Delete customer app app-1 and its API keys? (y/N) ".to_owned(),
                Rx::CustomerAppDelete,
            ),
        ]
    }

    /// Every confirming command: `y`/`yes` send the write; `n`, Enter, EOF and anything
    /// else decline with `ℹ Aborted` (exit 0, nothing sent, no key file).
    #[test]
    fn every_prompt_confirms_only_yes() {
        for index in 0..4 {
            for answer in [&b"n\n"[..], b"\n", b"\x04", b"yep\n", b"y\n", b" YES \n"] {
                let f = fx();
                let (args, prompt, route) = cases(&f).remove(index);
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                let out = pty(&f, &args, &prompt, answer);
                out.run.assert_success();
                let confirmed = answer.trim_ascii().eq_ignore_ascii_case(b"y")
                    || answer.trim_ascii().eq_ignore_ascii_case(b"yes");
                if confirmed {
                    assert_eq!(f.server.rx_requests(route).len(), 1, "{args:?}");
                } else {
                    assert!(
                        transcript(&out).contains("  ℹ Aborted\n"),
                        "{args:?} {answer:?}"
                    );
                    assert!(f.server.rx_requests(route).is_empty(), "{args:?}");
                    assert!(!f.sandbox.tmp().join("pty.key").exists());
                    assert!(temporaries(&f.sandbox.tmp()).is_empty());
                }
            }
        }
    }

    /// The update prompt reads the current record through the list walk (G30), names a
    /// rename, and refuses an unknown id before sending anything.
    #[test]
    fn the_update_prompt_reads_the_record_first() {
        let f = fx();
        let app = fx::uuid(101);
        let mut renamed = app_config();
        renamed["app_name"] = json!("renamed");
        renamed["model_name"] = json!("gpt");
        renamed["ai_agent_framework"] = json!("none");
        let config = f.app_config(&renamed);
        let out = pty(
            &f,
            &["customer-apps", "update", &app, "--config", &config],
            &format!(
                "? Replace customer app app-1 ({app}) with the settings in {config}? It renames the app to renamed. (y/N) "
            ),
            b"y\n",
        );
        out.run.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {APPS}?offset=0&limit=100"),
                format!("PUT {APP}?customer_app_id={app}")
            ]
        );
        let f = fx();
        let unknown = fx::uuid(199);
        let config = f.app_config(&app_config());
        let out = spawn_pty(
            &rust(),
            &f.sandbox,
            &rt_args(&["customer-apps", "update", &unknown, "--config", &config]),
            &RunOptions::new(),
        )
        .wait();
        out.run.assert_code(1);
        assert!(
            transcript(&out).contains(&format!(
                "Customer app {unknown} was not found; nothing was sent"
            )),
            "{}",
            transcript(&out)
        );
        assert!(f.writes().is_empty());
    }

    /// Ctrl-C at a prompt: `Cancelled; nothing was changed.`, exit 130, no write, no
    /// key file.
    #[test]
    fn ctrl_c_at_the_prompt_changes_nothing() {
        for index in [0, 3] {
            let f = fx();
            let (args, _, route) = cases(&f).remove(index);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut session = spawn_pty(&rust(), &f.sandbox, &rt_args(&args), &RunOptions::new());
            session.expect("(y/N) ");
            session.signal("INT");
            let out = session.wait();
            out.run.assert_code(130);
            assert!(
                transcript(&out).contains("\n  Cancelled; nothing was changed.\n"),
                "{}",
                transcript(&out)
            );
            assert!(f.server.rx_requests(route).is_empty(), "{args:?}");
            assert!(!f.sandbox.tmp().join("pty.key").exists());
        }
    }

    /// `api-keys create` never asks (choice 8).
    #[test]
    fn create_does_not_confirm() {
        let f = fx();
        let config = f.key_config();
        let key_file = f.key_path("nopty.key");
        let out = spawn_pty(
            &rust(),
            &f.sandbox,
            &rt_args(&[
                "api-keys",
                "create",
                "--config",
                &config,
                "--key-file",
                &key_file,
            ]),
            &RunOptions::new(),
        )
        .wait();
        out.run.assert_success();
        assert!(!transcript(&out).contains("(y/N)"));
        assert!(!transcript(&out).contains(fx::KEY_MARKER));
    }
}

// ---------------------------------------------------------------------------
// One attempt per write (D95)
// ---------------------------------------------------------------------------

mod attempts {
    use super::*;

    /// Each write: its route, its arguments, its outcome line and hint.
    fn writes(f: &Fx) -> Vec<(Rx, Vec<String>, String, String)> {
        let s = |text: &str| text.to_owned();
        vec![
            (
                Rx::ApiKeyCreate,
                vec![
                    s("api-keys"),
                    s("create"),
                    s("--config"),
                    f.key_config(),
                    s("--key-file"),
                    f.key_path("a.key"),
                ],
                s("Outcome unknown: the API key may have been created."),
                s(CREATE_HINT),
            ),
            (
                Rx::ApiKeyRegenerate,
                vec![
                    s("api-keys"),
                    s("regenerate"),
                    fx::uuid(1),
                    s("--interval"),
                    s("1"),
                    s("--unit"),
                    s("days"),
                    s("--key-file"),
                    f.key_path("b.key"),
                    s("--force"),
                ],
                s("Outcome unknown: the API key may have been regenerated."),
                s(REGENERATE_HINT),
            ),
            (
                Rx::ApiKeyDelete,
                vec![
                    s("api-keys"),
                    s("delete"),
                    s("key-1"),
                    s("--updated-by"),
                    s("u"),
                    s("--force"),
                ],
                s("Outcome unknown: the API key may have been deleted."),
                s("Check it with 'airs runtime api-keys list'."),
            ),
            (
                Rx::CustomerAppUpdate,
                vec![
                    s("customer-apps"),
                    s("update"),
                    fx::uuid(101),
                    s("--config"),
                    f.app_config(&app_config()),
                    s("--force"),
                ],
                s("Outcome unknown: the customer app may have been updated."),
                s("Check it with 'airs runtime customer-apps get app-1'."),
            ),
            (
                Rx::CustomerAppDelete,
                vec![
                    s("customer-apps"),
                    s("delete"),
                    s("app-1"),
                    s("--updated-by"),
                    s("u"),
                    s("--force"),
                ],
                s("Outcome unknown: the customer app may have been deleted."),
                s(
                    "Check 'airs runtime customer-apps list'; its API keys may have been deleted too.",
                ),
            ),
        ]
    }

    fn strs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }

    /// A 5xx with `Retry-After: 0` is one request and an unknown outcome with the hint;
    /// a 401 is `token, write, token, write`; a 403 is one request with no outcome line.
    #[test]
    fn every_write_is_one_attempt() {
        for index in 0..5 {
            let f = fx();
            let (route, args, unknown, hint) = writes(&f).remove(index);
            f.server.push_once(
                Route::Runtime(route),
                Planned::json(502, &json!({"message": "busy"})).with_retry_after(0),
            );
            let out = f.rt(&strs(&args));
            out.assert_code(1);
            assert_eq!(f.server.rx_requests(route).len(), 1, "{route:?} 5xx");
            assert_eq!(
                out.stderr,
                error_block(
                    "AISEC_SERVER_SIDE_ERROR:API error 502",
                    Some(502),
                    &[&unknown, &hint]
                ),
                "{route:?}"
            );
            assert_eq!(out.stdout, "");
            assert!(temporaries(&f.sandbox.tmp()).is_empty(), "{route:?}");
            let f = fx();
            let (_, args, _, _) = writes(&f).remove(index);
            f.server
                .push_once(Route::Runtime(route), Planned::empty_json(401));
            f.rt(&strs(&args)).assert_success();
            assert_eq!(f.server.rx_requests(route).len(), 2, "{route:?} 401");
            assert_eq!(f.tokens(), 2, "{route:?}: a fresh token for the replay");
            let f = fx();
            let (_, args, _, _) = writes(&f).remove(index);
            f.server
                .push_once(Route::Runtime(route), Planned::empty_json(403));
            let out = f.rt(&strs(&args));
            out.assert_code(1);
            assert_eq!(f.server.rx_requests(route).len(), 1, "{route:?} 403");
            assert!(!out.stderr.contains("Outcome"), "{route:?}");
        }
    }

    /// An applied write whose connection drops: one request, the outcome line and the
    /// hint, nothing looked up; a key create leaves no key file.
    #[test]
    fn applied_then_dropped_is_an_unknown_outcome() {
        for index in [0, 3, 4] {
            let f = fx();
            let (route, args, unknown, hint) = writes(&f).remove(index);
            f.server
                .push_once(Route::Runtime(route), Planned::applied_then_dropped());
            let out = f.rt(&strs(&args));
            out.assert_code(1);
            assert!(
                out.stderr.contains(&format!("    {unknown}\n    {hint}\n")),
                "{route:?}: {}",
                out.stderr
            );
            assert_eq!(f.api().len(), 1, "{route:?}: one write, no read");
        }
        let f = fx();
        let (_, args, _, _) = writes(&f).remove(0);
        f.server.push_once(
            Route::Runtime(Rx::ApiKeyCreate),
            Planned::applied_then_dropped(),
        );
        f.rt(&strs(&args)).assert_code(1);
        assert!(!f.sandbox.tmp().join("a.key").exists());
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
    }

    /// D11: server text in a write error is never echoed (the §6 message only).
    #[test]
    fn write_errors_name_the_status_only() {
        let f = fx();
        f.server.push_once(
            Route::Runtime(Rx::ApiKeyCreate),
            Planned::json(
                409,
                &json!({"message": format!("key {} exists \u{1b}[31m", fx::key_secret(TSG, "2"))}),
            ),
        );
        let config = f.key_config();
        let key_file = f.key_path("conflict.key");
        let out = f.rt(&[
            "api-keys",
            "create",
            "--config",
            &config,
            "--key-file",
            &key_file,
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            error_block("AISEC_CLIENT_SIDE_ERROR:API error 409", Some(409), &[])
        );
    }
}

// ---------------------------------------------------------------------------
// Debug log (D64) and tenant selection
// ---------------------------------------------------------------------------

mod debug {
    use super::*;

    /// The writes record status and headers only: no body, no query, no key; the raw key
    /// POSTs are `custom.request` (G26: the SDK's `named` is crate-private).
    #[test]
    fn writes_record_their_operations_and_no_body() {
        let f = fx();
        let config = f.key_config();
        let app = f.app_config(&app_config());
        let cases: Vec<(Vec<String>, &str)> = vec![
            (
                vec![
                    "api-keys".into(),
                    "create".into(),
                    "--config".into(),
                    config.clone(),
                    "--key-file".into(),
                    f.key_path("d1.key"),
                ],
                "custom.request",
            ),
            (
                vec![
                    "api-keys".into(),
                    "regenerate".into(),
                    fx::uuid(2),
                    "--interval".into(),
                    "1".into(),
                    "--unit".into(),
                    "days".into(),
                    "--updated-by".into(),
                    "secret-mail@example.com".into(),
                    "--key-file".into(),
                    f.key_path("d2.key"),
                    "--force".into(),
                ],
                "custom.request",
            ),
            (
                vec![
                    "api-keys".into(),
                    "delete".into(),
                    "key-3".into(),
                    "--updated-by".into(),
                    "secret-mail@example.com".into(),
                    "--force".into(),
                ],
                "airs.management.api_keys.delete",
            ),
            (
                vec![
                    "customer-apps".into(),
                    "update".into(),
                    fx::uuid(102),
                    "--config".into(),
                    app.clone(),
                    "--force".into(),
                ],
                "airs.management.customer_apps.update",
            ),
            (
                vec![
                    "customer-apps".into(),
                    "delete".into(),
                    "app-3".into(),
                    "--updated-by".into(),
                    "secret-mail@example.com".into(),
                    "--force".into(),
                ],
                "airs.management.customer_apps.delete",
            ),
        ];
        for (args, operation) in cases {
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            for path in debug_log::log_files(&debug_log::log_dir(&f.sandbox)) {
                std::fs::remove_file(path).unwrap();
            }
            let mut full = vec!["--debug", "runtime"];
            full.extend(args.iter().map(String::as_str));
            let out = run(
                &rust(),
                &f.sandbox,
                &full,
                &RunOptions::new().env("XDG_STATE_HOME", &state),
            );
            out.assert_success();
            let (path, records) = debug_log::only_log(&f.sandbox);
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(!text.contains("secret-mail"), "{args:?}");
            assert!(
                !text.contains("new-key") && !text.contains("FAKE-AUTHCODE"),
                "{args:?}"
            );
            let found: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .filter(|operation| *operation != "oauth.token")
                .collect();
            assert_eq!(found, [operation], "{args:?}");
            debug_log::assert_logs_clean(
                &f.sandbox,
                &f.server,
                &[debug_log::log_dir(&f.sandbox)],
                &[fx::KEY_MARKER, fx::AUTHCODE_MARKER],
            );
        }
    }

    /// Usage errors open no log.
    #[test]
    fn usage_errors_open_no_log() {
        let f = fx();
        let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
        let out = run(
            &rust(),
            &f.sandbox,
            &[
                "--debug",
                "runtime",
                "api-keys",
                "delete",
                "..",
                "--updated-by",
                "u",
                "--force",
            ],
            &RunOptions::new().env("XDG_STATE_HOME", &state),
        );
        out.assert_code(2);
        assert!(debug_log::log_files(&debug_log::log_dir(&f.sandbox)).is_empty());
    }
}

// ---------------------------------------------------------------------------
// Interruption (D224)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    fn spawn_rt(f: &Fx, args: &[&str]) -> airs_test_harness::Running {
        spawn(
            &rust(),
            &f.sandbox,
            &rt_args(args),
            &RunOptions::new().expect_signal(),
        )
    }

    /// A signal while a write is held: the change may have been applied; nothing is
    /// re-sent; a key create leaves no key file (the reservation held no key).
    #[test]
    fn a_signal_during_a_write_reports_an_unknown_outcome() {
        for (signal, code) in [("INT", 130), ("TERM", 143)] {
            let f = fx();
            let config = f.key_config();
            let key_file = f.key_path("held.key");
            f.server
                .push_once(Route::Runtime(Rx::ApiKeyCreate), Planned::held());
            let running = spawn_rt(
                &f,
                &[
                    "api-keys",
                    "create",
                    "--config",
                    &config,
                    "--key-file",
                    &key_file,
                ],
            );
            assert!(f.server.wait_for_route(
                Route::Runtime(Rx::ApiKeyCreate),
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
                "\n  ✗ Error: Interrupted; the change may already have been applied (outcome unknown)\n\n"
            );
            assert_eq!(
                f.server.rx_requests(Rx::ApiKeyCreate).len(),
                1,
                "nothing re-sent"
            );
            assert!(!Path::new(&key_file).exists());
            assert!(temporaries(&f.sandbox.tmp()).is_empty());
        }
        let f = fx();
        let config = f.app_config(&app_config());
        f.server
            .push_once(Route::Runtime(Rx::CustomerAppUpdate), Planned::held());
        let running = spawn_rt(
            &f,
            &[
                "customer-apps",
                "update",
                &fx::uuid(101),
                "--config",
                &config,
                "--force",
            ],
        );
        assert!(f.server.wait_for_route(
            Route::Runtime(Rx::CustomerAppUpdate),
            1,
            Duration::from_secs(20)
        ));
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert!(out.stderr.contains("outcome unknown"), "{}", out.stderr);
        assert_eq!(f.server.rx_requests(Rx::CustomerAppUpdate).len(), 1);
    }

    /// A signal before the write (the token request of `api-keys create` hangs, after the
    /// reservation): nothing was changed, and the reservation is removed.
    #[test]
    fn a_signal_before_the_write_changes_nothing() {
        let f = fx();
        let config = f.key_config();
        let key_file = f.key_path("token.key");
        f.server.push_once(Route::Token, Planned::hang());
        let running = spawn_rt(
            &f,
            &[
                "api-keys",
                "create",
                "--config",
                &config,
                "--key-file",
                &key_file,
            ],
        );
        assert!(
            f.server
                .wait_for_route(Route::Token, 1, Duration::from_secs(20))
        );
        running.send_signal("TERM");
        let out = running.wait();
        out.assert_code(143);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; nothing was changed\n\n"
        );
        assert!(f.writes().is_empty());
        assert!(
            temporaries(&f.sandbox.tmp()).is_empty(),
            "the reservation is removed"
        );
        assert!(!Path::new(&key_file).exists());
    }

    /// A signal while the interactive update's list walk (G30) is held, before its
    /// prompt: `Interrupted; nothing was changed`, no prompt and no write.
    #[test]
    fn a_signal_during_the_update_walk_changes_nothing() {
        let f = fx();
        let config = f.app_config(&app_config());
        f.server
            .push_once(Route::Runtime(Rx::CustomerApps), Planned::held());
        let session = spawn_pty(
            &rust(),
            &f.sandbox,
            &rt_args(&[
                "customer-apps",
                "update",
                &fx::uuid(101),
                "--config",
                &config,
            ]),
            &RunOptions::new(),
        );
        assert!(f.server.wait_for_route(
            Route::Runtime(Rx::CustomerApps),
            1,
            Duration::from_secs(20)
        ));
        session.signal("INT");
        let out = session.wait();
        f.server.release_held();
        out.run.assert_code(130);
        let text = transcript(&out);
        assert!(
            text.contains("\n  ✗ Error: Interrupted; nothing was changed\n"),
            "{text}"
        );
        assert!(!text.contains("(y/N)"), "{text}");
        assert!(f.writes().is_empty());
    }

    /// A signal once the 2xx key answer was saved, while the run is still reporting (its
    /// created line, with an id longer than any pipe buffer, blocks on a stalled stderr):
    /// the key file is complete and the interruption names it (§18.5 "Interruption").
    #[test]
    fn a_signal_after_the_key_is_saved_names_the_key_file() {
        let f = fx();
        let config = f.key_config();
        let key_file = f.key_path("saved.key");
        let key = fx::key_secret(TSG, "7");
        let answer = json!({
            "api_key": key,
            "api_key_id": format!("id-{}", "x".repeat(300_000)),
            "api_key_last8": "LAST8-07",
            "auth_code": "a",
            "expiration": "2027-01-01T00:00:00Z",
            "revoked": false,
        });
        f.server.push_once(
            Route::Runtime(Rx::ApiKeyCreate),
            Planned::raw(200, "application/json", answer.to_string()),
        );
        let mut running = spawn(
            &rust(),
            &f.sandbox,
            &rt_args(&[
                "api-keys",
                "create",
                "--config",
                &config,
                "--key-file",
                &key_file,
            ]),
            &RunOptions::new()
                .stall_stderr()
                .signal_marker(&f.sandbox.tmp().join("signal.marker")),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !Path::new(&key_file).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the key file was never saved"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // The signal thread records the signal while the run is blocked on stderr; stderr
        // is released only once it has (the marker file).
        running.send_signal_recorded("INT");
        running.release_stderr();
        let out = running.wait();
        out.assert_code(130);
        assert_eq!(out.stdout, "");
        assert!(
            out.stderr.ends_with(&format!(
                "\n  ✗ Error: Interrupted; the API key was saved in {key_file}\n\n"
            )),
            "{}",
            &out.stderr[out.stderr.len().saturating_sub(400)..]
        );
        assert!(!out.stderr.contains("Wrote the API key"));
        assert_eq!(
            std::fs::read_to_string(&key_file).unwrap(),
            format!("{key}\n")
        );
        assert_eq!(mode(Path::new(&key_file)), 0o600);
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
    }
}
