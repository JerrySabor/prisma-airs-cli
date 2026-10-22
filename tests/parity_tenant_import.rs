//! TS-vs-Rust parity around `tenant import` (DESIGN §3.12, §3.13, §10 "Import tests")
//! and the `dNN_` pins of its §12 rows (D27, D44, D51, D52, D82, D84, D85).
//!
//! - **After an import**, airs-cli-rs reads only its own copy, so every read command
//!   (`tenant list|read|get|path`, `doctor`, `runtime profiles|topics list`) must give
//!   the same answer as the TypeScript CLI reading its registry for the same tenants.
//!   The TypeScript side is written first, the Rust store emptied (`ts_only`), and only
//!   `airs-cli-rs tenant import` fills it: no provisioning shortcut is involved.
//! - **Import-source parity**: for every registry-path form and every corrupt registry,
//!   TypeScript `tenant list --output json` and airs-cli-rs
//!   `tenant import --dry-run --output json` agree on the names and TSGs, or on the
//!   generic registry message.
//! - `tenant import --from-config` and TypeScript `tenant create --config` report the
//!   same file errors.
//!
//! Both CLIs run in the same sandbox; outputs are compared after
//! `normalise_tenant_output`. A missing or unverified TypeScript reference fails the
//! tests (`AIRS_ALLOW_PARITY_SKIP=1` skips them with a notice).

use std::fs;

use airs_test_harness::live::{compare_doctor, doctor_from_json};
use airs_test_harness::{
    Cli, FixtureServer, FixtureTenant, RegistryEntry, Run, RunOptions, Sandbox,
    assert_json_semantic_eq, error_line, fixtures, normalise_tenant_output, registry_json,
    require_ts, run, ts_rows_as_rust,
};
use serde_json::Value;

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn norm(sandbox: &Sandbox, text: &str) -> String {
    normalise_tenant_output(text, sandbox).replace(&sandbox.root().display().to_string(), "<ROOT>")
}

/// `airs-cli-rs tenant import <args>`, allowed to write `store/` only (so the
/// TypeScript files are checked unchanged by the runner).
fn import(sandbox: &Sandbox, args: &[&str]) -> Run {
    let mut full = vec!["tenant", "import"];
    full.extend_from_slice(args);
    run(
        &rust(),
        sandbox,
        &full,
        &RunOptions::new().allow_writes_under("store"),
    )
}

fn read(cli: &Cli, sandbox: &Sandbox, args: &[&str]) -> Run {
    run(cli, sandbox, args, &RunOptions::new())
}

/// The cells of a `│` table, trimmed (padding follows each side's real path lengths).
fn cells(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|line| line.contains('│'))
        .map(|line| line.split('│').map(|cell| cell.trim().to_owned()).collect())
        .collect()
}

/// Fixture tenants: `dev` (standard), `prod` (renamed, dropped, empty and coerced
/// values), `scan` (scanner only); `prod` active. TypeScript side only.
fn three(server: &FixtureServer, sandbox: &Sandbox) -> Vec<FixtureTenant> {
    let dev = sandbox.add_fixture_tenant(server, "dev", "100");
    let prod = sandbox.add_fixture_tenant_with(server, "prod", "200", |config| {
        config
            .set("aiGwInferenceApiKey", "FAKE-GW-KEY-200")
            .set("aiGwInferenceModel", "model-200")
            .set("aiGwEmbeddingModel", "")
            .set("airsApiToken", "")
            .set("scanConcurrency", "7")
            .set("airsNumRetries", true)
            .set("defaultOutput", "table")
            .set("dataDir", "/runs")
            .set("typesafeApiKey", "FAKE-TS-KEY-200")
            .set("customSetting", 1);
    });
    let scan = sandbox.add_fixture_tenant_with(server, "scan", "300", |config| {
        config.remove("mgmtClientId");
        config.remove("mgmtClientSecret");
    });
    sandbox.register(&[&dev, &prod, &scan], Some("prod"));
    sandbox.ts_only();
    vec![dev, prod, scan]
}

/// The airs-cli-rs name of a TypeScript key (renamed or unchanged).
fn rust_key(ts_key: &str) -> &str {
    airs_test_harness::store::rust_key(ts_key)
}

mod after_import {
    use super::*;

    #[test]
    fn every_read_command_agrees_with_the_typescript_cli() {
        let Some(ts) = require_ts("every_read_command_agrees_with_the_typescript_cli") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tenants = three(&server, &sandbox);
        server.set_profiles("200", vec![fixtures::profile(1, "alpha", 1)]);
        server.set_topics("200", vec![fixtures::topic(11, "pii", 1, "topic")]);
        let imported = import(&sandbox, &["--output", "json"]);
        imported.assert_success();
        assert!(
            imported
                .stderr
                .contains("  Selected prod (selected in the TypeScript registry)")
        );
        let same = |args: &[&str]| {
            let (r, t) = (read(&rust(), &sandbox, args), read(&ts, &sandbox, args));
            assert_eq!(r.code, t.code, "{args:?}\nrust: {r:?}\nts: {t:?}");
            (r, t)
        };
        // tenant list: rows (json) and table cells (pretty).
        let (r, t) = same(&["tenant", "list", "--output", "json"]);
        assert_eq!(norm(&sandbox, &r.stdout), norm(&sandbox, &t.stdout));
        assert_eq!(norm(&sandbox, &r.stderr), norm(&sandbox, &t.stderr));
        let (r, t) = same(&["tenant", "list"]);
        assert_eq!(
            cells(&norm(&sandbox, &r.stdout)),
            cells(&norm(&sandbox, &t.stdout))
        );
        for tenant in &tenants {
            let name = tenant.name.as_str();
            // tenant read: TypeScript rows through the import conversion.
            let (r, t) = same(&["tenant", "read", name, "--output", "json"]);
            assert_eq!(r.json(), ts_rows_as_rust(&t.json(), false), "{name}");
            assert_eq!(
                norm(&sandbox, &r.stderr),
                norm(&sandbox, &t.stderr),
                "{name}"
            );
            // tenant get: every TypeScript key the Rust schema keeps, under its new name.
            for (ts_key, _) in tenant.config.entries() {
                let key = rust_key(ts_key);
                if airs_test_harness::store::RUST_KEYS.contains(&key) {
                    let r = read(
                        &rust(),
                        &sandbox,
                        &["tenant", "get", name, key, "--output", "json"],
                    );
                    let t = read(
                        &ts,
                        &sandbox,
                        &["tenant", "get", name, ts_key, "--output", "json"],
                    );
                    assert_eq!((r.code, t.code), (0, 0), "{name} {key}");
                    assert_eq!(r.json(), ts_rows_as_rust(&t.json(), true), "{name} {key}");
                }
            }
            // tenant path: each side's own file for the tenant.
            let (r, t) = same(&["tenant", "path", name]);
            assert_eq!(norm(&sandbox, &r.stdout), norm(&sandbox, &t.stdout));
            assert_eq!(norm(&sandbox, &r.stdout), format!("<CONFIG:{name}>\n"));
        }
        // Management reads with the imported credentials and endpoints.
        for args in [
            &["runtime", "profiles", "list", "--output", "json"][..],
            &["runtime", "topics", "list", "--output", "json"],
        ] {
            let (r, t) = same(args);
            assert_eq!(r.code, 0, "{args:?}: {r:?}");
            assert_json_semantic_eq(&r.json(), &t.json());
        }
        // prod's imported defaultOutput (table) applies on both.
        let (r, t) = same(&["runtime", "profiles", "list"]);
        assert_eq!(cells(&r.stdout), cells(&t.stdout));
        assert!(r.stdout.contains("│"), "{}", r.stdout);
        // doctor on the imported dev, selected on both sides: the seven shared checks
        // agree, and each CLI exits 1 exactly when one of its own checks failed
        // (TypeScript runs more checks, D19, D20).
        for cli in [rust(), ts.clone()] {
            let dir = if cli.is_ts() { "state" } else { "store" };
            run(
                &cli,
                &sandbox,
                &["tenant", "switch", "dev"],
                &RunOptions::new().allow_writes_under(dir),
            )
            .assert_success();
        }
        let args = ["doctor", "--output", "json"];
        let (r, t) = (read(&rust(), &sandbox, &args), read(&ts, &sandbox, &args));
        let (agree, note) = compare_doctor(
            &doctor_from_json(&r.json()).expect("rust doctor json"),
            &doctor_from_json(&t.json()).expect("ts doctor json"),
            Some(r.code),
            Some(t.code),
        );
        assert!(agree, "doctor: {note}\nrust: {r:?}\nts: {t:?}");
    }

    #[test]
    fn errors_of_the_imported_tenant_agree() {
        let Some(ts) = require_ts("errors_of_the_imported_tenant_agree") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        three(&server, &sandbox);
        import(&sandbox, &[]).assert_success();
        for args in [
            &["tenant", "get", "ghost", "mgmtTsgId"][..],
            &["tenant", "read", "ghost"],
            &["tenant", "path", "ghost"],
        ] {
            let (r, t) = (read(&rust(), &sandbox, args), read(&ts, &sandbox, args));
            assert_eq!(r.code, t.code, "{args:?}\nrust: {r:?}\nts: {t:?}");
            assert_eq!(
                error_line(&norm(&sandbox, &r.stderr)),
                error_line(&norm(&sandbox, &t.stderr)),
                "{args:?}"
            );
        }
        assert_eq!(server.request_count(), 0);
    }
}

mod import_source {
    use super::*;

    /// The run options that select one registry-path form.
    type PathForm = Box<dyn Fn(&Sandbox) -> RunOptions>;

    /// TypeScript `tenant list --output json` against airs-cli-rs
    /// `tenant import --dry-run --output json` under `options`: the same names and TSGs
    /// on success, the same error line otherwise.
    fn assert_same_source(sandbox: &Sandbox, ts: &Cli, options: &RunOptions, label: &str) {
        let t = run(
            ts,
            sandbox,
            &["tenant", "list", "--output", "json"],
            options,
        );
        let r = run(
            &rust(),
            sandbox,
            &["tenant", "import", "--dry-run", "--output", "json"],
            options,
        );
        assert_eq!(r.code, t.code, "{label}\nrust: {r:?}\nts: {t:?}");
        if t.code == 0 {
            let pairs = |value: &Value| -> Vec<(String, String)> {
                let mut pairs: Vec<(String, String)> = value
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| {
                        (
                            row["name"].as_str().unwrap().to_owned(),
                            row["tsgId"].as_str().unwrap().to_owned(),
                        )
                    })
                    .collect();
                pairs.sort();
                pairs
            };
            assert_eq!(pairs(&r.json()), pairs(&t.json()), "{label}");
            assert!(!pairs(&r.json()).is_empty(), "{label}");
        } else {
            assert_eq!(
                error_line(&norm(sandbox, &r.stderr)),
                error_line(&norm(sandbox, &t.stderr)),
                "{label}"
            );
        }
    }

    /// A registry of one standard tenant at `relative` (under the sandbox root).
    fn registry_at(server: &FixtureServer, sandbox: &Sandbox, relative: &str) {
        let tenant = sandbox.add_fixture_tenant(server, "dev", "100");
        sandbox.write_file(
            relative,
            registry_json(&[tenant.entry()], Some("dev")).as_bytes(),
            0o600,
        );
        sandbox.ts_only();
    }

    #[test]
    fn every_registry_path_form_agrees() {
        let Some(ts) = require_ts("every_registry_path_form_agrees") else {
            return;
        };
        let server = FixtureServer::start();
        let forms: Vec<(&str, &str, PathForm)> = vec![
            (
                "PRISMA_AIRS_TENANTS_PATH with ~/",
                "home/r.json",
                Box::new(|_| RunOptions::new().env("PRISMA_AIRS_TENANTS_PATH", "~/r.json")),
            ),
            (
                "PRISMA_AIRS_TENANTS_PATH relative",
                "cwd/sub/r.json",
                Box::new(|_| RunOptions::new().env("PRISMA_AIRS_TENANTS_PATH", "sub/./r.json")),
            ),
            (
                "PRISMA_AIRS_TENANTS_PATH absolute",
                "state/other.json",
                Box::new(|sandbox| {
                    RunOptions::new().env(
                        "PRISMA_AIRS_TENANTS_PATH",
                        sandbox.state_dir().join("other.json").display().to_string(),
                    )
                }),
            ),
            (
                "XDG_STATE_HOME",
                "tmp/xdg/prisma-airs/tenants.json",
                Box::new(|sandbox| {
                    RunOptions::new()
                        .without_env("PRISMA_AIRS_TENANTS_PATH")
                        .env(
                            "XDG_STATE_HOME",
                            sandbox.tmp().join("xdg").display().to_string(),
                        )
                }),
            ),
            (
                "HOME",
                "home/.local/state/prisma-airs/tenants.json",
                Box::new(|_| RunOptions::new().without_env("PRISMA_AIRS_TENANTS_PATH")),
            ),
            (
                "an empty HOME (cwd-relative)",
                "cwd/.local/state/prisma-airs/tenants.json",
                Box::new(|_| {
                    RunOptions::new()
                        .without_env("PRISMA_AIRS_TENANTS_PATH")
                        .env("HOME", "")
                }),
            ),
        ];
        for (label, relative, options) in &forms {
            let sandbox = Sandbox::new();
            registry_at(&server, &sandbox, relative);
            assert_same_source(&sandbox, &ts, &options(&sandbox), label);
        }
        // `~` alone names the home directory itself: both refuse it.
        let sandbox = Sandbox::new();
        assert_same_source(
            &sandbox,
            &ts,
            &RunOptions::new().env("PRISMA_AIRS_TENANTS_PATH", "~"),
            "PRISMA_AIRS_TENANTS_PATH=~",
        );
        // A relative XDG_STATE_HOME: the same error.
        let sandbox = Sandbox::new();
        assert_same_source(
            &sandbox,
            &ts,
            &RunOptions::new()
                .without_env("PRISMA_AIRS_TENANTS_PATH")
                .env("XDG_STATE_HOME", "relative"),
            "relative XDG_STATE_HOME",
        );
    }

    #[test]
    fn every_corrupt_registry_agrees() {
        let Some(ts) = require_ts("every_corrupt_registry_agrees") else {
            return;
        };
        let sandbox = Sandbox::new();
        let config = sandbox.configs_dir().join("dev.json").display().to_string();
        let entry = |name: &str, path: &str, tsg: &str| {
            format!(r#"{{"name":"{name}","configPath":"{path}","tsgId":"{tsg}"}}"#)
        };
        let registries: Vec<(&str, Vec<u8>)> = vec![
            ("invalid JSON", b"{".to_vec()),
            ("empty file", Vec::new()),
            ("version 2", br#"{"version":2,"active":null,"tenants":[]}"#.to_vec()),
            ("missing active", br#"{"version":1,"tenants":[]}"#.to_vec()),
            (
                "unknown key",
                br#"{"version":1,"active":null,"tenants":[],"x":1}"#.to_vec(),
            ),
            (
                "unknown entry key",
                format!(
                    r#"{{"version":1,"active":null,"tenants":[{{"name":"dev","configPath":"{config}","tsgId":"1","x":1}}]}}"#
                )
                .into_bytes(),
            ),
            (
                "active not registered",
                br#"{"version":1,"active":"ghost","tenants":[]}"#.to_vec(),
            ),
            (
                "duplicate names",
                format!(
                    r#"{{"version":1,"active":null,"tenants":[{},{}]}}"#,
                    entry("dev", &config, "1"),
                    entry("dev", &config, "2")
                )
                .into_bytes(),
            ),
            (
                "relative configPath",
                format!(
                    r#"{{"version":1,"active":null,"tenants":[{}]}}"#,
                    entry("dev", "configs/dev.json", "1")
                )
                .into_bytes(),
            ),
            (
                "empty tsgId",
                format!(
                    r#"{{"version":1,"active":null,"tenants":[{}]}}"#,
                    entry("dev", &config, "")
                )
                .into_bytes(),
            ),
            (
                "bad name",
                format!(
                    r#"{{"version":1,"active":null,"tenants":[{}]}}"#,
                    entry("-bad", &config, "1")
                )
                .into_bytes(),
            ),
            ("over 1 MiB", vec![b' '; 1_048_577]),
        ];
        for (label, bytes) in &registries {
            sandbox.write_registry_raw(bytes);
            sandbox.ts_only();
            assert_same_source(&sandbox, &ts, &RunOptions::new(), label);
        }
        // A directory and a symlink in the registry's place.
        fs::remove_file(sandbox.registry_path()).unwrap();
        fs::create_dir(sandbox.registry_path()).unwrap();
        assert_same_source(&sandbox, &ts, &RunOptions::new(), "a directory");
        fs::remove_dir(sandbox.registry_path()).unwrap();
        let real = sandbox.state_dir().join("real.json");
        fs::write(&real, br#"{"version":1,"active":null,"tenants":[]}"#).unwrap();
        std::os::unix::fs::symlink(&real, sandbox.registry_path()).unwrap();
        assert_same_source(&sandbox, &ts, &RunOptions::new(), "a symlink");
    }
}

mod from_config {
    use super::*;

    #[test]
    fn file_errors_agree_with_create_config() {
        let Some(ts) = require_ts("file_errors_agree_with_create_config") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.ts_only();
        let missing = sandbox.configs_dir().join("missing.json");
        let bad = sandbox.write_config_raw("bad", br#"{"mgmtClientSecret":"FAKE-S9",oops"#);
        let schema = sandbox.write_fixture_config(
            "schema",
            &Sandbox::fixture_config(&server, "1").with("scanConcurrency", 99),
        );
        let link = sandbox.configs_dir().join("link.json");
        std::os::unix::fs::symlink(&schema, &link).unwrap();
        for path in [&missing, &bad, &schema, &link] {
            let path = path.display().to_string();
            let r = import(&sandbox, &["--from-config", &path, "--name", "dev"]);
            let t = run(
                &ts,
                &sandbox,
                &["tenant", "create", "dev", "--config", &path],
                &RunOptions::new(),
            );
            assert_eq!((r.code, t.code), (1, 1), "{path}\nrust: {r:?}\nts: {t:?}");
            assert_eq!(
                error_line(&r.stderr),
                error_line(&t.stderr),
                "{path}: the same message and canonical path"
            );
        }
    }
}

mod divergences {
    use super::*;

    #[test]
    fn d27_import_rejects_invalid_utf8() {
        let Some(ts) = require_ts("d27_import_rejects_invalid_utf8") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let text = Sandbox::fixture_config(&server, "100").to_json();
        let (before, after) = text.split_once("FAKE-APIKEY-100").unwrap();
        let config = sandbox.write_config_raw(
            "dev",
            &[before.as_bytes(), b"FAKE-APIKEY-\xff", after.as_bytes()].concat(),
        );
        sandbox.write_registry(&[RegistryEntry::new("dev", &config, "100")], Some("dev"));
        sandbox.ts_only();
        // TypeScript decodes the config lossily and uses it.
        let t = read(
            &ts,
            &sandbox,
            &["tenant", "read", "dev", "--output", "json"],
        );
        t.assert_success();
        // airs-cli-rs refuses to import it.
        let r = import(&sandbox, &["--output", "json"]);
        r.assert_code(1);
        assert_eq!(r.json()[0]["action"], "skip");
        assert_eq!(
            r.json()[0]["notes"][0],
            format!("cannot read a valid tenant config at {}", config.display())
        );
        // An invalid UTF-8 registry: TypeScript lists it, airs-cli-rs refuses it.
        let registry = format!(
            r#"{{"version":1,"active":null,"tenants":[{{"name":"dev","configPath":"{}","tsgId":"1"#,
            config.display()
        );
        sandbox.write_registry_raw(&[registry.as_bytes(), b"\xff\"}]}"].concat());
        sandbox.ts_only();
        let t = read(&ts, &sandbox, &["tenant", "list", "--output", "json"]);
        t.assert_success();
        assert_eq!(t.json()[0]["tsgId"], "1\u{fffd}");
        let r = import(&sandbox, &[]);
        r.assert_code(1);
        assert!(
            r.stderr.contains("Cannot read tenant registry at"),
            "{}",
            r.stderr
        );
    }

    #[test]
    fn d44_import_rejects_unrepresentable_json() {
        let Some(ts) = require_ts("d44_import_rejects_unrepresentable_json") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let config = Sandbox::fixture_config(&server, "100").with("customSetting", "x");
        let text = config.to_json().replace("\"x\"", "\"\\ud800\"");
        let path = sandbox.write_config_raw("dev", text.as_bytes());
        sandbox.write_registry(&[RegistryEntry::new("dev", &path, "100")], Some("dev"));
        sandbox.ts_only();
        let t = read(
            &ts,
            &sandbox,
            &["tenant", "read", "dev", "--output", "json"],
        );
        t.assert_success();
        let r = import(&sandbox, &["--output", "json"]);
        r.assert_code(1);
        assert_eq!(
            r.json()[0]["notes"][0],
            format!("cannot read a valid tenant config at {}", path.display())
        );
    }

    #[test]
    fn d51_import_drops_a_dead_default_output() {
        let Some(ts) = require_ts("d51_import_drops_a_dead_default_output") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tenant = sandbox.add_fixture_tenant_with(&server, "dev", "100", |config| {
            config.set("defaultOutput", "markdown");
        });
        sandbox.register(&[&tenant], Some("dev"));
        sandbox.ts_only();
        let t = read(&ts, &sandbox, &["tenant", "get", "dev", "defaultOutput"]);
        assert_eq!(t.stdout, "markdown\n", "TypeScript keeps the format");
        let r = import(&sandbox, &["--output", "json"]);
        r.assert_success();
        let notes = r.json()[0]["notes"].clone();
        assert!(
            notes.as_array().unwrap().contains(&Value::from(
                "dropped defaultOutput markdown (format no longer supported)"
            )),
            "{notes}"
        );
        let r = read(
            &rust(),
            &sandbox,
            &["tenant", "get", "dev", "defaultOutput"],
        );
        assert_eq!(r.stdout, "\n", "airs has no defaultOutput: pretty applies");
        let profiles = read(&rust(), &sandbox, &["runtime", "profiles", "list"]);
        profiles.assert_success();
    }

    #[test]
    fn d52_import_report_is_terminal_safe() {
        let Some(ts) = require_ts("d52_import_report_is_terminal_safe") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tsg = "1\u{1b}[31m";
        let tenant = sandbox.add_fixture_tenant_with(&server, "dev", "100", |config| {
            config.set("mgmtTsgId", tsg);
        });
        sandbox.write_registry(&[RegistryEntry::new("dev", &tenant.config_path, tsg)], None);
        sandbox.ts_only();
        // TypeScript writes the escape sequence to the terminal.
        let t = read(&ts, &sandbox, &["tenant", "list"]);
        assert!(t.stdout.contains('\u{1b}'), "{:?}", t.stdout);
        let r = import(&sandbox, &["--dry-run"]);
        r.assert_success();
        assert!(!r.stdout.contains('\u{1b}'), "{:?}", r.stdout);
        assert!(r.stdout.contains("1\u{fffd}[31m"), "{:?}", r.stdout);
    }

    #[test]
    fn d82_from_config_without_management_credentials() {
        let Some(ts) = require_ts("d82_from_config_without_management_credentials") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.ts_only();
        let config = Sandbox::fixture_config(&server, "100")
            .without("mgmtClientId")
            .without("mgmtClientSecret");
        let path = sandbox
            .write_fixture_config("scan", &config)
            .display()
            .to_string();
        let t = run(
            &ts,
            &sandbox,
            &["tenant", "create", "scan", "--config", &path],
            &RunOptions::new(),
        );
        t.assert_code(1);
        assert_eq!(
            error_line(&t.stderr).as_deref(),
            Some("Tenant config requires mgmtTsgId, mgmtClientId and mgmtClientSecret")
        );
        let r = import(&sandbox, &["--from-config", &path, "--name", "scan"]);
        r.assert_success();
        let scan = read(
            &rust(),
            &sandbox,
            &[
                "--tenant",
                "scan",
                "runtime",
                "scan",
                "--profile",
                "p",
                "hello",
            ],
        );
        assert_ne!(scan.code, 2, "the scanner-only tenant is usable: {scan:?}");
    }

    #[test]
    fn d84_from_config_copies_the_file() {
        let Some(ts) = require_ts("d84_from_config_copies_the_file") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let config = sandbox.write_fixture_config("own", &Sandbox::fixture_config(&server, "100"));
        let source_before = fs::read(&config).unwrap();
        sandbox.ts_only();
        let path = config.display().to_string();
        // TypeScript registers the file in place.
        let t = run(
            &ts,
            &sandbox,
            &["tenant", "create", "own", "--config", &path],
            &RunOptions::new().allow_writes_under("state"),
        );
        t.assert_success();
        let registry: Value =
            serde_json::from_slice(&fs::read(sandbox.registry_path()).unwrap()).unwrap();
        assert_eq!(registry["tenants"][0]["configPath"], path.as_str());
        // airs-cli-rs copies it into its store.
        let r = import(&sandbox, &["--from-config", &path, "--name", "own"]);
        r.assert_success();
        let rust_path = read(&rust(), &sandbox, &["tenant", "path", "own"]);
        assert_eq!(
            rust_path.stdout,
            format!("{}\n", sandbox.store_tenant_path("own").display())
        );
        assert_eq!(
            fs::read(&config).unwrap(),
            source_before,
            "the source is unchanged"
        );
        // `create --config` is gone from airs-cli-rs.
        let gone = run(
            &rust(),
            &sandbox,
            &["tenant", "create", "x", "--config", &path],
            &RunOptions::new(),
        );
        gone.assert_code(2);
    }

    #[test]
    fn d85_import_skips_names_differing_only_in_case() {
        let Some(ts) = require_ts("d85_import_skips_names_differing_only_in_case") else {
            return;
        };
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let upper = sandbox.write_fixture_config("upper", &Sandbox::fixture_config(&server, "100"));
        let lower = sandbox.write_fixture_config("lower", &Sandbox::fixture_config(&server, "200"));
        sandbox.write_registry(
            &[
                RegistryEntry::new("Dev", &upper, "100"),
                RegistryEntry::new("dev", &lower, "200"),
            ],
            None,
        );
        sandbox.ts_only();
        let t = read(&ts, &sandbox, &["tenant", "list", "--output", "json"]);
        assert_eq!(
            t.json().as_array().unwrap().len(),
            2,
            "TypeScript keeps both"
        );
        let r = import(&sandbox, &["--output", "json"]);
        r.assert_success();
        assert_eq!(r.json()[0]["action"], "import");
        assert_eq!(r.json()[1]["action"], "skip");
        assert_eq!(
            r.json()[1]["notes"][0],
            "conflicts with existing tenant Dev; names may not differ only in case"
        );
        let listed = read(&rust(), &sandbox, &["tenant", "list", "--output", "json"]);
        assert_eq!(listed.json().as_array().unwrap().len(), 1);
    }
}
