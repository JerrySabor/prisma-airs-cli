//! Executable tests of the 0.2 renderings: every command in `pretty`, `table`, `json`
//! and its default, including empty lists, long and Unicode values, control
//! characters, `--quiet` and colour on/off (DESIGN §2.4, §2.7, §2.8, §3.6, §7.6, §8.6,
//! §9). The TypeScript comparisons live in the `tests/parity_*.rs` files; these pin the
//! airs-cli-rs bytes on their own, so they run without the reference build.
//!
//! The harness pipes both streams, so a terminal is never seen: colour is on only when
//! `CLICOLOR_FORCE` is set and `NO_COLOR` is not (the runner sets `NO_COLOR=1`; the
//! colour tests remove it). The per-stream terminal decision is unit-tested in
//! `src/render/style.rs`.

use airs_test_harness::{Cli, FixtureServer, Run, RunOptions, Sandbox, fixtures, run};
use serde_json::{Value, json};

const TSG: &str = "100";
const BANNER: &str =
    "\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n";
const ESC: char = '\u{1b}';

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

fn fx() -> Fx {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    Fx { server, sandbox }
}

fn fx_with(edit: impl FnOnce(&mut airs_test_harness::FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

impl Fx {
    fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, RunOptions::new())
    }

    fn run_with(&self, args: &[&str], options: RunOptions) -> Run {
        let before = self.sandbox.snapshot();
        let out = run(&rust(), &self.sandbox, args, &options);
        self.sandbox.assert_unchanged(&before);
        self.server.assert_no_unknown_routes();
        out
    }

    /// With colour forced on both streams.
    fn coloured(&self, args: &[&str]) -> Run {
        self.run_with(args, forced())
    }
}

fn forced() -> RunOptions {
    RunOptions::new()
        .without_env("NO_COLOR")
        .env("CLICOLOR_FORCE", "1")
}

fn with<'a>(base: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
    base.iter().chain(extra).copied().collect()
}

fn assert_out(out: &Run, code: i32, stdout: &str, stderr: &str) {
    assert_eq!(
        (out.code, out.stdout.as_str(), out.stderr.as_str()),
        (code, stdout, stderr),
        "{:?}",
        out.args
    );
}

fn usage(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
}

/// A `Key │ Value` or list table built the way §2.7 specifies (display width).
fn table(labels: &[&str], rows: &[Vec<&str>]) -> String {
    let width = |text: &str| -> usize {
        text.chars()
            .map(|c| match c {
                '日' | '本' | '語' | '🚀' => 2,
                '\u{301}' => 0,
                _ => 1,
            })
            .sum()
    };
    let widths: Vec<usize> = (0..labels.len())
        .map(|i| {
            rows.iter()
                .map(|row| width(row[i]))
                .fold(width(labels[i]), usize::max)
        })
        .collect();
    let line = |cells: Vec<&str>| -> String {
        cells
            .iter()
            .zip(&widths)
            .map(|(cell, w)| format!(" {cell}{} ", " ".repeat(w - width(cell))))
            .collect::<Vec<_>>()
            .join("│")
    };
    let mut lines = vec![line(labels.to_vec())];
    lines.push(
        widths
            .iter()
            .map(|w| "─".repeat(w + 2))
            .collect::<Vec<_>>()
            .join("┼"),
    );
    for row in rows {
        lines.push(line(row.clone()));
    }
    format!("{}\n", lines.join("\n"))
}

// ---------------------------------------------------------------------------------------
// tenant list | read | get | path
// ---------------------------------------------------------------------------------------

mod tenant {
    use super::*;

    fn three(fx: &Fx) -> Vec<String> {
        let configs = fx.sandbox.configs_dir();
        let paths = [
            configs.join("prod.json"),
            configs.join("dév-日本-🚀.json"),
            configs.join("a/much/longer/path/staging.json"),
        ];
        fx.sandbox.write_registry(
            &[
                airs_test_harness::RegistryEntry::new("prod", &paths[0], "100"),
                airs_test_harness::RegistryEntry::new("dev", &paths[1], "1234567890"),
                airs_test_harness::RegistryEntry::new("a-much-longer-tenant-name", &paths[2], "7"),
            ],
            Some("prod"),
        );
        // airs-cli-rs lists its own tenant files, in byte order (D70, D86).
        ["a-much-longer-tenant-name", "dev", "prod"]
            .iter()
            .map(|name| fx.sandbox.store_tenant_path(name).display().to_string())
            .collect()
    }

    #[test]
    fn list_pretty_and_table_are_the_same_table() {
        let fx = Fx {
            server: FixtureServer::start(),
            sandbox: Sandbox::new(),
        };
        let paths = three(&fx);
        let expected = table(
            &["Tenant", "Selected", "TSG ID", "Config file"],
            &[
                vec!["a-much-longer-tenant-name", "false", "7", &paths[0]],
                vec!["dev", "false", "1234567890", &paths[1]],
                vec!["prod", "true", "100", &paths[2]],
            ],
        );
        for args in [
            &["tenant", "list"][..],
            &["tenant", "ls", "--output", "pretty"],
            &["--output", "table", "tenant", "list"],
            &["tenant", "list", "--output", "table", "--quiet"],
        ] {
            assert_out(&fx.run(args), 0, &expected, "");
        }
        let json = fx.run(&["tenant", "list", "--output", "json"]);
        assert_eq!(json.json()[1]["configPath"], paths[1].as_str());
    }

    #[test]
    fn list_without_a_selection_and_empty() {
        let fx = Fx {
            server: FixtureServer::start(),
            sandbox: Sandbox::new(),
        };
        let path = fx.sandbox.configs_dir().join("prod.json");
        fx.sandbox.write_registry(
            &[airs_test_harness::RegistryEntry::new("prod", &path, "100")],
            None,
        );
        let path = fx.sandbox.store_tenant_path("prod").display().to_string();
        let expected = table(
            &["Tenant", "Selected", "TSG ID", "Config file"],
            &[vec!["prod", "false", "100", &path]],
        );
        let status = "  No tenant selected; run 'airs tenant switch <name>'.\n";
        for format in ["pretty", "table"] {
            assert_out(
                &fx.run(&["tenant", "list", "--output", format]),
                0,
                &expected,
                status,
            );
            assert_out(
                &fx.run(&["tenant", "list", "--output", format, "--quiet"]),
                0,
                &expected,
                "",
            );
        }
        fx.sandbox.write_registry(&[], None);
        let created = "  Run 'airs tenant create <name>' to register one.\n";
        assert_out(
            &fx.run(&["tenant", "list"]),
            0,
            "  No tenants found\n",
            created,
        );
        assert_out(
            &fx.run(&["tenant", "list", "--quiet"]),
            0,
            "  No tenants found\n",
            "",
        );
        assert_out(
            &fx.run(&["tenant", "list", "--output", "table"]),
            0,
            "\n",
            "",
        );
        assert_out(
            &fx.run(&["tenant", "list", "--output", "json"]),
            0,
            "[]\n",
            "",
        );
    }

    #[test]
    fn read_pretty_and_table_are_the_key_value_table() {
        let fx = fx_with(|config| {
            config
                .set("scanConcurrency", "3")
                .set("aiGwInferenceModel", "m");
        });
        let base = fx.server.base_url();
        let pretty = fx.run(&["tenant", "read"]);
        assert_eq!(pretty.code, 0);
        let lines: Vec<&str> = pretty.stdout.lines().collect();
        assert!(
            lines[0].starts_with(" Key                          │ Value"),
            "{}",
            pretty.stdout
        );
        assert!(
            lines[2].starts_with(" airsApiKey                   │ [REDACTED] "),
            "{}",
            pretty.stdout
        );
        let width = lines[0].chars().count();
        assert!(
            lines.iter().all(|line| line.chars().count() == width),
            "aligned"
        );
        assert!(
            pretty
                .stdout
                .contains(&format!(" mgmtEndpoint                 │ {base}/aisec "))
        );
        assert!(pretty.stdout.contains(" scanConcurrency              │ 3 "));
        assert!(
            pretty
                .stdout
                .contains("\n gatewayInferenceModel        │ m "),
            "the renamed key (D71)"
        );
        assert!(
            !pretty.stdout.contains("dataDir") && !pretty.stdout.contains("typesafe"),
            "dropped keys have no row (D71)"
        );
        assert!(pretty.stderr.starts_with("  Tenant prod (TSG 100): "));
        for args in [
            &["tenant", "read", "--output", "table"][..],
            &["tenant", "read", "prod", "--output", "pretty"],
        ] {
            assert_out(&fx.run(args), 0, &pretty.stdout, &pretty.stderr);
        }
        assert_out(
            &fx.run(&["tenant", "read", "--quiet"]),
            0,
            &pretty.stdout,
            "",
        );
        let json = fx.run(&["tenant", "read", "--output", "json"]);
        assert_eq!(
            json.json()[0],
            json!({"key": "airsApiKey", "value": "[REDACTED]"})
        );
    }

    /// D52: the `tenant read` status line carries `config.toml` text (`tsg_id`);
    /// control characters in it become U+FFFD on stderr in every format, as in the
    /// cells.
    #[test]
    fn read_status_line_is_terminal_safe() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tsg = "10\u{1b}[0m0";
        let tenant = sandbox.add_fixture_tenant(&server, "pr\u{1b}]0;t\u{7}\tod", tsg);
        sandbox.write_registry(
            &[airs_test_harness::RegistryEntry::new(
                "prod",
                &tenant.config_path,
                tsg,
            )],
            Some("prod"),
        );
        let fx = Fx { server, sandbox };
        let store = fx.sandbox.store_dir().display().to_string();
        let expected = format!("  Tenant prod (TSG 10\u{fffd}[0m0): {store}/tenants/prod.toml\n");
        for format in ["pretty", "table", "json"] {
            let out = fx.run(&["tenant", "read", "--output", format]);
            assert_eq!(
                (out.code, out.stderr.as_str()),
                (0, expected.as_str()),
                "{format}"
            );
        }
    }

    #[test]
    fn get_pretty_table_json_and_default() {
        let fx = fx_with(|config| {
            config.set("aiGwInferenceModel", "model\u{1b}[31m-ü\t");
        });
        for (key, shown) in [
            ("mgmtTsgId", "100"),
            ("mgmtClientSecret", "[REDACTED]"),
            ("scanConcurrency", "5"),
            ("defaultOutput", ""),
            // D52: control characters are replaced in the bare value and the cell.
            ("gatewayInferenceModel", "model\u{fffd}[31m-ü\u{fffd}"),
        ] {
            let expected = format!("{shown}\n");
            assert_out(&fx.run(&["tenant", "get", "prod", key]), 0, &expected, "");
            assert_out(
                &fx.run(&["tenant", "get", "prod", key, "--output", "pretty"]),
                0,
                &expected,
                "",
            );
            assert_out(
                &fx.run(&["tenant", "get", "prod", key, "--output", "table"]),
                0,
                &table(&["Key", "Value"], &[vec![key, shown]]),
                "",
            );
        }
        let json = fx.run(&[
            "tenant",
            "get",
            "prod",
            "gatewayInferenceModel",
            "--output",
            "json",
        ]);
        assert_eq!(
            json.json(),
            json!([{"key": "gatewayInferenceModel", "value": "model\u{1b}[31m-ü\t"}])
        );
        assert!(
            json.stdout.contains("\\u001b"),
            "JSON escapes the control character"
        );
    }

    /// D52: the store paths come from `AIRS_CLI_CONFIG_DIR`; a control character in it
    /// is U+FFFD in the list cell, the `tenant read` status line and `tenant path`, and
    /// stays escaped in JSON.
    #[test]
    fn store_paths_are_terminal_safe() {
        let fx = fx();
        let hostile = fx.sandbox.tmp().join("st\u{1b}[31mo\tre");
        let status = std::process::Command::new("cp")
            .arg("-Rp")
            .arg(fx.sandbox.store_dir())
            .arg(&hostile)
            .status()
            .expect("cp");
        assert!(status.success());
        let options =
            || RunOptions::new().env("AIRS_CLI_CONFIG_DIR", hostile.display().to_string());
        let safe = format!(
            "{}/st\u{fffd}[31mo\u{fffd}re/tenants/prod.toml",
            fx.sandbox.tmp().display()
        );
        let list = fx.run_with(&["tenant", "list"], options());
        assert_eq!(list.code, 0);
        assert!(
            list.stdout.contains(&format!(" {safe} ")),
            "{}",
            list.stdout
        );
        let read = fx.run_with(&["tenant", "read"], options());
        assert_eq!(read.stderr, format!("  Tenant prod (TSG {TSG}): {safe}\n"));
        let path = fx.run_with(&["tenant", "path"], options());
        assert_eq!(path.stdout, format!("{safe}\n"));
        let json = fx.run_with(&["tenant", "list", "--output", "json"], options());
        assert!(json.stdout.contains("\\u001b[31mo\\tre"), "{}", json.stdout);
    }

    /// D59: `tenant path` validates `--output` and then ignores a valid one.
    #[test]
    fn path_ignores_a_valid_output_and_rejects_an_invalid_one() {
        let fx = fx();
        let path = format!("{}\n", fx.sandbox.store_tenant_path("prod").display());
        for args in [
            &["tenant", "path"][..],
            &["tenant", "path", "--output", "pretty"],
            &["tenant", "path", "--output", "table"],
            &["--output", "json", "tenant", "path"],
        ] {
            assert_out(&fx.run(args), 0, &path, "");
        }
        for format in ["xml", "csv", "markdown", "yaml", ""] {
            assert_out(
                &fx.run(&["tenant", "path", "--output", format]),
                2,
                "",
                &usage(&format!(
                    "Invalid output format '{format}'. Expected: pretty, table, json"
                )),
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------------------

mod doctor {
    use super::*;

    fn rows(stdout: &str) -> Vec<Vec<String>> {
        stdout
            .lines()
            .map(|line| line.split('│').map(|cell| cell.trim().to_owned()).collect())
            .collect()
    }

    #[test]
    fn table_has_the_eight_checks_and_nothing_else() {
        let fx = fx();
        let out = fx.run(&["doctor", "--output", "table"]);
        assert_eq!((out.code, out.stderr.as_str()), (0, ""));
        let rows = rows(&out.stdout);
        assert_eq!(rows[0], ["Name", "Status", "Detail", "Hint"]);
        assert!(
            out.stdout
                .lines()
                .nth(1)
                .is_some_and(|rule| rule.chars().all(|c| c == '─' || c == '┼'))
        );
        let names: Vec<&str> = rows[2..].iter().map(|row| row[0].as_str()).collect();
        assert_eq!(
            names,
            [
                "Tenant",
                "Config file",
                "Environment",
                "Scanner credentials",
                "Management credentials",
                "Scanner API",
                "Management OAuth",
                "Gateway API"
            ]
        );
        assert!(
            rows[2..].iter().all(|row| row[1] == "pass"),
            "{}",
            out.stdout
        );
        assert!(!out.stdout.contains("All checks passed"));
        let width = out.stdout.lines().next().map(|l| l.chars().count());
        assert!(
            out.stdout.lines().all(|l| Some(l.chars().count()) == width),
            "aligned"
        );
        let quiet = fx.run(&["doctor", "--output", "table", "--quiet"]);
        assert_out(&quiet, 0, &out.stdout, "");
        let coloured = fx.coloured(&["doctor", "--output", "table"]);
        assert!(
            !coloured.stdout.contains(ESC) && coloured.stderr.is_empty(),
            "tables are never coloured"
        );
    }

    #[test]
    fn table_of_a_failing_report_exits_1_without_a_summary() {
        let fx = fx_with(|config| {
            config.remove("airsApiKey");
            config.remove("mgmtClientSecret");
        });
        let out = fx.run(&["--output", "table", "doctor"]);
        assert_eq!((out.code, out.stderr.as_str()), (1, ""));
        let rows = rows(&out.stdout);
        let credentials = rows
            .iter()
            .find(|row| row[0] == "Management credentials")
            .expect("row");
        assert_eq!(credentials[1], "fail");
        assert!(
            credentials[3].starts_with("Run 'airs tenant set prod <key>' for mgmtClientSecret")
        );
        assert!(
            rows.iter()
                .any(|row| row[0] == "Scanner API" && row[1] == "skip" && row[3].is_empty())
        );
    }

    #[test]
    fn pretty_colours_follow_ts() {
        let fx = fx_with(|config| {
            config.remove("airsApiKey");
            config.remove("mgmtClientSecret");
        });
        let out = fx.coloured(&["doctor"]);
        assert_eq!(out.code, 1);
        assert!(out.stdout.starts_with("\n  \u{1b}[1mDoctor\u{1b}[22m\n  \u{1b}[2mPrisma AIRS CLI preflight checks\u{1b}[22m\n\n"));
        assert!(out.stdout.contains("  \u{1b}[32m✓\u{1b}[39m Tenant — "));
        assert!(
            out.stdout
                .contains("  \u{1b}[31m✗\u{1b}[39m Management credentials — ")
        );
        assert!(
            out.stdout
                .contains("  \u{1b}[33m○\u{1b}[39m Scanner API — ")
        );
        assert!(
            out.stdout
                .contains("\n  \u{1b}[2m    Run 'airs tenant set prod <key>' for ")
        );
        assert_eq!(out.stderr, "  \u{1b}[31m✗ 1 check failed\u{1b}[39m\n");
        let plain = fx.run(&["doctor"]);
        assert!(!plain.stdout.contains(ESC) && !plain.stderr.contains(ESC));
        assert_eq!(plain.stderr, "  ✗ 1 check failed\n");
    }
}

// ---------------------------------------------------------------------------------------
// runtime profiles list | get
// ---------------------------------------------------------------------------------------

mod profiles {
    use super::*;

    fn alpha_beta() -> Vec<Value> {
        vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(2, "alpha", 2),
            fixtures::profile(3, "beta", 1),
        ]
    }

    #[test]
    fn list_in_every_format() {
        let fx = fx();
        fx.server.set_profiles(TSG, alpha_beta());
        let pretty = format!(
            "{BANNER}\n  Security Profiles:\n\n  {}\n    alpha  active rev:2\n  {}\n    beta  active rev:1\n\n",
            fixtures::uuid(2),
            fixtures::uuid(3)
        );
        let showing = "  Showing 2\n";
        assert_out(
            &fx.run(&["runtime", "profiles", "list"]),
            0,
            &pretty,
            showing,
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "ls", "--output", "pretty"]),
            0,
            &pretty,
            showing,
        );
        let quiet = format!(
            "  {}\n    alpha  active rev:2\n  {}\n    beta  active rev:1\n\n",
            fixtures::uuid(2),
            fixtures::uuid(3)
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "list", "--quiet"]),
            0,
            &quiet,
            "",
        );
        let ids = [fixtures::uuid(2), fixtures::uuid(3)];
        let table = table(
            &["ID", "Name", "Active", "Revision"],
            &[
                vec![&ids[0], "alpha", "true", "2"],
                vec![&ids[1], "beta", "true", "1"],
            ],
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "list", "--output", "table"]),
            0,
            &table,
            showing,
        );
        assert_out(
            &fx.run(&[
                "runtime", "profiles", "list", "--output", "table", "--quiet",
            ]),
            0,
            &table,
            "",
        );
        let json = fx.run(&["runtime", "profiles", "list", "--output", "json"]);
        assert_eq!(json.json()[0]["profileName"], "alpha");
        // --all-versions get: the list layout without a status line.
        let versions = fx.run(&["runtime", "profiles", "get", "alpha", "--all-versions"]);
        assert_out(
            &versions,
            0,
            &format!(
                "{BANNER}\n  Security Profiles:\n\n  {}\n    alpha  active rev:1\n  {}\n    alpha  active rev:2\n\n",
                fixtures::uuid(1),
                fixtures::uuid(2)
            ),
            "",
        );
    }

    #[test]
    fn empty_lists() {
        let fx = fx();
        let showing = "  Showing 0\n";
        assert_out(
            &fx.run(&["runtime", "profiles", "list"]),
            0,
            &format!("{BANNER}  No profiles found\n"),
            showing,
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "list", "--quiet"]),
            0,
            "  No profiles found\n",
            "",
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "list", "--output", "table"]),
            0,
            "",
            showing,
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "list", "--output", "json"]),
            0,
            "[]\n",
            showing,
        );
    }

    #[test]
    fn edge_rows_numbers_ids_and_unicode() {
        let fx = fx();
        let long = "a-very-long-security-profile-name-that-goes-on-and-on-for-a-while-0123456789";
        fx.server.set_profiles(
            TSG,
            vec![
                json!({"profile_name": "no-id-inactive", "active": false}),
                json!({"profile_id": fixtures::uuid(10), "profile_name": "no-active-field", "revision": 0}),
                json!({"profile_id": fixtures::uuid(5), "profile_name": long, "revision": 3, "active": true}),
                json!({"profile_id": fixtures::uuid(6), "profile_name": "prøfile-日本語-🚀", "revision": 1, "active": true}),
                json!({"profile_id": fixtures::uuid(31), "profile_name": "frac-rev", "revision": 2.5, "active": true}),
                json!({"profile_id": fixtures::uuid(32), "profile_name": "huge-rev", "revision": 1e21, "active": true}),
                json!({"profile_id": fixtures::uuid(33), "profile_name": "ctl\u{1b}[31mred\ttab\nline", "revision": 1, "active": true}),
            ],
        );
        let out = fx.run(&["runtime", "profiles", "list"]);
        // D56: no ID line for the profile without one; D52: controls replaced.
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Security Profiles:\n\n    no-id-inactive  inactive\n  {}\n    no-active-field  inactive rev:0\n  {}\n    {long}  active rev:3\n  {}\n    prøfile-日本語-🚀  active rev:1\n  {}\n    frac-rev  active rev:2.5\n  {}\n    huge-rev  active rev:1e+21\n  {}\n    ctl\u{fffd}[31mred\u{fffd}tab\u{fffd}line  active rev:1\n\n",
                fixtures::uuid(10),
                fixtures::uuid(5),
                fixtures::uuid(6),
                fixtures::uuid(31),
                fixtures::uuid(32),
                fixtures::uuid(33)
            )
        );
        let ids: Vec<String> = [10, 5, 6, 31, 32, 33].map(fixtures::uuid).to_vec();
        let expected = table(
            &["ID", "Name", "Active", "Revision"],
            &[
                vec!["", "no-id-inactive", "false", ""],
                vec![&ids[0], "no-active-field", "", "0"],
                vec![&ids[1], long, "true", "3"],
                vec![&ids[2], "prøfile-日本語-🚀", "true", "1"],
                vec![&ids[3], "frac-rev", "true", "2.5"],
                vec![&ids[4], "huge-rev", "true", "1e+21"],
                vec![
                    &ids[5],
                    "ctl\u{fffd}[31mred\u{fffd}tab\u{fffd}line",
                    "true",
                    "1",
                ],
            ],
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "list", "--output", "table"]),
            0,
            &expected,
            "  Showing 7\n",
        );
        // JSON keeps the JS number forms and escapes the control characters.
        let json = fx.run(&["runtime", "profiles", "list", "--output", "json"]);
        assert!(
            json.stdout.contains("\"revision\": 1e+21"),
            "{}",
            json.stdout
        );
        assert!(json.stdout.contains("ctl\\u001b[31mred\\ttab\\nline"));
    }

    #[test]
    fn get_detail_in_every_format() {
        let fx = fx();
        fx.server.set_profiles(
            TSG,
            vec![
                fixtures::profile(2, "alpha", 2),
                json!({"profile_name": "sparse", "active": false, "last_modified_ts": "2026-02-01T00:00:00Z"}),
                json!({"profile_id": fixtures::uuid(8), "profile_name": "empty-policy", "revision": 1,
                       "active": true, "policy": {"zz": {"b": 1, "a": [1.0, null]}}}),
            ],
        );
        let detail = format!(
            "{BANNER}\n  Profile Detail:\n\n  ID        {}\n  Name      alpha\n  Status    active\n  Revision  2\n  Created   creator@example.com\n  Updated   updater@example.com\n  Modified  2026-02-01T00:00:00Z\n  Policy    {{\n    \"ai-security-profiles\": [\n      {{\n        \"model-type\": \"default\",\n        \"model-configuration\": {{\n          \"mask-data-in-storage\": false\n        }}\n      }}\n    ],\n    \"dlp-data-profiles\": []\n  }}\n\n",
            fixtures::uuid(2)
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "get", "alpha"]),
            0,
            &detail,
            "",
        );
        let quiet = detail.replacen(&format!("{BANNER}\n  Profile Detail:\n\n"), "", 1);
        assert_out(
            &fx.run(&["runtime", "profiles", "get", "alpha", "--quiet"]),
            0,
            &quiet,
            "",
        );
        let id = fixtures::uuid(2);
        let policy = r#"{"ai-security-profiles":[{"model-type":"default","model-configuration":{"mask-data-in-storage":false}}],"dlp-data-profiles":[]}"#;
        assert_out(
            &fx.run(&["runtime", "profiles", "get", "alpha", "--output", "table"]),
            0,
            &table(
                &["Key", "Value"],
                &[
                    vec!["profileId", &id],
                    vec!["profileName", "alpha"],
                    vec!["revision", "2"],
                    vec!["active", "true"],
                    vec!["createdBy", "creator@example.com"],
                    vec!["updatedBy", "updater@example.com"],
                    vec!["lastModifiedTs", "2026-02-01T00:00:00Z"],
                    vec!["policy", policy],
                ],
            ),
            "",
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "get", "sparse"]),
            0,
            &format!(
                "{BANNER}\n  Profile Detail:\n\n  ID        \n  Name      sparse\n  Status    inactive\n  Modified  2026-02-01T00:00:00Z\n\n"
            ),
            "",
        );
        assert_out(
            &fx.run(&["runtime", "profiles", "get", "sparse", "--output", "table"]),
            0,
            &table(
                &["Key", "Value"],
                &[
                    vec!["profileId", ""],
                    vec!["profileName", "sparse"],
                    vec!["revision", ""],
                    vec!["active", "false"],
                    vec!["createdBy", ""],
                    vec!["updatedBy", ""],
                    vec!["lastModifiedTs", "2026-02-01T00:00:00Z"],
                    vec!["policy", ""],
                ],
            ),
            "",
        );
        // Unknown policy keys sorted (D60), numbers in JS form, in both renderings.
        let pretty = fx.run(&["runtime", "profiles", "get", "empty-policy"]);
        assert!(
            pretty.stdout.contains("  Policy    {\n    \"zz\": {\n      \"a\": [\n        1,\n        null\n      ],\n      \"b\": 1\n    }\n  }\n"),
            "{}",
            pretty.stdout
        );
        let table = fx.run(&[
            "runtime",
            "profiles",
            "get",
            "empty-policy",
            "--output",
            "table",
        ]);
        assert!(
            table
                .stdout
                .contains(r#" policy         │ {"zz":{"a":[1,null],"b":1}} "#),
            "{}",
            table.stdout
        );
    }

    /// D57: a failing read leaves stdout empty in every format.
    #[test]
    fn failures_leave_stdout_empty_in_every_format() {
        let fx = fx();
        fx.server.set_profiles(TSG, alpha_beta());
        for format in [
            &[][..],
            &["--output", "pretty"],
            &["--output", "table"],
            &["--output", "json"],
        ] {
            let out = fx.run(&with(&["runtime", "profiles", "get", "nosuch"], format));
            assert_out(
                &out,
                1,
                "",
                "\n  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: nosuch\n\n",
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// runtime topics list | get
// ---------------------------------------------------------------------------------------

mod topics {
    use super::*;

    #[test]
    fn list_in_every_format_with_description_previews() {
        let fx = fx();
        let eighty = "e".repeat(80);
        let eighty_one = "f".repeat(81);
        let straddle = format!("{}🚀tail", "d".repeat(79));
        fx.server.set_topics(
            TSG,
            vec![
                fixtures::topic(1, "fin", 1, "old"),
                fixtures::topic(2, "fin", 2, "new"),
                fixtures::topic(20, "eighty", 1, &eighty),
                fixtures::topic(21, "eighty-one", 1, &eighty_one),
                fixtures::topic(22, "straddle", 1, &straddle),
                fixtures::topic(23, "no-description", 1, ""),
                json!({"topic_name": "no-id", "revision": 1, "description": "line\none\u{1b}"}),
            ],
        );
        let out = fx.run(&["runtime", "topics", "list"]);
        let f80 = "f".repeat(80);
        let d79 = "d".repeat(79);
        assert_out(
            &out,
            0,
            &format!(
                "{BANNER}\n  Custom Topics:\n\n  {}\n    fin rev:2 — new\n  {}\n    eighty rev:1 — {eighty}\n  {}\n    eighty-one rev:1 — {f80}\n  {}\n    straddle rev:1 — {d79}\n  {}\n    no-description rev:1\n    no-id rev:1 — line\u{fffd}one\u{fffd}\n\n",
                fixtures::uuid(2),
                fixtures::uuid(20),
                fixtures::uuid(21),
                fixtures::uuid(22),
                fixtures::uuid(23)
            ),
            "  Showing 6\n",
        );
        let ids: Vec<String> = [2, 20, 21, 22, 23].map(fixtures::uuid).to_vec();
        assert_out(
            &fx.run(&["runtime", "topics", "list", "--output", "table"]),
            0,
            &table(
                &["ID", "Name", "Revision", "Description"],
                &[
                    vec![&ids[0], "fin", "2", "new"],
                    vec![&ids[1], "eighty", "1", &eighty],
                    vec![&ids[2], "eighty-one", "1", &eighty_one],
                    vec![&ids[3], "straddle", "1", &straddle],
                    vec![&ids[4], "no-description", "1", ""],
                    vec!["", "no-id", "1", "line\u{fffd}one\u{fffd}"],
                ],
            ),
            "  Showing 6\n",
        );
        let json = fx.run(&["runtime", "topics", "list", "--output", "json"]);
        assert_eq!(json.json().as_array().map(Vec::len), Some(6));
        let empty = fx_with(|_| {});
        assert_out(
            &empty.run(&["runtime", "topics", "list"]),
            0,
            &format!("{BANNER}  No topics found\n"),
            "  Showing 0\n",
        );
        assert_out(
            &empty.run(&["runtime", "topics", "list", "--output", "table"]),
            0,
            "",
            "  Showing 0\n",
        );
        assert_out(
            &empty.run(&["runtime", "topics", "list", "--output", "table", "--quiet"]),
            0,
            "",
            "",
        );
    }

    #[test]
    fn get_detail_in_every_format() {
        let fx = fx();
        fx.server.set_topics(
            TSG,
            vec![
                json!({"topic_id": fixtures::uuid(21), "topic_name": "many", "revision": 3, "active": true,
                       "description": "Has several examples",
                       "examples": ["first", "multi\nline", "ünïcödé 日本 🚀"],
                       "created_by": "creator@example.com", "updated_by": "updater@example.com",
                       "last_modified_ts": "2026-02-01T00:00:00Z", "created_ts": "2026-01-01T00:00:00Z"}),
                json!({"topic_id": fixtures::uuid(22), "topic_name": "bare", "revision": 1, "description": ""}),
            ],
        );
        let id = fixtures::uuid(21);
        assert_out(
            &fx.run(&["runtime", "topics", "get", "many"]),
            0,
            &format!(
                "{BANNER}\n  Topic Detail:\n\n  ID           {id}\n  Name         many\n  Revision     3\n  Description  Has several examples\n  Examples:\n  • first\n  • multi\u{fffd}line\n  • ünïcödé 日本 🚀\n  Created   creator@example.com\n  Updated   updater@example.com\n  Modified  2026-02-01T00:00:00Z\n\n"
            ),
            "",
        );
        assert_out(
            &fx.run(&["runtime", "topics", "get", "bare", "--quiet"]),
            0,
            &format!(
                "  ID        {}\n  Name      bare\n  Revision  1\n\n",
                fixtures::uuid(22)
            ),
            "",
        );
        assert_out(
            &fx.run(&["runtime", "topics", "get", "many", "--output", "table"]),
            0,
            &table(
                &["Key", "Value"],
                &[
                    vec!["topicId", &id],
                    vec!["topicName", "many"],
                    vec!["revision", "3"],
                    vec!["active", "true"],
                    vec!["description", "Has several examples"],
                    vec!["examples", r#"["first","multi\nline","ünïcödé 日本 🚀"]"#],
                    vec!["createdBy", "creator@example.com"],
                    vec!["updatedBy", "updater@example.com"],
                    vec!["lastModifiedTs", "2026-02-01T00:00:00Z"],
                    vec!["createdTs", "2026-01-01T00:00:00Z"],
                ],
            ),
            "",
        );
        let bare = fx.run(&["runtime", "topics", "get", "bare", "--output", "table"]);
        assert!(
            bare.stdout.contains(" examples       │ [] "),
            "{}",
            bare.stdout
        );
        assert!(bare.stdout.contains(" active         │ "));
        let json = fx.run(&["runtime", "topics", "get", "bare", "--output", "json"]);
        assert_eq!(json.json()["examples"], json!([]));
    }

    #[test]
    fn tenant_default_output_selects_the_format() {
        for (value, starts) in [
            ("table", " ID "),
            ("json", "["),
            ("pretty", "\n  Prisma AIRS"),
        ] {
            let fx = fx_with(|config| {
                config.set("defaultOutput", value);
            });
            fx.server
                .set_topics(TSG, vec![fixtures::topic(1, "fin", 1, "old")]);
            let out = fx.run(&["runtime", "topics", "list"]);
            assert_eq!((out.code, out.stderr.as_str()), (0, "  Showing 1\n"));
            assert!(out.stdout.starts_with(starts), "{value}: {}", out.stdout);
            let explicit = fx.run(&["runtime", "topics", "list", "--output", "pretty"]);
            assert!(
                explicit.stdout.starts_with("\n  Prisma AIRS"),
                "--output wins"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// runtime scan
// ---------------------------------------------------------------------------------------

mod scan {
    use super::*;

    const ARGS: &[&str] = &["runtime", "scan", "--profile", "p", "hello"];
    const STATUS: &str = "  Prisma AIRS Runtime Scan\n  Profile: p\n  Prompt:  \"hello\"\n";

    #[test]
    fn table_is_the_record_without_result() {
        let fx = fx();
        let out = fx.run(&with(ARGS, &["--output", "table"]));
        assert_eq!((out.code, out.stderr.as_str()), (0, STATUS));
        let rows: Vec<Vec<String>> = out
            .stdout
            .lines()
            .filter(|line| line.contains('│'))
            .map(|line| line.split('│').map(|cell| cell.trim().to_owned()).collect())
            .collect();
        let keys: Vec<&str> = rows.iter().map(|row| row[0].as_str()).collect();
        assert_eq!(
            keys,
            [
                "Key",
                "profileName",
                "scanId",
                "reportId",
                "action",
                "category",
                "triggered",
                "detections",
                "responseDetections"
            ]
        );
        assert_eq!(rows[4][1], "allow");
        assert_eq!(rows[6][1], "false");
        assert!(rows[7][1].starts_with(r#"{"topic_violation":false,"injection":false"#));
        assert_eq!(
            fx.run(&with(ARGS, &["--output", "table", "--quiet"]))
                .stdout,
            out.stdout
        );
    }

    #[test]
    fn failed_scan_table_ends_with_the_error_row_and_exits_1() {
        let fx = fx();
        fx.server.set_default(
            airs_test_harness::Route::ScanSync,
            airs_test_harness::Planned::json(
                200,
                &json!({"report_id": "R1", "scan_id": "S1", "category": "benign", "action": "allow",
                        "timeout": true, "error": false, "errors": []}),
            ),
        );
        let out = fx.run(&with(ARGS, &["--output", "table"]));
        assert_eq!(out.code, 1);
        let last = out.stdout.lines().last().unwrap_or_default();
        assert!(
            last.starts_with(" error ") && last.contains("│ AIRS scan timed out"),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains(" category           │ error "));
        assert_eq!(
            out.stderr,
            format!("{STATUS}\n  ✗ Error: AIRS scan did not complete: AIRS scan timed out\n\n")
        );
    }

    #[test]
    fn pretty_colours() {
        let fx = fx();
        let out = fx.coloured(ARGS);
        assert_eq!(out.code, 0);
        assert_eq!(
            out.stdout,
            "\n  \u{1b}[1mScan Result\u{1b}[22m\n\n  \u{1b}[2mAction   \u{1b}[22m  \u{1b}[32mALLOW\u{1b}[39m\n  \u{1b}[2mCategory \u{1b}[22m  benign\n  \u{1b}[2mTriggered\u{1b}[22m  \u{1b}[32mno\u{1b}[39m\n  \u{1b}[2mScan ID  \u{1b}[22m  \u{1b}[2m00000000-0000-4000-8000-0000000000a1\u{1b}[22m\n  \u{1b}[2mReport ID\u{1b}[22m  \u{1b}[2mR00000000-0000-4000-8000-0000000000a1\u{1b}[22m\n"
        );
        assert_eq!(
            out.stderr,
            "  \u{1b}[2mPrisma AIRS Runtime Scan\u{1b}[22m\n  \u{1b}[2mProfile: p\u{1b}[22m\n  \u{1b}[2mPrompt:  \"hello\"\u{1b}[22m\n"
        );
        let table = fx.coloured(&with(ARGS, &["--output", "table"]));
        assert!(!table.stdout.contains(ESC));
        let json = fx.coloured(&with(ARGS, &["--output", "json"]));
        assert!(!json.stdout.contains(ESC));
        assert!(
            json.stderr.contains(ESC),
            "status lines stay dim in every format"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Colour decision (§2.8, D58) and the dropped formats (D50)
// ---------------------------------------------------------------------------------------

mod colour {
    use super::*;

    fn ansi(out: &Run) -> (bool, bool) {
        (out.stdout.contains(ESC), out.stderr.contains(ESC))
    }

    #[test]
    fn environment_rules() {
        let fx = fx();
        fx.server
            .set_profiles(TSG, vec![fixtures::profile(1, "alpha", 1)]);
        let args = ["runtime", "profiles", "list"];
        let base = || RunOptions::new().without_env("NO_COLOR");
        for (options, expected, label) in [
            (RunOptions::new(), (false, false), "harness NO_COLOR=1"),
            (base(), (false, false), "a pipe is not a terminal"),
            (
                base().env("TERM", "xterm-256color").env("CI", "1"),
                (false, false),
                "TERM and CI need a terminal",
            ),
            (
                base().env("FORCE_COLOR", "1"),
                (false, false),
                "FORCE_COLOR is not read",
            ),
            (
                base().env("CLICOLOR_FORCE", "1"),
                (true, true),
                "CLICOLOR_FORCE forces both streams",
            ),
            (
                base().env("CLICOLOR_FORCE", "0"),
                (true, true),
                "any non-empty value forces",
            ),
            (
                base().env("CLICOLOR_FORCE", ""),
                (false, false),
                "an empty value does not",
            ),
            (
                base().env("CLICOLOR_FORCE", "1").env("CLICOLOR", "0"),
                (true, true),
                "force wins over CLICOLOR=0",
            ),
            (
                RunOptions::new().env("CLICOLOR_FORCE", "1"),
                (false, false),
                "NO_COLOR wins over CLICOLOR_FORCE",
            ),
            (
                base().env("NO_COLOR", "").env("CLICOLOR_FORCE", "1"),
                (true, true),
                "an empty NO_COLOR is unset",
            ),
        ] {
            let out = fx.run_with(&args, options);
            assert_eq!(out.code, 0);
            assert_eq!(ansi(&out), expected, "{label}");
        }
    }

    #[test]
    fn never_coloured_outputs() {
        let fx = fx();
        fx.server
            .set_profiles(TSG, vec![fixtures::profile(1, "alpha", 1)]);
        for args in [
            &["runtime", "profiles", "list", "--output", "table"][..],
            &["runtime", "profiles", "list", "--output", "json"],
            &["runtime", "profiles", "get", "alpha", "--output", "table"],
            &["tenant", "get", "prod", "mgmtTsgId"],
            &["tenant", "path"],
            &["tenant", "read", "--output", "table"],
            &["doctor", "--output", "json"],
            &["--version"],
        ] {
            let out = fx.coloured(args);
            assert_eq!(out.code, 0, "{args:?}");
            assert!(!out.stdout.contains(ESC), "{args:?}: {}", out.stdout);
        }
    }

    #[test]
    fn error_blocks_are_red() {
        let fx = fx();
        let out = fx.coloured(&["runtime", "profiles", "list", "--output", "xml"]);
        assert_out(
            &out,
            2,
            "",
            "\u{1b}[31m\u{1b}[39m\n\u{1b}[31m  ✗ Invalid output format 'xml'. Expected: pretty, table, json\u{1b}[39m\n\u{1b}[31m\u{1b}[39m\n",
        );
        fx.server.set_default(
            airs_test_harness::Route::Profiles,
            airs_test_harness::Planned::json(404, &json!({})),
        );
        let out = fx.coloured(&["runtime", "profiles", "list"]);
        assert_eq!(out.code, 1);
        assert_eq!(out.stdout, "");
        assert!(
            out.stderr
                .starts_with("\u{1b}[31m\u{1b}[39m\n\u{1b}[31m  ✗ Error: AISEC_"),
            "{:?}",
            out.stderr
        );
        assert!(
            out.stderr.contains("\u{1b}[31m    HTTP 404\u{1b}[39m\n\u{1b}[2m    Re-run with --debug to capture redacted API diagnostics.\u{1b}[22m\n"),
            "the hint is dim: {:?}",
            out.stderr
        );
        assert!(out.stderr.ends_with("\u{1b}[22m\n\n"));
    }

    /// D50: every command that renders data rejects the dropped names before the
    /// tenant is read (no tenant needed, no request).
    #[test]
    fn dropped_formats_are_usage_errors_everywhere() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        for format in ["markdown", "csv", "yaml"] {
            for args in [
                &["tenant", "list"][..],
                &["tenant", "read"],
                &["tenant", "get", "prod", "mgmtTsgId"],
                &["tenant", "path"],
                &["doctor"],
                &["runtime", "scan", "--profile", "p", "hi"],
                &["runtime", "profiles", "list"],
                &["runtime", "profiles", "get", "x"],
                &["runtime", "topics", "list"],
                &["runtime", "topics", "get", "x"],
            ] {
                let out = run(
                    &rust(),
                    &sandbox,
                    &with(args, &["--output", format]),
                    &RunOptions::new(),
                );
                assert_out(
                    &out,
                    2,
                    "",
                    &usage(&format!(
                        "Invalid output format '{format}'. Expected: pretty, table, json"
                    )),
                );
            }
        }
        assert_eq!(server.request_count(), 0);
    }
}
