//! TS-vs-Rust parity for tenant loading and the read-only tenant commands (DESIGN §3,
//! §3.6, §4) plus divergence pins for the §12 differences in this area (D2, D4, D8,
//! D27, D28, D33, D34, D44, D45).
//!
//! Every scenario runs on a fresh fixture server + sandbox per CLI. Outputs are compared
//! after replacing the sandbox root with `<ROOT>` and the server base URL with `<BASE>`;
//! request logs are compared in normalised form. A missing or unverified TypeScript
//! reference fails the tests (`AIRS_ALLOW_PARITY_SKIP=1` skips them with a notice).

use std::fs;
use std::path::Path;

use airs_test_harness::{
    AuthIdentity, Cli, FixtureConfig, FixtureServer, NormalizedRequest, RecordedRequest,
    RegistryEntry, Route, Run, RunOptions, Sandbox, assert_json_semantic_eq, fixtures,
    normalise_tenant_output, normalize_all, registry_json, require_ts, run, ts_rows_as_rust,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------
// Harness glue
// ---------------------------------------------------------------------------------------

const LIST: &[&str] = &["runtime", "profiles", "list", "--output", "json"];
const SCAN: &[&str] = &[
    "runtime",
    "scan",
    "--profile",
    "fixture-profile",
    "hello world",
];

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// One fresh server + sandbox.
struct Env {
    server: FixtureServer,
    sandbox: Sandbox,
    /// Whether this environment is for the airs-cli-rs run (setups that build a
    /// Rust-only store state check it).
    rust: bool,
}

/// The outcome of one CLI on its own `Env`, with environment-specific text normalised.
struct Side {
    cli: &'static str,
    code: i32,
    /// stdout and stderr after [`normalise_tenant_output`] (each side's own paths as
    /// `<REGISTRY>` / `<CONFIG:name>`, `airs` in hints as `airs-cli`), then the
    /// sandbox root as `<ROOT>` and the server as `<BASE>`.
    stdout: String,
    stderr: String,
    /// stderr with only `<ROOT>` and `<BASE>` replaced (for the D70/D73 pins).
    raw_stderr: String,
    requests: Vec<NormalizedRequest>,
    raw: Vec<RecordedRequest>,
}

impl std::fmt::Debug for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Side")
            .field("cli", &self.cli)
            .field("code", &self.code)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field(
                "requests",
                &self
                    .raw
                    .iter()
                    .map(RecordedRequest::line)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Side {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|err| {
            panic!("{}: stdout is not JSON ({err}): {}", self.cli, self.stdout)
        })
    }
    fn routes(&self) -> Vec<Route> {
        self.raw.iter().map(|r| r.route).collect()
    }
}

type Setup<'a> = &'a dyn Fn(&Env);
type Options<'a> = &'a dyn Fn(&Env) -> RunOptions;

fn no_options(_: &Env) -> RunOptions {
    RunOptions::new()
}

fn exec(cli: &Cli, setup: Setup<'_>, args: &[&str], options: Options<'_>) -> Side {
    let env = Env {
        server: FixtureServer::start(),
        sandbox: Sandbox::new(),
        rust: !cli.is_ts(),
    };
    setup(&env);
    let options = options(&env);
    let before = env.sandbox.snapshot();
    let home = env.sandbox.home_listing();
    let cwd = env.sandbox.cwd_listing();
    let out: Run = run(cli, &env.sandbox, args, &options);
    env.sandbox.assert_unchanged(&before);
    assert_eq!(
        env.sandbox.home_listing(),
        home,
        "{} changed HOME",
        cli.label()
    );
    assert_eq!(
        env.sandbox.cwd_listing(),
        cwd,
        "{} changed cwd",
        cli.label()
    );
    env.server.assert_no_unknown_routes();
    let root = env.sandbox.root().display().to_string();
    let base = env.server.base_url();
    let plain = |text: &str| text.replace(&root, "<ROOT>").replace(&base, "<BASE>");
    let clean = |text: &str| plain(&normalise_tenant_output(text, &env.sandbox));
    let raw = env.server.requests();
    Side {
        cli: out.cli,
        code: out.code,
        stdout: clean(&out.stdout),
        stderr: clean(&out.stderr),
        raw_stderr: plain(&out.stderr),
        requests: normalize_all(&raw),
        raw,
    }
}

/// Runs the scenario against both CLIs, or `None` (PARITY SKIPPED) without the reference.
fn pair(test: &str, setup: Setup<'_>, args: &[&str], options: Options<'_>) -> Option<(Side, Side)> {
    let ts = require_ts(test)?;
    Some((
        exec(&rust(), setup, args, options),
        exec(&ts, setup, args, options),
    ))
}

/// Same exit code, byte-identical stdout and stderr, identical normalised requests.
fn assert_same(rust: &Side, ts: &Side) {
    assert_eq!(
        rust.code, ts.code,
        "exit codes differ\nrust: {rust:?}\nts: {ts:?}"
    );
    assert_eq!(
        rust.stdout, ts.stdout,
        "stdout differs\nrust: {rust:?}\nts: {ts:?}"
    );
    assert_eq!(
        rust.stderr, ts.stderr,
        "stderr differs\nrust: {rust:?}\nts: {ts:?}"
    );
    assert_same_requests(rust, ts);
}

/// Like [`assert_same`] for `tenant read` / `tenant get` JSON: the TypeScript rows are
/// mapped through the import conversion first (renamed keys renamed; `dataDir`,
/// `typesafe*` and, for `tenant read`, `""` rows dropped: D71, D72), then the JSON must
/// be equal; stderr and the exit code byte for byte.
fn assert_same_rows(rust: &Side, ts: &Side, get: bool) {
    assert_eq!(
        rust.code, ts.code,
        "exit codes differ\nrust: {rust:?}\nts: {ts:?}"
    );
    assert_eq!(
        rust.json(),
        ts_rows_as_rust(&ts.json(), get),
        "rows differ\nrust: {rust:?}\nts: {ts:?}"
    );
    assert_eq!(
        rust.stderr, ts.stderr,
        "stderr differs\nrust: {rust:?}\nts: {ts:?}"
    );
    assert_same_requests(rust, ts);
}

/// Requests agree on method, path, query order, body and client identity, and on every
/// non-transport, non-credential header.
fn assert_same_requests(rust: &Side, ts: &Side) {
    assert_eq!(
        rust.requests.len(),
        ts.requests.len(),
        "request counts differ\nrust: {rust:?}\nts: {ts:?}"
    );
    for (r, t) in rust.requests.iter().zip(&ts.requests) {
        assert_eq!(
            (&r.method, &r.path, &r.route, &r.query, &r.body, &r.auth),
            (&t.method, &t.path, &t.route, &t.query, &t.body, &t.auth),
            "request differs"
        );
        assert_eq!(
            r.headers, t.headers,
            "headers differ for {} {}",
            r.method, r.path
        );
    }
}

fn assert_zero_requests(side: &Side) {
    assert!(
        side.raw.is_empty(),
        "{}: unexpected requests {side:?}",
        side.cli
    );
}

fn op_error(msg: &str) -> String {
    format!("\n  ✗ Error: {msg}\n\n")
}

fn prod(env: &Env) {
    env.sandbox.single_tenant(&env.server, "prod", "100");
    env.server
        .set_profiles("100", vec![fixtures::profile(1, "alpha", 1)]);
}

fn prod_with(edit: impl Fn(&mut FixtureConfig)) -> impl Fn(&Env) {
    move |env: &Env| {
        let tenant = env
            .sandbox
            .add_fixture_tenant_with(&env.server, "prod", "100", &edit);
        env.sandbox.register(&[&tenant], Some("prod"));
        env.server
            .set_profiles("100", vec![fixtures::profile(1, "alpha", 1)]);
    }
}

/// prod (100) and dev (200), registered in that order with `active`.
fn two(active: Option<&'static str>) -> impl Fn(&Env) {
    move |env: &Env| {
        let prod = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
        let dev = env.sandbox.add_fixture_tenant(&env.server, "dev", "200");
        // Byte order of the names, so both CLIs list them alike (D86 is pinned apart).
        env.sandbox.register(&[&dev, &prod], active);
        env.server
            .set_profiles("100", vec![fixtures::profile(1, "alpha", 1)]);
        env.server
            .set_profiles("200", vec![fixtures::profile(2, "beta", 1)]);
    }
}

fn entry_text(name: &str, path: &Path, tsg: &str) -> String {
    format!(
        r#"{{"name":{},"configPath":{},"tsgId":{}}}"#,
        Value::String(name.into()),
        Value::String(path.display().to_string()),
        Value::String(tsg.into())
    )
}

// ---------------------------------------------------------------------------------------
// tenant list | ls
// ---------------------------------------------------------------------------------------
mod tenant_list {
    use super::*;

    #[test]
    fn json_single_active_tenant() {
        for args in [
            &["tenant", "list", "--output", "json"][..],
            &["tenant", "ls", "--output", "json"][..],
            &["--output", "yaml", "tenant", "list", "--output", "json"][..],
        ] {
            let Some((r, t)) = pair("tenant_list_json_single", &prod, args, &no_options) else {
                return;
            };
            assert_same(&r, &t);
            assert_eq!(r.code, 0);
            assert_eq!(
                r.stdout,
                "[\n  {\n    \"name\": \"prod\",\n    \"configPath\": \"<CONFIG:prod>\",\n    \"tsgId\": \"100\",\n    \"active\": true\n  }\n]\n"
            );
            assert_zero_requests(&r);
            assert_zero_requests(&t);
        }
    }

    #[test]
    fn json_two_tenants_with_and_without_active() {
        for active in [Some("dev"), None] {
            for quiet in [false, true] {
                let mut args = vec!["tenant", "list", "--output", "json"];
                if quiet {
                    args.push("--quiet");
                }
                let Some((r, t)) = pair("tenant_list_two", &two(active), &args, &no_options) else {
                    return;
                };
                assert_same(&r, &t);
                let expected_status = if active.is_none() && !quiet {
                    "  No tenant selected; run 'airs-cli tenant switch <name>'.\n"
                } else {
                    ""
                };
                assert_eq!(r.stderr, expected_status);
            }
        }
    }

    #[test]
    fn json_empty_and_missing_registry() {
        let empty = |env: &Env| env.sandbox.write_registry(&[], None);
        let missing = |_: &Env| {};
        let missing_dir_options = |env: &Env| {
            RunOptions::new().env(
                "PRISMA_AIRS_TENANTS_PATH",
                env.sandbox
                    .root()
                    .join("nope/x/tenants.json")
                    .display()
                    .to_string(),
            )
        };
        for (setup, options) in [
            (&empty as Setup<'_>, &no_options as Options<'_>),
            (&missing, &no_options),
            (&missing, &missing_dir_options),
        ] {
            let Some((r, t)) = pair(
                "tenant_list_empty",
                setup,
                &["tenant", "list", "--output", "json"],
                options,
            ) else {
                return;
            };
            assert_same(&r, &t);
            assert_eq!(
                (r.code, r.stdout.as_str(), r.stderr.as_str()),
                (0, "[]\n", "")
            );
        }
    }

    #[test]
    fn never_opens_config_files() {
        let setup = |env: &Env| {
            let invalid = env.sandbox.write_config_raw("invalid", b"{oops");
            let missing = env.sandbox.configs_dir().join("missing.json");
            env.sandbox.write_registry(
                &[
                    RegistryEntry::new("invalid", &invalid, "1"),
                    RegistryEntry::new("missing", &missing, "2"),
                ],
                Some("invalid"),
            );
        };
        let Some((r, t)) = pair(
            "tenant_list_no_config",
            &setup,
            &["tenant", "list", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        assert_same(&r, &t);
        assert_eq!(r.code, 0);
    }

    #[test]
    fn invalid_output_is_a_usage_error_even_with_a_corrupt_registry() {
        let setup = |env: &Env| env.sandbox.write_registry_raw(b"not json");
        for args in [
            &["tenant", "list", "--output", "xml"][..],
            &["tenant", "read", "--output", "xml"][..],
            &["tenant", "get", "prod", "mgmtTsgId", "--output", "xml"][..],
        ] {
            let Some((r, t)) = pair("tenant_invalid_output", &setup, args, &no_options) else {
                return;
            };
            // Both exit 2 before the registry is read; the name lists differ (D50).
            assert_eq!(
                (r.code, r.stderr.as_str()),
                (
                    2,
                    "\n  ✗ Invalid output format 'xml'. Expected: pretty, table, json\n\n"
                )
            );
            assert_eq!(
                (t.code, t.stderr.as_str()),
                (
                    2,
                    "\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n"
                )
            );
            assert!(r.stdout.is_empty() && t.stdout.is_empty());
        }
    }
}

// ---------------------------------------------------------------------------------------
// tenant read / get / path
// ---------------------------------------------------------------------------------------
mod tenant_read_get_path {
    use super::*;

    #[test]
    fn read_json_standard_config() {
        for args in [
            &["tenant", "read", "--output", "json"][..],
            &["tenant", "read", "prod", "--output", "json"][..],
            &["tenant", "read", "--output", "json", "--quiet"][..],
        ] {
            let Some((r, t)) = pair("tenant_read_standard", &prod, args, &no_options) else {
                return;
            };
            assert_same_rows(&r, &t, false);
            assert_eq!(r.code, 0);
            assert_zero_requests(&r);
        }
    }

    #[test]
    fn read_json_coercion_empty_values_and_hidden_keys() {
        let setup = prod_with(|config| {
            config
                .set("airsApiToken", "")
                .set("aiGwInferenceApiKey", "FAKE-INFERENCE-KEY")
                .set("typesafeApiKey", "  ")
                .set("typesafeModel", "")
                .set("scanConcurrency", "3")
                .set("defaultOutput", "table")
                .set("dataDir", "~/runs")
                .set("custom", json!({"nested": true}))
                .set("redTeamTokenEndpoint", "hidden");
        });
        let Some((r, t)) = pair(
            "tenant_read_coercion",
            &setup,
            &["tenant", "read", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        assert_same_rows(&r, &t, false);
        assert_eq!(r.code, 0);
    }

    #[test]
    fn read_minimal_config() {
        // Minimal apart from the endpoint keys, which the harness guard requires on
        // loopback for every config the TS CLI may load.
        let setup = |env: &Env| {
            let mut config = Sandbox::fixture_config(&env.server, "100")
                .without("airsApiKey")
                .without("airsNumRetries");
            config.set("mgmtClientSecret", "X-SECRET-VALUE");
            let path = env.sandbox.write_fixture_config("mini", &config);
            env.sandbox
                .write_registry(&[RegistryEntry::new("mini", &path, "100")], Some("mini"));
        };
        let Some((r, t)) = pair(
            "tenant_read_minimal",
            &setup,
            &["tenant", "read", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        assert_same_rows(&r, &t, false);
        assert_eq!(r.stderr, "  Tenant mini (TSG 100): <CONFIG:mini>\n");
    }

    #[test]
    fn js_coercion_forms_agree() {
        let cases: &[(&str, Value)] = &[
            ("scanConcurrency", json!("3")),
            ("scanConcurrency", json!(" 7 ")),
            ("scanConcurrency", json!(true)),
            ("scanConcurrency", json!("0x5")),
            ("scanConcurrency", json!("0b11")),
            ("scanConcurrency", json!("0o7")),
            ("scanConcurrency", json!("1e1")),
            ("scanConcurrency", json!([4])),
            ("scanConcurrency", json!([[2]])),
            ("scanConcurrency", json!(2.0)),
            ("airsNumRetries", Value::Null),
            // `""` is not here: TS `get` shows `Number("")` = 0, but import drops the
            // empty value (D72), so the Rust tenant has no airsNumRetries.
            ("airsNumRetries", json!(false)),
            ("airsNumRetries", json!([])),
            ("airsNumRetries", json!([null])),
            ("airsNumRetries", json!("5")),
        ];
        for (key, value) in cases {
            let setup = prod_with(|config| {
                config.set(key, value.clone());
            });
            for args in [
                vec!["tenant", "get", "prod", key],
                vec!["tenant", "get", "prod", key, "--output", "json"],
            ] {
                let Some((r, t)) = pair("tenant_coercion", &setup, &args, &no_options) else {
                    return;
                };
                if args.len() > 4 {
                    assert_same_rows(&r, &t, true);
                } else {
                    assert_same(&r, &t);
                }
                assert_eq!(r.code, 0, "{key} = {value}");
            }
        }
    }

    #[test]
    fn get_pretty_and_json_values() {
        let setup = prod_with(|config| {
            config.set("airsApiToken", "");
        });
        // Keys both CLIs name alike (the renamed and dropped ones are D71).
        for key in [
            "mgmtTsgId",
            "mgmtClientId",
            "mgmtClientSecret",
            "airsApiKey",
            "airsApiToken",
            "airsNumRetries",
            "scanConcurrency",
            "defaultOutput",
            "iamEndpoint",
            "mgmtEndpoint",
        ] {
            for args in [
                vec!["tenant", "get", "prod", key],
                vec!["tenant", "get", "prod", key, "--output", "pretty"],
                vec!["tenant", "get", "prod", key, "--output", "json"],
            ] {
                let Some((r, t)) = pair("tenant_get_values", &setup, &args, &no_options) else {
                    return;
                };
                if args.len() > 4 && args[5] == "json" {
                    assert_same_rows(&r, &t, true);
                } else {
                    assert_same(&r, &t);
                }
                assert_eq!(r.code, 0, "{args:?}");
            }
        }
    }

    #[test]
    fn get_unknown_tenant_and_name_case() {
        for args in [
            &["tenant", "get", "ghost", "mgmtTsgId"][..],
            &["tenant", "get", "PROD", "mgmtTsgId"][..],
        ] {
            let Some((r, t)) = pair("tenant_get_unknown_tenant", &prod, args, &no_options) else {
                return;
            };
            assert_same(&r, &t);
            assert_eq!(r.stderr, op_error("Tenant not found"));
        }
    }

    #[test]
    fn path_outputs() {
        let missing_config = |env: &Env| {
            let missing = env.sandbox.configs_dir().join("missing.json");
            env.sandbox
                .write_registry(&[RegistryEntry::new("gone", &missing, "1")], Some("gone"));
        };
        let dev_active = two(Some("dev"));
        for (setup, args) in [
            (&prod as Setup<'_>, &["tenant", "path"][..]),
            (&dev_active, &["tenant", "path"][..]),
            (&dev_active, &["tenant", "path", "prod"][..]),
            (&prod, &["tenant", "path", "--output", "table"][..]),
            (&prod, &["--output", "json", "tenant", "path"][..]),
            (&missing_config, &["tenant", "path"][..]),
        ] {
            let Some((r, t)) = pair("tenant_path", setup, args, &no_options) else {
                return;
            };
            assert_same(&r, &t);
            assert_eq!(r.code, 0, "{args:?}");
        }
    }

    #[test]
    fn name_resolution_errors_for_read_and_path() {
        let none_active = two(None);
        let empty = |env: &Env| env.sandbox.write_registry(&[], None);
        let cases: [(Setup<'_>, &[&str], &str); 6] = [
            (
                &none_active,
                &["tenant", "read", "--output", "json"],
                "No tenant selected; pass a name or run 'airs-cli tenant switch <name>' (registered: dev, prod)",
            ),
            (
                &none_active,
                &["tenant", "path"],
                "No tenant selected; pass a name or run 'airs-cli tenant switch <name>' (registered: dev, prod)",
            ),
            (
                &none_active,
                &["tenant", "read", "ghost", "--output", "json"],
                "Tenant not found",
            ),
            (
                &none_active,
                &["tenant", "path", "ghost"],
                "Tenant not found",
            ),
            (
                &empty,
                &["tenant", "read", "--output", "json"],
                "No tenant selected; run 'airs-cli tenant create <name>' first",
            ),
            (
                &empty,
                &["tenant", "path"],
                "No tenant selected; run 'airs-cli tenant create <name>' first",
            ),
        ];
        for (setup, args, msg) in cases {
            let Some((r, t)) = pair("tenant_name_resolution", setup, args, &no_options) else {
                return;
            };
            assert_same(&r, &t);
            assert_eq!((r.code, r.stderr.clone()), (1, op_error(msg)), "{args:?}");
        }
    }
}

// ---------------------------------------------------------------------------------------
// Shared error messages (zero requests on both sides)
// ---------------------------------------------------------------------------------------
mod shared_errors {
    use super::*;

    fn same_error(test: &str, setup: Setup<'_>, args: &[&str], options: Options<'_>, msg: &str) {
        let Some((r, t)) = pair(test, setup, args, options) else {
            return;
        };
        assert_same(&r, &t);
        assert_eq!(
            (r.code, r.stdout.as_str(), r.stderr.clone()),
            (1, "", op_error(msg)),
            "{args:?}"
        );
        assert_zero_requests(&r);
        assert_zero_requests(&t);
    }

    #[test]
    fn no_tenant_selected() {
        let empty = |env: &Env| env.sandbox.write_registry(&[], None);
        let missing = |_: &Env| {};
        let none_active = two(None);
        let none = "No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'";
        let registered =
            "No tenant selected. Run 'airs-cli tenant switch <name>' (registered: dev, prod)";
        for args in [
            LIST,
            SCAN,
            &["runtime", "topics", "list", "--output", "json"][..],
        ] {
            same_error("no_tenant_empty", &empty, args, &no_options, none);
            same_error("no_tenant_missing", &missing, args, &no_options, none);
            same_error(
                "no_tenant_registered",
                &none_active,
                args,
                &no_options,
                registered,
            );
        }
    }

    /// Registry documents both CLIs reject (D27's invalid UTF-8 is pinned separately).
    fn corrupt_registries(env: &Env) -> Vec<(&'static str, Vec<u8>)> {
        let config = env.sandbox.config_path("prod");
        let ok = entry_text("prod", &config, "100");
        let path = Value::String(config.display().to_string());
        let with_entry = |fields: String| {
            format!(r#"{{"version":1,"active":null,"tenants":[{{{fields}}}]}}"#).into_bytes()
        };
        let mut oversize =
            registry_json(&[RegistryEntry::new("prod", &config, "100")], Some("prod"));
        oversize.push_str(&" ".repeat(1_048_577 - oversize.len()));
        let thousand_and_one: Vec<String> = (0..1001)
            .map(|i| entry_text(&format!("t{i}"), Path::new("/c/t.json"), "1"))
            .collect();
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend_from_slice(ok.as_bytes());
        vec![
            ("invalid JSON", br#"{"version":1,"#.to_vec()),
            ("0-byte", Vec::new()),
            ("oversize", oversize.into_bytes()),
            ("null", b"null".to_vec()),
            (
                "version 2",
                format!(r#"{{"version":2,"active":null,"tenants":[{ok}]}}"#).into_bytes(),
            ),
            (
                "missing active",
                format!(r#"{{"version":1,"tenants":[{ok}]}}"#).into_bytes(),
            ),
            (
                "unknown top-level key",
                format!(r#"{{"version":1,"active":null,"tenants":[{ok}],"x":1}}"#).into_bytes(),
            ),
            (
                "unknown entry key",
                with_entry(format!(
                    r#""name":"prod","configPath":{path},"tsgId":"100","x":1"#
                )),
            ),
            (
                "active unregistered",
                format!(r#"{{"version":1,"active":"ghost","tenants":[{ok}]}}"#).into_bytes(),
            ),
            (
                "duplicate names",
                format!(r#"{{"version":1,"active":null,"tenants":[{ok},{ok}]}}"#).into_bytes(),
            ),
            (
                "relative configPath",
                with_entry(
                    r#""name":"prod","configPath":"configs/prod.json","tsgId":"100""#.into(),
                ),
            ),
            (
                "empty tsgId",
                with_entry(format!(r#""name":"prod","configPath":{path},"tsgId":"""#)),
            ),
            (
                "numeric tsgId",
                with_entry(format!(r#""name":"prod","configPath":{path},"tsgId":100"#)),
            ),
            (
                "bad name",
                with_entry(format!(
                    r#""name":"-bad","configPath":{path},"tsgId":"100""#
                )),
            ),
            (
                "65-char name",
                with_entry(format!(
                    r#""name":"{}","configPath":{path},"tsgId":"100""#,
                    "x".repeat(65)
                )),
            ),
            (
                "1001 entries",
                format!(
                    r#"{{"version":1,"active":null,"tenants":[{}]}}"#,
                    thousand_and_one.join(",")
                )
                .into_bytes(),
            ),
            ("BOM", bom),
        ]
    }

    #[test]
    fn corrupt_registry() {
        let count = 17;
        for index in 0..count {
            let setup = move |env: &Env| {
                env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
                let cases = corrupt_registries(env);
                assert_eq!(cases.len(), count);
                env.sandbox.write_registry_raw(&cases[index].1);
            };
            for args in [
                LIST,
                &["tenant", "list", "--output", "json"][..],
                &["tenant", "path"][..],
            ] {
                same_error(
                    "corrupt_registry",
                    &setup,
                    args,
                    &no_options,
                    "Cannot read tenant registry at <REGISTRY>; restore a valid registry before proceeding",
                );
            }
        }
    }

    #[test]
    fn registry_that_is_a_symlink_or_directory() {
        // D79: TS gives its generic registry message for a symlinked or directory
        // registry; airs-cli-rs refuses a symlinked or non-regular config.toml with the
        // safety message.
        let link = |env: &Env| {
            let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
            if env.rust {
                env.sandbox.single_tenant(&env.server, "prod", "100");
                let real = env.sandbox.tmp().join("real.toml");
                fs::copy(env.sandbox.store_index_path(), &real).expect("copy");
                env.sandbox.detach_store();
                fs::remove_file(env.sandbox.store_index_path()).expect("remove");
                std::os::unix::fs::symlink(&real, env.sandbox.store_index_path()).expect("symlink");
                return;
            }
            let real = env.sandbox.state_dir().join("real.json");
            fs::write(&real, registry_json(&[tenant.entry()], Some("prod"))).expect("write");
            std::os::unix::fs::symlink(&real, env.sandbox.registry_path()).expect("symlink");
        };
        let directory = |env: &Env| {
            let path = if env.rust {
                env.sandbox.detach_store();
                env.sandbox.store_index_path()
            } else {
                env.sandbox.registry_path()
            };
            fs::create_dir(path).expect("mkdir");
        };
        for setup in [&link as Setup<'_>, &directory] {
            let Some((r, t)) = pair("registry_symlink_or_dir", setup, LIST, &no_options) else {
                return;
            };
            assert_eq!(
                (t.code, t.stderr.clone()),
                (
                    1,
                    op_error(
                        "Cannot read tenant registry at <REGISTRY>; restore a valid registry before proceeding"
                    )
                )
            );
            assert_eq!(
                (r.code, r.raw_stderr.clone()),
                (
                    1,
                    op_error(
                        "Refusing to use <ROOT>/store/config.toml: it must be a regular file (not a symlink) owned by the current user with no group or other permissions (chmod 600)"
                    )
                )
            );
            assert_zero_requests(&r);
            assert_zero_requests(&t);
        }
    }

    /// Config documents both CLIs reject (invalid UTF-8 is D27, pinned separately).
    fn invalid_configs(env: &Env) -> Vec<Vec<u8>> {
        let base = Sandbox::fixture_config(&env.server, "100");
        let edited = |key: &str, value: Value| base.clone().with(key, value).to_json().into_bytes();
        let text = base.to_json();
        let truncated = format!(
            "{},\n  \"mgmtClientSecret\": \"SUPER-SECRET\",oops",
            text.trim_end().trim_end_matches('}').trim_end()
        );
        let pad = 1_048_577 - base.clone().with("custom", "").to_json().len();
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend_from_slice(text.as_bytes());
        vec![
            b"null".to_vec(),
            b"[]".to_vec(),
            edited("scanConcurrency", json!(99)),
            edited("scanConcurrency", json!("")),
            edited("scanConcurrency", Value::Null),
            edited("scanConcurrency", json!("abc")),
            edited("defaultOutput", json!("xml")),
            edited("mgmtDashboardEndpoint", json!("not a url")),
            edited("typesafeBaseUrl", json!("not a url")),
            edited("mgmtTsgId", json!(100)),
            edited("airsApiKey", Value::Null),
            edited("airsNumRetries", json!(6)),
            base.clone()
                .with("custom", "x".repeat(pad))
                .to_json()
                .into_bytes(),
            bom,
            truncated.into_bytes(),
        ]
    }

    #[test]
    fn invalid_config() {
        let count = 15;
        for index in 0..count {
            let setup = move |env: &Env| {
                let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
                env.sandbox.register(&[&tenant], Some("prod"));
                let cases = invalid_configs(env);
                assert_eq!(cases.len(), count);
                env.sandbox.write_config_raw("prod", &cases[index]);
            };
            let options = |_: &Env| RunOptions::new().secret("SUPER-SECRET");
            for args in [
                LIST,
                SCAN,
                &["tenant", "read", "--output", "json"][..],
                &["tenant", "get", "prod", "mgmtTsgId"][..],
            ] {
                same_error(
                    "invalid_config",
                    &setup,
                    args,
                    &options,
                    "Cannot read a valid tenant config at <CONFIG:prod>",
                );
            }
        }
    }

    #[test]
    fn config_that_is_missing_or_a_directory() {
        for target in ["missing.json", "dir.d"] {
            let setup = move |env: &Env| {
                let path = env.sandbox.configs_dir().join(target);
                if target.ends_with(".d") {
                    fs::create_dir(&path).expect("mkdir");
                }
                env.sandbox
                    .write_registry(&[RegistryEntry::new("prod", &path, "100")], Some("prod"));
            };
            same_error(
                "config_missing_or_dir",
                &setup,
                LIST,
                &no_options,
                "Cannot read a valid tenant config at <CONFIG:prod>",
            );
        }
    }

    #[test]
    fn tsg_mismatch_and_missing_tsg() {
        let msg =
            "Tenant config TSG differs from its registered identity; register it under a new name";
        let mismatch = prod_with(|config| {
            config.set("mgmtTsgId", "200");
        });
        let missing = prod_with(|config| {
            config.remove("mgmtTsgId");
        });
        for setup in [&mismatch as Setup<'_>, &missing] {
            for args in [
                LIST,
                SCAN,
                &["tenant", "read", "--output", "json"][..],
                &["tenant", "get", "prod", "mgmtTsgId"][..],
            ] {
                same_error("tsg_pin", setup, args, &no_options, msg);
            }
        }
    }

    #[test]
    fn missing_management_credentials() {
        let no_secret = prod_with(|config| {
            config.remove("mgmtClientSecret");
        });
        same_error(
            "mgmt_missing_secret",
            &no_secret,
            LIST,
            &no_options,
            "Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set prod <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)",
        );
        let blank_id = prod_with(|config| {
            config.set("mgmtClientId", "  ");
            config.remove("mgmtClientSecret");
        });
        same_error(
            "mgmt_blank_id",
            &blank_id,
            LIST,
            &no_options,
            "Management credentials are not configured (missing mgmtClientId, mgmtClientSecret). Run 'airs-cli tenant set prod <key>' for mgmtClientId, mgmtClientSecret (secrets prompt hidden, or use --stdin)",
        );
    }

    #[test]
    fn missing_scanner_credentials_even_with_env_key() {
        let no_key = prod_with(|config| {
            config.remove("airsApiKey");
            config.set("airsApiToken", "  ");
        });
        let options = |env: &Env| {
            env.sandbox.add_secret("env key", "ENV-LEAK-APIKEY-0001");
            RunOptions::new().env("PANW_AI_SEC_API_KEY", "ENV-LEAK-APIKEY-0001")
        };
        same_error(
            "scanner_missing",
            &no_key,
            SCAN,
            &options,
            "Scanner credentials are not configured (airsApiKey or airsApiToken). Run 'airs-cli tenant set prod <key>' for airsApiKey (secrets prompt hidden, or use --stdin)",
        );
    }

    #[test]
    fn xdg_state_home_must_be_absolute() {
        // D70: XDG_STATE_HOME locates the TypeScript registry, so a relative value fails
        // TS; airs-cli-rs reads its store and is unaffected. The store variables have the
        // same rule with their own names.
        let options = |_: &Env| {
            RunOptions::new()
                .without_env("PRISMA_AIRS_TENANTS_PATH")
                .env("XDG_STATE_HOME", "relative/state")
        };
        let rust_options = |_: &Env| RunOptions::new().env("AIRS_CLI_CONFIG_DIR", "relative/store");
        for args in [LIST, &["tenant", "list", "--output", "json"][..]] {
            let Some((r, t)) = pair("xdg_relative", &prod, args, &options) else {
                return;
            };
            assert_eq!(
                (t.code, t.stderr.clone()),
                (1, op_error("XDG_STATE_HOME must be an absolute path"))
            );
            assert_eq!(r.code, 0, "{r:?}");
            let r = exec(&rust(), &prod, args, &rust_options);
            assert_eq!(
                (r.code, r.stderr.clone()),
                (1, op_error("AIRS_CLI_CONFIG_DIR must be an absolute path"))
            );
            assert_zero_requests(&t);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Registry path resolution: the resolved path is visible in the shared error message
// ---------------------------------------------------------------------------------------
mod registry_path {
    use super::*;

    fn corrupt(path: &Path) {
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, b"{").expect("write");
    }

    #[test]
    fn every_resolution_form_agrees() {
        type Case = (
            &'static str,
            fn(&Env) -> RunOptions,
            fn(&Env) -> std::path::PathBuf,
        );
        let cases: [Case; 8] = [
            (
                "tilde slash",
                |_| RunOptions::new().env("PRISMA_AIRS_TENANTS_PATH", "~/reg/./x/../r.json"),
                |e| e.sandbox.home().join("reg/r.json"),
            ),
            (
                "exact tilde",
                |_| RunOptions::new().env("PRISMA_AIRS_TENANTS_PATH", "~"),
                |e| e.sandbox.home(),
            ),
            (
                "relative",
                |_| RunOptions::new().env("PRISMA_AIRS_TENANTS_PATH", "sub/../r.json"),
                |e| e.sandbox.cwd().join("r.json"),
            ),
            (
                "tilde user",
                |_| RunOptions::new().env("PRISMA_AIRS_TENANTS_PATH", "~other/r.json"),
                |e| e.sandbox.cwd().join("~other/r.json"),
            ),
            (
                "messy absolute",
                |e| {
                    RunOptions::new().env(
                        "PRISMA_AIRS_TENANTS_PATH",
                        format!("{}//state/./x/../other.json/", e.sandbox.root().display()),
                    )
                },
                |e| e.sandbox.state_dir().join("other.json"),
            ),
            (
                "empty falls back to XDG",
                |e| {
                    RunOptions::new().env("PRISMA_AIRS_TENANTS_PATH", "").env(
                        "XDG_STATE_HOME",
                        format!("{}/xdg/../xdg2/", e.sandbox.root().display()),
                    )
                },
                |e| e.sandbox.root().join("xdg2/prisma-airs/tenants.json"),
            ),
            (
                "HOME default",
                |_| RunOptions::new().without_env("PRISMA_AIRS_TENANTS_PATH"),
                |e| {
                    e.sandbox
                        .home()
                        .join(".local/state/prisma-airs/tenants.json")
                },
            ),
            (
                "empty XDG falls back to HOME",
                |_| {
                    RunOptions::new()
                        .without_env("PRISMA_AIRS_TENANTS_PATH")
                        .env("XDG_STATE_HOME", "")
                },
                |e| {
                    e.sandbox
                        .home()
                        .join(".local/state/prisma-airs/tenants.json")
                },
            ),
        ];
        for (label, options, target) in cases {
            let setup = move |env: &Env| {
                let path = target(env);
                if path != env.sandbox.home() {
                    corrupt(&path);
                }
            };
            let Some((r, t)) = pair(
                "registry_path_forms",
                &setup,
                &["tenant", "list", "--output", "json"],
                &options,
            ) else {
                return;
            };
            // TS resolves the path and rejects the corrupt registry there; airs-cli-rs
            // reads only its store (D70), here empty.
            assert_eq!(t.code, 1, "{label}");
            assert!(
                t.stderr.contains("Cannot read tenant registry at <ROOT>/"),
                "{label}: {t:?}"
            );
            assert_eq!((r.code, r.stdout.as_str()), (0, "[]\n"), "{label}: {r:?}");
            // D90: its pretty listing names the same resolved path in the import hint.
            let pretty = exec(&rust(), &setup, &["tenant", "list"], &options);
            let resolved = t
                .stderr
                .split("Cannot read tenant registry at ")
                .nth(1)
                .and_then(|rest| rest.split("; ").next())
                .unwrap_or_default()
                .to_owned();
            assert_eq!(
                pretty.raw_stderr,
                format!(
                    "  Run 'airs tenant create <name>' to register one; a TypeScript tenant registry exists at {resolved}: run 'airs tenant import' to copy it.\n"
                ),
                "{label}"
            );
        }
    }

    #[test]
    fn home_default_registry_is_used_for_requests() {
        // Each CLI finds the tenant in its own default location under HOME: TS in
        // ~/.local/state/prisma-airs/tenants.json, airs-cli-rs in ~/.config/airs-cli.
        let setup = |env: &Env| {
            let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
            env.server
                .set_profiles("100", vec![fixtures::profile(1, "alpha", 1)]);
            if env.rust {
                env.sandbox.register(&[&tenant], Some("prod"));
                let store = env.sandbox.home().join(".config/airs-cli");
                fs::create_dir_all(store.parent().expect("parent")).expect("mkdir");
                let status = std::process::Command::new("cp")
                    .arg("-Rp")
                    .arg(env.sandbox.store_dir())
                    .arg(&store)
                    .status()
                    .expect("cp");
                assert!(status.success());
                return;
            }
            let path = env
                .sandbox
                .home()
                .join(".local/state/prisma-airs/tenants.json");
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(&path, registry_json(&[tenant.entry()], Some("prod"))).expect("write");
        };
        let options = |_: &Env| {
            RunOptions::new()
                .without_env("PRISMA_AIRS_TENANTS_PATH")
                .without_env("AIRS_CLI_CONFIG_DIR")
        };
        let Some((r, t)) = pair("registry_home_default", &setup, LIST, &options) else {
            return;
        };
        assert_eq!((r.code, t.code), (0, 0));
        assert_json_semantic_eq(&r.json(), &t.json());
        assert_same_requests(&r, &t);
        assert_eq!(r.routes(), vec![Route::Token, Route::Profiles]);
    }

    #[test]
    fn exactly_one_mib_registry_and_one_thousand_entries_are_accepted() {
        let one_mib = |env: &Env| {
            let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
            let mut text = registry_json(&[tenant.entry()], Some("prod"));
            text.push_str(&" ".repeat(1_048_576 - text.len()));
            env.sandbox.write_registry_raw(text.as_bytes());
        };
        let thousand = |env: &Env| {
            let entries: Vec<RegistryEntry> = (0..1000)
                .map(|i| RegistryEntry::new(&format!("t{i:04}"), format!("/c/t{i:04}.json"), "1"))
                .collect();
            env.sandbox.write_registry(&entries, Some("t0500"));
        };
        for setup in [&one_mib as Setup<'_>, &thousand] {
            let Some((r, t)) = pair(
                "registry_limits_accepted",
                setup,
                &["tenant", "list", "--output", "json"],
                &no_options,
            ) else {
                return;
            };
            assert_same(&r, &t);
            assert_eq!(r.code, 0);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Accepted configs and request parity
// ---------------------------------------------------------------------------------------
mod accepted {
    use super::*;

    fn same_list(test: &str, setup: Setup<'_>, args: &[&str], options: Options<'_>, tsg: &str) {
        let Some((r, t)) = pair(test, setup, args, options) else {
            return;
        };
        assert_eq!((r.code, t.code), (0, 0), "rust: {r:?}\nts: {t:?}");
        assert_json_semantic_eq(&r.json(), &t.json());
        assert_eq!(r.stderr, t.stderr);
        assert_same_requests(&r, &t);
        assert_eq!(r.routes(), vec![Route::Token, Route::Profiles]);
        for side in [&r, &t] {
            assert_eq!(
                side.raw[0].auth,
                AuthIdentity::Basic {
                    client_id: format!("client-{tsg}"),
                    tsg: Some(tsg.into()),
                    valid: true
                },
                "{}",
                side.cli
            );
            assert_eq!(
                side.raw[1].auth,
                AuthIdentity::Bearer {
                    tsg: Some(tsg.into())
                }
            );
        }
    }

    #[test]
    fn symlinked_config_extra_keys_and_coerced_values() {
        let symlinked = |env: &Env| {
            let tenant = env.sandbox.add_fixture_tenant(&env.server, "real", "100");
            let link = env.sandbox.configs_dir().join("link.json");
            std::os::unix::fs::symlink(&tenant.config_path, &link).expect("symlink");
            env.sandbox
                .write_registry(&[RegistryEntry::new("prod", &link, "100")], Some("prod"));
            env.server
                .set_profiles("100", vec![fixtures::profile(1, "alpha", 1)]);
        };
        let extra = |env: &Env| {
            let retired = env.server.url("/retired-token");
            prod_with(move |config| {
                config
                    .set("custom", 1)
                    .set("redTeamTokenEndpoint", retired.clone())
                    .set("scanConcurrency", "3")
                    .set("airsNumRetries", "0");
            })(env)
        };
        for setup in [&symlinked as Setup<'_>, &extra] {
            same_list("accepted_configs", setup, LIST, &no_options, "100");
        }
    }

    #[test]
    fn environment_is_ignored_for_management() {
        let setup = |env: &Env| {
            prod(env);
            env.sandbox.add_fixture_tenant(&env.server, "dev", "200");
            env.server
                .set_profiles("200", vec![fixtures::profile(2, "beta", 1)]);
        };
        let options = |env: &Env| {
            env.sandbox.add_secret("env token", "ENV-SCANNER-TOKEN-200");
            RunOptions::new()
                .env("PANW_MGMT_CLIENT_ID", "client-200")
                .env("PANW_MGMT_CLIENT_SECRET", "FAKE-SECRET-200")
                .env("PANW_MGMT_TSG_ID", "200")
                .env("PANW_MGMT_ENDPOINT", env.server.url("/env-mgmt"))
                .env("PANW_MGMT_TOKEN_ENDPOINT", env.server.url("/env-token"))
                .env("PANW_AI_SEC_API_KEY", "FAKE-APIKEY-200")
                .env("PANW_AI_SEC_API_TOKEN", "ENV-SCANNER-TOKEN-200")
                .env("PANW_AI_SEC_API_ENDPOINT", env.server.url("/env-scan"))
                .env(
                    "PRISMA_AIRS_CONFIG_PATH",
                    env.sandbox.config_path("dev").display().to_string(),
                )
                .env("PANW_CLI_OUTPUT", "yaml")
                .env("SCAN_CONCURRENCY", "99")
        };
        same_list("env_ignored_mgmt", &setup, LIST, &options, "100");
        // Tenant commands ignore the environment too.
        for args in [
            &["tenant", "read", "--output", "json"][..],
            &["tenant", "get", "prod", "mgmtTsgId"][..],
            &["tenant", "get", "prod", "scanConcurrency"][..],
        ] {
            let Some((r, t)) = pair("env_ignored_tenant", &setup, args, &options) else {
                return;
            };
            if args[1] == "read" {
                assert_same_rows(&r, &t, false);
            } else {
                assert_same(&r, &t);
            }
            assert_eq!(r.code, 0);
        }
    }

    #[test]
    fn environment_is_ignored_for_scan_with_a_key_tenant() {
        let options = |env: &Env| {
            RunOptions::new()
                .env("PANW_AI_SEC_API_KEY", "FAKE-APIKEY-200")
                .env("PANW_AI_SEC_API_ENDPOINT", env.server.url("/env-scan"))
                .env("PANW_MGMT_TSG_ID", "200")
        };
        let setup = |env: &Env| {
            prod(env);
            env.sandbox.add_fixture_tenant(&env.server, "dev", "200");
        };
        let Some((r, t)) = pair("env_ignored_scan", &setup, SCAN, &options) else {
            return;
        };
        assert_eq!((r.code, t.code), (0, 0), "rust: {r:?}\nts: {t:?}");
        assert_same_requests(&r, &t);
        assert_eq!(
            r.raw[0].auth,
            AuthIdentity::ApiKey {
                key_id: Some("100".into()),
                hash_valid: true
            }
        );
    }

    #[test]
    fn switching_the_registry_active_switches_requests() {
        for (active, tsg) in [("prod", "100"), ("dev", "200")] {
            let setup = two(Some(active));
            same_list("two_tenant_isolation", &setup, LIST, &no_options, tsg);
        }
    }

    #[test]
    fn scanner_only_and_management_only_tenants() {
        let scanner_only = prod_with(|config| {
            config.remove("mgmtClientId");
            config.remove("mgmtClientSecret");
        });
        let Some((r, t)) = pair("scanner_only", &scanner_only, SCAN, &no_options) else {
            return;
        };
        assert_eq!((r.code, t.code), (0, 0));
        assert_same_requests(&r, &t);
        let management_only = prod_with(|config| {
            config.remove("airsApiKey");
        });
        same_list(
            "management_only",
            &management_only,
            LIST,
            &no_options,
            "100",
        );
    }
}

// ---------------------------------------------------------------------------------------
// Divergences (DESIGN §12): both sides' actual behaviour is pinned
// ---------------------------------------------------------------------------------------
mod divergences {
    use super::*;

    /// D34: `tenant get` with an unknown key: TS exit 1 as an operational error;
    /// airs-cli-rs exit 2 as a usage error. Same message text.
    #[test]
    fn d34_tenant_get_unknown_key_exit_code() {
        let Some((r, t)) = pair(
            "d34",
            &prod,
            &["tenant", "get", "prod", "notAKey"],
            &no_options,
        ) else {
            return;
        };
        let keys = "airsApiKey, airsApiToken, airsApiEndpoint, airsNumRetries, mgmtClientId, mgmtClientSecret, mgmtTsgId, mgmtEndpoint, mgmtDashboardEndpoint, mgmtTokenEndpoint, dlpEndpoint, redTeamDataEndpoint, redTeamMgmtEndpoint, redTeamNetworkBrokerEndpoint, modelSecDataEndpoint, modelSecMgmtEndpoint, agentGuardDataEndpoint, agentGuardMgmtEndpoint, aiGwDataEndpoint, aiGwAdminEndpoint, iamEndpoint, aiGwInferenceEndpoint, aiGwInferenceApiKey, aiGwInferenceModel, aiGwEmbeddingModel, typesafeApiKey, typesafeBaseUrl, typesafeModel, scanConcurrency, defaultOutput, dataDir";
        let msg = format!("Unknown configuration key. Supported keys: {keys}");
        assert_eq!(
            (t.code, t.stdout.as_str(), t.stderr.clone()),
            (1, "", op_error(&msg))
        );
        // The same text with the 27 airs-cli-rs keys (D71).
        let rust_keys = airs_test_harness::store::RUST_KEYS.join(", ");
        assert_eq!(
            (r.code, r.stdout.as_str(), r.stderr.clone()),
            (
                2,
                "",
                format!("\n  ✗ Unknown configuration key. Supported keys: {rust_keys}\n\n")
            )
        );
        assert_zero_requests(&r);
        assert_zero_requests(&t);
    }

    /// D8: a token-only tenant plus `PANW_AI_SEC_API_KEY`: the TS SDK also sends the
    /// environment key (`x-pan-token` + `x-payload-hash`); airs-cli-rs sends only the
    /// tenant's bearer token.
    #[test]
    fn d8_token_only_tenant_with_env_api_key() {
        let setup = prod_with(|config| {
            config.remove("airsApiKey");
            config.set("airsApiToken", "FAKE-SCANTOKEN-100");
        });
        let options = |env: &Env| {
            env.sandbox.add_secret("env key", "ENV-LEAK-APIKEY-0001");
            RunOptions::new().env("PANW_AI_SEC_API_KEY", "ENV-LEAK-APIKEY-0001")
        };
        let Some((r, t)) = pair("d8_token_only", &setup, SCAN, &options) else {
            return;
        };
        assert_eq!(r.code, 0, "{r:?}");
        assert_eq!(r.routes(), vec![Route::ScanSync]);
        assert_eq!(
            r.raw[0].auth,
            AuthIdentity::ApiToken {
                token_id: "100".into()
            }
        );
        assert!(r.raw[0].header("x-pan-token").is_none());
        assert!(r.raw[0].header("x-payload-hash").is_none());

        assert_eq!(t.routes(), vec![Route::ScanSync], "{t:?}");
        assert!(
            matches!(
                &t.raw[0].auth,
                AuthIdentity::ApiKeyAndToken { key_id: None, token_id: Some(token), .. } if token == "100"
            ),
            "TS no longer leaks the env key (D8 fixed?): {:?}",
            t.raw[0].auth
        );
        assert_eq!(t.raw[0].header("x-pan-token"), Some("ENV-LEAK-APIKEY-0001"));
        assert!(t.raw[0].header("x-payload-hash").is_some());
    }

    /// D8: a key-only tenant plus `PANW_AI_SEC_API_TOKEN`: TS also sends the env token as
    /// a bearer; airs-cli-rs sends only `x-pan-token` + `x-payload-hash`.
    #[test]
    fn d8_key_only_tenant_with_env_api_token() {
        let options = |env: &Env| {
            env.sandbox.add_secret("env token", "ENV-LEAK-TOKEN-0001");
            RunOptions::new().env("PANW_AI_SEC_API_TOKEN", "ENV-LEAK-TOKEN-0001")
        };
        let Some((r, t)) = pair("d8_key_only", &prod, SCAN, &options) else {
            return;
        };
        assert_eq!(r.code, 0, "{r:?}");
        assert_eq!(
            r.raw[0].auth,
            AuthIdentity::ApiKey {
                key_id: Some("100".into()),
                hash_valid: true
            }
        );
        assert!(r.raw[0].header("authorization").is_none());
        assert_eq!(t.routes(), vec![Route::ScanSync], "{t:?}");
        assert!(
            matches!(
                &t.raw[0].auth,
                AuthIdentity::ApiKeyAndToken { key_id: Some(key), token_id: None, .. } if key == "100"
            ),
            "TS no longer leaks the env token (D8 fixed?): {:?}",
            t.raw[0].auth
        );
        assert_eq!(
            t.raw[0].header("authorization"),
            Some("Bearer ENV-LEAK-TOKEN-0001")
        );
    }

    /// D27: invalid UTF-8 inside a config string: Node decodes lossily and accepts;
    /// airs-cli-rs requires UTF-8 in its TOML tenant file and rejects it with the generic
    /// config message (the import-side rejection is `src/tenant/ts.rs`'s unit test).
    #[test]
    fn d27_invalid_utf8_config() {
        let setup = |env: &Env| {
            let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
            env.sandbox.register(&[&tenant], Some("prod"));
            let lossy = |bytes: Vec<u8>| {
                let text = String::from_utf8(bytes).expect("utf-8");
                let (before, after) = text.split_once("client-100").expect("client id");
                let mut bytes = before.as_bytes().to_vec();
                bytes.extend_from_slice(b"a\xffb");
                bytes.extend_from_slice(after.as_bytes());
                bytes
            };
            if env.rust {
                let file = fs::read(&tenant.store_path).expect("tenant file");
                env.sandbox
                    .write_tenant_file_raw("prod", &lossy(file), 0o600);
            } else {
                env.sandbox
                    .write_config_raw("prod", &lossy(tenant.config.to_json().into_bytes()));
            }
        };
        let Some((r, t)) = pair(
            "d27_config",
            &setup,
            &["tenant", "get", "prod", "mgmtClientId"],
            &no_options,
        ) else {
            return;
        };
        assert_eq!((t.code, t.stdout.as_str()), (0, "a\u{fffd}b\n"), "{t:?}");
        assert_eq!(
            (r.code, r.stderr.clone()),
            (
                1,
                op_error("Cannot read a valid tenant config at <CONFIG:prod>")
            )
        );
    }

    /// D27: invalid UTF-8 in the registry: TS lists the lossy value; airs-cli-rs rejects
    /// invalid UTF-8 in `config.toml` with the same generic registry message.
    #[test]
    fn d27_invalid_utf8_registry() {
        let setup = |env: &Env| {
            if env.rust {
                env.sandbox.write_store_raw(
                    b"version = 1\n\n[tenants.prod]\ntsg_id = \"1\xff\"\n",
                    0o600,
                );
                return;
            }
            let path = Value::String(env.sandbox.config_path("prod").display().to_string());
            let mut bytes = format!(r#"{{"version":1,"active":null,"tenants":[{{"name":"prod","configPath":{path},"tsgId":"1"#)
                .into_bytes();
            bytes.extend_from_slice(b"\xff\"}]}");
            env.sandbox.write_registry_raw(&bytes);
        };
        let Some((r, t)) = pair(
            "d27_registry",
            &setup,
            &["tenant", "list", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        assert_eq!(t.code, 0, "{t:?}");
        assert_eq!(t.json()[0]["tsgId"], "1\u{fffd}");
        assert_eq!(
            (r.code, r.stderr.clone()),
            (
                1,
                op_error(
                    "Cannot read tenant registry at <REGISTRY>; restore a valid registry before proceeding"
                )
            )
        );
    }

    /// D28: a non-numeric `mgmtTsgId`: TS sends it to the token endpoint; airs-cli-rs
    /// fails locally with zero requests.
    #[test]
    fn d28_non_numeric_tsg() {
        let setup = |env: &Env| {
            let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "abc");
            env.sandbox.register(&[&tenant], Some("prod"));
        };
        let Some((r, t)) = pair("d28", &setup, LIST, &no_options) else {
            return;
        };
        assert_eq!(
            (r.code, r.stderr.clone()),
            (
                1,
                op_error("Invalid mgmtTsgId: the Rust SDK requires 1-32 ASCII digits")
            )
        );
        assert_zero_requests(&r);
        assert!(!t.raw.is_empty(), "{t:?}");
        assert_eq!(t.raw[0].route, Route::Token);
        assert!(
            t.raw[0]
                .form()
                .contains(&("scope".to_owned(), "tsg_id:abc".to_owned())),
            "{:?}",
            t.raw[0].form()
        );
    }

    /// D48: endpoint admission. A loopback token endpoint with a fragment: TS sends the
    /// token request (fetch drops the fragment) and lists the profiles; airs-cli-rs
    /// refuses the URL locally with zero requests. (A non-loopback http endpoint cannot
    /// be tried on TS here: the harness never lets the TypeScript CLI leave loopback.)
    #[test]
    fn d48_endpoint_with_fragment() {
        let setup = |env: &Env| {
            let url = env.server.url("/oauth/token#frag");
            let tenant =
                env.sandbox
                    .add_fixture_tenant_with(&env.server, "prod", "100", |config| {
                        config.set("mgmtTokenEndpoint", url.as_str());
                    });
            env.sandbox.register(&[&tenant], Some("prod"));
            env.server
                .set_profiles("100", vec![fixtures::profile(1, "alpha", 1)]);
        };
        let Some((r, t)) = pair("d48", &setup, LIST, &no_options) else {
            return;
        };
        assert_eq!(
            (r.code, r.stdout.as_str(), r.stderr.clone()),
            (
                1,
                "",
                op_error(
                    "Invalid mgmtTokenEndpoint: endpoints must use https (http is allowed only \
                     for loopback hosts) and must not contain credentials, a query or a fragment"
                )
            )
        );
        assert_zero_requests(&r);
        assert_eq!(t.code, 0, "{t:?}");
        assert_eq!(t.routes(), vec![Route::Token, Route::Profiles], "{t:?}");
        assert_eq!(t.raw[0].path, "/oauth/token", "{t:?}");
    }

    /// D33: `--tenant` exists only in airs-cli-rs (commander rejects it, exit 1).
    #[test]
    fn d33_tenant_flag() {
        let setup = two(Some("prod"));
        let Some((r, t)) = pair(
            "d33",
            &setup,
            &["--tenant", "dev", "tenant", "path"],
            &no_options,
        ) else {
            return;
        };
        assert_eq!(
            (t.code, t.stdout.as_str(), t.stderr.as_str()),
            (1, "", "error: unknown option '--tenant'\n")
        );
        assert_eq!((r.code, r.stdout.as_str()), (0, "<CONFIG:dev>\n"));
    }

    /// D2: an invalid `--output` with no tenant: TS loads the tenant first (exit 1);
    /// airs-cli-rs validates usage first (exit 2).
    #[test]
    fn d2_usage_before_tenant_loading() {
        let empty = |env: &Env| env.sandbox.write_registry(&[], None);
        let Some((r, t)) = pair(
            "d2",
            &empty,
            &["runtime", "profiles", "list", "--output", "xml"],
            &no_options,
        ) else {
            return;
        };
        assert_eq!(
            (t.code, t.stderr.clone()),
            (
                1,
                op_error(
                    "No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'"
                )
            )
        );
        assert_eq!(
            (r.code, r.stderr.as_str()),
            (
                2,
                "\n  ✗ Invalid output format 'xml'. Expected: pretty, table, json\n\n"
            )
        );
    }

    /// D50: the dropped formats are a usage error for `tenant list|read|get`; TS
    /// renders them.
    #[test]
    fn d50_dropped_formats_tenant() {
        for (format, marker) in [
            ("yaml", "name: prod"),
            ("csv", "Tenant,Selected,TSG ID,Config file"),
            ("markdown", "| Tenant | Selected | TSG ID | Config file |"),
        ] {
            for (args, ts_marker) in [
                (vec!["tenant", "list", "--output", format], marker),
                (vec!["tenant", "read", "--output", format], "mgmtTsgId"),
                (
                    vec!["tenant", "get", "prod", "mgmtTsgId", "--output", format],
                    "100",
                ),
            ] {
                let Some((r, t)) = pair("d50_dropped_formats_tenant", &prod, &args, &no_options)
                else {
                    return;
                };
                assert_eq!(
                    (r.code, r.stdout.as_str(), r.stderr.clone()),
                    (
                        2,
                        "",
                        format!(
                            "\n  ✗ Invalid output format '{format}'. Expected: pretty, table, json\n\n"
                        )
                    ),
                    "{args:?}"
                );
                assert_eq!(t.code, 0, "{args:?}: {t:?}");
                assert!(t.stdout.contains(ts_marker), "{args:?}: {t:?}");
            }
        }
    }

    /// D59: `tenant path` validates `--output`: TS ignores every value, airs-cli-rs
    /// rejects a name outside the three (a valid one is ignored, `path_outputs`).
    #[test]
    fn d59_tenant_path_rejects_invalid_output() {
        for format in ["xml", "csv"] {
            let args = ["tenant", "path", "--output", format];
            let Some((r, t)) = pair("d59_tenant_path", &prod, &args, &no_options) else {
                return;
            };
            assert_eq!(
                (r.code, r.stdout.as_str(), r.stderr.clone()),
                (
                    2,
                    "",
                    format!(
                        "\n  ✗ Invalid output format '{format}'. Expected: pretty, table, json\n\n"
                    )
                )
            );
            assert_eq!(
                (t.code, t.stdout.as_str(), t.stderr.as_str()),
                (0, "<CONFIG:prod>\n", "")
            );
        }
    }

    /// D53: a wide character in a config path: airs-cli-rs pads by display width,
    /// TS by UTF-16 units (the CJK row's later columns drift).
    /// D52 (tenant): control characters from the registry (`configPath`, `tsgId`) and
    /// from the config reach the terminal raw in TS: in `tenant list` cells, `tenant
    /// read` cells and its stderr status line, and the bare `tenant get` value.
    /// airs-cli-rs writes U+FFFD for each, on stdout and on stderr.
    #[test]
    fn d52_control_characters_tenant() {
        const HOSTILE: &str = "x\u{1b}[31my\tz\u{1b}]0;t\u{7}";
        const TSG: &str = "10\u{1b}[0m0";
        let setup = |env: &Env| {
            let tenant = env.sandbox.add_fixture_tenant_with(
                &env.server,
                &format!("pr{HOSTILE}od"),
                TSG,
                |config| {
                    config.set("mgmtClientId", HOSTILE);
                },
            );
            env.sandbox.write_registry(
                &[RegistryEntry::new("prod", &tenant.config_path, TSG)],
                Some("prod"),
            );
        };
        let raw = |text: &str| text.chars().any(|c| c.is_control() && c != '\n');
        for args in [
            &["tenant", "list"][..],
            &["tenant", "list", "--output", "table"],
            &["tenant", "read"],
            &["tenant", "read", "--output", "table"],
            &["tenant", "get", "prod", "mgmtClientId"],
        ] {
            let Some((r, t)) = pair("d52_tenant", &setup, args, &no_options) else {
                return;
            };
            assert_eq!((r.code, t.code), (0, 0), "{args:?}\nrust: {r:?}\nts: {t:?}");
            assert!(t.stdout.contains('\u{1b}'), "TS stdout raw: {t:?}");
            assert!(!raw(&r.stdout), "Rust stdout: {r:?}");
            assert!(r.stdout.contains('\u{fffd}'), "{r:?}");
            assert!(
                !r.stdout.contains("\u{fffd}\u{fffd}"),
                "one U+FFFD per character"
            );
            if args[1] == "read" {
                assert!(
                    t.stderr.starts_with("  Tenant prod (TSG 10\u{1b}[0m0): "),
                    "{t:?}"
                );
                assert!(t.raw_stderr.contains(HOSTILE), "TS status line raw: {t:?}");
                // The Rust status line names its own tenant file (D70); the TSG from
                // config.toml is made terminal-safe.
                assert_eq!(
                    r.raw_stderr,
                    "  Tenant prod (TSG 10\u{fffd}[0m0): <ROOT>/store/tenants/prod.toml\n",
                    "Rust status line: {r:?}"
                );
            } else {
                assert!(!raw(&r.stderr), "Rust stderr: {r:?}");
            }
        }
    }

    #[test]
    fn d53_tenant_list_display_width() {
        let setup = |env: &Env| {
            // The wide text is in the TSG column: airs-cli-rs lists its own tenant files
            // (D70), so a config path cannot carry it. Names in byte order (D86).
            let configs = env.sandbox.configs_dir();
            env.sandbox.write_registry(
                &[
                    RegistryEntry::new("dev", configs.join("dev.json"), "dév-日本-🚀"),
                    RegistryEntry::new("prod", configs.join("prod.json"), "100"),
                ],
                Some("prod"),
            );
        };
        let Some((r, t)) = pair("d53_tenant_list", &setup, &["tenant", "list"], &no_options) else {
            return;
        };
        assert_eq!((r.code, t.code), (0, 0));
        // Display width of a line up to the end (日, 本 and 🚀 take two columns).
        let columns = |line: &str| -> usize {
            line.chars()
                .map(|c| {
                    if matches!(c, '日' | '本' | '🚀') {
                        2
                    } else {
                        1
                    }
                })
                .sum()
        };
        let r_lines: Vec<&str> = r.stdout.lines().collect();
        let t_lines: Vec<&str> = t.stdout.lines().collect();
        // Both body rows carry one `<CONFIG:…>` placeholder whose names differ by one
        // character (dev, prod), as the paths it replaced did, so they compare.
        assert_eq!(columns(r_lines[2]), columns(r_lines[3]), "{r:?}");
        assert_eq!(columns(r_lines[0]), columns(r_lines[1]), "{r:?}");
        // TS counts UTF-16 units: the CJK row is two columns wider than the ASCII row.
        assert_eq!(columns(t_lines[2]), columns(t_lines[3]) + 2, "{t:?}");
        for (r_line, t_line) in r_lines.iter().zip(&t_lines) {
            let cells = |line: &str| -> Vec<String> {
                line.split(['│', '┼'])
                    .map(|cell| cell.trim().to_owned())
                    .collect()
            };
            if !r_line.starts_with('─') {
                assert_eq!(cells(r_line), cells(t_line), "same cells");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// tenant pretty and table renderings, exact bytes (§3.6, R§3.5–R§3.8)
// ---------------------------------------------------------------------------------------
mod render {
    use super::*;

    const FORMATS: [&[&str]; 3] = [&[], &["--output", "pretty"], &["--output", "table"]];

    fn bytes(test: &str, setup: Setup<'_>, args: &[&str]) -> Option<Side> {
        let (r, t) = pair(test, setup, args, &no_options)?;
        assert_same_render(&r, &t);
        assert_zero_requests(&r);
        Some(r)
    }

    /// The cells of a §2.7 table, trimmed (the rule line skipped).
    fn table_rows(text: &str) -> Vec<Vec<String>> {
        text.lines()
            .filter(|line| !line.starts_with('─'))
            .map(|line| line.split('│').map(|cell| cell.trim().to_owned()).collect())
            .collect()
    }

    /// Same exit code and stderr; stdout byte for byte, except for tables: their
    /// padding follows each side's own paths (`<CONFIG:…>` replaced them afterwards),
    /// so the trimmed cells are compared, the TypeScript `Key │ Value` rows mapped
    /// through the import conversion (D71, D72). The Rust table bytes are pinned by
    /// `tests/render.rs`.
    fn assert_same_render(r: &Side, t: &Side) {
        assert_eq!(r.code, t.code, "exit codes differ\nrust: {r:?}\nts: {t:?}");
        assert_eq!(r.stderr, t.stderr, "stderr differs\nrust: {r:?}\nts: {t:?}");
        if !r.stdout.contains('│') {
            assert_eq!(r.stdout, t.stdout, "stdout differs\nrust: {r:?}\nts: {t:?}");
            return;
        }
        let mut ts_rows = table_rows(&t.stdout);
        if ts_rows
            .first()
            .is_some_and(|header| header == &["Key", "Value"])
        {
            ts_rows.retain(|row| {
                !airs_test_harness::store::DROPPED.contains(&row[0].as_str())
                    && (!row[1].is_empty() || row[0] == "Key")
            });
            for row in &mut ts_rows {
                row[0] = airs_test_harness::store::rust_key(&row[0]).to_owned();
            }
            // An unset key's one-row `get` table keeps its empty cell on both sides.
            if t.stdout.lines().count() == 3 && ts_rows.len() == 1 {
                ts_rows = table_rows(&t.stdout);
            }
        }
        assert_eq!(
            table_rows(&r.stdout),
            ts_rows,
            "cells differ\nrust: {r:?}\nts: {t:?}"
        );
    }

    /// Three tenants in byte order of their names (D86 is pinned apart).
    fn three(env: &Env) {
        let configs = env.sandbox.configs_dir();
        env.sandbox.write_registry(
            &[
                RegistryEntry::new(
                    "a-much-longer-tenant-name",
                    configs.join("a/much/longer/path/to/configs/staging.json"),
                    "7",
                ),
                RegistryEntry::new("dev", configs.join("dév-ünï.json"), "1234567890"),
                RegistryEntry::new("prod", configs.join("prod.json"), "100"),
            ],
            Some("prod"),
        );
    }

    #[test]
    fn tenant_list_render() {
        let none_selected = |env: &Env| {
            three(env);
            let configs = env.sandbox.configs_dir();
            env.sandbox.write_registry(
                &[
                    RegistryEntry::new("dev", configs.join("dev.json"), "200"),
                    RegistryEntry::new("prod", configs.join("prod.json"), "100"),
                ],
                None,
            );
        };
        let empty = |env: &Env| env.sandbox.write_registry(&[], None);
        for format in FORMATS {
            for (setup, quiet) in [
                (&three as Setup<'_>, false),
                (&three, true),
                (&none_selected, false),
                (&none_selected, true),
                (&empty, false),
                (&empty, true),
            ] {
                let mut args = vec!["tenant", "list"];
                args.extend_from_slice(format);
                if quiet {
                    args.push("--quiet");
                }
                bytes("tenant_list_render", setup, &args);
            }
        }
        let r = bytes("tenant_list_render_ls", &three, &["tenant", "ls"]);
        if let Some(r) = r {
            assert!(
                r.stdout.starts_with(
                    " Tenant                    │ Selected │ TSG ID     │ Config file"
                )
            );
        }
        let r = bytes("tenant_list_render_empty", &empty, &["tenant", "list"]);
        if let Some(r) = r {
            assert_eq!(r.stdout, "  No tenants found\n");
            assert_eq!(
                r.stderr,
                "  Run 'airs-cli tenant create <name>' to register one.\n"
            );
        }
        let r = bytes(
            "tenant_list_render_empty_table",
            &empty,
            &["tenant", "list", "--output", "table"],
        );
        if let Some(r) = r {
            assert_eq!((r.stdout.as_str(), r.stderr.as_str()), ("\n", ""));
        }
    }

    #[test]
    fn tenant_read_render() {
        let edited = prod_with(|config| {
            config
                .set("airsApiToken", "")
                .set("scanConcurrency", "3")
                .set("typesafeModel", "model-ü")
                .set("dataDir", "~/runs");
        });
        for format in FORMATS {
            for (setup, extra) in [
                (&prod as Setup<'_>, &[][..]),
                (&prod, &["prod"]),
                (&prod, &["--quiet"]),
                (&edited, &[]),
            ] {
                let mut args = vec!["tenant", "read"];
                args.extend_from_slice(extra);
                args.extend_from_slice(format);
                let r = bytes("tenant_read_render", setup, &args);
                if let Some(r) = r {
                    assert!(r.stdout.starts_with(" Key "), "{r:?}");
                }
            }
        }
    }

    #[test]
    fn tenant_get_render() {
        let edited = prod_with(|config| {
            config
                .set("airsApiToken", "")
                .set("mgmtClientId", "client-ü");
        });
        for format in FORMATS {
            for key in [
                "mgmtTsgId",
                "mgmtClientSecret",
                "airsApiToken",
                "defaultOutput",
                "scanConcurrency",
                "airsNumRetries",
                "mgmtClientId",
                "mgmtEndpoint",
            ] {
                let mut args = vec!["tenant", "get", "prod", key];
                args.extend_from_slice(format);
                bytes("tenant_get_render", &edited, &args);
            }
        }
        let r = bytes(
            "tenant_get_render_unset",
            &prod,
            &["tenant", "get", "prod", "defaultOutput"],
        );
        if let Some(r) = r {
            assert_eq!(r.stdout, "\n");
        }
    }

    /// Forced colour on both sides: tables stay plain, status lines are dim.
    #[test]
    fn tenant_forced_colour() {
        let none_selected = |env: &Env| {
            let configs = env.sandbox.configs_dir();
            env.sandbox.write_registry(
                &[RegistryEntry::new("prod", configs.join("prod.json"), "100")],
                None,
            );
        };
        let empty = |env: &Env| env.sandbox.write_registry(&[], None);
        let Some(ts) = require_ts("tenant_forced_colour") else {
            return;
        };
        let rust_colour = |_: &Env| {
            RunOptions::new()
                .without_env("NO_COLOR")
                .env("CLICOLOR_FORCE", "1")
        };
        let ts_colour = |_: &Env| {
            RunOptions::new()
                .without_env("NO_COLOR")
                .env("FORCE_COLOR", "1")
        };
        for (setup, args) in [
            (&none_selected as Setup<'_>, &["tenant", "list"][..]),
            (&empty, &["tenant", "list"]),
            (&prod, &["tenant", "read"]),
            (&prod, &["tenant", "get", "prod", "mgmtTsgId"]),
            (&prod, &["tenant", "get", "prod", "nope"]),
            (&prod, &["tenant", "read", "ghost"]),
        ] {
            let r = exec(&rust(), setup, args, &rust_colour);
            let t = exec(&ts, setup, args, &ts_colour);
            if args.contains(&"nope") {
                // D34: exit codes and texts differ; both are red blocks.
                assert!(
                    r.stderr
                        .starts_with("\u{1b}[31m\u{1b}[39m\n\u{1b}[31m  ✗ Unknown"),
                    "{r:?}"
                );
                assert!(
                    t.stderr
                        .starts_with("\u{1b}[31m\u{1b}[39m\n\u{1b}[31m  ✗ Error: Unknown"),
                    "{t:?}"
                );
                continue;
            }
            assert_same_render(&r, &t);
            // Tables and the bare value are never coloured; status lines and errors are.
            let coloured_stdout = args == ["tenant", "list"] && r.stdout.starts_with("  ");
            assert_eq!(
                r.stdout.contains('\u{1b}'),
                coloured_stdout,
                "{args:?}: {r:?}"
            );
            assert_eq!(
                r.stderr.contains('\u{1b}'),
                !r.stderr.is_empty(),
                "{args:?}: {r:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Review fixes: empty HOME (§3.1), empty positional names (§3.6), and the divergences
// D44 (JSON serde cannot represent) and D45 (redacted endpoint values)
// ---------------------------------------------------------------------------------------

mod review_fixes {
    use super::*;

    /// §3.1: `HOME=""`: both CLIs read `.local/state/prisma-airs/tenants.json` relative
    /// to the current directory (Node's `os.homedir()` is "").
    #[test]
    fn empty_home_reads_the_cwd_relative_registry() {
        // TS reads the cwd-relative registry an empty HOME gives; airs-cli-rs reads its
        // store (AIRS_CLI_CONFIG_DIR), provisioned with the same tenant.
        let setup = |env: &Env| {
            let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
            if env.rust {
                env.sandbox.register(&[&tenant], Some("prod"));
            }
            env.sandbox.write_file(
                "cwd/.local/state/prisma-airs/tenants.json",
                registry_json(&[tenant.entry()], Some("prod")).as_bytes(),
                0o600,
            );
        };
        let options = |_: &Env| {
            RunOptions::new()
                .env("HOME", "")
                .without_env("PRISMA_AIRS_TENANTS_PATH")
        };
        for args in [
            &["tenant", "list", "--output", "json"][..],
            &["tenant", "path"],
            &["tenant", "get", "prod", "mgmtTsgId"],
        ] {
            let Some((r, t)) = pair("empty_home", &setup, args, &options) else {
                return;
            };
            assert_same(&r, &t);
            assert_eq!(r.code, 0, "{r:?}");
            assert_zero_requests(&r);
        }
        let corrupt = |env: &Env| {
            env.sandbox
                .write_file("cwd/.local/state/prisma-airs/tenants.json", b"{oops", 0o600);
        };
        let Some((r, t)) = pair(
            "empty_home_corrupt",
            &corrupt,
            &["tenant", "list"],
            &options,
        ) else {
            return;
        };
        assert_eq!(
            t.stderr,
            op_error(
                "Cannot read tenant registry at .local/state/prisma-airs/tenants.json; restore a valid registry before proceeding"
            )
        );
        // D90: airs-cli-rs never parses it; it names it (absolute) in the import hint.
        assert_eq!(
            (r.code, r.stdout.as_str(), r.raw_stderr.as_str()),
            (
                0,
                "  No tenants found\n",
                "  Run 'airs tenant create <name>' to register one; a TypeScript tenant registry exists at <ROOT>/cwd/.local/state/prisma-airs/tenants.json: run 'airs tenant import' to copy it.\n"
            )
        );
    }

    /// §3.6: an empty positional name is "no tenant selected" (TS falsy check), with
    /// tenants registered or not.
    #[test]
    fn empty_positional_name() {
        let empty = |env: &Env| env.sandbox.write_registry(&[], None);
        for setup in [&prod as Setup<'_>, &empty] {
            for args in [
                &["tenant", "path", ""][..],
                &["tenant", "read", "", "--output", "json"],
                &["tenant", "get", "", "mgmtTsgId"],
            ] {
                let Some((r, t)) = pair("empty_name", setup, args, &no_options) else {
                    return;
                };
                assert_same(&r, &t);
                assert_eq!(r.code, 1);
                assert!(r.stderr.contains("No tenant selected; "), "{r:?}");
            }
        }
    }

    /// The standard config with `extra` (a JSON member) appended.
    fn config_with(env: &Env, extra: &str) {
        let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
        env.sandbox.register(&[&tenant], Some("prod"));
        let text = tenant.config.to_json();
        let body = text.trim_end().trim_end_matches('}').trim_end();
        env.sandbox
            .write_config_raw("prod", format!("{body},\n  {extra}\n}}\n").as_bytes());
    }

    /// D44 (narrowed in 0.3 to the files `tenant import` reads): JSON that
    /// `JSON.parse` accepts but serde_json cannot represent (a number beyond f64, a lone
    /// surrogate escape, nesting deeper than 128). TS reads the config; airs-cli-rs
    /// commands read only the TOML store (D70), so they never parse it. The import
    /// reader's rejection is `src/tenant/ts.rs::tests::documents_are_read_strictly`.
    #[test]
    fn d44_unrepresentable_json_config() {
        let nested = format!(r#""x": {}{}"#, "[".repeat(200), "]".repeat(200));
        for extra in [r#""x": 1e400"#, r#""x": "\ud800""#, nested.as_str()] {
            let setup = move |env: &Env| {
                if env.rust {
                    let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
                    env.sandbox.register(&[&tenant], Some("prod"));
                    env.sandbox.detach_store();
                }
                config_with(env, extra);
            };
            let Some((r, t)) = pair(
                "d44_config",
                &setup,
                &["tenant", "get", "prod", "mgmtTsgId"],
                &no_options,
            ) else {
                return;
            };
            assert_eq!((t.code, t.stdout.as_str()), (0, "100\n"), "{t:?}");
            assert_eq!((r.code, r.stdout.as_str()), (0, "100\n"), "{extra:.30}");
        }
    }

    /// D44 for the registry: TS lists a lone surrogate in `tsgId`; airs-cli-rs commands
    /// do not read the TypeScript registry (D70; the import reader rejects it,
    /// `src/tenant/ts.rs::tests::registry_files`).
    #[test]
    fn d44_unrepresentable_json_registry() {
        let setup = |env: &Env| {
            env.sandbox.detach_store();
            let path = Value::String(env.sandbox.config_path("prod").display().to_string());
            env.sandbox.write_registry_raw(
                format!(r#"{{"version":1,"active":null,"tenants":[{{"name":"prod","configPath":{path},"tsgId":"\ud800"}}]}}"#)
                    .as_bytes(),
            );
        };
        let Some((r, t)) = pair(
            "d44_registry",
            &setup,
            &["tenant", "list", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        assert_eq!(t.code, 0, "{t:?}");
        // JSON.stringify writes the lone surrogate back as an escape.
        assert!(t.stdout.contains(r#""tsgId": "\ud800""#), "{t:?}");
        assert_eq!(
            (r.code, r.stdout.as_str(), r.stderr.as_str()),
            (0, "[]\n", "")
        );
    }

    /// D45: an endpoint value with a query: TS shows it verbatim; airs-cli-rs redacts the
    /// query (and any userinfo or fragment).
    #[test]
    fn d45_endpoint_query_is_redacted() {
        let setup = |env: &Env| {
            let base = env.server.base_url();
            let tenant =
                env.sandbox
                    .add_fixture_tenant_with(&env.server, "prod", "100", |config| {
                        config.set("iamEndpoint", format!("{base}/iam?api_key=FAKE-Q-777"));
                    });
            env.sandbox.register(&[&tenant], Some("prod"));
        };
        let Some((r, t)) = pair(
            "d45",
            &setup,
            &["tenant", "get", "prod", "iamEndpoint"],
            &no_options,
        ) else {
            return;
        };
        assert_eq!(
            (t.code, t.stdout.as_str()),
            (0, "<BASE>/iam?api_key=FAKE-Q-777\n")
        );
        assert_eq!((r.code, r.stdout.as_str()), (0, "<BASE>/iam?[REDACTED]\n"));
    }
}

// ---------------------------------------------------------------------------------------
// M4t store divergences (DESIGN §12 D70–D90): both sides' behaviour is pinned
// ---------------------------------------------------------------------------------------
mod store_divergences {
    use super::*;

    /// A TypeScript-only state: the TS registry and configs, no Rust store.
    fn ts_only(env: &Env) {
        prod(env);
        env.sandbox.ts_only();
    }

    /// A Rust-only state: the Rust store, no TS registry.
    fn rust_only(env: &Env) {
        let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
        env.sandbox.rust_only(&[&tenant], Some("prod"));
    }

    /// D70: each CLI reads only its own tenant files; `tenant path` prints them.
    #[test]
    fn d70_tenants_live_in_the_toml_store() {
        let list = ["tenant", "list", "--output", "json"];
        let Some((r, t)) = pair("d70_ts_only", &ts_only, &list, &no_options) else {
            return;
        };
        assert_eq!(t.json()[0]["name"], "prod", "{t:?}");
        assert_eq!((r.code, r.stdout.as_str()), (0, "[]\n"), "{r:?}");
        let Some((r, t)) = pair("d70_rust_only", &rust_only, &list, &no_options) else {
            return;
        };
        assert_eq!((t.code, t.stdout.as_str()), (0, "[]\n"), "{t:?}");
        assert_eq!(r.json()[0]["name"], "prod", "{r:?}");
        assert_eq!(
            r.json()[0]["configPath"],
            "<CONFIG:prod>",
            "the store path, normalised"
        );
        // `tenant path` and the `tenant read` status name each CLI's own file.
        let Some((r, t)) = pair("d70_path", &prod, &["tenant", "path"], &no_options) else {
            return;
        };
        assert_eq!(
            (r.stdout.as_str(), t.stdout.as_str()),
            ("<CONFIG:prod>\n", "<CONFIG:prod>\n")
        );
        let Some((r, t)) = pair(
            "d70_read",
            &prod,
            &["tenant", "read", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        assert_eq!(
            t.raw_stderr,
            "  Tenant prod (TSG 100): <ROOT>/configs/prod.json\n"
        );
        assert_eq!(
            r.raw_stderr,
            "  Tenant prod (TSG 100): <ROOT>/store/tenants/prod.toml\n"
        );
    }

    /// D71: `aiGw*` → `gateway*`, `agentGuard*` → `supplychain*`; `dataDir` and
    /// `typesafe*` are gone, and the unknown-key message lists the 27 keys.
    #[test]
    fn d71_setting_keys_renamed_and_dropped() {
        let setup = prod_with(|config| {
            config
                .set("aiGwInferenceModel", "model-m")
                .set("typesafeModel", "t")
                .set("dataDir", "/runs");
        });
        for (old, new) in [
            ("aiGwInferenceModel", "gatewayInferenceModel"),
            ("agentGuardDataEndpoint", "supplychainDataEndpoint"),
        ] {
            let Some((r, t)) = pair(
                "d71_old",
                &setup,
                &["tenant", "get", "prod", old],
                &no_options,
            ) else {
                return;
            };
            assert_eq!(t.code, 0, "{t:?}");
            assert_eq!(r.code, 2, "{r:?}");
            assert!(r.stderr.contains("Unknown configuration key."), "{r:?}");
            let Some((r, t)) = pair(
                "d71_new",
                &setup,
                &["tenant", "get", "prod", new],
                &no_options,
            ) else {
                return;
            };
            assert_eq!(t.code, 1, "{t:?}");
            assert!(t.stderr.contains("Unknown configuration key."), "{t:?}");
            assert_eq!(r.code, 0, "{r:?}");
        }
        let Some((r, t)) = pair(
            "d71_read",
            &setup,
            &["tenant", "read", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        let keys = |side: &Side| -> Vec<String> {
            side.json()
                .as_array()
                .expect("rows")
                .iter()
                .map(|row| row["key"].as_str().unwrap_or_default().to_owned())
                .collect()
        };
        let (rust_keys, ts_keys) = (keys(&r), keys(&t));
        for key in ["dataDir", "typesafeModel", "aiGwInferenceModel"] {
            assert!(ts_keys.contains(&key.to_owned()), "{key}: {ts_keys:?}");
            assert!(!rust_keys.contains(&key.to_owned()), "{key}: {rust_keys:?}");
        }
        assert!(rust_keys.contains(&"gatewayInferenceModel".to_owned()));
        assert_eq!(r.json(), ts_rows_as_rust(&t.json(), false));
    }

    /// D72: TOML types, no coercion, `""` invalid, unknown keys invalid. TypeScript reads
    /// the same values (coerced, `""` unset, unknown keys ignored).
    #[test]
    fn d72_strict_toml_schema() {
        for (ts_edit, toml_line, key) in [
            (json!("3"), "scanConcurrency = \"3\"", "scanConcurrency"),
            (json!(""), "airsApiToken = \"\"", "airsApiToken"),
            (json!(1), "custom = 1", "custom"),
        ] {
            let ts_setup = prod_with(move |config| {
                config.set(key, ts_edit.clone());
            });
            let setup = move |env: &Env| {
                ts_setup(env);
                if env.rust {
                    if key == "custom" {
                        env.sandbox.append_tenant_line("prod", toml_line);
                    } else {
                        env.sandbox.set_tenant_line("prod", key, toml_line);
                    }
                }
            };
            let Some((r, t)) = pair(
                "d72",
                &setup,
                &["tenant", "get", "prod", "mgmtTsgId"],
                &no_options,
            ) else {
                return;
            };
            assert_eq!(
                (t.code, t.stdout.as_str()),
                (0, "100\n"),
                "{toml_line}: {t:?}"
            );
            assert_eq!(
                (r.code, r.stderr.clone()),
                (
                    1,
                    op_error("Cannot read a valid tenant config at <CONFIG:prod>")
                ),
                "{toml_line}"
            );
        }
    }

    /// D73: hints, remedies and messages name `airs`.
    #[test]
    fn d73_hints_name_airs() {
        let empty = |_: &Env| {};
        let Some((r, t)) = pair("d73", &empty, LIST, &no_options) else {
            return;
        };
        assert_eq!(
            t.raw_stderr,
            op_error(
                "No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'"
            )
        );
        assert_eq!(
            r.raw_stderr,
            op_error(
                "No tenant selected. Run 'airs tenant create <name>' and then 'airs tenant switch <name>'"
            )
        );
        assert_eq!(
            r.stderr, t.stderr,
            "equal once the program name is normalised"
        );
        let setup = prod_with(|config| {
            config.remove("mgmtClientSecret");
        });
        let Some((r, t)) = pair("d73_remedy", &setup, LIST, &no_options) else {
            return;
        };
        assert!(
            t.raw_stderr
                .contains("Run 'airs-cli tenant set prod <key>'"),
            "{t:?}"
        );
        assert!(
            r.raw_stderr.contains("Run 'airs tenant set prod <key>'"),
            "{r:?}"
        );
    }

    /// D79: TypeScript reads a group-readable or symlinked config; airs-cli-rs refuses
    /// such a tenant file (and a group-writable store directory).
    #[test]
    fn d79_store_file_safety() {
        let refusing = "Refusing to use <ROOT>/store/tenants/prod.toml: it must be a regular file (not a symlink) owned by the current user with no group or other permissions (chmod 600)";
        for variant in ["mode 0644", "symlink"] {
            let setup = move |env: &Env| {
                let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
                env.sandbox.register(&[&tenant], Some("prod"));
                if !env.rust {
                    return;
                }
                let bytes = fs::read(&tenant.store_path).expect("tenant file");
                if variant == "symlink" {
                    let real = env.sandbox.write_file("tmp/prod.toml", &bytes, 0o600);
                    env.sandbox.detach_store();
                    fs::remove_file(&tenant.store_path).expect("remove");
                    std::os::unix::fs::symlink(&real, &tenant.store_path).expect("symlink");
                } else {
                    env.sandbox.write_tenant_file_raw("prod", &bytes, 0o644);
                }
            };
            let ts_setup = move |env: &Env| {
                let tenant = env.sandbox.add_fixture_tenant(&env.server, "prod", "100");
                if variant == "symlink" {
                    let link = env.sandbox.configs_dir().join("link.json");
                    std::os::unix::fs::symlink(&tenant.config_path, &link).expect("symlink");
                    env.sandbox
                        .write_registry(&[RegistryEntry::new("prod", &link, "100")], Some("prod"));
                } else {
                    env.sandbox.register(&[&tenant], Some("prod"));
                    let mut permissions = fs::metadata(&tenant.config_path)
                        .expect("meta")
                        .permissions();
                    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o644);
                    fs::set_permissions(&tenant.config_path, permissions).expect("chmod");
                }
            };
            let args = ["tenant", "get", "prod", "mgmtTsgId"];
            let Some(ts) = require_ts("d79") else {
                return;
            };
            let t = exec(&ts, &ts_setup, &args, &no_options);
            let r = exec(&rust(), &setup, &args, &no_options);
            assert_eq!(
                (t.code, t.stdout.as_str()),
                (0, "100\n"),
                "{variant}: {t:?}"
            );
            assert_eq!(
                (r.code, r.raw_stderr.clone()),
                (1, op_error(refusing)),
                "{variant}"
            );
        }
    }

    /// D85: names that differ only in case: TS registers `dev` and `Dev`; a
    /// `config.toml` holding both is invalid for airs-cli-rs.
    #[test]
    fn d85_names_differing_only_in_case() {
        let setup = |env: &Env| {
            let lower = env.sandbox.add_fixture_tenant(&env.server, "dev", "100");
            let upper = env.sandbox.add_fixture_tenant(&env.server, "Dev", "200");
            env.sandbox.register(&[&upper, &lower], Some("dev"));
        };
        let Some((r, t)) = pair(
            "d85",
            &setup,
            &["tenant", "list", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        assert_eq!(t.json().as_array().map(Vec::len), Some(2), "{t:?}");
        assert_eq!(
            (r.code, r.stderr.clone()),
            (
                1,
                op_error(
                    "Cannot read tenant registry at <REGISTRY>; restore a valid registry before proceeding"
                )
            )
        );
    }

    /// D86: TS lists tenants (and `registered:` names) in registry order; airs-cli-rs in
    /// byte order of the names.
    #[test]
    fn d86_tenant_order_is_byte_order() {
        let setup = |env: &Env| {
            let zeta = env.sandbox.add_fixture_tenant(&env.server, "zeta", "300");
            let alpha = env.sandbox.add_fixture_tenant(&env.server, "alpha", "100");
            env.sandbox.register(&[&zeta, &alpha], None);
        };
        let Some((r, t)) = pair(
            "d86_list",
            &setup,
            &["tenant", "list", "--output", "json"],
            &no_options,
        ) else {
            return;
        };
        let names = |side: &Side| -> Vec<String> {
            side.json()
                .as_array()
                .expect("rows")
                .iter()
                .map(|row| row["name"].as_str().unwrap_or_default().to_owned())
                .collect()
        };
        assert_eq!(names(&t), ["zeta", "alpha"]);
        assert_eq!(names(&r), ["alpha", "zeta"]);
        let Some((r, t)) = pair("d86_registered", &setup, LIST, &no_options) else {
            return;
        };
        assert!(t.stderr.contains("(registered: zeta, alpha)"), "{t:?}");
        assert!(r.stderr.contains("(registered: alpha, zeta)"), "{r:?}");
    }

    /// D90: with only a TypeScript registry, the airs-cli-rs "nothing registered"
    /// messages name it and `tenant import`; TS has no second store and lists it.
    #[test]
    fn d90_import_suffix() {
        let suffix = "; a TypeScript tenant registry exists at <ROOT>/state/tenants.json: run 'airs tenant import' to copy it";
        let cases: [(&[&str], String); 3] = [
            (
                LIST,
                op_error(&format!(
                    "No tenant selected. Run 'airs tenant create <name>' and then 'airs tenant switch <name>'{suffix}"
                )),
            ),
            (
                &["tenant", "read"],
                op_error(&format!(
                    "No tenant selected; run 'airs tenant create <name>' first{suffix}"
                )),
            ),
            (
                &["tenant", "list"],
                format!("  Run 'airs tenant create <name>' to register one{suffix}.\n"),
            ),
        ];
        for (args, expected) in cases {
            let Some((r, t)) = pair("d90", &ts_only, args, &no_options) else {
                return;
            };
            assert_eq!(r.raw_stderr, expected, "{args:?}");
            assert_ne!(t.stderr, r.stderr, "{args:?}");
            assert!(!t.stderr.contains("tenant import"), "{t:?}");
        }
    }
}
