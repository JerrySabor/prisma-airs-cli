//! TS-vs-Rust parity tests for `doctor` (DESIGN §9, §12 D19–D25 and related rows).
//!
//! Each scenario runs against BOTH CLIs, each on a fresh sandbox and fixture server.
//! The TypeScript doctor has 11 checks and Rust has 8 (D19), so the comparison is on
//! the intersection of the seven shared check names, by status, detail and hint; the
//! Rust `Gateway API` check (TS `AI Gateway API`, D227, D250) is compared in its own
//! tests. Paths are compared after replacing each sandbox root with `<ROOT>`. Request
//! logs are compared normalised: the Rust log without its `Gateway API` probe must equal
//! the start of the TS log, and the TS remainder may only be its AI Gateway probe (a
//! second `token`, then the data-plane workspaces; Rust shares the first token, choice
//! 52).
//!
//! The harness runner always sets `NO_PROXY`, so the Rust Environment detail carries
//! `; proxy variables in effect: NO_PROXY`, which TS never prints: agreement tests strip
//! that suffix and `environment_proxy_suffix_is_rust_only` pins the difference.
//!
//! Every fixture tenant points every endpoint key at the fixture server, so the TS CLI
//! (including its AI Gateway probe) only ever talks to loopback. A missing or unverified reference CLI fails each test (`AIRS_ALLOW_PARITY_SKIP=1`
//! skips it with a `PARITY SKIPPED` notice).

use std::time::Duration;

use airs_test_harness::{
    AuthIdentity, Cli, ClosedPort, FixtureConfig, FixtureServer, Gw, NormalizedRequest, Planned,
    RecordedRequest, RegistryEntry, Route, Run, RunOptions, Sandbox, fixtures,
    normalise_tenant_output, normalize_all, require_ts, run,
};
use serde_json::{Value, json};

const NAMES: [&str; 7] = [
    "Tenant",
    "Config file",
    "Environment",
    "Scanner credentials",
    "Management credentials",
    "Scanner API",
    "Management OAuth",
];
const TS_NAMES: [&str; 11] = [
    "Node.js version",
    "Tenant",
    "Config file",
    "Environment",
    "Scanner credentials",
    "Management credentials",
    "Typesafe credentials",
    "Scanner API",
    "Management OAuth",
    "AI Gateway API",
    "Typesafe API",
];
/// The Rust checks: the shared seven and `Gateway API` (D19, §19.16).
const RUST_NAMES: [&str; 8] = [
    "Tenant",
    "Config file",
    "Environment",
    "Scanner credentials",
    "Management credentials",
    "Scanner API",
    "Management OAuth",
    "Gateway API",
];
const PROXY_SUFFIX: &str = "; proxy variables in effect: NO_PROXY";
const NOT_EVALUATED: &str = "not evaluated — fix the failed checks above first";
const SCANNER_API_SKIP: &str = "skipped — no scanner credentials configured";
const MGMT_OAUTH_SKIP: &str = "skipped — management credentials not configured";
const PROBES: [&str; 2] = ["Scanner API", "Management OAuth"];
const HEADER: &str = "\n  Doctor\n  Prisma AIRS CLI preflight checks\n\n";

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

type Setup<'a> = &'a dyn Fn(&FixtureServer, &Sandbox);
/// Labelled scenario setups for table-driven parity tests.
type Cases = Vec<(&'static str, Box<dyn Fn(&FixtureServer, &Sandbox)>)>;

/// One CLI's run of a scenario.
struct Side {
    /// The run with stdout and stderr through [`normalise_tenant_output`] (each side's
    /// own store paths as `<REGISTRY>` / `<CONFIG:name>`, `airs` in hints as
    /// `airs-cli`).
    out: Run,
    /// The run as printed (for the D73/D89 pins).
    raw: Run,
    requests: Vec<RecordedRequest>,
    root: String,
}

impl Side {
    /// Checks with the sandbox root replaced by `<ROOT>`.
    fn checks(&self) -> Vec<C> {
        parse_checks(&self.out.json(), &self.root)
    }

    fn check(&self, name: &str) -> C {
        self.checks()
            .into_iter()
            .find(|check| check.name == name)
            .unwrap_or_else(|| panic!("{}: check {name} missing", self.out.cli))
    }

    fn stdout(&self) -> String {
        self.out.stdout.replace(&self.root, "<ROOT>")
    }

    fn routes(&self) -> Vec<Route> {
        self.requests.iter().map(|request| request.route).collect()
    }
}

fn side(cli: &Cli, setup: Setup<'_>, args: &[&str], options: &RunOptions) -> Side {
    side_with_store(cli, setup, &|_| {}, args, options)
}

/// [`side`], with `rust_store` changing the provisioned Rust store after `setup` when
/// `cli` is airs-cli-rs (a state the TypeScript files cannot express).
fn side_with_store(
    cli: &Cli,
    setup: Setup<'_>,
    rust_store: &dyn Fn(&Sandbox),
    args: &[&str],
    options: &RunOptions,
) -> Side {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    setup(&server, &sandbox);
    if !cli.is_ts() {
        rust_store(&sandbox);
    }
    let before = sandbox.snapshot();
    let raw = run(cli, &sandbox, args, options);
    sandbox.assert_unchanged(&before);
    let mut out = raw.clone();
    out.stdout = normalise_tenant_output(&raw.stdout, &sandbox);
    out.stderr = normalise_tenant_output(&raw.stderr, &sandbox);
    Side {
        out,
        raw,
        requests: server.requests(),
        root: sandbox.root().display().to_string(),
    }
}

/// Runs the scenario on both CLIs (Rust first); `None` when the reference is absent.
fn both(test: &str, setup: Setup<'_>, args: &[&str], options: RunOptions) -> Option<(Side, Side)> {
    let ts = require_ts(test)?;
    let rust_side = side(&rust(), setup, args, &options);
    let ts_side = side(&ts, setup, args, &options);
    Some((rust_side, ts_side))
}

/// The provisioned Rust tenant file for `configs/prod.json` without `keys` (for a TS
/// config that is invalid only in those keys, whose provisioned file is a TOML error).
fn rust_base_without(sandbox: &Sandbox, keys: &[&str]) -> String {
    let text = std::fs::read_to_string(sandbox.config_path("prod")).expect("config");
    let mut value: Value = serde_json::from_str(&text).expect("json");
    for key in keys {
        value.as_object_mut().expect("object").remove(*key);
    }
    airs_test_harness::store::convert_config(value.to_string().as_bytes())
        .expect("a valid config")
        .to_toml()
}

/// [`both`], with `rust_store` applied to the Rust side's store (see [`side_with_store`]).
fn both_with_store(
    test: &str,
    setup: Setup<'_>,
    rust_store: &dyn Fn(&Sandbox),
    args: &[&str],
    options: RunOptions,
) -> Option<(Side, Side)> {
    let ts = require_ts(test)?;
    let rust_side = side_with_store(&rust(), setup, rust_store, args, &options);
    let ts_side = side(&ts, setup, args, &options);
    Some((rust_side, ts_side))
}

fn json_args() -> [&'static str; 3] {
    ["doctor", "--output", "json"]
}

fn healthy(server: &FixtureServer, sandbox: &Sandbox) {
    sandbox.single_tenant(server, "prod", "100");
}

/// Tenant `prod` / TSG 100 with an edited standard config (still all-loopback).
fn tenant_with(edit: impl Fn(&mut FixtureConfig) + 'static) -> impl Fn(&FixtureServer, &Sandbox) {
    move |server, sandbox| {
        let tenant = sandbox.add_fixture_tenant_with(server, "prod", "100", &edit);
        sandbox.register(&[&tenant], Some("prod"));
    }
}

#[derive(Clone, Debug, PartialEq)]
struct C {
    name: String,
    status: String,
    detail: String,
    hint: Option<String>,
}

fn c(name: &str, status: &str, detail: &str) -> C {
    C {
        name: name.into(),
        status: status.into(),
        detail: detail.into(),
        hint: None,
    }
}

impl C {
    fn hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

fn parse_checks(value: &Value, root: &str) -> Vec<C> {
    let text = |item: &Value, key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .map(|text| text.replace(root, "<ROOT>"))
    };
    value
        .as_array()
        .unwrap_or_else(|| panic!("doctor JSON is not an array: {value}"))
        .iter()
        .map(|item| C {
            name: text(item, "name").unwrap_or_default(),
            status: text(item, "status").unwrap_or_default(),
            detail: text(item, "detail").unwrap_or_default(),
            hint: text(item, "hint"),
        })
        .collect()
}

fn names(all: &[C]) -> Vec<&str> {
    all.iter().map(|check| check.name.as_str()).collect()
}

/// The TS checks restricted to the Rust check names (TS order).
fn intersection(all: &[C]) -> Vec<C> {
    all.iter()
        .filter(|check| NAMES.contains(&check.name.as_str()))
        .cloned()
        .collect()
}

/// The Rust Environment detail without the proxy suffix the runner's NO_PROXY causes,
/// and the management-credential line with TS's `AI Gateway` (D227: Rust names the
/// `gateway` commands).
fn strip_proxy(check: &C) -> C {
    let mut check = check.clone();
    if check.name == "Environment"
        && let Some(stripped) = check.detail.strip_suffix(PROXY_SUFFIX)
    {
        check.detail = stripped.to_owned();
    }
    check.detail = d227(&check.detail);
    check
}

/// D227, D312: the Rust management-credential line names `gateway` and `supplychain`
/// commands (TS `AI Gateway` and `AgentGuard`).
fn d227(text: &str) -> String {
    text.replace(
        "model security, gateway and supplychain",
        "model security, AI Gateway and AgentGuard",
    )
}

/// Exit codes equal, both report the scoped names in order, and every intersection
/// check except `except` is identical (Environment modulo the proxy suffix).
fn assert_checks_agree(rust: &Side, ts: &Side, except: &[&str]) {
    assert_eq!(
        rust.out.code,
        ts.out.code,
        "exit codes differ\nrust: {rust:?}\nts: {ts:?}",
        rust = rust.out,
        ts = ts.out
    );
    assert_eq!(names(&rust.checks()), RUST_NAMES);
    let rust_checks = intersection(&rust.checks());
    let ts_checks = intersection(&ts.checks());
    assert_eq!(names(&rust_checks), NAMES);
    assert_eq!(names(&ts_checks), NAMES);
    for (rust_check, ts_check) in rust_checks.iter().zip(&ts_checks) {
        if except.contains(&rust_check.name.as_str()) {
            continue;
        }
        assert_eq!(
            strip_proxy(rust_check),
            *ts_check,
            "check {}",
            rust_check.name
        );
    }
    assert_eq!(rust.out.stderr, "", "rust json stderr");
    assert_eq!(ts.out.stderr, "", "ts json stderr");
}

/// Normalised requests with the random probe id replaced.
fn normalized(requests: &[RecordedRequest]) -> Vec<NormalizedRequest> {
    normalize_all(requests)
        .into_iter()
        .map(|mut request| {
            for (name, value) in &mut request.query {
                if name == "scan_ids" {
                    *value = "<uuid>".into();
                }
            }
            request
        })
        .collect()
}

/// The Rust request log equals the start of the TS log; the TS remainder is only its AI
/// Gateway probe (token, then workspaces when the token was issued).
fn assert_requests_agree(rust: &Side, ts: &Side) {
    let mut rust_log = normalized(&rust.requests);
    let ts_log = normalized(&ts.requests);
    // The Rust Gateway API probe comes last and shares the Management OAuth token.
    let rust_gateway = rust_log
        .last()
        .is_some_and(|request| request.route == Route::Gateway(Gw::DataWorkspaces))
        .then(|| rust_log.pop())
        .flatten();
    if let Some(probe) = &rust_gateway {
        assert_eq!(
            ts_log.last(),
            Some(probe),
            "both probe the data-plane workspaces alike"
        );
    }
    assert!(
        ts_log.len() >= rust_log.len(),
        "TS sent fewer requests\nrust: {:?}\nts: {:?}",
        rust.requests,
        ts.requests
    );
    let (prefix, rest) = ts_log.split_at(rust_log.len());
    assert_eq!(prefix, rust_log.as_slice(), "request logs differ");
    let rest: Vec<Route> = rest.iter().map(|request| request.route).collect();
    assert!(
        rest.is_empty()
            || rest == [Route::Token]
            || rest == [Route::Token, Route::Gateway(Gw::DataWorkspaces)],
        "unexpected TS-only requests: {rest:?}"
    );
}

/// A pretty report split into header, per-check `(line, hint)` and tail.
struct Pretty {
    header: bool,
    checks: Vec<(String, String, Option<String>)>,
    tail: String,
}

fn parse_pretty(stdout: &str) -> Pretty {
    let header = stdout.starts_with(HEADER);
    let body = stdout.strip_prefix(HEADER).unwrap_or(stdout);
    let mut checks: Vec<(String, String, Option<String>)> = Vec::new();
    let mut rest = body;
    while let Some((line, after)) = rest.split_once('\n') {
        if let Some(hint) = line.strip_prefix("      ") {
            let last = checks
                .last_mut()
                .unwrap_or_else(|| panic!("hint before any check: {line}"));
            last.2 = Some(hint.to_owned());
        } else if let Some(text) = line.strip_prefix("  ").filter(|text| text.contains(" — ")) {
            let (_, named) = text.split_once(' ').unwrap_or_default();
            let name = named.split(" — ").next().unwrap_or_default().to_owned();
            checks.push((name, line.to_owned(), None));
        } else {
            break;
        }
        rest = after;
    }
    Pretty {
        header,
        checks,
        tail: rest.to_owned(),
    }
}

// ---------------------------------------------------------------------------------------
// Scenarios where DESIGN says both CLIs agree
// ---------------------------------------------------------------------------------------

mod agree {
    use super::*;

    #[test]
    fn healthy_json_checks_and_requests() {
        let Some((rust, ts)) = both("healthy_json", &healthy, &json_args(), RunOptions::new())
        else {
            return;
        };
        assert_checks_agree(&rust, &ts, &[]);
        assert_eq!(rust.out.code, 0);
        assert_requests_agree(&rust, &ts);
        assert_eq!(
            ts.routes()[3..],
            [Route::Token, Route::Gateway(Gw::DataWorkspaces)],
            "TS AI Gateway probe stays on loopback"
        );
    }

    #[test]
    fn healthy_pretty_layout() {
        let Some((rust, ts)) = both("healthy_pretty", &healthy, &["doctor"], RunOptions::new())
        else {
            return;
        };
        assert_eq!((rust.out.code, ts.out.code), (0, 0));
        let (rust_pretty, ts_pretty) = (parse_pretty(&rust.stdout()), parse_pretty(&ts.stdout()));
        assert!(rust_pretty.header && ts_pretty.header);
        let ts_lines: Vec<_> = ts_pretty
            .checks
            .iter()
            .filter(|(name, ..)| NAMES.contains(&name.as_str()))
            .cloned()
            .collect();
        assert_eq!(rust_pretty.checks.len(), 8);
        for (rust_line, ts_line) in rust_pretty.checks.iter().zip(&ts_lines) {
            let line = rust_line
                .1
                .strip_suffix(PROXY_SUFFIX)
                .unwrap_or(&rust_line.1);
            assert_eq!(
                (rust_line.0.as_str(), line),
                (ts_line.0.as_str(), ts_line.1.as_str())
            );
            assert_eq!(rust_line.2, ts_line.2, "hint of {}", rust_line.0);
        }
        assert!(rust_pretty.tail.starts_with("\n  ✓ All checks passed"));
        assert!(ts_pretty.tail.starts_with("\n  ✓ All checks passed"));
        assert!(rust_pretty.tail.ends_with("\n\n") && ts_pretty.tail.ends_with("\n\n"));
        assert_eq!((rust.out.stderr.as_str(), ts.out.stderr.as_str()), ("", ""));
        assert_requests_agree(&rust, &ts);
    }

    #[test]
    fn quiet_pretty_suppresses_header_and_hints_on_both() {
        // A warning on both: management credentials missing while the scanner passes.
        let setup = tenant_with(|config| {
            config.remove("mgmtClientId");
        });
        let Some((rust, ts)) = both(
            "quiet_pretty",
            &setup,
            &["doctor", "--quiet"],
            RunOptions::new(),
        ) else {
            return;
        };
        assert_eq!((rust.out.code, ts.out.code), (0, 0));
        for side in [&rust, &ts] {
            let pretty = parse_pretty(&side.stdout());
            assert!(!pretty.header, "{}: header suppressed", side.out.cli);
            assert!(
                pretty.checks.iter().all(|check| check.2.is_none()),
                "hints suppressed"
            );
            assert!(pretty.tail.starts_with("\n  ✓ All checks passed ("));
            assert_eq!(side.out.stderr, "");
        }
        let rust_lines: Vec<String> = parse_pretty(&rust.stdout())
            .checks
            .into_iter()
            .filter(|check| NAMES.contains(&check.0.as_str()))
            .map(|check| d227(check.1.strip_suffix(PROXY_SUFFIX).unwrap_or(&check.1)))
            .collect();
        let ts_lines: Vec<String> = parse_pretty(&ts.stdout())
            .checks
            .into_iter()
            .filter(|check| NAMES.contains(&check.0.as_str()))
            .map(|check| check.1)
            .collect();
        assert_eq!(rust_lines, ts_lines);
    }

    #[test]
    fn failure_summary_goes_to_stderr_on_both() {
        let none = |_: &FixtureServer, _: &Sandbox| {};
        let Some((rust, ts)) = both("failure_summary", &none, &["doctor"], RunOptions::new())
        else {
            return;
        };
        assert_eq!((rust.out.code, ts.out.code), (1, 1));
        assert_eq!(rust.out.stderr, "  ✗ 1 check failed\n");
        assert_eq!(ts.out.stderr, rust.out.stderr);
        for side in [&rust, &ts] {
            let pretty = parse_pretty(&side.stdout());
            assert!(pretty.header);
            assert_eq!(
                pretty.tail, "\n\n",
                "{}: blank, summary on stderr, blank",
                side.out.cli
            );
        }
        let rust_tenant = &parse_pretty(&rust.stdout()).checks[0];
        let ts_tenant = parse_pretty(&ts.stdout())
            .checks
            .into_iter()
            .find(|check| check.0 == "Tenant")
            .unwrap_or_else(|| panic!("TS Tenant line"));
        assert_eq!(*rust_tenant, ts_tenant);
    }

    #[test]
    fn tenant_default_output_is_ignored_by_both() {
        let setup = tenant_with(|config| {
            config.set("defaultOutput", "json");
        });
        let Some((rust, ts)) = both(
            "default_output_ignored",
            &setup,
            &["doctor"],
            RunOptions::new(),
        ) else {
            return;
        };
        assert!(rust.out.stdout.starts_with(HEADER));
        assert!(ts.out.stdout.starts_with(HEADER));
        assert_eq!((rust.out.code, ts.out.code), (0, 0));
    }

    #[test]
    fn global_output_before_the_subcommand() {
        let Some((rust, ts)) = both(
            "global_output",
            &healthy,
            &["--output", "json", "doctor"],
            RunOptions::new(),
        ) else {
            return;
        };
        assert_checks_agree(&rust, &ts, &[]);
    }

    #[test]
    fn no_registry_tenant_and_config_checks() {
        // Scanner API / Management OAuth texts differ: d23_after_a_tenant_failure.
        let none = |_: &FixtureServer, _: &Sandbox| {};
        let Some((rust, ts)) = both("no_registry", &none, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_checks_agree(&rust, &ts, &PROBES);
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn no_selection_lists_registered_names() {
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            let a = sandbox.add_fixture_tenant(server, "a", "100");
            let b = sandbox.add_fixture_tenant(server, "b", "200");
            sandbox.register(&[&a, &b], None);
        };
        let Some((rust, ts)) = both("no_selection", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_checks_agree(&rust, &ts, &PROBES);
        assert_eq!(
            rust.check("Tenant"),
            c("Tenant", "fail", "no tenant selected (registered: a, b)")
                .hint("Run 'airs-cli tenant switch <name>'")
        );
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn config_failures_agree_on_detail_and_hint() {
        // Probe skip texts after a config failure differ: d23_after_a_config_failure.
        // The details agree; the hints name the airs commands that fix the TOML
        // file (D89), so they are compared per CLI.
        let missing = |_: &FixtureServer, sandbox: &Sandbox| {
            let path = sandbox.config_path("prod");
            sandbox.write_registry(&[RegistryEntry::new("prod", &path, "100")], Some("prod"));
        };
        let invalid = tenant_with(|config| {
            config.set("scanConcurrency", 987654);
            config.set("airsNumRetries", "abc");
            config.set("mgmtDashboardEndpoint", "not a url");
            config.set("dlpEndpoint", Value::Null);
        });
        // The same invalid values as TOML (import has no conversion for them).
        let invalid_toml = |sandbox: &Sandbox| {
            let invalid = [
                "airsNumRetries",
                "mgmtDashboardEndpoint",
                "dlpEndpoint",
                "scanConcurrency",
            ];
            sandbox.write_tenant_file_raw(
                "prod",
                format!(
                    "{}airsNumRetries = \"abc\"\nmgmtDashboardEndpoint = \"not a url\"\ndlpEndpoint = 0\nscanConcurrency = 987654\n",
                    rust_base_without(sandbox, &invalid)
                )
                .as_bytes(),
                0o600,
            );
        };
        let mismatch = tenant_with(|config| {
            config.set("mgmtTsgId", "987654321");
        });
        type Case<'a> = (&'a str, Setup<'a>, &'a dyn Fn(&Sandbox), &'a str, &'a str);
        let cases: Vec<Case<'_>> = vec![
            (
                "missing file",
                &missing,
                &|_| {},
                "Restore the file, or register another with 'airs-cli tenant create <name> --config <path>' and delete 'prod'",
                "Restore the file, or delete the tenant with 'airs-cli tenant delete prod' and create it again",
            ),
            (
                "invalid values",
                &invalid,
                &invalid_toml,
                "Fix them with 'airs-cli tenant set <name> <key>' (values are never printed here)",
                "Correct them in the file, then re-run doctor (values are never printed here; 'airs-cli tenant set' refuses an invalid file)",
            ),
            (
                "TSG mismatch",
                &mismatch,
                &|_| {},
                "Register the file under a new tenant name with 'airs-cli tenant create <name> --config <path>'",
                "Choose the TSG with 'airs-cli tenant set prod mgmtTsgId <tsg>'; it updates both files",
            ),
        ];
        for (label, setup, store, ts_hint, rust_hint) in cases {
            let Some((rust, ts)) =
                both_with_store(label, setup, store, &json_args(), RunOptions::new())
            else {
                return;
            };
            let mut except = PROBES.to_vec();
            except.push("Config file");
            assert_checks_agree(&rust, &ts, &except);
            let (r, t) = (rust.check("Config file"), ts.check("Config file"));
            assert_eq!(
                (r.status.as_str(), r.detail.as_str()),
                ("fail", t.detail.as_str()),
                "{label}"
            );
            assert_eq!(t.hint.as_deref(), Some(ts_hint), "{label}");
            assert_eq!(r.hint.as_deref(), Some(rust_hint), "{label} (D89)");
            assert!(
                rust.requests.is_empty() && ts.requests.is_empty(),
                "{label}"
            );
            assert!(!rust.out.stdout.contains("987654") && !ts.out.stdout.contains("987654"));
        }
    }

    #[test]
    fn credential_variants() {
        let cases: Cases = vec![
            (
                "no scanner key",
                Box::new(tenant_with(|config| {
                    config.remove("airsApiKey");
                })),
            ),
            (
                "token only",
                Box::new(tenant_with(|config| {
                    config.remove("airsApiKey");
                    config.set("airsApiToken", "FAKE-APITOKEN-100");
                })),
            ),
            (
                "key and token",
                Box::new(tenant_with(|config| {
                    config.set("airsApiToken", "FAKE-APITOKEN-100");
                })),
            ),
            (
                "management missing (warn)",
                Box::new(tenant_with(|config| {
                    config.remove("mgmtClientId");
                    config.remove("mgmtClientSecret");
                })),
            ),
            (
                "everything missing (fail)",
                Box::new(tenant_with(|config| {
                    config.remove("mgmtClientId");
                    config.remove("mgmtClientSecret");
                    config.remove("airsApiKey");
                })),
            ),
        ];
        for (label, setup) in &cases {
            let Some((rust, ts)) = both(label, setup.as_ref(), &json_args(), RunOptions::new())
            else {
                return;
            };
            assert_checks_agree(&rust, &ts, &[]);
            assert_requests_agree(&rust, &ts);
        }
    }

    #[test]
    fn scanner_probe_status_outcomes() {
        for (status, code) in [(401, 1), (403, 1), (404, 0), (400, 0)] {
            let setup = move |server: &FixtureServer, sandbox: &Sandbox| {
                healthy(server, sandbox);
                server.set_default(Route::ScanResults, Planned::empty_json(status));
            };
            let Some((rust, ts)) = both("scanner_status", &setup, &json_args(), RunOptions::new())
            else {
                return;
            };
            assert_checks_agree(&rust, &ts, &[]);
            assert_eq!(rust.out.code, code, "HTTP {status}");
            assert_requests_agree(&rust, &ts);
        }
    }

    #[test]
    fn scanner_probe_hang_times_out_on_both() {
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(Route::ScanResults, Planned::hang());
        };
        let Some((rust, ts)) = both("scanner_hang", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_checks_agree(&rust, &ts, &[]);
        assert_eq!(
            rust.check("Scanner API").detail,
            "timed out after 5000ms — network unreachable or endpoint not responding"
        );
        assert_requests_agree(&rust, &ts);
    }

    #[test]
    fn topics_counts_and_paging() {
        let cases: Vec<(&str, Vec<Value>)> = vec![
            ("one topic", vec![fixtures::topic(1, "fin", 1, "f")]),
            (
                "two topics",
                vec![
                    fixtures::topic(1, "fin", 1, "f"),
                    fixtures::topic(2, "legal", 1, "l"),
                ],
            ),
            (
                "revisions",
                vec![
                    fixtures::topic(1, "fin", 1, "f"),
                    fixtures::topic(1, "fin", 2, "f"),
                ],
            ),
            (
                "three pages",
                (1..=250)
                    .map(|n| fixtures::topic(n, &format!("t{n}"), 1, "d"))
                    .collect(),
            ),
        ];
        for (label, rows) in cases {
            let setup = move |server: &FixtureServer, sandbox: &Sandbox| {
                healthy(server, sandbox);
                server.set_topics("100", rows.clone());
            };
            let Some((rust, ts)) = both(label, &setup, &json_args(), RunOptions::new()) else {
                return;
            };
            assert_checks_agree(&rust, &ts, &[]);
            assert_requests_agree(&rust, &ts);
        }
    }

    #[test]
    fn token_401_detail() {
        // DESIGN §9 adopts the TS wording `management API error (HTTP 401): …`.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(Route::Token, Planned::empty_json(401));
        };
        let Some((rust, ts)) = both("token_401", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_requests_agree(&rust, &ts);
        assert_checks_agree(&rust, &ts, &[]);
    }

    #[test]
    fn token_schema_mismatch_detail() {
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(
                Route::Token,
                Planned::json(200, &json!({"token_type": "Bearer"})),
            );
        };
        let Some((rust, ts)) = both("token_schema", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_checks_agree(&rust, &ts, &[]);
        assert_requests_agree(&rust, &ts);
    }

    #[test]
    fn token_hang_times_out_on_both() {
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(Route::Token, Planned::hang());
        };
        let Some((rust, ts)) = both("token_hang", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_checks_agree(&rust, &ts, &[]);
        assert_requests_agree(&rust, &ts);
    }
}

// ---------------------------------------------------------------------------------------
// Intentional divergences (DESIGN §12): both sides' actual behaviour is pinned
// ---------------------------------------------------------------------------------------

mod divergence {
    use super::*;

    #[test]
    fn d19_check_sets() {
        // D19: TS reports 11 checks, Rust 8: the 7 shared ones in the same relative order
        // and `Gateway API` (TS `AI Gateway API`, D227) last.
        let Some((rust, ts)) = both("d19", &healthy, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(names(&rust.checks()), RUST_NAMES);
        assert_eq!(
            rust.check("Gateway API"),
            c(
                "Gateway API",
                "pass",
                "endpoint reachable (0 workspaces in scope)"
            )
        );
        assert_eq!(names(&ts.checks()), TS_NAMES);
        assert_eq!(names(&intersection(&ts.checks())), NAMES);
        assert_eq!(
            ts.check("Typesafe credentials").status,
            "skip",
            "fixture leaves typesafeApiKey unset, so TS makes no Typesafe request"
        );
        assert_eq!(
            ts.check("AI Gateway API"),
            c(
                "AI Gateway API",
                "pass",
                "endpoint reachable (0 workspaces in scope)"
            )
        );
    }

    #[test]
    fn d20_scanner_5xx_and_429() {
        // D20: TS counts 5xx/429 as pass; Rust fails 5xx and warns on 429.
        for (status, rust_status, rust_detail, rust_code) in [
            (
                500,
                "fail",
                "scanner API error (HTTP 500): AISEC_SERVER_SIDE_ERROR:API error 500",
                1,
            ),
            (
                503,
                "fail",
                "scanner API error (HTTP 503): AISEC_SERVER_SIDE_ERROR:API error 503",
                1,
            ),
            (
                429,
                "warn",
                "endpoint reachable, but rate limited (HTTP 429): AISEC_CLIENT_SIDE_ERROR:API error 429",
                0,
            ),
        ] {
            let setup = move |server: &FixtureServer, sandbox: &Sandbox| {
                healthy(server, sandbox);
                server.set_default(
                    Route::ScanResults,
                    Planned::empty_json(status).with_retry_after(0),
                );
            };
            let Some((rust, ts)) = both("d20", &setup, &json_args(), RunOptions::new()) else {
                return;
            };
            assert_eq!(ts.out.code, 0);
            assert_eq!(
                ts.check("Scanner API"),
                c(
                    "Scanner API",
                    "pass",
                    &format!("endpoint reachable, API key accepted (HTTP {status} on probe query)")
                )
            );
            assert_eq!(rust.out.code, rust_code);
            let check = rust.check("Scanner API");
            assert_eq!(
                (check.status.as_str(), check.detail.as_str()),
                (rust_status, rust_detail)
            );
            assert_checks_agree_except_code(&rust, &ts, &["Scanner API"]);
            assert_requests_agree(&rust, &ts);
        }
    }

    /// Like `assert_checks_agree` without the exit-code comparison.
    fn assert_checks_agree_except_code(rust: &Side, ts: &Side, except: &[&str]) {
        let ts_checks = intersection(&ts.checks());
        for (rust_check, ts_check) in rust.checks().iter().zip(&ts_checks) {
            if !except.contains(&rust_check.name.as_str()) {
                assert_eq!(
                    strip_proxy(rust_check),
                    *ts_check,
                    "check {}",
                    rust_check.name
                );
            }
        }
    }

    /// D72, D89: unknown and retired keys: TS warns and lists them in file order; a TOML
    /// tenant file with them is invalid, so the airs-cli-rs check fails, listing them in
    /// byte order with the TypeScript-name hint.
    #[test]
    fn d89_unknown_and_retired_keys() {
        let setup = tenant_with(|config| {
            let retired = config
                .get_str("mgmtTokenEndpoint")
                .unwrap_or_default()
                .to_owned();
            config.set("zeta", 1);
            config.set("redTeamTokenEndpoint", retired);
            config.set("alpha", true);
        });
        let store = |sandbox: &Sandbox| {
            sandbox.append_tenant_line(
                "prod",
                "zeta = 1\nredTeamTokenEndpoint = \"http://127.0.0.1:1/t\"\nalpha = true",
            );
        };
        let Some((rust, ts)) = both_with_store(
            "unknown_keys",
            &setup,
            &store,
            &json_args(),
            RunOptions::new(),
        ) else {
            return;
        };
        assert_eq!(
            ts.check("Config file"),
            c(
                "Config file",
                "warn",
                "valid at <CONFIG:prod>; ignored 3 keys: zeta, redTeamTokenEndpoint, alpha"
            )
            .hint("Every product authenticates through mgmtTokenEndpoint now (redTeamTokenEndpoint ignored); remove them with 'airs-cli tenant unset <name> <key>'")
        );
        assert_eq!(
            rust.check("Config file"),
            c(
                "Config file",
                "fail",
                "<CONFIG:prod> has unknown keys: alpha, redTeamTokenEndpoint, zeta"
            )
            .hint("TypeScript names are not accepted: aiGw* keys are now gateway*, agentGuard* keys are now supplychain*, and dataDir, typesafe* and *TokenEndpoint keys were dropped; edit the file or re-import it with 'airs-cli tenant import --replace'")
        );
        assert_eq!((rust.out.code, ts.out.code), (1, 0));
        assert!(rust.requests.is_empty());
    }

    #[test]
    fn d21_oversized_config() {
        // D21: TS reads the >1 MiB file plainly (warns about the padding key, then cannot
        // inspect it and exits 0); Rust fails the Config file check.
        let setup = tenant_with(|config| {
            config.set("padding", "x".repeat(1_100_000));
        });
        // The Rust tenant file is made over 1 MiB as well (with a TOML comment).
        let store = |sandbox: &Sandbox| {
            sandbox.append_tenant_line("prod", &format!("# {}", "x".repeat(1_100_000)));
        };
        let Some((rust, ts)) =
            both_with_store("d21_big", &setup, &store, &json_args(), RunOptions::new())
        else {
            return;
        };
        assert_eq!(
            rust.check("Config file"),
            c(
                "Config file",
                "fail",
                "<CONFIG:prod> cannot be read (not a regular file, larger than 1 MiB, or unreadable)"
            )
        );
        assert_eq!(rust.out.code, 1);
        assert_eq!(
            ts.check("Config file"),
            c(
                "Config file",
                "warn",
                "valid at <CONFIG:prod>; ignored 1 key: padding"
            )
            .hint("Remove unknown keys with 'airs-cli tenant unset <name> <key>'")
        );
        assert_eq!(ts.check("Scanner credentials").detail, NOT_EVALUATED);
        assert_eq!(ts.out.code, 0, "TS false healthy");
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn d21_config_directory() {
        // D21: TS reports any read error as "not found"; for airs-cli-rs a directory at
        // the tenant-file path is not a private regular file (D79).
        let setup = |_: &FixtureServer, sandbox: &Sandbox| {
            let path = sandbox.config_path("prod");
            std::fs::create_dir(&path).unwrap_or_else(|err| panic!("mkdir: {err}"));
            sandbox.write_registry(&[RegistryEntry::new("prod", &path, "100")], Some("prod"));
        };
        let store = |sandbox: &Sandbox| {
            sandbox.detach_store();
            let path = sandbox.store_tenant_path("prod");
            std::fs::remove_file(&path).unwrap_or_else(|err| panic!("remove: {err}"));
            std::fs::create_dir(&path).unwrap_or_else(|err| panic!("mkdir: {err}"));
        };
        let Some((rust, ts)) =
            both_with_store("d21_dir", &setup, &store, &json_args(), RunOptions::new())
        else {
            return;
        };
        assert_eq!(
            rust.check("Config file"),
            c(
                "Config file",
                "fail",
                "<CONFIG:prod> is not private: it must be a regular file (not a symlink) owned by the current user with no group or other permissions"
            )
            .hint("Make it a regular file owned by you with mode 0600 (directories 0700), then re-run doctor")
        );
        assert_eq!(ts.check("Config file").detail, "not found at <CONFIG:prod>");
        assert_eq!((rust.out.code, ts.out.code), (1, 1));
    }

    #[test]
    fn d22_whitespace_scanner_key() {
        // D22: TS presence is untrimmed (pass), then its probe fails locally; Rust skips.
        let setup = tenant_with(|config| {
            config.set("airsApiKey", "   ");
        });
        let Some((rust, ts)) = both("d22_key", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(rust.check("Scanner credentials").status, "skip");
        assert_eq!(
            rust.check("Scanner API"),
            c("Scanner API", "skip", SCANNER_API_SKIP)
        );
        assert_eq!(rust.out.code, 0);
        assert_eq!(
            ts.check("Scanner credentials"),
            c("Scanner credentials", "pass", "airsApiKey (file)")
        );
        assert_eq!(
            ts.check("Scanner API"),
            c(
                "Scanner API",
                "fail",
                "network unreachable: Scanner credentials are not configured (airsApiKey or airsApiToken). Run 'airs-cli tenant set prod <key>' for airsApiKey (secrets prompt hidden, or use --stdin)"
            )
            .hint("Check network connectivity, proxy settings, and DNS")
        );
        assert_eq!(ts.out.code, 1);
        assert!(!rust.routes().contains(&Route::ScanResults));
        assert!(!ts.routes().contains(&Route::ScanResults));
    }

    #[test]
    fn d22_whitespace_client_secret() {
        // D22.
        let setup = tenant_with(|config| {
            config.set("mgmtClientSecret", "   ");
        });
        let Some((rust, ts)) = both("d22_secret", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(rust.check("Management credentials").status, "warn");
        assert_eq!(
            rust.check("Management OAuth"),
            c("Management OAuth", "skip", MGMT_OAUTH_SKIP)
        );
        assert_eq!(rust.out.code, 0);
        assert_eq!(ts.check("Management credentials").status, "pass");
        let ts_oauth = ts.check("Management OAuth");
        assert_eq!(ts_oauth.status, "fail");
        assert!(ts_oauth.detail.starts_with(
            "network unreachable: Management credentials are not configured (missing mgmtClientSecret)."
        ));
        assert_eq!(ts.out.code, 1);
        assert!(!rust.routes().contains(&Route::Token) && !ts.routes().contains(&Route::Token));
    }

    #[test]
    fn d23_after_a_config_failure() {
        // D23: TS says "skipped — …" although nothing was evaluated; Rust says notEvaluated.
        let setup = tenant_with(|config| {
            config.set("mgmtTsgId", "987654321");
        });
        let Some((rust, ts)) = both("d23_config", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(
            rust.check("Scanner API"),
            c("Scanner API", "skip", NOT_EVALUATED)
        );
        assert_eq!(
            rust.check("Management OAuth"),
            c("Management OAuth", "skip", NOT_EVALUATED)
        );
        assert_eq!(
            ts.check("Scanner API"),
            c("Scanner API", "skip", SCANNER_API_SKIP)
        );
        assert_eq!(
            ts.check("Management OAuth"),
            c("Management OAuth", "skip", MGMT_OAUTH_SKIP)
        );
        // The credential checks themselves agree (notEvaluated on both).
        assert_eq!(
            rust.check("Scanner credentials"),
            ts.check("Scanner credentials")
        );
        assert_eq!(
            rust.check("Management credentials"),
            ts.check("Management credentials")
        );
    }

    #[test]
    fn d23_after_a_tenant_failure() {
        // D23 (same texts when no tenant is selected).
        let none = |_: &FixtureServer, _: &Sandbox| {};
        let Some((rust, ts)) = both("d23_tenant", &none, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(rust.check("Scanner API").detail, NOT_EVALUATED);
        assert_eq!(rust.check("Management OAuth").detail, NOT_EVALUATED);
        assert_eq!(ts.check("Scanner API").detail, SCANNER_API_SKIP);
        assert_eq!(ts.check("Management OAuth").detail, MGMT_OAUTH_SKIP);
        assert_eq!(ts.check("Typesafe credentials").detail, NOT_EVALUATED);
    }

    #[test]
    fn d24_sdk_diagnostic_variables() {
        // D24: TS lists PANW_AI_SEC_DEBUG* / TIMEOUT_MS as "SDK diagnostics on" (and logs
        // hashed requests to stderr); Rust reports them as ignored variables.
        let options = RunOptions::new()
            .env("PANW_AI_SEC_DEBUG", "1")
            .env("PANW_AI_SEC_TIMEOUT_MS", "30000")
            .env("PANW_MGMT_TSG_ID", "4815162342");
        let Some((rust, ts)) = both("d24", &healthy, &json_args(), options) else {
            return;
        };
        assert_eq!(
            rust.check("Environment").detail,
            "ignored 3 variables: PANW_AI_SEC_DEBUG, PANW_AI_SEC_TIMEOUT_MS, PANW_MGMT_TSG_ID; proxy variables in effect: NO_PROXY"
        );
        assert_eq!(
            ts.check("Environment").detail,
            "ignored 1 variable: PANW_MGMT_TSG_ID; SDK diagnostics on: PANW_AI_SEC_DEBUG, PANW_AI_SEC_TIMEOUT_MS"
        );
        assert_eq!(rust.check("Environment").hint, ts.check("Environment").hint);
        assert_eq!(rust.out.stderr, "");
        assert!(
            ts.out.stderr.contains("[airs-sdk] → GET"),
            "{}",
            ts.out.stderr
        );
        assert_eq!((rust.out.code, ts.out.code), (0, 0));
        assert_requests_agree(&rust, &ts);
    }

    #[test]
    fn d25_registry_failure_hint() {
        // D25: the TS hint mentions the ignored PRISMA_AIRS_CONFIG_PATH.
        let setup = |_: &FixtureServer, sandbox: &Sandbox| {
            sandbox.write_registry_raw(b"{ corrupt");
        };
        let Some((rust, ts)) = both("d25", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        let rust_tenant = rust.check("Tenant");
        let ts_tenant = ts.check("Tenant");
        // The corrupt registry is provisioned as a corrupt config.toml: the same text
        // with each side's own path.
        assert_eq!(rust_tenant.detail, ts_tenant.detail);
        assert_eq!(
            rust_tenant.detail,
            "Cannot read tenant registry at <REGISTRY>; restore a valid registry before proceeding"
        );
        assert_eq!(
            rust.raw.json()[0]["hint"],
            format!("Fix or restore {}/store/config.toml", rust.root)
        );
        assert_eq!(
            ts_tenant.hint.as_deref(),
            Some(
                "Restore or remove <REGISTRY>; PRISMA_AIRS_CONFIG_PATH bypasses the registry meanwhile"
            )
        );
        // Every later check is notEvaluated on both (including the probes).
        let ts_checks = intersection(&ts.checks());
        for (rust_check, ts_check) in rust.checks().iter().zip(&ts_checks).skip(1) {
            assert_eq!(rust_check, ts_check);
            assert_eq!(rust_check.detail, NOT_EVALUATED);
        }
        assert_eq!((rust.out.code, ts.out.code), (1, 1));
    }

    #[test]
    fn d25_relative_xdg_state_home_hint() {
        // D25 (no path to name): TS for a relative XDG_STATE_HOME, airs-cli-rs for a
        // relative AIRS_CLI_CONFIG_DIR (each CLI ignores the other variable).
        let none = |_: &FixtureServer, _: &Sandbox| {};
        let options = RunOptions::new()
            .without_env("PRISMA_AIRS_TENANTS_PATH")
            .env("XDG_STATE_HOME", "relative/state")
            .env("AIRS_CLI_CONFIG_DIR", "relative/store");
        let Some((rust, ts)) = both("d25_xdg", &none, &json_args(), options) else {
            return;
        };
        assert_eq!(
            rust.check("Tenant").detail,
            "AIRS_CLI_CONFIG_DIR must be an absolute path"
        );
        assert_eq!(
            ts.check("Tenant").detail,
            "XDG_STATE_HOME must be an absolute path"
        );
        assert_eq!(
            rust.check("Tenant").hint.as_deref(),
            Some("Set AIRS_CLI_CONFIG_DIR or XDG_CONFIG_HOME to an absolute path")
        );
        assert_eq!(
            ts.check("Tenant").hint.as_deref(),
            Some(
                "Restore or remove the tenant registry; PRISMA_AIRS_CONFIG_PATH bypasses the registry meanwhile"
            )
        );
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn d11_scanner_rejection_server_text() {
        // D11: TS echoes the server message; Rust prints `API error <s>`.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(
                Route::ScanResults,
                Planned::json(401, &json!({"message": "bad key"})),
            );
        };
        let Some((rust, ts)) = both("d11", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(
            rust.check("Scanner API").detail,
            "API key rejected (HTTP 401): AISEC_CLIENT_SIDE_ERROR:API error 401"
        );
        assert_eq!(
            ts.check("Scanner API").detail,
            "API key rejected (HTTP 401): AISEC_CLIENT_SIDE_ERROR:bad key"
        );
        assert_eq!(rust.check("Scanner API").hint, ts.check("Scanner API").hint);
        assert_checks_agree(&rust, &ts, &["Scanner API"]);
    }

    #[test]
    fn d49_topics_403_without_refresh_replay() {
        // D49: both CLIs report the 403 the same way, but the Rust probe makes one
        // attempt while TS refreshes the token and replays once.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(Route::Topics, Planned::empty_json(403));
        };
        let Some((rust, ts)) = both("topics_403", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_checks_agree(&rust, &ts, &[]);
        // The refused lease is dropped, so the Gateway API probe fetches its own token
        // (choice 99).
        assert_eq!(
            rust.routes(),
            vec![
                Route::ScanResults,
                Route::Token,
                Route::Topics,
                Route::Token,
                Route::Gateway(Gw::DataWorkspaces)
            ]
        );
        let ts_routes = ts.routes();
        assert_eq!(
            &ts_routes[..5],
            &[
                Route::ScanResults,
                Route::Token,
                Route::Topics,
                Route::Token,
                Route::Topics
            ]
        );
    }

    #[test]
    fn d10_topics_500_retries() {
        // D10: TS retries 500; the Rust SDK does not retry 500 and reports the status.
        // TS's backoff is jittered, so it either runs out of the 5 s doctor budget (the
        // usual case locally) or out of retries first and reports the 500 (seen on CI).
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(Route::Topics, Planned::empty_json(500));
        };
        let Some((rust, ts)) = both("d10", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(
            rust.check("Management OAuth").detail,
            "management API error (HTTP 500): AISEC_SERVER_SIDE_ERROR:API error 500"
        );
        assert_eq!(
            rust.routes(),
            vec![
                Route::ScanResults,
                Route::Token,
                Route::Topics,
                Route::Gateway(Gw::DataWorkspaces)
            ]
        );
        let ts_detail = ts.check("Management OAuth").detail;
        assert!(
            [
                "timed out after 5000ms — network unreachable or endpoint not responding",
                "management API error (HTTP 500): AISEC_SERVER_SIDE_ERROR:API error 500",
            ]
            .contains(&ts_detail.as_str()),
            "{ts_detail}"
        );
        let ts_topics = ts
            .routes()
            .iter()
            .filter(|route| **route == Route::Topics)
            .count();
        assert!(
            ts_topics > 1,
            "TS retried the 500 ({ts_topics} topics requests)"
        );
        assert_eq!((rust.out.code, ts.out.code), (1, 1));
    }

    #[test]
    fn d30_scanner_redirect() {
        // D30: TS follows the 302 (re-sending x-pan-token) to a loopback 404 and passes;
        // Rust never follows redirects.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(
                Route::ScanResults,
                Planned::redirect(302, &server.url("/elsewhere")),
            );
        };
        let Some((rust, ts)) = both("d30", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(
            rust.check("Scanner API"),
            c(
                "Scanner API",
                "fail",
                "AISEC_CLIENT_SIDE_ERROR:Redirect responses are not followed"
            )
            .hint("Fix airsApiEndpoint in the tenant file")
        );
        assert!(!rust.routes().contains(&Route::Unknown));
        assert_eq!(
            ts.check("Scanner API").detail,
            "endpoint reachable, API key accepted (HTTP 404 on probe query)"
        );
        let followed = ts
            .requests
            .iter()
            .find(|request| request.path == "/elsewhere")
            .unwrap_or_else(|| panic!("TS followed the redirect"));
        assert!(matches!(followed.auth, AuthIdentity::ApiKey { .. }));
        assert_eq!((rust.out.code, ts.out.code), (1, 0));
    }

    #[test]
    fn d28_non_digit_tsg() {
        // D28: TS sends a non-numeric TSG to the token endpoint; Rust fails locally.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            let tenant = sandbox.add_fixture_tenant(server, "prod", "abc");
            sandbox.register(&[&tenant], Some("prod"));
        };
        let Some((rust, ts)) = both("d28", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(
            rust.check("Management OAuth").detail,
            "Invalid mgmtTsgId: the Rust SDK requires 1-32 ASCII digits"
        );
        assert_eq!(rust.routes(), vec![Route::ScanResults]);
        assert_eq!(
            ts.check("Management OAuth").detail,
            "OAuth token obtained, topics API answered (0 custom topics)"
        );
        assert!(ts.routes().contains(&Route::Token));
        assert_eq!((rust.out.code, ts.out.code), (1, 0));
    }

    #[test]
    fn d38_scanner_non_json_body() {
        // D38: TS has a distinct non-JSON text (classified as network unreachable); Rust
        // reports the generic response-validation message.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(
                Route::ScanResults,
                Planned::raw(200, "application/json", "{not json"),
            );
        };
        let Some((rust, ts)) = both("d38", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(
            rust.check("Scanner API"),
            c(
                "Scanner API",
                "fail",
                "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema"
            )
            .hint("Fix airsApiEndpoint in the tenant file")
        );
        assert_eq!(
            ts.check("Scanner API"),
            c(
                "Scanner API",
                "fail",
                "network unreachable: AISEC_RESPONSE_VALIDATION:Response body is not valid JSON"
            )
            .hint("Check network connectivity, proxy settings, and DNS")
        );
        assert_checks_agree(&rust, &ts, &["Scanner API"]);
    }

    #[test]
    fn d27_invalid_utf8_config() {
        // D27: TS decodes lossily (the file "passes" with an unknown key); Rust rejects it.
        // Every endpoint stays on loopback (harness guard); no credentials, so neither CLI
        // probes anything.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            let text = Sandbox::fixture_config(server, "100")
                .without("airsApiKey")
                .without("mgmtClientId")
                .without("mgmtClientSecret")
                .with("x", "INVALID-UTF8")
                .to_json();
            let (head, tail) = text.split_once("INVALID-UTF8").expect("placeholder");
            let bytes = [head.as_bytes(), b"\xff", tail.as_bytes()].concat();
            let path = sandbox.write_config_raw("prod", &bytes);
            sandbox.write_registry(&[RegistryEntry::new("prod", &path, "100")], Some("prod"));
        };
        // The TOML tenant file gets the same invalid byte (in a TOML comment).
        let store = |sandbox: &Sandbox| {
            let mut bytes = std::fs::read(sandbox.store_tenant_path("prod")).expect("tenant file");
            bytes.extend_from_slice(b"# x \xff\n");
            sandbox.write_tenant_file_raw("prod", &bytes, 0o600);
        };
        let Some((rust, ts)) =
            both_with_store("d27", &setup, &store, &json_args(), RunOptions::new())
        else {
            return;
        };
        assert_eq!(
            rust.check("Config file"),
            c("Config file", "fail", "<CONFIG:prod> is not valid TOML")
                .hint("Fix the file, then re-run doctor")
        );
        assert_eq!(
            ts.check("Config file").detail,
            "valid at <CONFIG:prod>; ignored 1 key: x"
        );
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    /// D52 (doctor): a control character in the TSG reaches TS's pretty bullet line and
    /// table Detail cell raw; airs-cli-rs writes U+FFFD in both. (The config path, the
    /// 0.2 carrier, is the airs-cli-rs tenant file now, whose name cannot hold one.)
    #[test]
    fn d52_control_characters_doctor() {
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            let tsg = "10\u{1b}[31m\t0";
            let tenant = sandbox.add_fixture_tenant(server, "prod", tsg);
            sandbox.write_registry(
                &[RegistryEntry::new("prod", &tenant.config_path, tsg)],
                Some("prod"),
            );
        };
        let raw = |text: &str| text.chars().any(|c| c.is_control() && c != '\n');
        for args in [&["doctor"][..], &["doctor", "--output", "table"]] {
            let Some((rust, ts)) = both("d52_doctor", &setup, args, RunOptions::new()) else {
                return;
            };
            // Both fail later checks on this TSG (D28 for airs-cli-rs); the Tenant line
            // is what carries the text.
            let line = |side: &Side| {
                side.stdout()
                    .lines()
                    .find(|line| line.contains("selected in"))
                    .unwrap_or_else(|| panic!("no tenant line: {}", side.stdout()))
                    .to_owned()
            };
            assert!(
                line(&ts).contains("(TSG 10\u{1b}[31m\t0)"),
                "TS raw: {}",
                line(&ts)
            );
            assert!(
                line(&rust).contains("(TSG 10\u{fffd}[31m\u{fffd}0)"),
                "Rust: {}",
                line(&rust)
            );
            assert!(!raw(&rust.out.stdout), "Rust stdout: {}", rust.out.stdout);
            assert!(!raw(&rust.out.stderr), "Rust stderr: {}", rust.out.stderr);
        }
    }

    #[test]
    fn d2_invalid_output_format() {
        // D2 (and ts-doctor.md §6): TS throws an uncaught CliUsageError (stack trace, exit
        // 1); Rust reports a usage error (exit 2). Neither sends a request.
        let Some((rust, ts)) = both(
            "d2",
            &healthy,
            &["doctor", "--output", "bogus"],
            RunOptions::new(),
        ) else {
            return;
        };
        assert_eq!(rust.out.code, 2);
        assert_eq!(
            rust.out.stderr,
            "\n  ✗ Invalid output format 'bogus'. Expected: pretty, table, json\n\n"
        );
        assert_eq!(ts.out.code, 1);
        assert!(ts.out.stderr.contains(
            "CliUsageError: Invalid output format 'bogus'. Expected: pretty, table, markdown, csv, json, yaml"
        ));
        assert_eq!((rust.out.stdout.as_str(), ts.out.stdout.as_str()), ("", ""));
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn d1_excess_argument() {
        // D1: commander exits 1, clap exits 2.
        let Some((rust, ts)) = both("d1", &healthy, &["doctor", "extra"], RunOptions::new()) else {
            return;
        };
        assert_eq!(rust.out.code, 2);
        assert!(rust.out.stderr.contains("unexpected argument 'extra'"));
        assert_eq!(ts.out.code, 1);
        assert_eq!(
            ts.out.stderr,
            "error: too many arguments for 'doctor'. Expected 0 arguments but got 1.\n"
        );
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn d33_tenant_flag() {
        // D33: --tenant is Rust-only.
        let Some((rust, ts)) = both(
            "d33",
            &healthy,
            &["doctor", "--tenant", "prod", "--output", "json"],
            RunOptions::new(),
        ) else {
            return;
        };
        assert_eq!(rust.out.code, 0);
        assert_eq!(
            rust.check("Tenant").detail,
            "prod (TSG 100) selected by --tenant in <REGISTRY>"
        );
        assert_eq!(ts.out.code, 1);
        assert_eq!(ts.out.stderr, "error: unknown option '--tenant'\n");
        assert!(ts.requests.is_empty());
    }

    /// D42 (narrowed in 0.2): a name outside the six TS names is an uncaught
    /// `CliUsageError` in TS (stack trace, exit 1) and a usage error here (exit 2).
    #[test]
    fn d42_unknown_format_name() {
        let Some((rust, ts)) = both(
            "d42",
            &healthy,
            &["doctor", "--output", "xml"],
            RunOptions::new(),
        ) else {
            return;
        };
        assert_eq!(
            (
                rust.out.code,
                rust.out.stdout.as_str(),
                rust.out.stderr.as_str()
            ),
            (
                2,
                "",
                "\n  ✗ Invalid output format 'xml'. Expected: pretty, table, json\n\n"
            )
        );
        assert_eq!(ts.out.code, 1);
        assert!(
            ts.out
                .stderr
                .contains("CliUsageError: Invalid output format 'xml'"),
            "{:?}",
            ts.out
        );
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    /// D50: the dropped formats: TS renders the report, airs-cli-rs exits 2 before
    /// reading the tenant.
    #[test]
    fn d50_dropped_formats_doctor() {
        for (format, marker) in [
            ("yaml", "name: Tenant"),
            ("csv", "Name,Status,Detail,Hint"),
            ("markdown", "| Name | Status | Detail | Hint |"),
        ] {
            let Some((rust, ts)) = both(
                "d50_doctor",
                &healthy,
                &["doctor", "--output", format],
                RunOptions::new(),
            ) else {
                return;
            };
            assert_eq!(
                (
                    rust.out.code,
                    rust.out.stdout.clone(),
                    rust.out.stderr.clone()
                ),
                (
                    2,
                    String::new(),
                    format!(
                        "\n  ✗ Invalid output format '{format}'. Expected: pretty, table, json\n\n"
                    )
                )
            );
            assert!(rust.requests.is_empty());
            assert_eq!(ts.out.code, 0, "{:?}", ts.out);
            assert!(ts.out.stdout.contains(marker), "{}", ts.out.stdout);
        }
    }

    /// D51: `defaultOutput` naming a dropped format passes the TS config check; the
    /// airs-cli-rs check fails naming the key, and its hint (for any invalid
    /// `defaultOutput`) lists the formats that remain.
    #[test]
    fn d51_default_output_dropped_doctor() {
        for value in ["yaml", "xml"] {
            let setup = tenant_with(move |config| {
                config.set("defaultOutput", value);
            });
            // Import drops a dead format (and has no conversion for xml), so the TOML
            // file is given the value directly: D51 holds for the store.
            let line = format!("defaultOutput = \"{value}\"");
            let store = move |sandbox: &Sandbox| {
                if value == "xml" {
                    sandbox.write_tenant_file_raw(
                        "prod",
                        format!("{}{line}\n", rust_base_without(sandbox, &["defaultOutput"]))
                            .as_bytes(),
                        0o600,
                    );
                } else {
                    sandbox.set_tenant_line("prod", "defaultOutput", &line);
                }
            };
            let Some((rust, ts)) = both_with_store(
                "d51_doctor",
                &setup,
                &store,
                &json_args(),
                RunOptions::new(),
            ) else {
                return;
            };
            let config = rust.check("Config file");
            assert_eq!(
                config,
                c(
                    "Config file",
                    "fail",
                    "<CONFIG:prod> has invalid values for: defaultOutput"
                )
                .hint("Correct them in the file, then re-run doctor (values are never printed here; 'airs-cli tenant set' refuses an invalid file); defaultOutput accepts only pretty, table or json (markdown, csv and yaml were dropped)")
            );
            assert_eq!(rust.out.code, 1);
            let ts_config = ts.check("Config file");
            if value == "yaml" {
                assert_eq!(ts_config.status, "pass", "{ts_config:?}");
            } else {
                assert_eq!(ts_config.detail, config.detail);
                assert_eq!(
                    ts_config.hint.as_deref(),
                    Some(
                        "Fix them with 'airs-cli tenant set <name> <key>' (values are never printed here)"
                    )
                );
            }
        }
    }

    #[test]
    fn environment_proxy_suffix_is_rust_only() {
        // Not in §12 (D36 covers proxies): Rust appends the proxy variables in effect.
        let Some((rust, ts)) = both("proxy_suffix", &healthy, &json_args(), RunOptions::new())
        else {
            return;
        };
        assert_eq!(
            rust.check("Environment").detail,
            "no configuration variables set; proxy variables in effect: NO_PROXY"
        );
        assert_eq!(
            ts.check("Environment").detail,
            "no configuration variables set"
        );
    }

    #[test]
    fn connection_refused_texts() {
        // Not in §12 (D11-style secret-safe texts): TS embeds `fetch failed`; for a refused
        // token endpoint TS also classifies it as "authentication failed".
        let (scan_closed, token_closed) = (ClosedPort::new(), ClosedPort::new());
        let (scan_port, token_port) = (scan_closed.port(), token_closed.port());
        let setup = tenant_with(move |config| {
            config.set(
                "airsApiEndpoint",
                format!("http://127.0.0.1:{scan_port}/scan"),
            );
            config.set(
                "mgmtTokenEndpoint",
                format!("http://127.0.0.1:{token_port}/oauth/token"),
            );
        });
        let Some((rust, ts)) = both("refused", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(
            rust.check("Scanner API").detail,
            "network unreachable: AISEC_CLIENT_SIDE_ERROR:Network request failed (connection refused, reset or unreachable)"
        );
        assert_eq!(
            ts.check("Scanner API").detail,
            "network unreachable: AISEC_CLIENT_SIDE_ERROR:fetch failed"
        );
        assert_eq!(rust.check("Scanner API").hint, ts.check("Scanner API").hint);
        assert_eq!(
            rust.check("Management OAuth").detail,
            "network unreachable: AISEC_OAUTH_ERROR:Token request failed: network error"
        );
        assert_eq!(
            ts.check("Management OAuth").detail,
            "authentication failed: AISEC_OAUTH_ERROR:Token request failed: fetch failed"
        );
        assert_eq!(
            rust.check("Management OAuth").hint,
            ts.check("Management OAuth").hint
        );
        assert_eq!((rust.out.code, ts.out.code), (1, 1));
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn doctor_probe_timeout_is_wall_clock_bounded_on_both() {
        // D31: both bound each probe at 5 s; a hung token costs TS a second 5 s for its
        // AI Gateway token, so TS takes about twice as long.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(Route::Token, Planned::hang());
        };
        let Some((rust, ts)) = both("d31", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert!(
            rust.out.elapsed < Duration::from_secs(9),
            "{:?}",
            rust.out.elapsed
        );
        assert!(
            ts.out.elapsed >= Duration::from_secs(9),
            "{:?}",
            ts.out.elapsed
        );
        assert_eq!(
            ts.check("AI Gateway API").detail,
            "timed out after 5000ms — network unreachable or endpoint not responding"
        );
    }

    /// D227: TS's check `AI Gateway API` is `Gateway API`, and the management-credential
    /// line names `gateway` commands (TS `AI Gateway`; from 0.11 also `supplychain`, D312).
    #[test]
    fn d227_the_doctor_names_the_gateway() {
        let setup = tenant_with(|config| {
            config.remove("mgmtClientId");
        });
        let Some((rust, ts)) = both("d227_doctor", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        let tail = |text: &str| text.split(" — ").nth(1).unwrap_or_default().to_owned();
        assert_eq!(
            tail(&rust.check("Management credentials").detail),
            "management, red team, model security, gateway and supplychain commands are unavailable"
        );
        assert_eq!(
            tail(&ts.check("Management credentials").detail),
            "management, red team, model security, AI Gateway and AgentGuard commands are unavailable"
        );
        assert_eq!(
            rust.check("Gateway API"),
            c("Gateway API", "skip", MGMT_OAUTH_SKIP)
        );
        assert_eq!(
            ts.check("AI Gateway API"),
            c("AI Gateway API", "skip", MGMT_OAUTH_SKIP)
        );
        assert!(!names(&rust.checks()).contains(&"AI Gateway API"));
    }

    /// D312: the management-credential line names `supplychain` commands (TS
    /// `AgentGuard`), as a warning when the scanner credentials passed and a failure
    /// otherwise; the rest of the line and the hint are TypeScript's.
    #[test]
    fn d312_the_doctor_names_supplychain_commands() {
        let setup = tenant_with(|config| {
            config.remove("mgmtClientSecret");
        });
        let Some((rust, ts)) = both("d312_doctor", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        let (r, t) = (
            rust.check("Management credentials"),
            ts.check("Management credentials"),
        );
        assert_eq!(r.status, t.status);
        assert_eq!(
            r.detail,
            "missing: mgmtClientSecret — management, red team, model security, gateway and supplychain commands are unavailable"
        );
        assert_eq!(
            t.detail,
            "missing: mgmtClientSecret — management, red team, model security, AI Gateway and AgentGuard commands are unavailable"
        );
        assert!(!r.detail.contains("AgentGuard"));
    }

    /// D250, D49: the Rust probe shares the Management OAuth token and makes one attempt,
    /// classifying each status (a 5xx fails at once, a 429 warns, every 403 gets the
    /// data-plane hint, a malformed 2xx names the endpoint setting); TS requests a second
    /// token, retries a 5xx into its 5 s timeout, fails a 429, gives the admin-plane hint
    /// without `AB03` in the message and calls a malformed 2xx `network unreachable`.
    #[test]
    fn d250_the_gateway_api_check() {
        let data_hint = "The service account is missing a workspace-scope grant (data plane, /ai_gw/v2). SCM Access Management edits the existing role row by default — use \"Add Role\" so the account ends up with both role rows, not one row moved.";
        // Healthy: one token for both Rust probes, two on the TS side.
        let Some((rust, ts)) = both("d250_healthy", &healthy, &json_args(), RunOptions::new())
        else {
            return;
        };
        let tokens = |side: &Side| {
            side.routes()
                .iter()
                .filter(|route| **route == Route::Token)
                .count()
        };
        assert_eq!((tokens(&rust), tokens(&ts)), (1, 2));
        assert_eq!(
            rust.check("Gateway API").detail,
            ts.check("AI Gateway API").detail
        );
        let gateway = Route::Gateway(Gw::DataWorkspaces);
        let count = |side: &Side| {
            side.routes()
                .iter()
                .filter(|route| **route == gateway)
                .count()
        };
        for (status, rust_status, rust_detail, rust_hint, ts_status) in [
            (
                503,
                "fail",
                "gateway API error (HTTP 503): AISEC_SERVER_SIDE_ERROR:API error 503",
                "Retry later; check the AIRS service status",
                "fail",
            ),
            (
                429,
                "warn",
                "endpoint reachable, but rate limited (HTTP 429): AISEC_CLIENT_SIDE_ERROR:API error 429",
                "Retry later",
                "fail",
            ),
            (
                403,
                "warn",
                "endpoint reachable, but access denied (HTTP 403): AISEC_CLIENT_SIDE_ERROR:API error 403",
                data_hint,
                "warn",
            ),
        ] {
            let setup = move |server: &FixtureServer, sandbox: &Sandbox| {
                healthy(server, sandbox);
                server.set_default(
                    Route::Gateway(Gw::DataWorkspaces),
                    Planned::empty_json(status).with_retry_after(0),
                );
            };
            let Some((rust, ts)) = both("d250", &setup, &json_args(), RunOptions::new()) else {
                return;
            };
            assert_eq!(
                rust.check("Gateway API"),
                c("Gateway API", rust_status, rust_detail).hint(rust_hint),
                "{status}"
            );
            assert_eq!(count(&rust), 1, "{status}: one attempt");
            let ts_check = ts.check("AI Gateway API");
            assert_eq!(ts_check.status, ts_status, "{status}: {ts_check:?}");
            match status {
                503 => {
                    // TS retries the 5xx: into its 5 s timeout, or (with `Retry-After: 0`)
                    // out of retries first.
                    assert!(
                        [
                            "timed out after 5000ms — network unreachable or endpoint not responding",
                            "AI Gateway API error (HTTP 503): AISEC_SERVER_SIDE_ERROR:API error 503",
                        ]
                        .contains(&ts_check.detail.as_str()),
                        "{ts_check:?}"
                    );
                    assert!(count(&ts) > 1, "TS retries the 5xx");
                }
                429 => assert!(
                    ts_check
                        .detail
                        .starts_with("AI Gateway API error (HTTP 429)")
                ),
                _ => assert_eq!(
                    ts_check.hint.as_deref(),
                    Some(
                        "the service account is missing a tenant-root admin grant (admin plane, /ai_gw/admin/v2). SCM Access Management edits the existing role row by default — use \"Add Role\" so the account ends up with both role rows, not one row moved."
                    ),
                    "TS: the admin-plane hint without AB03 in the message"
                ),
            }
        }
        // A malformed 2xx.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(
                Route::Gateway(Gw::DataWorkspaces),
                Planned::json(200, &json!({"object": 5})),
            );
        };
        let Some((rust, ts)) = both("d250_malformed", &setup, &json_args(), RunOptions::new())
        else {
            return;
        };
        let check = rust.check("Gateway API");
        assert!(check.detail.starts_with("gateway API error: "), "{check:?}");
        assert_eq!(
            check.hint.as_deref(),
            Some("Fix gatewayDataEndpoint in the tenant file")
        );
        assert!(
            ts.check("AI Gateway API")
                .detail
                .starts_with("network unreachable: AISEC_RESPONSE_VALIDATION"),
            "{:?}",
            ts.check("AI Gateway API")
        );
        // A token failure: Rust does not probe (not evaluated); TS asks for a second token.
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(Route::Token, Planned::empty_json(401));
        };
        let Some((rust, ts)) = both("d250_token", &setup, &json_args(), RunOptions::new()) else {
            return;
        };
        assert_eq!(
            rust.check("Gateway API"),
            c("Gateway API", "skip", NOT_EVALUATED)
        );
        assert_eq!((tokens(&rust), tokens(&ts)), (1, 2));
        assert_eq!(ts.check("AI Gateway API").status, "fail");
    }
}

// ---------------------------------------------------------------------------------------
// doctor --output table (§9, R§3.9): TS has eleven checks (D19), so the widths differ;
// the shared checks' cells must agree.
// ---------------------------------------------------------------------------------------

mod table {
    use super::*;

    /// `(name, status, detail, hint)` per body row of a doctor table, cells trimmed.
    fn rows(stdout: &str) -> Vec<C> {
        let lines: Vec<&str> = stdout.lines().collect();
        assert!(lines.len() >= 3, "not a table: {stdout:?}");
        let header: Vec<&str> = lines[0].split('│').map(str::trim).collect();
        assert_eq!(header, ["Name", "Status", "Detail", "Hint"], "{stdout}");
        assert!(lines[1].chars().all(|c| c == '─' || c == '┼'), "{stdout}");
        assert!(lines[0].starts_with(' ') && lines[0].ends_with(' '));
        lines[2..]
            .iter()
            .map(|line| {
                let cells: Vec<&str> = line.split('│').map(str::trim).collect();
                assert_eq!(cells.len(), 4, "{line}");
                C {
                    name: cells[0].into(),
                    status: cells[1].into(),
                    detail: cells[2].into(),
                    hint: Some(cells[3])
                        .filter(|hint| !hint.is_empty())
                        .map(str::to_owned),
                }
            })
            .collect()
    }

    fn assert_tables_agree(rust: &Side, ts: &Side) {
        assert_eq!(rust.out.code, ts.out.code, "{:?}\n{:?}", rust.out, ts.out);
        assert_eq!((rust.out.stderr.as_str(), ts.out.stderr.as_str()), ("", ""));
        assert!(rust.out.stdout.ends_with(" \n") && ts.out.stdout.ends_with(" \n"));
        let rust_rows = rows(&rust.stdout());
        let ts_rows = rows(&ts.stdout());
        assert_eq!(names(&rust_rows), RUST_NAMES);
        assert_eq!(names(&ts_rows), TS_NAMES);
        for (rust_row, ts_row) in intersection(&rust_rows).iter().zip(&intersection(&ts_rows)) {
            assert_eq!(strip_proxy(rust_row), *ts_row, "check {}", rust_row.name);
        }
        assert_requests_agree(rust, ts);
    }

    #[test]
    fn doctor_table_shape() {
        let rejected = |server: &FixtureServer, sandbox: &Sandbox| {
            healthy(server, sandbox);
            server.set_default(
                Route::ScanResults,
                Planned::json(401, &json!({"error": {"message": "bad key"}})),
            );
        };
        let cases: Cases = vec![
            ("healthy", Box::new(healthy)),
            (
                "missing scanner key",
                Box::new(tenant_with(|config| {
                    config.remove("airsApiKey");
                })),
            ),
        ];
        for (label, setup) in &cases {
            let Some((rust, ts)) = both(
                label,
                setup.as_ref(),
                &["doctor", "--output", "table"],
                RunOptions::new(),
            ) else {
                return;
            };
            assert_tables_agree(&rust, &ts);
        }
        // A rejected key: exit 1 on both, still nothing on stderr; the shared cells
        // agree except the Scanner API detail text (D11 server text).
        let Some((rust, ts)) = both(
            "rejected",
            &rejected,
            &["--output", "table", "doctor"],
            RunOptions::new(),
        ) else {
            return;
        };
        assert_eq!((rust.out.code, ts.out.code), (1, 1));
        assert_eq!((rust.out.stderr.as_str(), ts.out.stderr.as_str()), ("", ""));
        let scanner = |side: &Side| {
            rows(&side.stdout())
                .into_iter()
                .find(|row| row.name == "Scanner API")
                .expect("Scanner API row")
        };
        let (r, t) = (scanner(&rust), scanner(&ts));
        assert_eq!((r.status.as_str(), t.status.as_str()), ("fail", "fail"));
        assert_eq!(r.hint, t.hint);
        assert!(
            r.detail.starts_with("API key rejected (HTTP 401): "),
            "{r:?}"
        );
    }

    #[test]
    fn doctor_table_quiet() {
        let Some((rust, ts)) = both(
            "table_quiet",
            &healthy,
            &["doctor", "--output", "table", "--quiet"],
            RunOptions::new(),
        ) else {
            return;
        };
        assert_tables_agree(&rust, &ts);
        let loud = side(
            &super::rust(),
            &healthy,
            &["doctor", "--output", "table"],
            &RunOptions::new(),
        );
        assert_eq!(rust.stdout(), loud.stdout(), "--quiet changes nothing");
    }

    /// The pretty report under forced colour: the shared check lines, hints and the
    /// summary carry the same escape codes (glyph per status, dim hint, green summary).
    #[test]
    fn doctor_pretty_forced_colour() {
        let setup = tenant_with(|config| {
            config.remove("airsApiKey");
        });
        let Some(ts) = require_ts("doctor_pretty_forced_colour") else {
            return;
        };
        let forced = |name: &str| RunOptions::new().without_env("NO_COLOR").env(name, "1");
        let rust_side = side(&rust(), &setup, &["doctor"], &forced("CLICOLOR_FORCE"));
        let ts_side = side(&ts, &setup, &["doctor"], &forced("FORCE_COLOR"));
        let (r, t) = (rust_side.stdout(), ts_side.stdout());
        let header = "\n  \u{1b}[1mDoctor\u{1b}[22m\n  \u{1b}[2mPrisma AIRS CLI preflight checks\u{1b}[22m\n\n";
        assert!(r.starts_with(header) && t.starts_with(header), "{r}\n{t}");
        for line in [
            "  \u{1b}[32m✓\u{1b}[39m Tenant — prod (TSG 100) selected in <REGISTRY>\n",
            "  \u{1b}[33m○\u{1b}[39m Scanner credentials — not configured — runtime scan, bulk-scan and topics eval are unavailable\n",
            "  \u{1b}[2m    Run 'airs-cli tenant set prod <key>' for airsApiKey (secrets prompt hidden, or use --stdin)\u{1b}[22m\n",
        ] {
            assert!(r.contains(line) && t.contains(line), "{line:?}\n{r}\n{t}");
        }
        assert!(
            r.ends_with("\n  \u{1b}[32m✓ All checks passed (2 skipped)\u{1b}[39m\n\n"),
            "{r}"
        );
        assert!(t.contains("  \u{1b}[32m✓ All checks passed ("), "{t}");
    }
}

// ---------------------------------------------------------------------------------------
// M4t: the doctor and the TOML store (D89)
// ---------------------------------------------------------------------------------------
mod store {
    use super::*;

    /// D89: with only a TypeScript registry, TS passes its Tenant check; the airs-cli-rs
    /// Tenant check fails with the import hint, and every check after it is the
    /// no-tenant outcome.
    #[test]
    fn d89_doctor_import_case() {
        let setup = |server: &FixtureServer, sandbox: &Sandbox| {
            sandbox.single_tenant(server, "prod", "100");
        };
        let store = |sandbox: &Sandbox| sandbox.ts_only();
        let Some((rust, ts)) = both_with_store(
            "d89_import",
            &setup,
            &store,
            &json_args(),
            RunOptions::new(),
        ) else {
            return;
        };
        assert_eq!(ts.check("Tenant").status, "pass", "{:?}", ts.out);
        assert_eq!(
            rust.raw.json()[0],
            json!({
                "name": "Tenant",
                "status": "fail",
                "detail": format!(
                    "no airs tenants in {root}/store/config.toml; a TypeScript tenant registry exists at {root}/state/tenants.json",
                    root = rust.root
                ),
                "hint": "Run 'airs tenant import' to copy its tenants (the TypeScript files are not changed)"
            })
        );
        assert_eq!(rust.check("Config file").detail, NOT_EVALUATED);
        assert_eq!(rust.out.code, 1);
        assert!(rust.requests.is_empty());
    }
}
