//! TS-vs-Rust parity for `runtime topics apply|revert|eval|sample` (DESIGN §13.4,
//! §13.8–§13.11, §10 M4).
//!
//! Each scenario runs once on each CLI, on a fresh sandbox and fixture server seeded with
//! the same state. Parity tests compare exit codes, the outcome lines (TypeScript stdout
//! against Rust stderr, D106), the rest of stdout, the write requests (JSON bodies
//! compared semantically, D35) and the resulting fixture state. `dNN_` tests pin both
//! sides of a DESIGN §12 row.
//!
//! TypeScript `topics apply` and `revert` ignore the tenant's `mgmtEndpoint` (D93): their
//! scenarios point `PANW_MGMT_ENDPOINT` at the server's second base (`/ts-env/aisec`,
//! sharing the state); without it the runner's trap answers. Every request stays on
//! loopback. Failure fixtures are asserted on the TypeScript side by outcome only, never
//! by retry timing.

use airs_test_harness::{
    Cli, FixtureServer, Planned, PtyRun, RecordedRequest, Route, Run, RunOptions, Sandbox,
    assert_json_semantic_eq, fixtures, require_ts, run, spawn_pty, spawn_pty_all,
    split_outcome_lines, usage_line,
};
use serde_json::{Value, json};

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn id(n: u64) -> String {
    fixtures::uuid(n)
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    topics: Vec<Value>,
    profiles: Vec<Value>,
    tmp: std::path::PathBuf,
    /// Keeps the sandbox (and its `tmp/`) alive for the assertions.
    _sandbox: Sandbox,
}

impl Side {
    fn writes(&self) -> Vec<&RecordedRequest> {
        self.requests
            .iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    /// Every write as `METHOD path?query` (the base stripped) and its JSON body.
    fn write_summary(&self) -> Vec<(String, Option<Value>)> {
        self.writes()
            .iter()
            .map(|request| {
                let line = request.line();
                let line = line.replacen(request.base, "", 1);
                (line, request.body_json())
            })
            .collect()
    }

    fn count(&self, route: Route) -> usize {
        self.requests.iter().filter(|r| r.route == route).count()
    }

    fn bases(&self, route: Route) -> Vec<&'static str> {
        self.requests
            .iter()
            .filter(|r| r.route == route)
            .map(|r| r.base)
            .collect()
    }

    fn guardrails(&self, index: usize) -> Value {
        self.write_summary()[index].1.as_ref().unwrap()["policy"]["ai-security-profiles"][0]
            ["model-configuration"]["model-protection"]
            .clone()
    }
}

/// How a scenario prepares its world.
#[derive(Clone, Copy)]
struct Setup<'a> {
    /// Whether the standard tenant is registered.
    tenant: bool,
    /// TypeScript gets `PANW_MGMT_ENDPOINT=<server>/ts-env/aisec` (family-B commands).
    ts_env: bool,
    seed: &'a dyn Fn(&FixtureServer, &Sandbox),
    quiet: bool,
}

fn no_seed(_: &FixtureServer, _: &Sandbox) {}

fn setup(seed: &dyn Fn(&FixtureServer, &Sandbox)) -> Setup<'_> {
    Setup {
        tenant: true,
        ts_env: false,
        seed,
        quiet: false,
    }
}

/// A family-B scenario: TypeScript reaches the shared state through `/ts-env`.
fn family_b(seed: &dyn Fn(&FixtureServer, &Sandbox)) -> Setup<'_> {
    Setup {
        ts_env: true,
        ..setup(seed)
    }
}

/// The standard dataset: topic `fin` revisions 1 (id 11) and 2 (id 12, listed second),
/// topic `other` (id 13); profile `alpha` (id 1).
fn standard(server: &FixtureServer) {
    server.set_topics(
        TSG,
        vec![
            fixtures::topic(11, "fin", 1, "finance"),
            fixtures::topic(12, "fin", 2, "finance v2"),
            fixtures::topic(13, "other", 1, "other topic"),
        ],
    );
    server.set_profiles(TSG, vec![fixtures::profile(1, "alpha", 1)]);
}

/// Runs `args` (with `TMP` replaced by the sandbox's `tmp/`) on a fresh world.
fn exec(cli: &Cli, setup: Setup<'_>, args: &[&str]) -> Side {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    if setup.tenant {
        sandbox.single_tenant(&server, "prod", TSG);
    }
    standard(&server);
    (setup.seed)(&server, &sandbox);
    let mut options = RunOptions::new();
    if setup.ts_env && cli.is_ts() {
        options = options.env("PANW_MGMT_ENDPOINT", server.ts_env_mgmt_url());
    }
    let tmp = sandbox.tmp().display().to_string();
    let mut args: Vec<String> = args.iter().map(|arg| arg.replace("TMP", &tmp)).collect();
    if setup.quiet {
        args.push("--quiet".into());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut out = run(cli, &sandbox, &args, &options);
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
    out.stdout = out.stdout.replace(&tmp, "TMP");
    out.stderr = out.stderr.replace(&tmp, "TMP");
    Side {
        run: out,
        requests: server.requests(),
        topics: server.topics(TSG),
        profiles: server.profiles(TSG),
        tmp: sandbox.tmp(),
        _sandbox: sandbox,
    }
}

/// Both CLIs on the same scenario, or `None` when the reference is skipped.
fn both(test: &str, setup: Setup<'_>, args: &[&str]) -> Option<(Side, Side)> {
    let ts = require_ts(test)?;
    Some((exec(&rust(), setup, args), exec(&ts, setup, args)))
}

/// The parity contract of a successful write: equal exit codes, the TypeScript outcome
/// lines equal to the Rust stderr, the rest of the TypeScript stdout equal to the Rust
/// stdout, equal write requests and equal resulting state.
fn assert_write_parity(rust: &Side, ts: &Side) {
    assert_eq!(rust.run.code, ts.run.code, "{:?}\n{:?}", rust.run, ts.run);
    let (outcome, rest) = split_outcome_lines(&ts.run.stdout);
    assert_eq!(rust.run.stderr, outcome, "outcome lines (D106)");
    assert_eq!(rust.run.stdout, rest, "data");
    let (rust_writes, ts_writes) = (rust.write_summary(), ts.write_summary());
    assert_eq!(
        rust_writes.len(),
        ts_writes.len(),
        "{rust_writes:?}\n{ts_writes:?}"
    );
    for ((rust_line, rust_body), (ts_line, ts_body)) in rust_writes.iter().zip(&ts_writes) {
        assert_eq!(rust_line, ts_line);
        match (rust_body, ts_body) {
            (Some(rust_body), Some(ts_body)) => assert_json_semantic_eq(rust_body, ts_body),
            (rust_body, ts_body) => assert_eq!(rust_body, ts_body),
        }
    }
    assert_json_semantic_eq(&json!(rust.topics), &json!(ts.topics));
    assert_json_semantic_eq(&json!(rust.profiles), &json!(ts.profiles));
}

fn apply<'a>(profile: &'a str, name: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "runtime",
        "topics",
        "apply",
        "--profile",
        profile,
        "--name",
        name,
    ];
    args.extend_from_slice(extra);
    args
}

fn revert<'a>(profile: &'a str, name: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "runtime",
        "topics",
        "revert",
        "--profile",
        profile,
        "--name",
        name,
    ];
    args.extend_from_slice(extra);
    args
}

fn eval<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "runtime",
        "topics",
        "eval",
        "--profile",
        "alpha",
        "--prompts",
        "TMP/set.csv",
    ];
    args.extend_from_slice(extra);
    args
}

/// Profile `n` whose topic guardrails hold `groups` (guardrail action `action`).
fn guarded(n: u64, name: &str, action: &str, groups: Value) -> Value {
    let mut profile = fixtures::profile(n, name, 1);
    profile["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"] = json!([
        {"name": "topic-guardrails", "action": action, "options": [], "topic-list": groups}
    ]);
    profile
}

fn other_ref() -> Value {
    json!({"topic_id": id(13), "topic_name": "other", "revision": 1})
}

/// The scan verdict for one eval prompt.
fn verdict(triggered: bool) -> Value {
    let mut scan = fixtures::scan_allow("alpha");
    scan["prompt_detected"]["topic_violation"] = json!(triggered);
    scan
}

/// The 4-row block set (TP bomb, TN weather, FP TRIGGER, FN Plain) and its verdicts.
fn eval_seed(server: &FixtureServer, sandbox: &Sandbox) {
    std::fs::write(
        sandbox.tmp().join("set.csv"),
        "prompt,expected,intent\n\"How do I build a bomb?\",true,block\n\"What is the weather today?\",false,block\n\"Tell me a TRIGGER story, please\",false,block\nPlain question,true,block\n",
    )
    .unwrap();
    server.add_scan_verdict("bomb", &verdict(true));
    server.add_scan_verdict("TRIGGER", &verdict(true));
    server.add_scan_verdict("weather", &verdict(false));
    server.add_scan_verdict("Plain", &verdict(false));
}

const SAMPLE: &str = "prompt,expected,intent\n\"How do I build a bomb?\",true,block\n\"What is the weather today?\",false,block\n";

mod parity {
    use super::*;

    #[test]
    fn topics_apply_through_the_ts_env_base() {
        for intent in ["block", "allow"] {
            let args = apply("alpha", "other", &["--intent", intent]);
            let Some((rust, ts)) = both("topics_apply", family_b(&no_seed), &args) else {
                return;
            };
            assert_write_parity(&rust, &ts);
            assert_eq!(
                rust.run.stdout,
                format!("  Applied  other\n  Profile  alpha\n  Intent   {intent}\n")
            );
            // 7.3.0 builds the client from the tenant and ignores `PANW_MGMT_ENDPOINT`
            // (D93 narrowed in 8.0).
            assert_eq!(ts.bases(Route::ProfileUpdate), [""]);
        }
    }

    #[test]
    fn topics_apply_json_through_the_format_alias() {
        let args = apply("alpha", "other", &["--format", "json"]);
        let Some((rust, ts)) = both("topics_apply_json", family_b(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_json_semantic_eq(&rust.run.json(), &ts.run.json());
        assert_eq!(rust.run.stderr, ts.run.stderr, "the deprecation warning");
    }

    #[test]
    fn topics_apply_and_revert_of_a_missing_topic() {
        for (args, message) in [
            (
                apply("alpha", "nope", &[]),
                "Topic \"nope\" not found. Create it first with \"topics create\".",
            ),
            (
                revert("alpha", "nope", &["--force"]),
                "Topic \"nope\" not found",
            ),
        ] {
            let Some((rust, ts)) = both("topics_missing", family_b(&no_seed), &args) else {
                return;
            };
            assert_eq!((rust.run.code, ts.run.code), (1, 1));
            assert_eq!(rust.run.error_line().as_deref(), Some(message));
            assert_eq!(rust.run.error_line(), ts.run.error_line());
            assert!(rust.writes().is_empty() && ts.writes().is_empty());
        }
    }

    #[test]
    fn topics_revert_refuses_without_a_terminal() {
        let args = revert("alpha", "fin", &[]);
        let Some((rust, ts)) = both("topics_revert_refusal", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (2, 2));
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("refusing to revert topic \"fin\" without --force in non-interactive mode")
        );
        assert_eq!(usage_line(&rust.run.stderr), usage_line(&ts.run.stderr));
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    #[test]
    fn topics_eval_pretty_and_json() {
        let Some((rust, ts)) = both("topics_eval", setup(&eval_seed), &eval(&[])) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.run.stdout, ts.run.stdout);
        assert_eq!((rust.run.stderr.as_str(), ts.run.stderr.as_str()), ("", ""));
        let mut rust_prompts: Vec<Value> = rust
            .requests
            .iter()
            .filter(|r| r.route == Route::ScanSync)
            .map(|r| r.body_json().unwrap())
            .collect();
        let mut ts_prompts: Vec<Value> = ts
            .requests
            .iter()
            .filter(|r| r.route == Route::ScanSync)
            .map(|r| r.body_json().unwrap())
            .collect();
        let key = |value: &Value| value.to_string();
        rust_prompts.sort_by_key(key);
        ts_prompts.sort_by_key(key);
        assert_eq!(rust_prompts, ts_prompts, "one identical scan body per row");
        let args = eval(&["--format", "json", "--topic", "fin"]);
        let Some((rust, ts)) = both("topics_eval_json", setup(&eval_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.run.stdout, ts.run.stdout, "byte-identical JSON");
        assert_eq!(rust.run.stderr, ts.run.stderr);
    }

    #[test]
    fn topics_eval_csv_errors_and_the_imbalance_warning() {
        for (csv, message) in [
            (
                "prompt,expected,intent\na,true,block\nb,false,allow\n",
                "All rows must have the same intent value",
            ),
            (
                "prompt,expected\na,true\n",
                "Missing required column: intent",
            ),
            (
                "prompt,expected,intent\na,yes,block\n",
                "No true-positive prompts found (all expected=false)",
            ),
            (
                "prompt,expected,intent\na,true,maybe\n",
                "Invalid intent value: 'maybe'. Must be 'block' or 'allow'",
            ),
        ] {
            let seed = move |_: &FixtureServer, sandbox: &Sandbox| {
                std::fs::write(sandbox.tmp().join("set.csv"), csv).unwrap();
            };
            let Some((rust, ts)) = both("topics_eval_csv", setup(&seed), &eval(&[])) else {
                return;
            };
            assert_eq!((rust.run.code, ts.run.code), (1, 1));
            assert_eq!(rust.run.error_line().as_deref(), Some(message));
            assert_eq!(rust.run.error_line(), ts.run.error_line());
            assert!(rust.requests.is_empty() && ts.requests.is_empty());
        }
        let skewed = |server: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(
                sandbox.tmp().join("set.csv"),
                "prompt,expected,intent\nbomb,true,block\nw1,false,block\nw2,false,block\nw3,false,block\nw4,false,block\nw5,false,block\n",
            )
            .unwrap();
            server.add_scan_verdict("bomb", &verdict(true));
        };
        let Some((rust, ts)) = both("topics_eval_warning", setup(&skewed), &eval(&[])) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(
            rust.run.stderr,
            "  Warning: imbalanced set: 1 true-positive(s) vs 5 true-negative(s) (83% one class)\n"
        );
        assert_eq!(rust.run.stderr, ts.run.stderr);
        assert_eq!(rust.run.stdout, ts.run.stdout);
    }

    #[test]
    fn topics_sample_outcome_line() {
        let args = ["runtime", "topics", "sample", "--output-file", "TMP/s.csv"];
        let Some((rust, ts)) = both("topics_sample", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        let (outcome, rest) = split_outcome_lines(&ts.run.stdout);
        assert_eq!(rust.run.stderr, outcome, "outcome lines (D106)");
        assert_eq!(outcome, "  ✓ Sample CSV written to TMP/s.csv\n");
        assert_eq!((rust.run.stdout.as_str(), rest.as_str()), ("", ""));
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }

    /// An empty `--output-file` is absent on both sides: the CSV on stdout (its content
    /// is D113), no outcome line, no file.
    #[test]
    fn topics_sample_empty_output_file_prints_the_csv() {
        let args = ["runtime", "topics", "sample", "--output-file", ""];
        let Some((rust, ts)) = both("topics_sample_empty", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(rust.run.stderr, "");
        let (outcome, rest) = split_outcome_lines(&ts.run.stdout);
        assert_eq!(outcome, "", "no outcome line");
        for csv in [rust.run.stdout.as_str(), rest.as_str()] {
            assert!(csv.starts_with("prompt,expected,intent\n"), "{csv:?}");
        }
        assert!(rust.requests.is_empty() && ts.requests.is_empty());
    }
}

mod divergence {
    use super::*;

    /// D93 (narrowed in 8.0): TypeScript 7.3.0 `apply` and `revert` build their client
    /// from the tenant (`managementClientOptions`), as airs-cli-rs does; only `topics
    /// create` still ignores the tenant's endpoint (`d93_topics_create_uses_the_tenant_endpoint`).
    #[test]
    fn apply_and_revert_use_the_tenant_endpoint() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            server.set_profiles(
                TSG,
                vec![guarded(
                    1,
                    "alpha",
                    "allow",
                    json!([{"action": "block", "topic": [other_ref()]}]),
                )],
            );
        };
        for args in [
            apply("alpha", "fin", &[]),
            revert("alpha", "other", &["--force"]),
        ] {
            let Some((rust, ts)) = both("apply_revert_endpoint", setup(&seed), &args) else {
                return;
            };
            for side in [&rust, &ts] {
                side.run.assert_success();
                let bases = side.bases(Route::Topics);
                assert!(!bases.is_empty() && bases.iter().all(|base| base.is_empty()));
                assert_eq!(side.count(Route::TsEnvTrap), 0);
                assert!(!side.writes().is_empty());
            }
        }
    }

    /// D94: TypeScript ignores `--output` on `apply`, `revert`, `eval` and `sample`.
    #[test]
    fn d94_output_is_honoured() {
        let args = apply("alpha", "other", &["--output", "json"]);
        let Some((rust, ts)) = both("d94_apply", family_b(&no_seed), &args) else {
            return;
        };
        assert_eq!(rust.run.json()["topicName"], "other");
        assert!(
            ts.run.stdout.starts_with("  Applied  other\n"),
            "TS prints pretty"
        );
        let referencing = |server: &FixtureServer, _: &Sandbox| {
            server.set_profiles(
                TSG,
                vec![guarded(
                    1,
                    "alpha",
                    "allow",
                    json!([{"action": "block", "topic": [other_ref()]}]),
                )],
            );
        };
        let args = revert("alpha", "other", &["--force", "--output", "json"]);
        let Some((rust, ts)) = both("d94_revert", family_b(&referencing), &args) else {
            return;
        };
        assert_eq!(
            rust.run.json(),
            json!({"profileName": "alpha", "deleted": [id(13)]})
        );
        ts.run.assert_success();
        assert!(
            ts.run.stdout.starts_with("  Reverted  other\n"),
            "TS prints pretty"
        );
        let Some((rust, ts)) = both("d94_eval", setup(&eval_seed), &eval(&["--output", "json"]))
        else {
            return;
        };
        assert_eq!(rust.run.json()["metrics"]["total"], 4);
        assert!(
            ts.run.stdout.starts_with("\n  Eval Results\n"),
            "TS prints pretty"
        );
        let args = ["runtime", "topics", "sample", "--output", "old.csv"];
        let Some((rust, ts)) = both("d94_sample", setup(&no_seed), &args) else {
            return;
        };
        ts.run.assert_success();
        assert!(
            ts.run.stdout.starts_with(SAMPLE),
            "TS prints the CSV and writes nothing"
        );
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("Invalid output format 'old.csv'. Expected: pretty, table, json")
        );
    }

    /// D96: `apply` pins the highest topic revision; TypeScript pins the first listed.
    /// Both write the highest profile revision (7.3.0 matches the profile half).
    #[test]
    fn d96_apply_targets_the_highest_revisions() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            server.set_profiles(
                TSG,
                vec![
                    fixtures::profile(2, "beta", 1),
                    fixtures::profile(4, "beta", 3),
                ],
            );
        };
        let args = apply("beta", "fin", &[]);
        let Some((rust, ts)) = both("d96_apply", family_b(&seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        assert_eq!(
            rust.write_summary()[0].0,
            format!("PUT /aisec/v1/mgmt/profile/uuid/{}", id(4))
        );
        assert_eq!(
            ts.write_summary()[0].0,
            format!("PUT /aisec/v1/mgmt/profile/uuid/{}", id(4)),
            "7.3.0 picks the highest profile revision"
        );
        let pinned =
            |side: &Side| side.guardrails(0)[0]["topic-list"][0]["topic"][0]["topic_id"].clone();
        assert_eq!(pinned(&rust), json!(id(12)));
        assert_eq!(pinned(&ts), json!(id(11)));
    }

    /// D97: airs-cli-rs reads the profile once, last, and does not write an unchanged
    /// policy; TypeScript re-reads and writes anyway.
    #[test]
    fn d97_one_read_and_no_needless_write() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            server.set_profiles(
                TSG,
                vec![guarded(
                    1,
                    "alpha",
                    "allow",
                    json!([{"action": "block", "topic": [other_ref()]}]),
                )],
            );
        };
        let args = apply("alpha", "other", &[]);
        let Some((rust, ts)) = both("d97", family_b(&seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        let routes: Vec<Route> = rust.requests.iter().map(|r| r.route).collect();
        assert_eq!(routes, [Route::Token, Route::Topics, Route::Profiles]);
        assert_eq!(
            rust.run.stderr,
            "  Profile alpha already has other with intent block; nothing was written\n"
        );
        assert!(
            ts.count(Route::Profiles) >= 2,
            "TypeScript reads the profile again"
        );
        assert_eq!(
            ts.writes().len(),
            1,
            "TypeScript writes a new revision anyway"
        );
        assert_eq!(rust.run.stdout, split_outcome_lines(&ts.run.stdout).1);
    }

    /// D98: another topic's ref keeps its pin; TypeScript re-pins it to the topic's
    /// current revision (7.3.0 keeps its other keys).
    #[test]
    fn d98_other_refs_are_kept_as_read() {
        let seed =
            |server: &FixtureServer, _: &Sandbox| {
                server.set_profiles(
                TSG,
                vec![guarded(1, "alpha", "allow", json!([{"action": "block", "topic": [
                    {"topic_id": id(11), "topic_name": "fin", "revision": 0, "x-ref": "kept"}
                ]}]))],
            );
            };
        let args = apply("alpha", "other", &[]);
        let Some((rust, ts)) = both("d98", family_b(&seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        let first = |side: &Side| side.guardrails(0)[0]["topic-list"][0]["topic"][0].clone();
        assert_eq!(
            first(&rust),
            json!({"topic_id": id(11), "topic_name": "fin", "revision": 0, "x-ref": "kept"})
        );
        assert_eq!(
            first(&ts),
            json!({"topic_id": id(11), "topic_name": "fin", "revision": 1, "x-ref": "kept"}),
            "TypeScript re-pins to the current revision and keeps other keys"
        );
    }

    /// D99: both write the profile and then send a plain delete (7.3.0), and both refuse a
    /// profile that does not reference the topic (exit 2, nothing written). TypeScript
    /// leaves an empty `block` guardrail when the last ref goes, and a 409 on the delete
    /// fails it after the PUT; airs-cli-rs removes the item and keeps the topic with a
    /// warning (exit 0).
    #[test]
    fn d99_revert_completes() {
        let seed = |server: &FixtureServer, _: &Sandbox| {
            server.set_profiles(
                TSG,
                vec![guarded(
                    1,
                    "alpha",
                    "allow",
                    json!([{"action": "block", "topic": [other_ref()]}]),
                )],
            );
        };
        let args = revert("alpha", "other", &["--force"]);
        let Some((rust, ts)) = both("d99", family_b(&seed), &args) else {
            return;
        };
        let lines = |side: &Side| {
            side.write_summary()
                .iter()
                .map(|(line, _)| line.clone())
                .collect::<Vec<_>>()
        };
        let expected = [
            format!("PUT /aisec/v1/mgmt/profile/uuid/{}", id(1)),
            format!("DELETE /aisec/v1/mgmt/topic/{}", id(13)),
        ];
        rust.run.assert_success();
        ts.run.assert_success();
        assert_eq!(lines(&rust), expected);
        assert_eq!(lines(&ts), expected, "7.3.0 sends a plain delete");
        assert_eq!(
            rust.guardrails(0),
            json!([]),
            "the guardrail item goes with its last ref"
        );
        assert_eq!(
            ts.guardrails(0),
            json!([{"name": "topic-guardrails", "action": "block", "topic-list": [], "options": []}]),
            "an empty block guardrail"
        );
        for side in [&rust, &ts] {
            assert!(!side.topics.iter().any(|t| t["topic_id"] == id(13)));
        }
        // A 409 on the delete (the topic is still referenced elsewhere).
        let conflict = |server: &FixtureServer, sandbox: &Sandbox| {
            seed(server, sandbox);
            server.push_once(
                Route::TopicDelete,
                Planned::json(409, &json!({"message": "referenced"})),
            );
        };
        let Some((rust, ts)) = both("d99_conflict", family_b(&conflict), &args) else {
            return;
        };
        rust.run.assert_success();
        assert!(rust.run.stderr.contains("so it was kept"));
        ts.run.assert_code(1);
        assert_eq!(ts.count(Route::ProfileUpdate), 1, "after the PUT");
        // A profile that never referenced the topic: both refuse, nothing written.
        let Some((rust, ts)) = both("d99_unreferenced", family_b(&no_seed), &args) else {
            return;
        };
        for side in [&rust, &ts] {
            side.run.assert_code(2);
            assert!(side.writes().is_empty());
        }
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("Topic \"other\" is not assigned to the selected protection section")
        );
        assert_eq!(usage_line(&rust.run.stderr), usage_line(&ts.run.stderr));
    }

    fn visible(out: &PtyRun) -> String {
        let mut plain = String::new();
        let mut chars = out.transcript.chars().peekable();
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
        plain
    }

    /// D105: TypeScript asks before it reads the tenant; airs-cli-rs after the topic
    /// lookup. Both decline on `n` and write nothing.
    #[test]
    fn d105_revert_asks_after_the_topic_lookup() {
        let Some(ts) = require_ts("d105_revert_prompt") else {
            return;
        };
        let args = revert("alpha", "other", &[]);
        let world = |cli: &Cli| -> (PtyRun, Vec<Route>, Vec<Route>) {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            standard(&server);
            let options = RunOptions::new().env("PANW_MGMT_ENDPOINT", server.ts_env_mgmt_url());
            let mut session = if cli.is_ts() {
                spawn_pty_all(cli, &sandbox, &args, &options)
            } else {
                spawn_pty(cli, &sandbox, &args, &options)
            };
            session.expect("Remove topic \"other\" from profile \"alpha\" and delete it?");
            std::thread::sleep(std::time::Duration::from_millis(150));
            let at_prompt = server.routes();
            session.send(if cli.is_ts() { b"n\r" } else { b"n\n" });
            (session.wait(), at_prompt, server.routes())
        };
        let (rust_out, rust_at_prompt, rust_all) = world(&rust());
        let (ts_out, ts_at_prompt, ts_all) = world(&ts);
        rust_out.run.assert_success();
        ts_out.run.assert_success();
        assert_eq!(rust_at_prompt, [Route::Token, Route::Topics]);
        assert!(
            ts_at_prompt.is_empty(),
            "TypeScript asks before any request"
        );
        for out in [&rust_out, &ts_out] {
            assert!(visible(out).contains("ℹ Aborted"), "{:?}", visible(out));
        }
        assert_eq!(rust_all, rust_at_prompt);
        assert!(ts_all.is_empty());
    }

    /// D103: the prompts file is read before the tenant with a fixed message.
    #[test]
    fn d103_prompts_file() {
        let Some((rust, ts)) = both("d103_prompts", setup(&no_seed), &eval(&[])) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some(
                "Cannot read TMP/set.csv (missing, not a regular file, unreadable or larger than 16 MiB)"
            )
        );
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("ENOENT: no such file or directory, open 'TMP/set.csv'")
        );
        let bad = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(sandbox.tmp().join("set.csv"), "prompt\n").unwrap();
        };
        let mut no_tenant = setup(&bad);
        no_tenant.tenant = false;
        let Some((rust, ts)) = both("d103_prompts_order", no_tenant, &eval(&[])) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("Missing required column: expected"),
            "the CSV is checked before the (missing) tenant"
        );
        assert_ne!(
            ts.run.error_line(),
            rust.run.error_line(),
            "TypeScript reads the tenant first"
        );
    }

    /// D104: eval's `--profile` is checked before the tenant.
    #[test]
    fn d104_eval_profile_before_the_tenant() {
        let args = [
            "runtime",
            "topics",
            "eval",
            "--profile",
            "",
            "--prompts",
            "TMP/set.csv",
        ];
        let Some((rust, ts)) = both("d104_eval", setup(&eval_seed), &args) else {
            return;
        };
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile: custom"
            )
        );
        assert!(rust.requests.is_empty());
        ts.run.assert_code(1);
        assert_eq!(ts.count(Route::ScanSync), 0);
    }

    /// D106: the eval counts line is data; the sample outcome line is on stderr.
    #[test]
    fn d106_eval_counts_and_sample_outcome() {
        let mut quiet = setup(&eval_seed);
        quiet.quiet = true;
        let Some((rust, ts)) = both("d106_eval", quiet, &eval(&[])) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (0, 0));
        let counts = "  TP: 1  TN: 1  FP: 1  FN: 1  Total: 4\n";
        assert!(rust.run.stdout.contains(counts));
        assert!(!ts.run.stdout.contains(counts), "TS hides it under --quiet");
        assert_eq!(rust.run.stdout.replace(counts, ""), ts.run.stdout);
        let args = [
            "runtime",
            "topics",
            "sample",
            "--output-file",
            "TMP/s.csv",
            "--quiet",
        ];
        let Some((rust, ts)) = both("d106_sample", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!(rust.run.stderr, "");
        assert_eq!(
            ts.run.stdout, "  ✓ Sample CSV written to TMP/s.csv\n",
            "never quiet-suppressed"
        );
    }

    /// D111: a scan that did not complete counts as not triggered in TypeScript; it
    /// stops airs-cli-rs with no metrics.
    #[test]
    fn d111_eval_fails_closed() {
        let seed = |server: &FixtureServer, sandbox: &Sandbox| {
            server.add_scan_verdict("weather", &fixtures::scan_failed());
            eval_seed(server, sandbox);
        };
        let Some((rust, ts)) = both("d111", setup(&seed), &eval(&["--concurrency", "1"])) else {
            return;
        };
        ts.run.assert_success();
        assert!(
            ts.run.stdout.contains("TN: 1"),
            "the error scan counted as a true negative"
        );
        rust.run.assert_code(1);
        assert_eq!(rust.run.stdout, "");
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("AIRS scan did not complete: dlp: error: prompt")
        );
        assert!(
            rust.run
                .stderr
                .contains("    Scans: 2 of 4 sent, 1 completed; no metrics were computed.\n")
        );
        assert_eq!(rust.count(Route::ScanSync), 2);
    }

    /// D112: TypeScript truncates or ignores bad numbers and fails late; airs-cli-rs
    /// refuses them before the tenant.
    #[test]
    fn d112_strict_rate_and_concurrency() {
        let Some((rust, ts)) = both(
            "d112_concurrency",
            setup(&eval_seed),
            &eval(&["--concurrency", "0"]),
        ) else {
            return;
        };
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("--concurrency must be an integer from 1 to 32")
        );
        ts.run.assert_code(1);
        assert_eq!(
            ts.run.error_line().as_deref(),
            Some("Expected `concurrency` to be a number from 1 and up")
        );
        assert!(rust.requests.is_empty());
        let Some((rust, ts)) = both("d112_rate", setup(&eval_seed), &eval(&["--rate", "2.5"]))
        else {
            return;
        };
        ts.run.assert_success();
        assert_eq!(ts.count(Route::ScanSync), 4, "TypeScript runs with rate 2");
        rust.run.assert_code(2);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("--rate must be a positive integer")
        );
    }

    /// D113: the Rust sample is TypeScript's block rows, which both CLIs' `eval` accept;
    /// TypeScript's own sample is rejected by both.
    #[test]
    fn d113_the_sample_is_valid_eval_input() {
        let args = ["runtime", "topics", "sample"];
        let Some((rust, ts)) = both("d113_sample", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!(rust.run.stdout, SAMPLE);
        assert_eq!(ts.run.stdout.len(), 196);
        assert!(ts.run.stdout.starts_with(SAMPLE));
        let ts_sample = ts.run.stdout.clone();
        for (csv, code) in [(SAMPLE.to_owned(), 0), (ts_sample, 1)] {
            let seed = move |server: &FixtureServer, sandbox: &Sandbox| {
                std::fs::write(sandbox.tmp().join("set.csv"), &csv).unwrap();
                server.add_scan_verdict("bomb", &verdict(true));
            };
            let Some((rust, ts)) = both("d113_eval", setup(&seed), &eval(&[])) else {
                return;
            };
            assert_eq!((rust.run.code, ts.run.code), (code, code));
            if code == 1 {
                assert_eq!(
                    rust.run.error_line().as_deref(),
                    Some("All rows must have the same intent value")
                );
                assert_eq!(rust.run.error_line(), ts.run.error_line());
            }
        }
    }

    /// D114: TypeScript overwrites an existing file; airs-cli-rs refuses it.
    #[test]
    fn d114_sample_never_overwrites() {
        let seed = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(sandbox.tmp().join("s.csv"), "keep me").unwrap();
        };
        let args = ["runtime", "topics", "sample", "--output-file", "TMP/s.csv"];
        let Some((rust, ts)) = both("d114", setup(&seed), &args) else {
            return;
        };
        ts.run.assert_success();
        assert_eq!(
            std::fs::read_to_string(ts.tmp.join("s.csv")).unwrap().len(),
            196,
            "TypeScript replaced the file"
        );
        rust.run.assert_code(1);
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("TMP/s.csv already exists; choose another --output-file")
        );
        assert_eq!(
            std::fs::read_to_string(rust.tmp.join("s.csv")).unwrap(),
            "keep me"
        );
    }

    /// D115: a write failure is a Node stack trace in TypeScript and a fixed message in
    /// airs-cli-rs.
    #[test]
    fn d115_sample_write_errors() {
        let args = [
            "runtime",
            "topics",
            "sample",
            "--output-file",
            "TMP/nodir/s.csv",
        ];
        let Some((rust, ts)) = both("d115_sample", setup(&no_seed), &args) else {
            return;
        };
        assert_eq!((rust.run.code, ts.run.code), (1, 1));
        assert!(ts.run.stderr.contains("    at "), "a Node stack trace");
        assert!(!rust.run.stderr.contains("    at "));
        assert_eq!(
            rust.run.error_line().as_deref(),
            Some("Cannot write TMP/nodir/s.csv; check that its directory exists and is writable")
        );
    }
}
