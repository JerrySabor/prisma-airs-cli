//! TS-vs-Rust parity for the M2 read-only management commands (DESIGN §7).
//!
//! Every scenario runs once against `airs-cli-rs` and once against the TypeScript
//! reference CLI, each on a fresh [`Sandbox`] + [`FixtureServer`] with the standard
//! fixture tenant (every endpoint key on the loopback server). Parity tests compare
//! exit codes, stdout (JSON semantic equality), the normalized request logs and the
//! status / error lines. `divergence` tests pin both sides of an intentional
//! difference listed in DESIGN §12 (named by its D#), so a change on either side is
//! detected. A missing or unverified reference CLI fails each test (`AIRS_ALLOW_PARITY_SKIP=1`
//! skips it with a `PARITY SKIPPED` notice).

use std::time::Duration;

use airs_test_harness::{
    Cli, ENDPOINT_KEYS, FixtureConfig, FixtureServer, NormalizedRequest, Planned, Route, Run,
    RunOptions, Sandbox, assert_json_semantic_eq, fixtures, normalise_program, normalize_all,
    require_ts, run, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const LIST: &[&str] = &["runtime", "profiles", "list", "--output", "json"];
const TLIST: &[&str] = &["runtime", "topics", "list", "--output", "json"];

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn with<'a>(base: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
    base.iter().chain(extra.iter()).copied().collect()
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    lines: Vec<String>,
}

impl Side {
    fn count(&self, route: Route) -> usize {
        self.requests.iter().filter(|r| r.route == route).count()
    }
    fn error(&self) -> Option<String> {
        self.run.error_line()
    }
}

/// How a scenario prepares its world.
struct Setup<'a> {
    /// Edits the standard tenant config (`None`: no tenant registered at all).
    tenant: Option<&'a dyn Fn(&mut FixtureConfig)>,
    /// Seeds data / overrides on the fresh server.
    server: &'a dyn Fn(&FixtureServer),
    /// Requests to an unknown route are expected (redirect target, D30).
    allow_unknown: bool,
    options: RunOptions,
}

fn no_edit(_: &mut FixtureConfig) {}

fn plain(server: &dyn Fn(&FixtureServer)) -> Setup<'_> {
    Setup {
        tenant: Some(&no_edit),
        server,
        allow_unknown: false,
        options: RunOptions::new(),
    }
}

/// Runs one CLI on a fresh sandbox and server.
fn exec(cli: &Cli, setup: &Setup<'_>, args: &[&str]) -> Side {
    exec_with_store(cli, setup, args, &|_| {})
}

/// [`exec`], with `store` changing the provisioned Rust store before the run.
fn exec_with_store(cli: &Cli, setup: &Setup<'_>, args: &[&str], store: &dyn Fn(&Sandbox)) -> Side {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    if let Some(edit) = setup.tenant {
        let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
        sandbox.register(&[&tenant], Some("prod"));
        // Hard rule: the TS CLI only ever sees a tenant whose every endpoint is loopback.
        let config: Value = serde_json::from_str(&tenant.config.to_json()).expect("config");
        for key in ENDPOINT_KEYS {
            let endpoint = config[*key].as_str().unwrap_or_default();
            assert!(
                endpoint.starts_with(&server.base_url()),
                "{key} must point at the fixture server"
            );
        }
    }
    store(&sandbox);
    (setup.server)(&server);
    let before = sandbox.snapshot();
    let out = run(cli, &sandbox, args, &setup.options);
    sandbox.assert_unchanged(&before);
    if !setup.allow_unknown {
        server.assert_no_unknown_routes();
    }
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
    let raw = server.requests();
    Side {
        run: out,
        requests: normalize_all(&raw),
        lines: raw.iter().map(|r| r.line()).collect(),
    }
}

/// Both sides of a scenario (`None` after a `PARITY SKIPPED` notice).
fn sides(name: &str, setup: &Setup<'_>, args: &[&str]) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    let rust_side = exec(&rust(), setup, args);
    let ts_side = exec(&ts, setup, args);
    Some((rust_side, ts_side))
}

/// Full parity: exit code, stdout JSON, requests, and stderr (exact for successes and
/// usage errors; error + HTTP lines for operational errors, whose other lines differ
/// by D11 and the Rust-only detail lines).
fn assert_parity(r: &Side, t: &Side) {
    let ctx = || format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run);
    assert_eq!(r.run.code, t.run.code, "exit codes differ{}", ctx());
    match (r.run.stdout.is_empty(), t.run.stdout.is_empty()) {
        (true, true) => {}
        (false, false) => assert_json_semantic_eq(&r.run.json(), &t.run.json()),
        _ => panic!("stdout presence differs{}", ctx()),
    }
    assert_eq!(r.requests, t.requests, "requests differ{}", ctx());
    match r.run.code {
        // Hints name airs (D73, pinned in tests/parity_tenant.rs).
        0 | 2 => assert_eq!(
            normalise_program(&r.run.stderr),
            t.run.stderr,
            "stderr differs{}",
            ctx()
        ),
        _ => {
            assert_eq!(
                r.error().map(|line| normalise_program(&line)),
                t.error(),
                "error lines differ{}",
                ctx()
            );
            assert_eq!(
                r.run.http_status(),
                t.run.http_status(),
                "HTTP lines differ{}",
                ctx()
            );
            assert!(r.error().is_some(), "no error line{}", ctx());
        }
    }
}

/// Standard tenant, `seed` on the server, full parity on `args`.
fn same(name: &str, seed: &dyn Fn(&FixtureServer), args: &[&str]) -> Option<(Side, Side)> {
    let (r, t) = sides(name, &plain(seed), args)?;
    assert_parity(&r, &t);
    Some((r, t))
}

fn profiles(rows: Vec<Value>) -> impl Fn(&FixtureServer) {
    move |server: &FixtureServer| server.set_profiles(TSG, rows.clone())
}

fn topics(rows: Vec<Value>) -> impl Fn(&FixtureServer) {
    move |server: &FixtureServer| server.set_topics(TSG, rows.clone())
}

fn nothing(_: &FixtureServer) {}

fn minimal_profile(name: &str, revision: u64) -> Value {
    json!({"profile_name": name, "revision": revision})
}

fn minimal_topic(name: &str, revision: u64) -> Value {
    json!({"topic_name": name, "revision": revision, "description": "d"})
}

fn n_profiles(n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| minimal_profile(&format!("p{i:05}"), 1))
        .collect()
}

fn n_topics(n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| minimal_topic(&format!("t{i:05}"), 1))
        .collect()
}

fn alpha_beta() -> Vec<Value> {
    vec![
        fixtures::profile(1, "alpha", 1),
        fixtures::profile(2, "alpha", 2),
        fixtures::profile(3, "beta", 1),
    ]
}

fn fin_legal() -> Vec<Value> {
    vec![
        fixtures::topic(1, "fin", 1, "old"),
        fixtures::topic(2, "fin", 2, "new"),
        fixtures::topic(3, "legal", 1, "law"),
    ]
}

fn len(side: &Side) -> usize {
    side.run.json().as_array().map_or(0, Vec::len)
}

// ---------------------------------------------------------------------------
// parity: profiles list
// ---------------------------------------------------------------------------

mod profiles_list {
    use super::*;

    #[test]
    fn default_page_collapsed_by_server_exact_bytes() {
        let Some((r, t)) = same("profiles_default_page", &profiles(alpha_beta()), LIST) else {
            return;
        };
        assert_eq!(
            r.run.stdout, t.run.stdout,
            "byte-identical JSON for fixture rows"
        );
        assert_eq!(r.run.stderr, "  Showing 2\n");
    }

    #[test]
    fn empty_list() {
        let Some((r, _)) = same("profiles_empty", &nothing, LIST) else {
            return;
        };
        assert_eq!(r.run.stdout, "[]\n");
        assert_eq!(r.run.stderr, "  Showing 0\n");
    }

    #[test]
    fn limit_one_more_available() {
        let Some((r, _)) = same(
            "profiles_limit_more",
            &profiles(alpha_beta()),
            &with(LIST, &["--limit", "1"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "  Showing 1 (more available)\n");
    }

    #[test]
    fn limit_and_offset_page() {
        let Some((r, _)) = same(
            "profiles_limit_offset",
            &profiles(n_profiles(6)),
            &with(LIST, &["--limit", "2", "--offset", "4"]),
        ) else {
            return;
        };
        assert_eq!(len(&r), 2);
    }

    #[test]
    fn all_versions_page() {
        let Some((r, _)) = same(
            "profiles_all_versions",
            &profiles(alpha_beta()),
            &with(LIST, &["--all-versions"]),
        ) else {
            return;
        };
        assert_eq!(len(&r), 3);
    }

    #[test]
    fn ls_alias() {
        same(
            "profiles_ls",
            &profiles(alpha_beta()),
            &["runtime", "profiles", "ls", "--output", "json"],
        );
    }

    #[test]
    fn output_before_subcommand_and_equals_form() {
        same(
            "profiles_global_output",
            &profiles(alpha_beta()),
            &["--output", "json", "runtime", "profiles", "list"],
        );
        same(
            "profiles_output_equals",
            &profiles(alpha_beta()),
            &["runtime", "profiles", "list", "--output=json"],
        );
    }

    #[test]
    fn quiet_has_no_status_lines() {
        let Some((r, _)) = same(
            "profiles_quiet",
            &profiles(alpha_beta()),
            &with(LIST, &["--quiet", "--limit", "1"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "");
    }

    #[test]
    fn tenant_default_output_json() {
        let edit = |config: &mut FixtureConfig| {
            config.set("defaultOutput", "json");
        };
        let seed = profiles(alpha_beta());
        let setup = Setup {
            tenant: Some(&edit),
            server: &seed,
            allow_unknown: false,
            options: RunOptions::new(),
        };
        let Some((r, t)) = sides(
            "profiles_default_output_json",
            &setup,
            &["runtime", "profiles", "list"],
        ) else {
            return;
        };
        assert_parity(&r, &t);
    }

    #[test]
    fn all_walk_limit_one_all_versions() {
        let Some((r, _)) = same(
            "profiles_all_walk",
            &profiles(alpha_beta()),
            &with(LIST, &["--all", "--limit", "1", "--all-versions"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "  Showing all 3\n");
        assert_eq!(r.count(Route::Token), 1);
        assert_eq!(r.count(Route::Profiles), 3);
    }

    #[test]
    fn all_walk_multi_page_default_limit() {
        let Some((r, _)) = same(
            "profiles_all_multi_page",
            &profiles(n_profiles(250)),
            &with(LIST, &["--all"]),
        ) else {
            return;
        };
        assert_eq!(len(&r), 250);
        assert_eq!(r.count(Route::Profiles), 3);
    }

    #[test]
    fn all_walk_ends_on_next_offset_zero() {
        let seed = |server: &FixtureServer| {
            server.set_zero_next_offset_on_last_page(true);
            server.set_profiles(TSG, n_profiles(3));
        };
        let Some((r, _)) = same(
            "profiles_all_next_offset_zero",
            &seed,
            &with(LIST, &["--all", "--limit", "2"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "  Showing all 3\n");
        assert_eq!(r.count(Route::Profiles), 2);
    }

    #[test]
    fn all_max_zero_uncapped() {
        let Some((r, _)) = same(
            "profiles_all_max_zero",
            &profiles(n_profiles(12)),
            &with(LIST, &["--all", "--limit", "5", "--max", "0"]),
        ) else {
            return;
        };
        assert_eq!(len(&r), 12);
    }

    #[test]
    fn all_max_equal_to_total_is_all() {
        let Some((r, _)) = same(
            "profiles_all_max_equal",
            &profiles(n_profiles(2)),
            &with(LIST, &["--all", "--limit", "5", "--max", "2"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "  Showing all 2\n");
    }

    #[test]
    fn max_without_all_is_ignored_for_a_page() {
        same(
            "profiles_max_without_all",
            &profiles(n_profiles(3)),
            &with(LIST, &["--max", "1"]),
        );
    }
}

// ---------------------------------------------------------------------------
// parity: profile projection
// ---------------------------------------------------------------------------

mod profile_projection {
    use super::*;

    #[test]
    fn drops_csp_tsg_unknown_and_keeps_policy_extensions() {
        let row = json!({
            "zzz_unknown": {"nested": 1},
            "policy": {
                "zeta-extension": {"b": 1, "a": [true, null]},
                "dlp-data-profiles": [],
                "ai-security-profiles": [{
                    "model-type": "default",
                    "model-configuration": {"mask-data-in-storage": true, "x-custom": "kept"}
                }]
            },
            "last_modified_ts": "2026-02-01T00:00:00Z",
            "updated_by": "u@example.com",
            "created_by": "c@example.com",
            "tsg_id": "100",
            "csp_id": "csp-1",
            "active": false,
            "revision": 7,
            "profile_name": "alpha",
            "profile_id": fixtures::uuid(9)
        });
        let Some((r, t)) = same("profile_projection", &profiles(vec![row]), LIST) else {
            return;
        };
        for side in [&r, &t] {
            assert!(!side.run.stdout.contains("csp"));
            assert!(!side.run.stdout.contains("zzz_unknown"));
            assert!(side.run.stdout.contains("x-custom"));
        }
    }

    #[test]
    fn unset_fields_omitted_exact_bytes() {
        let Some((r, t)) = same(
            "profile_projection_bare",
            &profiles(vec![json!({"profile_name": "bare"})]),
            LIST,
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout);
    }

    #[test]
    fn integral_float_revision_prints_as_integer() {
        let Some((r, t)) = same(
            "profile_revision_float",
            &profiles(vec![
                json!({"profile_name": "a", "revision": 2.0}),
                json!({"profile_name": "b", "revision": 2.5}),
            ]),
            LIST,
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout);
        assert!(r.run.stdout.contains("\"revision\": 2\n"));
        assert!(r.run.stdout.contains("\"revision\": 2.5\n"));
    }
}

// ---------------------------------------------------------------------------
// parity: profiles get
// ---------------------------------------------------------------------------

mod profiles_get {
    use super::*;

    fn get<'a>(extra: &[&'a str]) -> Vec<&'a str> {
        with(
            &with(&["runtime", "profiles", "get"], extra),
            &["--output", "json"],
        )
    }

    #[test]
    fn by_name_highest_revision() {
        let rows = vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(3, "alpha", 3),
            fixtures::profile(2, "alpha", 2),
            fixtures::profile(4, "beta", 9),
        ];
        let Some((r, t)) = same(
            "profiles_get_name",
            &profiles(rows),
            &get(&["alpha", "--output", "json"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout);
        assert_eq!(r.run.json()["revision"], 3);
    }

    #[test]
    fn by_name_tie_first_seen() {
        let rows = vec![
            fixtures::profile(1, "alpha", 2),
            fixtures::profile(2, "alpha", 2),
        ];
        let Some((r, _)) = same("profiles_get_tie", &profiles(rows), &get(&["alpha"])) else {
            return;
        };
        assert_eq!(r.run.json()["profileId"], fixtures::uuid(1).as_str());
    }

    #[test]
    fn by_name_unset_revision_is_zero() {
        let rows = vec![
            json!({"profile_name": "alpha", "profile_id": fixtures::uuid(1)}),
            json!({"profile_name": "alpha", "profile_id": fixtures::uuid(2), "revision": 0}),
        ];
        same("profiles_get_unset_zero", &profiles(rows), &get(&["alpha"]));
        let rows = vec![
            json!({"profile_name": "alpha", "profile_id": fixtures::uuid(1)}),
            json!({"profile_name": "alpha", "profile_id": fixtures::uuid(2), "revision": 1}),
        ];
        same(
            "profiles_get_unset_vs_one",
            &profiles(rows),
            &get(&["alpha"]),
        );
    }

    #[test]
    fn by_uuid_first_exact_match() {
        let id = fixtures::uuid(7);
        let rows = vec![
            fixtures::profile(1, "other", 5),
            json!({"profile_name": "alpha", "profile_id": id, "revision": 1}),
            json!({"profile_name": "alpha", "profile_id": id, "revision": 2}),
        ];
        let Some((r, _)) = same("profiles_get_uuid", &profiles(rows), &get(&[&id])) else {
            return;
        };
        assert_eq!(r.run.json()["revision"], 1);
    }

    #[test]
    fn uppercase_uuid_not_found() {
        let id = "0000abcd-0000-4000-8000-00000000000a";
        let rows = vec![json!({"profile_name": "alpha", "profile_id": id, "revision": 1})];
        let upper = id.to_uppercase();
        let Some((r, _)) = same("profiles_get_upper_uuid", &profiles(rows), &get(&[&upper])) else {
            return;
        };
        assert_eq!(
            r.error(),
            Some(format!(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: {upper}"
            ))
        );
    }

    #[test]
    fn lookup_walks_pages() {
        let mut rows = n_profiles(150);
        rows.push(minimal_profile("p00003", 4));
        let Some((r, _)) = same("profiles_get_pages", &profiles(rows), &get(&["p00003"])) else {
            return;
        };
        assert_eq!(r.count(Route::Profiles), 2);
    }

    #[test]
    fn not_found_name_and_uuid() {
        let Some((r, _)) = same(
            "profiles_get_missing",
            &profiles(alpha_beta()),
            &get(&["missing"]),
        ) else {
            return;
        };
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: missing")
        );
        let id = fixtures::uuid(99);
        same(
            "profiles_get_missing_uuid",
            &profiles(alpha_beta()),
            &get(&[&id]),
        );
    }

    #[test]
    fn revision_selects_and_not_found() {
        let Some((r, _)) = same(
            "profiles_get_revision",
            &profiles(alpha_beta()),
            &get(&["alpha", "--revision", "1"]),
        ) else {
            return;
        };
        assert_eq!(r.run.json()["profileId"], fixtures::uuid(1).as_str());
        let Some((r, _)) = same(
            "profiles_get_revision_missing",
            &profiles(alpha_beta()),
            &get(&["alpha", "--revision", "9"]),
        ) else {
            return;
        };
        assert_eq!(r.error().as_deref(), Some("Profile alpha not found"));
    }

    #[test]
    fn revision_zero_does_not_match_unset() {
        same(
            "profiles_get_revision_zero_unset",
            &profiles(vec![json!({"profile_name": "alpha"})]),
            &get(&["alpha", "--revision", "0"]),
        );
    }

    #[test]
    fn all_versions_list_filter_and_not_found() {
        let rows = vec![
            fixtures::profile(3, "alpha", 3),
            fixtures::profile(9, "beta", 1),
            fixtures::profile(1, "alpha", 1),
        ];
        let Some((r, _)) = same(
            "profiles_get_all_versions",
            &profiles(rows.clone()),
            &get(&["alpha", "--all-versions"]),
        ) else {
            return;
        };
        assert_eq!(len(&r), 2);
        same(
            "profiles_get_all_versions_revision",
            &profiles(rows.clone()),
            &get(&["alpha", "--all-versions", "--revision", "1"]),
        );
        same(
            "profiles_get_all_versions_missing",
            &profiles(rows),
            &get(&["nope", "--all-versions"]),
        );
    }
}

// ---------------------------------------------------------------------------
// parity: topics list
// ---------------------------------------------------------------------------

mod topics_list {
    use super::*;

    #[test]
    fn latest_default_exact_bytes() {
        let Some((r, t)) = same("topics_default", &topics(fin_legal()), TLIST) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout);
        assert_eq!(r.run.stderr, "  Showing 2\n");
    }

    #[test]
    fn ls_alias() {
        same(
            "topics_ls",
            &topics(fin_legal()),
            &["runtime", "topics", "ls", "--output", "json"],
        );
    }

    #[test]
    fn empty() {
        same("topics_empty", &nothing, TLIST);
    }

    #[test]
    fn latest_walk_over_200_rows() {
        let Some((r, _)) = same(
            "topics_walk_200",
            &topics(n_topics(250)),
            &with(TLIST, &["--limit", "1000"]),
        ) else {
            return;
        };
        assert_eq!(len(&r), 250);
        assert_eq!(r.count(Route::Topics), 2);
        assert_eq!(r.count(Route::Token), 1);
    }

    #[test]
    fn latest_last_slice_and_beyond() {
        let rows = vec![
            fixtures::topic(1, "fin", 1, "d"),
            fixtures::topic(2, "legal", 1, "d"),
            fixtures::topic(3, "fin", 2, "d"),
        ];
        same(
            "topics_last_slice",
            &topics(rows.clone()),
            &with(TLIST, &["--limit", "1", "--offset", "1"]),
        );
        same(
            "topics_beyond",
            &topics(rows),
            &with(TLIST, &["--offset", "5"]),
        );
    }

    #[test]
    fn all_complete_and_max_not_reached() {
        let Some((r, _)) = same(
            "topics_all",
            &topics(fin_legal()),
            &with(TLIST, &["--all", "--limit", "1"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "  Showing all 2\n");
        same(
            "topics_all_max_equal",
            &topics(fin_legal()),
            &with(TLIST, &["--all", "--max", "2"]),
        );
    }

    #[test]
    fn all_versions_slices() {
        let Some((r, _)) = same(
            "topics_all_versions_slice",
            &topics(fin_legal()),
            &with(TLIST, &["--all-versions", "--limit", "1", "--offset", "1"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "  Showing 1 of 3 (next --offset 2)\n");
        same(
            "topics_all_versions_last",
            &topics(fin_legal()),
            &with(TLIST, &["--all-versions", "--limit", "1", "--offset", "2"]),
        );
        same(
            "topics_all_versions_beyond",
            &topics(fin_legal()),
            &with(TLIST, &["--all-versions", "--offset", "9"]),
        );
    }

    #[test]
    fn all_versions_walk_over_100_rows() {
        let Some((r, _)) = same(
            "topics_all_versions_walk",
            &topics(n_topics(150)),
            &with(TLIST, &["--all-versions"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "  Showing 100 of 150 (next --offset 100)\n");
        assert_eq!(r.count(Route::Topics), 2);
    }

    #[test]
    fn all_versions_all_complete() {
        let Some((r, _)) = same(
            "topics_all_versions_all",
            &topics(fin_legal()),
            &with(TLIST, &["--all-versions", "--all"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "  Showing all 3\n");
    }

    #[test]
    fn quiet() {
        let Some((r, _)) = same(
            "topics_quiet",
            &topics(fin_legal()),
            &with(TLIST, &["--quiet", "--all-versions"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stderr, "");
    }

    #[test]
    fn projection_examples_default_and_dropped_fields() {
        let rows = vec![
            json!({"topic_name": "t", "revision": 3.0, "description": ""}),
            json!({
                "zzz_unknown": 1, "created_ts": "2025-12-01T00:00:00Z",
                "last_modified_ts": "2026-01-01T00:00:00Z", "updated_by": "u@example.com",
                "created_by": "c@example.com", "examples": ["e1", "e2"], "description": "desc",
                "active": true, "revision": 1, "tsg_id": "100", "csp_id": "csp-1",
                "topic_name": "fin", "topic_id": fixtures::uuid(11)
            }),
        ];
        let Some((r, t)) = same("topics_projection", &topics(rows), TLIST) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout, "byte-identical projection");
    }
}

// ---------------------------------------------------------------------------
// parity: topics get
// ---------------------------------------------------------------------------

mod topics_get {
    use super::*;

    fn get<'a>(extra: &[&'a str]) -> Vec<&'a str> {
        with(
            &with(&["runtime", "topics", "get"], extra),
            &["--output", "json"],
        )
    }

    fn data() -> Vec<Value> {
        vec![
            fixtures::topic(1, "fin", 1, "old"),
            fixtures::topic(3, "fin", 3, "newest"),
            fixtures::topic(2, "fin", 2, "mid"),
            fixtures::topic(4, "legal", 1, "law"),
        ]
    }

    #[test]
    fn by_name_highest_and_tie() {
        let Some((r, t)) = same(
            "topics_get_name",
            &topics(data()),
            &get(&["fin", "--output", "json"]),
        ) else {
            return;
        };
        assert_eq!(r.run.stdout, t.run.stdout);
        same(
            "topics_get_tie",
            &topics(vec![
                fixtures::topic(1, "fin", 2, "first"),
                fixtures::topic(2, "fin", 2, "second"),
            ]),
            &get(&["fin"]),
        );
    }

    #[test]
    fn by_uuid_first_match() {
        let id = fixtures::uuid(5);
        let rows = vec![
            json!({"topic_id": id, "topic_name": "fin", "revision": 1, "description": "one"}),
            json!({"topic_id": id, "topic_name": "fin", "revision": 2, "description": "two"}),
        ];
        let Some((r, _)) = same("topics_get_uuid", &topics(rows), &get(&[&id])) else {
            return;
        };
        assert_eq!(r.run.json()["description"], "one");
    }

    #[test]
    fn lookup_walks_pages() {
        let mut rows = n_topics(120);
        rows.push(minimal_topic("t00005", 7));
        same("topics_get_pages", &topics(rows), &get(&["t00005"]));
    }

    #[test]
    fn not_found_variants() {
        let Some((r, _)) = same("topics_get_missing_name", &topics(data()), &get(&["nope"])) else {
            return;
        };
        assert_eq!(r.error().as_deref(), Some("Topic \"nope\" not found"));
        let id = fixtures::uuid(77);
        let Some((r, _)) = same("topics_get_missing_uuid", &topics(data()), &get(&[&id])) else {
            return;
        };
        assert_eq!(r.error(), Some(format!("Topic {id} not found")));
        let upper = "0000ABCD-0000-4000-8000-00000000000A";
        same(
            "topics_get_upper_uuid",
            &topics(vec![json!({
                "topic_id": upper.to_lowercase(), "topic_name": "fin",
                "revision": 1, "description": "d"
            })]),
            &get(&[upper]),
        );
        let first = fixtures::uuid(1);
        same(
            "topics_get_uuid_flags_missing",
            &topics(data()),
            &get(&[&first, "--revision", "5"]),
        );
    }

    #[test]
    fn revision_and_all_versions() {
        let Some((r, _)) = same(
            "topics_get_revision",
            &topics(data()),
            &get(&["fin", "--revision", "2"]),
        ) else {
            return;
        };
        assert_eq!(r.run.json()["description"], "mid");
        let Some((r, _)) = same(
            "topics_get_revision_missing",
            &topics(data()),
            &get(&["fin", "--revision", "9"]),
        ) else {
            return;
        };
        assert_eq!(r.error().as_deref(), Some("Topic fin not found"));
        same(
            "topics_get_all_versions",
            &topics(data()),
            &get(&["fin", "--all-versions"]),
        );
        same(
            "topics_get_all_versions_revision",
            &topics(data()),
            &get(&["fin", "--all-versions", "--revision", "3"]),
        );
        same(
            "topics_get_all_versions_missing",
            &topics(data()),
            &get(&["nope", "--all-versions"]),
        );
    }
}

// ---------------------------------------------------------------------------
// parity: flag validation (both exit 2, zero requests, identical stderr)
// ---------------------------------------------------------------------------

mod validation {
    use super::*;

    fn usage(name: &str, args: &[&str], message: &str) {
        let Some((r, _)) = same(name, &nothing, args) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(r.run.stderr, format!("\n  ✗ {message}\n\n"));
        assert!(r.requests.is_empty());
    }

    #[test]
    fn limit_errors() {
        for cmd in [LIST, TLIST] {
            for value in ["0", "abc", "1.5", "-1"] {
                usage(
                    "validation_limit",
                    &with(cmd, &["--limit", value]),
                    "--limit must be a positive integer",
                );
            }
        }
    }

    #[test]
    fn offset_and_max_errors() {
        for cmd in [LIST, TLIST] {
            usage(
                "validation_offset",
                &with(cmd, &["--offset", "-1"]),
                "--offset must be a non-negative integer",
            );
            usage(
                "validation_max",
                &with(cmd, &["--max", "-1"]),
                "--max must be a non-negative integer",
            );
            usage(
                "validation_max_without_all",
                &with(cmd, &["--max", "x"]),
                "--max must be a non-negative integer",
            );
        }
    }

    #[test]
    fn all_with_explicit_offset() {
        for cmd in [LIST, TLIST] {
            for value in ["0", "3"] {
                usage(
                    "validation_all_offset",
                    &with(cmd, &["--all", "--offset", value]),
                    "--all cannot be combined with --offset",
                );
            }
        }
    }

    /// D50: both reject an unknown name with exit 2 and no request; TS lists its six
    /// names, airs-cli-rs the three that remain.
    #[test]
    fn d50_invalid_format_message_lists_three_names() {
        for args in [
            vec!["runtime", "profiles", "list", "--output", "xml"],
            vec!["runtime", "topics", "list", "--output", "xml"],
            vec!["runtime", "profiles", "get", "alpha", "--output", "xml"],
            vec!["runtime", "topics", "get", "alpha", "--output", "xml"],
        ] {
            let Some((r, t)) = sides("validation_output_xml", &plain(&nothing), &args) else {
                return;
            };
            assert_eq!((r.run.code, t.run.code), (2, 2), "{args:?}");
            assert_eq!(
                r.run.stderr,
                "\n  ✗ Invalid output format 'xml'. Expected: pretty, table, json\n\n"
            );
            assert_eq!(
                t.run.stderr,
                "\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n"
            );
            assert!(r.requests.is_empty() && t.requests.is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// parity: local failures and HTTP / OAuth errors
// ---------------------------------------------------------------------------

mod errors {
    use super::*;

    #[test]
    fn missing_management_secret_zero_requests() {
        let edit = |config: &mut FixtureConfig| {
            config.remove("mgmtClientSecret");
        };
        let setup = Setup {
            tenant: Some(&edit),
            server: &nothing,
            allow_unknown: false,
            options: RunOptions::new(),
        };
        let Some((r, t)) = sides("missing_secret", &setup, LIST) else {
            return;
        };
        assert_parity(&r, &t);
        assert!(r.requests.is_empty());
        assert_eq!(
            r.error().as_deref(),
            Some(
                "Management credentials are not configured (missing mgmtClientSecret). Run 'airs tenant set prod <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)"
            )
        );
    }

    #[test]
    fn tsg_pin_mismatch_zero_requests() {
        let edit = |config: &mut FixtureConfig| {
            config.set("mgmtTsgId", "200");
        };
        let setup = Setup {
            tenant: Some(&edit),
            server: &nothing,
            allow_unknown: false,
            options: RunOptions::new(),
        };
        let Some((r, t)) = sides("tsg_mismatch", &setup, TLIST) else {
            return;
        };
        assert_parity(&r, &t);
        assert!(r.requests.is_empty());
    }

    #[test]
    fn credential_environment_is_ignored() {
        let seed = profiles(alpha_beta());
        let setup = Setup {
            tenant: Some(&no_edit),
            server: &seed,
            allow_unknown: false,
            options: RunOptions::new()
                .env("PANW_MGMT_CLIENT_ID", "env-client")
                .env("PANW_MGMT_CLIENT_SECRET", "ENV-SECRET-VALUE")
                .env("PANW_MGMT_TSG_ID", "999")
                .env("PANW_MGMT_ENDPOINT", "http://127.0.0.1:1/nowhere")
                .env("PANW_MGMT_TOKEN_ENDPOINT", "http://127.0.0.1:1/nowhere")
                .secret("ENV-SECRET-VALUE"),
        };
        let Some((r, t)) = sides("credential_env_ignored", &setup, LIST) else {
            return;
        };
        assert_parity(&r, &t);
    }

    #[test]
    fn empty_404() {
        let seed = |server: &FixtureServer| {
            server.push_once(Route::Profiles, Planned::empty_json(404));
        };
        let Some((r, t)) = same("error_404_empty", &seed, LIST) else {
            return;
        };
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 404")
        );
        assert_eq!(r.run.http_status(), Some(404));
        // Without --debug both print the hint after the HTTP line (D69 covers --debug).
        assert_eq!(r.run.stderr, t.run.stderr);
        assert!(r.run.stderr.ends_with(
            "    HTTP 404\n    Re-run with --debug to capture redacted API diagnostics.\n\n"
        ));
    }

    #[test]
    fn unauthorized_once_refreshes_and_replays() {
        let seed = |server: &FixtureServer| {
            server.set_profiles(TSG, alpha_beta());
            server.push_once(Route::Profiles, Planned::empty_json(401));
        };
        let Some((r, _)) = same("error_401_once", &seed, LIST) else {
            return;
        };
        assert_eq!(r.count(Route::Token), 2);
        assert_eq!(r.count(Route::Profiles), 2);
    }

    #[test]
    fn forbidden_without_opa_header_refreshes() {
        let seed = |server: &FixtureServer| {
            server.set_topics(TSG, fin_legal());
            server.push_once(Route::Topics, Planned::empty_json(403));
        };
        let Some((r, _)) = same("error_403_refresh", &seed, TLIST) else {
            return;
        };
        assert_eq!(r.count(Route::Token), 2);
    }

    #[test]
    fn forbidden_with_opa_decision_false_no_refresh() {
        let seed = |server: &FixtureServer| {
            server.push_once(
                Route::Profiles,
                Planned::empty_json(403).with_header("x-opa-decision", "false"),
            );
        };
        let Some((r, _)) = same("error_403_opa", &seed, LIST) else {
            return;
        };
        assert_eq!(r.count(Route::Token), 1);
        assert_eq!(r.run.http_status(), Some(403));
    }

    #[test]
    fn service_unavailable_six_attempts() {
        let seed = |server: &FixtureServer| {
            server.set_default(
                Route::Profiles,
                Planned::empty_json(503).with_retry_after(0),
            );
        };
        let Some((r, _)) = same("error_503", &seed, LIST) else {
            return;
        };
        assert_eq!(r.count(Route::Profiles), 6);
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_SERVER_SIDE_ERROR:API error 503")
        );
    }

    #[test]
    fn transient_503_then_success() {
        let seed = |server: &FixtureServer| {
            server.set_profiles(TSG, alpha_beta());
            server.push_once(
                Route::Profiles,
                Planned::empty_json(503).with_retry_after(0),
            );
        };
        same("error_503_transient", &seed, LIST);
    }

    #[test]
    fn token_401_zero_api_requests() {
        let seed = |server: &FixtureServer| {
            server.push_once(Route::Token, Planned::empty_json(401));
        };
        let Some((r, _)) = same("token_401", &seed, LIST) else {
            return;
        };
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_OAUTH_ERROR:Token request failed with status 401")
        );
        assert_eq!(r.lines, ["POST /oauth/token"]);
    }

    #[test]
    fn token_schema_mismatch() {
        let seed = |server: &FixtureServer| {
            server.push_once(
                Route::Token,
                Planned::json(200, &json!({"token_type": "Bearer"})),
            );
        };
        let Some((r, _)) = same("token_schema", &seed, TLIST) else {
            return;
        };
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_OAUTH_ERROR:Token response did not match the OAuth schema")
        );
    }

    #[test]
    fn problem_json_400_allowlisted_text() {
        let seed = |server: &FixtureServer| {
            server.push_once(
                Route::Profiles,
                Planned::raw(
                    400,
                    "application/problem+json",
                    json!({"title": "Bad Request", "detail": "free text from server"}).to_string(),
                ),
            );
        };
        let Some((r, _)) = same("problem_400", &seed, LIST) else {
            return;
        };
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 400; Bad Request; [withheld]")
        );
    }
}

// ---------------------------------------------------------------------------
// divergences (DESIGN §12): both sides pinned
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D1: argument-parse errors exit 2 (Rust) vs 1 (commander).
    #[test]
    fn d1_parse_errors_exit_code() {
        for args in [
            vec!["runtime", "profiles", "get"],
            vec!["runtime", "topics", "list", "--bogus"],
            vec!["runtime", "profiles", "list", "extra"],
        ] {
            let Some((r, t)) = sides("d1_parse", &plain(&nothing), &args) else {
                return;
            };
            assert_eq!((r.run.code, t.run.code), (2, 1), "{args:?}");
            assert!(r.requests.is_empty() && t.requests.is_empty());
            assert_eq!((r.run.stdout.as_str(), t.run.stdout.as_str()), ("", ""));
        }
    }

    /// D2: usage errors are found before the (missing) tenant.
    #[test]
    fn d2_usage_before_tenant() {
        let setup = Setup {
            tenant: None,
            server: &nothing,
            allow_unknown: false,
            options: RunOptions::new(),
        };
        let Some((r, t)) = sides("d2_usage_first", &setup, &with(LIST, &["--limit", "0"])) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(r.run.stderr, "\n  ✗ --limit must be a positive integer\n\n");
        assert_eq!(t.run.code, 1);
        assert_eq!(
            t.error().as_deref(),
            Some(
                "No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'"
            )
        );
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// D10: 500 is retried by TS (6 attempts) but not by the Rust SDK.
    #[test]
    fn d10_internal_server_error_retries() {
        let seed = |server: &FixtureServer| {
            server.set_default(
                Route::Profiles,
                Planned::json(500, &json!({"error_message": "boom"})).with_retry_after(0),
            );
        };
        let Some((r, t)) = sides("d10_500", &plain(&seed), LIST) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!((r.count(Route::Profiles), t.count(Route::Profiles)), (1, 6));
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_SERVER_SIDE_ERROR:API error 500")
        );
        assert_eq!(t.error().as_deref(), Some("AISEC_SERVER_SIDE_ERROR:boom"));
        assert_eq!(
            (r.run.http_status(), t.run.http_status()),
            (Some(500), Some(500))
        );
    }

    /// D10: 429 is retried by the Rust SDK (6 attempts) but not by TS.
    #[test]
    fn d10_too_many_requests_retries() {
        let seed = |server: &FixtureServer| {
            server.set_default(
                Route::Profiles,
                Planned::json(429, &json!({"message": "slow down"})).with_retry_after(0),
            );
        };
        let Some((r, t)) = sides("d10_429", &plain(&seed), LIST) else {
            return;
        };
        assert_eq!((r.count(Route::Profiles), t.count(Route::Profiles)), (6, 1));
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 429")
        );
        assert_eq!(
            t.error().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:slow down")
        );
    }

    /// D10: a persistent 401 - both refresh once; Rust counts it against max_retries.
    #[test]
    fn d10_persistent_unauthorized() {
        let seed = |server: &FixtureServer| {
            server.set_default(Route::Profiles, Planned::empty_json(401));
        };
        let Some((r, t)) = sides("d10_401_persistent", &plain(&seed), LIST) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert_eq!(t.run.code, 1);
        assert_eq!((r.count(Route::Token), r.count(Route::Profiles)), (2, 2));
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 401")
        );
        // TS observed behaviour, pinned so a change is noticed.
        assert_eq!(
            (t.count(Route::Token), t.count(Route::Profiles)),
            (2, 2),
            "{:?}",
            t.lines
        );
    }

    /// D11: server message text is echoed by TS, never by Rust.
    #[test]
    fn d11_server_text() {
        let seed = |server: &FixtureServer| {
            server.push_once(
                Route::Profiles,
                Planned::json(404, &json!({"message": "nope"})),
            );
        };
        let Some((r, t)) = sides("d11_404_message", &plain(&seed), LIST) else {
            return;
        };
        assert_eq!(r.requests, t.requests);
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 404")
        );
        assert_eq!(t.error().as_deref(), Some("AISEC_CLIENT_SIDE_ERROR:nope"));

        let seed = |server: &FixtureServer| {
            server.set_default(
                Route::Profiles,
                Planned::raw(502, "text/plain", "oops").with_retry_after(0),
            );
        };
        let Some((r, t)) = sides("d11_502_text", &plain(&seed), LIST) else {
            return;
        };
        assert_eq!(r.requests, t.requests, "both retry 502 six times");
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_SERVER_SIDE_ERROR:API error 502")
        );
        assert_eq!(
            t.error().as_deref(),
            Some("AISEC_SERVER_SIDE_ERROR:API error 502: oops")
        );

        let seed = |server: &FixtureServer| {
            server.push_once(
                Route::Token,
                Planned::json(
                    401,
                    &json!({"error": "invalid_client", "error_description": "Client authentication failed"}),
                ),
            );
        };
        let Some((r, t)) = sides("d11_token_description", &plain(&seed), LIST) else {
            return;
        };
        assert_eq!(r.requests, t.requests);
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_OAUTH_ERROR:Token request failed with status 401")
        );
        assert_eq!(
            t.error().as_deref(),
            Some("AISEC_OAUTH_ERROR:Client authentication failed")
        );
        assert_eq!(
            (r.run.http_status(), t.run.http_status()),
            (Some(401), Some(401))
        );
    }

    /// D12: `next_offset: 0` on a single profiles page.
    #[test]
    fn d12_next_offset_zero_single_page() {
        let seed = |server: &FixtureServer| {
            server.set_zero_next_offset_on_last_page(true);
            server.set_profiles(TSG, alpha_beta());
        };
        let Some((r, t)) = sides("d12", &plain(&seed), LIST) else {
            return;
        };
        assert_eq!(r.requests, t.requests);
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        assert_eq!(r.run.stderr, "  Showing 2\n");
        assert_eq!(t.run.stderr, "  Showing 2 (more available)\n");
    }

    /// D13: a topics latest listing truncated by `--limit`.
    #[test]
    fn d13_topics_truncated_by_limit() {
        let Some((r, t)) = sides(
            "d13",
            &plain(&topics(fin_legal())),
            &with(TLIST, &["--limit", "1"]),
        ) else {
            return;
        };
        assert_eq!(r.requests, t.requests);
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        assert_eq!(r.run.stderr, "  Showing 1 (more available)\n");
        assert_eq!(t.run.stderr, "  Showing 1\n");
    }

    /// D14: `--all` truncated by `--max` (profiles walk and topics slice).
    #[test]
    fn d14_all_truncated_by_max() {
        let Some((r, t)) = sides(
            "d14_profiles",
            &plain(&profiles(n_profiles(5))),
            &with(LIST, &["--all", "--limit", "1", "--max", "2"]),
        ) else {
            return;
        };
        assert_eq!(r.requests, t.requests, "both stop without an extra fetch");
        assert_eq!(r.count(Route::Profiles), 2);
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        assert_eq!(
            r.run.stderr,
            "  Showing first 2 (stopped at --max 2; more available)\n"
        );
        assert_eq!(t.run.stderr, "  Showing all 2\n");

        let Some((r, t)) = sides(
            "d14_topics",
            &plain(&topics(fin_legal())),
            &with(TLIST, &["--all", "--max", "1"]),
        ) else {
            return;
        };
        assert_eq!(r.requests, t.requests);
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        assert_eq!(
            r.run.stderr,
            "  Showing first 1 (stopped at --max 1; more available)\n"
        );
        assert_eq!(t.run.stderr, "  Showing all 1\n");
    }

    /// D15: a lookup beyond 10,000 rows: TS silently truncates (false not-found),
    /// Rust fails the incomplete walk.
    #[test]
    fn d15_lookup_beyond_10000_rows() {
        let mut rows: Vec<Value> = (0..10_000)
            .map(|n| json!({"profile_name": format!("p{n}")}))
            .collect();
        rows.push(json!({"profile_name": "needle", "revision": 1}));
        let seed = profiles(rows);
        let setup = Setup {
            tenant: Some(&no_edit),
            server: &seed,
            allow_unknown: false,
            options: RunOptions::new().timeout(Duration::from_secs(120)),
        };
        let Some((r, t)) = sides("d15", &setup, &["runtime", "profiles", "get", "needle"]) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_SDK_ERROR:Response exceeded a client safety limit")
        );
        assert_eq!(
            t.error().as_deref(),
            Some("AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: needle")
        );
        assert_eq!(t.count(Route::Profiles), 100, "TS stops at 10,000 rows");
    }

    /// D16: `topics list --all --max 0` is capped at 10,000 by TS, uncapped by Rust.
    #[test]
    fn d16_topics_max_zero() {
        let seed = topics(n_topics(10_001));
        let setup = Setup {
            tenant: Some(&no_edit),
            server: &seed,
            allow_unknown: false,
            options: RunOptions::new().timeout(Duration::from_secs(120)),
        };
        let Some((r, t)) = sides("d16", &setup, &with(TLIST, &["--all", "--max", "0"])) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (0, 0));
        assert_eq!((len(&r), len(&t)), (10_001, 10_000));
        assert_eq!(r.run.stderr, "  Showing all 10001\n");
        assert_eq!(t.run.stderr, "  Showing all 10000\n");
        assert_eq!(r.count(Route::Topics), 51);
    }

    /// D17: strict decimal parsing of `--revision` and `--limit`.
    #[test]
    fn d17_strict_numbers() {
        let Some((r, t)) = sides(
            "d17_revision_abc",
            &plain(&profiles(alpha_beta())),
            &["runtime", "profiles", "get", "alpha", "--revision", "abc"],
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --revision must be a non-negative integer\n\n"
        );
        assert!(r.requests.is_empty());
        assert_eq!(t.run.code, 1);
        assert_eq!(t.error().as_deref(), Some("Profile alpha not found"));
        assert_eq!(t.count(Route::Profiles), 1);

        for (value, wire) in [("1e2", "100"), ("0x10", "16")] {
            let Some((r, t)) = sides(
                "d17_limit_js_number",
                &plain(&profiles(alpha_beta())),
                &with(LIST, &["--limit", value]),
            ) else {
                return;
            };
            assert_eq!(r.run.code, 2);
            assert_eq!(r.run.stderr, "\n  ✗ --limit must be a positive integer\n\n");
            assert!(r.requests.is_empty());
            assert_eq!(t.run.code, 0, "{:?}", t.run);
            assert_eq!(
                t.lines[1],
                format!("GET /aisec/v1/mgmt/profiles/tsg/100?offset=0&limit={wire}&latest=true")
            );
        }
    }

    /// D30: TS follows a redirect (re-sending the bearer); Rust never contacts the target.
    #[test]
    fn d30_redirect() {
        let seed = |server: &FixtureServer| {
            server.push_once(
                Route::Profiles,
                Planned::redirect(302, &server.url("/elsewhere")),
            );
        };
        let setup = Setup {
            tenant: Some(&no_edit),
            server: &seed,
            allow_unknown: true,
            options: RunOptions::new(),
        };
        let Some((r, t)) = sides("d30", &setup, LIST) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(
            r.error().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:Redirect responses are not followed")
        );
        assert_eq!(r.run.http_status(), Some(302));
        assert_eq!(
            r.count(Route::Unknown),
            0,
            "Rust never contacts the Location target"
        );
        assert_eq!(r.lines.len(), 2);
        assert_eq!(t.count(Route::Unknown), 1, "TS follows the redirect");
        assert_eq!(t.lines[2], "GET /elsewhere");
        let followed = t
            .requests
            .iter()
            .find(|q| q.route == Route::Unknown)
            .expect("followed");
        assert_eq!(
            followed.auth,
            airs_test_harness::AuthIdentity::Bearer {
                tsg: Some(TSG.into())
            },
            "TS forwards the bearer token"
        );
        assert_eq!(
            t.error().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 404")
        );
    }

    /// D32: SIGINT - TS dies by the signal, Rust cancels and exits 130.
    #[test]
    fn d32_sigint() {
        let Some(ts) = require_ts("d32") else { return };
        let mut outcomes = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            server.set_default(Route::Profiles, Planned::hang());
            let child = spawn(&cli, &sandbox, LIST, &RunOptions::new().expect_signal());
            assert!(
                server.wait_for_requests(2, Duration::from_secs(20)),
                "GET never arrived"
            );
            child.send_signal("INT");
            let out = child.wait();
            assert!(server.wait_for_disconnects(1, Duration::from_secs(10)));
            outcomes.push(out);
        }
        let (r, t) = (&outcomes[0], &outcomes[1]);
        assert_eq!((r.code, r.signal), (130, None));
        assert_eq!(
            r.stderr,
            "\n  ✗ Error: Interrupted; no data was written\n\n"
        );
        assert_eq!(t.signal, Some(2));
        assert_eq!((t.stdout.as_str(), t.stderr.as_str()), ("", ""));
    }

    /// D35: unknown policy keys - TS keeps server order, Rust sorts them (semantically equal).
    #[test]
    fn d35_policy_unknown_key_order() {
        // Hand-written wire bytes: the fixture's serde_json maps would sort the keys.
        let body = r#"{"ai_profiles":[{"profile_name":"p","policy":{"zeta-extension":1,"ai-security-profiles":[],"alpha-extension":2}}]}"#;
        let seed = move |server: &FixtureServer| {
            server.push_once(Route::Profiles, Planned::raw(200, "application/json", body));
        };
        let Some((r, t)) = sides("d35", &plain(&seed), LIST) else {
            return;
        };
        assert_eq!(r.requests, t.requests);
        assert_json_semantic_eq(&r.run.json(), &t.run.json());
        let order = |text: &str| {
            let z = text.find("zeta-extension").unwrap_or(0);
            let a = text.find("alpha-extension").unwrap_or(0);
            z < a
        };
        assert!(!order(&r.run.stdout), "Rust sorts unknown keys");
        assert!(order(&t.run.stdout), "TS keeps input order");
    }

    /// D37: repeated-cursor text.
    #[test]
    fn d37_repeated_cursor() {
        let seed = |server: &FixtureServer| {
            server.set_default(
                Route::Profiles,
                Planned::json(
                    200,
                    &json!({"ai_profiles": [fixtures::profile(1, "alpha", 1)], "next_offset": 5}),
                ),
            );
        };
        let Some((r, t)) = sides("d37", &plain(&seed), &with(LIST, &["--all"])) else {
            return;
        };
        assert_eq!(r.requests, t.requests, "both stop after offset 0 and 5");
        assert_eq!(r.count(Route::Profiles), 2);
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(
            r.error().as_deref(),
            Some(
                "AISEC_SDK_ERROR:Pagination stopped: the service returned a repeated cursor or an empty intermediate page"
            )
        );
        assert_eq!(
            t.error().as_deref(),
            Some("Pagination returned a repeated cursor")
        );
        assert_eq!((r.run.stdout.as_str(), t.run.stdout.as_str()), ("", ""));
    }

    /// D38: response-validation text.
    #[test]
    fn d38_schema_invalid_rows() {
        const RUST: &str = "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema";
        let cases: Vec<(&[&str], Route, Planned, &str)> = vec![
            (
                LIST,
                Route::Profiles,
                Planned::json(
                    200,
                    &json!({"ai_profiles": [{"revision": 1}], "next_offset": null}),
                ),
                "AISEC_RESPONSE_VALIDATION:Response did not match schema: ai_profiles.0.profile_name: invalid_type; next_offset: invalid_type",
            ),
            (
                LIST,
                Route::Profiles,
                Planned::raw(200, "application/json", "{not json"),
                "AISEC_RESPONSE_VALIDATION:Response body is not valid JSON",
            ),
            (
                TLIST,
                Route::Topics,
                Planned::json(
                    200,
                    &json!({"custom_topics": [{"topic_name": "t", "revision": 1}]}),
                ),
                "AISEC_RESPONSE_VALIDATION:Response did not match schema: custom_topics.0.description: invalid_type",
            ),
            (
                LIST,
                Route::Profiles,
                Planned::json(
                    200,
                    &json!({"ai_profiles": [{"profile_name": "p", "created_by": null}]}),
                ),
                "AISEC_RESPONSE_VALIDATION:Response did not match schema: ai_profiles.0.created_by: invalid_type",
            ),
        ];
        for (args, route, planned, ts_text) in cases {
            let seed = move |server: &FixtureServer| server.push_once(route, planned.clone());
            let Some((r, t)) = sides("d38", &plain(&seed), args) else {
                return;
            };
            assert_eq!(r.requests, t.requests);
            assert_eq!((r.run.code, t.run.code), (1, 1));
            assert_eq!((r.run.stdout.as_str(), t.run.stdout.as_str()), ("", ""));
            assert_eq!(r.error().as_deref(), Some(RUST));
            assert_eq!(t.error().as_deref(), Some(ts_text));
            assert_eq!((r.run.http_status(), t.run.http_status()), (None, None));
        }
    }

    /// D39: `topics list --all-versions --all --max N`: TS ignores --max.
    #[test]
    fn d39_all_versions_all_max() {
        let Some((r, t)) = sides(
            "d39",
            &plain(&topics(fin_legal())),
            &with(TLIST, &["--all-versions", "--all", "--max", "2"]),
        ) else {
            return;
        };
        assert_eq!(r.requests, t.requests);
        assert_eq!((len(&r), len(&t)), (2, 3));
        assert_eq!(
            r.run.stderr,
            "  Showing first 2 (stopped at --max 2; more available)\n"
        );
        assert_eq!(t.run.stderr, "  Showing all 3\n");
    }
}

// ---------------------------------------------------------------------------
// Divergences added with the review fixes (DESIGN §12 D29, D46)
// ---------------------------------------------------------------------------

mod divergence_review {
    use super::*;

    /// D29: reserved characters in the client pair: TS sends `base64(id:secret)` raw,
    /// airs-cli-rs form-encodes each half first (RFC 6749 §2.3.1). Both authenticate.
    #[test]
    fn d29_basic_encoding() {
        let edit = |config: &mut FixtureConfig| {
            config.set("mgmtClientId", "client+/100");
            config.set("mgmtClientSecret", "FAKE+SECRET/=x");
        };
        let setup = Setup {
            tenant: Some(&edit),
            ..plain(&|server: &FixtureServer| {
                server.set_profiles(TSG, vec![fixtures::profile(1, "alpha", 1)]);
            })
        };
        let Some(ts) = require_ts("d29_basic_encoding") else {
            return;
        };
        for (cli, expected) in [
            (rust(), airs_test_harness::BasicEncoding::FormUrlEncoded),
            (ts, airs_test_harness::BasicEncoding::Raw),
        ] {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
            sandbox.register(&[&tenant], Some("prod"));
            (setup.server)(&server);
            let out = run(&cli, &sandbox, LIST, &RunOptions::new());
            out.assert_success();
            let token = &server.requests_for(Route::Token)[0];
            assert_eq!(token.basic_encoding, Some(expected), "{}", cli.label());
            assert!(
                matches!(
                    token.auth,
                    airs_test_harness::AuthIdentity::Basic { valid: true, .. }
                ),
                "{}: {:?}",
                cli.label(),
                token.auth
            );
        }
    }

    /// D46: an empty intermediate page (no rows, a fresh non-zero `next_offset`): TS
    /// follows the cursor and prints every row (exit 0); airs-cli-rs fails the walk with
    /// the SDK pagination error and no partial data (exit 1).
    #[test]
    fn d46_empty_intermediate_page() {
        let seed = |server: &FixtureServer| {
            server.push_once(
                Route::Profiles,
                Planned::json(200, &json!({"ai_profiles": [], "next_offset": 100})),
            );
            server.set_default(
                Route::Profiles,
                Planned::json(
                    200,
                    &json!({"ai_profiles": [fixtures::profile(1, "alpha", 1)], "next_offset": 0}),
                ),
            );
        };
        let Some((r, t)) = sides("d46_empty_page", &plain(&seed), &with(LIST, &["--all"])) else {
            return;
        };
        assert_eq!(t.run.code, 0, "{:?}", t.run);
        assert_eq!(t.run.json()[0]["profileName"], "alpha", "{:?}", t.run);
        assert_eq!(t.count(Route::Profiles), 2, "TS follows the cursor");
        assert_eq!(r.run.code, 1, "{:?}", r.run);
        assert_eq!(r.run.stdout, "");
        assert_eq!(
            r.error().as_deref(),
            Some(
                "AISEC_SDK_ERROR:Pagination stopped: the service returned a repeated cursor or an empty intermediate page"
            )
        );
        assert_eq!(r.count(Route::Profiles), 1);
    }
}

// ---------------------------------------------------------------------------
// parity: pretty and table renderings, exact bytes (DESIGN §7.6, R§3.1–R§3.4)
// ---------------------------------------------------------------------------

mod render {
    use super::*;

    /// Exact parity: exit code, stdout and stderr bytes, requests.
    pub(super) fn assert_bytes(r: &Side, t: &Side) {
        let ctx = || format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run);
        assert_eq!(r.run.code, t.run.code, "exit codes differ{}", ctx());
        assert_eq!(r.run.stdout, t.run.stdout, "stdout differs{}", ctx());
        assert_eq!(r.run.stderr, t.run.stderr, "stderr differs{}", ctx());
        assert_eq!(r.requests, t.requests, "requests differ{}", ctx());
    }

    /// Runs `args` on both CLIs (standard tenant, `seed`) and asserts exact bytes.
    pub(super) fn bytes(name: &str, seed: &dyn Fn(&FixtureServer), args: &[&str]) -> Option<Side> {
        let (r, t) = sides(name, &plain(seed), args)?;
        assert_bytes(&r, &t);
        Some(r)
    }

    const PROFILES: &[&str] = &["runtime", "profiles", "list"];
    const TOPICS: &[&str] = &["runtime", "topics", "list"];

    fn pget(extra: &[&'static str]) -> Vec<&'static str> {
        with(&["runtime", "profiles", "get"], extra)
    }

    fn tget(extra: &[&'static str]) -> Vec<&'static str> {
        with(&["runtime", "topics", "get"], extra)
    }

    /// The formats compared byte for byte: the default (no `--output`), pretty, table.
    const FORMATS: [&[&str]; 3] = [&[], &["--output", "pretty"], &["--output", "table"]];

    /// Profiles whose renderings involve no §12 row (no missing ID, no control
    /// characters, no wide text): absent `active`, revision 0, absent revision, a long
    /// name, Latin and emoji text, CSV/markdown metacharacters, JS number forms.
    fn edge_profiles() -> Vec<Value> {
        vec![
            json!({"profile_id": fixtures::uuid(10), "profile_name": "no-active-field", "revision": 0}),
            json!({"profile_id": fixtures::uuid(11), "profile_name": "inactive-no-revision", "active": false,
                   "last_modified_ts": "2026-02-01T00:00:00Z"}),
            json!({"profile_id": fixtures::uuid(5), "profile_name":
                   "a-very-long-security-profile-name-that-goes-on-and-on-for-a-while-0123456789",
                   "revision": 3, "active": true}),
            json!({"profile_id": fixtures::uuid(6), "profile_name": "prøfile-ünïcödé-🚀", "revision": 1, "active": true}),
            json!({"profile_id": fixtures::uuid(7), "profile_name": "pipe|comma,quote\"", "revision": 1, "active": true}),
            json!({"profile_id": fixtures::uuid(31), "profile_name": "frac-rev", "revision": 2.5, "active": true}),
            json!({"profile_id": fixtures::uuid(32), "profile_name": "huge-rev", "revision": 1e21, "active": true}),
        ]
    }

    /// A policy with known keys only, nested several levels (one 1,000+ character
    /// compact cell); unknown keys are D60.
    fn big_policy_profile() -> Value {
        json!({
            "profile_id": fixtures::uuid(4), "profile_name": "big-policy", "revision": 7, "active": true,
            "created_by": "creator@example.com", "updated_by": "updater@example.com",
            "last_modified_ts": "2026-02-01T00:00:00Z",
            "policy": {
                "ai-security-profiles": [{
                    "model-type": "default",
                    "content-type": "text",
                    "model-configuration": {
                        "mask-data-in-storage": true,
                        "latency": {"inline-timeout-action": "block", "max-inline-latency": 20},
                        "data-protection": {
                            "data-leak-detection": {
                                "member": [{"text": "Bank Account Numbers", "id": "11995035", "version": "2"}],
                                "action": "block", "mask-data-inline": false
                            },
                            "database-security": [{"name": "database-security-create", "action": "allow"}]
                        },
                        "app-protection": {
                            "alert-url-category": {"member": ["adult", "gambling"]},
                            "block-url-category": {"member": null},
                            "url-detected-action": "alert",
                            "malicious-code-protection": {"name": "malicious-code", "action": "block"}
                        },
                        "model-protection": [
                            {"name": "prompt-injection", "action": "block", "options": []},
                            {"name": "topic-guardrails", "action": "", "topic-list": [{"action": "block",
                              "topic": [{"topic_name": "fin", "topic_id": fixtures::uuid(12), "revision": 2}]}]},
                            {"name": "toxic-content", "action": "high:block, moderate:block"}
                        ],
                        "agent-protection": [{"name": "agent-security", "action": "block"}]
                    }
                }],
                "dlp-data-profiles": [{"name": "Bank Account Numbers",
                    "uuid": "aa3c0e2b-0000-4000-8000-000000000001", "rule1": {"action": "block"}}]
            }
        })
    }

    #[test]
    fn profiles_list_render() {
        for format in FORMATS {
            for extra in [&[][..], &["--limit", "1"], &["--all"], &["--all-versions"]] {
                let args = with(&with(PROFILES, format), extra);
                bytes("profiles_list_render", &profiles(alpha_beta()), &args);
            }
            let empty = bytes(
                "profiles_list_render_empty",
                &nothing,
                &with(PROFILES, format),
            );
            // `None` when parity is skipped (AIRS_ALLOW_PARITY_SKIP=1).
            if format == ["--output", "table"]
                && let Some(empty) = empty
            {
                assert_eq!(empty.run.stdout, "");
            }
        }
        // --quiet changes neither a table nor its absence of status lines (D55 is pretty).
        let quiet = bytes(
            "profiles_list_render_quiet",
            &profiles(alpha_beta()),
            &[
                "runtime", "profiles", "list", "--output", "table", "--quiet",
            ],
        );
        if let Some(r) = quiet {
            assert_eq!(r.run.stderr, "");
            assert!(r.run.stdout.starts_with(" ID "), "{}", r.run.stdout);
        }
        let empty_quiet = bytes(
            "profiles_list_render_empty_quiet",
            &nothing,
            &["--quiet", "runtime", "profiles", "list"],
        );
        if let Some(r) = empty_quiet {
            assert_eq!(r.run.stdout, "  No profiles found\n");
        }
    }

    #[test]
    fn profiles_list_render_edges() {
        for format in FORMATS {
            let r = bytes(
                "profiles_list_render_edges",
                &profiles(edge_profiles()),
                &with(PROFILES, format),
            );
            if let Some(r) = r
                && format.is_empty()
            {
                assert!(r.run.stdout.contains("    frac-rev  active rev:2.5\n"));
                assert!(r.run.stdout.contains("    huge-rev  active rev:1e+21\n"));
                assert!(
                    r.run
                        .stdout
                        .contains("    no-active-field  inactive rev:0\n")
                );
                assert!(
                    r.run
                        .stdout
                        .contains("    inactive-no-revision  inactive\n")
                );
            }
        }
        // A profile without an ID is an empty cell in both tables (pretty is D56).
        let mut rows = edge_profiles();
        rows.push(json!({"profile_name": "no-id-inactive", "active": false}));
        bytes(
            "profiles_list_render_edges_no_id",
            &profiles(rows),
            &with(PROFILES, &["--output", "table"]),
        );
    }

    #[test]
    fn profiles_get_render() {
        let mut rows = alpha_beta();
        rows.push(json!({"profile_name": "sparse", "active": false, "last_modified_ts": "2026-02-01T00:00:00Z"}));
        rows.push(
            json!({"profile_id": fixtures::uuid(8), "profile_name": "empty-policy", "revision": 1,
                         "active": true, "policy": {}}),
        );
        rows.push(big_policy_profile());
        let id = fixtures::uuid(3);
        let id: &'static str = Box::leak(id.into_boxed_str());
        for format in FORMATS {
            for lookup in [
                &["alpha"][..],
                &[id],
                &["alpha", "--revision", "1"],
                &["alpha", "--all-versions"],
                &["sparse"],
                &["empty-policy"],
                &["big-policy"],
            ] {
                let args = with(&pget(lookup), format);
                let r = bytes("profiles_get_render", &profiles(rows.clone()), &args);
                if let Some(r) = r {
                    assert_eq!(r.run.stderr, "", "gets print no status: {args:?}");
                }
            }
        }
        for quiet in [
            pget(&["alpha", "--quiet"]),
            pget(&["big-policy", "--quiet", "--output", "table"]),
        ] {
            bytes("profiles_get_render_quiet", &profiles(rows.clone()), &quiet);
        }
    }

    #[test]
    fn topics_list_render() {
        let mut rows = fin_legal();
        rows.push(fixtures::topic(20, "eighty", 1, &"e".repeat(80)));
        rows.push(fixtures::topic(21, "eighty-one", 1, &"f".repeat(81)));
        rows.push(fixtures::topic(22, "no-description", 1, ""));
        rows.push(fixtures::topic(
            23,
            "tøpic-ünï-🚀",
            4,
            "Latin, emoji 🚀 and | pipes",
        ));
        for format in FORMATS {
            for extra in [
                &[][..],
                &["--all"],
                &["--all-versions"],
                &["--all-versions", "--limit", "2"],
            ] {
                let args = with(&with(TOPICS, format), extra);
                bytes("topics_list_render", &topics(rows.clone()), &args);
            }
            bytes("topics_list_render_empty", &nothing, &with(TOPICS, format));
        }
        bytes(
            "topics_list_render_quiet",
            &topics(rows.clone()),
            &with(TOPICS, &["--output", "table", "--quiet"]),
        );
    }

    #[test]
    fn topics_get_render() {
        let mut rows = fin_legal();
        rows.push(json!({
            "topic_id": fixtures::uuid(21), "topic_name": "many-examples", "revision": 3, "active": true,
            "description": "Has several examples",
            "examples": ["first example", "second, with comma", "third | pipe", "ünïcödé 🚀"],
            "created_by": "creator@example.com", "updated_by": "updater@example.com",
            "last_modified_ts": "2026-02-01T00:00:00Z", "created_ts": "2026-01-01T00:00:00Z"
        }));
        rows.push(
            json!({"topic_id": fixtures::uuid(22), "topic_name": "no-examples", "revision": 1,
                         "description": ""}),
        );
        rows.push(
            json!({"topic_id": fixtures::uuid(24), "topic_name": "updater-only", "revision": 2,
                         "description": "d", "updated_by": "updater@example.com"}),
        );
        for format in FORMATS {
            for lookup in [
                &["fin"][..],
                &["many-examples"],
                &["no-examples"],
                &["updater-only"],
                &["fin", "--revision", "1"],
                &["fin", "--all-versions"],
            ] {
                bytes(
                    "topics_get_render",
                    &topics(rows.clone()),
                    &with(&tget(lookup), format),
                );
            }
        }
        bytes(
            "topics_get_render_quiet",
            &topics(rows.clone()),
            &tget(&["many-examples", "--quiet"]),
        );
    }

    #[test]
    fn default_output_render() {
        let edit = |config: &mut FixtureConfig| {
            config.set("defaultOutput", "table");
        };
        let seed = profiles(alpha_beta());
        for args in [
            &["runtime", "profiles", "list"][..],
            &["runtime", "profiles", "get", "alpha"],
            &["runtime", "profiles", "list", "--output", "pretty"],
            &["--output", "json", "runtime", "profiles", "list"],
            &[
                "--output", "pretty", "runtime", "profiles", "list", "--output", "table",
            ],
        ] {
            let setup = Setup {
                tenant: Some(&edit),
                ..plain(&seed)
            };
            let Some((r, t)) = sides("default_output_render", &setup, args) else {
                return;
            };
            assert_bytes(&r, &t);
        }
        let json_default = |config: &mut FixtureConfig| {
            config.set("defaultOutput", "json");
        };
        let setup = Setup {
            tenant: Some(&json_default),
            ..plain(&seed)
        };
        let Some((r, t)) = sides(
            "default_output_render_json",
            &setup,
            &["runtime", "topics", "list"],
        ) else {
            return;
        };
        assert_parity(&r, &t);
        assert_eq!(r.run.stdout, "[]\n");
    }

    /// Forced colour on both sides (`CLICOLOR_FORCE` for Rust, `FORCE_COLOR` for TS):
    /// the same escape codes and spans (DESIGN §2.8).
    #[test]
    fn forced_colour_render() {
        let seed = |server: &FixtureServer| {
            server.set_profiles(TSG, alpha_beta());
            let mut rows = fin_legal();
            rows.push(
                json!({"topic_id": fixtures::uuid(9), "topic_name": "inactive", "revision": 1,
                             "description": "", "active": false}),
            );
            server.set_topics(TSG, rows);
        };
        let mut sparse = alpha_beta();
        sparse
            .push(json!({"profile_id": fixtures::uuid(9), "profile_name": "off", "active": false}));
        for args in [
            &["runtime", "profiles", "list"][..],
            &["runtime", "profiles", "get", "alpha"],
            &["runtime", "topics", "list"],
            &["runtime", "topics", "get", "fin"],
            &["runtime", "topics", "list", "--output", "table"],
            &["runtime", "topics", "get", "nosuch"],
        ] {
            let Some(ts) = require_ts("forced_colour_render") else {
                return;
            };
            let rust_side = exec(&rust(), &coloured(&seed, false), args);
            let ts_side = exec(&ts, &coloured(&seed, true), args);
            match rust_side.run.code {
                0 => assert_bytes(&rust_side, &ts_side),
                // TS has already printed the banner (D57); stderr is identical.
                _ => {
                    assert_eq!(rust_side.run.code, ts_side.run.code);
                    assert_eq!(rust_side.run.stdout, "");
                    assert_eq!(rust_side.run.stderr, ts_side.run.stderr);
                    assert!(rust_side.run.stderr.contains("\u{1b}[31m"));
                }
            }
            if !args.contains(&"table") && rust_side.run.code == 0 {
                assert!(rust_side.run.stdout.contains("\u{1b}[1m"), "{args:?}");
            }
        }
        let Some(ts) = require_ts("forced_colour_render") else {
            return;
        };
        let seed_sparse = profiles(sparse);
        let args = ["runtime", "profiles", "list"];
        let r = exec(&rust(), &coloured(&seed_sparse, false), &args);
        let t = exec(&ts, &coloured(&seed_sparse, true), &args);
        assert_bytes(&r, &t);
        assert!(r.run.stdout.contains("\u{1b}[33minactive\u{1b}[39m"));
    }

    /// The standard tenant with colour forced for the given CLI.
    pub(super) fn coloured<'a>(seed: &'a dyn Fn(&FixtureServer), ts: bool) -> Setup<'a> {
        let options = RunOptions::new().without_env("NO_COLOR");
        Setup {
            options: if ts {
                options.env("FORCE_COLOR", "1")
            } else {
                options.env("CLICOLOR_FORCE", "1")
            },
            ..plain(seed)
        }
    }
}

// ---------------------------------------------------------------------------
// divergences of the 0.2 renderer (DESIGN §12 D50–D60)
// ---------------------------------------------------------------------------

mod divergence_render {
    use super::render::{assert_bytes, coloured};
    use super::*;

    /// D50: the dropped formats are a usage error before the tenant is read; TS
    /// renders them.
    #[test]
    fn d50_dropped_formats() {
        for (format, ts_marker) in [
            ("yaml", "profileName: alpha"),
            ("csv", "ID,Name,Active,Revision"),
            ("markdown", "| ID | Name | Active | Revision |"),
        ] {
            for args in [
                vec!["runtime", "profiles", "list", "--output", format],
                vec![
                    "--output",
                    format,
                    "runtime",
                    "profiles",
                    "get",
                    "alpha",
                    "--all-versions",
                ],
            ] {
                let Some((r, t)) = sides(
                    "d50_dropped_formats",
                    &plain(&profiles(alpha_beta())),
                    &args,
                ) else {
                    return;
                };
                assert_eq!(r.run.code, 2);
                assert_eq!(
                    r.run.stderr,
                    format!(
                        "\n  ✗ Invalid output format '{format}'. Expected: pretty, table, json\n\n"
                    )
                );
                assert_eq!(r.run.stdout, "");
                assert!(r.requests.is_empty());
                assert_eq!(t.run.code, 0, "{args:?}");
                assert!(t.run.stdout.contains(ts_marker), "{}", t.run.stdout);
            }
        }
    }

    /// D51: a dropped `defaultOutput` makes the config invalid for airs-cli-rs; TS
    /// renders that format.
    #[test]
    fn d51_default_output_dropped() {
        for value in ["yaml", "markdown", "csv"] {
            let edit = move |config: &mut FixtureConfig| {
                config.set("defaultOutput", value);
            };
            let seed = profiles(alpha_beta());
            let setup = Setup {
                tenant: Some(&edit),
                ..plain(&seed)
            };
            let Some(ts) = require_ts("d51_default_output_dropped") else {
                return;
            };
            let args = ["runtime", "profiles", "list"];
            // The TypeScript config keeps the dead format; import would drop it, so the
            // Rust tenant file is given it explicitly (D51 holds for the TOML store).
            let line = format!("defaultOutput = \"{value}\"");
            let r = exec_with_store(&rust(), &setup, &args, &|sandbox| {
                sandbox.set_tenant_line("prod", "defaultOutput", &line);
            });
            let t = exec(&ts, &setup, &args);
            assert_eq!(r.run.code, 1);
            assert_eq!(r.run.stdout, "");
            assert!(
                r.error()
                    .is_some_and(|line| line.starts_with("Cannot read a valid tenant config at ")),
                "{:?}",
                r.run
            );
            assert!(r.requests.is_empty());
            assert_eq!(t.run.code, 0);
            assert!(!t.run.stdout.is_empty());
            assert_eq!(t.run.stderr, "  Showing 2\n");
        }
    }

    /// D52: ESC, TAB, LF, DEL and C1 controls in names, descriptions and examples are
    /// U+FFFD in airs-cli-rs; TS writes them raw. JSON in cells stays escaped.
    #[test]
    fn d52_control_characters() {
        let hostile = "ctl\u{1b}[31mred\ttab\nline\u{7f}\u{9b}x";
        let safe = "ctl\u{fffd}[31mred\u{fffd}tab\u{fffd}line\u{fffd}\u{fffd}x";
        let seed = |server: &FixtureServer| {
            server.set_profiles(
                TSG,
                vec![
                    json!({"profile_id": fixtures::uuid(33), "profile_name": hostile,
                                                 "revision": 1, "active": true}),
                ],
            );
            server.set_topics(
                TSG,
                vec![json!({"topic_id": fixtures::uuid(34), "topic_name": "t",
                                               "revision": 1, "description": hostile,
                                               "examples": [hostile]})],
            );
        };
        for args in [
            &["runtime", "profiles", "list"][..],
            &["runtime", "profiles", "list", "--output", "table"],
            &["runtime", "profiles", "get", fixtures::uuid(33).leak()],
            &["runtime", "topics", "list"],
            &["runtime", "topics", "list", "--output", "table"],
            &["runtime", "topics", "get", "t"],
            &["runtime", "topics", "get", "t", "--output", "table"],
        ] {
            let Some((r, t)) = sides("d52_control_characters", &plain(&seed), args) else {
                return;
            };
            assert_eq!((r.run.code, t.run.code), (0, 0));
            assert!(
                !r.run.stdout.chars().any(|c| c.is_control() && c != '\n'),
                "{args:?}: {:?}",
                r.run.stdout
            );
            assert!(
                t.run.stdout.contains('\u{1b}'),
                "{args:?}: TS writes ESC raw"
            );
            if args.contains(&"table") && args.contains(&"get") {
                // The examples cell is JSON: C0 escaped by both, DEL/C1 replaced by Rust.
                assert!(
                    r.run.stdout.contains(r#"["ctl\u001b[31mred\ttab\nline"#),
                    "{}",
                    r.run.stdout
                );
            } else {
                assert!(r.run.stdout.contains(safe), "{args:?}: {}", r.run.stdout);
            }
        }
    }

    /// D53: wide text pads by display width in airs-cli-rs (aligned columns); TS pads
    /// by UTF-16 units. Rows of ASCII text keep identical bytes.
    #[test]
    fn d53_unicode_width() {
        let rows = vec![
            fixtures::profile(1, "alpha", 1),
            json!({"profile_id": fixtures::uuid(6), "profile_name": "prøfile-日本語-🚀", "revision": 1, "active": true}),
            json!({"profile_id": fixtures::uuid(7), "profile_name": "combining-e\u{301}", "revision": 1, "active": true}),
        ];
        let Some((r, t)) = sides(
            "d53_unicode_width",
            &plain(&profiles(rows)),
            &["runtime", "profiles", "list", "--output", "table"],
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (0, 0));
        let columns = |line: &str| -> Vec<usize> {
            // The display column of each separator.
            let mut width = 0;
            let mut seps = Vec::new();
            for c in line.chars() {
                if c == '│' {
                    seps.push(width);
                }
                width += match c {
                    '日' | '本' | '語' | '🚀' => 2,
                    '\u{301}' => 0,
                    _ => 1,
                };
            }
            seps
        };
        let r_lines: Vec<&str> = r.run.stdout.lines().collect();
        let t_lines: Vec<&str> = t.run.stdout.lines().collect();
        assert!(
            r_lines
                .iter()
                .filter(|l| l.contains('│'))
                .all(|l| columns(l) == columns(r_lines[0]))
        );
        assert_ne!(
            columns(t_lines[3]),
            columns(t_lines[0]),
            "TS misaligns the CJK row"
        );
        assert_ne!(
            columns(t_lines[4]),
            columns(t_lines[0]),
            "TS misaligns the combining row"
        );
        // The widest name is the CJK one under display width only.
        assert_ne!(r_lines[0], t_lines[0]);
    }

    /// D54: a description whose 80th UTF-16 unit splits a surrogate pair: TS keeps the
    /// lone surrogate (written as U+FFFD), airs-cli-rs drops the character.
    #[test]
    fn d54_description_surrogate_cut() {
        let description = format!("{}🚀tail after the boundary", "d".repeat(79));
        let Some((r, t)) = sides(
            "d54_description_surrogate_cut",
            &plain(&topics(vec![fixtures::topic(
                20,
                "long-desc",
                1,
                &description,
            )])),
            &["runtime", "topics", "list"],
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (0, 0));
        let cut = "d".repeat(79);
        assert!(
            r.run
                .stdout
                .contains(&format!("    long-desc rev:1 — {cut}\n")),
            "{}",
            r.run.stdout
        );
        assert!(
            t.run
                .stdout
                .contains(&format!("    long-desc rev:1 — {cut}\u{fffd}\n")),
            "{}",
            t.run.stdout
        );
        assert_eq!(
            r.run
                .stdout
                .replace(&format!("{cut}\n"), &format!("{cut}\u{fffd}\n")),
            t.run.stdout,
            "otherwise identical"
        );
    }

    /// D55: `--quiet` keeps the pretty-list ID lines in airs-cli-rs; TS drops them.
    #[test]
    fn d55_quiet_id_lines() {
        for (args, seed) in [
            (
                &["--quiet", "runtime", "profiles", "list"][..],
                profiles(alpha_beta()),
            ),
            (
                &[
                    "runtime",
                    "profiles",
                    "get",
                    "alpha",
                    "--all-versions",
                    "--quiet",
                ],
                profiles(alpha_beta()),
            ),
        ] {
            let Some((r, t)) = sides("d55_quiet_id_lines", &plain(&seed), args) else {
                return;
            };
            assert_eq!((r.run.code, t.run.code), (0, 0));
            assert_eq!((r.run.stderr.as_str(), t.run.stderr.as_str()), ("", ""));
            let ids: String = r
                .run
                .stdout
                .lines()
                .filter(|l| !l.starts_with("  00"))
                .map(|l| format!("{l}\n"))
                .collect();
            assert_eq!(
                ids, t.run.stdout,
                "TS is the Rust output without the ID lines"
            );
            assert!(r.run.stdout.contains(&format!("  {}\n", fixtures::uuid(2))));
        }
        let Some((r, t)) = sides(
            "d55_quiet_id_lines_topics",
            &plain(&topics(fin_legal())),
            &["runtime", "topics", "list", "--quiet"],
        ) else {
            return;
        };
        assert_eq!(
            t.run.stdout,
            "    fin rev:2 — new\n    legal rev:1 — law\n\n"
        );
        assert_eq!(
            r.run.stdout,
            format!(
                "  {}\n    fin rev:2 — new\n  {}\n    legal rev:1 — law\n\n",
                fixtures::uuid(2),
                fixtures::uuid(3)
            )
        );
    }

    /// D56: a pretty list row without an ID: TS prints `  undefined`, airs-cli-rs omits
    /// the line.
    #[test]
    fn d56_missing_id() {
        type Seed = Box<dyn Fn(&FixtureServer)>;
        let cases: [(&[&str], Seed); 2] = [
            (
                &["runtime", "profiles", "list"],
                Box::new(profiles(vec![
                    json!({"profile_name": "no-id-inactive", "active": false}),
                ])),
            ),
            (
                &["runtime", "topics", "list"],
                Box::new(topics(vec![
                    json!({"topic_name": "no-id", "revision": 1, "description": "desc"}),
                ])),
            ),
        ];
        for (args, seed) in cases {
            let Some((r, t)) = sides("d56_missing_id", &plain(seed.as_ref()), args) else {
                return;
            };
            assert_eq!((r.run.code, t.run.code), (0, 0));
            assert!(t.run.stdout.contains("\n  undefined\n"), "{}", t.run.stdout);
            assert!(!r.run.stdout.contains("undefined"));
            assert_eq!(r.run.stdout, t.run.stdout.replace("  undefined\n", ""));
            assert_eq!(r.run.stderr, t.run.stderr);
        }
    }

    /// D57: a failing pretty management read leaves stdout empty; TS has already written
    /// the banner. stderr is identical.
    #[test]
    fn d57_failing_pretty_read_stdout_empty() {
        const BANNER: &str =
            "\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n";
        for args in [
            &["runtime", "profiles", "get", "nosuch"][..],
            &["runtime", "topics", "get", "nosuch"],
            &["runtime", "profiles", "list", "--output", "pretty"],
        ] {
            let seed = |server: &FixtureServer| {
                server.set_profiles(TSG, alpha_beta());
                server.set_default(Route::Profiles, Planned::json(404, &json!({})));
            };
            let seed_get = profiles(alpha_beta());
            let setup = if args.contains(&"list") {
                plain(&seed)
            } else {
                plain(&seed_get)
            };
            let Some((r, t)) = sides("d57_failing_pretty_read_stdout_empty", &setup, args) else {
                return;
            };
            assert_eq!((r.run.code, t.run.code), (1, 1), "{args:?}");
            assert_eq!(r.run.stdout, "");
            assert_eq!(t.run.stdout, BANNER);
            assert_eq!(r.error(), t.error());
            assert_eq!(r.run.http_status(), t.run.http_status());
        }
        // In table the TS stdout is empty too.
        let Some((r, t)) = sides(
            "d57_table",
            &plain(&profiles(alpha_beta())),
            &["runtime", "profiles", "get", "nosuch", "--output", "table"],
        ) else {
            return;
        };
        assert_eq!((r.run.stdout.as_str(), t.run.stdout.as_str()), ("", ""));
        assert_eq!(r.run.stderr, t.run.stderr);
    }

    /// D58: colour. Piped, neither CLI colours. `FORCE_COLOR` colours only TS (with a
    /// Node warning when `NO_COLOR` is also set); `CLICOLOR_FORCE` colours only
    /// airs-cli-rs, and `NO_COLOR` wins over it.
    #[test]
    fn d58_colour() {
        let seed = profiles(alpha_beta());
        let args = ["runtime", "profiles", "list"];
        let Some(ts) = require_ts("d58_colour") else {
            return;
        };
        let ansi =
            |side: &Side| side.run.stdout.contains('\u{1b}') || side.run.stderr.contains('\u{1b}');
        let with_options = |options: RunOptions| Setup {
            options,
            ..plain(&seed)
        };
        // Piped with the harness's NO_COLOR=1, and piped with no colour variable at all.
        for options in [RunOptions::new(), RunOptions::new().without_env("NO_COLOR")] {
            let r = exec(&rust(), &with_options(options.clone()), &args);
            let t = exec(&ts, &with_options(options), &args);
            assert!(!ansi(&r) && !ansi(&t));
            assert_bytes(&r, &t);
        }
        // FORCE_COLOR: TS only.
        let forced = RunOptions::new()
            .without_env("NO_COLOR")
            .env("FORCE_COLOR", "1");
        let r = exec(&rust(), &with_options(forced.clone()), &args);
        let t = exec(&ts, &with_options(forced), &args);
        assert!(!ansi(&r) && ansi(&t));
        // FORCE_COLOR with NO_COLOR: TS still colours and warns; Rust does neither.
        let both = RunOptions::new().env("FORCE_COLOR", "1");
        let r = exec(&rust(), &with_options(both.clone()), &args);
        let t = exec(&ts, &with_options(both), &args);
        assert!(!ansi(&r) && ansi(&t));
        assert!(
            t.run
                .stderr
                .contains("Warning: The 'NO_COLOR' env is ignored"),
            "{}",
            t.run.stderr
        );
        assert_eq!(r.run.stderr, "  Showing 2\n");
        // CLICOLOR_FORCE: Rust only, on both of its streams.
        let clicolor = RunOptions::new()
            .without_env("NO_COLOR")
            .env("CLICOLOR_FORCE", "1");
        let r = exec(&rust(), &with_options(clicolor.clone()), &args);
        let t = exec(&ts, &with_options(clicolor), &args);
        assert!(ansi(&r) && !ansi(&t));
        assert_eq!(r.run.stderr, "  \u{1b}[2mShowing 2\u{1b}[22m\n");
        // NO_COLOR wins over CLICOLOR_FORCE.
        let r = exec(
            &rust(),
            &with_options(RunOptions::new().env("CLICOLOR_FORCE", "1")),
            &args,
        );
        assert!(!ansi(&r));
        // The forced TS bytes equal the forced Rust bytes (same codes and spans).
        let r = exec(&rust(), &coloured(&seed, false), &args);
        let t = exec(&ts, &coloured(&seed, true), &args);
        assert_bytes(&r, &t);
    }

    /// D60: unknown policy keys are sorted (SDK model) in the pretty `Policy` block and
    /// the table `policy` cell; TS keeps JS object order (integer-like keys first).
    #[test]
    fn d60_policy_key_order() {
        let row = json!({
            "profile_id": fixtures::uuid(4), "profile_name": "unknown-keys", "revision": 1, "active": true,
            "policy": {"dlp-data-profiles": [], "zz-unknown": {"b": 2, "10": "ten", "a": 1, "2": "two"}}
        });
        for args in [
            &["runtime", "profiles", "get", "unknown-keys"][..],
            &[
                "runtime",
                "profiles",
                "get",
                "unknown-keys",
                "--output",
                "table",
            ],
        ] {
            let Some((r, t)) = sides(
                "d60_policy_key_order",
                &plain(&profiles(vec![row.clone()])),
                args,
            ) else {
                return;
            };
            assert_eq!((r.run.code, t.run.code), (0, 0));
            if args.contains(&"table") {
                assert!(
                    r.run
                        .stdout
                        .contains(r#""zz-unknown":{"10":"ten","2":"two","a":1,"b":2}"#),
                    "{}",
                    r.run.stdout
                );
                assert!(
                    t.run
                        .stdout
                        .contains(r#""zz-unknown":{"2":"two","10":"ten","a":1,"b":2}"#),
                    "{}",
                    t.run.stdout
                );
            } else {
                let order = |text: &str| -> Vec<String> {
                    text.lines()
                        .filter(|l| l.starts_with("      \""))
                        .map(|l| l.trim().split('"').nth(1).unwrap_or_default().to_owned())
                        .collect()
                };
                assert_eq!(order(&r.run.stdout), ["10", "2", "a", "b"]);
                // The fixture sends the keys sorted; JS moves integer-like keys first.
                assert_eq!(order(&t.run.stdout), ["2", "10", "a", "b"]);
            }
        }
    }
}
