//! Executable acceptance tests for the M6b step-1 DLP reads (DESIGN §16.1–§16.4):
//! `runtime dlp filtering-profiles|patterns|profiles|dictionaries list|ls|get`.
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server with the
//! seeded DLP dataset (`FixtureServer::seed_dlp`), whose custom records carry
//! `FAKE-DLP-CONTENT-<nn>` markers in their detection content. The runner's leak check
//! forbids every marker on stderr and in the debug log of each run; the tests assert
//! where they may appear on stdout (§16.9). The read cases of the TypeScript
//! `tests/unit/cli/dlp-renderer.spec.ts`, `dlp-visibility.spec.ts`, `dlp-debug.spec.ts`,
//! `tests/unit/airs/dlp/*.spec.ts` and `tests/integration/dlp-tenant-auth.spec.ts` are
//! ported here.

use std::time::Duration;

use airs_test_harness::fixtures::dlp as fx;
use airs_test_harness::{
    Cli, ClosedPort, Collection, Dl, FixtureConfig, FixtureServer, PageStyle, Planned,
    RecordedRequest, Route, Run, RunOptions, Sandbox, debug_log, run, spawn,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seeded DLP dataset and one standard tenant `prod` (TSG 100).
fn fx() -> Fx {
    fx_with(|_| {})
}

fn fx_with(edit: impl FnOnce(&mut FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    server.seed_dlp();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

impl Fx {
    fn run_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let before = self.sandbox.snapshot();
        let out = run(&rust(), &self.sandbox, args, options);
        self.sandbox.assert_unchanged(&before);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.cwd_listing().is_empty(), "wrote into cwd");
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        out
    }

    /// `runtime dlp <args>`, with the read-only and loopback checks.
    fn dlp(&self, args: &[&str]) -> Run {
        self.dlp_with(args, &RunOptions::new())
    }

    fn dlp_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let mut full = vec!["runtime", "dlp"];
        full.extend_from_slice(args);
        self.run_with(&full, options)
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

    fn clear(&self) {
        self.server.clear_requests();
    }
}

fn s(text: &str) -> String {
    text.to_owned()
}

const PATTERNS: &str = "/dlp/v2/api/data-patterns";
const PROFILES: &str = "/dlp/v2/api/data-profiles";
const DICTIONARIES: &str = "/dlp/v2/api/dictionaries";
const FILTERING: &str = "/dlp/v2/api/data-filtering-profiles";
const SORT: &str = "sort=name%2Casc";

/// The ids of a JSON list.
fn ids(out: &Run) -> Vec<String> {
    out.json()
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// `count` custom patterns `c-<nnn>` named `Custom <nnn>`.
fn custom_patterns(count: u64) -> Vec<Value> {
    (0..count)
        .map(|n| {
            fx::pattern(
                &format!("c-{n:03}"),
                &format!("Custom {n:03}"),
                "custom",
                "active",
                "regex",
                1,
                None,
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Request shapes (TS `unit/airs/dlp/*.spec.ts`, §16.3, §16.4)
// ---------------------------------------------------------------------------

mod requests {
    use super::*;

    /// D170: the default (custom-only) list of patterns, profiles and dictionaries reads
    /// every page of 100 with the default sort, then shows the custom rows.
    #[test]
    fn default_lists_walk_every_page_and_show_the_custom_rows() {
        let f = fx();
        for (group, path, expected, total) in [
            (
                "patterns",
                PATTERNS,
                vec!["p-del-1", "p-dis-1", "p-cus-1", "p-par-1"],
                4,
            ),
            (
                "profiles",
                PROFILES,
                vec!["dp-dis-1", "dp-multi-1", "dp-cus-1"],
                3,
            ),
            ("dictionaries", DICTIONARIES, vec!["d-cus-1"], 1),
        ] {
            f.clear();
            let out = f.dlp(&[group, "list", "--output", "json"]);
            out.assert_success();
            assert_eq!(ids(&out), expected, "{group}");
            assert_eq!(f.api(), [format!("GET {path}?page=0&size=100&{SORT}")]);
            assert_eq!(out.stderr, format!("  Showing {total} of {total}\n"));
        }
    }

    /// `filtering-profiles list` and `--include-predefined` send one server page: no
    /// `page` or `size` without `--limit`/`--offset` (TS), the server's total in the
    /// status line.
    #[test]
    fn server_pages_send_the_typescript_query() {
        let f = fx();
        let out = f.dlp(&["filtering-profiles", "ls", "--output", "json"]);
        out.assert_success();
        assert_eq!(ids(&out), ["fp-1", "fp-2"]);
        assert_eq!(f.api(), [format!("GET {FILTERING}?{SORT}")]);
        assert_eq!(out.stderr, "  Showing 2 of 2\n");
        f.clear();
        let out = f.dlp(&[
            "patterns",
            "list",
            "--include-predefined",
            "--limit",
            "2",
            "--offset",
            "2",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(ids(&out), ["p-dis-1", "p-cus-1"]);
        assert_eq!(f.api(), [format!("GET {PATTERNS}?page=1&size=2&{SORT}")]);
        assert_eq!(out.stderr, "  Showing 2 of 5 (next --offset 4)\n");
        f.clear();
        // --offset without --limit rounds with 50 and sends size=50 (D170).
        let out = f.dlp(&["profiles", "ls", "--include-predefined", "--offset", "3"]);
        out.assert_success();
        assert_eq!(f.api(), [format!("GET {PROFILES}?page=0&size=50&{SORT}")]);
        f.clear();
        let out = f.dlp(&[
            "filtering-profiles",
            "list",
            "--limit",
            "1",
            "--sort",
            "id,desc",
            "--sort",
            "name",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(ids(&out), ["fp-2"]);
        assert_eq!(
            f.api(),
            [format!("GET {FILTERING}?size=1&sort=id%2Cdesc&sort=name")]
        );
        assert_eq!(out.stderr, "  Showing 1 of 2 (next --offset 1)\n");
    }

    /// The hidden `--size` and `--page` aliases (TS `pagination.ts`): a warning each,
    /// never quiet-suppressed; `--page` gives the page directly; the canonical flags win.
    #[test]
    fn deprecated_aliases_warn_and_map_onto_the_canonical_flags() {
        let f = fx();
        let out = f.dlp(&[
            "filtering-profiles",
            "list",
            "--size",
            "1",
            "--page",
            "1",
            "--quiet",
        ]);
        out.assert_success();
        assert_eq!(f.api(), [format!("GET {FILTERING}?page=1&size=1&{SORT}")]);
        assert_eq!(
            out.stderr,
            "  ⚠ --size is deprecated and will be removed in v4 — use --limit\n  ⚠ --page is deprecated and will be removed in v4 — use --offset\n"
        );
        f.clear();
        let out = f.dlp(&[
            "filtering-profiles",
            "list",
            "--size",
            "9",
            "--limit",
            "1",
            "--page",
            "9",
            "--offset",
            "1",
        ]);
        out.assert_success();
        assert_eq!(f.api(), [format!("GET {FILTERING}?page=1&size=1&{SORT}")]);
    }

    /// Dictionaries: `keywords=true` after the sort values with `--keywords` or
    /// `--include-keywords`; otherwise no parameter and no keywords.
    #[test]
    fn dictionary_keywords_are_asked_for_with_either_flag() {
        let f = fx();
        for flag in ["--keywords", "--include-keywords"] {
            f.clear();
            let out = f.dlp(&[
                "dictionaries",
                "list",
                "--include-predefined",
                flag,
                "--output",
                "json",
            ]);
            out.assert_success();
            assert_eq!(
                f.api(),
                [format!("GET {DICTIONARIES}?{SORT}&keywords=true")]
            );
            assert_eq!(
                out.json()[0]["keywords"],
                json!([fx::content(8), fx::content(9)])
            );
            f.clear();
            let out = f.dlp(&["dictionaries", "get", "d-cus-1", flag, "--output", "json"]);
            out.assert_success();
            assert_eq!(
                f.api(),
                [format!("GET {DICTIONARIES}/d-cus-1?keywords=true")]
            );
            assert_eq!(out.json()["keywords"].as_array().unwrap().len(), 2);
        }
        f.clear();
        let out = f.dlp(&["dictionaries", "get", "d-cus-1", "--output", "json"]);
        out.assert_success();
        assert_eq!(f.api(), [format!("GET {DICTIONARIES}/d-cus-1")]);
        assert!(out.json().get("keywords").is_none());
        // The custom-only view walks without keywords and reads the shown rows' keywords
        // per id (G13).
        f.clear();
        let out = f.dlp(&["dictionaries", "ls", "--keywords", "--output", "json"]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {DICTIONARIES}?page=0&size=100&{SORT}"),
                format!("GET {DICTIONARIES}/d-cus-1?keywords=true")
            ]
        );
        assert_eq!(
            out.json()[0]["keywords"],
            json!([fx::content(8), fx::content(9)])
        );
    }

    /// G13: the custom-only `dictionaries list --keywords` never asks a page for keywords
    /// (a tenant's keyword lists can exceed the response limit, and `--limit 1` would
    /// still download all of them); only the rows of the slice are read with keywords.
    #[test]
    fn custom_only_keyword_lists_read_only_the_shown_keywords() {
        let f = fx();
        f.server.dlp(|data| {
            data.dictionaries = (0..3u32)
                .map(|n| {
                    fx::dictionary(
                        &format!("d-big-{n}"),
                        &format!("Big {n}"),
                        "custom",
                        "active",
                        1,
                        Some(40 + 3 * n),
                    )
                })
                .chain([fx::dictionary(
                    "d-pre-1",
                    "Pre",
                    "predefined",
                    "active",
                    1,
                    None,
                )])
                .collect();
        });
        let out = f.dlp(&[
            "dictionaries",
            "list",
            "--keywords",
            "--limit",
            "1",
            "--offset",
            "1",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                format!("GET {DICTIONARIES}?page=0&size=100&{SORT}"),
                format!("GET {DICTIONARIES}/d-big-1?keywords=true")
            ]
        );
        let rows = out.json();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["id"], "d-big-1");
        assert_eq!(
            rows[0]["keywords"],
            json!([fx::content(44), fx::content(45)])
        );
        assert_eq!(out.stderr, "  Showing 1 of 3 (next --offset 2)\n");
        // `--all`: every shown row, one keyword read each.
        f.clear();
        let out = f.dlp(&[
            "dictionaries",
            "list",
            "--keywords",
            "--all",
            "--output",
            "table",
        ]);
        out.assert_success();
        assert_eq!(f.api().len(), 4, "{:?}", f.api());
        assert!(
            f.api()[1..]
                .iter()
                .all(|line| line.ends_with("?keywords=true")),
            "{:?}",
            f.api()
        );
        assert!(!f.api()[0].contains("keywords"), "{:?}", f.api());
        assert!(
            out.stdout
                .contains(" d-big-2 │ Big 2 │ custom │ active │ 2        │ 1       \n"),
            "{}",
            out.stdout
        );
        // A keyword read that fails fails the list (nothing printed).
        f.clear();
        f.server.push_once(
            Route::Dlp(Dl::Get(Collection::Dictionaries)),
            Planned::json(404, &json!({"title": "Not Found", "status": 404})),
        );
        let out = f.dlp(&["dictionaries", "list", "--keywords", "--limit", "1"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
    }

    /// Gets: one request to `<collection>/<id>`, the id sent as one encoded segment.
    #[test]
    fn gets_send_the_id_as_one_encoded_segment() {
        let f = fx();
        for (group, path, id) in [
            ("filtering-profiles", FILTERING, "fp-1"),
            ("patterns", PATTERNS, "p-cus-1"),
            ("profiles", PROFILES, "dp-cus-1"),
            ("dictionaries", DICTIONARIES, "d-cus-1"),
        ] {
            f.clear();
            let out = f.dlp(&[group, "get", id, "--output", "json"]);
            out.assert_success();
            assert_eq!(out.json()["id"], id);
            assert_eq!(f.api(), [format!("GET {path}/{id}")]);
        }
        f.clear();
        let out = f.dlp(&["patterns", "get", "a/b?c"]);
        out.assert_code(1);
        assert_eq!(f.api(), [format!("GET {PATTERNS}/a%2Fb%3Fc")]);
        assert_eq!(out.http_status(), Some(404));
        assert_eq!(out.stdout, "");
    }

    /// `--all` on a server-paged list walks from page 0 with `--limit` (else 50) and
    /// stops at `--max` with the D14 line.
    #[test]
    fn all_walks_server_pages_and_stops_at_max() {
        let f = fx();
        let out = f.dlp(&[
            "patterns",
            "list",
            "--include-predefined",
            "--all",
            "--limit",
            "2",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(ids(&out).len(), 5);
        assert_eq!(
            f.api(),
            [
                format!("GET {PATTERNS}?page=0&size=2&{SORT}"),
                format!("GET {PATTERNS}?page=1&size=2&{SORT}"),
                format!("GET {PATTERNS}?page=2&size=2&{SORT}"),
            ]
        );
        assert_eq!(out.stderr, "  Showing 5 of 5\n");
        f.clear();
        let out = f.dlp(&[
            "patterns",
            "list",
            "--include-predefined",
            "--all",
            "--limit",
            "2",
            "--max",
            "3",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert_eq!(ids(&out), ["p-del-1", "p-pre-1", "p-dis-1"]);
        assert_eq!(f.api().len(), 2);
        assert_eq!(
            out.stderr,
            "  Showing first 3 (stopped at --max 3; more available)\n"
        );
        f.clear();
        let out = f.dlp(&["filtering-profiles", "list", "--all"]);
        out.assert_success();
        assert_eq!(f.api(), [format!("GET {FILTERING}?page=0&size=50&{SORT}")]);
    }

    /// D170: the custom-only view slices locally: `[offset, offset + limit)` with the
    /// custom total and the next offset; `--all` keeps the first `--max` rows.
    #[test]
    fn custom_only_views_slice_locally() {
        let f = fx();
        let out = f.dlp(&[
            "patterns", "list", "--limit", "2", "--offset", "1", "--output", "json",
        ]);
        out.assert_success();
        assert_eq!(ids(&out), ["p-dis-1", "p-cus-1"]);
        assert_eq!(f.api(), [format!("GET {PATTERNS}?page=0&size=100&{SORT}")]);
        assert_eq!(out.stderr, "  Showing 2 of 4 (next --offset 3)\n");
        let out = f.dlp(&["patterns", "list", "--offset", "3", "--output", "json"]);
        assert_eq!(ids(&out), ["p-par-1"]);
        assert_eq!(out.stderr, "  Showing 1 of 4\n");
        let out = f.dlp(&["patterns", "list", "--offset", "9", "--output", "json"]);
        assert_eq!(out.stdout, "[]\n");
        assert_eq!(out.stderr, "  Showing 0 of 4\n");
        let out = f.dlp(&[
            "patterns", "list", "--page", "1", "--limit", "3", "--output", "json",
        ]);
        assert_eq!(ids(&out), ["p-par-1"], "--page counts pages of --limit");
        let out = f.dlp(&[
            "patterns", "list", "--all", "--max", "2", "--output", "json",
        ]);
        assert_eq!(ids(&out), ["p-del-1", "p-dis-1"]);
        assert_eq!(
            out.stderr,
            "  Showing first 2 (stopped at --max 2; more available)\n"
        );
        let out = f.dlp(&["profiles", "list", "--all", "--output", "json"]);
        assert_eq!(out.stderr, "  Showing 3 of 3\n");
    }

    /// G12: a service that caps its page size (the dictionaries: 100 → 50, snake_case
    /// metadata) is walked to the end.
    #[test]
    fn a_capped_page_size_is_walked_to_the_end() {
        let f = fx();
        f.server.dlp(|data| {
            data.dictionaries = (0..60)
                .map(|n| {
                    fx::dictionary(
                        &format!("d-{n:03}"),
                        &format!("Dict {n:03}"),
                        "custom",
                        "active",
                        1,
                        None,
                    )
                })
                .collect();
        });
        let out = f.dlp(&["dictionaries", "list", "--output", "json"]);
        out.assert_success();
        assert_eq!(ids(&out).len(), 60);
        assert_eq!(
            f.api(),
            [
                format!("GET {DICTIONARIES}?page=0&size=100&{SORT}"),
                format!("GET {DICTIONARIES}?page=1&size=100&{SORT}"),
            ]
        );
        assert_eq!(out.stderr, "  Showing 60 of 60\n");
        // Without any metadata the short page ends the walk.
        f.clear();
        f.server.dlp(|data| {
            data.styles.insert(Collection::Patterns, PageStyle::Bare);
        });
        let out = f.dlp(&["patterns", "list", "--output", "json"]);
        out.assert_success();
        assert_eq!(ids(&out).len(), 4);
        assert_eq!(f.api().len(), 1);
    }
}

// ---------------------------------------------------------------------------
// Visibility (TS `unit/cli/dlp-visibility.spec.ts`, D170)
// ---------------------------------------------------------------------------

mod visibility {
    use super::*;

    /// Predefined records are hidden by default across every page (not only the first)
    /// and shown with `--include-predefined`; filtering profiles always list every record.
    #[test]
    fn predefined_records_are_hidden_across_every_page_and_shown_on_request() {
        let f = fx();
        f.server.dlp(|data| {
            let mut rows: Vec<Value> = (0..120)
                .map(|n| {
                    fx::pattern(
                        &format!("pre-{n:03}"),
                        &format!("A predefined {n:03}"),
                        "predefined",
                        "active",
                        "regex",
                        1,
                        None,
                    )
                })
                .collect();
            rows.extend(custom_patterns(2));
            data.patterns = rows;
        });
        let out = f.dlp(&["patterns", "list", "--limit", "1", "--output", "json"]);
        out.assert_success();
        assert_eq!(ids(&out), ["c-000"]);
        assert_eq!(out.stderr, "  Showing 1 of 2 (next --offset 1)\n");
        assert_eq!(f.api().len(), 2, "two pages of 100");
        let out = f.dlp(&[
            "patterns",
            "list",
            "--include-predefined",
            "--limit",
            "1",
            "--output",
            "json",
        ]);
        assert_eq!(ids(&out), ["pre-000"]);
        assert_eq!(out.stderr, "  Showing 1 of 122 (next --offset 1)\n");
        let out = f.dlp(&["filtering-profiles", "list", "--output", "json"]);
        assert_eq!(ids(&out), ["fp-1", "fp-2"], "the predefined fp-1 is listed");
    }
}

// ---------------------------------------------------------------------------
// Layouts (TS `unit/cli/dlp-renderer.spec.ts`, §16.4)
// ---------------------------------------------------------------------------

mod formats {
    use super::*;

    #[test]
    fn pretty_lists_are_the_typescript_layouts() {
        let f = fx();
        let out = f.dlp(&["patterns", "list"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            "\n  Data Patterns:\n\n  p-del-1\n    Archived Pattern  custom  deleted regex v3\n  p-dis-1\n    Disabled Pattern  custom  disabled weighted_regex v4\n  p-cus-1\n    My Pattern  custom  active regex v1\n  p-par-1\n    Parent Pattern  custom  active regex v1\n\n"
        );
        let out = f.dlp(&["profiles", "ls", "--include-predefined"]);
        assert_eq!(
            out.stdout,
            "\n  Data Profiles:\n\n  dp-dis-1\n    Disabled Profile  custom  disabled advanced v2\n  dp-multi-1\n    Multi Profile  custom  active advanced v1\n  dp-cus-1\n    My Profile  custom  active advanced v1\n  dp-pre-1\n    PCI Profile  predefined  active basic v3\n\n"
        );
        let out = f.dlp(&["dictionaries", "ls", "--include-predefined", "--keywords"]);
        assert_eq!(
            out.stdout,
            "\n  Data Dictionaries:\n\n  d-cus-1\n    My Dict  custom  active 2 kw v2\n  d-pre-1\n    Predef Dict  predefined  active 1 kw v1\n\n"
        );
        let out = f.dlp(&["filtering-profiles", "ls"]);
        assert_eq!(
            out.stdout,
            "\n  Data Filtering Profiles:\n\n  fp-1\n    Bulk CCN  predefined dir:c2s sev:low v1\n  fp-2\n    Custom FP  custom v2\n\n"
        );
        // --quiet drops the heading and the status line, never the entries.
        let out = f.dlp(&["--quiet", "filtering-profiles", "ls"]);
        assert_eq!(
            out.stdout,
            "  fp-1\n    Bulk CCN  predefined dir:c2s sev:low v1\n  fp-2\n    Custom FP  custom v2\n\n"
        );
        assert_eq!(out.stderr, "");
    }

    #[test]
    fn empty_lists_in_every_format() {
        let f = fx();
        f.server.dlp(|data| {
            data.patterns.clear();
            data.profiles.clear();
            data.dictionaries.clear();
            data.filtering_profiles.clear();
        });
        for (group, phrase) in [
            ("patterns", "No data patterns found"),
            ("profiles", "No data profiles found"),
            ("dictionaries", "No data dictionaries found"),
            ("filtering-profiles", "No data filtering profiles found"),
        ] {
            let out = f.dlp(&[group, "list"]);
            out.assert_success();
            assert_eq!(out.stdout, format!("  {phrase}\n"));
            let table = f.dlp(&[group, "list", "--output", "table"]);
            assert_eq!(table.stdout, "");
            assert_eq!(table.stderr, out.stderr);
            assert_eq!(f.dlp(&[group, "list", "--output", "json"]).stdout, "[]\n");
        }
    }

    #[test]
    fn table_lists_are_the_typescript_layouts() {
        let f = fx();
        let out = f.dlp(&[
            "patterns",
            "list",
            "--include-predefined",
            "--output",
            "table",
        ]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            " ID      │ Name               │ Type       │ Status   │ Technique      │ Version \n─────────┼────────────────────┼────────────┼──────────┼────────────────┼─────────\n p-del-1 │ Archived Pattern   │ custom     │ deleted  │ regex          │ 3       \n p-pre-1 │ Credit Card Number │ predefined │ active   │ regex          │ 2       \n p-dis-1 │ Disabled Pattern   │ custom     │ disabled │ weighted_regex │ 4       \n p-cus-1 │ My Pattern         │ custom     │ active   │ regex          │ 1       \n p-par-1 │ Parent Pattern     │ custom     │ active   │ regex          │ 1       \n"
        );
        let out = f.dlp(&["filtering-profiles", "list", "--output", "table"]);
        assert_eq!(
            out.stdout,
            " ID   │ Name      │ Type       │ Direction │ Severity │ Version \n──────┼───────────┼────────────┼───────────┼──────────┼─────────\n fp-1 │ Bulk CCN  │ predefined │ c2s       │ low      │ 1       \n fp-2 │ Custom FP │ custom     │           │          │ 2       \n"
        );
        let out = f.dlp(&["profiles", "list", "--output", "table"]);
        assert!(
            out.stdout.starts_with(
                " ID         │ Name             │ Type   │ Profile Type │ Status   │ Version \n"
            ),
            "{}",
            out.stdout
        );
        let out = f.dlp(&["dictionaries", "list", "--output", "table"]);
        assert!(out.stdout.contains(" Keywords │"), "{}", out.stdout);
        assert!(
            out.stdout
                .contains(" d-cus-1 │ My Dict │ custom │ active │          │ 2       \n"),
            "{}",
            out.stdout
        );
        let out = f.dlp(&["dictionaries", "list", "--output", "table", "--keywords"]);
        assert!(
            out.stdout
                .contains(" d-cus-1 │ My Dict │ custom │ active │ 2        │ 2       \n"),
            "{}",
            out.stdout
        );
    }

    /// TS `dlp-renderer.spec.ts`: json is the full validated record, camelCased; a list is
    /// a bare array; the keys under `tags` and `exclusions.exclusion_list` are kept (D171).
    #[test]
    fn json_is_the_camel_case_record() {
        let f = fx();
        let out = f.dlp(&["filtering-profiles", "get", "fp-1", "--output", "json"]);
        out.assert_success();
        let record = out.json();
        for key in [
            "dataProfileId",
            "scanType",
            "fileBased",
            "nonFileBased",
            "fileType",
            "tenantId",
            "isParentManaged",
            "auditMetadata",
        ] {
            assert!(record.get(key).is_some(), "{key}: {record}");
        }
        assert_eq!(record["auditMetadata"]["updatedAt"], json!(fx::UPDATED_MS));
        let out = f.dlp(&["filtering-profiles", "get", "fp-2", "--output", "json"]);
        assert_eq!(
            out.json()["exclusions"],
            json!({"appExclusionList": [{"appId": "app-1", "appName": "App One"}], "exclusionList": {"my_category": ["one"], "Some_Category": []}})
        );
        let out = f.dlp(&["patterns", "get", "p-cus-1", "--output", "json"]);
        let pattern = out.json();
        assert_eq!(
            pattern["tags"],
            json!({"compliance": [fx::content(4)], "my_tag": [fx::content(5)]})
        );
        assert_eq!(
            pattern["matchingRules"]["regexes"][0]["regex"],
            format!("{}-[0-9]+", fx::content(3))
        );
        assert_eq!(
            pattern["detectionConfig"]["supportedConfidenceLevels"],
            json!(["high"])
        );
        let out = f.dlp(&["profiles", "get", "dp-cus-1", "--output", "json"]);
        let profile = out.json();
        assert_eq!(profile["profileType"], "advanced");
        assert_eq!(
            profile["detectionRules"][0]["expressionTree"]["subExpressions"][0]["ruleItem"]["id"],
            "p-cus-1"
        );
        let out = f.dlp(&["profiles", "get", "dp-pre-1", "--output", "json"]);
        assert_eq!(out.json()["detectionRules"], Value::Null, "null is kept");
        let out = f.dlp(&["patterns", "list", "--output", "json"]);
        let rows = out.json();
        assert!(rows.is_array());
        assert_eq!(
            rows[2]["matchingRules"]["proximityKeywords"],
            json!([fx::content(2)])
        );
        // The dictionary `status` and `version` are not schema fields: they come last.
        let out = f.dlp(&["dictionaries", "get", "d-cus-1", "--output", "json"]);
        let keys: Vec<String> = out.json().as_object().unwrap().keys().cloned().collect();
        assert!(keys.contains(&s("status")) && keys.contains(&s("version")));
        let text = &out.stdout;
        assert!(
            text.find("\"auditMetadata\"").unwrap() < text.find("\"status\"").unwrap(),
            "{text}"
        );
    }

    #[test]
    fn pretty_gets_are_the_typescript_layouts() {
        let f = fx();
        let out = f.dlp(&["patterns", "get", "p-cus-1"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "\n  Data Pattern:\n\n  ID           p-cus-1\n  Name         My Pattern\n  Description  desc {}\n  Type         custom\n  Status       active\n  Technique    regex\n  Confidence   high\n  Regexes      1\n  Version      1\n  Updated      2023-11-14T22:13:20.000Z\n\n",
                fx::content(1)
            )
        );
        assert_eq!(out.stderr, "");
        let out = f.dlp(&["filtering-profiles", "get", "fp-1"]);
        assert_eq!(
            out.stdout,
            "\n  Data Filtering Profile:\n\n  ID              fp-1\n  Name            Bulk CCN\n  Type            predefined\n  Data Profile    11995031\n  Direction       c2s\n  Severity        low\n  Scan Type       include\n  File Based      yes\n  Non-File Based  no\n  Version         1\n  File Types      2\n  Updated         2023-11-14T22:13:20.000Z\n\n"
        );
        let out = f.dlp(&["profiles", "get", "dp-pre-1"]);
        assert_eq!(
            out.stdout,
            "\n  Data Profile:\n\n  ID            dp-pre-1\n  Name          PCI Profile\n  Type          predefined\n  Profile Type  basic\n  Status        active\n  Version       3\n  Updated       2023-11-14T22:13:20.000Z\n\n"
        );
        let out = f.dlp(&["dictionaries", "get", "d-cus-1"]);
        assert!(
            !out.stdout.contains("Keywords"),
            "no count without keywords"
        );
        let out = f.dlp(&["dictionaries", "get", "d-cus-1", "--keywords"]);
        assert_eq!(
            out.stdout,
            format!(
                "\n  Data Dictionary:\n\n  ID           d-cus-1\n  Name         My Dict\n  Description  dict {}\n  Type         custom\n  Status       active\n  Keywords     2\n  Version      2\n  Updated      2023-11-14T22:13:20.000Z\n\n",
                fx::content(7)
            )
        );
        let out = f.dlp(&["--quiet", "patterns", "get", "p-pre-1"]);
        assert!(
            out.stdout.starts_with("  ID          p-pre-1\n"),
            "{}",
            out.stdout
        );
        assert!(
            !out.stdout.contains("Regexes"),
            "regexes: null has no count"
        );
    }

    /// The get table is the camelCase record, objects and arrays as compact JSON (the
    /// keyword list and regexes as TS prints them, §16.9).
    #[test]
    fn table_gets_are_the_key_value_table() {
        let f = fx();
        let out = f.dlp(&[
            "dictionaries",
            "get",
            "d-cus-1",
            "--keywords",
            "--output",
            "table",
        ]);
        out.assert_success();
        let lines: Vec<&str> = out.stdout.lines().collect();
        assert!(lines[0].starts_with(" Key "), "{}", out.stdout);
        let cell = |key: &str| {
            lines.iter().find_map(|line| {
                let (left, right) = line.split_once('│')?;
                (left.trim() == key).then(|| right.trim().to_owned())
            })
        };
        assert_eq!(cell("regionName").as_deref(), Some("United States"));
        assert_eq!(
            cell("keywords"),
            Some(format!("[\"{}\",\"{}\"]", fx::content(8), fx::content(9)))
        );
        assert_eq!(
            cell("dictionaryMetadata").as_deref(),
            Some(r#"{"numberOfKeywords":2,"originalFileName":"keywords.txt"}"#)
        );
        assert_eq!(cell("isCaseSensitive").as_deref(), Some("false"));
    }

    /// §16.9: pretty lists print no detection content; the pretty get prints the
    /// description only; json and the get table print the record.
    #[test]
    fn detection_content_reaches_stdout_only_where_the_record_is_printed() {
        let f = fx();
        let contains_marker = |text: &str| fx::markers().iter().any(|marker| text.contains(marker));
        for args in [
            &["patterns", "list"][..],
            &["profiles", "list"],
            &["dictionaries", "list", "--keywords"],
            &["patterns", "list", "--output", "table"],
            &["dictionaries", "list", "--keywords", "--output", "table"],
        ] {
            let out = f.dlp(args);
            out.assert_success();
            assert!(!contains_marker(&out.stdout), "{args:?}: {}", out.stdout);
        }
        let pretty = f.dlp(&["patterns", "get", "p-cus-1"]);
        let shown: Vec<String> = fx::markers()
            .into_iter()
            .filter(|marker| pretty.stdout.contains(marker))
            .collect();
        assert_eq!(shown, [fx::content(1)], "only the description");
        let json = f.dlp(&["patterns", "get", "p-cus-1", "--output", "json"]);
        for n in 1..=5 {
            assert!(json.stdout.contains(&fx::content(n)), "{n}");
        }
    }

    /// The tenant's `defaultOutput` is honoured by every read (§16.3).
    #[test]
    fn default_output_is_honoured() {
        let f = fx_with(|config| {
            config.set("defaultOutput", "json");
        });
        let out = f.dlp(&["patterns", "list"]);
        out.assert_success();
        assert!(out.json().is_array());
        let out = f.dlp(&["patterns", "get", "p-cus-1", "--output", "table"]);
        assert!(out.stdout.starts_with(" Key "), "{}", out.stdout);
    }

    /// D52 (0.7): control characters in server text are replaced in every layout and
    /// status line; a get's description keeps its line breaks.
    #[test]
    fn control_characters_are_replaced_in_every_layout() {
        let f = fx();
        f.server.dlp(|data| {
            data.patterns[3]["name"] = json!("Evil\u{1b}[31mRED\nline2");
            data.patterns[3]["description"] = json!("one\ntwo\r\n\tthree\u{7}");
            data.patterns[0]["id"] = json!("p-\u{1b}x");
        });
        let out = f.dlp(&["patterns", "list"]);
        out.assert_success();
        assert!(
            out.stdout
                .contains("  p-\u{fffd}x\n    Archived Pattern  custom"),
            "{:?}",
            out.stdout
        );
        assert!(
            out.stdout
                .contains("  p-cus-1\n    Evil\u{fffd}[31mRED\u{fffd}line2  custom"),
            "{:?}",
            out.stdout
        );
        let out = f.dlp(&["patterns", "list", "--output", "table"]);
        assert!(
            out.stdout.contains("Evil\u{fffd}[31mRED\u{fffd}line2"),
            "{:?}",
            out.stdout
        );
        assert!(!out.stdout.contains('\u{1b}'));
        let out = f.dlp(&["patterns", "get", "p-cus-1"]);
        out.assert_success();
        assert!(
            out.stdout
                .contains("  Description  one\ntwo\r\n\tthree\u{fffd}\n"),
            "{:?}",
            out.stdout
        );
        let out = f.dlp(&["patterns", "get", "p-cus-1", "--output", "table"]);
        assert!(!out.stdout.contains('\u{1b}') && !out.stdout.contains('\u{7}'));
        let out = f.dlp(&["patterns", "get", "p-cus-1", "--output", "json"]);
        assert_eq!(
            out.json()["name"],
            "Evil\u{1b}[31mRED\nline2",
            "json keeps the text"
        );
    }

    /// D56 (0.7): a row without `id` omits its id line and a missing `name` prints as
    /// empty; an `updated_at` that is not ISO 8601 is dropped.
    #[test]
    fn missing_ids_names_and_bad_timestamps() {
        let f = fx();
        f.server.dlp(|data| {
            let row = data.profiles[1].as_object_mut().unwrap();
            row.remove("id");
            row.remove("name");
            data.profiles[2]["audit_metadata"]["updated_at"] = json!("last tuesday");
        });
        let out = f.dlp(&["profiles", "list"]);
        out.assert_success();
        // The row without a name sorts first on the fixture service.
        assert_eq!(
            out.stdout,
            "\n  Data Profiles:\n\n      custom  active advanced v1\n  dp-dis-1\n    Disabled Profile  custom  disabled advanced v2\n  dp-cus-1\n    My Profile  custom  active advanced v1\n\n"
        );
        let out = f.dlp(&["profiles", "get", "dp-cus-1"]);
        assert!(!out.stdout.contains("Updated"), "{}", out.stdout);
        let out = f.dlp(&["profiles", "get", "dp-cus-1", "--output", "json"]);
        assert_eq!(out.json()["auditMetadata"]["updatedAt"], "last tuesday");
    }

    /// §16.3 "Server text": a printed name or description that carries a secret of the
    /// invocation is `[withheld]` in every format.
    #[test]
    fn names_carrying_a_secret_are_withheld() {
        let f = fx();
        let secret = format!("FAKE-SECRET-{TSG}");
        f.server.dlp(|data| {
            data.patterns[3]["name"] = json!(format!("leak {secret}"));
            data.patterns[3]["description"] = json!(secret.clone());
        });
        for format in ["pretty", "table", "json"] {
            let out = f.dlp(&["patterns", "list", "--output", format]);
            out.assert_success();
            assert!(
                out.stdout.contains("[withheld]"),
                "{format}: {}",
                out.stdout
            );
        }
        let out = f.dlp(&["patterns", "get", "p-cus-1", "--output", "json"]);
        assert_eq!(out.json()["name"], "[withheld]");
        assert_eq!(out.json()["description"], "[withheld]");
    }
}

// ---------------------------------------------------------------------------
// Argument checks before the tenant (D162, D50)
// ---------------------------------------------------------------------------

mod checks {
    use super::*;

    /// Every argument error is a usage error before the tenant: no tenant is needed, no
    /// request is sent, no debug log is created.
    #[test]
    fn argument_errors_are_usage_errors_before_the_tenant() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let state = debug_log::xdg_state_home(&sandbox).display().to_string();
        let long_sort = "x".repeat(1025);
        let many_sorts: Vec<String> = (0..129).flat_map(|_| [s("--sort"), s("name")]).collect();
        let mut many = vec![s("patterns"), s("list")];
        many.extend(many_sorts);
        for (args, message) in [
            (
                vec![s("patterns"), s("get"), s("..")],
                "Invalid data pattern id: ..",
            ),
            (
                vec![s("profiles"), s("get"), s(".")],
                "Invalid data profile id: .",
            ),
            (
                vec![s("dictionaries"), s("get"), s("")],
                "Invalid dictionary id: ",
            ),
            (
                vec![s("filtering-profiles"), s("get"), s("a/../b")],
                "Invalid filtering profile id: a/../b",
            ),
            (
                vec![s("patterns"), s("get"), s("%2E%2E")],
                "Invalid data pattern id: %2E%2E",
            ),
            (
                vec![s("patterns"), s("get"), s("a\\b")],
                "Invalid data pattern id: a\\b",
            ),
            (
                vec![s("patterns"), s("list"), s("--limit"), s("abc")],
                "--limit must be a positive integer",
            ),
            (
                vec![s("patterns"), s("list"), s("--limit"), s("1.5")],
                "--limit must be a positive integer",
            ),
            (
                vec![s("patterns"), s("list"), s("--limit"), s("0")],
                "--limit must be a positive integer",
            ),
            (
                vec![s("patterns"), s("list"), s("--limit"), s("-1")],
                "--limit must be a positive integer",
            ),
            (
                vec![s("profiles"), s("list"), s("--size"), s("x")],
                "--limit must be a positive integer",
            ),
            (
                vec![s("profiles"), s("list"), s("--offset"), s("-5")],
                "--offset must be a non-negative integer",
            ),
            (
                vec![s("profiles"), s("list"), s("--page"), s("x")],
                "--offset must be a non-negative integer",
            ),
            (
                vec![s("dictionaries"), s("list"), s("--max"), s("abc")],
                "--max must be a non-negative integer",
            ),
            (
                vec![
                    s("filtering-profiles"),
                    s("list"),
                    s("--all"),
                    s("--offset"),
                    s("0"),
                ],
                "--all cannot be combined with --offset",
            ),
            (
                vec![
                    s("filtering-profiles"),
                    s("list"),
                    s("--all"),
                    s("--page"),
                    s("1"),
                ],
                "--all cannot be combined with --offset",
            ),
            (
                vec![s("patterns"), s("list"), s("--sort"), long_sort],
                "--sort values must be 1-1024 bytes with no control characters",
            ),
            (
                vec![s("patterns"), s("list"), s("--sort"), s("")],
                "--sort values must be 1-1024 bytes with no control characters",
            ),
            (many, "--sort accepts at most 128 values"),
            (
                vec![s("patterns"), s("list"), s("--output"), s("yaml")],
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            ),
            (
                vec![s("dictionaries"), s("get"), s("d"), s("--output"), s("csv")],
                "Invalid output format 'csv'. Expected: pretty, table, json",
            ),
            (
                vec![
                    s("filtering-profiles"),
                    s("list"),
                    s("--output"),
                    s("markdown"),
                ],
                "Invalid output format 'markdown'. Expected: pretty, table, json",
            ),
        ] {
            let mut full = vec![s("--debug"), s("runtime"), s("dlp")];
            full.extend(args.iter().cloned());
            let full: Vec<&str> = full.iter().map(String::as_str).collect();
            let out = run(
                &rust(),
                &sandbox,
                &full,
                &RunOptions::new().env("XDG_STATE_HOME", &state),
            );
            out.assert_code(2);
            let mut warnings = String::new();
            if args.contains(&s("--size")) {
                warnings
                    .push_str("  ⚠ --size is deprecated and will be removed in v4 — use --limit\n");
            }
            if args.contains(&s("--page")) {
                warnings.push_str(
                    "  ⚠ --page is deprecated and will be removed in v4 — use --offset\n",
                );
            }
            assert_eq!(
                out.stderr,
                format!("{warnings}\n  ✗ {message}\n\n"),
                "{args:?}"
            );
            assert_eq!(out.stdout, "");
            assert_eq!(server.request_count(), 0);
            assert!(
                debug_log::log_files(&debug_log::log_dir(&sandbox)).is_empty(),
                "{args:?} created a debug log"
            );
        }
    }

    /// `runtime dlp generate` is dropped (as `redteam judge`): an unrecognised
    /// subcommand, exit 2, and no help lists it; groups without a subcommand print their
    /// help on stderr, exit 2 (D1).
    #[test]
    fn generate_is_not_a_command_and_bare_groups_print_help() {
        let sandbox = Sandbox::new();
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "dlp", "generate"],
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert!(
            out.stderr.contains("unrecognized subcommand 'generate'"),
            "{}",
            out.stderr
        );
        let help = run(
            &rust(),
            &sandbox,
            &["runtime", "dlp", "--help"],
            &RunOptions::new(),
        );
        help.assert_success();
        assert!(!help.stdout.contains("generate"), "{}", help.stdout);
        assert!(help.stdout.contains(
            "DLP management (filtering-profiles, patterns, profiles, dictionaries, backup/restore)"
        ));
        for group in [
            &["runtime", "dlp"][..],
            &["runtime", "dlp", "patterns"],
            &["runtime", "dlp", "profiles"],
            &["runtime", "dlp", "dictionaries"],
            &["runtime", "dlp", "filtering-profiles"],
        ] {
            let out = run(&rust(), &sandbox, group, &RunOptions::new());
            out.assert_code(2);
            assert_eq!(out.stdout, "");
            assert!(
                out.stderr
                    .contains(&format!("Usage: airs {}", group.join(" "))),
                "{}",
                out.stderr
            );
        }
        let out = run(
            &rust(),
            &sandbox,
            &[
                "runtime",
                "dlp",
                "filtering-profiles",
                "list",
                "--include-predefined",
            ],
            &RunOptions::new(),
        );
        out.assert_code(2);
        // Step 2 commands are not registered yet (§16.1).
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "dlp", "patterns", "create"],
            &RunOptions::new(),
        );
        out.assert_code(2);
    }

    /// The deprecation warnings come before every other check, even under `--quiet`.
    #[test]
    fn deprecation_warnings_come_first() {
        let sandbox = Sandbox::new();
        let out = run(
            &rust(),
            &sandbox,
            &[
                "--quiet", "runtime", "dlp", "patterns", "list", "--page", "1", "--output", "xml",
            ],
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            "  ⚠ --page is deprecated and will be removed in v4 — use --offset\n\n  ✗ Invalid output format 'xml'. Expected: pretty, table, json\n\n"
        );
    }

    #[test]
    fn help_lists_the_commands_with_the_typescript_texts() {
        let sandbox = Sandbox::new();
        let help = |args: &[&str]| {
            let mut full = vec!["runtime", "dlp"];
            full.extend_from_slice(args);
            full.push("--help");
            let out = run(&rust(), &sandbox, &full, &RunOptions::new());
            out.assert_success();
            out.stdout
        };
        let text = help(&["patterns", "list"]);
        for line in [
            "--include-predefined",
            "Include predefined (PANW-shipped) records; listings show only tenant-created records by default",
            "Max results per page (API page size)",
            "Starting offset — rounds down to a page boundary",
            "Sort criteria (repeatable)",
            "Output format: pretty, table, json",
            "Usage: airs runtime dlp patterns list",
        ] {
            assert!(text.contains(line), "{line}: {text}");
        }
        assert!(
            !text.contains("--size") && !text.contains("--page"),
            "hidden aliases"
        );
        let text = help(&["dictionaries", "get"]);
        assert!(text.contains("--keywords") && text.contains("Alias for --keywords"));
        let text = help(&["dictionaries"]);
        for command in ["create", "delete", "get", "list", "patch", "replace"] {
            assert!(text.contains(command), "{command}: {text}");
        }
        assert!(text.contains("[aliases: rm]"), "{text}");
        // §16.2: the replace describes the D172 fallback, not TypeScript's text.
        let squashed = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            squashed.contains("204 (re-get; when the re-get fails, warns and prints the id)"),
            "{text}"
        );
        assert!(!text.contains("state not echoed"), "{text}");
        let text = help(&[]);
        assert!(!text.contains("generate"), "{text}");
        let runtime = run(
            &rust(),
            &sandbox,
            &["runtime", "--help"],
            &RunOptions::new(),
        );
        assert!(runtime.stdout.contains("dlp"), "{}", runtime.stdout);
    }
}

// ---------------------------------------------------------------------------
// Failures (§6, §16.3)
// ---------------------------------------------------------------------------

mod errors {
    use super::*;

    /// A 404 and a 500 are the §6 messages with their HTTP lines (exit 1, nothing on
    /// stdout); an error body is never echoed.
    #[test]
    fn http_errors_are_the_section_6_messages() {
        let f = fx();
        let out = f.dlp(&["profiles", "get", "nope"]);
        out.assert_code(1);
        assert_eq!(out.http_status(), Some(404));
        assert_eq!(out.stdout, "");
        f.server.set_default(
            Route::Dlp(Dl::List(Collection::Patterns)),
            Planned::json(
                500,
                &json!({"title": "Internal", "detail": format!("echo {}", fx::content(1))}),
            )
            .with_retry_after(0),
        );
        let out = f.dlp(&["patterns", "list"]);
        out.assert_code(1);
        assert_eq!(out.http_status(), Some(500));
        assert_eq!(out.stdout, "");
        assert!(
            out.error_line()
                .unwrap()
                .starts_with("AISEC_SERVER_SIDE_ERROR:API error 500")
        );
        f.server
            .clear_overrides(Route::Dlp(Dl::List(Collection::Patterns)));
        f.server.push_once(
            Route::Dlp(Dl::Get(Collection::Patterns)),
            Planned::raw(400, "text/plain", format!("plain {}", fx::content(2))),
        );
        let out = f.dlp(&["patterns", "get", "p-cus-1"]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some("AISEC_CLIENT_SIDE_ERROR:API error 400")
        );
    }

    /// D178: an unfamiliar enum value (a new `status`) is kept by the SDK's tolerant
    /// response mode and printed as server text; the known structure is still checked
    /// (TypeScript fails the whole read).
    #[test]
    fn an_unfamiliar_status_is_printed_and_a_broken_structure_fails() {
        let f = fx();
        f.server
            .dlp(|data| data.patterns[3]["status"] = json!("weird"));
        let out = f.dlp(&["patterns", "get", "p-cus-1"]);
        out.assert_success();
        assert!(
            out.stdout.contains("  Status       weird\n"),
            "{}",
            out.stdout
        );
        let out = f.dlp(&["patterns", "list", "--output", "json"]);
        assert_eq!(out.json()[2]["status"], "weird");
        f.server
            .dlp(|data| data.patterns[3]["version"] = json!("one"));
        let out = f.dlp(&["patterns", "get", "p-cus-1"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert!(
            out.error_line()
                .unwrap()
                .starts_with("AISEC_RESPONSE_VALIDATION:"),
            "{}",
            out.stderr
        );
    }

    /// D170 / D37: a service that ignores `page` (repeated ids) and an empty page that is
    /// not the last fail the walk; no partial list is printed.
    #[test]
    fn broken_walks_fail_without_printing_a_partial_list() {
        let f = fx();
        f.server.dlp(|data| {
            data.patterns = custom_patterns(150);
            data.ignore_page = true;
        });
        let out = f.dlp(&["patterns", "list"]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "AISEC_SDK_ERROR:Pagination stopped: the service returned a repeated cursor or an empty intermediate page"
            )
        );
        assert_eq!(f.api().len(), 2);
        f.clear();
        f.server.dlp(|data| {
            data.patterns = custom_patterns(3);
            data.ignore_page = false;
            data.extra_pages = 2;
            data.styles.insert(Collection::Patterns, PageStyle::NoLast);
        });
        let out = f.dlp(&[
            "patterns",
            "list",
            "--include-predefined",
            "--all",
            "--limit",
            "2",
        ]);
        out.assert_code(1);
        assert!(
            out.error_line()
                .unwrap()
                .starts_with("AISEC_SDK_ERROR:Pagination stopped")
        );
        assert_eq!(f.api().len(), 3, "pages 0, 1 and the empty page 2");
    }

    #[test]
    fn a_refused_connection_is_a_network_error() {
        let closed = ClosedPort::new();
        let f = fx_with(|config| {
            config.set(
                "dlpEndpoint",
                format!("http://127.0.0.1:{}/dlp", closed.port()),
            );
        });
        let out = f.dlp(&["filtering-profiles", "list"]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "AISEC_CLIENT_SIDE_ERROR:Network request failed (connection refused, reset or unreachable)"
            )
        );
    }

    /// §3.5: missing management credentials cost zero requests.
    #[test]
    fn missing_management_credentials_send_nothing() {
        let f = fx_with(|config| {
            config.remove("mgmtClientSecret");
        });
        let out = f.dlp(&["patterns", "list"]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "Management credentials are not configured (missing mgmtClientSecret). Run 'airs tenant set prod <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)"
            )
        );
        assert_eq!(f.server.request_count(), 0);
    }

    /// D48: a `dlpEndpoint` that is not https (or loopback http) is refused locally, the
    /// key named and the value never echoed.
    #[test]
    fn a_bad_dlp_endpoint_is_named_without_its_value() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tenant = sandbox.add_fixture_tenant_allowing_external_endpoints(
            &server,
            "prod",
            TSG,
            |config| {
                config.set("dlpEndpoint", "http://dlp.example.test/x");
            },
        );
        sandbox.register(&[&tenant], Some("prod"));
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "dlp", "patterns", "get", "p"],
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "Invalid dlpEndpoint: endpoints must use https (http is allowed only for loopback hosts) and must not contain credentials, a query or a fragment"
            )
        );
        assert!(!out.stderr.contains("example.test"));
        assert_eq!(server.request_count(), 0);
    }

    /// A token failure is the OAuth message; no DLP request is sent.
    #[test]
    fn a_token_failure_sends_no_dlp_request() {
        let f = fx();
        f.server.push_once(Route::Token, Planned::empty_json(401));
        let out = f.dlp(&["patterns", "get", "p-cus-1"]);
        out.assert_code(1);
        assert!(
            out.error_line().unwrap().starts_with("AISEC_OAUTH_ERROR:"),
            "{}",
            out.stderr
        );
        assert!(f.api().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Tenants and credentials (TS `integration/dlp-tenant-auth.spec.ts`)
// ---------------------------------------------------------------------------

mod tenants {
    use super::*;
    use airs_test_harness::AuthIdentity;

    fn two_tenants() -> (FixtureServer, Sandbox) {
        let server = FixtureServer::start();
        server.seed_dlp();
        let sandbox = Sandbox::new();
        let prod = sandbox.add_fixture_tenant_with(&server, "prod", "100", |config| {
            config.set("mgmtEndpoint", server.url("/not-the-dlp-host"));
        });
        let dev = sandbox.add_fixture_tenant_with(&server, "dev", "200", |config| {
            config.set("mgmtEndpoint", server.url("/not-the-dlp-host"));
        });
        sandbox.register(&[&prod, &dev], Some("prod"));
        (server, sandbox)
    }

    fn tsgs(server: &FixtureServer) -> Vec<String> {
        server
            .requests()
            .iter()
            .map(|request| match &request.auth {
                AuthIdentity::Basic { tsg: Some(tsg), .. }
                | AuthIdentity::Form { tsg: Some(tsg), .. }
                | AuthIdentity::Bearer { tsg: Some(tsg) } => tsg.clone(),
                other => format!("{other:?}"),
            })
            .collect()
    }

    /// Each group loads the selected tenant's credentials and `dlpEndpoint`: one token
    /// request, then one GET on the DLP base attributed to that TSG (`mgmtEndpoint` is not
    /// used).
    #[test]
    fn every_group_uses_the_selected_tenant_and_its_dlp_endpoint() {
        let (server, sandbox) = two_tenants();
        for group in ["patterns", "profiles", "dictionaries", "filtering-profiles"] {
            for (tenant, tsg) in [(None, "100"), (Some("dev"), "200")] {
                server.clear_requests();
                let mut args = Vec::new();
                if let Some(tenant) = tenant {
                    args.extend(["--tenant", tenant]);
                }
                args.extend(["runtime", "dlp", group, "list", "--output", "json"]);
                let before = sandbox.snapshot();
                let out = run(&rust(), &sandbox, &args, &RunOptions::new());
                out.assert_success();
                sandbox.assert_unchanged(&before);
                let requests = server.requests();
                assert_eq!(requests.len(), 2, "{group}");
                assert_eq!(requests[0].route, Route::Token);
                assert!(
                    requests[1].path.starts_with("/dlp/v2/api/"),
                    "{}",
                    requests[1].path
                );
                assert_eq!(tsgs(&server), [tsg, tsg]);
            }
        }
    }

    /// Environment credentials, endpoints and config paths are ignored.
    #[test]
    fn the_environment_is_ignored() {
        let (server, sandbox) = two_tenants();
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "dlp", "profiles", "list", "--output", "json"],
            &RunOptions::new()
                .env("PANW_MGMT_CLIENT_ID", "wrong-client")
                .env("PANW_MGMT_CLIENT_SECRET", "wrong-secret")
                .env("PANW_MGMT_TSG_ID", "200")
                .env("PANW_DLP_ENDPOINT", "http://127.0.0.1:9/never")
                .env(
                    "PRISMA_AIRS_CONFIG_PATH",
                    sandbox.tmp().join("dev.json").display().to_string(),
                ),
        );
        out.assert_success();
        assert_eq!(tsgs(&server), ["100", "100"]);
        assert!(
            server
                .requests()
                .iter()
                .all(|request| request.path.starts_with("/oauth")
                    || request.path.starts_with("/dlp/"))
        );
    }
}

// ---------------------------------------------------------------------------
// `--debug` (TS `unit/cli/dlp-debug.spec.ts`, §2.9)
// ---------------------------------------------------------------------------

mod debug {
    use super::*;

    /// `--debug` before or after the subcommand writes one log of status and headers
    /// only: no body, no query, no detection content; the SDK operation names (G17).
    #[test]
    fn the_debug_log_holds_status_and_headers_only() {
        for position in ["before", "after"] {
            for status in [200u16, 400] {
                let f = fx();
                if status == 400 {
                    f.server.push_once(
                        Route::Dlp(Dl::Get(Collection::Dictionaries)),
                        Planned::json(400, &json!({"title": "Bad Request", "detail": fx::content(20), "keywords": [fx::content(21)]})),
                    );
                }
                let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
                let mut args = Vec::new();
                if position == "before" {
                    args.push("--debug");
                }
                args.extend([
                    "runtime",
                    "dlp",
                    "dictionaries",
                    "get",
                    "d-cus-1",
                    "--keywords",
                    "--output",
                    "json",
                ]);
                if position == "after" {
                    args.push("--debug");
                }
                let out = f.run_with(&args, &RunOptions::new().env("XDG_STATE_HOME", &state));
                out.assert_code(if status == 200 { 0 } else { 1 });
                let (path, records) = debug_log::only_log(&f.sandbox);
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(!text.contains("FAKE-DLP-CONTENT"), "{position} {status}");
                assert!(!text.contains("keywords=true"), "no URL query");
                debug_log::assert_logs_clean(
                    &f.sandbox,
                    &f.server,
                    &[debug_log::log_dir(&f.sandbox)],
                    &[],
                );
                let operations: Vec<&str> = records
                    .iter()
                    .filter_map(|record| record["operation"].as_str())
                    .collect();
                assert_eq!(operations, ["oauth.token", "dlp.dictionaries.get"]);
                assert!(
                    out.stderr.starts_with("  Debug: API log → "),
                    "{}",
                    out.stderr
                );
            }
        }
    }

    /// The operation names of every read (G17).
    #[test]
    fn every_read_records_its_operation_name() {
        for (args, operation) in [
            (
                &["filtering-profiles", "list"][..],
                "dlp.filtering_profiles.list",
            ),
            (
                &["filtering-profiles", "get", "fp-1"],
                "dlp.filtering_profiles.get",
            ),
            (&["patterns", "list"], "dlp.data_patterns.list"),
            (&["patterns", "get", "p-cus-1"], "dlp.data_patterns.get"),
            (&["profiles", "list"], "dlp.data_profiles.list"),
            (&["profiles", "get", "dp-cus-1"], "dlp.data_profiles.get"),
            (&["dictionaries", "list"], "dlp.dictionaries.list"),
        ] {
            let f = fx();
            let state = debug_log::xdg_state_home(&f.sandbox).display().to_string();
            let mut full = vec!["--debug", "runtime", "dlp"];
            full.extend_from_slice(args);
            f.run_with(&full, &RunOptions::new().env("XDG_STATE_HOME", &state))
                .assert_success();
            let (_, records) = debug_log::only_log(&f.sandbox);
            let operations: Vec<&str> = records
                .iter()
                .filter_map(|record| record["operation"].as_str())
                .collect();
            assert_eq!(operations, ["oauth.token", operation], "{args:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Interruption (§2.5, §16.3, D174)
// ---------------------------------------------------------------------------

mod interrupt {
    use super::*;

    /// A signal during a read writes no data (exit 130 / 143).
    #[test]
    fn a_signal_during_a_read_writes_nothing() {
        for (signal, code) in [("INT", 130), ("TERM", 143)] {
            let f = fx();
            f.server
                .push_once(Route::Dlp(Dl::List(Collection::Patterns)), Planned::hang());
            let running = spawn(
                &rust(),
                &f.sandbox,
                &["runtime", "dlp", "patterns", "list"],
                &RunOptions::new().expect_signal(),
            );
            assert!(f.server.wait_for_route(
                Route::Dlp(Dl::List(Collection::Patterns)),
                1,
                Duration::from_secs(10)
            ));
            running.send_signal(signal);
            let out = running.wait();
            out.assert_code(code);
            assert_eq!(out.stdout, "");
            assert_eq!(
                out.stderr,
                "\n  ✗ Error: Interrupted; no data was written\n\n"
            );
        }
    }
}
