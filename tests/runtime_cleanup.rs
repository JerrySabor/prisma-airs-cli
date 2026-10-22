//! Executable-level acceptance tests for `runtime profiles cleanup` (DESIGN §13.15, D105,
//! D108–D110).
//!
//! Every test spawns the real `airs-cli-rs` binary against the loopback fixture server.
//! The listing, the selection, the preview in each format, the confirmation (on a pty)
//! and its re-check, the deletion loop with its per-revision outcomes, and the requests
//! that must not be sent (after an incomplete listing, a changed listing or an unknown
//! outcome) are checked request by request.

use std::time::Duration;

use airs_test_harness::{
    Cli, FixtureServer, FixtureTenant, Planned, PtyRun, RUNTIME_BANNER, RecordedRequest, Route,
    Run, RunOptions, Sandbox, fixtures, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

const TSG: &str = "100";
const LIST: &str = "GET /aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=200";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn id(n: u64) -> String {
    fixtures::uuid(n)
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
    #[allow(dead_code)]
    tenant: FixtureTenant,
}

/// Profiles `alpha` (id 1, one revision), `beta` revisions 1 (id 2) and 3 (id 4), and
/// `gamma` revisions 2 (id 6), 1 (id 5) and 3 (id 7), in that list order.
fn standard_rows() -> Vec<Value> {
    vec![
        fixtures::profile(1, "alpha", 1),
        fixtures::profile(2, "beta", 1),
        fixtures::profile(4, "beta", 3),
        fixtures::profile(6, "gamma", 2),
        fixtures::profile(5, "gamma", 1),
        fixtures::profile(7, "gamma", 3),
    ]
}

fn world() -> Fx {
    world_with(standard_rows())
}

fn world_with(rows: Vec<Value>) -> Fx {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    let tenant = sandbox.single_tenant(&server, "prod", TSG);
    server.set_profiles(TSG, rows);
    Fx {
        server,
        sandbox,
        tenant,
    }
}

impl Fx {
    fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, &RunOptions::new())
    }

    fn run_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let out = run(&rust(), &self.sandbox, args, options);
        self.server.assert_no_unknown_routes();
        assert!(self.sandbox.home_listing().is_empty(), "wrote into HOME");
        assert!(self.sandbox.cwd_listing().is_empty(), "wrote into cwd");
        out
    }

    fn lines(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .map(RecordedRequest::line)
            .collect()
    }

    fn deletes(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route.is_write())
            .map(RecordedRequest::line)
            .collect()
    }

    fn ids(&self) -> Vec<String> {
        self.server
            .profiles(TSG)
            .iter()
            .map(|row| row["profile_id"].as_str().unwrap_or_default().to_owned())
            .collect()
    }
}

fn cleanup(extra: &[&str]) -> Vec<String> {
    let mut args = vec!["runtime".to_owned(), "profiles".into(), "cleanup".into()];
    args.extend(extra.iter().map(|arg| (*arg).to_owned()));
    args
}

fn refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

fn plain_delete(n: u64) -> String {
    format!("DELETE /aisec/v1/mgmt/profile/{}", id(n))
}

/// The preview table of the standard world, as the §2.7 table.
const TABLE: &str = " Profile │ Revisions │ Keeping │ Deleting \n─────────┼───────────┼─────────┼──────────\n beta    │ 2         │ rev 3   │ 1        \n gamma   │ 3         │ rev 3   │ 2        ";

/// The pretty preview of the standard world (stdout).
fn pretty_preview() -> String {
    let indented: String = TABLE
        .split('\n')
        .map(|line| format!("  {line}\n"))
        .collect();
    format!(
        "{RUNTIME_BANNER}\n  Duplicate Profiles:\n\n{indented}\n  Total: 3 old revisions to delete across 2 profiles\n\n"
    )
}

const CLEAN_RUN: &str = "  ✓ beta rev 1\n  ✓ gamma rev 2\n  ✓ gamma rev 1\n\n  ✓ Cleanup complete: 3 deleted, 0 failed\n\n";

fn usage_block(message: &str) -> String {
    format!("\n  ✗ {message}\n\n")
}

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

mod usage {
    use super::*;

    /// Usage checks run in their §13.15 order before the tenant is read (no tenant in
    /// the sandbox, no request).
    #[test]
    fn argument_checks_come_before_the_tenant_d105() {
        for (extra, message) in [
            (
                &["--force", "--dry-run", "--updated-by", " "][..],
                "--dry-run cannot be combined with --force",
            ),
            (
                &["--force", "--updated-by", " \t"],
                "--updated-by <email> must not be blank",
            ),
            (
                &["--force", "--updated-by", "ops\tteam@x"],
                "--updated-by <email> must not contain control characters",
            ),
            (
                &["--updated-by", "a@b"],
                "refusing to delete profile revisions without --force in non-interactive mode",
            ),
            (
                &[],
                "refusing to delete profile revisions without --force in non-interactive mode",
            ),
            (
                &["--force", "--output", "csv"],
                "Invalid output format 'csv'. Expected: pretty, table, json",
            ),
        ] {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            let args = cleanup(extra);
            let out = run(&rust(), &sandbox, &refs(&args), &RunOptions::new());
            out.assert_code(2);
            assert_eq!(out.stdout, "", "{extra:?}");
            assert_eq!(out.stderr, usage_block(message), "{extra:?}");
            assert_eq!(server.request_count(), 0);
        }
    }
}

mod deleting {
    use super::*;

    /// `--force`: the preview on stdout, then plain deletes of the old revisions, highest
    /// first within each group, in group order; one bullet per revision and the summary
    /// on stderr (D106, D109).
    #[test]
    fn force_deletes_the_old_revisions_with_plain_deletes_d109() {
        let fx = world();
        let out = fx.run(&refs(&cleanup(&["--force"])));
        out.assert_success();
        assert_eq!(out.stdout, pretty_preview());
        assert_eq!(out.stderr, CLEAN_RUN);
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                LIST.to_owned(),
                plain_delete(2),
                plain_delete(6),
                plain_delete(5),
            ]
        );
        assert_eq!(fx.ids(), [id(1), id(4), id(7)]);
    }

    /// `--updated-by` selects the force endpoint with that audit email (D109).
    #[test]
    fn updated_by_selects_the_force_endpoint_d109() {
        let fx = world();
        let out = fx.run(&refs(&cleanup(&[
            "--force",
            "--updated-by",
            "ops@example.com",
        ])));
        out.assert_success();
        assert_eq!(
            fx.deletes(),
            [2, 6, 5].map(|n| format!(
                "DELETE /aisec/v1/mgmt/profile/{}/force?updated_by=ops%40example.com",
                id(n)
            ))
        );
    }

    /// `--quiet` keeps the preview data and drops the banner, the section and the
    /// success lines.
    #[test]
    fn quiet_keeps_the_preview_data_only() {
        let fx = world();
        let out = fx.run(&refs(&cleanup(&["--force", "--quiet"])));
        out.assert_success();
        let indented: String = TABLE
            .split('\n')
            .map(|line| format!("  {line}\n"))
            .collect();
        assert_eq!(
            out.stdout,
            format!("{indented}\n  Total: 3 old revisions to delete across 2 profiles\n\n")
        );
        assert_eq!(out.stderr, "");
    }

    /// The JSON document: preview, skipped groups, counts and per-revision details, once
    /// after the run (D94).
    #[test]
    fn json_is_one_document_after_the_run_d94() {
        let mut rows = standard_rows();
        rows.push(fixtures::profile(8, "tied", 2));
        rows.push(fixtures::profile(9, "tied", 2));
        let fx = world_with(rows);
        let out = fx.run(&refs(&cleanup(&["--force", "--output", "json"])));
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({
                "duplicates": [
                    {"name": "beta", "revisions": 2, "keeping": 3, "deleting": 1},
                    {"name": "gamma", "revisions": 3, "keeping": 3, "deleting": 2}
                ],
                "total": 3,
                "skipped": [{"name": "tied", "reason": "missing or tied revisions"}],
                "deleted": 3,
                "failed": 0,
                "unknown": 0,
                "notAttempted": 0,
                "details": [
                    {"id": id(2), "revision": 1, "name": "beta", "status": "ok"},
                    {"id": id(6), "revision": 2, "name": "gamma", "status": "ok"},
                    {"id": id(5), "revision": 1, "name": "gamma", "status": "ok"}
                ]
            })
        );
        assert!(
            out.stdout.starts_with(
                "{\n  \"duplicates\": [\n    {\n      \"name\": \"beta\",\n      \"revisions\": 2,"
            ),
            "key order: {}",
            out.stdout
        );
        assert_eq!(
            out.stderr,
            format!(
                "  ⚠ Skipped tied: its revisions are missing or tied; nothing was deleted for it\n{CLEAN_RUN}"
            )
        );
    }

    /// The table is the preview table without indent, banner or total line.
    #[test]
    fn table_is_the_bare_preview_table() {
        let fx = world();
        let out = fx.run(&refs(&cleanup(&["--force", "--output", "table"])));
        out.assert_success();
        assert_eq!(out.stdout, format!("{TABLE}\n"));
        assert_eq!(out.stderr, CLEAN_RUN);
    }

    /// Nothing to delete: no stdout in pretty and table, the success line on stderr, and
    /// a JSON document with zero counts.
    #[test]
    fn nothing_to_delete_is_a_success_line() {
        let rows = vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(3, "beta", 1),
        ];
        for format in ["pretty", "table"] {
            let fx = world_with(rows.clone());
            let out = fx.run(&refs(&cleanup(&["--force", "--output", format])));
            out.assert_success();
            assert_eq!(out.stdout, "", "{format}");
            assert_eq!(out.stderr, "  ✓ No duplicate profiles found.\n", "{format}");
            assert!(fx.deletes().is_empty());
        }
        let fx = world_with(rows);
        let out = fx.run(&refs(&cleanup(&["--force", "--output", "json"])));
        out.assert_success();
        assert_eq!(
            out.json(),
            json!({"duplicates": [], "total": 0, "skipped": [], "deleted": 0, "failed": 0,
                   "unknown": 0, "notAttempted": 0, "details": []})
        );
    }

    /// A rejected deletion (a 409 for a revision a policy references) is reported, the
    /// run continues, and the warning summary exits 1 without an error block (D109).
    #[test]
    fn a_rejected_deletion_is_reported_and_the_run_continues_d109() {
        let fx = world();
        fx.server.push_once(
            Route::ProfileDelete,
            Planned::json(
                409,
                &json!({"message": "Profile is referenced by a policy"}),
            ),
        );
        let out = fx.run(&refs(&cleanup(&["--force"])));
        out.assert_code(1);
        assert_eq!(out.stdout, pretty_preview());
        let failure = "  ✗ beta rev 1: AISEC_CLIENT_SIDE_ERROR:API error 409\n";
        assert_eq!(
            out.stderr,
            format!(
                "{failure}  ✓ gamma rev 2\n  ✓ gamma rev 1\n\n  Failures:\n\n{failure}\n  ⚠ Cleanup complete: 2 deleted, 1 failed\n\n"
            )
        );
        assert_eq!(
            fx.deletes(),
            [plain_delete(2), plain_delete(6), plain_delete(5)]
        );
        assert!(fx.ids().contains(&id(2)), "the referenced revision is kept");
    }

    /// The first deletion with an unknown outcome stops the run: one request for it, the
    /// rest not attempted (D110, D95).
    #[test]
    fn an_unknown_outcome_stops_the_run_d110() {
        let fx = world();
        fx.server.push_once(
            Route::ProfileDelete,
            Planned::json(200, &json!({"message": "deleted"})),
        );
        fx.server.push_once(
            Route::ProfileDelete,
            Planned::json(503, &json!({})).with_retry_after(0),
        );
        let out = fx.run(&refs(&cleanup(&["--force", "--output", "json"])));
        out.assert_code(1);
        let failure = "  ✗ gamma rev 2: AISEC_SERVER_SIDE_ERROR:API error 503 (outcome unknown)\n";
        assert_eq!(
            out.stderr,
            format!(
                "  ✓ beta rev 1\n{failure}  ⚠ Stopped after a deletion with an unknown outcome; 1 not attempted\n\n  Failures:\n\n{failure}\n  ⚠ Cleanup complete: 1 deleted, 0 failed, 1 outcome unknown, 1 not attempted\n\n"
            )
        );
        assert_eq!(
            fx.deletes(),
            [plain_delete(2), plain_delete(6)],
            "one attempt"
        );
        let document = out.json();
        assert_eq!(
            (
                &document["deleted"],
                &document["failed"],
                &document["unknown"],
                &document["notAttempted"]
            ),
            (&json!(1), &json!(0), &json!(1), &json!(1))
        );
        assert_eq!(
            document["details"],
            json!([
                {"id": id(2), "revision": 1, "name": "beta", "status": "ok"},
                {"id": id(6), "revision": 2, "name": "gamma", "status": "unknown",
                 "error": "AISEC_SERVER_SIDE_ERROR:API error 503"},
                {"id": id(5), "revision": 1, "name": "gamma", "status": "notAttempted"}
            ])
        );
    }

    /// A 401 on a deletion is replayed once with a fresh token (D95).
    #[test]
    fn a_401_is_replayed_once() {
        let fx = world_with(vec![
            fixtures::profile(2, "beta", 1),
            fixtures::profile(4, "beta", 3),
        ]);
        fx.server
            .push_once(Route::ProfileDelete, Planned::empty_json(401));
        let out = fx.run(&refs(&cleanup(&["--force", "--quiet"])));
        out.assert_success();
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                LIST.to_owned(),
                plain_delete(2),
                "POST /oauth/token".to_owned(),
                plain_delete(2),
            ]
        );
    }

    /// Groups with tied highest revisions or a missing revision or id are skipped with a
    /// warning and nothing is deleted from them (D110).
    #[test]
    fn tied_and_incomplete_groups_are_skipped_d110() {
        let mut missing_revision = fixtures::profile(12, "norev", 1);
        missing_revision
            .as_object_mut()
            .map(|row| row.remove("revision"));
        let mut missing_id = fixtures::profile(14, "noid", 1);
        missing_id
            .as_object_mut()
            .map(|row| row.remove("profile_id"));
        let fx = world_with(vec![
            fixtures::profile(10, "tied", 2),
            fixtures::profile(11, "tied", 2),
            missing_revision,
            fixtures::profile(13, "norev", 2),
            missing_id,
            fixtures::profile(15, "noid", 2),
            fixtures::profile(16, "ok", 1),
            fixtures::profile(17, "ok", 2),
        ]);
        let out = fx.run(&refs(&cleanup(&["--force", "--quiet"])));
        out.assert_success();
        assert_eq!(
            out.stderr,
            "  ⚠ Skipped tied: its revisions are missing or tied; nothing was deleted for it\n  ⚠ Skipped norev: its revisions are missing or tied; nothing was deleted for it\n  ⚠ Skipped noid: its revisions are missing or tied; nothing was deleted for it\n"
        );
        assert_eq!(fx.deletes(), [plain_delete(16)]);
    }

    /// D110: revisions that share a profile_id (a service that keeps the id across
    /// revisions and lists each one) are skipped, so the kept revision's id is never
    /// deleted; other groups are still cleaned up.
    #[test]
    fn revisions_sharing_an_id_are_skipped_d110() {
        let fx = world_with(vec![
            fixtures::profile(1, "prod-guard", 1),
            fixtures::profile(1, "prod-guard", 2),
            fixtures::profile(16, "ok", 1),
            fixtures::profile(17, "ok", 2),
        ]);
        let out = fx.run(&refs(&cleanup(&["--force", "--output", "json"])));
        out.assert_success();
        assert_eq!(fx.deletes(), [plain_delete(16)], "never the shared id");
        let document = out.json();
        assert_eq!(
            document["skipped"],
            json!([{"name": "prod-guard", "reason": "shared profile ids"}])
        );
        assert_eq!(document["total"], 1);
        assert!(
            out.stderr.starts_with(
                "  ⚠ Skipped prod-guard: its revisions share a profile id; nothing was deleted for it\n"
            ),
            "{:?}",
            out.stderr
        );
        // With only the shared group, nothing is deleted at all.
        let fx = world_with(vec![
            fixtures::profile(1, "prod-guard", 1),
            fixtures::profile(1, "prod-guard", 2),
        ]);
        let out = fx.run(&refs(&cleanup(&["--force", "--quiet"])));
        out.assert_success();
        assert!(fx.deletes().is_empty(), "{:?}", fx.deletes());
        assert_eq!(
            out.stderr,
            "  ⚠ Skipped prod-guard: its revisions share a profile id; nothing was deleted for it\n"
        );
    }

    /// A name with control characters is shown terminal-safe in the preview and lines.
    #[test]
    fn names_are_terminal_safe() {
        let fx = world_with(vec![
            fixtures::profile(2, "be\u{1b}[31mta", 1),
            fixtures::profile(4, "be\u{1b}[31mta", 3),
        ]);
        let out = fx.run(&refs(&cleanup(&["--force"])));
        out.assert_success();
        assert!(!out.stdout.contains('\u{1b}'), "{:?}", out.stdout);
        assert!(!out.stderr.contains('\u{1b}'), "{:?}", out.stderr);
        assert!(
            out.stderr.contains("  ✓ be\u{fffd}[31mta rev 1\n"),
            "{:?}",
            out.stderr
        );
    }

    /// A signal during a deletion stops the run and names what was deleted.
    #[test]
    fn an_interrupted_deletion_names_the_deletions_so_far() {
        let fx = world();
        fx.server.push_once(
            Route::ProfileDelete,
            Planned::json(200, &json!({"message": "deleted"})),
        );
        fx.server.push_once(Route::ProfileDelete, Planned::hang());
        let args = cleanup(&["--force"]);
        let running = spawn(&rust(), &fx.sandbox, &refs(&args), &RunOptions::new());
        assert!(
            fx.server.wait_for_requests(4, Duration::from_secs(20)),
            "the second DELETE arrived"
        );
        running.send_signal("TERM");
        let out = running.wait();
        out.assert_code(143);
        assert!(
            out.stderr.ends_with(
                "\n  ✗ Error: Interrupted; 1 deleted, 1 outcome unknown, 1 not attempted\n\n"
            ),
            "{}",
            out.stderr
        );
        assert_eq!(fx.deletes(), [plain_delete(2), plain_delete(6)]);
    }

    /// `--debug` logs the listing and the deletions.
    #[test]
    fn debug_logs_the_requests() {
        let fx = world();
        let xdg = airs_test_harness::debug_log::xdg_state_home(&fx.sandbox);
        let out = fx.run_with(
            &refs(&cleanup(&["--force", "--debug", "--quiet"])),
            &RunOptions::new().env("XDG_STATE_HOME", xdg.display().to_string()),
        );
        out.assert_success();
        let (_, records) = airs_test_harness::debug_log::only_log(&fx.sandbox);
        let text = serde_json::to_string(&records).unwrap();
        assert!(text.contains("/v1/mgmt/profiles/tsg/"), "{text}");
        assert!(text.contains("DELETE"), "{text}");
    }
}

mod listing {
    use super::*;

    /// `next_offset: 0` ends the walk (D108).
    #[test]
    fn next_offset_zero_ends_the_walk_d108() {
        let fx = world();
        fx.server.set_zero_next_offset_on_last_page(true);
        let out = fx.run(&refs(&cleanup(&["--force", "--quiet"])));
        out.assert_success();
        assert_eq!(
            fx.server.requests_for(Route::Profiles).len(),
            1,
            "one page, no re-fetch"
        );
        assert_eq!(fx.deletes().len(), 3);
    }

    /// The walk pages with `limit=200` and follows `next_offset`.
    #[test]
    fn the_walk_follows_next_offset() {
        let rows: Vec<Value> = (1..=201)
            .map(|n| {
                let name = if n == 201 {
                    "p1".to_owned()
                } else {
                    format!("p{n}")
                };
                fixtures::profile(n, &name, n)
            })
            .collect();
        let fx = world_with(rows);
        let out = fx.run(&refs(&cleanup(&["--force", "--quiet"])));
        out.assert_success();
        let pages: Vec<String> = fx
            .server
            .requests_for(Route::Profiles)
            .iter()
            .map(RecordedRequest::line)
            .collect();
        assert_eq!(
            pages,
            [
                LIST.to_owned(),
                "GET /aisec/v1/mgmt/profiles/tsg/100?offset=200&limit=200".to_owned()
            ]
        );
        assert_eq!(fx.deletes(), [plain_delete(1)], "p1 rev 1 (201 is rev 201)");
    }

    /// A repeated cursor stops the walk with an error, and nothing is deleted (D108).
    #[test]
    fn a_repeated_cursor_deletes_nothing_d108() {
        let fx = world();
        let page = json!({"ai_profiles": [fixtures::profile(2, "beta", 1)], "next_offset": 1});
        fx.server
            .push_once(Route::Profiles, Planned::json(200, &page));
        let page = json!({"ai_profiles": [fixtures::profile(4, "beta", 3)], "next_offset": 1});
        fx.server
            .push_once(Route::Profiles, Planned::json(200, &page));
        let out = fx.run(&refs(&cleanup(&["--force"])));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert!(out.error_line().is_some(), "{}", out.stderr);
        assert!(fx.deletes().is_empty());
    }

    /// A failed listing deletes nothing.
    #[test]
    fn a_failed_listing_deletes_nothing() {
        let fx = world();
        fx.server
            .set_default(Route::Profiles, Planned::json(404, &json!({})));
        let out = fx.run(&refs(&cleanup(&["--force"])));
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert!(fx.deletes().is_empty());
    }
}

mod dry_run {
    use super::*;

    /// `--dry-run` previews and deletes nothing, without a terminal (D105).
    #[test]
    fn dry_run_previews_and_deletes_nothing_d105() {
        let fx = world();
        let out = fx.run(&refs(&cleanup(&["--dry-run"])));
        out.assert_success();
        assert_eq!(out.stdout, pretty_preview());
        assert_eq!(out.stderr, "  Pass --force to delete these revisions.\n");
        assert_eq!(
            fx.lines(),
            ["POST /oauth/token".to_owned(), LIST.to_owned()]
        );
        let fx = world();
        let out = fx.run(&refs(&cleanup(&["--dry-run", "--output", "json"])));
        out.assert_success();
        let document = out.json();
        assert_eq!(document["total"], 3);
        assert_eq!(document["details"], json!([]));
        assert_eq!(document["deleted"], 0);
        assert_eq!(document["notAttempted"], 0);
        assert!(fx.deletes().is_empty());
    }
}

mod confirmation {
    use super::*;

    fn prompted(fx: &Fx, extra: &[&str]) -> airs_test_harness::pty::PtySession {
        let args = cleanup(extra);
        let mut session = spawn_pty(&rust(), &fx.sandbox, &refs(&args), &RunOptions::new());
        session.expect("? Delete 3 old profile revisions? (y/N) ");
        session
    }

    /// The preview comes first, the question on the terminal, then the listing is read
    /// again before anything is deleted (D105).
    #[test]
    fn yes_rechecks_the_listing_then_deletes_d105() {
        let fx = world();
        let mut session = prompted(&fx, &[]);
        assert_eq!(
            fx.lines(),
            ["POST /oauth/token".to_owned(), LIST.to_owned()]
        );
        session.send(b"yes\n");
        let out = session.wait();
        out.run.assert_success();
        assert_eq!(out.run.stdout, pretty_preview());
        assert!(transcript(&out).contains(CLEAN_RUN), "{}", transcript(&out));
        assert_eq!(
            fx.lines(),
            [
                "POST /oauth/token".to_owned(),
                LIST.to_owned(),
                LIST.to_owned(),
                plain_delete(2),
                plain_delete(6),
                plain_delete(5),
            ]
        );
    }

    /// One revision: the singular question.
    #[test]
    fn one_revision_is_singular() {
        let fx = world_with(vec![
            fixtures::profile(2, "beta", 1),
            fixtures::profile(4, "beta", 3),
        ]);
        let args = cleanup(&[]);
        let mut session = spawn_pty(&rust(), &fx.sandbox, &refs(&args), &RunOptions::new());
        session.expect("? Delete 1 old profile revision? (y/N) ");
        session.send(b"n\n");
        let out = session.wait();
        out.run.assert_success();
        assert!(fx.deletes().is_empty());
    }

    /// A listing that changed while the question waited deletes nothing (D105).
    #[test]
    fn a_changed_listing_deletes_nothing_d105() {
        let fx = world();
        let mut session = prompted(&fx, &[]);
        let mut rows = standard_rows();
        rows.push(fixtures::profile(8, "beta", 4));
        fx.server.set_profiles(TSG, rows);
        session.send(b"y\n");
        let out = session.wait();
        out.run.assert_code(1);
        assert!(
            transcript(&out).contains(
                "✗ Error: The profile list changed while waiting for confirmation; nothing was deleted. Run the command again."
            ),
            "{}",
            transcript(&out)
        );
        assert!(fx.deletes().is_empty());
    }

    /// Decline, EOF and an empty answer abort; table and json print nothing then.
    #[test]
    fn declining_aborts_with_nothing_deleted_d105() {
        for (answer, extra) in [
            (&b"n\n"[..], &[][..]),
            (b"\n", &["--output", "json"]),
            (b"\x04", &["--output", "table"]),
        ] {
            let fx = world();
            let mut session = prompted(&fx, extra);
            session.send(answer);
            let out = session.wait();
            out.run.assert_success();
            assert!(transcript(&out).contains("  ℹ Aborted\n"), "{answer:?}");
            if extra.is_empty() {
                assert_eq!(out.run.stdout, pretty_preview());
            } else {
                assert_eq!(out.run.stdout, "", "{extra:?}");
            }
            assert!(fx.deletes().is_empty());
            assert_eq!(fx.server.requests_for(Route::Profiles).len(), 1);
        }
    }

    /// Ctrl-C at the question changes nothing.
    #[test]
    fn ctrl_c_at_the_question_changes_nothing_d105() {
        let fx = world();
        let session = prompted(&fx, &["--updated-by", "a@b"]);
        session.signal("INT");
        let out = session.wait();
        out.run.assert_code(130);
        assert!(
            transcript(&out).contains("\n  Cancelled; nothing was changed.\n"),
            "{}",
            transcript(&out)
        );
        assert!(fx.deletes().is_empty());
    }
}
