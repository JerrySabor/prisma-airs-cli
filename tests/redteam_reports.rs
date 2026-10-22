//! Executable acceptance tests for the M6a step-3 red team commands (DESIGN §15.16–
//! §15.19): `redteam report|dashboard <jobId>`, the environment report, `targets backup`
//! and `targets restore`.
//!
//! Every test spawns the real `airs-cli-rs` against the loopback fixture server with the
//! seeded red team dataset, whose targets carry `FAKE-TARGET-SECRET-<n>` markers in
//! every credential path and whose static attacks carry one in their prompt: the
//! runner's leak check fails any run that prints one (D140). The cases of the
//! TypeScript `tests/integration/cli/redteam-dashboard.spec.ts`, `unit/cli/backup.spec.ts`,
//! `restore.spec.ts`, `backup-renderer.spec.ts`, `redteam-attacks-renderer.spec.ts`,
//! `redteam-footnote.spec.ts` and `redteam-dynamic-renderer.spec.ts` are ported here
//! (adjusted by D151, D152, D155, D156); the `unit/reports/redteam.spec.ts` cases are the
//! collector's unit tests (`src/report/tests.rs`).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airs_test_harness::fixtures::redteam as fx;
use airs_test_harness::{
    Cli, FixtureConfig, FixtureServer, Planned, PtyRun, RecordedRequest, Route, Rt, Run,
    RunOptions, Sandbox, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n";
const BACKUP_BANNER: &str = "\n  Prisma AIRS — Backup & Restore\n\n";
/// The restore refusal of a target whose credentials were withheld (§15.19 rule 2, D157).
const WITHHELD_REASON: &str = "the service withheld its credentials when it was backed up, so it cannot be restored; recreate the target or set its credentials by hand";
const FAILED_LINE: &str = "  ✗ Report generation failed. Verify Management API configuration and a writable, new output path. Existing files are never overwritten.\n";
const COLLECTING: &str =
    "  Collecting Red Team statistics and current configuration (read-only)...\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

fn fx() -> Fx {
    fx_with(|_| {})
}

fn fx_with(edit: impl FnOnce(&mut FixtureConfig)) -> Fx {
    let server = FixtureServer::start();
    server.seed_redteam();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", TSG, edit);
    sandbox.register(&[&tenant], Some("prod"));
    Fx { server, sandbox }
}

fn rt(args: &[&str]) -> Vec<String> {
    std::iter::once("redteam")
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect()
}

impl Fx {
    /// `redteam <args>`; writes allowed under `cwd/` (default report and backup names).
    fn rt(&self, args: &[&str]) -> Run {
        self.rt_with(args, &RunOptions::new())
    }

    fn rt_with(&self, args: &[&str], options: &RunOptions) -> Run {
        let args = rt(args);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run(
            &rust(),
            &self.sandbox,
            &args,
            &options.clone().allow_writes_under("cwd"),
        );
        self.server.assert_no_unknown_routes();
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

    fn clear(&self) {
        self.server.clear_requests();
    }

    /// Files under `cwd/` whose names start with `prefix`.
    fn cwd_files(&self, prefix: &str) -> Vec<PathBuf> {
        self.sandbox
            .cwd_listing()
            .into_iter()
            .filter(|path| path.to_string_lossy().starts_with(prefix))
            .map(|path| self.sandbox.cwd().join(path))
            .collect()
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn transcript(out: &PtyRun) -> String {
    out.transcript.replace("\r\n", "\n")
}

/// No `.airs-*.tmp` is left in `dir`.
fn no_temporaries(dir: &Path) {
    let left: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".airs-"))
        .collect();
    assert!(left.is_empty(), "temporaries left: {left:?}");
}

// ---------------------------------------------------------------------------
// report <jobId> (§15.16)
// ---------------------------------------------------------------------------

const STATIC_STATUS: &str = "\n  Scan Status:\n\n  ID        00000000-0000-4000-8000-000000000101\n  Name      fixture-scan\n  Type      STATIC\n  Target    fixture-target\n  Status    COMPLETED\n  Progress  40/40\n  Score     7.5\n  ASR       12.3%\n\n";

const STATIC_REPORT: &str = "\n  Static Scan Report:\n\n  Score  8.25\n  ASR    20.0%\n\n  Severity Breakdown:\n\n    HIGH       3 bypassed  7 blocked\n    LOW        0 bypassed  5 blocked\n\n  Categories:\n\n   Category         │ ASR   │ Bypassed/Total \n  ──────────────────┼───────┼────────────────\n   Jailbreak        │ 30.0% │ 3/10           \n   Prompt injection │ 0.0%  │ 0/5            \n\n  Summary:\n\n    Overall high risk posture {{UNKNOWN}}\n\n### Summary\n\n- 3 of 15 prompts bypassed the guardrails\n- Jailbreak: high risk\n\n### Recommendations\r\n- Review the jailbreak findings\n-\tRetest after changes\n\n";

mod job_report {
    use super::*;

    /// The static report: the status block, the severity lines, the indented categories
    /// table, the interpolated summary, then the attack lines and the footnote of
    /// `buildAttackListFootnote` (TS `redteam-attacks-renderer`, `redteam-footnote`).
    #[test]
    fn a_static_report_with_attacks_and_the_footnote() {
        let f = fx();
        let job = fx::job_id(1);
        let out = f.rt(&[
            "report",
            &job,
            "--attacks",
            "--severity",
            "HIGH",
            "--limit",
            "5",
        ]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}{STATIC_STATUS}{STATIC_REPORT}\n  Attacks:\n\n    HIGH       BYPASSED  Jailbreak [SECURITY]\n    HIGH       BLOCKED  Prompt injection [SECURITY]\n  (showing 2 of 10 expected for severity HIGH — list-attacks endpoint excludes some variants; tracking upstream divergence at #206)\n\n"
            )
        );
        assert_eq!(out.stderr, "");
        assert_eq!(
            f.api(),
            [
                format!("GET /redteam/data/v1/scan/{job}"),
                format!("GET /redteam/data/v1/report/static/{job}/report"),
                format!(
                    "GET /redteam/data/v1/report/static/{job}/list-attacks?limit=5&severity=HIGH"
                ),
            ]
        );
    }

    /// Without `--attacks` no list is read; `--severity` alone is accepted and unused
    /// (TS). The default `--limit` is 20; an attack without a severity is `N/A`, one
    /// without `threat` is blocked; no footnote without `--severity`.
    #[test]
    fn attacks_only_with_the_flag_and_the_default_limit() {
        let f = fx();
        let job = fx::job_id(1);
        let out = f.rt(&["report", &job, "--severity", "HIGH"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!("{BANNER}{STATIC_STATUS}{STATIC_REPORT}")
        );
        assert_eq!(f.api().len(), 2);
        f.clear();
        let out = f.rt(&["dashboard", &job, "--attacks"]);
        out.assert_success();
        assert!(out.stdout.ends_with(
            "\n  Attacks:\n\n    HIGH       BYPASSED  Jailbreak [SECURITY]\n    HIGH       BLOCKED  Prompt injection [SECURITY]\n    N/A        BLOCKED  Jailbreak [SECURITY]\n\n"
        ), "{}", out.stdout);
        assert_eq!(
            f.api()[2],
            format!("GET /redteam/data/v1/report/static/{job}/list-attacks?limit=20")
        );
        assert!(
            !out.stdout.contains("attack prompt"),
            "the attack prompt is never printed"
        );
    }

    /// No attacks: `No attacks found`, then the footnote when warranted, no blank line.
    #[test]
    fn no_attacks_and_the_footnote() {
        let f = fx();
        let job = fx::job_id(1);
        f.server.redteam(|data| {
            data.attacks.insert(job.clone(), Vec::new());
        });
        let out = f.rt(&["report", &job, "--attacks", "--severity", "HIGH"]);
        out.assert_success();
        assert!(out.stdout.ends_with(&format!(
            "{STATIC_REPORT}  No attacks found\n  (showing 0 of 10 expected for severity HIGH — list-attacks endpoint excludes some variants; tracking upstream divergence at #206)\n"
        )), "{}", out.stdout);
        // The footnote needs a severity row and fewer items than expected.
        let out = f.rt(&["report", &job, "--attacks", "--severity", "CRITICAL"]);
        assert!(
            out.stdout.ends_with("  No attacks found\n"),
            "{}",
            out.stdout
        );
        f.server.redteam(|data| {
            data.attacks.insert(job.clone(), fx::attacks());
            data.attack_totals.insert(job.clone(), 10);
        });
        let out = f.rt(&["report", &job, "--attacks", "--severity", "HIGH"]);
        assert!(!out.stdout.contains("(showing"), "{}", out.stdout);
    }

    /// The dynamic report: ASR × 100, goals, streams, threats; `--attacks` unused (TS
    /// `redteam-dynamic-renderer`).
    #[test]
    fn a_dynamic_report() {
        let f = fx();
        let job = fx::job_id(2);
        let out = f.rt(&["report", &job, "--attacks"]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BANNER}\n  Scan Status:\n\n  ID      {job}\n  Name    second-scan\n  Type    DYNAMIC\n  Target  fixture-target\n  Status  RUNNING\n\n\n  Dynamic Scan Report:\n\n  Score    6\n  ASR      25.0%\n  Goals    1 achieved / 4 total\n  Streams  24\n  Threats  2\n\n  Summary:\n\n    Dynamic low risk\n\n### Summary\n- 1 of 4 goals achieved\n\n"
            )
        );
        assert_eq!(f.api().len(), 2, "no attack list for a dynamic job");
        // Missing numbers: only what is present; goals from either count.
        f.server.redteam(|data| {
            data.dynamic_reports.insert(
                job.clone(),
                json!({"goals_achieved": 2, "report_summary": null}),
            );
        });
        let out = f.rt(&["report", &job]);
        assert!(
            out.stdout
                .ends_with("\n  Dynamic Scan Report:\n\n  Goals  2 achieved / 0 total\n\n"),
            "{}",
            out.stdout
        );
        f.server.redteam(|data| {
            data.dynamic_reports.insert(job.clone(), json!({}));
        });
        let out = f.rt(&["report", &job]);
        assert!(
            out.stdout.ends_with("\n  Dynamic Scan Report:\n\n\n"),
            "{}",
            out.stdout
        );
    }

    /// The custom report with its attack list: 80-unit previews, the dim goal line.
    #[test]
    fn a_custom_report_with_attacks() {
        let f = fx();
        f.server.redteam(|data| data.scans.push(fx::custom_job()));
        let job = fx::job_id(3);
        let out = f.rt(&["report", &job, "--attacks", "--limit", "3"]);
        out.assert_success();
        assert!(out.stdout.ends_with(&format!(
            "\n  Custom Attack Report:\n\n  Score    7\n  ASR      30.0%\n  Attacks  10\n  Threats  3\n\n  Prompt Sets:\n\n   Prompt Set  │ Threats │ Threat Rate \n  ─────────────┼─────────┼─────────────\n   fixture-set │ 3/10    │ 30.0%       \n\n\n  Custom Attacks:\n\n    THREAT ASR: 50.0%  {}...\n      Leak\n    SAFE  short prompt\n\n",
            "X".repeat(77)
        )), "{}", out.stdout);
        assert_eq!(
            f.api(),
            [
                format!("GET /redteam/data/v1/scan/{job}"),
                format!("GET /redteam/data/v1/custom-attacks/report/{job}"),
                format!(
                    "GET /redteam/data/v1/custom-attacks/job/{job}/list-custom-attacks?limit=3"
                ),
            ]
        );
        f.server.redteam(|data| {
            data.custom_attacks.insert(job.clone(), Vec::new());
        });
        let out = f.rt(&["report", &job, "--attacks"]);
        assert!(
            out.stdout.ends_with("  No custom attacks found\n"),
            "{}",
            out.stdout
        );
    }

    /// An unknown job type reads the static report (TS).
    #[test]
    fn another_job_type_reads_the_static_report() {
        let f = fx();
        let job = fx::job_id(1);
        f.server.redteam(|data| {
            data.scans[0]["job_type"] = json!("CLARA");
        });
        f.rt(&["report", &job]).assert_success();
        assert_eq!(
            f.api()[1],
            format!("GET /redteam/data/v1/report/static/{job}/report")
        );
    }

    /// The summary is multi-line server text (§15.3): its line feeds, CR LF pairs and
    /// tabs stay (continuation lines at column 0, TS); every other control character is
    /// still replaced, in pretty and table.
    #[test]
    fn a_multi_line_summary_keeps_its_lines_and_replaces_other_controls() {
        let f = fx();
        f.server.redteam(|data| {
            let report = data.static_reports.get_mut(&fx::job_id(1)).unwrap();
            report["report_summary"] =
                json!("## Risk\n\n- a\u{1b}]0;title\u{7}\r\n- b\rc\u{9b}2K\n\tdone");
        });
        let out = f.rt(&["report", &fx::job_id(1)]);
        out.assert_success();
        assert!(
            out.stdout.contains(
                "  Summary:\n\n    ## Risk\n\n- a\u{fffd}]0;title\u{fffd}\r\n- b\u{fffd}c\u{fffd}2K\n\tdone\n\n"
            ),
            "{:?}",
            out.stdout
        );
        for raw in ['\u{1b}', '\u{7}', '\u{9b}'] {
            assert!(!out.stdout.contains(raw), "{:?}", out.stdout);
        }
        let table = f.rt(&["report", &fx::job_id(1), "--output", "table"]);
        table.assert_success();
        assert!(!table.stdout.contains('\u{1b}') && !table.stdout.contains('\r'));
    }

    /// json: `{job, report, attacks: {items, totalItems}}`; table: `Key │ Value` (D144).
    #[test]
    fn json_and_table_documents_d144() {
        let f = fx();
        let job = fx::job_id(1);
        let out = f.rt(&["report", &job, "--attacks", "--output", "json"]);
        out.assert_success();
        let doc = out.json();
        assert_eq!(doc["job"]["uuid"], job);
        assert_eq!(doc["job"]["jobType"], "STATIC");
        assert_eq!(
            doc["report"],
            json!({
                "score": 8.25, "asr": 20,
                "severityBreakdown": [
                    {"severity": "HIGH", "successful": 3, "failed": 7},
                    {"severity": "LOW", "successful": 0, "failed": 5}
                ],
                "reportSummary": "Overall high risk posture {{UNKNOWN}}\n\n### Summary\n\n- 3 of 15 prompts bypassed the guardrails\n- Jailbreak: high risk\n\n### Recommendations\r\n- Review the jailbreak findings\n-\tRetest after changes",
                "categories": [
                    {"id": "JAILBREAK", "displayName": "Jailbreak", "asr": 30, "successful": 3, "failed": 7, "total": 10},
                    {"id": "PROMPT_INJECTION", "displayName": "Prompt injection", "asr": 0, "successful": 0, "failed": 5, "total": 5}
                ]
            })
        );
        assert_eq!(doc["attacks"]["totalItems"], 3);
        assert_eq!(
            doc["attacks"]["items"][0],
            json!({"id": fx::job_id(800 + 1), "name": "attack-1", "severity": "HIGH", "category": "SECURITY", "subCategory": "JAILBREAK", "subCategoryDisplayName": "Jailbreak", "successful": true})
        );
        assert_eq!(doc["attacks"]["items"][2]["successful"], false);
        let keys: Vec<&String> = doc.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 3);
        let out = f.rt(&["report", &job, "--output", "table"]);
        out.assert_success();
        assert!(out.stdout.starts_with(" Key    │ Value"), "{}", out.stdout);
        assert!(out.stdout.contains("\n job    │ {"), "{}", out.stdout);
        assert!(!out.stdout.contains("attacks"));
        // A dynamic job has no attack list even with --attacks.
        let out = f.rt(&["report", &fx::job_id(2), "--attacks", "--output", "json"]);
        assert!(out.json().get("attacks").is_none());
    }

    /// Server text that carries a secret is withheld (D47); the attack prompt marker
    /// never appears (the runner's leak check).
    #[test]
    fn server_text_with_a_secret_is_withheld() {
        let f = fx();
        let job = fx::job_id(1);
        let secret = "FAKE-SECRET-100";
        f.server.redteam(|data| {
            data.static_reports.get_mut(&job).unwrap()["report_summary"] =
                json!(format!("leaked {secret}"));
        });
        let out = f.rt(&["report", &job]);
        out.assert_success();
        assert!(out.stdout.contains("\n    [withheld]\n"), "{}", out.stdout);
    }

    /// Argument checks before the tenant: exit 2, no request (D141).
    #[test]
    fn argument_checks_come_first() {
        let f = fx();
        let job = fx::job_id(1);
        for (args, message) in [
            (
                vec!["report", "nope"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: nope",
            ),
            (
                vec!["report", &job, "--strict"],
                "Environment report options cannot be combined with a scan job ID",
            ),
            (
                vec!["report", &job, "--output-file", "x.html"],
                "Environment report options cannot be combined with a scan job ID",
            ),
            (
                vec!["report", &job, "--title", "t"],
                "Environment report options cannot be combined with a scan job ID",
            ),
            (
                vec!["report", &job, "--max-pages", "2"],
                "Environment report options cannot be combined with a scan job ID",
            ),
            (
                vec!["report", &job, "--limit", "0"],
                "--limit must be a positive integer",
            ),
            (
                vec!["report", &job, "--limit", "2.5"],
                "--limit must be a positive integer",
            ),
            (
                vec!["report", &job, "--severity", "HI\u{7}GH"],
                "--severity must be at most 4096 bytes and contain no control characters",
            ),
        ] {
            let out = f.rt(&args);
            out.assert_code(2);
            assert_eq!(
                out.stderr,
                format!("\n  ✗ {}\n\n", message.replace('\u{7}', "\u{fffd}")),
                "{args:?}"
            );
            assert_eq!(out.stdout, "");
        }
        assert_eq!(f.server.request_count(), 0);
    }

    /// A failed read: the §6 message, no banner, nothing on stdout.
    #[test]
    fn a_failed_report_read() {
        let f = fx();
        let job = fx::job_id(1);
        f.server.push_once(
            Route::RedTeam(Rt::StaticReport),
            Planned::json(404, &json!({"message": "PRIVATE-REPORT"})),
        );
        let out = f.rt(&["report", &job]);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert!(out.stderr.contains("HTTP 404"), "{}", out.stderr);
        assert!(!out.stderr.contains("PRIVATE"));
    }
}

// ---------------------------------------------------------------------------
// The environment report (§15.17; TS `redteam-dashboard.spec.ts`)
// ---------------------------------------------------------------------------

mod environment {
    use super::*;

    const SOURCES: [Rt; 7] = [
        Rt::DashboardOverview,
        Rt::ScanStatistics,
        Rt::TargetList,
        Rt::Quota,
        Rt::ScanList,
        Rt::ChannelStats,
        Rt::AdapterList,
    ];

    /// The default file: a new timestamped name in the working directory, 0600, HTML,
    /// the TS status lines, the seven reads in TS order, no POST quota.
    #[test]
    fn the_default_file_is_new_private_html_in_the_working_directory() {
        let f = fx();
        let out = f.rt(&["report"]);
        out.assert_success();
        assert_eq!(out.stdout, "");
        let files = f.cwd_files("airs-redteam-report-");
        assert_eq!(files.len(), 1, "{files:?}");
        let path = &files[0];
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.ends_with(".html")
                && name.len() == "airs-redteam-report-2026-10-17T12-00-00.000Z-0a1b2c3d.html".len(),
            "{name}"
        );
        assert!(!name.contains(':'));
        assert_eq!(mode(path), 0o600);
        let html = std::fs::read_to_string(path).unwrap();
        assert!(html.starts_with("<!doctype html>\n"));
        assert!(html.contains("<span class=\"badge\">Attention required</span>"));
        assert!(html.contains("<title>Red Team environment report</title>"));
        assert_eq!(
            out.stderr,
            format!("{COLLECTING}  Report → {} (mode 0600)\n", path.display())
        );
        assert_eq!(
            f.api(),
            [
                "GET /redteam/mgmt/v1/dashboard/overview",
                "GET /redteam/data/v1/dashboard/scan-statistics",
                "GET /redteam/mgmt/v1/target?skip=0&limit=15",
                "GET /redteam/data/v1/metering/quota",
                "GET /redteam/data/v1/scan?skip=0&limit=15",
                "GET /redteam/broker/v1/channels/stats",
                "GET /redteam/mgmt/v1/adapters?skip=0&limit=15&include_target_count=true",
            ]
        );
        assert!(f.server.rt_requests(Rt::QuotaPost).is_empty());
        no_temporaries(&f.sandbox.cwd());
        // Aggregates only: no target names, ids or settings.
        for needle in [
            "Rest Target One",
            "fixture-scan",
            &fx::target_id(1),
            "adapter-one",
        ] {
            assert!(!html.contains(needle), "{needle}");
        }
        // Two runs: two different files.
        f.rt(&["dashboard"]).assert_success();
        assert_eq!(f.cwd_files("airs-redteam-report-").len(), 2);
    }

    /// `--output-file -`: the document on stdout; HTML whatever `defaultOutput` says.
    #[test]
    fn stdout_delivery_and_the_tenant_default_output() {
        let f = fx_with(|config| {
            config.set("defaultOutput", "json");
        });
        let out = f.rt(&["--quiet", "report", "--output-file", "-"]);
        out.assert_success();
        assert!(out.stdout.starts_with("<!doctype html>\n"));
        assert!(out.stdout.ends_with("</body></html>\n"));
        assert_eq!(out.stderr, "");
        assert!(f.sandbox.cwd_listing().is_empty());
    }

    /// An explicit path, a title, the page budget.
    #[test]
    fn an_explicit_path_title_and_budget() {
        let f = fx();
        let path = f.sandbox.tmp().join("daily.html");
        let path_text = path.display().to_string();
        let out = f.rt(&[
            "report",
            "--output-file",
            &path_text,
            "--title",
            "</script><b>Daily</b>",
            "--max-pages",
            "1",
        ]);
        out.assert_success();
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("<title>&#60;/script&#62;&#60;b&#62;Daily&#60;/b&#62;</title>"));
        assert!(!html.contains("<b>"));
        assert_eq!(mode(&path), 0o600);
    }

    /// A partial report exits 0; `--strict` exits 1 after writing; the status line counts
    /// the incomplete sources.
    #[test]
    fn a_partial_report_and_strict() {
        let f = fx();
        f.server
            .set_default(Route::RedTeam(Rt::ScanList), Planned::json(200, &json!({})));
        let first = f.sandbox.tmp().join("partial.html");
        let out = f.rt(&["report", "--output-file", &first.display().to_string()]);
        out.assert_success();
        assert!(
            out.stderr
                .ends_with("  1 source(s) incomplete; review the evidence section.\n"),
            "{}",
            out.stderr
        );
        assert!(
            std::fs::read_to_string(&first)
                .unwrap()
                .contains("unavailable")
        );
        let second = f.sandbox.tmp().join("strict.html");
        let out = f.rt(&[
            "report",
            "--strict",
            "--output-file",
            &second.display().to_string(),
        ]);
        out.assert_code(1);
        assert!(!out.stderr.contains("✗"), "no error block: {}", out.stderr);
        assert!(
            std::fs::read_to_string(&second)
                .unwrap()
                .contains("unavailable")
        );
    }

    /// No source available: the file is still written (`Unable to assess`), exit 1, and
    /// no server text (`PRIVATE-ERROR`) anywhere; every read sent once (`numRetries: 0`).
    #[test]
    fn no_source_available_still_writes_the_report() {
        let f = fx();
        for source in SOURCES {
            f.server.set_default(
                Route::RedTeam(source),
                Planned::json(503, &json!({"message": "PRIVATE-ERROR"})).with_retry_after(0),
            );
        }
        let path = f.sandbox.tmp().join("unavailable.html");
        let out = f.rt(&["report", "--output-file", &path.display().to_string()]);
        out.assert_code(1);
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("Unable to assess"));
        assert!(html.contains("HTTP 503: source unavailable"));
        assert!(!html.contains("PRIVATE-ERROR"));
        assert!(!out.stderr.contains("PRIVATE-ERROR"));
        assert!(
            out.stderr
                .ends_with("  7 source(s) incomplete; review the evidence section.\n")
        );
        for source in SOURCES {
            assert_eq!(
                f.server.rt_requests(source).len(),
                1,
                "{source:?}: no retry"
            );
        }
    }

    /// G7: a read answered 401 is re-read once after a fresh token (TS's free replay);
    /// a 403 too.
    #[test]
    fn an_authentication_rejection_is_re_read_once_g7() {
        for status in [401, 403] {
            let f = fx();
            f.server.push_once(
                Route::RedTeam(Rt::DashboardOverview),
                Planned::json(status, &json!({})),
            );
            let out = f.rt(&["report", "--output-file", "-"]);
            out.assert_success();
            assert_eq!(
                f.server.rt_requests(Rt::DashboardOverview).len(),
                2,
                "{status}"
            );
            assert!(out.stdout.contains("<td>Targets</td><td>4</td>"));
        }
        let f = fx();
        for _ in 0..2 {
            f.server.push_once(
                Route::RedTeam(Rt::DashboardOverview),
                Planned::json(401, &json!({})),
            );
        }
        let out = f.rt(&["report", "--output-file", "-"]);
        out.assert_success();
        assert_eq!(
            f.server.rt_requests(Rt::DashboardOverview).len(),
            2,
            "once only"
        );
        assert!(out.stdout.contains("HTTP 401: source unavailable"));
    }

    /// An existing path, a dangling symlink or a symlink to a file is refused before the
    /// tenant and any request: the TS failure line only, the file untouched.
    #[test]
    fn an_existing_path_is_refused_before_any_request() {
        let f = fx();
        let existing = f.sandbox.tmp().join("existing.html");
        std::fs::write(&existing, "KEEP").unwrap();
        let dangling = f.sandbox.tmp().join("dangling.html");
        std::os::unix::fs::symlink(f.sandbox.tmp().join("nowhere"), &dangling).unwrap();
        let linked = f.sandbox.tmp().join("linked.html");
        std::os::unix::fs::symlink(&existing, &linked).unwrap();
        for path in [&existing, &dangling, &linked] {
            let out = f.rt(&["report", "--output-file", &path.display().to_string()]);
            out.assert_code(1);
            assert_eq!(out.stderr, FAILED_LINE);
            assert_eq!(out.stdout, "");
        }
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "KEEP");
        assert!(!f.sandbox.tmp().join("nowhere").exists());
        assert_eq!(f.server.request_count(), 0);
    }

    /// A tenant or credential error, or a directory that does not exist: only the TS
    /// failure line (no path, no OS error, no config content), exit 1.
    #[test]
    fn other_failures_print_only_the_failure_line() {
        let f = fx_with(|config| {
            config.remove("mgmtClientSecret");
        });
        let out = f.rt(&["report", "--output-file", "-"]);
        out.assert_code(1);
        assert_eq!(out.stderr, FAILED_LINE);
        assert_eq!(f.server.request_count(), 0);
        let f = fx();
        let missing = f.sandbox.tmp().join("nodir").join("r.html");
        let out = f.rt(&["report", "--output-file", &missing.display().to_string()]);
        out.assert_code(1);
        assert_eq!(out.stderr, format!("{COLLECTING}{FAILED_LINE}"));
        assert!(!missing.exists());
    }

    /// Every invalid option exits 2 before the tenant and any request (TS order).
    #[test]
    fn invalid_options_exit_2_before_any_request() {
        let f = fx();
        let job = fx::job_id(1);
        let long = "x".repeat(241);
        for (args, message) in [
            (
                vec!["report", "--attacks"],
                "--attacks, --severity and --limit require a scan job ID",
            ),
            (
                vec!["report", "--severity", "HIGH"],
                "--attacks, --severity and --limit require a scan job ID",
            ),
            (
                vec!["report", "--limit", "10"],
                "--attacks, --severity and --limit require a scan job ID",
            ),
            (
                vec!["report", &job, "--strict"],
                "Environment report options cannot be combined with a scan job ID",
            ),
            (
                vec!["--output", "json", "report"],
                "The environment report is written as HTML; omit --output",
            ),
            (
                vec!["--output", "pretty", "report"],
                "The environment report is written as HTML; omit --output",
            ),
            (
                vec!["--output", "html", "report"],
                "Invalid output format 'html'. Expected: pretty, table, json",
            ),
            (
                vec!["--output", "markdown", "report"],
                "Invalid output format 'markdown'. Expected: pretty, table, json",
            ),
            (
                vec!["report", "--max-pages", "0"],
                "--max-pages must be an integer from 1 to 100",
            ),
            (
                vec!["report", "--max-pages", "1.5"],
                "--max-pages must be an integer from 1 to 100",
            ),
            (
                vec!["report", "--max-pages", "101"],
                "--max-pages must be an integer from 1 to 100",
            ),
            (
                vec!["report", "--max-pages", "1e1"],
                "--max-pages must be an integer from 1 to 100",
            ),
            (
                vec!["report", "--max-pages", "07"],
                "--max-pages must be an integer from 1 to 100",
            ),
            (
                vec!["report", "--title", ""],
                "--title must contain 1–240 characters",
            ),
            (
                vec!["report", "--title", " \t "],
                "--title must contain 1–240 characters",
            ),
            (
                vec!["report", "--title", &long],
                "--title must contain 1–240 characters",
            ),
            (
                vec!["report", "--output-file", ""],
                "--output-file cannot be empty",
            ),
            (
                vec!["report", "--output-file", "  "],
                "--output-file cannot be empty",
            ),
        ] {
            let mut full = vec!["redteam"];
            full.extend(args.iter().copied());
            let (head, tail) = if full[1] == "--output" {
                (vec![full[1], full[2]], vec!["redteam", full[3]])
            } else {
                (Vec::new(), full.clone())
            };
            let mut command: Vec<&str> = head;
            command.extend(tail);
            let out = run(&rust(), &f.sandbox, &command, &RunOptions::new());
            out.assert_code(2);
            assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
        }
        assert_eq!(f.server.request_count(), 0);
        assert!(f.sandbox.cwd_listing().is_empty());
    }

    /// `--debug` is refused through both names (D156): no debug directory, no request.
    #[test]
    fn debug_is_refused_d156() {
        let f = fx();
        for name in ["report", "dashboard"] {
            let out = f.rt(&["--debug", name]);
            out.assert_code(2);
            assert_eq!(
                out.stderr,
                "\n  ✗ Disable --debug for environment reports to avoid persisting sensitive traffic content\n\n"
            );
        }
        // The flag is global: after the subcommand too.
        let out = run(
            &rust(),
            &f.sandbox,
            &["redteam", "report", "--debug"],
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert_eq!(f.server.request_count(), 0);
        assert!(f.sandbox.home_listing().is_empty());
        assert!(!f.sandbox.state_dir().join("airs-cli/debug").exists());
        // A job report allows --debug.
        let out = f.rt_with(
            &["--debug", "report", &fx::job_id(1)],
            &RunOptions::new().allow_writes_under("home"),
        );
        out.assert_success();
        assert!(
            out.stderr.starts_with("  Debug: API log → "),
            "{}",
            out.stderr
        );
    }

    /// A signal while a source is held: `no report was written`, exit 130, no file.
    #[test]
    fn an_interruption_writes_no_report() {
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::ScanList), Planned::held());
        let path = f.sandbox.tmp().join("held.html");
        let path_text = path.display().to_string();
        let running = spawn(
            &rust(),
            &f.sandbox,
            &["redteam", "report", "--output-file", &path_text],
            &RunOptions::new().expect_signal(),
        );
        assert!(
            f.server
                .wait_for_route(Route::RedTeam(Rt::ScanList), 1, Duration::from_secs(20))
        );
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert!(
            out.stderr
                .ends_with("\n  ✗ Error: Interrupted; no report was written\n\n"),
            "{}",
            out.stderr
        );
        assert!(!path.exists());
        no_temporaries(&f.sandbox.tmp());
    }
}

// ---------------------------------------------------------------------------
// targets backup (§15.18; TS `backup.spec.ts`, `backup-renderer.spec.ts`)
// ---------------------------------------------------------------------------

/// The single backup file in `dir`.
fn backup_file(dir: &Path) -> PathBuf {
    let files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("airs-redteam-targets-"))
        })
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    files[0].clone()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

mod backup {
    use super::*;

    /// Every target into one new 0600 file in the working directory: the Rust format,
    /// the create projections (server fields stripped, the adapter-backed target kept
    /// whole, D151), no fabricated `ws_response_timeout` (D153), the warning, the summary.
    #[test]
    fn backs_up_every_target_into_one_private_file() {
        let f = fx();
        let out = f.rt(&["targets", "backup"]);
        out.assert_success();
        let path = backup_file(&f.sandbox.cwd());
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(
            name.len(),
            "airs-redteam-targets-20261017T120000Z-0a1b2c3d.json".len(),
            "{name}"
        );
        assert_eq!(mode(&path), 0o600);
        no_temporaries(&f.sandbox.cwd());
        let shown = format!("./{name}");
        assert_eq!(
            out.stdout,
            format!(
                "{BACKUP_BANNER}\n  Backed up 4 target(s) to {shown}:\n\n  ✓ Rest Target One\n  ✓ Native/OpenAI ✓\n  ✓ Bedrock Target\n  ✓ Adapter Target\n\n"
            )
        );
        assert_eq!(
            out.stderr,
            format!("  ⚠ {shown} contains target credentials; keep it private (mode 0600)\n")
        );
        let doc = read_json(&path);
        let keys: Vec<&String> = doc.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 8);
        assert_eq!(doc["format"], "airs-cli-rs.redteam-targets");
        assert_eq!(doc["version"], 1);
        assert_eq!(doc["tenant"], "prod");
        assert_eq!(doc["tsgId"], "100");
        assert_eq!(doc["complete"], true);
        assert_eq!(doc["failed"], json!([]));
        let targets = doc["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 4);
        let rest = &targets[0];
        assert_eq!(rest["uuid"], fx::target_id(1));
        assert_eq!(rest["name"], "Rest Target One");
        assert_eq!(rest["credentialsWithheld"], false);
        let stored = &rest["target"];
        for server_field in [
            "uuid",
            "tsg_id",
            "status",
            "active",
            "validated",
            "created_at",
            "updated_at",
        ] {
            assert!(stored.get(server_field).is_none(), "{server_field}");
        }
        assert_eq!(stored["description"], "Fixture REST target");
        assert_eq!(
            stored["auth_config"]["auth_header"]["Authorization"],
            format!("Bearer {}", fx::secret(4))
        );
        assert!(
            stored["connection_params"]
                .get("ws_response_timeout")
                .is_none(),
            "D153"
        );
        assert!(
            stored["target_metadata"]
                .get("multi_turn_error_message")
                .is_none()
        );
        let adapter = &targets[3]["target"];
        assert_eq!(adapter["adapter_uuid"], fx::adapter_id(1));
        assert_eq!(
            adapter["adapter_variable_overrides"][1],
            json!({"key": "api_token", "value": fx::secret(15), "type": "SECRET"})
        );
        // The projection keeps the order of the create schema.
        let text = std::fs::read_to_string(&path).unwrap();
        let order: Vec<usize> = [
            "\"name\"",
            "\"description\"",
            "\"target_type\"",
            "\"connection_type\"",
        ]
        .iter()
        .map(|key| {
            text[text.find("\"target\": {").unwrap()..]
                .find(key)
                .unwrap()
        })
        .collect();
        assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");
        assert_eq!(
            f.api(),
            [
                "GET /redteam/mgmt/v1/target?skip=0&limit=100".to_owned(),
                format!("GET /redteam/mgmt/v1/target/{}", fx::target_id(1)),
                format!("GET /redteam/mgmt/v1/target/{}", fx::target_id(2)),
                format!("GET /redteam/mgmt/v1/target/{}", fx::target_id(3)),
                format!("GET /redteam/mgmt/v1/target/{}", fx::target_id(4)),
            ]
        );
    }

    /// D153, §15.18: the backup stores each target's settings as the server returned
    /// them: every key it sent (unknown keys and explicit `null`s included), no schema
    /// default it omitted (`ws_response_timeout`, `basic_auth_location`), and below the
    /// create projection the keys in sorted order, the bytes of the 0.6 raw read.
    #[test]
    fn a_backup_stores_only_what_the_server_sent() {
        let f = fx();
        f.server.redteam(|data| data.targets.truncate(1));
        let id = fx::target_id(1);
        let params = r#"{"response_key":"r","api_endpoint":"https://x.invalid/v1","zz_extra":{"y":1,"x":2},"request_json":{"z":"{INPUT}","a":null},"request_headers":{"X-B":"1","Content-Type":"application/json"}}"#;
        let text = format!(
            r#"{{"uuid":"{id}","tsg_id":"100","name":"Ordered","status":"ACTIVE","active":true,"validated":true,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z","target_type":"APPLICATION","connection_type":"CUSTOM","api_endpoint_type":"PUBLIC","response_mode":"REST","auth_type":"BASIC_AUTH","connection_params":{params},"auth_config":{{"basic_auth_header":{{"X-Basic":"plain"}}}},"extra_info":{{"zeta":1,"alpha":2.5}}}}"#
        );
        f.server.push_once(
            Route::RedTeam(Rt::TargetGet),
            Planned::raw(200, "application/json", text),
        );
        let out = f.rt(&["targets", "backup"]);
        out.assert_success();
        let path = backup_file(&f.sandbox.cwd());
        let stored = read_json(&path);
        let target = &stored["targets"][0]["target"];
        assert_eq!(
            target["connection_params"],
            serde_json::from_str::<Value>(params).unwrap()
        );
        assert_eq!(
            target["auth_config"],
            json!({"basic_auth_header": {"X-Basic": "plain"}})
        );
        assert_eq!(target["extra_info"], json!({"zeta": 1, "alpha": 2.5}));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(
                r#"      "target": {
        "name": "Ordered",
        "target_type": "APPLICATION",
        "connection_type": "CUSTOM",
        "api_endpoint_type": "PUBLIC",
        "response_mode": "REST",
        "connection_params": {
          "api_endpoint": "https://x.invalid/v1",
          "request_headers": {
            "Content-Type": "application/json",
            "X-B": "1"
          },
          "request_json": {
            "a": null,
            "z": "{INPUT}"
          },
          "response_key": "r",
          "zz_extra": {
            "x": 2,
            "y": 1
          }
        },
        "auth_config": {
          "basic_auth_header": {
            "X-Basic": "plain"
          }
        },
        "auth_type": "BASIC_AUTH",
        "extra_info": {
          "alpha": 2.5,
          "zeta": 1
        }
      }"#
            ),
            "{text}"
        );
    }

    /// `--output-dir`, `--name` (every target of that name), json and table.
    #[test]
    fn output_dir_name_and_formats() {
        let f = fx();
        f.server.redteam(|data| {
            let mut twin = fx::bedrock_target(5, "Bedrock Target");
            twin["uuid"] = json!(fx::target_id(5));
            data.targets.push(twin);
        });
        let dir = f.sandbox.tmp().join("backups");
        std::fs::create_dir(&dir).unwrap();
        let dir_text = dir.display().to_string();
        let out = f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &dir_text,
            "--name",
            "Bedrock Target",
            "--output",
            "json",
        ]);
        out.assert_success();
        let path = backup_file(&dir);
        let doc = out.json();
        assert_eq!(doc["file"], path.display().to_string());
        assert_eq!(doc["backedUp"], 2);
        assert_eq!(doc["failed"], json!([]));
        assert_eq!(
            doc["targets"],
            json!([
                {"uuid": fx::target_id(3), "name": "Bedrock Target", "credentialsWithheld": false},
                {"uuid": fx::target_id(5), "name": "Bedrock Target", "credentialsWithheld": false}
            ])
        );
        assert_eq!(read_json(&path)["targets"].as_array().unwrap().len(), 2);
        let other = f.sandbox.tmp().join("other");
        std::fs::create_dir(&other).unwrap();
        let out = f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &other.display().to_string(),
            "--output",
            "table",
        ]);
        out.assert_success();
        assert!(out.stdout.starts_with(" Target "), "{}", out.stdout);
        assert!(
            out.stdout.contains(&format!(" {} │ ok", fx::target_id(1))),
            "{}",
            out.stdout
        );
    }

    /// `Target not found` (TS), exit 1, no file; no target at all: no file, exit 0.
    #[test]
    fn not_found_and_no_targets() {
        let f = fx();
        let out = f.rt(&["targets", "backup", "--name", "Nonexistent"]);
        out.assert_code(1);
        assert!(
            out.stderr
                .contains("✗ Error: Target not found: Nonexistent"),
            "{}",
            out.stderr
        );
        assert!(f.sandbox.cwd_listing().is_empty());
        f.server.redteam(|data| data.targets.clear());
        let out = f.rt(&["targets", "backup"]);
        out.assert_success();
        assert_eq!(out.stdout, format!("{BACKUP_BANNER}  No targets found\n"));
        assert_eq!(out.stderr, "");
        let out = f.rt(&["targets", "backup", "--output", "json"]);
        assert_eq!(
            out.json(),
            json!({"file": null, "backedUp": 0, "failed": [], "targets": []})
        );
        assert!(f.sandbox.cwd_listing().is_empty());
    }

    /// The per-target read is the SDK's typed `get` (D153, scm-sdk 0.1.1): the `--debug`
    /// log names it `red_team.targets.get` (0.6's raw read was `custom.read`).
    #[test]
    fn the_debug_log_names_the_typed_target_read() {
        let f = fx();
        f.server.redteam(|data| data.targets.truncate(1));
        let state = airs_test_harness::debug_log::xdg_state_home(&f.sandbox)
            .display()
            .to_string();
        let out = run(
            &rust(),
            &f.sandbox,
            &["--debug", "redteam", "targets", "backup"],
            &RunOptions::new()
                .env("XDG_STATE_HOME", &state)
                .allow_writes_under("cwd"),
        );
        out.assert_success();
        let (_, records) = airs_test_harness::debug_log::only_log(&f.sandbox);
        let operations: Vec<&str> = records
            .iter()
            .filter_map(|record| record["operation"].as_str())
            .collect();
        assert_eq!(
            operations,
            [
                "oauth.token",
                "red_team.targets.list",
                "red_team.targets.get"
            ]
        );
    }

    /// A target document the response schema refuses is a failed row (the SDK's
    /// decode failure), its body never echoed.
    #[test]
    fn a_refused_target_document_is_a_failed_row() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::TargetGet),
            Planned::raw(
                200,
                "application/json",
                r#"{"uuid":"PRIVATE","name":"x","active":"yes"}"#,
            ),
        );
        let out = f.rt(&["targets", "backup", "--output", "json"]);
        out.assert_code(1);
        let doc = out.json();
        assert_eq!(doc["backedUp"], 3);
        assert_eq!(
            doc["failed"],
            json!([{
                "uuid": fx::target_id(1),
                "name": "Rest Target One",
                "error": "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema"
            }])
        );
        assert!(!out.stdout.contains("PRIVATE"));
    }

    /// A target that cannot be read is a failed row: the file is still written (complete
    /// false), the summary lists it, exit 1 without an error block.
    #[test]
    fn a_failed_target_is_a_failed_row() {
        let f = fx();
        f.server.push_once(
            Route::RedTeam(Rt::TargetGet),
            Planned::json(404, &json!({"message": "PRIVATE"})),
        );
        let out = f.rt(&["targets", "backup"]);
        out.assert_code(1);
        assert!(out.stdout.contains("  ✓ Native/OpenAI ✓\n"));
        assert!(
            out.stdout.contains(
                "\n  Failed (1):\n\n  ✗ Rest Target One: AISEC_CLIENT_SIDE_ERROR:API error 404\n\n"
            ),
            "{}",
            out.stdout
        );
        assert!(!out.stderr.contains("✗"), "{}", out.stderr);
        assert!(!out.stdout.contains("PRIVATE"));
        let doc = read_json(&backup_file(&f.sandbox.cwd()));
        assert_eq!(doc["complete"], false);
        assert_eq!(doc["failed"][0]["uuid"], fx::target_id(1));
        assert_eq!(doc["targets"].as_array().unwrap().len(), 3);
    }

    /// The location and the argument checks come before the tenant: no request.
    #[test]
    fn location_and_argument_checks() {
        let f = fx();
        let file = f.sandbox.tmp().join("file");
        std::fs::write(&file, "x").unwrap();
        let missing = f.sandbox.tmp().join("missing");
        for dir in [&file, &missing] {
            let shown = dir.display().to_string();
            let out = f.rt(&["targets", "backup", "--output-dir", &shown]);
            out.assert_code(1);
            assert!(
                out.stderr.contains(&format!(
                    "Cannot write a backup into {shown}; it must be an existing directory"
                )),
                "{}",
                out.stderr
            );
        }
        for (args, message) in [
            (
                vec!["targets", "backup", "--file-format", "yaml"],
                "--file-format must be json (yaml was dropped)",
            ),
            (
                vec!["targets", "backup", "--name", ""],
                "--name needs a target name",
            ),
            (
                vec!["targets", "backup", "--output-dir", ""],
                "--output-dir needs a path",
            ),
        ] {
            let out = f.rt(&args);
            out.assert_code(2);
            assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"));
        }
        // The deprecated --format warns first, never quiet-suppressed.
        let out = f.rt(&["--quiet", "targets", "backup", "--format", "yaml"]);
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            "  ⚠ --format is deprecated and will be removed in v4 — use --file-format\n\n  ✗ --file-format must be json (yaml was dropped)\n\n"
        );
        assert_eq!(f.server.request_count(), 0);
        let dir = f.sandbox.tmp().join("ok");
        std::fs::create_dir(&dir).unwrap();
        let out = f.rt(&[
            "targets",
            "backup",
            "--format",
            "json",
            "--output-dir",
            &dir.display().to_string(),
        ]);
        out.assert_success();
        assert!(out.stderr.starts_with("  ⚠ --format is deprecated"));
    }

    /// A symlinked directory is followed; the file inside it is new and private.
    #[test]
    fn a_symlinked_directory_is_followed() {
        let f = fx();
        let real = f.sandbox.tmp().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = f.sandbox.tmp().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &link.display().to_string(),
        ])
        .assert_success();
        assert_eq!(mode(&backup_file(&real)), 0o600);
    }

    /// D157: a target whose credentials the service returned masked or without a value
    /// is stored as returned (masks included) with `credentialsWithheld: true` and a `⚠`
    /// row; the backup stays complete and exits 0; json and table mark it too. Restore
    /// then refuses it by name before any write (also in a dry run).
    #[test]
    fn withheld_credentials_are_stored_with_a_marker_d157() {
        let f = fx();
        f.server.redteam(|data| {
            data.targets[1]["connection_params"]["target_connection_config"]["api_key"] =
                json!("********");
            data.targets[3]["adapter_variable_overrides"][1]
                .as_object_mut()
                .unwrap()
                .remove("value");
        });
        let dir = f.sandbox.tmp().join("masked");
        std::fs::create_dir(&dir).unwrap();
        let dir_text = dir.display().to_string();
        let out = f.rt(&["targets", "backup", "--output-dir", &dir_text]);
        out.assert_success();
        let path = backup_file(&dir);
        let shown = path.display().to_string();
        let note = "credentials withheld by the service; restore will refuse it";
        assert_eq!(
            out.stdout,
            format!(
                "{BACKUP_BANNER}\n  Backed up 4 target(s) to {shown}:\n\n  ✓ Rest Target One\n  ⚠ Native/OpenAI ✓ — {note}\n  ✓ Bedrock Target\n  ⚠ Adapter Target — {note}\n\n"
            )
        );
        // The other targets carry credentials the service returned.
        assert_eq!(
            out.stderr,
            format!("  ⚠ {shown} contains target credentials; keep it private (mode 0600)\n")
        );
        let doc = read_json(&path);
        assert_eq!(doc["complete"], true);
        assert_eq!(doc["failed"], json!([]));
        let targets = doc["targets"].as_array().unwrap();
        let marks: Vec<&Value> = targets.iter().map(|t| &t["credentialsWithheld"]).collect();
        assert_eq!(
            marks,
            [&json!(false), &json!(true), &json!(false), &json!(true)]
        );
        assert_eq!(
            targets[1]["target"]["connection_params"]["target_connection_config"]["api_key"],
            "********",
            "stored as returned"
        );
        assert_eq!(
            targets[3]["target"]["adapter_variable_overrides"][1],
            json!({"key": "api_token", "type": "SECRET"})
        );
        let json_dir = f.sandbox.tmp().join("masked-json");
        std::fs::create_dir(&json_dir).unwrap();
        let out = f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &json_dir.display().to_string(),
            "--output",
            "json",
        ]);
        out.assert_success();
        let summary = out.json();
        assert_eq!(summary["backedUp"], 4);
        assert_eq!(
            summary["targets"][1],
            json!({"uuid": fx::target_id(2), "name": "Native/OpenAI ✓", "credentialsWithheld": true})
        );
        let table_dir = f.sandbox.tmp().join("masked-table");
        std::fs::create_dir(&table_dir).unwrap();
        let out = f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &table_dir.display().to_string(),
            "--output",
            "table",
        ]);
        out.assert_success();
        assert!(
            out.stdout
                .contains(&format!(" {} │ withheld", fx::target_id(2))),
            "{}",
            out.stdout
        );
        assert!(
            out.stdout.contains(&format!(" {} │ ok", fx::target_id(1))),
            "{}",
            out.stdout
        );
        // Restore: the marked targets are failed rows before any write.
        f.server.redteam(|data| data.targets.clear());
        let refused = format!("failed: {WITHHELD_REASON}");
        f.clear();
        let out = f.rt(&["targets", "restore", "--file", &shown, "--dry-run"]);
        out.assert_code(1);
        assert_eq!(
            out.stdout,
            format!(
                "{BACKUP_BANNER}\n  Restore results:\n\n  • Rest Target One — would create\n  ✗ Native/OpenAI ✓ — {refused}\n  • Bedrock Target — would create\n  ✗ Adapter Target — {refused}\n\n  Total: 2 would create, 2 failed\n\n"
            )
        );
        assert!(f.api().iter().all(|line| line.starts_with("GET ")));
        let out = f.rt(&["targets", "restore", "--file", &shown]);
        out.assert_code(1);
        assert!(
            out.stdout
                .contains(&format!("  ✗ Native/OpenAI ✓ — {refused}\n")),
            "{}",
            out.stdout
        );
        assert!(out.stdout.ends_with("\n  Total: 2 created, 2 failed\n\n"));
        let posted: Vec<String> = f
            .server
            .rt_requests(Rt::TargetCreate)
            .iter()
            .map(|request| {
                request.body_json().unwrap()["name"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(posted, ["Rest Target One", "Bedrock Target"]);
    }

    /// The credentials warning needs a credential the service returned: none for a file
    /// whose every target failed, or whose stored credentials were all withheld (the file
    /// is 0600 either way).
    #[test]
    fn the_credentials_warning_needs_a_returned_credential() {
        let f = fx();
        for _ in 0..4 {
            f.server.push_once(
                Route::RedTeam(Rt::TargetGet),
                Planned::json(404, &json!({"message": "gone"})),
            );
        }
        let dir = f.sandbox.tmp().join("failed");
        std::fs::create_dir(&dir).unwrap();
        let out = f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &dir.display().to_string(),
        ]);
        out.assert_code(1);
        assert_eq!(out.stderr, "");
        let path = backup_file(&dir);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(read_json(&path)["targets"], json!([]));
        f.server.redteam(|data| {
            data.targets.drain(..3);
            data.targets[0]["adapter_variable_overrides"][1]["value"] = json!("**********");
        });
        let dir = f.sandbox.tmp().join("masked");
        std::fs::create_dir(&dir).unwrap();
        let out = f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &dir.display().to_string(),
        ]);
        out.assert_success();
        assert_eq!(out.stderr, "");
        assert!(out.stdout.contains(
            "  ⚠ Adapter Target — credentials withheld by the service; restore will refuse it\n"
        ));
        let path = backup_file(&dir);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(read_json(&path)["targets"][0]["credentialsWithheld"], true);
    }

    /// A signal while a target read is held: no file.
    #[test]
    fn an_interruption_writes_no_backup() {
        let f = fx();
        f.server
            .push_once(Route::RedTeam(Rt::TargetGet), Planned::held());
        let dir = f.sandbox.tmp().join("held");
        std::fs::create_dir(&dir).unwrap();
        let dir_text = dir.display().to_string();
        let running = spawn(
            &rust(),
            &f.sandbox,
            &["redteam", "targets", "backup", "--output-dir", &dir_text],
            &RunOptions::new().expect_signal(),
        );
        assert!(
            f.server
                .wait_for_route(Route::RedTeam(Rt::TargetGet), 1, Duration::from_secs(20))
        );
        running.send_signal("TERM");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(143);
        assert!(
            out.stderr
                .ends_with("\n  ✗ Error: Interrupted; no backup file was written\n\n"),
            "{}",
            out.stderr
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }
}

// ---------------------------------------------------------------------------
// targets restore (§15.19; TS `restore.spec.ts`)
// ---------------------------------------------------------------------------

mod restore {
    use super::*;

    /// A backup of the seeded targets in `tmp/`, returned with its path text.
    fn backup(f: &Fx) -> (PathBuf, String) {
        let dir = f.sandbox.tmp().join("b");
        std::fs::create_dir_all(&dir).unwrap();
        f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &dir.display().to_string(),
        ])
        .assert_success();
        let path = backup_file(&dir);
        let text = path.display().to_string();
        f.clear();
        (path, text)
    }

    fn bodies(f: &Fx, route: Rt) -> Vec<Value> {
        f.server
            .rt_requests(route)
            .iter()
            .map(|request| request.body_json().unwrap())
            .collect()
    }

    /// A round trip: every target recreated with its stored body and TS's routing
    /// defaults, the adapter-backed one included (D151); one POST each.
    #[test]
    fn a_round_trip_recreates_every_target() {
        let f = fx();
        let (path, text) = backup(&f);
        let stored = read_json(&path);
        f.server.redteam(|data| data.targets.clear());
        let out = f.rt(&["targets", "restore", "--file", &text]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BACKUP_BANNER}\n  Restore results:\n\n  ✓ Rest Target One — created\n  ✓ Native/OpenAI ✓ — created\n  ✓ Bedrock Target — created\n  ✓ Adapter Target — created\n\n  Total: 4 created\n\n"
            )
        );
        let posted = bodies(&f, Rt::TargetCreate);
        assert_eq!(posted.len(), 4);
        for (body, stored) in posted.iter().zip(stored["targets"].as_array().unwrap()) {
            for (key, value) in stored["target"].as_object().unwrap() {
                if key == "connection_params" {
                    continue;
                }
                assert_eq!(&body[key], value, "{key}");
            }
        }
        assert_eq!(posted[3]["adapter_uuid"], fx::adapter_id(1));
        assert_eq!(
            posted[3]["adapter_variable_overrides"][1]["value"],
            fx::secret(15)
        );
        assert_eq!(
            f.server.rt_requests(Rt::TargetCreate)[0].line(),
            "POST /redteam/mgmt/v1/target"
        );
        assert_eq!(f.server.redteam_data().targets.len(), 4);
    }

    /// Existing names are skipped without `--overwrite`; with `--overwrite --force` they
    /// are updated (PUT, routing filled from the current target); `--validate` is passed.
    #[test]
    fn skip_overwrite_and_validate() {
        let f = fx();
        let (_, text) = backup(&f);
        let out = f.rt(&["targets", "restore", "--file", &text]);
        out.assert_success();
        assert!(out.stdout.contains("  ○ Rest Target One — skipped\n"));
        assert!(out.stdout.ends_with("\n  Total: 4 skipped\n\n"));
        assert!(f.server.rt_requests(Rt::TargetCreate).is_empty());
        assert!(f.server.rt_requests(Rt::TargetUpdate).is_empty());
        f.clear();
        let out = f.rt(&[
            "targets",
            "restore",
            "--file",
            &text,
            "--overwrite",
            "--force",
            "--validate",
            "--output",
            "json",
        ]);
        out.assert_success();
        let doc = out.json();
        assert_eq!(doc["updated"], 4);
        assert_eq!(doc["dryRun"], false);
        assert_eq!(
            doc["details"][0],
            json!({"name": "Rest Target One", "uuid": fx::target_id(1), "action": "update", "status": "updated"})
        );
        let puts = f.server.rt_requests(Rt::TargetUpdate);
        assert_eq!(puts.len(), 4);
        assert_eq!(
            puts[0].line(),
            format!(
                "PUT /redteam/mgmt/v1/target/{}?validate=true",
                fx::target_id(1)
            )
        );
        assert_eq!(
            f.server.rt_requests(Rt::TargetGet).len(),
            4,
            "the current target first"
        );
    }

    /// `--dry-run` prints the plan and writes nothing.
    #[test]
    fn a_dry_run_writes_nothing() {
        let f = fx();
        let (_, text) = backup(&f);
        f.server.redteam(|data| {
            data.targets.remove(0);
        });
        let out = f.rt(&[
            "targets",
            "restore",
            "--file",
            &text,
            "--dry-run",
            "--overwrite",
        ]);
        out.assert_success();
        assert_eq!(
            out.stdout,
            format!(
                "{BACKUP_BANNER}\n  Restore results:\n\n  • Rest Target One — would create\n  • Native/OpenAI ✓ — would update\n  • Bedrock Target — would update\n  • Adapter Target — would update\n\n  Total: 1 would create, 3 would update\n\n"
            )
        );
        assert!(
            f.api().iter().all(|line| line.starts_with("GET ")),
            "{:?}",
            f.api()
        );
    }

    /// Rules 1–3 are failed rows before any write; exit 1 after the summary.
    #[test]
    fn duplicates_ambiguous_names_and_withheld_credentials_are_refused() {
        let f = fx();
        let (path, text) = backup(&f);
        let mut doc = read_json(&path);
        let targets = doc["targets"].as_array_mut().unwrap();
        targets[2]["target"]["auth_config"]["basic_auth_header"]["Authorization"] =
            json!("[REDACTED]");
        targets[3]["target"]["adapter_variable_overrides"][1]["value"] = json!("**********");
        let twin = targets[0].clone();
        targets.push(twin);
        let edited = f.sandbox.tmp().join("edited.json");
        std::fs::write(&edited, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
        let _ = text;
        f.server.redteam(|data| {
            let mut twin = fx::openai_target(6, "Native/OpenAI ✓");
            twin["uuid"] = json!(fx::target_id(6));
            data.targets.push(twin);
        });
        let out = f.rt(&[
            "targets",
            "restore",
            "--file",
            &edited.display().to_string(),
        ]);
        out.assert_code(1);
        assert_eq!(
            out.stdout,
            format!(
                "{BACKUP_BANNER}\n  Restore results:\n\n  ✗ Rest Target One — failed: the backup holds more than one target named Rest Target One\n  ✗ Native/OpenAI ✓ — failed: more than one target named Native/OpenAI ✓ exists\n  ✗ Bedrock Target — failed: {WITHHELD_REASON}\n  ✗ Adapter Target — failed: {WITHHELD_REASON}\n  ✗ Rest Target One — failed: the backup holds more than one target named Rest Target One\n\n  Total: 5 failed\n\n"
            )
        );
        assert!(!out.stderr.contains("✗"), "no error block");
        assert!(f.api().iter().all(|line| line.starts_with("GET ")));
    }

    /// A rejected write is that row's failure and the run continues (TS "collects
    /// errors"); an unknown outcome stops it: one POST, later rows not attempted.
    #[test]
    fn rejections_continue_and_an_unknown_outcome_stops() {
        let f = fx();
        let (_, text) = backup(&f);
        f.server.redteam(|data| data.targets.clear());
        f.server.push_once(
            Route::RedTeam(Rt::TargetCreate),
            Planned::json(422, &json!({"detail": [{"msg": "PRIVATE"}]})),
        );
        f.server
            .push_once(Route::RedTeam(Rt::TargetCreate), Planned::builtin());
        f.server.push_once(
            Route::RedTeam(Rt::TargetCreate),
            Planned::json(503, &json!({})).with_retry_after(0),
        );
        let out = f.rt(&["targets", "restore", "--file", &text]);
        out.assert_code(1);
        assert!(
            out.stdout
                .contains("  ✗ Rest Target One — failed: AISEC_CLIENT_SIDE_ERROR:API error 422"),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("  ✓ Native/OpenAI ✓ — created\n"));
        assert!(
            out.stdout
                .contains("  ✗ Bedrock Target — outcome unknown: "),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("  ○ Adapter Target — not attempted\n"));
        assert!(
            out.stdout.ends_with(
                "\n  Total: 1 created, 1 failed, 1 outcome unknown, 1 not attempted\n\n"
            ),
            "{}",
            out.stdout
        );
        assert_eq!(
            f.server.rt_requests(Rt::TargetCreate).len(),
            3,
            "never re-sent (D133)"
        );
        assert!(!out.stdout.contains("PRIVATE"));
    }

    /// A service that ignores `skip` repeats the first page: the listing is the D37
    /// pagination error, so nothing is planned or written (no duplicate targets).
    #[test]
    fn a_repeated_listing_page_writes_nothing() {
        let f = fx();
        let (_, text) = backup(&f);
        let rows: Vec<Value> = f.server.redteam_data().targets[..2].to_vec();
        for _ in 0..2 {
            f.server.push_once(
                Route::RedTeam(Rt::TargetList),
                Planned::json(
                    200,
                    &json!({"data": rows, "pagination": {"total_items": 4}}),
                ),
            );
        }
        let out = f.rt(&["targets", "restore", "--file", &text]);
        out.assert_code(1);
        assert!(
            out.stderr.contains("Pagination stopped: the service returned a repeated cursor or an empty intermediate page"),
            "{}",
            out.stderr
        );
        assert_eq!(out.stdout, "");
        assert!(f.server.rt_requests(Rt::TargetCreate).is_empty());
        assert!(f.server.rt_requests(Rt::TargetUpdate).is_empty());
        assert_eq!(f.server.redteam_data().targets.len(), 4);
    }

    /// A last write whose answer cannot be read: the row says the target was created but
    /// the answer was unreadable, and the run exits 1 (§15.3), as it does for an earlier
    /// row.
    #[test]
    fn an_unreadable_last_write_exits_1() {
        let f = fx();
        let (_, text) = backup(&f);
        f.server.redteam(|data| data.targets.clear());
        for _ in 0..3 {
            f.server
                .push_once(Route::RedTeam(Rt::TargetCreate), Planned::builtin());
        }
        f.server.push_once(
            Route::RedTeam(Rt::TargetCreate),
            Planned::raw(201, "application/json", "{not json"),
        );
        let out = f.rt(&["targets", "restore", "--file", &text]);
        out.assert_code(1);
        assert!(
            out.stdout.contains("  ✓ Adapter Target — created: Outcome: the target was created, but the response could not be read.\n"),
            "{}",
            out.stdout
        );
        assert!(
            out.stdout.ends_with("\n  Total: 4 created\n\n"),
            "{}",
            out.stdout
        );
        assert_eq!(f.server.rt_requests(Rt::TargetCreate).len(), 4);
    }

    /// The file rules (before the tenant, zero requests): TypeScript backups refused
    /// (D152), a newer version, malformed JSON, schema breaks, the size cap.
    #[test]
    fn foreign_and_broken_files_are_refused_before_the_tenant() {
        let f = fx();
        let file = |name: &str, bytes: &[u8]| {
            let path = f.sandbox.tmp().join(name);
            std::fs::write(&path, bytes).unwrap();
            path.display().to_string()
        };
        let ts = file(
            "ts.json",
            br#"{"version": "1", "resourceType": "redteam-target", "exportedAt": "2026-01-01T00:00:00.000Z", "data": {"name": "x", "target_type": "APPLICATION"}}"#,
        );
        let newer = file(
            "newer.json",
            br#"{"format": "airs-cli-rs.redteam-targets", "version": 2}"#,
        );
        let broken = file("broken.json", b"{\"format\": ");
        let ts_yaml = file(
            "ts.yaml",
            b"version: '1'\nresourceType: redteam-target\nexportedAt: '2026-01-01T00:00:00.000Z'\ndata:\n  name: x\n",
        );
        let foreign = file("foreign.json", br#"{"format": "other"}"#);
        let big = f.sandbox.tmp().join("big.json");
        std::fs::write(&big, vec![b' '; 16 * 1_048_576 + 1]).unwrap();
        let big = big.display().to_string();
        let missing = f.sandbox.tmp().join("missing.json").display().to_string();
        for (path, message) in [
            (
                &ts,
                format!(
                    "{ts} is a TypeScript airs-cli backup; airs cannot restore it. Restore it with the TypeScript airs-cli, or back the targets up again with 'airs redteam targets backup'."
                ),
            ),
            (
                &ts_yaml,
                format!(
                    "{ts_yaml} is a TypeScript airs-cli backup; airs cannot restore it. Restore it with the TypeScript airs-cli, or back the targets up again with 'airs redteam targets backup'."
                ),
            ),
            (
                &newer,
                format!(
                    "{newer} was written by a newer version of airs; upgrade airs to restore it"
                ),
            ),
            (
                &broken,
                format!("Invalid red team target backup {broken}: malformed JSON"),
            ),
            (
                &foreign,
                format!(
                    "Invalid red team target backup {foreign}: it is not an airs red team target backup"
                ),
            ),
            (
                &big,
                format!(
                    "Cannot read {big} (missing, not a regular file, unreadable or larger than 16 MiB)"
                ),
            ),
            (
                &missing,
                format!(
                    "Cannot read {missing} (missing, not a regular file, unreadable or larger than 16 MiB)"
                ),
            ),
        ] {
            let out = f.rt(&["targets", "restore", "--file", path]);
            out.assert_code(1);
            assert!(
                out.stderr.contains(&format!("✗ Error: {message}")),
                "{}",
                out.stderr
            );
        }
        assert_eq!(f.server.request_count(), 0);
    }

    /// Another TSG is refused before any request unless `--allow-other-tenant`; an
    /// incomplete backup warns.
    #[test]
    fn another_tsg_and_an_incomplete_backup() {
        let f = fx();
        let (path, _) = backup(&f);
        let mut doc = read_json(&path);
        doc["tsgId"] = json!("999");
        doc["complete"] = json!(false);
        doc["failed"] =
            json!([{"uuid": fx::target_id(9), "name": "lost", "error": "AISEC_SDK_ERROR:x"}]);
        let edited = f.sandbox.tmp().join("other.json");
        std::fs::write(&edited, serde_json::to_string(&doc).unwrap()).unwrap();
        let shown = edited.display().to_string();
        let out = f.rt(&["targets", "restore", "--file", &shown]);
        out.assert_code(1);
        assert!(
            out.stderr.starts_with(&format!(
                "  ⚠ {shown} is incomplete: 1 target(s) could not be backed up\n"
            )),
            "{}",
            out.stderr
        );
        assert!(out.stderr.contains(&format!(
            "✗ Error: {shown} was exported from TSG 999; the selected tenant uses TSG 100. Pass --allow-other-tenant to restore it here."
        )), "{}", out.stderr);
        assert_eq!(f.server.request_count(), 0);
        let out = f.rt(&[
            "targets",
            "restore",
            "--file",
            &shown,
            "--allow-other-tenant",
        ]);
        out.assert_success();
        assert!(out.stdout.ends_with("\n  Total: 4 skipped\n\n"));
    }

    /// The argument checks and the non-interactive `--overwrite` refusal (D137): exit 2,
    /// no request.
    #[test]
    fn argument_checks_d137() {
        let f = fx();
        for (args, message) in [
            (vec!["targets", "restore"], "Specify --file <path>"),
            (
                vec!["targets", "restore", "--file", ""],
                "Specify --file <path>",
            ),
            (
                vec!["targets", "restore", "--input-dir", "x"],
                "--input-dir is not supported: an airs backup is one file; pass --file <backup>",
            ),
            (
                vec!["targets", "restore", "--file", "x", "--dry-run", "--force"],
                "--dry-run cannot be combined with --force",
            ),
            (
                vec!["targets", "restore", "--file", "x", "--overwrite"],
                "refusing to overwrite targets without --force in non-interactive mode",
            ),
        ] {
            let out = f.rt(&args);
            out.assert_code(2);
            assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
        }
        assert_eq!(f.server.request_count(), 0);
    }

    fn pty_restore(f: &Fx, text: &str, answer: &[u8]) -> PtyRun {
        let mut session = spawn_pty(
            &rust(),
            &f.sandbox,
            &[
                "redteam",
                "targets",
                "restore",
                "--file",
                text,
                "--overwrite",
            ],
            &RunOptions::new(),
        );
        session.expect(&format!(
            "? Overwrite 4 existing targets with the settings in {text}? (y/N) "
        ));
        session.send(answer);
        session.wait()
    }

    /// The confirmation on a terminal: `y` updates; `n` declines with nothing written.
    #[test]
    fn the_overwrite_confirmation_on_a_terminal_d137() {
        let f = fx();
        let (_, text) = backup(&f);
        let out = pty_restore(&f, &text, b"y\n");
        out.run.assert_success();
        assert_eq!(f.server.rt_requests(Rt::TargetUpdate).len(), 4);
        let f = fx();
        let (_, text) = backup(&f);
        let out = pty_restore(&f, &text, b"n\n");
        out.run.assert_success();
        assert!(transcript(&out).contains("  ℹ Aborted\n"));
        assert!(f.server.rt_requests(Rt::TargetUpdate).is_empty());
    }

    /// A signal during a held create: the counts so far, exit 130, the write not re-sent.
    #[test]
    fn an_interruption_reports_the_counts() {
        let f = fx();
        let (_, text) = backup(&f);
        f.server.redteam(|data| data.targets.clear());
        f.server
            .push_once(Route::RedTeam(Rt::TargetCreate), Planned::builtin());
        f.server
            .push_once(Route::RedTeam(Rt::TargetCreate), Planned::held());
        let running = spawn(
            &rust(),
            &f.sandbox,
            &["redteam", "targets", "restore", "--file", &text],
            &RunOptions::new().expect_signal(),
        );
        assert!(f.server.wait_for_route(
            Route::RedTeam(Rt::TargetCreate),
            2,
            Duration::from_secs(20)
        ));
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert!(
            out.stderr.ends_with("\n  ✗ Error: Interrupted; 1 created, 0 updated, 1 outcome unknown, 2 not attempted\n\n"),
            "{}",
            out.stderr
        );
        assert_eq!(f.server.rt_requests(Rt::TargetCreate).len(), 2);
    }
}

// ---------------------------------------------------------------------------
// The vendor 0.93.0 contract of scm-sdk 0.2.2 (D301, D303, DESIGN §15.23)
// ---------------------------------------------------------------------------

mod contract {
    use super::*;

    /// With `--attacks`, `--limit` above 100 and a `--severity` outside the vendor enum
    /// (`""` included) are usage errors before the tenant: no tenant, no request. The
    /// message names the flag, never the value.
    #[test]
    fn attack_list_values_are_checked_before_the_tenant() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let job = fx::job_id(1);
        let severities = "--severity must be one of LOW, MEDIUM, HIGH, CRITICAL";
        for (args, message) in [
            (
                vec!["report", &job, "--attacks", "--limit", "101"],
                "--limit must be at most 100 (the red team API maximum)",
            ),
            (
                vec!["dashboard", &job, "--attacks", "--limit", "1000"],
                "--limit must be at most 100 (the red team API maximum)",
            ),
            (
                vec!["report", &job, "--attacks", "--limit", "0"],
                "--limit must be a positive integer",
            ),
            (
                vec!["report", &job, "--attacks", "--severity", "high"],
                severities,
            ),
            (
                vec!["report", &job, "--attacks", "--severity", "SECRET-VALUE"],
                severities,
            ),
            (
                vec!["report", &job, "--attacks", "--severity", ""],
                severities,
            ),
            (
                vec!["report", &job, "--attacks", "--severity", "HI\u{7}GH"],
                "--severity must be at most 4096 bytes and contain no control characters",
            ),
            // The job id is checked first (D141).
            (
                vec!["report", "job-1", "--attacks", "--limit", "101"],
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: job-1",
            ),
        ] {
            let full = rt(&args);
            let full: Vec<&str> = full.iter().map(String::as_str).collect();
            let out = run(&rust(), &sandbox, &full, &RunOptions::new());
            out.assert_code(2);
            assert_eq!(out.stdout, "", "{args:?}");
            assert_eq!(out.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
            assert_eq!(server.request_count(), 0, "{args:?}");
        }
    }

    /// The boundaries are sent (`--limit 100`, each severity); without `--attacks` the
    /// values are unused and accepted as before (TS parity, §15.16).
    #[test]
    fn the_contract_boundaries_are_sent_and_unused_values_accepted() {
        let f = fx();
        let job = fx::job_id(1);
        f.rt(&[
            "report",
            &job,
            "--attacks",
            "--limit",
            "100",
            "--output",
            "json",
        ])
        .assert_success();
        let mut expected = vec![
            format!("GET /redteam/data/v1/scan/{job}"),
            format!("GET /redteam/data/v1/report/static/{job}/report"),
            format!("GET /redteam/data/v1/report/static/{job}/list-attacks?limit=100"),
        ];
        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] {
            f.rt(&[
                "report",
                &job,
                "--attacks",
                "--severity",
                severity,
                "--output",
                "json",
            ])
            .assert_success();
            expected.extend([
                format!("GET /redteam/data/v1/scan/{job}"),
                format!("GET /redteam/data/v1/report/static/{job}/report"),
                format!(
                    "GET /redteam/data/v1/report/static/{job}/list-attacks?limit=20&severity={severity}"
                ),
            ]);
        }
        let out = f.rt(&[
            "report",
            &job,
            "--limit",
            "1000",
            "--severity",
            "",
            "--output",
            "json",
        ]);
        out.assert_success();
        assert!(out.json().get("attacks").is_none());
        expected.extend([
            format!("GET /redteam/data/v1/scan/{job}"),
            format!("GET /redteam/data/v1/report/static/{job}/report"),
        ]);
        assert_eq!(f.api(), expected);
    }
}

// ---------------------------------------------------------------------------
// G25 closed (scm-sdk 0.2.2, DESIGN §15 G25, §15.23)
// ---------------------------------------------------------------------------

mod g25 {
    use super::*;

    /// Attack lists whose rows carry non-UUID ids (`p-1`, `map-1`, `atk-1`, `job-1`,
    /// `t-1`, `cp-1`) and an unlisted severity are read and printed unchanged (scm-sdk
    /// 0.2.0 refused these answers, G25).
    #[test]
    fn attack_lists_keep_opaque_ids() {
        let f = fx();
        let job = fx::job_id(1);
        let custom = fx::job_id(3);
        f.server.redteam(|data| {
            let mut attack = fx::attack(1, Some("EXTREME"), Some(true), "Jailbreak");
            attack["uuid"] = json!("atk-1");
            attack["job_id"] = json!("job-1");
            attack["target_id"] = json!("t-1");
            attack["prompt_id"] = json!("p-1");
            attack["prompt_mapping_id"] = json!("map-1");
            data.attacks.insert(job.clone(), vec![attack]);
            data.scans.push(fx::custom_job());
            let mut rows = fx::custom_attacks();
            // Only the opaque-id row, with its own text, so the output can be traced to it.
            let mut row = rows.swap_remove(0);
            row["prompt_id"] = json!("cp-1");
            row["prompt_set_id"] = json!("set-1");
            row["prompt_text"] = json!("opaque-id prompt");
            data.custom_attacks.insert(custom.clone(), vec![row]);
        });
        let out = f.rt(&["report", &job, "--attacks", "--output", "json"]);
        out.assert_success();
        assert_eq!(
            out.json()["attacks"]["items"],
            json!([{"id": "atk-1", "name": "attack-1", "severity": "EXTREME", "category": "SECURITY", "subCategory": "JAILBREAK", "subCategoryDisplayName": "Jailbreak", "successful": true}])
        );
        let pretty = f.rt(&["report", &job, "--attacks"]);
        pretty.assert_success();
        assert!(
            pretty
                .stdout
                .contains("\n  Attacks:\n\n    EXTREME    BYPASSED  Jailbreak [SECURITY]\n"),
            "{}",
            pretty.stdout
        );
        let out = f.rt(&["report", &custom, "--attacks", "--output", "json"]);
        out.assert_success();
        assert_eq!(
            out.json()["attacks"]["items"],
            json!([{"promptId": "cp-1", "promptText": "opaque-id prompt", "goal": "Leak", "threat": true, "asr": 50, "promptSetName": "fixture-set"}])
        );
        let out = f.rt(&["report", &custom, "--attacks"]);
        out.assert_success();
        assert!(
            out.stdout.ends_with(
                "\n  Custom Attacks:\n\n    THREAT ASR: 50.0%  opaque-id prompt\n      Leak\n\n"
            ),
            "{}",
            out.stdout
        );
    }
}

// ---------------------------------------------------------------------------
// Management 0.86.0 (scm-sdk 0.2.3, DESIGN §15.24)
// ---------------------------------------------------------------------------

mod management_0_86 {
    use super::*;

    /// D329 (backup and restore): a Vertex AI realtime target and an n8n target with
    /// audio templates are stored whole and recreated with the stored bodies, the 0.86.0
    /// values included. 0.11 (scm-sdk 0.2.2) refused both: the Vertex AI read failed,
    /// and the n8n target, which it read, was the failed row `its settings do not match
    /// the target create schema`, because its 0.2.2 create schema refused `N8N`.
    #[test]
    fn a_backup_stores_the_0_86_targets_and_restore_recreates_them() {
        let f = fx();
        f.server.redteam(|data| {
            data.targets = vec![
                fx::vertex_target(1, "Vertex Realtime"),
                fx::audio_target(2, "n8n Audio"),
            ];
        });
        let dir = f.sandbox.tmp().join("b");
        std::fs::create_dir_all(&dir).unwrap();
        let dir_text = dir.display().to_string();
        let out = f.rt(&["targets", "backup", "--output-dir", &dir_text]);
        out.assert_success();
        let path = backup_file(&dir);
        assert!(
            out.stdout.contains("  ✓ Vertex Realtime\n  ✓ n8n Audio\n"),
            "{}",
            out.stdout
        );
        assert!(
            out.stderr.contains("contains target credentials"),
            "{}",
            out.stderr
        );
        let doc = read_json(&path);
        assert_eq!(doc["complete"], true);
        let vertex = &doc["targets"][0];
        assert_eq!(vertex["credentialsWithheld"], false);
        let stored = &vertex["target"];
        assert_eq!(stored["connection_type"], "VERTEX_AI");
        assert_eq!(stored["response_mode"], "REALTIME");
        assert_eq!(
            stored["connection_params"]["target_connection_config"],
            fx::vertex_connection_config()
        );
        assert_eq!(
            stored["connection_params"]["multi_turn_config"],
            json!({"type": "client_session"})
        );
        assert_eq!(stored["auth_config"]["basic_password"], fx::secret(33));
        assert_eq!(
            doc["targets"][1]["target"]["connection_params"]["audio_curl"],
            fx::audio_target(2, "n8n Audio")["connection_params"]["audio_curl"]
        );

        f.clear();
        f.server.redteam(|data| data.targets.clear());
        let text = path.display().to_string();
        let out = f.rt(&["targets", "restore", "--file", &text]);
        out.assert_success();
        assert!(
            out.stdout
                .contains("  ✓ Vertex Realtime — created\n  ✓ n8n Audio — created\n"),
            "{}",
            out.stdout
        );
        let posted: Vec<Value> = f
            .server
            .rt_requests(Rt::TargetCreate)
            .iter()
            .map(|request| request.body_json().unwrap())
            .collect();
        assert_eq!(posted.len(), 2);
        for (body, entry) in posted.iter().zip(doc["targets"].as_array().unwrap()) {
            assert_eq!(body, &entry["target"], "{body}");
        }
    }

    /// D329 (backup): a target whose answer carries only a 0.86.0 vocabulary value
    /// (`N8N`, `REALTIME`, or `VERTEX_AI` without a Vertex AI config) is read by both SDKs,
    /// but 0.11's create schema refused its projection, so 0.11 recorded the failed row
    /// `its settings do not match the target create schema` and exited 1. From 1.0 the
    /// widened create schema accepts it: each is stored and the backup is complete
    /// (exit 0).
    #[test]
    fn a_target_with_only_the_0_86_vocabulary_is_stored() {
        let f = fx();
        f.server.redteam(|data| {
            let mut n8n = fx::rest_target(1, "N8n Realtime");
            n8n["connection_type"] = json!("N8N");
            n8n["response_mode"] = json!("REALTIME");
            let mut realtime = fx::rest_target(2, "Custom Realtime");
            realtime["response_mode"] = json!("REALTIME");
            let mut vertex = fx::rest_target(3, "Vertex Plain");
            vertex["connection_type"] = json!("VERTEX_AI");
            data.targets = vec![n8n, realtime, vertex];
        });
        let get = f.rt(&["targets", "get", &fx::target_id(1), "--output", "json"]);
        get.assert_success();
        assert_eq!(get.json()["responseMode"], "REALTIME");
        let dir = f.sandbox.tmp().join("b");
        std::fs::create_dir_all(&dir).unwrap();
        let dir_text = dir.display().to_string();
        let out = f.rt(&["targets", "backup", "--output-dir", &dir_text]);
        out.assert_success();
        assert!(
            out.stdout
                .contains("  ✓ N8n Realtime\n  ✓ Custom Realtime\n  ✓ Vertex Plain\n"),
            "{}",
            out.stdout
        );
        assert!(!out.stdout.contains("Failed"), "{}", out.stdout);
        assert!(
            out.stderr.contains("contains target credentials"),
            "{}",
            out.stderr
        );
        let doc = read_json(&backup_file(&dir));
        assert_eq!(doc["complete"], true);
        assert_eq!(doc["failed"], json!([]));
        let stored: Vec<(&Value, &Value)> = doc["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    &entry["target"]["connection_type"],
                    &entry["target"]["response_mode"],
                )
            })
            .collect();
        assert_eq!(
            stored,
            vec![
                (&json!("N8N"), &json!("REALTIME")),
                (&json!("CUSTOM"), &json!("REALTIME")),
                (&json!("VERTEX_AI"), &json!("REST")),
            ]
        );
    }

    /// A Vertex AI target whose answer masks a patterned field cannot be sent back: its
    /// projection fails the management 0.86.0 request patterns, so the backup records it
    /// as a failed row (a stored entry would make the whole file unrestorable) whose
    /// reason names the masked fields and the remedy (§15.24 choice 13), in json and
    /// pretty; a field outside its pattern that is not a mask, alone or beside a mask,
    /// keeps the §15.18 reason. A mask in the unpatterned `customer_sa_email` is stored
    /// and marked withheld (D157). The Vertex AI identifiers are never registered
    /// (choice 12), so a target named after its location prints its name, not
    /// `[withheld]`.
    #[test]
    fn a_masked_vertex_target_is_failed_or_withheld() {
        let f = fx();
        f.server.redteam(|data| {
            let vertex = |n: u64, name: &str, fields: &[(&str, &str)]| {
                let mut target = fx::vertex_target(n, name);
                for (field, value) in fields {
                    target["connection_params"]["target_connection_config"][*field] = json!(value);
                }
                target
            };
            data.targets = vec![
                vertex(1, "Masked Project", &[("project_id", "****")]),
                vertex(2, "Masked Email", &[("customer_sa_email", "********")]),
                vertex(
                    3,
                    "Masked Engine",
                    &[("location", "****"), ("engine_id", "******")],
                ),
                vertex(4, "us-central1", &[("engine_id", "engine-1")]),
                vertex(
                    5,
                    "Masked And Odd",
                    &[("project_id", "****"), ("engine_id", "engine-1")],
                ),
            ];
        });
        let masked = |names: &str| {
            format!(
                "the service masked its Vertex AI {names}, which the target create schema refuses; recreate the target or set its identifiers by hand"
            )
        };
        let schema = "its settings do not match the target create schema";
        let dir = f.sandbox.tmp().join("b");
        std::fs::create_dir_all(&dir).unwrap();
        let dir_text = dir.display().to_string();
        let out = f.rt(&[
            "targets",
            "backup",
            "--output-dir",
            &dir_text,
            "--output",
            "json",
        ]);
        out.assert_code(1);
        let doc = out.json();
        assert_eq!(doc["backedUp"], 1);
        assert_eq!(
            doc["failed"],
            json!([
                {"uuid": fx::target_id(1), "name": "Masked Project", "error": masked("project_id")},
                {"uuid": fx::target_id(3), "name": "Masked Engine", "error": masked("location and engine_id")},
                {"uuid": fx::target_id(4), "name": "us-central1", "error": schema},
                {"uuid": fx::target_id(5), "name": "Masked And Odd", "error": schema}
            ])
        );
        assert_eq!(
            doc["targets"],
            json!([{"uuid": fx::target_id(2), "name": "Masked Email", "credentialsWithheld": true}])
        );
        // Pretty: the same rows under the summary's `Failed` section.
        let out = f.rt(&["targets", "backup", "--output-dir", &dir_text]);
        out.assert_code(1);
        let block = format!(
            "\n  Failed (4):\n\n  ✗ Masked Project: {}\n  ✗ Masked Engine: {}\n  ✗ us-central1: {schema}\n  ✗ Masked And Odd: {schema}\n\n",
            masked("project_id"),
            masked("location and engine_id"),
        );
        assert!(out.stdout.contains(&block), "{}", out.stdout);
        assert!(!out.stdout.contains("[withheld]"), "{}", out.stdout);
    }

    /// The backup's credentials warning counts only credentials the service returned
    /// (§15.18): a Vertex AI target without basic credentials or an audio template, whose
    /// only returned config values are the identifiers, gets none (choice 12; the first 1.0
    /// chunk's length rule registered them), while a returned `customer_sa_email` still
    /// counts.
    #[test]
    fn the_credentials_warning_ignores_the_vertex_identifiers() {
        for (email, warned) in [
            ("********", false),
            ("service@example-project.iam.invalid", true),
        ] {
            let f = fx();
            f.server.redteam(|data| {
                let mut target = fx::vertex_target(1, "Vertex Plain Config");
                let entries = target.as_object_mut().unwrap();
                entries.remove("auth_config");
                entries.remove("auth_type");
                let params = target["connection_params"].as_object_mut().unwrap();
                params.remove("audio_curl");
                params["target_connection_config"]["customer_sa_email"] = json!(email);
                data.targets = vec![target];
            });
            let dir = f.sandbox.tmp().join("b");
            std::fs::create_dir_all(&dir).unwrap();
            let dir_text = dir.display().to_string();
            let out = f.rt(&["targets", "backup", "--output-dir", &dir_text]);
            out.assert_success();
            assert_eq!(
                out.stderr.contains("contains target credentials"),
                warned,
                "{email}: {}",
                out.stderr
            );
            let doc = read_json(&backup_file(&dir));
            assert_eq!(doc["targets"][0]["credentialsWithheld"], !warned, "{email}");
            assert_eq!(
                doc["targets"][0]["target"]["connection_params"]["target_connection_config"]["project_id"],
                "example-project"
            );
        }
    }
}
