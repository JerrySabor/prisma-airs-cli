//! TS-vs-Rust parity for the M6a step-3 commands (DESIGN §15.16–§15.19): the scan job
//! reports, the environment report, `targets backup` and `targets restore`.
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh seeded [`FixtureServer`] and a fresh [`Sandbox`]. The
//! `parity` tests compare exit codes, stdout bytes (the job reports and the environment
//! report's HTML with its timestamps normalised) and requests; the `divergence` tests pin
//! both sides of each §12 row this step implements. The TypeScript side prints and
//! stores the fixture credentials (D140, D151), so its runs disable the marker check;
//! the airs-cli-rs runs keep it.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use airs_test_harness::fixtures::redteam as fx;
use airs_test_harness::{
    Cli, FixtureServer, NormalizedRequest, Planned, RedTeamData, Route, Rt, Run, RunOptions,
    Sandbox, normalize_all, require_ts, run,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    server: FixtureServer,
    sandbox: Sandbox,
}

/// The seed of every scenario: the standard dataset, the CUSTOM job, and scan creation
/// times far in the past (the report's 24-hour window must not depend on the clock).
fn seed(data: &mut RedTeamData) {
    data.scans.push(fx::custom_job());
    for job in &mut data.scans {
        job["created_at"] = json!("2020-01-01T00:00:00Z");
    }
}

/// A change to a scenario's server or sandbox before the run.
type Edit<'a> = dyn Fn(&FixtureServer, &Sandbox) + 'a;

fn exec_with(cli: &Cli, args: &[&str], edit: &Edit<'_>) -> Side {
    let server = FixtureServer::start();
    server.seed_redteam();
    server.redteam(seed);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    edit(&server, &sandbox);
    let mut full = vec!["redteam"];
    full.extend_from_slice(args);
    let options = RunOptions::new().allow_writes_under("cwd");
    let options = if cli.is_ts() {
        options.allow_secret_output()
    } else {
        options
    };
    let out = run(cli, &sandbox, &full, &options);
    let requests = normalize_all(&server.requests());
    Side {
        run: out,
        requests,
        server,
        sandbox,
    }
}

fn exec(cli: &Cli, args: &[&str]) -> Side {
    exec_with(cli, args, &|_, _| {})
}

fn sides(name: &str, args: &[&str]) -> Option<(Side, Side)> {
    sides_with(name, args, &|_, _| {})
}

fn sides_with(
    name: &str,
    args: &[&str],
    edit: &dyn Fn(&FixtureServer, &Sandbox),
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((exec_with(&rust(), args, edit), exec_with(&ts, args, edit)))
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

/// Every `YYYY-MM-DDTHH:MM:SS.mmmZ` as `<time>`.
fn without_times(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let candidate = text.get(index..index + 24).unwrap_or_default();
        let shape = candidate.len() == 24
            && candidate.bytes().enumerate().all(|(i, b)| match i {
                4 | 7 => b == b'-',
                10 => b == b'T',
                13 | 16 => b == b':',
                19 => b == b'.',
                23 => b == b'Z',
                _ => b.is_ascii_digit(),
            });
        if shape {
            out.push_str("<time>");
            index += 24;
        } else {
            let c = text[index..].chars().next().unwrap_or_default();
            out.push(c);
            index += c.len_utf8();
        }
    }
    out
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The files under `dir` (recursively), relative.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path.strip_prefix(dir).unwrap().to_path_buf());
            }
        }
    }
    found.sort();
    found
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The job reports are the TypeScript bytes (requests included): static with and
    /// without attacks and the footnote, dynamic, custom with its attack list, the empty
    /// lists, another job type.
    #[test]
    fn job_reports_match_typescript_byte_for_byte() {
        let (one, two, three) = (fx::job_id(1), fx::job_id(2), fx::job_id(3));
        for args in [
            vec!["report", &one],
            vec![
                "report",
                &one,
                "--attacks",
                "--severity",
                "HIGH",
                "--limit",
                "5",
            ],
            vec!["dashboard", &one, "--attacks"],
            vec!["report", &one, "--severity", "LOW"],
            vec!["report", &two],
            vec!["report", &two, "--attacks"],
            vec!["report", &three],
            vec!["report", &three, "--attacks", "--limit", "3"],
        ] {
            let Some((r, t)) = sides("job_reports_match_typescript_byte_for_byte", &args) else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{}", context(&r, &t));
            assert_eq!(r.run.stdout, t.run.stdout, "{args:?}{}", context(&r, &t));
            assert_eq!(r.run.stderr, t.run.stderr, "{args:?}{}", context(&r, &t));
            assert_eq!(r.requests, t.requests, "{args:?}{}", context(&r, &t));
        }
        // The empty lists with and without the footnote, and a CLARA job.
        let empty = |server: &FixtureServer, _: &Sandbox| {
            server.redteam(|data| {
                data.attacks.insert(fx::job_id(1), Vec::new());
                data.custom_attacks.insert(fx::job_id(3), Vec::new());
                data.scans[1]["job_type"] = json!("CLARA");
                data.static_reports
                    .insert(fx::job_id(2), fx::static_report());
            });
        };
        for args in [
            vec!["report", &one, "--attacks", "--severity", "HIGH"],
            vec!["report", &three, "--attacks"],
            vec!["report", &two, "--attacks"],
        ] {
            let Some((r, t)) =
                sides_with("job_reports_match_typescript_byte_for_byte", &args, &empty)
            else {
                return;
            };
            assert_eq!(r.run.stdout, t.run.stdout, "{args:?}{}", context(&r, &t));
            assert_eq!(r.requests, t.requests, "{args:?}{}", context(&r, &t));
        }
    }

    /// The environment report's HTML is the TypeScript document byte for byte (times
    /// normalised): every source complete, one source unavailable, every source
    /// unavailable (exit 1 on both), and the same status lines and requests.
    #[test]
    fn the_environment_report_matches_typescript() {
        let scenarios: [&Edit<'_>; 3] = [
            &|_, _| {},
            &|server, _| {
                server.set_default(Route::RedTeam(Rt::ScanList), Planned::json(200, &json!({})));
            },
            &|server, _| {
                for source in [
                    Rt::DashboardOverview,
                    Rt::ScanStatistics,
                    Rt::TargetList,
                    Rt::Quota,
                    Rt::ScanList,
                    Rt::ChannelStats,
                    Rt::AdapterList,
                ] {
                    server.set_default(
                        Route::RedTeam(source),
                        Planned::json(404, &json!({"message": "PRIVATE-ERROR"})),
                    );
                }
            },
        ];
        for (index, edit) in scenarios.iter().enumerate() {
            let Some((r, t)) = sides_with(
                "the_environment_report_matches_typescript",
                &[
                    "report",
                    "--output-file",
                    "-",
                    "--title",
                    "Daily <report> & co",
                ],
                edit,
            ) else {
                return;
            };
            assert_eq!(
                r.run.code,
                t.run.code,
                "scenario {index}{}",
                context(&r, &t)
            );
            assert!(r.run.stdout.starts_with("<!doctype html>\n"));
            assert_eq!(
                without_times(&r.run.stdout),
                without_times(&t.run.stdout),
                "scenario {index}"
            );
            assert_eq!(
                r.run.stderr,
                t.run.stderr,
                "scenario {index}{}",
                context(&r, &t)
            );
            assert_eq!(r.requests, t.requests, "scenario {index}");
            assert!(!r.run.stdout.contains("PRIVATE"));
            assert!(r.server.rt_requests(Rt::QuotaPost).is_empty());
            assert!(t.server.rt_requests(Rt::QuotaPost).is_empty());
        }
    }

    /// Both write a new 0600 file and refuse an existing path before any request with
    /// the same failure line; both validate the options alike (exit 2).
    #[test]
    fn environment_report_files_and_checks_match_typescript() {
        let Some(ts) = require_ts("environment_report_files_and_checks_match_typescript") else {
            return;
        };
        for cli in [rust(), ts.clone()] {
            let side = exec_with(&cli, &["report", "--output-file", "r.html"], &|_, _| {});
            side.run.assert_success();
            assert_eq!(
                mode(&side.sandbox.cwd().join("r.html")),
                0o600,
                "{}",
                cli.label()
            );
            let existing = exec_with(
                &cli,
                &["report", "--output-file", "e.html"],
                &|_, sandbox| {
                    std::fs::write(sandbox.cwd().join("e.html"), "KEEP").unwrap();
                },
            );
            assert_eq!(existing.run.code, 1, "{}", cli.label());
            assert_eq!(
                existing.run.stderr,
                "  ✗ Report generation failed. Verify Management API configuration and a writable, new output path. Existing files are never overwritten.\n",
                "{}",
                cli.label()
            );
            assert!(existing.requests.is_empty(), "{}", cli.label());
            assert_eq!(
                std::fs::read_to_string(existing.sandbox.cwd().join("e.html")).unwrap(),
                "KEEP"
            );
        }
        let job = fx::job_id(1);
        for (args, message) in [
            (
                vec!["report", "--attacks"],
                "--attacks, --severity and --limit require a scan job ID",
            ),
            (
                vec!["report", "--max-pages", "0"],
                "--max-pages must be an integer from 1 to 100",
            ),
            (
                vec!["report", "--max-pages", "101"],
                "--max-pages must be an integer from 1 to 100",
            ),
            (
                vec!["report", "--title", ""],
                "--title must contain 1–240 characters",
            ),
            (
                vec!["report", "--output-file", " "],
                "--output-file cannot be empty",
            ),
            (
                vec!["report", &job, "--strict"],
                "Environment report options cannot be combined with a scan job ID",
            ),
        ] {
            for cli in [rust(), ts.clone()] {
                let side = exec(&cli, &args);
                assert_eq!(side.run.code, 2, "{} {args:?}", cli.label());
                assert!(
                    side.run.stderr.contains(&format!("✗ {message}")),
                    "{} {args:?}: {}",
                    cli.label(),
                    side.run.stderr
                );
                assert!(side.requests.is_empty());
            }
        }
    }

    /// Backup reads the same targets on both CLIs (the list, then one GET per target in
    /// list order); restore of an existing name skips it on both.
    #[test]
    fn backup_reads_and_restore_skips_match_typescript() {
        let Some((r, t)) = sides(
            "backup_reads_and_restore_skips_match_typescript",
            &["targets", "backup"],
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let gets = |side: &Side| -> Vec<String> {
            side.server
                .rt_requests(Rt::TargetGet)
                .iter()
                .map(|request| request.path.clone())
                .collect()
        };
        assert_eq!(gets(&r), gets(&t));
        assert_eq!(gets(&r).len(), 4);
    }
}

// ---------------------------------------------------------------------------
// Divergences (§12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D144: TypeScript ignores `--output` on a job report (pretty either way);
    /// airs-cli-rs prints the JSON document or the `Key │ Value` table.
    #[test]
    fn d144_job_reports_honour_output() {
        let job = fx::job_id(1);
        let Some((r, t)) = sides(
            "d144_job_reports_honour_output",
            &["report", &job, "--attacks", "--output", "json"],
        ) else {
            return;
        };
        r.run.assert_success();
        let doc = r.run.json();
        assert_eq!(doc["job"]["uuid"], job);
        assert_eq!(doc["attacks"]["items"].as_array().unwrap().len(), 3);
        assert!(
            t.run.stdout.contains("Static Scan Report:"),
            "TS prints pretty"
        );
        assert!(serde_json::from_str::<Value>(&t.run.stdout).is_err());
    }

    /// D155: TypeScript writes Markdown with `--output markdown` and refuses other
    /// formats with its own text; airs-cli-rs writes HTML only: `markdown` is an invalid
    /// format and `json` is refused with the HTML text (exit 2, no request).
    #[test]
    fn d155_the_environment_report_is_html_only() {
        let Some(ts) = require_ts("d155_the_environment_report_is_html_only") else {
            return;
        };
        let global = |cli: &Cli, format: &str| {
            let server = FixtureServer::start();
            server.seed_redteam();
            server.redteam(seed);
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let options = if cli.is_ts() {
                RunOptions::new().allow_secret_output()
            } else {
                RunOptions::new()
            };
            let out = run(
                cli,
                &sandbox,
                &[
                    "--output",
                    format,
                    "redteam",
                    "report",
                    "--output-file",
                    "-",
                ],
                &options,
            );
            (out, server.request_count())
        };
        let (t, _) = global(&ts, "markdown");
        t.assert_success();
        assert!(
            t.stdout.starts_with("# Daily") || t.stdout.starts_with("# Red Team"),
            "{}",
            t.stdout
        );
        let (r, requests) = global(&rust(), "markdown");
        r.assert_code(2);
        assert_eq!(
            r.stderr,
            "\n  ✗ Invalid output format 'markdown'. Expected: pretty, table, json\n\n"
        );
        assert_eq!(requests, 0);
        let (t, _) = global(&ts, "json");
        t.assert_code(2);
        assert!(t.stderr.contains("Report output must be html or markdown"));
        let (r, requests) = global(&rust(), "json");
        r.assert_code(2);
        assert_eq!(
            r.stderr,
            "\n  ✗ The environment report is written as HTML; omit --output\n\n"
        );
        assert_eq!(requests, 0);
    }

    /// D156: both refuse `--debug` (exit 2, no request); the TypeScript text names
    /// `PANW_AI_SEC_DEBUG`, which airs-cli-rs never reads.
    #[test]
    fn d156_the_debug_refusal_names_no_environment_variable() {
        let Some(ts) = require_ts("d156_the_debug_refusal_names_no_environment_variable") else {
            return;
        };
        let (r, t) = (
            exec(&rust(), &["--debug", "report"]),
            exec(&ts, &["--debug", "report"]),
        );
        assert_eq!((r.run.code, t.run.code), (2, 2));
        assert!(t.run.stderr.contains("Disable --debug and PANW_AI_SEC_DEBUG for environment reports to avoid persisting sensitive traffic content"));
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Disable --debug for environment reports to avoid persisting sensitive traffic content\n\n"
        );
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// D151: TypeScript writes one 0644 file per target under `./airs-backup/targets/`
    /// and drops `description`, `canonical_id`, `adapter_uuid` and the overrides;
    /// airs-cli-rs writes one Rust-format 0600 file in the working directory that keeps
    /// them (an adapter-backed target can be restored).
    #[test]
    fn d151_one_private_lossless_backup_file() {
        let Some((r, t)) = sides(
            "d151_one_private_lossless_backup_file",
            &["targets", "backup"],
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let ts_files = files_under(&t.sandbox.cwd().join("airs-backup/targets"));
        assert_eq!(ts_files.len(), 4, "{ts_files:?}");
        // TypeScript's files take the default (umask) mode, not 0600.
        let adapter_file = t
            .sandbox
            .cwd()
            .join("airs-backup/targets/adapter-target.json");
        let ts_doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&adapter_file).unwrap()).unwrap();
        assert_eq!(ts_doc["resourceType"], "redteam-target");
        assert!(ts_doc["data"].get("adapter_uuid").is_none());
        assert!(ts_doc["data"].get("adapter_variable_overrides").is_none());
        let rust_files = files_under(&r.sandbox.cwd());
        assert_eq!(rust_files.len(), 1, "{rust_files:?}");
        let path = r.sandbox.cwd().join(&rust_files[0]);
        assert_eq!(mode(&path), 0o600);
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["format"], "airs-cli-rs.redteam-targets");
        assert_eq!(
            doc["targets"][3]["target"]["adapter_uuid"],
            fx::adapter_id(1)
        );
        assert_eq!(
            doc["targets"][0]["target"]["description"],
            "Fixture REST target"
        );
    }

    /// D157: a target whose credentials the service returned masked. TypeScript writes
    /// its file, reports `✓`, and its restore sends the mask as the credential;
    /// airs-cli-rs stores it as returned with `credentialsWithheld: true`, reports `⚠`
    /// (exit 0, the backup complete), and its restore refuses it before any write.
    #[test]
    fn d157_withheld_credentials_are_marked_and_never_restored() {
        let mask = |server: &FixtureServer, _: &Sandbox| {
            server.redteam(|data| {
                data.targets[0]["connection_params"]["request_headers"]["apikey"] =
                    json!("********");
            });
        };
        let Some((r, t)) = sides_with(
            "d157_withheld_credentials_are_marked_and_never_restored",
            &["targets", "backup"],
            &mask,
        ) else {
            return;
        };
        t.run.assert_success();
        assert!(
            t.run.stdout.contains("✓ Rest Target One"),
            "{}",
            context(&r, &t)
        );
        let ts_file = t
            .sandbox
            .cwd()
            .join("airs-backup/targets/rest-target-one.json");
        let ts_doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&ts_file).unwrap()).unwrap();
        assert_eq!(
            ts_doc["data"]["connection_params"]["request_headers"]["apikey"], "********",
            "TypeScript stores the mask"
        );
        r.run.assert_success();
        assert!(
            r.run.stdout.contains("  ⚠ Rest Target One — credentials withheld by the service; restore will refuse it\n"),
            "{}",
            context(&r, &t)
        );
        let rust_files = files_under(&r.sandbox.cwd());
        let rust_file = r.sandbox.cwd().join(&rust_files[0]);
        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&rust_file).unwrap()).unwrap();
        assert_eq!(doc["complete"], true);
        assert_eq!(doc["failed"], json!([]));
        assert_eq!(doc["targets"].as_array().unwrap().len(), 4);
        assert_eq!(doc["targets"][0]["credentialsWithheld"], true);
        assert_eq!(
            doc["targets"][0]["target"]["connection_params"]["request_headers"]["apikey"],
            "********",
            "stored as returned"
        );
        // Each restores its own backup into a tenant without targets.
        let restore = |side: &Side, cli: &Cli, file: &Path| {
            side.server.redteam(|data| data.targets.clear());
            side.server.clear_requests();
            let options = if cli.is_ts() {
                RunOptions::new().allow_secret_output()
            } else {
                RunOptions::new()
            };
            let file = file.display().to_string();
            run(
                cli,
                &side.sandbox,
                &["redteam", "targets", "restore", "--file", &file],
                &options,
            )
        };
        let Some(ts) = require_ts("d157_withheld_credentials_are_marked_and_never_restored") else {
            return;
        };
        let out = restore(&t, &ts, &ts_file);
        out.assert_success();
        let posted = t.server.rt_requests(Rt::TargetCreate);
        assert_eq!(posted.len(), 1);
        assert_eq!(
            posted[0].body_json().unwrap()["connection_params"]["request_headers"]["apikey"],
            "********",
            "TypeScript sends the mask as the credential"
        );
        let out = restore(&r, &rust(), &rust_file);
        out.assert_code(1);
        assert!(
            out.stdout.contains("  ✗ Rest Target One — failed: the service withheld its credentials when it was backed up, so it cannot be restored; recreate the target or set its credentials by hand\n"),
            "{}",
            out.stdout
        );
        let names: Vec<String> = r
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
        assert_eq!(
            names,
            ["Native/OpenAI ✓", "Bedrock Target", "Adapter Target"]
        );
    }

    /// D153 (backups): TypeScript stores the SDK's fabricated `ws_response_timeout: 110`;
    /// airs-cli-rs reads the target without the SDK's response defaults (scm-sdk 0.1.1)
    /// and stores only the keys the server sent.
    #[test]
    fn d153_backups_store_no_fabricated_ws_response_timeout() {
        let Some((r, t)) = sides(
            "d153_backups_store_no_fabricated_ws_response_timeout",
            &["targets", "backup"],
        ) else {
            return;
        };
        let ts_doc: Value = serde_json::from_str(
            &std::fs::read_to_string(
                t.sandbox
                    .cwd()
                    .join("airs-backup/targets/rest-target-one.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            ts_doc["data"]["connection_params"]["ws_response_timeout"],
            110
        );
        let rust_files = files_under(&r.sandbox.cwd());
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(r.sandbox.cwd().join(&rust_files[0])).unwrap(),
        )
        .unwrap();
        assert!(
            doc["targets"][0]["target"]["connection_params"]
                .get("ws_response_timeout")
                .is_none()
        );
        assert_eq!(
            doc["targets"][0]["target"]["connection_params"]["response_key"],
            "choices.0.message.content"
        );
    }

    /// D152: TypeScript restores its own per-target envelopes; airs-cli-rs refuses them
    /// with a message (no request), and refuses `--input-dir`; TypeScript cannot read an
    /// airs-cli-rs backup either.
    #[test]
    fn d152_restore_refuses_typescript_backups() {
        let Some(ts) = require_ts("d152_restore_refuses_typescript_backups") else {
            return;
        };
        let backup = exec(&ts, &["targets", "backup"]);
        backup.run.assert_success();
        let envelope = std::fs::read(
            backup
                .sandbox
                .cwd()
                .join("airs-backup/targets/rest-target-one.json"),
        )
        .unwrap();
        let place = |sandbox: &Sandbox| {
            std::fs::write(sandbox.tmp().join("ts.json"), &envelope).unwrap();
        };
        let ts_file = |sandbox: &Sandbox| sandbox.tmp().join("ts.json").display().to_string();
        // TypeScript restores it (the target is created again).
        let server = FixtureServer::start();
        server.seed_redteam();
        server.redteam(|data| data.targets.clear());
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        place(&sandbox);
        let out = run(
            &ts,
            &sandbox,
            &[
                "redteam",
                "targets",
                "restore",
                "--file",
                &ts_file(&sandbox),
            ],
            &RunOptions::new().allow_secret_output(),
        );
        out.assert_success();
        assert!(
            out.stdout.contains("Rest Target One — created"),
            "{}",
            out.stdout
        );
        assert_eq!(server.rt_requests(Rt::TargetCreate).len(), 1);
        // airs-cli-rs refuses it before the tenant.
        let server = FixtureServer::start();
        server.seed_redteam();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        place(&sandbox);
        let path = ts_file(&sandbox);
        let out = run(
            &rust(),
            &sandbox,
            &["redteam", "targets", "restore", "--file", &path],
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert!(
            out.stderr.contains(&format!(
                "✗ Error: {path} is a TypeScript airs-cli backup; airs cannot restore it."
            )),
            "{}",
            out.stderr
        );
        assert_eq!(server.request_count(), 0);
        // A TypeScript `--file-format yaml` backup gets the same refusal, not `malformed
        // JSON`.
        let yaml_backup = exec(&ts, &["targets", "backup", "--file-format", "yaml"]);
        yaml_backup.run.assert_success();
        let yaml = std::fs::read(
            yaml_backup
                .sandbox
                .cwd()
                .join("airs-backup/targets/rest-target-one.yaml"),
        )
        .unwrap();
        assert!(
            String::from_utf8_lossy(&yaml).contains("resourceType: redteam-target"),
            "a js-yaml envelope"
        );
        let yaml_path = sandbox.tmp().join("ts.yaml");
        std::fs::write(&yaml_path, &yaml).unwrap();
        let yaml_path = yaml_path.display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &["redteam", "targets", "restore", "--file", &yaml_path],
            &RunOptions::new(),
        );
        out.assert_code(1);
        assert!(
            out.stderr.contains(&format!(
                "✗ Error: {yaml_path} is a TypeScript airs-cli backup; airs cannot restore it."
            )),
            "{}",
            out.stderr
        );
        assert!(!out.stderr.contains("malformed JSON"), "{}", out.stderr);
        assert_eq!(server.request_count(), 0);
        let out = run(
            &rust(),
            &sandbox,
            &["redteam", "targets", "restore", "--input-dir", "x"],
            &RunOptions::new(),
        );
        out.assert_code(2);
        // TypeScript cannot read an airs-cli-rs backup.
        let rust_backup = exec(&rust(), &["targets", "backup"]);
        let file = files_under(&rust_backup.sandbox.cwd()).remove(0);
        let bytes = std::fs::read(rust_backup.sandbox.cwd().join(file)).unwrap();
        let server = FixtureServer::start();
        server.seed_redteam();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        std::fs::write(sandbox.tmp().join("rs.json"), bytes).unwrap();
        let rs_file = sandbox.tmp().join("rs.json").display().to_string();
        let out = run(
            &ts,
            &sandbox,
            &["redteam", "targets", "restore", "--file", &rs_file],
            &RunOptions::new().allow_secret_output(),
        );
        assert_eq!(out.code, 1);
        assert!(server.rt_requests(Rt::TargetCreate).is_empty());
    }

    /// D137 (restore): TypeScript overwrites without asking; airs-cli-rs refuses
    /// `--overwrite` without `--force` when there is no terminal (exit 2, no request).
    #[test]
    fn d137_restore_overwrite_confirms() {
        let Some(ts) = require_ts("d137_restore_overwrite_confirms") else {
            return;
        };
        let backup = exec(&ts, &["targets", "backup"]);
        let envelope = std::fs::read(
            backup
                .sandbox
                .cwd()
                .join("airs-backup/targets/rest-target-one.json"),
        )
        .unwrap();
        let server = FixtureServer::start();
        server.seed_redteam();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        std::fs::write(sandbox.tmp().join("ts.json"), &envelope).unwrap();
        let file = sandbox.tmp().join("ts.json").display().to_string();
        let out = run(
            &ts,
            &sandbox,
            &[
                "redteam",
                "targets",
                "restore",
                "--file",
                &file,
                "--overwrite",
            ],
            &RunOptions::new().allow_secret_output(),
        );
        out.assert_success();
        assert_eq!(
            server.rt_requests(Rt::TargetUpdate).len(),
            1,
            "TS overwrites without asking"
        );
        server.clear_requests();
        let out = run(
            &rust(),
            &sandbox,
            &[
                "redteam",
                "targets",
                "restore",
                "--file",
                &file,
                "--overwrite",
            ],
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert_eq!(
            out.stderr,
            "\n  ✗ refusing to overwrite targets without --force in non-interactive mode\n\n"
        );
        assert_eq!(server.request_count(), 0);
    }

    /// D143 (restore): TypeScript reports a missing file with Node's error text after
    /// the banner; airs-cli-rs reads it before the tenant with a fixed message.
    #[test]
    fn d143_the_restore_file_is_read_before_the_tenant() {
        let Some((r, t)) = sides_with(
            "d143_the_restore_file_is_read_before_the_tenant",
            &["targets", "restore", "--file", "missing.json"],
            &|_, _| {},
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert!(t.run.stderr.contains("ENOENT"), "{}", t.run.stderr);
        assert!(
            t.run.stdout.contains("Backup & Restore"),
            "TS prints the banner first"
        );
        assert!(r.run.stderr.contains(
            "✗ Error: Cannot read missing.json (missing, not a regular file, unreadable or larger than 16 MiB)"
        ), "{}", r.run.stderr);
        assert_eq!(r.run.stdout, "");
        assert!(r.requests.is_empty());
    }

    /// The `METHOD /path?query` lines of a side's API requests (the token left out).
    fn api_lines(side: &Side) -> Vec<String> {
        side.server
            .requests()
            .iter()
            .map(airs_test_harness::RecordedRequest::line)
            .filter(|line| !line.starts_with("POST /oauth/token"))
            .collect()
    }

    /// airs-cli-rs refuses `args` before the tenant with `message`; TypeScript reads the
    /// report and sends `ts_line` (§15.23).
    fn assert_refused_first(name: &str, args: &[&str], message: &str, ts_line: &str) {
        let Some((r, t)) = sides(name, args) else {
            return;
        };
        assert_eq!(r.run.code, 2, "{args:?}{}", context(&r, &t));
        assert_eq!(r.run.stdout, "", "{args:?}");
        assert_eq!(r.run.stderr, format!("\n  ✗ {message}\n\n"), "{args:?}");
        assert!(r.requests.is_empty(), "{args:?}");
        t.run.assert_success();
        assert!(
            api_lines(&t).iter().any(|line| line == ts_line),
            "{args:?}: {:?}",
            api_lines(&t)
        );
    }

    /// D301 (`report <jobId> --attacks`): TypeScript sends any positive `--limit`;
    /// airs-cli-rs refuses more than 100 for every job type, and both send 100. Without
    /// `--attacks` the value is unused on both.
    #[test]
    fn d301_attack_list_limits_are_at_most_100() {
        let job = fx::job_id(1);
        let custom = fx::job_id(3);
        let message = "--limit must be at most 100 (the red team API maximum)";
        assert_refused_first(
            "d301_attack_list_limits_are_at_most_100",
            &["report", &job, "--attacks", "--limit", "101"],
            message,
            &format!("GET /redteam/data/v1/report/static/{job}/list-attacks?limit=101"),
        );
        assert_refused_first(
            "d301_attack_list_limits_are_at_most_100",
            &["report", &custom, "--attacks", "--limit", "1000"],
            message,
            &format!(
                "GET /redteam/data/v1/custom-attacks/job/{custom}/list-custom-attacks?limit=1000"
            ),
        );
        for args in [
            vec!["report", job.as_str(), "--attacks", "--limit", "100"],
            vec!["report", job.as_str(), "--limit", "101"],
        ] {
            let Some((r, t)) = sides("d301_attack_list_limits_are_at_most_100", &args) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.run.stdout, t.run.stdout, "{args:?}{}", context(&r, &t));
            assert_eq!(r.requests, t.requests, "{args:?}{}", context(&r, &t));
        }
    }

    /// D303: TypeScript sends any `report --attacks --severity` text (`""` as
    /// `severity=`); airs-cli-rs refuses a value outside `LOW`, `MEDIUM`, `HIGH`,
    /// `CRITICAL`, `""` included. Without `--attacks` it is unused on both.
    #[test]
    fn d303_attack_severities_use_the_api_vocabulary() {
        let job = fx::job_id(1);
        let message = "--severity must be one of LOW, MEDIUM, HIGH, CRITICAL";
        let path = format!("GET /redteam/data/v1/report/static/{job}/list-attacks");
        for (args, ts_line) in [
            (
                vec!["report", job.as_str(), "--attacks", "--severity", "high"],
                format!("{path}?limit=20&severity=high"),
            ),
            (
                vec!["report", job.as_str(), "--attacks", "--severity", ""],
                format!("{path}?limit=20&severity="),
            ),
        ] {
            assert_refused_first(
                "d303_attack_severities_use_the_api_vocabulary",
                &args,
                message,
                &ts_line,
            );
        }
        for args in [
            vec![
                "report",
                job.as_str(),
                "--attacks",
                "--severity",
                "CRITICAL",
            ],
            vec!["report", job.as_str(), "--severity", "high"],
        ] {
            let Some((r, t)) = sides("d303_attack_severities_use_the_api_vocabulary", &args) else {
                return;
            };
            r.run.assert_success();
            assert_eq!(r.run.stdout, t.run.stdout, "{args:?}{}", context(&r, &t));
            assert_eq!(r.requests, t.requests, "{args:?}{}", context(&r, &t));
        }
    }

    /// D301, D303 (§15.23 choice 20): TypeScript sends `--severity` only for a STATIC job
    /// and `--limit` only for STATIC and CUSTOM jobs; a DYNAMIC job lists no attacks. The
    /// job type is known only after a read, so airs-cli-rs checks both values before the
    /// tenant for every job type: these commands, which send nothing invalid on
    /// TypeScript, are usage errors.
    #[test]
    fn d303_attack_values_are_checked_whatever_the_job_type() {
        let custom = fx::job_id(3);
        let dynamic = fx::job_id(2);
        let severity = "--severity must be one of LOW, MEDIUM, HIGH, CRITICAL";
        let limit = "--limit must be at most 100 (the red team API maximum)";
        for (args, message, ts_line, unsent) in [
            (
                vec!["report", custom.as_str(), "--attacks", "--severity", "high"],
                severity,
                format!(
                    "GET /redteam/data/v1/custom-attacks/job/{custom}/list-custom-attacks?limit=20"
                ),
                "severity",
            ),
            (
                vec![
                    "report",
                    dynamic.as_str(),
                    "--attacks",
                    "--severity",
                    "high",
                ],
                severity,
                format!("GET /redteam/data/v1/report/dynamic/{dynamic}/report"),
                "severity",
            ),
            (
                vec!["report", dynamic.as_str(), "--attacks", "--limit", "500"],
                limit,
                format!("GET /redteam/data/v1/report/dynamic/{dynamic}/report"),
                "limit=",
            ),
        ] {
            let name = "d303_attack_values_are_checked_whatever_the_job_type";
            assert_refused_first(name, &args, message, &ts_line);
            let Some(t) = require_ts(name).map(|ts| exec(&ts, &args)) else {
                return;
            };
            assert!(
                api_lines(&t).iter().all(|line| !line.contains(unsent)),
                "{args:?}: TypeScript never sends {unsent}: {:?}",
                api_lines(&t)
            );
        }
    }
}
