//! TS-vs-Rust parity for `gateway report|dashboard` (DESIGN §19.15; TS `aigateway report`,
//! renamed, D227).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript reference,
//! each on a fresh [`FixtureServer`] seeded with the gateway dataset and a fresh
//! [`Sandbox`] (the TypeScript runs get `TZ=UTC`, G41, so both send the window with
//! `+00:00`). The `parity` tests compare exit codes, the HTML byte for byte with the
//! collection timestamps normalised (the shared renderer with the gateway profile,
//! choice 50), stderr and the 25 reads; the `divergence` tests pin both sides of each §12
//! row this report implements. The TypeScript side may print fixture markers, so its runs
//! disable the marker check; the airs-cli-rs runs keep it.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use airs_test_harness::{
    Cli, FixtureServer, GatewayData, Gw, Planned, RecordedRequest, Route, Run, RunOptions, Sandbox,
    require_ts, run,
};
use serde_json::json;

const TSG: &str = "100";
const SLUG: &str = "ws-main-a-349e0e";
const WINDOW: [&str; 4] = [
    "--start",
    "2026-10-01T00:00:00Z",
    "--end",
    "2026-10-02T00:00:00Z",
];
const FAILED_LINE: &str = "  ✗ Report generation failed. Verify Management API configuration and a writable, new output path. Existing files are never overwritten.\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    sandbox: Sandbox,
}

impl Side {
    fn api(&self) -> Vec<String> {
        self.requests
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }
}

/// A change to a scenario's dataset or server before the run.
type Edit<'a> = &'a dyn Fn(&FixtureServer, &Sandbox);

fn exec_with(cli: &Cli, args: &[&str], edit: Edit<'_>, options: &RunOptions) -> Side {
    let server = FixtureServer::start();
    server.seed_gateway();
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    edit(&server, &sandbox);
    let mut full = vec![if cli.is_ts() { "aigateway" } else { "gateway" }];
    full.extend_from_slice(args);
    let options = options.clone().allow_writes_under("cwd");
    let options = if cli.is_ts() {
        options.allow_secret_output()
    } else {
        options
    };
    let out = run(cli, &sandbox, &full, &options);
    server.assert_no_unknown_routes();
    Side {
        run: out,
        requests: server.requests(),
        sandbox,
    }
}

fn exec(cli: &Cli, args: &[&str], edit: Edit<'_>) -> Side {
    exec_with(cli, args, edit, &RunOptions::new())
}

fn sides(name: &str, args: &[&str], edit: Edit<'_>) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((exec(&rust(), args, edit), exec(&ts, args, edit)))
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

fn data(server: &FixtureServer, edit: impl FnOnce(&mut GatewayData)) {
    server.gateway(edit);
}

/// `report --workspace <slug> <the window> <args>`.
fn report(args: &[&'static str]) -> Vec<&'static str> {
    let mut full = vec!["report", "--workspace", SLUG];
    full.extend_from_slice(&WINDOW);
    full.extend_from_slice(args);
    full
}

/// Every `YYYY-MM-DDTHH:MM:SS.mmmZ` that is not the window as `<time>` (the collection
/// timestamps).
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
            })
            && !candidate.starts_with("2026-10-01T00:00:00.000")
            && !candidate.starts_with("2026-10-02T00:00:00.000");
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

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The HTML is the TypeScript document byte for byte (times normalised) with the same
    /// status lines and the same 25 reads: every source complete, a chart refused, an
    /// organisation 403 (re-read once by both: TS's token replay, G7), an unknown workspace
    /// (the tenant reads only) and every telemetry source failing (exit 1 on both).
    #[test]
    fn the_report_matches_typescript() {
        let scenarios: [(&str, Edit<'_>); 5] = [
            ("complete", &|_, _| {}),
            ("a chart refused", &|server, _| {
                data(server, |data| {
                    data.charts.remove("errors");
                });
            }),
            ("organisation 403", &|server, _| {
                server.set_default(
                    Route::Gateway(Gw::OrganisationInfo),
                    Planned::json(403, &json!({"message": "PRIVATE-ERROR"})),
                );
            }),
            ("telemetry down", &|server, _| {
                for gw in [Gw::Chart, Gw::FilterBoundaries, Gw::Logs] {
                    server.set_default(
                        Route::Gateway(gw),
                        Planned::json(500, &json!({"message": "PRIVATE-ERROR"})),
                    );
                }
            }),
            ("paged logs", &|server, _| {
                data(server, |data| {
                    data.logs = (1..=60)
                        .map(|n| {
                            let mut row = airs_test_harness::fixtures::gateway::log(n);
                            row["response_status_code"] = json!(if n % 3 == 0 { 429 } else { 200 });
                            row
                        })
                        .collect();
                });
            }),
        ];
        for (name, edit) in scenarios {
            let Some((r, t)) = sides(
                "the_report_matches_typescript",
                &report(&["--output-file", "-", "--title", "Daily <report> & co"]),
                edit,
            ) else {
                return;
            };
            assert_eq!(r.run.code, t.run.code, "{name}{}", context(&r, &t));
            assert!(r.run.stdout.starts_with("<!doctype html>\n"), "{name}");
            assert_eq!(
                without_times(&r.run.stdout),
                without_times(&t.run.stdout),
                "{name}"
            );
            assert_eq!(r.run.stderr, t.run.stderr, "{name}{}", context(&r, &t));
            assert_eq!(r.api(), t.api(), "{name}");
            assert!(!r.run.stdout.contains("PRIVATE"));
        }
        // An unknown workspace: the tenant reads only, on both.
        let Some((r, t)) = sides(
            "the_report_matches_typescript",
            &["report", "--workspace", "Missing", "--output-file", "-"],
            &|_, _| {},
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(r.api(), t.api());
        assert_eq!(r.api().len(), 3);
        assert_eq!(r.run.stderr, t.run.stderr);
    }

    /// Both write a new 0600 file and refuse an existing path before any request with the
    /// same failure line; both validate the options alike (exit 2, TS order).
    #[test]
    fn report_files_and_checks_match_typescript() {
        let Some(ts) = require_ts("report_files_and_checks_match_typescript") else {
            return;
        };
        for cli in [rust(), ts.clone()] {
            let side = exec(&cli, &report(&["--output-file", "r.html"]), &|_, _| {});
            side.run.assert_success();
            assert_eq!(
                mode(&side.sandbox.cwd().join("r.html")),
                0o600,
                "{}",
                cli.label()
            );
            let existing = exec(
                &cli,
                &report(&["--output-file", "e.html"]),
                &|_, sandbox| {
                    std::fs::write(sandbox.cwd().join("e.html"), "KEEP").unwrap();
                },
            );
            assert_eq!(existing.run.code, 1, "{}", cli.label());
            assert_eq!(existing.run.stderr, FAILED_LINE, "{}", cli.label());
            assert!(existing.requests.is_empty(), "{}", cli.label());
            assert_eq!(
                std::fs::read_to_string(existing.sandbox.cwd().join("e.html")).unwrap(),
                "KEEP"
            );
            // The alias.
            let alias = exec(
                &cli,
                &["dashboard", "--workspace", SLUG, "--output-file", "-"],
                &|_, _| {},
            );
            alias.run.assert_success();
            assert!(alias.run.stdout.starts_with("<!doctype html>"));
        }
        let window_error = "Provide a valid increasing ISO-8601 window with timezone";
        for (args, message) in [
            (
                vec!["report", "--workspace", " "],
                "--workspace cannot be empty",
            ),
            (
                vec!["report", "--workspace", SLUG, "--days", "0"],
                "--days must be a positive integer",
            ),
            (
                vec!["report", "--workspace", SLUG, "--days", "1.5"],
                "--days must be a positive integer",
            ),
            (
                vec![
                    "report",
                    "--workspace",
                    SLUG,
                    "--start",
                    "2026-09-01T00:00:00Z",
                ],
                "--start and --end must be supplied together",
            ),
            (
                vec![
                    "report",
                    "--workspace",
                    SLUG,
                    "--days",
                    "1",
                    "--start",
                    "2026-09-01T00:00:00Z",
                    "--end",
                    "2026-09-02T00:00:00Z",
                ],
                "Use --days or --start/--end, not both",
            ),
            (
                vec![
                    "report",
                    "--workspace",
                    SLUG,
                    "--start",
                    "invalid",
                    "--end",
                    "2026-09-02T00:00:00Z",
                ],
                window_error,
            ),
            (
                vec![
                    "report",
                    "--workspace",
                    SLUG,
                    "--start",
                    "2026-09-02T00:00:00Z",
                    "--end",
                    "2026-09-01T00:00:00Z",
                ],
                window_error,
            ),
            (
                vec![
                    "report",
                    "--workspace",
                    SLUG,
                    "--start",
                    "2026-09-01T00:00:00",
                    "--end",
                    "2026-09-02T00:00:00Z",
                ],
                window_error,
            ),
            (
                vec!["report", "--workspace", SLUG, "--max-pages", "101"],
                "--max-pages must be an integer from 1 to 100",
            ),
            (
                vec!["report", "--workspace", SLUG, "--title", ""],
                "--title must contain 1–240 characters",
            ),
            (
                vec!["report", "--workspace", SLUG, "--output-file", " "],
                "--output-file cannot be empty",
            ),
        ] {
            for cli in [rust(), ts.clone()] {
                let side = exec(&cli, &args, &|_, _| {});
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

    /// The help: TS's options with the Rust `--output` line, one `(default: 1)` for
    /// `--days`, and the examples without the Markdown one (D155).
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let help = |cli: &Cli| exec(cli, &["report", "--help"], &|_, _| {}).run.stdout;
        let (r, t) = (help(&rust()), help(&ts));
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let ts_about = squash(t.split("\n\n").nth(1).unwrap());
        assert!(squash(&r).contains(&ts_about));
        for (flag, description) in [
            ("--days <n>", "Rolling window in days (default: 1)"),
            ("--end <iso>", "Explicit ISO-8601 end; requires --start"),
            (
                "--max-pages <n>",
                "Page budget per source, 1–100 (50 transactions/page) (default: \"40\")",
            ),
            (
                "--output-file <path>",
                "Destination (default: new timestamped file in CWD); - for stdout; never overwrite",
            ),
            ("--start <iso>", "Explicit ISO-8601 start; requires --end"),
            (
                "--strict",
                "Exit 1 after writing if any source is incomplete",
            ),
            (
                "--title <text>",
                "Report title (default: \"AI Gateway environment report\")",
            ),
            (
                "--workspace <ref>",
                "Workspace slug, UUID, or unique display name",
            ),
        ] {
            assert!(
                squash(&t).contains(flag) && squash(&r).contains(flag),
                "{flag}"
            );
            assert!(squash(&r).contains(description), "rust {flag}: {r}");
            assert!(
                squash(&t).contains(description),
                "ts {flag} (commander's own default suffix aside)"
            );
        }
        for example in [
            "report --workspace ws-develo-71f8d8 --output-file ./airs-daily.html",
            "report --workspace ws-develo-71f8d8 --strict --max-pages 20 --output-file - > daily.html",
        ] {
            assert!(t.contains(&format!("$ airs-cli aigateway {example}")));
            assert!(r.contains(&format!("$ airs gateway {example}")));
        }
        assert!(t.contains("--output markdown") && !r.contains("markdown"));
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D227: the default file is `airs-gateway-report-…` (TS `airs-aigateway-report-…`).
    #[test]
    fn d227_the_report_file_names_the_gateway() {
        let Some((r, t)) = sides("d227_report_file", &report(&[]), &|_, _| {}) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let names = |side: &Side| {
            side.sandbox
                .cwd_listing()
                .into_iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let (rust_names, ts_names) = (names(&r), names(&t));
        assert_eq!(rust_names.len(), 1);
        assert!(
            rust_names[0].starts_with("airs-gateway-report-"),
            "{rust_names:?}"
        );
        assert!(
            ts_names[0].starts_with("airs-aigateway-report-"),
            "{ts_names:?}"
        );
        assert_eq!(rust_names[0].len() + 2, ts_names[0].len());
    }

    /// D155: HTML only. TS writes Markdown on `--output markdown`; airs-cli-rs refuses the
    /// format, and an explicit valid format, before any request.
    #[test]
    fn d155_the_gateway_report_is_html_only() {
        let Some(ts) = require_ts("d155_the_gateway_report_is_html_only") else {
            return;
        };
        let mut args = vec!["--output", "markdown"];
        args.extend(report(&["--output-file", "-"]));
        let t = exec(&ts, &args, &|_, _| {});
        t.run.assert_success();
        assert!(t.run.stdout.starts_with("# AI Gateway environment report"));
        let r = exec(&rust(), &args, &|_, _| {});
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Invalid output format 'markdown'. Expected: pretty, table, json\n\n"
        );
        let mut args = vec!["--output", "json"];
        args.extend(report(&[]));
        let r = exec(&rust(), &args, &|_, _| {});
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ The environment report is written as HTML; omit --output\n\n"
        );
        let t = exec(&ts, &args, &|_, _| {});
        t.run.assert_code(2);
        assert!(
            t.run
                .stderr
                .contains("✗ Report output must be html or markdown")
        );
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// D156: the debug refusal names no environment variable.
    #[test]
    fn d156_the_gateway_report_refuses_debug() {
        let Some(ts) = require_ts("d156_the_gateway_report_refuses_debug") else {
            return;
        };
        let mut args = vec!["--debug"];
        args.extend(report(&[]));
        let r = exec(&rust(), &args, &|_, _| {});
        let t = exec(&ts, &args, &|_, _| {});
        assert_eq!((r.run.code, t.run.code), (2, 2));
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Disable --debug for environment reports to avoid persisting sensitive traffic content\n\n"
        );
        assert!(t.run.stderr.contains(
            "✗ Disable --debug and PANW_AI_SEC_DEBUG for environment reports to avoid persisting sensitive traffic content"
        ));
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// D214, D226: a missing parent directory (or a path that names no file) is refused
    /// before the tenant by airs-cli-rs; TS reads all 25 sources first.
    #[test]
    fn d214_d226_the_destination_parent_is_checked_first() {
        let Some((r, t)) = sides(
            "d214_gateway_report",
            &report(&["--output-file", "nodir/r.html"]),
            &|_, _| {},
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(r.run.stderr, FAILED_LINE);
        assert!(r.requests.is_empty());
        assert_eq!(t.api().len(), 25);
        assert!(t.run.stderr.ends_with(FAILED_LINE));
        let r = exec(&rust(), &report(&["--output-file", "sub/"]), &|_, _| {});
        r.run.assert_code(1);
        assert!(r.requests.is_empty());
    }

    /// D249: TS reads a zone-less `created_at` in the host zone (UTC here: complete);
    /// airs-cli-rs refuses it. TS runs a window outside the years 0000–9999 (every
    /// telemetry source fails without a request); airs-cli-rs refuses it at the check. A
    /// closed stdout is the failure line (TS: a Node stack trace).
    #[test]
    fn d249_times_windows_and_a_closed_stdout() {
        let zoneless = |server: &FixtureServer, _: &Sandbox| {
            data(server, |data| {
                data.logs[0]["created_at"] = json!("2026-10-01T12:00:00");
            });
        };
        let Some((r, t)) = sides(
            "d249_zone_less",
            &report(&["--output-file", "-"]),
            &zoneless,
        ) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let logs =
            "<td>telemetry.logs</td><td>telemetry.logs</td><td>Displayed telemetry window</td><td>";
        assert!(r.run.stdout.contains(&format!("{logs}unavailable")));
        assert!(t.run.stdout.contains(&format!("{logs}complete")));
        let Some((r, t)) = sides(
            "d249_window",
            &[
                "report",
                "--workspace",
                SLUG,
                "--days",
                "100000000",
                "--output-file",
                "-",
            ],
            &|_, _| {},
        ) else {
            return;
        };
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Provide a valid increasing ISO-8601 window with timezone\n\n"
        );
        assert!(r.requests.is_empty());
        t.run.assert_code(1);
        assert!(t.run.stdout.contains("Unable to assess"));
        assert_eq!(t.api().len(), 6, "{:?}", t.api());
        let closed = RunOptions::new().close_stdout_after(0);
        let Some(ts) = require_ts("d249_closed_stdout") else {
            return;
        };
        let args = report(&["--output-file", "-"]);
        let r = exec_with(&rust(), &args, &|_, _| {}, &closed);
        let t = exec_with(&ts, &args, &|_, _| {}, &closed);
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert!(r.run.stderr.ends_with(FAILED_LINE), "{}", r.run.stderr);
        assert!(
            !t.run.stderr.contains("Report generation failed"),
            "{}",
            t.run.stderr
        );
    }

    /// D1: a missing `--workspace` is clap's usage error (exit 2); commander exits 1.
    #[test]
    fn d1_a_missing_workspace_is_a_usage_error() {
        let Some((r, t)) = sides("d1_gateway_report", &["report"], &|_, _| {}) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (2, 1));
        assert!(
            t.run
                .stderr
                .contains("required option '--workspace <ref>' not specified")
        );
        assert!(r.run.stderr.contains("--workspace <ref>"));
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }
}
