//! TS-vs-Rust parity for `supplychain report` (DESIGN §20.9; TS `agentguard report`,
//! renamed, D308).
//!
//! Each scenario runs once against airs-cli-rs (`supplychain report`) and once against the
//! TypeScript reference (`agentguard report`), each on a fresh [`FixtureServer`] seeded with
//! the supplychain dataset whose scans were created an hour before the run (inside both
//! CLIs' 30-day windows) and a fresh [`Sandbox`]. The byte-comparing scenarios leave out the
//! zone-less row (TypeScript reads it in the host's zone, D322) and pass the same `--title`
//! (D309). The `parity` tests compare exit codes, the HTML byte for byte with the run's
//! times normalised (the shared renderer with the supplychain profile, choice 34), stderr
//! and the requests (their window values normalised); the `divergence` tests pin both sides
//! of each §12 row the report implements.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use airs_test_harness::fixtures::supplychain as fx;
use airs_test_harness::{
    Cli, FixtureServer, Planned, RecordedRequest, Route, Run, RunOptions, Sandbox, Sc,
    SupplychainData, require_ts, run, spawn,
};
use serde_json::json;

const TSG: &str = "100";
const TITLE: &str = "Supply <chain> & co";
const RS_FAILED: &str = "  ✗ Supply chain report failed. Check credentials and a writable, new output path. Existing files are never overwritten.\n";
const TS_FAILED: &str = "  ✗ AgentGuard report failed. Check credentials and a writable, new output path. Existing files are never overwritten.\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    sandbox: Sandbox,
}

impl Side {
    /// `METHOD path?query` of every request (the token as `POST <token>`), the window
    /// values as `<t>`.
    fn lines(&self) -> Vec<String> {
        self.requests
            .iter()
            .map(|request| {
                if request.route == Route::Token {
                    return "POST <token>".to_owned();
                }
                let line = request.line();
                let Some((head, query)) = line.split_once('?') else {
                    return line;
                };
                let query: Vec<String> = query
                    .split('&')
                    .map(|pair| match pair.split_once('=') {
                        Some((key @ ("start_time" | "end_time"), _)) => format!("{key}=<t>"),
                        _ => pair.to_owned(),
                    })
                    .collect();
                format!("{head}?{}", query.join("&"))
            })
            .collect()
    }

    fn api(&self) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|line| line != "POST <token>")
            .collect()
    }
}

/// A change to a scenario's dataset or server before the run.
type Edit<'a> = &'a dyn Fn(&FixtureServer, &Sandbox);

/// The zoned recent scans (byte parity), then `edit`.
fn exec_with(cli: &Cli, args: &[&str], edit: Edit<'_>, options: &RunOptions) -> Side {
    let server = FixtureServer::start();
    server.seed_supplychain();
    server.supplychain(|data| data.scans = fx::recent_zoned_scans());
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    edit(&server, &sandbox);
    let mut full = vec![if cli.is_ts() {
        "agentguard"
    } else {
        "supplychain"
    }];
    full.extend_from_slice(args);
    let options = options.clone().allow_writes_under("cwd");
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

fn data(server: &FixtureServer, edit: impl FnOnce(&mut SupplychainData)) {
    server.supplychain(edit);
}

/// Every `YYYY-MM-DDTHH:MM:SS.mmmZ` as `<time>` (the run's own times).
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

/// `report --output-file - --title <TITLE> <args>`.
fn report(args: &[&'static str]) -> Vec<&'static str> {
    let mut full = vec!["report", "--output-file", "-", "--title", TITLE];
    full.extend_from_slice(args);
    full
}

/// The evidence row of `source` (`<tr><td>Scans</td>…`).
fn evidence_row<'a>(html: &'a str, source: &str) -> &'a str {
    let at = html
        .find(&format!("<tr><td>{source}</td>"))
        .unwrap_or_else(|| panic!("{source}"));
    let row = &html[at..];
    &row[..row.find("</tr>").unwrap()]
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// The HTML is the TypeScript document byte for byte (times normalised) with the same
    /// status lines and the same requests: the seeded dataset (the 2020 and `garbage` rows
    /// excluded on both sides), rules at 403 (re-read once by both: TS's token replay, G63),
    /// every source at 500 (exit 1 on both), the `--max-pages 2` budget over 25 scans and
    /// 25 rules, valid empty data (`no-findings`), the statistics' JavaScript numbers.
    #[test]
    fn the_report_matches_typescript() {
        let scenarios: [(&str, Edit<'_>, &[&'static str]); 8] = [
            ("seeded", &|_, _| {}, &[]),
            (
                "rules 403",
                &|server, _| {
                    server.set_default(
                        Route::Supplychain(Sc::Rules),
                        Planned::json(403, &json!({"message": "PRIVATE-ERROR"})),
                    );
                },
                &[],
            ),
            (
                "everything 500",
                &|server, _| {
                    for sc in [Sc::Scans, Sc::Stats, Sc::Rules] {
                        server.set_default(
                            Route::Supplychain(sc),
                            Planned::json(500, &json!({"message": "PRIVATE-ERROR"})),
                        );
                    }
                },
                &[],
            ),
            (
                "page budget",
                &|server, _| {
                    data(server, |data| {
                        let template = fx::recent_scans()[0].clone();
                        data.scans = (1..=25)
                            .map(|n| {
                                let mut row = template.clone();
                                row.set("uuid", serde_json::Value::from(fx::uuid(500 + n)));
                                row
                            })
                            .collect();
                    });
                },
                &["--max-pages", "2"],
            ),
            (
                "empty",
                &|server, _| {
                    data(server, |data| {
                        data.scans.clear();
                        data.rules.clear();
                        data.stats = Some(fx::Wire::from(json!({
                            "unique_skills_scanned": {"count": 0, "percent_change": null},
                            "total_vulnerabilities_found": {"count": 0, "percent_change": null},
                            "top_vulnerability": null
                        })));
                    });
                },
                &[],
            ),
            (
                "numbers",
                &|server, _| {
                    data(server, |data| {
                        data.stats = Some(fx::Wire::from(json!({
                            "unique_skills_scanned": {"count": 4, "percent_change": -3},
                            "total_vulnerabilities_found": {"count": 7, "percent_change": 1e-7},
                            "top_vulnerability": null
                        })));
                    });
                },
                &[],
            ),
            (
                "a non-integral count",
                &|server, _| {
                    data(server, |data| {
                        data.stats = Some(fx::Wire::from(json!({
                            "unique_skills_scanned": {"count": 4, "percent_change": -3},
                            "total_vulnerabilities_found": {"count": 7.5, "percent_change": 1e-7},
                            "top_vulnerability": null
                        })));
                    });
                },
                &[],
            ),
            (
                "a repeated scan",
                &|server, _| {
                    server.push_once(Route::Supplychain(Sc::Scans), Planned::builtin());
                    let mut rows = fx::recent_zoned_scans();
                    rows.truncate(1);
                    server.push_once(
                        Route::Supplychain(Sc::Scans),
                        Planned::raw(200, "application/json", fx::scan_list_body(&rows, 11)),
                    );
                },
                &[],
            ),
        ];
        for (name, edit, extra) in scenarios {
            let Some((r, t)) = sides("the_report_matches_typescript", &report(extra), edit) else {
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
            assert_eq!(r.lines(), t.lines(), "{name}");
            assert!(!r.run.stdout.contains("PRIVATE"), "{name}");
            if name == "a non-integral count" {
                // Both SDKs refuse the answer: the Statistics source is unavailable on
                // both sides and no statistics table is printed.
                assert!(!r.run.stdout.contains("Skill statistics"), "{name}");
            }
            if name == "numbers" {
                // Both SDKs validate the counts as integers; the changes are the server's
                // JavaScript numbers (choice 49): the Statistics table is rendered and
                // compared.
                assert!(
                    r.run.stdout.contains("<tr><td>Unique skills scanned</td><td>4</td><td>-3</td></tr><tr><td>Vulnerabilities found</td><td>7</td><td>1e-7</td></tr>"),
                    "{name}"
                );
            }
        }
    }

    /// Both write a new 0600 file and refuse an existing path (a dangling symlink included)
    /// before any request; both validate the options alike (exit 2, the shared texts).
    #[test]
    fn report_files_and_checks_match_typescript() {
        let Some(ts) = require_ts("report_files_and_checks_match_typescript") else {
            return;
        };
        for cli in [rust(), ts.clone()] {
            let side = exec(
                &cli,
                &["report", "--output-file", "r.html", "--title", TITLE],
                &|_, _| {},
            );
            side.run.assert_success();
            let file = side.sandbox.cwd().join("r.html");
            assert_eq!(mode(&file), 0o600, "{}", cli.label());
            assert_eq!(
                side.run.stderr,
                format!(
                    "  Report → {} (mode 0600)\n  1 source(s) incomplete; review the evidence section.\n",
                    file.display()
                ),
                "{}",
                cli.label()
            );
            for setup in [
                |sandbox: &Sandbox| std::fs::write(sandbox.cwd().join("e.html"), "KEEP").unwrap(),
                |sandbox: &Sandbox| {
                    std::os::unix::fs::symlink(
                        sandbox.tmp().join("nowhere"),
                        sandbox.cwd().join("e.html"),
                    )
                    .unwrap();
                },
            ] {
                let existing = exec(
                    &cli,
                    &["report", "--output-file", "e.html"],
                    &|_, sandbox| setup(sandbox),
                );
                assert_eq!(existing.run.code, 1, "{}", cli.label());
                assert!(existing.requests.is_empty(), "{}", cli.label());
            }
        }
        for (args, message) in [
            (
                vec!["report", "--max-pages", "0"],
                "--max-pages must be between 1 and 100",
            ),
            (
                vec!["report", "--max-pages", "101"],
                "--max-pages must be between 1 and 100",
            ),
            (
                vec!["report", "--title", " "],
                "--title must contain 1–240 characters",
            ),
            (
                vec!["report", "--output-file", " "],
                "--output-file cannot be empty",
            ),
            (
                vec!["report", "--max-pages", "0", "--title", " "],
                "--max-pages must be between 1 and 100",
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
        let title = "x".repeat(240);
        for cli in [rust(), ts] {
            let side = exec(
                &cli,
                &["report", "--output-file", "-", "--title", &title],
                &|_, _| {},
            );
            side.run.assert_success();
            assert!(side.run.stdout.contains(&format!("<title>{title}</title>")));
        }
    }

    /// The help: TS's options and texts with the program name and `supplychain`, the
    /// description without `/Markdown` and the refused `--output` (D155), the renamed title
    /// default (D309).
    #[test]
    fn help_texts_match_typescript() {
        let Some(ts) = require_ts("help_texts_match_typescript") else {
            return;
        };
        let help = |cli: &Cli| exec(cli, &["report", "--help"], &|_, _| {}).run.stdout;
        let (r, t) = (help(&rust()), help(&ts));
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(t.contains("Generate an aggregate-only 30-day HTML/Markdown report"));
        assert!(r.contains("Generate an aggregate-only 30-day HTML report"));
        for (flag, description) in [
            (
                "--max-pages <n>",
                "Page budget per inventory (1–100, 10 rows/page) (default: 40)",
            ),
            (
                "--output-file <path>",
                "New file in CWD by default; - for stdout; never overwrite",
            ),
            (
                "--strict",
                "Exit 1 after writing if any source is incomplete",
            ),
        ] {
            assert!(
                squash(&t).contains(&format!("{flag} {description}")),
                "ts {flag}"
            );
            assert!(
                squash(&r).contains(&format!("{flag} {description}")),
                "rust {flag}"
            );
        }
        assert!(t.contains("Report title (default: \"AgentGuard environment report\")"));
        assert!(r.contains("Report title (default: \"Supply chain environment report\")"));
        assert!(t.contains("--output <format>     Deliverable: html (default) or markdown"));
        assert!(r.contains(
            "--output <format>     Refused by this command: the report is written as HTML (omit --output)"
        ));
        // §20.2 (choice 81): the leaf options in TypeScript's sorted order on both sides.
        let order = ["--max-pages", "--output-file", "--strict", "--title"];
        for text in [&r, &t] {
            let at: Vec<usize> = order
                .iter()
                .map(|flag| text.find(&format!("  {flag} ")).expect(flag))
                .collect();
            assert!(at.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
        }
        assert!(t.starts_with("Usage: airs-cli agentguard report [options]"));
        assert!(r.contains("Usage: airs supplychain report [OPTIONS]"));
    }
}

// ---------------------------------------------------------------------------
// Divergences (DESIGN §12)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D308: the report is `supplychain report`; `agentguard report` is no command here.
    /// The product line keeps `AgentGuard` on both sides (it names the service).
    #[test]
    fn d308_the_report_is_a_supplychain_command() {
        let Some((r, t)) = sides("d308_report", &report(&[]), &|_, _| {}) else {
            return;
        };
        r.run.assert_success();
        t.run.assert_success();
        let product = "<header><p>Prisma AIRS AI Supply Chain — AgentGuard</p>";
        assert!(r.run.stdout.contains(product) && t.run.stdout.contains(product));
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", TSG);
        let out = run(
            &rust(),
            &sandbox,
            &["agentguard", "report"],
            &RunOptions::new(),
        );
        out.assert_code(2);
        assert!(out.stderr.contains("unrecognized subcommand 'agentguard'"));
        assert_eq!(server.request_count(), 0);
    }

    /// D309: the default title is `Supply chain environment report` (TS `AgentGuard
    /// environment report`); otherwise the documents are equal.
    #[test]
    fn d309_the_default_title_names_the_supply_chain() {
        let Some((r, t)) = sides("d309", &["report", "--output-file", "-"], &|_, _| {}) else {
            return;
        };
        assert!(
            r.run
                .stdout
                .contains("<title>Supply chain environment report</title>")
        );
        assert!(
            t.run
                .stdout
                .contains("<title>AgentGuard environment report</title>")
        );
        assert_eq!(
            without_times(&r.run.stdout),
            without_times(&t.run.stdout).replace(
                "AgentGuard environment report",
                "Supply chain environment report"
            )
        );
    }

    /// D310: the default file is `airs-supplychain-report-…` (TS
    /// `airs-agentguard-report-…`), both in the working directory at 0600.
    #[test]
    fn d310_the_default_file_names_the_supplychain_report() {
        let Some((r, t)) = sides("d310", &["report"], &|_, _| {}) else {
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
        assert_eq!((rust_names.len(), ts_names.len()), (1, 1));
        assert!(
            rust_names[0].starts_with("airs-supplychain-report-"),
            "{rust_names:?}"
        );
        assert!(
            ts_names[0].starts_with("airs-agentguard-report-"),
            "{ts_names:?}"
        );
        assert_eq!(rust_names[0].len(), ts_names[0].len() + 1);
        for (side, name) in [(&r, &rust_names[0]), (&t, &ts_names[0])] {
            assert_eq!(mode(&side.sandbox.cwd().join(name)), 0o600);
        }
    }

    /// D311: the failure line names the supply chain report (TS `AgentGuard report
    /// failed`): an existing destination, refused before any request on both sides.
    #[test]
    fn d311_the_failure_line_names_the_supply_chain_report() {
        let existing = |_: &FixtureServer, sandbox: &Sandbox| {
            std::fs::write(sandbox.cwd().join("keep.html"), "KEEP").unwrap();
        };
        let Some((r, t)) = sides("d311", &["report", "--output-file", "keep.html"], &existing)
        else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(r.run.stderr, RS_FAILED);
        assert_eq!(t.run.stderr, TS_FAILED);
        assert!(r.requests.is_empty() && t.requests.is_empty());
        for side in [&r, &t] {
            assert_eq!(
                std::fs::read_to_string(side.sandbox.cwd().join("keep.html")).unwrap(),
                "KEEP"
            );
        }
    }

    /// D155: HTML only. TS writes Markdown on `--output markdown`; airs-cli-rs refuses the
    /// format, and an explicit valid format, before any request.
    #[test]
    fn d155_the_supplychain_report_is_html_only() {
        let Some(ts) = require_ts("d155_the_supplychain_report_is_html_only") else {
            return;
        };
        let args = [
            "--output",
            "markdown",
            "agentguard",
            "report",
            "--output-file",
            "-",
        ];
        let t_markdown = {
            let server = FixtureServer::start();
            server.seed_supplychain();
            server.supplychain(|data| data.scans = fx::recent_zoned_scans());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            run(&ts, &sandbox, &args, &RunOptions::new())
        };
        t_markdown.assert_success();
        assert!(
            t_markdown
                .stdout
                .starts_with("# AgentGuard environment report")
        );
        let r = {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let out = run(
                &rust(),
                &sandbox,
                &[
                    "--output",
                    "markdown",
                    "supplychain",
                    "report",
                    "--output-file",
                    "-",
                ],
                &RunOptions::new(),
            );
            assert_eq!(server.request_count(), 0);
            out
        };
        r.assert_code(2);
        assert_eq!(
            r.stderr,
            "\n  ✗ Invalid output format 'markdown'. Expected: pretty, table, json\n\n"
        );
        let r = exec(&rust(), &["report", "--output", "json"], &|_, _| {});
        r.run.assert_code(2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ The environment report is written as HTML; omit --output\n\n"
        );
        let t = exec(&ts, &["report", "--output", "json"], &|_, _| {});
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
    fn d156_the_supplychain_report_refuses_debug() {
        let Some(ts) = require_ts("d156_the_supplychain_report_refuses_debug") else {
            return;
        };
        let refusal = |cli: &Cli| {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let group = if cli.is_ts() {
                "agentguard"
            } else {
                "supplychain"
            };
            let out = run(
                cli,
                &sandbox,
                &["--debug", group, "report"],
                &RunOptions::new(),
            );
            assert_eq!(server.request_count(), 0);
            out
        };
        let (r, t) = (refusal(&rust()), refusal(&ts));
        assert_eq!((r.code, t.code), (2, 2));
        assert_eq!(
            r.stderr,
            "\n  ✗ Disable --debug for environment reports to avoid persisting sensitive traffic content\n\n"
        );
        assert!(t.stderr.contains(
            "✗ Disable --debug and PANW_AI_SEC_DEBUG for environment reports to avoid persisting sensitive traffic content"
        ));
    }

    /// D214, D226: a missing parent directory (or a path that names no file) is refused
    /// before the tenant by airs-cli-rs; TS reads every source first and fails at the write.
    #[test]
    fn d214_d226_the_destination_parent_is_checked_first() {
        let Some((r, t)) = sides(
            "d214_supplychain_report",
            &["report", "--output-file", "nodir/r.html"],
            &|_, _| {},
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(r.run.stderr, RS_FAILED);
        assert!(r.requests.is_empty());
        assert_eq!(t.api().len(), 6, "{:?}", t.api());
        assert!(t.run.stderr.ends_with(TS_FAILED));
        let r = exec(&rust(), &["report", "--output-file", "sub/"], &|_, _| {});
        r.run.assert_code(1);
        assert_eq!(r.run.stderr, RS_FAILED);
        assert!(r.requests.is_empty());
    }

    /// D314: `--max-pages abc` is the range text here (TS: commander's pagination text at
    /// parse time).
    #[test]
    fn d314_report_page_budgets_name_their_flag() {
        let Some((r, t)) = sides("d314_report", &["report", "--max-pages", "abc"], &|_, _| {})
        else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ --max-pages must be between 1 and 100\n\n"
        );
        assert_ne!(t.run.code, 0);
        assert!(
            t.run
                .stderr
                .contains("Pagination requires a safe nonnegative integer"),
            "{}",
            t.run.stderr
        );
        assert!(r.requests.is_empty() && t.requests.is_empty());
    }

    /// D322: a zone-less `created_at` is unusable here (excluded, the Scans source partial);
    /// TS reads it in the host's zone (`TZ=UTC` here: inside the window, complete).
    #[test]
    fn d322_report_times_need_a_zone() {
        let Some(ts) = require_ts("d322") else {
            return;
        };
        let zoneless = |server: &FixtureServer, _: &Sandbox| {
            data(server, |data| {
                let rows = fx::recent_scans();
                data.scans = vec![rows[0].clone(), rows[9].clone()];
            });
        };
        let r = exec(&rust(), &report(&[]), &zoneless);
        let t = exec_with(
            &ts,
            &report(&[]),
            &zoneless,
            &RunOptions::new().env("TZ", "UTC"),
        );
        r.run.assert_success();
        t.run.assert_success();
        let rust_row = evidence_row(&r.run.stdout, "Scans");
        let ts_row = evidence_row(&t.run.stdout, "Scans");
        assert!(
            rust_row.ends_with("<td>partial</td><td>2</td><td>1</td><td>Rows with missing or out-of-window creation timestamps were excluded.</td>"),
            "{rust_row}"
        );
        assert!(
            ts_row.ends_with("<td>complete</td><td>2</td><td>1</td><td>Collection completed.</td>"),
            "{ts_row}"
        );
        // The date-only form is UTC midnight on both sides.
        let date_only = |server: &FixtureServer, _: &Sandbox| {
            data(server, |data| {
                data.scans = vec![fx::recent_scans()[10].clone()];
            });
        };
        let r = exec(&rust(), &report(&[]), &date_only);
        let t = exec_with(
            &ts,
            &report(&[]),
            &date_only,
            &RunOptions::new().env("TZ", "UTC"),
        );
        assert_eq!(without_times(&r.run.stdout), without_times(&t.run.stdout));
        assert!(evidence_row(&r.run.stdout, "Scans").contains("<td>complete</td>"));
    }

    /// D324 (G71): scan rows with the `null`s the service sends make TypeScript's Scans
    /// source `unavailable` (its zod schema refuses the page); airs-cli-rs reads them (a
    /// `null` creation time excluded, the source partial). Statistics and Rules agree.
    #[test]
    fn d324_report_scans_with_nulls_are_read() {
        let Some(ts) = require_ts("d324_report") else {
            return;
        };
        let nulls = |server: &FixtureServer, _: &Sandbox| {
            data(server, |data| data.scans = fx::recent_null_scans());
        };
        let r = exec(&rust(), &report(&[]), &nulls);
        let t = exec_with(
            &ts,
            &report(&[]),
            &nulls,
            &RunOptions::new().env("TZ", "UTC"),
        );
        r.run.assert_success();
        t.run.assert_success();
        assert!(
            evidence_row(&r.run.stdout, "Scans").ends_with("<td>partial</td><td>3</td><td>1</td><td>Rows with missing or out-of-window creation timestamps were excluded.</td>"),
            "{}",
            evidence_row(&r.run.stdout, "Scans")
        );
        assert!(
            evidence_row(&t.run.stdout, "Scans").ends_with("<td>unavailable</td><td>0</td><td>0</td><td>Request or validation failed; no upstream error body included.</td>"),
            "{}",
            evidence_row(&t.run.stdout, "Scans")
        );
        for source in ["Statistics", "Rules"] {
            assert_eq!(
                evidence_row(&r.run.stdout, source),
                evidence_row(&t.run.stdout, source),
                "{source}"
            );
        }
        assert!(r.run.stdout.contains("<h2>Scan outcomes</h2>"));
        assert!(!t.run.stdout.contains("<h2>Scan outcomes</h2>"));
        assert!(!r.run.stdout.contains(fx::MARKER));
        assert_eq!(r.api(), t.api(), "the same reads");
    }

    /// D323: an interrupted report prints its context; TS dies by the signal silently.
    #[test]
    fn d323_an_interrupted_report_prints_its_context() {
        let Some(ts) = require_ts("d323_report") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_supplychain();
            server.push_once(Route::Supplychain(Sc::Stats), Planned::hang());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let name = if cli.is_ts() {
                "agentguard"
            } else {
                "supplychain"
            };
            let path = sandbox.tmp().join("r.html").display().to_string();
            let running = spawn(
                &cli,
                &sandbox,
                &[name, "report", "--output-file", &path],
                &RunOptions::new().expect_signal(),
            );
            assert!(server.wait_for_route(
                Route::Supplychain(Sc::Stats),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal("INT");
            outs.push(running.wait());
            assert!(!Path::new(&path).exists());
        }
        assert_eq!(outs[0].code, 130);
        assert_eq!(
            outs[0].stderr,
            "\n  ✗ Error: Interrupted; no report was written\n\n"
        );
        assert_eq!(outs[1].code, 130);
        assert_eq!(outs[1].stderr, "");
        assert_eq!((outs[0].stdout.as_str(), outs[1].stdout.as_str()), ("", ""));
    }
}
