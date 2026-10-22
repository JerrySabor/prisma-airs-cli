//! Prints observed TypeScript reference CLI behaviour for the scenarios recorded in
//! `docs/research/ts-baseline-observed.md`. Loopback only, synthetic credentials.
//!
//! ```text
//! cargo run -p airs-test-harness --example ts_baseline [filter]
//! ```

use std::time::Duration;

use airs_test_harness::{
    Cli, FixtureServer, FixtureTenant, Planned, RecordedRequest, Route, RunOptions, Sandbox,
    fixtures, run, spawn,
};
use serde_json::json;

const SENSITIVE: &[&str] = &["authorization", "x-pan-token", "x-payload-hash"];

struct Ctx {
    server: FixtureServer,
    sandbox: Sandbox,
    tenant: FixtureTenant,
}

fn ctx() -> Ctx {
    ctx_with(|_| {})
}

fn ctx_with(edit: impl FnOnce(&mut airs_test_harness::FixtureConfig)) -> Ctx {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    let tenant = sandbox.add_fixture_tenant_with(&server, "prod", "100", edit);
    sandbox.register(&[&tenant], Some("prod"));
    Ctx {
        server,
        sandbox,
        tenant,
    }
}

fn describe(request: &RecordedRequest) -> String {
    let encoding = request
        .basic_encoding
        .map(|encoding| format!(" basic={encoding:?}"))
        .unwrap_or_default();
    let mut out = format!(
        "    {} [{}] auth={:?}{encoding}\n",
        request.line(),
        request.route,
        request.auth
    );
    for (name, value) in &request.headers {
        if SENSITIVE.contains(&name.as_str()) {
            let shown = if name == "authorization" {
                value.split(' ').next().unwrap_or_default().to_owned() + " <redacted>"
            } else {
                "<present>".to_owned()
            };
            out.push_str(&format!("      {name}: {shown}\n"));
        } else {
            out.push_str(&format!("      {name}: {value}\n"));
        }
    }
    if !request.body.is_empty() && request.route != Route::Token {
        out.push_str(&format!("      body: {}\n", request.body_text()));
    } else if request.route == Route::Token {
        let names: Vec<String> = request
            .form()
            .into_iter()
            .map(|(name, value)| {
                if name == "client_secret" {
                    format!("{name}=<redacted>")
                } else {
                    format!("{name}={value}")
                }
            })
            .collect();
        out.push_str(&format!("      form: {}\n", names.join("&")));
    }
    out
}

fn show(name: &str, cli: &Cli, ctx: &Ctx, args: &[&str], options: &RunOptions) {
    let before = ctx.sandbox.snapshot();
    let out = run(cli, &ctx.sandbox, args, options);
    println!("=== {name}");
    println!("  args: {args:?}");
    println!(
        "  exit: {} (signal {:?}) in {:?}",
        out.code, out.signal, out.elapsed
    );
    println!("  stdout: {:?}", out.stdout);
    println!("  stderr: {:?}", out.stderr);
    println!("  requests ({}):", ctx.server.request_count());
    for request in ctx.server.requests() {
        print!("{}", describe(&request));
    }
    let unchanged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx.sandbox.assert_unchanged(&before)
    }))
    .is_ok();
    println!(
        "  tenant files unchanged: {unchanged}; home: {:?}; cwd: {:?}",
        ctx.sandbox.home_listing(),
        ctx.sandbox.cwd_listing()
    );
    println!();
}

fn main() {
    let filter = std::env::args().nth(1).unwrap_or_default();
    let Some(ts) = Cli::ts() else {
        eprintln!(
            "TS reference not found at {}",
            Cli::ts_entry_path().display()
        );
        std::process::exit(1);
    };
    let opts = RunOptions::new().timeout(Duration::from_secs(120));
    let wanted = |name: &str| filter.is_empty() || name.contains(&filter);
    let profiles = || {
        vec![
            fixtures::profile(1, "alpha", 1),
            fixtures::profile(2, "alpha", 2),
            fixtures::profile(3, "beta", 1),
        ]
    };
    let topics = || {
        vec![
            fixtures::topic(11, "fin", 1, "old"),
            fixtures::topic(12, "fin", 2, "new"),
            fixtures::topic(13, "legal", 1, "legal desc"),
        ]
    };

    type Scenario = (&'static str, Box<dyn Fn(&Ctx)>, Vec<&'static str>);
    let list = vec!["runtime", "profiles", "list", "--output", "json"];
    let scenarios: Vec<Scenario> = vec![
        ("version", Box::new(|_| {}), vec!["--version"]),
        ("profiles-list-empty", Box::new(|_| {}), list.clone()),
        (
            "profiles-list-data",
            Box::new(move |c| c.server.set_profiles("100", profiles())),
            list.clone(),
        ),
        (
            "profiles-list-all-limit1",
            Box::new(move |c| c.server.set_profiles("100", profiles())),
            vec![
                "runtime",
                "profiles",
                "list",
                "--output",
                "json",
                "--all",
                "--limit",
                "1",
                "--all-versions",
            ],
        ),
        (
            "profiles-list-zero-next-offset",
            Box::new(move |c| {
                c.server.set_profiles("100", profiles());
                c.server.set_zero_next_offset_on_last_page(true);
            }),
            list.clone(),
        ),
        (
            "profiles-list-more-available",
            Box::new(move |c| c.server.set_profiles("100", profiles())),
            vec![
                "runtime", "profiles", "list", "--output", "json", "--limit", "1",
            ],
        ),
        (
            "topics-list",
            Box::new(move |c| c.server.set_topics("100", topics())),
            vec!["runtime", "topics", "list", "--output", "json"],
        ),
        (
            "topics-list-all-versions-page",
            Box::new(move |c| c.server.set_topics("100", topics())),
            vec![
                "runtime",
                "topics",
                "list",
                "--output",
                "json",
                "--all-versions",
                "--limit",
                "1",
                "--offset",
                "1",
            ],
        ),
        (
            "profiles-get-name",
            Box::new(move |c| c.server.set_profiles("100", profiles())),
            vec!["runtime", "profiles", "get", "alpha", "--output", "json"],
        ),
        (
            "profiles-get-uuid",
            Box::new(move |c| c.server.set_profiles("100", profiles())),
            vec![
                "runtime",
                "profiles",
                "get",
                "00000000-0000-4000-8000-000000000001",
                "--output",
                "json",
            ],
        ),
        (
            "profiles-get-missing",
            Box::new(move |c| c.server.set_profiles("100", profiles())),
            vec!["runtime", "profiles", "get", "missing", "--output", "json"],
        ),
        (
            "profiles-get-revision-missing",
            Box::new(move |c| c.server.set_profiles("100", profiles())),
            vec![
                "runtime",
                "profiles",
                "get",
                "alpha",
                "--revision",
                "9",
                "--output",
                "json",
            ],
        ),
        (
            "topics-get-name",
            Box::new(move |c| c.server.set_topics("100", topics())),
            vec!["runtime", "topics", "get", "fin", "--output", "json"],
        ),
        (
            "topics-get-missing",
            Box::new(move |c| c.server.set_topics("100", topics())),
            vec!["runtime", "topics", "get", "nope", "--output", "json"],
        ),
        (
            "scan-allow",
            Box::new(|_| {}),
            vec![
                "runtime",
                "scan",
                "--profile",
                "fixture-profile",
                "hello world",
            ],
        ),
        (
            "scan-block",
            Box::new(|c| {
                c.server
                    .add_scan_verdict("BLOCK", &fixtures::scan_block("fixture-profile"))
            }),
            vec![
                "runtime",
                "scan",
                "--profile",
                "fixture-profile",
                "please BLOCK this",
            ],
        ),
        (
            "scan-failed",
            Box::new(|c| c.server.add_scan_verdict("FAIL", &fixtures::scan_failed())),
            vec!["runtime", "scan", "--profile", "fixture-profile", "FAIL"],
        ),
        (
            "scan-response-json-ignored",
            Box::new(|_| {}),
            vec![
                "runtime",
                "scan",
                "--profile",
                "p",
                "--response",
                "an answer",
                "--output",
                "json",
                "q",
            ],
        ),
        (
            "scan-quiet",
            Box::new(|_| {}),
            vec!["--quiet", "runtime", "scan", "--profile", "p", "q"],
        ),
        (
            "scan-empty-prompt",
            Box::new(|_| {}),
            vec!["runtime", "scan", "--profile", "p", ""],
        ),
        (
            "scan-503",
            Box::new(|c| {
                c.server.set_default(
                    Route::ScanSync,
                    Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
                )
            }),
            vec!["runtime", "scan", "--profile", "p", "q"],
        ),
        (
            "scan-429",
            Box::new(|c| {
                c.server.set_default(
                    Route::ScanSync,
                    Planned::json(429, &json!({"message": "slow down"})).with_retry_after(2),
                )
            }),
            vec!["runtime", "scan", "--profile", "p", "q"],
        ),
        (
            "scan-401",
            Box::new(|c| {
                c.server
                    .set_default(Route::ScanSync, Planned::empty_json(401))
            }),
            vec!["runtime", "scan", "--profile", "p", "q"],
        ),
        (
            "doctor-json",
            Box::new(|_| {}),
            vec!["doctor", "--output", "json"],
        ),
        ("doctor-pretty", Box::new(|_| {}), vec!["doctor"]),
        (
            "token-401-empty",
            Box::new(|c| c.server.set_default(Route::Token, Planned::empty_json(401))),
            list.clone(),
        ),
        (
            "token-401-description",
            Box::new(|c| {
                c.server.set_default(Route::Token, Planned::json(401, &json!({"error": "invalid_client", "error_description": "Client authentication failed"})))
            }),
            list.clone(),
        ),
        (
            "token-schema",
            Box::new(|c| {
                c.server.set_default(
                    Route::Token,
                    Planned::json(200, &json!({"token_type": "Bearer"})),
                )
            }),
            list.clone(),
        ),
        (
            "profiles-404-message",
            Box::new(|c| {
                c.server.set_default(
                    Route::Profiles,
                    Planned::json(404, &json!({"message": "nope"})),
                )
            }),
            list.clone(),
        ),
        (
            "profiles-404-empty",
            Box::new(|c| {
                c.server
                    .set_default(Route::Profiles, Planned::empty_json(404))
            }),
            list.clone(),
        ),
        (
            "profiles-429",
            Box::new(|c| {
                c.server.set_default(
                    Route::Profiles,
                    Planned::json(429, &json!({"message": "slow down"})).with_retry_after(0),
                )
            }),
            list.clone(),
        ),
        (
            "profiles-503",
            Box::new(|c| {
                c.server.set_default(
                    Route::Profiles,
                    Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
                )
            }),
            list.clone(),
        ),
        (
            "profiles-401-once",
            Box::new(|c| {
                c.server
                    .push_once(Route::Profiles, Planned::empty_json(401))
            }),
            list.clone(),
        ),
        (
            "profiles-302",
            Box::new(|c| {
                let to = c.server.url("/elsewhere");
                c.server
                    .set_default(Route::Profiles, Planned::redirect(302, &to))
            }),
            list.clone(),
        ),
        (
            "profiles-502-text",
            Box::new(|c| {
                c.server.set_default(
                    Route::Profiles,
                    Planned::raw(502, "text/plain", "oops").with_retry_after(0),
                )
            }),
            list.clone(),
        ),
        (
            "profiles-schema-invalid",
            Box::new(|c| {
                c.server.set_default(
                    Route::Profiles,
                    Planned::json(
                        200,
                        &json!({"ai_profiles": [{"revision": 1}], "next_offset": null}),
                    ),
                )
            }),
            list.clone(),
        ),
        (
            "profiles-200-not-json",
            Box::new(|c| {
                c.server.set_default(
                    Route::Profiles,
                    Planned::raw(200, "application/json", "{not json"),
                )
            }),
            list.clone(),
        ),
        (
            "profiles-repeated-cursor",
            Box::new(|c| {
                c.server.set_default(Route::Profiles, Planned::json(200, &json!({"ai_profiles": [fixtures::profile(1, "alpha", 1)], "next_offset": 5})))
            }),
            vec!["runtime", "profiles", "list", "--output", "json", "--all"],
        ),
        (
            "parse-unknown-option",
            Box::new(|_| {}),
            vec!["runtime", "profiles", "list", "--bogus"],
        ),
        (
            "parse-missing-argument",
            Box::new(|_| {}),
            vec!["runtime", "profiles", "get"],
        ),
        (
            "parse-unknown-command",
            Box::new(|_| {}),
            vec!["runtime", "bogus"],
        ),
        (
            "parse-bare-group",
            Box::new(|_| {}),
            vec!["runtime", "profiles"],
        ),
        (
            "parse-scan-missing-profile",
            Box::new(|_| {}),
            vec!["runtime", "scan", "q"],
        ),
        (
            "parse-excess-args",
            Box::new(|_| {}),
            vec!["runtime", "profiles", "list", "extra"],
        ),
        (
            "usage-limit-zero",
            Box::new(|_| {}),
            vec!["runtime", "profiles", "list", "--limit", "0"],
        ),
        (
            "usage-all-offset",
            Box::new(|_| {}),
            vec!["runtime", "profiles", "list", "--all", "--offset", "0"],
        ),
        (
            "usage-output-xml",
            Box::new(|_| {}),
            vec!["runtime", "profiles", "list", "--output", "xml"],
        ),
        (
            "tenant-list",
            Box::new(|_| {}),
            vec!["tenant", "list", "--output", "json"],
        ),
    ];

    for (name, setup, args) in &scenarios {
        if !wanted(name) {
            continue;
        }
        let c = ctx();
        setup(&c);
        show(name, &ts, &c, args, &opts);
    }

    if wanted("scan-token-only") {
        let c = ctx_with(|config| {
            config.remove("airsApiKey");
            config.set("airsApiToken", "FAKE-APITOKEN-100");
        });
        show(
            "scan-token-only",
            &ts,
            &c,
            &["runtime", "scan", "--profile", "p", "q"],
            &opts,
        );
    }
    if wanted("scan-key-and-token") {
        let c = ctx_with(|config| {
            config.set("airsApiToken", "FAKE-APITOKEN-100");
        });
        show(
            "scan-key-and-token",
            &ts,
            &c,
            &["runtime", "scan", "--profile", "p", "q"],
            &opts,
        );
    }
    if wanted("doctor-no-scanner") {
        let c = ctx_with(|config| {
            config.remove("airsApiKey");
        });
        show(
            "doctor-no-scanner",
            &ts,
            &c,
            &["doctor", "--output", "json"],
            &opts,
        );
    }
    if wanted("doctor-scanner-503") {
        let c = ctx();
        c.server.set_default(
            Route::ScanResults,
            Planned::json(503, &json!({"message": "busy"})).with_retry_after(0),
        );
        show(
            "doctor-scanner-503",
            &ts,
            &c,
            &["doctor", "--output", "json"],
            &opts,
        );
    }
    if wanted("oauth-reserved-secret") {
        let c = ctx_with(|config| {
            config.set("mgmtClientSecret", "FAKE+SECRET/=x y:z");
        });
        show("oauth-reserved-secret", &ts, &c, &list, &opts);
    }
    if wanted("doctor-token-401") {
        let c = ctx();
        c.server.set_default(Route::Token, Planned::empty_json(401));
        show(
            "doctor-token-401",
            &ts,
            &c,
            &["doctor", "--output", "json"],
            &opts,
        );
    }
    if wanted("doctor-scanner-401") {
        let c = ctx();
        c.server.set_default(
            Route::ScanResults,
            Planned::json(401, &json!({"message": "bad key"})),
        );
        show(
            "doctor-scanner-401",
            &ts,
            &c,
            &["doctor", "--output", "json"],
            &opts,
        );
    }
    if wanted("wrong-tsg") {
        let c = ctx();
        let mut config = c.tenant.config.clone();
        config.set("mgmtTsgId", "200");
        c.sandbox.write_fixture_config("prod", &config);
        show("wrong-tsg", &ts, &c, &list, &opts);
    }
    if wanted("no-tenant") {
        let c = ctx();
        c.sandbox.write_registry(&[c.tenant.entry()], None);
        show("no-tenant-selected", &ts, &c, &list, &opts);
        c.sandbox.write_registry(&[], None);
        show("no-tenants-registered", &ts, &c, &list, &opts);
    }
    if wanted("sigint") {
        let c = ctx();
        c.server.set_default(Route::Profiles, Planned::hang());
        let running = spawn(&ts, &c.sandbox, &list, &opts.clone().expect_signal());
        let arrived = c.server.wait_for_requests(2, Duration::from_secs(20));
        running.send_signal("INT");
        let out = running.wait();
        let disconnected = c.server.wait_for_disconnects(1, Duration::from_secs(5));
        println!("=== sigint-during-profiles-list");
        println!(
            "  requests arrived: {arrived}; exit {} signal {:?}; stdout {:?}; stderr {:?}; server saw disconnect: {disconnected}",
            out.code, out.signal, out.stdout, out.stderr
        );
        println!();
    }
}
