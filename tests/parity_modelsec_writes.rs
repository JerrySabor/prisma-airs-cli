//! TS-vs-Rust parity for the M6c step-2 model-security writes (DESIGN §17.3,
//! §17.8–§17.11).
//!
//! Each scenario runs once against airs-cli-rs and once against the TypeScript
//! reference, each on a fresh [`FixtureServer`] seeded with the model-security dataset
//! and a fresh [`Sandbox`] (configs are written into each sandbox's `tmp/`). `parity`
//! tests compare exit codes, the bytes (the TypeScript stdout without the outcome line
//! that airs-cli-rs prints on stderr, D190) and the normalised requests, bodies included.
//! `divergence` tests pin both sides of each §12 row this step implements (named by its
//! D#). The TypeScript side prints the fixture markers raw, so its runs disable the
//! marker check; the airs-cli-rs runs keep it.

use airs_test_harness::fixtures::modelsec as fx;
use airs_test_harness::{
    Cli, FixtureServer, GroupDeleteMode, ModelSecData, Ms, NormalizedRequest, Planned, Route, Run,
    RunOptions, Sandbox, normalize_all, require_ts, run, spawn,
};
use serde_json::{Value, json};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const TSG: &str = "100";
const BANNER: &str = "\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn u(n: u64) -> String {
    fx::uuid(n)
}

fn s(text: &str) -> String {
    text.to_owned()
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<NormalizedRequest>,
    routes: Vec<Route>,
    data: ModelSecData,
}

impl Side {
    fn count(&self, ms: Ms) -> usize {
        self.routes
            .iter()
            .filter(|route| **route == Route::ModelSecurity(ms))
            .count()
    }

    fn api(&self) -> Vec<Route> {
        self.routes
            .iter()
            .copied()
            .filter(|route| *route != Route::Token)
            .collect()
    }
}

/// What a scenario passes to one CLI: its arguments after `model-security`, built in
/// its own sandbox (a config is written into `tmp/` first).
type Args<'a> = &'a dyn Fn(&Sandbox, bool) -> Vec<String>;

/// Runs `cli` on a fresh seeded server and sandbox; `seed` edits the dataset; `plan`
/// queues planned answers before the run.
fn exec_with(
    cli: &Cli,
    args: Args<'_>,
    seed: &dyn Fn(&mut ModelSecData),
    plan: &dyn Fn(&FixtureServer),
) -> Side {
    let server = FixtureServer::start();
    server.seed_modelsec();
    server.modelsec(|data| seed(data));
    plan(&server);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    let mut full = vec![s("model-security")];
    full.extend(args(&sandbox, cli.is_ts()));
    let full: Vec<&str> = full.iter().map(String::as_str).collect();
    let options = if cli.is_ts() {
        RunOptions::new().allow_secret_output()
    } else {
        RunOptions::new()
    };
    let out = run(cli, &sandbox, &full, &options);
    let raw = server.requests();
    Side {
        run: out,
        requests: normalize_all(&raw),
        routes: raw.iter().map(|request| request.route).collect(),
        data: server.modelsec_data(),
    }
}

fn unchanged(_: &mut ModelSecData) {}
fn unplanned(_: &FixtureServer) {}

/// Both sides (`None` after a `PARITY SKIPPED` notice).
fn sides_with(
    name: &str,
    args: Args<'_>,
    seed: &dyn Fn(&mut ModelSecData),
    plan: &dyn Fn(&FixtureServer),
) -> Option<(Side, Side)> {
    let ts = require_ts(name)?;
    Some((
        exec_with(&rust(), args, seed, plan),
        exec_with(&ts, args, seed, plan),
    ))
}

fn sides(name: &str, args: Args<'_>) -> Option<(Side, Side)> {
    sides_with(name, args, &unchanged, &unplanned)
}

/// A file in the sandbox's `tmp/`; its absolute path.
fn file(sandbox: &Sandbox, name: &str, value: &Value) -> String {
    let path = sandbox.tmp().join(name);
    std::fs::write(&path, value.to_string()).unwrap();
    path.display().to_string()
}

fn context(r: &Side, t: &Side) -> String {
    format!("\n--- rust ---\n{:?}\n--- ts ---\n{:?}", r.run, t.run)
}

fn labels_json(pairs: &[(&str, &str)]) -> String {
    Value::Array(
        pairs
            .iter()
            .map(|(key, value)| json!({"key": key, "value": value}))
            .collect(),
    )
    .to_string()
}

fn group_config() -> Value {
    json!({
        "name": "g1",
        "source_type": "LOCAL",
        "description": "d1",
        "rule_configurations": {u(201): {"state": "BLOCKING"}}
    })
}

/// Parity of a write whose TypeScript stdout is the banner, the outcome line and (for
/// the writes that answer a record) the detail: airs-cli-rs prints the same stdout
/// without the outcome line (none at all for the writes without a record, which leave
/// stdout empty), and the outcome line alone on stderr (D190); exit codes and requests
/// equal.
fn assert_moved_outcome(r: &Side, t: &Side, outcome: &str, record: bool) {
    assert_eq!(r.run.code, 0, "{}", context(r, t));
    assert_eq!(t.run.code, 0, "{}", context(r, t));
    let line = format!("  ✓ {outcome}\n");
    assert!(
        t.run.stdout.starts_with(&format!("{BANNER}{line}")),
        "{}",
        context(r, t)
    );
    let expected = if record {
        t.run.stdout.replacen(&line, "", 1)
    } else {
        String::new()
    };
    assert_eq!(r.run.stdout, expected, "stdout{}", context(r, t));
    assert_eq!(r.run.stderr, line, "stderr{}", context(r, t));
    assert_eq!(t.run.stderr, "", "{}", context(r, t));
    assert_eq!(r.requests, t.requests, "requests differ{}", context(r, t));
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

mod parity {
    use super::*;

    /// `groups create|update`, `rule-instances update`, `scans create`: the TypeScript
    /// bodies and detail bytes (MS§5.3, §5.4, §7.3, §8.3).
    #[test]
    fn writes_with_a_record_match_typescript() {
        let (g, i) = (u(1), u(302));
        let create = |sandbox: &Sandbox, _: bool| {
            vec![
                s("groups"),
                s("create"),
                s("--config"),
                file(sandbox, "g.json", &group_config()),
            ]
        };
        let defaulted = |sandbox: &Sandbox, _: bool| {
            vec![
                s("groups"),
                s("create"),
                s("--config"),
                file(
                    sandbox,
                    "g.json",
                    &json!({"name": "g2", "source_type": "LOCAL"}),
                ),
            ]
        };
        let update = |_: &Sandbox, _: bool| {
            vec![
                s("groups"),
                s("update"),
                u(1),
                s("--name"),
                s("Updated"),
                s("--description"),
                s("new desc"),
            ]
        };
        let instance = |sandbox: &Sandbox, _: bool| {
            vec![
                s("rule-instances"),
                s("update"),
                u(1),
                u(302),
                s("--config"),
                file(
                    sandbox,
                    "ri.json",
                    &json!({"state": "ALLOWING", "field_values": {"approved_formats": ["onnx"]}}),
                ),
            ]
        };
        let scan = |sandbox: &Sandbox, _: bool| {
            vec![
                s("scans"),
                s("create"),
                s("--config"),
                file(
                    sandbox,
                    "s.json",
                    &json!({
                        "model_uri": "hf://org/model",
                        "security_group_uuid": u(1),
                        "scan_origin": "MODEL_SECURITY_SDK",
                        "labels": [{"key": "env", "value": "prod"}],
                        "unknown": "kept"
                    }),
                ),
            ]
        };
        let cases: [(Args<'_>, String); 5] = [
            (&create, format!("Group created: {}", u(101))),
            (&defaulted, format!("Group created: {}", u(101))),
            (&update, format!("Group updated: {g}")),
            (&instance, format!("Rule instance updated: {i}")),
            (&scan, format!("Scan created: {}", u(451))),
        ];
        for (args, outcome) in cases {
            let Some((r, t)) = sides("writes_with_a_record_match_typescript", args) else {
                return;
            };
            assert_moved_outcome(&r, &t, &outcome, true);
        }
    }

    /// `groups delete` (a hard delete, TS has no `--force`), `labels add` and `labels
    /// delete` (TS has no `--force`): the TypeScript requests and outcome lines.
    #[test]
    fn writes_without_a_record_match_typescript() {
        let g = u(1);
        let delete = |_: &Sandbox, ts: bool| {
            let mut args = vec![s("groups"), s("delete"), u(1)];
            if !ts {
                args.push(s("--force"));
            }
            args
        };
        let add = |_: &Sandbox, _: bool| {
            vec![
                s("labels"),
                s("add"),
                u(401),
                s("--labels"),
                labels_json(&[("env", "staging"), ("new", "x")]),
            ]
        };
        let remove = |_: &Sandbox, ts: bool| {
            let mut args = vec![
                s("labels"),
                s("delete"),
                u(401),
                s("--keys"),
                s("env, nope"),
            ];
            if !ts {
                args.push(s("--force"));
            }
            args
        };
        let cases: [(Args<'_>, String); 3] = [
            (&delete, format!("Group {g} deleted.")),
            (&add, s("Labels added.")),
            (&remove, s("Labels deleted.")),
        ];
        for (args, outcome) in cases {
            let Some((r, t)) = sides("writes_without_a_record_match_typescript", args) else {
                return;
            };
            assert_moved_outcome(&r, &t, &outcome, false);
            assert_eq!(
                r.data.scans, t.data.scans,
                "the service holds the same labels"
            );
        }
    }

    /// The `rm` alias of `groups delete` and `labels delete` (`aliases.spec.ts:66-86`).
    #[test]
    fn rm_aliases_match_typescript() {
        let delete = |_: &Sandbox, ts: bool| {
            let mut args = vec![s("groups"), s("rm"), u(1)];
            if !ts {
                args.push(s("--force"));
            }
            args
        };
        let remove = |_: &Sandbox, ts: bool| {
            let mut args = vec![s("labels"), s("rm"), u(401), s("--keys"), s("env")];
            if !ts {
                args.push(s("--force"));
            }
            args
        };
        let cases: [Args<'_>; 2] = [&delete, &remove];
        for args in cases {
            let Some((r, t)) = sides("rm_aliases_match_typescript", args) else {
                return;
            };
            assert_eq!(r.run.code, 0, "{}", context(&r, &t));
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            assert_eq!(r.requests, t.requests);
        }
    }

    /// A failed write: exit 1 with the `HTTP <s>` line on both sides; airs-cli-rs adds no
    /// outcome line to a plain rejection (a 404).
    #[test]
    fn rejected_writes_exit_1_with_the_status() {
        let update =
            |_: &Sandbox, _: bool| vec![s("groups"), s("update"), u(77), s("--name"), s("n")];
        let Some((r, t)) = sides("rejected_writes_exit_1_with_the_status", &update) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(r.run.http_status(), Some(404));
        assert_eq!(t.run.http_status(), Some(404));
        assert!(!r.run.stderr.contains("Outcome"));
        assert_eq!(r.requests, t.requests);
    }
}

// ---------------------------------------------------------------------------
// Divergences (§12 rows of step 2)
// ---------------------------------------------------------------------------

mod divergence {
    use super::*;

    /// D179: TypeScript re-sends a write after a 5xx (a group POST, a billed scan POST);
    /// airs-cli-rs sends it once and says the outcome is unknown. A 401 is `token, write,
    /// token, write` on both; a 403 is replayed by TypeScript only.
    #[test]
    fn d179_every_write_is_sent_once() {
        let create = |sandbox: &Sandbox, _: bool| {
            vec![
                s("groups"),
                s("create"),
                s("--config"),
                file(sandbox, "g.json", &group_config()),
            ]
        };
        let scan = |sandbox: &Sandbox, _: bool| {
            vec![
                s("scans"),
                s("create"),
                s("--config"),
                file(
                    sandbox,
                    "s.json",
                    &json!({"model_uri": "hf://org/model", "security_group_uuid": u(1)}),
                ),
            ]
        };
        let cases: [(Args<'_>, Ms, &str); 2] = [
            (
                &create,
                Ms::GroupCreate,
                "Outcome unknown: the security group may have been created.",
            ),
            (
                &scan,
                Ms::ScanCreate,
                "Outcome unknown: the scan may have been created.",
            ),
        ];
        for (args, route, line) in cases {
            let busy = move |server: &FixtureServer| {
                for _ in 0..2 {
                    server.push_once(
                        Route::ModelSecurity(route),
                        Planned::json(502, &json!({"message": "busy"})).with_retry_after(0),
                    );
                }
            };
            let Some((r, t)) = sides_with("d179_every_write_is_sent_once", args, &unchanged, &busy)
            else {
                return;
            };
            assert_eq!(r.run.code, 1);
            assert_eq!(r.count(route), 1, "{route:?}");
            assert!(r.run.stderr.contains(line), "{}", r.run.stderr);
            assert!(
                t.count(route) > 1,
                "TypeScript re-sends {route:?}: {}",
                t.count(route)
            );
        }
        let unauthorized = |server: &FixtureServer| {
            server.push_once(
                Route::ModelSecurity(Ms::GroupCreate),
                Planned::empty_json(401),
            );
        };
        let Some((r, t)) = sides_with(
            "d179_every_write_is_sent_once",
            &create,
            &unchanged,
            &unauthorized,
        ) else {
            return;
        };
        let replay = [
            Route::Token,
            Route::ModelSecurity(Ms::GroupCreate),
            Route::Token,
            Route::ModelSecurity(Ms::GroupCreate),
        ];
        assert_eq!(r.routes, replay);
        assert_eq!(t.routes, replay);
        assert_eq!((r.run.code, t.run.code), (0, 0));
        let forbidden = |server: &FixtureServer| {
            server.push_once(
                Route::ModelSecurity(Ms::GroupCreate),
                Planned::empty_json(403),
            );
        };
        let Some((r, t)) = sides_with(
            "d179_every_write_is_sent_once",
            &create,
            &unchanged,
            &forbidden,
        ) else {
            return;
        };
        assert_eq!(r.count(Ms::GroupCreate), 1);
        assert_eq!(r.run.code, 1);
        assert_eq!(t.count(Ms::GroupCreate), 2, "TypeScript replays a 403");
    }

    /// D185: without a terminal and `--force`, airs-cli-rs refuses `groups delete`,
    /// `labels set` and `labels delete` before the tenant; TypeScript changes the data.
    /// With `--force`, `labels set` reads the scan first and names what it drops.
    #[test]
    fn d185_destructive_writes_confirm() {
        let delete = |_: &Sandbox, _: bool| vec![s("groups"), s("delete"), u(1)];
        let set = |_: &Sandbox, _: bool| {
            vec![
                s("labels"),
                s("set"),
                u(401),
                s("--labels"),
                labels_json(&[("only", "x")]),
            ]
        };
        let remove =
            |_: &Sandbox, _: bool| vec![s("labels"), s("delete"), u(401), s("--keys"), s("env")];
        let cases: [(Args<'_>, String); 3] = [
            (
                &delete,
                format!(
                    "refusing to delete security group {} without --force in non-interactive mode",
                    u(1)
                ),
            ),
            (
                &set,
                format!(
                    "refusing to replace the labels of scan {} without --force in non-interactive mode",
                    u(401)
                ),
            ),
            (
                &remove,
                format!(
                    "refusing to delete labels from scan {} without --force in non-interactive mode",
                    u(401)
                ),
            ),
        ];
        for (args, refusal) in cases {
            let Some((r, t)) = sides("d185_destructive_writes_confirm", args) else {
                return;
            };
            assert_eq!(r.run.code, 2);
            assert_eq!(r.run.stderr, format!("\n  ✗ {refusal}\n\n"));
            assert!(r.routes.is_empty());
            assert_eq!(t.run.code, 0, "{}", context(&r, &t));
            assert!(
                t.api().iter().any(|route| route.is_write()),
                "TypeScript wrote"
            );
        }
        let forced = |_: &Sandbox, ts: bool| {
            let mut args = vec![
                s("labels"),
                s("set"),
                u(401),
                s("--labels"),
                labels_json(&[("only", "x")]),
            ];
            if !ts {
                args.push(s("--force"));
            }
            args
        };
        let Some((r, t)) = sides("d185_destructive_writes_confirm", &forced) else {
            return;
        };
        assert_eq!(
            r.run.stderr,
            "  ⚠ The replacement drops 2 label(s) the scan has now: env, team\n  ✓ Labels set.\n"
        );
        assert_eq!(
            r.api(),
            [
                Route::ModelSecurity(Ms::ScanGet),
                Route::ModelSecurity(Ms::LabelsSet)
            ]
        );
        assert_eq!(t.api(), [Route::ModelSecurity(Ms::LabelsSet)]);
        assert_eq!(t.run.stdout, format!("{BANNER}  ✓ Labels set.\n"));
        assert_eq!(r.data.scans, t.data.scans);
    }

    /// D186: a failed verification read is "deleted" for TypeScript and "not verified"
    /// for airs-cli-rs; a tombstone is "still reports state" for TypeScript and "deleted
    /// (the service is removing it)" for airs-cli-rs. Exit 0 on both.
    #[test]
    fn d186_a_delete_is_confirmed_only_by_a_404_or_a_tombstone() {
        let g = u(1);
        let delete = |_: &Sandbox, ts: bool| {
            let mut args = vec![s("groups"), s("delete"), u(1)];
            if !ts {
                args.push(s("--force"));
            }
            args
        };
        let failing = |server: &FixtureServer| {
            server.set_default(
                Route::ModelSecurity(Ms::GroupGet),
                Planned::json(500, &json!({"message": "busy"})).with_retry_after(0),
            );
        };
        let Some((r, t)) = sides_with(
            "d186_a_delete_is_confirmed_only_by_a_404_or_a_tombstone",
            &delete,
            &|data| data.group_delete = GroupDeleteMode::StillActive,
            &failing,
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (0, 0));
        assert_eq!(t.run.stdout, format!("{BANNER}  ✓ Group {g} deleted.\n"));
        assert_eq!(
            r.run.stderr,
            format!(
                "  ⚠ Delete request accepted, but its result could not be verified; re-check with 'airs model-security groups get {g}'.\n"
            )
        );
        let Some((r, t)) = sides_with(
            "d186_a_delete_is_confirmed_only_by_a_404_or_a_tombstone",
            &delete,
            &|data| data.group_delete = GroupDeleteMode::Tombstone,
            &unplanned,
        ) else {
            return;
        };
        assert!(
            t.run.stdout.contains(&format!(
                "  ⚠ Delete request accepted, but group {g} still reports state 'ACTIVE'.\n"
            )),
            "{}",
            t.run.stdout
        );
        assert_eq!(
            r.run.stderr,
            format!("  ✓ Group {g} deleted (the service is removing it).\n")
        );
    }

    /// D187: TypeScript sends `PUT {}` for `groups update` without a flag, cannot clear a
    /// description, sends `{security_group_uuid}` for an empty rule-instance file and
    /// `?keys=` for `--keys ''`, reporting success each time; airs-cli-rs refuses or sends
    /// the change.
    #[test]
    fn d187_writes_must_change_what_they_name() {
        let bare = |_: &Sandbox, _: bool| vec![s("groups"), s("update"), u(1)];
        let Some((r, t)) = sides("d187_writes_must_change_what_they_name", &bare) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ groups update needs --name or --description\n\n"
        );
        assert!(r.routes.is_empty());
        assert_eq!(t.run.code, 0);
        assert_eq!(t.count(Ms::GroupUpdate), 1);
        let clear =
            |_: &Sandbox, _: bool| vec![s("groups"), s("update"), u(1), s("--description"), s("")];
        let Some((r, t)) = sides("d187_writes_must_change_what_they_name", &clear) else {
            return;
        };
        let body = |side: &Side| {
            side.requests
                .iter()
                .find(|request| request.route == Route::ModelSecurity(Ms::GroupUpdate))
                .map(|request| format!("{:?}", request.body))
                .unwrap_or_default()
        };
        assert!(body(&r).contains("description"), "{}", body(&r));
        assert!(!body(&t).contains("description"), "{}", body(&t));
        assert_eq!(r.data.groups[0]["description"], "");
        assert_eq!(t.data.groups[0]["description"], "Auto group");
        let empty = |sandbox: &Sandbox, _: bool| {
            vec![
                s("rule-instances"),
                s("update"),
                u(1),
                u(302),
                s("--config"),
                file(sandbox, "ri.json", &json!({})),
            ]
        };
        let Some((r, t)) = sides("d187_writes_must_change_what_they_name", &empty) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert!(r.run.stderr.contains("must set state or field_values"));
        assert!(r.routes.is_empty());
        assert_eq!(t.run.code, 0);
        assert_eq!(t.count(Ms::RuleInstanceUpdate), 1);
        let keys = |_: &Sandbox, ts: bool| {
            let mut args = vec![s("labels"), s("delete"), u(401), s("--keys"), s("")];
            if !ts {
                args.push(s("--force"));
            }
            args
        };
        let Some((r, t)) = sides("d187_writes_must_change_what_they_name", &keys) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(r.run.stderr, "\n  ✗ --keys values must not be empty\n\n");
        assert_eq!(t.run.code, 0);
        assert_eq!(t.count(Ms::LabelsDelete), 1);
    }

    /// D188: a config's unknown key is dropped silently by TypeScript and refused by
    /// airs-cli-rs; invalid JSON is quoted by TypeScript and named by path only here; a
    /// rule-instance file naming another group is ignored by TypeScript; a missing file
    /// is an OS error after the tenant in TypeScript.
    #[test]
    fn d188_config_files_are_checked_first_and_never_echoed() {
        let unknown = |sandbox: &Sandbox, _: bool| {
            let mut config = group_config();
            config["owner"] = json!(fx::secret(5));
            vec![
                s("groups"),
                s("create"),
                s("--config"),
                file(sandbox, "g.json", &config),
            ]
        };
        let Some((r, t)) = sides(
            "d188_config_files_are_checked_first_and_never_echoed",
            &unknown,
        ) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert!(r.run.stderr.contains("has an unknown key owner; a security group config takes name, source_type, description and rule_configurations"));
        assert!(r.routes.is_empty());
        assert_eq!(t.run.code, 0);
        let sent = t
            .requests
            .iter()
            .find(|request| request.route == Route::ModelSecurity(Ms::GroupCreate))
            .map(|request| format!("{:?}", request.body))
            .unwrap_or_default();
        assert!(
            !sent.contains("owner"),
            "TypeScript dropped the key: {sent}"
        );
        let broken = |sandbox: &Sandbox, _: bool| {
            let path = sandbox.tmp().join("g.json");
            std::fs::write(&path, "MS-PRIVATE-TEXT").unwrap();
            vec![
                s("groups"),
                s("create"),
                s("--config"),
                path.display().to_string(),
            ]
        };
        let Some((r, t)) = sides(
            "d188_config_files_are_checked_first_and_never_echoed",
            &broken,
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert!(
            r.run.stderr.ends_with("g.json is not valid JSON\n\n"),
            "{}",
            r.run.stderr
        );
        assert!(
            t.run.stderr.contains("MS-PRIVATE-TEXT"),
            "TypeScript quotes the content"
        );
        assert!(!r.run.stderr.contains("MS-PRIVATE"), "{}", r.run.stderr);
        assert!(r.routes.is_empty());
        let elsewhere = |sandbox: &Sandbox, _: bool| {
            vec![
                s("rule-instances"),
                s("update"),
                u(1),
                u(302),
                s("--config"),
                file(
                    sandbox,
                    "ri.json",
                    &json!({"security_group_uuid": u(2), "state": "BLOCKING"}),
                ),
            ]
        };
        let Some((r, t)) = sides(
            "d188_config_files_are_checked_first_and_never_echoed",
            &elsewhere,
        ) else {
            return;
        };
        assert_eq!(r.run.code, 1);
        assert!(
            r.run
                .stderr
                .contains(&format!("names another security group than {}", u(1)))
        );
        assert_eq!(t.run.code, 0);
        let missing = |sandbox: &Sandbox, _: bool| {
            vec![
                s("scans"),
                s("create"),
                s("--config"),
                sandbox.tmp().join("missing.json").display().to_string(),
            ]
        };
        let Some((r, t)) = sides(
            "d188_config_files_are_checked_first_and_never_echoed",
            &missing,
        ) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert!(r.run.stderr.contains("Cannot read "), "{}", r.run.stderr);
        assert!(t.run.stderr.contains("ENOENT"), "{}", t.run.stderr);
        assert!(r.routes.is_empty());
        assert!(
            t.run.stdout.starts_with(BANNER),
            "TypeScript printed its banner first"
        );
        assert_eq!(r.run.stdout, "");
    }

    /// D189: TypeScript ignores `--output` on a write (pretty bytes); airs-cli-rs prints
    /// the record as json.
    #[test]
    fn d189_writes_honour_output() {
        let create = |sandbox: &Sandbox, _: bool| {
            vec![
                s("groups"),
                s("create"),
                s("--config"),
                file(sandbox, "g.json", &group_config()),
                s("--output"),
                s("json"),
            ]
        };
        let Some((r, t)) = sides("d189_writes_honour_output", &create) else {
            return;
        };
        assert!(t.run.stdout.starts_with(BANNER), "{}", t.run.stdout);
        assert_eq!(r.run.json()["uuid"], u(101));
        assert_eq!(r.run.json()["name"], "g1");
        assert_eq!(r.requests, t.requests);
    }

    /// D190: TypeScript prints the outcome line on stdout and keeps it under `--quiet`,
    /// and a failed write leaves its banner on stdout; airs-cli-rs prints it on stderr,
    /// drops it under `--quiet` and leaves stdout empty on failure.
    #[test]
    fn d190_write_outcome_lines_go_to_stderr() {
        let add = |_: &Sandbox, _: bool| {
            vec![
                s("--quiet"),
                s("labels"),
                s("add"),
                u(401),
                s("--labels"),
                labels_json(&[("a", "b")]),
            ]
        };
        let Some((r, t)) = sides("d190_write_outcome_lines_go_to_stderr", &add) else {
            return;
        };
        assert_eq!(t.run.stdout, "  ✓ Labels added.\n");
        assert_eq!(r.run.stdout, "");
        assert_eq!(r.run.stderr, "");
        let failing = |_: &Sandbox, _: bool| {
            vec![
                s("labels"),
                s("add"),
                u(499),
                s("--labels"),
                labels_json(&[("a", "b")]),
            ]
        };
        let Some((r, t)) = sides("d190_write_outcome_lines_go_to_stderr", &failing) else {
            return;
        };
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert_eq!(t.run.stdout, BANNER);
        assert_eq!(r.run.stdout, "");
    }

    /// D191: a `scans create` config's URI is printed raw by TypeScript and withheld by
    /// airs-cli-rs.
    #[test]
    fn d191_a_created_scan_uri_is_withheld() {
        let scan = |sandbox: &Sandbox, _: bool| {
            let uri = format!(
                "https://{}:{}@models.example.invalid/m.bin?sig={}",
                fx::secret(1),
                fx::secret(2),
                fx::secret(3)
            );
            vec![
                s("scans"),
                s("create"),
                s("--config"),
                file(
                    sandbox,
                    "s.json",
                    &json!({"model_uri": uri, "security_group_uuid": u(1)}),
                ),
            ]
        };
        let Some((r, t)) = sides("d191_a_created_scan_uri_is_withheld", &scan) else {
            return;
        };
        assert!(
            t.run.stdout.contains(&fx::secret(2)),
            "TypeScript prints the URI raw"
        );
        assert!(
            r.run.stdout.contains(
                "  Model URI  https://[withheld]@models.example.invalid/m.bin?[withheld]\n"
            ),
            "{}",
            r.run.stdout
        );
        assert_eq!(r.requests, t.requests);
    }

    /// D193: an interrupted held `groups create`: TypeScript exits with nothing on
    /// stderr; airs-cli-rs says the change may already have been applied.
    #[test]
    fn d193_an_interrupted_write_prints_its_context() {
        let Some(ts) = require_ts("d193_an_interrupted_write_prints_its_context") else {
            return;
        };
        let mut outs = Vec::new();
        for cli in [rust(), ts] {
            let server = FixtureServer::start();
            server.seed_modelsec();
            server.push_once(Route::ModelSecurity(Ms::GroupCreate), Planned::held());
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            let config = file(&sandbox, "g.json", &group_config());
            let options = if cli.is_ts() {
                RunOptions::new().expect_signal().allow_secret_output()
            } else {
                RunOptions::new().expect_signal()
            };
            let running = spawn(
                &cli,
                &sandbox,
                &["model-security", "groups", "create", "--config", &config],
                &options,
            );
            assert!(server.wait_for_route(
                Route::ModelSecurity(Ms::GroupCreate),
                1,
                Duration::from_secs(20)
            ));
            running.send_signal("INT");
            let out = running.wait();
            server.release_held();
            outs.push((out, server.ms_requests(Ms::GroupCreate).len()));
        }
        let (rust_out, rust_posts) = &outs[0];
        assert_eq!(rust_out.code, 130);
        assert_eq!(
            rust_out.stderr,
            "\n  ✗ Error: Interrupted; the change may already have been applied (outcome unknown)\n\n"
        );
        assert_eq!(*rust_posts, 1);
        let (ts_out, _) = &outs[1];
        assert_eq!(ts_out.code, 130);
        assert_eq!(ts_out.stderr, "");
    }

    /// D116 (extended): TypeScript names the failing fields of a group body; airs-cli-rs
    /// names the request only (exit 1 for a file body, before the tenant).
    #[test]
    fn d116_model_security_body_text_without_field_paths() {
        let create = |sandbox: &Sandbox, _: bool| {
            vec![
                s("groups"),
                s("create"),
                s("--config"),
                file(
                    sandbox,
                    "g.json",
                    &json!({"name": "", "source_type": "FTP"}),
                ),
            ]
        };
        let Some((r, t)) = sides("d116_model_security_body_text_without_field_paths", &create)
        else {
            return;
        };
        let text = "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/security-groups did not match schema";
        assert_eq!((r.run.code, t.run.code), (1, 1));
        assert!(
            r.run.stderr.contains(&format!("{text}\n")),
            "{}",
            r.run.stderr
        );
        assert!(
            t.run.stderr.contains(&format!("{text}: ")),
            "{}",
            t.run.stderr
        );
        assert!(r.routes.is_empty());
    }

    /// D11 (extended): TypeScript echoes a write error's server `message`; airs-cli-rs
    /// prints the status only.
    #[test]
    fn d11_model_security_write_errors_do_not_echo_server_text() {
        let update =
            |_: &Sandbox, _: bool| vec![s("groups"), s("update"), u(1), s("--name"), s("n")];
        let rejecting = |server: &FixtureServer| {
            server.push_once(
                Route::ModelSecurity(Ms::GroupUpdate),
                Planned::json(400, &json!({"message": "bad PRIVATE-ECHO value"})),
            );
        };
        let Some((r, t)) = sides_with(
            "d11_model_security_write_errors_do_not_echo_server_text",
            &update,
            &unchanged,
            &rejecting,
        ) else {
            return;
        };
        assert!(t.run.stderr.contains("PRIVATE-ECHO"), "{}", t.run.stderr);
        assert!(!r.run.stderr.contains("PRIVATE-ECHO"), "{}", r.run.stderr);
        assert!(
            r.run
                .stderr
                .contains("AISEC_CLIENT_SIDE_ERROR:API error 400\n")
        );
    }

    /// D50 (extended): TypeScript ignores `--output yaml` on a write and sends it;
    /// airs-cli-rs refuses it before the tenant.
    #[test]
    fn d50_dropped_formats_are_usage_errors_on_model_security_writes() {
        let add = |_: &Sandbox, _: bool| {
            vec![
                s("labels"),
                s("add"),
                u(401),
                s("--labels"),
                labels_json(&[("a", "b")]),
                s("--output"),
                s("yaml"),
            ]
        };
        let Some((r, t)) = sides(
            "d50_dropped_formats_are_usage_errors_on_model_security_writes",
            &add,
        ) else {
            return;
        };
        assert_eq!(r.run.code, 2);
        assert_eq!(
            r.run.stderr,
            "\n  ✗ Invalid output format 'yaml'. Expected: pretty, table, json\n\n"
        );
        assert!(r.routes.is_empty());
        assert_eq!(t.run.code, 0);
        assert_eq!(t.count(Ms::LabelsAdd), 1);
    }

    /// D184 (extended): a write's id is a usage error before the tenant here; TypeScript
    /// fails in its SDK after the banner and the tenant (exit 1).
    #[test]
    fn d184_write_ids_are_checked_before_the_tenant() {
        let update = |_: &Sandbox, _: bool| {
            vec![
                s("groups"),
                s("update"),
                s("not-a-uuid"),
                s("--name"),
                s("n"),
            ]
        };
        let Some((r, t)) = sides("d184_write_ids_are_checked_before_the_tenant", &update) else {
            return;
        };
        let text = "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: not-a-uuid";
        assert_eq!(r.run.code, 2);
        assert_eq!(r.run.stderr, format!("\n  ✗ {text}\n\n"));
        assert_eq!(t.run.code, 1);
        assert!(t.run.stderr.contains(text), "{}", t.run.stderr);
        assert!(t.run.stdout.starts_with(BANNER));
        assert!(r.routes.is_empty() && t.api().is_empty());
    }

    /// D52 (extended): a control character in an answered group name reaches the
    /// terminal from TypeScript and is replaced here.
    #[test]
    fn d52_control_characters_in_write_layouts_are_replaced() {
        let create = |sandbox: &Sandbox, _: bool| {
            vec![
                s("groups"),
                s("create"),
                s("--config"),
                file(
                    sandbox,
                    "g.json",
                    &json!({"name": "Evil\u{1b}[31m", "source_type": "LOCAL"}),
                ),
            ]
        };
        let Some((r, t)) = sides(
            "d52_control_characters_in_write_layouts_are_replaced",
            &create,
        ) else {
            return;
        };
        assert!(t.run.stdout.contains("Evil\u{1b}[31m"));
        assert!(r.run.stdout.contains("Evil\u{fffd}[31m"));
        assert!(!r.run.stdout.contains('\u{1b}'));
    }
}
