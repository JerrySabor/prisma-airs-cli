//! Executable acceptance tests for `runtime profiles backup` and `runtime profiles restore`
//! (DESIGN §18.15, §18.16): the TypeScript `tests/integration/tenant-profile-transfer.spec.ts`
//! cases and the executor cases of `tests/unit/backup/runtime-profiles.spec.ts` against the
//! loopback fixture server (the planner cases are unit tests in
//! `src/runtime/transfer/plan_tests.rs`, `compareRuntimePolicies` in
//! `src/runtime/transfer/policy.rs`), plus the Rust additions: the Rust format and its
//! strict reader (D215, D216), the TSG checks, one attempt per write and the
//! outcome-unknown stop (D217), absent collections (D218), confirmations and
//! interruption (D224).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use airs_test_harness::{
    Cli, Collection, Dl, FixtureServer, Planned, RecordedRequest, Route, Run, RunOptions, Sandbox,
    fixtures, run, spawn, spawn_pty,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

const SOURCE: &str = "100";
const DEST: &str = "200";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

/// The referenced topic (`Restricted`, revision 3).
fn topic() -> Value {
    fixtures::topic(11, "Restricted", 3, "Restricted business topics")
}

/// `Production` (revision 2) referencing [`topic`] from a blocked topic-guardrails list.
fn production(revision: u64) -> Value {
    let mut profile = fixtures::profile(1, "Production", revision);
    profile["tsg_id"] = json!(SOURCE);
    profile["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"] = json!([{
        "name": "topic-guardrails", "action": "",
        "topic-list": [{"action": "block", "topic": [
            {"topic_name": "Restricted", "topic_id": fixtures::uuid(11), "revision": 3}
        ]}]
    }]);
    profile
}

/// `Staging`: no topic, no DLP.
fn staging() -> Value {
    let mut profile = fixtures::profile(2, "Staging", 1);
    profile["tsg_id"] = json!(SOURCE);
    profile
}

/// [`staging`] with a custom DLP member and an embedded DLP entry (`My Profile`).
fn with_dlp() -> Value {
    let mut profile = staging();
    let policy = &mut profile["policy"];
    policy["dlp-data-profiles"] = json!([{"name": "My Profile", "uuid": "dp-src", "id": "dp-src",
        "version": "1", "rule1": {"action": "block"}}]);
    policy["ai-security-profiles"][0]["model-configuration"]["data-protection"] = json!({
        "data-leak-detection": {"action": "block",
            "member": [{"text": "My Profile", "id": "dp-src", "version": "1"}]}
    });
    profile
}

struct Fx {
    server: FixtureServer,
    sandbox: Sandbox,
}

/// One fixture server with the source TSG 100 seeded (`Production`, `Staging`, the
/// topic, and an older `Production` revision) and a tenant `prod` of `tsg`.
fn fx(tsg: &str) -> Fx {
    let server = FixtureServer::start();
    server.seed_dlp();
    server.set_profiles(SOURCE, vec![production(1), production(2), staging()]);
    server.set_topics(SOURCE, vec![topic()]);
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", tsg);
    Fx { server, sandbox }
}

impl Fx {
    fn tmp(&self, name: &str) -> String {
        self.sandbox.tmp().join(name).display().to_string()
    }

    fn profiles(&self, args: &[&str]) -> Run {
        let mut full = vec!["runtime", "profiles"];
        full.extend_from_slice(args);
        let out = run(
            &rust(),
            &self.sandbox,
            &full,
            &RunOptions::new().allow_writes_under("cwd"),
        );
        self.server.assert_no_unknown_routes();
        out
    }

    /// The API requests (no token request).
    fn api(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|request| request.route != Route::Token)
            .map(RecordedRequest::line)
            .collect()
    }

    fn writes(&self) -> Vec<RecordedRequest> {
        self.server
            .requests()
            .into_iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    /// A Rust backup of `selector` (all when empty) from TSG 100, written to `tmp/<name>`.
    fn backup_file(&self, name: &str, selector: &[&str]) -> String {
        let path = self.tmp(name);
        let mut args = vec!["backup"];
        args.extend_from_slice(selector);
        args.extend(["--output-file", &path]);
        self.profiles(&args).assert_success();
        self.server.clear_requests();
        path
    }

    fn write(&self, name: &str, text: &str) -> String {
        let path = self.tmp(name);
        std::fs::write(&path, text).unwrap();
        path
    }
}

/// A Rust backup made against TSG 100 and then restored on a tenant of `tsg`.
fn restore_fx(tsg: &str, selector: &[&str]) -> (Fx, String) {
    let source = fx(SOURCE);
    let file = source.backup_file("b.json", selector);
    let text = std::fs::read_to_string(&file).unwrap();
    let dest = fx(tsg);
    let path = dest.write("b.json", &text);
    (dest, path)
}

fn mode(path: &str) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn temporaries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".airs-"))
        .collect()
}

fn json_of(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

const PROFILES_100: &str = "GET /aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100&latest=true";
const TOPICS_100: &str = "GET /aisec/v1/mgmt/topics/tsg/100?offset=0&limit=100";
const PROFILES_200: &str = "GET /aisec/v1/mgmt/profiles/tsg/200?offset=0&limit=100&latest=true";
const TOPICS_200: &str = "GET /aisec/v1/mgmt/topics/tsg/200?offset=0&limit=100";
const FORCE: [&str; 4] = ["--allow-other-tenant", "--expect-tsg", DEST, "--force"];

// ---------------------------------------------------------------------------
// backup (§18.15)
// ---------------------------------------------------------------------------

mod backup {
    use super::*;

    /// TS: the backup summary, 0600, every policy and topic in the file; the latest
    /// revision per name; the topic inventory read for the reference.
    #[test]
    fn writes_the_rust_format_at_0600() {
        let f = fx(SOURCE);
        let path = f.tmp("all.json");
        let out = f.profiles(&["backup", "--all", "--output-file", &path]);
        out.assert_success();
        assert_eq!(f.api(), [PROFILES_100, TOPICS_100]);
        assert_eq!(mode(&path), 0o600);
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
        let width = path.chars().count().max("Backup file".len());
        let header = format!(
            " {:<width$} │ Source TSG │ Profiles │ Topics ",
            "Backup file"
        );
        assert_eq!(
            out.stdout,
            format!(
                "{header}\n{}┼────────────┼──────────┼────────\n {path:<width$} │ 100        │ 2        │ 1      \n",
                "─".repeat(width + 2)
            )
        );
        assert_eq!(
            out.stderr,
            format!(
                "  ⚠ {path} contains security profile policies and topic definitions; keep it private (mode 0600)\n"
            )
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("}\n"));
        let file: Value = serde_json::from_str(&text).unwrap();
        let keys: Vec<&String> = file.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 8);
        assert_eq!(file["format"], "airs-cli-rs.runtime-profiles");
        assert_eq!(file["version"], 1);
        assert_eq!(file["tenant"], "prod");
        assert_eq!(file["tsgId"], SOURCE);
        assert_eq!(file["selector"], Value::Null);
        let names: Vec<&str> = file["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Production", "Staging"]);
        assert_eq!(file["profiles"][0]["revision"], 2, "the latest revision");
        assert_eq!(file["profiles"][0]["id"], fixtures::uuid(1));
        assert_eq!(file["profiles"][0]["record"], production(2));
        assert_eq!(file["topics"][0]["record"], topic());
        assert!(text.find("\"format\"").unwrap() < text.find("\"profiles\"").unwrap());
    }

    /// TS: the json summary is a one-element array; table is the pretty table; the
    /// default name lands in the working directory (TS name).
    #[test]
    fn summaries_and_the_default_name() {
        let f = fx(SOURCE);
        let out = f.profiles(&["backup", "Staging", "--output", "json"]);
        out.assert_success();
        let summary = out.json();
        let file = summary[0]["file"].as_str().unwrap().to_owned();
        assert!(
            file.starts_with("./airs-runtime-profiles-backup-"),
            "{file}"
        );
        assert_eq!(
            summary,
            json!([{"file": file, "sourceTsgId": SOURCE, "profiles": 1, "topics": 0}])
        );
        let on_disk = f.sandbox.cwd().join(file.trim_start_matches("./"));
        assert_eq!(mode(&on_disk.display().to_string()), 0o600);
        assert_eq!(f.api(), [PROFILES_100], "no topic read without a reference");
        let backup = json_of(&on_disk.display().to_string());
        assert_eq!(backup["selector"], "Staging");
        let path = f.tmp("t.json");
        let table = f.profiles(&[
            "backup",
            fixtures::uuid(2).as_str(),
            "--output-file",
            &path,
            "--output",
            "table",
        ]);
        table.assert_success();
        assert!(table.stdout.starts_with(" Backup file"), "{}", table.stdout);
        assert!(
            table
                .stdout
                .contains(" │ 100        │ 1        │ 0      \n")
        );
        assert_eq!(
            json_of(&path)["profiles"][0]["name"],
            "Staging",
            "selected by id"
        );
    }

    /// The §18.15 argument checks (exit 2, no request, no debug log), in order.
    #[test]
    fn argument_checks_come_before_the_tenant() {
        let f = fx(SOURCE);
        let json_file = f.tmp("x.json");
        for (args, message) in [
            (
                vec!["--debug", "runtime", "profiles", "backup"],
                "Disable --debug for profile transfer; backups can contain sensitive policy configuration",
            ),
            (
                vec!["runtime", "profiles", "backup", "--max-pages", "0"],
                "--max-pages must be an integer from 1 to 1000",
            ),
            (
                vec!["runtime", "profiles", "backup", "--max-pages", "1001"],
                "--max-pages must be an integer from 1 to 1000",
            ),
            (
                vec!["runtime", "profiles", "backup", "--max-pages", "1e2"],
                "--max-pages must be an integer from 1 to 1000",
            ),
            (
                vec!["runtime", "profiles", "backup", "P", "--all"],
                "Choose either a profile selector or --all",
            ),
            (
                vec!["runtime", "profiles", "backup", "--file-format", "yaml"],
                "--file-format must be json (yaml was dropped)",
            ),
            (
                vec!["runtime", "profiles", "backup", "--file-format", "exe"],
                "--file-format must be json (yaml was dropped)",
            ),
            (
                vec!["runtime", "profiles", "backup", "--output-file", "-"],
                "Backups require a private file destination, not stdout",
            ),
            (
                vec!["runtime", "profiles", "backup", "--output-file", ""],
                "--output-file needs a path",
            ),
            (
                vec!["runtime", "profiles", "backup", "--output-file", "x.yaml"],
                "Backup filename extension must match --file-format",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "backup",
                    " ",
                    "--output-file",
                    &json_file,
                ],
                "Profile selector must not be empty",
            ),
            (
                vec!["runtime", "profiles", "backup", "--output", "yaml"],
                "Invalid output format 'yaml'. Expected: pretty, table, json",
            ),
        ] {
            let out = run(&rust(), &f.sandbox, &args, &RunOptions::new());
            out.assert_code(2);
            assert!(out.stderr.contains(message), "{args:?}: {}", out.stderr);
            assert_eq!(out.stdout, "");
        }
        assert!(f.server.requests().is_empty());
        assert!(!f.sandbox.home().join(".local/state/airs-cli").exists());
    }

    /// D215: an existing path (a dangling symlink included) or a missing directory is
    /// refused before the tenant, with no request; the file is unchanged.
    #[test]
    fn the_destination_is_checked_before_any_request() {
        let f = fx(SOURCE);
        let existing = f.write("exists.json", "keep");
        let dangling = f.tmp("dangling.json");
        std::os::unix::fs::symlink(f.tmp("nowhere"), &dangling).unwrap();
        for path in [&existing, &dangling] {
            let out = f.profiles(&["backup", "--output-file", path]);
            out.assert_code(1);
            assert!(
                out.stderr.contains(&format!(
                    "{path} already exists; choose another --output-file"
                )),
                "{}",
                out.stderr
            );
        }
        // D226: a path that names no file (its extension still reads `json`).
        for name in ["b.json/", "b.json/."] {
            let path = f.tmp(name);
            let out = f.profiles(&["backup", "--output-file", &path]);
            out.assert_code(1);
            assert!(
                out.stderr.contains(&format!(
                    "Cannot write {path}; check that its directory exists and is writable"
                )),
                "{}",
                out.stderr
            );
        }
        assert!(!Path::new(&f.tmp("b.json")).exists());
        let missing = f.tmp("no-dir/b.json");
        let out = f.profiles(&["backup", "--output-file", &missing]);
        out.assert_code(1);
        assert!(out.stderr.contains(&format!(
            "Cannot write a backup into {}; it must be an existing directory",
            f.tmp("no-dir")
        )));
        assert!(f.server.requests().is_empty());
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "keep");
        // TS: a second backup to the same path is refused, the file unchanged.
        let path = f.tmp("again.json");
        f.profiles(&["backup", "--output-file", &path])
            .assert_success();
        let first = std::fs::read(&path).unwrap();
        f.server.clear_requests();
        f.profiles(&["backup", "--output-file", &path])
            .assert_code(1);
        assert!(f.server.requests().is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), first);
    }

    fn refused(f: &Fx, args: &[&str], message: &str) {
        let path = f.tmp(&format!("r{}.json", f.server.requests().len()));
        let mut full = vec!["backup"];
        full.extend_from_slice(args);
        full.extend(["--output-file", &path]);
        let out = f.profiles(&full);
        out.assert_code(1);
        assert_eq!(out.stdout, "");
        assert!(out.stderr.contains(message), "{message}: {}", out.stderr);
        assert!(!Path::new(&path).exists());
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
    }

    /// TS selection and inventory rules (`runtime-profiles.spec.ts`, "Runtime profile
    /// backup"), plus D218.
    #[test]
    fn selection_and_inventory_rules() {
        let f = fx(SOURCE);
        refused(&f, &["Missing"], "No matching profiles to back up");
        let mut other = production(2);
        other["profile_id"] = json!("different");
        f.server.push_once(
            Route::Profiles,
            Planned::json(200, &json!({"ai_profiles": [production(2), other]})),
        );
        refused(&f, &[], "Ambiguous profile name: Production");
        f.server.set_profiles(
            SOURCE,
            vec![{
                let mut other = staging();
                other["tsg_id"] = json!("200");
                other
            }],
        );
        refused(
            &f,
            &[],
            "Destination/source profile tenant identity does not match the selected TSG",
        );
        f.server.set_profiles(
            SOURCE,
            vec![{
                let mut bare = staging();
                bare.as_object_mut().unwrap().remove("policy");
                bare
            }],
        );
        refused(&f, &[], "Profile has no policy: Staging");
        f.server.push_once(
            Route::Profiles,
            Planned::json(200, &json!({"ai_profiles": [staging(), staging()]})),
        );
        refused(&f, &[], "Inventory contains repeated profile records");
        // Exact topics: absent, another revision, duplicated.
        f.server.set_profiles(SOURCE, vec![production(2)]);
        for topics in [
            vec![],
            vec![fixtures::topic(11, "Restricted", 4, "d")],
            vec![topic(), topic()],
        ] {
            f.server.set_topics(SOURCE, topics);
            refused(
                &f,
                &[],
                "Cannot export the exact referenced topic revision: Restricted revision 3",
            );
        }
        // D218: an absent collection is not an empty inventory.
        f.server.set_topics(SOURCE, vec![topic()]);
        f.server
            .push_once(Route::Profiles, Planned::json(200, &json!({})));
        refused(
            &f,
            &[],
            "Inventory of security profiles was not returned; retry the operation",
        );
        f.server.push_once(
            Route::Topics,
            Planned::json(200, &json!({"next_offset": 0})),
        );
        refused(
            &f,
            &[],
            "Inventory of custom topics was not returned; retry the operation",
        );
        // Stalled and capped walks.
        f.server.push_once(
            Route::Profiles,
            Planned::json(200, &json!({"ai_profiles": [], "next_offset": 5})),
        );
        refused(&f, &[], "Inventory pagination did not advance");
        f.server.set_profiles(
            SOURCE,
            (0..3)
                .map(|n| fixtures::profile(30 + n, &format!("P{n}"), 1))
                .collect(),
        );
        let path = f.tmp("capped.json");
        f.server.clear_requests();
        let out = f.profiles(&["backup", "--max-pages", "1", "--output-file", &path]);
        assert_eq!(f.api().len(), 1);
        out.assert_success();
    }

    /// TS walks complete pages (`next_offset` until absent or 0).
    #[test]
    fn walks_every_page() {
        let f = fx(SOURCE);
        let many: Vec<Value> = (0..150)
            .map(|n| fixtures::profile(100 + n, &format!("P{n:03}"), 1))
            .collect();
        f.server.set_profiles(SOURCE, many);
        let path = f.tmp("many.json");
        f.profiles(&["backup", "--output-file", &path])
            .assert_success();
        assert_eq!(
            f.api(),
            [
                PROFILES_100,
                "GET /aisec/v1/mgmt/profiles/tsg/100?offset=100&limit=100&latest=true"
            ]
        );
        assert_eq!(json_of(&path)["profiles"].as_array().unwrap().len(), 150);
        let f = fx(SOURCE);
        f.server.set_profiles(
            SOURCE,
            (0..150)
                .map(|n| fixtures::profile(100 + n, &format!("P{n:03}"), 1))
                .collect(),
        );
        refused(
            &f,
            &["--max-pages", "1"],
            "Inventory is incomplete: increase --max-pages before exporting or restoring",
        );
    }

    /// G27: a topic stored without `examples` stays without it; unknown policy keys stay.
    #[test]
    fn records_are_stored_without_defaults_and_losslessly() {
        let f = fx(SOURCE);
        let mut bare = topic();
        bare.as_object_mut().unwrap().remove("examples");
        f.server.set_topics(SOURCE, vec![bare.clone()]);
        let mut unknown = production(2);
        unknown["policy"]["future_setting"] = json!({"enabled": true});
        unknown["extra_top_level"] = json!("kept");
        f.server.set_profiles(SOURCE, vec![unknown.clone()]);
        let path = f.tmp("raw.json");
        f.profiles(&["backup", "--output-file", &path])
            .assert_success();
        let file = json_of(&path);
        assert_eq!(file["topics"][0]["record"], bare);
        assert!(file["topics"][0]["record"].get("examples").is_none());
        assert_eq!(file["profiles"][0]["record"], unknown);
    }

    /// 8.0 (scm-sdk 0.2.4, D334): a directional record is stored as the server sent it: a
    /// string `dlp_tenant_id`, an explicit `false`, an omitted shared setting and an omitted
    /// direction stay as they were (nothing inserted), and an unknown direction, an unknown
    /// mode and an explicit `null` of a newly modelled field survive. Restoring that record
    /// sends the request schema's refusal, not a changed body (§13.17, §15.25).
    #[test]
    fn directional_records_are_stored_as_sent() {
        let f = fx(SOURCE);
        let mut profile = fixtures::runtime::directional_profile();
        profile["tsg_id"] = json!(SOURCE);
        let ai = &mut profile["policy"]["ai-security-profiles"][0];
        let directions = ai["content-type-configurations"].as_object_mut().unwrap();
        directions.remove("tool-call");
        directions.insert(
            "audio".into(),
            json!({"model-protection": [{"name": "future-detector", "action": "alert"}]}),
        );
        ai["content-type-mode"] = json!("per_modality");
        ai["model-configuration"]
            .as_object_mut()
            .unwrap()
            .remove("mask-data-in-storage");
        let mut nulls = profile.clone();
        nulls["profile_id"] = json!(fixtures::uuid(9));
        nulls["profile_name"] = json!("Nulls");
        nulls["dlp_tenant_id"] = Value::Null;
        nulls["policy"]["ai-security-profiles"][0]["model-configuration"]["enable-full-conversation-inspection"] =
            Value::Null;
        f.server
            .set_profiles(SOURCE, vec![profile.clone(), nulls.clone()]);
        f.server.set_topics(SOURCE, Vec::new());
        let path = f.tmp("directional.json");
        f.profiles(&["backup", "--output-file", &path])
            .assert_success();
        let file = json_of(&path);
        let records: Vec<&Value> = file["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| &entry["record"])
            .collect();
        assert_eq!(records, [&profile, &nulls]);
        let stored = &records[0]["policy"]["ai-security-profiles"][0];
        assert_eq!(records[0]["dlp_tenant_id"], json!("8259670718644550000"));
        assert_eq!(
            stored["model-configuration"]["enable-full-conversation-inspection"],
            json!(false)
        );
        assert!(
            stored["model-configuration"]
                .get("mask-data-in-storage")
                .is_none()
        );
        assert!(
            stored["content-type-configurations"]
                .get("tool-call")
                .is_none()
        );
        assert!(records[1].get("dlp_tenant_id").is_some_and(Value::is_null));
    }

    /// 8.0 (scm-sdk 0.2.4, §15.25): every page of the walk is read without the response
    /// defaults and stored as sent. Directional records on both pages (an explicit `false`,
    /// a string or `null` `dlp_tenant_id`, an unknown direction and mode, a `null`
    /// inspection setting, an unknown top-level key, an omitted direction) are stored
    /// as the same JSON values. (`--debug` is refused for the transfer commands, D156; the
    /// page reads are the SDK's `airs.management.profiles.list`.)
    #[test]
    fn directional_records_are_stored_losslessly_on_every_page() {
        let f = fx(SOURCE);
        let mut rows: Vec<Value> = (0..150)
            .map(|n| {
                let mut row = fixtures::profile(100 + n, &format!("P{n:03}"), 1);
                row["tsg_id"] = json!(SOURCE);
                row
            })
            .collect();
        let directional = |n: u64, name: &str| {
            let mut profile = fixtures::runtime::directional_profile();
            profile["profile_id"] = json!(fixtures::uuid(n));
            profile["profile_name"] = json!(name);
            profile["tsg_id"] = json!(SOURCE);
            profile
        };
        rows[7] = directional(901, "Near");
        let mut far = directional(902, "Far");
        far["dlp_tenant_id"] = Value::Null;
        far["extra_top_level"] = json!({"kept": [1, null]});
        let ai = &mut far["policy"]["ai-security-profiles"][0];
        ai["content-type-mode"] = json!("per_modality");
        ai["content-type-configurations"]["audio"] =
            json!({"model-protection": [{"name": "future-detector", "action": "alert"}]});
        ai["content-type-configurations"]
            .as_object_mut()
            .unwrap()
            .remove("tool-response");
        ai["model-configuration"]["enable-full-conversation-inspection"] = Value::Null;
        rows[142] = far;
        f.server.set_profiles(SOURCE, rows.clone());
        f.server.set_topics(SOURCE, Vec::new());
        let path = f.tmp("pages.json");
        f.profiles(&["backup", "--output-file", &path])
            .assert_success();
        assert_eq!(
            f.api(),
            [
                PROFILES_100,
                "GET /aisec/v1/mgmt/profiles/tsg/100?offset=100&limit=100&latest=true"
            ]
        );
        let file = json_of(&path);
        let stored: Vec<&Value> = file["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| &entry["record"])
            .collect();
        assert_eq!(stored.len(), 150);
        for (index, name) in [(7, "Near"), (142, "Far")] {
            let record = stored
                .iter()
                .find(|record| record["profile_name"] == name)
                .unwrap();
            assert_eq!(*record, &rows[index], "{name}");
        }
        let far = stored
            .iter()
            .find(|record| record["profile_name"] == "Far")
            .unwrap();
        assert!(far.get("dlp_tenant_id").is_some_and(Value::is_null));
        assert_eq!(far["extra_top_level"], json!({"kept": [1, null]}));
    }

    /// A failed read is its §6 message; a 5xx is retried by the SDK (reads).
    #[test]
    fn read_failures() {
        let f = fx(SOURCE);
        f.server.set_default(
            Route::Profiles,
            Planned::json(503, &json!({"message": "SECRET-SERVER-TEXT"})).with_retry_after(0),
        );
        let path = f.tmp("fail.json");
        let out = f.profiles(&["backup", "--output-file", &path]);
        out.assert_code(1);
        assert!(!out.stderr.contains("SECRET-SERVER-TEXT"));
        assert!(out.stderr.contains("\n    HTTP 503\n"), "{}", out.stderr);
        assert!(
            f.server.route_count(Route::Profiles) > 1,
            "reads keep the SDK retries"
        );
        assert!(!Path::new(&path).exists());
    }

    /// D224: a signal during the reads writes no file.
    #[test]
    fn an_interrupted_backup_writes_no_file() {
        let f = fx(SOURCE);
        f.server.push_once(Route::Profiles, Planned::held());
        let path = f.tmp("held.json");
        let running = spawn(
            &rust(),
            &f.sandbox,
            &["runtime", "profiles", "backup", "--output-file", &path],
            &RunOptions::new(),
        );
        assert!(
            f.server
                .wait_for_route(Route::Profiles, 1, Duration::from_secs(20))
        );
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; no backup file was written\n\n"
        );
        assert!(!Path::new(&path).exists());
        assert!(temporaries(&f.sandbox.tmp()).is_empty());
    }

    /// TS defaultOutput applies to the summary.
    #[test]
    fn the_tenant_default_output_applies() {
        let server = FixtureServer::start();
        server.set_profiles(SOURCE, vec![staging()]);
        let sandbox = Sandbox::new();
        let tenant = sandbox.add_fixture_tenant_with(&server, "prod", SOURCE, |config| {
            config.set("defaultOutput", "json");
        });
        sandbox.register(&[&tenant], Some("prod"));
        let path = sandbox.tmp().join("d.json").display().to_string();
        let out = run(
            &rust(),
            &sandbox,
            &["runtime", "profiles", "backup", "--output-file", &path],
            &RunOptions::new(),
        );
        out.assert_success();
        assert_eq!(out.json()[0]["profiles"], 1);
    }
}

// ---------------------------------------------------------------------------
// restore (§18.16)
// ---------------------------------------------------------------------------

mod restore {
    use super::*;

    /// 8.0 (scm-sdk 0.2.4): a directional profile restores with its policy as backed up
    /// (every direction, an unknown one included, an explicit `false`, nothing inserted) and
    /// without the source's tenant-bound `dlp_tenant_id` (TS's `{profile_name, active,
    /// policy}` body). A record holding an explicit `null` for a newly modelled field fails
    /// the request schema during planning: nothing is written (D334).
    #[test]
    fn directional_profiles_restore_their_policy_as_backed_up() {
        let source = fx(SOURCE);
        let mut profile = fixtures::runtime::directional_profile();
        profile["tsg_id"] = json!(SOURCE);
        profile["policy"]["ai-security-profiles"][0]["content-type-configurations"]["audio"] =
            json!({"model-protection": [{"name": "future-detector", "action": "alert"}]});
        source.server.set_profiles(SOURCE, vec![profile.clone()]);
        source.server.set_topics(SOURCE, Vec::new());
        let text = std::fs::read_to_string(source.backup_file("d.json", &[])).unwrap();
        let dest = fx(DEST);
        dest.server.set_profiles(DEST, Vec::new());
        let file = dest.write("d.json", &text);
        let mut args = vec!["restore", file.as_str()];
        args.extend(FORCE);
        dest.profiles(&args).assert_success();
        let writes = dest.writes();
        assert_eq!(writes.len(), 1);
        let body = writes[0].body_json().unwrap();
        assert_eq!(
            body,
            json!({"profile_name": "Directionality Test", "active": true, "policy": profile["policy"]})
        );

        let mut nulls = profile.clone();
        nulls["policy"]["ai-security-profiles"][0]["model-configuration"]["enable-full-conversation-inspection"] =
            Value::Null;
        source.server.set_profiles(SOURCE, vec![nulls]);
        let path = source.tmp("nulls.json");
        source
            .profiles(&["backup", "--output-file", &path])
            .assert_success();
        let dest = fx(DEST);
        dest.server.set_profiles(DEST, Vec::new());
        let file = dest.write("nulls.json", &std::fs::read_to_string(&path).unwrap());
        let mut args = vec!["restore", file.as_str()];
        args.extend(FORCE);
        let out = dest.profiles(&args);
        out.assert_code(1);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/mgmt/profile did not match schema\n\n"
        );
        assert!(dest.writes().is_empty(), "{out:?}");
    }

    /// TS: a dry run only GETs (profiles, then topics for the reference) and prints the
    /// preview.
    #[test]
    fn a_dry_run_only_reads() {
        let (f, file) = restore_fx(DEST, &[]);
        let out = f.profiles(&["restore", &file, "--dry-run", "--allow-other-tenant"]);
        out.assert_success();
        assert_eq!(f.api(), [PROFILES_200, TOPICS_200]);
        assert_eq!(
            out.stdout,
            "Restore preview — no changes made\n\nSource TSG: 100\nDestination TSG: 200\n\nProfiles (2)\n\n Action │ Name       \n────────┼────────────\n create │ Production \n create │ Staging    \n\nTopics (1)\n\n Action │ Name       \n────────┼────────────\n create │ Restricted \n"
        );
        assert_eq!(out.stderr, "");
        let json = f.profiles(&[
            "restore",
            &file,
            "--dry-run",
            "--allow-other-tenant",
            "--output",
            "json",
        ]);
        json.assert_success();
        assert_eq!(
            json.json(),
            json!([{"sourceTsgId": "100", "destinationTsgId": "200", "dryRun": true,
                "profiles": [{"name": "Production", "action": "create"}, {"name": "Staging", "action": "create"}],
                "topics": [{"name": "Restricted", "action": "create"}],
                "dlpMappings": [], "dlpFallbacks": [], "serverDefaults": []}])
        );
        assert!(f.writes().is_empty());
    }

    /// TS: a forced cross-tenant restore creates fresh ids in the destination TSG (one
    /// topic POST, then each profile with a fresh inventory before and after).
    #[test]
    fn a_forced_restore_creates_fresh_ids() {
        let (f, file) = restore_fx(DEST, &[]);
        let mut args = vec!["restore", file.as_str(), "--output", "json"];
        args.extend(FORCE);
        let out = f.profiles(&args);
        out.assert_success();
        assert_eq!(
            f.api(),
            [
                PROFILES_200,
                TOPICS_200,   // plan
                PROFILES_200, // recheck
                TOPICS_200,
                "POST /aisec/v1/mgmt/topic",
                PROFILES_200,
                "POST /aisec/v1/mgmt/profile",
                PROFILES_200,
                PROFILES_200,
                "POST /aisec/v1/mgmt/profile",
                PROFILES_200,
            ]
        );
        let writes = f.writes();
        let topic_body = writes[0].body_json().unwrap();
        assert_eq!(
            topic_body,
            json!({"topic_name": "Restricted", "active": true, "description": "Restricted business topics",
                "examples": ["Restricted example"]})
        );
        let profile_body = writes[1].body_json().unwrap();
        let keys: Vec<&String> = profile_body.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["active", "policy", "profile_name"]);
        let created_topic = f.server.topics(DEST)[0].clone();
        let reference = &profile_body["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"]
            [0]["topic-list"][0]["topic"][0];
        assert_eq!(reference["topic_id"], created_topic["topic_id"]);
        assert_ne!(
            reference["topic_id"],
            fixtures::uuid(11),
            "no source topic id"
        );
        let result = out.json();
        assert_eq!(result[0]["complete"], true);
        assert_eq!(result[0]["outcomeUnknown"], Value::Null);
        assert_eq!(result[0]["notAttempted"], json!([]));
        assert_eq!(result[0]["topics"][0]["action"], "created");
        assert_eq!(result[0]["topics"][0]["id"], created_topic["topic_id"]);
        let actions: Vec<&str> = result[0]["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["action"].as_str().unwrap())
            .collect();
        assert_eq!(actions, ["created", "created"]);
        assert!(result[0].get("error").is_none());
        let order: Vec<usize> = [
            "sourceTsgId",
            "destinationTsgId",
            "complete",
            "dlpFallbacks",
            "serverDefaults",
            "topics",
            "profiles",
            "outcomeUnknown",
            "notAttempted",
        ]
        .iter()
        .map(|key| out.stdout.find(&format!("\"{key}\":")).unwrap())
        .collect();
        assert!(
            order.windows(2).all(|pair| pair[0] < pair[1]),
            "TS key order, then the Rust keys"
        );
        assert_eq!(f.server.profiles(DEST).len(), 2);
        // TS: a second dry run conflicts; `skip` creates nothing; `verify` writes nothing.
        f.server.clear_requests();
        let again = f.profiles(&["restore", &file, "--dry-run", "--allow-other-tenant"]);
        again.assert_code(1);
        assert!(again.stderr.contains("Destination profile already exists: Production; choose --on-conflict verify, skip or update"));
        let mut skip = vec![
            "restore",
            file.as_str(),
            "--on-conflict",
            "skip",
            "--output",
            "json",
        ];
        skip.extend(FORCE);
        let skipped = f.profiles(&skip);
        skipped.assert_success();
        assert_eq!(skipped.json()[0]["profiles"][0]["action"], "skipped");
        assert!(f.writes().is_empty());
        let mut verify = vec![
            "restore",
            file.as_str(),
            "--on-conflict",
            "verify",
            "--output",
            "json",
        ];
        verify.extend(FORCE);
        let verified = f.profiles(&verify);
        verified.assert_success();
        assert_eq!(verified.json()[0]["profiles"][0]["action"], "verified");
        assert_eq!(verified.json()[0]["topics"][0]["action"], "reused");
        assert!(f.writes().is_empty(), "verify sends no write");
    }

    /// TS: `--on-conflict update` sends one PUT on the destination id.
    #[test]
    fn update_uses_the_destination_identity() {
        let (f, file) = restore_fx(SOURCE, &["Staging"]);
        let mut existing = staging();
        existing["profile_id"] = json!(fixtures::uuid(77));
        f.server.set_profiles(SOURCE, vec![existing]);
        let out = f.profiles(&[
            "restore",
            &file,
            "--on-conflict",
            "update",
            "--expect-tsg",
            SOURCE,
            "--force",
        ]);
        out.assert_success();
        let writes = f.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].line(),
            format!("PUT /aisec/v1/mgmt/profile/uuid/{}", fixtures::uuid(77))
        );
        assert_eq!(writes[0].body_json().unwrap()["profile_name"], "Staging");
        assert!(
            out.stdout.starts_with("Restore complete\n\n"),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains(" updated │ Staging "));
    }

    /// TS (integration): custom DLP needs `--dlp-map` (dry run exit 1); `--on-missing-dlp
    /// basic` warns and reports the fallback; the forced restore converts to Basic
    /// without a DLP read.
    #[test]
    fn custom_dlp_needs_a_mapping_or_an_explicit_fallback() {
        let source = fx(SOURCE);
        source.server.set_profiles(SOURCE, vec![with_dlp()]);
        let text = std::fs::read_to_string(source.backup_file("d.json", &[])).unwrap();
        let f = fx(DEST);
        let file = f.write("d.json", &text);
        let out = f.profiles(&["restore", &file, "--dry-run", "--allow-other-tenant"]);
        out.assert_code(1);
        assert!(out.stderr.contains("Cross-tenant DLP reference requires explicit --dlp-map \"My Profile=<destination-name>\"; DLP resources are not cloned. Inspect destination resources with airs runtime dlp profiles list --all --output json, or explicitly accept --on-missing-dlp basic."), "{}", out.stderr);
        let warning = "  ⚠ DLP protection change: Staging will use Basic detection instead of My Profile. Custom rules are not preserved.\n";
        for format in ["pretty", "table", "json"] {
            let out = f.profiles(&[
                "restore",
                &file,
                "--dry-run",
                "--allow-other-tenant",
                "--on-missing-dlp",
                "basic",
                "--output",
                format,
            ]);
            out.assert_success();
            assert!(out.stderr.contains(warning), "{format}: {}", out.stderr);
            if format == "json" {
                assert_eq!(out.json()[0]["dlpFallbacks"].as_array().unwrap().len(), 1);
                assert_eq!(
                    out.json()[0]["dlpFallbacks"][0],
                    json!({"profile": "Staging",
                    "unresolved": ["My Profile"], "replaced": ["My Profile"],
                    "reason": "unmapped-or-missing", "protection": "basic"})
                );
            } else {
                assert!(
                    out.stdout.contains(
                        "\n\nBasic DLP fallbacks — custom protection lost\n\nStaging: My Profile\n"
                    ),
                    "{}",
                    out.stdout
                );
            }
        }
        f.server.clear_requests();
        let mut args = vec!["restore", file.as_str(), "--on-missing-dlp", "basic"];
        args.extend(FORCE);
        f.profiles(&args).assert_success();
        assert!(
            f.server
                .dl_requests(Dl::List(Collection::Profiles))
                .is_empty(),
            "no DLP read"
        );
        let created = &f.server.profiles(DEST)[0]["policy"];
        assert_eq!(created["dlp-data-profiles"], json!([]));
        assert_eq!(
            created["ai-security-profiles"][0]["model-configuration"]["data-protection"]["data-leak-detection"]
                ["member"],
            json!([{"text": "sensitive content", "id": "", "version": "2"}])
        );
        // An explicit mapping reads the catalog and binds the destination id and version.
        let f = fx(DEST);
        let file = f.write("d.json", &text);
        let mut args = vec![
            "restore",
            file.as_str(),
            "--dlp-map",
            "My Profile=My Profile",
            "--output",
            "json",
        ];
        args.extend(FORCE);
        let out = f.profiles(&args);
        out.assert_success();
        let lists = f.server.dl_requests(Dl::List(Collection::Profiles));
        assert_eq!(lists.len(), 2, "the plan and the recheck");
        assert_eq!(
            lists[0].line(),
            "GET /dlp/v2/api/data-profiles?page=0&size=100&sort=name%2Casc"
        );
        let created = &f.server.profiles(DEST)[0]["policy"];
        assert_eq!(
            created["dlp-data-profiles"][0],
            json!({"name": "My Profile", "uuid": "dp-cus-1",
            "id": "dp-cus-1", "version": "1", "rule1": {"action": "block"}})
        );
        assert!(!created.to_string().contains("dp-src"));
    }

    /// The §18.16 argument checks (exit 2, before the file: none of these files exist).
    #[test]
    fn argument_checks_come_before_the_file() {
        let f = fx(SOURCE);
        let missing = f.tmp("missing.json");
        let m = missing.as_str();
        for (args, message) in [
            (
                vec!["--debug", "runtime", "profiles", "restore", m, "--dry-run"],
                "Disable --debug for profile transfer; backups can contain sensitive policy configuration",
            ),
            (
                vec!["runtime", "profiles", "restore", m, "--max-pages", "0"],
                "--max-pages must be an integer from 1 to 1000",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "restore",
                    m,
                    "--on-conflict",
                    "reconcile",
                ],
                "--on-conflict must be error, verify, skip or update",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "restore",
                    m,
                    "--on-missing-dlp",
                    "drop",
                ],
                "--on-missing-dlp must be error or basic",
            ),
            (
                vec!["runtime", "profiles", "restore", m, "--force"],
                "--force requires --expect-tsg <destination-tsg>",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "restore",
                    m,
                    "--dry-run",
                    "--force",
                    "--expect-tsg",
                    "100",
                ],
                "--dry-run cannot be combined with --force",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "restore",
                    m,
                    "--dry-run",
                    "--dlp-map",
                    "a",
                ],
                "--dlp-map requires source-name=destination-name",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "restore",
                    m,
                    "--dry-run",
                    "--dlp-map",
                    "a=b",
                    "--dlp-map",
                    "a=c",
                ],
                "Duplicate source names in --dlp-map",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "restore",
                    m,
                    "--dry-run",
                    "--name-prefix",
                    "a\u{1b}",
                ],
                "Invalid --name-prefix",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "restore",
                    m,
                    "--dry-run",
                    "--expect-tsg",
                    "x1",
                ],
                "--expect-tsg must be a TSG ID (1-32 digits)",
            ),
            (
                vec!["runtime", "profiles", "restore", m],
                "refusing to restore profiles without --force in non-interactive mode",
            ),
            (
                vec![
                    "runtime",
                    "profiles",
                    "restore",
                    m,
                    "--dry-run",
                    "--output",
                    "csv",
                ],
                "Invalid output format 'csv'. Expected: pretty, table, json",
            ),
        ] {
            let out = run(&rust(), &f.sandbox, &args, &RunOptions::new());
            out.assert_code(2);
            assert!(out.stderr.contains(message), "{args:?}: {}", out.stderr);
        }
        assert!(f.server.requests().is_empty());
    }

    /// D216: the strict reader before the tenant (exit 1, no request, nothing echoed).
    #[test]
    fn files_are_read_strictly_before_the_tenant() {
        let (f, good) = restore_fx(DEST, &[]);
        let text = std::fs::read_to_string(&good).unwrap();
        let ts = json!({"version": 1, "resourceType": "runtime-security-profiles", "exportedAt": "2026-09-08T00:00:00Z",
            "source": {"tsgId": "100"}, "profiles": [production(2)], "topics": [topic()]});
        let cases = [
            ("bad.json", "{not json PRIVATE-SECRET".to_owned(), "Invalid runtime profiles backup {}: malformed JSON".to_owned()),
            ("ts.json", ts.to_string(), "{} is a TypeScript airs-cli backup; airs cannot restore it. Restore it with the TypeScript airs-cli, or back the profiles up again with 'airs runtime profiles backup'.".to_owned()),
            ("ts.yaml", "version: 1\nresourceType: runtime-security-profiles\n".to_owned(), "{} is a TypeScript airs-cli backup;".to_owned()),
            ("newer.json", text.replacen("\"version\": 1", "\"version\": 2", 1), "{} was written by a newer version of airs; upgrade airs to restore it".to_owned()),
            ("other.json", text.replacen("runtime-profiles", "redteam-targets", 1), "Invalid runtime profiles backup {}: it is not an airs runtime profiles backup".to_owned()),
            ("tsg.json", text.replacen("\"tsgId\": \"100\"", "\"tsgId\": \"wrong\"", 1), "Invalid runtime profiles backup {}: tsgId must be a TSG ID (1-32 digits)".to_owned()),
            ("schema.json", text.replacen("\"profile_name\": \"Production\"", "\"profile_name\": 5", 1), "Invalid runtime profiles backup {}: profiles[0] does not match the security profile response schema".to_owned()),
            ("empty.json", "{}".to_owned(), "Invalid runtime profiles backup {}: it is not an airs runtime profiles backup".to_owned()),
        ];
        for (name, content, message) in cases {
            let path = f.write(name, &content);
            let out = f.profiles(&["restore", &path, "--dry-run"]);
            out.assert_code(1);
            assert!(
                out.stderr.contains(&message.replace("{}", &path)),
                "{name}: {}",
                out.stderr
            );
            assert!(!out.stderr.contains("PRIVATE-SECRET"));
        }
        let out = f.profiles(&["restore", &f.tmp("absent.json"), "--dry-run"]);
        out.assert_code(1);
        assert!(f.server.requests().is_empty());
    }

    /// D216: another TSG's backup needs `--allow-other-tenant`; `--expect-tsg` must match;
    /// both exit 1 with no request.
    #[test]
    fn the_tsg_checks_come_before_any_request() {
        let (f, file) = restore_fx(DEST, &[]);
        let out = f.profiles(&["restore", &file, "--dry-run"]);
        out.assert_code(1);
        assert!(out.stderr.contains(&format!("{file} was exported from TSG 100; the selected tenant uses TSG 200. Pass --allow-other-tenant to restore it here.")), "{}", out.stderr);
        let out = f.profiles(&[
            "restore",
            &file,
            "--allow-other-tenant",
            "--expect-tsg",
            "100",
            "--force",
        ]);
        out.assert_code(1);
        assert!(out.stderr.contains(
            "--expect-tsg does not match the selected destination tenant; no API request was made"
        ));
        assert!(f.server.requests().is_empty());
    }

    /// §18.3, §18.16: the tenant checks run before the client is built, so a destination
    /// with an inadmissible `dlpEndpoint` (D48) still reports the TSG refusal; with the
    /// TSG accepted, the client's D48 refusal follows. No request either way.
    #[test]
    fn the_tsg_checks_come_before_the_client() {
        let source = fx(SOURCE);
        let text = std::fs::read_to_string(source.backup_file("b.json", &[])).unwrap();
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        let tenant = sandbox.add_fixture_tenant_allowing_external_endpoints(
            &server,
            "prod",
            DEST,
            |config| {
                config.set("dlpEndpoint", "http://dlp.example.test/x");
            },
        );
        sandbox.register(&[&tenant], Some("prod"));
        let file = sandbox.tmp().join("b.json").display().to_string();
        std::fs::write(&file, text).unwrap();
        let restore = |args: &[&str]| {
            let mut full = vec!["runtime", "profiles", "restore", &file];
            full.extend_from_slice(args);
            run(&rust(), &sandbox, &full, &RunOptions::new())
        };
        let out = restore(&["--dry-run"]);
        out.assert_code(1);
        assert_eq!(
            out.error_line(),
            Some(format!(
                "{file} was exported from TSG 100; the selected tenant uses TSG 200. Pass --allow-other-tenant to restore it here."
            ))
        );
        let out = restore(&["--allow-other-tenant", "--expect-tsg", "100", "--force"]);
        out.assert_code(1);
        assert_eq!(
            out.error_line().as_deref(),
            Some(
                "--expect-tsg does not match the selected destination tenant; no API request was made"
            )
        );
        let out = restore(&["--allow-other-tenant", "--dry-run"]);
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

    /// D218: an absent destination collection is refused before any write.
    #[test]
    fn absent_destination_collections_are_refused() {
        let (f, file) = restore_fx(DEST, &[]);
        f.server.set_profiles(
            DEST,
            vec![{
                let mut existing = production(2);
                existing["tsg_id"] = json!(DEST);
                existing
            }],
        );
        f.server
            .push_once(Route::Profiles, Planned::json(200, &json!({})));
        let mut args = vec!["restore", file.as_str()];
        args.extend(FORCE);
        let out = f.profiles(&args);
        out.assert_code(1);
        assert!(
            out.stderr.contains(
                "Destination inventory of security profiles was not returned; nothing was changed"
            ),
            "{}",
            out.stderr
        );
        f.server
            .push_once(Route::Topics, Planned::json(200, &json!({})));
        f.server.set_profiles(DEST, vec![]);
        let out = f.profiles(&args);
        out.assert_code(1);
        assert!(out.stderr.contains(
            "Destination inventory of custom topics was not returned; nothing was changed"
        ));
        assert!(f.writes().is_empty());
    }

    /// D217: a 502 on the profile create is sent once and reported as outcome unknown;
    /// the later profile is not attempted; a re-run reuses the topic and finds the
    /// profile.
    #[test]
    fn an_unknown_create_stops_the_run_and_a_rerun_never_duplicates() {
        let (f, file) = restore_fx(DEST, &[]);
        f.server
            .push_once(Route::ProfileCreate, Planned::applied_then_dropped());
        let mut args = vec!["restore", file.as_str(), "--output", "json"];
        args.extend(FORCE);
        let out = f.profiles(&args);
        out.assert_code(1);
        assert_eq!(
            f.server.route_count(Route::ProfileCreate),
            1,
            "never re-sent"
        );
        let result = &out.json()[0];
        assert_eq!(result["complete"], false);
        assert_eq!(
            result["outcomeUnknown"],
            json!({"kind": "profile", "name": "Production", "action": "create"})
        );
        assert_eq!(
            result["notAttempted"],
            json!([{"kind": "profile", "name": "Staging"}])
        );
        let error = "Outcome unknown: the security profile Production may have been created; run the restore again with --on-conflict verify to check it";
        assert_eq!(result["error"], error);
        assert_eq!(out.stderr, format!("  ✗ {error}\n"));
        assert_eq!(result["topics"][0]["action"], "created");
        // The default conflict policy refuses; verify checks it and creates Staging once.
        let again = f.profiles(&args);
        again.assert_code(1);
        assert!(
            again
                .stderr
                .contains("Destination profile already exists: Production")
        );
        let mut verify = vec![
            "restore",
            file.as_str(),
            "--on-conflict",
            "verify",
            "--output",
            "json",
        ];
        verify.extend(FORCE);
        let resumed = f.profiles(&verify);
        resumed.assert_success();
        let result = &resumed.json()[0];
        assert_eq!(result["topics"][0]["action"], "reused");
        let actions: Vec<&str> = result["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["action"].as_str().unwrap())
            .collect();
        assert_eq!(actions, ["verified", "created"]);
        assert_eq!(f.server.topics(DEST).len(), 1, "no duplicate topic");
        assert_eq!(f.server.profiles(DEST).len(), 2, "no duplicate profile");
    }

    /// Choice 68: a topic created whose answer does not verify (the service normalised
    /// it) keeps its `created` row, so json, pretty and table name what exists; the
    /// profiles are not attempted and nothing is outcome-unknown.
    #[test]
    fn a_created_topic_that_does_not_verify_is_reported() {
        for format in ["json", "pretty", "table"] {
            let (f, file) = restore_fx(DEST, &[]);
            let answer = fixtures::topic(77, "Restricted", 1, "normalised by the service");
            f.server
                .push_once(Route::TopicCreate, Planned::json(200, &answer));
            let mut args = vec!["restore", file.as_str(), "--output", format];
            args.extend(FORCE);
            let out = f.profiles(&args);
            out.assert_code(1);
            assert_eq!(f.server.route_count(Route::TopicCreate), 1);
            assert_eq!(f.server.route_count(Route::ProfileCreate), 0);
            let error = "Topic response did not verify: Restricted";
            assert_eq!(out.stderr, format!("  ✗ {error}\n"));
            if format == "json" {
                let result = &out.json()[0];
                assert_eq!(
                    result["topics"],
                    json!([{"name": "Restricted", "id": fixtures::uuid(77), "action": "created"}])
                );
                assert_eq!(result["outcomeUnknown"], Value::Null);
                assert_eq!(
                    result["notAttempted"],
                    json!([
                        {"kind": "profile", "name": "Production"},
                        {"kind": "profile", "name": "Staging"}
                    ])
                );
                assert_eq!(result["error"], error);
            } else {
                assert!(
                    out.stdout
                        .starts_with("Restore incomplete — completed writes remain\n\n"),
                    "{}",
                    out.stdout
                );
                assert!(out.stdout.contains("\n\nTopics (1)\n\n"), "{}", out.stdout);
                assert!(
                    out.stdout.contains(" created │ Restricted "),
                    "{}",
                    out.stdout
                );
            }
        }
    }

    /// D217: one attempt per write: a 502 once, a 403 once (TS replays it), a 401
    /// replayed once with a fresh token; pretty shows the Rust-only blocks.
    #[test]
    fn every_write_is_one_attempt() {
        for (planned, posts, error) in [
            (
                Planned::json(502, &json!({})).with_retry_after(0),
                1,
                "Outcome unknown: the custom topic Restricted may have been created; run the restore again with --on-conflict verify to check it",
            ),
            (
                Planned::json(403, &json!({"message": "SECRET-SERVER-TEXT"})),
                1,
                "API request failed (HTTP 403); verify destination state before retrying",
            ),
            (
                Planned::json(400, &json!({})),
                1,
                "API request failed (HTTP 400); verify destination state before retrying",
            ),
        ] {
            let (f, file) = restore_fx(DEST, &[]);
            f.server.set_default(Route::TopicCreate, planned);
            let mut args = vec!["restore", file.as_str()];
            args.extend(FORCE);
            let out = f.profiles(&args);
            out.assert_code(1);
            assert_eq!(f.server.route_count(Route::TopicCreate), posts, "{error}");
            assert_eq!(f.server.route_count(Route::ProfileCreate), 0);
            assert!(
                out.stdout
                    .starts_with("Restore incomplete — completed writes remain\n\n"),
                "{}",
                out.stdout
            );
            assert!(
                out.stdout.ends_with(&format!("\n\nError: {error}\n")),
                "{}",
                out.stdout
            );
            assert!(
                out.stdout
                    .contains("\n\nNot attempted\n\n Resource │ Name       \n"),
                "{}",
                out.stdout
            );
            if error.starts_with("Outcome unknown") {
                assert!(out.stdout.contains("\n\nPossibly written (outcome unknown)\n\n Resource │ Name       │ Action \n"), "{}", out.stdout);
            }
            assert!(
                !out.stdout.contains("SECRET-SERVER-TEXT")
                    && !out.stderr.contains("SECRET-SERVER-TEXT")
            );
        }
        let (f, file) = restore_fx(DEST, &["Staging"]);
        f.server.set_rotating_tokens(true);
        f.server
            .push_once(Route::ProfileCreate, Planned::empty_json(401));
        let mut args = vec!["restore", file.as_str()];
        args.extend(FORCE);
        f.profiles(&args).assert_success();
        assert_eq!(
            f.server.route_count(Route::ProfileCreate),
            2,
            "a 401 is replayed once"
        );
    }

    /// `Injection`: a prompt-injection detector and the built-in Basic DLP member (no
    /// DLP read), without the server-added severity and `database-security`.
    fn injection() -> Value {
        let mut profile = fixtures::profile(3, "Injection", 1);
        profile["tsg_id"] = json!(SOURCE);
        profile["policy"]["ai-security-profiles"][0]["model-configuration"] = json!({
            "model-protection": [{"name": "prompt-injection", "action": "block"}],
            "data-protection": {"data-leak-detection": {"action": "block",
                "member": [{"text": "sensitive content", "id": "", "version": "2"}]}},
        });
        profile
    }

    fn server_defaults(record: &mut Value) {
        let model = &mut record["policy"]["ai-security-profiles"][0]["model-configuration"];
        model["model-protection"][0]["severity"] = json!("medium");
        model["data-protection"]["database-security"] = Value::Null;
    }

    /// TS: server-added severities and the null `database-security` are verified and
    /// recorded at create and at verify; a changed policy fails the verification (the
    /// receipt stays).
    #[test]
    fn read_back_verification() {
        let source = fx(SOURCE);
        source.server.set_profiles(SOURCE, vec![injection()]);
        let text = std::fs::read_to_string(source.backup_file("i.json", &[])).unwrap();
        let f = fx(DEST);
        let file = f.write("i.json", &text);
        f.server.set_profile_write_edit(Some(server_defaults));
        let mut args = vec!["restore", file.as_str(), "--output", "json"];
        args.extend(FORCE);
        let out = f.profiles(&args);
        out.assert_success();
        let defaults = out.json()[0]["serverDefaults"].clone();
        assert_eq!(defaults[0]["profile"], "Injection");
        assert_eq!(
            defaults[0]["fields"].as_array().unwrap().len(),
            2,
            "{defaults}"
        );
        assert!(
            f.server
                .dl_requests(Dl::List(Collection::Profiles))
                .is_empty()
        );
        let mut verify = vec![
            "restore",
            file.as_str(),
            "--on-conflict",
            "verify",
            "--dry-run",
        ];
        verify.extend(["--allow-other-tenant", "--output", "json"]);
        let preview = f.profiles(&verify);
        preview.assert_success();
        assert_eq!(preview.json()[0]["serverDefaults"], defaults);
        assert_eq!(preview.json()[0]["profiles"][0]["action"], "verify");
        let pretty = f.profiles(&verify[..verify.len() - 2]);
        assert!(pretty.stdout.contains("\n\nVerified server-added defaults (source omitted these fields)\n\nInjection: 2 fields; use --output json for paths\n"), "{}", pretty.stdout);
        let (f, file) = restore_fx(DEST, &["Staging"]);
        f.server.set_profile_write_edit(Some(|record: &mut Value| {
            record["policy"] = json!({});
        }));
        let mut args = vec!["restore", file.as_str(), "--output", "json"];
        args.extend(FORCE);
        let out = f.profiles(&args);
        out.assert_code(1);
        assert_eq!(
            out.json()[0]["error"],
            "Restored profile did not verify: Staging"
        );
        assert_eq!(out.json()[0]["profiles"][0]["action"], "created");
        assert_eq!(out.json()[0]["outcomeUnknown"], Value::Null);
    }

    /// TS: the recheck after the prompt stops without writes when the destination changed
    /// meanwhile; the D81 prompt on stderr (y, yes; anything else declines).
    #[test]
    fn the_confirmation_and_the_recheck() {
        let prompt = "? Restore 1 profiles from TSG 100 to TSG 200 (0 updates, 0 Basic DLP fallbacks losing custom detection)? (y/N) ";
        for (answer, writes) in [
            (&b"n\n"[..], 0),
            (b"\n", 0),
            (b"\x04", 0),
            (b"y\n", 1),
            (b" YES \n", 1),
        ] {
            let (f, file) = restore_fx(DEST, &["Staging"]);
            let mut session = spawn_pty(
                &rust(),
                &f.sandbox,
                &[
                    "runtime",
                    "profiles",
                    "restore",
                    &file,
                    "--allow-other-tenant",
                ],
                &RunOptions::new(),
            );
            session.expect(prompt);
            assert!(f.writes().is_empty());
            session.send(answer);
            let out = session.wait();
            out.run.assert_success();
            assert_eq!(f.writes().len(), writes, "{answer:?}");
            if writes == 0 {
                assert!(out.transcript.contains("ℹ Aborted"), "{}", out.transcript);
            }
        }
        let (f, file) = restore_fx(DEST, &["Staging"]);
        let mut session = spawn_pty(
            &rust(),
            &f.sandbox,
            &[
                "runtime",
                "profiles",
                "restore",
                &file,
                "--allow-other-tenant",
            ],
            &RunOptions::new(),
        );
        session.expect(prompt);
        let mut concurrent = staging();
        concurrent["tsg_id"] = json!(DEST);
        f.server.set_profiles(DEST, vec![concurrent]);
        session.send(b"y\n");
        let out = session.wait();
        out.run.assert_code(1);
        assert!(
            out.transcript
                .contains("Destination profile changed after planning: Staging"),
            "{}",
            out.transcript
        );
        assert!(f.writes().is_empty());
    }

    /// TS: a topic that appeared after planning stops the run before its create.
    #[test]
    fn a_topic_that_appeared_after_planning_stops_the_run() {
        let (f, file) = restore_fx(DEST, &["Production"]);
        let mut session = spawn_pty(
            &rust(),
            &f.sandbox,
            &[
                "runtime",
                "profiles",
                "restore",
                &file,
                "--allow-other-tenant",
            ],
            &RunOptions::new(),
        );
        session.expect("(y/N) ");
        f.server
            .set_topics(DEST, vec![fixtures::topic(50, "Restricted", 1, "other")]);
        session.send(b"y\n");
        let out = session.wait();
        out.run.assert_code(1);
        assert!(
            out.transcript
                .contains("Destination topic changed after planning: Restricted")
        );
        assert!(f.writes().is_empty());
    }

    /// D224: a signal during a write names what was written and what may have been.
    #[test]
    fn an_interrupted_restore_names_its_writes() {
        let (f, file) = restore_fx(DEST, &[]);
        f.server.push_once(Route::ProfileCreate, Planned::held());
        let mut args = vec!["runtime", "profiles", "restore", file.as_str()];
        args.extend(FORCE);
        let running = spawn(&rust(), &f.sandbox, &args, &RunOptions::new());
        assert!(
            f.server
                .wait_for_route(Route::ProfileCreate, 1, Duration::from_secs(20))
        );
        running.send_signal("INT");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(130);
        assert_eq!(out.stdout, "");
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; 1 topic(s) and 0 profile(s) written; the security profile Production may also have been created (outcome unknown); run the restore again with --on-conflict verify to resume\n\n"
        );
        assert_eq!(f.server.route_count(Route::ProfileCreate), 1);
        let (f, file) = restore_fx(DEST, &[]);
        f.server.push_once(Route::Profiles, Planned::held());
        let mut args = vec!["runtime", "profiles", "restore", file.as_str()];
        args.extend(FORCE);
        let running = spawn(&rust(), &f.sandbox, &args, &RunOptions::new());
        assert!(
            f.server
                .wait_for_route(Route::Profiles, 1, Duration::from_secs(20))
        );
        running.send_signal("TERM");
        let out = running.wait();
        f.server.release_held();
        out.assert_code(143);
        assert_eq!(
            out.stderr,
            "\n  ✗ Error: Interrupted; nothing was changed\n\n"
        );
    }

    /// The prefix names restored profiles and topics; a same-tenant restore keeps its
    /// references.
    #[test]
    fn the_prefix_and_same_tenant_restores() {
        let (f, file) = restore_fx(SOURCE, &["Production"]);
        let out = f.profiles(&[
            "restore",
            &file,
            "--name-prefix",
            "migrated-",
            "--expect-tsg",
            SOURCE,
            "--force",
            "--output",
            "json",
        ]);
        out.assert_success();
        let names: Vec<String> = f
            .server
            .profiles(SOURCE)
            .iter()
            .map(|p| p["profile_name"].as_str().unwrap().to_owned())
            .collect();
        assert!(
            names.contains(&"migrated-Production".to_owned()),
            "{names:?}"
        );
        assert!(
            f.server
                .topics(SOURCE)
                .iter()
                .any(|t| t["topic_name"] == "migrated-Restricted")
        );
        assert_eq!(out.json()[0]["sourceTsgId"], SOURCE);
    }
}
