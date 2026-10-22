//! TS-vs-Rust parity for directional security profiles (DESIGN §13.17, 8.0): the
//! scenarios of TypeScript 7.3.0 `tests/integration/directional-security-profiles.spec.ts`
//! run on both CLIs against the loopback fixture server, seeded with the TypeScript
//! fixture (`fixtures::runtime::directional_profile`).
//!
//! Each scenario runs once on each CLI, on a fresh sandbox and server. The tests compare
//! exit codes, stdout and stderr where both CLIs print the same bytes, the write requests
//! (JSON bodies compared semantically, D35) and the resulting fixture state. `dNN_` tests
//! pin both sides of a DESIGN §12 row.

use airs_test_harness::{
    Cli, FixtureServer, RecordedRequest, Route, Run, RunOptions, Sandbox, assert_json_semantic_eq,
    fixtures, require_ts, run, usage_line,
};
use serde_json::{Value, json};

const TSG: &str = "100";
/// The fixture's `profile_id`.
const PROFILE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
/// The fixture's `profile_name`.
const PROFILE_NAME: &str = "Directionality Test";

fn rust() -> Cli {
    Cli::rust(env!("CARGO_BIN_EXE_airs"))
}

fn directional() -> Value {
    fixtures::runtime::directional_profile()
}

/// The same directional profile with a legacy policy.
fn legacy(policy: Value) -> Value {
    let mut profile = directional();
    profile["policy"] = policy;
    profile
}

/// The fixture's topic `Restricted` (id 1, revision 3).
fn restricted() -> Value {
    fixtures::topic(1, "Restricted", 3, "Fixture")
}

/// One CLI's run of a scenario.
struct Side {
    run: Run,
    requests: Vec<RecordedRequest>,
    topics: Vec<Value>,
    profiles: Vec<Value>,
}

impl Side {
    fn writes(&self) -> Vec<&RecordedRequest> {
        self.requests
            .iter()
            .filter(|request| request.route.is_write())
            .collect()
    }

    /// The JSON body of the first write.
    fn body(&self) -> Value {
        self.writes()[0].body_json().expect("a JSON body")
    }

    fn count(&self, route: Route) -> usize {
        self.requests.iter().filter(|r| r.route == route).count()
    }

    /// The stored profile (the server keeps one record per id).
    fn profile(&self) -> Value {
        self.profiles
            .iter()
            .find(|row| row["profile_id"] == PROFILE_ID)
            .cloned()
            .expect("the fixture profile")
    }
}

/// Runs `args` (with `TMP` replaced by the sandbox's `tmp/`) on a fresh world holding
/// `profile`, the `Restricted` topic and the file `TMP/profile.json` (the fixture).
fn exec(cli: &Cli, profile: &Value, files: &[(&str, &Value)], args: &[&str]) -> Side {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", TSG);
    server.set_profiles(TSG, vec![profile.clone()]);
    server.set_topics(TSG, vec![restricted()]);
    std::fs::write(
        sandbox.tmp().join("profile.json"),
        directional().to_string(),
    )
    .unwrap();
    for (name, body) in files {
        std::fs::write(sandbox.tmp().join(name), body.to_string()).unwrap();
    }
    let tmp = sandbox.tmp().display().to_string();
    let args: Vec<String> = args.iter().map(|arg| arg.replace("TMP", &tmp)).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut out = run(cli, &sandbox, &args, &RunOptions::new());
    server.assert_no_unknown_routes();
    out.stdout = out.stdout.replace(&tmp, "TMP");
    out.stderr = out.stderr.replace(&tmp, "TMP");
    Side {
        run: out,
        requests: server.requests(),
        topics: server.topics(TSG),
        profiles: server.profiles(TSG),
    }
}

/// Both CLIs on the same scenario, or `None` when the reference is skipped.
fn both(test: &str, profile: &Value, args: &[&str]) -> Option<(Side, Side)> {
    both_with(test, profile, &[], args)
}

fn both_with(
    test: &str,
    profile: &Value,
    files: &[(&str, &Value)],
    args: &[&str],
) -> Option<(Side, Side)> {
    let ts = require_ts(test)?;
    Some((
        exec(&rust(), profile, files, args),
        exec(&ts, profile, files, args),
    ))
}

/// Each write's method and path (the server base removed).
fn write_lines(side: &Side) -> Vec<String> {
    side.writes()
        .iter()
        .map(|request| request.line().replacen(request.base, "", 1))
        .collect()
}

/// Equal exit codes, writes (semantically) and resulting state.
fn assert_same_writes(rust: &Side, ts: &Side) {
    assert_eq!(rust.run.code, ts.run.code, "{:?}\n{:?}", rust.run, ts.run);
    assert_eq!(write_lines(rust), write_lines(ts));
    for (rust_write, ts_write) in rust.writes().iter().zip(ts.writes()) {
        match (rust_write.body_json(), ts_write.body_json()) {
            (Some(rust_body), Some(ts_body)) => assert_json_semantic_eq(&rust_body, &ts_body),
            (rust_body, ts_body) => assert_eq!(rust_body, ts_body),
        }
    }
    assert_json_semantic_eq(&json!(rust.topics), &json!(ts.topics));
    assert_json_semantic_eq(&json!(rust.profiles), &json!(ts.profiles));
}

/// Both refused with a usage error (exit 2) and nothing written.
fn assert_refused_without_writes(rust: &Side, ts: &Side) {
    for side in [rust, ts] {
        assert_eq!(side.run.code, 2, "{:?}", side.run);
        assert!(side.writes().is_empty(), "{:?}", side.writes());
    }
}

fn profiles(args: &[&str]) -> Vec<String> {
    let mut all = vec!["runtime".to_owned(), "profiles".to_owned()];
    all.extend(args.iter().map(|arg| (*arg).to_owned()));
    all
}

fn refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

mod parity {
    use super::*;

    /// TS spec: "preserves the complete JSON create fixture and get/list policy in JSON
    /// and YAML" (YAML stays refused, D50).
    #[test]
    fn a_complete_json_create_and_its_reads_keep_the_policy() {
        let args = profiles(&["create", "--config", "TMP/profile.json", "--output", "json"]);
        let Some((rust, ts)) = both("directional_create_config", &directional(), &refs(&args))
        else {
            return;
        };
        assert_same_writes(&rust, &ts);
        rust.run.assert_success();
        assert_json_semantic_eq(&rust.body(), &directional());
        assert_eq!(rust.run.stderr, ts.run.stderr, "the status line");
        assert_json_semantic_eq(&rust.run.json(), &ts.run.json());
        assert_eq!(
            rust.run.json()["dlpTenantId"],
            directional()["dlp_tenant_id"]
        );
        for args in [
            profiles(&["get", PROFILE_ID, "--output", "json"]),
            profiles(&["list", "--output", "json"]),
        ] {
            let Some((rust, ts)) = both("directional_reads", &directional(), &refs(&args)) else {
                return;
            };
            rust.run.assert_success();
            assert_json_semantic_eq(&rust.run.json(), &ts.run.json());
        }
        // A GET may omit `dlp_tenant_id`: no `dlpTenantId`.
        let mut bare = directional();
        bare.as_object_mut().unwrap().remove("dlp_tenant_id");
        let args = profiles(&["get", PROFILE_ID, "--output", "json"]);
        let Some((rust, ts)) = both("directional_get_bare", &bare, &refs(&args)) else {
            return;
        };
        for side in [&rust, &ts] {
            assert!(side.run.json().get("dlpTenantId").is_none());
            assert_json_semantic_eq(&side.run.json()["policy"], &directional()["policy"]);
        }
    }

    /// The pretty detail: the `DLP tenant` line and `Protection locations`, byte for byte.
    #[test]
    fn the_pretty_detail_names_the_dlp_tenant_and_every_direction() {
        let args = profiles(&["get", PROFILE_NAME]);
        let Some((rust, ts)) = both("directional_get_pretty", &directional(), &refs(&args)) else {
            return;
        };
        rust.run.assert_success();
        assert_eq!(rust.run.stdout, ts.run.stdout);
        assert!(
            rust.run
                .stdout
                .contains("  DLP tenant            8259670718644550000\n")
        );
        assert!(rust.run.stdout.contains(
            "  Protection locations  AI[0] default / prompt, AI[0] default / response, AI[0] default / tool-call, AI[0] default / tool-response\n"
        ));
    }

    /// TS spec: "updates response detectors and masking while preserving prompt/tool
    /// settings, metadata and UUID".
    #[test]
    fn a_direction_edit_keeps_every_other_direction() {
        let mut inactive = directional();
        inactive["active"] = json!(false);
        let args = profiles(&[
            "update",
            PROFILE_ID,
            "--direction",
            "response",
            "--toxic-content",
            "alert",
            "--malicious-code",
            "allow",
            "--no-mask-data-inline",
            "--no-enable-full-conversation-inspection",
            "--output",
            "json",
        ]);
        let Some((rust, ts)) = both("directional_update", &inactive, &refs(&args)) else {
            return;
        };
        assert_same_writes(&rust, &ts);
        rust.run.assert_success();
        assert_eq!(rust.run.stderr, ts.run.stderr, "the status line");
        let body = rust.body();
        assert_eq!(body["active"], false);
        let ai = &body["policy"]["ai-security-profiles"][0];
        let prior = &directional()["policy"]["ai-security-profiles"][0];
        for direction in ["prompt", "tool-call", "tool-response"] {
            assert_eq!(
                ai["content-type-configurations"][direction],
                prior["content-type-configurations"][direction]
            );
        }
        let response = &ai["content-type-configurations"]["response"];
        assert_eq!(
            response["app-protection"]["malicious-code-protection"],
            json!({"name": "malicious-code", "action": "allow", "severity": "high"})
        );
        assert_eq!(
            response["data-protection"]["data-leak-detection"]["action"],
            "block"
        );
        assert_eq!(
            response["data-protection"]["data-leak-detection"]["mask-data-inline"],
            false
        );
        assert_eq!(
            ai["model-configuration"]["enable-full-conversation-inspection"],
            false
        );
        assert_eq!(
            rust.writes()[0]
                .line()
                .replacen(rust.writes()[0].base, "", 1),
            format!("PUT /aisec/v1/mgmt/profile/uuid/{PROFILE_ID}")
        );
    }

    /// TS spec: "global-only %s updates preserve all protections" (both layouts).
    #[test]
    fn shared_only_updates_keep_every_protection() {
        let prompt = directional()["policy"]["ai-security-profiles"][0]["content-type-configurations"]
            ["prompt"]
            .clone();
        let mut model = prompt;
        model["latency"] = json!({"inline-timeout-action": "block", "max-inline-latency": 5});
        let legacy_profile = legacy(json!({"ai-security-profiles": [
            {"model-type": "default", "model-configuration": model}
        ]}));
        for profile in [directional(), legacy_profile] {
            let args = profiles(&[
                "update",
                PROFILE_ID,
                "--max-inline-latency",
                "9",
                "--no-mask-data-in-storage",
                "--output",
                "json",
            ]);
            let Some((rust, ts)) = both("directional_shared", &profile, &refs(&args)) else {
                return;
            };
            assert_same_writes(&rust, &ts);
            rust.run.assert_success();
            let mut expected = profile["policy"].clone();
            let config = &mut expected["ai-security-profiles"][0]["model-configuration"];
            config["latency"]["max-inline-latency"] = json!(9);
            config["mask-data-in-storage"] = json!(false);
            assert_json_semantic_eq(&rust.profile()["policy"], &expected);
        }
    }

    /// TS spec: "rejects malformed directional JSON on %s before OAuth".
    #[test]
    fn malformed_directional_json_is_refused_before_oauth() {
        let mut bad = directional();
        bad["policy"]["ai-security-profiles"][0]["content-type-configurations"]["response"]["model-protection"]
            [0]["severity"] = json!(123);
        for args in [
            profiles(&["create", "--config", "TMP/bad.json"]),
            profiles(&["update", PROFILE_ID, "--config", "TMP/bad.json"]),
        ] {
            let Some((rust, ts)) = both_with(
                "directional_bad_json",
                &directional(),
                &[("bad.json", &bad)],
                &refs(&args),
            ) else {
                return;
            };
            for side in [&rust, &ts] {
                assert_eq!(side.run.code, 2, "{:?}", side.run);
                assert!(side.requests.is_empty(), "before OAuth");
            }
        }
    }

    /// TS spec: "refuses locally invalid flags before OAuth" (the selector and conflict
    /// texts are TypeScript's; the number texts are D102's).
    #[test]
    fn invalid_flags_are_refused_before_oauth() {
        for (args, same_text) in [
            (
                profiles(&[
                    "create",
                    "--config",
                    "TMP/profile.json",
                    "--direction",
                    "prompt",
                ]),
                true,
            ),
            (
                profiles(&["create", "--name", "Bad", "--direction", "invalid"]),
                true,
            ),
            (
                profiles(&["create", "--name", "Bad", "--max-inline-latency", "1.5"]),
                false,
            ),
            (
                profiles(&[
                    "create",
                    "--name",
                    "Bad",
                    "--max-inline-latency",
                    "5garbage",
                ]),
                false,
            ),
            (
                profiles(&["update", PROFILE_ID, "--direction", "invalid"]),
                true,
            ),
            (
                profiles(&["update", PROFILE_ID, "--ai-profile-index", "-1"]),
                true,
            ),
            (
                profiles(&["update", PROFILE_ID, "--max-inline-latency", "NaN"]),
                false,
            ),
        ] {
            let Some((rust, ts)) = both("directional_invalid_flags", &directional(), &refs(&args))
            else {
                return;
            };
            for side in [&rust, &ts] {
                assert_eq!(side.run.code, 2, "{:?}", side.run);
                assert!(side.requests.is_empty(), "before OAuth: {args:?}");
            }
            if same_text {
                assert_eq!(rust.run.stderr, ts.run.stderr);
            }
        }
    }

    /// TS spec: "refuses ambiguous directional edits after reading without submitting a
    /// write".
    #[test]
    fn a_protection_edit_without_a_direction_is_refused_after_the_read() {
        let args = profiles(&["update", PROFILE_ID, "--toxic-content", "alert"]);
        let Some((rust, ts)) = both("directional_ambiguous", &directional(), &refs(&args)) else {
            return;
        };
        assert_refused_without_writes(&rust, &ts);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("Directional protection edits require --direction")
        );
        assert_eq!(rust.run.stderr, ts.run.stderr);
        for side in [&rust, &ts] {
            assert!(side.count(Route::Profiles) >= 1, "the profile was read");
        }
    }

    /// TS spec: "rejects legacy direction updates and accepts a deliberate complete JSON
    /// replacement".
    #[test]
    fn a_legacy_profile_refuses_a_direction_and_takes_a_complete_replacement() {
        let profile = legacy(json!({"ai-security-profiles": [
            {"model-configuration": {"model-protection": [{"name": "prompt-injection", "action": "block"}]}}
        ]}));
        let args = profiles(&[
            "update",
            PROFILE_ID,
            "--direction",
            "response",
            "--toxic-content",
            "alert",
        ]);
        let Some((rust, ts)) = both("directional_legacy_refused", &profile, &refs(&args)) else {
            return;
        };
        assert_refused_without_writes(&rust, &ts);
        assert_eq!(rust.run.stderr, ts.run.stderr);
        // The fixture names the same profile, so the D103 name check passes.
        let args = profiles(&[
            "update",
            PROFILE_ID,
            "--config",
            "TMP/profile.json",
            "--output",
            "json",
        ]);
        let Some((rust, ts)) = both("directional_legacy_replaced", &profile, &refs(&args)) else {
            return;
        };
        assert_same_writes(&rust, &ts);
        rust.run.assert_success();
        assert_json_semantic_eq(&rust.profile()["policy"], &directional()["policy"]);
    }

    /// TS spec: "applies and reverts %s topics without touching other protections".
    #[test]
    fn topics_apply_and_revert_in_both_layouts() {
        let legacy_profile = legacy(json!({"ai-security-profiles": [
            {"model-configuration": {"model-protection": []}}
        ]}));
        for (profile, selector) in [
            (directional(), &["--direction", "response"][..]),
            (legacy_profile, &[][..]),
        ] {
            let mut args = vec![
                "runtime",
                "topics",
                "apply",
                "--profile",
                PROFILE_NAME,
                "--name",
                "Restricted",
            ];
            args.extend_from_slice(selector);
            let Some((rust, ts)) = both("directional_apply", &profile, &args) else {
                return;
            };
            assert_same_writes(&rust, &ts);
            rust.run.assert_success();
            let ai = &rust.profile()["policy"]["ai-security-profiles"][0];
            let block = if selector.is_empty() {
                &ai["model-configuration"]
            } else {
                &ai["content-type-configurations"]["response"]
            };
            let guardrail = block["model-protection"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .clone();
            assert_eq!(guardrail["name"], "topic-guardrails");
            assert_eq!(
                guardrail["topic-list"],
                json!([{"action": "block", "topic": [{"topic_id": fixtures::uuid(1), "topic_name": "Restricted", "revision": 3}]}])
            );
            if !selector.is_empty() {
                let prior =
                    &profile["policy"]["ai-security-profiles"][0]["content-type-configurations"];
                for direction in ["prompt", "tool-call", "tool-response"] {
                    assert_eq!(
                        ai["content-type-configurations"][direction],
                        prior[direction]
                    );
                }
            }
            // Revert from the applied state: the profile after the apply.
            let applied = rust.profile();
            let mut args = vec![
                "runtime",
                "topics",
                "revert",
                "--profile",
                PROFILE_NAME,
                "--name",
                "Restricted",
                "--force",
            ];
            args.extend_from_slice(selector);
            let Some((rust, ts)) = both("directional_revert", &applied, &args) else {
                return;
            };
            rust.run.assert_success();
            ts.run.assert_success();
            for side in [&rust, &ts] {
                assert!(
                    !side
                        .requests
                        .iter()
                        .any(|r| r.route == Route::TopicForceDelete),
                    "never the force endpoint"
                );
                assert!(side.topics.is_empty(), "the topic was deleted");
            }
        }
    }

    /// TS spec: "refuses ambiguous topic apply and refuses revert when another direction
    /// still references the topic".
    #[test]
    fn ambiguous_apply_and_a_cross_direction_revert_are_refused() {
        let args = [
            "runtime",
            "topics",
            "apply",
            "--profile",
            PROFILE_NAME,
            "--name",
            "Restricted",
        ];
        let Some((rust, ts)) = both("directional_apply_ambiguous", &directional(), &args) else {
            return;
        };
        assert_refused_without_writes(&rust, &ts);
        assert_eq!(rust.run.stderr, ts.run.stderr);
        let mut both_directions = directional();
        for direction in ["prompt", "response"] {
            both_directions["policy"]["ai-security-profiles"][0]["content-type-configurations"]
                [direction]["model-protection"]
                .as_array_mut()
                .unwrap()
                .push(guardrail());
        }
        let args = [
            "runtime",
            "topics",
            "revert",
            "--profile",
            PROFILE_NAME,
            "--name",
            "Restricted",
            "--direction",
            "response",
            "--force",
        ];
        let Some((rust, ts)) = both("directional_revert_referenced", &both_directions, &args)
        else {
            return;
        };
        assert_refused_without_writes(&rust, &ts);
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some(
                "Topic is referenced in another direction or AI entry; detach those references before reverting and deleting"
            )
        );
        assert_eq!(rust.run.stderr, ts.run.stderr);
    }

    /// TS spec: "refuses %s against an absent direction or legacy layout before any write".
    #[test]
    fn an_absent_direction_or_a_legacy_layout_is_refused() {
        let mut absent = directional();
        absent["policy"]["ai-security-profiles"][0]["content-type-configurations"]
            .as_object_mut()
            .unwrap()
            .remove("tool-response");
        let legacy_profile = legacy(json!({"ai-security-profiles": [{"model-configuration": {}}]}));
        for command in ["apply", "revert"] {
            for profile in [&absent, &legacy_profile] {
                let mut args = vec![
                    "runtime",
                    "topics",
                    command,
                    "--profile",
                    PROFILE_NAME,
                    "--name",
                    "Restricted",
                    "--direction",
                    "tool-response",
                ];
                if command == "revert" {
                    args.push("--force");
                }
                let Some((rust, ts)) = both("directional_absent", profile, &args) else {
                    return;
                };
                assert_refused_without_writes(&rust, &ts);
                assert_eq!(rust.run.stderr, ts.run.stderr);
            }
        }
    }

    /// TS spec: "refuses revert while a retained inactive legacy block references the
    /// topic".
    #[test]
    fn a_retained_legacy_reference_blocks_the_revert() {
        let mut profile = directional();
        let ai = &mut profile["policy"]["ai-security-profiles"][0];
        ai["model-configuration"]["model-protection"] = json!([guardrail()]);
        ai["content-type-configurations"]["response"]["model-protection"]
            .as_array_mut()
            .unwrap()
            .push(guardrail());
        let args = [
            "runtime",
            "topics",
            "revert",
            "--profile",
            PROFILE_NAME,
            "--name",
            "Restricted",
            "--direction",
            "response",
            "--force",
        ];
        let Some((rust, ts)) = both("directional_revert_inactive", &profile, &args) else {
            return;
        };
        assert_refused_without_writes(&rust, &ts);
        assert_eq!(rust.run.stderr, ts.run.stderr);
    }

    /// A directional flag create with no policy flag at all (TS `buildProfileRequest` with
    /// `--direction`) is refused on both CLIs before OAuth (exit 2, no request). The text
    /// differs (D336, pinned on both sides by
    /// `divergence::d336_a_directional_flag_create_without_a_protection_is_refused`), and
    /// the body of a filled create differs by D335
    /// (`divergence::d335_flag_creation_writes_every_known_direction`).
    #[test]
    fn an_empty_directional_flag_creation_is_refused() {
        let args = profiles(&["create", "--name", "Empty", "--direction", "response"]);
        let Some((rust, ts)) = both(
            "directional_flag_create_empty",
            &directional(),
            &refs(&args),
        ) else {
            return;
        };
        assert_refused_without_writes(&rust, &ts);
        for side in [&rust, &ts] {
            assert!(side.requests.is_empty(), "before OAuth: {:?}", side.run);
        }
    }

    /// Several AI entries: `--ai-profile-index` selects one, also for shared settings;
    /// the others survive.
    #[test]
    fn the_ai_profile_index_selects_one_entry() {
        let mut multi = directional();
        multi["policy"]["ai-security-profiles"]
            .as_array_mut()
            .unwrap()
            .insert(
                0,
                json!({"model-type": "other", "model-configuration": {"model-protection": [{"name": "other", "action": "allow"}]}}),
            );
        let args = profiles(&[
            "update",
            PROFILE_ID,
            "--direction",
            "response",
            "--toxic-content",
            "alert",
        ]);
        let Some((rust, ts)) = both("directional_multi_refused", &multi, &refs(&args)) else {
            return;
        };
        assert_refused_without_writes(&rust, &ts);
        assert_eq!(rust.run.stderr, ts.run.stderr);
        for extra in [
            &["--direction", "response", "--toxic-content", "alert"][..],
            &["--max-inline-latency", "11"],
        ] {
            let mut args = profiles(&["update", PROFILE_ID, "--ai-profile-index", "1"]);
            args.extend(extra.iter().map(|arg| (*arg).to_owned()));
            let Some((rust, ts)) = both("directional_multi_index", &multi, &refs(&args)) else {
                return;
            };
            assert_same_writes(&rust, &ts);
            rust.run.assert_success();
            assert_eq!(
                rust.profile()["policy"]["ai-security-profiles"][0],
                multi["policy"]["ai-security-profiles"][0],
                "the other entry survives"
            );
        }
    }

    /// scm-sdk 0.2.4 and TS SDK 0.35.0 both keep an unknown direction key (with its
    /// unknown members) and treat `content-type-mode` as free text: reads print them and a
    /// shared-only edit sends them back unchanged. No direction is synthesized.
    #[test]
    fn unknown_directions_and_modes_are_kept() {
        let mut future = directional();
        let ai = &mut future["policy"]["ai-security-profiles"][0];
        ai["content-type-configurations"]["audio"] = json!({
            "model-protection": [{"name": "future-detector", "action": "alert"}],
            "future-setting": {"nested": [1, "two", null]}
        });
        ai["content-type-configurations"]
            .as_object_mut()
            .unwrap()
            .remove("tool-call");
        let mut unknown_mode = directional();
        unknown_mode["policy"]["ai-security-profiles"][0]["content-type-mode"] =
            json!("per_modality");
        for (name, profile) in [("future", &future), ("unknown_mode", &unknown_mode)] {
            let args = profiles(&["get", PROFILE_ID, "--output", "json"]);
            let Some((rust, ts)) = both(&format!("directional_{name}_get"), profile, &refs(&args))
            else {
                return;
            };
            rust.run.assert_success();
            assert_json_semantic_eq(&rust.run.json(), &ts.run.json());
            assert_json_semantic_eq(&rust.run.json()["policy"], &profile["policy"]);
            let args = profiles(&["update", PROFILE_ID, "--max-inline-latency", "7"]);
            let Some((rust, ts)) =
                both(&format!("directional_{name}_shared"), profile, &refs(&args))
            else {
                return;
            };
            assert_same_writes(&rust, &ts);
            rust.run.assert_success();
            let mut expected = profile["policy"].clone();
            expected["ai-security-profiles"][0]["model-configuration"]["latency"]["max-inline-latency"] =
                json!(7);
            assert_json_semantic_eq(&rust.body()["policy"], &expected);
            let directions =
                &rust.body()["policy"]["ai-security-profiles"][0]["content-type-configurations"];
            assert_eq!(
                directions.get("tool-call").is_some(),
                profile["policy"]["ai-security-profiles"][0]["content-type-configurations"]
                    .get("tool-call")
                    .is_some(),
                "no direction is synthesized"
            );
        }
    }

    /// scm-sdk 0.2.4 / TS SDK 0.35.0 request validation: an explicit `null` or a wrong type
    /// for a newly modelled field (`dlp_tenant_id`, `content-type-mode`,
    /// `content-type-configurations`, a known direction, `enable-full-conversation-
    /// inspection`) is refused by both CLIs before OAuth, on create and update.
    #[test]
    fn invalid_new_request_fields_are_refused_before_oauth() {
        type Edit = fn(&mut Value);
        let cases: [(&str, Edit); 10] = [
            ("dlp_number", |p| {
                p["dlp_tenant_id"] = json!(8_259_670_718_644_550_000_u64)
            }),
            ("dlp_null", |p| p["dlp_tenant_id"] = Value::Null),
            ("mode_null", |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-mode"] = Value::Null
            }),
            ("mode_number", |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-mode"] = json!(1)
            }),
            ("configurations_null", |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-configurations"] = Value::Null
            }),
            ("configurations_text", |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-configurations"] =
                    json!("prompt")
            }),
            ("tool_call_null", |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-configurations"]["tool-call"] =
                    Value::Null
            }),
            ("tool_response_array", |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-configurations"]["tool-response"] =
                    json!([])
            }),
            ("inspection_null", |p| {
                p["policy"]["ai-security-profiles"][0]["model-configuration"]["enable-full-conversation-inspection"] =
                    Value::Null
            }),
            ("inspection_text", |p| {
                p["policy"]["ai-security-profiles"][0]["model-configuration"]["enable-full-conversation-inspection"] =
                    json!("false")
            }),
        ];
        for (name, edit) in cases {
            let mut bad = directional();
            edit(&mut bad);
            for (args, path) in [
                (
                    profiles(&["create", "--config", "TMP/bad.json"]),
                    "POST /v1/mgmt/profile".to_owned(),
                ),
                (
                    profiles(&["update", PROFILE_ID, "--config", "TMP/bad.json"]),
                    format!("PUT /v1/mgmt/profile/uuid/{PROFILE_ID}"),
                ),
            ] {
                let Some((rust, ts)) = both_with(
                    &format!("directional_invalid_{name}"),
                    &directional(),
                    &[("bad.json", &bad)],
                    &refs(&args),
                ) else {
                    return;
                };
                for side in [&rust, &ts] {
                    assert_eq!(side.run.code, 2, "{name}: {:?}", side.run);
                    assert!(side.requests.is_empty(), "{name}: before OAuth");
                }
                assert_eq!(
                    usage_line(&rust.run.stderr),
                    Some(format!(
                        "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for {path} did not match schema"
                    )),
                    "{name}"
                );
            }
        }
    }
}

mod divergence {
    use super::*;

    /// D332: `--ai-profile-index` takes decimal digits only; TypeScript reads it with
    /// `Number`, so `0x0`, `1e0`, an empty value or one with spaces is an index.
    #[test]
    fn d332_ai_profile_index_takes_decimal_digits_only() {
        let profile = legacy(json!({"ai-security-profiles": [
            {"model-type": "default", "model-configuration": {"model-protection": []}}
        ]}));
        for index in ["0x0", "0e0", " 0"] {
            let args = [
                "runtime",
                "topics",
                "apply",
                "--profile",
                PROFILE_NAME,
                "--name",
                "Restricted",
                "--ai-profile-index",
                index,
            ];
            let Some((rust, ts)) = both("d332", &profile, &args) else {
                return;
            };
            rust.run.assert_code(2);
            assert_eq!(
                usage_line(&rust.run.stderr).as_deref(),
                Some("--ai-profile-index must be a nonnegative integer")
            );
            assert!(rust.requests.is_empty(), "before the tenant");
            ts.run.assert_success();
            assert_eq!(ts.writes().len(), 1, "TypeScript reads {index:?} as 0");
        }
    }

    /// D333: `revert`'s reference checks use the §13.4 identity of the topic (its name, or
    /// the id of any listed revision), as its surgery does; TypeScript's in-scope check
    /// needs the first-listed revision's id, so a ref pinned to another revision is "not
    /// assigned" there.
    #[test]
    fn d333_revert_finds_a_ref_to_any_revision() {
        let mut profile = directional();
        profile["policy"]["ai-security-profiles"][0]["content-type-configurations"]["response"]
            ["model-protection"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "topic-guardrails", "action": "allow", "topic-list": [
                {"action": "block", "topic": [{"topic_id": fixtures::uuid(2), "topic_name": "Restricted", "revision": 4}]}
            ]}));
        let args = [
            "runtime",
            "topics",
            "revert",
            "--profile",
            PROFILE_NAME,
            "--name",
            "Restricted",
            "--direction",
            "response",
            "--force",
        ];
        let Some(ts) = require_ts("d333") else {
            return;
        };
        let newer = |cli: &Cli| {
            let server = FixtureServer::start();
            let sandbox = Sandbox::new();
            sandbox.single_tenant(&server, "prod", TSG);
            server.set_profiles(TSG, vec![profile.clone()]);
            server.set_topics(
                TSG,
                vec![
                    restricted(),
                    fixtures::topic(2, "Restricted", 4, "Fixture v4"),
                ],
            );
            let out = run(cli, &sandbox, &args, &RunOptions::new());
            (out, server.requests())
        };
        let (rust, rust_requests) = newer(&rust());
        let (ts, ts_requests) = newer(&ts);
        rust.assert_success();
        assert!(
            rust_requests
                .iter()
                .any(|r| r.route == Route::ProfileUpdate)
        );
        ts.assert_code(2);
        assert_eq!(
            usage_line(&ts.stderr).as_deref(),
            Some("Topic \"Restricted\" is not assigned to the selected protection section")
        );
        assert!(!ts_requests.iter().any(|r| r.route.is_write()));
    }

    /// D334: a profile answer whose newly modelled fields hold an unexpected value (an
    /// explicit `null`, a wrong type). TypeScript SDK 0.35.0's response schema refuses the
    /// whole read; scm-sdk 0.2.4 keeps the value (its tolerant response binding), and the
    /// CLI prints it as the server sent it.
    #[test]
    fn d334_unexpected_directional_response_values_are_printed_as_sent() {
        type Edit = fn(&mut Value);
        let cases: [(&str, Edit); 5] = [
            ("dlp_null", |p| p["dlp_tenant_id"] = Value::Null),
            ("dlp_number", |p| p["dlp_tenant_id"] = json!(42)),
            ("inspection_null", |p| {
                p["policy"]["ai-security-profiles"][0]["model-configuration"]["enable-full-conversation-inspection"] =
                    Value::Null
            }),
            ("mode_number", |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-mode"] = json!(7)
            }),
            ("prompt_null", |p| {
                p["policy"]["ai-security-profiles"][0]["content-type-configurations"]["prompt"] =
                    Value::Null
            }),
        ];
        for (name, edit) in cases {
            let mut profile = directional();
            edit(&mut profile);
            let args = profiles(&["get", PROFILE_ID, "--output", "json"]);
            let Some((rust, ts)) = both(&format!("d334_{name}"), &profile, &refs(&args)) else {
                return;
            };
            rust.run.assert_success();
            let printed = rust.run.json();
            assert_eq!(printed["policy"], profile["policy"], "{name}");
            assert_eq!(
                printed.get("dlpTenantId"),
                profile.get("dlp_tenant_id"),
                "{name}: the key is kept, null included"
            );
            ts.run.assert_code(1);
            assert!(
                ts.run.stderr.contains("Response did not match schema"),
                "{name}: {}",
                ts.run.stderr
            );
            assert!(ts.run.stdout.is_empty(), "{name}");
        }
    }

    /// D335: a directional flag create fills the selected direction and writes the other
    /// three known directions as empty objects; TypeScript 7.3.0 writes the selected
    /// direction only, a body the live service refuses with HTTP 400 (MILESTONES 8.0, B7).
    /// Everything else in the body is the same on both sides.
    #[test]
    fn d335_flag_creation_writes_every_known_direction() {
        let args = profiles(&[
            "create",
            "--name",
            "Directional",
            "--direction",
            "tool-call",
            "--prompt-injection",
            "block",
            "--malicious-code",
            "block",
            "--no-enable-full-conversation-inspection",
            "--max-inline-latency",
            "8",
            "--output",
            "json",
        ]);
        let Some((rust, ts)) = both("d335", &directional(), &refs(&args)) else {
            return;
        };
        rust.run.assert_success();
        ts.run.assert_success();
        assert_eq!(
            write_lines(&rust),
            write_lines(&ts),
            "the same method and path"
        );
        assert_eq!(write_lines(&rust), ["POST /aisec/v1/mgmt/profile"]);
        let selected = json!({
            "model-protection": [{"name": "prompt-injection", "action": "block"}],
            "app-protection": {"malicious-code-protection": {"name": "malicious-code", "action": "block"}}
        });
        let shared = json!({"enable-full-conversation-inspection": false,
            "latency": {"max-inline-latency": 8}});
        let entry = |configurations: Value| {
            json!({"ai-security-profiles": [{
                "model-type": "default",
                "content-type-mode": "per_content_type",
                "model-configuration": shared.clone(),
                "content-type-configurations": configurations
            }]})
        };
        assert_eq!(
            rust.body()["policy"],
            entry(
                json!({"prompt": {}, "response": {}, "tool-call": selected.clone(), "tool-response": {}})
            )
        );
        assert_eq!(
            ts.body()["policy"],
            entry(json!({"tool-call": selected})),
            "TypeScript writes the selected direction only"
        );
        let mut rust_rest = rust.body();
        let mut ts_rest = ts.body();
        rust_rest.as_object_mut().unwrap().remove("policy");
        ts_rest.as_object_mut().unwrap().remove("policy");
        assert_eq!(rust_rest, ts_rest, "the rest of the body is the same");
    }

    /// D336: a directional flag create whose flags fill no direction (no policy flag, or
    /// shared settings only) is refused before OAuth (exit 2), because the live service
    /// refuses a directional policy with no protection in any direction (HTTP 400, B7).
    /// TypeScript 7.3.0 refuses only the create with no flag at all, with a text that
    /// points at `--config` for an empty policy, and sends a shared-only create (its
    /// `{<d>: {}}` body; the fixture server accepts it).
    #[test]
    fn d336_a_directional_flag_create_without_a_protection_is_refused() {
        const D336: &str = "Directional flag creation requires at least one protection flag, \
                            not only shared settings: the service refuses a directional policy \
                            with no protection in any direction";
        let args = profiles(&["create", "--name", "Empty", "--direction", "response"]);
        let Some((rust, ts)) = both("d336_empty", &directional(), &refs(&args)) else {
            return;
        };
        for side in [&rust, &ts] {
            assert_eq!(side.run.code, 2, "{:?}", side.run);
            assert!(side.requests.is_empty(), "before OAuth: {:?}", side.run);
        }
        assert_eq!(usage_line(&rust.run.stderr).as_deref(), Some(D336));
        assert_eq!(
            usage_line(&ts.run.stderr).as_deref(),
            Some(
                "Directional flag creation requires at least one protection or shared \
                 setting; use --config for an empty policy"
            )
        );
        for (direction, shared, stored) in [
            (
                "prompt",
                &["--max-inline-latency", "8"][..],
                json!({"latency": {"max-inline-latency": 8}}),
            ),
            (
                "response",
                &["--inline-timeout-action", "allow"],
                json!({"latency": {"inline-timeout-action": "allow"}}),
            ),
            (
                "tool-call",
                &["--no-mask-data-in-storage"],
                json!({"mask-data-in-storage": false}),
            ),
            (
                "tool-response",
                &["--enable-full-conversation-inspection"],
                json!({"enable-full-conversation-inspection": true}),
            ),
        ] {
            let mut args = profiles(&["create", "--name", "Shared", "--direction", direction]);
            args.extend(shared.iter().map(|arg| (*arg).to_owned()));
            let Some((rust, ts)) = both("d336_shared", &directional(), &refs(&args)) else {
                return;
            };
            assert_eq!(rust.run.code, 2, "{direction}: {:?}", rust.run);
            assert!(rust.requests.is_empty(), "{direction}: before OAuth");
            assert_eq!(usage_line(&rust.run.stderr).as_deref(), Some(D336));
            ts.run.assert_success();
            assert_eq!(
                write_lines(&ts),
                ["POST /aisec/v1/mgmt/profile"],
                "{direction}"
            );
            assert_eq!(
                ts.body()["policy"],
                json!({"ai-security-profiles": [{
                    "model-type": "default",
                    "content-type-mode": "per_content_type",
                    "model-configuration": stored,
                    "content-type-configurations": {direction: {}}
                }]}),
                "{direction}: TypeScript sends the shared settings and an empty direction"
            );
        }
        // An invalid shared value is reported as such on both CLIs: the flag check runs
        // before the D336 gate. The texts differ by D102 (TypeScript prints its request
        // schema's issue for the field).
        let args = profiles(&[
            "create",
            "--name",
            "Shared",
            "--direction",
            "prompt",
            "--max-inline-latency",
            "1.5",
        ]);
        let Some((rust, ts)) = both("d336_invalid", &directional(), &refs(&args)) else {
            return;
        };
        for side in [&rust, &ts] {
            assert_eq!(side.run.code, 2, "{:?}", side.run);
            assert!(side.requests.is_empty(), "before OAuth: {:?}", side.run);
        }
        assert_eq!(
            usage_line(&rust.run.stderr).as_deref(),
            Some("--max-inline-latency must be a non-negative integer")
        );
        assert!(
            ts.run.stderr.contains("\"max-inline-latency\""),
            "{:?}",
            ts.run
        );
    }
}

/// A `topic-guardrails` item that blocks `Restricted`.
fn guardrail() -> Value {
    json!({"name": "topic-guardrails", "action": "allow", "topic-list": [
        {"action": "block", "topic": [{"topic_id": fixtures::uuid(1), "topic_name": "Restricted", "revision": 3}]}
    ]})
}
