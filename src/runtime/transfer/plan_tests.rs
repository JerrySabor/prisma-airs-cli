//! The planner cases of the TypeScript `tests/unit/backup/runtime-profiles.spec.ts`,
//! driven through the pure stages with in-memory inventories (the executor cases run
//! against the loopback fixture in `tests/runtime_transfer.rs`).

use super::*;
use serde_json::json;

fn source_topic() -> Value {
    json!({"topic_id": "source-topic", "topic_name": "Restricted", "revision": 3,
        "description": "Sensitive business topics", "examples": ["Example"], "active": true})
}

fn profile(name: &str) -> Value {
    json!({
        "profile_id": format!("source-{name}"), "profile_name": name, "tsg_id": "100",
        "revision": 8, "active": true, "created_by": "source-user", "csp_id": "source-csp",
        "policy": {
            "ai-security-profiles": [{"model-configuration": {
                "model-protection": [{"name": "topic-guardrail", "topic-list": [{"action": "block",
                    "topic": [{"topic_id": "source-topic", "topic_name": "Restricted", "revision": 3}]}]}],
                "mask-data-in-storage": true,
            }}],
            "dlp-data-profiles": [],
            "future_setting": {"enabled": true},
        }
    })
}

fn with_dlp() -> Value {
    let mut input = profile("Production");
    let policy = &mut input["policy"];
    policy["dlp-data-profiles"] = json!([{"name": "Source DLP", "uuid": "source-dlp",
        "id": "source-dlp", "version": "2", "rule1": {"action": "block"}}]);
    policy["ai-security-profiles"][0]["model-configuration"]["data-protection"] = json!({
        "data-leak-detection": {"action": "block",
            "member": [{"text": "Source DLP", "id": "source-dlp", "version": "2"}]}
    });
    input
}

fn detection(profile: &mut Value) -> &mut Value {
    &mut profile["policy"]["ai-security-profiles"][0]["model-configuration"]["data-protection"]["data-leak-detection"]
}

fn options() -> Options {
    Options {
        prefix: String::new(),
        conflict: Conflict::Error,
        dlp_map: Vec::new(),
        missing_dlp: MissingDlp::Error,
    }
}

/// The destination of a run, and which inventories the planner read.
#[derive(Default)]
struct Destination {
    profiles: Vec<Value>,
    topics: Vec<Value>,
    catalog: Vec<Value>,
    read_topics: std::cell::Cell<bool>,
    read_catalog: std::cell::Cell<bool>,
}

impl Destination {
    fn with_catalog() -> Self {
        Self {
            catalog: vec![json!({"id": "dest-dlp", "name": "Destination DLP", "version": 5})],
            ..Self::default()
        }
    }
}

/// Every planner stage, reading only the inventories TypeScript reads.
fn plan_all(
    profiles: &[Value],
    topics: &[Value],
    destination_tsg: &str,
    options: &Options,
    destination: &Destination,
) -> Result<RestorePlan, String> {
    let prepared = prepare(profiles, "100", destination_tsg, options)?;
    assert_tenant(&destination.profiles, destination_tsg)?;
    let plans = plan_profiles(&prepared, &destination.profiles, options)?;
    let refs = changing_refs(&plans)?;
    let target_topics: &[Value] = if refs.is_empty() {
        &[]
    } else {
        destination.read_topics.set(true);
        &destination.topics
    };
    let topic_plans = plan_topics(&refs, topics, target_topics, &options.prefix)?;
    let dlp = dlp_names(&plans, prepared.cross_tenant, options)?;
    let catalog: &[Value] = if dlp.needs_catalog(prepared.cross_tenant, options) {
        destination.read_catalog.set(true);
        &destination.catalog
    } else {
        &[]
    };
    finish(
        Finish {
            source_tsg: "100",
            destination_tsg,
            cross_tenant: prepared.cross_tenant,
            profiles: plans,
            topics: topic_plans,
            dlp,
            catalog,
        },
        options,
    )
}

/// A destination profile created from a plan item the way the fixture does (the mapped
/// policy, a fresh id, TSG 200).
fn created(item: &ProfilePlan, plan: &RestorePlan, topics: &[(String, Value)], n: usize) -> Value {
    let policy = mapped_policy(item, &plan.dlp_mappings, topics).unwrap();
    let mut record = profile_body(&item.name, &item.source, &policy);
    record["profile_id"] = json!(format!("dest-{n}"));
    record["revision"] = json!(1);
    record["tsg_id"] = json!("200");
    record
}

fn dest_topic(source: &Value, id: &str) -> Value {
    let mut topic = source.clone();
    topic["topic_id"] = json!(id);
    topic["revision"] = json!(1);
    topic
}

/// The destination after a complete create of every profile and topic of `plan`.
fn restored(plan: &RestorePlan) -> Destination {
    let topics: Vec<(String, Value)> = plan
        .topics
        .iter()
        .enumerate()
        .map(|(n, topic)| {
            (
                topic.key.clone(),
                topic
                    .existing
                    .clone()
                    .unwrap_or_else(|| dest_topic(&topic.source, &format!("dest-topic-{n}"))),
            )
        })
        .collect();
    Destination {
        profiles: plan
            .profiles
            .iter()
            .enumerate()
            .map(|(n, item)| created(item, plan, &topics, n))
            .collect(),
        topics: topics.into_iter().map(|(_, topic)| topic).collect(),
        ..Destination::with_catalog()
    }
}

#[test]
fn verify_resumes_with_rewritten_topic_ids_and_creates_only_missing() {
    let first = plan_all(
        &[profile("Production")],
        &[source_topic()],
        "200",
        &options(),
        &Destination::default(),
    )
    .unwrap();
    let destination = restored(&first);
    let verify = Options {
        conflict: Conflict::Verify,
        ..options()
    };
    let plan = plan_all(
        &[profile("Production"), profile("Second")],
        &[source_topic()],
        "200",
        &verify,
        &destination,
    )
    .unwrap();
    let actions: Vec<Action> = plan.profiles.iter().map(|p| p.action).collect();
    assert_eq!(actions, [Action::Verify, Action::Create]);
    assert!(plan.topics.iter().all(|topic| topic.existing.is_some()));
}

#[test]
fn verify_mismatches_are_refused_before_writes() {
    for mismatch in ["policy", "active", "missing-topic"] {
        let first = plan_all(
            &[profile("Production")],
            &[source_topic()],
            "200",
            &options(),
            &Destination::default(),
        )
        .unwrap();
        let mut destination = restored(&first);
        match mismatch {
            "active" => destination.profiles[0]["active"] = json!(false),
            "policy" => destination.profiles[0]["policy"] = json!({"unexpected": true}),
            _ => destination.topics.clear(),
        }
        let verify = Options {
            conflict: Conflict::Verify,
            ..options()
        };
        assert!(
            plan_all(
                &[profile("Production")],
                &[source_topic()],
                "200",
                &verify,
                &destination
            )
            .is_err(),
            "{mismatch}"
        );
    }
}

#[test]
fn server_added_severity_is_recorded_by_verification() {
    let mut input = profile("Production");
    input["policy"] = json!({"ai-security-profiles": [{"model-configuration":
        {"model-protection": [{"name": "prompt-injection", "action": "block"}]}}]});
    let first = plan_all(
        &[input.clone()],
        &[],
        "200",
        &options(),
        &Destination::default(),
    )
    .unwrap();
    let mut destination = restored(&first);
    destination.profiles[0]["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"]
        [0]["severity"] = json!("medium");
    let verify = Options {
        conflict: Conflict::Verify,
        ..options()
    };
    let plan = plan_all(&[input], &[], "200", &verify, &destination).unwrap();
    assert_eq!(plan.server_defaults.len(), 1);
    assert_eq!(plan.server_defaults[0].fields.len(), 1);
}

#[test]
fn the_builtin_sensitive_content_member_needs_no_catalog() {
    for name in ["sensitive content", "Sensitive Content"] {
        let mut input = with_dlp();
        input["policy"]["dlp-data-profiles"] = json!([]);
        detection(&mut input)["member"] = json!([{"text": name, "id": "", "version": "2"}]);
        detection(&mut input)["mask-data-inline"] = json!(true);
        let original = input.clone();
        let destination = Destination::with_catalog();
        let plan = plan_all(
            &[input.clone()],
            &[source_topic()],
            "200",
            &options(),
            &destination,
        )
        .unwrap();
        assert!(plan.dlp_mappings.is_empty() && plan.dlp_fallbacks.is_empty());
        assert!(!destination.read_catalog.get(), "{name}");
        let topics: Vec<(String, Value)> = vec![(
            plan.topics[0].key.clone(),
            dest_topic(&source_topic(), "dest-topic-0"),
        )];
        let mapped = mapped_policy(&plan.profiles[0], &plan.dlp_mappings, &topics).unwrap();
        assert_eq!(
            mapped["ai-security-profiles"][0]["model-configuration"]["data-protection"]["data-leak-detection"],
            *detection(&mut input)
        );
        assert_eq!(input, original);
    }
}

#[test]
fn a_custom_profile_named_sensitive_content_needs_a_mapping() {
    let mut input = with_dlp();
    detection(&mut input)["member"] =
        json!([{"text": "sensitive content", "id": "custom-id", "version": "2"}]);
    let error = plan_all(
        &[input],
        &[source_topic()],
        "200",
        &options(),
        &Destination::with_catalog(),
    )
    .unwrap_err();
    assert!(error.contains("--dlp-map"), "{error}");
}

#[test]
fn basic_fallback_keeps_the_action_and_unrelated_settings() {
    for action in ["block", "allow", ""] {
        let mut input = with_dlp();
        detection(&mut input)["action"] = json!(action);
        let original = input.clone();
        let basic = Options {
            missing_dlp: MissingDlp::Basic,
            ..options()
        };
        let plan = plan_all(
            &[input.clone()],
            &[source_topic()],
            "200",
            &basic,
            &Destination::with_catalog(),
        )
        .unwrap();
        assert_eq!(
            plan.dlp_fallbacks,
            vec![DlpFallback {
                profile: "Production".into(),
                unresolved: vec!["Source DLP".into()],
                replaced: vec!["Source DLP".into()],
            }]
        );
        let fallback = plan.profiles[0].fallback.clone().unwrap();
        assert_eq!(fallback["dlp-data-profiles"], json!([]));
        assert_eq!(fallback["future_setting"], json!({"enabled": true}));
        let actual = &fallback["ai-security-profiles"][0]["model-configuration"]["data-protection"]
            ["data-leak-detection"];
        assert_eq!(actual["action"], json!(action));
        let expected = if action.is_empty() {
            Value::Null
        } else {
            json!([{"text": "sensitive content", "id": "", "version": "2"}])
        };
        assert_eq!(actual["member"], expected);
        assert!(!fallback.to_string().contains("source-dlp"));
        assert_eq!(input, original);
        assert_eq!(plan.profiles[0].source["policy"], original["policy"]);
    }
}

#[test]
fn mappings_win_over_fallback_and_missing_mapped_profiles_fall_back() {
    let both = Options {
        missing_dlp: MissingDlp::Basic,
        dlp_map: vec![("Source DLP".into(), "Destination DLP".into())],
        ..options()
    };
    let plan = plan_all(
        &[with_dlp()],
        &[source_topic()],
        "200",
        &both,
        &Destination::with_catalog(),
    )
    .unwrap();
    assert!(plan.dlp_fallbacks.is_empty());
    assert_eq!(plan.dlp_mappings.len(), 1);
    let missing = Options {
        dlp_map: vec![("Source DLP".into(), "Missing".into())],
        ..both.clone()
    };
    let plan = plan_all(
        &[with_dlp()],
        &[source_topic()],
        "200",
        &missing,
        &Destination::default(),
    )
    .unwrap();
    assert_eq!(plan.dlp_fallbacks.len(), 1);
    assert!(plan.dlp_mappings.is_empty());
}

#[test]
fn a_same_tenant_basic_fallback_reads_the_catalog() {
    let basic = Options {
        missing_dlp: MissingDlp::Basic,
        ..options()
    };
    let destination = Destination::default();
    let plan = plan_all(
        &[with_dlp()],
        &[source_topic()],
        "100",
        &basic,
        &destination,
    )
    .unwrap();
    assert!(destination.read_catalog.get());
    assert_eq!(plan.dlp_fallbacks.len(), 1);
}

#[test]
fn ambiguous_destination_dlp_profiles_are_refused() {
    let destination = Destination {
        catalog: vec![
            json!({"id": "a", "name": "Destination DLP", "version": 1}),
            json!({"id": "b", "name": "Destination DLP", "version": 1}),
        ],
        ..Destination::default()
    };
    let both = Options {
        missing_dlp: MissingDlp::Basic,
        dlp_map: vec![("Source DLP".into(), "Destination DLP".into())],
        ..options()
    };
    let error = plan_all(&[with_dlp()], &[source_topic()], "200", &both, &destination).unwrap_err();
    assert!(error.contains("ambiguous"), "{error}");
}

#[test]
fn a_partial_mapping_reports_every_custom_name() {
    let mut input = with_dlp();
    detection(&mut input)["member"]
        .as_array_mut()
        .unwrap()
        .push(json!({"text": "Unmapped", "id": "unmapped-id", "version": "1"}));
    let both = Options {
        missing_dlp: MissingDlp::Basic,
        dlp_map: vec![("Source DLP".into(), "Destination DLP".into())],
        ..options()
    };
    let plan = plan_all(
        &[input],
        &[source_topic()],
        "200",
        &both,
        &Destination::with_catalog(),
    )
    .unwrap();
    assert_eq!(plan.dlp_fallbacks[0].replaced, ["Source DLP", "Unmapped"]);
    assert!(plan.dlp_mappings.is_empty());
    assert_eq!(plan.dlp_fallbacks[0].unresolved, ["Unmapped"]);
}

#[test]
fn masking_with_allow_is_refused() {
    let mut input = with_dlp();
    detection(&mut input)["action"] = json!("allow");
    detection(&mut input)["mask-data-inline"] = json!(true);
    let basic = Options {
        missing_dlp: MissingDlp::Basic,
        ..options()
    };
    let error = plan_all(
        &[input],
        &[source_topic()],
        "200",
        &basic,
        &Destination::with_catalog(),
    )
    .unwrap_err();
    assert!(error.contains("masking requires a block"), "{error}");
}

#[test]
fn skipped_profiles_are_not_inspected() {
    let mut existing = profile("Production");
    existing["tsg_id"] = json!("200");
    existing["profile_id"] = json!("destination-profile");
    let destination = Destination {
        profiles: vec![existing],
        ..Destination::with_catalog()
    };
    let skip = Options {
        missing_dlp: MissingDlp::Basic,
        conflict: Conflict::Skip,
        ..options()
    };
    let plan = plan_all(&[with_dlp()], &[source_topic()], "200", &skip, &destination).unwrap();
    assert!(plan.dlp_fallbacks.is_empty() && plan.topics.is_empty());
    assert!(!destination.read_catalog.get() && !destination.read_topics.get());
}

#[test]
fn unexpected_tenant_references_are_refused_cross_tenant() {
    for key in ["objectId", "extra_uuid"] {
        let mut input = profile("Production");
        input["policy"]["ai-security-profiles"][0]["model-configuration"]["model-protection"][0]
            ["topic-list"][0]["topic"][0][key] = json!("unmapped-source-id");
        let error = prepare(&[input.clone()], "100", "200", &options()).unwrap_err();
        assert!(
            error.starts_with("Unsupported cross-tenant policy reference at policy."),
            "{error}"
        );
        assert!(
            prepare(&[input], "100", "100", &options()).is_ok(),
            "same tenant: {key}"
        );
    }
    let mut input = profile("Production");
    input["policy"]["future"] = json!({"object_id": "source-only"});
    assert_eq!(
        prepare(&[input], "100", "200", &options()).unwrap_err(),
        "Unsupported cross-tenant policy reference at policy.future.object_id"
    );
}

#[test]
fn fresh_bodies_carry_only_the_request_keys_and_the_prefix() {
    let prefixed = Options {
        prefix: "migrated-".into(),
        ..options()
    };
    let plan = plan_all(
        &[profile("Production")],
        &[source_topic()],
        "200",
        &prefixed,
        &Destination::default(),
    )
    .unwrap();
    assert_eq!(plan.profiles[0].name, "migrated-Production");
    assert_eq!(plan.topics[0].name, "migrated-Restricted");
    let topic = topic_body(&plan.topics[0].name, &plan.topics[0].source);
    let keys: Vec<&String> = topic.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["active", "description", "examples", "topic_name"]);
    let topics = vec![(
        plan.topics[0].key.clone(),
        dest_topic(&source_topic(), "dest-topic-0"),
    )];
    let policy = mapped_policy(&plan.profiles[0], &plan.dlp_mappings, &topics).unwrap();
    let body = profile_body(&plan.profiles[0].name, &plan.profiles[0].source, &policy);
    let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["active", "policy", "profile_name"]);
    let text = policy.to_string();
    assert!(text.contains("dest-topic-0") && !text.contains("source-topic"));
    assert_eq!(policy["future_setting"], json!({"enabled": true}));
}

#[test]
fn dlp_mappings_bind_destination_ids_and_versions() {
    let error = plan_all(
        &[with_dlp()],
        &[source_topic()],
        "200",
        &options(),
        &Destination::with_catalog(),
    )
    .unwrap_err();
    assert!(
        error.contains("--dlp-map") && error.contains("airs runtime dlp"),
        "{error}"
    );
    let mapped = Options {
        dlp_map: vec![("Source DLP".into(), "Destination DLP".into())],
        ..options()
    };
    let plan = plan_all(
        &[with_dlp()],
        &[source_topic()],
        "200",
        &mapped,
        &Destination::with_catalog(),
    )
    .unwrap();
    let topics = vec![(
        plan.topics[0].key.clone(),
        dest_topic(&source_topic(), "dest-topic-0"),
    )];
    let policy = mapped_policy(&plan.profiles[0], &plan.dlp_mappings, &topics).unwrap();
    assert_eq!(
        policy["dlp-data-profiles"][0],
        json!({"name": "Destination DLP", "uuid": "dest-dlp", "id": "dest-dlp", "version": "5",
            "rule1": {"action": "block"}})
    );
    assert!(!policy.to_string().contains("source-dlp"));
}

#[test]
fn unknown_dlp_versions_are_refused() {
    let destination = Destination {
        catalog: vec![json!({"id": "dest-dlp", "name": "Destination DLP"})],
        ..Destination::default()
    };
    let mapped = Options {
        dlp_map: vec![("Source DLP".into(), "Destination DLP".into())],
        ..options()
    };
    let error = plan_all(
        &[with_dlp()],
        &[source_topic()],
        "200",
        &mapped,
        &destination,
    )
    .unwrap_err();
    assert!(error.contains("version is unknown"), "{error}");
}

#[test]
fn identical_topics_are_reused_and_others_refused() {
    let mut existing = source_topic();
    existing["topic_id"] = json!("dest-existing");
    existing["revision"] = json!(9);
    let mut destination = Destination {
        topics: vec![existing],
        ..Destination::default()
    };
    let plan = plan_all(
        &[profile("Production")],
        &[source_topic()],
        "200",
        &options(),
        &destination,
    )
    .unwrap();
    assert_eq!(
        plan.topics[0].existing.as_ref().unwrap()["topic_id"],
        json!("dest-existing")
    );
    destination.topics[0]["description"] = json!("Different");
    let error = plan_all(
        &[profile("Production")],
        &[source_topic()],
        "200",
        &options(),
        &destination,
    )
    .unwrap_err();
    assert!(error.contains("topic differs"), "{error}");
    let mut other = source_topic();
    other["topic_id"] = json!("other");
    destination.topics.push(other);
    let error = plan_all(
        &[profile("Production")],
        &[source_topic()],
        "200",
        &options(),
        &destination,
    )
    .unwrap_err();
    assert!(error.contains("Ambiguous destination topic"), "{error}");
}

#[test]
fn a_topic_without_examples_matches_an_empty_list() {
    let mut stored = source_topic();
    stored["examples"] = json!([]);
    let mut absent = source_topic();
    absent.as_object_mut().unwrap().remove("examples");
    assert!(same_topic(&stored, &absent));
    absent["active"] = Value::Null;
    assert!(same_topic(&stored, &absent), "null active reads as true");
    absent["description"] = json!("x");
    assert!(!same_topic(&stored, &absent));
}

#[test]
fn conflicts_default_to_refusal_and_skip_creates_nothing() {
    let mut existing = profile("Production");
    existing["tsg_id"] = json!("200");
    existing["profile_id"] = json!("destination-profile");
    let destination = Destination {
        profiles: vec![existing],
        ..Destination::default()
    };
    let error = plan_all(
        &[profile("Production")],
        &[source_topic()],
        "200",
        &options(),
        &destination,
    )
    .unwrap_err();
    assert_eq!(
        error,
        "Destination profile already exists: Production; choose --on-conflict verify, skip or update"
    );
    let skip = Options {
        conflict: Conflict::Skip,
        ..options()
    };
    let plan = plan_all(
        &[profile("Production")],
        &[source_topic()],
        "200",
        &skip,
        &destination,
    )
    .unwrap();
    assert!(plan.topics.is_empty());
    assert_eq!(plan.profiles[0].action, Action::Skip);
    let update = Options {
        conflict: Conflict::Update,
        ..options()
    };
    let plan = plan_all(
        &[profile("Production")],
        &[source_topic()],
        "200",
        &update,
        &destination,
    )
    .unwrap();
    assert_eq!(plan.profiles[0].action, Action::Update);
    assert_eq!(
        plan.profiles[0].existing.as_ref().unwrap()["profile_id"],
        json!("destination-profile")
    );
    assert_eq!((plan.changing(), plan.updates()), (1, 1));
}

#[test]
fn invalid_selections_are_refused_before_requests() {
    let mut other_tsg = profile("Production");
    other_tsg["tsg_id"] = json!("wrong");
    assert_eq!(
        prepare(&[other_tsg], "100", "200", &options()).unwrap_err(),
        "Destination/source profile tenant identity does not match the selected TSG"
    );
    let mut older = profile("Production");
    older["revision"] = json!(1);
    assert_eq!(
        prepare(&[profile("Production"), older], "100", "200", &options()).unwrap_err(),
        "Backup contains duplicate profile names/revisions"
    );
    let mut bare = profile("Production");
    bare.as_object_mut().unwrap().remove("policy");
    assert_eq!(
        prepare(&[bare], "100", "200", &options()).unwrap_err(),
        "Backup profile has no policy"
    );
}

#[test]
fn latest_profiles_keep_one_revision_per_name() {
    let mut older = profile("Production");
    older["revision"] = json!(1);
    let rows = vec![older, profile("Production"), profile("Other")];
    let kept = latest_profiles(&rows).unwrap();
    assert_eq!(kept, [2, 1], "name order, the highest revision");
    let mut different = profile("Production");
    different["profile_id"] = json!("different");
    assert_eq!(
        latest_profiles(&[profile("Production"), different]).unwrap_err(),
        Refusal::Withheld("Ambiguous profile name: Production".to_owned())
    );
    assert_eq!(
        latest_profiles(&[profile("Production"), profile("Production")]).unwrap_err(),
        Refusal::Stated("Inventory contains repeated profile records".to_owned())
    );
    assert_eq!(
        latest_profiles(&[profile(" ")]).unwrap_err(),
        Refusal::Withheld(NAME_RULE.to_owned())
    );
    assert!(latest_profiles(&[profile("a\u{1b}")]).is_err());
    assert!(
        latest_profiles(&[profile("a\u{85}")]).is_ok(),
        "C1 passes (TS)"
    );
}

#[test]
fn offset_walks_follow_the_typescript_page_rules() {
    let page = |rows: usize, next: Option<Value>| {
        let mut value =
            json!({"ai_profiles": (0..rows).map(|n| json!({"n": n})).collect::<Vec<_>>()});
        if let Some(next) = next {
            value["next_offset"] = next;
        }
        crate::json::parse(&value.to_string()).unwrap()
    };
    let walk = || OffsetWalk::new(Collection::Profiles, 2, "absent".into());
    let mut done = walk();
    assert_eq!(done.accept(&page(1, Some(json!(100)))), Ok(Step::Next(100)));
    assert_eq!(done.accept(&page(1, Some(json!(0)))), Ok(Step::Done));
    assert_eq!(done.into_items().len(), 2);
    let mut capped = walk();
    capped.accept(&page(1, Some(json!(1)))).unwrap();
    assert_eq!(
        capped.accept(&page(1, Some(json!(2)))),
        Err(Refusal::Stated(INCOMPLETE.to_owned()))
    );
    for stalled in [
        page(0, Some(json!(5))),
        page(1, Some(json!(1.5))),
        page(1, Some(json!(-1))),
    ] {
        let mut stall = walk();
        assert_eq!(
            stall.accept(&stalled),
            Err(Refusal::Stated(
                "Inventory pagination did not advance".to_owned()
            ))
        );
    }
    let mut repeated = walk();
    repeated.accept(&page(1, Some(json!(3)))).unwrap();
    assert_eq!(
        repeated.accept(&page(1, Some(json!(3)))),
        Err(Refusal::Stated(
            "Inventory pagination did not advance".to_owned()
        ))
    );
    let mut absent = walk();
    assert_eq!(
        absent.accept(&crate::json::parse("{}").unwrap()),
        Err(Refusal::Stated("absent".to_owned())),
        "D218: an absent collection is not an empty one"
    );
    let mut big = OffsetWalk::new(Collection::Profiles, 1000, "absent".into());
    assert_eq!(
        big.accept(&page(10_001, None)),
        Err(Refusal::Stated(
            "Inventory exceeds the 10000-record safety limit".to_owned()
        ))
    );
}

#[test]
fn topic_references_must_be_well_formed() {
    let bad = json!({"x": [{"topic_id": "a", "topic_name": "n", "revision": -1}]});
    assert_eq!(
        topic_references(Some(&bad)).unwrap_err(),
        Refusal::Withheld("Invalid topic identity in profile policy".to_owned())
    );
    let good = json!({"x": [{"topic_id": "a", "topic_name": "n", "revision": 2}]});
    let refs = topic_references(Some(&good)).unwrap();
    assert_eq!(refs[0].key(), "[\"a\",2]");
    assert!(id_like("object_id") && id_like("objectId") && id_like("uuid") && !id_like("idea"));
}

/// D217: a refusal's kind is what TS's `result.error` rule
/// (`/^(Destination|Topic response|Missing planned|Restored profile|Inventory|DLP inventory)/`)
/// makes of its message, for every refusal the execution can meet.
#[test]
fn refusal_kinds_follow_the_typescript_result_error_rule() {
    fn ts_states(message: &str) -> bool {
        [
            "Destination",
            "Topic response",
            "Missing planned",
            "Restored profile",
            "Inventory",
            "DLP inventory",
        ]
        .iter()
        .any(|prefix| message.starts_with(prefix))
    }
    let mut different = profile("Production");
    different["profile_id"] = json!("different");
    let mut foreign = profile("Production");
    foreign["tsg_id"] = json!("999");
    let refusals = [
        latest_profiles(&[profile("Production"), different]).unwrap_err(),
        latest_profiles(&[profile("Production"), profile("Production")]).unwrap_err(),
        latest_profiles(&[profile(" ")]).unwrap_err(),
        assert_tenant([&foreign], "100").unwrap_err(),
        topic_references(Some(&json!({"x": [{"topic_id": 1}]}))).unwrap_err(),
        dlp_references(Some(&json!({"dlp-data-profiles": [{}]}))).unwrap_err(),
        dlp_references(Some(
            &json!({"ai-security-profiles": [{"model-configuration":
            {"data-protection": {"data-leak-detection": {"member": [{}]}}}}]}),
        ))
        .unwrap_err(),
        OffsetWalk::new(
            Collection::Topics,
            1,
            "Destination inventory of custom topics was not returned; nothing was changed".into(),
        )
        .accept(&crate::json::parse("{}").unwrap())
        .unwrap_err(),
    ];
    for refusal in &refusals {
        assert_eq!(
            refusal.stated().is_some(),
            ts_states(refusal.message()),
            "{refusal:?}"
        );
    }
    assert!(refusals.iter().any(|refusal| refusal.stated().is_none()));
}

#[test]
fn unchanged_normalises_only_database_security() {
    let prior = json!({"profile_id": "p", "revision": 1, "active": true,
        "policy": {"ai-security-profiles": [{"model-configuration": {"data-protection": {}}}]}});
    let mut current = prior.clone();
    current["policy"]["ai-security-profiles"][0]["model-configuration"]["data-protection"]["database-security"] =
        Value::Null;
    assert!(unchanged(Some(&current), &prior));
    current["revision"] = json!(2);
    assert!(!unchanged(Some(&current), &prior));
    assert!(!unchanged(None, &prior));
}

/// TS 7.3.0 (§13.17): the DLP walk, the Basic fallback and the canonical policy cover a
/// directional entry's directions and its retained `model-configuration`; the
/// canonical `database-security: null` applies to legacy entries only.
#[test]
fn directional_sections_are_walked() {
    let mut policy = airs_test_harness::fixtures::runtime::directional_profile()["policy"].clone();
    let entry = &mut policy["ai-security-profiles"][0];
    entry["content-type-configurations"]["response"]["data-protection"]["data-leak-detection"]["member"] =
        json!([{"text": "My Profile", "id": "dp-1", "version": "1"}]);
    entry["model-configuration"]["data-protection"] = json!({"data-leak-detection": {
        "action": "block", "member": [{"text": "Retained", "id": "dp-2"}]}});
    let refs = dlp_references(Some(&policy)).unwrap();
    let found: Vec<(String, Vec<PathStep>)> = refs
        .iter()
        .map(|reference| (reference.name.clone(), reference.path.clone()))
        .collect();
    let path = |block: &[&str], at: usize| {
        let mut steps = vec![
            PathStep::Key("ai-security-profiles".into()),
            PathStep::Index(0),
        ];
        steps.extend(block.iter().map(|key| PathStep::Key((*key).into())));
        steps.extend([
            PathStep::Key("data-protection".into()),
            PathStep::Key("data-leak-detection".into()),
            PathStep::Key("member".into()),
            PathStep::Index(at),
        ]);
        steps
    };
    assert_eq!(
        found,
        vec![
            ("Retained".to_owned(), path(&["model-configuration"], 0)),
            (
                "My Profile".to_owned(),
                path(&["content-type-configurations", "response"], 0)
            ),
        ],
        "the built-in Basic members of the other directions are not references"
    );
    let fallback = basic_fallback(Some(&policy)).unwrap();
    let basic = json!([{"text": "sensitive content", "id": "", "version": "2"}]);
    let entry = &fallback["ai-security-profiles"][0];
    assert_eq!(
        entry["content-type-configurations"]["response"]["data-protection"]["data-leak-detection"]
            ["member"],
        basic
    );
    assert_eq!(
        entry["model-configuration"]["data-protection"]["data-leak-detection"]["member"],
        basic
    );
    let mut legacy_and_directional = json!({"ai-security-profiles": [
        {"model-configuration": {"data-protection": {}}},
        {"content-type-mode": "per_content_type", "model-configuration": {"data-protection": {}},
         "content-type-configurations": {"prompt": {"data-protection": {}}}}
    ]});
    let canonical = canonical_policy(Some(&legacy_and_directional)).unwrap();
    legacy_and_directional["ai-security-profiles"][0]["model-configuration"]["data-protection"]["database-security"] =
        Value::Null;
    assert_eq!(canonical, legacy_and_directional);
}
