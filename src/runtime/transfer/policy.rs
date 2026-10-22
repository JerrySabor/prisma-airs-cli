//! TypeScript `compareRuntimePolicies` (`src/backup/runtime-policy.ts`), ported verbatim
//! on `serde_json::Value` (DESIGN §18.16): the directional comparison of a requested
//! policy with its read-back, where only the observed server defaults (fields the source
//! omitted) may differ. They are recorded as `serverDefaults` paths; every other
//! difference fails the comparison.
//!
//! JavaScript semantics kept: `===` on scalars (numbers by value), objects and arrays
//! compared element by element, an absent value (`undefined`) distinct from `null`.
//! Object keys are visited in the order of the value (`serde_json` sorts them; TypeScript
//! visits insertion order, so only the order of reported paths can differ, D35).

use serde_json::{Map, Value};

/// The result of one comparison.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    pub matches: bool,
    pub server_defaults: Vec<String>,
    pub differences: Vec<String>,
}

/// `compareRuntimePolicies(expected, actual)`; `None` is `undefined`.
pub fn compare(expected: Option<&Value>, actual: Option<&Value>) -> Comparison {
    let mut walk = Walk::default();
    walk.visit(expected, actual, "policy", false, false);
    Comparison {
        matches: walk.differences.is_empty(),
        server_defaults: walk.server_defaults,
        differences: walk.differences,
    }
}

/// JavaScript `===` of two JSON values: scalars by value, `undefined === undefined`;
/// objects and arrays are never identical (the TypeScript inputs are distinct clones).
pub fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

/// Whether `text` matches `pattern` exactly, where `#` stands for one or more ASCII
/// digits (the `\d+` of the TypeScript regular expressions) and every other character is
/// literal.
pub(crate) fn matches_pattern(text: &str, pattern: &str) -> bool {
    match_prefix(text, pattern) == Some(text.len())
}

/// The length of the prefix of `text` that matches `pattern` (see [`matches_pattern`]).
fn match_prefix(text: &str, pattern: &str) -> Option<usize> {
    let text = text.as_bytes();
    let mut at = 0;
    for &expected in pattern.as_bytes() {
        if expected == b'#' {
            let digits = text[at..].iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 {
                return None;
            }
            at += digits;
        } else if text.get(at) == Some(&expected) {
            at += 1;
        } else {
            return None;
        }
    }
    Some(at)
}

/// `path.replace(/^policy\.ai-security-profiles\[\d+\]\.model-configuration/, 'model')`.
fn relative(path: &str) -> String {
    match match_prefix(path, "policy.ai-security-profiles[#].model-configuration") {
        Some(end) => format!("model{}", &path[end..]),
        None => path.to_owned(),
    }
}

/// `value.name` of an object as a string.
fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key)
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

#[derive(Default)]
struct Walk {
    server_defaults: Vec<String>,
    differences: Vec<String>,
}

impl Walk {
    fn visit(
        &mut self,
        source: Option<&Value>,
        target: Option<&Value>,
        path: &str,
        toxic: bool,
        topics: bool,
    ) {
        if strict_eq(source, target) {
            return;
        }
        match (source, target) {
            (Some(Value::Array(source)), Some(Value::Array(target))) => {
                if source.len() != target.len() {
                    self.differences.push(format!("{path}.length"));
                }
                for (index, item) in source.iter().enumerate() {
                    self.visit(
                        Some(item),
                        target.get(index),
                        &format!("{path}[{index}]"),
                        toxic,
                        topics,
                    );
                }
            }
            (Some(Value::Object(source)), Some(Value::Object(target))) => {
                self.objects(source, target, path, toxic, topics);
            }
            _ => self.differences.push(path.to_owned()),
        }
    }

    fn objects(
        &mut self,
        source: &Map<String, Value>,
        target: &Map<String, Value>,
        path: &str,
        toxic: bool,
        topics: bool,
    ) {
        let mut keys: Vec<&String> = source.keys().collect();
        keys.extend(target.keys().filter(|key| !source.contains_key(*key)));
        let same_name = |source: &Map<String, Value>, target: &Map<String, Value>| {
            strict_eq(field(source, "name"), field(target, "name"))
        };
        for key in keys {
            let field_path = format!("{path}.{key}");
            match (source.get(key), target.get(key)) {
                (None, Some(added)) => {
                    if self.server_default(source, target, path, key, added, toxic, topics) {
                        self.server_defaults.push(field_path);
                    } else {
                        self.differences.push(field_path);
                    }
                }
                (Some(_), None) => self.differences.push(field_path),
                (Some(child_source), Some(child_target)) => {
                    let detector = matches_pattern(
                        path,
                        "policy.ai-security-profiles[#].model-configuration.model-protection[#]",
                    );
                    let child_toxic = key == "toxic-category-list"
                        && text(source, "name") == Some("toxic-content")
                        && same_name(source, target)
                        && detector;
                    let child_topics = (key == "topic-list"
                        && text(source, "name") == Some("topic-guardrails")
                        && same_name(source, target)
                        && detector)
                        || (topics
                            && key == "topic"
                            && text(source, "action") == Some("block")
                            && text(target, "action") == Some("block"));
                    self.visit(
                        Some(child_source),
                        Some(child_target),
                        &field_path,
                        child_toxic,
                        child_topics,
                    );
                }
                (None, None) => {}
            }
        }
    }

    /// Whether `key`, present only in `target`, is one of the observed server defaults.
    #[allow(clippy::too_many_arguments)]
    fn server_default(
        &self,
        source: &Map<String, Value>,
        target: &Map<String, Value>,
        path: &str,
        key: &str,
        added: &Value,
        toxic: bool,
        topics: bool,
    ) -> bool {
        let relative = relative(path);
        let source_name = text(source, "name");
        let same_name = strict_eq(field(source, "name"), field(target, "name"));
        let mut allowed: Option<Value> = None;
        if relative == "model.data-protection" && key == "database-security" {
            allowed = Some(Value::Null);
        }
        if key == "severity" {
            if matches_pattern(&relative, "model.data-protection.database-security[#]")
                && same_name
                && let Some(name) = source_name
            {
                allowed = match name {
                    "database-security-create" | "database-security-update" => Some("medium"),
                    "database-security-read" => Some("low"),
                    "database-security-delete" => Some("high"),
                    _ => None,
                }
                .map(|value| Value::String(value.to_owned()));
            }
            if relative == "model.data-protection.source-code-detection" {
                allowed = Some(Value::String("high".to_owned()));
            }
            if relative == "model.app-protection.malicious-code-protection"
                && source_name == Some("malicious-code")
                && same_name
            {
                allowed = Some(Value::String("high".to_owned()));
            }
            if matches_pattern(&relative, "model.model-protection[#]")
                && (matches!(source_name, Some("prompt-injection" | "topic-guardrails"))
                    || (source_name == Some("contextual-grounding")
                        && text(source, "action") == Some("block")))
                && same_name
            {
                allowed = Some(Value::String("medium".to_owned()));
            }
            if topics
                && matches_pattern(
                    &relative,
                    "model.model-protection[#].topic-list[#].topic[#]",
                )
                && text(source, "topic_id").is_some_and(|id| !id.is_empty())
                && strict_eq(field(source, "topic_id"), field(target, "topic_id"))
                && strict_eq(field(source, "topic_name"), field(target, "topic_name"))
                && field(source, "revision").is_some_and(is_integer)
                && strict_eq(field(source, "revision"), field(target, "revision"))
            {
                allowed = Some(Value::String("medium".to_owned()));
            }
            if matches_pattern(&relative, "model.agent-protection[#]")
                && source_name == Some("agent-security")
                && same_name
            {
                allowed = Some(Value::String("medium".to_owned()));
            }
        }
        if relative == "model.app-protection" && key == "url-detected-severity" {
            allowed = Some(Value::String("low".to_owned()));
        }
        if relative == "model.app-protection"
            && key == "default-url-category"
            && let Value::Object(value) = added
            && value.len() == 1
            && value.get("member") == Some(&Value::Null)
        {
            return true;
        }
        let toxic_detector = matches_pattern(&relative, "model.model-protection[#]")
            && source_name == Some("toxic-content")
            && same_name;
        let toxic_category = toxic
            && matches_pattern(
                &relative,
                "model.model-protection[#].toxic-category-list[#]",
            )
            && text(source, "category").is_some_and(|category| !category.is_empty())
            && strict_eq(field(source, "category"), field(target, "category"));
        if (toxic_detector || toxic_category)
            && key == "severity-by-confidence"
            && let Value::Object(value) = added
            && value.len() == 2
            && text(value, "high") == Some("medium")
            && text(value, "moderate") == Some("low")
        {
            return true;
        }
        allowed.is_some_and(|allowed| strict_eq(Some(&allowed), Some(added)))
    }
}

/// `Number.isInteger(value)`.
fn is_integer(value: &Value) -> bool {
    value
        .as_f64()
        .is_some_and(|number| number.is_finite() && number.fract() == 0.0)
}

#[cfg(test)]
mod tests {
    //! The TypeScript `tests/unit/backup/runtime-policy.spec.ts`, case by case.
    use super::*;
    use serde_json::json;

    fn cmp(expected: &Value, actual: &Value) -> Comparison {
        compare(Some(expected), Some(actual))
    }

    fn fixture() -> (Value, Value) {
        let plain: Vec<Value> = ["create", "read", "update", "delete"]
            .iter()
            .map(|name| json!({"name": format!("database-security-{name}"), "action": "block"}))
            .collect();
        let source = json!({"ai-security-profiles": [{"model-configuration": {
            "data-protection": {
                "database-security": plain,
                "source-code-detection": {"action": "block"},
            },
            "app-protection": {
                "url-detected-action": "block",
                "malicious-code-protection": {"name": "malicious-code", "action": "block"},
            },
            "model-protection": [
                {"name": "prompt-injection", "action": "block"},
                {"name": "toxic-content", "action": "high:block, moderate:block"},
            ],
            "agent-protection": [{"name": "agent-security", "action": "block"}],
        }}]});
        let severities = ["medium", "low", "medium", "high"];
        let databases: Vec<Value> = ["create", "read", "update", "delete"]
            .iter()
            .zip(severities)
            .map(|(name, severity)| {
                json!({"name": format!("database-security-{name}"), "action": "block", "severity": severity})
            })
            .collect();
        let target = json!({"ai-security-profiles": [{"model-configuration": {
            "data-protection": {
                "database-security": databases,
                "source-code-detection": {"action": "block", "severity": "high"},
            },
            "app-protection": {
                "url-detected-action": "block",
                "malicious-code-protection": {"name": "malicious-code", "action": "block", "severity": "high"},
                "url-detected-severity": "low",
            },
            "model-protection": [
                {"name": "prompt-injection", "action": "block", "severity": "medium"},
                {"name": "toxic-content", "action": "high:block, moderate:block",
                    "severity-by-confidence": {"high": "medium", "moderate": "low"}},
            ],
            "agent-protection": [{"name": "agent-security", "action": "block", "severity": "medium"}],
        }}]});
        (source, target)
    }

    fn model(policy: &mut Value) -> &mut Value {
        &mut policy["ai-security-profiles"][0]["model-configuration"]
    }

    #[test]
    fn patterns_match_digits_and_literals() {
        assert!(matches_pattern(
            "model.model-protection[12]",
            "model.model-protection[#]"
        ));
        assert!(!matches_pattern(
            "model.model-protection[]",
            "model.model-protection[#]"
        ));
        assert!(!matches_pattern(
            "model.model-protection[1].x",
            "model.model-protection[#]"
        ));
        assert_eq!(
            relative("policy.ai-security-profiles[3].model-configuration.app-protection"),
            "model.app-protection"
        );
        assert_eq!(relative("policy.other"), "policy.other");
    }

    #[test]
    fn contextual_grounding_default_only_for_block() {
        let policy = |detector: Value| json!({"ai-security-profiles": [{"model-configuration": {"model-protection": [detector]}}]});
        let detector = json!({"name": "contextual-grounding", "action": "block"});
        let with = |extra: Value| {
            let mut value = detector.clone();
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            policy(value)
        };
        let source = policy(detector.clone());
        let target = with(json!({"severity": "medium"}));
        assert_eq!(cmp(&source, &target).server_defaults.len(), 1);
        assert!(cmp(&source, &target).matches);
        assert!(!cmp(&with(json!({"severity": "high"})), &target).matches);
        assert!(
            !cmp(
                &source,
                &with(json!({"action": "allow", "severity": "medium"}))
            )
            .matches
        );
        assert!(!cmp(&source, &with(json!({"severity": "high"}))).matches);
    }

    fn topic_policy(explicit: bool, action: &str, name: &str) -> Value {
        let mut detector = json!({"name": name, "topic-list": [{"action": action, "topic": [
            {"topic_id": "mapped-destination", "topic_name": "example", "revision": 1}
        ]}]});
        if explicit {
            detector["severity"] = json!("medium");
            detector["topic-list"][0]["topic"][0]["severity"] = json!("medium");
        }
        json!({"ai-security-profiles": [{"model-configuration": {"model-protection": [detector]}}]})
    }

    #[test]
    fn topic_guardrail_severities_only_for_matching_blocked_references() {
        let source = topic_policy(false, "block", "topic-guardrails");
        let target = topic_policy(true, "block", "topic-guardrails");
        let before = (source.clone(), target.clone());
        let result = cmp(&source, &target);
        assert!(result.matches);
        assert_eq!(result.server_defaults.len(), 2);
        assert_eq!((source.clone(), target.clone()), before);
        assert!(!cmp(&target, &source).matches);
        assert!(cmp(&target, &target.clone()).matches);
        assert!(
            !cmp(
                &topic_policy(false, "allow", "topic-guardrails"),
                &topic_policy(true, "allow", "topic-guardrails")
            )
            .matches
        );
        assert!(
            !cmp(
                &topic_policy(false, "block", "other"),
                &topic_policy(true, "block", "other")
            )
            .matches
        );
    }

    #[test]
    fn topic_drift_is_refused() {
        for key in [
            "topic_id",
            "topic_name",
            "revision",
            "severity",
            "action",
            "explicit",
        ] {
            let mut source = topic_policy(false, "block", "topic-guardrails");
            let mut target = topic_policy(true, "block", "topic-guardrails");
            let detector = &mut model(&mut target)["model-protection"][0];
            match key {
                "action" => detector["topic-list"][0]["action"] = json!("allow"),
                "explicit" => {
                    model(&mut source)["model-protection"][0]["topic-list"][0]["topic"][0]["severity"] =
                        json!("high");
                }
                "revision" => detector["topic-list"][0]["topic"][0]["revision"] = json!(2),
                other => detector["topic-list"][0]["topic"][0][other] = json!("changed"),
            }
            assert!(!cmp(&source, &target).matches, "{key}");
        }
    }

    fn categories(explicit: bool) -> Value {
        let model = || {
            let list: Vec<Value> = ["hate", "self-harm"]
                .iter()
                .map(|category| {
                    let mut value =
                        json!({"category": category, "action": "high:allow, moderate:allow"});
                    if explicit {
                        value["severity-by-confidence"] =
                            json!({"high": "medium", "moderate": "low"});
                    }
                    value
                })
                .collect();
            json!({"model-configuration": {"model-protection": [
                {"name": "prompt-injection", "action": "block"},
                {"name": "toxic-content", "action": "", "toxic-category-list": list},
            ]}})
        };
        json!({"ai-security-profiles": [model(), model()]})
    }

    #[test]
    fn category_confidence_defaults_across_models() {
        let source = categories(false);
        let target = categories(true);
        let result = cmp(&source, &target);
        assert!(result.matches);
        assert_eq!(result.server_defaults.len(), 4);
        assert!(result.server_defaults[3].contains(
            "ai-security-profiles[1].model-configuration.model-protection[1].toxic-category-list[1].severity-by-confidence"
        ));
        assert!(!cmp(&target, &source).matches);
    }

    #[test]
    fn category_drift_is_refused() {
        for mutation in [
            "category",
            "action",
            "name",
            "explicit",
            "extra",
            "unexpected-default",
            "misplaced",
        ] {
            let mut source = categories(false);
            let mut target = categories(true);
            let detector = &mut model(&mut target)["model-protection"][1];
            match mutation {
                "category" => detector["toxic-category-list"][0]["category"] = json!("other"),
                "action" => {
                    detector["toxic-category-list"][0]["action"] =
                        json!("high:block, moderate:block");
                }
                "name" => detector["name"] = json!("other-detector"),
                "explicit" => {
                    model(&mut source)["model-protection"][1]["toxic-category-list"][0]["severity-by-confidence"] =
                        json!({"high": "high", "moderate": "low"});
                }
                "extra" => {
                    detector["toxic-category-list"][0]["severity-by-confidence"]["extra"] =
                        json!("low");
                }
                "unexpected-default" => {
                    detector["toxic-category-list"][0]["severity-by-confidence"]["high"] =
                        json!("high");
                }
                _ => {
                    detector["name"] = json!("other-detector");
                    model(&mut source)["model-protection"][1]["name"] = json!("other-detector");
                }
            }
            assert!(!cmp(&source, &target).matches, "{mutation}");
        }
    }

    #[test]
    fn explicit_categories_must_match_in_number() {
        let source = categories(true);
        let mut target = categories(true);
        assert!(cmp(&source, &target).matches);
        model(&mut target)["model-protection"][1]["toxic-category-list"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(!cmp(&source, &target).matches);
        assert!(!cmp(&target, &source).matches);
    }

    #[test]
    fn only_the_empty_default_url_category() {
        let source =
            json!({"ai-security-profiles": [{"model-configuration": {"app-protection": {}}}]});
        let policy = |category: Value| json!({"ai-security-profiles": [{"model-configuration": {"app-protection": {"default-url-category": category}}}]});
        assert!(cmp(&source, &policy(json!({"member": null}))).matches);
        for value in [
            json!({"member": ["malicious"]}),
            json!({"member": null, "unknown": true}),
            Value::Null,
            json!([]),
        ] {
            assert!(!cmp(&source, &policy(value.clone())).matches, "{value}");
        }
        assert!(
            !cmp(
                &policy(json!({"member": ["malicious"]})),
                &policy(json!({"member": null}))
            )
            .matches
        );
    }

    #[test]
    fn the_ten_observed_fields_without_mutation() {
        let (source, target) = fixture();
        let before = (source.clone(), target.clone());
        let result = cmp(&source, &target);
        assert!(result.matches, "{:?}", result.differences);
        assert_eq!(result.server_defaults.len(), 10);
        assert_eq!((source.clone(), target.clone()), before);
        assert!(!cmp(&target, &source).matches);
    }

    #[test]
    fn explicit_severities_must_be_equal() {
        let (_, target) = fixture();
        assert!(cmp(&target, &target.clone()).matches);
        for explicit in [json!("high"), Value::Null, json!("")] {
            let mut source = target.clone();
            model(&mut source)["model-protection"][0]["severity"] = explicit.clone();
            assert!(!cmp(&source, &target).matches, "{explicit}");
        }
        let mut source = target.clone();
        model(&mut source)["model-protection"][1]["severity-by-confidence"]["high"] = json!("high");
        assert!(!cmp(&source, &target).matches);
    }

    #[test]
    fn unrecognized_changes_are_refused() {
        for key in ["severity", "action", "name", "unknown"] {
            let (source, mut target) = fixture();
            model(&mut target)["model-protection"][0][key] = json!("unexpected");
            assert!(!cmp(&source, &target).matches, "{key}");
        }
    }

    #[test]
    fn extra_settings_detectors_and_shapes_are_refused() {
        let (source, mut target) = fixture();
        model(&mut target)["model-protection"][1]["severity-by-confidence"]["extra"] = json!("low");
        assert!(!cmp(&source, &target).matches);
        assert!(!compare(Some(&source), None).matches);
        assert!(!cmp(&json!({}), &json!({"severity": "medium"})).matches);
        assert!(!cmp(&json!({"ai-security-profiles": []}), &source).matches);
        assert!(!cmp(&json!({"future": []}), &json!({"future": {}})).matches);
    }

    #[test]
    fn only_an_added_null_database_security() {
        let source =
            json!({"ai-security-profiles": [{"model-configuration": {"data-protection": {}}}]});
        let target = json!({"ai-security-profiles": [{"model-configuration": {"data-protection": {"database-security": null}}}]});
        assert!(cmp(&source, &target).matches);
        assert!(!cmp(&target, &source).matches);
        assert!(!cmp(&source, &fixture().1).matches);
    }

    #[test]
    fn numbers_compare_by_value() {
        assert!(strict_eq(Some(&json!(1)), Some(&json!(1.0))));
        assert!(!strict_eq(Some(&json!(1)), Some(&json!("1"))));
        assert!(strict_eq(None, None));
        assert!(!strict_eq(Some(&Value::Null), None));
    }
}
