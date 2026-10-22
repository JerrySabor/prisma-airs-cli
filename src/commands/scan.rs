//! `runtime scan --profile <name> [--response <text>] <prompt>` (DESIGN §8).

use super::Invocation;
use crate::cli::ScanArgs;
use crate::clients::{self, SINGLE_REQUEST_BUDGET};
use crate::error::{self, CliError, Operation, Phase, Plane, SdkContext, SecretSet, WITHHELD};
use crate::json::{self, OValue};
use crate::output::{Format, terminal_safe};
use crate::tenant::config;
use scm::airs::scan::Content;
use scm::airs::scan::models::{AiProfile, ScanResponse};
use scm::data::Optional;
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};

const MAX_TEXT_BYTES: usize = 2_097_152;
const MAX_PROFILE_NAME: usize = 100;
const PREVIEW_UNITS: usize = 80;
/// Longest server-provided `errors[]` part shown in a failure reason, in characters.
const MAX_REASON_PART: usize = 200;

/// Prompt detection keys, in report order.
pub const PROMPT_KEYS: [&str; 8] = [
    "topic_violation",
    "injection",
    "toxic_content",
    "dlp",
    "url_cats",
    "malicious_code",
    "source_code",
    "agent",
];

/// Response detection keys, in report order.
pub const RESPONSE_KEYS: [&str; 8] = [
    "topic_violation",
    "toxic_content",
    "dlp",
    "url_cats",
    "malicious_code",
    "agent",
    "db_security",
    "ungrounded",
];

/// Validated scan input. An empty `--response` is dropped (TS parity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanInput {
    pub profile: String,
    pub prompt: String,
    pub response: Option<String>,
}

fn payload_error(message: &str) -> CliError {
    CliError::usage(format!("AISEC_USER_REQUEST_PAYLOAD_ERROR:{message}"))
}

/// The §8.1 profile-name rules (usage errors).
pub fn check_profile(profile: &str) -> Result<(), CliError> {
    if profile.is_empty() {
        return Err(payload_error(
            "Request body for POST /v1/scan/sync/request did not match schema: ai_profile: custom",
        ));
    }
    if profile.encode_utf16().count() > MAX_PROFILE_NAME {
        return Err(payload_error(
            "Request body for POST /v1/scan/sync/request did not match schema: ai_profile.profile_name: too_big",
        ));
    }
    Ok(())
}

/// The §8.1 content rules for a prompt scanned alone: the message of the first
/// failure.
pub fn prompt_problem(prompt: &str) -> Option<String> {
    if prompt.is_empty() {
        Some("AISEC_USER_REQUEST_PAYLOAD_ERROR:At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided".to_owned())
    } else if prompt.len() > MAX_TEXT_BYTES {
        Some(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:prompt exceeds max length of 2097152 bytes"
                .to_owned(),
        )
    } else {
        None
    }
}

/// Local request validation (usage errors, before the tenant is read).
pub fn validate_input(args: &ScanArgs) -> Result<ScanInput, CliError> {
    let response = args.response.clone().filter(|text| !text.is_empty());
    if args.prompt.is_empty() && response.is_none() {
        return Err(payload_error(
            "At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided",
        ));
    }
    if args.prompt.len() > MAX_TEXT_BYTES {
        return Err(payload_error("prompt exceeds max length of 2097152 bytes"));
    }
    if response
        .as_ref()
        .is_some_and(|text| text.len() > MAX_TEXT_BYTES)
    {
        return Err(payload_error(
            "response exceeds max length of 2097152 bytes",
        ));
    }
    check_profile(&args.profile)?;
    Ok(ScanInput {
        profile: args.profile.clone(),
        prompt: args.prompt.clone(),
        response,
    })
}

/// The first 80 UTF-16 code units (never splitting a character), `...` when longer.
pub fn preview(prompt: &str) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in prompt.chars() {
        units += c.len_utf16();
        if units > PREVIEW_UNITS {
            break;
        }
        out.push(c);
    }
    if prompt.encode_utf16().count() > PREVIEW_UNITS {
        out.push_str("...");
    }
    out
}

/// The CLI verdict. Anything but a clean allow/block fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
    Failed,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Failed => "failed",
        }
    }
}

/// Detection flags in fixed key order (serialised as an ordered object).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flags(pub Vec<(&'static str, bool)>);

impl Flags {
    pub fn triggered(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.iter().filter(|(_, on)| *on).map(|(key, _)| *key)
    }
}

impl Serialize for Flags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// The normalised scan result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Normalized {
    pub verdict: Verdict,
    pub category: String,
    pub triggered: bool,
    pub prompt: Flags,
    pub response: Flags,
    pub error: Option<String>,
}

fn flag(value: &Optional<bool>) -> Option<bool> {
    value.as_ref().into_option().copied()
}

fn prompt_flags(response: &ScanResponse) -> Flags {
    let Optional::Value(detected) = &response.prompt_detected else {
        return Flags::default();
    };
    // The explicit length ties this list to PROMPT_KEYS: adding a key to one and not
    // the other does not compile (the order is pinned by the all-detections tests).
    let values: [&Optional<bool>; PROMPT_KEYS.len()] = [
        &detected.topic_violation,
        &detected.injection,
        &detected.toxic_content,
        &detected.dlp,
        &detected.url_cats,
        &detected.malicious_code,
        &detected.source_code,
        &detected.agent,
    ];
    Flags(
        PROMPT_KEYS
            .into_iter()
            .zip(values)
            .filter_map(|(key, value)| flag(value).map(|on| (key, on)))
            .collect(),
    )
}

fn response_flags(response: &ScanResponse) -> Flags {
    let Optional::Value(detected) = &response.response_detected else {
        return Flags::default();
    };
    let values: [&Optional<bool>; RESPONSE_KEYS.len()] = [
        &detected.topic_violation,
        &detected.toxic_content,
        &detected.dlp,
        &detected.url_cats,
        &detected.malicious_code,
        &detected.agent,
        &detected.db_security,
        &detected.ungrounded,
    ];
    Flags(
        RESPONSE_KEYS
            .into_iter()
            .zip(values)
            .filter_map(|(key, value)| flag(value).map(|on| (key, on)))
            .collect(),
    )
}

/// One server-provided reason part: withheld when it carries a secret, bounded.
pub fn reason_part(text: &str, secrets: &SecretSet) -> String {
    let text = secrets.scrub(text);
    match text.char_indices().nth(MAX_REASON_PART) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_owned(),
    }
}

fn error_reason(response: &ScanResponse, secrets: &SecretSet) -> String {
    let entries: Vec<String> = response
        .errors
        .iter()
        .map(|entry| {
            [&entry.feature, &entry.status, &entry.content_type]
                .into_iter()
                .filter_map(|part| part.as_ref().into_option())
                .filter(|part| !part.is_empty())
                .map(|part| reason_part(part, secrets))
                .collect::<Vec<_>>()
                .join(": ")
        })
        .filter(|entry| !entry.is_empty())
        .collect();
    if !entries.is_empty() {
        entries.join("; ")
    } else if response.timeout {
        "AIRS scan timed out".to_owned()
    } else if response.error {
        "AIRS scan failed".to_owned()
    } else {
        format!(
            "Unknown AIRS action: {}",
            reason_part(&response.action, secrets)
        )
    }
}

/// Normalise a response: lower-cased allow/block pass through; error, timeout or any
/// other action fails closed with a reason. Server text that carries a configured
/// secret is withheld (DESIGN §8.3).
pub fn normalize(response: &ScanResponse, secrets: &SecretSet) -> Normalized {
    let action = response.action.to_lowercase();
    let failed = response.error || response.timeout || (action != "allow" && action != "block");
    let prompt = prompt_flags(response);
    let response_detections = response_flags(response);
    let triggered =
        prompt.triggered().next().is_some() || response_detections.triggered().next().is_some();
    Normalized {
        verdict: if failed {
            Verdict::Failed
        } else if action == "block" {
            Verdict::Block
        } else {
            Verdict::Allow
        },
        category: if failed {
            "error".to_owned()
        } else {
            secrets.scrub(&response.category).to_owned()
        },
        triggered,
        prompt,
        response: response_detections,
        error: failed.then(|| error_reason(response, secrets)),
    }
}

/// The serialised response with every string that carries a configured secret
/// replaced by [`WITHHELD`], and every object entry whose key carries one dropped
/// (DESIGN §8.5).
fn scrubbed_result(response: &ScanResponse, secrets: &SecretSet) -> Result<OValue, CliError> {
    fn scrub(value: &mut OValue, secrets: &SecretSet) {
        match value {
            OValue::String(text) if secrets.taints(text) => *text = WITHHELD.to_owned(),
            OValue::Array(items) => items.iter_mut().for_each(|item| scrub(item, secrets)),
            OValue::Object(entries) => {
                entries.retain(|(key, _)| !secrets.taints(key));
                entries
                    .iter_mut()
                    .for_each(|(_, item)| scrub(item, secrets));
            }
            _ => {}
        }
    }
    let mut value = json::to_ordered(response).map_err(|_| {
        CliError::operational("AISEC_SDK_ERROR:Output could not be serialized as JSON")
    })?;
    scrub(&mut value, secrets);
    Ok(value)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanJson<'a> {
    profile_name: &'a str,
    scan_id: &'a str,
    report_id: &'a str,
    action: &'static str,
    category: &'a str,
    triggered: bool,
    detections: &'a Flags,
    response_detections: &'a Flags,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    result: &'a OValue,
}

/// The pretty result lines (stdout). Server-provided values are withheld when they
/// carry a configured secret and have control characters replaced (DESIGN §2.2, §8.4);
/// colours per §2.8.
pub fn render_pretty(
    output: &mut crate::output::Output,
    response: &ScanResponse,
    result: &Normalized,
    secrets: &SecretSet,
) {
    use crate::render::pretty;
    use crate::render::style::Style;
    pretty::banner(output, "Scan Result", None);
    let safe = |value: &str| terminal_safe(value).into_owned();
    let action = output.paint(
        match result.verdict {
            Verdict::Allow => Style::Green,
            Verdict::Block | Verdict::Failed => Style::Red,
        },
        &result.verdict.name().to_uppercase(),
    );
    let triggered = if result.triggered {
        output.paint(Style::Red, "yes")
    } else {
        output.paint(Style::Green, "no")
    };
    let mut pairs = vec![
        ("Action", action),
        ("Category", safe(&result.category)),
        ("Triggered", triggered),
        (
            "Scan ID",
            output.paint(Style::Dim, &safe(secrets.scrub(&response.scan_id))),
        ),
        (
            "Report ID",
            output.paint(Style::Dim, &safe(secrets.scrub(&response.report_id))),
        ),
    ];
    if let Some(reason) = &result.error {
        pairs.push(("Error", safe(reason)));
    }
    pretty::key_value(output, &pairs);
    if result.triggered {
        pretty::section(output, "Detections");
        for key in result.prompt.triggered() {
            pretty::bullet(output, key, pretty::Bullet::Flag);
        }
        for key in result.response.triggered() {
            pretty::bullet(output, &format!("response.{key}"), pretty::Bullet::Flag);
        }
    }
}

/// The table result (D5, §8.6): `Key │ Value` rows of the JSON record without
/// `result`, `error` last for a failed scan.
fn render_table(output: &mut crate::output::Output, record: &ScanJson<'_>) -> Result<(), CliError> {
    let value = json::to_ordered(record).map_err(|_| {
        CliError::operational("AISEC_SDK_ERROR:Output could not be serialized as JSON")
    })?;
    let rows = value
        .as_object()
        .unwrap_or_default()
        .iter()
        .filter(|(key, _)| key != "result")
        .map(|(key, item)| (key.clone(), crate::render::cell_text(Some(item))))
        .collect();
    output.data_line(&crate::render::table::key_value_table(rows));
    Ok(())
}

pub async fn run(
    invocation: &mut Invocation,
    input: &ScanInput,
    format: Format,
) -> Result<(), CliError> {
    let tenant = invocation.load_tenant()?;
    config::require_scanner(&tenant.config, Some(tenant.name()))?;
    let scanner = clients::build_scanner(
        &tenant.config,
        &invocation.session,
        invocation.debug.as_ref(),
    )?;

    invocation.output.status("Prisma AIRS Runtime Scan");
    invocation
        .output
        .status(&format!("Profile: {}", input.profile));
    invocation
        .output
        .status(&format!("Prompt:  \"{}\"", preview(&input.prompt)));

    let local = |_| CliError::usage("AISEC_USER_REQUEST_PAYLOAD_ERROR:Validation error");
    let mut content = Content::builder().prompt(input.prompt.clone());
    if let Some(response) = &input.response {
        content = content.response(response.clone());
    }
    let content = content.build().map_err(local)?;
    let profile = AiProfile::builder()
        .profile_name(Optional::Value(input.profile.clone()))
        .build()
        .map_err(local)?;

    let response = scanner
        .sync_scan(&profile, &content, None)
        .await
        .map_err(|failure| {
            error::from_sdk(
                &failure,
                &SdkContext {
                    plane: Plane::Scanner,
                    phase: Phase::Api,
                    operation: Operation::ScanSubmit,
                    timeout: SINGLE_REQUEST_BUDGET,
                    secrets: &invocation.secrets,
                },
            )
        })?;

    let secrets = &invocation.secrets;
    let result = normalize(&response, secrets);
    let scrubbed = match format {
        Format::Json => scrubbed_result(&response, secrets)?,
        Format::Table | Format::Pretty => OValue::Null,
    };
    let record = ScanJson {
        profile_name: &input.profile,
        scan_id: secrets.scrub(&response.scan_id),
        report_id: secrets.scrub(&response.report_id),
        action: result.verdict.name(),
        category: &result.category,
        triggered: result.triggered,
        detections: &result.prompt,
        response_detections: &result.response,
        error: result.error.as_deref(),
        result: &scrubbed,
    };
    match format {
        Format::Json => invocation.output.json(&record)?,
        Format::Table => render_table(&mut invocation.output, &record)?,
        Format::Pretty => render_pretty(&mut invocation.output, &response, &result, secrets),
    }
    match result.error {
        Some(reason) => {
            // The failed result is data: write it, then report the failure.
            let _ = invocation.output.commit();
            Err(CliError::operational(format!(
                "AIRS scan did not complete: {reason}"
            )))
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing::capture;
    use serde_json::json;

    fn response(value: serde_json::Value) -> ScanResponse {
        serde_json::from_value(value).unwrap()
    }

    fn base(extra: serde_json::Value) -> ScanResponse {
        let mut value = json!({
            "report_id": "R1", "scan_id": "S1", "category": "benign", "action": "allow",
            "timeout": false, "error": false, "errors": []
        });
        for (key, item) in extra.as_object().unwrap() {
            value[key] = item.clone();
        }
        response(value)
    }

    fn args(profile: &str, prompt: &str, response: Option<&str>) -> ScanArgs {
        ScanArgs {
            profile: profile.into(),
            prompt: prompt.into(),
            response: response.map(str::to_owned),
        }
    }

    #[test]
    fn input_validation_order_and_messages() {
        let err = |a: ScanArgs| match validate_input(&a) {
            Err(CliError::Usage(message)) => message,
            other => panic!("{other:?}"),
        };
        assert!(err(args("p", "", None)).ends_with("toolEvent must be provided"));
        assert!(err(args("p", "", Some(""))).ends_with("toolEvent must be provided"));
        assert!(err(args("", "", None)).ends_with("toolEvent must be provided"));
        assert_eq!(
            err(args("", "hi", None)),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile: custom"
        );
        assert!(
            err(args(&"p".repeat(101), "hi", None)).ends_with("ai_profile.profile_name: too_big")
        );
        assert!(validate_input(&args(&"p".repeat(100), "hi", None)).is_ok());
        assert!(
            err(args("p", &"x".repeat(MAX_TEXT_BYTES + 1), None))
                .ends_with("prompt exceeds max length of 2097152 bytes")
        );
        assert!(validate_input(&args("p", &"x".repeat(MAX_TEXT_BYTES), None)).is_ok());
        assert!(
            err(args("p", "", Some(&"x".repeat(MAX_TEXT_BYTES + 1))))
                .ends_with("response exceeds max length of 2097152 bytes")
        );
        let ok = validate_input(&args("p", "", Some("R"))).unwrap();
        assert_eq!(ok.response.as_deref(), Some("R"));
        assert_eq!(
            validate_input(&args("p", "x", Some(""))).unwrap().response,
            None
        );
    }

    #[test]
    fn prompt_preview() {
        assert_eq!(preview("hello"), "hello");
        assert_eq!(preview(&"a".repeat(80)), "a".repeat(80));
        assert_eq!(preview(&"a".repeat(81)), format!("{}...", "a".repeat(80)));
        let emoji = format!("{}😀", "a".repeat(79));
        assert_eq!(preview(&emoji), format!("{}...", "a".repeat(79)));
    }

    #[test]
    fn allow_and_block() {
        let none = SecretSet::default();
        let allow = normalize(&base(json!({})), &none);
        assert_eq!(allow.verdict, Verdict::Allow);
        assert_eq!(allow.category, "benign");
        assert!(!allow.triggered);
        assert_eq!(allow.error, None);

        let block = normalize(
            &base(json!({
                "action": "BLOCK", "category": "malicious",
                "prompt_detected": {"toxic_content": true, "injection": true, "dlp": false},
                "response_detected": {"ungrounded": true, "dlp": false}
            })),
            &none,
        );
        assert_eq!(block.verdict, Verdict::Block);
        assert_eq!(
            block.prompt.0,
            [("injection", true), ("toxic_content", true), ("dlp", false)]
        );
        assert_eq!(block.response.0, [("dlp", false), ("ungrounded", true)]);
        assert!(block.triggered);
    }

    #[test]
    fn response_detections_alone_trigger() {
        let result = normalize(
            &base(json!({"response_detected": {"db_security": true}})),
            &SecretSet::default(),
        );
        assert!(result.triggered);
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn failures_close() {
        let none = SecretSet::default();
        let failed = normalize(
            &base(json!({
                "error": true,
                "errors": [{"content_type": "prompt", "feature": "dlp", "status": "error"}, {"feature": "tc"}, {}]
            })),
            &none,
        );
        assert_eq!(failed.verdict, Verdict::Failed);
        assert_eq!(failed.category, "error");
        assert_eq!(failed.error.as_deref(), Some("dlp: error: prompt; tc"));
        let timeout = normalize(&base(json!({"timeout": true, "action": "block"})), &none);
        assert_eq!(timeout.verdict, Verdict::Failed);
        assert_eq!(timeout.error.as_deref(), Some("AIRS scan timed out"));
        let error = normalize(&base(json!({"error": true})), &none);
        assert_eq!(error.error.as_deref(), Some("AIRS scan failed"));
        let unknown = normalize(&base(json!({"action": "Alert"})), &none);
        assert_eq!(unknown.verdict, Verdict::Failed);
        assert_eq!(unknown.error.as_deref(), Some("Unknown AIRS action: Alert"));
    }

    #[test]
    fn server_text_with_a_secret_is_withheld_and_bounded() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-APIKEY-123");
        let long = "x".repeat(MAX_REASON_PART + 5);
        let failed = normalize(
            &base(json!({
                "error": true,
                "category": "FAKE-APIKEY-123",
                "errors": [{"feature": "dlp", "status": "echo FAKE-APIKEY-123", "content_type": long}]
            })),
            &secrets,
        );
        assert_eq!(
            failed.error.as_deref(),
            Some(format!("dlp: [withheld]: {}...", "x".repeat(MAX_REASON_PART)).as_str())
        );
        let allow = normalize(&base(json!({"category": "a FAKE-APIKEY-123"})), &secrets);
        assert_eq!(allow.category, WITHHELD);
        let scan = base(json!({
            "report_id": "R-FAKE-APIKEY-123",
            "zz": {"FAKE-APIKEY-123": 1, "keep": ["RkFLRS1BUElLRVktMTIz", "fine"]}
        }));
        let value = scrubbed_result(&scan, &secrets).unwrap();
        let text = serde_json::to_string(&value).unwrap();
        assert!(!text.contains("FAKE-APIKEY-123") && !text.contains("RkFLRS1BUElLRVktMTIz"));
        assert!(text.contains(r#""keep":["[withheld]","fine"]"#), "{text}");
        assert!(text.contains(r#""report_id":"[withheld]""#), "{text}");
    }

    #[test]
    fn pretty_rendering() {
        let scan = base(json!({
            "action": "block", "category": "malicious",
            "prompt_detected": {"toxic_content": true, "injection": true},
            "response_detected": {"dlp": true}
        }));
        let none = SecretSet::default();
        let (mut output, stdout, _) = capture(false);
        render_pretty(&mut output, &scan, &normalize(&scan, &none), &none);
        output.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Scan Result\n\n  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n  Scan ID    S1\n  Report ID  R1\n\n  Detections\n\n  ● injection\n  ● toxic_content\n  ● response.dlp\n"
        );

        let failed = base(json!({"error": true}));
        let (mut output, stdout, _) = capture(true);
        render_pretty(&mut output, &failed, &normalize(&failed, &none), &none);
        output.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "  Action     FAILED\n  Category   error\n  Triggered  no\n  Scan ID    S1\n  Report ID  R1\n  Error      AIRS scan failed\n"
        );

        let hostile = base(json!({"report_id": "R\u{1b}]0;pwned\u{7}", "category": "b\u{1b}[31m"}));
        let (mut output, stdout, _) = capture(true);
        render_pretty(&mut output, &hostile, &normalize(&hostile, &none), &none);
        output.commit().unwrap();
        assert!(
            stdout
                .text()
                .contains("  Report ID  R\u{fffd}]0;pwned\u{fffd}\n")
        );
        assert!(stdout.text().contains("  Category   b\u{fffd}[31m\n"));
    }

    #[test]
    fn json_shape_keeps_order_and_unknown_fields() {
        let scan =
            base(json!({"zz_future": {"b": 1, "a": 2.0}, "prompt_detected": {"dlp": false}}));
        let none = SecretSet::default();
        let result = normalize(&scan, &none);
        let scrubbed = scrubbed_result(&scan, &none).unwrap();
        let text = crate::json::to_pretty(&ScanJson {
            profile_name: "p",
            scan_id: &scan.scan_id,
            report_id: &scan.report_id,
            action: result.verdict.name(),
            category: &result.category,
            triggered: result.triggered,
            detections: &result.prompt,
            response_detections: &result.response,
            error: result.error.as_deref(),
            result: &scrubbed,
        })
        .unwrap();
        let keys: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("  \""))
            .map(|line| line.trim().split('"').nth(1).unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "profileName",
                "scanId",
                "reportId",
                "action",
                "category",
                "triggered",
                "detections",
                "responseDetections",
                "result"
            ]
        );
        assert!(text.contains("\"zz_future\": {\n      \"a\": 2,\n      \"b\": 1\n    }"));
        assert!(text.contains("\"detections\": {\n    \"dlp\": false\n  }"));
        assert!(text.contains("\"responseDetections\": {}"));
    }
}
