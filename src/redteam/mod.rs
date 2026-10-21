//! Shared red team rules (DESIGN §15.3): the argument checks with the TypeScript texts,
//! the number and filter rules, and the list flags. Every check here is pure and runs
//! during planning, before the tenant is read (D141).

pub mod args;
pub mod backup;
#[cfg(test)]
mod contract_tests;
pub mod secrets;
pub mod views;

pub use crate::walk::ListParams;

use crate::error::CliError;
use crate::pagination::{self, MAX_SAFE_INTEGER};

/// The SDK filter bound (bytes).
const FILTER_LIMIT: usize = 4096;
/// The SDK bound on repeated `status` values of `channels list`.
pub const MAX_STATUS_VALUES: usize = 252;
/// The largest data-plane page the vendor 0.93.0 contract accepts (`list`, `targets
/// error-logs`, `report <jobId> --attacks`; D301, DESIGN §15.23).
pub const MAX_PAGE: u32 = 100;
/// The largest DYNAMIC `stream_depth` and `stream_breadth` of the scan body (D304).
pub const MAX_STREAM: u32 = 20;
/// The `--limit` of `report <jobId>` when none is given (TS).
pub const DEFAULT_ATTACK_LIMIT: u32 = 20;
/// The `list_jobs` `status` vocabulary of the vendor contract (D302).
pub const JOB_STATUSES: [&str; 6] = [
    "QUEUED",
    "RUNNING",
    "COMPLETED",
    "PARTIALLY_COMPLETE",
    "FAILED",
    "ABORTED",
];
/// The `list_jobs` `job_type` vocabulary of the vendor contract (D302).
pub const LIST_JOB_TYPES: [&str; 4] = ["STATIC", "DYNAMIC", "CUSTOM", "CLARA"];
/// The `list_attacks` `severity` vocabulary of the vendor contract (D303).
pub const SEVERITIES: [&str; 4] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/// `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid <field>: <value>` (the TypeScript SDK's
/// `assertUuid` text) unless `value` has the UUID shape.
pub fn check_uuid(field: &str, value: &str) -> Result<(), CliError> {
    if pagination::is_uuid(value) {
        Ok(())
    } else {
        Err(CliError::usage(format!(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid {field}: {value}"
        )))
    }
}

/// A filter value (`--status`, `--type`, `--target`, `--search`, …): at most 4,096 bytes
/// and no control character (the SDK `filter` rule), else
/// `<flag> must be at most 4096 bytes and contain no control characters`.
pub fn check_filter(flag: &str, value: &str) -> Result<(), CliError> {
    if value.len() <= FILTER_LIMIT && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(CliError::usage(format!(
            "{flag} must be at most {FILTER_LIMIT} bytes and contain no control characters"
        )))
    }
}

/// `--serial-numbers` names at least one serial number (D158): an empty value, or one
/// made only of commas and whitespace, is refused rather than sent as an empty list. A
/// list that names one is sent as given (TS).
pub fn check_serial_numbers(value: &str) -> Result<(), CliError> {
    if value.split(',').any(|serial| !serial.trim().is_empty()) {
        Ok(())
    } else {
        Err(CliError::usage(
            "--serial-numbers needs at least one serial number",
        ))
    }
}

/// An optional filter value, checked.
pub fn filter(flag: &str, value: Option<&str>) -> Result<Option<String>, CliError> {
    match value {
        Some(value) => {
            check_filter(flag, value)?;
            Ok(Some(value.to_owned()))
        }
        None => Ok(None),
    }
}

/// A query filter value, checked: an empty value sends no parameter (TypeScript skips a
/// falsy filter, so `--target ""` lists every scan rather than none).
pub fn query_filter(flag: &str, value: Option<&str>) -> Result<Option<String>, CliError> {
    Ok(filter(flag, value)?.filter(|value| !value.is_empty()))
}

/// `value` itself unless it is above the API `bound`, else
/// `<flag> must be at most <bound> (the red team API maximum)` (D301, D304). The message
/// never echoes the value.
pub fn at_most(flag: &str, value: u32, bound: u32) -> Result<u32, CliError> {
    if value <= bound {
        Ok(value)
    } else {
        Err(CliError::usage(format!(
            "{flag} must be at most {bound} (the red team API maximum)"
        )))
    }
}

/// `value` is exactly one of `vocabulary` (case-sensitive), else
/// `<flag> must be one of <A, B, …>` (D302, D303). The message never echoes the value.
pub fn check_one_of(flag: &str, value: &str, vocabulary: &[&str]) -> Result<(), CliError> {
    if vocabulary.contains(&value) {
        Ok(())
    } else {
        Err(CliError::usage(format!(
            "{flag} must be one of {}",
            vocabulary.join(", ")
        )))
    }
}

/// A `redteam list` query filter with an API vocabulary (D302): the filter rule, then a
/// non-empty value outside `vocabulary` refused; an empty value still sends nothing.
pub fn vocabulary_filter(
    flag: &str,
    value: Option<&str>,
    vocabulary: &[&str],
) -> Result<Option<String>, CliError> {
    let value = query_filter(flag, value)?;
    if let Some(value) = &value {
        check_one_of(flag, value, vocabulary)?;
    }
    Ok(value)
}

/// `redteam list --target` (D302): the filter rule, then a non-empty value must be a
/// UUID (`--target must be a target UUID`); an empty value still sends nothing.
pub fn target_filter(value: Option<&str>) -> Result<Option<String>, CliError> {
    let value = query_filter("--target", value)?;
    match &value {
        Some(value) if !pagination::is_uuid(value) => {
            Err(CliError::usage("--target must be a target UUID"))
        }
        _ => Ok(value),
    }
}

/// An option the red team API refuses for `command` (D300): refused whenever it is given,
/// whatever its value, with `<flag> is not supported for <command> (the red team API
/// accepts only <accepted>)`.
pub fn refuse_option(
    flag: &str,
    given: bool,
    command: &str,
    accepted: &str,
) -> Result<(), CliError> {
    if given {
        Err(CliError::usage(format!(
            "{flag} is not supported for {command} (the red team API accepts only {accepted})"
        )))
    } else {
        Ok(())
    }
}

/// Decimal digits only, as a `u64`.
fn decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok()
}

/// How a command words a bad `--limit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitText {
    /// `--limit must be a positive integer` (the §7.1 text).
    Contract,
    /// `<flag>: expected a positive integer, got "<value>"` (TypeScript
    /// `parsePositiveInt`).
    Typescript,
}

/// A positive integer from 1 to 4,294,967,295.
pub fn positive(flag: &str, value: &str, text: LimitText) -> Result<u32, CliError> {
    decimal(value)
        .filter(|n| *n >= 1)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| match text {
            LimitText::Contract => CliError::usage(format!("{flag} must be a positive integer")),
            LimitText::Typescript => CliError::usage(format!(
                "{flag}: expected a positive integer, got \"{value}\""
            )),
        })
}

/// [`positive`], then at most the API `bound` (D301): the order every bounded flag uses.
pub fn bounded_positive(
    flag: &str,
    value: &str,
    text: LimitText,
    bound: u32,
) -> Result<u32, CliError> {
    positive(flag, value, text).and_then(|n| at_most(flag, n, bound))
}

/// `report <jobId>`'s `--limit` and `--severity`, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttackListArgs {
    pub limit: u32,
    pub severity: Option<String>,
}

/// `report <jobId> [--attacks] [--limit] [--severity]` (D301, D303, DESIGN §15.23 choices 3,
/// 17 and 20), `--limit` first: `--limit` is positive (default 20) and `--severity` keeps the
/// filter rule. With `attacks` a value may be sent, and which one depends on the job type,
/// known only after a read, so both must also meet the vendor contract for every job type:
/// `--limit` at most [`MAX_PAGE`] and `--severity` one of [`SEVERITIES`] (`""` included).
/// Without `attacks` both stay unused, as in TypeScript.
pub fn attack_list_args(
    limit: Option<&str>,
    severity: Option<&str>,
    attacks: bool,
) -> Result<AttackListArgs, CliError> {
    let limit = match limit {
        Some(value) if attacks => {
            bounded_positive("--limit", value, LimitText::Contract, MAX_PAGE)?
        }
        Some(value) => positive("--limit", value, LimitText::Contract)?,
        None => DEFAULT_ATTACK_LIMIT,
    };
    let severity = filter("--severity", severity)?;
    if let (true, Some(severity)) = (attacks, &severity) {
        check_one_of("--severity", severity, &SEVERITIES)?;
    }
    Ok(AttackListArgs { limit, severity })
}

/// `--offset`: 0 to 2^53 − 1.
pub fn offset(value: &str) -> Result<u64, CliError> {
    decimal(value)
        .filter(|n| *n <= MAX_SAFE_INTEGER)
        .ok_or_else(|| CliError::usage("--offset must be a non-negative integer"))
}

/// `--max` (§7.1): a non-negative safe integer; `0` means no item cap.
pub fn max(value: &str) -> Result<u64, CliError> {
    decimal(value)
        .filter(|n| *n <= MAX_SAFE_INTEGER)
        .ok_or_else(|| CliError::usage("--max must be a non-negative integer"))
}

/// Validate `--limit`, `--offset`, `--max` and `--all` with `--offset`, in that order.
pub fn list_params(
    limit: Option<&str>,
    offset_value: Option<&str>,
    all: bool,
    max_value: Option<&str>,
    text: LimitText,
) -> Result<ListParams, CliError> {
    bounded_list_params(limit, offset_value, all, max_value, text, None)
}

/// [`list_params`] with an API `bound` on `--limit`, checked right after its positive
/// rule (D301).
pub fn bounded_list_params(
    limit: Option<&str>,
    offset_value: Option<&str>,
    all: bool,
    max_value: Option<&str>,
    text: LimitText,
    bound: Option<u32>,
) -> Result<ListParams, CliError> {
    let limit = limit
        .map(|value| match bound {
            Some(bound) => bounded_positive("--limit", value, text, bound),
            None => positive("--limit", value, text),
        })
        .transpose()?;
    let offset = offset_value.map(offset).transpose()?;
    let max = max_value
        .map(max)
        .transpose()?
        .unwrap_or(pagination::DEFAULT_MAX);
    if all && offset_value.is_some() {
        return Err(CliError::usage("--all cannot be combined with --offset"));
    }
    Ok(ListParams {
        limit,
        offset,
        all,
        max,
    })
}

/// `--status` of `channels list`: one or more non-empty filter values, at most 252.
pub fn statuses(values: &[String]) -> Result<Vec<String>, CliError> {
    if values.len() > MAX_STATUS_VALUES {
        return Err(CliError::usage(format!(
            "--status accepts at most {MAX_STATUS_VALUES} values"
        )));
    }
    for value in values {
        if value.is_empty() {
            return Err(CliError::usage("--status values must not be empty"));
        }
        check_filter("--status", value)?;
    }
    Ok(values.to_vec())
}

/// The red team banner (`renderRedteamHeader`).
pub const BANNER_TITLE: &str = "Prisma AIRS — AI Red Team";
pub const BANNER_SUBTITLE: &str = "Adversarial scan operations";

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(result: Result<impl std::fmt::Debug, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    #[test]
    fn uuid_checks_use_the_typescript_text() {
        assert!(check_uuid("job id", "00000000-0000-4000-8000-000000000101").is_ok());
        assert_eq!(
            usage(check_uuid("job id", "not-a-uuid")),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: not-a-uuid"
        );
        assert_eq!(
            usage(check_uuid("target uuid", "")),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid target uuid: "
        );
    }

    #[test]
    fn serial_number_lists_name_at_least_one() {
        for good in ["SN1", "SN1,SN2", " SN1 ", ",SN1,", "SN1,,SN2"] {
            assert!(check_serial_numbers(good).is_ok(), "{good:?}");
        }
        for empty in ["", " ", ",", " , ,", ",,,", "\u{a0}"] {
            assert_eq!(
                usage(check_serial_numbers(empty)),
                "--serial-numbers needs at least one serial number",
                "{empty:?}"
            );
        }
    }

    #[test]
    fn filters_numbers_and_list_flags() {
        assert!(check_filter("--status", "RUNNING").is_ok());
        assert_eq!(
            usage(check_filter("--search", "a\nb")),
            "--search must be at most 4096 bytes and contain no control characters"
        );
        assert!(check_filter("--search", &"x".repeat(4096)).is_ok());
        assert!(check_filter("--search", &"x".repeat(4097)).is_err());
        for bad in ["0", "-1", "abc", "1.5", "2.5x", "", "4294967296"] {
            assert_eq!(
                usage(positive("--limit", bad, LimitText::Contract)),
                "--limit must be a positive integer",
                "{bad}"
            );
            assert_eq!(
                usage(positive("--depth", bad, LimitText::Typescript)),
                format!("--depth: expected a positive integer, got \"{bad}\""),
            );
        }
        assert_eq!(
            positive("--limit", "4294967295", LimitText::Contract).unwrap(),
            u32::MAX
        );
        assert_eq!(offset("9007199254740991").unwrap(), MAX_SAFE_INTEGER);
        assert!(offset("9007199254740992").is_err());
        assert_eq!(
            usage(list_params(
                None,
                Some("0"),
                true,
                None,
                LimitText::Contract
            )),
            "--all cannot be combined with --offset"
        );
        assert_eq!(
            usage(list_params(
                Some("x"),
                Some("y"),
                true,
                Some("z"),
                LimitText::Contract
            )),
            "--limit must be a positive integer"
        );
        assert_eq!(
            usage(list_params(
                None,
                Some("y"),
                true,
                Some("z"),
                LimitText::Contract
            )),
            "--offset must be a non-negative integer"
        );
        assert_eq!(
            usage(list_params(
                None,
                None,
                false,
                Some("z"),
                LimitText::Contract
            )),
            "--max must be a non-negative integer"
        );
        let params = list_params(Some("5"), None, true, Some("0"), LimitText::Contract).unwrap();
        assert_eq!(
            params,
            ListParams {
                limit: Some(5),
                offset: None,
                all: true,
                max: 0
            }
        );
        assert_eq!(
            usage(statuses(&["ONLINE".into(), String::new()])),
            "--status values must not be empty"
        );
        assert_eq!(
            usage(statuses(&vec!["A".to_owned(); 253])),
            "--status accepts at most 252 values"
        );
        assert_eq!(statuses(&vec!["A".to_owned(); 252]).unwrap().len(), 252);
    }

    #[test]
    fn api_bounds_and_vocabularies_name_the_flag_only() {
        assert_eq!(at_most("--limit", 100, MAX_PAGE).unwrap(), 100);
        assert_eq!(
            usage(at_most("--limit", 101, MAX_PAGE)),
            "--limit must be at most 100 (the red team API maximum)"
        );
        assert_eq!(
            usage(at_most("--breadth", 21, MAX_STREAM)),
            "--breadth must be at most 20 (the red team API maximum)"
        );
        assert_eq!(
            usage(bounded_list_params(
                Some("101"),
                Some("x"),
                false,
                None,
                LimitText::Contract,
                Some(MAX_PAGE)
            )),
            "--limit must be at most 100 (the red team API maximum)"
        );
        assert_eq!(
            usage(bounded_list_params(
                Some("0"),
                None,
                false,
                None,
                LimitText::Contract,
                Some(MAX_PAGE)
            )),
            "--limit must be a positive integer"
        );
        for status in JOB_STATUSES {
            assert_eq!(
                vocabulary_filter("--status", Some(status), &JOB_STATUSES).unwrap(),
                Some(status.to_owned())
            );
        }
        assert_eq!(
            vocabulary_filter("--status", Some(""), &JOB_STATUSES).unwrap(),
            None
        );
        for bad in ["completed", "PROFILING", " RUNNING"] {
            assert_eq!(
                usage(vocabulary_filter("--status", Some(bad), &JOB_STATUSES)),
                "--status must be one of QUEUED, RUNNING, COMPLETED, PARTIALLY_COMPLETE, FAILED, ABORTED"
            );
        }
        assert_eq!(
            usage(vocabulary_filter("--type", Some("a\tb"), &LIST_JOB_TYPES)),
            "--type must be at most 4096 bytes and contain no control characters"
        );
        assert_eq!(
            usage(vocabulary_filter("--type", Some("static"), &LIST_JOB_TYPES)),
            "--type must be one of STATIC, DYNAMIC, CUSTOM, CLARA"
        );
        assert_eq!(target_filter(Some("")).unwrap(), None);
        assert_eq!(
            usage(target_filter(Some("t-1"))),
            "--target must be a target UUID"
        );
        assert_eq!(
            usage(check_one_of("--severity", "", &SEVERITIES)),
            "--severity must be one of LOW, MEDIUM, HIGH, CRITICAL"
        );
        assert!(refuse_option("--offset", false, "target error logs", "--limit").is_ok());
        assert_eq!(
            usage(refuse_option(
                "--search",
                true,
                "target error logs",
                "--limit"
            )),
            "--search is not supported for target error logs (the red team API accepts only --limit)"
        );
        assert_eq!(
            bounded_positive("--limit", "100", LimitText::Typescript, MAX_PAGE).unwrap(),
            100
        );
        assert_eq!(
            usage(bounded_positive(
                "--limit",
                "0",
                LimitText::Typescript,
                MAX_PAGE
            )),
            "--limit: expected a positive integer, got \"0\""
        );
        assert_eq!(
            usage(bounded_positive(
                "--limit",
                "101",
                LimitText::Typescript,
                MAX_PAGE
            )),
            "--limit must be at most 100 (the red team API maximum)"
        );
    }

    #[test]
    fn attack_list_args_bound_only_with_attacks() {
        assert_eq!(
            attack_list_args(None, None, true).unwrap(),
            AttackListArgs {
                limit: DEFAULT_ATTACK_LIMIT,
                severity: None
            }
        );
        assert_eq!(
            attack_list_args(Some("100"), Some("HIGH"), true).unwrap(),
            AttackListArgs {
                limit: 100,
                severity: Some("HIGH".to_owned())
            }
        );
        // Without `--attacks` the values are unused: only the positive and filter rules.
        assert_eq!(
            attack_list_args(Some("500"), Some("high"), false).unwrap(),
            AttackListArgs {
                limit: 500,
                severity: Some("high".to_owned())
            }
        );
        assert_eq!(
            usage(attack_list_args(Some("0"), None, false)),
            "--limit must be a positive integer"
        );
        assert_eq!(
            usage(attack_list_args(Some("101"), None, true)),
            "--limit must be at most 100 (the red team API maximum)"
        );
        for bad in ["high", "", "SEVERE"] {
            assert_eq!(
                usage(attack_list_args(None, Some(bad), true)),
                "--severity must be one of LOW, MEDIUM, HIGH, CRITICAL",
                "{bad:?}"
            );
        }
        assert_eq!(
            usage(attack_list_args(None, Some("a\tb"), false)),
            "--severity must be at most 4096 bytes and contain no control characters"
        );
        // `--limit` is reported before `--severity` (choice 17).
        assert_eq!(
            usage(attack_list_args(Some("101"), Some("high"), true)),
            "--limit must be at most 100 (the red team API maximum)"
        );
    }
}
