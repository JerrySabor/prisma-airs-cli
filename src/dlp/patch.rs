//! The DLP merge patch of `--set` and `--clear` (DESIGN §16.3 "Merge patch", TS
//! `patch.ts:10-51`, D163). Pure: no message here echoes a key or a value.
//!
//! `--set k=v` splits at the first `=` and coerces the value as TypeScript does:
//! `true`/`false` are booleans; `^-?\d+(\.\d+)?$` is a JSON number (the nearest double for
//! a fraction, as `Number()`; an integer part beyond 2^53 is refused, where TypeScript
//! rounds it); a value starting with `{`, `[` or `"` is parsed as JSON, falling back to
//! the raw string; anything else is the string. `--clear k` sets `k` to `null` after
//! every `--set`, and a repeated `--set` of one key keeps the last value.

use serde_json::{Map, Number, Value};

/// Why a `--set`/`--clear` list was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchError {
    /// An entry without `=`, or with an empty key.
    ExpectsKeyValue,
    /// A dotted (nested) key.
    Nested,
    /// The raw value `null`.
    Null,
    /// A number the coercion cannot represent exactly.
    Inexact,
}

impl PatchError {
    /// The fixed message (the patterns texts; profiles and dictionaries mask every
    /// failure with their own TS text).
    pub fn message(self) -> &'static str {
        match self {
            Self::ExpectsKeyValue => "--set expects key=value",
            Self::Nested => {
                "--set and --clear take top-level fields; use --body-file for nested fields"
            }
            Self::Null => "--set cannot set null; use --clear for that field",
            Self::Inexact => {
                "--set numbers must keep their exact value; quote them to send a string"
            }
        }
    }
}

/// The largest integer a JavaScript number holds exactly (2^53).
const SAFE: u64 = 1 << 53;

/// Whether `raw` matches `^-?\d+(\.\d+)?$`.
fn numeric(raw: &str) -> bool {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    let (int, fraction) = match digits.split_once('.') {
        Some((int, fraction)) => (int, Some(fraction)),
        None => (digits, None),
    };
    let all_digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    all_digits(int) && fraction.is_none_or(all_digits)
}

/// A decimal number as JSON in JavaScript form (`Number(raw)`, then `JSON.stringify`):
/// an integral value is an integer, a fraction the nearest double. `None` when the
/// integer part exceeds 2^53 (not exact).
pub fn js_number(raw: &str) -> Option<Number> {
    let negative = raw.starts_with('-');
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    let (int, fraction) = digits.split_once('.').unwrap_or((digits, ""));
    let int_value: u64 = int.trim_start_matches('0').parse().unwrap_or(0);
    if int.trim_start_matches('0').len() > 16 || int_value > SAFE {
        return None;
    }
    let integral = fraction.bytes().all(|b| b == b'0');
    if integral {
        let value = i64::try_from(int_value).ok()?;
        return Some(Number::from(if negative { -value } else { value }));
    }
    let value: f64 = raw.parse().ok()?;
    Number::from_f64(value)
}

/// TS `coerceValue`.
fn coerce(raw: &str) -> Result<Value, PatchError> {
    match raw {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if numeric(raw) {
        return js_number(raw).map(Value::Number).ok_or(PatchError::Inexact);
    }
    if raw.starts_with('{') || raw.starts_with('[') || raw.starts_with('"') {
        return Ok(serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned())));
    }
    Ok(Value::String(raw.to_owned()))
}

/// The merge-patch document of `--set` entries and `--clear` keys (`{}` when both are
/// empty).
pub fn merge_patch(set: &[String], clear: &[String]) -> Result<Map<String, Value>, PatchError> {
    let mut out = Map::new();
    for entry in set {
        let Some((key, raw)) = entry.split_once('=').filter(|(key, _)| !key.is_empty()) else {
            return Err(PatchError::ExpectsKeyValue);
        };
        if key.contains('.') {
            return Err(PatchError::Nested);
        }
        if raw == "null" {
            return Err(PatchError::Null);
        }
        out.insert(key.to_owned(), coerce(raw)?);
    }
    for key in clear {
        if key.contains('.') {
            return Err(PatchError::Nested);
        }
        out.insert(key.clone(), Value::Null);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn patch(set: &[&str], clear: &[&str]) -> Result<Value, PatchError> {
        let set: Vec<String> = set.iter().map(|s| (*s).to_owned()).collect();
        let clear: Vec<String> = clear.iter().map(|s| (*s).to_owned()).collect();
        merge_patch(&set, &clear).map(Value::Object)
    }

    /// TS `dlp-patch.spec.ts`: the coercion table.
    #[test]
    fn values_are_coerced_as_typescript_does() {
        assert_eq!(
            patch(
                &[
                    "name=My",
                    "type=custom",
                    r#"detection_config={"technique":"regex"}"#,
                    "n=5",
                    r#"s="5""#,
                    "b=true",
                    "f=false",
                    "arr=[1,2]",
                    "bad={oops",
                    "neg=-3",
                    "frac=1.5",
                    "whole=2.0",
                    "word=null-ish",
                    "empty=",
                    r#"q="null""#,
                    "eq=a=b",
                ],
                &["description"]
            )
            .unwrap(),
            json!({
                "name": "My",
                "type": "custom",
                "detection_config": {"technique": "regex"},
                "n": 5,
                "s": "5",
                "b": true,
                "f": false,
                "arr": [1, 2],
                "bad": "{oops",
                "neg": -3,
                "frac": 1.5,
                "whole": 2,
                "word": "null-ish",
                "empty": "",
                "q": "null",
                "eq": "a=b",
                "description": null
            })
        );
        // Not numbers: exponents, leading plus, a trailing dot.
        for raw in ["1e3", "+1", "1.", ".5", "0x10"] {
            assert_eq!(
                patch(&[&format!("v={raw}")], &[]).unwrap()["v"],
                json!(raw),
                "{raw}"
            );
        }
        assert_eq!(
            patch(&["v=9007199254740992"], &[]).unwrap()["v"],
            json!(9_007_199_254_740_992_u64)
        );
    }

    #[test]
    fn clears_come_after_sets_and_the_last_set_wins() {
        assert_eq!(patch(&["k=v", "k=w"], &[]).unwrap(), json!({"k": "w"}));
        assert_eq!(patch(&["k=v"], &["k"]).unwrap(), json!({"k": null}));
        assert_eq!(patch(&[], &[]).unwrap(), json!({}));
    }

    #[test]
    fn malformed_entries_are_refused_without_echoing_them() {
        for (set, clear, error) in [
            (&["noequals"][..], &[][..], PatchError::ExpectsKeyValue),
            (&["=v"], &[], PatchError::ExpectsKeyValue),
            (&["a.b=1"], &[], PatchError::Nested),
            (&[], &["a.b"], PatchError::Nested),
            (&["k=null"], &[], PatchError::Null),
            (&["k=12345678901234567890"], &[], PatchError::Inexact),
            (&["k=9007199254740993.5"], &[], PatchError::Inexact),
        ] {
            assert_eq!(patch(set, clear).unwrap_err(), error, "{set:?} {clear:?}");
        }
        for error in [
            PatchError::ExpectsKeyValue,
            PatchError::Nested,
            PatchError::Null,
            PatchError::Inexact,
        ] {
            assert!(!error.message().contains("noequals"));
        }
    }
}
