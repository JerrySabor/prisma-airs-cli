//! The SDK path-segment rule shared by every command that puts a user value into a URL
//! path (the red team, model-security, DLP and runtime key ids and names; DESIGN §15.3,
//! §18.5 G29). Feature-neutral: no feature module owns it.

use crate::error::CliError;

/// The SDK bound of one segment (bytes).
const SEGMENT_LIMIT: usize = 4096;

/// The SDK path-segment rule (`rs:config.rs:121-151`): non-empty, at most 4,096 bytes,
/// no `\`, no control character and no `.`/`..` part, also once percent-decoded (up to
/// eight times). A valid value is sent as one encoded segment. Failure:
/// `Invalid <field>: <value>`.
pub fn check_segment(field: &str, value: &str) -> Result<(), CliError> {
    if segment_ok(value) {
        Ok(())
    } else {
        Err(CliError::usage(format!("Invalid {field}: {value}")))
    }
}

fn segment_ok(value: &str) -> bool {
    if value.is_empty() || value.len() > SEGMENT_LIMIT || value.chars().any(char::is_control) {
        return false;
    }
    let hex = |byte: u8| {
        (byte as char)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let mut decoded = value.as_bytes().to_vec();
    for _ in 0..=8 {
        if decoded.iter().any(|b| b.is_ascii_control() || *b == b'\\')
            || decoded
                .split(|b| *b == b'/')
                .any(|part| part == b"." || part == b"..")
        {
            return false;
        }
        let mut next = Vec::with_capacity(decoded.len());
        let mut index = 0;
        while index < decoded.len() {
            if decoded[index] == b'%'
                && index + 2 < decoded.len()
                && let (Some(high), Some(low)) = (hex(decoded[index + 1]), hex(decoded[index + 2]))
            {
                next.push(high * 16 + low);
                index += 3;
            } else {
                next.push(decoded[index]);
                index += 1;
            }
        }
        if next == decoded {
            return true;
        }
        decoded = next;
    }
    false
}

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
    fn segments_refuse_traversal_at_every_decoding_depth() {
        for good in ["ten-1", "a/b", "a b", "100%", "%zz", "x.y", ".hidden"] {
            assert!(segment_ok(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "..",
            "../registry-credentials",
            "a/..",
            "a\\b",
            "%2e%2e",
            "%252e%252e",
            "a%2F..",
            "%5c",
            "%00",
            "tab\there",
        ] {
            assert!(!segment_ok(bad), "{bad:?}");
        }
        assert!(!segment_ok(&"x".repeat(4097)));
        assert_eq!(
            usage(check_segment("tenant id", "../x")),
            "Invalid tenant id: ../x"
        );
    }
}
