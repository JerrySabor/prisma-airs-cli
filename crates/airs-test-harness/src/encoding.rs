//! Small encoding helpers: form/query decoding, percent-encoding, HMAC and base64.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Decodes `application/x-www-form-urlencoded` text (also used for query strings, with
/// WHATWG `URLSearchParams` semantics: `+` is a space, pairs keep their order, a missing
/// `=` yields an empty value, empty segments are skipped).
pub fn form_decode(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let (name, value) = segment.split_once('=').unwrap_or((segment, ""));
            (percent_decode_plus(name), percent_decode_plus(value))
        })
        .collect()
}

/// Percent-decodes `input`, treating `+` as a space; invalid escapes are kept literally
/// and invalid UTF-8 is replaced lossily.
pub fn percent_decode_plus(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high << 4 | low);
                        index += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-decodes `input` as a URL userinfo part (`+` stays `+`); invalid escapes are
/// kept literally and invalid UTF-8 is replaced lossily.
pub fn percent_decode(input: &str) -> String {
    percent_decode_plus(&input.replace('+', "%2B"))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-encodes everything except RFC 3986 unreserved characters (the
/// `encodeURIComponent`-style form used for secret leak checks).
pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Standard (padded) base64.
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decodes standard base64, returning `None` for malformed input.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    STANDARD.decode(input.trim()).ok()
}

/// Lowercase hex HMAC-SHA256 of `body` keyed with `key` (the AIRS `x-payload-hash`).
pub fn payload_hash(key: &str, body: &[u8]) -> String {
    // HMAC accepts keys of any length, so construction cannot fail.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key.as_bytes()) else {
        unreachable!("HMAC-SHA256 accepts any key length");
    };
    mac.update(body);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_decoding_follows_url_search_params() {
        assert_eq!(
            form_decode("grant_type=client_credentials&scope=tsg_id%3A100&a+b=c+d&flag&&x=%zz"),
            vec![
                ("grant_type".into(), "client_credentials".into()),
                ("scope".into(), "tsg_id:100".into()),
                ("a b".into(), "c d".into()),
                ("flag".into(), String::new()),
                ("x".into(), "%zz".into()),
            ]
        );
        assert_eq!(percent_decode_plus("100%"), "100%");
        assert_eq!(percent_decode_plus("%4"), "%4");
        assert_eq!(percent_decode_plus("%41"), "A");
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        assert_eq!(
            payload_hash("Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn percent_encoding_keeps_unreserved() {
        assert_eq!(percent_encode("FAKE-SECRET-100"), "FAKE-SECRET-100");
        assert_eq!(percent_encode("a b/c"), "a%20b%2Fc");
    }
}
