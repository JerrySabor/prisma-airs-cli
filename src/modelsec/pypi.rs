//! The PyPI index URL of `model-security pypi-auth` and `install` (DESIGN §17.12, §17.13,
//! D194, D201). Pure: parsing, the secret registration, the withheld form, the index
//! check and the credential split.
//!
//! The service answers a credential-bearing Google Artifact Registry index URL
//! (`https://oauth2accesstoken:<access token>@<host>/<project>/<repo>/simple/`). Its
//! credential joins the invocation's `SecretSet` before anything else uses the response,
//! and the URL itself is printed only in its withheld form.

use crate::error::{SecretSet, WITHHELD};
use crate::output::terminal_safe;

/// The largest index URL the CLI hands to uv or writes to `--url-file` (D201).
pub const MAX_INDEX_URL_BYTES: usize = 8 * 1024;

/// `pypi-auth --url-file` refuses a URL that fails the index check (§17.12).
pub const UNUSABLE_FOR_FILE: &str =
    "The PyPI auth response is not a usable index URL; nothing was written";

/// `install` refuses a URL that fails the index check (§17.13, D201).
pub const UNUSABLE_FOR_INSTALL: &str =
    "The PyPI auth response is not a usable index URL; nothing was installed.";

/// RFC 3986 percent-decoding of a userinfo part (`+` stays `+`); `None` when the result
/// is not UTF-8.
pub fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2]))
        {
            out.push(high * 16 + low);
            index += 3;
            continue;
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8(out).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parsed(raw: &str) -> Option<url::Url> {
    let url = url::Url::parse(raw).ok()?;
    url.has_host().then_some(url)
}

/// The raw (percent-encoded) userinfo of `raw` as the URL carries it, when it has one.
fn raw_userinfo(raw: &str) -> Option<&str> {
    let (_, rest) = raw.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    authority.rsplit_once('@').map(|(userinfo, _)| userinfo)
}

/// Register the credential of `raw` in `secrets` (§17.12 "The credential"): the full URL,
/// its raw userinfo, the password raw and percent-decoded, the `username:password` pair
/// (raw and as the HTTP Basic base64 carries it), and the username alone only when there
/// is no password. Called before anything is printed, written or spawned.
pub fn register(raw: &str, secrets: &SecretSet) {
    if !raw.is_empty() {
        secrets.add(raw);
    }
    let Some(userinfo) = raw_userinfo(raw) else {
        return;
    };
    if !userinfo.is_empty() {
        secrets.add(userinfo);
    }
    let (username, password) = match userinfo.split_once(':') {
        Some((username, password)) => (username, Some(password)),
        None => (userinfo, None),
    };
    match password.filter(|password| !password.is_empty()) {
        Some(password) => {
            secrets.add(password);
            let decoded_password = percent_decode(password);
            if let Some(decoded) = &decoded_password {
                secrets.add(decoded);
            }
            let decoded_username = percent_decode(username).unwrap_or_else(|| username.to_owned());
            secrets.add_basic_credentials(
                &decoded_username,
                decoded_password.as_deref().unwrap_or(password),
            );
            secrets.add_basic_credentials(username, password);
        }
        None if !username.is_empty() => {
            secrets.add(username);
            if let Some(decoded) = percent_decode(username) {
                secrets.add(&decoded);
            }
        }
        None => {}
    }
}

/// The withheld form of `raw` (§17.12): `<scheme>://` + `[withheld]@` when it has a
/// userinfo + `<host>[:<port>]<path>` + `?[withheld]` / `#[withheld]`, terminal-safe;
/// `[withheld]` when it does not parse with a host or when the form still carries a
/// registered secret.
pub fn withheld_form(raw: &str, secrets: &SecretSet) -> String {
    let Some(url) = parsed(raw) else {
        return WITHHELD.to_owned();
    };
    let mut out = format!("{}://", url.scheme());
    if !url.username().is_empty() || url.password().is_some() || raw_userinfo(raw).is_some() {
        out.push_str(WITHHELD);
        out.push('@');
    }
    out.push_str(url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        out.push_str(&format!(":{port}"));
    }
    out.push_str(url.path());
    if url.query().is_some() {
        out.push('?');
        out.push_str(WITHHELD);
    }
    if url.fragment().is_some() {
        out.push('#');
        out.push_str(WITHHELD);
    }
    let out = terminal_safe(&out).into_owned();
    if secrets.carried_by(&out) {
        WITHHELD.to_owned()
    } else {
        out
    }
}

/// A URL that passed the index check (D201): the credential-free index and the
/// percent-decoded credential pair.
#[derive(Clone, PartialEq, Eq)]
pub struct Index {
    /// `https://<host>[:<port>]<path>`, no userinfo, query or fragment.
    pub index: String,
    /// The percent-decoded username (`UV_INDEX_AIRS_MODEL_SECURITY_USERNAME`).
    pub username: String,
    /// The percent-decoded password (`UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD`).
    pub password: String,
    /// The raw (percent-encoded) password as the URL carries it.
    pub raw_password: String,
    /// The raw (percent-encoded) userinfo.
    pub raw_userinfo: String,
}

impl std::fmt::Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Index")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

/// The index check (§17.13 step 6, D201): the URL parses with `url::Url`; the scheme is
/// `https`; it has a host; the username and the password are non-empty once
/// percent-decoded (and UTF-8 without control characters); there is no query and no
/// fragment; the whole URL has no control character and is at most 8 KiB.
pub fn check(raw: &str) -> Option<Index> {
    if raw.len() > MAX_INDEX_URL_BYTES || has_control(raw) {
        return None;
    }
    let url = parsed(raw)?;
    if url.scheme() != "https" || url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    let userinfo = raw_userinfo(raw)?;
    let (raw_username, raw_password) = userinfo.split_once(':')?;
    let username = percent_decode(raw_username)?;
    let password = percent_decode(raw_password)?;
    if username.is_empty()
        || password.is_empty()
        || has_control(&username)
        || has_control(&password)
    {
        return None;
    }
    let mut index = format!("https://{}", url.host_str()?);
    if let Some(port) = url.port() {
        index.push_str(&format!(":{port}"));
    }
    index.push_str(url.path());
    if has_control(&index) || index.contains('@') {
        return None;
    }
    Some(Index {
        index,
        username,
        password,
        raw_password: raw_password.to_owned(),
        raw_userinfo: userinfo.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str =
        "https://oauth2accesstoken:FAKE-PYPI-SECRET-100@us-west1-python.pkg.dev/proj/repo/simple/";

    #[test]
    fn the_credential_joins_the_secret_set_and_is_withheld() {
        let secrets = SecretSet::default();
        register(URL, &secrets);
        for text in [
            URL,
            "FAKE-PYPI-SECRET-100",
            "oauth2accesstoken:FAKE-PYPI-SECRET-100",
            &crate::error::base64_standard(b"oauth2accesstoken:FAKE-PYPI-SECRET-100"),
        ] {
            assert!(secrets.carried_by(text), "{text}");
        }
        assert!(
            !secrets.carried_by("oauth2accesstoken"),
            "the username alone is not a secret when a password exists"
        );
        assert_eq!(
            withheld_form(URL, &secrets),
            "https://[withheld]@us-west1-python.pkg.dev/proj/repo/simple/"
        );
        // A percent-encoded password is registered decoded too.
        let secrets = SecretSet::default();
        register("https://u:FAKE%2DPW%2B1@h.example/simple/", &secrets);
        assert!(secrets.carried_by("FAKE-PW+1"));
        assert!(secrets.carried_by("FAKE%2DPW%2B1"));
        // A username without a password is the credential.
        let secrets = SecretSet::default();
        register("https://TOKEN-ONLY-1234@h.example/simple/", &secrets);
        assert!(secrets.carried_by("TOKEN-ONLY-1234"));
    }

    #[test]
    fn the_withheld_form_keeps_scheme_host_port_and_path_only() {
        let secrets = SecretSet::default();
        for (raw, form) in [
            ("https://h.example/simple/", "https://h.example/simple/"),
            (
                "https://u:p@h.example:8443/s/?token=abc#frag",
                "https://[withheld]@h.example:8443/s/?[withheld]#[withheld]",
            ),
            (
                "http://u:p@127.0.0.1:9/x",
                "http://[withheld]@127.0.0.1:9/x",
            ),
            ("not a url", "[withheld]"),
            ("", "[withheld]"),
            ("mailto:someone", "[withheld]"),
        ] {
            assert_eq!(withheld_form(raw, &secrets), form, "{raw}");
        }
        // A form that still carries a registered value is withheld whole.
        let secrets = SecretSet::default();
        secrets.add("h.example");
        assert_eq!(
            withheld_form("https://u:p@h.example/s/", &secrets),
            "[withheld]"
        );
    }

    #[test]
    fn the_index_check_refuses_unusable_urls() {
        let index = check(URL).unwrap();
        assert_eq!(
            index.index,
            "https://us-west1-python.pkg.dev/proj/repo/simple/"
        );
        assert_eq!(index.username, "oauth2accesstoken");
        assert_eq!(index.password, "FAKE-PYPI-SECRET-100");
        assert!(!format!("{index:?}").contains("FAKE"), "Debug withholds");
        let decoded = check("https://us%65r:p%40ss%2Bw@h.example:444/s/").unwrap();
        assert_eq!(decoded.username, "user");
        assert_eq!(decoded.password, "p@ss+w");
        assert_eq!(decoded.index, "https://h.example:444/s/");
        let long = format!("https://u:p@h.example/{}", "a".repeat(MAX_INDEX_URL_BYTES));
        for bad in [
            "http://u:p@h.example/s/",
            "https://h.example/s/",
            "https://u@h.example/s/",
            "https://u:@h.example/s/",
            "https://:p@h.example/s/",
            "https://u:p@h.example/s/?q=1",
            "https://u:p@h.example/s/#f",
            "https://u:p@h.example/s/\u{1b}[31m",
            "https://u:p%0A@h.example/s/",
            "https://u:%FF@h.example/s/",
            "not a url",
            long.as_str(),
        ] {
            assert!(check(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn percent_decoding_keeps_plus_and_stray_percents() {
        assert_eq!(percent_decode("a+b%20c%2").as_deref(), Some("a+b c%2"));
        assert_eq!(percent_decode("%zz").as_deref(), Some("%zz"));
        assert_eq!(percent_decode("%ff"), None);
    }
}
