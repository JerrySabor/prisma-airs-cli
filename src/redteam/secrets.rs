//! The §15.4 redaction of red team documents (D140; the SDK cannot mark secret fields,
//! G8). [`redact`] replaces every credential value of a document with `[REDACTED]`
//! before anything is rendered, in every format, and registers each value it replaces
//! (a structured value through its credentials, below) in the invocation's
//! [`SecretSet`], so an echo of it anywhere else is withheld.
//!
//! Only non-empty strings are replaced: keys, `null`, `""`, numbers and booleans are
//! kept, so the document's shape stays visible.
//!
//! Which replaced values join the secret set (§15.4 "Registration"): a value the rules
//! know to be a credential (a `SECRET` variable value, the value of a secret-named key or
//! header) always; any other replaced value (a plain header value, an `auth_config` or
//! `target_connection_config` field) only when it is at least [`MIN_REGISTERED`] bytes
//! long and not under a non-credential key ([`UNREGISTERED_KEYS`]) nor a Vertex AI
//! identifier string directly under `target_connection_config` ([`VERTEX_AI_IDS`], whose
//! embedded credentials still register, [`identifier`]). A short or
//! non-credential value such as `X-Api-Version: 1`, `grant_type: client_credentials` or
//! `location: us-central1` is still `[REDACTED]` where it stands, but it does not withhold
//! every later text that happens to contain it (a Vertex AI `api_endpoint` holds the
//! location and the project). A secret-named key registers its value whatever it is under.
//!
//! A structured value is never registered as one secret: a `curl` command and a URL
//! carry the endpoint, the model, the request and the target's own name and
//! description, and the §6 fragment rule would withhold every name that occurs in them.
//! They are redacted where they stand, and only the credentials extracted from them
//! join the set ([`curl_credentials`], [`url_credentials`]).

use crate::error::SecretSet;
use crate::json::OValue;

/// What replaces a credential value.
pub const REDACTED: &str = "[REDACTED]";

/// The shortest replaced value that joins the secret set when the rules do not know it to
/// be a credential.
pub const MIN_REGISTERED: usize = 8;

/// Keys under a credential path whose values are redacted but are not credentials, so
/// they never join the secret set (ASCII case-insensitive).
pub const UNREGISTERED_KEYS: [&str; 5] =
    ["client_id", "clientid", "grant_type", "scope", "audience"];

/// The patterned Vertex AI identifiers of a `target_connection_config` (management 0.86.0,
/// scm-sdk 0.2.3), each with the smallest value of its request pattern: a string directly
/// under the config is redacted by rule 4 but not registered itself (DESIGN §15.24
/// choice 12); the backup names a masked one and checks the projection with the
/// placeholders in place (choice 13).
pub const VERTEX_AI_IDS: [(&str, &str); 3] = [
    ("project_id", "placeholder"),
    ("location", "placeholder"),
    ("engine_id", "0"),
];

/// The key lists of an [`all_strings`] walk, each matched ASCII case-sensitively at any
/// depth.
#[derive(Clone, Copy)]
struct Keys<'a> {
    /// Values kept as they are.
    kept: &'a [&'a str],
    /// Values under the D45 URL rule ([`url`]).
    urls: &'a [&'a str],
}

impl Keys<'_> {
    /// No key list: every string redacted, registered by its keys alone.
    const NONE: Keys<'static> = Keys {
        kept: &[],
        urls: &[],
    };
}

/// How a replaced value joins the secret set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reg {
    /// A known credential: always.
    Strong,
    /// Redacted by its path: when at least [`MIN_REGISTERED`] bytes long.
    Weak,
    /// A non-credential key: never.
    Never,
}

impl Reg {
    /// The registration of the value under `key` inside a value registered as `self`. A
    /// secret-named key is [`Reg::Strong`] first, under a non-credential key too, so a
    /// credential nested in one (`{"scope": {"token": …}}`) still registers.
    fn under(self, key: &str) -> Self {
        let lower = key.to_ascii_lowercase();
        if secret_key(key) {
            Self::Strong
        } else if self == Self::Never || UNREGISTERED_KEYS.contains(&lower.as_str()) {
            Self::Never
        } else {
            self
        }
    }

    fn admits(self, value: &str) -> bool {
        match self {
            Self::Strong => true,
            Self::Weak => value.len() >= MIN_REGISTERED,
            Self::Never => false,
        }
    }
}

/// The kind of document being redacted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A target (`TargetResponse`, the normalised target detail, probe and
    /// update-profile answers, a target body, an error log's `target_object`).
    Target,
    /// An adapter (the normalised detail and the adapter answers).
    Adapter,
    /// A normalised target-profile error log.
    ErrorLog,
    /// Anything else: the catch-all rule only (profiles, metadata, templates).
    Generic,
}

/// The credential of an `Authorization`-style value (`Bearer <token>`, `Basic <b64>`):
/// the part after a short alphabetic scheme, when it is at least 4 characters long.
fn scheme_credential(value: &str) -> Option<&str> {
    let (scheme, rest) = value.trim().split_once(' ')?;
    let rest = rest.trim();
    (!scheme.is_empty()
        && scheme.len() <= 16
        && scheme.bytes().all(|byte| byte.is_ascii_alphabetic())
        && rest.len() >= 4)
        .then_some(rest)
}

/// Redact `document` as a `shape`; every replaced value joins `secrets` (and, for a
/// `<scheme> <credential>` value, the credential on its own, so an echo of the bare
/// token is withheld too).
pub fn redact(document: &mut OValue, shape: Shape, secrets: &SecretSet) {
    let mut sink = |value: &str, reg: Reg| {
        if !reg.admits(value) {
            return;
        }
        secrets.add(value);
        if let Some(credential) = scheme_credential(value)
            && reg.admits(credential)
        {
            secrets.add(credential);
        }
    };
    match shape {
        Shape::Target => target(document, &mut sink),
        Shape::Adapter => adapter(document, &mut sink),
        Shape::ErrorLog => error_log(document, &mut sink),
        Shape::Generic => catch_all(document, &mut sink),
    }
}

type Sink<'a> = dyn FnMut(&str, Reg) + 'a;

/// What stands in for a withheld value while [`withheld`] runs the target rules.
const SENTINEL: &str = "\u{0}airs-withheld\u{0}";

/// A server mask: four or more `*` and nothing else.
pub(crate) fn is_mask(text: &str) -> bool {
    text.len() >= 4 && text.bytes().all(|byte| byte == b'*')
}

fn mark_withheld(value: &mut OValue) {
    match value {
        OValue::String(text) if text == REDACTED || is_mask(text) => {
            *text = SENTINEL.to_owned();
        }
        OValue::Array(items) => items.iter_mut().for_each(mark_withheld),
        OValue::Object(entries) => entries
            .iter_mut()
            .for_each(|(_, value)| mark_withheld(value)),
        _ => {}
    }
}

/// Whether a target body lacks credentials the service did not return (§15.19 rule 2):
/// a credential path of the target rules 1–4, 6 and 7 holding `[REDACTED]` or a server
/// mask (four or more `*` only), or a `SECRET` variable override without a value.
pub fn withheld(document: &OValue) -> bool {
    let mut copy = document.clone();
    mark_withheld(&mut copy);
    let mut found = false;
    target(&mut copy, &mut |value: &str, _| found |= value == SENTINEL);
    let overrides = ["adapter_variable_overrides", "adapterVariableOverrides"]
        .iter()
        .filter_map(|key| document.get(key).and_then(OValue::as_array))
        .flatten();
    for entry in overrides {
        let secret = entry.get("type").and_then(OValue::as_str) == Some("SECRET");
        let valueless = match entry.get("value") {
            None | Some(OValue::Null) => true,
            Some(OValue::String(text)) => text.is_empty(),
            Some(_) => false,
        };
        found |= secret && valueless;
    }
    found
}

/// Whether a target body holds at least one credential the service did return (the
/// backup's credentials warning, §15.18): a value the target rules would redact and
/// treat as a credential (any registration but [`Reg::Never`]) that is not `[REDACTED]`
/// or a server mask, alone or after a `<scheme> ` prefix.
pub fn carries_credentials(document: &OValue) -> bool {
    let mut copy = document.clone();
    mark_withheld(&mut copy);
    let mut found = false;
    target(&mut copy, &mut |value: &str, reg| {
        let masked = |text: &str| text == SENTINEL || text == REDACTED || is_mask(text);
        found |=
            reg != Reg::Never && !masked(value) && !scheme_credential(value).is_some_and(masked);
    });
    found
}

/// Replace a non-empty string with [`REDACTED`], registering the value as `reg`.
fn replace(value: &mut OValue, reg: Reg, sink: &mut Sink<'_>) {
    if let OValue::String(text) = value
        && !text.is_empty()
        && text != REDACTED
    {
        sink(text, reg);
        *text = REDACTED.to_owned();
    }
}

/// Every string at any depth, except the values of the kept keys and the D45 rule for the
/// URL keys; each registered as `reg` refined by its keys ([`Reg::under`]).
fn all_strings(value: &mut OValue, keys: Keys<'_>, reg: Reg, sink: &mut Sink<'_>) {
    match value {
        OValue::String(_) => replace(value, reg, sink),
        OValue::Array(items) => {
            for item in items {
                all_strings(item, keys, reg, sink);
            }
        }
        OValue::Object(entries) => {
            for (key, value) in entries {
                if keys.kept.contains(&key.as_str()) {
                    continue;
                }
                if keys.urls.contains(&key.as_str()) {
                    url(value, sink);
                    continue;
                }
                all_strings(value, keys, reg.under(key), sink);
            }
        }
        OValue::Null | OValue::Bool(_) | OValue::Number(_) => {}
    }
}

/// The D45 rule: a URL's userinfo, query and fragment replaced (a non-URL with `@`, `?`
/// or `#` replaced whole). The URL itself never joins the secret set (its host and path
/// are not secret); its credentials do ([`url_credentials`]).
fn url(value: &mut OValue, sink: &mut Sink<'_>) {
    if let OValue::String(text) = value
        && let Some(redacted) = crate::tenant::config::redact_url(text)
    {
        sink(text, Reg::Never);
        url_credentials(text, sink);
        *text = redacted;
    }
}

/// Whether a query, form or cookie field name names a credential: rule 7's names, plus
/// the signature (`sig`, `…signature`) and `auth` parameters of signed and token URLs.
fn secret_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    secret_key(name) || lower == "sig" || lower == "auth" || lower.ends_with("signature")
}

/// The `name=value` fields of a query, fragment or form body whose name is a credential
/// ([`secret_param`]): the raw value and the decoded one, each [`Reg::Strong`].
fn param_credentials(text: &str, sink: &mut Sink<'_>) {
    for piece in text.split('&') {
        let Some((name, raw)) = piece.split_once('=') else {
            continue;
        };
        let name: String = url::form_urlencoded::parse(name.as_bytes())
            .map(|(key, _)| key.into_owned())
            .next()
            .unwrap_or_default();
        if raw.is_empty() || !secret_param(&name) {
            continue;
        }
        sink(raw, Reg::Strong);
        let decoded: String = url::form_urlencoded::parse(piece.as_bytes())
            .map(|(_, value)| value.into_owned())
            .next()
            .unwrap_or_default();
        if !decoded.is_empty() && decoded != raw {
            sink(&decoded, Reg::Strong);
        }
    }
}

/// The credentials of a URL (or of URL-like text such as a template): the userinfo's
/// password ([`Reg::Strong`]) and user name ([`Reg::Weak`]; some services take the key as
/// the user name), and the secret-named fields of the query and the fragment.
fn url_credentials(text: &str, sink: &mut Sink<'_>) {
    if let Some(start) = text.find("://").map(|index| index + 3) {
        let rest = &text[start..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        if let Some((userinfo, _)) = rest[..end].rsplit_once('@') {
            let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            let decode = |part: &str| -> String {
                url::form_urlencoded::parse(format!("x={part}").as_bytes())
                    .map(|(_, value)| value.into_owned())
                    .next()
                    .unwrap_or_default()
            };
            for (part, reg) in [(user, Reg::Weak), (password, Reg::Strong)] {
                if part.is_empty() {
                    continue;
                }
                sink(part, reg);
                let decoded = decode(part);
                if !decoded.is_empty() && decoded != part {
                    sink(&decoded, reg);
                }
            }
        }
    }
    let (before_fragment, fragment) = text.split_once('#').unwrap_or((text, ""));
    if let Some((_, query)) = before_fragment.split_once('?') {
        param_credentials(query, sink);
    }
    param_credentials(fragment, sink);
}

/// Splits a shell command line into words (POSIX quoting: `'…'` literal, `"…"` with
/// `\` escapes, `$'…'` with `\` escapes, a backslash outside quotes escaping the next
/// character, backslash-newline a continuation). An unterminated quote takes the rest.
fn shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '\\' => match chars.next() {
                Some('\n') | None => {}
                Some(next) => {
                    word.push(next);
                    in_word = true;
                }
            },
            '\'' => {
                in_word = true;
                for next in chars.by_ref() {
                    if next == '\'' {
                        break;
                    }
                    word.push(next);
                }
            }
            '$' if chars.peek() == Some(&'\'') => {
                chars.next();
                in_word = true;
                while let Some(next) = chars.next() {
                    match next {
                        '\'' => break,
                        '\\' => {
                            if let Some(escaped) = chars.next() {
                                word.push(escaped);
                            }
                        }
                        other => word.push(other),
                    }
                }
            }
            '"' => {
                in_word = true;
                while let Some(next) = chars.next() {
                    match next {
                        '"' => break,
                        '\\' => match chars.next() {
                            Some('\n') | None => {}
                            Some(escaped @ ('"' | '\\' | '$' | '`')) => word.push(escaped),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                        },
                        other => word.push(other),
                    }
                }
            }
            other => {
                word.push(other);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// The credentials of a `curl` command (§15.4 rule 3): the values of `-H`/`--header`
/// (and `--proxy-header`) headers with a rule-7 name, a `<scheme> <credential>` value
/// also on its own (the sink's rule); the password of `-u`/`--user`/`--proxy-user` and
/// the Basic credential it forms; `--oauth2-bearer`; the values of `-b`/`--cookie`
/// cookies ([`Reg::Weak`]); the secret-named fields of `-d`/`--data*`/`--json`/`-F`
/// bodies (rule 7 on a JSON body, [`secret_param`] on a form body); and the
/// [`url_credentials`] of every URL word. The command itself is never registered.
fn curl_credentials(command: &str, sink: &mut Sink<'_>) {
    const HEADER: [&str; 3] = ["-H", "--header", "--proxy-header"];
    const USER: [&str; 4] = ["-u", "--user", "-U", "--proxy-user"];
    const COOKIE: [&str; 2] = ["-b", "--cookie"];
    const BEARER: [&str; 1] = ["--oauth2-bearer"];
    const BODY: [&str; 9] = [
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-ascii",
        "--data-urlencode",
        "--json",
        "-F",
        "--form",
    ];
    const URL: [&str; 1] = ["--url"];
    let takes_value = |flag: &str| {
        [&HEADER[..], &USER, &COOKIE, &BEARER, &BODY, &URL]
            .iter()
            .any(|flags| flags.contains(&flag))
    };
    let words = shell_words(command);
    let mut index = 0;
    while index < words.len() {
        let word = words[index].as_str();
        index += 1;
        // `--flag=value`, `-Hvalue` or `--flag value`.
        let (flag, value) = if let Some((flag, value)) = word
            .split_once('=')
            .filter(|(flag, _)| flag.starts_with("--") && takes_value(flag))
        {
            (flag, Some(value.to_owned()))
        } else if word.len() > 2
            && word.is_char_boundary(2)
            && !word.starts_with("--")
            && takes_value(&word[..2])
        {
            (&word[..2], Some(word[2..].to_owned()))
        } else if takes_value(word) {
            let value = words.get(index).cloned();
            index += 1;
            (word, value)
        } else {
            if word.contains("://") {
                url_credentials(word, sink);
            }
            continue;
        };
        let Some(value) = value.filter(|value| !value.is_empty()) else {
            continue;
        };
        if HEADER.contains(&flag) {
            if let Some((name, header)) = value.split_once(':') {
                let header = header.trim();
                if secret_key(name.trim()) && !header.is_empty() {
                    sink(header, Reg::Strong);
                }
            }
        } else if USER.contains(&flag) {
            if let Some((_, password)) = value.split_once(':')
                && !password.is_empty()
            {
                sink(password, Reg::Strong);
                sink(
                    &crate::error::base64_standard(value.as_bytes()),
                    Reg::Strong,
                );
            }
        } else if COOKIE.contains(&flag) {
            for cookie in value.split(';') {
                if let Some((_, cookie)) = cookie.split_once('=') {
                    sink(cookie.trim(), Reg::Weak);
                }
            }
        } else if BEARER.contains(&flag) {
            sink(&value, Reg::Strong);
        } else if BODY.contains(&flag) {
            body_credentials(&value, sink);
        } else {
            url_credentials(&value, sink);
        }
    }
}

/// The credentials of a request body given to curl: rule 7 on a JSON document (the values
/// it would redact), else the secret-named fields of a form body.
fn body_credentials(body: &str, sink: &mut Sink<'_>) {
    if let Ok(mut document) = crate::json::parse(body)
        && matches!(document, OValue::Object(_) | OValue::Array(_))
    {
        catch_all(&mut document, sink);
        return;
    }
    param_credentials(body, sink);
}

/// Rule 7: a key whose value is a credential wherever it appears.
fn secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    if matches!(
        key.as_str(),
        "response_key" | "response_stop_key" | "oauth2_token_response_key"
    ) {
        return false;
    }
    ["key", "secret", "token", "password"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
        || ["authorization", "cookie", "credential", "passwd"]
            .iter()
            .any(|part| key.contains(part))
}

/// Rule 7 everywhere in `value`. Inside `variables[]` and `adapter_variable_overrides[]`
/// entries the `key` field is the variable's name (rule 6 covers its value).
fn catch_all(value: &mut OValue, sink: &mut Sink<'_>) {
    catch_all_in(value, false, sink);
}

fn catch_all_in(value: &mut OValue, variable_entry: bool, sink: &mut Sink<'_>) {
    match value {
        OValue::Array(items) => {
            for item in items {
                catch_all_in(item, false, sink);
            }
        }
        OValue::Object(entries) => {
            for (key, value) in entries.iter_mut() {
                if variable_entry && key == "key" {
                    continue;
                }
                if secret_key(key) {
                    if let OValue::String(_) = value {
                        replace(value, Reg::Strong, sink);
                        continue;
                    }
                    all_strings(value, Keys::NONE, Reg::Strong, sink);
                    continue;
                }
                if is_variables_key(key)
                    && let OValue::Array(items) = value
                {
                    for item in items {
                        catch_all_in(item, true, sink);
                    }
                    continue;
                }
                catch_all_in(value, false, sink);
            }
        }
        OValue::Null | OValue::Bool(_) | OValue::Number(_) | OValue::String(_) => {}
    }
}

fn is_variables_key(key: &str) -> bool {
    matches!(
        key,
        "variables" | "adapter_variable_overrides" | "adapterVariableOverrides"
    )
}

/// The value of `key` (either of its spellings) in an object.
fn field<'a>(value: &'a mut OValue, names: &[&str]) -> Vec<&'a mut OValue> {
    match value {
        OValue::Object(entries) => entries
            .iter_mut()
            .filter(|(key, _)| names.contains(&key.as_str()))
            .map(|(_, value)| value)
            .collect(),
        _ => Vec::new(),
    }
}

/// Rule 6: the `value` of every entry whose `type` is not `VAR`.
fn variables(value: &mut OValue, sink: &mut Sink<'_>) {
    let OValue::Array(items) = value else {
        return;
    };
    for item in items {
        let secret = item.get("type").and_then(OValue::as_str) != Some("VAR");
        if secret {
            for value in field(item, &["value"]) {
                replace(value, Reg::Strong, sink);
            }
        }
    }
}

/// The target rules 1–7.
fn target(document: &mut OValue, sink: &mut Sink<'_>) {
    // Rule 1.
    for auth in field(document, &["auth_config", "authConfig"]) {
        let keys = Keys {
            kept: &["basic_auth_location", "oauth2_token_response_key"],
            urls: &["oauth2_token_url"],
        };
        all_strings(auth, keys, Reg::Weak, sink);
    }
    for params in field(document, &["connection_params", "connectionParams"]) {
        connection_params(params, sink);
    }
    // Rule 6.
    for overrides in field(
        document,
        &["adapter_variable_overrides", "adapterVariableOverrides"],
    ) {
        variables(overrides, sink);
    }
    // Rule 7.
    catch_all(document, sink);
}

/// Rules 2–5 on a `connection_params` object.
fn connection_params(params: &mut OValue, sink: &mut Sink<'_>) {
    let OValue::Object(entries) = params else {
        return;
    };
    for (key, value) in entries.iter_mut() {
        match key.as_str() {
            // Rule 2: every header value but the content-negotiation ones.
            "request_headers" => {
                if let OValue::Object(headers) = value {
                    for (name, value) in headers.iter_mut() {
                        let kept = ["accept", "content-type", "user-agent"]
                            .iter()
                            .any(|allowed| name.eq_ignore_ascii_case(allowed));
                        if !kept {
                            all_strings(value, Keys::NONE, Reg::Weak.under(name), sink);
                        }
                    }
                }
            }
            // Rule 3: the whole command is redacted; only its credentials register. The
            // management 0.86.0 `audio_curl` (scm-sdk 0.2.3) is a curl template too (D327).
            "curl" | "audio_curl" => match value {
                OValue::String(command) => {
                    let command = command.clone();
                    replace(value, Reg::Never, sink);
                    curl_credentials(&command, sink);
                }
                other => all_strings(other, Keys::NONE, Reg::Never, sink),
            },
            // Rule 4; a Vertex AI identifier string directly under the config is redacted
            // first, without registering itself, and anything deeper by the walk. The walk
            // leaves it unregistered only because `replace` skips a value already
            // `[REDACTED]`, so the pre-pass must run first.
            "target_connection_config" => {
                if let OValue::Object(fields) = value {
                    for (name, field) in fields.iter_mut() {
                        if VERTEX_AI_IDS.iter().any(|(id, _)| id == name) {
                            identifier(field, sink);
                        }
                    }
                }
                let keys = Keys {
                    kept: &["model_name", "model_id", "region", "auth_type"],
                    urls: &["workspace_url"],
                };
                all_strings(value, keys, Reg::Weak, sink);
            }
            // Rule 5.
            name if name == "api_endpoint" || name.ends_with("_url") => url(value, sink),
            _ => {}
        }
    }
}

/// A Vertex AI identifier string (choice 12): redacted, the value itself never registered
/// (an endpoint, name or description holds it), but the credentials embedded in it are,
/// as anywhere else: a URL's ([`url_credentials`]) and the credential of a
/// `<scheme> <credential>` value (by the length rule). Any other value is left to the walk.
fn identifier(value: &mut OValue, sink: &mut Sink<'_>) {
    let OValue::String(text) = value else {
        return;
    };
    let text = text.clone();
    replace(value, Reg::Never, sink);
    url_credentials(&text, sink);
    if let Some(credential) = scheme_credential(&text) {
        sink(credential, Reg::Weak);
    }
}

/// The adapter rules: rule 6 on `variables[]`, rule 7 elsewhere.
fn adapter(document: &mut OValue, sink: &mut Sink<'_>) {
    for list in field(document, &["variables"]) {
        variables(list, sink);
    }
    catch_all(document, sink);
}

/// The error-log rules: `targetObject` as a target, `extraInfo` (and the rest) by rule 7.
fn error_log(document: &mut OValue, sink: &mut Sink<'_>) {
    for object in field(document, &["targetObject", "target_object"]) {
        target(object, sink);
    }
    catch_all(document, sink);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn withheld_credentials_are_found_by_the_target_rules() {
        let check = |text: &str| withheld(&parse(text).unwrap());
        assert!(!check(
            r#"{"name":"t","auth_config":{"auth_header":{"Authorization":"Bearer S1"}}}"#
        ));
        assert!(check(
            r#"{"name":"t","auth_config":{"auth_header":{"Authorization":"[REDACTED]"}}}"#
        ));
        assert!(check(
            r#"{"connection_params":{"request_headers":{"apikey":"********"}}}"#
        ));
        assert!(check(
            r#"{"connection_params":{"target_connection_config":{"api_key":"****"}}}"#
        ));
        assert!(check(r#"{"extra_info":{"token":"[REDACTED]"}}"#));
        assert!(!check(
            r#"{"description":"[REDACTED]","connection_params":{"api_endpoint":"[REDACTED]","request_headers":{"Accept":"****"}}}"#
        ));
        assert!(check(
            r#"{"adapter_variable_overrides":[{"key":"k","type":"SECRET"}]}"#
        ));
        assert!(check(
            r#"{"adapter_variable_overrides":[{"key":"k","value":null,"type":"SECRET"}]}"#
        ));
        assert!(check(
            r#"{"adapter_variable_overrides":[{"key":"k","value":"**********","type":"SECRET"}]}"#
        ));
        assert!(!check(
            r#"{"adapter_variable_overrides":[{"key":"k","value":"v","type":"SECRET"},{"key":"e","type":"VAR"}]}"#
        ));
    }

    /// The backup's credentials warning: a credential the service returned, never a mask,
    /// `[REDACTED]`, a masked `<scheme>` value or a non-credential field.
    #[test]
    fn returned_credentials_are_told_from_withheld_ones() {
        let check = |text: &str| carries_credentials(&parse(text).unwrap());
        assert!(check(
            r#"{"auth_config":{"auth_header":{"Authorization":"Bearer S1"}}}"#
        ));
        assert!(check(
            r#"{"adapter_variable_overrides":[{"key":"k","value":"v","type":"SECRET"}]}"#
        ));
        assert!(check(
            r#"{"connection_params":{"request_headers":{"apikey":"********","X-Key":"real"}}}"#
        ));
        assert!(!check(
            r#"{"name":"t","description":"no credentials","connection_params":{"api_endpoint":"https://x.invalid/v1","request_headers":{"Content-Type":"application/json"}}}"#
        ));
        assert!(!check(
            r#"{"auth_config":{"auth_header":{"Authorization":"Bearer ********"}},"connection_params":{"request_headers":{"apikey":"[REDACTED]"},"target_connection_config":{"api_key":"****"}}}"#
        ));
        assert!(!check(
            r#"{"adapter_variable_overrides":[{"key":"k","type":"SECRET"},{"key":"m","value":"*****","type":"SECRET"}]}"#
        ));
        assert!(!check(
            r#"{"auth_config":{"oauth2_token_url":"https://auth.invalid/t","client_id":"app"}}"#
        ));
    }

    /// The management 0.86.0 shapes (scm-sdk 0.2.3, DESIGN §15.24): `audio_curl` is a
    /// curl template (rule 3, D327: redacted whole, only its credentials register);
    /// `basic_username` and `basic_password` are `auth_config` strings (rule 1); every
    /// Vertex AI field is a `target_connection_config` string (rule 4), the identifiers
    /// redacted but never registered (choice 12: the endpoint and the target's own text
    /// hold them); `audio_request_json` is printed like `request_json` (rule 7 inside it).
    #[test]
    fn management_0_86_shapes_follow_the_target_rules() {
        let (text, secrets) = redacted(
            r#"{"name":"Vertex Realtime","connection_type":"VERTEX_AI","response_mode":"REALTIME",
               "auth_config":{"basic_username":"svc-user-0001","basic_password":"PW-SECRET-1"},
               "connection_params":{"api_endpoint":"wss://rt.invalid/ws",
                "target_connection_config":{"project_id":"example-project","location":"us-central1","engine_id":"12345","customer_sa_email":"sa@example.iam.invalid"},
                "multi_turn_config":{"type":"client_session"},
                "audio_request_json":{"audio":"{AUDIO}","api_key":"AK-SECRET-2"},
                "audio_curl":"curl -X POST wss://rt.invalid/ws -H 'Authorization: Bearer AUDIO-SECRET-3' -d '{\"audio\":\"{AUDIO}\"}'"}}"#,
            Shape::Target,
        );
        assert_eq!(
            text,
            concat!(
                r#"{"name":"Vertex Realtime","connection_type":"VERTEX_AI","response_mode":"REALTIME","#,
                r#""auth_config":{"basic_username":"[REDACTED]","basic_password":"[REDACTED]"},"#,
                r#""connection_params":{"api_endpoint":"wss://rt.invalid/ws","#,
                r#""target_connection_config":{"project_id":"[REDACTED]","location":"[REDACTED]","engine_id":"[REDACTED]","customer_sa_email":"[REDACTED]"},"#,
                r#""multi_turn_config":{"type":"client_session"},"#,
                r#""audio_request_json":{"audio":"{AUDIO}","api_key":"[REDACTED]"},"#,
                r#""audio_curl":"[REDACTED]"}}"#,
            )
        );
        for secret in [
            "svc-user-0001",
            "PW-SECRET-1",
            "AK-SECRET-2",
            "AUDIO-SECRET-3",
            "Bearer AUDIO-SECRET-3",
            "sa@example.iam.invalid",
        ] {
            assert!(secrets.taints(secret), "{secret} is not registered");
        }
        // The template itself, its URL and body are never registered, nor the Vertex AI
        // identifiers, so the endpoint that holds them prints.
        for printable in [
            "curl -X POST",
            "rt.invalid",
            "{AUDIO}",
            "Vertex Realtime",
            "example-project",
            "us-central1",
            "https://us-central1-aiplatform.googleapis.com/v1/projects/example-project/locations/us-central1/reasoningEngines/12345:streamQuery",
        ] {
            assert!(!secrets.taints(printable), "{printable} is withheld");
        }
        // Only a string directly under the config with the exact name: the same names
        // elsewhere, deeper or in another case keep the length rule.
        let (_, secrets) = redacted(
            r#"{"auth_config":{"location":"auth-location-1"},
               "connection_params":{"request_headers":{"Location":"header-location-1"},
                "target_connection_config":{"Project_Id":"cased-project-1","nested":{"project_id":"nested-project-1"}}}}"#,
            Shape::Target,
        );
        for secret in [
            "auth-location-1",
            "header-location-1",
            "cased-project-1",
            "nested-project-1",
        ] {
            assert!(secrets.taints(secret), "{secret} is not registered");
        }
        // The accepted over-withholding (choice 12): an account address that holds the
        // project registers, so the bare project id, a fragment of it, is withheld, while
        // the endpoint that holds the project is not.
        let (_, secrets) = redacted(
            r#"{"connection_params":{"api_endpoint":"https://us-central1-aiplatform.googleapis.com/v1/projects/example-project/locations/us-central1/reasoningEngines/12345:streamQuery",
               "target_connection_config":{"project_id":"example-project","location":"us-central1","engine_id":"12345","customer_sa_email":"service@example-project.iam.invalid"}}}"#,
            Shape::Target,
        );
        assert!(secrets.taints("example-project"));
        assert!(!secrets.taints("us-central1"));
        assert!(!secrets.taints(
            "https://us-central1-aiplatform.googleapis.com/v1/projects/example-project/locations/us-central1/reasoningEngines/12345:streamQuery"
        ));
        // Restore's withheld test and the backup warning see the new paths.
        for masked in [
            r#"{"connection_params":{"audio_curl":"[REDACTED]"}}"#,
            r#"{"connection_params":{"audio_curl":"****"}}"#,
            r#"{"auth_config":{"basic_username":"u","basic_password":"********"}}"#,
            r#"{"connection_params":{"target_connection_config":{"project_id":"p","location":"l","engine_id":"1","customer_sa_email":"****"}}}"#,
        ] {
            assert!(withheld(&parse(masked).unwrap()), "{masked}");
        }
        assert!(carries_credentials(
            &parse(r#"{"connection_params":{"audio_curl":"curl -H 'X-Api-Key: K-SECRET-4' https://x.invalid"}}"#).unwrap()
        ));
        assert!(carries_credentials(
            &parse(r#"{"auth_config":{"basic_username":"u","basic_password":"p-secret"}}"#)
                .unwrap()
        ));
        assert!(!carries_credentials(
            &parse(r#"{"connection_params":{"audio_curl":"curl https://x.invalid","audio_request_json":{"audio":"{AUDIO}"}}}"#).unwrap()
        ));
        // The identifiers are no credential for the warning; the account e-mail is.
        let vertex = |email: &str| {
            parse(&format!(
                r#"{{"connection_params":{{"target_connection_config":{{"project_id":"example-project","location":"us-central1","engine_id":"12345","customer_sa_email":"{email}"}}}}}}"#
            ))
            .unwrap()
        };
        assert!(!carries_credentials(&vertex("********")));
        assert!(carries_credentials(&vertex("sa@example.iam.invalid")));
    }

    /// Choice 12 is narrow: an identifier string directly under the config does not
    /// register itself, but the credentials embedded in it do (a URL's userinfo, the
    /// credential after a scheme), and a non-string identifier or an identifier name
    /// deeper in the config keeps the walk's registration.
    #[test]
    fn an_identifier_exempts_only_its_own_plain_string() {
        for (config, secret) in [
            (
                r#"{"location":"https://u:PASSINLOC99@h.invalid/x"}"#,
                "PASSINLOC99",
            ),
            (r#"{"engine_id":"Bearer ENGINE-TOKEN-1"}"#, "ENGINE-TOKEN-1"),
            (
                r#"{"location":{"auth":"LOCATION-AUTH-1"}}"#,
                "LOCATION-AUTH-1",
            ),
            (
                r#"{"token_cache_json":{"location":"CACHED-LOCATION-1"}}"#,
                "CACHED-LOCATION-1",
            ),
        ] {
            let text =
                format!(r#"{{"connection_params":{{"target_connection_config":{config}}}}}"#);
            let (redacted, secrets) = redacted(&text, Shape::Target);
            assert!(!redacted.contains(secret), "{redacted}");
            assert!(secrets.taints(secret), "{secret} is not registered");
            assert!(carries_credentials(&parse(&text).unwrap()), "{text}");
        }
        // The identifier strings themselves stay unregistered: only what they embed joins.
        let (_, secrets) = redacted(
            r#"{"connection_params":{"target_connection_config":{"location":"https://u:PASSINLOC99@h.invalid/x","engine_id":"Bearer ENGINE-TOKEN-1"}}}"#,
            Shape::Target,
        );
        let forms = secrets.snapshot();
        for whole in ["https://u:PASSINLOC99@h.invalid/x", "Bearer ENGINE-TOKEN-1"] {
            assert!(
                !forms.iter().any(|form| form == whole),
                "{whole}: {forms:?}"
            );
        }
        assert!(!secrets.taints("h.invalid/x"));
    }

    /// A secret-named key registers its value under a key whose own value does not
    /// (a `scope`, a non-string `curl`) or under an identifier name holding an object:
    /// rule 7 skips what rule 1 or 4 already replaced, so the registration has to happen
    /// there.
    #[test]
    fn a_credential_nested_in_an_unregistered_value_registers() {
        for (text, secret) in [
            (
                r#"{"connection_params":{"target_connection_config":{"location":{"api_key":"PROBE-NESTED-KEY-88"}}}}"#,
                "PROBE-NESTED-KEY-88",
            ),
            (
                r#"{"auth_config":{"scope":{"token":"SCOPE-NESTED-TOKEN-89"}}}"#,
                "SCOPE-NESTED-TOKEN-89",
            ),
            (
                r#"{"authConfig":{"oauth2_body_params":{"Audience":{"client_secret":"s9"}}}}"#,
                "s9",
            ),
            (
                r#"{"connection_params":{"curl":{"headers":{"X-Api-Key":"CURL-OBJECT-KEY-90"}}}}"#,
                "CURL-OBJECT-KEY-90",
            ),
        ] {
            let (redacted, secrets) = redacted(text, Shape::Target);
            assert!(!redacted.contains(secret), "{redacted}");
            assert!(secrets.taints(secret), "{secret} is not registered");
            assert!(carries_credentials(&parse(text).unwrap()), "{text}");
        }
        // The non-credential values beside them still do not register under `scope`; an
        // identifier name holding an object is no identifier string, so the walk's
        // length rule registers what is inside it (choice 12).
        let (_, secrets) = redacted(
            r#"{"auth_config":{"scope":{"name":"read-all-scope"}},
               "connection_params":{"target_connection_config":{"location":{"zone":"us-central1-a"}}}}"#,
            Shape::Target,
        );
        assert!(!secrets.taints("read-all-scope"));
        assert!(secrets.taints("us-central1-a"));
    }

    fn redacted(text: &str, shape: Shape) -> (String, SecretSet) {
        let secrets = SecretSet::default();
        let mut value = parse(text).unwrap();
        redact(&mut value, shape, &secrets);
        (crate::json::to_compact(&value).unwrap(), secrets)
    }

    #[test]
    fn target_rules_cover_every_credential_path() {
        let (text, secrets) = redacted(
            r#"{"name":"t","auth_config":{"auth_header":{"Authorization":"Bearer S1"},
                "basic_auth_location":"HEADER","oauth2_token_response_key":"access_token",
                "oauth2_token_url":"https://auth.invalid/t?client_secret=S2","oauth2_expiry_minutes":60},
               "connection_params":{"api_endpoint":"https://x.invalid/v1?key=S3",
                "request_headers":{"Content-Type":"application/json","ACCEPT":"*/*","apikey":"S4","n":{"deep":"S5-DEEP-VALUE"}},
                "curl":"curl -H 'X-Api-Key: S6'","response_key":"choices.0","base_url":"https://u:S7@h.invalid/p",
                "target_connection_config":{"api_key":"S8","model_name":"m","region":"r","workspace_url":"https://w.invalid/?t=S9","secret":"S10"},
                "request_json":{"messages":[]}},
               "adapter_variable_overrides":[{"key":"endpoint","value":"http://a","type":"VAR"},{"key":"api_token","value":"S11","type":"SECRET"},{"key":"x","value":null,"type":"SECRET"}],
               "extra_info":{"note":"plain","token":"S12","key":"S13","count":3},
               "description":"","password":""}"#,
            Shape::Target,
        );
        assert_eq!(
            text,
            concat!(
                r#"{"name":"t","auth_config":{"auth_header":{"Authorization":"[REDACTED]"},"#,
                r#""basic_auth_location":"HEADER","oauth2_token_response_key":"access_token","#,
                r#""oauth2_token_url":"https://auth.invalid/t?[REDACTED]","oauth2_expiry_minutes":60},"#,
                r#""connection_params":{"api_endpoint":"https://x.invalid/v1?[REDACTED]","#,
                r#""request_headers":{"Content-Type":"application/json","ACCEPT":"*/*","apikey":"[REDACTED]","n":{"deep":"[REDACTED]"}},"#,
                r#""curl":"[REDACTED]","response_key":"choices.0","base_url":"https://[REDACTED]@h.invalid/p","#,
                r#""target_connection_config":{"api_key":"[REDACTED]","model_name":"m","region":"r","workspace_url":"https://w.invalid/?[REDACTED]","secret":"[REDACTED]"},"#,
                r#""request_json":{"messages":[]}},"#,
                r#""adapter_variable_overrides":[{"key":"endpoint","value":"http://a","type":"VAR"},{"key":"api_token","value":"[REDACTED]","type":"SECRET"},{"key":"x","value":null,"type":"SECRET"}],"#,
                r#""extra_info":{"note":"plain","token":"[REDACTED]","key":"[REDACTED]","count":3},"#,
                r#""description":"","password":""}"#
            )
        );
        for value in [
            "Bearer S1",
            "S3",
            "S4",
            "S5-DEEP-VALUE",
            "S6",
            "S7",
            "S8",
            "S10",
            "S11",
            "S12",
        ] {
            assert!(secrets.taints(value), "{value} joined the secret set");
        }
        assert!(secrets.taints("https://x.invalid/v1?key=S3"));
        assert!(!secrets.taints("choices.0"));
        // Neither the curl command nor a URL is registered as a whole.
        for text in ["curl -H", "X-Api-Key", "x.invalid/v1", "h.invalid"] {
            assert!(!secrets.taints(text), "{text} is not withheld");
        }
    }

    #[test]
    fn short_and_non_credential_values_are_redacted_but_not_registered() {
        let (text, secrets) = redacted(
            r#"{"name":"prod chatbot v1","description":"Uses client_credentials grant",
               "auth_config":{"client_id":"cid","oauth2_body_params":{"grant_type":"client_credentials","scope":"read:all"},
                 "client_secret":"s3","username":"svc-account-7"},
               "connection_params":{"request_headers":{"X-Env":"prod","X-Api-Version":"1","X-Api-Key":"k1","X-Trace":"trace-long-value"}}}"#,
            Shape::Target,
        );
        assert_eq!(
            text,
            concat!(
                r#"{"name":"prod chatbot v1","description":"Uses client_credentials grant","#,
                r#""auth_config":{"client_id":"[REDACTED]","oauth2_body_params":{"grant_type":"[REDACTED]","scope":"[REDACTED]"},"#,
                r#""client_secret":"[REDACTED]","username":"[REDACTED]"},"#,
                r#""connection_params":{"request_headers":{"X-Env":"[REDACTED]","X-Api-Version":"[REDACTED]","X-Api-Key":"[REDACTED]","X-Trace":"[REDACTED]"}}}"#
            ),
            "every credential-path value is still redacted"
        );
        for kept in [
            "prod chatbot v1",
            "Uses client_credentials grant",
            "Acid target",
            "read:all",
        ] {
            assert!(!secrets.taints(kept), "{kept} is not withheld");
        }
        // Known credentials join whatever their length; long path values join too.
        for value in ["s3", "k1", "svc-account-7", "trace-long-value"] {
            assert!(secrets.taints(value), "{value} joined the secret set");
        }
        let (_, secrets) = redacted(
            r#"{"variables":[{"key":"pin","value":"42","type":"SECRET"}]}"#,
            Shape::Adapter,
        );
        assert!(secrets.taints("42"), "a SECRET value always joins");
    }

    #[test]
    fn normalised_targets_and_error_logs_use_the_camel_case_keys() {
        let (text, _) = redacted(
            r#"{"authConfig":{"auth_header":{"Authorization":"Bearer S1"}},"connectionParams":{"curl":"c S2"}}"#,
            Shape::Target,
        );
        assert_eq!(
            text,
            r#"{"authConfig":{"auth_header":{"Authorization":"[REDACTED]"}},"connectionParams":{"curl":"[REDACTED]"}}"#
        );
        let (text, _) = redacted(
            r#"{"errorMessage":"m","targetObject":{"connection_params":{"request_headers":{"apikey":"S1"}}},"extraInfo":{"api_key":"S2","x":"y"}}"#,
            Shape::ErrorLog,
        );
        assert_eq!(
            text,
            r#"{"errorMessage":"m","targetObject":{"connection_params":{"request_headers":{"apikey":"[REDACTED]"}}},"extraInfo":{"api_key":"[REDACTED]","x":"y"}}"#
        );
    }

    #[test]
    fn adapter_secret_values_are_always_redacted() {
        let (text, secrets) = redacted(
            r#"{"name":"a","scriptB64":"cHJpbnQ=","variables":[{"key":"endpoint","value":"http://e","type":"VAR","isRedacted":false},{"key":"api_token","value":"**********","type":"SECRET","isRedacted":true},{"key":"raw","value":"S1","type":"SECRET"},{"key":"gone","value":null,"type":"SECRET"}]}"#,
            Shape::Adapter,
        );
        assert_eq!(
            text,
            r#"{"name":"a","scriptB64":"cHJpbnQ=","variables":[{"key":"endpoint","value":"http://e","type":"VAR","isRedacted":false},{"key":"api_token","value":"[REDACTED]","type":"SECRET","isRedacted":true},{"key":"raw","value":"[REDACTED]","type":"SECRET"},{"key":"gone","value":null,"type":"SECRET"}]}"#
        );
        assert!(secrets.taints("S1"));
    }

    #[test]
    fn scheme_values_register_the_bare_credential() {
        let (_, secrets) = redacted(
            r#"{"auth_config":{"auth_header":{"Authorization":"Bearer S1-TOKEN"}}}"#,
            Shape::Target,
        );
        assert!(secrets.taints("echo S1-TOKEN"));
        assert_eq!(scheme_credential("Basic dXNlcjpw"), Some("dXNlcjpw"));
        assert_eq!(scheme_credential("no-space"), None);
        assert_eq!(
            scheme_credential("Bearer x"),
            None,
            "too short to be a credential"
        );
        assert_eq!(scheme_credential("two words here"), Some("words here"));
    }

    /// A curl command is redacted whole but only its credentials register: the target's
    /// name, description, model and endpoint inside it stay printable (§15.4 rule 3).
    #[test]
    fn a_curl_command_registers_only_its_credentials() {
        let curl = concat!(
            r#"curl -sS -X POST 'https://chat.example.invalid/v1/chat/completions?api-version=2024-06-01&api_key=QK-SECRET-1' \"#,
            "\n",
            r#"  -H 'Content-Type: application/json' -H "Authorization: Bearer TOK-SECRET-2" \"#,
            "\n",
            r#"  --header=X-Api-Key:K3-SECRET -H 'X-Model: gpt-4o-mini' -u svc-user:PW-SECRET-4 \"#,
            "\n",
            r#"  -b 'session=COOKIE-SECRET-5; consent=1' --oauth2-bearer OB-SECRET-6 \"#,
            "\n",
            r#"  -d '{"model":"gpt-4o-mini","client_secret":"BODY-SECRET-7","messages":[{"role":"system","content":"You are Rest Target One, the fixture REST target"}]}'"#,
        );
        let document = format!(
            r#"{{"name":"Rest Target One","connection_params":{{"curl":{}}}}}"#,
            serde_json::to_string(curl).unwrap()
        );
        let (text, secrets) = redacted(&document, Shape::Target);
        assert_eq!(
            text,
            r#"{"name":"Rest Target One","connection_params":{"curl":"[REDACTED]"}}"#
        );
        for secret in [
            "Bearer TOK-SECRET-2",
            "TOK-SECRET-2",
            "QK-SECRET-1",
            "K3-SECRET",
            "PW-SECRET-4",
            "COOKIE-SECRET-5",
            "OB-SECRET-6",
            "BODY-SECRET-7",
        ] {
            assert!(secrets.taints(&format!("echo {secret}")), "{secret}");
        }
        assert!(
            secrets.taints(&crate::error::base64_standard(b"svc-user:PW-SECRET-4")),
            "the Basic credential -u forms"
        );
        for printable in [
            "Rest Target One",
            "the fixture REST target",
            "gpt-4o-mini",
            "chat.example.invalid",
            "completions",
            "2024-06-01",
            "svc-user",
            "application/json",
            "curl -sS",
            "1",
        ] {
            assert!(!secrets.taints(printable), "{printable} is not withheld");
        }
        // Withheld detection (restore) still sees a redacted curl.
        assert!(withheld(
            &parse(r#"{"connection_params":{"curl":"[REDACTED]"}}"#).unwrap()
        ));
    }

    #[test]
    fn urls_register_their_credentials_not_their_host_or_path() {
        let (text, secrets) = redacted(
            r#"{"name":"gpt-4o","connection_params":{"api_endpoint":"https://contoso.openai.invalid/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01&sig=SIG%2BSECRET#access_token=FRAG-SECRET",
               "base_url":"https://apikey-as-user-0001:PASS-SECRET@h.invalid/p"}}"#,
            Shape::Target,
        );
        assert_eq!(
            text,
            r#"{"name":"gpt-4o","connection_params":{"api_endpoint":"https://contoso.openai.invalid/openai/deployments/gpt-4o/chat/completions?[REDACTED]#[REDACTED]","base_url":"https://[REDACTED]@h.invalid/p"}}"#
        );
        for secret in [
            "SIG%2BSECRET",
            "SIG+SECRET",
            "FRAG-SECRET",
            "PASS-SECRET",
            "apikey-as-user-0001",
        ] {
            assert!(secrets.taints(&format!("x {secret} y")), "{secret}");
        }
        for printable in [
            "gpt-4o",
            "contoso",
            "deployments",
            "2024-06-01",
            "h.invalid",
        ] {
            assert!(!secrets.taints(printable), "{printable} is not withheld");
        }
    }

    #[test]
    fn shell_words_follow_posix_quoting() {
        assert_eq!(
            shell_words("curl -H 'A: b c' \"d\\\"e\" f\\ g \\\n h $'i\\'j'"),
            ["curl", "-H", "A: b c", "d\"e", "f g", "h", "i'j"]
        );
        assert_eq!(shell_words("a 'unterminated"), ["a", "unterminated"]);
    }

    #[test]
    fn the_catch_all_rule_names() {
        for key in [
            "api_key",
            "x-api-key",
            "ApiKey",
            "client_secret",
            "access_token",
            "Password",
            "Authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "credentials",
            "passwd_file",
            "key",
        ] {
            assert!(secret_key(key), "{key}");
        }
        for key in [
            "response_key",
            "response_stop_key",
            "oauth2_token_response_key",
            "name",
            "keyboard",
            "tokens_used",
            "model_name",
        ] {
            assert!(!secret_key(key), "{key}");
        }
    }
}
