//! `--debug` API logs in a sandbox (DESIGN §2.9, §10): where they are, reading them,
//! and the leak check every test applies to them.
//!
//! The runner leak-checks every log file after every run against the sandbox's secret
//! forms (see [`crate::Running::wait`]). [`assert_logs_clean`] adds what only the
//! fixture server knows: every `x-payload-hash` it received and every URL query.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::sandbox::{Sandbox, SecretForm};
use crate::server::FixtureServer;

/// `XDG_STATE_HOME` for `--debug` tests: `<sandbox>/tmp/xdg` (the runner allows writes
/// under `tmp/`).
pub fn xdg_state_home(sandbox: &Sandbox) -> PathBuf {
    sandbox.tmp().join("xdg")
}

/// The Rust log directory under [`xdg_state_home`].
pub fn log_dir(sandbox: &Sandbox) -> PathBuf {
    xdg_state_home(sandbox).join("airs-cli/debug")
}

/// The Rust log directory when `XDG_STATE_HOME` is unset (`<home>/.local/state/...`).
pub fn default_log_dir(sandbox: &Sandbox) -> PathBuf {
    sandbox.home().join(".local/state/airs-cli/debug")
}

/// Whether `name` is a debug log name (`debug-api-<13 digits>-<8 hex>.jsonl`).
pub fn is_log_name(name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix("debug-api-")
        .and_then(|rest| rest.strip_suffix(".jsonl"))
    else {
        return false;
    };
    let Some((stamp, hex)) = rest.split_once('-') else {
        return false;
    };
    stamp.len() == 13
        && stamp.bytes().all(|b| b.is_ascii_digit())
        && hex.len() == 8
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Every log file (by name) directly in `dir`, sorted; empty when `dir` is missing.
pub fn log_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_name().to_str().is_some_and(is_log_name))
                .map(|entry| entry.path())
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// The records of one log file, one JSON value per line.
///
/// # Panics
///
/// When a line is not JSON (a partial or corrupt record).
pub fn records(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "{}: the last record is not a whole line",
        path.display()
    );
    text.lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("{}: a record is not JSON ({err})", path.display()))
        })
        .collect()
}

/// The single log in [`log_dir`] and its records.
///
/// # Panics
///
/// Unless exactly one log exists there.
pub fn only_log(sandbox: &Sandbox) -> (PathBuf, Vec<Value>) {
    let files = log_files(&log_dir(sandbox));
    assert_eq!(files.len(), 1, "expected exactly one debug log: {files:?}");
    let records = records(&files[0]);
    (files[0].clone(), records)
}

/// The directories a run's logs can be in: the Rust state directory under the child's
/// `XDG_STATE_HOME` (when absolute) or its default under the sandbox home, and the
/// working directory, where the TypeScript CLI writes its log.
pub(crate) fn candidate_dirs(sandbox: &Sandbox, xdg: Option<&str>) -> Vec<PathBuf> {
    let mut dirs = vec![default_log_dir(sandbox), sandbox.cwd()];
    if let Some(xdg) = xdg.filter(|xdg| Path::new(xdg).is_absolute()) {
        dirs.push(Path::new(xdg).join("airs-cli/debug"));
    }
    dirs
}

/// Panics, naming the form and the file (never the value), when a log file in `dirs`
/// contains one of `forms`, ignoring ASCII case (header names are written lowercased,
/// so a secret echoed as a name appears case-folded).
pub(crate) fn check_forms(dirs: &[PathBuf], forms: &[SecretForm], context: &str) {
    for dir in dirs {
        for file in log_files(dir) {
            let bytes = std::fs::read(&file).unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            for form in forms {
                assert!(
                    !text.contains(&form.value.to_ascii_lowercase()),
                    "{context}: {} appeared in the debug log {}",
                    form.label,
                    file.display()
                );
            }
        }
    }
}

/// The full leak check for the logs in `dirs`: every sandbox secret form (raw, trimmed,
/// URL-encoded and base64 forms, the Basic pairs, the `mock-token-` lease prefix), every
/// `x-payload-hash` and `authorization`/`x-pan-token` value and every raw URL query the
/// server received, plus `extra` (prompt and response text, for example).
///
/// # Panics
///
/// On any match, naming what leaked and where (never the value).
pub fn assert_logs_clean(
    sandbox: &Sandbox,
    server: &FixtureServer,
    dirs: &[PathBuf],
    extra: &[&str],
) {
    let mut forms = sandbox.secret_forms();
    for request in server.requests() {
        for name in ["x-payload-hash", "x-pan-token", "authorization"] {
            if let Some(value) = request.header(name).filter(|value| !value.is_empty()) {
                forms.push(SecretForm {
                    label: format!("a received {name} value"),
                    value: value.to_owned(),
                });
            }
        }
        if let Some(query) = request.raw_query.as_ref().filter(|query| !query.is_empty()) {
            forms.push(SecretForm {
                label: "a received URL query".into(),
                value: format!("?{query}"),
            });
            forms.push(SecretForm {
                label: "a received URL query".into(),
                value: query.clone(),
            });
        }
    }
    for value in extra.iter().filter(|value| !value.is_empty()) {
        forms.push(SecretForm {
            label: "test-supplied text".into(),
            value: (*value).to_owned(),
        });
    }
    check_forms(dirs, &forms, "debug log leak check");
    for dir in dirs {
        for file in log_files(dir) {
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            for word in ["\"body\"", "Bearer ", "Basic "] {
                assert!(
                    !text.contains(word),
                    "{word} appeared in the debug log {}",
                    file.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn leaks(sandbox: &Sandbox, server: &FixtureServer, line: &str, extra: &[&str]) -> bool {
        let dir = log_dir(sandbox);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("debug-api-1000000000000-0000000a.jsonl");
        std::fs::write(&file, format!("{line}\n")).unwrap();
        let caught = catch_unwind(AssertUnwindSafe(|| {
            assert_logs_clean(sandbox, server, std::slice::from_ref(&dir), extra);
        }))
        .is_err();
        std::fs::remove_file(&file).unwrap();
        caught
    }

    #[test]
    fn log_names_and_candidate_dirs() {
        assert!(is_log_name("debug-api-1792062224500-0a1b2c3d.jsonl"));
        assert!(!is_log_name("debug-api-1792062224500-0A1B2C3D.jsonl"));
        assert!(!is_log_name("debug-api-1-0a1b2c3d.jsonl"));
        assert!(!is_log_name("notes.txt"));
        let sandbox = Sandbox::new();
        let dirs = candidate_dirs(&sandbox, Some("/abs/state"));
        assert!(dirs.contains(&PathBuf::from("/abs/state/airs-cli/debug")));
        assert!(dirs.contains(&sandbox.cwd()));
        assert!(dirs.contains(&default_log_dir(&sandbox)));
        assert_eq!(candidate_dirs(&sandbox, Some("relative")).len(), 2);
    }

    /// The leak check catches every kind of forbidden text and passes a clean record.
    #[test]
    fn leak_check_catches_secrets_queries_headers_bodies_and_extras() {
        let server = FixtureServer::start();
        let sandbox = Sandbox::new();
        sandbox.single_tenant(&server, "prod", "100");
        let clean = r#"{"timestamp":"t","operation":"op","request":{"method":"GET","url":"http://127.0.0.1:1/x","headers":{"authorization":"***"}}}"#;
        assert!(!leaks(&sandbox, &server, clean, &[]));
        assert!(
            leaks(&sandbox, &server, "FAKE-SECRET-100", &[]),
            "a config secret"
        );
        assert!(
            leaks(&sandbox, &server, r#"{"fake-secret-100":"***"}"#, &[]),
            "a config secret, case-folded"
        );
        assert!(leaks(&sandbox, &server, "x mock-token-3 y", &[]), "a lease");
        assert!(
            leaks(&sandbox, &server, r#"{"body":{}}"#, &[]),
            "a body key"
        );
        assert!(
            leaks(&sandbox, &server, "Bearer abc", &[]),
            "a bearer scheme"
        );
        assert!(
            leaks(&sandbox, &server, "my prompt", &["my prompt"]),
            "an extra"
        );
        // What the server received: a query and an x-payload-hash value.
        use std::io::{Read, Write};
        let mut client = std::net::TcpStream::connect(server.addr()).unwrap();
        client
            .write_all(
                b"GET /aisec/v1/mgmt/profiles/tsg/100?offset=7&limit=9 HTTP/1.1\r\nhost: 127.0.0.1\r\nx-payload-hash: hash-value-123\r\nconnection: close\r\n\r\n",
            )
            .unwrap();
        let mut answer = Vec::new();
        let _ = client.read_to_end(&mut answer);
        assert_eq!(server.requests().len(), 1);
        assert!(leaks(&sandbox, &server, "offset=7&limit=9", &[]), "a query");
        assert!(
            leaks(&sandbox, &server, "hash-value-123", &[]),
            "a payload hash"
        );
    }
}
