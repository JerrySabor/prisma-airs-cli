//! The M6c live model-security reads and the Rust-only `pypi-auth` check (DESIGN §10,
//! "M6c Model Security", Reads).
//!
//! [`run_live_modelsec_reads`] runs only when `tests/live.rs` passes the read gate
//! (`AIRS_RS_LIVE=1` and `AIRS_E2E_TENANT`), or against the loopback fixture server
//! through [`super::LiveTarget::loopback`]. It is its own run (run id, private store,
//! fingerprints, leak checks, 90 s per CLI run) and read-only on both CLIs; the
//! TypeScript CLI is sandboxed as in every live run.
//!
//! The first step is the Rust `model-security groups list --limit 1 --output json`: an
//! HTTP 401, 403 or 404 there means the tenant has no model-security access, the summary
//! notes `model-security unavailable` and nothing else runs (not a mismatch). The JSON
//! documents are compared after the tolerated rows are applied (D180: a key TypeScript
//! invents as `''`, `0`, `[]` or `{}` may be absent on the Rust side, and a `null` count
//! may be TypeScript's `0`; D191: the TypeScript `modelUri` withheld first; D192: the Rust
//! `customRuleUuid`/`customRule` dropped). The class-B reads are compared pretty, byte for
//! byte after the banner and D52.
//!
//! `pypi-auth` runs on the Rust side only (TypeScript prints the credential, D194;
//! [`super::Session`] refuses a TypeScript `pypi-auth` and any `install`): json, pretty
//! and table runs, each with `--debug` and its own `--url-file` (each call may mint a new
//! token), then a pretty run without one. Each 0600 file is read in memory only and
//! removed (also on failure and panic); every run's output and the debug log are checked
//! against the credential forms of every saved URL, for any userinfo but `[withheld]@`,
//! and for exactly the withheld form of the run's own URL; the forms also join the
//! summary check. The summary records only whether the credential was withheld and the
//! formats checked.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Exec, LiveAbort, LivePlan, LiveReport, LiveRow, RunPlace, Session};
use crate::compare::json_semantic_eq;
use crate::sandbox::SecretForm;

/// The banner of every model-security pretty layout.
pub const BANNER: &str = "\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n";

/// What airs-cli-rs prints for a withheld part.
const WITHHELD: &str = "[withheld]";

/// The keys airs-cli-rs adds to a rule instance (D192).
const RUST_ONLY_KEYS: [&str; 2] = ["customRuleUuid", "customRule"];

/// The withheld form of a model URI as airs-cli-rs prints it (D191): userinfo, query and
/// fragment replaced by `[withheld]` when the value parses as a URL with a host.
pub fn withheld_uri(text: &str) -> String {
    let Ok(url) = url::Url::parse(text) else {
        return text.to_owned();
    };
    if !url.has_host() {
        return text.to_owned();
    }
    let userinfo = !url.username().is_empty() || url.password().is_some();
    if !userinfo && url.query().is_none() && url.fragment().is_none() {
        return text.to_owned();
    }
    let mut out = format!("{}://", url.scheme());
    if userinfo {
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
    out
}

/// Whether `value` is one TypeScript invents for a field the server did not send (D180).
fn invented(value: &Value) -> bool {
    match value {
        Value::String(text) => text.is_empty(),
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

/// The Rust `--output json` document equals the TypeScript one after the tolerated rows
/// (D180, D191, D192; see the module docs).
pub fn ms_json_equal(rust: &Value, ts: &Value) -> bool {
    match (rust, ts) {
        (Value::Object(r), Value::Object(t)) => {
            let keys: std::collections::BTreeSet<&String> = r.keys().chain(t.keys()).collect();
            keys.into_iter().all(|key| {
                if RUST_ONLY_KEYS.contains(&key.as_str()) {
                    return true;
                }
                match (r.get(key), t.get(key)) {
                    (Some(Value::String(rv)), Some(Value::String(tv))) if key == "modelUri" => {
                        *rv == withheld_uri(tv)
                    }
                    (None, Some(tv)) => invented(tv),
                    (Some(Value::Null), Some(Value::Number(n))) => n.as_f64() == Some(0.0),
                    (Some(rv), Some(tv)) => ms_json_equal(rv, tv),
                    (Some(_), None) | (None, None) => false,
                }
            })
        }
        (Value::Array(r), Value::Array(t)) => {
            r.len() == t.len() && r.iter().zip(t).all(|(rv, tv)| ms_json_equal(rv, tv))
        }
        _ => json_semantic_eq(rust, ts),
    }
}

/// A pretty layout without the banner and with D52 applied to the TypeScript side
/// (control characters other than LF shown as U+FFFD).
pub fn pretty_body(text: &str, ts: bool) -> String {
    let text = text.strip_prefix(BANNER).unwrap_or(text);
    if !ts {
        return text.to_owned();
    }
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\n' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
}

/// The `uuid` of the first row of a listing.
pub fn first_uuid(listing: &Value) -> Option<String> {
    listing
        .as_array()?
        .first()?
        .get("uuid")?
        .as_str()
        .map(str::to_owned)
}

/// The credential forms of a full PyPI index URL (`https://<user>:<pass>@host/…`): the
/// URL, the raw userinfo, the password raw and percent-decoded, and the base64 of
/// `<username>:<password>`. Labels never carry a value.
pub fn pypi_forms(url: &str) -> Vec<SecretForm> {
    let mut forms = vec![SecretForm {
        label: "the PyPI index URL".into(),
        value: url.to_owned(),
    }];
    let Some((_, rest)) = url.split_once("://") else {
        return forms;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let Some((userinfo, _)) = authority.rsplit_once('@') else {
        return forms;
    };
    forms.push(SecretForm {
        label: "the PyPI index userinfo".into(),
        value: userinfo.to_owned(),
    });
    let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let decode = |text: &str| crate::encoding::percent_decode(text);
    for (label, value) in [
        ("the PyPI index password", password.to_owned()),
        ("the PyPI index password (decoded)", decode(password)),
        (
            "the PyPI index credential (base64)",
            crate::encoding::base64_encode(
                format!("{}:{}", decode(username), decode(password)).as_bytes(),
            ),
        ),
    ] {
        if value.len() >= 4 {
            forms.push(SecretForm {
                label: label.into(),
                value,
            });
        }
    }
    forms
}

struct Reads<'s, 'p> {
    session: &'s mut Session<'p>,
}

impl Reads<'_, '_> {
    fn row(&mut self, check: &str, rust: &Exec, ts: Option<&Exec>, agree: bool, note: &str) {
        let both_ran = rust.code.is_some() && ts.is_none_or(|ts| ts.code.is_some());
        self.session.report.rows.push(LiveRow {
            check: check.to_owned(),
            rust_exit: rust.exit_cell(),
            ts_exit: ts.map_or_else(|| "-".to_owned(), Exec::exit_cell),
            agree: agree && both_ran,
            rust_verdict: None,
            ts_verdict: None,
            note: note.to_owned(),
        });
    }

    /// Both `--output json`, equal after the tolerated rows.
    fn json(&mut self, check: &str, args: &[&str]) -> Result<Value, LiveAbort> {
        let mut full = vec!["model-security"];
        full.extend_from_slice(args);
        full.extend(["--output", "json"]);
        let (rust, ts) = self.session.both(check, &full)?;
        let (r, t) = (rust.json(), ts.json());
        let agree = rust.code == Some(0) && ts.code == Some(0) && ms_json_equal(&r, &t);
        let note = if agree {
            "json equal (D180, D191, D192)"
        } else {
            "json differs"
        };
        self.row(check, &rust, Some(&ts), agree, note);
        Ok(r)
    }

    /// Both pretty (TypeScript prints these in pretty only), byte-equal after the banner
    /// and D52; the Rust `--output json` must parse.
    fn pretty(&mut self, check: &str, args: &[&str]) -> Result<Value, LiveAbort> {
        let mut full = vec!["model-security"];
        full.extend_from_slice(args);
        let (rust, ts) = self.session.both(check, &full)?;
        full.extend(["--output", "json"]);
        let json = self.session.exec(&self.session.plan.rust, check, &full)?;
        let parsed = serde_json::from_str::<Value>(&json.stdout).ok();
        let agree = rust.code == Some(0)
            && ts.code == Some(0)
            && json.code == Some(0)
            && parsed.is_some()
            && pretty_body(&rust.stdout, false) == pretty_body(&ts.stdout, true);
        let note = if agree {
            "pretty equal after the banner (D52); rust json parses (D189)"
        } else {
            "pretty differs or the rust json does not parse"
        };
        self.row(check, &rust, Some(&ts), agree, note);
        Ok(parsed.unwrap_or(Value::Null))
    }

    /// The Rust table against the TypeScript one (multiset of trimmed cells; the
    /// TypeScript `Model URI` cells withheld first, D191).
    fn table(&mut self, check: &str, args: &[&str], labels: &[&str]) -> Result<(), LiveAbort> {
        let mut full = vec!["model-security"];
        full.extend_from_slice(args);
        full.extend(["--output", "table"]);
        let (rust, ts) = self.session.both(check, &full)?;
        let ts_text = match labels.iter().position(|label| *label == "Model URI") {
            Some(column) => withhold_table_column(&ts.stdout, column),
            None => ts.stdout.clone(),
        };
        let (agree, note) = super::compare_tables(&rust.stdout, &ts_text, labels);
        let agree = agree && rust.code == Some(0) && ts.code == Some(0);
        self.row(
            check,
            &rust,
            Some(&ts),
            agree,
            &format!("{note} (D53, D191)"),
        );
        Ok(())
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        let probe = self.session.exec(
            &self.session.plan.rust,
            "model-security groups list (probe)",
            &[
                "model-security",
                "groups",
                "list",
                "--limit",
                "1",
                "--output",
                "json",
            ],
        )?;
        if super::redteam::no_access(probe.code, &probe.stderr) {
            self.session.report.notices.push(
                "model-security unavailable: the tenant has no model-security access (HTTP 401, 403 or 404); the model-security reads were not run".into(),
            );
            return Ok(());
        }
        self.row(
            "model-security groups list --limit 1 (rs)",
            &probe,
            None,
            probe.code == Some(0),
            "model-security access",
        );
        let mut firsts: Vec<(&str, Option<String>)> = Vec::new();
        for group in ["groups", "rules", "scans", "models"] {
            let listing = self.json(
                &format!("model-security {group} list --limit 20"),
                &[group, "list", "--limit", "20"],
            )?;
            firsts.push((group, first_uuid(&listing)));
        }
        let mut first_group = None;
        let mut first_scan = None;
        let mut first_model = None;
        for (group, first) in firsts {
            let Some(id) = first else {
                self.session.report.notices.push(format!(
                    "model-security {group} get skipped: the listing returned no row"
                ));
                continue;
            };
            self.json(
                &format!("model-security {group} get <first>"),
                &[group, "get", &id],
            )?;
            match group {
                "groups" => first_group = Some(id),
                "scans" => first_scan = Some(id),
                "models" => first_model = Some(id),
                _ => {}
            }
        }
        if let Some(group) = &first_group {
            let instances = self.json(
                "model-security rule-instances list <first group> --limit 20",
                &["rule-instances", "list", group, "--limit", "20"],
            )?;
            match first_uuid(&instances) {
                Some(instance) => {
                    self.json(
                        "model-security rule-instances get <first group> <first instance>",
                        &["rule-instances", "get", group, &instance],
                    )?;
                }
                None => self.session.report.notices.push(
                    "model-security rule-instances get skipped: the first group lists no instance"
                        .into(),
                ),
            }
        }
        if let Some(model) = &first_model {
            let versions = self.json(
                "model-security models versions <first model> --limit 20",
                &["models", "versions", model, "--limit", "20"],
            )?;
            match first_uuid(&versions) {
                Some(version) => {
                    self.json(
                        "model-security models version <first version>",
                        &["models", "version", &version],
                    )?;
                    self.json(
                        "model-security models files <first version> --limit 20",
                        &["models", "files", &version, "--limit", "20"],
                    )?;
                }
                None => self.session.report.notices.push(
                    "model-security models version skipped: the first model lists no version"
                        .into(),
                ),
            }
        }
        if let Some(scan) = &first_scan {
            for sub in ["evaluations", "violations", "files"] {
                self.pretty(
                    &format!("model-security scans {sub} <first scan> --limit 20"),
                    &["scans", sub, scan, "--limit", "20"],
                )?;
            }
        }
        let keys = self.pretty("model-security labels keys", &["labels", "keys"])?;
        match keys
            .as_array()
            .and_then(|keys| keys.first())
            .and_then(Value::as_str)
        {
            Some(key) => {
                let key = key.to_owned();
                self.pretty(
                    "model-security labels values <first key>",
                    &["labels", "values", &key],
                )?;
            }
            None => self
                .session
                .report
                .notices
                .push("model-security labels values skipped: no label key exists".into()),
        }
        self.table(
            "model-security groups list --limit 20 (table)",
            &["groups", "list", "--limit", "20"],
            &["ID", "Name", "State", "Source Type"],
        )?;
        self.table(
            "model-security scans list --limit 20 (table)",
            &["scans", "list", "--limit", "20"],
            &["ID", "Outcome", "Origin", "Model URI", "Created"],
        )?;
        Ok(())
    }

    /// The Rust-only `pypi-auth` check (see the module docs).
    fn pypi_auth(&mut self) -> Result<(), LiveAbort> {
        let dir = self.session.sandbox.tmp().join("pypi");
        std::fs::create_dir_all(&dir)
            .map_err(|err| LiveAbort::Setup(format!("cannot create the pypi directory: {err}")))?;
        let outcome = self.pypi_checks(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        outcome
    }

    fn pypi_checks(&mut self, dir: &Path) -> Result<(), LiveAbort> {
        let state = dir.join("xdg");
        let place = RunPlace {
            env: vec![("XDG_STATE_HOME", state.display().to_string())],
            ..RunPlace::default()
        };
        let rust = self.session.plan.rust.clone();
        // Each call may mint a new token server-side (§17.12), so every run that can save
        // the URL saves its own, and its output is checked against its own credential (and
        // every other run's); the last run shows the no-`--url-file` layout.
        let plan: [(&'static str, Option<&str>); 4] = [
            ("json", Some("pypi-json.url")),
            ("pretty", Some("pypi-pretty.url")),
            ("table", Some("pypi-table.url")),
            ("pretty", None),
        ];
        let mut execs = Vec::new();
        let mut saved = Vec::new();
        for (index, (format, file)) in plan.iter().enumerate() {
            let url_file = file.map(|file| dir.join(file));
            let url_text = url_file
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            let mut args = vec!["--debug", "model-security", "pypi-auth"];
            if url_file.is_some() {
                args.extend(["--url-file", url_text.as_str()]);
            }
            if *format != "pretty" {
                args.extend(["--output", format]);
            }
            let check = format!(
                "model-security pypi-auth (rs {format}{})",
                if url_file.is_some() {
                    ", --url-file"
                } else {
                    ""
                }
            );
            self.session.rust_runs.set(self.session.rust_runs.get() + 1);
            let exec = self.session.run_in(&rust, &check, &args, &place)?;
            if index == 0 && super::redteam::no_access(exec.code, &exec.stderr) {
                self.session.report.notices.push(
                    "pypi-auth unavailable: the tenant's pypi/authenticate answers HTTP 401, 403 or 404".into(),
                );
                return Ok(());
            }
            saved.push(url_file.map(|path| {
                let file = SavedUrl::read(&path);
                let _ = std::fs::remove_file(&path);
                file
            }));
            execs.push(exec);
        }
        let debug_text: String = debug_files(&state)
            .iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .collect();
        let runs: Vec<PypiRun<'_>> = plan
            .iter()
            .zip(&execs)
            .zip(&saved)
            .map(|(((format, _), exec), saved)| PypiRun {
                format,
                exec,
                saved: saved.as_ref(),
            })
            .collect();
        let withheld = pypi_withheld(&runs, &debug_text);
        // The summary must not carry any of them either (checked once more at the end).
        let forms: Vec<SecretForm> = saved
            .iter()
            .flatten()
            .filter(|file| !file.url.is_empty())
            .flat_map(|file| pypi_forms(&file.url))
            .collect();
        self.session.secrets.extend(forms);
        self.row(
            "model-security pypi-auth (rs: json, pretty, table, --url-file, --debug)",
            &execs[0],
            None,
            withheld,
            if withheld {
                "credential withheld; 0600 url files; D194"
            } else {
                "credential check failed; D194"
            },
        );
        self.session.report.notices.push(format!(
            "pypi-auth credential withheld: {withheld} (formats: json, pretty, table)"
        ));
        Ok(())
    }
}

/// What one `pypi-auth --url-file` run saved (read in memory only, then removed).
#[derive(Clone, Debug, PartialEq, Eq)]
struct SavedUrl {
    url: String,
    mode: Option<u32>,
    one_line: bool,
}

impl SavedUrl {
    fn read(path: &Path) -> Self {
        let mode = std::fs::metadata(path)
            .ok()
            .map(|metadata| metadata.permissions().mode() & 0o777);
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let one_line =
            content.ends_with('\n') && content.trim_end_matches('\n').lines().count() == 1;
        Self {
            url: content.trim_end_matches('\n').to_owned(),
            mode,
            one_line,
        }
    }
}

/// One Rust `pypi-auth` run of the live check.
struct PypiRun<'a> {
    format: &'a str,
    exec: &'a Exec,
    /// Its `--url-file`, when it was given one.
    saved: Option<&'a SavedUrl>,
}

/// Whether every URI authority in `text` that carries a userinfo carries exactly
/// `[withheld]` (no credential-shaped `://user:token@` of any token, rotated or not).
pub fn userinfo_withheld(text: &str) -> bool {
    text.match_indices("://").all(|(at, _)| {
        let rest = &text[at + 3..];
        let end = rest
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>' | '│')
            })
            .unwrap_or(rest.len());
        let authority = &rest[..end];
        authority
            .rsplit_once('@')
            .is_none_or(|(userinfo, _)| userinfo == WITHHELD)
    })
}

/// The verdict of the live `pypi-auth` check: every run exited 0; every URL file is one
/// line at 0600; no run's output, nor the debug log, carries any saved credential form or
/// a userinfo other than `[withheld]`; and each run prints exactly the withheld form of
/// its own URL (the run without a file: of the first saved one; host and path do not
/// rotate).
fn pypi_withheld(runs: &[PypiRun<'_>], debug_text: &str) -> bool {
    let files: Vec<&SavedUrl> = runs.iter().filter_map(|run| run.saved).collect();
    let Some(first) = files.first() else {
        return false;
    };
    if files
        .iter()
        .any(|file| file.url.is_empty() || file.mode != Some(0o600) || !file.one_line)
    {
        return false;
    }
    let forms: Vec<SecretForm> = files
        .iter()
        .flat_map(|file| pypi_forms(&file.url))
        .collect();
    let clean = |text: &str| {
        !forms.iter().any(|form| text.contains(&form.value)) && userinfo_withheld(text)
    };
    if !clean(debug_text) {
        return false;
    }
    runs.iter().all(|run| {
        let exec = run.exec;
        let expected = withheld_uri(&run.saved.unwrap_or(first).url);
        let shown = match run.format {
            "json" => exec.json().get("url").and_then(Value::as_str) == Some(expected.as_str()),
            "pretty" => exec.stdout.contains(&format!("  URL      {expected}\n")),
            _ => exec.stdout.contains(&expected),
        };
        exec.code == Some(0)
            && expected.contains(&format!("{WITHHELD}@"))
            && shown
            && clean(&exec.stdout)
            && clean(&exec.stderr)
    })
}

/// Every debug log under an `XDG_STATE_HOME`.
fn debug_files(state: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(state.join("airs-cli/debug"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect()
        })
        .unwrap_or_default()
}

/// The cells of `column` of a table replaced by their withheld URI form.
fn withhold_table_column(text: &str, column: usize) -> String {
    let newline = if text.ends_with('\n') { "\n" } else { "" };
    let body = text.strip_suffix('\n').unwrap_or(text);
    let joined = body
        .split('\n')
        .map(|line| {
            if !line.contains('│') {
                return line.to_owned();
            }
            let cells: Vec<&str> = line.split('│').collect();
            cells
                .iter()
                .enumerate()
                .map(|(index, cell)| {
                    if index == column && !cell.trim().is_empty() {
                        let trimmed = cell.trim();
                        cell.replacen(trimmed, &withheld_uri(trimmed), 1)
                    } else {
                        (*cell).to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("│")
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{joined}{newline}")
}

/// Runs the model-security reads (and the Rust-only `pypi-auth` check) and returns the
/// sanitized summary.
pub fn run_live_modelsec_reads(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
    let mut session = Session::open(plan)?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut reads = Reads {
            session: &mut session,
        };
        reads.steps()?;
        if !reads
            .session
            .report
            .notices
            .iter()
            .any(|notice| notice.starts_with("model-security unavailable"))
        {
            reads.pypi_auth()?;
        }
        reads.session.verify()?;
        reads.session.summary_check()
    }));
    let _ = std::fs::remove_dir_all(session.sandbox.tmp().join("pypi"));
    session.report.store_removed = Some(session.store.remove());
    match outcome {
        Err(panic) => std::panic::resume_unwind(panic),
        Ok(result) => result?,
    }
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_documents_compare_with_the_tolerated_rows() {
        let ts = json!({"uuid": "a", "modelUri": "s3://u:p@b/m?sig=1", "labels": [], "scanOrigin": "",
            "evalSummary": {"rulesFailed": 0}});
        let rust = json!({"uuid": "a", "modelUri": "s3://[withheld]@b/m?[withheld]", "evalSummary": {"rulesFailed": null}});
        assert!(ms_json_equal(&rust, &ts));
        assert!(!ms_json_equal(&json!({"uuid": "b"}), &json!({"uuid": "a"})));
        assert!(
            !ms_json_equal(&json!({"x": 1}), &json!({})),
            "a Rust-only key differs"
        );
        assert!(ms_json_equal(
            &json!([{"customRuleUuid": "c", "uuid": "a"}]),
            &json!([{"uuid": "a"}])
        ));
        assert_eq!(withheld_uri("hf://org/m"), "hf://org/m");
    }

    #[test]
    fn pypi_forms_cover_the_credential() {
        let forms = pypi_forms("https://oauth2accesstoken:ya29%2Eabcd@h.example/s/");
        let values: Vec<&str> = forms.iter().map(|form| form.value.as_str()).collect();
        assert!(values.contains(&"ya29%2Eabcd"));
        assert!(values.contains(&"ya29.abcd"));
        assert!(values.contains(&"oauth2accesstoken:ya29%2Eabcd"));
        assert!(forms.iter().all(|form| !form.label.contains("ya29")));
    }

    fn exec(stdout: &str, stderr: &str) -> Exec {
        Exec {
            code: Some(0),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            elapsed: std::time::Duration::ZERO,
        }
    }

    fn saved(token: &str) -> SavedUrl {
        SavedUrl {
            url: format!("https://oauth2accesstoken:{token}@h.example/s/simple/"),
            mode: Some(0o600),
            one_line: true,
        }
    }

    /// A rotated token: the pretty run saved token B and printed it; the json run's
    /// forms (token A) alone would not see it, its own file's forms and the userinfo
    /// rule do.
    #[test]
    fn every_pypi_run_is_checked_against_its_own_url() {
        let shown = "https://[withheld]@h.example/s/simple/";
        let json_run = exec(&format!(r#"{{"url":"{shown}","expiresAt":"x"}}"#), "");
        let pretty_ok = exec(&format!("  URL      {shown}\n  Expires  x\n"), "");
        let table_ok = exec(&format!("│ url       │ {shown} │\n"), "");
        let (a, b, c) = (
            saved("ya29.TOKEN-A"),
            saved("ya29.TOKEN-B"),
            saved("ya29.TOKEN-C"),
        );
        let runs = |pretty: &Exec, bare: &Exec| -> bool {
            let runs = [
                PypiRun {
                    format: "json",
                    exec: &json_run,
                    saved: Some(&a),
                },
                PypiRun {
                    format: "pretty",
                    exec: pretty,
                    saved: Some(&b),
                },
                PypiRun {
                    format: "table",
                    exec: &table_ok,
                    saved: Some(&c),
                },
                PypiRun {
                    format: "pretty",
                    exec: bare,
                    saved: None,
                },
            ];
            pypi_withheld(&runs, "")
        };
        assert!(runs(&pretty_ok, &pretty_ok));
        let leaked = exec(&format!("  URL      {}\n", b.url), "");
        assert!(!runs(&leaked, &pretty_ok), "its own rotated token");
        // A token no file saved (the run without --url-file): the userinfo rule.
        let unsaved = exec(
            "  URL      https://oauth2accesstoken:ya29.OTHER@h.example/s/simple/\n",
            "",
        );
        assert!(!runs(&pretty_ok, &unsaved), "an unsaved token");
        // The exact withheld form is required.
        let bare_withheld = exec("  URL      [withheld]\n", "");
        assert!(!runs(&pretty_ok, &bare_withheld));
    }

    #[test]
    fn userinfo_other_than_withheld_is_refused() {
        assert!(userinfo_withheld("x https://[withheld]@h/s/ y https://h/p"));
        assert!(userinfo_withheld("mailto someone@example.com"));
        assert!(!userinfo_withheld("https://u:t@h/s/"));
        assert!(!userinfo_withheld("│ https://oauth2accesstoken@h │"));
    }

    #[test]
    fn pretty_bodies_drop_the_banner_and_apply_d52() {
        assert_eq!(
            pretty_body(&format!("{BANNER}  a\u{1b}b\n"), true),
            "  a\u{fffd}b\n"
        );
        assert_eq!(pretty_body("x", false), "x");
    }
}
