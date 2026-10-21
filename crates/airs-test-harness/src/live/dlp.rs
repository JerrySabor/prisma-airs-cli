//! The M6b live DLP reads (DESIGN §10, "M6b DLP", Reads).
//!
//! [`run_live_dlp_reads`] runs only when `tests/live.rs` passes the read gate
//! (`AIRS_RS_LIVE=1` and `AIRS_E2E_TENANT`), or against the loopback fixture server
//! through [`super::LiveTarget::loopback`]. It is its own run (run id, private store,
//! fingerprints, leak checks, 90 s per CLI run) and read-only on both CLIs; the
//! TypeScript CLI is sandboxed as in every live run.
//!
//! The first step is the Rust `runtime dlp patterns list --include-predefined --limit 1
//! --output json`: an HTTP 401, 403 or 404 there means the tenant has no DLP access, the
//! summary notes `dlp unavailable` and nothing else runs (not a mismatch). Neither CLI
//! reads a keyword list (no `--keywords`). Both CLIs write a backup into the run's own
//! sandbox (`tmp/rs`, `tmp/ts`), compared in memory by counts and name sets only and
//! removed right after the check; nothing from either file reaches a summary.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::Value;

use super::{Exec, LiveAbort, LivePlan, LiveReport, LiveRow, Session};
use crate::compare::json_semantic_eq;

/// TS `camelKey` (`[_-]([a-z0-9])` → upper case).
fn camel_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut chars = key.chars().peekable();
    while let Some(c) = chars.next() {
        if (c == '_' || c == '-')
            && let Some(next) = chars.peek().copied()
            && (next.is_ascii_lowercase() || next.is_ascii_digit())
        {
            out.push(next.to_ascii_uppercase());
            chars.next();
            continue;
        }
        out.push(c);
    }
    out
}

fn camel_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| (camel_key(key), camel_keys(child)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(camel_keys).collect()),
        other => other.clone(),
    }
}

/// The Rust `--output json` document with TypeScript's camelCasing applied to the data
/// keys airs-cli-rs keeps (under `tags` and `exclusions.exclusionList`, D171).
pub fn ts_camel_data_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| {
                    let child = if key == "tags" {
                        camel_keys(child)
                    } else if key == "exclusions" {
                        match child {
                            Value::Object(inner) => Value::Object(
                                inner
                                    .iter()
                                    .map(|(k, v)| {
                                        if k == "exclusionList" {
                                            (k.clone(), camel_keys(v))
                                        } else {
                                            (k.clone(), ts_camel_data_keys(v))
                                        }
                                    })
                                    .collect(),
                            ),
                            other => ts_camel_data_keys(other),
                        }
                    } else {
                        ts_camel_data_keys(child)
                    };
                    (key.clone(), child)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(ts_camel_data_keys).collect()),
        other => other.clone(),
    }
}

/// The `id`s of a listing (`None` unless an array).
pub fn ids_of(listing: &Value) -> Option<BTreeSet<String>> {
    Some(
        listing
            .as_array()?
            .iter()
            .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect(),
    )
}

/// The first `id` of a listing.
fn first_id(listing: &Value) -> Option<String> {
    listing
        .as_array()?
        .first()?
        .get("id")?
        .as_str()
        .map(str::to_owned)
}

/// The `(kind, names)` of one backup file: the Rust format (entries, plus the names of
/// its `failed` rows, which count as present) or the TypeScript envelope (records).
pub fn backup_names(doc: &Value) -> Option<[(usize, BTreeSet<String>); 3]> {
    let rust = doc.get("format").and_then(Value::as_str) == Some("airs-cli-rs.dlp-resources");
    let mut out: Vec<(usize, BTreeSet<String>)> = Vec::new();
    for (key, kind) in [
        ("dictionaries", "dictionary"),
        ("patterns", "pattern"),
        ("profiles", "profile"),
    ] {
        let items = doc.get(key)?.as_array()?;
        let mut names: BTreeSet<String> = items
            .iter()
            .filter_map(|item| {
                let record = if rust { item.get("record")? } else { item };
                record.get("name")?.as_str().map(str::to_owned)
            })
            .collect();
        let mut count = items.len();
        if rust {
            for failed in doc.get("failed")?.as_array()? {
                if failed.get("kind").and_then(Value::as_str) == Some(kind) {
                    count += 1;
                    if let Some(name) = failed.get("name").and_then(Value::as_str) {
                        names.insert(name.to_owned());
                    }
                }
            }
        }
        out.push((count, names));
    }
    out.try_into().ok()
}

/// The checks of one backup file: mode 0600 and, for the Rust file, the format.
fn backup_file(path: &Path, rust: bool) -> Result<Value, &'static str> {
    let mode = std::fs::metadata(path)
        .map_err(|_| "the backup file is missing")?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err("the backup file is not mode 0600");
    }
    let doc: Value = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .ok_or("the backup file is not JSON")?;
    if rust
        && (doc.get("format").and_then(Value::as_str) != Some("airs-cli-rs.dlp-resources")
            || doc.get("version").and_then(Value::as_u64) != Some(1))
    {
        return Err("the Rust backup is not the airs-cli-rs format");
    }
    Ok(doc)
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

    /// Both `--output json`, semantically equal after the D171 normalisation.
    fn json(&mut self, check: &str, args: &[&str]) -> Result<(Exec, Exec), LiveAbort> {
        let (rust, ts) = self.session.both(check, args)?;
        let agree = rust.code == Some(0)
            && ts.code == Some(0)
            && serde_json::from_str::<Value>(&rust.stdout)
                .ok()
                .zip(serde_json::from_str::<Value>(&ts.stdout).ok())
                .is_some_and(|(r, t)| json_semantic_eq(&ts_camel_data_keys(&r), &t));
        let note = if agree {
            "json equal (D171 data keys)"
        } else {
            "json differs"
        };
        self.row(check, &rust, Some(&ts), agree, note);
        Ok((rust, ts))
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        let probe = self.session.exec(
            &self.session.plan.rust,
            "dlp patterns list (probe)",
            &[
                "runtime",
                "dlp",
                "patterns",
                "list",
                "--include-predefined",
                "--limit",
                "1",
                "--output",
                "json",
            ],
        )?;
        if super::redteam::no_access(probe.code, &probe.stderr) {
            self.session.report.notices.push(
                "dlp unavailable: the tenant has no DLP access (HTTP 401, 403 or 404); the DLP reads were not run".into(),
            );
            return Ok(());
        }
        self.row(
            "dlp patterns list --limit 1 (rs)",
            &probe,
            None,
            probe.code == Some(0),
            "DLP access",
        );
        // Single server pages on both sides.
        let mut firsts: Vec<(&str, Option<String>)> = Vec::new();
        for (group, predefined) in [
            ("filtering-profiles", false),
            ("patterns", true),
            ("profiles", true),
            ("dictionaries", true),
        ] {
            let mut args = vec!["runtime", "dlp", group, "list", "--limit", "50"];
            if predefined {
                args.push("--include-predefined");
            }
            args.extend(["--output", "json"]);
            let check = if predefined {
                format!("dlp {group} list --include-predefined --limit 50")
            } else {
                format!("dlp {group} list --limit 50")
            };
            let (rust, _) = self.json(&check, &args)?;
            firsts.push((group, first_id(&rust.json())));
        }
        // The custom-only defaults: TypeScript reads one page (D170).
        for group in ["patterns", "profiles", "dictionaries"] {
            let check = format!("dlp {group} list");
            let (rust, ts) = self.session.both(
                &check,
                &["runtime", "dlp", group, "list", "--output", "json"],
            )?;
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && ids_of(&ts.json())
                    .zip(ids_of(&rust.json()))
                    .is_some_and(|(t, r)| t.is_subset(&r));
            self.row(
                &check,
                &rust,
                Some(&ts),
                agree,
                "TS ids within the Rust ids (D170)",
            );
        }
        for (group, first) in firsts {
            match first {
                Some(id) => {
                    self.json(
                        &format!("dlp {group} get <first>"),
                        &["runtime", "dlp", group, "get", &id, "--output", "json"],
                    )?;
                }
                None => self.session.report.notices.push(format!(
                    "dlp {group} get skipped: the listing returned no row"
                )),
            }
        }
        self.backups()
    }

    /// Both CLIs back up into the run's own sandbox; counts and name sets compared.
    fn backups(&mut self) -> Result<(), LiveAbort> {
        let mut runs = Vec::new();
        for (cli, label) in [
            (&self.session.plan.rust, "rs"),
            (&self.session.plan.ts, "ts"),
        ] {
            let dir = self.session.sandbox.tmp().join(label);
            std::fs::create_dir_all(&dir).map_err(|err| {
                LiveAbort::Setup(format!("cannot create the backup directory: {err}"))
            })?;
            let path = dir.join("dlp.json");
            let path_text = path.display().to_string();
            let exec = self.session.exec(
                cli,
                "dlp backup",
                &[
                    "runtime",
                    "dlp",
                    "backup",
                    "--skip-unsupported",
                    "--output-file",
                    &path_text,
                ],
            )?;
            let doc = backup_file(&path, label == "rs");
            let _ = std::fs::remove_dir_all(&dir);
            runs.push((exec, doc));
        }
        let (rust, rust_doc) = &runs[0];
        let (ts, ts_doc) = &runs[1];
        let rust_failed = rust_doc
            .as_ref()
            .ok()
            .and_then(|doc| doc.get("failed"))
            .and_then(Value::as_array)
            .is_some_and(|failed| !failed.is_empty());
        if rust_failed {
            self.session
                .report
                .notices
                .push("the Rust DLP backup has failed rows (keyword reads, D175)".into());
        }
        let exits = match (rust.code, ts.code) {
            (Some(0), Some(0)) => true,
            (Some(1), Some(0)) => rust_failed,
            _ => false,
        };
        let (agree, note) = match (rust_doc, ts_doc) {
            (Ok(r), Ok(t)) => match (backup_names(r), backup_names(t)) {
                (Some(r), Some(t)) if r == t => {
                    (exits, "0600 files; counts and names equal".to_owned())
                }
                (Some(_), Some(_)) => (false, "counts or names differ".to_owned()),
                _ => (false, "a backup file is not readable".to_owned()),
            },
            (Err(problem), _) | (_, Err(problem)) => (false, (*problem).to_owned()),
        };
        self.row("dlp backup", rust, Some(ts), agree, &note);
        Ok(())
    }
}

/// Runs the DLP reads and returns the sanitized summary.
pub fn run_live_dlp_reads(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
    let mut session = Session::open(plan)?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut reads = Reads {
            session: &mut session,
        };
        reads.steps()?;
        reads.session.verify()
    }));
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
    fn data_keys_are_camel_cased_as_typescript_does() {
        let rust = json!([{"id": "a", "tags": {"my_tag": ["x"], "a-1": []}, "exclusions": {"exclusionList": {"my_category": []}, "appExclusionList": []}, "nested": {"tags": {"b_c": 1}}}]);
        assert_eq!(
            ts_camel_data_keys(&rust),
            json!([{"id": "a", "tags": {"myTag": ["x"], "a1": []}, "exclusions": {"exclusionList": {"myCategory": []}, "appExclusionList": []}, "nested": {"tags": {"bC": 1}}}])
        );
        assert_eq!(camel_key("Some_Category"), "Some_Category");
        assert_eq!(camel_key("x_Y"), "x_Y");
    }

    #[test]
    fn backup_names_count_failed_rows_as_present() {
        let rust = json!({"format": "airs-cli-rs.dlp-resources", "dictionaries": [], "patterns": [{"record": {"name": "P"}}],
            "profiles": [], "failed": [{"kind": "dictionary", "name": "D"}]});
        let ts = json!({"resourceType": "dlp-resources", "dictionaries": [{"name": "D"}], "patterns": [{"name": "P"}], "profiles": []});
        assert_eq!(backup_names(&rust), backup_names(&ts));
        assert_eq!(backup_names(&json!({})), None);
        assert!(ids_of(&json!([{"id": "a"}])).unwrap().contains("a"));
    }
}
