//! The M6a live red team reads (DESIGN §10, "M6a red team", Reads).
//!
//! [`run_live_redteam_reads`] runs only when `tests/live.rs` passes the read gate
//! (`AIRS_RS_LIVE=1` and `AIRS_E2E_TENANT`), or against the loopback fixture server
//! through [`super::LiveTarget::loopback`]. It is its own run (run id, private store,
//! fingerprints, leak checks, 90 s per CLI run) and read-only on both CLIs; the
//! TypeScript CLI is sandboxed as in every live run.
//!
//! The first step is the Rust `redteam categories --output json`: an HTTP 401, 403 or
//! 404 there means the tenant has no red team access, the summary notes `redteam
//! unavailable` and nothing else runs (not a mismatch). The TypeScript CLI never runs
//! `targets get` (it would print the target credentials, D140) nor a backup: those are
//! Rust-only checks, made in memory and discarded. The backup and the environment
//! reports land in the run's sandbox, which is removed with it.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::Value;

use super::{Exec, LiveAbort, LivePlan, LiveReport, LiveRow, Session, compare_tables};
use crate::compare::json_semantic_eq;

/// The table columns of `redteam targets list` (§15.12).
pub const TARGET_TABLE_COLUMNS: &[&str] = &["ID", "Name", "Status", "Type"];

/// Whether a Rust failure says the tenant has no red team access (HTTP 401, 403, 404).
pub fn no_access(exec_code: Option<i32>, stderr: &str) -> bool {
    exec_code != Some(0)
        && stderr
            .lines()
            .any(|line| matches!(line.trim(), "HTTP 401" | "HTTP 403" | "HTTP 404"))
}

/// Whether every §15.4 credential path of a Rust `targets get --output json` document
/// (the normalised camelCase target) is `[REDACTED]`, empty or absent, the management
/// 0.86.0 `audio_curl` included (DESIGN §15.24).
pub fn credentials_redacted(doc: &Value) -> bool {
    fn strings_hidden(value: &Value, kept: &[&str]) -> bool {
        match value {
            Value::String(text) => text.is_empty() || text == "[REDACTED]",
            Value::Array(items) => items.iter().all(|item| strings_hidden(item, kept)),
            Value::Object(map) => map
                .iter()
                .filter(|(key, _)| !kept.contains(&key.as_str()))
                .all(|(_, value)| strings_hidden(value, kept)),
            _ => true,
        }
    }
    let auth = doc.get("authConfig").is_none_or(|auth| {
        strings_hidden(
            auth,
            &[
                "basic_auth_location",
                "oauth2_token_response_key",
                "oauth2_token_url",
            ],
        )
    });
    let params = doc.get("connectionParams");
    let headers = params
        .and_then(|params| params.get("request_headers"))
        .and_then(Value::as_object)
        .is_none_or(|headers| {
            headers
                .iter()
                .filter(|(name, _)| {
                    !["accept", "content-type", "user-agent"]
                        .iter()
                        .any(|kept| name.eq_ignore_ascii_case(kept))
                })
                .all(|(_, value)| strings_hidden(value, &[]))
        });
    // `audio_curl` (management 0.86.0, scm-sdk 0.2.3) is a curl template too (D327).
    let templates_hidden = ["curl", "audio_curl"].iter().all(|key| {
        params
            .and_then(|params| params.get(*key))
            .is_none_or(|template| strings_hidden(template, &[]))
    });
    let native = params
        .and_then(|params| params.get("target_connection_config"))
        .is_none_or(|config| {
            strings_hidden(
                config,
                &[
                    "model_name",
                    "model_id",
                    "region",
                    "auth_type",
                    "workspace_url",
                ],
            )
        });
    let overrides = doc
        .get("adapterVariableOverrides")
        .and_then(Value::as_array)
        .is_none_or(|items| {
            items.iter().all(|item| {
                item.get("type").and_then(Value::as_str) == Some("VAR")
                    || item
                        .get("value")
                        .is_none_or(|value| strings_hidden(value, &[]))
            })
        });
    auth && headers && templates_hidden && native && overrides
}

/// The sorted `(name, status, type)` rows of a targets listing.
pub fn target_multiset(listing: &Value) -> Option<Vec<(String, String, String)>> {
    let mut rows: Vec<(String, String, String)> = listing
        .as_array()?
        .iter()
        .map(|row| {
            let text = |key: &str| {
                row.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            (text("name"), text("status"), text("type"))
        })
        .collect();
    rows.sort();
    Some(rows)
}

/// The statuses of the scan ids both listings name agree.
pub fn statuses_agree(rust: &Value, ts: &Value) -> Option<(bool, usize)> {
    let map = |value: &Value| -> Option<BTreeMap<String, String>> {
        Some(
            value
                .as_array()?
                .iter()
                .filter_map(|row| {
                    Some((
                        row.get("id")?.as_str()?.to_owned(),
                        row.get("status")?.as_str()?.to_owned(),
                    ))
                })
                .collect(),
        )
    };
    let (rust, ts) = (map(rust)?, map(ts)?);
    let common: Vec<&String> = rust.keys().filter(|id| ts.contains_key(*id)).collect();
    Some((
        common.iter().all(|id| rust.get(*id) == ts.get(*id)),
        common.len(),
    ))
}

/// Whether every TypeScript row is a Rust row (D147: TypeScript may read one page).
pub fn rows_subset(ts: &Value, rust: &Value) -> Option<bool> {
    let (ts, rust) = (ts.as_array()?, rust.as_array()?);
    Some(
        ts.iter()
            .all(|row| rust.iter().any(|other| json_semantic_eq(row, other))),
    )
}

/// Whether `stdout` is the line TypeScript prints for an empty red team list in every
/// format, `  No <resource> found` (`ui.emptyList`, colour off). airs-cli-rs prints `[]`
/// in json and nothing in table there (D146), which the read comparisons treat as equal.
pub fn ts_empty_list(stdout: &str, resource: &str) -> bool {
    stdout
        .strip_prefix("  No ")
        .and_then(|rest| rest.strip_suffix(" found\n"))
        == Some(resource)
}

/// The JSON document of a list run of TypeScript, the D146 empty line read as `[]`
/// (exit 0 only); `Null` when the output is not JSON.
pub fn ts_list_json(code: Option<i32>, stdout: &str, resource: Option<&str>) -> Value {
    if code == Some(0) && resource.is_some_and(|resource| ts_empty_list(stdout, resource)) {
        return Value::Array(Vec::new());
    }
    serde_json::from_str(stdout).unwrap_or(Value::Null)
}

/// The table stdout of a list run of TypeScript, the D146 empty line read as the empty
/// table airs-cli-rs prints (nothing; exit 0 only).
pub fn ts_list_table<'a>(code: Option<i32>, stdout: &'a str, resource: &str) -> &'a str {
    if code == Some(0) && ts_empty_list(stdout, resource) {
        ""
    } else {
        stdout
    }
}

/// Whether the `--output json` documents of both CLIs agree (D35), both exit 0, the
/// TypeScript D146 empty line of a list of `resource` counting as `[]`.
pub fn json_runs_agree(
    rust: (Option<i32>, &str),
    ts: (Option<i32>, &str),
    resource: Option<&str>,
) -> bool {
    let parsed = serde_json::from_str::<Value>(rust.1).ok();
    let ts_doc = ts_list_json(ts.0, ts.1, resource);
    rust.0 == Some(0)
        && ts.0 == Some(0)
        && parsed.is_some_and(|rust| !ts_doc.is_null() && json_semantic_eq(&rust, &ts_doc))
}

/// The first string `key` of a listing's rows.
fn first(listing: &Value, key: &str) -> Option<String> {
    listing
        .as_array()?
        .first()?
        .get(key)?
        .as_str()
        .map(str::to_owned)
}

/// The §15.18 checks of one backup directory: exactly one file, 0600, the format, and
/// as many targets plus failures as the listing has rows; no file when nothing is listed
/// (`No targets found`, §15.18).
pub fn backup_ok(dir: &Path, listed: usize) -> Result<(), &'static str> {
    let files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|_| "the backup directory is unreadable")?
        .flatten()
        .collect();
    if listed == 0 {
        return if files.is_empty() {
            Ok(())
        } else {
            Err("a backup file was written for no target")
        };
    }
    let [file] = files.as_slice() else {
        return Err("expected exactly one backup file");
    };
    let path = file.path();
    let mode = std::fs::metadata(&path)
        .map_err(|_| "the backup file is unreadable")?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err("the backup file is not mode 0600");
    }
    let doc: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .ok_or("the backup file is not JSON")?;
    if doc.get("format").and_then(Value::as_str) != Some("airs-cli-rs.redteam-targets")
        || doc.get("version").and_then(Value::as_u64) != Some(1)
    {
        return Err("the backup file is not the airs-cli-rs format");
    }
    let count = |key: &str| doc.get(key).and_then(Value::as_array).map_or(0, Vec::len);
    if count("targets") + count("failed") != listed {
        return Err("the backup does not account for every listed target");
    }
    Ok(())
}

/// The `<n> source(s) incomplete` status line of a report run, if any.
fn incomplete_line(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .find(|line| line.contains("source(s) incomplete"))
        .map(|line| line.trim().to_owned())
}

/// With `AIRS_RS_LIVE_DUMP=<dir>`, writes every row's stdout and stderr of both
/// CLIs into `<dir>` (created 0700, files 0600) for the maintainer to diff. The output
/// can hold tenant data, so it is never printed; best effort.
fn dump(check: &str, rust: &Exec, ts: Option<&Exec>) {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let Some(dir) = std::env::var_os("AIRS_RS_LIVE_DUMP").filter(|dir| !dir.is_empty()) else {
        return;
    };
    let dir = Path::new(&dir);
    let _ = std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(dir);
    let stem: String = check
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let mut outputs = vec![("rs", rust)];
    outputs.extend(ts.map(|ts| ("ts", ts)));
    for (side, exec) in outputs {
        for (stream, text) in [("stdout", &exec.stdout), ("stderr", &exec.stderr)] {
            let path = dir.join(format!("{stem}.{side}.{stream}"));
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
            {
                let _ = file.write_all(text.as_bytes());
            }
        }
    }
}

struct Reads<'s, 'p> {
    session: &'s mut Session<'p>,
}

impl Reads<'_, '_> {
    fn both(&self, check: &str, args: &[&str]) -> Result<(Exec, Exec), LiveAbort> {
        self.session.both(check, args)
    }

    fn rust(&self, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        self.session.exec(&self.session.plan.rust, check, args)
    }

    fn row(&mut self, check: &str, rust: &Exec, ts: Option<&Exec>, agree: bool, note: &str) {
        let both_ran = rust.code.is_some() && ts.is_none_or(|ts| ts.code.is_some());
        dump(check, rust, ts);
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

    /// Both pretty, stdout byte-equal (D52 tolerated: a control character the Rust side
    /// replaced with U+FFFD).
    fn bytes(&mut self, check: &str, args: &[&str]) -> Result<(), LiveAbort> {
        let (rust, ts) = self.both(check, args)?;
        let agree = rust.code == ts.code
            && (rust.stdout == ts.stdout
                || (rust.stdout.contains('\u{fffd}')
                    && rust.stdout.lines().count() == ts.stdout.lines().count()));
        let note = if agree {
            "stdout equal"
        } else {
            "stdout differs"
        };
        self.row(check, &rust, Some(&ts), agree, note);
        Ok(())
    }

    /// Both `--output json` (or raw JSON), semantically equal (D35). `empty` names the
    /// resource of a list whose empty TypeScript output is the `No … found` line (D146).
    fn json(
        &mut self,
        check: &str,
        args: &[&str],
        empty: Option<&str>,
    ) -> Result<(Exec, Exec), LiveAbort> {
        let (rust, ts) = self.both(check, args)?;
        let agree = json_runs_agree((rust.code, &rust.stdout), (ts.code, &ts.stdout), empty);
        let note = if agree { "json equal" } else { "json differs" };
        self.row(check, &rust, Some(&ts), agree, note);
        Ok((rust, ts))
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        let probe = self.rust(
            "redteam categories",
            &["redteam", "categories", "--output", "json"],
        )?;
        if no_access(probe.code, &probe.stderr) {
            self.session.report.notices.push(
                "redteam unavailable: the tenant has no red team access (HTTP 401, 403 or 404); the red team reads were not run".into(),
            );
            return Ok(());
        }
        self.row(
            "redteam categories --output json (rs)",
            &probe,
            None,
            probe.code == Some(0),
            "red team access",
        );
        self.bytes("redteam categories", &["redteam", "categories"])?;
        self.bytes("redteam eula status", &["redteam", "eula", "status"])?;
        // The third column: the resource of the TypeScript `No … found` line of an empty
        // list (`src/cli/renderer/redteam.ts`; the languages, property-names and prompt
        // lists print JSON before their empty check).
        for (check, args, empty) in [
            (
                "redteam languages",
                vec!["redteam", "languages", "--output", "json"],
                None,
            ),
            (
                "redteam languages --management",
                vec!["redteam", "languages", "--management", "--output", "json"],
                None,
            ),
            (
                "redteam properties list",
                vec!["redteam", "properties", "list", "--output", "json"],
                None,
            ),
            (
                "redteam network-broker stats",
                vec!["redteam", "network-broker", "stats", "--output", "json"],
                None,
            ),
            (
                "redteam channels list",
                vec![
                    "redteam",
                    "network-broker",
                    "channels",
                    "list",
                    "--output",
                    "json",
                ],
                Some("channels"),
            ),
            (
                "redteam adapter list",
                vec!["redteam", "adapter", "list", "--output", "json"],
                Some("adapters"),
            ),
            (
                "redteam targets metadata",
                vec!["redteam", "targets", "metadata", "--output", "json"],
                None,
            ),
        ] {
            self.json(check, &args, empty)?;
        }
        // Set comparisons.
        let (rust, ts) = self.both(
            "redteam list --limit 5",
            &["redteam", "list", "--limit", "5", "--output", "json"],
        )?;
        let ts_scans = ts_list_json(ts.code, &ts.stdout, Some("scans"));
        let (agree, note) = match statuses_agree(&rust.json(), &ts_scans) {
            Some((agree, common)) => (
                agree && rust.code == Some(0) && ts.code == Some(0),
                format!("statuses of {common} common ids"),
            ),
            None => (false, "output is not a scan listing".to_owned()),
        };
        self.row("redteam list --limit 5", &rust, Some(&ts), agree, &note);
        let (rust, ts) = self.both(
            "redteam targets list",
            &["redteam", "targets", "list", "--output", "json"],
        )?;
        let targets = rust.json();
        let agree = rust.code == Some(0)
            && ts.code == Some(0)
            && target_multiset(&targets).is_some()
            && target_multiset(&targets)
                == target_multiset(&ts_list_json(ts.code, &ts.stdout, Some("targets")));
        self.row(
            "redteam targets list",
            &rust,
            Some(&ts),
            agree,
            "multiset of (name, status, type)",
        );
        let (rust_table, ts_table) = self.both(
            "redteam targets list --output table",
            &["redteam", "targets", "list", "--output", "table"],
        )?;
        let (agree, note) = compare_tables(
            &rust_table.stdout,
            ts_list_table(ts_table.code, &ts_table.stdout, "targets"),
            TARGET_TABLE_COLUMNS,
        );
        let agree = agree && rust_table.code == Some(0) && ts_table.code == Some(0);
        self.row(
            "redteam targets list --output table",
            &rust_table,
            Some(&ts_table),
            agree,
            &note,
        );
        let (rust_sets, ts_sets) = self.both(
            "redteam prompt-sets list",
            &["redteam", "prompt-sets", "list", "--output", "json"],
        )?;
        let agree = rust_sets.code == Some(0)
            && ts_sets.code == Some(0)
            && rows_subset(
                &ts_list_json(ts_sets.code, &ts_sets.stdout, Some("prompt sets")),
                &rust_sets.json(),
            ) == Some(true);
        self.row(
            "redteam prompt-sets list",
            &rust_sets,
            Some(&ts_sets),
            agree,
            "TS rows within the Rust rows (D147)",
        );
        match first(&rust_sets.json(), "id") {
            Some(set) => {
                self.json(
                    "redteam prompt-sets get <first>",
                    &["redteam", "prompt-sets", "get", &set, "--output", "json"],
                    None,
                )?;
                self.json(
                    "redteam prompts list <first> --limit 5",
                    &[
                        "redteam", "prompts", "list", &set, "--limit", "5", "--output", "json",
                    ],
                    None,
                )?;
            }
            None => {
                self.session.report.notices.push(
                    "prompt-sets get and prompts list skipped: no prompt set is listed".into(),
                )
            }
        }
        // A completed job, when one exists.
        let done = self.rust(
            "redteam list --status COMPLETED",
            &[
                "redteam",
                "list",
                "--status",
                "COMPLETED",
                "--limit",
                "1",
                "--output",
                "json",
            ],
        )?;
        match first(&done.json(), "id") {
            Some(job) => {
                self.bytes("redteam status <completed>", &["redteam", "status", &job])?;
                self.bytes("redteam report <completed>", &["redteam", "report", &job])?;
            }
            None => self
                .session
                .report
                .notices
                .push("status and report skipped: no completed scan is listed".into()),
        }
        // Rust only, checked in memory: the redaction of a target and a backup.
        match first(&targets, "id") {
            Some(target) => {
                let exec = self.rust(
                    "redteam targets get <first> (rs)",
                    &["redteam", "targets", "get", &target, "--output", "json"],
                )?;
                let agree = exec.code == Some(0) && credentials_redacted(&exec.json());
                self.row(
                    "redteam targets get <first> (rs)",
                    &exec,
                    None,
                    agree,
                    "credential paths redacted (D140)",
                );
            }
            None => self
                .session
                .report
                .notices
                .push("targets get skipped: no target is listed".into()),
        }
        let listed = targets.as_array().map_or(0, Vec::len);
        let dir = self.session.sandbox.tmp().join("backup");
        std::fs::create_dir_all(&dir).map_err(|err| {
            LiveAbort::Setup(format!("cannot create the backup directory: {err}"))
        })?;
        let dir_text = dir.display().to_string();
        let exec = self.rust(
            "redteam targets backup (rs)",
            &["redteam", "targets", "backup", "--output-dir", &dir_text],
        )?;
        let (agree, note) = match (exec.code, backup_ok(&dir, listed)) {
            (Some(0), Ok(())) if listed == 0 => (true, "no target, no file".to_owned()),
            (Some(0 | 1), Ok(())) if listed > 0 => {
                (true, "one 0600 file in the airs-cli-rs format".to_owned())
            }
            (_, Err(problem)) => (false, problem.to_owned()),
            _ => (false, "unexpected exit".to_owned()),
        };
        self.row("redteam targets backup (rs)", &exec, None, agree, &note);
        let _ = std::fs::remove_dir_all(&dir);
        // The environment report on both CLIs.
        let mut runs = Vec::new();
        for (cli, label) in [
            (&self.session.plan.rust, "rs"),
            (&self.session.plan.ts, "ts"),
        ] {
            let dir = self.session.sandbox.tmp().join(label);
            std::fs::create_dir_all(&dir).map_err(|err| {
                LiveAbort::Setup(format!("cannot create the report directory: {err}"))
            })?;
            let path = dir.join("rt.html");
            let path_text = path.display().to_string();
            let exec = self.session.exec(
                cli,
                "redteam report",
                &["redteam", "report", "--output-file", &path_text],
            )?;
            let private = std::fs::metadata(&path)
                .is_ok_and(|metadata| metadata.permissions().mode() & 0o777 == 0o600);
            let _ = std::fs::remove_dir_all(&dir);
            runs.push((exec, private));
        }
        let (rust, rust_private) = &runs[0];
        let (ts, ts_private) = &runs[1];
        let agree = rust.code == ts.code
            && *rust_private
            && *ts_private
            && incomplete_line(&rust.stderr) == incomplete_line(&ts.stderr);
        self.row(
            "redteam report (environment)",
            rust,
            Some(ts),
            agree,
            "exit, 0600 files and incomplete sources equal; HTML not compared",
        );
        Ok(())
    }
}

/// Runs the red team reads and returns the sanitized summary.
pub fn run_live_redteam_reads(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
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
    fn no_access_is_a_401_403_or_404() {
        assert!(no_access(Some(1), "\n  ✗ Error: x\n    HTTP 403\n"));
        assert!(no_access(Some(1), "    HTTP 404\n"));
        assert!(!no_access(Some(1), "    HTTP 500\n"));
        assert!(!no_access(Some(0), "    HTTP 403\n"));
    }

    #[test]
    fn redaction_checks_every_credential_path() {
        assert!(credentials_redacted(&json!({
            "authConfig": {"auth_header": {"Authorization": "[REDACTED]"}, "basic_auth_location": "HEADER"},
            "connectionParams": {"request_headers": {"Content-Type": "application/json", "apikey": "[REDACTED]"}, "curl": "", "target_connection_config": {"api_key": "[REDACTED]", "model_name": "m"}},
            "adapterVariableOverrides": [{"key": "a", "value": "v", "type": "VAR"}, {"key": "b", "value": "[REDACTED]", "type": "SECRET"}]
        })));
        assert!(!credentials_redacted(
            &json!({"authConfig": {"auth_header": {"Authorization": "Bearer x"}}})
        ));
        assert!(!credentials_redacted(
            &json!({"connectionParams": {"request_headers": {"apikey": "x"}}})
        ));
        assert!(!credentials_redacted(
            &json!({"adapterVariableOverrides": [{"value": "x", "type": "SECRET"}]})
        ));
        assert!(credentials_redacted(&json!({"name": "t"})));
        // The management 0.86.0 paths (scm-sdk 0.2.3): `audio_curl`, the basic
        // credentials and the Vertex AI settings.
        assert!(credentials_redacted(&json!({
            "authConfig": {"basic_username": "[REDACTED]", "basic_password": "[REDACTED]"},
            "connectionParams": {
                "audio_curl": "[REDACTED]",
                "audio_request_json": {"audio": "{AUDIO}"},
                "multi_turn_config": {"type": "client_session"},
                "target_connection_config": {"project_id": "[REDACTED]", "customer_sa_email": "[REDACTED]"}
            }
        })));
        assert!(!credentials_redacted(
            &json!({"connectionParams": {"audio_curl": "curl -H 'Authorization: Bearer x'"}})
        ));
        assert!(!credentials_redacted(
            &json!({"authConfig": {"basic_password": "x"}})
        ));
        assert!(!credentials_redacted(
            &json!({"connectionParams": {"target_connection_config": {"project_id": "p"}}})
        ));
    }

    #[test]
    fn an_empty_typescript_list_line_equals_an_empty_rust_listing() {
        // D146: TypeScript prints the `No … found` line in json and table too.
        let adapters = "  No adapters found\n";
        let sets = "  No prompt sets found\n";
        assert!(ts_empty_list(adapters, "adapters"));
        assert!(ts_empty_list(sets, "prompt sets"));
        assert!(!ts_empty_list(adapters, "prompt sets"));
        assert!(!ts_empty_list("No adapters found\n", "adapters"));
        assert!(json_runs_agree(
            (Some(0), "[]\n"),
            (Some(0), adapters),
            Some("adapters")
        ));
        assert!(json_runs_agree(
            (Some(0), "[]\n"),
            (Some(0), "[]\n"),
            Some("adapters")
        ));
        // Only the named resource, only on exit 0, only against an empty Rust listing.
        assert!(!json_runs_agree(
            (Some(0), "[]\n"),
            (Some(0), adapters),
            None
        ));
        assert!(!json_runs_agree(
            (Some(0), "[]\n"),
            (Some(1), adapters),
            Some("adapters")
        ));
        assert!(!json_runs_agree(
            (Some(0), "[{\"uuid\": \"a\"}]\n"),
            (Some(0), adapters),
            Some("adapters")
        ));
        assert!(!json_runs_agree(
            (Some(0), "  No adapters found\n"),
            (Some(0), adapters),
            Some("adapters")
        ));
        assert_eq!(
            rows_subset(
                &ts_list_json(Some(0), sets, Some("prompt sets")),
                &json!([])
            ),
            Some(true)
        );
        assert_eq!(
            ts_list_json(Some(1), sets, Some("prompt sets")),
            Value::Null
        );
        assert_eq!(
            statuses_agree(
                &json!([]),
                &ts_list_json(Some(0), "  No scans found\n", Some("scans"))
            ),
            Some((true, 0))
        );
        assert_eq!(
            target_multiset(&ts_list_json(
                Some(0),
                "  No targets found\n",
                Some("targets")
            )),
            Some(Vec::new())
        );
        let table = ts_list_table(Some(0), "  No targets found\n", "targets");
        assert!(compare_tables("", table, TARGET_TABLE_COLUMNS).0);
        assert!(
            !compare_tables(
                "",
                ts_list_table(Some(1), "  No targets found\n", "targets"),
                TARGET_TABLE_COLUMNS
            )
            .0
        );
    }

    #[test]
    fn a_backup_of_no_target_writes_no_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(backup_ok(dir.path(), 0), Ok(()));
        assert!(backup_ok(dir.path(), 1).is_err());
        std::fs::write(dir.path().join("b.json"), "{}").unwrap();
        assert!(backup_ok(dir.path(), 0).is_err());
    }

    #[test]
    fn listings_compare_as_sets() {
        let rust = json!([{"id": "a", "status": "RUNNING"}, {"id": "b", "status": "COMPLETED"}]);
        let ts = json!([{"id": "b", "status": "COMPLETED"}, {"id": "c", "status": "QUEUED"}]);
        assert_eq!(statuses_agree(&rust, &ts), Some((true, 1)));
        let ts = json!([{"id": "b", "status": "FAILED"}]);
        assert_eq!(statuses_agree(&rust, &ts), Some((false, 1)));
        assert_eq!(
            rows_subset(&json!([{"id": "a"}]), &json!([{"id": "a"}, {"id": "b"}])),
            Some(true)
        );
        assert_eq!(
            rows_subset(&json!([{"id": "c"}]), &json!([{"id": "a"}])),
            Some(false)
        );
        assert_eq!(
            target_multiset(&json!([{"name": "b", "status": "active", "type": "MODEL"}, {"name": "a", "status": "inactive", "type": "AGENT"}])).unwrap()[0].0,
            "a"
        );
    }
}
