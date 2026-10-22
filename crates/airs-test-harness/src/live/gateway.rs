//! The M6e live gateway reads (DESIGN §10, "M6e Gateway").
//!
//! [`run_live_gateway_reads`] runs only when `tests/live.rs` passes the read gate
//! (`AIRS_RS_LIVE=1` and `AIRS_E2E_TENANT`), or against the loopback fixture server
//! through [`super::LiveTarget::loopback`]. It is its own run (run id, private store,
//! fingerprints, leak checks, 90 s per CLI run) and read-only on both CLIs: the session
//! guard refuses every gateway write and every `inference` command on either CLI
//! ([`super::gateway_refusal`]); the TypeScript CLI is sandboxed as in every live run and
//! runs the same leaves under `aigateway` (D227). Both CLIs run with `TZ=UTC` here.
//!
//! Three gates come first: Rust `gateway workspaces list --output json` (the data plane),
//! `--plane admin` (the admin plane) and `gateway scopes list` (IAM). A gate that fails
//! with HTTP 401, 403 or 404 runs the TypeScript list once (`--output table`): both failing
//! so is a notice (`gateway unavailable`, …) and the plane's checks are skipped; one side
//! only is a mismatch. TypeScript runs only where its output cannot show a credential
//! (workspaces, scopes, `telemetry requests`, the list tables, whose columns omit
//! objects; choice 65); the reads that can carry one run on the Rust side only and assert
//! that every credential is withheld. Tenant content is compared in memory only: rows and
//! notices hold fixed texts, counts and HTTP statuses.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::runtime::{same_shape, table_part};
use super::{Exec, LiveAbort, LivePlan, LiveReport, LiveRow, RunPlace, Session};
use crate::compare::json_semantic_eq;

/// The marker of a withheld value (D238).
pub use crate::withhold::WITHHELD;

/// The HTTP status of a failed run's stderr: the Rust `    HTTP <s>` line, or a
/// TypeScript `(HTTP <s>)` / `HTTP <s>` mention.
pub fn http_status(stderr: &str) -> Option<u16> {
    for line in stderr.lines() {
        let trimmed = line.trim();
        if let Some(code) = trimmed.strip_prefix("HTTP ")
            && let Ok(code) = code.parse()
        {
            return Some(code);
        }
        if let Some(at) = line.find("HTTP ") {
            let digits: String = line[at + 5..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if digits.len() == 3
                && let Ok(code) = digits.parse()
            {
                return Some(code);
            }
        }
    }
    None
}

/// Whether a run failed with HTTP 401, 403 or 404 (no access to that plane or read).
fn no_access(exec: &Exec) -> Option<u16> {
    (exec.code != Some(0))
        .then(|| http_status(&exec.stderr))
        .flatten()
        .filter(|status| matches!(status, 401 | 403 | 404))
}

/// The withholding rules of DESIGN §19.3: the CLI's own rules module, compiled into this
/// harness from the CLI's files ([`crate::withhold`], choices 172, 185), so the
/// classification, the action table and the checker below are the CLI's by construction.
pub use crate::withhold::check::is_schema;
pub use crate::withhold::names::{self, is_credential_name};

/// Whether a Rust gateway json document withholds every credential, read the way the CLI
/// reads it: the shared checker [`crate::withhold::check::withheld`] on the parsed output
/// (choice 172). The CLI's own tests run the same checker on everything the CLI prints for the
/// pinned and the generated documents ([`crate::withhold::corpus`]).
pub fn withheld(doc: &Value) -> bool {
    crate::withhold::check::withheld(doc)
}

/// The cells of a table run (from its first `│` line; a banner above it dropped).
fn cells(stdout: &str) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    super::table_cells(&table_part(stdout))
}

/// A table cell holding a JSON object or array (a detail's nested member, printed as
/// compact JSON by both CLIs).
fn json_cell(cell: &str) -> Option<Value> {
    if !cell.starts_with(['{', '[']) {
        return None;
    }
    serde_json::from_str::<Value>(cell)
        .ok()
        .filter(|value| value.is_object() || value.is_array())
}

/// Whether a Rust JSON value stands for a TypeScript one: equal as JSON (key order ignored,
/// D35; numbers as JavaScript reads them), except that a Rust string carrying `[withheld]`
/// may stand for any TypeScript value at that place (D238, D251).
fn json_agrees(rust: &Value, ts: &Value) -> bool {
    match (rust, ts) {
        (Value::String(text), _) if text.contains(WITHHELD) => true,
        (Value::Object(rust), Value::Object(ts)) => {
            rust.len() == ts.len()
                && rust.iter().all(|(name, value)| {
                    ts.get(name).is_some_and(|other| json_agrees(value, other))
                })
        }
        (Value::Array(rust), Value::Array(ts)) => {
            rust.len() == ts.len() && rust.iter().zip(ts).all(|(r, t)| json_agrees(r, t))
        }
        _ => json_semantic_eq(rust, ts),
    }
}

/// How one Rust table cell compares with the TypeScript cell in its place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cell {
    /// The same text.
    Equal,
    /// Both JSON objects or arrays, equal apart from key order (D35: airs-cli-rs prints
    /// nested members sorted, TypeScript in the server's order).
    KeyOrder,
    /// airs-cli-rs shows `[withheld]` where TypeScript shows something else (D238, D251):
    /// more placeholders than TypeScript, or inside a JSON cell a Rust leaf carrying one
    /// where the rest is equal apart from key order.
    Withheld,
    /// Any other difference.
    Differs,
}

fn compare_cell(rust: &str, ts: &str) -> Cell {
    if rust == ts {
        return Cell::Equal;
    }
    if let (Some(rust_json), Some(ts_json)) = (json_cell(rust), json_cell(ts)) {
        return if json_semantic_eq(&rust_json, &ts_json) {
            Cell::KeyOrder
        } else if json_agrees(&rust_json, &ts_json) {
            Cell::Withheld
        } else {
            Cell::Differs
        };
    }
    if rust.matches(WITHHELD).count() > ts.matches(WITHHELD).count() {
        Cell::Withheld
    } else {
        Cell::Differs
    }
}

/// Two `--output table` listings agree: the same header and rows (sorted), each cell
/// equal, equal as JSON apart from key order (D35), or showing `[withheld]` where
/// TypeScript shows something else (D238, D251: TS prints `***`, `[REDACTED]` or the raw
/// value), inside a JSON cell too ([`compare_cell`]). An empty Rust table against a
/// TypeScript listing without a table is an empty list on both (D231).
pub fn tables_agree(rust: &str, ts: &str) -> bool {
    let rust_cells = cells(rust);
    let ts_cells = cells(ts);
    match (rust_cells, ts_cells) {
        (Some((rh, mut rr)), Some((th, mut tr))) => {
            if rh.is_empty() && rr.is_empty() {
                return th.is_empty() && tr.is_empty();
            }
            rr.sort();
            tr.sort();
            rh == th
                && rr.len() == tr.len()
                && rr.iter().zip(&tr).all(|(r, t)| {
                    r.len() == t.len()
                        && r.iter()
                            .zip(t)
                            .all(|(r, t)| compare_cell(r, t) != Cell::Differs)
                })
        }
        (Some((rh, rr)), None) => rh.is_empty() && rr.is_empty() && !ts.contains('│'),
        _ => false,
    }
}

/// A field or column name the summary may print: letters, `_` and spaces only, at most 40
/// characters (a member name such as `object` or a TS label such as `Created At`; anything
/// that could be tenant content, a slug or an id with digits, a marker, is not).
fn printable_name(name: &str) -> bool {
    (1..=40).contains(&name.chars().count())
        && name
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '_' || c == ' ')
}

/// The names of `names` absent from `other`, sorted.
fn only_in<'a>(names: &'a [String], other: &[String]) -> BTreeSet<&'a String> {
    names.iter().filter(|name| !other.contains(name)).collect()
}

/// The airs-cli-rs-only names: the printable ones by name and the count of the rest (the
/// Rust output passed the withholding policy, and a name with digits or a marker is counted
/// only).
fn rust_names_note(side: &str, missing: BTreeSet<&String>) -> Option<String> {
    let mut parts: Vec<String> = missing
        .iter()
        .filter(|name| printable_name(name))
        .map(|name| (*name).clone())
        .collect();
    let masked = missing.len() - parts.len();
    if masked > 0 {
        parts.push(format!("{masked} unprintable"));
    }
    (!parts.is_empty()).then(|| format!("{side} only: {}", parts.join(", ")))
}

/// The TypeScript-only names: their count only (choice 155: D47 drops a member exactly when
/// its name carries a registered secret, so a TypeScript-only name can be a letters-only
/// credential).
fn ts_names_note(side: &str, missing: BTreeSet<&String>) -> Option<String> {
    (!missing.is_empty()).then(|| format!("{side} only: {}", missing.len()))
}

/// The cell counts over the paired rows of two tables ([`table_pairs`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CellCounts {
    withheld: usize,
    placeholders: usize,
    key_order: usize,
    other: usize,
}

/// The paired rows of two tables: for a `Field │ Value` detail on both sides the rows of the
/// same field, for lists with equal headers and row counts the rows in sorted order, else
/// none.
fn table_pairs<'a>(
    rust: &'a (Vec<String>, Vec<Vec<String>>),
    ts: &'a (Vec<String>, Vec<Vec<String>>),
) -> Vec<(&'a Vec<String>, &'a Vec<String>)> {
    let ((rust_header, rust_rows), (ts_header, ts_rows)) = (rust, ts);
    if rust_header == &["Field", "Value"] && ts_header == rust_header {
        rust_rows
            .iter()
            .filter_map(|row| {
                ts_rows
                    .iter()
                    .find(|other| other[0] == row[0])
                    .map(|other| (row, other))
            })
            .collect()
    } else if rust_header == ts_header && rust_rows.len() == ts_rows.len() {
        let mut rust_sorted: Vec<&Vec<String>> = rust_rows.iter().collect();
        let mut ts_sorted: Vec<&Vec<String>> = ts_rows.iter().collect();
        rust_sorted.sort();
        ts_sorted.sort();
        rust_sorted.into_iter().zip(ts_sorted).collect()
    } else {
        Vec::new()
    }
}

fn cell_counts(pairs: &[(&Vec<String>, &Vec<String>)]) -> CellCounts {
    let mut counts = CellCounts::default();
    for (rust_row, ts_row) in pairs {
        for (rust_cell, ts_cell) in rust_row.iter().zip(ts_row.iter()) {
            match compare_cell(rust_cell, ts_cell) {
                Cell::Equal => {}
                Cell::KeyOrder => counts.key_order += 1,
                Cell::Withheld => {
                    counts.withheld += 1;
                    counts.placeholders += rust_cell
                        .matches(WITHHELD)
                        .count()
                        .saturating_sub(ts_cell.matches(WITHHELD).count());
                }
                Cell::Differs => counts.other += 1,
            }
        }
    }
    counts
}

/// The note of two agreeing tables: `equal`, and the count of JSON cells equal apart from
/// key order when there are any (D35).
pub fn agree_note(rust: &str, ts: &str, equal: &str) -> String {
    let key_order = match (cells(rust), cells(ts)) {
        (Some(rust), Some(ts)) => cell_counts(&table_pairs(&rust, &ts)).key_order,
        _ => 0,
    };
    if key_order > 0 {
        format!("{equal}; JSON cells equal apart from key order: {key_order} (D35)")
    } else {
        equal.to_owned()
    }
}

/// Why two `--output table` runs disagree, from their shapes only (choices 149, 155): the
/// row counts, whether the headers are equal (the airs-cli-rs-only column names, the count
/// of the TypeScript-only ones), for a `Field │ Value` detail the field names on one side
/// only (the same way), and, over the paired rows ([`table_pairs`]), the cells where
/// airs-cli-rs shows `[withheld]` and TypeScript does not (with the placeholder count), the
/// JSON cells equal apart from key order (D35) and the other differing cells. No cell value
/// and no TypeScript-only name is ever printed, so the summary carries no tenant content.
pub fn table_note(rust: &str, ts: &str) -> String {
    let (Some(rust_table), Some(ts_table)) = (cells(rust), cells(ts)) else {
        return format!(
            "tables differ: {}",
            match (cells(rust).is_some(), cells(ts).is_some()) {
                (false, false) => "neither output is one table",
                (false, true) => "the airs-cli-rs output is not one table",
                _ => "the TypeScript output is not one table",
            }
        );
    };
    let ((rust_header, rust_rows), (ts_header, ts_rows)) = (&rust_table, &ts_table);
    let mut notes = vec![format!(
        "rows {}/{} (airs-cli-rs/TypeScript)",
        rust_rows.len(),
        ts_rows.len()
    )];
    if rust_header == ts_header {
        notes.push("header equal".into());
    } else {
        notes.push("header differs".into());
        notes.extend(rust_names_note(
            "columns airs-cli-rs",
            only_in(rust_header, ts_header),
        ));
        notes.extend(ts_names_note(
            "columns TypeScript",
            only_in(ts_header, rust_header),
        ));
    }
    if rust_header == &["Field", "Value"] && ts_header == rust_header {
        let field = |rows: &[Vec<String>]| -> Vec<String> {
            rows.iter().map(|row| row[0].clone()).collect()
        };
        let (rust_fields, ts_fields) = (field(rust_rows), field(ts_rows));
        notes.extend(rust_names_note(
            "fields airs-cli-rs",
            only_in(&rust_fields, &ts_fields),
        ));
        notes.extend(ts_names_note(
            "fields TypeScript",
            only_in(&ts_fields, &rust_fields),
        ));
    }
    let pairs = table_pairs(&rust_table, &ts_table);
    if !pairs.is_empty() {
        let counts = cell_counts(&pairs);
        notes.push(format!(
            "cells withheld by airs-cli-rs only: {} ({} placeholders)",
            counts.withheld, counts.placeholders
        ));
        notes.push(format!(
            "JSON cells equal apart from key order: {}",
            counts.key_order
        ));
        notes.push(format!("other differing cells: {}", counts.other));
    }
    format!("tables differ: {}", notes.join("; "))
}

/// The comparable parts of a gateway report file (the shared environment template).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReportShape {
    pub sections: Vec<String>,
    /// `(source, window, status, notes)` of each evidence row.
    pub evidence: Vec<(String, String, String, String)>,
    pub csp: bool,
    pub external: bool,
}

/// The section ids, the evidence rows (`table-5`), the CSP meta and any external
/// reference of a gateway report.
pub fn report_shape(html: &str) -> Option<ReportShape> {
    if !html.starts_with("<!doctype html>") {
        return None;
    }
    let sections = html
        .match_indices("<section id=\"")
        .filter_map(|(at, mark)| {
            let rest = &html[at + mark.len()..];
            rest.find('"').map(|end| rest[..end].to_owned())
        })
        .collect();
    let evidence = html
        .find("<section id=\"table-5\">")
        .map(|at| {
            let section = &html[at..];
            let section = &section[..section.find("</section>").unwrap_or(section.len())];
            section
                .split("<tr>")
                .skip(2)
                .filter_map(|row| {
                    let cells: Vec<&str> = row
                        .split("<td>")
                        .skip(1)
                        .map(|cell| cell.split("</td>").next().unwrap_or_default())
                        .collect();
                    (cells.len() >= 7).then(|| {
                        (
                            cells[0].to_owned(),
                            cells[2].to_owned(),
                            cells[3].to_owned(),
                            cells[6].to_owned(),
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let lower = html.to_ascii_lowercase();
    Some(ReportShape {
        sections,
        evidence,
        csp: lower.contains("<meta http-equiv=\"content-security-policy\""),
        external: lower.contains("src=") || lower.contains("http://") || lower.contains("https://"),
    })
}

/// The generic validation note of a report source.
const VALIDATION_NOTE: &str =
    "Request, scope or response validation failed; upstream details omitted.";

/// The two reports agree: the same sections, evidence sources, windows and statuses (D249
/// tolerated: a Rust `telemetry.logs` or `telemetry.groupedErrors` that is not complete
/// with the validation note against a complete TypeScript one, a time TS read in its
/// zone), a CSP and no external reference on both.
pub fn reports_agree(rust: &ReportShape, ts: &ReportShape) -> bool {
    rust.sections == ts.sections
        && rust.csp
        && ts.csp
        && !rust.external
        && !ts.external
        && rust.evidence.len() == ts.evidence.len()
        && rust.evidence.iter().zip(&ts.evidence).all(|(r, t)| {
            r.0 == t.0
                && r.1 == t.1
                && (r.2 == t.2
                    || (matches!(r.0.as_str(), "telemetry.logs" | "telemetry.groupedErrors")
                        && t.2 == "complete"
                        && r.3.contains(VALIDATION_NOTE)))
        })
}

/// The pinned window of the run (DESIGN §10 M6e): the hour before `now`, both ends cut to
/// the minute and written with `Z`.
pub fn pinned_window(now: SystemTime) -> (String, String) {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let end = seconds - seconds % 60;
    (iso_minute(end - 3600), iso_minute(end))
}

/// `YYYY-MM-DDTHH:MM:00Z` of Unix seconds.
fn iso_minute(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rest = seconds % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:00Z",
        rest / 3600,
        rest % 3600 / 60
    )
}

/// The Rust `Gateway API` doctor entry against the TypeScript `AI Gateway API` entry:
/// equal statuses; D250 tolerated (a TypeScript `fail` against a Rust `fail` or `warn`
/// for a 5xx or 429).
pub fn doctor_agrees(rust: &Value, ts: &Value) -> Option<bool> {
    let entry = |doc: &Value, name: &str| -> Option<(String, String)> {
        doc.as_array()?.iter().find_map(|check| {
            (check.get("name")?.as_str()? == name).then(|| {
                (
                    check
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    check
                        .get("detail")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
        })
    };
    let (rust_status, rust_detail) = entry(rust, "Gateway API")?;
    let (ts_status, _) = entry(ts, "AI Gateway API")?;
    Some(
        rust_status == ts_status
            || (ts_status == "fail"
                && matches!(rust_status.as_str(), "fail" | "warn")
                && (rust_detail.contains("HTTP 5") || rust_detail.contains("HTTP 429"))),
    )
}

fn mode_of(path: &Path) -> Option<u32> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o777)
}

/// Which planes answered their gate.
#[derive(Clone, Copy, Debug, Default)]
struct Planes {
    data: bool,
    admin: bool,
    iam: bool,
}

struct Reads<'s, 'p> {
    session: &'s mut Session<'p>,
    start: String,
    end: String,
}

/// `TZ=UTC` for every run of this part (the TypeScript window bytes, G41; Rust ignores
/// it).
fn utc<'a>() -> RunPlace<'a> {
    RunPlace {
        utc: true,
        ..RunPlace::default()
    }
}

/// The note of a table comparison: `equal` when the tables agree (with the count of JSON
/// cells equal apart from key order, [`agree_note`]), else the exit codes when a run failed,
/// else the structural [`table_note`].
fn mismatch_note(agree: bool, equal: &str, rust: &Exec, ts: &Exec) -> String {
    if agree {
        agree_note(&rust.stdout, &ts.stdout, equal)
    } else if rust.code != Some(0) || ts.code != Some(0) {
        "tables differ: a run failed".to_owned()
    } else {
        table_note(&rust.stdout, &ts.stdout)
    }
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

    fn notice(&mut self, text: String) {
        self.session.report.notices.push(text);
    }

    /// One Rust run (`gateway <args>`).
    fn rust(&self, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        self.session.rust_runs.set(self.session.rust_runs.get() + 1);
        let mut full = vec!["gateway"];
        full.extend_from_slice(args);
        self.session
            .run_in(&self.session.plan.rust, check, &full, &utc())
    }

    /// One TypeScript run (`aigateway <args>`).
    fn ts(&self, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        self.session.ts_runs.set(self.session.ts_runs.get() + 1);
        let mut full = vec!["aigateway"];
        full.extend_from_slice(args);
        self.session
            .run_in(&self.session.plan.ts, check, &full, &utc())
    }

    /// Both CLIs; a run pair that both end in 401/403/404 is `unavailable` (notice).
    fn both(&mut self, check: &str, args: &[&str]) -> Result<Option<(Exec, Exec)>, LiveAbort> {
        let rust = self.rust(check, args)?;
        let ts = self.ts(check, args)?;
        if let (Some(r), Some(t)) = (no_access(&rust), no_access(&ts)) {
            let note = if r == t {
                format!("unavailable: HTTP {r} on both CLIs")
            } else {
                format!("unavailable: HTTP {r} / HTTP {t}")
            };
            self.row(check, &rust, Some(&ts), true, &note);
            self.notice(format!("{check} {note}"));
            return Ok(None);
        }
        Ok(Some((rust, ts)))
    }

    /// A gate: the Rust json list; on 401/403/404 the TypeScript table once. `Ok(None)`
    /// when the plane is unavailable on both (notice) or the gate mismatched.
    fn gate(
        &mut self,
        check: &str,
        args: &[&str],
        unavailable: &str,
    ) -> Result<Option<Exec>, LiveAbort> {
        let mut json = args.to_vec();
        json.extend(["--output", "json"]);
        let rust = self.rust(check, &json)?;
        if rust.code == Some(0) {
            return Ok(Some(rust));
        }
        let mut table = args.to_vec();
        table.extend(["--output", "table"]);
        let ts = self.ts(check, &table)?;
        match (no_access(&rust), no_access(&ts)) {
            (Some(r), Some(t)) => {
                let note = format!("unavailable: HTTP {r} on both CLIs");
                self.row(check, &rust, Some(&ts), true, &note);
                self.notice(format!(
                    "{unavailable}: HTTP {r} on both CLIs ({t} on the TypeScript side)"
                ));
            }
            _ => self.row(
                check,
                &rust,
                Some(&ts),
                false,
                "the gate failed on one side only",
            ),
        }
        Ok(None)
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        let mut planes = Planes::default();
        let data = self.gate(
            "workspaces list (gate)",
            &["workspaces", "list"],
            "gateway unavailable",
        )?;
        let first = data.as_ref().and_then(|exec| {
            let rows = exec.json();
            let row = rows.as_array()?.first()?;
            Some((
                row.get("slug")?.as_str()?.to_owned(),
                row.get("id")?.as_str()?.to_owned(),
            ))
        });
        planes.data = data.is_some();
        let admin = self.gate(
            "workspaces list --plane admin (gate)",
            &["workspaces", "list", "--plane", "admin"],
            "gateway admin plane unavailable",
        )?;
        planes.admin = admin.is_some();
        let iam = self.gate(
            "scopes list (gate)",
            &["scopes", "list"],
            "IAM scopes unavailable",
        )?;
        planes.iam = iam.is_some();
        if planes.data {
            self.workspaces(&["workspaces", "list"], "workspaces list")?;
            match &first {
                Some((slug, id)) => {
                    self.workspace_get(slug)?;
                    self.telemetry(slug)?;
                    self.data_inventory(id)?;
                    self.report(slug)?;
                }
                None => self.notice(
                    "workspace-bound checks skipped: the data-plane listing returned no workspace"
                        .into(),
                ),
            }
        }
        if planes.admin {
            self.workspaces(
                &["workspaces", "list", "--plane", "admin"],
                "workspaces list --plane admin",
            )?;
            self.admin_inventory()?;
        }
        if planes.iam {
            self.scopes()?;
        }
        self.doctor()
    }

    /// `workspaces list`: json rows equal (D231: TS's `No workspaces found` against `[]`)
    /// and the table cells equal (D53).
    fn workspaces(&mut self, args: &[&str], check: &str) -> Result<(), LiveAbort> {
        let mut json = args.to_vec();
        json.extend(["--output", "json"]);
        let name = format!("{check} --output json");
        if let Some((rust, ts)) = self.both(&name, &json)? {
            let rust_doc = rust.json();
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && (json_semantic_eq(&rust_doc, &ts.json())
                    || (rust_doc == Value::Array(Vec::new())
                        && ts.stdout.contains("No workspaces found")));
            self.row(
                &name,
                &rust,
                Some(&ts),
                agree,
                if agree {
                    "rows equal (D231)"
                } else {
                    "rows differ"
                },
            );
        }
        let mut table = args.to_vec();
        table.extend(["--output", "table"]);
        let name = format!("{check} --output table");
        if let Some((rust, ts)) = self.both(&name, &table)? {
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && tables_agree(&rust.stdout, &ts.stdout);
            let note = mismatch_note(agree, "cells equal (D53)", &rust, &ts);
            self.row(&name, &rust, Some(&ts), agree, &note);
        }
        Ok(())
    }

    fn workspace_get(&mut self, slug: &str) -> Result<(), LiveAbort> {
        let check = "workspaces get <first data-plane slug>";
        if let Some((rust, ts)) =
            self.both(check, &["workspaces", "get", slug, "--output", "json"])?
        {
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && json_semantic_eq(&rust.json(), &ts.json());
            self.row(
                check,
                &rust,
                Some(&ts),
                agree,
                if agree {
                    "projections equal (D35)"
                } else {
                    "projections differ"
                },
            );
        }
        Ok(())
    }

    fn scopes(&mut self) -> Result<(), LiveAbort> {
        let check = "scopes list --output json";
        if let Some((rust, ts)) = self.both(check, &["scopes", "list", "--output", "json"])? {
            let rust_doc = rust.json();
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && (json_semantic_eq(&rust_doc, &ts.json())
                    || (rust_doc == Value::Array(Vec::new())
                        && ts.stdout.contains("No IAM scopes found")));
            self.row(
                check,
                &rust,
                Some(&ts),
                agree,
                if agree {
                    "rows equal (D231)"
                } else {
                    "rows differ"
                },
            );
        }
        Ok(())
    }

    /// `telemetry requests` over the pinned window: the envelopes equal in shape.
    fn telemetry(&mut self, slug: &str) -> Result<(), LiveAbort> {
        let check = "telemetry requests <pinned window>";
        let (start, end) = (self.start.clone(), self.end.clone());
        let args = [
            "telemetry",
            "requests",
            "--workspace",
            slug,
            "--start",
            &start,
            "--end",
            &end,
            "--output",
            "json",
        ];
        if let Some((rust, ts)) = self.both(check, &args)? {
            let agree =
                rust.code == Some(0) && ts.code == Some(0) && same_shape(&rust.json(), &ts.json());
            self.row(
                check,
                &rust,
                Some(&ts),
                agree,
                if agree {
                    "same shape (live aggregates)"
                } else {
                    "shapes differ"
                },
            );
        }
        Ok(())
    }

    /// A list on both CLIs, `--output table` on the TypeScript side (choice 65).
    fn table(&mut self, check: &str, args: &[&str]) -> Result<(), LiveAbort> {
        let mut full = args.to_vec();
        full.extend(["--output", "table"]);
        if let Some((rust, ts)) = self.both(check, &full)? {
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && tables_agree(&rust.stdout, &ts.stdout);
            let note = mismatch_note(agree, "cells equal (D238)", &rust, &ts);
            self.row(check, &rust, Some(&ts), agree, &note);
        }
        Ok(())
    }

    /// A Rust-only json read that must withhold every credential; the first item's `id`
    /// when it is a list.
    fn withheld_read(&mut self, check: &str, args: &[&str]) -> Result<Option<String>, LiveAbort> {
        let mut full = args.to_vec();
        full.extend(["--output", "json"]);
        let rust = self.rust(check, &full)?;
        if let Some(status) = no_access(&rust) {
            let note = format!("unavailable: HTTP {status}");
            self.row(check, &rust, None, true, &note);
            self.notice(format!("{check} {note}"));
            return Ok(None);
        }
        let doc = rust.json();
        let ok = rust.code == Some(0) && withheld(&doc);
        self.row(
            check,
            &rust,
            None,
            ok,
            if ok {
                "credentials withheld (D238, D239, D251)"
            } else {
                "a credential was printed or the read failed"
            },
        );
        Ok(doc
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| row.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned))
    }

    /// The data-plane inventory: the list tables on both, the gets on the Rust side.
    fn data_inventory(&mut self, workspace: &str) -> Result<(), LiveAbort> {
        let (start, end) = (self.start.clone(), self.end.clone());
        for (check, group) in [
            ("configs list (table)", vec!["configs"]),
            ("guardrails list (table)", vec!["guardrails"]),
            ("api-keys service list (table)", vec!["api-keys", "service"]),
            ("api-keys user list (table)", vec!["api-keys", "user"]),
        ] {
            let mut args = group.clone();
            args.extend(["list", "--workspace", workspace]);
            self.table(check, &args)?;
            let mut json = group.clone();
            json.extend(["list", "--workspace", workspace]);
            let first = self.withheld_read(
                &format!("{} (rs json)", check.trim_end_matches(" (table)")),
                &json,
            )?;
            match first {
                Some(id) => {
                    let mut get = group.clone();
                    get.extend(["get", &id]);
                    self.withheld_read(
                        &format!("{} get <first> (rs json)", group.join(" ")),
                        &get,
                    )?;
                }
                None => self.notice(format!("{} get skipped: no item listed", group.join(" "))),
            }
        }
        let first = self.withheld_read(
            "providers list (rs json)",
            &["providers", "list", "--workspace", workspace],
        )?;
        if let Some(id) = first {
            self.withheld_read(
                "providers get <first> (rs json)",
                &["providers", "get", &id],
            )?;
        }
        self.withheld_read(
            "telemetry logs list --page-size 5 (rs json)",
            &[
                "telemetry",
                "logs",
                "list",
                "--page-size",
                "5",
                "--workspace",
                workspace,
                "--start",
                &start,
                "--end",
                &end,
            ],
        )?;
        Ok(())
    }

    /// The admin-plane inventory.
    fn admin_inventory(&mut self) -> Result<(), LiveAbort> {
        let (start, end) = (self.start.clone(), self.end.clone());
        for (check, args, get) in [
            (
                "integrations list (table)",
                vec!["integrations", "list"],
                Some(vec!["integrations", "get"]),
            ),
            (
                "integrations providers (table)",
                vec!["integrations", "providers"],
                None,
            ),
            (
                "mcp integrations list (table)",
                vec!["mcp", "integrations", "list"],
                Some(vec!["mcp", "integrations", "get"]),
            ),
            (
                "deployments list (table)",
                vec!["deployments", "list"],
                Some(vec!["deployments", "get"]),
            ),
            ("plugins list (table)", vec!["plugins", "list"], None),
            (
                "admin-guardrails list --page-size 20 (table)",
                vec!["admin-guardrails", "list", "--page-size", "20"],
                Some(vec!["admin-guardrails", "get"]),
            ),
            (
                "guardrails catalog (table)",
                vec!["guardrails", "catalog"],
                None,
            ),
        ] {
            self.table(check, &args)?;
            if let Some(get) = get {
                let first = self.withheld_read(
                    &format!("{} (rs json)", check.trim_end_matches(" (table)")),
                    &args,
                )?;
                match first {
                    Some(id) => {
                        let mut full = get.clone();
                        full.push(&id);
                        self.withheld_read(&format!("{} <first> (rs json)", get.join(" ")), &full)?;
                    }
                    None => self.notice(format!("{} skipped: no item listed", get.join(" "))),
                }
            }
        }
        self.withheld_read(
            "audit-logs list (rs json)",
            &["audit-logs", "list", "--start", &start, "--end", &end],
        )?;
        self.withheld_read(
            "organisations self get (rs json)",
            &["organisations", "self", "get"],
        )?;
        self.withheld_read(
            "organisations auth-settings get (rs json)",
            &["organisations", "auth-settings", "get"],
        )?;
        Ok(())
    }

    /// `<sandbox>/tmp/<label>/`, created.
    fn dir(&self, label: &str) -> Result<PathBuf, LiveAbort> {
        let dir = self.session.sandbox.tmp().join(label);
        std::fs::create_dir_all(&dir)
            .map_err(|err| LiveAbort::Setup(format!("cannot create a run directory: {err}")))?;
        Ok(dir)
    }

    /// `report` on both CLIs over the pinned window, into each CLI's own file (TS with
    /// `--output html`), checked and removed at once.
    fn report(&mut self, slug: &str) -> Result<(), LiveAbort> {
        let check = "report --output-file";
        let (start, end) = (self.start.clone(), self.end.clone());
        let mut runs = Vec::new();
        for (label, ts) in [("gw-rs", false), ("gw-ts", true)] {
            let path = self.dir(label)?.join("report.html");
            let path_text = path.display().to_string();
            let mut args = vec![
                "report",
                "--workspace",
                slug,
                "--start",
                &start,
                "--end",
                &end,
                "--output-file",
                path_text.as_str(),
            ];
            let exec = if ts {
                args.extend(["--output", "html"]);
                self.ts(check, &args)?
            } else {
                self.rust(check, &args)?
            };
            let mode = mode_of(&path);
            let html = std::fs::read_to_string(&path).unwrap_or_default();
            let _ = std::fs::remove_dir_all(path.parent().unwrap_or(&path));
            runs.push((exec, mode, html));
        }
        let (rust, rust_mode, rust_html) = &runs[0];
        let (ts, ts_mode, ts_html) = &runs[1];
        let leak = super::leak_in(&self.session.secrets, rust_html).is_some();
        let shapes = report_shape(rust_html).zip(report_shape(ts_html));
        let agree = rust.code == ts.code
            && *rust_mode == Some(0o600)
            && *ts_mode == Some(0o600)
            && !leak
            && shapes.is_some_and(|(r, t)| reports_agree(&r, &t));
        self.row(
            check,
            rust,
            Some(ts),
            agree,
            if agree {
                "0600 files; sections, sources, windows and statuses equal (D249)"
            } else {
                "the reports differ"
            },
        );
        Ok(())
    }

    /// `doctor --output json`: `Gateway API` against TS `AI Gateway API` (D250).
    fn doctor(&mut self) -> Result<(), LiveAbort> {
        let check = "doctor Gateway API";
        self.session.rust_runs.set(self.session.rust_runs.get() + 1);
        let rust = self.session.run_in(
            &self.session.plan.rust,
            check,
            &["doctor", "--output", "json"],
            &utc(),
        )?;
        self.session.ts_runs.set(self.session.ts_runs.get() + 1);
        let ts = self.session.run_in(
            &self.session.plan.ts,
            check,
            &["doctor", "--output", "json"],
            &utc(),
        )?;
        let agree = doctor_agrees(&rust.json(), &ts.json()) == Some(true);
        self.row(
            check,
            &rust,
            Some(&ts),
            agree,
            if agree {
                "statuses equal (D250)"
            } else {
                "statuses differ"
            },
        );
        Ok(())
    }
}

/// Runs the gateway reads and returns the sanitized summary.
pub fn run_live_gateway_reads(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
    run_live_gateway_reads_at(plan, SystemTime::now())
}

/// [`run_live_gateway_reads`] with the run's start time (the pinned window).
pub fn run_live_gateway_reads_at(
    plan: &LivePlan,
    now: SystemTime,
) -> Result<LiveReport, LiveAbort> {
    let mut session = Session::open(plan)?;
    let (start, end) = pinned_window(now);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut reads = Reads {
            session: &mut session,
            start,
            end,
        };
        reads.steps()?;
        reads.session.verify()?;
        reads.session.summary_check()
    }));
    for label in ["gw-rs", "gw-ts"] {
        let _ = std::fs::remove_dir_all(session.sandbox.tmp().join(label));
    }
    session.report.store_removed = Some(session.store.remove());
    match outcome {
        Err(panic) => std::panic::resume_unwind(panic),
        Ok(result) => result?,
    }
    session.report.rust_runs = session.rust_runs.get();
    session.report.ts_runs = session.ts_runs.get();
    Ok(session.report)
}

/// The routes a gateway live flow may reach: `GET` only, and never an inference route
/// (`/ai_gw/inference`); a self-test checks the fixture's request log with it.
pub fn reads_only(requests: &[crate::RecordedRequest]) -> Result<(), String> {
    let bad: BTreeSet<String> = requests
        .iter()
        .filter(|request| match request.route {
            crate::Route::Gateway(gw) => request.method != "GET" || gw.is_inference(),
            _ => false,
        })
        .map(crate::RecordedRequest::line)
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the live flow sent {} non-read gateway request(s)",
            bad.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn statuses_are_read_from_either_cli() {
        assert_eq!(http_status("\n  ✗ Error: x\n    HTTP 403\n"), Some(403));
        assert_eq!(http_status("  ✗ Failed (HTTP 404). Try again\n"), Some(404));
        assert_eq!(
            http_status("  ✗ Error: AISEC: HTTP 401 Unauthorized\n"),
            Some(401)
        );
        assert_eq!(http_status("nothing"), None);
    }

    #[test]
    fn credentials_and_urls_must_be_withheld() {
        assert!(withheld(
            &json!([{"id": "a", "key": "[withheld]", "masked_api_key": "ab12", "total_tokens": 5}])
        ));
        assert!(!withheld(
            &json!({"configurations": {"client_secret": "x"}})
        ));
        assert!(!withheld(&json!({"key": {"nested": "x"}})));
        assert!(withheld(
            &json!({"custom_headers": {"x-api": "[withheld]"}})
        ));
        assert!(!withheld(&json!({"custom_headers": {"x-api": "v"}})));
        assert!(withheld(
            &json!({"request_url": "https://[withheld]@host/p?[withheld]#[withheld]"})
        ));
        assert!(withheld(&json!({"request_url": "https://host/p"})));
        assert!(!withheld(&json!({"request_url": "https://host/p?key=1"})));
        assert!(!withheld(&json!({"u": "https://user:pw@host/"})));
        assert!(!withheld(&json!([{"request_body": "{\"a\":1}"}])));
        assert!(!withheld(
            &json!({"rows": [{"vertex_service_account_json": "{\"private_key\":\"x\"}"}]})
        ));
        assert!(!withheld(&json!({"auth_config": {"a": "b"}})));
        assert!(withheld(&json!({"auth_config": "[withheld]"})));
        assert!(!withheld(
            &json!({"config": "{\"targets\":[{\"api_key\":\"x\"}]}"})
        ));
        assert!(withheld(
            &json!({"config": "{\"targets\":[{\"api_key\":\"[withheld]\"}]}"})
        ));
        assert!(withheld(&json!([{"request_body": "[withheld]"}])));
        assert!(!withheld(&Value::Null));
        assert!(is_credential_name("X-Api-Key") && !is_credential_name("api_key_id"));
        // Choice 157: camelCase names and credential words anywhere in a name.
        for name in [
            "clientSecret",
            "awsSessionToken",
            "bearerToken",
            "adminpassword",
            "secret_value",
        ] {
            assert!(!withheld(&json!({"configurations": {name: "v"}})), "{name}");
            assert!(
                withheld(&json!({"configurations": {name: "[withheld]"}})),
                "{name}"
            );
        }
        assert!(withheld(
            &json!({"total_tokens": "3", "tokenizer": "cl100k", "secret_mappings": [{"secret_reference_id": "r"}]})
        ));
        // Choice 163: plural and camelCase-plural token names are credential names.
        for name in ["access_tokens", "refreshTokens", "apiTokens", "tokens"] {
            assert!(!withheld(&json!({"configurations": {name: "v"}})), "{name}");
            assert!(
                !withheld(&json!({"configurations": {name: ["v"]}})),
                "{name}"
            );
        }
        // Choice 165: a credential-named value without text may be printed; one keyed by a
        // credential may not.
        assert!(withheld(
            &json!({"pay_as_you_go": {"request_token": {"price": 0.5}}, "usage": {"completion_tokens_details": {"reasoning_tokens": 1}}})
        ));
        assert!(!withheld(
            &json!({"api_tokens": {"sk-0123456789abcdef0": 1}})
        ));
        // Choice 164: `secret_key` beside a secret anchor is a location, elsewhere a credential.
        assert!(withheld(
            &json!({"secret_mappings": [{"target_field": "api_key", "secret_reference_id": "r", "secret_key": "api_key"}]})
        ));
        assert!(!withheld(
            &json!({"aws": {"secret_key": "v", "region": "us"}})
        ));
    }

    /// D238 rule 3f and D251 read as the CLI reads them (choices 167–169): a text shaped as
    /// a JSON document that serde_json cannot read must be `[withheld]`; every URL inside a
    /// string, the userinfo up to its last `@`, must show no userinfo, query or fragment.
    #[test]
    fn d238_d251_unreadable_json_texts_and_urls_in_prose_must_be_withheld() {
        let key = "sk-proj-abcdefghij0123456789";
        for inner in [
            format!(r#"{{"targets":[{{"api_key":"{key}","note":"\ud83d"}}]}}"#),
            format!(r#"{{"api_key":"{key}","weight":1e400}}"#),
            format!("{}\"{key}\"{}", "[".repeat(129), "]".repeat(129)),
            format!(r#"{{"api_key":"{key}","#),
        ] {
            assert!(serde_json::from_str::<Value>(&inner).is_err(), "{inner}");
            assert!(!withheld(&json!({"config": inner})), "{inner}");
            assert!(!withheld(&json!({"rows": [{"note": [inner]}]})), "{inner}");
        }
        assert!(withheld(
            &json!({"config": "[withheld]", "note": "[INFO] started"})
        ));
        for url in [
            "https://AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY@s3.example.test/b",
            "https://user:pa/ss@host.example/p",
            "https://user:pa?ss@host.example/p",
            "https://user:pa#ss@host.example/p",
            "connect ECONNREFUSED https://admin:Pa55word@llm.internal/v1",
            "connect via https://db.local/x?token=abc",
            " https://admin:hunter2x@db.local/x",
            "a https://h.example/x then http://h2.example/y#frag",
        ] {
            assert!(!withheld(&json!({"error": url})), "{url}");
        }
        for url in [
            "https://[withheld]@s3.example.test/b",
            "connect ECONNREFUSED https://[withheld]@llm.internal/v1",
            "a https://h.example/x then http://h2.example/y#[withheld]",
            "http://h?",
        ] {
            assert!(withheld(&json!({"error": url})), "{url}");
        }
    }

    /// Choice 166: every pinned document runs through this traversal as the CLI's tests run
    /// it through the CLI's (`withhold::tests::corpus::the_live_tier_accepts_what_the_cli_prints`):
    /// what the CLI prints is accepted, and what it receives is refused unless the CLI prints
    /// it as received.
    #[test]
    fn the_pinned_documents_are_checked_as_the_cli_prints_them() {
        for (received, printed) in crate::withhold::corpus::PINNED_DOCUMENTS {
            let as_printed: Value = serde_json::from_str(printed).unwrap();
            assert!(withheld(&as_printed), "printed: {printed}");
            let as_received: Value = serde_json::from_str(received).unwrap();
            assert_eq!(
                withheld(&as_received),
                received == printed,
                "received: {received}"
            );
        }
    }

    /// Choices 181, 183: every rule-independent text (`corpus::REAL_WORLD_TEXTS`) is checked as
    /// the CLI prints it (`withhold::tests::corpus::d238_real_world_texts_print_as_pinned`): the
    /// printed document is accepted, and the received one refused unless it prints as
    /// received (a model id after `token` in prose in one row, under `echo` in another). The
    /// cross-row reading uses the rules module's own text rules (`values::text_withheld`, whose
    /// registrations are filtered by `names::registrable`, as the CLI's are): each `registered`
    /// credential is carried by what the text registers, and no `kept` word is.
    #[test]
    fn the_real_world_texts_are_checked_as_the_cli_prints_them() {
        for case in crate::withhold::corpus::REAL_WORLD_TEXTS {
            let parts = crate::withhold::values::text_withheld(case.text)
                .map(|(_, parts)| parts)
                .unwrap_or_default();
            let carried = |word: &str| parts.iter().any(|part| word.contains(part.as_str()));
            for secret in case.registered {
                assert!(carried(secret), "{}", case.case);
            }
            for word in case.kept {
                assert!(!carried(word), "{}: {word}", case.case);
            }
            let (received, printed) = case.documents();
            let as_printed: Value = serde_json::from_str(&printed).unwrap();
            assert!(withheld(&as_printed), "{}: {printed}", case.case);
            let as_received: Value = serde_json::from_str(&received).unwrap();
            assert_eq!(
                withheld(&as_received),
                case.text == case.printed,
                "{}: {received}",
                case.case
            );
        }
    }

    /// Choice 173: every generated document holds its planted credential where a rule
    /// withholds it, so the live check refuses each one as received (the CLI's
    /// `d238_a_planted_credential_never_prints_in_any_format` proves that what it prints for
    /// each one is accepted and never shows the credential).
    #[test]
    fn every_planted_credential_is_refused() {
        let planted = crate::withhold::corpus::planted();
        assert!(planted.len() > 5000);
        for case in planted {
            let doc: Value = serde_json::from_str(&case.document).unwrap();
            assert!(!withheld(&doc), "{}: {}", case.case, case.document);
        }
    }

    /// Choice 170: a `{"name": …, "value": …}` pair is read as a header with that name.
    #[test]
    fn name_value_pairs_are_read_as_headers() {
        assert!(!withheld(
            &json!({"deployment_config": {"env": [{"name": "OPENAI_API_KEY", "value": "sk-proj-x"}]}})
        ));
        assert!(withheld(
            &json!({"deployment_config": {"env": [{"name": "OPENAI_API_KEY", "value": "[withheld]"}, {"name": "LOG_LEVEL", "value": "info"}]}})
        ));
        assert!(!withheld(
            &json!({"forward_headers": [{"name": "Authorization", "value": "Bearer x"}]})
        ));
        // Choice 187: what describes a credential prints whatever its value (the live
        // `workspaces get` settings), and so do `null` and a boolean; a number and an empty
        // string under a credential name, a credential header's number and a credential under a
        // fingerprint name must be hidden, as must a container under a credential name.
        assert!(!withheld(&json!({"password": 12_345_678})));
        assert!(!withheld(&json!({"secret": ""})));
        assert!(!withheld(
            &json!({"headers": {"Authorization": 12_345_678}})
        ));
        assert!(!withheld(
            &json!({"tags": [{"key": "password", "value": 12_345_678}]})
        ));
        assert!(!withheld(
            &json!({"api_key_hint": "sk-live-1234567890abcdefghij"})
        ));
        assert!(withheld(
            &json!({"password": "[withheld]", "secret": "[withheld]", "client_secret": null, "user_api_key_auto_create": false, "api_key_last4": "wxyz", "headers": {"x-retries": 3}})
        ));
        assert!(withheld(&json!({"settings": {
            "user_api_key_count": 3,
            "user_api_key_max_ttl": 7_776_000,
            "user_api_key_ttl": 2_592_000,
            "user_api_key_rotation_period": "",
            "token_type": "Bearer",
            "api_key_name": "production"
        }})));
        assert!(!withheld(&json!({"credentials": {"pin": 1234}})));
        assert!(withheld(
            &json!({"password": "[withheld]", "prompt_tokens": 3, "is_secret": true})
        ));
        assert!(!withheld(
            &json!({"cert": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"})
        ));
    }

    /// Pairs are read as the CLI reads them: a tag pair's `key` and a non-credential value
    /// are printed, a credential-named pair's value must be hidden; a header map at any
    /// depth (`headers`, `custom_headers`, a pair or a list of pairs under it) must hide
    /// every value but a safe header's.
    #[test]
    fn pairs_and_header_maps_are_read_as_the_cli_reads_them() {
        assert!(withheld(
            &json!([{"id": "x", "tags": [{"key": "env", "value": "prod"}]}])
        ));
        assert!(withheld(
            &json!({"tags": [{"key": "x-api-key", "value": "[withheld]"}]})
        ));
        assert!(!withheld(
            &json!({"tags": [{"key": "x-api-key", "value": "v"}]})
        ));
        assert!(withheld(
            &json!({"configurations": {"custom_headers": {"key": "X-T", "value": "[withheld]"}}})
        ));
        assert!(!withheld(
            &json!({"models": [{"configurations": {"custom_headers": {"key": "X-T", "value": "v"}}}]})
        ));
        assert!(withheld(
            &json!({"custom_headers": [{"key": "x-a", "value": "[withheld]"}, {"key": "accept", "value": "*/*"}]})
        ));
        assert!(!withheld(
            &json!({"custom_headers": [{"key": "x-a", "value": "v"}]})
        ));
        assert!(!withheld(
            &json!({"checks": [{"parameters": {"headers": {"X-Functions-Key": "v"}}}]})
        ));
        assert!(withheld(
            &json!({"checks": [{"parameters": {"headers": {"X-Functions-Key": "[withheld]", "Content-Type": "application/json"}}}]})
        ));
        assert!(!withheld(&json!({"headers": "{\"x-h\":\"v\"}"})));
        assert!(withheld(&json!({"headers": "{\"x-h\":\"[withheld]\"}"})));
        assert!(!withheld(&json!({"headers": "X-Api: v"})));
        assert!(withheld(&json!({"headers": null})));
        // Choice 159: a pair is read as one header outside a header map too.
        assert!(!withheld(
            &json!({"tags": [{"key": "x-functions-key", "value": "v"}]})
        ));
        assert!(withheld(
            &json!({"tags": [{"key": "x-functions-key", "value": "[withheld]"}, {"key": "region", "value": "eu"}]})
        ));
    }

    #[test]
    fn tables_tolerate_withheld_cells_and_empty_lists() {
        let rust = " Id │ Key        \n────┼────────────\n a  │ [withheld] \n";
        let ts = "\n  banner\n\n Id │ Key \n────┼─────\n a  │ *** \n";
        assert!(tables_agree(rust, ts));
        assert!(!tables_agree(rust, &ts.replace(" a  ", " b  ")));
        assert!(tables_agree("", "  No configs found\n"));
        assert!(!tables_agree(rust, ""));
    }

    /// Choices 149 and 155: a mismatch note names shapes and counts only: the row counts,
    /// the header, the airs-cli-rs-only field names (a name with digits or a marker masked)
    /// and the count of the TypeScript-only ones (never their names: D47 drops a member whose
    /// name carries a secret), the cells where Rust shows `[withheld]` and TS does not, the
    /// JSON cells equal apart from key order, and the other cells.
    #[test]
    fn table_notes_name_shapes_and_counts_only() {
        let rust = " Field  │ Value                       \n───┼───\n object │ list                        \n evals  │ [{\"type\":\"[withheld]\"},\"[withheld]\"] \n token  │ [withheld]                  \n";
        let ts = " Field │ Value \n───┼───\n object │ list \n evals │ [{\"type\":\"subHeading\"},\"TENANT-WORD\"] \n token │ TENANT-SECRET-0001 \n TENANT-SECRET-0001 │ shown \n created_at │ 2026 \n tenantsecret │ x \n";
        assert!(!tables_agree(rust, ts));
        let note = table_note(rust, ts);
        assert_eq!(
            note,
            "tables differ: rows 3/6 (airs-cli-rs/TypeScript); header equal; fields TypeScript only: 3; cells withheld by airs-cli-rs only: 2 (3 placeholders); JSON cells equal apart from key order: 0; other differing cells: 0"
        );
        for tenant in [
            "TENANT",
            "tenantsecret",
            "created_at",
            "subHeading",
            "2026",
            "shown",
        ] {
            assert!(!note.contains(tenant), "{note}");
        }
        let list = " Id │ Name \n───┼───\n a1 │ Main \n";
        let other = " Id │ Slug │ Name \n───┼───┼───\n a1 │ ws-1 │ Main \n";
        assert_eq!(
            table_note(list, other),
            "tables differ: rows 1/1 (airs-cli-rs/TypeScript); header differs; columns TypeScript only: 1"
        );
        assert_eq!(
            table_note(other, list),
            "tables differ: rows 1/1 (airs-cli-rs/TypeScript); header differs; columns airs-cli-rs only: Slug"
        );
        assert_eq!(
            table_note(list, &list.replace("Main", "Other")),
            "tables differ: rows 1/1 (airs-cli-rs/TypeScript); header equal; cells withheld by airs-cli-rs only: 0 (0 placeholders); JSON cells equal apart from key order: 0; other differing cells: 1"
        );
        assert_eq!(
            table_note(" Id │ Name \nno rule\n", list),
            "tables differ: the airs-cli-rs output is not one table"
        );
    }

    /// Choice 156 (live): a JSON cell compares as JSON. airs-cli-rs prints nested members
    /// sorted (D35) and TypeScript in the server's order, so a key-order-only difference
    /// agrees (and the note counts it); a `[withheld]` Rust leaf stands for any TypeScript
    /// value inside the JSON; a real difference inside a JSON cell, or a member on one side
    /// only, still mismatches.
    #[test]
    fn json_cells_compare_apart_from_key_order() {
        let detail = |object: &str, evals: &str| {
            format!(" Field │ Value \n───┼───\n object │ {object} \n evals │ {evals} \n")
        };
        let rust = detail("list", r#"[{"text":"Scan","type":"subHeading"},{"n":1}]"#);
        let ts = " Field │ Value \n───┼───\n evals │ [{\"type\":\"subHeading\",\"text\":\"Scan\"},{\"n\":1}] \n object │ list \n";
        assert!(tables_agree(&rust, ts));
        assert_eq!(
            agree_note(&rust, ts, "cells equal (D238)"),
            "cells equal (D238); JSON cells equal apart from key order: 1 (D35)"
        );
        assert_eq!(
            agree_note(&rust, &rust, "cells equal (D238)"),
            "cells equal (D238)"
        );
        let changed = ts.replace("Scan", "Other");
        assert!(!tables_agree(&rust, &changed));
        assert_eq!(
            table_note(&rust, &changed),
            "tables differ: rows 2/2 (airs-cli-rs/TypeScript); header equal; cells withheld by airs-cli-rs only: 0 (0 placeholders); JSON cells equal apart from key order: 0; other differing cells: 1"
        );
        let withheld = detail("list", r#"{"a":"[withheld]","b":{"c":1,"d":2}}"#);
        assert!(tables_agree(
            &withheld,
            &detail("list", r#"{"b":{"d":2,"c":1},"a":{"key":"x"}}"#)
        ));
        assert!(!tables_agree(
            &withheld,
            &detail("list", r#"{"b":{"d":2,"c":3},"a":"x"}"#)
        ));
        assert!(
            !tables_agree(
                &detail("list", r#"{"a":"[withheld]"}"#),
                &detail("list", r#"{"a":"x","e":1}"#)
            ),
            "a member on one side only"
        );
        assert!(!tables_agree(
            &detail("list", r#"["a","b"]"#),
            &detail("list", r#"["b","a"]"#)
        ));
    }

    /// The schema clause is read as the CLI reads it (choice 146): a schema under a
    /// credential name inside `properties` may be printed, its instance values must be
    /// hidden; a non-schema value there is a credential.
    #[test]
    fn schemas_are_read_as_the_cli_reads_them() {
        assert!(withheld(&json!({"parameters": {"properties": {
            "apiKey": {"type": "string", "description": [{"type": "subHeading", "text": "t"}]},
            "credentials": {"type": "object", "properties": {"token": {"type": ["string", "null"]}}},
            "items_key": {"type": "array", "items": {"type": "string"}},
        }}})));
        assert!(!withheld(
            &json!({"properties": {"apiKey": {"type": "string", "default": "v"}}})
        ));
        assert!(withheld(
            &json!({"properties": {"apiKey": {"type": "string", "default": "[withheld]"}}})
        ));
        assert!(!withheld(&json!({"properties": {"api_key": "v"}})));
        assert!(!withheld(
            &json!({"properties": {"credentials": {"type": "basic", "password": "v"}}})
        ));
        assert!(!withheld(
            &json!({"properties": {"token": {"type": "array", "items": {"type": "string", "const": "v"}}}})
        ));
        assert!(
            !withheld(&json!({"apiKey": {"type": "string"}})),
            "outside a property map"
        );
        // Choice 150: a credential named inside a schema is checked under its own name.
        for probe in [
            json!({"properties": {"db": {"type": "object", "password": "v"}}}),
            json!({"properties": {"openai": {"type": "string", "api_key": "v"}}}),
            json!({"properties": {"openai": {"type": "string", "key": "v"}}}),
            json!({"properties": {"svc": {"type": "object", "oauth_metadata": {"x": "v"}}}}),
            json!({"configurations": {"properties": {"auth": {"type": "object", "client_secret": "v"}}}}),
            json!({"config": "{\"properties\":{\"t\":{\"type\":\"string\",\"secret\":\"v\"}}}"}),
            json!({"properties": {"l": {"type": "array", "items": {"type": "object", "token": "v"}}}}),
            json!({"properties": {"svc": {"type": "object", "headers": {"x-api": "v"}}}}),
        ] {
            assert!(!withheld(&probe), "{probe}");
        }
        assert!(withheld(
            &json!({"properties": {"db": {"type": "object", "password": "[withheld]", "headers": {"x-api": "[withheld]", "accept": "*/*"}}}})
        ));
        // Choice 152: under a withheld property no describing text shows a credential.
        assert!(!withheld(
            &json!({"properties": {"token": {"type": "string", "description": "e.g. Bearer hunter2x"}}})
        ));
        assert!(withheld(
            &json!({"properties": {"token": {"type": "string", "description": "[withheld]", "title": "Bearer token"}}})
        ));
        // Choice 177: under any property, the credential after a scheme is withheld in place.
        assert!(!withheld(
            &json!({"properties": {"region": {"type": "string", "description": "e.g. Bearer hunter2x"}}})
        ));
        assert!(withheld(
            &json!({"properties": {"region": {"type": "string", "description": "e.g. Bearer [withheld]"}}})
        ));
        assert!(is_schema(&json!({"type": ["string", "null"]})));
        assert!(!is_schema(&json!({"type": []})));
        assert!(!is_schema(&json!({"type": "service_account"})));
    }

    #[test]
    fn the_window_is_the_hour_before_cut_to_the_minute() {
        let now = UNIX_EPOCH + std::time::Duration::from_secs(1_790_899_259);
        assert_eq!(
            pinned_window(now),
            (
                "2026-10-01T23:00:00Z".to_owned(),
                "2026-10-02T00:00:00Z".to_owned()
            )
        );
    }

    #[test]
    fn doctor_entries_compare_statuses_with_d250() {
        let doc = |name: &str, status: &str, detail: &str| json!([{"name": name, "status": status, "detail": detail}]);
        assert_eq!(
            doctor_agrees(
                &doc("Gateway API", "pass", "x"),
                &doc("AI Gateway API", "pass", "y")
            ),
            Some(true)
        );
        assert_eq!(
            doctor_agrees(
                &doc("Gateway API", "warn", "rate limited (HTTP 429): m"),
                &doc("AI Gateway API", "fail", "t")
            ),
            Some(true)
        );
        assert_eq!(
            doctor_agrees(
                &doc("Gateway API", "pass", "x"),
                &doc("AI Gateway API", "fail", "t")
            ),
            Some(false)
        );
        assert_eq!(
            doctor_agrees(&json!([]), &doc("AI Gateway API", "pass", "y")),
            None
        );
    }

    #[test]
    fn report_shapes_read_the_evidence_table() {
        let html = "<!doctype html>\n<meta http-equiv=\"Content-Security-Policy\" content=\"x\"><section id=\"findings\"></section><section id=\"table-5\"><table><thead><tr><th>h</th></tr></thead><tbody><tr><td>telemetry.logs</td><td>telemetry.logs</td><td>Displayed telemetry window</td><td>unavailable</td><td>0</td><td>1</td><td>Request, scope or response validation failed; upstream details omitted.</td></tr></tbody></table></section>";
        let shape = report_shape(html).unwrap();
        assert_eq!(shape.sections, ["findings", "table-5"]);
        assert_eq!(shape.evidence[0].2, "unavailable");
        let mut ts = shape.clone();
        ts.evidence[0].2 = "complete".into();
        assert!(reports_agree(&shape, &ts), "D249");
        assert!(!reports_agree(&ts, &shape));
    }

    #[test]
    fn the_guard_refuses_gateway_writes_and_inference() {
        for args in [
            &["gateway", "configs", "create", "--name", "x"][..],
            &["aigateway", "workspaces", "archive", "w", "--force"],
            &["gateway", "mcp", "integrations", "capabilities", "set", "x"],
            &["gateway", "scopes", "bind", "s", "--workspace", "w"],
            &["gateway", "inference", "chat", "hi"],
            &[
                "--output", "json", "gateway", "api-keys", "service", "rotate", "x",
            ],
            // Global flags with values after the group shift no leaf out of reach.
            &[
                "gateway",
                "--output",
                "json",
                "mcp",
                "integrations",
                "workspaces",
                "set",
                "x",
                "--force",
            ],
            &[
                "gateway",
                "--tenant",
                "t",
                "--output",
                "json",
                "admin-guardrails",
                "mcp-servers",
                "sync",
                "x",
                "--force",
            ],
            &["gateway", "--output", "json", "inference", "chat", "hi"],
            &["gateway", "--tenant", "t", "--", "configs", "delete", "x"],
        ] {
            assert!(super::super::gateway_refusal(args).is_some(), "{args:?}");
        }
        for args in [
            &["gateway", "configs", "list", "--workspace", "w"][..],
            &["gateway", "report", "--workspace", "w"],
            &["aigateway", "telemetry", "requests", "--workspace", "w"],
            &["doctor", "--output", "json"],
        ] {
            assert!(super::super::gateway_refusal(args).is_none(), "{args:?}");
        }
    }
}
