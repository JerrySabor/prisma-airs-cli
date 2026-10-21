//! The M6f live supplychain reads (DESIGN §10, "M6f Supplychain").
//!
//! [`run_live_supplychain_reads`] runs only when `tests/live.rs` passes the read gate
//! (`AIRS_RS_LIVE=1` and `AIRS_E2E_TENANT`), or against the loopback fixture server through
//! [`super::LiveTarget::loopback`]. It is its own run (run id, private store, fingerprints,
//! leak checks, 90 s per CLI run). Every request is a `GET` on both CLIs; the TypeScript CLI
//! is sandboxed as in every live run and runs the same leaves under `agentguard` (D308).
//!
//! The gate comes first: Rust `supplychain stats --output json`. When it fails with HTTP
//! 401, 403 or 404, TypeScript `agentguard stats --output json` runs once: both failing so
//! is the notice `supplychain unavailable: …` and nothing else runs; one side only is a
//! mismatch. Then one page of each read on both CLIs (json and table), the Rust-only
//! `--include-content` run checked in memory (its stdout is dropped after the check), and
//! the report on both CLIs, checked by structure and removed at once. A check whose two
//! documents differ is run once more on both sides (the service's data rolls). Tenant
//! content is compared in memory only: rows and notices hold fixed texts, counts, exit codes
//! and HTTP statuses, and a mismatch is noted by shape (member names that are letters, `_`
//! and spaces only; row and cell counts), never by value.
//!
//! G71 (D324): the service sends `null` where both SDK contracts require a scan member, so
//! TypeScript refuses a scan page that airs-cli-rs prints. TypeScript prints the same
//! status-less request line for a timeout, a network error, a body that is not JSON and a
//! credential error, so that line alone is no evidence: a scan read passes with
//! [`G71_NOTE`] only when airs-cli-rs exits 0 with at least one row and TypeScript fails with
//! exactly that line on the first read **and** on the re-read (`Reads::scan_compared`); a
//! refusal on one read only is compared as any other answer (or fails with
//! [`G71_ONCE_NOTE`]). The report may differ in its Scans source alone
//! ([`reports_agree_g71`]) only when the json and the table checks both passed so and no
//! TypeScript scan run succeeded. The vulnerabilities checks then read the first scan
//! airs-cli-rs listed. Every other failure stays a mismatch.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::gateway::http_status;
use super::{Exec, LiveAbort, LivePlan, LiveReport, LiveRow, RunPlace, Session};
use crate::compare::json_semantic_eq;

/// The D321 notice of an `--include-content` run.
pub const CONTENT_NOTICE: &str = "Finding content included: source code, file paths and finding text can contain secrets from the scanned artifacts; keep this output private.";

/// The finding members whose text the content check looks for outside stdout.
pub const CONTENT_MEMBERS: [&str; 8] = [
    "title",
    "description",
    "file_path",
    "node_name",
    "remediation_description",
    "original_code",
    "suggested_code",
    "type_description",
];

/// The scan projection's members (§20.5), and the scan members neither CLI may print.
const SCAN_KEYS: [&str; 9] = [
    "uuid",
    "artifact_type",
    "status",
    "eval_outcome",
    "created_at",
    "vulnerability_count",
    "attack_chain_count",
    "is_batch",
    "parent_uuid",
];
const NEVER_SCAN_KEYS: [&str; 4] = ["name", "git_url", "fingerprint", "device_metadata"];

/// TypeScript's request failure line without a status (`ag.ts:81-92`): the whole stderr
/// of a TypeScript read whose answer its zod schema refused.
pub const TS_REQUEST_LINE: &str = "  ✗ AgentGuard request failed. Check credentials, query options and service availability. No upstream body is included.\n";
/// The note of a scan read that airs-cli-rs printed and TypeScript refused on both reads
/// (G71, D324).
pub const G71_NOTE: &str =
    "airs-cli-rs reads rows the shared contract refuses (G71); TypeScript refuses the answer";
/// The note of a scan read whose TypeScript refusal held on the re-read only (not G71).
pub const G71_ONCE_NOTE: &str =
    "TypeScript refused the answer on the re-read only; G71 needs the refusal on both reads";
/// The first read's note when TypeScript refused it (the re-read decides).
const G71_FIRST_NOTE: &str = "TypeScript refused the answer once";
/// The report note of the same case (G71): TypeScript's Scans source is unavailable.
pub const G71_REPORT_NOTE: &str = "0600 files; Statistics and Rules equal; airs-cli-rs reads the scan rows the shared contract refuses (G71), TypeScript's Scans source unavailable; aggregates only";
/// The report's note of a failed source (`Request or validation failed; …`).
const FAILED_SOURCE_NOTE: &str = "Request or validation failed; no upstream error body included.";
/// The table the Rust report adds from the scan rows TypeScript refused (G71).
const SCAN_OUTCOMES: &str = "Scan outcomes";

/// G71 (D324) on one pair: airs-cli-rs exited 0 on a scan read and TypeScript failed with
/// exactly its request failure line without an HTTP status and printed nothing on stdout.
/// Any other TypeScript failure (a status, another text) or a failed Rust run is not this
/// case. TypeScript prints this line for other failures too (a timeout, a body that is not
/// JSON), so [`Reads::scan_compared`] also needs Rust rows and the refusal on the re-read.
fn g71_refusal(rust: &Exec, ts: &Exec) -> bool {
    rust.code == Some(0)
        && ts.code == Some(1)
        && ts.stdout.is_empty()
        && ts.stderr == TS_REQUEST_LINE
}

/// The note of the D322 tolerance and the report directories.
const TIMESTAMP_NOTE: &str =
    "Rows with missing or out-of-window creation timestamps were excluded.";
const REPORT_DIRS: [&str; 2] = ["sc-rs", "sc-ts"];
const DEBUG_DIR: &str = "sc-debug";

/// Whether a run failed with HTTP 401, 403 or 404 (no access): the request failure line's
/// `(HTTP <s>)`.
fn no_access(exec: &Exec) -> Option<u16> {
    (exec.code != Some(0))
        .then(|| http_status(&exec.stderr))
        .flatten()
        .filter(|status| matches!(status, 401 | 403 | 404))
}

/// A member name the summary may print: letters, `_` and spaces only, at most 40
/// characters.
fn printable_name(name: &str) -> bool {
    (1..=40).contains(&name.chars().count())
        && name
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '_' || c == ' ')
}

/// Every member name of a document, at any depth.
fn member_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(members) => {
            for (name, member) in members {
                names.insert(name.clone());
                member_names(member, names);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| member_names(item, names)),
        _ => {}
    }
}

/// The record count of a document: the length of its record array (`scans`,
/// `vulnerabilities`, `rules`), else 1 for an object.
fn rows_of(value: &Value) -> usize {
    match value {
        Value::Object(members) => ["scans", "vulnerabilities", "rules"]
            .iter()
            .find_map(|key| members.get(*key).and_then(Value::as_array))
            .map_or(1, Vec::len),
        Value::Array(items) => items.len(),
        _ => 0,
    }
}

/// Why two json documents differ, by shape only (choice 149's pattern): the record counts
/// and the member names on one side only (printable names by name, the rest counted; the
/// TypeScript-only names counted only).
pub fn json_note(rust: &Value, ts: &Value) -> String {
    let (mut rust_names, mut ts_names) = (BTreeSet::new(), BTreeSet::new());
    member_names(rust, &mut rust_names);
    member_names(ts, &mut ts_names);
    let mut notes = vec![format!(
        "records {}/{} (airs-cli-rs/TypeScript)",
        rows_of(rust),
        rows_of(ts)
    )];
    let rust_only: Vec<&String> = rust_names.difference(&ts_names).collect();
    if !rust_only.is_empty() {
        let mut parts: Vec<String> = rust_only
            .iter()
            .filter(|name| printable_name(name))
            .map(|name| (*name).clone())
            .collect();
        let masked = rust_only.len() - parts.len();
        if masked > 0 {
            parts.push(format!("{masked} unprintable"));
        }
        notes.push(format!("members airs-cli-rs only: {}", parts.join(", ")));
    }
    let ts_only = ts_names.difference(&rust_names).count();
    if ts_only > 0 {
        notes.push(format!("members TypeScript only: {ts_only}"));
    }
    if rust_only.is_empty() && ts_only == 0 {
        notes.push("the same members; values differ".to_owned());
    }
    format!("json differs: {}", notes.join("; "))
}

/// The table of a run: its header and rows (trimmed cells), from the lines that hold `│`
/// (an empty listing prints `"\n"`: no lines, no cells).
fn table_lines(stdout: &str) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    let lines: Vec<&str> = stdout.lines().filter(|line| line.contains('│')).collect();
    let split = |line: &str| -> Vec<String> {
        line.split('│').map(|cell| cell.trim().to_owned()).collect()
    };
    let (header, rows) = lines.split_first()?;
    Some((split(header), rows.iter().map(|line| split(line)).collect()))
}

/// The sorted multiset of trimmed cells (header included).
fn cell_multiset(stdout: &str) -> Vec<String> {
    let mut cells: Vec<String> = match table_lines(stdout) {
        Some((header, rows)) => header
            .into_iter()
            .chain(rows.into_iter().flatten())
            .collect(),
        None => Vec::new(),
    };
    cells.sort();
    cells
}

/// Two `--output table` runs agree: the same multiset of trimmed cells (padding is not
/// compared, D53).
pub fn tables_agree(rust: &str, ts: &str) -> bool {
    cell_multiset(rust) == cell_multiset(ts)
}

/// Why two tables differ, by shape only: `tables differ: rows <r>/<t>
/// (airs-cli-rs/TypeScript); header equal|differs; differing cells: <n>` (the Rust cells
/// without a TypeScript counterpart). No value is printed.
pub fn table_note(rust: &str, ts: &str) -> String {
    let (rust_table, ts_table) = (table_lines(rust), table_lines(ts));
    let rows =
        |table: &Option<(Vec<String>, Vec<Vec<String>>)>| table.as_ref().map_or(0, |t| t.1.len());
    let header = match (&rust_table, &ts_table) {
        (Some(r), Some(t)) if r.0 == t.0 => "header equal",
        (None, None) => "header equal",
        _ => "header differs",
    };
    let mut ts_cells = cell_multiset(ts);
    let mut differing = 0;
    for cell in cell_multiset(rust) {
        match ts_cells.iter().position(|other| *other == cell) {
            Some(at) => {
                ts_cells.remove(at);
            }
            None => differing += 1,
        }
    }
    format!(
        "tables differ: rows {}/{} (airs-cli-rs/TypeScript); {header}; differing cells: {differing}",
        rows(&rust_table),
        rows(&ts_table)
    )
}

/// Whether the Rust statistics document has an array member (D318: TypeScript then prints
/// the array's record table instead of the field table).
fn has_array_member(doc: &Value) -> bool {
    doc.as_object()
        .is_some_and(|members| members.values().any(Value::is_array))
}

/// The record-table labels TypeScript prints for `records` (the union of their keys
/// without `description` and `remediation`, the first nine, `_` read as a space), sorted.
fn record_labels(records: &[Value]) -> Vec<String> {
    let mut keys: Vec<&str> = Vec::new();
    for record in records {
        for key in record
            .as_object()
            .into_iter()
            .flat_map(|members| members.keys())
        {
            if !["description", "remediation"].contains(&key.as_str())
                && !keys.contains(&key.as_str())
            {
                keys.push(key);
            }
        }
    }
    keys.truncate(9);
    let mut labels: Vec<String> = keys.iter().map(|key| key.replace('_', " ")).collect();
    labels.sort();
    labels
}

/// D318's shape, the only table difference the stats check tolerates (`doc` is the Rust
/// statistics document of the json pair that agreed with TypeScript): the Rust table is
/// the `Field │ Value` table whose rows equal `doc` member by member (an array member's
/// row parsed back to its array), and the TypeScript table is the record table of one of
/// those arrays (its row count, its header labels as a set; an empty array prints no
/// table). The reason it fails is a fixed text with counts only.
pub fn d318_tolerated(doc: &Value, rust_table: &str, ts_table: &str) -> Result<(), String> {
    let members = doc
        .as_object()
        .ok_or_else(|| "the statistics document is not an object".to_owned())?;
    let Some((header, rows)) = table_lines(rust_table) else {
        return Err("no airs-cli-rs field table".to_owned());
    };
    if header != ["Field", "Value"] {
        return Err("the airs-cli-rs table is not the field table".to_owned());
    }
    let mut arrays: Vec<Vec<Value>> = Vec::new();
    let mut differing = members.len().abs_diff(rows.len());
    for row in &rows {
        let [field, cell] = row.as_slice() else {
            differing += 1;
            continue;
        };
        let parsed = serde_json::from_str::<Value>(cell).ok();
        let same = match (members.get(field.as_str()), parsed) {
            (Some(Value::Array(_)), Some(Value::Array(items))) => {
                arrays.push(items);
                true
            }
            (Some(Value::Array(_)) | None, _) => false,
            (Some(Value::String(text)), _) => text.trim() == cell.as_str(),
            (Some(expected), Some(parsed)) => json_semantic_eq(expected, &parsed),
            (Some(_), None) => false,
        };
        if !same {
            differing += 1;
        }
    }
    if differing > 0 {
        return Err(format!(
            "field rows differing from the statistics document: {differing}"
        ));
    }
    let fits = match table_lines(ts_table) {
        None => arrays.iter().any(Vec::is_empty),
        Some((ts_header, ts_rows)) => {
            let mut ts_labels = ts_header;
            ts_labels.sort();
            arrays
                .iter()
                .any(|items| items.len() == ts_rows.len() && record_labels(items) == ts_labels)
        }
    };
    if fits {
        Ok(())
    } else {
        Err("the TypeScript table is not an array member's record table".to_owned())
    }
}

/// G71's Rust side of the json check: the 9-key projection with at least one row (an
/// empty listing shows no row the shared contract could refuse).
fn g71_listing(doc: &Value) -> bool {
    projected(doc)
        && doc
            .get("scans")
            .and_then(Value::as_array)
            .is_some_and(|rows| !rows.is_empty())
}

/// G71's Rust side of the table check: a table with at least one row.
fn g71_table(stdout: &str) -> bool {
    table_lines(stdout).is_some_and(|(_, rows)| !rows.is_empty())
}

/// The scan projection holds exactly the 9 keys, never a sensitive member, on every row.
fn projected(doc: &Value) -> bool {
    doc.get("scans")
        .and_then(Value::as_array)
        .is_some_and(|rows| {
            rows.iter().all(|row| {
                row.as_object().is_some_and(|members| {
                    members.len() == SCAN_KEYS.len()
                        && SCAN_KEYS.iter().all(|key| members.contains_key(*key))
                        && NEVER_SCAN_KEYS
                            .iter()
                            .all(|key| !members.contains_key(*key))
                })
            })
        })
}

/// D319 on both sides: the finding list is short of `pagination.total_items`.
fn short_list(doc: &Value) -> bool {
    let total = doc
        .get("pagination")
        .and_then(|pagination| pagination.get("total_items"))
        .and_then(Value::as_f64);
    let rows = doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .map(Vec::len);
    matches!((total, rows), (Some(total), Some(rows)) if total > u32::try_from(rows).map_or(f64::MAX, f64::from))
}

/// The finding uuids of a vulnerabilities document, in order.
fn finding_ids(doc: &Value) -> Vec<String> {
    doc.get("vulnerabilities")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.get("uuid").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Every string of at least 8 characters in the content members of the findings (the texts
/// the content check looks for outside stdout).
pub fn content_strings(doc: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for row in doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for member in CONTENT_MEMBERS {
            if let Some(text) = row.get(member).and_then(Value::as_str)
                && text.chars().count() >= 8
            {
                out.push(text.to_owned());
            }
        }
    }
    out
}

/// The text of a `--include-content` stdout outside its finding rows (the scanned
/// artifacts' data, which may hold a JWT-shaped string): the document with
/// `vulnerabilities` emptied, else the whole text (a stdout that is not that document is
/// checked whole).
pub fn outside_findings(stdout: &str) -> String {
    match serde_json::from_str::<Value>(stdout) {
        Ok(Value::Object(mut members)) if members.contains_key("vulnerabilities") => {
            members.insert("vulnerabilities".to_owned(), Value::Array(Vec::new()));
            Value::Object(members).to_string()
        }
        _ => stdout.to_owned(),
    }
}

/// A debug log holds status and headers only: every line a JSON record with no `body`
/// member anywhere, no request URL with a query, and none of `content`.
pub fn debug_clean(text: &str, content: &[String]) -> bool {
    fn has_body(value: &Value) -> bool {
        match value {
            Value::Object(members) => members.iter().any(|(name, member)| {
                name.to_ascii_lowercase().contains("body") || has_body(member)
            }),
            Value::Array(items) => items.iter().any(has_body),
            _ => false,
        }
    }
    let records: Option<Vec<Value>> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).ok())
        .collect();
    let Some(records) = records else {
        return false;
    };
    !records.is_empty()
        && records.iter().all(|record| {
            !has_body(record)
                && record
                    .get("request")
                    .and_then(|request| request.get("url"))
                    .and_then(Value::as_str)
                    .is_none_or(|url| !url.contains('?'))
        })
        && content.iter().all(|piece| !text.contains(piece.as_str()))
}

/// The comparable parts of a supplychain report file (the shared environment template).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReportShape {
    pub sections: Vec<String>,
    /// The titles of the table sections (`<section id="table-<n>"><h2>…</h2>`), in order.
    pub tables: Vec<String>,
    /// `(source, method, status, notes)` of each evidence row.
    pub evidence: Vec<(String, String, String, String)>,
    pub csp: bool,
    pub external: bool,
}

/// The section ids, the evidence rows, the CSP meta and any external reference of a report.
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
    let tables = html
        .match_indices("<section id=\"table-")
        .filter_map(|(at, _)| {
            let rest = &html[at..];
            let rest = &rest[rest.find("<h2>")? + "<h2>".len()..];
            rest.find("</h2>").map(|end| rest[..end].to_owned())
        })
        .collect();
    let evidence = html
        .find("<h2>Evidence and completeness</h2>")
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
                            cells[1].to_owned(),
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
        tables,
        evidence,
        csp: lower.contains("<meta http-equiv=\"content-security-policy\""),
        external: lower.contains("src=") || lower.contains("http://") || lower.contains("https://"),
    })
}

/// The two reports agree: the same sections, evidence sources, methods and statuses (D322
/// tolerated: a TypeScript `complete` Scans source against a Rust `partial` one only with
/// the timestamp note), a CSP and no external reference on both.
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
                    || (r.0 == "Scans"
                        && r.2 == "partial"
                        && t.2 == "complete"
                        && r.3.contains(TIMESTAMP_NOTE)))
        })
}

/// G71 in the report (only after the scan listing showed G71 in the same flow): the
/// TypeScript Scans source is `unavailable` with exactly the failed-source note while the
/// Rust one read rows; the Statistics and Rules rows agree (source, method, status); the
/// sections are the same but for the table the Rust Scans source adds: the table titles
/// agree as a multiset once one `Scan outcomes` is taken from the Rust side (a Rust report
/// that drops a table and adds two is not this case); both carry the CSP and no external
/// reference.
pub fn reports_agree_g71(rust: &ReportShape, ts: &ReportShape) -> bool {
    let fixed = |shape: &ReportShape| -> Vec<String> {
        shape
            .sections
            .iter()
            .filter(|id| !id.starts_with("table-"))
            .cloned()
            .collect()
    };
    let scans = |shape: &ReportShape| shape.evidence.iter().find(|row| row.0 == "Scans").cloned();
    let rest = |shape: &ReportShape| -> Vec<(String, String, String)> {
        shape
            .evidence
            .iter()
            .filter(|row| row.0 != "Scans")
            .map(|row| (row.0.clone(), row.1.clone(), row.2.clone()))
            .collect()
    };
    let scans_g71 = match (scans(rust), scans(ts)) {
        (Some(r), Some(t)) => {
            t.2 == "unavailable" && t.3 == FAILED_SOURCE_NOTE && r.2 != "unavailable" && r.1 == t.1
        }
        _ => false,
    };
    let titles = |shape: &ReportShape| -> Vec<String> {
        let mut titles = shape.tables.clone();
        titles.sort();
        titles
    };
    let mut rust_titles = titles(rust);
    let tables_g71 = match rust_titles.iter().position(|title| title == SCAN_OUTCOMES) {
        Some(at) => {
            rust_titles.remove(at);
            rust_titles == titles(ts)
        }
        None => false,
    };
    scans_g71
        && tables_g71
        && rust.csp
        && ts.csp
        && !rust.external
        && !ts.external
        && rust.sections.len() == ts.sections.len() + 1
        && fixed(rust) == fixed(ts)
        && rest(rust) == rest(ts)
        && rust.evidence.len() == ts.evidence.len()
}

fn mode_of(path: &Path) -> Option<u32> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o777)
}

/// Every debug log under an `XDG_STATE_HOME`, concatenated.
fn debug_text(state: &Path) -> String {
    std::fs::read_dir(state.join("airs-cli/debug"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Two `--output table` runs: both succeeded and their cells agree (D53).
fn table_pair(rust: &Exec, ts: &Exec) -> (bool, String) {
    if rust.code != Some(0) || ts.code != Some(0) {
        (false, "tables differ: a run failed".to_owned())
    } else if tables_agree(&rust.stdout, &ts.stdout) {
        (true, "cells equal (D53)".to_owned())
    } else {
        (false, table_note(&rust.stdout, &ts.stdout))
    }
}

/// How a pair of runs compares.
type Compare<'c> = &'c dyn Fn(&Exec, &Exec) -> (bool, String);

/// Both runs of a check, or both no-access with their `unavailable: …` note.
enum Answer {
    Both(Exec, Exec),
    Unavailable(Exec, Exec, String),
}

struct Reads<'s, 'p> {
    session: &'s mut Session<'p>,
    /// The scan listing passed as G71 on the json and the table check (TypeScript refused
    /// each twice, airs-cli-rs read rows) and no TypeScript scan run succeeded, so the
    /// report may differ in its Scans source alone ([`reports_agree_g71`]).
    g71: bool,
    /// A TypeScript scan run (`scans list`, any check, first read or re-read) exited 0: the
    /// service answered TypeScript, so its refusals were not G71.
    ts_scan_ok: bool,
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

    /// One Rust run (`supplychain <args>`).
    fn rust_in(&self, check: &str, args: &[&str], place: &RunPlace<'_>) -> Result<Exec, LiveAbort> {
        self.session.rust_runs.set(self.session.rust_runs.get() + 1);
        let mut full = vec!["supplychain"];
        full.extend_from_slice(args);
        self.session
            .run_in(&self.session.plan.rust, check, &full, place)
    }

    fn rust(&self, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        self.rust_in(check, args, &RunPlace::default())
    }

    /// One TypeScript run (`agentguard <args>`).
    fn ts(&self, check: &str, args: &[&str]) -> Result<Exec, LiveAbort> {
        self.session.ts_runs.set(self.session.ts_runs.get() + 1);
        let mut full = vec!["agentguard"];
        full.extend_from_slice(args);
        self.session
            .run_in(&self.session.plan.ts, check, &full, &RunPlace::default())
    }

    /// Both CLIs, no row written: [`Answer::Unavailable`] with the `unavailable: …` note
    /// when both end in 401/403/404.
    fn runs(&mut self, check: &str, args: &[&str]) -> Result<Answer, LiveAbort> {
        let rust = self.rust(check, args)?;
        let ts = self.ts(check, args)?;
        if let (Some(r), Some(t)) = (no_access(&rust), no_access(&ts)) {
            let note = if r == t {
                format!("unavailable: HTTP {r} on both CLIs")
            } else {
                format!("unavailable: HTTP {r} / HTTP {t}")
            };
            return Ok(Answer::Unavailable(rust, ts, note));
        }
        Ok(Answer::Both(rust, ts))
    }

    /// Both CLIs; a pair that both end in 401/403/404 is `unavailable` (a row and a notice).
    fn pair(&mut self, check: &str, args: &[&str]) -> Result<Option<(Exec, Exec)>, LiveAbort> {
        match self.runs(check, args)? {
            Answer::Both(rust, ts) => Ok(Some((rust, ts))),
            Answer::Unavailable(rust, ts, note) => {
                self.row(check, &rust, Some(&ts), true, &note);
                self.notice(format!("{check} {note}"));
                Ok(None)
            }
        }
    }

    /// Both CLIs, compared; a disagreement runs both once more (the data rolls) and the
    /// second comparison decides. Returns the Rust run of the deciding pair. A re-read that
    /// is unavailable on both CLIs does not clear the first disagreement: the row fails
    /// (`differed, then unavailable on re-read`) and the first Rust run is returned.
    fn compared(
        &mut self,
        check: &str,
        args: &[&str],
        compare: Compare<'_>,
    ) -> Result<Option<Exec>, LiveAbort> {
        let Some((rust, ts)) = self.pair(check, args)? else {
            return Ok(None);
        };
        let (agree, note) = compare(&rust, &ts);
        if agree {
            self.row(check, &rust, Some(&ts), true, &note);
            return Ok(Some(rust));
        }
        let first = (rust, note);
        let (rust, ts) = match self.runs(check, args)? {
            Answer::Both(rust, ts) => (rust, ts),
            Answer::Unavailable(rust, ts, unavailable) => {
                self.row(
                    check,
                    &rust,
                    Some(&ts),
                    false,
                    &format!(
                        "differed, then {unavailable} on re-read (first: {})",
                        first.1
                    ),
                );
                return Ok(Some(first.0));
            }
        };
        let (agree, note) = compare(&rust, &ts);
        let note = if agree {
            format!("{note} (after one re-read)")
        } else {
            note
        };
        self.row(check, &rust, Some(&ts), agree, &note);
        Ok(Some(rust))
    }

    /// The gate (Rust `stats --output json`; on 401/403/404 the TypeScript run once).
    /// `false` when nothing else may run.
    fn gate(&mut self) -> Result<bool, LiveAbort> {
        let check = "stats (gate)";
        let args = ["stats", "--output", "json"];
        let rust = self.rust(check, &args)?;
        if rust.code == Some(0) {
            self.row(check, &rust, None, true, "the service answered");
            return Ok(true);
        }
        let Some(status) = no_access(&rust) else {
            self.row(check, &rust, None, false, "the gate failed");
            self.notice("supplychain checks skipped: the gate failed".to_owned());
            return Ok(false);
        };
        let ts = self.ts(check, &args)?;
        match no_access(&ts) {
            Some(ts_status) => {
                self.row(
                    check,
                    &rust,
                    Some(&ts),
                    true,
                    &format!("unavailable: HTTP {status} on both CLIs"),
                );
                self.notice(format!(
                    "supplychain unavailable: HTTP {status} on both CLIs (no AI Supply Chain access){}",
                    if ts_status == status {
                        String::new()
                    } else {
                        format!(" (HTTP {ts_status} on the TypeScript side)")
                    }
                ));
            }
            None => self.row(
                check,
                &rust,
                Some(&ts),
                false,
                "the gate failed on one side only",
            ),
        }
        Ok(false)
    }

    fn steps(&mut self) -> Result<(), LiveAbort> {
        if !self.gate()? {
            return Ok(());
        }
        self.stats()?;
        let uuids = self.scans()?;
        match uuids.first() {
            Some(scan) => {
                let ids = self.vulnerabilities(scan)?;
                self.content(scan, ids.as_deref())?;
            }
            None => self.notice(
                "scans vulnerabilities skipped: the scan listing returned no scan".to_owned(),
            ),
        }
        self.rules()?;
        self.report(&uuids)?;
        self.notice(
            "doctor: no supplychain check exists (TypeScript has none); D312 is a loopback test"
                .to_owned(),
        );
        Ok(())
    }

    fn stats(&mut self) -> Result<(), LiveAbort> {
        let json = |rust: &Exec, ts: &Exec| {
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && json_semantic_eq(&rust.json(), &ts.json());
            let note = if agree {
                "documents equal (D35)".to_owned()
            } else if rust.code != Some(0) || ts.code != Some(0) {
                "a run failed".to_owned()
            } else {
                json_note(&rust.json(), &ts.json())
            };
            (agree, note)
        };
        let doc = self.compared("stats --output json", &["stats", "--output", "json"], &json)?;
        let d318 = doc.map(|exec| exec.json()).filter(has_array_member);
        let table = move |rust: &Exec, ts: &Exec| {
            if rust.code != Some(0) || ts.code != Some(0) {
                return (false, "tables differ: a run failed".to_owned());
            }
            if tables_agree(&rust.stdout, &ts.stdout) {
                return (true, "cells equal (D53)".to_owned());
            }
            match &d318 {
                Some(doc) => match d318_tolerated(doc, &rust.stdout, &ts.stdout) {
                    Ok(()) => (true, "D318 tolerated: the field rows equal the statistics document; TypeScript prints an array member's record table".to_owned()),
                    Err(why) => (false, format!("D318 shape not met: {why}")),
                },
                None => (false, table_note(&rust.stdout, &ts.stdout)),
            }
        };
        self.compared(
            "stats --output table",
            &["stats", "--output", "table"],
            &table,
        )?;
        Ok(())
    }

    /// A scan read on both CLIs (G71, choice 85). A pair where TypeScript refuses with its
    /// status-less line and airs-cli-rs shows rows (`rows`) is not decided: both run once
    /// more, and the row passes with [`G71_NOTE`] only when the re-read is refused so too.
    /// A re-read that answers TypeScript is compared as usual (`compare`; noted
    /// `(after one re-read)` when it agrees); a refusal on the re-read alone fails with
    /// [`G71_ONCE_NOTE`]. Any other pair is [`Reads::compared`]'s. Every TypeScript run that
    /// exits 0 sets `ts_scan_ok`. Returns the deciding Rust run and whether the row passed
    /// as G71.
    fn scan_compared(
        &mut self,
        check: &str,
        args: &[&str],
        compare: Compare<'_>,
        rows: &dyn Fn(&Exec) -> bool,
    ) -> Result<Option<(Exec, bool)>, LiveAbort> {
        let refused = |rust: &Exec, ts: &Exec| g71_refusal(rust, ts) && rows(rust);
        let Some((rust, ts)) = self.pair(check, args)? else {
            return Ok(None);
        };
        self.ts_scan_ok |= ts.code == Some(0);
        let first_refused = refused(&rust, &ts);
        let first_note = if first_refused {
            G71_FIRST_NOTE.to_owned()
        } else {
            let (agree, note) = compare(&rust, &ts);
            if agree {
                self.row(check, &rust, Some(&ts), true, &note);
                return Ok(Some((rust, false)));
            }
            note
        };
        let (rerun, ts) = match self.runs(check, args)? {
            Answer::Both(rust, ts) => (rust, ts),
            Answer::Unavailable(again, ts, unavailable) => {
                self.row(
                    check,
                    &again,
                    Some(&ts),
                    false,
                    &format!("differed, then {unavailable} on re-read (first: {first_note})"),
                );
                return Ok(Some((rust, false)));
            }
        };
        self.ts_scan_ok |= ts.code == Some(0);
        let (agree, note, g71) = match (first_refused, refused(&rerun, &ts)) {
            (true, true) => (true, G71_NOTE.to_owned(), true),
            (false, true) => (false, G71_ONCE_NOTE.to_owned(), false),
            (_, false) => {
                let (agree, note) = compare(&rerun, &ts);
                let note = if agree {
                    format!("{note} (after one re-read)")
                } else {
                    note
                };
                (agree, note, false)
            }
        };
        self.row(check, &rerun, Some(&ts), agree, &note);
        Ok(Some((rerun, g71)))
    }

    /// `scans list --limit 10`: json (the pagination documents and projections equal) and
    /// table; the listed scan uuids, in order (from the Rust json; held in memory only).
    /// G71 ([`Reads::scan_compared`]): TypeScript refusing both reads with its request line
    /// while airs-cli-rs prints rows passes with [`G71_NOTE`] (and the scan uuids are
    /// Rust's); the report's G71 tolerance needs both checks so and no TypeScript scan
    /// success.
    fn scans(&mut self) -> Result<Vec<String>, LiveAbort> {
        let json = |rust: &Exec, ts: &Exec| {
            let (r, t) = (rust.json(), ts.json());
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && projected(&r)
                && projected(&t)
                && json_semantic_eq(&r, &t);
            let note = if agree {
                "pagination and projections equal (9 keys, no sensitive member)".to_owned()
            } else if rust.code != Some(0) || ts.code != Some(0) {
                "a run failed".to_owned()
            } else if !projected(&r) || !projected(&t) {
                "a projection is not the 9 keys".to_owned()
            } else {
                json_note(&r, &t)
            };
            (agree, note)
        };
        let listing = self.scan_compared(
            "scans list --limit 10 --output json",
            &["scans", "list", "--limit", "10", "--output", "json"],
            &json,
            &|rust: &Exec| g71_listing(&rust.json()),
        )?;
        let table = self.scan_compared(
            "scans list --limit 10 --output table",
            &["scans", "list", "--limit", "10", "--output", "table"],
            &table_pair,
            &|rust: &Exec| g71_table(&rust.stdout),
        )?;
        let passed = |run: &Option<(Exec, bool)>| run.as_ref().is_some_and(|(_, g71)| *g71);
        self.g71 = passed(&listing) && passed(&table) && !self.ts_scan_ok;
        Ok(listing.map_or_else(Vec::new, |(exec, _)| {
            exec.json()
                .get("scans")
                .and_then(Value::as_array)
                .map(|rows| {
                    rows.iter()
                        .filter_map(|row| row.get("uuid").and_then(Value::as_str))
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        }))
    }

    /// A table on both CLIs: the multiset of trimmed cells equal.
    fn tables(&mut self, check: &str, args: &[&str]) -> Result<(), LiveAbort> {
        let mut full = args.to_vec();
        full.extend(["--output", "table"]);
        self.compared(check, &full, &table_pair)?;
        Ok(())
    }

    /// `scans vulnerabilities <first scan> --output json` without content: equal (D319
    /// tolerated). The finding uuids of the Rust run.
    fn vulnerabilities(&mut self, scan: &str) -> Result<Option<Vec<String>>, LiveAbort> {
        let json = |rust: &Exec, ts: &Exec| {
            let (r, t) = (rust.json(), ts.json());
            let codes_agree = (rust.code == Some(0) && ts.code == Some(0))
                || (short_list(&r) && rust.code == Some(1) && ts.code == Some(0));
            let agree = codes_agree
                && r.get("content_included") == Some(&Value::Bool(false))
                && json_semantic_eq(&r, &t);
            let note = if agree && rust.code == Some(1) {
                "documents equal; D319 tolerated (a short list fails here)".to_owned()
            } else if agree {
                "documents equal (4-key projection, content_included false)".to_owned()
            } else if !codes_agree {
                "a run failed".to_owned()
            } else {
                json_note(&r, &t)
            };
            (agree, note)
        };
        let doc = self.compared(
            "scans vulnerabilities <first scan> --output json",
            &["scans", "vulnerabilities", scan, "--output", "json"],
            &json,
        )?;
        Ok(doc.map(|exec| finding_ids(&exec.json())))
    }

    /// Rust only: `--include-content --debug --output json`, checked in memory; its stdout
    /// is dropped in [`Reads::content_run`] (never written, never in the summary). Findings
    /// other than the plain read's (the data rolls) run the Rust plain read and the content
    /// run once more, and the second pair decides (choice 60).
    fn content(&mut self, scan: &str, ids: Option<&[String]>) -> Result<(), LiveAbort> {
        let check = "scans vulnerabilities <first scan> --include-content (rs, in memory)";
        let first = match self.content_run(check, scan)? {
            ContentRun::Checked(first) => first,
            ContentRun::Refused(exec, status) => {
                if ids.is_some() {
                    // The plain read of the same scan just succeeded on both CLIs: a
                    // refusal here leaves the D321 policy unchecked, so it fails.
                    self.row(check, &exec, None, false, &refused_note(status));
                    return Ok(());
                }
                let note = format!("unavailable: HTTP {status}");
                self.row(check, &exec, None, true, &note);
                self.notice(format!("{check} {note}"));
                return Ok(());
            }
        };
        let Some(ids) = ids.filter(|ids| first.ids != *ids) else {
            self.row(check, &first.exec, None, first.ok(ids), &first.note(ids));
            return Ok(());
        };
        let differed = first.note(Some(ids));
        let plain = self.rust(
            check,
            &["scans", "vulnerabilities", scan, "--output", "json"],
        )?;
        if let Some(status) = no_access(&plain) {
            let note =
                format!("differed, then unavailable: HTTP {status} on re-read (first: {differed})");
            self.row(check, &plain, None, false, &note);
            return Ok(());
        }
        let doc = plain.json();
        if !(plain.code == Some(0) || (plain.code == Some(1) && short_list(&doc))) {
            let note = format!("differed, then the plain re-read failed (first: {differed})");
            self.row(check, &plain, None, false, &note);
            return Ok(());
        }
        let ids = finding_ids(&doc);
        let second = match self.content_run(check, scan)? {
            ContentRun::Checked(second) => second,
            ContentRun::Refused(exec, status) => {
                self.row(check, &exec, None, false, &refused_note(status));
                return Ok(());
            }
        };
        let ok = second.ok(Some(&ids));
        let note = second.note(Some(&ids));
        let note = if ok {
            format!("{note} (after one re-read)")
        } else {
            note
        };
        self.row(check, &second.exec, None, ok, &note);
        Ok(())
    }

    /// One Rust content run, checked in memory: refused with 401/403/404, or the parts of
    /// the D321 check with the stdout and stderr dropped. A JWT shape in stdout outside the
    /// finding rows stops the flow (a leak).
    fn content_run(&mut self, check: &str, scan: &str) -> Result<ContentRun, LiveAbort> {
        let dir = self.session.sandbox.tmp().join(DEBUG_DIR);
        std::fs::create_dir_all(&dir)
            .map_err(|err| LiveAbort::Setup(format!("cannot create the debug directory: {err}")))?;
        let state = dir.join("xdg");
        let place = RunPlace {
            env: vec![("XDG_STATE_HOME", state.display().to_string())],
            content_stdout: true,
            ..RunPlace::default()
        };
        let outcome = self.rust_in(
            check,
            &[
                "--debug",
                "scans",
                "vulnerabilities",
                scan,
                "--include-content",
                "--output",
                "json",
            ],
            &place,
        );
        let log = debug_text(&state);
        let _ = std::fs::remove_dir_all(&dir);
        let mut exec = outcome?;
        // The run's stdout was checked for the plan's secret forms only; a JWT shape
        // outside the finding rows is still a leak.
        if super::contains_jwt(&outside_findings(&exec.stdout)) {
            return Err(LiveAbort::Leak(format!(
                "{} {check}: a JWT-shaped token appeared in stdout outside the findings",
                self.session.plan.rust.label()
            )));
        }
        if let Some(status) = no_access(&exec) {
            exec.stdout = String::new();
            exec.stderr = String::new();
            return Ok(ContentRun::Refused(exec, status));
        }
        let doc = exec.json();
        let content = content_strings(&doc);
        let checked = ContentCheck {
            ids: finding_ids(&doc),
            code_ok: exec.code == Some(0) || (exec.code == Some(1) && short_list(&doc)),
            included: doc.get("content_included") == Some(&Value::Bool(true)),
            notice: exec.stderr.contains(CONTENT_NOTICE),
            stderr_clean: content
                .iter()
                .all(|piece| !exec.stderr.contains(piece.as_str())),
            log_clean: debug_clean(&log, &content),
            strings: content.len(),
            exec: Exec {
                stdout: String::new(),
                stderr: String::new(),
                ..exec
            },
        };
        drop(doc);
        drop(content);
        Ok(ContentRun::Checked(checked))
    }

    fn rules(&mut self) -> Result<(), LiveAbort> {
        let json = |rust: &Exec, ts: &Exec| {
            let agree = rust.code == Some(0)
                && ts.code == Some(0)
                && json_semantic_eq(&rust.json(), &ts.json());
            let note = if agree {
                "documents equal (D35)".to_owned()
            } else if rust.code != Some(0) || ts.code != Some(0) {
                "a run failed".to_owned()
            } else {
                json_note(&rust.json(), &ts.json())
            };
            (agree, note)
        };
        self.compared(
            "rules list --limit 10 --output json",
            &["rules", "list", "--limit", "10", "--output", "json"],
            &json,
        )?;
        self.tables(
            "rules list --limit 10 --output table",
            &["rules", "list", "--limit", "10"],
        )
    }

    /// `<sandbox>/tmp/<label>/`, created.
    fn dir(&self, label: &str) -> Result<PathBuf, LiveAbort> {
        let dir = self.session.sandbox.tmp().join(label);
        std::fs::create_dir_all(&dir)
            .map_err(|err| LiveAbort::Setup(format!("cannot create a run directory: {err}")))?;
        Ok(dir)
    }

    /// `report --max-pages 3` on both CLIs, into each CLI's own file, checked and removed at
    /// once. The Rust file holds no `SecretSet` value and no scan uuid of the listing. A pair
    /// that differs (the data rolls) runs once more on both CLIs and the second pair decides;
    /// a Rust file that holds a secret or a listed uuid fails at once (choice 61).
    fn report(&mut self, uuids: &[String]) -> Result<(), LiveAbort> {
        let check = "report --max-pages 3 --output-file";
        let first = self.report_pair(check, uuids)?;
        let (pair, reread) = if first.agree || first.leak {
            (first, false)
        } else {
            (self.report_pair(check, uuids)?, true)
        };
        let note = if pair.leak {
            "the Rust report holds a secret or a scan uuid of the listing".to_owned()
        } else if !pair.agree {
            "the reports differ".to_owned()
        } else {
            let base = if pair.g71 {
                G71_REPORT_NOTE
            } else {
                "0600 files; sections, sources, methods and statuses equal (D322); aggregates only"
            };
            if reread {
                format!("{base} (after one re-read)")
            } else {
                base.to_owned()
            }
        };
        self.row(check, &pair.rust, Some(&pair.ts), pair.agree, &note);
        Ok(())
    }

    /// One report run on each CLI, each file checked and removed at once.
    fn report_pair(&mut self, check: &str, uuids: &[String]) -> Result<ReportPair, LiveAbort> {
        let mut runs = Vec::new();
        for (label, ts) in [(REPORT_DIRS[0], false), (REPORT_DIRS[1], true)] {
            let path = self.dir(label)?.join("report.html");
            let path_text = path.display().to_string();
            let args = [
                "report",
                "--max-pages",
                "3",
                "--output-file",
                path_text.as_str(),
            ];
            let exec = if ts {
                self.ts(check, &args)?
            } else {
                self.rust(check, &args)?
            };
            let mode = mode_of(&path);
            let html = std::fs::read_to_string(&path).unwrap_or_default();
            let _ = std::fs::remove_dir_all(path.parent().unwrap_or(&path));
            runs.push((exec, mode, html));
        }
        let (ts, ts_mode, ts_html) = runs.pop().expect("the TypeScript run");
        let (rust, rust_mode, rust_html) = runs.pop().expect("the Rust run");
        let leak = super::leak_in(&self.session.secrets, &rust_html).is_some()
            || uuids.iter().any(|uuid| rust_html.contains(uuid.as_str()));
        let shapes = report_shape(&rust_html).zip(report_shape(&ts_html));
        let files =
            rust.code == ts.code && rust_mode == Some(0o600) && ts_mode == Some(0o600) && !leak;
        let same = shapes.as_ref().is_some_and(|(r, t)| reports_agree(r, t));
        let g71 = !same
            && self.g71
            && shapes
                .as_ref()
                .is_some_and(|(r, t)| reports_agree_g71(r, t));
        Ok(ReportPair {
            rust,
            ts,
            agree: files && (same || g71),
            leak,
            g71: files && g71,
        })
    }
}

/// One Rust `--include-content` run (see [`Reads::content_run`]).
enum ContentRun {
    /// Refused with this HTTP 401, 403 or 404.
    Refused(Exec, u16),
    Checked(ContentCheck),
}

/// The parts of the D321 check of one content run; `exec` without its streams.
struct ContentCheck {
    exec: Exec,
    /// The finding uuids, in order (in memory only).
    ids: Vec<String>,
    code_ok: bool,
    included: bool,
    notice: bool,
    stderr_clean: bool,
    log_clean: bool,
    /// How many content strings were looked for outside stdout.
    strings: usize,
}

impl ContentCheck {
    /// The findings are the plain read's (`ids`, when it ran).
    fn same_ids(&self, ids: Option<&[String]>) -> bool {
        ids.is_none_or(|ids| self.ids == ids)
    }

    fn ok(&self, ids: Option<&[String]>) -> bool {
        self.code_ok
            && self.included
            && self.same_ids(ids)
            && self.notice
            && self.stderr_clean
            && self.log_clean
    }

    fn note(&self, ids: Option<&[String]>) -> String {
        if self.ok(ids) {
            format!(
                "content on stdout only; the D321 notice; the debug log holds status and headers ({} content strings checked)",
                self.strings
            )
        } else {
            format!(
                "content check failed: exit ok {}, same findings {}, notice {}, stderr clean {}, debug log clean {}",
                self.code_ok,
                self.same_ids(ids),
                self.notice,
                self.stderr_clean,
                self.log_clean
            )
        }
    }
}

/// The row note of a content run refused after the plain read answered (choice 57).
fn refused_note(status: u16) -> String {
    format!("content run refused after the plain read succeeded: HTTP {status}")
}

/// One report pair: both runs, whether they agree, whether the Rust file leaked, whether
/// they agree only as G71 allows ([`reports_agree_g71`]).
struct ReportPair {
    rust: Exec,
    ts: Exec,
    agree: bool,
    leak: bool,
    g71: bool,
}

/// Runs the supplychain reads and returns the sanitized summary.
pub fn run_live_supplychain_reads(plan: &LivePlan) -> Result<LiveReport, LiveAbort> {
    let mut session = Session::open(plan)?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut reads = Reads {
            session: &mut session,
            g71: false,
            ts_scan_ok: false,
        };
        reads.steps()?;
        reads.session.verify()?;
        reads.session.summary_check()
    }));
    for label in REPORT_DIRS.iter().chain([&DEBUG_DIR]) {
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

/// The supplychain routes a live flow may reach: `GET` only; a self-test checks the
/// fixture's request log with it. Every request under the data or management base counts,
/// whatever its route: the fixture classifies only a `GET` as `Route::Supplychain`, so a
/// write there is an unknown route.
pub fn reads_only(requests: &[crate::RecordedRequest]) -> Result<(), String> {
    use crate::fixtures::supplychain as fx;
    let bad = requests
        .iter()
        .filter(|request| {
            let path = request
                .path
                .strip_prefix(request.base)
                .unwrap_or(&request.path);
            let under = |base: &str| path == base || path.starts_with(&format!("{base}/"));
            (matches!(request.route, crate::Route::Supplychain(_))
                || under(fx::DATA_PREFIX)
                || under(fx::MGMT_PREFIX))
                && request.method != "GET"
        })
        .count();
    if bad == 0 {
        Ok(())
    } else {
        Err(format!(
            "the live flow sent {bad} non-read supplychain request(s)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Choice 149's pattern: a json mismatch names the printable members on the Rust side,
    /// counts the rest and the TypeScript-only ones, and never prints a value.
    #[test]
    fn json_notes_name_shapes_and_counts_only() {
        let rust = json!({"pagination": {"total_items": 2}, "scans": [{"uuid": "SECRETVALUE", "extra_x": 1, "k9": 2}]});
        let ts = json!({"pagination": {"total_items": 2}, "scans": [{"uuid": "OTHERVALUE", "tsonly": 3}], "more": []});
        let note = json_note(&rust, &ts);
        assert_eq!(
            note,
            "json differs: records 1/1 (airs-cli-rs/TypeScript); members airs-cli-rs only: extra_x, 1 unprintable; members TypeScript only: 2"
        );
        assert!(!note.contains("SECRETVALUE") && !note.contains("tsonly"));
        assert_eq!(
            json_note(&json!({"a": 1}), &json!({"a": 2})),
            "json differs: records 1/1 (airs-cli-rs/TypeScript); the same members; values differ"
        );
    }

    /// Tables compare as multisets of trimmed cells (padding aside, D53); a mismatch note
    /// holds row and cell counts only.
    #[test]
    fn tables_compare_by_cells() {
        let rust = " uuid │ name \n─────┼─────\n a    │ 日本 \n b    │ x    \n";
        let ts = " uuid │ name \n─────┼─────\n b │ x \n a │ 日本 \n";
        assert!(tables_agree(rust, ts));
        assert!(tables_agree("\n", "\n"));
        let other = " uuid │ name \n─────┼─────\n a │ SECRETCELL \n";
        assert!(!tables_agree(rust, other));
        let note = table_note(rust, other);
        assert_eq!(
            note,
            "tables differ: rows 2/1 (airs-cli-rs/TypeScript); header equal; differing cells: 3"
        );
        assert!(!note.contains("SECRETCELL"));
    }

    /// The projection check, D319, the finding ids and the content strings.
    #[test]
    fn documents_are_read_as_the_flow_reads_them() {
        let scan = json!({"uuid": "u", "artifact_type": "SKILL", "status": "COMPLETED", "eval_outcome": null,
            "created_at": "t", "vulnerability_count": 1, "attack_chain_count": 0, "is_batch": false, "parent_uuid": null});
        assert!(projected(
            &json!({"pagination": {}, "scans": [scan.clone()]})
        ));
        let mut leaked = scan.clone();
        leaked["name"] = json!("x");
        assert!(!projected(&json!({"scans": [leaked]})));
        let doc = json!({"pagination": {"total_items": 3}, "vulnerabilities": [
            {"uuid": "f1", "title": "a long title", "original_code": "short", "file_path": "src/a/b/c.py"},
            {"uuid": "f2", "description": "described at length"}
        ], "content_included": true});
        assert!(short_list(&doc));
        assert_eq!(finding_ids(&doc), ["f1", "f2"]);
        assert_eq!(
            content_strings(&doc),
            ["a long title", "src/a/b/c.py", "described at length"]
        );
        assert!(has_array_member(&json!({"a": {}, "b": []})));
        assert!(!has_array_member(&json!({"a": {}})));
    }

    /// The debug check: JSON records with no body and no query, and none of the content.
    #[test]
    fn debug_logs_must_hold_status_and_headers_only() {
        let clean = r#"{"operation":"oauth.token","request":{"method":"POST","url":"http://h/oauth/token","headers":{}},"response":{"status":200}}
{"operation":"airs.agentguard.list_scan_vulnerabilities","request":{"method":"GET","url":"http://h/v1/scans/u/vulnerabilities","headers":{}},"response":{"status":200,"headers":{}}}
"#;
        let content = vec!["api_key = os.environ".to_owned()];
        assert!(debug_clean(clean, &content));
        assert!(!debug_clean("", &content), "no log is not a clean log");
        assert!(!debug_clean(
            &clean.replace("/vulnerabilities", "/vulnerabilities?skip=1"),
            &content
        ));
        assert!(!debug_clean(
            &clean.replace("\"headers\":{}}}", "\"headers\":{},\"body\":\"x\"}}"),
            &content
        ));
        assert!(!debug_clean(
            &format!("{clean}{{\"note\":\"api_key = os.environ\"}}\n"),
            &content
        ));
        assert!(!debug_clean("not json\n", &content));
    }

    fn recorded(method: &str, path: &str) -> crate::RecordedRequest {
        let route = crate::Route::classify(method, path).0;
        crate::RecordedRequest {
            seq: 0,
            connection: 0,
            method: method.to_owned(),
            path: path.to_owned(),
            raw_query: None,
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
            route,
            base: crate::Route::base_of(path),
            path_tsg: None,
            auth: crate::AuthIdentity::None,
            basic_encoding: None,
        }
    }

    /// A write under either supplychain base fails the check, though the fixture records
    /// it as an unknown route; reads and other planes pass.
    #[test]
    fn reads_only_sees_writes_on_unknown_routes() {
        let reads = [
            recorded("GET", "/agentguard/data/v1/scans"),
            recorded("GET", "/agentguard/mgmt/v1/rules"),
            recorded("POST", "/oauth2/access_token"),
        ];
        assert!(reads_only(&reads).is_ok());
        for (method, path) in [
            ("POST", "/agentguard/mgmt/v1/rules"),
            ("DELETE", "/agentguard/data/v1/scans/u"),
            ("PUT", "/agentguard/data"),
        ] {
            let write = recorded(method, path);
            assert_eq!(write.route, crate::Route::Unknown, "{method} {path}");
            let mut log = reads.to_vec();
            log.push(write);
            assert_eq!(
                reads_only(&log),
                Err("the live flow sent 1 non-read supplychain request(s)".to_owned()),
                "{method} {path}"
            );
        }
    }

    /// A JWT shape inside the finding rows of a content stdout is scanned content; outside
    /// them (or in a stdout that is not the document) it is still seen.
    #[test]
    fn content_stdout_is_checked_outside_the_findings() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc";
        let inside = json!({"pagination": {"total_items": 1}, "vulnerabilities": [{"uuid": "f", "original_code": format!("AUTH = '{jwt}'")}], "content_included": true}).to_string();
        assert!(super::super::leak_in(&[], &inside).is_some());
        assert!(!super::super::contains_jwt(&outside_findings(&inside)));
        assert!(outside_findings(&inside).contains("content_included"));
        let outside = json!({"pagination": {"note": jwt}, "vulnerabilities": []}).to_string();
        assert!(super::super::contains_jwt(&outside_findings(&outside)));
        let text = format!("not json {jwt}");
        assert!(super::super::contains_jwt(&outside_findings(&text)));
    }

    /// D318 is tolerated only in its shape: the Rust field rows equal the statistics
    /// document and the TypeScript table is an array member's record table.
    #[test]
    fn the_d318_tolerance_keeps_comparing_the_fields() {
        let doc = json!({
            "unique_skills_scanned": {"count": 4, "percent_change": 12.5},
            "total_vulnerabilities_found": {"count": 7, "percent_change": null},
            "top_vulnerability": null,
            "zz_list": [{"k": 1, "skill_name": "a"}, {"k": 2}],
            "zz_window": "30_DAYS"
        });
        let field_table = |count: u64| {
            format!(
                " Field │ Value \n───┼───\n unique_skills_scanned │ {{\"count\":{count},\"percent_change\":12.5}} \n total_vulnerabilities_found │ {{\"count\":7,\"percent_change\":null}} \n top_vulnerability │ null \n zz_list │ [{{\"k\":1,\"skill_name\":\"a\"}},{{\"k\":2}}] \n zz_window │ 30_DAYS \n"
            )
        };
        let record_table = " k │ skill name \n───┼───\n 1 │ a \n 2 │  \n";
        assert_eq!(d318_tolerated(&doc, &field_table(4), record_table), Ok(()));
        assert_eq!(
            d318_tolerated(&doc, &field_table(999), record_table),
            Err("field rows differing from the statistics document: 1".to_owned())
        );
        assert_eq!(
            d318_tolerated(
                &doc,
                &field_table(4),
                " k │ other \n───┼───\n 1 │ a \n 2 │ b \n"
            ),
            Err("the TypeScript table is not an array member's record table".to_owned())
        );
        assert_eq!(
            d318_tolerated(&doc, &field_table(4), " k \n───\n 1 \n"),
            Err("the TypeScript table is not an array member's record table".to_owned())
        );
        assert!(d318_tolerated(&doc, record_table, record_table).is_err());
        assert!(d318_tolerated(&doc, &field_table(4), "\n").is_err());
    }

    fn exec(code: Option<i32>, stdout: &str, stderr: &str) -> Exec {
        Exec {
            code,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            elapsed: std::time::Duration::ZERO,
        }
    }

    /// G71 (D324) is only TypeScript's request line without a status, nothing on its
    /// stdout, exit 1, against a Rust run that exited 0; anything else is not G71.
    #[test]
    fn g71_is_only_the_status_less_request_line() {
        let rust = exec(Some(0), "{}", "");
        assert!(g71_refusal(&rust, &exec(Some(1), "", TS_REQUEST_LINE)));
        for ts in [
            exec(
                Some(1),
                "",
                &TS_REQUEST_LINE.replace("failed.", "failed (HTTP 500)."),
            ),
            exec(
                Some(1),
                "",
                "  ✗ AgentGuard request failed (HTTP 403). Check credentials, query options and service availability. No upstream body is included.\n",
            ),
            exec(Some(1), "x", TS_REQUEST_LINE),
            exec(Some(1), "", &format!("{TS_REQUEST_LINE}more\n")),
            exec(Some(2), "", TS_REQUEST_LINE),
            exec(None, "", TS_REQUEST_LINE),
            exec(Some(0), "{}", ""),
        ] {
            assert!(!g71_refusal(&rust, &ts), "{:?}", ts.stderr);
        }
        let ts = exec(Some(1), "", TS_REQUEST_LINE);
        assert!(!g71_refusal(&exec(Some(1), "", "x"), &ts));
        assert!(!g71_refusal(&exec(None, "", ""), &ts));
    }

    /// G71's Rust side needs rows: an empty listing (json or table) shows nothing the
    /// shared contract could refuse.
    #[test]
    fn g71_needs_rust_rows() {
        let scan = json!({"uuid": "u", "artifact_type": null, "status": null, "eval_outcome": null,
            "created_at": null, "vulnerability_count": null, "attack_chain_count": null, "is_batch": null, "parent_uuid": null});
        assert!(g71_listing(&json!({"pagination": {}, "scans": [scan]})));
        assert!(projected(&json!({"pagination": {}, "scans": []})));
        assert!(!g71_listing(&json!({"pagination": {}, "scans": []})));
        assert!(!g71_listing(&json!({"pagination": {}})));
        assert!(g71_table(" uuid │ status \n───┼───\n u │  \n"));
        assert!(!g71_table(" uuid │ status \n───┼───\n"));
        assert!(!g71_table("\n"));
    }

    /// The G71 report tolerance: TypeScript's Scans source unavailable with the failed
    /// note, the Rust one read; the rest equal; one more table section on the Rust side.
    #[test]
    fn the_g71_report_tolerance_keeps_comparing_the_rest() {
        let row = |source: &str, status: &str, note: &str| {
            (
                source.to_owned(),
                format!("{}()", source.to_lowercase()),
                status.to_owned(),
                note.to_owned(),
            )
        };
        let titled = |titles: &[&str], scans: (&str, &str), stats: &str| ReportShape {
            sections: std::iter::once("findings".to_owned())
                .chain((0..titles.len()).map(|n| format!("table-{n}")))
                .chain(std::iter::once("scope".to_owned()))
                .collect(),
            tables: titles.iter().map(|title| (*title).to_owned()).collect(),
            evidence: vec![
                row("Scans", scans.0, scans.1),
                row("Statistics", stats, "Collection completed."),
                row("Rules", "complete", "Collection completed."),
            ],
            csp: true,
            external: false,
        };
        let ts_titles = [
            "Skill statistics",
            "Rule catalog",
            "Evidence and completeness",
        ];
        let rust_titles = [
            SCAN_OUTCOMES,
            "Skill statistics",
            "Rule catalog",
            "Evidence and completeness",
        ];
        let shape = |tables: usize, scans: (&str, &str), stats: &str| {
            let titles: &[&str] = if tables == 4 {
                &rust_titles
            } else {
                &ts_titles[..tables.min(3)]
            };
            titled(titles, scans, stats)
        };
        let rust = shape(4, ("partial", TIMESTAMP_NOTE), "complete");
        let ts = shape(3, ("unavailable", FAILED_SOURCE_NOTE), "complete");
        assert!(!reports_agree(&rust, &ts));
        assert!(reports_agree_g71(&rust, &ts));
        // The same section count, but the Rust report dropped a table (`Rule catalog`) and
        // added two (`Scan outcomes` and another): not G71. Nor is an extra table that is
        // not `Scan outcomes`.
        let scans = ("partial", TIMESTAMP_NOTE);
        let swapped = titled(
            &[
                SCAN_OUTCOMES,
                "Skill statistics",
                "Other",
                "Evidence and completeness",
            ],
            scans,
            "complete",
        );
        assert_eq!(swapped.sections.len(), ts.sections.len() + 1);
        assert!(!reports_agree_g71(&swapped, &ts));
        let other_extra = titled(
            &[
                "Other",
                "Skill statistics",
                "Rule catalog",
                "Evidence and completeness",
            ],
            scans,
            "complete",
        );
        assert!(!reports_agree_g71(&other_extra, &ts));
        // Another TypeScript note, a Rust source that also failed, a differing statistic,
        // the same section count, or a missing CSP are not G71.
        for (rust, ts) in [
            (rust.clone(), shape(3, ("unavailable", "other"), "complete")),
            (
                shape(4, ("unavailable", FAILED_SOURCE_NOTE), "complete"),
                ts.clone(),
            ),
            (
                rust.clone(),
                shape(3, ("unavailable", FAILED_SOURCE_NOTE), "partial"),
            ),
            (
                shape(3, ("partial", TIMESTAMP_NOTE), "complete"),
                ts.clone(),
            ),
            (
                ReportShape {
                    csp: false,
                    ..rust.clone()
                },
                ts.clone(),
            ),
        ] {
            assert!(!reports_agree_g71(&rust, &ts));
        }
    }

    /// Report shapes: sections, evidence rows, the CSP; D322 tolerated only for Scans with
    /// the timestamp note.
    #[test]
    fn reports_compare_by_structure() {
        let html = |status: &str, note: &str| {
            format!(
                "<!doctype html>\n<meta http-equiv=\"Content-Security-Policy\" content=\"x\"><section id=\"findings\"></section><section id=\"table-0\"><h2>Evidence and completeness</h2><table><thead><tr><th>Source</th></tr></thead><tbody><tr><td>Scans</td><td>listScans()</td><td>w</td><td>{status}</td><td>1</td><td>1</td><td>{note}</td></tr></tbody></table></section>"
            )
        };
        let rust = report_shape(&html("partial", TIMESTAMP_NOTE)).unwrap();
        let ts = report_shape(&html("complete", "Collection completed.")).unwrap();
        assert_eq!(rust.sections, ["findings", "table-0"]);
        assert_eq!(rust.tables, ["Evidence and completeness"]);
        assert_eq!(rust.evidence[0].0, "Scans");
        assert!(reports_agree(&rust, &ts));
        let other = report_shape(&html("partial", "Inventory incomplete")).unwrap();
        assert!(!reports_agree(&other, &ts));
        let external = report_shape(&html("complete", "<img src=x>")).unwrap();
        assert!(!reports_agree(&external, &ts));
        assert!(report_shape("<html>").is_none());
    }
}
