//! The scan list read (DESIGN §20.5, §20.9; G71): `GET <data>/v1/scans` sent as a raw read
//! on the SDK's AgentGuard data client and decoded by a CLI-side tolerant projection.
//!
//! Both SDKs require `fingerprint`, `name`, `artifact_type`, `status`, `created_at`,
//! `updated_at` (and more) to be non-null strings, and the service sends `null` in at least
//! `fingerprint`, so the typed `list_scans` refuses the whole page (G71). This read keeps
//! everything the typed call does except its response schema: the data client (the OAuth
//! bearer, `x-tsg-id`, the origin policy, the 32 MiB bound, D320), its validation bounds
//! (G66: depth 64 and 1,000,000 values, checked by [`within_bounds`]), the caller's options
//! (budget, `with_retries(0)`; the G63 re-read is the caller's), TypeScript's query keys,
//! order and value forms, the SDK's 16 KiB query bound (the engine's own preflight refuses
//! a longer query before the request is sent), and the `airs.agentguard.list_scans`
//! operation name in the `--debug` log (status and headers only). An empty 2xx body is a
//! `Decode` (the request line), not `{}`. The answer is then read by [`project`]:
//! - the page (an object), its `pagination` (an object) and `pagination.total_items` (a
//!   non-negative safe integer) and its `scans` (an array of objects) are the SDK's rules;
//! - each scan's `uuid` must be a string (the SDK's rule; its emptiness and uniqueness are
//!   the page checks of §20.4): a scan without a usable `uuid` refuses the page, it is never
//!   dropped;
//! - every other member the CLI reads accepts `null`, and an absent member reads as `null`:
//!   `artifact_type`, `status`, `eval_outcome`, `created_at`, `parent_uuid` (a string or
//!   `null`), `summary` (an object or `null`; its two counts each a non-negative safe integer
//!   or `null`), `is_batch` (a boolean or `null`), `child_scan_uuids` (an array, counted, or
//!   `null`); any other type refuses the page;
//! - nothing else of a scan is read: `name`, `git_url`, `fingerprint`, `device_metadata`,
//!   `error_message`, `eval_summary`, `eval_details`, `scanner_version`, `batch_summary`,
//!   `tsg_id`, `updated_at`, `duration_seconds` and the passthrough members are neither
//!   validated nor kept, so no value of theirs can reach an output (§20.11).

use crate::clients::SupplychainClients;
use crate::supplychain::Failure;
use crate::walk::total_of;
use scm::RawRequest;
use scm::airs::agentguard::models::FiniteNumber;
use serde_json::{Map, Number, Value};

/// The `--debug` operation name of the read (the typed SDK call's, G67).
pub const OPERATION: &str = "airs.agentguard.list_scans";

/// One scan-list request (TS `{skip, limit, start_time, end_time, isBackgroundRefresh:
/// false}`): the bounds only when given, sent as typed.
#[derive(Clone, Copy, Debug)]
pub struct ScanQuery<'a> {
    pub skip: u64,
    pub limit: u32,
    pub start: Option<&'a str>,
    pub end: Option<&'a str>,
}

/// A JavaScript number as the SDK writes it into a query (`ryu_js`, finite).
fn query_number(value: u64) -> String {
    let number = FiniteNumber::from(value).as_f64().unwrap_or(0.0);
    ryu_js::Buffer::new().format_finite(number).to_owned()
}

impl ScanQuery<'_> {
    /// The query pairs in the SDK's order (`skip`, `limit`, `isBackgroundRefresh`,
    /// `start_time`, `end_time`). The SDK's 16 KiB bound is not repeated here: the engine's
    /// preflight (`config::resolve`, before authentication and dispatch) refuses a longer
    /// query as a `Limit` with no status and no failure kind, the error the local copy
    /// raised (`tests/supplychain_reads.rs::failures::failures_print_the_typescript_line_only`:
    /// the request line, no GET sent).
    pub fn pairs(&self) -> Vec<(String, String)> {
        let mut pairs = vec![
            ("skip".to_owned(), query_number(self.skip)),
            ("limit".to_owned(), query_number(u64::from(self.limit))),
            ("isBackgroundRefresh".to_owned(), "false".to_owned()),
        ];
        if let Some(start) = self.start {
            pairs.push(("start_time".to_owned(), start.to_owned()));
        }
        if let Some(end) = self.end {
            pairs.push(("end_time".to_owned(), end.to_owned()));
        }
        pairs
    }
}

/// Send one scan-list request on the data plane with `options` and return the answer as
/// JSON (no schema applied; [`project`] reads it). One attempt: the caller re-reads after a
/// 401 or 403 (G63). An empty 2xx body is a local `Decode` with no status or failure kind,
/// printed like a body that is not JSON (the request line, choice 69; `send_json` would read it as
/// `{}`, which the projection refuses with the contract line). An answer over the G66
/// validation bounds ([`within_bounds`], with the bounds the client was built with,
/// computed once per command) is the typed call's `Limit`, so the request failure line,
/// as `scans vulnerabilities` prints it.
pub async fn send(
    clients: &SupplychainClients,
    query: &ScanQuery<'_>,
    options: &scm::RequestOptions,
) -> scm::Result<Value> {
    let request = RawRequest::read("/v1/scans").query(query.pairs());
    let answer = crate::debug::named(
        OPERATION,
        clients
            .agentguard
            .data_client()
            .send_optional_json::<Value>(request, Some(options)),
    )
    .await?
    .ok_or_else(|| scm::Error::new(scm::ErrorKind::Decode))?;
    if within_bounds(&answer, &clients.validation) {
        Ok(answer)
    } else {
        Err(scm::Error::new(scm::ErrorKind::Limit))
    }
}

/// The SDK's validation preflight over a decoded answer (G66, `validation::preflight`; the
/// raw read's decoder alone allows depth 128): the root at depth 0 and no value deeper
/// than `max_depth` (64), at most `max_nodes` values, at most `max_input_bytes` of keys and
/// strings. Iterative, so an answer at the decoder's depth cannot exhaust the stack. The
/// work bound counts the schema walk's steps, which this read does not take: the projection
/// reads a fixed number of members per scan, so its work is bounded by the value count.
pub fn within_bounds(answer: &Value, limits: &scm::validation::ValidationLimits) -> bool {
    let mut stack = vec![(answer, 0usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > limits.max_nodes || depth > limits.max_depth {
            return false;
        }
        match value {
            Value::String(text) => bytes = bytes.saturating_add(text.len()),
            Value::Array(values) => stack.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => {
                for (key, value) in values {
                    bytes = bytes.saturating_add(key.len());
                    stack.push((value, depth + 1));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        if bytes > limits.max_input_bytes {
            return false;
        }
    }
    true
}

/// A count of a scan's `summary`, `null` kept.
#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    pub vulnerability_count: Option<Number>,
    pub attack_chain_count: Option<Number>,
}

/// One scan as the CLI reads it (G71): `None` is a `null` or absent member.
#[derive(Clone, Debug, PartialEq)]
pub struct Scan {
    pub uuid: String,
    pub artifact_type: Option<String>,
    pub status: Option<String>,
    pub eval_outcome: Option<String>,
    pub created_at: Option<String>,
    pub summary: Option<Summary>,
    pub is_batch: Option<bool>,
    pub parent_uuid: Option<String>,
    /// The number of `child_scan_uuids`.
    pub children: Option<usize>,
}

/// One page: its scans and `pagination.total_items`.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanPage {
    pub scans: Vec<Scan>,
    pub total: u64,
}

/// Why an answer does not match the scan-list contract (no server value is kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The page, its `pagination`, its total or its `scans` array.
    Page,
    /// A scan that is not an object or has no string `uuid`.
    Identity,
    /// A read member of another type than the contract's (or `null`).
    Member,
}

impl From<Refused> for Failure {
    fn from(_: Refused) -> Self {
        Failure::Contract
    }
}

/// A member that is `null`, absent or of type `T` (`read`); any other value refuses.
fn nullable<'a, T>(
    scan: &'a Map<String, Value>,
    key: &str,
    read: impl Fn(&'a Value) -> Option<T>,
) -> Result<Option<T>, Refused> {
    match scan.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => read(value).map(Some).ok_or(Refused::Member),
    }
}

fn text(scan: &Map<String, Value>, key: &str) -> Result<Option<String>, Refused> {
    nullable(scan, key, |value| value.as_str().map(str::to_owned))
}

/// A summary member that is `null`, absent or a count (`walk::total_of`: a non-negative
/// safe integer); any other value refuses.
fn summary_count(summary: &Map<String, Value>, key: &str) -> Result<Option<Number>, Refused> {
    nullable(summary, key, |value| match value {
        Value::Number(number) => total_of(number.as_f64()).map(|_| number.clone()),
        _ => None,
    })
}

/// One scan (see the module rules).
pub fn scan(value: &Value) -> Result<Scan, Refused> {
    let scan = value.as_object().ok_or(Refused::Identity)?;
    let uuid = match scan.get("uuid") {
        Some(Value::String(uuid)) => uuid.clone(),
        _ => return Err(Refused::Identity),
    };
    let summary = match nullable(scan, "summary", Value::as_object)? {
        None => None,
        Some(summary) => Some(Summary {
            vulnerability_count: summary_count(summary, "vulnerability_count")?,
            attack_chain_count: summary_count(summary, "attack_chain_count")?,
        }),
    };
    Ok(Scan {
        uuid,
        artifact_type: text(scan, "artifact_type")?,
        status: text(scan, "status")?,
        eval_outcome: text(scan, "eval_outcome")?,
        created_at: text(scan, "created_at")?,
        summary,
        is_batch: nullable(scan, "is_batch", Value::as_bool)?,
        parent_uuid: text(scan, "parent_uuid")?,
        children: nullable(scan, "child_scan_uuids", |value| {
            value.as_array().map(Vec::len)
        })?,
    })
}

/// The tolerant projection of one scan-list answer (see the module rules).
pub fn project(answer: &Value) -> Result<ScanPage, Refused> {
    let page = answer.as_object().ok_or(Refused::Page)?;
    let total = page
        .get("pagination")
        .and_then(Value::as_object)
        .and_then(|pagination| pagination.get("total_items"))
        .and_then(Value::as_number)
        .and_then(|number| total_of(number.as_f64()))
        .ok_or(Refused::Page)?;
    let scans = page
        .get("scans")
        .and_then(Value::as_array)
        .ok_or(Refused::Page)?
        .iter()
        .map(scan)
        .collect::<Result<Vec<Scan>, Refused>>()?;
    Ok(ScanPage { scans, total })
}

#[cfg(test)]
#[path = "scans_tests.rs"]
mod tests;
