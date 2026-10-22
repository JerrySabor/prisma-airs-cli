//! Shared supplychain rules (DESIGN §20.3, §20.4; TypeScript `agentguard`, renamed, D308):
//! the argument checks (every one runs during planning, before the tenant is read, D314),
//! the options of every SDK call, the failure lines (D325's contract line for a page G71's
//! tolerant scan read refuses, [`scans`]), the page checks and the pagination document of the
//! two walks on the shared `walk::walk_with`.

pub mod scans;
pub mod views;

use crate::error::{CliError, InterruptContext};
use crate::json::OValue;
use crate::output::{Output, terminal_safe};
use crate::pagination::MAX_SAFE_INTEGER;
use crate::render::style::Style;
use crate::walk::{self, Page, Spec};
use scm::airs::agentguard::models::{FiniteNumber, Optional};
use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

/// The `--limit` default of both lists (TS `pageOptions`).
pub const DEFAULT_LIMIT: u32 = 10;
/// The one statistics period the service supports (TS zod literal, G70).
pub const TIME_PERIOD: &str = "30_DAYS";
/// The longest value a usage message quotes (§20.3).
const QUOTED_CHARS: usize = 200;

/// A member of an ordered JSON object (the documents and projections of §20.5–§20.8).
pub(crate) fn member(key: &str, value: OValue) -> (String, OValue) {
    (key.to_owned(), value)
}

/// A count as a query number of the SDK (`skip`, `limit`).
pub(crate) fn count(value: u64) -> Optional<FiniteNumber> {
    Optional::Value(FiniteNumber::from(value))
}

/// The validated list flags of `scans list` and `rules list` (§20.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paging {
    pub limit: u32,
    pub offset: u64,
    pub all: bool,
    /// `--max` (default 10,000; `0`: no item cap, D317).
    pub max: u64,
}

/// Decimal digits only (`^[0-9]+$`, leading zeros accepted), as a `u64`.
pub(crate) fn digits(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let trimmed = value.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(0);
    }
    trimmed.parse().ok()
}

/// `--limit`, `--offset` and `--max`, in that order (D314, D315): `--limit` 1 to
/// 4,294,967,295, `--offset` and `--max` 0 to 2^53 − 1, decimal digits only. `--max` is
/// checked even without `--all` (TS), then ignored.
pub fn paging(
    limit: Option<&str>,
    offset: Option<&str>,
    all: bool,
    max: Option<&str>,
) -> Result<Paging, CliError> {
    let limit = match limit {
        None => DEFAULT_LIMIT,
        Some(value) => digits(value)
            .filter(|n| *n >= 1)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| CliError::usage("--limit must be a positive integer"))?,
    };
    let offset = match offset {
        None => 0,
        Some(value) => digits(value)
            .filter(|n| *n <= MAX_SAFE_INTEGER)
            .ok_or_else(|| CliError::usage("--offset must be a non-negative integer"))?,
    };
    let max = match max {
        None => crate::pagination::DEFAULT_MAX,
        Some(value) => digits(value)
            .filter(|n| *n <= MAX_SAFE_INTEGER)
            .ok_or_else(|| CliError::usage("--max must be a safe nonnegative integer"))?,
    };
    Ok(Paging {
        limit,
        offset,
        all,
        max,
    })
}

/// The validated creation-time bounds of `scans list`, sent as typed (§20.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanWindow {
    pub start: Option<String>,
    pub end: Option<String>,
}

fn timestamp_error(flag: &str) -> CliError {
    CliError::usage(format!(
        "{flag} must be an ISO-8601 timestamp with a timezone (for example 2026-10-01T00:00:00Z)"
    ))
}

/// `--start` and `--end` (§20.3): zod 3's `datetime({ offset: true })` grammar through the
/// shared checker (`modelsec::datetime`, choice 43); with both, the start instant must not
/// be after the end instant. A matching value that is no JavaScript instant passes alone
/// and fails the order check with the other bound (TS `Date.parse` gives NaN).
pub fn window(start: Option<&str>, end: Option<&str>) -> Result<ScanWindow, CliError> {
    let start_at = start
        .map(|value| crate::modelsec::datetime(value).ok_or_else(|| timestamp_error("--start")))
        .transpose()?;
    let end_at = end
        .map(|value| crate::modelsec::datetime(value).ok_or_else(|| timestamp_error("--end")))
        .transpose()?;
    if let (Some(start_at), Some(end_at)) = (start_at, end_at) {
        match (start_at, end_at) {
            (Some(a), Some(b)) if a <= b => {}
            _ => return Err(CliError::usage("--start must not be after --end")),
        }
    }
    Ok(ScanWindow {
        start: start.map(str::to_owned),
        end: end.map(str::to_owned),
    })
}

/// A value quoted in a usage message: terminal-safe, at most 200 characters, then `…`.
fn quoted(value: &str) -> String {
    let safe = terminal_safe(value);
    let mut chars = safe.chars();
    let head: String = chars.by_ref().take(QUOTED_CHARS).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// `<scanUuid>` (§20.3): the 8-4-4-4-12 hex shape in any case (the SDK and zod rule), else
/// `Invalid scanUuid: <value> (expected a UUID)`. A valid id is sent as typed.
pub fn scan_uuid(value: &str) -> Result<String, CliError> {
    if crate::pagination::is_uuid(value) {
        Ok(value.to_owned())
    } else {
        Err(CliError::usage(format!(
            "Invalid scanUuid: {} (expected a UUID)",
            quoted(value)
        )))
    }
}

/// `--time-period` (§20.3): exactly `30_DAYS`, case-sensitive (choice 42).
pub fn time_period(value: Option<&str>) -> Result<(), CliError> {
    match value {
        None | Some(TIME_PERIOD) => Ok(()),
        Some(_) => Err(CliError::usage(
            "--time-period must be 30_DAYS (the only period the service supports)",
        )),
    }
}

/// The options of every supplychain SDK call (§20.3, choices 2 and 3): the budget, no
/// retries (TS `numRetries: 0`; the G63 re-read is `clients::reread`) and the typed
/// answer validated without the frozen schema defaults.
pub fn options(budget: Duration) -> Result<scm::RequestOptions, CliError> {
    sdk_options(budget).map_err(|_| {
        CliError::operational("AISEC_SDK_ERROR:The request options could not be configured")
    })
}

/// [`options`] as the SDK result (the report's per-source budget builds them, §20.9).
pub fn sdk_options(budget: Duration) -> scm::Result<scm::RequestOptions> {
    scm::RequestOptions::with_timeout(budget)
        .and_then(|options| options.with_retries(0))
        .map(scm::RequestOptions::without_response_defaults)
}

/// The tail of TypeScript's request failure line (`ag.ts:81-92`).
const FAILED_TAIL: &str =
    "Check credentials, query options and service availability. No upstream body is included.";

/// TypeScript's request failure line without its indent and colour: ` (HTTP <s>)` only for
/// a status from 400 to 599 (§20.3, choice 5).
pub fn request_failure_text(status: Option<u16>) -> String {
    let status = status
        .filter(|status| (400..=599).contains(status))
        .map_or_else(String::new, |status| format!(" (HTTP {status})"));
    format!("✗ AgentGuard request failed{status}. {FAILED_TAIL}")
}

/// The size-bound line (D320, G66).
pub const SIZE_FAILURE: &str = "✗ AgentGuard response was larger than 32 MiB; nothing was printed. No upstream body is included.";

/// The incomplete finding list line (D319, G61).
pub fn incomplete_findings_text(returned: usize, total: u64, scan: &str) -> String {
    format!(
        "✗ The service returned {returned} of {total} findings for scan {}; the list is incomplete (the API offers no paging)",
        terminal_safe(scan)
    )
}

/// Whether an SDK error is the response size bound (D320): a `Limit` the SDK raised while
/// reading an answer (failure kind `Http`) without an error status. A `Limit` with an
/// error status is an HTTP failure; a local one (a query over the URL bound) and the
/// walk's own bounds (§20.4) carry no failure kind and print the request line.
pub fn is_oversized(error: &scm::Error) -> bool {
    error.kind() == scm::ErrorKind::Limit
        && error.failure_kind() == Some(scm::FailureKind::Http)
        && !error
            .status()
            .is_some_and(|status| (400..=599).contains(&status))
}

/// The contract failure line (D325, G71): an answer the CLI's tolerant scan projection
/// still refuses (§20.5), for example a scan without a string `uuid`.
pub const CONTRACT_FAILURE: &str = "✗ The AgentGuard answer does not match the API contract; nothing was printed. No upstream body is included.";

/// Why a supplychain read failed after the client was built: an SDK error, or an answer
/// the CLI's own tolerant projection refused (G71, [`scans::project`]).
#[derive(Debug)]
pub enum Failure {
    Sdk(scm::Error),
    Contract,
}

impl From<scm::Error> for Failure {
    fn from(error: scm::Error) -> Self {
        Self::Sdk(error)
    }
}

/// Print a failed read (§20.3): an SDK error as [`failure`], a refused answer as the
/// contract line (D325; stderr, red, never suppressed), exit 1.
pub fn read_failure(output: &mut Output, failed: &Failure) -> CliError {
    match failed {
        Failure::Sdk(error) => failure(output, error),
        Failure::Contract => {
            fail_line(output, CONTRACT_FAILURE);
            CliError::Reported(crate::error::EXIT_OPERATIONAL)
        }
    }
}

/// Print a failed read after the client was built (§20.3): a cancellation stays an
/// interruption; the size bound ([`is_oversized`]) is its own line; anything else is
/// TypeScript's request failure line with at most the HTTP status (stderr, red as one
/// span, never suppressed, no error block), exit 1.
pub fn failure(output: &mut Output, error: &scm::Error) -> CliError {
    if error.kind() == scm::ErrorKind::Cancelled {
        return CliError::Interrupted(InterruptContext::NoDataWritten);
    }
    let text = if is_oversized(error) {
        SIZE_FAILURE.to_owned()
    } else {
        request_failure_text(error.status())
    };
    fail_line(output, &text);
    CliError::Reported(crate::error::EXIT_OPERATIONAL)
}

/// `  <red ✗ text>` on stderr, never suppressed.
pub fn fail_line(output: &mut Output, text: &str) {
    let line = output.paint_err(Style::Red, text);
    output.write_stderr(&format!("  {line}\n"));
}

/// Which list a page belongs to (§20.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `scans list`: `total_items` is the inventory count.
    Scans,
    /// `rules list`: `total_items` is the page length (G62), so it is never read.
    Rules,
}

/// One page as the CLI reads it: the printed rows (each with its `uuid`) and, for scans,
/// `pagination.total_items`.
pub struct ListPage {
    pub rows: Vec<OValue>,
    pub total: Option<u64>,
}

/// The pagination document (§20.4; TS keys and order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pagination {
    pub total_items: Option<u64>,
    pub returned: usize,
    pub skip: u64,
    pub next_offset: Option<u64>,
    pub truncated: bool,
}

impl Pagination {
    fn new(
        kind: Kind,
        total: Option<u64>,
        paging: &Paging,
        returned: usize,
        complete: bool,
    ) -> Self {
        let rows = u64::try_from(returned).unwrap_or(u64::MAX);
        let total_items = match kind {
            Kind::Scans => total,
            Kind::Rules => (complete && paging.offset == 0).then_some(rows),
        };
        Self {
            total_items,
            returned,
            skip: paging.offset,
            next_offset: (!complete).then(|| paging.offset.saturating_add(rows)),
            truncated: !complete,
        }
    }

    /// The document as ordered JSON.
    pub fn value(&self) -> OValue {
        let count = |n: u64| OValue::Number(n.into());
        let optional = |n: Option<u64>| n.map_or(OValue::Null, count);
        OValue::Object(vec![
            ("total_items".to_owned(), optional(self.total_items)),
            (
                "returned".to_owned(),
                count(u64::try_from(self.returned).unwrap_or(u64::MAX)),
            ),
            ("skip".to_owned(), count(self.skip)),
            ("next_offset".to_owned(), optional(self.next_offset)),
            ("truncated".to_owned(), OValue::Bool(self.truncated)),
        ])
    }
}

/// A finished listing: the rows and their pagination document.
pub struct Listed {
    pub rows: Vec<OValue>,
    pub pagination: Pagination,
}

fn unstable() -> scm::Error {
    scm::Error::new(scm::ErrorKind::Pagination)
}

/// The page checks of §20.4, in order, before any row of the page is taken: at most the
/// rows asked for; `scans`: the first page's total on every page; every `uuid` non-empty
/// and new to this command; `scans`: with rows collected, `--offset + rows` within the
/// total. `skip` is where the page starts.
struct Checks {
    kind: Kind,
    offset: u64,
    first_total: Option<u64>,
    seen: HashSet<String>,
}

impl Checks {
    fn new(kind: Kind, offset: u64) -> Self {
        Self {
            kind,
            offset,
            first_total: None,
            seen: HashSet::new(),
        }
    }

    /// `rows` and `total` of one page asked for `asked` rows at `skip`.
    fn check(
        &mut self,
        rows: &[OValue],
        total: Option<u64>,
        skip: u64,
        asked: u32,
    ) -> Result<(), scm::Error> {
        let received = u64::try_from(rows.len()).map_err(|_| unstable())?;
        if received > u64::from(asked) {
            return Err(unstable());
        }
        if self.kind == Kind::Scans {
            let total = total.ok_or_else(unstable)?;
            match self.first_total {
                None => self.first_total = Some(total),
                Some(first) if first != total => return Err(unstable()),
                Some(_) => {}
            }
        }
        for row in rows {
            let uuid = row.get("uuid").and_then(OValue::as_str).unwrap_or_default();
            if uuid.is_empty() || !self.seen.insert(uuid.to_owned()) {
                return Err(unstable());
            }
        }
        if let (Kind::Scans, Some(total)) = (self.kind, self.first_total) {
            let collected = skip.saturating_sub(self.offset).saturating_add(received);
            if collected > 0 && skip.saturating_add(received) > total {
                return Err(unstable());
            }
        }
        Ok(())
    }
}

/// The serialised size of a row (the walk's byte bound).
fn row_size(row: &OValue) -> usize {
    crate::json::to_compact(row).map_or(0, |text| text.len())
}

/// TypeScript's `inventory` (`ag.ts:94-133`, §20.4) on `walk_with`: without `--all` one
/// request at `--offset` (the walk is not entered); with `--all` pages from `--offset`,
/// each asking for at most the rows `--max` still allows (`Spec::shrink_last_page`), under
/// the §7.2 bounds (D317). `read(skip, limit)` sends one page request.
pub async fn inventory<F, Fut>(kind: Kind, paging: &Paging, mut read: F) -> Result<Listed, Failure>
where
    F: FnMut(u64, u32) -> Fut,
    Fut: Future<Output = Result<ListPage, Failure>>,
{
    let mut checks = Checks::new(kind, paging.offset);
    if !paging.all {
        let page = read(paging.offset, paging.limit).await?;
        checks.check(&page.rows, page.total, paging.offset, paging.limit)?;
        let rows = u64::try_from(page.rows.len()).unwrap_or(u64::MAX);
        let complete = match kind {
            Kind::Scans => page
                .total
                .is_some_and(|total| paging.offset.saturating_add(rows) >= total),
            Kind::Rules => rows < u64::from(paging.limit),
        };
        let pagination = Pagination::new(kind, page.total, paging, page.rows.len(), complete);
        return Ok(Listed {
            rows: page.rows,
            pagination,
        });
    }
    // A refused answer stops the walk as an SDK `Decode` and is reported as the contract
    // failure it was (only this listing sets the flag).
    let refused = std::cell::Cell::new(false);
    let spec = Spec {
        start: paging.offset,
        shrink_last_page: true,
        ..Spec::default()
    };
    let walked = walk::walk_with(
        spec,
        paging.limit,
        paging.max,
        |skip, asked| {
            let page = read(skip, asked);
            let refused = &refused;
            async move {
                let page = match page.await {
                    Ok(page) => page,
                    Err(Failure::Sdk(error)) => return Err(error),
                    Err(Failure::Contract) => {
                        refused.set(true);
                        return Err(scm::Error::new(scm::ErrorKind::Decode));
                    }
                };
                let total = match kind {
                    Kind::Scans => page.total,
                    Kind::Rules => None,
                };
                Ok(Page::new(page.rows, total))
            }
        },
        row_size,
        |_| None,
        |skip, asked, page| checks.check(&page.rows, page.total, skip, asked),
    )
    .await
    .map_err(|error| {
        if refused.get() {
            Failure::Contract
        } else {
            Failure::Sdk(error)
        }
    })?;
    let complete = !walked.stopped_at_max;
    let pagination = Pagination::new(
        kind,
        checks.first_total,
        paging,
        walked.rows.len(),
        complete,
    );
    Ok(Listed {
        rows: walked.rows,
        pagination,
    })
}

#[cfg(test)]
mod tests;
