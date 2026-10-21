//! Shared model-security rules (DESIGN §17.3): the UUID checks with the TypeScript field
//! words, the label-key segment rule, the creation-time window, the filter values and
//! comma lists, the list numbers and their defaults, and the options of every SDK call.
//! Every check here is pure and runs during planning, before the tenant is read (D184).

pub mod body;
pub mod fetch;
pub mod pypi;
pub mod uv;
pub mod views;

use crate::error::CliError;
use crate::redteam::{self, LimitText};
use crate::walk::ListParams;
use std::time::Duration;

/// The model-security banner (`renderModelSecurityHeader`).
pub const BANNER_TITLE: &str = "Prisma AIRS — Model Security";
pub const BANNER_SUBTITLE: &str = "ML model supply chain security";

/// The SDK bound on the values of one query (`ms:query.rs:19-21`).
pub const MAX_QUERY_VALUES: usize = 256;

/// The page size of the `scans list --scan-origin` walk (§17.5).
pub const ORIGIN_PAGE_SIZE: u32 = 100;

/// The page size of an `--all` walk without `--limit` on a list without a TypeScript
/// default (`collectSkipPages`).
pub const FALLBACK_PAGE_SIZE: u32 = 50;

/// The `--limit` default of the lists that declare one (TS `"20"`).
pub const DEFAULT_LIMIT: u32 = 20;

/// The options of every model-security SDK call (G20): the given budget (the SDK's own
/// 60 s for one request, the 300 s walk budget for a walk and its token) with the typed
/// response validated **without** the frozen schema defaults, so a summary the server sent
/// without counts is never turned into `0 failed` (D180).
pub fn options(budget: Duration) -> Result<scm::RequestOptions, CliError> {
    scm::RequestOptions::with_timeout(budget)
        .map(scm::RequestOptions::without_response_defaults)
        .map_err(|_| {
            CliError::operational("AISEC_SDK_ERROR:The request options could not be configured")
        })
}

/// The words of each model-security write (§17.3 "Writes and outcomes", D179).
pub mod change {
    use crate::writes::Change;

    pub const GROUP_CREATED: Change = Change::Words("security group", "created");
    pub const GROUP_UPDATED: Change = Change::Words("security group", "updated");
    pub const GROUP_DELETED: Change = Change::Words("security group", "deleted");
    pub const INSTANCE_UPDATED: Change = Change::Words("rule instance", "updated");
    pub const SCAN_CREATED: Change = Change::Words("scan", "created");
    pub const LABELS_ADDED: Change = Change::Words("labels", "added");
    pub const LABELS_REPLACED: Change = Change::Words("labels", "replaced");
    pub const LABELS_DELETED: Change = Change::Words("labels", "deleted");

    /// The hint after an unknown or unreadable `groups create`.
    pub const GROUP_CREATE_HINT: &str =
        "Check 'airs model-security groups list' before creating it again.";
    /// The hint after an unknown or unreadable `scans create` (billed, not deletable).
    pub const SCAN_CREATE_HINT: &str = "Check 'airs model-security scans list' before creating another scan; scans are billed and cannot be deleted.";

    /// The hint after an unknown or unreadable `groups delete <uuid>`.
    pub fn group_delete_hint(uuid: &str) -> String {
        format!("Check it with 'airs model-security groups get {uuid}'.")
    }
}

/// `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid <field>: <value>` (the TypeScript SDK's
/// `assertUuid` text) unless `value` has the UUID shape (exit 2, D184).
pub fn check_uuid(field: &str, value: &str) -> Result<(), CliError> {
    redteam::check_uuid(field, value)
}

/// `labels values <key>`: the SDK segment rule (G21), else `Invalid label key: <value>`.
pub fn check_label_key(key: &str) -> Result<(), CliError> {
    crate::segment::check_segment("label key", key)
}

/// A single-value filter (`--search`, `--state`, …): bounded (the SDK query rule); an
/// empty value sends no parameter (TS skips a falsy filter).
pub fn filter(flag: &str, value: Option<&str>) -> Result<Option<String>, CliError> {
    redteam::query_filter(flag, value)
}

/// A comma list (`--source-types`, `--enabled-rules`): split on `,`, each item trimmed
/// (TS); an empty item is a usage error (choice 8), each item is bounded, and the list
/// holds at most [`MAX_QUERY_VALUES`] items.
pub fn comma_list(flag: &str, value: Option<&str>) -> Result<Option<Vec<String>>, CliError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let items: Vec<String> = value
        .split(',')
        .map(|item| item.trim().to_owned())
        .collect();
    if items.iter().any(String::is_empty) {
        return Err(CliError::usage(format!("{flag} values must not be empty")));
    }
    if items.len() > MAX_QUERY_VALUES {
        return Err(CliError::usage(format!(
            "{flag} accepts at most {MAX_QUERY_VALUES} values"
        )));
    }
    for item in &items {
        redteam::check_filter(flag, item)?;
    }
    Ok(Some(items))
}

/// The query-value bound across the comma lists of one request (skip and limit count):
/// `<flag> accepts at most 256 values`, naming the longest list.
pub fn check_query_values(
    lists: &[(&str, Option<&Vec<String>>)],
    others: usize,
) -> Result<(), CliError> {
    let total: usize = others
        + lists
            .iter()
            .map(|(_, items)| items.map_or(0, Vec::len))
            .sum::<usize>();
    if total <= MAX_QUERY_VALUES {
        return Ok(());
    }
    let longest = lists
        .iter()
        .max_by_key(|(_, items)| items.map_or(0, Vec::len))
        .map_or("--source-types", |(flag, _)| flag);
    Err(CliError::usage(format!(
        "{longest} accepts at most {MAX_QUERY_VALUES} values"
    )))
}

/// The list flags (§17.3 "Numbers"): `--limit` 1..=u32::MAX, `--offset` a safe integer,
/// `--max` the §7.1 rule (validated even without `--all`), `--all` with `--offset`
/// refused; in that order.
pub fn list_params(
    limit: Option<&str>,
    offset: Option<&str>,
    all: bool,
    max: Option<&str>,
) -> Result<ListParams, CliError> {
    redteam::list_params(limit, offset, all, max, LimitText::Contract)
}

/// The window message (TS `supplyChainWindow`).
pub const WINDOW_MESSAGE: &str =
    "Use valid ISO timestamps with start <= end and a valid model-version UUID.";

/// The validated creation-time window of `scans list` and `models list` (values sent as
/// typed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub start: Option<String>,
    pub end: Option<String>,
    pub model_version: Option<String>,
}

/// TS `supplyChainWindow`: `--start` and `--end` must match zod 3's
/// `datetime({ offset: true })`, `--model-version` must be a UUID, and when both bounds
/// are given the start instant must not be after the end instant. An empty value is
/// absent (commander keeps `""`, which zod's `.optional()` refuses: TS fails on it too,
/// so an empty bound is refused here as well).
pub fn window(
    start: Option<&str>,
    end: Option<&str>,
    model_version: Option<&str>,
) -> Result<Window, CliError> {
    let refuse = || CliError::usage(WINDOW_MESSAGE);
    let start_at = start
        .map(|value| datetime(value).ok_or_else(refuse))
        .transpose()?;
    let end_at = end
        .map(|value| datetime(value).ok_or_else(refuse))
        .transpose()?;
    if let Some(uuid) = model_version
        && !crate::pagination::is_uuid(uuid)
    {
        return Err(refuse());
    }
    if let (Some(start_at), Some(end_at)) = (start_at, end_at) {
        // `Date.parse` of an offset outside ±23:59 is NaN, and NaN <= x is false.
        match (start_at, end_at) {
            (Some(a), Some(b)) if a <= b => {}
            _ => return Err(refuse()),
        }
    }
    Ok(Window {
        start: start.map(str::to_owned),
        end: end.map(str::to_owned),
        model_version: model_version.map(str::to_owned),
    })
}

/// [`datetime`] as epoch milliseconds: `Some` only for a text that matches the grammar
/// and is a valid JavaScript instant (the gateway windows, DESIGN §19.8).
pub(crate) fn datetime_millis(text: &str) -> Option<i64> {
    let nanos = datetime(text)??;
    i64::try_from(nanos.div_euclid(1_000_000)).ok()
}

/// zod 3 `datetime({ offset: true })` (`zod/v3/types.js:406-431`): a leap-year-checked
/// `YYYY-MM-DD`, `T`, `HH:MM`, an optional `:SS` with an optional fraction, then `Z` or
/// `±HH:MM` / `±HHMM`. `Some(instant)` when the text matches: the instant in nanoseconds
/// since the epoch, `None` when JavaScript's `Date.parse` would give NaN (an offset hour
/// above 23 or minute above 59). `None` outside: the text does not match.
pub(crate) fn datetime(text: &str) -> Option<Option<i128>> {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = bytes.get(range)?;
        if part.iter().all(u8::is_ascii_digit) {
            std::str::from_utf8(part).ok()?.parse().ok()
        } else {
            None
        }
    };
    if bytes.len() < 17 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > days_in_month {
        return None;
    }
    if bytes[13] != b':' {
        return None;
    }
    let (hour, minute) = (digits(11..13)?, digits(14..16)?);
    if hour > 23 || minute > 59 {
        return None;
    }
    let mut at = 16;
    let mut second = 0;
    let mut nanos: i128 = 0;
    if bytes.get(at) == Some(&b':') {
        second = digits(at + 1..at + 3)?;
        if second > 59 {
            return None;
        }
        at += 3;
        if bytes.get(at) == Some(&b'.') {
            let start = at + 1;
            let mut end = start;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            if end == start {
                return None;
            }
            // JavaScript dates keep milliseconds.
            let fraction = &text[start..end.min(start + 3)];
            let millis: i128 = format!("{fraction:0<3}").parse().ok()?;
            nanos = millis * 1_000_000;
            at = end;
        }
    }
    let rest = &text[at..];
    let offset_minutes: Option<i64> = if rest == "Z" {
        Some(0)
    } else {
        let sign = match rest.as_bytes().first() {
            Some(b'+') => 1,
            Some(b'-') => -1,
            _ => return None,
        };
        let body = &rest[1..];
        let (hh, mm) = match body.len() {
            5 if body.as_bytes()[2] == b':' => (&body[..2], &body[3..]),
            4 => (&body[..2], &body[2..]),
            _ => return None,
        };
        if !hh.bytes().chain(mm.bytes()).all(|b| b.is_ascii_digit()) {
            return None;
        }
        let (hh, mm): (i64, i64) = (hh.parse().ok()?, mm.parse().ok()?);
        (hh <= 23 && mm <= 59).then_some(sign * (hh * 60 + mm))
    };
    let Some(offset_minutes) = offset_minutes else {
        return Some(None);
    };
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset_minutes * 60;
    Some(Some(i128::from(seconds) * 1_000_000_000 + nanos))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month_index = (month + 9) % 12;
    let doy = (153 * month_index + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// How a list sends `skip` and `limit` on a single page (§17.3 "Lists and walks").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paging {
    /// `groups`, `rules`, `scans list`: always `skip=<--offset or 0>&limit=<--limit or 20>`.
    Always,
    /// `rule-instances list`, the scan sub-lists, the label lists: always
    /// `limit=<--limit or 20>`, `skip` only when `--offset` is given.
    LimitAlways,
    /// `models list|versions|files`: each only when given (the server's default page).
    WhenGiven,
}

impl Paging {
    /// The `skip` and `limit` of a single page.
    pub fn page(self, params: &ListParams) -> (Option<u64>, Option<u32>) {
        match self {
            Self::Always => (
                Some(params.offset.unwrap_or(0)),
                Some(params.limit.unwrap_or(DEFAULT_LIMIT)),
            ),
            Self::LimitAlways => (params.offset, Some(params.limit.unwrap_or(DEFAULT_LIMIT))),
            Self::WhenGiven => (params.offset, params.limit),
        }
    }

    /// The page size of an `--all` walk: `--limit`, else the command's default, else 50.
    pub fn walk_size(self, params: &ListParams) -> u32 {
        params.limit.unwrap_or(match self {
            Self::Always | Self::LimitAlways => DEFAULT_LIMIT,
            Self::WhenGiven => FALLBACK_PAGE_SIZE,
        })
    }
}

/// The status line of a single page (§17.3 "Status lines"; TS prints none, so a page
/// that shows everything prints none either, choice 6): a page whose total exceeds what
/// it shows names the next offset; a full page without a total says more may exist.
pub fn page_status(
    rows: usize,
    skip: u64,
    limit: Option<u32>,
    total: Option<u64>,
) -> Option<String> {
    let shown_to = skip.saturating_add(rows as u64);
    match total {
        Some(total) if total > shown_to => Some(format!(
            "Showing {rows} of {total} (next --offset {shown_to})"
        )),
        Some(_) => None,
        None => limit
            .filter(|limit| rows > 0 && rows as u64 == u64::from(*limit))
            .map(|_| format!("Showing {rows} (more may be available; use --all)")),
    }
}

/// The `--scan-origin` slice line (§17.5): without `--all`, `Showing <rows> of
/// <matching>[ (next --offset <offset + limit>)]`.
pub fn origin_status(rows: usize, matching: usize, offset: u64, limit: u32) -> String {
    let next = offset.saturating_add(u64::from(limit));
    if next < matching as u64 {
        format!("Showing {rows} of {matching} (next --offset {next})")
    } else {
        format!("Showing {rows} of {matching}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage<T: std::fmt::Debug>(result: Result<T, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    /// D184: the TS SDK's id text, any case accepted.
    #[test]
    fn uuids_and_label_keys_are_checked_with_the_typescript_words() {
        assert!(check_uuid("scan uuid", "11111111-1111-4111-8111-00000000000A").is_ok());
        assert_eq!(
            usage(check_uuid("security group uuid", "not-a-uuid")),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: not-a-uuid"
        );
        for key in ["", ".", "..", "a/../b", "%2e%2e", "a\\b", "a\u{1b}b"] {
            assert_eq!(
                usage(check_label_key(key)),
                format!("Invalid label key: {key}")
            );
        }
        assert!(check_label_key("a/b c?d").is_ok());
        assert!(check_label_key("env").is_ok());
    }

    /// The zod 3 `datetime({ offset: true })` shapes and the `start <= end` refinement.
    #[test]
    fn the_window_follows_zod_and_compares_instants() {
        for good in [
            "2026-01-01T00:00Z",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.123456Z",
            "2026-02-01T00:00:00+01:00",
            "2026-02-01T00:00:00-0130",
            "2024-02-29T10:00Z",
            "2000-02-29T10:00Z",
        ] {
            assert!(window(Some(good), None, None).is_ok(), "{good}");
        }
        for bad in [
            "2026-01-01",
            "2026-01-01T00:00:00",
            "2026-01-01 00:00:00Z",
            "2026-13-01T00:00Z",
            "2023-02-29T00:00Z",
            "1900-02-29T00:00Z",
            "2026-04-31T00:00Z",
            "2026-01-01T24:00Z",
            "2026-01-01T00:60Z",
            "2026-01-01T00:00:60Z",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00+1",
            "2026-01-01T00:00:00z",
            "",
        ] {
            assert_eq!(
                usage(window(Some(bad), None, None)),
                WINDOW_MESSAGE,
                "{bad}"
            );
        }
        assert!(
            window(
                Some("2026-01-01T00:00:00Z"),
                Some("2026-02-01T00:00:00+01:00"),
                Some("11111111-1111-4111-8111-000000000901")
            )
            .is_ok()
        );
        // Equal instants in different offsets.
        assert!(
            window(
                Some("2026-01-01T01:00:00+01:00"),
                Some("2026-01-01T00:00Z"),
                None
            )
            .is_ok()
        );
        assert_eq!(
            usage(window(
                Some("2026-02-01T00:00Z"),
                Some("2026-01-01T00:00Z"),
                None
            )),
            WINDOW_MESSAGE
        );
        assert_eq!(
            usage(window(None, None, Some("not-a-uuid"))),
            WINDOW_MESSAGE
        );
        // An offset JavaScript cannot parse: valid alone, refused in a comparison.
        assert!(window(Some("2026-01-01T00:00+99:00"), None, None).is_ok());
        assert_eq!(
            usage(window(
                Some("2026-01-01T00:00+99:00"),
                Some("2026-01-02T00:00Z"),
                None
            )),
            WINDOW_MESSAGE
        );
    }

    /// Choice 8: empty comma-list items are usage errors; items are trimmed.
    #[test]
    fn comma_lists_are_trimmed_and_refuse_empty_items() {
        assert_eq!(
            comma_list("--source-types", Some("LOCAL, S3")).unwrap(),
            Some(vec!["LOCAL".to_owned(), "S3".to_owned()])
        );
        for bad in ["", "LOCAL,,S3", ",", " , "] {
            assert_eq!(
                usage(comma_list("--source-types", Some(bad))),
                "--source-types values must not be empty"
            );
        }
        let many = vec!["x"; 257].join(",");
        assert_eq!(
            usage(comma_list("--enabled-rules", Some(&many))),
            "--enabled-rules accepts at most 256 values"
        );
        assert_eq!(
            usage(comma_list("--enabled-rules", Some(&"x".repeat(4097)))),
            "--enabled-rules must be at most 4096 bytes and contain no control characters"
        );
        let a = vec!["a".to_owned(); 200];
        let b = vec!["b".to_owned(); 60];
        assert_eq!(
            usage(check_query_values(
                &[("--source-types", Some(&a)), ("--enabled-rules", Some(&b))],
                2
            )),
            "--source-types accepts at most 256 values"
        );
        assert!(check_query_values(&[("--source-types", Some(&a))], 2).is_ok());
    }

    #[test]
    fn filters_are_bounded_and_empty_ones_are_not_sent() {
        assert_eq!(filter("--search", Some("")).unwrap(), None);
        assert_eq!(filter("--search", Some("x")).unwrap(), Some("x".to_owned()));
        assert_eq!(
            usage(filter("--state", Some("a\u{7}"))),
            "--state must be at most 4096 bytes and contain no control characters"
        );
    }

    /// §17.3 "Numbers": the contract texts, in order, before the tenant.
    #[test]
    fn list_numbers_follow_the_contract() {
        for (limit, offset, all, max, message) in [
            (
                Some("0"),
                None,
                false,
                None,
                "--limit must be a positive integer",
            ),
            (
                Some("abc"),
                None,
                false,
                None,
                "--limit must be a positive integer",
            ),
            (
                Some("1.5"),
                None,
                false,
                None,
                "--limit must be a positive integer",
            ),
            (
                Some("4294967296"),
                None,
                false,
                None,
                "--limit must be a positive integer",
            ),
            (
                None,
                Some("-2"),
                false,
                None,
                "--offset must be a non-negative integer",
            ),
            (
                None,
                Some("abc"),
                false,
                None,
                "--offset must be a non-negative integer",
            ),
            (
                None,
                None,
                false,
                Some("abc"),
                "--max must be a non-negative integer",
            ),
            (
                None,
                Some("0"),
                true,
                None,
                "--all cannot be combined with --offset",
            ),
        ] {
            assert_eq!(usage(list_params(limit, offset, all, max)), message);
        }
        let params = list_params(Some("4294967295"), None, true, Some("0")).unwrap();
        assert_eq!(params.limit, Some(u32::MAX));
        assert_eq!(params.max, 0);
    }

    /// The single-page `skip`/`limit` of each paging mode and the walk sizes.
    #[test]
    fn paging_modes_send_what_typescript_sends() {
        let none = ListParams::none();
        assert_eq!(Paging::Always.page(&none), (Some(0), Some(20)));
        assert_eq!(Paging::LimitAlways.page(&none), (None, Some(20)));
        assert_eq!(Paging::WhenGiven.page(&none), (None, None));
        let given = ListParams {
            limit: Some(5),
            offset: Some(3),
            ..ListParams::none()
        };
        assert_eq!(Paging::Always.page(&given), (Some(3), Some(5)));
        assert_eq!(Paging::LimitAlways.page(&given), (Some(3), Some(5)));
        assert_eq!(Paging::WhenGiven.page(&given), (Some(3), Some(5)));
        assert_eq!(Paging::Always.walk_size(&none), 20);
        assert_eq!(Paging::WhenGiven.walk_size(&none), 50);
        assert_eq!(Paging::WhenGiven.walk_size(&given), 5);
    }

    /// Choice 6: a status line only when a page does not show everything.
    #[test]
    fn status_lines_appear_only_when_a_page_is_incomplete() {
        assert_eq!(page_status(2, 0, Some(20), Some(2)), None);
        assert_eq!(
            page_status(2, 0, Some(2), Some(5)).as_deref(),
            Some("Showing 2 of 5 (next --offset 2)")
        );
        assert_eq!(
            page_status(2, 3, Some(2), Some(9)).as_deref(),
            Some("Showing 2 of 9 (next --offset 5)")
        );
        assert_eq!(
            page_status(2, 0, Some(2), None).as_deref(),
            Some("Showing 2 (more may be available; use --all)")
        );
        assert_eq!(page_status(1, 0, Some(2), None), None);
        assert_eq!(page_status(0, 0, Some(2), None), None);
        assert_eq!(page_status(3, 0, None, None), None);
        assert_eq!(
            origin_status(2, 5, 0, 2),
            "Showing 2 of 5 (next --offset 2)"
        );
        assert_eq!(origin_status(1, 5, 4, 2), "Showing 1 of 5");
    }

    #[test]
    fn days_from_civil_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }
}
