//! Unit tests of the shared supplychain rules (DESIGN §20.3, §20.4).

use super::*;
use std::cell::RefCell;

fn usage_text(error: CliError) -> String {
    match error {
        CliError::Usage(message) => message,
        other => panic!("expected a usage error, got {other:?}"),
    }
}

fn run<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

/// D314, D315: decimal digits only; `--limit` 1..=u32::MAX, `--offset` and `--max` up to
/// 2^53 − 1; the TS texts for `--max`; defaults 10, 0 and 10,000.
#[test]
fn paging_flags() {
    assert_eq!(
        paging(None, None, false, None).unwrap(),
        Paging {
            limit: 10,
            offset: 0,
            all: false,
            max: 10_000
        }
    );
    assert_eq!(
        paging(Some("007"), Some("0005"), true, Some("0")).unwrap(),
        Paging {
            limit: 7,
            offset: 5,
            all: true,
            max: 0
        }
    );
    assert_eq!(
        paging(Some("4294967295"), None, false, None).unwrap().limit,
        u32::MAX
    );
    assert_eq!(
        paging(
            None,
            Some("9007199254740991"),
            false,
            Some("9007199254740991")
        )
        .unwrap()
        .max,
        9_007_199_254_740_991
    );
    for limit in [
        "0",
        "",
        "abc",
        "1.5",
        "-1",
        "+1",
        " 1",
        "4294967296",
        "99999999999999999999",
    ] {
        assert_eq!(
            usage_text(paging(Some(limit), None, false, None).unwrap_err()),
            "--limit must be a positive integer",
            "{limit:?}"
        );
    }
    for offset in ["-1", "", "9007199254740992", "1e3"] {
        assert_eq!(
            usage_text(paging(None, Some(offset), false, None).unwrap_err()),
            "--offset must be a non-negative integer"
        );
    }
    for max in ["0x2", "1e0", " 2 ", "", "-0", "9007199254740992"] {
        assert_eq!(
            usage_text(paging(None, None, false, Some(max)).unwrap_err()),
            "--max must be a safe nonnegative integer",
            "{max:?}"
        );
    }
    // The order: --limit, then --offset, then --max.
    assert_eq!(
        usage_text(paging(Some("0"), Some("-1"), false, Some("x")).unwrap_err()),
        "--limit must be a positive integer"
    );
    assert_eq!(
        usage_text(paging(None, Some("-1"), false, Some("x")).unwrap_err()),
        "--offset must be a non-negative integer"
    );
}

/// §20.3: the zod `datetime({offset: true})` grammar per bound, then the order check;
/// values are kept as typed.
#[test]
fn windows() {
    let start =
        "--start must be an ISO-8601 timestamp with a timezone (for example 2026-10-01T00:00:00Z)";
    let end =
        "--end must be an ISO-8601 timestamp with a timezone (for example 2026-10-01T00:00:00Z)";
    assert_eq!(window(None, None).unwrap(), ScanWindow::default());
    let kept = window(Some("2026-10-01T00:00:00+02:00"), Some("2026-10-30T00:00Z")).unwrap();
    assert_eq!(kept.start.as_deref(), Some("2026-10-01T00:00:00+02:00"));
    assert_eq!(kept.end.as_deref(), Some("2026-10-30T00:00Z"));
    for bad in [
        "",
        "bad",
        "2026-10-01",
        "2026-10-01T00:00:00",
        "2026-10-01T00:00:00z",
        "2026-02-29T00:00Z",
    ] {
        assert_eq!(
            usage_text(window(Some(bad), None).unwrap_err()),
            start,
            "{bad:?}"
        );
        assert_eq!(
            usage_text(window(None, Some(bad)).unwrap_err()),
            end,
            "{bad:?}"
        );
    }
    assert!(window(Some("2028-02-29T00:00Z"), None).is_ok());
    assert!(
        window(Some("2026-10-01T00:00Z"), Some("2026-10-01T00:00:00.000Z")).is_ok(),
        "equal"
    );
    assert_eq!(
        usage_text(window(Some("2026-10-02T00:00Z"), Some("2026-10-01T00:00Z")).unwrap_err()),
        "--start must not be after --end"
    );
    // An offset beyond ±23:59 matches the grammar but is no instant: alone it passes, with
    // the other bound it fails the order check (TS `Date.parse` NaN).
    assert!(window(Some("2026-10-01T00:00+24:00"), None).is_ok());
    assert_eq!(
        usage_text(window(Some("2026-10-01T00:00+24:00"), Some("2026-10-30T00:00Z")).unwrap_err()),
        "--start must not be after --end"
    );
    // The start check comes first.
    assert_eq!(usage_text(window(Some("x"), Some("y")).unwrap_err()), start);
}

#[test]
fn scan_ids_and_the_time_period() {
    let id = "11111111-1111-4111-8111-00000000010A";
    assert_eq!(scan_uuid(id).unwrap(), id, "sent as typed");
    assert_eq!(
        usage_text(scan_uuid("../escape").unwrap_err()),
        "Invalid scanUuid: ../escape (expected a UUID)"
    );
    assert_eq!(
        usage_text(scan_uuid("a\u{1b}b").unwrap_err()),
        "Invalid scanUuid: a\u{fffd}b (expected a UUID)"
    );
    let long = "é".repeat(201);
    assert_eq!(
        usage_text(scan_uuid(&long).unwrap_err()),
        format!("Invalid scanUuid: {}… (expected a UUID)", "é".repeat(200))
    );
    assert!(time_period(None).is_ok());
    assert!(time_period(Some("30_DAYS")).is_ok());
    for bad in ["30_days", "week", "", " 30_DAYS"] {
        assert_eq!(
            usage_text(time_period(Some(bad)).unwrap_err()),
            "--time-period must be 30_DAYS (the only period the service supports)"
        );
    }
}

/// Choice 5, D320: the request line with a 400–599 status only; the size line for an SDK
/// `Limit` without an error status; a cancellation is an interruption.
#[test]
fn failure_lines() {
    assert_eq!(
        request_failure_text(Some(403)),
        "✗ AgentGuard request failed (HTTP 403). Check credentials, query options and service availability. No upstream body is included."
    );
    for status in [None, Some(200), Some(302), Some(600)] {
        assert_eq!(
            request_failure_text(status),
            "✗ AgentGuard request failed. Check credentials, query options and service availability. No upstream body is included."
        );
    }
    // (The size line for an answer over the bound and a status error are pinned by the
    // executable tests, `oversized_findings`: the SDK alone builds errors with a failure
    // kind or a status.)
    assert!(!is_oversized(&scm::Error::new(scm::ErrorKind::Decode)));
    assert_eq!(
        SIZE_FAILURE,
        "✗ AgentGuard response was larger than 32 MiB; nothing was printed. No upstream body is included."
    );
    let (mut out, stdout, stderr) = crate::output::testing::capture(true);
    let error = failure(&mut out, &crate::pagination::incomplete_walk());
    assert!(matches!(error, CliError::Reported(1)));
    assert_eq!(
        stderr.text(),
        "  ✗ AgentGuard request failed. Check credentials, query options and service availability. No upstream body is included.\n",
        "never quiet-suppressed; a walk bound is the request line (D317)"
    );
    assert_eq!(stdout.text(), "");
    let (mut out, stdout, stderr) = crate::output::testing::capture(false);
    let cancelled = failure(&mut out, &scm::Error::new(scm::ErrorKind::Cancelled));
    assert!(matches!(
        cancelled,
        CliError::Interrupted(InterruptContext::NoDataWritten)
    ));
    assert_eq!(stderr.text(), "");
    assert_eq!(stdout.text(), "");
    assert_eq!(
        incomplete_findings_text(3, 5, "id\u{1b}"),
        "✗ The service returned 3 of 5 findings for scan id\u{fffd}; the list is incomplete (the API offers no paging)"
    );
}

fn row(uuid: &str) -> OValue {
    OValue::Object(vec![("uuid".to_owned(), OValue::String(uuid.to_owned()))])
}

/// A service of `count` rows (`u<n>`) reporting `total` (scans) per page; records the
/// requests.
fn service(
    count: u64,
    total: Option<u64>,
    calls: &RefCell<Vec<(u64, u32)>>,
) -> impl FnMut(u64, u32) -> std::future::Ready<Result<ListPage, Failure>> + '_ {
    move |skip, limit| {
        calls.borrow_mut().push((skip, limit));
        let rows = (skip..count.min(skip + u64::from(limit)))
            .map(|n| row(&format!("u{n}")))
            .collect();
        std::future::ready(Ok(ListPage { rows, total }))
    }
}

fn listed(
    kind: Kind,
    paging: &Paging,
    count: u64,
    total: Option<u64>,
) -> (Listed, Vec<(u64, u32)>) {
    let calls = RefCell::new(Vec::new());
    let listed = run(inventory(kind, paging, service(count, total, &calls)))
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    (listed, calls.into_inner())
}

/// The SDK error of a failed listing (a contract failure is a test failure here).
fn sdk(failure: Failure) -> scm::Error {
    match failure {
        Failure::Sdk(error) => error,
        Failure::Contract => panic!("a contract failure"),
    }
}

fn params(limit: u32, offset: u64, all: bool, max: u64) -> Paging {
    Paging {
        limit,
        offset,
        all,
        max,
    }
}

/// §20.4's captured outcomes (SC§3) and the document's keys and order.
#[test]
fn inventory_documents() {
    let doc = |listed: &Listed| crate::json::to_compact(&listed.pagination.value()).unwrap();
    let (scans, calls) = listed(Kind::Scans, &params(2, 0, false, 10_000), 3, Some(3));
    assert_eq!(
        doc(&scans),
        r#"{"total_items":3,"returned":2,"skip":0,"next_offset":2,"truncated":true}"#
    );
    assert_eq!(calls, [(0, 2)], "one request without --all");
    let (scans, _) = listed(Kind::Scans, &params(10, 2, false, 10_000), 3, Some(3));
    assert_eq!(
        doc(&scans),
        r#"{"total_items":3,"returned":1,"skip":2,"next_offset":null,"truncated":false}"#
    );
    let (scans, _) = listed(Kind::Scans, &params(10, 5, false, 10_000), 2, Some(2));
    assert_eq!(
        scans.pagination,
        Pagination {
            total_items: Some(2),
            returned: 0,
            skip: 5,
            next_offset: None,
            truncated: false
        }
    );
    let (scans, _) = listed(Kind::Scans, &params(10, 0, false, 10_000), 0, Some(5));
    assert_eq!(scans.pagination.next_offset, Some(0));
    assert!(scans.pagination.truncated);
    let (scans, calls) = listed(Kind::Scans, &params(1, 0, true, 2), 3, Some(3));
    assert_eq!(
        doc(&scans),
        r#"{"total_items":3,"returned":2,"skip":0,"next_offset":2,"truncated":true}"#
    );
    assert_eq!(calls, [(0, 1), (1, 1)]);
    let (rules, _) = listed(Kind::Rules, &params(10, 0, false, 10_000), 25, Some(10));
    assert_eq!(
        doc(&rules),
        r#"{"total_items":null,"returned":10,"skip":0,"next_offset":10,"truncated":true}"#
    );
    let (rules, calls) = listed(Kind::Rules, &params(10, 0, true, 10_000), 20, None);
    assert_eq!(rules.pagination.total_items, Some(20));
    assert_eq!(calls, [(0, 10), (10, 10), (20, 10)]);
    let (rules, calls) = listed(Kind::Rules, &params(10, 5, true, 12), 100, None);
    assert_eq!(calls, [(5, 10), (15, 2)]);
    assert_eq!(rules.pagination.next_offset, Some(17));
    assert_eq!(
        rules.pagination.total_items, None,
        "an offset walk has no total"
    );
}

/// §20.4's page checks: each fails before the page's rows count (a pagination error,
/// never the size bound).
#[test]
fn page_checks() {
    let fail = |kind: Kind, paging: Paging, pages: Vec<ListPage>| {
        let pages = RefCell::new(pages.into_iter());
        let result = run(inventory(kind, &paging, |_, _| {
            let page = pages.borrow_mut().next().expect("a page");
            std::future::ready(Ok(page))
        }));
        let failure = sdk(result.err().expect("a failure"));
        assert_eq!(failure.kind(), scm::ErrorKind::Pagination);
        assert!(!is_oversized(&failure));
    };
    let page = |ids: &[&str], total: Option<u64>| ListPage {
        rows: ids.iter().map(|id| row(id)).collect(),
        total,
    };
    // More rows than asked for (with and without --all).
    fail(
        Kind::Scans,
        params(1, 0, false, 10_000),
        vec![page(&["a", "b"], Some(9))],
    );
    fail(
        Kind::Rules,
        params(1, 0, true, 10_000),
        vec![page(&["a", "b"], None)],
    );
    // The total changes.
    fail(
        Kind::Scans,
        params(1, 0, true, 10_000),
        vec![page(&["a"], Some(3)), page(&["b"], Some(4))],
    );
    // Empty and repeated ids, within a page and across pages.
    fail(
        Kind::Scans,
        params(10, 0, false, 10_000),
        vec![page(&[""], Some(1))],
    );
    fail(
        Kind::Rules,
        params(10, 0, false, 10_000),
        vec![page(&["a", "a"], None)],
    );
    fail(
        Kind::Rules,
        params(1, 0, true, 10_000),
        vec![page(&["a"], None), page(&["a"], None)],
    );
    // Rows beyond the total.
    fail(
        Kind::Scans,
        params(10, 0, false, 10_000),
        vec![page(&["a", "b"], Some(1))],
    );
    fail(
        Kind::Scans,
        params(10, 3, false, 10_000),
        vec![page(&["a"], Some(3))],
    );
    // An empty page before the total (--all).
    fail(
        Kind::Scans,
        params(2, 0, true, 10_000),
        vec![page(&["a", "b"], Some(5)), page(&[], Some(5))],
    );
    // A scans page without a usable total.
    fail(
        Kind::Scans,
        params(10, 0, false, 10_000),
        vec![page(&["a"], None)],
    );
}

/// D320, D317: only an SDK answer-size failure (failure kind `Http`, pinned by the
/// executable tests: the SDK alone builds such errors) is the size line; a local `Limit`
/// (a query over the URL bound) and the walk's own bounds are the request line, and a walk
/// keeps the SDK error's kind.
#[test]
fn walk_failures_keep_their_kind() {
    assert!(!is_oversized(&scm::Error::new(scm::ErrorKind::Limit)));
    assert!(!is_oversized(&crate::pagination::incomplete_walk()));
    let calls = std::cell::Cell::new(0);
    let failure = run(inventory(Kind::Rules, &params(1, 0, true, 0), |_, _| {
        calls.set(calls.get() + 1);
        let result = if calls.get() == 2 {
            Err(Failure::Sdk(scm::Error::new(scm::ErrorKind::Transport)))
        } else {
            Ok(ListPage {
                rows: vec![row("a")],
                total: None,
            })
        };
        std::future::ready(result)
    }))
    .err()
    .map(sdk)
    .unwrap();
    assert!(!is_oversized(&failure));
    assert_eq!(failure.kind(), scm::ErrorKind::Transport);
    assert_eq!(calls.get(), 2);
}

/// G71, D325: an answer the tolerant projection refuses stops a single page and a walk
/// (on any page) as the contract failure, never as the SDK error that stops the walk; the
/// line is the contract line, never quiet-suppressed, exit 1.
#[test]
fn a_refused_answer_is_the_contract_failure() {
    let single = run(inventory(
        Kind::Scans,
        &params(10, 0, false, 10_000),
        |_, _| std::future::ready(Err(Failure::Contract)),
    ));
    assert!(matches!(single, Err(Failure::Contract)));
    let calls = std::cell::Cell::new(0);
    let walked = run(inventory(
        Kind::Scans,
        &params(1, 0, true, 10_000),
        |_, _| {
            calls.set(calls.get() + 1);
            let result = if calls.get() == 2 {
                Err(Failure::Contract)
            } else {
                Ok(ListPage {
                    rows: vec![row("a")],
                    total: Some(3),
                })
            };
            std::future::ready(result)
        },
    ));
    assert!(matches!(walked, Err(Failure::Contract)));
    assert_eq!(calls.get(), 2, "the walk stops at the refused page");
    let (mut out, stdout, stderr) = crate::output::testing::capture(true);
    let error = read_failure(&mut out, &Failure::Contract);
    assert!(matches!(error, CliError::Reported(1)));
    assert_eq!(
        stderr.text(),
        "  ✗ The AgentGuard answer does not match the API contract; nothing was printed. No upstream body is included.\n"
    );
    assert_eq!(stdout.text(), "");
    // An SDK error keeps its own line.
    let (mut out, _, stderr) = crate::output::testing::capture(false);
    read_failure(
        &mut out,
        &Failure::Sdk(scm::Error::new(scm::ErrorKind::Decode)),
    );
    assert!(stderr.text().contains("AgentGuard request failed."));
}
