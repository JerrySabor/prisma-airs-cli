//! The shared skip/limit page loop (DESIGN §15.3 "Lists and walks", §17.3, §18.9, D147, D183,
//! D211): a CLI loop over the single-page SDK list calls of red team, model security and the
//! M6d dashboard lists. `skip` starts at 0 and advances by the rows of each page.
//! A page that carries `total_items` continues the walk while `next < total_items` (a
//! service may cap the page below the requested `limit`); a page without it continues
//! only when it was full. The item cap ends the walk too. An empty page while
//! `total_items` says more rows exist is the D37 pagination error (the SDK's own walk
//! ends silently there), and the §7.2 bounds (100,000 pages, 512 MiB, the item cap behind
//! `--max 0`) are the D40 error. A row whose key (a red team list row's `uuid`) was
//! already seen is the D37 error too: a service that ignores `skip` and repeats a page
//! would otherwise yield a listing with duplicates and missing rows. The walk is complete
//! or an error. A page marked `count_capped` (model-security scans, D182) latches: from
//! then on `total_items` is a cap, not a count, so it is ignored for the rest of the walk,
//! which then ends at a short page (the SDK's own rule, `ms:scans.rs:160-168`).
//!
//! [`walk_with`] (DESIGN §18.13) adds a start offset, a page bound that may end the walk as
//! partial instead of failing, and a check run on every page before its rows are taken:
//! `sessions list --all` keeps TypeScript's stricter page checks through it (choice 14);
//! [`walk`] is `walk_with` with the defaults. [`Spec::shrink_last_page`] (DESIGN §20.4)
//! asks each page for at most the rows the item cap still allows, as TypeScript's
//! supplychain `inventory` loop does, and compares a page with the size it asked for.

use std::collections::HashSet;
use std::future::Future;

/// The page bound of a walk.
pub const MAX_PAGES: usize = 100_000;
/// The byte bound of a walk (rows as serialised).
pub const MAX_BYTES: usize = 512 * 1024 * 1024;
/// The item ceiling (`--max 0`).
pub const MAX_ITEMS: u64 = 1_000_000;

/// One page as the SDK returned it: the rows and `pagination.total_items`.
pub struct Page<T> {
    pub rows: Vec<T>,
    /// `total_items` when the service sent a usable count.
    pub total: Option<u64>,
    /// The page said `count_capped: true` (its total is a cap, D182).
    pub capped: bool,
}

impl<T> Page<T> {
    /// A page whose total is a count.
    pub fn new(rows: Vec<T>, total: Option<u64>) -> Self {
        Self {
            rows,
            total,
            capped: false,
        }
    }
}

/// The validated list flags of a skip/limit list (§15.3, §17.3 "Numbers" and "Lists and
/// walks").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListParams {
    /// `--limit` when given.
    pub limit: Option<u32>,
    /// `--offset` when given.
    pub offset: Option<u64>,
    pub all: bool,
    /// `--max` (default 10,000; `0`: no item cap).
    pub max: u64,
}

impl ListParams {
    /// A list without flags.
    #[cfg(test)]
    pub fn none() -> Self {
        Self {
            limit: None,
            offset: None,
            all: false,
            max: crate::pagination::DEFAULT_MAX,
        }
    }
}

/// A finished walk.
#[derive(Debug)]
pub struct Walked<T> {
    pub rows: Vec<T>,
    /// The walk stopped at the user's `--max` while more rows existed.
    pub stopped_at_max: bool,
    /// The walk used its page cap without reaching the end ([`Spec::page_cap_partial`]).
    pub stopped_at_pages: bool,
}

/// How [`walk_with`] walks (DESIGN §18.13): where it starts, how many pages it may read,
/// and whether running out of pages ends it as partial instead of failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    /// The first `skip`.
    pub start: u64,
    /// The page bound.
    pub max_pages: usize,
    /// At the page bound: a partial walk ([`Walked::stopped_at_pages`]) rather than the
    /// D40 error.
    pub page_cap_partial: bool,
    /// Ask each page for `min(limit, cap − rows collected)` rows instead of `limit`, and
    /// read a page without a total as full when it holds the rows it asked for (DESIGN
    /// §20.4; the supplychain walks). Off: every page asks for `limit`.
    pub shrink_last_page: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            start: 0,
            max_pages: MAX_PAGES,
            page_cap_partial: false,
            shrink_last_page: false,
        }
    }
}

/// `total_items` of a red team page as a count: a non-negative safe integer, else
/// `None` (treated as absent).
pub fn total_of(total: Option<f64>) -> Option<u64> {
    let total = total?;
    let in_range =
        (0.0..=crate::pagination::MAX_SAFE_INTEGER_F64).contains(&total) && total.fract() == 0.0;
    // Checked: integral and within the safe range, so the cast is exact (and a cast of
    // an out-of-range value saturates; it is discarded).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    in_range.then_some(total as u64)
}

/// The pagination failure (D37 text through the §6 mapping).
fn pagination_error() -> scm::Error {
    scm::Error::new(scm::ErrorKind::Pagination)
}

/// Walk every page of `limit` rows from `skip=0`, keeping at most `max` rows (`0`: the
/// 1,000,000 ceiling, which is a safety bound, not a cap the user chose). `fetch(skip,
/// limit)` sends one page request; `size` gives a row's serialised size for the byte
/// bound; `key` a row's identity (`None`: not checked), and a key seen twice fails the
/// walk.
pub async fn walk<T, F, Fut>(
    limit: u32,
    max: u64,
    fetch: F,
    size: impl Fn(&T) -> usize,
    key: impl Fn(&T) -> Option<String>,
) -> Result<Walked<T>, scm::Error>
where
    F: FnMut(u64, u32) -> Fut,
    Fut: Future<Output = Result<Page<T>, scm::Error>>,
{
    walk_with(Spec::default(), limit, max, fetch, size, key, |_, _, _| {
        Ok(())
    })
    .await
}

/// [`walk`] from `spec.start`, at most `spec.max_pages` pages, with `check(skip, asked,
/// page)` run on every page before its rows are taken (an error ends the walk); `asked` is
/// the page size the request asked for (below `limit` under [`Spec::shrink_last_page`]).
pub async fn walk_with<T, F, Fut>(
    spec: Spec,
    limit: u32,
    max: u64,
    mut fetch: F,
    size: impl Fn(&T) -> usize,
    key: impl Fn(&T) -> Option<String>,
    mut check: impl FnMut(u64, u32, &Page<T>) -> Result<(), scm::Error>,
) -> Result<Walked<T>, scm::Error>
where
    F: FnMut(u64, u32) -> Fut,
    Fut: Future<Output = Result<Page<T>, scm::Error>>,
{
    let user_cap = max != 0 && max <= MAX_ITEMS;
    let cap = if user_cap { max } else { MAX_ITEMS };
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let page_size = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut rows: Vec<T> = Vec::new();
    let mut bytes = 0usize;
    let mut seen: HashSet<String> = HashSet::new();
    let mut skip: u64 = spec.start;
    let mut capped = false;
    let done = |rows: Vec<T>| Walked {
        rows,
        stopped_at_max: false,
        stopped_at_pages: false,
    };
    for _ in 0..spec.max_pages {
        let (asked, asked_size) = if spec.shrink_last_page {
            // `rows.len() < cap` here: a walk at its cap has already returned.
            let remaining = cap.saturating_sub(rows.len());
            let size = page_size.min(remaining);
            (u32::try_from(size).unwrap_or(limit), size)
        } else {
            (limit, page_size)
        };
        let mut page = fetch(skip, asked).await?;
        check(skip, asked, &page)?;
        // D182: once a page says its count is capped, no later total is a count.
        capped |= page.capped;
        if capped {
            page.total = None;
        }
        let received = page.rows.len();
        if received == 0 {
            if page.total.is_some_and(|total| skip < total) {
                return Err(pagination_error());
            }
            return Ok(done(rows));
        }
        let next = skip
            .checked_add(u64::try_from(received).map_err(|_| pagination_error())?)
            .ok_or_else(pagination_error)?;
        let more = match page.total {
            Some(total) => next < total,
            None => received >= asked_size,
        };
        for row in page.rows {
            if let Some(key) = key(&row)
                && !seen.insert(key)
            {
                // A repeated row: the service ignored `skip` (D37).
                return Err(pagination_error());
            }
            if rows.len() == cap {
                // More rows than the cap: the user's --max, or a safety bound.
                return stop_at_cap(rows, user_cap);
            }
            bytes = bytes.saturating_add(size(&row));
            if bytes > MAX_BYTES {
                return Err(crate::pagination::incomplete_walk());
            }
            rows.push(row);
        }
        if !more {
            return Ok(done(rows));
        }
        if rows.len() == cap {
            return stop_at_cap(rows, user_cap);
        }
        skip = next;
    }
    if spec.page_cap_partial {
        return Ok(Walked {
            rows,
            stopped_at_max: false,
            stopped_at_pages: true,
        });
    }
    Err(crate::pagination::incomplete_walk())
}

fn stop_at_cap<T>(rows: Vec<T>, user_cap: bool) -> Result<Walked<T>, scm::Error> {
    if user_cap {
        Ok(Walked {
            rows,
            stopped_at_max: true,
            stopped_at_pages: false,
        })
    } else {
        Err(crate::pagination::incomplete_walk())
    }
}

/// The client-side slice of a complete list (§15.3): without `--all` the rows
/// `[offset, offset + limit)` (no `--limit`: to the end); with `--all` the first `--max`
/// rows (`0`: all) and whether `--max` cut the list.
pub fn slice<T>(rows: Vec<T>, params: &ListParams) -> (Vec<T>, bool) {
    if params.all {
        let (rows, end) = crate::pagination::first(rows, params.max);
        return (rows, end == crate::pagination::WalkEnd::StoppedAtMax);
    }
    let skip = usize::try_from(params.offset.unwrap_or(0)).unwrap_or(usize::MAX);
    let rows = rows.into_iter().skip(skip);
    let rows = match params.limit {
        Some(limit) => rows
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .collect(),
        None => rows.collect(),
    };
    (rows, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A service of `count` rows reporting `total` on every page; records the skips.
    fn service(
        count: u64,
        total: Option<u64>,
        skips: &RefCell<Vec<(u64, u32)>>,
    ) -> impl FnMut(u64, u32) -> std::future::Ready<Result<Page<u64>, scm::Error>> + '_ {
        move |skip, limit| {
            skips.borrow_mut().push((skip, limit));
            let rows = (skip..count.min(skip + u64::from(limit))).collect();
            std::future::ready(Ok(Page::new(rows, total)))
        }
    }

    fn run<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn walks_until_the_total_a_short_page_or_an_empty_page() {
        let skips = RefCell::new(Vec::new());
        let walked = run(walk(
            2,
            10_000,
            service(5, Some(5), &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap();
        assert_eq!(walked.rows, [0, 1, 2, 3, 4]);
        assert!(!walked.stopped_at_max);
        assert_eq!(*skips.borrow(), [(0, 2), (2, 2), (4, 2)]);
        // No total: a short page ends the walk.
        let skips = RefCell::new(Vec::new());
        let walked = run(walk(
            2,
            10_000,
            service(3, None, &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap();
        assert_eq!(walked.rows, [0, 1, 2]);
        assert_eq!(skips.borrow().len(), 2);
        // No total and a full last page: one more (empty) page ends it.
        let skips = RefCell::new(Vec::new());
        let walked = run(walk(
            2,
            10_000,
            service(4, None, &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap();
        assert_eq!(walked.rows.len(), 4);
        assert_eq!(skips.borrow().len(), 3);
    }

    #[test]
    fn a_short_page_before_the_total_continues_the_walk() {
        // The service caps its pages at 3 rows; the total keeps the walk going.
        let skips = RefCell::new(Vec::new());
        let capped = |skip: u64, limit: u32| {
            skips.borrow_mut().push((skip, limit));
            let rows = (skip..7.min(skip + 3)).collect();
            std::future::ready(Ok(Page::new(rows, Some(7))))
        };
        let walked = run(walk(5, 10_000, capped, |_| 8, |row| Some(row.to_string()))).unwrap();
        assert_eq!(walked.rows, [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(*skips.borrow(), [(0, 5), (3, 5), (6, 5)]);
    }

    #[test]
    fn an_empty_page_before_the_total_is_an_error() {
        let skips = RefCell::new(Vec::new());
        let error = run(walk(
            2,
            10_000,
            service(3, Some(9), &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Pagination);
        let skips = RefCell::new(Vec::new());
        let error = run(walk(
            2,
            10_000,
            service(0, Some(1), &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Pagination);
        let skips = RefCell::new(Vec::new());
        let walked = run(walk(
            2,
            10_000,
            service(0, Some(0), &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap();
        assert!(walked.rows.is_empty());
    }

    #[test]
    fn a_repeated_row_is_a_pagination_error() {
        // The service ignores `skip`: every page is the first one, and the total says 4.
        let skips = RefCell::new(Vec::new());
        let repeating = |skip: u64, limit: u32| {
            skips.borrow_mut().push((skip, limit));
            std::future::ready(Ok(Page::new(vec![1u64, 2], Some(4))))
        };
        let error = run(walk(
            2,
            10_000,
            repeating,
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Pagination);
        assert_eq!(*skips.borrow(), [(0, 2), (2, 2)], "stops at the repeat");
        // Rows without a key are not checked.
        let skips = RefCell::new(Vec::new());
        let walked = run(walk(
            2,
            10_000,
            service(4, Some(4), &skips),
            |_| 8,
            |_| None,
        ))
        .unwrap();
        assert_eq!(walked.rows, [0, 1, 2, 3]);
    }

    #[test]
    fn max_stops_with_a_flag_and_safety_bounds_fail() {
        let skips = RefCell::new(Vec::new());
        let walked = run(walk(
            2,
            3,
            service(9, Some(9), &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap();
        assert_eq!(walked.rows, [0, 1, 2]);
        assert!(walked.stopped_at_max);
        // Exactly the cap and nothing more: complete.
        let skips = RefCell::new(Vec::new());
        let walked = run(walk(
            2,
            4,
            service(4, Some(4), &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap();
        assert_eq!(walked.rows.len(), 4);
        assert!(!walked.stopped_at_max);
        // The byte bound.
        let skips = RefCell::new(Vec::new());
        let error = run(walk(
            2,
            0,
            service(4, Some(4), &skips),
            |_| MAX_BYTES,
            |row| Some(row.to_string()),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Limit);
    }

    /// D182: a page that says `count_capped` makes every later total a cap: the walk goes
    /// on past it and ends at a short page.
    #[test]
    fn a_capped_count_is_ignored_for_the_rest_of_the_walk() {
        let skips = RefCell::new(Vec::new());
        // Seven rows, the service reports a capped total of 2 on the first page only and
        // the cap again (not flagged) later: neither ends the walk.
        let capped = |skip: u64, limit: u32| {
            skips.borrow_mut().push((skip, limit));
            let rows: Vec<u64> = (skip..7.min(skip + u64::from(limit))).collect();
            let mut page = Page::new(rows, Some(2));
            page.capped = skip == 0;
            std::future::ready(Ok(page))
        };
        let walked = run(walk(2, 10_000, capped, |_| 8, |row| Some(row.to_string()))).unwrap();
        assert_eq!(walked.rows, [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(*skips.borrow(), [(0, 2), (2, 2), (4, 2), (6, 2)]);
        // Without the flag the same total ends the walk after the first page.
        let skips = RefCell::new(Vec::new());
        let walked = run(walk(
            2,
            10_000,
            service(7, Some(2), &skips),
            |_| 8,
            |row| Some(row.to_string()),
        ))
        .unwrap();
        assert_eq!(walked.rows, [0, 1]);
        // A capped walk still fails at an empty page only when it is not the end: an
        // empty page after full pages ends it (no count to contradict).
        let skips = RefCell::new(Vec::new());
        let even = |skip: u64, limit: u32| {
            skips.borrow_mut().push((skip, limit));
            let rows: Vec<u64> = (skip..4.min(skip + u64::from(limit))).collect();
            let mut page = Page::new(rows, Some(100));
            page.capped = true;
            std::future::ready(Ok(page))
        };
        let walked = run(walk(2, 10_000, even, |_| 8, |row| Some(row.to_string()))).unwrap();
        assert_eq!(walked.rows, [0, 1, 2, 3]);
        assert_eq!(skips.borrow().len(), 3);
    }

    /// `walk_with` (§18.13): a start offset, a per-page check that runs before the rows are
    /// taken, and a page cap that ends the walk as partial.
    #[test]
    fn walk_with_starts_checks_and_caps_pages() {
        let skips = RefCell::new(Vec::new());
        let spec = Spec {
            start: 1,
            max_pages: 2,
            page_cap_partial: true,
            shrink_last_page: false,
        };
        let walked = run(walk_with(
            spec,
            2,
            0,
            service(9, Some(9), &skips),
            |_| 8,
            |row| Some(row.to_string()),
            |_, _, _| Ok(()),
        ))
        .unwrap();
        assert_eq!(walked.rows, [1, 2, 3, 4]);
        assert!(walked.stopped_at_pages && !walked.stopped_at_max);
        assert_eq!(*skips.borrow(), [(1, 2), (3, 2)]);
        // Without `page_cap_partial` the page bound is the D40 error.
        let skips = RefCell::new(Vec::new());
        let error = run(walk_with(
            Spec {
                page_cap_partial: false,
                ..spec
            },
            2,
            0,
            service(9, Some(9), &skips),
            |_| 8,
            |_| None,
            |_, _, _| Ok(()),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Limit);
        // A failing check ends the walk before the page's rows count.
        let skips = RefCell::new(Vec::new());
        let error = run(walk_with(
            Spec::default(),
            2,
            0,
            service(9, Some(9), &skips),
            |_| 8,
            |_| None,
            |skip, _, _| {
                if skip == 2 {
                    Err(scm::Error::new(scm::ErrorKind::Pagination))
                } else {
                    Ok(())
                }
            },
        ))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Pagination);
        assert_eq!(skips.borrow().len(), 2);
    }

    /// `Spec::shrink_last_page` (DESIGN §20.4, choice 11): each page asks for at most the
    /// rows the item cap still allows (TS `rules ls --all --offset 5 --max 12` sends
    /// `skip=5&limit=10`, then `skip=15&limit=2`), and a page without a total is full when
    /// it holds the rows it asked for; the per-page check is given that size.
    #[test]
    fn shrink_last_page_asks_for_the_rows_the_cap_allows() {
        let shrink = Spec {
            shrink_last_page: true,
            ..Spec::default()
        };
        let walk_of = |spec: Spec, limit: u32, max: u64, count: u64, total: Option<u64>| {
            let skips = RefCell::new(Vec::new());
            let mut checked = Vec::new();
            let walked = run(walk_with(
                spec,
                limit,
                max,
                service(count, total, &skips),
                |_| 8,
                |row| Some(row.to_string()),
                |skip, asked, _| {
                    checked.push((skip, asked));
                    Ok(())
                },
            ))
            .unwrap();
            // The per-page check sees the size each request asked for (choice 62).
            assert_eq!(checked, *skips.borrow());
            (walked, skips.into_inner())
        };
        let (walked, skips) = walk_of(Spec { start: 5, ..shrink }, 10, 12, 100, None);
        assert_eq!(walked.rows.len(), 12);
        assert!(walked.stopped_at_max);
        assert_eq!(skips, [(5, 10), (15, 2)]);
        // A catalog ending exactly at the shrunk page reads as truncated (TS: `2 < 2` is
        // false), and one a row short of it as complete.
        let (walked, skips) = walk_of(shrink, 10, 12, 12, None);
        assert!(walked.stopped_at_max);
        assert_eq!(skips, [(0, 10), (10, 2)]);
        let (walked, _) = walk_of(shrink, 10, 12, 11, None);
        assert_eq!(walked.rows.len(), 11);
        assert!(!walked.stopped_at_max);
        // With a total: `--all --max 2 --limit 1` over 3 rows.
        let (walked, skips) = walk_of(shrink, 1, 2, 3, Some(3));
        assert_eq!(walked.rows, [0, 1]);
        assert!(walked.stopped_at_max);
        assert_eq!(skips, [(0, 1), (1, 1)]);
        // Off (every other walk): each page asks for the limit.
        let (walked, skips) = walk_of(Spec::default(), 10, 12, 100, None);
        assert_eq!(walked.rows.len(), 12);
        assert_eq!(skips, [(0, 10), (10, 10)]);
    }

    /// D317: `--max 0` is no user cap; the 1,000,000-item ceiling is a safety bound, so a
    /// walk that reaches it with more rows to read fails instead of printing a cut list.
    #[test]
    fn the_item_ceiling_fails_a_shrunk_walk() {
        let skips = RefCell::new(Vec::new());
        let error = run(walk_with(
            Spec {
                shrink_last_page: true,
                ..Spec::default()
            },
            u32::MAX,
            0,
            service(MAX_ITEMS + 1, None, &skips),
            |_| 1,
            |_| None,
            |_, _, _| Ok(()),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Limit);
        assert_eq!(
            *skips.borrow(),
            [(0, 1_000_000)],
            "the page asks for the ceiling"
        );
    }

    #[test]
    fn totals_and_slices() {
        assert_eq!(total_of(Some(3.0)), Some(3));
        assert_eq!(total_of(Some(-1.0)), None);
        assert_eq!(total_of(Some(1.5)), None);
        assert_eq!(total_of(None), None);
        let params = |limit, offset, all, max| ListParams {
            limit,
            offset,
            all,
            max,
        };
        let rows: Vec<u32> = (0..5).collect();
        assert_eq!(
            slice(rows.clone(), &params(Some(2), Some(1), false, 0)).0,
            [1, 2]
        );
        assert_eq!(
            slice(rows.clone(), &params(None, Some(3), false, 0)).0,
            [3, 4]
        );
        assert_eq!(
            slice(rows.clone(), &params(None, None, true, 2)),
            (vec![0, 1], true)
        );
        assert_eq!(
            slice(rows.clone(), &params(None, None, true, 0)),
            (rows.clone(), false)
        );
        assert_eq!(
            slice(rows.clone(), &params(None, None, true, 5)),
            (rows, false)
        );
    }
}
