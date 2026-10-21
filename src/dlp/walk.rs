//! The DLP page loop (DESIGN §16.3 "Lists and walks", D170, G12): a CLI loop over the
//! single-page SDK `list()` calls, never the SDK's own Spring walks (which read only the
//! camelCase totals, stop early when a service caps its page size and never check for
//! repeated rows).
//!
//! CRUD mode: pages `0, 1, …` of the requested size. The page size of the end rule is the
//! page's own reported size (`size`, `pageable.pageSize` or `pageable.page_size`), else
//! the requested one. The walk ends at `last: true`, else when `page + 1 >= totalPages`
//! (`totalPages` or `total_pages`), else at a page shorter than its size. An empty page
//! that is not the last, and a row whose non-empty `id` an earlier row already had, are
//! the D37 pagination error; the §7.2 bounds (100,000 pages, 512 MiB, the item cap
//! behind `--max 0`) are the D40 error. The walk is complete, stopped by the user's
//! `--max`, or an error.

use crate::json::OValue;
use std::collections::HashSet;
use std::future::Future;

/// The page bound of a walk.
pub const MAX_PAGES: u64 = 100_000;
/// The byte bound of a walk (rows as serialised).
pub const MAX_BYTES: usize = 512 * 1024 * 1024;
/// The item ceiling (`--max 0`).
pub const MAX_ITEMS: u64 = 1_000_000;

/// The page metadata a DLP page reports, in either spelling (camelCase in the typed
/// fields, snake_case in the extensions).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub last: Option<bool>,
    pub total_pages: Option<u64>,
    pub total_elements: Option<u64>,
    /// `size`, else `pageable.pageSize`, else `pageable.page_size`.
    pub size: Option<u64>,
}

/// A count: a non-negative safe integer, else `None` (treated as absent).
fn count(value: Option<&OValue>) -> Option<u64> {
    match value {
        Some(OValue::Number(number)) => crate::walk::total_of(number.as_f64()),
        _ => None,
    }
}

fn first_count(value: &OValue, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| count(value.get(key)))
}

/// The rows of a page (`content`; the SDK schema requires the array).
pub fn rows_of(page: &OValue) -> Vec<OValue> {
    page.get("content")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .to_vec()
}

/// The metadata of a page.
pub fn meta_of(page: &OValue) -> Meta {
    let pageable = page.get("pageable");
    let pageable_size =
        pageable.and_then(|pageable| first_count(pageable, &["pageSize", "page_size"]));
    Meta {
        last: match page.get("last") {
            Some(OValue::Bool(last)) => Some(*last),
            _ => None,
        },
        total_pages: first_count(page, &["totalPages", "total_pages"]),
        total_elements: first_count(page, &["totalElements", "total_elements"]),
        size: count(page.get("size"))
            .or(pageable_size)
            .filter(|size| *size >= 1),
    }
}

/// The numbers of the page status line (TS `pageMeta`, `rdlp.ts:48-56`): the page number
/// (`pageable.pageNumber`, `pageable.page_number`, else 0), the page size
/// (`pageable.pageSize`, `pageable.page_size`, else the rows returned) and the total
/// (`totalElements`, `total_elements`), when reported.
pub fn status_numbers(page: &OValue, returned: usize) -> (u64, u64, Option<u64>) {
    let pageable = page.get("pageable");
    let number = pageable
        .and_then(|pageable| first_count(pageable, &["pageNumber", "page_number"]))
        .unwrap_or(0);
    let size = pageable
        .and_then(|pageable| first_count(pageable, &["pageSize", "page_size"]))
        .unwrap_or(returned as u64);
    let total = first_count(page, &["totalElements", "total_elements"]);
    (number, size, total)
}

/// A finished walk.
#[derive(Debug)]
pub struct Walked {
    pub rows: Vec<OValue>,
    /// The walk stopped at the user's `--max` while more rows existed.
    pub stopped_at_max: bool,
}

fn pagination_error() -> scm::Error {
    scm::Error::new(scm::ErrorKind::Pagination)
}

/// The non-empty string `id` of a row.
fn id_of(row: &OValue) -> Option<&str> {
    row.get("id")
        .and_then(OValue::as_str)
        .filter(|id| !id.is_empty())
}

/// Walk every page of `size` rows from page 0, keeping at most `max` rows (`0`: the
/// 1,000,000 ceiling, a safety bound). `fetch(page, size)` sends one page request and
/// returns the page as ordered JSON.
pub async fn walk<F, Fut>(size: u32, max: u64, fetch: F) -> Result<Walked, scm::Error>
where
    F: FnMut(u64, u32) -> Fut,
    Fut: Future<Output = Result<OValue, scm::Error>>,
{
    walk_bounded(size, max, MAX_BYTES, fetch).await
}

/// [`walk`] with the byte bound as a parameter.
async fn walk_bounded<F, Fut>(
    size: u32,
    max: u64,
    max_bytes: usize,
    mut fetch: F,
) -> Result<Walked, scm::Error>
where
    F: FnMut(u64, u32) -> Fut,
    Fut: Future<Output = Result<OValue, scm::Error>>,
{
    let user_cap = max != 0 && max <= MAX_ITEMS;
    let cap = usize::try_from(if user_cap { max } else { MAX_ITEMS }).unwrap_or(usize::MAX);
    let mut rows: Vec<OValue> = Vec::new();
    let mut bytes = 0usize;
    let mut seen: HashSet<String> = HashSet::new();
    for page in 0..MAX_PAGES {
        let answer = fetch(page, size).await?;
        let content = rows_of(&answer);
        let meta = meta_of(&answer);
        let page_size = meta.size.unwrap_or(u64::from(size));
        let last = match (meta.last, meta.total_pages) {
            (Some(last), _) => last,
            (None, Some(total)) => page + 1 >= total,
            (None, None) => (content.len() as u64) < page_size,
        };
        if content.is_empty() && !last {
            return Err(pagination_error());
        }
        for row in content {
            if let Some(id) = id_of(&row)
                && !seen.insert(id.to_owned())
            {
                // A repeated row: the service ignored `page` (D37).
                return Err(pagination_error());
            }
            if rows.len() == cap {
                return stop_at_cap(rows, user_cap);
            }
            bytes =
                bytes.saturating_add(crate::json::to_compact(&row).map_or(0, |text| text.len()));
            if bytes > max_bytes {
                return Err(crate::pagination::incomplete_walk());
            }
            rows.push(row);
        }
        if last {
            return Ok(Walked {
                rows,
                stopped_at_max: false,
            });
        }
        if rows.len() == cap {
            return stop_at_cap(rows, user_cap);
        }
    }
    Err(crate::pagination::incomplete_walk())
}

fn stop_at_cap(rows: Vec<OValue>, user_cap: bool) -> Result<Walked, scm::Error> {
    if user_cap {
        Ok(Walked {
            rows,
            stopped_at_max: true,
        })
    } else {
        Err(crate::pagination::incomplete_walk())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn run<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn page(text: &str) -> OValue {
        crate::json::parse(text).unwrap()
    }

    /// A Spring service of `count` rows `r0…`, capped at `cap` rows per page; `style`
    /// shapes the metadata.
    fn service<'a>(
        count: u64,
        cap: u64,
        style: &'a str,
        calls: &'a RefCell<Vec<(u64, u32)>>,
    ) -> impl FnMut(u64, u32) -> std::future::Ready<Result<OValue, scm::Error>> + 'a {
        move |number, size| {
            calls.borrow_mut().push((number, size));
            let size_used = u64::from(size).min(cap);
            let start = number * size_used;
            let rows: Vec<String> = (start..count.min(start + size_used))
                .map(|n| format!(r#"{{"id":"r{n}"}}"#))
                .collect();
            let total_pages = count.div_ceil(size_used);
            let last = number + 1 >= total_pages;
            let content = rows.join(",");
            let text = match style {
                "camel" => format!(
                    r#"{{"content":[{content}],"last":{last},"totalPages":{total_pages},"totalElements":{count},"size":{size_used}}}"#
                ),
                "snake" => format!(
                    r#"{{"content":[{content}],"total_pages":{total_pages},"total_elements":{count},"pageable":{{"page_number":{number},"page_size":{size_used}}}}}"#
                ),
                _ => format!(r#"{{"content":[{content}]}}"#),
            };
            std::future::ready(Ok(page(&text)))
        }
    }

    fn ids(walked: &Walked) -> Vec<String> {
        walked
            .rows
            .iter()
            .map(|row| row.get("id").and_then(OValue::as_str).unwrap().to_owned())
            .collect()
    }

    #[test]
    fn walks_by_last_by_total_pages_and_by_a_short_page() {
        for style in ["camel", "snake", "bare"] {
            let calls = RefCell::new(Vec::new());
            let walked = run(walk(2, 0, service(5, 100, style, &calls))).unwrap();
            assert_eq!(ids(&walked), ["r0", "r1", "r2", "r3", "r4"], "{style}");
            assert!(!walked.stopped_at_max);
            assert_eq!(*calls.borrow(), [(0, 2), (1, 2), (2, 2)], "{style}");
        }
        // A bare service with a full last page needs one more (empty, last) page.
        let calls = RefCell::new(Vec::new());
        let walked = run(walk(2, 0, service(4, 100, "bare", &calls))).unwrap();
        assert_eq!(walked.rows.len(), 4);
        assert_eq!(calls.borrow().len(), 3);
    }

    /// A service that caps its pages (dictionaries: 100 → 50) reports the smaller size;
    /// the walk continues instead of ending at the first "short" page (G12).
    #[test]
    fn a_capped_page_size_continues_the_walk() {
        for style in ["camel", "snake"] {
            let calls = RefCell::new(Vec::new());
            let walked = run(walk(100, 0, service(120, 50, style, &calls))).unwrap();
            assert_eq!(walked.rows.len(), 120, "{style}");
            assert_eq!(*calls.borrow(), [(0, 100), (1, 100), (2, 100)], "{style}");
        }
    }

    #[test]
    fn an_empty_page_that_is_not_the_last_is_a_pagination_error() {
        let pages = RefCell::new(vec![
            page(r#"{"content":[{"id":"a"}],"last":false,"size":1}"#),
            page(r#"{"content":[],"last":false,"size":1}"#),
        ]);
        let error = run(walk(1, 0, |_, _| {
            std::future::ready(Ok(pages.borrow_mut().remove(0)))
        }))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Pagination);
        // totalPages says more pages exist.
        let error = run(walk(1, 0, |number, _| {
            let text = if number == 0 {
                r#"{"content":[{"id":"a"}],"totalPages":3,"size":1}"#
            } else {
                r#"{"content":[],"totalPages":3,"size":1}"#
            };
            std::future::ready(Ok(page(text)))
        }))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Pagination);
        // An empty last page is the end.
        let walked = run(walk(5, 0, |_, _| {
            std::future::ready(Ok(page(r#"{"content":[],"last":true}"#)))
        }))
        .unwrap();
        assert!(walked.rows.is_empty());
    }

    #[test]
    fn a_repeated_id_is_a_pagination_error() {
        let calls = RefCell::new(0);
        let error = run(walk(2, 0, |_, _| {
            *calls.borrow_mut() += 1;
            std::future::ready(Ok(page(
                r#"{"content":[{"id":"a"},{"id":"b"}],"totalPages":3,"size":2}"#,
            )))
        }))
        .unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Pagination);
        assert_eq!(*calls.borrow(), 2, "stops at the repeat");
        // Rows without an id (or an empty one) are not checked.
        let walked = run(walk(2, 0, |number, _| {
            let text = if number == 0 {
                r#"{"content":[{"name":"x"},{"id":""}],"totalPages":2,"size":2}"#
            } else {
                r#"{"content":[{"name":"x"}],"totalPages":2,"size":2}"#
            };
            std::future::ready(Ok(page(text)))
        }))
        .unwrap();
        assert_eq!(walked.rows.len(), 3);
    }

    #[test]
    fn max_stops_with_a_flag_and_the_safety_bounds_fail() {
        let calls = RefCell::new(Vec::new());
        let walked = run(walk(2, 3, service(9, 100, "camel", &calls))).unwrap();
        assert_eq!(ids(&walked), ["r0", "r1", "r2"]);
        assert!(walked.stopped_at_max);
        let calls = RefCell::new(Vec::new());
        let walked = run(walk(2, 4, service(4, 100, "camel", &calls))).unwrap();
        assert_eq!(walked.rows.len(), 4);
        assert!(!walked.stopped_at_max, "exactly the cap and nothing more");
        let calls = RefCell::new(Vec::new());
        let error = run(walk_bounded(2, 0, 20, service(4, 100, "camel", &calls))).unwrap_err();
        assert_eq!(error.kind(), scm::ErrorKind::Limit);
    }

    #[test]
    fn metadata_in_both_spellings() {
        let camel = page(
            r#"{"content":[],"last":true,"totalPages":2,"totalElements":30,"size":20,"pageable":{"pageNumber":1,"pageSize":20}}"#,
        );
        assert_eq!(
            meta_of(&camel),
            Meta {
                last: Some(true),
                total_pages: Some(2),
                total_elements: Some(30),
                size: Some(20)
            }
        );
        assert_eq!(status_numbers(&camel, 0), (1, 20, Some(30)));
        let snake = page(
            r#"{"content":[{"id":"a"}],"total_pages":2,"total_elements":3,"pageable":{"page_number":0,"page_size":2}}"#,
        );
        assert_eq!(
            meta_of(&snake),
            Meta {
                last: None,
                total_pages: Some(2),
                total_elements: Some(3),
                size: Some(2)
            }
        );
        assert_eq!(status_numbers(&snake, 1), (0, 2, Some(3)));
        let bare = page(r#"{"content":[{"id":"a"}],"size":0,"totalElements":-1}"#);
        assert_eq!(meta_of(&bare), Meta::default());
        assert_eq!(status_numbers(&bare, 1), (0, 1, None));
    }
}
