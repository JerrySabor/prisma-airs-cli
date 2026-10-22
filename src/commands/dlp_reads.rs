//! The eight DLP list and get leaves (DESIGN §16.3, §16.4).
//!
//! A list is one of three shapes (D170):
//! - a single server page (`filtering-profiles list`, and the others with
//!   `--include-predefined`): one request, the rows as the service returned them, the
//!   server's total in the status line;
//! - a server-paged `--all` walk from page 0 with `--limit` (else 50) rows per page,
//!   stopped at `--max`;
//! - the custom-only view (the default of patterns, profiles and dictionaries): every page
//!   of 100, the predefined rows dropped, then the slice `[offset, offset + limit)` (or,
//!   with `--all`, the first `--max` rows). With `dictionaries list --keywords` the pages
//!   are read without keywords and the keywords of the shown rows only are read per id
//!   (G13, as `backup`), so a tenant's keyword lists are not all downloaded.

use super::Invocation;
use super::redteam::{page_value, read, value};
use crate::clients::WALK_BUDGET;
use crate::dlp::views;
use crate::dlp::walk::{self, Walked};
use crate::dlp::{FALLBACK_PAGE_SIZE, Kind, ListParams, SLICE_PAGE_SIZE, is_predefined};
use crate::error::CliError;
use crate::json::OValue;
use crate::output::Format;
use crate::pagination::{self, WalkEnd};
use scm::dlp::{DataFilteringProfileListParams, DictionaryListParams, DlpClient, SpringListParams};

/// One list page of `kind` as ordered JSON (`page`, `size`, every `sort` value and, for
/// dictionaries, `keywords=true` when asked for).
async fn list_page(
    dlp: &DlpClient,
    kind: Kind,
    params: &ListParams,
    page: Option<u64>,
    size: Option<u32>,
    options: Option<&scm::RequestOptions>,
) -> Result<OValue, scm::Error> {
    let sort = params.sort.clone();
    match kind {
        Kind::FilteringProfile => {
            let mut query = DataFilteringProfileListParams::default();
            query.page = page;
            query.size = size;
            query.sort = sort;
            page_value(&dlp.data_filtering_profiles().list(&query, options).await?)
        }
        Kind::Pattern | Kind::Profile => {
            let mut query = SpringListParams::new().sort(sort);
            query.page = page;
            query.size = size;
            if kind == Kind::Pattern {
                page_value(&dlp.data_patterns().list(&query, options).await?)
            } else {
                page_value(&dlp.data_profiles().list(&query, options).await?)
            }
        }
        Kind::Dictionary => {
            let mut query = DictionaryListParams::default();
            query.page = page;
            query.size = size;
            query.sort = sort;
            query.keywords = params.keywords.then_some(true);
            page_value(&dlp.dictionaries().list(&query, options).await?)
        }
    }
}

/// Walk every page of `size` rows under the walk deadline, keeping at most `max`.
async fn walk_pages(
    invocation: &Invocation,
    dlp: &DlpClient,
    kind: Kind,
    params: &ListParams,
    size: u32,
    max: u64,
    deadline: &scm::RequestOptions,
) -> Result<Walked, CliError> {
    walk::walk(size, max, |page, size| async move {
        list_page(dlp, kind, params, Some(page), Some(size), Some(deadline)).await
    })
    .await
    .map_err(|error| invocation.management_error(&error, WALK_BUDGET))
}

/// `<kind> list|ls` (§16.3, §16.4).
pub async fn list(
    invocation: &mut Invocation,
    kind: Kind,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let sliced = params.client_sliced(kind);
    let deadline = if sliced || params.all {
        Some(super::walk_options()?)
    } else {
        None
    };
    let connected = invocation.connect_dlp(deadline.as_ref()).await?;
    let format = connected.format(format);
    let dlp = connected.client;
    let (mut rows, status) = match &deadline {
        Some(deadline) if sliced => {
            let walk_params = ListParams {
                keywords: false,
                ..params.clone()
            };
            let walked = walk_pages(
                invocation,
                &dlp,
                kind,
                &walk_params,
                SLICE_PAGE_SIZE,
                0,
                deadline,
            )
            .await?;
            let custom: Vec<OValue> = walked
                .rows
                .into_iter()
                .filter(|row| !is_predefined(row))
                .collect();
            let total = custom.len();
            if params.all {
                let (rows, end) = pagination::first(custom, params.max);
                let status = match end {
                    WalkEnd::Complete => views::all_status(rows.len()),
                    WalkEnd::StoppedAtMax => pagination::showing_first(rows.len(), params.max),
                };
                (rows, status)
            } else {
                let offset = params.slice_offset();
                let skip = usize::try_from(offset).unwrap_or(usize::MAX);
                let rows: Vec<OValue> = match params.limit {
                    Some(limit) => custom
                        .into_iter()
                        .skip(skip)
                        .take(usize::try_from(limit).unwrap_or(usize::MAX))
                        .collect(),
                    None => custom.into_iter().skip(skip).collect(),
                };
                let next = params
                    .limit
                    .map(|limit| offset.saturating_add(u64::from(limit)));
                let status = views::slice_status(rows.len(), total, next);
                (rows, status)
            }
        }
        Some(deadline) => {
            let size = params.limit.unwrap_or(FALLBACK_PAGE_SIZE);
            let walked =
                walk_pages(invocation, &dlp, kind, params, size, params.max, deadline).await?;
            let status = if walked.stopped_at_max {
                pagination::showing_first(walked.rows.len(), params.max)
            } else {
                views::all_status(walked.rows.len())
            };
            (walked.rows, status)
        }
        None => {
            let (page, size) = params.server_page();
            let answer = read(invocation, list_page(&dlp, kind, params, page, size, None)).await?;
            let rows = walk::rows_of(&answer);
            let status = views::server_page_status(&answer, rows.len());
            (rows, status)
        }
    };
    if sliced && kind == Kind::Dictionary && params.keywords {
        for row in &mut rows {
            with_keywords(invocation, &dlp, row).await?;
        }
    }
    for row in &mut rows {
        views::withhold(row, &invocation.secrets);
    }
    views::render_list(&mut invocation.output, kind, format, &rows)?;
    invocation.output.status(&status);
    Ok(())
}

/// A shown dictionary row replaced by its keyword-bearing record
/// (`GET …/<id>?keywords=true`, G13); a row without an id is kept as listed.
async fn with_keywords(
    invocation: &Invocation,
    dlp: &DlpClient,
    row: &mut OValue,
) -> Result<(), CliError> {
    let Some(id) = row.get("id").and_then(OValue::as_str).map(str::to_owned) else {
        return Ok(());
    };
    let record = value(&read(invocation, dlp.dictionaries().get(&id, Some(true), None)).await?)?;
    if record.get("id").and_then(OValue::as_str) != Some(id.as_str()) {
        let name = row.get("name").and_then(OValue::as_str).unwrap_or_default();
        return Err(CliError::operational(format!(
            "Dictionary {} changed while it was listed; retry the operation",
            crate::output::terminal_safe(name)
        )));
    }
    *row = record;
    Ok(())
}

/// `<kind> get <id>` (§16.4); `keywords`: `dictionaries get --keywords`.
pub async fn get(
    invocation: &mut Invocation,
    kind: Kind,
    id: &str,
    keywords: bool,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_dlp(None).await?;
    let format = connected.format(format);
    let dlp = connected.client;
    let mut record = match kind {
        Kind::FilteringProfile => {
            value(&read(invocation, dlp.data_filtering_profiles().get(id, None)).await?)?
        }
        Kind::Pattern => value(&read(invocation, dlp.data_patterns().get(id, None)).await?)?,
        Kind::Profile => value(&read(invocation, dlp.data_profiles().get(id, None)).await?)?,
        Kind::Dictionary => value(
            &read(
                invocation,
                dlp.dictionaries().get(id, keywords.then_some(true), None),
            )
            .await?,
        )?,
    };
    views::withhold(&mut record, &invocation.secrets);
    views::render_get(&mut invocation.output, kind, format, &record)
}
