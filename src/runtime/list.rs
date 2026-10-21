//! The offset-cursor list machinery of the runtime inventories (DESIGN §18.4, §18.7,
//! §18.10): the D12 page end, SDK models as ordered rows, the repeated-row check of a
//! complete walk (G28, D219), the D205 sanitising of a whole listing, the `--all`
//! status line, and [`OffsetList`], the one walk-or-page read of `api-keys list` and
//! `customer-apps list`.

use super::views;
use crate::clients::{ManagementClients, SINGLE_REQUEST_BUDGET, TOKEN_BUDGET, WALK_BUDGET};
use crate::error::{CliError, SecretSet};
use crate::json::OValue;
use crate::pagination::{self, ListParams};
use scm::RequestOptions;
use scm::airs::management::PaginationOptions;
use scm::airs::management::models::FiniteNumber;
use scm::pagination::{CollectOptions, CollectionResult};
use std::collections::HashSet;
use std::time::Duration;

/// One page of an offset listing: its rows and whether more follow (D12, [`more_rows`]).
pub struct Listed<T> {
    pub items: Vec<T>,
    pub more: bool,
}

/// The walk-or-page read of an offset inventory (§18.4, §18.7); the command supplies only
/// its client calls, the row identity and the projection.
pub struct OffsetList<P, A> {
    /// The row identity of the G28 check (D219).
    pub id_key: &'static str,
    /// One page: the page options and the request options to its rows.
    pub page: P,
    /// The SDK `list_all` walk (D46): `--limit`, the collect options of `--max` and the
    /// request options.
    pub all: A,
    /// The TS projection of one sanitised row.
    pub project: fn(&OValue) -> OValue,
}

/// What an [`OffsetList`] read gives: the projected rows and the status line.
pub struct Listing {
    pub docs: Vec<OValue>,
    pub status: String,
}

impl<P, A> OffsetList<P, A> {
    /// `--all`: one `WALK_BUDGET` for the token and the walk, the repeated-row check and
    /// the `--all` status line. One page: the token under its own budget, then the page
    /// under its own `SINGLE_REQUEST_BUDGET` and the D12 status line. Either way the rows
    /// are sanitised as one listing (D205) before the projection. `fail` is the §6 read
    /// error of an SDK failure under a budget.
    pub async fn read<T>(
        self,
        clients: &ManagementClients,
        params: &ListParams,
        secrets: &SecretSet,
        fail: impl Fn(&scm::Error, Duration) -> CliError,
    ) -> Result<Listing, CliError>
    where
        T: serde::Serialize,
        P: AsyncFnOnce(PaginationOptions, &RequestOptions) -> Result<Listed<T>, scm::Error>,
        A: AsyncFnOnce(u32, CollectOptions, &RequestOptions) -> CollectionResult<T, u64>,
    {
        let (mut rows, status) = if params.all {
            let options = super::options(WALK_BUDGET)?;
            clients.authenticate(Some(&options), WALK_BUDGET).await?;
            let failed = |error: &scm::Error| fail(error, WALK_BUDGET);
            let collect =
                pagination::collect_options(params.max).map_err(|error| failed(&error))?;
            let collection = (self.all)(params.limit, collect, &options)
                .await
                .map_err(|error| failed(error.error()))?;
            let rows =
                unique_rows(&collection.items, self.id_key).map_err(|error| failed(&error))?;
            let status = walk_status(collection.completion, rows.len(), params.max)
                .map_err(|error| failed(&error))?;
            (rows, status)
        } else {
            clients.authenticate(None, TOKEN_BUDGET).await?;
            let failed = |error: &scm::Error| fail(error, SINGLE_REQUEST_BUDGET);
            let mut page = PaginationOptions::default();
            page.offset = params.offset;
            page.limit = params.limit;
            let listed = (self.page)(page, &super::options(SINGLE_REQUEST_BUDGET)?)
                .await
                .map_err(|error| failed(&error))?;
            let rows = rows_of(&listed.items).map_err(|error| failed(&error))?;
            let status = pagination::showing_page(rows.len(), listed.more);
            (rows, status)
        };
        sanitize_all(&mut rows, secrets);
        Ok(Listing {
            docs: rows.iter().map(self.project).collect(),
            status,
        })
    }
}

/// `next_offset` > 0 means more rows (D12: `0` ends pagination).
pub fn more_rows(next: Option<&FiniteNumber>) -> bool {
    next.and_then(FiniteNumber::as_f64)
        .is_some_and(|next| next > 0.0)
}

/// SDK models as ordered JSON.
pub fn rows_of<T: serde::Serialize>(items: &[T]) -> Result<Vec<OValue>, scm::Error> {
    items.iter().map(views::ordered).collect()
}

/// G28 (D219): a row identity (`id_key`) seen twice in a complete walk is the D37 error.
pub fn check_unique(rows: &[OValue], id_key: &str) -> Result<(), scm::Error> {
    let mut seen = HashSet::new();
    for row in rows {
        if let Some(id) = views::text(row, id_key)
            && !seen.insert(id.to_owned())
        {
            return Err(scm::Error::new(scm::ErrorKind::Pagination));
        }
    }
    Ok(())
}

/// The rows of a complete walk ([`rows_of`]) with the [`check_unique`] row check.
pub fn unique_rows<T: serde::Serialize>(
    items: &[T],
    id_key: &str,
) -> Result<Vec<OValue>, scm::Error> {
    let rows = rows_of(items)?;
    check_unique(&rows, id_key)?;
    Ok(rows)
}

/// D205 over a whole listing: every `api_key` member removed and registered first, then
/// every string that carries a registered secret withheld.
pub fn sanitize_all(rows: &mut [OValue], secrets: &SecretSet) {
    for row in rows.iter_mut() {
        views::strip_api_keys(row, secrets);
    }
    for row in rows.iter_mut() {
        crate::secrets::withhold(row, secrets);
    }
}

/// The `--all` status line, or the incomplete-walk error (§7.3, D14).
pub fn walk_status(
    completion: scm::pagination::Completion,
    returned: usize,
    max: u64,
) -> Result<String, scm::Error> {
    let end = pagination::walk_end(completion, max).ok_or_else(pagination::incomplete_walk)?;
    Ok(pagination::all_status(returned, end, max))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(text: &str) -> OValue {
        crate::json::parse(text).unwrap()
    }

    #[test]
    fn a_repeated_identity_is_the_pagination_error() {
        let rows = [row(r#"{"id":"a"}"#), row(r#"{"id":"b"}"#), row("{}")];
        assert!(check_unique(&rows, "id").is_ok());
        let repeated = [row(r#"{"id":"a"}"#), row(r#"{"id":"a"}"#)];
        assert_eq!(
            check_unique(&repeated, "id").unwrap_err().kind(),
            scm::ErrorKind::Pagination
        );
    }

    #[test]
    fn a_secret_seen_in_one_row_is_withheld_in_every_row() {
        let secrets = SecretSet::default();
        let mut rows = [
            row(r#"{"name":"a FAKE-K9 b"}"#),
            row(r#"{"api_key":"FAKE-K9"}"#),
        ];
        sanitize_all(&mut rows, &secrets);
        assert_eq!(
            crate::json::to_compact(&rows).unwrap(),
            r#"[{"name":"[withheld]"},{}]"#
        );
    }
}
