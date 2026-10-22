//! `runtime profiles list|ls` and `runtime profiles get` (DESIGN §7).
//!
//! Flags arrive validated (`pagination`); `format` is the explicit `--output` or
//! `None`, in which case the tenant's `defaultOutput` (else `pretty`) applies.
//! A single page uses the SDK's per-request budget; every walk (`--all`, lookups) runs
//! under one shared 300 s deadline. Every profile read is validated without the SDK's
//! response defaults (§15.25), so a record holds only the keys the server sent.

use super::{Invocation, profile_walk_options};
use crate::clients::{SINGLE_REQUEST_BUDGET, WALK_BUDGET};
use crate::error::CliError;
use crate::output::Format;
use crate::pagination::{self, GetParams, ListParams};
use crate::views;
use scm::ErrorKind;
use scm::airs::management::models::FiniteNumber;
use scm::airs::management::{PaginationOptions, ProfileListAllOptions, ProfilesClient};
use scm::pagination::CollectionError;

pub async fn list(
    invocation: &mut Invocation,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    if params.all {
        return list_all(invocation, params, format).await;
    }
    let (management, format) = invocation.connect_management(format, None).await?;
    let mut page = PaginationOptions::default();
    page.offset = params.offset;
    page.limit = params.limit;
    page.latest = Some(!params.all_versions);
    // The SDK's per-request budget (what `None` gives), without the response defaults.
    let options = crate::runtime::options(SINGLE_REQUEST_BUDGET)?;
    let response = management
        .profiles()
        .list(page, Some(&options))
        .await
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
    // `next_offset` 0 ends pagination, so it does not mean more rows (D12).
    let more = response
        .next_offset
        .as_ref()
        .into_option()
        .and_then(FiniteNumber::as_f64)
        .is_some_and(|next| next > 0.0);
    let rows = response.ai_profiles.into_option().unwrap_or_default();
    invocation
        .output
        .status(&pagination::showing_page(rows.len(), more));
    views::render_profile_list(&mut invocation.output, &rows, format)
}

/// `--all`: follow `next_offset` from offset 0 with the page `--limit`, up to `--max`.
async fn list_all(
    invocation: &mut Invocation,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let options = profile_walk_options()?;
    let (management, format) = invocation
        .connect_management(format, Some(&options))
        .await?;
    let mut all = ProfileListAllOptions::default();
    all.limit = params.limit;
    all.latest = Some(!params.all_versions);
    all.collect = pagination::collect_options(params.max)
        .map_err(|error| invocation.management_error(&error, WALK_BUDGET))?;
    let collection = management
        .profiles()
        .list_all(all, Some(&options))
        .await
        .map_err(|error| invocation.management_error(error.error(), WALK_BUDGET))?;
    let end = pagination::walk_end(collection.completion, params.max)
        .ok_or_else(|| invocation.management_error(&pagination::incomplete_walk(), WALK_BUDGET))?;
    invocation.output.status(&pagination::all_status(
        collection.items.len(),
        end,
        params.max,
    ));
    views::render_profile_list(&mut invocation.output, &collection.items, format)
}

pub async fn get(
    invocation: &mut Invocation,
    params: &GetParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let options = profile_walk_options()?;
    let (management, format) = invocation
        .connect_management(format, Some(&options))
        .await?;
    let profiles = management.profiles();
    let value = params.name_or_id.as_str();
    let filtered = params.revision.is_some() || params.all_versions;
    if !filtered {
        let found = if params.is_id() {
            profiles.get(value, Some(&options)).await
        } else {
            profiles.get_by_name(value, Some(&options)).await
        };
        return match found {
            Ok(profile) => views::render_profile_detail(&mut invocation.output, &profile, format),
            // A complete walk without a match; an incomplete one is `Limit`.
            Err(error) if error.kind() == ErrorKind::Validation => {
                Err(CliError::operational(not_found(value, false)))
            }
            Err(error) => Err(invocation.management_error(&error, WALK_BUDGET)),
        };
    }
    let rows = every_revision(&profiles, &options)
        .await
        .map_err(|error| invocation.management_error(&error, WALK_BUDGET))?;
    let selected = views::matching_versions(rows, value, params.is_id(), params.revision);
    let Some(first) = selected.first() else {
        return Err(CliError::operational(not_found(value, true)));
    };
    if params.all_versions {
        views::render_profile_list(&mut invocation.output, &selected, format)
    } else {
        views::render_profile_detail(&mut invocation.output, first, format)
    }
}

/// Every profile revision (`latest=false`, 100 per page); an incomplete walk fails.
async fn every_revision(
    profiles: &ProfilesClient,
    options: &scm::RequestOptions,
) -> Result<Vec<scm::airs::management::models::SecurityProfile>, scm::Error> {
    let mut all = ProfileListAllOptions::default();
    all.latest = Some(false);
    let collection = profiles
        .list_all(all, Some(options))
        .await
        .map_err(CollectionError::into_error)?;
    if collection.is_complete() {
        Ok(collection.items)
    } else {
        Err(pagination::incomplete_walk())
    }
}

/// The not-found message: the SDK lookup's wording, or the filtered lookup's (§7.4).
fn not_found(value: &str, filtered: bool) -> String {
    if filtered {
        format!("Profile {value} not found")
    } else {
        format!("AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: {value}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_messages() {
        assert_eq!(
            not_found("alpha", false),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: alpha"
        );
        assert_eq!(
            not_found("00000000-0000-4000-8000-000000000002", false),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: 00000000-0000-4000-8000-000000000002"
        );
        assert_eq!(not_found("alpha", true), "Profile alpha not found");
        assert_eq!(
            CliError::operational(not_found("alpha", true)).render(),
            "\n  ✗ Error: Profile alpha not found\n\n"
        );
    }
}
