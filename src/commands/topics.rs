//! `runtime topics list|ls` and `runtime topics get` (DESIGN §7).
//!
//! Flags arrive validated (`pagination`); `format` is the explicit `--output` or
//! `None`, in which case the tenant's `defaultOutput` (else `pretty`) applies.
//! Every topic read is a walk (the service has no latest filter for topics), run
//! under one shared 300 s deadline; `--limit`/`--offset` slice locally. Listings walk
//! under the `--all` safety bounds (1,000,000 rows); lookups keep the SDK's 10,000-row
//! default (D15). An incomplete walk is an error either way.

use super::{Invocation, walk_options};
use crate::clients::WALK_BUDGET;
use crate::error::CliError;
use crate::output::Format;
use crate::pagination::{self, GetParams, ListParams};
use crate::views;
use scm::airs::management::models::CustomTopic;
use scm::airs::management::{TopicListAllOptions, TopicsClient};
use scm::pagination::{CollectOptions, CollectionError};
use scm::{ErrorKind, RequestOptions};

/// Page size of the SDK's latest-topic walk, reused for `--all`.
const LATEST_PAGE: u32 = 200;

pub async fn list(
    invocation: &mut Invocation,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let options = walk_options()?;
    let (management, format) = invocation
        .connect_management(format, Some(&options))
        .await?;
    let topics = management.topics();
    let listed = match (params.all_versions, params.all) {
        (false, false) => latest_page(&topics, params, &options).await,
        (false, true) => latest_all(&topics, params, &options).await,
        (true, false) => versions_page(&topics, params, &options).await,
        (true, true) => versions_all(&topics, params, &options).await,
    };
    let (rows, status) =
        listed.map_err(|error| invocation.management_error(&error, WALK_BUDGET))?;
    invocation.output.status(&status);
    views::render_topic_list(&mut invocation.output, &rows, format)
}

/// Latest revisions sliced to `[offset, offset+limit)`, with `(more available)` only
/// when more topics follow the slice (D13). This is `TopicsClient::list` with
/// `latest_only` (same 200-row walk, first-seen order, first-wins ties), but bounded
/// like `--all` rather than by the SDK's fixed 10,000-row default, so the page works
/// on every tenant the `--all` listing works on.
async fn latest_page(
    topics: &TopicsClient,
    params: &ListParams,
    options: &RequestOptions,
) -> Result<(Vec<CustomTopic>, String), scm::Error> {
    let rows = complete_walk(
        topics,
        LATEST_PAGE,
        pagination::collect_options(0)?,
        options,
    )
    .await?;
    let latest = views::latest_per_name(rows);
    let total = latest.len() as u64;
    let more = params.offset.saturating_add(u64::from(params.limit)) < total;
    let rows = pagination::slice(latest, params.offset, params.limit);
    let status = pagination::showing_page(rows.len(), more);
    Ok((rows, status))
}

/// `--all`: the same 200-row walk bounded only by the safety ceiling (so `--max 0`
/// is uncapped, D16), latest revisions, then the first `--max` of them.
async fn latest_all(
    topics: &TopicsClient,
    params: &ListParams,
    options: &RequestOptions,
) -> Result<(Vec<CustomTopic>, String), scm::Error> {
    let rows = complete_walk(
        topics,
        LATEST_PAGE,
        pagination::collect_options(0)?,
        options,
    )
    .await?;
    let (rows, end) = pagination::first(views::latest_per_name(rows), params.max);
    let status = pagination::all_status(rows.len(), end, params.max);
    Ok((rows, status))
}

/// `--all-versions`: every revision (100 per page), sliced locally.
async fn versions_page(
    topics: &TopicsClient,
    params: &ListParams,
    options: &RequestOptions,
) -> Result<(Vec<CustomTopic>, String), scm::Error> {
    let rows = complete_walk(topics, 100, pagination::collect_options(0)?, options).await?;
    let total = rows.len();
    let rows = pagination::slice(rows, params.offset, params.limit);
    let status = pagination::showing_slice(rows.len(), total, params.offset, params.limit);
    Ok((rows, status))
}

/// `--all-versions --all`: every revision up to `--max`.
async fn versions_all(
    topics: &TopicsClient,
    params: &ListParams,
    options: &RequestOptions,
) -> Result<(Vec<CustomTopic>, String), scm::Error> {
    let mut all = TopicListAllOptions::default();
    all.collect = pagination::collect_options(params.max)?;
    let collection = topics
        .list_all(all, Some(options))
        .await
        .map_err(CollectionError::into_error)?;
    let end = pagination::walk_end(collection.completion, params.max)
        .ok_or_else(pagination::incomplete_walk)?;
    let status = pagination::all_status(collection.items.len(), end, params.max);
    Ok((collection.items, status))
}

/// Walk every topic row; a walk cut short by a client bound is an error.
pub(crate) async fn complete_walk(
    topics: &TopicsClient,
    limit: u32,
    collect: CollectOptions,
    options: &RequestOptions,
) -> Result<Vec<CustomTopic>, scm::Error> {
    let mut all = TopicListAllOptions::default();
    all.limit = limit;
    all.collect = collect;
    let collection = topics
        .list_all(all, Some(options))
        .await
        .map_err(CollectionError::into_error)?;
    if collection.is_complete() {
        Ok(collection.items)
    } else {
        Err(pagination::incomplete_walk())
    }
}

pub async fn get(
    invocation: &mut Invocation,
    params: &GetParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let options = walk_options()?;
    let (management, format) = invocation
        .connect_management(format, Some(&options))
        .await?;
    let topics = management.topics();
    let value = params.name_or_id.as_str();
    let by_id = params.is_id();
    let filtered = params.revision.is_some() || params.all_versions;
    if !filtered {
        let found = if by_id {
            topics.get(value, Some(&options)).await
        } else {
            topics.get_by_name(value, Some(&options)).await
        };
        return match found {
            Ok(topic) => views::render_topic_detail(&mut invocation.output, &topic, format),
            // A complete walk without a match; an incomplete one is `Limit`.
            Err(error) if error.kind() == ErrorKind::Validation => {
                Err(CliError::operational(not_found(value, by_id, false)))
            }
            Err(error) => Err(invocation.management_error(&error, WALK_BUDGET)),
        };
    }
    let rows = complete_walk(&topics, 100, CollectOptions::default(), &options)
        .await
        .map_err(|error| invocation.management_error(&error, WALK_BUDGET))?;
    let selected = views::matching_versions(rows, value, by_id, params.revision);
    let Some(first) = selected.first() else {
        return Err(CliError::operational(not_found(value, by_id, true)));
    };
    if params.all_versions {
        views::render_topic_list(&mut invocation.output, &selected, format)
    } else {
        views::render_topic_detail(&mut invocation.output, first, format)
    }
}

/// The TypeScript CLI's three not-found wordings (§7.4).
fn not_found(value: &str, by_id: bool, filtered: bool) -> String {
    if by_id || filtered {
        format!("Topic {value} not found")
    } else {
        format!("Topic \"{value}\" not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_messages() {
        let id = "00000000-0000-4000-8000-000000000011";
        assert_eq!(not_found(id, true, false), format!("Topic {id} not found"));
        assert_eq!(not_found("fin", false, false), "Topic \"fin\" not found");
        assert_eq!(not_found("fin", false, true), "Topic fin not found");
        assert_eq!(not_found(id, true, true), format!("Topic {id} not found"));
    }
}
