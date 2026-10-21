//! Every model-security list and get leaf (DESIGN §17.4–§17.7).
//!
//! A list is one of three shapes:
//! - a single page, with `skip` and `limit` as TypeScript sends them (§17.3) and a status
//!   line only when the page does not show everything (choice 6);
//! - an `--all` walk from `skip=0` (the shared page loop, `src/walk.rs`, D183), with the
//!   scans `count_capped` latch (D182) and the D14 line when `--max` stopped it;
//! - `scans list --scan-origin`: every page of 100 walked with the other filters, the rows
//!   of that origin kept, then sliced (D181, G18).
//!
//! Every SDK call validates its answer without the frozen response defaults (G20, D180).

use super::Invocation;
use super::modelsec::{Connected, MsGet, MsList};
use super::redteam::page_value;
use crate::clients::{SINGLE_REQUEST_BUDGET, WALK_BUDGET};
use crate::error::CliError;
use crate::json::OValue;
use crate::modelsec::views::{self, Kind, List};
use crate::modelsec::{self, ORIGIN_PAGE_SIZE};
use crate::output::Format;
use crate::walk::{self, ListParams, Page};
use scm::airs::model_security::{
    ModelSecurityClient, ModelSecurityEvaluationListOptions, ModelSecurityFileListOptions,
    ModelSecurityGroupListOptions, ModelSecurityLabelListOptions, ModelSecurityModelListOptions,
    ModelSecurityModelVersionListOptions, ModelSecurityRuleInstanceListOptions,
    ModelSecurityRuleListOptions, ModelSecurityScanListOptions,
};

/// One page of `list` as ordered JSON: its rows (under the list's own key), the
/// `pagination.total_items` count and the scans `count_capped` flag. `walk`: the page of a
/// walk (scans send `--search` as `search_query` there, choice 4).
async fn fetch(
    ms: &ModelSecurityClient,
    list: &MsList,
    skip: Option<u64>,
    limit: Option<u32>,
    walk: bool,
    options: &scm::RequestOptions,
) -> Result<Page<OValue>, scm::Error> {
    let options = Some(options);
    let (answer, key) = match list {
        MsList::Groups {
            source_types,
            search,
            sort_field,
            sort_dir,
            enabled_rules,
        } => {
            let mut query = ModelSecurityGroupListOptions::default();
            query.skip = skip;
            query.limit = limit;
            query.sort_field = sort_field.clone();
            query.sort_dir = sort_dir.clone();
            query.source_types = source_types.clone();
            query.search_query = search.clone();
            query.enabled_rules = enabled_rules.clone();
            (
                page_value(&ms.security_groups().list(&query, options).await?)?,
                "security_groups",
            )
        }
        MsList::Rules {
            source_type,
            search,
        } => {
            let mut query = ModelSecurityRuleListOptions::default();
            query.skip = skip;
            query.limit = limit;
            query.source_type = source_type.clone();
            query.search_query = search.clone();
            (
                page_value(&ms.security_rules().list(&query, options).await?)?,
                "rules",
            )
        }
        MsList::RuleInstances {
            group,
            security_rule_uuid,
            state,
        } => {
            let mut query = ModelSecurityRuleInstanceListOptions::default();
            query.skip = skip;
            query.limit = limit;
            query.security_rule_uuid = security_rule_uuid.clone();
            query.state = state.clone();
            (
                page_value(
                    &ms.security_groups()
                        .list_rule_instances(group, &query, options)
                        .await?,
                )?,
                "rule_instances",
            )
        }
        MsList::Scans {
            window,
            eval_outcome,
            source_type,
            search,
            scan_origin: _,
        } => {
            let mut query = ModelSecurityScanListOptions::default();
            query.skip = skip;
            query.limit = limit;
            if walk {
                query.search_query = search.clone();
            } else {
                query.search = search.clone();
            }
            query.model_version_uuid = window.model_version.clone();
            query.eval_outcomes = eval_outcome.clone().map(|value| vec![value]);
            query.source_types = source_type.clone().map(|value| vec![value]);
            query.start_time = window.start.clone();
            query.end_time = window.end.clone();
            (
                page_value(&ms.scans().list(&query, options).await?)?,
                "scans",
            )
        }
        MsList::Evaluations { scan } => {
            let mut query = ModelSecurityEvaluationListOptions::default();
            query.skip = skip;
            query.limit = limit;
            (
                page_value(&ms.scans().get_evaluations(scan, &query, options).await?)?,
                "evaluations",
            )
        }
        MsList::Violations { scan } => {
            let mut query = ModelSecurityLabelListOptions::default();
            query.skip = skip;
            query.limit = limit;
            (
                page_value(&ms.scans().get_violations(scan, &query, options).await?)?,
                "violations",
            )
        }
        MsList::Files {
            scan,
            file_type,
            result,
        } => {
            let mut query = ModelSecurityFileListOptions::default();
            query.skip = skip;
            query.limit = limit;
            query.type_ = file_type.clone();
            query.result = result.clone();
            (
                page_value(&ms.scans().get_files(scan, &query, options).await?)?,
                "files",
            )
        }
        MsList::Models {
            window,
            search,
            search_query,
            sort_field,
            sort_order,
        } => {
            let mut query = ModelSecurityModelListOptions::default();
            query.skip = skip;
            query.limit = limit;
            query.search = search.clone();
            query.search_query = search_query.clone();
            query.sort_field = sort_field.clone();
            query.sort_order = sort_order.clone();
            query.start_time = window.start.clone();
            query.end_time = window.end.clone();
            (
                page_value(&ms.models().list_models(&query, options).await?)?,
                "models",
            )
        }
        MsList::Versions { model, sort_order } => {
            let mut query = ModelSecurityModelVersionListOptions::default();
            query.skip = skip;
            query.limit = limit;
            query.sort_order = sort_order.clone();
            (
                page_value(
                    &ms.models()
                        .list_model_versions(model, &query, options)
                        .await?,
                )?,
                "model_versions",
            )
        }
        MsList::ModelFiles { version } => {
            let mut query = ModelSecurityLabelListOptions::default();
            query.skip = skip;
            query.limit = limit;
            (
                page_value(
                    &ms.models()
                        .list_model_version_files(version, &query, options)
                        .await?,
                )?,
                "files",
            )
        }
        MsList::LabelKeys => {
            let mut query = ModelSecurityLabelListOptions::default();
            query.skip = skip;
            query.limit = limit;
            (
                page_value(&ms.scans().get_label_keys(&query, options).await?)?,
                "keys",
            )
        }
        MsList::LabelValues { key } => {
            let mut query = ModelSecurityLabelListOptions::default();
            query.skip = skip;
            query.limit = limit;
            (
                page_value(&ms.scans().get_label_values(key, &query, options).await?)?,
                "values",
            )
        }
    };
    let rows = answer
        .get(key)
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .to_vec();
    let total = answer
        .get("pagination")
        .and_then(|pagination| crate::json::number(pagination, "total_items"));
    let mut page = Page::new(rows, walk::total_of(total));
    page.capped = matches!(answer.get("count_capped"), Some(OValue::Bool(true)));
    Ok(page)
}

/// The identity of a walked row (D37): a record's `uuid`, a label key or value itself.
fn row_key(row: &OValue) -> Option<String> {
    match row {
        OValue::String(text) => Some(text.clone()),
        other => other
            .get("uuid")
            .and_then(OValue::as_str)
            .filter(|uuid| !uuid.is_empty())
            .map(str::to_owned),
    }
}

/// Walk every page of `size` rows from `skip=0`, keeping at most `max` (`0`: the safety
/// bound only).
async fn walk_rows(
    invocation: &Invocation,
    ms: &ModelSecurityClient,
    list: &MsList,
    size: u32,
    max: u64,
    options: &scm::RequestOptions,
) -> Result<walk::Walked<OValue>, CliError> {
    walk::walk(
        size,
        max,
        |skip, limit| fetch(ms, list, Some(skip), Some(limit), true, options),
        |row| crate::json::to_compact(row).map_or(0, |text| text.len()),
        row_key,
    )
    .await
    .map_err(|error| invocation.management_error(&error, WALK_BUDGET))
}

/// The table/json/pretty layout of a list's rows.
fn layout(list: &MsList) -> Option<List> {
    Some(match list {
        MsList::Groups { .. } => List::Groups,
        MsList::Rules { .. } => List::Rules,
        MsList::RuleInstances { .. } => List::RuleInstances,
        MsList::Scans { .. } => List::Scans,
        MsList::Evaluations { .. } => List::Evaluations,
        MsList::Violations { .. } => List::Violations,
        MsList::Files { .. } | MsList::ModelFiles { .. } => List::Files,
        MsList::Models { .. } => List::Models,
        MsList::Versions { .. } => List::Versions,
        MsList::LabelKeys | MsList::LabelValues { .. } => return None,
    })
}

/// A list leaf (§17.3–§17.7).
pub async fn list(
    invocation: &mut Invocation,
    list: &MsList,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let origin = match list {
        MsList::Scans { scan_origin, .. } => scan_origin.clone(),
        _ => None,
    };
    let walking = params.all || origin.is_some();
    let options = modelsec::options(if walking {
        WALK_BUDGET
    } else {
        SINGLE_REQUEST_BUDGET
    })?;
    let connected: Connected = invocation
        .connect_model_security(walking.then_some(&options))
        .await?;
    let format = connected.format(format, list.tenant_default());
    let ms = connected.client;
    let paging = list.paging();
    let (rows, status) = if let Some(origin) = origin {
        // D181: the exact local filter over a complete walk, then the slice.
        let walked = walk_rows(invocation, &ms, list, ORIGIN_PAGE_SIZE, 0, &options).await?;
        let matching: Vec<OValue> = walked
            .rows
            .into_iter()
            .filter(|row| row.get("scan_origin").and_then(OValue::as_str) == Some(origin.as_str()))
            .collect();
        let total = matching.len();
        let (rows, cut) = walk::slice(
            matching,
            &ListParams {
                limit: Some(params.limit.unwrap_or(modelsec::DEFAULT_LIMIT)),
                ..params.clone()
            },
        );
        let status = if params.all {
            cut.then(|| crate::pagination::showing_first(rows.len(), params.max))
        } else {
            Some(modelsec::origin_status(
                rows.len(),
                total,
                params.offset.unwrap_or(0),
                params.limit.unwrap_or(modelsec::DEFAULT_LIMIT),
            ))
        };
        (rows, status)
    } else if params.all {
        let walked = walk_rows(
            invocation,
            &ms,
            list,
            paging.walk_size(params),
            params.max,
            &options,
        )
        .await?;
        let status = walked
            .stopped_at_max
            .then(|| crate::pagination::showing_first(walked.rows.len(), params.max));
        (walked.rows, status)
    } else {
        let (skip, limit) = paging.page(params);
        let page = fetch(&ms, list, skip, limit, false, &options)
            .await
            .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
        // D182: a capped total is a cap, not a count, so a capped page is judged as one
        // without a total (a full page says more may be available).
        let total = if page.capped { None } else { page.total };
        let status = modelsec::page_status(page.rows.len(), skip.unwrap_or(0), limit, total);
        (page.rows, status)
    };
    match layout(list) {
        Some(layout) => {
            if layout == List::Scans {
                views::register_uris(&rows, &invocation.secrets);
            }
            let mut docs = views::project_all(layout.kind(), &rows);
            for doc in &mut docs {
                views::withhold(doc, &invocation.secrets);
            }
            views::render_list(&mut invocation.output, layout, format, &docs)?;
        }
        None => {
            let mut items: Vec<String> = rows
                .iter()
                .map(|row| row.as_str().unwrap_or_default().to_owned())
                .collect();
            views::withhold_strings(&mut items, &invocation.secrets);
            let key = match list {
                MsList::LabelValues { key } => Some(key.as_str()),
                _ => None,
            };
            views::render_labels(&mut invocation.output, key, format, &items)?;
        }
    }
    if let Some(status) = status {
        invocation.output.status(&status);
    }
    Ok(())
}

/// A get leaf (§17.4–§17.6).
pub async fn get(
    invocation: &mut Invocation,
    get: &MsGet,
    format: Option<Format>,
) -> Result<(), CliError> {
    let options = modelsec::options(SINGLE_REQUEST_BUDGET)?;
    let connected = invocation.connect_model_security(None).await?;
    let format = connected.format(format, get.tenant_default());
    let ms = connected.client;
    let read = async {
        let options = Some(&options);
        Ok::<_, scm::Error>(match get {
            MsGet::Group(id) => (
                Kind::Group,
                page_value(&ms.security_groups().get(id, options).await?)?,
            ),
            MsGet::Rule(id) => (
                Kind::Rule,
                page_value(&ms.security_rules().get(id, options).await?)?,
            ),
            MsGet::RuleInstance { group, instance } => (
                Kind::RuleInstance,
                page_value(
                    &ms.security_groups()
                        .get_rule_instance(group, instance, options)
                        .await?,
                )?,
            ),
            MsGet::Scan(id) => (Kind::Scan, page_value(&ms.scans().get(id, options).await?)?),
            MsGet::Evaluation(id) => (
                Kind::Evaluation,
                page_value(&ms.scans().get_evaluation(id, options).await?)?,
            ),
            MsGet::Violation(id) => (
                Kind::Violation,
                page_value(&ms.scans().get_violation(id, options).await?)?,
            ),
            MsGet::Model(id) => (
                Kind::Model,
                page_value(&ms.models().get_model(id, options).await?)?,
            ),
            MsGet::Version(id) => (
                Kind::ModelVersion,
                page_value(&ms.models().get_model_version(id, options).await?)?,
            ),
        })
    };
    let (kind, raw) = read
        .await
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
    if kind == Kind::Scan {
        views::register_uris(std::slice::from_ref(&raw), &invocation.secrets);
    }
    let mut doc = views::project(kind, &raw);
    views::withhold(&mut doc, &invocation.secrets);
    views::render_get(&mut invocation.output, kind, format, &doc)
}
