//! Workspace reference resolution (DESIGN §19.4; D235): the command's lists are read in
//! order, a failing list stops the resolution, an exact `id` or `slug` on any list wins
//! over a display name on an earlier one (choice 127), and a reference nothing matches is
//! refused with nothing sent (TS skips a failing list and sends an unmatched reference as
//! typed).

use super::GwPlane;
use crate::json::OValue;
use scm::airs::gateway::{
    AIGatewayClient, AIGatewayWorkspaceListOptions, AIGatewayWorkspaceStatus,
};

/// The `status` a workspace list sends (none: the server's active-only default).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListStatus {
    Active,
    Archived,
}

/// One workspace list (`GET <plane>/workspaces[?status=<s>]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListRead {
    pub plane: GwPlane,
    pub status: Option<ListStatus>,
}

/// Every telemetry leaf: data active, admin active, admin archived (choice 13).
pub const TELEMETRY: &[ListRead] = &[
    ListRead {
        plane: GwPlane::Data,
        status: None,
    },
    ListRead {
        plane: GwPlane::Admin,
        status: None,
    },
    ListRead {
        plane: GwPlane::Admin,
        status: Some(ListStatus::Archived),
    },
];

/// What a resolution found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// The row whose `id` or `slug` equals the reference: its slug.
    ByRef(String),
    /// The one row whose `name` equals the reference: its slug.
    ByName(String),
    /// Several rows of one list carry the name: their slugs.
    Ambiguous(Vec<String>),
    /// A list says it is incomplete (`has_more: true`, or a `total` other than its rows,
    /// G39) and no row carries the reference as its `id` or `slug`: a name match or a miss
    /// cannot be trusted, because a row beyond the answer may carry the name (D254).
    Incomplete,
    /// No list matched.
    NotFound,
    /// The matched row carries no non-empty string `slug`, so there is no path segment to
    /// send (the request would go to a malformed route).
    NoSlug,
}

/// A list read that failed, with the plane it went to (for the grant hint).
pub struct ListFailure {
    pub error: scm::Error,
    pub plane: GwPlane,
    /// An earlier list of the resolution was read and carried no exact `id` or `slug`, so
    /// this list was read only to look further (a display name reads every list, choice
    /// 127): [`later_list_hint`] tells the user how to resolve without it.
    pub after_unmatched: bool,
}

/// The `data` rows of one workspace list.
pub async fn read_list(gateway: &AIGatewayClient, read: ListRead) -> Result<OValue, ListFailure> {
    let failure = |error| ListFailure {
        error,
        plane: read.plane,
        after_unmatched: false,
    };
    let options = super::sdk_options(crate::clients::SINGLE_REQUEST_BUDGET).map_err(failure)?;
    let mut query = AIGatewayWorkspaceListOptions::default();
    query.plane = read.plane.sdk();
    query.status = read.status.map(|status| match status {
        ListStatus::Active => AIGatewayWorkspaceStatus::Active,
        ListStatus::Archived => AIGatewayWorkspaceStatus::Archived,
    });
    let answer = gateway
        .workspaces()
        .list(&query, Some(&options))
        .await
        .map_err(failure)?;
    crate::json::page_value(&answer).map_err(failure)
}

/// A row's `slug`, when it is a non-empty string (the only usable path segment).
fn slug_of(row: &OValue) -> Option<String> {
    row.get("slug")
        .and_then(OValue::as_str)
        .filter(|slug| !slug.is_empty())
        .map(str::to_owned)
}

/// The row whose `id` or `slug` equals `reference` exactly (§19.4 step 2).
fn exact_row<'a>(rows: &'a [OValue], reference: &str) -> Option<&'a OValue> {
    let text = |row: &OValue, key: &str| row.get(key).and_then(OValue::as_str) == Some(reference);
    rows.iter().find(|row| text(row, "id") || text(row, "slug"))
}

/// The display-name rule within one list (§19.4 step 2): exactly one row whose `name`
/// equals `reference`; several are ambiguous (a row without a slug shown `(no slug)`).
fn match_name(rows: &[OValue], reference: &str) -> Resolved {
    let named: Vec<Option<String>> = rows
        .iter()
        .filter(|row| row.get("name").and_then(OValue::as_str) == Some(reference))
        .map(slug_of)
        .collect();
    match named.as_slice() {
        [] => Resolved::NotFound,
        [Some(slug)] => Resolved::ByName(slug.clone()),
        [None] => Resolved::NoSlug,
        _ => Resolved::Ambiguous(
            named
                .into_iter()
                .map(|slug| slug.unwrap_or_else(|| "(no slug)".to_owned()))
                .collect(),
        ),
    }
}

/// Whether a workspace list answer says it is incomplete (the shared G39 rule,
/// [`super::incomplete_total`], over its `data` rows, `total` and `has_more`).
pub fn incomplete(answer: &OValue) -> bool {
    let rows = answer
        .get("data")
        .and_then(OValue::as_array)
        .map_or(0, <[OValue]>::len);
    let has_more = matches!(answer.get("has_more"), Some(OValue::Bool(true)));
    super::incomplete_total(rows, answer.get("total"), has_more).is_some()
}

/// The match rule over one list answer (§19.4 step 2, D254): on an incomplete list only an
/// exact `id` or `slug` match resolves (a name may also sit beyond the answer).
pub fn match_answer(answer: &OValue, reference: &str) -> Resolved {
    match_answers(std::slice::from_ref(answer), reference)
}

/// The rows of a list answer.
fn rows_of(answer: &OValue) -> &[OValue] {
    answer
        .get("data")
        .and_then(OValue::as_array)
        .unwrap_or_default()
}

/// The two passes of §19.4 over list answers already read, in the command's order: an
/// exact `id` or `slug` on any list wins (choice 127); without one, an incomplete list
/// stops the resolution (D254: the exact row, or a second named row, may sit beyond it);
/// else the first list with a display-name match decides.
pub fn match_answers(answers: &[OValue], reference: &str) -> Resolved {
    if let Some(row) = answers
        .iter()
        .find_map(|answer| exact_row(rows_of(answer), reference))
    {
        return slug_of(row).map_or(Resolved::NoSlug, Resolved::ByRef);
    }
    if answers.iter().any(incomplete) {
        return Resolved::Incomplete;
    }
    answers
        .iter()
        .map(|answer| match_name(rows_of(answer), reference))
        .find(|found| *found != Resolved::NotFound)
        .unwrap_or(Resolved::NotFound)
}

/// Resolve `reference` over `reads`, in order (§19.4). The lists are read one after the
/// other until one carries the reference as an exact `id` or `slug`; a display name is
/// matched only once every list has been read, so a later list's exact slug wins over an
/// earlier list's name (choice 127). A failing list stops the resolution.
pub async fn resolve(
    gateway: &AIGatewayClient,
    reference: &str,
    reads: &[ListRead],
) -> Result<Resolved, ListFailure> {
    let mut answers = Vec::with_capacity(reads.len());
    for read in reads {
        let answer = read_list(gateway, *read)
            .await
            .map_err(|failure| ListFailure {
                after_unmatched: !answers.is_empty(),
                ..failure
            })?;
        let exact = exact_row(rows_of(&answer), reference).is_some();
        answers.push(answer);
        if exact {
            break;
        }
    }
    Ok(match_answers(&answers, reference))
}

/// The hint of a [`TELEMETRY`] resolution stopped by a later list
/// ([`ListFailure::after_unmatched`]): the reference was no `id` or `slug` on the
/// data-plane list, so the admin-plane lists were read too; a slug or UUID resolves from
/// the data plane alone (a data-plane-only grant reads no admin-plane list).
pub fn later_list_hint(reference: &str) -> String {
    format!(
        "⚠ '{}' is no workspace id or slug on the data-plane list, so the admin-plane lists were read too: use the workspace slug or UUID (a display name also reads the admin-plane lists, which need the admin grant)",
        super::shown(reference)
    )
}

/// `Workspace '<ref>' was not found on the <planes>; nothing was sent`.
pub fn not_found_message(reference: &str, reads: &[ListRead]) -> String {
    let mut planes: Vec<&str> = Vec::new();
    for read in reads {
        if !planes.contains(&read.plane.name()) {
            planes.push(read.plane.name());
        }
    }
    let planes = match planes.as_slice() {
        [one] => format!("{one} plane"),
        many => format!("{} planes", many.join(" and ")),
    };
    format!(
        "Workspace '{}' was not found on the {planes}; nothing was sent",
        super::shown(reference)
    )
}

/// The refusal of a reference an incomplete list cannot resolve (D254); `nothing_sent`
/// adds `; nothing was sent` (every write and telemetry leaf; `workspaces get` has sent its
/// detail read).
pub fn incomplete_message(reference: &str, nothing_sent: bool) -> String {
    format!(
        "Workspace '{}' cannot be resolved: the workspace list is incomplete (the API offers no continuation); use the workspace slug or UUID{}",
        super::shown(reference),
        if nothing_sent {
            "; nothing was sent"
        } else {
            ""
        }
    )
}

/// The refusal of a matched row that carries no slug (no path segment to send);
/// `nothing_sent` as for [`incomplete_message`].
pub fn no_slug_message(reference: &str, nothing_sent: bool) -> String {
    format!(
        "Workspace '{}' cannot be resolved: the matching workspace carries no slug in the list answer{}",
        super::shown(reference),
        if nothing_sent {
            "; nothing was sent"
        } else {
            ""
        }
    )
}

/// TS's ambiguity text.
pub fn ambiguous_message(reference: &str, slugs: &[String]) -> String {
    format!(
        "workspace name '{}' is ambiguous ({}) — use a slug or UUID",
        super::shown(reference),
        slugs
            .iter()
            .map(|slug| crate::output::terminal_safe(slug).into_owned())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn rows_match_by_ref_then_unique_name() {
        let rows = parse(
            r#"{"data":[{"id":"u-dev","slug":"ws-develo-71f8d8","name":"Development"},{"id":"u-prod","slug":"ws-produc-985697","name":"Production"},{"id":"u-p2","slug":"ws-produc-111111","name":"Twin"},{"id":"u-p3","slug":"ws-produc-222222","name":"Twin"}]}"#,
        )
        .unwrap();
        let rows = &rows;
        assert_eq!(
            match_answer(rows, "Development"),
            Resolved::ByName("ws-develo-71f8d8".into())
        );
        assert_eq!(
            match_answer(rows, "u-prod"),
            Resolved::ByRef("ws-produc-985697".into())
        );
        assert_eq!(
            match_answer(rows, "ws-develo-71f8d8"),
            Resolved::ByRef("ws-develo-71f8d8".into())
        );
        assert_eq!(
            match_answer(rows, "Twin"),
            Resolved::Ambiguous(vec!["ws-produc-111111".into(), "ws-produc-222222".into()])
        );
        assert_eq!(match_answer(rows, "nope"), Resolved::NotFound);
        // D254: an incomplete answer resolves only an exact id or slug.
        for incomplete in [
            r#"{"data":[{"id":"u-prod","slug":"ws-produc-985697","name":"Production"}],"has_more":true}"#,
            r#"{"data":[{"id":"u-prod","slug":"ws-produc-985697","name":"Production"}],"total":50}"#,
        ] {
            let answer = parse(incomplete).unwrap();
            assert!(super::incomplete(&answer));
            assert_eq!(match_answer(&answer, "Production"), Resolved::Incomplete);
            assert_eq!(match_answer(&answer, "nope"), Resolved::Incomplete);
            assert_eq!(
                match_answer(&answer, "u-prod"),
                Resolved::ByRef("ws-produc-985697".into())
            );
            assert_eq!(
                match_answer(&answer, "ws-produc-985697"),
                Resolved::ByRef("ws-produc-985697".into())
            );
        }
        for complete in [
            r#"{"data":[{"id":"u-prod","slug":"ws-produc-985697","name":"Production"}],"total":1,"has_more":false}"#,
            r#"{"data":[{"id":"u-prod","slug":"ws-produc-985697","name":"Production"}],"total":2.5}"#,
        ] {
            let answer = parse(complete).unwrap();
            assert!(!super::incomplete(&answer));
            assert_eq!(
                match_answer(&answer, "Production"),
                Resolved::ByName("ws-produc-985697".into())
            );
        }
        assert_eq!(
            incomplete_message("Production", true),
            "Workspace 'Production' cannot be resolved: the workspace list is incomplete (the API offers no continuation); use the workspace slug or UUID; nothing was sent"
        );
        assert_eq!(
            ambiguous_message("Twin", &["a".into(), "b".into()]),
            "workspace name 'Twin' is ambiguous (a, b) — use a slug or UUID"
        );
        assert_eq!(
            not_found_message("NoSuch", &TELEMETRY[1..]),
            "Workspace 'NoSuch' was not found on the admin plane; nothing was sent"
        );
        assert_eq!(
            not_found_message("NoSuch", TELEMETRY),
            "Workspace 'NoSuch' was not found on the data and admin planes; nothing was sent"
        );
    }

    /// Choice 127: an exact id or slug on any list wins over a display name on an earlier
    /// one; without one, an incomplete list stops the resolution; else the first list with
    /// a name decides.
    #[test]
    fn an_exact_reference_on_a_later_list_wins_over_an_earlier_name() {
        let data = parse(r#"{"data":[{"id":"u-a","slug":"ws-a","name":"ws-b"}]}"#).unwrap();
        let admin = parse(
            r#"{"data":[{"id":"u-a","slug":"ws-a","name":"ws-b"},{"id":"u-b","slug":"ws-b","name":"B"}]}"#,
        )
        .unwrap();
        let answers = [data.clone(), admin.clone()];
        assert_eq!(
            match_answers(&answers, "ws-b"),
            Resolved::ByRef("ws-b".into())
        );
        assert_eq!(
            match_answers(&answers, "u-b"),
            Resolved::ByRef("ws-b".into())
        );
        assert_eq!(
            match_answers(&answers, "B"),
            Resolved::ByName("ws-b".into())
        );
        assert_eq!(
            match_answers(std::slice::from_ref(&data), "ws-b"),
            Resolved::ByName("ws-a".into())
        );
        // The first list with a name decides; a later list's twin is not consulted.
        let archived = parse(r#"{"data":[{"id":"u-c","slug":"ws-c","name":"B"}]}"#).unwrap();
        assert_eq!(
            match_answers(&[admin.clone(), archived], "B"),
            Resolved::ByName("ws-b".into())
        );
        // A later incomplete list may hold the exact reference: a name cannot resolve.
        let partial = parse(r#"{"data":[],"has_more":true}"#).unwrap();
        assert_eq!(
            match_answers(&[data.clone(), partial.clone()], "ws-b"),
            Resolved::Incomplete
        );
        assert_eq!(
            match_answers(&[data, partial, admin], "u-b"),
            Resolved::ByRef("ws-b".into())
        );
    }

    /// A matched row without a non-empty string slug is `NoSlug`, never an empty segment.
    #[test]
    fn a_matched_row_without_a_slug_is_refused() {
        for answer in [
            r#"{"data":[{"id":"u-a","name":"A"}]}"#,
            r#"{"data":[{"id":"u-a","slug":"","name":"A"}]}"#,
            r#"{"data":[{"id":"u-a","slug":7,"name":"A"}]}"#,
        ] {
            let answer = parse(answer).unwrap();
            assert_eq!(match_answer(&answer, "u-a"), Resolved::NoSlug);
            assert_eq!(match_answer(&answer, "A"), Resolved::NoSlug);
        }
        let twins =
            parse(r#"{"data":[{"id":"u-a","name":"A"},{"id":"u-b","slug":"ws-b","name":"A"}]}"#)
                .unwrap();
        assert_eq!(
            match_answer(&twins, "A"),
            Resolved::Ambiguous(vec!["(no slug)".into(), "ws-b".into()])
        );
        assert_eq!(
            no_slug_message("u-a", true),
            "Workspace 'u-a' cannot be resolved: the matching workspace carries no slug in the list answer; nothing was sent"
        );
        assert_eq!(
            no_slug_message("u-a", false),
            "Workspace 'u-a' cannot be resolved: the matching workspace carries no slug in the list answer"
        );
    }
}
