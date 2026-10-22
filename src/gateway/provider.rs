//! `integrations create --ai-provider <slug>` (DESIGN §19.12, G38): the slug matched
//! against the provider catalog the CLI reads itself (the SDK's `resolve_provider_id`
//! refuses an unknown slug without text or suggestions, GW3). A UUID never reaches here: it
//! is lowercased and used without a request during planning (TS).

use crate::error::CliError;
use crate::json::OValue;
use crate::output::terminal_safe;

/// At most this many suggestions (TS).
const SUGGESTIONS: usize = 5;

/// The catalog answer's unreadable-row text (a matched row without a string `id`).
const UNREADABLE: &str = "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema";

/// A catalog row's `slug`.
fn slug_of(row: &OValue) -> Option<&str> {
    row.get("slug").and_then(OValue::as_str)
}

/// The id of the catalog row whose `slug` equals `slug` ASCII case-insensitively; else the
/// unknown-provider error with TS's suggestions (`; did you mean a, b?`, through
/// `terminal_safe`).
pub fn resolve(catalog: &OValue, slug: &str) -> Result<String, CliError> {
    let rows = catalog
        .get("data")
        .and_then(OValue::as_array)
        .unwrap_or_default();
    if let Some(row) = rows
        .iter()
        .find(|row| slug_of(row).is_some_and(|candidate| candidate.eq_ignore_ascii_case(slug)))
    {
        return row
            .get("id")
            .and_then(OValue::as_str)
            .map(str::to_owned)
            .ok_or_else(|| CliError::operational(UNREADABLE));
    }
    let close: Vec<String> = rows
        .iter()
        .filter_map(slug_of)
        .filter(|candidate| suggests(slug, candidate))
        .take(SUGGESTIONS)
        .map(|candidate| terminal_safe(candidate).into_owned())
        .collect();
    let suggestion = if close.is_empty() {
        String::new()
    } else {
        format!("; did you mean {}?", close.join(", "))
    };
    Err(CliError::operational(format!(
        "Unknown provider '{}'{suggestion} (list slugs with '{} gateway integrations providers')",
        super::shown(slug),
        crate::store::PROGRAM
    )))
}

/// TS's suggestion rule (`resolveProviderId`): either folded text contains the other.
///
/// The two sides fold differently, as in TS: the typed reference is **lowercased first**
/// and then keeps `[a-z0-9]` (`wanted.toLowerCase().replace(/[^a-z0-9]/g, "")`), while a
/// catalog slug keeps `[a-z0-9]` **without** lowercasing (`slug.replace(/[^a-z0-9]/g,
/// "")`), so a slug's upper-case letters drop out. Catalog slugs are lower case, so the
/// asymmetry only shows on an unusual slug; it is kept so the suggestions equal TS's.
pub fn suggests(typed: &str, candidate: &str) -> bool {
    let keep = |c: &char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let needle: String = typed.to_lowercase().chars().filter(keep).collect();
    let folded: String = candidate.chars().filter(keep).collect();
    folded.contains(&needle) || needle.contains(&folded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn message(error: CliError) -> String {
        match error {
            CliError::Operational(failure) => failure.message,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn slugs_resolve_case_insensitively_and_suggest_like_typescript() {
        let catalog = parse(
            r#"{"data":[{"id":"p-openai","slug":"openai"},{"id":"p-azure","slug":"azure-openai"},{"id":"p-x","slug":"x-ai"},{"slug":"broken"}]}"#,
        )
        .unwrap();
        assert_eq!(resolve(&catalog, "OpenAI").unwrap(), "p-openai");
        assert_eq!(resolve(&catalog, "X-AI").unwrap(), "p-x");
        assert_eq!(
            message(resolve(&catalog, "broken").unwrap_err()),
            UNREADABLE
        );
        assert_eq!(
            message(resolve(&catalog, "opnai").unwrap_err()),
            "Unknown provider 'opnai' (list slugs with 'airs gateway integrations providers')"
        );
        assert_eq!(
            message(resolve(&catalog, "Open_AI!").unwrap_err()),
            "Unknown provider 'Open_AI!'; did you mean openai, azure-openai? (list slugs with 'airs gateway integrations providers')"
        );
        // The typed side is lowercased before folding; the catalog side is not.
        assert!(suggests("OPENAI", "openai"));
        assert!(
            !suggests("openai", "OPENAI-x"),
            "a slug's upper-case letters drop out"
        );
        assert!(suggests("x", "OPENAI-x"));
    }
}
