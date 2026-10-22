//! Shared DLP rules (DESIGN §16.3): the resource kinds and their words, the id checks
//! (the SDK segment rule), the list flags (`--limit`, `--offset`, the hidden `--size` and
//! `--page`, `--sort`, `--all`, `--max`) and the visibility filter. Every check here is
//! pure and runs during planning, before the tenant is read (D162).

pub mod backup;
pub mod body;
pub mod patch;
pub mod plan;
pub mod views;
pub mod walk;

use crate::cli::DlpListFlags;
use crate::error::CliError;
use crate::json::OValue;

/// The sort every list sends when `--sort` is absent (TS).
pub const DEFAULT_SORT: &str = "name,asc";
/// The page size `--offset` rounds with when `--limit` is absent, and the size of a
/// server-paged `--all` walk without `--limit` (TS `DEFAULT_PAGE_SIZE`).
pub const FALLBACK_PAGE_SIZE: u32 = 50;
/// The page size of the walk behind a custom-only (client-sliced) listing (D170).
pub const SLICE_PAGE_SIZE: u32 = 100;
/// The SDK bounds on `--sort` (`dlp:common.rs`).
const MAX_SORT_VALUES: usize = 128;
const MAX_SORT_BYTES: usize = 1024;

/// The `--size` deprecation warning (TS `deprecated-flags.ts` text).
pub const SIZE_DEPRECATED: &str = "⚠ --size is deprecated and will be removed in v4 — use --limit";
/// The `--page` deprecation warning.
pub const PAGE_DEPRECATED: &str = "⚠ --page is deprecated and will be removed in v4 — use --offset";

/// The four DLP resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    FilteringProfile,
    Pattern,
    Profile,
    Dictionary,
}

impl Kind {
    /// The resource word of messages (`Invalid <resource> id: …`).
    pub fn resource(self) -> &'static str {
        match self {
            Self::FilteringProfile => "filtering profile",
            Self::Pattern => "data pattern",
            Self::Profile => "data profile",
            Self::Dictionary => "dictionary",
        }
    }

    /// The pretty list heading (TS `rdlp.ts`); lower-cased it names the empty list.
    pub fn list_header(self) -> &'static str {
        match self {
            Self::FilteringProfile => "Data Filtering Profiles",
            Self::Pattern => "Data Patterns",
            Self::Profile => "Data Profiles",
            Self::Dictionary => "Data Dictionaries",
        }
    }

    /// The pretty get heading.
    pub fn get_title(self) -> &'static str {
        match self {
            Self::FilteringProfile => "Data Filtering Profile",
            Self::Pattern => "Data Pattern",
            Self::Profile => "Data Profile",
            Self::Dictionary => "Data Dictionary",
        }
    }

    /// The `Change` words of a write (`data pattern`, `created`; §16.3 table).
    pub fn change(self, done: &'static str) -> crate::writes::Change {
        crate::writes::Change::Words(self.resource(), done)
    }

    /// The `runtime dlp` group of the kind (`patterns`, …).
    pub fn group(self) -> &'static str {
        match self {
            Self::FilteringProfile => "filtering-profiles",
            Self::Pattern => "patterns",
            Self::Profile => "profiles",
            Self::Dictionary => "dictionaries",
        }
    }

    /// The hint after a create whose outcome is unknown or unreadable (§16.3).
    pub fn create_hint(self) -> Option<String> {
        let group = match self {
            Self::FilteringProfile => return None,
            other => other.group(),
        };
        let tail = if self == Self::Profile {
            "; data profiles cannot be deleted."
        } else {
            "."
        };
        Some(format!(
            "Check 'airs runtime dlp {group} list' before creating it again{tail}"
        ))
    }

    /// Whether listings hide predefined records unless `--include-predefined` (TS
    /// `visibility.ts`; filtering profiles always list every record).
    pub fn hides_predefined(self) -> bool {
        !matches!(self, Self::FilteringProfile)
    }
}

/// `Invalid <resource> id: <value>` (exit 2) unless `id` passes the SDK segment rule
/// (non-empty, no `.`/`..` part, no `\` and no control character, also once
/// percent-decoded; D162). The value is made terminal-safe when the error is printed.
pub fn check_id(kind: Kind, id: &str) -> Result<(), CliError> {
    crate::segment::check_segment(&format!("{} id", kind.resource()), id)
}

/// The validated flags of a DLP list (§16.3 "List flags").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListParams {
    /// `--limit`, else the hidden `--size`.
    pub limit: Option<u32>,
    /// An explicit `--offset`.
    pub offset: Option<u64>,
    /// The hidden `--page` (a page number), when no `--offset` was given.
    pub page: Option<u64>,
    pub all: bool,
    /// `--max` (default 10,000; `0`: no item cap).
    pub max: u64,
    /// `--sort` in order, else `name,asc`.
    pub sort: Vec<String>,
    pub include_predefined: bool,
    /// `--keywords` / `--include-keywords` (dictionaries).
    pub keywords: bool,
}

/// The deprecation warnings of a list's hidden aliases, printed before any other check
/// and never quiet-suppressed (§16.3 "Validation order").
pub fn deprecation_warnings(flags: &DlpListFlags) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    if flags.size.is_some() {
        warnings.push(SIZE_DEPRECATED);
    }
    if flags.page.is_some() {
        warnings.push(PAGE_DEPRECATED);
    }
    warnings
}

/// Validate the list flags in the §16.3 order: `--limit` (or `--size`), `--offset` (or
/// `--page`), `--max`, `--all` with an offset, then `--sort`.
pub fn list_params(
    flags: &DlpListFlags,
    sort: &[String],
    include_predefined: bool,
    keywords: bool,
) -> Result<ListParams, CliError> {
    use crate::redteam::{LimitText, max, offset, positive};
    // An explicit `--limit` wins over `--size`, and `--offset` over `--page` (TS).
    let limit = flags
        .limit
        .as_deref()
        .or(flags.size.as_deref())
        .map(|value| positive("--limit", value, LimitText::Contract))
        .transpose()?;
    let explicit_offset = flags.offset.as_deref().map(offset).transpose()?;
    let page = match (&flags.offset, flags.page.as_deref()) {
        (None, Some(value)) => Some(offset(value)?),
        _ => None,
    };
    let max = flags
        .max
        .as_deref()
        .map(max)
        .transpose()?
        .unwrap_or(crate::pagination::DEFAULT_MAX);
    if flags.all && (flags.offset.is_some() || flags.page.is_some()) {
        return Err(CliError::usage("--all cannot be combined with --offset"));
    }
    if sort.len() > MAX_SORT_VALUES {
        return Err(CliError::usage(format!(
            "--sort accepts at most {MAX_SORT_VALUES} values"
        )));
    }
    if sort.iter().any(|value| {
        value.is_empty() || value.len() > MAX_SORT_BYTES || value.chars().any(char::is_control)
    }) {
        return Err(CliError::usage(
            "--sort values must be 1-1024 bytes with no control characters",
        ));
    }
    let sort = if sort.is_empty() {
        vec![DEFAULT_SORT.to_owned()]
    } else {
        sort.to_vec()
    };
    Ok(ListParams {
        limit,
        offset: explicit_offset,
        page,
        all: flags.all,
        max,
        sort,
        include_predefined,
        keywords,
    })
}

impl ListParams {
    /// Whether the listing is the custom-only view sliced locally from every page (D170),
    /// rather than the server's pages.
    pub fn client_sliced(&self, kind: Kind) -> bool {
        kind.hides_predefined() && !self.include_predefined
    }

    /// The `page` and `size` of a single server page (TS `resolvePageParams`): `--offset`
    /// rounds down with `--limit` (else 50, and then `size=50` is sent too, D170);
    /// `--page` passes through; `size` is `--limit`.
    pub fn server_page(&self) -> (Option<u64>, Option<u32>) {
        match self.offset {
            Some(offset) => {
                let size = self.limit.unwrap_or(FALLBACK_PAGE_SIZE);
                (Some(offset / u64::from(size)), Some(size))
            }
            None => (self.page, self.limit),
        }
    }

    /// The first row of a client slice: `--offset`, else `--page` × (`--limit` or 50).
    pub fn slice_offset(&self) -> u64 {
        match (self.offset, self.page) {
            (Some(offset), _) => offset,
            (None, Some(page)) => {
                page.saturating_mul(u64::from(self.limit.unwrap_or(FALLBACK_PAGE_SIZE)))
            }
            (None, None) => 0,
        }
    }
}

/// Whether a record is predefined (PANW-shipped): its `type` is `predefined`.
pub fn is_predefined(row: &OValue) -> bool {
    row.get("type").and_then(OValue::as_str) == Some("predefined")
}

/// The `type` values of records airs may write: the tenant-created vocabulary of
/// the SDK enums (`None`: the filtering profiles' free-string `type`, where only
/// `predefined` is refused).
fn writable_types(kind: Kind) -> Option<&'static [&'static str]> {
    match kind {
        Kind::Pattern => Some(&["custom", "file_property"]),
        Kind::Profile | Kind::Dictionary => Some(&["custom"]),
        Kind::FilteringProfile => None,
    }
}

/// The predefined guard (D166): the record read before a replace, patch or delete must
/// carry the argument's `id`, must not be predefined (nor carry a `type` outside the
/// tenant-created vocabulary of its SDK enum, which the tolerant response mode keeps,
/// D178) and must not be managed by a parent tenant (exit 1, nothing written).
pub fn guard(kind: Kind, id: &str, record: &OValue) -> Result<(), CliError> {
    let resource = kind.resource();
    if record.get("id").and_then(OValue::as_str) != Some(id) {
        return Err(CliError::operational(format!(
            "The service returned a different {resource} for {id}; nothing was changed"
        )));
    }
    if is_predefined(record) {
        return Err(CliError::operational(format!(
            "{id} is a predefined {resource}; airs never modifies or deletes predefined resources"
        )));
    }
    let unfamiliar = match (record.get("type"), writable_types(kind)) {
        (Some(OValue::String(kind)), Some(known)) => !known.contains(&kind.as_str()),
        (None | Some(OValue::Null), _) | (_, None) => false,
        (Some(_), Some(_)) => true,
    };
    if unfamiliar {
        return Err(CliError::operational(format!(
            "{id} has a {resource} type airs does not recognise; it modifies or deletes only tenant-created resources"
        )));
    }
    if matches!(record.get("is_parent_managed"), Some(OValue::Bool(true))) {
        return Err(CliError::operational(format!(
            "{id} is managed by a parent tenant; airs never modifies or deletes it here"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage<T: std::fmt::Debug>(result: Result<T, CliError>) -> String {
        match result {
            Err(CliError::Usage(message)) => message,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    fn flags(edit: impl FnOnce(&mut DlpListFlags)) -> DlpListFlags {
        let mut flags = DlpListFlags::default();
        edit(&mut flags);
        flags
    }

    fn params(edit: impl FnOnce(&mut DlpListFlags)) -> Result<ListParams, CliError> {
        list_params(&flags(edit), &[], false, false)
    }

    #[test]
    fn ids_follow_the_segment_rule_with_the_resource_word() {
        assert!(check_id(Kind::Pattern, "p-cus-1").is_ok());
        assert!(check_id(Kind::Pattern, "a/b?c").is_ok());
        assert!(check_id(Kind::Profile, "11995031").is_ok());
        for (kind, word) in [
            (Kind::FilteringProfile, "filtering profile"),
            (Kind::Pattern, "data pattern"),
            (Kind::Profile, "data profile"),
            (Kind::Dictionary, "dictionary"),
        ] {
            for bad in ["", ".", "..", "a/..", "%2e%2e", "a\\b", "tab\tx"] {
                assert_eq!(
                    usage(check_id(kind, bad)),
                    format!("Invalid {word} id: {bad}"),
                    "{bad:?}"
                );
            }
        }
    }

    #[test]
    fn list_flags_are_checked_in_order_with_the_contract_texts() {
        for bad in ["0", "-1", "1.5", "abc", "", "4294967296"] {
            assert_eq!(
                usage(params(|f| f.limit = Some(bad.into()))),
                "--limit must be a positive integer",
                "{bad}"
            );
            assert_eq!(
                usage(params(|f| f.size = Some(bad.into()))),
                "--limit must be a positive integer",
                "--size {bad}"
            );
        }
        for bad in ["-5", "1.5", "abc", "9007199254740992"] {
            assert_eq!(
                usage(params(|f| f.offset = Some(bad.into()))),
                "--offset must be a non-negative integer"
            );
            assert_eq!(
                usage(params(|f| f.page = Some(bad.into()))),
                "--offset must be a non-negative integer"
            );
            assert_eq!(
                usage(params(|f| f.max = Some(bad.into()))),
                "--max must be a non-negative integer"
            );
        }
        // --max is checked without --all too (TS fails after the tenant).
        assert_eq!(
            usage(params(|f| f.max = Some("abc".into()))),
            "--max must be a non-negative integer"
        );
        for edit in [
            (|f: &mut DlpListFlags| {
                f.all = true;
                f.offset = Some("0".into());
            }) as fn(&mut DlpListFlags),
            |f| {
                f.all = true;
                f.page = Some("1".into());
            },
        ] {
            assert_eq!(
                usage(params(edit)),
                "--all cannot be combined with --offset"
            );
        }
        // The limit comes first.
        assert_eq!(
            usage(params(|f| {
                f.limit = Some("0".into());
                f.offset = Some("x".into());
            })),
            "--limit must be a positive integer"
        );
    }

    #[test]
    fn sort_values_are_bounded_and_default_to_name() {
        let ok = list_params(
            &DlpListFlags::default(),
            &["id,desc".to_owned(), "name".to_owned()],
            false,
            false,
        )
        .unwrap();
        assert_eq!(ok.sort, ["id,desc", "name"]);
        assert_eq!(params(|_| {}).unwrap().sort, [DEFAULT_SORT]);
        let many = vec!["name".to_owned(); 129];
        assert_eq!(
            usage(list_params(&DlpListFlags::default(), &many, false, false)),
            "--sort accepts at most 128 values"
        );
        for bad in [String::new(), "a\nb".to_owned(), "x".repeat(1025)] {
            assert_eq!(
                usage(list_params(&DlpListFlags::default(), &[bad], false, false)),
                "--sort values must be 1-1024 bytes with no control characters"
            );
        }
        assert!(list_params(&DlpListFlags::default(), &["x".repeat(1024)], false, false).is_ok());
    }

    #[test]
    fn aliases_yield_to_the_canonical_flags() {
        let p = params(|f| {
            f.limit = Some("5".into());
            f.size = Some("abc".into());
        })
        .unwrap();
        assert_eq!(p.limit, Some(5), "an explicit --limit wins over --size");
        let p = params(|f| f.size = Some("7".into())).unwrap();
        assert_eq!(p.limit, Some(7));
        let p = params(|f| {
            f.offset = Some("10".into());
            f.page = Some("abc".into());
        })
        .unwrap();
        assert_eq!((p.offset, p.page), (Some(10), None));
        assert_eq!(
            deprecation_warnings(&flags(|f| {
                f.size = Some("1".into());
                f.page = Some("1".into());
            })),
            [SIZE_DEPRECATED, PAGE_DEPRECATED]
        );
        assert!(deprecation_warnings(&DlpListFlags::default()).is_empty());
    }

    #[test]
    fn server_pages_and_slices() {
        let p = |edit: fn(&mut DlpListFlags)| params(edit).unwrap();
        assert_eq!(p(|_| {}).server_page(), (None, None));
        assert_eq!(
            p(|f| f.limit = Some("5".into())).server_page(),
            (None, Some(5))
        );
        assert_eq!(
            p(|f| {
                f.limit = Some("5".into());
                f.offset = Some("12".into());
            })
            .server_page(),
            (Some(2), Some(5))
        );
        // --offset without --limit rounds with 50 and sends size=50 (D170).
        assert_eq!(
            p(|f| f.offset = Some("120".into())).server_page(),
            (Some(2), Some(50))
        );
        assert_eq!(
            p(|f| f.page = Some("3".into())).server_page(),
            (Some(3), None)
        );
        assert_eq!(p(|f| f.offset = Some("7".into())).slice_offset(), 7);
        assert_eq!(p(|f| f.page = Some("2".into())).slice_offset(), 100);
        assert_eq!(
            p(|f| {
                f.page = Some("2".into());
                f.limit = Some("3".into());
            })
            .slice_offset(),
            6
        );
        let visible = p(|_| {});
        assert!(visible.client_sliced(Kind::Pattern));
        assert!(!visible.client_sliced(Kind::FilteringProfile));
        let mut all = visible;
        all.include_predefined = true;
        assert!(!all.client_sliced(Kind::Dictionary));
    }

    /// D166: the guard refuses mismatched ids, predefined, unfamiliar-type and
    /// parent-managed records; it accepts the tenant-created vocabulary and a missing type.
    #[test]
    fn the_guard_refuses_what_is_not_tenant_created() {
        let record = |text: &str| crate::json::parse(text).unwrap();
        let message = |kind: Kind, text: &str| match guard(kind, "x", &record(text)) {
            Ok(()) => String::new(),
            Err(CliError::Operational(failure)) => failure.message,
            Err(other) => panic!("{other:?}"),
        };
        for (kind, text) in [
            (Kind::Pattern, r#"{"id":"x","type":"custom"}"#),
            (
                Kind::Pattern,
                r#"{"id":"x","type":"file_property","is_parent_managed":false}"#,
            ),
            (Kind::Profile, r#"{"id":"x","type":"custom"}"#),
            (Kind::Dictionary, r#"{"id":"x"}"#),
            (Kind::Dictionary, r#"{"id":"x","type":null}"#),
            (Kind::FilteringProfile, r#"{"id":"x","type":"anything"}"#),
        ] {
            assert_eq!(message(kind, text), "", "{text}");
        }
        assert_eq!(
            message(Kind::Pattern, r#"{"id":"y","type":"custom"}"#),
            "The service returned a different data pattern for x; nothing was changed"
        );
        assert_eq!(
            message(Kind::Pattern, r#"{"type":"custom"}"#),
            "The service returned a different data pattern for x; nothing was changed"
        );
        assert_eq!(
            message(Kind::FilteringProfile, r#"{"id":"x","type":"predefined"}"#),
            "x is a predefined filtering profile; airs never modifies or deletes predefined resources"
        );
        for (kind, text) in [
            (Kind::Profile, r#"{"id":"x","type":"shared"}"#),
            (Kind::Dictionary, r#"{"id":"x","type":"file_property"}"#),
            (Kind::Pattern, r#"{"id":"x","type":5}"#),
        ] {
            assert!(
                message(kind, text).ends_with(
                    "type airs does not recognise; it modifies or deletes only tenant-created resources"
                ),
                "{text}"
            );
        }
        assert_eq!(
            message(
                Kind::Dictionary,
                r#"{"id":"x","type":"custom","is_parent_managed":true}"#
            ),
            "x is managed by a parent tenant; airs never modifies or deletes it here"
        );
    }

    /// TS `dlp-visibility.spec.ts`: only `type: predefined` is hidden.
    #[test]
    fn only_predefined_records_are_hidden() {
        let rows =
            crate::json::parse(r#"[{"type":"custom"},{"type":"predefined"},{"type":null},{}]"#)
                .unwrap();
        let visible: Vec<&OValue> = rows
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| !is_predefined(row))
            .collect();
        assert_eq!(visible.len(), 3);
    }
}
