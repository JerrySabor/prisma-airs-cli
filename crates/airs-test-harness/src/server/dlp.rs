//! The DLP fixture routes (DESIGN §10 M6b): the four collections under
//! `/dlp/v2/api/` (the fixture tenant's `dlpEndpoint` is `<base>/dlp`), bearer-checked
//! like management, over a per-server dataset ([`DlpData`]).
//!
//! Lists are Spring pages: `page` (default 0), `size` (default 20, capped per collection
//! by [`DlpData::size_caps`]), repeated `sort` (`<field>[,asc|desc]`, applied to string
//! fields) and, for dictionaries, `keywords=true` (keywords are served only then). The
//! page metadata follows [`PageStyle`]. The writes of step 2 (`super::dlp_writes`) change
//! the dataset, so a later read sees them; `DELETE …/data-profiles/<id>` is a trap that
//! answers 501 (the live API has no profile DELETE, G11). Any other method under `/dlp` is
//! an unknown route.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::plan::Planned;
use super::record::{AuthIdentity, RecordedRequest};
use crate::fixtures::dlp as fx;

/// Path prefix of the DLP API (`dlpEndpoint = <base>/dlp`).
pub const PREFIX: &str = "/dlp/v2/api/";

/// A DLP collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Collection {
    FilteringProfiles,
    Patterns,
    Profiles,
    Dictionaries,
}

impl Collection {
    /// The path segment.
    pub fn segment(self) -> &'static str {
        match self {
            Self::FilteringProfiles => "data-filtering-profiles",
            Self::Patterns => "data-patterns",
            Self::Profiles => "data-profiles",
            Self::Dictionaries => "dictionaries",
        }
    }

    fn of(segment: &str) -> Option<Self> {
        [
            Self::FilteringProfiles,
            Self::Patterns,
            Self::Profiles,
            Self::Dictionaries,
        ]
        .into_iter()
        .find(|collection| collection.segment() == segment)
    }
}

/// A DLP fixture route (`Route::Dlp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dl {
    /// `GET /dlp/v2/api/<collection>`.
    List(Collection),
    /// `GET /dlp/v2/api/<collection>/{id}`.
    Get(Collection),
    /// `POST /dlp/v2/api/<collection>` (patterns, profiles, dictionaries).
    Create(Collection),
    /// `PUT /dlp/v2/api/<collection>/{id}` (every collection).
    Replace(Collection),
    /// `PATCH /dlp/v2/api/<collection>/{id}` (patterns, profiles, dictionaries).
    Patch(Collection),
    /// `DELETE /dlp/v2/api/<collection>/{id}` (patterns, dictionaries; on profiles the
    /// 501 trap).
    Delete(Collection),
}

impl Dl {
    /// A short stable label (`dlp-data-patterns-list`, ...).
    pub fn label(self) -> &'static str {
        match self {
            Dl::Create(Collection::FilteringProfiles) => "dlp-data-filtering-profiles-create",
            Dl::Create(Collection::Patterns) => "dlp-data-patterns-create",
            Dl::Create(Collection::Profiles) => "dlp-data-profiles-create",
            Dl::Create(Collection::Dictionaries) => "dlp-dictionaries-create",
            Dl::Replace(Collection::FilteringProfiles) => "dlp-data-filtering-profiles-replace",
            Dl::Replace(Collection::Patterns) => "dlp-data-patterns-replace",
            Dl::Replace(Collection::Profiles) => "dlp-data-profiles-replace",
            Dl::Replace(Collection::Dictionaries) => "dlp-dictionaries-replace",
            Dl::Patch(Collection::FilteringProfiles) => "dlp-data-filtering-profiles-patch",
            Dl::Patch(Collection::Patterns) => "dlp-data-patterns-patch",
            Dl::Patch(Collection::Profiles) => "dlp-data-profiles-patch",
            Dl::Patch(Collection::Dictionaries) => "dlp-dictionaries-patch",
            Dl::Delete(Collection::FilteringProfiles) => "dlp-data-filtering-profiles-delete",
            Dl::Delete(Collection::Patterns) => "dlp-data-patterns-delete",
            Dl::Delete(Collection::Profiles) => "dlp-data-profiles-delete",
            Dl::Delete(Collection::Dictionaries) => "dlp-dictionaries-delete",
            Dl::List(Collection::FilteringProfiles) => "dlp-data-filtering-profiles-list",
            Dl::List(Collection::Patterns) => "dlp-data-patterns-list",
            Dl::List(Collection::Profiles) => "dlp-data-profiles-list",
            Dl::List(Collection::Dictionaries) => "dlp-dictionaries-list",
            Dl::Get(Collection::FilteringProfiles) => "dlp-data-filtering-profiles-get",
            Dl::Get(Collection::Patterns) => "dlp-data-patterns-get",
            Dl::Get(Collection::Profiles) => "dlp-data-profiles-get",
            Dl::Get(Collection::Dictionaries) => "dlp-dictionaries-get",
        }
    }

    /// Whether the route is a write (every non-GET DLP request, D160).
    pub fn is_write(self) -> bool {
        !matches!(self, Dl::List(_) | Dl::Get(_))
    }

    /// Whether the route is a trap no airs-cli-rs command may send (the profile DELETE
    /// the API does not have, G11).
    pub fn is_trap(self) -> bool {
        self == Dl::Delete(Collection::Profiles)
    }

    /// Classifies a request path under `/dlp/v2/api/`; `None` for anything else.
    pub fn classify(method: &str, path: &str) -> Option<Dl> {
        let rest = path.strip_prefix(PREFIX)?;
        let segments: Vec<&str> = rest.split('/').collect();
        let collection = Collection::of(segments.first()?)?;
        let item = segments.len() == 2 && !segments[1].is_empty();
        let top = segments.len() == 1;
        match method {
            "GET" if top => Some(Dl::List(collection)),
            "GET" if item => Some(Dl::Get(collection)),
            "POST" if top && collection != Collection::FilteringProfiles => {
                Some(Dl::Create(collection))
            }
            "PUT" if item => Some(Dl::Replace(collection)),
            "PATCH" if item && collection != Collection::FilteringProfiles => {
                Some(Dl::Patch(collection))
            }
            "DELETE" if item && collection != Collection::FilteringProfiles => {
                Some(Dl::Delete(collection))
            }
            _ => None,
        }
    }
}

/// The page metadata a collection's lists report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PageStyle {
    /// The Spring camelCase envelope (`totalElements`, `pageable.pageNumber`, `last`, …).
    #[default]
    Camel,
    /// The dictionaries' live snake_case metadata (`total_elements`,
    /// `pageable.page_size`, …), without `last`.
    Snake,
    /// camelCase without `last`.
    NoLast,
    /// `content` only.
    Bare,
}

/// The DLP dataset of one fixture server. Tests seed it with [`DlpData::seeded`]
/// (through `FixtureServer::seed_dlp`) and edit its public fields (`FixtureServer::dlp`).
#[derive(Clone, Debug, Default)]
pub struct DlpData {
    pub filtering_profiles: Vec<Value>,
    pub patterns: Vec<Value>,
    pub profiles: Vec<Value>,
    /// Full records, keywords included (served only with `keywords=true`).
    pub dictionaries: Vec<Value>,
    /// The page style per collection (default camelCase).
    pub styles: BTreeMap<Collection, PageStyle>,
    /// The largest page a collection serves (a larger `size` is capped, the live
    /// dictionaries cap 100 at 50).
    pub size_caps: BTreeMap<Collection, u64>,
    /// Serve page 0 for every `page` (a service that ignores paging repeats rows).
    pub ignore_page: bool,
    /// Report this many more `totalPages` than exist (an empty intermediate page).
    pub extra_pages: u64,
    /// `PUT …/dictionaries/<id>` answers `204` with no body (the live region that does
    /// not echo the new state).
    pub dictionary_replace_empty: bool,
    /// Profile names a create answers `409` for (a deleted profile keeps its name, G11).
    pub reserved_profile_names: Vec<String>,
    /// Records the write routes created so far (ids `p-new-<n>`, `dp-new-<n>`,
    /// `d-new-<n>`).
    pub created: u64,
    /// The DLP `tenant_id` of created patterns and profiles (default
    /// [`crate::fixtures::dlp::TENANT_ID`]; a restore destination of another tenant sets
    /// its own).
    pub created_tenant_id: Option<String>,
}

impl DlpData {
    /// The standard dataset (`fixtures::dlp`): two filtering profiles, five patterns, four
    /// profiles and two dictionaries; dictionaries page in the live snake_case style with
    /// a size cap of 50.
    pub fn seeded() -> Self {
        Self {
            filtering_profiles: fx::filtering_profiles(),
            patterns: fx::patterns(),
            profiles: fx::profiles(),
            dictionaries: fx::dictionaries(),
            styles: BTreeMap::from([(Collection::Dictionaries, PageStyle::Snake)]),
            size_caps: BTreeMap::from([(Collection::Dictionaries, 50)]),
            ignore_page: false,
            extra_pages: 0,
            dictionary_replace_empty: false,
            reserved_profile_names: Vec::new(),
            created: 0,
            created_tenant_id: None,
        }
    }

    /// The records of `collection`.
    pub fn records(&self, collection: Collection) -> &Vec<Value> {
        match collection {
            Collection::FilteringProfiles => &self.filtering_profiles,
            Collection::Patterns => &self.patterns,
            Collection::Profiles => &self.profiles,
            Collection::Dictionaries => &self.dictionaries,
        }
    }

    /// The records of `collection`, mutably.
    pub fn records_mut(&mut self, collection: Collection) -> &mut Vec<Value> {
        match collection {
            Collection::FilteringProfiles => &mut self.filtering_profiles,
            Collection::Patterns => &mut self.patterns,
            Collection::Profiles => &mut self.profiles,
            Collection::Dictionaries => &mut self.dictionaries,
        }
    }
}

/// The percent-decoded id segment of an item path.
pub(crate) fn id_of(path: &str) -> String {
    let id = path.rsplit('/').next().unwrap_or_default();
    super::redteam::percent_decode(id)
}

/// A dictionary as served: without `keywords` unless they were asked for.
pub(crate) fn served(collection: Collection, record: &Value, keywords: bool) -> Value {
    let mut record = record.clone();
    if collection == Collection::Dictionaries
        && !keywords
        && let Value::Object(map) = &mut record
    {
        map.remove("keywords");
    }
    record
}

/// The answer of a DLP route (credentials already checked by the caller).
pub(crate) fn answer(data: &mut DlpData, route: Dl, request: &RecordedRequest) -> Planned {
    if request.header("x-pan-token").is_some() {
        return Planned::empty_json(403);
    }
    let AuthIdentity::Bearer { tsg: Some(_) } = &request.auth else {
        return Planned::empty_json(401);
    };
    let keywords = request.query_value("keywords") == Some("true");
    match route {
        Dl::Get(collection) => {
            let id = id_of(&request.path);
            match data
                .records(collection)
                .iter()
                .find(|record| record.get("id").and_then(Value::as_str) == Some(id.as_str()))
            {
                Some(record) => Planned::json(200, &served(collection, record, keywords)),
                None => Planned::json(
                    404,
                    &json!({"title": "Not Found", "status": 404, "detail": "Resource not found"}),
                ),
            }
        }
        Dl::List(collection) => list(data, collection, request, keywords),
        write => super::dlp_writes::answer(data, write, request, keywords),
    }
}

fn list(
    data: &DlpData,
    collection: Collection,
    request: &RecordedRequest,
    keywords: bool,
) -> Planned {
    let number = |name: &str, default: u64| match request.query_value(name) {
        None => Some(default),
        Some(value) => value.parse::<u64>().ok(),
    };
    let (Some(page), Some(size)) = (number("page", 0), number("size", 20)) else {
        return Planned::json(400, &json!({"title": "Bad Request", "status": 400}));
    };
    if size == 0 {
        return Planned::json(400, &json!({"title": "Bad Request", "status": 400}));
    }
    let size = data
        .size_caps
        .get(&collection)
        .map_or(size, |cap| size.min(*cap));
    let page = if data.ignore_page { 0 } else { page };
    let mut rows: Vec<Value> = data
        .records(collection)
        .iter()
        .map(|record| served(collection, record, keywords))
        .collect();
    for sort in request
        .query
        .iter()
        .filter(|(name, _)| name == "sort")
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let (field, direction) = sort.split_once(',').unwrap_or((sort, "asc"));
        let key = |row: &Value| row.get(field).and_then(Value::as_str).map(str::to_owned);
        rows.sort_by(|a, b| {
            let order = key(a).cmp(&key(b));
            if direction.eq_ignore_ascii_case("desc") {
                order.reverse()
            } else {
                order
            }
        });
    }
    let total = rows.len() as u64;
    let total_pages = total.div_ceil(size) + data.extra_pages;
    let start = usize::try_from(page.saturating_mul(size))
        .unwrap_or(usize::MAX)
        .min(rows.len());
    let end = usize::try_from(page.saturating_mul(size).saturating_add(size))
        .unwrap_or(usize::MAX)
        .min(rows.len());
    let content: Vec<Value> = rows[start..end].to_vec();
    let returned = content.len() as u64;
    let last = page + 1 >= total_pages;
    let style = data.styles.get(&collection).copied().unwrap_or_default();
    let mut body = Map::new();
    body.insert("content".to_owned(), Value::Array(content));
    match style {
        PageStyle::Camel | PageStyle::NoLast => {
            body.insert(
                "pageable".to_owned(),
                json!({"pageNumber": page, "pageSize": size, "offset": page * size, "paged": true, "unpaged": false}),
            );
            if style == PageStyle::Camel {
                body.insert("last".to_owned(), json!(last));
            }
            body.insert("totalElements".to_owned(), json!(total));
            body.insert("totalPages".to_owned(), json!(total_pages));
            body.insert("size".to_owned(), json!(size));
            body.insert("number".to_owned(), json!(page));
            body.insert("first".to_owned(), json!(page == 0));
            body.insert("numberOfElements".to_owned(), json!(returned));
            body.insert("empty".to_owned(), json!(returned == 0));
        }
        PageStyle::Snake => {
            body.insert(
                "pageable".to_owned(),
                json!({"page_number": page, "page_size": size, "offset": page * size}),
            );
            body.insert("total_elements".to_owned(), json!(total));
            body.insert("total_pages".to_owned(), json!(total_pages));
            body.insert("number_of_elements".to_owned(), json!(returned));
            body.insert("size".to_owned(), json!(size));
            body.insert("number".to_owned(), json!(page));
            body.insert("first".to_owned(), json!(page == 0));
            body.insert("empty".to_owned(), json!(returned == 0));
        }
        PageStyle::Bare => {}
    }
    Planned::json(200, &Value::Object(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_read_and_write_routes() {
        for (method, path, route) in [
            (
                "GET",
                "/dlp/v2/api/data-patterns",
                Some(Dl::List(Collection::Patterns)),
            ),
            (
                "GET",
                "/dlp/v2/api/data-patterns/p-1",
                Some(Dl::Get(Collection::Patterns)),
            ),
            (
                "GET",
                "/dlp/v2/api/dictionaries/a%2Fb",
                Some(Dl::Get(Collection::Dictionaries)),
            ),
            (
                "GET",
                "/dlp/v2/api/data-filtering-profiles",
                Some(Dl::List(Collection::FilteringProfiles)),
            ),
            (
                "GET",
                "/dlp/v2/api/data-profiles/x",
                Some(Dl::Get(Collection::Profiles)),
            ),
            ("GET", "/dlp/v2/api/data-patterns/", None),
            ("GET", "/dlp/v2/api/", None),
            ("GET", "/dlp/v2/api/other", None),
            (
                "POST",
                "/dlp/v2/api/data-patterns",
                Some(Dl::Create(Collection::Patterns)),
            ),
            (
                "DELETE",
                "/dlp/v2/api/data-profiles/x",
                Some(Dl::Delete(Collection::Profiles)),
            ),
            (
                "PUT",
                "/dlp/v2/api/data-filtering-profiles/fp-1",
                Some(Dl::Replace(Collection::FilteringProfiles)),
            ),
            (
                "PATCH",
                "/dlp/v2/api/dictionaries/d-1",
                Some(Dl::Patch(Collection::Dictionaries)),
            ),
            ("POST", "/dlp/v2/api/data-filtering-profiles", None),
            ("PATCH", "/dlp/v2/api/data-filtering-profiles/fp-1", None),
            ("DELETE", "/dlp/v2/api/data-filtering-profiles/fp-1", None),
            ("PUT", "/dlp/v2/api/data-patterns", None),
            ("DELETE", "/dlp/v2/api/data-patterns/", None),
            ("GET", "/dlp/v2/api/data-patterns/a/b", None),
        ] {
            assert_eq!(Dl::classify(method, path), route, "{method} {path}");
        }
    }
}
