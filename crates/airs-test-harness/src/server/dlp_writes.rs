//! The DLP write routes (DESIGN §10 M6b, step 2): every non-GET DLP request, answered
//! over the per-server [`DlpData`] so a later read sees the change.
//!
//! - patterns: `POST` creates `p-new-<n>` (`status: active`, `version: 1`, the
//!   `supported_confidence_levels` expanded to `high`, `medium`, `low` as the live
//!   service does), `PUT` replaces
//!   the request fields, `PATCH` (`application/merge-patch+json` required, else 415)
//!   applies RFC 7386, `DELETE` archives (`status: deleted`, 204);
//! - profiles: `POST` creates `dp-new-<n>` (a name over 32 UTF-16 units answers 400, a
//!   [`DlpData::reserved_profile_names`] name 409), `PUT` and `PATCH` as patterns;
//!   `DELETE` is the 501 trap;
//! - dictionaries: `POST` and `PUT` take the multipart upload ([`multipart`]): a `json`
//!   part with the metadata and a `file` part whose non-empty lines become the keywords
//!   (a `.csv` file's first line is its header, which the live service consumes);
//!   `PUT` answers 204 without a body under [`DlpData::dictionary_replace_empty`];
//!   `PATCH` as patterns; `DELETE` removes the record (204);
//! - filtering profiles: `PUT` replaces the request fields.
//!
//! Every write bumps `version`. A missing record answers the 404 problem; a malformed
//! body the 400 problem.

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::dlp::{Collection, Dl, DlpData, id_of, served};
use super::plan::Planned;
use super::record::RecordedRequest;
use crate::fixtures::dlp as fx;

/// One part of a multipart upload, as the fixture records it: never the file bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// The `name` of its `Content-Disposition`.
    pub name: String,
    /// Its `filename`, when given.
    pub filename: Option<String>,
    /// Its `Content-Type`, when given.
    pub content_type: Option<String>,
    /// The part body parsed as JSON, when it is JSON.
    pub json: Option<Value>,
    /// The body length in bytes.
    pub len: usize,
    /// The lowercase hex SHA-256 of the body.
    pub sha256: String,
}

/// A parsed `multipart/form-data` body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Multipart {
    pub parts: Vec<Part>,
}

impl Multipart {
    /// The part named `name`.
    pub fn part(&self, name: &str) -> Option<&Part> {
        self.parts.iter().find(|part| part.name == name)
    }
}

/// The hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The parts of a `multipart/form-data` request and the raw body of each (`None` for
/// any other request or a malformed body).
fn parse_parts(request: &RecordedRequest) -> Option<Vec<(Part, Vec<u8>)>> {
    let content_type = request.header("content-type")?;
    if !content_type.starts_with("multipart/form-data") {
        return None;
    }
    let boundary = content_type
        .split(';')
        .map(str::trim)
        .find_map(|param| param.strip_prefix("boundary="))?
        .trim_matches('"');
    let delimiter = format!("--{boundary}");
    let body = &request.body;
    let mut parts = Vec::new();
    let mut rest: &[u8] = body;
    let start = find(rest, delimiter.as_bytes())?;
    rest = &rest[start + delimiter.len()..];
    loop {
        if rest.starts_with(b"--") {
            return Some(parts);
        }
        rest = rest.strip_prefix(b"\r\n")?;
        let headers_end = find(rest, b"\r\n\r\n")?;
        let headers = std::str::from_utf8(&rest[..headers_end]).ok()?;
        rest = &rest[headers_end + 4..];
        let end = find(rest, format!("\r\n{delimiter}").as_bytes())?;
        let content = rest[..end].to_vec();
        rest = &rest[end + 2 + delimiter.len()..];
        let mut name = None;
        let mut filename = None;
        let mut part_type = None;
        for line in headers.split("\r\n") {
            let (key, value) = line.split_once(':')?;
            if key.eq_ignore_ascii_case("content-disposition") {
                for param in value.split(';').map(str::trim) {
                    if let Some(found) = param.strip_prefix("name=") {
                        name = Some(found.trim_matches('"').to_owned());
                    } else if let Some(found) = param.strip_prefix("filename=") {
                        filename = Some(found.trim_matches('"').to_owned());
                    }
                }
            } else if key.eq_ignore_ascii_case("content-type") {
                part_type = Some(value.trim().to_owned());
            }
        }
        let part = Part {
            name: name?,
            filename,
            content_type: part_type,
            json: serde_json::from_slice(&content).ok(),
            len: content.len(),
            sha256: sha256_hex(&content),
        };
        parts.push((part, content));
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The parts of a recorded multipart upload (names, filenames, content types, the parsed
/// JSON, the length and hash of each body); `None` for any other request.
pub fn multipart(request: &RecordedRequest) -> Option<Multipart> {
    parse_parts(request).map(|parts| Multipart {
        parts: parts.into_iter().map(|(part, _)| part).collect(),
    })
}

fn bad_request() -> Planned {
    Planned::json(400, &json!({"title": "Bad Request", "status": 400}))
}

fn not_found() -> Planned {
    Planned::json(
        404,
        &json!({"title": "Not Found", "status": 404, "detail": "Resource not found"}),
    )
}

/// RFC 7386: `patch` merged into `target`.
pub fn merge_patch(target: &mut Value, patch: &Value) {
    match patch {
        Value::Object(entries) => {
            if !target.is_object() {
                *target = Value::Object(Map::new());
            }
            if let Value::Object(map) = target {
                for (key, value) in entries {
                    if value.is_null() {
                        map.remove(key);
                    } else {
                        merge_patch(map.entry(key.clone()).or_insert(Value::Null), value);
                    }
                }
            }
        }
        other => *target = other.clone(),
    }
}

fn audit() -> Value {
    json!({"created_by": "someone@example.com", "updated_at": fx::UPDATED_MS})
}

fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

/// The keys a write never takes from a body (the service owns them).
const OWNED: [&str; 5] = [
    "id",
    "tenant_id",
    "version",
    "audit_metadata",
    "is_parent_managed",
];

fn position(rows: &[Value], id: &str) -> Option<usize> {
    rows.iter()
        .position(|row| row.get("id").and_then(Value::as_str) == Some(id))
}

fn bump(record: &mut Value) {
    let version = record.get("version").and_then(Value::as_u64).unwrap_or(0);
    record["version"] = json!(version + 1);
}

/// `fields` of a body copied over `record` (the service-owned keys left alone).
fn overlay(record: &mut Value, fields: &Map<String, Value>) {
    if let Value::Object(map) = record {
        for (key, value) in fields {
            if !OWNED.contains(&key.as_str()) {
                map.insert(key.clone(), value.clone());
            }
        }
    }
}

/// A full replacement: every request field of `record` that the body omits is dropped
/// (the identity keys, `type` and `status` kept), then the body's fields applied.
fn replace(record: &mut Value, fields: &Map<String, Value>, keep: &[&str]) {
    if let Value::Object(map) = record {
        map.retain(|key, _| OWNED.contains(&key.as_str()) || keep.contains(&key.as_str()));
    }
    overlay(record, fields);
    bump(record);
}

pub(crate) fn answer(
    data: &mut DlpData,
    route: Dl,
    request: &RecordedRequest,
    keywords: bool,
) -> Planned {
    match route {
        Dl::Delete(Collection::Profiles) => {
            Planned::json(501, &json!({"title": "Not Implemented", "status": 501}))
        }
        Dl::Create(Collection::Dictionaries) | Dl::Replace(Collection::Dictionaries) => {
            upload(data, route, request, keywords)
        }
        Dl::Create(collection) => {
            let Some(body) = request.body_json() else {
                return bad_request();
            };
            create(data, collection, &body)
        }
        Dl::Replace(collection) => {
            let Some(body) = request.body_json() else {
                return bad_request();
            };
            let Some(fields) = object(&body) else {
                return bad_request();
            };
            let id = id_of(&request.path);
            let keep: &[&str] = match collection {
                Collection::FilteringProfiles => &["name", "type"],
                Collection::Patterns => &["status", "license_type"],
                Collection::Profiles => &["type", "profile_status", "profile_type"],
                Collection::Dictionaries => &[],
            };
            let rows = data.records_mut(collection);
            let Some(index) = position(rows, &id) else {
                return not_found();
            };
            replace(&mut rows[index], fields, keep);
            Planned::json(200, &rows[index])
        }
        Dl::Patch(collection) => {
            let merge = request
                .header("content-type")
                .is_some_and(|value| value.starts_with("application/merge-patch+json"));
            if !merge {
                return Planned::json(
                    415,
                    &json!({"title": "Unsupported Media Type", "status": 415}),
                );
            }
            let Some(body) = request.body_json().filter(Value::is_object) else {
                return bad_request();
            };
            let id = id_of(&request.path);
            let rows = data.records_mut(collection);
            let Some(index) = position(rows, &id) else {
                return not_found();
            };
            let mut patch = body;
            if let Value::Object(map) = &mut patch {
                for key in OWNED {
                    map.remove(key);
                }
            }
            merge_patch(&mut rows[index], &patch);
            bump(&mut rows[index]);
            Planned::json(200, &served(collection, &rows[index], false))
        }
        Dl::Delete(collection) => {
            let id = id_of(&request.path);
            let rows = data.records_mut(collection);
            let Some(index) = position(rows, &id) else {
                return not_found();
            };
            if collection == Collection::Patterns {
                rows[index]["status"] = json!("deleted");
            } else {
                rows.remove(index);
            }
            Planned::status(204)
        }
        Dl::List(_) | Dl::Get(_) => not_found(),
    }
}

fn create(data: &mut DlpData, collection: Collection, body: &Value) -> Planned {
    let Some(fields) = object(body) else {
        return bad_request();
    };
    let Some(name) = fields
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
    else {
        return bad_request();
    };
    data.created += 1;
    let n = data.created;
    let tenant = data
        .created_tenant_id
        .clone()
        .unwrap_or_else(|| fx::TENANT_ID.to_owned());
    let mut record = match collection {
        Collection::Patterns => json!({
            "id": format!("p-new-{n}"),
            "name": name,
            "tenant_id": tenant,
            "type": "custom",
            "status": "active",
            "license_type": "standard",
            "is_parent_managed": false,
            "version": 1,
            "audit_metadata": audit()
        }),
        Collection::Profiles => {
            if name.encode_utf16().count() > 32 {
                data.created -= 1;
                return bad_request();
            }
            if data
                .reserved_profile_names
                .iter()
                .any(|taken| taken == name)
            {
                data.created -= 1;
                return Planned::json(409, &json!({"title": "Conflict", "status": 409}));
            }
            json!({
                "id": format!("dp-new-{n}"),
                "name": name,
                "tenant_id": tenant,
                "type": "custom",
                "profile_status": "active",
                "profile_type": "advanced",
                "is_granular_data_profile": false,
                "is_parent_managed": false,
                "version": 1,
                "audit_metadata": audit()
            })
        }
        Collection::FilteringProfiles | Collection::Dictionaries => return not_found(),
    };
    overlay(&mut record, fields);
    if collection == Collection::Patterns {
        expand_confidence(&mut record);
    }
    data.records_mut(collection).push(record.clone());
    Planned::json(201, &record)
}

/// The live service expands a created pattern's `supported_confidence_levels` to every
/// level of its technique (TB§5.5): the missing ones of `high`, `medium`, `low` are
/// appended.
fn expand_confidence(record: &mut Value) {
    if let Some(Value::Array(levels)) = record
        .get_mut("detection_config")
        .and_then(|config| config.get_mut("supported_confidence_levels"))
    {
        for level in ["high", "medium", "low"] {
            if !levels.iter().any(|known| known == level) {
                levels.push(json!(level));
            }
        }
    }
}

/// A dictionary create (`POST`) or replace (`PUT`) from its multipart upload.
fn upload(data: &mut DlpData, route: Dl, request: &RecordedRequest, keywords: bool) -> Planned {
    let Some(parts) = parse_parts(request) else {
        return bad_request();
    };
    let metadata = parts
        .iter()
        .find(|(part, _)| part.name == "json")
        .and_then(|(part, _)| part.json.clone());
    let file = parts.iter().find(|(part, _)| part.name == "file");
    let (Some(Value::Object(metadata)), Some((file_part, bytes))) = (metadata, file) else {
        return bad_request();
    };
    let original = metadata
        .get("original_file_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if original.trim().is_empty() {
        return Planned::json(
            400,
            &json!({
                "title": "Bad Request",
                "status": 400,
                "errors": [{"property": "originalFileName", "reason": "must not be blank"}]
            }),
        );
    }
    // A CSV upload's first row is a header the service consumes (TB§3, live).
    let header = usize::from(original.to_ascii_lowercase().ends_with(".csv"));
    let words: Vec<Value> = String::from_utf8_lossy(bytes)
        .lines()
        .skip(header)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| Value::String(line.to_owned()))
        .collect();
    let dictionary_metadata = json!({
        "number_of_keywords": words.len(),
        "original_file_name": original,
        "original_file_size_in_byte": file_part.len
    });
    let fields: Map<String, Value> = metadata
        .into_iter()
        .filter(|(key, _)| key != "original_file_name")
        .collect();
    let record = if let Dl::Replace(_) = route {
        let id = id_of(&request.path);
        let empty = data.dictionary_replace_empty;
        let rows = data.records_mut(Collection::Dictionaries);
        let Some(index) = position(rows, &id) else {
            return not_found();
        };
        replace(
            &mut rows[index],
            &fields,
            &["type", "status", "detection_technique"],
        );
        rows[index]["dictionary_metadata"] = dictionary_metadata;
        rows[index]["keywords"] = Value::Array(words);
        if empty {
            return Planned::status(204);
        }
        rows[index].clone()
    } else {
        data.created += 1;
        let mut record = json!({
            "id": format!("d-new-{}", data.created),
            "type": "custom",
            "is_case_sensitive": false,
            "is_parent_managed": false,
            "detection_technique": "dictionary",
            "dictionary_metadata": dictionary_metadata,
            "audit_metadata": audit(),
            "status": "active",
            "version": 1
        });
        overlay(&mut record, &fields);
        record["keywords"] = Value::Array(words);
        data.dictionaries.push(record.clone());
        record
    };
    let status = if matches!(route, Dl::Create(_)) {
        201
    } else {
        200
    };
    Planned::json(status, &served(Collection::Dictionaries, &record, keywords))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_patch_follows_rfc_7386() {
        let mut target = json!({"a": "b", "c": {"d": "e", "f": "g"}});
        merge_patch(&mut target, &json!({"a": "z", "c": {"f": null}}));
        assert_eq!(target, json!({"a": "z", "c": {"d": "e"}}));
        let mut target = json!({"a": [1]});
        merge_patch(&mut target, &json!({"a": {"b": "c"}, "n": null}));
        assert_eq!(target, json!({"a": {"b": "c"}}));
    }

    #[test]
    fn hashes_are_lowercase_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
