//! The supplychain (TypeScript `agentguard`) fixture routes (DESIGN §10 M6f, §20.13): the
//! data plane under `/agentguard/data` (scans, statistics, findings) and the management
//! plane under `/agentguard/mgmt` (the rule catalog), `GET` only, each checking the
//! `mock-token-<tsg>` bearer **and** `x-tsg-id: <tsg>`, over a per-server dataset
//! ([`SupplychainData`]) whose bodies are written in the service's member order
//! ([`crate::fixtures::supplychain::Wire`]).
//!
//! Knobs: a reported scan total other than the count, a finding total above the rows
//! (D319), an answer over 32 MiB (D320), and the dataset itself (repeated or empty ids,
//! a catalog of any size). Any other method or path under these bases is an unknown route.

use std::collections::BTreeMap;

use serde_json::json;

use super::plan::Planned;
use super::record::{AuthIdentity, RecordedRequest};
use crate::fixtures::supplychain::{self as fx, Wire};

/// A supplychain fixture route (`Route::Supplychain`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Sc {
    /// `GET <data>/v1/scans?skip=&limit=&isBackgroundRefresh=[&start_time=][&end_time=]`.
    Scans,
    /// `GET <data>/v1/stats/scans?time_period=30_DAYS`.
    Stats,
    /// `GET <data>/v1/scans/{uuid}/vulnerabilities`.
    Vulnerabilities,
    /// `GET <mgmt>/v1/rules?skip=&limit=`.
    Rules,
}

impl Sc {
    /// Every route, in declaration order.
    pub const ALL: [Sc; 4] = [Sc::Scans, Sc::Stats, Sc::Vulnerabilities, Sc::Rules];

    /// A short stable label.
    pub fn label(self) -> &'static str {
        match self {
            Sc::Scans => "sc-scans",
            Sc::Stats => "sc-stats",
            Sc::Vulnerabilities => "sc-vulnerabilities",
            Sc::Rules => "sc-rules",
        }
    }

    /// Classify a request: only `GET` on the four paths.
    pub fn classify(method: &str, path: &str) -> Option<Sc> {
        if method != "GET" {
            return None;
        }
        if let Some(rest) = path.strip_prefix(fx::DATA_PREFIX) {
            return match rest {
                "/v1/scans" => Some(Sc::Scans),
                "/v1/stats/scans" => Some(Sc::Stats),
                _ => rest
                    .strip_prefix("/v1/scans/")
                    .and_then(|rest| rest.strip_suffix("/vulnerabilities"))
                    .filter(|id| !id.is_empty() && !id.contains('/'))
                    .map(|_| Sc::Vulnerabilities),
            };
        }
        (path == format!("{}/v1/rules", fx::MGMT_PREFIX)).then_some(Sc::Rules)
    }
}

/// The supplychain dataset of one fixture server.
#[derive(Clone, Debug, Default)]
pub struct SupplychainData {
    /// The scans, in list order.
    pub scans: Vec<Wire>,
    /// The reported `total_items` of every scan page (default: the count).
    pub scan_total: Option<u64>,
    /// The statistics answer (`None`: `404`).
    pub stats: Option<Wire>,
    /// The findings per scan id (looked up ignoring case; an unknown id is `404`).
    pub findings: BTreeMap<String, Vec<Wire>>,
    /// The reported finding `total_items` (default: the rows; D319 knob).
    pub finding_total: Option<u64>,
    /// Answer every finding list with one finding whose code is 33 MiB (D320 knob).
    pub oversized_findings: bool,
    /// The rule catalog.
    pub rules: Vec<Wire>,
    /// Two passthrough members on the scan and finding `pagination` objects (seeded on).
    pub pagination_passthrough: bool,
}

impl SupplychainData {
    /// The dataset of §20.13.
    pub fn seeded() -> Self {
        Self {
            scans: fx::scans(),
            scan_total: None,
            stats: Some(fx::stats()),
            findings: BTreeMap::from([(fx::uuid(fx::SCAN_WITH_FINDINGS), fx::findings())]),
            finding_total: None,
            oversized_findings: false,
            rules: fx::rules(),
            pagination_passthrough: true,
        }
    }

    /// Every record without its passthrough members (byte-comparing parity scenarios).
    pub fn without_passthrough(&mut self) {
        fx::without_passthrough(&mut self.scans);
        fx::without_passthrough(&mut self.rules);
        for rows in self.findings.values_mut() {
            fx::without_passthrough(rows);
        }
        if let Some(stats) = &mut self.stats {
            stats.remove("zz_window");
            stats.remove("aa_generated_at");
        }
        self.pagination_passthrough = false;
    }
}

fn json_body(status: u16, text: String) -> Planned {
    Planned::raw(status, "application/json", text)
}

/// `skip` and `limit` as numbers (absent: the defaults), else `None` (a `400`).
fn page_query(request: &RecordedRequest) -> Option<(usize, usize)> {
    let number = |key: &str, default: usize| match request.query_value(key) {
        None => Some(default),
        Some(value) => value.parse::<usize>().ok(),
    };
    Some((number("skip", 0)?, number("limit", 10)?))
}

fn page(rows: &[Wire], skip: usize, limit: usize) -> Vec<Wire> {
    rows.iter().skip(skip).take(limit).cloned().collect()
}

/// The answer of a supplychain route.
pub(crate) fn answer(data: &mut SupplychainData, route: Sc, request: &RecordedRequest) -> Planned {
    let AuthIdentity::Bearer { tsg: Some(tsg) } = &request.auth else {
        return Planned::empty_json(401);
    };
    if request.header("x-tsg-id") != Some(tsg.as_str()) {
        return Planned::json(403, &json!({"message": "Forbidden"}));
    }
    match route {
        Sc::Scans => {
            let Some((skip, limit)) = page_query(request) else {
                return Planned::json(400, &json!({"message": "Invalid pagination"}));
            };
            if request.query_value("isBackgroundRefresh") != Some("false") {
                return Planned::json(400, &json!({"message": "isBackgroundRefresh expected"}));
            }
            let total = data
                .scan_total
                .unwrap_or_else(|| u64::try_from(data.scans.len()).unwrap_or(u64::MAX));
            let rows = page(&data.scans, skip, limit);
            json_body(
                200,
                fx::scan_list_body_with(&rows, total, data.pagination_passthrough),
            )
        }
        Sc::Stats => {
            if request.query_value("time_period") != Some("30_DAYS") {
                return Planned::json(400, &json!({"message": "Unsupported time_period"}));
            }
            match &data.stats {
                Some(stats) => json_body(200, stats.text()),
                None => Planned::json(404, &json!({"message": "Not found"})),
            }
        }
        Sc::Vulnerabilities => {
            let id = request
                .path
                .trim_end_matches("/vulnerabilities")
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let Some(rows) = data.findings.get(&id) else {
                return Planned::json(404, &json!({"message": "Scan not found"}));
            };
            if data.oversized_findings {
                let mut big = fx::finding(399, fx::SCAN_WITH_FINDINGS, "SECRET_EXPOSURE", 0);
                big.set("original_code", json!("x".repeat(33 * 1024 * 1024)));
                return json_body(200, fx::vulnerability_list_body(&[big], 1, true));
            }
            let total = data
                .finding_total
                .unwrap_or_else(|| u64::try_from(rows.len()).unwrap_or(u64::MAX));
            json_body(
                200,
                fx::vulnerability_list_body(rows, total, data.pagination_passthrough),
            )
        }
        Sc::Rules => {
            let Some((skip, limit)) = page_query(request) else {
                return Planned::json(400, &json!({"message": "Invalid pagination"}));
            };
            json_body(200, fx::rule_list_body(&page(&data.rules, skip, limit)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_only_the_four_reads() {
        let id = fx::uuid(101);
        for (method, path, route) in [
            (
                "GET",
                "/agentguard/data/v1/scans".to_owned(),
                Some(Sc::Scans),
            ),
            (
                "GET",
                "/agentguard/data/v1/stats/scans".to_owned(),
                Some(Sc::Stats),
            ),
            (
                "GET",
                format!("/agentguard/data/v1/scans/{id}/vulnerabilities"),
                Some(Sc::Vulnerabilities),
            ),
            (
                "GET",
                "/agentguard/mgmt/v1/rules".to_owned(),
                Some(Sc::Rules),
            ),
            ("POST", "/agentguard/data/v1/scans".to_owned(), None),
            ("GET", "/agentguard/data/v1/rules".to_owned(), None),
            ("GET", "/agentguard/mgmt/v1/scans".to_owned(), None),
            (
                "GET",
                "/agentguard/data/v1/scans//vulnerabilities".to_owned(),
                None,
            ),
            ("GET", format!("/agentguard/data/v1/scans/{id}"), None),
        ] {
            assert_eq!(Sc::classify(method, &path), route, "{method} {path}");
        }
    }
}
