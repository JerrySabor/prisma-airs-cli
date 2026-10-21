//! Supplychain (TypeScript `agentguard`) wire bodies (DESIGN §10 M6f, §20.13), in the
//! **real shapes** of the research (SC§4, SK§4.2): the documented member order of every
//! record (never sorted: `serde_json` would sort a `Value`, so the bodies are written
//! from [`Wire`], an ordered JSON value), nested objects, `null` in every nullable member,
//! realistic content (multi-line code, paths with directories, rule texts with
//! punctuation) and passthrough members placed out of alphabetical order (`zz_added`
//! before `aa_added`) on scans, findings, rules, the statistics and the pagination
//! objects. Every record validates against the TypeScript SDK's zod schemas and the Rust
//! SDK models (`scm::airs::agentguard`).
//!
//! Ids are `11111111-1111-4111-8111-<12 digits>` ([`uuid`]): scans 101–112, rules
//! 201–225, findings 301–399.
//!
//! **Markers.** Every value the CLI must never print without `--include-content` carries
//! [`MARKER`] (`PRIVATE-`): scan names, git URLs (with userinfo and a query),
//! fingerprints, error messages, evaluation details, device metadata and passthrough
//! members, and the finding titles, descriptions, paths and code. The runner forbids the
//! marker in every output of an airs-cli-rs `supplychain` run, and on stderr and in the
//! debug log of one with `--include-content` (whose stdout carries the finding content).
//! Ordinary data that only looks sensitive ([`ORDINARY_PATH`], [`ORDINARY_CODE`], a rule
//! that speaks of a "secret token") carries no marker: the over-withholding tests assert
//! that it prints unchanged.

use serde_json::{Value, json};

/// The TSG of the supplychain fixtures.
pub const TSG: &str = "100";
/// The prefix of every sensitive fixture value.
pub const MARKER: &str = "PRIVATE-";
/// The data-plane prefix (`agentGuardDataEndpoint = <base>/agentguard/data`).
pub const DATA_PREFIX: &str = "/agentguard/data";
/// The management-plane prefix (`agentGuardMgmtEndpoint = <base>/agentguard/mgmt`).
pub const MGMT_PREFIX: &str = "/agentguard/mgmt";
/// A finding path that names a password but is ordinary data (over-withholding).
pub const ORDINARY_PATH: &str = "src/password_reset.py";
/// Finding code that reads a key from the environment: ordinary data.
pub const ORDINARY_CODE: &str = "api_key = os.environ[\"KEY\"]";
/// A rule description that speaks of a secret token: ordinary catalog text.
pub const ORDINARY_RULE_TEXT: &str =
    "Flags a secret token committed to a skill (API keys, passwords, \"bearer\" headers).";

/// `11111111-1111-4111-8111-<n:012>`.
pub fn uuid(n: u64) -> String {
    format!("11111111-1111-4111-8111-{n:012}")
}

/// The seeded scans, in list order (101–112).
pub const SCAN_COUNT: u64 = 12;
/// The scan with findings (`SKILL` / `BLOCKED`).
pub const SCAN_WITH_FINDINGS: u64 = 101;
/// The seeded rule catalog size.
pub const RULE_COUNT: u64 = 25;

/// An ordered JSON value: objects keep their member order when written, as the service
/// sends them.
#[derive(Clone, Debug, PartialEq)]
pub enum Wire {
    /// A JSON scalar (or a scalar array), written as `serde_json` writes it.
    Leaf(Value),
    /// An array of ordered values.
    List(Vec<Wire>),
    /// An object, its members in this order.
    Object(Vec<(String, Wire)>),
}

impl From<Value> for Wire {
    /// A `Value` as ordered JSON (its objects in `serde_json`'s sorted order).
    fn from(value: Value) -> Self {
        match value {
            Value::Array(items) => Wire::List(items.into_iter().map(Wire::from).collect()),
            Value::Object(members) => Wire::Object(
                members
                    .into_iter()
                    .map(|(key, value)| (key, Wire::from(value)))
                    .collect(),
            ),
            scalar => Wire::Leaf(scalar),
        }
    }
}

/// An ordered object from `(key, value)` pairs.
pub fn obj(members: Vec<(&str, Wire)>) -> Wire {
    Wire::Object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// A leaf (scalars; nested objects should use [`obj`]).
pub fn w(value: Value) -> Wire {
    Wire::from(value)
}

impl Wire {
    /// The JSON text, members in order.
    pub fn text(&self) -> String {
        match self {
            Wire::Leaf(value) => value.to_string(),
            Wire::List(items) => {
                let items: Vec<String> = items.iter().map(Wire::text).collect();
                format!("[{}]", items.join(","))
            }
            Wire::Object(members) => {
                let members: Vec<String> = members
                    .iter()
                    .map(|(key, value)| format!("{}:{}", Value::from(key.as_str()), value.text()))
                    .collect();
                format!("{{{}}}", members.join(","))
            }
        }
    }

    /// The value as a `serde_json::Value` (for assertions; its objects sorted).
    pub fn value(&self) -> Value {
        serde_json::from_str(&self.text()).unwrap_or(Value::Null)
    }

    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Wire> {
        match self {
            Wire::Object(members) => members
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The member `key` of an object, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Wire> {
        match self {
            Wire::Object(members) => members
                .iter_mut()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// A string member.
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Wire::Leaf(Value::String(text))) => Some(text),
            _ => None,
        }
    }

    /// Replace the member `key` in place, or append it when absent.
    pub fn set(&mut self, key: &str, value: impl Into<Wire>) {
        let value = value.into();
        if let Wire::Object(members) = self {
            match members.iter_mut().find(|(name, _)| name == key) {
                Some((_, slot)) => *slot = value,
                None => members.push((key.to_owned(), value)),
            }
        }
    }

    /// Remove the member `key` (a schema-invalid record when it is required).
    pub fn remove(&mut self, key: &str) {
        if let Wire::Object(members) = self {
            members.retain(|(name, _)| name != key);
        }
    }

    /// The member names, in order.
    pub fn keys(&self) -> Vec<&str> {
        match self {
            Wire::Object(members) => members.iter().map(|(name, _)| name.as_str()).collect(),
            _ => Vec::new(),
        }
    }
}

/// The passthrough members every record of one kind may carry, out of alphabetical order.
fn passthrough(record: &mut Wire, zz: Wire, aa: Wire) {
    record.set("zz_added", zz);
    record.set("aa_added", aa);
}

/// One scan in the service's member order (SC§4). `n` is the id number; the other
/// arguments are the members the seeded rows vary.
#[allow(clippy::too_many_arguments)]
pub fn scan(
    n: u64,
    created_at: &str,
    artifact_type: &str,
    status: &str,
    eval_outcome: Option<&str>,
    summary: Option<(u64, u64)>,
) -> Wire {
    let summary = summary.map_or(w(Value::Null), |(vulnerabilities, chains)| {
        obj(vec![
            ("vulnerability_count", w(json!(vulnerabilities))),
            ("attack_chain_count", w(json!(chains))),
        ])
    });
    let completed = status == "COMPLETED";
    let eval_summary = if completed {
        obj(vec![
            ("total_rules", w(json!(3))),
            (
                "blocked",
                w(json!(u64::from(eval_outcome == Some("BLOCKED")))),
            ),
            ("allowed", w(json!(2))),
        ])
    } else {
        w(Value::Null)
    };
    let eval_details = if completed {
        obj(vec![
            (
                "rule_outcomes",
                Wire::List(vec![obj(vec![
                    ("rule_instance_uuid", w(json!(uuid(200 + n)))),
                    ("rule_name", w(json!("Secret exposure"))),
                    ("vulnerability_types", w(json!(["SECRET_EXPOSURE"]))),
                    ("state", w(json!("BLOCKING"))),
                    ("outcome", w(json!(eval_outcome.unwrap_or("ALLOWED")))),
                    (
                        "description",
                        w(json!(format!(
                            "{MARKER}EVAL-{n} matched skills/deploy/run.sh"
                        ))),
                    ),
                    (
                        "remediation",
                        w(json!(format!("{MARKER}EVAL-FIX-{n}: rotate the key"))),
                    ),
                    ("vulnerability_count", w(json!(1))),
                ])]),
            ),
            ("skill_override_applied", w(json!(false))),
            (
                "unknown_findings",
                w(json!([{ "detail": format!("{MARKER}UNKNOWN-{n}") }])),
            ),
        ])
    } else {
        w(Value::Null)
    };
    let error = if status == "FAILED" {
        w(json!(format!(
            "{MARKER}ERROR-{n}: clone failed for https://{MARKER}USER:{MARKER}PASS@git.example.invalid/o/r.git"
        )))
    } else {
        w(Value::Null)
    };
    obj(vec![
        ("uuid", w(json!(uuid(n)))),
        ("tsg_id", w(json!(TSG))),
        ("created_at", w(json!(created_at))),
        ("updated_at", w(json!(created_at))),
        ("name", w(json!(format!("{MARKER}NAME-{n} deploy-helper")))),
        (
            "git_url",
            w(json!(format!(
                "https://{MARKER}USER-{n}:{MARKER}TOKEN-{n}@git.example.invalid/org/skills.git?{MARKER}QUERY={n}"
            ))),
        ),
        ("artifact_type", w(json!(artifact_type))),
        ("status", w(json!(status))),
        ("error_message", error),
        ("summary", summary),
        ("eval_outcome", w(json!(eval_outcome))),
        ("eval_summary", eval_summary),
        ("eval_details", eval_details),
        (
            "duration_seconds",
            w(if completed { json!(12.5) } else { Value::Null }),
        ),
        (
            "fingerprint",
            w(json!(format!("{MARKER}FINGERPRINT-{n}-sha256:9f2c"))),
        ),
        (
            "scanner_version",
            w(if completed {
                json!("1.4.2")
            } else {
                Value::Null
            }),
        ),
        (
            "device_metadata",
            obj(vec![
                ("token", w(json!(format!("{MARKER}DEVICE-TOKEN-{n}")))),
                (
                    "hostname",
                    w(json!(format!("{MARKER}HOST-{n}.corp.invalid"))),
                ),
                ("os", w(json!("darwin"))),
            ]),
        ),
        ("parent_uuid", w(Value::Null)),
        ("is_batch", w(json!(false))),
        ("child_scan_uuids", w(json!([]))),
        ("batch_summary", w(Value::Null)),
    ])
}

/// The seeded scans (§20.13): a complete `SKILL`/`BLOCKED` scan, an `AGENT`/`ALLOWED`
/// one, a `RUNNING` one with `summary` and `eval_outcome` `null`, a batch parent and its
/// child, an unfamiliar `artifact_type` and `eval_outcome`, a lowercase `skill`, a
/// `FAILED`/`ERROR` row, a row created in 2020, a zone-less `created_at`, a date-only one
/// and a `garbage` one.
pub fn scans() -> Vec<Wire> {
    let at = "2026-10-19T01:57:59.751Z";
    let mut rows = vec![
        scan(101, at, "SKILL", "COMPLETED", Some("BLOCKED"), Some((2, 1))),
        scan(102, at, "AGENT", "COMPLETED", Some("ALLOWED"), Some((0, 0))),
        scan(103, "2026-10-19T02:00:00Z", "SKILL", "RUNNING", None, None),
        scan(104, at, "SKILL", "COMPLETED", Some("ALLOWED"), Some((1, 0))),
        scan(105, at, "SKILL", "COMPLETED", Some("ALLOWED"), Some((1, 0))),
        scan(
            106,
            at,
            "UNLISTED<b>",
            "COMPLETED",
            Some("UNLISTED-X"),
            Some((0, 0)),
        ),
        scan(107, at, "skill", "COMPLETED", Some("ALLOWED"), Some((0, 0))),
        scan(108, at, "SKILL", "FAILED", Some("ERROR"), None),
        scan(
            109,
            "2020-01-01T00:00:00Z",
            "SKILL",
            "COMPLETED",
            Some("ALLOWED"),
            Some((0, 0)),
        ),
        scan(
            110,
            "2026-10-18T10:00:00",
            "SKILL",
            "COMPLETED",
            Some("ALLOWED"),
            Some((0, 0)),
        ),
        scan(
            111,
            "2026-10-18",
            "AGENT",
            "COMPLETED",
            Some("BLOCKED"),
            Some((3, 2)),
        ),
        scan(
            112,
            "garbage",
            "SKILL",
            "COMPLETED",
            Some("ALLOWED"),
            Some((0, 0)),
        ),
    ];
    // The batch parent (104) and its child (105).
    rows[3].set("is_batch", w(json!(true)));
    rows[3].set("child_scan_uuids", w(json!([uuid(105)])));
    rows[3].set(
        "batch_summary",
        obj(vec![
            ("total", w(json!(1))),
            ("completed", w(json!(1))),
            ("note", w(json!(format!("{MARKER}BATCH-NOTE")))),
        ]),
    );
    rows[4].set("parent_uuid", w(json!(uuid(104))));
    // Passthrough members, out of alphabetical order, on the first scan.
    passthrough(
        &mut rows[0],
        w(json!(format!("{MARKER}PASSTHROUGH"))),
        obj(vec![("nested", w(json!(format!("{MARKER}NESTED"))))]),
    );
    rows
}

/// The scans of [`null_scans`] (G71).
pub const NULL_SCANS: [u64; 3] = [113, 114, 115];

/// Scans in the service's shape with the `null`s the live service sends where both SDK
/// contracts require a value (DESIGN §20.5, G71; observed 2026-10-20: `"fingerprint":
/// null`). Neither SDK accepts them, so TypeScript refuses the whole page; airs-cli-rs
/// reads them through its tolerant projection.
/// - 113: a complete `SKILL`/`BLOCKED` scan with `"fingerprint": null` and nothing else
///   changed (the observed row);
/// - 114: every member the tolerant read accepts as `null` set to `null` (`tsg_id`,
///   `created_at`, `updated_at`, `name`, `git_url`, `artifact_type`, `status`,
///   `error_message`, `summary`, `eval_outcome`, `eval_summary`, `eval_details`,
///   `duration_seconds`, `fingerprint`, `scanner_version`, `device_metadata`,
///   `parent_uuid`, `is_batch`, `child_scan_uuids`, `batch_summary`), `uuid` kept;
/// - 115: an `AGENT`/`ALLOWED` scan with `name`, `fingerprint` and `device_metadata`
///   `null`, a summary whose `vulnerability_count` is `null` (`attack_chain_count` 3), and
///   a passthrough member that is `null`.
///
/// Every member stays in the service's order (`Wire::set` replaces in place).
pub fn null_scans() -> Vec<Wire> {
    let at = "2026-10-19T03:04:05.006Z";
    let mut observed = scan(113, at, "SKILL", "COMPLETED", Some("BLOCKED"), Some((1, 1)));
    observed.set("fingerprint", w(Value::Null));
    let mut all = scan(114, at, "SKILL", "RUNNING", None, None);
    for key in all
        .keys()
        .into_iter()
        .filter(|key| *key != "uuid")
        .map(str::to_owned)
        .collect::<Vec<_>>()
    {
        all.set(&key, w(Value::Null));
    }
    let mut partial = scan(115, at, "AGENT", "COMPLETED", Some("ALLOWED"), Some((0, 3)));
    for key in ["name", "fingerprint", "device_metadata"] {
        partial.set(key, w(Value::Null));
    }
    if let Some(summary) = partial.get_mut("summary") {
        summary.set("vulnerability_count", w(Value::Null));
    }
    partial.set("zz_added", w(Value::Null));
    vec![observed, all, partial]
}

/// [`null_scans`] created an hour ago (the report's window ends now), 114's `created_at`
/// still `null` (a missing creation time).
pub fn recent_null_scans() -> Vec<Wire> {
    let at = iso_ms(now_ms().saturating_sub(3_600_000));
    let mut rows = null_scans();
    for row in &mut rows {
        if row.str("created_at").is_some() {
            row.set("created_at", w(json!(at)));
            row.set("updated_at", w(json!(at)));
        }
    }
    rows
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` of `ms` milliseconds since the Unix epoch (from 1970).
pub fn iso_ms(ms: u64) -> String {
    let days = i64::try_from(ms / 86_400_000).unwrap_or(0);
    let rest = ms % 86_400_000;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3_600_000,
        rest / 60_000 % 60,
        rest / 1000 % 60,
        rest % 1000
    )
}

/// Milliseconds since the Unix epoch, now.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(0))
}

/// The seeded scans (§20.13) with creation times for a report whose 30-day window ends
/// now (DESIGN §20.9): the ISO rows an hour ago, 109 in 2020 (out of the window), 110 an
/// hour ago **without a zone** (D322), 111 today's UTC date only (UTC midnight, inside),
/// 112 `garbage`. The members and their order are [`scans`]'s.
pub fn recent_scans() -> Vec<Wire> {
    let hour_ago = now_ms().saturating_sub(3_600_000);
    let at = iso_ms(hour_ago);
    let mut rows = scans();
    for (index, row) in rows.iter_mut().enumerate() {
        let created = match index {
            8 => continue,
            9 => at.trim_end_matches('Z').to_owned(),
            10 => at[..10].to_owned(),
            11 => continue,
            _ => at.clone(),
        };
        row.set("created_at", w(json!(created)));
        row.set("updated_at", w(json!(at)));
    }
    rows
}

/// [`recent_scans`] without the zone-less row 110 (the scenarios that compare bytes with
/// TypeScript, which reads that row in the host's zone, D322).
pub fn recent_zoned_scans() -> Vec<Wire> {
    let mut rows = recent_scans();
    rows.remove(9);
    rows
}

/// The deepest value's depth in a JSON document, the root at 0 (the SDK's validation
/// preflight count, G66).
pub fn json_depth(value: &Value) -> usize {
    let mut deepest = 0;
    let mut stack = vec![(value, 0usize)];
    while let Some((value, depth)) = stack.pop() {
        deepest = deepest.max(depth);
        match value {
            Value::Array(values) => stack.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => stack.extend(values.values().map(|value| (value, depth + 1))),
            _ => {}
        }
    }
    deepest
}

/// [`scans`] with the first scan's `eval_details` in the service's shape (`rule_outcomes`,
/// `skill_override_applied`, `unknown_findings`) whose rule outcome carries an `evidence` chain of
/// `{"context": …}` objects ending in a marked string, so that the deepest value of the
/// page [`scan_list_body`] writes sits at `depth` (at least 6; G66's depth bound is 64,
/// DESIGN §20.16). Every other member and row is unchanged.
pub fn deep_scans(depth: usize) -> Vec<Wire> {
    // page 0 > scans 1 > scan 2 > eval_details 3 > rule_outcomes 4 > outcome 5 > evidence 6.
    let levels = depth.checked_sub(6).expect("at least the outcome's depth");
    let evidence = (0..levels).fold(w(json!(format!("{MARKER}DEEP-EVIDENCE"))), |inner, _| {
        obj(vec![("context", inner)])
    });
    let mut rows = scans();
    rows[0].set(
        "eval_details",
        obj(vec![
            (
                "rule_outcomes",
                Wire::List(vec![obj(vec![
                    ("rule_instance_uuid", w(json!(uuid(201)))),
                    ("rule_name", w(json!("Secret exposure"))),
                    ("vulnerability_types", w(json!(["SECRET_EXPOSURE"]))),
                    ("state", w(json!("BLOCKING"))),
                    ("outcome", w(json!("BLOCKED"))),
                    (
                        "description",
                        w(json!(format!(
                            "{MARKER}EVAL-101 matched skills/deploy/run.sh"
                        ))),
                    ),
                    (
                        "remediation",
                        w(json!(format!("{MARKER}EVAL-FIX-101: rotate the key"))),
                    ),
                    ("vulnerability_count", w(json!(1))),
                    ("evidence", evidence),
                ])]),
            ),
            ("skill_override_applied", w(json!(false))),
            ("unknown_findings", w(json!([]))),
        ]),
    );
    rows
}

/// A list's `pagination`: `total_items`, then (`extras`) two passthrough members out of
/// alphabetical order.
pub fn list_pagination(total: u64, extras: bool) -> Wire {
    let mut pagination = obj(vec![("total_items", w(json!(total)))]);
    if extras {
        pagination.set("zz_cursor", w(Value::Null));
        pagination.set("aa_page_hint", w(json!(1)));
    }
    pagination
}

/// A `GET /v1/scans` page body: the rows and `pagination` (`total_items`, then two
/// passthrough members).
pub fn scan_list_body(rows: &[Wire], total: u64) -> String {
    scan_list_body_with(rows, total, true)
}

/// [`scan_list_body`], the pagination passthrough members only with `extras`.
pub fn scan_list_body_with(rows: &[Wire], total: u64, extras: bool) -> String {
    obj(vec![
        ("pagination", list_pagination(total, extras)),
        ("scans", Wire::List(rows.to_vec())),
    ])
    .text()
}

/// Multi-line finding code with a tab, CR LF, an ESC, non-ASCII text and a C1 control.
pub fn finding_code(n: u64) -> String {
    format!(
        "def load_config():\r\n\tapi_key = \"{MARKER}CODE-{n}\"\u{1b}[31m\n\treturn {{'name': 'ü 日本'}}\u{85}\n"
    )
}

/// One finding in the service's member order (SC§4).
pub fn finding(n: u64, scan: u64, vulnerability_type: &str, chains: u64) -> Wire {
    obj(vec![
        ("uuid", w(json!(uuid(n)))),
        ("tsg_id", w(json!(TSG))),
        ("created_at", w(json!("2026-10-19T01:58:10.004Z"))),
        ("updated_at", w(json!("2026-10-19T01:58:10.004Z"))),
        ("scan_uuid", w(json!(uuid(scan)))),
        (
            "title",
            w(json!(format!("{MARKER}TITLE-{n}: hard-coded credential"))),
        ),
        (
            "description",
            w(json!(format!(
                "{MARKER}DESCRIPTION-{n}: the skill embeds a credential\nthat any caller can read."
            ))),
        ),
        ("vulnerability_type", w(json!(vulnerability_type))),
        (
            "file_path",
            w(json!(format!("skills/{MARKER}PATH-{n}/config/load.py"))),
        ),
        ("node_id", w(json!(format!("node-{n}")))),
        ("node_type", w(json!("function"))),
        ("node_name", w(json!(format!("{MARKER}NODE-{n}")))),
        (
            "remediation_description",
            w(json!(format!(
                "{MARKER}REMEDIATION-{n}: move the key to a secret store; rotate it."
            ))),
        ),
        ("original_code", w(json!(finding_code(n)))),
        (
            "suggested_code",
            w(json!(format!(
                "def load_config():\n\tapi_key = os.environ[\"{MARKER}ENV-{n}\"]\n"
            ))),
        ),
        ("attack_chain_count", w(json!(chains))),
        (
            "attack_chain_uuids",
            w(json!(
                (0..chains).map(|i| uuid(900 + i)).collect::<Vec<_>>()
            )),
        ),
        (
            "type_description",
            w(json!("Secrets exposed in skill source")),
        ),
    ])
}

/// A finding whose path and code only look sensitive (over-withholding): no marker.
pub fn ordinary_finding(n: u64, scan: u64) -> Wire {
    let mut record = finding(n, scan, "PROMPT_INJECTION", 0);
    record.set("title", w(json!("Password reset token logged")));
    record.set(
        "description",
        w(json!("The reset handler logs the token; mask it.")),
    );
    record.set("file_path", w(json!(ORDINARY_PATH)));
    record.set("node_name", w(json!("reset_password")));
    record.set("remediation_description", w(json!("Mask the token.")));
    record.set("original_code", w(json!(ORDINARY_CODE)));
    record.set("suggested_code", w(Value::Null));
    record
}

/// The seeded findings of [`SCAN_WITH_FINDINGS`]: two marked ones (one with an attack
/// chain and passthrough members) and an ordinary one.
pub fn findings() -> Vec<Wire> {
    let mut first = finding(301, SCAN_WITH_FINDINGS, "SECRET_EXPOSURE", 0);
    passthrough(
        &mut first,
        w(json!(format!("{MARKER}FINDING-PASSTHROUGH"))),
        w(json!(7)),
    );
    vec![
        first,
        finding(302, SCAN_WITH_FINDINGS, "PROMPT_INJECTION", 1),
        ordinary_finding(303, SCAN_WITH_FINDINGS),
    ]
}

/// A `GET /v1/scans/{uuid}/vulnerabilities` body (the pagination passthrough members
/// only with `extras`).
pub fn vulnerability_list_body(rows: &[Wire], total: u64, extras: bool) -> String {
    obj(vec![
        ("pagination", list_pagination(total, extras)),
        ("vulnerabilities", Wire::List(rows.to_vec())),
    ])
    .text()
}

/// The seeded statistics (`percent_change` `12.5` and `null`) with two passthrough
/// members out of alphabetical order.
pub fn stats() -> Wire {
    obj(vec![
        (
            "unique_skills_scanned",
            obj(vec![
                ("count", w(json!(4))),
                ("percent_change", w(json!(12.5))),
            ]),
        ),
        (
            "total_vulnerabilities_found",
            obj(vec![
                ("count", w(json!(7))),
                ("percent_change", w(Value::Null)),
            ]),
        ),
        (
            "top_vulnerability",
            obj(vec![
                ("vulnerability_type", w(json!("SECRET_EXPOSURE"))),
                ("finding_count", w(json!(3))),
            ]),
        ),
        ("zz_window", w(json!("30_DAYS"))),
        ("aa_generated_at", w(json!("2026-10-19T00:00:00Z"))),
    ])
}

/// The rule names, by vulnerability type (the catalog's punctuation included).
const RULE_TYPES: [(&str, &str); 5] = [
    (
        "SECRET_EXPOSURE",
        "Secret exposure — hard-coded credentials",
    ),
    ("PROMPT_INJECTION", "Prompt injection (indirect)"),
    ("DATA_EXFILTRATION", "Data exfiltration: outbound calls"),
    ("UNSAFE_EXECUTION", "Unsafe execution / shell"),
    ("SUPPLY_CHAIN", "Dependency confusion & typo-squatting"),
];

/// One rule in the service's member order.
pub fn rule(n: u64) -> Wire {
    let index = usize::try_from(n.wrapping_sub(1) % 5).unwrap_or(0);
    let (vulnerability, name) = RULE_TYPES[index];
    let description = if index == 0 {
        ORDINARY_RULE_TEXT.to_owned()
    } else {
        format!("Detects {} in skills and agents.", name.to_lowercase())
    };
    obj(vec![
        ("uuid", w(json!(uuid(n)))),
        ("name", w(json!(format!("{name} #{n}")))),
        ("vulnerability_types", w(json!([vulnerability]))),
        (
            "default_state",
            w(json!(if n.is_multiple_of(3) {
                "ALLOWING"
            } else {
                "BLOCKING"
            })),
        ),
        ("description", w(json!(description))),
        (
            "remediation",
            w(json!(
                "Review the flagged code; rotate exposed values.\nRe-scan."
            )),
        ),
    ])
}

/// The seeded catalog (201–225); the first rule carries two passthrough members.
pub fn rules() -> Vec<Wire> {
    let mut rows: Vec<Wire> = (201..201 + RULE_COUNT).map(rule).collect();
    passthrough(&mut rows[0], w(json!("catalog-v2")), w(json!(true)));
    rows
}

/// A `GET /v1/rules` page body: `total_items` is the page length (G62).
pub fn rule_list_body(rows: &[Wire]) -> String {
    obj(vec![
        (
            "pagination",
            obj(vec![("total_items", w(json!(rows.len())))]),
        ),
        ("rules", Wire::List(rows.to_vec())),
    ])
    .text()
}

/// Remove the passthrough members from every record (the parity scenarios that compare
/// bytes; D35 orders them differently).
pub fn without_passthrough(rows: &mut [Wire]) {
    for row in rows {
        row.remove("zz_added");
        row.remove("aa_added");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_keep_the_service_member_order() {
        let scan = &scans()[0];
        assert_eq!(
            scan.keys(),
            [
                "uuid",
                "tsg_id",
                "created_at",
                "updated_at",
                "name",
                "git_url",
                "artifact_type",
                "status",
                "error_message",
                "summary",
                "eval_outcome",
                "eval_summary",
                "eval_details",
                "duration_seconds",
                "fingerprint",
                "scanner_version",
                "device_metadata",
                "parent_uuid",
                "is_batch",
                "child_scan_uuids",
                "batch_summary",
                "zz_added",
                "aa_added",
            ]
        );
        let text = scan.text();
        let summary = text.find("\"summary\":{\"vulnerability_count\"").unwrap();
        assert!(summary > 0, "nested members unsorted: {text}");
        assert!(
            stats().text().ends_with(
                "\"zz_window\":\"30_DAYS\",\"aa_generated_at\":\"2026-10-19T00:00:00Z\"}"
            )
        );
        assert_eq!(
            rule_list_body(&rules()[..2]).find("\"total_items\":2"),
            Some(15)
        );
        // The text is JSON and round-trips.
        assert_eq!(Wire::from(scan.value()).value(), scan.value());
    }

    #[test]
    fn recent_scans_sit_in_a_window_ending_now() {
        assert_eq!(iso_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_ms(1_788_868_800_123), "2026-09-08T12:00:00.123Z");
        let rows = recent_scans();
        assert_eq!(rows.len(), scans().len());
        assert_eq!(rows[0].keys(), scans()[0].keys());
        let created: Vec<&str> = rows
            .iter()
            .map(|row| row.str("created_at").unwrap())
            .collect();
        assert!(created[0].ends_with('Z') && created[0].len() == 24);
        assert_eq!(created[8], "2020-01-01T00:00:00Z");
        assert_eq!(created[9].len(), 23, "zone-less");
        assert_eq!(created[10].len(), 10, "date only");
        assert_eq!(created[11], "garbage");
        assert_eq!(recent_zoned_scans().len(), rows.len() - 1);
    }

    /// G71's rows keep the service's member order and carry the `null`s they document.
    #[test]
    fn null_scans_keep_the_service_shape() {
        let rows = null_scans();
        assert_eq!(rows.len(), NULL_SCANS.len());
        for (row, n) in rows.iter().zip(NULL_SCANS) {
            assert_eq!(row.str("uuid"), Some(uuid(n).as_str()));
            assert_eq!(row.keys()[..21], scans()[1].keys()[..21], "{n}");
            assert_eq!(row.get("fingerprint"), Some(&w(Value::Null)), "{n}");
        }
        assert!(rows[0].str("name").unwrap().starts_with(MARKER));
        assert_eq!(rows[0].str("status"), Some("COMPLETED"));
        let all = &rows[1];
        assert!(
            all.keys()
                .iter()
                .filter(|key| **key != "uuid")
                .all(|key| all.get(key) == Some(&w(Value::Null)))
        );
        let summary = rows[2].get("summary").unwrap().text();
        assert_eq!(
            summary,
            r#"{"vulnerability_count":null,"attack_chain_count":3}"#
        );
        let recent = recent_null_scans();
        assert!(recent[0].str("created_at").unwrap().ends_with('Z'));
        assert_eq!(recent[1].get("created_at"), Some(&w(Value::Null)));
    }

    #[test]
    fn markers_are_only_on_sensitive_members() {
        for rule in rules() {
            assert!(!rule.text().contains(MARKER), "{}", rule.text());
        }
        let ordinary = ordinary_finding(303, 101).text();
        assert!(!ordinary.contains(MARKER));
        for scan in scans() {
            for key in [
                "uuid",
                "artifact_type",
                "status",
                "eval_outcome",
                "created_at",
            ] {
                assert!(
                    !scan
                        .get(key)
                        .map(Wire::text)
                        .unwrap_or_default()
                        .contains(MARKER)
                );
            }
            assert!(scan.str("name").unwrap().starts_with(MARKER));
        }
    }
}
