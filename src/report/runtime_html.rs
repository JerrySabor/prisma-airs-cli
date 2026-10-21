//! The self-contained HTML of the runtime environment report (TS
//! `renderRuntimeReportHtml`, DESIGN §18.14): its own CSS and JS with a hash-based Content
//! Security Policy, `& < > " '` escaped as named entities (the red team report uses
//! `&#<code>;`), the eight evidence tables, the four metrics and the en-US number format.
//! The bytes are TypeScript's.

use super::Health;
use super::html::{UNKNOWN, hash};
use super::runtime::Report;

/// The inline style (TS `CSS`, with its leading and trailing newline).
pub const CSS: &str = r#"
#evidence td:nth-child(3){white-space:nowrap}
:root{color-scheme:light;--ink:#172b40;--muted:#526476;--line:#d8e2e9;--bg:#f2f5f8;--accent:#00786e;font:16px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink)}a{color:var(--accent)}header{background:#11283d;color:#fff;padding:2.5rem max(1.25rem,calc((100vw - 1240px)/2))}header p{color:#d7e4ec;max-width:85ch}h1{font-size:clamp(1.8rem,4vw,2.7rem);line-height:1.15;margin:.6rem 0 1rem;overflow-wrap:anywhere}h2{font-size:1.35rem;margin:0 0 .6rem}h3{font-size:1.05rem;margin:.35rem 0}p{margin:.5rem 0 1rem}.eyebrow{font-size:.8rem;letter-spacing:.12em;text-transform:uppercase}.badge{display:inline-block;padding:.35rem .7rem;border:1px solid currentColor;border-radius:100px;font-weight:650;background:#fff;color:var(--ink)}.attention .badge{color:#a62b1b}.review .badge{color:#795500}.unknown .badge{color:#69439b}.no-findings .badge{color:#006a54}
main{max-width:1280px;margin:auto;padding:1.5rem 1.25rem 3rem}nav{display:flex;gap:1.25rem;flex-wrap:wrap;margin-bottom:1.5rem}section{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.4rem;margin:1.3rem 0}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1rem}.card{background:#fff;border:1px solid var(--line);border-top:4px solid var(--accent);border-radius:9px;padding:1.2rem}.card strong{display:block;font-size:2rem;font-variant-numeric:tabular-nums}.card span,.note{color:var(--muted);font-size:.9rem}.toolbar{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin:1rem 0}button,input,select{font:inherit;border:1px solid #8b9eaf;border-radius:6px;padding:.5rem .7rem;background:#fff;color:var(--ink)}button{cursor:pointer}input{max-width:100%}:focus-visible{outline:3px solid #c06605;outline-offset:3px}.finding{border-left:4px solid #b3c3cf;padding:.5rem 1rem;margin:1rem 0;background:#f7f9fb}.finding[data-priority=attention]{border-color:#c74429}.finding[data-priority=review]{border-color:#b78712}.priority{font-size:.75rem;text-transform:uppercase;font-weight:750;letter-spacing:.07em}.finding p{margin:.4rem 0}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.9rem;text-align:left}th{background:#edf3f7;font-weight:700}th,td{padding:.7rem .8rem;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere;min-width:90px}tbody tr:hover{background:#f8fbfd}caption{text-align:left;font-weight:600;padding:.5rem 0}footer{color:var(--muted);font-size:.8rem;margin-top:2rem}.hidden,[hidden]{display:none!important}.js-only{display:none}.js-ready .js-only{display:flex}.skip{position:absolute;left:-9999px}.skip:focus{left:1rem;top:1rem;background:#fff;padding:1rem;z-index:1}li{margin:.5rem 0}
@media(max-width:760px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}section{padding:1rem}header{padding:1.5rem 1.25rem}.card strong{font-size:1.5rem}}
@media print{body{background:#fff;font-size:10pt}header{background:#fff;color:#000;padding:0}header p{color:#333}main{padding:0;max-width:none}nav,.toolbar,.skip{display:none!important}section,.card{border-radius:0;break-inside:auto}.finding,.card{break-inside:avoid}.table-wrap{overflow:visible}table{font-size:8pt}th,td{min-width:0;padding:.3rem}.hidden,[hidden]{display:revert!important}h2,h3{break-after:avoid}a{color:#000}}
"#;

/// The inline script (TS `JS`, with its leading and trailing newline). Static code only:
/// API strings are never interpolated into script or an attribute.
pub const JS: &str = r#"
'use strict';
document.documentElement.classList.add('js-ready');
document.getElementById('print-report').addEventListener('click',function(){window.print();});
var filter=document.getElementById('finding-filter');
filter.addEventListener('change',function(){
  var visible=0;
  document.querySelectorAll('.finding').forEach(function(row){row.hidden=filter.value!=='all'&&row.dataset.priority!==filter.value;if(!row.hidden)visible++;});
  document.getElementById('finding-count').textContent=visible+' findings shown';
});
var search=document.getElementById('app-search');
search.addEventListener('input',function(){
  var query=search.value.toLowerCase().trim(),visible=0;
  document.querySelectorAll('#applications tbody tr').forEach(function(row){row.hidden=!row.textContent.toLowerCase().includes(query);if(!row.hidden)visible++;});
  document.getElementById('app-count').textContent=visible+' application buckets shown';
});
"#;

/// The `body` class of a health (TS `report.health`).
fn health_name(health: Health) -> &'static str {
    match health {
        Health::Attention => "attention",
        Health::Review => "review",
        Health::NoFindings => "no-findings",
        Health::Unknown => "unknown",
    }
}

/// TS `html()`: `& < > " '` as `&amp; &lt; &gt; &quot; &#39;`.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The CSP of the document.
pub fn policy() -> String {
    format!(
        "default-src 'none'; script-src 'sha256-{}'; style-src 'sha256-{}'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'",
        hash(JS),
        hash(CSS)
    )
}

/// TS `number()`: `Unknown` for `null`, else `toLocaleString('en-US',
/// {maximumFractionDigits: 2})`: the shortest decimal form rounded half away from zero to
/// two fraction digits, trailing zeros dropped, thousands separated by `,`.
pub fn number(value: Option<f64>) -> String {
    let Some(value) = value else {
        return UNKNOWN.to_owned();
    };
    if !value.is_finite() {
        return if value.is_nan() {
            "NaN".to_owned()
        } else if value > 0.0 {
            "∞".to_owned()
        } else {
            "-∞".to_owned()
        };
    }
    let negative = value < 0.0;
    let text = format!("{}", value.abs());
    let (int_part, frac_part) = text.split_once('.').unwrap_or((&text, ""));
    let mut digits: Vec<u8> = int_part.bytes().map(|b| b - b'0').collect();
    let mut fraction: Vec<u8> = frac_part.bytes().map(|b| b - b'0').collect();
    if fraction.len() > 2 {
        let round_up = fraction[2] >= 5;
        fraction.truncate(2);
        if round_up {
            // Carry through the fraction, then the integer digits.
            let mut carry = true;
            for digit in fraction.iter_mut().rev().chain(digits.iter_mut().rev()) {
                if !carry {
                    break;
                }
                if *digit == 9 {
                    *digit = 0;
                } else {
                    *digit += 1;
                    carry = false;
                }
            }
            if carry {
                digits.insert(0, 1);
            }
        }
    }
    while fraction.last() == Some(&0) {
        fraction.pop();
    }
    let mut grouped = String::new();
    for (index, digit) in digits.iter().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(b'0' + digit));
    }
    if !fraction.is_empty() {
        grouped.push('.');
        grouped.extend(fraction.iter().map(|digit| char::from(b'0' + digit)));
    }
    if negative && grouped.bytes().any(|b| b.is_ascii_digit() && b != b'0') {
        format!("-{grouped}")
    } else {
        grouped
    }
}

#[allow(clippy::cast_precision_loss)]
fn count(value: Option<u64>) -> String {
    number(value.map(|value| value as f64))
}

/// One table of the report (TS `Table`).
struct Table {
    title: &'static str,
    id: &'static str,
    headers: &'static [&'static str],
    rows: Vec<Vec<String>>,
    note: String,
}

/// TS `tables(report)`.
#[allow(clippy::too_many_lines)]
fn tables(report: &Report) -> Vec<Table> {
    let session_status = report
        .sources
        .iter()
        .find(|source| source.name == "Daily session inventory")
        .map_or("unavailable", |source| source.status.name());
    let unknown = || UNKNOWN.to_owned();
    vec![
        Table {
            title: "Daily application activity",
            id: "applications",
            headers: &[
                "Application bucket",
                "Sessions",
                "Violating sessions",
                "Violation rate",
                "Registered ID match",
            ],
            rows: report
                .applications
                .iter()
                .map(|app| {
                    #[allow(clippy::cast_precision_loss)]
                    let rate = match (app.sessions, app.violating_sessions) {
                        (Some(sessions), Some(violating)) if sessions > 0 && violating <= sessions => {
                            format!(
                                "{}%",
                                number(Some(violating as f64 / sessions as f64 * 100.0))
                            )
                        }
                        _ => unknown(),
                    };
                    vec![
                        app.name.clone(),
                        count(app.sessions),
                        count(app.violating_sessions),
                        rate,
                        match app.registered {
                            None => unknown(),
                            Some(true) => "Yes".to_owned(),
                            Some(false) => "Not in returned inventory".to_owned(),
                        },
                    ]
                })
                .collect(),
            note: "API-reported rolling one-day application buckets, ranked by violating sessions. Partial-source totals cover collected buckets only. Violating sessions are not necessarily blocked sessions.".to_owned(),
        },
        Table {
            title: "Current security profiles",
            id: "profiles",
            headers: &[
                "Profile",
                "Revision",
                "Active",
                "Timeout action",
                "Storage masking",
                "Last modified (UTC)",
            ],
            rows: report
                .profiles
                .iter()
                .map(|profile| {
                    vec![
                        profile.name.clone(),
                        count(profile.revision),
                        match profile.active {
                            None => unknown(),
                            Some(true) => "Yes".to_owned(),
                            Some(false) => "No".to_owned(),
                        },
                        if profile.timeout_actions.is_empty() {
                            unknown()
                        } else {
                            profile.timeout_actions.join(", ")
                        },
                        profile.storage_masking.to_owned(),
                        profile.modified.clone().unwrap_or_else(unknown),
                    ]
                })
                .collect(),
            note: "Latest returned revision per profile name. These are current settings, not a record of changes during the daily window.".to_owned(),
        },
        Table {
            title: "Registered application inventory",
            id: "inventory",
            headers: &["Application", "Environment", "Cloud", "Model", "Key associations"],
            rows: report
                .registered_apps
                .iter()
                .map(|app| {
                    vec![
                        app.name.clone(),
                        app.environment.clone(),
                        app.cloud.clone(),
                        app.model.clone(),
                        count(app.key_associations),
                    ]
                })
                .collect(),
            note: "Current registered applications, separate from scan-metadata application buckets. Association counts do not establish key validity or deployment health. No key values or auth codes are included.".to_owned(),
        },
        Table {
            title: "Collected session observations",
            id: "sessions",
            headers: &["Session status", "Entries"],
            rows: report
                .sessions
                .statuses
                .iter()
                .map(|(name, entries)| vec![name.clone(), count(Some(*entries))])
                .collect(),
            note: format!(
                "Source: {session_status}. Timestamp-eligible entries: {}. Violated status: {}. Missing timestamps: {}; outside window: {}. These are collected session counts, not scan actions or detector events. No scan content is fetched.",
                count(report.sessions.entries),
                count(report.sessions.violating_sessions),
                report.sessions.missing_timestamps,
                report.sessions.outside_window
            ),
        },
        Table {
            title: "Daily session chart",
            id: "session-chart",
            headers: &[
                "Bucket time (UTC)",
                "Sessions",
                "Violating sessions",
                "Detector violations",
            ],
            rows: report
                .chart_buckets
                .iter()
                .map(|bucket| {
                    vec![
                        bucket.time.clone(),
                        count(bucket.sessions),
                        count(bucket.violating_sessions),
                        count(bucket.violations.total),
                    ]
                })
                .collect(),
            note: format!(
                "Independent chart totals: {} sessions; {} violating sessions. Do not force these counters to equal a separately paginated inventory.",
                count(report.chart_sessions),
                count(report.chart_violating)
            ),
        },
        Table {
            title: "Top applications by detector violations",
            id: "top-violations",
            headers: &["Application bucket", "Detector violations", "Detection types"],
            rows: report
                .top_applications
                .iter()
                .map(|app| {
                    vec![
                        app.name.clone(),
                        count(app.violations),
                        app.detectors
                            .iter()
                            .map(|(name, total)| format!("{name}: {}", count(*total)))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ]
                })
                .collect(),
            note: "Server-ranked subset for one day, not a complete application inventory. Detector violations may exceed the number of violating sessions.".to_owned(),
        },
        Table {
            title: "Daily detector severity trend",
            id: "violation-trend",
            headers: &["Bucket time (UTC)", "Critical", "High", "Medium", "Low", "Total"],
            rows: report
                .violation_trend
                .iter()
                .map(|bucket| {
                    let v = &bucket.violations;
                    vec![
                        bucket.time.clone(),
                        count(v.critical),
                        count(v.high),
                        count(v.medium),
                        count(v.low),
                        count(v.total),
                    ]
                })
                .collect(),
            note: "API-reported detector-policy events over the rolling day. Severity counts are preserved independently from distinct session counts; no previous-day comparison is inferred.".to_owned(),
        },
        Table {
            title: "Evidence and collection coverage",
            id: "evidence",
            headers: &[
                "Source / SDK method",
                "Window",
                "Status",
                "Records",
                "Pages",
                "Collection notes",
            ],
            rows: report
                .sources
                .iter()
                .map(|source| {
                    let notes = source.notes.join(" ");
                    vec![
                        format!("{} — {}", source.name, source.method),
                        source.window.to_owned(),
                        source.status.name().to_owned(),
                        count(Some(source.records)),
                        source.pages.to_string(),
                        if notes.is_empty() {
                            "Collection completed.".to_owned()
                        } else {
                            notes
                        },
                    ]
                })
                .collect(),
            note: "Complete means pagination finished for that source, not that the environment is secure or that all traffic was ingested. Unavailable does not mean zero.".to_owned(),
        },
    ]
}

/// TS `metrics(report)`.
fn metrics(report: &Report) -> [(&'static str, String); 4] {
    let complete = report
        .sources
        .iter()
        .filter(|source| source.status == super::Status::Complete)
        .count();
    [
        (
            "Sessions in collected app buckets",
            count(report.sessions_total),
        ),
        ("Violating sessions", count(report.violating_total)),
        (
            "Violation rate",
            report.violation_rate.map_or_else(
                || UNKNOWN.to_owned(),
                |rate| format!("{}%", number(Some(rate))),
            ),
        ),
        (
            "Complete evidence sources",
            format!("{complete} / {}", report.sources.len()),
        ),
    ]
}

/// TS `renderRuntimeReportHtml`, ending in one newline.
pub fn render(report: &Report) -> String {
    let finding_cards: String = report
        .findings
        .iter()
        .map(|finding| {
            let priority = escape(finding.priority.name());
            format!(
                "<article class=\"finding\" data-priority=\"{priority}\"><span class=\"priority\">{priority}</span><h3>{}</h3><p><strong>Evidence:</strong> {}</p><p><strong>Next step:</strong> {}</p><p class=\"note\">Source: {}</p></article>",
                escape(&finding.title),
                escape(&finding.evidence),
                escape(&finding.recommendation),
                escape(&finding.source)
            )
        })
        .collect();
    let sections: String = tables(report)
        .iter()
        .map(|table| {
            let toolbar = if table.id == "applications" {
                "<div class=\"toolbar js-only\"><label for=\"app-search\">Find an application</label><input id=\"app-search\" type=\"search\" placeholder=\"Filter application buckets\"><span id=\"app-count\" role=\"status\"></span></div>"
            } else {
                ""
            };
            let body = if table.rows.is_empty() {
                "<p>No rows available. Consult the source status before interpreting this as an empty result.</p>".to_owned()
            } else {
                let headers: String = table
                    .headers
                    .iter()
                    .map(|header| format!("<th scope=\"col\">{header}</th>"))
                    .collect();
                let rows: String = table
                    .rows
                    .iter()
                    .map(|row| {
                        let cells: String = row
                            .iter()
                            .map(|cell| format!("<td>{}</td>", escape(cell)))
                            .collect();
                        format!("<tr>{cells}</tr>")
                    })
                    .collect();
                format!(
                    "<div class=\"table-wrap\" role=\"region\" aria-label=\"{title}\" tabindex=\"0\"><table><caption>{} collected rows</caption><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table></div>",
                    table.rows.len(),
                    title = table.title
                )
            };
            format!(
                "<section id=\"{id}\" aria-labelledby=\"{id}-title\"><h2 id=\"{id}-title\">{title}</h2><p class=\"note\">{note}</p>{toolbar}{body}</section>",
                id = table.id,
                title = table.title,
                note = escape(&table.note)
            )
        })
        .collect();
    let cards: String = metrics(report)
        .iter()
        .map(|(name, value)| {
            format!("<div class=\"card\"><span>{name}</span><strong>{value}</strong></div>")
        })
        .collect();
    let findings = if finding_cards.is_empty() {
        "<p>No findings in the available evidence. This does not establish an absence of risk.</p>"
            .to_owned()
    } else {
        finding_cards
    };
    let limitations: String = report
        .limitations
        .iter()
        .map(|note| format!("<li>{}</li>", escape(note)))
        .collect();
    let title = escape(&report.title);
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"{policy}\"><meta name=\"referrer\" content=\"no-referrer\"><title>{title} — Prisma AIRS</title><style>{CSS}</style></head>\n<body class=\"{health_name}\"><a class=\"skip\" href=\"#main\">Skip to report</a><header><div class=\"eyebrow\">Prisma AIRS · AI Runtime Security</div><h1>{title}</h1><span class=\"badge\">{health}</span><p>{window}<br><time>{start}</time> → <time>{end}</time></p><p>Collected {collected} → {generated}<br>Read-only evidence · Confidential environment metadata</p></header>\n<main id=\"main\"><nav aria-label=\"Report sections\"><a href=\"#findings\">Attention</a><a href=\"#applications\">Activity</a><a href=\"#profiles\">Profiles</a><a href=\"#inventory\">Inventory</a><a href=\"#evidence\">Evidence</a><a href=\"#scope\">Scope</a></nav>\n<div class=\"cards\">{cards}</div>\n<section id=\"findings\"><h2>What needs attention</h2><p class=\"note\">Observed violations and configuration review items, not a numerical health score. Collection gaps remain visible in the evidence table.</p><div class=\"toolbar js-only\"><label for=\"finding-filter\">Priority</label><select id=\"finding-filter\"><option value=\"all\">All findings</option><option value=\"attention\">Attention</option><option value=\"review\">Review</option><option value=\"info\">Information</option></select><span id=\"finding-count\" role=\"status\"></span><button id=\"print-report\" type=\"button\">Print / save PDF</button></div>{findings}</section>\n{sections}<section id=\"scope\"><h2>Scope, privacy, and limitations</h2><ul>{limitations}</ul></section><footer>Generated by Prisma AIRS CLI · Report schema {schema} · Self-contained HTML; no network access required. All evidence remains readable with JavaScript disabled.</footer></main><script>{JS}</script></body></html>\n",
        policy = escape(&policy()),
        health_name = escape(health_name(report.health)),
        health = report.health.label(),
        window = escape(super::runtime::WINDOW),
        start = escape(&report.window_start),
        end = escape(&report.window_end),
        collected = escape(&report.collection_started_at),
        generated = escape(&report.generated_at),
        schema = super::runtime::SCHEMA_VERSION,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CSP hashes are TypeScript's (the inline assets are byte-identical).
    #[test]
    fn the_policy_pins_the_typescript_assets() {
        assert_eq!(
            policy(),
            "default-src 'none'; script-src 'sha256-5LxzE6qTHVB6GkFp5aSlfgYy4D1HefDNuhJF25u8bAE='; style-src 'sha256-VLFdq2Qs156m0R7mhD0UAHR12n5y2Ki6ghMmFhbLmow='; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'"
        );
        assert!(CSS.starts_with("\n#evidence") && CSS.ends_with("}\n"));
        assert!(JS.starts_with("\n'use strict';") && JS.ends_with("});\n"));
    }

    /// `toLocaleString('en-US', {maximumFractionDigits: 2})`.
    #[test]
    fn numbers_are_en_us() {
        for (value, text) in [
            (None, "Unknown"),
            (Some(0.0), "0"),
            (Some(25.0), "25"),
            (Some(1234.0), "1,234"),
            (Some(1_234_567.0), "1,234,567"),
            (Some(9_007_199_254_740_991.0), "9,007,199,254,740,991"),
            (Some(100.0 / 3.0), "33.33"),
            (Some(200.0 / 3.0), "66.67"),
            (Some(0.125), "0.13"),
            (Some(1.005), "1.01"),
            (Some(99.999), "100"),
            (Some(999.995), "1,000"),
            (Some(12.5), "12.5"),
            (Some(0.001), "0"),
        ] {
            assert_eq!(number(value), text, "{value:?}");
        }
    }

    #[test]
    fn escaping_uses_named_entities() {
        assert_eq!(escape("</script>\"'&"), "&lt;/script&gt;&quot;&#39;&amp;");
    }
}
