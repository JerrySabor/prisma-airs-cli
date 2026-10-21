//! The self-contained HTML of an environment report (TS `environment-render.ts`,
//! DESIGN §15.17): a hash-based Content Security Policy over the inline style and script,
//! `&#<code>;` escaping of `&<>"'`, the evidence tables and the scope section. The bytes
//! are TypeScript's.
//!
//! One template serves every environment report that TypeScript renders with
//! `renderEnvironmentReportHtml` (red team, gateway and supplychain): a [`Profile`]
//! supplies the product line, the window label, the footer label and the limitations
//! (DESIGN §19.15, choice 50; §20.9). The runtime report has its own template
//! (`runtime_html.rs`) and shares only [`hash`] and the [`UNKNOWN`] cell rule.

use super::{Cell, Report, Table};
use sha2::{Digest, Sha256};

/// The inline style (TS `CSS`, with its leading and trailing newline).
pub const CSS: &str = concat!(
    "\n",
    r#":root{font:16px/1.6 system-ui,sans-serif;color:#193449;background:#f0f4f7}*{box-sizing:border-box}body{margin:0}header{background:#152e43;color:white;padding:3rem max(1rem,calc((100vw - 1160px)/2))}h1{font-size:clamp(1.8rem,4vw,3rem);line-height:1.15}h1,h2,h3,p,td{overflow-wrap:anywhere}main{max-width:1200px;margin:auto;padding:1rem}section,article{padding:1.4rem;background:white;border:1px solid #cddbe4;border-radius:10px;margin:1rem 0}.finding{border-left:5px solid #b08528}.finding[data-priority=attention]{border-left-color:#b1392d}.note{color:#536575;font-size:.9rem}.badge{border:1px solid;padding:.3rem .8rem;border-radius:30px;display:inline-block}nav,.controls{display:flex;gap:1rem;flex-wrap:wrap}button,select{font:inherit;padding:.4rem;border:1px solid #526778;border-radius:5px;background:white;color:#193449}a{color:#006b63}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;text-align:left}th,td{padding:.7rem;border-bottom:1px solid #d4dfe6;vertical-align:top}th{background:#edf3f7}caption{text-align:left}footer{padding:1rem;color:#536575}.js-only{display:none}.ready .js-only{display:flex}[hidden]{display:none!important}:focus-visible{outline:3px solid #ae6816;outline-offset:3px}.skip{position:absolute;left:-10000px}.skip:focus{left:1rem;top:1rem;background:white;padding:1rem}@media(max-width:600px){header{padding:1.5rem 1rem}section{padding:1rem}th,td{padding:.5rem}}@media print{body{background:white;font-size:10pt}header{background:white;color:black;padding:0}main{max-width:none;padding:0}nav,.controls,.skip{display:none!important}[hidden]{display:revert!important}.table-wrap{overflow:visible}section{border:0;padding:0}article{break-inside:avoid}}"#,
    "\n"
);

/// The inline script (TS `JS`).
pub const JS: &str = r#"'use strict';document.documentElement.classList.add('ready');document.getElementById('print').addEventListener('click',function(){window.print()});document.getElementById('priority').addEventListener('change',function(){var n=0;document.querySelectorAll('.finding').forEach(function(e){e.hidden=this.value!=='all'&&e.dataset.priority!==this.value;if(!e.hidden)n++},this);document.getElementById('count').textContent=n+' findings shown'});"#;

/// The text of a `null` cell (TS `String(v ?? 'Unknown')`), shared with the runtime
/// report's numbers.
pub const UNKNOWN: &str = "Unknown";

/// The parameters of one report kind (TS `report.product`, `windowLabel`, `schemaLabel`
/// and `limitations`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The product line above the title.
    pub product: &'static str,
    /// The label of the window line (`<label>: <start> → <end>`).
    pub window_label: &'static str,
    /// The footer's report name (`Prisma AIRS CLI · <label> report schema 1 · …`).
    pub footer_label: &'static str,
    /// The scope statements, in order.
    pub limitations: &'static [&'static str],
}

/// The red team environment report (DESIGN §15.17).
pub const RED_TEAM: Profile = Profile {
    product: "Prisma AIRS AI Red Teaming",
    window_label: "Scan creation window (UTC)",
    footer_label: "Red Team",
    limitations: &super::LIMITATIONS,
};

/// The gateway environment report (DESIGN §19.15).
pub const GATEWAY: Profile = Profile {
    product: "Prisma AIRS AI Gateway",
    window_label: "Telemetry window (UTC)",
    footer_label: "AI Gateway",
    limitations: &super::gateway::LIMITATIONS,
};

/// The supplychain environment report (DESIGN §20.9): the product line names the
/// AgentGuard service (D308), the window line is a free label.
pub const SUPPLYCHAIN: Profile = Profile {
    product: "Prisma AIRS AI Supply Chain — AgentGuard",
    window_label: "30-day scan inventory; rolling 30_DAYS statistics; current rule catalog",
    footer_label: "Experimental browser APIs",
    limitations: &super::supplychain::LIMITATIONS,
};

/// `html(v)`: `String(v ?? 'Unknown')` with `&<>"'` as `&#<code>;`.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' | '<' | '>' | '"' | '\'' => out.push_str(&format!("&#{};", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// A cell as `String(v ?? 'Unknown')`, escaped: a number as ECMAScript
/// `Number::toString` (`-0` is `0`).
fn cell(value: &Cell) -> String {
    match value {
        Cell::Text(text) => escape(text),
        Cell::Count(count) => count.to_string(),
        Cell::Null => UNKNOWN.to_owned(),
        Cell::Number(number) => escape(&crate::render::js_number(*number)),
    }
}

/// `base64(sha256(text))` (the CSP hashes of both reports).
pub(crate) fn hash(text: &str) -> String {
    crate::redteam::args::base64(&Sha256::digest(text.as_bytes()))
}

/// The CSP of the document (`default-src 'none'; script-src 'sha256-…'; …`).
pub fn policy() -> String {
    format!(
        "default-src 'none'; script-src 'sha256-{}'; style-src 'sha256-{}'; connect-src 'none'; base-uri 'none'; form-action 'none'",
        hash(JS),
        hash(CSS)
    )
}

fn section(index: usize, table: &Table) -> String {
    let title = escape(&table.title);
    let body = if table.rows.is_empty() {
        "<p>No rows collected; consult source completeness before interpreting this as empty.</p>"
            .to_owned()
    } else {
        let headers: String = table
            .headers
            .iter()
            .map(|header| format!("<th scope=\"col\">{}</th>", escape(header)))
            .collect();
        let rows: String = table
            .rows
            .iter()
            .map(|row| {
                let cells: String = row
                    .iter()
                    .map(|value| format!("<td>{}</td>", cell(value)))
                    .collect();
                format!("<tr>{cells}</tr>")
            })
            .collect();
        format!(
            "<div class=\"table-wrap\" role=\"region\" aria-label=\"{title}\" tabindex=\"0\"><table><caption>{} aggregate rows</caption><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table></div>",
            table.rows.len()
        )
    };
    format!(
        "<section id=\"table-{index}\"><h2>{title}</h2><p class=\"note\">{}</p>{body}</section>",
        escape(&table.note)
    )
}

/// `renderEnvironmentReportHtml` under `profile`, ending in one newline.
pub fn render(report: &Report, profile: &Profile) -> String {
    let sections: String = report
        .all_tables()
        .iter()
        .enumerate()
        .map(|(index, table)| section(index, table))
        .collect();
    let findings: String = report
        .findings
        .iter()
        .map(|finding| {
            format!(
                "<article class=\"finding\" data-priority=\"{}\"><h3>{}</h3><p>{}</p><p><strong>Next step:</strong> {}</p><p class=\"note\">{}</p></article>",
                escape(finding.priority.name()),
                escape(&finding.title),
                escape(&finding.evidence),
                escape(&finding.recommendation),
                escape(&finding.source)
            )
        })
        .collect();
    let findings = if findings.is_empty() {
        "<p>No findings in available evidence; this does not establish absence of risk.</p>"
            .to_owned()
    } else {
        findings
    };
    let limitations: String = profile
        .limitations
        .iter()
        .map(|limitation| format!("<li>{}</li>", escape(limitation)))
        .collect();
    let title = escape(&report.title);
    format!(
        concat!(
            "<!doctype html>\n",
            "<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
            "<meta http-equiv=\"Content-Security-Policy\" content=\"{policy}\"><meta name=\"referrer\" content=\"no-referrer\">",
            "<title>{title}</title><style>{css}</style></head><body><a class=\"skip\" href=\"#main\">Skip to report</a>",
            "<header><p>{product}</p><h1>{title}</h1><span class=\"badge\">{health}</span>",
            "<p>Collection: {started} → {generated}</p><p>{window_label}: {start} → {end}</p>",
            "<p>Read-only evidence · Confidential environment metadata</p></header>",
            "<main id=\"main\"><nav aria-label=\"Report sections\"><a href=\"#findings\">Attention</a><a href=\"#table-0\">Evidence tables</a><a href=\"#scope\">Scope</a></nav>",
            "<section id=\"findings\"><h2>What needs attention</h2><div class=\"controls js-only\"><label for=\"priority\">Priority</label>",
            "<select id=\"priority\"><option value=\"all\">All</option><option value=\"attention\">Attention</option><option value=\"review\">Review</option></select>",
            "<span id=\"count\" role=\"status\"></span><button id=\"print\" type=\"button\">Print / save PDF</button></div>{findings}</section>",
            "{sections}<section id=\"scope\"><h2>Scope and limitations</h2><ul>{limitations}</ul></section>",
            "<footer>Prisma AIRS CLI · {footer_label} report schema 1 · Works offline and without JavaScript.</footer></main>",
            "<script>{js}</script></body></html>\n"
        ),
        policy = escape(&policy()),
        title = title,
        css = CSS,
        product = escape(profile.product),
        window_label = escape(profile.window_label),
        footer_label = escape(profile.footer_label),
        health = report.health.label(),
        started = escape(&report.collection_started_at),
        generated = escape(&report.generated_at),
        start = escape(&report.window_start),
        end = escape(&report.window_end),
        findings = findings,
        sections = sections,
        limitations = limitations,
        js = JS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CSP hashes of the TypeScript reference (computed with Node's crypto over the
    /// same CSS and JS).
    #[test]
    fn the_policy_hashes_the_inline_assets_as_typescript_does() {
        assert_eq!(
            policy(),
            "default-src 'none'; script-src 'sha256-vxcVmn+OlgkxEN2VQ7q63vmVAZ/uCr6B1goVcd7EK6c='; style-src 'sha256-jPa0PJ+rVzL3fveVWR9DWnRPrxPWaM+zQ/+OnWDs2+A='; connect-src 'none'; base-uri 'none'; form-action 'none'"
        );
        assert_eq!(CSS.len(), 1701);
        assert_eq!(JS.len(), 438);
    }

    /// The three profiles of the shared template (DESIGN §15.17, §19.15, §20.9): the red
    /// team and gateway values are unchanged from 0.10 (their reports stay byte-identical,
    /// pinned by their parity tests); the supplychain profile names the AgentGuard service.
    #[test]
    fn profiles_name_their_reports() {
        let fields = |p: &Profile| {
            (
                p.product,
                p.window_label,
                p.footer_label,
                p.limitations.len(),
            )
        };
        assert_eq!(
            fields(&RED_TEAM),
            (
                "Prisma AIRS AI Red Teaming",
                "Scan creation window (UTC)",
                "Red Team",
                7
            )
        );
        assert_eq!(
            fields(&GATEWAY),
            (
                "Prisma AIRS AI Gateway",
                "Telemetry window (UTC)",
                "AI Gateway",
                7
            )
        );
        assert_eq!(
            fields(&SUPPLYCHAIN),
            (
                "Prisma AIRS AI Supply Chain — AgentGuard",
                "30-day scan inventory; rolling 30_DAYS statistics; current rule catalog",
                "Experimental browser APIs",
                5
            )
        );
        assert_eq!(
            SUPPLYCHAIN.limitations,
            &super::super::supplychain::LIMITATIONS
        );
    }

    #[test]
    fn text_is_escaped_as_numeric_references() {
        assert_eq!(
            escape("</script><img src=x onerror=alert('1')>&\""),
            "&#60;/script&#62;&#60;img src=x onerror=alert(&#39;1&#39;)&#62;&#38;&#34;"
        );
    }
}
