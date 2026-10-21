//! The tests of the gateway withholding traversal (DESIGN §19.3), one file per group of
//! rules: `name_rule` (rule 3 by name, registration, the DESIGN table), `headers` (3c's maps
//! and pairs), `schemas` (3e), `paths` (rules 1 and 2), `audit` (rule 5), `texts` (3f, private
//! keys, the URL, scheme and key=value rules, model output) and `corpus` (the pinned,
//! generated and real-world documents and the checker held equal to the traversal). The
//! helpers every group uses are here.

mod audit;
mod corpus;
mod headers;
mod name_rule;
mod paths;
mod schemas;
mod texts;

use super::names::{CREDENTIAL_MEMBERS, is_credential_name, normalised};
use super::*;
use crate::gateway::withhold_rules;
use crate::gateway::withhold_rules::check;
use crate::gateway::withhold_rules::corpus::PINNED_DOCUMENTS;
use crate::gateway::withhold_rules::values::{is_date, looks_like_password, url_withheld};
use crate::json::{parse, to_compact};

/// The shared checker on a printed JSON text (the CLI's own value type).
fn checked(text: &str) -> bool {
    check::withheld(&parse(text).unwrap())
}

/// The `SecretSet` of a document whose path rule withholds inside a member that the
/// name rule then withholds whole: the placeholder is never registered.
fn secrets_of(policy: &Policy) -> SecretSet {
    applied(
        r#"{"credentials":{"password":"FAKE-GW-SECRET-15","username":"edge"}}"#,
        policy,
    )
    .1
}

fn applied(text: &str, policy: &Policy) -> (String, SecretSet) {
    let secrets = SecretSet::default();
    let mut doc = parse(text).unwrap();
    apply(&mut doc, policy, &secrets);
    (to_compact(&doc).unwrap(), secrets)
}

/// A withheld document printed in json, pretty and table (the generic detail renderer
/// every inventory read uses).
fn printed_formats(doc: &OValue) -> [(crate::output::Format, String); 3] {
    use crate::output::Format;
    use crate::output::testing::capture;
    [Format::Json, Format::Pretty, Format::Table].map(|format| {
        let (mut out, stdout, _) = capture(false);
        crate::gateway::views::render_detail(&mut out, doc, format).unwrap();
        out.commit().unwrap();
        (format, stdout.text())
    })
}
