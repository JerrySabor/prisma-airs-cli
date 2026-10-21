//! `customer-apps consumption` (DESIGN §18.9): the dashboard application overview walked
//! once over the `--time-interval` window through the shared page loop (D211), the name
//! lookup and its refusals, and each application's two reads (each under its own
//! request budget, §18.3).

use super::views::{self, Consumption};
use crate::error::{CliError, SecretSet};
use crate::json::OValue;
use crate::walk::{self, Page};
use scm::airs::management::{
    DashboardAppQuery, DashboardApplicationsOverviewQuery, DashboardClient,
};
use std::time::Duration;

/// The window unit of every consumption read (§18.9 `time_unit=days`), sent explicitly
/// rather than left to the SDK default.
const TIME_UNIT: &str = "days";

/// The overview page size (TS `listConsumptionApps({limit: 100})`).
pub const PAGE_SIZE: u32 = 100;

/// One dashboard bucket: an application id and the scan-payload name it was seen under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub id: String,
    pub name: String,
}

/// The walked overview: the buckets with a string id and name, in overview order, and how
/// many items lacked one (TS drops them silently; choice 34 says how many).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Overview {
    pub buckets: Vec<Bucket>,
    pub skipped: usize,
}

/// `  ⚠ <n> dashboard application(s) without an id or name were skipped` (choice 34).
pub fn skipped_warning(skipped: usize) -> String {
    format!("⚠ {skipped} dashboard application(s) without an id or name were skipped")
}

/// One overview page: `items` and `pagination.total_items`.
async fn page(
    dash: &DashboardClient,
    interval: u64,
    skip: u64,
    limit: u32,
    options: &scm::RequestOptions,
) -> Result<Page<OValue>, scm::Error> {
    let mut query = DashboardApplicationsOverviewQuery::default();
    query.time_interval = Some(interval);
    query.time_unit = Some(TIME_UNIT.to_owned());
    query.limit = Some(u64::from(limit));
    query.offset = Some(skip);
    let answer = views::ordered(&dash.applications_overview(&query, Some(options)).await?)?;
    let rows = answer
        .get("items")
        .and_then(OValue::as_array)
        .unwrap_or_default()
        .to_vec();
    let total = answer
        .get("pagination")
        .and_then(|pagination| crate::json::number(pagination, "total_items"));
    Ok(Page::new(rows, walk::total_of(total)))
}

fn bucket(item: &OValue) -> Option<Bucket> {
    Some(Bucket {
        id: views::text(item, "id")?.to_owned(),
        name: views::text(item, "name")?.to_owned(),
    })
}

/// Walk the overview (`src/walk.rs`: by `total_items`, the D37 error at an empty page
/// before the total and at a repeated `[id, name]`, the D40 bounds).
pub async fn overview(
    dash: &DashboardClient,
    interval: u64,
    options: &scm::RequestOptions,
) -> Result<Overview, scm::Error> {
    let walked = walk::walk(
        PAGE_SIZE,
        0,
        |skip, limit| page(dash, interval, skip, limit, options),
        |row| crate::json::to_compact(row).map_or(0, |text| text.len()),
        |row| {
            bucket(row).and_then(|bucket| crate::json::to_compact(&[bucket.id, bucket.name]).ok())
        },
    )
    .await?;
    let mut buckets = Vec::new();
    let mut skipped = 0;
    for item in &walked.rows {
        match bucket(item) {
            Some(bucket) => buckets.push(bucket),
            None => skipped += 1,
        }
    }
    Ok(Overview { buckets, skipped })
}

/// The bucket named exactly `name` (§18.9): not found (TS text, the first five names), or
/// refused when buckets of that name carry different ids (D211, choice 20).
pub fn lookup<'a>(
    buckets: &'a [Bucket],
    name: &str,
    secrets: &SecretSet,
) -> Result<&'a Bucket, CliError> {
    let matching: Vec<&Bucket> = buckets
        .iter()
        .filter(|bucket| bucket.name == name)
        .collect();
    let Some(found) = matching.first() else {
        let sample: Vec<String> = buckets
            .iter()
            .take(5)
            .map(|bucket| format!("\"{}\"", super::shown(&bucket.name, secrets)))
            .collect();
        let more = if buckets.len() > 5 {
            format!(", ... ({} total)", buckets.len())
        } else {
            String::new()
        };
        return Err(CliError::operational(format!(
            "Dashboard application not found: \"{}\". Available (as shown in SCM AI Applications view): {}{more}. Note: the name to use is the literal value your integration sends in scan metadata.app_name (which may differ from the SCM application name).",
            super::shown(name, secrets),
            sample.join(", ")
        )));
    };
    let mut ids: Vec<&str> = matching.iter().map(|bucket| bucket.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() > 1 {
        return Err(CliError::operational(format!(
            "Dashboard application name \"{}\" matches {} applications with different ids; use 'airs runtime dashboard application --app-id <id> --app-name <name>' for one of them",
            super::shown(name, secrets),
            ids.len()
        )));
    }
    Ok(found)
}

/// The two reads of one bucket, in TS order (`apps/application`, then the violation
/// breakdown; sequential, choice 17). Each read gets fresh options with `budget` (the
/// SDK deadline is absolute from when the options are built), so neither the overview
/// walk nor the reads before it shorten a read (§18.3, choices 44 and 73).
pub async fn read(
    dash: &DashboardClient,
    bucket: &Bucket,
    interval: u64,
    budget: Duration,
    secrets: &SecretSet,
) -> Result<Consumption, scm::Error> {
    let mut query = DashboardAppQuery::new(bucket.id.clone(), bucket.name.clone());
    query.time_interval = Some(interval);
    query.time_unit = Some(TIME_UNIT.to_owned());
    let options = super::request_options(budget)?;
    let mut application = views::ordered(&dash.application(&query, Some(&options)).await?)?;
    let options = super::request_options(budget)?;
    let mut breakdown = views::ordered(
        &dash
            .application_violation_breakdown(&query, Some(&options))
            .await?,
    )?;
    views::strip_api_keys(&mut application, secrets);
    views::strip_api_keys(&mut breakdown, secrets);
    let mut app = Consumption::from_answers(&bucket.id, &bucket.name, &application, &breakdown);
    app.withhold(secrets);
    Ok(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(id: &str, name: &str) -> Bucket {
        Bucket {
            id: id.to_owned(),
            name: name.to_owned(),
        }
    }

    fn message(result: Result<&Bucket, CliError>) -> String {
        match result {
            Err(error) => error.message(),
            Ok(found) => panic!("found {found:?}"),
        }
    }

    /// TS `management.spec.ts:1227-1395`: a shared app id with two names resolves the
    /// named bucket; a missing name lists the first five; D211 refuses one name with two
    /// ids.
    #[test]
    fn lookup_rules() {
        let secrets = SecretSet::default();
        let buckets = vec![
            b("uuid-shared", "chatbot"),
            b("uuid-shared", "LiteLLM"),
            b("uuid-litellm", "litellm"),
        ];
        assert_eq!(
            lookup(&buckets, "LiteLLM", &secrets).unwrap().id,
            "uuid-shared"
        );
        assert_eq!(
            lookup(&buckets, "litellm", &secrets).unwrap().id,
            "uuid-litellm"
        );
        assert_eq!(
            message(lookup(&buckets, "nonexistent", &secrets)),
            "Dashboard application not found: \"nonexistent\". Available (as shown in SCM AI Applications view): \"chatbot\", \"LiteLLM\", \"litellm\". Note: the name to use is the literal value your integration sends in scan metadata.app_name (which may differ from the SCM application name)."
        );
        let many: Vec<Bucket> = (1..=7)
            .map(|n| b(&format!("i{n}"), &format!("a{n}")))
            .collect();
        assert!(
            message(lookup(&many, "zz", &secrets))
                .contains("\"a1\", \"a2\", \"a3\", \"a4\", \"a5\", ... (7 total). Note:")
        );
        let shared = vec![b("one", "same"), b("two", "same")];
        assert_eq!(
            message(lookup(&shared, "same", &secrets)),
            "Dashboard application name \"same\" matches 2 applications with different ids; use 'airs runtime dashboard application --app-id <id> --app-name <name>' for one of them"
        );
        let escaped = vec![b("x", "evil\u{1b}[31m")];
        assert!(message(lookup(&escaped, "e\u{7}", &secrets)).contains("\"e\u{fffd}\""));
    }

    /// §18.3, choices 44 and 73: every application read gets its own budget from when it is sent,
    /// so a run longer than one budget still reads its later apps. Against the loopback
    /// fixture each answer takes `DELAY` (under `BUDGET`), one app's two reads take more
    /// than `BUDGET` and the run several times it; every read succeeds. An answer slower
    /// than the budget is the SDK deadline error (the budget does apply).
    #[test]
    fn each_read_gets_its_own_budget() {
        use crate::clients::{ManagementClients, Planes};
        use crate::tenant::config::{ConfigValue, TenantConfig};
        use airs_test_harness::{FixtureServer, Planned, Route, Rx};
        use std::time::{Duration, Instant};

        const BUDGET: Duration = Duration::from_millis(1_000);
        const DELAY: Duration = Duration::from_millis(600);
        let server = FixtureServer::start();
        server.add_tenant("100", "client-100", "FAKE-SECRET-100", None, None);
        server.seed_runtime();
        let text = |value: String| ConfigValue::Text(value);
        let config = TenantConfig::from_values([
            ("mgmtClientId", text("client-100".to_owned())),
            ("mgmtClientSecret", text("FAKE-SECRET-100".to_owned())),
            ("mgmtTsgId", text("100".to_owned())),
            ("mgmtEndpoint", text(server.url("/aisec"))),
            ("mgmtDashboardEndpoint", text(server.url("/dashboard"))),
            ("mgmtTokenEndpoint", text(server.url("/oauth/token"))),
        ]);
        let session = scm::Session::new();
        let secrets = SecretSet::default();
        let planes = Planes {
            dashboard: true,
            dlp: false,
        };
        let clients = ManagementClients::build_for(&config, &session, &secrets, None, planes)
            .unwrap_or_else(|_| panic!("the loopback client builds"));
        let dash = clients.management.dashboard();
        let slow = Planned::builtin().with_delay(DELAY);
        server.set_default(Route::Runtime(Rx::Application), slow.clone());
        server.set_default(Route::Runtime(Rx::ApplicationViolations), slow);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            clients
                .authenticate(None, crate::clients::TOKEN_BUDGET)
                .await
                .unwrap();
            let started = Instant::now();
            for bucket in [b("uuid-shared", "chatbot"), b("uuid-litellm", "litellm")] {
                let app = read(&dash, &bucket, 30, BUDGET, &secrets).await;
                assert_eq!(app.map(|app| app.app_name).ok(), Some(bucket.name));
            }
            assert!(
                started.elapsed() > BUDGET * 2,
                "the run outlasted two budgets"
            );
            let error = read(&dash, &b("uuid-shared", "chatbot"), 30, DELAY / 2, &secrets)
                .await
                .err()
                .map(|error| error.kind());
            assert_eq!(error, Some(scm::ErrorKind::Deadline));
        });
        // The deadline stopped the last app before its breakdown.
        assert_eq!(
            server
                .requests_for(Route::Runtime(Rx::ApplicationViolations))
                .len(),
            2
        );
    }
}
