//! The `--debug` API log (DESIGN §2.9).
//!
//! One JSONL file per run under `$XDG_STATE_HOME/airs-cli/debug/` (default
//! `~/.local/state/airs-cli/debug/`), one record per transport attempt. A record holds
//! status and headers only: never a request or response body, never a URL query or
//! fragment. Header values are written only for an allow-list of names; every other
//! value is `***`. Before each write the whole line is checked against the
//! invocation's [`SecretSet`] (defence in depth). A failed write never changes the
//! command: logging stops and one warning goes to stderr.

use crate::error::{CliError, SecretSet};
use crate::json::{self, OValue};
use crate::render::style::{self, Style};
use futures_util::future::BoxFuture;
use reqwest::header::HeaderMap;
use reqwest::{Method, StatusCode};
use scm::transport::{Transport, TransportRequest, TransportResponse};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use url::Url;

/// How many logs the directory keeps, this run's included.
pub const KEEP: usize = 20;
/// What a header value outside the allow-list (or carrying a secret) is written as.
pub const MASK: &str = "***";
/// The one stderr warning after a failed write (yellow, TS `ui.warning`).
pub const WRITE_WARNING: &str = "⚠ Debug: the API log could not be written; it is incomplete";
/// `error` of an attempt whose `send` returned an error.
pub const REQUEST_FAILED: &str = "Request failed";
/// `error` of an attempt whose `send` future was dropped first (deadline, cancel).
pub const REQUEST_CANCELLED: &str = "Request cancelled before a response";
/// The SDK operation of an OAuth token request: its record waits for the lease
/// ([`TokenHold`]).
pub const TOKEN_OPERATION: &str = "oauth.token";

/// Request headers whose values are written.
const REQUEST_HEADERS: &[&str] = &[
    "accept",
    "content-length",
    "content-type",
    "service-name",
    "user-agent",
    "x-tsg-id",
];
/// Response headers whose values are written (`location` is sanitised separately).
const RESPONSE_HEADERS: &[&str] = &[
    "cache-control",
    "content-length",
    "content-type",
    "date",
    "request-id",
    "retry-after",
    "server",
    "vary",
    "x-correlation-id",
    "x-request-id",
];

/// Whether a command writes the log under `--debug` (the planning table, DESIGN §2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugPolicy {
    /// The command can send requests: `--debug` opens a log.
    Log,
    /// The command sends nothing (`tenant *`): `--debug` is accepted and ignored.
    None,
    /// The command refuses `--debug` during planning (the environment report, §15.17,
    /// D156), so no log is ever opened for it.
    Refused,
}

/// The log directory: `$XDG_STATE_HOME/airs-cli/debug` (set and non-empty; it must be
/// absolute), else `<home>/.local/state/airs-cli/debug` (the home must be absolute).
pub fn directory(xdg_state_home: Option<&OsStr>, home: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(state) = xdg_state_home.filter(|value| !value.is_empty()) {
        let state = Path::new(state);
        if !state.is_absolute() {
            return Err(CliError::operational(
                "XDG_STATE_HOME must be an absolute path",
            ));
        }
        return Ok(crate::store::normalize(&state.join("airs-cli/debug")));
    }
    match home.filter(|home| home.is_absolute()) {
        Some(home) => Ok(crate::store::normalize(
            &home.join(".local/state/airs-cli/debug"),
        )),
        None => Err(CliError::operational(
            "Cannot create the debug log: HOME is not an absolute path; set XDG_STATE_HOME or omit --debug",
        )),
    }
}

/// The setup failure naming `dir` (the OS error is never echoed; the renderer makes
/// the path terminal-safe).
fn setup_failed(dir: &Path) -> CliError {
    CliError::operational(format!(
        "Cannot create the debug log in {}; fix that directory or omit --debug",
        dir.display()
    ))
}

/// `debug-api-<epoch ms>-<8 hex>.jsonl` (the TS pattern).
pub fn file_name(epoch_ms: u128, hex: &str) -> String {
    format!("debug-api-{epoch_ms}-{hex}.jsonl")
}

/// The timestamp of a log name matching `^debug-api-[0-9]{13}-[0-9a-f]{8}\.jsonl$`.
pub fn log_timestamp(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("debug-api-")?.strip_suffix(".jsonl")?;
    let (stamp, hex) = rest.split_once('-')?;
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if stamp.len() == 13
        && stamp.bytes().all(|b| b.is_ascii_digit())
        && hex.len() == 8
        && hex.bytes().all(lower_hex)
    {
        stamp.parse().ok()
    } else {
        None
    }
}

/// Keep `own` plus the [`KEEP`]` - 1` newest other logs in `dir` (by the timestamp in
/// the name, then by name, never by mtime) and remove the rest. Only regular files with
/// log names are counted or touched; every error is ignored.
pub fn prune(dir: &Path, own: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut logs: Vec<(u64, String)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let stamp = log_timestamp(&name)?;
            let metadata = fs::symlink_metadata(entry.path()).ok()?;
            metadata.file_type().is_file().then_some((stamp, name))
        })
        .collect();
    logs.sort_by(|a, b| b.cmp(a));
    let mut kept = 1;
    for (_, name) in logs {
        if name == own {
            continue;
        }
        if kept < KEEP {
            kept += 1;
        } else {
            let _ = fs::remove_file(dir.join(&name));
        }
    }
}

/// The invocation's API log. Clones share one file.
#[derive(Clone)]
pub struct DebugLog {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    /// `None` once a write failed (the log is closed for the rest of the run).
    sink: Mutex<Option<Box<dyn Write + Send>>>,
    /// Where the write warning goes; taken by the first failure, so it prints once.
    warning: Mutex<Option<Box<dyn Write + Send>>>,
    warning_color: bool,
    secrets: SecretSet,
    /// Token records waiting for their lease (see [`TokenHold`]).
    holds: Mutex<Holds>,
}

/// The token-record holds of a log.
#[derive(Default)]
struct Holds {
    /// Live [`TokenHold`]s.
    active: usize,
    /// Whether a hold was dropped unreleased (cancelled) since the last flush.
    cancelled: bool,
    /// Finished token attempts not yet written.
    pending: Vec<Finished>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl DebugLog {
    /// Create the directory and this run's file, then prune old logs. `secrets` is the
    /// invocation's set (shared: leases registered later are seen by the line check);
    /// `warning_color` is the stderr colour decision.
    pub fn open(dir: &Path, secrets: SecretSet, warning_color: bool) -> Result<Self, CliError> {
        let epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let uuid = uuid::Uuid::new_v4().simple().to_string();
        let file = create_file(dir, &file_name(epoch_ms, &uuid[..8]))?;
        Ok(Self::with_sinks(
            file.0,
            Box::new(file.1),
            Box::new(std::io::stderr()),
            warning_color,
            secrets,
        ))
    }

    /// A log over arbitrary sinks (tests).
    fn with_sinks(
        path: PathBuf,
        sink: Box<dyn Write + Send>,
        warning: Box<dyn Write + Send>,
        warning_color: bool,
        secrets: SecretSet,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                path,
                sink: Mutex::new(Some(sink)),
                warning: Mutex::new(Some(warning)),
                warning_color,
                secrets,
                holds: Mutex::new(Holds::default()),
            }),
        }
    }

    /// The log file.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Start recording one attempt (at entry to `Transport::send`).
    pub fn begin(
        &self,
        method: &Method,
        url: &Url,
        headers: &HeaderMap,
        operation: &'static str,
    ) -> Attempt {
        Attempt {
            log: self.clone(),
            started: Instant::now(),
            fields: Some(Fields {
                timestamp: iso_timestamp(SystemTime::now()),
                operation,
                method: method.as_str().to_owned(),
                url: sanitize_url(url),
                request_headers: header_object(
                    headers,
                    REQUEST_HEADERS,
                    false,
                    &self.inner.secrets,
                ),
            }),
        }
    }

    /// Hold every `oauth.token` record finished from now until the hold is released
    /// (the lease is registered) or dropped (DESIGN §2.9).
    pub fn hold_tokens(&self) -> TokenHold {
        lock(&self.inner.holds).active += 1;
        TokenHold {
            log: self.clone(),
            released: false,
        }
    }

    /// Write a finished attempt now, or keep it when it is a token record and a hold
    /// is live.
    fn finished(&self, finished: Finished) {
        if finished.fields.operation == TOKEN_OPERATION {
            let mut holds = lock(&self.inner.holds);
            if holds.active > 0 {
                holds.pending.push(finished);
                return;
            }
        }
        self.write_record(&finished, false);
    }

    /// End one hold; the last one out writes the held records, every header withheld
    /// (the fallback record) when any hold since the last flush was cancelled.
    fn end_hold(&self, cancelled: bool) {
        let (pending, withhold) = {
            let mut holds = lock(&self.inner.holds);
            holds.active = holds.active.saturating_sub(1);
            holds.cancelled |= cancelled;
            if holds.active > 0 {
                return;
            }
            let withhold = std::mem::take(&mut holds.cancelled);
            (std::mem::take(&mut holds.pending), withhold)
        };
        for finished in &pending {
            self.write_record(finished, withhold);
        }
    }

    /// Build the record with the secrets known now, run the line check
    /// (case-insensitive) and write it; `withhold` writes the fallback record.
    fn write_record(&self, finished: &Finished, withhold: bool) {
        let secrets = &self.inner.secrets;
        if !withhold {
            let full = line(&finished.record(secrets, false));
            if !secrets.appears_in_ignoring_case(&full)
                && !secrets.appears_in_ignoring_case(&finished.fields.url)
            {
                self.write_line(&full);
                return;
            }
        }
        let fallback = line(&finished.record(secrets, true));
        if !secrets.appears_in_ignoring_case(&fallback) {
            self.write_line(&fallback);
        }
    }

    /// Write one finished line (with its `"\n"`) in a single `write_all`. The first
    /// failure closes the log and prints the warning once; nothing is retried.
    fn write_line(&self, line: &str) {
        let mut sink = lock(&self.inner.sink);
        let Some(file) = sink.as_mut() else {
            return;
        };
        if file.write_all(line.as_bytes()).is_ok() {
            return;
        }
        *sink = None;
        drop(sink);
        if let Some(mut stderr) = lock(&self.inner.warning).take() {
            let text = format!(
                "  {}\n",
                style::paint(Style::Yellow, WRITE_WARNING, self.inner.warning_color)
            );
            let _ = stderr.write_all(text.as_bytes());
            let _ = stderr.flush();
        }
    }
}

/// Create `dir` (0700 for each component created; an existing directory is never
/// chmod'ed), check the leaf, create this run's file exclusively at 0600, check its
/// owner, then prune. Any failure is the setup error naming `dir`.
fn create_file(dir: &Path, name: &str) -> Result<(PathBuf, fs::File), CliError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| setup_failed(dir))?;
    let metadata = fs::symlink_metadata(dir).map_err(|_| setup_failed(dir))?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(setup_failed(dir));
    }
    let path = dir.join(name);
    let file = OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| setup_failed(dir))?;
    let owned = file
        .metadata()
        .is_ok_and(|file_metadata| file_metadata.uid() == metadata.uid());
    if !owned {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(setup_failed(dir));
    }
    prune(dir, name);
    Ok((path, file))
}

/// Keeps `oauth.token` records unwritten until the lease they issued is in the
/// [`SecretSet`], so a token the server echoes in a header of its own response is
/// masked like every other lease. [`TokenHold::release`] after registering the lease;
/// dropping the hold unreleased (the token future was cancelled) writes the held
/// records without URL or headers (`redactionFallback`).
pub struct TokenHold {
    log: DebugLog,
    released: bool,
}

impl TokenHold {
    /// The lease (if any) is registered: write the held records normally.
    pub fn release(mut self) {
        self.released = true;
        self.log.end_hold(false);
    }
}

impl Drop for TokenHold {
    fn drop(&mut self) {
        if !self.released {
            self.log.end_hold(true);
        }
    }
}

/// One attempt being recorded. Dropping it unfinished (the `send` future was dropped
/// by a deadline, a cancel or a signal) writes the cancelled record.
pub struct Attempt {
    log: DebugLog,
    started: Instant,
    /// `None` once finished.
    fields: Option<Fields>,
}

/// What an attempt records at entry to `send`.
struct Fields {
    timestamp: String,
    operation: &'static str,
    method: String,
    url: String,
    request_headers: OValue,
}

/// An attempt that ended, its response headers still raw (they are filtered when the
/// record is written, against the secrets known then).
struct Finished {
    fields: Fields,
    duration_ms: u64,
    outcome: Outcome,
}

/// How an attempt ended.
enum Outcome {
    Response {
        status: u16,
        status_text: &'static str,
        headers: HeaderMap,
    },
    Failed,
    Cancelled,
}

impl Attempt {
    /// The response headers arrived.
    pub fn response(mut self, status: StatusCode, headers: &HeaderMap) {
        self.finish(Outcome::Response {
            status: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or(""),
            headers: headers.clone(),
        });
    }

    /// `send` returned an error (its text is never logged).
    pub fn failed(mut self) {
        self.finish(Outcome::Failed);
    }

    fn finish(&mut self, outcome: Outcome) {
        let Some(fields) = self.fields.take() else {
            return;
        };
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.log.finished(Finished {
            fields,
            duration_ms,
            outcome,
        });
    }
}

impl Finished {
    /// The record in field order; `fallback` drops the URL and every header and adds
    /// `redactionFallback` (after a line-check hit or a cancelled token hold).
    fn record(&self, secrets: &SecretSet, fallback: bool) -> OValue {
        let fields = &self.fields;
        let text = |value: &str| OValue::String(value.to_owned());
        let mut request = vec![("method".to_owned(), text(&fields.method))];
        if !fallback {
            request.push(("url".to_owned(), text(&fields.url)));
            request.push(("headers".to_owned(), fields.request_headers.clone()));
        }
        let mut entries = vec![
            ("timestamp".to_owned(), text(&fields.timestamp)),
            (
                "durationMs".to_owned(),
                OValue::Number(serde_json::Number::from(self.duration_ms)),
            ),
            ("operation".to_owned(), text(fields.operation)),
            ("request".to_owned(), OValue::Object(request)),
        ];
        match &self.outcome {
            Outcome::Response {
                status,
                status_text,
                headers,
            } => {
                let mut response = vec![
                    (
                        "status".to_owned(),
                        OValue::Number(serde_json::Number::from(*status)),
                    ),
                    ("statusText".to_owned(), text(status_text)),
                ];
                if !fallback {
                    response.push((
                        "headers".to_owned(),
                        header_object(headers, RESPONSE_HEADERS, true, secrets),
                    ));
                }
                entries.push(("response".to_owned(), OValue::Object(response)));
            }
            Outcome::Failed => entries.push(("error".to_owned(), text(REQUEST_FAILED))),
            Outcome::Cancelled => entries.push(("error".to_owned(), text(REQUEST_CANCELLED))),
        }
        if fallback {
            entries.push(("redactionFallback".to_owned(), OValue::Bool(true)));
        }
        OValue::Object(entries)
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}

/// Compact JSON plus `"\n"` (serialising an `OValue` cannot fail).
fn line(record: &OValue) -> String {
    let mut text = json::to_compact(record).unwrap_or_default();
    text.push('\n');
    text
}

/// Every header name once (lowercase, byte order), repeated values joined by `, `,
/// each value written only when allowed.
fn header_object(
    headers: &HeaderMap,
    allowed: &[&str],
    response: bool,
    secrets: &SecretSet,
) -> OValue {
    let names: BTreeSet<&str> = headers.keys().map(|name| name.as_str()).collect();
    OValue::Object(
        names
            .into_iter()
            .map(|name| {
                let values: Vec<String> = headers
                    .get_all(name)
                    .iter()
                    .map(|value| header_value(name, value.as_bytes(), allowed, response, secrets))
                    .collect();
                (name.to_owned(), OValue::String(values.join(", ")))
            })
            .collect(),
    )
}

/// One header value per the allow-list (DESIGN §2.9).
pub fn header_value(
    name: &str,
    bytes: &[u8],
    allowed: &[&str],
    response: bool,
    secrets: &SecretSet,
) -> String {
    let location = response && name == "location";
    if !location && !allowed.contains(&name) {
        return MASK.to_owned();
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return MASK.to_owned();
    };
    let value = if location {
        sanitize_location(text)
    } else {
        text.to_owned()
    };
    if secrets.taints(text) || secrets.taints(&value) {
        MASK.to_owned()
    } else {
        value
    }
}

/// Scheme, host, port and path: no query, no fragment; userinfo becomes `[REDACTED]@`.
pub fn sanitize_url(url: &Url) -> String {
    let mut out = format!("{}://", url.scheme());
    if !url.username().is_empty() || url.password().is_some() {
        out.push_str("[REDACTED]@");
    }
    out.push_str(url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        out.push_str(&format!(":{port}"));
    }
    out.push_str(url.path());
    out
}

/// A `location` value: an absolute URL as [`sanitize_url`], a relative reference as its
/// path alone, anything that does not parse as `***`.
pub fn sanitize_location(text: &str) -> String {
    match Url::parse(text) {
        Ok(url) if !url.cannot_be_a_base() && url.has_host() => sanitize_url(&url),
        Ok(_) => MASK.to_owned(),
        Err(url::ParseError::RelativeUrlWithoutBase) => Url::parse("http://relative.invalid/")
            .and_then(|base| base.join(text))
            .map(|url| url.path().to_owned())
            .unwrap_or_else(|_| MASK.to_owned()),
        Err(_) => MASK.to_owned(),
    }
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC), as JavaScript's `Date.prototype.toISOString`.
pub fn iso_timestamp(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = since.as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        since.subsec_millis()
    )
}

/// Days since 1970-01-01 → (year, month, day) in the proleptic Gregorian calendar
/// (Howard Hinnant's `civil_from_days`).
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month as u32, day as u32)
}

/// The SDK's default operation name of a raw read (`scm::RawRequest::read`; the SDK's
/// `RawRequest::named` is crate-private).
pub const RAW_READ_OPERATION: &str = "custom.read";

tokio::task_local! {
    /// The operation name a raw read sent inside [`named`] carries in the log.
    static RAW_READ_NAME: &'static str;
}

/// Run `future` so that every raw read it sends (operation [`RAW_READ_OPERATION`]) is
/// logged as `operation`: a CLI-side read that replaces a typed SDK call keeps that call's
/// operation name in the `--debug` log (G71, `airs.agentguard.list_scans`). Every other
/// operation (the token request included) keeps its own name.
///
/// Pin constraint: the name is a tokio task-local, so it reaches [`DebugTransport::send`]
/// only because scm-sdk 0.2.2 and 0.2.3 await `Transport::send` inside the caller's future (the
/// engine's `send_buffered` polls it in place; it spawns no task and hands no attempt to
/// another one). An SDK release that moved the attempt onto a spawned task, a channel or
/// a worker pool would log the read as `custom.read` again, with no compile error. Check
/// this before moving the pin; `tests/supplychain_reads.rs::g71::no_scan_page_is_logged_as_a_raw_read`
/// fails if any scan page (a single page, the G63 re-read, every page of a walk) is
/// logged under another name.
pub async fn named<F: std::future::Future>(operation: &'static str, future: F) -> F::Output {
    RAW_READ_NAME.scope(operation, future).await
}

/// The operation an attempt is logged under: a raw read inside [`named`] takes its name.
fn logged_operation(operation: &'static str) -> &'static str {
    if operation == RAW_READ_OPERATION {
        RAW_READ_NAME.try_with(|name| *name).unwrap_or(operation)
    } else {
        operation
    }
}

/// Records every attempt of the transport it wraps; a pass-through without a log, so a
/// `--debug` run uses the same HTTP stack as any other.
pub struct DebugTransport {
    inner: Arc<dyn Transport>,
    log: Option<DebugLog>,
}

impl DebugTransport {
    pub fn wrap(inner: Arc<dyn Transport>, log: Option<&DebugLog>) -> Arc<dyn Transport> {
        Arc::new(Self {
            inner,
            log: log.cloned(),
        })
    }
}

impl Transport for DebugTransport {
    fn send<'a>(
        &'a self,
        request: TransportRequest,
    ) -> BoxFuture<'a, scm::Result<TransportResponse>> {
        let Some(log) = &self.log else {
            return self.inner.send(request);
        };
        let attempt = log.begin(
            request.method(),
            request.url(),
            request.headers(),
            logged_operation(request.operation()),
        );
        observe(attempt, self.inner.send(request))
    }
}

/// Await `sent` and finish `attempt` from its result, which is returned unchanged.
/// Dropping the returned future first records a cancelled attempt.
fn observe<'a>(
    attempt: Attempt,
    sent: BoxFuture<'a, scm::Result<TransportResponse>>,
) -> BoxFuture<'a, scm::Result<TransportResponse>> {
    Box::pin(async move {
        let result = sent.await;
        match &result {
            Ok(response) => attempt.response(response.status(), response.headers()),
            Err(_) => attempt.failed(),
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderName, HeaderValue};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A shared in-memory sink (thread-safe, for the log and the warning).
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(lock(&self.0).clone()).unwrap()
        }
    }

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            lock(&self.0).extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Fails every write and counts the attempts.
    #[derive(Clone, Default)]
    struct Failing(Arc<AtomicUsize>);

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn memory_log(secrets: SecretSet) -> (DebugLog, Shared, Shared) {
        let sink = Shared::default();
        let warning = Shared::default();
        let log = DebugLog::with_sinks(
            PathBuf::from("/x/debug-api-1-a.jsonl"),
            Box::new(sink.clone()),
            Box::new(warning.clone()),
            false,
            secrets,
        );
        (log, sink, warning)
    }

    fn headers(pairs: &[(&str, &[u8])]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_bytes(value).unwrap(),
            );
        }
        map
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn records(sink: &Shared) -> Vec<serde_json::Value> {
        sink.text()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// Replace the volatile timestamp and duration so whole lines can be compared.
    fn stable(line: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let timestamp = value["timestamp"].as_str().unwrap().to_owned();
        let duration = value["durationMs"].to_string();
        line.replacen(&timestamp, "T", 1).replacen(
            &format!("\"durationMs\":{duration}"),
            "\"durationMs\":0",
            1,
        )
    }

    #[test]
    fn header_allow_list_and_masking() {
        let secrets = SecretSet::default();
        secrets.add("s3cr3t-value");
        let request = headers(&[
            ("authorization", b"Basic YWJjOmRlZg"),
            ("x-pan-token", b"tok"),
            ("x-payload-hash", b"abcdef0123"),
            ("cookie", b"a=b"),
            ("proxy-authorization", b"Bearer x"),
            ("x-unknown", b"plain"),
            ("user-agent", b"PAN-AIRS/0.1.1-rust-sdk"),
            ("service-name", b"api"),
            ("content-type", b"application/json"),
            ("accept", b"application/json"),
            ("x-tsg-id", b"100"),
            ("content-length", b"s3cr3t-value"),
        ]);
        let object = header_object(&request, REQUEST_HEADERS, false, &secrets);
        assert_eq!(
            json::to_compact(&object).unwrap(),
            r#"{"accept":"application/json","authorization":"***","content-length":"***","content-type":"application/json","cookie":"***","proxy-authorization":"***","service-name":"api","user-agent":"PAN-AIRS/0.1.1-rust-sdk","x-pan-token":"***","x-payload-hash":"***","x-tsg-id":"100","x-unknown":"***"}"#,
            "names sorted; only allow-listed values; an allow-listed secret masked"
        );
        let response = headers(&[
            ("set-cookie", b"id=1"),
            ("set-cookie", b"id=2"),
            ("vary", b"accept"),
            ("vary", b"origin"),
            ("x-request-id", b"r-1"),
            ("x-request-id", b"s3cr3t-value"),
            ("server", b"\xffbin"),
            ("date", b"Sat, 17 Oct 2026 11:03:44 GMT"),
            ("retry-after", b"0"),
            ("authorization", b"Bearer x"),
        ]);
        let object = header_object(&response, RESPONSE_HEADERS, true, &secrets);
        assert_eq!(
            json::to_compact(&object).unwrap(),
            r#"{"authorization":"***","date":"Sat, 17 Oct 2026 11:03:44 GMT","retry-after":"0","server":"***","set-cookie":"***, ***","vary":"accept, origin","x-request-id":"r-1, ***"}"#,
            "repeated values joined; non-UTF-8 and tainted values masked"
        );
        assert_eq!(
            header_value("x-request-id", b"r-1", REQUEST_HEADERS, false, &secrets),
            MASK,
            "response names are not allowed on requests"
        );
        assert_eq!(
            header_value("location", b"/x?y", REQUEST_HEADERS, false, &secrets),
            MASK,
            "a request location is not allow-listed"
        );
    }

    #[test]
    fn location_is_sanitised() {
        let secrets = SecretSet::default();
        let value = |text: &str| header_value("location", text.as_bytes(), &[], true, &secrets);
        assert_eq!(
            value("https://user:pw@example.com:8443/a/b?token=x#f"),
            "https://[REDACTED]@example.com:8443/a/b"
        );
        assert_eq!(value("/next/page?offset=100&k=v"), "/next/page");
        assert_eq!(value("next?x=1"), "/next");
        assert_eq!(value("//other.example/p?q"), "/p");
        assert_eq!(value("http://[::1]:9/x"), "http://[::1]:9/x");
        assert_eq!(value("http://[bad"), MASK);
        assert_eq!(value("mailto:a@b"), MASK);
        secrets.add("leaky-secret");
        assert_eq!(value("/a/leaky-secret?x"), MASK);
    }

    #[test]
    fn urls_lose_query_fragment_and_userinfo() {
        assert_eq!(
            sanitize_url(&url(
                "https://api.example.com/aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100&latest=true"
            )),
            "https://api.example.com/aisec/v1/mgmt/profiles/tsg/100"
        );
        assert_eq!(
            sanitize_url(&url(
                "http://127.0.0.1:8080/v1/scan/results?scan_ids=a#frag"
            )),
            "http://127.0.0.1:8080/v1/scan/results"
        );
        assert_eq!(
            sanitize_url(&url("https://u:p@h.example/x?")),
            "https://[REDACTED]@h.example/x"
        );
        assert_eq!(
            sanitize_url(&url("https://u@h.example:443/")),
            "https://[REDACTED]@h.example/",
            "the default port is not written"
        );
        assert_eq!(sanitize_url(&url("http://[::1]:9/x")), "http://[::1]:9/x");
    }

    #[test]
    fn record_schema_and_field_order() {
        let (log, sink, warning) = memory_log(SecretSet::default());
        let attempt = log.begin(
            &Method::GET,
            &url("http://127.0.0.1:9/aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100"),
            &headers(&[("authorization", b"Bearer t"), ("service-name", b"api")]),
            "airs.management.profiles.list",
        );
        attempt.response(
            StatusCode::OK,
            &headers(&[("content-type", b"application/json"), ("x-other", b"v")]),
        );
        log.begin(
            &Method::POST,
            &url("http://h.example/oauth/token"),
            &HeaderMap::new(),
            "oauth.token",
        )
        .failed();
        drop(log.begin(
            &Method::POST,
            &url("http://h.example/v1/scan/sync/request"),
            &HeaderMap::new(),
            "airs.scan.sync",
        ));
        log.begin(
            &Method::GET,
            &url("http://h.example/x"),
            &HeaderMap::new(),
            "op",
        )
        .response(StatusCode::from_u16(599).unwrap(), &HeaderMap::new());
        let lines: Vec<String> = sink.text().lines().map(stable).collect();
        assert_eq!(
            lines,
            [
                r#"{"timestamp":"T","durationMs":0,"operation":"airs.management.profiles.list","request":{"method":"GET","url":"http://127.0.0.1:9/aisec/v1/mgmt/profiles/tsg/100","headers":{"authorization":"***","service-name":"api"}},"response":{"status":200,"statusText":"OK","headers":{"content-type":"application/json","x-other":"***"}}}"#,
                r#"{"timestamp":"T","durationMs":0,"operation":"oauth.token","request":{"method":"POST","url":"http://h.example/oauth/token","headers":{}},"error":"Request failed"}"#,
                r#"{"timestamp":"T","durationMs":0,"operation":"airs.scan.sync","request":{"method":"POST","url":"http://h.example/v1/scan/sync/request","headers":{}},"error":"Request cancelled before a response"}"#,
                r#"{"timestamp":"T","durationMs":0,"operation":"op","request":{"method":"GET","url":"http://h.example/x","headers":{}},"response":{"status":599,"statusText":"","headers":{}}}"#,
            ]
        );
        assert!(sink.text().ends_with("}\n"));
        assert_eq!(warning.text(), "");
        for record in records(&sink) {
            let timestamp = record["timestamp"].as_str().unwrap();
            assert_eq!(timestamp.len(), 24, "{timestamp}");
            assert!(timestamp.ends_with('Z'));
            assert!(record.get("body").is_none());
        }
    }

    #[test]
    fn line_check_falls_back_then_skips() {
        let secrets = SecretSet::default();
        secrets.add("path-secret-1");
        let (log, sink, _) = memory_log(secrets.clone());
        log.begin(
            &Method::GET,
            &url("http://h.example/a/path-secret-1/b"),
            &headers(&[("user-agent", b"ua")]),
            "airs.op",
        )
        .response(StatusCode::NOT_FOUND, &headers(&[("date", b"d")]));
        let lines: Vec<String> = sink.text().lines().map(stable).collect();
        assert_eq!(
            lines,
            [
                r#"{"timestamp":"T","durationMs":0,"operation":"airs.op","request":{"method":"GET"},"response":{"status":404,"statusText":"Not Found"},"redactionFallback":true}"#
            ]
        );
        // A secret the fallback itself would carry: nothing is written.
        secrets.add("airs.secret.op");
        log.begin(
            &Method::GET,
            &url("http://h.example/"),
            &HeaderMap::new(),
            "airs.secret.op",
        )
        .failed();
        assert_eq!(sink.text().lines().count(), 1);
        // A lease registered after `begin` is still caught at write time.
        let attempt = log.begin(
            &Method::GET,
            &url("http://h.example/late-lease-9"),
            &HeaderMap::new(),
            "airs.op",
        );
        secrets.add("late-lease-9");
        attempt.failed();
        assert!(
            sink.text()
                .lines()
                .nth(1)
                .unwrap()
                .contains("\"redactionFallback\":true")
        );
        assert!(!sink.text().contains("path-secret-1"));
        assert!(!sink.text().contains("late-lease-9"));
    }

    /// A secret echoed as a response header name is written lowercased; the line
    /// check ignores case, so the record falls back.
    #[test]
    fn line_check_catches_a_case_folded_header_name() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-SECRET-100");
        let (log, sink, _) = memory_log(secrets);
        log.begin(
            &Method::GET,
            &url("http://h.example/"),
            &HeaderMap::new(),
            "airs.op",
        )
        .response(StatusCode::OK, &headers(&[("FAKE-SECRET-100", b"1")]));
        let text = sink.text();
        assert!(text.contains("\"redactionFallback\":true"), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("fake-secret-100"),
            "{text}"
        );
    }

    /// A token record waits for its hold: the lease registered before `release` masks
    /// the token echoed in the response's own headers; other records are not held.
    #[test]
    fn token_records_wait_for_the_lease() {
        let secrets = SecretSet::default();
        let (log, sink, _) = memory_log(secrets.clone());
        let hold = log.hold_tokens();
        log.begin(
            &Method::POST,
            &url("http://h.example/oauth/token"),
            &HeaderMap::new(),
            TOKEN_OPERATION,
        )
        .response(
            StatusCode::OK,
            &headers(&[
                ("x-request-id", b"lease-77"),
                ("content-type", b"application/json"),
            ]),
        );
        assert_eq!(sink.text(), "", "held until the lease is registered");
        log.begin(
            &Method::GET,
            &url("http://h.example/a"),
            &HeaderMap::new(),
            "airs.op",
        )
        .failed();
        assert_eq!(
            sink.text().lines().count(),
            1,
            "only token records are held"
        );
        secrets.add("lease-77");
        hold.release();
        let records = records(&sink);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["operation"], TOKEN_OPERATION);
        assert_eq!(records[1]["response"]["headers"]["x-request-id"], MASK);
        assert_eq!(
            records[1]["response"]["headers"]["content-type"],
            "application/json"
        );
        assert!(!sink.text().contains("lease-77"));
        // Without a hold, a token record is written at once.
        log.begin(
            &Method::POST,
            &url("http://h.example/oauth/token"),
            &HeaderMap::new(),
            TOKEN_OPERATION,
        )
        .failed();
        assert_eq!(sink.text().lines().count(), 3);
    }

    /// A hold dropped unreleased (the token future was cancelled) writes the held
    /// records without URL or headers; nested holds flush when the last one ends.
    #[test]
    fn cancelled_token_hold_withholds_headers() {
        let (log, sink, _) = memory_log(SecretSet::default());
        let outer = log.hold_tokens();
        let inner = log.hold_tokens();
        log.begin(
            &Method::POST,
            &url("http://h.example/oauth/token"),
            &HeaderMap::new(),
            TOKEN_OPERATION,
        )
        .response(
            StatusCode::OK,
            &headers(&[("x-request-id", b"unregistered-lease")]),
        );
        drop(inner);
        assert_eq!(sink.text(), "", "an outer hold is still live");
        outer.release();
        let lines: Vec<String> = sink.text().lines().map(stable).collect();
        assert_eq!(
            lines,
            [
                r#"{"timestamp":"T","durationMs":0,"operation":"oauth.token","request":{"method":"POST"},"response":{"status":200,"statusText":"OK"},"redactionFallback":true}"#
            ]
        );
        // The cancellation does not outlive its flush.
        let hold = log.hold_tokens();
        log.begin(
            &Method::POST,
            &url("http://h.example/oauth/token"),
            &HeaderMap::new(),
            TOKEN_OPERATION,
        )
        .response(StatusCode::OK, &HeaderMap::new());
        hold.release();
        assert!(
            !sink
                .text()
                .lines()
                .nth(1)
                .unwrap()
                .contains("redactionFallback")
        );
    }

    #[test]
    fn write_failure_closes_the_log_and_warns_once() {
        let failing = Failing::default();
        let warning = Shared::default();
        let log = DebugLog::with_sinks(
            PathBuf::from("/x"),
            Box::new(failing.clone()),
            Box::new(warning.clone()),
            false,
            SecretSet::default(),
        );
        for _ in 0..3 {
            log.begin(
                &Method::GET,
                &url("http://h.example/"),
                &HeaderMap::new(),
                "op",
            )
            .response(StatusCode::OK, &HeaderMap::new());
        }
        assert_eq!(failing.0.load(Ordering::SeqCst), 1, "no write is retried");
        assert_eq!(
            warning.text(),
            "  ⚠ Debug: the API log could not be written; it is incomplete\n"
        );
        let coloured = Shared::default();
        let log = DebugLog::with_sinks(
            PathBuf::from("/x"),
            Box::new(Failing::default()),
            Box::new(coloured.clone()),
            true,
            SecretSet::default(),
        );
        log.begin(
            &Method::GET,
            &url("http://h.example/"),
            &HeaderMap::new(),
            "op",
        )
        .failed();
        assert_eq!(
            coloured.text(),
            "  \u{1b}[33m⚠ Debug: the API log could not be written; it is incomplete\u{1b}[39m\n"
        );
    }

    #[test]
    fn observed_results_are_returned_unchanged() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        // A log that cannot be written must not change the response.
        let warning = Shared::default();
        let log = DebugLog::with_sinks(
            PathBuf::from("/x"),
            Box::new(Failing::default()),
            Box::new(warning.clone()),
            false,
            SecretSet::default(),
        );
        let attempt = log.begin(
            &Method::GET,
            &url("http://h.example/"),
            &HeaderMap::new(),
            "op",
        );
        let response = runtime
            .block_on(observe(
                attempt,
                Box::pin(async {
                    Ok(TransportResponse::new(
                        StatusCode::ACCEPTED,
                        headers(&[("x-a", b"1")]),
                        Box::pin(futures_util::stream::empty()),
                    ))
                }),
            ))
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()["x-a"], "1");
        assert!(!warning.text().is_empty());

        let (log, sink, _) = memory_log(SecretSet::default());
        let attempt = log.begin(
            &Method::GET,
            &url("http://h.example/"),
            &HeaderMap::new(),
            "op",
        );
        let failure = runtime.block_on(observe(
            attempt,
            Box::pin(async { Err(scm::Error::new(scm::ErrorKind::Transport)) }),
        ));
        assert_eq!(failure.err().unwrap().kind(), scm::ErrorKind::Transport);
        // Dropped before completion: the cancelled record.
        let attempt = log.begin(
            &Method::GET,
            &url("http://h.example/"),
            &HeaderMap::new(),
            "op",
        );
        drop(observe(attempt, Box::pin(futures_util::future::pending())));
        let errors: Vec<String> = records(&sink)
            .iter()
            .map(|record| record["error"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(errors, [REQUEST_FAILED, REQUEST_CANCELLED]);
    }

    #[test]
    fn timestamps_are_iso_utc_with_milliseconds() {
        let at = |ms: u64| iso_timestamp(UNIX_EPOCH + std::time::Duration::from_millis(ms));
        assert_eq!(at(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(1_792_062_224_500), "2026-10-15T11:03:44.500Z");
        assert_eq!(at(951_782_400_007), "2000-02-29T00:00:00.007Z");
        assert_eq!(at(1_709_251_199_999), "2024-02-29T23:59:59.999Z");
        assert_eq!(at(4_107_542_400_000), "2100-03-01T00:00:00.000Z");
        assert_eq!(at(253_402_300_799_999), "9999-12-31T23:59:59.999Z");
    }

    #[test]
    fn directory_resolution() {
        let home = Path::new("/home/u");
        assert_eq!(
            directory(Some(OsStr::new("/state//x/")), Some(home)).unwrap(),
            Path::new("/state/x/airs-cli/debug")
        );
        assert_eq!(
            directory(None, Some(home)).unwrap(),
            Path::new("/home/u/.local/state/airs-cli/debug")
        );
        assert_eq!(
            directory(Some(OsStr::new("")), Some(home)).unwrap(),
            Path::new("/home/u/.local/state/airs-cli/debug"),
            "an empty XDG_STATE_HOME counts as unset"
        );
        assert_eq!(
            directory(Some(OsStr::new("rel/state")), Some(home))
                .unwrap_err()
                .message(),
            "XDG_STATE_HOME must be an absolute path"
        );
        for home in [None, Some(Path::new("")), Some(Path::new("rel"))] {
            assert_eq!(
                directory(None, home).unwrap_err().message(),
                "Cannot create the debug log: HOME is not an absolute path; set XDG_STATE_HOME or omit --debug"
            );
        }
    }

    #[test]
    fn log_names() {
        assert_eq!(
            file_name(1_792_062_224_500, "0a1b2c3d"),
            "debug-api-1792062224500-0a1b2c3d.jsonl"
        );
        assert_eq!(
            log_timestamp("debug-api-1792062224500-0a1b2c3d.jsonl"),
            Some(1_792_062_224_500)
        );
        for name in [
            "debug-api-179206222450-0a1b2c3d.jsonl",
            "debug-api-1792062224500-0A1B2C3D.jsonl",
            "debug-api-1792062224500-0a1b2c3.jsonl",
            "debug-api-1792062224500-0a1b2c3d.json",
            "xdebug-api-1792062224500-0a1b2c3d.jsonl",
            "debug-api-1792062224500-0a1b2c3d.jsonl.bak",
            "notes.txt",
        ] {
            assert_eq!(log_timestamp(name), None, "{name}");
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "airs-debug-test-{label}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn retention_keeps_the_newest_twenty_including_this_run() {
        let dir = temp_dir("prune");
        let name = |stamp: u64, hex: &str| file_name(u128::from(stamp), hex);
        // 24 old logs; their mtimes disagree with their names (newest name written first).
        for index in (0..24u64).rev() {
            fs::write(dir.join(name(1_700_000_000_000 + index, "aaaaaaaa")), b"").unwrap();
        }
        // Ties on the timestamp are ordered by name.
        fs::write(dir.join(name(1_700_000_000_023, "bbbbbbbb")), b"").unwrap();
        // This run's file is the oldest by name and is still kept.
        let own = name(1_600_000_000_000, "cccccccc");
        fs::write(dir.join(&own), b"").unwrap();
        // Never touched or counted.
        fs::write(dir.join("notes.txt"), b"keep").unwrap();
        fs::create_dir(dir.join(name(1_000_000_000_000, "dddddddd"))).unwrap();
        std::os::unix::fs::symlink("notes.txt", dir.join(name(1_000_000_000_001, "eeeeeeee")))
            .unwrap();
        fs::write(dir.join("debug-api-1-x.jsonl"), b"").unwrap();
        prune(&dir, &own);
        let remaining = names(&dir);
        let logs: Vec<&String> = remaining
            .iter()
            .filter(|name| {
                log_timestamp(name).is_some()
                    && dir.join(name).is_file()
                    && !dir.join(name).is_symlink()
            })
            .collect();
        assert_eq!(logs.len(), KEEP);
        assert!(remaining.contains(&own));
        assert!(remaining.contains(&name(1_700_000_000_023, "bbbbbbbb")));
        assert!(remaining.contains(&name(1_700_000_000_023, "aaaaaaaa")));
        // 19 others kept: the tie pair (023) plus 006..=022.
        assert!(remaining.contains(&name(1_700_000_000_006, "aaaaaaaa")));
        assert!(!remaining.contains(&name(1_700_000_000_005, "aaaaaaaa")));
        assert!(!remaining.contains(&name(1_700_000_000_000, "aaaaaaaa")));
        for kept in [
            "notes.txt".to_owned(),
            "debug-api-1-x.jsonl".to_owned(),
            name(1_000_000_000_000, "dddddddd"),
            name(1_000_000_000_001, "eeeeeeee"),
        ] {
            assert!(remaining.contains(&kept), "{kept}");
        }
        // A second prune (another run converging) removes nothing more.
        prune(&dir, &own);
        assert_eq!(names(&dir), remaining);
        // A missing directory is ignored.
        prune(&dir.join("missing"), &own);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_creates_private_files_and_refuses_unsafe_directories() {
        let root = temp_dir("open");
        let dir = root.join("a/b/airs-cli/debug");
        let log = DebugLog::open(&dir, SecretSet::default(), false).unwrap();
        let mode = |path: &Path| fs::symlink_metadata(path).unwrap().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700 & !umask_bits(&root));
        assert_eq!(mode(&root.join("a")), 0o700 & !umask_bits(&root));
        assert_eq!(mode(log.path()), 0o600);
        let name = log.path().file_name().unwrap().to_str().unwrap().to_owned();
        assert!(log_timestamp(&name).is_some(), "{name}");
        log.begin(
            &Method::GET,
            &url("http://h.example/"),
            &HeaderMap::new(),
            "op",
        )
        .response(StatusCode::OK, &HeaderMap::new());
        assert_eq!(fs::read_to_string(log.path()).unwrap().lines().count(), 1);

        // An existing name (or a symlink at the path) is never opened.
        assert_eq!(
            create_file(&dir, &name).err().unwrap().message(),
            format!(
                "Cannot create the debug log in {}; fix that directory or omit --debug",
                dir.display()
            )
        );
        let target = root.join("target");
        let linked = file_name(1_000_000_000_000, "abcdef01");
        std::os::unix::fs::symlink(&target, dir.join(&linked)).unwrap();
        assert!(create_file(&dir, &linked).is_err());
        assert!(!target.exists(), "the symlink was not followed");

        // An existing 0755 directory is accepted and not chmod'ed.
        let open_dir = root.join("shared");
        fs::create_dir(&open_dir).unwrap();
        fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(DebugLog::open(&open_dir, SecretSet::default(), false).is_ok());
        assert_eq!(mode(&open_dir), 0o755);

        let refused = |dir: &Path| {
            let error = DebugLog::open(dir, SecretSet::default(), false)
                .err()
                .unwrap();
            assert_eq!(
                error.message(),
                format!(
                    "Cannot create the debug log in {}; fix that directory or omit --debug",
                    dir.display()
                )
            );
        };
        let writable = root.join("world");
        fs::create_dir(&writable).unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
        refused(&writable);
        assert_eq!(
            names(&writable).len(),
            0,
            "nothing created in a refused dir"
        );
        let group = root.join("group");
        fs::create_dir(&group).unwrap();
        fs::set_permissions(&group, fs::Permissions::from_mode(0o770)).unwrap();
        refused(&group);
        let link = root.join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        refused(&link);
        let file = root.join("plain-file");
        fs::write(&file, b"").unwrap();
        refused(&file);
        let read_only = root.join("read-only");
        fs::create_dir(&read_only).unwrap();
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o500)).unwrap();
        refused(&read_only);
        refused(&read_only.join("below"));
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    /// The process umask, observed through a directory created with 0777.
    fn umask_bits(root: &Path) -> u32 {
        let probe = root.join(format!("umask-{}", uuid::Uuid::new_v4().simple()));
        DirBuilder::new().mode(0o777).create(&probe).unwrap();
        let bits = !(fs::metadata(&probe).unwrap().mode() & 0o777) & 0o777;
        fs::remove_dir(&probe).unwrap();
        bits
    }

    /// G71: a raw read sent inside `named` is logged under the typed call's operation name;
    /// outside it, and for every other operation (the token request included), the
    /// request's own name stays.
    #[test]
    fn named_raw_reads_take_the_scoped_operation() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let inside = runtime.block_on(named("airs.agentguard.list_scans", async {
            (
                logged_operation(RAW_READ_OPERATION),
                logged_operation(TOKEN_OPERATION),
                logged_operation("custom.request"),
            )
        }));
        assert_eq!(
            inside,
            (
                "airs.agentguard.list_scans",
                TOKEN_OPERATION,
                "custom.request"
            )
        );
        assert_eq!(logged_operation(RAW_READ_OPERATION), RAW_READ_OPERATION);
    }
}
