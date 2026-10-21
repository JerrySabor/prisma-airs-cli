//! `redteam list|ls`, `status`, `categories` and `languages` (DESIGN §15.5).

use super::Invocation;
use super::redteam::{ScanFilters, page_of, page_value, read, value, walk_all, walk_deadline};
use crate::error::CliError;
use crate::json::OValue;
use crate::output::Format;
use crate::redteam::ListParams;
use crate::redteam::views;
use scm::airs::red_team::RedTeamScanListOptions;

/// `redteam list|ls`: one page (`skip` and `limit` always sent, TS), or the `--all` walk
/// from `skip=0` with page size `--limit` (default 10).
pub async fn list(
    invocation: &mut Invocation,
    filters: &ScanFilters,
    params: &ListParams,
    format: Option<Format>,
) -> Result<(), CliError> {
    let limit = params.limit.unwrap_or(10);
    let mut options = RedTeamScanListOptions::default();
    options.status.clone_from(&filters.status);
    options.job_type.clone_from(&filters.job_type);
    options.target_id.clone_from(&filters.target);
    let (rows, format) = if params.all {
        let deadline = walk_deadline()?;
        let connected = invocation.connect_red_team(Some(&deadline)).await?;
        let format = connected.format(format);
        let scans = connected.client.scans();
        let rows = walk_all(invocation, limit, params.max, true, |skip, limit| {
            let mut page = options.clone();
            page.skip = Some(skip);
            page.limit = Some(limit);
            let scans = scans.clone();
            let deadline = deadline.clone();
            async move {
                let answer = scans.list(&page, Some(&deadline)).await?;
                Ok(page_of(&page_value(&answer)?))
            }
        })
        .await?;
        (rows, format)
    } else {
        let connected = invocation.connect_red_team(None).await?;
        let format = connected.format(format);
        options.skip = Some(params.offset.unwrap_or(0));
        options.limit = Some(limit);
        let answer = read(invocation, connected.client.scans().list(&options, None)).await?;
        (page_of(&value(&answer)?).rows, format)
    };
    let mut jobs: Vec<OValue> = rows.iter().map(views::job).collect();
    for job in &mut jobs {
        views::withhold(job, &invocation.secrets);
    }
    let rows: Vec<OValue> = jobs.iter().map(views::job_row).collect();
    let out = &mut invocation.output;
    match format {
        Format::Pretty => views::list(out, format, &jobs, &[], "scans", views::scan_list_layout),
        _ => views::list(out, format, &rows, &views::JOB_COLUMNS, "scans", |_, _| {}),
    }
}

/// `redteam status <jobId>`: `GET <data>/v1/scan/<jobId>`, the `Scan Status:` block.
pub async fn status(
    invocation: &mut Invocation,
    job_id: &str,
    format: Format,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let answer = read(invocation, connected.client.scans().get(job_id, None)).await?;
    let mut job = views::job(&value(&answer)?);
    views::withhold(&mut job, &invocation.secrets);
    views::detail(&mut invocation.output, format, &job, |out| {
        views::scan_status_layout(out, &job);
    })
}

/// `redteam categories`: `GET <data>/v1/categories`.
pub async fn categories(invocation: &mut Invocation, format: Format) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let answer = read(invocation, connected.client.scans().get_categories(None)).await?;
    let mut doc = views::categories(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    views::render_categories(&mut invocation.output, format, &doc)
}

/// `redteam languages [--management]`: the data plane, or the management plane.
pub async fn languages(
    invocation: &mut Invocation,
    management: bool,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_red_team(None).await?;
    let format = connected.format(format);
    let answer = if management {
        read(invocation, connected.client.get_management_languages(None)).await?
    } else {
        read(invocation, connected.client.get_languages(None)).await?
    };
    let mut doc = views::languages(&value(&answer)?);
    views::withhold(&mut doc, &invocation.secrets);
    views::render_languages(&mut invocation.output, format, &doc)
}

// ---------------------------------------------------------------------------
// Writes: `scan` (§15.6) and `abort` (§15.5)
// ---------------------------------------------------------------------------

use super::redteam_write::{self as rw, Contexts};
use crate::error::InterruptContext;
use crate::redteam::args::{self, Goals, ScanSpec};
use crate::writes::Change;
use std::time::Duration;

/// The poll interval of the scan wait (TS `waitForCompletion`).
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

const NO_SCAN_STARTED: &str = "no scan was started";

/// `Scan <uuid> was started and may still be running on AIRS; it was not aborted. …`
fn still_running(uuid: &str) -> String {
    format!(
        "Scan {uuid} was started and may still be running on AIRS; it was not aborted. Check it with 'airs redteam status {uuid}'."
    )
}

/// `redteam scan` (D133–D136): the default categories, one `POST /v1/scan` that is never
/// re-sent, then the bounded wait or the `--no-wait` hint.
pub async fn scan(
    invocation: &mut Invocation,
    spec: &ScanSpec,
    format: Format,
) -> Result<(), CliError> {
    let goals = match &spec.goals {
        Goals::None => Vec::new(),
        Goals::Inline(goals) => goals.clone(),
        Goals::File(path) => {
            let text = crate::files::read_text(path.as_ref(), crate::files::CONFIG_LIMIT)?;
            args::goal_list(&text, "--goals").map_err(CliError::operational)?
        }
    };
    let contexts = Contexts {
        not_sent: InterruptContext::Context(NO_SCAN_STARTED.to_owned()),
        sent: InterruptContext::Context(format!(
            "the scan may already have been started (outcome unknown); check 'airs redteam list --target {}' before starting another",
            spec.target
        )),
    };
    let prepared = rw::connect(invocation, &contexts).await?;
    let scans = prepared.client().scans();
    let categories = match (&spec.categories, spec.job_type.as_str()) {
        (None, "STATIC") => {
            let catalogue = read(invocation, scans.get_categories(None))
                .await
                .map_err(|error| contexts.before(error))?;
            let (categories, count) = args::default_categories(&value(&catalogue)?);
            invocation.output.status(&format!(
                "No --categories given — defaulting to all {count} categories (MULTI_TURN excluded). Pass --categories to narrow the scan."
            ));
            Some(categories)
        }
        (categories, _) => categories.clone(),
    };
    invocation.output.status(&format!(
        "Creating {} scan \"{}\"...",
        spec.job_type,
        crate::output::terminal_safe(&spec.name)
    ));
    let body = rw::body(
        args::scan_body(spec, categories.as_ref(), &goals),
        "POST",
        "/v1/scan",
        scm::airs::red_team::models::JobCreateRequest::parse,
    )?;
    let hint = format!(
        "Check 'airs redteam list --target {}' before starting another scan.",
        spec.target
    );
    let created = rw::send(
        invocation,
        Change::Words("scan", "started"),
        Some(&hint),
        &contexts,
        async || scans.create(&body, None).await,
    )
    .await?;
    let mut created = views::job(&value(&created)?);
    views::withhold(&mut created, &invocation.secrets);
    let uuid = rw::field(&created, "uuid");
    // From here on an interruption leaves the scan running (§15.6 "Interruption").
    invocation.interrupt = Some(InterruptContext::Context(format!(
        "scan {uuid} was started and may still be running on AIRS; it was not aborted"
    )));
    let Some(minutes) = spec.wait_minutes else {
        render_scan(&mut invocation.output, format, &created, None, &uuid)?;
        invocation
            .output
            .status("Run `airs redteam status <jobId>` to check progress.");
        return Ok(());
    };
    invocation.output.status("Waiting for completion...");
    let bound = Duration::from_secs(u64::from(minutes) * 60);
    let mut progress = Progress::new(invocation.terminals.stderr);
    let session = invocation.session.clone();
    let outcome = wait(
        &session,
        POLL_INTERVAL,
        bound,
        async || scans.get(&uuid, None).await,
        |job| {
            let mut doc = views::job(&page_value(job).unwrap_or(OValue::Null));
            views::withhold(&mut doc, &invocation.secrets);
            progress.update(&mut invocation.output, &doc);
            doc
        },
    )
    .await;
    progress.end(&mut invocation.output);
    match outcome {
        Waited::Terminal(job) => {
            let status = rw::field(&job, "status");
            match status.as_str() {
                "FAILED" => Err(CliError::operational(format!("Scan {uuid} failed"))),
                "ABORTED" => Err(CliError::operational(format!("Scan {uuid} was aborted"))),
                _ => {
                    if status == "PARTIALLY_COMPLETE" {
                        invocation
                            .output
                            .warning(&format!("⚠ Scan {uuid} completed partially"));
                    }
                    render_scan(&mut invocation.output, format, &created, Some(&job), &uuid)?;
                    invocation
                        .output
                        .status("Run `airs redteam report <jobId>` to view results.");
                    Ok(())
                }
            }
        }
        Waited::TimedOut => Err(CliError::Operational(crate::error::Failure {
            message: format!("Scan {uuid} did not finish within {minutes} minutes"),
            status: None,
            details: vec![still_running(&uuid)],
        })),
        Waited::Interrupted => Err(CliError::Interrupted(InterruptContext::Context(format!(
            "scan {uuid} was started and may still be running on AIRS; it was not aborted"
        )))),
        Waited::Failed(error) => {
            let failure =
                invocation.management_error(&error, crate::clients::SINGLE_REQUEST_BUDGET);
            Err(match failure {
                CliError::Operational(mut failure) => {
                    failure.details.push(still_running(&uuid));
                    CliError::Operational(failure)
                }
                CliError::Interrupted(_) => {
                    CliError::Interrupted(InterruptContext::Context(format!(
                        "scan {uuid} was started and may still be running on AIRS; it was not aborted"
                    )))
                }
                other => other,
            })
        }
    }
}

/// The scan output: pretty the banner, the `Scan Status:` block of the created job,
/// the final job's block when the wait ended, and `  Job ID  <uuid>`; json and table the
/// last job document.
fn render_scan(
    out: &mut crate::output::Output,
    format: Format,
    created: &OValue,
    last: Option<&OValue>,
    uuid: &str,
) -> Result<(), CliError> {
    let shown = last.unwrap_or(created);
    views::detail(out, format, shown, |out| {
        views::scan_status_layout(out, created);
        if let Some(last) = last {
            views::scan_status_layout(out, last);
        }
        views::job_id_line(out, uuid);
    })
}

/// How a scan wait ended.
#[derive(Debug)]
pub enum Waited {
    /// `COMPLETED`, `PARTIALLY_COMPLETE`, `FAILED` or `ABORTED` (the job document).
    Terminal(OValue),
    /// `--wait-timeout` passed with the scan still running.
    TimedOut,
    /// A signal cancelled the wait.
    Interrupted,
    /// A poll failed after the SDK read retries.
    Failed(scm::Error),
}

/// The terminal job statuses (TS `TERMINAL_STATUSES`).
pub const TERMINAL: [&str; 4] = ["COMPLETED", "PARTIALLY_COMPLETE", "FAILED", "ABORTED"];

/// Poll at once and every `interval` until a terminal status, a poll error, a signal or
/// `bound` (measured from the start; the last sleep is cut to the bound, then one more
/// poll decides). `observe` turns each answer into its job document (and draws the
/// progress).
pub async fn wait<T>(
    session: &scm::Session,
    interval: Duration,
    bound: Duration,
    mut poll: impl AsyncFnMut() -> scm::Result<T>,
    mut observe: impl FnMut(&T) -> OValue,
) -> Waited {
    let start = tokio::time::Instant::now();
    loop {
        if session.is_cancelled() {
            return Waited::Interrupted;
        }
        match poll().await {
            Ok(answer) => {
                let job = observe(&answer);
                if TERMINAL.contains(&rw::field(&job, "status").as_str()) {
                    return Waited::Terminal(job);
                }
            }
            Err(error) if error.kind() == scm::ErrorKind::Cancelled => {
                return Waited::Interrupted;
            }
            Err(error) => return Waited::Failed(error),
        }
        let elapsed = start.elapsed();
        if elapsed >= bound {
            return Waited::TimedOut;
        }
        let pause = interval.min(bound - elapsed);
        tokio::select! {
            () = tokio::time::sleep(pause) => {}
            () = session.cancelled() => return Waited::Interrupted,
        }
    }
}

/// The scan progress on stderr (D135, quiet-suppressed): redrawn with `\r` after each
/// poll on a terminal, one line per change otherwise.
pub struct Progress {
    terminal: bool,
    drawn: bool,
    last: Option<String>,
}

impl Progress {
    pub fn new(terminal: bool) -> Self {
        Self {
            terminal,
            drawn: false,
            last: None,
        }
    }

    /// `<status> <bar> <pct>% (<completed>/<total>)` or `<status>...` (TS
    /// `renderScanProgress`), the status coloured by the stderr decision.
    pub fn text(out: &crate::output::Output, job: &OValue) -> (String, String) {
        let status = rw::field(job, "status");
        let painted = out.paint_err(views::status_style(&status), &status);
        let counts = match (
            crate::json::number(job, "total"),
            crate::json::number(job, "completed"),
        ) {
            (Some(total), Some(completed)) if total > 0.0 => Some((total, completed)),
            _ => None,
        };
        match counts {
            Some((total, completed)) => {
                let pct = (completed / total * 100.0 + 0.5).floor();
                let cells = (pct / 5.0 + 0.5).floor().clamp(0.0, 20.0) as usize;
                let bar = format!("{}{}", "█".repeat(cells), "░".repeat(20 - cells));
                let tail = format!(
                    "{bar} {}% ({}/{})",
                    crate::render::js_number(pct),
                    crate::render::js_number(completed),
                    crate::render::js_number(total)
                );
                (format!("{painted} {tail}"), format!("{status} {tail}"))
            }
            None => (format!("{painted}..."), format!("{status}...")),
        }
    }

    pub fn update(&mut self, out: &mut crate::output::Output, job: &OValue) {
        if out.quiet() {
            return;
        }
        let (painted, plain) = Self::text(out, job);
        if self.terminal {
            out.write_stderr(&format!("\r  {painted}"));
            self.drawn = true;
        } else if self.last.as_deref() != Some(plain.as_str()) {
            out.write_stderr(&format!("  {painted}\n"));
            self.last = Some(plain);
        }
    }

    /// End the redrawn line.
    pub fn end(&mut self, out: &mut crate::output::Output) {
        if self.drawn {
            out.write_stderr("\n");
            self.drawn = false;
        }
    }
}

/// `redteam abort <jobId>` (D133, D137): the prompt (no read first, TS), then one
/// `POST /v1/scan/<jobId>/abort` that is never re-sent.
pub async fn abort(invocation: &mut Invocation, job_id: &str, force: bool) -> Result<(), CliError> {
    let contexts = Contexts::sent("the scan may already have been aborted (outcome unknown)");
    let prepared = invocation
        .red_team_unauthenticated()
        .map_err(|error| contexts.before(error))?;
    if !force && !rw::confirm(invocation, &format!("Abort scan {job_id}?"))? {
        return Ok(());
    }
    rw::authenticate(&prepared, &contexts).await?;
    let scans = prepared.client().scans();
    let hint = format!("Check it with 'airs redteam status {job_id}'.");
    rw::send(
        invocation,
        Change::Words("scan", "aborted"),
        Some(&hint),
        &contexts,
        async || scans.abort(job_id, None).await,
    )
    .await?;
    invocation.committed = true;
    invocation
        .output
        .success(&format!("Scan {job_id} aborted."));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn job(status: &str, completed: u64) -> OValue {
        crate::json::parse(&format!(
            r#"{{"uuid":"u","status":"{status}","total":40,"completed":{completed}}}"#
        ))
        .unwrap()
    }

    fn run(
        answers: Vec<scm::Result<OValue>>,
        interval: Duration,
        bound: Duration,
    ) -> (Waited, usize) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let session = scm::Session::new();
        let queue = RefCell::new(std::collections::VecDeque::from(answers));
        let polls = RefCell::new(0);
        let waited = runtime.block_on(wait(
            &session,
            interval,
            bound,
            async || {
                *polls.borrow_mut() += 1;
                queue
                    .borrow_mut()
                    .pop_front()
                    .unwrap_or_else(|| Ok(job("RUNNING", 1)))
            },
            |answer: &OValue| answer.clone(),
        ));
        let polls = *polls.borrow();
        (waited, polls)
    }

    /// TS `waitForCompletion`: every terminal status ends the wait; the others poll on.
    #[test]
    fn the_wait_ends_at_a_terminal_status() {
        for status in TERMINAL {
            let (waited, polls) = run(
                vec![
                    Ok(job("QUEUED", 0)),
                    Ok(job("RUNNING", 20)),
                    Ok(job(status, 40)),
                ],
                Duration::from_millis(1),
                Duration::from_secs(60),
            );
            assert!(
                matches!(&waited, Waited::Terminal(doc) if rw::field(doc, "status") == status),
                "{status}: {waited:?}"
            );
            assert_eq!(polls, 3, "{status}");
        }
        let (waited, _) = run(
            vec![Ok(job("SOMETHING_NEW", 0)), Ok(job("COMPLETED", 40))],
            Duration::from_millis(1),
            Duration::from_secs(60),
        );
        assert!(
            matches!(waited, Waited::Terminal(_)),
            "unknown statuses keep waiting"
        );
    }

    /// D135: the bound ends the wait after one more poll; a failed poll ends it at once.
    #[test]
    fn the_bound_and_a_failed_poll_end_the_wait() {
        let (waited, polls) = run(Vec::new(), Duration::from_secs(5), Duration::ZERO);
        assert!(matches!(waited, Waited::TimedOut));
        assert_eq!(polls, 1);
        let (waited, polls) = run(
            vec![
                Ok(job("RUNNING", 1)),
                Err(scm::Error::new(scm::ErrorKind::Transport)),
            ],
            Duration::from_millis(1),
            Duration::from_secs(60),
        );
        assert!(matches!(waited, Waited::Failed(_)));
        assert_eq!(polls, 2);
        let (waited, _) = run(
            vec![Err(scm::Error::new(scm::ErrorKind::Cancelled))],
            Duration::from_millis(1),
            Duration::from_secs(60),
        );
        assert!(matches!(waited, Waited::Interrupted));
    }

    /// The TS progress line: a 20-cell bar, `Math.round` percentages; on a terminal it is
    /// redrawn, otherwise written once per change.
    #[test]
    fn progress_lines() {
        let (out, _, _) = crate::output::testing::capture(false);
        assert_eq!(
            Progress::text(&out, &job("RUNNING", 10)).1,
            "RUNNING █████░░░░░░░░░░░░░░░ 25% (10/40)"
        );
        assert_eq!(
            Progress::text(&out, &crate::json::parse(r#"{"status":"QUEUED"}"#).unwrap()).1,
            "QUEUED..."
        );
        assert_eq!(
            Progress::text(&out, &job("RUNNING", 1)).1,
            "RUNNING █░░░░░░░░░░░░░░░░░░░ 3% (1/40)"
        );
        let (mut out, _, stderr) = crate::output::testing::capture(false);
        let mut progress = Progress::new(false);
        for doc in [job("RUNNING", 1), job("RUNNING", 1), job("RUNNING", 40)] {
            progress.update(&mut out, &doc);
        }
        progress.end(&mut out);
        assert_eq!(
            stderr.text(),
            "  RUNNING █░░░░░░░░░░░░░░░░░░░ 3% (1/40)\n  RUNNING ████████████████████ 100% (40/40)\n"
        );
        let (mut out, _, stderr) = crate::output::testing::capture(false);
        let mut progress = Progress::new(true);
        progress.update(&mut out, &job("RUNNING", 20));
        progress.update(&mut out, &job("COMPLETED", 40));
        progress.end(&mut out);
        assert_eq!(
            stderr.text(),
            "\r  RUNNING ██████████░░░░░░░░░░ 50% (20/40)\r  COMPLETED ████████████████████ 100% (40/40)\n"
        );
        let (mut out, _, stderr) = crate::output::testing::capture(true);
        let mut progress = Progress::new(true);
        progress.update(&mut out, &job("RUNNING", 20));
        progress.end(&mut out);
        assert_eq!(stderr.text(), "", "quiet-suppressed");
    }
}
