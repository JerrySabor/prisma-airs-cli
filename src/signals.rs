//! Process-lifetime SIGINT/SIGTERM handling (DESIGN §2.5).
//!
//! A dedicated thread with its own small Tokio runtime owns the signal streams for the
//! whole life of the process, so signals are acted on while a synchronous command runs,
//! while stdout blocks during a commit, and while the command runtime shuts down. The
//! first signal records its exit code and cancels the invocation's SDK session; a second
//! signal exits at once with the first signal's code. A signal that arrives while stdout
//! is being written cannot be honoured by cancellation (the write may block forever on a
//! stalled reader), so it ends the process at once.
//!
//! The tenant write commands add two phases in which the first signal also ends the
//! process at once: a prompt (the saved terminal mode is restored and the status
//! `Cancelled; no configuration saved.` is printed) and a wait for piped stdin or the
//! store lock (`Interrupted; no configuration was changed`).

use crate::error::{CliError, InterruptContext};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// How long the signal thread lets its final stderr message take before exiting anyway
/// (stderr may be the same stalled pipe as stdout).
const MESSAGE_GRACE: Duration = Duration::from_millis(200);

/// The test harness's synchronisation point (DESIGN §2.5, choice 129): when this variable
/// names an absolute path, the signal thread creates that file (empty, 0600, never
/// replacing one) right after it has recorded a signal and before it acts on it, so a
/// test can wait for the record instead of sleeping. It carries no configuration,
/// credential or endpoint and changes nothing else; a failure to create the file is
/// ignored. Debug builds only (like the `--fetch-uv` hook, choice 36 of §17): a release
/// build contains neither the variable name nor the lookup.
#[cfg(debug_assertions)]
pub const SIGNAL_MARKER_VAR: &str = "AIRS_CLI_TEST_SIGNAL_MARKER";

/// The [`SIGNAL_MARKER_VAR`] path, when set and absolute (always `None` in a release
/// build).
fn marker_path() -> Option<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(SIGNAL_MARKER_VAR)
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// Shared between the signal thread and the command thread.
#[derive(Debug, Default)]
pub struct SignalState {
    /// Exit code of the first signal; 0 until one arrives.
    code: AtomicI32,
    /// Whether stdout is being written right now.
    writing: AtomicBool,
    /// What the command thread waits for ([`Phase`] as a number).
    phase: AtomicU8,
    /// The terminal mode a hidden prompt changed, restored when a signal ends it.
    saved_termios: Mutex<Option<rustix::termios::Termios>>,
    /// `--quiet`: the cancellation status is not printed.
    quiet: AtomicBool,
    /// A runtime write command's confirmation is waiting: a cancelled prompt prints
    /// [`CANCELLED_NOTHING_CHANGED`] instead of [`CANCELLED`] (DESIGN §13.2).
    runtime_prompt: AtomicBool,
    /// The process group of a running child (`model-security install`'s uv steps,
    /// DESIGN §17.13); 0 when none runs.
    child: AtomicI32,
    /// Whether the first signal was forwarded to the child's group already (exactly once,
    /// whichever thread sees both the signal and the child first).
    forwarded: AtomicBool,
}

/// What the command thread is blocked on (DESIGN §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Running: the first signal cancels the session and is reported at the end.
    Normal,
    /// A prompt or the delete confirmation waits for the user.
    Prompt,
    /// Piped stdin or the store lock is awaited.
    Waiting,
    /// A runtime write's piped stdin body (`--body -`) is awaited: the first signal ends
    /// the process with `nothing was changed` (DESIGN §16.3).
    WaitingBody,
}

impl Phase {
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Prompt,
            2 => Self::Waiting,
            3 => Self::WaitingBody,
            _ => Self::Normal,
        }
    }
    fn raw(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Prompt => 1,
            Self::Waiting => 2,
            Self::WaitingBody => 3,
        }
    }
}

/// The status printed when a prompt is cancelled (TypeScript text).
pub const CANCELLED: &str = "Cancelled; no configuration saved.";

/// The status printed when an M4 confirmation is cancelled (DESIGN §13.2).
pub const CANCELLED_NOTHING_CHANGED: &str = "Cancelled; nothing was changed.";

/// What the signal thread does with one signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// First signal: cancel the session; the command reports the interruption.
    Cancel,
    /// Exit now with this code, printing the interruption context when given.
    Exit(i32, Option<InterruptContext>),
    /// A prompt was waiting: restore the terminal, print [`CANCELLED`], exit.
    CancelPrompt(i32),
    /// A child runs in its own process group (DESIGN §17.13, D200): cancel the session
    /// and forward the first signal (this exit code) to the group once; the command waits
    /// for the child.
    ForwardToChild(i32),
    /// A later signal while the child runs: `SIGKILL` its group; the command still waits.
    KillChild,
}

impl Action {
    /// Whether the signal thread restores a saved terminal mode before acting: always
    /// when the process ends, so a second signal during a hidden prompt (whose first
    /// one only cancelled) never leaves the terminal without echo.
    pub fn restores_terminal(&self) -> bool {
        !matches!(
            self,
            Self::Cancel | Self::ForwardToChild(_) | Self::KillChild
        )
    }
}

impl SignalState {
    /// The exit code of the first signal, once one arrived.
    pub fn code(&self) -> Option<i32> {
        match self.code.load(Ordering::SeqCst) {
            0 => None,
            code => Some(code),
        }
    }

    /// Mark stdout as being written until the guard drops. The flag is raised before
    /// the caller checks [`SignalState::code`], and the signal thread records the code
    /// before it reads the flag, so a signal is never missed by both sides.
    pub fn begin_write(&self) -> WriteGuard<'_> {
        self.writing.store(true, Ordering::SeqCst);
        WriteGuard(self)
    }

    /// Mark the command thread as blocked on `phase` until the guard drops.
    pub fn enter(&self, phase: Phase) -> PhaseGuard<'_> {
        self.phase.store(phase.raw(), Ordering::SeqCst);
        PhaseGuard(self)
    }

    /// The current phase.
    pub fn phase(&self) -> Phase {
        Phase::from_raw(self.phase.load(Ordering::SeqCst))
    }

    /// Remember (or forget) the terminal mode to restore if a prompt is cancelled.
    pub fn save_termios(&self, termios: Option<rustix::termios::Termios>) {
        *self
            .saved_termios
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = termios;
    }

    /// `--quiet` for the cancellation status.
    pub fn set_quiet(&self, quiet: bool) {
        self.quiet.store(quiet, Ordering::SeqCst);
    }

    /// The prompts of this run are M4 confirmations ([`CANCELLED_NOTHING_CHANGED`]).
    pub fn set_runtime_prompt(&self) {
        self.runtime_prompt.store(true, Ordering::SeqCst);
    }

    /// The status a cancelled prompt of this run prints.
    pub fn cancelled_status(&self) -> &'static str {
        if self.runtime_prompt.load(Ordering::SeqCst) {
            CANCELLED_NOTHING_CHANGED
        } else {
            CANCELLED
        }
    }

    /// Restore the saved terminal mode (best effort); whether one was saved.
    pub fn restore_termios(&self) -> bool {
        let saved = self
            .saved_termios
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match saved {
            Some(termios) => {
                let _ = rustix::termios::tcsetattr(
                    std::io::stdin(),
                    rustix::termios::OptionalActions::Now,
                    &termios,
                );
                true
            }
            None => false,
        }
    }

    /// A child now runs in process group `pgid` (DESIGN §17.13). A signal that arrived
    /// before is forwarded now (once).
    pub fn attach_child(&self, pgid: i32) {
        self.forwarded.store(false, Ordering::SeqCst);
        self.child.store(pgid, Ordering::SeqCst);
        if let Some(code) = self.code() {
            self.forward_once(code);
        }
    }

    /// The child was reaped.
    pub fn detach_child(&self) {
        self.child.store(0, Ordering::SeqCst);
    }

    /// The process group of the running child, if any.
    pub fn child(&self) -> Option<i32> {
        match self.child.load(Ordering::SeqCst) {
            0 => None,
            pgid => Some(pgid),
        }
    }

    /// Forward the signal of exit code `code` to the child's group, at most once.
    pub fn forward_once(&self, code: i32) {
        let Some(pgid) = self.child() else {
            return;
        };
        if self.forwarded.swap(true, Ordering::SeqCst) {
            return;
        }
        let signal = if code == crate::error::EXIT_SIGTERM {
            rustix::process::Signal::TERM
        } else {
            rustix::process::Signal::INT
        };
        signal_group(pgid, signal);
    }

    /// Decide what one arriving signal (exit code `code`) does.
    pub fn on_signal(&self, code: i32) -> Action {
        match self
            .code
            .compare_exchange(0, code, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) if self.child().is_some() => Action::ForwardToChild(code),
            Err(_) if self.child().is_some() => Action::KillChild,
            Ok(_) if self.writing.load(Ordering::SeqCst) => {
                Action::Exit(code, Some(InterruptContext::OutputIncomplete))
            }
            Ok(_) => match self.phase() {
                Phase::Prompt => Action::CancelPrompt(code),
                Phase::Waiting => {
                    Action::Exit(code, Some(InterruptContext::NoConfigurationChanged))
                }
                Phase::WaitingBody => Action::Exit(code, Some(InterruptContext::NothingChanged)),
                Phase::Normal => Action::Cancel,
            },
            // A second signal exits immediately with the first signal's code.
            Err(first) => Action::Exit(first, None),
        }
    }
}

/// Send `signal` to the process group `pgid` (best effort).
fn signal_group(pgid: i32, signal: rustix::process::Signal) {
    if let Some(pid) = rustix::process::Pid::from_raw(pgid) {
        let _ = rustix::process::kill_process_group(pid, signal);
    }
}

/// Returns the command thread to [`Phase::Normal`] when dropped.
#[derive(Debug)]
pub struct PhaseGuard<'a>(&'a SignalState);

impl Drop for PhaseGuard<'_> {
    fn drop(&mut self) {
        self.0.phase.store(Phase::Normal.raw(), Ordering::SeqCst);
    }
}

/// Clears the writing flag when dropped.
#[derive(Debug)]
pub struct WriteGuard<'a>(&'a SignalState);

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        self.0.writing.store(false, Ordering::SeqCst);
    }
}

/// Start the signal thread. Without a usable signal runtime the process keeps the
/// default signal disposition (it is killed by the signal).
pub fn install(session: scm::Session) -> Arc<SignalState> {
    let marker = marker_path();
    let state = Arc::new(SignalState::default());
    let thread_state = Arc::clone(&state);
    let (ready, listening) = std::sync::mpsc::channel::<()>();
    let started = std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                let _ = ready.send(());
                return;
            };
            runtime.block_on(watch(&thread_state, &session, ready, marker.as_deref()));
        });
    if started.is_ok() {
        // Signals are only caught once the streams are registered; wait for that so a
        // signal sent right after start is never lost (bounded, in case of failure).
        let _ = listening.recv_timeout(Duration::from_secs(5));
    }
    state
}

async fn watch(
    state: &SignalState,
    session: &scm::Session,
    ready: std::sync::mpsc::Sender<()>,
    marker: Option<&std::path::Path>,
) {
    #[cfg(unix)]
    {
        use crate::error::{EXIT_SIGINT, EXIT_SIGTERM};
        use tokio::signal::unix::{SignalKind, signal as listen};
        let (Ok(mut interrupt), Ok(mut terminate)) = (
            listen(SignalKind::interrupt()),
            listen(SignalKind::terminate()),
        ) else {
            let _ = ready.send(());
            return;
        };
        let _ = ready.send(());
        loop {
            let code = tokio::select! {
                _ = interrupt.recv() => EXIT_SIGINT,
                _ = terminate.recv() => EXIT_SIGTERM,
            };
            let action = state.on_signal(code);
            mark(marker);
            act(state, action, session);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ready.send(());
        while tokio::signal::ctrl_c().await.is_ok() {
            let action = state.on_signal(crate::error::EXIT_SIGINT);
            mark(marker);
            act(state, action, session);
        }
    }
}

/// Create the [`SIGNAL_MARKER_VAR`] file, if one is named (best effort).
fn mark(marker: Option<&std::path::Path>) {
    if let Some(path) = marker {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let _ = options.open(path);
    }
}

/// Write `text` to stderr from a helper thread, waiting at most [`MESSAGE_GRACE`] (a
/// stalled stderr cannot keep the process alive).
fn write_stderr_briefly(text: String) {
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let _ = std::thread::Builder::new().spawn(move || {
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_all(text.as_bytes());
        let _ = stderr.flush();
        let _ = done.send(());
    });
    let _ = finished.recv_timeout(MESSAGE_GRACE);
}

/// The stderr bytes of a cancelled prompt: a line break ending the prompt line, then
/// the status unless `--quiet`.
#[cfg(test)]
pub fn cancelled_text(quiet: bool, color: bool) -> String {
    cancelled_text_with(CANCELLED, quiet, color)
}

/// [`cancelled_text`] with the given status.
pub fn cancelled_text_with(status: &str, quiet: bool, color: bool) -> String {
    if quiet {
        "\n".to_owned()
    } else {
        format!(
            "\n  {}\n",
            crate::render::style::paint(crate::render::style::Style::Dim, status, color)
        )
    }
}

fn act(state: &SignalState, action: Action, session: &scm::Session) {
    if action.restores_terminal() {
        state.restore_termios();
    }
    match action {
        Action::Cancel => session.cancel(),
        Action::ForwardToChild(code) => {
            session.cancel();
            state.forward_once(code);
        }
        Action::KillChild => {
            if let Some(pgid) = state.child() {
                signal_group(pgid, rustix::process::Signal::KILL);
            }
        }
        Action::CancelPrompt(code) => {
            session.cancel();
            write_stderr_briefly(cancelled_text_with(
                state.cancelled_status(),
                state.quiet.load(Ordering::SeqCst),
                crate::render::style::stderr_color(),
            ));
            std::process::exit(code);
        }
        Action::Exit(code, context) => {
            session.cancel();
            if let Some(context) = context {
                write_stderr_briefly(
                    CliError::Interrupted(context)
                        .render_colored(crate::render::style::stderr_color()),
                );
            }
            std::process::exit(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test marker is an empty 0600 file, never replacing one; no name, no file.
    #[test]
    fn the_signal_marker_is_a_new_private_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_support::TempDir::new("signal-marker");
        let path = dir.join("marker");
        mark(None);
        mark(Some(&path));
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        std::fs::write(&path, "kept").unwrap();
        mark(Some(&path));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "kept");
    }

    #[test]
    fn first_signal_cancels_and_second_exits_with_the_first_code() {
        let state = SignalState::default();
        assert_eq!(state.code(), None);
        assert_eq!(state.on_signal(130), Action::Cancel);
        assert_eq!(state.code(), Some(130));
        assert_eq!(state.on_signal(143), Action::Exit(130, None));
        assert_eq!(state.code(), Some(130), "the first code is kept");
        // Every action that ends the process restores the terminal first; only the
        // first signal outside a prompt or wait (which cancels) does not.
        assert!(!Action::Cancel.restores_terminal());
        assert!(Action::Exit(130, None).restores_terminal());
        assert!(Action::Exit(143, Some(InterruptContext::OutputIncomplete)).restores_terminal());
        assert!(Action::CancelPrompt(130).restores_terminal());
    }

    /// D200: while a child runs, the first signal is forwarded (the command waits) and a
    /// second one kills the child's group instead of exiting.
    #[test]
    fn a_running_child_gets_the_signal_and_the_command_waits() {
        let state = SignalState::default();
        state.attach_child(999_999);
        assert_eq!(state.child(), Some(999_999));
        assert_eq!(state.on_signal(143), Action::ForwardToChild(143));
        assert_eq!(state.on_signal(130), Action::KillChild);
        assert!(!Action::ForwardToChild(143).restores_terminal());
        assert!(!Action::KillChild.restores_terminal());
        state.detach_child();
        assert_eq!(state.child(), None);
        assert_eq!(state.on_signal(130), Action::Exit(143, None));
    }

    #[test]
    fn a_signal_during_a_stdout_write_exits_at_once() {
        let state = SignalState::default();
        {
            let _writing = state.begin_write();
            assert_eq!(
                state.on_signal(143),
                Action::Exit(143, Some(InterruptContext::OutputIncomplete))
            );
        }
        let state = SignalState::default();
        drop(state.begin_write());
        assert_eq!(
            state.on_signal(143),
            Action::Cancel,
            "the guard cleared the flag"
        );
    }

    #[test]
    fn prompts_and_waits_end_the_process_at_once() {
        let state = SignalState::default();
        {
            let _prompt = state.enter(Phase::Prompt);
            assert_eq!(state.phase(), Phase::Prompt);
            assert_eq!(state.on_signal(130), Action::CancelPrompt(130));
        }
        assert_eq!(state.phase(), Phase::Normal, "the guard restored the phase");
        let state = SignalState::default();
        {
            let _wait = state.enter(Phase::Waiting);
            assert_eq!(
                state.on_signal(143),
                Action::Exit(143, Some(InterruptContext::NoConfigurationChanged))
            );
        }
        let state = SignalState::default();
        {
            let _wait = state.enter(Phase::WaitingBody);
            assert_eq!(
                state.on_signal(130),
                Action::Exit(130, Some(InterruptContext::NothingChanged))
            );
        }
        assert_eq!(state.phase(), Phase::Normal);
        assert!(!state.restore_termios(), "nothing saved");
        assert_eq!(
            cancelled_text(false, false),
            "\n  Cancelled; no configuration saved.\n"
        );
        assert_eq!(cancelled_text(true, false), "\n");
        assert_eq!(
            cancelled_text(false, true),
            "\n  \u{1b}[2mCancelled; no configuration saved.\u{1b}[22m\n"
        );
    }
}
