//! The feature-neutral machinery of every confirming management write (DESIGN §13.2,
//! §15.3, §16.3, §17.3, §18.3): the D81 gate and prompt, the one-attempt send with its
//! outcome and hint lines (D95, D133) and the interruption contexts before and after a
//! write is sent, the bounded `--config` reader and the request-body validation (D116).
//!
//! The per-feature `*_write` modules (`redteam_write`, `dlp_write`, `modelsec_write`,
//! `runtime_write`) are thin wrappers that add their tenant, client and token steps.

use super::Invocation;
use crate::error::{CliError, InterruptContext};
use crate::output::terminal_safe;
use crate::writes::{self, Change};
use std::ffi::OsStr;

/// What an interruption reports for one write: before it was sent and after.
#[derive(Clone, Debug)]
pub struct Contexts {
    pub not_sent: InterruptContext,
    pub sent: InterruptContext,
}

impl Contexts {
    /// `nothing was changed` / `the change may already have been applied (outcome
    /// unknown)` (§15.3 "Interruption").
    pub fn plain() -> Self {
        Self {
            not_sent: InterruptContext::NothingChanged,
            sent: InterruptContext::ChangeMayBeApplied,
        }
    }

    /// A write with its own text once sent (scan start, abort, EULA accept).
    pub fn sent(text: impl Into<String>) -> Self {
        Self {
            not_sent: InterruptContext::NothingChanged,
            sent: InterruptContext::Context(text.into()),
        }
    }

    /// Before the write: a read or the token request that was interrupted.
    pub fn before(&self, error: CliError) -> CliError {
        match error {
            CliError::Interrupted(
                InterruptContext::NoDataWritten | InterruptContext::NothingChanged,
            ) => CliError::Interrupted(self.not_sent.clone()),
            other => other,
        }
    }
}

/// `refusing to <action> without --force in non-interactive mode` (the D81 gate,
/// checked during planning: exit 2 before the tenant).
pub fn gate(force: bool, interactive: bool, action: &str) -> Result<(), CliError> {
    if force || interactive {
        Ok(())
    } else {
        Err(CliError::usage(format!(
            "refusing to {} without --force in non-interactive mode",
            terminal_safe(action)
        )))
    }
}

/// [`gate`] with the terminals of this process (stdin and stderr, §3.10).
pub fn gate_on_terminals(force: bool, action: &str) -> Result<(), CliError> {
    gate(
        force,
        crate::input::Terminals::detect().interactive(),
        action,
    )
}

/// The D81 confirmation (`? <message> (y/N) ` on stderr, terminal-safe); a decline
/// prints `  ℹ Aborted` and returns `false` (exit 0, nothing sent).
pub fn confirm(invocation: &mut Invocation, message: &str) -> Result<bool, CliError> {
    let message = terminal_safe(message).into_owned();
    if super::confirm(invocation, &message)? {
        Ok(true)
    } else {
        invocation.output.info("Aborted");
        Ok(false)
    }
}

/// One write (D95, D133): one attempt with the single 401 replay; an unknown or
/// unreadable outcome gets its outcome line and `hint`; an interruption maps to
/// `contexts`.
pub async fn send<T>(
    invocation: &Invocation,
    change: Change,
    hint: Option<&str>,
    contexts: &Contexts,
    call: impl AsyncFnMut() -> scm::Result<T>,
) -> Result<T, CliError> {
    writes::send_hinted(&invocation.secrets, change, hint, call)
        .await
        .map_err(|error| writes::in_contexts(error, &contexts.not_sent, &contexts.sent))
}

/// A JSON input file of at most 1 MiB that must hold one object (`--config`, §15.3).
pub fn config_object(path: &OsStr) -> Result<serde_json::Value, CliError> {
    crate::files::read_config(path).map(serde_json::Value::Object)
}

/// A request body validated with its SDK schema (D116 text on failure, exit 1).
pub fn body<M>(
    value: serde_json::Value,
    method: &str,
    path: &str,
    parse: impl FnOnce(serde_json::Value, scm::validation::Mode) -> scm::Result<M>,
) -> Result<M, CliError> {
    parse(value, scm::validation::Mode::Request).map_err(|_| writes::invalid_body(method, path))
}
