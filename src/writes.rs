//! One management write (POST, PUT, DELETE) and its outcome (DESIGN §13.2, D95).
//!
//! The SDK never re-sends a write. The CLI adds exactly one replay: a write answered
//! HTTP 401 (`RemoteOutcome::Rejected`, so nothing was processed) is sent once more,
//! after the SDK invalidated the token, so the replay fetches a fresh one. A 403 is
//! never replayed (the CLI cannot see `x-opa-decision`). A failure whose outcome is not
//! a plain rejection gets one detail line saying what may or did happen, and the hint
//! after it ([`OutcomeLines`], [`describe`]): one rule for every milestone's writes.

use crate::clients::SINGLE_REQUEST_BUDGET;
use crate::error::{
    self, CliError, InterruptContext, Operation, Phase, Plane, SdkContext, SecretSet,
};
use scm::{ErrorKind, RemoteOutcome};

/// The detail lines a failed write adds when its outcome is not a plain rejection
/// ([`describe`]): the unknown line when it may have been applied, the unreadable line for a
/// 2xx whose answer could not be decoded, and the optional hint after either. [`Change`]
/// (topics, profiles, red team), [`Lines`] (owned texts), [`Hinted`] and the gateway's
/// `Words` and `SecretWrite` implement it.
pub trait OutcomeLines {
    /// `Outcome unknown: …`.
    fn unknown_line(&self) -> String;
    /// `Outcome: … could not be read.`
    fn unreadable_line(&self) -> String;
    /// The line after either (`Check it with '…' before …`); none by default.
    fn hint(&self) -> Option<String> {
        None
    }
}

impl<T: OutcomeLines + ?Sized> OutcomeLines for &T {
    fn unknown_line(&self) -> String {
        (**self).unknown_line()
    }
    fn unreadable_line(&self) -> String {
        (**self).unreadable_line()
    }
    fn hint(&self) -> Option<String> {
        (**self).hint()
    }
}

/// Outcome lines given as texts (a write whose lines name more than `<thing> <done>`, such
/// as a gateway workspace create that keeps its IAM scope).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lines {
    pub unknown: String,
    pub unreadable: String,
    pub hint: Option<String>,
}

impl OutcomeLines for Lines {
    fn unknown_line(&self) -> String {
        self.unknown.clone()
    }
    fn unreadable_line(&self) -> String {
        self.unreadable.clone()
    }
    fn hint(&self) -> Option<String> {
        self.hint.clone()
    }
}

/// `lines` with `hint` after its unknown or unreadable line (none when `None`).
#[derive(Clone, Copy, Debug)]
pub struct Hinted<'a, L>(pub L, pub Option<&'a str>);

impl<L: OutcomeLines> OutcomeLines for Hinted<'_, L> {
    fn unknown_line(&self) -> String {
        self.0.unknown_line()
    }
    fn unreadable_line(&self) -> String {
        self.0.unreadable_line()
    }
    fn hint(&self) -> Option<String> {
        self.1.map(str::to_owned)
    }
}

/// What a write does, for its outcome lines (`<thing> <done>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    TopicCreated,
    TopicUpdated,
    TopicDeleted,
    ProfileCreated,
    ProfileUpdated,
    ProfileDeleted,
    /// A red team write (DESIGN §15.3 "Writes and outcomes"): `(thing, done)`.
    Words(&'static str, &'static str),
}

impl Change {
    /// `(thing, done)`: `("topic", "created")`.
    pub fn words(self) -> (&'static str, &'static str) {
        match self {
            Self::TopicCreated => ("topic", "created"),
            Self::TopicUpdated => ("topic", "updated"),
            Self::TopicDeleted => ("topic", "deleted"),
            Self::ProfileCreated => ("profile", "created"),
            Self::ProfileUpdated => ("profile", "updated"),
            Self::ProfileDeleted => ("profile", "deleted"),
            Self::Words(thing, done) => (thing, done),
        }
    }
}

impl OutcomeLines for Change {
    /// `Outcome unknown: the <thing> may have been <done>.`
    fn unknown_line(&self) -> String {
        let (thing, done) = self.words();
        format!("Outcome unknown: the {thing} may have been {done}.")
    }

    /// `Outcome: the <thing> was <done>, but the response could not be read.`
    fn unreadable_line(&self) -> String {
        let (thing, done) = self.words();
        format!("Outcome: the {thing} was {done}, but the response could not be read.")
    }
}

/// Whether a failed write is a plain 401 rejection, which the CLI replays once.
fn replayable(error: &scm::Error) -> bool {
    error.kind() == ErrorKind::Http
        && error.status() == Some(401)
        && error.remote_outcome() == RemoteOutcome::Rejected
}

/// Send one write with `call`, replaying it once after a 401 (D95); the SDK error of
/// the final attempt is returned as is.
pub async fn attempt<T>(mut call: impl AsyncFnMut() -> scm::Result<T>) -> scm::Result<T> {
    match call().await {
        Err(error) if replayable(&error) => call().await,
        other => other,
    }
}

/// [`attempt`], with the error described by [`describe`]: the §6 message plus the
/// outcome detail line.
pub async fn send<T>(
    secrets: &SecretSet,
    change: Change,
    call: impl AsyncFnMut() -> scm::Result<T>,
) -> Result<T, CliError> {
    attempt(call)
        .await
        .map_err(|error| describe(&error, change, secrets))
}

/// [`send`] with one extra detail line after an unknown or unreadable outcome (the
/// red team hints of §15.3, such as `Check it with '…' before accepting again.`).
pub async fn send_hinted<T>(
    secrets: &SecretSet,
    change: Change,
    hint: Option<&str>,
    call: impl AsyncFnMut() -> scm::Result<T>,
) -> Result<T, CliError> {
    attempt(call)
        .await
        .map_err(|error| describe(&error, Hinted(change, hint), secrets))
}

/// The failure of a write: the §6 message, then `Outcome unknown: …` when the write may
/// have been applied ([`Failure::Unknown`]), or `Outcome: … could not be read.` for a 2xx
/// whose body could not be decoded (the write was applied, G4; [`Failure::Unreadable`]),
/// and the hint of `lines` after either. An interruption maps to its §13.2 context.
pub fn describe(error: &scm::Error, lines: impl OutcomeLines, secrets: &SecretSet) -> CliError {
    let mut failure = error::from_sdk(
        error,
        &SdkContext {
            plane: Plane::Management,
            phase: Phase::Api,
            operation: Operation::Write,
            timeout: SINGLE_REQUEST_BUDGET,
            secrets,
        },
    );
    if let CliError::Operational(failure) = &mut failure {
        let line = match classify(error) {
            Failure::Unreadable => Some(lines.unreadable_line()),
            Failure::Unknown => Some(lines.unknown_line()),
            _ => None,
        };
        if let Some(line) = line {
            failure.details.push(line);
            failure.details.extend(lines.hint());
        }
    }
    failure
}

/// `failure` with an interruption mapped to the command's own contexts: `not_sent` when
/// nothing was sent ([`InterruptContext::NothingChanged`]), `sent` when the change may
/// have been applied.
pub fn in_contexts(
    failure: CliError,
    not_sent: &InterruptContext,
    sent: &InterruptContext,
) -> CliError {
    match failure {
        CliError::Interrupted(InterruptContext::NothingChanged) => {
            CliError::Interrupted(not_sent.clone())
        }
        CliError::Interrupted(InterruptContext::ChangeMayBeApplied) => {
            CliError::Interrupted(sent.clone())
        }
        other => other,
    }
}

/// The local schema failure of a request body (D116): `<METHOD> <path>` names the
/// request, the id included.
pub fn invalid_body(method: &str, path: &str) -> CliError {
    CliError::operational(format!(
        "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for {method} {path} did not match schema"
    ))
}

/// How one write that failed ended (D95, D177, D217): the restore executors' outcome
/// rows and texts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// A definite rejection (3xx, 4xx): nothing was created.
    Rejected(Option<u16>),
    /// Sent; the outcome is unknown (5xx, transport, timeout).
    Unknown,
    /// Applied, but the answer could not be read.
    Unreadable,
    /// A local failure before dispatch.
    Local,
    /// A signal stopped it; `sent`: the request may have reached the service.
    Interrupted { sent: bool },
}

/// The [`Failure`] of an SDK error from a write.
pub fn classify(error: &scm::Error) -> Failure {
    match error.kind() {
        ErrorKind::Cancelled => Failure::Interrupted {
            sent: error.remote_outcome() != RemoteOutcome::NotSent,
        },
        ErrorKind::Decode
            if error
                .status()
                .is_some_and(|status| (200..300).contains(&status)) =>
        {
            Failure::Unreadable
        }
        _ if error.remote_outcome() == RemoteOutcome::Unknown => Failure::Unknown,
        ErrorKind::Http if error.remote_outcome() == RemoteOutcome::Rejected => {
            Failure::Rejected(error.status())
        }
        _ => Failure::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Failure, InterruptContext};

    #[test]
    fn outcome_lines() {
        assert_eq!(
            Change::TopicCreated.unknown_line(),
            "Outcome unknown: the topic may have been created."
        );
        assert_eq!(
            Change::ProfileDeleted.unreadable_line(),
            "Outcome: the profile was deleted, but the response could not be read."
        );
        assert_eq!(Change::ProfileUpdated.words(), ("profile", "updated"));
    }

    /// Every milestone's lines go through one trait: [`Lines`] (owned texts, the gateway
    /// workspace steps) and [`Hinted`] carry the hint that [`describe`] appends after an
    /// unknown or unreadable line; a local failure adds neither line nor hint.
    #[test]
    fn outcome_lines_carry_their_hint() {
        let lines = Lines {
            unknown: "Outcome unknown: u.".into(),
            unreadable: "Outcome: r.".into(),
            hint: Some("Check it.".into()),
        };
        // A reference serves as its lines (the gateway passes `&Lines`).
        fn read(lines: impl OutcomeLines) -> (String, Option<String>) {
            (lines.unknown_line(), lines.hint())
        }
        assert_eq!(
            read(&lines),
            (
                "Outcome unknown: u.".to_owned(),
                Some("Check it.".to_owned())
            )
        );
        let hinted = Hinted(Change::TopicCreated, Some("Look first."));
        assert_eq!(
            hinted.unreadable_line(),
            Change::TopicCreated.unreadable_line()
        );
        assert_eq!(hinted.hint().as_deref(), Some("Look first."));
        assert_eq!(Change::TopicCreated.hint(), None);
        let secrets = SecretSet::default();
        let local = describe(&scm::Error::new(ErrorKind::Validation), &lines, &secrets);
        assert_eq!(
            local.message(),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Validation error"
        );
        assert!(matches!(local, CliError::Operational(f) if f.details.is_empty()));
        let interrupted = in_contexts(
            describe(&scm::Error::new(ErrorKind::Cancelled), hinted, &secrets),
            &InterruptContext::Context("not sent".into()),
            &InterruptContext::ChangeMayBeApplied,
        );
        assert_eq!(
            interrupted,
            CliError::Interrupted(InterruptContext::Context("not sent".into()))
        );
    }

    #[test]
    fn local_and_rejected_failures_add_no_outcome_line() {
        let secrets = SecretSet::default();
        let validation = describe(
            &scm::Error::new(ErrorKind::Validation),
            Change::TopicCreated,
            &secrets,
        );
        assert_eq!(
            validation,
            CliError::Operational(Failure {
                message: "AISEC_USER_REQUEST_PAYLOAD_ERROR:Validation error".into(),
                status: None,
                details: Vec::new(),
            })
        );
        let cancelled = describe(
            &scm::Error::new(ErrorKind::Cancelled),
            Change::TopicDeleted,
            &secrets,
        );
        assert_eq!(
            cancelled,
            CliError::Interrupted(InterruptContext::NothingChanged)
        );
        assert_eq!(
            invalid_body("POST", "/v1/mgmt/profile").message(),
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/mgmt/profile did not match schema"
        );
    }
}
