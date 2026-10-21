//! The one-time credential channel of the gateway (DESIGN §19.11, D237, G36): `api-keys
//! service|user create|rotate`, `deployments create` and a rotating `deployments update`.
//!
//! The only channel is a required `--secret-output <new path>` (the D204 pattern): the
//! path is checked before the tenant, a private temporary next to it is reserved before
//! the request, and the credential members are taken from the raw answer, registered in the
//! `SecretSet` and the **whole answer** (TS writes the whole response) linked into place
//! before the rest of the answer is validated, so a schema mismatch never loses it. The
//! credential is never printed.

use crate::error::{CliError, Failure, InterruptContext, SecretSet};
use crate::files::{self, LinkError, Published, Reservation, shown};
use crate::output::terminal_safe;
use scm::airs::gateway::models::{
    GatewayApiKeyCreateResponse, GatewayApiKeyRotateResponse, GatewayDeploymentCreateResponse,
    GatewayWriteResponse,
};
use scm::validation::Mode;
use serde_json::Value;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::GwPlane;
use super::inventory::KeyKind;
use super::writes::{Typed, Write, kind_name};
use crate::writes::OutcomeLines;
use scm::airs::gateway::AIGatewayClient;

/// The response-validation text of an answer the CLI could not read (§6).
pub const UNREADABLE: &str = "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema";

/// `--show-secret` (D237).
pub const SHOW_SECRET: &str = "--show-secret is not supported: one-time credentials are written only to --secret-output <new file>";

/// A secret write without a destination (D237).
pub const NEEDS_DESTINATION: &str =
    "A one-time credential needs --secret-output <new file>; airs never prints it";

/// `--secret-output` on a `deployments update` that does not rotate.
pub const ONLY_ROTATE: &str = "--secret-output is used only with --rotate-auth true";

/// Which one-time credential write this is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretWrite {
    KeyCreate(KeyKind),
    KeyRotate(KeyKind, String),
    DeploymentCreate,
    DeploymentRotate(String),
}

impl SecretWrite {
    /// `(thing, done)` of the outcome lines (§19.11 table).
    pub fn words(&self) -> (String, &'static str) {
        match self {
            Self::KeyCreate(kind) => (format!("{} API key", kind_name(*kind)), "created"),
            Self::KeyRotate(kind, id) => (format!("{} API key {id}", kind_name(*kind)), "rotated"),
            Self::DeploymentCreate => ("deployment".to_owned(), "registered"),
            Self::DeploymentRotate(id) => (format!("deployment {id} authentication"), "rotated"),
        }
    }

    /// What a user does when the credential of an applied write was not saved.
    pub fn remedy(&self) -> &'static str {
        match self {
            Self::KeyCreate(_) => "revoke the new key and create another",
            Self::KeyRotate(..) => "rotate the key again to obtain a usable credential",
            Self::DeploymentCreate => {
                "rotate its authentication with --rotate-auth true and a new --secret-output file"
            }
            Self::DeploymentRotate(_) => {
                "rotate it again with --secret-output <new file> to obtain usable ones"
            }
        }
    }

    /// The credential members of the answer (`key`; `client_auth` and
    /// `credentials.password`).
    fn members(&self) -> &'static [&'static [&'static str]] {
        match self {
            Self::KeyCreate(_) | Self::KeyRotate(..) => &[&["key"]],
            Self::DeploymentCreate | Self::DeploymentRotate(_) => {
                &[&["client_auth"], &["credentials", "password"]]
            }
        }
    }

    /// The `✓` line of the write (`id`: the argument, else the answer's `id`).
    pub fn success_line(&self, answer_id: Option<&str>) -> String {
        let id = |id: Option<&str>| id.map(|id| format!(": {id}")).unwrap_or_default();
        match self {
            Self::KeyCreate(kind) => {
                let mut noun = kind_name(*kind).to_owned();
                noun.replace_range(..1, &noun[..1].to_ascii_uppercase());
                format!("{noun} API key created{}", id(answer_id))
            }
            Self::KeyRotate(kind, key) => {
                let mut noun = kind_name(*kind).to_owned();
                noun.replace_range(..1, &noun[..1].to_ascii_uppercase());
                format!("{noun} API key rotated: {key}")
            }
            Self::DeploymentCreate => format!("Deployment registered{}", id(answer_id)),
            Self::DeploymentRotate(deployment) => {
                format!("Deployment authentication rotated: {deployment}")
            }
        }
    }

    /// Validate the rest of the answer with the operation's response schema.
    fn valid(&self, answer: &Value) -> bool {
        let mode = Mode::ResponseWithoutDefaults;
        match self {
            Self::KeyCreate(_) => GatewayApiKeyCreateResponse::parse(answer.clone(), mode).is_ok(),
            Self::KeyRotate(..) => GatewayApiKeyRotateResponse::parse(answer.clone(), mode).is_ok(),
            Self::DeploymentCreate => {
                GatewayDeploymentCreateResponse::parse(answer.clone(), mode).is_ok()
            }
            Self::DeploymentRotate(_) => GatewayWriteResponse::parse(answer.clone(), mode).is_ok(),
        }
    }
}

impl OutcomeLines for SecretWrite {
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

    /// The hint after an unknown or unreadable outcome, or a missing credential: always
    /// present, and only through this trait, so [`crate::writes::describe`] can never be
    /// handed the write without it (choice 143).
    fn hint(&self) -> Option<String> {
        let p = crate::store::PROGRAM;
        Some(match self {
            Self::KeyCreate(kind) => format!(
                "Check '{p} gateway api-keys {} list --workspace <uuid>' before creating another key; revoke a key whose credential was not saved.",
                kind_name(*kind)
            ),
            Self::KeyRotate(kind, id) => format!(
                "The old key stops working after its transition period; check '{p} gateway api-keys {} get {id}' and rotate it again to obtain a usable credential.",
                kind_name(*kind)
            ),
            Self::DeploymentCreate => format!(
                "Check '{p} gateway deployments list'; a registration whose credentials were not saved needs '{p} gateway deployments update <id> --rotate-auth true --secret-output <new file>'."
            ),
            Self::DeploymentRotate(_) => "Its old credentials may no longer work; rotate it again with --secret-output <new file> to obtain usable ones.".to_owned(),
        })
    }
}

/// The largest request body a raw credential write sends (the SDK's JSON body limit).
const BODY_LIMIT: usize = 2 * 1_048_576;

/// The G36 raw request of a one-time credential write (§19.11): the SDK's route and the
/// validated body ([`Typed::credential_wire`]), sent with `send_json` on the write's plane
/// so the credential is read from the raw answer before the rest is validated. The
/// request is rebuilt for each send because `RawRequest` is consumed; the caller sends it
/// once (D228, a 401 replayed once by `crate::writes::attempt`).
#[derive(Clone, Debug)]
pub struct CredentialRequest {
    method: reqwest::Method,
    /// The route's non-empty segments (`["api-keys", "service"]`), each sent through
    /// `RawRequest::segment` (percent-encoded).
    segments: Vec<String>,
    wire: Value,
    plane: GwPlane,
}

impl CredentialRequest {
    /// The request of `write` with its validated body. A body without a credential wire
    /// form, a method other than `POST`/`PUT`, an empty route or the IAM plane is the D116
    /// invalid-body error (never a silent `null` body or another method).
    pub fn new(write: &Write, typed: &Typed) -> Result<Self, CliError> {
        let (method, route) = write.route(None);
        let invalid = || crate::writes::invalid_body(method, &route);
        let wire = typed.credential_wire(write)?;
        let method = match method {
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            _ => return Err(invalid()),
        };
        let segments: Vec<String> = route
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        let plane = write.plane();
        if segments.is_empty() || plane == GwPlane::Iam {
            return Err(invalid());
        }
        Ok(Self {
            method,
            segments,
            wire,
            plane,
        })
    }

    /// The plane the write goes to (its grant hint).
    pub fn plane(&self) -> GwPlane {
        self.plane
    }

    /// The raw request (rebuilt per send).
    fn request(&self) -> scm::Result<scm::RawRequest> {
        let (first, rest) = self
            .segments
            .split_first()
            .ok_or_else(|| scm::Error::new(scm::ErrorKind::Configuration))?;
        let mut request = scm::RawRequest::new(self.method.clone(), format!("/{first}"));
        for segment in rest {
            request = request.segment(segment)?;
        }
        request.json_value(&self.wire, BODY_LIMIT)
    }

    /// Send the request once on the write's plane: the data-plane client, or the admin
    /// client (the SDK exposes it only through an admin-plane resource, here
    /// `deployments()`).
    pub async fn send(
        &self,
        gateway: &AIGatewayClient,
        options: &scm::RequestOptions,
    ) -> scm::Result<Value> {
        let admin;
        let client = match self.plane {
            GwPlane::Data => gateway.client(),
            GwPlane::Admin => {
                admin = gateway.deployments();
                admin.client()
            }
            GwPlane::Iam => return Err(scm::Error::new(scm::ErrorKind::Configuration)),
        };
        client
            .send_json::<Value>(self.request()?, Some(options))
            .await
    }
}

/// The `--secret-output` value checks during planning (exit 2): `""` and `-` refused.
pub fn plan_destination(value: &OsStr) -> Result<PathBuf, CliError> {
    if value.is_empty() {
        return Err(CliError::usage("--secret-output needs a path"));
    }
    if value == "-" {
        return Err(CliError::usage(
            "--secret-output - would print the credential; give a file path",
        ));
    }
    Ok(PathBuf::from(value))
}

/// The `--secret-output` path checks before the tenant (exit 1): nothing may exist at the
/// path (`lstat`, a dangling symlink included) and its directory must exist.
pub fn check_destination(path: &Path) -> Result<(), CliError> {
    files::check_new(path, "--secret-output")
}

/// A path for a message: as given, terminal-safe.
pub fn shown_path(path: &Path) -> String {
    terminal_safe(&shown(path.as_os_str())).into_owned()
}

fn failure(message: String, details: Vec<String>) -> CliError {
    CliError::Operational(Failure {
        message,
        status: None,
        details,
    })
}

/// A 2xx answer the CLI could not read: the §6 validation text, the unreadable line and
/// the hint.
pub fn unreadable(write: &SecretWrite) -> CliError {
    failure(
        UNREADABLE.to_owned(),
        std::iter::once(write.unreadable_line())
            .chain(write.hint())
            .collect(),
    )
}

/// The durability warning of a saved file, if any (§3.9, §18.20 choices 49 and 67).
pub fn durability_warning(published: Published, path: &Path) -> Option<String> {
    match published {
        Published::Durable => None,
        Published::DirectoryNotSynced => Some(crate::store::atomic::dir_sync_warning(path)),
        Published::FileNotSynced => Some(format!(
            "⚠ {} was saved, but it could not be synced; the credential may not survive a system crash",
            shown_path(path)
        )),
    }
}

/// The interruption context once a 2xx answer arrived but before its credential is saved.
pub fn not_saved_context(write: &SecretWrite) -> InterruptContext {
    let (thing, done) = write.words();
    InterruptContext::Context(format!(
        "the {thing} was {done}, but its credential was not saved; {}",
        write.remedy()
    ))
}

/// A saved answer (steps 1–3).
#[derive(Debug)]
pub struct Saved {
    /// How durable the file is (its warning is printed whether or not the rest of the
    /// answer could be read).
    pub published: Published,
    /// The answer's `id` when it is a string (the acknowledgement).
    pub answer_id: Option<String>,
    /// The step-3 error when the rest of the answer did not match its schema.
    pub rest: Result<(), CliError>,
}

/// The string at `path` within `answer`, when non-empty.
fn member<'a>(answer: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut node = answer;
    for key in path {
        node = node.get(*key)?;
    }
    node.as_str().filter(|text| !text.is_empty())
}

/// The G36 answer handling (§19.11 "The answer", steps 1–6). `interrupt` receives the
/// context an interruption reports: [`not_saved_context`] from the start, then the saved
/// file or the kept temporary.
pub fn save_answer(
    answer: Value,
    reservation: Reservation,
    path: &Path,
    write: &SecretWrite,
    secrets: &SecretSet,
    interrupt: &mut Option<InterruptContext>,
) -> Result<Saved, CliError> {
    *interrupt = Some(not_saved_context(write));
    if !answer.is_object() {
        return Err(unreadable(write));
    }
    let (thing, done) = write.words();
    let typed = shown_path(path);
    let credentials: Vec<String> = write
        .members()
        .iter()
        .filter_map(|path| member(&answer, path).map(str::to_owned))
        .collect();
    for credential in &credentials {
        secrets.add(credential);
    }
    let answer_id = answer
        .get("id")
        .and_then(Value::as_str)
        .map(|id| terminal_safe(secrets.scrub(id)).into_owned());
    if credentials.is_empty() {
        drop(reservation);
        if !write.valid(&answer) {
            return Err(unreadable(write));
        }
        let named = match (write, &answer_id) {
            (SecretWrite::KeyCreate(_) | SecretWrite::DeploymentCreate, Some(id)) => {
                format!("{thing} {id}")
            }
            _ => thing.clone(),
        };
        return Err(failure(
            format!(
                "The service {done} {named} but returned no one-time credential; nothing was written to {typed}."
            ),
            write.hint().into_iter().collect(),
        ));
    }
    // The one copy of a credential shown only once: a serialization failure is the
    // `could not be written` outcome below, never an empty file linked as the credential.
    let not_written = || {
        failure(
            format!(
                "The {thing} was {done}, but its credential could not be written to {typed}; {}.",
                write.remedy()
            ),
            Vec::new(),
        )
    };
    let Ok(text) = serde_json::to_string_pretty(&answer) else {
        drop(reservation);
        return Err(not_written());
    };
    // No cancellation point from here to the link: plain blocking I/O.
    let linked = match reservation.write_and_link(path, format!("{text}\n").as_bytes()) {
        // Written whole but its fsync failed: the complete 0600 copy is linked anyway (a
        // warning follows), never discarded.
        Err(LinkError::NotSynced(reservation)) => reservation.link_unsynced(path),
        other => other,
    };
    let published = match linked {
        Ok(published) => published,
        Err(LinkError::Write | LinkError::NotSynced(_)) => return Err(not_written()),
        Err(LinkError::Exists(reservation)) => {
            let temp = shown_path(&reservation.keep());
            *interrupt = Some(InterruptContext::Context(format!(
                "the {thing} was {done}; its credential is in {temp} (mode 0600)"
            )));
            return Err(failure(
                format!(
                    "The {thing} was {done}, but {typed} now exists; the credential is in {temp} (mode 0600). Move it before running again."
                ),
                Vec::new(),
            ));
        }
        Err(LinkError::Link(reservation)) => {
            let temp = shown_path(&reservation.keep());
            *interrupt = Some(InterruptContext::Context(format!(
                "the {thing} was {done}; its credential is in {temp} (mode 0600)"
            )));
            return Err(failure(
                format!(
                    "The {thing} was {done}, but the credential is in {temp} (mode 0600) because {typed} could not be written. Move it before running again."
                ),
                Vec::new(),
            ));
        }
    };
    *interrupt = Some(InterruptContext::Context(format!(
        "the one-time credential was saved in {typed}"
    )));
    let rest = if write.valid(&answer) {
        Ok(())
    } else {
        Err(failure(
            UNREADABLE.to_owned(),
            vec![format!(
                "Outcome: the {thing} was {done} and its one-time credential was saved in {typed}, but the rest of the response could not be read."
            )],
        ))
    };
    Ok(Saved {
        published,
        answer_id,
        rest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use serde_json::json;

    fn message(error: CliError) -> (String, Vec<String>) {
        match error {
            CliError::Operational(failure) => (failure.message, failure.details),
            other => panic!("{other:?}"),
        }
    }

    /// Choice 143: the hint of a credential write is its `OutcomeLines::hint` (no inherent
    /// method shadows it), so the write handed to `describe` as its lines always carries it.
    #[test]
    fn every_credential_write_carries_its_hint_as_its_outcome_lines() {
        fn lines(lines: impl OutcomeLines) -> (String, Option<String>) {
            (lines.unknown_line(), lines.hint())
        }
        for write in [
            SecretWrite::KeyCreate(KeyKind::Service),
            SecretWrite::KeyRotate(KeyKind::User, "k-1".into()),
            SecretWrite::DeploymentCreate,
            SecretWrite::DeploymentRotate("d-1".into()),
        ] {
            let (unknown, hint) = lines(&write);
            assert!(unknown.starts_with("Outcome unknown: the "), "{unknown}");
            let hint = hint.unwrap_or_else(|| panic!("{write:?} has no hint"));
            assert!(
                hint.contains("--secret-output") || hint.contains("api-keys"),
                "{write:?}: {hint}"
            );
        }
        assert_eq!(
            lines(SecretWrite::KeyRotate(KeyKind::User, "k-1".into()))
                .1
                .as_deref(),
            Some(
                "The old key stops working after its transition period; check 'airs gateway api-keys user get k-1' and rotate it again to obtain a usable credential."
            )
        );
    }

    fn temporaries(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".airs-"))
            .count()
    }

    /// The G36 raw request: only a credential write with its own validated body builds
    /// one; any other pair is the D116 invalid-body error, never a `null` body.
    #[test]
    fn credential_requests_take_only_credential_bodies() {
        let rotate = Write::KeyRotate(KeyKind::Service, "k-1".into());
        let typed =
            Typed::parse(&rotate, &json!({"key_transition_period_ms": 1800000}), None).unwrap();
        let request = CredentialRequest::new(&rotate, &typed).unwrap();
        assert_eq!(request.method, reqwest::Method::POST);
        assert_eq!(request.segments, ["api-keys", "service", "k-1", "rotate"]);
        assert_eq!(request.wire, json!({"key_transition_period_ms": 1800000}));
        assert_eq!(request.plane(), GwPlane::Data);
        let update = Write::DeploymentUpdate("d-1".into());
        let typed = Typed::parse(&update, &json!({"rotate_auth": true}), None).unwrap();
        let request = CredentialRequest::new(&update, &typed).unwrap();
        assert_eq!(request.method, reqwest::Method::PUT);
        assert_eq!(request.plane(), GwPlane::Admin);
        // A body of another write, or none, is refused.
        let create = Write::KeyCreate(KeyKind::Service);
        for (write, typed) in [
            (&create, Typed::None),
            (&create, Typed::parse(&rotate, &json!({}), None).unwrap()),
            (&Write::ConfigDelete("c-1".into()), Typed::None),
        ] {
            let (method, route) = write.route(None);
            let (text, _) = message(CredentialRequest::new(write, &typed).unwrap_err());
            assert_eq!(
                text,
                format!(
                    "AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for {method} {route} did not match schema"
                )
            );
        }
    }

    #[test]
    fn destination_arguments() {
        assert!(
            matches!(plan_destination(OsStr::new("")), Err(CliError::Usage(m)) if m == "--secret-output needs a path")
        );
        assert!(
            matches!(plan_destination(OsStr::new("-")), Err(CliError::Usage(m)) if m == "--secret-output - would print the credential; give a file path")
        );
    }

    /// Steps 1–3: the whole answer (sorted keys) is saved at 0600 before the rest is
    /// validated; the credential joins the `SecretSet`.
    #[test]
    fn the_whole_answer_is_saved_first() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("gw-secrets");
        let path = dir.join("key.json");
        let secrets = SecretSet::default();
        let mut interrupt = None;
        let write = SecretWrite::KeyCreate(KeyKind::Service);
        let saved = save_answer(
            json!({"object": "api-key", "key": "SECRET-GW-ONE", "id": "k-1"}),
            Reservation::reserve_new(&path).unwrap(),
            &path,
            &write,
            &secrets,
            &mut interrupt,
        )
        .unwrap();
        assert!(saved.rest.is_ok());
        assert_eq!(saved.answer_id.as_deref(), Some("k-1"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\n  \"id\": \"k-1\",\n  \"key\": \"SECRET-GW-ONE\",\n  \"object\": \"api-key\"\n}\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(secrets.carried_by("SECRET-GW-ONE"));
        assert_eq!(temporaries(dir.path()), 0);
        // A rotate answer without `key_transition_expires_at` still saves the key (G36).
        let path = dir.join("rotate.json");
        let write = SecretWrite::KeyRotate(KeyKind::User, "k-2".into());
        let saved = save_answer(
            json!({"id": "k-2", "key": "SECRET-GW-TWO"}),
            Reservation::reserve_new(&path).unwrap(),
            &path,
            &write,
            &secrets,
            &mut None,
        )
        .unwrap();
        let (text, details) = message(saved.rest.unwrap_err());
        assert_eq!(text, UNREADABLE);
        assert_eq!(
            details,
            [format!(
                "Outcome: the user API key k-2 was rotated and its one-time credential was saved in {}, but the rest of the response could not be read.",
                path.display()
            )]
        );
        assert!(path.exists());
    }

    /// Steps 4–6: no credential, not an object, a lost race.
    #[test]
    fn missing_credentials_and_races() {
        let dir = TempDir::new("gw-secrets");
        let path = dir.join("d.json");
        let secrets = SecretSet::default();
        let write = SecretWrite::DeploymentCreate;
        let (text, details) = message(
            save_answer(
                json!({"id": "d-1", "client_auth": "", "credentials": {"username": "u", "password": ""}, "organisation_id": "o", "object": "deployment"}),
                Reservation::reserve_new(&path).unwrap(),
                &path,
                &write,
                &secrets,
                &mut None,
            )
            .unwrap_err(),
        );
        assert_eq!(
            text,
            format!(
                "The service registered deployment d-1 but returned no one-time credential; nothing was written to {}.",
                path.display()
            )
        );
        assert_eq!(
            details,
            [write.hint().expect("a credential write has a hint")]
        );
        assert_eq!(temporaries(dir.path()), 0);
        let (text, details) = message(
            save_answer(
                json!(["x"]),
                Reservation::reserve_new(&path).unwrap(),
                &path,
                &write,
                &secrets,
                &mut None,
            )
            .unwrap_err(),
        );
        assert_eq!(text, UNREADABLE);
        assert_eq!(
            details[0],
            "Outcome: the deployment was registered, but the response could not be read."
        );
        let reservation = Reservation::reserve_new(&path).unwrap();
        std::fs::write(&path, "OTHER").unwrap();
        let mut interrupt = None;
        let (text, _) = message(
            save_answer(
                json!({"id": "d-2", "client_auth": "SECRET-GW-AUTH", "credentials": {"username": "u", "password": "SECRET-GW-PASS"}, "organisation_id": "o", "object": "deployment"}),
                reservation,
                &path,
                &write,
                &secrets,
                &mut interrupt,
            )
            .unwrap_err(),
        );
        assert!(text.starts_with(&format!(
            "The deployment was registered, but {} now exists; the credential is in ",
            path.display()
        )));
        assert!(secrets.carried_by("SECRET-GW-AUTH") && secrets.carried_by("SECRET-GW-PASS"));
        assert_eq!(temporaries(dir.path()), 1, "the credential is kept");
        assert!(
            matches!(interrupt, Some(InterruptContext::Context(text)) if text.starts_with("the deployment was registered; its credential is in "))
        );
    }

    #[test]
    fn lines() {
        assert_eq!(
            SecretWrite::KeyCreate(KeyKind::User).success_line(Some("k")),
            "User API key created: k"
        );
        assert_eq!(
            SecretWrite::DeploymentRotate("d".into()).success_line(None),
            "Deployment authentication rotated: d"
        );
        assert_eq!(
            SecretWrite::DeploymentRotate("d".into()).unknown_line(),
            "Outcome unknown: the deployment d authentication may have been rotated."
        );
    }
}
