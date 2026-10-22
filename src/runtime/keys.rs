//! The API key secret channel of `api-keys create|regenerate` (DESIGN §18.5, D204, G26).
//!
//! The key value of a create or regenerate answer is a credential shown once. Its only
//! channel is a required `--key-file <new path>`: the path is checked before the tenant,
//! a private temporary next to it is reserved before the request (a key is never created
//! that cannot be stored), and the key is taken from the raw answer, registered in the
//! `SecretSet` and linked into place before the rest of the answer is validated, so a
//! schema mismatch never loses it. The key is never printed.

use crate::error::{CliError, Failure, InterruptContext, SecretSet};
use crate::files::{self, LinkError, Published, Reservation, shown};
use crate::json::OValue;
use crate::output::terminal_safe;
use crate::writes::{Change, OutcomeLines};
use scm::airs::management::models::ApiKey;
use scm::validation::Mode;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The response-validation text of an answer the CLI could not read (§6).
const UNREADABLE: &str = "AISEC_RESPONSE_VALIDATION:Response did not match the expected schema";

/// Which key write this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyWrite {
    Create,
    Regenerate,
}

impl KeyWrite {
    /// `created` / `regenerated`.
    pub fn done(self) -> &'static str {
        match self {
            Self::Create => "created",
            Self::Regenerate => "regenerated",
        }
    }

    /// The outcome words (§18.3 "Writes and outcomes").
    pub fn change(self) -> Change {
        Change::Words("API key", self.done())
    }

    /// The hint after an unknown or unreadable outcome (§18.3).
    pub fn hint(self) -> &'static str {
        match self {
            Self::Create => {
                "Check 'airs runtime api-keys list' before creating another key; a key whose value was not saved cannot be shown again (regenerate or delete it)."
            }
            Self::Regenerate => {
                "The old key may no longer work; check 'airs runtime api-keys list' and regenerate it again only if needed."
            }
        }
    }
}

/// The `--key-file` value checks during planning (exit 2): `""` and `-` are refused (as
/// D194's `--url-file`).
pub fn plan_key_file(value: &OsStr) -> Result<PathBuf, CliError> {
    if value.is_empty() {
        return Err(CliError::usage("--key-file needs a path"));
    }
    if value == "-" {
        return Err(CliError::usage(
            "--key-file - would print the key; give a file path",
        ));
    }
    Ok(PathBuf::from(value))
}

/// The `--key-file` path checks before the tenant (exit 1): nothing may exist at the path
/// (`lstat`, a dangling symlink included) and its directory must exist.
pub fn check_key_file(path: &Path) -> Result<(), CliError> {
    files::check_new(path, "--key-file")
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
/// the hint (the reservation is dropped by the caller).
pub fn unreadable(write: KeyWrite) -> CliError {
    failure(
        UNREADABLE.to_owned(),
        vec![write.change().unreadable_line(), write.hint().to_owned()],
    )
}

/// A key answer whose key was saved in the key file (steps 1–3).
#[derive(Debug)]
pub struct Saved {
    /// How durable the key file is: the caller prints its warning whether or not the rest
    /// of the answer could be read (choice 67, §3.9).
    pub published: Published,
    /// The validated answer as ordered JSON (the key still in it; the caller strips it),
    /// or the step-3 error when the rest of the answer did not match its schema.
    pub record: Result<OValue, CliError>,
}

/// The warning a saved key file needs, if any: the §3.9 directory-sync warning, or the
/// key-file sync warning of choice 67.
pub fn durability_warning(published: Published, path: &Path) -> Option<String> {
    match published {
        Published::Durable => None,
        Published::DirectoryNotSynced => Some(crate::store::atomic::dir_sync_warning(path)),
        Published::FileNotSynced => Some(format!(
            "⚠ {} was saved, but it could not be synced; the key may not survive a system crash",
            shown_path(path)
        )),
    }
}

/// The interruption context once a 2xx answer arrived but before its key is saved: the
/// service already created or rotated the key, so "nothing was changed" would be false.
pub fn not_saved_context(write: KeyWrite) -> InterruptContext {
    InterruptContext::Context(format!(
        "the API key was {}, but its value was not saved; regenerate the key to obtain a usable value",
        write.done()
    ))
}

/// The G26 answer handling (§18.5 "The answer", steps 1–6). `interrupt` receives the
/// context an interruption reports on every path: [`not_saved_context`] from the start
/// (the answer is a 2xx), then the saved key file or the kept temporary. `Ok` once the
/// key file is linked (its `record` carries a step-3 mismatch); `Err` when the key was
/// not saved there (steps 4–6).
pub fn save_answer(
    answer: serde_json::Value,
    reservation: Reservation,
    path: &Path,
    write: KeyWrite,
    secrets: &SecretSet,
    interrupt: &mut Option<InterruptContext>,
) -> Result<Saved, CliError> {
    *interrupt = Some(not_saved_context(write));
    let serde_json::Value::Object(object) = answer else {
        return Err(unreadable(write));
    };
    let done = write.done();
    let typed = shown_path(path);
    let key = match object.get("api_key") {
        Some(serde_json::Value::String(key)) if !key.is_empty() => Some(key.clone()),
        _ => None,
    };
    let answer = serde_json::Value::Object(object);
    let Some(key) = key else {
        drop(reservation);
        return match ApiKey::parse(answer, Mode::ResponseWithoutDefaults) {
            Ok(model) => {
                let id = terminal_safe(secrets.scrub(&model.api_key_id)).into_owned();
                Err(failure(
                    format!(
                        "The service {done} API key {id} but returned no key value; nothing was written to {typed}. Regenerate the key to obtain a usable value."
                    ),
                    Vec::new(),
                ))
            }
            Err(_) => Err(unreadable(write)),
        };
    };
    secrets.add(&key);
    // No cancellation point from here to the link (choice 40): plain blocking I/O.
    let linked = match reservation.write_and_link(path, format!("{key}\n").as_bytes()) {
        // The key was written whole but its fsync failed: the complete 0600 copy is
        // linked anyway (a warning follows), never discarded (choice 67).
        Err(LinkError::NotSynced(reservation)) => reservation.link_unsynced(path),
        other => other,
    };
    let published = match linked {
        Ok(published) => published,
        Err(LinkError::Write | LinkError::NotSynced(_)) => {
            return Err(failure(
                format!(
                    "The API key was {done}, but its value could not be written to {typed}; regenerate the key to obtain a usable value."
                ),
                Vec::new(),
            ));
        }
        Err(LinkError::Exists(reservation)) => {
            let temp = shown_path(&reservation.keep());
            *interrupt = Some(InterruptContext::Context(format!(
                "the API key was {done}; it is in {temp} (mode 0600)"
            )));
            return Err(failure(
                format!(
                    "The API key was {done}, but {typed} now exists; the key is in {temp} (mode 0600). Move it before running again."
                ),
                Vec::new(),
            ));
        }
        Err(LinkError::Link(reservation)) => {
            let temp = shown_path(&reservation.keep());
            *interrupt = Some(InterruptContext::Context(format!(
                "the API key was {done}; it is in {temp} (mode 0600)"
            )));
            return Err(failure(
                format!(
                    "The API key was {done}, but the key is in {temp} (mode 0600) because {typed} could not be written. Move it before running again."
                ),
                Vec::new(),
            ));
        }
    };
    *interrupt = Some(InterruptContext::Context(format!(
        "the API key was saved in {typed}"
    )));
    let record = ApiKey::parse(answer, Mode::ResponseWithoutDefaults)
        .ok()
        .and_then(|model| crate::json::to_ordered(&model).ok())
        .ok_or_else(|| {
            failure(
                UNREADABLE.to_owned(),
                vec![format!(
                    "Outcome: the API key was {done} and its value was saved in {typed}, but the rest of the response could not be read."
                )],
            )
        });
    Ok(Saved { published, record })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::test_support::TempDir;

    fn answer(key: Option<&str>) -> serde_json::Value {
        let mut answer = json!({
            "api_key_id": "id-1",
            "api_key_last8": "LAST8-01",
            "auth_code": "a",
            "expiration": "2027-01-01T00:00:00Z",
            "revoked": false,
        });
        if let Some(key) = key {
            answer["api_key"] = json!(key);
        }
        answer
    }

    fn message(error: CliError) -> (String, Vec<String>) {
        match error {
            CliError::Operational(failure) => (failure.message, failure.details),
            other => panic!("{other:?}"),
        }
    }

    fn temporaries(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".airs-"))
            .count()
    }

    #[test]
    fn key_file_arguments() {
        assert!(
            matches!(plan_key_file(OsStr::new("")), Err(CliError::Usage(m)) if m == "--key-file needs a path")
        );
        assert!(
            matches!(plan_key_file(OsStr::new("-")), Err(CliError::Usage(m)) if m == "--key-file - would print the key; give a file path")
        );
        assert_eq!(
            plan_key_file(OsStr::new("k.txt")).unwrap(),
            PathBuf::from("k.txt")
        );
    }

    /// Step 1–2: the key is registered, written at 0600 and the record validated.
    #[test]
    fn the_key_is_saved_before_the_answer_is_validated() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("keys-test");
        let path = dir.join("key.txt");
        let secrets = SecretSet::default();
        let mut interrupt = None;
        let saved = save_answer(
            answer(Some("SECRET-KEY-VALUE")),
            Reservation::reserve_new(&path).unwrap(),
            &path,
            KeyWrite::Create,
            &secrets,
            &mut interrupt,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "SECRET-KEY-VALUE\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(secrets.carried_by("SECRET-KEY-VALUE"));
        assert_eq!(saved.published, Published::Durable);
        assert_eq!(
            saved.record.unwrap().get("api_key_id"),
            Some(&OValue::String("id-1".into()))
        );
        assert!(
            matches!(interrupt, Some(InterruptContext::Context(text)) if text.starts_with("the API key was saved in "))
        );
        assert_eq!(temporaries(dir.path()), 0);
        // Step 3: a schema mismatch still saves the key.
        let path = dir.join("mismatch.txt");
        let mut bad = answer(Some("SECRET-TWO"));
        bad.as_object_mut().unwrap().remove("auth_code");
        let saved = save_answer(
            bad,
            Reservation::reserve_new(&path).unwrap(),
            &path,
            KeyWrite::Regenerate,
            &secrets,
            &mut None,
        )
        .unwrap();
        assert_eq!(saved.published, Published::Durable);
        let (text, details) = message(saved.record.unwrap_err());
        assert_eq!(text, UNREADABLE);
        assert_eq!(
            details,
            [format!(
                "Outcome: the API key was regenerated and its value was saved in {}, but the rest of the response could not be read.",
                path.display()
            )]
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "SECRET-TWO\n");
    }

    /// A 2xx answer whose key was not saved never leaves the "nothing was changed"
    /// fallback for an interruption: no key, not an object, a failed write.
    #[test]
    fn an_unsaved_key_sets_the_interruption_context() {
        let dir = TempDir::new("keys-test");
        let path = dir.join("key.txt");
        let secrets = SecretSet::default();
        let expected = |write: KeyWrite| {
            format!(
                "the API key was {}, but its value was not saved; regenerate the key to obtain a usable value",
                write.done()
            )
        };
        for (answer, write) in [
            (answer(None), KeyWrite::Regenerate),
            (json!(["x"]), KeyWrite::Create),
        ] {
            let mut interrupt = None;
            assert!(
                save_answer(
                    answer,
                    Reservation::reserve_new(&path).unwrap(),
                    &path,
                    write,
                    &secrets,
                    &mut interrupt,
                )
                .is_err()
            );
            assert!(
                matches!(&interrupt, Some(InterruptContext::Context(text)) if *text == expected(write)),
                "{interrupt:?}"
            );
        }
    }

    /// A failed fsync of the whole key keeps it: the key file is linked (0600), never
    /// deleted (choice 67).
    #[test]
    fn a_failed_key_sync_still_saves_the_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("keys-test");
        let path = dir.join("key.txt");
        let secrets = SecretSet::default();
        let mut reservation = Reservation::reserve_new(&path).unwrap();
        reservation.fail_sync_for_test();
        let mut interrupt = None;
        let saved = save_answer(
            answer(Some("SECRET-UNSYNCED")),
            reservation,
            &path,
            KeyWrite::Regenerate,
            &secrets,
            &mut interrupt,
        )
        .unwrap();
        assert_eq!(saved.published, Published::FileNotSynced);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "SECRET-UNSYNCED\n");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(temporaries(dir.path()), 0);
        assert!(
            matches!(interrupt, Some(InterruptContext::Context(text)) if text.starts_with("the API key was saved in "))
        );
    }

    /// A failed fsync and a schema mismatch together (steps 1 and 3): the key file is
    /// linked, the step-3 error is returned with `FileNotSynced`, so the caller still prints
    /// the sync warning (choice 67, choice 75).
    #[test]
    fn a_failed_key_sync_survives_a_schema_mismatch() {
        let dir = TempDir::new("keys-test");
        let path = dir.join("key.txt");
        let secrets = SecretSet::default();
        let mut reservation = Reservation::reserve_new(&path).unwrap();
        reservation.fail_sync_for_test();
        let mut bad = answer(Some("SECRET-UNSYNCED-BAD"));
        bad.as_object_mut().unwrap().remove("auth_code");
        let mut interrupt = None;
        let saved = save_answer(
            bad,
            reservation,
            &path,
            KeyWrite::Create,
            &secrets,
            &mut interrupt,
        )
        .unwrap();
        assert_eq!(saved.published, Published::FileNotSynced);
        assert_eq!(
            durability_warning(saved.published, &path).unwrap(),
            format!(
                "⚠ {} was saved, but it could not be synced; the key may not survive a system crash",
                path.display()
            )
        );
        let (text, details) = message(saved.record.unwrap_err());
        assert_eq!(text, UNREADABLE);
        assert_eq!(
            details,
            [format!(
                "Outcome: the API key was created and its value was saved in {}, but the rest of the response could not be read.",
                path.display()
            )]
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "SECRET-UNSYNCED-BAD\n"
        );
        assert_eq!(temporaries(dir.path()), 0);
        assert!(
            matches!(interrupt, Some(InterruptContext::Context(text)) if text.starts_with("the API key was saved in "))
        );
        assert_eq!(durability_warning(Published::Durable, &path), None);
    }

    /// Steps 4–6: no key, not an object, a lost race.
    #[test]
    fn answers_without_a_usable_key_and_lost_races() {
        let dir = TempDir::new("keys-test");
        let path = dir.join("key.txt");
        let secrets = SecretSet::default();
        for missing in [answer(None), {
            let mut empty = answer(None);
            empty["api_key"] = json!("");
            empty
        }] {
            let (text, _) = message(
                save_answer(
                    missing,
                    Reservation::reserve_new(&path).unwrap(),
                    &path,
                    KeyWrite::Create,
                    &secrets,
                    &mut None,
                )
                .unwrap_err(),
            );
            assert_eq!(
                text,
                format!(
                    "The service created API key id-1 but returned no key value; nothing was written to {}. Regenerate the key to obtain a usable value.",
                    path.display()
                )
            );
            assert!(!path.exists());
            assert_eq!(temporaries(dir.path()), 0);
        }
        let (text, details) = message(
            save_answer(
                json!(["x"]),
                Reservation::reserve_new(&path).unwrap(),
                &path,
                KeyWrite::Create,
                &secrets,
                &mut None,
            )
            .unwrap_err(),
        );
        assert_eq!(text, UNREADABLE);
        assert_eq!(
            details[0],
            "Outcome: the API key was created, but the response could not be read."
        );
        assert_eq!(temporaries(dir.path()), 0);
        // The path appeared between the reservation and the link: the temporary is kept.
        let reservation = Reservation::reserve_new(&path).unwrap();
        std::fs::write(&path, "OTHER").unwrap();
        let mut interrupt = None;
        let (text, _) = message(
            save_answer(
                answer(Some("SECRET-RACE")),
                reservation,
                &path,
                KeyWrite::Create,
                &secrets,
                &mut interrupt,
            )
            .unwrap_err(),
        );
        assert!(text.starts_with(&format!(
            "The API key was created, but {} now exists; the key is in ",
            path.display()
        )));
        assert!(text.ends_with(" (mode 0600). Move it before running again."));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "OTHER");
        assert_eq!(temporaries(dir.path()), 1, "the key is kept");
        assert!(interrupt.is_some());
    }
}
