//! The output CSV (DESIGN §14.12, D121, D122): the TypeScript projection byte for byte,
//! the default name that always stays in the working directory, the exclusive claim,
//! and the identity-checked rewrite around a checkpoint.

use super::checkpoint::{Step, injected};
use super::state::{JobState, NextOutput, OutputRecord};
use super::{Identity, PROGRAM};
use crate::error::CliError;
use crate::store::{euid, shown};
use crate::tenant::config::is_js_whitespace;
use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The CSV header (TS `formatResultsCsv`).
pub const HEADER: &str = "prompt,action,category,triggered,topic_violation,injection,toxic_content,dlp,url_cats,malicious_code,source_code,agent,scan_id,report_id,error";

/// `<profile>-bulk-scan.csv`, where every run of JavaScript whitespace, every `/` and
/// every C0, DEL and C1 control becomes one `-` (D122).
pub fn default_name(profile: &str) -> String {
    let mut name = String::with_capacity(profile.len() + 14);
    let mut in_space = false;
    for c in profile.chars() {
        if is_js_whitespace(c) {
            if !in_space {
                name.push('-');
            }
            in_space = true;
            continue;
        }
        in_space = false;
        name.push(if c == '/' || c.is_control() { '-' } else { c });
    }
    name.push_str("-bulk-scan.csv");
    name
}

/// `"<value>"` with `"` doubled.
fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// The projection of `state`: the header, then one row per item with a result in
/// input order, joined by `\n`, no trailing newline.
pub fn projection(state: &JobState) -> String {
    let mut lines = vec![HEADER.to_owned()];
    for item in &state.items {
        let Some(result) = &item.result else { continue };
        let flag = |value: bool| if value { "true" } else { "false" };
        let mut fields = vec![
            quote(&item.prompt),
            quote(result.action.name()),
            quote(&result.category),
            quote(flag(result.triggered)),
        ];
        for key in crate::commands::scan::PROMPT_KEYS {
            fields.push(quote(flag(result.detections.get(key) == Some(true))));
        }
        fields.push(quote(&result.scan_id));
        fields.push(quote(&result.report_id));
        fields.push(quote(result.error.as_deref().unwrap_or("")));
        lines.push(fields.join(","));
    }
    lines.join("\n")
}

/// `<path> already exists; choose another --output-file` (the D114 text).
pub fn exists_error(path: &Path) -> CliError {
    CliError::operational(format!(
        "{} already exists; choose another --output-file",
        shown(path)
    ))
}

fn cannot_write(path: &Path) -> CliError {
    CliError::operational(format!(
        "Cannot write {}; check that its directory exists and is writable",
        shown(path)
    ))
}

/// The absolute, lexically normalised output path (no symlink resolution).
pub fn absolute(path: &Path, cwd: &Path) -> PathBuf {
    crate::store::normalize(&cwd.join(path))
}

/// Refuse a path that exists (any type; a symlink is not followed).
pub fn refuse_existing(path: &Path) -> Result<(), CliError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(exists_error(path)),
        Err(_) => Err(cannot_write(path)),
    }
}

fn parent(path: &Path) -> &Path {
    path.parent().unwrap_or(Path::new("/"))
}

fn sync_dir(dir: &Path) -> bool {
    injected(Step::DirSync).is_ok() && File::open(dir).and_then(|dir| dir.sync_all()).is_ok()
}

/// `<path> is not the file this job wrote …` (§14.12 rewrite step 3).
pub fn foreign_error(path: &Path, state_shown: &str) -> CliError {
    CliError::operational(format!(
        "{} is not the file this job wrote (it was replaced, moved or edited); the results are saved in {state_shown}: resume with --output-file <new path>",
        shown(path)
    ))
}

/// What is at the job's recorded output path (`resume-poll`, §14.12 step 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtPath {
    /// Nothing: the file is claimed again.
    Absent,
    /// The file this job last put there (`output`).
    Current,
    /// The rewrite recorded as `output.next` was renamed into place.
    Next,
    /// Anything else (another file, a symlink, a directory, another owner).
    Foreign,
}

fn same(dev: &str, ino: &str, metadata: &std::fs::Metadata) -> bool {
    dev == metadata.dev().to_string() && ino == metadata.ino().to_string()
}

/// Classify the recorded output path against the state's output record.
pub fn at_path(record: &OutputRecord) -> AtPath {
    match std::fs::symlink_metadata(&record.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => AtPath::Absent,
        Ok(metadata) if metadata.file_type().is_file() && metadata.uid() == euid() => {
            if same(&record.dev, &record.ino, &metadata) {
                AtPath::Current
            } else if record
                .next
                .as_ref()
                .is_some_and(|next| same(&next.dev, &next.ino, &metadata))
            {
                AtPath::Next
            } else {
                AtPath::Foreign
            }
        }
        _ => AtPath::Foreign,
    }
}

/// Remove a rewrite temporary left by a run that stopped between step 1 and step 4
/// (`output.next.temp`), only when it is a regular file of ours with the recorded
/// identity, next to the output and named like one of its temporaries. Returns
/// whether one was removed.
pub fn remove_leftover_temp(record: &OutputRecord) -> bool {
    let Some(next) = &record.next else {
        return false;
    };
    let output = Path::new(&record.path);
    let temp = Path::new(&next.temp);
    let Some(file_name) = output.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let named_like_ours = temp.parent() == output.parent()
        && temp
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with(&format!(".{file_name}.")) && name.ends_with(".tmp")
            });
    if !named_like_ours {
        return false;
    }
    match std::fs::symlink_metadata(temp) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == euid()
                && same(&next.dev, &next.ino, &metadata) =>
        {
            std::fs::remove_file(temp).is_ok()
        }
        _ => false,
    }
}

/// The job's output file and the rewrite in progress.
#[derive(Debug)]
pub struct OutputFile {
    path: PathBuf,
    /// Whether the directory-sync warning was already printed this run.
    warned: bool,
}

/// A prepared rewrite: the fsynced temporary and its identity (§14.12 step 1).
#[derive(Debug)]
pub struct Prepared {
    temp: PathBuf,
    identity: Identity,
}

/// What a rewrite reports besides success.
#[derive(Debug, PartialEq, Eq)]
pub enum Rewritten {
    Durable,
    /// The rename happened but the directory fsync failed: print this warning once.
    Warning(String),
}

impl OutputFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            warned: false,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn warning(&mut self) -> Rewritten {
        if self.warned {
            return Rewritten::Durable;
        }
        self.warned = true;
        Rewritten::Warning(crate::store::atomic::dir_sync_warning(&self.path))
    }

    /// Create the path exclusively (`O_EXCL | O_NOFOLLOW`, 0600) with `bytes`, fsync it
    /// and its directory (§14.12 "Claim"). A partly written file is removed.
    pub fn claim(&mut self, bytes: &[u8]) -> Result<(Identity, Rewritten), CliError> {
        let path = &self.path;
        // Every later rewrite needs a temporary about 28 bytes longer than the name:
        // refuse a name whose temporary the directory would not accept before anything
        // exists (or is sent), rather than at the first rewrite.
        if !self.probe() {
            return Err(cannot_write(path));
        }
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = match rustix::fs::open(path, flags, Mode::from_raw_mode(0o600)) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::EXIST) => return Err(exists_error(path)),
            Err(_) => return Err(cannot_write(path)),
        };
        let mut file = File::from(fd);
        let written = (|| -> std::io::Result<Identity> {
            injected(Step::OutputTemp)?;
            rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Identity::of_file(&file)
        })();
        drop(file);
        match written {
            Ok(identity) => {
                let report = if sync_dir(parent(path)) {
                    Rewritten::Durable
                } else {
                    self.warning()
                };
                Ok((identity, report))
            }
            Err(_) => {
                let _ = std::fs::remove_file(path);
                Err(cannot_write(path))
            }
        }
    }

    /// Remove the claimed file when it is still the one with `identity` (a failed
    /// setup, §14.4).
    pub fn remove_if(&self, identity: Identity) {
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.dev() == identity.dev && metadata.ino() == identity.ino)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Whether the output's directory accepts a rewrite temporary of the longest form
    /// (created exclusively and removed at once, §14.12 "Claim").
    pub fn probe(&self) -> bool {
        let Some(file_name) = self.path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        let temp = parent(&self.path).join(crate::store::atomic::longest_temp_name(file_name));
        match rustix::fs::open(
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                drop(fd);
                let _ = std::fs::remove_file(&temp);
                true
            }
            Err(_) => false,
        }
    }

    /// `Cannot write <path>; the results are saved in <state>: resume with
    /// --output-file <new path>` (a recorded output whose rewrites cannot succeed).
    pub fn unwritable_error(&self, state: &str) -> CliError {
        CliError::operational(format!(
            "Cannot write {}; the results are saved in {state}: resume with --output-file <new path>",
            shown(&self.path)
        ))
    }

    fn rewrite_failed(&self, state: &str) -> CliError {
        CliError::operational(format!(
            "Cannot write {}; the results are saved in {state}: run '{PROGRAM} runtime resume-poll {state}' to write it again",
            shown(&self.path)
        ))
    }

    /// Step 1: write `bytes` to `.<file name>.<pid>.<16 hex>.tmp` next to the output
    /// (`O_EXCL | O_NOFOLLOW`, 0600), fsync and `fstat` it.
    pub fn prepare(&self, bytes: &[u8], state: &str) -> Result<Prepared, CliError> {
        let file_name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| self.rewrite_failed(state))?;
        let temp = parent(&self.path).join(crate::store::atomic::temp_name(&file_name));
        let written = (|| -> std::io::Result<Identity> {
            injected(Step::OutputTemp)?;
            let fd = rustix::fs::open(
                &temp,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            let mut file = File::from(fd);
            rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Identity::of_file(&file)
        })();
        match written {
            Ok(identity) => Ok(Prepared { temp, identity }),
            Err(_) => {
                let _ = std::fs::remove_file(&temp);
                Err(self.rewrite_failed(state))
            }
        }
    }

    /// The `output.next` record of a prepared rewrite.
    pub fn next_record(prepared: &Prepared) -> NextOutput {
        NextOutput {
            dev: prepared.identity.dev.to_string(),
            ino: prepared.identity.ino.to_string(),
            temp: prepared.temp.to_string_lossy().into_owned(),
        }
    }

    /// Drop a prepared rewrite (the checkpoint before it failed).
    pub fn abandon(&self, prepared: Prepared) {
        let _ = std::fs::remove_file(&prepared.temp);
    }

    /// Steps 3–5, after the checkpoint that recorded `output.next`: the identity check
    /// of the path, the rename and the directory fsync; then `output` becomes `next`
    /// in `state` (persisted by the next checkpoint).
    pub fn commit(
        &mut self,
        prepared: Prepared,
        state: &mut JobState,
        state_shown: &str,
    ) -> Result<Rewritten, CliError> {
        let known = |dev: &str, ino: &str, metadata: &std::fs::Metadata| {
            dev == metadata.dev().to_string() && ino == metadata.ino().to_string()
        };
        let acceptable = match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Ok(metadata) => {
                metadata.file_type().is_file()
                    && metadata.uid() == euid()
                    && (known(&state.output.dev, &state.output.ino, &metadata)
                        || state
                            .output
                            .next
                            .as_ref()
                            .is_some_and(|next| known(&next.dev, &next.ino, &metadata)))
            }
            Err(_) => false,
        };
        if !acceptable {
            let _ = std::fs::remove_file(&prepared.temp);
            return Err(foreign_error(&self.path, state_shown));
        }
        if injected(Step::OutputRename)
            .and_then(|()| std::fs::rename(&prepared.temp, &self.path))
            .is_err()
        {
            let _ = std::fs::remove_file(&prepared.temp);
            return Err(self.rewrite_failed(state_shown));
        }
        state.output.dev = prepared.identity.dev.to_string();
        state.output.ino = prepared.identity.ino.to_string();
        state.output.next = None;
        Ok(if sync_dir(parent(&self.path)) {
            Rewritten::Durable
        } else {
            self.warning()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::ItemStatus;
    use super::super::checkpoint::tests::tempfile_dir::Dir;
    use super::super::state::tests::sample;
    use super::super::state::{Action, Detections, ItemResult};
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const SCAN: &str = "78288af4-031d-4d49-a03c-71105cd0df8a";

    fn resolved(
        state: &mut JobState,
        index: usize,
        action: Action,
        category: &str,
        flags: &[(&str, bool)],
        error: Option<&str>,
    ) {
        let item = &mut state.items[index];
        item.status = if action == Action::Failed {
            ItemStatus::Failed
        } else {
            ItemStatus::Complete
        };
        item.scan_id = Some(SCAN.into());
        item.result = Some(ItemResult {
            action,
            category: category.into(),
            triggered: flags.iter().any(|(_, on)| *on),
            detections: Detections(flags.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()),
            scan_id: SCAN.into(),
            report_id: if action == Action::Failed {
                String::new()
            } else {
                format!("R{SCAN}")
            },
            error: error.map(str::to_owned),
        });
    }

    /// The TS capture (B§10): quoting, `true`/`false`, input order, only resolved
    /// rows, no trailing newline.
    #[test]
    fn the_projection_matches_the_typescript_bytes() {
        let mut state = sample();
        assert_eq!(projection(&state), HEADER, "header only, no newline");
        state.items[0].prompt = "hello one".into();
        state.items[1].prompt = "third, \"quoted\"".into();
        resolved(&mut state, 1, Action::Allow, "benign", &[], None);
        resolved(
            &mut state,
            0,
            Action::Block,
            "malicious",
            &[("injection", true), ("dlp", false)],
            None,
        );
        assert_eq!(
            projection(&state),
            format!(
                "{HEADER}\n\"hello one\",\"block\",\"malicious\",\"true\",\"false\",\"true\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"{SCAN}\",\"R{SCAN}\",\"\"\n\"third, \"\"quoted\"\"\",\"allow\",\"benign\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"{SCAN}\",\"R{SCAN}\",\"\""
            )
        );
        state.items[2].prompt = "=cmd|' /C calc'!A0\r\n".into();
        resolved(
            &mut state,
            2,
            Action::Failed,
            "error",
            &[],
            Some("AIRS async scan failed"),
        );
        assert!(projection(&state).ends_with(&format!(
            "\n\"=cmd|' /C calc'!A0\r\n\",\"failed\",\"error\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"false\",\"{SCAN}\",\"\",\"AIRS async scan failed\""
        )));
    }

    /// D122: the default name is always one file name in the working directory.
    #[test]
    fn default_names_stay_in_the_working_directory() {
        for (profile, expected) in [
            ("my prof", "my-prof-bulk-scan.csv"),
            ("a  \t b", "a-b-bulk-scan.csv"),
            ("../esc dir/x", "..-esc-dir-x-bulk-scan.csv"),
            ("p\u{1}q\u{7f}r\u{85}s", "p-q-r-s-bulk-scan.csv"),
            ("x\u{3000}y\u{feff}", "x-y--bulk-scan.csv"),
            ("Prisma AIRS Harness", "Prisma-AIRS-Harness-bulk-scan.csv"),
        ] {
            let name = default_name(profile);
            assert_eq!(name, expected, "{profile:?}");
            assert!(!name.contains('/'));
            assert_eq!(Path::new(&name).components().count(), 1);
        }
    }

    #[test]
    fn claims_are_exclusive_and_private() {
        let dir = Dir::new();
        let path = dir.path().join("out.csv");
        let mut output = OutputFile::new(path.clone());
        let (identity, report) = output.claim(HEADER.as_bytes()).unwrap();
        assert_eq!(report, Rewritten::Durable);
        assert_eq!(std::fs::read(&path).unwrap(), HEADER.as_bytes());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), identity.ino);
        let message = output.claim(b"x").unwrap_err().message();
        assert_eq!(
            message,
            format!(
                "{} already exists; choose another --output-file",
                path.display()
            )
        );
        let link = dir.path().join("link.csv");
        std::os::unix::fs::symlink(dir.path().join("target"), &link).unwrap();
        assert!(
            OutputFile::new(link.clone())
                .claim(b"x")
                .unwrap_err()
                .message()
                .ends_with("already exists; choose another --output-file")
        );
        assert!(refuse_existing(&link).is_err());
        assert!(!dir.path().join("target").exists());
        let missing = dir.path().join("nodir/x.csv");
        assert_eq!(
            OutputFile::new(missing.clone())
                .claim(b"x")
                .unwrap_err()
                .message(),
            format!(
                "Cannot write {}; check that its directory exists and is writable",
                missing.display()
            )
        );
        assert!(
            !dir.path().join("nodir").exists(),
            "no parent directory is created"
        );
        output.remove_if(identity);
        assert!(!path.exists());
    }

    /// §14.12: the rewrite renames only over the job's own file (or an absent one).
    #[test]
    fn rewrites_check_the_identity() {
        let dir = Dir::new();
        let path = dir.path().join("out.csv");
        let mut output = OutputFile::new(path.clone());
        let (identity, _) = output.claim(HEADER.as_bytes()).unwrap();
        let mut state = sample();
        state.output.dev = identity.dev.to_string();
        state.output.ino = identity.ino.to_string();
        let prepared = output.prepare(b"one", "S").unwrap();
        state.output.next = Some(OutputFile::next_record(&prepared));
        output.commit(prepared, &mut state, "S").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        assert!(state.output.next.is_none());
        assert_eq!(
            state.output.ino,
            std::fs::metadata(&path).unwrap().ino().to_string()
        );
        // The user removed it: the rename recreates it.
        std::fs::remove_file(&path).unwrap();
        let prepared = output.prepare(b"two", "S").unwrap();
        output.commit(prepared, &mut state, "S").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        // Replaced by another file (a spreadsheet's save): refused, temporary removed.
        // The replacement is created while the job's file still exists, so its inode
        // differs.
        let edited = dir.path().join("edited.csv");
        std::fs::write(&edited, b"edited").unwrap();
        std::fs::rename(&edited, &path).unwrap();
        let prepared = output.prepare(b"three", "S").unwrap();
        let message = output
            .commit(prepared, &mut state, "S")
            .unwrap_err()
            .message();
        assert_eq!(
            message,
            format!(
                "{} is not the file this job wrote (it was replaced, moved or edited); the results are saved in S: resume with --output-file <new path>",
                path.display()
            )
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"edited");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    /// §14.12 step 5: `resume-poll` accepts either identity, promotes a finished
    /// rewrite and removes only its own leftover temporary.
    #[test]
    fn resume_classifies_the_output_and_its_leftovers() {
        let dir = Dir::new();
        let path = dir.path().join("out.csv");
        let mut output = OutputFile::new(path.clone());
        let (identity, _) = output.claim(HEADER.as_bytes()).unwrap();
        let mut state = sample();
        state.output.path = path.to_string_lossy().into_owned();
        state.output.dev = identity.dev.to_string();
        state.output.ino = identity.ino.to_string();
        assert_eq!(at_path(&state.output), AtPath::Current);
        // A rewrite stopped after its checkpoint, before the rename: the temporary is
        // ours and is removed; the path still has the current identity.
        let prepared = output.prepare(b"one", "S").unwrap();
        state.output.next = Some(OutputFile::next_record(&prepared));
        assert_eq!(at_path(&state.output), AtPath::Current);
        let temp = PathBuf::from(&state.output.next.as_ref().unwrap().temp);
        assert!(temp.exists());
        assert!(remove_leftover_temp(&state.output));
        assert!(!temp.exists());
        // A rewrite renamed into place before its next checkpoint: the path has `next`.
        let prepared = output.prepare(b"two", "S").unwrap();
        state.output.next = Some(OutputFile::next_record(&prepared));
        std::fs::rename(
            PathBuf::from(&state.output.next.as_ref().unwrap().temp),
            &path,
        )
        .unwrap();
        assert_eq!(at_path(&state.output), AtPath::Next);
        assert!(
            !remove_leftover_temp(&state.output),
            "nothing left to remove"
        );
        // A recorded temporary that is not named like ours is never removed.
        let other = dir.path().join("precious.txt");
        std::fs::write(&other, "x").unwrap();
        let metadata = std::fs::metadata(&other).unwrap();
        state.output.next = Some(NextOutput {
            dev: metadata.dev().to_string(),
            ino: metadata.ino().to_string(),
            temp: other.to_string_lossy().into_owned(),
        });
        assert!(!remove_leftover_temp(&state.output));
        assert!(other.exists());
        // Anything else at the path is foreign; nothing is absent.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(at_path(&state.output), AtPath::Absent);
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert_eq!(at_path(&state.output), AtPath::Foreign);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "edited").unwrap();
        assert_eq!(at_path(&state.output), AtPath::Foreign);
    }

    #[test]
    fn failed_rewrites_name_the_state() {
        let dir = Dir::new();
        let path = dir.path().join("out.csv");
        let mut output = OutputFile::new(path.clone());
        let (identity, _) = output.claim(HEADER.as_bytes()).unwrap();
        let mut state = sample();
        state.output.dev = identity.dev.to_string();
        state.output.ino = identity.ino.to_string();
        let expected = format!(
            "Cannot write {}; the results are saved in S: run 'airs runtime resume-poll S' to write it again",
            path.display()
        );
        injected_case(
            Step::OutputTemp,
            || output.prepare(b"x", "S").map(|_| ()).unwrap_err().message(),
            &expected,
        );
        let prepared = output.prepare(b"x", "S").unwrap();
        super::super::checkpoint::fail_at(Some(Step::OutputRename));
        let message = output
            .commit(prepared, &mut state, "S")
            .unwrap_err()
            .message();
        super::super::checkpoint::fail_at(None);
        assert_eq!(message, expected);
        assert_eq!(std::fs::read(&path).unwrap(), HEADER.as_bytes());
        // A failed directory fsync is a warning, printed once.
        super::super::checkpoint::fail_at(Some(Step::DirSync));
        let prepared = output.prepare(b"y", "S").unwrap();
        let first = output.commit(prepared, &mut state, "S").unwrap();
        let prepared = output.prepare(b"z", "S").unwrap();
        let second = output.commit(prepared, &mut state, "S").unwrap();
        super::super::checkpoint::fail_at(None);
        assert!(
            matches!(first, Rewritten::Warning(text) if text.contains("was saved, but its directory could not be synced"))
        );
        assert_eq!(second, Rewritten::Durable);
    }

    fn injected_case(step: Step, run: impl FnOnce() -> String, expected: &str) {
        super::super::checkpoint::fail_at(Some(step));
        let message = run();
        super::super::checkpoint::fail_at(None);
        assert_eq!(message, expected);
    }
}
