//! The per-job lock (DESIGN §14.11, D119): `flock(LOCK_EX | LOCK_NB)` on
//! `<S>/<job>.lock`, opened relative to the checked state directory, with the §3.9
//! holder record. There is no wait: a held lock is refused at once, naming its holder.
//! The kernel releases the lock when its holder dies, so there are no stale locks; the
//! file is never deleted (except by a `bulk-scan` whose setup failed, §14.4).

use super::{Identity, StateDir, private_regular};
use crate::error::CliError;
use crate::store::lock::{holder_record, holder_text, host_name};
use crate::store::{shown, unsafe_file_error};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use std::fs::File;
use std::path::PathBuf;
use std::time::SystemTime;

/// The most holder-record bytes read.
const RECORD_LIMIT: usize = 512;
/// How often `resume-poll` opens a lock file that was replaced before it was locked.
const ATTEMPTS: usize = 3;

/// Whether `file` is the file named `name` in `dir` (same device and inode).
fn still_named(dir: &StateDir, name: &str, file: &File) -> bool {
    match (
        rustix::fs::fstat(file),
        rustix::fs::statat(dir.fd(), name, AtFlags::SYMLINK_NOFOLLOW),
    ) {
        (Ok(held), Ok(named)) => Identity::of_stat(&held) == Identity::of_stat(&named),
        _ => false,
    }
}

/// A held job lock; dropping it releases the lock (`ftruncate(0)` and close).
#[derive(Debug)]
pub struct JobLock {
    file: Option<File>,
    name: String,
    path: PathBuf,
}

/// `<job>.lock`.
pub fn lock_name(job: &str) -> String {
    format!("{job}.lock")
}

fn cannot_lock(path: &std::path::Path) -> CliError {
    CliError::operational(format!(
        "Cannot lock {}; the file system may not support file locks",
        shown(path)
    ))
}

/// `Bulk-scan job is already active in process <pid> on <host> since <since>. …`
/// (`in another process` without a well-formed holder record).
pub fn active_message(record: &[u8], state: &str) -> String {
    let holder = holder_text(record);
    let holder = match holder.strip_prefix("pid ") {
        Some(rest) => format!("process {rest}"),
        None => holder,
    };
    format!(
        "Bulk-scan job is already active in {holder}. Wait for it to finish before resuming {state}."
    )
}

impl JobLock {
    /// Create `<job>.lock` with `O_EXCL` (the job id is fresh) and lock it
    /// (`bulk-scan`, §14.4 step 4).
    pub fn create(dir: &StateDir, job: &str, state: &str) -> Result<Self, CliError> {
        let name = lock_name(job);
        let path = dir.path().join(&name);
        let fd = rustix::fs::openat(
            dir.fd(),
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| cannot_lock(&path))?;
        let file = File::from(fd);
        rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(|_| cannot_lock(&path))?;
        match Self::lock(dir, file, name, path.clone(), state)? {
            Some(lock) => Ok(lock),
            // The fresh file was removed between its creation and the lock.
            None => Err(cannot_lock(&path)),
        }
    }

    /// Open (creating it 0600 when missing) and lock an existing job's lock file, with
    /// the §3.8 file rule (`resume-poll`, §14.13 step 3; the lock-spec ports).
    ///
    /// A lock file that is removed or replaced between its open and the `flock` is
    /// opened again (at most [`ATTEMPTS`] times), so the lock taken is always the one on
    /// the file at `<job>.lock`.
    pub fn acquire(dir: &StateDir, job: &str, state: &str) -> Result<Self, CliError> {
        let name = lock_name(job);
        let path = dir.path().join(&name);
        for _ in 0..ATTEMPTS {
            let file = Self::open_existing(dir, &name, &path)?;
            #[cfg(test)]
            tests::before_flock(&path);
            if let Some(lock) = Self::lock(dir, file, name.clone(), path.clone(), state)? {
                return Ok(lock);
            }
        }
        Err(cannot_lock(&path))
    }

    /// Open `<job>.lock`, creating it 0600 when missing, with the §3.8 file rule.
    fn open_existing(dir: &StateDir, name: &str, path: &std::path::Path) -> Result<File, CliError> {
        let created = rustix::fs::openat(
            dir.fd(),
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        );
        let file = match created {
            Ok(fd) => {
                let file = File::from(fd);
                rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600))
                    .map_err(|_| cannot_lock(path))?;
                file
            }
            Err(rustix::io::Errno::EXIST) => {
                let before = rustix::fs::statat(dir.fd(), name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| cannot_lock(path))?;
                if !private_regular(&before) {
                    return Err(unsafe_file_error(path));
                }
                let fd = rustix::fs::openat(
                    dir.fd(),
                    name,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|errno| {
                    if errno == rustix::io::Errno::LOOP {
                        unsafe_file_error(path)
                    } else {
                        cannot_lock(path)
                    }
                })?;
                let file = File::from(fd);
                let after = rustix::fs::fstat(&file).map_err(|_| cannot_lock(path))?;
                if !private_regular(&after)
                    || Identity::of_stat(&after) != Identity::of_stat(&before)
                {
                    return Err(unsafe_file_error(path));
                }
                file
            }
            Err(rustix::io::Errno::LOOP) => return Err(unsafe_file_error(path)),
            Err(_) => return Err(cannot_lock(path)),
        };
        Ok(file)
    }

    /// `flock` `file`, then check that it is still the file named `name` in `dir`
    /// (`fstat` against `statat`): `None` when it was removed or replaced in between
    /// (the lock is dropped), so a caller never holds a lock on an unlinked file.
    fn lock(
        dir: &StateDir,
        file: File,
        name: String,
        path: PathBuf,
        state: &str,
    ) -> Result<Option<Self>, CliError> {
        match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(errno) if errno == rustix::io::Errno::WOULDBLOCK => {
                let mut record = vec![0u8; RECORD_LIMIT];
                let read = rustix::io::pread(&file, &mut record[..], 0).unwrap_or(0);
                record.truncate(read);
                return Err(CliError::operational(active_message(&record, state)));
            }
            Err(_) => return Err(cannot_lock(&path)),
        }
        if !still_named(dir, &name, &file) {
            return Ok(None);
        }
        let record = holder_record(std::process::id(), &host_name(), SystemTime::now());
        // The record is diagnostic only: a failed write leaves `another process`.
        let _ = rustix::fs::ftruncate(&file, 0);
        let _ = rustix::io::pwrite(&file, record.as_bytes(), 0);
        Ok(Some(Self {
            file: Some(file),
            name,
            path,
        }))
    }

    /// Whether the held lock is still on the file at `<job>.lock` (checked before every
    /// submission's C1, §14.11): a lock file removed or replaced while it is held no
    /// longer keeps another `resume-poll` out.
    pub fn still_held(&self, dir: &StateDir) -> bool {
        self.file
            .as_ref()
            .is_some_and(|file| still_named(dir, &self.name, file))
    }

    /// `<lock> was removed or replaced by another program; the job was stopped`.
    pub fn removed_message(&self) -> String {
        format!(
            "{} was removed or replaced by another program; the job was stopped",
            shown(&self.path)
        )
    }

    /// The lock file's path.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Unlink the lock file while it is held, when it is still the file this process
    /// created (a `bulk-scan` whose setup failed; no other process knows the job id).
    pub fn remove(mut self, dir: &StateDir) {
        if let Some(file) = &self.file
            && let (Ok(held), Ok(named)) = (
                rustix::fs::fstat(file),
                rustix::fs::statat(dir.fd(), self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW),
            )
            && Identity::of_stat(&held) == Identity::of_stat(&named)
        {
            let _ = rustix::fs::unlinkat(dir.fd(), self.name.as_str(), AtFlags::empty());
        }
        self.release_now();
    }

    /// `ftruncate(0)` and close.
    pub fn release(mut self) {
        self.release_now();
    }

    fn release_now(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = rustix::fs::ftruncate(&file, 0);
            drop(file);
        }
    }
}

impl Drop for JobLock {
    fn drop(&mut self) {
        self.release_now();
    }
}

#[cfg(test)]
mod tests {
    use super::super::checkpoint::tests::TempState;
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const JOB: &str = "20261017T120000Z-3f9c0a1b2c3d4e5f";

    fn dir(temp: &TempState) -> StateDir {
        StateDir::ensure(&temp.bulk_dir()).unwrap()
    }

    /// lock-spec #7: one owner at a time, refused at once naming the holder; released
    /// for a later run.
    #[test]
    fn one_owner_at_a_time() {
        let temp = TempState::new();
        let dir = dir(&temp);
        let held = JobLock::create(&dir, JOB, "STATE").unwrap();
        let mode = std::fs::metadata(held.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let refused = JobLock::acquire(&dir, JOB, "STATE").unwrap_err().message();
        let expected = format!(
            "Bulk-scan job is already active in process {} on {} since ",
            std::process::id(),
            host_name()
        );
        assert!(refused.starts_with(&expected), "{refused}");
        assert!(
            refused.ends_with(". Wait for it to finish before resuming STATE."),
            "{refused}"
        );
        held.release();
        let again = JobLock::acquire(&dir, JOB, "STATE").unwrap();
        // A fresh job id cannot be created twice.
        assert!(JobLock::create(&dir, JOB, "STATE").is_err());
        drop(again);
        // The released file stays, empty.
        assert_eq!(std::fs::read(dir.path().join(lock_name(JOB))).unwrap(), b"");
    }

    /// lock-spec #8: a dead owner never blocks (the kernel released its `flock`); its
    /// record is not shown and the file stays.
    #[test]
    fn a_dead_owners_record_never_blocks() {
        let temp = TempState::new();
        let dir = dir(&temp);
        let path = dir.path().join(lock_name(JOB));
        std::fs::write(
            &path,
            "pid=2147483647\nhost=gone\nsince=2026-10-14T17:46:40Z\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let held = JobLock::acquire(&dir, JOB, "STATE").unwrap();
        let record = std::fs::read_to_string(&path).unwrap();
        assert!(
            record.starts_with(&format!("pid={}\n", std::process::id())),
            "{record}"
        );
        drop(held);
        assert!(path.exists());
    }

    /// A hook run between opening the lock file and `flock`ing it.
    type Hook = Option<Box<dyn FnMut(&std::path::Path)>>;

    thread_local! {
        /// Runs between opening the lock file and `flock`ing it (this thread only).
        static BEFORE_FLOCK: std::cell::RefCell<Hook> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn before_flock(path: &std::path::Path) {
        BEFORE_FLOCK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(path);
            }
        });
    }

    /// A lock file removed between its open and the `flock` is opened again, so the
    /// lock taken is on the file at `<job>.lock`; a held lock whose file is removed or
    /// replaced is no longer held (checked before every C1, §14.11).
    #[test]
    fn the_lock_is_always_on_the_file_at_its_name() {
        let temp = TempState::new();
        let dir = dir(&temp);
        let mut removals = 0;
        BEFORE_FLOCK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |path: &std::path::Path| {
                if removals == 0 {
                    std::fs::remove_file(path).unwrap();
                }
                removals += 1;
            }));
        });
        let held = JobLock::acquire(&dir, JOB, "S");
        BEFORE_FLOCK.with(|hook| *hook.borrow_mut() = None);
        let held = held.unwrap();
        assert!(held.still_held(&dir), "the lock is on the file at its name");
        // Removed while held: no longer held; a new file in its place is not ours.
        std::fs::remove_file(held.path()).unwrap();
        assert!(!held.still_held(&dir));
        let other = JobLock::acquire(&dir, JOB, "S").unwrap();
        assert!(!held.still_held(&dir));
        assert!(other.still_held(&dir));
        assert_eq!(
            held.removed_message(),
            format!(
                "{} was removed or replaced by another program; the job was stopped",
                held.path().display()
            )
        );
    }

    #[test]
    fn holder_messages() {
        assert_eq!(
            active_message(
                b"pid=42\nhost=h\nsince=2026-10-14T17:46:40Z\n",
                "/s/j.bulk-scan.json"
            ),
            "Bulk-scan job is already active in process 42 on h since 2026-10-14T17:46:40Z. Wait for it to finish before resuming /s/j.bulk-scan.json."
        );
        assert_eq!(
            active_message(b"garbage", "S"),
            "Bulk-scan job is already active in another process. Wait for it to finish before resuming S."
        );
    }

    #[test]
    fn unsafe_lock_files_are_refused() {
        let temp = TempState::new();
        let dir = dir(&temp);
        let path = dir.path().join(lock_name(JOB));
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            JobLock::acquire(&dir, JOB, "S")
                .unwrap_err()
                .message()
                .starts_with("Refusing to use ")
        );
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(temp.dir.path().join("elsewhere"), &path).unwrap();
        assert!(
            JobLock::acquire(&dir, JOB, "S")
                .unwrap_err()
                .message()
                .starts_with("Refusing to use ")
        );
        assert!(!temp.dir.path().join("elsewhere").exists());
    }

    #[test]
    fn a_failed_setup_removes_its_own_lock() {
        let temp = TempState::new();
        let dir = dir(&temp);
        let held = JobLock::create(&dir, JOB, "S").unwrap();
        let path = held.path().to_path_buf();
        held.remove(&dir);
        assert!(!path.exists());
    }
}
