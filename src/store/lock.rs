//! `D/config.lock`: the one write lock (DESIGN §3.9, D77).
//!
//! The lock is a `flock(LOCK_EX)` on `D/config.lock`. The holder writes a record
//! (`pid`, `host`, `since`) that a waiting writer reads to say who holds it. The kernel
//! releases a `flock` when its process dies, so a crash never leaves the store locked;
//! the lock file itself is never deleted (unlinking a `flock` file races a waiter that
//! already opened it).

use super::{FileError, Store, shown, unsafe_file_error};
use crate::error::CliError;
use crate::output::terminal_safe;
use rustix::fs::{FlockOperation, Mode, OFlags};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

/// How often a waiting writer retries.
pub const POLL: Duration = Duration::from_millis(100);
/// How long a writer waits in total, from its first attempt.
pub const WAIT_BOUND: Duration = Duration::from_secs(5);
/// The most holder-record bytes read.
const RECORD_LIMIT: usize = 512;
/// How often a lock file replaced before it was locked is opened again.
const REOPEN_LIMIT: u32 = 3;

/// Whether `file` is the file at `path` (same device and inode; a symlink not followed).
pub(crate) fn still_named(path: &Path, file: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), std::fs::symlink_metadata(path)) {
        (Ok(held), Ok(named)) => held.dev() == named.dev() && held.ino() == named.ino(),
        _ => false,
    }
}

/// A held lock. Dropping it releases the lock (the record is truncated first).
#[derive(Debug)]
pub struct Lock {
    file: Option<File>,
}

impl Lock {
    /// `ftruncate(0)` and close (the `flock` is released on close).
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

impl Drop for Lock {
    fn drop(&mut self) {
        self.release_now();
    }
}

/// What a waiting writer is told, and whether it should stop waiting.
pub trait Waiter {
    /// Called once, after the first failed attempt, with the holder text.
    fn waiting(&mut self, holder: &str);
    /// `Some(error)` stops the wait at once (a signal arrived).
    fn interrupted(&mut self) -> Option<CliError>;
}

/// A waiter that prints nothing and is never interrupted (tests).
#[cfg(test)]
pub struct Silent;

#[cfg(test)]
impl Waiter for Silent {
    fn waiting(&mut self, _: &str) {}
    fn interrupted(&mut self) -> Option<CliError> {
        None
    }
}

/// `pid=<pid>\nhost=<nodename>\nsince=<YYYY-MM-DDTHH:MM:SSZ>\n`.
pub fn holder_record(pid: u32, host: &str, since: SystemTime) -> String {
    let stamp = crate::debug::iso_timestamp(since);
    // `YYYY-MM-DDTHH:MM:SS.mmmZ` → whole seconds.
    let seconds = stamp.get(..19).unwrap_or(&stamp);
    let host = cut_to(host, 255);
    format!("pid={pid}\nhost={host}\nsince={seconds}Z\n")
}

fn cut_to(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn since_shaped(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 20
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// `pid <pid> on <host> since <since>` for a well-formed record, else `another process`.
pub fn holder_text(record: &[u8]) -> String {
    let parsed = std::str::from_utf8(record).ok().and_then(|text| {
        let body = text.strip_suffix('\n')?;
        let lines: Vec<&str> = body.split('\n').collect();
        let [pid, host, since] = lines.as_slice() else {
            return None;
        };
        let pid = pid.strip_prefix("pid=")?;
        let host = host.strip_prefix("host=")?;
        let since = since.strip_prefix("since=")?;
        let pid_ok = (1..=10).contains(&pid.len()) && pid.bytes().all(|b| b.is_ascii_digit());
        let host_ok = (1..=255).contains(&host.len()) && !host.chars().any(char::is_control);
        (pid_ok && host_ok && since_shaped(since))
            .then(|| format!("pid {pid} on {host} since {since}"))
    });
    match parsed {
        Some(text) => terminal_safe(&text).into_owned(),
        None => "another process".to_owned(),
    }
}

fn read_record(file: &File) -> Vec<u8> {
    let mut buffer = vec![0u8; RECORD_LIMIT];
    match rustix::io::pread(file, &mut buffer[..], 0) {
        Ok(read) => {
            buffer.truncate(read);
            buffer
        }
        Err(_) => Vec::new(),
    }
}

fn cannot_lock(path: &Path) -> CliError {
    CliError::operational(format!(
        "Cannot lock {}; the file system may not support file locks",
        shown(path)
    ))
}

/// Open `D/config.lock` (creating it 0600) and check it as a §3.8 file. `D` must exist.
fn open_lock_file(path: &Path) -> Result<File, CliError> {
    let created = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    );
    match created {
        Ok(fd) => {
            let file = File::from(fd);
            rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(|_| cannot_lock(path))?;
            Ok(file)
        }
        Err(rustix::io::Errno::EXIST) => {
            super::open_checked(path, OFlags::RDWR).map_err(|error| match error {
                FileError::Unsafe => unsafe_file_error(path),
                _ => cannot_lock(path),
            })
        }
        Err(rustix::io::Errno::LOOP) => Err(unsafe_file_error(path)),
        Err(_) => Err(cannot_lock(path)),
    }
}

/// The nodename, cut to 255 bytes.
pub fn host_name() -> String {
    let uname = rustix::system::uname();
    let name = uname.nodename().to_string_lossy().into_owned();
    cut_to(&name, 255).to_owned()
}

/// Take the store lock (§3.9 "Acquiring", steps 2–4). `D` must already exist and pass
/// §3.8. Retries every [`POLL`] for at most [`WAIT_BOUND`].
pub fn acquire(store: &Store, waiter: &mut dyn Waiter) -> Result<Lock, CliError> {
    acquire_with(store, waiter, WAIT_BOUND)
}

/// [`acquire`] with an explicit bound (tests).
pub fn acquire_with(
    store: &Store,
    waiter: &mut dyn Waiter,
    bound: Duration,
) -> Result<Lock, CliError> {
    let path = store.lock_path();
    let mut file = open_lock_file(&path)?;
    #[cfg(test)]
    tests::before_flock(&path);
    let started = Instant::now();
    let mut announced = false;
    let mut reopened = 0;
    loop {
        match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            // The lock counts only while it is on the file at the path: one removed or
            // replaced between the open and the `flock` is opened again.
            Ok(()) if still_named(&path, &file) => break,
            Ok(()) => {
                reopened += 1;
                if reopened > REOPEN_LIMIT {
                    return Err(cannot_lock(&path));
                }
                file = open_lock_file(&path)?;
                #[cfg(test)]
                tests::before_flock(&path);
            }
            Err(errno)
                if errno == rustix::io::Errno::WOULDBLOCK || errno == rustix::io::Errno::INTR =>
            {
                let holder = holder_text(&read_record(&file));
                if !announced {
                    waiter.waiting(&holder);
                    announced = true;
                }
                if let Some(error) = waiter.interrupted() {
                    return Err(error);
                }
                if started.elapsed() >= bound {
                    return Err(CliError::operational(format!(
                        "Another change is in progress: {} is held by {holder}; try again when it finishes",
                        shown(&path)
                    )));
                }
                std::thread::sleep(POLL);
                if let Some(error) = waiter.interrupted() {
                    return Err(error);
                }
            }
            Err(_) => return Err(cannot_lock(&path)),
        }
    }
    let mut lock = Lock { file: Some(file) };
    if let Some(file) = lock.file.as_mut() {
        let record = holder_record(std::process::id(), &host_name(), SystemTime::now());
        // The record is diagnostic only: a failed write leaves `another process`.
        let _ = rustix::fs::ftruncate(&*file, 0);
        let _ = rustix::io::pwrite(&*file, record.as_bytes(), 0);
        let _ = file.flush();
    }
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::super::testdir::TestDir;
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::{Child, Command, Stdio};

    #[test]
    fn holder_records_round_trip() {
        let since = SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000);
        let record = holder_record(4242, "build-host", since);
        assert_eq!(
            record,
            "pid=4242\nhost=build-host\nsince=2026-10-14T17:46:40Z\n"
        );
        assert_eq!(
            holder_text(record.as_bytes()),
            "pid 4242 on build-host since 2026-10-14T17:46:40Z"
        );
        assert_eq!(
            holder_record(1, &"h".repeat(300), since).len(),
            6 + 5 + 255 + 1 + 27
        );
    }

    #[test]
    fn malformed_records_are_another_process() {
        for record in [
            "",
            "pid=1\nhost=h\nsince=2026-10-14T02:13:20Z",
            "pid=1\nhost=h\nsince=2026-10-14T02:13:20Z\nextra=1\n",
            "pid=\nhost=h\nsince=2026-10-14T02:13:20Z\n",
            "pid=12345678901\nhost=h\nsince=2026-10-14T02:13:20Z\n",
            "pid=-1\nhost=h\nsince=2026-10-14T02:13:20Z\n",
            "pid=1\nhost=\nsince=2026-10-14T02:13:20Z\n",
            "pid=1\nhost=a\u{1b}b\nsince=2026-10-14T02:13:20Z\n",
            "pid=1\nhost=h\nsince=2026-10-14 02:13:20Z\n",
            "pid=1\nhost=h\nsince=yesterday\n",
            "host=h\npid=1\nsince=2026-10-14T02:13:20Z\n",
        ] {
            assert_eq!(
                holder_text(record.as_bytes()),
                "another process",
                "{record:?}"
            );
        }
        assert_eq!(holder_text(b"\xff\xfe"), "another process");
        assert_eq!(
            holder_text("pid=1\nhost=\u{85}x\nsince=2026-10-14T02:13:20Z\n".as_bytes()),
            "another process",
            "C1 controls are control characters"
        );
    }

    fn store(dir: &TestDir) -> Store {
        Store::at(dir.path())
    }

    /// A hook run between opening the lock file and `flock`ing it.
    type Hook = Option<Box<dyn FnMut(&Path)>>;

    thread_local! {
        /// Runs between opening the lock file and `flock`ing it (this thread only).
        static BEFORE_FLOCK: std::cell::RefCell<Hook> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn before_flock(path: &Path) {
        BEFORE_FLOCK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(path);
            }
        });
    }

    /// A lock file removed between its open and the `flock` is opened again: the lock
    /// taken is always on the file at the path, so no other writer can take a second
    /// one on a new file.
    #[test]
    fn a_lock_file_removed_before_the_flock_is_opened_again() {
        let dir = TestDir::new("lock-replaced");
        let store = store(&dir);
        let mut removals = 0;
        BEFORE_FLOCK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |path: &Path| {
                if removals == 0 {
                    std::fs::remove_file(path).unwrap();
                }
                removals += 1;
            }));
        });
        let lock = acquire(&store, &mut Silent);
        BEFORE_FLOCK.with(|hook| *hook.borrow_mut() = None);
        let lock = lock.unwrap();
        let held = lock.file.as_ref().unwrap();
        assert!(
            still_named(&store.lock_path(), held),
            "the held lock is the file at the path"
        );
        drop(lock);
    }

    #[test]
    fn lock_file_is_created_0600_written_and_truncated_on_release() {
        let dir = TestDir::new("lock-basic");
        let store = store(&dir);
        let lock = acquire(&store, &mut Silent).unwrap();
        let metadata = std::fs::metadata(store.lock_path()).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let record = std::fs::read(store.lock_path()).unwrap();
        let text = holder_text(&record);
        assert!(
            text.starts_with(&format!("pid {} on ", std::process::id())),
            "{text}"
        );
        lock.release();
        assert_eq!(std::fs::read(store.lock_path()).unwrap(), b"");
        assert!(store.lock_path().exists(), "the lock file is never deleted");
        // A second acquisition reuses the existing file.
        drop(acquire(&store, &mut Silent).unwrap());
    }

    #[test]
    fn unsafe_lock_files_are_refused() {
        let dir = TestDir::new("lock-unsafe");
        let store = store(&dir);
        let target = dir.write("elsewhere", b"", 0o600);
        symlink(&target, store.lock_path()).unwrap();
        assert!(
            acquire(&store, &mut Silent)
                .unwrap_err()
                .message()
                .starts_with(&format!("Refusing to use {}", store.lock_path().display()))
        );
        std::fs::remove_file(store.lock_path()).unwrap();
        dir.write("config.lock", b"", 0o644);
        assert!(
            acquire(&store, &mut Silent)
                .unwrap_err()
                .message()
                .starts_with("Refusing to use")
        );
    }

    struct Recording {
        waits: Vec<String>,
        polls: u32,
        stop_after: Option<u32>,
    }

    impl Waiter for Recording {
        fn waiting(&mut self, holder: &str) {
            self.waits.push(holder.to_owned());
        }
        fn interrupted(&mut self) -> Option<CliError> {
            self.polls += 1;
            match self.stop_after {
                Some(limit) if self.polls >= limit => Some(CliError::operational("stopped")),
                _ => None,
            }
        }
    }

    #[test]
    fn a_held_lock_waits_once_then_times_out_naming_the_holder() {
        let dir = TestDir::new("lock-busy");
        let store = store(&dir);
        let held = acquire(&store, &mut Silent).unwrap();
        let mut waiter = Recording {
            waits: Vec::new(),
            polls: 0,
            stop_after: None,
        };
        let started = Instant::now();
        let error = acquire_with(&store, &mut waiter, Duration::from_millis(350)).unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(350));
        assert_eq!(waiter.waits.len(), 1, "the waiting status is printed once");
        let holder = format!("pid {} on ", std::process::id());
        assert!(waiter.waits[0].starts_with(&holder), "{:?}", waiter.waits);
        let message = error.message();
        assert!(
            message.starts_with(&format!(
                "Another change is in progress: {} is held by {holder}",
                store.lock_path().display()
            )) && message.ends_with("; try again when it finishes"),
            "{message}"
        );
        // An interruption stops the wait at once.
        let mut stopping = Recording {
            waits: Vec::new(),
            polls: 0,
            stop_after: Some(1),
        };
        assert_eq!(
            acquire(&store, &mut stopping).unwrap_err().message(),
            "stopped"
        );
        drop(held);
        drop(acquire(&store, &mut Silent).unwrap());
    }

    // -- Cross-process tests: the test binary re-runs itself as the child. --------------

    const CHILD_DIR: &str = "AIRS_RS_LOCK_TEST_DIR";
    const CHILD_MODE: &str = "AIRS_RS_LOCK_TEST_MODE";

    /// Not a test: the child half of the cross-process tests. Without the variables it
    /// returns at once.
    #[test]
    #[ignore = "helper process for the cross-process lock tests"]
    fn lock_child_helper() {
        let (Ok(dir), Ok(mode)) = (std::env::var(CHILD_DIR), std::env::var(CHILD_MODE)) else {
            return;
        };
        let store = Store::at(dir);
        match mode.as_str() {
            "hold" => {
                let _lock = acquire(&store, &mut Silent).unwrap();
                println!("LOCK-HELD");
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }
            "increment" => {
                let counter = store.dir().join("counter");
                for _ in 0..25 {
                    let lock = acquire(&store, &mut Silent).unwrap();
                    let value: u64 = std::fs::read_to_string(&counter)
                        .ok()
                        .and_then(|text| text.trim().parse().ok())
                        .unwrap_or(0);
                    // Widen the race window: a lost update would show without the lock.
                    std::thread::sleep(Duration::from_millis(1));
                    super::super::atomic::write_atomic(
                        store.dir(),
                        &counter,
                        format!("{}\n", value + 1).as_bytes(),
                    )
                    .unwrap();
                    lock.release();
                }
            }
            other => panic!("unknown mode {other}"),
        }
    }

    fn spawn_child(dir: &Path, mode: &str) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::lock::tests::lock_child_helper",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_DIR, dir)
            .env(CHILD_MODE, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn wait_for_held(child: &mut Child) {
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next() {
                Some(Ok(line)) if line.contains("LOCK-HELD") => break,
                Some(Ok(_)) => {}
                _ => panic!("the helper exited before it held the lock"),
            }
        }
        // Keep the pipe open so the helper never sees EPIPE.
        std::mem::forget(lines);
    }

    #[test]
    fn another_process_holds_the_lock_until_it_is_killed() {
        let dir = TestDir::new("lock-process");
        let store = store(&dir);
        let mut child = spawn_child(dir.path(), "hold");
        wait_for_held(&mut child);
        let mut waiter = Recording {
            waits: Vec::new(),
            polls: 0,
            stop_after: None,
        };
        let error = acquire_with(&store, &mut waiter, Duration::from_millis(250)).unwrap_err();
        let holder = format!("pid {} on {} since ", child.id(), host_name());
        assert!(waiter.waits[0].starts_with(&holder), "{:?}", waiter.waits);
        assert!(error.message().contains(&holder), "{}", error.message());
        // SIGKILL: the kernel releases the flock, the stale record stays in the file.
        child.kill().unwrap();
        child.wait().unwrap();
        let stale = std::fs::read(store.lock_path()).unwrap();
        assert!(
            holder_text(&stale).starts_with(&holder),
            "stale record kept"
        );
        let started = Instant::now();
        let lock = acquire(&store, &mut Silent).unwrap();
        assert!(started.elapsed() < POLL, "no wait after the holder died");
        let fresh = holder_text(&std::fs::read(store.lock_path()).unwrap());
        assert!(
            fresh.starts_with(&format!("pid {} on ", std::process::id())),
            "the stale record was overwritten: {fresh}"
        );
        drop(lock);
    }

    #[test]
    fn concurrent_writers_in_six_processes_lose_no_update() {
        let dir = TestDir::new("lock-concurrent");
        let mut children: Vec<Child> = (0..6)
            .map(|_| spawn_child(dir.path(), "increment"))
            .collect();
        for child in &mut children {
            assert!(child.wait().unwrap().success());
        }
        let total = std::fs::read_to_string(dir.path().join("counter")).unwrap();
        assert_eq!(total, "150\n", "6 processes × 25 locked increments");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}
