//! Bulk scanning (DESIGN §14): the shared types of a job, its state directory and the
//! helpers every part of `runtime bulk-scan` and `runtime resume-poll` uses.
//!
//! - [`input`]: the line and CSV parsers and the prompt checks (§14.3).
//! - [`plan`]: logical batches, chunks within the body budget, receipt grouping (§14.5).
//! - [`state`]: the state schema, its writer, strict reader and invariants (§14.9).
//! - [`checkpoint`]: the descriptor-relative durable write of the state, its checked
//!   load and the stale-temporary sweep (§14.9, §14.10).
//! - [`lock`]: the per-job `flock` (§14.11).
//! - [`output`]: the CSV projection, the exclusive claim and the identity-checked
//!   rewrite (§14.12).
//! - [`engine`]: submission, polling and result correlation (§14.6–§14.8).

pub mod checkpoint;
pub mod engine;
pub mod input;
pub mod lock;
pub mod output;
pub mod plan;
pub mod state;

use crate::error::CliError;
use crate::store::{dir_metadata_ok, euid, shown, unsafe_dir_error};
use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The most prompts one job holds (D128).
pub const MAX_PROMPTS: usize = 10_000;
/// The SDK's largest async submission (`MAX_NUMBER_OF_BATCH_SCAN_OBJECTS`).
pub const CHUNK_SIZE: usize = 20;
/// The largest serialised state, in bytes (§14.9).
pub const MAX_STATE_BYTES: u64 = 128 * 1024 * 1024;
/// The largest `batchSize` (`Number.MAX_SAFE_INTEGER`).
pub const MAX_BATCH_SIZE: u64 = (1 << 53) - 1;
/// The program name in the resume hints (D73).
pub const PROGRAM: &str = crate::store::PROGRAM;
/// The state file suffix (`<job>.bulk-scan.json`).
pub const STATE_SUFFIX: &str = ".bulk-scan.json";

/// An item's state (the TypeScript set, §14.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemStatus {
    Pending,
    Submitting,
    Submitted,
    Complete,
    Failed,
    Ambiguous,
}

impl ItemStatus {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitting => "submitting",
            Self::Submitted => "submitted",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// How one POST attempt ended (the attempt journal, §14.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AttemptOutcome {
    InFlight,
    Accepted,
    UnusableReceipt,
    Rejected,
    NotSent,
    Unknown,
}

/// `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, case-insensitive
/// (the §7.1 id shape).
pub fn is_scan_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// The indices as ascending comma-separated `a-b` ranges or single numbers
/// (`0-19`, `18, 20-24`).
pub fn ranges(indices: &[u64]) -> String {
    let mut sorted = indices.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut iter = sorted.into_iter().peekable();
    while let Some(start) = iter.next() {
        let mut end = start;
        while iter.peek() == Some(&(end + 1)) {
            end += 1;
            iter.next();
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
    }
    parts.join(", ")
}

/// 16 lowercase hex digits from 8 random bytes (the v4 UUID generator's source).
pub fn random_hex() -> String {
    uuid::Uuid::new_v4().as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A fresh job id: `<UTC yyyymmddThhmmssZ>-<16 lowercase hex>`.
pub fn new_job_id(now: std::time::SystemTime) -> String {
    let stamp = crate::debug::iso_timestamp(now);
    // `YYYY-MM-DDTHH:MM:SS.mmmZ` → `YYYYMMDDTHHMMSSZ`.
    let compact: String = stamp
        .get(..19)
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T')
        .collect();
    format!("{compact}Z-{}", random_hex())
}

/// `^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$`
pub fn is_job_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 33
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            0..=7 | 9..=14 => byte.is_ascii_digit(),
            8 => *byte == b'T',
            15 => *byte == b'Z',
            16 => *byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// The UTC timestamp format of the state (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
pub fn now_stamp() -> String {
    crate::debug::iso_timestamp(std::time::SystemTime::now())
}

/// Whether `value` has the `YYYY-MM-DDTHH:MM:SS.mmmZ` shape.
pub fn is_stamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 24
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'.',
            23 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// The bulk-scan state directory `S` (§14.9): `$XDG_STATE_HOME/airs-cli/bulk-scans`
/// when it is set and non-empty (it must be absolute), else
/// `<home>/.local/state/airs-cli/bulk-scans` (an absolute home only).
pub fn state_dir_path(
    xdg_state_home: Option<&std::ffi::OsStr>,
    home: Option<&Path>,
) -> Result<PathBuf, CliError> {
    if let Some(state) = xdg_state_home.filter(|value| !value.is_empty()) {
        let state = Path::new(state);
        if !state.is_absolute() {
            return Err(CliError::operational(
                "XDG_STATE_HOME must be an absolute path",
            ));
        }
        return Ok(crate::store::normalize(&state.join("airs-cli/bulk-scans")));
    }
    match home.filter(|home| home.is_absolute()) {
        Some(home) => Ok(crate::store::normalize(
            &home.join(".local/state/airs-cli/bulk-scans"),
        )),
        None => Err(CliError::operational(
            "Cannot store the bulk-scan state: HOME is not an absolute path; set XDG_STATE_HOME",
        )),
    }
}

/// The checked state directory: its canonical path and a descriptor opened with
/// `O_DIRECTORY | O_NOFOLLOW` that every state, temporary and lock file is opened,
/// renamed and unlinked relative to.
#[derive(Debug)]
pub struct StateDir {
    path: PathBuf,
    fd: File,
}

impl StateDir {
    /// Create `dir` if missing (0700, an existing directory is never chmod'ed),
    /// canonicalise it, open it and check it on the descriptor (§3.8 directory rule).
    pub fn ensure(dir: &Path) -> Result<Self, CliError> {
        let cannot = || {
            CliError::operational(format!(
                "Cannot create {}; check the permissions of its parent directory",
                shown(dir)
            ))
        };
        match std::fs::symlink_metadata(dir) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)
                    .map_err(|_| cannot())?;
            }
            Err(_) => return Err(cannot()),
        }
        Self::open(dir)
    }

    /// Open an existing `dir` (canonicalised) and check it on the descriptor.
    pub fn open(dir: &Path) -> Result<Self, CliError> {
        let refuse = |path: &Path| unsafe_dir_error(path);
        // A symlinked leaf is refused before it is resolved.
        match std::fs::symlink_metadata(dir) {
            Ok(metadata) if !metadata.file_type().is_dir() => return Err(refuse(dir)),
            Ok(_) => {}
            Err(_) => {
                return Err(CliError::operational(format!(
                    "Cannot create {}; check the permissions of its parent directory",
                    shown(dir)
                )));
            }
        }
        let path = std::fs::canonicalize(dir).map_err(|_| refuse(dir))?;
        let fd = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| refuse(&path))?;
        let fd = File::from(fd);
        let metadata = fd.metadata().map_err(|_| refuse(&path))?;
        if !dir_metadata_ok(
            metadata.file_type().is_dir(),
            metadata.uid(),
            metadata.permissions().mode(),
            euid(),
        ) {
            return Err(refuse(&path));
        }
        Ok(Self { path, fd })
    }

    /// The canonical directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The checked descriptor.
    pub fn fd(&self) -> &File {
        &self.fd
    }

    /// `fsync` of the directory; whether it worked.
    pub fn sync(&self) -> bool {
        checkpoint::injected(checkpoint::Step::DirSync).is_ok() && self.fd.sync_all().is_ok()
    }
}

/// A file's device and inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub dev: u64,
    pub ino: u64,
}

impl Identity {
    // `st_dev` and `st_ino` have platform-dependent integer types.
    #[allow(clippy::unnecessary_cast)]
    pub fn of_stat(stat: &rustix::fs::Stat) -> Self {
        Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
        }
    }

    pub fn of_file(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

/// Whether a `statat` result is a regular file owned by the effective uid with no
/// group or other permissions (the §3.8 file rule).
// `st_mode` is `u16` on macOS and `u32` on Linux.
#[allow(clippy::unnecessary_cast)]
pub fn private_regular(stat: &rustix::fs::Stat) -> bool {
    rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::RegularFile
        && stat.st_uid == euid()
        && (stat.st_mode as u32) & 0o077 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn ranges_are_ascending_runs() {
        assert_eq!(ranges(&(0..20).collect::<Vec<_>>()), "0-19");
        assert_eq!(ranges(&[24, 18, 20, 21, 22, 23]), "18, 20-24");
        assert_eq!(ranges(&[5]), "5");
        assert_eq!(ranges(&[1, 3, 5]), "1, 3, 5");
        assert_eq!(ranges(&[]), "");
    }

    #[test]
    fn job_ids_have_the_documented_shape() {
        let id = new_job_id(UNIX_EPOCH + Duration::from_secs(1_792_000_000));
        assert!(id.starts_with("20261014T174640Z-"), "{id}");
        assert!(is_job_id(&id), "{id}");
        assert_ne!(
            id,
            new_job_id(UNIX_EPOCH + Duration::from_secs(1_792_000_000))
        );
        for bad in [
            "",
            "20261014T174640Z-0123456789abcdeF",
            "20261014T174640-0123456789abcdef0",
            "2026101xT174640Z-0123456789abcdef",
            "20261014T174640Z-0123456789abcde",
        ] {
            assert!(!is_job_id(bad), "{bad}");
        }
    }

    #[test]
    fn scan_ids_are_uuid_shaped() {
        assert!(is_scan_id("00000000-0000-4000-8000-0000000000a1"));
        assert!(is_scan_id("ABCDEF00-0000-4000-8000-0000000000A1"));
        for bad in [
            "not-a-uuid",
            "",
            "00000000-0000-4000-8000-0000000000a",
            "00000000_0000-4000-8000-0000000000a1",
        ] {
            assert!(!is_scan_id(bad), "{bad}");
        }
    }

    #[test]
    fn the_state_directory_follows_xdg_then_home() {
        let home = Path::new("/home/u");
        assert_eq!(
            state_dir_path(Some("/s//x/".as_ref()), Some(home)).unwrap(),
            Path::new("/s/x/airs-cli/bulk-scans")
        );
        assert_eq!(
            state_dir_path(None, Some(home)).unwrap(),
            Path::new("/home/u/.local/state/airs-cli/bulk-scans")
        );
        assert_eq!(
            state_dir_path(Some("".as_ref()), Some(home)).unwrap(),
            Path::new("/home/u/.local/state/airs-cli/bulk-scans")
        );
        assert_eq!(
            state_dir_path(Some("rel".as_ref()), Some(home))
                .unwrap_err()
                .message(),
            "XDG_STATE_HOME must be an absolute path"
        );
        assert_eq!(
            state_dir_path(None, Some(Path::new("rel")))
                .unwrap_err()
                .message(),
            "Cannot store the bulk-scan state: HOME is not an absolute path; set XDG_STATE_HOME"
        );
        assert!(state_dir_path(None, None).is_err());
    }

    #[test]
    fn stamps_have_the_state_shape() {
        assert!(is_stamp(&now_stamp()));
        assert!(!is_stamp("2026-10-17T12:00:00Z"));
    }
}
