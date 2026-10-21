//! The live write ledger (DESIGN §10, M4 write flow; MILESTONES live rules).
//!
//! Every create, update, apply, revert and delete of the live write flow, its teardown
//! and the sweeper is journalled to `<store root>/ledger.jsonl` (`target/live/` for the
//! real tenant): a `pending` line before the command and a result line after it. The
//! file is created 0600, opened `O_APPEND`, one JSON object per line, never rewritten.
//! A line holds only fixed vocabulary, the run id, a run-created resource name
//! (`airs-rs-e2e-…`), a UUID (a DLP id for the DLP kinds) and an exit code; [`Ledger::record`] refuses anything else,
//! so no token, credential, tenant name, TSG, endpoint, prompt, description, policy or
//! error text can reach it.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::{Value, json};

use super::writes::RESOURCE_PREFIX;

/// The file name under the store root.
pub const LEDGER_FILE: &str = "ledger.jsonl";

/// Which part of a live run wrote the line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Flow,
    Teardown,
    Cleanup,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::Flow => "flow",
            Self::Teardown => "teardown",
            Self::Cleanup => "cleanup",
        }
    }
}

/// The resource kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Profile,
    Topic,
    /// A red team draft adapter (the M6a write flow, DESIGN §10).
    Adapter,
    /// A red team scan (the M6a scan flow; scans cannot be deleted, only aborted).
    Scan,
    /// A custom DLP data pattern (the M6b write flow, DESIGN §10).
    Pattern,
    /// A custom DLP dictionary (the M6b write flow).
    Dictionary,
    /// A model-security security group (the M6c write and scan flows, DESIGN §10).
    Group,
    /// A model-security scan (the M6c scan flow; the API cannot delete it).
    ModelScan,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Topic => "topic",
            Self::Adapter => "adapter",
            Self::Scan => "scan",
            Self::Pattern => "pattern",
            Self::Dictionary => "dictionary",
            Self::Group => "group",
            Self::ModelScan => "model-scan",
        }
    }

    /// Whether the kind is a DLP resource (ids are service-defined, not UUIDs).
    pub fn is_dlp(self) -> bool {
        matches!(self, Self::Pattern | Self::Dictionary)
    }
}

/// A DLP resource id as the ledger records it: 1–64 ASCII letters, digits, `-` or `_`
/// (DLP ids are not UUIDs; they are never secrets).
pub fn is_dlp_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `id` is a valid id of `kind` (a UUID, or a DLP id for the DLP kinds).
pub fn is_resource_id(kind: Kind, id: &str) -> bool {
    if kind.is_dlp() {
        is_dlp_id(id)
    } else {
        is_uuid(id)
    }
}

/// How a journalled command ended (`Pending` is the line before it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Ok,
    Failed,
    Unknown,
    Skipped,
}

impl Outcome {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Skipped => "skipped",
        }
    }
}

/// One ledger line.
#[derive(Clone, Debug)]
pub struct Entry<'a> {
    pub phase: Phase,
    /// `rs` or `ts`.
    pub cli: &'static str,
    /// A fixed operation name (`topics create`, `profiles delete`, …).
    pub op: &'static str,
    pub kind: Kind,
    /// The run-created resource name.
    pub name: &'a str,
    /// The resource id (a UUID) when known.
    pub id: Option<&'a str>,
    pub outcome: Outcome,
    /// The exit code (`None` before the command, or after a timeout).
    pub exit: Option<i32>,
    /// §12 row numbers or check names (fixed vocabulary).
    pub note: &'a str,
}

/// The append-only ledger file.
#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    file: File,
    run: String,
}

/// `^[0-9a-f]{8}-…-[0-9a-f]{12}$`, case-insensitive.
pub fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// A note may hold only words, row numbers and punctuation.
fn fixed_vocabulary(text: &str) -> bool {
    text.len() <= 200
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" ,;:_-./()".contains(&b))
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix time (proleptic Gregorian, UTC).
pub fn utc(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rest = seconds % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// The current Unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl Ledger {
    /// Opens `<root>/ledger.jsonl` for appending (created 0600 with `root` as needed);
    /// refuses a path that is not a regular file (a symlink included) or that group or
    /// other can access.
    pub fn open(root: &Path, run: &str) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|err| format!("cannot create the ledger root: {err}"))?;
        let path = root.join(LEDGER_FILE);
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.file_type().is_file() {
                return Err("the live ledger is not a regular file".into());
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("the live ledger is accessible to group or other".into());
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|err| format!("cannot open the live ledger: {err}"))?;
        Ok(Self {
            path,
            file,
            run: run.to_owned(),
        })
    }

    /// The ledger file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one line (one `write` call, so concurrent appends do not interleave).
    pub fn record(&mut self, entry: &Entry<'_>) -> Result<(), String> {
        if !entry.name.starts_with(RESOURCE_PREFIX)
            || !entry
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("the ledger only records run-created resource names".into());
        }
        if entry.id.is_some_and(|id| !is_resource_id(entry.kind, id)) {
            return Err("the ledger only records UUIDs (DLP: service ids) as ids".into());
        }
        if !fixed_vocabulary(entry.note) || !fixed_vocabulary(entry.op) {
            return Err("a ledger note must be fixed vocabulary".into());
        }
        let line = json!({
            "v": 1,
            "ts": utc(now_unix()),
            "run": self.run,
            "phase": entry.phase.name(),
            "cli": entry.cli,
            "op": entry.op,
            "kind": entry.kind.name(),
            "name": entry.name,
            "id": entry.id,
            "outcome": entry.outcome.name(),
            "exit": entry.exit,
            "note": entry.note,
        });
        let mut text = serde_json::to_string(&line).map_err(|err| err.to_string())?;
        text.push('\n');
        self.file
            .write_all(text.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|err| format!("cannot append to the live ledger: {err}"))
    }
}

/// Every line of a ledger file, parsed (lines that are not JSON become `null`).
pub fn read(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or(Value::Null))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry<'a>(name: &'a str, id: Option<&'a str>, note: &'a str) -> Entry<'a> {
        Entry {
            phase: Phase::Flow,
            cli: "rs",
            op: "topics create",
            kind: Kind::Topic,
            name,
            id,
            outcome: Outcome::Ok,
            exit: Some(0),
            note,
        }
    }

    #[test]
    fn utc_formats_known_instants() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc(1_792_281_599), "2026-10-17T23:59:59Z");
    }

    #[test]
    fn lines_are_appended_0600_and_refuse_foreign_content() {
        let dir = tempfile::tempdir().unwrap();
        let id = "00000000-0000-4000-8000-000000000901";
        let name = "airs-rs-e2e-1792238399-7-0-topic-rs";
        let mut ledger = Ledger::open(dir.path(), "1792238399-7-0").unwrap();
        ledger.record(&entry(name, None, "")).unwrap();
        ledger.record(&entry(name, Some(id), "D93")).unwrap();
        let mode = fs::metadata(ledger.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(ledger);
        let mut again = Ledger::open(dir.path(), "1792238399-7-1").unwrap();
        again.record(&entry(name, Some(id), "id kept")).unwrap();
        let lines = read(&dir.path().join(LEDGER_FILE));
        assert_eq!(lines.len(), 3, "appended, never rewritten");
        assert_eq!(lines[1]["id"], id);
        assert_eq!(lines[1]["run"], "1792238399-7-0");
        assert_eq!(lines[2]["run"], "1792238399-7-1");
        assert_eq!(lines[0]["id"], Value::Null);
        for key in [
            "v", "ts", "run", "phase", "cli", "op", "kind", "name", "id", "outcome", "exit", "note",
        ] {
            assert!(lines[0].get(key).is_some(), "{key}");
        }
        assert!(
            again.record(&entry("alpha", None, "")).is_err(),
            "not run-created"
        );
        assert!(
            again.record(&entry(name, Some("x"), "")).is_err(),
            "not a UUID"
        );
        assert!(
            again.record(&entry(name, None, "secret=\"x\"")).is_err(),
            "free text"
        );
        assert_eq!(read(&dir.path().join(LEDGER_FILE)).len(), 3);
    }

    #[test]
    fn dlp_kinds_record_service_ids_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open(dir.path(), "1792238399-7-0").unwrap();
        let mut line = entry("airs-rs-e2e-1792238399-7-0-pattern-rs", Some("p-new-1"), "");
        line.kind = Kind::Pattern;
        ledger.record(&line).unwrap();
        line.id = Some("p new");
        assert!(ledger.record(&line).is_err(), "not a DLP id");
        let mut topic = entry("airs-rs-e2e-1792238399-7-0-topic-rs", Some("p-new-1"), "");
        topic.kind = Kind::Topic;
        assert!(ledger.record(&topic).is_err(), "a topic id is a UUID");
        assert!(is_dlp_id("6762a4e6_b0"));
        assert!(!is_dlp_id(&"x".repeat(65)));
    }

    #[test]
    fn a_symlinked_or_shared_ledger_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(LEDGER_FILE)).unwrap();
        assert!(Ledger::open(dir.path(), "r").is_err());
        let other = tempfile::tempdir().unwrap();
        let path = other.path().join(LEDGER_FILE);
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Ledger::open(other.path(), "r").is_err());
    }
}
