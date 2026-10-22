//! `model-security install --fetch-uv` (DESIGN §17.14, D195): one pinned uv release,
//! downloaded into the airs-cli tools directory, its archive SHA-256 verified before
//! anything else, extracted in memory by a strict tar reader that writes no archive
//! path, and installed with exclusive creates relative to the checked tools-directory
//! descriptor. An existing copy is verified and never replaced.

use crate::bulk::StateDir;
use crate::error::{CliError, InterruptContext};
use crate::store::{dir_metadata_ok, euid, file_metadata_ok, shown};
use rustix::fs::{AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The pinned uv release (choice 26).
pub const UV_VERSION: &str = "0.12.17";
/// The pinned version as numbers.
pub const UV_VERSION_PARTS: (u64, u64, u64) = (0, 12, 17);

/// One host target of the pinned release: the cargo-dist target triple and the SHA-256 of
/// `uv-<target>.tar.gz` from the release's official `sha256.sum` (§17.14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    pub target: &'static str,
    pub sha256: &'static str,
}

/// Every pinned target (Linux uses the static musl assets, choice 26).
pub const RELEASES: [Release; 4] = [
    Release {
        target: "aarch64-apple-darwin",
        sha256: "85f00cbdc6dd3e97eba4c31b4d014375a9fdfe8f570023b84e5102fc3456896b",
    },
    Release {
        target: "x86_64-apple-darwin",
        sha256: "8dcf05a8c809bb3c471d2b614788ba27a6e41298fc8c31ac84b5f4339fd468e5",
    },
    Release {
        target: "aarch64-unknown-linux-musl",
        sha256: "a6096da273d548cb9f277d237a01ac7344a39ef0f455c0e148e4dc9737c1596b",
    },
    Release {
        target: "x86_64-unknown-linux-musl",
        sha256: "6401c4665d8fa2a9893e087c91f585430738e3170f5398a1141483efb4a93310",
    },
];

/// The target triple of this host, when the release has one.
pub fn host_target() -> Option<&'static str> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-musl")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-musl")
    } else {
        None
    }
}

/// The pinned release of this host.
pub fn host_release() -> Option<Release> {
    let target = host_target()?;
    RELEASES
        .into_iter()
        .find(|release| release.target == target)
}

pub const NO_RELEASE: &str =
    "--fetch-uv has no pinned uv release for this platform; install uv yourself.";

/// `uv-<target>.tar.gz`.
pub fn archive_name(target: &str) -> String {
    format!("uv-{target}.tar.gz")
}

/// The official download URL of the pinned archive.
pub fn release_url(target: &str) -> String {
    format!(
        "https://github.com/astral-sh/uv/releases/download/{UV_VERSION}/{}",
        archive_name(target)
    )
}

/// `uv-0.12.17-<target>`: the managed copy's directory under the tools directory.
pub fn managed_name(target: &str) -> String {
    format!("uv-{UV_VERSION}-{target}")
}

/// Where the archive comes from and the hash it must have: the release, or (debug builds
/// only) the loopback test hook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub target: &'static str,
    pub url: String,
    pub sha256: String,
    /// The one loopback http hop of the test hook is allowed.
    pub loopback: bool,
}

impl Source {
    /// The release source of this host, or the test hook's replacement (choice 36).
    pub fn for_host(hook: Option<&(String, String)>) -> Result<Self, CliError> {
        let release = host_release().ok_or_else(|| CliError::operational(NO_RELEASE))?;
        Ok(match hook {
            Some((url, sha256)) => Self {
                target: release.target,
                url: url.clone(),
                sha256: sha256.clone(),
                loopback: true,
            },
            None => Self {
                target: release.target,
                url: release_url(release.target),
                sha256: release.sha256.to_owned(),
                loopback: false,
            },
        })
    }
}

/// Whether the `--fetch-uv` test hook is compiled into this build (debug builds only).
#[cfg_attr(all(debug_assertions, not(test)), allow(dead_code))]
pub const HOOK_COMPILED: bool = cfg!(debug_assertions);

// A release build contains neither the hook's code nor its variable names (choice 36).
#[cfg(not(debug_assertions))]
const _: () = assert!(!HOOK_COMPILED);

#[cfg(debug_assertions)]
mod hook {
    use crate::error::CliError;

    pub const URL_VAR: &str = "AIRS_CLI_TEST_UV_ARCHIVE_URL";
    pub const SHA_VAR: &str = "AIRS_CLI_TEST_UV_ARCHIVE_SHA256";
    pub const REFUSED: &str = "AIRS_CLI_TEST_UV_ARCHIVE_URL must be a loopback http URL with AIRS_CLI_TEST_UV_ARCHIVE_SHA256";

    /// The hook's values, both or neither: an `http://127.0.0.1:<port>/…` or
    /// `http://[::1]:<port>/…` URL and 64 lowercase hex digits.
    pub fn values(
        url: Option<&str>,
        sha: Option<&str>,
    ) -> Result<Option<(String, String)>, CliError> {
        match (url, sha) {
            (None, None) => Ok(None),
            (Some(url), Some(sha)) => {
                let parsed = url::Url::parse(url).map_err(|_| CliError::usage(REFUSED))?;
                let loopback_host = matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]"));
                let ok = parsed.scheme() == "http"
                    && loopback_host
                    && parsed.port().is_some()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                    && sha.len() == 64
                    && sha
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                if ok {
                    Ok(Some((url.to_owned(), sha.to_owned())))
                } else {
                    Err(CliError::usage(REFUSED))
                }
            }
            _ => Err(CliError::usage(REFUSED)),
        }
    }

    pub fn from_env() -> Result<Option<(String, String)>, CliError> {
        let read = |name: &str| match std::env::var_os(name) {
            None => Ok(None),
            Some(value) => value
                .into_string()
                .map(Some)
                .map_err(|_| CliError::usage(REFUSED)),
        };
        values(read(URL_VAR)?.as_deref(), read(SHA_VAR)?.as_deref())
    }
}

/// The `--fetch-uv` test hook (debug builds only; a release build has none): the URL and
/// hash that replace the release's, checked during planning (exit 2).
pub fn test_hook() -> Result<Option<(String, String)>, CliError> {
    #[cfg(debug_assertions)]
    {
        hook::from_env()
    }
    #[cfg(not(debug_assertions))]
    {
        Ok(None)
    }
}

/// `T = <data>/airs-cli/tools` (§17.14): `$XDG_DATA_HOME` when set and non-empty (it must
/// be absolute), else `<home>/.local/share`.
pub fn tools_dir_path(
    xdg_data_home: Option<&std::ffi::OsStr>,
    home: Option<&Path>,
) -> Result<PathBuf, CliError> {
    if let Some(data) = xdg_data_home.filter(|value| !value.is_empty()) {
        let data = Path::new(data);
        if !data.is_absolute() {
            return Err(CliError::operational(
                "XDG_DATA_HOME must be an absolute path",
            ));
        }
        return Ok(crate::store::normalize(&data.join("airs-cli/tools")));
    }
    match home.filter(|home| home.is_absolute()) {
        Some(home) => Ok(crate::store::normalize(
            &home.join(".local/share/airs-cli/tools"),
        )),
        None => Err(CliError::operational(
            "Cannot install uv: HOME is not an absolute path; set XDG_DATA_HOME",
        )),
    }
}

/// The lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The `SHA256SUMS` content of a managed copy.
pub fn sums_text(target: &str, archive_sha: &str, uv_sha: &str) -> String {
    format!("{archive_sha}  {}\n{uv_sha}  uv\n", archive_name(target))
}

fn not_verified(path: &Path) -> CliError {
    CliError::operational(format!(
        "{} exists but is not the verified uv {UV_VERSION}; remove it to download again.",
        shown(path)
    ))
}

/// The bound on a managed `uv` read back for its hash, and on the gunzipped archive.
pub const MAX_UNPACKED_BYTES: u64 = 256 * 1024 * 1024;
/// The bound on the downloaded archive.
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

/// Open `name` under `dir` without following a symlink.
fn open_at(dir: &File, name: &str, flags: OFlags) -> rustix::io::Result<File> {
    rustix::fs::openat(
        dir,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

/// The state of the managed copy.
#[derive(Debug)]
pub enum Managed {
    /// Verified: the absolute path of its `uv`.
    Verified(PathBuf),
    /// Not there (the tools directory may be missing too).
    Absent,
}

/// Look for the managed copy under the existing tools directory `tools` and verify it
/// (§17.14 "Reuse"); a copy that does not verify is refused, never replaced.
pub fn verify_managed(tools: &StateDir, source: &Source) -> Result<Managed, CliError> {
    let name = managed_name(source.target);
    let dir_path = tools.path().join(&name);
    let dir = match open_at(tools.fd(), &name, OFlags::RDONLY | OFlags::DIRECTORY) {
        Ok(dir) => dir,
        Err(rustix::io::Errno::NOENT) => {
            // A dangling symlink is still "something there".
            return match std::fs::symlink_metadata(&dir_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Managed::Absent),
                _ => Err(not_verified(&dir_path)),
            };
        }
        Err(_) => return Err(not_verified(&dir_path)),
    };
    let fail = || not_verified(&dir_path);
    let metadata = dir.metadata().map_err(|_| fail())?;
    if !dir_metadata_ok(metadata.is_dir(), metadata.uid(), metadata.mode(), euid()) {
        return Err(fail());
    }
    let sums =
        open_at(&dir, "SHA256SUMS", OFlags::RDONLY | OFlags::NONBLOCK).map_err(|_| fail())?;
    let sums_meta = sums.metadata().map_err(|_| fail())?;
    if !file_metadata_ok(
        sums_meta.is_file(),
        sums_meta.uid(),
        sums_meta.mode(),
        euid(),
    ) || sums_meta.len() > 4096
    {
        return Err(fail());
    }
    let mut text = String::new();
    sums.take(4097)
        .read_to_string(&mut text)
        .map_err(|_| fail())?;
    let uv = open_at(&dir, "uv", OFlags::RDONLY | OFlags::NONBLOCK).map_err(|_| fail())?;
    let uv_meta = uv.metadata().map_err(|_| fail())?;
    if !uv_meta.is_file() || uv_meta.uid() != euid() || uv_meta.mode() & 0o022 != 0 {
        return Err(fail());
    }
    if uv_meta.len() > MAX_UNPACKED_BYTES {
        return Err(fail());
    }
    let mut bytes = Vec::new();
    uv.take(MAX_UNPACKED_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail())?;
    if text != sums_text(source.target, &source.sha256, &sha256_hex(&bytes)) {
        return Err(fail());
    }
    Ok(Managed::Verified(dir_path.join("uv")))
}

/// The `--fetch-uv` download's user agent: `airs/<version>` (DESIGN §21.4 family 14, choice 11).
fn user_agent() -> String {
    format!("{}/{}", crate::store::PROGRAM, crate::VERSION)
}

/// Why a download failed (§17.14 "Download"): only the class is named.
fn download_failed(class: &str) -> CliError {
    CliError::operational(format!("Cannot download uv {UV_VERSION}: {class}"))
}

fn is_loopback_http(url: &reqwest::Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
}

/// Download the archive (one attempt, https only on every hop, at most 5 redirects, no
/// gzip decoding, no credential or cookie, a 64 MiB cap, 120 s in all). The proxy policy
/// is reqwest's (as the API's https transport); the loopback test hook uses no proxy.
pub async fn download(source: &Source) -> Result<Vec<u8>, CliError> {
    let loopback = source.loopback;
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        let allowed =
            attempt.url().scheme() == "https" || (loopback && is_loopback_http(attempt.url()));
        if attempt.previous().len() > 5 || !allowed {
            attempt.error("redirect refused")
        } else {
            attempt.follow()
        }
    });
    let mut builder = reqwest::Client::builder()
        .redirect(policy)
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .gzip(false)
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .referer(false)
        .user_agent(user_agent());
    if loopback {
        builder = builder.no_proxy();
    } else {
        builder = builder.https_only(true);
    }
    let client = builder
        .build()
        .map_err(|_| download_failed("network error"))?;
    let classify = |error: &reqwest::Error| {
        if error.is_timeout() {
            download_failed("timed out")
        } else if error.is_redirect() {
            download_failed("redirect refused")
        } else {
            download_failed("network error")
        }
    };
    let mut response = client
        .get(&source.url)
        .send()
        .await
        .map_err(|error| classify(&error))?;
    if !response.status().is_success() {
        return Err(download_failed(&format!(
            "HTTP {}",
            response.status().as_u16()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ARCHIVE_BYTES as u64)
    {
        return Err(download_failed("response too large"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| classify(&error))? {
        if body.len() + chunk.len() > MAX_ARCHIVE_BYTES {
            return Err(download_failed("response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub const HASH_MISMATCH: &str =
    "The downloaded uv archive does not match its pinned SHA-256; nothing was installed.";
pub const TOO_LARGE: &str = "The uv archive is larger than expected; nothing was installed.";
pub const MALFORMED: &str =
    "The uv archive is malformed or has an unexpected layout; nothing was installed.";

fn missing_uv(target: &str) -> CliError {
    CliError::operational(format!(
        "The uv archive does not contain uv-{target}/uv; nothing was installed."
    ))
}

/// The archive must hash to the pinned value before anything else touches it.
pub fn verify_archive(bytes: &[u8], sha256: &str) -> Result<(), CliError> {
    if sha256_hex(bytes) == sha256 {
        Ok(())
    } else {
        Err(CliError::operational(HASH_MISMATCH))
    }
}

/// gunzip (capped at 256 MiB).
pub fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, CliError> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(MAX_UNPACKED_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|_| CliError::operational(MALFORMED))?;
    if out.len() as u64 > MAX_UNPACKED_BYTES {
        return Err(CliError::operational(TOO_LARGE));
    }
    Ok(out)
}

/// One tar entry as the strict reader sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: u8,
    pub data: Vec<u8>,
}

fn octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return None; // base-256 is refused
    }
    let text: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ')
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .collect();
    if text.is_empty() {
        return Some(0);
    }
    let mut value: u64 = 0;
    for byte in text {
        if !(b'0'..=b'7').contains(&byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

fn c_string(field: &[u8]) -> Option<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    String::from_utf8(field[..end].to_vec()).ok()
}

/// The `path` record of a pax extended header.
fn pax_path(data: &[u8]) -> Option<Option<String>> {
    let mut rest = data;
    let mut path = None;
    while !rest.is_empty() {
        let space = rest.iter().position(|byte| *byte == b' ')?;
        let length: usize = std::str::from_utf8(&rest[..space]).ok()?.parse().ok()?;
        if length <= space + 1 || length > rest.len() {
            return None;
        }
        let record = &rest[space + 1..length];
        let record = record.strip_suffix(b"\n")?;
        let equals = record.iter().position(|byte| *byte == b'=')?;
        if &record[..equals] == b"path" {
            path = Some(String::from_utf8(record[equals + 1..].to_vec()).ok()?);
        }
        rest = &rest[length..];
    }
    Some(path)
}

/// Read every entry of a tar stream strictly (§17.14 "Extract"): checksummed 512-byte
/// headers, octal sizes (base-256 refused), ustar `prefix` + `name`, a pax `x` `path` or
/// a GNU `L` long name applying to the next entry, pax `g` skipped, a leading `./`
/// stripped. `None`: malformed (a bad header, a truncated entry).
pub fn read_tar(bytes: &[u8]) -> Option<Vec<Entry>> {
    const BLOCK: usize = 512;
    let mut entries = Vec::new();
    let mut offset = 0;
    let mut next_name: Option<String> = None;
    loop {
        if offset == bytes.len() {
            // The end of the data after a complete entry.
            return (next_name.is_none()).then_some(entries);
        }
        let header = bytes.get(offset..offset + BLOCK)?;
        if header.iter().all(|byte| *byte == 0) {
            // Two zero blocks, or one at the very end.
            let second = bytes.get(offset + BLOCK..offset + 2 * BLOCK);
            return match second {
                Some(block) if block.iter().all(|byte| *byte == 0) => Some(entries),
                None if offset + BLOCK == bytes.len() => Some(entries),
                _ => None,
            };
        }
        let recorded = octal(&header[148..156])?;
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    u64::from(b' ')
                } else {
                    u64::from(*byte)
                }
            })
            .sum();
        if sum != recorded {
            return None;
        }
        let size = usize::try_from(octal(&header[124..136])?).ok()?;
        let kind = header[156];
        let data_start = offset + BLOCK;
        let data_end = data_start.checked_add(size)?;
        let data = bytes.get(data_start..data_end)?;
        let padded = size.div_ceil(BLOCK).checked_mul(BLOCK)?;
        offset = data_start.checked_add(padded)?;
        if offset > bytes.len() {
            return None;
        }
        match kind {
            b'x' => {
                if let Some(path) = pax_path(data)? {
                    next_name = Some(path);
                }
                continue;
            }
            b'g' => continue,
            b'L' => {
                next_name = Some(c_string(data)?);
                continue;
            }
            b'K' => continue,
            _ => {}
        }
        let name = match next_name.take() {
            Some(name) => name,
            None => {
                let name = c_string(&header[0..100])?;
                // Only POSIX ustar has a `prefix` field (GNU uses those bytes otherwise).
                let prefix = if &header[257..263] == b"ustar\0" {
                    c_string(&header[345..500])?
                } else {
                    String::new()
                };
                if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                }
            }
        };
        let name = name.strip_prefix("./").map(str::to_owned).unwrap_or(name);
        entries.push(Entry {
            name,
            kind,
            data: data.to_vec(),
        });
    }
}

/// The bytes of the one regular entry `uv-<target>/uv` of the gunzipped archive; every
/// other entry is skipped without touching the filesystem.
pub fn extract_uv(tar: &[u8], target: &str) -> Result<Vec<u8>, CliError> {
    let entries = read_tar(tar).ok_or_else(|| CliError::operational(MALFORMED))?;
    let wanted = format!("uv-{target}/uv");
    let mut found: Option<Vec<u8>> = None;
    for entry in entries {
        if entry.name != wanted {
            continue;
        }
        if !matches!(entry.kind, b'0' | 0) || found.is_some() {
            return Err(CliError::operational(MALFORMED));
        }
        found = Some(entry.data);
    }
    found.ok_or_else(|| missing_uv(target))
}

/// What an interruption during the install reports.
pub fn not_installed() -> InterruptContext {
    InterruptContext::Context("uv was not installed".to_owned())
}

/// The temporaries a killed run left (`.uv-*.tmp`, older than 1 hour) are removed.
fn remove_stale_temps(tools: &StateDir) {
    let Ok(dir) = rustix::fs::Dir::read_from(tools.fd()) else {
        return;
    };
    let names: Vec<String> = dir
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().ok().map(str::to_owned))
        .filter(|name| name.starts_with(".uv-") && name.ends_with(".tmp"))
        .collect();
    for name in names {
        let Ok(temp) = open_at(tools.fd(), &name, OFlags::RDONLY | OFlags::DIRECTORY) else {
            continue;
        };
        let old = temp
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > Duration::from_secs(3600));
        if old {
            remove_temp(tools, &name);
        }
    }
}

/// Remove a temporary directory of ours and its two files (best effort).
fn remove_temp(tools: &StateDir, name: &str) {
    if let Ok(dir) = open_at(tools.fd(), name, OFlags::RDONLY | OFlags::DIRECTORY) {
        for file in ["uv", "SHA256SUMS"] {
            let _ = rustix::fs::unlinkat(&dir, file, AtFlags::empty());
        }
    }
    let _ = rustix::fs::unlinkat(tools.fd(), name, AtFlags::REMOVEDIR);
}

fn create_file(dir: &File, name: &str, mode: Mode, bytes: &[u8]) -> std::io::Result<()> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    rustix::fs::fchmod(&fd, mode)?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

/// Whether a signal arrived (the install stops before its rename).
pub type Interrupted<'a> = &'a dyn Fn() -> bool;

/// Install the managed copy (§17.14 "Install"): a new `0700` temporary directory under
/// `T`, `uv` (0755) and `SHA256SUMS` (0600) created exclusively in it, synced, renamed to
/// `uv-0.12.17-<target>` without replacing anything, `T` synced. Returns the `uv` path.
pub fn install(
    tools: &StateDir,
    source: &Source,
    uv: &[u8],
    interrupted: Interrupted<'_>,
) -> Result<PathBuf, CliError> {
    remove_stale_temps(tools);
    let final_name = managed_name(source.target);
    let temp = format!(
        ".{final_name}.{}.tmp",
        &uuid::Uuid::new_v4().simple().to_string()[..16]
    );
    let cannot = || {
        CliError::operational(format!(
            "Cannot install uv {UV_VERSION} in {}; check the permissions of that directory",
            shown(tools.path())
        ))
    };
    rustix::fs::mkdirat(tools.fd(), temp.as_str(), Mode::from_raw_mode(0o700))
        .map_err(|_| cannot())?;
    let written = (|| -> std::io::Result<()> {
        let dir = open_at(tools.fd(), &temp, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let mode = dir.metadata()?.permissions().mode();
        if mode & 0o077 != 0 {
            rustix::fs::fchmod(&dir, Mode::from_raw_mode(0o700))?;
        }
        create_file(&dir, "uv", Mode::from_raw_mode(0o755), uv)?;
        let sums = sums_text(source.target, &source.sha256, &sha256_hex(uv));
        create_file(
            &dir,
            "SHA256SUMS",
            Mode::from_raw_mode(0o600),
            sums.as_bytes(),
        )?;
        dir.sync_all()
    })();
    if written.is_err() {
        remove_temp(tools, &temp);
        return Err(cannot());
    }
    if interrupted() {
        remove_temp(tools, &temp);
        return Err(CliError::Interrupted(not_installed()));
    }
    let renamed = rustix::fs::renameat_with(
        tools.fd(),
        temp.as_str(),
        tools.fd(),
        final_name.as_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    );
    let renamed = match renamed {
        Err(errno)
            if errno == rustix::io::Errno::INVAL
                || errno == rustix::io::Errno::NOSYS
                || errno == rustix::io::Errno::OPNOTSUPP =>
        {
            rustix::fs::renameat(tools.fd(), temp.as_str(), tools.fd(), final_name.as_str())
        }
        other => other,
    };
    match renamed {
        Ok(()) => {}
        Err(errno) if errno == rustix::io::Errno::EXIST || errno == rustix::io::Errno::NOTEMPTY => {
            // Another run installed it meanwhile: never replaced, verified instead.
            remove_temp(tools, &temp);
            return match verify_managed(tools, source)? {
                Managed::Verified(path) => Ok(path),
                Managed::Absent => Err(cannot()),
            };
        }
        Err(_) => {
            remove_temp(tools, &temp);
            return Err(cannot());
        }
    }
    let _ = tools.fd().sync_all();
    Ok(tools.path().join(final_name).join("uv"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar header for `name` with `kind` and `size`.
    fn header(name: &str, kind: u8, size: usize) -> Vec<u8> {
        let mut block = vec![0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..108].copy_from_slice(b"0000755\0");
        block[108..116].copy_from_slice(b"0000000\0");
        block[116..124].copy_from_slice(b"0000000\0");
        block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        block[136..148].copy_from_slice(b"00000000000\0");
        block[156] = kind;
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        block[148..156].copy_from_slice(b"        ");
        let sum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        block
    }

    fn entry(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
        let mut out = header(name, kind, data.len());
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = entries.concat();
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    const T: &str = "aarch64-apple-darwin";

    #[test]
    fn the_pins_and_the_hook_build() {
        assert_eq!(RELEASES.len(), 4);
        for release in RELEASES {
            assert_eq!(release.sha256.len(), 64);
            assert!(release.sha256.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        assert_eq!(
            release_url("x86_64-unknown-linux-musl"),
            "https://github.com/astral-sh/uv/releases/download/0.12.17/uv-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(managed_name(T), "uv-0.12.17-aarch64-apple-darwin");
        #[cfg(debug_assertions)]
        const {
            assert!(HOOK_COMPILED, "tests run a debug build")
        };
        assert!(
            host_release().is_some(),
            "the test hosts are pinned targets"
        );
        assert_eq!(
            sums_text(T, "a", "b"),
            "a  uv-aarch64-apple-darwin.tar.gz\nb  uv\n"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn the_hook_takes_only_loopback_http_with_a_hash() {
        let sha = "a".repeat(64);
        assert_eq!(hook::values(None, None).unwrap(), None);
        assert!(
            hook::values(Some("http://127.0.0.1:9/uv.tar.gz"), Some(&sha))
                .unwrap()
                .is_some()
        );
        assert!(
            hook::values(Some("http://[::1]:9/uv.tar.gz"), Some(&sha))
                .unwrap()
                .is_some()
        );
        for (url, hash) in [
            (Some("http://127.0.0.1:9/x"), None),
            (None, Some(sha.as_str())),
            (Some("https://127.0.0.1:9/x"), Some(sha.as_str())),
            (Some("http://example.com:9/x"), Some(sha.as_str())),
            (Some("http://localhost:9/x"), Some(sha.as_str())),
            (Some("http://127.0.0.1/x"), Some(sha.as_str())),
            (Some("http://u:p@127.0.0.1:9/x"), Some(sha.as_str())),
            (Some("http://127.0.0.1:9/x"), Some("ABC")),
            (Some("http://127.0.0.1:9/x"), Some(&"A".repeat(64))),
        ] {
            assert!(
                matches!(hook::values(url, hash), Err(CliError::Usage(message)) if message == hook::REFUSED),
                "{url:?} {hash:?}"
            );
        }
    }

    #[test]
    fn the_tools_directory_follows_the_data_home() {
        assert_eq!(
            tools_dir_path(Some(std::ffi::OsStr::new("/d")), Some(Path::new("/h"))).unwrap(),
            PathBuf::from("/d/airs-cli/tools")
        );
        assert_eq!(
            tools_dir_path(Some(std::ffi::OsStr::new("")), Some(Path::new("/h"))).unwrap(),
            PathBuf::from("/h/.local/share/airs-cli/tools")
        );
        assert!(matches!(
            tools_dir_path(Some(std::ffi::OsStr::new("rel")), None),
            Err(CliError::Operational(f)) if f.message == "XDG_DATA_HOME must be an absolute path"
        ));
        assert!(matches!(
            tools_dir_path(None, Some(Path::new("rel"))),
            Err(CliError::Operational(f)) if f.message.starts_with("Cannot install uv: HOME")
        ));
    }

    #[test]
    fn the_tar_reader_takes_exactly_one_regular_uv() {
        let wanted = format!("uv-{T}/uv");
        let good = archive(&[
            entry(&format!("uv-{T}/"), b'5', b""),
            entry(&format!("./uv-{T}/uv"), b'0', b"#!/bin/sh\n"),
            entry(&format!("uv-{T}/uvx"), b'0', b"x"),
            entry("../../evil", b'0', b"x"),
            entry("/abs/evil", b'0', b"x"),
            entry(&format!("uv-{T}/link"), b'2', b""),
        ]);
        assert_eq!(extract_uv(&good, T).unwrap(), b"#!/bin/sh\n");
        // A symlink, a hard link or a second copy named uv: malformed.
        for kind in *b"1235" {
            let bad = archive(&[entry(&wanted, kind, b"")]);
            assert!(
                matches!(extract_uv(&bad, T), Err(CliError::Operational(f)) if f.message == MALFORMED)
            );
        }
        let twice = archive(&[entry(&wanted, b'0', b"a"), entry(&wanted, 0, b"b")]);
        assert!(
            matches!(extract_uv(&twice, T), Err(CliError::Operational(f)) if f.message == MALFORMED)
        );
        // No uv: named.
        let none = archive(&[entry(&format!("uv-{T}/uvx"), b'0', b"x")]);
        assert!(matches!(
            extract_uv(&none, T),
            Err(CliError::Operational(f)) if f.message == format!("The uv archive does not contain uv-{T}/uv; nothing was installed.")
        ));
        // A bad checksum, a truncated entry, base-256 sizes.
        let mut checksum = good.clone();
        checksum[0] ^= 1;
        assert!(read_tar(&checksum).is_none());
        let truncated = entry(&wanted, b'0', b"0123456789")[..515].to_vec();
        assert!(read_tar(&truncated).is_none());
        let mut base256 = header(&wanted, b'0', 0);
        base256[124] = 0x80;
        assert!(read_tar(&archive(&[base256])).is_none());
        // The end of the data right after a complete entry is a valid end.
        assert_eq!(read_tar(&entry(&wanted, b'0', b"z")).unwrap().len(), 1);
    }

    #[test]
    fn pax_and_gnu_names_apply_to_the_next_entry() {
        let wanted = format!("uv-{T}/uv");
        let record = format!(" path={wanted}\n");
        let length = record.len() + 2;
        let pax = format!("{length}{record}");
        assert_eq!(pax.len(), length);
        let archive_pax = archive(&[
            entry("PaxHeaders/x", b'x', pax.as_bytes()),
            entry("short-name", b'0', b"pax"),
        ]);
        assert_eq!(extract_uv(&archive_pax, T).unwrap(), b"pax");
        let mut long = wanted.clone().into_bytes();
        long.push(0);
        let archive_gnu = archive(&[
            entry("././@LongLink", b'L', &long),
            entry("short-name", b'0', b"gnu"),
        ]);
        assert_eq!(extract_uv(&archive_gnu, T).unwrap(), b"gnu");
        // A pax override that renames the real uv entry away leaves no uv.
        let away = " path=elsewhere\n";
        let away = format!("{}{away}", away.len() + 2);
        let renamed = archive(&[
            entry("PaxHeaders/x", b'x', away.as_bytes()),
            entry(&wanted, b'0', b"x"),
        ]);
        assert!(extract_uv(&renamed, T).is_err());
    }

    #[test]
    fn archives_are_verified_and_bounded() {
        assert!(verify_archive(b"abc", &sha256_hex(b"abc")).is_ok());
        assert!(
            matches!(verify_archive(b"abd", &sha256_hex(b"abc")), Err(CliError::Operational(f)) if f.message == HASH_MISMATCH)
        );
        assert!(
            matches!(gunzip(b"not gzip"), Err(CliError::Operational(f)) if f.message == MALFORMED)
        );
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"hello").unwrap();
        assert_eq!(gunzip(&encoder.finish().unwrap()).unwrap(), b"hello");
    }
}
