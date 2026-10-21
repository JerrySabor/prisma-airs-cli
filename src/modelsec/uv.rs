//! `model-security install` with uv (DESIGN §17.13, D195–D201): uv discovery on `PATH`
//! and the version check, the `--dir` and uv-workspace preflight, the two steps and their
//! environments, the POSIX dry-run plan, the children (own process group, stdin
//! `/dev/null`, output scrubbed of the credential and written to stderr, signals
//! forwarded once) and the persistence check of the written project files.

use crate::error::{CliError, SecretSet, WITHHELD, base64_standard};
use crate::files::shown;
use crate::modelsec::pypi::Index;
use crate::output::{Output, terminal_safe};
use crate::signals::SignalState;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The extras TypeScript accepts (`VALID_EXTRAS`), case-sensitive.
pub const VALID_EXTRAS: [&str; 6] = ["all", "aws", "gcp", "azure", "artifactory", "gitlab"];

/// The `--extras` and `--dir` defaults (TS).
pub const DEFAULT_EXTRAS: &str = "all";
pub const DEFAULT_DIR: &str = "model-security";

/// The named index the CLI passes to `uv add` (choice 25).
pub const INDEX_NAME: &str = "airs-model-security";
/// The environment variables uv reads the named index's credential from.
pub const USERNAME_VAR: &str = "UV_INDEX_AIRS_MODEL_SECURITY_USERNAME";
pub const PASSWORD_VAR: &str = "UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD";

/// The detail line after a failed `uv add` (D203): it runs with `--no-build`.
pub const NO_BUILD_HINT: &str = "uv add runs with --no-build so that no package build code sees the index credential; if uv reports a dependency that needs building, build it yourself without the credential in the environment, then add model-security-client with uv.";

/// The oldest uv accepted from `PATH` (choice 27).
pub const MINIMUM_VERSION: (u64, u64, u64) = (0, 12, 0);

/// The `--extras` check (TS text), during planning.
pub fn check_extras(extras: &str) -> Result<(), CliError> {
    if VALID_EXTRAS.contains(&extras) {
        Ok(())
    } else {
        Err(CliError::usage(format!(
            "Invalid extras \"{}\". Valid: {}",
            terminal_safe(extras),
            VALID_EXTRAS.join(", ")
        )))
    }
}

/// The package spec `model-security-client[<extras>]`.
pub fn package(extras: &str) -> String {
    format!("model-security-client[{extras}]")
}

/// The first `uv` on `PATH` (§17.13 step 4): entries split on `:`, empty and relative
/// entries skipped, `<entry>/uv` a regular file once symlinks are followed and executable
/// by the effective user.
pub fn find_on_path(path: Option<&OsStr>) -> Option<PathBuf> {
    let path = path?;
    for entry in std::env::split_paths(path) {
        if entry.as_os_str().is_empty() || !entry.is_absolute() {
            continue;
        }
        let candidate = entry.join("uv");
        let regular = std::fs::metadata(&candidate).is_ok_and(|metadata| metadata.is_file());
        if regular
            && rustix::fs::accessat(
                rustix::fs::CWD,
                &candidate,
                rustix::fs::Access::EXEC_OK,
                rustix::fs::AtFlags::EACCESS,
            )
            .is_ok()
        {
            return Some(candidate);
        }
    }
    None
}

/// `uv was not found on PATH. …` (D195).
pub fn not_found(tools: &Path) -> CliError {
    CliError::operational(format!(
        "uv was not found on PATH. Install uv (https://docs.astral.sh/uv/) or re-run with --fetch-uv to download uv {} into {}.",
        super::fetch::UV_VERSION,
        shown(tools.as_os_str())
    ))
}

fn not_usable(uv: &Path) -> CliError {
    CliError::operational(format!(
        "{} is not a usable uv (model-security install needs uv 0.12.0 or later; re-run with --fetch-uv to use uv {})",
        shown(uv.as_os_str()),
        super::fetch::UV_VERSION
    ))
}

/// The version of a `uv --version` first line (`uv 0.12.17 (Homebrew …)`).
pub fn parse_version(output: &str) -> Option<(u64, u64, u64)> {
    let line = output.lines().next()?;
    let rest = line.strip_prefix("uv ")?;
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    let mut parts = rest[..end].split('.');
    let number = |part: Option<&str>| -> Option<u64> {
        let part = part?;
        if part.is_empty() || part.len() > 9 {
            return None;
        }
        part.parse().ok()
    };
    let version = (
        number(parts.next())?,
        number(parts.next())?,
        number(parts.next())?,
    );
    parts.next().is_none().then_some(version)
}

/// What an interruption before the children reports.
pub fn nothing_installed() -> crate::error::InterruptContext {
    crate::error::InterruptContext::Context("nothing was installed".to_owned())
}

/// `<uv> --version` (stdin `/dev/null`, at most 64 KiB captured, 10 s): the version, at
/// least 0.12.0 (`exact`: exactly that one). A signal stops it (`interrupted`).
pub fn check_version(
    uv: &Path,
    exact: Option<(u64, u64, u64)>,
    output: &Output,
    interrupted: &crate::error::InterruptContext,
) -> Result<String, CliError> {
    let mut child = Command::new(uv)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| not_usable(uv))?;
    let stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(stdout) = stdout {
            let _ = stdout.take(64 * 1024).read_to_end(&mut bytes);
        }
        bytes
    });
    let started = Instant::now();
    let status = loop {
        if output.pending_signal().is_some() {
            kill_group(&child, rustix::process::Signal::KILL);
            let _ = child.wait();
            return Err(CliError::Interrupted(interrupted.clone()));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                kill_group(&child, rustix::process::Signal::KILL);
                let _ = child.wait();
                return Err(not_usable(uv));
            }
        }
    };
    let bytes = reader.join().unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes);
    let version = parse_version(&text).ok_or_else(|| not_usable(uv))?;
    let ok = status.success()
        && match exact {
            Some(exact) => version == exact,
            None => version >= MINIMUM_VERSION,
        };
    if !ok {
        return Err(not_usable(uv));
    }
    Ok(format!("{}.{}.{}", version.0, version.1, version.2))
}

fn kill_group(child: &Child, signal: rustix::process::Signal) {
    let _ = rustix::process::kill_process_group(rustix::process::Pid::from_child(child), signal);
}

/// The `--dir` preflight (D198, §17.13 step 3): the absolute target (lexically joined to
/// the working directory, components kept as typed), which must not exist, whose parent
/// must be a directory outside any uv workspace.
pub fn preflight_dir(dir: &OsStr, cwd: Option<&Path>) -> Result<PathBuf, CliError> {
    let typed = shown(dir);
    let no_parent = || {
        CliError::operational(format!(
            "Cannot create {typed}; its parent directory does not exist"
        ))
    };
    let path = Path::new(dir);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.ok_or_else(no_parent)?.join(path)
    };
    match std::fs::symlink_metadata(&absolute) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        // A path through a non-directory: its parent is the problem.
        Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => return Err(no_parent()),
        _ => {
            return Err(CliError::operational(format!(
                "{typed} already exists; choose another --dir"
            )));
        }
    }
    let parent = absolute.parent().ok_or_else(no_parent)?;
    if !std::fs::metadata(parent).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(no_parent());
    }
    let canonical = std::fs::canonicalize(parent).map_err(|_| no_parent())?;
    workspace_check(&typed, &workspace_candidates(parent, &canonical))?;
    Ok(absolute)
}

/// `path` with `.` dropped and `..` taken lexically (never above the root).
fn lexically_normal(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push(component);
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Every directory whose `pyproject.toml` the workspace check reads (§17.13 step 3): the
/// ancestors of the parent as typed (made absolute), of its lexically normalised form and
/// of its canonical form, each once. uv discovers a workspace along the path it was given,
/// so a parent reached through a symlink is checked on the side the link leads from as
/// well as the side it leads to.
fn workspace_candidates(parent: &Path, canonical: &Path) -> Vec<PathBuf> {
    let normal = lexically_normal(parent);
    let mut candidates: Vec<PathBuf> = Vec::new();
    for chain in [parent, normal.as_path(), canonical] {
        for ancestor in chain.ancestors() {
            if !ancestor.as_os_str().is_empty() && !candidates.iter().any(|seen| seen == ancestor) {
                candidates.push(ancestor.to_path_buf());
            }
        }
    }
    candidates
}

/// Refuse a parent inside a uv workspace (§17.13 step 3): one of the candidate
/// directories holds a `pyproject.toml` with a `[tool.uv.workspace]` table.
fn workspace_check(typed: &str, candidates: &[PathBuf]) -> Result<(), CliError> {
    for ancestor in candidates {
        let file = ancestor.join("pyproject.toml");
        match std::fs::symlink_metadata(&file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            _ => {}
        }
        let cannot = || {
            CliError::operational(format!(
                "Cannot check {} for a uv workspace; choose a --dir outside it",
                shown(file.as_os_str())
            ))
        };
        let text = crate::files::read_text(file.as_os_str(), crate::files::CONFIG_LIMIT)
            .map_err(|_| cannot())?;
        let table: toml::Table = toml::from_str(&text).map_err(|_| cannot())?;
        let workspace = table
            .get("tool")
            .and_then(|tool| tool.get("uv"))
            .and_then(|uv| uv.get("workspace"))
            .is_some_and(toml::Value::is_table);
        if workspace {
            return Err(CliError::operational(format!(
                "{typed} is inside the uv workspace at {}; choose a --dir outside it",
                shown(ancestor.as_os_str())
            )));
        }
    }
    Ok(())
}

/// One uv step of the install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// `uv init` / `uv add` (the TS labels).
    pub label: &'static str,
    /// The arguments after the uv path.
    pub args: Vec<OsString>,
    /// Whether the step gets the credential in its environment (`uv add` only).
    pub credential: bool,
}

/// The two steps (§17.13 steps 9 and 10).
pub fn steps(dir: &Path, index: &str, extras: &str, quiet: bool) -> [Step; 2] {
    let quiet_flag: Vec<OsString> = if quiet {
        vec![OsString::from("--quiet")]
    } else {
        Vec::new()
    };
    let mut init = quiet_flag.clone();
    init.extend(
        ["init", "--no-workspace", "--"]
            .into_iter()
            .map(OsString::from),
    );
    init.push(dir.as_os_str().to_owned());
    let mut add = quiet_flag;
    // `--no-build` (D203): no PEP 517 build backend, which inherits uv's environment and
    // so the index credential, runs while the credential is set.
    add.extend(
        ["add", "--no-build", "--project"]
            .into_iter()
            .map(OsString::from),
    );
    add.push(dir.as_os_str().to_owned());
    add.push(OsString::from("--index"));
    add.push(OsString::from(format!("{INDEX_NAME}={index}")));
    add.push(OsString::from("--"));
    add.push(OsString::from(package(extras)));
    [
        Step {
            label: "uv init",
            args: init,
            credential: false,
        },
        Step {
            label: "uv add",
            args: add,
            credential: true,
        },
    ]
}

/// One POSIX shell word: as it is when it matches `[A-Za-z0-9_@%+=:,./-]+`, else
/// single-quoted with `'` written `'\''`.
pub fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// A dry-run line of `step` (D197): the credential environment as `[withheld]` words
/// (left unquoted on purpose), the uv path and the arguments as POSIX words.
pub fn plan_line(uv: &Path, step: &Step) -> String {
    let mut words: Vec<String> = Vec::new();
    if step.credential {
        words.push(format!("{USERNAME_VAR}={WITHHELD}"));
        words.push(format!("{PASSWORD_VAR}={WITHHELD}"));
    }
    words.push(shell_word(&uv.to_string_lossy()));
    for arg in &step.args {
        words.push(shell_word(&arg.to_string_lossy()));
    }
    terminal_safe(&format!("  $ {}", words.join(" "))).into_owned()
}

/// How a child ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    Exited(i32),
    Signalled(i32),
    /// The CLI received a signal and forwarded it; the child was reaped.
    Interrupted,
}

/// The longest forwarded line (a longer one is split).
const MAX_LINE: usize = 64 * 1024;

/// The most a split keeps back for the next piece (a registered form longer than this
/// is not guarded across a split; the credential is at most 8 KiB, D201).
const MAX_CARRY: usize = MAX_LINE / 2;

/// Where to split an over-long `line` so that no registered form of `secrets` straddles
/// the split: at most `line.len()`, at least `line.len() - MAX_CARRY` unless a form
/// crossing that point starts earlier; never inside a UTF-8 sequence. The bytes after it
/// stay for the next piece, so a form that the next bytes may complete is never cut.
fn split_point(line: &[u8], secrets: &SecretSet) -> usize {
    let forms = secrets.snapshot();
    let longest = forms.iter().map(String::len).max().unwrap_or(0);
    let keep = longest.saturating_sub(1).min(MAX_CARRY);
    let mut cut = line.len().saturating_sub(keep);
    loop {
        while cut > 0 && cut < line.len() && line[cut] & 0xC0 == 0x80 {
            cut -= 1;
        }
        // A form occurrence that starts before `cut` and ends after it.
        let low = cut.saturating_sub(longest);
        let high = (cut + longest).min(line.len());
        let window = &line[low..high];
        let crossing = forms
            .iter()
            .filter(|form| !form.is_empty() && form.len() <= window.len())
            .flat_map(|form| {
                let form = form.as_bytes();
                window
                    .windows(form.len())
                    .enumerate()
                    .filter(move |(_, candidate)| *candidate == form)
                    .map(move |(at, _)| (low + at, low + at + form.len()))
            })
            .filter(|(start, end)| *start < cut && *end > cut)
            .map(|(start, _)| start)
            .min();
        match crossing {
            Some(start) => cut = start,
            None => break,
        }
    }
    if cut == 0 { line.len() } else { cut }
}

/// Forward the lines of `pipe` to `sink`; a line longer than [`MAX_LINE`] is sent in
/// pieces split where no registered secret form straddles them ([`split_point`]), so the
/// per-piece scrub withholds every whole form.
fn forward(pipe: impl Read, sink: std::sync::mpsc::Sender<Vec<u8>>, secrets: &SecretSet) {
    let mut reader = BufReader::with_capacity(MAX_LINE, pipe);
    let mut line: Vec<u8> = Vec::new();
    loop {
        let buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if buffer.is_empty() {
            break;
        }
        let room = MAX_LINE - line.len();
        let window = &buffer[..buffer.len().min(room)];
        match window.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                line.extend_from_slice(&window[..index]);
                reader.consume(index + 1);
                if sink.send(std::mem::take(&mut line)).is_err() {
                    return;
                }
            }
            None => {
                let taken = window.len();
                line.extend_from_slice(window);
                reader.consume(taken);
                if line.len() >= MAX_LINE {
                    let cut = split_point(&line, secrets);
                    let rest = line.split_off(cut);
                    if sink.send(std::mem::replace(&mut line, rest)).is_err() {
                        return;
                    }
                }
            }
        }
    }
    if !line.is_empty() {
        let _ = sink.send(line);
    }
}

/// A line of uv output as the CLI prints it: every registered secret form replaced by
/// `[withheld]`, terminal-safe.
pub fn scrubbed(line: &[u8], secrets: &SecretSet) -> String {
    let text = String::from_utf8_lossy(line);
    let text = text.strip_suffix('\r').unwrap_or(&text);
    terminal_safe(&secrets.redact(text)).into_owned()
}

/// Run one uv step: spawned by absolute path in its own process group, stdin
/// `/dev/null`, stdout and stderr piped, each line scrubbed and written to the CLI's
/// stderr. A signal the CLI receives is forwarded once to the child's group (a second one
/// kills it) and the child is waited for.
pub fn run_step(
    output: &mut Output,
    uv: &Path,
    step: &Step,
    index: &Index,
    secrets: &SecretSet,
) -> Result<Ended, CliError> {
    let mut command = Command::new(uv);
    command
        .args(&step.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if step.credential {
        command
            .env(USERNAME_VAR, &index.username)
            .env(PASSWORD_VAR, &index.password);
    } else {
        command.env_remove(USERNAME_VAR).env_remove(PASSWORD_VAR);
    }
    let signals: Option<Arc<SignalState>> = output.signals();
    if output.pending_signal().is_some() {
        return Ok(Ended::Interrupted);
    }
    let mut child = command
        .spawn()
        .map_err(|_| CliError::operational(format!("Cannot start {}", shown(uv.as_os_str()))))?;
    let pgid = i32::try_from(child.id()).unwrap_or(0);
    if let Some(signals) = &signals {
        signals.attach_child(pgid);
    }
    let (sender, lines) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut threads = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let (sender, secrets) = (sender.clone(), secrets.clone());
        threads.push(std::thread::spawn(move || {
            forward(stdout, sender, &secrets);
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let (sender, secrets) = (sender.clone(), secrets.clone());
        threads.push(std::thread::spawn(move || {
            forward(stderr, sender, &secrets);
        }));
    }
    drop(sender);
    let mut status = None;
    let mut exited_at: Option<Instant> = None;
    loop {
        match lines.recv_timeout(Duration::from_millis(20)) {
            Ok(line) => {
                output.write_stderr(&format!("{}\n", scrubbed(&line, secrets)));
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) if status.is_some() => break,
            Err(_) => {}
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(done)) => {
                    status = Some(done);
                    exited_at = Some(Instant::now());
                }
                Ok(None) => {}
                Err(_) => {
                    let _ = child.kill();
                    status = child.wait().ok();
                    exited_at = Some(Instant::now());
                }
            }
        }
        // A grandchild that keeps the pipes open is not waited for.
        if exited_at.is_some_and(|at| at.elapsed() > Duration::from_secs(2)) {
            break;
        }
    }
    if let Some(signals) = &signals {
        signals.detach_child();
    }
    drop(lines);
    for thread in threads {
        if thread.is_finished() {
            let _ = thread.join();
        }
    }
    if output.pending_signal().is_some() {
        return Ok(Ended::Interrupted);
    }
    Ok(match status {
        Some(status) => match (status.code(), status.signal()) {
            (Some(code), _) => Ended::Exited(code),
            (None, Some(signal)) => Ended::Signalled(signal),
            (None, None) => Ended::Exited(1),
        },
        None => Ended::Exited(1),
    })
}

/// The bound on a project file read back for the persistence check.
const MAX_PROJECT_FILE: u64 = 16 * 1024 * 1024;

/// The persistence check (D196, §17.13 step 11): `pyproject.toml` (a missing one
/// skipped) and `uv.lock` (which must exist: a `uv add` that locked elsewhere, such as a
/// uv workspace above `dir`, wrote a lock this check cannot see) must not hold the
/// password (raw or decoded), the raw userinfo or the base64 of `username:password`.
pub fn persistence_check(dir: &Path, index: &Index) -> Result<(), CliError> {
    let forms = [
        index.password.clone(),
        index.raw_password.clone(),
        index.raw_userinfo.clone(),
        base64_standard(format!("{}:{}", index.username, index.password).as_bytes()),
    ];
    for name in ["pyproject.toml", "uv.lock"] {
        let file = dir.join(name);
        match std::fs::symlink_metadata(&file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && name == "uv.lock" => {
                return Err(CliError::operational(format!(
                    "uv did not write {}; it may have locked a uv workspace above the project (or UV_FROZEN is set). Check any parent uv.lock for the PyPI index credential before sharing it.",
                    shown(file.as_os_str())
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            _ => {}
        }
        let bytes = crate::files::read_bytes(file.as_os_str(), MAX_PROJECT_FILE).map_err(|_| {
            CliError::operational(format!(
                "Cannot check {} for the PyPI index credential; check it before sharing the project.",
                shown(file.as_os_str())
            ))
        })?;
        let text = String::from_utf8_lossy(&bytes);
        if forms
            .iter()
            .any(|form| !form.is_empty() && text.contains(form.as_str()))
        {
            return Err(CliError::operational(format!(
                "The PyPI index credential was written to {}; remove it from the file before sharing the project.",
                shown(file.as_os_str())
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extras_are_checked_case_sensitively() {
        for extras in VALID_EXTRAS {
            assert!(check_extras(extras).is_ok());
        }
        assert!(matches!(
            check_extras("ALL"),
            Err(CliError::Usage(message)) if message == "Invalid extras \"ALL\". Valid: all, aws, gcp, azure, artifactory, gitlab"
        ));
        assert!(matches!(
            check_extras("a\u{1b}b"),
            Err(CliError::Usage(message)) if message.starts_with("Invalid extras \"a\u{fffd}b\"")
        ));
    }

    #[test]
    fn versions_parse_from_the_first_line() {
        assert_eq!(
            parse_version("uv 0.12.17 (Homebrew 2026-09-18 aarch64-apple-darwin)\n"),
            Some((0, 12, 17))
        );
        assert_eq!(parse_version("uv 1.0.0\n"), Some((1, 0, 0)));
        assert_eq!(parse_version("uv 0.12.17-rc1"), Some((0, 12, 17)));
        for bad in [
            "",
            "uv",
            "uv 0.12",
            "uvx 0.12.17",
            "pip 0.12.17",
            "uv 0.12.17.1",
            "uv a.b.c",
        ] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
        assert!((0, 11, 99) < MINIMUM_VERSION && (0, 12, 0) >= MINIMUM_VERSION);
    }

    #[test]
    fn the_steps_carry_no_credential_in_argv() {
        let [init, add] = steps(
            Path::new("/w/-odd dir"),
            "https://h.example/s/",
            "aws",
            true,
        );
        let words = |step: &Step| -> Vec<String> {
            step.args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(
            words(&init),
            ["--quiet", "init", "--no-workspace", "--", "/w/-odd dir"]
        );
        assert_eq!(
            words(&add),
            [
                "--quiet",
                "add",
                "--no-build",
                "--project",
                "/w/-odd dir",
                "--index",
                "airs-model-security=https://h.example/s/",
                "--",
                "model-security-client[aws]"
            ]
        );
        assert!(!init.credential && add.credential);
    }

    #[test]
    fn the_dry_run_quotes_posix_words() {
        assert_eq!(shell_word("/abs/model-security"), "/abs/model-security");
        assert_eq!(shell_word("/abs/$(id)"), "'/abs/$(id)'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
        assert_eq!(
            shell_word("model-security-client[all]"),
            "'model-security-client[all]'"
        );
        let [init, add] = steps(
            Path::new("/abs/$(id)"),
            "https://h.example/s/",
            "all",
            false,
        );
        let uv = Path::new("/opt/homebrew/bin/uv");
        assert_eq!(
            plan_line(uv, &init),
            "  $ /opt/homebrew/bin/uv init --no-workspace -- '/abs/$(id)'"
        );
        assert_eq!(
            plan_line(uv, &add),
            "  $ UV_INDEX_AIRS_MODEL_SECURITY_USERNAME=[withheld] UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD=[withheld] /opt/homebrew/bin/uv add --no-build --project '/abs/$(id)' --index airs-model-security=https://h.example/s/ -- 'model-security-client[all]'"
        );
    }

    #[test]
    fn uv_output_is_scrubbed() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-PYPI-SECRET-100");
        assert_eq!(
            scrubbed(b"auth FAKE-PYPI-SECRET-100 failed\x1b[31m\r", &secrets),
            "auth [withheld] failed\u{fffd}[31m"
        );
    }

    /// A line longer than 64 KiB is split where no secret form straddles the split, so
    /// the per-piece scrub withholds the whole credential (review finding).
    #[test]
    fn a_secret_across_the_split_is_withheld() {
        let secrets = SecretSet::default();
        secrets.add("FAKE-PYPI-SECRET-100");
        for padding in [MAX_LINE - 6, MAX_LINE - 1, MAX_LINE, MAX_LINE + 3] {
            let mut input = "a".repeat(padding).into_bytes();
            input.extend_from_slice(b"FAKE-PYPI-SECRET-100 tail\nnext\n");
            let (sender, receiver) = std::sync::mpsc::channel();
            forward(&input[..], sender, &secrets);
            let pieces: Vec<String> = receiver
                .iter()
                .map(|piece| scrubbed(&piece, &secrets))
                .collect();
            let joined = pieces.concat();
            assert!(joined.contains("[withheld] tail"), "{padding}");
            assert!(!joined.contains("FAKE-PYPI"), "{padding}: a half in clear");
            assert!(!joined.contains("SECRET-100"), "{padding}: a half in clear");
            assert_eq!(pieces.last().map(String::as_str), Some("next"));
            assert!(pieces.iter().all(|piece| piece.len() <= MAX_LINE));
        }
        // Without secrets the split stays at 64 KiB.
        let input = "b".repeat(MAX_LINE + 10);
        let (sender, receiver) = std::sync::mpsc::channel();
        forward(input.as_bytes(), sender, &SecretSet::default());
        let lengths: Vec<usize> = receiver.iter().map(|piece| piece.len()).collect();
        assert_eq!(lengths, [MAX_LINE, 10]);
    }

    /// uv discovers a workspace along the path it is given: a parent reached through a
    /// symlink is checked on both sides of the link (review finding).
    #[test]
    fn a_workspace_behind_a_symlinked_parent_is_refused() {
        let root =
            std::env::temp_dir().join(format!("airs-uvws-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(root.join("ws")).unwrap();
        std::fs::create_dir_all(root.join("x/models")).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        std::fs::write(
            root.join("ws/pyproject.toml"),
            "[project]\nname='ws'\n[tool.uv.workspace]\nmembers=['models/*']\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("x/models"), root.join("ws/models")).unwrap();
        match preflight_dir(OsStr::new("ws/models/new"), Some(&root)) {
            Err(CliError::Operational(failure)) => assert_eq!(
                failure.message,
                format!(
                    "ws/models/new is inside the uv workspace at {}; choose a --dir outside it",
                    root.join("ws").display()
                )
            ),
            other => panic!("{other:?}"),
        }
        // `..` taken lexically as well as physically.
        std::fs::create_dir_all(root.join("ws/plain")).unwrap();
        assert!(preflight_dir(OsStr::new("x/../ws/plain/new"), Some(&root)).is_err());
        assert!(preflight_dir(OsStr::new("x/models/new"), Some(&root)).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_lock_fails_the_persistence_check() {
        let root =
            std::env::temp_dir().join(format!("airs-uvlock-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
        let index = crate::modelsec::pypi::check(
            "https://oauth2accesstoken:FAKE-PYPI-SECRET-100@h.example/s/simple/",
        )
        .unwrap();
        match persistence_check(&root, &index) {
            Err(CliError::Operational(failure)) => {
                assert!(
                    failure.message.starts_with("uv did not write "),
                    "{}",
                    failure.message
                );
                assert!(!failure.message.contains("FAKE-PYPI"));
            }
            other => panic!("{other:?}"),
        }
        std::fs::write(root.join("uv.lock"), "version = 1\n").unwrap();
        assert!(persistence_check(&root, &index).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_dir_must_be_new_with_an_existing_parent() {
        let root = std::env::temp_dir().join(format!("airs-uv-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        std::fs::create_dir(root.join("taken")).unwrap();
        let message = |dir: &str| match preflight_dir(OsStr::new(dir), Some(&root)) {
            Err(CliError::Operational(failure)) => failure.message,
            other => panic!("{dir}: {other:?}"),
        };
        assert_eq!(
            message("taken"),
            "taken already exists; choose another --dir"
        );
        assert_eq!(
            message("missing/new"),
            "Cannot create missing/new; its parent directory does not exist"
        );
        assert_eq!(
            preflight_dir(OsStr::new("new"), Some(&root)).unwrap(),
            root.join("new")
        );
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname='x'\n[tool.uv.workspace]\nmembers=[]\n",
        )
        .unwrap();
        assert_eq!(
            message("taken/new"),
            format!(
                "taken/new is inside the uv workspace at {}; choose a --dir outside it",
                root.display()
            )
        );
        std::fs::write(root.join("pyproject.toml"), "not = [toml").unwrap();
        assert!(message("new").starts_with("Cannot check "));
        std::fs::write(root.join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
        assert!(preflight_dir(OsStr::new("new"), Some(&root)).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }
}
