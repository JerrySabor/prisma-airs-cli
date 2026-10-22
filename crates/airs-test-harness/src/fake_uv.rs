//! The fake tools of the `model-security install` tests (DESIGN §10 M6c): a fake `uv`
//! (a `/bin/sh` script on the sandbox `PATH`, also packed into the fake uv archive that
//! the fixture serves for `--fetch-uv`), the fake `python3` and `pip` of the TypeScript
//! fallback (D195), and a strict tar + gzip builder for the archive variants.
//!
//! Every invocation records itself in its own directory `<sandbox>/tmp/uv-calls/<n>/`:
//! `argv` (the arguments, NUL-separated) and `info` (`program=`, `pid=`, `pgid=`, and for
//! `UV_INDEX_AIRS_MODEL_SECURITY_USERNAME`, `_PASSWORD` and `UV_NO_CONFIG` whether each is
//! set and the SHA-256 of the credential values, never the values), `signals` (every
//! signal it trapped) and `finished`. The real uv is never run.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::Sandbox;

/// What the fake uv does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeUv {
    /// The first line of `uv --version`.
    pub version: String,
    /// The exit code of `uv init` / `uv add`.
    pub init_exit: i32,
    pub add_exit: i32,
    /// Sleep (trapping INT and TERM) during `init` or `add`.
    pub sleep_in: Option<&'static str>,
    /// How long that sleep lasts.
    pub sleep_secs: u32,
    /// During that sleep, record INT and TERM but keep sleeping (only `SIGKILL` ends it).
    pub stubborn: bool,
    /// Print the password it received on stdout and stderr during `add` (the scrub test).
    pub echo_credential: bool,
    /// The number of `a` bytes printed before the password on each echo line (a line
    /// longer than the CLI's 64 KiB split).
    pub echo_padding: usize,
    /// Write no `uv.lock` during `add` (a uv that locked elsewhere).
    pub skip_lock: bool,
    /// Write the password it received into `uv.lock` during `add` (the persistence check).
    pub write_credential: bool,
    /// `kill -9` itself during `init` or `add`.
    pub kill_self_in: Option<&'static str>,
}

impl Default for FakeUv {
    fn default() -> Self {
        Self {
            version: "uv 0.12.17 (fake 2026-09-18)".to_owned(),
            init_exit: 0,
            add_exit: 0,
            sleep_in: None,
            sleep_secs: 30,
            stubborn: false,
            echo_credential: false,
            echo_padding: 0,
            skip_lock: false,
            write_credential: false,
            kill_self_in: None,
        }
    }
}

/// `<sandbox>/tmp/uv-calls`.
pub fn calls_dir(sandbox: &Sandbox) -> PathBuf {
    sandbox.tmp().join("uv-calls")
}

fn first_existing(candidates: &[&str]) -> String {
    candidates
        .iter()
        .find(|candidate| Path::new(candidate.split(' ').next().unwrap_or_default()).exists())
        .copied()
        .unwrap_or_else(|| panic!("fake uv: none of {candidates:?} exists"))
        .to_owned()
}

/// The shell prologue that records one invocation of `program`.
fn record_prologue(program: &str, records: &Path) -> String {
    let sha = first_existing(&[
        "/usr/bin/sha256sum",
        "/bin/sha256sum",
        "/sbin/sha256sum",
        "/usr/bin/shasum -a 256",
    ]);
    let ps = first_existing(&["/bin/ps", "/usr/bin/ps"]);
    format!(
        r#"#!/bin/sh
R='{records}'
/bin/mkdir -p "$R"
n=1
while ! /bin/mkdir "$R/$n" 2>/dev/null; do n=$((n+1)); done
D="$R/$n"
for a in "$@"; do printf '%s\0' "$a"; done > "$D/argv"
{{
  echo "program={program}"
  echo "pid=$$"
  p=$({ps} -o pgid= -p $$)
  echo "pgid=$(echo $p)"
  if [ -n "${{UV_INDEX_AIRS_MODEL_SECURITY_USERNAME+x}}" ]; then
    h=$(printf '%s' "$UV_INDEX_AIRS_MODEL_SECURITY_USERNAME" | {sha})
    echo "username_sha=${{h%% *}}"
  fi
  if [ -n "${{UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD+x}}" ]; then
    h=$(printf '%s' "$UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD" | {sha})
    echo "password_sha=${{h%% *}}"
  fi
  if [ -n "${{UV_NO_CONFIG+x}}" ]; then echo "no_config=1"; fi
}} > "$D/info"
"#,
        records = records.display(),
    )
}

/// The fake uv script recording into `records`.
pub fn fake_uv_script(fake: &FakeUv, records: &Path) -> String {
    let mut script = record_prologue("uv", records);
    let step = |name: &str| -> String {
        let mut body = String::new();
        if fake.kill_self_in == Some(name) {
            body.push_str("  kill -9 $$\n");
        }
        if fake.sleep_in == Some(name) && fake.stubborn {
            body.push_str(&format!(
                "  trap 'echo INT >> \"$D/signals\"' INT\n  trap 'echo TERM >> \"$D/signals\"' TERM\n  echo \"fake uv sleeping\" >&2\n  i=0\n  while [ $i -lt {} ]; do /bin/sleep 1 & wait $!; i=$((i+1)); done\n",
                fake.sleep_secs
            ));
        } else if fake.sleep_in == Some(name) {
            body.push_str(&format!(
                "  trap 'echo INT >> \"$D/signals\"; exit 130' INT\n  trap 'echo TERM >> \"$D/signals\"; exit 143' TERM\n  echo \"fake uv sleeping\" >&2\n  /bin/sleep {} &\n  wait $!\n",
                fake.sleep_secs
            ));
        }
        body
    };
    script.push_str(&format!(
        r#"cmd=""
for a in "$@"; do case "$a" in -*) ;; *) cmd="$a"; break;; esac; done
last=""; project=""; index=""; prev=""
for a in "$@"; do
  case "$prev" in --project) project="$a";; --index) index="$a";; esac
  prev="$a"; last="$a"
done
case "$cmd" in
"")
  echo '{version}'
  echo finished > "$D/finished"
  exit 0
  ;;
init)
{init_step}  /bin/mkdir -p "$last"
  printf '[project]\nname = "model-security"\nversion = "0.1.0"\n' > "$last/pyproject.toml"
  echo "fake uv stdout line"
  echo "fake uv stderr line" >&2
  echo finished > "$D/finished"
  exit {init_exit}
  ;;
add)
{add_step}  url="${{index#airs-model-security=}}"
  printf '\n[[tool.uv.index]]\nname = "airs-model-security"\nurl = "%s"\n' "$url" >> "$project/pyproject.toml"
{lock}{write}{echo}  echo "fake uv stdout line"
  echo "fake uv stderr line" >&2
  echo finished > "$D/finished"
  exit {add_exit}
  ;;
esac
exit 0
"#,
        version = fake.version,
        init_step = step("init"),
        add_step = step("add"),
        init_exit = fake.init_exit,
        add_exit = fake.add_exit,
        write = if fake.write_credential {
            "  printf '# %s\\n' \"$UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD\" >> \"$project/uv.lock\"\n"
        } else {
            ""
        },
        lock = if fake.skip_lock {
            ""
        } else {
            "  printf 'version = 1\\n[[package]]\\nname = \"model-security-client\"\\nsource = { registry = \"%s\" }\\n' \"$url\" > \"$project/uv.lock\"\n"
        },
        echo = if fake.echo_credential {
            format!(
                "  pad=$(/usr/bin/head -c {} /dev/zero | /usr/bin/tr '\\0' a)\n  echo \"${{pad}}fake uv saw $UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD\"\n  echo \"${{pad}}fake uv saw $UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD\" >&2\n",
                fake.echo_padding
            )
        } else {
            String::new()
        },
    ));
    script
}

fn write_executable(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("fake uv: cannot create {}: {err}", parent.display()));
    }
    std::fs::write(path, text)
        .unwrap_or_else(|err| panic!("fake uv: cannot write {}: {err}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|err| panic!("fake uv: cannot chmod {}: {err}", path.display()));
}

/// Writes `<sandbox>/bin/uv` and returns its path.
pub fn fake_uv(sandbox: &Sandbox, fake: &FakeUv) -> PathBuf {
    let path = sandbox.bin_dir().join("uv");
    write_executable(&path, &fake_uv_script(fake, &calls_dir(sandbox)));
    path
}

/// Writes `<sandbox>/bin/python3` (the TypeScript fallback, D195): `-m venv <dir>` creates
/// `<dir>/bin/pip`, a recording fake that exits 0; `--version` answers.
pub fn fake_python(sandbox: &Sandbox) -> PathBuf {
    let records = calls_dir(sandbox);
    let mut pip = record_prologue("pip", &records);
    pip.push_str("echo \"fake pip line\"\nexit 0\n");
    let mut python = record_prologue("python3", &records);
    python.push_str(&format!(
        "if [ \"$1\" = \"--version\" ]; then echo 'Python 3.99.0'; exit 0; fi\nif [ \"$1\" = \"-m\" ] && [ \"$2\" = \"venv\" ]; then\n  /bin/mkdir -p \"$3/bin\"\n  /bin/cat > \"$3/bin/pip\" <<'PIPEOF'\n{pip}PIPEOF\n  /bin/chmod 755 \"$3/bin/pip\"\nfi\nexit 0\n"
    ));
    let path = sandbox.bin_dir().join("python3");
    write_executable(&path, &python);
    path
}

/// One recorded invocation of a fake tool.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UvCall {
    pub program: String,
    pub argv: Vec<String>,
    pub pid: Option<u32>,
    pub pgid: Option<u32>,
    pub username_sha: Option<String>,
    pub password_sha: Option<String>,
    pub no_config: bool,
    pub signals: Vec<String>,
    pub finished: bool,
}

/// Every recorded invocation, in order.
pub fn uv_calls(sandbox: &Sandbox) -> Vec<UvCall> {
    let dir = calls_dir(sandbox);
    let mut numbers: Vec<u64> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    numbers.sort_unstable();
    numbers
        .into_iter()
        .map(|n| {
            let call = dir.join(n.to_string());
            let argv = std::fs::read(call.join("argv")).unwrap_or_default();
            let argv: Vec<String> = argv
                .split(|byte| *byte == 0)
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect();
            let argv = match argv.split_last() {
                Some((last, rest)) if last.is_empty() => rest.to_vec(),
                _ => argv,
            };
            let info = std::fs::read_to_string(call.join("info")).unwrap_or_default();
            let field = |name: &str| {
                info.lines()
                    .find_map(|line| line.strip_prefix(&format!("{name}=")))
                    .map(str::to_owned)
            };
            UvCall {
                program: field("program").unwrap_or_default(),
                argv,
                pid: field("pid").and_then(|value| value.parse().ok()),
                pgid: field("pgid").and_then(|value| value.trim().parse().ok()),
                username_sha: field("username_sha"),
                password_sha: field("password_sha"),
                no_config: field("no_config").is_some(),
                signals: std::fs::read_to_string(call.join("signals"))
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_owned)
                    .collect(),
                finished: call.join("finished").exists(),
            }
        })
        .collect()
}

/// The lowercase hex SHA-256 of `text` (to compare with a recorded `*_sha`).
pub fn sha256_text(text: &str) -> String {
    crate::server::sha256_hex(text.as_bytes())
}

/// The cargo-dist target of this host (the CLI's `--fetch-uv` table).
pub fn host_target() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    }
}

/// One tar entry of a fake archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarEntry {
    pub name: String,
    /// The ustar type flag (`b'0'` regular, `b'2'` symlink, `b'1'` hard link, `b'5'`
    /// directory, `b'x'` pax header, `b'L'` GNU long name).
    pub kind: u8,
    pub data: Vec<u8>,
    /// The link target of a link entry.
    pub link: String,
    /// Corrupt the header checksum.
    pub bad_checksum: bool,
}

impl TarEntry {
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.to_owned(),
            kind: b'0',
            data: data.to_vec(),
            link: String::new(),
            bad_checksum: false,
        }
    }

    pub fn dir(name: &str) -> Self {
        Self {
            kind: b'5',
            ..Self::file(name, b"")
        }
    }

    pub fn link(name: &str, kind: u8, target: &str) -> Self {
        Self {
            kind,
            link: target.to_owned(),
            ..Self::file(name, b"")
        }
    }

    /// A pax extended header whose `path` record renames the next entry.
    pub fn pax_path(path: &str) -> Self {
        let record = format!(" path={path}\n");
        let mut length = record.len() + 1;
        while format!("{length}{record}").len() != length {
            length += 1;
        }
        Self {
            kind: b'x',
            ..Self::file("PaxHeaders/next", format!("{length}{record}").as_bytes())
        }
    }

    /// A GNU long-name entry naming the next entry.
    pub fn gnu_long_name(name: &str) -> Self {
        let mut data = name.as_bytes().to_vec();
        data.push(0);
        Self {
            kind: b'L',
            ..Self::file("././@LongLink", &data)
        }
    }

    fn header(&self) -> Vec<u8> {
        let mut block = vec![0u8; 512];
        let name = self.name.as_bytes();
        let cut = name.len().min(100);
        block[..cut].copy_from_slice(&name[..cut]);
        let mode: &[u8] = if self.kind == b'5' || self.name.ends_with("/uv") {
            b"0000755\0"
        } else {
            b"0000644\0"
        };
        block[100..108].copy_from_slice(mode);
        block[108..116].copy_from_slice(b"0000000\0");
        block[116..124].copy_from_slice(b"0000000\0");
        block[124..136].copy_from_slice(format!("{:011o}\0", self.data.len()).as_bytes());
        block[136..148].copy_from_slice(b"00000000000\0");
        block[156] = self.kind;
        let link = self.link.as_bytes();
        let cut = link.len().min(100);
        block[157..157 + cut].copy_from_slice(&link[..cut]);
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        block[148..156].copy_from_slice(b"        ");
        let mut sum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
        if self.bad_checksum {
            sum += 1;
        }
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        block
    }
}

/// A gzipped tar of `entries` ending with two zero blocks.
pub fn tar_gz(entries: &[TarEntry]) -> Vec<u8> {
    let mut tar = Vec::new();
    for entry in entries {
        tar.extend_from_slice(&entry.header());
        tar.extend_from_slice(&entry.data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.extend_from_slice(&[0u8; 1024]);
    gzip(&tar)
}

/// gzip of `bytes`.
pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(bytes)
        .unwrap_or_else(|err| panic!("fake uv archive: gzip failed: {err}"));
    encoder
        .finish()
        .unwrap_or_else(|err| panic!("fake uv archive: gzip failed: {err}"))
}

/// The cargo-dist layout with `script` as `uv-<target>/uv` (and a `uvx`).
pub fn uv_archive_entries(script: &str) -> Vec<TarEntry> {
    let target = host_target();
    vec![
        TarEntry::dir(&format!("uv-{target}/")),
        TarEntry::file(&format!("uv-{target}/uv"), script.as_bytes()),
        TarEntry::file(&format!("uv-{target}/uvx"), b"#!/bin/sh\nexit 0\n"),
    ]
}

/// The standard fake archive: the fake uv recording into the sandbox's calls directory.
pub fn uv_archive(sandbox: &Sandbox, fake: &FakeUv) -> Vec<u8> {
    tar_gz(&uv_archive_entries(&fake_uv_script(
        fake,
        &calls_dir(sandbox),
    )))
}

/// `uv-<target>.tar.gz` of this host.
pub fn archive_file_name() -> String {
    format!("uv-{}.tar.gz", host_target())
}
