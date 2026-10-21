//! `scripts/homebrew-formula.sh` (DESIGN §21.8, §21.9): the formula it renders, its
//! checksum sources and its refusals. Every run is offline: the script runs with a
//! cleared environment, `HOME` and `TMPDIR` inside a private directory under
//! `CARGO_TARGET_TMPDIR`, and a `PATH` whose first entry holds a stub `curl`. The stub
//! of the offline tests records that it ran and exits 97, and they check it never ran;
//! the crates.io test's stub serves local files and records its arguments. The tests
//! never use the default output path (the repository's `target/homebrew/`), so a
//! formula the maintainer rendered there is never replaced by a fixture.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The fixture checksum: SHA-256 of `airs-cli-1.0.0 test fixture, not a real crate`.
const CHECKSUM: &str = "952a1b3582f98b3f6a3905961058383445aa07e298b51805f5e08e53b7a5589d";
const FIXTURE: &str = "tests/fixtures/homebrew/airs-cli-1.0.0.rb";
const METADATA: &str = "tests/fixtures/homebrew/crates-io-airs-cli-1.0.0.json";
const TEMPLATE: &str = "packaging/homebrew/airs-cli.rb.in";
const USER_AGENT: &str = "airs-cli-homebrew-formula (+https://git.cdot.io/cdot/prisma-airs-cli-rs)";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    fs::read_to_string(root().join(relative))
        .unwrap_or_else(|error| panic!("cannot read {relative}: {error}"))
}

/// The first executable `name` on the test's own `PATH`.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| {
                path.metadata()
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
    })
}

/// A private directory with `home/`, `tmp/`, `out/` and `stub/` (the stub `curl`).
struct Sandbox {
    dir: PathBuf,
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

impl Sandbox {
    fn new(tag: &str) -> Sandbox {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "homebrew-formula-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["home", "tmp", "out", "stub"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let sandbox = Sandbox { dir };
        sandbox.stub_curl(&format!(
            "#!/bin/sh\necho ran > '{}'\nexit 97\n",
            sandbox.marker().display()
        ));
        sandbox
    }

    fn marker(&self) -> PathBuf {
        self.dir.join("curl-ran")
    }

    fn out(&self) -> PathBuf {
        self.dir.join("out")
    }

    fn stub_curl(&self, script: &str) {
        let path = self.dir.join("stub/curl");
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Runs the script with `args`; returns the exit code, stdout and stderr.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let jq = on_path("jq").expect(
            "jq is required by tests/homebrew_formula.rs (brew install jq, apt-get install jq); \
             DESIGN §21.9 choice 28: these tests fail rather than skip without it",
        );
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs = vec![self.dir.join("stub"), jq.parent().unwrap().to_path_buf()];
        dirs.extend(std::env::split_paths(&inherited));
        let out = Command::new("bash")
            .arg(root().join("scripts/homebrew-formula.sh"))
            .args(args)
            .current_dir(&self.dir)
            .env_clear()
            .env("PATH", std::env::join_paths(dirs).unwrap())
            .env("HOME", self.dir.join("home"))
            .env("TMPDIR", self.dir.join("tmp"))
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }

    /// The names in `dir`, sorted.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn last_line(text: &str) -> &str {
    text.lines().last().unwrap_or("")
}

/// The template rendered by the test itself, the bytes the script must write.
fn expected(version: &str, checksum: &str) -> String {
    read(TEMPLATE)
        .replace("@VERSION@", version)
        .replace("@SHA256@", checksum)
}

/// The fixture is the template rendered for 1.0.0 with the fixture checksum, and the
/// template is the formula of DESIGN §21.8: it builds `airs` from the crates.io crate,
/// links the compatibility name and tests both names. With ruby on `PATH`, the fixture
/// also passes `ruby -c`.
#[test]
fn the_template_and_the_fixture_are_the_designed_formula() {
    let template = read(TEMPLATE);
    assert_eq!(template.matches("@VERSION@").count(), 2, "{template}");
    assert_eq!(template.matches("@SHA256@").count(), 1, "{template}");
    let without = template.replace("@VERSION@", "").replace("@SHA256@", "");
    assert!(!without.contains('@'), "no other placeholder: {without}");
    let fixture = read(FIXTURE);
    assert_eq!(fixture, expected("1.0.0", CHECKSUM));
    for line in [
        "# airs-cli 1.0.0, rendered by scripts/homebrew-formula.sh from packaging/homebrew/airs-cli.rb.in.",
        "class AirsCli < Formula",
        "  desc \"Native Rust CLI for Prisma AIRS\"",
        "  homepage \"https://crates.io/crates/airs-cli\"",
        "  url \"https://crates.io/api/v1/crates/airs-cli/1.0.0/download\"",
        &format!("  sha256 \"{CHECKSUM}\""),
        "  license \"Apache-2.0\"",
        "  depends_on \"rust\" => :build",
        "    system \"cargo\", \"install\", \"--bin\", \"airs\", *std_cargo_args",
        "    bin.install_symlink \"airs\" => \"airs-cli-rs\"",
        "  test do",
        "    assert_equal version.to_s, shell_output(\"#{bin}/airs --version\").strip",
        "    assert_equal version.to_s, shell_output(\"#{bin}/airs-cli-rs --version\").strip",
        "    ENV[\"AIRS_CLI_CONFIG_DIR\"] = (testpath/\"store\").to_s",
        "    assert_equal \"[]\", shell_output(\"#{bin}/airs tenant list --output json\").strip",
        "end",
    ] {
        assert!(
            fixture.lines().any(|got| got == line),
            "missing {line:?}:\n{fixture}"
        );
    }
    // Homebrew scans the version from the url, so an explicit `version` would be
    // redundant (`brew audit --strict` flags it; DESIGN §21.14 choice 41).
    assert!(!fixture.contains("\n  version "), "{fixture}");
    assert!(!fixture.contains("airs-cli\", \"install"), "{fixture}");
    assert!(fixture.ends_with("end\n") && !fixture.ends_with("\n\n"));
    // Structure: every `do`/`def`/`class` opener has its `end`.
    let opens = fixture
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            line.starts_with("class ") || line.starts_with("def ") || line.ends_with(" do")
        })
        .count();
    let ends = fixture.lines().filter(|line| line.trim() == "end").count();
    assert_eq!((opens, ends), (3, 3), "{fixture}");
    if let Some(ruby) = on_path("ruby") {
        let out = Command::new(ruby)
            .arg("-c")
            .arg(root().join(FIXTURE))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "Syntax OK\n");
    }
}

/// `--checksum` renders exactly the fixture, writes it 0644 with no temporary file
/// left, and reports the path on stderr's last line.
#[test]
fn a_checksum_renders_the_fixture() {
    let sandbox = Sandbox::new("checksum");
    let output = sandbox.out().join("airs-cli.rb");
    let path = output.to_str().unwrap();
    let (code, stdout, stderr) = sandbox.run(&["1.0.0", "--checksum", CHECKSUM, "--output", path]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        last_line(&stderr),
        format!("homebrew-formula: wrote {path} (airs-cli 1.0.0, sha256 {CHECKSUM})")
    );
    assert_eq!(fs::read_to_string(&output).unwrap(), read(FIXTURE));
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(Sandbox::names(&sandbox.out()), ["airs-cli.rb"]);
    assert!(!sandbox.marker().exists(), "curl ran");
    // Another version renders the template for it.
    let (code, _, stderr) = sandbox.run(&["2.3.4", "--checksum", CHECKSUM, "--output", path]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        expected("2.3.4", CHECKSUM)
    );
}

/// A saved crates.io answer renders the same bytes as `--checksum`.
#[test]
fn a_metadata_file_renders_the_same_bytes() {
    let sandbox = Sandbox::new("metadata");
    let output = sandbox.out().join("airs-cli.rb");
    let metadata = root().join(METADATA);
    let (code, stdout, stderr) = sandbox.run(&[
        "1.0.0",
        "--metadata-file",
        metadata.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "");
    assert_eq!(fs::read_to_string(&output).unwrap(), read(FIXTURE));
    assert!(!sandbox.marker().exists(), "curl ran");
}

/// `--output -` writes the formula to stdout and nothing to disk.
#[test]
fn output_dash_writes_standard_output() {
    let sandbox = Sandbox::new("stdout");
    let (code, stdout, stderr) = sandbox.run(&["1.0.0", "--checksum", CHECKSUM, "--output", "-"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, read(FIXTURE));
    assert_eq!(
        last_line(&stderr),
        format!("homebrew-formula: wrote standard output (airs-cli 1.0.0, sha256 {CHECKSUM})")
    );
    assert!(Sandbox::names(&sandbox.out()).is_empty());
    assert!(!sandbox.marker().exists(), "curl ran");
}

/// An existing formula is replaced whole; a refused run leaves it as it was.
#[test]
fn an_existing_formula_is_replaced() {
    let sandbox = Sandbox::new("replace");
    let output = sandbox.out().join("airs-cli.rb");
    let path = output.to_str().unwrap();
    fs::write(&output, "# an older formula\n").unwrap();
    let (code, _, stderr) = sandbox.run(&[
        "1.0.0",
        "--checksum",
        "0".repeat(63).as_str(),
        "--output",
        path,
    ]);
    assert_eq!(code, 2, "{stderr}");
    assert_eq!(fs::read_to_string(&output).unwrap(), "# an older formula\n");
    let (code, _, stderr) = sandbox.run(&["1.0.0", "--checksum", CHECKSUM, "--output", path]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(fs::read_to_string(&output).unwrap(), read(FIXTURE));
    assert_eq!(Sandbox::names(&sandbox.out()), ["airs-cli.rb"]);
    assert!(!sandbox.marker().exists(), "curl ran");
}

/// Every refusal of §21.9 exits with its code, names the problem and writes nothing.
#[test]
fn refusals_exit_with_their_code_and_write_nothing() {
    let sandbox = Sandbox::new("refusals");
    let output = sandbox.out().join("airs-cli.rb");
    let out = output.to_str().unwrap().to_owned();
    let answer = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut value: serde_json::Value = serde_json::from_str(&read(METADATA)).unwrap();
        edit(&mut value);
        let path = sandbox.dir.join(format!(
            "answer-{}.json",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let wrong_crate = answer(&|v| v["version"]["crate"] = "airs".into());
    let wrong_num = answer(&|v| v["version"]["num"] = "1.0.1".into());
    let yanked = answer(&|v| v["version"]["yanked"] = true.into());
    let yanked_null = answer(&|v| v["version"]["yanked"] = serde_json::Value::Null);
    let no_checksum = answer(&|v| {
        v["version"].as_object_mut().unwrap().remove("checksum");
    });
    let upper = answer(&|v| v["version"]["checksum"] = CHECKSUM.to_uppercase().into());
    let short = answer(&|v| v["version"]["checksum"] = CHECKSUM[1..].into());
    let no_version = answer(&|v| *v = serde_json::json!({"errors": [{"detail": "Not Found"}]}));
    // A trailing newline: jq's `$` matches before it, and `$(…)` would strip it.
    let newline = answer(&|v| v["version"]["checksum"] = format!("{CHECKSUM}\n").into());
    let not_json = sandbox.dir.join("not-json.json");
    fs::write(&not_json, "{\"version\":").unwrap();
    let not_json = not_json.to_str().unwrap().to_owned();
    // Two documents (each a usable answer) would make jq print two checksums.
    let two_documents = sandbox.dir.join("two-documents.json");
    fs::write(
        &two_documents,
        format!("{}\n{}", read(METADATA), read(METADATA)),
    )
    .unwrap();
    let two_documents = two_documents.to_str().unwrap().to_owned();
    let empty = sandbox.dir.join("empty.json");
    fs::write(&empty, "").unwrap();
    let empty = empty.to_str().unwrap().to_owned();
    let missing = sandbox.dir.join("absent.json").to_str().unwrap().to_owned();
    let no_dir = sandbox
        .dir
        .join("absent/airs-cli.rb")
        .to_str()
        .unwrap()
        .to_owned();
    let a_dir = sandbox.out().to_str().unwrap().to_owned();
    let usage =
        "  scripts/homebrew-formula.sh <version> [--checksum <sha256> | --metadata-file <path>]";
    let unusable =
        |why: &str| format!("homebrew-formula: crates.io has no usable airs-cli 1.0.0 ({why})");
    let upper_checksum = CHECKSUM.to_uppercase();
    let cases: Vec<(Vec<&str>, i32, String)> = vec![
        (vec![], 2, "homebrew-formula: no version given".into()),
        (
            vec!["1.0.0-rc.1", "--checksum", CHECKSUM],
            2,
            "homebrew-formula: 1.0.0-rc.1 is a pre-release; the tap carries stable releases only"
                .into(),
        ),
        (
            vec!["v1.0.0", "--checksum", CHECKSUM],
            2,
            "homebrew-formula: 'v1.0.0' is not a version like 1.0.0 (no leading v)".into(),
        ),
        (
            vec!["1.0", "--checksum", CHECKSUM],
            2,
            "homebrew-formula: '1.0' is not a version like 1.0.0 (no leading v)".into(),
        ),
        (
            vec!["1.0.0", "1.0.1", "--checksum", CHECKSUM],
            2,
            "homebrew-formula: more than one version given".into(),
        ),
        (
            vec!["1.0.0", "--sha256", CHECKSUM],
            2,
            "homebrew-formula: unknown option: --sha256".into(),
        ),
        (
            vec!["1.0.0", "--checksum=abc"],
            2,
            "homebrew-formula: unknown option: --checksum=abc".into(),
        ),
        (
            vec!["1.0.0", "--checksum"],
            2,
            "homebrew-formula: --checksum needs a value".into(),
        ),
        (
            vec!["1.0.0", "--checksum", CHECKSUM, "--output"],
            2,
            "homebrew-formula: --output needs a value".into(),
        ),
        (
            vec!["1.0.0", "--checksum", CHECKSUM, "--checksum", CHECKSUM],
            2,
            "homebrew-formula: --checksum given more than once".into(),
        ),
        (
            vec!["1.0.0", "--checksum", CHECKSUM, "--metadata-file", &missing],
            2,
            "homebrew-formula: --checksum and --metadata-file exclude each other".into(),
        ),
        (
            vec!["1.0.0", "--checksum", &upper_checksum],
            2,
            "homebrew-formula: --checksum needs a SHA-256 of 64 lowercase hex digits".into(),
        ),
        (
            vec!["1.0.0", "--checksum", &CHECKSUM[1..]],
            2,
            "homebrew-formula: --checksum needs a SHA-256 of 64 lowercase hex digits".into(),
        ),
        (
            vec!["1.0.0", "--metadata-file", &wrong_crate],
            1,
            unusable("the crate is not airs-cli"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &wrong_num],
            1,
            unusable("the version is not 1.0.0"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &yanked],
            1,
            unusable("the version is yanked"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &yanked_null],
            1,
            unusable("no yanked flag"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &no_checksum],
            1,
            unusable("no checksum"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &upper],
            1,
            unusable("the checksum is not 64 lowercase hex"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &short],
            1,
            unusable("the checksum is not 64 lowercase hex"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &newline],
            1,
            unusable("the checksum is not 64 lowercase hex"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &no_version],
            1,
            unusable("no version object"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &not_json],
            1,
            unusable("the answer is not JSON"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &two_documents],
            1,
            unusable("the answer is not JSON"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &empty],
            1,
            unusable("the answer is not JSON"),
        ),
        (
            vec!["1.0.0", "--metadata-file", &missing],
            1,
            format!("homebrew-formula: cannot read {missing}"),
        ),
        (
            vec!["1.0.0", "--checksum", CHECKSUM, "--output", &no_dir],
            1,
            format!("homebrew-formula: the directory of {no_dir} does not exist"),
        ),
        (
            vec!["1.0.0", "--checksum", CHECKSUM, "--output", &a_dir],
            1,
            format!("homebrew-formula: {a_dir} is a directory"),
        ),
    ];
    for (mut args, code, message) in cases {
        if !args.contains(&"--output") {
            args.extend(["--output", out.as_str()]);
        }
        let (got, stdout, stderr) = sandbox.run(&args);
        assert_eq!(got, code, "{args:?}: {stderr}");
        assert_eq!(stdout, "", "{args:?}");
        let first = stderr
            .lines()
            .find(|line| !line.starts_with("homebrew-formula: checksum from"));
        assert_eq!(first, Some(message.as_str()), "{args:?}: {stderr}");
        if code == 2 {
            assert!(
                stderr.lines().any(|line| line == usage),
                "{args:?}: usage on stderr: {stderr}"
            );
        } else {
            assert!(!stderr.contains(usage), "{args:?}: {stderr}");
        }
        assert!(
            Sandbox::names(&sandbox.out()).is_empty(),
            "{args:?} wrote something"
        );
        assert!(
            Sandbox::names(&sandbox.dir.join("tmp")).is_empty(),
            "{args:?} left a temporary file"
        );
    }
    assert!(!sandbox.marker().exists(), "curl ran");
    let (code, stdout, stderr) = sandbox.run(&["--help"]);
    assert_eq!((code, stderr.as_str()), (0, ""));
    assert!(stdout.starts_with(&format!("{usage}\n")), "{stdout}");
}

/// Without a checksum source the script asks crates.io: one answer request and one
/// download of the `.crate` (`-q` first so no `.curlrc` is read, no credential, https
/// only, the tool's user agent), and the downloaded file's SHA-256 must equal the
/// answer's checksum; a mismatched download, a failed download and a failed answer
/// request are refused with nothing written. The stub `curl` serves local files, so
/// nothing leaves the machine.
#[test]
fn crates_io_answers_are_confirmed_by_the_downloaded_crate() {
    let sandbox = Sandbox::new("crates-io");
    let crate_file = sandbox.dir.join("served.crate");
    fs::write(&crate_file, "not a real crate, only bytes to hash\n").unwrap();
    let hasher = if on_path("shasum").is_some() {
        ("shasum", vec!["-a", "256"])
    } else {
        ("sha256sum", vec![])
    };
    let hashed = Command::new(hasher.0)
        .args(&hasher.1)
        .arg(&crate_file)
        .output()
        .unwrap();
    let checksum = String::from_utf8(hashed.stdout).unwrap()[..64].to_owned();
    let mut answer: serde_json::Value = serde_json::from_str(&read(METADATA)).unwrap();
    answer["version"]["checksum"] = checksum.clone().into();
    let answer_file = sandbox.dir.join("served.json");
    fs::write(&answer_file, serde_json::to_string(&answer).unwrap()).unwrap();
    let log = sandbox.dir.join("curl.log");
    let fail = sandbox.dir.join("fail-api");
    let fail_download = sandbox.dir.join("fail-download");
    sandbox.stub_curl(&format!(
        r#"#!/bin/sh
log='{log}'
echo '--- curl' >> "$log"
out=""
url=""
while [ "$#" -gt 0 ]; do
  printf '%s\n' "$1" >> "$log"
  if [ "$1" = -o ]; then out="$2"; printf '%s\n' "$2" >> "$log"; shift 2; continue; fi
  url="$1"
  shift
done
case "$url" in
  */download) [ ! -e '{fail_download}' ] || exit 22; cp '{crate_file}' "$out" ;;
  *) [ ! -e '{fail}' ] || exit 22; cp '{answer}' "$out" ;;
esac
"#,
        log = log.display(),
        crate_file = crate_file.display(),
        fail = fail.display(),
        fail_download = fail_download.display(),
        answer = answer_file.display(),
    ));
    let output = sandbox.out().join("airs-cli.rb");
    let path = output.to_str().unwrap();

    let (code, stdout, stderr) = sandbox.run(&["1.0.0", "--output", path]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        expected("1.0.0", &checksum)
    );
    assert_eq!(
        last_line(&stderr),
        format!("homebrew-formula: wrote {path} (airs-cli 1.0.0, sha256 {checksum})")
    );
    let calls: Vec<Vec<String>> = fs::read_to_string(&log)
        .unwrap()
        .split("--- curl\n")
        .filter(|call| !call.is_empty())
        .map(|call| call.lines().map(str::to_owned).collect())
        .collect();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let api = "https://crates.io/api/v1/crates/airs-cli/1.0.0";
    for (call, url) in calls
        .iter()
        .zip([api.to_owned(), format!("{api}/download")])
    {
        assert_eq!(call.last(), Some(&url), "{call:?}");
        // curl honours -q (--disable) only as its first argument; with it no .curlrc is
        // read, so the maintainer's curl config never reaches crates.io (choice 55).
        assert_eq!(call.first().map(String::as_str), Some("-q"), "{call:?}");
        for flag in ["-sS", "--fail", "--tlsv1.2"] {
            assert!(call.iter().any(|arg| arg == flag), "{flag} in {call:?}");
        }
        for pair in [
            ["--proto", "=https"],
            ["--proto-redir", "=https"],
            ["--max-time", "30"],
            ["-A", USER_AGENT],
        ] {
            assert!(call.windows(2).any(|w| w == pair), "{pair:?} in {call:?}");
        }
        for banned in [
            "-H", "--header", "-u", "--user", "--netrc", "-K", "--config", "-b", "--cookie",
        ] {
            assert!(
                !call.iter().any(|arg| arg == banned),
                "{banned} in {call:?}"
            );
        }
        assert!(
            !call
                .iter()
                .any(|arg| arg.to_lowercase().contains("authorization")),
            "{call:?}"
        );
    }
    assert!(
        !calls[0].iter().any(|arg| arg == "--location"),
        "{:?}",
        calls[0]
    );
    assert!(
        calls[1].iter().any(|arg| arg == "--location"),
        "{:?}",
        calls[1]
    );
    assert!(
        calls[1]
            .windows(2)
            .any(|w| w == ["--max-filesize", "67108864"]),
        "{:?}",
        calls[1]
    );
    assert!(
        Sandbox::names(&sandbox.dir.join("tmp")).is_empty(),
        "a temporary file was left"
    );

    // A crate that does not hash to the answer's checksum writes nothing.
    fs::remove_file(&output).unwrap();
    fs::write(&crate_file, "a different crate\n").unwrap();
    let (code, _, stderr) = sandbox.run(&["1.0.0", "--output", path]);
    assert_eq!(code, 1, "{stderr}");
    let message = last_line(&stderr);
    assert!(
        message.starts_with("homebrew-formula: the downloaded airs-cli-1.0.0.crate has sha256 ")
            && message.ends_with(&format!(", crates.io says {checksum}")),
        "{stderr}"
    );
    assert!(Sandbox::names(&sandbox.out()).is_empty());
    assert!(
        Sandbox::names(&sandbox.dir.join("tmp")).is_empty(),
        "a temporary file was left"
    );

    // A failed download of the `.crate` names its URL and writes nothing.
    fs::write(&crate_file, "not a real crate, only bytes to hash\n").unwrap();
    fs::write(&fail_download, "").unwrap();
    let (code, stdout, stderr) = sandbox.run(&["1.0.0", "--output", path]);
    assert_eq!((code, stdout.as_str()), (1, ""), "{stderr}");
    assert_eq!(
        last_line(&stderr),
        format!("homebrew-formula: cannot fetch {api}/download (curl exit 22)")
    );
    assert!(Sandbox::names(&sandbox.out()).is_empty());
    assert!(
        Sandbox::names(&sandbox.dir.join("tmp")).is_empty(),
        "a temporary file was left"
    );
    fs::remove_file(&fail_download).unwrap();

    // A failed request (curl --fail on a 404, say) names the URL and writes nothing.
    fs::write(&fail, "").unwrap();
    let (code, _, stderr) = sandbox.run(&["1.0.0", "--output", path]);
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(
        last_line(&stderr),
        format!("homebrew-formula: cannot fetch {api} (curl exit 22)")
    );
    assert!(Sandbox::names(&sandbox.out()).is_empty());
    assert!(
        Sandbox::names(&sandbox.dir.join("tmp")).is_empty(),
        "a temporary file was left"
    );
    assert!(!sandbox.marker().exists(), "the refusing stub ran");
}
