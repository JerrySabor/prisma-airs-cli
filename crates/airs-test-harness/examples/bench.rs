//! Performance comparison of `airs-cli-rs` (the release binary) and the pinned
//! TypeScript reference CLI (`node .reference/prisma-airs-cli/dist/cli/index.js`, what
//! the installed `airs-cli` bin runs). Methodology and results: `docs/BENCHMARKS.md`.
//!
//! ```text
//! cargo build --release
//! cargo run --release -p airs-test-harness --example bench -- [options]
//!
//!   --iterations N        timed runs per scenario and CLI (default 30; live: 5, max 20)
//!   --warmup N            untimed runs per scenario and CLI first (default 3)
//!   --batch-size N        scans per sequential batch sample (default 50)
//!   --batch-iterations N  timed batches per CLI (default 5)
//!   --filter TEXT         only scenarios whose name contains TEXT
//!   --name NAME           output name: target/bench/NAME.json and .md (default
//!                         loopback, or live)
//!   --ts-compile-cache    also time the TypeScript CLI with NODE_COMPILE_CACHE set
//!   --no-static           skip the static footprint metrics
//!   --allow-stale         run even when target/release/airs is older than src/
//!   --show-output         print the start of each verification run's stdout
//!   --live                read-only timing against a real tenant (see below)
//! ```
//!
//! # Loopback mode (the default)
//!
//! Every scenario gets its own [`FixtureServer`] on `127.0.0.1` and a [`Sandbox`] whose
//! tenant config is [`FixtureConfig::standard`](airs_test_harness::FixtureConfig), so the
//! loopback guard applies to every TypeScript run. Each scenario first runs once per CLI
//! through the harness [`run`] (timeout, leak check, unchanged-sandbox check) and must
//! exit 0 with the expected output. The timed runs then go through a small `python3 -I`
//! helper that starts each CLI with the scrubbed environment of the parity tests
//! ([`child_environment`]) and reaps it with `wait4(2)`, which gives the wall time
//! (spawn to exit, `time.perf_counter_ns`), user and system CPU time and the peak
//! resident set size of that one process. Every timed run is checked again: exit 0, the
//! expected output, no fixture secret in either stream, no sandbox file changed, and the
//! number of requests the fixture saw. Rounds alternate which CLI goes first.
//!
//! # Live mode (`--live`; only the user runs it)
//!
//! Needs `AIRS_RS_LIVE=1` and `AIRS_E2E_TENANT=<name>` and refuses otherwise
//! ([`LiveBenchSettings`]). It times only read-only commands ([`BENCH_CHECKS`]: tenant
//! read, doctor, profiles list, topics list, profiles get of the first listed profile;
//! no scans) through [`run_live_bench`], which uses the live tier's isolation: an
//! isolated copy of the one registry entry, a cleared environment, a leak check of every
//! output and the fingerprint check of the real registry and config after every run.
//! The output holds only check labels, exit codes and durations.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, SystemTime};

use airs_test_harness::live::{
    BENCH_CHECKS, LiveBenchReport, LiveBenchSettings, LiveTarget, Verdict, real_registry_path,
    run_live_bench,
};
use airs_test_harness::{
    Cli, FixtureServer, Route, RunOptions, Sandbox, child_environment, fixtures, reference, run,
    workspace_root,
};
use serde_json::{Value, json};

const PROFILE: &str = "bench-profile";
const PROMPT: &str = "What is the capital of France?";
const RESPONSE: &str = "The capital of France is Paris.";
/// Rows in the bulk profiles and topics datasets.
const BULK_ROWS: u64 = 2000;
/// The profile `profiles get` looks up in the bulk dataset (in the middle of the walk).
const BULK_LOOKUP: &str = "profile-1000";
const RUN_TIMEOUT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------------------

struct Options {
    iterations: Option<u32>,
    warmup: u32,
    batch_size: u32,
    batch_iterations: u32,
    filter: Option<String>,
    name: Option<String>,
    ts_compile_cache: bool,
    no_static: bool,
    allow_stale: bool,
    show_output: bool,
    live: bool,
}

fn parse_options() -> Options {
    let mut options = Options {
        iterations: None,
        warmup: 3,
        batch_size: 50,
        batch_iterations: 5,
        filter: None,
        name: None,
        ts_compile_cache: false,
        no_static: false,
        allow_stale: false,
        show_output: false,
        live: false,
    };
    let mut args = std::env::args().skip(1);
    let number = |flag: &str, value: Option<String>| -> u32 {
        value
            .and_then(|text| text.parse::<u32>().ok())
            .unwrap_or_else(|| usage(&format!("{flag} needs a non-negative integer")))
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iterations" => options.iterations = Some(number(&arg, args.next())),
            "--warmup" => options.warmup = number(&arg, args.next()),
            "--batch-size" => options.batch_size = number(&arg, args.next()),
            "--batch-iterations" => options.batch_iterations = number(&arg, args.next()),
            "--filter" => options.filter = args.next(),
            "--name" => {
                let name = args.next().unwrap_or_default();
                let valid = !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
                if !valid {
                    usage("--name needs letters, digits, '-' or '_'");
                }
                options.name = Some(name);
            }
            "--ts-compile-cache" => options.ts_compile_cache = true,
            "--no-static" => options.no_static = true,
            "--allow-stale" => options.allow_stale = true,
            "--show-output" => options.show_output = true,
            "--live" => options.live = true,
            "-h" | "--help" => {
                println!("see the header of crates/airs-test-harness/examples/bench.rs");
                std::process::exit(0);
            }
            other => usage(&format!("unknown argument {other}")),
        }
    }
    if options.iterations == Some(0) && !options.live {
        usage("--iterations must be at least 1");
    }
    options
}

fn usage(problem: &str) -> ! {
    eprintln!("bench: {problem} (see the header of crates/airs-test-harness/examples/bench.rs)");
    std::process::exit(2);
}

fn fail(problem: &str) -> ! {
    eprintln!("bench: {problem}");
    std::process::exit(1);
}

// ---------------------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Stats {
    n: usize,
    min: f64,
    median: f64,
    mean: f64,
    p95: f64,
    max: f64,
    stddev: f64,
}

impl Stats {
    fn of(values: &[f64]) -> Self {
        let mut sorted = values.to_vec();
        sorted.sort_by(f64::total_cmp);
        let n = sorted.len();
        if n == 0 {
            return Self {
                n,
                min: f64::NAN,
                median: f64::NAN,
                mean: f64::NAN,
                p95: f64::NAN,
                max: f64::NAN,
                stddev: f64::NAN,
            };
        }
        let mean = sorted.iter().sum::<f64>() / n as f64;
        let median = if n % 2 == 1 {
            sorted[n / 2]
        } else {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        };
        // Nearest rank.
        let rank = ((0.95 * n as f64).ceil() as usize).clamp(1, n);
        let variance = if n > 1 {
            sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64
        } else {
            0.0
        };
        Self {
            n,
            min: sorted[0],
            median,
            mean,
            p95: sorted[rank - 1],
            max: sorted[n - 1],
            stddev: variance.sqrt(),
        }
    }

    fn to_json(self) -> Value {
        let round = |v: f64| (v * 1000.0).round() / 1000.0;
        json!({
            "n": self.n,
            "min": round(self.min),
            "median": round(self.median),
            "mean": round(self.mean),
            "p95": round(self.p95),
            "max": round(self.max),
            "stddev": round(self.stddev),
        })
    }
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator > 0.0 {
        numerator / denominator
    } else {
        f64::NAN
    }
}

// ---------------------------------------------------------------------------------------
// The wait4 meter
// ---------------------------------------------------------------------------------------

/// Reads one JSON request per line, runs it, answers with one JSON line. The wall time
/// runs from just before `Popen` to `wait4` returning; the rusage is that child's.
const METER_SCRIPT: &str = r#"
import json, os, subprocess, sys, threading, time
def drain(pipe, path):
    with open(path, "wb") as out:
        while True:
            chunk = pipe.read(65536)
            if not chunk:
                break
            out.write(chunk)
for line in sys.stdin:
    req = json.loads(line)
    t0 = time.perf_counter_ns()
    proc = subprocess.Popen(req["argv"], env=req["env"], cwd=req["cwd"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, close_fds=True)
    readers = [threading.Thread(target=drain, args=(proc.stdout, req["stdout"])),
               threading.Thread(target=drain, args=(proc.stderr, req["stderr"]))]
    for reader in readers:
        reader.start()
    killed = []
    def kill():
        killed.append(True)
        try:
            os.kill(proc.pid, 9)
        except OSError:
            pass
    timer = threading.Timer(req["timeout"], kill)
    timer.start()
    _, status, usage = os.wait4(proc.pid, 0)
    t1 = time.perf_counter_ns()
    timer.cancel()
    proc.returncode = os.waitstatus_to_exitcode(status)
    for reader in readers:
        reader.join()
    sys.stdout.write(json.dumps({
        "wall_ns": t1 - t0,
        "code": proc.returncode,
        "timed_out": bool(killed),
        "utime": usage.ru_utime,
        "stime": usage.ru_stime,
        "maxrss": usage.ru_maxrss,
        "nvcsw": usage.ru_nvcsw,
        "nivcsw": usage.ru_nivcsw,
    }) + "\n")
    sys.stdout.flush()
"#;

struct Meter {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    dir: tempfile::TempDir,
    python: PathBuf,
    python_version: String,
}

/// One measured process.
struct Measured {
    wall_ms: f64,
    code: i32,
    timed_out: bool,
    user_ms: f64,
    sys_ms: f64,
    /// `ru_maxrss` (bytes on macOS).
    maxrss: u64,
    stdout: String,
    stderr: String,
}

impl Meter {
    fn start() -> Self {
        let python = resolve_python();
        let python_version =
            command_text(Command::new(&python).args(["-I", "--version"])).unwrap_or_default();
        let dir = tempfile::Builder::new()
            .prefix("airs-bench-")
            .tempdir()
            .unwrap_or_else(|err| fail(&format!("cannot create a temp directory: {err}")));
        let mut child = Command::new(&python)
            .args(["-I", "-c", METER_SCRIPT])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|err| fail(&format!("cannot start {}: {err}", python.display())));
        let stdin = child.stdin.take().unwrap_or_else(|| fail("meter stdin"));
        let stdout = BufReader::new(child.stdout.take().unwrap_or_else(|| fail("meter stdout")));
        Self {
            child,
            stdin,
            stdout,
            dir,
            python,
            python_version: python_version.trim().to_owned(),
        }
    }

    fn run(&mut self, argv: &[String], env: &BTreeMap<String, String>, cwd: &Path) -> Measured {
        let out = self.dir.path().join("stdout");
        let err = self.dir.path().join("stderr");
        let request = json!({
            "argv": argv,
            "env": env,
            "cwd": cwd,
            "stdout": out,
            "stderr": err,
            "timeout": RUN_TIMEOUT.as_secs_f64(),
        });
        writeln!(self.stdin, "{request}")
            .and_then(|()| self.stdin.flush())
            .unwrap_or_else(|err| fail(&format!("meter write: {err}")));
        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .unwrap_or_else(|err| fail(&format!("meter read: {err}")));
        if read == 0 {
            fail("the meter exited");
        }
        let answer: Value =
            serde_json::from_str(&line).unwrap_or_else(|err| fail(&format!("meter: {err}")));
        let float = |key: &str| answer.get(key).and_then(Value::as_f64).unwrap_or(f64::NAN);
        let read_lossy = |path: &Path| {
            String::from_utf8_lossy(&std::fs::read(path).unwrap_or_default()).into_owned()
        };
        Measured {
            wall_ms: float("wall_ns") / 1e6,
            code: answer.get("code").and_then(Value::as_i64).unwrap_or(-1) as i32,
            timed_out: answer.get("timed_out").and_then(Value::as_bool) == Some(true),
            user_ms: float("utime") * 1000.0,
            sys_ms: float("stime") * 1000.0,
            maxrss: answer.get("maxrss").and_then(Value::as_u64).unwrap_or(0),
            stdout: read_lossy(&out),
            stderr: read_lossy(&err),
        }
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `AIRS_BENCH_PYTHON`, else the interpreter `python3` on `PATH` resolves to (so a
/// version-manager shim is not run once per request).
fn resolve_python() -> PathBuf {
    if let Some(path) = std::env::var_os("AIRS_BENCH_PYTHON").filter(|v| !v.is_empty()) {
        return PathBuf::from(path);
    }
    let resolved = command_text(Command::new("python3").args([
        "-I",
        "-c",
        "import sys; print(sys.executable)",
    ]))
    .map(|text| PathBuf::from(text.trim()))
    .filter(|path| path.is_file());
    resolved.unwrap_or_else(|| fail("python3 not found (set AIRS_BENCH_PYTHON)"))
}

fn command_text(command: &mut Command) -> Option<String> {
    let output = command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn text_of(program: &str, args: &[&str]) -> Option<String> {
    command_text(Command::new(program).args(args)).map(|text| text.trim().to_owned())
}

// ---------------------------------------------------------------------------------------
// CLIs and scenarios
// ---------------------------------------------------------------------------------------

#[derive(Clone)]
struct Variant {
    /// `airs-cli-rs`, `airs-cli`, `airs-cli+cache`.
    label: &'static str,
    cli: Cli,
    /// Set `NODE_COMPILE_CACHE=<sandbox>/tmp/node-compile-cache`.
    compile_cache: bool,
}

impl Variant {
    fn argv(&self, args: &[String]) -> Vec<String> {
        let mut argv = match &self.cli {
            Cli::Rust(path) => vec![path.display().to_string()],
            Cli::Ts { node, entry } => {
                vec![node.display().to_string(), entry.display().to_string()]
            }
        };
        argv.extend(args.iter().cloned());
        argv
    }

    fn options(&self, sandbox: &Sandbox) -> RunOptions {
        let options = RunOptions::new().timeout(RUN_TIMEOUT);
        if self.compile_cache {
            options.env(
                "NODE_COMPILE_CACHE",
                sandbox
                    .tmp()
                    .join("node-compile-cache")
                    .display()
                    .to_string(),
            )
        } else {
            options
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dataset {
    /// 3 profile rows (2 names), 3 topic rows.
    Small,
    /// [`BULK_ROWS`] profiles and [`BULK_ROWS`] topics, unique names, one revision each.
    Bulk,
}

impl Dataset {
    fn label(self) -> &'static str {
        match self {
            Self::Small => "small (3 profiles, 3 topics)",
            Self::Bulk => "bulk (2,000 profiles, 2,000 topics)",
        }
    }
}

type Check = fn(&str) -> Result<(), String>;

struct Scenario {
    name: &'static str,
    args: Vec<String>,
    dataset: Dataset,
    check: Check,
    /// Invocations per sample: 1, or the batch size.
    batch: u32,
    note: &'static str,
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

fn check_version(stdout: &str) -> Result<(), String> {
    let text = stdout.trim();
    (!text.is_empty() && text.bytes().any(|b| b.is_ascii_digit()))
        .then_some(())
        .ok_or_else(|| "no version on stdout".into())
}

fn check_help(stdout: &str) -> Result<(), String> {
    stdout
        .contains("Usage")
        .then_some(())
        .ok_or_else(|| "no Usage line on stdout".into())
}

fn check_tenant_list(stdout: &str) -> Result<(), String> {
    stdout
        .contains("prod")
        .then_some(())
        .ok_or_else(|| "tenant prod not listed".into())
}

fn json_of(stdout: &str) -> Result<Value, String> {
    serde_json::from_str(stdout).map_err(|err| format!("stdout is not JSON: {err}"))
}

/// A `[{key, value}]` array that holds the TSG.
fn check_tenant_read(stdout: &str) -> Result<(), String> {
    let value = json_of(stdout)?;
    let has_tsg = value.as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row.get("key").and_then(Value::as_str) == Some("mgmtTsgId"))
    });
    has_tsg
        .then_some(())
        .ok_or_else(|| "no mgmtTsgId row in the key/value array".into())
}

fn check_doctor(stdout: &str) -> Result<(), String> {
    let value = json_of(stdout)?;
    let text = value.to_string();
    (text.contains("Scanner API") && text.contains("Management OAuth"))
        .then_some(())
        .ok_or_else(|| "doctor JSON lacks the probe checks".into())
}

fn check_profiles_page(stdout: &str) -> Result<(), String> {
    (stdout.contains("alpha") && stdout.contains(PROFILE))
        .then_some(())
        .ok_or_else(|| "profiles alpha and bench-profile not listed".into())
}

fn array_len(stdout: &str) -> Result<usize, String> {
    json_of(stdout)?
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| "stdout is not a JSON array".into())
}

fn check_bulk_list(stdout: &str) -> Result<(), String> {
    let len = array_len(stdout)?;
    (len == BULK_ROWS as usize)
        .then_some(())
        .ok_or_else(|| format!("{len} rows, expected {BULK_ROWS}"))
}

fn check_profile_get(stdout: &str) -> Result<(), String> {
    let value = json_of(stdout)?;
    (value.get("profileName").and_then(Value::as_str) == Some(BULK_LOOKUP))
        .then_some(())
        .ok_or_else(|| format!("profileName is not {BULK_LOOKUP}"))
}

/// Rust `--output json`, or the pretty verdict (the TS CLI prints pretty only, D5).
fn check_allow(stdout: &str) -> Result<(), String> {
    let verdict = serde_json::from_str::<Value>(stdout)
        .ok()
        .and_then(|value| Verdict::from_rust_json(&value))
        .or_else(|| Verdict::from_pretty(stdout))
        .ok_or("no scan verdict on stdout")?;
    (verdict.action == "allow")
        .then_some(())
        .ok_or_else(|| format!("verdict {}", verdict.cell()))
}

fn scenarios(options: &Options) -> Vec<Scenario> {
    let scan = |extra: &[&str]| {
        let mut args = strings(&["runtime", "scan", "--profile", PROFILE]);
        args.extend(strings(extra));
        args.push(PROMPT.to_owned());
        args
    };
    let all = vec![
        Scenario {
            name: "version",
            args: strings(&["--version"]),
            dataset: Dataset::Small,
            check: check_version,
            batch: 1,
            note: "startup only",
        },
        Scenario {
            name: "help",
            args: strings(&["--help"]),
            dataset: Dataset::Small,
            check: check_help,
            batch: 1,
            note: "startup and help rendering",
        },
        Scenario {
            name: "tenant-list",
            args: strings(&["tenant", "list", "--output", "json"]),
            dataset: Dataset::Small,
            check: check_tenant_list,
            batch: 1,
            note: "registry read, no network",
        },
        Scenario {
            name: "tenant-read-json",
            args: strings(&["tenant", "read", "--output", "json"]),
            dataset: Dataset::Small,
            check: check_tenant_read,
            batch: 1,
            note: "registry and config read, no network",
        },
        Scenario {
            name: "doctor-json",
            args: strings(&["doctor", "--output", "json"]),
            dataset: Dataset::Small,
            check: check_doctor,
            batch: 1,
            note: "TS runs 11 checks (adds Node.js, Typesafe x2, AI Gateway), Rust 7 (D19)",
        },
        Scenario {
            name: "profiles-list",
            args: strings(&["runtime", "profiles", "list", "--output", "json"]),
            dataset: Dataset::Small,
            check: check_profiles_page,
            batch: 1,
            note: "one page",
        },
        Scenario {
            name: "profiles-list-all-2000",
            args: strings(&["runtime", "profiles", "list", "--all", "--output", "json"]),
            dataset: Dataset::Bulk,
            check: check_bulk_list,
            batch: 1,
            note: "20 pages of 100",
        },
        Scenario {
            name: "topics-list-all-2000",
            args: strings(&["runtime", "topics", "list", "--all", "--output", "json"]),
            dataset: Dataset::Bulk,
            check: check_bulk_list,
            batch: 1,
            note: "10 pages of 200",
        },
        Scenario {
            name: "profiles-get-of-2000",
            args: strings(&[
                "runtime",
                "profiles",
                "get",
                BULK_LOOKUP,
                "--output",
                "json",
            ]),
            dataset: Dataset::Bulk,
            check: check_profile_get,
            batch: 1,
            note: "lookup by name in the 2,000-profile dataset",
        },
        Scenario {
            name: "scan-pretty",
            args: scan(&[]),
            dataset: Dataset::Small,
            check: check_allow,
            batch: 1,
            note: "one prompt, pretty output",
        },
        Scenario {
            name: "scan-json",
            args: scan(&["--output", "json"]),
            dataset: Dataset::Small,
            check: check_allow,
            batch: 1,
            note: "TS prints pretty for --output json (D5)",
        },
        Scenario {
            name: "scan-prompt-response-json",
            args: scan(&["--output", "json", "--response", RESPONSE]),
            dataset: Dataset::Small,
            check: check_allow,
            batch: 1,
            note: "prompt and response",
        },
        Scenario {
            name: "scan-batch",
            args: scan(&["--output", "json"]),
            dataset: Dataset::Small,
            check: check_allow,
            batch: options.batch_size.max(1),
            note: "sequential scans per sample (scripted use); times are per batch",
        },
    ];
    all.into_iter()
        .filter(|scenario| {
            options
                .filter
                .as_deref()
                .is_none_or(|filter| scenario.name.contains(filter))
        })
        .collect()
}

struct Ctx {
    server: FixtureServer,
    sandbox: Sandbox,
}

fn context(dataset: Dataset) -> Ctx {
    let server = FixtureServer::start();
    let sandbox = Sandbox::new();
    sandbox.single_tenant(&server, "prod", "100");
    match dataset {
        Dataset::Small => {
            server.set_profiles(
                "100",
                vec![
                    fixtures::profile(1, "alpha", 1),
                    fixtures::profile(2, "alpha", 2),
                    fixtures::profile(3, PROFILE, 1),
                ],
            );
            server.set_topics(
                "100",
                vec![
                    fixtures::topic(11, "fin", 1, "old"),
                    fixtures::topic(12, "fin", 2, "new"),
                    fixtures::topic(13, "legal", 1, "legal desc"),
                ],
            );
        }
        Dataset::Bulk => {
            server.set_profiles(
                "100",
                (1..=BULK_ROWS)
                    .map(|n| fixtures::profile(n, &format!("profile-{n:04}"), 1))
                    .collect(),
            );
            server.set_topics(
                "100",
                (1..=BULK_ROWS)
                    .map(|n| {
                        fixtures::topic(
                            100_000 + n,
                            &format!("topic-{n:04}"),
                            1,
                            "bulk fixture topic",
                        )
                    })
                    .collect(),
            );
        }
    }
    Ctx { server, sandbox }
}

/// One timed sample: a single invocation, or a batch summed.
#[derive(Default)]
struct Sample {
    wall_ms: f64,
    cpu_ms: f64,
    user_ms: f64,
    sys_ms: f64,
    maxrss: u64,
    requests: usize,
}

/// Runs one invocation through the meter and checks it like the harness runner does.
fn measured_run(
    meter: &mut Meter,
    ctx: &Ctx,
    variant: &Variant,
    scenario: &Scenario,
) -> Result<(Measured, usize), String> {
    let env = child_environment(&ctx.sandbox, &variant.options(&ctx.sandbox));
    if variant.cli.is_ts() {
        ctx.sandbox.assert_safe_for_ts(&env);
    }
    let before = ctx.sandbox.full_snapshot();
    ctx.server.clear_requests();
    let measured = meter.run(&variant.argv(&scenario.args), &env, &ctx.sandbox.cwd());
    let requests = ctx.server.request_count();
    let label = variant.label;
    if measured.timed_out {
        return Err(format!("{label} {}: timed out", scenario.name));
    }
    let changes = Sandbox::changes_under(ctx.sandbox.root(), &before);
    if !changes.is_empty() {
        return Err(format!(
            "{label} {}: changed sandbox files {changes:?}",
            scenario.name
        ));
    }
    for form in ctx.sandbox.secret_forms() {
        if measured.stdout.contains(&form.value) || measured.stderr.contains(&form.value) {
            return Err(format!(
                "{label} {}: {} appeared in output",
                scenario.name, form.label
            ));
        }
    }
    if measured.code != 0 {
        return Err(format!(
            "{label} {}: exit {}\n--- stderr ---\n{}",
            scenario.name, measured.code, measured.stderr
        ));
    }
    (scenario.check)(&measured.stdout)
        .map_err(|problem| format!("{label} {}: {problem}", scenario.name))?;
    Ok((measured, requests))
}

fn sample(
    meter: &mut Meter,
    ctx: &Ctx,
    variant: &Variant,
    scenario: &Scenario,
) -> Result<Sample, String> {
    let mut total = Sample::default();
    for _ in 0..scenario.batch {
        let (measured, requests) = measured_run(meter, ctx, variant, scenario)?;
        total.wall_ms += measured.wall_ms;
        total.user_ms += measured.user_ms;
        total.sys_ms += measured.sys_ms;
        total.cpu_ms += measured.user_ms + measured.sys_ms;
        total.maxrss = total.maxrss.max(measured.maxrss);
        total.requests += requests;
    }
    Ok(total)
}

/// The strict harness run (panics on a leak, a changed sandbox file or a timeout), plus
/// the scenario's output check. Returns the routes the fixture saw and, for doctor
/// output, each check's `name: status`.
fn verify(
    ctx: &Ctx,
    variant: &Variant,
    scenario: &Scenario,
    show: bool,
) -> (Vec<String>, Vec<String>) {
    ctx.server.clear_requests();
    let refs: Vec<&str> = scenario.args.iter().map(String::as_str).collect();
    let out = run(
        &variant.cli,
        &ctx.sandbox,
        &refs,
        &variant.options(&ctx.sandbox),
    );
    if out.code != 0 {
        fail(&format!(
            "verification: {} {}: exit {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            variant.label, scenario.name, out.code, out.stdout, out.stderr
        ));
    }
    if let Err(problem) = (scenario.check)(&out.stdout) {
        fail(&format!(
            "verification: {} {}: {problem}\n--- stdout ---\n{}",
            variant.label, scenario.name, out.stdout
        ));
    }
    if show {
        let head: String = out.stdout.chars().take(600).collect();
        println!("--- {} {} stdout ---\n{head}", variant.label, scenario.name);
    }
    let unknown = ctx.server.requests_for(Route::Unknown).len();
    if unknown > 0 {
        eprintln!(
            "bench: note: {} {} made {unknown} request(s) to unknown fixture routes",
            variant.label, scenario.name
        );
    }
    let checks = serde_json::from_str::<Value>(&out.stdout)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    let name = row.get("name")?.as_str()?;
                    let status = row.get("status")?.as_str()?;
                    Some(format!("{name}: {status}"))
                })
                .collect()
        })
        .unwrap_or_default();
    let routes = ctx
        .server
        .routes()
        .into_iter()
        .map(|route| route.label().to_owned())
        .collect();
    (routes, checks)
}

struct VariantResult {
    label: &'static str,
    samples: Vec<Sample>,
    routes: Vec<String>,
    /// Doctor `name: status` pairs of the verification run (empty otherwise).
    checks: Vec<String>,
}

impl VariantResult {
    fn stats(&self, field: impl Fn(&Sample) -> f64) -> Stats {
        Stats::of(&self.samples.iter().map(field).collect::<Vec<_>>())
    }

    fn requests(&self) -> (usize, usize) {
        let counts = self.samples.iter().map(|s| s.requests);
        (counts.clone().min().unwrap_or(0), counts.max().unwrap_or(0))
    }

    fn to_json(&self) -> Value {
        let mib = |s: &Sample| s.maxrss as f64 / 1_048_576.0;
        let (min_requests, max_requests) = self.requests();
        json!({
            "cli": self.label,
            "samples": self.samples.len(),
            "wall_ms": self.stats(|s| s.wall_ms).to_json(),
            "cpu_ms": self.stats(|s| s.cpu_ms).to_json(),
            "user_ms": self.stats(|s| s.user_ms).to_json(),
            "sys_ms": self.stats(|s| s.sys_ms).to_json(),
            "peak_rss_mib": self.stats(mib).to_json(),
            "requests_per_sample": {"min": min_requests, "max": max_requests},
            "verification_routes": self.routes,
            "verification_checks": self.checks,
            "raw": {
                "wall_ms": self.samples.iter().map(|s| (s.wall_ms * 1000.0).round() / 1000.0).collect::<Vec<_>>(),
                "cpu_ms": self.samples.iter().map(|s| (s.cpu_ms * 1000.0).round() / 1000.0).collect::<Vec<_>>(),
                "peak_rss_bytes": self.samples.iter().map(|s| s.maxrss).collect::<Vec<_>>(),
            },
        })
    }
}

struct ScenarioResult {
    name: &'static str,
    args: Vec<String>,
    dataset: Dataset,
    batch: u32,
    note: &'static str,
    variants: Vec<VariantResult>,
}

impl ScenarioResult {
    fn variant(&self, label: &str) -> Option<&VariantResult> {
        self.variants.iter().find(|v| v.label == label)
    }

    fn ratio_of(&self, label: &str, field: impl Fn(&Sample) -> f64 + Copy) -> f64 {
        match (self.variant(label), self.variant("airs-cli-rs")) {
            (Some(other), Some(rust)) => ratio(other.stats(field).median, rust.stats(field).median),
            _ => f64::NAN,
        }
    }

    fn to_json(&self) -> Value {
        let rss = |s: &Sample| s.maxrss as f64;
        let round = |v: f64| (v * 100.0).round() / 100.0;
        let mut ratios = serde_json::Map::new();
        for variant in &self.variants {
            if variant.label == "airs-cli-rs" {
                continue;
            }
            ratios.insert(
                variant.label.to_owned(),
                json!({
                    "wall_median": round(self.ratio_of(variant.label, |s| s.wall_ms)),
                    "cpu_median": round(self.ratio_of(variant.label, |s| s.cpu_ms)),
                    "peak_rss_median": round(self.ratio_of(variant.label, rss)),
                }),
            );
        }
        json!({
            "name": self.name,
            "args": self.args,
            "dataset": self.dataset.label(),
            "invocations_per_sample": self.batch,
            "note": self.note,
            "variants": self.variants.iter().map(VariantResult::to_json).collect::<Vec<_>>(),
            "ratios_over_rust": ratios,
        })
    }
}

fn run_scenario(
    meter: &mut Meter,
    variants: &[Variant],
    scenario: &Scenario,
    options: &Options,
    iterations: u32,
) -> ScenarioResult {
    let ctx = context(scenario.dataset);
    let mut results: Vec<VariantResult> = variants
        .iter()
        .map(|variant| {
            let (routes, checks) = verify(&ctx, variant, scenario, options.show_output);
            VariantResult {
                label: variant.label,
                samples: Vec::new(),
                routes,
                checks,
            }
        })
        .collect();
    let single = Scenario {
        name: scenario.name,
        args: scenario.args.clone(),
        dataset: scenario.dataset,
        check: scenario.check,
        batch: 1,
        note: scenario.note,
    };
    let rounds = if scenario.batch > 1 {
        options.batch_iterations.max(1)
    } else {
        iterations
    };
    for round in 0..options.warmup + rounds {
        // Rotate which CLI goes first.
        for offset in 0..variants.len() {
            let index = (round as usize + offset) % variants.len();
            let warm = round < options.warmup;
            let target = if warm { &single } else { scenario };
            let measured = sample(meter, &ctx, &variants[index], target)
                .unwrap_or_else(|problem| fail(&problem));
            if !warm {
                results[index].samples.push(measured);
            }
        }
    }
    ScenarioResult {
        name: scenario.name,
        args: scenario.args.clone(),
        dataset: scenario.dataset,
        batch: scenario.batch,
        note: scenario.note,
        variants: results,
    }
}

// ---------------------------------------------------------------------------------------
// Environment and static footprint
// ---------------------------------------------------------------------------------------

fn environment(rust_bin: &Path, ts: &Cli, meter: Option<&Meter>) -> Value {
    let root = workspace_root();
    let sysctl = |name: &str| text_of("sysctl", &["-n", name]);
    let (node, entry) = match ts {
        Cli::Ts { node, entry } => (node.clone(), entry.clone()),
        Cli::Rust(_) => (PathBuf::new(), PathBuf::new()),
    };
    let clone = root.join(".reference/prisma-airs-cli");
    let package_version = std::fs::read_to_string(clone.join("package.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| {
            value
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let dirty = text_of(
        "git",
        &["-C", &root.display().to_string(), "status", "--porcelain"],
    )
    .map(|text| text.lines().count());
    let power =
        text_of("pmset", &["-g", "batt"]).and_then(|text| text.lines().next().map(str::to_owned));
    json!({
        "date_utc": text_of("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]),
        "chip": sysctl("machdep.cpu.brand_string"),
        "cpus_logical": sysctl("hw.ncpu"),
        "cpu_perflevels": (0..4)
            .filter_map(|level| {
                let name = sysctl(&format!("hw.perflevel{level}.name"))
                    .filter(|name| !name.is_empty())?;
                let cores = sysctl(&format!("hw.perflevel{level}.physicalcpu"))
                    .filter(|cores| !cores.is_empty())?;
                Some(format!("{cores} {name}"))
            })
            .collect::<Vec<_>>(),
        "memory_bytes": sysctl("hw.memsize").and_then(|v| v.parse::<u64>().ok()),
        "macos": text_of("sw_vers", &["-productVersion"]),
        "macos_build": text_of("sw_vers", &["-buildVersion"]),
        "kernel": text_of("uname", &["-r"]),
        "power": power,
        "load_average": sysctl("vm.loadavg"),
        "all_processes_cpu_percent": all_processes_cpu_percent(),
        "rustc": text_of("rustc", &["--version"]),
        "node": text_of(&node.display().to_string(), &["--version"]),
        "node_path": node.display().to_string(),
        "ts_entry": entry.strip_prefix(&root).unwrap_or(&entry).display().to_string(),
        "ts_reference_commit": text_of("git", &["-C", &clone.display().to_string(), "rev-parse", "HEAD"]),
        "ts_package_version": package_version,
        "repo_head": text_of("git", &["-C", &root.display().to_string(), "rev-parse", "HEAD"]),
        "repo_dirty_paths": dirty,
        "rust_cli_version": text_of(&rust_bin.display().to_string(), &["--version"]),
        "rust_bin_sha256": text_of("shasum", &["-a", "256", &rust_bin.display().to_string()])
            .and_then(|text| text.split_whitespace().next().map(str::to_owned)),
        "python": meter.map(|m| json!({"path": m.python.display().to_string(), "version": m.python_version})),
    })
}

/// The sum of `ps` %CPU over every process (a rough indicator of background load;
/// 100 = one busy core). No process names are recorded.
fn all_processes_cpu_percent() -> Option<f64> {
    let text = text_of("ps", &["-Ao", "pcpu="])?;
    let total: f64 = text
        .lines()
        .filter_map(|line| line.trim().parse::<f64>().ok())
        .sum();
    Some((total * 10.0).round() / 10.0)
}

/// Apparent bytes and file count under `path`, not following symlinks.
fn tree_size(path: &Path) -> (u64, u64) {
    let mut bytes = 0;
    let mut files = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        if meta.is_file() {
            bytes += meta.len();
            files += 1;
            continue;
        }
        if !meta.is_dir() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            stack.push(entry.path());
        }
    }
    (bytes, files)
}

/// `du -sk` (allocated KiB).
fn disk_kib(path: &Path) -> Option<u64> {
    text_of("du", &["-sk", &path.display().to_string()])
        .and_then(|text| text.split_whitespace().next()?.parse().ok())
}

fn static_metrics(rust_bin: &Path, ts: &Cli) -> Value {
    let root = workspace_root();
    let mib = |bytes: u64| (bytes as f64 / 1_048_576.0 * 100.0).round() / 100.0;
    let rust_size = std::fs::metadata(rust_bin).map(|m| m.len()).unwrap_or(0);
    let tarball = std::fs::read_dir(root.join("target/dist"))
        .ok()
        .and_then(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .find(|path| path.to_string_lossy().ends_with(".tar.gz"))
        });
    let tarball_size = tarball
        .as_ref()
        .and_then(|path| std::fs::metadata(path).ok())
        .map(|m| m.len());
    let dylibs: Vec<String> = text_of("otool", &["-L", &rust_bin.display().to_string()])
        .map(|text| {
            text.lines()
                .skip(1)
                .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let rust_runtime_crates = command_text(
        Command::new(&cargo)
            .args([
                "tree", "-p", "airs-cli", "-e", "normal", "--prefix", "none", "--target", "all",
            ])
            .current_dir(&root),
    )
    .map(|text| {
        let mut names: Vec<String> = text
            .lines()
            .map(|line| line.trim_end_matches(" (*)").trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect();
        names.sort();
        names.dedup();
        names.len().saturating_sub(1)
    });
    let lock_packages = std::fs::read_to_string(root.join("Cargo.lock"))
        .ok()
        .map(|text| text.matches("[[package]]").count());

    let clone = root.join(".reference/prisma-airs-cli");
    let (dist_bytes, dist_files) = tree_size(&clone.join("dist"));
    let (nm_bytes, nm_files) = tree_size(&clone.join("node_modules"));
    let pnpm_store_entries = std::fs::read_dir(clone.join("node_modules/.pnpm"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_name() != "lock.yaml" && entry.path().is_dir())
                .filter(|entry| entry.file_name() != "node_modules")
                .count()
        })
        .ok();
    // `pnpm list` only reads (node_modules/.modules.yaml is unchanged by it).
    let prod_paths: Option<Vec<PathBuf>> = command_text(
        Command::new("pnpm")
            .args(["list", "--prod", "--parseable", "--depth", "Infinity"])
            .current_dir(&clone),
    )
    .map(|text| {
        let mut paths: Vec<PathBuf> = text
            .lines()
            .map(PathBuf::from)
            .filter(|path| path != &clone && path.starts_with(&clone))
            .collect();
        paths.sort();
        paths.dedup();
        paths
    });
    let prod = prod_paths.as_ref().map(|paths| {
        let (bytes, files) = paths
            .iter()
            .map(|path| tree_size(path))
            .fold((0, 0), |(bytes, files), (b, f)| (bytes + b, files + f));
        (paths.len(), bytes, files)
    });
    let node = match ts {
        Cli::Ts { node, .. } => std::fs::canonicalize(node).unwrap_or_else(|_| node.clone()),
        Cli::Rust(path) => path.clone(),
    };
    let node_size = std::fs::metadata(&node).map(|m| m.len()).unwrap_or(0);
    let ts_install = prod.map(|(_, bytes, _)| bytes + dist_bytes + node_size);
    json!({
        "rust": {
            "binary": rust_bin.strip_prefix(&root).unwrap_or(rust_bin).display().to_string(),
            "binary_bytes": rust_size,
            "binary_mib": mib(rust_size),
            "binary_note": "release profile: lto=thin, codegen-units=1, strip=symbols",
            "file": text_of("file", &["-b", &rust_bin.display().to_string()]),
            "dynamic_libraries": dylibs,
            "tarball": tarball.as_ref().map(|p| p.strip_prefix(&root).unwrap_or(p).display().to_string()),
            "tarball_bytes": tarball_size,
            "tarball_mib": tarball_size.map(mib),
            "runtime_crates": rust_runtime_crates,
            "cargo_lock_packages": lock_packages,
        },
        "ts": {
            "dist_bytes": dist_bytes,
            "dist_mib": mib(dist_bytes),
            "dist_files": dist_files,
            "dist_disk_kib": disk_kib(&clone.join("dist")),
            "node_modules_bytes": nm_bytes,
            "node_modules_mib": mib(nm_bytes),
            "node_modules_files": nm_files,
            "node_modules_disk_kib": disk_kib(&clone.join("node_modules")),
            "node_modules_note": "includes dev dependencies (pnpm install of the reference checkout)",
            "pnpm_store_packages": pnpm_store_entries,
            "prod_packages": prod.map(|(count, _, _)| count),
            "prod_bytes": prod.map(|(_, bytes, _)| bytes),
            "prod_mib": prod.map(|(_, bytes, _)| mib(bytes)),
            "prod_files": prod.map(|(_, _, files)| files),
            "node_binary": node.display().to_string(),
            "node_binary_bytes": node_size,
            "node_binary_mib": mib(node_size),
            "install_estimate_bytes": ts_install,
            "install_estimate_mib": ts_install.map(mib),
            "install_estimate_note": "node binary + dist + production dependencies",
        },
    })
}

/// Refuses a release binary older than the newest file under `src/` or the manifests.
fn check_fresh(rust_bin: &Path, allow_stale: bool) {
    let root = workspace_root();
    let built = std::fs::metadata(rust_bin)
        .and_then(|m| m.modified())
        .unwrap_or_else(|_| {
            fail(&format!(
                "{} not found; run cargo build --release",
                rust_bin.display()
            ))
        });
    let mut newest = SystemTime::UNIX_EPOCH;
    let mut stack = vec![
        root.join("src"),
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
    ];
    while let Some(path) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&path) {
                stack.extend(entries.flatten().map(|entry| entry.path()));
            }
        } else if let Ok(modified) = meta.modified() {
            newest = newest.max(modified);
        }
    }
    if newest > built {
        let message = format!(
            "{} is older than the sources; run cargo build --release",
            rust_bin.display()
        );
        if allow_stale {
            eprintln!("bench: warning: {message} (--allow-stale)");
        } else {
            fail(&format!("{message} (or pass --allow-stale)"));
        }
    }
}

// ---------------------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------------------

fn fmt_ms(value: f64) -> String {
    if value >= 100.0 {
        format!("{value:.0}")
    } else if value >= 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.2}")
    }
}

fn fmt_ratio(value: f64) -> String {
    if value.is_nan() {
        "n/a".into()
    } else if value >= 10.0 {
        format!("{value:.0}x")
    } else {
        format!("{value:.1}x")
    }
}

fn markdown(results: &[ScenarioResult], variants: &[Variant]) -> String {
    let mib = |s: &Sample| s.maxrss as f64 / 1_048_576.0;
    let mut out = String::new();
    let others: Vec<&Variant> = variants
        .iter()
        .filter(|v| v.label != "airs-cli-rs")
        .collect();
    out.push_str("| Scenario | airs-cli-rs median ms | ");
    for other in &others {
        out.push_str(&format!("{} median ms | TS/Rust wall | ", other.label));
    }
    out.push_str("airs-cli-rs CPU ms | airs-cli CPU ms | TS/Rust CPU | airs-cli-rs peak RSS MiB | airs-cli peak RSS MiB | TS/Rust RSS | requests (rs / ts) |\n|---|---:|");
    for _ in &others {
        out.push_str("---:|---:|");
    }
    out.push_str("---:|---:|---:|---:|---:|---:|---:|\n");
    for result in results {
        let Some(rust) = result.variant("airs-cli-rs") else {
            continue;
        };
        let name = if result.batch > 1 {
            format!("{} (x{} per sample)", result.name, result.batch)
        } else {
            result.name.to_owned()
        };
        out.push_str(&format!(
            "| {name} | {} | ",
            fmt_ms(rust.stats(|s| s.wall_ms).median)
        ));
        for other in &others {
            let stats = result
                .variant(other.label)
                .map(|v| v.stats(|s| s.wall_ms).median)
                .unwrap_or(f64::NAN);
            out.push_str(&format!(
                "{} | {} | ",
                fmt_ms(stats),
                fmt_ratio(result.ratio_of(other.label, |s| s.wall_ms))
            ));
        }
        let ts = result.variant("airs-cli");
        let requests = |v: Option<&VariantResult>| {
            v.map(|v| {
                let (min, max) = v.requests();
                if min == max {
                    min.to_string()
                } else {
                    format!("{min}-{max}")
                }
            })
            .unwrap_or_default()
        };
        out.push_str(&format!(
            "{} | {} | {} | {:.1} | {} | {} | {} / {} |\n",
            fmt_ms(rust.stats(|s| s.cpu_ms).median),
            ts.map(|v| fmt_ms(v.stats(|s| s.cpu_ms).median))
                .unwrap_or_default(),
            fmt_ratio(result.ratio_of("airs-cli", |s| s.cpu_ms)),
            rust.stats(mib).median,
            ts.map(|v| format!("{:.1}", v.stats(mib).median))
                .unwrap_or_default(),
            fmt_ratio(result.ratio_of("airs-cli", |s| s.maxrss as f64)),
            requests(Some(rust)),
            requests(ts),
        ));
    }
    out.push_str(
        "\nDetail (wall ms min / median / mean / p95 / max; CPU = user + sys ms, median):\n\n",
    );
    out.push_str("| Scenario | CLI | n | min | median | mean | p95 | max | stddev | CPU | user | sys | peak RSS MiB (median / max) |\n");
    out.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for result in results {
        for variant in &result.variants {
            let wall = variant.stats(|s| s.wall_ms);
            let rss = variant.stats(mib);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.1} / {:.1} |\n",
                result.name,
                variant.label,
                wall.n,
                fmt_ms(wall.min),
                fmt_ms(wall.median),
                fmt_ms(wall.mean),
                fmt_ms(wall.p95),
                fmt_ms(wall.max),
                fmt_ms(wall.stddev),
                fmt_ms(variant.stats(|s| s.cpu_ms).median),
                fmt_ms(variant.stats(|s| s.user_ms).median),
                fmt_ms(variant.stats(|s| s.sys_ms).median),
                rss.median,
                rss.max,
            ));
        }
    }
    out
}

fn write_outputs(name: &str, document: &Value, table: &str) {
    let dir = workspace_root().join("target/bench");
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|err| fail(&format!("cannot create {}: {err}", dir.display())));
    let json_path = dir.join(format!("{name}.json"));
    let md_path = dir.join(format!("{name}.md"));
    let text = serde_json::to_string_pretty(document).unwrap_or_default() + "\n";
    std::fs::write(&json_path, text)
        .unwrap_or_else(|err| fail(&format!("cannot write {}: {err}", json_path.display())));
    std::fs::write(&md_path, table)
        .unwrap_or_else(|err| fail(&format!("cannot write {}: {err}", md_path.display())));
    eprintln!(
        "bench: wrote {} and {}",
        json_path.display(),
        md_path.display()
    );
}

// ---------------------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------------------

fn loopback_main(options: &Options, rust_bin: PathBuf, ts: Cli) {
    let iterations = options.iterations.unwrap_or(30);
    let mut variants = vec![
        Variant {
            label: "airs-cli-rs",
            cli: Cli::rust(&rust_bin),
            compile_cache: false,
        },
        Variant {
            label: "airs-cli",
            cli: ts.clone(),
            compile_cache: false,
        },
    ];
    if options.ts_compile_cache {
        variants.push(Variant {
            label: "airs-cli+cache",
            cli: ts.clone(),
            compile_cache: true,
        });
    }
    let mut meter = Meter::start();
    let environment_before = environment(&rust_bin, &ts, Some(&meter));
    let static_metrics = (!options.no_static).then(|| static_metrics(&rust_bin, &ts));
    // The meter's own cost: spawning and reaping a process that does nothing.
    let floor_dir = tempfile::tempdir()
        .unwrap_or_else(|err| fail(&format!("cannot create a temp directory: {err}")));
    let floor_argv = vec!["/usr/bin/true".to_owned()];
    let floor_env = BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]);
    let floor: Vec<f64> = (0..options.warmup + iterations)
        .map(|_| meter.run(&floor_argv, &floor_env, floor_dir.path()).wall_ms)
        .skip(options.warmup as usize)
        .collect();
    let floor = Stats::of(&floor);
    eprintln!(
        "bench: spawn floor (/usr/bin/true) median {} ms",
        fmt_ms(floor.median)
    );
    let mut results = Vec::new();
    for scenario in scenarios(options) {
        eprintln!("bench: {} ...", scenario.name);
        let result = run_scenario(&mut meter, &variants, &scenario, options, iterations);
        for variant in &result.variants {
            let wall = variant.stats(|s| s.wall_ms);
            eprintln!(
                "bench:   {:<15} median {:>9} ms  p95 {:>9} ms  ({} samples)",
                variant.label,
                fmt_ms(wall.median),
                fmt_ms(wall.p95),
                wall.n
            );
        }
        results.push(result);
    }
    let load_after = json!({
        "load_average": text_of("sysctl", &["-n", "vm.loadavg"]),
        "all_processes_cpu_percent": all_processes_cpu_percent(),
    });
    let mut table = markdown(&results, &variants);
    table.push_str(&format!(
        "\nSpawn floor (/usr/bin/true through the same meter): median {} ms, p95 {} ms.\n",
        fmt_ms(floor.median),
        fmt_ms(floor.p95)
    ));
    let document = json!({
        "mode": "loopback",
        "settings": {
            "iterations": iterations,
            "warmup": options.warmup,
            "batch_size": options.batch_size,
            "batch_iterations": options.batch_iterations,
            "filter": options.filter,
            "ts_compile_cache": options.ts_compile_cache,
            "run_order": "each round runs every CLI once, rotating which goes first",
            "timing": "python3 -I helper: perf_counter_ns from before Popen to wait4 return; rusage from wait4",
            "output": "stdout and stderr are pipes drained by the helper",
        },
        "environment": environment_before,
        "spawn_floor_ms": floor.to_json(),
        "after": load_after,
        "static": static_metrics,
        "scenarios": results.iter().map(ScenarioResult::to_json).collect::<Vec<_>>(),
    });
    println!("{table}");
    write_outputs(
        options.name.as_deref().unwrap_or("loopback"),
        &document,
        &table,
    );
}

fn live_main(options: &Options, rust_bin: PathBuf, ts: Cli) {
    let settings = LiveBenchSettings::from_env(options.iterations)
        .unwrap_or_else(|problem| usage(&format!("--live refused: {problem}")));
    let registry = real_registry_path().unwrap_or_else(|problem| fail(&problem));
    let target = LiveTarget::real(registry, &settings.tenant).unwrap_or_else(|p| fail(&p));
    let environment = environment(&rust_bin, &ts, None);
    let report: LiveBenchReport =
        run_live_bench(target, Cli::rust(&rust_bin), ts, settings.iterations)
            .unwrap_or_else(|abort| fail(&format!("live benchmark stopped: {abort}")));
    let mut table = String::from(
        "| Check | CLI | exits | min | median | mean | p95 | max |\n|---|---|---|---:|---:|---:|---:|---:|\n",
    );
    let mut rows = Vec::new();
    for row in &report.rows {
        let stats = Stats::of(&row.wall_ms);
        let mut exits: BTreeMap<&str, usize> = BTreeMap::new();
        for exit in &row.exits {
            *exits.entry(exit.as_str()).or_default() += 1;
        }
        let exits_cell: Vec<String> = exits
            .iter()
            .map(|(code, n)| format!("{code}x{n}"))
            .collect();
        table.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            row.check,
            row.cli,
            exits_cell.join(" "),
            fmt_ms(stats.min),
            fmt_ms(stats.median),
            fmt_ms(stats.mean),
            fmt_ms(stats.p95),
            fmt_ms(stats.max)
        ));
        rows.push(json!({"check": row.check, "cli": row.cli, "wall_ms": stats.to_json()}));
    }
    table.push_str("\nTS/Rust median wall:\n\n| Check | ratio |\n|---|---:|\n");
    for check in BENCH_CHECKS {
        let median = |cli: &str| {
            report
                .rows
                .iter()
                .find(|row| row.check == check && row.cli == cli)
                .map(|row| Stats::of(&row.wall_ms).median)
        };
        if let (Some(rust), Some(ts)) = (median("airs-cli-rs"), median("airs-cli")) {
            table.push_str(&format!("| {check} | {} |\n", fmt_ratio(ratio(ts, rust))));
        }
    }
    for notice in &report.notices {
        table.push_str(&format!("\n- {notice}"));
    }
    table.push('\n');
    let document = json!({
        "mode": "live-read-only",
        "environment": environment,
        "report": report.to_json(),
        "stats": rows,
    });
    println!("{table}");
    write_outputs(options.name.as_deref().unwrap_or("live"), &document, &table);
}

fn main() {
    let options = parse_options();
    let rust_bin = workspace_root().join("target/release/airs");
    check_fresh(&rust_bin, options.allow_stale);
    let ts = reference().unwrap_or_else(|reason| {
        fail(&format!(
            "the TypeScript reference is unusable: {reason}; run scripts/build-reference-cli.sh"
        ))
    });
    if options.live {
        live_main(&options, rust_bin, ts);
    } else {
        loopback_main(&options, rust_bin, ts);
    }
}
