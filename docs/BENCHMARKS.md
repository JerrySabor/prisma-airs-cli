# Benchmarks: airs-cli-rs and airs-cli

This page records measured performance of the Rust CLI (`airs-cli-rs`, the release
binary) and the TypeScript CLI (`airs-cli`, the pinned reference build run with
`node .reference/prisma-airs-cli/dist/cli/index.js`, which is what the installed
`airs-cli` bin runs). All numbers come from
`crates/airs-test-harness/examples/bench.rs`. The raw data of the run shown here is
written to `target/bench/loopback.json` (not checked in).

## Scope

- Only commands both CLIs implement are measured. `airs-cli-rs` is release 1, a subset
  of `airs-cli` (DESIGN §1): tenant list/path/read/get, doctor, runtime profiles and
  topics list/get, and single scans. Tenant writes, topic writes, bulk scanning, Red
  Team, Model Security, AI Gateway and AgentGuard are not in release 1. These numbers
  say nothing about those commands, and they cannot by themselves justify retiring
  `airs-cli` for users who need them.
- The loopback results measure CLI overhead (process start, argument parsing, tenant
  loading, HTTP client work, JSON handling, output) against an in-process fixture
  server on `127.0.0.1`. They do not include real network latency or TLS.

## Summary

From the loopback run of 2026-10-17 (30 timed runs per scenario and CLI, medians):

- Short commands (`--version`, `--help`, `tenant list`, `tenant read`): 5.9–6.4 ms
  against 87.6–93.3 ms, a TS/Rust ratio of 14–15x.
- One-request commands (one profiles page, one scan): 13.2–13.5 ms against
  100–104 ms, 7.5–7.9x. `doctor`: 13.7 ms against 123 ms, 9.0x. The TS doctor runs 4
  more checks and 2 more requests (see Caveats).
- `--all` walks over 2,000 rows (11–21 requests): 28.3–41.0 ms against 124–140 ms,
  3.4–4.4x.
- 50 sequential scans: 620 ms against 4,942 ms per batch, 8.0x.
- CPU time (user + sys): 7.3–30x less for Rust. Peak RSS: 6.2–48.0 MiB against
  105.6–171.1 MiB, 3.0–17x.
- Install footprint: a 9.6 MiB binary (3.9 MiB tarball) against about 198 MiB for
  node, `dist` and the production dependencies.
- Both CLIs sent the same number of requests in every scenario except `doctor`.
- Live, against a production tenant, read-only:
  - Local commands keep the 15x gap.
  - Network-bound management reads are 1.0–1.2x faster, because the service's
    latency dominates. The saving is a constant 30–100 ms per command.
  - The live `doctor` times measure the scanner endpoint's HTTP 429 rate limit and the
    SDK's retry of it, not CLI speed (see Live results).

## Method

### Loopback mode

1. Each scenario gets a fresh `FixtureServer` (127.0.0.1) and `Sandbox`. The tenant
   config is `FixtureConfig::standard`, so every endpoint points at the fixture and the
   harness loopback guard (`Sandbox::assert_safe_for_ts`) checks every TypeScript run.
2. Datasets: "small" has 3 profile rows (2 names) and 3 topic rows. "bulk" has 2,000
   profiles and 2,000 topics with unique names. The bulk profiles walk is 20 pages of
   100 (`latest=true`). The topics walk is 10 pages of 200.
3. Verification: each scenario runs once per CLI through the harness `run`, with its
   timeout, secret leak check and unchanged-sandbox check. The run must exit 0 with
   the expected output: a version string, `Usage`, the tenant, a `mgmtTsgId` row, the
   doctor probe checks, the listed names, exactly 2,000 rows, the looked-up profile,
   or an `allow` verdict. If either CLI fails, the benchmark stops.
4. Timing: the runs go through a `python3 -I` helper started once. For each run it
   receives the argv, the environment and the cwd. It records `time.perf_counter_ns()`,
   starts the CLI with `subprocess.Popen` (stdin `/dev/null`, stdout and stderr pipes
   drained by threads), and reaps it with `os.wait4`. The wall time runs from just
   before `Popen` to `wait4` returning. User time, system time and `ru_maxrss` (peak
   resident set size, in bytes on macOS) come from that one child's rusage. The
   environment is exactly the parity tests' scrubbed environment
   (`airs_test_harness::child_environment`): `PATH`, `HOME`, `TMPDIR`,
   `PRISMA_AIRS_TENANTS_PATH`, `NO_COLOR=1`, `NO_PROXY`.
5. Every timed run is checked again: exit 0, the scenario's expected output, no fixture
   secret in either stream, no sandbox file changed outside `tmp/`, and the number of
   requests the fixture recorded.
6. Order: 3 untimed warm-up rounds, then 30 timed rounds. Each round runs every CLI
   once and rotates which goes first, so slow drift affects all CLIs alike. The batch
   scenario uses 5 timed rounds of 50 sequential scans per CLI. Its numbers are per
   batch: the sum of the 50 wall and CPU times, and the largest RSS.
7. Statistics: min, median, mean, nearest-rank p95, max and sample standard deviation.
   A ratio is the TypeScript median divided by the Rust median.
8. Spawn floor: the same helper starting `/usr/bin/true` takes 1.92 ms (median, p95
   2.30 ms). This fixed cost is included in every wall time and is not subtracted.
   Subtracting it would raise the short-command ratios: for `--version`,
   (93.3 − 1.9) / (6.27 − 1.9) is about 21x instead of 15x.
9. The `airs-cli+cache` variant runs the same TypeScript CLI with
   `NODE_COMPILE_CACHE=<sandbox>/tmp/node-compile-cache`. The CLI does not enable
   Node's compile cache itself, and the scrubbed environment does not set it, so the
   plain `airs-cli` rows have no compile cache. The verification and warm-up runs fill
   the cache before the timed runs.

### Live mode

`--live` times only read-only commands against one real tenant: `tenant read <name>
--output json`, `doctor --output json`, `runtime profiles list --output json`,
`runtime topics list --output json` and `runtime profiles get <first listed>
--output json`. It never scans. It runs only with `AIRS_RS_LIVE=1` and
`AIRS_E2E_TENANT=<name>`, and refuses otherwise
(`live::LiveBenchSettings`, unit-tested in `live_bench_refuses_without_the_opt_in`).
The flow is `live::run_live_bench`, which reuses the live tier's session
(`tests/live.rs`, TESTING §6.2):

- the real registry is read only to copy the selected entry into an isolated registry
  in a temp sandbox;
- both CLIs run with a cleared environment;
- every output is searched for the config's secrets in each encoded form and for
  JWT-shaped text;
- the real registry, the real config and the isolated registry are fingerprinted
  before the first run and re-checked after every run;
- the session's scan budget is 0.

There is 1 untimed warm-up per check and CLI, then 5 timed rounds by default (at most
20), alternating which CLI goes first. The output (`target/bench/live.json`) holds only
check labels, exit codes and durations: no tenant, profile or topic names, IDs or
bodies. The wall time is measured by polling the child every 1 ms. The rusage meter is
not used in live mode. `tests/live.rs::live_bench_self_test_against_fixture` runs the
whole flow against the fixture server and checks that the report is free of names,
IDs, paths and secrets.

## Environment

| Item | Value |
|---|---|
| Date (UTC) | 2026-10-17T09:30:35Z |
| Machine | Apple M5 Pro, 18 cores (6 Super, 12 Performance), 64 GiB, on AC power |
| OS | macOS 27.0 (26A428), Darwin 27.0.0 |
| airs-cli-rs | 0.1.0, built from commit `f2fbdf0` (`src/` unmodified); release profile `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`; binary sha256 `5a8fe410…41d2` |
| rustc | 1.99.0 (b940084d7 2026-09-28) |
| airs-cli | 7.2.1-forgejo.0, reference commit `5711012246d325f20dbe93b710dcc697a7f18a8a` |
| node | v24.21.0 |
| Meter | Python 3.13.15 (`-I`) |
| Background load | Not idle. Load average 7.2 (1 min) at the start and 9.7 at the end; the summed `ps` %CPU of all processes was 455 at the start and 189 at the end (100 = one busy core). |

Two earlier full runs on the same day gave the same picture. In the scenarios outside
the bulk dataset the ratios were within 1x of the ones below (for example 7.5–8.5x for
the json scan), and the medians were within about 20%. The bulk scenarios can be
compared only after the fixture fix described under Caveats. The run before that fix
measured the profiles walk at 2.3x.

## Reproduce

```sh
export PATH="$HOME/.cargo/bin:$PATH"
scripts/build-reference-cli.sh --verify     # the pinned TypeScript reference, node 24 on PATH
cargo build --release                       # the benchmark refuses an older binary
cargo run --release -p airs-test-harness --example bench -- --ts-compile-cache
```

Options: `--iterations N` (default 30), `--warmup N` (3), `--batch-size N` (50),
`--batch-iterations N` (5), `--filter TEXT`, `--name NAME` (output file name),
`--no-static`, `--show-output`, `--allow-stale`. `AIRS_BENCH_PYTHON` overrides the
interpreter (default: what `python3` on `PATH` resolves to). The run takes about 2.5
minutes and writes `target/bench/<name>.json` and `target/bench/<name>.md`.

Live mode (only the user runs it):

```sh
AIRS_RS_LIVE=1 AIRS_E2E_TENANT=<name> \
  cargo run --release -p airs-test-harness --example bench -- --live [--iterations 5]
```

## Loopback results

Medians of 30 runs (batch: 5 batches of 50 scans). "requests" is the number of requests
the fixture recorded per run, the same for every run.

| Scenario | Rust ms | TS ms | TS/Rust wall | TS+cache ms | TS+cache/Rust | Rust CPU ms | TS CPU ms | TS/Rust CPU | Rust RSS MiB | TS RSS MiB | TS/Rust RSS | requests rs / ts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `--version` | 6.27 | 93.3 | 15x | 79.1 | 13x | 3.74 | 111 | 30x | 6.2 | 105.6 | 17x | 0 / 0 |
| `--help` | 6.27 | 92.8 | 15x | 81.5 | 13x | 3.81 | 109 | 29x | 7.2 | 107.9 | 15x | 0 / 0 |
| `tenant list --output json` | 6.37 | 88.6 | 14x | 79.6 | 12x | 3.90 | 110 | 28x | 7.9 | 109.0 | 14x | 0 / 0 |
| `tenant read --output json` | 5.90 | 87.6 | 15x | 75.4 | 13x | 3.66 | 109 | 30x | 8.1 | 109.3 | 13x | 0 / 0 |
| `doctor --output json` | 13.7 | 123 | 9.0x | 112 | 8.2x | 10.6 | 150 | 14x | 38.5 | 143.5 | 3.7x | 3 / 5 |
| `runtime profiles list --output json` (1 page) | 13.2 | 104 | 7.9x | 91.5 | 6.9x | 10.3 | 130 | 13x | 38.6 | 117.5 | 3.0x | 2 / 2 |
| `runtime profiles list --all --output json` (2,000) | 41.0 | 140 | 3.4x | 129 | 3.2x | 30.4 | 223 | 7.3x | 48.0 | 171.1 | 3.6x | 21 / 21 |
| `runtime topics list --all --output json` (2,000) | 28.3 | 124 | 4.4x | 111 | 3.9x | 23.1 | 198 | 8.6x | 45.2 | 163.2 | 3.6x | 11 / 11 |
| `runtime profiles get profile-1000 --output json` (of 2,000) | 32.6 | 131 | 4.0x | 120 | 3.7x | 26.3 | 211 | 8.0x | 42.6 | 168.0 | 3.9x | 21 / 21 |
| `runtime scan` (pretty) | 13.5 | 101 | 7.5x | 89.5 | 6.6x | 10.4 | 125 | 12x | 38.4 | 117.3 | 3.1x | 1 / 1 |
| `runtime scan --output json` | 13.4 | 100 | 7.5x | 89.0 | 6.6x | 10.3 | 123 | 12x | 38.5 | 117.3 | 3.0x | 1 / 1 |
| `runtime scan --output json --response …` | 13.5 | 101 | 7.5x | 90.9 | 6.8x | 10.4 | 125 | 12x | 38.5 | 117.3 | 3.0x | 1 / 1 |
| 50 sequential `runtime scan --output json` (per batch) | 620 | 4,942 | 8.0x | 4,394 | 7.1x | 486 | 6,063 | 12x | 38.6 | 117.6 | 3.0x | 50 / 50 |

Wall-time spread (ms):

| Scenario | CLI | min | median | mean | p95 | max | stddev |
|---|---|---:|---:|---:|---:|---:|---:|
| `--version` | airs-cli-rs | 5.72 | 6.27 | 7.23 | 17.5 | 21.7 | 3.44 |
| | airs-cli | 84.4 | 93.3 | 99.4 | 164 | 179 | 21.6 |
| `--help` | airs-cli-rs | 5.74 | 6.27 | 6.38 | 7.01 | 8.11 | 0.42 |
| | airs-cli | 88.0 | 92.8 | 94.2 | 107 | 110 | 5.31 |
| `tenant list` | airs-cli-rs | 5.77 | 6.37 | 6.61 | 8.22 | 8.55 | 0.70 |
| | airs-cli | 85.1 | 88.6 | 91.0 | 108 | 109 | 6.30 |
| `tenant read` | airs-cli-rs | 5.15 | 5.90 | 5.90 | 6.49 | 6.70 | 0.39 |
| | airs-cli | 84.3 | 87.6 | 88.1 | 94.1 | 94.5 | 2.10 |
| `doctor` | airs-cli-rs | 12.9 | 13.7 | 13.9 | 15.8 | 18.3 | 1.03 |
| | airs-cli | 119 | 123 | 125 | 132 | 155 | 6.43 |
| profiles list, 1 page | airs-cli-rs | 12.4 | 13.2 | 13.3 | 14.0 | 16.5 | 0.76 |
| | airs-cli | 101 | 104 | 105 | 118 | 123 | 5.10 |
| profiles list `--all` (2,000) | airs-cli-rs | 39.9 | 41.0 | 41.7 | 45.1 | 49.2 | 2.00 |
| | airs-cli | 135 | 140 | 144 | 165 | 179 | 9.56 |
| topics list `--all` (2,000) | airs-cli-rs | 27.5 | 28.3 | 28.4 | 29.5 | 29.9 | 0.53 |
| | airs-cli | 119 | 124 | 124 | 129 | 134 | 3.05 |
| profiles get (of 2,000) | airs-cli-rs | 31.8 | 32.6 | 32.9 | 36.0 | 37.6 | 1.19 |
| | airs-cli | 127 | 131 | 132 | 139 | 165 | 6.62 |
| scan, pretty | airs-cli-rs | 12.9 | 13.5 | 13.6 | 14.4 | 16.1 | 0.56 |
| | airs-cli | 98.2 | 101 | 102 | 111 | 119 | 4.54 |
| scan, json | airs-cli-rs | 13.1 | 13.4 | 13.5 | 14.0 | 14.1 | 0.25 |
| | airs-cli | 96.8 | 100 | 101 | 105 | 105 | 2.26 |
| scan, prompt + response | airs-cli-rs | 12.8 | 13.5 | 13.5 | 14.3 | 15.0 | 0.43 |
| | airs-cli | 97.1 | 101 | 102 | 108 | 115 | 3.44 |
| 50 scans (per batch, n = 5) | airs-cli-rs | 605 | 620 | 618 | 633 | 633 | 11.0 |
| | airs-cli | 4,901 | 4,942 | 4,954 | 5,028 | 5,028 | 57.2 |

User and system CPU (medians), the compile-cache rows and every raw sample are in
`target/bench/loopback.json`. The TypeScript CPU time is higher than its wall time
because V8 and libuv use helper threads.

## Static footprint

| Item | airs-cli-rs | airs-cli |
|---|---:|---:|
| Program | 9.63 MiB binary (Mach-O arm64, symbols stripped) | 0.87 MiB `dist/` (5 files) |
| Distribution archive | 3.88 MiB (`target/dist/airs-cli-rs-0.1.0-aarch64-apple-darwin.tar.gz`) | n/a (npm package) |
| Runtime | none; links only macOS system libraries (Security, SystemConfiguration, CoreFoundation, libiconv, libSystem) | node v24.21.0, 116.47 MiB binary |
| Production dependencies | compiled in: 181 crates in the normal dependency graph (`cargo tree -e normal`); 229 packages in `Cargo.lock` including dev and build | 95 npm packages, 80.81 MiB, 3,192 files (`pnpm list --prod`) |
| All installed dependencies of the build checkout | n/a | `node_modules/`: 226.81 MiB, 11,031 files, 355 packages (includes dev dependencies) |
| Install estimate | 9.63 MiB | 198.15 MiB (node + `dist` + production dependencies) |

The largest production packages are `@cdot65/prisma-airs-sdk` (26 MiB on disk),
`pdf-lib` (23 MiB), `@img/sharp-libvips-darwin-arm64` (17 MiB), `zod` (5 MiB) and `docx`
(3.4 MiB). `pdf-lib`, `docx` and `sharp` are imported only by the TypeScript DLP
document generators (`src/dlp/`), a feature outside release 1. A user who already has
node installed for other reasons does not pay its 116 MiB for `airs-cli` alone.

## Caveats

- **Loopback isolates CLI overhead.** The fixture answers from memory on
  `127.0.0.1` over plain HTTP. A real tenant adds network latency and TLS to every
  request, for both CLIs. For commands dominated by network time the absolute saving
  per invocation (about 87 ms for a scan here) is the useful number, and the ratio
  shrinks. TLS handshake cost was not measured: the two CLIs use different TLS
  stacks.
- **The fixture's own time is in every number.** The fixture server runs in the
  benchmark process. During this work its `latest=true` paging was made linear and it
  stopped cloning the whole dataset per request. Before that change it spent about
  25 ms per page on the 2,000-profile dataset, which inflated both CLIs' `--all` times
  equally. Its remaining per-request cost is the same for both CLIs.
- **doctor does different work.** The TypeScript doctor runs 11 checks and the Rust
  doctor 7 (D19). On the fixture, `Node.js version` passed without a request,
  `Typesafe credentials` and `Typesafe API` were skipped (the fixture config has no
  Typesafe credentials; no request was made), and `AI Gateway API` passed after two
  extra requests (`POST /oauth/token`, `GET /ai_gw/v2/workspaces`, both answered by
  the fixture). That is 5 requests for TypeScript against 3 for Rust. The 7 shared
  checks passed on both.
- **Output formats.** Management and tenant scenarios use `--output json` on both
  CLIs, because the 0.1 `airs-cli-rs` measured here wrote JSON only (D4, retired in
  0.2) while the TypeScript default is a table. The TypeScript scan always prints the pretty verdict, even with
  `--output json` (D5), so the json scan rows compare Rust JSON with TypeScript pretty
  output.
- **Node compile cache.** With `NODE_COMPILE_CACHE` set, the TypeScript CLI was
  9–14 ms faster per invocation (about 10–15%). The ratios with the cache are in
  the `TS+cache` columns. The CLI does not enable the cache itself.
- **Warm runs only.** All timed runs follow a verification run and 3 warm-ups, so
  the file cache is warm and, for the cache variant, the compile cache is full. The
  first invocation after a reboot or cache eviction was not measured.
- **Peak RSS** is `ru_maxrss`: the resident peak of the process, including touched
  pages of the node binary or the Rust binary. It is not unique heap use.
- **Measurement overhead.** The Python helper's spawn floor (1.92 ms) is in every
  wall time; see Method item 8. stdout and stderr are pipes, as in the harness.
- **Background load.** The machine was running other work during the run (see
  Environment). Its effect shows in the long tails (for example the `--version` p95 on
  both CLIs). The medians agreed with earlier full runs on the same day.
- **Single machine.** One Apple Silicon Mac, one node version (24), one build of each
  CLI.

## Live (read-only) results

Two runs on 2026-10-17, from a home network, against one production tenant: 5 and then
10 iterations per CLI, in rotating order. The machine and the binary are the same as
for the loopback run. Times are milliseconds.

The 10-iteration run:

| Check | CLI | exits | min | median | mean | p95 | max |
|---|---|---|---:|---:|---:|---:|---:|
| tenant read --output json | airs-cli-rs | 0x10 | 3.96 | 5.32 | 4.80 | 5.35 | 5.35 |
| tenant read --output json | airs-cli | 0x10 | 76.9 | 78.4 | 78.5 | 80.9 | 80.9 |
| doctor --output json | airs-cli-rs | 0x10 | 874 | 4807 | 4275 | 5682 | 5682 |
| doctor --output json | airs-cli | 0x10 | 1318 | 1411 | 1417 | 1516 | 1516 |
| runtime profiles list --output json | airs-cli-rs | 0x10 | 693 | 747 | 745 | 787 | 787 |
| runtime profiles list --output json | airs-cli | 0x10 | 745 | 777 | 787 | 836 | 836 |
| runtime topics list --output json | airs-cli-rs | 0x10 | 657 | 701 | 704 | 766 | 766 |
| runtime topics list --output json | airs-cli | 0x10 | 702 | 736 | 745 | 789 | 789 |
| runtime profiles get <first> --output json | airs-cli-rs | 0x10 | 709 | 780 | 772 | 843 | 843 |
| runtime profiles get <first> --output json | airs-cli | 0x10 | 789 | 834 | 835 | 905 | 905 |

Medians from the 5-iteration run:

| Check | airs-cli-rs | airs-cli |
|---|---:|---:|
| tenant read | 5.34 | 79.6 |
| doctor | 854 | 1465 |
| profiles list | 732 | 818 |
| topics list | 674 | 826 |
| profiles get | 758 | 855 |

What the live numbers show:

- **Local commands keep the full gap.** `tenant read` was 5.3 ms against 78–80 ms
  (15x).
- **Network-bound commands are dominated by the service.** A management read is an
  OAuth token request (about 350–400 ms) plus one or more API requests (about
  220–250 ms each). The Rust CLI saves a fairly constant 30–100 ms per command, which
  is the process start-up and runtime overhead also seen on loopback. In ratio terms
  that is 1.0–1.2x.
- **Do not read `doctor` as a speed result.** When the Rust doctor runs back to back,
  the Scanner API probe's `GET /v1/scan/results` is answered with HTTP 429. Both CLIs
  were timed with per-request instrumentation, alternating Rust and TS doctors:
  - The first Rust doctor in a quiet period took 0.86 s, with all three requests
    answered 200 in 180–400 ms.
  - Later ones got 429 on the scanner probe. The SDK retried the 429 up to four times
    with backoff until a 200 arrived or the 5 s probe budget ran out, so the run took
    4.9–6.1 s.
  - The TS doctor does not retry a 429 and reports it as a pass (D20), so it stayed at
    1.3–1.8 s, with one 3.2 s run.
  - Every run of both CLIs exited 0. A persistent 429 is a warning in the Rust doctor
    (DESIGN §9), not a failure.
  - The Rust median of 4.8 s in the 10-iteration run therefore measures the
    rate-limit retry policy, not CLI speed. A preflight that does not retry would
    report the warning at once (next section).

## Doctor and rate limits

Up to 0.1, the Scanner API and Management OAuth probes ran with the SDK's normal retry
policy inside one 5 s budget, and that policy retries 429/502/503/504. Under a rate
limit, the doctor therefore spent up to the whole budget waiting before it warned.
That was slow, and the retries added load to an endpoint that had already said "slow
down".

Since 0.2 the probes make one attempt each (`RequestOptions::with_retries(0)`, D49),
so a 429 or 5xx is classified at once. The rate-limited case therefore costs one
request and returns in about the time of an unthrottled doctor (about 0.9 s live). The
live numbers above predate this change.
