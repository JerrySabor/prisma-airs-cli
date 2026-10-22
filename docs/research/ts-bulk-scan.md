# Spec: TS `airs-cli` bulk scanning (M5): `runtime bulk-scan` and `runtime resume-poll`

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0), which pins `@cdot65/prisma-airs-sdk` 0.34.0 and commander 14.0.3. Citations:
  - `runtime.ts:<line>` is `src/cli/commands/runtime.ts`.
  - `state.ts:<line>` is `src/cli/bulk-scan-state.ts`; `lock.ts:<line>` is `src/cli/bulk-scan-lock.ts`; `parse-input.ts:<line>` is `src/cli/parse-input.ts`.
  - `svc:<line>` is `src/airs/runtime.ts` (`SdkRuntimeService`, `submitBatch`, `pollBatch`, `formatResultsCsv`).
  - `ui.ts`, `common.ts` are `src/cli/renderer/{ui,common}.ts`; `deprecated-flags.ts`, `program.ts` are under `src/cli/`; `client-options.ts`, `credentials.ts`, `loader.ts`, `schema.ts` are under `src/config/`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js`.
  - Docs: `docs-site/docs/cli/runtime/bulk-scan.md` (`bulk-doc`), `resume-poll.md` (`resume-doc`), `docs-site/docs/runtime/scanning.md`.
  - TS tests: `tests/unit/cli/bulk-scan-state.spec.ts` (`state-spec`), `tests/unit/cli/bulk-scan-lock.spec.ts` (`lock-spec`), `tests/integration/cli/runtime-bulk-scan.spec.ts` (`int-spec`). The integration spec mocks `Scanner` (`int-spec:7-21`), so it never exercises the SDK's schema checks, UUID checks or HTTP classification. §6.6 and §7 show where the real SDK behaves differently from those mocks.
- How behaviour was captured: the reference build (`dist/cli/index.js`, node v24.21.0) ran against a stateful loopback stub of the three async scan routes, in a fresh sandbox per scenario. The probe tooling is in this session's scratchpad under `m5probe/`: `server.mjs` (stub), `lib.sh` (sandbox and runner), `guard.mjs`, `fstrace.mjs`, `routes.cjs` and the scenario scripts `s_*.sh`.
  - Each sandbox has `home/`, `state/tenants.json` (a TS registry, `version: 1`, one active tenant `t`, TSG `100`), `configs/t.json` (0600; fake `airsApiKey: FAKE-APIKEY-100`, `mgmtClientSecret: FAKE-SECRET-100`, `airsApiEndpoint` on the stub, `dataDir` inside the sandbox unless the scenario tests the default), `cwd/`, `tmp/` and `data/`.
  - Every run used `env -i` with `PATH=/usr/bin:/bin`, `HOME`, `TMPDIR`, `XDG_STATE_HOME`, `XDG_CONFIG_HOME` and `PRISMA_AIRS_TENANTS_PATH` inside the sandbox, `NO_COLOR=1` (or `FORCE_COLOR=1` for the colour capture), and `PANW_AI_SEC_API_ENDPOINT` / `PANW_MGMT_ENDPOINT` set to a trap path on the stub. The trap was never hit: `runtimeInitOptions` passes the tenant's endpoint explicitly (`client-options.ts:89-97`), so the SDK's `PANW_AI_SEC_API_ENDPOINT` fallback (`SDK:261`) does not apply. The SDK still reads `PANW_AI_SEC_TIMEOUT_MS` (`SDK:10095`, default 60 s per attempt) and `PANW_AI_SEC_DEBUG*` (`SDK:10001`, `:10141`) from the environment.
  - Every node run preloaded `guard.mjs`, which replaces `globalThis.fetch` and `dns.lookup` and refuses any host other than `127.0.0.1`. No refusal was recorded. `fstrace.mjs` wraps `fs/promises` (`writeFile`, `rename`, `chmod`, `mkdir`, `rm`, `link`, `readFile`, `realpath`) and logs each call, which gives the write sequences in §8.4.
  - Interruptions were driven with `kill -INT` / `kill -TERM` on the node process; the concurrent-lock case ran a second CLI while the first was polling.
- No real tenant or credential file was read. No host other than loopback was contacted. Sandbox paths are shown as `<SB>`. Captured stdout and stderr are shown as JSON strings.

## 1. Command surface (help verified)

| Command | Registration | Arguments and options |
|---|---|---|
| `runtime bulk-scan` | `runtime.ts:279-306` | `--profile <name>` (required, `Security profile name`), `--file <file>` (`Input file — .csv (extracts prompt column) or .txt (one per line)`; required by the action, not by commander), `--output-file <file>` (`Output CSV file path`), `--session-id <id>` (`Session ID for grouping scans in AIRS dashboard`), `--batch-size <n>` (`Prompts per sequential submit/poll batch`, default `"25"`). Hidden deprecated aliases `--input <file>` → `--file` and `--output <file>` → `--output-file` (`runtime.ts:295-306`) |
| `runtime resume-poll <stateFile>` | `runtime.ts:906-915` | `--output-file <file>` (`Output CSV file path`). Hidden deprecated alias `--output <file>` → `--output-file` |

`runtime bulk-scan --help`, byte-exact (stdout, exit 0):

```
Usage: airs-cli runtime bulk-scan [options]

Scan multiple prompts via the async AIRS API

Options:
  --batch-size <n>      Prompts per sequential submit/poll batch (default: "25")
  --file <file>         Input file — .csv (extracts prompt column) or .txt (one
                        per line)
  -h, --help            display help for command
  --output-file <file>  Output CSV file path
  --profile <name>      Security profile name
  --session-id <id>     Session ID for grouping scans in AIRS dashboard

Examples:
  $ airs-cli runtime bulk-scan --profile prod-guard --file prompts.csv
  $ airs-cli runtime bulk-scan --profile prod-guard --file prompts.txt --output-file results.csv
  $ airs-cli runtime bulk-scan --profile prod-guard --file prompts.csv --session-id nightly-run

```

`runtime resume-poll --help`, byte-exact:

```
Usage: airs-cli runtime resume-poll [options] <stateFile>

Resume polling for a previously submitted bulk scan

Options:
  -h, --help            display help for command
  --output-file <file>  Output CSV file path
```

In `runtime --help` the entries are `bulk-scan [options]` / `Scan multiple prompts via the async AIRS` / `API` and `resume-poll [options] <stateFile>` / `Resume polling for a previously submitted` / `bulk scan` (commander wraps at 80 columns). The docs page says `Safely continue a bulk scan from item-level state` (`resume-doc:9`); the code's description wins.

**Deprecated aliases.** `--input p.txt` works and prints `  ⚠ --input is deprecated and will be removed in v4 — use --file` (yellow, stderr, not quiet-suppressed, `deprecated-flags.ts:42-46`) before the banner; the canonical flag wins when both are given. `--output <file>` is unreachable: the root parser consumes every `--output` (`docs/research/ts-cli-shell.md` §3), and bulk-scan is not a read command, so the root value is never validated (`program.ts:162-175`). Observed: `runtime bulk-scan --output json --profile p --file p.txt --output-file j.csv` behaves exactly like the run without `--output json` (exit per results, the CSV at `j.csv`).

**No output format.** Neither command has a format option. The data product is the CSV file; the terminal shows a status banner (stderr) and a key/value summary (stdout).

## 2. Validation order and usage errors

`bulk-scan` (`runtime.ts:307-323`):

1. commander: unknown options, missing option values and a missing `--profile` exit **1** with `error: …` on stderr (`error: required option '--profile <name>' not specified`, `error: option '--batch-size <n>' argument missing`, `error: unknown option '--bogus'`).
2. Deprecated alias resolution (`runtime.ts:308`).
3. `--file` missing → usage error `--file <file> is required` (exit 2, before the tenant).
4. `--batch-size` → `parsePositiveInteger` (`runtime.ts:166-172`): must match `^[1-9]\d*$` and be a safe integer, else `--batch-size must be a positive integer` (exit 2, before the tenant). Verified rejections: `0`, `-1`, `1.5`, `abc`, `007` (leading zero), `9007199254740992`.
5. `loadConfig({})` (tenant selection, registry, TSG pin; `loader.ts:84-92`). Failure is `fail` (exit 1), e.g. `✗ Error: No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'`.
6. `assertScannerCredentials` (`credentials.ts:65-70`): `✗ Error: Scanner credentials are not configured (airsApiKey or airsApiToken). Run 'airs-cli tenant set t <key>' for airsApiKey (secrets prompt hidden, or use --stdin)` (exit 1).
7. `readFile(opts.file, 'utf-8')` (relative to the cwd). Raw Node text: `✗ Error: ENOENT: no such file or directory, open 'nope.txt'`, `✗ Error: EISDIR: illegal operation on a directory, read` (exit 1).
8. `parseInputFile` (§3). CSV without a `prompt` header: `✗ Error: No "prompt" column found in CSV header` (exit 1).
9. Zero prompts → usage error `No prompts found in input file` (exit **2**, after the tenant read and the file read).
10. Job setup, state, lock and output (§4), then the scanner client: `new SdkRuntimeService(runtimeInitOptions(config))` (`runtime.ts:354`). An SDK `init` failure (e.g. an over-long key, `SDK:240-275`) therefore happens after the state file, the lock and the empty output exist.

There is no client-side check of the profile name, the session ID, prompt sizes or prompt count. The SDK checks the request body only when it serialises the submission (§7, row "pre-dispatch validation").

`resume-poll` (`runtime.ts:916-932`): commander (`error: missing required argument 'stateFile'`, exit 1) → `fs.promises.realpath(stateFile)` (`✗ Error: ENOENT: no such file or directory, realpath 'nope.json'`) → **lock** (§9) → `loadConfig` → scanner credentials → `loadBulkScanState` (§8.5) → `new SdkRuntimeService` → the state's `outputFile` is replaced by `resolvePath(--output-file ?? state.outputFile)` and saved. The lock is therefore created and removed even when the tenant is missing (observed: `No tenant selected` after 5 lock-file operations).

## 3. Input parsing (`parse-input.ts`)

The file is decoded as UTF-8 with replacement: invalid bytes become U+FFFD (a Latin-1 `caf\xe9` was sent as `"caf�"`). A BOM is not stripped by the decoder.

**Choice of parser** (`parse-input.ts:8-17`): `/\.csv$/i` on the path selects CSV (`UPPER.CSV` is CSV). Everything else, including `.txt` and extensionless files, is line mode.

**Line mode** (`parse-input.ts:13-16`): split on `\n`, JavaScript `trim()` each line, drop empty lines. `trim` removes JS whitespace, which includes `\r`, `\t`, U+00A0, U+2028 and U+FEFF, so CRLF files and a leading BOM work. Duplicates are kept and scanned separately. Control characters other than whitespace are kept and sent verbatim (`a\u0007b\u001b[31mred` was submitted as is).

**CSV mode** (`parse-input.ts:20-125`), a minimal RFC 4180 reader:
- A record ends at `\n`, `\r\n` or a bare `\r` (outside quotes).
- A field that starts with `"` runs to the next unpaired `"`; `""` inside is a literal quote; CR, LF and commas inside quotes are kept (`"a\r\nb"` gives `a\r\nb`). An **unterminated quote runs to end of file** silently (`"abc\ndef\n` gives `abc\ndef` after trim).
- After a closing quote, a comma is consumed if present; any other text starts a **new field**: `"ab"cd,1` is three fields `ab`, `cd`, `1`, which shifts the later columns.
- An unquoted field runs to the next comma or line break, so ` "a,b",1` is ` "a`, `b"`, `1` (the prompt becomes `"a` after trim).
- Records that are empty, or one empty field, are dropped (`parseCsvRows`, `:47`). So blank lines anywhere, including before the header, are skipped.
- The first remaining record is the header. The prompt column is the **first** header field whose `trim().toLowerCase()` is `prompt` (` PROMPT ` and `"prompt"` match; with `prompt,prompt` the first wins). The BOM case works because `trim` strips U+FEFF.
- Each data row contributes `row[promptIdx]?.trim() ?? ''`; empty values are dropped (a short row, `,` and `""` contribute nothing). Other columns are ignored.
- No header row (empty file): zero prompts → §2 step 9 (exit 2). Header only: the same.

Verified results (prompts as submitted):

| File | Content | Prompts |
|---|---|---|
| `bom.csv` | `﻿prompt\nhi\n` | `["hi"]` |
| `crlf.csv` | `prompt\r\na\r\nb\r\n` | `["a","b"]` |
| `cr.csv` | `prompt\ra\rb` | `["a","b"]` |
| `multiline.csv` | `prompt,x\n"line1\nline2",1\n` | `["line1\nline2"]` |
| `quoted-crlf.csv` | `prompt\r\n"a\r\nb"\r\n` | `["a\r\nb"]` |
| `escaped.csv` | `prompt\n"He said ""hi"""\n` | `["He said \"hi\""]` |
| `unterminated.csv` | `prompt\n"abc\ndef\n` | `["abc\ndef"]` |
| `afterquote.csv` | `prompt,x\n"ab"cd,1\n` | `["ab"]` |
| `spacequote.csv` | `prompt,x\n "a,b",1\n` | `["\"a"]` |
| `shortrow.csv` | `id,prompt\n1\n2,two\n` | `["two"]` |
| `hdrspace.csv` | `id, PROMPT \n1,  padded  \n` | `["padded"]` |
| `blankrows.csv` | `prompt\n\n\na\n,\n""\n   \n` | `["a"]` |
| `emptyfirst.csv` | `\nprompt\na\n` | `["a"]` |
| `crlf.txt` | `a\r\n\r\n b\t\r\n` | `["a","b"]` |
| `bom.txt` | `﻿first\nsecond` | `["first","second"]` |
| `nbsp.txt` | ` x \n y\n` | `["x","y"]` |
| `dup.txt` | `same\nsame\n` | `["same","same"]` |
| `latin1.txt` | bytes `63 61 66 e9 0a` | `["caf�"]` |
| `nocol.csv` | `id,text\n1,hi\n` | `✗ Error: No "prompt" column found in CSV header`, exit 1 |
| `hdr.csv`, `empty.csv`, `blank.txt` | header only / empty / whitespace lines | `✗ No prompts found in input file`, exit 2 |

The docs describe the same format (`bulk-doc:27-57`). The file size and the prompt sizes are unbounded on the client.

## 4. Job setup (`runtime.ts:325-360`)

- **Session ID**: `--session-id` as given, else `prisma-airs-cli-bulk-${Date.now().toString(36)}` (e.g. `prisma-airs-cli-bulk-mvd0d79b`). It is sent on every scan object and stored in the state. `--session-id ""` does not fall back (`??` keeps `""`): verified, the banner shows `Session:  ` (empty), the state stores `"sessionId": ""`, and `submitBatch` omits `session_id` from the body (`svc:255`, falsy check), so the body keys are only `ai_profile`, `contents`.
- **Output path**: `resolvePath(--output-file ?? `${profile.replace(/\s+/g, '-')}-bulk-scan.csv`)`, relative to the cwd. Only whitespace runs are replaced, so `/` and `..` in a profile name are path syntax. Observed: `--profile "../esc dir/x"` wrote `<SB>/esc-dir/x-bulk-scan.csv`, **outside the cwd**, creating the directory `esc-dir` (`writeBulkResults` runs `mkdir -p`), before the first POST (which then failed with 400).
- **State directory**: from the tenant key `dataDir` (default `~/.prisma-airs/runs`, `schema.ts:55`; `~` expanded with `os.homedir()`, `loader.ts:13-15`): `dirname(dataDir)/bulk-scans` when `basename(dataDir) === 'runs'`, else `dataDir/bulk-scans` (`runtime.ts:329-333`). Verified: no `dataDir` → `$HOME/.prisma-airs/bulk-scans/`; `dataDir: "<SB>/custom"` → `<SB>/custom/bulk-scans/`; `dataDir: "~/x/runs"` → `$HOME/x/bulk-scans/`. `XDG_STATE_HOME` plays no part.
- **State file name**: `<createdAt with ':' and '.' replaced by '-'>-<uuid v4>.bulk-scan.json`, e.g. `2026-10-17T23-08-58-751Z-319c7426-3373-4d53-86cf-192e2ef1ccda.bulk-scan.json` (`state.ts:148-150`). The docs show `…-bulk-scan.json` (`bulk-doc:73`); the code uses a dot.
- **Order of side effects** (all before the first request):
  1. `saveBulkScanState(state, stateDir)` creates the state with every item `pending` (§8).
  2. `acquireBulkScanLock(statePath)` (§9).
  3. `writeBulkResults(outputPath, [])`: the output becomes the header-only projection, **replacing any existing file** (`int-spec:492-525` pins this as intended TS behaviour).
  4. The scanner client is built, then the banner is printed (§12).
- A failure at step 3 (e.g. the output path is a directory: `✗ Error: EISDIR: illegal operation on a directory, rename '<SB>/cwd/d.csv.tmp-<pid>-<uuid>' -> '<SB>/cwd/d.csv'`) or step 4 leaves an orphan all-`pending` state file. `resume-poll` on it would submit every prompt.

## 5. Batching

- **Logical batches** of `batchSize` (default 25) over the items in input order (`runtime.ts:362-363`). `Batches: ${Math.ceil(prompts / batchSize)}`.
- Within a logical batch, **SDK chunks** of at most `SDK_ASYNC_BATCH_SIZE` = `MAX_NUMBER_OF_BATCH_SCAN_OBJECTS` = 20 (`svc:18`, `SDK:28`) are submitted one after another (`runtime.ts:366-394`). Every chunk of the logical batch is submitted **before** any polling.
- Then each receipt (one per chunk) is polled to completion, sequentially, in the order of `submittedBatches(logicalBatch)` (`runtime.ts:87-108`: items grouped by `scanId` in first-seen order, entries sorted by index). Only then does the next logical batch start.
- Verified sequences: 45 prompts, batch 25 → `P[0..19] P[20..24] G G P[25..44] G`; 3 prompts, `--batch-size 2` → `P[0,1] G P[2] G`; `int-spec:840-885` pins `submit:0, poll:a, submit:5, poll:b` for 7 prompts at size 5.
- `resume-poll` keeps the stored `batchSize` (`runtime.ts:967-1009`): per logical batch it polls the already-submitted receipts, then submits that batch's `pending` items in chunks of 20, then polls again (`int-spec:887-956`: `poll:0, submit:2,3, poll:2, submit:4,5, poll:4`).

## 6. The async request sequence

### 6.1 Submit (`svc:229-289`, `SDK:10410-10435`)

`POST <airsApiEndpoint>/v1/scan/async/request`, one per chunk. Body (raw bytes captured, schema key order from the SDK's Zod output):

```
[{"req_id":0,"scan_req":{"session_id":"s1","ai_profile":{"profile_name":"p"},"contents":[{"prompt":"a"}]}},{"req_id":1,"scan_req":{"session_id":"s1","ai_profile":{"profile_name":"p"},"contents":[{"prompt":"b BLOCK"}]}},…]
```

- `req_id` is the item's **global input index** (0-based, stable across chunks, batches and resumes), not the position in the chunk.
- Headers: `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `service-name: api`, `Content-Type: application/json`, `x-pan-token: <airsApiKey>` (and/or `Authorization: Bearer <airsApiToken>`), `x-payload-hash: <HMAC-SHA256(body, apiKey)>` (`SDK:9564-9590`).
- SDK retries are off (`NO_SDK_RETRIES = {numRetries: 0}`, `svc:23`): exactly one HTTP attempt per call, for every status and transport error. The tenant's `airsNumRetries` has no effect.
- The CLI retries only a **definite 429** (`failureKind === 'http' && statusCode === 429`, `svc:77-80`), up to `maxRetries` = 5 (6 attempts). The delay is `retryAfterMs` when it is a finite number ≥ 0 (the SDK fills it from the `Retry-After` header, seconds or HTTP date, else from a JSON body `retry_after: {interval, unit}`; `SDK:9726-9770`, `:9841-9846`), otherwise `10000 * 2^(attempt-1)` ms (10, 20, 40, 80, 160 s). **There is no cap.** Verified: `Retry-After: 1` waited 1 s; a past HTTP date gave 0 s.
- Each retry prints the status line `  ⚠ Rate limited while submitting — retry <n> in <(delayMs/1000).toFixed(0)>s...` (quiet-suppressed).
- Receipt: `{received, scan_id, report_id?, source?}` (`SDK:1726-1731`). Every item of the chunk gets `status: submitted`, `scanId = receipt.scan_id`, `receiptReportId = receipt.report_id` (omitted when absent).

### 6.2 Poll (`svc:291-466`, `SDK:10460-10490`)

`GET <airsApiEndpoint>/v1/scan/results?scan_ids=<one scan id>`. The SDK requires 1–5 UUIDs (`SDK:9556`); the CLI always sends exactly one. No body, no content type, no hash.

Loop, per receipt, until every entry is resolved:
1. Query. On error: a **rate-limit error** with `retryLevel < 5` sleeps and repeats (no poll is counted); anything else throws. "Rate limit" here is `isRateLimitError` (`svc:68-75`): `statusCode === 429` **or an error message containing `rate limit`, `rate_limit` or `429`** (case-insensitive), so a 500 whose server message mentions "rate limit" is retried. The delay is `retryAfterMs` (uncapped) or `10000 * 2^(retryLevel-1)`. Status line `  ⚠ Rate limited — retry <n> in <s>s...`.
2. For each row (server order; `scan_id` defaults to the receipt's):
   - **Batch-level terminal row** (no `req_id`, status `failed`/`complete`/`completed`, same scan): `failed` resolves every unresolved entry as failed (`AIRS async scan failed`); complete/completed records a report ID (`row.result.report_id` ?? `row.report_id` ?? the receipt's) for the report fallback; none available throws `AIRS result correlation failed for scan <id>: terminal row has no request or report ID`.
   - A row whose `(scan_id, req_id)` is not an unresolved entry is ignored (other scans, unknown `req_id`, duplicates).
   - `status` `failed` (case-insensitive) → a failed result (`failedBulkResult`, `svc:184-201`).
   - `complete`/`completed` **with** `result` → `scanResponseToResult(result)` (§6.4). A nested `result.scan_id` that differs throws `AIRS result correlation mismatch: nested scan ID <a> does not match <b>`.
   - Any other status (`pending`, unknown words) or a complete row without `result` is not progress.
   - Every newly resolved result is passed to `onProgress` **one at a time** and awaited (state save + full CSV rewrite each time, §8.4).
3. **Report fallback** (`svc:407-445`): `GET /v1/scan/reports?report_ids=<id>` (1–5 IDs, `SDK:10511-10536`), same rate-limit handling. Each report must have the receipt's scan ID and the expected report ID, else `AIRS report correlation mismatch for scan <id>, request <reqId>`; reports for unresolved `req_id`s become `threatReportToResult` (§6.4). Verified with a batch-level `complete` row: `G:results G:reports`, and a report detector action `quarantine` became a failed row `Unknown AIRS action in threat report: quarantine`.
4. After a successful poll `retryLevel` decreases by 1 (so the five-retry budget refills).
5. **No-progress bound**: a successful poll that resolves nothing increments `noProgressPolls`; progress resets it. At 120 it throws `AIRS polling made no progress after 120 polls for scan <id>` (`svc:449-458`). Not captured (it takes ~10 minutes at the fixed interval); verified by reading.
6. If entries remain, sleep `intervalMs` = 5000 ms (`svc:19`; bulk-scan passes `undefined`, so the default applies; `svc:460-462`). The first poll follows the submission immediately. Verified: one `pending` round made the run take ~6 s (`G G`).

`queryByScanIds` validates the response (`ScanIdResultSchema`, `SDK:1735-1741`): a `result` object must satisfy the full `ScanResponseSchema` (`report_id`, `scan_id`, `category`, `action`, `timeout`, `error`, `errors` required, `SDK:1696-1719`), or the whole poll throws `AISEC_RESPONSE_VALIDATION:Response did not match schema: …`. The TS integration fixtures (`int-spec:965-984`) omit those fields; they pass only because `Scanner` is mocked.

### 6.3 Errors that end polling

Any thrown error (a non-rate-limit HTTP error, 5 exhausted rate limits, a transport error, a schema error, a correlation error, the no-progress bound) propagates out of `pollBatch` and the command (§11 for resume). Items stay `submitted`; results resolved before the error were already checkpointed by `onProgress`. Verified: poll 500 → exit 1, items `submitted`; six 429s → five retry lines, then `✗ Error: AISEC_CLIENT_SIDE_ERROR:stub status 429` / `    HTTP 429`, items `submitted`.

**Receipt with a non-UUID scan ID.** A 2xx receipt `{"scan_id":"not-a-uuid"}` is checkpointed as `submitted`, then every poll fails before sending: `✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid scan_id: not-a-uuid` (exit 1). Resume repeats this forever; the accepted prompts can never be recovered.

**Retry-After overflow.** A poll 429 with `Retry-After: 3000000` printed `⚠ Rate limited — retry 1 in 3000000s...`, then Node's `TimeoutOverflowWarning: 3000000000 does not fit into a 32-bit signed integer. Timeout duration was set to 1.` on stderr, and retried at once. Values below 2^31 ms (~24.8 days) are slept in full.

### 6.4 Result normalisation (`svc:82-201`)

From a per-request `result` (`scanResponseToResult`):
- `detections`: only the eight `RUNTIME_DETECTION_KEYS` (`topic_violation, injection, toxic_content, dlp, url_cats, malicious_code, source_code, agent`) whose `prompt_detected` value is a boolean. `triggered` = any of them `true`.
- `action` = lower-cased `result.action` when `allow`/`block`, else `failed`. `failed` also when `error === true` or `timeout === true`.
- failed → `category: "error"` and `error` = the `errors[]` entries joined (`feature: status: content_type`, `; `-separated) or `AIRS scan timed out` / `AIRS scan failed` / `Unknown AIRS action: <action or missing>`; otherwise `category` = `result.category ?? 'unknown'`.
- `scanId` = the row's scan ID; `reportId` = `result.report_id ?? ''`.

From a threat report (`threatReportToResult`): each `detection_results[]` entry maps `detection_service` through `REPORT_DETECTION_KEYS` (`svc:37-53`; unknown names are kept as keys); a detector fires on action `block` or verdict `malicious|unsafe|violation|detected`. Any `block` → `block`; else any detector action other than `allow`/empty → `failed` (`Unknown AIRS action in threat report: <a>`); else `allow`. Category `malicious` if triggered, `benign` otherwise, `error` when failed.

A failed row (`failedBulkResult`) has `reportId: ""`, `category: "error"`, `triggered: false`, `detections: {}`, `error: "AIRS async scan failed"`.

Verified rows (`s_poll.sh actions`): `allow/benign`, `block/malicious`, `failed/error AIRS scan timed out` (timeout), `failed/error dlp: error: prompt` (`error:true` with an errors entry), `failed/error Unknown AIRS action: quarantine`, `failed/error AIRS async scan failed` (row status `failed`, empty report ID). Bulk-scan fails closed: these never count as allowed.

### 6.5 Correlation

Results are keyed by `(scanId, reqId)` (`recordBulkResults`, `runtime.ts:110-126`); a result whose key, index or prompt does not match a stored item throws `Bulk-scan result correlation mismatch for scan <id>, request <reqId>`. Server row order does not matter (verified with reversed rows and status `completed`). Prompt text never comes from the server.

### 6.6 SDK-level guards that fire before sending

`asyncScan` validates the body against `AsyncScanObjectSchema[]` (`SDK:1722-1725`, `ScanRequestSchema` `SDK:1534-1540`): `session_id` ≤ 100, `profile_name` ≤ 100 (`AiProfileSchema`, `SDK:1486-1491`), `contents` non-empty. A violation throws `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/async/request did not match schema: 0.scan_req.session_id: too_big; 1.scan_req.session_id: too_big; …` **with no `failureKind`** and no request sent. Prompt length is not checked for async scans (only `Content` checks it, which bulk-scan does not use).

## 7. Submission failure classification (`runtime.ts:386-393`, `:998-1005`)

After any submit error the chunk's items are saved with `error = err.message` and the status below, and the error is rethrown (the run ends; later chunks and batches are not attempted, and **accepted earlier chunks of the same logical batch are not polled**).

`isDefiniteSubmissionRejection` (`runtime.ts:156-164`): `failureKind === 'http'` and `400 <= statusCode < 500` → `pending`; **anything else → `ambiguous`**.

| Case (verified) | Requests | Item status | Message (`✗ Error: …`) | Extra lines |
|---|---|---|---|---|
| 429 ×6 (`Retry-After: 0`) | 6 POSTs | pending | `AISEC_CLIENT_SIDE_ERROR:stub status 429` | `HTTP 429`, debug hint |
| 400 `{"message":"profile not found"}` | 1 | pending | `AISEC_CLIENT_SIDE_ERROR:profile not found` (server text) | `HTTP 400`, hint |
| 401 | 1 | pending | `AISEC_CLIENT_SIDE_ERROR:stub status 401` | `HTTP 401`, hint |
| 500 | 1 | ambiguous | `AISEC_SERVER_SIDE_ERROR:stub status 500` | `HTTP 500`, hint |
| 503 with `Retry-After: 0` | 1 (no SDK retry) | ambiguous | `AISEC_SERVER_SIDE_ERROR:stub status 503` | `HTTP 503`, hint |
| connection destroyed after the request | 1 | ambiguous | `AISEC_CLIENT_SIDE_ERROR:fetch failed` | — |
| 200 with an invalid receipt `{"nope":true}` | 1 | ambiguous | `AISEC_RESPONSE_VALIDATION:Response did not match schema: received: invalid_type; scan_id: invalid_type` | — |
| **pre-dispatch validation** (`--session-id` of 101 chars) | **0** | **ambiguous** | `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/async/request did not match schema: 0.scan_req.session_id: too_big; …` | — |
| SIGINT/SIGTERM while the POST is in flight | 1 | `submitting` (never updated) | none (§14) | — |

The last two rows are the defects: a request that was provably never sent is recorded as ambiguous and blocks the job forever; and nothing distinguishes connection-refused (nothing sent) from a reset after the write (both `failureKind: network`). The server's message text is printed and stored in the state's `error` field.

## 8. The state file

### 8.1 Schema (version 2, `state.ts:7-132`)

Top level: `version: 2` (literal), `profile` (non-empty), `sessionId?`, `outputFile` (non-empty; absolute when written by the CLI), `batchSize` (positive safe integer), `createdAt`, `updatedAt` (ISO date-times), `items` (≥ 1).

Item: `index`, `reqId` (non-negative integers, `reqId === index`), `prompt` (the full prompt text), `status` ∈ `pending | submitting | submitted | complete | failed | ambiguous`, `scanId?` (non-empty), `receiptReportId?`, `result?`, `error?` (the last submit error message).

Result (`BulkScanResultSchema`, `state.ts:39-51`): `index`, `reqId`, `prompt`, `response?`, `scanId`, `reportId`, `action` ∈ `allow|block|failed`, `category`, `triggered`, `detections` (string → boolean), `error?`.

Invariants enforced on every save and load (`state.ts:64-131`), each with its message:
- `reqId must match the stable input index`
- `submitted|complete|failed entries require a scanId`; `pending|submitting|ambiguous entries cannot contain a scanId`
- `complete|failed entries require a result`; other statuses `cannot contain a result`
- `stored result does not match its prompt entry` (index, reqId, prompt); `stored result scanId does not match its receipt`
- `failed entries require a failed result`; `complete entries cannot contain a failed result`
- `duplicate input index <n>`; `prompt entries must remain in input order` (index = position); `input indices must be contiguous from zero`

Errors join the Zod messages with `; ` under `Invalid bulk-scan state: …` (e.g. `Invalid bulk-scan state: Number must be greater than 0; submitted entries require a scanId`).

Serialisation: `JSON.stringify(state, null, 2)`, no trailing newline, key order as built (`version, profile, sessionId, outputFile, batchSize, createdAt, updatedAt, items`); undefined fields are dropped. A completed captured state for 3 prompts is shown in the scratchpad capture `s_happy.sh`; the shape is:

```
{"version":2,"profile":"my prof","sessionId":"prisma-airs-cli-bulk-mvd0d79b","outputFile":"<SB>/cwd/my-prof-bulk-scan.csv","batchSize":25,"createdAt":"…","updatedAt":"…",
 "items":[{"index":0,"reqId":0,"prompt":"hello one","status":"complete","scanId":"7828…","receiptReportId":"R7828…",
           "result":{"prompt":"hello one","scanId":"7828…","reportId":"R7828…","action":"allow","category":"benign","triggered":false,"detections":{},"index":0,"reqId":0}}, …]}
```

### 8.2 Location and modes

See §4 for the directory. `saveBulkScanState` (`state.ts:135-165`): `mkdir(dir, {recursive, mode: 0o700})`; on the **first** save only, `chmod(dir, 0o700)` (an existing directory is tightened; parents created by `mkdir -p` get 0700 too, the pre-existing ones are untouched). Verified: `<SB>/home/.prisma-airs` and `…/bulk-scans` are `drwx------`, the file `-rw-------`. There is no symlink, owner or mode check of the directory or file, no fsync of the file or the directory, and no lock on the directory.

### 8.3 Atomic rewrite

Each save: validate (refuses to persist an invalid state, `state-spec:82-87`), set `updatedAt`, write `<target>.tmp-<pid>-<uuid>` with flag `wx` and mode 0600, `rename` over the target, `chmod 0600`. On a write or rename error the temp file is removed. A process killed between write and rename leaves the temp file behind.

### 8.4 When writes happen (verified with `fstrace.mjs`, 2 prompts, 1 chunk)

```
readFile p.txt
mkdir bulk-scans {recursive, 0700}; chmod bulk-scans 0700; writeFile <state>.tmp (wx 0600); rename → <state>; chmod <state> 0600    # all pending
writeFile <state>.lock.candidate-<pid>-<uuid> (wx 0600); link → <state>.lock; rm candidate                                       # lock
mkdir <cwd> {recursive}; writeFile <out>.tmp (wx 0600); rename → <out>                                                           # header-only CSV, replaces an existing file
save state                                                                                                                       # chunk items "submitting"
  POST /v1/scan/async/request
save state                                                                                                                       # "submitted" + scanId/receiptReportId
  GET /v1/scan/results
save state; write CSV                                                                                                            # onProgress, result 1
save state; write CSV                                                                                                            # onProgress, result 2
save state; write CSV                                                                                                            # after pollBatch returns
write CSV                                                                                                                        # final projection
readFile <state>.lock; rm <state>.lock                                                                                           # release
```

So a submission is checkpointed as `submitting` before it is sent and as `submitted` before polling (`bulk-doc:128`), and each result is checkpointed as soon as it is known (`int-spec:739-807`). Each progress event rewrites the whole state and the whole CSV (quadratic in the batch). Completed state files are never deleted; prompts persist in `bulk-scans/` indefinitely.

### 8.5 Loading and legacy rejection (`state.ts:168-187`)

- `readFile` errors are raw Node text.
- Not JSON: `Invalid bulk-scan state: malformed JSON`.
- `parsed?.version !== 2` (a legacy `{scanIds, profile, promptCount}` file, `{"version":1}`, `null`, an array): `This legacy bulk-scan state predates prompt persistence and cannot be resumed. Re-run bulk-scan.`
- Schema failures: `Invalid bulk-scan state: <messages>`.
- The loaded `outputFile` is trusted as is: a hand-written state with `"outputFile":"rel.csv"` made resume write `rel.csv` in the **current** directory (relative paths resolve against the resume's cwd), even on the ambiguous error path.

## 9. The job lock (`lock.ts`)

- File: `<realpath of state>.lock`, next to the state file. Record (compact JSON): `{"version":1,"pid":<pid>,"createdAt":"<ISO>","token":"<uuid v4>"}`. No host, no user.
- Acquire (`lock.ts:69-111`), up to 2 attempts: write `<lock>.candidate-<pid>-<uuid>` (`wx`, 0600), `link` it to `<lock>` (atomic create-if-absent), remove the candidate. On `EEXIST`: read and parse the existing lock; `ENOENT` → retry; owner alive (`process.kill(pid, 0)` succeeds **or fails with anything but `ESRCH`**, so `EPERM` counts as alive) → refuse; owner dead → `rm` the lock and retry. Two failed attempts: `Could not acquire bulk-scan lock for <state>`.
- Release: re-read the lock; remove it only when the token is ours; `ENOENT` is fine. Released in the `catch` before `fail` and in `finally` (`runtime.ts:433-439`, `:1031-1037`), so every error exit removes it. A signal does not (§14).
- `bulk-scan` takes the lock right after the first state save, so two bulk-scans never share a job. `resume-poll` takes it before reading the tenant.

Messages (all `✗ Error: …`, exit 1):

| Case (verified) | Message |
|---|---|
| live owner (a running pid, or pid 1 → `EPERM`) | `Bulk-scan job is already active in process <pid>. Wait for it to finish before resuming <state>.` |
| dead owner (pid 2147483647) | none; the lock is recovered silently and the command proceeds |
| not JSON | `Bulk-scan lock <state>.lock is malformed. If no bulk-scan process is running, remove it manually.` |
| wrong shape (`version` ≠ 1, pid not a positive safe integer, missing `createdAt`/`token`) | `Bulk-scan lock <state>.lock has invalid ownership data. If no bulk-scan process is running, remove it manually.` |
| the lock path is a directory | `EISDIR: illegal operation on a directory, read` |
| the state directory is not writable | `EACCES: permission denied, open '<state>.lock.candidate-<pid>-<uuid>'` |

The concurrent case was verified live: a `resume-poll` started while the original bulk-scan was polling refused at once with the "already active" message and sent nothing; the bulk-scan finished normally (`int-spec:159-210` pins the same for two resumes). The docs show the message as `Error: …` without the glyph (`bulk-doc:111`).

Hazards (by reading): pid reuse makes a dead owner look alive; an unrelated process with that pid owned by another user (EPERM) makes the lock permanent; the stale-recovery path is racy: two processes that both read the same dead record can both `rm` and re-`link`, and the second `rm` can delete the first one's fresh lock, giving two owners. The lock lives only on the local host (no host check).

## 10. The output CSV (`svc:597-622`, `runtime.ts:134-154`)

- Header (unquoted), byte-exact: `prompt,action,category,triggered,topic_violation,injection,toxic_content,dlp,url_cats,malicious_code,source_code,agent,scan_id,report_id,error`
- One row per resolved item (`complete` or `failed`), in **input-index order**; unresolved items have no row. Every field is double-quoted, with `"` doubled; nothing else is escaped (commas, CR, LF, control characters and leading `=`/`+`/`-`/`@` are kept verbatim inside the quotes). `triggered` and the detector columns are `"true"`/`"false"` (a detector absent from `detections` is `"false"`). `error` is `""` when absent.
- Lines are joined with `\n`; **no trailing newline**. A header-only file is exactly the header line without a newline.
- Captured (3 prompts, one blocked):

```
prompt,action,category,triggered,topic_violation,injection,toxic_content,dlp,url_cats,malicious_code,source_code,agent,scan_id,report_id,error
"hello one","allow","benign","false","false","false","false","false","false","false","false","false","78288af4-031d-4d49-a03c-71105cd0df8a","R78288af4-031d-4d49-a03c-71105cd0df8a",""
"please BLOCK me","block","malicious","true","false","true","false","false","false","false","false","false","78288af4-031d-4d49-a03c-71105cd0df8a","R78288af4-031d-4d49-a03c-71105cd0df8a",""
"third, ""quoted""","allow","benign","false","false","false","false","false","false","false","false","false","78288af4-031d-4d49-a03c-71105cd0df8a","R78288af4-031d-4d49-a03c-71105cd0df8a",""
```

  A failed row: `"c FAILROW","failed","error","false","false",…,"false","1ed8…","","AIRS async scan failed"`. The docs sample shows unquoted rows (`bulk-doc:97-99`); the code quotes every data field.
- Write (`writeBulkResults`): `mkdir -p dirname(output)` (default mode, e.g. `drwxr-xr-x`), write `<out>.tmp-<pid>-<uuid>` (`wx`, 0600), `rename` over the target; no fsync. Consequences: the file ends up 0600; an existing file is replaced; a **symlink at the output path is replaced by a regular file** (the target is untouched); a directory fails with `EISDIR … rename …`.
- Default name `<profile with whitespace runs → '-'>-bulk-scan.csv` in the cwd (§4). `--output-file` is relative to the cwd.
- The CSV is a full projection rewritten after every result, so re-running resume never duplicates rows (`int-spec:663-737`: byte-identical output on a second resume with zero requests).

## 11. `runtime resume-poll <stateFile>` (`runtime.ts:916-1038`)

Order after §2: load the state; build the scanner; find the first item (lowest index) whose status is `submitting` or `ambiguous`; set `state.outputFile = resolvePath(--output-file ?? state.outputFile)` and save (the new output path is **persisted**).

**Ambiguous path** (any `submitting`/`ambiguous` item): poll every submitted receipt (all items, grouped by scan ID), write the CSV, then fail with
`Cannot safely resubmit prompt <index>: its submission outcome is ambiguous. Known accepted results were preserved; inspect <state realpath> before taking manual action.`
(exit 1). No banner is printed; `pending` items are not submitted; nothing is ever resubmitted. The job can never progress past an ambiguous item through the CLI. Verified: after a 500 submit, resume sent 0 requests and printed only the error; after an interrupted POST (`submitting`), the same.

**Normal path**: banner (§12), then per stored logical batch: poll its submitted receipts; submit its `pending` items (lowest index first, chunks of 20, `session_id` = the stored one; on success `error` is cleared, `runtime.ts:995`); poll again. Submit failures follow §7 (and end the run). Then save, write the CSV, print the summary, exit 1 if any row is failed.

Verified:
- Completed job, resumed: 0 requests, byte-identical CSV, exit 0, the state rewritten twice (load-time save and final save) and the CSV once.
- Poll 500, then resume: `G:results`, all complete, exit 0.
- 21 prompts, chunk 1 accepted, chunk 2 400: bulk-scan exit 1 (chunk 1 not polled); resume `G P[20] G`, 21 rows, exit 0 (`int-spec:212-341`).
- `resume-poll link.json --output-file other.csv` with a symlinked state and a pre-existing `other.csv` containing `precious`: the realpath was used (lock next to the real file); `other.csv` was **overwritten**, and the state's `outputFile` now points at it.
- Interrupted polling (SIGINT), resume: the stale lock was recovered silently, the receipt polled, exit 0.

Failed rows are terminal: resume never retries them, and every later resume exits 1 again.

## 12. Messages and colours

Streams: `ui.status` (dim, **stderr**, quiet-suppressed); `ui.header` (bold title with blank lines, **stdout**, quiet-suppressed); `ui.keyValue` (dim keys padded to the longest key, 2-space indent and gap, **stdout**, not suppressed); `ui.error` (red `✗`, stderr, not suppressed); `fail` (red `\n  ✗ Error: <message>`, then red `    HTTP <status>` and dim `    Re-run with --debug to capture redacted API diagnostics.` when the error has a status, then an empty line; exit 1; `common.ts:12-25`); `usageError` (red `\n  ✗ <message>\n\n`, exit 2).

`bulk-scan` success, byte-exact (NO_COLOR):

```
stderr: "  Prisma AIRS Bulk Scan\n  Profile:  my prof\n  Session:  prisma-airs-cli-bulk-mvd0d79b\n  Prompts:  3\n  Batches:  1 (size 25)\n  State:    <state path>\n  Submitting batch 1...\n  Scan IDs saved: <state path>\n"
stdout: "\n  Bulk Scan Complete\n\n  Total    3\n  Blocked  1\n  Allowed  2\n  Failed   0\n  Output   <absolute output path>\n"
```

- `Submitting batch <n>...` and `Scan IDs saved: <state>` repeat per logical batch; rate-limit lines (§6) interleave.
- With failed rows, stderr ends `  ✗ <n> prompt(s) failed; successful results were preserved.\n` and the exit code is 1 (`runtime.ts:429-432`).
- `--quiet`: stderr only the failure line (if any); stdout only the five key/value lines.
- Colours (`FORCE_COLOR=1`): status lines `\e[2m…\e[22m`; title `\e[1mBulk Scan Complete\e[22m`; keys `\e[2mTotal  \e[22m` (padding inside the dim span); Blocked and Failed values `\e[31m…\e[39m`, Allowed `\e[32m…\e[39m`, Output `\e[36m…\e[39m`, Total uncoloured; the failure line `\e[31m✗ … preserved.\e[39m`.

`resume-poll` uses `Prisma AIRS Resume Poll`, `Profile:  <p>`, `Scan IDs: <distinct scan IDs in the state>`, `Prompts:  <n>` and the header `Resume Poll Complete`; the summary is the same five rows (`runtime.ts:960-1030`). It prints no `Submitting batch` or `Scan IDs saved` lines.

Message catalogue (all verified unless marked "code"):

| Text | Stream | When |
|---|---|---|
| `--file <file> is required` | usage | §2 |
| `--batch-size must be a positive integer` | usage | §2 |
| `No prompts found in input file` | usage (after the tenant) | §2 |
| `No "prompt" column found in CSV header` | fail | §3 |
| `⚠ Rate limited while submitting — retry <n> in <s>s...` | status | §6.1 |
| `⚠ Rate limited — retry <n> in <s>s...` | status | §6.2 |
| `AIRS polling made no progress after <n> polls for scan <id>` | fail (code) | §6.2 |
| `AIRS result correlation failed for scan <id>: terminal row has no request or report ID` | fail (code) | §6.2 |
| `AIRS result correlation mismatch: nested scan ID <a> does not match <b>` | fail (code) | §6.2 |
| `AIRS report correlation mismatch for scan <id>, request <reqId>` | fail (code) | §6.2 |
| `Bulk-scan result correlation mismatch for scan <id>, request <reqId>` | fail (code) | §6.5 |
| `Bulk-scan state is missing input index <n>` | fail (code) | `runtime.ts:128-132` |
| `Cannot safely resubmit prompt <i>: its submission outcome is ambiguous. …` | fail | §11 |
| `This legacy bulk-scan state predates prompt persistence and cannot be resumed. Re-run bulk-scan.` | fail | §8.5 |
| `Invalid bulk-scan state: …` | fail | §8 |
| the four lock messages | fail | §9 |
| `<n> prompt(s) failed; successful results were preserved.` | ui.error | §12 |

## 13. Exit codes

| Code | Cases |
|---|---|
| 0 | every row `allow`/`block` (including a resume that had nothing to do) |
| 1 | commander parse errors; tenant, credential, file and CSV-header errors; any submit or poll error; lock refusal; state load errors; the ambiguous refusal; **any failed row** (after the summary is printed) |
| 2 | `--file` missing, `--batch-size` invalid, no prompts |
| 130 / 143 | killed by SIGINT / SIGTERM (Node's default; no handler, no message) |

## 14. Interruption

There is no signal handler for these commands (only `aigateway inference` installs one). SIGINT/SIGTERM kill node at once; the shell sees 130/143; nothing is printed after the last status line.

- **During polling** (verified, both signals): items stay `submitted`; resolved results are already checkpointed; the lock file **remains** with the dead pid; the next `resume-poll` recovers it silently and finishes (no new submission).
- **During a submission** (verified, SIGINT while the stub delayed the 200 by 5 s): the state shows the chunk as `submitting`; the stub still received and accepted the request; resume refuses with the ambiguous message. The accepted scan is billed, and its results can never be fetched through the CLI.
- Between a temp write and its rename, the temp file (`*.tmp-<pid>-<uuid>`, or a lock candidate) is left behind; the target keeps its previous content (rename is atomic, but there is no fsync, so a power loss can lose or truncate the latest checkpoint).
- The docs advertise Ctrl+C after `Scan IDs saved:` as safe (`bulk-doc:102-106`), which matches the polling case.

## 15. `--debug`, `--quiet`, root `--output`

- `--debug` (`program.ts:176-191`) creates `./debug-api-<ms>-<8 hex>.jsonl` in the **cwd** and prints `  Debug: API log → <path>` first. Only real AIRS hosts are logged (`debug-logger.ts:20-27`), so the loopback capture left an empty file. On a real tenant the async POST bodies, which contain every prompt, are logged verbatim (`docs/research/ts-debug-log.md` §4, "Scan prompts and responses … verbatim"). The Rust log never records bodies (DESIGN §2.9, D61–D69).
- `--quiet`: §12.
- Root `--output <any>`: silently ignored (§1).

## 16. Doctor wording

The only doctor mention is the scanner-credentials skip detail `not configured — runtime scan, bulk-scan and topics eval are unavailable` (`doctor.ts:272`), already ported (DESIGN §9 table, `src/commands/doctor.rs:295`). Doctor has no state-directory or `dataDir` check. The TS docs list `dataDir` as `Bulk-scan state directory` (`docs-site/docs/reference/configuration.md:89`); the key is already dropped in Rust (D71).

## 17. TS test behaviours to port as acceptance tests

`state-spec` (unit, on `saveBulkScanState`/`loadBulkScanState`):
1. A save writes the version, profile and per-item correlation (`index`, `reqId`, `prompt`, `scanId`) and an `updatedAt` (`:40-53`).
2. New state files end in `.bulk-scan.json` (`:55-59`); the directory is created when missing (`:61-67`).
3. Re-saving rewrites the same path; exactly one state file exists (`:69-80`).
4. An invalid state (batch size 0) is refused and nothing is written (`:82-87`).
5. Directory 0700, file 0600 (`:89-98`).
6. Load round-trips (`:102-110`); a missing file fails (`:112-114`); malformed JSON fails as malformed (`:116-121`); legacy state fails with the legacy/re-run message (`:123-132`); duplicate indices (`:134-143`), out-of-order items (`:145-160`), a submitted item without a receipt (`:162-174`) and a result whose scan ID differs from its receipt (`:176-204`) are rejected.

`lock-spec`:
7. One owner at a time; a second acquire fails "already active"; after release a new acquire succeeds (`:21-29`).
8. A lock whose owner is not running is recovered and removed on release (`:31-46`).

`int-spec` (mocked Scanner):
9. 7 prompts, rows returned out of order: 7 aligned rows in input order with the right actions and detector columns (`:47-98`).
10. A poll failure exits 1; resume completes both prompts (`:100-157`).
11. Overlapping resumes: the second exits 1 while the first holds the lock, one submission total, the lock removed afterwards (`:159-210`).
12. 21 prompts, second chunk exhausts 429 retries: resume submits only `req_id` 20, 21 rows (`:212-283`).
13. A 4xx-rejected submission stays `pending` and resume submits it once (`:285-341`).
14. A `failed` row: both rows written, exit 1 (`:343-377`), also on resume (`:379-434`).
15. An ambiguous (network) submission: items `ambiguous`, one POST; resume makes no POST and no poll and exits 1 (`:436-490`).
16. Stale output is replaced by the header-only projection before the first POST (`:492-525`). **Rust inverts this** (settled: an existing output is refused before anything is submitted).
17. Accepted chunk + ambiguous chunk: resume polls once, writes 20 rows, makes no POST, exits 1 (`:527-586`).
18. Accepted chunk + rejected chunk: resume polls before it submits, the retried submission is ambiguous, states end `complete ×20, ambiguous` (`:588-661`).
19. A later batch's poll fails: 20 rows kept; resume completes to 21 rows; a second resume is byte-identical with no request (`:663-737`).
20. Results are checkpointed per row within one receipt (`:739-807`).
21. Invalid batch sizes exit 2 with no request (`:809-838`).
22. Batches are sequential (`:840-885`) and resume keeps the stored batch size (`:887-956`).

## 18. Rust SDK (`scm-sdk 0.1.0`) coverage

- `Scanner::async_scan(&[AsyncScanObject], …)` (`src/airs/scan/scanner.rs:175-197`): 1–20 objects (else `Validation`), content validated, body validated against `AsyncScanObjectSchema[]`; `RawRequest::new`, so never replayed (`docs/research/rs-sdk-scan.md` §"retries"). `AsyncScanObject.req_id` is a `FiniteNumber`.
- `query_by_scan_ids` (1–5 UUIDs) and `query_by_report_ids` (1–5 IDs) exist; `ScanIdResult` and `ThreatScanReport` have optional `req_id: FiniteNumber`, `status`, `scan_id`, `result: ScanResponse` (strict, like TS).
- Errors carry `status()`, `retry_after()` (header, then body `retry_after`), `remote_outcome()`: `NotSent` for pre-dispatch failures (`Error::new` default, `src/error.rs:63-75`), `Rejected` for any HTTP 4xx including 429 (`src/engine.rs:1237-1241`), `Unknown` for 5xx, transport (connection refused included, because the sent flag is set before `transport.send`), deadline, cancellation after dispatch, and a 2xx whose body does not decode (`response.annotate` sets `Unknown`, `src/engine.rs:207-214`). An error body over 64 KiB is `Limit` with outcome `Unknown` even for 4xx.
- Mapping to the TS states: `NotSent` → leave `pending` (fixes §7's pre-dispatch defect); `Rejected` → `pending` (429 first goes through the bounded retry); `Unknown` → `ambiguous`.
- **No blocker found.** Over-conservative but safe: connection refused is `Unknown`, so it is recorded as ambiguous in Rust as in TS. Verify in the port that `async_scan`'s `Validation` errors (session ID or profile over 100) surface as `NotSent`; if they do not, that is an SDK gap to report.

## 19. Notes for the live tier

- TS state follows the tenant's `dataDir`. The sandbox copy of the TS config can set `dataDir` to `<run tmp>/ts-data/runs`, which puts TS state at `<run tmp>/ts-data/bulk-scans/` while the CLI still finds the tenant through `PRISMA_AIRS_TENANTS_PATH`. With `HOME` also inside the sandbox, the default (`~/.prisma-airs/bulk-scans`) would land there too. Pass an explicit `--output-file` under the run directory and run with the cwd there (the default output and the TS `--debug` log go to the cwd). If the live harness cannot write that config copy, skip the TS bulk step with a notice, as the task rules require.
- TS never reads `XDG_STATE_HOME` for bulk state, so the Rust and TS states cannot collide.
- A resume of the completed Rust state must send zero requests (§11, verified for TS); a resume after an injected interruption during polling must send only `GET /v1/scan/results`.

## Acceptance criteria

Behaviour the Rust port must reproduce (parity unless a divergence below says otherwise), each pinned by an executable test against the loopback fixture:

1. Help text and option set of §1 (help bytes may differ only where DESIGN already diverges for help); `--input` accepted with the TS warning, unless the user decides otherwise (open question 15).
2. Usage checks: `--file` missing and `--batch-size` invalid (`0`, `-1`, `1.5`, `abc`, `007`, `9007199254740992`, empty) exit 2 before the tenant with the §2 messages and no request; commander-style errors exit 2 (D1).
3. Input parsing matches §3 for every row of the table (BOM, CRLF, bare CR, quoted newlines, `""`, the after-quote and space-before-quote cases, blank rows, the first `prompt` column, trimming, `.CSV` case-insensitivity, extensionless files as lines), except where open question 9 decides otherwise.
4. Batching and request order of §5 (sequential logical batches, chunks ≤ 20, all chunks of a batch before its polls, one scan ID per poll, the stored batch size on resume).
5. Request shapes of §6.1/§6.2: `req_id` = global input index; `session_id` on every object (default `prisma-airs-cli-bulk-<base36 ms>`); headers and payload hash as for sync scans; exactly one HTTP attempt per call; the CLI's own 429 retries (5, honouring `Retry-After`, else 10 s doubling).
6. Polling semantics of §6.2–§6.5: per-row and batch-level rows, the report fallback, fail-closed normalisation (timeout, `error:true`, unknown action → `failed` with the §6.4 error texts), 5 s interval, the 120 no-progress bound with its message, correlation by `(scan_id, req_id)` independent of row order, correlation-mismatch errors.
7. Exactly-once rules: a chunk is checkpointed (fsynced) as submitting before the POST and as submitted with its receipt before polling; `Rejected` → pending, `NotSent` → pending, `Unknown` → ambiguous; an ambiguous or submitting item is never resubmitted; resume polls known receipts first, writes the output, then fails with the ambiguous message naming the lowest such index and the state path.
8. Each resolved result is checkpointed before the next poll; a poll error keeps `submitted` items and completed rows; exit 1.
9. Output CSV of §10: header, quoting, `true`/`false`, input order, only resolved rows, no trailing newline, header-only file at job start, atomic rewrite, identical bytes on a repeated resume.
10. Summary and banner of §12 (texts, streams, quiet behaviour, colours), the failure line and exit 1 when any row failed; exit codes of §13.
11. Lock: a second bulk/resume on the same job is refused immediately with the "already active" wording (process ID of the holder) and sends nothing; a lock left by a dead or interrupted process never blocks (flock).
12. State: version check and legacy rejection with a clear message for a TypeScript state file; the §8.1 invariants on load.
13. Interruption: Ctrl-C during polling leaves a consistent state that `resume-poll` completes with no new submission; during a submission the chunk is recorded as ambiguous (submitting) and named.
14. All 22 behaviours of §17, with item 16 inverted per the settled decision.

## Open questions / likely §12 divergences

Numbers are provisional (from D118). Each is a safety or correctness fix unless marked; items marked **confirm** are choices the user should confirm.

1. **D118 state location, format and durability.** TS: `dirname(dataDir)/bulk-scans` (default `~/.prisma-airs/bulk-scans/`), JSON v2, no fsync, no symlink/owner/mode checks, chmod of the directory on first save only. Rust (settled): `$XDG_STATE_HOME/airs-cli/bulk-scans/` (default `~/.local/state/airs-cli/bulk-scans/`), Rust-only format, dir 0700 / files 0600, temp → fsync → rename → dir fsync, symlink, owner and mode checks as in §3.8/§3.9. `resume-poll` on a TS v2 file (and on a legacy file) fails with a clear message, e.g. `<path> is a TypeScript airs-cli bulk-scan state; airs-cli-rs cannot resume it. Run 'airs-cli runtime resume-poll' with the TypeScript CLI, or re-run bulk-scan.` **confirm** the wording and whether a TS file is recognised by its `version: 2` shape.
2. **D119 job lock.** TS: hard-link lock file with `{version,pid,createdAt,token}`, liveness by `kill(pid,0)` (pid reuse; EPERM counts as alive forever), a stale-recovery race that can yield two owners, and a lock left behind by every signal. Rust (settled): `flock` on a per-job lock file in the state directory, holder record (pid, host) only for the message, immediate refusal, no stale state. Message parity: `Bulk-scan job is already active in process <pid>. Wait for it to finish before resuming <state>.` (**confirm**: add the host when it differs?). Malformed-lock messages disappear (a flock cannot be malformed).
3. **D120 existing output files.** TS replaces an existing output (the default name or `--output-file`) before the first POST, replaces a symlink with a regular file, and `resume-poll --output-file` overwrites any existing file and persists it as the job's output. Rust (settled): an output that exists when bulk-scan starts (file or symlink) is refused before the state is created or anything is submitted (exit 1, D114-style text, e.g. `<path> already exists; choose another --output-file`); the job's own output is created exclusively at start and rewritten atomically by the job and by resume; resume `--output-file` to a different pre-existing path is refused. **confirm** how "the job's own output" is recognised on resume (recommendation: record the absolute path plus device/inode at creation and require a match before rewriting; if the file was deleted, recreate it exclusively).
4. **D121 default output name from the profile.** TS keeps `/` and `..` from the profile name, so the default output can land outside the cwd and directories are created (`../esc dir/x` → `../esc-dir/x-bulk-scan.csv`). Rust: the default name must stay in the cwd; recommendation: map every character outside `[A-Za-z0-9._-]` to `-` (and refuse a name that becomes `.`/`..`), or refuse such profiles for the default name with a usage hint to pass `--output-file`. **confirm** which.
5. **D122 output parent directories.** TS `mkdir -p` creates missing parents with default modes. Rust recommendation: require the parent directory to exist (exit 1, fixed message), like other report writers. **confirm**.
6. **D123 pre-dispatch failures recorded as ambiguous.** TS records a chunk as `ambiguous` when the SDK rejects the body before sending (session ID or profile name over 100), which blocks the job forever although nothing was sent. Rust: validate `--profile` (§8.1 rules) and `--session-id` (≤ 100, non-empty? **confirm** whether `""` should mean "no session" as in TS or be a usage error) and each prompt (non-empty after parsing, ≤ 2,097,152 UTF-8 bytes) as usage errors (exit 2) before the tenant, and treat any `NotSent` submit error as pending.
7. **D124 Retry-After bounds.** TS sleeps for any `Retry-After` (days), and above 2^31 ms Node fires at once with a `TimeoutOverflowWarning` on stderr. Rust recommendation: cap each wait (e.g. 60 s, matching the SDK's retry cap) or treat a longer request as a failure that ends the run with the state intact. **confirm**.
8. **D125 what counts as a rate limit while polling.** TS also retries any error whose message contains `429`, `rate limit` or `rate_limit` (server text). Rust: HTTP 429 only.
9. **D126 input file rules.** TS decodes invalid UTF-8 as U+FFFD, accepts an unterminated quote silently, reads files of any size and sends control characters. Rust recommendation (consistent with D103): the §13.2 input-file rules (regular file, bounded size, valid UTF-8, read before the tenant, fixed messages that echo no content); an unterminated quote is an error; keep the RFC quirks of §3 (after-quote text, BOM, bare CR) for parity, as `topics eval` did. Also move `No "prompt" column…` (exit 1) and `No prompts found…` (exit 2) before the tenant read (D2/D103 pattern). **confirm** whether control characters in prompts are allowed (they reach only the server and the CSV).
10. **D127 crafted or edited state.** TS trusts `outputFile` from the state (relative paths resolve against the resume's cwd), so a state file can make resume overwrite any file the user can write. Rust: the state lives only in the checked state directory, the recorded output path is absolute, and resume rewrites it only under rule 3. A `resume-poll` argument outside the state directory: **confirm** whether it is refused or accepted after the same file checks.
11. **D128 interruption.** TS: no handler, no message, exit 130/143, the lock and temp files left behind, an in-flight chunk left `submitting`. Rust (§2.5 style): a signal during polling stops before the next poll and prints `Interrupted; the job was saved; resume it with 'airs-cli-rs runtime resume-poll <state>'`; during a submission the chunk is saved as ambiguous and the context says `the scan request may already have reached AIRS (outcome unknown); …`; nothing is left locked. **confirm** the wording.
12. **D129 non-UUID receipt scan ID.** TS checkpoints it as submitted and then fails every poll forever. Rust recommendation: record the chunk as ambiguous with a fixed message (the scan was accepted but cannot be queried), so resume reports it instead of failing in a loop. **confirm**.
13. **D130 output formats** (not safety; the task asks the spec to decide). TS: text only (root `--output` ignored). Recommendation: `pretty` default with the TS bytes; `--output json` prints one summary object on stdout (`{"profile","sessionId","state","output","total","blocked","allowed","failed"}`; never prompts or results); `--output table` the summary as a two-column table; other values exit 2 (as D5/D94). The CSV file is unchanged.
14. **D131 error text.** TS prints and stores server message text (`AISEC_CLIENT_SIDE_ERROR:profile not found`, `fetch failed`, raw Node `ENOENT` texts with paths). Rust: §6 messages from SDK metadata only, with `Outcome unknown: …` for `Unknown` submits; the state records the outcome class, never server text. Likely covered by the existing §6 rows; **confirm** whether a new row is needed.
15. **Deprecated `--input`** (not safety). TS accepts `--input` with a warning; `--output <file>` is unreachable. Recommendation: keep `--input` hidden with the TS warning (as `--format`, D94), and treat `--output` as the global format flag. **confirm**.
16. **D132 orphan pending state.** TS leaves an all-`pending` state when the output write or client setup fails after the state exists, and resume would then submit it. Rust: validate and create the output before the state, and delete a state file whose job sent nothing when setup fails.
17. **State retention** (not a divergence yet). TS never deletes completed state files, so prompts accumulate in the state directory. **confirm** whether Rust keeps them (parity) or removes a fully completed job's state after a successful run (it then cannot be resumed byte-identically, which `int-spec:663-737` relies on). Recommendation: keep, and document.
18. **Ambiguous items block the job forever** (parity, settled: never resubmitted automatically). **confirm** whether a later milestone should add an explicit, opt-in way to abandon ambiguous items (e.g. mark them failed) so the remaining pending prompts can run.
19. **`--debug`**: TS logs every prompt verbatim in the cwd; Rust logs status and headers only (existing D61–D69). No new row expected.
20. **CSV formula injection** (not a divergence; parity recommended). Prompts beginning with `=`, `+`, `-` or `@` are written verbatim inside quotes; spreadsheets may evaluate them. Recommendation: keep the bytes (the CSV is a data product) and mention it in the docs. **confirm**.
