# Rust SDK async scanning for M5 (0.5): `runtime bulk-scan` and `runtime resume-poll`

Scope: every M5 operation, the `scm-sdk` 0.1.0 API that serves it, and how it differs from the
TypeScript SDK 0.34.0 that the frozen TS CLI (5711012) uses. It also proposes the Rust state
file, its write protocol, the job lock and the live-tier flow for M5. The command contract itself
(flags, messages, formats) belongs to the DESIGN section the spec step writes. This file supplies
the SDK facts and the safety design that section needs.

Citation prefixes:

- `rs:` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scm-sdk-0.1.0/` (the published
  crate the CLI pins).
- `tsdk:` = `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js` (the
  0.34.0 bundle the TS CLI really runs).
- `cli:` = `.reference/prisma-airs-cli/` (the TS CLI).
- `here:` = this repository.

How it was verified:

- Source reading of all three code bases.
- A throwaway probe built against the published crate (`=0.1.0`, offline, with this repository's
  lock file) and a raw `127.0.0.1` HTTP/1.1 server. Its source is at
  `/private/tmp/claude-501/-Users-cdot-development-redtail-prisma-airs-cli-rs/2663a1f5-b86a-45e5-9990-00ce664767e6/scratchpad/asyncprobe/src/main.rs`.
  "Observed" below means a probe result (§3).
- Nothing in either repository was changed except this file. No non-loopback host was contacted.

Companion specs: `rs-sdk-scan.md` (sync scan, §2.5 and §7 touch async), `rs-sdk-foundation.md`
(engine, auth), `rs-sdk-writes.md` (outcome handling for writes).

---

## 0. Summary

- **No blocking SDK gap.** scm-sdk 0.1.0 has every call M5 needs:
  - async submission of 1–20 objects;
  - the receipt;
  - poll by scan id;
  - the report fallback;
  - `req_id` and session id;
  - a per-call deadline and cancel;
  - safe-read retry control;
  - `RemoteOutcome` on every error;
  - 429 status and `Retry-After`.

  The wire shapes match TS 0.34.0 (§1, §2).
- **Exactly-once comes for free at the SDK layer.** `async_scan` is never replayed, for any
  status, transport error or `with_retries` value (observed: one request for 429, 500, 502 and
  503). Every failure after dispatch is `RemoteOutcome::Unknown`. A 4xx or 3xx answer is
  `Rejected`, and a local refusal is `NotSent`. That is exactly the three-way split the TS CLI
  builds by hand from `failureKind` and `statusCode`.
- **Seven non-blocking limitations** (G1–G7, §5). Each has a safe CLI-side handling, a §12 row,
  or both. Two would be worth an SDK branch, but M5 does not need either:
  - **G1.** A refused connection is reported as `Unknown`, not `NotSent`.
  - **G2.** A 4xx whose body exceeds 64 KiB becomes `Limit`/`Unknown` and loses its
    `Retry-After`.
- **TS behaviours the port must not copy** (§6). Each is a §12 candidate, numbered from D118:
  - A local validation failure (session id over 100 characters) is recorded as *ambiguous*, so
    the job can never resume.
  - An existing output file is replaced.
  - A `Retry-After` HTTP-date or a huge delta overflows Node's `setTimeout`, so the "wait" lasts
    1 ms.
  - The pid-liveness lock can be stolen or wedged.
  - Ctrl-C kills the process with no message.
  - A non-UUID receipt makes every later poll fail.
- **Proposals:**
  - a Rust-only, versioned state file with a per-chunk attempt journal, fsynced before every
    POST and again before every poll (§7);
  - a per-job `flock` lock next to the state file with immediate refusal, a holder record and no
    stale locks (§8);
  - a live flow behind `AIRS_RS_LIVE_BULK=1` with a 4-prompt-per-CLI budget (cap 8). It runs an
    injected-interruption recovery, then a no-op resume that must send zero submissions (proved
    by counting `airs.scan.async` records in the `--debug` log). The TS step runs only when its
    state directory provably lands in the sandbox (§9).

---

## 1. Operation map: what M5 calls, in both SDKs

| M5 operation | scm-sdk 0.1.0 | TS SDK 0.34.0 call the TS CLI makes |
|---|---|---|
| Submit one SDK chunk (1–20 prompts) | `Scanner::async_scan(&[AsyncScanObject], Option<&RequestOptions>) -> Result<AsyncScanResponse>` (`rs:src/airs/scan/scanner.rs:175-197`). Operation name `airs.scan.async`, `POST /v1/scan/async/request`, JSON array body | `scanner.asyncScan(objects, { numRetries: 0 })` (`cli:src/airs/runtime.ts:23,264`; `tsdk:10410-10441`) |
| Build one object | `AsyncScanObject::builder().req_id(FiniteNumber::from(index as u64)).scan_req(ScanRequest)` (`rs:src/models/generated.rs:5763-5770`, builder `:5806-5840`). `ScanRequest::builder().ai_profile(AiProfile{profile_name}).contents(vec![Content::builder().prompt(p).build()?.into_json()]).session_id(Optional::Value(s))` (`generated.rs:163974-163988`; builder setters `:164040-164080`) | literal `{ req_id: index, scan_req: { ai_profile: { profile_name }, contents: [{ prompt }], session_id? } }` (`cli:src/airs/runtime.ts:250-257`) |
| Receipt | `AsyncScanResponse { received: String, scan_id: String, report_id: Optional<String>, source: Optional<String>, extensions }` (`generated.rs:5854-5866`). Unknown keys are kept in `extensions` (observed) | `AsyncScanResponseSchema` = `{received, scan_id, report_id?, source?}` passthrough (`tsdk:1726-1731`) |
| Poll by scan id | `Scanner::query_by_scan_ids(&[String], Option<&RequestOptions>) -> Result<Vec<ScanIdResult>>` (`scanner.rs:201-216`). `GET /v1/scan/results?scan_ids=<ids joined by ,>`, 1–5 ids, each UUID-shaped (`scanner.rs:238-255`; `rs:src/data.rs:324-333`, case-insensitive hex) | `scanner.queryByScanIds([scanId], { numRetries: 0 })` (`cli:src/airs/runtime.ts:325`; `tsdk:10460-10491`; `UUID_RE` with `/i`, `tsdk:9555`) |
| Result row | `ScanIdResult { source, req_id: Optional<FiniteNumber>, status: Optional<String>, scan_id: Optional<String>, result: Optional<ScanResponse>, extensions }` (`generated.rs:163705-163718`). A row-level `report_id` lands in `extensions` (observed) | `ScanIdResultSchema` (`tsdk:1735-1741`) |
| Report fallback (terminal row without `req_id`) | `Scanner::query_by_report_ids(&[String], …) -> Result<Vec<ThreatScanReport>>` (`scanner.rs:221-236`). `GET /v1/scan/reports?report_ids=…`, 1–5 ids, no commas or controls. `ThreatScanReport` (`generated.rs:177710-177727`), `DetectionServiceResult { detection_service, verdict, action, … }` (`generated.rs:28344-28358`) | `scanner.queryByReportIds(ids, { numRetries: 0 })` (`cli:src/airs/runtime.ts:410-413`; `tsdk:10511-10541`) |
| `req_id` correlation | `FiniteNumber::{as_u64, as_i64, as_f64}` (`data.rs:185-210`). `From<u64>` is exact (`data.rs:252-262`) | JS number equality |
| Session id | `ScanRequest.session_id: Optional<String>`. The 100-UTF-16-unit limit is enforced by the request schema at dispatch (observed: 101 gives `Validation`/`NotSent` with 0 requests, 100 is sent). `scm::constants::MAX_SESSION_ID_STR_LENGTH = 100` (`rs:src/constants.rs:661`) | `ScanRequestSchema.session_id: z.string().max(100)` (`tsdk:1536`) |
| Batch bound | 1–20 checked in `async_scan` (`scanner.rs:180-182`); `MAX_NUMBER_OF_BATCH_SCAN_OBJECTS = 20` (`constants.rs:655`) | `MAX_NUMBER_OF_BATCH_SCAN_OBJECTS = 20` (`tsdk:28`), re-exported as `SDK_ASYNC_BATCH_SIZE` (`cli:src/airs/runtime.ts:18`) |
| Per-call deadline | `RequestOptions::with_timeout(d)`: a total budget fixed at construction (`rs:src/config.rs:367-379`, enforced by `run` at `:405-426`). The default is `Limits.operation_timeout` = 60 s (`config.rs:285-302`; `engine.rs:470-479`) | per *attempt*, `PANW_AI_SEC_TIMEOUT_MS` or 60 000 ms (`tsdk:10095`) |
| Retry control | `RequestOptions::with_retries(n)` (n ≤ 5) affects safe reads only (`config.rs:385-391`). See §2.2 | `{ numRetries: 0 }` per call (`tsdk:10287-10296`) |
| Cancellation | `Session::cancel`, `is_cancelled`, `cancelled().await` (`config.rs:341-356`), sticky for every client clone. `RequestOptions::cancel()` for one call | none in the TS CLI (no `signal`; Node's default SIGINT kills the process) |
| Error metadata | `kind()`, `status()`, `remote_outcome()`, `failure_kind()`, `retry_after()`, `request_id()`, `service_code()`, `error_type()`, `problem()`, `operation()` (`rs:src/error.rs:101-203`). No server text is retained | `AISecSDKException { message: "<TYPE>:<server text>", statusCode, failureKind, retryAfterMs, problem }` (`tsdk:200-215`) |

The CLI already builds its scanner through `scm::configuration::init(...)?.client_builder()?`
(`here:src/clients.rs:419-449`). That builder sets `Limits { max_retries: airsNumRetries, ..default }`
(`rs:src/configuration.rs:107-121`). The CLI may call `.limits(..)` again on the returned
`ClientBuilder` to change other limits (§5 G5).

---

## 2. Behaviour of each call

### 2.1 `async_scan`: one dispatch, never replayed

- **Request construction.**
  - `RawRequest::new(POST, …)` has `replay_safe = false` (`rs:src/engine.rs:47-61`).
  - `send_model` (`engine.rs:583-606`) serialises the array.
  - It validates the array against `AsyncScanObjectSchema[]` in request mode, including
    `req_id` as an integer: observed, `1.5` gives `Validation`/`NotSent`.
  - It checks the body against `Limits.max_request_bytes` (8 MiB by default).
  - All of this runs before authentication.
  - Each content item also goes through `validate_content` (`scanner.rs:183-187`):
    - an empty prompt is refused;
    - a prompt over 2 MiB is refused.
- **Retry.** The engine retries only when `request.replay_safe || request.runtime_retries.is_some()`:
  - for transport errors at `engine.rs:1173-1186`;
  - for statuses at `engine.rs:1226-1236`.

  Neither holds for async, so there is exactly one `transport.send`. Observed: one request for
  429 even with `with_retries(5)`, and one each for 500, 502 and 503.
- **Outcome classification** (`engine.rs:1193-1253`; observed, see the matrix in §3):
  - 3xx: `Destination`, `Rejected` (never followed).
  - 4xx: `Http`, `Rejected`.
  - 5xx: `Http`, `Unknown`.
  - Transport failure, deadline or cancel after `sent` was set (`engine.rs:1164`): `Unknown`.
    That includes a refused connection (G1).
  - A 2xx whose receipt does not decode: `Decode` with status 200, `Unknown`. The response's
    `annotate` forces `Unknown` (`engine.rs:206-214`).
  - Local validation, limit or pre-dispatch cancel: `NotSent`.
- **Wire body.** The body is re-serialised from a `serde_json::Value` with no `preserve_order`,
  so every object's keys come out alphabetical. Observed:
  `[{"req_id":0,"scan_req":{"ai_profile":{"profile_name":"Prof A"},"contents":[{"prompt":"a"}],"session_id":"sess-1"}},…]`.
  TS sends Zod schema order inside `scan_req` (`session_id, ai_profile, contents`; `tsdk:1534-1540`).
  The bytes therefore differ whenever a session id is present, which is always for bulk-scan
  because TS generates a default. So `x-payload-hash` differs too, each value valid for its own
  bytes. Parity tests must compare the body as parsed JSON and verify the HMAC over the
  received bytes (as `rs-sdk-scan.md` §2.4 already prescribes).
- **Receipt.** `scan_id` is a plain `String`; the SDK does not check that it is a UUID (observed:
  `"not-a-uuid"` is accepted). `report_id: null` is a `Decode` error, because `Optional` rejects
  an explicit null (observed); TS `.optional()` rejects null as well.
- **Duplicate `req_id`s in one batch are accepted** (observed). The CLI guarantees uniqueness,
  because `req_id` is the input index.

### 2.2 `query_by_scan_ids` and `query_by_report_ids`: safe reads

- **Retry rules.** These calls use `RawRequest::read` (`engine.rs:62-67`), which is
  replay-safe:
  - Retried statuses are 429, 502, 503 and 504 (`engine.rs:1372-1374`), plus transport errors.
    500 is not retried.
  - The budget is `options.retry_limit()`, else `Limits.max_retries`, which equals
    `airsNumRetries` through `configuration::init` (`engine.rs:1135-1139`).
  - The delay is `Retry-After`, else `250 ms · 2^n` capped at 5 s (`engine.rs:1337-1343`).
  - When `Retry-After` exceeds `max_retry_delay` (5 s), there is no retry: the error is returned
    with `retry_after()` set (`engine.rs:1226-1236`).
- **Observed timings:**
  - 429 with `Retry-After: 1` and default options: 3 requests in 2.0 s.
  - The same with `with_retries(0)`: 1 request.
  - `Retry-After: 10`: 1 request, `retry_after = 10 s`.
  - 500: 1 request.
- **TS parity requires `RequestOptions::with_timeout(60 s)?.with_retries(0)?` on every poll and
  report call.** The TS CLI disables SDK retries (`NO_SDK_RETRIES`) and runs its own 429 loop
  (§4.2). Without the override, Rust would add up to `airsNumRetries` silent replays on
  502/503/504. That is not unsafe for a GET, but it changes request counts and timing, which the
  parity rule forbids without a safety reason.
- **Decode** is all-or-nothing per response:
  - Observed: a row with `"req_id": null`, a row whose `result` lacks a required `ScanResponse`
    field (`result: {}`), a `result.prompt_detected: null`, and a non-array body each make the
    whole call fail with `Decode` (status 200).
  - TS fails the same rows the same way: Zod `.optional()` rejects null, and `result` is
    `ScanResponseSchema`.
  - Either way the poll throws, the job stops and the items stay `submitted`. This is parity,
    not a gap.
- **`req_id` decoding** (observed): `2.0` decodes with `as_u64() = None` and `as_f64() = Some(2.0)`;
  `-1` and `1.5` decode too. The CLI must correlate on "an integral finite number in
  `0..=2^53`", not on `as_u64()` alone, because TS `Map.get(2.0)` finds key `2`. Other values
  are uncorrelated rows and are skipped (TS: `entries.get(1.5)` is `undefined`; `cli:src/airs/runtime.ts:377-379`).
- **`status`** is a free string. TS lower-cases it and treats `complete`, `completed` and
  `failed` as terminal (`cli:src/airs/runtime.ts:348-349`); the CLI does the same. Observed:
  `"PENDING"` is passed through unchanged.
- **Report ids** are percent-encoded in the query (observed `report_ids=R1%2CR+2` for
  `["R1","R 2"]`). The comma that joins them is encoded, which matches URLSearchParams in TS.

### 2.3 429 and `Retry-After` visibility (async and poll)

A 429 has `kind() == Http`, `status() == Some(429)`, `failure_kind() == Some(FailureKind::Http)`
and `remote_outcome() == Rejected`. This is the TS `isDefiniteRateLimitError`
(`failureKind === 'http' && statusCode === 429`, `cli:src/airs/runtime.ts:77-80`).

`retry_after()` takes the header first, then the body:

- **Header** (`engine.rs:1375-1393`): delta-seconds, or an HTTP-date converted to "time from
  now".
- **Body** `retry_after{interval,unit}` (`rs:src/error/problem.rs:271-289`, applied in
  `error.rs:220-226`) when the header is absent. TS uses the same header-then-body precedence
  (`tsdk:9842-9846`) and the same unit table (`tsdk:9746-9781`).

Observed:

- header 30 with body 7: 30 s;
- body only: 7 s;
- HTTP-date in 2099: about 2.3·10⁹ s. **The value is unbounded, so the CLI must cap it** (§6.3).

### 2.4 Timeouts and cancellation

- **Deadline.** Build `RequestOptions::with_timeout(60 s)` immediately before each call: the
  deadline is fixed at construction. With zero SDK retries, the Rust total budget equals the TS
  per-attempt timeout. Observed: a hung async POST with a 500 ms budget fails at 501 ms as
  `Deadline`, `Unknown`.
- **Cancel during a call.**
  - In flight, `RequestOptions::cancel()` or `Session::cancel()` gives `Cancelled`/`Unknown`.
  - A pre-cancelled call gives `Cancelled`/`NotSent` with 0 requests.
  - After a session cancel, every later SDK call is `Cancelled`/`NotSent` (observed). The CLI's
    own checkpoint writes after Ctrl-C are local I/O and are unaffected.
- **The CLI's own waits** (the 5 s poll interval and the 429 backoff) are not SDK calls. They
  must `tokio::select!` on `session.cancelled()`, as `topics eval` already does
  (`here:src/commands/topic_eval.rs:617-645`).

---

## 3. Observed outcome matrix (probe, scm-sdk 0.1.0)

| Scenario (`async_scan` unless noted) | kind | status | outcome | requests | other |
|---|---|---|---|---|---|
| 2 objects, 200 receipt | ok | 200 | – | 1 | receipt extension kept |
| 0 or 21 objects | Validation | – | NotSent | 0 | `operation()` None |
| session id 101 / 100 | Validation / ok | – | NotSent / – | 0 / 1 | |
| prompt 2 MiB + 1 | Validation | – | NotSent | 0 | |
| 20 × 1 MiB prompts (body > 8 MiB) | Limit | – | NotSent | 0 | §5 G5 |
| `req_id` 1.5 | Validation | – | NotSent | 0 | |
| `req_id` 2^53+1 | ok | 200 | – | 1 | serialised exactly |
| duplicate `req_id` | ok | 200 | – | 1 | the CLI must prevent it |
| 429, `Retry-After: 30`, `with_retries(5)` | Http | 429 | Rejected | 1 | `retry_after` 30 s |
| 400, 401, 404, 409, 422 | Http | 4xx | Rejected | 1 | |
| 500, 502, 503 | Http | 5xx | Unknown | 1 | |
| 200 with a bad receipt (missing `scan_id`, empty, non-JSON, `report_id: null`) | Decode | 200 | Unknown | 1 | |
| 200 with a non-UUID `scan_id` | ok | 200 | – | 1 | §5 G6 |
| connection refused | Transport | – | **Unknown** | 0 reached | §5 G1 |
| 307 with `Location` | Destination | 307 | Rejected | 1 | not followed |
| 400 / 429 with a 70 KiB body | **Limit** | 400 / 429 | **Unknown** | 1 | `retry_after` lost; §5 G2 |
| hang past a 500 ms deadline | Deadline | – | Unknown | 1 | |
| cancel in flight / pre-cancel / session cancel | Cancelled | – | Unknown / NotSent / Unknown | 1 / 0 / 1 | |
| poll 429, `with_retries(0)` | Http | 429 | Rejected | 1 | |
| poll 429 `RA:1`, default retries (2) | Http | 429 | Rejected | 3 | 2.0 s |
| poll 429 `RA:10`, default | Http | 429 | Rejected | 1 | above the 5 s cap |
| poll 500 / 404 | Http | 500 / 404 | Unknown / Rejected | 1 / 1 | |
| poll non-UUID id, 6 ids, report id with a comma | Validation | – | NotSent | 0 | |

---

## 4. What the TS CLI layers on top (the Rust CLI must do this itself)

### 4.1 Submission (`SdkRuntimeService.submitBatch`, `cli:src/airs/runtime.ts:229-289`)

- **Input checks.** It needs 1–20 prompts with unique non-negative safe indices
  (`:235-248`). `req_id` is the input index (`:250-251`).
- **429 retry loop** (`:258-277`):
  - Only a definitive 429 is retried, up to 5 times.
  - The delay is `retryAfterMs` when it is finite and ≥ 0, else `10 000 ms · 2^(n-1)`.
  - The status line `⚠ Rate limited while submitting — retry <n> in <s>s...` is printed through
    `onRetry` (`cli:src/cli/commands/runtime.ts:372-377`).
  - **There is no cap on `retryAfterMs`** (§6.3).
- **Receipt to entries.** Every entry gets the receipt's `scan_id`; the batch keeps
  `receipt.report_id` (`:279-288`).
- **The caller classifies the error** (`cli:src/cli/commands/runtime.ts:386-393`, `:156-164`):
  `failureKind === 'http' && 400 <= status < 500` means `pending`. Everything else, including
  local SDK validation errors that carry no `failureKind`, means `ambiguous`. Then it rethrows,
  and the command exits 1.

### 4.2 Polling (`pollBatch`, `cli:src/airs/runtime.ts:291-466`)

- **Checks.** It requires the batch invariants first: 1–20 entries, one scan id, and
  `reqId === index`, unique (`:296-313`).
- **The loop** (`:322-463`) calls `queryByScanIds([scanId], {numRetries: 0})`, then:
  - **Rate limits.** `isRateLimitError` (status 429, *or* a message containing `rate limit`,
    `rate_limit` or `429`, `:68-75`) retries up to 5 levels, with the same delay rule and no
    cap. The status line is `⚠ Rate limited — retry <n> in <s>s...`. Any other error rethrows,
    so the job stops and its items stay `submitted`.
  - **A row with `req_id` and status `failed`** becomes a failed row
    (`error: "AIRS async scan failed"`, `:381-386`).
  - **A row with `req_id`, status `complete`/`completed` and a `result`** goes through
    `scanResponseToResult`. A nested `scan_id` that differs from the row's is a correlation
    error (`:388-404`). Fail-closed mapping: `error`/`timeout`/unknown action becomes `failed`
    (`:100-134`).
  - **A terminal row without `req_id`** (`:350-376`):
    - `failed` fails every unresolved entry.
    - `complete` collects a report id from `row.result.report_id`, else `row.report_id`, else
      the receipt's `report_id` (missing → correlation error), then calls
      `queryByReportIds([...], {numRetries: 0})` and maps each report by `req_id` with
      `threatReportToResult` (`:407-445`, `:136-182`).
    - A report whose `scan_id` or `report_id` disagrees is a correlation error.
  - **Retry level** decays by one after each successful poll (`:447`).
  - **Progress bound.** `noProgressPolls` counts successful polls that resolved nothing new; at
    120 the call throws `AIRS polling made no progress after 120 polls for scan <id>`
    (`:449-458`). The poll interval is 5 000 ms (`:19`, `:460-462`).
  - **Checkpoints.** `onProgress` hands newly resolved rows to the caller, which saves the state
    and then rewrites the CSV (`cli:src/cli/commands/runtime.ts:401-406`).
- **Bound.** Each scan id has at most 20 entries, and every progress resets the counter, so one
  `pollBatch` makes at most about 20 × 120 + 120 successful polls plus at most 5 rate-limit
  waits per level. Polling is already bounded (about 3.5 h worst case at 5 s). The Rust port
  keeps the 120-poll rule (parity). It may add a total-time ceiling only if the spec decides one
  is a safety fix. **Flag for the user:** recommend parity (no extra ceiling) for M5.

### 4.3 Classification table for the Rust port (safe, no SDK change)

| SDK result | Item transition | Then |
|---|---|---|
| `Ok(receipt)` with a UUID-shaped `scan_id` | `submitting → submitted` (scanId, receiptReportId, received) | checkpoint, then poll |
| `Ok(receipt)` with a non-UUID `scan_id` | `submitting → ambiguous` (reason: unusable receipt) | checkpoint, stop, exit 1 (§6.6) |
| `Err`, `status() == Some(429)` and `failure_kind() == Some(Http)`, retries left | `submitting → pending` | checkpoint, cancellable wait `min(retry_after, cap)` or `10 s · 2^(n-1)`, re-checkpoint `submitting`, send again |
| `Err`, `remote_outcome() == Rejected` (3xx/4xx), or (G2) `kind() == Limit` with a 4xx `status()` | `submitting → pending` (error recorded) | checkpoint, stop, exit 1 |
| `Err`, `remote_outcome() == NotSent` | `submitting → pending` | checkpoint; Ctrl-C → exit 130/143; otherwise exit 1 |
| `Err`, `remote_outcome() == Unknown` (5xx, transport, deadline, cancel in flight, decode after 2xx) | `submitting → ambiguous` (error kind/status recorded) | checkpoint, stop, exit 1, or 130/143 for a signal |

The rate-limit loop for polls uses `status() == Some(429)` only (§6.4). Polls never change an
item's submission state. An error stops the command with the items still `submitted`, which
`resume-poll` can recover.

---

## 5. SDK limitations (G1–G7): none blocks M5, none needs an SDK patch for M5

| # | Operation | What is missing or different | Evidence | CLI-side handling | Safe? |
|---|---|---|---|---|---|
| G1 | `async_scan` | A connection that was never established (refused, DNS, connect timeout) is `Unknown`, not `NotSent`: `sent` is set before `transport.send`, and the transport error keeps `NotSent`, which the wrapper turns into `Unknown` | `rs:src/engine.rs:1164`, `:1173-1186`, `:1249-1253`; observed "connection refused → Transport, Unknown" | Treat as ambiguous (never resubmit). This is TS parity: a TS network error has `failureKind: 'network'`, which means ambiguous (`tsdk:9800-9813`). The cost is usability: a wrong endpoint wedges the first chunk. The status lines must make that clear | Yes (conservative). **Optional SDK branch:** map connect-phase errors (reqwest `is_connect()`) to `NotSent` |
| G2 | `async_scan`, polls | An error body over `max_error_bytes` (64 KiB) becomes `Limit` with outcome `Unknown` even for a 4xx, and the `Retry-After` header is dropped (`with_metadata` is never reached) | `engine.rs:1210-1213`, `:1249-1253`; observed "400/429 with 70 KiB body → Limit, Unknown, retry_after None" | Classify on `status()`: a 4xx status line is a definitive answer whatever the body, so treat `Limit` with a 4xx status as a rejection (a 429 then uses the computed backoff). This matches DESIGN §6's "Limit with an HTTP error status: treat as Http with that status" and TS, which classifies by status. **Flag for the user:** the conservative alternative is ambiguous | Yes. **Optional SDK branch:** keep `Rejected` and `Retry-After` for an oversized 4xx body |
| G3 | `async_scan` | Local validation errors are bare (`Validation`, no field or text). TS has `At least 1 scan object is required`, `Max of 20 scan objects allowed` and `Request body for POST /v1/scan/async/request did not match schema: …` | `scanner.rs:180-182`; `tsdk:10412-10423`, `:10100-10111` | The CLI pre-validates everything those messages describe (chunking ≤ 20, session id ≤ 100, prompt sizes, the body budget) before the tenant is read or before anything is submitted, so the SDK error is unreachable in practice. As with D116, no field list | Yes |
| G4 | all | `retry_after()` is unbounded (an HTTP-date far in the future gives about 2.3·10⁹ s); the SDK caps only its own safe-read decision | `engine.rs:1375-1393`, `:1226-1236`; observed | The CLI caps every wait it schedules (§6.3) | Yes |
| G5 | `async_scan` | Rust enforces a 2 MiB per-prompt limit (`validate_content`) and an 8 MiB total body (`Limits.max_request_bytes`, also the validation string budget through `contract_limits`). TS has neither on the async path: `ScanRequestContentsInnerSchema` has no max (`tsdk:1526-1533`), and `submitBatch` never builds `Content` | `scanner.rs:183-187`; `rs:src/airs/scan/content.rs:188-216`; `engine.rs:411-422`, `:524-552`; observed "20 × 1 MiB → Limit, NotSent" | (a) Check each prompt ≤ 2,097,152 UTF-8 bytes when the input is loaded, before anything is submitted. (b) At plan time, serialise every SDK chunk exactly as the SDK will and refuse the job up front if one exceeds the request limit. Optionally raise `max_request_bytes` on the bulk scanner client with `client_builder()?.limits(Limits { max_request_bytes: …, max_retries: airsNumRetries, ..Default })` (allowed up to 512 MiB, `config.rs:304-336`). Both refusals happen before any POST, so neither can strand a job. §12 row (§6.1) | Yes. **Flag:** the limit to choose (recommend keeping 8 MiB and refusing up front; AIRS's own server limit is unknown) |
| G6 | receipt | `AsyncScanResponse.scan_id` is not checked as a UUID, but `query_by_scan_ids` requires one. TS has the same split | `generated.rs:5854-5866`; `scanner.rs:238-255`; observed "not-a-uuid accepted"; `tsdk:1726-1731`, `:10475-10479` | Check the receipt's `scan_id` with the UUID shape at once; a bad one makes the chunk `ambiguous` (accepted, but cannot be polled; never resubmitted). §6.6 | Yes |
| G7 | polls | `req_id` is a `FiniteNumber`: `2.0` has no `as_u64()`; negative and fractional values decode | `data.rs:185-210`; observed | Correlate on an integral `as_f64()` in `0..=2^53` (equal to a TS `Map` lookup). Skip other rows | Yes |

Not a gap (parity):

- Scan auth gets no 401/403 refresh. Both SDKs report the error: `Rejected` in Rust, `pending`
  in TS.
- Polls with zero retries behave identically in both.
- Timeouts are equivalent with zero retries. Rust reads no `PANW_AI_SEC_TIMEOUT_MS`, which is
  already covered by the env rows.
- The user agent differs (`rs-sdk-scan.md` §2.2).

Not available in either SDK: a lookup of scans by session id or `tr_id` that could reconcile an
ambiguous submission. Ambiguity is therefore final in both CLIs (manual review). A later
milestone could use the M6d `sessions`/`scan-logs` APIs. Out of scope for M5.

---

## 6. TS behaviours the port must not reproduce (§12 candidates; number from D118)

Each needs a §12 row, a `dNN_` parity test that asserts both sides, and a COMPATIBILITY.md row.
The numbering is a proposal; the spec step assigns the final numbers.

1. **Local refusals are "ambiguous" in TS** (D118 candidate, correctness).
   - What TS does: `--session-id` over 100 characters fails Zod in `request()` before any fetch
     (`tsdk:10100-10111`). The `AISecSDKException` carries no `failureKind`, so
     `isDefiniteSubmissionRejection` is false (`cli:src/cli/commands/runtime.ts:156-164`).
     The chunk is saved as `ambiguous`, and `resume-poll` then refuses the job forever
     (`:952-959`). TS also sends prompts over 2 MiB, and bodies of any size.
   - Rust:
     - validate `--session-id` (≤ 100 UTF-16 units) as a usage error, exit 2, before the tenant
       is read;
     - validate prompt sizes when the input is read and the per-chunk body budget at plan time,
       both before anything is submitted (G5);
     - any `NotSent` that still occurs leaves the items `pending`.
2. **Output overwrite** (D119 candidate, safety; settled).
   - TS writes the empty projection to `--output-file` (or `<profile>-bulk-scan.csv`) before the
     first POST, silently replacing any existing file (`cli:src/cli/commands/runtime.ts:352`,
     `:140-154`; integration test "replaces stale output with the current empty projection
     before the first POST").
   - Rust refuses an existing path, or a symlink, before anything is submitted. It then claims
     the path with `O_CREAT|O_EXCL|O_NOFOLLOW` (header-only CSV) and rewrites only its own file
     atomically. `resume-poll --output-file` to a different, pre-existing file is refused.
3. **Unbounded `Retry-After`** (D120 candidate, safety).
   - The TS CLI waits `retryAfterMs` with no cap (`cli:src/airs/runtime.ts:269-275`,
     `:331-337`). Node's `setTimeout` treats any delay above 2³¹−1 ms as 1 ms, so a far-future
     HTTP-date turns into an immediate hammering retry.
   - Rust uses `min(retry_after, 60 s)` (the TS SDK's own cap for its retries, `tsdk:9828`), and
     every wait is cancellable. **Flag:** 60 s is recommended. The alternative is to stop when
     the server asks for more than the cap.
4. **Rate-limit detection by message text** (D121 candidate, correctness).
   - TS `isRateLimitError` also retries any error whose *message* contains `rate limit`,
     `rate_limit` or `429` (`cli:src/airs/runtime.ts:68-75`), for example a 503 whose body
     mentions rate limits.
   - Rust: status 429 only (the SDK keeps no message text). Already noted in `rs-sdk-scan.md` §7.
5. **Redirects on the async POST and the polls** (extend D30 or add D122, safety).
   - TS fetch follows 307/308, re-POSTing the body and `x-pan-token` to `Location`.
   - Rust never follows: `Destination`/`Rejected`, so the items stay `pending` (observed).
6. **Unusable receipt** (D123 candidate, correctness).
   - A non-UUID `scan_id` is stored as `submitted` in TS, and every later poll fails with a
     payload error.
   - Rust records the chunk as `ambiguous` with the reason, and never polls or resubmits it (G6).
7. **Job lock** (D124 candidate, safety; settled flock).
   - TS uses a `link()`-installed JSON lock with pid-liveness recovery
     (`cli:src/cli/bulk-scan-lock.ts:49-111`):
     - a reused pid wedges the job ("already active in process N" forever);
     - a lock on a shared home is "recovered" by a host where that pid is not alive, so two
       hosts own one job;
     - a malformed lock needs manual removal.
   - Rust: `flock` (§8). No stale locks, no manual removal. A holder record is shown on
     refusal.
8. **Interruption** (D125 candidate, safety).
   - TS installs no SIGINT handler. Ctrl-C kills the process with no message, which leaves
     `submitting` items (treated as ambiguous on resume).
   - Rust: the signal thread cancels the session, so an in-flight call ends `NotSent` or
     `Unknown`. The CLI checkpoints the resulting states (§7.3), names the state file in
     `Interrupted; …`, and exits 130/143.
9. **State location and format** (D126 candidate; settled).
   - TS: `<dirname(dataDir)>/bulk-scans/<createdAt>-<uuid>.bulk-scan.json`, version 2
     (`cli:src/cli/commands/runtime.ts:329-333`; `cli:src/cli/bulk-scan-state.ts:134-165`). TS
     writes it with no fsync, no owner or symlink checks, and `chmod`s an existing directory
     to 0700.
   - Rust:
     - `$XDG_STATE_HOME/airs-cli/bulk-scans/` with the §7 format;
     - `resume-poll` refuses a TS file with a clear message;
     - the `dataDir` key does not exist (D71).
10. **Resuming a moved or copied state, or under another tenant** (D127 candidate, safety).
    - TS resumes any state file with the active tenant. Resuming a stale *copy* after the
      original moved on resubmits prompts the original already submitted (duplicates).
      Resuming under another tenant submits the pending prompts to the wrong account, and polls
      scan ids that do not belong to it.
    - Rust: the state records its canonical path and tenant name, and `resume-poll` refuses a
      mismatch (§7.4). **Flag for the user:** this is the recommendation, but it is a new
      refusal TS does not have.

Kept for parity (no row):

- the item states;
- `reqId === index`;
- sequential logical batches of `--batch-size` (default 25), each split into SDK chunks of ≤ 20;
- polling a logical batch completely before the next one is submitted;
- the 120-poll no-progress bound and the 5 s interval;
- a 10 s base backoff with 5 retries per level;
- the CSV columns and quoting (`cli:src/airs/runtime.ts:597-622`);
- failed rows plus exit 1 with the successful rows kept;
- `resume-poll`'s order: poll the receipts, then submit `pending`, then poll;
- the ambiguous refusal text, which still names the state file.

The default session id `prisma-airs-cli-bulk-<base36 ms>` (`cli:src/cli/commands/runtime.ts:325`)
is visible in the AIRS dashboard. **Flag:** recommend keeping that exact prefix for parity.

---

## 7. Proposed state file and write protocol (exactly-once safety)

### 7.1 Location and names

- **Directory.** `S = $XDG_STATE_HOME/airs-cli/bulk-scans/`. Without `XDG_STATE_HOME`, use
  `<home>/.local/state/airs-cli/bulk-scans/`, resolved exactly like the debug log directory
  (DESIGN §2.9: absolute only, the same errors).
  - It is created recursively with mode 0700. An existing directory is never chmod'ed.
  - Every use checks it with the §3.8 directory rule: `symlink_metadata`, a directory and not a
    symlink, owned by the euid, `mode & 0o022 == 0`. For listing and unlinking it is opened
    with `O_DIRECTORY|O_NOFOLLOW` and `fstat`-checked.
  - **Flag:** whether to require `mode & 0o077 == 0` on this directory, because prompts are
    sensitive. Recommend 0o022 for consistency with §3.8: the files themselves are 0600.
- **Job id.** `<UTC yyyymmddThhmmssZ>-<16 lowercase hex>`, the hex from 8 random bytes
  (`uuid` v4's source, as §3.9 temp names). It is sortable and unique.
- **Files** in `S`:
  - `<job>.state.json`: the state;
  - `<job>.lock`: the job lock, §8;
  - temporaries `.<job>.state.json.<pid>.<16 hex>.tmp`.
- **File rule.** Every state or lock file is opened `O_NOFOLLOW|O_CLOEXEC` and checked with the
  §3.8 file rule (same dev/inode before and after open, regular, euid-owned,
  `mode & 0o077 == 0`).

### 7.2 Schema (JSON, `serde(deny_unknown_fields)`, camelCase, 2-space pretty + `\n`)

```json
{
  "format": "airs-cli-rs.bulk-scan",
  "version": 1,
  "jobId": "20261017T120000Z-3f9c0a1b2c3d4e5f",
  "statePath": "/home/u/.local/state/airs-cli/bulk-scans/20261017T120000Z-3f9c0a1b2c3d4e5f.state.json",
  "tenant": "redtail-prod",
  "scanEndpoint": "https://service.api.aisecurity.paloaltonetworks.com",
  "profile": "Prisma AIRS Harness",
  "sessionId": "prisma-airs-cli-bulk-mgx1a2b3",
  "batchSize": 25,
  "input": { "path": "/abs/prompts.csv", "prompts": 4 },
  "output": { "path": "/abs/out.csv", "dev": 16777230, "ino": 1234567 },
  "createdAt": "2026-10-17T12:00:00.000Z",
  "updatedAt": "2026-10-17T12:00:09.412Z",
  "sequence": 7,
  "attempts": [
    { "id": 1, "indices": [0, 1], "startedAt": "…", "endedAt": "…",
      "outcome": "accepted", "status": 200, "scanId": "…" },
    { "id": 2, "indices": [2, 3], "startedAt": "…", "endedAt": null,
      "outcome": "inFlight" }
  ],
  "items": [
    { "index": 0, "reqId": 0, "prompt": "…", "status": "complete", "attempt": 1,
      "scanId": "…", "receiptReportId": "R…",
      "result": { "action": "allow", "category": "benign", "triggered": false,
                  "detections": { "topic_violation": false, "injection": false, "…": false },
                  "scanId": "…", "reportId": "R…" } },
    { "index": 2, "reqId": 2, "prompt": "…", "status": "submitting", "attempt": 2 }
  ]
}
```

- **Item `status`** ∈ `pending | submitting | submitted | complete | failed | ambiguous`, the TS
  set.
- **Attempt `outcome`** ∈ `inFlight | accepted | rejected | notSent | unknown`.
  - `status` is the HTTP status when there was one.
  - `error` is the CLI's secret-safe message, built from SDK metadata (DESIGN §6). It never
    contains server text.
- **The attempt journal** is new. It records which prompts went out together, when, and with
  what outcome. That is the evidence a user needs to review an ambiguous chunk manually (time
  window and session id), and the live tier counts submissions from it (§9).
- **`result`** is the normalised row, with the §8.3 secret withholding already applied, so the
  state and the CSV hold the same values. It is not the raw `ScanResponse`. The prompt is
  stored once, on the item.
- **`scanEndpoint`** is the origin only. `tenant` is the store name. Neither is a secret, and the
  file never holds a credential.
- **`output.dev`/`ino`** identify the last output file this job wrote (§7.5).

**Load-time invariants** (port of `cli:src/cli/bulk-scan-state.ts:53-132`, plus additions). Any
violation is `Invalid bulk-scan state <path>: <reason>` (exit 1). The same check runs before
every write: TS also refuses to persist an invalid state (`:141-145`).

- `format` and `version` are exact.
  - An unknown version: `written by a newer airs-cli-rs`.
  - A TS file, recognised by `"version": 2` and no `format` key:
    `<path> is a TypeScript airs-cli bulk-scan state; airs-cli-rs cannot resume it (resume it with airs-cli, or start a new airs-cli-rs runtime bulk-scan)`.
- `items` is non-empty, `index == position`, `reqId == index`.
- `submitted | complete | failed` require a UUID-shaped `scanId`.
- `pending | submitting | ambiguous` have no `scanId`.
- `complete | failed` require a `result`; the other states have none.
- `result.scanId == scanId`; `failed` ⇔ `result.action == "failed"`; `complete` ⇒ `allow|block`.
- `submitting` ⇒ its `attempt` exists with outcome `inFlight`.
- Every attempt index refers to an item.
- At most 20 items share one `scanId`, and they share `receiptReportId`.
- `profile` is 1–100 characters, `sessionId` ≤ 100, `batchSize` in `1..=2^53−1`.
- The file is at most a fixed size (**flag:** recommend 4 × the input-file limit).

### 7.3 Write protocol: `checkpoint(state)`

1. Validate the invariants, then `sequence += 1` and `updatedAt = now`. Serialise.
2. Create the temp `.<job>.state.json.<pid>.<hex>.tmp` in `S` with
   `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode 0600, then `fchmod 0600`.
   `write_all`, `fsync`, close.
3. If `<job>.state.json` exists, it must pass the §3.8 file rule, and its (dev, ino) must equal
   what this process last renamed into place, so that a foreign replacement during the job is
   detected. On a mismatch, stop: `<path> was changed by another program; the job was stopped`.
4. `rename(temp, state)`, then `fsync(S)`. **Unlike §3.9, a failed directory fsync is a
   checkpoint failure, not a warning**, because this checkpoint is the durability guarantee.
5. On failure at 2–4, unlink the temp (best effort) and fail with
   `Cannot save <state>; …` (the OS error is never echoed), with a suffix that depends on the
   point in the job:
   - before a submission: `no further prompts were submitted` (nothing is sent);
   - after a receipt: `prompts <i>–<j> were accepted under scan <scan id>, but the job state could not be saved`
     (scan ids are printable; the on-disk state still says `submitting`, so a resume treats the
     chunk as ambiguous);
   - after results: `results since the last save will be polled again by resume-poll`.

**Ordering per SDK chunk.** This is the exactly-once core. Every arrow is a completed
`checkpoint`.

| Step | Durable state before the network call | Network | Crash here leaves | `resume-poll` does |
|---|---|---|---|---|
| C1 | chunk items `submitting`, attempt `inFlight` | – | `submitting` | treats it as ambiguous; never resubmits |
| C2 | (C1) | **one** `async_scan`, a fresh 60 s `RequestOptions` | `submitting` | the same |
| C3 accepted | items `submitted` + receipt, attempt `accepted` | – (checkpointed **before the first poll**) | `submitted` | polls it |
| C3 429, retries left | items `pending`, attempt `rejected` 429 | cancellable wait, then back to C1 with a new attempt | `pending` | resubmits (safe: the server refused it) |
| C3 rejected / not sent | items `pending`, attempt `rejected`/`notSent` | – | `pending` | resubmits |
| C3 unknown | items `ambiguous`, attempt `unknown` | – | `ambiguous` | refuses after polling the known receipts |
| Poll | – | `query_by_scan_ids` (`with_retries(0)`, 60 s) | `submitted` | polls again (idempotent) |
| Poll progress | newly terminal results | – | `complete`/`failed` | nothing to redo |

- **Output ordering.** After each state checkpoint that recorded results, the CSV projection is
  rewritten (§7.5). The output is never written ahead of the state. A failed output write stops
  the job with `results are saved in <state>; run resume-poll to rewrite <output>` (exit 1).
- **The 429 pending-and-resubmit cycle is internal.** TS keeps `submitting` across its 429
  waits, so a TS crash during a wait looks ambiguous. Rust records the definitive rejection
  first. This is an internal improvement with no observable CLI difference, so no row.
- **Signals.**
  - The signal thread cancels the session, and the in-flight call returns `NotSent` or
    `Unknown`. The CLI applies the table above (local I/O only), then fails with
    `Interrupted; <context>` and exits 130/143.
  - Context strings (proposal):
    - `no prompt was submitted; the job state was saved: <state>`;
    - `<n> prompts were submitted; resume with airs-cli-rs runtime resume-poll <state>`;
    - when a chunk became ambiguous:
      `prompts <i>–<j> may already have been submitted (outcome unknown); the job state was saved: <state>`.
  - A second signal exits at once. The worst case is a durable `submitting`, which a resume
    treats as ambiguous: conservative and never a duplicate.
  - A signal during a checkpoint lets the checkpoint finish (§3.9 rule).

### 7.4 `bulk-scan` and `resume-poll` order of operations (proposal)

**`bulk-scan`:**

1. Usage validation, exit 2, before the tenant:
   - `--profile` 1–100 characters;
   - `--file` present;
   - `--batch-size` a positive safe integer (TS text `--batch-size must be a positive integer`);
   - `--session-id` ≤ 100.
2. Open the debug log.
3. Load the tenant and check the scanner credentials.
4. Read the input file (bounded) and parse it. With no prompts, the TS usage error
   `No prompts found in input file` (exit 2). Check each prompt ≤ 2 MiB, then plan the chunks
   and check each chunk body (G5).
5. Resolve the output path. Refuse an existing path or symlink.
6. Ensure and check `S`, then create the job id.
7. Create and lock `<job>.lock` (§8).
8. Claim the output (`O_EXCL`, header-only CSV, fsync, directory fsync).
9. Write the first checkpoint: every item `pending`.
10. Build the scanner and print the status lines (TS text, with `State:` naming the Rust path).
11. Logical batches → chunks → C1–C3 → poll.
12. Final projection, summary, exit 0, or exit 1 when a row failed.

A failure before step 11 removes the claimed output and the state (both created by this
process, under its lock; best effort). Nothing was submitted.

**`resume-poll <stateFile> [--output-file <f>]`:**

1. Usage validation.
2. Open the debug log.
3. `realpath` the state file, then apply the §3.8 file and directory checks.
4. Lock `<job>.lock` next to it. The job id is taken from the file name; the name must match
   `<job>.state.json`. **No state decision is made before the lock is held.**
5. Read and validate the state (the TS-file refusal included).
6. Refuse when `statePath` ≠ the realpath (moved or copied state), or when the selected tenant
   ≠ `tenant` (§6.10).
7. Load the tenant and credentials.
8. Sweep stale temps for this job (the §3.9 step 4 pattern, restricted to `.<job>.state.json.*.tmp`).
9. Resolve the output (§7.5).
10. Convert any `submitting` item to `ambiguous` and checkpoint. The state then says what the
    process knows.
11. If any item is `ambiguous`: poll every `submitted` receipt, write the projection, then fail
    with the TS text
    `Cannot safely resubmit prompt <i>: its submission outcome is ambiguous. Known accepted results were preserved; inspect <state> before taking manual action.`
    (exit 1).
12. Otherwise, per logical batch: poll the `submitted` items, submit the `pending` ones (C1–C3),
    then poll again.
13. Final projection, summary, exit code as `bulk-scan`.

On a completed state, steps 10–12 send **zero requests**. The live tier relies on that (§9).

### 7.5 Output CSV

- **Content.** The TS projection, byte for byte:
  - the header plus every resolved item in input order;
  - every field double-quoted with `"` doubled;
  - `\n` between lines and no trailing newline (`cli:src/airs/runtime.ts:597-622`).
- **Write.** A temp `.<name>.<pid>.<hex>.tmp` in the output's directory (`O_EXCL|O_NOFOLLOW`,
  0600, TS mode), then fsync and rename. The directory fsync is a warning only: the output can
  always be rebuilt from the state.
- **Identity check before each rename.** The path must be a regular, euid-owned file whose
  (dev, ino) equals the state's `output` record, updated after every rename. Otherwise the job
  stops: `<output> was changed by another program; results are in <state>`.
- **`resume-poll` without `--output-file`** uses the recorded path:
  - absent: claim it again with `O_EXCL`;
  - present with the recorded identity: rewrite it;
  - present with another identity: refuse.
- **`resume-poll --output-file <f>`:**
  - `f` equals the recorded path: as above;
  - `f` does not exist: claim it, and it becomes the job's output (recorded; TS also re-points
    `outputFile`, `cli:src/cli/commands/runtime.ts:930-932`);
  - `f` exists: refuse with `<f> already exists; choose another --output-file` (D114 text).
- **Flag:** the identity check is stricter than the settled rule requires. It is the
  recommended way to enforce "never overwrite a file the job did not write".

---

## 8. Proposed job lock (`flock`)

- **File.** `<S>/<job>.lock`, next to the state. It is opened
  `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC` with mode 0600 (`fchmod` on creation) and checked with
  the §3.8 file rule. `bulk-scan` creates it with `O_EXCL`, because the job id is fresh.
- **Acquire.** `flock(LOCK_EX|LOCK_NB)` (`rustix::fs::flock`, as in `here:src/store/lock.rs`).
  - **Refusal is immediate**, which is TS parity: TS does not wait either.
  - `EWOULDBLOCK` gives
    `Bulk-scan job is already active in process <pid> on <host> since <since>. Wait for it to finish before resuming <state>.`
    (the TS text, `cli:src/cli/bulk-scan-lock.ts:102-106`, with the holder record). The holder
    becomes `another process` when the record is malformed (exit 1, nothing sent).
  - `ENOLCK`, `EINVAL` or `EOPNOTSUPP` give
    `Cannot lock <lock>; the file system may not support file locks` (exit 1).
- **Holder record.** After acquisition: `ftruncate(0)`, then
  `pid=…\nhost=…\nsince=…\n` at offset 0. Reuse `store::lock::holder_record` and `holder_text`
  (`here:src/store/lock.rs:72-168`). It is read with a bounded `pread` only when a lock attempt
  fails, and printed through `terminal_safe`. It is not fsynced.
- **Held** from before the first byte of state is written (`bulk-scan`) or read (`resume-poll`)
  until after the final output write. Released with `ftruncate(0)` and close.
- **Never unlinked.** Unlinking a `flock` file races with a process that has already opened it
  (§3.9 rule 5), so each job leaves one empty `.lock` behind.
  - **Flag:** if the user wants lock files removed when a job completes, the safe pattern is:
    after acquiring, `fstat` the descriptor and `statat` the name. If the name is gone or names
    another inode, close and retry once. Then a completed job may unlink its lock while holding
    it. Not recommended for M5.
- **Crashes.** The kernel releases the lock when the holder dies, so there are no stale locks
  and no pid-liveness guess (§6.7).
- **Scope.** The lock covers one job, so jobs with different ids run concurrently, as in TS. Two
  jobs cannot share an output: the `O_EXCL` claim refuses the second. The tenant-store lock
  (`D/config.lock`) is unrelated, and bulk scanning never takes it.
- **Test ports.**
  - TS "allows only one owner and releases for a later invocation" maps to the harness
    `lock_holder` holding `<job>.lock`: `resume-poll` refuses at once (exit 1, 0 requests, holder
    shown), then succeeds after release.
  - TS "recovers a lock whose owner process is no longer running" maps to a SIGKILLed holder:
    the next run acquires the lock with no manual step. The lock file stays (it is not
    `ENOENT`, unlike TS). That is a `dNN_` row (§6.7).
  - TS integration "prevents overlapping resume processes from submitting the same pending
    prompt" maps to two concurrent `resume-poll` runs: exactly one sends the POST.

---

## 9. Proposed live-tier design for M5 (within the LIVE RULES)

### 9.1 Opt-in and budget

- **Gate.** `live_bulk` in `tests/live.rs` and a `live::bulk` module in the harness. It runs only
  with `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT=<name>` and `AIRS_RS_LIVE_BULK=1`. Otherwise it prints
  `LIVE SKIPPED: …`.
- **Profile.** `AIRS_E2E_PROFILE` must be `Prisma AIRS Harness`; anything else fails before
  starting, as in `live::eval`.
- **Budget.** `AIRS_RS_LIVE_BULK_PROMPTS`: default 4, range 2–8 per CLI; anything else fails the
  run before anything is opened. The minimum of 2 lets the flow make two logical batches. The
  planned total (the prompt count for Rust, plus the same count for TypeScript when its step
  runs) is checked before the first run.
  - Each run reserves its prompts first: `bulk-scan` reserves N, a resume reserves the number of
    `pending` items in the Rust state, and the no-op resume reserves 0.
  - A run that would exceed the budget is not started.
  - The flow is its own run, separate from `live_eval`.
  - **Flag:** the per-CLI budget gives up to 16 billed prompts per flow at the cap, beyond the
    "8 scans per run" line in MILESTONES. Recommend keeping 4 as the default (8 billed prompts
    in total).
- **Prompts.** A fixed, harmless 4-line `.txt` file written to the run's temp directory: two
  benign prompts and two plain prompt-injection probes. With N < 4, the first N lines are used.

### 9.2 Environment and isolation

The flow uses the existing `Session`:

- the isolated registry, the private Rust store via `tenant import`, fingerprints, leak checks
  and removal on panic;
- the cleared environment `PATH`, `HOME=<sandbox>/home`, `TMPDIR=<sandbox>/tmp`,
  `PRISMA_AIRS_TENANTS_PATH=<isolated registry>` and `NO_COLOR=1`.

**Rust runs:**

- `XDG_STATE_HOME=<sandbox>/tmp/state`, so state and debug logs are under the run's temp
  directory;
- cwd `<sandbox>/tmp/rs`;
- `--output-file <sandbox>/tmp/rs/out.csv`;
- `--session-id airs-rs-e2e-<run id>-rs`.

**TypeScript run.** Its state directory is `<dirname(dataDir)>/bulk-scans`, with `~` expanded
through `os.homedir()`, which is `$HOME` (`cli:src/config/loader.ts:13-15`, `:91`;
`cli:src/cli/commands/runtime.ts:329-333`). The flow inspects the in-memory tenant config it
already hashes, and never prints it:

- **No `dataDir` key, or a value that starts with `~`:** the state lands under
  `<sandbox>/home/…`. Run TS with:
  - cwd `<sandbox>/tmp/ts`;
  - `--output-file <sandbox>/tmp/ts/out.csv`;
  - `--session-id airs-rs-e2e-<run id>-ts`.

  Afterwards, assert that exactly one `*.bulk-scan.json` exists under
  `<sandbox>/home/.prisma-airs/bulk-scans/` (or the `~`-relative equivalent) and that the
  fingerprints are unchanged. Otherwise abort with an integrity error.
- **Any other `dataDir`** (absolute or relative): **skip the TS step** with
  `LIVE NOTICE: TypeScript bulk-scan skipped: its state directory cannot be redirected into the sandbox`.
  Compare Rust only.

The TS run never gets the real `HOME`, never runs in the repository cwd, and never receives a
path outside the sandbox.

### 9.3 Flow

1. **R1, interrupted Rust bulk-scan.**
   - Command: `bulk-scan --profile "Prisma AIRS Harness" --file <prompts> --batch-size <ceil(N/2)> --debug`.
   - The runner watches stderr. On the first `Scan IDs saved:` line it sends SIGINT. That line
     is printed after batch 1's receipts are checkpointed (C3), so the signal is triggered by
     an event, not a timer.
   - Expected: exit 130 with `Interrupted; …` naming the state, or exit 0 if the run finished
     before the signal landed.
2. **Inspect the state** (exactly one `*.state.json` under `<sandbox>/tmp/state/airs-cli/bulk-scans/`).
   - Count the submitted prompts from its attempt journal and assert ≤ N.
   - Two outcomes are accepted, and each has deterministic assertions:
     - **(a) Recoverable:** no `ambiguous` item.
     - **(b) The signal landed during batch 2's POST:** that chunk is `ambiguous`.
   - Anything else (for example an ambiguous item with no signal) fails the flow.
3. **R2, `resume-poll <state> --debug`.**
   - **(a):** expect exit 0. In R2's debug log, the `airs.scan.async` records must equal the
     number of chunks of `pending` items at R2's start. The final CSV has N rows in input order,
     each with `allow|block`, a nonempty scan id and a nonempty report id.
   - **(b):** expect exit 1 with the ambiguous refusal. R2's debug log has **zero**
     `airs.scan.async` records: the ambiguous chunk is never resubmitted. The CSV holds the
     rows of the known receipts. The flow then stops the Rust part as passed, with a note.
4. **R3, `resume-poll <state> --debug` on the completed state ((a) only).**
   - Expect exit 0, with **zero** debug-log records of any kind: nothing to poll and nothing to
     submit.
   - The CSV is byte-identical to R2's.
   - Total submitted prompts across R1–R3 equal N. **This is the "recovery without new
     submissions" proof.**
5. **T1, TypeScript `bulk-scan` (if not skipped).**
   - Command: the same prompts and `--batch-size`, uninterrupted.
   - Expect exit 0.
   - Compare the per-row verdict tokens (action, category, triggered, the 8 detection flags)
     between `rs/out.csv` and `ts/out.csv` by input index. Mismatches are reported and do not
     stop the flow. Ids are never compared or printed.
6. **Summary.** `target/live/summary-bulk.json` holds the check names, exit codes, counts
   (prompts planned and submitted, async records per run), the branch taken ((a) or (b)) and the
   verdict agreement. It never holds prompts, ids, paths or values.

**Fixture self-tests:** `live_bulk_self_test_against_fixture`, using `LiveTarget::loopback`.
They need fixture routes for `/v1/scan/async/request`, `/v1/scan/results` and
`/v1/scan/reports` with scripted rows. Fixture rules can delay the first result so that branch
(a) is forced deterministically, or make batch 2's POST hang until the signal so that branch (b)
is forced. Both branches are therefore tested on loopback without depending on timing.

---

## 10. Acceptance criteria (SDK-facing; for the executable and parity tests)

- **Chunk size.** A chunk of 20 prompts sends exactly one `POST /v1/scan/async/request`, even
  on 429, 5xx, a transport failure or a deadline. A plan that would need a 21-object call never
  sends one: chunks are ≤ 20.
- **Body.** It parses to `[{"req_id":<index>,"scan_req":{"ai_profile":{"profile_name":P},"contents":[{"prompt":X}],"session_id":S}}…]`
  with `req_id` equal to the input index. `x-payload-hash` is the HMAC of the received bytes.
  Compare TS bodies semantically: their key order differs.
- **Polls.** Every poll is `GET /v1/scan/results?scan_ids=<one receipt id>` with no body, and
  sends exactly one request on 429, 502, 503 or 504. The CLI does its own 429 wait.
- **429 on submission.**
  - With `Retry-After: 1`, the CLI retries the same chunk after about 1 s, up to 5 times. Then
    the items are `pending` and the exit is 1.
  - A `Retry-After` in the year 2099 waits the cap, not forever and not 1 ms.
- **Classification.** 400, 401, 403, 404, 409 or 307 on submission leaves the items `pending`.
  500, 503, a dropped connection, a refused connection, a deadline, or a 200 with a bad receipt
  leaves them `ambiguous`. In both cases the state on disk says so before the process exits.
- **Local refusals.** `--session-id` of 101 characters is exit 2 with 0 requests. A prompt over
  2 MiB, or a chunk over the body budget, is refused before any POST.
- **Unusable receipt.** A receipt with a non-UUID `scan_id` leaves the chunk `ambiguous` with 0
  polls.
- **Correlation.** Result rows with `req_id` `2.0` correlate to index 2. Rows with `-1`, `1.5`
  or another `scan_id` are ignored.
- **Fail closed.** `timeout: true`, `error: true` or an unknown action in a `complete` row
  becomes a `failed` CSV row, and the exit is 1.
- **Fallback.** A `complete` row without `req_id` triggers one `GET /v1/scan/reports` for the
  report id.
- **Interruption.** SIGINT during a hung async POST exits 130. The state shows the chunk
  `ambiguous` (`Unknown`). SIGINT before dispatch shows it `pending`. SIGINT during a poll
  wait shows the items `submitted`.
- **Crash point.** A run killed (SIGKILL) between the `submitting` checkpoint and the receipt
  leaves `submitting`. `resume-poll` then refuses to resubmit it and sends 0 async POSTs.

---

## 11. Open questions (for the user)

1. G2: treat a `Limit` error with a 4xx status as a definitive rejection (recommended; TS
   parity by status), or as ambiguous?
2. Is the `Retry-After` cap 60 s (recommended)? Or stop when the server asks for more than
   the cap?
3. Refuse `resume-poll` of a moved or copied state, and under a different tenant than the one
   that started the job (recommended; §6.10)?
4. Keep the TS default session prefix `prisma-airs-cli-bulk-` (recommended), or use an
   `airs-cli-` prefix?
5. Keep the request-body limit at 8 MiB and refuse oversized chunks up front (recommended), or
   raise `max_request_bytes` for bulk scanning?
6. Check the output identity (dev, ino) before each rewrite (recommended), or check only that
   the path is a regular file?
7. Should the live budget of 4 prompts per CLI (cap 8, so up to 16 billed prompts per flow) be
   reconciled with the MILESTONES "8 scans per run" line, for example by counting both CLIs
   against 8?
8. Never unlink job lock files (recommended), or remove them on completion with the inode
   re-check?
9. SDK branch (optional, not needed for M5): report connect-phase failures as `NotSent` (G1),
   and keep `Rejected` and `Retry-After` for an oversized 4xx body (G2)?
