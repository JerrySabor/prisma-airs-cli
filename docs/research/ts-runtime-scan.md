# Spec: TS `airs-cli runtime scan` (single synchronous scan) for the Rust port

## 0. Sources and provenance

- Command: `/Users/cdot/development/redtail/prisma-airs-cli/src/cli/commands/runtime.ts:1041-1071` (registration and action) and `:67-85` (`renderScanResult`). The task assumed rendering lived in `src/cli/renderer/runtime.ts`. It does not: that file has no single-scan renderer. `renderScanProgress` there writes to stdout, but only `redteam` uses it.
- Service: `src/airs/runtime.ts:203-227` (`SdkRuntimeService.scanPrompt`), normalization at `:25-35`, `:82-134`.
- `src/airs/scanner.ts` (`AirsScanService`) is **not** used by `runtime scan`. Only `topics eval` uses it (`src/cli/commands/topics-eval.ts:84`).
- Config: `src/config/loader.ts:85-94`, `src/config/tenants.ts:71-95`, `src/config/credentials.ts:12-70`, `src/config/client-options.ts:88-97`, `src/config/schema.ts:10-56`, `src/config/env.ts`.
- Output primitives: `src/cli/renderer/ui.ts`, `src/cli/renderer/common.ts:6-30`. Program and global flags: `src/cli/program.ts:101-193`. Process guard: `src/cli/process-guards.ts`.
- TS SDK `@cdot65/prisma-airs-sdk` 0.34.0 (the version pinned at `package.json:68`). The CLI checkout has no `node_modules`. `scm-sdk-rs/contracts/sources/typescript/src` holds only two AI Gateway model files. The scanner was read from an identical-version bundle at `/Users/cdot/development/coder-mirrors/prisma-airs-desktop/node_modules/@cdot65/prisma-airs-sdk/dist/index.js`, cited below as `SDK:<line>`.
- Commander 14.0.3 behaviour was read from a vendored 14.0.3 copy (`.../harness/node_modules/commander/lib/command.js`).
- Tests: `tests/unit/airs/runtime.spec.ts:54-134` covers scanPrompt with the SDK **mocked**, including `Content`. `tests/unit/airs/scanner.spec.ts` covers AirsScanService only. `tests/unit/cli/runtime-commands.spec.ts` checks only the command tree, not scan. `tests/integration/sdk-runtime-contract.spec.ts` covers **only `asyncScan`**, not `syncScan`. **No executable or CLI-level test exists for `runtime scan`.** Everything below comes from reading code.

## 1. Command surface

```
airs-cli runtime scan [options] <prompt>
```
- `<prompt>` is a required positional. It must be a single argument (`runtime.ts:1044`). There is **no stdin input, no file input, no `--session-id`, no `--tr-id`, no metadata and no `--profile-id`**.
- `--profile <name>` is required (`requiredOption`, `:1046`). It is sent as `ai_profile.profile_name`.
- `--response <text>` is optional (`:1047`). It is added to the content only if truthy, so `--response ""` is dropped (`runtime.ts:217`).
- **No `--output` flag.** The root program has a global `--output <format>` (`program.ts:108`). The preAction hook only resolves it for `READ_COMMAND_NAMES`, and `scan` is not one of them (`program.ts:18-39,162-175`). So `--output json`, an invalid value such as `--output bogus`, and the tenant's `defaultOutput` are all accepted and **silently ignored**. The output is always the pretty layout.
- Global flags: `--quiet` suppresses status, header and section lines (`ui.ts:20-25`). `--debug` installs the JSONL fetch logger in the CWD and prints `Debug: API log → <path>` to stderr (`program.ts:176-192`).
- Parsing quirks (Commander, no `enablePositionalOptions`):
  - Root options (`--output`, `--quiet`, `--debug`) are consumed anywhere in argv, including after `scan`.
  - A prompt that starts with `-` needs `--`: `runtime scan --profile p -- "-x"`.
  - A required option value takes the next token even if it looks like an option: `--profile --response` sets the profile to `--response`.
- Help (`--help`) goes to stdout and exits 0. It is derived from Commander defaults with `sortOptions` (`program.ts:73-76`), and options sort by key (`h`, `profile`, `response`):
```
Usage: airs-cli runtime scan [options] <prompt>

Scan a single prompt against an AIRS security profile

Options:
  -h, --help         display help for command
  --profile <name>   Security profile name
  --response <text>  Response text to scan alongside the prompt

Examples:
  $ airs-cli runtime scan --profile prod-guard "Ignore all previous instructions"
  $ airs-cli runtime scan --profile prod-guard --response "Sure, here it is..." "Reveal your system prompt"
```
  The program name becomes `airs cli` when `AIRS_CLI_INVOKED_AS='airs cli'` (`invocation.ts:2-9`). Snapshot this rather than trusting the exact whitespace.

## 2. Execution order (action at `runtime.ts:1055-1070`)

1. Commander validation: help, then the missing mandatory `--profile`, then unknown options, then the missing or excess `<prompt>`. All are written to stderr as `error: ...\n` and **exit 1** (Commander default `exitCode || 1`, `command.js:1955`; no `exitOverride` anywhere in `src`).
   - `error: required option '--profile <name>' not specified`
   - `error: missing required argument 'prompt'`
   - `error: too many arguments for 'scan'. Expected 1 argument but got 2.`
   - `error: unknown option '--x'` (optionally followed by `\n(Did you mean --profile?)`)
   - `error: option '--profile <name>' argument missing`
2. preAction: set quiet mode, and optionally install the debug logger. No config is read here for `scan`.
3. `loadConfig({})` reads the active tenant from the registry (`PRISMA_AIRS_TENANTS_PATH`, else `$XDG_STATE_HOME/prisma-airs/tenants.json`, else `~/.local/state/prisma-airs/tenants.json`; `tenants.ts:35-41`). It then reads the tenant file and enforces **`config.mgmtTsgId === registry tsgId`**, even though scanning never uses OAuth (`tenants.ts:90-93`). The read is read-only: it never writes the registry or the file.
4. `assertScannerCredentials`: at least one of `airsApiKey` or `airsApiToken` must be a non-blank string (`credentials.ts:24-26,65-70`).
5. `new SdkRuntimeService(runtimeInitOptions(config))` calls SDK `init({apiKey, apiToken, apiEndpoint: airsApiEndpoint ?? DEFAULT_ENDPOINT, numRetries: airsNumRetries})` (`client-options.ts:89-96`). Init can throw on an over-long key or token.
6. **Only now** are three status lines written to stderr (`runtime.ts:1061-1063`). See §6.
7. `new Content({prompt[, response]})`. This can throw on empty content. Status lines are already printed at that point.
8. `scanner.syncScan({profile_name}, content, undefined)`.
9. Normalize the result, render it to stdout, and return. The process exits naturally with **0**.
10. Any throw in steps 3-9 goes to `fail(err)`, which writes to stderr and calls `process.exit(1)` (`common.ts:12-25`). `runtime scan` has **no path that exits 2**.

## 3. Credential and config resolution (scan-relevant keys)

- `airsApiKey`, `airsApiToken`: strings. A blank-string key is removed by `stripUndefined` (`loader.ts:26-28`).
- `airsApiEndpoint`: a string with no URL validation. The default is `https://service.api.aisecurity.paloaltonetworks.com` (`SDK:6`). Trailing slashes are stripped (`SDK:272,10133`). A path prefix is preserved: `http://127.0.0.1:P/base/` becomes `http://127.0.0.1:P/base/v1/scan/sync/request`. `http://` is accepted with no restriction.
- `airsNumRetries`: coerced int 0..5 (`schema.ts:15`). If absent, the SDK uses `MAX_NUMBER_OF_RETRIES = 5` (`SDK:30,273`). An out-of-range value makes the whole tenant file invalid: `Cannot read a valid tenant config at <path>`.
- **Env leak (bug vs. the stated invariant).** The CLI passes `apiKey: config.airsApiKey` and `apiToken: config.airsApiToken`, and either may be `undefined`. The SDK does `opts.apiKey ?? process.env.PANW_AI_SEC_API_KEY` and `opts.apiToken ?? process.env.PANW_AI_SEC_API_TOKEN` (`SDK:241-242`).
  - With a tenant that has only `airsApiToken`, an exported `PANW_AI_SEC_API_KEY` **is sent** as `x-pan-token` (plus `x-payload-hash`).
  - The reverse case adds `Authorization: Bearer <env token>`.
  - The endpoint does not leak, because the CLI always passes a concrete endpoint. `numRetries` does not leak either.
  - The existing test only covers the case where both are absent (`tests/unit/config/client-options.spec.ts:194-199`).
- The SDK still reads these env vars on every request: `PANW_AI_SEC_TIMEOUT_MS`, `PANW_AI_SEC_DEBUG` and `PANW_AI_SEC_DEBUG_BODY` (`env.ts:8-12`, `SDK:10095,10014-10016,10139`).
- Config and credential error messages, all written via `fail` as `\n  ✗ Error: <msg>\n\n` with exit 1:
  - `No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'`, or, when tenants exist, `No tenant selected. Run 'airs-cli tenant switch <name>' (registered: a, b)` (`loader.ts:39-45`)
  - `Cannot read tenant registry at <path>; restore a valid registry before proceeding` (`tenants.ts:59-61`)
  - `Cannot read a valid tenant config at <path>` (`tenants.ts:88`)
  - `Tenant config TSG differs from its registered identity; register it under a new name` (`tenants.ts:91-93`)
  - `Scanner credentials are not configured (airsApiKey or airsApiToken). Run 'airs-cli tenant set <tenant> <key>' for airsApiKey (secrets prompt hidden, or use --stdin)` (`credentials.ts:43-46,65-69`)

## 4. HTTP request (SDK `syncScan`, `SDK:10335-10373`; `request`, `SDK:10094-10283`)

- `POST {endpoint}/v1/scan/sync/request` (`SDK:41`). There is no query string.
- Body: Zod-validated against `ScanRequestSchema` (`SDK:1534-1540`), then `JSON.stringify` with no whitespace. The key order follows the schema shape (tr_id, session_id, ai_profile, metadata, contents), and absent optional keys are omitted. So the CLI always sends exactly one of:
  - `{"ai_profile":{"profile_name":"<P>"},"contents":[{"prompt":"<X>"}]}`
  - `{"ai_profile":{"profile_name":"<P>"},"contents":[{"prompt":"<X>","response":"<R>"}]}`
  
  `tr_id`, `session_id`, `metadata` and `profile_id` are never sent. An empty prompt with a response is sent as `"prompt":""` (`Content.toJSON`, `SDK:10737-10745`).
- Headers (`SDK:10156-10163`, ApiKeyAuth `SDK:9564-9590`):
  - `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`
  - `service-name: api`
  - `Content-Type: application/json`
  - when a key is set: `x-pan-token: <airsApiKey trimmed>` and `x-payload-hash: <lowercase hex HMAC-SHA256(key=apiKey, msg=exact body text)>` (`SDK:9559-9561,9583-9586`)
  - when a token is set: `Authorization: Bearer <airsApiToken trimmed>`
  - both are sent when both are configured
  
  Undici adds its own defaults (`accept`, `accept-language`, `sec-fetch-mode`, `accept-encoding`, `content-length`, `connection`). Compare a whitelist case-insensitively.
- Client-side validation happens before any network I/O, and each failure exits 1:
  - Empty content: `AISEC_USER_REQUEST_PAYLOAD_ERROR:At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided` (`SDK:10565-10569`)
  - Profile name over 100 chars: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile.profile_name: too_big`
  - `--profile ""`: `... did not match schema: ai_profile: custom` (refine at `SDK:1486-1491`)
  - Prompt or response over 2 MiB: `prompt exceeds max length of 2097152 bytes`. This cannot be reached through argv on macOS.
  - API key or token over 2048 chars: `apiKey exceeds max length of 2048`, raised at init, before the status lines.
  - Invalid endpoint URL: a raw `TypeError` printed as `✗ Error: Invalid URL`.

## 5. Transport: timeouts, retries, errors (`executeWithRetry`, `SDK:9786-9845`)

- **Per-attempt timeout**: `PANW_AI_SEC_TIMEOUT_MS`, else 60000 ms (`SDK:10095`). A non-integer or non-positive value raises `AISEC_USER_REQUEST_PAYLOAD_ERROR:timeoutMs must be a positive integer`. The CLI has no timeout flag or config key.
- **Attempts**: `numRetries + 1`, where `numRetries` defaults to 5 (the CLI passes no per-call override).
- **Retried**:
  - A fetch throw that is not an `AISecSDKException`: network errors, and **timeouts**, because the abort reason `DOMException("Request timed out")` is treated as a network error.
  - HTTP **500, 502, 503 and 504** only (`SDK:31,9707`).
  
  **The sync POST is re-sent.** A 5xx or timeout can therefore create several server-side scans.
- **Not retried**: 429 and every other 4xx, 501, 505+, and errors raised after headers arrive (body read failure, invalid JSON, schema mismatch).
- **Backoff**: full jitter, `floor(random * (2^attempt*1000 + 1))` ms, so attempt 0 waits 0-1 s, then 0-2 s, 0-4 s, 0-8 s, 0-16 s (`SDK:9703-9706`). For 5xx, a `Retry-After` header (delta-seconds or HTTP-date) overrides the backoff, capped at 60 s (`SDK:9825-9829`). There is no auth-refresh retry (ApiKeyAuth has no `onUnauthorized`).
- **HTTP error object**: `AISecSDKException`. The message is `<errorType>:<text>`, where errorType is `AISEC_SERVER_SIDE_ERROR` if status ≥ 500, else `AISEC_CLIENT_SIDE_ERROR`. It carries `statusCode`, `failureKind:'http'` and `retryAfterMs` (`SDK:9710-9712,9834-9844`). The text is chosen as follows (`SDK:9713-9724`, problem details `SDK:9643-9688`):
  1. An RFC 7807 body (has `title`, `detail` or `errors`) gives `API error <s>; <title>; <detail>`. Any value outside a fixed allow-list becomes `[withheld]`.
  2. Otherwise, a JSON body gives the first present of `error_message`, `message`, `data.message`, `error.message`, `msg`, then `API error <s>`. If `data.errorCode` is present, ` (errorCode: X)` is appended.
  3. A non-JSON body gives `API error <s>: <raw body>`; an empty body gives `API error <s>`.
  
  **The server's text is echoed verbatim to stderr.** Errors are only secret-safe if the server does not echo secrets.
- **Network error after the retries are exhausted**: `AISEC_CLIENT_SIDE_ERROR:fetch failed` (Node fetch) or `AISEC_CLIENT_SIDE_ERROR:Request timed out`, with `failureKind:'network'` and no statusCode.
- **Response validation** (`SDK:10264-10280`):
  - A non-JSON 200 body gives `AISEC_RESPONSE_VALIDATION:Response body is not valid JSON`.
  - An empty body is parsed as `{}`.
  - A schema mismatch gives `AISEC_RESPONSE_VALIDATION:Response did not match schema: <path>: <code>; ...`, in schema field order. For example, a body missing the three booleans gives `timeout: invalid_type; error: invalid_type; errors: invalid_type`.
  - A body stall after headers gives `Failed to read response body` with `statusCode` equal to the 2xx status, so the CLI then prints `HTTP 200` under an error.

### Response schema (`SDK:1696-1718`, passthrough; extra keys allowed)

- **Required**: `report_id` (string), `scan_id` (string), `category` (string), `action` (string), `timeout` (bool), `error` (bool), `errors` (array of `{content_type?, feature?, status?}`).
- **Optional**: source, tr_id, session_id, profile_id, profile_name, prompt_detected, response_detected, prompt_masked_data, response_masked_data, prompt_detection_details, response_detection_details, tool_detected, created_at, completed_at.
- Zod `.optional()` **rejects `null`**, so fixtures must omit fields rather than send null.
- `prompt_detected`: optional booleans `url_cats, dlp, injection, toxic_content, malicious_code, source_code, agent, topic_violation`. A non-boolean value is a schema error.
- `response_detected`: `url_cats, dlp, db_security, toxic_content, malicious_code, agent, ungrounded, topic_violation`.

## 6. Normalization (`runtime.ts:82-134`, overridden at `:220-226`)

- `detections`: built from **`prompt_detected` only**. It keeps the keys of `RUNTIME_DETECTION_KEYS` whose value is boolean, in this fixed order: `topic_violation, injection, toxic_content, dlp, url_cats, malicious_code, source_code, agent` (`:26-35,82-90`). **`response_detected` is never read.** `db_security`, `ungrounded`, masked data, details and `tool_detected` are all ignored.
- `triggered`: true if any of the 8 keys is `true`. (AirsScanService uses `topic_violation` only, a different meaning.)
- `action`: lower-cased, and must be `allow` or `block`, otherwise it is `failed`.
  - The result counts as failed if `error === true` or `timeout === true` or the action is unknown (for example `alert`).
  - A failed result gets `category = 'error'` and an `error` string: the joined `feature: status: content_type` entries, or `AIRS scan timed out`, `AIRS scan failed`, or `Unknown AIRS action: <x>`.
  - Otherwise `category` is the response category, or `unknown`.
- **scanPrompt then coerces every non-`block` action to `allow`** (`:225`). Failed, timed-out and unknown-action scans are therefore displayed as **ALLOW**, with Category `error`, and **exit 0**. The `error` string is never shown. This fails open.
- `scanId` and `reportId` come from the response (`?? ''`).
- The result object, in key order: `{prompt, response, scanId, reportId, action, category, triggered, detections, error?}` (`types.ts:49-59`).

## 7. Rendering (`runtime.ts:67-85`, `ui.ts`)

Color: chalk derives its level from **stdout's** TTY status, plus `FORCE_COLOR`, even for stderr writes. With stdout piped and `FORCE_COLOR` unset, there are no ANSI codes. The bytes below assume no color.

stderr status lines (`ui.status`; suppressed by `--quiet`; passed through `commandHint`):
```
  Prisma AIRS Runtime Scan\n
  Profile: <profile>\n
  Prompt:  "<first 80 UTF-16 code units of prompt><... if length>80>"\n
```
There are two spaces after `Prompt:`. The prompt is embedded raw, including any newlines. With `AIRS_CLI_INVOKED_AS='airs cli'`, any `airs-cli ` substring inside the profile or prompt is rewritten to `airs cli `.

stdout result:
- The header (`\n  Scan Result\n\n`) and the section header are quiet-suppressed.
- Key/value lines are always printed. Keys are padded to width 9 and followed by two spaces.
- `Detections` appears only if at least one detection is `true`. Each bullet is `  ● <key>` (U+25CF), in the fixed key order.

```
\n  Scan Result\n\n  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n  Scan ID    <scan_id>\n  Report ID  <report_id>\n\n  Detections\n\n  ● injection\n  ● toxic_content\n
```
For allow, the action is `ALLOW`, Triggered is `no`, and there is no Detections block.

With `--quiet`, stdout is `  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n  Scan ID    S\n  Report ID  R\n  ● injection\n  ● toxic_content\n` and stderr is empty.

The docs (`docs-site/docs/cli/runtime/scan.md`, `docs-site/docs/runtime/scanning.md`) show a different, stale layout (`Action:    BLOCK`, a `─────` divider, `Detections:` with 4-space bullets). **The code wins.**

Error rendering (`common.ts:12-25`):
```
\n  ✗ Error: <message>\n            (always)
    HTTP <status>\n                 (only if err.status ?? err.statusCode is set)
    Re-run with --debug to capture redacted API diagnostics.\n   (only with status)
\n
```
Then exit 1. This is not quiet-suppressed. An unhandled rejection prints `\n  Unexpected error: <msg>` and the `--debug` hint, then exits 1 (`process-guards.ts:4-9`).

## 8. Exit codes

| Situation | TS exit |
|---|---|
| allow, block, failed-coerced-to-allow, any parsed 2xx | 0 |
| `--help` | 0 |
| Commander parse errors (missing `--profile` or prompt, excess args, unknown option, missing value) | 1 (docs claim 2) |
| config, registry, TSG or credential errors | 1 |
| SDK payload validation (empty content, profile > 100, bad key length, bad timeout env) | 1 |
| HTTP 4xx/5xx, network, timeout, response validation | 1 |
| SIGINT/SIGTERM | terminated by signal (no handler; a shell shows 130/143), stdout empty |

A block verdict never produces a nonzero exit.

## 9. Error matrix (with `airsNumRetries: 0`)

| Fixture | Attempts | stderr message line | `HTTP` line |
|---|---|---|---|
| 401 `{"message":"Invalid API key"}` | 1 | `✗ Error: AISEC_CLIENT_SIDE_ERROR:Invalid API key` | `HTTP 401` |
| 403 `{"error":{"message":"Forbidden"}}` | 1 | `AISEC_CLIENT_SIDE_ERROR:Forbidden` | `HTTP 403` |
| 429 + `Retry-After: 2` | 1 (never retried) | `AISEC_CLIENT_SIDE_ERROR:<msg>` | `HTTP 429` |
| 503 `{"message":"busy"}` | 1, or N+1 with airsNumRetries=N | `AISEC_SERVER_SIDE_ERROR:busy` | `HTTP 503` |
| 501 | 1 always | `AISEC_SERVER_SIDE_ERROR:...` | `HTTP 501` |
| non-JSON 502 `oops` | 1 | `AISEC_SERVER_SIDE_ERROR:API error 502: oops` | `HTTP 502` |
| connection refused | N+1 | `AISEC_CLIENT_SIDE_ERROR:fetch failed` | none |
| no response > timeout | N+1 (each up to 60 s) | `AISEC_CLIENT_SIDE_ERROR:Request timed out` | none |
| 200 non-JSON | 1 | `AISEC_RESPONSE_VALIDATION:Response body is not valid JSON` | none |
| 200 missing timeout/error/errors | 1 | `AISEC_RESPONSE_VALIDATION:Response did not match schema: timeout: invalid_type; error: invalid_type; errors: invalid_type` | none |

Each row is preceded by the three stderr status lines and exits 1.

## 10. Cancellation

There is no AbortSignal, no SIGINT/SIGTERM handler for scan (`grep` shows handlers only in `aigateway/inference.ts:158-159`), and no cleanup. Node's default disposition kills the process immediately. Status lines may already be on stderr. Nothing is written to stdout, nothing is written to disk, and no further retry happens. The in-flight request may or may not have reached the server. For contrast, `aigateway inference` aborts on SIGINT and maps `USER_REQUEST_PAYLOAD_ERROR` to exit 2 (`inference.ts:124-222`). Scan does neither.

## 11. Fixture responses (valid against both the TS Zod schema and the Rust `ScanResponse`)

Allow (expected: `Action ALLOW`, `Category benign`, `Triggered no`, no Detections, exit 0):
```json
{"report_id":"R00000000-0000-4000-8000-0000000000a1","scan_id":"00000000-0000-4000-8000-0000000000a1","profile_id":"11111111-1111-4111-8111-111111111111","profile_name":"fixture-profile","category":"benign","action":"allow","timeout":false,"error":false,"errors":[],"prompt_detected":{"url_cats":false,"dlp":false,"injection":false,"toxic_content":false,"malicious_code":false,"source_code":false,"agent":false,"topic_violation":false},"created_at":"2026-10-16T00:00:00Z","completed_at":"2026-10-16T00:00:01Z"}
```
Block (expected detections `injection`, `toxic_content` in that order; the `response_detected.dlp` is ignored; exit 0):
```json
{"report_id":"R00000000-0000-4000-8000-0000000000b2","scan_id":"00000000-0000-4000-8000-0000000000b2","profile_name":"fixture-profile","category":"malicious","action":"block","timeout":false,"error":false,"errors":[],"prompt_detected":{"toxic_content":true,"injection":true,"dlp":false,"url_cats":false,"malicious_code":false,"source_code":false,"agent":false,"topic_violation":false},"response_detected":{"dlp":true,"url_cats":false},"prompt_detection_details":{"toxic_content_details":{"toxic_categories":["violence"]}}}
```
Failed (TS renders `Action ALLOW`, `Category error`, exit 0):
```json
{"report_id":"R...c3","scan_id":"00000000-0000-4000-8000-0000000000c3","category":"benign","action":"allow","timeout":false,"error":true,"errors":[{"content_type":"prompt","feature":"dlp","status":"error"}]}
```
Send fixtures with `Content-Type: application/json`.

## 12. Rust SDK deltas that affect side-by-side comparison

- `scm-sdk` `Scanner::sync_scan` (`crates/scm-sdk/src/airs/scan/scanner.rs:117-148`) does not replay POSTs ("Submissions do not replay automatically"). The TS SDK re-POSTs up to `numRetries` times (default 5). Use `airsNumRetries: 0` in fixture tenants for request-count parity, or decide whether Rust honours the setting.
- The Rust body order is ai_profile, contents, then the optional fields. For CLI-shaped requests this is byte-identical to TS, so the `x-payload-hash` values should match. Assert it.
- Rust sends `User-Agent: PAN-AIRS/<ver>-rust-sdk` and `service-name: api` (`engine.rs:22-31`). Compare only the UA prefix.
- Rust needs `Endpoint::loopback` for `http://` (`config.rs:12-40`). TS accepts any `http://` URL.
- Rust `validate_content` matches TS: an all-empty content is rejected, while `prompt:""` with a response is allowed (`content.rs:188-215`).
- The Rust `ScanResponse` requires the same 7 fields. Its null handling for optionals may differ from Zod, which rejects null, so avoid nulls in fixtures.

## 13. Harness notes

- Isolate the registry with `PRISMA_AIRS_TENANTS_PATH`. The fixture tenant file needs `mgmtClientId`, `mgmtClientSecret`, `mgmtTsgId` (matching the registry `tsgId`), `airsApiKey` and/or `airsApiToken`, `airsApiEndpoint: http://127.0.0.1:<port>`, and `airsNumRetries: 0`.
- Unset `FORCE_COLOR`, `PANW_AI_SEC_DEBUG*`, `PANW_AI_SEC_TIMEOUT_MS` and `AIRS_CLI_INVOKED_AS` unless the test exercises them. Pipe stdout.
- The `--debug` logger only intercepts US production AIRS/SCM hosts (`debug-logger.ts:12-27`). Loopback, EU, IN and SG scan traffic is never logged, but an empty JSONL file is still created in the CWD.
- `fail()` calls `process.exit(1)` right after `console.error`. Output is small, so truncation risk on macOS pipes is low but nonzero.

## Acceptance criteria
- `runtime scan --profile P "X"` against an allow fixture sends exactly one `POST /v1/scan/sync/request` (no query string) with body bytes `{"ai_profile":{"profile_name":"P"},"contents":[{"prompt":"X"}]}` and exits 0.
- With `--response R`, the body bytes are `{"ai_profile":{"profile_name":"P"},"contents":[{"prompt":"X","response":"R"}]}`.
- With `--response ""`, the body has no `response` key.
- With prompt `""` and `--response R`, the body contains `"prompt":""` and `"response":"R"`.
- With prompt `""` and no response, no HTTP request is sent and the exit is nonzero (TS: 1), with stderr containing `At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided`.
- The request carries `content-type: application/json`, `service-name: api`, a user-agent starting with `PAN-AIRS/`, and `x-pan-token` equal to the tenant `airsApiKey` (trimmed).
- `x-payload-hash` equals lowercase hex HMAC-SHA256 of the exact received body bytes, keyed with `airsApiKey`; it is absent when only `airsApiToken` is configured.
- A tenant with `airsApiToken` sends `Authorization: Bearer <token>`; with both credentials, both auth headers are sent.
- A tenant with only `airsApiToken` and env `PANW_AI_SEC_API_KEY=ENV-LEAK`: Rust must send no `x-pan-token` (TS sends `ENV-LEAK`, a known bug).
- Env `PANW_AI_SEC_API_ENDPOINT` pointing elsewhere is ignored; the request goes to the tenant's `airsApiEndpoint`, including any path prefix and with trailing slashes stripped.
- Allow fixture: stdout is exactly `\n  Scan Result\n\n  Action     ALLOW\n  Category   benign\n  Triggered  no\n  Scan ID    <scan_id>\n  Report ID  <report_id>\n` with no Detections block.
- Block fixture with prompt_detected injection and toxic_content true: stdout ends with `\n  Detections\n\n  ● injection\n  ● toxic_content\n`, keys appear in fixed order regardless of JSON key order, and the exit code is 0.
- Detections only lists keys whose prompt_detected value is `true`, drawn from topic_violation, injection, toxic_content, dlp, url_cats, malicious_code, source_code, agent; response_detected never adds bullets or sets Triggered in TS.
- On success, stderr is exactly `  Prisma AIRS Runtime Scan\n  Profile: P\n  Prompt:  "X"\n` and stdout contains no status text.
- A prompt longer than 80 characters is previewed in the stderr Prompt line as its first 80 characters followed by `...`.
- `--quiet` on a block fixture: stderr is empty; stdout is the five key/value lines followed by the bullet lines, with no `Scan Result` or `Detections` headers.
- Global `--output json` (before or after `scan`) is accepted by TS; it exits 0 with the pretty layout (any Rust JSON mode must be a deliberate, documented extension).
- Missing `--profile`: no HTTP request, stderr `error: required option '--profile <name>' not specified`, TS exit 1 (record the Rust policy for usage errors, 1 vs 2).
- Missing prompt: stderr `error: missing required argument 'prompt'`, no request, TS exit 1.
- Two positionals: stderr `error: too many arguments for 'scan'. Expected 1 argument but got 2.`, TS exit 1.
- A profile name of 101 characters sends no HTTP request and exits 1 (TS stderr contains `ai_profile.profile_name: too_big`).
- No tenant selected (empty registry): exit 1, stderr contains `No tenant selected.`, no request sent, registry file unchanged.
- A tenant file whose mgmtTsgId differs from the registry tsgId: exit 1, stderr contains `Tenant config TSG differs from its registered identity; register it under a new name`, no request sent.
- A tenant with neither airsApiKey nor airsApiToken: exit 1, stderr contains `Scanner credentials are not configured (airsApiKey or airsApiToken).`, no request sent.
- The registry and tenant files are byte-identical (and keep the same mtime) after any scan run.
- HTTP 401 fixture `{"message":"Invalid API key"}`: exit 1, stdout empty, stderr contains `Invalid API key` and a line `    HTTP 401`, and never contains the API key or token.
- HTTP 403 fixture: exit 1 with `    HTTP 403` on stderr.
- HTTP 429 fixture with `Retry-After: 2`: exactly one attempt, exit 1, `    HTTP 429` on stderr.
- HTTP 503 fixture with airsNumRetries=0: exactly one attempt, exit 1, `    HTTP 503` on stderr (TS makes N+1 attempts for airsNumRetries=N; Rust behaviour must be documented).
- Connection refused (closed port) with airsNumRetries=0: exit 1, stdout empty, stderr has an error line and no `HTTP` line.
- A server that never responds, with a short timeout: exit 1, no `HTTP` line (TS default timeout is 60 s, overridable via PANW_AI_SEC_TIMEOUT_MS).
- A 200 response missing timeout/error/errors: exit 1, stdout empty (TS stderr `AISEC_RESPONSE_VALIDATION:Response did not match schema: timeout: invalid_type; error: invalid_type; errors: invalid_type`).
- A 200 non-JSON body: exit 1, stdout empty (TS: `Response body is not valid JSON`).
- A 200 response with `error:true` and errors[] (TS: exit 0 with `Action     ALLOW` and `Category   error`); Rust must either reproduce this or document the deliberate fail-closed change.
- Uppercase `"action":"BLOCK"` renders `Action     BLOCK`; `"action":"alert"` renders ALLOW with Category `error` in TS.
- SIGINT sent while the fixture holds the request open: the process terminates promptly (TS: killed by SIGINT, no stdout, no further request attempts).
- `runtime scan --help` exits 0 and prints usage plus the `--profile <name>` and `--response <text>` options and an `Examples:` block on stdout.
- With FORCE_COLOR unset and stdout piped, neither stdout nor stderr contains ANSI escape sequences.


## Discrepancies
- Docs (`docs-site/docs/cli/runtime/scan.md`, `docs-site/docs/runtime/scanning.md`) show `Action:    BLOCK` with colons, a `─────` divider and `Detections:` with 4-space bullets. The code (`src/cli/commands/runtime.ts:67-85`, `ui.ts:56-121`) prints `  Action     BLOCK` (no colon, padded to width 9), no divider, `  Detections` and `  ● key`.
- The exit-code docs (`docs-site/docs/getting-started/exit-codes-and-output.md`, AGENTS.md:123, CLAUDE.md:175) say usage errors exit 2. Commander parse errors for scan (missing `--profile`, missing prompt, excess args, unknown option) exit 1 because there is no exitOverride. `runtime scan` has no exit-2 path at all.
- The 'environment is never consulted' invariant (`loader.ts:83-86`, `client-options.ts:29-32`, `env.ts`) is violated. `runtimeInitOptions` passes `apiKey`/`apiToken` as `undefined` when only one is configured, and SDK `Configuration.init` (`SDK:241-242`) then falls back to `PANW_AI_SEC_API_KEY`/`PANW_AI_SEC_API_TOKEN`. Only the both-missing case is tested.
- Fail-open bug: `scanResponseToResult` marks `error:true`, `timeout:true` or unknown actions as `failed`, but `scanPrompt` (`runtime.ts:225`) coerces anything not `block` to `allow`. Failed or timed-out scans and an `alert` action are shown as ALLOW (Category `error`) with exit 0, and the error detail is discarded.
- `response_detected` is never read. Response-side detections (including response-only `db_security`/`ungrounded`) neither set Triggered nor appear under Detections, although full-cli-sweep.md says the `--response` example 'tests both prompt and response paths'.
- `runtime scan` has no `--output` option. The global `--output` and tenant `defaultOutput` are silently ignored, and an invalid `--output bogus` is not rejected. This conflicts with the exit-codes doc claim that read commands support six formats; scan is not classified as a read command.
- Retry semantics: scan uses the SDK default `numRetries` = 5 (unless `airsNumRetries` is set). The SDK re-POSTs the sync scan on network errors, timeouts and 500/502/503/504, which risks duplicate server-side scans. 429 is never retried for scan. The docs only describe retry behaviour for bulk-scan, where SDK retries are disabled.
- Timeouts are retried as network errors. Worst case is 6 attempts of 60 s each plus up to 31 s of jittered backoff, about 6.5 minutes, with no CLI flag to bound it; only `PANW_AI_SEC_TIMEOUT_MS` controls it.
- Error text reflects the server body verbatim (`message`/`error.message`/raw non-JSON body via `extractErrorMessage`, `SDK:9713-9724`; `safeErrorMessages` is not set for scan). Secret-safe errors depend on the server not echoing secrets.
- Scan requires `mgmtTsgId` in the tenant file to match the registry identity even though scanning uses only the API key. A scanner-only tenant file is rejected with the TSG-mismatch error.
- The `--debug` logger only intercepts the US scan host (`debug-logger.ts:12-27`). Regional EU/IN/SG endpoints and custom `airsApiEndpoint` traffic are never logged, contrary to docs saying `--debug` captures the full request/response traffic.
- `commandHint` is applied to status lines that embed user data. With `AIRS_CLI_INVOKED_AS='airs cli'`, `airs-cli ` inside a prompt or profile name is rewritten in the stderr preview.
- The prompt preview uses `prompt.slice(0, 80)` (UTF-16 code units), which can split a surrogate pair. `prompt.length > 80` also counts UTF-16 units, not characters or bytes.
- A response body stall after 2xx headers yields 'Failed to read response body' carrying statusCode 200, so the CLI prints `HTTP 200` under an error.
- `triggered` means 'any of 8 prompt detections' in SdkRuntimeService but 'topic_violation only' in AirsScanService (`scanner.ts:26`, used by topics eval). The ScanResult doc comment in `types.ts:38` describes only the latter.
- The task premise placed scan rendering in `src/cli/renderer/runtime.ts`; it is actually a private function in `src/cli/commands/runtime.ts:67-85`.
- Test coverage: there is no CLI-level or executable test for `runtime scan`. `sdk-runtime-contract.spec.ts` exercises only `asyncScan`. The scanPrompt unit tests mock `Content` and `syncScan`, so request serialization, schema validation, headers, retries and error rendering are untested in the TS repo.
- `scm-sdk-rs/contracts/sources/typescript/src` contains only two AI Gateway model files, not the scanner. The syncScan source was read from an identical 0.34.0 dist bundle in another checkout (`coder-mirrors/prisma-airs-desktop/node_modules`).
- The TS SDK accepts any `http://` endpoint. The Rust SDK requires an explicit `Endpoint::loopback` for HTTP, so the Rust CLI needs a deliberate loopback opt-in to reproduce fixture testing.
- The TS SDK retries sync POSTs while the Rust `Scanner::sync_scan` never replays, so request counts differ under 5xx or network faults unless `airsNumRetries: 0`.
- `assertScannerCredentials` runs twice per scan (`runtime.ts:1058` and `client-options.ts:90`). This is harmless but redundant.


## Open questions
- Usage-error exit code: should Rust match the TS reality (Commander errors exit 1) or the documented contract (exit 2)? The harness must encode one.
- Should Rust add `--output json` for `runtime scan`? If yes, should the shape mirror RuntimeScanResult `{prompt, response?, scanId, reportId, action, category, triggered, detections, error?}`, and what happens to the pretty layout on stdout?
- Fail-open coercion: should Rust reproduce ALLOW/exit 0 for `error:true`, `timeout:true` or unknown actions, or fail closed (for example action `failed`, exit 1)? This changes live security outcomes.
- Should Rust surface `response_detected` (and `db_security`/`ungrounded`) in Detections and Triggered, or match the TS omission?
- Should Rust honour `airsNumRetries` for the sync POST (the Rust SDK does not replay by default), given the duplicate-scan risk?
- Should Rust honour `PANW_AI_SEC_TIMEOUT_MS`, `PANW_AI_SEC_DEBUG` and `PANW_AI_SEC_DEBUG_BODY` (the TS SDK reads them per request), or expose a tenant or flag timeout instead?
- SIGINT: should Rust die by the default signal (TS parity) or catch it, print a message and exit 130 or 1? Is a per-request cancellation token required for milestone 3?
- Error message parity: must Rust stderr match the TS `AISEC_<TYPE>:<server text>` strings, or only the structure (`✗ Error:` line, `HTTP <status>` line, exit code), given that TS echoes server bodies verbatim?
- Should SDK payload-validation errors (empty content, profile name over 100 chars) be usage errors (exit 2, like `aigateway inference`) or operational errors (exit 1, as in TS scan)?
- Should a scanner-only invocation keep requiring the `mgmtTsgId` registry-identity match in the tenant file?
- Should hint strings name `airs-cli` or `airs-cli-rs` (for example `Run 'airs-cli tenant set ...'`), and should the harness normalise program names in help and error comparisons?
- Are stdin or `--session-id`/`--profile-id`/metadata inputs in scope for milestone 3? The TS scan supports none of them, while bulk-scan has `--session-id`.
