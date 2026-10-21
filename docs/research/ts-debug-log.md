# `--debug` API log: TS behaviour and the airs-cli-rs design (milestone 0.2)

Purpose: an implementation-ready spec for porting the global `--debug` flag, which
DESIGN §12 D3 lists as not implemented. These decisions were made before this research:
the Rust log is secret-redacted, lives under `$XDG_STATE_HOME/airs-cli/debug/` (default
`~/.local/state/airs-cli/debug/`), and only the newest 20 logs are kept.

Sources:
- The frozen reference `.reference/prisma-airs-cli` at commit `5711012`. Paths in §1 are
  relative to it.
- The bundled TS SDK `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` (0.34.0).
- The published `scm-sdk-0.1.0` crate in `~/.cargo/registry`. It is byte-identical to
  `scm-sdk-rs/crates/scm-sdk/src`.
- This repository's `src/`.

Observed behaviour comes from runs of the TS reference (node 24.21.0) against the
loopback fixture server, recorded on 2026-10-17. §1.9 describes how they were made.

---

## 1. TypeScript behaviour

### 1.1 Flag, timing and which invocations create a file

- `--debug` is a root option with the help text `Write redacted API diagnostics to a
  private JSONL file` (`src/cli/program.ts:107`).
- The log is installed in the root `preAction` hook (`program.ts:111-192`). That hook
  runs only for an action command, after commander parsed successfully. So:
  - `--help`, `--version` and parse errors create **no file**. Observed:
    `--debug runtime profiles list --bogus` exits 1 with no file, and `… --help` exits 0
    with no file.
  - Usage checks that run earlier in the same hook stop the run before the file exists.
    These are the `--debug` refusals for profile backup/restore, environment reports and
    `redteam judge` (`:131-161`, exit 2), and `resolveOutput` (`:162-175`). Observed:
    `--debug runtime profiles list --output xml` exits 2 with no file.
  - **Every other action command creates a file**, even one that makes no HTTP request.
    Observed: `--debug tenant list` leaves an empty file. Validation inside the action
    also runs after creation. Observed: `--debug runtime scan --profile p ""` exits 1 and
    leaves an empty file.
  - The file is created before the tenant config is loaded (the actions load it), so a
    tenant error still leaves a file behind.
- Commands that refuse `--debug` (and also refuse `PANW_AI_SEC_DEBUG` set to a truthy
  value) exit 2 with `Disable --debug and PANW_AI_SEC_DEBUG for …`. They are
  `runtime profiles backup|restore`, `runtime|redteam|aigateway|agentguard report`
  (environment reports) and `redteam judge`. None of them is in Rust scope yet.

### 1.2 Name, location, mode

- The path is `join(process.cwd(), \`debug-api-${Date.now()}-${randomUUID().slice(0, 8)}.jsonl\`)`
  (`program.ts:177-180`). That is **the current working directory**, a 13-digit epoch-ms
  value, and 8 lowercase hex digits.
- Creation is `mkdirSync(dirname, {recursive, mode: 0o700})` followed by
  `writeFileSync(path, '', {mode: 0o600, flag: 'wx'})` (`src/cli/debug-logger.ts:140-141`).
  `wx` is O_CREAT|O_EXCL: an existing name or a symlink at the path fails. Observed: the
  file is 0600, and the existing cwd was left at 0700.
- **No pruning.** `pruneDebugLogs(dir, keep)` exists (`debug-logger.ts:82-110`) but nothing
  calls it. The comment at `:142` and the test
  `tests/integration/cli/debug-output-path.spec.ts:29-40` assert that earlier logs are
  never pruned or truncated. If it were used, it would sort by mtime and skip files that
  fail to unlink.
- `teardown()` is never called. The interceptor lives for the whole process.

### 1.3 stderr notice and `--quiet`

- After creation the hook calls `ui.status(\`Debug: API log → ${logPath}\`)` (`program.ts:191`).
  The text is `"  Debug: API log → <absolute path>\n"` on stderr. It is the first status
  line and comes before any command output.
- `ui.status` is quiet-suppressed (`src/cli/renderer/ui.ts:131-134`). Observed: with
  `--quiet` there is no notice, but the file is still created and written.
- The operational error block always adds `    Re-run with --debug to capture redacted API diagnostics.`
  after the `HTTP <status>` line (`src/cli/renderer/common.ts:18-22`), **even when
  `--debug` is on**. Observed for a 503 and a 401 under `--debug`.

### 1.4 Setup failure and write failure

- **Setup failure.** If `installDebugLogger` throws (mkdir, or the create with `wx`), the
  CLI prints `ui.error('Cannot create the debug log in the current working directory. Run
  from a writable directory or omit --debug.')` and exits 1 before the action runs
  (`program.ts:181-190`). The OS error is never echoed. Observed with cwd at 0555: stderr
  was exactly `"  ✗ Cannot create the debug log in the current working directory. Run from a writable directory or omit --debug.\n"`,
  exit 1, and zero requests. That is the `✗` form with no `Error:` and no blank lines.
- **Write failure during the run.** `appendFileSync` is called without a guard, both after
  a response (`debug-logger.ts:249`) and on the error path (`:205`). Its exception escapes
  from the patched `fetch`, so **a successful HTTP response becomes a fetch rejection**.
  On the error path it replaces the original error. The SDK then treats it as a network
  failure, which can mean retries or a failed command. Reproduced with
  `scratchpad/debuglog/writefail.mjs`: log chmod 0400, then fetch → rejected with
  `EACCES: permission denied, open '<dir>/debug-api-x.jsonl'`.

### 1.5 What is intercepted

- The interceptor replaces `globalThis.fetch` (`debug-logger.ts:146-256`). The TS SDK looks
  up `globalThis.fetch` on **every attempt**:
  - `request()` calls `(spec.fetch ?? globalThis.fetch)(…)` inside `executeWithRetry`
    (`dist/index.js:10186`).
  - The OAuth client's `fetchToken` calls the bare `fetch(this.tokenEndpoint, …)`
    (`dist/index.js:11028`).
  - So each retry, each token request and each 401/403 refresh-and-replay gets its own
    record. Observed:
    - 503 on profiles: 1 token record and 6 profiles records.
    - 401 on profiles: token, profiles 401, token, profiles 401.
- **Host filter.** A request is logged only when `isAirsUrl(url)` is true or the request
  carries an `x-portkey-api-key` header (`:155-165`). `isAirsUrl` accepts the hostname
  equal to, or ending in `.` plus, one of these (`:12-26`):
  - `api.sase.paloaltonetworks.com`
  - `api.apps.paloaltonetworks.com`
  - `service.api.aisecurity.paloaltonetworks.com`
  - `auth.apps.paloaltonetworks.com`
  - `api.dlp.paloaltonetworks.com`
- What the host filter leaves out:
  - **The regional scanner hosts** `service-de`, `service-in` and
    `service-sg.api.aisecurity.paloaltonetworks.com` (the TS SDK's EU/INDIA/SINGAPORE
    defaults, `dist/index.js:9-11`). They are not subdomains of `service.api.aisecurity…`,
    so they are not logged (checked with the TS `isAirsUrl`).
  - `api.typesafe.ai`, any custom or proxy endpoint, and **all loopback endpoints**.
  - Observed: against the harness's loopback endpoints every TS log was **0 bytes**
    (doctor, profiles list, topics get, scan, 503, 401), while the server recorded the
    requests.
- Coverage therefore spans every SDK client that sends to those hosts: management, US
  scanner, OAuth, DLP, red team, model security and AgentGuard. It also includes any
  non-SDK `fetch` the CLI makes to those hosts. AI Gateway inference traffic (any host,
  with `x-portkey-api-key`) is logged with both bodies omitted.

### 1.6 Record (one JSON object per line, `JSON.stringify`, `\n`-terminated)

Field order is fixed by the object literals at `debug-logger.ts:238-248` and `:199-204`:

```jsonc
{
  "timestamp": "<ISO-8601 UTC, ms, Z>",   // taken before the fetch (request start)
  "durationMs": 6,                         // start → fetch resolved (response headers), not body
  "request": {
    "method": "GET",
    "url": "<redactUrl(url)>",
    "headers": { "<name as sent>": "<value or ***>" },
    "body": <redacted JSON | form object | marker>   // key ABSENT when there is no body
  },
  "response": {                            // absent on a fetch rejection
    "status": 200,
    "statusText": "OK",                    // server reason phrase (undici)
    "headers": { "<lowercase name>": "<value or ***>" },
    "body": <redacted JSON | marker>
  },
  "error": "Request failed"                // only on rejection; "Runtime request failed" for inference
}
```

- A rejection record has no `response` key (`:199-204`). The thrown error's text is never
  logged.
- Request header names keep the case the caller used (`User-Agent`, `Authorization`).
  Response header names are lowercase (the WHATWG `Headers`).
- The token request has no `User-Agent`: `fetchToken` sets only `Content-Type` and
  `Authorization`.
- The response body is read from `response.clone().text()` **before** the response is
  returned to the SDK (`:225-235`). So the whole body is buffered, the record is written
  when the body has been read, and records come out in request order.
- Body markers:
  - `[BODY OMITTED]`: inference, dashboard or `--omitBodies` traffic, and any
    `text/event-stream` response.
  - `[NON-JSON BODY OMITTED]`: a body that does not parse, unless the content type is
    form-urlencoded.
  - `<unreadable>`: the clone could not be read.

### 1.7 Redaction (exact rules and gaps)

- The key rule is
  `/token|secret|password|passwd|credential|authorization|cookie|api[-_]?key|client[-_]?auth|auth[-_]?code|^key$/i`
  (`:32-37`). It is a **substring** match, and the mask is `***`.
- **Headers** use a denylist (`redactHeaders`, `:40-47`). A name that matches the key rule
  is masked, and so is `x-portkey-(config|metadata|forward-headers)`. Everything else is
  logged verbatim.
- **JSON bodies** are masked with `redactDeep` (`:50-62`): the value of any key that
  matches the key rule is replaced, at any depth. Values are never inspected.
- **Form bodies** are parsed with `URLSearchParams` and then masked with `redactDeep`
  (`:181-183`).
- **URLs** go through `redactUrl` (`:65-80`). Only query parameters whose name matches the
  key rule are masked.

What these rules redact, confirmed against the copied TS functions in
`scratchpad/debuglog/probe.mjs` and in the captured logs:

| Item | TS result |
|---|---|
| `x-pan-token` request header | `***` |
| `Authorization` (Basic on the token request, Bearer on API requests) | `***` |
| `Proxy-Authorization`, `set-cookie`, `x-api-key`, `x-*-token` | `***` |
| OAuth token response `access_token` | `***` |
| OAuth `client_secret` in a form body | `***`. The TS SDK sends the secret in Basic, not in the body. The form is `grant_type=client_credentials&scope=tsg_id:<tsg>`, logged in clear |
| `?api_key=` / `?token=` query values | `***` |

What they miss:

| Item | TS result |
|---|---|
| **`x-payload-hash`** (an HMAC computed with the API key, sent on every scan POST) | **logged verbatim** (observed) |
| **`Location` and other response headers** | verbatim, including userinfo and query (`https://u:p@h/x?code=1` passes through) |
| **URL userinfo** | kept (`redactUrl` touches only query parameters) |
| **Query names outside the rule** (`code`, `sig`, `X-Amz-Signature`, …) | kept |
| **Model Security PyPI auth response** `{"url": …, "expires_at": …}` (`dist/index.js:3329-3332`) | `url` is not a sensitive key, so the URL is logged verbatim. Any credential embedded in it (userinfo or query) ends up in the log. The command exists only to hand out that authenticated index URL (`src/cli/commands/modelsecurity.ts:242-256`) |
| **Secrets echoed in values** (`"message": "invalid token Bearer abc"`, `"detail": "client_secret S3CR3T rejected"`) | verbatim: values are never compared with the configured secrets |
| **Scan prompts and responses** | verbatim: `contents[].prompt` and `contents[].response` (observed), and the whole scan response |

The key rule also over-redacts:
- `token_type` (`"Bearer"`) is masked (observed in every token record).
- `tokens_used`, `max_tokens`, `apiKeyName` and `apiKeyId` are masked too.

Body omission (`:166-176`, `:217-224`):
- **Every** body is omitted (request and response, OAuth included) when the command is
  under `agentguard` or `runtime dlp` (`omitBodies`, `program.ts:114-121,182-184`).
- Bodies are omitted for `/v1/mgmt/dashboard/…`, `/v1/mgmt/reports/scancontent` and any
  `/aiag/` path.
- Bodies are omitted for SSE responses and for inference traffic.
- For `runtime dlp`, the CLI also forces `PANW_AI_SEC_DEBUG_BODY=0` (`program.ts:122-127`).

The TS SDK has a separate stderr logger, enabled by `PANW_AI_SEC_DEBUG`
(`dist/index.js:9988-10057`). It hashes sensitive headers to `sha256:<12 hex>` and logs
bodies only with `PANW_AI_SEC_DEBUG_BODY`. That logger is not `--debug`. The Rust SDK
reads no environment (D24), so it stays out of scope.

### 1.8 Concurrency

Node runs the logger on one thread, and `appendFileSync` writes each line with one
synchronous call, so lines never interleave. With parallel requests (scan batches) the
records come out in completion order. There is no sequence number, attempt counter or
link between records of the same logical operation.

### 1.9 Captured samples (sanitized)

Because of the host filter (§1.5), a loopback run logs nothing. The samples were made in
the `alias` mode of `scratchpad/debuglog/capture`, which works like this:
- The tenant config names the real production hostnames.
- `scratchpad/debuglog/alias-preload.mjs` is loaded through `node --import` before the
  CLI. It rewrites those hostnames to `http://127.0.0.1:<fixture port>` *underneath* the
  CLI's interceptor, and it rejects every other host.
- The process runs under `sandbox-exec` with a profile that denies all non-loopback
  outbound connections. A connect to TEST-NET `192.0.2.1` was checked to fail with EPERM.
- All credentials are fixture values. None of the fixture secret forms (raw, form-encoded,
  base64, Basic pair, `mock-token-`) appeared in any log.

The only changes below are `<sandbox>` for temp paths and `…` for elided array items.

`--debug doctor` (5 records; the Scanner probe, then two management clients, each with
its own token):
```jsonl
{"timestamp":"2026-10-17T11:03:44.327Z","durationMs":11,"request":{"method":"GET","url":"https://service.api.aisecurity.paloaltonetworks.com/scan/v1/scan/results?scan_ids=ced5c8fc-b867-4a3b-b9c4-9c956a5da005","headers":{"User-Agent":"PAN-AIRS/0.34.0-typescript-sdk","service-name":"api","x-pan-token":"***"}},"response":{"status":200,"statusText":"OK","headers":{"content-length":"2","content-type":"application/json","date":"Sat, 17 Oct 2026 11:03:44 GMT"},"body":[]}}
{"timestamp":"2026-10-17T11:03:44.344Z","durationMs":1,"request":{"method":"POST","url":"https://auth.apps.paloaltonetworks.com/oauth/token","headers":{"Content-Type":"application/x-www-form-urlencoded","Authorization":"***"},"body":{"grant_type":"client_credentials","scope":"tsg_id:100"}},"response":{"status":200,"statusText":"OK","headers":{"content-length":"73","content-type":"application/json","date":"Sat, 17 Oct 2026 11:03:44 GMT"},"body":{"access_token":"***","expires_in":3600,"token_type":"***"}}}
{"timestamp":"2026-10-17T11:03:44.345Z","durationMs":1,"request":{"method":"GET","url":"https://api.sase.paloaltonetworks.com/aisec/v1/mgmt/topics/tsg/100?offset=0&limit=100","headers":{"User-Agent":"PAN-AIRS/0.34.0-typescript-sdk","service-name":"api","Authorization":"***"}},"response":{"status":200,"statusText":"OK","headers":{"content-length":"20","content-type":"application/json","date":"Sat, 17 Oct 2026 11:03:44 GMT"},"body":{"custom_topics":[]}}}
{"timestamp":"2026-10-17T11:03:44.346Z","durationMs":1,"request":{"method":"POST","url":"https://auth.apps.paloaltonetworks.com/oauth/token", …same as record 2…}
{"timestamp":"2026-10-17T11:03:44.347Z","durationMs":0,"request":{"method":"GET","url":"https://api.sase.paloaltonetworks.com/ai_gw/v2/workspaces","headers":{"User-Agent":"PAN-AIRS/0.34.0-typescript-sdk","service-name":"api","Authorization":"***","x-tsg-id":"100"}},"response":{"status":200,"statusText":"OK","headers":{…},"body":{"data":[],"object":"list","total":0}}}
```
stderr: `  Debug: API log → <sandbox>/cwd/debug-api-1792235024322-035293ca.jsonl\n`

`--debug runtime profiles list --output json`: the token record (as above), then:
```jsonl
{"timestamp":"2026-10-17T11:03:44.507Z","durationMs":1,"request":{"method":"GET","url":"https://api.sase.paloaltonetworks.com/aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100&latest=true","headers":{"User-Agent":"PAN-AIRS/0.34.0-typescript-sdk","service-name":"api","Authorization":"***"}},"response":{"status":200,"statusText":"OK","headers":{"content-length":"722","content-type":"application/json","date":"Sat, 17 Oct 2026 11:03:44 GMT"},"body":{"ai_profiles":[{"active":true,"created_by":"creator@example.com","last_modified_ts":"2026-02-01T00:00:00Z","policy":{"ai-security-profiles":[{"model-configuration":{"mask-data-in-storage":false},"model-type":"default"}],"dlp-data-profiles":[]},"profile_id":"00000000-0000-4000-8000-000000000002","profile_name":"alpha","revision":2,"updated_by":"updater@example.com"},…]}}}
```
stderr: the notice, then `  Showing 2`. With `--quiet`: empty stderr and the same 2 records.

`--debug runtime topics get fin --output json`: the token record, then
`GET …/aisec/v1/mgmt/topics/tsg/100?offset=0&limit=100` with the full
`custom_topics` body (descriptions and examples in clear).

`--debug runtime scan --profile fixture-profile --response "a model answer" "please BLOCK this prompt"`:
```jsonl
{"timestamp":"2026-10-17T11:03:44.827Z","durationMs":13,"request":{"method":"POST","url":"https://service.api.aisecurity.paloaltonetworks.com/scan/v1/scan/sync/request","headers":{"User-Agent":"PAN-AIRS/0.34.0-typescript-sdk","service-name":"api","Content-Type":"application/json","x-pan-token":"***","x-payload-hash":"<64 hex digits, logged verbatim>"},"body":{"ai_profile":{"profile_name":"fixture-profile"},"contents":[{"prompt":"please BLOCK this prompt","response":"a model answer"}]}},"response":{"status":200,"statusText":"OK","headers":{…},"body":{"action":"block","category":"malicious","error":false,"errors":[],"profile_name":"fixture-profile","prompt_detected":{…,"injection":true,…,"toxic_content":true,…},"prompt_detection_details":{"toxic_content_details":{"toxic_categories":["violence"]}},"report_id":"R00000000-0000-4000-8000-0000000000b2","response_detected":{"dlp":true,"url_cats":false},"scan_id":"00000000-0000-4000-8000-0000000000b2","timeout":false}}}
```

Error cases:
- Profiles answered 503 with `retry-after: 0`: exit 1 and 7 records. Each attempt is a
  separate line with `"response":{"status":503,"statusText":"Service Unavailable",…,"retry-after":"0"},"body":{"message":"busy"}}`.
- Profiles answered 401: 4 records (token, 401, token, 401). stderr ends with
  `✗ Error: AISEC_CLIENT_SIDE_ERROR:API error 401`, `HTTP 401` and the `Re-run with --debug` line.
- Token endpoint refused (connection refused on loopback): 1 record, exit 1, stderr
  `✗ Error: AISEC_OAUTH_ERROR:Token request failed: fetch failed`.
  ```jsonl
  {"timestamp":"2026-10-17T11:03:45.276Z","durationMs":1,"request":{"method":"POST","url":"https://auth.apps.paloaltonetworks.com/oauth/token","headers":{"Content-Type":"application/x-www-form-urlencoded","Authorization":"***"},"body":{"grant_type":"client_credentials","scope":"tsg_id:100"}},"error":"Request failed"}
  ```

---

## 2. What the Rust side can observe

### 2.1 scm-sdk 0.1.0

- **`Transport` is the only public request/response seam** (`transport.rs:127-129`):
  `send(TransportRequest) -> BoxFuture<Result<TransportResponse>>`.
  - `TransportRequest` exposes `method()`, `url()` (full URL, query included),
    `headers()`, `body()` and `operation()`. The body is the whole request as `Bytes`,
    not a stream. `operation()` is the SDK name, for example `oauth.token`,
    `airs.management.profiles.list`, `airs.management.topics.list`, `airs.scan.sync`,
    `airs.scan.results`.
  - Header values are marked `set_sensitive(true)`, but they stay readable through
    `HeaderMap`.
  - The SDK sets these headers: API requests carry `user-agent: PAN-AIRS/0.1.0-rust-sdk`
    and `service-name: api`. Auth adds `authorization`, `x-pan-token`,
    `x-payload-hash` and `x-tsg-id` (`engine.rs:24-31`, `auth.rs:737-797`).
  - The token request carries only `authorization: Basic …` and `content-type`. Its
    body is `grant_type=client_credentials&scope=tsg_id:<tsg>` (`auth.rs:615-645`).
  - reqwest adds `host`, `content-length`, `accept-encoding` and, for the token request,
    the builder user agent at send time. A transport wrapper never sees those.
- **The response body cannot be read from outside the crate.** `TransportResponse` has
  public `new`, `from_bytes`, `status()` and `headers()`, but the `body` field is
  `pub(crate)` and there is no accessor (`transport.rs:67-93`).
  - A wrapper *around* `scm::transport::ReqwestTransport` sees status and headers only.
  - To capture bodies, the CLI must create the stream itself: build the
    `reqwest::Client`, wrap `bytes_stream()` in a tee, then call `TransportResponse::new`.
    `DirectTransport` (`src/clients.rs:157-209`) already works this way.
- **Every attempt goes through the transport:**
  - The buffered engine loop calls `transport.send` once per attempt, after
    `auth.prepare` (`engine.rs:1116-1257`). That covers each 429/5xx retry (`:1225-1240`),
    each transport-error retry of a replay-safe request (`:1172-1183`) and the 401/403
    refresh-and-replay (`:1214-1224`).
  - OAuth refresh sends through the provider's own transport (`auth.rs:640-648`).
  - `send_stream` behaves the same way (`engine.rs:959-1091`).
  - In this CLI the management client and its `OAuthProvider` share one transport
    (`src/clients.rs:293-311`), and the scanner gets one through `client_builder().transport`
    (`:410-418`). Doctor builds through the same functions (`src/commands/doctor.rs:431,463`).
    **One wrapper therefore sees every request the CLI makes.**
- **What the transport cannot see:**
  - Requests rejected before dispatch: destination policy, preflight, header limits,
    deadline or cancel before send.
  - Backoff sleeps and retry decisions (only the timestamps show them).
  - The SDK `Error` the attempt ended in.
  - A deadline or cancel that drops the in-flight `send` future or the body stream. The
    wrapper sees only the drop.
  - How much of the body the engine reads: success bodies up to `max_response_bytes`
    (8 MiB) and error bodies up to `max_error_bytes` (64 KiB) (`config.rs:288-293`). A tee
    sees only the bytes the engine pulls.
  - With `gzip(true)`, reqwest decompresses before the stream and removes
    `content-encoding`/`content-length` from the headers it returns.
- **Observability module** (`observability.rs`):
  - It is private and active only with the `tracing` feature, which the CLI does not
    enable.
  - It emits `tracing` events on target `scm_sdk::lifecycle` from a closed vocabulary:
    operation name, stage `start|dispatch|response|complete|failure|drop`, error kind,
    remote outcome, status and `has_correlation`. It records no URL, headers, body or
    request ID, and the events have no parent span to correlate them.
  - It is not a substitute for a transport wrapper. It could only add an
    "attempt dropped / failure kind" signal, and the wrapper's own drop guard covers that.
    **Not recommended** (new feature, new dependency, uncorrelated events).
- **Redaction utilities:**
  - `redaction.rs` is a private `redacted_debug!` macro that makes `Debug` print
    `Type([REDACTED])`.
  - `Secret` prints `[REDACTED]`, and `Error` redacts its request ID and code in
    ordinary formatting (`error.rs:190-197`).
  - **There is no public header, URL or body redaction function.** The CLI must write its
    own.

### 2.2 What the CLI already has

- `ObservedTransport` (`src/clients.rs:113-133`) wraps any transport and records the last
  status. It shows that the wrapper pattern sits in the right place.
- `DirectTransport` (`:157-209`) is the CLI-owned reqwest client for plain-http loopback.
  It copies the SDK's hardening (`transport.rs:150-166`) and adds `.no_proxy()`. It
  already owns the body stream.
- `RecordingProvider` (`:212-243`) registers each OAuth lease in the invocation's
  `SecretSet`, but only **after** `inner.token()` returns. The token response record is
  finished inside `inner.token()` (the body is read before the lease exists), so the
  `access_token` must be redacted **by key**, not by `SecretSet`. Every later request and
  echo comes after registration.
- `SecretSet` (`src/error.rs:123-216`) holds every configured secret in raw, trimmed,
  form-encoded and base64 (standard and URL-safe) forms, the Basic pair forms, and every
  lease.
  - `taints(text)` is true when `text` contains a form, or when `text` is at least
    4 bytes long and is a fragment of one.
  - Applied to every JSON string in a log, that 4-byte fragment rule will mask short
    ordinary words such as `busy` that happen to appear inside a base64 form. The debug
    log should use a stricter check: `contains(form)` for any length, and the fragment
    rule only for strings of 8 bytes or more.

---

## 3. Proposed Rust design

### 3.1 Where it hooks in

1. **Flag.** `--debug` is global (`global = true`) in `cli::Global`, with the TS help text
   `Write redacted API diagnostics to a private JSONL file`. It sets
   `Invocation::debug_log: Option<DebugLog>`.
2. **When the file is opened.** After `commands::plan` succeeds (all usage validation is
   done), before the tenant is read, and **only for plans that can make HTTP requests**:
   `doctor`, `runtime profiles|topics list|get` and `runtime scan`.
   - `tenant *`, help, version, parse errors and usage errors create no file.
   - This keeps zero-request commands from filling the 20-file retention with empty logs.
   - The per-command policy (`allowed | not applicable | refused`) belongs in the planning
     table, ready for the TS refusals (§1.1) when backup/restore, reports and judge are
     ported.
3. **Transport.** Replace `DirectTransport` and the SDK `ReqwestTransport` with one
   CLI-owned `HttpTransport { client, log: Option<DebugLog> }`.
   - It uses the exact `ReqwestTransport::configured(None, &[])` builder, plus
     `.no_proxy()` when any endpoint of the client is plain http (DESIGN §2.6 unchanged).
   - Feature unification already gives the CLI's reqwest `rustls` and `system-proxy`
     from scm-sdk, so https behaviour does not change.
   - Use the same transport whether or not `--debug` is set, so that debug runs do not
     use a different HTTP stack.
   - `ObservedTransport` keeps wrapping it.
   - If owning the https client is rejected in review, the fallback is to log https
     response metadata only (`"body":"[BODY NOT CAPTURED]"`). The response body is the
     main thing a user needs from this log, because D38 errors carry no field paths.
4. **Inside `send`, when `log` is set:**
   - Take `timestamp` and `Instant` at entry, and build the request half (redacted per
     §3.3) from `TransportRequest`.
   - Hold a `PendingRecord` guard. If the `send` future is dropped before it resolves,
     the guard writes `"error":"Request cancelled before a response"` (a deadline or a
     signal).
   - On a transport error, write `"error":"Request failed"` (TS text).
   - On a response, set `durationMs` to the time the headers arrived (TS semantics), then
     wrap the stream in a `TeeStream`. The tee passes every chunk through unchanged and
     copies at most the capture cap. It finishes the record exactly once:
     - at end of stream, with the redacted body;
     - on a chunk error, with `"body":"[BODY INCOMPLETE]"` and
       `"error":"Response body could not be read"`;
     - on drop before the end (the engine hit a limit, a redirect status left the body
       unread, or a deadline), with `"body":"[BODY INCOMPLETE]"`.
   - Each attempt (retry, token, refresh-and-replay) is its own `send` and so its own
     record, as in TS.

### 3.2 Record schema

TS field names and order, with three additions:

```jsonc
{
  "timestamp": "2026-10-17T11:03:44.500Z", // UTC, ms, Z; request start (formatted in-crate, no chrono)
  "durationMs": 6,                          // to response headers (TS semantics)
  "operation": "airs.management.profiles.list", // NEW: TransportRequest::operation()
  "request": {
    "method": "GET",
    "url": "https://api.sase.paloaltonetworks.com/aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100&latest=true",
    "headers": { "user-agent": "PAN-AIRS/0.1.0-rust-sdk", "service-name": "api", "authorization": "***" },
    "body": …                               // key absent when the body is empty (TS)
  },
  "response": {
    "status": 200,
    "statusText": "OK",                     // StatusCode::canonical_reason() ("" if none)
    "headers": { "content-type": "application/json", "date": "…" },
    "body": …,
    "bodyBytes": 722                        // NEW: bytes the engine read (decoded)
  },
  "error": "Request failed"                 // only on failure / cancel / body error
}
```

- Header names are lowercase (the `http` crate does that). Repeated values are joined with
  `, `. A value that is not UTF-8 becomes `[NON-TEXT HEADER OMITTED]`.
- The body markers are the TS ones (`[BODY OMITTED]`, `[NON-JSON BODY OMITTED]`) plus:
  - `[BODY OMITTED: <n> bytes exceeds the 1 MiB debug capture limit]`
  - `[BODY OMITTED: debug log size limit reached]`
  - `[BODY INCOMPLETE]`
  - `[CONTENT OMITTED: <n> characters]`
- A form body is logged as an object, as in TS.
- Serialize through the CLI's order-preserving `json.rs` and JS number rendering, never
  `{:?}`.

### 3.3 Redaction rules

All redaction is centralised in `src/debug_log.rs` and is a pure function of
(record parts, operation, `SecretSet`), so it can be unit-tested.

1. **Headers: allowlist.** Every name is logged. A value is shown only for these names:
   - request: `content-type`, `content-length`, `accept`, `user-agent`, `service-name`,
     `x-tsg-id`
   - response: `content-type`, `content-length`, `date`, `retry-after`, `x-request-id`,
     `x-correlation-id`, `request-id`, `server`, `cache-control`, `vary`
   - `location`, with userinfo, query and fragment replaced by `[REDACTED]`, as D45 does

   Every other value becomes `***`. That covers `authorization`, `x-pan-token`,
   **`x-payload-hash`**, `cookie`/`set-cookie` and anything unknown. An allowlisted value
   that `SecretSet`-taints also becomes `***`.
2. **URL.**
   - Userinfo becomes `[REDACTED]`. Admission already forbids userinfo in configured
     endpoints, so this is defence in depth.
   - A query value whose key matches the key rule (rule 3) becomes `***`, and so does any
     query value that taints. Paging parameters stay readable.
   - The fragment is dropped.
3. **JSON bodies** are masked recursively, by key and by value.
   - The key rule is the TS rule (§1.7) ∪ the TS SDK's
     `access_id|license_key|auth_header|request_headers|oauth2_*|script_b64`.
   - Exempt `token_type`, `expires_in` and `scope` (the over-redaction in §1.7).
   - A string value that taints becomes `***`.
   - An object key that taints drops its entry, as D47 does.
4. **Per-operation body policy (fail closed).**
   - `oauth.token`:
     - Request form: show only `grant_type`, `scope` and `audience`. Mask every other
       field.
     - Response: show only `token_type`, `expires_in` and `scope`. `access_token` and
       every other field are **always** `***`, whatever `SecretSet` holds.
     - This order matters because the lease is registered only after the record is
       finished (§2.2).
   - `airs.management.profiles.*` and `airs.management.topics.*`: JSON rule 3 on both
     bodies.
   - `airs.scan.*` (sync, async, results, reports): rule 3, and also every string under a
     content key becomes `[CONTENT OMITTED: <n> characters]`, at any depth. The content
     keys are `prompt`, `response`, `code_prompt`, `code_response`, `context`,
     `tool_event` (the whole subtree), and any key ending in `_masked_data`.
     - **Prompts and responses are never persisted.** The TS CLI already treats attack
       prompts, DLP payloads and traffic reports as not persistable (§1.1, §1.7). Scan
       content is the same kind of data, and the stderr status line already shows the
       first 80 characters.
     - Verdict fields, IDs, `errors[]`, `*_detected` and `profile_name` stay.
   - **Any other operation**: metadata only (`"body":"[BODY OMITTED]"`). A new command
     must opt in by adding a row.
   - A body that is not JSON (and not a form body for `oauth.token`):
     `[NON-JSON BODY OMITTED]`.
5. **Final line check.** Before writing, check the serialized line against `SecretSet`
   (`contains` only). If a form is still present, write the record with both bodies
   replaced by `[BODY OMITTED]` and every header value by `***`, and add
   `"redactionFallback": true`. A secret never reaches disk, even through a rule bug.

### 3.4 Size caps

- **Per body:** capture at most 1 MiB of raw bytes for redaction. JSON cannot be redacted
  once it is truncated, so a larger body becomes the size marker. A scan request is at
  most about 2 MiB (D18) and its content is omitted anyway.
- **Per file:** after 16 MiB, later records drop their bodies (size-limit marker) and keep
  their metadata. A capped `--all` walk still shows every attempt.
- Worst case on disk is 20 × (16 MiB + metadata).

### 3.5 Location, naming, permissions

- **Directory.**
  - If `XDG_STATE_HOME` is set and not empty, it must be absolute; otherwise the error
    is `XDG_STATE_HOME must be an absolute path`, exit 1, which is the registry text
    (§3.1).
  - Else the directory is `<HOME>/.local/state/airs-cli/debug`, and `HOME` must be
    absolute.
  - An empty `HOME` gives the setup error below. Do **not** copy the registry's
    relative-path behaviour.
  - `PRISMA_AIRS_TENANTS_PATH` does not affect this path.
- **Directory creation.**
  - Create it with `DirBuilder::new().recursive(true).mode(0o700)`. Every component it
    creates gets 0700, subject to umask.
  - Then `symlink_metadata` the leaf. Refuse a symlink, a non-directory, or a directory
    that is group- or world-writable (`mode & 0o022 != 0`).
  - An existing 0755 directory is accepted, because every file in it is 0600.
- **File name:** `debug-api-<epoch ms, 13 digits>-<first 8 hex of a v4 uuid>.jsonl` (the
  TS pattern; `uuid` is already a dependency).
- **File creation.**
  - `OpenOptions::new().append(true).create_new(true).mode(0o600)`. O_EXCL does not
    follow a symlink at the path.
  - Then check that the file's `uid` equals the directory's `uid`. That stands in for an
    owner check without `libc` and without `unsafe`.
- **Retention.** Prune right after the file is created.
  - List the regular files whose names match `^debug-api-\d{13}-[0-9a-f]{8}\.jsonl$`
    (skip symlinks and anything else).
  - Sort newest first by the numeric timestamp, then by name. Do **not** use mtime: a
    concurrent run that is still writing is newer by mtime but older by name.
  - Keep the newest 20, **always counting and keeping this run's own file**, and
    `remove_file` the rest.
- **Pruning race-safety.**
  - Ignore `NotFound` (another run pruned first) and every other error (best effort,
    silent).
  - Two runs pruning at once converge, because both delete the same oldest names.
  - Another run's log can be unlinked while that run is still writing it only when 20 or
    more newer logs were created meanwhile. Writing to an unlinked file is harmless.
  - No lock files are needed (the `*.lock` invariant does not apply to this directory,
    but no lock is needed either).

### 3.6 stderr notice and the hint line

- The notice is `  Debug: API log → <path>` (the TS text), sent through
  `Output::status`, so `--quiet` suppresses it. The path goes through `terminal_safe`.
  It is printed as soon as the file is created, before any other status line.
- The hint line ` Re-run with --debug to capture redacted API diagnostics.` is printed in
  the operational error block after `HTTP <status>`, as in TS, **only when `--debug` is
  off**.
  - Today Rust never prints it (D3), and with this change it would.
  - TS prints it even with `--debug`. Rust prints nothing more when `--debug` is on,
    because the notice already gave the path (§12 row).

### 3.7 Failure handling

- **Setup failure.** Directory or file creation, the directory check, or the owner check
  fails. The result is an operational error with exit 1, **before the tenant is read and
  with zero requests** (TS parity on exit code and timing):
  `\n  ✗ Error: Cannot create the debug log in <dir>; fix that directory or omit --debug\n\n`.
  The OS error is never echoed, and `<dir>` goes through `terminal_safe`.
- **Write failure during a run** (`ENOSPC`, `EIO`, file removed, …):
  - It **never changes the command's requests, stdout, exit code or error text**.
  - The first failure disables the log for the rest of the run and prints one
    non-suppressed stderr line at that moment:
    `  Warning: the debug log could not be written; it is incomplete`.
  - That is not TS parity. TS turns the failure into a fetch rejection (§1.4).
- **Signals.** Records are complete lines, each written with one unbuffered `write_all`
  on an O_APPEND file. A cancel drops in-flight futures, so the guards write their
  `cancelled` records before the exit. The "second signal exits at once" path can lose
  the in-flight record, but it never leaves a partial line, except for a single write
  the kernel splits, which is very unlikely below the pipe-buffer size and on a regular
  file.

### 3.8 Concurrency

- `DebugLog` is `Arc<Inner { file: Mutex<Option<File>>, bytes_written: AtomicU64, secrets: SecretSet }>`.
- The record is serialized outside the lock. Under the lock there is a single `write_all`.
  On error the lock sets `None`.
- The runtime is current-thread, but the design does not depend on that (future scan
  batches).
- Records come out in completion order, as in TS. Synchronous file I/O inside the async
  `send` is acceptable at these sizes, as TS also does.

### 3.9 Candidate §12 rows (D3 is replaced)

| # | Behaviour | TypeScript | airs-cli-rs |
|---|---|---|---|
| D3 | `--debug` location and retention | `./debug-api-<ms>-<8hex>.jsonl` in cwd; never pruned; setup failure says "current working directory" | `$XDG_STATE_HOME/airs-cli/debug/` (default `~/.local/state/airs-cli/debug/`), dir 0700, file 0600, newest 20 kept; setup failure names the dir in the standard `✗ Error:` block |
| new | which traffic is logged | only 5 production host suffixes; regional scanners (`service-de/in/sg`), custom and loopback endpoints give an empty file | every request of the invocation's SDK clients, whatever the host |
| new | which runs create a log | every action command, including `tenant *` and runs that fail in-action validation (an empty file) | only commands that can send requests, after usage validation |
| new | header redaction | denylist: `x-payload-hash`, `location`, unknown headers logged verbatim | allowlist; every other value `***` |
| new | body redaction | key substring rule only; echoed secrets, the PyPI auth URL and URL userinfo pass through; `token_type` masked | key rule + `SecretSet` value check + final line check; per-operation policy, unknown operations metadata-only; `token_type` shown |
| new | scan content | prompts, responses and the full scan response persisted | content fields replaced by `[CONTENT OMITTED: n characters]`; verdict kept |
| new | write failure during a run | the patched fetch throws: a good response becomes a request failure (may retry or fail the command) | outcome unchanged; one stderr warning; logging stops |
| new | record fields | `timestamp, durationMs, request, response{status,statusText,headers,body}, error`; header names in sender case | adds `operation`, `response.bodyBytes`, optional `redactionFallback`; lowercase header names; `statusText` is the canonical reason; size-cap and incomplete markers |
| new | hint line under `--debug` | `Re-run with --debug …` printed even when `--debug` is on | printed only when `--debug` is off |

### 3.10 Contract changes outside §12

- AGENTS.md "Secret safety" and DESIGN §6 say no output path may print "raw response
  bodies or URL queries". The debug log becomes the **one sanctioned sink** for
  *redacted* bodies and paging queries. Add that exception with a pointer to the new
  DESIGN section.
- DESIGN §2.3 gains `--debug`. §2.6 changes: the https transport becomes CLI-owned
  (same settings). §11 adds `src/debug_log.rs`. COMPATIBILITY rows 70, 98, 99 and the D3
  row change.

### 3.11 Tests

**Unit tests (`src/debug_log.rs`):**
- Headers:
  - allowlisted values kept, everything else `***`;
  - `x-payload-hash`, `authorization` (Basic and Bearer), `x-pan-token` and an unknown
    header are masked;
  - a `location` with userinfo and query is sanitized;
  - an allowlisted value that carries a secret is masked;
  - non-UTF-8 values get the marker; repeated values are joined.
- URL: userinfo, sensitive query keys, a tainted query value and the fragment are
  handled; `offset`, `limit` and `latest` are kept.
- JSON:
  - the TS key-rule matrix (copy the cases in `tests/unit/cli/debug-logger.spec.ts:82-131`);
  - the exemptions (`token_type`);
  - nested arrays;
  - every `SecretSet` form (raw, form-encoded, base64 standard and URL-safe, Basic pair,
    lease) is masked as a value;
  - a tainted key drops its entry;
  - the stricter fragment rule (a short ordinary word stays);
  - non-JSON and oversize bodies get markers.
- `oauth.token`:
  - the form allowlist;
  - `access_token` masked with an **empty** `SecretSet`;
  - `token_type` and `expires_in` shown.
- Scan policy: `prompt`, `response`, `code_*`, `context`, `tool_event` and
  `*_masked_data` are omitted with their lengths; the verdict fields are kept.
- An unknown operation logs metadata only.
- The final line check triggers `redactionFallback` when a rule is deliberately bypassed
  (a test-only hook).
- Golden shape: field order, an absent `body` for an empty request, an error record with
  no `response`.
- Timestamp formatting: fixed epochs, including leap days and the millisecond padding.
- `TeeStream`: bytes pass through unchanged across chunk boundaries; the record is
  written on end, on drop (incomplete), on a chunk error, and once only. A
  `PendingRecord` dropped before the response writes the cancelled record.
- Files:
  - name regex;
  - prune with 25 files keeps 20 including our own; names that do not match, symlinks
    and directories are untouched; the order is numeric, not mtime (set mtimes to
    disagree with the names); `NotFound` is tolerated;
  - a new dir is 0700 and the file 0600; `create_new` fails on collision;
  - a symlinked or world-writable dir is refused;
  - a relative `XDG_STATE_HOME` and an empty `HOME` are refused.
- Write failure: inject a failing writer. The first error disables the log and emits one
  warning, and later records are not attempted.

**Executable tests (`tests/debug_log.rs`, harness):**
- Set `XDG_STATE_HOME=<sandbox>/tmp/xdg`. The runner allows writes under `tmp/`, and
  `PRISMA_AIRS_TENANTS_PATH` still picks the registry.
- **Leak check.** Add a harness helper `Sandbox::files_under(path)`. Every test asserts
  that no `sandbox.secret_forms()` entry, no `mock-token-` lease and no `x-payload-hash`
  value recorded by the server appears in any log line. Better still: extend `Running` so
  that it automatically leak-checks every file under `<XDG_STATE_HOME or home/.local/state>/airs-cli/debug/`.
- `profiles list`: one file (0600, dir 0700) with 2 records (`oauth.token`, profiles); the
  notice is on stderr; **stdout and the exit code are byte-identical to a run without
  `--debug`**.
- `--quiet`: no notice, the file still has its records.
- 401: 4 records in order. 503 with `retry-after: 0`: 1 + 6 records. Token refused:
  1 record with `error`, exit 1. `Planned::hang` with a short budget: a cancelled record.
- `Planned::echoing_bearer` on profiles and a scan error echoing the key: `***` in the log.
- Scan with key and token: `x-pan-token`, `x-payload-hash` and `authorization` are masked;
  a unique prompt marker and the response marker are **absent** from the log, and
  `[CONTENT OMITTED` is present.
- Doctor: a record for every probe request; the outcome is unchanged.
- Retention: seed 25 old valid names plus a `notes.txt`. After the run, 20 valid files
  remain (including the new one) and `notes.txt` is untouched.
- Unwritable dir (pre-created 0500): exit 1, `server.request_count() == 0`, the message,
  empty stdout.
- Usage error with `--debug` (`--output xml`, empty prompt): exit 2, no dir created.
  `tenant list --debug`: no file.
- Default path: `XDG_STATE_HOME` unset, so the file is under `home/.local/state/airs-cli/debug/`.
  This needs a new harness opt-out that is narrower than `allow_tenant_writes`, for
  example `RunOptions::allow_writes_under("home/.local/state/airs-cli")`.
- Hint line: printed on an HTTP error without `--debug`; absent with `--debug`.

**Parity tests (`tests/parity_*.rs`, `dNN_` names):**
- Run both CLIs with `--debug`:
  - TS leaves a cwd file that is **empty** against loopback (the host filter).
  - Rust leaves a state-dir file with records.
  - Assert both sides.
- The TS hint line under `--debug` vs its absence in Rust.
- The TS empty file for `tenant list` vs no file in Rust.

To get populated TS logs for manual comparison, use the scratch alias capture (§1.9). It
needs `sandbox-exec` and a preload, so it stays out of CI.

---

## 4. Scratch artifacts (not part of the repo)

All of these are under
`/private/tmp/claude-501/-Users-cdot-development-redtail-prisma-airs-cli-rs/2663a1f5-b86a-45e5-9990-00ce664767e6/scratchpad/debuglog/`:
- `capture/`: Rust driver using `airs-test-harness`. Run `target/debug/debuglog-capture plain|alias [filter]`.
- `alias-preload.mjs`: maps the production hostnames to loopback and refuses everything
  else.
- `net.sb`: `sandbox-exec` profile that denies non-loopback outbound connections.
- `out-plain/*.jsonl` (all 0 bytes) and `out-alias/*.jsonl`: the captured logs.
- `plain.txt` and `alias.txt`: run transcripts.
- `probe.mjs` (redaction gaps) and `writefail.mjs` (write failure during a run), with
  `debug-logger.copy.ts` (an unmodified copy of the reference file).
