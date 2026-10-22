# Rust SDK scanning: spec for `airs-cli-rs` milestones 1–3

Scope: what `scm-sdk` (crate `scm-sdk`, imported as `scm`, version 0.1.0, baseline TS SDK 0.34.0) provides for AIRS runtime scanning; the exact wire behaviour it produces; how that differs from `@cdot65/prisma-airs-sdk` 0.34.0 as the TS `airs-cli` uses it; and what the Rust CLI has to add itself.

How I verified it:
- I read the source and docs. TS SDK source text came from the frozen contract inventory `scm-sdk-rs/contracts/typescript.json` (embedded `src/...` texts, commit 4a80dbdb).
- I also built a throwaway probe against the real crate, using the default reqwest transport and a raw local `127.0.0.1` HTTP/1.1 server. It is in `/private/tmp/claude-501/-Users-cdot-development-redtail-prisma-airs-cli-rs/2663a1f5-b86a-45e5-9990-00ce664767e6/scratchpad/scanprobe/`. Its target dir and lockfile stay in the scratchpad, and `git status` is clean in both repos.
- Where this spec says "observed", it means a probe result.
- Housekeeping: while setting up, I accidentally overwrote a sibling agent's `scratchpad/probe/Cargo.lock` with the scm-sdk-rs workspace lock. If that probe misbehaves, regenerate its lock.

---

## 1. Public API surface

### 1.1 Features and imports
- Cargo features: `default = ["reqwest-transport", "scan"]`, and `scan = ["models"]` (`crates/scm-sdk/Cargo.toml` [features]). serde_json is built **without** `preserve_order` (Cargo.toml deps; Cargo.lock serde_json has no indexmap). This matters for wire key order (§2.4).
- Re-exports in `src/airs/scan/mod.rs:1-12`:
  - `scm::airs::scan::{Content, ContentBuilder, Region, Scanner, SyncScanOptions}`
  - `scm::airs::scan::models::*`, which re-exports `crate::models::scan::*` (`src/models/scan.rs:2-30`): `AiProfile`, `ScanRequest`, `ScanRequestContentsInner`, `ScanResponse`, `PromptDetected`, `ResponseDetected`, `ContentError`, `Metadata`, `AgentMeta`, `ToolEvent`, `AsyncScanObject`, `AsyncScanResponse`, `ScanIdResult`, `ThreatScanReport`, …, plus `Optional`, `Nullable`, `Patch`, `JsonValue`, `JsonObject`, `FiniteNumber`.
- Crate-root re-exports in `src/lib.rs:45-53`: `Client`, `ClientBuilder`, `RawRequest`, `Endpoint`, `Limits`, `RequestOptions`, `Session`, `Error`, `ErrorKind`, `ErrorType`, `FailureKind`, `ProblemDetails`, `RemoteOutcome`, `Result`, `Secret`.
- Also used: `scm::auth::Authentication`, `scm::transport::{Transport, TransportRequest, TransportResponse}`, `scm::validation::Mode`, `scm::configuration::{init, InitOptions, ScanConfiguration}`, `scm::constants::*`.

### 1.2 Region and endpoints
`Region::{Us, Eu, India, Singapore}` and `Region::endpoint()` are defined in `src/airs/scan/scanner.rs:15-35`. The values match TS `AIRS_ENDPOINTS` and `scm::constants::AIRS_ENDPOINTS` (`constants.rs:606`):
- `https://service.api.aisecurity.paloaltonetworks.com`
- `https://service-de.api.aisecurity.paloaltonetworks.com`
- `https://service-in.api.aisecurity.paloaltonetworks.com`
- `https://service-sg.api.aisecurity.paloaltonetworks.com`

`DEFAULT_ENDPOINT` is the US URL (`constants.rs:627`).

`Endpoint` (`src/config.rs:12-117`) has two constructors:
- `Endpoint::parse(&str)` accepts **https only**. A query string, userinfo or fragment is rejected.
- `Endpoint::loopback(&str)` also allows `http://` to `localhost` or a loopback IP (`config.rs:24-27,177-197`). Observed: `Endpoint::parse("http://127.0.0.1:PORT")` gives `ErrorKind::Configuration`. `Endpoint::loopback("http://127.0.0.1:PORT/")` is OK. `Endpoint::loopback("http://example.com")` gives `Configuration`.
- A path on the base URL is joined as `<base path trimmed of trailing '/'>/<path>` (`config.rs:93-98`), which matches the TS `baseUrl.replace(/\/+$/,'') + path`.
- **The test harness must use `Endpoint::loopback`.** `Scanner::for_region` cannot target a fixture.

### 1.3 Scanner constructors
- `Scanner::new(client: Client) -> Result<Scanner>` (`scanner.rs:81-84`) requires `Authentication::Scan`. Otherwise it returns `ErrorKind::Configuration` (observed for a client with no auth). It performs no I/O and reads no environment variables.
- `Scanner::for_region(region, api_key: Option<Secret>, api_token: Option<Secret>) -> Result<Scanner>` (`scanner.rs:96-106`). It uses the region endpoint, the default reqwest transport and `Limits::default()`.
- `Scanner::client(&self) -> &Client` (`scanner.rs:108-110`). Use `client().session()` to cancel everything at once.
- Explicit endpoint, recommended for the CLI:
  ```rust
  let client = Client::builder(Endpoint::loopback(url)?/*or parse*/)
      .authentication(Authentication::scan(key, token)?)
      .limits(limits) // optional
      .build()?;
  let scanner = Scanner::new(client)?;
  ```
- Alternative mirroring TS `init()`: `scm::configuration::init(InitOptions{api_key, api_token, api_endpoint, num_retries})?.client_builder()?.build()` (`src/configuration.rs:10-135`).
  - It uses an **empty** environment snapshot, so it never reads `PANW_*` (`configuration.rs:64-66`).
  - It trims credentials with JS whitespace semantics and drops empty values. It rejects credentials longer than 2048 UTF-16 units (`configuration.rs:26-37`).
  - It defaults the endpoint to US and normalises a trailing `/`, re-applying `loopback` for http (`:83-89`).
  - `num_retries` (default 5, max 5) maps to `Limits.max_retries` (`:111-114`). This affects **only replay-safe GETs**, never `sync_scan` (§3).
  - `InitOptions` is `#[non_exhaustive]` with pub fields, so build it with `let mut o = InitOptions::default(); o.api_key = …`.

### 1.4 Credentials
- `Secret::new(value)` rejects empty strings and values over 16 KiB (`src/secret.rs:15-21`). Debug and Display print `[REDACTED]`.
- `Authentication::scan(api_key, api_token)` (`src/auth.rs:703-711`):
  - Both `None` gives `Configuration` (observed).
  - Each secret must pass `validate_header_secret`: non-empty, ≤16 KiB, every byte `is_ascii_graphic` (`auth.rs:841-850`). So `"key with space"` and `"key\n"` both give `Configuration` (observed).
  - TS `init()` instead does `.trim()` and treats empty as absent (TS `src/configuration.ts:49`). **The Rust CLI must trim tenant values itself, or use `configuration::init`, to match.**
- Headers applied in `Authentication::prepare` (`auth.rs:727-777`):
  - Caller-supplied `authorization`, `x-pan-token`, `x-payload-hash`, `x-portkey-api-key` or `x-tsg-id` gives `Configuration`.
  - Token present: `authorization: Bearer <token>`.
  - Key present: `x-pan-token: <key>`, plus, when the request has a body, `x-payload-hash: hex(HMAC-SHA256(key, exact body bytes))`. The hex is lowercase, 64 chars, and checked against RFC 4231 in `auth.rs:1019-1047`.
  - All header values are marked sensitive.
- This matches TS `ApiKeyAuth.prepare` (`src/http/auth/api-key.ts:33`), which sets Authorization if a token is present, and `x-pan-token` plus `x-payload-hash` (`generatePayloadHash` = `createHmac('sha256', key).update(bodyText).digest('hex')`, `src/utils.ts:37`) if a key is present.

### 1.5 `SyncScanOptions` (`scanner.rs:37-53`)
`#[non_exhaustive] #[derive(Clone, Default)]`, with pub fields:
- `tr_id: Option<String>`. An empty string is omitted.
- `session_id: Option<String>`. An empty string is omitted.
- `metadata: Option<Metadata>`.
- `request: Option<RequestOptions>`, which carries the deadline, cancellation and retry override.

Debug prints `SyncScanOptions([REDACTED])`. Length limits are enforced by the schema, not by this struct: `tr_id` and `session_id` must be ≤100 UTF-16 units. Observed: a 101-char `tr_id` gives `Validation` with 0 requests sent. TS checks the same limit by `.length` (`scanner.ts` syncScan).

### 1.6 `sync_scan` signature
```rust
pub async fn sync_scan(&self, profile: &AiProfile, content: &Content,
                       options: Option<&SyncScanOptions>) -> Result<ScanResponse>   // scanner.rs:115-150
pub async fn scan_request(&self, request: &ScanRequest, options: Option<&RequestOptions>)
                       -> Result<ScanResponse>                                        // :154-171
```
`sync_scan` builds the `Body { ai_profile, contents: [content.to_json()], tr_id?, session_id?, metadata? }` (`:123-140`). It then calls `send_model(RawRequest::new(POST, "/v1/scan/sync/request").named("airs.scan.sync"), body, "ScanRequestSchema", "ScanResponseSchema", options.request)`.

`scan_request` validates every content item with `validate_content`. It keeps `ScanRequest` extensions, because the schema is passthrough.

### 1.7 `RequestOptions`, `Session`, `Limits` (`src/config.rs`)
- `RequestOptions::with_timeout(d)` (`:367-379`):
  - Accepts 0 < d ≤ 86400 s. The deadline is fixed at **construction time** (`Instant::now()+d`), so build it immediately before the call.
  - It is a **total operation budget**: permit, auth, send, body read and decode are all bounded by `options.run` (`:405-426`).
- `.with_retries(n)` with n ≤ 5 overrides **safe-read** retries only. The doc says "never enables mutation or inference replay" (`:383-391`).
- `.cancel()`, `.cancellation_token()`. Clones share one token.
- With no options, `Limits.operation_timeout` (60 s) is used (`engine.rs:470-479`).
- `Session::cancel()` is shared by all clones of a `Client` and is **sticky**. Observed: after a session cancel, every later call fails immediately with `Cancelled`/`NotSent` and sends 0 requests.
- `Limits::default()` (`config.rs:285-302`):

  | Field | Default |
  | --- | --- |
  | `operation_timeout` | 60 s |
  | `max_request_bytes` | 8 MiB |
  | `max_response_bytes` | 8 MiB |
  | `max_error_bytes` | 64 KiB |
  | `max_concurrency` | 32 |
  | `max_retries` | 2 |
  | `retry_base_delay` | 250 ms |
  | `max_retry_delay` | 5 s |

  `validate()` caps `max_retries` at 5 (`:304-336`).

### 1.8 `Content` (`src/airs/scan/content.rs`)
- Builder (`:23-60`): `.prompt(s)`, `.response(s)`, `.context(s)`, `.code_prompt(s)`, `.code_response(s)`, `.tool_event(ToolEvent)`, then `.build() -> Result<Content>`.
- Other constructors: `Content::from_json(ScanRequestContentsInner)`, which drops undeclared extension fields (`:74-79`); `from_json_slice(&[u8])`; `from_reader(impl Read, max_bytes)` (`:88-101`, max_bytes 1..=512 MiB, else `Configuration`; over the bound gives `Limit`; read failure gives `Io`); `async from_json_file(path, max_bytes)` (`:104-121`, errors carry no path or OS text).
- Accessors: `to_json()`, `into_json()`, `prompt()`, `response()`, …, `length()`, which sums UTF-8 bytes of the five text fields and so equals the TS `Buffer.byteLength` sum.
- Transactional setters (`set_prompt(Option<String>)`, …) validate a candidate first (`:162-186`).
- `validate_content` (`:188-216`):
  - Error if every primary field (prompt, response, code_prompt, code_response) is unset or `""` **and** `tool_event` is unset. Context alone is rejected.
  - prompt, response and code_* must each be ≤ 2 MiB (2,097,152 UTF-8 bytes); context ≤ 100 MiB.
  - Errors are bare `ErrorKind::Validation`, with no message.
  - Observed: `prompt("")` gives Validation. `context("c")` alone gives Validation. 2 MiB + 1 byte gives Validation. Exactly 2 MiB is sent.
- TS `Content` has the same truthiness rule (`src/scan/content.ts:33`). Its errors carry messages: `At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided`, and `prompt exceeds max length of 2097152 bytes`.
- **Empty-string semantics:** both SDKs *send* a present empty string. Observed: Rust `prompt("p").response("")` gives `{"prompt":"p","response":""}`. The TS **CLI** omits an empty `--response` (`src/airs/runtime.ts:217` `if (response) contentOpts.response = response`), so the Rust CLI must not call `.response("")`.
- The client request bound (8 MiB by default) applies independently. A 100 MiB context is allowed by `Content` but rejected at dispatch with `Limit` unless `Limits.max_request_bytes` and the validation limits are raised (docs/VALIDATION.md:46-50). The TS SDK has no client-side byte cap.

### 1.9 `AiProfile` (`src/models/generated.rs:4365-4447`)
- Fields: `profile_id: Optional<String>`, `profile_name: Optional<String>`, `extensions`. Build with `AiProfile::builder().profile_name(Optional::Value(name)).build()` or `.build_validated(Mode::Request)`.
- `build()` checks nothing. The request schema (`AiProfileSchema`, TS `src/models/ai-profile.ts:5`) is enforced inside `sync_scan`:
  - `profile_id` must be a UUID.
  - `profile_name` must be ≤ 100.
  - The refine `profile_id || profile_name` requires a truthy selector.
- Observed failures (all `Validation`, 0 requests): `profile_name ""`, 101 chars, no selector, `profile_id "nope"`. 100 chars is sent.
- TS failure text for the same cases: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/scan/sync/request did not match schema: ai_profile: custom` (TS `src/http/request.ts:20`).

---

## 2. Exact HTTP request produced by `sync_scan`

### 2.1 Pipeline
1. `send_model` (`engine.rs:583-606`) calls `validated_json` (`:524-552`), which serialises `Body` compactly (`serialize_bounded`, `:1436`, depth ≤128, ≤ `max_request_bytes`). It then parses the bytes into a `serde_json::Value`, runs `validation::parse_with_limits("ScanRequestSchema", Mode::Request)`, and **re-serialises the normalised Value**. All of this runs before authentication.
2. `preflight` (`:908-943`) resolves and admits the URL against the endpoint origin plus the `OriginPolicy`, checks byte and header limits, and re-checks that the JSON parses.
3. `Authentication::prepare` adds auth headers, then the request is sent once (§3).

### 2.2 Headers
- Defaults on every request: `user-agent: PAN-AIRS/<crate version>-rust-sdk`, observed `PAN-AIRS/0.1.0-rust-sdk` (`engine.rs:22-32`, also `scm::constants::USER_AGENT`), and `service-name: api`.
- Plus `content-type: application/json` and the auth headers. reqwest adds `accept: */*`, `accept-encoding: gzip`, `host` and `content-length`.
- No `x-tsg-id`.
- Observed for a key-only tenant, in order: `user-agent, service-name, content-type, x-pan-token, x-payload-hash, accept, accept-encoding, host, content-length`.
  - Token-only: `authorization: Bearer <tok>` and no `x-pan-token` or hash.
  - Key and token: `authorization`, `x-pan-token`, `x-payload-hash`.
- TS sends `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `service-name: api`, `Content-Type: application/json`, then the same auth headers (`src/http/request.ts:20` request(); TS `USER_AGENT` in `src/constants.ts:51`). Node/undici adds its own transport headers.
- **The harness should assert only the SDK-owned headers, case-insensitively, and accept either user-agent value by prefix `PAN-AIRS/`.**

### 2.3 Method, path, query
`POST /v1/scan/sync/request` (`scanner.rs:143`; TS `SYNC_SCAN_PATH`). There is no query string.

### 2.4 Body key order (observed; matters for byte comparison and for `x-payload-hash`)
Because the body is normalised through a `serde_json::Value` (a BTreeMap, since there is no `preserve_order`), **Rust emits object keys in alphabetical order at every level**, regardless of the `Body` struct order. Observed:
- Minimal: `{"ai_profile":{"profile_name":"prof-a"},"contents":[{"prompt":"Ignore all previous instructions"}]}`
- Full: `{"ai_profile":{"profile_id":"550e…","profile_name":"prof-a"},"contents":[{"code_prompt":"cp","context":"c","prompt":"p","response":"r"}],"metadata":{"ai_model":"m","app_name":"airs-cli","app_user":"u"},"session_id":"sess-1","tr_id":"tr-1"}`
- Empty `tr_id` and `session_id` are omitted.

TS sends Zod v3 (`zod@3.25.76`) `safeParse` output (`validatedBody = result.data`, `request.ts:20`). That output is in **schema-shape order**, followed by passthrough extras:
- ScanRequest order: `tr_id, session_id, ai_profile, metadata, contents`.
- Contents order: `prompt, response, code_prompt, code_response, context, tool_event`.
- Metadata order: `app_name, app_user, ai_model, user_ip, agent_meta`.

Consequences:
- For the M3 shapes the TS CLI sends — `{profile_name}` plus `{prompt[, response]}`, no tr_id, session or metadata (`runtime.ts:220`) — **the bytes are identical**, so `x-payload-hash` is identical across CLIs.
- If any of tr_id, session_id, metadata, context or code_* is used, the bytes differ. Both hashes are valid for their own bytes.
- Compare bodies semantically (parsed JSON deep-equal), and verify the hash by recomputing HMAC over the *received* bytes.
- JSON string escaping is compatible: both are compact, with control characters as `\n`/`\t`/… or `\u00xx` lowercase, and non-ASCII sent raw.

### 2.5 Other scan operations
- `async_scan(&[AsyncScanObject], Option<&RequestOptions>)` (`scanner.rs:175-197`): `POST /v1/scan/async/request`, JSON array body, 1–20 objects. Otherwise it returns bare `Validation`, with no TS-style messages `At least 1 scan object is required` / `Max of 20 scan objects allowed`. It validates every content item. `scm::constants::MAX_NUMBER_OF_BATCH_SCAN_OBJECTS = 20` (`constants.rs:655`).
  - Observed body: `[{"req_id":0,"scan_req":{"ai_profile":{"profile_name":"p"},"contents":[{"prompt":"a"}],"session_id":"s"}},…]` (alphabetical within `scan_req`).
  - Receipt `AsyncScanResponse{received, scan_id, report_id?, source?}`.
- `query_by_scan_ids(&[String], …)` (`:201-216`): `GET /v1/scan/results?scan_ids=<ids joined by ','>`, 1–5 UUIDs, with no body, no content-type and no hash. This is the TS doctor's scanner probe (`doctor.ts:614-617`, random UUID).
- `query_by_report_ids` (`:221-236`): `GET /v1/scan/reports?report_ids=…`, 1–5 ids, each ≤1024 bytes, no commas or control characters (`:238-252`).

---

## 3. Retry, timeout, cancellation

Rust logic is in `send_buffered_observed` (`engine.rs:1116-1267`):
- `sync_scan` and `async_scan` use `RawRequest::new`, so `replay_safe=false` (`engine.rs:49-61`). **They are never retried, for any status or transport error, even with `with_retries(5)`.** Tested in `tests/scan_contracts.rs:382-438`. Observed: 401, 403, 429, 500 and 503 each produced exactly 1 request, and so did the async 503.
- Safe reads (`RawRequest::read`, the GET queries):
  - Retried statuses are **429, 502, 503, 504** (`retryable`, `engine.rs:1372-1374`). **500 is not retried.** Transport errors are also retried (`:1175-1185`).
  - Budget is `options.retry_limit()` or else `Limits.max_retries` (2) (`:1135-1139`).
  - Delay is `Retry-After` (delta-seconds or HTTP-date, `:1375-1393`) or else backoff `250ms·2^n` capped at 5 s (`:1337-1343`). If the Retry-After wait is over `max_retry_delay` (5 s), **no retry**: the error is returned immediately (`:1226-1236`).
  - Observed: GET 503 gave 3 requests in ~750 ms. GET 500 gave 1. GET 429 with `Retry-After: 1` gave 3 in ~2 s. GET 503 with `Retry-After: 10` gave 1. `with_retries(0)` gave 1.
- 401/403 with scan auth: no refresh (only OAuth refreshes, `auth_rejection` `:1345`).
- Redirects are never followed: 3xx gives `Destination` with status and `Rejected` (`:1193-1198`; observed 302).
- TS `executeWithRetry` (`src/http-retry.ts:182`) applies to **all methods including the syncScan POST**:
  - Retried statuses `HTTP_FORCE_RETRY_STATUS_CODES = [500,502,503,504]`. **429 is not retried.** Network errors are retried too.
  - Budget is `numRetries`: per-call value, else global `init({numRetries})`, default `MAX_NUMBER_OF_RETRIES = 5`. The TS CLI passes `config.airsNumRetries` (`client-options.ts:95`) and no per-call override for `runtime scan`.
  - Backoff is full jitter `random[0, 2^attempt·1000] ms` (`http-retry.ts:37`). `Retry-After` is honoured on retryable statuses, capped at 60 s.
  - The timeout is **per attempt**: `PANW_AI_SEC_TIMEOUT_MS` or 60 000 ms (`request.ts:20`). The TS CLI allows that env var (`src/config/env.ts:8-12`).
  - Fetch `redirect` defaults to follow.
- Deadline (observed): a server that hangs with a 500 ms budget gives `Deadline` after ~502 ms, outcome `Unknown`, error type `AISEC_SDK_ERROR`.
- Cancellation (observed):
  - In-flight `RequestOptions::cancel()` gives `Cancelled` after ~300 ms, outcome `Unknown`.
  - A pre-cancelled options value gives `Cancelled`, `NotSent`, and 0 requests.
  - A session cancel gives `Cancelled`/`Unknown`, and every later call gives `NotSent`.
  - The TS `runtime scan` installs no SIGINT handler and passes no signal (`runtime.ts:1044-1069`). The default Node SIGINT terminates the process.

---

## 4. Response model and JSON output

### 4.1 `ScanResponse` (`generated.rs:164240-164395`; TS `ScanResponseSchema`, `src/models/scan-response.ts:114`, passthrough)
- Required: `report_id: String`, `scan_id: String`, `category: String`, `action: String`, `timeout: bool`, `error: bool`, `errors: Vec<ContentError>`.
- Optional (`Optional<T>`; **an explicit JSON null is rejected**): `source`, `tr_id`, `session_id`, `profile_id`, `profile_name`, `prompt_detected: PromptDetected`, `response_detected: ResponseDetected`, `prompt_masked_data`, `response_masked_data: MaskedData`, `prompt_detection_details`, `response_detection_details`, `tool_detected`, `created_at`, `completed_at`.
- Also `extensions: Extensions<JsonValue>` (BTreeMap).
- `action` and `category` are plain strings, so unknown values are preserved and never mapped (docs/SCANNING.md:39-42).
- `PromptDetected` (`generated.rs:157252`): `url_cats, dlp, injection, toxic_content, malicious_code, source_code, agent, topic_violation`, all `Optional<bool>`, plus extensions.
- `ResponseDetected` (`generated.rs:160290`): `url_cats, dlp, db_security, toxic_content, malicious_code, agent, ungrounded, topic_violation`, plus extensions. **It has no `injection` and no `source_code`.**
- `ContentError`: `content_type, feature, status`, all `Optional<String>`, plus extensions.
- Reading a flag: `resp.prompt_detected.as_ref().into_option().and_then(|p| p.injection.as_ref().into_option().copied())`. `Optional` has `is_unset`, `as_ref`, `into_option` (`src/data.rs:11-30`).
- Decoding (`decode_contract`, `engine.rs:702-734`): an empty 2xx body is treated as `{}`, which then fails on required fields. Then come `validation::parse(Mode::Response)` (unknown fields and enum strings kept) and serde.
  - Observed `Decode` (HTTP 200) for: non-JSON, an empty body, a missing `action`, and `"prompt_detected": null`.
  - TS gives the same outcomes as `AISEC_RESPONSE_VALIDATION`, with messages like `Response did not match schema: action: invalid_type`.
- Size cap is 8 MiB; over that gives `Limit` with status 200.

### 4.2 Serialising back to JSON
`serde_json::to_string(&response)` emits:
- known fields in **schema order**, skipping unset ones;
- then extension keys **alphabetically**;
- nested `JsonValue` objects alphabetically.

Observed: a server object starting with `zz_server_field:{b,a}` and `action` comes back as `{"source",…,"report_id","scan_id","tr_id","profile_id","profile_name","category","action","timeout","error","errors","prompt_detected":{"dlp","injection","topic_violation","future_det"},"response_detected",…,"created_at","zz_server_field":{"a":2,"b":1}}`.

TS `JSON.stringify` of the Zod output gives schema order, then extras in **server order**, with nested extra objects untouched. So for semantic equality the content matches, but byte order differs whenever the server sends unknown or nested-unknown keys. Serialisation fails only if an extension key collides with a known key, which cannot happen after decode.

### 4.3 What the TS CLI derives (it must be reproduced; the SDK does not do it)
`runtime scan <prompt> --profile <name> [--response <text>]` (`runtime.ts:1044-1069`) calls `SdkRuntimeService.scanPrompt` (`src/airs/runtime.ts:211-229`), which works as follows:
1. `syncScan({profile_name}, new Content({prompt[, response if truthy]}), undefined)`.
2. `scanResponseToResult` (`:100-135`):
   - `detections` = the keys of **`prompt_detected` only**, in `RUNTIME_DETECTION_KEYS` order `topic_violation, injection, toxic_content, dlp, url_cats, malicious_code, source_code, agent` (`:26-35`), included when the value is boolean (`:82-89`).
   - `action` is lowercased; anything other than allow or block is `failed` (`:94-97`).
   - `failed = error===true || timeout===true || action==='failed'`. Then `category = failed ? 'error' : (category ?? 'unknown')`, and `triggered = any detection true`.
3. Then **`action: normalized.action === 'block' ? 'block' : 'allow'`** (`:225`). A failed, timed-out or unknown-action scan is therefore reported as **ALLOW** (with Category `error`).
4. Rendering (`runtime.ts:67-85`):
   - Header `Scan Result`, then key/value lines `Action` (uppercase), `Category`, `Triggered` (`yes`/`no`), `Scan ID`, `Report ID`, all to stdout.
   - Then, if any flag is true, section `Detections` with a bullet per true key.
   - Status lines `Prisma AIRS Runtime Scan`, `Profile: <name>`, and `Prompt:  "<first 80 chars>[...]"` go to stderr (`ui.status`, `src/cli/renderer/ui.ts:130-134`).
   - **There is no `--output json` on `runtime scan`.**

---

## 5. Errors

`Error` API (`src/error.rs`):
- `kind() -> ErrorKind`: Configuration, Validation, Destination, Authentication, Io, Transport, Http, Decode, Limit, Deadline, Cancelled, Protocol, Pagination.
- `status() -> Option<u16>`, `operation() -> Option<&'static str>` (`"airs.scan.sync"`, `"airs.scan.async"`, `"airs.scan.results"`, `"airs.scan.reports"`), `request_id()` (allowlisted from `x-request-id`, `x-correlation-id` or `request-id`), `service_code()` (body `code`, `error.code`, `data.errorCode` or `errorCode`; `engine.rs:1402-1427`).
- `retry_after()`: the header is preferred, then body `retry_after{interval,unit}` (`problem.rs` `body_retry_after`).
- `remote_outcome()` (NotSent/Rejected/Unknown), `failure_kind()` (Http/Network), `error_type()` (AIRS taxonomy, `error.rs:110-146`), `problem()` (allowlisted title, detail and fields only, else `[withheld]`; `problem.rs:8-60,126-182`).
- Display is `SCM SDK <Kind>[ (HTTP n)]` (`error.rs:268-276`). Debug carries only metadata flags. **No server message text is ever retained.**

Observed matrix for `sync_scan` (all with 1 request sent unless noted):

| Scenario | kind | status | outcome | error_type | other |
| --- | --- | --- | --- | --- | --- |
| local validation | Validation | – | NotSent | USER_REQUEST_PAYLOAD_ERROR | 0 requests |
| 401 | Http | 401 | Rejected | CLIENT_SIDE_ERROR | failure Http |
| 403 | Http | 403 | Rejected | CLIENT_SIDE_ERROR | |
| 404 with `x-request-id` and `code` | Http | 404 | Rejected | CLIENT_SIDE_ERROR | request_id `req-123`, code `E404` |
| 400 problem | Http | 400 | Rejected | CLIENT_SIDE_ERROR | problem title `Bad Request`, detail `[withheld]` |
| 429 with `Retry-After: 2` | Http | 429 | Rejected | CLIENT_SIDE_ERROR | retry_after 2 s (header beat body 3 s) |
| 500 | Http | 500 | Unknown | SERVER_SIDE_ERROR | |
| 503 | Http | 503 | Unknown | SERVER_SIDE_ERROR | retry_after 1 s |
| connection refused | Transport | – | **Unknown** | CLIENT_SIDE_ERROR | failure Network |
| hang past deadline | Deadline | – | Unknown | SDK_ERROR | |
| cancel | Cancelled | – | Unknown or NotSent | SDK_ERROR | |
| 302 | Destination | 302 | Rejected | CLIENT_SIDE_ERROR | |

Connection refused is `Unknown` because the "sent" flag is set before `transport.send`, `engine.rs:1164`.

Edge cases:
- An error body over 64 KiB becomes `Limit` (status kept, outcome Unknown even for 4xx), not `Http` (`engine.rs:1211-1213`). Classify by `status()` before `kind()`.
- TS errors are `AISecSDKException` with `message = "<ERRORTYPE>:<text>"`, `statusCode`, `failureKind`, `retryAfterMs`, `problem` (`src/errors.ts:46`). The text comes from `extractErrorMessage` (`http-retry.ts:73`):
  - `problemMessage`, which is `API error <status>; <title>; <detail>; <prop>: <reason>`, or else `error_message`, `message`, `data.message`, `error.message`, `msg`, or `API error <status>`;
  - plus ` (errorCode: X)`;
  - a non-JSON body gives `API error <status>: <body>`.
- The TS CLI `fail()` (`src/cli/renderer/common.ts:12-25`) prints `\n  ✗ Error: <message>`, then `    HTTP <status>` and `    Re-run with --debug to capture redacted API diagnostics.` to stderr, and exits 1. `usageError` exits 2.
- **The Rust CLI must construct its own messages** from kind, status, problem and code. It cannot echo server text, which is a deliberate safety difference.

---

## 6. Test-harness notes
- Build the Rust client with `Endpoint::loopback(tenant.airsApiEndpoint)` when it is `http://127.0.0.1:…`, otherwise `Endpoint::parse`. The TS CLI passes `apiEndpoint` straight to `init`.
- To get a request-count parity fixture with 5xx, set `airsNumRetries: 0` in the fixture tenant. Otherwise TS sends 1 + N POSTs and Rust sends 1.
- Unset `PANW_AI_SEC_API_KEY`, `PANW_AI_SEC_API_TOKEN`, `PANW_AI_SEC_API_ENDPOINT` and `PANW_AI_SEC_TIMEOUT_MS` for TS runs (see the token-only leak in Discrepancies). Separately assert that sentinel values in these never reach the server from the Rust binary.
- Unset `HTTP(S)_PROXY`/`ALL_PROXY` (reqwest `system-proxy` honours env and macOS proxies; undici does not by default).
- Record raw body bytes and verify `x-payload-hash == hmac_sha256_hex(key, raw)`. Compare bodies as parsed JSON, and also byte-compare for the minimal M3 shapes, where they are identical.
- Fixture responses should list known fields in schema order. Test unknown-field preservation semantically.

---

## 7. Later milestones (brief)
- The TS CLI bulk path calls `asyncScan(objects, {numRetries: 0})` (`runtime.ts:23,264,487`), which Rust already guarantees: one dispatch, ambiguous failures are `Unknown`.
- TS rate-limit detection `isDefiniteRateLimitError` (`failureKind==='http' && statusCode===429`, `runtime.ts:76-79`) maps to Rust `kind()==Http && status()==Some(429) && failure_kind()==Some(FailureKind::Http)` (outcome Rejected).
- The TS message-sniffing `isRateLimitError` (`'rate limit'`/`'429'` in the text) cannot be ported.
- Rust results keep server order, duplicates and one-to-many rows (`scan_contracts.rs:227-271`).


## Acceptance criteria
- `airs-cli-rs runtime scan --profile P "text"` sends exactly one HTTP request: POST /v1/scan/sync/request on the tenant's airsApiEndpoint (loopback fixture), with no query string.
- The minimal scan body parses to exactly {"ai_profile":{"profile_name":"P"},"contents":[{"prompt":"text"}]}, with no tr_id, session_id or metadata keys.
- For the minimal and prompt+response shapes, the raw body bytes are byte-identical between airs-cli and airs-cli-rs (compact JSON, keys ai_profile < contents, prompt < response).
- `--response R` gives contents[0] == {"prompt":"text","response":"R"}; `--response ""` gives no response key (TS CLI parity, runtime.ts:217).
- A key-only tenant: the request has x-pan-token == airsApiKey, x-payload-hash == lowercase hex HMAC-SHA256(airsApiKey, raw body bytes), content-type application/json, service-name: api, and user-agent starting with "PAN-AIRS/".
- A token-only tenant: the request has authorization == "Bearer <airsApiToken>" and has neither x-pan-token nor x-payload-hash.
- A key+token tenant: the request carries authorization Bearer, x-pan-token and x-payload-hash together.
- With PANW_AI_SEC_API_KEY, PANW_AI_SEC_API_TOKEN and PANW_AI_SEC_API_ENDPOINT set to sentinel values, airs-cli-rs never sends the sentinels and never contacts the sentinel endpoint.
- Leading/trailing whitespace in tenant airsApiKey is trimmed before it is sent (TS init().trim() parity), rather than failing with a configuration error.
- `runtime scan --profile P ""` (no response) sends zero HTTP requests, exits 1, writes the error to stderr and nothing to stdout.
- A profile name of 101 characters sends zero HTTP requests and exits nonzero (1 for TS parity); 100 characters is sent.
- A prompt of exactly 2,097,152 UTF-8 bytes is sent; 2,097,153 bytes sends zero requests and exits nonzero.
- A 200 response with action "block" and prompt_detected.injection=true gives exit 0, stdout reporting action BLOCK, triggered yes and an injection detection, and stderr holding only status lines.
- A 200 response with action "allow" and no prompt_detected gives exit 0 with triggered no and an empty detections set.
- Detections are derived only from prompt_detected keys in the order topic_violation, injection, toxic_content, dlp, url_cats, malicious_code, source_code, agent, and include a key only when its value is boolean.
- A 200 response with an unknown action string (e.g. "future-action"), error:true or timeout:true is never reported as ALLOW by airs-cli-rs (fail-closed; TS displays ALLOW — documented divergence).
- HTTP 401 on the sync scan gives exactly one request, exit 1, stderr containing "HTTP 401", empty stdout, and stderr never containing the API key, token, payload hash or response-body text.
- HTTP 403 on the sync scan gives exactly one request, exit 1, and stderr containing "HTTP 403".
- HTTP 429 with Retry-After: 2 on the sync scan gives exactly one request from both CLIs, exit 1, and stderr containing "HTTP 429".
- HTTP 500 or 503 on the sync scan gives exactly one request from airs-cli-rs (no POST replay) and exit 1; airs-cli sends 1+airsNumRetries requests.
- A 200 response with a non-JSON body, an empty body, a missing required field (action/category/scan_id/report_id/timeout/error/errors) or prompt_detected:null gives exit 1 with no stdout data.
- A 302 response with Location on the sync scan gives exit 1 from airs-cli-rs, and no request is made to the Location target.
- A server that accepts the connection but never responds makes airs-cli-rs exit 1 within the configured scan deadline (default 60 s total) with a timeout message on stderr.
- Connection refused on airsApiEndpoint gives exit 1, a network-failure message on stderr, empty stdout, and no secrets in the output.
- SIGINT during an in-flight scan makes airs-cli-rs exit promptly with a nonzero status and write no partial data to stdout.
- An error response body that echoes the API key or prompt is never reproduced on stdout or stderr by airs-cli-rs.
- The doctor scanner probe sends GET /v1/scan/results?scan_ids=<valid UUID> with x-pan-token and no body, content-type or x-payload-hash.
- The doctor scanner probe treats 401/403 as 'API key rejected (HTTP <status>)' (fail) and a 200 empty array as pass.
- The airs-cli-rs doctor scanner probe on HTTP 503 sends 3 requests by default (1 + 2 safe-read retries), and on HTTP 500 sends 1 request.
- If airs-cli-rs offers JSON scan output, unknown top-level and nested response fields from the fixture appear in its stdout JSON (semantic deep-equal to the fixture for all server keys).
- async/batch (later milestone): a batch of 21 objects sends zero requests; a batch of 20 sends exactly one POST /v1/scan/async/request even on a 5xx or transport failure.


## Discrepancies
- Retry divergence on the sync scan POST: TS executeWithRetry (src/http-retry.ts:182) retries 500/502/503/504 and network errors up to numRetries (tenant airsNumRetries, default 5), with jittered backoff random[0, 2^n·1000] ms and Retry-After capped at 60 s. Rust sync_scan (RawRequest::new, replay_safe=false, engine.rs:49-61,1226) never retries. Request counts differ under 5xx and network faults.
- Safe-read retry sets differ (affects the doctor probe GET /v1/scan/results): Rust retries 429/502/503/504 (not 500) with default max_retries=2, 250 ms·2^n backoff capped at 5 s, and skips the retry entirely when Retry-After > 5 s (engine.rs:1372-1374,1226-1236,1337-1343). TS retries 500/502/503/504 (not 429) with default 5.
- airsNumRetries maps to Limits.max_retries in Rust (configuration.rs:111-114). That only affects GETs, never sync/async scans, so the tenant setting has different meaning in the two CLIs.
- Timeout semantics: TS uses a per-attempt deadline of 60 s, overridable by the PANW_AI_SEC_TIMEOUT_MS env var, which the TS CLI explicitly allows (env.ts:8-12, request.ts:20). Rust uses one total operation deadline (Limits.operation_timeout 60 s, or RequestOptions::with_timeout fixed at construction time) and reads no env vars.
- Wire JSON key order: Rust re-serialises the validated serde_json::Value (BTreeMap, no preserve_order), so keys are alphabetical at every level (observed). TS sends Zod v3 output in schema-shape order (tr_id, session_id, ai_profile, metadata, contents; prompt, response, code_prompt, code_response, context, tool_event). The bytes, and therefore x-payload-hash, differ whenever tr_id, session_id, metadata, context or code_* is present; they are identical for the M3 minimal and prompt+response shapes.
- User-Agent differs: TS sends PAN-AIRS/0.34.0-typescript-sdk (constants.ts:51); Rust sends PAN-AIRS/0.1.0-rust-sdk (engine.rs:22-23).
- Error text: TS messages are "AISEC_<TYPE>:<server-derived text>" (extractErrorMessage echoes message/error_message/msg or a raw non-JSON body) and the CLI prints them via fail(). Rust Error Display is only "SCM SDK <Kind> (HTTP n)" and retains no server text (only allowlisted problem phrases), so stderr parity cannot be literal.
- Credential normalisation: TS init() trims apiKey/apiToken and treats '' as absent, with max length 2048. Rust Authentication::scan rejects any non-graphic ASCII byte (space, newline) with Configuration and allows up to 16 KiB (auth.rs:841-850). Only scm::configuration::init trims and caps at 2048.
- Credential-env leak in the TS CLI: runtimeInitOptions passes apiKey: config.airsApiKey, which may be undefined (client-options.ts:92). TS init falls back to process.env.PANW_AI_SEC_API_KEY (and likewise the token), so a token-only tenant picks up an env API key. That contradicts env.ts ('The CLI reads no configuration from the environment'). The unit test (client-options.spec.ts:194-199) covers only the no-credential case.
- TS CLI fail-open: scanPrompt maps any non-'block' normalized action — including 'failed' for error:true, timeout:true or an unknown action — to 'allow' (src/airs/runtime.ts:225), so the user sees ALLOW with Category 'error'. This is untested (tests/unit/airs/runtime.spec.ts). The Rust SDK docs require never mapping unfamiliar outcomes to allow.
- The TS CLI runtime scan derives detections and triggered only from prompt_detected and ignores response_detected even when --response is supplied (runtime.ts:100-135). response_detected's distinct keys (db_security, ungrounded) are never surfaced.
- `runtime scan` in the TS CLI has no --output json (runtime.ts:1044-1069); output is pretty text only, so there is no TS JSON scan shape to compare against.
- Connection refused (nothing reached the server) is reported by Rust with RemoteOutcome::Unknown, because the sent flag is set before transport.send (engine.rs:1164). Don't use outcome to tell 'never connected' from 'ambiguous'.
- An error body larger than max_error_bytes (64 KiB) yields ErrorKind::Limit (status preserved, outcome Unknown even for 4xx) instead of ErrorKind::Http (engine.rs:1211-1213). A Rust CLI that classifies by kind() would mislabel 401/403.
- Size caps: Rust defaults max_request_bytes and max_response_bytes to 8 MiB and validation string budgets to 8 MiB, so a Content with a 100 MiB context (allowed by Content::validate) fails at dispatch with Limit. TS has no client-side caps.
- Redirects: Rust never follows 3xx (Destination error). TS fetch uses the default redirect 'follow' (request.ts passes redirect only when spec.redirect is set), so TS would follow and may forward x-pan-token (custom headers survive cross-origin redirects; only Authorization is stripped).
- Empty --response: the TS CLI omits it (runtime.ts:217), but both SDKs send a present empty string (observed Rust {"prompt":"p","response":""}). The Rust CLI must not call .response("").
- Scanner::for_region always uses an https regional endpoint and default Limits, so it cannot target the loopback fixture. Endpoint::parse rejects http:// (Configuration); Endpoint::loopback is required.
- Ledger inconsistency in scm-sdk-rs: contracts/export-classification.json lists Scanner, Scanner.syncScan, asyncScan and the query methods as rustImplementation 'unimplemented', liveAcceptance 'unverified' (around lines 28940-29010), while contracts/native-operations.json (around lines 12070-12260) records them as implemented with live evidence 'verified'.
- TS validation errors are descriptive (e.g. 'Request body for POST /v1/scan/sync/request did not match schema: ai_profile: custom', 'trId exceeds max length of 100', 'Max of 20 scan objects allowed'). Rust returns bare ErrorKind::Validation with operation 'airs.scan.sync' and no field information.
- The TS doctor's withTimeout (doctor.ts:331, 5000 ms) does not cancel the underlying SDK request, which may keep retrying in the background. The Rust equivalent can and should pass RequestOptions::with_timeout(5s) to actually cancel.
- TS isRateLimitError (runtime.ts:68-74) also matches on message substrings ('rate limit', '429'); Rust errors carry no messages, so only status-based detection can be ported.
- Response re-serialisation order: Rust emits known fields in schema order and then extension keys alphabetically, with nested unknown objects sorted. TS keeps passthrough extras and nested objects in server order. JSON output from the two would differ byte-wise whenever the server sends unknown fields.
- The TS CLI runtime scan writes the first 80 characters of the prompt to stderr as a status line (runtime.ts:1063). This is relevant to the 'secret-safe' goal if prompts contain sensitive data.


## Open questions
- Should airs-cli-rs reproduce the TS fail-open display (failed/unknown action shown as ALLOW, runtime.ts:225) or fail closed, e.g. show FAILED and exit 1? The Rust SDK contract says never map unfamiliar outcomes to allow.
- What JSON shape should `airs-cli-rs runtime scan --output json` emit, given TS has no JSON output? Options: the raw ScanResponse (SDK re-serialisation, schema order plus alphabetical extensions), the normalized RuntimeScanResult {prompt, response, scanId, reportId, action, category, triggered, detections, error?}, or both.
- Should response_detected flags contribute to detections/triggered when --response is supplied (deviating from TS), or should strict parity be kept?
- How should airsNumRetries be treated for sync scans, given the Rust SDK forbids POST replay? Options: accept and document the divergence, warn when it is nonzero, or implement CLI-level retries only for definitely-rejected responses such as HTTP 429.
- Should airs-cli-rs honour PANW_AI_SEC_TIMEOUT_MS (TS SDK diagnostic env var) or a tenant/flag-based scan timeout? Note the semantics differ: TS is per attempt, Rust is total.
- Which exit code should airs-cli-rs use for user cancellation (SIGINT): 130, 1, or the default signal death? TS runtime scan installs no handler.
- Should local pre-dispatch validation failures (empty prompt, profile name over 100 characters, prompt over 2 MiB) exit 1 (TS parity: they surface via fail()) or 2 (usage error)?
- Should the Rust CLI raise Limits.max_request_bytes and the validation limits to allow 100 MiB context and large responses, or keep the 8 MiB defaults and document them?
- Should the TS token-only env leak (PANW_AI_SEC_API_KEY picked up when the tenant has only airsApiToken) be fixed in airs-cli, or only neutralised in the harness by unsetting PANW_* for TS runs?
- Which user-visible stderr message format should airs-cli-rs use for HTTP failures, given it cannot echo server text? Candidates: 'Error: scan request rejected (HTTP 401)' plus the allowlisted problem title and service code, keeping the 'HTTP <status>' second line for grep parity with TS fail().
- For live comparisons, should tr_id/session_id/metadata ever be set? If so, byte-level body and hash parity will not hold and only semantic comparison applies.
- Should airs-cli-rs build its scanner via scm::configuration::init (trimming, 2048 cap, endpoint normalisation built in) or via Client::builder + Authentication::scan with CLI-side trimming? Both read no environment variables.
