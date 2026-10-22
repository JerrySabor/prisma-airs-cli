# Rust SDK foundation for `airs-cli-rs` (scm-sdk 0.1.0, frozen against @cdot65/prisma-airs-sdk 0.34.0)

All paths below are relative to `/Users/cdot/development/redtail/scm-sdk-rs/crates/scm-sdk/` unless noted. The crate is imported as `scm` through the README's alias: `scm = { package = "scm-sdk", path = "../scm-sdk-rs/crates/scm-sdk" }` (README.md "Start here"). Every claim cites code. Where the docs and the code disagree, the code wins and the gap is noted.

---

## 1. Build and dependency requirements

- **Edition / MSRV**: edition 2024, `rust-version = "1.89"` (workspace `Cargo.toml`). The CLI must build with rustc >= 1.89. The SDK uses let-chains.
- **Features** (`Cargo.toml` `[features]`): the default is `["reqwest-transport", "scan"]`. `management = ["models", "dlp"]`. For M1-M3 the CLI needs `features = ["management"]` plus the defaults. `tracing` is optional and metadata-only (OBSERVABILITY.md).
- **tokio**: the SDK enables `sync, time, macros, rt, fs, io-util` only. It does **not** enable `rt-multi-thread` or `signal`. Library code never calls `tokio::spawn`; spawns appear only in tests (grep of `src/`). A **`current_thread` runtime is sufficient**, and every SDK example uses `#[tokio::main(flavor = "current_thread")]` (examples/management.rs:2, scan.rs:2, pagination.rs:7). The CLI must add `signal` for Ctrl-C handling. If it builds the runtime by hand, it must call `.enable_all()`, because `RequestOptions::run` uses `tokio::time::sleep_until` (config.rs:416-425) and reqwest needs the IO driver.
- **HTTP stack**: `reqwest 0.13.5` with `default-features = false, features = ["rustls","http2","stream","gzip","system-proxy"]`. Locked crypto is `aws-lc-rs`/`aws-lc-sys 0.46`, which requires a C toolchain on macOS, plus `rustls-platform-verifier` (Cargo.lock).
- **Non-exhaustive structs**: `Limits`, `InitOptions`, `OAuthProviderOptions`, `PaginationOptions`, `ProfileListAllOptions`, `TopicListOptions`, `TopicListAllOptions`, `CollectOptions`, `SyncScanOptions` and `ResolveOAuthConfigOptions` are all `#[non_exhaustive]`. Outside the crate you cannot use struct literals or `..Default::default()`. Write `let mut x = T::default(); x.field = ...;` instead, as the SDK's own tests do (tests/representative_clients.rs:256-259, 431-433).
- **Non-exhaustive enums**: `ErrorKind`, `RemoteOutcome`, `FailureKind`, `ErrorType`, `Completion`, `Truncation`, `RefreshBuffer`, `DestinationPurpose` and `Authentication` are non-exhaustive, so every match needs a wildcard arm.
- **Platform**: PLATFORMS.md lists `aarch64-apple-darwin` as **compile-only**, with reqwest, rustls, AWS-LC and proxies excluded from cross checks. Native Apple Silicon runtime behaviour of the default transport is therefore unqualified by the SDK. The CLI project must qualify it itself.

## 2. Public API map

- Root re-exports (lib.rs:45-53): `scm::{Endpoint, Limits, OriginPolicy, RequestOptions, Session, Client, ClientBuilder, RawRequest, Error, ErrorKind, ErrorMetadata, ErrorType, FailureKind, ProblemDetails, ProblemFieldError, RemoteOutcome, Result, Secret}`.
- `scm::config::{DestinationPolicy, DestinationPurpose}` (config.rs:207-221).
- `scm::auth::{AuthContext, OAuthProvider, OAuthProviderOptions, RefreshBuffer, Authentication, TokenProvider, TokenLease, TokenInfo}` (auth.rs).
- `scm::transport::{Transport, TransportRequest, TransportResponse, ReqwestTransport, BodyStream}` (transport.rs).
- `scm::pagination::{Page, Pages, Items, Resume, CollectOptions, CursorLimits, Completion, Truncation, Collection, CollectionResult, CollectionError}` (pagination.rs).
- `scm::configuration::{InitOptions, ScanConfiguration, init, init_from_environment}` and `scm::environment::{EnvironmentSnapshot, SCAN_ENVIRONMENT_NAMES, ResolveOAuthConfigOptions, OAuthServiceConfig, resolve_oauth_config}`.
- `scm::airs::management::{ManagementClient, ProfilesClient, TopicsClient, PaginationOptions, ProfileListAllOptions, TopicListOptions, TopicListAllOptions}` (airs/management/mod.rs:35-38) and `scm::airs::scan::{Scanner, Region, SyncScanOptions, Content, ContentBuilder, models::*}`.

## 3. Endpoints and destination admission

### `Endpoint`

`pub fn parse(value: &str) -> Result<Endpoint>` and `pub fn loopback(value: &str) -> Result<Endpoint>` (config.rs:21-27). Validation in `parse_inner` (28-42) and `valid_url` (177-197):

- The URL must be at most 16 KiB and must parse.
- It must have a host and no userinfo or fragment, and **no query string** (`url.query().is_some()` rejects; line 33).
- `https` is accepted for **any** host, by both constructors.
- `http` is accepted **only** through `loopback`, and only when the host is the domain `localhost`, an IPv4 address with `is_loopback()` (all of 127.0.0.0/8), or `::1`.
- `http://0.0.0.0`, `http://localhost.` and any non-loopback http host give `ErrorKind::Configuration`.
- `Endpoint::parse("http://127.0.0.1:PORT")` fails with `Configuration`.

Because `loopback` still accepts https everywhere, **the CLI can pass every configured URL through `Endpoint::loopback`**. That gives "HTTPS anywhere, HTTP only on loopback" in a single code path, and is how `ScanConfiguration` handles http endpoints (configuration.rs:84-89).

**Path prefixes are preserved.** `resolve` builds `format!("{}/{}", base.path().trim_end_matches('/'), path.trim_start_matches('/'))` (config.rs:94-98), so `http://127.0.0.1:P/aisec` plus `/v1/mgmt/profiles/tsg` becomes `/aisec/v1/mgmt/profiles/tsg/<tsg>`. The management contract tests use `https://management.example/aisec` (tests/management_contracts.rs:131-135, 199-203).

`resolve` rejects the following with `Validation` before authentication (config.rs:64-92):

- paths starting with `//`, or containing `?`, `#`, `\` or `://`;
- percent-encoded `%2f`, `%5c` or `%25`;
- `.` and `..` segments;
- more than 256 query entries, or query/URL text over 16 KiB (`Limit`).

Path segments added with `RawRequest::segment` are percent-encoded once (config.rs:121-168).

### Admission

`Endpoint::admit` requires the same origin and a valid scheme (config.rs:51-57). `OriginPolicy::new(endpoints)` is an exact allowlist of origins (config.rs:225-263) and ignores paths. A custom policy implements `DestinationPolicy::check(&Url, DestinationPurpose) -> Result<()>`, with purposes `Api`, `OAuthToken`, `Download` and `Realtime`.

If you call `ClientBuilder::build()` without `destination_policy`, the default policy is `OriginPolicy` over the API endpoint plus the OAuth issuer when `oauth_credentials` is used (engine.rs:329-335). An explicit policy must admit both.

`Client::with_endpoint(Endpoint)` checks the existing policy and cannot widen it (engine.rs:438-444).

**Loopback works for both the OAuth token endpoint and the API base.** The token exchange calls `self.context.issuer.admit(&destination)` and then `policy.check(.., OAuthToken)` (auth.rs:611-614). The issuer `Endpoint` built by `loopback` carries the http opt-in. The API and token endpoint may share one fixture origin, as in the TS `dlp-tenant-auth.spec.ts:104-123` (`${base}/oauth/token`, `${base}/dlp`). No SDK admission rule rejects `/aisec` or other prefixes.

### Things that can break a loopback fixture (not SDK admission)

1. **Proxies.** The default `ReqwestTransport` keeps reqwest's system proxy (transport.rs:139-170). `hyper-util 0.1.21` `Matcher::from_system()` reads `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, in both cases. It ignores proxy variables when `REQUEST_METHOD` is set (CGI). On macOS it also reads SCDynamicStore HTTP/HTTPS proxies **without the exceptions list**. Loopback is **not** automatically bypassed. The SDK offers no "no proxy" switch: `configured(Some(proxy), ..)` replaces the system proxy and `configured(None, ..)` keeps it. Harnesses should unset proxy variables and set `NO_PROXY=127.0.0.1,localhost`. Alternatively, the CLI can supply its own `Transport` that disables proxies; that transport becomes trusted code.
2. **Use the `127.0.0.1` literal, not `localhost`.** `localhost` may resolve to `::1` first while the fixture binds only IPv4. The SDK's own tests use `127.0.0.1:0`.
3. **Redirects** are never followed. Any 3xx becomes `Destination` with outcome `Rejected` (engine.rs:1193-1197; reqwest `redirect::Policy::none()`, transport.rs:142).
4. **The connect timeout is fixed at 10 s** in `ReqwestTransport` (transport.rs:144).

## 4. OAuth (client-credentials) management client

### Identity

`AuthContext::new(issuer: Endpoint, client_id: impl Into<String>, credential_generation: u64, tsg_id: impl Into<String>) -> Result<AuthContext>` (auth.rs:101-127):

- `client_id` must be non-empty, at most 1024 bytes and free of control characters.
- `tsg_id` must be **1-32 ASCII digits**. Anything else returns `Configuration` locally, before any network call.
- The default scope is exactly `tsg_id:<tsg>` (line 118).
- `with_scopes` must include the tenant scope and rejects any conflicting `tsg_id:` scope (131-150).
- The secret comes from `Secret::new(value)` (secret.rs:15-21): non-empty and at most 16 KiB. `OAuthProvider::new_with_options` also rejects control characters (auth.rs:392).

### Route A: SDK-managed provider (simplest)

```rust
let api = Endpoint::loopback(&cfg.mgmt_endpoint)?;            // e.g. http://127.0.0.1:P/aisec
let issuer = Endpoint::loopback(&cfg.mgmt_token_endpoint)?;   // e.g. http://127.0.0.1:P/oauth/token
let ctx = scm::auth::AuthContext::new(issuer, cfg.mgmt_client_id, 1, cfg.mgmt_tsg_id)?;
let mut limits = scm::Limits::default(); limits.max_retries = 2; // 0..=5
let client = scm::Client::builder(api)
    .oauth_credentials(ctx, scm::Secret::new(cfg.mgmt_client_secret)?, /*tsg_header*/ false)
    .limits(limits)
    .session(session.clone())
    .build()?;
let mgmt = scm::airs::management::ManagementClient::new(client)?; // Configuration if not OAuth
```

`ClientBuilder` methods (engine.rs:265-376): `new/builder(Endpoint)`, `authentication(Authentication)`, `oauth_credentials(AuthContext, Secret, bool)`, `oauth_provider_options(OAuthProviderOptions)`, `transport(Arc<dyn Transport>)`, `destination_policy(Arc<dyn DestinationPolicy>)`, `limits(Limits)`, `validation_limits(..)`, `session(Session)`, `build() -> Result<Client>`.

- `authentication` and `oauth_credentials` override each other; the last call wins.
- The provider is created inside `build()` using the builder's transport, policy and session (349-360), so the order of builder calls does not matter.
- With Route A the provider is private. `Client::oauth_context()` exposes only the context.

### Route B: application-owned provider (needed for `doctor`)

```rust
let transport: Arc<dyn Transport> = Arc::new(ReqwestTransport::new()?);
let policy = Arc::new(OriginPolicy::new([api.clone(), issuer.clone()]));
let provider = Arc::new(OAuthProvider::new(ctx, secret, transport.clone(), policy.clone(), session.clone())?);
let lease = provider.get_token(None).await?;   // isolated OAuth check, default 30 s budget
let client = Client::builder(api).transport(transport).destination_policy(policy)
    .authentication(Authentication::oauth(provider.clone(), false)).session(session.clone()).build()?;
```

`OAuthProvider` (auth.rs:362-546) provides `new`, `new_with_options`, `get_token(Option<&RequestOptions>) -> Result<TokenLease>`, `clear()`, `is_token_expired()`, `is_token_expiring_soon(Option<Duration>)`, `token_info() -> Result<TokenInfo>` and `subscribe_refresh()`. `TokenLease::secret().expose()` is the only way to get the token string. `TokenInfo` contains no token or identity (291-301). `OAuthServiceConfig::provider(..)` and `client_builder(tsg_header)` (environment.rs:192-217) are the equivalents for env-resolved configuration. Do **not** use `resolve_oauth_config` with a captured environment if credential environment variables must be ignored.

### Token exchange on the wire (auth.rs:603-681)

- `POST <issuer URL exactly>`. Note that `http://127.0.0.1:P` without a path posts to `/`.
- Headers set by the SDK:
  - `authorization: Basic base64(form_urlencode(client_id) + ":" + form_urlencode(secret))`, which is RFC 6749 encoding (624-632; test auth.rs:1131-1139 decodes to `client%3A+%26%2B:sec%2F+%2B%3A`);
  - `content-type: application/x-www-form-urlencoded`.
- Headers added by reqwest: `user-agent: PAN-AIRS/0.1.0-rust-sdk` (reqwest client default, transport.rs:154) and `accept: */*`.
- No `service-name` header: the token exchange bypasses `RawRequest` defaults.
- Body: `grant_type=client_credentials&scope=tsg_id%3A<tsg>`, plus `&audience=...` if one is set.
- The response must be at most 64 KiB of JSON `{"access_token": string, "token_type": string, "expires_in": u64}`:
  - `token_type` must equal `bearer` case-insensitively (667);
  - `access_token` must match the RFC 6750 b64token set `[A-Za-z0-9-._~+/]+=*` and be at most 16 KiB (851-864);
  - `expires_in` must be an integer from 1 s to 31 days (238-244). A string or float fails with `Decode`.
- One refresh is single-attempt, has a fixed 30 s budget (37, 608) and **is never retried**.
- Refreshes are deduplicated and cached per provider. The default early-refresh buffer is `Adaptive(30s)`, i.e. `min(30s, TTL/5)` (43-61).
- A non-2xx response gives `ErrorKind::Authentication` with `status = issuer status` (657-661). Token text is never retained.

### API request headers (OAuth)

After `prepare` (auth.rs:777-800): `authorization: Bearer <token>`, plus `x-tsg-id: <tsg>` **only if** `tsg_header` is true. The SDK defaults `user-agent: PAN-AIRS/0.1.0-rust-sdk` and `service-name: api` are always added (engine.rs:22-32). Caller code cannot set `authorization`, `x-pan-token`, `x-payload-hash`, `x-portkey-api-key`, `x-tsg-id`, `service-name`, `user-agent`, `host`, `content-type` and similar headers (engine.rs:156-175; auth.rs:735-745).

The baseline management contract builds with `Authentication::oauth(token, false)`, so **profiles and topics requests carry no `x-tsg-id`** (tests/management_contracts.rs:150-155, 199-203). `ManagementClient::new` separately derives a `with_tsg_header(true)` client for dashboard calls (airs/management/mod.rs:62-69). The tenant is also in the path: `tenant()` reads `oauth_context().tsg_id()` (mod.rs:137-142).

## 5. Scanner client (API key or bearer)

`Authentication::scan(api_key: Option<Secret>, api_token: Option<Secret>) -> Result<Authentication>` (auth.rs:703-711). At least one must be present. Each value must be non-empty, at most 16 KiB and **all ASCII-graphic**, so spaces and control characters give `Configuration` (841-850).

On the wire (748-776):

- with a token: `authorization: Bearer <token>`;
- with a key: `x-pan-token: <key>`, and if the request has a body, `x-payload-hash: lowercase-hex(HMAC-SHA256(key, exact body bytes))`;
- if both are supplied, both header sets are sent (tests/configuration_contracts.rs:238-245).

```rust
let client = Client::builder(Endpoint::loopback(&cfg.scan_endpoint)?)
    .authentication(Authentication::scan(Some(Secret::new(cfg.airs_api_key)?), None)?)
    .session(session.clone()).build()?;
let scanner = scm::airs::scan::Scanner::new(client)?;   // Configuration unless Scan auth
```

The alternative is `configuration::init(InitOptions)`, then `.client_builder()?`, then `.session(..).build()`. That path trims ECMAScript whitespace, enforces 2048 UTF-16 units, strips trailing `/` from the endpoint, and sets `max_retries = num_retries` (default **5**) (configuration.rs:26-37, 67-121). `Scanner::for_region` uses the HTTPS regional bases only (airs/scan/scanner.rs:96-107).

`sync_scan(&AiProfile, &Content, Option<&SyncScanOptions>)` sends `POST /v1/scan/sync/request` with body fields `ai_profile`, `contents:[one]` and optional `tr_id`, `session_id` and `metadata` (scanner.rs:115-151).

- The body is validated, parsed into `serde_json::Value` and **re-serialized** (engine.rs:524-544). serde_json has no `preserve_order` (Cargo.lock), so object keys are **sorted**. The HMAC covers exactly the bytes sent.
- `Content::builder().prompt(..).response(..).build()` fails with `Validation`, before authentication, if all primary fields are empty, or if prompt/response exceed 2 MiB or context exceeds 100 MiB (content.rs:6-7, 196-215).
- Scan POSTs are created with `RawRequest::new` and are **never replayed**, even with `RequestOptions::with_retries`.

## 6. Sessions, cancellation and Ctrl-C

`Session` (config.rs:341-357) wraps a `CancellationToken` that all client clones share. It has `new`, `cancel`, `is_cancelled` and `async cancelled`.

- `RequestOptions::run` races the operation against request cancellation, session cancellation and the deadline (405-426). Results are `Error::new(Cancelled)` or `Error::new(Deadline)`.
- A cancelled session interrupts pending OAuth refreshes too (auth.rs:483-485, 554) and **blocks all future requests** on that session.
- Dropping a response or future releases the connection and permit. The test `cancellation_closes_an_incomplete_default_http_response` (engine/tests.rs:2104-2147) shows the server sees EOF.

Recommended Ctrl-C pattern:

```rust
let s = session.clone();
tokio::spawn(async move { if tokio::signal::ctrl_c().await.is_ok() { s.cancel(); } });
```

The in-flight call then returns `ErrorKind::Cancelled`, with remote outcome `NotSent` if cancelled before dispatch and `Unknown` after it. For a scan, `Unknown` means the scan may have been processed and billed (FOUNDATION.md "Budgets and cancellation").

## 7. RequestOptions, Limits and retries

`RequestOptions::with_timeout(Duration) -> Result<RequestOptions>` (config.rs:367-379):

- The timeout must be greater than 0 and at most 86 400 s.
- It sets **one absolute deadline at construction time**, covering queueing, authentication, all attempts, backoff sleeps and body reads.
- `with_retries(u32 <= 5)` overrides the safe-read replay count only (385-391).
- `cancel()` and `cancellation_token()` are also available.
- Without options, each call gets `Limits.operation_timeout`, default 60 s (engine.rs:470-478, 1122-1130).
- Pagination walks share one options snapshot, so `list_all` gets 60 s **in total** unless you pass a longer `RequestOptions`.

`Limits` defaults (config.rs:285-301):

| Field | Default |
| --- | --- |
| `operation_timeout` | 60 s |
| `max_request_bytes` | 8 MiB |
| `max_response_bytes` | 8 MiB |
| `max_error_bytes` | 64 KiB |
| `max_concurrency` | 32 |
| `max_retries` | **2** |
| `retry_base_delay` | 250 ms |
| `max_retry_delay` | 5 s |

`validate` rejects zero durations and `max_retries > 5` (304-336). `ScanConfiguration` and `OAuthServiceConfig` builders set `max_retries` to 5 by default.

Retry rules, from `send_buffered_observed` (engine.rs:1116-1265):

- Only requests declared as reads (`RawRequest::read`, i.e. `replay_safe`) retry.
- A read retries on a transport error (1172-1186) or on HTTP **429/502/503/504** (`retryable`, 1372-1374). **500 is not retried** (test engine/tests.rs:1420-1444).
- Backoff is `250ms * 2^n`, capped at 5 s (1337-1343).
- `Retry-After` uses integer seconds or an HTTP date (1375-1393). It is honoured only if it is at most `max_retry_delay`. Otherwise the error returns immediately with `retry_after()` set (test 1384-1418).
- On a safe read, OAuth 401, or 403 without `x-opa-decision: false`, invalidates the token generation and allows **one** replay if `max_retries >= 1`. That replay consumes a retry (1216-1225, 1345-1349). With `max_retries = 0` there is no replay (tests 1446-1468).
- POST, PUT and DELETE never replay (test 1334-1382). The `x-pan-token` scan path never replays.
- Management reads (`profiles.list`, `topics.list`, `pages`, `list_all`, `get`) all use `RawRequest::read` (profiles.rs:73,102; topics.rs:56,87), so they retry.

## 8. Error model

`scm::Error` (error.rs:44-251) exposes:

- `kind() -> ErrorKind`;
- `status() -> Option<u16>`;
- `operation() -> Option<&'static str>`;
- `request_id()`, taken from the `x-request-id`, `x-correlation-id` or `request-id` header when it matches `[A-Za-z0-9-_.:]{1,128}` (engine.rs:1402-1434);
- `service_code()`, taken from body `code`, `error.code`, `data.errorCode` or `errorCode`;
- `retry_after() -> Option<Duration>`, from the header or else from body `retry_after{interval,unit}` (problem.rs:271-289);
- `remote_outcome() -> RemoteOutcome`;
- `failure_kind() -> Option<FailureKind>` (`Http` or `Network`);
- `problem() -> Option<&ProblemDetails>`, an allowlisted `title`/`detail`/`errors` with everything else turned into `"[withheld]"` (problem.rs:8-33, 126-212);
- `error_type()`, the AIRS taxonomy: `Configuration`→`AISEC_MISSING_VARIABLE`, `Authentication`→`AISEC_OAUTH_ERROR`, Http 5xx→`AISEC_SERVER_SIDE_ERROR`, Http 4xx/`Transport`/`Io`→`AISEC_CLIENT_SIDE_ERROR`, `Decode`→`AISEC_RESPONSE_VALIDATION`, `Deadline`/`Cancelled`/`Pagination`→`AISEC_SDK_ERROR` (error.rs:110-146);
- `name()` = `"ScmSdkError"`.

**`ErrorKind` variants** (error.rs:16-30): `Configuration, Validation, Destination, Authentication, Io, Transport, Http, Decode, Limit, Deadline, Cancelled, Protocol, Pagination`.

**Formatting.** `Display` is exactly `SCM SDK {kind:?}`, followed by ` (HTTP {status})` when a status is present (error.rs:268-276), e.g. `SCM SDK Http (HTTP 404)` or `SCM SDK Authentication (HTTP 401)`. `Debug` prints `Error { kind, status, operation, remote_outcome, retry_after, has_request_id, has_service_code, failure_kind, has_problem }` (253-267). Neither format includes a body, URL, query, credential, request ID or upstream message.

`Secret` formats as `Secret([REDACTED])` with Debug and `[REDACTED]` with Display (secret.rs:29-38). `AuthContext`, `OAuthProvider`, `Authentication`, `TokenLease`, `TransportRequest`, `EnvironmentSnapshot`, `InitOptions` and `Collection` all redact. **The token, client secret or API key never appear in SDK formatting.** Server error text is never available, so the CLI must write its own messages.

**Remote outcome.**

- `Error::new` defaults to `NotSent` (65-76).
- After transport dispatch, the `sent` flag converts `NotSent` to `Unknown` (engine.rs:1249-1264).
- HTTP 4xx gives `Rejected`; 5xx gives `Unknown` (1237-1246).
- A redirect gives `Rejected`.
- Decode or body-limit failures after a 2xx give `Unknown` and keep the status (annotate, 207-214).
- A transport error such as connection refused **after dispatch** gives `Unknown` with failure kind `Network`.
- Validation, destination and configuration errors before authentication give `NotSent`.

**Telling OAuth failures from API failures** when going through a `Client`:

- Token endpoint non-2xx → `ErrorKind::Authentication` with the issuer's status and outcome `NotSent`.
- Token endpoint unreachable → `Transport` with status `None`, `NotSent` and no failure kind.
- Malformed token JSON → `Decode` with status `None`.
- API 401 → `ErrorKind::Http` with status 401 and `Rejected`.
- In every case `operation()` is overwritten with the API operation name, e.g. `airs.management.profiles.list` (engine.rs:1263). Use `kind()`, not the operation. A direct `provider.get_token` keeps `operation() == Some("oauth.token")` (auth.rs:680).

**Pagination failures** return `CollectionError` with `error()`, `partial()` (accepted rows, `Completion::Interrupted` and resume position) and `into_parts()`. Its Display delegates to the SDK error (pagination.rs:162-211).

## 9. Pagination

- `Pages::new(initial: C, RequestOptions, Session, max_pages: usize (1..=100000), fetch: FnMut(C, RequestOptions) -> Fut)` (pagination.rs:246-297) has `next_page() -> Result<Option<Page<T,C>>>`, `items() -> Items`, `collect(CollectOptions) -> CollectionResult` and `resume()`.
- `next_page` fails with `ErrorKind::Pagination` on a repeated cursor or `max_pages` (346-350), and on an empty page that still has a next cursor (390-394).
- `Items` has `next()`, `resume_from(Resume)` (before any fetch; 433-441), `resume()` and `collect`.
- `CollectOptions` defaults to `max_items` 10 000, `max_bytes` 64 MiB and `max_pages` 1000, with ceilings of 1 000 000, 512 MiB and 100 000; zero is invalid (47-91). Use `with_max_items`, `with_max_bytes` and `with_max_pages`.
- `Collection { items, completion: Completion::{Complete | Truncated(Items|Bytes|Pages) | Interrupted}, resume: Option<Resume{cursor,item_offset}>, pages_read, wire_bytes }`, with `is_complete()` (130-147).
- Reaching a limit exactly at the end of the final page still counts as complete (523-531).

**Management dialect.**

- `ProfilesClient::list(PaginationOptions{offset,limit,latest}, opts)` sends `GET {base}/v1/mgmt/profiles/tsg/{tsg}?offset=O&limit=L[&latest=true|false]`. The default is `offset=0&limit=100` (profiles.rs:16-41, 97-109).
- `limit == 0` or `offset > 2^53-1` gives `Validation` with `NotSent` before any token request (tests/representative_clients.rs:271-292).
- `pages`, `list_all(ProfileListAllOptions{limit:100, latest, collect})` follow `next_offset` until it is absent or 0. A non-integer or negative value gives `Decode` (mod.rs:167-178).
- `get(id)` walks the whole inventory. If the walk is truncated it returns `Limit`; if the id is not found it returns `**Validation**` with outcome `NotSent` (profiles.rs:154-168).
- `get_by_name` chooses the highest `revision`, with the first one winning a tie.
- `TopicsClient::list(TopicListOptions{offset,limit,latest_only:false})` sends `GET /v1/mgmt/topics/tsg/{tsg}?offset&limit` and never sends `latest`. `latest_only=true` walks all pages at `limit=200`, keeps the highest revision per name in first-seen order, then slices locally and synthesizes `next_offset`. It returns `Limit` if the walk is incomplete (topics.rs:97-152).
- Absent arrays serialize as `[]`: `{"future_page":true}` becomes `{"ai_profiles":[],"future_page":true}` (tests/representative_clients.rs:253-269).
- Unknown fields are preserved through `#[serde(flatten)] extensions`. `SecurityProfile` requires `profile_name` (models/generated.rs:166008-166031), so fixtures missing it produce `Decode`.

## 10. How the SDK's own tests use loopback

- `engine/tests.rs:1875-2147` (`mod default_adapter`): `TcpListener::bind("127.0.0.1:0")` and `Endpoint::loopback(&format!("http://{}", addr))`. A minimal HTTP/1.1 parser captures the headers and `Content-Length` body and replies with canned bytes such as `HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok`. The tests assert exact HMAC bytes, redirects never following, gzip limits, a failed POST not being replayed, and cancellation closing the socket.
- `streaming/sse/tests.rs:836` and `tests/native_realtime.rs` use the same technique.
- `tests/configuration_contracts.rs:163-168` checks `Endpoint::loopback("http://127.0.0.1:8321/scan///")` normalizes to `http://127.0.0.1:8321/scan` through `init`.
- Most contract tests inject a fake `Transport` and match on `request.url().host_str()` to answer token or API requests (configuration_contracts.rs:22-55). No SDK test runs OAuth plus management against a real loopback socket; that combination is new territory for the CLI harness.

## 11. Implications for the dual-CLI harness

- Compare request bodies as parsed JSON, not bytes. Verify `x-pan-token` and `x-payload-hash` by recomputing HMAC over the bytes actually received.
- Don't compare `user-agent` exactly: Rust sends `PAN-AIRS/0.1.0-rust-sdk` and TS sends `PAN-AIRS/0.34.0-typescript-sdk` (contracts/native-operations.json `requestHeaderContracts.airs_api_defaults`).
- Basic credentials differ for reserved characters. Use alphanumeric and hyphen secrets in fixtures, as the TS fixture does (`FAKE-SECRET-100`), or form-decode both halves on the server.
- Retry counts differ. Rust reads make `1 + max_retries` attempts on 502/503/504/429, one attempt on 500, and one attempt on every POST. The TS SDK retries 500/502/503/504 (constants.rs:646) and, per its tests, gives a "free" 401 retry even with `numRetries: 0` (contracts/fixtures/typescript/test/http/request.spec.ts:574-598).
- A Rust API 401 with retries enabled produces 2 token POSTs and 2 GETs.
- stderr cannot match the TS CLI byte for byte when an error message comes from the server (TS includes server text: request.spec.ts:518). Compare exit codes and normalized stderr classes instead, and always assert that secrets are absent.
- The SDK writes nothing to stdout or stderr: there is no `println`/`eprintln` outside tests. All console output belongs to the CLI.
- The SDK reads no environment variables except `EnvironmentSnapshot::capture` (environment.rs:79-107). reqwest still reads proxy variables.


## Acceptance criteria
- When a tenant config points both mgmtEndpoint and mgmtTokenEndpoint at http://127.0.0.1:PORT (with paths such as /aisec and /oauth/token), `airs-cli-rs runtime profiles list` reaches the fixture server and exits 0. Every configured URL must go through Endpoint::loopback.
- When a tenant config uses a non-loopback http:// endpoint (for example http://example.test), or an endpoint with a query string or userinfo, the CLI exits non-zero, the fixture server receives zero requests (token included), and stderr contains no secret.
- When mgmtTsgId is not 1-32 ASCII digits (for example 'abc' or ' 123 '), the CLI fails locally with zero token or API requests.
- The token request is POST to the exact token endpoint path, with content-type application/x-www-form-urlencoded and form body grant_type=client_credentials&scope=tsg_id%3A<tsg> (decoding to scope 'tsg_id:<tsg>'). Authorization is 'Basic ' + base64(form-urlencoded client_id ':' form-urlencoded secret), and there is no service-name header.
- A token response missing token_type, with token_type other than bearer, with expires_in as a string, zero or float, or with access_token outside [A-Za-z0-9-._~+/]+=* makes the CLI exit 1 with no API request sent.
- When the token endpoint returns 401, the CLI exits 1, sends exactly 1 token request and 0 API requests (the token fetch is not retried), and stdout is empty.
- One CLI invocation that makes several management GETs (for example list --all across 3 pages) issues exactly 1 token request (cached lease).
- Every management GET carries 'authorization: Bearer <fixture token>', 'service-name: api' and a user-agent matching ^PAN-AIRS/.*-rust-sdk$. It carries no x-pan-token or x-payload-hash, and no x-tsg-id on profiles/topics calls when built with tsg_header=false (baseline).
- `runtime profiles list` with no paging flags sends GET <prefix>/v1/mgmt/profiles/tsg/<tsg>?offset=0&limit=100. With --offset 10 --limit 20 the query is exactly offset=10&limit=20, in that order.
- Topics list sends GET <prefix>/v1/mgmt/topics/tsg/<tsg>?offset=0&limit=100 and never includes a 'latest' query key.
- List-all follows next_offset across pages (offset=0, then offset=<next_offset>) and stops when next_offset is absent or 0. The stdout JSON array contains every row, in server order.
- When a fixture returns the same next_offset twice, or a non-final empty page, the CLI exits 1 with a pagination error on stderr and never re-requests the repeated cursor.
- A limit of 0 (for example --limit 0) is rejected with zero network requests, the token request included.
- With the item/page traversal limit set below the inventory size, the CLI reports truncation (incomplete) instead of claiming a complete listing. `get` by id or name over a truncated inventory fails rather than reporting not-found.
- `runtime profiles get <id>` for an id absent from a complete inventory exits 1 with a not-found message. The SDK returns ErrorKind::Validation here, so the CLI must map it.
- A management GET answered with 503 is retried with backoff (total attempts = 1 + configured max_retries). A GET answered with 500 is not retried (exactly 1 attempt).
- A GET answered with 429 and Retry-After: 20 is not retried and exits 1 immediately. The CLI can report the retry-after value.
- An API GET answered with 401 once and then 200 leads to a second token request and one replayed GET when max_retries >= 1, and the CLI exits 0.
- `runtime scan` sends exactly one POST <scan base>/v1/scan/sync/request with content-type application/json and x-pan-token: <key>. x-payload-hash must equal lowercase hex HMAC-SHA256(key, received body bytes), and the body must parse to {ai_profile:{profile_name|profile_id}, contents:[{prompt[,response]}]}.
- A scan POST answered with 503, or a connection reset after the request was sent, produces exactly 1 POST (no replay), exit 1, and stderr stating that the scan outcome is unknown/uncertain.
- A scan with empty prompt and response is rejected locally with zero requests.
- Sending SIGINT while a fixture holds a scan or list response open makes the process exit promptly (well before the fixture's delay). The fixture observes the connection closing (EOF), and no secret appears in the output.
- A fixture response that echoes the client secret, API key or bearer token in its error body, headers or title (with any status) never causes those values to appear on stdout or stderr.
- Credential environment variables (PANW_MGMT_CLIENT_ID, PANW_MGMT_CLIENT_SECRET, PANW_MGMT_TSG_ID, PANW_AI_SEC_API_KEY, PANW_AI_SEC_API_TOKEN, PANW_AI_SEC_API_ENDPOINT) set to bogus values do not change any request sent to the fixture.
- A 3xx response with a Location pointing at a second loopback listener is not followed. The second listener receives no connection and the CLI exits 1.
- With HTTP_PROXY/HTTPS_PROXY/ALL_PROXY unset and NO_PROXY=127.0.0.1,localhost, all fixture traffic reaches the loopback server directly. The harness should enforce this environment for both CLIs.
- The management client never sends the scan API key, and the scanner never sends the OAuth bearer token (separate credential planes): ManagementClient::new rejects a scan-auth Client and Scanner::new rejects an OAuth Client.


## Discrepancies
- Retry status sets differ. Rust safe reads retry only 429/502/503/504 (engine.rs:1372-1374; test engine/tests.rs:1420-1444 asserts 500 is not retried). The SDK nonetheless exports HTTP_FORCE_RETRY_STATUS_CODES=[500,502,503,504] (constants.rs:646), and the frozen TS SDK retries 5xx including on POST scans. The two CLIs will issue different request counts against 500 and 5xx scan fixtures.
- 401 refresh semantics differ. TS gives a 'free' extra attempt after 401 even with numRetries 0 (contracts/fixtures/typescript/test/http/request.spec.ts:574-598). Rust counts the refresh replay against max_retries and disables it at 0 (engine.rs:1216-1225; FOUNDATION.md; test engine/tests.rs:1446-1468).
- Default retry counts are inconsistent across SDK construction paths. Limits::default().max_retries = 2 (config.rs:293), but ScanConfiguration::client_builder and OAuthServiceConfig::client_builder set 5 (configuration.rs:90,111-114; environment.rs:209-212). Depending on how the CLI builds clients, read retry counts silently change between 3 and 6 attempts.
- CONFIGURATION.md says scan initialization's 'Retry count ... default five', but sync_scan uses RawRequest::new (not replay-safe) and is never retried (scanner.rs:143). The setting only affects read operations such as query_by_scan_ids.
- FOUNDATION.md says 'Before dispatch, failures report NotSent'. In practice the sent flag is set just before transport.send (engine.rs:1164), so a TCP connection-refused on a scan POST reports RemoteOutcome::Unknown and FailureKind::Network. The SDK cannot tell 'never connected' from 'request lost'.
- The operation label is lost for OAuth failures. auth.rs:680 tags token errors with operation 'oauth.token', but send_buffered's map_err overwrites it with the API operation name (engine.rs:1263). Through a Client, a token-endpoint 401 looks like Authentication + status 401 + operation 'airs.management.profiles.list'.
- The OAuth token exchange bypasses RawRequest defaults: it sends no service-name header, and user-agent is added only by reqwest's client default (auth.rs:633-650; transport.rs:154). Yet contracts/native-operations.json labels OAuthClient.getToken with headerContract 'airs_api_defaults'. A custom Transport would send no user-agent at all on token requests.
- Error text is never retained. TS errors include server message text (request.spec.ts:518 expects message to contain 'not found'), while Rust Display is only 'SCM SDK <Kind> (HTTP n)' (error.rs:268-276), and ProblemDetails withholds non-allowlisted text as '[withheld]' (problem.rs:7-33,205-213). stderr parity with the TS CLI is impossible for server-provided messages.
- ProfilesClient::get / TopicsClient::get report not-found as ErrorKind::Validation with RemoteOutcome::NotSent, even after successful network traffic (profiles.rs:164-167; topics.rs:205-208). error_type() then maps this to AISEC_USER_REQUEST_PAYLOAD_ERROR, which is misleading for a lookup miss.
- error_type() maps every Configuration error, including invalid values such as a non-digit TSG, to AISEC_MISSING_VARIABLE (error.rs:117). Deadline and Cancelled map to AISEC_SDK_ERROR (error.rs:144).
- TSG IDs must be 1-32 ASCII digits in Rust (auth.rs:109-117) but are arbitrary strings in TS (FOUNDATION.md 'Deliberate TypeScript differences'). Wrong-tenant fixtures using non-numeric TSGs behave differently: Rust fails locally, TS sends to the token endpoint.
- OAuth Basic credentials are form-encoded before base64 in Rust (auth.rs:624-632) but raw in TS. Secrets containing reserved characters (/, +, :, %, ~, space) produce different Authorization bytes, and a fixture that compares the raw decoded Basic value (dlp-tenant-auth.spec.ts:47-55 does) would reject Rust.
- The token response contract is strict in Rust: token_type is required and must be bearer, expires_in must be a JSON integer from 1 to 31 days, and access_token must be b64token at most 16 KiB (auth.rs:588-593, 236-244, 667-669, 851-864). TS may accept looser responses (unverified, since the TS source is not in this checkout).
- PLATFORMS.md lists aarch64-apple-darwin as compile-only, with reqwest, rustls, AWS-LC and proxies excluded from cross checks. The first-release target (native Apple Silicon executable) is therefore not runtime-qualified by the SDK.
- FOUNDATION.md says 'System proxy settings are supported by the default adapter'. The SDK gives no way to disable them, though: ReqwestTransport::configured(None, ..) keeps them (transport.rs:140-170). hyper-util 0.1.21 does not bypass loopback automatically and does not read the macOS proxy exceptions list, so a configured system or env proxy can capture http://127.0.0.1 fixture traffic.
- The foundation example uses https://api.sase.paloaltonetworks.com/aisec (examples/foundation.rs:9), but DEFAULT_MGMT_ENDPOINT and the management example use https://api.apps.paloaltonetworks.com/aisec (constants.rs:629; examples/management.rs:18). The docs are inconsistent about the management base.
- x-tsg-id is inconsistent across SDK tests. Baseline management contracts build with Authentication::oauth(..., false), so profiles and topics requests omit x-tsg-id (tests/management_contracts.rs:199-203). The representative test uses true and asserts that x-tsg-id is present (tests/representative_clients.rs:203-244). The CLI must choose false to match the TS wire shape.
- JSON key ordering differs. serde_json is built without preserve_order (Cargo.lock), and request bodies are re-serialized from serde_json::Value (engine.rs:524-544), so wire keys are sorted. Enabling serde_json/preserve_order in the CLI would change SDK wire bytes through feature unification. Rust output JSON key order will not match TS JSON.stringify order.
- Absent list arrays serialize as [] (tests/representative_clients.rs:253-269), so `{"future_page":true}` is printed as `{"ai_profiles":[],"future_page":true}`. TS output for the same fixture may differ unless its zod schema also defaults the field.
- Live acceptance is uneven (contracts/native-operations.json). ProfilesClient.list, listForToken, Scanner.syncScan/queryByScanIds and OAuthProvider::get_token are 'verified'. TopicsClient.list/get/listAll/getByName and ProfilesClient.get/getByName/listAll are 'unverified'.
- The full-traversal deadline is implicit. pages, list_all and get share one RequestOptions created at call time with a 60 s default (engine.rs:470-478; profiles.rs:117-118). A long --all traversal can fail with Deadline unless the CLI passes a longer RequestOptions. The TS collectAll has no such total budget (PAGINATION.md).


## Open questions
- What numRetries does the TS CLI configure for management reads and for sync scans? Rust should set Limits.max_retries explicitly to match, and the harness needs expected request counts for 5xx and 401 fixtures.
- How should SDK ErrorKinds map to the CLI's exit codes 1 and 2? In particular, should SDK Validation errors caused by user input (for example --limit 0, empty prompt, bad UUID) be exit 2 like the TS CLI's usage errors, or exit 1? What exit code does the TS CLI use for not-found and for SIGINT (130?)?
- For the doctor scanner-connectivity check, which non-billable probe does the TS CLI use? Options with this SDK are a sync scan (billable) or GET /v1/scan/results?scan_ids=<uuid> via query_by_scan_ids, which is a read and is retried.
- How should wrong-tenant rejection work? The SDK has no token introspection; the tenant appears only in the scope, the path and the optional x-tsg-id. Should the CLI compare the selected tenant's mgmtTsgId against an expected TSG argument, against response tsg_id fields, or rely on token-endpoint rejection?
- Should the Rust CLI ship a custom Transport (reqwest with .no_proxy() for loopback destinations) to avoid system and env proxy capture of fixture traffic, or should it rely on the harness setting NO_PROXY? Note that a custom Transport becomes trusted code under the SDK's security model.
- Should airs-cli-rs pin the SDK's Cargo.lock dependency versions (reqwest 0.13.5, hyper-util 0.1.21, tokio 1.53.3, aws-lc-sys 0.46.0) to stay inside the SDK's qualified set? A path dependency resolves its own lockfile in the CLI.
- Do the TS CLI's tenant JSON files contain endpoint keys beyond mgmtEndpoint, mgmtTokenEndpoint and dlpEndpoint (for example a scan endpoint key) and the airsApiKey/airsApiToken names? Their exact names and defaults must be mapped to Endpoint::loopback and Authentication::scan.
- Should `runtime profiles get` and `topics get` use the SDK's full-inventory walk (get / get_by_name, bounded by CollectOptions defaults of 10 000 items and 1000 pages) to match TS revision-selection semantics, or should the CLI perform its own walk with user-configurable traversal limits?
- Does the TS SDK accept token responses without token_type, or with string expires_in? This determines whether shared deterministic fixtures must use the strict shape `{"access_token":"...","token_type":"Bearer","expires_in":3600}`.
