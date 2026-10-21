# Spec: Rust SDK management client for security profiles and custom topics (input to `airs-cli-rs` M2)

Scope: `scm-sdk` crate (imported as `scm`) at `/Users/cdot/development/redtail/scm-sdk-rs/crates/scm-sdk`. It covers profiles and topics only, compared with the frozen TypeScript SDK 0.34.0 baseline (commit `4a80dbd…`, embedded in `scm-sdk-rs/contracts/typescript.json`) and with how the TS CLI (`prisma-airs-cli`) calls that SDK. Everything here was read from source. Nothing was built or run, and no network calls were made.

Citation prefixes: `rs:` = `scm-sdk-rs/crates/scm-sdk/`, `doc:` = `scm-sdk-rs/docs/`, `ts:` = frozen TS source text inside `scm-sdk-rs/contracts/typescript.json` (file:line as recorded there), `cli:` = `prisma-airs-cli/`.

---

## 1. Construction (exact public API)

Feature gate: the `management` Cargo feature (`rs:Cargo.toml:21`, `management = ["models", "dlp"]`). The default features are `reqwest-transport`, `scan`. The CLI must add `management`.

There is no environment or tenant-file reading anywhere in this path (`doc:MANAGEMENT.md:3`, `rs:examples/management.rs:9-10`). Credentials must be passed explicitly.

```rust
use scm_sdk::{Client, Endpoint, Secret, auth::AuthContext,
  airs::management::{ManagementClient, PaginationOptions, ProfileListAllOptions,
                     TopicListOptions, TopicListAllOptions}};
let issuer = Endpoint::parse("https://auth.apps.paloaltonetworks.com/oauth2/access_token")?; // or Endpoint::loopback("http://127.0.0.1:PORT/token")
let ctx = AuthContext::new(issuer, client_id, /*credential_generation*/ 0, tsg_id)?;
let client = Client::builder(Endpoint::parse("https://api.apps.paloaltonetworks.com/aisec")?)
    .oauth_credentials(ctx, Secret::new(client_secret)?, /*tsg_header*/ false)
    .build()?;
let mgmt = ManagementClient::new(client)?;
```

Constructor details:

- **`Endpoint::parse(&str) -> Result<Endpoint>`** accepts HTTPS only. **`Endpoint::loopback(&str)`** also admits `http://` for `localhost`, `127.0.0.0/8` or `::1` (`rs:src/config.rs:21-27,177-197`). Both reject a URL with a query, userinfo or fragment (`Configuration`). The harness's loopback server therefore needs `Endpoint::loopback` for both the API base and the token issuer. `parse` rejects `http://127.0.0.1`.
- **`AuthContext::new(issuer, client_id, credential_generation: u64, tsg_id)`** (`rs:src/auth.rs:101-127`):
  - `tsg_id` must be 1–32 ASCII digits.
  - `client_id` must be 1–1024 characters with no control characters.
  - Otherwise it returns `ErrorKind::Configuration`.
  - The scope is exactly `tsg_id:<tsg>`.
- **`Secret::new`** rejects an empty value or one over 16 KiB (`rs:src/secret.rs:15-21`).
- **`ManagementClient::new(client: Client) -> Result<Self>`** (`rs:src/airs/management/mod.rs:62-69`). It rejects non-OAuth authentication with `Configuration` before any network work. It derives a dashboard client with `x-tsg-id` forced on. Profiles and topics use the original client, so they send `x-tsg-id` only if the caller passed `tsg_header=true`.
  - **The TS SDK never sends `x-tsg-id` on profile/topic routes.** It wraps them in plain `OAuthAuth` (`ts:src/management/client.ts:65`). To match, pass `false`.
- **Other constructors:**
  - `ManagementClient::with_dashboard_endpoint(Endpoint)` affects only the dashboard (mod.rs:75-78).
  - `ProfilesClient::new(Client)` and `TopicsClient::new(Client)` are standalone constructors that also require OAuth (profiles.rs:62-65, topics.rs:45-48).
  - `ManagementClient::profiles()` and `topics()` return cheap clones (mod.rs:80-90).
  - There is no other constructor. The endpoint is the `Client`'s endpoint.
- **Optional TS-like configuration resolver:** `scm_sdk::environment::resolve_oauth_config(ResolveOAuthConfigOptions, &EnvironmentSnapshot)` (`rs:src/environment.rs:220-265`).
  - Pass `EnvironmentSnapshot::empty()` so nothing is read from the environment.
  - It defaults `num_retries` to 5, clamped to 0–5.
  - `OAuthServiceConfig::client_builder(tsg_header)` sets `Limits.max_retries = num_retries` (environment.rs:208-217).
- **Default `Limits`** (`rs:src/config.rs:285-302`): `operation_timeout` 60 s, `max_response_bytes` 8 MiB, `max_error_bytes` 64 KiB, `max_retries` 2, `retry_base_delay` 250 ms, `max_retry_delay` 5 s, `max_concurrency` 32.
- **`RequestOptions`** (`rs:src/config.rs:361-395`):
  - `with_timeout(d)` accepts 0 < d ≤ 86400 s.
  - `with_retries(n)` accepts n ≤ 5.
  - `.cancel()` and `.cancellation_token()` are available.
  - **`Session`**: `Session::new()` and `.cancel()`. Pass it via `ClientBuilder::session` to cancel everything at once (useful for Ctrl-C).
- Most option structs are `#[non_exhaustive]` and have public fields, so external crates must write `let mut p = PaginationOptions::default(); p.offset = …;` rather than struct literals. This applies to `PaginationOptions`, `ProfileListAllOptions`, `TopicListOptions`, `TopicListAllOptions`, `CollectOptions` and the models.

## 2. Common wire contract

**URL.** `Endpoint::resolve` (`rs:src/config.rs:58-116`):
- The URL is the base path with its trailing `/` trimmed, then `/`, then the route with its leading `/` trimmed, then each `segment()` percent-encoded once.
- Unreserved characters `A-Za-z0-9-_.~` stay literal. Anything else becomes `%XX`, uppercase hex (`config.rs:121-168`).
- Query pairs are serialized with `url::form_urlencoded`, in insertion order.
- With a base of `http://127.0.0.1:P/aisec`, a profile list goes to `/aisec/v1/mgmt/profiles/tsg/<tsg>`.
- TS builds `new URL(baseUrl.replace(/\/+$/,'') + path)` and sets query parameters with `URLSearchParams` (`ts:src/http/request.ts:20`). For numeric TSGs and integer parameters the result is the same URL.

**Headers.** On every API request the SDK sets:
- `User-Agent: PAN-AIRS/0.1.0-rust-sdk` and `service-name: api` (`rs:src/engine.rs:22-32`).
- `Authorization: Bearer <token>`.
- `content-type: application/json` only when there is a body.

Header differences from TS:
- TS sends `User-Agent: PAN-AIRS/0.34.0-typescript-sdk` (`ts:src/constants.ts:51`); this is a documented difference (`doc:MANAGEMENT.md:13`).
- Transport-added headers differ: reqwest adds `accept: */*` and `accept-encoding: gzip`, while undici adds others.

The harness should assert `authorization`, `service-name`, `content-type`, the absence of `x-tsg-id`, and the `PAN-AIRS/` user-agent prefix only. The contract tests pin the exact Rust header set: `{authorization, service-name, user-agent}` plus `content-type` when a body is present (`rs:tests/management_contracts.rs:148-169`).

**Token exchange** (`rs:src/auth.rs:603-681`):
- `POST <issuer URL>` with `content-type: application/x-www-form-urlencoded` and body `grant_type=client_credentials&scope=tsg_id%3A<tsg>`.
- `Authorization: Basic base64(urlencode(client_id) ":" urlencode(secret))`.
- The response must decode as `{access_token: string, token_type: string, expires_in: u64}`. `token_type` must equal `bearer`, case-insensitively. Otherwise the error is `Authentication` or `Decode`.
- A non-2xx response gives `ErrorKind::Authentication` with the status attached.
- TS (`ts:src/management/oauth-client.ts fetchToken`) instead uses `btoa(clientId:clientSecret)` without URL-encoding. Its `OAuthTokenResponseSchema` makes `token_type` optional and allows any finite nonnegative `expires_in` (`ts:src/models/oauth-token.ts:4`).
- **Harness token fixture:** `{"access_token":"…","token_type":"Bearer","expires_in":3600}`. Use a client secret made only of unreserved characters so the Basic headers come out byte-identical.

**Empty 2xx body** is hydrated as `{}` before validation (`rs:src/engine.rs:710-715`), the same as TS (`ts:src/http/request.ts:20`, `parsed = text ? JSON.parse(text) : {}`). Schema defaults then produce `ai_profiles: []` or `custom_topics: []`. Tests: `rs:tests/management_contracts.rs:1469-1506`.

**Redirects** (3xx) produce `ErrorKind::Destination` with `RemoteOutcome::Rejected`; no request goes to the redirect target (`engine.rs:1193-1197`). reqwest is built with `redirect::Policy::none()` (`rs:src/transport.rs:142`). TS `fetch` follows redirects by default.

**Proxies.** `ReqwestTransport` honors system and environment proxies (`transport.rs:138-159`, `doc:FOUNDATION.md:75`). Node `fetch` ignores `HTTP(S)_PROXY`. Run the harness with proxy variables cleared and `NO_PROXY=127.0.0.1,localhost`.

## 3. ProfilesClient (`rs:src/airs/management/profiles.rs`)

### Option types

| Type | Lines | Fields | Defaults |
| --- | --- | --- | --- |
| `PaginationOptions` | 10-25 | `offset: u64`, `limit: u32`, `latest: Option<bool>` | `{0, 100, None}` |
| `ProfileListAllOptions` | 41-56 | `limit: u32`, `latest: Option<bool>`, `collect: CollectOptions` | `{100, None, default}` |

`PaginationOptions::query(latest_allowed)` (lines 27-39):
- Rejects `limit == 0` or `offset > 2^53-1` with `ErrorKind::Validation`, before any authentication or network work. Tested at `tests/management_contracts.rs:877-1018`, which asserts zero token calls and zero requests.
- Emits `offset`, `limit`, then `latest=true|false` only when `latest` is `Some` and the route allows it.

### Methods and the HTTP they send

All methods are `async` and `options: Option<&RequestOptions>`. Every listing is a GET marked replay-safe via `RawRequest::read`. The tenant segment comes from the OAuth context's `tsg_id` (`mod.rs:137-142`).

| Method | Returns | HTTP |
| --- | --- | --- |
| `list_for_token(PaginationOptions, opts)` | `Result<SecurityProfileListResponse>` | `GET {base}/v1/mgmt/profiles?offset=&limit=[&latest=]` (lines 66-80) |
| `list(PaginationOptions, opts)` | `Result<SecurityProfileListResponse>` | `GET {base}/v1/mgmt/profiles/tsg/{tsg}?offset={o}&limit={l}[&latest={b}]` (lines 97-109) |
| `pages(PaginationOptions, max_pages: usize, opts)` | `Result<Pages<'static, SecurityProfile, u64>>` | Lazy. No I/O until `next_page`. Cursor = offset; starts at `page.offset` (lines 110-136; test 1685-1708) |
| `list_all(ProfileListAllOptions, opts)` | `CollectionResult<SecurityProfile, u64>` | Starts at offset 0 and follows `next_offset` (lines 137-153) |
| `get(id: &str, opts)` | `Result<SecurityProfile>` | `list_all(ProfileListAllOptions::default())`, then the first `profile_id == id` (lines 154-168) |
| `get_by_name(name, opts)` | `Result<SecurityProfile>` | Same walk; highest `revision` among `profile_name == name`, with an unset revision counting as 0 and the first one winning ties (lines 169-200) |

Request examples:
- `list`: query order is exactly offset, limit, latest. Test: `PaginationOptions{offset:10, limit:20, latest:Some(false)}` sends `?offset=10&limit=20&latest=false` (`tests:272-283`).
- `get` and `get_by_name`: query `?offset=0&limit=100` with **no `latest` parameter**.

Lookup failures:
- If the walk is incomplete (truncated), the error is `ErrorKind::Limit`.
- If the walk is complete but nothing matches, the error is `ErrorKind::Validation`. There is no message, and the id or name is not included.
- Underlying walk errors surface via `.into_error()`.

The client also has mutations (`create`, `update`, `delete`, `force_delete`), which are out of scope for M2.

Profile lists send `latest` (if `Some`); topic lists never do (`doc:MANAGEMENT.md:17`).

## 4. TopicsClient (`rs:src/airs/management/topics.rs`)

### Option types

| Type | Lines | Fields | Defaults |
| --- | --- | --- | --- |
| `TopicListOptions` | 10-25 | `offset: u64`, `limit: u32`, `latest_only: bool` | `{0, 100, false}` |
| `TopicListAllOptions` | 26-39 | `limit: u32`, `collect: CollectOptions` | `{100, default}` |

`TopicListAllOptions` has no `latest` field.

### Methods and the HTTP they send

| Method | Returns | HTTP |
| --- | --- | --- |
| `list_for_token(PaginationOptions, opts)` | `Result<CustomTopicListResponse>` | `GET /v1/mgmt/topics?offset=&limit=`; `latest` is ignored (49-63) |
| `list(TopicListOptions, opts)` with `latest_only == false` | `Result<CustomTopicListResponse>` | One `GET /v1/mgmt/topics/tsg/{tsg}?offset={o}&limit={l}` (96-110; private `list_raw` 80-95) |
| `list(TopicListOptions, opts)` with `latest_only == true` | `Result<CustomTopicListResponse>` | **Client-side**, see below (111-151) |
| `pages(PaginationOptions, max_pages, opts)` | `Result<Pages<'static, CustomTopic, u64>>` | Lazy (153-179) |
| `list_all(TopicListAllOptions, opts)` | `CollectionResult<CustomTopic, u64>` | Offset walk (180-195) |
| `get(id, opts)` | `Result<CustomTopic>` | Walk with limit 100, then the first `topic_id == id` (196-210) |
| `get_by_name(name, opts)` | `Result<CustomTopic>` | Walk with limit 100; highest `revision` (required number), first on ties (211-238) |

The `latest_only == true` path:
1. Walks all pages at **limit 200**: `?offset=0&limit=200`, then `?offset={next}&limit=200`.
2. Fails with `Limit` if the walk is incomplete.
3. Keeps the largest revision per `topic_name`, preserving first-seen name order and the first revision on ties.
4. Slices the result locally to `[offset, offset+limit)`.
5. Returns a synthesized `CustomTopicListResponse{custom_topics: Value(slice), next_offset: Value(end) only if end < total}`.

Test: `tests:456-479`. Rows `A1, B2 | A3, A3'` with limit 1 return `[A3]` and `next_offset` 1.

Lookup failures behave the same as for profiles: an incomplete walk gives `Limit`, and no match gives `Validation`. Test: 10,001 rows produce `Limit` (`tests:1227-1268`).

## 5. Pagination and collections (`rs:src/pagination.rs`, `doc:PAGINATION.md`)

### The `next_offset` cursor rule

Defined in `mod.rs:167-178` and applied only inside `pages()`, `list_all()` and the lookups:
- An unset value, or `0`, ends the walk.
- A positive integer ≤ 2^53-1 becomes the next offset, **taken as given rather than computed as offset + item count**. Test: a page of 1 item with `next_offset: 2` leads to a request with `offset=2` (`tests:383-396`).
- Negative, fractional or unsafe values fail with `ErrorKind::Decode` (`tests:1293-1311`). That page's rows are lost because the failure happens inside the fetch.
- The single-page `list()` does not interpret `next_offset`; it returns it raw.

### Walk safety checks (`pages()` and `list_all()`)

- A repeated cursor fails with `ErrorKind::Pagination` before any duplicate request is sent (pagination.rs:346-350; tests:1270-1292). Accepted rows are kept in `partial()`.
- An empty non-final page (no items but a next cursor) fails with `Pagination` (`pagination.empty_page`, lines 390-394).
- Every request in a walk shares one `RequestOptions` deadline. If the caller passes `None`, the deadline is 60 s for the whole walk (tests:1315-1344).

### `CollectOptions` and `Collection`

`CollectOptions` (lines 45-91):
- Defaults: `max_items` 10,000, `max_bytes` 64 MiB of serialized JSON, `max_pages` 1,000.
- Allowed ranges: `max_items` 1..=1,000,000, `max_bytes` 2..=512 MiB, `max_pages` 1..=100,000.
- Zero is invalid and does **not** mean unlimited.
- Builders: `with_max_items`, `with_max_bytes`, `with_max_pages`.

`Collection<T, u64>` (lines 136-147) has `items`, `completion`, `resume`, `pages_read` and `wire_bytes`:
- `completion` is one of `Complete`, `Truncated(Items|Bytes|Pages)` or `Interrupted`.
- `resume` is `Option<Resume{cursor: u64, item_offset: usize}>`.
- Use `is_complete()` to check.
- Reaching `max_items` exactly at the known end (no next cursor, nothing buffered) still counts as `Complete`.

`CollectionResult = Result<Collection, CollectionError>`. `CollectionError` exposes `.error()`, `.partial()`, `.into_error()` and `.into_parts()` (lines 159-179).

To resume: `pages(PaginationOptions{offset: r.cursor, ..}, max_pages, opts)?.items().resume_from(r)?`. This refetches the page and skips `item_offset` items.

The TS baseline has no completion signal:
- `collectAll` (`ts:src/listing.ts:66`) defaults to `max ?? 10_000`, **silently truncates**, and treats `max: 0` as unbounded.
- `paginate` (`ts:src/listing.ts:41`) throws a plain `Error('Pagination returned a repeated cursor')`. It has no empty-page check and no page cap.
- `next` is `page.next_offset || undefined`, so 0 ends the walk while negative or fractional offsets are followed.

## 6. Models and JSON fidelity

### SecurityProfile and its list response

**`SecurityProfile`** (`rs:src/models/generated.rs:166008`, schema `s009612`) mirrors `ts:src/models/mgmt-security-profile.ts:294`:
- `profile_id: Optional<String>`
- **`profile_name: String` (required)**
- `csp_id: Optional<String>`, `tsg_id: Optional<String>`
- `revision: Optional<FiniteNumber>`, `active: Optional<bool>`
- `policy: Optional<Policy>`
- `created_by: Optional<String>`, `updated_by: Optional<String>`, `last_modified_ts: Optional<String>`
- `#[serde(flatten)] extensions: Extensions<JsonValue>` for passthrough fields

**`SecurityProfileListResponse`** (`generated.rs:166198`, `s009651`):
- `ai_profiles: Optional<Vec<SecurityProfile>>`, defaulted to `[]` (`ts: …:349`, `ai_profiles: z.array(...).default([])`)
- `next_offset: Optional<FiniteNumber>` (`z.number().optional()`)
- extensions

**`Policy`** (`generated.rs:156478`) has `ai-security-profiles: Optional<Vec<AiSecurityProfile>>`, `dlp-data-profiles: Optional<Vec<DlpDataProfilePolicy>>` and extensions. `AiSecurityProfile` (`generated.rs:4459`) has `model-type`, `content-type` and `model-configuration`, plus extensions. All nested schemas are `.passthrough()`.

### CustomTopic and its list response

**`CustomTopic`** (`generated.rs:18053`, `s008864`) mirrors `ts:src/models/mgmt-custom-topic.ts:4`:
- `topic_id: Optional<String>`
- **`topic_name: String`, `revision: FiniteNumber` and `description: String` (all required)**
- `active: Optional<bool>`
- `examples: Optional<Vec<String>>`, defaulted to `[]` because "the deployed service omits examples"
- `created_by`, `updated_by`, `last_modified_ts`, `created_ts`
- extensions

**`CustomTopicListResponse`** (`generated.rs:18243`, `s008906`) has `custom_topics` (default `[]`), `next_offset: Optional<FiniteNumber>` and extensions.

The native validator applies these defaults in Response mode. They are recorded in `contracts/native-semantics.json`: `s008873` examples, `s008908` custom_topics, `s009653` ai_profiles.

### Presence rules

- `Optional<T>` means omitted or a non-null value. **An explicit JSON `null` for an optional field is rejected** (`rs:src/data.rs:57-67`). Zod `.optional()` rejects null too, so both SDKs fail on `"created_by": null`.
- A missing required field also fails in both: `profile_name` for profiles; `topic_name`, `revision` or `description` for topics.

### Serialization

Every model has a hand-written `Serialize`:
- Known keys come first in **schema order**, unset optionals are skipped, then **extensions in `BTreeMap` (sorted) order** (`rs:src/models/support.rs:9`).
- An extension key that collides with a known field is a serialization error.
- `serde_json::to_value(&profile)` gives faithful snake_case JSON including unknown fields.
- **Pitfall:** serializing a bare `Optional::Unset` errors with "omitted field must be skipped by its container" (`data.rs:47-56`). The CLI must `match` on `Optional` (or call `into_option()`) instead of serializing fields on their own.
- `Debug` on all models prints only `Type([REDACTED])` (e.g. `generated.rs:166188-166192`), so output must use explicit serialization.
- Extension access: `extensions.get(k)`, `.iter()`, `.into_map()`. `JsonValue::as_value()` exposes the underlying `serde_json::Value`.

### Numbers

`FiniteNumber` wraps `serde_json::Number` and keeps its representation (`data.rs:185-263`):
- `1.0` is re-emitted as `1.0`; JavaScript prints `1`.
- `1e2` becomes `100.0`; JavaScript prints `100`.
- Integers above 2^53 stay exact; JavaScript rounds them.
- Accessors: `as_f64`, `as_u64`, `as_i64`.

### Key order

TS Zod passthrough output puts known keys in shape order, then **unknown keys in input order**. Rust sorts unknown keys. Nested unknown objects (`JsonValue`) are also sorted unless serde_json's `preserve_order` feature is enabled somewhere in the dependency graph, but the per-level `Extensions` map stays sorted either way. Byte-identical output is therefore only possible when fixture unknown keys are already sorted. Compare JSON semantically instead.

### Pretty printing and parsing

`JSON.stringify(x, null, 2)` and `serde_json::to_string_pretty` agree on indentation, `": "`, `[]`, `{}`, escapes (lowercase `\u00XX`) and non-ASCII handling.

Parsing edge cases:
- Duplicate keys: the last one wins in both.
- A leading UTF-8 BOM is stripped by `fetch().text()` in TS, but `serde_json` rejects it, giving `Decode` in Rust.
- Responses over 8 MiB fail with `Limit` in Rust only.
- Objects containing the reserved keys `$serde_json::private::Number` or `RawValue` are rejected in Rust only (`doc:MODELS.md:64-79`).

## 7. Revisions

There is no server-side "latest by name" API in the SDK. The available revision tools are:
- **Profiles:** the server `latest` query parameter (`PaginationOptions.latest` / `ProfileListAllOptions.latest`), plus client-side `get_by_name`, which picks the highest revision with the first winning ties. This matches TS `reduce((best,p)=> (p.revision??0) > (best.revision??0) ? p : best)` (`ts:src/management/profiles.ts:197`).
- **Topics:** client-side `latest_only` and `get_by_name`, matching `ts:src/management/topics.ts:128,203`.

`get(id)` returns the **first** row with a matching id, not the highest revision. TS does the same (`find`).

Whether `profile_id` or `topic_id` changes per revision on the live service is not established; see the open questions. SDK fixtures use distinct ids per revision (`tests:312`), while the TS CLI treats `topic_id` as stable across revisions (`cli:src/airs/management.ts:118-119`).

## 8. Error behavior

**`Error`** (`rs:src/error.rs`):
- `kind()` is one of `Configuration`, `Validation`, `Destination`, `Authentication`, `Io`, `Transport`, `Http`, `Decode`, `Limit`, `Deadline`, `Cancelled`, `Protocol`, `Pagination`.
- Other accessors: `status()`, `operation()` (e.g. `"airs.management.profiles.list"`), `request_id()`, `service_code()`, `retry_after()`, `remote_outcome()`, `error_type()` (`AISEC_*` strings), and `problem()`, which holds allowlisted RFC 7807 fields only.
- `Display` is exactly `SCM SDK {Kind:?}` plus ` (HTTP {status})` when a status is present, e.g. `SCM SDK Http (HTTP 404)` (`error.rs:268-276`).
- **Upstream body text is never included.** TS messages do include it, e.g. `extractErrorMessage` uses `error_message`, `message` and so on, or falls back to `API error 404` (`ts:src/http-retry.ts:73,182`). The Rust CLI has to write its own stderr text.

How the engine handles HTTP statuses (`rs:src/engine.rs:1116-1265`):

| Status | Rust behavior |
| --- | --- |
| **404, 400, other 4xx** | Immediate `Http` error with the status. `RemoteOutcome::Rejected`, error type `AISEC_CLIENT_SIDE_ERROR`. |
| **401**, or **403 without `x-opa-decision: false`** | Invalidates the token. On replay-safe reads it fetches a new token and replays **once**, counting against the retry budget, so `max_retries=0` disables the replay. If the replay fails, the result is `Http` 401/403 (`engine.rs:1216-1225,1345-1349`; tests `rs:src/engine/tests.rs:507-554`). |
| **403 with `x-opa-decision: false`** | No refresh, no replay. |
| **429, 502, 503, 504** on reads | Retried up to `max_retries` (default 2). Backoff is 250 ms·2^n, capped at 5 s. `Retry-After` is honored only if ≤ 5 s; otherwise the error is returned immediately (`engine.rs:1226-1236,1372-1374`; `doc:FOUNDATION.md:139-149`). |
| **500** | Not retried (tests `engine/tests.rs:1420-1443`). |
| Transport errors on reads | Retried within the same budget. |
| A 2xx body that fails JSON or schema decoding | `Decode`, with the status and `RemoteOutcome::Unknown`. |
| Deadline or cancellation | `Deadline` or `Cancelled`. |

TS 0.34.0 differs (`ts:src/http-retry.ts:182`, `ts:src/constants.ts:46-47`):
- The CLI passes no `numRetries`, so the TS SDK retries **500/502/503/504** up to **5** times, with random backoff `floor(rand*(2^n*1000+1))` ms and `Retry-After` capped at 60 s.
- **429 is not retried.**
- The 401/403 refresh happens once and does not count against the budget.
- The timeout is **per attempt**: 60 s, or `PANW_AI_SEC_TIMEOUT_MS` from the environment.

Note: Rust exports `constants::HTTP_FORCE_RETRY_STATUS_CODES = [500,502,503,504]` (`rs:src/constants.rs:646`), but the engine does not use it.

## 9. Cancellation

Cancel with `RequestOptions::cancel()` or `Session::cancel()`. Every page fetch and buffered-item yield checks first, so the walk stops with `Cancelled` and no further requests (tests:1685-1708). TS management calls take no `AbortSignal`; the TS CLI has no cooperative cancellation here.

## 10. How the TS CLI uses these SDK calls (the requests Rust must reproduce)

List flags are defined in `cli:src/cli/pagination.ts:6-8,20-56`:
- `--limit` defaults to 100 and must be an integer ≥ 1.
- `--offset` defaults to 0 and must be an integer ≥ 0.
- `--max` defaults to 10000; 0 means "no cap".
- `--all`. Combining `--all` with an explicit `--offset` is a usage error: `--all cannot be combined with --offset`.

| CLI invocation | TS SDK call | Wire requests | Rust equivalent |
| --- | --- | --- | --- |
| `runtime profiles list` | `profiles.list({limit,offset,latest:!allVersions})` | 1× `GET …/profiles/tsg/{tsg}?offset={o}&limit={l}&latest=true` (`false` with `--all-versions`) | `profiles().list(PaginationOptions{offset,limit,latest:Some(!all_versions)})` |
| `runtime profiles list --all` | `profiles.listAll({limit,latest,max})` | Walk at `limit`, `latest` included, stop at `max` items with no extra fetch | `list_all(ProfileListAllOptions{limit,latest:Some(..),collect.max_items=max or 1_000_000 when max=0})` |
| `runtime profiles get <uuid>` | `profiles.get(id)` | Walk `?offset=0&limit=100` (no latest), max 10k | `profiles().get(id)` |
| `runtime profiles get <name>` | `profiles.getByName(name)` | Same walk | `get_by_name(name)` |
| `runtime profiles get X --revision N` or `--all-versions` | `profiles.listAll({latest:false})` | Walk `?offset=0&limit=100&latest=false` | `list_all` with `latest:Some(false)`, then CLI filter |
| `runtime topics list` | `topics.list({latestOnly:true,limit,offset})` | Walk `…/topics/tsg/{tsg}?offset=0&limit=200` (**200, not `--limit`**) | `topics().list(TopicListOptions{offset,limit,latest_only:true})` |
| `runtime topics list --all` | Same, with `{offset:0, limit: max===0?10000:max}` | Same walk | Same |
| `runtime topics list --all-versions` | `topics.listAll()`, then local slice | Walk `?offset=0&limit=100` | `list_all(default)`, then slice |
| `runtime topics get <uuid or name>` (incl. `--revision`/`--all-versions`) | `topics.listAll()`, then CLI find or reduce | Walk `?offset=0&limit=100` | `list_all(default)` or `get` / `get_by_name` |

Sources for the table: `cli:src/cli/commands/runtime.ts:611-690,1133-1205` and `cli:src/airs/management.ts:55-80,256-283`.

## 11. JSON output shapes the TS CLI prints (not raw SDK models)

Profiles have no `structured` view, so JSON rows are `normalizeProfile` output (`cli:src/airs/management.ts:243-254`), in this key order with undefined keys omitted:

`{profileId, profileName, revision, active, createdBy, updatedBy, lastModifiedTs, policy}`

`csp_id`, `tsg_id` and unknown top-level fields are **dropped**. `policy` is the Zod-parsed object, with passthrough keys retained.

Topics use `topicsView.structured` (`cli:src/cli/renderer/views/runtime.ts:64-75`):

`{topicId, topicName, revision, active, description, examples, createdBy, updatedBy, lastModifiedTs, createdTs}`

`examples` is always present because of the default. Unknown fields are dropped.

Printing:
- A list prints `JSON.stringify(rows, null, 2)`, or `[]` when empty, to stdout (`cli:src/cli/renderer/common.ts:101-109`).
- A detail view prints `JSON.stringify(obj, null, 2)` (`view.ts:68-69`).
- The page status (e.g. `Showing N`, `Showing N (more available)`) goes to stderr via `ui.status` (`view.ts:32-41`; `ui.ts:131-135`).

The Rust CLI must build these maps explicitly, either with ordered `#[derive(Serialize)]` structs and `skip_serializing_if`, or with `serde_json::Map` plus `preserve_order`. A plain `serde_json::Map` sorts keys alphabetically.

## 12. Harness guidance

**Parity-safe fixtures:**
- 200 responses with integer numbers and lexicographically sorted unknown keys.
- `next_offset` either absent, 0, or the true next offset.
- No empty non-final pages.
- Fewer than 1,000 pages and 10,000 items.
- A Bearer token fixture with integer `expires_in`.
- A secret made of unreserved characters.
- 404, 400 or 401 responses, where 401 is replayed once in both SDKs.

**Known divergences** (assert separately, don't diff the two CLIs):
- 500: TS sends 6 requests, Rust 1.
- 429: TS sends 1, Rust 3.
- 3xx: TS follows, Rust fails.
- Empty non-final page.
- Negative or fractional `next_offset`.
- More than 1,000 pages or more than 10,000 items (TS silently truncates).
- Non-integer numbers; unsorted unknown keys.
- A leading BOM.
- More than 8 MiB in one page.
- A full walk that takes longer than 60 s.


## Acceptance criteria
- `airs-cli-rs runtime profiles list --output json` sends exactly one `GET {base}/v1/mgmt/profiles/tsg/{tsg}?offset=0&limit=100&latest=true` (query order offset, limit, latest) with `authorization: Bearer <token>` and `service-name: api`, no `x-tsg-id`, no body; exits 0.
- With `--all-versions`, profiles list sends `latest=false` instead of `latest=true`; `--limit 20 --offset 40` sends `?offset=40&limit=20&latest=true`.
- With base endpoint `http://127.0.0.1:<port>/aisec`, every management request path starts with `/aisec/v1/mgmt/` (trailing slash on the base is tolerated, no double slash).
- Before the first API request a token request is sent: `POST <token endpoint>` with `content-type: application/x-www-form-urlencoded`, body `grant_type=client_credentials&scope=tsg_id%3A<tsg>`, and `Authorization: Basic ...`; with a secret made of unreserved characters the Basic value equals base64(`<client_id>:<secret>`).
- Token response `{"access_token":"t","token_type":"Bearer","expires_in":3600}` is accepted, and later API requests carry `Authorization: Bearer t`.
- `profiles list --all` walks offsets as returned: a page with `next_offset: 2` leads to `?offset=2&limit=100&latest=true` next; `next_offset` absent or 0 ends the walk; stdout holds the concatenated rows; exit 0.
- `profiles list --all --max 1` against a 2-item first page with next_offset returns 1 item and sends no second request.
- `profiles get <name>` sends `?offset=0&limit=100` with NO `latest` parameter, follows next_offset, and prints the highest-revision match (first one on equal revisions).
- `profiles get <uuid>` uses the same walk and prints the first row whose profile_id equals the argument.
- `profiles get X --revision N` and `--all-versions` walk with `?offset=0&limit=100&latest=false`.
- Profile JSON output is an array (list) or object (get) with keys in order profileId, profileName, revision, active, createdBy, updatedBy, lastModifiedTs, policy; unset fields omitted; csp_id, tsg_id and unknown top-level fields absent; unknown keys inside policy preserved.
- Profiles list with an empty 200 body (or `{}`) prints `[]` on stdout and exits 0.
- `runtime topics list` (default) walks `GET {base}/v1/mgmt/topics/tsg/{tsg}?offset=0&limit=200` pages regardless of --limit, keeps the highest revision per topic_name in first-seen name order (first on ties), then applies --offset/--limit locally.
- `topics list --all-versions` walks with `limit=100` and slices locally; `topics get <name|uuid>` walks with `?offset=0&limit=100`.
- Topic JSON output has keys in order topicId, topicName, revision, active, description, examples, createdBy, updatedBy, lastModifiedTs, createdTs; a topic without `examples` on the wire prints `"examples": []`; unknown topic fields are absent.
- A topic row missing `description` (or `revision`, or `topic_name`), or a profile row missing `profile_name`, makes the command exit 1 with empty stdout.
- A profile or topic row with an explicit `null` for an optional field (e.g. `"created_by": null`) makes the command exit 1 with empty stdout (both SDKs reject it).
- Unknown top-level fields in the list envelope (e.g. `"total": 5`) are ignored without error.
- HTTP 404 on a list gives exit 1, empty stdout, non-empty stderr, exactly 1 API request; stderr contains neither the bearer token nor the client secret.
- HTTP 401 on a list request triggers exactly one fresh token request and one replay (2 API requests and 2 token requests in total); if the replay also returns 401, exit 1.
- HTTP 403 with header `x-opa-decision: false` causes no token refresh and no replay (1 API request); exit 1.
- A walk where next_offset repeats an earlier offset exits 1 without re-requesting that offset.
- `get` by a name or id that is absent after a complete walk exits 1 with a not-found message on stderr and empty stdout.
- `--limit 0`, `--limit -1`, `--offset -1`, or `--all` combined with an explicit `--offset` exit 2 with no token or API request sent.
- Setting PANW_MGMT_CLIENT_ID, PANW_MGMT_CLIENT_SECRET, PANW_MGMT_TSG_ID, PANW_MGMT_ENDPOINT and PANW_MGMT_TOKEN_ENDPOINT to bogus values does not change any request URL, token request body, Authorization value or tsg path segment.
- The tsg path segment in every profile/topic list URL equals the selected tenant's mgmt TSG, and the token scope is `tsg_id:<same tsg>`.
- Sending SIGINT during a multi-page walk stops further page requests and exits non-zero without printing partial data to stdout (Rust: Session/RequestOptions cancel gives ErrorKind::Cancelled).


## Discrepancies
- Retry status sets differ: the TS SDK retries 500/502/503/504 (HTTP_FORCE_RETRY_STATUS_CODES, ts:src/constants.ts:47) up to 5 times because the TS CLI passes no numRetries (cli:src/config/client-options.ts:34-51); the Rust engine retries 429/502/503/504 up to Limits.max_retries (default 2) and never 500 (rs:src/engine.rs:1372-1374; doc:FOUNDATION.md:139-140). A 500 fixture gives 6 requests in TS and 1 in Rust; a 429 fixture gives 1 in TS and 3 in Rust.
- The Rust crate exports `constants::HTTP_FORCE_RETRY_STATUS_CODES = [500,502,503,504]` (rs:src/constants.rs:646), but the engine does not use it; it implements a different set. This is misleading for anyone porting TS retry logic.
- native-operations.json lists `deliberateDifferences: []` and `optionParity: complete` for ProfilesClient.list, listForToken and TopicsClient.listForToken, yet the retry statuses, retry budget, backoff, Retry-After cap (5 s vs 60 s), redirect handling and per-walk vs per-attempt timeout all differ from TS. These are documented globally in FOUNDATION.md, not per operation.
- Timeout semantics: Rust applies one 60 s deadline (RequestOptions or Limits.operation_timeout) to the entire list_all, get or get_by_name walk (tests/management_contracts.rs:1315-1344); TS uses 60 s per attempt and reads PANW_AI_SEC_TIMEOUT_MS from the environment (ts:src/http/request.ts:20). That env read happens inside the TS SDK, outside the CLI's 'tenant file only' guarantee.
- Truncation: TS listAll/get/getByName/latestOnly silently truncate at 10,000 items (ts:src/listing.ts:66), so TS `get` can report 'Profile not found' when the item lies beyond 10,000 rows (false absence). Rust returns ErrorKind::Limit for lookups and an explicit Truncated completion for list_all.
- TS `max: 0` means unbounded; Rust CollectOptions rejects 0 and caps max_items at 1,000,000, max_pages at 100,000 and max_bytes at 512 MiB (rs:src/pagination.rs:78-90). Rust's default max_pages of 1,000 truncates `--limit 1 --all` walks that TS would continue (TS has no page cap).
- Rust rejects empty non-final pages (Pagination) and negative, fractional or >2^53 next_offset values (Decode) inside walks (rs:src/pagination.rs:390-394; rs:src/airs/management/mod.rs:167-178). TS continues past empty pages and sends requests with offset=-1 or 1.5 (`page.next_offset || undefined`, ts:src/management/profiles.ts:143).
- TS repeated-cursor failure is a plain `Error('Pagination returned a repeated cursor')` rather than an AISecSDKException (ts:src/listing.ts:41). Rust returns ErrorKind::Pagination. stderr text and possibly exit-code mapping in the TS CLI depend on that error class.
- OAuth Basic header encoding differs: Rust form-urlencodes client_id and secret before base64 (RFC 6749 §2.3.1; rs:src/auth.rs:624-632); TS uses `btoa(clientId:clientSecret)` raw (ts:src/management/oauth-client.ts fetchToken). For secrets containing reserved characters (`+ / = : @ %` or spaces) the two CLIs send different Authorization headers, and one of them may fail live.
- Token response strictness differs: Rust requires `token_type` equal to bearer (case-insensitive) and an integer `expires_in` (u64) (rs:src/auth.rs:588-593,667); TS treats token_type as optional and accepts any finite nonnegative expires_in (ts:src/models/oauth-token.ts:4).
- Redirects: Rust fails with ErrorKind::Destination (Rejected) on any 3xx (rs:src/engine.rs:1193-1197); TS fetch follows redirects by default.
- 401 refresh accounting: Rust counts the refresh replay against max_retries, so with_retries(0) or max_retries=0 disables it (doc:FOUNDATION.md:144-147); TS refresh does not count against the budget (attempt-- in ts:src/http-retry.ts:182).
- JSON number representation: Rust FiniteNumber preserves `1.0`, `1e2` becomes `100.0`, and integers above 2^53 stay exact (rs:src/data.rs:185-263); TS prints `1` and `100` and rounds large integers. Profile and topic `revision` values in the output can differ byte-wise.
- Unknown-key ordering: Rust Extensions is a BTreeMap (rs:src/models/support.rs:9), so unknown keys serialize sorted after known keys; TS Zod passthrough keeps input order. The `policy` subtree in profile output can differ in key order.
- The TS CLI's profile JSON is a normalized camelCase subset (cli:src/airs/management.ts:243-254) that drops csp_id, tsg_id and unknown fields, while the SDK model preserves them. Topics are also projected to camelCase (cli:src/cli/renderer/views/runtime.ts:64-75). Serializing Rust SDK models directly would not match the TS CLI.
- Test gap: the profile fixture carries an unknown `future` field (rs:tests/management_contracts.rs:209), but no assertion checks that it is retained or reserialized.
- Test gap: management_contracts.rs only ever returns HTTP 200; no profile/topic test covers 401, 403, 404, 429 or 5xx. Status behavior is tested only generically in rs:src/engine/tests.rs:507-554,1420-1443.
- Live evidence gap: of the operations here, only profiles.list and profiles.list_for_token are live-verified (native-operations.json, docs/checks/phase-08-live-attempt-06.json). topics.list, list_all, get, get_by_name, profiles get, get_by_name and list_all have no live acceptance.
- TS CLI quirk: `runtime topics list --all --all-versions --max N` ignores --max, because listTopics() always uses the SDK default of 10,000 (cli:src/cli/commands/runtime.ts:1179-1189). Latest-topics `--all --max 20000` is still capped internally at 10,000 by `listAll({limit:200})`.
- TS CLI quirk: `profiles list` passes the raw next_offset to the page status, so `next_offset: 0` (which the SDK treats as end-of-list) still prints 'Showing N (more available)' on stderr (cli:src/cli/renderer/view.ts:39; cli:src/airs/management.ts:272).
- TS CLI quirk: `--revision abc` parses to NaN via Number and produces 'Profile/Topic X not found' rather than a usage error (cli:src/cli/commands/runtime.ts:659,677,1136,1154).
- Not-found message text differs by path in the TS CLI: SDK get/getByName give `Profile not found: <x>` (ts:src/management/profiles.ts:170,197), the --revision path gives `Profile <x> not found`, and topics give `Topic <id> not found` or `Topic "<name>" not found` (cli:src/airs/management.ts:71,78). Rust SDK lookups return a message-less ErrorKind::Validation, so the Rust CLI must produce these strings itself.
- Rust ReqwestTransport honors system and environment proxies (rs:src/transport.rs:138-159); Node fetch does not honor HTTP(S)_PROXY. Loopback harness runs can diverge if a proxy is configured.
- Response-size bound: Rust fails a page larger than 8 MiB with Limit (Limits.max_response_bytes); TS has no cap. A leading UTF-8 BOM is accepted by TS (fetch().text() strips it) but rejected by serde_json in Rust (Decode).


## Open questions
- Should airs-cli-rs reproduce TS retry counts? The SDK lets you change the retry budget (Limits.max_retries, RequestOptions::with_retries up to 5) but not the status set (429 vs 500). Exact parity for 500/429 fixtures needs a custom Transport wrapper or an accepted documented divergence.
- When a Rust list_all or lookup is truncated (more than 10,000 items, more than 1,000 pages, or more than 64 MiB), should the Rust CLI exit 1, or emit the partial rows with a stderr warning and exit 0? TS silently returns the truncated set and can report a false not-found.
- How should `--max 0` (TS: unbounded) map in Rust: to CollectOptions max_items 1,000,000 with max_pages computed from limit, or to a manual pages() walk?
- Does the live PANW issuer URL-decode Basic credentials (RFC 6749)? If it does not, Rust's form-urlencoded Basic header fails for secrets containing reserved characters, while TS's raw btoa works, or the reverse.
- On the live service, does profile_id or topic_id change per revision, or stay stable across revisions? `get <uuid>` returns the first listed row, not the highest revision, in both SDKs.
- What does the live /v1/mgmt/profiles/tsg/{tsg} route return when `latest` is omitted (used by profiles get) vs `latest=true` (used by profiles list)? get_by_name relies on client-side highest-revision selection.
- Is the `@cdot65/prisma-airs-sdk@0.34.0` npm tarball the CLI installs byte-identical to the frozen baseline commit 4a80dbd recorded in scm-sdk-rs/contracts? node_modules is not installed in the checkout, so this could not be verified.
- Should the Rust CLI enable serde_json `preserve_order`? It affects SDK-wide Value maps through feature unification and moves nested unknown-object key order closer to TS. Alternatively, keep typed ordered output structs and compare policy subtrees semantically in the harness.
- Should the Rust CLI pass an explicit per-walk RequestOptions timeout larger than 60 s for list_all and lookups, to approximate the TS per-attempt timeout on large tenants?
- Should the harness pin proxy environment variables and NO_PROXY, or should the Rust CLI supply a custom Transport with proxies disabled for loopback endpoints? ReqwestTransport exposes no no_proxy option.
