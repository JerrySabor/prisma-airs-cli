# Rust SDK writes for M4 (0.4): topics and profiles create/update/delete, apply/revert/eval, cleanup

Scope: every M4 operation, the `scm-sdk` 0.1.0 API that serves it, and how it differs from the
TypeScript SDK 0.34.0 that the frozen TS CLI (5711012) uses. Everything here was read from source.
Nothing was built or run, and no network calls were made.

Citation prefixes:

- `rs:` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scm-sdk-0.1.0/` (the published
  crate the CLI pins).
- `tsdk:` = `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js`
  (the 0.34.0 bundle the TS CLI really runs).
- `cli:` = `.reference/prisma-airs-cli/` (the TS CLI).
- `here:` = this repository.

Companion specs: `rs-sdk-management.md` (reads, models, pagination), `rs-sdk-scan.md` (sync scan),
`rs-sdk-foundation.md` (engine, auth). This file covers only what M4 adds.

---

## 0. Summary

- **No blocking SDK gap.** Every operation M4 needs exists in scm-sdk 0.1.0 with the TS wire
  shape: method, path, query, body schema and response schema (§2, §3). Every request body the TS
  CLI sends can be expressed with the Rust types (§4).
- **Six non-blocking SDK limitations** (G1–G6, §9). Each has a safe CLI-side handling or needs a
  §12 row. The two that matter most:
  - **G1.** The SDK never replays a write. That includes the 401/403 refresh-and-replay, which TS
    does for every method.
  - **G2.** 409 conflict payloads and server message text cannot be reached from `Error`.
- **TS behaviours the port must not copy** (§8). Each is a §12 candidate.
  - TS replays POST/PUT/DELETE on 5xx, network errors and timeouts, up to 5 times (duplicate
    creates).
  - `topics revert` always fails at its delete step. The profile has already been modified by
    then.
  - The endpoint bypass is not only in `topics create` but also in `topics apply` and
    `topics revert`.
  - Root `--output` swallows the leaf `--output` on create, apply, revert, eval and cleanup.
  - `profiles cleanup` loops forever on `next_offset: 0`.
  - apply/revert edit the *first-listed* profile revision.
  - `profiles create` reports a pre-existing profile as "created" on 409.
  - eval counts failed scans as "not triggered".
- **Doc correction.** DESIGN §5 says a 401/403 makes the SDK refresh and replay "the request".
  For writes that is false in scm-sdk 0.1.0 (`rs:src/engine.rs:1216-1225`, `replay_safe` is false
  for `RawRequest::new`).
- **Live tier (§11).** This is a separate opt-in, `AIRS_RS_LIVE_WRITES=1`, on top of the existing
  `AIRS_RS_LIVE=1 AIRS_E2E_TENANT`.
  - The flow creates 4 resources (2 topics, 2 profiles; the cap is 10) named
    `airs-rs-e2e-<unix>-<pid>-<n>-<role>`.
  - It journals every create and delete to `target/live/ledger.jsonl`, intent before outcome.
  - It tears down its own resources on success, failure and panic.
  - The re-runnable sweeper `live_cleanup` (`AIRS_RS_LIVE_CLEANUP=1`) deletes only prefixed
    resources whose embedded Unix time is at least 1 h old. It deletes profiles first, then
    topics, through the Rust CLI's plain (non-force) delete on a pty.
  - `topics eval` runs only with `AIRS_RS_LIVE_EVAL=1`, against "Prisma AIRS Harness", with its own
    scan budget `AIRS_RS_LIVE_EVAL_MAX_SCANS` (default 4, max 8).
  - `profiles cleanup` never runs live.

---

## 1. The write engine path (shared by every M4 write)

### 1.1 Request construction

- **Writes are not replay-safe.** Every write is built with `RawRequest::new(method, path)`, which
  sets `replay_safe: false` (`rs:src/engine.rs:49-61`; the doc comment says "No replay is assumed
  for an arbitrary operation"). Reads use `RawRequest::read` (`:63-67`), which sets
  `replay_safe: true`.
- **Bodies go through `Client::send_model(request, body, request_schema, response_schema, opts)`**
  (`rs:src/engine.rs:583-597`), in this order:
  1. `operation_options(opts)`: the caller's `RequestOptions`, else
     `RequestOptions::with_timeout(limits.operation_timeout)` (60 s by default) (`:470-479`).
     **The deadline is absolute.** It is fixed when the `RequestOptions` is created
     (`rs:src/config.rs:367-375`).
  2. `prepare_model` → `validated_json` (`:524-581`):
     - Serialize the typed body, bounded by `limits.max_request_bytes` (8 MiB by default,
       `rs:src/config.rs:289`).
     - Parse it back to a `serde_json::Value`.
     - Run `validation::parse_with_limits(schema, value, Mode::Request, …)`. The default
       `ValidationLimits` are depth 64 and 100,000 nodes (`rs:src/validation.rs:33-41`).
     - Serialize the normalized value again.
     - A schema failure is `ErrorKind::Validation`. **All of this happens before authentication,
       so an invalid body sends zero requests.**
  3. `send_contract` → `send_buffered` → `decode_contract(response_schema, Mode::Response)`
     (`:608-620`, `:702-734`).
- **Body bytes on the wire.** The body is re-serialized from a `serde_json::Value` without
  `preserve_order`, so **every object level is sent with its keys sorted**. TS sends Zod output
  order: known keys in shape order, then unknown keys in input order (`tsdk:10104-10135`). The two
  bodies are equal as JSON but not as bytes. Parity fixtures must compare request bodies
  semantically. (Never enable `serde_json/preserve_order`: feature unification would change the
  SDK's own wire bytes.)
- **No body** (DELETE): `send_contract` directly. No `content-type` is sent
  (`rs:src/engine.rs:94-104`, `:1154-1158`). TS also omits it without a body
  (`tsdk:10161-10163`).

### 1.2 Dispatch, retries and outcomes (`rs:src/engine.rs:1116-1265`)

| Situation | Rust write (`replay_safe = false`) | TS SDK write (`executeWithRetry`, `tsdk:9786-9850`) |
|---|---|---|
| Transport error (refused, reset, timeout mid-flight) | no retry (`:1176` requires `replay_safe`). `Transport`, outcome **Unknown**, because `sent` was set before `transport.send` (`:1164`, `:1249-1262`) | retried up to `numRetries` (5 by default) with backoff `rand·2^n s` (`tsdk:9800-9808`). **The POST/PUT/DELETE is re-sent** |
| Per-attempt timeout | n/a: the deadline covers the whole call. `Deadline`, Unknown once dispatched | the attempt is aborted and the error becomes `lastError`, so **it is retried** (`tsdk:9800-9808`) |
| 3xx | `Destination`, **Rejected**, nothing follows (`:1193-1197`) | fetch follows the redirect |
| 401, or 403 without `x-opa-decision: false` | token invalidated (`on_unauthorized`) but **no replay**: `replay_safe` is false (`:1216-1225`). `Http 401/403`, **Rejected** | `OAuthAuth.onUnauthorized` clears the token and returns true, so the request is **replayed once**. That replay does not count against the budget (`tsdk:9816-9823`, `:10208-10230`, `:10865-10872`) |
| 403 with `x-opa-decision: false` | no refresh. `Http 403`, Rejected | no refresh, error |
| 429 | not retried. `Http 429`, Rejected | not retried |
| 500/502/503/504 | not retried. `Http 5xx`, **Unknown** (`:1237-1247`) | **retried** up to 5 times (`tsdk:9825-9830`; `HTTP_FORCE_RETRY_STATUS_CODES`, `tsdk:31`) |
| other 4xx (400, 404, 409, 422) | `Http`, **Rejected** | error, no retry |
| 2xx with a body that fails JSON or schema | `Decode`, status attached, **Unknown** (`BufferedResponse::annotate`, `:207-213`). **The write was applied** | `AISEC_RESPONSE_VALIDATION`. The write was applied |
| empty 2xx body | hydrated as `{}` before schema (`:702-712`); TS does the same (`tsdk:10264`) | same |
| cancellation (`Session` / `RequestOptions::cancel`) | `Cancelled`; Unknown if dispatched | no signal is passed by the CLI |

Consequences:

- **scm-sdk never re-sends a write.** `Limits.max_retries` (the CLI sets 5,
  `here:src/clients.rs:329`) and `RequestOptions::with_retries` have no effect on POST/PUT/DELETE.
- `RemoteOutcome` is the only safe reconciliation signal:
  - `Rejected`: the server answered 3xx/4xx, so nothing was applied. The one exception is a 409
    that is about pre-existing state, not about this request being applied.
  - `Unknown`: the request may have been applied.
  - `NotSent`: a local failure before dispatch (validation, UUID, token request, cancellation
    before send).
- `Error` keeps only metadata: kind, status, operation name (`airs.management.topics.create`
  etc.), request id, service code, `retry_after`, allowlisted RFC 7807 `problem()`, and
  `remote_outcome()` (`rs:src/error.rs:101-203`). **No server message text and no body.**
- The token is fetched inside the loop, before `sent` is set (`:1150-1155`). A token-endpoint
  failure is therefore `NotSent`.
- **Concurrency.** Each `Client` has a semaphore of `limits.max_concurrency` (32 by default).
  The permit is awaited inside the request's deadline (`:1139-1146` runs under `options.run`), so
  queued requests consume their budget.

---

## 2. Topic operations

All of these are on `scm::airs::management::TopicsClient`, obtained from `ManagementClient::topics()`
(`rs:src/airs/management/mod.rs:85-90`). The SDK requires OAuth (`require_auth`, `topics.rs:45-48`).
The models live in `scm::airs::management::models` (re-exported from `rs:src/models/management.rs`).

| CLI step | Rust API | Wire | TS SDK call |
|---|---|---|---|
| create | `TopicsClient::create(&CreateCustomTopicRequest, Option<&RequestOptions>) -> Result<CustomTopic>` (`rs:src/airs/management/topics.rs:64-79`) | `POST {base}/v1/mgmt/topic`, JSON body validated against `CreateCustomTopicRequestSchema` (s008884), response `CustomTopicSchema` | `topics.create(body)` (`tsdk:11497-11508`), same path |
| update | `TopicsClient::update(id: &str, &CreateCustomTopicRequest, opts) -> Result<CustomTopic>` (`:239-257`) | `PUT {base}/v1/mgmt/topic/uuid/{id}`; `uuid(id)` is checked first (Validation, zero requests) | `topics.update` (`tsdk:11623-11635`): `assertUuid`, then the same PUT |
| delete | `TopicsClient::delete(id, opts) -> Result<DeleteTopicResponse>` (`:258-273`) | `DELETE {base}/v1/mgmt/topic/{id}`, UUID-checked | `topics.delete` (`tsdk:11649-11659`) |
| force delete | `force_delete_with_audit(id, updated_by: &str, opts)` (`:274-293`) or `force_delete(id, Option<&str>, opts)` (`:294-302`, which maps `None` to `""`) | `DELETE {base}/v1/mgmt/topic/{id}/force?updated_by=<form-encoded>`. Checks run in the order `uuid(id)`, then `nonblank(updated_by)` (ECMAScript whitespace trim, `mod.rs:152-165`) | `forceDeleteWithAudit` (`tsdk:11453-11466`): `assertUuid`, then `if (!updatedBy.trim()) throw "updatedBy is required"`. `forceDelete(id, undefined)` passes `""` (`tsdk:11679-11681`) |
| lookups (create-or-update, apply, revert) | `list_all(TopicListAllOptions::default())` (limit 100), then a CLI-side `find` | `GET …/topics/tsg/{tsg}?offset=…&limit=100` walk | `topics.listAll()` |

Notes:

- **Validation parity.**
  - `uuid()` matches TS `UUID_RE`: 8-4-4-4-12 hex, any case (`rs:src/data.rs:324-333`,
    `tsdk:9555`).
  - `nonblank` matches `.trim()`.
  - In both SDKs, an invalid id is refused before the empty-`updated_by` check, and both refuse
    before any request.
- **Query encoding.** `updated_by` goes through `url::form_urlencoded`: `@` becomes `%40` and a
  space becomes `+`. `URLSearchParams.set` gives the same bytes.
- **`DeleteTopicResponse`** is an untagged enum: `Variant1 {message: String}`, the server-string
  form after the `message_object` transform (`rs:src/validation.rs:909-917`);
  `Variant2 {message: Optional<String>}`; and `Unknown(JsonValue)`
  (`rs:src/models/generated.rs:27114-27225`).
  - TS has the same union: a string transformed to `{message}`, or `{message?}` with passthrough
    (`tsdk:2031-2034`).
  - The CLI reads `message` from Variant1/Variant2. `{}` gives no message.
- **`DeleteTopicConflict`** (`{message, payload: [{profile_id, profile_name, revision}]}`,
  `rs:…/generated.rs:26914`, `:27008`) exists as a model, but no operation decodes a 409 body into
  it. See G2.
- **Revisions.** There is no optimistic concurrency: no If-Match, no expected-revision parameter.
  - `revision` in `CreateCustomTopicRequest` is `Optional<FiniteNumber>` with a Zod `int` check.
    The TS CLI never sends it, except through a user `--config`.
  - The server assigns revisions. Whether PUT keeps `topic_id` is not established (open question
    1). The TS CLI assumes it does (`cli:src/cli/commands/topics-create.ts:46-48`).

## 3. Profile operations (`rs:src/airs/management/profiles.rs`)

| CLI step | Rust API | Wire | TS SDK |
|---|---|---|---|
| create | `ProfilesClient::create(&CreateSecurityProfileRequest, opts) -> Result<SecurityProfile>` (`:81-96`) | `POST {base}/v1/mgmt/profile`, schema `CreateSecurityProfileRequestSchema` (s009632), response `SecurityProfileSchema` | `profiles.create` (`tsdk:11238-11249`) |
| update | `update(id, &CreateSecurityProfileRequest, opts)` (`:201-219`) | `PUT {base}/v1/mgmt/profile/uuid/{id}`, UUID-checked | `profiles.update` (`tsdk:11370-11382`) |
| delete | `delete(id, opts) -> Result<DeleteProfileResponse>` (`:220-235`) | `DELETE {base}/v1/mgmt/profile/{id}` | `profiles.delete` (`tsdk:11396-11406`) |
| force delete | `force_delete(id, updated_by: &str, opts)` (`:236-254`) | `DELETE {base}/v1/mgmt/profile/{id}/force?updated_by=…`. **No nonblank check** | `profiles.forceDelete` (`tsdk:11424-11435`). **No check either** (parity) |
| resolve by UUID / name | `get(id)` (`:154-168`) and `get_by_name(name)` (`:169-200`, highest revision with an unset revision counting as 0, first on ties) | walk `?offset=0&limit=100`, no `latest` | `profiles.get` / `getByName` (`tsdk:11278-11368`) |
| cleanup listing | `list(PaginationOptions{offset, limit: 200, latest: None})` per page, or `pages()` / `list_all` | `GET …/profiles/tsg/{tsg}?offset=…&limit=200` | the CLI's own loop over `listProfiles({limit: 200, offset})` (`cli:src/cli/commands/profiles-cleanup.ts:82-90`) |

`DeleteProfileResponse` and `DeleteProfileConflict` (`{message, payload: [{policy_id, policy_name,
priority}]}`, `rs:…/generated.rs:26534`, `:26734`) mirror `tsdk:1985-2000`. G2 applies here too.

The CLI must validate `--updated-by` itself for profiles. The SDK accepts `""`, and so does TS
(`cli:src/cli/commands/runtime.ts:884-886` guards with `!opts.updatedBy`).

## 4. Request bodies the TS CLI sends, and whether Rust can express them

| TS body | Source | Rust construction | Expressible? |
|---|---|---|---|
| `{topic_name, description, examples}` | `topics create` (create-or-update) `cli:src/cli/commands/topics-create.ts:36-40` | `CreateCustomTopicRequest::builder().topic_name(..).description(Optional::Value(..)).examples(Optional::Value(vec)).build()` (`rs:…/generated.rs:13168-13340`) | yes |
| any JSON object from `--config` | `topics update` `cli:…/runtime.ts:1218-1219` | `CreateCustomTopicRequest::parse(value, Mode::Request)`: schema check plus typed decode; unknown keys go to `extensions` | yes (see the limits below) |
| `{profile_name, active, policy?}` from flags | `profiles create` (`cli:src/cli/builders/profile-builder.ts:211-249`) | `CreateSecurityProfileRequest`; `policy: Policy` is **required** (`generated.rs:13361-13460`) | yes. **The TS body without `policy`** (no protection flag given) fails Zod locally: `Request body for POST /v1/mgmt/profile did not match schema: policy: invalid_type`, exit 1, zero requests. The Rust builder also refuses it (Validation); the CLI must produce the TS-shaped message |
| default sections with JSON `null` (`'data-leak-detection': {action:'', 'mask-data-inline': false, member: null}`, `'database-security': null`) | `profile-builder.ts:226-231` | `DataProtection.database_security: Patch<Vec<…>>`, `DataProtectionDataLeakDetection.member: Patch<Vec<…>>` (`generated.rs:25780-25894`), so `Patch::Null` | yes |
| `{profile_name, active, policy: mergeProfilePolicy(current.policy, overrides)}` | `profiles update` (`runtime.ts:847-851`) | build the policy as a `serde_json::Value` (the merge is JSON surgery), then `Policy::parse(v, Mode::Request)` or `CreateSecurityProfileRequest::parse` | yes |
| `{profile_name, active, policy}` with `topic-guardrails.topic-list = [{action, topic: [{topic_id, topic_name, revision}]}]` | apply/revert via `assignTopicsToProfile` (`cli:src/airs/management.ts:104-181`) | `TopicArray {action: String, topic: Nullable<Vec<TopicObject>>}`, `TopicObject {topic_name, topic_id, revision: FiniteNumber, severity?}` (`generated.rs:179370`, `:179555`); `ModelProtectionItem.options: Optional<Vec<JsonValue>>` | yes |
| any JSON object from `--config` | `profiles create/update` (`runtime.ts:725`, `:819`) | `CreateSecurityProfileRequest::parse` | yes (see the limits below) |
| `?updated_by=<email>` | force deletes | `&str` | yes |

The frozen schemas are identical in both SDKs:

- `int` on `revision` and `max-inline-latency`. The Rust check is `fract() == 0`
  (`rs:src/validation.rs:1101`). `1.0` passes in both, and `1.5` fails in both, so
  `--max-inline-latency 1.5` fails locally in both.
- `datetime({offset: true})` on `last_modified_ts` and `created_ts` (s008903, s008905, s009650).
- Required `topic_name` / `profile_name` / `policy`, plus required nested members: `TopicObject`
  topic_id/topic_name/revision, `AgentProtectionItem` name/action, `DlpDataProfilePolicy`
  name/uuid, `DataLeakDetection` action.
- An explicit `null` is rejected for every optional, non-nullable field.

These are compared at `tsdk:1838-2048` and `rs:src/validation/schema_graph.json` roots.

Edges where Rust is stricter. All are local failures with zero requests, and none is reachable
with flag-built bodies:

- a body over 8 MiB, deeper than 64 levels, or with more than 100,000 nodes;
- values `serde_json` cannot hold, such as lone surrogates (D44-style);
- the reserved `$serde_json::private::Number` key.

**Number fidelity.** `FiniteNumber` keeps `1.0` as `1.0`, where TS sends `1`. A revision copied
from a server answer is re-sent exactly as received.

**Token-first ordering (CLI-level).** DESIGN §5 has every command await `provider.get_token`
first. That would send a token request on a run TS refuses with zero requests:

- an invalid `--config` body;
- a non-UUID `topics update` / `delete` id;
- the empty `updated_by` in `topics delete --force`.

For M4 writes the CLI should validate locally before the token:

- the body, with `CreateCustomTopicRequest::parse` / `CreateSecurityProfileRequest::parse` in
  `Mode::Request`;
- UUIDs, with the same 8-4-4-4-12 rule;
- blank `updated_by`.

## 5. Command → SDK call sequences

TS sequences are taken from the CLI source. The Rust column is the recommended equivalent.

**topics create** (create-or-update by name, `topics-create.ts:23-60`):
1. `validateTopic` runs locally: name ≤ 100 bytes, description ≤ 250, 2–5 examples ≤ 250 bytes,
   combined ≤ 1000 (`cli:src/core/constraints.ts`).
2. `listTopics()` = `topics.listAll()` (limit 100; TS truncates silently at 10,000).
3. `find` the first row by name.
4. `update(match.topic_id, body)` or `create(body)`.
5. Output `{topicId, topicName, revision, created}`.

Rust:
1. Run `topics().list_all(TopicListAllOptions::default())`. It must be complete (`is_complete()`,
   D15), or the command fails closed. TS would create a duplicate when the match lies past 10,000
   rows.
2. Find the first match, then call `update`, or `create`.
3. If `create` fails with an `Unknown` outcome, print an outcome-unknown line (§6). Do not
   re-POST.

**topics update `<topicId>` --config**: `topics().update(id, &parse(file))`. TS sends no lookup.

**topics delete `<topicId>`**:
- `--force`: `force_delete_with_audit(id, updated_by)`. TS prints `ui.success(result.message)`,
  which is `  ✓ undefined` when the server sends no message (`runtime.ts:1117-1118`;
  `cli:src/cli/renderer/ui.ts:90-92`).
- Otherwise: confirm, then `delete(id)`.
- TS `--force` without `--updated-by` reaches the SDK's `updatedBy is required` (exit 1, zero
  requests, after the config load).

**profiles create**: build the request, then `profiles().create`. On an error whose message
contains `'409'`, TS calls `getProfileByName(name)` and reports "Profile created" if the profile is
found, otherwise `Profile "<n>" already exists…` (`runtime.ts:756-774`). The Rust CLI has
`error.status() == Some(409)`. See §8 (P7).

**profiles update `<nameOrId>`**: `get(uuid)` or `get_by_name(name)` (highest revision), then
merge, then `update(profile_id, {profile_name: --name or current, active: --active/--no-active,
else current, else true, policy})`.

**profiles delete `<nameOrId>`**: resolve, then either `force_delete(id, updated_by)` (`--force`)
or confirm and `delete(id)`. TS checks `--updated-by` only after the lookup requests
(`runtime.ts:884-886`). Rust validates usage first (D2).

**topics apply** (`topics-apply.ts:21-53`, `management.ts:104-237`), five calls:
1. `listTopics()`, then the first match by name.
2. `getProfileTopics(profile)`: `profiles.listAll()` (no `latest`), the **first row** whose name
   matches, then the topic-list refs, then `listTopics()` again.
3. `assignTopicsToProfile`:
   - another `profiles.listAll()` and first match;
   - another `listTopics()`, building `Map(topic_id → revision)` (later rows win);
   - deep-clone the policy;
   - replace `topic-guardrails.topic-list` grouped by action. The guardrail `action` is the
     opposite of the intent, and empty groups are skipped.
4. `profiles.update(profile_id, {profile_name, active, policy})`.

That is 2 profile walks, 3 topic walks and 1 PUT. Rust can do the same with
`profiles().list_all(ProfileListAllOptions::default())` and `topics().list_all(…)`. One walk of
each is enough, reused. That is not observable except in request counts, so keep the TS request
count if parity fixtures count requests, or record it.

**topics revert** (`topics-revert.ts:14-37`):
1. Confirm (or `--force`) **before** the tenant load.
2. List topics, find the first match by name.
3. `getProfileTopics`; compute the remaining refs (guardrail `allow` if any block topic remains,
   else `block`).
4. `assignTopicsToProfile` (PUT).
5. `forceDeleteTopic(match.topic_id, undefined)`. **This always throws `updatedBy is required` in
   TS** (§8 P2).

**topics eval**: §7. **topics sample**: no SDK.

**profiles cleanup** (`profiles-cleanup.ts:67-150`):
1. Page `listProfiles({limit: 200, offset})` until `nextOffset == null`.
2. `findDuplicateProfiles`: group by name; sort by revision descending (stable); keep the first,
   remove the rest.
3. Preview.
4. Without `--force`: **non-TTY stdout means preview only, exit 0.** A TTY gets a confirm.
5. `updatedBy = --updated-by`, else `git config user.email`, else error.
6. `forceDeleteProfile(id, updatedBy)` for each removal, sequentially, continuing past failures.
   Exit 1 if any failed.

Rust:
- Use `profiles().pages(PaginationOptions{limit: 200, latest: None, ..}, …)` or `list_all` with a
  raised `CollectOptions` (D16/D40).
- Then `force_delete` per entry. Each one is a separate non-replayed DELETE. An `Unknown` outcome
  is a third status beside `ok` and `failed` (§6).
- The `git` fallback spawns `git config user.email`. Tests must sandbox `HOME` and set
  `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=<sandbox file>`.
- **The non-TTY preview exit 0 conflicts with the settled D81 rule** ("non-interactive without
  `--force` is a usage error"). The orchestrator must pick one (open question 6).

## 6. Recommended CLI handling of write outcomes (safe, no SDK change)

| SDK result | CLI behaviour |
|---|---|
| `Ok` | success line on stderr (D74), data on stdout |
| `Err`, outcome `NotSent` (`Validation` / `Configuration` / token failure / cancelled before send) | the existing §6 message, exit 1 (or 2 for usage); nothing was sent |
| `Err`, `Rejected`, `Http 401` | **option A (parity, recommended):** one CLI-level replay of the same write. The SDK has already invalidated the token (`rs:src/engine.rs:1216-1219`), so the replay fetches a fresh one, and a 401 means the request was not processed. **Option B:** no replay, plus a §12 row. A 403 cannot be replayed safely from the CLI, because the CLI cannot see `x-opa-decision` (`Error` exposes no headers). Keep 403 as a §12 difference under either option |
| `Err`, `Rejected`, other status | §6 `API error <status>`, exit 1. A 409 has no server text (G2) |
| `Err`, `Unknown` (5xx, transport, deadline or cancel after dispatch) | §6 message plus an outcome line in the style of the scan line, e.g. `Outcome unknown: the topic may have been created.` / `…updated.` / `…deleted.` Exit 1. Never re-send. Optionally run a read-only reconcile (walk and find by name or id) and report what is found, without claiming who created it |
| `Err`, `Decode` with a 2xx `status()` | the write **was applied**. Report `<thing> was <created/updated/deleted>, but the response could not be read` and exit 1. Never retry. (The SDK marks this Unknown; `status()` disambiguates it, G4) |

For multi-step commands (apply, revert, create-or-update, cleanup), say which steps completed.
Revert in particular: "profile updated; topic not deleted" or "outcome unknown". A failure after
the PUT must not read as "nothing happened".

## 7. Scan API for `topics eval`

TS (`cli:src/cli/commands/topics-eval.ts:21-101`, `cli:src/airs/scanner.ts:7-137`):

- `AirsScanService` calls `init(runtimeInitOptions(config))` (`apiEndpoint` from the tenant,
  `numRetries = airsNumRetries`).
- **Request.** One `Scanner.syncScan({profile_name}, new Content({prompt}))` per CSV row. That is
  `POST {scan}/v1/scan/sync/request` with body `{ai_profile, contents: [content]}`, no tr_id,
  session or metadata (`tsdk:10335-10366`).
- **Retries.** Re-POSTs on 500/502/503/504, network errors and per-attempt timeouts up to
  `airsNumRetries` (default 5). This is D9.
- **Concurrency.** `p-limit(--concurrency)`, default `'5'` through `Number.parseInt`. A `NaN` or
  `0` makes p-limit throw a `TypeError` (exit 1).
- **Order.** `Promise.all`, so results are in input order. **The first rejection fails the whole
  eval** (exit 1, no output) while the other in-flight scans continue.
- **`--rate N`.** `RateLimitedScanService`, a sliding 1 s window of call start times
  (`scanner.ts:94-120`):
  - `--rate 0` and `--rate abc` disable the limiter: `length >= 0` gives a `NaN` wait and no wait,
    and `length >= NaN` is false.
  - Concurrent waiters wake together and all push, so the window can be exceeded.
- **Normalization.**
  - `action === 'block'` becomes block. **Anything else becomes allow.**
  - `triggered = prompt_detected.topic_violation === true`.
  - `timeout: true` or `error: true` scans count as "not triggered". Fail-open metrics (P8).

Rust (`rs:src/airs/scan/scanner.rs:115-152`):

- **Request.** `Scanner::sync_scan(&AiProfile, &Content, Option<&SyncScanOptions>)`, one per row.
  It sends the same POST, validated against `ScanRequestSchema` before auth.
- **Retries.** **Never replayed** (`RawRequest::new`, `:143`). Outcome `Unknown` on 5xx, transport
  or decode-after-2xx; `Rejected` on 4xx. Already D9 and §6 for `runtime scan`.
- **Detection field.** `ScanResponse.prompt_detected: Optional<PromptDetected>` with
  `topic_violation: Optional<bool>` (`rs:…/generated.rs:157268`, `:164269`). Required fields
  `action, category, scan_id, report_id, timeout, error, errors` are decode failures when missing,
  as for `runtime scan`.
- **Concurrency is the CLI's job.** Use `futures_util::stream::iter(..).map(scan).buffered(n)`
  (ordered; `futures-util` is already a dependency) on the current-thread runtime. No `spawn`.
  - Create each scan's `RequestOptions::with_timeout(60 s)` **when that scan is dispatched**. The
    deadline is fixed at creation (§1.1).
  - Concurrency above `limits.max_concurrency` (32) queues inside the SDK and burns deadline.
    Either cap `--concurrency` at 32 (usage error above it) or set `limits.max_concurrency` to the
    requested value.
- **Rate is the CLI's job.** Use a `tokio::time` window of dispatch instants that admits one
  waiter at a time, so the cap holds. Recommend strict parsing (decimal integer ≥ 1 for both
  flags; D17-style usage errors).
- **Fail closed.** A scan with `timeout`/`error`, an unknown action, or a failed or Unknown POST
  must not count as "not triggered" or "allow" (the D6 rule).
  - On the first failure, stop dispatching new scans and let in-flight ones finish (or cancel
    them, which makes them Unknown).
  - Exit 1. Report how many scans were sent and how many completed, so the scan budget is
    auditable.
  - This is a §12 candidate (P8).
- **Credentials.** Eval uses the scanner plane only (`airsApiKey` / `airsApiToken`). It must never
  build the management client. TS does not build it either.

## 8. TS behaviours the port must not reproduce (each a §12 candidate, number from D93)

Suggested numbering. The orchestrator assigns the final numbers.

- **P1 (D93, scope item 1, wider than recorded).**
  - **The bypass.** `topics create`, **`topics apply` and `topics revert`** all build
    `new SdkManagementService({clientId, clientSecret, tsgId, tokenEndpoint})`
    (`topics-create.ts:87-92`, `topics-apply.ts:76-81`, `topics-revert.ts:62-67`):
    - no `apiEndpoint`, so they use `process.env.PANW_MGMT_ENDPOINT ?? DEFAULT_MGMT_ENDPOINT`
      (`tsdk:13419`);
    - no `assertManagementCredentials`, so a missing credential falls back to `PANW_MGMT_*` env
      (`tsdk:11099-11146`).
  - **The cached client.** `getOrCreateManagementClient` caches the first client for the process
    (`cli:src/airs/management.ts:549-554`).
  - **The token endpoint.** The token request does go to the tenant's `mgmtTokenEndpoint` when it
    is set.
  - **Rust.** One rule for all three commands: §3.5 credential checks and §5 tenant endpoints.
  - **Parity fixtures.** The runner clears the environment (`env_clear`,
    `crates/airs-test-harness/src/runner.rs:547`). So a TS `topics create/apply/revert` run sends
    its API calls to `https://api.apps.paloaltonetworks.com/aisec`, with a loopback-issued bearer.
    **`env_guard_violation` does not catch this**: it only rejects variables that are set to
    non-loopback values (`sandbox.rs:1117-1131`).
  - **Recommendation for the parity tests.** For every TS run, the runner should default
    `PANW_MGMT_ENDPOINT` (and `PANW_MGMT_TOKEN_ENDPOINT`, `PANW_AI_SEC_API_ENDPOINT`) to a
    loopback trap base on the fixture server, e.g. `http://127.0.0.1:<port>/ts-env-trap`, unless
    the test sets them itself.
    - The trap answers 404 to everything. 4xx is never retried by TS, so it is fast and
      deterministic.
    - Do not use a `ClosedPort` for this. TS retries network errors 5 times with random backoff
      (up to about 31 s), which is slow and timing-dependent.
  - **The `dNN_` test.** It mounts the topic fixtures under the env base for the TS run and under
    the tenant base for the Rust run, and asserts each CLI's request paths. TS paths are under
    `/ts-env…`; Rust paths are only under the tenant's `/aisec`.
- **P2 (D94, scope item 2, wider than recorded).** The root parser consumes `--output`
  everywhere, so these leaf options never take effect:
  - `--output json` on `topics create`, `apply`, `revert`, `eval` and `profiles cleanup`. All of
    them print pretty in TS (`ts-cli-shell.md` §3).
  - The deprecated `topics sample --output <path>` alias is unreachable.

  Rust honours `--output` on all five.
- **P3 (D95).** Management write retries. TS re-sends POST/PUT/DELETE up to 5 times on
  500/502/503/504, network errors and per-attempt timeouts (§1.2). That risks duplicate topics and
  profiles: a re-POST after a lost 2xx creates a second revision or returns a 409. Rust sends
  exactly one attempt and reports `Unknown` (§6). It is the write analogue of D9; D10 covers only
  reads.
- **P4 (D96, only if option B of §6 is chosen).** A 401/403 on a write: TS refreshes and replays
  once; Rust does not. The 403 part remains a difference under option A as well.
- **P5 (D97).** `topics revert` always deletes nothing.
  - **The bug.** `forceDeleteTopic(id, undefined)` → `topics.forceDelete(id, "")` →
    `updatedBy is required` (`topics-revert.ts:34`; `tsdk:11455`, `:11679-11681`). The profile
    PUT has already been applied, so TS exits 1 with the topic removed from the profile but not
    deleted.
  - **The TS test mocks it away.** `tests/unit/cli/topics-revert.spec.ts:16-21` asserts the call
    with `undefined` against a mock that resolves.
  - **Options for Rust:**
    - (a) add `--updated-by` (required with revert), then force delete;
    - (b) recommended, safest: plain `delete(id)` after the PUT. It succeeds when no other
      profile references the topic. It fails with a 409, touching nothing, when one does. Force
      delete would silently strip the topic from *other* profiles.
  - **Either way,** report partial completion when the delete fails.
- **P6 (D98).** `profiles cleanup` pagination. `if (page.nextOffset == null) break` lets
  `next_offset: 0` re-fetch offset 0 forever, and a repeated cursor loops forever with no item
  cap (`profiles-cleanup.ts:85-90`). Rust uses SDK pagination: 0 ends the walk, a repeated cursor
  is a `Pagination` error, and the bounds apply (D37/D40/D46).
- **P7 (D99).** Profile revision chosen by apply/revert.
  - **TS.** `profiles.listAll().find(name)` takes the **first-listed** row (`management.ts:110-114`,
    `:185-189`). It is not the highest revision, and the walk has no `latest`. A stale revision's
    policy can therefore be PUT back, which regresses the profile.
  - **TS topic revision pins.** They come from `Map(topic_id → revision)`, where the last listed
    row wins (`management.ts:118-119`).
  - **Rust.** Select the profile with `get_by_name` semantics (highest revision) and the pin with
    the max revision per `topic_id`. This equals TS whenever the service lists revisions in
    ascending order.
- **P8 (D100).** `profiles create` on a 409.
  - **The TS bug.** TS treats any message containing `409` as "maybe created": `getProfileByName`,
    then `Profile created: <id>`, exit 0 (`runtime.ts:756-774`). That reports a **pre-existing**
    profile as created. The comment's "AIRS may create the profile but also return 409" is
    consistent with P3: the TS SDK re-POSTs after a lost response, and the replay gets the 409.
  - **Rust.** Rust sends one POST. A 409 is therefore `Rejected` and means "already exists": print
    TS's `Profile "<n>" already exists. Use 'profiles update' to modify it.` and exit 1.
  - **Rust on `Unknown`.** Use the §6 outcome line, optionally with a read-only lookup.
  - **Why `status()`.** TS matching `'409'` against free server text is itself unreliable.
- **P9 (D101).** `topics eval` fails open on failed scans (§7). Also strict `--rate` and
  `--concurrency` parsing.
- **P10 (extend D38 or a new row).** Request-validation text.
  - **TS.** `Request body for <METHOD> <path> did not match schema: <path>: <code>; …`
    (`tsdk:10104-10113`).
  - **Rust.** The SDK reports a bare `Validation` with no field paths (G5). Either give one generic
    text, or have the CLI pre-validate the few fields it constructs and name them.
- **P11 (minor).** `topics delete --force` with a message-less response prints `✓ undefined` in
  TS. Rust should print `Topic <id> deleted.` (or the server message after `terminal_safe` and the
  `SecretSet` check).
- **P12 (D2 instance, no new row needed).** `profiles delete --force` without `--updated-by` is
  checked after the lookup requests in TS. In Rust it is a usage error before the tenant is read.
  For `topics delete --force` without `--updated-by`, TS fails at the SDK (exit 1, zero requests).
  Recommend a usage error (exit 2), which needs a row.

## 9. SDK limitations (G1–G6). None blocks M4; none needs an SDK patch

| # | Operation(s) | What is missing or different | Evidence | CLI-side handling | Safe? |
|---|---|---|---|---|---|
| G1 | all writes | no 401/403 refresh-and-replay for non-replay-safe requests. TS replays once | `rs:src/engine.rs:1216-1225` (`request.replay_safe && …`); `tsdk:9816-9823`, `:10865-10872` | option A: one CLI replay on `Http 401` + `Rejected`; 403 becomes a §12 row. Or option B: a §12 row | yes. 401 means the request was not processed |
| G2 | topic/profile delete (and any write) | 409 conflict payloads (`DeleteTopicConflict`, `DeleteProfileConflict`) and server messages cannot be reached from `Error`; only allowlisted RFC 7807 fields survive | `rs:src/error.rs:41-50`, `:101-203`; models at `generated.rs:26534`, `:26914`; no decoder uses them (grep) | generic `API error 409` (D11 already covers server text) | yes. It loses the "referenced by profiles X, Y" hint; report it upstream as an enhancement |
| G3 | all writes | a refused connection (never sent) is reported `Unknown`, because `sent` is set before `transport.send` | `rs:src/engine.rs:1164`, `:1249-1262` | already the §6 convention for scans; reuse it | yes (conservative) |
| G4 | create/update/delete | a schema failure after 2xx is `Unknown`, although the write was applied | `rs:src/engine.rs:207-213` | check `kind() == Decode` with `status()` 2xx and report "applied but unreadable" | yes |
| G5 | create/update (`--config`, built bodies) | request-validation errors carry no field path | `rs:src/engine.rs:524-552`; `validation::parse` returns a bare `Validation` | a generic text plus a §12 row (P10), or CLI pre-checks | yes |
| G6 | all bodies | request bodies are re-serialized from `Value`: keys sorted at every level; numbers keep source form | `rs:src/engine.rs:532-541`; no `preserve_order` | semantic body comparison in fixtures (a D35-style note) | yes |

Not gaps (verified):

- Every needed operation exists: topic create, update, delete and force delete; profile create,
  update, delete and force delete; list, list_all, pages, get and get_by_name; sync scan.
- UUID validation and topic `updated_by` validation match TS. Profile force delete accepts `""` in
  both.
- `DeleteTopicResponse` / `DeleteProfileResponse` accept the same string-or-object union.
- The `Patch` / `Nullable` types cover every nullable policy field the TS builder emits.

## 10. Harness and fixture notes for M4

- **Request counts depend on write retries.** Any 5xx or transport fixture on a write gives TS 6
  attempts and Rust 1 (P3), so assert each side separately. A 401 on a write gives TS
  `token, write, token, write`. Rust gives `token, write` (option B) or the TS sequence
  (option A).
- **Byte-level body comparison will fail** (G6). Parse both bodies and compare them as JSON, with
  numbers compared by value.
- **Topics create/apply/revert parity** needs the P1 trap and env base, or TS reaches production.
- **Prompts.** Confirmation prompts (topics delete, profiles delete, revert, cleanup) use the pty
  helper (`airs_test_harness::spawn_pty`). D81: interactive only with TTY stdin and stderr. TS
  decides from stdout (`cli:src/cli/confirm.ts:39`).
- **TS cleanup's git fallback.** Run it with a sandboxed `HOME` and `GIT_CONFIG_GLOBAL`. Pass
  `--updated-by` in every other test.
- **Ordering assertions** (what must not be sent):
  - revert: no topic DELETE when the profile PUT fails;
  - apply: no PUT when the topic is not found;
  - create-or-update: no POST when the walk is incomplete;
  - eval: no further scans after the first failure (Rust only).

## 11. Live-tier design for M4 (within the LIVE RULES)

### 11.1 Opt-in and budgets

| Variable | Meaning |
|---|---|
| `AIRS_RS_LIVE=1`, `AIRS_E2E_TENANT=<name>` | unchanged gate for the whole live tier (DESIGN §10) |
| `AIRS_RS_LIVE_WRITES=1` (new) | enables the M4 write flow. Without it, the live tier stays read-only as today and the summary says `writes skipped` |
| `AIRS_RS_LIVE_EVAL=1` (new) | enables the `topics eval` check. It also requires `AIRS_E2E_PROFILE`, which must equal `Prisma AIRS Harness`; anything else fails the run before it starts |
| `AIRS_RS_LIVE_EVAL_MAX_SCANS` (new, default 4, range 4–8) | scans that eval may send, counted as prompt rows × CLIs before each eval run. The eval CSV has 2 rows, so 2 CLIs × 2 = 4. TS may re-POST (D9); counting stops at the first incomplete scan, as in the existing series. This is separate from `AIRS_RS_LIVE_MAX_SCANS` (the existing 8) |
| `AIRS_RS_LIVE_CLEANUP=1` (new) | enables the `live_cleanup` sweeper test (§11.4) |

The resource budget is a hard cap of 10 creates per run. It is not overridable, and a counter is
checked before every create command. The planned flow uses 4.

### 11.2 Names and run id

- Use `airs-rs-e2e-<unix>-<pid>-<n>-<role>`, e.g.
  `airs-rs-e2e-1760700000-4242-0-topic-rs`. That is 37–45 bytes, well under the 100-byte
  topic-name limit. The digits and hyphens are safe for profile names too.
- `<unix>-<pid>-<n>` is the existing `LiveStore` run id, so the age needed for the 1-hour rule is
  in the name. Cleanup never depends on server timestamps.
- Roles: `topic-rs`, `topic-ts`, `profile-rs`, `profile-ts`.

### 11.3 Flow

The flow lives in `airs_test_harness::live::writes`, called from `tests/live.rs`. It uses the same
isolated store, cleared environment, fingerprint checks and leak checks as today, with a 90 s
timeout per run. Every step is a CLI invocation.

1. **Preflight, read-only.**
   - Rust `runtime topics list --all-versions --all --output json` and
     `runtime profiles list --all --all-versions --output json`: no planned name may exist yet. A
     collision fails the run.
   - If the tenant's `mgmtEndpoint` is set and is not the SDK default, **skip every TS step that
     uses `topics create`, `apply` or `revert`**, with a `D93` notice. TS would write to the
     default endpoint, not the tenant (P1). Never let the TS CLI write somewhere other than the
     tenant under test.
2. **Rust `topics create`** `--name <topic-rs> --description … --examples a b --output json`:
   creates `topic-rs`. Ledger entries before and after (§11.5).
3. **TS `topics create`** with `topic-ts`, unless skipped in step 1.
4. **Poll** `runtime topics get <name>` until visible (at most 5 tries, 2 s apart) to absorb
   eventual consistency.
5. **Rust `topics create` again with `topic-rs`** (the update path, own resource). Record in the
   ledger whether `topic_id` changed. This answers open question 1.
6. **Rust `topics update <topic-rs id> --config <file>`** (own resource).
7. **Rust and TS `profiles create`** `--name <profile-rs|profile-ts> --prompt-injection block`.
   A protection flag is needed, or TS fails locally (§4).
8. **Rust and TS `profiles update <name> --prompt-injection alert`** (own resources). Record
   whether `profile_id` changed per revision.
9. **`topics apply`.** Rust: `--profile <profile-rs> --name <topic-rs>`. TS: `<profile-ts>`,
   `<topic-ts>`. Then `profiles get` on each and compare the topic-guardrails shape (action, ids,
   pinned revision) semantically.
10. **Eval** (only with `AIRS_RS_LIVE_EVAL=1`):
    - `topics eval --profile "Prisma AIRS Harness" --prompts <2-row csv> --topic <topic-rs> --concurrency 1 --rate 1`
      on both CLIs.
    - Topics are never applied to the Harness profile (the rules forbid touching pre-existing
      resources). The check therefore asserts command parity and fail-closed behaviour, not
      topic efficacy.
    - Rust runs with `--output json`; TS prints pretty (D94).
11. **`topics revert`.**
    - Rust: `--profile <profile-rs> --name <topic-rs> --force`. It must remove the topic and delete
      it. Ledger: delete.
    - TS: `<profile-ts>`, `<topic-ts>`, `--force`. **Expected: exit 1 with `updatedBy is required`
      and `topic-ts` still present** (D97 evidence, asserted, not a mismatch).
12. **Teardown** (always, also on failure and panic, via `catch_unwind` like `LiveStore`). It
    deletes this run's resources, whatever their age:
    - **profiles first, then topics**, so no topic is still referenced;
    - with the **Rust CLI's plain delete on a pty**: `runtime profiles delete <id>` and
      `runtime topics delete <id>`, answering `y`. That is not `--force`: force delete would also
      strip a topic from any other referencing profile;
    - for every listed id under each planned name (all revisions).
    A 409 or a failure is reported and left for the sweeper. Teardown never escalates to force.
13. **Summary.** Check names, exit codes, agreement, counts, §12 row numbers, and
    `resourcesCreated` / `resourcesDeleted` / `resourcesLeft`. A non-zero `resourcesLeft` fails the
    run. No IDs and no names go in the summary; they are in the ledger only.

TS deletes are not used for cleanup. TS `delete` needs a TTY or `--force`, which uses the force
endpoint. A TS delete check, if wanted, is `topics delete <topic-ts id> --force --updated-by
airs-rs-e2e@example.invalid` on a run-created, unreferenced topic only.

### 11.4 Cleanup command (safe to re-run)

- **Shape.**
  `AIRS_RS_LIVE=1 AIRS_E2E_TENANT=<name> AIRS_RS_LIVE_CLEANUP=1 cargo test --test live live_cleanup -- --nocapture --test-threads=1`.
  The logic is in `airs_test_harness::live::cleanup`, and it reuses the private `LiveStore`.
- **Selection.**
  - List all topic and profile revisions with the Rust CLI (complete walks only, or abort).
  - Select names that fully match `^airs-rs-e2e-(\d{10})-\d+-\d+-(topic|profile)-(rs|ts)$` and
    whose embedded Unix time is ≥ 3600 s before now.
  - Nothing else is touched: no prefix-only match and no ledger-only id.
- **Bounds.** Delete at most 20 resources per invocation. If more than 20 match, delete the oldest
  20 and report the rest. If the listing looks wrong (a walk is incomplete), delete nothing.
- **Order and method.** Profiles first, then topics. Plain (non-force) Rust CLI deletes on a pty.
  A 409 (something else references the resource) is reported and skipped.
- **Ledger.** Append every delete with phase `cleanup`.
- **Re-running.** Already-deleted resources are no longer listed, so a re-run is idempotent.
  Resources younger than 1 h are left alone, because they may belong to a concurrent run.
- **`profiles cleanup` is never invoked**, live or by the sweeper. It is tenant-wide.

### 11.5 Ledger format (`target/live/ledger.jsonl`)

- **File handling.** Mode 0600, opened with `O_APPEND`, one JSON object per line, never rewritten.
  The harness creates `target/live/` with mode 0700 if it is missing.
- **Intent line.** Written **before** each create or delete command, with outcome `pending`, so
  a crash mid-request still leaves a trace.
- **Result line.** Written after, once the outcome is known:

```json
{"v":1,"ts":"2026-10-17T12:00:00Z","run":"1760700000-4242-0","phase":"flow","cli":"rs","op":"create","kind":"topic","name":"airs-rs-e2e-1760700000-4242-0-topic-rs","id":null,"outcome":"pending"}
{"v":1,"ts":"2026-10-17T12:00:01Z","run":"1760700000-4242-0","phase":"flow","cli":"rs","op":"create","kind":"topic","name":"airs-rs-e2e-1760700000-4242-0-topic-rs","id":"3f2c…-uuid","outcome":"ok","exit":0}
```

Field values:

- `phase`: `flow`, `teardown` or `cleanup`.
- `cli`: `rs` or `ts`.
- `op`: `create`, `update`, `delete`, `apply` or `revert`. Updates and applies to own resources
  are recorded too.
- `outcome`: `pending`, `ok`, `failed`, `unknown` (the Rust outcome-unknown line, or a TS 5xx) or
  `skipped`.
- `id`: the server UUID taken from the CLI's JSON output, or `null`.
- `note`: optional; only §12 row numbers or check names.

The ledger never holds:

- tokens or credentials;
- the tenant name, TSG or endpoints;
- prompt text or descriptions;
- profile or policy content;
- error text.

## 12. Open questions

1. Does `PUT /v1/mgmt/topic/uuid/{id}` keep `topic_id` across revisions? Does
   `PUT …/profile/uuid/{id}` keep `profile_id`?
   - TS create-or-update and apply assume `topic_id` is stable.
   - The live flow (steps 5 and 8) can record this in the ledger.
2. Does the profiles walk without `latest` return every revision, in ascending order? This decides
   whether P7 changes any live result.
3. §6 option A (CLI replays a 401 write once) or option B (§12 row)? Recommendation: A for 401,
   with a row for 403.
4. P5 revert fix: (a) `--updated-by` plus force delete, or (b) plain delete? Recommendation: (b).
5. Should eval cap `--concurrency` at 32 (usage error) or raise `Limits.max_concurrency`?
6. `profiles cleanup` without `--force` on a non-TTY: TS previews and exits 0, while the settled
   D81 rule makes it a usage error. Which one? Note that agents rely on the TS preview, according
   to its comment.
7. `topics delete --force` without `--updated-by`: a usage error (exit 2, needs a row) or the TS
   operational error (exit 1)?
