# Rust SDK for M6a (0.6): Red Team

Scope: every M6a command (all of `redteam` except `judge`), the `scm-sdk` 0.1.0 API that serves
it, and how it differs from the TypeScript SDK 0.34.0 that the frozen TS CLI (5711012) calls.
Everything here was read from source. The only commands run were `--help` invocations of the
reference build, with a scratch `HOME` and XDG directories. Nothing was built, and no network
call was made.

Citation prefixes:

- `rs:` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scm-sdk-0.1.0/src/` (the
  published crate the CLI pins). `rt:` = `rs:airs/red_team/`, `gen:` = `rs:models/generated.rs`.
- `tsdk:` = `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js`
  (0.34.0, the bundle the TS CLI really runs).
- `cli:` = `.reference/prisma-airs-cli/src/` (the TS CLI). `cmd:` = `cli:cli/commands/redteam.ts`.
- `here:` = this repository.

Companion specs: `rs-sdk-foundation.md` (engine, auth), `rs-sdk-management.md` (models,
pagination, key order), `rs-sdk-writes.md` (the write path, G1–G6, D95). This file covers only
what M6a adds.

---

## 0. Summary

- **No blocking SDK gap.** scm-sdk 0.1.0 has every operation the M6a commands call, with the TS
  method, path, query and body schema (§4). Paths and planes match the TS SDK exactly
  (`tsdk:101-124` vs `rt:*`). The only change the CLI build needs is to enable the `red-team`
  feature of the existing `scm` dependency. That feature adds models only, not dependencies
  (`rs:../Cargo.toml` `red-team = ["models"]`).
- **Nine non-blocking SDK limitations** (G1–G9, §9). Each has a safe CLI-side handling. Three
  of them are new for M6a:
  - **G7.** A 401 refresh-and-replay on a read counts against the retry budget, so
    `RequestOptions::with_retries(0)` also turns the 401 replay off (`rs:engine.rs:1216-1221`).
    TS does not count the replay (`tsdk:9816-9823`, `attempt--`). This affects the environment
    report, which TS runs with `numRetries: 0`.
  - **G8.** Secret-bearing model fields are plain `String` or `TypedMap<String>`. `Debug` is
    redacted, but `Serialize` writes plaintext, and nothing marks which fields are secret
    (§6). The CLI has to keep its own list of secret paths.
  - **G9.** SDK operation names are inconsistent: `airs.red_team.scans.*` but
    `red_team.targets.*`, `red_team.eula.*` and so on. The `--debug` log records them as they
    are (`here:src/debug.rs:483`).
- **TS behaviours the port must not copy** (§8, numbered as candidates from D133). The ones that
  matter most:
  - TS re-sends every red team write up to 5 times on 5xx, network errors and timeouts. That
    covers starting a scan (duplicate billed scans), abort, EULA accept, registry-credentials
    (mints a credential each time), the prompt CSV upload, and target probe and validate-auth
    (repeated outbound contact).
  - TS prints target and registry credentials: `targets get/create/update/probe/update-profile`
    JSON shows `auth_config` and `connection_params`, and `registry-credentials` shows the first
    20 token characters in pretty output and the whole token in JSON.
  - TS writes backups and downloads at the default file mode and overwrites existing files.
  - TS interpolates `instances` tenant IDs into the URL path without encoding.
  - `prompt-sets list` reads only the first server page. `prompts list` ignores `--offset` and
    `--all`.
- **Headline proposals.**
  - **Client.** `RedTeamClients::build` sits next to `ManagementClients` in
    `here:src/clients.rs`. It admits all three tenant red team endpoints and the token issuer
    into one `OriginPolicy`, shares the lease-recording OAuth provider, and wraps the result in
    `RedTeamClient::new(data, mgmt, broker)`.
  - **Writes.** Writes go through the existing `here:src/writes.rs::attempt`: one attempt, and a
    single replay after a 401 with outcome `Rejected` (D95). New `Change` words cover scans,
    EULA, targets, adapters and the rest.
  - **Secrets.** A pure `redteam::secrets` module redacts secret paths in every printed target,
    adapter and error-log document.
  - **Backups.** A Rust-only backup envelope, 0600 files in a 0700 directory, never overwritten.
  - **Harness.** A nested `Route::RedTeam(..)` family of stateful fixture routes (§11).
  - **Live tier.** Red team reads join `AIRS_RS_LIVE=1`. The opt-in write flow
    (`AIRS_RS_LIVE_REDTEAM_WRITES=1`) creates draft **adapters only**, at most 2 per run. The
    scan flow (`AIRS_RS_LIVE_REDTEAM_SCAN=1` + `AIRS_E2E_REDTEAM_TARGET`) has a hard budget of
    one STATIC scan with one subcategory. It polls on a bound and aborts its own scan at the
    end (§12).

---

## 1. Client construction

### 1.1 The TS side (`cli:config/client-options.ts:61-69`, `tsdk:17231-17320`)

`redTeamClientOptions(config)` passes the shared management OAuth identity (`mgmtClientId`,
`mgmtClientSecret`, `mgmtTsgId`, `mgmtTokenEndpoint` or the default) and three base URLs:

| Tenant key | TS default (`tsdk:91-93`) | Used by |
|---|---|---|
| `redTeamDataEndpoint` | `https://api.apps.paloaltonetworks.com/ai-red-teaming/data-plane` | scans, reports, custom-attack reports, categories, languages, error logs, quota, scan statistics |
| `redTeamMgmtEndpoint` | `…/ai-red-teaming/mgmt-plane` | targets, custom attacks (prompt sets, prompts, properties), EULA, instances, devices, registry credentials, adapters, dashboard overview, management languages |
| `redTeamNetworkBrokerEndpoint` | `…/ai-red-teaming/data-plane/network-broker` | channels, channel stats |

- Every endpoint is passed explicitly, so the `PANW_RED_TEAM_*` environment fallbacks
  (`tsdk:17283-17285`) never apply.
  - **Unlike M4 `topics create`, no TS red team path bypasses the tenant endpoints.** The scan
    report (`cli:cli/commands/redteam-report.ts:89-92`), backup and restore
    (`cli:cli/commands/backup.ts:8-11`) all use `redTeamClientOptions`. Parity fixtures need no
    `/ts-env` trap for red team routes.
- `numRetries` is not passed, so it is 5 (`tsdk:11105-11114`). The environment report passes
  `numRetries: 0` (`redteam-report.ts:89-92`).
- No `x-tsg-id` header is sent: `OAuthAuth.prepare` adds only `Authorization`
  (`tsdk:10854-10862`).

### 1.2 The Rust side

`scm::airs::red_team::RedTeamClient::new(data: Client, management: Endpoint, broker: Endpoint)`
(`rt:facade.rs:44-58`):

- `data.require_auth(AuthKind::OAuth)` comes first. A scanner-key client fails with
  `Configuration`.
- `data.with_tsg_header(false)` matches TS: no `x-tsg-id`.
- The management and broker clients come from `data.with_endpoint(..)`
  (`rs:engine.rs:438-445`). They share the transport, the OAuth provider, the limits, the
  session and the permits. **The data client's destination policy must already admit the
  management and broker endpoints**, otherwise construction fails with `Destination`.
- Sub-clients:
  - data plane: `scans()`, `reports()`, `custom_attack_reports()`
  - management plane: `targets()`, `custom_attacks()`, `adapters()`, `eula()`, `instances()`
  - broker: `network_broker()`
  - facade methods on the data plane: `get_languages`, `get_error_logs`,
    `get_target_profile_error_logs`, `get_quota_summary`, `get_scan_statistics`
  - facade methods on the management plane: `get_management_languages`,
    `get_dashboard_overview`
  - Each sub-client exposes `client()`, which gives raw `Client::send_json/send_text/send_bytes`
    access on that plane if a raw call is ever needed (`RawRequest::new` is never replayed;
    `rs:engine.rs:47-61`).
- SDK default constants match TS: `rs:constants.rs:632-637` (`DEFAULT_RED_TEAM_DATA_ENDPOINT`
  and the others).

Proposed `here:src/clients.rs::RedTeamClients::build(config, session, secrets, debug)`, in the
same shape as `ManagementClients::build` (`here:src/clients.rs:269-376`):

1. Admit `redTeamDataEndpoint`, `redTeamMgmtEndpoint` and `redTeamNetworkBrokerEndpoint` (or
   the SDK defaults) and `mgmtTokenEndpoint` with `admit(..)`. The D48 message applies, and the
   value is never echoed.
2. Validate `mgmtTsgId`, `mgmtClientId` and `mgmtClientSecret` exactly as for management, with
   the same messages.
3. Build the transport: `transport(&[&data, &mgmt, &broker, &issuer], ..)`, so the direct
   (unproxied) transport is used if any endpoint is loopback http.
4. Build the destination policy: `OriginPolicy::new([data, mgmt, broker, issuer])`.
5. Wrap the OAuth provider in `RecordingProvider`, so every lease enters the `SecretSet`.
6. `Client::builder(data)…authentication(Authentication::oauth(provider, false))` with
   `limits.max_retries = 5` (the TS read retry count), then
   `RedTeamClient::new(client, mgmt, broker)`.
7. A construction failure is reported as
   `AISEC_SDK_ERROR:The red team client could not be configured`.

Credential checks (§3.5: zero requests on missing `mgmt*` keys) are the same as for management.
The red team plane is the management OAuth plane, so it never sends scanner credentials.

### 1.3 Budgets

| Use | Options |
|---|---|
| single read or write | SDK default 60 s per call (`RequestOptions` absent). TS uses 60 s **per attempt**, `tsdk:10095` |
| walks (`--all`, `targets list`, which TS always walks, restore and backup lookups) | `RequestOptions::with_timeout(WALK_BUDGET = 300 s)` for the whole walk |
| environment-report source | one `WALK_BUDGET` per source, `with_retries(0)` (TS `numRetries: 0`; see G7) |
| scan wait polling | each `scans().get` call gets its own 60 s budget. Waits between polls are cancellable `tokio::time` sleeps (§2.5) |

---

## 2. Engine behaviour for red team calls

Read and write semantics are the M4 table in `rs-sdk-writes.md` §1.2: reads use
`RawRequest::read` (replay-safe), and everything else uses `RawRequest::new` (never replayed).
What is specific to red team:

- **Every non-GET red team call is a single attempt in the SDK.** That includes the calls that
  are semantically reads but are POSTs:
  - `instances().get_registry_credentials()` (`rt:instances.rs:136-149`). The SDK documents
    that it may mint credentials and is never replayed.
  - `targets().probe()`, `targets().validate_auth()` and `adapters().validate()`. The service
    contacts the customer's endpoint or runs the adapter script.
  - `get_quota()` (POST). The CLI never calls it; the report uses `get_quota_summary` (GET), as
    TS does.

  TS sends each of these up to 6 times (`tsdk:9786-9850`, `HTTP_FORCE_RETRY_STATUS_CODES`
  `tsdk:31`).
- **The CLI's one replay.** `here:src/writes.rs::attempt` re-sends a write once only when it got
  `Http 401` with `RemoteOutcome::Rejected` (D95). That is safe for every M6a write, because a
  401 means the request was not processed. It is also right for `registry-credentials`. A 403
  is never replayed.
- **The uploads are writes.** `upload_prompts_csv` builds the multipart body under the
  operation deadline before sending (`rt:custom_attacks.rs:233-264`). A local failure (size or
  validation) is `NotSent`. Once the body is dispatched, a failure follows the normal outcome
  rules.
- **Outcomes per write**:
  - `Rejected` for 3xx and 4xx: nothing was applied.
  - `Unknown` for 5xx, transport errors (including a refused connection, G3), deadlines and
    cancellations after dispatch.
  - `Decode` with a 2xx status: the write was applied but the response could not be read (G4).
  - `NotSent` for local validation, a token failure, or cancellation before dispatch.

  The `Unknown` and 2xx-`Decode` cases get the §6 outcome lines, using new `Change` words
  (§10.2).
- **Must never be duplicated:** scan create, scan abort, EULA accept. Their unknown-outcome
  handling is in §4.1 and §4.2.

---

## 3. Common API facts the CLI must know

- **Option structs are `#[non_exhaustive]` with public fields and `Default`.** Examples:
  `RedTeamScanListOptions`, `TargetListOptions`, `AdapterListOptions`, `ChannelListOptions`,
  `PromptSetListOptions`, `PromptListOptions`, `RedTeamListOptions`, `AttackListOptions`,
  `CustomAttacksReportListOptions`, `TargetOperationOptions`, `AdapterOperationOptions`.
  Outside the crate, build them with `let mut o = X::default(); o.limit = Some(n);`, not with a
  struct literal. Models are `#[non_exhaustive]` too. Build them with `X::builder()…build()` or
  `X::parse(value, scm::validation::Mode::Request)`.
- **Local validation is a bare `ErrorKind::Validation` with `NotSent` and no text.**
  - Cases:
    - UUID arguments: job, target, adapter, prompt set, prompt and channel IDs, plus the
      `adapter_uuid` filter (`rt:common.rs:55-61`).
    - Filter strings: more than 4096 bytes or a control character (`rt:common.rs:37-43`).
    - `skip` above 2^53-1 or `limit = 0` (`rt:common.rs:24-26`).
    - Path segments: empty, `.`/`..`, a backslash or control characters, including once
      percent-decoded (`rs:config.rs:121-151`).
  - TS throws `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid <field>: <value>` (`tsdk:11148-11155`),
    with field names such as `job id`, `target uuid`, `adapter uuid`, `prompt set uuid`,
    `prompt uuid` and `channel id`. That is exit 1, during the action. **The CLI must check
    UUIDs itself to produce that text** (`terminal_safe` on the echoed value). Running the check
    before the tenant is read with exit 2 is a spec choice (§13).
- **Pagination** (`rt:common.rs:62-92`, the same rule as TS `collectSkipPages`,
  `tsdk:10813-10827`):
  - `skip`/`limit` paging. The next skip is `skip + items`.
  - With `total_items` present, the walk stops at `next >= total`. Without it, a short page
    stops the walk. An empty page always stops.
  - `list_pages`, `list_items` and `list_all` exist for scans, targets, adapters, prompt sets
    and prompts. They default `limit` to 50 when the CLI passes none.
  - Channels have only the single-page `list_channels`. TS loops in the CLI
    (`cli:airs/redteam.ts:686-702`), and the Rust CLI must too, with the §7.2 guards (page
    budget, empty-page and repeated-identity stops, complete or error).
  - `CollectOptions` and the `--max 0` → 1,000,000 mapping are already in
    `here:src/pagination.rs:109-121`.
  - The TS walk silently truncates at `max` (default 10,000; `0` means unbounded). The Rust walk
    is complete or an error (D15, D46).
- **Models** (`rs-sdk-management.md` §6 applies unchanged):
  - Known keys are serialised in schema order, then extensions in sorted order (D35). Numbers
    keep their source form.
  - `Debug` prints `Type([REDACTED])` for every model, builder, option struct and container
    (for example `gen:159518-159521`).
  - Untagged unions (`ConnectionParams`, `ConnectionParamsRequest`, `AuthConfig`,
    `AuthConfigRequest`, `JobCreateRequestJobMetadata`, `PropertyNameCreateResponse`) pick the
    first variant that decodes. Every variant carries `#[serde(flatten)] extensions`, so a
    re-serialised document keeps every key. The CLI must never branch on the variant to decide
    what an object *is*.
  - Request validation mirrors the frozen Zod schemas: `.passthrough()` keeps unknown keys, and
    unions are first-match (`tsdk:3901-3974`).
- **Response bounds**: 8 MiB per response and per request (`rs:config.rs:289-290`). TS has none.

---

## 4. Command → SDK map

Columns: the TS call (CLI service method → TS SDK), the Rust call, the wire request, and the
notes that matter for the port. Planes are D (data), M (management) and B (broker). `R` means
read (SDK retries, 401 replay). `W1` means one attempt (§2), with the CLI's single 401 replay.

### 4.1 Scans (data plane, `rt:scans.rs`)

| Command | TS | Rust | Wire | Kind | Notes |
|---|---|---|---|---|---|
| `list\|ls` | `listScans` → `scans.list({status, job_type, target_id, limit, skip})` (`cli:airs/redteam.ts:483-499`); `--all` → `scans.listAll({.., limit, max})` | `scans().list(&o)` / `scans().list_all(&o, collect, walk)` with `o.limit = Some(--limit)` | `GET D/v1/scan?skip&limit&status&job_type&target_id` → `JobListResponse` | R | TS `--all` walks with page size `--limit` (default 10), so the Rust walk passes `limit` explicitly. Defaults: TS `limit` 10, `offset` 0. Filters are free strings (`common::filter`) |
| `status <jobId>` | `getScan` → `scans.get` | `scans().get(id)` | `GET D/v1/scan/{id}` → `JobResponse` | R | normalised view: `uuid,name,status,job_type,target_id,target.name,score,asr,total,completed,created_at` (`cli:airs/redteam.ts:47-61`). `JobResponse.status` is `Optional<String>` (`gen:144363`) |
| `abort <jobId>` | `scans.abort` | `scans().abort(id)` | `POST D/v1/scan/{id}/abort`, no body, no content-type → `JobAbortResponse{job_id,message}` | W1 | **never duplicated.** Unknown outcome → `Outcome unknown: the scan abort may have been applied.` and a hint to check `redteam status <jobId>`. TS has no confirmation; a D81 confirmation is a spec choice (§13) |
| `categories` | `scans.getCategories` | `scans().get_categories()` | `GET D/v1/categories` → `Vec<CategoryModel>` | R | also used by `scan` STATIC defaults (all sub-categories except `MULTI_TURN`, `cmd:79-88`) |
| `scan` | `getCategories` (STATIC without `--categories`) → `scans.create(body)` → (wait) `scans.get` every 5 s (`cli:airs/redteam.ts:647-667`) | `scans().create(&JobCreateRequest)`; poll `scans().get` | `POST D/v1/scan` body `{name, target:{uuid}, job_type, job_metadata}` → `JobResponse` | W1 + R | see below |
| `languages [--management]` | `getLanguages` / `getManagementLanguages` | `get_languages()` (D) / `get_management_languages()` (M) | `GET {D\|M}/v1/languages` → `TenantLanguagesResponse` | R | |

`scan` details:

- **Body.** `job_metadata` is built as in `cli:airs/redteam.ts:439-475`:
  - STATIC: `{categories}`
  - CUSTOM: `{custom_prompt_sets:[..]}`
  - DYNAMIC: `{stream_breadth, stream_depth[, attack_goals]}`

  Build it with `JobCreateRequest::parse(json!(…), Mode::Request)`, or with the builder and the
  matching `JobCreateRequestJobMetadataVariantN` (`gen:143337-144240`). The schema limits `name`
  to 3–255 characters and requires `target.uuid` to be a UUID (`tsdk:3891-3958`).
- **Validation fixes the port should make** (§8 rows):
  - CUSTOM without `--prompt-sets`: TS sends `job_metadata: {}`, which passes the DYNAMIC union
    arm (`tsdk:3915-3935`). Rust should make it a usage error.
  - `--categories` that is not a JSON object of string arrays: TS lets the union fall through.
    Rust should make it a usage error.
  - `--type` outside STATIC/DYNAMIC/CUSTOM: TS fails with an SDK enum error, exit 1.
- **Outcome.** The create is W1, and **it must never be duplicated.**
  - An Unknown outcome prints `Outcome unknown: the scan may have been started.` plus a hint:
    `Check \`airs-cli-rs redteam list --target <uuid>\` before starting another scan.` The
    command exits 1 and does not wait, since there is no job ID.
  - A 2xx with an unreadable body means the scan started but its ID is unknown. That gets the
    same hint.
- **Wait loop.** The TS loop has no bound. `FAILED` throws `Scan <id> failed`, exit 1. The
  terminal set is `COMPLETED`, `PARTIALLY_COMPLETE`, `FAILED` and `ABORTED`
  (`cli:airs/redteam.ts:41`).
  - A poll failure ends the TS wait with the error alone. In Rust, polls are reads with SDK
    retries. A final failure should print the §6 error and `The scan is still running on AIRS:
    job <id>` (fail closed: never reported as complete).
  - Interrupting the wait (SIGINT or SIGTERM) must not abort the scan. It prints
    `Interrupted; the scan keeps running: job <id>` (a §2.5 context) and exits 130/143.
- **Progress** is written to stdout with `\r` in TS (`cli:cli/renderer/runtime.ts:6-20`). In
  Rust it goes to stderr, quiet-suppressed (stdout is data only).

### 4.2 EULA, instances, devices, registry credentials (management plane)

| Command | TS | Rust | Wire | Kind | Notes |
|---|---|---|---|---|---|
| `eula status` | `eula.getStatus` | `eula().get_status()` | `GET M/v1/eula/status` → `EulaResponse{uuid?,is_accepted,accepted_at?,accepted_by_user_id?}` | R | |
| `eula content` | `eula.getContent` | `eula().get_content()` | `GET M/v1/eula/content` → `EulaContentResponse{content}` | R | content is server text: `terminal_safe`, but no 200-character cut (it is the document) |
| `eula accept [--force]` | `getContent`, then with `--force` `eula.accept({eula_content, accepted_at: ISO now})` (`cli:airs/redteam.ts:255-266`); without `--force` it prints the content and `Pass --force to accept.`, exit 0 (`cmd:340-357`) | `eula().get_content()` → `eula().accept(&EulaAcceptRequest)` | `POST M/v1/eula/accept` → `EulaResponse` | R + W1 | **never live; never duplicated.** D81 rule: TTY → show content, prompt; `--force` → no prompt; no TTY and no `--force` → usage error before any request (TS: exit 0). `accepted_at` uses `here:src/debug.rs:610 iso_timestamp` (the same `toISOString` shape). Unknown outcome → `Outcome unknown: the EULA may have been accepted.` and a pointer to `redteam eula status` |
| `instances create` | `instances.createInstance({tsg_id,tenant_id,app_id,region})` | `instances().create_instance(&InstanceRequest)` | `POST M/v1/instances` → `InstanceResponse` | W1 | tenant infrastructure; never live |
| `instances get <tenantId>` | `instances.getInstance` — **path interpolated without encoding** (`tsdk:16707-16714`) | `instances().get_instance(id)`: `.segment` encodes and rejects traversal | `GET M/v1/instances/{id}` → `InstanceGetResponse` | R | §8 row: TS sends `instances get ../x` to `/v1/x` |
| `instances update <tenantId>` | `updateInstance` (unencoded, `tsdk:16737`) | `update_instance(id, &InstanceRequest)` | `PUT M/v1/instances/{id}` | W1 | the body's `tenant_id` comes from the argument (`cmd:401-406`) |
| `instances delete\|rm <tenantId>` | `deleteInstance` (unencoded, `tsdk:16763`) | `delete_instance(id)` | `DELETE M/v1/instances/{id}` → `InstanceResponse` (required body) | W1 | an empty 2xx body is hydrated as `{}` and fails the schema → `Decode`, **applied** (same in TS) |
| `devices create <tenantId> --config` | `createDevices(tenantId, json)` | `create_devices(id, &DeviceRequest)` | `POST M/v1/instances/{id}/devices` → `DeviceResponse` | W1 | the body comes from a file. Use `DeviceRequest::parse(value, Mode::Request)` after the bounded §13.2 read (`here:src/files.rs:65`) |
| `devices update <tenantId> --config` | `updateDevices` | `update_devices(id, &DeviceRequest)` | `PATCH M/v1/instances/{id}/devices` | W1 | |
| `devices delete\|rm <tenantId> --serial-numbers` | `deleteDevices(tenantId, csv)` | `delete_devices(id, csv)` | `DELETE M/v1/instances/{id}/devices?serial_numbers=<csv>` | W1 | `common::filter`: at most 4096 bytes, no control characters |
| `registry-credentials` | `instances.getRegistryCredentials` | `instances().get_registry_credentials()` | `POST M/v1/registry-credentials`, no body → `RegistryCredentials{token,expiry}` | W1 | **mints a credential** (`rt:instances.rs:136`). TS retries it on 5xx. The token is a secret (§6). Never live |

### 4.3 Prompt sets, prompts, properties (`rt:custom_attacks.rs`, management plane)

| Command | TS | Rust | Wire | Kind | Notes |
|---|---|---|---|---|---|
| `prompt-sets list\|ls` | `customAttacks.listPromptSets()` **with no options: one server page**, then a client-side slice (`cli:airs/promptsets.ts:70-77`, `cmd:564-565`) | `custom_attacks().list_all_prompt_sets(&o, collect, walk)` then the same slice | `GET M/v1/custom-attack/list-custom-prompt-sets?skip&limit` → `CustomPromptSetList` | R | §8 row: TS silently misses every set after the first server page |
| `prompt-sets get <uuid>` | `getPromptSet` + `getPromptSetVersionInfo`. A version-info failure is swallowed (`cli:airs/promptsets.ts:108-127`; the upstream route returns 500) | `get_prompt_set(id)` + `get_prompt_set_version_info(id, None)`, errors swallowed | `GET M/v1/custom-attack/custom-prompt-set/{id}` and `…/{id}/version-info` | R | the version-info read keeps its SDK retries, so a 500 costs 6 attempts in both CLIs. A §12 alternative is `with_retries(0)` on that read only |
| `prompt-sets create` | `createPromptSet({name[,description]})` | `create_prompt_set(&CustomPromptSetCreateRequest)` | `POST M/v1/custom-attack/custom-prompt-set` → `CustomPromptSetResponse` | W1 | TS omits an empty `description` |
| `prompt-sets update <uuid>` | `updatePromptSet(uuid, {name?,description?})` | `update_prompt_set(id, &CustomPromptSetUpdateRequest)` | `PUT …/custom-prompt-set/{id}` | W1 | TS drops empty strings (`if (opts.name)`) |
| `prompt-sets archive <uuid> [--unarchive]` | `archivePromptSet(uuid, {archive})` | `archive_prompt_set(id, &CustomPromptSetArchiveRequest{archive})` | `PUT …/custom-prompt-set/{id}/archive` | W1 | **There is no prompt-set delete** in either SDK. That is why prompt sets are never created live (§12) |
| `prompt-sets download <uuid> [--output-file]` | `downloadTemplate` (text), then `fs.writeFileSync(path)`, **which overwrites** (`cmd:658-663`) | `download_template(id)` → `String` (`send_text`: UTF-8 lossy, BOM dropped, ≤ 8 MiB; `rs:engine.rs:1269-1287`) | `GET M/v1/custom-attack/download-template/{id}` | R | §5. Default file `<uuid>-template.csv` in the current directory. Rust refuses an existing path before the request and writes with exclusive create (`here:src/files.rs:82 write_new`) |
| `prompt-sets upload <uuid> <file>` | reads the whole file, builds `new File([..], basename, {type:'text/csv'})`; the SDK appends it as `file` named `prompts.csv` (`tsdk:16252-16266`) | `upload_prompts_csv(id, &BinaryFile)` | `POST M/v1/custom-attack/upload-custom-prompts-csv?prompt_set_uuid=<id>`, `multipart/form-data` → `BaseResponse{message,status}` | W1 | §5. Prints the server `message` (`terminal_safe`, SecretSet) |
| `prompts list\|ls <setUuid>` | `listPrompts(set, {limit})`. **`--offset` and `--all` are accepted but ignored** (`cmd:692-708`) | `list_prompts(set, &o)` with `skip`/`limit`; `--all` → `list_all_prompts` | `GET …/custom-prompt-set/{set}/list-custom-prompts?skip&limit` → `CustomPromptList` | R | §8 row |
| `prompts get <set> <prompt>` | `getPrompt` | `get_prompt(set, prompt)` | `GET …/{set}/custom-prompt/{prompt}` → `CustomPromptResponse` | R | |
| `prompts add <set> --prompt [--goal]` | `createPrompt({prompt, prompt_set_id[, goal]})` | `create_prompt(&CustomPromptCreateRequest)` | `POST …/custom-prompt-set/custom-prompt` | W1 | the set UUID goes in the body, so the CLI's own UUID check is the only local check on it |
| `prompts update <set> <prompt>` | `updatePrompt(set, prompt, {prompt?, goal?})` | `update_prompt(..)` | `PUT …/{set}/custom-prompt/{prompt}` | W1 | |
| `prompts delete\|rm <set> <prompt>` | `deletePrompt` | `delete_prompt(..)` → `Option<BaseResponse>` | `DELETE …/{set}/custom-prompt/{prompt}` (empty body allowed) | W1 | no TS confirmation; D81 is a spec choice |
| `properties list\|ls` | `getPropertyNames` → `data[]`, client-side slice | `get_property_names()` → `PropertyNamesListResponse{data?}` | `GET M/v1/custom-attack/property-names` | R | the API does not paginate |
| `properties create --name` | `createPropertyName({name})` → prints `result.message`; **an empty 2xx makes `result` undefined and throws after the write** (`cmd:806-807`; the TS schema is `.optional()` with `allowEmptyBody`) | `create_property_name(&PropertyNameCreateRequest)` → `Option<PropertyNameCreateResponse>` (an untagged union of `BaseResponse` and `PropertyNamesListResponse`) | `POST M/v1/custom-attack/property-names` | W1 | §8 row: Rust reports success on an empty body. Tenant-wide, never live |
| `properties values <name>` | `getPropertyValues(name)` | `get_property_values(name)` (segment-encoded, `filter`) | `GET M/v1/custom-attack/property-values/{name}` → `PropertyValuesResponse` | R | |
| `properties add-value --name --value` | `createPropertyValue({property_name, property_value})` | `create_property_value(&PropertyValueCreateRequest)` | `POST M/v1/custom-attack/property-values` → `BaseResponse` | W1 | tenant-wide, never live |

### 4.4 Targets (`rt:targets.rs`, management plane; error logs on the data plane)

| Command | TS | Rust | Wire | Kind | Notes |
|---|---|---|---|---|---|
| `targets list\|ls` | `targets.listAll({limit:100})` (an unbounded TS walk, truncated at 10,000), client-side slice (`cli:airs/redteam.ts:379-388`) | `targets().list_all(&o{limit:100}, collect, walk)` | `GET M/v1/target?skip&limit=100` → `TargetList` | R | the row is `uuid,name,status,target_type,active`. No secrets |
| `targets get <uuid>` | `targets.get` → `normalizeTargetDetail` (includes `authConfig` and `connectionParams`; drops `multi_turn_error_message` when `multi_turn` is false; `cli:airs/redteam.ts:93-162`) | `targets().get(id)` → `TargetResponse` | `GET M/v1/target/{id}` | R | **secret-bearing** (§6) |
| `targets create --config [--validate]` | `targets.create(json, {validate:true}?)` | `targets().create(&TargetCreateRequest::parse(v, Request)?, Some(&TargetOperationOptions{validate}), ..)` | `POST M/v1/target[?validate=true]` → `TargetResponse` | W1 | the input file holds credentials: register its secret values in the SecretSet (§6). With `--validate` the service contacts the endpoint. Never live |
| `targets update <uuid> --config [--validate]` | `targets.update` | `targets().update(id, &TargetUpdateRequest, ..)` | `PUT M/v1/target/{id}[?validate=true]` | W1 | `TargetUpdateRequest.name` is required (`gen:176969`) |
| `targets delete\|rm <uuid> [--force]` | D81-style `confirmOrAbort` (TS prompts on stdout), then `targets.delete` | `targets().delete(id)` → `Option<BaseResponse>` | `DELETE M/v1/target/{id}` | W1 | TS confirms **before** the banner. Rust keeps the D81 order |
| `targets probe --config` | `targets.probe(json)` → raw `TargetResponse` printed with `JSON.stringify` (`cmd:1110-1124`) | `targets().probe(&TargetProbeRequest)` | `POST M/v1/target/probe` | W1 (POST, contacts the endpoint) | prints `connection_params` and `auth_config`, so redact (§6). Never live |
| `targets profile <uuid>` | `getProfile` → raw JSON | `targets().get_profile(id)` → `TargetProfileResponse` | `GET M/v1/target/{id}/profile` | R | AI-generated discovery (may quote a system prompt). No credential fields in the schema |
| `targets update-profile <uuid> --config` | `updateProfile` → raw `TargetResponse` | `targets().update_profile(id, &TargetContextUpdate)` | `PUT M/v1/target/{id}/profile` | W1 | the response carries `auth_config`, so redact |
| `targets validate-auth --auth-type --config [--target-id]` | `validateAuth({auth_type, auth_config[, target_id]})` → `{validated, token_preview, expires_in}` | `targets().validate_auth(&TargetAuthValidationRequest)` | `POST M/v1/target/validate-auth` | W1 (POST; the service calls the target's token endpoint) | `token_preview` is a fragment of a live target token (§6). Never live |
| `targets metadata` | `getTargetMetadata` | `targets().get_target_metadata()` → `JsonObject` | `GET M/v1/template/target-metadata` | R | no banner in TS (`cmd:1181-1191`) |
| `targets templates` | `getTargetTemplates` | `targets().get_target_templates()` → `TargetTemplateCollection` | `GET M/v1/template/target-templates` | R | |
| `targets init <provider> [--output-file]` | usage check, then refuses an existing path (usage error), then `getTargetTemplates`, then `writeFileSync` (a TOCTOU race; mode 0644) | `get_target_templates()` + `buildTargetScaffold` port (`cmd:144-226`) | as above | R | write with `write_new` (exclusive, 0600 proposed). The scaffold holds only the placeholder `Bearer <token>` |
| `targets backup [--output-dir] [--name] [--file-format]` | `listAll` → per target `get` → `toBackupData` → `writeFileSync` (overwrites; mode 0644; `<sanitized name>.json\|yaml`) (`cli:cli/commands/backup.ts:27-104`, `cli:backup/io.ts:29-41`) | `list_all` + `get` per target | reads only | R | §6.3. Rust format, 0600/0700, never overwrite |
| `targets restore (--file\|--input-dir) [--overwrite] [--validate]` | reads envelopes (`version:"1"`, `resourceType:"redteam-target"`) → `listAll` → per file `get` + `update`, or `create` (`cli:cli/commands/restore.ts:44-130`) | `list_all`, `get`, `update`/`create` | W1 per target | | refuses TS envelopes (§6.3). One write per target; an unknown outcome stops the run? (spec choice; §13) |
| `targets error-logs <targetId> [--limit --offset --search]` | `getTargetProfileErrorLogs(id, {limit, skip, search})` | `get_target_profile_error_logs(id, &RedTeamListOptions)` | `GET D/v1/error-log/target-profile/{id}?skip&limit&search` → `ErrorLogListResponse` | R | `target_object` is a snapshot of the target and may hold credentials, so redact (§6) |

### 4.5 Adapters (`rt:adapters.rs`, management plane)

| Command | TS | Rust | Wire | Kind | Notes |
|---|---|---|---|---|---|
| `adapter list\|ls` | `adapters.list({limit, skip, search})`; `--all` → `listAll` | `adapters().list(&o)` / `list_all` | `GET M/v1/adapters?skip&limit&search` → `AdapterList` | R | no secrets in the list row |
| `adapter get <uuid>` | `adapters.get` → `normalizeAdapterDetail` (`scriptB64` and `variables[{key,value,type,isRedacted}]`) | `adapters().get(id)` → `AdapterResponse` | `GET M/v1/adapters/{id}` | R | §6: SECRET values (the server marks them with `is_redacted`) |
| `adapter create` | optional `assertChannelOnline` (`getChannel`, errors ignored), then `adapters.create(body, {validate:false}` when `--draft`) | `adapters().create(&AdapterCreateRequest, Some(&AdapterOperationOptions{validate}))` | `POST M/v1/adapters?validate=true\|false` (always sent; the default is true, `rt:adapters.rs:91-96`, `tsdk` the same) | R + W1 | `--script-file` is read and base64-encoded (`cmd:229-237`). `--variables` is a JSON array; register its SECRET values in the SecretSet. `--prompt` is required and never stored |
| `adapter update <uuid>` | read-modify-write: `get`, then a full-replacement `PUT` with redacted variables sent as `value:null` (keep stored) (`cli:airs/redteam.ts:838-871`, `preserveVariablesForUpdate` `:215-225`) | `adapters().get` + `adapters().update(id, &AdapterUpdateRequest, ..)` | `PUT M/v1/adapters/{id}?validate=…` | R + W1 | the SDK documents the rule ("missing variable keys delete them; null preserves a stored secret", `rt:adapters.rs:135`). Port `preserveVariablesForUpdate` exactly |
| `adapter delete\|rm <uuid> [--force]` | banner, confirm, `adapters.delete` | `adapters().delete(id)` → `Option<BaseResponse>` | `DELETE M/v1/adapters/{id}` | W1 | the only resource type the live write flow creates (§12) |
| `adapter validate` | `assertChannelOnline`; with `--adapter` and no `--variables` it fills the variables from the stored adapter (`cli:airs/redteam.ts:873-901`); `validated:false` → exit 1 | `adapters().validate(&AdapterValidateRequest)` | `POST M/v1/adapters/validate` → `AdapterValidateResponse{validated,stdout,stderr,traceback}` | R + W1 (runs code through the broker) | script output may echo variable values (§6). Never live |

### 4.6 Network broker (`rt:network_broker.rs`, broker plane)

| Command | TS | Rust | Wire | Kind | Notes |
|---|---|---|---|---|---|
| `network-broker channels list\|ls` | `listChannels({limit, skip, search, status[]})`; `--all` → a CLI loop with `limit` 100, stopping on a short page or at `total_items` (`cli:airs/redteam.ts:686-702`) | `network_broker().list_channels(&o)`; `--all` → a CLI loop (§3) | `GET B/v1/channels?skip&limit&search&status=…&status=…` → `ChannelListResponse{pagination?,data?}` | R | `status` repeats in caller order, with at most 252 values (`rt:network_broker.rs:42-49`) |
| `network-broker channels get <id>` | `getChannel` | `get_channel(id)` | `GET B/v1/channels/{id}` → `Channel` | R | |
| `network-broker channels create --name [--description]` | `createChannel({name[,description]})` | `create_channel(&CreateChannelRequest)` | `POST B/v1/channels` | W1 | **There is no channel delete** in either SDK. Infrastructure; never live |
| `network-broker channels update <id>` | the usage check `Specify --name and/or --description to update` comes after option parsing but before the tenant (`cmd:1656-1658`), then `updateChannel` | `update_channel(id, &UpdateChannelRequest)` | `PATCH B/v1/channels/{id}` (plain JSON, not merge-patch) | W1 | |
| `network-broker stats` | `getChannelStats` | `get_channel_stats()` → `ChannelStats` | `GET B/v1/channels/stats` | R | |

### 4.7 `report|dashboard [jobId]`

- **With a job ID** (`cmd:851-890`), all reads:
  1. `scans().get(id)`.
  2. Then, by `job_type`:
     - CUSTOM: `custom_attack_reports().get_report(id)` (`GET D/v1/custom-attacks/report/{id}`),
       plus `list_custom_attacks(id, {limit})` with `--attacks`
       (`GET D/v1/custom-attacks/job/{id}/list-custom-attacks`).
     - DYNAMIC: `reports().get_dynamic_report(id)` (`GET D/v1/report/dynamic/{id}/report`).
     - otherwise (STATIC): `reports().get_static_report(id)`
       (`GET D/v1/report/static/{id}/report`), plus `list_attacks(id, {severity, limit})` with
       `--attacks` (`GET D/v1/report/static/{id}/list-attacks`).
  3. The footnote uses `pagination.total_items` (`cli:airs/redteam.ts:592-622`).
  4. Summary placeholders `{{HIGH_RISK}}` and similar are interpolated
     (`cli:airs/redteam.ts:67-88`).
- **Without a job ID** (the environment report, `cli:reports/redteam.ts:69-366`): seven read-only
  sources, run in order. TS uses `numRetries: 0`.

  | Source | Call | Rust |
  |---|---|---|
  | Overview | `getDashboardOverview()` (M) | `get_dashboard_overview()` |
  | Statistics | `getScanStatistics()` (D) | `get_scan_statistics(&Default)` |
  | Targets | `targets.list({skip, limit:15})`, paged | `targets().list` per page |
  | Quota | `getQuotaSummary()` (**GET**, D) | `get_quota_summary()` |
  | Scans | `scans.list({skip, limit:15})`, paged | `scans().list` per page |
  | Network broker | `networkBroker.getChannelStats()` (B) | `network_broker().get_channel_stats()` |
  | Adapters | `adapters.list({skip, limit:15, include_target_count:true})`, paged | `adapters().list` per page |

  - The pages loop is report-specific: it checks identity, the total and the page budget. Port
    it as written (`:178-212`). Do not use the SDK `list_all`, whose stopping rule differs.
  - Counters use `FiniteNumber::as_u64`, and must be safe integers.
  - The file is written to a temporary file, linked, and the temporary file removed. Mode is
    0600, and an existing file is never overwritten (`cli:reports/io.ts:6-19`). This already
    matches the settled rule.
  - Rust: `with_retries(0)` per source, plus G7.
- **Scope flag:** the TS environment report's deliverable formats are `html` and `markdown`
  (`--output`). The settled "markdown is dropped" rule would make `--output markdown` a usage
  error here. The user should confirm (§13).

---

## 5. Uploads and downloads

- **Upload** (`prompt-sets upload`): `BinaryFile::new(bytes)?.with_content_type("text/csv")?`
  (`rs:models/support.rs:290-348`), then `upload_prompts_csv`.
  - The SDK always names the part `file` with `filename="prompts.csv"` (`rt:custom_attacks.rs:246-251`),
    as TS does (`tsdk:16254-16256`). TS's own basename is overridden.
  - Without `with_content_type`, the part's content type would be `application/octet-stream`.
    The CLI must set `text/csv` to match TS (Blob type, `cmd:678`).
  - There is no streaming: the body is buffered in memory (`rs:multipart.rs`). The boundary is
    `scm-sdk-<16 hex>`, chosen so it cannot occur in the payload (`:109-125`). The total body
    must be at most `max_request_bytes` (8 MiB) or the SDK returns `Limit`, NotSent.
  - Read the file with the bounded §13.2 reader (regular file, size cap, before the tenant).
    The CLI cap must sit below 8 MiB minus the multipart framing, so the user gets a fixed
    message instead of the generic `Limit`. That is a §12 row: TS has no limit.
  - The bytes are not UTF-8-checked (TS sends them as is). Keep them binary-exact.
  - A 401 replay rebuilds the form from the same `Bytes` (a cheap clone).
- **Download** (`prompt-sets download`): `send_text` buffers at most 8 MiB, decodes UTF-8 lossy
  and drops a leading BOM, as Fetch `.text()` does.
  - Write it with `write_new`: exclusive create, mode 0600, no symlink following.
  - Refuse an existing path before the tenant is read. TS overwrites (§8).
  - A response over 8 MiB is a `Limit` error and nothing is written. That is a §12 row.
- **Other files written**: `targets init` (scaffold), `targets backup` (directory),
  `report` (HTML). The settled rule applies to all of them: the current directory or the given
  path, never overwritten, and refused before any request where the path is known up front.

---

## 6. Secrets

### 6.1 Secret-bearing fields in the models (G8)

All of the following are plain `String`, `TypedMap<String>` or `TypedMap<JsonValue>`. `Debug`
is redacted on the model and its builder; `Serialize` writes plaintext.

| Where | Field(s) | Evidence |
|---|---|---|
| `RegistryCredentials` | `token` (`expiry` is not secret) | `gen:159433` |
| `HeadersAuthConfig` (auth variant 1) | `auth_header` map values | `gen:141526` |
| `BasicAuthAuthConfig` / `AuthConfigRequestVariant3` | `basic_auth_header` values | `gen:8612`, `gen:8296` |
| `OAuth2AuthConfig` / `AuthConfigRequestVariant2` | `oauth2_headers`, `oauth2_body_params` (client secret), `oauth2_inject_header` values. `oauth2_token_url` is an endpoint but may carry a query credential | `gen:154674`, `gen:8151` |
| REST, streaming and WebSocket connection params | `request_headers` values; `curl` (a pasted `curl -H 'Authorization: …'`); `request_json` may embed a key | `gen:160679`, `gen:12120` |
| `target_connection_config` native providers | OpenAI and Hugging Face `api_key`; Bedrock `access_id`, `access_secret`, `session_token`; Databricks `access_token`, `client_id`, `secret` | `gen:154979`, `gen:141609`, `gen:8909`, `gen:26096` |
| `AdapterVar` / `AdapterVarResponse` | `value` when `type == SECRET`. The server sets `is_redacted` on reads | `gen:1347`, `gen:1449` |
| `AdapterResponse.script_b64` | the adapter source. It is not a credential field, but scripts can embed tokens | `gen:718` |
| `TargetAuthValidationResponse.token_preview` | a fragment of a live target token | `gen:171408` |
| `ErrorLog.target_object`, `extra_info` | a target snapshot: everything above | `gen:32418` |
| `TargetProbeRequest`, `TargetCreateRequest`, `TargetUpdateRequest`, `TargetAuthValidationRequest` inputs | everything above, read from `--config` files | `gen:173124`, `gen:171810`, `gen:176969`, `gen:171240` |

Not verifiable from source: whether the AIRS API masks `auth_config` and connection credentials
on `GET /v1/target/{id}`. `TargetResponse.secret_version` and `adapter_secret_version`
(`gen:176260`) suggest secrets are stored separately, but nothing in either SDK says the read
masks them. The port must assume **plaintext can arrive**.

### 6.2 Proposed output policy (each difference is a §12 candidate; flagged for the user)

A pure `redteam::secrets::redact(&mut serde_json::Value, Shape)` replaces each secret-path value
with `"[REDACTED]"`. A shape names the document: target, probe result, error log or adapter. The
function keeps keys, so the shape stays visible, and leaves `null` and empty values alone. It
runs on every printed document in every format before rendering. The CLI also registers every
secret value it reads from an input file (`--config`, `--variables`) in the invocation's
`SecretSet`. Server text that echoes one (request IDs, error codes, adapter stdout, upload
messages) is then masked by the existing D11/D47 rules.

| Command | TS prints | Proposed |
|---|---|---|
| `targets get/create/update`, `update-profile`, `probe` | JSON: `authConfig`/`auth_config` and `connectionParams` in full. Pretty: `connectionParams` key/values (`cli:cli/renderer/redteam.ts:462-504`) | redact the secret paths in every format |
| `targets error-logs` | `targetObject` in JSON | redact the target paths inside `target_object` |
| `targets validate-auth` | `Token: <token_preview>` | withhold: `Token: (received)` when present, plus `expires_in` (choice: print the preview) |
| `registry-credentials` | pretty: the first 20 characters + `...` (`cli:cli/renderer/redteam.ts:792`); JSON: the full token | **choice.** Recommended: pretty and table print `Token: (withheld; use --output json)` and the expiry. JSON prints the token: the command's purpose, data on stdout. Alternative: always print it (TS parity in JSON) |
| `adapter get/create/update` | variables with server-redacted SECRET values (`(redacted)`); JSON includes `scriptB64` | SECRET values always `[REDACTED]`, even when the server sent a value. VAR values printed. `scriptB64` printed (choice: withhold unless `--output json`) |
| `adapter validate` | stdout, stderr, traceback verbatim | `terminal_safe` + SecretSet masking (the input SECRET values) |
| `prompts`, `prompt-sets`, `properties`, `scan`, `report` | prompt text, goals, names | not secrets. Printed with `terminal_safe` |
| environment report | aggregates only (`cli:reports/redteam.ts:22-23`, limitations list) | the same allowlist |
| `--debug` | n/a (the TS debug log is not ported) | status and headers only (§2.9). Bodies, including multipart, are never logged |

### 6.3 Backups (`targets backup`/`restore`)

- **Format (Rust-only; §12 row; TS envelopes refused):**

  ```json
  {
    "format": "airs-cli-rs.redteam-target",
    "version": 1,
    "exportedAt": "…",
    "source": {"uuid": "…", "name": "…"},
    "target": { …the create-request projection… }
  }
  ```

  - The `target` projection is the TS `toBackupData` set and order
    (`cli:cli/commands/backup.ts:27-46`), with nulls stripped.
  - Files are `<sanitized-name>.json` and `<sanitized-name>-<uuid8>.json` when two names
    sanitise to the same file. TS lets the later file overwrite the earlier one silently.
  - The default directory is `./airs-backup/targets/` (`cli:backup/io.ts:22-25`).
  - The directory is created 0700 and files 0600 with exclusive create. Every planned file name
    is checked before the first write. With `--name`, the single path is checked before any
    request.
  - `--file-format yaml` is a usage error (YAML is dropped), or the flag is dropped entirely
    (choice).
- **Secrets in backups (choice).**
  - (A, recommended) Write what the API returns, with no redaction: a restore must be able to
    recreate the target. Secrecy comes from file mode 0600, the 0700 directory, never-overwrite
    and a stderr notice: `Backup files contain target connection settings and credentials
    (mode 0600).`
  - (B) Withhold secret paths (`[REDACTED]`). Restore of such a file then refuses `create`, and
    with `--overwrite` sends the update without those keys. That is only safe if the API keeps
    an omitted credential, which is unverified.
  - In both cases restore must **refuse to send** a value that equals the CLI's own
    `"[REDACTED]"` marker (or a server mask, if the live read shows one). That would store a
    broken credential.
- **Restore** recognises a TS envelope (`version: "1"` + `resourceType: "redteam-target"`)
  and refuses it, naming `docs/MIGRATION.md`. Each target costs one W1 write. An unknown outcome
  is reported per target. The summary must not count an unknown-outcome target as created or
  updated.

---

## 7. Error mapping (what M6a adds to §6)

- Every SDK error maps through `here:src/error.rs` (§6). There is no new kind. The red team API
  is FastAPI: a 422 carries `HTTPValidationError{detail:[{loc,msg,type}]}` (`gen` model
  `HTTPValidationError`). The SDK keeps none of it (G2), so the message is
  `<error_type>:API error 422`. TS prints the extracted server text (D11
  already covers this).
- Local request-schema failures (`--config` bodies, `--name` length) are a bare `Validation`
  with no field path (G5). TS prints
  `Request body for POST /v1/target did not match schema: <path>: <code>`
  (`tsdk:10101-10113`). Choose between fixed CLI pre-checks for the flag-built bodies (scan name
  3–255, UUIDs, `--categories` shape) and a generic message for file-built bodies (an existing
  D-row pattern).
- `Decode` with a 2xx status on a write gives `Outcome: the <thing> was <done>, but the response
  could not be read.` For scan create that adds the "check `redteam list`" hint.
- An `Unknown` write gives `Outcome unknown: the <thing> may have been <done>.` (§10.2 words).
- An adapter validate with `validated:false` exits 1 after printing the result (TS
  `process.exitCode = 1`, `cmd:1573`).
- A scan wait that ends at `FAILED`: `Scan <id> failed`, exit 1 (TS message,
  `cli:airs/redteam.ts:660`).

---

## 8. TS behaviours the port must not copy (§12 candidates, numbering from D133)

| # | Behaviour | TS | Proposed Rust | Reason |
|---|---|---|---|---|
| D133 (or D95 extended) | red team write retries | every POST/PUT/PATCH/DELETE re-sent up to 5 times on 500/502/503/504, network errors and per-attempt timeouts, plus once after 401/403 (`tsdk:9786-9850`, `:10854-10871`). That covers scan create (duplicate billed scans), abort, EULA accept, registry-credentials (several minted tokens), CSV upload (duplicate prompts), and probe, validate-auth and adapter validate (repeated outbound calls) | one attempt; 401 replayed once; outcome lines | safety |
| D134 | `instances get/update/delete` path | tenant ID interpolated raw (`tsdk:16707`, `:16737`, `:16763`): `../x` reaches `/v1/x` | one encoded segment; traversal refused locally | safety |
| D135 | credentials in target outputs | printed in JSON and pretty | redacted paths (§6.2) | secret safety |
| D136 | registry token | pretty 20-character prefix; JSON full | per the user's choice (§6.2) | secret safety |
| D137 | `validate-auth` token preview | printed | withheld (choice) | secret safety |
| D138 | adapter SECRET values / validate output | as the server sent them | always redacted; SecretSet masking of script output | secret safety |
| D139 | `prompt-sets download` | overwrites; mode 0644; unbounded | exclusive create, 0600, refused before the request; 8 MiB cap | file safety |
| D140 | `targets backup` | overwrites; 0644; name collisions lose files; YAML | Rust format, 0600/0700, never overwrite, collision suffix, JSON only | file and secret safety |
| D141 | `targets restore` of TS files | n/a (TS format) | refused with a clear message | settled decision |
| D142 | `prompt-sets list` | first server page only | full walk, complete or error | correctness |
| D143 | `prompts list --offset/--all` | ignored | honoured | correctness |
| D144 | `properties create` with an empty 2xx | TypeError after the write applied → exit 1 | success | correctness |
| D145 | `eula accept` without `--force` and without a TTY | prints the content, exit 0 | usage error (D81); with a TTY, prompts | D81 / settled decision |
| D146 | scan validation | CUSTOM without `--prompt-sets` sends `{}`; non-object `--categories` falls through the union; a bad `--type` is an SDK error | usage errors before the tenant is read | correctness |
| D147 | scan wait failures and interruption | unbounded loop; a poll error ends it with no job hint; progress on stdout | progress on stderr; failure and interruption name the job and say it is still running | streams; fail closed |
| D148 | upload size | unbounded | refused above the cap before sending | bounded inputs |
| D149 | `targets init` write | TOCTOU between the existence check and `writeFileSync` | exclusive create | file safety |
| (choice) | confirmations | only `targets delete`, `adapter delete` (and `eula accept --force`) | D81 on those; optionally also `abort`, `prompts delete`, `instances delete`, `devices delete` | safety vs script compatibility |

---

## 9. SDK limitations (none blocks M6a; none needs an SDK patch)

| # | Operation(s) | What is missing or different | Evidence | CLI-side handling | Safe? |
|---|---|---|---|---|---|
| G1 | all writes | no 401/403 refresh-and-replay for non-replay-safe requests | `rs:engine.rs:1216-1221` (`request.replay_safe && …`) | the existing `writes::attempt` (D95) | yes |
| G2 | all | server error bodies (FastAPI `detail`) unreachable; only allowlisted RFC 7807 fields | `rs:error.rs` (see `rs-sdk-writes.md` G2) | D11 messages | yes |
| G3 | all writes | a refused connection is reported `Unknown` | `rs:engine.rs:1164`, `:1249-1257` | conservative wording (existing) | yes |
| G4 | create/update/delete, `instances delete` | a 2xx with an unreadable body is `Unknown`/`Decode` although applied | `rs:engine.rs:702-734` | "applied but unreadable" line | yes |
| G5 | `--config` bodies, scan name | `Validation` without a field path | `rs:engine.rs:524-552` | pre-checks plus a generic message; an SDK enhancement request | yes |
| G6 | printed raw JSON (`probe`, `profile`, `update-profile`, `metadata`, `templates`, `devices *`) | key order: known schema order, then sorted extensions and sorted nested `JsonValue` | `rs:models/support.rs:7-9` | D35/D60 semantic comparison | yes |
| G7 | reads with `with_retries(0)` (environment report) | the 401 refresh-and-replay consumes the retry budget, so with 0 retries there is no 401 replay. TS replays on 401 without counting (`attempt--`) | `rs:engine.rs:1216-1221` vs `tsdk:9816-9823` | on `Http 401` + `Rejected` for a report read, re-read once (safe: a read); or accept a §12 row | yes |
| G8 | target/adapter/registry models | secret fields untyped (plain `String`); `Serialize` plaintext; no secret-path metadata | §6.1 table | CLI-owned secret-path redactor + SecretSet registration | yes |
| G9 | `--debug` operation names | `airs.red_team.scans.*`, `airs.red_team.reports.*` but `red_team.targets.*`, `red_team.custom_attacks.*`, `red_team.adapters.*`, `red_team.eula.*`, `red_team.network_broker.*` | `rt:scans.rs:57`, `rt:targets.rs:80`, `rt:eula.rs:26`, `rt:network_broker.rs:57` | print as is; pin in the debug tests; upstream naming nit | yes |

Not gaps (verified):

- Every M6a operation exists: §4.
- The TS SDK has no prompt-set delete and no channel delete either (`tsdk:15965-16566`,
  `:16885-17035`), so their absence is not a parity issue.
- The `validate` query defaults (targets: omitted unless set; adapters: always sent, default
  `true`) match TS.
- The channel `status` repeat encoding matches. `include_all_if_empty` is never set by the CLI.
- `delete` bodies are optional for targets, adapters and prompts (`send_optional_contract`), and
  required for instances and devices, as in TS.
- Request unions are `.passthrough()` in both SDKs, so `custom_prompt_sets` survives the DYNAMIC
  union arm.

---

## 10. Proposed CLI module layout

### 10.1 Files

```
src/clients.rs                 + RedTeamClients::build (§1.2)
src/redteam/mod.rs             shared: client accessors, UUID/argument checks with the TS texts,
                               terminal-status set, list-flag reuse (pagination.rs)
src/redteam/body.rs            pure builders: the scan JobCreateRequest (+ default STATIC
                               categories without MULTI_TURN), the adapter RMW body and
                               preserveVariablesForUpdate, the target init scaffold, the
                               restore payload (prepareTargetPayload + routing defaults)
src/redteam/secrets.rs         pure: secret-path redaction per document shape; extraction of
                               input-file secrets into the SecretSet
src/redteam/views.rs           TS normalisers (normalizeJob, normalizeTargetDetail incl. the
                               multi_turn sanitiser, normalizeAdapterDetail, normalizeChannel,
                               normalizeErrorLog, report summaries + placeholder interpolation)
                               and the pretty/table layouts (renderer/redteam.ts)
src/redteam/backup.rs          the Rust backup envelope, its strict reader, TS-envelope
                               recognition, file naming and collision rule
src/report/mod.rs, html.rs     the environment-report model and self-contained HTML renderer
                               (environment-render.ts), shared with the M6d/M6e/M6f reports
src/commands/redteam_scan.rs   list, status, abort, categories, languages, scan (+ wait loop,
                               interruption contexts)
src/commands/redteam_report.rs report|dashboard (job report; environment report and its
                               seven sources, page loop, findings, health, strict exit)
src/commands/redteam_targets.rs targets list/get/create/update/delete/probe/profile/
                               update-profile/validate-auth/metadata/init/templates/error-logs
src/commands/redteam_backup.rs targets backup/restore
src/commands/redteam_custom.rs prompt-sets, prompts, properties (download/upload included)
src/commands/redteam_adapters.rs adapter list/get/create/update/delete/validate
src/commands/redteam_infra.rs  eula, instances, devices, registry-credentials, network-broker
```

### 10.2 Changes to existing modules

- `cli.rs`: the commands, aliases (`ls`, `rm`, `dashboard`) and help.
- `commands/mod.rs`: planning, usage validation before the tenant, and format and debug
  policies.
- `writes.rs`: new `Change` variants, each giving `(thing, done)` for the outcome lines:
  - `("scan", "started")`, `("scan abort", "applied")`, `("EULA", "accepted")`
  - `("target", created/updated/deleted)`, `("adapter", …)`, `("prompt set", …)`,
    `("prompt", …)`
  - `("property", "created")`, `("property value", "created")`, `("instance", …)`,
    `("devices", …)`, `("channel", …)`
  - `("registry credential", "issued")`, `("prompts upload", "applied")`,
    `("target profile", "updated")`
- `input.rs`: the confirmation texts (`Delete red team target <uuid>?`,
  `Delete adapter <uuid>?`, the EULA prompt).
- `signals.rs`: the scan-wait and scan-create contexts.
- `files.rs`: the CSV upload cap, `write_new` for downloads, init and backups, and a 0700
  directory helper.

No new dependency. Base64 for `--script-file` reuses the encoder already in
`here:src/error.rs:241` (`base64(.., STANDARD_ALPHABET)`).

---

## 11. Fixture-server routes the loopback harness needs

All routes sit under the sandbox endpoints `/redteam/data`, `/redteam/mgmt` and
`/redteam/broker` (`crates/airs-test-harness/src/sandbox.rs:78-80`), with bearer checks as for
management (`AuthIdentity::Bearer`). Propose one nested family, `Route::RedTeam(Rt)`, so the
flat `Route` enum stays readable, and keep per-route `Planned` overrides (5xx, 401 once, held,
disconnect, delay) through the existing `once`/`defaults` maps.

### 11.1 Stateful datasets (seeded per test)

| Dataset | Routes (method path → behaviour) |
|---|---|
| scans (data) | `GET /v1/scan` (skip/limit/total, filters); `POST /v1/scan` → job `QUEUED` (id `fixtures::uuid(900+n)`; scripted status series per job name marker, as the M5 async rules do: `QUEUED` → `RUNNING` (completed/total) → `COMPLETED`/`PARTIALLY_COMPLETE`/`FAILED`/`ABORTED`); `GET /v1/scan/{id}`; `POST /v1/scan/{id}/abort` (sets `ABORTED`, counts calls); `GET /v1/categories` |
| reports (data) | `GET /v1/report/static/{id}/report`, `…/list-attacks` (severity filter, total_items); `GET /v1/report/dynamic/{id}/report`; `GET /v1/custom-attacks/report/{id}`; `GET /v1/custom-attacks/job/{id}/list-custom-attacks` |
| data misc | `GET /v1/languages`; `GET /v1/error-log/target-profile/{id}` (`target_object` with `FAKE-TARGET-SECRET-*` markers); `GET /v1/metering/quota`; `GET /v1/dashboard/scan-statistics`; a `POST /v1/metering/quota` trap (must never be called) |
| targets (mgmt) | `GET/POST /v1/target` (records `validate` query); `GET/PUT/DELETE /v1/target/{id}`; `POST /v1/target/probe`; `GET/PUT /v1/target/{id}/profile`; `POST /v1/target/validate-auth` (returns a `token_preview` marker); `GET /v1/template/target-metadata`, `…/target-templates`. Targets carry secret markers in `auth_config` and `connection_params` (headers, `api_key`, `access_secret`, `curl`) so tests assert that redaction leaves none on stdout or stderr, in the debug log, or in summaries |
| custom attacks (mgmt) | prompt sets list/get/create/update/archive; `…/version-info` (500 by default: the upstream behaviour); `GET /v1/custom-attack/download-template/{id}` (CSV text, optional BOM, oversize mode); `POST /v1/custom-attack/upload-custom-prompts-csv?prompt_set_uuid=` (parses multipart; records part name, filename, content type and byte length, never the content); prompts list/get/create/update/delete; property names get/post (empty-2xx mode); property values get/post |
| adapters (mgmt) | `GET/POST /v1/adapters` (records `validate`); `GET/PUT/DELETE /v1/adapters/{id}` (stores SECRET variables, returns them `is_redacted:true, value:null`; PUT applies the full-replacement and null-preserves rule so RMW tests are meaningful); `POST /v1/adapters/validate` |
| EULA, instances, devices (mgmt) | `GET /v1/eula/status`, `/content`; `POST /v1/eula/accept` (state flips, counts calls); `POST/GET/PUT/DELETE /v1/instances[/{id}]` (records the raw request path so D134 is provable); `POST/PATCH/DELETE /v1/instances/{id}/devices`; `POST /v1/registry-credentials` (`FAKE-REGISTRY-TOKEN-<n>`, counts mints); `GET /v1/dashboard/overview`; `GET /v1/languages` (management variant, distinguishable payload) |
| broker | `GET/POST /v1/channels` (multi-`status`, pagination); `GET/PATCH /v1/channels/{id}`; `GET /v1/channels/stats` |

### 11.2 Harness notes

- **Parity request counts.** Any 5xx or transport fixture on a red team write gives TS 6
  attempts and Rust 1. Assert each side separately, as in M4. A 401 on a write gives TS and
  Rust (D95) the same `token, write, token, write`.
- **The runner's path guards.** Add `--config`, `--output-file`, `--output-dir`, `--input-dir`,
  `--file`, `--script-file` and the positional `upload` file to `PATH_FLAGS` and to the
  absolute-path checks. TS `targets backup` without `--output-dir` writes to
  `./airs-backup/targets` in the working directory, so the TS run's working directory must be
  inside the sandbox `tmp/`.
- **The ledger of mints and starts.** Tests for "never duplicated" assert the server's counters
  (scans created, aborts, EULA accepts, registry mints, uploads) after held, 5xx, disconnect and
  SIGINT cases.

---

## 12. Live-tier design for M6a (within the LIVE RULES)

### 12.1 Read comparison (`AIRS_RS_LIVE=1 AIRS_E2E_TENANT`; both CLIs; TS sandboxed as today)

| Check | Both CLIs? | Compared |
|---|---|---|
| `redteam categories`, `languages`, `languages --management`, `eula status`, `network-broker stats` | yes | normalised JSON, or pretty with the banner stripped |
| `redteam list --limit 5 --output json` | yes | ID set and statuses (a race window is tolerated: compare only IDs present in both) |
| `targets list --output json`, `prompt-sets list --output json`, `properties list`, `adapter list --output json`, `network-broker channels list --output json` | yes | the projections (no secret fields in these rows) |
| `prompt-sets get <first>`, `prompts list <first set> --limit 5` | yes | projections (prompt text compared in memory, never written to summaries) |
| `targets get <first>` | **Rust only** | the Rust JSON is checked in memory: every §6.2 secret path is `[REDACTED]` or absent. The output is discarded. TS would print credentials, so it is not run |
| `status <id>` and `report <id>` for the newest `COMPLETED` job (from `list --status COMPLETED --limit 1`), when one exists | yes | normalised status and report fields |
| `report --output-file <run tmp>/rt.html` | yes | each side's file is mode 0600; the source statuses are equal; HTML is not compared byte-wise (timestamps) |
| `targets backup --output-dir <run tmp>/backup` | **Rust only** | dir 0700, files 0600, file count equals the `targets list` count, every file parses as the Rust envelope. The directory is removed when the flow ends (also on failure and panic) and never copied into summaries |

Not run live: `registry-credentials` (a mint), `eula content` (large, but harmless; optional),
`adapter get` (scripts may embed secrets), `targets error-logs` (target snapshots),
`targets profile`.

### 12.2 Write flow (`AIRS_RS_LIVE_REDTEAM_WRITES=1`, on top of the read opt-ins)

- **The only resource type: draft adapters.** They are fully deletable (`DELETE /v1/adapters/{id}`),
  not tenant-wide, and with `validate=false` and no channel the service does not run the script.
  *Assumption to confirm with the user:* a draft create contacts nothing external. If it does,
  the write flow has no resource type and is dropped.
- **Plan.** At most 2 resources per run, under the cap of 10.
  - Rust `adapter create --draft --name airs-rs-e2e-<unix>-<pid>-1-rs-adapter`, with a fixed
    placeholder script (`--script-b64` of `# airs-rs-e2e placeholder\n`), `--prompt e2e`, one
    `VAR` variable and no SECRET variable.
  - TS creates `…-2-ts-adapter` the same way.
  - Each adapter is read by `adapter get` on both CLIs. Equal projections are required;
    `scriptB64` is compared but never printed.
  - `adapter list --search airs-rs-e2e-<unix>-<pid>` on both.
  - Each CLI runs `adapter update <own> --draft --description e2e-updated --prompt e2e`. The RMW
    must keep the VAR variable.
  - Each CLI deletes its own adapter with `adapter delete --force`.
  - Teardown (on success, failure and panic) deletes anything left, with the Rust CLI.
- **Ledger.** `target/live/ledger.jsonl` gets the new `Kind::Adapter` (and `Kind::Scan` for
  §12.3). There is a pending line before every create and delete and a result line after.
- **Sweeper.** `AIRS_RS_LIVE_CLEANUP=1` adds adapters: it deletes only prefixed names whose
  embedded Unix time is at least 1 h old, via `adapter delete --force` on the Rust CLI.
- **Excluded, with reasons:**
  - targets: create/probe/validate-auth make AIRS contact an external endpoint, and targets
    carry credentials. Update-profile changes an existing target.
  - prompt sets: archive only; neither SDK can delete one.
  - prompts: would need a run-owned prompt set (impossible, see above) or would change an
    existing one.
  - properties: tenant-wide, no delete.
  - instances, devices, channels (no delete), registry credentials (mints): infrastructure.
  - EULA accept: never live.
  - adapter validate: runs code through an ONLINE broker channel.
  - abort of any scan the run did not start.

### 12.3 Scan flow (`AIRS_RS_LIVE_REDTEAM_SCAN=1` + `AIRS_E2E_REDTEAM_TARGET=<uuid>`; never by default; the orchestrator asks the user first)

1. **Gates before any request.**
   - Both variables are set and the target value is a UUID; otherwise refuse with a fixed
     message.
   - The scan budget is a constant 1 with no override. The ledger holds no scan entry for this
     run.
   - `AIRS_RS_LIVE=1 AIRS_E2E_TENANT` are set.
2. **Smallest kind.** Run Rust `redteam categories --output json` and take the first category
   and its first sub-category that is not `MULTI_TURN`. Then run Rust
   `redteam scan --target <uuid> --name airs-rs-e2e-<run>-scan --type STATIC --categories '{"<cat>":["<sub>"]}' --no-wait`.
   The ledger gets its pending line first. TS never starts a scan.
3. **Unknown outcome.** The ledger records `unknown`. The flow then finds the job, read-only,
   with `redteam list --target <uuid> --limit 20 --output json`, matching the run's exact name.
   It records the ID if found. It never starts a second scan.
4. **Bounded polling.** Rust `redteam status <id>` every 30 s, until a terminal status or the
   deadline `AIRS_RS_LIVE_REDTEAM_SCAN_MINUTES` (default 20, max 60). On a terminal status, TS
   `status <id>` is compared. On `COMPLETED`/`PARTIALLY_COMPLETE`, both CLIs run
   `report <id>` and `report <id> --attacks --limit 5`.
5. **End.** If the job is not terminal at the deadline, or the flow fails or panics, run Rust
   `redteam abort <id> --force` (ledger), then one `status` read expecting `ABORTED`. The flow
   only ever aborts the ID from its own create output, or the name match in step 3. A match
   needs both the run's own name and the given target.

### 12.4 Loopback self-tests (fixture server; `LiveTarget::loopback`)

- **Opt-in refusals before any request:**
  - writes without `AIRS_RS_LIVE_REDTEAM_WRITES`
  - scan without `AIRS_RS_LIVE_REDTEAM_SCAN`
  - scan without `AIRS_E2E_REDTEAM_TARGET`, or with a non-UUID value
  - a second scan in one run (budget)

  Each is asserted by an empty request log.
- **Prefix and ledger.** `Ledger::record` refuses a non-prefixed name. After a flow, every
  create in the ledger has a delete with outcome `ok`. The fixture's adapter set equals its seed
  set.
- **The sweeper** deletes only prefixed adapters older than 1 h. A fresh prefixed adapter and a
  foreign adapter survive.
- **Abort safety.** A seeded foreign `RUNNING` job (same target, different name) is never
  aborted: no `POST …/{foreign}/abort` in the log. The run's own job is aborted after a
  simulated deadline. An unknown-outcome create is resolved by the name match without a second
  `POST /v1/scan`.
- **No writes outside the sandbox.** The backup and report land under the run tmp and are
  removed. The runner's file-change check passes. The TS `targets get`/`backup` are never
  invoked (the request log has no TS `GET /v1/target/{id}`).
- **Secret markers** from the fixture targets never appear in summaries, the ledger or stdout
  copies.

---

## 13. Choices to record and confirm (for the spec)

1. **The registry token** in pretty/table output: withheld (recommended) or TS prefix; JSON:
   full token (recommended) or withheld.
2. **Target credential redaction** in every printed format (recommended), with no reveal flag.
3. **`validate-auth`** token preview: withheld (recommended) or printed.
4. **Adapter `scriptB64`:** printed (TS parity, recommended) or withheld outside JSON.
5. **Backup secrets:** (A) as returned, 0600 + notice (recommended) or (B) withheld. Restore
   refuses redaction markers either way.
6. **`--file-format`** on backup: dropped flag or `yaml` usage error (YAML dropped).
7. **Confirmations:** D81 only where TS confirms (`targets delete`, `adapter delete`,
   `eula accept`), or also `abort`, `prompts delete`, `instances delete` and `devices delete`.
8. **`redteam report --output markdown`:** dropped (per the settled format rule) or kept as a
   deliverable.
9. **UUID and flag checks** before the tenant (exit 2) or TS-timed (exit 1 with the TS text).
10. **Restore after an unknown-outcome write:** continue with the next target (recommended,
    reported per target) or stop.
11. **`prompt-sets get` version-info:** keep the SDK read retries (6 attempts against a route
    that always returns 500) or `with_retries(0)` on that read only (a §12 row).
12. **Live:** confirm that draft adapter create contacts nothing external. Confirm the scan
    flow's smallest kind (one STATIC sub-category) and its 20-minute default deadline.
