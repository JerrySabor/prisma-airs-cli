# Rust SDK for M6d (0.9): Runtime extras

Scope: the M6d commands of the frozen TS CLI (5711012):

- `runtime api-keys list|ls`, `create`, `regenerate <apiKeyId>`, `delete|rm <apiKeyName>`;
- `runtime customer-apps list|ls`, `get <appName>`, `update <appId>`, `delete|rm <appName>`,
  `consumption [appName]`;
- `runtime deployment-profiles list|ls`;
- `runtime scan-logs query`;
- `runtime dashboard applications|application|application-violations|top-applications|violations-trend|apps-list`;
- `runtime sessions chart|list|ls|get|transaction|scan-content`;
- `runtime report` (the daily environment report);
- `runtime profiles backup [profile]` and `runtime profiles restore <file>`.

For each one, this file gives the `scm-sdk` 0.1.1 API that serves it and compares it with the HTTP
calls the TS CLI makes through its SDK 0.34.0. It ends with the gaps, the proposed module layout, the
fixture routes and the live-tier design. The proposed §12 rows start at D204 and the gaps at G26.

Method. Everything was read from source, with two exceptions, both in the session scratchpad:

- `--help` and argument-error runs of the reference build (`node dist/cli/index.js`, `env -i` with a
  scratch `HOME` and scratch XDG directories, no tenant);
- a read-only Python walk of the SDK's frozen schema graph (`rs:validation/schema_graph.json` and
  `semantics.json`) from every M6d root, listing `ZodDefault` nodes, enums and the unknown-field mode
  of every object.

No Rust was built, no request left the machine, and no tenant or credential file was read.

Citation prefixes:

- `rs:` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scm-sdk-0.1.1/src/`;
  `mg:` = `rs:airs/management/`; `gen:` = `rs:models/generated.rs`.
- `tsdk:` = `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js` (0.34.0).
- `cli:` = `.reference/prisma-airs-cli/src/`; `cmd:` = `cli:cli/commands/runtime.ts`;
  `dash:` = `cli:cli/commands/runtime-dashboard.ts`; `rep:` = `cli:cli/commands/runtime-report.ts`;
  `xfer:` = `cli:cli/commands/profile-transfer.ts`; `svc:` = `cli:airs/management.ts`;
  `bk:` = `cli:backup/runtime-profiles.ts`; `pol:` = `cli:backup/runtime-policy.ts`;
  `rr:` = `cli:reports/runtime.ts`; `rh:` = `cli:reports/render.ts`;
  `rnd:` = `cli:cli/renderer/runtime.ts`; `view:` = `cli:cli/renderer/view.ts`.
- `spec:` = `.reference/prisma-airs-cli/tests/`; `docs:` = `.reference/prisma-airs-cli/docs-site/docs/`;
  `here:` = this repository.

Companion specs: `rs-sdk-foundation.md`, `rs-sdk-management.md`, `rs-sdk-writes.md` (G1–G6, D95),
`rs-sdk-redteam.md` (G7–G10), `rs-sdk-dlp.md` (G11–G17), `rs-sdk-model-security.md` (G18–G24).
G25 (scm-sdk 0.2.0 not adopted) is DESIGN §15. This file covers only what M6d adds.

---

## 0. Summary

- **Every M6d API command has an SDK operation**, and the paths, methods, query names and schemas
  match the TS SDK one for one (`mg:*.rs` against `tsdk:11685-12649`). Nothing new is needed in
  `Cargo.toml`: the `management` feature (already enabled, `here:Cargo.toml:46`) covers api-keys,
  customer-apps, deployment profiles, scan logs and the dashboard, and it pulls in `dlp`, which
  profile restore needs for the DLP data-profile inventory. No dependency or lock-file change.
- **Two management planes.** The dashboard and sessions reads (and `customer-apps consumption`, and
  four of the seven report sources) go to the tenant's `mgmtDashboardEndpoint` (TS default
  `https://api.apps.paloaltonetworks.com/aisec`, `cli:config/client-options.ts:27`, `:48`) with an
  `x-tsg-id` header. Everything else goes to `mgmtEndpoint` without that header. The Rust
  `ManagementClient` models exactly this (`mg:mod.rs:59-75`), but `ManagementClients::build`
  (`here:src/clients.rs:280-330`) admits only `mgmtEndpoint` and the issuer, so the dashboard origin
  (and, for restore, `dlpEndpoint`) must be admitted into the same destination policy first (G30).
- **Schema defaults (G10) reach M6d output in three places** (G27, the schema walk):
  `SecurityProfileListResponse.ai_profiles` defaults to `[]`, and `CustomTopic.examples` and
  `CustomTopicListResponse.custom_topics` default to `[]`. They matter for `runtime report` (an
  absent profile array becomes a "complete, zero profiles" inventory and an attention finding), for
  `profiles backup` (a topic without `examples` is stored with `examples: []` and sent back by
  restore) and for restore's planning and verification. Every M6d response schema is `passthrough`,
  and no M6d response has an enum except the DLP data profiles, which D178 already covers.
  **Recommendation: `RequestOptions::without_response_defaults()` on every M6d call**, through one
  options helper, as M6c did.
- **One attempt per write holds by construction.** `api_keys().create`, `regenerate`, `delete`,
  `customer_apps().update`, `delete`, and the restore's `profiles().create`, `update` and
  `topics().create` are all `RawRequest::new(..)`, so `replay_safe = false` (`rs:engine.rs:49-61`,
  `:1173-1236`). `writes::attempt` adds the D95 single 401 replay. The TS SDK re-sends the api-keys
  and customer-apps writes up to 5 times on 500/502/503/504 and network errors, and once after a 401
  or 403 (`tsdk:9786-9848`). The TS restore passes `numRetries: 0` (`xfer:118`), which still
  replays once after a 401 or 403.
- **The API key value is a plain `Optional<String>`** (`gen:4645-4646`; only the struct's `Debug` is
  redacted, `gen:4965-4967`) (G26). The CLI must register it in the `SecretSet` the moment the
  create or regenerate answer is decoded. **Proposed channel (D204): `--key-file <new path>` is
  required on `create` and `regenerate`.** The key is written there at 0600 through a reservation
  made before the request, and is never printed. TS prints the full key on stdout.
- **`scan-logs query` sends nothing in TS.** It is a stub that prints a fixed error and exits 1
  (`cmd:1076-1096`). The SDK's `ScanLogsClient::query` (`mg:inventory.rs:93-135`) exists but is not
  used. The port is the stub.
- **Gaps (§9).** No SDK patch is needed, and no M6d behaviour is skipped. G26–G35 are each either a
  safe CLI-side workaround or a naming/shape note.

---

## 1. Client construction

### 1.1 The TS side

- **Default retries.** `createMgmtService()` (`cmd:175-178`) → `new SdkManagementService(managementClientOptions(config))`
  → `getOrCreateManagementClient(opts)` (`svc:549-555`, cached per process). It is used by api-keys,
  customer-apps (`consumption` included) and deployment-profiles, with `numRetries` defaulting to 5.
- **Dashboard, sessions and report.** These call `getOrCreateManagementClient({...managementClientOptions(config), numRetries: 0})`
  (`dash:130-134`, `rep:57-61`).
- **Profile transfer.** It uses `new ManagementClient({...managementClientOptions(config), numRetries: 0})`
  (`xfer:118`). Its API subset is `profiles.list/create/update`, `topics.list/create` and
  `dlp.dataProfiles.list` (`bk:14-18`).
- **Options.** `managementClientOptions` (`cli:config/client-options.ts:44-51`) passes `clientId`,
  `clientSecret`, `tsgId`, `tokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`, `apiEndpoint: mgmtEndpoint ?? DEFAULT_MGMT_ENDPOINT`,
  `dashboardEndpoint: mgmtDashboardEndpoint ?? DEFAULT_MGMT_DASHBOARD_ENDPOINT` and
  `dlpEndpoint: dlpEndpoint ?? DEFAULT_DLP_ENDPOINT`.
- **`new ManagementClient`** (`tsdk:13407-13447`) builds one `OAuthAuth` and the sub-clients. The
  `DashboardClient` gets `baseUrl: dashboardEndpoint ?? baseUrl` and the header `x-tsg-id: <tsg>`
  (`tsdk:12238-12247`). No other sub-client sends `x-tsg-id`.
- **Env fallback.** The `PANW_MGMT_ENDPOINT` fallback (`tsdk:13419`) never applies, because the CLI
  always passes `apiEndpoint`.

### 1.2 The Rust side (proposed changes to `clients::ManagementClients`)

Keep one OAuth identity (one token) per invocation, as TS does.

1. **Admit the endpoints** with `admit` and the D48 messages:
   - `mgmtEndpoint` (as today);
   - for dashboard users, `admit("mgmtDashboardEndpoint", config.effective_str("mgmtDashboardEndpoint"), DEFAULT_MGMT_ENDPOINT)`.
     The TS default dashboard constant is the same URL as `DEFAULT_MGMT_ENDPOINT`. The key is already
     known (`here:src/tenant/config.rs:20`, `:82`), and the fixture tenant sets it to `<base>/dashboard`
     (`here:crates/airs-test-harness/src/sandbox.rs:75`);
   - for `profiles restore` only, `admit("dlpEndpoint", …, DEFAULT_DLP_ENDPOINT)`.
2. **`oauth_parts(config, &issuer, &[mgmt, dashboard?, dlp?], …)`.** One `OriginPolicy` admits all of
   them. This uses the management OAuth plane only, so the scanner key is never sent.
3. **Build** `ManagementClient::new(client)?`, then `.with_dashboard_endpoint(dashboard)?` when the
   command reads the dashboard (`mg:mod.rs:72-75`). The SDK refuses an endpoint the policy did not
   admit (`rs:engine.rs:438-444`).
   - The dashboard client keeps `with_tsg_header(true)` (`mg:mod.rs:61`), which matches TS.
   - The main client has the header off (`Authentication::oauth(provider, false)`, `here:src/clients.rs:313-318`).
4. **DLP for restore.** `management.dlp(dlp_endpoint)?` (`mg:mod.rs:131-134`) gives a `scm::dlp::DlpClient`
   on the same identity, so there is no second token. It inherits the base client's `Limits`, so the
   transfer client is built with `max_response_bytes = DLP_MAX_RESPONSE_BYTES` (32 MiB,
   `here:src/clients.rs:522`), as `DlpClients` is (G31).
5. **Retries.** `Limits::max_retries = MANAGEMENT_RETRIES` (5). It applies to replay-safe reads only.
   Per-call options decide the rest (§1.3).

Proposed shape: `ManagementClients::build_for(config, session, secrets, debug, Planes { dashboard: bool, dlp: bool })`.
The existing `build` becomes `build_for(.., Planes::default())`, so the policy of existing commands
does not widen.

### 1.3 Options and budgets

| Call | `RequestOptions` |
|---|---|
| api-keys, customer-apps and deployment-profiles single reads | `with_timeout(SINGLE_REQUEST_BUDGET)?.without_response_defaults()` (SDK read retries, D10 as today) |
| `--all` walks (api-keys, customer-apps), the consumption bucket walk | one `with_timeout(WALK_BUDGET)?.without_response_defaults()` per walk |
| dashboard and sessions reads | `with_timeout(SINGLE_REQUEST_BUDGET)?.with_retries(0)?.without_response_defaults()` plus **one CLI re-read after an `Http` 401 or 403 `Rejected`** (G7; TS `numRetries: 0` with its free 401/403 replay, `tsdk:9811-9819`); `sessions list --all`: one `WALK_BUDGET` deadline shared by every page, each page `with_retries(0)` |
| `runtime report` sources | §15.17's rule: each source one `with_timeout(300 s).with_retries(0)` budget, and the G7 re-read inside it |
| `profiles backup` and restore reads | SDK read retries (as D175 chose for the DLP backup), `WALK_BUDGET` per inventory, `.without_response_defaults()` |
| every write | `with_timeout(SINGLE_REQUEST_BUDGET)?.without_response_defaults()` through `writes::attempt`/`writes::send` (one attempt; D95 401 replay once, a 403 never) |

Never use `with_retries(0)` on a write: it is meaningless there, and it also drops the 401 refresh (G7).
For writes the refresh is `writes::attempt`'s job.

---

## 2. Engine behaviour for M6d calls

| Call shape | SDK path | SDK replay | Outcome on failure |
|---|---|---|---|
| GET reads (`api_keys().list`, `customer_apps().list/get`, `deployment_profiles().list`, every `dashboard()` method) | `RawRequest::read(..)` → `send_contract` | up to `max_retries` on transport errors and 429/502/503/504 (`Retry-After` ≤ `max_retry_delay`), plus one 401/403 refresh, unless `with_retries(0)` | read errors per DESIGN §6 |
| `api_keys().create` (`POST /v1/mgmt/apikey`), `regenerate` (`POST /v1/mgmt/apikey/regenerate/{id}`) | `RawRequest::new(POST)` → `send_model(body, req_schema, "ApiKeySchema")` (`mg:api_keys.rs:46-61`, `:138-155`) | never | `NotSent` before dispatch; `Rejected` for 3xx/4xx; `Unknown` for 5xx, post-dispatch transport errors and cancels (G3); a 2xx that does not decode carries the status (G4) |
| `api_keys().delete` (`DELETE /v1/mgmt/apikey/delete/{name}?updated_by=`) | `RawRequest::new(DELETE)` → `send_contract("ApiKeyDeleteResponseSchema")` (`mg:api_keys.rs:121-137`) | never | as above |
| `customer_apps().update` (`PUT /v1/mgmt/customerapp?customer_app_id=`) | `send_model(body: &CustomerApp, "CustomerAppSchema", "CustomerAppSchema")` (`mg:customer_apps.rs:116-133`) | never | as above |
| `customer_apps().delete` (`DELETE /v1/mgmt/customerapp?app_name=&updated_by=`) | `send_contract("CustomerAppDeleteResponseSchema")` (`mg:customer_apps.rs:134-152`) | never | as above |
| restore: `profiles().create` (`POST /v1/mgmt/profile`), `update` (`PUT /v1/mgmt/profile/uuid/{id}`), `topics().create` (`POST /v1/mgmt/topic`) | `send_model` (`mg:profiles.rs:79-94`, `:206-223`; `mg:topics.rs:64-79`) | never | as above |
| `scan_logs().query` | `RawRequest::new(POST)` (`mg:inventory.rs:121-133`) | never | not used (§4.4) |

**Request bodies** are validated in `Mode::Request` (request defaults inserted, then re-serialised with
sorted keys, D35). The CLI parses every `--config` file with `<Model>::parse(value, Mode::Request)` during
planning, so a schema failure is an error before the tenant. Unknown keys survive in `extensions`
(every M6d object schema is `passthrough`).

| Body (`gen:` line) | Required | Notes |
|---|---|---|
| `ApiKeyCreateRequest` (4974) | `auth_code cust_app revoked created_by api_key_name rotation_time_interval` (integer), `rotation_time_unit` | `tsdk:2075-2087`. TS sends `JSON.parse(--config)` whole (`cmd:229-230`) |
| `ApiKeyRegenerateRequest` | `rotation_time_interval` (integer), `rotation_time_unit` | the CLI builds `{rotation_time_interval, rotation_time_unit, updated_by?}` from flags (`cmd:247-252`) |
| `CustomerApp` as the update body (18337) | `app_name cloud_provider environment` | the SDK reuses the response type as the request (TS likewise, `tsdk:11950-11962`); the body is the whole `--config` object |
| `CreateSecurityProfileRequest`, `CreateCustomTopicRequest` (13168) | `profile_name` (+ `policy` as TS sends it) / `topic_name` | restore builds them (`bk:634-639`, `:661-665`) |

**Responses** (`gen:`; all `passthrough`, unknown keys in `extensions`):

- `ApiKey` (4604) requires `api_key_id api_key_last8 auth_code expiration revoked`. The optional
  fields include `api_key` (the secret), `api_key_name`, `creation_ts`, `customer_appId` and
  `rotation_*`.
- `ApiKeyListResponse` (5462): `api_keys: Optional<Vec<ApiKey>>`, `next_offset`.
- `ApiKeyDeleteResponse` (5282) and `CustomerAppDeleteResponse` (18528) are unions with a string
  variant (TS turns a string into `{message}`), an object variant and `Unknown(JsonValue)` (G35).
  The customer-app union also has a `CustomerApp` arm.
- `CustomerApp` (18337): `customer_appId` (Rust field `customer_app_id`), `app_name`, `cloud_provider`,
  `environment` and options.
- `CustomerAppWithKeys` (18803) requires `customer_appId tsg_id app_name cloud_provider environment`;
  `api_keys_dp_info` is a list of `{api_key_name, dp_name, auth_code}`.
- `DeploymentProfilesResponse` (27714) requires `deployment_profiles` (each with `dp_name`, `auth_code`)
  and `status`.
- Dashboard (`gen:19744-22487`):
  - `DashboardApplicationsOverview` has `items` required, `pagination` optional;
  - `DashboardSessionsOverview` has `items` and `pagination` required, and `pagination` has
    `limit`, `skip` and `total_items`, all optional;
  - `DashboardSessionsChart` has `bucket_size_seconds` and `buckets` required;
  - `DashboardSession` has `application`, `id`, `session_actions` and `pagination`;
  - `DashboardScanContent` has `scan_contents: Nullable<{prompt, response}>`.

  These are the same required sets as TS (`tsdk:2150-2300`). A missing `items` fails both CLIs as a
  decode error (the TS comment says "A missing body/array is unavailable data, not a successful
  empty inventory", `tsdk:2205`).
- `Patch` and `Nullable` keep unset, `null` and a value apart. The dashboard views need that:
  `session_stats: null` is not `{}`, and `scan_contents: null` is valid.

---

## 3. Common API facts the CLI must know

- **Two pagination dialects.**
  - *Offset cursor* (api-keys, customer-apps, profiles, topics): `offset` and `limit` are sent, and the
    page carries `next_offset`. `next_offset` of 0 or absent ends the walk; a non-integral value is a
    decode error (`mg:mod.rs:163-176`). The SDK's `pages`/`list_all` detect a repeated cursor and an
    empty non-final page (`rs:pagination.rs:346-391`), but not a repeated row (G28). TS
    `paginate`/`collectAll` (`tsdk:10790-10813`) checks repeated cursors only.
  - *Skip/limit with total* (dashboard `applicationsoverview` and `sessionsoverview`): `limit` and
    `offset` are sent, and `pagination.{skip, limit, total_items}` comes back.
- **The TSG path segment.** `apikeys/tsg/{tsg}` and `customerapp/tsg/{tsg}` come from the OAuth
  context (`mg:mod.rs:137-142`), not from the CLI.
- **Identifiers in paths.** `api-keys delete <name>` and `regenerate <id>` use `.segment(..)`
  (`mg:api_keys.rs:130`, `:147`). That refuses `.`, `..`, `\`, control characters and recursively
  encoded traversal, and encodes `/` (`rs:config.rs:121-151`). TS uses `encodeURIComponent`
  (`tsdk:11802`, `:11833`). The CLI checks this in planning (G29, D213).
- **Identifiers in queries.** `customer-apps get|delete <appName>` and `update <appId>`, and every
  dashboard identity (`appid`, `appname`, `session_id`, `app_id`, `app_name`, `scan_id`), are query
  parameters. They are exact text with no segment rule. Dashboard identities must be non-blank under
  ECMAScript trim (`nonblank`, `mg:mod.rs:143-162`, the TS zod `nonBlank`).
- **The dashboard query schemas are request-validated with defaults** (`sem:` `s000075` … `s000095`:
  30, `days`, 1, `day`, 25, 0), the same as TS `appQuerySchema`, `timeRangeSchema` and so on
  (`tsdk:12201-12224`).
  - `applications_overview` is checked by hand: interval ∈ {1, 7, 30, 60}, unit ∈ {`days`, `day`,
    `hour`}, `limit` ≥ 1 (`mg:dashboard.rs:315-342`).
  - The CLI's own checks run first (TS order, §4.5), so a local SDK `Validation` cannot occur.
- **Debug operation names** are fixed (G34):
  - `airs.management.api_keys.{list,create,regenerate,delete}`;
  - `airs.management.customer_apps.{list,get,update,delete}`;
  - `airs.management.deployment_profiles.list`;
  - `airs.management.dashboard.{applications_overview,application,application_violation_breakdown,top_applications_violations,applications_violations_trend,apps_list,sessions_chart,sessions_overview,session,session_transaction,scan_content}`;
  - `airs.management.profiles.{list,create,update}` and `airs.management.topics.{list,create}`;
  - the DLP data-profile list name of M6b.

---

## 4. Command → SDK map

"TS" gives the options as `--help` lists them. The `ls`/`rm` aliases come from
`applyListDeleteAliases` (`cli:cli/program.ts:42-52`). `--limit`/`--offset`/`--all`/`--max` on
api-keys and customer-apps lists come from `registerListFlags` with the offset dialect (`--limit`
default 100, `--max` default 10000, `cli:cli/pagination.ts:20-31`).

### 4.1 `runtime api-keys` (`mgmtEndpoint`; `mg:api_keys.rs`; TS `tsdk:11685-11841`, `svc:312-356`)

| Command (TS options) | Rust | Wire | Notes |
|---|---|---|---|
| `list\|ls` (`--limit` 100, `--offset` 0, `--all`, `--max` 10000, `--output`) | `api_keys().list(PaginationOptions{offset, limit, latest: None})`; `--all`: `list_all(ApiKeyListAllOptions{limit, collect})` with `pagination::collect_options(max)`, the profiles `list_all` pattern (`here:src/commands/profiles.rs:53-80`), plus the G28 row check on `api_key_id` | `GET /v1/mgmt/apikeys/tsg/{tsg}?offset&limit` | `resolveListParams`: `--all` with an explicit `--offset` is a usage error (TS text `--all cannot be combined with --offset`). Status lines as profiles (D12, D14). Projection: §6.1 |
| `create --config <path>` | `api_keys().create(&ApiKeyCreateRequest)` (one attempt) | `POST /v1/mgmt/apikey` | TS: banner, then `API key created: <id>` and `API Key Detail` with the full `Key` (`rnd:362-381`). Rust: D204 (§7) |
| `regenerate <apiKeyId> --interval <n> --unit <unit> [--updated-by <email>]` | `api_keys().regenerate(id, &ApiKeyRegenerateRequest)` (one attempt) | `POST /v1/mgmt/apikey/regenerate/{id}` | `--interval`: TS `parseInt` (`90abc` → 90; `abc` → NaN, then a zod error after the tenant); Rust: a decimal integer, as a usage error (D17). `--unit` is free text in TS (help says hours, days, months); Rust keeps free text and requires it non-blank. A **new id and a new secret; the old key stops working** (`docs:cli/runtime/api-keys.md`): D206 confirmation plus D204 |
| `delete\|rm <apiKeyName> --updated-by <email>` | `api_keys().delete(name, updated_by)` (one attempt) | `DELETE /v1/mgmt/apikey/delete/{name}?updated_by=` | TS prints `ui.success(result.message)`, which is `✓ undefined` when the answer has no message (`cmd:262-275`). Rust: D206 confirmation, D208 text, G29 segment rule |

### 4.2 `runtime customer-apps` (`mgmtEndpoint`, `consumption` on the dashboard; `mg:customer_apps.rs`; TS `tsdk:11843-11991`, `svc:358-503`)

| Command (TS options) | Rust | Wire | Notes |
|---|---|---|---|
| `list\|ls` (as api-keys) | `customer_apps().list(..)`; `--all`: `list_all(CustomerAppListAllOptions{..})` plus the G28 check on `customer_appId` | `GET /v1/mgmt/customerapp/tsg/{tsg}?offset&limit` | Projection `{id, name, description, raw}` (`svc:358-365`); D207 for `id` |
| `get <appName>` (`--output`) | `customer_apps().get(name)` | `GET /v1/mgmt/customerapp?app_name=` | Pretty: `Customer App Detail:` with `Data` = `JSON.stringify(raw, null, 2).slice(0, 500)` (`rnd:421-436`), printed through `terminal_safe_lines` |
| `update <appId> --config <path>` | `customer_apps().update(id, &CustomerApp)` (one attempt) | `PUT /v1/mgmt/customerapp?customer_app_id=` | A replace (PUT of the whole record). There is no read by id (G30). D206 confirmation. Rust parses the config in planning (`CustomerApp::parse(.., Mode::Request)`). Prints `Customer app updated: <app_name>` and the detail (`cmd:497-503`) |
| `delete\|rm <appName> --updated-by <email>` | `customer_apps().delete(name, updated_by)` (one attempt) | `DELETE /v1/mgmt/customerapp?app_name=&updated_by=` | The service also deletes the app's keys (`tsdk:11976`: `customer app and associated keys successfully deleted`). D206 confirmation; D208 text |
| `consumption [appName]` (`--time-interval` "30", `--output`) | §4.2.1 | dashboard | `--time-interval` must be 7, 30 or 60 (TS text `--time-interval must be 7, 30, or 60 (the API rejects other values)`, a usage error before the tenant in Rust; TS checks after `resolveOutput`, which loads the tenant) |

#### 4.2.1 `consumption` mechanics (TS `svc:401-503`, `cmd:523-578`)

1. **Bucket list.** `applications_overview({limit: 100, offset})` with **no time window**, so the
   defaults (30 days) apply (`svc:417-421`). The loop:
   - pages with `offset += items.length`;
   - stops at an empty page, a short page or `offset ≥ total_items`;
   - keeps items whose `id` and `name` are strings.

   TS has no page cap and no repeated-row check. Rust: the shared `src/walk.rs` loop (§5) with key
   `[id, name]` and the D40 bounds (D211).
2. **Single-app mode.**
   - Find buckets with `name == appName`. TS takes the first; Rust refuses two or more buckets with
     different ids (D211), with a message that names the count and suggests nothing secret.
   - Not found: TS's message names up to five bucket names (`svc:446-459`). That is server text
     through `terminal_safe` and the `SecretSet`.
   - Then `dashboard().application(&DashboardAppQuery{app_id, app_name, time_interval: Some(n), time_unit: None})`
     and `application_violation_breakdown(..)`. TS runs these with `Promise.all`; Rust runs them in
     sequence (choice 14). The unit defaults to `days` in the schema.
3. **All-apps mode.** For each bucket, the same two reads, rendered per app. An app's failure is
   `ui.error("[<name>] <message>")` and the loop continues (`cmd:563-572`). Rust: the §6 message,
   exit 1 at the end when any app failed.
4. **Projection** (`svc:476-503`). TS fills `sessions.total`, `sessions.violating`, every detector
   count and `totalViolating` with `?? 0`. Rust prints what the server sent (D209).
5. **Output** (`rnd:438-551`).
   - pretty: per app a header `<appName> (<appId>)`, then `Monitoring since`, `Source`, `Cloud` and
     `Profiles`, the `Token consumption:`, `Sessions:` and `Detectors (…)` sections and the firing
     table.
   - table and json: one row per detector, with the app fields repeated. **In all-apps mode TS prints
     one JSON array per app**, so stdout is several JSON documents, and an app without detectors
     prints `[]`. Rust prints one array for the whole run, and an app without detectors gets one row
     with `detector: null` (D210).

### 4.3 `runtime deployment-profiles list|ls` (`mg:inventory.rs:5-38`; TS `tsdk:12028-12066`)

| Command | Rust | Wire | Notes |
|---|---|---|---|
| `list\|ls` (`--unactivated`, `--output`) | `deployment_profiles().list(DeploymentProfileListOptions{unactivated: flag.then_some(true)})` | `GET /v1/mgmt/deploymentprofiles[?unactivated=true]` | TS sends the parameter only when the flag is given (`tsdk:12053-12056`). Projection `{name: dp_name ?? profile_name ?? name ?? '', status, authCode: auth_code}` (`rnd:553-592`); json emits `{raw}` objects (`svc:509-514`, `view:` `asRecord`): parity. `auth_code` is printed (choice 6) |

### 4.4 `runtime scan-logs query` (TS stub)

TS options: `--interval <n>` and `--unit <unit>` (required by commander), `--filter` "all", `--limit` "50",
`--offset` "0", `--output`, and the hidden deprecated `--page`/`--page-size` (`cmd:1080-1088`). The
action ignores all of them. It prints
`Legacy scan-logs retrieval is broken and under refactor. Empty results do not mean no activity. Use airs-cli runtime sessions list --interval 1 --unit day --output json, or airs-cli runtime report.`
with `ui.error` and exit 1 (`cmd:1089-1095`). Because `query` is a read-command name, the root
`preAction` resolves `--output` first, which loads the tenant. Without a tenant that run fails with
`No tenant selected` (exit 1, observed).

Rust, at TS parity:

- the arguments are checked first (missing `--interval`/`--unit`: exit 2, D1; `--output` validity, D2/D50);
- then the tenant is loaded (the read resolves `defaultOutput`);
- then the same line on stderr, exit 1, **no request** (`scm::airs::management::ScanLogsClient` is
  unused);
- debug policy `none` (nothing is sent);
- the message keeps `airs-cli` (choice 7).

### 4.5 `runtime dashboard` and `runtime sessions` (dashboard endpoint; `mg:dashboard.rs`; TS `dash:`, `tsdk:12238-12649`)

The shared rules of every subcommand (`dash:103-153`):

- **Arguments before the tenant**, with the TS texts. `integer(v, name, min)` is
  `/^\d+$/` + safe + ≥ min, else `<name> must be a safe integer >= <min>`. `text` must be non-blank
  under JS trim, else `<name> is required`.
- **The `--unit` vocabulary is checked at parse time**, before every hook:
  `Unsupported --unit. Supported units: <list>. For one week, use --interval 7 --unit days.` (exit 2).
- **Output.**
  - TS `--output` allows `pretty`, `json` and `yaml`, and pretty is the 2-space JSON text
    (`dash:136-139`).
  - Rust: `pretty` (the same JSON text), `json` and `table`, with `yaml` per D50.
  - Table is added (D212): a JSON object prints as `Key │ Value` rows of its top-level fields,
    values compact JSON as TS `emitDetail` does (`view:84-101`). `sessions list` prints a row table
    with the columns `application_name`, `application_id`, `session_id`, `violation_status` and
    `last_session_activity`.
- **Failures.** TS prints only
  `Dashboard operation failed[ (HTTP <s>)]. Check credentials, query options, and any output destination. No existing file is overwritten.`
  (exit 1, `dash:144-151`). It never prints a server body (spec "sanitizes upstream failures",
  `spec:integration/cli/runtime-dashboard.spec.ts:294-311`). Rust ports this line verbatim for
  every post-planning failure (choice 11). A tenant, config or credential error is still its own
  message, as in TS.
- **Retries.** No retry; the G7 re-read (§1.3).
- **`--debug`.** Status and headers only, and never the URL query: `debug::sanitize_url` drops it
  (`here:src/debug.rs:584-596`). Session and scan-content bodies never reach the log. TS also omits
  those bodies (`omitDebugBody`, `tsdk:12390-12480`).

| Command | TS defaults and checks | Rust | Wire (dashboard base) |
|---|---|---|---|
| `dashboard applications` (`--interval` 1, `--unit` day ∈ {day, days, hour}, `--limit` 25, `--offset` 0) | interval ∈ {1,7,30,60} and unit ∈ {day, days, hour}, else `Application overview supports interval 1/7/30/60 and unit day/days/hour`; limit ≥ 1, offset ≥ 0 | `dashboard().applications_overview(&DashboardApplicationsOverviewQuery{..})` | `GET /v1/mgmt/dashboard/v2/apps/applicationsoverview?time_interval&time_unit&limit&offset` |
| `dashboard application`, `application-violations` (`--app-id`, `--app-name` required; `--interval` 30; `--unit` days ∈ {days}) | interval ∈ {7,30,60} and unit `days`, else `Application detail requires 7, 30, or 60 days` | `application(&DashboardAppQuery)`, `application_violation_breakdown(..)` | `GET …/apps/application?appid&appname&time_interval&time_unit`, `…/apps/applicationviolationbreakdown?…` |
| `dashboard top-applications`, `violations-trend` (`--interval` 1, `--unit` day ∈ {hour, hours, day, days}) | interval ≥ 1 | `top_applications_violations(&DashboardTimeRangeQuery)`, `applications_violations_trend(..)` | `GET …/apps/topapplicationsviolations?time_interval&time_unit`, `…/apps/applicationsviolationstrend?…` |
| `dashboard apps-list` (`--interval` 30, `--unit` days) | interval ≥ 1 | `apps_list(..)` (session-window schema) | `GET …/apps/appslist?…` |
| `sessions chart` (`--interval` 1, `--unit` day) | interval ≥ 1 | `sessions_chart(..)` | `GET …/sessions/sessionschart?…` |
| `sessions list\|ls` (`--interval` 1, `--unit` day, `--limit` 25, `--offset` 0, `--all`, `--max` 10000) | limit ≥ 1, offset ≥ 0, max ≥ 0 | `sessions_overview(&DashboardSessionsOverviewQuery)`; `--all`: §5 | `GET …/sessions/sessionsoverview?time_interval&time_unit&limit&offset` |
| `sessions get` (`--session-id`, `--app-id`, `--app-name` required; `--interval` 30; `--unit` days; `--limit` 25; `--offset` 0) | as above | `session(&DashboardSessionQuery)` | `GET …/sessions/session?session_id&app_id&app_name&offset&limit&time_interval&time_unit` |
| `sessions transaction` (the three identities, `--scan-id`, `--scan-sub-req-id` (≥ 0, zero valid); `--interval` 30; `--unit` days) | as above | `session_transaction(&DashboardSessionTransactionQuery)` | `GET …/sessions/sessiontransaction?…&scan_id&scan_sub_req_id&…` |
| `sessions scan-content` (`--scan-id`, `--scan-sub-req-id`, exactly one of `--show-content` or `--output-file <new path>`) | `Scan content requires exactly one of --show-content or --output-file <new-path>` (exit 2); `--output-file`: `lstat` before the tenant, anything there → `Destination exists` → the generic failure line (exit 1) | `scan_content(&DashboardScanContentQuery)` | `GET /v1/mgmt/reports/scancontent?scan_id&scan_sub_req_id` |

**`sessions list`.**

- One page: the status line `Returned <n> of <total_items|unknown> sessions; this is one page.`
  (`dash:248-252`, quiet-suppressed), then the bare `items` array.
- `--all`: §5.

**`scan-content`.**

- `--show-content`: the document on stdout.
- `--output-file`: the document plus `\n` through `files::publish_new` (0600, exclusive, never
  overwrites; TS `writeReportFile`), then `Scan content exported to the requested private file (0600).`
  (TS `ui.status`). In Rust the file always holds the JSON text, and `--output table` with
  `--output-file` is a usage error (choice 12).
- Prompts and responses go only to stdout or that file. They are never in errors, stderr or the
  debug log.

### 4.6 `runtime report` (TS `rep:`, `rr:`, `rh:`)

Port the TS collector and renderer, under DESIGN §15.17's rules: D155 (HTML only), D156 (`--debug`
refused), G7, `files::publish_new`, the TS failure line and the exit rules. The differences from the
red team report:

- **Argument checks** (exit 2, before the tenant): `--debug` refused
  (`Disable --debug for environment reports to avoid persisting sensitive traffic content`; TS also
  names `PANW_AI_SEC_DEBUG`, `cli:cli/program.ts:141-151`); `--output` given →
  `The environment report is written as HTML; omit --output`; `--max-pages` `^[1-9]\d*$`, ≤ 100,
  default 40; `--title` 1–240 UTF-16 units, non-blank, default `Daily environment report`;
  `--output-file` blank → `--output-file cannot be empty`. These are the TS texts (`rep:36-45`), with
  D155 replacing the format rule.
- **Destination.** `-` is stdout. The default is
  `airs-runtime-report-<ISO with ':' → '-'>-<8 hex of a v4 UUID>.html` (`rep:46`). The path is made
  absolute and `lstat`ed before the tenant; anything there gives the generic failure line (exit 1, no
  request; `spec:integration/cli/runtime-report.spec.ts:137-144`).
- **Status line.** `Collecting daily runtime activity and current configuration (read-only)...`
- **Sources** (`rr:147-301`; TS reads them concurrently with `Promise.all`, Rust in this order,
  choice 14):

  | # | Name / method label | Window | Read | Page rule |
  |---|---|---|---|---|
  | 1 | `Daily application activity` / `dashboard.applicationsOverview` | `Rolling 1 day` | `applications_overview({1, day, 100, offset})` | total-based when `total_items` is a safe count (total constant, `offset+size ≤ total`, no empty page before the total), else a full page probes on; key `[id, name]` |
  | 2 | `Security profiles` / `profiles.list (latest=true)` | `Current configuration` | `profiles().list({offset, 100, latest: Some(true)})` | `inventoryNext`: `next_offset` 0 ends; absent with a full page probes `offset+size` (`rr:101-104`); key `[profile_name, revision]` |
  | 3 | `Registered applications` / `customerApps.list` | `Current configuration` | `customer_apps().list({offset, 100})` | as 2; key `customer_appId` |
  | 4 | `Daily session inventory` / `dashboard.sessionsOverview` | `Rolling 1 day` | `sessions_overview({1, day, 25, offset})` | `total_items` present and `skip == offset` and `limit == 25`, total constant, `offset+size ≤ total`, `size ≤ 25`, no empty page before the total; key `[application_id, application_name, session_id]` |
  | 5 | `Daily session chart` / `dashboard.sessionsChart` | `Rolling 1 day` | `sessions_chart({1, day})` | one page; key `bucket_number` |
  | 6 | `Top application violations` / `dashboard.topApplicationsViolations` | `Rolling 1 day; server-ranked subset` | `top_applications_violations({1, day})` | one page; key `[id, name]` |
  | 7 | `Daily violation trend` / `dashboard.applicationsViolationsTrend` | `Rolling 1 day` | `applications_violations_trend({1, day})` | one page; key `bucket_number` |

  The collector is TS `collect` verbatim (`rr:53-95`):
  - a non-array record collection gives the note
    `The API returned no record array. An empty object or absent collection does not establish zero activity.`;
  - duplicates are excluded, with `partial`;
  - a non-advancing cursor gives `Pagination did not advance; collection stopped safely.`;
  - the page budget gives `Reached the <n>-page budget; this is not a complete inventory.`;
  - errors give TS `safeFailure` notes (`rr:26-36`: 401/403 credentials, 429, other HTTP, else the
    generic validation note).
- **G27 here.** With `without_response_defaults()`, an absent `ai_profiles` is `Optional::Unset`.
  The CLI maps it to "no record array" (unavailable). TS's zod default makes it `[]`, so the source
  is `complete` and the attention finding `No security profiles returned` is raised (D214). An absent
  `customer_apps` is unavailable in both CLIs (no default).
- **The model and findings** are TS (`rr:303-604`): schema 2, product
  `Prisma AIRS AI Runtime Security`, the eight limitations verbatim.
  - `label` cuts at **240** UTF-16 units (the red team report cuts at 120).
  - `count` admits safe non-negative integers only.
  - Sessions are filtered to the anchored half-open window `[start, end)` by `last_session_activity`
    (`Date.parse`; Rust admits the ISO form of `report::parse_iso`, the §15.17 approximation).
  - Profiles are reduced to the latest revision per name.
  - `registeredApps` keep only `app_name`, `environment`, `cloud_provider`, `model_name` and the
    **count** of `api_keys_dp_info`. No key names, auth codes or ids.
- **Rendering**: `renderRuntimeReportHtml` byte for byte (`rh:266-289`).
  - It has its own `CSS` and `JS` constants, and a CSP hashed over them:
    `default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'`.
  - `html()` escapes `& < > " '` as named entities (`&amp;` and so on, `rh:11-23`). The red team
    report uses `&#<code>;`, so the escape function is per report.
  - `number()` is `toLocaleString('en-US', {maximumFractionDigits: 2})`: thousands separators and
    half-expand rounding to two decimals (`rh:32-34`). That needs a small Rust formatter.
  - The footer is `Generated by Prisma AIRS CLI · Report schema 2 · Self-contained HTML; no network access required. All evidence remains readable with JavaScript disabled.`
  - The Markdown renderer is not ported (D155).
- **Exit.** 1 when the health is `unknown` (the file is still written) or `--strict` with an
  incomplete source. The status lines are `Report → <path> (mode 0600)` and
  `<n> source(s) incomplete; review the evidence section.` A failure after the checks prints the TS
  line `Report generation failed. Verify Management API configuration and a writable, new output path. Existing files are never overwritten.`
  (`rep:78-84`).

### 4.7 `runtime profiles backup [profile]` (TS `xfer:147-221`, `bk:139-177`)

- **TS options.**
  - `--all`: with a selector it is `Choose either a profile selector or --all`; it is redundant,
    since no argument already means all.
  - `--file-format` json|yaml (default json).
  - `--output-file <path>`: `-` gives `Backups require a private file destination, not stdout`.
  - The extension must match the format: `Backup filename extension must match --file-format`.
  - `--max-pages` 1–1000 (default 100) at parse time.
  - `--output`.
  - `--debug` is refused (`Disable --debug and PANW_AI_SEC_DEBUG for profile transfer; backups can contain sensitive policy configuration`,
    `cli:cli/program.ts:128-138`).
- **Requests** (TS order). The profile inventory comes first: `profiles().list({offset, limit: 100, latest: Some(true)})`
  pages under TS `offsetPages` (`bk:44-61`):
  - at most `--max-pages` pages and 10,000 records;
  - `next_offset` 0 or absent ends the walk, a non-advancing one fails;
  - the texts `Inventory pagination did not advance`, `Inventory exceeds the 10000-record safety limit`
    and `Inventory is incomplete: increase --max-pages before exporting or restoring`.

  Then `latestProfiles` (`bk:64-79`):
  - a repeated `[name, id, revision]` → `Inventory contains repeated profile records`;
  - the same name with two ids → `Ambiguous profile name: <name>`;
  - a blank name or one with a control character → `Profile/topic names must be nonempty and contain no control characters`.

  Then `assertTenant` (`profile.tsg_id` must be the tenant's TSG) and the selector match (by
  `profile_id` or `profile_name`: `No matching profiles to back up`, `Ambiguous profile selector`).
  Every selected profile needs a policy that passes `PolicySchema` (`Profile has no policy: <name>`).
  Only when some policy references a topic is the topic inventory read: `topics().list(TopicListOptions{offset, 100, latest_only: false})`,
  every revision. Each reference `[topic_id, revision]` must match exactly one topic with the same
  name (`Cannot export the exact referenced topic revision: <name> revision <n>`).
- **SDK fit.**
  - The typed `SecurityProfile` (`gen:166008`) keeps `policy: Optional<Policy>` and `extensions`.
    Every object in the schema is `passthrough` (the schema walk: 22 of 22), so a re-serialised
    record is lossless.
  - The topic walk (`topicReferences`) and `PolicySchema` work on the JSON value. Rust serialises
    the typed model to a `serde_json::Value`, walks it as TS does, and parses the policy with the
    SDK's `Policy` model.
  - `without_response_defaults()` keeps `examples` unset when the server omits it (G27).
- **Rust format and file rules**: §8, D215.

### 4.8 `runtime profiles restore <file>` (TS `xfer:223-357`, `bk:179-749`, `pol:`)

- **TS options.**
  - `--dry-run`;
  - `--name-prefix` (≤ 64 units, no control character);
  - `--on-conflict` error|verify|skip|update (default error);
  - `--on-missing-dlp` error|basic (default error);
  - `--dlp-map <source=destination>`, repeatable, with `--dlp-map requires source-name=destination-name`
    and `Duplicate source names in --dlp-map`;
  - `--max-pages` 1–1000;
  - `--expect-tsg`, and `--force`, which requires `--expect-tsg`;
  - `--output`.

  Files: `.json`, `.yaml` or `.yml`, a regular file of at most 20 MiB (`xfer:275-290`).
- **Reads.** The destination inventory: profiles (`latest=true`) and topics as in the backup. Only
  when a DLP reference must be resolved, the **DLP data profiles**: `dlp.dataProfiles.list({page, size: 100})`
  with `last`/`totalPages`/short-page ends (`bk:319-337`). In Rust that is the M6b inventory walk
  (`here:src/dlp/walk.rs`) on `management.dlp(dlp_endpoint)`, with its stricter checks (D175).
- **Planner** (TS verbatim, `bk:340-527`):
  - the conflict policy;
  - topic reuse when identical (`sameTopic`: description, examples, active ?? true), else
    `Destination topic differs`;
  - the cross-tenant rules: `assertKnownPolicyReferences` refuses any `*id`/`*uuid` key except
    topic and DLP identities; DLP references need a `--dlp-map` or `--on-missing-dlp basic`
    (`basicFallback`, `bk:266-286`);
  - `verify` compares with `compareRuntimePolicies` (`pol:12-161`, port verbatim; it allows only the
    ten observed server-added defaults).
- **Executor** (`bk:581-717`):
  - re-check the destination after the confirmation, before any write;
  - per topic, re-list, then `topics().create` (one attempt);
  - per profile, re-list, then `profiles().create` or, for `update`, `profiles().update(existing_id, body)`
    (one attempt);
  - re-list and verify (`compareRuntimePolicies`, active, `profile_id` equals the answer's);
  - stop at the first failure.

  TS reports the failure only as `API request failed (HTTP <s>); verify destination state before retrying`
  or `Restore stopped; …`. Nothing says a timed-out create may exist (D217).
- **Confirmation** (TS `confirmOrAbort` when anything is created or updated, `xfer:339-347`). Rust:
  D81 with the D167 refusal before the tenant (§8.3).

---

## 5. Walks

- **api-keys and customer-apps `--all`.** The SDK offset walk (`list_all`, `rs:pagination.rs`),
  exactly as `runtime profiles list --all` does today (D12, D14, D37, D40, `pagination::walk_end`).
  The CLI adds a repeated-row check on the identity (`api_key_id`, `customer_appId`) over the
  collected items: a repeat is the D37 error (G28, D218).
- **`sessions list --all`** (TS `dash:234-299`).
  - It starts at `--offset` (TS allows it with `--all`) and advances by the returned count.
  - Each page must have a safe non-negative `total_items`, `skip == offset`, `limit == --limit`,
    `items.length ≤ limit` and a total equal to the first page's. Otherwise `Unstable pagination`.
  - A repeated `[application_id, application_name, session_id]` is `Overlapping session pages`.
  - `offset > total`, or an empty page before the total, is `Incomplete inventory`. Each of these
    three errors is exit 1 with no data.
  - `--max` reached gives `Session item cap reached; output is partial.` with the first `max` rows,
    exit 1.
  - 100 pages give `Session page cap reached; output is partial.`, exit 1.
  - Success gives `Retrieved <n> sessions from offset <o>; pagination complete.`

  Proposal: generalise `src/walk.rs` with a `walk_with(spec, fetch, size, key, check)` entry:
  - `spec.start` (the first skip);
  - `spec.max_pages` (100 here; `MAX_PAGES` elsewhere);
  - `spec.page_cap_partial` (stop with `stopped_at_pages` instead of the D40 error);
  - a per-page `check` closure for the echo and constant-total rules.

  The existing `walk` becomes `walk_with(Spec::default(), …, |_| Ok(()))`. The caller keeps the TS
  texts and exit codes, which are already stricter than D147 (choice 9).
- **The consumption bucket walk.** `walk_with(Spec::default())` with the key `[id, name]` and the TS
  stop rule (a short page or `offset ≥ total`), `limit` 100.
- **Report and profile-transfer inventories.** Their own TS loops (`rr:53-95`, `bk:44-61`), as
  §15.17 kept the red team report's loop. They produce partial or failed sources with fixed notes
  rather than D37 errors.

---

## 6. Projections, errors, messages

### 6.1 Projections (`svc:312-365`)

- **API key**:
  - `id: id ?? api_key_id ?? ''`;
  - `name: name ?? api_key_name ?? ''`;
  - `apiKey: api_key`;
  - `last8: api_key_last8`;
  - `createdAt: created_at`;
  - `expiresAt: expires_at`.

  The API sends `creation_ts` and `expiration` (`tsdk:2048-2074`), so TS always shows empty `Created`
  and `Expires` (`docs:cli/runtime/api-keys.md` shows `"createdAt": ""` and `"expiresAt": ""`). Rust
  keeps TS's keys first and falls back to `creation_ts` and `expiration` (D207).
  - The json view has no `structured` mapping (`cli:cli/renderer/views/runtime.ts:29-41`), so TS
    json prints the whole projection, **including `apiKey` whenever a list row carries `api_key`**.
    Rust never prints it (D205).
  - Pretty: `API Keys:` then `<id>` dim and `    <name> key: …<last8> expires: <expiresAt>` (`rnd:314-360`).
  - Table: `ID │ Name │ Last 8 │ Expires`. The list renderer's non-pretty path (`Key (last 8)`,
    `Created`) is dead code: `emitList` uses the view columns.
- **Customer app**: `{id: customer_app_id ?? id, name: app_name ?? name ?? '', description, raw}`.
  The API sends `customer_appId` (`tsdk:2109-2130`), so TS never shows an app id. Rust falls back to
  `customer_appId` (D207); without it, `customer-apps update <appId>` cannot be fed from `list`.
- **Write acknowledgements.**
  - `Customer app "<app.name>" deleted.`, where TS's name comes from the response. For a
    `{message}` answer that is `""` (`cmd:515-517`, `svc:396-399`).
  - `ui.success(result.message)` for an API key, which shows `undefined` when there is no message.

  Rust: the response's `app_name` when the answer is a `CustomerApp`, else the positional name. For a
  key, the server `message` (terminal-safe, `SecretSet`-checked) or `API key "<name>" deleted.` (D208).

### 6.2 Errors (what M6d adds to DESIGN §6)

- **Planes.** Every M6d call is `Plane::Management`. Reads are `Operation::Read`. Writes are
  `Operation::Write` with `writes::describe` and `Change::Words`:
  - `("API key", "created" | "regenerated" | "deleted")`;
  - `("customer app", "updated" | "deleted")`;
  - `("security profile", "created" | "updated")` and `("custom topic", "created")` in restore.
- **Outcome lines** (D95 shape):
  - `Outcome unknown: the API key may have been created.` with the hint
    `List keys with runtime api-keys list before creating another.`;
  - `… may have been regenerated` (`the old key may no longer work`);
  - `… may have been deleted`.
- **2xx unreadable.** `Outcome: the API key was created, but the response could not be read.`, with
  `regenerate it to obtain a usable key` (the value is lost, G4).
- **Dashboard and sessions**: the TS generic line (choice 11).
- **Profile transfer**: DESIGN §6 messages (the DLP precedent, D175). TS prints
  `Profile transfer API request failed (HTTP <s>); no automatic retry was made.`, and a zod failure
  becomes `Invalid profile backup/request schema; content is not logged.` (`xfer:129-145`).

---

## 7. Secrets and sensitive data

| Data | Rule |
|---|---|
| `api_key` in a create or regenerate answer (`gen:4645`) | Registered in the `SecretSet` as soon as the answer is decoded. **Never on stdout, stderr, in the debug log, an error, a summary or the ledger.** The only channel is `--key-file` (below) |
| `api_key` in a list row (if the service ever sends one) | Registered in the `SecretSet`; the `apiKey` field is omitted from every format (D205). TS json prints it |
| `api_key_last8` | Printed (TS and the service's own fingerprint; 8 of ~48 characters, not recoverable) (choice 5) |
| `auth_code` (deployment profiles, `api_keys_dp_info`, `ApiKey`) | Printed as TS does: it is the entitlement code `api-keys create` needs, not a bearer credential (choice 6). The report keeps only counts |
| Scan content (`prompt`, `response`) | `--show-content` (stdout) or `--output-file` (0600) only; never in an error, stderr or the debug log |
| Session and transaction details, app names, user ids and IPs (`DashboardSessionTransaction.attributes`) | Server text: `terminal_safe`/`SecretSet`; JSON text escapes control characters |
| Profile backups | Policies and topic definitions in clear at 0600 (TS does the same); `--debug` refused |

**`--key-file <path>` (Rust-only, required on `create` and `regenerate`, D204).**

1. **Planning** (before the tenant):
   - `--key-file ""` gives `--key-file needs a path` (exit 2);
   - `--key-file -` gives `--key-file - would print the key; give a file path` (exit 2), as D194;
   - an existing path (`lstat`, a dangling symlink included) gives
     `<path> already exists; choose another --key-file` (`files::refuse_existing`, exit 1);
   - a missing or unusable parent gives the `publish_new` message.
2. **Reservation.** After the confirmation and before the POST, create
   `.airs-<16 hex>.tmp` exclusively (0600, `O_EXCL|O_NOFOLLOW`) in the destination directory
   (proposed `files::Reservation`, the first half of `publish_new`). A write that cannot store its
   key is then never sent.
3. **After a 2xx with `api_key`.** Add it to the `SecretSet`, then write `<key>\n`, `fsync` and
   `link`. On success, print
   `✓ Wrote the API key to <path> (mode 0600); it is shown only once.` (stderr). If the link fails
   (the path appeared meanwhile), keep the temporary file and print
   `The API key was created; it is in <temp path> (mode 0600) because <path> now exists` (exit 1).
   The key is never lost to a race.
4. **A 2xx without `api_key`.** Remove the reservation. Print
   `Outcome: the API key was created, but the service returned no key value; regenerate it.`
   (exit 1).
5. **Output.** The detail on stdout has `Key` as `…<last8>` (pretty), or `"keyFile": "<path>"` and
   no `apiKey` (json). Pretty keeps TS's layout otherwise.
6. **Interruption.** Before dispatch: `Interrupted; no API key was created`. After dispatch: the
   outcome-unknown line. After the link: `Interrupted; the key was saved in <path>`.

---

## 8. `profiles backup` and `restore`: the Rust format and the safety rules

### 8.1 Backup (D215, the D175 pattern)

- **Argument checks** (exit 2, in order):
  - `--file-format` other than `json` gives `--file-format must be json (yaml was dropped)`;
  - `--all` with a selector gives the TS text;
  - `--max-pages` gives the TS text;
  - `--output-file -` gives the TS text;
  - `--output-file ""` gives `--output-file needs a path`;
  - an extension other than `.json` gives the TS text;
  - `--debug` gives `Disable --debug for profile transfer; backups can contain sensitive policy configuration`
    (debug policy `refused`; the TS text minus `PANW_AI_SEC_DEBUG`, as D156).
- **Location** (before the tenant, exit 1):
  - the default name is TS's `airs-runtime-profiles-backup-<ISO, [:.] → '-'>-<8 hex>.json` in the
    working directory;
  - the parent must exist;
  - anything at the path gives `<path> already exists; choose another --output-file`.

  TS finds the clash only at the final `link`, after every read.
- **Reads.** §4.7, with the SDK read retries and `without_response_defaults()`.
- **Format** (`airs-cli-rs.runtime-profiles`, version 1). One JSON document plus `\n`, at most 20 MiB
  (TS's `Backup exceeds the 20 MiB size limit; select individual profiles`):

  ```json
  {
    "format": "airs-cli-rs.runtime-profiles",
    "version": 1,
    "exportedAt": "2026-10-18T12:00:00.000Z",
    "tenant": "redtail-prod",
    "tsgId": "100",
    "selector": "Production",
    "profiles": [{"id": "…", "name": "Production", "revision": 8, "record": {…}}],
    "topics": [{"id": "…", "name": "Restricted", "revision": 3, "record": {…}}]
  }
  ```

  - `record` is the typed SDK model re-serialised: lossless, unset and `null` kept, no default
    inserted.
  - `selector` is `null` for all profiles.
  - Entries are sorted by name (profiles, as TS `latestProfiles`) and by `[name, revision]` (topics).
  - There is no `complete` key: a backup is complete or not written (TS has no partial file either).
- **Publishing.** `files::publish_new` (0600, exclusive `link`, never overwrites). The interrupt
  contexts are `no backup file was written` and `the backup was saved in <path>`.
- **Output.**
  - pretty and table: TS's one-row table `Backup file │ Source TSG │ Profiles │ Topics`
    (`xfer:199-217`).
  - json: `[{"file", "sourceTsgId", "profiles", "topics"}]`.
  - `file` is the path as given (D175; TS absolute).

### 8.2 Restore: file and tenant (D216, the D176 pattern)

- **Argument checks** (exit 2, before the file):
  - the TS texts for `--on-conflict`, `--on-missing-dlp`, `--dlp-map` and `--max-pages`, and
    `--force requires --expect-tsg <destination-tsg>`;
  - `--dry-run` with `--force` gives `--dry-run cannot be combined with --force`;
  - `--name-prefix` longer than 64 units or with a control character gives `Invalid --name-prefix`
    (TS: exit 1 in the plan);
  - `--expect-tsg` not 1–32 digits gives `--expect-tsg must be a TSG ID (1-32 digits)`;
  - non-interactive without `--dry-run` or `--force` gives
    `refusing to restore profiles without --force in non-interactive mode` (D167 pattern);
  - `--debug` is refused (as backup).
- **The file.** A regular file, `.json` only, at most 20 MiB, read whole, UTF-8, parsed with the
  order-keeping `json` reader. The strict reader:
  - checks exactly the keys above, `format` and `version`;
  - requires `tsgId` to be 1–32 digits;
  - requires `profiles` (1–10,000) and `topics` (0–10,000);
  - checks each entry's `id`, `name` and `revision` against its `record`;
  - checks each `record` with `SecurityProfile::parse` or `CustomTopic::parse` in
    `Mode::ResponseWithoutDefaults`;
  - refuses duplicate names (profiles) and duplicate `[id, revision]` (topics).

  Fixed reasons only; no content is echoed.
- **TS backups** (`"resourceType": "runtime-security-profiles"`, or any `.yaml`/`.yml`) are
  **refused**: `<file> is a TypeScript airs-cli backup; airs-cli-rs restores only backups it wrote (runtime profiles backup)`
  (exit 1, as D152 and D176; MILESTONES: "No compatibility with TypeScript-made files"). This keeps
  one strict format.
- **Tenant.** A backup whose `tsgId` is not the tenant's needs `--allow-other-tenant`, else
  `The backup is from TSG <x>; pass --allow-other-tenant to restore it into TSG <y>` (exit 2, after
  the file is read and before the tenant's requests). `--expect-tsg` must equal the tenant's
  `mgmtTsgId` (TS text: `--expect-tsg does not match the selected destination tenant; no API request was made`).
  The cross-tenant DLP and identity rules of the planner then apply as in TS.

### 8.3 Restore: writes and outcomes (D217, the D177 pattern)

- **Confirmation.** D81, prompt TS's
  `Restore <n> profiles from TSG <src> to TSG <dst> (<u> updates, <f> Basic DLP fallbacks losing custom detection)?`.
  It is asked only when something is created or updated. `--force` skips it.
- **Writes.** One attempt per create or update (`writes::send`). A 401 is replayed once; a 403 is
  never replayed.
- **The first failure stops the run.**
  - An `Unknown` outcome gives `Outcome unknown: the <custom topic|security profile> <name> may have been created; run the restore again with --on-conflict verify to check it`
    (json `outcomeUnknown`).
  - A 2xx without a usable id gives `Outcome: the … <name> was created, but the response could not be read; …`
    (in `outcomeUnknown` too).
  - Later items go in `notAttempted`.
- **A re-run never duplicates.** Topics are reused when identical (`sameTopic`). An existing profile
  name is `error` by default, and `verify` checks it without writing. An unknown create is therefore
  either found (verify) or absent (created once). Under `update` the target is the destination id
  from the plan, re-checked as unchanged just before the PUT (TS `unchanged`, `bk:570-578`).
- **No `DELETE` ever.** No PATCH. PUT only under the explicit `--on-conflict update`, inside the
  confirmation count (TS invariant).
- **Output.**
  - pretty and table: TS `renderRestore` (`xfer:26-92`) plus an `Outcome unknown` block.
  - json: TS's one-element array `[{sourceTsgId, destinationTsgId, dryRun, profiles, topics, dlpMappings, dlpFallbacks, serverDefaults, complete}]`
    plus `outcomeUnknown` and `notAttempted`.
  - DLP fallback warnings on stderr (TS `ui.warning`).
- **Exit.** 1 when not complete.

---

## 9. Gaps

| # | Operation | What is missing or different | Evidence | CLI-side workaround |
|---|---|---|---|---|
| **G26** | `api_keys().create` / `regenerate` answer | The key value is a plain `Optional<String>`, not a `Secret`. Only `ApiKey`'s whole-struct `Debug` is redacted; `Serialize` writes it. The SDK marks nothing as a credential | `gen:4645-4646`, `:4750-4752`, `:4965-4967`; `mg:api_keys.rs:46-61`, `:138-155` | **Safe**: register the value in the `SecretSet` on decode, never serialise an `ApiKey` to output, write it only through `--key-file` (§7). The same treatment applies to an `api_key` in list rows |
| **G27** (G10 for M6d) | `profiles().list`, `topics().list` and `create` answers | Response defaults: `SecurityProfileListResponse.ai_profiles = []` (`sem:s009653`), `CustomTopic.examples = []` (`s008873`), `CustomTopicListResponse.custom_topics = []` (`s008908`). An absent array becomes an empty one | schema walk from `SecurityProfileListResponseSchema`, `CustomTopicSchema`, `CustomTopicListResponseSchema`; `rs:config.rs:398-409` | **Safe**: `RequestOptions::without_response_defaults()` on every M6d call. It matters for the report (D214), the backup's stored topics and restore's comparison |
| **G28** | `ApiKeysClient::pages/list_all`, `CustomerAppsClient::pages/list_all` | The offset walk detects a repeated cursor and an empty non-final page, but not a repeated row | `mg:api_keys.rs:78-120`; `mg:customer_apps.rs:73-115`; `rs:pagination.rs:346-391` | **Safe**: a CLI identity check over the collected rows (`api_key_id`, `customer_appId`); a repeat is the D37 error |
| **G29** | `api_keys().delete(name)`, `regenerate(id)` | `.segment(..)` refuses `.`, `..`, `\`, control characters and encoded traversal, and caps the length. TS `encodeURIComponent`s anything | `mg:api_keys.rs:130`, `:147`; `rs:config.rs:121-151`; `tsdk:11802`, `:11833` | **Safe**: the same rule as a usage error in planning (the red team segment helper, `here:src/redteam/mod.rs:37`) |
| **G30** | `ManagementClient::new` and the dashboard plane; `customer_apps()` by id | The dashboard client is derived from the management client. A separate `mgmtDashboardEndpoint` needs `with_dashboard_endpoint` and must already be admitted by the destination policy (otherwise `Destination`). There is no customer-app read by id (`get` takes `app_name`), so `update <appId>` cannot read before it replaces | `mg:mod.rs:59-75`; `rs:engine.rs:438-444`; `mg:customer_apps.rs:46-56`, `:116-133` | **Safe**: admit the dashboard origin in `ManagementClients` (§1.2). `update` is confirmed as a replace (D206) rather than read-modify-written |
| **G31** | `ManagementClient::dlp(endpoint)` for restore | The DLP client inherits the management client's `Limits` (8 MiB responses by default). The M6b DLP clients use 32 MiB | `mg:mod.rs:131-134`; `here:src/clients.rs:522`, `:536-584` | **Safe**: build the transfer client with `max_response_bytes = DLP_MAX_RESPONSE_BYTES` and admit `dlpEndpoint`; one OAuth identity |
| G32 (shape) | `scan_logs().query` | A POST (`RawRequest::new`), not replay-safe, sending `page_token` in a JSON body. The TS CLI never calls it | `mg:inventory.rs:93-135`; `cmd:1089-1095` | Not used: the port is the TS stub (§4.4) |
| G33 (ergonomics) | every options and query struct | `#[non_exhaustive]` with `Default` (`PaginationOptions`, `DeploymentProfileListOptions`, `Dashboard*Query`); some have `new(..)` | `mg:profiles.rs:10-24`; `mg:dashboard.rs:11-143` | `Default::default()` (or `new`) plus field assignment |
| G34 (naming) | debug operation names | `airs.management.{api_keys,customer_apps,deployment_profiles,dashboard,profiles,topics}.*` (list in §3) | `mg:*.rs` `.named(..)` | Pin them in the debug tests (as G9, G17, G23) |
| G35 (shape) | `ApiKeyDeleteResponse`, `CustomerAppDeleteResponse` | Unions with an `Unknown(JsonValue)` arm: any decodable 2xx JSON is accepted as a delete answer | `gen:5282-5287`, `:18528-18533` | Print a fixed acknowledgement (D208), never the `Unknown` value |

G3, G4, G7 and G10 apply unchanged. **No blocker:** every M6d behaviour is portable on scm-sdk 0.1.1.

---

## 10. Proposed §12 rows (from D204)

Each row needs its `dNN_` parity test and a COMPATIBILITY.md row.

| # | Area | TypeScript | Rust (proposed) | Why |
|---|---|---|---|---|
| D204 | `api-keys create`, `regenerate`: the key value | printed in full on stdout (`Key: <secret>`), pretty only, `--quiet` too (`rnd:362-381`) | `--key-file <new path>` required (checked before the tenant; `-` refused); the key written 0600 through a reservation made before the request, never overwritten; stdout shows `…<last8>`; the key is in the `SecretSet` from decode (§7) | a credential must not land on a terminal or in a CI log; a key that is shown once must not be lost to a write failure |
| D205 | an `api_key` in `api-keys list` rows | `--output json` prints `apiKey` whenever the service sends `api_key` (no structured view, `cli:cli/renderer/views/runtime.ts:29-41`) | omitted in every format; registered in the `SecretSet` | secret safety |
| D206 | confirmations: `api-keys delete`, `api-keys regenerate`, `customer-apps delete`, `customer-apps update` | never asks | D81 rules with a Rust-only `--force`; the non-interactive refusal is a usage error before the tenant (as D137, D186) | each destroys a working key or app (regenerate invalidates the old key; delete removes the app's keys; update replaces the record) |
| D207 | projection field names | `createdAt`/`expiresAt` read `created_at`/`expires_at` and the app id reads `customer_app_id`/`id`, which the API never sends: empty `Created`/`Expires` and no app id, always | TS's keys first, then `creation_ts`, `expiration` and `customer_appId` | correctness: the listed id is what `customer-apps update` needs |
| D208 | write acknowledgements | `Customer app "" deleted.` when the answer is `{message}`; `✓ undefined` for a key delete without a message | the positional name when the answer carries none; the server message (terminal-safe) or `API key "<name>" deleted.` | correctness |
| D209 | `customer-apps consumption` counts the server omitted | `0` (`?? 0` on sessions, detectors and `total_violating`, `svc:476-503`) | only what the server sent: JSON `null`, pretty `-`, table empty | a fabricated `0 violating` is a fail-open display (as D180) |
| D210 | `consumption` output in all-apps mode | one JSON array per app on stdout (several documents); an app without detectors prints `[]` and vanishes | one JSON array for the run; an app without detectors gets one row with `detector: null`; per-app failures make the exit 1 | stdout must be one parseable document; no silent loss |
| D211 | `consumption` bucket lookup | first bucket with the name; the bucket walk has no page cap or repeat check | an ambiguous name (two ids) is an error; the walk is complete or an error (D37, D40) | correctness: the wrong app's data is not shown |
| D212 | dashboard and sessions formats | `pretty` (JSON text), `json`, `yaml`; `table` refused | `pretty` (the same JSON text), `json`, `table` (Key │ Value; a row table for `sessions list`); `yaml` per D50 | every command has pretty and table (M3.5); the dropped formats are dropped |
| D213 | `api-keys delete <name>` and `regenerate <id>` path segments | `encodeURIComponent` of anything, `.` and `..` included | `.`, `..`, `\`, control characters and encoded traversal refused as a usage error before the tenant (G29) | a path segment must not traverse |
| D214 | `runtime report` profile source when `ai_profiles` is absent | the SDK default `[]`: the source is `complete`, with the attention finding `No security profiles returned` | `unavailable` with the TS "no record array" note (G27) | absent data is not zero (the report's own rule) |
| D215 | `runtime profiles backup` | the TS envelope in JSON or YAML; an existing path found only at the final link after every read; the summary shows the absolute path; reads sent once (`numRetries: 0`) | the Rust format (`airs-cli-rs.runtime-profiles` v1, lossless records, no defaults); `--file-format yaml` a usage error; the path checked before the tenant; 0600, never overwritten; the path as given; SDK read retries (§8.1) | as D175 |
| D216 | `runtime profiles restore` file and tenant | reads TS envelopes from `.json`, `.yaml` or `.yml`; another TSG's backup is restored with no flag; `--dry-run --force` accepted | a TypeScript backup is refused with a message; the Rust format read strictly; another TSG needs `--allow-other-tenant`; `--dry-run --force` a usage error; the non-interactive refusal before the tenant (§8.2) | as D176 |
| D217 | `runtime profiles restore` writes and outcomes | stops at the first failure, reported only as `API request failed (HTTP <s>)` or `Restore stopped`, with nothing saying a create may exist; a create replayed after a 403 | one attempt per create or update; outcome-unknown and unreadable lines naming the resource, `outcomeUnknown` and `notAttempted` in json, the `--on-conflict verify` resume hint (§8.3) | never duplicate a profile; name what may exist |
| D218 | `api-keys list --all`, `customer-apps list --all` repeated rows | printed twice | the D37 pagination error (G28) | an incomplete walk is never complete (as D147) |

Existing rows that extend to M6d:

- D10: the api-keys, customer-apps and deployment-profiles reads.
- D11: the dashboard texts are TS's own generic line, so nothing more there.
- D14: `--all --max` on the two lists.
- D17: `--interval`, `--time-interval`, `--limit`, `--offset`, `--max` and `--scan-sub-req-id`;
  TS `parseInt` and `Number` coercions are usage errors.
- D50: yaml, markdown and csv.
- D52: server text.
- D95: the api-keys and customer-apps writes.
- D116: the `--config` bodies of `api-keys create` and `customer-apps update`.
- D155: the runtime report is HTML only.
- D156: the runtime report and the profile transfer refuse `--debug` without naming
  `PANW_AI_SEC_DEBUG`.
- The M4 `--output` rule: `api-keys create|regenerate` and `customer-apps update` have no `--output`
  in TS, and Rust honours the global one.

---

## 11. Proposed CLI module layout (mirrors `src/modelsec` and `src/commands/modelsec*`)

| File | Contents |
|---|---|
| `src/runtime/mod.rs` | Argument checks: the TS dashboard `integer`/`text` rules; the unit vocabularies per command; the application interval rules; `--time-interval`; `--interval` for regenerate; the segment rule for key names and ids (G29); `--updated-by` non-blank; the options helper (§1.3: `read_options`, `dashboard_options` with the G7 re-read wrapper, `write_options`) |
| `src/runtime/views.rs` | The TS projections and layouts: api-key list and detail (D205, D207), customer-app list and detail, deployment profiles, the consumption rows and pretty layout (D209, D210), the dashboard JSON-text pretty and table layouts (D212), the banner |
| `src/runtime/keys.rs` | The `--key-file` plan, the `files::Reservation` use, `SecretSet` registration and the withheld display (§7) |
| `src/runtime/consumption.rs` | The bucket walk, the lookup (D211) and the per-app pair of reads |
| `src/runtime/transfer/mod.rs` | The Rust backup format: writer, strict reader, TS-file detection (§8) |
| `src/runtime/transfer/plan.rs` | The TS planner and executor (`bk:340-717`): `latestProfiles`, `topicReferences`, `dlpReferences`, `assertKnownPolicyReferences`, `basicFallback`, `mappedPolicy`, `unchanged`, the re-checks |
| `src/runtime/transfer/policy.rs` | `compareRuntimePolicies` (`pol:12-161`), verbatim on `serde_json::Value` |
| `src/report/runtime.rs` | The runtime collector (`rr:`), reusing `report::{Source, Status, Priority, Finding, Health, label, iso, parse_iso, is_control_or_format}` (with `label` taking the cut length: 120 red team, 240 runtime) |
| `src/report/runtime_html.rs` | `renderRuntimeReportHtml` (`rh:`): its CSS, JS, CSP, entity escaping and the `en-US` number formatter |
| `src/commands/runtime_keys.rs` | `api-keys list|create|regenerate|delete` |
| `src/commands/runtime_apps.rs` | `customer-apps list|get|update|delete|consumption` |
| `src/commands/runtime_inventory.rs` | `deployment-profiles list` and the `scan-logs query` stub |
| `src/commands/runtime_dashboard.rs` | `dashboard *` and `sessions *` (the shared `register` flow of `dash:103-153`; `sessions list --all`; `scan-content`) |
| `src/commands/runtime_report.rs` | `runtime report` |
| `src/commands/profile_backup.rs`, `profile_restore.rs` | The two transfer commands |
| `src/commands/runtime_write.rs` | Shared connect (without a token request before the confirmation, §13.2), confirm (D81 plus `--force`) and `writes::send` wrappers, as `dlp_write.rs` and `modelsec_write.rs` |

**Changes to existing modules.**

- `clients.rs`: `ManagementClients::build_for(.., Planes { dashboard, dlp })` (§1.2).
- `commands/mod.rs`:
  - `connect_management_for(planes, ..)`;
  - the planning table: debug policies `log` (every new read and write), `none` (`scan-logs query`)
    and `refused` (`runtime report`, `profiles backup`, `profiles restore`);
  - the format policies (dashboard and sessions: pretty, json, table, tenant default applies).
- `cli.rs`: the clap trees.
  - Sorted subcommands, `ls` on every `list` (`sessions list` included) and `rm` on the two deletes.
  - The hidden `--page`/`--page-size` on `scan-logs query`.
  - Rust-only `--force` (api-keys delete, regenerate; customer-apps update, delete), `--key-file`
    and `--allow-other-tenant`.
  - `profiles backup|restore` under the existing `runtime profiles` group.
- `walk.rs`: `walk_with(spec, …, check)` (§5).
- `files.rs`: `Reservation` (`reserve_new(path, flag)` → `write_and_link(bytes)` / `keep()` / drop
  removes), which `publish_new` becomes a wrapper of.
- `report/mod.rs`: `label` with a length parameter; the shared types stay.

**No change needed.** `Cargo.toml` (`management` already enabled), the tenant keys
(`mgmtDashboardEndpoint` and `dlpEndpoint` are known), and the doctor and tenant wording. The TS
management-credential line already names management commands generically
(`cli:cli/commands/doctor.ts:299`, `here:src/commands/doctor.rs:318-325`). The TS doctor has no
dashboard probe, and `tenant` has nothing M6d-specific.

---

## 12. Fixture-server routes the loopback harness needs

Add `server/runtime.rs` (reads), `server/runtime_writes.rs` and a seeded dataset `fixtures_runtime.rs`.
Every route checks the `mock-token-<tsg>` bearer and records the query. Every dashboard route also
checks `x-tsg-id: <tsg>`, and every `/aisec` route checks its absence. Add a family
`Route::Runtime(Rx)` with stable labels.

| Route (`/aisec` prefix, `mgmtEndpoint`) | Behaviour |
|---|---|
| `GET /v1/mgmt/apikeys/tsg/{tsg}?offset&limit` | Seeded keys with `api_key_last8`, `creation_ts` and `expiration`; `next_offset` paging. Knobs: a row carrying `api_key: FAKE-APIKEY-SECRET-<tsg>-list` (D205), a repeated row (G28), a repeated cursor, an empty non-final page |
| `POST /v1/mgmt/apikey` | Validates the required fields; answers a new `api_key_id` and `api_key: FAKE-APIKEY-SECRET-<tsg>-<n>` (the marker). Knobs: no `api_key`, an undecodable 2xx, 401 once, 403, 500, 502, a held-then-dropped connection. POSTs are counted |
| `POST /v1/mgmt/apikey/regenerate/{id}` | A new id and a new marker secret; the old key is marked revoked |
| `DELETE /v1/mgmt/apikey/delete/{name}?updated_by=` | `{message}`, a bare string, or `{}` (D208) |
| `GET /v1/mgmt/customerapp/tsg/{tsg}?offset&limit` | `CustomerAppWithKeys` rows with `customer_appId` and `api_keys_dp_info`; knobs as for keys |
| `GET /v1/mgmt/customerapp?app_name=` | 404 for an unknown name |
| `PUT /v1/mgmt/customerapp?customer_app_id=` | Replaces the record (the replace semantics D206 assumes); write knobs |
| `DELETE /v1/mgmt/customerapp?app_name=&updated_by=` | `{message}` or a `CustomerApp` answer (D208); removes the app and its keys |
| `GET /v1/mgmt/deploymentprofiles[?unactivated=true]` | Two profiles; one more with `unactivated=true` |
| `POST /v1/mgmt/scanlogs` | Must never be hit (asserted by every scan-logs test) |
| Existing profile and topic routes (`Route::Profiles`, `Topics`, `ProfileCreate`, `ProfileUpdate`, `TopicCreate`, …) | Reused by backup and restore. Add the knobs: a profile list without `ai_profiles` (G27/D214), a topic without `examples`, a profile with an unknown policy key (losslessness), a profile from another `tsg_id`, two ids with one name, and a create answering 500/502/drop (D217) |
| Existing DLP data-profile routes (`fixtures_dlp.rs`) | Reused by restore's DLP mapping |

| Route (`/dashboard` prefix, `mgmtDashboardEndpoint`) | Behaviour |
|---|---|
| `GET /v1/mgmt/dashboard/v2/apps/applicationsoverview` | Buckets with `pagination.{skip, limit, total_items}`. Knobs: two buckets with one name and different ids (D211), absent counters (D209), a changing total, an empty page before the total |
| `GET …/apps/application`, `…/apps/applicationviolationbreakdown` | Token and session stats (with nulls), detector breakdowns (one app with none) |
| `GET …/apps/topapplicationsviolations`, `…/apps/applicationsviolationstrend`, `…/apps/appslist` | Daily data |
| `GET …/sessions/sessionschart` | Buckets |
| `GET …/sessions/sessionsoverview` | Pages echoing `skip` and `limit`. Knobs: a mismatched `skip`, a mismatched `limit`, a changing total, overlap, an empty page, a total of 0 with rows (the TS spec's four unstable pages), a missing `items` |
| `GET …/sessions/session`, `…/sessions/sessiontransaction` | `scan_sub_req_id` 0 kept |
| `GET /v1/mgmt/reports/scancontent` | `prompt: FAKE-PROMPT-CONTENT-<tsg>`, `response: FAKE-RESPONSE-CONTENT-<tsg>`; `scan_contents: null` knob |

**Markers.**

- `FAKE-APIKEY-SECRET-<tsg>-*` must never appear in stdout, stderr, the debug log, any file outside
  an explicit `--key-file`, or a live summary or ledger.
- `FAKE-PROMPT-CONTENT-*` and `FAKE-RESPONSE-CONTENT-*` may appear only on `scan-content`'s stdout
  (`--show-content`) or in its `--output-file`, never in stderr or the debug log.

**Runner.** Add `--key-file` to `PATH_FLAGS` (`--output-file` is already there).

---

## 13. Live-tier design for M6d (within the LIVE RULES)

### 13.1 Read comparison (`AIRS_RS_LIVE=1 AIRS_E2E_TENANT`; both CLIs; TS sandboxed as today)

Read-only. Bounded to one page and the first listed item. Tenant content (names, prompts, responses,
auth codes, app names) is compared in memory, and the summary records only check names, counts,
booleans and expected-row ids.

- **`api-keys list --limit 20`.** TS runs with `--output table`: its table projects only `id`,
  `name`, `last8` and `expiresAt` (`view:24-31`) and cannot show a key, while TS json would show
  `apiKey` if the service sent one. Rust runs with `--output table` and with `--output json`. The
  check:
  - the table rows agree, with `Expires` per D207;
  - the Rust json has no `apiKey`;
  - no value in it matches the shape of a full key (a long field that is not one of the projected
    fields). The check is Rust-only.
- **`customer-apps list --limit 20`** and **`customer-apps get <first app_name>`**, json on both,
  compared per D207 (`id`).
- **`customer-apps consumption <first bucket name> --time-interval 7`.** The bucket name comes from
  Rust `dashboard applications --limit 1`. Both CLIs, json, with D209 nulls tolerated against TS
  zeros. All-apps mode never runs live (unbounded requests).
- **`deployment-profiles list`**, json on both.
- **`scan-logs query --interval 1 --unit hours --limit 5`.** Both CLIs. Both must exit 1 with the
  same stub line; no request (Rust debug log empty of requests).
- **dashboard.**
  - `dashboard applications --limit 5`, `top-applications`, `violations-trend` and `apps-list`;
  - `application` and `application-violations` for the first bucket (`--interval 7`);
  - `sessions chart`, `sessions list --limit 5` (one page);
  - `sessions get` for the first listed session (`--limit 5`);
  - `sessions transaction` for its first action;
  - `sessions scan-content` of that action with `--show-content` (stdout captured in memory only).

  All json on both. The rolling windows move between the two runs, so lists compare by structure and
  identity overlap, not exact counts.
- **`runtime report`.** Both CLIs, each with `--output-file <session tmp>/<rs|ts>.html` in the private
  sandbox, TS with `--output html`. The structural check, then the files are removed:
  - both 0600 and starting `<!doctype html>`;
  - the same section ids;
  - the same seven evidence sources, method labels and statuses (counts may drift; D214 tolerated);
  - a CSP meta, no external URL or `src=`;
  - the Rust file contains no `SecretSet` value.
- **`profiles backup "<first profile name>"`.** Both CLIs, into the session tmp. The structural
  check, then the files are removed:
  - the Rust `profiles[0].record` equals the TS `profiles[0]` (key order ignored; G27 `examples`
    tolerated);
  - the topic sets agree by `[topic_id, revision]`;
  - both files are 0600;
  - read-only (no write route touched).

### 13.2 Write flow (`AIRS_RS_LIVE_PROFILE_TRANSFER=1`, on top of the read opt-in)

- **Gate and budget.** `gate_with(lookup, "AIRS_RS_LIVE_PROFILE_TRANSFER", "profile transfer skipped")`
  refuses before any request. The `ResourceBudget` allows `MAX_RESOURCES` (10) and is reserved before
  every create, the restores' creates included.
- **Names.** The existing sweeper shape, `airs-rs-e2e-<unix>-<pid>-<n>-<topic|profile>-rs`.
  Restores recreate the same names, so every resource the flow can leave matches the sweeper's
  regex. Profiles and topics are already sweeper kinds (`here:crates/airs-test-harness/src/live/cleanup.rs:47-70`):
  nothing to add.
- **Flow.** Each step writes to the ledger (IDs and outcomes only). Profile deletes use the existing
  write flow's helper (`delete` on a pty, never `--force`).

  | Step | Action | Creates (running total) |
  |---|---|---|
  | 1 | Rust `topics create` T | 1 |
  | 2 | Rust `profiles create` P1 (plain) and P2 | 3 |
  | 3 | Rust `topics apply` T to P2 (a revision, not a new resource) | 3 |
  | 4 | Rust and TS `profiles backup` of P1 and of P2, each into the session tmp (four files) | 3 |
  | 5 | Delete P1, P2 (every revision, as the existing teardown lists them) and T | 3 |
  | 6 | Rust `profiles restore` of its P2 file with `--dry-run` (plan only: one topic create, one profile create), then for real with `--expect-tsg <tsg> --force`, then its P1 file. T is created again | 6 |
  | 7 | Verify with Rust `profiles get` and `topics get`: the policy projection equals step 4's, modulo the rewritten `topic_id`; one revision each; no duplicate | 6 |
  | 8 | Rust `profiles restore` of the same file again with `--on-conflict verify`: no write; the restore json reports `verified` | 6 |
  | 9 | Rust `profiles restore` of a TS file: refused (D216), zero requests | 6 |
  | 10 | Delete the restored P1, P2 and T | 6 |
  | 11 | TS `profiles restore` of its own P2 and P1 files (`--expect-tsg <tsg> --force`; TS accepts its own format) | 9 |
  | 12 | Verify with Rust `get` | 9 |
  | 13 | Delete everything | 9 |

  The plan stays at 9 of 10. When step 5 cannot delete T (an older profile revision still references
  it, the M4 observation), the restores reuse it (identical topic) and the count is lower.
- **Teardown.** Always runs, also after an abort or a panic. Every planned name found in a Rust
  `profiles list --all-versions --all` or `topics list --all-versions --all`, and every captured id,
  is deleted. `resourcesLeft` counts the rest.
- **Never live.**
  - `api-keys create`, `regenerate`, `delete`;
  - `customer-apps update`, `delete`;
  - `profiles restore --on-conflict update`;
  - any write to a profile or topic the run did not create;
  - a backup without a selector (all profiles: tenant-wide content);
  - `consumption` all-apps mode.

### 13.3 Loopback self-tests (`LiveTarget::loopback`)

- **Gates.** With `AIRS_RS_LIVE_PROFILE_TRANSFER` unset there are zero recorded write requests. With
  every gate unset there are zero requests.
- **Never-live routes.** No live flow ever records `POST /v1/mgmt/apikey`, `…/regenerate/*`,
  `DELETE …/apikey/delete/*`, `PUT` or `DELETE /v1/mgmt/customerapp`, or `POST /v1/mgmt/scanlogs`.
  Asserted across the read flow and the write flow.
- **Prefix.** Every `POST /v1/mgmt/profile` and `POST /v1/mgmt/topic` body name starts with the run
  prefix. There is no `PUT` or `DELETE` on a seeded id.
- **Budget.** At most 10 creates.
- **Ledger.** An `ok` delete for every `ok` create.
- **Failure.** An injected 502 on the Rust restore's profile create gives the outcome-unknown stop
  (D217), and the teardown still removes everything. An injected panic after step 2 still tears down.
- **Sweeper.** It ignores young, unprefixed and wrong-kind resources (existing tests extended to the
  restored names).
- **Markers.** `FAKE-APIKEY-SECRET-*` (the list knob) never appears in a summary, ledger or captured
  stderr. `FAKE-PROMPT-CONTENT-*` never appears in the summary.
- **Files.** No file is written outside the sandbox (runner guard). Report and backup files are
  0600 and removed by the flow.

---

## 14. Choices decided (for the "Choices decided" subsection at the end of §18; each with the rejected alternative)

1. **`without_response_defaults()` on every M6d call**, through one options helper. Rejected:
   per-call selection.
2. **One OAuth identity per invocation**: the dashboard and DLP origins are admitted into the
   management client's policy only for the commands that need them (`build_for`). Rejected: separate
   `DlpClients` (a second token request) and widening the policy of every management command.
3. **The API key channel is a required `--key-file <new path>`** on create and regenerate, 0600,
   reserved before the request, kept as a named temporary if the final link loses a race. Rejected:
   stdout (TS: terminal and CI exposure); an optional `--key-file` (a forgotten flag orphans a
   shown-once key); a `--show-key` stdout opt-in (as TS `--show-content`), refused for consistency
   with D194's `--url-file -` refusal.
4. **`apiKey` is omitted from every read**, and any listed value joins the `SecretSet`. Rejected:
   `[withheld]` placeholders (they suggest the field is normally present).
5. **`api_key_last8` stays visible.** It is the service's designed fingerprint, used to match a key
   to its deployment, and 8 of about 48 characters do not make the key recoverable. Rejected:
   withholding it (keys could be told apart only by name).
6. **`auth_code` is printed** where TS prints it (deployment profiles, `customer-apps` `raw`). It is
   the entitlement code that `api-keys create --config` requires, not a bearer credential; the
   report keeps only counts, as TS. Rejected: withholding it (the CLI could no longer feed `create`).
7. **The `scan-logs query` stub** keeps TS's text verbatim, `airs-cli` included, reads the tenant
   first as TS does, and sends nothing. Rejected: implementing the broken legacy query (TS removed it
   on purpose); renaming the program in the text (D73 covers tenant hints only; the name is right
   from 1.0).
8. **Confirmations** (D206) for `api-keys delete` and `regenerate` and for `customer-apps delete` and
   `update`; `update` is treated as a replace. Rejected: a read-modify-write update (there is no read
   by id, G30, and it would change TS's replace semantics); no confirmation for `update`.
9. **`sessions list --all`** keeps TS's stricter page checks and its exit-1 partial results at
   `--max` and at 100 pages, through a generalised `src/walk.rs`. Rejected: plain `walk.rs`
   semantics (`--max` is a success there, and the echo checks are missing).
10. **Dashboard and sessions reads use `with_retries(0)` plus the G7 re-read** (TS `numRetries: 0`).
    The api-keys, customer-apps and deployment-profiles reads keep the SDK retries (D10). Profile
    transfer reads use the SDK retries (D175's precedent). Rejected: one policy for all (each
    follows its own precedent).
11. **Dashboard and sessions failures print TS's generic line verbatim.** It is already secret-safe
    and its spec pins it. Rejected: §6 messages, which add an API error code but break parity
    without a safety gain.
12. **`scan-content --output-file` always writes the JSON text**, and `--output table` with it is a
    usage error. Rejected: a table in a file.
13. **The table format for dashboard and sessions** (D212) is `Key │ Value` with compact JSON values,
    plus a fixed row table for `sessions list`. Rejected: refusing `table` as TS does (it breaks the
    M3.5 rule).
14. **The runtime report reads its seven sources sequentially in TS order**, and so do
    `consumption`'s two reads. Rejected: TS's concurrent `Promise.all`, which gives a
    nondeterministic request order in tests for no observable gain (each read evaluates its own
    server window either way).
15. **TS profile backups are refused** by restore (MILESTONES: no compatibility with TS-made files;
    D176). Rejected: importing TS envelopes (a second, looser format, and YAML).
16. **Backup format `airs-cli-rs.runtime-profiles` v1 with no `complete` key.** The backup is
    complete or not written, as TS. Rejected: DLP's `complete`/`failed` rows (no per-resource
    partial read exists here).
17. **Restore keeps `--on-conflict update`** (PUT of a destination profile) inside the confirmation
    count, one attempt, the `unchanged` re-check just before the PUT. Rejected: dropping `update`
    (it is TS's documented migration path).
18. **The consumption name lookup refuses ambiguity** (D211). Rejected: TS's first match, and a
    new `--app-id` flag (not in TS; the dashboard commands already take `--app-id`).
19. **Live `api-keys list` compares TS `--output table`**, which cannot show a key, and checks the
    Rust json for withholding. Rejected: running TS json (it may print a key), and Rust only (it
    would lose the comparison).
20. **The live transfer flow restores without `--name-prefix`** after deleting the originals, so
    every name keeps the sweeper's shape. Rejected: prefixed restores (the names would escape the
    sweeper's regex).
