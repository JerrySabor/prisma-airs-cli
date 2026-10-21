# Rust SDK for M6e (0.10): Gateway

Scope: every `aigateway` command of the frozen TS CLI (5711012), which the port renames `gateway`
(MILESTONES "Renames"), and its `report|dashboard`. That is 105 visible leaves plus the hidden
`workspaces delete` (§1). For each one this file gives the `scm-sdk` 0.1.1 API that serves it and
compares it with the HTTP calls the TS CLI makes through its SDK 0.34.0. It ends with the gaps, the
proposed module layout, the fixture routes, the live-tier design, acceptance criteria and the likely §12
rows.

Method. Everything here was read from source, plus these runs, all in the session scratchpad:

- `--help` of every leaf, collected by walking the command tree (105 visible leaves).
- About 120 runs of the reference build (`node dist/cli/index.js`) under `env -i`. `HOME`, `TMPDIR`,
  every XDG directory, `AIRS_CLI_CONFIG_DIR` and `PRISMA_AIRS_TENANTS_PATH` were set inside a
  sandbox, and the sandbox tenant (`gw`, TSG `1234567890`, fake `client-…`/`FAKE-SECRET-…`) pointed
  every endpoint at a node stub on `127.0.0.1:48731`. The stub was written for this study. It answers
  the token route, takes every gateway, IAM and inference route body either from a minimal instance
  generated from the SDK's own zod response schema or from a per-run override (status, headers, delay,
  SSE body), and logs method, path, query, the presence of `authorization`, `x-tsg-id` and
  `x-portkey-api-key`, and the request body. `TZ=UTC` unless stated. Colours were captured with
  `FORCE_COLOR=1`.
- A read-only Python walk of the SDK's frozen schema graph (`rs:validation/schema_graph.json` with
  `semantics.json`) from every response and request schema the commands use (§3.4).
- No Rust was built, no non-loopback host was contacted, and no tenant or credential file was read.

Citation prefixes:

- `rs:` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scm-sdk-0.1.1/src/`;
  `gw:` = `rs:airs/gateway/`; `gen:` = `rs:models/generated.rs`.
- `tsdk:` = `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js` (0.34.0).
- `cli:` = `.reference/prisma-airs-cli/src/`; `cmd:` = `cli:cli/commands/aigateway.ts`;
  `inv:` = `cli:cli/commands/aigateway/inventory.ts`; `sh:` = `cli:cli/commands/aigateway/shared.ts`;
  `tel:` = `cli:cli/commands/aigateway/telemetry.ts`; `svc:` = `cli:airs/aigateway.ts`;
  `rnd:` = `cli:cli/renderer/aigateway.ts`; `rep:` = `cli:reports/aigateway.ts`.
- `here:` = this repository.

Companion specs: `rs-sdk-foundation.md` (engine, auth), `rs-sdk-writes.md` (G1–G6, D95),
`rs-sdk-redteam.md` (G7–G10), `rs-sdk-dlp.md` (G11–G17), `rs-sdk-model-security.md` (G18–G24) and
the M6d research (G25–G35). Gaps in this file are numbered provisionally **GW1…**. They would become
G36 and onward.

---

## 0. Summary

- **Every API-backed command has an scm-sdk 0.1.1 operation**, behind the `gateway` feature.
  - That feature is `gateway = ["models", "iam"]`, and `iam` pulls `dep:getrandom`
    (`rs:../Cargo.toml:54-61`). `getrandom 0.4.3` is already in `here:Cargo.lock`, so enabling the
    feature adds one dependency edge (scm-sdk → getrandom) and no new crate.
  - `realtime` and `ws-transport` are **not** needed: no TS command opens the realtime socket
    (`connectRealtime` is unused by `cli:`).
  - Paths, methods, query keys and request/response schema names match the TS SDK one for one (§2, §4).
- **Four clients.**
  - `AIGatewayClient::new(oauth_data_client, admin, iam)` serves the data plane (`gatewayDataEndpoint`,
    default `…/ai_gw/v2`), the admin plane (`gatewayAdminEndpoint`, `…/ai_gw/admin/v2`) and IAM
    (`iamEndpoint`, `…/iam/v1`) (`gw:mod.rs:135-149`).
  - It uses one management OAuth identity **with** the `x-tsg-id` header (`gw:common.rs:10-13`). This is
    TS parity: `TsgHeaderAuth` (`tsdk:14663-14678`, `:22722`), captured on every request.
  - Inference is a separate `RuntimeClient` over `Authentication::runtime_key` (`x-portkey-api-key`,
    `rs:auth.rs:720-723`, `:801-805`), built only from `gatewayInferenceEndpoint`/`gatewayInferenceApiKey`.
    It never touches OAuth.
- **Retries.**
  - Every gateway, IAM and runtime write is `RawRequest::new(METHOD, …)`, so `replay_safe = false`
    (`rs:engine.rs:49-61`). There is no transport retry, no 5xx retry and no 401/403 refresh replay
    (`rs:engine.rs:1176`, `:1220-1236`). One attempt holds by construction.
  - Reads use `RawRequest::read` and are replayed under `Limits::max_retries` (429/502/503/504, network,
    one refresh on 401/403; `rs:engine.rs:1345-1349`, `:1372-1374`).
  - Runtime calls never replay unless the caller passes a `RuntimeReplay` permit (`rs:routing.rs:65-83`).
  - The TS CLI re-sends **every** gateway write up to 5 times on 500/502/503/504 and network errors
    (`numRetries` default 5, `tsdk:11111-11114`, `:9786-9848`), and once after a 401/403. Captured:
    - `api-keys service create` POSTed 3 times when the stub answered 502, 502, 200. Several one-time
      keys may have been minted, and only the last was saved.
    - `workspaces create` POSTed the workspace 6 times on 503, then **deleted the IAM scope** it had just
      created, although any of those 503 answers may have applied (§4.1). That is the D179 class.
- **Schema defaults (G10) do not reach any gateway output.** The walk from all 70 response roots used
  here (§3.4) finds no `ZodDefault`. No request schema used here has one either.
  - `RequestOptions::without_response_defaults()` (`rs:config.rs:406`) changes nothing today.
  - It is still recommended on every gateway call through one options helper (as `modelsec::options`),
    so a later schema default can never fabricate a value. It also governs SSE events
    (`rs:config.rs:396-405`).
- **Response vocabulary differs, as in D178.** Rust's response modes keep unknown fields and widen
  closed vocabularies (`rs:validation.rs:29-31`). TS rejects:
  - a guardrail `target` other than `llm|mcp_tools` (captured: `AISEC_RESPONSE_VALIDATION:Response did
    not match schema: data.0.target: invalid_enum_value`, exit 1);
  - an admin guardrail `status` other than `active|archived`;
  - unknown keys in the strict `pricing_adjustments.multiplier` of integrations;
  - the strict empty `McpIntegrationWorkspacesUpdateResponseSchema`;
  - unknown inference `finish_reason` literals.

  See GW5.
- **Gaps (§9).** Nothing is blocked on scm-sdk, and every workaround is CLI-side and safe.
  - GW1: one-time credentials can be lost to a response decode failure (G26 class).
  - GW2: provisioning is one SDK call over 3–4 writes.
  - GW3: `resolve_provider_id` has no error text.
  - GW4: the API has no continuation contract for lists.
  - GW5: the vocabulary difference above.
  - GW6: telemetry window offset bytes.
  - GW7: the grant hint is keyed on the error code.
  - GW8–GW13: shape, ergonomics and notes.
- **TS behaviours that must not be ported.** Each one becomes a §12 row (§14):
  - success lines and `⚠ 403:` hints on stdout;
  - `No workspaces found` printed under `--output json`;
  - YAML printed for `workspaces get --output table`;
  - the one-time credential and the inference key read from `PANW_AI_GW_INFERENCE_*` environment
    variables (captured);
  - audit-log request bodies and headers printed with embedded credentials (captured);
  - a 0600 empty `--secret-output` file left behind on SIGINT (captured);
  - local-timezone telemetry windows and lenient JS `Date` parsing of `--start`/`--end`.

---

## 1. Command inventory

The TS tree (`cmd:128-137` registers inventory, admin guardrails, report and inference first, then
workspaces, scopes and telemetry; help lists them sorted). All leaves were captured with `--help`. List
leaves have the alias `ls` and delete leaves `rm` where TS declares them (`admin-guardrails`, all
inventory `delete`s, `scopes delete`). The groups are:

| Group | Leaves | Plane (SDK sub-client) | Output helper (TS) |
|---|---|---|---|
| `workspaces\|workspace` | `list`, `get <ref>`, `create`, `update <ref>`, `archive <ref>`, hidden `delete <ref>` | data/admin (`workspaces()`), IAM (`iam_scopes()`) | own renderer (`rnd:39-122`), banner |
| `scopes` | `list`, `get <name>`, `create`, `bind <name>`, `delete\|rm <name>` | IAM (`iam_scopes()`); `bind` also admin `workspaces().list` | own renderer (`rnd:129-184`), banner |
| `telemetry` | `cost`; `cache summary\|trend`; `error-trends`, `errors`, `error-category-trends`, `grouped-errors`, `filter-boundaries`, `rescued-retries`, `user-trends`, `users`; `feedback distribution\|models\|trend\|weighted`; `latency`, `requests`, `tokens` (chart filters); `group-by <dimension>`; `logs list` | data (`telemetry()`); `cost` also `workspaces().list` | `cost`: own renderer + banner (`rnd:191-228`); others `runDetail` (`sh:182-194`), no banner |
| `api-keys service\|user` | `list`, `get <id>`, `create`, `update <id>`, `delete\|rm <id>`, `rotate <id>` (×2) | data (`api_keys()`) | `runList`/`runDetail`/`runWrite`/`runConfirmedWrite`/`runSecretWrite` |
| `audit-logs` | `list\|ls` | admin (`audit_logs()`) | `runList` |
| `configs` | `list`, `get`, `versions <id>`, `create`, `update`, `delete\|rm` | data (`configs()`) | inventory helpers |
| `deployments` | `list`, `get`, `ping <id>`, `create`, `update`, `archive <id>` | admin (`deployments()`) | inventory helpers, `runSecretWrite` |
| `guardrails` | `list`, `get`, `catalog`, `create`, `update`, `delete\|rm` | data (`guardrails()`); `catalog` admin | inventory helpers |
| `admin-guardrails` | `list\|ls`, `get`, `create`, `update`, `delete\|rm`, `mcp-servers list\|ls\|sync\|upsert` | admin (`admin_guardrails()`) | inventory helpers |
| `integrations` | `list`, `get`, `providers`, `create`, `update`, `delete\|rm`, `models list\|set`, `workspaces list\|set` | admin (`integrations()`) | inventory helpers |
| `mcp integrations` | `list`, `get`, `create`, `update`, `delete\|rm`, `capabilities list\|set`, `metadata`, `workspaces list\|set` | admin (`mcp_integrations()`) | inventory helpers |
| `organisations` | `info`, `self get\|update`, `auth-settings get\|update` | admin (`organisations()`) | inventory helpers |
| `plugins` | `list`, `create` | admin (`plugins()`) | inventory helpers |
| `providers` | `list`, `get`, `create`, `update`, `delete\|rm` | data (`providers()`) | inventory helpers |
| `inference` | `chat [prompt]`, `responses [prompt]`, `embeddings [prompt]` | runtime (`RuntimeClient`) | own writer (`cli:…/aigateway/inference.ts:123-224`) |
| `report\|dashboard` | — | data + admin, `numRetries: 0` | environment report (HTML/Markdown) |

TS registers no `workspaces list --all` pagination flags, no `--offset`, and no client-side walk. The
only paged reads are `telemetry logs list` (`--page-size` default `50`, `--current-page` default `0`)
and `admin-guardrails list` (`--page-size` 1–1000, `--current-page` ≥ 0), each one request.

---

## 2. Client construction

### 2.1 The TS side

- **Management.** `aiGatewayClientOptions(config)` (`cli:config/client-options.ts:79-86`) passes
  `mgmtClientId/Secret/TsgId` (after `assertManagementCredentials`, `:34-42`), `mgmtTokenEndpoint ??
  DEFAULT_TOKEN_ENDPOINT`, `aiGwDataEndpoint ?? …/ai_gw/v2`, `aiGwAdminEndpoint ?? …/ai_gw/admin/v2` and
  `iamEndpoint ?? …/iam/v1` (`tsdk:125-129`).
  - `new AIGatewayClient` (`tsdk:22706-22761`) builds one `TsgHeaderAuth(OAuthAuth)` and gives it to every
    sub-client.
  - The `PANW_AI_GW_*` and `PANW_MGMT_*` env fallbacks (`tsdk:22709-22711`, `:11099-11104`) never apply,
    because every value is passed.
  - `numRetries` is unset, so it defaults to 5 (`tsdk:11111`). The report passes `numRetries: 0`
    (`cli:cli/commands/aigateway-report.ts:87-90`).
  - Each command constructs the client lazily after its own checks (`sh:30-33`, `cmd:34-37`).
- **Inference.** `new AIGatewayInferenceClient({ endpoint: config.aiGwInferenceEndpoint, apiKey:
  config.aiGwInferenceApiKey, timeoutMs, numRetries: 0 })` (`…/inference.ts:152-157`). The command's
  `--endpoint` is merged as a config override (`loadConfig({ aiGwInferenceEndpoint: opts.endpoint })`,
  `:132`).
  - **The SDK falls back to `process.env.PANW_AI_GW_INFERENCE_ENDPOINT` / `…_API_KEY`** when either is
    absent (`tsdk:22444-22445`).
  - Captured: with both keys removed from the tenant and the two variables set to fake values, the TS
    CLI sent the request with the environment key.
  - The endpoint must be https, or http on `localhost|127.0.0.1|[::1]`, without userinfo, query or
    fragment (`tsdk:22446-22466`, the rule at `:22460`).
  - The key is sent as `x-portkey-api-key` (`:22471-22476`). `--timeout` (default `60000`) is the total
    deadline including streaming. The debug body is omitted (`omitDebugBody`, `:22491-22512`).
- **Harness.** A child gets only the runner's allowlisted environment (`here:crates/airs-test-harness/src/runner.rs:1251-1290`),
  so no `PANW_*` variable is inherited. `TS_ENDPOINT_VARIABLES` (`:524-545`) lists
  `PANW_AI_GW_ADMIN_ENDPOINT`, `…_DATA_ENDPOINT`, `…_INFERENCE_ENDPOINT` and `PANW_IAM_ENDPOINT` for the
  trap of TS `runtime` runs. The env-fallback test of this section has to pass
  `PANW_AI_GW_INFERENCE_API_KEY` and `…_ENDPOINT` explicitly, with fake loopback values (§11).

### 2.2 The Rust side (proposed `clients::GatewayClients`)

This mirrors `ModelSecurityClients::build` (`here:src/clients.rs:672-740`):

1. **Admit** `gatewayDataEndpoint` (default `scm::constants::DEFAULT_AI_GW_DATA_ENDPOINT`),
   `gatewayAdminEndpoint` (`DEFAULT_AI_GW_ADMIN_ENDPOINT`), `iamEndpoint` (`DEFAULT_IAM_ENDPOINT`) and
   `mgmtTokenEndpoint` with `clients::admit` (D48 messages name the key). All are known tenant keys
   (`here:src/tenant/config.rs:30-36`); the TS names are import renames (`:43-48`).
2. **Run the §3.5 management credential check** before any client is built.
3. **Call `oauth_parts(config, &issuer, &[data, admin, iam], …)`.** It returns one recording provider
   (every lease in the `SecretSet`), one transport and one `OriginPolicy` admitting the three bases and
   the issuer.
4. **Set the limits:** `Limits::default()` with `max_retries = MANAGEMENT_RETRIES` (5, reads only) and
   the 8 MiB response bound.
   - The largest payloads are `telemetry logs` pages (`pageSize ≤ 1000` rows of 25 fields) and audit
     logs, well inside 8 MiB.
   - A 1000-row admin page of guardrails is also bounded.
5. **Build the client:** `Client::builder(data).transport(..).destination_policy(..)
   .authentication(Authentication::oauth(provider, true)).session(..).limits(..).build()`, then
   `scm::airs::gateway::AIGatewayClient::new(client, admin, iam)`.
   - `new` re-checks OAuth, forces the TSG header on (`gw:common.rs:10-13`) and derives the admin and IAM
     clients with `with_endpoint` (`gw:mod.rs:140-142`).
   - On failure, report `AISEC_SDK_ERROR:The gateway client could not be configured` (exit 1).
6. **Authenticate:** `authenticate(options, budget)` as the other builders, so a token failure is the §6
   `AISEC_OAUTH_ERROR:…`.
7. **Sub-clients** are cheap clones: `workspaces()`, `telemetry()`, `configs()`, `guardrails()`,
   `providers()`, `api_keys()` on data; `deployments()`, `organisations()`, `integrations()`,
   `mcp_integrations()`, `admin_guardrails()`, `plugins()`, `audit_logs()` on admin; `iam_scopes()`
   (`gw:mod.rs:170-266`). For raw requests (GW1): `AIGatewayClient::client()` is the data client, and
   `deployments().client()` is the admin client (`gw:deployments.rs:15`).

**Runtime (`clients::GatewayRuntime`).**

- Admit `--endpoint` or `gatewayInferenceEndpoint` by §5 (loopback http only for tests). Its absence is
  `gatewayInferenceEndpoint is not configured` (exit 1, before any request).
- Wrap `gatewayInferenceApiKey` in `Secret` and register it in the `SecretSet`. Its absence is
  `gatewayInferenceApiKey is not configured`.
- Build `Client::builder(endpoint).authentication(Authentication::runtime_key(secret)?)`, then
  `RuntimeClient::new(client)` (`gw:runtime.rs:44-51`; it refuses non-runtime auth).
- No OAuth and no §3.5 check: inference needs no management credentials (TS: `loadConfig` only).
- Never read the environment (§0, GW13).

### 2.3 Options and budgets

| Call | `RequestOptions` |
|---|---|
| Single read | `gateway::options(SINGLE_REQUEST_BUDGET)` = `with_timeout(..)?.without_response_defaults()` |
| Write | the same, sent through `writes::attempt` (one attempt; the D95 single replay after 401 decided per command, GW2) |
| Report sources, doctor probe | `.with_retries(0)?` (TS `numRetries: 0`; doctor D49) (`rs:config.rs:387`) |
| Inference | `with_timeout(--timeout)`. One deadline covers the whole stream: `ContractStream::next` runs under the same options (`rs:streaming.rs:64-120`) |

---

## 3. Engine behaviour for gateway calls

### 3.1 Request shapes (captured TS, matching the Rust adapters)

- **Headers.** `authorization: Bearer …` and `x-tsg-id: <mgmtTsgId>` go on every management request,
  IAM included. `content-type: application/json` goes on bodies. Inference sends only `x-portkey-api-key`
  and `content-type`.
- **Window queries.** TS sends `organisationId`, `workspaceSlug`, `timeOfGenerationMin` and
  `timeOfGenerationMax` in that order (`tsdk:17979-17995`). Rust sends the same keys in the same order
  (`gw:telemetry.rs:25-66`), reading `organisationId` from the OAuth context TSG (`:176-183`).
  `filter-boundaries` drops `organisationId` on both sides (`tsdk:18058-18060`, `gw:telemetry.rs:478-497`).
  - **The timestamp bytes differ (GW6).** TS formats the instant in the **process's local timezone** at
    second precision (`toOffsetIso`, `tsdk:17968-17975`). Captured with `TZ=America/New_York`:
    `timeOfGenerationMin=2026-10-11T23:05:58-04:00`; with `TZ=UTC`: `…T03:05:58+00:00`.
  - Rust uses `offset_minutes` (default 0), so it always sends `+00:00` (`gw:common.rs:193-212`).
- **Chart filters.** Both send `traceId`, `metadata` (compact JSON), `statusCode` (comma-joined
  `statusCodes`), `apiKeyIds` (comma), `aiOrgModel` (comma `aiOrgModels`), `totalUnitsMin`,
  `totalUnitsMax`, `costMin`, `costMax`, then `columns` (comma) for group-bys (`tsdk:18024-18035`,
  `gw:telemetry.rs:184-238`, `:506-545`). Numbers are JS-formatted on both sides (`ryu_js`,
  `gw:common.rs:78-91`). Captured: `…&metadata=%7B%22env%22%3A%22p%22%7D&statusCode=200%2C446&costMin=0.5`.
- **Audit logs.** `start_time`/`end_time` are `Date.toISOString()` with milliseconds (captured
  `2026-10-18T03:07:27.198Z`), and Rust `date_iso` matches (`gw:audit_logs.rs:29-47`,
  `gw:common.rs:178-192`).
- **Admin guardrails list.** The query is `workspace_id`, `page_size`, `current_page`, each only when set
  (`tsdk:17670-17686`, `gw:admin_guardrails.rs:15-49`).
- **Bodies.** TS sends key order as built (file < named flags < `--set` merges, `cli:…/structured-input.ts:189-247`).
  Rust sends sorted keys (D35). Equality with TS is JSON equality.

### 3.2 Retries and attempts

| Request | TS (captured / source) | Rust 0.1.1 |
|---|---|---|
| Any read | 1 + 5 on 500/502/503/504/network; one token refresh + replay after 401/403 (captured: a 403 read was sent twice, with two token requests) | 1 + `max_retries` on 429/502/503/504/network; one refresh after 401/403 unless `x-opa-decision: false` (`rs:engine.rs:1345-1349`) |
| Any write | **1 + 5** on 500/502/503/504/network; one refresh-replay after 401/403 | **1**, no replay of any kind (`replay_safe = false`) |
| `iam_scopes().bind_workspace` | GET (retried) then PUT (retried ×5) | GET (read, retried) then PUT (one attempt), one deadline (`rs:shared/iam/scopes.rs:128-164`) |
| `workspaces().provision` | `iamScopes.create` → `workspaces.create` → `bindWorkspace`, each retried; on **any** create error the fresh scope is deleted (`tsdk:18662-18728`) | the same order, each write once; scope deleted only after a `Rejected` create, retained after `Unknown` (`gw:provision.rs:279-309`) |
| Inference | `numRetries: 0` (one attempt) | `RuntimeReplay::Never` (one attempt) |
| Report | `numRetries: 0` | `with_retries(0)` |

### 3.3 Errors

The §6 mapping applies unchanged. The TS texts differ in these places:

- **Server text.** TS prints the server's `message` (`extractErrorMessage`, `tsdk:9713-9725`).
  Captured: `✗ Error: AISEC_CLIENT_SIDE_ERROR:Forbidden: missing scope`, `AISEC_SERVER_SIDE_ERROR:upstream`.
  Rust prints `API error <status>` plus the allowlisted problem fields and `(errorCode: <code>)`.
- **The grant hint (GW7).** On a 403, TS warns `⚠ 403: <hint>` **on stdout** before the error
  (`sh:76-80`, `cmd:40-44`). The hint comes from `aiGatewayGrantHint` (`svc:87-100`): a message
  containing `AB03` gets the workspace-scope (data plane) text, anything else the tenant-root admin text.
  - TS merges only `data.errorCode` into the message (`tsdk:9719-9721`). So a top-level `errorCode: "AB03"`
    data-plane 403 gets the **admin** hint (captured with `configs list`).
  - Rust's `Error::service_code()` reads `code`, `error.code`, `data.errorCode` and `errorCode`
    (`rs:engine.rs:1402-1427`). Proposal: choose the hint from `service_code() == "AB03"`, else from the
    plane of the failing request, and print it on stderr.
- **Local SDK validation** (UUIDs, workspace refs, scope names, TSG digits, telemetry window, request
  schemas). TS throws `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid <field>: <value> (…)` **after** the tenant
  and, for most commands, after the banner, exit 1. Captured examples:
  - `configs get not-a-uuid` gives `Invalid configId: not-a-uuid`.
  - `workspaces get "Main A"` gives `Invalid workspaceRef: Main A (expected a workspace UUID or slug)`.
  - `scopes get "bad name"` gives `Invalid name: bad name (expected an IAM scope name such as
    ws_production_bx7qw0)`.

  Rust's adapters refuse the same inputs with a bare `ErrorKind::Validation` (`gw:common.rs:93-150`,
  `rs:shared/iam/scopes.rs:9-19`). Proposal: the CLI checks them during planning (§6) with the TS words
  and exit 2, as D184.
- **Request-schema failures.** TS: `Invalid AI Gateway request: <path>: <zod message>[; …]` (exit 2,
  `cli:…/structured-input.ts:157-182`). Captured: `checks: Array must contain at least 1 element(s);
  actions: Provide at least one field`, `key_transition_period_ms: Number must be greater than or equal
  to 1800000`. Rust keeps no field paths, so the text is without the list (D116 extended; §14).

### 3.4 Schema-graph results

The walk covered these roots:

- `ListWorkspacesResponseSchema`, `GatewayWorkspaceDetailSchema`, `GatewayWorkspaceCreateResponseSchema`
  and `GatewayWriteResponseSchema`;
- `IamScopeListResponseSchema` and `IamScopeSchema`;
- the 17 chart schemas, `GatewayFilterBoundariesResponseSchema`, `GroupListResponseSchema`,
  `UserGroupResponseSchema` and `GatewayLogsResponseSchema`;
- every inventory list, detail and write response named in §4.4;
- the four inference response and stream-event schemas;
- the request schemas of §4.

| Finding | Where | Effect |
|---|---|---|
| No `ZodDefault` in any response or request root above | — | `without_response_defaults()` is a no-op today (GW12) |
| Closed enums | `ListGuardrailsResponseSchema.data.target`, `GatewayGuardrailDetailSchema.target` (`llm\|mcp_tools`); `GatewayAdminGuardrail{List,Detail}.status` (`active\|archived`), `.target`; inference `finish_reason` literal unions | TS rejects an unknown value (captured); Rust widens (GW5) |
| Strict objects without catchall | `GatewayIntegrationSchema.pricing_adjustments`, `.multiplier`, `.multiplier.image` (also in `ListIntegrationsResponseSchema`); `McpIntegrationWorkspacesUpdateResponseSchema` (empty strict) | TS rejects an unknown key; Rust keeps it (GW5) |
| `strip` objects with a `finite_json` catchall | e.g. `GatewayConfigCreateRequestSchema.config` | unknown keys are **kept**, not stripped (captured: `config.unknown_key` sent) |
| Everything else | `passthrough` | unknown keys kept by both; Rust prints them sorted (D35) |

---

## 4. Per-command mapping

Notation: `ws.` = `gateway.workspaces()`, `tel.` = `gateway.telemetry()`, `iam.` =
`gateway.iam_scopes()`, `opt` = the §2.3 options. All captured sequences start with `POST /oauth/token`.

### 4.1 `workspaces`

| Command (TS options, defaults) | TS sequence (captured) | Rust 0.1.1 |
|---|---|---|
| `list` (`--plane <data\|admin>`, `--status <active\|archived>`, `--all`) | `GET <data>/workspaces`; `--plane admin` → `<admin>/workspaces`; `--status s` → `?status=s`; `--all` → admin `GET /workspaces` and `GET /workspaces?status=archived` **concurrently** (`svc:115-126`) | `ws.list(&AIGatewayWorkspaceListOptions{plane, status}, opt)` → `ListWorkspacesResponse` (`gw:workspaces.rs:41-68`); `--all` = two calls (sequential is fine) |
| `get <ref>` (`--plane`) | `GET <plane>/workspaces/<ref>`. On **404** only: list `[plane ?? data, admin]` (a failing list is skipped), match `id`/`slug`, else a unique `name` → slug, re-`GET`, else rethrow (`svc:128-150`). Captured `get Production`: `GET …/workspaces/Production` (404) → `GET …/workspaces` → `GET …/workspaces/ws-produc-985697`. A ref with a space fails the SDK check (no request, exit 1) | `ws.get(ref, &AIGatewayWorkspaceGetOptions{plane}, opt)` → `GatewayWorkspaceDetail`; same `workspace_ref` grammar (`gw:common.rs:107-121` = `tsdk:11165-11172`). The 404 fallback is CLI code (§10 `gateway::resolve`) |
| `create` (`--name` required; `--scope-name`, `--existing-scope`, `--description`, `--icon`, `--metadata <json>`, `--defaults <json>`, `--users <csv>`, `--usage-limits <json array>`, `--rate-limits <json array>`; `--output` default `pretty`, allowed pretty/json/yaml) | `POST <iam>/scopes {"name","description":desc??"","resources":[]}` (skipped with `--existing-scope`) → `POST <admin>/workspaces {name, scope_name, …}` → `GET <iam>/scopes/<name>` → `PUT <iam>/scopes/<name> {name, description, resources:[…existing, {resource_type:"workspace", resource_id:<slug>, metadata:[]}]}` → `GET <admin>/workspaces/<id>` (a failure falls back to the partial create body, `svc:298-307`; captured with 500: six GETs, then `Status unknown`). The generated scope is `ws_<stem>_<6 random [a-z0-9]>` (`tsdk:18481-18488`) | Compose the steps (GW2): `iam.create(&IamScopeCreateInput)`, `ws.create(&GatewayWorkspaceCreateRequest)`, `iam.bind_workspace(name, slug)`, then `ws.get(id, Admin)`; or `ws.provision(&GatewayWorkspaceProvisionRequest, &AIGatewayWorkspaceProvisionOptions{existing_scope}, opt)` with its `ProvisionError::recovery()` (`gw:provision.rs:157-328`). Scope generator: `scm::airs::gateway::generate_workspace_scope_name` (rejection sampling, `rs:helpers.rs:466-502`; TS uses `byte % 36`, a modulo bias — not observable) |
| `update <ref>` (the write flags without `--scope-name/--existing-scope/--users`) | resolve on admin (`GET <admin>/workspaces`, match id/slug, else unique name → slug, else pass through, `svc:236-259`) → `PUT <admin>/workspaces/<ref> {only given keys}` (answer `{}`) → `GET <admin>/workspaces/<ref>` | `ws.list(Admin)`, `ws.update(ref, &GatewayWorkspaceUpdateRequest, opt)` → `GatewayWriteResponse`, `ws.get(ref, Admin)` |
| `archive <ref>` (`--force`); hidden `delete <ref>` (`--force`, deprecation warning) | resolve on admin → `DELETE <admin>/workspaces/<ref>`. No verify-by-get (an archived workspace answers 404 AB08, `svc:222-228`) | `ws.delete(ref, opt)` (`gw:workspaces.rs:124-134`) |

`--metadata` merges into `defaults.metadata` and wins over `--defaults` on that key. `defaults`,
`usage_limits` and `rate_limits` are validated with `GatewayDefaultsInputSchema`,
`GatewayUsageLimitInputSchema.array()` and `GatewayRateLimitInputSchema.array()` before the client
(`cmd:82-110`). `--users` is split on `,`, trimmed and emptied of blanks. A JSON parse failure is the
plain `Error`, `<flag> must be valid JSON` (exit 1).

When `--scope-name` shares no token with `--name` (alnum-folded name of at least 4 characters not
contained in the folded scope), TS warns on stdout (`cmd:118-125`, `:255-260`).

### 4.2 `scopes`

| Command | TS (captured) | Rust |
|---|---|---|
| `list` | `GET <iam>/scopes` | `iam.list(opt)` → `IamScopeListResponse {count, items}` (`rs:shared/iam/scopes.rs:53-61`) |
| `get <name>` | `GET <iam>/scopes/<name>` (name `^[A-Za-z0-9_][A-Za-z0-9_.-]*$`, `tsdk:11181-11188`) | `iam.get(name, opt)`; `validate_scope_name` (same grammar plus the segment rule) |
| `create` (`--name` required, `--description`; `--output` pretty/json/yaml) | `POST <iam>/scopes {"name","description":"","resources":[]}` | `iam.create(&IamScopeCreateInput{name, description, resources}, opt)` (empty description and resources defaulted, `:76-96`) |
| `bind <name>` (`--workspace <ref>` required) | resolve on admin (`requireSlug`) → `GET <iam>/scopes/<name>` → `PUT <iam>/scopes/<name>` with the existing resources (metadata defaulted to `[]`) plus the workspace, once. Captured with `--workspace "Main A"` | `ws.list(Admin)` + `iam.bind_workspace(name, slug, opt)` (`:128-164`). Read-modify-write without a concurrency token on both sides; a concurrent writer can be overwritten (documented in the SDK) |
| `delete\|rm <name>` (`--force`) | `DELETE <iam>/scopes/<name>` | `iam.delete(name, opt)` ("experimental": the route is inferred, `:165-177`) |

### 4.3 `telemetry`

**Window** (every leaf except `cost`; `tel:30-46`):

- `--workspace <slug>` is required and passed as typed; there is **no name resolution** (a name with a
  space fails the SDK window schema, captured `Invalid telemetry query options or time window`, exit 1).
- `--days <n>` defaults to `7`. `--start <iso>`, when given, replaces the days rule.
- `--end <iso>` defaults to now. With only `--end`, start is end − days.
- Dates are parsed with JS `new Date(String(v))` (`cli:…/structured-input.ts:68-72`): any string JS
  accepts, local timezone for zone-less forms. Captured: `--start 2026-10-01 --end "Oct 2 2026"` was
  accepted.
- `--days` must match `^-?(0|[1-9]\d*)$` and be > 0 (`Invalid --days: Expected a positive integer`,
  exit 2, before the client).

Rust: `AIGatewayWindowOptions::new(slug)` with `days: Option<f64>`, `start`/`end` as
`validation::NativeDate::from_epoch_millis`, and `offset_minutes = 0` (`gw:telemetry.rs:9-66`).

**Chart filters** (`latency`, `requests`, `tokens`, `cost`, `group-by`; `cli:…/telemetry-filters.ts:19-75`):

- The flags are `--trace-id`, `--metadata <json string map>`, `--status-codes <csv int>`,
  `--api-key-ids <csv uuid>`, `--ai-org-models <csv provider__model>`, `--total-units-min|max <int ≥0>`
  and `--cost-min|max <JSON number ≥0>`.
- Syntax errors give `Invalid chart filters: check JSON, CSV and numeric flag syntax`. Schema errors give
  `Invalid chart filters: check status codes, UUIDs, provider__model pairs, string metadata and inclusive
  nonnegative bounds`. Both exit 2 and never echo values.
- Rust: `AIGatewayChartFilters::builder()` plus the SDK's `AIGatewayChartFiltersSchema` validation
  inside `filtered_query` (`gw:telemetry.rs:184-238`). The CLI should pre-validate with
  `validation::parse("AIGatewayChartFiltersSchema", …, Mode::Request)` to keep exit 2 before the tenant.

| Leaf | TS call → path | Rust |
|---|---|---|
| `cost` (`--workspace <ref>` resolved over `[data, admin]` with slug required, `svc:261-295`; `--days` default `7`, no `--start/--end`) | `GET <data>/workspaces` (resolution) → `GET /logs/charts/cost?…` | `ws.list` + `tel.cost(&AIGatewayChartOptions{window, filters}, opt)` → `CostChartResponse` (`:410-426`) |
| `requests`, `latency`, `tokens` | `/logs/charts/{requests,latency,tokens}` + filters | `tel.requests\|latency\|tokens(&AIGatewayChartOptions, opt)` |
| `errors`, `users`, `error-trends`, `error-category-trends`, `grouped-errors`, `rescued-retries`, `user-trends`, `cache summary` (`cache-summary`), `cache trend` (`cache-hit-trend`), `feedback trend\|weighted\|distribution\|models` (`feedback-trend`, `-weighted`, `-score-distribution`, `-models`) | `/logs/charts/<metric>` | `tel.errors\|users\|error_trends\|error_category_trends\|grouped_errors\|rescued_retries\|user_trends\|cache_summary\|cache_hit_trend\|feedback_trend\|feedback_weighted\|feedback_score_distribution\|feedback_models(&AIGatewayWindowOptions, opt)`; all log as `airs.gateway.telemetry.chart` (GW10) |
| `filter-boundaries` | `/analytics/filter-boundaries` (no `organisationId`); the **whole `data`** is then replaced by `"[REDACTED]"` (`redactAIGatewaySecrets('telemetry.filterBoundaries')`, `tel:87-90`; captured) | `tel.filter_boundaries`, then `redact_ai_gateway_secrets(TelemetryFilterBoundaries, …)` (`gw:helpers.rs:91-105`, rule `rs:constants.rs:168-178`) |
| `group-by <dimension>` (`ai_service\|model\|api_key\|provider\|status_code\|users`; `--columns <csv of cost,avg_latency,avg_tokens,total_tokens,success_rate,last_seen>`, refused for `users`) | `/logs/groups/<dimension>` (+`columns`); `users` → `/logs/groups/users`; `status_code` → `/logs/groups/status_code` | `tel.group_by(AIGatewayGroupDimension, &AIGatewayGroupOptions, opt)`, `tel.by_status_code`, `tel.by_user(&AIGatewayChartOptions)` (`:498-562`) |
| `logs list` (`--page-size` default `50` > 0, `--current-page` default `0` ≥ 0, `--status-code` > 0, `--trace-id`) | `/logs?…&pageSize&currentPage&traceId&statusCode` (captured order) | `tel.logs(&AIGatewayLogsOptions{window, page_size, current_page, trace_id, status_code}, opt)` (`:564-612`) |

Error texts: `Invalid grouping dimension: choose from ai_service, model, api_key, provider, status_code,
users`, `User grouping does not support --columns`, `Invalid --columns: choose from …` and
`--current-page must be a nonnegative safe integer` (all exit 2, before the client).

### 4.4 Inventory (`inv:`, `cli:…/aigateway/admin-guardrails.ts`)

The shared runners are `sh:167-337`.

- **`runList`** resolves `--output` (six TS formats). It prints `responseItems(result)` (an array,
  `data[]`, `data.records[]` or `records[]`, `sh:82-90`). JSON and YAML always print (`[]` when empty);
  pretty and table print `No <label> found` when empty, else a table.
  - The table's columns are the preferred keys `id, slug, name, type, status, enabled, created_at,
    last_updated_at` that are scalar in every row, then the other all-scalar keys sorted, capped at 8.
  - Labels are snake → Title Case (`sh:96-118`).
- **`runDetail`** prints JSON/YAML, else a `Field`/`Value` table whose object values are compact JSON
  (`sh:142-165`).
- **`runWrite`, `runConfirmedWrite` and `runSecretWrite`** allow pretty/json/yaml only (`Output format
  'table' is not supported here. Expected: pretty, json, yaml`, exit 2).
  - The body is built and validated before the client (`buildStructuredRequest`: `--file` JSON, or YAML
    for `.yaml|.yml`, < named flags < `--set path=json` / `--set-string path=text`; duplicate or colliding
    paths refused, `buildDottedObject`).
  - A delete renders `{"success": true}` when the SDK returns nothing.
- **No inventory command prints the banner.**

| TS command | Path (captured or `tsdk:` route) | Rust 0.1.1 | Response type |
|---|---|---|---|
| `api-keys service\|user list --workspace <uuid>` (`--reveal-sensitive`) | `GET <data>/api-keys/{service,user}?workspace_id=` | `api_keys().list_service\|list_user(&AIGatewayWorkspaceScopedListOptions::new(id), opt)` (`gw:api_keys.rs:16-31`, `:116-131`) | `ListApiKeysResponse` |
| `… get <id>` (`--reveal-sensitive`) | `GET …/<id>` | `get_service\|get_user` | `GatewayApiKey` |
| `… create` (`--alert-emails`, `--description`, `--expires-at`, `--name`, `--organisation-id`, `--scopes`, `--type`, `--workspace`, `--user-id` for user; `--secret-output <path>` or `--show-secret`, one required) | `POST …/api-keys/{service,user}` | `create_service\|create_user(&Gateway{Service,User}ApiKeyCreateRequest, opt)` (`:59-74`, `:159-174`); **GW1** | `GatewayApiKeyCreateResponse` (`key: Optional<String>`) |
| `… update <id>` (`--reset-usage <bool>` and the create fields minus org/type/workspace) | `PUT …/<id>` | `update_service\|update_user` | `GatewayWriteResponse` |
| `… delete\|rm <id>` (`--force`) | `DELETE …/<id>` | `delete_service\|delete_user` | `()` |
| `… rotate <id>` (`--force`, `--transition-ms` → `key_transition_period_ms` ≥ 1800000; secret flags) | `POST …/<id>/rotate {…}` | `rotate_service\|rotate_user(id, Some(&GatewayApiKeyRotateRequest), opt)` (`:94-115`); **GW1** | `GatewayApiKeyRotateResponse {id, key, key_transition_expires_at}` |
| `audit-logs list` (`--days` default `7`, `--start`, `--end`, `--reveal-sensitive`) | `GET <admin>/audit-logs?start_time&end_time` | `audit_logs().list(&AIGatewayAuditLogListOptions::new(start, end), opt)` (`gw:audit_logs.rs:29-47`) | `GatewayAuditLogsResponse` (bodies faithful, GW9) |
| `configs list --workspace`, `get`, `versions <id>` | `GET <data>/configs?workspace_id=`, `/configs/<id>`, `/configs/<id>/versions` | `configs().list\|get\|list_versions` (`gw:configs.rs:18-66`) | `ListConfigsResponse`, `GatewayConfigDetail`, `ListConfigVersionsResponse` |
| `configs create\|update\|delete` (`--name`, `--workspace`, `--status` for update) | `POST /configs`, `PUT /configs/<id>`, `DELETE /configs/<id>` | `configs().create\|update\|delete` (`:67-112`) | `GatewayConfigCreateResponse`, `GatewayWriteResponse` |
| `deployments list\|get\|ping` | `GET <admin>/deployments`, `/<id>`, `/<id>/ping` | `deployments().list\|get\|ping` (`gw:deployments.rs:18-94`) | `ListDeploymentsResponse`, `GatewayDeploymentDetail`, `GatewayDeploymentPingResponse` |
| `deployments create` (secret flags required) | `POST <admin>/deployments` | `deployments().create` (`:43-58`); **GW1** | `GatewayDeploymentCreateResponse {id, client_auth, credentials, …}` |
| `deployments update` (`--rotate-auth true` requires a secret destination; otherwise the answer is redacted with `deployments.update`) | `PUT /deployments/<id>` | `deployments().update` (`:59-77`); GW1 when rotating | `GatewayWriteResponse` |
| `deployments archive <id> --organisation-id <tsg>` | `DELETE /deployments/<id>?organisation_id=` | `deployments().delete(id, org, opt)` (`:95-112`) | `()` |
| `guardrails list --workspace`, `get`, `catalog` | `GET <data>/guardrails?workspace_id=`, `/<id>`; `GET <admin>/utils/static-resources/schema?resource=guardrails` | `guardrails().list\|get\|get_catalog` (`gw:guardrails.rs:22-70`) | `ListGuardrailsResponse` (closed `target`, GW5), `GatewayGuardrailDetail`, `GatewayGuardrailCatalogResponse` |
| `guardrails create\|update\|delete` | `POST\|PUT\|DELETE <data>/guardrails…` | `guardrails().create\|update\|delete` | `GatewayGuardrailCreateResponse`, `GatewayWriteResponse` |
| `admin-guardrails list` (`--workspace`, `--page-size`, `--current-page`), `get`, `create` (`--target`, `--workspace`, `--organisation`), `update`, `delete` | `<admin>/guardrails…` | `admin_guardrails().list(&GatewayAdminGuardrailListOptions)\|get\|create\|update\|delete` (`gw:admin_guardrails.rs:15-110`) | `GatewayAdminGuardrailListResponse` etc. |
| `admin-guardrails mcp-servers list\|sync\|upsert` | `GET\|PUT <admin>/guardrails/<id>/mcp-servers[/<server>]` | `admin_guardrails().get_mcp_servers\|sync_mcp_servers\|upsert_mcp_server` (`:112-171`) | mappings responses |
| `integrations list\|get\|providers` | `GET <admin>/integrations`, `/<id>`, `/utils/static-resources/ai-providers` | `integrations().list\|get\|catalog` (`gw:integrations.rs:15-104`) | `ListIntegrationsResponse` (strict pricing, GW5), `GatewayIntegration`, `ListCatalogProvidersResponse` |
| `integrations create` (`--ai-provider <slug\|uuid>` or `--ai-provider-id`, `--key`/`--key-file`/`--key-stdin`/prompt, `--base-url`, `--header n=v`…, `--secret-mappings`, `--configurations`, `--organisation-id`, `--slug`, `--name`, `--description`) | `GET <admin>/utils/static-resources/ai-providers` (only for a slug) → `POST <admin>/integrations` (captured body with `configurations.{provider_auth_type:"apiKey",custom_host,custom_headers}` and `key`) | `integrations().resolve_provider_id` (GW3) + `custom_host_configuration` (`gw:helpers.rs:50-84`) + `integrations().create` | `GatewayWriteResponse` |
| `integrations update\|delete --organisation-id`, `models list\|set`, `workspaces list\|set` | `PUT /integrations/<id>`, `DELETE /integrations/<id>?organisation_id=`, `GET\|PUT /integrations/<id>/models`, `/workspaces` | `integrations().update\|delete\|get_models\|set_models\|get_workspaces\|set_workspaces` (`:56-176`) | write and binding responses |
| `mcp integrations list\|get\|create\|update\|delete\|capabilities list\|set\|metadata`; `workspaces list` = `get` (TS reads the detail, `inv:887-892`); `workspaces set` | `<admin>/mcp-integrations…` | `mcp_integrations().list\|get\|create\|update\|delete\|get_capabilities\|set_capabilities\|get_metadata\|set_workspaces` (`gw:mcp_integrations.rs:15-163`) | `McpIntegrationWorkspacesUpdateResponse` is strict and empty (GW5) |
| `organisations info --tsg-id`, `self get\|update`, `auth-settings get\|update --tsg-id` | `GET <admin>/organisations/<tsg>/info`, `/organisations/self`, `PUT /organisations/self`, `GET\|PUT /organisations/<tsg>/auth-settings` | `organisations().get_info\|get_self\|update_self\|get_auth_settings\|update_auth_settings` (`gw:organisations.rs:18-100`) | `info.settings` always redacted (captured), auth settings redacted unless `--reveal-sensitive` |
| `plugins list\|create` (`--credential k=v`…, `--integration-id`, `--organisation-id`) | `GET\|POST <admin>/plugins` | `plugins().list\|create` (`gw:plugins.rs:16-39`) | `ListPluginsResponse`, `GatewayWriteResponse` |
| `providers list --workspace`, `get` (`--reveal-sensitive`), `create`, `update`, `delete` | `<data>/providers…` | `providers().list\|get\|create\|update\|delete` (`gw:providers.rs:18-95`) | `get` redacted by `providers.get` rules + `redactDeep` (captured `key`, `masked_api_key` `***`, `model_config` `[REDACTED]`) |

Inventory redaction in TS has three layers:

- `redactApiKeyMaterial`: every key named `key` becomes `***`, recursively (`inv:118-127`), for the
  api-key list and get.
- `redactAIGatewaySecrets(op, …, 'response')`: the SDK rule table (`tsdk:9887-9980`), mirrored by
  `AI_GATEWAY_SECRET_FIELDS` (`rs:constants.rs:167-…`).
- `redactDeep`: key-name pattern `/token|secret|password|passwd|credential|authorization|cookie|api[-_]?key|client[-_]?auth|auth[-_]?code|^key$/i`
  (`cli:cli/debug-logger.ts:31-62`), for providers get and audit logs.

`--reveal-sensitive` skips the redaction.

### 4.5 `inference`

| Leaf (TS options) | TS | Rust |
|---|---|---|
| `chat [prompt]` (`--model`, `--endpoint`, `--file <json>`, `--timeout` default `60000`, `--stream`, `--max-tokens` → `max_completion_tokens`) | `POST <endpoint>/chat/completions {messages:[{role:"user",content}], model, …}` (captured); stream: SSE until `[DONE]` | `RuntimeClient::create_chat_completion(&GatewayChatCompletionRequest)` / `create_chat_completion_stream` → `ContractStream<GatewayChatCompletionChunk>` (`TerminalPolicy::DoneMarker`) (`gw:runtime.rs:268-317`) |
| `responses [prompt]` (`--max-tokens` → `max_output_tokens`; `store:false` added unless the file sets it) | `POST /responses`; stream ends on `response.completed\|failed\|incomplete`; failed or incomplete → `Gateway generation ended with <type>` (exit 1) | `create_response` / `create_response_stream` (`TerminalPolicy::Responses`) (`:333-374`) |
| `embeddings [prompt]` (`--dimensions`, `--encoding float\|base64`) | `POST /embeddings {input, model, …}` | `create_embedding` (`:318-332`) |

- **Body.** The prompt and `--file` are mutually exclusive, and one is required. The model comes from
  `--model`, else the file's `model`, else `aiGwInferenceModel` (`aiGwEmbeddingModel` for embeddings), else
  `Set --model, the request model, or the matching inference model config` (exit 2). The body is validated
  with the SDK input schema before the client (`…/inference.ts:35-76`, `:141-151`). `--stream` with yaml is
  refused.
- **Output.**
  - pretty: the concatenated text; for a stream, the deltas then `\n`; embeddings print JSON.
  - json: the response pretty-printed, or one compact event per line when streaming.
  - yaml: a dump.
  - An `EPIPE` on stdout is exit 0.
- **SIGINT/SIGTERM** abort the request: `✗ Error: Inference interrupted`, **exit 1** (captured). This is
  the only TS command that catches the signal.
- **Rust input types.** The typed inputs are `GatewayInferenceInput…` (Deserialize from the merged JSON).
  The runtime response models carry the stream's closed `finish_reason` literals (GW5).

### 4.6 `report|dashboard`

- **Options** (`cli:cli/commands/aigateway-report.ts:18-124`):
  - `--workspace <ref>` is required and must not be empty.
  - `--days` defaults to `1`, matching `^[1-9]\d*$`.
  - `--start` and `--end` must come together, each a zod `datetime({offset:true})`, and cannot be
    combined with an explicit `--days`. Start must come before end.
  - `--max-pages` 1–100, default `40`. `--title` 1–240 characters, default `AI Gateway environment report`.
  - `--output html|markdown` (the root's `--output` too). `--output-file` (`-` means stdout; never
    overwrite; the default is `airs-aigateway-report-<iso with : as ->-<8 hex>.<html|md>`). `--strict`.
- **Collector** (`rep:63-396`). Every call is sequential with `numRetries: 0`, captured in this order:
  1. `workspaces.list({plane:'admin'})`. The workspace is matched by id or slug, else by a unique name;
     otherwise the source fails and every window source fails too.
  2. 17 charts in `CHARTS` order (`requests, errors, users, cost, latency, tokens, cacheSummary,
     cacheHitTrend, userTrends, errorTrends, errorCategoryTrends, groupedErrors, rescuedRetries,
     feedbackTrend, feedbackWeighted, feedbackScoreDistribution, feedbackModels`) over the fixed window.
  3. `filterBoundaries`.
  4. `logs` pages `pageSize=50, currentPage=0…` until the unique ids reach the first `total`, or the page
     budget runs out.
  5. `configs.list`, `apiKeys.listService`, `apiKeys.listUser` (workspace id).
  6. `organisations.getInfo(mgmtTsgId)`.
  7. `guardrails.getCatalog()`.

  That is 25 sources. Each source is complete, partial or unavailable:
  - `success !== true` or `isQuotaExceeded !== false` → partial (the quota note);
  - a list with `has_more` or `total !== rows` → partial;
  - a logs page with an unstable total, a row outside the window, a duplicate id, a foreign
    `workspace_slug` or a premature empty page → partial or unavailable;
  - an HTTP error → `HTTP <code>: request failed; …`.

  Health is `unknown` when no telemetry source is complete, which gives exit 1; `--strict` also exits 1
  on any incomplete source. Every other failure is the fixed `Report generation failed. …` (exit 1).
- **Rust.** Every call above has its typed operation (`ws.list`, `tel.*`, `tel.logs`, `configs().list`,
  `api_keys().list_*`, `organisations().get_info`, `guardrails().get_catalog`) with `with_retries(0)`.
  - The renderer is TS `environment-render.ts`, already ported as `here:src/report/html.rs` for red team
    (D155: HTML only).
  - The collector is new: `src/report/gateway.rs`.

### 4.7 doctor "Gateway API" (renamed from TS "AI Gateway API")

TS check 10 (`cli:cli/commands/doctor.ts:462-523`, probe `:627-632`):

- It probes the data-plane `workspaces.list()` with default retries.
- It is skipped without management credentials (`skipped — management credentials not configured`).
- pass: `endpoint reachable (<n> workspace[s] in scope)`.
- A 403 is a **warn**: `endpoint reachable, but access denied (HTTP 403): <server message>`, with the grant
  hint (captured, AB03 in the message → the data-plane hint).
- fail: `AI Gateway API error (HTTP <s>): <message>` or `network unreachable: …`.

Rust: `ws.list(&Default::default(), opt.with_retries(0))` (D49), `gatewayDataEndpoint`, the grant hint
from GW7, and no server text.

---

## 5. Captured layouts (pretty and table bytes)

The banner (`renderAiGatewayHeader`, `rnd:13-15`) goes on stdout for the pretty workspaces, scopes and
`telemetry cost` commands, and for every `workspaces`/`scopes` write and archive/delete whatever the
format. It is `\n  \e[1mPrisma AIRS — AI Gateway\e[22m\n  \e[2mGateway workspace operations\e[22m\n\n`.

`workspaces list` (pretty, colour):

```
\n  \e[1mAI Gateway Workspaces:\e[22m\n
  \e[2m16f7e90d-…-1b01eb5f8297\e[22m
    Main A  \e[2mws-main-a-349e0e\e[22m  \e[32mactive\e[39m\e[36m  default\e[39m
    \e[2mscope: main_airs_workspace_1852583913\e[22m
<blank>
```

- `archived` is yellow, other statuses dim, and a null status prints `unknown`.
- Data-plane runs (not `--all`, not `--plane admin`) add this to **stderr**: `  \e[2mData-plane list shows
  only active workspaces you are scoped to — use --plane admin or --all for the whole tenant.\e[22m`.
- `--output table` gives columns `ID │ Slug │ Name │ Status │ Default │ Scope` (`true`/`false`).
- `--output json` gives the projection `{id, slug, name, status, isDefault, scopeName}` (camelCase, `svc:37-50`).
- **An empty list prints `  No workspaces found` on stdout in every format, json included** (`rnd:43-46`;
  captured).

`workspaces get` (pretty):

- `Workspace Detail:` then a key/value block `ID, Slug, Name, Status, Default (yes/no)[, Description][,
  Scope][, Created][, Updated]`. The detail schema has no `scope_name`, so `Scope` never prints after a
  `get` and only appears after `create`.
- Then `Defaults:`, `Usage Limits:` and `Rate Limits:` sections, each a dim pretty-JSON block, and
  `Security Settings:` key/values.
- `--output json` gives the camelCase detail projection (`svc:53-65`): `usageLimits`/`rateLimits`
  normalised to arrays; unknown and absent fields dropped.
- **`--output table|markdown|csv` print YAML** (`rnd:88-90`; captured).

Scopes:

- The pretty list is `    <name>  \e[2m<type:id, …>\e[22m` or yellow `unbound`, then the dim description.
- The table is `Name │ Description │ Bound resources │ TSG`.
- The detail is `Name, Description ((none) dim), TSG, ID, Bound resources (none — unbound yellow)`.
- An empty list prints `[]` for json (`rnd:131-134`).

`telemetry cost` (pretty): `Cost — <slug> (last <d>d):` then `Total $12.39`, `Daily average $6.20`
(`(cents/100).toFixed(2)`), an optional yellow warning `Telemetry quota exceeded — data may be truncated`,
and `Per day:` rows `<x>  $<n>`. The table form is `Key │ Value`, with `records` as compact JSON. JSON is
`{workspaceSlug, days, totalCents, totalUsd, avgCents, avgUsd, quotaExceeded, records:[{date, costCents,
costUsd}]}`.

Inventory pretty and table (captured): `Id │ Name │ Status │ Created At │ Key │ Object` for api keys
(`***`), and `Field │ Value` for details. An empty list prints `  No <label> found`, where the label is
the group name (`configs`, `service API keys`, `Admin guardrails`, …).

Writes:

- `✓ Workspace created: <id>`, `✓ Workspace updated: <id>`, `✓ Workspace archived: <ref>`,
  `✓ IAM scope created: <name>`, `✓ IAM scope <name> now binds <n> resource(s)` and
  `✓ IAM scope deleted: <name>` are green, **on stdout, also before JSON** (captured `update --output json`).
- The status lines (`IAM scope … created and bound…`, `The scope is not bound to anything yet…`,
  `This is a soft delete…`) go to stderr.
- Inventory writes print only the response through `renderGatewayDetail`. An integration create answering
  `{}` prints nothing in pretty and `{}` in json (captured).
- A secret write prints `Field │ Value` / `saved_to │ <path as typed>`.

Errors: `\n  ✗ <message>\n\n` in red on stderr. HTTP errors add `    HTTP <s>` and the dim
`    Re-run with --debug to capture redacted API diagnostics.`. The 403 hint is a yellow
`  ⚠ 403: …` on **stdout** (captured).

---

## 6. Validation order and exit codes (TS, captured)

Commander parse errors (`unknown option`, a missing required option, `too many arguments`) exit **1**.
A group without a subcommand prints its help on **stdout**, exit **0**. For actions:

1. `resolveOutput` runs first (`Invalid output format 'x'. Expected: pretty, table, markdown, csv, json,
   yaml`, exit 2; writes: `Output format 'table' is not supported here…`, exit 2).
2. The banner (pretty, workspaces/scopes), then the command's flag checks:
   - `Invalid --plane 'x'. Valid planes: data, admin`;
   - `Invalid --status 'x'. Valid statuses: active, archived`;
   - `--all already merges admin-plane active + archived; drop --plane/--status`;
   - `--existing-scope requires --scope-name`;
   - `Specify at least one of --name --description --icon --metadata --defaults --usage-limits --rate-limits`;
   - the window and filter errors;
   - `Choose --secret-output <path> (recommended) or --show-secret before requesting a one-time credential`.

   All exit 2, before the tenant.
3. The structured body (exit 2) and the `--secret-output` reservation (`open(path,'wx',0o600)`; captured
   `EEXIST: file already exists, open 'key.json'`, exit 1).
4. The confirmation: `refusing to <action> without --force in non-interactive mode` (exit 2), where the
   action is the prompt lowercased without `?` (`Archive workspace X? (soft delete — …)` →
   `archive workspace X`).
5. The tenant (`loadConfig`), the credential assertion, the client, and the SDK's local checks (exit 1),
   then the requests.

Rust (proposal, as §17.3): clap → `--output` (pretty/table/json; writes the same set, D50) →
`--tenant` → every argument, id, window, filter and confirmation check (exit 2) → `--debug` →
input files (`--file`, `--key-file`, `--secret-output` reservation, `--output-file`) → bodies → tenant →
credentials → client and token → requests.

---

## 7. Interruption

- TS default (every command but inference): SIGINT or SIGTERM end the process with 130/143 and nothing
  printed.
  - Captured: `api-keys service create --secret-output k4.json` interrupted while the POST was in flight
    exits 130 and **leaves an empty 0600 `k4.json`**. Its cleanup runs only on a caught error or an
    aborted prompt (`sh:287-336`). The key, if the service minted one, is lost.
- Inference: exit 1 `Inference interrupted` (§4.5).
- Rust: the §2.5 signal thread and the D224 `Interrupted; <context>` lines. A secret reservation is
  removed unless the secret was written. An interrupted write after dispatch names the unknown outcome
  (`Interrupted; the <thing> may have been <done>`). A stream is closed (`ContractStream::close`) before
  exit.

---

## 8. Sensitive data exposure (TS)

| Path | Exposure (captured where marked) |
|---|---|
| `audit-logs list` (default, no `--reveal-sensitive`) | `request_body`, `request_headers`, `query_params` are JSON **strings**. `redactDeep` matches key names only, so a `{"key":"sk-…"}` body and an `authorization: Bearer …` header are printed in json **and** in the pretty table (captured: the table showed both). |
| `api-keys … --reveal-sensitive`, `--show-secret`; `deployments create/update --show-secret` | raw keys, `client_auth` and `credentials.password` on stdout |
| `--secret-output` | the whole response JSON in a new 0600 file; on SIGINT an empty file is left (captured) |
| `integrations create\|update --key <v>`, `organisations auth-settings update --scim-token <v>`, `plugins create --credential k=v` | the credential on argv (TS warns only for `--key`) |
| `integrations get`, `mcp integrations get\|metadata\|capabilities` | printed unredacted (no rule applied by the CLI; `configurations.custom_headers`, `client_secret`, `oauth_*` are SDK secret paths for create/update) |
| `telemetry logs list` | raw request rows: `_user`, `api_key_id`, `request_url`, `metadataKey/Value`, `trace_id` |
| `inference` | the key from the tenant **or the environment** (captured); prompts and completions printed; debug body omitted |
| error lines | server `message` text verbatim |

Rust rules (DESIGN §6, AGENTS):

- Every credential that is read (inference key, `--key-file`, `--key-stdin`, prompt), every one-time
  credential that is received (GW1), and every `--scim-token`/`--credential` value enters the `SecretSet`.
  So any printed server text that echoes one is refused.
- The SDK rule table (`redact_ai_gateway_secrets`) is applied as TS does. In addition, `integrations get`
  and the MCP detail reads apply the create/update response paths of their operations. This is proposed:
  it is a §12 row.
- Audit-log `request_body`, `request_headers` and `query_params` are withheld (shown as `[WITHHELD]`)
  unless `--reveal-sensitive` (§14, GW9).
- One-time credentials go only to a `files::Reservation` (`--secret-output`, D204 style).
  `--show-secret` is proposed as dropped, or kept behind an explicit TTY check; §14 open question 2.

---

## 9. Gaps (provisional GW1…)

| Gap | Operation | What is missing | Evidence | CLI-side workaround |
|---|---|---|---|---|
| **GW1** (G26 class; shape) | `api_keys().create_service\|create_user\|rotate_service\|rotate_user`, `deployments().create`, `deployments().update` with `rotate_auth` | The typed answer is decoded before the CLI can read the one-time credential, so a 2xx that fails the response schema loses it. Rotate requires `key` and `key_transition_expires_at`; deployment create requires `client_auth` and `credentials`; a create answer whose `data` or `key` has another type also fails. The secret fields are plain `String`. | `gw:api_keys.rs:59-115`, `:159-215`; `gw:deployments.rs:43-77`; `gen:` `GatewayApiKeyRotateResponse`, `GatewayDeploymentCreateResponse` | **Safe:** build the typed body, `validation::parse(<request schema>, …, Mode::Request)`, send `RawRequest::new(POST\|PUT, path).segment(..)` with `json_value` through `gateway.client()` (data) or `gateway.deployments().client()` (admin) and `send_json::<serde_json::Value>`, one attempt via `writes::attempt`. Take the credential from the raw value first (register it, write the reservation), then validate the rest with `Mode::ResponseWithoutDefaults`; a validation failure becomes "saved, but the response could not be read". `RawRequest::named` is crate-private, so the debug log records `custom.request` (as G26 amended). |
| **GW2** (attempt shape) | `workspaces().provision` | One call spans `iam create` → `workspace create` → `iam get` → `iam put`, so `writes::attempt`'s D95 single 401 replay cannot be applied per step (replaying the whole call would create a second scope). The result `ProvisionRecovery` is stage-level. | `gw:provision.rs:157-328` | **Safe:** compose the public steps (`iam_scopes().create`, `workspaces().create`, `iam_scopes().bind_workspace`, `workspaces().get`), each under `writes::attempt`. Keep the SDK's cleanup rule (delete our scope only after a `Rejected` workspace create; retain and name it after `Unknown`). Report recovery lines naming the scope and slug. Alternatively call `provision` with no 401 replay and map `ProvisionStage`. TS deletes the scope after **any** error, including 5xx (captured), which is unsafe (§14). |
| **GW3** (message) | `integrations().resolve_provider_id` | An unknown slug is a bare `ErrorKind::Validation`: no text, no suggestions. TS says `Unknown provider '<x>'; did you mean a, b? (list slugs with integrations.catalog())`. | `gw:integrations.rs:181-209` vs `tsdk:19704-19733` | **Safe:** the CLI calls `integrations().catalog()` and applies the TS rule (trim; a UUID is returned lowercase without a request; case-insensitive slug match; suggestions by alnum containment, at most 5), with `terminal_safe` slugs. |
| **GW4** (API; incomplete traversal) | every list (`workspaces`, `iam scopes`, `configs`, `api_keys`, `guardrails`, `providers`, `integrations`, `mcp`, `deployments`, `plugins`, `audit_logs`) | No continuation parameters exist in either SDK or the API; responses carry `total` and sometimes `has_more`. TS prints a truncated list as complete. | `ListWorkspacesResponse{total, has_more}` (`gen:147773`); TS report treats it as partial (`rep:160-172`) | **Safe:** print the rows, then a stderr warning `The service returned <n> of <total> <things>; the list is incomplete` (exit 0; `report` keeps TS's partial rule). A §12 row (fail closed, AGENTS). |
| **GW5** (difference, D178 class) | guardrail and admin-guardrail reads, integration reads, MCP workspace set, inference | Rust response modes keep unknown keys in strict objects and widen enums and literal unions; TS fails with `AISEC_RESPONSE_VALIDATION` (captured). | `rs:validation.rs:29-31`; §3.4 table | No workaround needed; print `terminal_safe` values. A §12 row extending D178. |
| **GW6** (difference) | every telemetry window | TS formats the bounds in the local timezone (host-dependent bytes); Rust `offset_minutes` defaults to UTC `+00:00`. | `tsdk:17968-17975`; `gw:common.rs:193-212`; captured with two `TZ`s | Keep UTC (deterministic, same instant). A §12 row. Parity tests run TS with `TZ=UTC` and compare instants. |
| **GW7** (difference) | 403 on any gateway call | TS picks the grant hint from server message text (`AB03`), and only `data.errorCode` reaches the message. Rust has `service_code()` from four locations. | `svc:87-100`, `tsdk:9719-9721`; `rs:engine.rs:1402-1427` | **Safe:** hint = workspace-scope text when `service_code() == Some("AB03")`, or the failing request was data-plane and the code is absent; admin text for admin-plane requests; none for IAM. On stderr. A §12 row. |
| **GW8** (shape) | secret-bearing models | Plain `String`/`TypedMap<String>`: `GatewayApiKeyCreateResponse.key`, `GatewayApiKeyRotateResponse.key`, `GatewayDeploymentCreateResponse.client_auth`/`credentials`, `GatewayIntegrationCreateRequest.key`, `GatewayPluginCreateRequest.credentials`, `GatewayOrganisationAuthSettingsUpdateRequest.scim_token`, `GatewayProviderDetail.key`. Debug is redacted, Display is not. | `gen:` (above) | **Safe:** register each in the `SecretSet` on read or decode; never `{:?}` (AGENTS). |
| **GW9** (faithful bodies) | `audit_logs().list` | The SDK returns audit bodies faithfully ("may include unredacted credentials"); the secrets sit in JSON-in-string fields no key-name redaction reaches. | `gw:audit_logs.rs:28`; captured leak | **Safe:** withhold `request_body`, `request_headers`, `query_params` unless `--reveal-sensitive`. A §12 row. |
| **GW10** (names) | `--debug` operation names | Logged as they are: `airs.gateway.<client>.<op>`; every chart is `airs.gateway.telemetry.chart` and every group-by `airs.gateway.telemetry.group` (the metric is not in the name); IAM `shared.iam.scopes.*`; runtime `airs.gateway.chat`, `airs.gateway.chat_stream`, `gateway.embedding`, `gateway.response`, `gateway.response_stream` (inconsistent prefix); raw GW1 calls `custom.request`. | `gw:telemetry.rs:248-252`, `gw:runtime.rs:275-358` | Pin in the debug tests (as G9, G17, G23). |
| **GW11** (ergonomics) | options structs | `#[non_exhaustive]` with `new`/`Default`: `AIGatewayWindowOptions::new(slug)`, `AIGatewayChartOptions::new(window)?`, `AIGatewayGroupOptions::new`, `AIGatewayLogsOptions::new`, `AIGatewayWorkspaceScopedListOptions::new`, `AIGatewayAuditLogListOptions::new`; filters through `AIGatewayChartFilters::builder()`; request models are `Deserialize`, so bodies merged as JSON become typed with `serde_json::from_value`. | `gw:telemetry.rs:9-160`, `gw:common.rs:214-249` | Construct with `new`/builders and field assignment. |
| **GW12** (note; G10 result) | all | No response default reachable (§3.4). | schema walk | Use `without_response_defaults()` uniformly anyway (one helper). |
| **GW13** (difference) | inference | Rust `RuntimeClient` has no environment fallback; TS reads `PANW_AI_GW_INFERENCE_*` (captured). | `tsdk:22444-22445`; `gw:runtime.rs:44-51` | Do not add one (AGENTS). A §12 row, pinned by a `dNN_` parity test that passes fake loopback values for both variables and an empty tenant key: TS sends the request; Rust refuses before any request. |

Nothing in M6e is blocked on scm-sdk 0.1.1. No `ws-transport`/`realtime` work is needed.

---

## 10. Proposed module layout (mirrors `src/modelsec` + `src/commands/modelsec*`)

```
src/gateway/mod.rs        shared: id checks with the TS field words (uuid, workspace ref, scope name,
                          numeric TSG), the plane, the GW7 grant hint, the gateway Change words and
                          hints, options(), the redaction table glue (redact_ai_gateway_secrets)
src/gateway/views.rs      TS projections: workspace list/detail (svc.ts normalisers), scope, cost
                          report; the generic inventory list (responseItems, displayColumns) and
                          Field/Value detail
src/gateway/body.rs       structured input: --file (JSON; YAML decision §14 q.3), named fields,
                          --set/--set-string via build_dotted_object/set_dotted_value, the workspace
                          write builder (--metadata into defaults), the binding parsers
                          (id=bool, slug=bool, type:name=bool, key=value)
src/gateway/window.rs     telemetry window (strict ISO with offset), --days, chart filters,
                          group dimensions/columns, logs paging
src/gateway/resolve.rs    workspace ref resolution (planes, ambiguity text, slug requirement),
                          the get-404 fallback, provider resolution (GW3)
src/gateway/secrets.rs    one-time credential writes (GW1 raw path, Reservation, outcome lines),
                          provider key sources (--key, --key-file, --key-stdin, hidden prompt)
src/gateway/inference.rs  RuntimeClient build, body builder, response text extraction, JSONL
                          stream writer, terminal-event check
src/commands/gateway.rs                planning for every leaf (argument checks before the tenant)
src/commands/gateway_workspaces.rs     workspaces + scopes (provision composition, GW2)
src/commands/gateway_telemetry.rs      cost and every telemetry read
src/commands/gateway_inventory.rs      inventory reads (api-keys, audit-logs, configs, deployments,
                                       guardrails, admin-guardrails, integrations, mcp,
                                       organisations, plugins, providers)
src/commands/gateway_write.rs          shared write machinery: the D81 gate and prompt, attempts,
                                       outcome lines; inventory creates/updates/deletes/sets
src/commands/gateway_inference.rs      chat, responses, embeddings
src/report/gateway.rs                  the 25-source collector; HTML via src/report/html.rs
src/clients.rs                         GatewayClients::build/authenticate, GatewayRuntime::build
src/commands/doctor.rs                 the "Gateway API" check
```

`Cargo.toml` adds `"gateway"` to the `scm` features. This is one lock-file edge (`scm-sdk` →
`getrandom 0.4.3`, already locked). Build steps, as §17.1:

1. Reads, doctor and report.
2. Writes and secret writes.
3. Inference and the live tier.

---

## 11. Loopback fixture routes (harness)

The existing `Route::AiGwWorkspaces` (`here:crates/airs-test-harness/src/server/record.rs:30`, `:266`)
folds into a new `Route::Gateway(Gw)`. The fixture data lives in `fixtures_gateway.rs`, and the servers in
`server/gateway.rs` and `server/gateway_writes.rs`. The tenant keeps `aiGwDataEndpoint=<base>/ai_gw/v2`,
`aiGwAdminEndpoint=<base>/ai_gw/admin/v2`, `iamEndpoint=<base>/iam` and
`aiGwInferenceEndpoint=<base>/ai_gw/inference` (`sandbox.rs:85-88`; the Rust store gets the `gateway*`
names).

| Route | Behaviour and knobs |
|---|---|
| `GET {data,admin}/workspaces[?status=]` | rows by plane and status; knobs: `has_more`/`total` mismatch (GW4), a duplicate display name (ambiguity), 403 with top-level `errorCode: AB03` and with `data.errorCode` (GW7) |
| `GET {data,admin}/workspaces/<ref>` | detail by id or slug; 404 `AB08` for names; 500 for the re-read-fallback case |
| `POST admin/workspaces`, `PUT/DELETE admin/workspaces/<ref>` | counters; traps: a 502/503 must be seen once (single attempt), a 400 for the scope-rollback path, a create answer with a mismatched `scope_name` (SDK `Protocol`/`Unknown`) |
| `GET/POST /iam/scopes`, `GET/PUT/DELETE /iam/scopes/<name>` | resources with and without `metadata`; the PUT body recorded for the bind merge |
| `GET /ai_gw/v2/logs/charts/<metric>`, `/analytics/filter-boundaries`, `/logs/groups/<dim>`, `/logs` | the 17 chart bodies (`isQuotaExceeded` true/false); query recorded (key order, UTC offsets, filters); logs pages with `total`, a duplicate id, a foreign slug, an out-of-window row and an empty intermediate page (report rules) |
| api-keys, configs, guardrails, providers (data); integrations, catalog, mcp, deployments, plugins, organisations, audit-logs, admin guardrails, `utils/static-resources/schema` (admin) | minimal schema-valid bodies plus traps: a guardrail `target: "a2a"` (GW5), an integration `pricing_adjustments.multiplier.newKey` (GW5), audit rows with credentials in `request_body`/`request_headers` (GW9), provider details with `key`/`model_config` |
| `POST api-keys/{service,user}`, `…/<id>/rotate`, `POST/PUT admin/deployments` | one-time credential answers carrying a canary credential; a 2xx answer failing the schema (GW1 keeps the key); 502 (single attempt; reservation removed); a slow answer for the interrupt test |
| `POST /ai_gw/inference/{chat/completions,responses,embeddings}` | JSON answers; SSE streams (`data: …\n\n`, `[DONE]`, a `response.failed` terminal, an empty keepalive, a non-SSE content type); 500; a slow answer; records `x-portkey-api-key` presence and asserts no `authorization` |

The GW13 parity test passes `PANW_AI_GW_INFERENCE_API_KEY` (fake) and `PANW_AI_GW_INFERENCE_ENDPOINT` (the fixture) explicitly through `RunOptions::env`; nothing else reaches a child (allowlisted environment).

---

## 12. Live-tier design (DESIGN §10 rules)

- **Default reads** (`AIRS_RS_LIVE=1`; both CLIs, sanitized summaries of ids and counts only):
  - `gateway workspaces list` (data and `--plane admin`), `workspaces get <first data-plane slug>`,
    `scopes list` (names count);
  - `telemetry requests|errors|cost` and `logs list --page-size 5` (totals only, no row content) for
    `AIRS_E2E_GATEWAY_WORKSPACE`, else the first data-plane workspace;
  - `configs|guardrails|providers list --workspace <id>`, `api-keys service|user list` (redacted;
    compare ids and counts);
  - `integrations list`, `integrations providers` (count), `mcp integrations list`, `deployments list`,
    `plugins list`, `admin-guardrails list`, `guardrails catalog` (count), `organisations self get` (id
    only);
  - `report` (source names and statuses compared, the file removed);
  - doctor "Gateway API".

  A run where both CLIs get 403 is recorded `skipped (no gateway grant)`, not failed, as with model
  security in 0.8. The tier never uses `--reveal-sensitive` or `audit-logs`, `organisations auth-settings
  get`, `info` settings, or provider `get`.
- **Opt-in write flow** (`AIRS_RS_LIVE_GATEWAY_WRITES=1`, plus `AIRS_E2E_GATEWAY_WORKSPACE=<uuid>` of
  an existing data-plane workspace the account is scoped to):
  - create, update and delete one `configs` entry and one workspace `guardrails` entry, named
    `airs-rs-e2e-<run>-…`, per CLI. Both are hard deletes on the data plane.
  - At most 4 resources per run. Ledgered.
  - The sweeper gains the kinds `gateway-config` and `gateway-guardrail` (prefixed and older than 1 h only).
- **Opt-in billed inference** (`AIRS_RS_LIVE_GATEWAY_INFERENCE=1`; the tenant's `gatewayInferenceEndpoint`
  and key): budget 2 (one `chat --max-tokens 8`, one `chat --stream --max-tokens 8`), comparing only the
  exit code and the non-emptiness of the text.
- **Never live:**
  - workspaces create, update, archive or delete (IAM scope creation, admin plane; archive is
    irreversible);
  - every `scopes` write;
  - admin-guardrail, integration, MCP, deployment, plugin and organisation writes (organisation, admin
    and scope changes; MILESTONES);
  - api-keys create, update, rotate and delete (credentials);
  - provider writes (they need an integration).

---

## 13. Acceptance criteria

1. The `gateway` feature is enabled. No other dependency changes; the lock file gains only the
   `scm-sdk → getrandom` edge.
2. Every TS leaf of §1 exists under `gateway` with TS help texts (program name `airs-cli-rs`, `aigateway`
   → `gateway`, `--output` lines from the format policy), aliases `ls`/`rm` and `workspace`, and the hidden
   `workspaces delete`. A group without a subcommand is D1.
3. Each read sends exactly the TS method, path and query keys in TS order; values are compared as
   instants for windows (GW6). Each write sends exactly one request, with the D95 401 rule decided per
   command (GW2). Fixture counters prove one POST under 502/503.
4. The workspace create sequence (scope, workspace, get, put, re-read) and its failure branches: rejected
   create → scope deleted; unknown → scope retained and named; bind failure → workspace and scope named.
   The `--existing-scope` path skips scope creation.
5. Name resolution matches TS: get-404 fallback over planes; update, archive, bind, cost and report
   resolution; the ambiguity text; pass-through of unmatched refs.
6. The one-time credential flow (GW1): reservation before the request, removed on refusal, abort,
   interrupt or non-2xx; the credential written from the raw answer even when the rest fails the schema;
   never printed by default.
7. The redaction parity of §4.4 plus the Rust-only withholding (GW9, MCP and integration details);
   canary credentials never appear on stdout, stderr or the debug log.
8. The output layouts of §5 in pretty and table, with the D-row changes (§14): stdout carries data only;
   empty JSON is `[]`; table is a table.
9. Telemetry window and filter validation before the tenant (exit 2), strict ISO-8601 with offset.
10. Inference: tenant-only credentials, §5 admission of `--endpoint`, the JSONL stream, the terminal
    events, EPIPE exit 0, interrupt.
11. The report: 25 sources in TS order, `with_retries(0)`, the TS partial and unavailable rules, HTML only
    (D155), the existing-path refusal before the tenant.
12. The doctor "Gateway API" check: pass, warn-on-403 with the GW7 hint, fail, skip, no retry.
13. Loopback self-tests for every live flow; the sweeper's new kinds.

---

## 14. Open questions / likely §12 divergences

The rows are provisional; DESIGN assigns the numbers (after D225).

| # | Behaviour | TypeScript (captured or source) | Proposed Rust |
|---|---|---|---|
| 1 | Names | `aigateway`, `AI Gateway API` check, report file `airs-aigateway-report-…`, `aiGw*` keys | `gateway`, `Gateway API`, `airs-gateway-report-…`, `gateway*` keys (MILESTONES renames; banner text and report title stay "AI Gateway" unless decided otherwise — open) |
| 2 | Write attempts | up to 6 POSTs per write (captured 3 for an API key, 6 for a workspace) | one attempt (D179 extended) |
| 3 | Provision rollback | scope deleted after any create error, including 5xx (captured) | deleted only after a rejected create; otherwise retained and named (GW2) |
| 4 | Streams | `✓ …` acknowledgements and `⚠ 403:` hints on stdout, also before JSON | stderr (D222 class) |
| 5 | Empty workspace list | `No workspaces found` in json and yaml | `[]` |
| 6 | `workspaces get --output table` | YAML | a table (D50) |
| 7 | Formats | six; writes pretty/json/yaml | pretty, table, json everywhere (D50); writes accept table |
| 8 | ID, ref and scope-name checks | after the tenant and banner, exit 1 | planning, exit 2 (D184 class) |
| 9 | Request-schema errors | `Invalid AI Gateway request: <path>: <message>` | without field paths (D116) |
| 10 | Error text | server `message` | metadata only (§6) |
| 11 | Grant hint | message heuristic, stdout | error code or plane, stderr (GW7) |
| 12 | Telemetry window | local timezone; lenient JS `Date` parsing | UTC `+00:00`; strict ISO-8601 with offset (GW6) |
| 13 | Closed vocabularies | response validation error | printed (GW5, D178) |
| 14 | Lists with `has_more`/`total` mismatch | printed as complete | printed plus an incomplete warning (GW4) |
| 15 | Audit-log bodies | printed with embedded credentials (captured) | withheld unless `--reveal-sensitive` (GW9) |
| 16 | One-time credentials | `--show-secret` prints to stdout; an interrupted reservation is left empty | the reservation only (open: keep `--show-secret` for TTYs?); removed on interrupt |
| 17 | Inference credentials | env fallback (captured) | tenant only (GW13) |
| 18 | Inference interrupt | `✗ Error: Inference interrupted`, exit 1 | exit 130/143 with `Interrupted; …` (D224) |
| 19 | Parse errors and group help | exit 1; help on stdout, exit 0 | exit 2; help on stderr, exit 2 (D1) |
| 20 | Report | html or markdown | HTML only (D155); `--debug` refused (D156) |
| 21 | Integration and MCP detail reads | unredacted | the SDK secret paths applied (open) |

Open questions:

1. Banner and report title wording after the rename.
2. `--show-secret`: drop it, or keep it for a TTY only.
3. `--file` YAML input: `js-yaml` load for `.yaml|.yml` has no Rust dependency yet. Options: JSON only
   (a §12 row), or add a YAML parser (a lock-file change).
4. Dollar rounding: JS `toFixed(2)` rounds exact ties up (`0.125` → `0.13`), while Rust `{:.2}` rounds
   them to even. A `costCents` of `12.5` would differ. Port `toFixed` or render from integer cents.
5. Whether `telemetry logs list` should withhold `request_url` queries and `metadataValue` by default.
6. Whether `workspaces list --all` must stay concurrent; sequential is proposed.
