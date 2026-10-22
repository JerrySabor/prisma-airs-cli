# Rust SDK for M6f (0.11): Supplychain (TS `agentguard`)

Scope: every `agentguard` command of the frozen TS CLI (5711012), which airs-cli-rs renames to
`supplychain` (MILESTONES, no alias): `scans list|ls`, `scans vulnerabilities <scanUuid>`, `stats`,
`rules list|ls` and `report` (the environment report). That is the whole tree. There are no writes,
no deletes, no prompts and no hidden commands (`cmd:136-292`). For each command, this file gives the
`scm-sdk` 0.1.1 API that serves it (feature `agentguard`) and compares it with the HTTP calls the TS
CLI makes through its SDK 0.34.0. It ends with the gaps, candidate §12 rows, the proposed module
layout, the fixture routes and the live-tier design. Gaps are numbered **SC1…** (provisional; the
G-series stopped at G35 in `rs-sdk-runtime-extras.md`) and candidate §12 rows **C1…** (provisional,
renumbered when DESIGN takes them).

The TS behaviour, with byte captures of every layout, is specified in the companion
`docs/research/ts-supplychain.md` (cited **TSC§n**). This file restates TS behaviour only where the
SDK comparison needs it, and adds the SDK facts that TSC§14 listed as "to verify".

Method (2026-10-18, node v24.21.0):

- Source reading of the reference build, its SDK bundle, the Rust SDK 0.1.1 sources and its frozen
  schema graph (a read-only Python walk of `rs:validation/schema_graph.json` and `semantics.json` from
  the ten AgentGuard roots).
- Captures of the reference build (`dist/cli/index.js`) against a loopback stub written for this file
  (`node:http` on `127.0.0.1`, random port; the scripts are listed in Appendix A). The stub served
  `POST /oauth/token`, `GET /aiag/data/v1/scans`, `GET /aiag/data/v1/stats/scans`,
  `GET /aiag/data/v1/scans/<id>/vulnerabilities` and `GET /aiag/mgmt/v1/rules`. Pages honoured `skip`
  and `limit`; the rules answer reported `total_items` = the length of the returned page (the observed
  service behaviour, `tsdk:14753-14756`). Every request was logged (method, path, raw query, auth
  scheme, `x-tsg-id`, `User-Agent`, `service-name`, body), and a fault plan could set a status,
  headers, a body, a hang or a sequence of answers.
- Sandbox: `env -i` with `PATH=/usr/bin:/bin`, and `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`,
  `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, `AIRS_CLI_CONFIG_DIR` and
  `PRISMA_AIRS_TENANTS_PATH` all inside the scratchpad. The TS registry held fake tenants only:
  - `src`: `mgmtClientId: client-100`, `mgmtClientSecret: FAKE-SECRET-100`, `mgmtTsgId: 100`, and
    `mgmtTokenEndpoint`, `agentGuardDataEndpoint`, `agentGuardMgmtEndpoint` on the stub;
  - `nocred` (no client id or secret);
  - `json` (`defaultOutput: json`);
  - `partial` (no `agentGuardMgmtEndpoint`).
- Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and `dns.lookup` and
  refuses any host but `127.0.0.1`. It fired once, as designed: the `partial` tenant's `rules list` went
  to the production default host and was refused. Fake sensitive fixture values are `PRIVATE-…`.
- No Rust was built, no host other than loopback was contacted, and no tenant or credential file was
  read.

Citation prefixes:

- `rs:` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scm-sdk-0.1.1/src/`;
  `ag:` = `rs:airs/agentguard/`; `gen:` = `rs:models/generated.rs`.
- `tsdk:` = `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js` (0.34.0).
- `cli:` = `.reference/prisma-airs-cli/src/`; `cmd:` = `cli:cli/commands/agentguard.ts`;
  `rep:` = `cli:reports/agentguard.ts`; `er:` = `cli:reports/environment-render.ts`;
  `io:` = `cli:reports/io.ts`; `prog:` = `cli:cli/program.ts`; `co:` = `cli:config/client-options.ts`;
  `common:` = `cli:cli/renderer/common.ts`.
- `spec:` = `.reference/prisma-airs-cli/tests/`; `docs:` = `.reference/prisma-airs-cli/docs-site/docs/`;
  `sdkdoc:` = `../scm-sdk-rs/docs/` (read-only checkout); `here:` = this repository.

Companion specs: `rs-sdk-foundation.md` (engine, auth), `rs-sdk-redteam.md` (G7–G10, the environment
report), `rs-sdk-model-security.md` (G18–G24) and `rs-sdk-runtime-extras.md` (G26–G35).

---

## 0. Summary

- **Every command has an SDK operation.** The four reads map one-to-one onto the four
  `AgentGuardClient` methods. Paths, planes, query keys, query order, headers and request and
  response schemas match the TS SDK (`ag:client.rs:47-150` against `tsdk:14680-14766`;
  `gen:1815-3990` against `tsdk:9401-9493`). The report needs `list_scans`, `get_scan_stats` and
  `list_rules`, as the TS collector does (`rep:4-7`).
- **The feature must be enabled.** It is `agentguard = ["models"]` (`rs:../Cargo.toml:48`): no new
  crate, no lock-file change. Today `here:Cargo.toml` enables `reqwest-transport, scan, management,
  red-team, dlp, model-security`.
- **No schema defaults (G10 does not arise).** The graph walk from all ten roots finds no `ZodDefault`
  and no `ZodEnum`. The only effect is the `time_order` refinement on `AgentGuardScanListOptionsSchema`
  (`s000196`, bound in `semantics.json`). Every response object is `passthrough`. Unfamiliar
  `status`, `artifact_type`, `eval_outcome` and `default_state` values are plain strings on both
  sides, so D178 does not arise either. `without_response_defaults()` changes nothing, but is harmless
  in a shared options helper.
- **The query rules are the same as TS and are enforced locally:**
  - `skip` must be a safe non-negative integer and `limit` a positive one;
  - `start_time`/`end_time` are zod 3 `datetime({offset: true})`, and start must not be after end
    (`rs:validation.rs:870-881`, `:1040-1090`);
  - `time_period` is the closed literal `30_DAYS`;
  - unknown keys are refused (`strict`).

  Each failure is `ErrorKind::Validation`, `NotSent`, before the token is fetched
  (`ag:client.rs:152-203`). The CLI checks all of them during planning, so a usage error is exit 2
  before the tenant is read.
- **No writes, so no one-attempt rule is needed.** All four operations are `RawRequest::read`
  (`replay_safe`). TS builds the client with `numRetries: 0` (`cmd:23-24`): one attempt, plus the single
  auth replay after a 401, or a 403 without `x-opa-decision: false` (`tsdk:10208-10230`,
  `:10865-10872`; captured).
  - The Rust equivalent is `with_retries(0)`, which loses that auth replay (**G7**,
    `rs:engine.rs:1215-1222`).
  - So the CLI re-reads once after an `Http` 401/403 `Rejected`, as the red team environment report
    already does (DESIGN §15.17).
- **Gaps (§10).** No SDK patch is needed and no behaviour is blocked. Two items are safety gaps that
  the CLI can close:
  - **SC1**: `vulnerabilities` is one unpaged read, and neither SDK can page it;
  - **SC6**: the 8 MiB response bound on that unpaged, content-bearing read.

  The rest are semantic notes (SC2 `total_items` is a page count for rules; SC3 G7), differences
  (SC4 D35 key order; SC5 redirects), naming (SC7 `airs.agentguard.*` in the debug log) and the
  unqualified browser-derived contract (SC8). SC9 and SC10 are ergonomics. The full list is in §10.

---

## 1. Client construction

### 1.1 The TS side

- `createClient()` (`cmd:23-24`) is `new AgentGuardClient({ ...agentGuardClientOptions(await loadConfig()), numRetries: 0 })`.
- `agentGuardClientOptions` (`co:53-59`) calls `oauth(config)`, which runs
  `assertManagementCredentials`, then passes:
  - `mgmtClientId`, `mgmtClientSecret`, `mgmtTsgId`;
  - `tokenEndpoint: mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`;
  - `dataEndpoint: agentGuardDataEndpoint ?? AGENT_GUARD_DATA_ENDPOINT` (`https://api.apps.paloaltonetworks.com/aiag/data`, `tsdk:180`);
  - `mgmtEndpoint: agentGuardMgmtEndpoint ?? AGENT_GUARD_MGMT_ENDPOINT` (`…/aiag/mgmt`, `tsdk:181`).
- **The environment never applies.**
  - The constructor's env fallbacks (`PANW_AGENT_GUARD_DATA_ENDPOINT`, `…_MGMT_ENDPOINT`,
    `tsdk:14696-14697`, and `PANW_AGENT_GUARD_*`/`PANW_MGMT_*` credentials through
    `resolveOAuthConfig`, `tsdk:11099-11110`) are never reached, because every value is passed.
  - Captured: the `partial` tenant with `PANW_AGENT_GUARD_MGMT_ENDPOINT=<stub>` still went to the
    production default and was refused by the guard.
  - `docs:cli/agentguard/index.md` claims the env equivalents and a config key
    `agentGuardTokenEndpoint`. That key is retired (`cli:config/schema.ts:66-71`). The docs are wrong;
    the code is the spec.
- **Auth.** The client uses `TsgHeaderAuth(OAuthAuth)` (`tsdk:14663-14678`, `:14700-14702`), so every
  API request carries `Authorization: Bearer <token>` and `x-tsg-id: <tsg>`, plus
  `User-Agent: PAN-AIRS/0.34.0-typescript-sdk` and `service-name: api` (`tsdk:10157-10161`; captured).
  The token request is `POST <mgmtTokenEndpoint>`, Basic auth, body
  `grant_type=client_credentials&scope=tsg_id%3A<tsg>`, `User-Agent: node`.
- **Lazy token.** No token is requested at construction. The first read fetches it.
  - In the report, each source retries the token: three token POSTs when the token endpoint answers
    401 (captured).
  - A credential or config failure inside `run()` is swallowed into the generic line
    `AgentGuard request failed. …` (captured with `nocred`, exit 1; TSC§2.4).
- **Timeout.** Each attempt is limited to `PANW_AI_SEC_TIMEOUT_MS`, default 60 s (`tsdk:10095`). There
  is no total budget.

### 1.2 The Rust side (proposed `clients::SupplychainClients`)

Mirror `ModelSecurityClients::build` (`here:src/clients.rs:664-731`):

1. **Admit the three endpoints:**
   - `admit("supplychainDataEndpoint", config.effective_str("supplychainDataEndpoint"), scm::constants::AGENT_GUARD_DATA_ENDPOINT)`;
   - the same for `supplychainMgmtEndpoint` with `AGENT_GUARD_MGMT_ENDPOINT` (`rs:constants.rs:144-145`
     equal `tsdk:180-181`);
   - `mgmtTokenEndpoint` with `DEFAULT_TOKEN_ENDPOINT`.

   Both keys exist in the store schema with the WHATWG URL read rule (DESIGN §3.3 rows 17–18). The
   harness already maps the TS names onto them (`here:crates/airs-test-harness/src/store.rs:96-97`).
   The D48 message names the key, never the value.
2. **Credentials.** Run the §3.5 management credential check before any client is built.
3. **OAuth parts.** `oauth_parts(config, &issuer, &[data.clone(), mgmt.clone()], session, secrets, debug, &LastStatus::default())`:
   the recording provider, one transport (the direct one when any endpoint is loopback http) and one
   `OriginPolicy` admitting both bases and the issuer. This is the management plane only, so scanner
   credentials are never sent.
4. **Limits.** `Limits::default()` with `max_response_bytes` raised for SC6 (§10). The read retry
   count is set per call through `RequestOptions` (§1.3), not in `Limits`.
5. **Build:**
   - `Client::builder(data).transport(..).destination_policy(..).authentication(Authentication::oauth(provider, false)).session(..).limits(..).build()`;
   - then `scm::airs::agentguard::AgentGuardClient::new(client, data, mgmt)`.

   `new` requires OAuth, turns the TSG header **on**, and scopes one client per plane
   (`ag:client.rs:30-37`, `rs:engine.rs:447-455`). `x-tsg-id` then comes from the provider's tenant
   (`rs:auth.rs:797`), as TS sends it. `service-name: api` is added by the engine (`rs:engine.rs:30`).
   A construction failure is `AISEC_SDK_ERROR:The supplychain client could not be configured` (exit 1).
6. **Token.** Rust awaits the token explicitly before the first read (`authenticate(options, budget)`,
   as `ModelSecurityClients::authenticate`), except in the report (§6.5), where TS's lazy,
   per-source token is kept (DESIGN §15.17 "Client and token").

### 1.3 Options and budgets

| Call | `RequestOptions` |
|---|---|
| One-page read (`scans list`, `rules list`, `vulnerabilities`, `stats`) | `with_timeout(SINGLE_REQUEST_BUDGET)?.with_retries(0)?` plus the G7 re-read (§3) |
| `--all` walk | one `with_timeout(WALK_BUDGET)?.with_retries(0)?` for the whole walk, the G7 re-read per page |
| Report source | one `with_timeout(300 s)?.with_retries(0)?` per source (TS: none), the G7 re-read inside it (DESIGN §15.17) |

The table makes three choices:

- **Retries.** Keeping `max_retries = 5` instead would retry 429/502/503/504 where TS makes one
  attempt. That is safe (these are reads) but a §12 row, and it changes the request counts the parity
  tests compare. Recommend parity (choice 1).
- **Timeouts.** The SDK's default operation timeout is 60 s (`rs:config.rs:288`); the budgets
  replace it.
- **Defaults.** `without_response_defaults()` (`rs:config.rs:406`) may be added for uniformity; it
  changes nothing here.

---

## 2. Engine behaviour for AgentGuard calls

| Call shape | SDK path | SDK replay | Outcome on failure |
|---|---|---|---|
| GET with query (`list_scans`, `get_scan_stats`, `list_rules`) | `query_values` serialises the options struct (bounded at `MAX_URL_BYTES`), validates it with the frozen schema in `Mode::Request`, refuses unknown keys, then emits the keys in a fixed order; strings as is, booleans `true`/`false`, numbers through `ryu_js` (`ag:client.rs:152-203`). Then `RawRequest::read(PATH).named(..).query(q)` → `send_contract` (`rs:engine.rs:608-620`) | `with_retries(0)`: none; no 401/403 replay (G7). With a positive limit: transport errors and 429/502/503/504 within `max_retry_delay` 5 s, and one 401/403 refresh that **consumes** a retry (`rs:engine.rs:1172-1240`, `:1345-1374`) | query errors `Validation`/`Limit`, `NotSent`, before auth; HTTP errors `Http` + status, `Rejected` for 4xx, `Unknown` for 5xx; a 3xx is `Destination` (never followed, `rs:engine.rs:1192-1196`); a 2xx that fails the schema or JSON is `Decode` with the status (`rs:engine.rs:702-733`, G4) |
| GET by id (`list_scan_vulnerabilities`) | `crate::data::is_uuid` (8-4-4-4-12 hex, any case), else `Validation`; `RawRequest::read("/v1/scans").segment(id)?.segment("vulnerabilities")?` (`ag:client.rs:106-125`); no query | as above | as above |

- **Query encoding.** `url.query_pairs_mut()` (`rs:config.rs:107-109`) is
  `application/x-www-form-urlencoded`, the same as TS's `URLSearchParams`: `:` → `%3A`, `+` → `%2B`.
  Captured from TS: `start_time=2026-10-30T00%3A00%3A00%2B02%3A00`.
- **Query order.** `skip, limit, isBackgroundRefresh, start_time, end_time` for scans, and
  `skip, limit` for rules. That is the zod shape order TS emits (captured:
  `?skip=1&limit=2&isBackgroundRefresh=false&start_time=…&end_time=…`).
- **Explicit values stay present.** `skip=0` and `isBackgroundRefresh=false` are sent when set, as
  TS sends them (sdkdoc:AGENTGUARD.md "explicit zero and false remain present").
- **Stats.** When `time_period` is unset, `get_scan_stats` pushes `time_period=30_DAYS`
  (`ag:client.rs:92-94`). TS does the same (`tsdk:14736-14740`).
- **Headers.** Exactly bearer, `x-tsg-id`, `service-name` and the SDK `User-Agent` (sdkdoc:AGENTGUARD.md),
  with no body on any GET. This is parity apart from the User-Agent string, which already differs on
  every command (DESIGN §5).

---

## 3. Retries and the G7 re-read

| Case | TS (captured, `numRetries: 0`) | Rust `with_retries(0)` alone | Rust with the CLI re-read |
|---|---|---|---|
| 401 then 200 | token, GET 401, token, GET 200: success | token, GET 401: failure | token, GET 401, (token invalidated) CLI re-read: token, GET 200 |
| 403 twice | token, GET, token, GET: `… (HTTP 403)` | one GET | two GETs, then the 403 line |
| 403 with `x-opa-decision: false` | one GET, no replay | one GET | the CLI sees only `Http` 403; it cannot see the header, so it would re-read once (SC3) |
| 429, 500, 502, 503 (with `Retry-After`), 504 | one GET: `… (HTTP <s>)` | one GET | one GET |
| network error, timeout | one attempt: generic line without `(HTTP …)` | one attempt | one attempt |
| 3xx | fetch **follows** the redirect (captured: a 302 to another loopback port gave the generic network failure) | `Destination`, not followed | the same (SC5) |

The re-read reuses the call's budget. It runs only for `ErrorKind::Http` with status 401 or 403 and
`RemoteOutcome::Rejected`, at most once per request. For a walk, that means once per page request.

---

## 4. Types (feature `agentguard`, `ag:mod.rs` re-exports `rs:models/agentguard.rs`)

### 4.1 Request options (all `#[non_exhaustive]`, with builders; SC9)

| Type (`gen:` line) | Fields | Schema |
|---|---|---|
| `AgentGuardPageOptions` (1815) | `skip: Optional<FiniteNumber>`, `limit: Optional<FiniteNumber>`, `extensions` | `s000191` strict; `skip` = `s000101` (int, ≥ 0, safe), `limit` = int, > 0, safe |
| `AgentGuardScanListOptions` (3027) | as above, plus `is_background_refresh: Optional<bool>` (`isBackgroundRefresh`), `start_time: Optional<String>`, `end_time: Optional<String>` | `s000196` = refinement `time_order` over `s000197` strict; both times `datetime {offset: true, precision: null, local: false}` (`s000201`, `s000203`) |
| `AgentGuardStatsOptions` (3560) | `time_period: Optional<AgentGuardStatsOptionsTimePeriod>` | `s000204` strict; the enum has one variant, `Model30DAYS` ↔ `"30_DAYS"` (`gen:3643-3662`) |

- **Construction.** `AgentGuardScanListOptions::builder().skip(Optional::Value(FiniteNumber::from(n)))…build()?`.
  `FiniteNumber` has `From` for the integer types (`rs:data.rs:255`) and `TryFrom<f64>`. `extensions`
  must stay empty: a non-empty one is refused as an unknown key.
- **The `time_order` binding** (`rs:validation.rs:870-881`):
  - it parses both times with the zod datetime pattern (`timestamp`, `:1040`) and compares the instants;
  - an unparsable time with both bounds present is a failure, as TS's
    `Date.parse(NaN) <= x === false`;
  - a single bound passes.

  So `--start 2026-10-01T00:00+0200 --end …Z` is accepted by both, and both send it as typed
  (captured).

### 4.2 Responses (all `passthrough`: unknown keys in `extensions`, a `BTreeMap`, SC4)

| Type (`gen:` line) | Required fields (the zod 0.34.0 sets) | Notes |
|---|---|---|
| `AgentGuardScanList` (2933) | `pagination: AgentGuardRuleListPagination { total_items: FiniteNumber }` (2145), `scans: Vec<AgentGuardScan>` | `total_items` is a safe non-negative integer (`s000101`) |
| `AgentGuardScan` (2228) | `uuid tsg_id created_at updated_at name artifact_type status fingerprint: String`; `git_url error_message eval_outcome scanner_version parent_uuid: Nullable<String>`; `summary: Nullable<{vulnerability_count, attack_chain_count}>` (3466); `eval_summary: Nullable<{total_rules, blocked, allowed}>` (2828); `eval_details: Nullable<{rule_outcomes[…], skill_override_applied, unknown_findings}>` (2550, 2659); `duration_seconds: Nullable<FiniteNumber>`; `device_metadata: Nullable<TypedMap<JsonValue>>`; `is_batch: bool`; `child_scan_uuids: Vec<String>`; `batch_summary: Patch<JsonValue>` (optional) | `Nullable` = key required, `null` allowed (TS `.nullable()` without `.optional()`). A row missing `fingerprint` fails both CLIs alike (parity, SC8) |
| `AgentGuardScanStats` (3160) | `unique_skills_scanned`, `total_vulnerabilities_found`: `{count: FiniteNumber (safe int ≥ 0), percent_change: Nullable<FiniteNumber>}` (3372); `top_vulnerability: Nullable<{vulnerability_type, finding_count}>` (3278) | `percent_change` is any finite number (`-3`, `12.5`, `1e-7` captured) |
| `AgentGuardVulnerabilityList` (3965) | `pagination` (as above), `vulnerabilities: Vec<AgentGuardVulnerability>` | |
| `AgentGuardVulnerability` (3676) | `uuid tsg_id created_at updated_at scan_uuid title description vulnerability_type file_path type_description: String`; `node_id node_type node_name remediation_description original_code suggested_code: Nullable<String>`; `attack_chain_count: FiniteNumber`; `attack_chain_uuids: Vec<String>` | `original_code`/`suggested_code`/`file_path`/`description` are the sensitive content (§9) |
| `AgentGuardRuleList` (2051), `AgentGuardRule` (1909) | `pagination`; `uuid name default_state description remediation: String`, `vulnerability_types: Vec<String>` | `pagination.total_items` is the **page** row count (`ag:client.rs:126`, `tsdk:14753-14756`; SC2) |

Every model's `Debug` is `…([REDACTED])` (for example `gen:1900-1903`), so models are never printed
with `{:?}` (AGENTS). The explicit `Serialize` emits the known keys in schema order, then the
extensions in key order (`gen:1823-1849`).

---

## 5. Common API facts

- **Planes.**
  - Data (`supplychainDataEndpoint`): `GET /v1/scans`, `GET /v1/stats/scans` and
    `GET /v1/scans/{uuid}/vulnerabilities`.
  - Management (`supplychainMgmtEndpoint`): `GET /v1/rules`.

  A trailing `/` on a base is ignored by both SDKs (`tsdk:10117`; `rs:config.rs:94-97`).
- **Pagination** is skip/limit with `pagination.total_items`.
  - Scans: `total_items` is the global count.
  - Rules: it is the page length, so a walk ends at a short or empty page.
  - Vulnerabilities: there is no paging query at all (SC1).
  - Neither SDK exports a walk (sdkdoc:AGENTGUARD.md "no exported all-page helper"). G19 does not
    arise.
- **Ids.** `vulnerabilities <scanUuid>`:
  - TS checks `z.string().uuid()` (zod 3.25.76: 8-4-4-4-12 hex, any case, the nil UUID included);
  - the SDK checks `is_uuid`, the same rule (`rs:data.rs:324-333`);
  - the id is sent as typed (uppercase kept, captured);
  - the segment rule cannot be reached once the UUID check passed.
- **Debug operation names** (SC7): `airs.agentguard.list_scans`, `airs.agentguard.get_scan_stats`,
  `airs.agentguard.list_scan_vulnerabilities`, `airs.agentguard.list_rules` (`ag:client.rs:70`,
  `:98`, `:120`, `:144`).

---

## 6. Command → SDK map

TS's option surface after `applyReadContractFlags` (`prog:54-69`):

- `--output` is a leaf option on the four reads. In Rust it is the global `--output` (§2.3).
- `--all` and `--max <n>` (`Number`, default `10000`) are added to both `list`s.
- `--limit <n>` (default `10`) and `--offset <n>` (default `0`) use the strict parser `integer`
  (`/^\d+$/`, safe integer, `cmd:25-29`): `Pagination requires a safe nonnegative integer`, exit 2,
  at commander parse time.

Every read runs `run()` (`cmd:81-92`), which prints any failure as the one line
`AgentGuard request failed[ (HTTP <s>)]. Check credentials, query options and service availability. No upstream body is included.`
(red, stderr, never quiet-suppressed, exit 1). `(HTTP <s>)` appears only for an integer status in
400–599, so a 2xx decode failure never shows `(HTTP 200)`.

**TS validation order** (captured; TSC§2.5):

1. commander parse (`integer`; extra arguments: `too many arguments`, exit 1);
2. `preAction`: the tenant is read and `--output` resolved, honouring `defaultOutput`
   (`prog:160-175`);
3. the query schema → `Invalid AgentGuard query. Check pagination, UUID and ISO timestamps; statistics support 30_DAYS only.`
   (exit 2);
4. `createClient`: the credentials, else the generic line, exit 1;
5. `--max` → `--max must be a safe nonnegative integer` (exit 2, `cmd:99-100`);
6. the token and the requests.

**Rust order** (DESIGN §17.3 pattern):

1. clap;
2. `--output`;
3. `--tenant` name;
4. every argument check of the command;
5. debug log;
6. tenant;
7. credentials;
8. client and token;
9. reads.

Every usage error is exit 2 before the tenant is read (the D184 pattern; candidate C2).

### 6.1 `scans list|ls`

| | TS | Rust |
|---|---|---|
| Options | `--start <iso>`, `--end <iso>`, `--limit` (10), `--offset` (0), `--all`, `--max` (10000), `--output` | the same, global `--output` |
| SDK | `client.listScans({skip, limit, start_time, end_time, isBackgroundRefresh: false})` per page (`cmd:149-160`) | `ag.list_scans(&q, Some(&opts))` per page, with `q.is_background_refresh = Optional::Value(false)` always |
| Wire | `GET <data>/v1/scans?skip=<n>&limit=<n>&isBackgroundRefresh=false[&start_time=…][&end_time=…]` | identical bytes |
| Walk | TS `inventory` (`cmd:94-133`; TSC§3) | §7 |
| Output | `{pagination: {total_items, returned, skip, next_offset, truncated}, scans: [9-key projection]}`; the projection is `uuid, artifact_type, status, eval_outcome, created_at, vulnerability_count (summary?.… ?? null), attack_chain_count (?? null), is_batch, parent_uuid` (`cmd:162-175`) | built from `AgentGuardScan`: `summary` `Null` → `null` counts; never `0` |
| pretty = table | `formatOutput(records, keys − {description, remediation} first 9, 'table')` + status `  Returned <n> records; see JSON/YAML for pagination metadata.` (dim) | the same layout (§6.6) |

Window checks are the DESIGN §17.3 "window" rule: the zod datetime regex, start ≤ end. Plus TS's
own: an empty `--start ''` fails (captured exit 2). Rust can reuse `modelsec`'s window checker (today
it also checks `--model-version`; factor out the time part).

### 6.2 `scans vulnerabilities <scanUuid> [--include-content]`

| | TS | Rust |
|---|---|---|
| SDK | `client.listScanVulnerabilities(id)` (`cmd:187`), no options | `ag.list_scan_vulnerabilities(id, Some(&opts))` |
| Wire | `GET <data>/v1/scans/<id>/vulnerabilities`, no query | identical |
| Output without the opt-in | `{pagination: <as sent, passthrough>, vulnerabilities: [{uuid, scan_uuid, vulnerability_type, attack_chain_count}], content_included: false}` | the same; `pagination` with its extensions (key order D35) |
| With `--include-content` | each record whole as parsed (passthrough), `content_included: true`; pretty/table: the first 9 union keys except `description`/`remediation`: `uuid, tsg id, created at, updated at, scan uuid, title, vulnerability type, file path, node id` (captured) | `serde_json::to_value(&AgentGuardVulnerability)`: the known keys in schema order, then extensions sorted (D35). The 9 table columns are fixed for schema-valid rows, since there are ≥ 9 known keys before any extension |

**SC1.** A single unpaged read. When `pagination.total_items` is larger than the rows returned, TS
prints the short list silently; the count is visible only in JSON. Recommend a Rust stderr warning,
or exit 1 under the fail-closed invariant (candidate C5).

### 6.3 `stats [--time-period <period>]`

| | TS | Rust |
|---|---|---|
| Option | `--time-period` default `"30_DAYS"`; any other value → the query error (exit 2, after the tenant) | `30_DAYS` only, checked in planning (exit 2) |
| SDK | `getScanStats({time_period})` (`cmd:209-210`) | `ag.get_scan_stats(&q, …)`, where `q.time_period = Optional::Value(Model30DAYS)` |
| Wire | `GET <data>/v1/stats/scans?time_period=30_DAYS` | identical |
| json | the parsed object as is (passthrough) | `serde_json::to_value(&stats)` (extensions sorted, D35) |
| pretty = table | **`emit` quirk:** if any top-level value is an array (a passthrough key), that array is rendered as the records table and the statistics disappear (captured: `aa_list: [{uuid, k}]` printed a `uuid │ k` table and `Returned 1 records`). Otherwise there is a `Field │ Value` table, with objects as compact JSON (`{"count":4,"percent_change":12.5}`) and `null` as `null` (`typeof null === 'object'`) | recommend always the field table (candidate C6); TS's `JSON.stringify` cell text through `js_number` |

### 6.4 `rules list|ls`

| | TS | Rust |
|---|---|---|
| SDK | `client.listRules({skip, limit})` per page (`cmd:218-229`), `inventory(…, pageCount = true)` | `ag.list_rules(&q, …)` per page on the management client |
| Wire | `GET <mgmt>/v1/rules?skip=<n>&limit=<n>` | identical |
| Walk | complete = a short page; `total_items` is ignored; the output `total_items` is the row count only when complete **and** `offset == 0`, else `null` (captured: `--limit 2` with 5 rules gives `total_items: null, next_offset: 2, truncated: true`; `--all --limit 5` gives 2 requests, the second empty) | §7, with `total: None` |
| Output | `{pagination, rules: [whole records]}`; table columns `uuid, name, vulnerability types, default state` (+ extensions in TS's server order, up to 9) | records via `Serialize` (extensions sorted, D35, which changes the column order only when the server adds keys) |

### 6.5 `report` (the supplychain environment report)

- **SDK.**
  - `list_scans` with page size 10, `skip` = the rows collected so far, `start_time`/`end_time` = the
    30-day window as ISO `…Z` with milliseconds, and `isBackgroundRefresh=false`;
  - `get_scan_stats` with `30_DAYS`;
  - `list_rules` with page size 10 (`rep:120-224`).

  The order is fixed: Scans, Statistics, Rules. Wire captured:
  `GET …/v1/scans?skip=0&limit=10&isBackgroundRefresh=false&start_time=2026-09-19T03%3A02%3A37.145Z&end_time=2026-10-19T03%3A02%3A37.145Z`,
  `…skip=10…`, `GET …/v1/stats/scans?time_period=30_DAYS`, `GET …/v1/rules?skip=0&limit=10`,
  `…skip=10…`.
- **TS checks**, all exit 2:
  1. `preAction` `--debug`/`PANW_AI_SEC_DEBUG` refusal (`prog:139-151`);
  2. the format (`opts.output ?? program.opts().output ?? 'html'`, which ignores the tenant
     `defaultOutput`): `Report output must be html or markdown`;
  3. `--max-pages` 1–100 (the `integer` parser first);
  4. `--title` non-blank and ≤ 240 UTF-16 units;
  5. `--output-file` non-blank (`cmd:242-250`).

  Then `lstat` the destination before the client is built (`cmd:259-265`).
- **Collection rules** (TSC§9.3; port `rep:78-119` verbatim):
  - at most 10 rows per page, else a failure;
  - scans `total` must stay constant;
  - collected + page ≤ total;
  - `uuid` must be non-empty and unique;
  - scans end at `rows == total`, rules at a page shorter than 10;
  - an empty page that is not the end is a failure;
  - the `--max-pages` budget applies, with the note `Reached the <n>-page budget.`;
  - any failure with rows collected gives `partial` + `Inventory incomplete: pagination changed, repeated, stopped early, failed or reached its budget.`;
  - with no rows the source is `unavailable` + `Request or validation failed; no upstream error body included.`
    (no HTTP code note, unlike red team).
- **Captured edge cases:**
  - a 500 on page 2 gave `partial` with 10 records, 1 page;
  - an empty first page with `total_items: 12` gave `unavailable` with 1 page;
  - a token 401 gave all three `unavailable`, `Unable to assess`, exit 1, file written, and three
    token POSTs;
  - stats 403 twice gave `unavailable` and 2 GETs (the auth replay);
  - out-of-window or unparsable `created_at` rows are excluded, and the source becomes `partial`;
  - `is_batch` or non-empty `child_scan_uuids` rows are excluded from the outcome counts;
  - labels outside `SKILL|AGENT` / `BLOCKED|ALLOWED|PENDING|ERROR` become `OTHER`, and `null` becomes
    `UNKNOWN`;
  - `percent_change: null` renders `Unknown`, and `-3` and `1e-7` render as JS numbers.
- **Rendering.**
  - `renderEnvironmentReportHtml` with `product = "Prisma AIRS AI Supply Chain — AgentGuard"`,
    `windowLabel = "30-day scan inventory; rolling 30_DAYS statistics; current rule catalog"`,
    `schemaLabel = "Experimental browser APIs"` and the five limitations (`rep:23-43`).
  - The CSP hashes are the red team ones (same CSS and JS; verified in the capture:
    `sha256-vxcV…EK6c=` / `sha256-jPa0…2+A=`).
  - There is no `Collecting …` status line (unlike red team).
- **Publishing.**
  - `writeReportFile` (`io:6-19`): exclusive temp file, then link, mode 0600.
  - Status `  Report → <abs path> (mode 0600)`, then `  <n> source(s) incomplete; review the evidence section.`.
  - Exit 1 when the health is `unknown`, or under `--strict` with an incomplete source.
  - Any error prints `AgentGuard report failed. Check credentials and a writable, new output path. Existing files are never overwritten.`
    (exit 1; captured for an existing file).
- **Default file name** (captured):
  `airs-agentguard-report-2026-10-19T03-02-37.143Z-5bdcf864.html` (`:` → `-`, the fraction kept).

Rust: the D155 (HTML only; any explicit `--output` is a usage error), D156 (`--debug` refused) and
§15.17 rules (G7 re-read, the 300 s per-source budget, the interrupt contexts) apply unchanged. What
the shared report module must gain is in §12.

### 6.6 pretty/table bytes (all reads; TSC§5)

`formatOutput(…, 'table')` (`common:96-139`):

- the header is ` <label padEnd w> ` joined by `│`, where the label is the key with `_` → space;
- the separator is `─`×(w+2) joined by `┼`;
- then the rows;
- `console.log` adds `\n`;
- there is no indent, and trailing pad spaces are kept;
- `null`/`undefined` cells are empty, objects and arrays are compact JSON, others `String(v)`;
- the width is in UTF-16 units (Rust: display width, D53).

Captured for one row:

```text
 uuid                                 │ name   │ vulnerability types  │ default state \n
──────────────────────────────────────┼────────┼──────────────────────┼───────────────\n
 7a1e0000-0000-4000-8000-000000000000 │ Rule 0 │ ["PROMPT_INJECTION"] │ ALLOWING      \n
```

- **Zero records** print `\n` on stdout (an empty `formatOutput`, then `console.log`) plus
  `  Returned 0 records; …`.
- **Colours** (`FORCE_COLOR=1`):
  - status: `  \e[2m…\e[22m`;
  - error: `  \e[31m✗ …\e[39m`;
  - usage error: `\n  ✗ <msg>\n\n` in red.
- **Control characters.** Server text reaches the terminal raw (captured: an ESC in a stats
  passthrough value). Rust: `terminal_safe` (D47/D52).

---

## 7. Walks (`--all`) and the pagination document

TS `inventory` (`cmd:94-133`) is stricter than the shared loop. Port its checks onto
`walk::walk_with` (`here:src/walk.rs:147`), which has the start offset and a per-page check hook
(DESIGN §18.13):

- **Page size.** `limit = min(--limit, cap − rows)`, where cap = `--max || 2^53−1` with `--all`, else
  `--limit`. Captured: `--all --limit 2 --offset 1 --max 3` sent `skip=1&limit=2` and then
  `skip=3&limit=1`. `walk_with` may need a "shrink the last page" option (today it sends the full
  `limit`).
- **Start offset.** `--offset` is honoured with `--all` (TS parity). This differs from model
  security, where Rust refuses `--all --offset` (DESIGN §17.3).
- **Scans (`total: Some(total_items)`):**
  - the total must not change between pages ("Unstable pagination");
  - rows must not exceed the page `limit`;
  - `uuid` must be non-empty and unique ("Repeated identity");
  - `offset + rows > total` with rows is "Invalid total";
  - complete when `offset + rows >= total`;
  - an empty page before that is "Premature empty page".
- **Rules (`total: None`):** complete at a page shorter than `limit`; the output `total_items` is the
  row count only if complete and the offset is 0, else `null`.
- **Bounds.**
  - TS: 1000 pages, then "Pagination safety limit reached".
  - Rust shared bounds: 100,000 pages and 1,000,000 items (D40).
  - Choice 4: keep the Rust bounds (a D40 extension), or TS's 1000.
- **Failure.** Any walk failure prints only the generic line (exit 1) and nothing on stdout: fail
  closed. Rust maps the D37/D40 errors to that line, or to its §6 text (choice 3).
- **The pagination object** (both lists, TS keys and order):

  ```json
  {"total_items": <n|null>, "returned": <rows>, "skip": <offset>, "next_offset": <n|null>, "truncated": <bool>}
  ```

  `next_offset` is `null` when complete, and `truncated` is `!complete`. A single page that is full
  but complete by total is not truncated. A rules page of exactly `--limit` rows is always
  `truncated: true` (parity, TSC open question 15).

---

## 8. Errors

- **Planes and operations.** Every call is `Plane::Management`, `Operation::Read`.
- **Message.** Recommend the TS line verbatim for API, decode, walk and timeout failures, with the
  product renamed per choice 7: it carries no server text and only the status. The alternative is the
  §6 `AISEC_*` texts.
  - Then the CLI chooses the suffix from SDK metadata: `ErrorKind::Http` with status 400–599 gives
    ` (HTTP <s>)`.
  - `Decode` (even with a 2xx status, G4), `Transport`, `Deadline`, `Destination`, `Limit` and walk
    errors get no suffix.
- **Before the API** (tenant, config, credentials, endpoint admission, token):
  - TS prints the same generic line;
  - recommend the §3.4/§3.5/§5/§6 messages (candidate C3), since TS hides the reason for a missing
    credential;
  - a token failure: `AISEC_OAUTH_ERROR:…` (§6).
- **Local SDK refusals** (`Validation`, `Limit` on queries) cannot happen after planning. If one
  happens anyway, it is the §6 SDK-error text.
- **Interruption.**
  - TS has no handler: SIGINT exits 130 and SIGTERM 143, silently (captured during a hung GET).
  - Rust (§2.5): `Interrupted; no data was written`, and for the report `Interrupted; no report was written`
    or `…the report was saved in <path>` once published (§15.17).
  - No partial stdout.

---

## 9. Secrets and sensitive data

| Data | TS | Rust rule |
|---|---|---|
| OAuth bearer, client secret | never printed | unchanged (SecretSet, §6) |
| Scan `name`, `git_url` (may hold `https://user:token@…`), `fingerprint`, `device_metadata`, `error_message`, `eval_details` | excluded from `scans list` (the 9-key projection) and from the report | the same projection; never serialise `AgentGuardScan` whole |
| Vulnerability `title`, `description`, `file_path`, `original_code`, `suggested_code`, `remediation_description` | only with `--include-content`, printed raw on stdout (JSON whole; the table shows title and file path) | the same opt-in; stdout data only; `terminal_safe` in pretty/table; SecretSet check on printed text; never in an error, the debug log or a summary |
| Rule `description`, `remediation` | in `rules list` JSON; dropped from the table | parity |
| `--debug` | log in CWD with bodies omitted (`prog:183`), loopback filtered (captured: an empty 0600 `debug-api-<ms>-<hex>.jsonl`, status `  Debug: API log → <path>`) | DESIGN §2.9 log (status and headers only, no query); the report refuses `--debug` (D156) |
| Report | aggregates only; the limitations name the exclusions | parity; the labels are allow-listed (`label()`), so no server string reaches the report except counts |

Findings of type `SECRET_EXPOSURE` exist on the live service (`docs:cli/agentguard/index.md`). That
means `original_code` can carry a real third-party secret. The live tier must never run
`--include-content` (§14).

---

## 10. Gaps

| # | Operation | What is missing or different | Evidence | CLI-side workaround |
|---|---|---|---|---|
| **SC1** | `list_scan_vulnerabilities` | No query parameters at all: no skip/limit, no filters. If the service pages findings, both CLIs show only the first page silently. Whether the endpoint pages is unverified | `ag:client.rs:106-125`; `tsdk:14743-14752`; sdkdoc:AGENTGUARD.md "no invented filters" | **Safe:** compare `pagination.total_items` with the rows. When it is larger, print a stderr warning (`Showing <r> of <t> findings; the service returned one page`), or exit 1 (choice 5). No raw request with an invented `skip` |
| **SC2** | `list_rules` | `pagination.total_items` is the current page's count, not the catalog size; the SDK documents it and exports no walk | `ag:client.rs:126`; `tsdk:14753-14756` | **Safe:** walk with `total: None` (continue only on a full page), as TS's `pageCount` |
| **SC3** (G7) | every read with `with_retries(0)` | No 401/403 refresh-and-replay; TS replays once without counting. The CLI re-read cannot see `x-opa-decision`, so it would also re-read a 403 that TS does not replay | `rs:engine.rs:1215-1222`, `:1345-1349`; `tsdk:10208-10230`, `:10865-10872` | **Safe:** one CLI re-read after `Http` 401/403 `Rejected` (a read). The extra GET on an OPA-denied 403 is harmless. Pin the request counts |
| **SC4** (D35) | every response with passthrough keys | `extensions` is a `BTreeMap` (`rs:models/support.rs:9`), so unknown keys serialise sorted; TS keeps server order. This affects `stats` JSON, `vulnerabilities --include-content` JSON, `rules list` JSON and the derived table columns of rules (the first 9 union keys) | `gen:1823-1849` | **Difference, accepted:** extend D35 to these outputs; parity tests compare JSON semantically, and rules tables by the known columns |
| **SC5** | transport | A 3xx is `Destination` and never followed; TS's fetch follows redirects (captured) | `rs:engine.rs:1192-1196` | **Safe (stricter).** Recommend the generic line without a suffix. Needs a §12 row only if §5/§6 do not already cover redirects (choice 9) |
| **SC6** | `list_scan_vulnerabilities` (and `list_scans` pages) | The default 8 MiB response bound (`rs:config.rs:290`) and validation node limits (`rs:validation.rs:63-74`) apply. An unpaged finding list with `original_code`/`suggested_code` can exceed it → `Limit`, fail closed. TS has no bound | `rs:config.rs:274-295` | **Safe:** raise `max_response_bytes` for the supplychain client (32 MiB proposed; `for_bytes` scales the node limits). A `Limit` gets a specific message, `The response was larger than <n> MiB` |
| SC7 (naming) | debug operation names | `airs.agentguard.*` while the command is `supplychain` | `ag:client.rs:70,98,120,144` | Print as is; pin in the debug tests (as G9/G17/G23) |
| SC8 (contract) | all four | The contracts are browser-derived and live-unqualified ("Phase 8 qualification is still required"). The required sets are TS 0.34.0's, so a response missing one fails both CLIs alike (parity), but nobody has proven the sets match the service | sdkdoc:AGENTGUARD.md "Qualification and evidence"; `tsdk:9406-9480` | The live tier (§14) is the qualification; a schema failure maps to the generic line |
| SC9 (ergonomics) | options | The structs are `#[non_exhaustive]` with builders; the numbers are `FiniteNumber` wrapped in `Optional`; `extensions` must stay empty | `gen:1815-1893`, `:3027` | `builder().skip(Optional::Value(n.into()))…build()?` |
| SC10 (ergonomics) | `get_scan_stats` | The one-variant enum `AgentGuardStatsOptionsTimePeriod` is `#[non_exhaustive]` | `gen:3643-3662` | Parse `--time-period` against `"30_DAYS"` in planning; send the variant |

**Not gaps (verified):**

- the datetime and `time_order` checks are enforced by the SDK (`semantics.json` binds `s000196` to
  `time_order`);
- there are no response defaults (no G10);
- there are no closed response enums (no D178);
- the query order and encoding equal TS;
- `x-tsg-id` and `service-name` are sent;
- uppercase UUIDs are accepted;
- `0.2.0` has the same client and scan model (no G25 impact here).

**Nothing in M6f is blocked on scm-sdk.**

---

## 11. Candidate §12 rows (C1…; DESIGN assigns the D numbers)

| # | Area | TypeScript | Rust (proposed) | Why |
|---|---|---|---|---|
| C1 | names (MILESTONES renames) | `agentguard …`; help, title `AgentGuard environment report`, file `airs-agentguard-report-…`, messages `…AgentGuard…` | `supplychain …`; title `Supply chain environment report`; file `airs-supplychain-report-…`; the message product word per choice 7; the product line kept (it names the service) | the rename |
| C2 | argument checks | the query schema, `--max`, the UUID and `--time-period` after the tenant (and `--max` after the credentials), exit 2 | all before the tenant, exit 2, no request (the D184 pattern) | §2.1 contract |
| C3 | tenant, config and credential failures | the generic `AgentGuard request failed…` line | the §3.4/§3.5/§5 messages | a missing credential is not a service failure |
| C4 | `scans list`/`rules list` `--max` parsing | `Number()`: `0x2`, `1e0`, `' 2 '`, `''` accepted (TSC open question 4) | decimal digits only (§7.1 rule) | D17 family |
| C5 | `vulnerabilities` with `total_items` > rows (SC1) | silent | stderr warning (or exit 1, choice 5) | fail closed: an incomplete listing is not presented as complete |
| C6 | `stats` pretty/table with a passthrough array | the array replaces the statistics | always the `Field │ Value` table | a server addition must not hide the statistics |
| C7 | status text `see JSON/YAML for pagination metadata` | names YAML | `see JSON for pagination metadata` (or verbatim, choice 6) | D50 dropped yaml |
| C8 | report `created_at` parsing | `Date.parse` (local time for zone-less) | the §15.17 rule: zone required, else unusable (excluded, partial) | determinism |

The existing rows that extend to M6f are:

- D1 (a group without a subcommand: TS prints help and exits 1, Rust exits 2);
- D35 (SC4), D37/D40 (walk bounds), D47/D52 (control characters), D48 (endpoints);
- D50 (`markdown`, `csv`, `yaml` are usage errors on the reads);
- D53 (display width);
- D155/D156 (report format and debug refusal);
- the §2.5 interrupt contexts.

---

## 12. Proposed CLI module layout

| File | Contents |
|---|---|
| `src/supplychain/mod.rs` | Argument checks (`--limit`/`--offset` with TS's `integer` rule, `--max`, the window via the shared datetime checker, `--time-period`, the scan UUID), the options helper (§1.3), the options-struct builders, the G7 re-read wrapper, the error-line mapping (§8) |
| `src/supplychain/views.rs` | The 9-key scan projection, the 4-key finding projection, the pagination document, the union-keys table columns (first 9, minus `description`/`remediation`) for records, the field table for `stats` |
| `src/commands/supplychain.rs` | Dispatch and the four reads, with the `inventory` checks on `walk_with` (§7) |
| `src/commands/supplychain_report.rs` | `report`: checks, destination, collection, publish (mirrors `redteam_report.rs`) |
| `src/report/supplychain.rs` | The collector (`rep:10-234` ported: `source`, `pages`, labels, the window filter, leaf rows, findings, health) behind a `Reader` trait with `scans(skip)`, `statistics()`, `rules(skip)` |
| `src/clients.rs` | `SupplychainClients::build` / `authenticate` (§1.2) |
| `src/cli.rs` | The `supplychain` clap tree: `scans list\|ls`, `scans vulnerabilities`, `stats`, `rules list\|ls`, `report`; TS help texts with the renamed program and product |

The shared report module needs generalising. Today `src/report/mod.rs` and `html.rs` hard-code the
red team values: `PRODUCT`, `LIMITATIONS`, the `Scan creation window (UTC)` label and the footer's
`Red Team`. They also lack two kinds of cell:

- **Parameters.** `Report` gains `product`, `window_label`, `schema_label` and `limitations`, and
  `render` uses them. The red team values become its constructor.
- **`Source.window`** becomes `String`, because the scans window holds the run's timestamps.
- **`Cell`** gains `Null` (renders `Unknown`, TS `v ?? 'Unknown'`) and `Number(f64)` (rendered with
  `render::js_number`) for `percent_change`.
- The red team HTML bytes must stay identical (the existing tests pin them).

`Cargo.toml`: add `"agentguard"` to the `scm` features. No other dependency or lock-file change.
Doctor and tenant need nothing new. The doctor credential line still says
`… AI Gateway and AgentGuard commands are unavailable` (TS text, DESIGN §9), to be renamed with
choice 7.

---

## 13. Fixture-server routes

Add `Route::Supplychain(Sc)` to the harness. The standard fixture tenant already sets
`agentGuardDataEndpoint = <base>/agentguard/data` and `agentGuardMgmtEndpoint = <base>/agentguard/mgmt`
(`here:crates/airs-test-harness/src/sandbox.rs:83-84`), mapped to the `supplychain*` keys for the Rust
store. Add `server/supplychain.rs` and `fixtures_supplychain.rs`. Every route checks the
`mock-token-<tsg>` bearer **and** `x-tsg-id == <tsg>`, and records the raw query.

| Route | Behaviour |
|---|---|
| `GET /agentguard/data/v1/scans` | skip/limit page over a seeded list. `total_items` = the count. The seed has a full scan, a scan with `summary: null` and `eval_outcome: null`, a batch parent with children, a child (`parent_uuid` set), an `AGENT`/`PENDING` row, an unfamiliar `artifact_type`/`eval_outcome`, an out-of-window `created_at` and a zone-less `created_at`. Every scan holds `PRIVATE-` name, git URL, fingerprint and device metadata. It honours `start_time`/`end_time` only by recording them |
| `GET /agentguard/data/v1/stats/scans` | requires `time_period=30_DAYS`; `percent_change` values `12.5`, `null`, `-3`; knobs: `top_vulnerability: null`, a passthrough array key, a control character in a passthrough string |
| `GET /agentguard/data/v1/scans/{uuid}/vulnerabilities` | `PRIVATE-` title, description, path and code; `total_items` = the rows; knob: `total_items` > rows (SC1); knob: a 9 MiB body (SC6) |
| `GET /agentguard/mgmt/v1/rules` | `total_items` = **the page length** (the observed service); 13 seeded rules (2 pages of 10 for the report; `--limit` walks) |
| `POST <token>` | the shared token route; knob: 401 |

The existing `once`/`defaults` plans provide these knobs:

- per route: 401 once (the G7 re-read), 403 twice, 403 with `x-opa-decision: false`, 429, 500, 503
  with `Retry-After`, 302;
- a hang (timeout and interrupt tests);
- malformed JSON and a 2xx failing the schema (`{"uuid":"x"}`);
- an empty page while the total says more, a repeated `uuid`, a total that changes between pages,
  more rows than `limit`, and an empty `uuid`.

**Markers.** `PRIVATE-` must never appear in stdout without `--include-content`, nor ever in stderr,
the debug log, the report or a live summary. `FAKE-SECRET-<tsg>` must never appear anywhere.

**Parity fixtures.** The TS side needs both `agentGuard*` endpoints set. Without them it goes to
production (captured), so the runner's endpoint check must cover them. They are already in its key
list (`sandbox.rs:28-29`, `:40-41`), and `PANW_AGENT_GUARD_*` is stripped (`runner.rs:530-531`).

---

## 14. Live-tier design (reads only)

The API has no write operation at all, in neither SDK nor the service as observed. So the
supplychain live flow is **reads only** and needs no opt-in beyond `AIRS_RS_LIVE=1 AIRS_E2E_TENANT`.
It creates nothing, writes nothing to the ledger, and the sweeper has no supplychain kind.

1. **Access probe.** Rust `supplychain stats --output json`. HTTP 401, 403 or 404 means the summary
   notes `supplychain unavailable`; the rest is skipped, and that is not a mismatch (the 0.8
   model-security pattern).
2. **Comparisons**, both CLIs, `--output json`, semantically equal (D35):
   - `stats`;
   - `scans list --limit 10`, `scans list --all --limit 10 --max 200`;
   - `rules list --limit 10`, `rules list --all --limit 3`;
   - `scans vulnerabilities <first listed scan uuid>` **without** `--include-content`;
   - a listing with no row skips the vulnerability read with a notice.

   The rolling data can change between the two CLIs' reads. Compare `stats` and the scan lists as
   "equal, or a retry of both once" (at most one retry), and compare the `--all` walks by the
   multiset of `uuid`s with a tolerance only for rows created during the run. The created times must
   be later than the run start.
3. **Rust only:**
   - `--output table` of `scans list` and `rules list` (the multiset of trimmed cells equal to the TS
     table, D53);
   - pretty `stats` (the field table);
   - `--debug` on one read, with the log checked to hold no body and no query.
4. **Report.**
   - Rust `supplychain report --output-file <run tmp>/sc.html --max-pages 3` and TS
     `agentguard report --output-file <run tmp>/ag.html --max-pages 3`, both sandboxed.
   - Compare the source statuses, record counts and table rows (not the timestamps).
   - Assert the 0600 mode and that no `uuid` from step 2 appears in either file.
   - Remove both files, also on failure and panic.
   - These are local files only; the tenant is unchanged.
5. **Never live:**
   - `--include-content` on either CLI: it prints scanned source code, which can hold third-party
     secrets;
   - an unbounded `--all` (`--max 0`).

**Summary.** `target/live/summary-supplychain.json` holds only check names, pass or fail, counts and
`supplychain unavailable` when it applies. It never holds a scan name, URL, fingerprint, uuid, rule
text or finding text. The real-tenant fingerprint check and the private store follow DESIGN §10
unchanged. Loopback self-tests use `LiveTarget::loopback` against the §13 routes, including the
unavailable path (403) and a run whose second read differs (the retry tolerance).

---

## Acceptance criteria

1. `supplychain` exists with exactly `scans list|ls`, `scans vulnerabilities <scanUuid>`, `stats`,
   `rules list|ls` and `report`. There is no `agentguard` alias. The `agentguard` SDK feature is
   enabled with no lock-file change.
2. Every request goes to the tenant's `supplychainDataEndpoint` / `supplychainMgmtEndpoint` (else the
   SDK defaults) with the bearer, `x-tsg-id` and `service-name`. Scanner credentials and environment
   variables are never used.
3. The query strings are byte-equal to TS:
   - `skip, limit, isBackgroundRefresh=false[, start_time, end_time]` for scans;
   - `skip, limit` for rules;
   - none for vulnerabilities;
   - `time_period=30_DAYS` for stats.
4. Each read makes one attempt, plus exactly one re-read after a 401 or 403 (pinned request counts).
   A 3xx is never followed.
5. Every usage error is exit 2 before the tenant, with no request and no debug log.
6. The walks enforce §7 and fail closed with an empty stdout. The rules walk never trusts
   `total_items`. The pagination document has the TS keys and semantics.
7. The projections are exact. `scans list` never prints `name`, `git_url`, `fingerprint`,
   `device_metadata`, `error_message` or `eval_details`. `vulnerabilities` prints content only with
   `--include-content`. Missing counts are `null`, never `0`.
8. pretty and table produce the TS layout (`terminal_safe`, D53), plus the status line. JSON is TS's
   documents (D35 key order for extensions).
9. A failure never prints server text. The `(HTTP <s>)` suffix appears only for 400–599 statuses.
10. The report follows §6.5 and DESIGN §15.17 with the generalised renderer:
    - HTML only;
    - `--debug` refused;
    - the destination checked with `lstat` before the tenant;
    - mode 0600, never overwriting;
    - `unknown` health or `--strict` with an incomplete source gives exit 1 after the write.

    The red team report bytes are unchanged.
11. Interrupting any command prints the §2.5 context, writes no data and leaves no report or temp
    file.
12. SC1 and SC6 are handled: `total_items` > rows warns (or fails), and an oversized body is a
    specific error, never a truncated listing.

## Open questions / likely §12 divergences

1. **Retries** (§1.3). Parity (`with_retries(0)` plus the G7 re-read) or the SDK read retries
   (`max_retries = 5`, a D10-like row)? Recommend parity: the API is experimental, and the request
   counts are pinned by the TS specs (`spec:integration/cli/agentguard.spec.ts:58-128`).
2. **The token** for the reads: explicit upfront (`AISEC_OAUTH_ERROR`, the §6 shape) or TS's lazy
   token inside the generic line? Recommend upfront (§6), as for model security. The report keeps
   the lazy, per-source token (DESIGN §15.17).
3. **Error text** (§8): the TS generic line verbatim, or §6 `AISEC_*`? Recommend the TS line: it is
   already body-free and status-only. Map D37/D40 walk errors to it too.
4. **Walk bound** (§7): 1000 pages (TS) or the Rust 100,000 pages and 1,000,000 items (D40)?
   Recommend D40.
5. **SC1 policy:** warn or exit 1 when `total_items` > rows? Recommend a warning with exit 0: the
   rows shown are real, and the JSON carries the total.
6. **C7:** reword the `JSON/YAML` status, or keep it verbatim?
7. **Rename scope** (C1, TSC open question 1). Which "AgentGuard" strings become "Supply chain"? The
   candidates are the report title, the file prefix, the three failure lines, the help texts and the
   doctor credential line. Recommend: rename all of them except the product line
   `Prisma AIRS AI Supply Chain — AgentGuard`, which names the service. One §12 row covers them.
8. **`--max-pages` parse text:** TS prints `Pagination requires a safe nonnegative integer` for `abc`
   and `--max-pages must be between 1 and 100` for out-of-range values. The red team port
   unified them as `--max-pages must be an integer from 1 to 100`. Recommend the same for
   consistency.
9. **Redirects** (SC5): confirm that DESIGN §5/§6 already cover them; otherwise one row.
10. **Live access:** `redtail-prod` may not entitle the service account to AI Supply Chain, as it did
    not for model security in 0.8. Then the live tier only proves the `unavailable` path. Is that
    acceptable for the 0.11 definition of done?

---

## Appendix A: scratch artifacts (not part of the repo)

The artifacts are under
`/private/tmp/claude-501/-Users-cdot-development-redtail-prisma-airs-cli-rs/2663a1f5-b86a-45e5-9990-00ce664767e6/scratchpad/sc/`:

- the loopback stub `scag_supplychain_server.mjs` (fault plan in `plan.json`, request log
  `log.jsonl`);
- the guard `guard.mjs`;
- the sandboxed runner `run.sh`, the capture script `cap.sh` and the restart helper `restart.sh`;
- the fake TS registry and tenants under `tenants/`.
