# TS CLI `doctor`: behavior spec for the airs-cli-rs port

Sources read: `src/cli/commands/doctor.ts` (all 825 lines), `tests/unit/cli/doctor.spec.ts` (all 719 lines), and the modules doctor depends on: `src/config/{env,credentials,loader,schema,tenants,client-options}.ts`, `src/cli/{program,index,process-guards,invocation,examples}.ts`, `src/cli/renderer/{common,ui}.ts`, `src/airs/{management,aigateway}.ts`, `src/redteam/judge/providers.ts`. Docs read: every docs-site file that mentions doctor. All paths are relative to `/Users/cdot/development/redtail/prisma-airs-cli` unless marked `scm-sdk-rs`. Nothing was run against the CLI: there is no `dist/` and no `node_modules`. The TS SDK 0.34.0 source is not on disk, so anything marked **[SDK]** is inferred from CLI code and tests, or from the Rust SDK, and is not verified against the TS SDK.

---

## 1. Command surface

- Registration is in `src/cli/commands/doctor.ts:782-825` and is wired up at `src/cli/program.ts:201`.
- Description (doctor.ts:786): `Check the selected tenant, its config file, credentials, and API connectivity (preflight)`.
- **There is exactly one option**, `--output <format>`, with help text `Output format: pretty, table, markdown, csv, json, yaml` (doctor.ts:788).
  - There is no `--scope`, `--skip`, `--product`, `--tenant`, `--config` or `--timeout`.
  - Every check always runs. A check that cannot run reports `skip`.
- Global options from program.ts:107-109 also apply: `--debug`, `--output <format>` and `--quiet`.
  - Commander has no positional options configured, so a root-level `--output` is consumed by the program even when it appears after `doctor`.
  - `resolveOutput` therefore checks both the local and the root value source (`src/cli/renderer/common.ts:53-57`).
  - Net effect: `airs-cli --output json doctor` and `airs-cli doctor --output json` behave the same.
- Help epilogue (doctor.ts:791-794, format from `src/cli/examples.ts:9-11`):
  ```
  
  Examples:
    $ airs-cli doctor
    $ airs-cli doctor --output json | jq '.[] | select(.status != "pass")'
  ```
  When `AIRS_CLI_INVOKED_AS='airs cli'`, the text is rewritten to `airs cli ...` (`src/cli/invocation.ts:2-9`; test at `tests/unit/cli/invocation.spec.ts:15-23`). Help options are sorted (program.ts:73-76).
- `doctor` is **not** in `READ_COMMAND_NAMES` (program.ts:18-39). The preAction output resolution, which loads the tenant config, never runs for doctor.
  - Doctor resolves output itself with `{ ignoreConfig: true }` (doctor.ts:799).
  - So a tenant file's `defaultOutput` is **ignored by doctor**. The default is always `pretty` unless `--output` is given.

## 2. Data model

```ts
type DoctorStatus = 'pass' | 'warn' | 'fail' | 'skip';            // doctor.ts:36
interface DoctorCheck { name: string; status: DoctorStatus; detail: string; hint?: string } // :38-43
DOCTOR_TIMEOUT_MS = 5000                                           // :46
SUPPORTED_NODE_VERSIONS = '^20.17.0 || ^22.13.0 || >=23.5.0'        // :48
```
`skip` "never affects the exit code" (doctor.ts:32-35).

### Check order (fixed, 11 checks; `DOCTOR_CHECK_NAMES`, doctor.ts:51-63)
1. `Node.js version`
2. `Tenant`
3. `Config file`
4. `Environment`
5. `Scanner credentials`
6. `Management credentials`
7. `Typesafe credentials`
8. `Scanner API`
9. `Management OAuth`
10. `AI Gateway API`
11. `Typesafe API`

`runDoctor()` always returns all 11, in this order, and never throws (doctor.ts:646-737; test doctor.spec.ts:477-505).

Helpers:
- `plural(n, noun)` → `` `${n} ${noun}${n===1?'':'s'}` `` (doctor.ts:65-67).
- `notEvaluated(name)` → `{status:'skip', detail:'not evaluated — fix the failed checks above first'}` (doctor.ts:73-75). The dash is an em dash, U+2014.

## 3. Orchestration (`runDoctor`, doctor.ts:647-737)

1. `node = checkNodeVersion(process.version)`.
2. `context = resolveConfigContext(deps.configFilePath)`. The CLI calls `runDoctor()` with no deps (doctor.ts:800), so this always resolves through the **tenant registry**. The `explicit` selection is library or test only.
   - If the registry cannot be read, the error is caught and `tenant = tenantRegistryFailure(err, registryPath)`.
   - `registryPath` falls back to the literal `'the tenant registry'` when `tenantStorePath()` itself throws (doctor.ts:657-665).
   - **Early return:** `[node, tenant, ...9 × notEvaluated]` (doctor.ts:666-668; test :597-605).
3. `configFile = await checkConfigFile(context)` and `environment = checkEnvironment(process.env)`.
4. `inspected = await inspectConfig()` runs only if `selection !== 'none'` and `configFile.status !== 'fail'`. Exceptions are swallowed with the comment `// Reported by the config file check.` (doctor.ts:673-680).
   - `inspectConfig()` with no argument **re-reads the registry** and then calls `readTenantConfigFile(path, tsgId)` (loader.ts:73-78, 102-110).
5. The credential checks run on `inspected`:
   - `hasScanner` = scanner creds `pass`.
   - `hasMgmt` = mgmt creds `pass`. A `warn` counts as not-has.
   - `hasTypesafe` = typesafe creds `pass`.
6. The effective config for the probes is loaded **lazily and once**: `loadConfig({}, context.path)` (doctor.ts:690-696; test :607-634).
   - Passing the path makes `resolveConfigContext` treat it as `explicit` (loader.ts:57-58).
   - That route uses `fromFile`, which swallows read and parse errors and returns `{}` (loader.ts:17-24). It also does **no** TSG pin or size check, because those already ran in step 3.
7. The network probes run **sequentially**, each separately time-boxed: Scanner API → Management OAuth → AI Gateway API → Typesafe API (doctor.ts:703-722).
   - The first probe's 5 s budget also includes the lazy `loadConfig`, because `getConfig()` is awaited inside the probe closure.
   - Worst case is about 4 × 5 s = 20 s.
8. Exit: `process.exit(hasFailure(checks) ? 1 : 0)` (doctor.ts:823). `hasFailure` = any `fail` (doctor.ts:740-742).
   - `process.exit` is used deliberately: "a timed-out probe may hold a pending socket" (doctor.ts:821-822).
   - Timed-out probes are **not aborted**. `withTimeout` only races a timer (doctor.ts:331-343).

## 4. Each check: exact strings

### 4.1 `Node.js version` (doctor.ts:82-104)
- The regex is `^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`. Supported versions: 20.≥17, 22.≥13, 23.≥5, or ≥24. Pre-releases and malformed versions fail (tests :100-114).
- pass: `` `${version} (^20.17.0 || ^22.13.0 || >=23.5.0 required)` ``
- fail: `` `${version} does not satisfy ^20.17.0 || ^22.13.0 || >=23.5.0` ``, hint `Use a supported Node runtime: 20.17+, 22.13+, or 24+ (e.g. via nvm or your package manager)`
- A test pins it equal to `package.json` `engines.node` (:80-85).
- **Not meaningful for a Rust binary.**

### 4.2 `Tenant` (doctor.ts:107-139)
| context | status | detail | hint |
|---|---|---|---|
| `tenant` | pass | `` `${tenant.name} (TSG ${tenant.tsgId}) selected in ${registryPath}` `` | — |
| `explicit` (library only) | pass | `` `explicit config path — ${path}` `` | — |
| `none`, tenants registered | fail | `` `no tenant selected (registered: ${names.join(', ')})` `` | `Run 'airs-cli tenant switch <name>'` |
| `none`, none registered | fail | `` `no tenants registered in ${registryPath}` `` | `Run 'airs-cli tenant create <name>' (prompts for TSG ID, client ID and secret), then 'airs-cli tenant switch <name>'` |
| registry unreadable | fail | the error message, e.g. `Cannot read tenant registry at <path>; restore a valid registry before proceeding` (tenants.ts:59-61) or `XDG_STATE_HOME must be an absolute path` (tenants.ts:38) | `` `Restore or remove ${registryPath}; PRISMA_AIRS_CONFIG_PATH bypasses the registry meanwhile` `` (**stale:** that variable is ignored; see discrepancies) |

Registry resolution (`src/config/tenants.ts:34-63`):
- Path:
  - If `PRISMA_AIRS_TENANTS_PATH` is non-empty, use `resolve(expandConfigPath(it))`.
  - Otherwise, if `XDG_STATE_HOME` is set, it must be absolute; the path is `<XDG_STATE_HOME>/prisma-airs/tenants.json`.
  - Otherwise the path is `~/.local/state/prisma-airs/tenants.json`.
- A missing registry (ENOENT) counts as an empty store.
- These conditions are treated as corrupt (fail closed):
  - the file is a symlink or not a regular file (`lstatSync`);
  - it is larger than 1 048 576 bytes;
  - the JSON is invalid;
  - the strict schema fails. The schema is `{version:1, active:string|null, tenants:[{name,configPath(absolute),tsgId(min1)}] max 1000}`, with unique names, `active` either null or a registered name, and names matching `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`.
- The active tenant is `tenants.find(name === active)`.
- Registered names are listed in registry order. `tenant create` sorts entries by `localeCompare` (tenants.ts:158).

### 4.3 `Config file` (doctor.ts:145-226)
Evaluated in this order. The first match wins.
1. `selection === 'none'` → `notEvaluated`.
2. `readFile(path)` throws, for any reason, including EISDIR or EACCES → fail `` `not found at ${path}` ``.
   - Hint for a tenant: `` `Restore the file, or register another with 'airs-cli tenant create <name> --config <path>' and delete '${tenant.name}'` ``
   - Hint for explicit: `Create the file or pass an existing one`
3. `JSON.parse` fails → fail `` `${path} is not valid JSON` ``, hint `Fix the file, then re-run doctor`.
4. Not a plain object (null or array) → fail `` `${path} is not a JSON object` ``, hint `Fix the file — it must contain a single JSON object`.
5. `ConfigSchema.safeParse` fails → fail `` `${path} has invalid values for: ${uniqueIssuePaths.join(', ')}` ``. Paths are joined with `.`; the root is shown as `(root)`. Hint: `Fix them with 'airs-cli tenant set <name> <key>' (values are never printed here)`.
   - **Values are never echoed** (test :168-177 asserts that neither `99` nor `SUPER-SECRET` appears).
6. **Wrong-tenant / TSG pin** (tenant selection only): `parsed.mgmtTsgId !== tenant.tsgId`, compared strictly on the raw value, so a missing value also mismatches.
   - fail: `` `${path} carries a different mgmtTsgId than the registration (TSG ${tenant.tsgId})` ``
   - hint: `Register the file under a new tenant name with 'airs-cli tenant create <name> --config <path>'`
   - **The file's TSG is deliberately not printed** (test :186-193 asserts `200` is absent).
7. Keys not in `ConfigSchema.shape` → warn `` `valid at ${path}; ignored ${plural(n,'key')}: ${keys.join(', ')}` ``, in file key order.
   - If any of them are retired (`redTeamTokenEndpoint`, `modelSecTokenEndpoint`, `agentGuardTokenEndpoint`, `aiGwTokenEndpoint`; schema.ts:66-71), the hint is `` `Every product authenticates through mgmtTokenEndpoint now (${retired.join(', ')} ignored); remove them with 'airs-cli tenant unset <name> <key>'` ``.
   - Otherwise the hint is `Remove unknown keys with 'airs-cli tenant unset <name> <key>'` (test :196-213).
8. pass:
   - tenant: `` `valid tenant config at ${path} (TSG ${tsgId} matches registration)` ``
   - explicit: `` `valid JSON at ${path}` ``

The schema keys are listed in `src/config/schema.ts:10-56`. Note `z.coerce.number()` for `airsNumRetries` (0-5) and `scanConcurrency` (1-20, default 5), and `.url()` on `mgmtDashboardEndpoint`, `agentGuard*Endpoint` and `typesafeBaseUrl`.

`checkConfigFile` uses plain `readFile`, with no size or regular-file check. The later `inspectConfig` uses `readTenantConfigFile`, which applies `lstat(realpath)`, `isFile` and ≤ 1 MiB checks and throws the generic `Cannot read a valid tenant config at <path>` (tenants.ts:75-95). That throw is swallowed (see discrepancies).

### 4.4 `Environment` (doctor.ts:233-247; src/config/env.ts)
- The **ignored** set (env.ts:42-51) contains every non-empty variable that either:
  - starts with `PANW_`, except the three SDK diagnostic switches `PANW_AI_SEC_DEBUG`, `PANW_AI_SEC_DEBUG_BODY` and `PANW_AI_SEC_TIMEOUT_MS`; or
  - is one of the retired names: `PRISMA_AIRS_CONFIG_PATH`, `TYPESAFE_API_KEY`, `TYPESAFE_BASE_URL`, `TYPESAFE_DEFAULT_MODEL`, `SCAN_CONCURRENCY`, `DATA_DIR`, `MEMORY_ENABLED`, `MEMORY_DIR`, `MAX_MEMORY_CHARS`, `ACCUMULATE_TESTS`, `MAX_ACCUMULATED_TESTS`.
- The set is sorted with JS default (code-unit) order. **Names only, never values.**
- `PRISMA_AIRS_TENANTS_PATH` and `XDG_STATE_HOME` are never flagged (test `tests/unit/config/env.spec.ts:8-33`).
- The diagnostics suffix lists each of the three switches that is non-empty, in fixed order: `` `; SDK diagnostics on: ${list.join(', ')}` ``. `PANW_AI_SEC_DEBUG=0` counts as "on" because it is a non-empty string.
- warn: `` `ignored ${plural(n,'variable')}: ${names.join(', ')}${suffix}` ``, hint `Configuration comes only from tenant files ('airs-cli tenant set <name> <key>'); unset these`
- pass: `` `no configuration variables set${suffix}` ``
- **This check is never `fail`.** The docs claim otherwise; see discrepancies.

### 4.5 Credential presence (doctor.ts:249-323; keys from credentials.ts:6-13)
`isSet` = value is not undefined, not null, and `String(v) !== ''`. It does **not trim** (doctor.ts:249-252). `inspectConfig` strips `''` and undefined before parsing, so an empty string has source `default`. The source is `file` or `default` (loader.ts:94-109).

**Scanner credentials** (keys `airsApiKey`, `airsApiToken`):
- Any key set → pass. Detail is the set keys as `` `${key} (${source})` `` joined with `, `, e.g. `airsApiKey (file)` or `airsApiKey (file), airsApiToken (file)` (test :247-255).
- None set → **skip**, `not configured — runtime scan, bulk-scan and topics eval are unavailable`, hint `settingRemedy(['airsApiKey'])`.
- `inspected` undefined → `notEvaluated`.

**Management credentials** (keys `mgmtClientId`, `mgmtClientSecret`, `mgmtTsgId`):
- All set → pass `set: mgmtClientId (file), mgmtClientSecret (file), mgmtTsgId (file)`.
- Any missing → status is **`warn` if scanner creds passed, otherwise `fail`**.
  - Detail: `` `missing: ${missing.join(', ')} — management, red team, model security, AI Gateway and AgentGuard commands are unavailable` ``
  - Hint: `settingRemedy(missing)` (test :283-295).

**Typesafe credentials** (key `typesafeApiKey`):
- pass `typesafeApiKey (file)`.
- skip `not configured — redteam judge is unavailable`, hint `settingRemedy(['typesafeApiKey'])`.

`settingRemedy` (credentials.ts:37-51):
- tenant: `` `Run 'airs-cli tenant set ${name} <key>' for ${keys.join(', ')} (secrets prompt hidden, or use --stdin)` ``
- explicit: `` `Add ${keys} to ${path}` ``
- none: `Run 'airs-cli tenant create <name>' (prompts for the OAuth credentials), then 'airs-cli tenant switch <name>'`

### 4.6 Error classification shared by the probes
- `httpStatus(err) = err.status ?? err.statusCode` (doctor.ts:345-348).
- `AUTH_REJECTED_PATTERN = /invalid api key|invalid.*oauth token|api key or oauth token|unauthorized|forbidden/i` (doctor.ts:355-356). The comment says the scanner SDK surfaces auth rejections only in the message, e.g. `AISEC_CLIENT_SIDE_ERROR:Invalid API Key or OAuth Token`.
- Timeout detail, identical across all four probes: `` `timed out after ${timeoutMs}ms — network unreachable or endpoint not responding` ``, which renders as `timed out after 5000ms — ...`.
- Error messages from the SDK or `fetch` are embedded **verbatim** after a colon.

### 4.7 `Scanner API` (doctor.ts:366-414, probe :614-618)
**Probe:**
- `init(runtimeInitOptions(config)); new Scanner().queryByScanIds([randomUUID()])`.
- This is a **results GET, not a scan**. No content is submitted and no profile is used. The design comment at :605-613 says this is deliberate, to avoid burning scan quota.
- `runtimeInitOptions` (client-options.ts:89-97) asserts a scanner credential (trimmed), then passes `{apiKey, apiToken, apiEndpoint: airsApiEndpoint ?? 'https://service.api.aisecurity.paloaltonetworks.com', numRetries: airsNumRetries}`.

**Expected wire shape [SDK]:**
- `GET {airsApiEndpoint}/v1/scan/results?scan_ids=<uuid-v4>`
- Header `x-pan-token: <airsApiKey>`, or `Authorization: Bearer <airsApiToken>` for a token.
- No body.
- Rust equivalents: scm-sdk-rs `constants.rs:644-645,747` and `airs/scan/scanner.rs:201-214`. The Rust SDK validates 1–5 UUIDs.

**Results:**
| outcome | status | detail | hint |
|---|---|---|---|
| no scanner creds | skip | `skipped — no scanner credentials configured` | — |
| timeout | fail | timeout text | `Check network connectivity and the airsApiEndpoint setting` |
| resolves (e.g. `200 []`) | pass | `endpoint reachable, API key accepted` | — |
| status 401/403 **or** message matches pattern | fail | `` `API key rejected${status?` (HTTP ${status})`:''}: ${message}` `` | `Verify airsApiKey belongs to this tenant and is not expired` |
| any other HTTP status (404, 429, **5xx**) | **pass** | `` `endpoint reachable, API key accepted (HTTP ${status} on probe query)` `` | — |
| no status | fail | `` `network unreachable: ${message}` `` | `Check network connectivity, proxy settings, and DNS` |

The pattern test runs before the status test, so a 404 whose message contains "unauthorized" is reported as a rejection. Tests: :364-409.

### 4.8 `Management OAuth` (doctor.ts:417-459, probe :621-625)
**Probe:**
- `new SdkManagementService(managementClientOptions(config)).listTopics()`, which is `client.topics.listAll()`, a **full traversal of every custom-topic page** (`src/airs/management.ts:55-57`).
- `managementClientOptions` (client-options.ts:34-51) passes:
  - `clientId`, `clientSecret`, `tsgId`;
  - `tokenEndpoint: mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT` (`https://auth.apps.paloaltonetworks.com/oauth2/access_token`);
  - `apiEndpoint: mgmtEndpoint ?? 'https://api.apps.paloaltonetworks.com/aisec'`;
  - plus the dashboard and DLP endpoints.
  - It asserts the mgmt creds first (trimmed).
- The client is a process-wide singleton (`management.ts:549-551`).
- OAuth is verified **by a successful authenticated call, not a bare token fetch**.

**Expected wire shape [SDK]:**
1. `POST {tokenEndpoint}`, `application/x-www-form-urlencoded`, body `grant_type=client_credentials&scope=tsg_id:<tsg>`.
   - Client authentication is either HTTP Basic `client_id:client_secret` or the form fields `client_id`/`client_secret`. The integration fixture accepts both (`tests/integration/dlp-tenant-auth.spec.ts:46-70`). Rust always uses Basic with form-urlencoded id and secret (scm-sdk-rs `auth.rs:615-633`).
   - Response: `{"access_token":"…","expires_in":3600,"token_type":"Bearer"}`.
2. `GET {mgmtEndpoint}/v1/mgmt/topics/tsg/<tsg>?offset=0&limit=<n>`, `Authorization: Bearer <token>`.
   - This repeats while the response carries `next_offset`.
   - Response: `{"custom_topics":[…], "next_offset"?:n}`.
   - Rust: `constants.rs:698`, `management/topics.rs:80-94,180-194`, default `limit=100` at `topics.rs:35`. The TS SDK limit and the revision counting of `listAll` are SDK-internal.

**Results:**
| outcome | status | detail | hint |
|---|---|---|---|
| mgmt creds not `pass` (including the scanner-only `warn`) | skip | `skipped — management credentials not configured` | — |
| timeout | fail | timeout text | `Check network connectivity and the mgmtTokenEndpoint / mgmtEndpoint settings` |
| resolves with n | pass | `` `OAuth token obtained, topics API answered (${plural(n,'custom topic')})` `` | — |
| error with status | fail | `` `management API error (HTTP ${status}): ${message}` `` | `Verify mgmtClientId / mgmtClientSecret / mgmtTsgId belong to this tenant` |
| no status, message matches pattern or `/oauth\|invalid_client/i` | fail | `` `authentication failed: ${message}` `` | same |
| otherwise | fail | `` `network unreachable: ${message}` `` | same |

The tests assume the real SDK OAuth failure has no status, e.g. `AISEC_OAUTH_ERROR:invalid_client` (:430-435). Every error is a `fail`, including a 403 on topics.

### 4.9 `AI Gateway API` (TS only; doctor.ts:467-516, probe :628-632)
- Probe: `new SdkAiGatewayService(aiGatewayClientOptions(config)).listWorkspaces()`, a data-plane list. **[SDK]** It is `GET {aiGwDataEndpoint ?? https://api.apps.paloaltonetworks.com/ai_gw/v2}/workspaces` with a Bearer token, after its own OAuth token request.
- Skips when mgmt creds are not `pass`: `skipped — management credentials not configured`.
- pass: `` `endpoint reachable (${plural(n,'workspace')} in scope)` ``
- 403 → **warn**: `` `endpoint reachable, but access denied (HTTP 403): ${message}` ``, with a hint from `aiGatewayGrantHint` (`src/airs/aigateway.ts:87-100`; mentions `workspace-scope grant` when the message contains `AB03`).
- Other HTTP errors → fail `AI Gateway API error (HTTP n): …`. No status → fail `network unreachable: …`, hint `Verify the tenant credentials and network connectivity`.
- Timeout hint: `Check network connectivity to api.apps.paloaltonetworks.com`.

### 4.10 `Typesafe API` (TS only; doctor.ts:525-578; providers.ts:261-289)
- `GET {typesafeBaseUrl ?? https://api.typesafe.ai}/v1/models` with headers `Authorization: Bearer <key>` and `Accept: application/json`, `redirect:'error'` and its own `AbortSignal.timeout(5000)`.
- 2xx with a `models` array → pass `` `endpoint reachable, API key accepted (${plural(n,'model')} listed)` ``.
- 401/403 → **warn** `` `endpoint reachable, but API key rejected (HTTP ${s}): ${message}` ``, hint `Verify typesafeApiKey is a current TypeSafe key; only redteam judge is affected`.
- 429 → **warn**, hint `Retry later; redteam judge backs off automatically`.
- Others → fail `TypeSafe API error (HTTP n): …` or `network unreachable: …`.
- Skip detail: `skipped — typesafeApiKey not configured`.
- This is the only probe whose default implementation is tested over the wire (test :657-693, which also asserts the key never appears in the output).

## 5. Output formats and streams

The formats are `pretty`, `table`, `markdown`, `csv`, `json` and `yaml` (common.ts:33-40). An unknown value throws `CliUsageError`: `` `Invalid output format '${x}'. Expected: pretty, table, markdown, csv, json, yaml` `` (common.ts:64-67). For doctor this error is **not caught**; see §6.

**Structured** (doctor.ts:806-818; common.ts:96-143): the rows are the checks, with columns `Name`, `Status`, `Detail`, `Hint`. Everything goes to **stdout** via one `console.log`, plus a trailing newline.
- `json`: `JSON.stringify(checks, null, 2)`. It is an array of 11 objects with key order `name, status, detail[, hint]`. `hint` is omitted when absent, never `null`. Example element: `{"name":"Scanner API","status":"skip","detail":"skipped — no scanner credentials configured"}`.
- `yaml`: `js-yaml dump(rows,{noRefs:true,lineWidth:-1}).trimEnd()`.
- `csv`: header `Name,Status,Detail,Hint`. RFC4180 quoting applies when a cell contains `"`, `,`, CR or LF. A missing hint is an empty cell.
- `markdown`: `| Name | Status | Detail | Hint |` / `| --- | --- | --- | --- |`, with `\` and `|` escaped and newlines rendered as `<br>`.
- `table`: box drawing, ` col │ col `, with a `─…┼…` rule.

**Pretty** (doctor.ts:769-780; ui.ts):
- Header (`ui.header`, stdout, suppressed by `--quiet`):
  ```
  \n  Doctor\n  Prisma AIRS CLI preflight checks\n\n
  ```
  "Doctor" is bold and the subtitle is dim.
- One line per check: `  <glyph> <name> — <detail>` (`ui.bullet`, stdout, **not** quiet-suppressed).
  - Glyphs: pass `✓` (green), warn `⚠` (yellow), fail `✗` (red), skip `○` (yellow).
- Hint, when present: `ui.dim('    '+hint)`, which is six spaces then the hint, dim, on stdout, suppressed by `--quiet`.
- Then a blank line (stdout), the summary, and another blank line (stdout).
  - The summary goes through `ui.success` → **stdout** `  ✓ <msg>` when nothing failed, or through `ui.error` → **stderr** `  ✗ <msg>` when anything failed.
- Summary text (`summarize`, doctor.ts:756-767):
  - Failures: `` `${plural(fails,'check')} failed` ``, e.g. `1 check failed` or `2 checks failed`.
  - Otherwise `All checks passed`, optionally followed by ` (<n warning[s]>, <n> skipped)` when there are warnings or skips. Examples: `All checks passed (1 warning, 2 skipped)`, `All checks passed (4 skipped)`.
- Color comes from chalk 5, which turns color off when stdout is not a TTY and honors `NO_COLOR`/`FORCE_COLOR` (renderer/DESIGN.md:45-47).
- In structured modes doctor writes **nothing to stderr**. The exceptions are the `--debug` status line `  Debug: API log → <cwd>/debug-api-<ms>-<8hex>.jsonl` (program.ts:176-192) and any SDK debug logging when `PANW_AI_SEC_DEBUG` is set **[SDK]**.
- Hints, but not details, pass through `commandHint` (doctor.ts:800-802), which rewrites `airs-cli ` to `airs cli ` under `AIRS_CLI_INVOKED_AS='airs cli'`.

## 6. Exit codes
- `0`: no check is `fail`. Warns and skips are fine (doctor.ts:739-742; tests :695-718).
- `1`: any `fail`. Also:
  - **an invalid `--output`**: the `CliUsageError` escapes the async action and is never passed to `fail()`. It surfaces as a rejected top-level `await` in `src/cli/index.ts:7`. Under Node 24 this bypasses the `unhandledRejection` guard (process-guards.ts:13), prints a raw stack (`CliUsageError: Invalid output format 'bogus'. Expected: …`) and exits **1**. Verified with an equivalent standalone ESM script on Node v24.21.0.
  - **Commander parse errors**: an unknown option, an excess argument (Commander ≥13 rejects excess args by default; the lock pins 14.0.3) or a missing option value. There is no `exitOverride` anywhere in `src`, so Commander's default exit code 1 applies.
  - `--debug` when the log file cannot be created: `ui.error(...)` and exit 1.
- `2`: **never produced by doctor**. `usageError()` (common.ts:27-30) is not reachable from doctor's code path.
- `--help` exits 0 with help on stdout.

## 7. Secret safety (what is and is not guaranteed)
- Credential details show **key names and sources only** (tests :247-305).
- Schema failures list key paths only. The TSG-mismatch message omits the file's TSG.
- The environment check prints names only.
- `--debug` logs are redacted by `installDebugLogger`; this is out of scope.
- **Not guaranteed:** probe details embed `err.message` verbatim from the TS SDK or `fetch`. Whether those messages can contain response bodies, URLs or credentials is SDK-dependent **[SDK]**.
- Paths and the registered TSG ID are printed in pass details. They are treated as non-secret.

## 8. Where credential env vars are ignored
- Doctor never reads `PANW_*` values. It only lists their names.
- The probes build SDK options solely from the tenant file (client-options.ts:29-42).
- **Gap [SDK]:** `runtimeInitOptions` passes `apiKey`/`apiToken`/`numRetries` as `undefined` when they are unset. Whether TS SDK `init()` then falls back to `PANW_AI_SEC_API_KEY`/`_TOKEN`/`_NUM_RETRIES` is not tested. The only test (client-options.spec.ts:194-199) covers the no-credential case. The Rust SDK reads no environment implicitly (scm-sdk-rs `environment.rs:1`), so this risk is absent in Rust.

## 9. Test coverage (what is actually executable-verified)
- Every doctor test is a **unit test with injected probes**. There is no executable-level, integration or E2E test of `airs-cli doctor`. That leaves these untested:
  - stdout/stderr split, pretty rendering and exit codes through the binary;
  - `commandHint` on hints;
  - the default Scanner, Management and AI Gateway probes over HTTP.
- Only the TypeSafe default probe is wire-tested. The HTTP shapes in §4.7–4.9 are therefore defined by the TS SDK, not pinned by CLI tests.
- Live scripts use `AIRS_E2E_TENANT` (`scripts/lib/live-tenant.mjs:29-35`, `tests/helpers/live-tenant.ts:7-13`). None runs doctor.

## 10. Proposed scoped doctor for airs-cli-rs (release 1: config, OAuth, scanner)

**Keep, with identical names, order relative to each other, statuses, detail and hint strings:**
1. `Tenant`
2. `Config file`
3. `Environment`
4. `Scanner credentials`
5. `Management credentials`
6. `Scanner API`
7. `Management OAuth`

**Omit:** `Node.js version` (meaningless for a native binary), `Typesafe credentials`/`Typesafe API` (M6 judge scope) and `AI Gateway API` (M6). The harness compares TS and Rust **by check name, on the intersection**. Do not invent new checks under TS names. If a build-identity line is wanted, add it as a new name such as `airs-cli-rs version`, and only after deciding (see open questions).

Implementation notes for fidelity:
- **Registry and config: read-only.**
  - Same path resolution: `PRISMA_AIRS_TENANTS_PATH` → `XDG_STATE_HOME` (must be absolute) → `~/.local/state`.
  - Same strict registry schema, 1 MiB limit, and regular-file and no-symlink rule for the registry.
  - Never open `.lock` files and never write anything.
  - Validate the config file once with the stricter rules: realpath, regular file, ≤ 1 MiB, object, schema, TSG pin. Then derive both the presence checks and the probe config from that single parsed value. This avoids the TS double-read and its silent-pass gap.
- **Environment:** reproduce `ignoredEnvironment` exactly. Decide how to classify `PANW_AI_SEC_DEBUG*`/`TIMEOUT_MS`, since the Rust SDK does not read them.
- **Scanner API:** use `Scanner::query_by_scan_ids(&[uuid_v4])`, i.e. `GET /v1/scan/results?scan_ids=<uuid>` with `x-pan-token`. Use a 5000 ms per-check budget enforced by cancellation (drop or abort the request). Map 401/403 → `API key rejected (HTTP n): …`, other HTTP → pass `(HTTP n on probe query)` (or fix 5xx; see open questions), transport → `network unreachable: …`.
- **Management OAuth:** the token fetch plus `topics.list_all(TopicListAllOptions::default())` within a 5000 ms budget. Count = traversed items. Map a token-endpoint `ErrorKind::Authentication` to `authentication failed: …`, which matches the TS SDK's status-less shape, and an HTTP status from the topics call to `management API error (HTTP n): …`.
- **Local HTTP fixtures need loopback endpoints:** Rust `Endpoint` permits `http` only through `Endpoint::loopback` (scm-sdk-rs `config.rs:12-40`). The CLI must opt in for literal loopback hosts in tenant files, and only for those.
- **TS side gotcha for side-by-side runs:** the TS doctor **always** runs the AI Gateway probe when mgmt creds pass. The fixture tenant file must set `aiGwDataEndpoint`, `aiGwAdminEndpoint` and `iamEndpoint` (plus `mgmtEndpoint`, `mgmtTokenEndpoint`, `airsApiEndpoint`) to the loopback server. Otherwise the TS run contacts `api.apps.paloaltonetworks.com` with fixture credentials. Leave `typesafeApiKey` unset.
- **Exit codes:** 0 or 1 per §6. For usage errors (bad `--output`, unknown flag, extra argument), recommend exit 2 with a `  ✗ <message>` stderr line. This is an intentional divergence from TS, which exits 1.


## Acceptance criteria
- With a healthy fixture tenant (mgmt + airsApiKey, every endpoint pointed at loopback), `airs-cli-rs doctor --output json` exits 0. stdout is a JSON array of objects whose keys are exactly name,status,detail with an optional string hint (never null), and stderr is empty.
- The check names in JSON output appear in this order: Tenant, Config file, Environment, Scanner credentials, Management credentials, Scanner API, Management OAuth. This is the TS DOCTOR_CHECK_NAMES order restricted to the scoped subset.
- Tenant pass detail equals `<name> (TSG <tsgId>) selected in <absolute registry path>`.
- Config file pass detail equals `valid tenant config at <configPath> (TSG <tsgId> matches registration)`.
- With no registry file at PRISMA_AIRS_TENANTS_PATH: Tenant is fail with detail `no tenants registered in <registryPath>` and a hint containing `airs-cli tenant create <name>`. Config file, Scanner credentials and Management credentials are skip with detail `not evaluated — fix the failed checks above first`. Scanner API is skip with `skipped — no scanner credentials configured`, Management OAuth is skip with `skipped — management credentials not configured`, zero HTTP requests are made, and the exit code is 1.
- A registry with tenants a,b and active=null gives Tenant fail with detail `no tenant selected (registered: a, b)` and hint `Run 'airs-cli tenant switch <name>'`, and exit 1.
- A corrupt registry (invalid JSON, a symlink, over 1 MiB, or a strict-schema violation) gives Tenant fail with detail `Cannot read tenant registry at <path>; restore a valid registry before proceeding`. Every later check is skip with `not evaluated — fix the failed checks above first`, and the exit code is 1.
- A relative XDG_STATE_HOME with PRISMA_AIRS_TENANTS_PATH unset gives Tenant fail with detail `XDG_STATE_HOME must be an absolute path`, and exit 1.
- When the selected tenant file's mgmtTsgId differs from the registry tsgId: Config file is fail with detail `<path> carries a different mgmtTsgId than the registration (TSG <registeredTsg>)`, the file's TSG appears nowhere in stdout or stderr, zero HTTP requests are made, and the exit code is 1.
- A missing tenant config file gives Config file fail with detail `not found at <path>` and a hint containing `airs-cli tenant create <name> --config <path>`.
- Malformed JSON gives `<path> is not valid JSON`. A JSON array gives `<path> is not a JSON object`. Both are fail with exit 1.
- A file with scanConcurrency 99 and mgmtClientSecret SUPER-SECRET gives Config file fail with detail `<path> has invalid values for: scanConcurrency`, and neither `99` nor `SUPER-SECRET` appears in stdout or stderr.
- A file with the extra keys redTeamTokenEndpoint and custom gives Config file warn with detail `valid at <path>; ignored 2 keys: redTeamTokenEndpoint, custom`. The hint contains `airs-cli tenant unset <name> <key>` and `redTeamTokenEndpoint`, and the exit code stays 0 when nothing else fails.
- With PANW_MGMT_CLIENT_SECRET=ENV-SECRET, PANW_MGMT_TSG_ID=999 and PRISMA_AIRS_CONFIG_PATH=/x set: Environment is warn with detail `ignored 3 variables: PANW_MGMT_CLIENT_SECRET, PANW_MGMT_TSG_ID, PRISMA_AIRS_CONFIG_PATH`, ENV-SECRET appears nowhere, and the fixture sees OAuth scope `tsg_id:<file tsg>` with the tenant-file client id.
- A clean environment (only HOME, PATH, PRISMA_AIRS_TENANTS_PATH, NO_COLOR) gives Environment pass with detail `no configuration variables set`.
- airsApiKey in the file gives Scanner credentials pass with detail `airsApiKey (file)`, and the key value is never printed.
- With no airsApiKey or airsApiToken: Scanner credentials is skip with detail `not configured — runtime scan, bulk-scan and topics eval are unavailable` and hint `Run 'airs-cli tenant set <name> <key>' for airsApiKey (secrets prompt hidden, or use --stdin)`. Scanner API is skip, no request reaches /v1/scan/results, and this alone does not cause exit 1.
- With airsApiKey set but mgmtClientId and mgmtClientSecret missing: Management credentials is warn with detail `missing: mgmtClientId, mgmtClientSecret — management, red team, model security, AI Gateway and AgentGuard commands are unavailable`. Management OAuth is skip with no token request, and the exit code is 0.
- With mgmtClientId and mgmtClientSecret missing and no scanner key, Management credentials is fail and the exit code is 1.
- The scanner probe sends exactly one `GET <airsApiEndpoint>/v1/scan/results` whose single `scan_ids` query value is a UUID, with header `x-pan-token` equal to the file's airsApiKey and no body. No request is made to /v1/scan/sync/request or /v1/scan/async/request.
- When the scanner fixture replies 200 `[]`, Scanner API is pass with detail `endpoint reachable, API key accepted`.
- When the scanner fixture replies 401, Scanner API is fail with detail starting `API key rejected (HTTP 401)` and hint `Verify airsApiKey belongs to this tenant and is not expired`, the exit code is 1, and the key never appears in output.
- When the scanner fixture replies 404, Scanner API is pass with detail `endpoint reachable, API key accepted (HTTP 404 on probe query)`.
- When the scanner fixture accepts the connection but never responds, Scanner API is fail with detail `timed out after 5000ms — network unreachable or endpoint not responding` and hint `Check network connectivity and the airsApiEndpoint setting`. The process exits within about 5 s plus a small margin per hung check.
- With airsApiEndpoint pointing at a closed loopback port, Scanner API is fail with detail starting `network unreachable: ` and hint `Check network connectivity, proxy settings, and DNS`.
- The Management OAuth probe sends one POST to mgmtTokenEndpoint with form grant_type=client_credentials and scope=tsg_id:<tsg>, carrying the file's client credentials as Basic auth or as form fields. It then sends GET <mgmtEndpoint>/v1/mgmt/topics/tsg/<tsg> with `Authorization: Bearer <token>`.
- When the topics fixture returns 2 topics and no next_offset, Management OAuth is pass with detail `OAuth token obtained, topics API answered (2 custom topics)`. With 1 topic, the detail ends `(1 custom topic)`.
- When the token endpoint returns 401, Management OAuth is fail with hint `Verify mgmtClientId / mgmtClientSecret / mgmtTsgId belong to this tenant`, no topics request is made, the secret appears nowhere, and the exit code is 1.
- When the token request succeeds and topics returns 403 or 500, Management OAuth is fail with detail starting `management API error (HTTP 403)` or `(HTTP 500)`.
- A hung token endpoint gives Management OAuth fail with the timeout detail and hint `Check network connectivity and the mgmtTokenEndpoint / mgmtEndpoint settings`.
- Probe order in the fixture request log is: the scanner results GET, then the token POST, then the topics GET(s).
- In every format (pretty, table, markdown, csv, json, yaml), stdout+stderr never contain mgmtClientSecret, airsApiKey, or the fixture access_token.
- The exit code is 0 when every check is pass, warn or skip, and 1 when any check is fail.
- `--output yaml` emits a YAML sequence of mappings with name/status/detail/hint. `--output csv` starts with the header `Name,Status,Detail,Hint`. `--output markdown` starts with `| Name | Status | Detail | Hint |` followed by `| --- | --- | --- | --- |`.
- Pretty output (NO_COLOR=1): stdout begins `\n  Doctor\n  Prisma AIRS CLI preflight checks\n\n`. Each check line is `  <✓|⚠|✗|○> <Name> — <detail>`, and each hint line is six spaces then the hint.
- Pretty summary: `  ✓ All checks passed` or `  ✓ All checks passed (1 warning, 2 skipped)` goes to stdout when nothing failed. `  ✗ N check(s) failed` goes to stderr when something failed.
- With `--quiet` in pretty mode, the header and hint lines are suppressed while the check lines and summary still print.
- `defaultOutput: "json"` in the tenant file does not change doctor's format: without --output the output is pretty.
- `airs-cli-rs --output json doctor` and `airs-cli-rs doctor --output json` produce identical stdout.
- `airs-cli-rs doctor --output bogus` exits 2 with stderr containing `Invalid output format 'bogus'. Expected: pretty, table, markdown, csv, json, yaml` and empty stdout. This is an intentional divergence from TS, which exits 1 with a stack trace.
- After any doctor run, the registry and tenant config file have unchanged bytes and mtime, no `tenants.json.lock` or temp file exists, and nothing is written to the working directory (without --debug).


## Discrepancies
- Docs vs code: quick-start.md:39-41 says "a conflicting environment ... is `fail`". In the code, the Environment check can only be pass or warn (doctor.ts:233-247).
- Docs vs code: quick-start.md:41 says missing management credentials are `fail`. The code makes them `warn` when scanner credentials are present, i.e. a scanner-only setup (doctor.ts:282-302; test :293-295).
- Docs vs code: the Environment docs (quick-start.md:20-22, tenant.md:110-112, release-notes.md:119-122) say only `PANW_*` or `PRISMA_AIRS_CONFIG_PATH` are listed. The code also flags TYPESAFE_API_KEY/BASE_URL/DEFAULT_MODEL, SCAN_CONCURRENCY, DATA_DIR, MEMORY_ENABLED, MEMORY_DIR, MAX_MEMORY_CHARS, ACCUMULATE_TESTS and MAX_ACCUMULATED_TESTS, and it excludes PANW_AI_SEC_DEBUG, PANW_AI_SEC_DEBUG_BODY and PANW_AI_SEC_TIMEOUT_MS (env.ts:8-31).
- Docs vs code: tenant.md:112 says doctor "phrases every remedy as `airs-cli tenant set <name> <key>`". Many hints use tenant create, switch or unset, or are non-CLI advice such as network checks or 'Fix the file'.
- Docs vs code: the old release note (release-notes.md:590) says doctor "Supports --output json|yaml". It now supports all six formats.
- Stale hint/bug: tenantRegistryFailure's hint says `PRISMA_AIRS_CONFIG_PATH bypasses the registry meanwhile` (doctor.ts:137), but that variable is retired and ignored (env.ts:19), and the Environment check warns about it.
- Bug: `--output bogus` throws CliUsageError from inside the doctor action, and nothing catches it (doctor.ts:799). The rejection reaches the top-level await in src/cli/index.ts:7 and bypasses the unhandledRejection guard, so Node prints a raw stack and exits 1 instead of the CLI's usage contract (exit 2 via usageError, common.ts:27-30). The Node 24 behavior was verified with an equivalent ESM script.
- Exit-code contract gap: there is no Commander exitOverride anywhere in src, so unknown options, excess arguments (Commander 14 rejects them by default) and missing option values exit 1, not 2. Only CliUsageError routed through fail() or usageError() exits 2.
- Bug (false healthy): checkConfigFile uses plain readFile with no size or regular-file limit (doctor.ts:151). inspectConfig uses readTenantConfigFile, which rejects files over 1 MiB and non-regular files (tenants.ts:82-83), and its throw is swallowed with the comment 'Reported by the config file check' (doctor.ts:675-679). In that case nothing reports it: the credentials become 'not evaluated' skips, the probes skip, and doctor exits 0.
- Bug: credential presence uses an untrimmed isSet (doctor.ts:249-252), but the probes assert trimmed presence (credentials.ts:15-17). A whitespace-only secret or key passes the presence check, then the probe throws 'Management/Scanner credentials are not configured ...'. That message has no status and does not match the auth patterns, so it is reported as `network unreachable: ...`.
- Questionable classification: in the Scanner API check, any non-401/403 HTTP status, including 429 and 5xx, is reported as pass `endpoint reachable, API key accepted (HTTP n on probe query)` (doctor.ts:398-406). A 5xx does not prove the key was accepted. The SDK likely retries 5xx, so in practice it may time out first [SDK].
- Misleading detail: after a failed Config file check, the probe skip details say `skipped — no scanner credentials configured` and `skipped — management credentials not configured`, even though the credentials were never evaluated.
- Misleading detail: any readFile error (EISDIR, EACCES) on the config is reported as `not found at <path>` (doctor.ts:152-161).
- Misleading detail: a TypeSafe 2xx response without a `models` array throws ProviderError without a status and is reported as `network unreachable: TypeSafe models response has no models array`.
- Comment vs code: doctor.ts:689 says probes never do 'a second registry lookup', but the CLI's default inspectConfig() (no path) does re-resolve the registry (loader.ts:73-78, 102-104). The probes load the file via the 'explicit' fromFile route, which silently returns {} on read errors and skips the TSG pin (loader.ts:17-24, 57-58, 76).
- Timeouts do not abort: withTimeout only races a timer (doctor.ts:331-343). Requests that time out keep running until process.exit. The 5 s budget is per probe, sequential (up to about 20 s in total), and the first probe's budget includes the lazy config load.
- Stream split in pretty mode: the report body and the success summary go to stdout, but the failure summary goes to stderr (ui.error, doctor.ts:777). The pretty 'report' is data on stdout even though it is human-oriented.
- The Management OAuth probe performs a complete topics traversal (topics.listAll, management.ts:55-57), not a minimal call. The doc comment calls it the 'smallest authenticated GET'. Its count, and whether it includes every revision, depends on the TS SDK.
- SDK-dependent env leakage risk: runtimeInitOptions passes apiKey/apiToken/numRetries as undefined when unset (client-options.ts:91-96). No test proves the TS SDK then ignores PANW_AI_SEC_API_KEY/TOKEN/NUM_RETRIES; the only test covers the case with no credential at all (client-options.spec.ts:194-199).
- Test coverage gap: doctor has only unit tests with injected probes (doctor.spec.ts). No test runs the doctor executable, pretty rendering, exit codes or stdout/stderr split, and no test checks the HTTP shape of the default Scanner, Management or AI Gateway probes. Only the TypeSafe default probe is wire-tested (:657-693).
- A per-subcommand `--output` is declared on doctor (doctor.ts:788), but Commander's non-positional option parsing assigns it to the root `--output` (program.ts:108). resolveOutput papers over this by checking both sources (common.ts:53-57). The behavior is equivalent, but the doctor-local option value is never set.
- judge.md:39 and :47 refer to `/doctor` (the Harness command), not `airs-cli doctor`. command-migration.md:15 says `airs doctor` now means harness diagnostics. Do not conflate these with the product doctor.


## Open questions
- How does airs-cli-rs select the tenant for M1's 'explicitly selected existing tenant configuration'? The TS CLI has no per-command --tenant/--config flag; it uses the registry's `active` pointer. Options: read the TS registry read-only at the same path (PRISMA_AIRS_TENANTS_PATH/XDG_STATE_HOME), add a `--tenant <name>` flag, or both. If a flag exists, does the Tenant pass detail stay `<name> (TSG <tsg>) selected in <registry>`?
- Check set: should Rust omit Node.js version, Typesafe credentials, AI Gateway API and Typesafe API, so its JSON array has 7 entries vs TS's 11, with the harness comparing the by-name intersection? Or emit them as skip with a 'not supported in airs-cli-rs' detail? Should a new `airs-cli-rs version` check, with its own name, replace the Node check?
- Should Rust deliberately fix the TS bugs, recorded as divergences, or reproduce them for byte parity? The bugs are: invalid --output exiting 1 with a stack trace, scanner 5xx/429 counted as pass, whitespace-only credentials misreported as network errors, the >1 MiB or non-regular config silently passing, the stale PRISMA_AIRS_CONFIG_PATH hint, and the 'not configured' skip text after config failure. Recommendation: fix them and document each.
- How should PANW_AI_SEC_DEBUG, PANW_AI_SEC_DEBUG_BODY and PANW_AI_SEC_TIMEOUT_MS be treated? The Rust SDK never reads the environment, so the TS suffix '; SDK diagnostics on: ...' would be false for airs-cli-rs. Report them as ignored (warn), keep TS wording, or use a Rust-specific note?
- What text should follow the colon in error details? TS embeds raw SDK/fetch err.message (e.g. `AISEC_OAUTH_ERROR:invalid_client`), and Rust SDK error Display text differs. Should the harness compare only status plus the detail prefix up to the colon? What sanitized Rust message should be appended, guaranteed free of secrets and response bodies?
- When the token endpoint rejects the client, should Rust report `authentication failed: ...`, matching the TS SDK's status-less error shape that the unit tests assume? Or `management API error (HTTP 401): ...`, since the Rust SDK attaches the status (auth.rs with_status)? The live TS outcome is unverified because the TS SDK source is unavailable.
- Should the Rust scanner probe honor the tenant's airsNumRetries, as TS does via init(), so that 5xx responses are retried within the 5 s budget? Or force 0 retries so the diagnostics are deterministic?
- Should the doctor have a total wall-clock bound, or a --timeout flag? TS has a fixed 5000 ms per check, run sequentially, with no cancellation.
- Should doctor gain --scope/--skip flags? TS has none. 'Scoped doctor' in the plan appears to mean a reduced check set, not a flag; confirm.
- When both airsApiKey and airsApiToken are set, which header does the TS SDK send (x-pan-token vs Authorization: Bearer)? Rust must match it for request-shape comparisons.
- Management OAuth count: does TS SDK topics.listAll() count every revision row, or only the latest revision per topic? Rust list_all returns every row. Fixtures should use single-revision topics until this is confirmed.
- Is `--debug` (private JSONL API log written to cwd) in scope for the Rust doctor in release 1?
- Should a `doctor` executable-level compatibility suite be added to the TS repo too, so both CLIs share pinned fixtures for the scanner and OAuth probe shapes that are currently SDK-defined and untested?
