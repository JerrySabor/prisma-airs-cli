# Spec: TS `airs-cli` runtime extras (M6d, part 1): `api-keys`, `customer-apps`, `deployment-profiles`, `scan-logs`

Commands covered: `runtime api-keys list|create|regenerate|delete`, `runtime customer-apps list|get|update|delete|consumption`, `runtime deployment-profiles list`, `runtime scan-logs query`. `runtime dashboard`, `runtime sessions`, `runtime report` and `runtime profiles backup|restore` need their own specs. They appear here only where they share machinery: the dashboard client of §2.1, and the `scan-logs` hint that names `sessions list` and `report`.

## 0. Sources and method

- **CLI source.** The frozen reference is `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0, SDK `@cdot65/prisma-airs-sdk` 0.34.0, commander 14). Citations use these short names:
  - `rt.ts`: `src/cli/commands/runtime.ts`.
  - `mgmt.ts`: `src/airs/management.ts` (the SDK wrappers and normalisers).
  - `rr.ts`: `src/cli/renderer/runtime.ts`.
  - `views.ts`: `src/cli/renderer/views/runtime.ts`.
  - `view.ts`, `common.ts` and `ui.ts`: under `src/cli/renderer/`.
  - `program.ts`: `src/cli/program.ts`.
  - `pag.ts`: `src/cli/pagination.ts`.
  - `co.ts`: `src/config/client-options.ts`.
  - `dbg.ts`: `src/cli/debug-logger.ts`.
- **SDK citations.** `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` in the reference build. `rs:<file>:<line>` is `~/.cargo/registry/src/*/scm-sdk-0.1.1/src/<file>`.
- **Shared shell behaviour** is in `ts-cli-shell.md`, `ts-renderer.md`, `ts-debug-log.md` and `ts-runtime-mgmt-read.md` (§1 flags). That covers commander parse errors (exit 1), the root `--output` consumer, `resolveOutput`, `ui`, quiet mode, colour and EPIPE. It is restated here only where these commands depend on it.
- **Capture setup.** The reference build (`dist/cli/index.js`, node v24.21.0) ran against a stateful loopback stub (`node:http` on `127.0.0.1`, random port). Probe tooling lives in the session scratchpad `…/scratchpad/rx/`: `server.mjs`, `guard.mjs`, `run.sh`, `sig.mjs` and the capture scripts `c1.sh`–`c7.sh`.
  - **Routes.** The stub serves `POST /oauth/token` and the management plane under `/aisec/v1/mgmt/`:
    - `apikeys/tsg/100` (offset pages with `next_offset`);
    - `POST apikey`;
    - `POST apikey/regenerate/<id>`;
    - `DELETE apikey/delete/<name>`;
    - `customerapp/tsg/100`;
    - `customerapp` with GET, PUT and DELETE;
    - `deploymentprofiles`.
  - **Dashboard routes.** A separate dashboard base `/dash/v1/mgmt/dashboard/v2/apps/` serves `applicationsoverview`, `application` and `applicationviolationbreakdown`.
  - **Request log.** The stub logged the method, path, raw query, auth scheme, `x-tsg-id`, content type and raw body of every request.
  - **Fault plan.** The stub accepted a fault plan of responses consumed in order: a status, a JSON or raw body, headers such as `Retry-After: 0` or `x-opa-decision: false`, or a hang.
  - **Sandbox.**
    - `env -i` with `PATH`, plus `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` and `XDG_CACHE_HOME`, all inside the sandbox.
    - The TS registry selected with `PRISMA_AIRS_TENANTS_PATH`.
    - One tenant `test` with TSG `100` and fake credentials (`fake-client`/`FAKE-SECRET-100`).
    - `mgmtTokenEndpoint` `<base>/oauth/token`, `mgmtEndpoint` `<base>/aisec` and `mgmtDashboardEndpoint` `<base>/dash`.
  - **Fake values.** Every fake sensitive value is `PRIVATE-…`: auth codes `PRIVATE-AUTHCODE-n`, the created key `PRIVATE-FULL-API-KEY-SECRET08` and the rotated key `PRIVATE-ROTATED-API-KEY-ROTATED8`.
- **Endpoint fallbacks.**
  - `managementClientOptions` (`co.ts:44-51`) passes explicit `clientId`, `clientSecret`, `tsgId`, `tokenEndpoint: mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`, `apiEndpoint: mgmtEndpoint ?? DEFAULT_MGMT_ENDPOINT` (`https://api.apps.paloaltonetworks.com/aisec`, `SDK:34`), `dashboardEndpoint: mgmtDashboardEndpoint ?? DEFAULT_MGMT_DASHBOARD_ENDPOINT` (the same URL, `co.ts:27`) and `dlpEndpoint`.
  - The SDK's fallbacks are therefore never reached: `opts.apiEndpoint ?? process.env.PANW_MGMT_ENDPOINT` (`SDK:13419`), the `PANW_MGMT_*` credentials (`resolveOAuthConfig`, `SDK:11099`) and the dashboard's `opts.dashboardEndpoint ?? baseUrl` (`SDK:13440`).
  - `mgmtDashboardEndpoint` must be a URL (`schema.ts:22`).
  - The environment variables that still change behaviour are `PANW_AI_SEC_TIMEOUT_MS` (per-attempt timeout, `SDK:10095`), `PANW_AI_SEC_DEBUG` and `PANW_AI_SEC_DEBUG_BODY` (§2.10), `AIRS_CLI_INVOKED_AS` (hint text), and `FORCE_COLOR`/TTY for chalk.
- **Network guard.** Every node run preloaded a guard (`--import guard.mjs`) that replaces `globalThis.fetch` and `dns.lookup` and refuses any host other than `127.0.0.1`.
  - For the `--debug` captures only (§2.10), the guard instead rewrote `https://api.apps.paloaltonetworks.com/<path>` to `http://127.0.0.1:<stub port>/<path>`. The TS debug logger records only production hostnames, so this was the only way to see what it writes.
  - The logger saw the production URL while every byte went to the loopback stub. The guard refused (and logged) every other host. Once, a run with stale rewrite endpoints and the rewrite disabled printed `GUARD-REFUSED api.apps.paloaltonetworks.com`, and no connection was made.
- **Signals** were sent with `child.kill('SIGINT'|'SIGTERM')` once the stub had logged the hung write.
- No real tenant or credential file was read, and no host other than loopback was contacted.
- **Capture format.** Captures are JSON strings (`"\n  ..."`), uncoloured (stdout is a pipe) unless stated. §4 lists the ANSI codes captured with `FORCE_COLOR=1`. Each run first sends the token request (`POST /oauth/token`, Basic auth, form body `grant_type=client_credentials&scope=tsg_id%3A100`); the request lists below omit it. One token is fetched per invocation, and the client is a process-wide singleton (`mgmt.ts:543-553`).

## 1. Command surface (help verified)

**Registration.**
- `registerRuntimeCommand` (`rt.ts:180-1231`) registers `api-keys` at `rt.ts:191-275`, `customer-apps` at `rt.ts:445-579`, `deployment-profiles` at `rt.ts:582-604` and `scan-logs` at `rt.ts:1076-1094`.
- After registration:
  - every `list` gets the alias `ls` and every `delete` gets `rm` (`program.ts:42-51`, `aliases.spec.ts:55-79`);
  - every `list`/`get` without `--output` gets one (`program.ts:54-70`; all of these declare it themselves);
  - the help text is sorted.
- No command here has `--force`, and nothing prompts.

**Help strings.**
- Group descriptions: `api-keys` `Manage AIRS API keys`, `customer-apps` `Manage AIRS customer apps`, `deployment-profiles` `List AIRS deployment profiles`, and `scan-logs` `BROKEN legacy retrieval — under refactor; use runtime sessions`.
- The format help on every `--output` is `Output format: pretty, table, markdown, csv, json, yaml`.

| Command | Registration | Arguments and options (help text; defaults) |
|---|---|---|
| `api-keys list\|ls` | `rt.ts:193-217` | `registerListFlags(…,{dialect:'offset'})` (`pag.ts:20-30`): `--limit <n>` (`Items per page (default: 100)`, `Number`, default `100`, so help prints `(default: 100) (default: 100)`), `--offset <n>` (`Item offset (default: 0)`, `Number`, `0`), `--all` (`Walk all pages`), `--max <n>` (`Maximum items with --all; 0 removes the cap`, `Number`, `10000`), `--output <format>` |
| `api-keys create` | `rt.ts:221-236` | `--config <path>` (`JSON file with API key configuration`, **required**) |
| `api-keys regenerate <apiKeyId>` | `rt.ts:238-259` | `--interval <n>` (`Rotation time interval`, required), `--unit <unit>` (`Rotation time unit (hours, days, months)`, required), `--updated-by <email>` (`Email of user performing regeneration`) |
| `api-keys delete\|rm <apiKeyName>` | `rt.ts:261-275` | `--updated-by <email>` (`Email of user performing deletion`, **required**) |
| `customer-apps list\|ls` | `rt.ts:447-473` | as `api-keys list` |
| `customer-apps get <appName>` | `rt.ts:475-490` | `--output <format>` |
| `customer-apps update <appId>` | `rt.ts:491-506` | `--config <path>` (`JSON file with app updates`, required) |
| `customer-apps delete\|rm <appName>` | `rt.ts:508-521` | `--updated-by <email>` (`Email of user performing deletion`, required) |
| `customer-apps consumption [appName]` | `rt.ts:523-579` | argument help `Dashboard application name — the literal scan-payload metadata.app_name, as shown in the SCM AI Applications view (may differ from the SCM-registered customer-app name). Omit to report every dashboard bucket.`; `--time-interval <n>` (`Window in days: 7, 30, or 60`, default **string** `"30"`), `--output <format>` |
| `deployment-profiles list\|ls` | `rt.ts:586-603` | `--unactivated` (`Include unactivated profiles`), `--output <format>`; no paging flags (`--limit` → `error: unknown option '--limit'`, exit 1) |
| `scan-logs query` | `rt.ts:1079-1094` | `--interval <n>` (`Time interval`, required), `--unit <unit>` (`Time unit (hours)`, required), `--filter <filter>` (`Filter: all, benign, threat`, `"all"`), `--limit <n>` (`Max results per page (API page size)`, `"50"`), `--offset <n>` (`Starting offset — rounds down to a page boundary`, `"0"`), `--output <format>`; hidden deprecated `--page <n>` and `--page-size <n>` (`registerPageAliases`, `pag.ts:65-81`) |

Captured help, verbatim (stdout, exit 0):

```
Usage: airs-cli runtime api-keys [options] [command]

Manage AIRS API keys

Options:
  -h, --help                        display help for command

Commands:
  create [options]                  Create a new API key
  delete|rm [options] <apiKeyName>  Delete an API key
  help [command]                    display help for command
  list|ls [options]                 List API keys
  regenerate [options] <apiKeyId>   Regenerate an API key
```

```
Usage: airs-cli runtime api-keys list|ls [options]

List API keys

Options:
  --all              Walk all pages
  -h, --help         display help for command
  --limit <n>        Items per page (default: 100) (default: 100)
  --max <n>          Maximum items with --all; 0 removes the cap (default:
                     10000)
  --offset <n>       Item offset (default: 0) (default: 0)
  --output <format>  Output format: pretty, table, markdown, csv, json, yaml
```

```
Usage: airs-cli runtime api-keys regenerate [options] <apiKeyId>

Regenerate an API key

Options:
  -h, --help            display help for command
  --interval <n>        Rotation time interval
  --unit <unit>         Rotation time unit (hours, days, months)
  --updated-by <email>  Email of user performing regeneration
```

```
Usage: airs-cli runtime customer-apps [options] [command]

Manage AIRS customer apps

Options:
  -h, --help                       display help for command

Commands:
  consumption [options] [appName]  Show per-app token consumption + violation
                                   breakdown (SCM dashboard). Omit appName to
                                   scan all apps.
  delete|rm [options] <appName>    Delete a customer app
  get [options] <appName>          Get customer app details
  help [command]                   display help for command
  list|ls [options]                List customer apps
  update [options] <appId>         Update a customer app
```

```
Usage: airs-cli runtime customer-apps consumption [options] [appName]

Show per-app token consumption + violation breakdown (SCM dashboard). Omit
appName to scan all apps.

Arguments:
  appName              Dashboard application name — the literal scan-payload
                       metadata.app_name, as shown in the SCM AI Applications
                       view (may differ from the SCM-registered customer-app
                       name). Omit to report every dashboard bucket.

Options:
  -h, --help           display help for command
  --output <format>    Output format: pretty, table, markdown, csv, json, yaml
  --time-interval <n>  Window in days: 7, 30, or 60 (default: "30")
```

```
Usage: airs-cli runtime scan-logs query [options]

Unavailable legacy query; use runtime sessions list

Options:
  --filter <filter>  Filter: all, benign, threat (default: "all")
  -h, --help         display help for command
  --interval <n>     Time interval
  --limit <n>        Max results per page (API page size) (default: "50")
  --offset <n>       Starting offset — rounds down to a page boundary (default:
                     "0")
  --output <format>  Output format: pretty, table, markdown, csv, json, yaml
  --unit <unit>      Time unit (hours)
```

Other help outputs captured:
- The `customer-apps list|ls`, `get`, `update`, `delete|rm` and `deployment-profiles list|ls` help texts follow the same layout as above, with the options of the table.
- `api-keys create`: `--config <path>  JSON file with API key configuration`.
- `customer-apps update`: `--config <path>  JSON file with app updates`.
- `deployment-profiles`: `list|ls [options]  List deployment profiles`.
- `scan-logs`: `query [options]  Unavailable legacy query; use runtime sessions list`.
- No command has an `Examples:` block.

## 2. Shared behaviour

### 2.1 Client, planes and credentials

- **Service setup.** Every action calls `createMgmtService()` (`rt.ts:175-178`): `loadConfig()`, then `new SdkManagementService(managementClientOptions(config))`.
  - With no tenant selected, it fails with `\n  ✗ Error: No tenant selected. Run 'airs-cli tenant switch <name>' (registered: test)\n\n` (exit 1).
  - It then runs `assertManagementCredentials`. A missing secret fails with `\n  ✗ Error: Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set test <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)\n\n` (exit 1, captured).
- **Planes.**
  - `apiKeys`, `customerApps`, `deploymentProfiles` and `scanLogs` use `apiEndpoint`, the tenant's `mgmtEndpoint` (`SDK:13433-13437`).
  - `dashboard` (used only by `consumption`) uses `dashboardEndpoint`, the tenant's `mgmtDashboardEndpoint`, and adds the header `x-tsg-id: <tsgId>` (`SDK:12243-12248`, captured `"tsg":"100"`).
  - No other request carries a TSG header. The TSG appears in the paths `apikeys/tsg/<tsg>` (raw, `SDK:11766`) and `customerapp/tsg/<encodeURIComponent(tsg)>` (`SDK:11914`).
- **Paths** (`SDK:50-61`):
  - `/v1/mgmt/apikey` and `/v1/mgmt/apikeys/tsg`;
  - `/v1/mgmt/customerapp` and `/v1/mgmt/customerapp/tsg`;
  - `/v1/mgmt/deploymentprofiles`;
  - `/v1/mgmt/scanlogs`;
  - `/v1/mgmt/dashboard/v2/apps/{applicationsoverview,application,applicationviolationbreakdown}`.
- **Headers:** `Authorization: Bearer <token>`, `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `service-name: api`, and `Content-Type: application/json` on bodies.
- **Retries.** `numRetries` is not passed, so the SDK maximum of 5 applies.

### 2.2 Output format resolution

The commands fall into three classes, decided by the leaf name (`READ_COMMAND_NAMES`, `program.ts:18-39`, which contains `list`, `get`, `consumption` and `query`) and by whether the command has `--output`.

| Class | Commands | Behaviour (captured) |
|---|---|---|
| A: resolved reads | `api-keys list`, `customer-apps list\|get\|consumption`, `deployment-profiles list`, `scan-logs query` | `preAction` (`program.ts:162-175`) calls `resolveOutput`, which reads the tenant **first**. With no tenant, `--output xml` still exits 1 with the no-tenant error. Then an unknown format fails with `\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n` (exit 2). The tenant `defaultOutput` applies (captured: `defaultOutput: "json"` makes `api-keys list` print JSON). `markdown`, `csv` and `yaml` work (§9.3). The root consumes every `--output`, and the last one wins. |
| B: writes | `api-keys create\|regenerate\|delete`, `customer-apps update\|delete` | No `--output`. The root consumes `--output json` and it is ignored (captured: `api-keys create --output json` and `rm --output json` print the pretty layout, exit 0). `defaultOutput` is ignored. |
| C: stub | `scan-logs query` (class A for parsing) | Every run fails after the `preAction` format check (§8). |

### 2.3 Banner, streams, quiet

- **Banner.** `renderRuntimeConfigHeader()` (`rr.ts:74-76`) = `ui.header('Prisma AIRS — Runtime Configuration', 'Security profile and topic management')`. On stdout it is `"\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n"`, and quiet mode suppresses it.
  - Class A prints the banner only for `pretty`, after `preAction`, and before the tenant and credentials are read in `createService`. A credential error therefore leaves the banner on stdout (captured for `api-keys list` without `mgmtClientSecret`).
  - Class A argument checks that run before the banner (list flags, `--time-interval`) leave stdout empty.
  - Class B prints the banner **first**, before the tenant, the credentials and the `--config` read, so every class-B failure leaves the banner on stdout (captured: no tenant, `ENOENT`, schema, HTTP and timeout errors).
- **stdout** carries the banner, every layout, the empty-list phrases (`ui.emptyList`), every write acknowledgement (`ui.success` → `  ✓ …`, `ui.ts:90-93`), and the `deployment-profiles` empty phrase even under `--output json` (§7).
- **stderr** carries:
  - errors (`fail`, `usageError`, commander, `ui.error`);
  - the list page status line (`ui.status`, quiet-suppressed, `view.ts:32-42`);
  - the `consumption` per-app failure lines;
  - the `scan-logs` message;
  - the `--debug` notice.
- **`--quiet`** suppresses `ui.header`, `ui.section`, `ui.dim` and `ui.status`. Consequences, all captured:
  - **Pretty `api-keys list` loses every key ID**, which is printed with `ui.dim`: `--quiet runtime api-keys list` → `"    key-1 key: …LAST8-01\n    key-2 key: …LAST8-02\n    key-3 key: …LAST8-03\n\n"`. The pretty `customer-apps list` would lose its ID too, if `id` were ever set (§2.11).
  - Quiet `api-keys create` still prints the **full key** and the success line: `"  ✓ API key created: <id>\n  ID    <id>\n  Name  new-key\n  Key   PRIVATE-FULL-API-KEY-SECRET08\n\n"`.
  - Quiet `consumption` drops the app title (`ui.header(appName, …)`), the section titles and `no detector violations in window`. The output keeps only key/value lines and the detector table, so in all-apps mode the blocks can no longer be told apart.
  - Quiet `scan-logs query` still prints its error (`ui.error` is not suppressed).

### 2.4 Errors and exit codes

Every action wraps its body in `try { … } catch (err) { fail(err) }` (`common.ts:12-25`):

- `fail`: a `CliUsageError` goes to `usageError`. Any other error writes `"\n  ✗ Error: <message>\n"` to stderr. For errors with `status`/`statusCode` it adds `"    HTTP <s>\n"` and `"    Re-run with --debug to capture redacted API diagnostics.\n"`, then `"\n"`, and exits 1.
- `usageError(msg)`: writes `"\n  ✗ <msg>\n\n"` to stderr and exits 2.

| Situation | Message (captured) | Exit |
|---|---|---|
| commander: missing positional, missing required option, unknown option, excess arguments | `error: missing required argument 'apiKeyId'`, `error: required option '--config <path>' not specified`, `error: required option '--interval <n>' not specified`, `error: required option '--updated-by <email>' not specified`, `error: unknown option '--bogus'`, `error: too many arguments for 'list'. Expected 0 arguments but got 1.` | 1 |
| list flags (§3.1) | `--limit must be a positive integer`, `--offset must be a non-negative integer`, `--max must be a non-negative integer`, `--all cannot be combined with --offset` (after the tenant is read in `preAction`, before the banner) | 2 |
| invalid `--output` (class A) | `Invalid output format 'xml'. Expected: …` | 2 |
| `consumption --time-interval` outside {7, 30, 60} after `parseInt` | `--time-interval must be 7, 30, or 60 (the API rejects other values)` (after the tenant, before the banner) | 2 |
| `--config` file errors | `ENOENT: no such file or directory, open 'missing.json'` (the path as typed); `/dev/null` → `Unexpected end of JSON input` | 1 |
| JSON syntax in `--config` | V8 message **quoting the input**: `Unexpected token 'P', ..."ey_name": PRIVATE-x}" is not valid JSON` | 1 |
| SDK request schema (§2.7) | `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/mgmt/apikey did not match schema: auth_code: invalid_type; cust_app: invalid_type; …` (paths and zod codes only); `null` file → `<root>: invalid_type`; `--interval abc` → `… /v1/mgmt/apikey/regenerate/<id> did not match schema: rotation_time_interval: invalid_type`; no token request | 1 |
| HTTP errors | `AISEC_CLIENT_SIDE_ERROR:<server message>` + `HTTP <s>` (§2.6) | 1 |
| response validation | `AISEC_RESPONSE_VALIDATION:Response did not match schema: api_keys.0.api_key_id: invalid_type; …`, `… items: invalid_type`, `… status: invalid_type`, `Response body is not valid JSON` | 1 |
| timeout | `AISEC_CLIENT_SIDE_ERROR:Request timed out` (no `HTTP` line) | 1 |
| walk repeated cursor | `Pagination returned a repeated cursor` (`SDK:10794`) | 1 |
| `consumption <name>` not in the dashboard list | `Dashboard application not found: "<name>". Available (as shown in SCM AI Applications view): "<n1>", "<n2>", … [, ... (<N> total)]. Note: the name to use is the literal value your integration sends in scan metadata.app_name (which may differ from the SCM application name).` (`mgmt.ts:446-458`) | 1 |
| `consumption` all-apps, one app fails | `  ✗ [<appName>] <message>` on stderr; the loop continues; **exit 0** (§6.5) | 0 |
| `scan-logs query` | `  ✗ Legacy scan-logs retrieval is broken …` (§8) | 1 |
| SIGINT / SIGTERM | nothing printed | 130 / 143 (killed by the signal) |

### 2.5 Validation order (captured)

- **Class A** (`api-keys list`, `customer-apps list`): argv (commander), then `preAction` (tenant read, format check), then the action: `resolveListParams` (list flags, exit 2), the banner (pretty), `createService` (credentials), the token, the request. So `--limit 0` with no tenant exits 1 with the tenant error, not 2.
- **`customer-apps get`, `deployment-profiles list`**: argv, `preAction`, banner, credentials, token, request. No local check of the name.
- **`consumption`**: argv, `preAction`, `parseInt(--time-interval)` check (exit 2), banner, credentials, token, the overview walk, then the two dashboard reads (§6.5).
- **Class B**: argv, banner, tenant and credentials, the `fs.readFileSync(--config)` and `JSON.parse` (create, update), the built body (regenerate), the SDK request schema, the token, the request. A missing tenant hides a missing `--config` file (captured).
- **`scan-logs query`**: argv (`--interval` and `--unit` required), `preAction` (tenant, format), then the fixed error. Credentials are never checked (captured: the run without `mgmtClientSecret` prints the legacy message).

### 2.6 HTTP error text and retries (captured)

- **Error text.** No request here sets `safeErrorMessages`, so the error text is built from the body (`SDK:9713-9725`, as in `ts-model-security.md` §2.6).
  - The JSON `message`/`error_message`/`error.message` is printed **verbatim**, control characters included: `AISEC_CLIENT_SIDE_ERROR:PRIVATE-ECHO not \e[31mfound`, and `AISEC_CLIENT_SIDE_ERROR:key PRIVATE-FULL-API-KEY exists` on a 409 for `create`.
  - A non-JSON body is printed whole: `AISEC_CLIENT_SIDE_ERROR:API error 400: PRIVATE plain text body`.
  - A status of 500 or more gives the prefix `AISEC_SERVER_SIDE_ERROR:`, for example `API error 503` (no body text).
- **Retries.** Every method, writes included, is re-sent up to 5 times on 500/502/503/504, transport errors and per-attempt timeouts (default 60 s), with jittered backoff or `Retry-After`. Captured:
  - `api-keys list` against a permanent 503 sent 6 GETs.
  - **`api-keys create` against three 502s sent 4 POSTs** and printed one created key, with its secret.
  - With `PANW_AI_SEC_TIMEOUT_MS=300`, a hung `create` sent **6 POSTs** and ended `Request timed out` (exit 1, no outcome text).
  - **`api-keys regenerate` against two 500s sent 3 POSTs** and printed the third key.
  - `customer-apps update` against a 503 sent 2 PUTs.
  - `customer-apps delete` against a 500 sent 2 DELETEs.
  - `api-keys delete` against a 504 sent 2 DELETEs and printed success.
  - In `consumption` all-apps mode, a permanent 500 on one app's `application` read sent 6 GETs for that app (§6.5).
- **401 and 403.** A 401, or a 403 without `x-opa-decision: false`, clears the token and replays once. Captured: token, GET(401), token, GET(401), then `API error 401`, exit 1. A 403 replays as `token, GET(403), token, GET(403)`. A 403 with `x-opa-decision: false` is sent once.
- **No outcome-unknown wording exists.** A 2xx with an unreadable body (`create` → `Response body is not valid JSON`; `update` with an empty body → `Response did not match schema: app_name: invalid_type; …`) exits 1 with the banner on stdout, though the key may have been created or the app replaced.

### 2.7 Request bodies and schemas

Bodies are the zod output, serialised with `JSON.stringify`. A failure lists paths and zod codes only, before any token request. All schemas are `.passthrough()` (`SDK:2048-2140`).

| Body | Schema | CLI construction (captured) |
|---|---|---|
| key create | `ApiKeyCreateRequestSchema` (`SDK:2075-2087`): `auth_code`, `cust_app`, `created_by`, `api_key_name`, `rotation_time_unit` strings; `revoked` boolean; `rotation_time_interval` int; optional `dp_name`, `cust_env`, `cust_cloud_provider`, `cust_ai_agent_framework` | **the whole `--config` file** is the body (`rt.ts:228-229`); unknown keys are sent (captured `"extra":"kept"`); `auth_code` (a license credential, §10) comes from the file |
| key regenerate | `ApiKeyRegenerateRequestSchema` (`SDK:2088-2092`): `rotation_time_interval` int, `rotation_time_unit` string, optional `updated_by` | `{rotation_time_interval: parseInt(--interval, 10), rotation_time_unit: --unit[, updated_by]}` (`rt.ts:248-252`): `--interval 1.9` → `1`; `-5` → `-5` (sent); `abc` → `NaN` → schema error; `--unit fortnights` is sent (no check against the help's `hours, days, months`); `updated_by` only when truthy |
| app update | `CustomerAppSchema` (`SDK:2109-2120`) as **request** schema: `app_name`, `cloud_provider`, `environment` required strings; optional `customer_appId`, `tsg_id`, `model_name`, `status`, `created_by`, `updated_by`, `ai_agent_framework` | **the whole file** (`rt.ts:499-500`); unknown keys sent; a partial file (`{"environment":"dev"}`) fails the schema (`app_name: invalid_type; cloud_provider: invalid_type`), so `update` is a **full replacement PUT** (§6.3) |
| scan-logs | `opts.page_token` body | never sent (§8) |

### 2.8 Path segments and query values

- **`regenerate <apiKeyId>`** is `encodeURIComponent`-ed into the path (`SDK:11828-11838`): `a/b ..` → `/v1/mgmt/apikey/regenerate/a%2Fb%20..`. But `..` is not encoded, and the URL parser normalises it: **`regenerate ..` sent `POST /aisec/v1/mgmt/apikey/`** (captured), a different endpoint. `.` behaves the same way (from the code).
- **`delete <apiKeyName>`**: `a/b?c d` → `/v1/mgmt/apikey/delete/a%2Fb%3Fc%20d`. **`delete ..` sent `DELETE /aisec/v1/mgmt/apikey/`**, and `delete ''` sent `DELETE /aisec/v1/mgmt/apikey/delete/` (both captured).
- **Query values** go through `URLSearchParams`, so they cannot inject parameters (`updated_by=x%26y%3Dz`, `app_name=a%26b%3Dc`). Empty values are sent (`?app_name=`).
- **No local check exists** on IDs (no UUID check), names, emails or `--unit`.
- `customer-apps consumption ''` is treated as **no app name** (`if (appName)`, `rt.ts:546`) and runs the all-apps loop (captured).

### 2.9 Interruption

There are no signal handlers and no prompts. SIGINT during a hung `api-keys create` or `customer-apps update`, and SIGTERM during a hung `api-keys delete`, killed the process by the signal. Exit is 130/143 in a shell. stdout held the banner only, stderr was empty, and nothing said whether the key was created, the app replaced or the key deleted (captured).

### 2.10 `--debug` and `PANW_AI_SEC_DEBUG`

- **The log file.** `--debug` creates `debug-api-<ms>-<8 hex>.jsonl` (0600, `wx`) in the **current directory** and prints `  Debug: API log → <abs path>` on stderr.
  - The logger is installed with `omitBodies: false` for these commands (`program.ts:183`).
  - Dashboard URLs (`/v1/mgmt/dashboard/`) always omit bodies (`dbg.ts:166-169`).
  - Other bodies pass through `redactDeep`, which masks the **whole value** of any key matching `/token|secret|password|passwd|credential|authorization|cookie|api[-_]?key|client[-_]?auth|auth[-_]?code|^key$/i` (`dbg.ts:31-61`). URL queries are masked by the same key rule, so `updated_by`, `app_name` and `appname` are kept.
  - Only production hosts are logged (`dbg.ts:11-27`). Records captured through the rewrite guard (§0):
    - `api-keys list` response: `{"api_keys":"***"}`. The whole array is masked, because the key contains `api_key`.
    - `api-keys create` request: `{"auth_code":"***","cust_app":"app-one","revoked":false,"created_by":"a@example.com","api_key_name":"***",…,"extra":"kept"}`. The response: `{"api_key_id":"***","api_key_last8":"***","api_key_name":"***","auth_code":"***","tsg_id":"100","expiration":"…","revoked":false,"cust_app":"app-one","created_by":"a@example.com","creation_ts":"…","api_key":"***"}`. **The secret is masked by key name.** This is redaction by name only: a server that put the key under another name would leak it.
    - `regenerate` request body: `updated_by` (the email) is recorded. The response is masked like `create`'s.
    - `customer-apps list|get`: the records are kept, except `"api_keys_dp_info":"***"`.
    - `deployment-profiles list`: `auth_code` is masked, and names, status and expiry are kept.
    - `delete`: the URL `…/apikey/delete/key-2?updated_by=u%40example.com` and the response `{"message":"api key key-2 deleted"}`.
    - `consumption`: three records, `"body":"[BODY OMITTED]"` for both directions.
    - `scan-logs query`: an empty 0600 file.
- **`PANW_AI_SEC_DEBUG=1`** prints SDK lines on stderr, including **the full URL with its query**:
  - `[airs-sdk] → DELETE http://127.0.0.1:<port>/aisec/v1/mgmt/customerapp?app_name=app-1&updated_by=u%40example.com`
  - `[airs-sdk]   headers {"User-Agent":…,"Authorization":"sha256:<12 hex>"}`
  - `[airs-sdk]   body [BODY OMITTED]`
  - With `PANW_AI_SEC_DEBUG_BODY=1` the bodies are printed with the SDK's own redaction (captured for `create`): request `{"auth_code":"[REDACTED]",…,"api_key_name":"new-key",…}`, response `{… "api_key_last8":"SECRET08",…,"auth_code":"[REDACTED]",…,"api_key":"[REDACTED]"}`. The SDK masks `api_key` and `auth_code` but keeps `api_key_last8` and `api_key_name`.
  - Unlike DLP, these commands do not force `PANW_AI_SEC_DEBUG_BODY=0`.

### 2.11 Normalised records, dropped fields, invented values

Printed records are CLI projections (`mgmt.ts:312-321,358-365`), not wire objects. JSON prints the projection (keys whose value is `undefined` are omitted). The table detail prints every own key (`undefined` → empty cell).

| Record | Projection | Wire mapping and its bugs |
|---|---|---|
| API key (`normalizeApiKey`) | `{id, name, apiKey, last8, createdAt, expiresAt}` | `id ← id ?? api_key_id ?? ''`, `name ← name ?? api_key_name ?? ''`, `apiKey ← api_key` (**the full secret**, when the server sends it), `last8 ← api_key_last8`, `createdAt ← created_at`, `expiresAt ← expires_at`. The wire fields are **`creation_ts` and `expiration`** (`SDK:2053-2072`), so for real responses **`createdAt` and `expiresAt` are always absent**: the `Expires` column and the pretty `expires:` part are always empty, and json omits both keys. Captured with the schema-shaped wire, and only a fixture with the unit test's `created_at`/`expires_at` filled them. Dropped: `auth_code`, `revoked`, `revoke_reason`, `cust_app`, `cust_env`, `dp_name`, `status`, `rotation_*`, `created_by`, `updated_by`, `customer_appId`, passthrough. The docs-site shows `"createdAt": ""`, which is stale. |
| customer app (`normalizeCustomerApp`) | `{id, name, description, raw}` | `id ← customer_app_id ?? id`; the wire key is **`customer_appId`** (`SDK:2110,2122`), so **`id` is always absent** (unit test mocks use `customer_app_id`, `management.spec.ts:1127`). `description ← description`, which no schema has. `name ← app_name ?? name ?? ''`. `raw` is the whole wire object, including the list's `api_keys_dp_info` entries with their **`auth_code`** values. |
| deployment profile | `{raw}` | the renderer reads `dp_name ?? profile_name ?? name`, `status`, `auth_code` |
| consumption (`getCustomerAppConsumption`, `mgmt.ts:435-505`) | `{appId, appName, cloud, source, monitoringSince, profiles, tokens{dailyAverage, dailyAverageScale, monthlyTotal, monthlyTotalScale}, sessions{total, violating}, detectors[{type, critical, high, medium, low, total}], totalViolating}` | **values invented by the CLI**: `sessions.total`/`violating` `?? 0` (a `session_stats: null` app prints `Total 0`, `Violating 0`, captured), every severity count `?? 0`, `type ?? 'unknown'`, `profiles ?? []`, `totalViolating ?? 0`; missing token stats print `-`. `appId` is the dashboard `id` (the customer-app UUID), not taken from the `application` response. |

**Schema defaults (G10).** Walking `rs:validation/schema_graph.json` from `ApiKeySchema`, `ApiKeyListResponseSchema`, `ApiKeyDeleteResponseSchema`, `CustomerAppSchema`, `CustomerAppListResponseSchema`, `CustomerAppDeleteResponseSchema`, `DeploymentProfilesResponseSchema`, `DashboardApplicationSchema`, `DashboardApplicationViolationBreakdownSchema`, `DashboardApplicationsOverviewSchema` and `PaginatedScanResultsSchema` found **no `ZodDefault` node**. The only defaults are request-side: `appQuerySchema` `timeInterval` 30 and `timeUnit` `days` (`SDK:12202-12207`), and the overview query defaults (`SDK:12633-12645`). `without_response_defaults()` changes nothing for these reads, but passing it is harmless and keeps the G10 rule uniform. The invented values above are CLI-side.

## 3. Lists: flags, requests, pagination (`api-keys list`, `customer-apps list`)

### 3.1 Parsing (captured, `pag.ts:32-56`)

- `--limit` (`Number`, default 100): `Number.isSafeInteger && >= 1`, else `--limit must be a positive integer` (exit 2). `0`, `abc` and `1.5` are refused. `500` is sent (`limit=500`; no upper bound).
- `--offset` (`Number`, default 0): `>= 0` safe integer, else `--offset must be a non-negative integer`.
- `--max` (`Number`, default 10000): `>= 0`, else `--max must be a non-negative integer`. It is validated even without `--all`, and ignored without `--all`.
- `--all` with an `--offset` given on the command line (even `--offset 0`) fails with `--all cannot be combined with --offset`.
- These checks run after the tenant is read (`preAction`) and before the banner.

### 3.2 Requests

| Command | Without `--all` | With `--all` |
|---|---|---|
| `api-keys list` | `GET /v1/mgmt/apikeys/tsg/<tsg>?offset=<o>&limit=<l>` (`SDK:11758-11771`) | `listAll({limit, max})` (`SDK:11774-11783`): `offset=0`, then `offset=<next_offset>` |
| `customer-apps list` | `GET /v1/mgmt/customerapp/tsg/<tsg>?offset=<o>&limit=<l>` (`SDK:11906-11920`) | `listAll` (`SDK:11922-11931`), same walk |

### 3.3 Walk (`paginate`/`collectAll`, `SDK:10790-10812`)

- **Stop rule.** The walk follows `next = page.next_offset || undefined`, so `next_offset` `0` or absent ends it.
  - An empty page that carries a fresh `next_offset` is followed: captured `{"api_keys":[],"next_offset":5}` then `offset=5`.
  - A repeated cursor fails with `Pagination returned a repeated cursor` (captured `next_offset: 1` twice, exit 1, banner on stdout).
  - Collection stops at `max` items **without saying so**. `--all --limit 1 --max 2` printed 2 of 3 with `Showing all 2` (captured).
  - `--max 0` removes the cap.
- **Status lines** (stderr, quiet-suppressed, `view.ts:32-42`):
  - `--all`: `  Showing all <n>`.
  - Otherwise, when `next_offset` is defined: `  Showing <n> (more available)`. **`next_offset: 0` counts as defined** (captured `customer-apps list` → `Showing 1 (more available)`; the D12 pattern).
  - Otherwise: `  Showing <n>`.
  - No total is printed, and the next offset is never named.
- **Response shape.** `api_keys`/`customer_apps` are optional (`SDK:2093-2096,2131-2134`): `{}` is an empty list (`No API keys found`, `Showing 0`, captured).

## 4. Pretty primitives and colours

- **Primitives** (`ui.ts`):
  - `ui.header(t, s)`: `"\n  <bold t>\n  <dim s>\n\n"`.
  - `ui.section(l)`: `"\n  <bold l>\n\n"`.
  - `ui.keyValue(pairs)`: `"  <dim key.padEnd(W)>  <String(v ?? '')>\n"` per pair, with `W` the longest key of that call. The padding sits inside the dim span.
  - `ui.dim(m)`: `"  <dim m>\n"`.
  - `ui.emptyList(r)`: `"  <dim No <r> found>\n"`.
  - `ui.success(m)`: `"  <green ✓ m>\n"` on stdout.
  - `ui.error(m)`: `"  <red ✗ m>\n"` on stderr.
  - `ui.table`: `formatOutput(…,'table')` with every line prefixed by two spaces.
- **ANSI codes** (captured, `FORCE_COLOR=1`): bold `\e[1m…\e[22m`, dim `\e[2m…\e[22m`, green `\e[32m…\e[39m`, red `\e[31m…\e[39m`.
  - The key-list line is `"    key-1\e[2m key: …LAST8-01\e[22m\n"`, with the dim span starting at the space.
  - The key detail is `"  \e[2mID  \e[22m  <id>\n  \e[2mName\e[22m  new-key\n  \e[2mKey \e[22m  PRIVATE-FULL-API-KEY-SECRET08\n"`.
  - The deployment status is green only for exactly `active` (`"    dp-1  \e[32mactive\e[39m  \e[2mPRIVATE-AUTHCODE-1\e[22m\n"`, while `activated` is dim).
  - Errors: chalk splits the red text per line: `"\e[31m\e[39m\n\e[31m  ✗ Error: AISEC_CLIENT_SIDE_ERROR:api key key-1 not found\e[39m\n\e[31m    HTTP 404\e[39m\n\e[2m    Re-run with --debug to capture redacted API diagnostics.\e[22m\n\n"`.
  - The `scan-logs` error is `"  \e[31m✗ Legacy …report.\e[39m\n"`.
  - The colour level follows stdout's TTY for both streams.
- **Server text is printed raw.** A key name `evil\e[31mRED\nline2` reached stdout with its escape and newline in pretty, table and (JSON-escaped) json output. An app name and a description containing `\e[2J` did the same in the pretty list. The dashboard names in the not-found error are raw too (all captured).

## 5. `api-keys`

### 5.1 `list|ls` (`rt.ts:193-217`, `rr.ts:314-359`, `views.ts:29-41`)

- **Request**: see §3.
- **Pretty**: the banner, then `"\n  API Keys:\n\n"`, then per key `"  <dim id>\n"` and `"    <name>[<dim ' key: …' + last8>][<dim ' expires: ' + expiresAt>]\n"` (U+2026), then `"\n"`.
- **Captured** (3 keys): `"\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n\n  API Keys:\n\n  11111111-1111-4111-8111-000000000001\n    key-1 key: …LAST8-01\n  …\n\n"`, with stderr `  Showing 3\n`.
  - A key without a name prints `"     key: …1"`.
  - The empty list prints `"  No API keys found\n"`, with stderr `Showing 0`.
- **Table**: `view.columns`, not the renderer's richer column set (`rr.ts:333-339` is unreachable for table, because `emitList` projects the view): `ID │ Name │ Last 8 │ Expires`. Captured: `" ID                                   │ Name  │ Last 8   │ Expires \n──────────────────────────────────────┼───────┼──────────┼─────────\n 11111111-1111-4111-8111-000000000001 │ key-1 │ LAST8-01 │         \n…"`. `Expires` is always empty (§2.11).
- **JSON** is the bare array of projections: `[{"id":"…","name":"key-1","last8":"LAST8-01"}, …]`. Absent keys are omitted, and an empty list prints `[]`.
  - **When the list response carries `api_key`, json prints it as `"apiKey": "PRIVATE-LISTED-FULL-KEY"`** (captured). Pretty and table do not show it.
- The api-keys tests in `management.spec.ts:1071-1087` mock `{id, name, created_at}` records. Those records fail the real response schema (captured: `AISEC_RESPONSE_VALIDATION:… api_keys.0.api_key_id: invalid_type; api_keys.0.api_key_last8: invalid_type; api_keys.0.auth_code: invalid_type; api_keys.0.expiration: invalid_type; api_keys.0.revoked: invalid_type`).

### 5.2 `create --config <path>` (`rt.ts:221-236`, `rr.ts:362-381`)

- **Order**: banner, tenant and credentials, `JSON.parse(fs.readFileSync(path,'utf-8'))` (no regular-file check, no size cap, `/dev/stdin` and FIFOs are read), the schema (§2.7), then `POST /v1/mgmt/apikey` with the file as the body.
- **Output** (stdout, captured):

  ```
  "\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n  ✓ API key created: 11111111-1111-4111-8111-900000000001\n\n  API Key Detail:\n\n  ID    11111111-1111-4111-8111-900000000001\n  Name  new-key\n  Key   PRIVATE-FULL-API-KEY-SECRET08\n\n"
  ```

  - The `Key` row shows the **full secret** when the response has `api_key`, otherwise `…<last8>`.
  - `Created` and `Expires` rows would follow, but are never filled (§2.11).
  - A response without `api_key_name` prints `Name  ` (an empty value).
  - `--output json` is ignored. `--quiet` keeps the success line, the rows and the secret (§2.3).
  - Nothing goes to stderr on success.
- **Response schema** `ApiKeySchema` (`SDK:2048-2074`) requires `api_key_id`, `api_key_last8`, `auth_code`, `expiration` and `revoked`. A response without `auth_code` fails validation **after the key was created** (captured `AISEC_RESPONSE_VALIDATION:Response did not match schema: auth_code: invalid_type`, exit 1). The secret in that response is never shown, so it is lost.
- **Retries**: §2.6. 4 POSTs after 502s, 6 after timeouts. Each successful replay can create one more key.

### 5.3 `regenerate <apiKeyId> --interval <n> --unit <unit> [--updated-by <email>]` (`rt.ts:238-259`)

- `POST /v1/mgmt/apikey/regenerate/<encodeURIComponent(id)>` with the §2.7 body. The output has the same layout as `create`, with `✓ API key regenerated: <new id>`.
- **Captured**: `regenerate 11111111-…-000000000001 --interval 30 --unit days --updated-by u@example.com` → body `{"rotation_time_interval":30,"rotation_time_unit":"days","updated_by":"u@example.com"}`, output `  ✓ API key regenerated: 11111111-1111-4111-8111-800000000001` … `  Key   PRIVATE-ROTATED-API-KEY-ROTATED8`.
- The docs-site says that regenerate returns a new UUID and a new secret, and that the old key is invalidated. That makes regenerate **destructive**: it revokes the key that running integrations use. No confirmation is asked.
- **Replay hazard** (derived from the captures and the API semantics): a 5xx or timeout *after* the service rotated the key is re-sent with the **old** id, and the outcome depends on the service.
  - If the service rotates again, the key printed is the last one, and each intermediate key is lost.
  - If the old id no longer exists, the user sees a 404 failure while the key **was** rotated and its new secret was never shown.
  - Captured on the stub, which rotated only on success: 3 POSTs after two 500s.
- An unknown id gives `AISEC_CLIENT_SIDE_ERROR:api key not found` + `HTTP 404` (the stub's text). For `..`, see §2.8.

### 5.4 `delete|rm <apiKeyName> --updated-by <email>` (`rt.ts:261-275`)

- `DELETE /v1/mgmt/apikey/delete/<encodeURIComponent(name)>?updated_by=<email>` (`SDK:11798-11808`). Captured: `?updated_by=u%40example.com`.
- **Output**: banner, then `ui.success(result.message)`: `"  ✓ api key key-1 deleted\n"`, which is the **server's** text, raw.
  - `ApiKeyDeleteResponseSchema` (`SDK:2097-2100`) accepts a JSON string, which becomes `{message}`: `"plain string message"` printed `✓ plain string message`.
  - It also accepts an object with optional `message`. `{}` prints **`  ✓ undefined`** (captured).
- There is no confirmation, no existence check and no verification. A 504 was replayed: 2 DELETEs, then success.

## 6. `customer-apps`

### 6.1 `list|ls` (`rt.ts:447-473`, `rr.ts:384-418`, `views.ts:43-54`)

- **Requests**: see §3.
- **Pretty**: the banner, then `"\n  Customer Apps:\n\n"`, then per app `["  <dim id>\n"]` (never printed for real data, §2.11) and `"    <name>[<dim ' — ' + description.slice(0, 80)>]\n"`, then `"\n"`.
  - Captured: `"\n  Customer Apps:\n\n    app-1\n    app-2\n    app-3\n\n"`, with stderr `Showing 3`.
  - The 80-unit cut is a UTF-16 slice, so a description is cut mid-word: `… cut at eighty characters by the pret`.
  - Empty: `"  No customer apps found\n"`.
- **Table**: `ID │ Name │ Description`. Both ID and Description are **always empty** (captured `"    │ app-1 │             "`).
- **JSON**: `[{"name":"app-1","raw":{"customer_appId":"…","tsg_id":"100","app_name":"app-1","model_name":"gpt","cloud_provider":"aws","environment":"prod","ai_agent_framework":"none","api_keys_dp_info":[{"api_key_name":"key-1","dp_name":"dp-1","auth_code":"PRIVATE-AUTHCODE-1"}]}}, …]`. There is no `id` key, and `raw` carries the auth codes (captured). The docs-site's `"id": ""` is stale.

### 6.2 `get <appName>` (`rt.ts:475-490`, `rr.ts:421-435`)

- `GET /v1/mgmt/customerapp?app_name=<name>` (`SDK:11880-11890`). The response must match `CustomerAppSchema`: a response without `environment` fails with `Response did not match schema: environment: invalid_type`.
- **Pretty** (captured):

  ```
  "\n  Customer App Detail:\n\n  Name  app-1\n  Data  {\n  \"customer_appId\": \"22222222-…-000000000001\",\n  \"tsg_id\": \"100\",\n  …\n  \"ai_agent_framework\": \"none\"\n}\n\n"
  ```

  - There is no `ID` row (§2.11). A `Desc` row prints only when `description` is set.
  - `Data` is `JSON.stringify(raw, null, 2).slice(0, 500)`: it is cut at 500 UTF-16 units **mid-string, with no marker** (captured, a long `notes` value ended without a closing quote or brace).
  - Lines after the first are not indented beyond JSON's own two spaces.
- **JSON**: `{"name":"app-1","raw":{…}}`.
- **Table** is `Key │ Value` with rows `id` (empty), `name`, `description` (empty), and `raw` (the compact JSON).
- Not found gives `AISEC_CLIENT_SIDE_ERROR:customer app not found` + `HTTP 404` (the stub's text).

### 6.3 `update <appId> --config <path>` (`rt.ts:491-506`)

- `PUT /v1/mgmt/customerapp?customer_app_id=<appId>` (`SDK:11952-11963`) with the whole file as the body. The output is `"  ✓ Customer app updated: <app_name>\n"`, then the §6.2 detail of the response.
- **Full replacement.** `CustomerAppSchema` requires `app_name`, `cloud_provider` and `environment`, so a patch-style file is refused locally (§2.7). TS does not read the current record, and never warns that optional fields omitted from the file (`model_name`, `ai_agent_framework`, `status`) may be cleared by the service. Whether the service clears them is unverified; the stub merged them.
- **Identity mismatch.** `update` takes the customer-app **id**, but `get` and `delete` take the **name**, and TS never prints the id: pretty, table and the json `id` are empty, so the id is visible only inside `raw`/`Data`.
- `app_name` in the file can rename the app, with no warning.
- The PUT is replayed on 5xx (§2.6). No confirmation is asked.

### 6.4 `delete|rm <appName> --updated-by <email>` (`rt.ts:508-521`)

- `DELETE /v1/mgmt/customerapp?app_name=<name>&updated_by=<email>` (`SDK:11979-11990`). The output is `"  ✓ Customer app \"<name>\" deleted.\n"`, where `<name>` comes from the **response**.
- `CustomerAppDeleteResponseSchema` (`SDK:2135-2139`) is a union: a string becomes `{message}`, or `{message}`, or `CustomerAppSchema`.
  - A message response (the SDK documents `customer app and associated keys successfully deleted`) prints **`✓ Customer app "" deleted.`** (captured with a string body).
  - The SDK's own doc string says the delete **also deletes the app's API keys**. The CLI does not say so and does not confirm.
- A 500 was replayed: 2 DELETEs, then success (captured).

### 6.5 `consumption [appName] [--time-interval 7|30|60]` (`rt.ts:523-579`, `mgmt.ts:401-505`, `rr.ts:438-550`)

- **`--time-interval`**: `Number.parseInt(v, 10)`, then 7/30/60 or the usage error. Captured: `7.5` → 7 and `60abc` → 60 are accepted; `14` → exit 2. The check runs after the tenant is read: with no tenant, `--time-interval 14` exits 1 with the tenant error.
- **Name resolution** (`listConsumptionApps`, `mgmt.ts:401-433`):
  - It walks `GET <dash>/v1/mgmt/dashboard/v2/apps/applicationsoverview?time_interval=30&time_unit=days&limit=100&offset=<o>` with `x-tsg-id`. The window is **always the default 30 days**, whatever `--time-interval` says.
  - `offset += page.length`. The walk stops when the page is empty, or `page.length < limit`, or `offset >= total_items`.
  - **A service that caps the page below 100 ends the walk after one page.** Captured: page `[a1, a2]` with `total_items: 3` → `quiet-app` reported as `Dashboard application not found`, a **false not-found**.
  - Items whose `id` or `name` is not a string are dropped silently (captured `{id: null, name: "no-id"}` → not found).
  - `items` is required: `{}` fails with `Response did not match schema: items: invalid_type`.
  - The match is the **first** exact, case-sensitive `appName`. Buckets share ids (`chatbot` and `LiteLLM` share `uuid-shared`, captured).
- **Single app.** One overview walk, then **two parallel GETs** (`Promise.all`):
  - `…/apps/application?appid=<id>&appname=<name>&time_interval=<n>&time_unit=days`
  - `…/apps/applicationviolationbreakdown?…` with the same query.
  - The SDK checks both values are non-blank (`appQuerySchema`, `SDK:12202-12207`; a failure is `Invalid dashboard query parameters`).
- **All apps** (no name or `''`):
  - One overview walk, then **per app another full overview walk** (`getCustomerAppConsumption` resolves the name again) plus the two reads: 1 + 3N requests (captured 10 requests for 3 apps). A failure for one app prints `  ✗ [<appName>] <message>` on stderr and continues. **The command exits 0** even if every app failed. The sibling request of the `Promise.all` is still sent (captured: `application` failed after 6 attempts while its `applicationviolationbreakdown` had succeeded).
  - An empty overview prints `"  No dashboard applications found\n"` (stdout, exit 0).
- **Pretty**, per app (captured):

  ```
  "\n  chatbot\n  (uuid-shared)\n\n  Monitoring since  2026-04-29T17:04:52Z\n  Source            api\n  Cloud             other\n  Profiles          ms-tuned, golden-v2\n\n  Token consumption:\n\n  Daily avg      744.233K\n  Monthly total  17.71M\n\n  Sessions:\n\n  Total      56935\n  Violating  31136\n\n  Detectors (6 violating, 2/3 firing):\n\n   Detector         │ Total │ Severity        \n  ──────────────────┼───────┼─────────────────\n   topic_guardrails │ 3     │ c=0 h=0 m=3 l=0 \n   pi               │ 3     │ c=1 h=2 m=0 l=0 \n\n"
  ```

  - The title is `ui.header(appName, '(' + appId + ')')`: the name in bold, then the id in dim on its **own** line. The docs-site shows them on one line.
  - The four metadata pairs print only when present. When none are present, a blank line follows the header and then the `Token consumption:` section (captured for `quiet-app`: `"\n  quiet-app\n  (uuid-quiet)\n\n\n  Token consumption:\n\n  Daily avg      -\n  Monthly total  -\n\n  Sessions:\n\n  Total      0\n  Violating  0\n\n  Detectors (0 violating, 0/0 firing):\n\n  no detector violations in window\n\n"`).
  - `Daily avg`/`Monthly total` = `<n><scale>`, or `-` when absent.
  - Only detectors with `total > 0` are listed: `firing/all` counts, and `severity` is `c=<n> h=<n> m=<n> l=<n>`.
  - `no detector violations in window` is `ui.dim`, so `--quiet` suppresses it.
- **JSON/table** (`rr.ts:467-505`): one row **per detector**, firing or not, with the app context repeated in every row.
  - Keys and labels: `app_name` (App), `app_id` (AppId), `monitoring_since` (MonitoringSince, `''` when absent), `daily_avg` (DailyAvg, a **string** such as `"744.233K"` or `"-"`), `monthly_total` (MonthlyTotal), `sessions_total` (Sessions), `sessions_violating` (Violating), `detector` (Detector), `critical` (C), `high` (H), `medium` (M), `low` (L), `total` (Total).
  - Captured json: `[{"app_name":"chatbot","app_id":"uuid-shared","monitoring_since":"2026-04-29T17:04:52Z","daily_avg":"744.233K","monthly_total":"17.71M","sessions_total":56935,"sessions_violating":31136,"detector":"topic_guardrails","critical":0,"high":0,"medium":3,"low":0,"total":3}, …]`.
  - An app with no detector rows prints `[]` (json), or **an empty line** (table: `formatOutput` returns `''`, which `console.log` prints as `"\n"`). The app is then invisible in the table.
  - **All-apps json is several JSON documents concatenated** (`"[…]\n[…]\n[]\n"`, captured): it is not parseable as one value.
  - `cloud`, `source` and `profiles` are not in json/table.
- **Errors**: the not-found message lists the first 5 names in quotes, raw, plus `, ... (<N> total)` when there are more (captured with `"evil\e[31m"` inside).

## 7. `deployment-profiles list|ls [--unactivated]` (`rt.ts:586-603`, `rr.ts:553-591`, `mgmt.ts:509-514`)

- **Request**: `GET /v1/mgmt/deploymentprofiles`, plus `?unactivated=true` with the flag (`SDK:12052-12066`; `String(true)`). There is no paging and no `--all`.
- **Response.** `DeploymentProfilesResponseSchema` requires the `deployment_profiles` array and a top-level `status` string: `{"deployment_profiles":[…]}` without `status` fails with `Response did not match schema: status: invalid_type` (captured).
- **Pretty**: the banner, then `"\n  Deployment Profiles:\n\n"`, then per row `"    <dp_name ?? profile_name ?? name ?? 'unknown'>[  <status: green if === 'active' else dim>][  <dim auth_code>]\n"`, then `"\n"`. Captured: `"    dp-1  active  PRIVATE-AUTHCODE-1\n    dp-2  activated  PRIVATE-AUTHCODE-2\n\n"`.
- **Table**: `Name │ Status │ Auth Code`. Captured `" Name │ Status    │ Auth Code          \n──────┼───────────┼────────────────────\n dp-1 │ active    │ PRIVATE-AUTHCODE-1 \n…"`.
- **JSON**: `[{"name":"dp-1","status":"active","authCode":"PRIVATE-AUTHCODE-1"}, …]`. It is built by the renderer (not `emitList`), so there is **no page status line**, and `expiration_date`, `ave_text_records` and `tsg_id` are dropped.
- **Empty list: `"  No deployment profiles found\n"` on stdout for every format, json included** (captured; `rr.ts:557-560` checks the length before the format), so `--output json | jq` fails.
- The **auth code is printed in every format**. Auth codes are the activation codes that `api-keys create` takes as `auth_code` (§10).

## 8. `scan-logs query` (`rt.ts:1076-1094`)

- The action is a stub (`rt.ts:1089-1094`). It prints `ui.error('Legacy scan-logs retrieval is broken and under refactor. Empty results do not mean no activity. Use airs-cli runtime sessions list --interval 1 --unit day --output json, or airs-cli runtime report.')` and sets `process.exitCode = 1`.
- **Output** (captured): stderr `"  ✗ Legacy scan-logs retrieval is broken and under refactor. Empty results do not mean no activity. Use airs-cli runtime sessions list --interval 1 --unit day --output json, or airs-cli runtime report.\n"`, stdout empty, exit 1. **No request** is sent, not even the token request.
  - The message has no leading blank line and no `Error:`.
  - With `AIRS_CLI_INVOKED_AS='airs cli'`, `commandHint` rewrites both hints to `airs cli runtime …` (captured).
- **Order**: commander checks first (`--interval` and `--unit` required: `error: required option '--interval <n>' not specified`, exit 1). Then `preAction` reads the tenant (no tenant → the tenant error, exit 1) and checks `--output` (`xml` → exit 2). Then the stub runs. `--filter`, `--limit`, `--offset`, `--page` and `--page-size` are accepted and ignored; the deprecation warning never prints, because `resolveDeprecatedAliases` is never called.
- `--quiet` does not suppress it (`ui.error`). `--debug` creates an empty log file first.
- **Dead code.** `SdkManagementService.queryScanLogs` (`mgmt.ts:520-538`) and `renderScanLogList` (`rr.ts:594-640`) are unreachable. The SDK's `scanLogs.query` (`SDK:12099-12124`, `@deprecated … broken`) would `POST /v1/mgmt/scanlogs?time_interval&time_unit&pageNumber&pageSize&filter` with an optional `{page_token}` body.
- The live e2e spec asserts only "legacy scan-logs exits 1 instead of fabricating empty results" (`tests/e2e/runtime-dashboard.e2e.spec.ts:146-168`). The unit spec `flag-standardization.spec.ts:253-280` tests only `resolvePageParams` on this command's flags (page 1 with size 50 by default; `--offset 100 --limit 50` → page 3; `--page 4 --page-size 20` passes through with a warning). The action never uses that function.

## 9. Table, JSON and dropped formats

### 9.1 Table

`formatOutput` (`common.ts:96-140`):
- The header is ` <label.padEnd(w)> ` cells joined by `│`.
- The separator is `─` × (w+2) joined by `┼`.
- The body cells use `displayValue` (`null` → `''`, objects → compact JSON).
- Widths are UTF-16 lengths, and there is no trailing newline beyond `console.log`'s.
- An empty list prints nothing at all for `emitList` (`if (rendered)`), but `"\n"` for the consumption and deployment renderers.

Column sets:
- `api-keys list`: `ID, Name, Last 8, Expires`.
- `customer-apps list`: `ID, Name, Description`.
- `customer-apps get`: `Key, Value`.
- `consumption`: the 13 columns of §6.5.
- `deployment-profiles`: `Name, Status, Auth Code`.

The page status still goes to stderr.

### 9.2 JSON

- `JSON.stringify(rows, null, 2)` plus `"\n"`, and `[]` for an empty `emitList`.
- Details print one object.
- The key order is the projection order of §2.11.

### 9.3 `markdown`, `csv`, `yaml` (TS only)

Captured for `api-keys list`:
- markdown: `| ID | Name | Last 8 | Expires |\n| --- | --- | --- | --- |\n| 11111111-… | key-1 | LAST8-01 |  |\n…`
- csv: `ID,Name,Last 8,Expires\n11111111-…,key-1,LAST8-01,\n…`
- yaml: `- id: 11111111-…\n  name: key-1\n  last8: LAST8-01\n…`

`customer-apps get --output yaml` prints `name: app-1\nraw:\n  customer_appId: …`. These formats are dropped in Rust (MILESTONES scope, D50).

## 10. Sensitive-data exposure (TS)

| Where | What can leak |
|---|---|
| `api-keys create`/`regenerate` stdout | the **full API key** in the pretty `Key` row, on the terminal or in a CI log, also under `--quiet`; no file channel, no `--output json` (ignored) |
| `api-keys list --output json` | `apiKey` when the list response carries `api_key` (the schema allows it, `SDK:2069`) |
| `api-keys create` replays | 4–6 POSTs on 5xx/timeouts: extra live keys whose secrets were never shown (§2.6) |
| `regenerate` | rotates (revokes) the key in use without confirmation; a replay after a post-dispatch failure can lose the new secret (§5.3) |
| response validation after create | a created key whose response lacks a required field is never shown (§5.2) |
| server error text | printed verbatim with control characters; a 409 echoing a key or an auth code reaches stderr (§2.6) |
| auth codes | `deployment-profiles list` prints `auth_code` in pretty, table and json; `customer-apps list --output json` prints `raw.api_keys_dp_info[].auth_code`; `api-keys create --config` files carry one; a JSON syntax error quotes up to ~30 characters of the file |
| `--debug` file | redaction by key name only (`api_key`, `auth_code`, `api_key_*` masked); query values (`updated_by` emails, `app_name`) and customer-app bodies kept; written in the cwd (§2.10) |
| `PANW_AI_SEC_DEBUG=1` | full URLs with queries on stderr; with `PANW_AI_SEC_DEBUG_BODY=1` bodies with the SDK's redaction (`api_key_last8` and names kept) |
| argv | `--updated-by` emails, app and key names; `--config` paths |
| `--config` read | no regular-file check or size cap; `ENOENT` prints the path as typed |
| destructive writes | `api-keys delete`, `regenerate`, `customer-apps delete` (also deletes the app's keys, per the SDK doc), `customer-apps update` (full replacement): no confirmation, no dry run, replayed on 5xx, no outcome-unknown text, silent on SIGINT/SIGTERM |
| path traversal | `regenerate ..` → `POST /v1/mgmt/apikey/`; `delete ..` → `DELETE /v1/mgmt/apikey/` (§2.8) |
| terminal control | every server string (names, descriptions, messages, the Data blob, dashboard names in errors) printed raw |

## 11. Doctor and tenant wording

- `doctor` has no check that names API keys, customer apps, deployment profiles, scan logs or the dashboard host. The management-credentials check's wording is shared (`missing: <keys> — management, red team, model security, AI Gateway and AgentGuard commands are unavailable`, already ported). No doctor probe reads `mgmtDashboardEndpoint`.
- `tenant`: `mgmtDashboardEndpoint` is an ordinary URL config key (`schema.ts:22`; `client-options.spec.ts:113-133` pins the default `https://api.apps.paloaltonetworks.com/aisec` and the override). It is already in the Rust key set (`src/tenant/config.rs:20,82`) and the import (`src/tenant/ts.rs:26`). No other wording.

## 12. TS specs to port

| TS spec | Behaviour to port as executable tests |
|---|---|
| `tests/unit/airs/management.spec.ts:1071-1117` | `listApiKeys` returns normalised keys and `nextOffset` (the mocks use `id`/`name`/`created_at`; port with schema-valid wire fields and assert the §12 decision on `created_at` vs `creation_ts`); `createApiKey` passes the config through unchanged; `regenerateApiKey(id, body)`; `deleteApiKey(name, updatedBy)` returns `{message}` |
| `management.spec.ts:1123-1170` | `listCustomerApps` normalises names; `getCustomerApp(name)` calls get with the name; `updateCustomerApp(id, body)` returns the updated name; `deleteCustomerApp(name, updatedBy)` returns the name from a record response |
| `management.spec.ts:1176-1194` | `listDeploymentProfiles` returns raw rows; `--unactivated` passes `{unactivated: true}` (`?unactivated=true`) |
| `management.spec.ts:1200-1225` | `queryScanLogs` request mapping: TS never calls it (§8). Port as the "`scan-logs query` sends nothing and exits 1" test |
| `management.spec.ts:1227-1395` | consumption: appId from the overview, both dashboard reads with `{appId, appName, timeInterval}` (default 30, `--time-interval 60` passed through); `not found` lists names and calls neither read; a shared appId with two names resolves the named bucket; null `token_stats`/`session_stats`/`profiles` and an empty breakdown (assert the §12 decision on invented zeros) |
| `management.spec.ts:1397-1440` | `listConsumptionApps` walks every page (`limit 2`, second call `offset 2`, total 3); normalises `{appId, appName, cloud, source}`; default `{limit: 100, offset: 0}`; caller limit/offset; drops items without a string id or name; empty items |
| `tests/unit/cli/aliases.spec.ts:55-79` | `ls` on `api-keys`, `customer-apps` and `deployment-profiles` lists; `rm` on `api-keys delete` and `customer-apps delete` |
| `tests/unit/cli/flag-standardization.spec.ts:66,253-280` | `scan-logs query` keeps `--limit/--offset` and the hidden `--page/--page-size`; the Rust stub must accept them and still send nothing |
| `tests/unit/config/client-options.spec.ts:113-133` | management options: `mgmtEndpoint` and `mgmtDashboardEndpoint` overrides and defaults, explicit OAuth values (no `PANW_*` fallback) |
| `tests/e2e/runtime-dashboard.e2e.spec.ts:146-168` | `--quiet runtime scan-logs query --interval 24 --unit hours` exits 1 |
| `tests/integration/*` | none for these commands |

## 13. Rust SDK (`scm-sdk` 0.1.1) pointers

- **Feature `management`** (already enabled) exposes all of them, through `ManagementClient::new(oauth)` (`rs:airs/management/mod.rs:62-69`, which derives a dashboard client with the TSG header) and `with_dashboard_endpoint(endpoint)` (`mod.rs:75-78`, for `mgmtDashboardEndpoint`):
  - `api_keys()`: `list(PaginationOptions{offset,limit}, opts)`, `pages`, `list_all(ApiKeyListAllOptions{limit, collect})`, `create(&ApiKeyCreateRequest)`, `regenerate(id, &ApiKeyRegenerateRequest)`, `delete(name, updated_by)` (`rs:airs/management/api_keys.rs:31-156`).
  - `customer_apps()`: `list`, `pages`, `list_all`, `get(name)`, `update(id, &CustomerApp)`, `delete(name, updated_by)` (`rs:airs/management/customer_apps.rs:31-153`).
  - `deployment_profiles().list(DeploymentProfileListOptions{unactivated}, opts)` (`rs:airs/management/inventory.rs:19-41`).
  - `scan_logs().query` (`inventory.rs:103-136`, not needed).
  - `dashboard()`: `applications_overview(&DashboardApplicationsOverviewQuery)` (`rs:airs/management/dashboard.rs:632-645`; interval ∈ {1, 7, 30, 60}, unit ∈ {days, day, hour}, limit ≥ 1, `dashboard.rs:315-341`), `application(&DashboardAppQuery)` and `application_violation_breakdown` (`dashboard.rs:350-392`, validated against the TS `appQuerySchema`).
- **Path segments.** `RawRequest::segment` (`rs:engine.rs:74-79`, `config::encode_segment`) rejects traversal segments locally, so `regenerate ..` and `delete ..` cannot reach another route. The CLI should still refuse `''`, `.`, `..` and control characters before the tenant, with a fixed message.
- **Pages.** `PaginationOptions::query` refuses `limit == 0` and offsets beyond 2^53 (`rs:airs/management/profiles.rs:27-39`). `next_offset` `0` or absent ends a page walk; a negative or fractional value is a decode error (`mod.rs:167-178`). The `Pages` walker detects repeated cursors and empty intermediate pages (D37/D46, `rs:pagination.rs:346`), with `CollectOptions` bounds (`pagination.rs:47-90`).
- **Secrets.** `ApiKey.api_key` is a plain `Optional<String>` (`rs:models/generated.rs:4646`). `Debug` is redacted (`generated.rs:4965-4969`), but `Serialize` writes the key, so the CLI must take the value out before any projection, register it in the `SecretSet`, and never serialise the model whole. `auth_code` (on `ApiKey`, `ApiKeyCreateRequest`, `ApiKeyDPInfo` and `DeploymentProfileEntry`) is a plain string too.
- **Typed bodies.** `ApiKeyCreateRequest` has typed required fields plus `extensions` (`generated.rs:4974-4998`), so a strict CLI reader can refuse unknown keys before building it. `CustomerApp` (`generated.rs:18337`) requires `app_name`, `cloud_provider` and `environment` as TS does.
- **Delete responses.** `ApiKeyDeleteResponse` and `CustomerAppDeleteResponse` are unions with an `Unknown(JsonValue)` arm (`generated.rs:5282-5291,18528-18538`): the CLI decides what to print for each arm.
- **G10.** No response defaults on these schemas (§2.11). Passing `without_response_defaults()` everywhere costs nothing.
- **SDK gap candidates (for numbering from G26).** None found that blocks a command. Notes:
  - (a) No request in either SDK can verify a key delete or a customer-app delete. There is no `get` for a key, so a re-read means a list walk, and an app is read by name. This is not a gap, but it bounds what "verified" can mean (§ open question 6).
  - (b) TS sends `updated_by` only as a query parameter on deletes. The Rust SDK does the same (`api_keys.rs:121-137`, `customer_apps.rs:134-153`).

## 14. Live-tier notes

- **Reads to compare** (settled scope):
  - `api-keys list --output json`: compare `id`, `name` and `last8` only. `createdAt`/`expiresAt` are absent in TS (§2.11), and TS json may carry `apiKey` (§5.1). If TS output shows any `apiKey`, run the read Rust-side only and check the key is withheld.
  - `customer-apps list --output json` and `get <first name> --output json`: the TS json carries `raw` with auth codes, so compare it in memory only and never write it to the summary.
  - `customer-apps consumption --output json` (all-apps mode prints concatenated arrays in TS; parse them as a stream) or a single named app.
  - `deployment-profiles list --output json`: auth codes are tenant secrets. Compare names and statuses, never write the codes, and treat the Rust withholding (§ open question 3) as an expected difference.
  - `scan-logs query --interval 1 --unit hours` (both exit 1, no request).
- **Never live:** `api-keys create|regenerate|delete` and `customer-apps update|delete`. The run cannot create its own customer app, and a customer-app delete also deletes the app's keys.
- **Timing.** The dashboard overview for all apps costs 1 + 3N requests in TS, so prefer naming one app (the first overview bucket) to bound the run.

## Acceptance criteria

Each criterion is a loopback executable test of airs-cli-rs. Parity tests compare both CLIs where the behaviour is shared.

1. **Credentials and endpoints.** Every command uses only the selected tenant's `mgmt*` credentials, `mgmtTokenEndpoint`, `mgmtEndpoint` (keys, apps, deployment profiles) and `mgmtDashboardEndpoint` (consumption, with `x-tsg-id`), with the SDK default bases. `PANW_*` variables are ignored, and tenant files are unchanged.
2. **Requests.** Requests match §3.2, §5–§7 (method, path, query keys and order, bodies of §2.7). `scan-logs query` sends no request at all and exits 1 with the §8 text, after the commander, tenant and format checks, with the hidden paging aliases accepted.
3. **Argument checks before the tenant (exit 2).** These run before the tenant is read: list flags (`--limit 0|abc|1.5`, `--offset -1`, `--max -1`, `--all` with `--offset`), `--output` outside `pretty|table|json` (markdown, csv and yaml included), `--time-interval` (decimal 7/30/60 only; `7.5` and `60abc` refused), `--interval` (positive decimal integer), `--unit` (`hours|days|months`, per the §12 decision), and the empty, `.`, `..` and control-character IDs and names. The output stays empty.
4. **Pretty layouts.** Pretty layouts match §5–§7 byte for byte on stdout (banner, sections, key padding, the U+2026 key suffix, colours of §4), except where a §12 row changes them. The banner is printed only for pretty output and only after every check passed (D57). `--quiet` never drops IDs, the app title in consumption, or the key data (D55).
5. **Table and JSON.** Table and JSON match §9 with the §12 decisions: a key's `expiresAt`/`createdAt` mapped from `expiration`/`creation_ts`, the customer-app `id` from `customer_appId`, the deployment-profile empty list as `[]` in json, and all-apps consumption json as one array.
6. **Key secrets.** The `create`/`regenerate` key value appears only on the channel decided in §12 (open question 1). It is registered in the `SecretSet` before anything is printed, and it never appears on stderr, in an error, in the debug log, in a list or get output, or in the live summary or ledger. A list response that carries `api_key` prints it as withheld. A test proves each channel with a planted key.
7. **One attempt per write.** Each write is sent once: one replay after a 401, none after a 403, none after a 5xx, a transport failure or a timeout. A post-dispatch failure prints an outcome-unknown line naming the action (`the API key may have been created`, `the API key may have been regenerated`, `the API key may have been deleted`, `the customer app may have been updated`, `the customer app may have been deleted`) and exits 1. A 2xx with an unreadable body says the change was made but the response could not be read, and for `create`/`regenerate` that the key could not be shown.
8. **Confirmations.** `api-keys delete`, `api-keys regenerate`, `customer-apps delete` and `customer-apps update` confirm per D81: `--force` skips the prompt; without a TTY and without `--force` the run is a usage error before the tenant; declining or Ctrl-C at the prompt sends nothing. The prompt names the target, and for `customer-apps delete` it says the app's API keys are deleted too.
9. **`--config` files.** `--config` files are checked before the tenant: a regular file, a size cap, UTF-8, one JSON object, the required fields, and unknown keys refused, naming the key, not its value. No error echoes their content. Auth codes in them join the `SecretSet`.
10. **Streams.** Acknowledgements and outcome lines go to stderr. stdout carries only data, and json/table output from writes is the response record without the secret, per the §12 decision. Colour is decided per stream.
11. **Server text.** All server text (names, descriptions, messages, dashboard names, the customer-app record) goes through `terminal_safe`. Error text is built from SDK metadata only (§6), never from raw bodies.
12. **`--debug`.** The debug log records method, path, status and headers only: no bodies, and no query values beyond the paging keys (`updated_by` and `app_name` withheld).
13. **Walks.** `--all` walks are complete or fail: a repeated cursor or an empty intermediate page fails (D37/D46), and a `--max` cut prints the D14 line. The consumption name lookup walks every overview page by `total_items`, not by short pages, and never reports a false not-found from an incomplete walk.
14. **Consumption failures.** If any app fails in all-apps consumption, the command exits 1 after printing the others. The failing app is named on stderr, and the window is applied to the lookup as well, per the §12 decision.
15. **Interruption.** SIGINT/SIGTERM during a write exits 130/143 with the `Interrupted; …` line saying the change may have been applied.

## Open questions / likely §12 divergences

The orchestrator assigns the numbers from D204. Each item is a safety or correctness fix unless marked otherwise.

1. **API key secret channel (safety; decision needed).** TS prints the full key on stdout in the pretty detail, also under `--quiet`, with `--output` ignored. Options:
   - (a) The key on stdout as the command's only data (pretty: `Key  <value>`; json: `{"id","name","last8","apiKey"}`). The ack and metadata go to stderr, and the key is never printed twice.
   - (b) `--key-file <path>` written exclusively at 0600, never overwritten and checked before the tenant (D194 style), with pretty showing `(written to <path>)`. Without `--key-file`, the key is printed per (a).
   - (c) Option (b), but with the key withheld unless `--key-file` or `--show-secret` is given. This is unsafe: an unrecoverable secret would be lost.

   Recommendation: (b), with stdout (a) as the fallback. A created key cannot be read again, so withholding it outright would destroy it. `--key-file` lets CI avoid the terminal.
   In every case: the `SecretSet` registration happens before printing; the key never appears in a list or get; `api_key_last8` is shown as `…<last8>`.
2. **Key in list json (safety).** TS json prints `apiKey` when a list response carries `api_key`. Rust: never print it in a read; show `[withheld]` or omit it (D139 precedent), and register it in the `SecretSet`.
3. **Auth codes (safety; choice).** `deployment-profiles list` prints `auth_code` in every format, and `customer-apps list|get` json prints `raw.api_keys_dp_info[].auth_code`. Auth codes are license activation codes, which `api-keys create` takes as a credential-like input. Recommendation: `[withheld]` in pretty and table, json too, and a `--show-auth-codes` flag only if a use case appears. Rejected alternative: parity printing.
4. **Write replay (safety).** TS re-sends `create` (4–6 POSTs captured), `regenerate`, `update` and the deletes. Rust: D95 (one attempt, one 401 replay, no 403 replay) with the outcome-unknown lines of acceptance 7. For `regenerate`, the outcome line says the old key may already be revoked.
5. **Confirmations (safety).** TS never confirms. Settled: `api-keys delete`, `regenerate` and `customer-apps delete` follow D81, and the customer-apps prompt says the app's keys are deleted too (the SDK's own doc string). Recommendation: `customer-apps update` confirms too, because it is a full replacement that can drop optional fields; show the fields the file omits that the current record has, read through a list walk by id, since `get` takes a name. Rejected alternative: confirming only deletes.
6. **Delete outcome wording (correctness).** TS prints the server message raw (`✓ undefined` for `{}`) and `Customer app "" deleted.` for message-style responses. Rust: a fixed `Deleted API key <name>.` / `Deleted customer app <name>.` built from the argument, with the server message dropped or passed through `terminal_safe`. Verifying by re-reading is optional (choice: no verification, because there is no single-key read; say "accepted by the service").
7. **Wrong listings (correctness).**
   - Key `createdAt`/`expiresAt` are read from `created_at`/`expires_at`, never sent, so `Expires` is always empty. Map them from `creation_ts`/`expiration`.
   - Customer-app `id` is read from `customer_app_id`, so it is always empty in pretty, table and json while `update` needs it. Map it from `customer_appId`.
   - `description` is a field no schema has: keep the column empty, or replace it with `environment`. Choice: keep TS's columns but fill them correctly.
   - The live comparison must project, because TS will differ.
8. **Customer-app `raw` blob (correctness/safety).** The json `raw` and the pretty `Data` (cut at 500 UTF-16 units mid-string) dump the wire object. Rust: a typed detail (pretty key/value rows of the known fields; json the record with auth codes withheld). Choice: whether json keeps TS's `{name, raw}` shape (recommended for comparison, with `id` added and `raw` sanitised) or a flat record.
9. **Consumption lookup (correctness).**
   - The lookup walk ends at the first short page, so a capped page gives a false not-found. Use `total_items` and fail on an incomplete walk.
   - The lookup ignores `--time-interval` (always 30 days). Apply the same window to the lookup; choice: yes.
   - The all-apps mode re-walks the overview per app (1 + 3N requests). Walk once.
   - A partial failure exits 0. Exit 1 after printing the rest.
   - `consumption ''` means all apps. Make it a usage error.
10. **Consumption invented values (correctness).** `null` session stats print `Total 0`, `Violating 0`, and missing severities print 0. Rust: absent stays absent (`-` in pretty, `null` in json). The `Detectors` heading counts only what was sent.
11. **Consumption output shape (correctness).** All-apps json is concatenated arrays: make it one array of the rows of every app. A detector-less app prints an empty table line: emit no rows, plus an app-level line on stderr, or rows with `detector: null` (choice: one row with `detector` null so the app stays visible). Under `--quiet` the app title is lost: print it as data.
12. **Deployment-profile empty json (correctness).** `No deployment profiles found` on stdout under `--output json`. Rust: `[]`.
13. **`next_offset: 0` status (correctness).** `Showing N (more available)` on the last page. Rust: `Showing N` (D12 extended).
14. **`--all --max` cut and walk errors (correctness).** `Showing all N` after a `--max` cut, and an empty page with `next_offset` is followed. Rust: D14 and D37/D46 extended to keys and apps.
15. **Flag parsing (correctness).** `--interval` (`parseInt`: `1.9` → 1, `-5` sent), `--time-interval` (`7.5` → 7, `60abc` → 60) and `--unit` (free text, while the help says `hours, days, months`). Rust: strict decimal integers, `--interval` ≥ 1, `--unit` ∈ {hours, days, months} (choice: a usage error naming the allowed values; rejected: passing unknown units through). All checks before the tenant (D17/D18 pattern).
16. **Banner and validation order (correctness).** Class-B commands print the banner before every check, list flags are checked after the tenant, and the `--time-interval` error with no tenant is the tenant error. Rust: every argument check before the tenant, and the banner only on the success path (D57).
17. **`--config` files (safety).** TS sends the whole file, unknown keys included, quotes the input in JSON errors, and reads FIFOs and `/dev/stdin`. Rust: D103-style strict reader before the tenant; unknown keys refused (choice) or dropped with a warning; errors never quote content; `auth_code` values in the `SecretSet`.
18. **Path traversal (safety).** `regenerate ..` and `delete ..` reach other routes, and `delete ''` hits `…/delete/`. Rust: usage error before the tenant (the SDK also refuses these).
19. **Error text from bodies (safety).** Server `message` text and non-JSON bodies are printed raw (a 409 echoing a key). Rust: §6 metadata only, and the `SecretSet` check (D11 extended).
20. **Terminal safety (safety).** All printed server text through `terminal_safe` (D52 extended).
21. **Stdout acknowledgements (correctness).** `✓ API key created: …`, `✓ Customer app updated: …` and the delete lines are on stdout. Rust: stderr (D94/D106 precedent); stdout carries only the data (the key per question 1, the updated record).
22. **`--output` on writes (correctness; choice).** TS ignores it. Recommendation: honour `pretty|table|json` on `create`, `regenerate` and `update` (the record, with the key per question 1), and refuse markdown, csv and yaml (D50, D94 precedents).
23. **`--debug` and body logging (safety, settled).** TS logs customer-app bodies, queries and response records, redacted by key name only, and `PANW_AI_SEC_DEBUG_BODY` can print bodies. Rust: status and headers only (D64 extended).
24. **Interruption (correctness).** TS exits silently on SIGINT/SIGTERM. Rust: §13.2 `Interrupted; …` (D32).
25. **`scan-logs query` (parity, no divergence expected).** Keep the stub: same text, exit 1, no request, after the argument checks. Choices:
    - (a) Keep TS's order: tenant first, then the message. Or (b) give the message before the tenant, because the command needs no tenant. Recommendation: (b) for the usage contract. A missing tenant is then not an error for a command that sends nothing.
    - The hidden `--page/--page-size` stay accepted and ignored.
    - `--output` is validated against `pretty|table|json`.
26. **Help texts (cosmetic).** The duplicated `(default: 100) (default: 100)` (§1) is a commander artefact; Rust prints one. The docs-site examples (consumption title on one line, `"createdAt": ""` and `"id": ""` in json) are stale and not a contract.
