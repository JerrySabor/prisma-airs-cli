# Spec: TS `airs-cli` runtime dashboard, sessions, report and profile transfer (M6d)

Commands covered: `runtime dashboard applications|application|application-violations|top-applications|violations-trend|apps-list`, `runtime sessions chart|list|get|transaction|scan-content`, `runtime report`, `runtime profiles backup [profile]` and `runtime profiles restore <file>`. `api-keys`, `customer-apps`, `deployment-profiles` and `scan-logs` are in a separate spec; they appear here only where the report reads customer apps (§5.3).

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0, SDK `@cdot65/prisma-airs-sdk` 0.34.0, commander 14, js-yaml 4, chalk 5). Citations:
  - `rd.ts` is `src/cli/commands/runtime-dashboard.ts`, `rr.ts` is `src/cli/commands/runtime-report.ts`, `pt.ts` is `src/cli/commands/profile-transfer.ts`, `rt.ts` is `src/cli/commands/runtime.ts`, `prog.ts` is `src/cli/program.ts`, `co.ts` is `src/config/client-options.ts`, `mg.ts` is `src/airs/management.ts`.
  - `rep.ts` is `src/reports/runtime.ts` (the collector), `ren.ts` is `src/reports/render.ts` (HTML and Markdown), `io.ts` is `src/reports/io.ts` (`writeReportFile`), `typ.ts` is `src/reports/types.ts`.
  - `rp.ts` is `src/backup/runtime-profiles.ts` (backup, plan, restore), `pol.ts` is `src/backup/runtime-policy.ts` (`compareRuntimePolicies`).
  - `common.ts`, `ui.ts` are under `src/cli/renderer/`; `confirm.ts` is `src/cli/confirm.ts`; `dbg.ts` is `src/cli/debug-logger.ts`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` of the reference build. `rs:<file>:<line>` is `~/.cargo/registry/src/*/scm-sdk-0.1.1/src/<file>`.
- Shared shell behaviour (commander parse errors exit 1, the root `--output` consumer, `resolveOutput`, `ui`, quiet, colour, EPIPE) is in `ts-cli-shell.md` and `ts-renderer.md`; the debug log in `ts-debug-log.md`; the confirmation helper in `ts-runtime-writes.md` §2.4; the DLP data-profile inventory in `ts-dlp-backup.md`. They are restated only where these commands depend on them.
- How behaviour was captured (2026-10-18, node v24.21.0): the reference build `dist/cli/index.js` ran against a stateful loopback stub (`node:http` on `127.0.0.1`, random port) implementing `POST /oauth/token` (Basic `client-<tsg>:FAKE-SECRET-<tsg>`, token `tok-<tsg>`), the management plane under `/mgmt` (`GET /v1/mgmt/profiles/tsg/<tsg>`, `GET /v1/mgmt/topics/tsg/<tsg>`, `GET /v1/mgmt/customerapp/tsg/<tsg>`, `POST /v1/mgmt/profile`, `PUT /v1/mgmt/profile/uuid/<id>`, `POST /v1/mgmt/topic`, paged by `offset`/`limit` with `next_offset`), the DLP plane under `/dlp` (`GET /v2/api/data-profiles`, Spring pages), and the dashboard plane under `/aisec` (the ten `/v1/mgmt/dashboard/v2/…` routes and `/v1/mgmt/reports/scancontent`). It logged method, path, raw query, content type, auth scheme, `x-tsg-id`, `User-Agent` and body, kept per-TSG state (two tenants, TSG `100` and `200`), and accepted a fault plan (status, raw body, headers, or a hang).
  - Sandbox: `env -i` with `PATH`, `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` inside the sandbox; the TS registry selected with `PRISMA_AIRS_TENANTS_PATH` (`{"version":1,"active":"src","tenants":[{"name":"src","configPath":…,"tsgId":"100"},{"name":"dst",…,"tsgId":"200"}]}`); each config `{"mgmtClientId":"client-<tsg>","mgmtClientSecret":"FAKE-SECRET-<tsg>","mgmtTsgId":"<tsg>","mgmtEndpoint":"<base>/mgmt","mgmtTokenEndpoint":"<base>/oauth/token","mgmtDashboardEndpoint":"<base>/aisec","dlpEndpoint":"<base>/dlp"}` (0600). Fake sensitive fixture values are `PRIVATE-…`.
  - **Endpoint fallbacks.** Every command builds its client from `managementClientOptions(config)` (`co.ts:44-51`): `clientId`, `clientSecret`, `tsgId`, `tokenEndpoint: mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`, `apiEndpoint: mgmtEndpoint ?? DEFAULT_MGMT_ENDPOINT`, `dashboardEndpoint: mgmtDashboardEndpoint ?? 'https://api.apps.paloaltonetworks.com/aisec'` (`co.ts:27,48`), `dlpEndpoint: dlpEndpoint ?? DEFAULT_DLP_ENDPOINT`. All are explicit, so the SDK environment fallbacks (`PANW_MGMT_ENDPOINT`, `PANW_MGMT_*` credentials, `SDK:13416-13428`) are never reached. **The docs claim `PANW_MGMT_DASHBOARD_ENDPOINT` overrides the dashboard host (`docs-site/docs/cli/runtime/dashboard.md`); no code reads it** (the SDK uses `opts.dashboardEndpoint ?? baseUrl`, `SDK:13439-13440`, and the CLI always passes a value). The only environment variables that change these commands are `PANW_AI_SEC_TIMEOUT_MS` (per-attempt timeout, default 60 000 ms, `SDK:10095`), `PANW_AI_SEC_DEBUG` (refusals, §2.5), `AIRS_CLI_INVOKED_AS` and `FORCE_COLOR`/TTY for chalk.
  - Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and `dns.lookup` and refuses any host other than `127.0.0.1`; its log stayed empty. Because of the debug logger's host filter (`dbg.ts:20-27,163`), a loopback `--debug` run writes an empty log; the debug contents below come from the code and `ts-debug-log.md` §1.9.
  - Pty captures used a Python `pty.fork` driver answering `n`/`y`. Signals were sent with `kill -INT|-TERM` during a hung request.
- No real tenant or credential file was read; no host other than loopback was contacted.
- Captures are JSON strings or verbatim blocks, uncoloured (stdout a pipe) unless stated; §2.4 lists the ANSI codes captured with `FORCE_COLOR=1`. The token request (`POST <mgmtTokenEndpoint>`, `Content-Type: application/x-www-form-urlencoded`, Basic auth, body `grant_type=client_credentials&scope=tsg_id%3A<tsg>`, `User-Agent: node`) precedes the first API request of every run and is omitted from the request lists below.

## 1. Command surface (help verified)

Registration: `rt.ts:185-186` calls `registerRuntimeReportCommand(runtime)` and `registerRuntimeDashboardCommands(runtime)`; `rt.ts:608-609` creates `runtime profiles` and calls `registerProfileTransferCommands(profiles)` before the CRUD subcommands. After registration (`prog.ts:204-206`) every `list` gets alias `ls` (so `sessions list|ls`), `applyReadContractFlags` adds nothing here (`sessions list` already has `--output`, `--limit`, `--offset`, `--all`, `--max`; `sessions get` has `--output`), and help sorts options and subcommands. No command here has a hidden alias, `--force` (except restore), or a prompt (except restore).

`runtime --help` lists (captured): `dashboard  SCM application summaries and daily telemetry (OAuth)`, `report [options]  Generate a daily AI Runtime Security environment report (read-only)`, `sessions  Verified SCM session inventory and drill-down (OAuth)` and `profiles  Manage AIRS security profiles` (whose help lists `backup [options] [profile]` and `restore [options] <file>` with the descriptions below).

| Command | Registration | Arguments and options (help text; defaults as commander prints them) |
|---|---|---|
| `dashboard applications` | `rd.ts:154-178` | description `One page of application activity`; `--interval <n>` (`Look-back interval`, `"1"`), `--unit <unit>` (`Time unit: day, days, hour`, `"day"`), `--limit <n>` (`Items per page`, `"25"`), `--offset <n>` (`Item offset`, `"0"`), `--output <format>` (`Output format: pretty, json, yaml`) |
| `dashboard application` | `rd.ts:179-206` | no description; `--app-id <id>` (`Application identity`, **required**), `--app-name <name>` (`Exact dashboard application name`, **required**), `--interval <n>` (`"30"`), `--unit <unit>` (`Time unit: days`, `"days"`), `--output` |
| `dashboard application-violations` | `rd.ts:179-206` | as `application` |
| `dashboard top-applications` | `rd.ts:207-219` | `--interval <n>` (`"1"`), `--unit <unit>` (`Time unit: hour, hours, day, days`, `"day"`), `--output` |
| `dashboard violations-trend` | `rd.ts:207-219` | as `top-applications` |
| `dashboard apps-list` | `rd.ts:207-219` | `--interval <n>` (`"30"`), `--unit <unit>` (`"days"`), `--output` |
| `sessions chart` | `rd.ts:220-223` | `--interval <n>` (`"1"`), `--unit <unit>` (`Time unit: hour, hours, day, days`, `"day"`), `--output` |
| `sessions list\|ls` | `rd.ts:224-300` | description `Session entries; --all walks pages with completeness checks`; `--interval` (`"1"`), `--unit` (`"day"`), `--limit <n>` (`"25"`), `--offset <n>` (`"0"`), `--all` (`Walk all pages (up to 100 pages)`), `--max <n>` (`Item cap with --all; 0 removes item cap`, `"10000"`), `--output` |
| `sessions get` | `rd.ts:301-308` | `--session-id <id>` (`Session identity`, required), `--app-id <id>` (required), `--app-name <name>` (required), `--interval` (`"30"`), `--unit` (`Time unit: hour, hours, day, days`, `"days"`), `--limit` (`"25"`), `--offset` (`"0"`), `--output` |
| `sessions transaction` | `rd.ts:309-312` | `--session-id`, `--app-id`, `--app-name` (required), `--scan-id <id>` (`Scan identity`, required), `--scan-sub-req-id <n>` (`Sub-request index, including zero`, required), `--interval` (`"30"`), `--unit` (`"days"`), `--output` |
| `sessions scan-content` | `rd.ts:313-325` | description `Explicit sensitive scan-content read; never automatically fetched`; `--scan-id` (required), `--scan-sub-req-id` (required), `--show-content` (`Explicitly display stored content on stdout`), `--output-file <path>` (`Private new file for stored content (no overwrite)`), `--output` |
| `report` | `rr.ts:14-34` | `--output <format>` (`Deliverable format: html or markdown (default: html)`), `--output-file <path>` (`Destination (default: new timestamped file in CWD); - for stdout; never overwrite`), `--title <text>` (`Report title`, `"Daily environment report"`), `--max-pages <n>` (`Page budget per source, 1–100 (25 sessions/page)`, `"40"`), `--strict` (`Exit 1 after writing if any source is incomplete`); four Examples lines |
| `profiles backup [profile]` | `pt.ts:148-169` | description `Back up latest Runtime profile policies and referenced topic definitions; no argument means all profiles`; `--all` (`Back up all latest profiles (cannot be combined with a profile selector)`), `--file-format <format>` (`Backup file format: json or yaml`, `"json"`), `--output-file <path>` (`New private backup file; defaults to the current directory`), `--max-pages <n>` (`Maximum pages per inventory; incomplete exports fail`, parser `maxPages`, default `100` number), `--output <format>` (`Output format: pretty, table, markdown, csv, json, yaml`); two Examples lines |
| `profiles restore <file>` | `pt.ts:223-265` | description `Restore profile policies into the selected tenant; validate all dependencies before changes`; `--dry-run` (`Read and validate a restore plan without changing destination resources`), `--name-prefix <prefix>` (`Prefix restored profile and topic names to avoid collisions`), `--on-conflict <policy>` (`Existing profile names: error, verify (resume without writes), skip or update`, `"error"`), `--on-missing-dlp <policy>` (`Unresolved custom DLP: error or basic (explicitly accepts loss of custom detection)`, `"error"`), `--dlp-map <source=destination>` (`Explicit cross-tenant binding to an existing DLP data profile (repeatable)`, default `[]`), `--max-pages <n>` (`Maximum pages per inventory; incomplete inventories fail`, `100`), `--expect-tsg <id>` (`Assert destination tenant ID; required with --force`), `--force` (`Execute without a prompt; requires --expect-tsg and does not override conflicts`), `--output <format>`; three Examples lines |

Captured leaf help, for example `sessions list --help` (stdout, exit 0):

```
Usage: airs-cli runtime sessions list|ls [options]

Session entries; --all walks pages with completeness checks

Options:
  --all              Walk all pages (up to 100 pages)
  -h, --help         display help for command
  --interval <n>     Look-back interval (default: "1")
  --limit <n>        Items per page (default: "25")
  --max <n>          Item cap with --all; 0 removes item cap (default: "10000")
  --offset <n>       Item offset (default: "0")
  --output <format>  Output format: pretty, json, yaml
  --unit <unit>      Time unit: hour, hours, day, days (default: "day")
```

`runtime report --help` ends with:

```
Examples:
  $ airs-cli runtime report --output-file ./airs-daily.html
  $ airs-cli runtime report --output markdown --output-file ./airs-daily.md
  $ airs-cli runtime report
  $ airs-cli runtime report --strict --max-pages 20 --output-file - > daily.html

```

`runtime profiles restore --help` Examples:

```
  $ airs-cli runtime profiles restore ./profiles.json --dry-run --output json
  $ airs-cli runtime profiles restore ./profiles.json --on-missing-dlp basic --dry-run --output json
  $ airs-cli runtime profiles restore ./profiles.json --name-prefix migrated- --expect-tsg <destination-tsg> --force
```

`runtime dashboard --help` and `runtime sessions --help` list only `applications` and `list|ls`, `scan-content` with descriptions; `application`, `application-violations`, `apps-list`, `top-applications`, `violations-trend`, `chart`, `get`, `transaction` have none (captured).

## 2. Shared behaviour

### 2.1 Client, planes and credentials

- `getOrCreateManagementClient({...managementClientOptions(config), numRetries: 0})` (`rd.ts:131-134`, `rr.ts:58-61`) returns a process-wide cached `ManagementClient` (`mg.ts:549-554`); the first call's options win, and in a one-shot run it is this call. Profile transfer builds its own `new ManagementClient({...managementClientOptions(config), numRetries: 0})` (`pt.ts:118`). `managementClientOptions` calls `assertManagementCredentials` first (missing secret → `Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set <name> <key>' …`).
- Profile transfer additionally requires `mgmtTsgId`, `mgmtClientId` and `mgmtClientSecret` before building the client (`pt.ts:114-117`), else the usage error `Profile transfer requires configured Management client ID, secret and TSG ID` (exit 2, after the tenant was read).
- One OAuth token per invocation, fetched lazily by the first request; requests that run in parallel (the report) share it (captured: one token request, then seven reads).
- Planes (captured):
  - **Dashboard** (`mgmtDashboardEndpoint`, default `https://api.apps.paloaltonetworks.com/aisec`): every `/v1/mgmt/dashboard/v2/…` route and `/v1/mgmt/reports/scancontent`. The `DashboardClient` sends `x-tsg-id: <mgmtTsgId>` on every request (`SDK:12236-12241`, captured `tsgHeader: "100"`).
  - **Management** (`mgmtEndpoint`): profiles, topics, customer apps; no `x-tsg-id` (captured `null`); the TSG is in the path (`/tsg/<tsg>`).
  - **DLP** (`dlpEndpoint`): `GET /v2/api/data-profiles` (restore only).
- Headers: `Authorization: Bearer <token>`, `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `Content-Type: application/json` on bodies.

### 2.2 HTTP layer (SDK-owned, `SDK:10094-10230`, `SDK:10855-10873`)

- Query parameters are set with `URLSearchParams` (`SDK:10117-10121`): a space is `+`, `&` is `%26` (captured `appname=A+%26+B`). Values are stringified numbers (`time_interval=7`) or the strings as given (not trimmed).
- `numRetries: 0`: a 5xx, 429 or timeout is never retried (captured: one GET for 500, 503, 429, 400, 404, and for a hang).
- **Auth replay**: a 401 or a 403 (unless `x-opa-decision: false`) clears the token and the request is sent once more with a fresh token, also for `POST`/`PUT` (captured: `GET sessionschart->403, POST token, GET sessionschart->403`; `POST profile->401, POST token, POST profile->401`; same for 403).
- Per-attempt timeout `PANW_AI_SEC_TIMEOUT_MS ?? 60000` (`SDK:10095`); a timeout is an `AISecSDKException` without `statusCode` (captured with 1500 ms: one request, generic error).
- Response validation: zod schemas, passthrough, so unknown keys are kept; **output key order is the schema's declared order, then the unknown keys in server order** (captured: the stub sent `sessions_total, sessions_violated, sessions` and `pagination {total_items, skip, limit}`; the CLI printed `sessions, sessions_total, sessions_violated` and `{limit, skip, total_items}`). A body that fails the schema, or an empty body, is an `AISecSDKException` without status.
- **Schema defaults (G10)**: `SecurityProfileListResponseSchema.ai_profiles` defaults to `[]` and `CustomTopicListResponseSchema.custom_topics` to `[]` (`SDK:1981-1984`, `SDK:2027-2030`); `CustomTopicSchema.examples` defaults to `[]` (`SDK:2002-2014`). So a profile or topic list answered `{}` is an empty inventory, and a topic the server returned without `examples` gains `"examples": []` (§5.3, §6.3, §7.3). The dashboard schemas have no defaults (`SDK:2141-2310`); `CustomerAppListResponseSchema.customer_apps` is optional without a default (`SDK:2131-2134`).

### 2.3 Output format resolution

- The root `--output <format>` option consumes `--output` wherever it appears on the command line (commander: program options are recognised after subcommands); a leaf `--output` therefore never receives a value from the command line, and `resolveOutput` (`common.ts:48-75`) uses the root value (explicit) → the tenant `defaultOutput` → `pretty`. Verified by instrumenting commander: `[set airs-cli table cli] [src list undefined]`. A name outside `pretty, table, markdown, csv, json, yaml` is `Invalid output format '<x>'. Expected: pretty, table, markdown, csv, json, yaml` (exit 2); a name outside the command's `allowed` set is `Output format '<x>' is not supported here. Expected: <allowed>` (exit 2). Resolution **loads the tenant config** (for `defaultOutput`), so a broken config fails here.
- The root `preAction` hook (`prog.ts:162-175`) resolves the format a first time (all six names allowed) for commands named `list` or `get` with an `--output` option, i.e. `sessions list` and `sessions get` (and `report` is excluded, `prog.ts:163-165`). That resolution loads the config **before the action's argument checks**: with an invalid tenant config, `sessions list --limit 0` exits 1 with `\n  ✗ Error: Cannot read a valid tenant config at <path>\n\n` (the `fail` block, `common.ts:12-25`), while `sessions chart --interval 0` exits 2 with the argument error (captured).
- Allowed sets: dashboard and sessions `pretty, json, yaml` (`rd.ts:113-115`; `table`, `markdown`, `csv` exit 2); report `html`/`markdown` from its own check (§5.1), the tenant `defaultOutput` ignored; backup and restore all six (the backup summary maps `pretty` to `table`, `pt.ts:215`).
- A tenant `defaultOutput: "table"` makes every dashboard and sessions command a usage error (`Output format 'table' is not supported here. Expected: pretty, json, yaml`, exit 2, captured) unless `--output` is given; `runtime report` ignores it (captured: Markdown written with `defaultOutput: "table"` and `--output markdown`).

### 2.4 Streams, quiet and colour

- `ui.status(msg)` (`ui.ts:131-135`): stderr, `"  " + dim(msg)`, suppressed by `--quiet`. `ui.error(msg)` (`ui.ts:113-116`): stderr, `"  " + red("✗ " + msg)`, never suppressed. `ui.warning(msg)` (`ui.ts:100-103`): stderr, `"  " + yellow("⚠ " + msg)`, never suppressed. `ui.info(msg)` (`ui.ts:106-110`): **stdout**, `"  " + cyan("ℹ " + msg)`, suppressed by `--quiet`. `usageError(msg)` (`common.ts:27-30`): stderr `chalk.red("\n  ✗ " + msg + "\n")`, exit 2.
- Captured with `FORCE_COLOR=1`: status `  \e[2mReturned 1 of 3 sessions; this is one page.\e[22m\n`; usage error `\e[31m\e[39m\n\e[31m  ✗ --interval must be a safe integer >= 1\e[39m\n\e[31m\e[39m\n` (chalk closes and reopens per line). Data on stdout is never coloured.
- Colour is per process (chalk's stdout detection) for both streams; `FORCE_COLOR`/`NO_COLOR` apply.
- `--quiet` drops only status and info lines; data, warnings and errors remain (captured: `--quiet sessions list` prints the data and an empty stderr).

### 2.5 Debug log

- `--debug` creates `debug-api-<epoch ms>-<8 hex>.jsonl` (0600, `wx`) in the CWD and prints `  Debug: API log → <path>` (status) before the action (`prog.ts:176-192`); dashboard and sessions accept it (captured: empty file on loopback, §0).
- Bodies are omitted (`[BODY OMITTED]`) for URLs matching `/\/v1\/mgmt\/(dashboard\/|reports\/scancontent(?:\?|$))/` (`dbg.ts:166-169,217-224`); the URL, query included, is logged (only query keys matching the sensitive-key pattern are masked, `dbg.ts:65-79`), so `session_id`, `app_id`, `app_name`, `scan_id` reach the log. Management-plane bodies (profiles, topics, customer apps with `auth_code`) would be logged redacted by key.
- `runtime report` refuses `--debug`, and `PANW_AI_SEC_DEBUG` matching `^(1|true|yes|on)$` (trimmed, case-insensitive): `Disable --debug and PANW_AI_SEC_DEBUG for environment reports to avoid persisting sensitive traffic content` (exit 2, before the log is created, `prog.ts:139-151`). `runtime profiles backup|restore` refuse both: `Disable --debug and PANW_AI_SEC_DEBUG for profile transfer; backups can contain sensitive policy configuration` (exit 2, `prog.ts:128-138`). Captured for `--debug`, `PANW_AI_SEC_DEBUG=yes` and `=on`.

### 2.6 Errors and exit codes

- Commander errors (unknown option, missing option argument, missing required option such as `error: required option '--app-name <name>' not specified`) exit **1** (shell spec).
- `usageError` exits 2. Option parsers that call it (`--unit`, `--max-pages`) run at parse time, before `preAction` (so before the debug refusal, the config and the debug file).
- Dashboard and sessions: any non-usage failure (config, credentials, HTTP, timeout, schema, pagination, file) is the single line `  ✗ Dashboard operation failed (HTTP <s>). Check credentials, query options, and any output destination. No existing file is overwritten.` (` (HTTP <s>)` only when `statusCode` is 400–599), stderr, exit 1 (`rd.ts:144-151`). No server text, path or SDK message (captured for 400, 401, 403, 404, 429, 500, 503, schema, empty body, timeout, an existing `--output-file`, an invalid config).
- Report: every failure after the argument checks is `  ✗ Report generation failed. Verify Management API configuration and a writable, new output path. Existing files are never overwritten.` (exit 1, `rr.ts:78-84`).
- Profile transfer: `failure()` (`pt.ts:129-145`): `CliUsageError` → exit 2; `ZodError` → `Invalid profile backup/request schema; content is not logged.`; `AISecSDKException` → `Profile transfer API request failed (HTTP <s>); no automatic retry was made.` (status part only when present); an errno error → `Profile transfer file operation failed (<CODE>); existing files are not overwritten.`; anything else → **the error's message verbatim** (e.g. `No matching profiles to back up`, `Destination profile already exists: <name>; …`, `Cannot read a valid tenant config at <path>`); all `ui.error`, exit 1.

### 2.7 Interruption

No handler is installed (`src/cli/process-guards.ts` handles only unhandled rejections). SIGINT/SIGTERM end node at once: exit 130/143, nothing printed, also during a restore write (captured with a hung `POST /v1/mgmt/profile`: exit 130, empty stdout and stderr) and during report collection (captured: exit 143, only the `Collecting …` status line, no file and no temporary left; the temporary exists only between `open` and `unlink` in `writeReportFile`).

## 3. `runtime dashboard`

### 3.1 Option helpers (`rd.ts:16-93`)

- `integer(value, name, minimum = 0)`: `String(value)` must match `^\d+$` and be a safe integer `>= minimum`, else `<name> must be a safe integer >= <minimum>` (usage). Leading zeros are accepted (`--interval 01` sends `time_interval=1`, captured); `+1`, ` 1`, `1e3`, `1.5`, `-1`, `NaN`, `1oops` are rejected (captured).
- `text(value, name)`: a string that is non-blank after JavaScript `trim()`, else `<name> is required` (usage); the value is used **untrimmed** (captured: `--app-id ' '` → `--app-id is required`).
- `--unit <unit>` parser (`rd.ts:57-69`), at parse time: an exact, case-sensitive member of the command's unit list, else `Unsupported --unit. Supported units: <list joined ', '>. For one week, use --interval 7 --unit days.` (exit 2). Defaults are not passed through the parser. Captured rejections: `week`, `weeks`, `month(s)`, `year(s)`, `fortnight`, `DAY`, ` day `, and `hours` for `applications`, `day` for `application`.
- Units: `TIME_UNITS = hour, hours, day, days` (`rd.ts:14`); `applications` uses `day, days, hour`; `application` and `application-violations` use `days`.

### 3.2 Subcommands, checks and requests (captured)

Each action (`rd.ts:109-152`) runs: (1) the command's `prepare(opts)` checks below, (2) `resolveOutput` with `allowed: pretty, json, yaml` (loads the config), (3) for `scan-content` its destination checks (§4.5), (4) `loadConfig`, credentials, the client, (5) the single read, (6) the output.

| Command | Checks (in order) | SDK call | Request |
|---|---|---|---|
| `applications` | `integer(--interval, 1)`; `text(--unit)`; interval ∈ {1, 7, 30, 60} and unit ∈ {day, days, hour}, else `Application overview supports interval 1/7/30/60 and unit day/days/hour`; `integer(--limit, 1)`; `integer(--offset, 0)` | `applicationsOverview({timeInterval, timeUnit, limit, offset})` | `GET <dash>/v1/mgmt/dashboard/v2/apps/applicationsoverview?time_interval=1&time_unit=day&limit=25&offset=0` |
| `application` | `integer(--interval, 1)`; interval ∈ {7, 30, 60} and unit `days`, else `Application detail requires 7, 30, or 60 days`; `text(--app-id)`; `text(--app-name)` | `application({appId, appName, timeInterval, timeUnit:'days'})` | `GET …/apps/application?appid=<id>&appname=<name>&time_interval=30&time_unit=days` |
| `application-violations` | as `application` | `applicationViolationBreakdown(…)` | `GET …/apps/applicationviolationbreakdown?appid=…&appname=…&time_interval=30&time_unit=days` |
| `top-applications` | `integer(--interval, 1)`; `text(--unit)` | `topApplicationsViolations({timeInterval, timeUnit})` | `GET …/apps/topapplicationsviolations?time_interval=1&time_unit=day` |
| `violations-trend` | as `top-applications` | `applicationsViolationsTrend(…)` | `GET …/apps/applicationsviolationstrend?time_interval=1&time_unit=day` (captured `24`/`hours` passed through) |
| `apps-list` | as `top-applications` (defaults 30 / days) | `appsList(…)` | `GET …/apps/appslist?time_interval=30&time_unit=days` |

Notes:
- The interval/unit pair of `applications` is checked as two independent sets (`60 hour` is accepted). The SDK repeats the `applicationsOverview` checks only partly (no zod schema for it, `SDK:12632-12650`).
- The `application` query uses `appid`/`appname` (no underscore); sessions use `app_id`/`app_name` (§4).
- Response schemas (`SDK:2141-2232`): `applicationsOverview` requires `items: array` (`pagination` optional); `application` requires `token_stats` and `session_stats` keys (nullable); `applicationViolationBreakdown` requires `detection_type_violation_breakdown`; `topApplicationsViolations` requires `applications[]` with `id`, `name`, `policy_violations[{detection_type, total ≥0 int}]`, `total_violations`; `applicationsViolationsTrend` requires `violations[]` with `bucket_number`, `date`, `violation_breakdown`; `appsList` requires `applications[]` with `application_id`, `application_name` strings.

### 3.3 Output (captured)

- `pretty` and `json`: `JSON.stringify(result, null, 2)` plus `\n` on stdout (`rd.ts:136-143`) — the whole zod-parsed response envelope, no header, no banner, no status line. `pretty` is byte-identical to `json`.
- `yaml`: `js-yaml dump(result, {noRefs: true, lineWidth: -1}).trimEnd()` plus `\n` (default js-yaml schema: ISO strings quoted `'2026-10-19T00:22:40.943Z'`, numeric-looking strings quoted `'100'`, empty arrays `[]`).
- Example (`applications`, pretty):

```
{
  "items": [
    {
      "id": "app-1",
      "name": "Assistant & <b>",
      "cloud": "aws",
      "source": "api",
      "sessions": [
        {
          "bucket_number": 0,
          "date": "2026-10-19T00:22:40.943Z",
          "total": 40,
          "violated": 10
        }
      ],
      "sessions_total": 40,
      "sessions_violated": 10
    }
  ],
  "pagination": {
    "limit": 25,
    "skip": 0,
    "total_items": 1
  }
}
```

- Control characters: `JSON.stringify` escapes U+0000–U+001F (`\u001b`, `\u0007`) but prints C1 (U+0080–U+009F, e.g. CSI U+009B) and `Cf` (U+202E) raw; YAML escapes C0 and C1 (`"\e[31m"`, `"a\x9B31m"`, `"\a"`) but prints `Cf` raw (captured with `application_id: "a\u009b31m"`, `application_name: "b‮c\u0007"`).

## 4. `runtime sessions`

All sessions commands share §3.1–§3.3 (output, errors, units `hour, hours, day, days`).

### 4.1 `sessions chart`

Checks `integer(--interval, 1)`, `text(--unit)`; `sessionsChart({timeInterval, timeUnit})` → `GET <dash>/v1/mgmt/dashboard/v2/sessions/sessionschart?time_interval=1&time_unit=day`. Schema: `bucket_size_seconds > 0`, `buckets[]` with `bucket_number`, `time`, `total`, `violating` (non-negative ints), `detection_type_violation_breakdown[]`, `violation_breakdown` (`SDK:2236-2247`). Output: the envelope.

### 4.2 `sessions list|ls` (`rd.ts:224-300`)

- Checks: `integer(--interval, 1)`, `text(--unit)`, `integer(--limit, 1)`, `integer(--offset, 0)`, `integer(--max, 0)` (`--max` checked even without `--all`). These run after the `preAction` format resolution (§2.3).
- Request: `GET …/sessions/sessionsoverview?time_interval=<i>&time_unit=<u>&limit=<l>&offset=<o>` (`SDK:12506-12514`). Schema: `items[]` (each `application_id`, `application_name`, `session_id`, `violation_status` strings, `violation_breakdown`, `detection_type_violation_breakdown[]`, optional nullable `last_session_activity`; the item schema is passthrough, so any extra server field — captured `prompt` — is printed) and a required `pagination` object (`limit`, `skip`, `total_items` all optional numbers).
- **Without `--all`**: one request; status `Returned <n> of <total_items ?? 'unknown'> sessions; this is one page.`; stdout the **bare `items` array** (not the envelope; JSON/YAML of an array). Exit 0.
- **With `--all`** (at most 100 pages, `offset` starting at `--offset`), per page in this order:
  1. Fail `Unstable pagination` unless `total_items` is a safe integer ≥ 0, `pagination.skip === offset`, `pagination.limit === --limit`, `items.length <= --limit`, and `total_items` equals the first page's.
  2. Each item's identity `JSON.stringify([application_id, application_name, session_id])` must be new, else `Overlapping session pages`.
  3. `offset += items.length`; fail `Incomplete inventory` if `offset > total` or (`items` empty and `offset < total`).
  4. If `--max > 0` and collected `> --max`: status `Session item cap reached; output is partial.`, exit code 1, print the first `--max` items.
  5. If `offset === total`: status `Retrieved <n> sessions from offset <--offset>; pagination complete.`, print all, exit 0.
  6. If `--max > 0` and collected `=== --max`: the cap status, exit 1, print.
  After 100 pages: `Session page cap reached; output is partial.`, exit 1, print. A thrown failure prints nothing on stdout and the generic dashboard error (exit 1).
- Captured: `--limit 2` over 3 sessions: requests at offsets 0, 2; `Retrieved 3 sessions from offset 0; pagination complete.`; `--all --limit 2 --max 1`: one request, one item printed, exit 1; `--all --limit 2 --offset 1`: offsets 1 (two items) → complete; a total of 5 with 3 records: offsets 0, 2, 3 → `Dashboard operation failed. …`, no stdout, exit 1.

### 4.3 `sessions get`

Checks: `text(--session-id)`, `text(--app-id)`, `text(--app-name)`, `integer(--interval, 1)`, `text(--unit)`, `integer(--limit, 1)`, `integer(--offset, 0)` (after the `preAction` resolution). Request `GET …/sessions/session?session_id=<s>&app_id=<a>&app_name=<n>&offset=0&limit=25&time_interval=30&time_unit=days` (`SDK:12515-12526`, captured order). Schema: `application {id, name}`, `id`, `session_actions[]` (each `application_id`, `application_name`, `session_id`, `scan_id`, `scan_sub_req_id` ≥0 int, breakdowns; optional `transaction_id`, `status`, `start_time`, `profile_name`, `kind[]`, `correlation_type`, `enable_full_conversation_inspection`), `pagination`, optional times and `violation_status`. Output: the envelope (one page of actions; no walk).

### 4.4 `sessions transaction`

Checks: `text(--session-id)`, `text(--app-id)`, `text(--app-name)`, `integer(--interval, 1)`, `text(--unit)`, `text(--scan-id)`, `integer(--scan-sub-req-id, 0)` (zero valid). Request `GET …/sessions/sessiontransaction?session_id=…&app_id=…&app_name=…&scan_id=…&scan_sub_req_id=0&time_interval=30&time_unit=days`. Schema: the action fields plus optional `ai_traffic_latency_ms`, `attributes {environment, model_name, profile, text_records, user_id, user_ip}`, `end_time`, `timeout`, `tokens` (`SDK:2287-2301`). Output: the envelope, **including `attributes.user_id` and `attributes.user_ip`** (captured).

### 4.5 `sessions scan-content` (`rd.ts:116-143,313-325`)

- Order: `text(--scan-id)`, `integer(--scan-sub-req-id, 0)`; `resolveOutput` (config); exactly one of `--show-content` and `--output-file`, else `Scan content requires exactly one of --show-content or --output-file <new-path>` (exit 2, both or neither); with `--output-file`: `text(--output-file)` (blank → `--output-file is required`, exit 2), `resolve()` it, `lstat`: anything there (a file, a symlink, dangling or not) → `Error('Destination exists')` → the generic dashboard error (exit 1) **before the tenant and any request** (captured: second run, no request). A missing parent directory is not checked first: the content is fetched, then `writeReportFile` fails `ENOENT` → generic error, exit 1 (captured: the GET was sent, no file).
- Request `GET <dash>/v1/mgmt/reports/scancontent?scan_id=<id>&scan_sub_req_id=<n>` (captured `scan_id=s+c&scan_sub_req_id=7` for `'s c'`/`007`). Schema: `report_id`, `scan_id`, `sub_scan_req_id` (≥0 int), `transaction_id`, `scan_contents` (nullable, `{prompt?, response?}` nullable strings, passthrough).
- `--show-content`: the envelope on stdout in the resolved format, prompts and responses included (captured `"prompt": "PRIVATE-PROMPT \u001b[31mred"`; YAML `"PRIVATE-PROMPT \e[31mred"`).
- `--output-file <path>`: `writeReportFile(path, output + "\n")` (§5.6: 0600, exclusive, hard-link publish); the file holds JSON for `pretty`/`json` and YAML for `yaml` regardless of the file name; stdout empty; status `Scan content exported to the requested private file (0600).` (the path is not printed). Captured: a 206-byte JSON file, mode `-rw-------`.

## 5. `runtime report` (`rr.ts`, `rep.ts`, `ren.ts`, `io.ts`)

### 5.1 Argument checks (exit 2, in this order, before the tenant)

0. Parse time: commander errors (`--title` without a value: `error: option '--title <text>' argument missing`, exit 1).
1. `preAction`: the `--debug`/`PANW_AI_SEC_DEBUG` refusal (§2.5). The `report` command is excluded from the `preAction` format resolution (`prog.ts:163`).
2. Format: `opts.output ?? root --output ?? 'html'` (`rr.ts:36`; the leaf never gets a value, §2.3, so this is the root value) must be `html` or `markdown`, else `Report output must be html or markdown` (captured for `--output json` and `--output json` before the subcommand). The tenant `defaultOutput` is ignored.
3. `--max-pages`: matches `^[1-9]\d*$`, safe integer, `<= 100`, else `--max-pages must be an integer from 1 to 100` (captured: `0`, `1.5`, `101`, `07`).
4. `--title`: a string, non-blank after `trim()`, `length <= 240` UTF-16 units, else `--title must contain 1–240 characters` (captured for `241` × `x`; `''`).
5. `--output-file` given and blank after `trim()`: `--output-file cannot be empty`.

### 5.2 Destination

- `--output-file -` → stdout. Else `resolve(--output-file ?? defaultName)` where `defaultName = airs-runtime-report-<new Date().toISOString() with ':' → '-'>-<first 8 chars of randomUUID()>.<html|md>` (`rr.ts:46`; the `.` and `Z` stay: `airs-runtime-report-2026-10-19T00-25-00.457Z-4a264ab8.html`, captured).
- Before the tenant: `lstat(outputPath)`; anything there (file, symlink to a credential file, dangling symlink) → `Error('Output already exists')` → the generic report failure (exit 1, no request, the existing file unchanged; captured for a regular file and a symlink). Other `lstat` errors also fail generically. The parent directory is not checked first (captured: `missing/x.html` ran all eight requests, then failed).

### 5.3 Collection (`collectRuntimeDailyReport`, `rep.ts:135-301`)

After `loadConfig`, the credentials and the client, status `Collecting daily runtime activity and current configuration (read-only)...`. `now = new Date()`; `end = now.toISOString()`, `start = end − 86 400 000 ms`. Seven sources run **in parallel** (`Promise.all`), each through `collect()` (`rep.ts:53-95`). Captured request set (one token, then):

| # | Source name | `method` label | window label | Request | Page rule | Identity |
|---|---|---|---|---|---|---|
| 1 | `Daily application activity` | `dashboard.applicationsOverview` | `Rolling 1 day` | `GET <dash>/…/apps/applicationsoverview?time_interval=1&time_unit=day&limit=100&offset=<o>` | if `pagination.total_items` is a valid count: fail if it changed between pages (`Application total changed during pagination; retry for a stable inventory.`), if `offset + size > total` (`Application records exceed the advertised total.`), if `total > offset + size` and size 0 (`The API returned an empty page before its advertised total.`); next = `offset + size` while `< total`; without a count, next when the page has 100 items | `[id, name]` |
| 2 | `Security profiles` | `profiles.list (latest=true)` | `Current configuration` | `GET <mgmt>/v1/mgmt/profiles/tsg/<tsg>?offset=<o>&limit=100&latest=true` | `inventoryNext`: `next_offset === 0` ends; absent with a full page (100) probes `offset + size`; else `next_offset` | `[profile_name, revision]` |
| 3 | `Registered applications` | `customerApps.list` | `Current configuration` | `GET <mgmt>/v1/mgmt/customerapp/tsg/<tsg>?offset=<o>&limit=100` | as 2 | `customer_appId` |
| 4 | `Daily session inventory` | `dashboard.sessionsOverview` | `Rolling 1 day` | `GET <dash>/…/sessions/sessionsoverview?time_interval=1&time_unit=day&limit=25&offset=<o>` | fail `Missing or mismatched session pagination metadata.` unless `total_items` valid, `skip === offset`, `limit === 25`; `Session total changed during pagination; retry for a stable inventory.`; `Session page does not agree with its advertised total.` if `offset + size > total`, `size > 25`, or size 0 before the total; next while `< total` | `[application_id, application_name, session_id]` |
| 5 | `Daily session chart` | `dashboard.sessionsChart` | `Rolling 1 day` | `GET <dash>/…/sessions/sessionschart?time_interval=1&time_unit=day` | one page (`buckets`) | `bucket_number` |
| 6 | `Top application violations` | `dashboard.topApplicationsViolations` | `Rolling 1 day; server-ranked subset` | `GET <dash>/…/apps/topapplicationsviolations?time_interval=1&time_unit=day` | one page (`applications`) | `[id, name]` |
| 7 | `Daily violation trend` | `dashboard.applicationsViolationsTrend` | `Rolling 1 day` | `GET <dash>/…/apps/applicationsviolationstrend?time_interval=1&time_unit=day` | one page (`violations`) | `bucket_number` |

`collect()` rules (status starts `unavailable`, `records`, `pages`, `notes`):
- After each response `pages++`. Not an array → `The API returned no record array. An empty object or absent collection does not establish zero activity.` (thrown as a data error).
- Records are kept in a map by identity; `records` = map size. If a page added fewer records than its length: note `Overlapping or repeated records detected; duplicates excluded.`, status `partial`.
- No next → status `complete` (unless already `partial`). A next that is not a safe integer, `<= offset`, or a page that added nothing → note `Pagination did not advance; collection stopped safely.`, `partial`. `--max-pages` reached → `Reached the <n>-page budget; this is not a complete inventory.`, `partial` (paged sources 1–4; 5–7 always budget 1).
- A thrown error → status `partial` if `pages > 0` and `records > 0`, else `unavailable`; note `safeFailure(error)`: a data error's own message; HTTP 401/403 → `HTTP <s>: check Management API credentials and grants.`; 429 → `HTTP 429: rate limited; retry the report later.`; other 400–599 → `HTTP <s>: source request failed; verify service availability and API compatibility.`; anything else (timeout, schema) → `Source request or response validation failed; check connectivity and SDK compatibility.` No server text.
- Schema defaults: a profiles answer `{}` is a **complete empty inventory** (`ai_profiles` default `[]`), which produces the `No security profiles returned` attention finding (captured: `Security profiles — … | complete | 0 | 1 | Collection completed.` and `### ATTENTION: No security profiles returned`); a customer-apps answer `{}` is `unavailable` with the no-record-array note (captured). A sessions-overview `{}` fails the SDK schema (generic validation note), not the no-record-array note.

### 5.4 Analysis (`rep.ts:303-604`)

- `label(v)`: `\p{Cc}` and `\p{Cf}` → space, `trim()`, empty or null → `Unknown`, then the first 240 UTF-16 units. `count(v)`: a safe integer ≥ 0, else `null`. `total(values)`: `null` if any is `null`, else the sum through `count` (an unsafe sum → `null`).
- Findings are added in this order and then stably sorted `attention` < `review` < `info` (no `info` finding exists):
  1. For each source not `complete`, `review`: title `<name>: <status>`; evidence the notes joined by a space; recommendation `Restore access or retry collection; do not treat missing data as zero. Increase --max-pages if the page budget was reached.`; source `<name>`.
  2. Applications: `{name: label(name), sessions: count(sessions_total), violatingSessions: count(sessions_violated), registered}` where `registered` is `true` if `id` is a registered `customer_appId`, else `false` if the apps source is `complete` and `id` is set, else `null`; sorted by violating desc (`null` as −1) then `localeCompare` of names. `sessions`/`violatingSessions` totals are `null` when source 1 is `unavailable`. `inconsistent` = any app with violating > sessions. If inconsistent or any counter `null`: `review` `Activity counters need verification` / `Some application counters are absent, invalid, or report more violating sessions than total sessions.` / `Compare these buckets with the SCM dashboard. A violation rate is withheld when counters are inconsistent.`
  3. Violating total > 0: `attention` `Violating sessions observed` / `<v> violating sessions across <k> application buckets in the collected daily data.` / `Review the highest-volume applications in SCM, confirm intended enforcement, and investigate unexpected activity. Violations are not proof of a successful attack.`
  4. Sessions total `=== 0` and source 1 complete: `review` `No sessions reported in the daily window` / `The complete application overview reports zero sessions.` / `If traffic was expected, check the integration, application metadata, and telemetry ingestion. No activity is not proof of health.`
  5. Profiles: latest revision per name (`revision ?? -1`); per profile `configs` = the `model-configuration` objects; `timeoutActions` = unique `label(latency['inline-timeout-action'])` (a config without it contributes `Unknown`); `active === false` → `review` `Inactive profile: <name>` / `The latest returned revision is explicitly inactive.` / `Confirm this is intentional before assigning the profile to an integration.`; active and any timeout action `allow` (case-insensitive) → `review` `Timeout allows traffic: <name>` / `An active profile explicitly sets inline-timeout-action to allow.` / `Review the availability-versus-enforcement tradeoff with the application owner; this is not evidence of a timeout or bypass.`; `storageMasking` = `Off in at least one configuration` if any `mask-data-in-storage === false`, `On in all returned configurations` if all true and non-empty, else `Unknown`; active and any false → `review` `Storage masking disabled: <name>` / `An active profile explicitly disables mask-data-in-storage in a model configuration.` / `Confirm retention and privacy requirements. This flag alone does not establish that sensitive data was stored.`; `modified` = ISO of `last_modified_ts` when `Date.parse` is finite, else `null`. Sorted by name. Empty and source 2 complete → `attention` `No security profiles returned` / `The current profile inventory is empty.` / `Verify tenant scope and configure a security profile before routing application scans.`
  6. Sessions: rows whose `Date.parse(last_session_activity)` is not finite count as `missingTimestamps`; outside the half-open `[start, end)` as `outsideWindow`; either > 0 → `review` `Some session records excluded from daily analysis` / `<m> records lack a valid last-activity timestamp; <o> fall outside the anchored UTC window.` / `Verify ingestion timestamps and collection-window drift before using session counts as daily totals.` Eligible rows with `violation_status` (trimmed, lowercased) in `failed`, `error`, `timeout` → `attention` `Session processing failures observed` / `<n> timestamp-eligible collected sessions explicitly report failed, error, or timeout status.` / `Review these sessions in SCM and check integration error handling. This is not a tenant-wide failure rate.`
  7. Chart totals (`null` when source 5 `unavailable`); when chart sessions ≠ the raw session inventory length and source 4 is complete → `review` `Session sources disagree` / `The chart reports <c> sessions; the independently paginated inventory returned <r>.` / `Preserve both measurements and verify in SCM. Separate rolling queries are not a consistent snapshot; the discrepancy has no verified cause.` (source `Daily session chart`).
  8. Trend critical + high > 0 → `attention` `High or critical detector violations observed` / `<n> high/critical detector violations in the returned daily trend. These are not distinct sessions.` / `Investigate the affected applications and confirm enforcement decisions before assigning incident severity.`
- `health`: `unknown` if every source is `unavailable`; else `attention` if any attention finding; else `review` if any review finding; else `no-findings`.
- The model (`typ.ts:122-144`): `schemaVersion: 2`, `product: 'Prisma AIRS AI Runtime Security'`, `title: label(--title)`, `generatedAt` (a second `now()`), `collectionStartedAt: end`, `window {start, end, description: 'Rolling last 24 hours, UTC (approximate for server-relative application queries)'}`, `health`, `sources`, `findings`, `activity {sessions, violatingSessions, violationRate (percent, null unless consistent and sessions > 0), applications}`, `profiles`, `registeredApps` (`label` of `app_name`, `environment`, `cloud_provider`, `model_name`; `keyAssociations` = `api_keys_dp_info.length` or `null`; sorted by name), `sessions {entries, statuses (label(violation_status).toLowerCase() counts, desc), violatingSessions (status exactly 'violated'), missingTimestamps, outsideWindow}`, `dailyTelemetry {chart {sessions, violatingSessions, buckets[{time, sessions, violatingSessions, violations}]}, topApplications[{name, violations, detectors[{name, count}]}], violationTrend[{time, violations}]}`, and eight fixed `limitations` (`rep.ts:594-603`, quoted verbatim in §5.5's capture). No ids, tenant ids, session ids, prompts, users, key names or auth codes (TS unit test).

### 5.5 Rendering

Shared (`ren.ts:4-173`): `HEALTH` labels `attention` → `Attention required`, `review` → `Review required`, `no-findings` → `No findings in available evidence`, `unknown` → `Unable to assess`. `number(v)`: `null` → `Unknown`, else `v.toLocaleString('en-US', {maximumFractionDigits: 2})` (thousands separators, `33.33`). Eight tables in this order (`ren.ts:38-156`), each `{title, id, headers, rows, note}`:

1. `Daily application activity` (`applications`): `Application bucket | Sessions | Violating sessions | Violation rate | Registered ID match`; rate `<number(v/s*100)>%` only when `s > 0` and `v <= s`, else `Unknown`; match `Unknown`/`Yes`/`Not in returned inventory`.
2. `Current security profiles` (`profiles`): `Profile | Revision | Active | Timeout action | Storage masking | Last modified (UTC)`; active `Unknown`/`Yes`/`No`; timeout actions joined `, ` or `Unknown`; modified raw (`null` → `Unknown` by the escaper).
3. `Registered application inventory` (`inventory`): `Application | Environment | Cloud | Model | Key associations`.
4. `Collected session observations` (`sessions`): `Session status | Entries`; note `Source: <status of 'Daily session inventory' ?? 'unavailable'>. Timestamp-eligible entries: <n>. Violated status: <n>. Missing timestamps: <m>; outside window: <o>. These are collected session counts, not scan actions or detector events. No scan content is fetched.`
5. `Daily session chart` (`session-chart`): `Bucket time (UTC) | Sessions | Violating sessions | Detector violations`; note `Independent chart totals: <s> sessions; <v> violating sessions. Do not force these counters to equal a separately paginated inventory.`
6. `Top applications by detector violations` (`top-violations`): `Application bucket | Detector violations | Detection types` (`<name>: <count>` joined `, `).
7. `Daily detector severity trend` (`violation-trend`): `Bucket time (UTC) | Critical | High | Medium | Low | Total`.
8. `Evidence and collection coverage` (`evidence`): `Source / SDK method | Window | Status | Records | Pages | Collection notes`; `<name> — <method>`; pages unformatted; notes joined by a space or `Collection completed.`

Metrics (`ren.ts:158-173`): `Sessions in collected app buckets`, `Violating sessions`, `Violation rate` (`<n>%` or `Unknown`), `Complete evidence sources` (`<complete> / 7`).

**Markdown** (`renderRuntimeReportMarkdown`, `ren.ts:176-235`): every dynamic value through `md()`: each of `& < > " ' \ ` * _ [ ] { } ( ) | ! # ~` becomes `&#<decimal>;`, CR and LF become a space; table headers, `HEALTH`, metric names and metric values are not escaped (static or numeric). Lines joined with `\n`, ending with `Generated by Prisma AIRS CLI · Report schema 2` and one `\n`. Captured (TS 7.2.1, fixture of §0, `--title 'T <x> | y'`, abridged at `…`):

```
# T &#60;x&#62; &#124; y

**Prisma AIRS AI Runtime Security**

Assessment: **Attention required**

Window: 2026-10-18T00:25:07.230Z → 2026-10-19T00:25:07.230Z

Rolling last 24 hours, UTC &#40;approximate for server-relative application queries&#41;. Collection: 2026-10-19T00:25:07.230Z → 2026-10-19T00:25:07.254Z.

## At a glance

- Sessions in collected app buckets: **40**
- Violating sessions: **10**
- Violation rate: **25%**
- Complete evidence sources: **7 / 7**

## What needs attention

### ATTENTION: Violating sessions observed

Evidence: 10 violating sessions across 1 application buckets in the collected daily data.

Next step: Review the highest-volume applications in SCM, confirm intended enforcement, and investigate unexpected activity. Violations are not proof of a successful attack.

Source: Daily application activity

…
## Daily application activity

API-reported rolling one-day application buckets, ranked by violating sessions. Partial-source totals cover collected buckets only. Violating sessions are not necessarily blocked sessions.

| Application bucket | Sessions | Violating sessions | Violation rate | Registered ID match |
| --- | --- | --- | --- | --- |
| Assistant &#38; &#60;b&#62; | 40 | 10 | 25% | Yes |
…
| Security profiles — profiles.list &#40;latest=true&#41; | Current configuration | complete | 3 | 1 | Collection completed. |
…
## Scope, privacy, and limitations

- This is a read-only operational review, not an uptime SLA, compliance attestation, or proof that attacks succeeded or were blocked. No health score is invented.
…
- Application buckets are keyed by registered application ID plus the literal scan metadata.app&#95;name, which can differ from registered names. Do not sum session counts as unique users or unique tenant-wide sessions.
…

Generated by Prisma AIRS CLI · Report schema 2
```

No findings: `No findings in the available evidence. This does not establish an absence of risk.`; an empty table: `No rows available. Consult the source status before interpreting this as an empty result.`

**HTML** (`renderRuntimeReportHtml`, `ren.ts:237-290`): one self-contained document; `html()` escapes `& < > " '` to `&amp; &lt; &gt; &quot; &#39;` (`null` → `Unknown`); table titles, ids, headers and metric names are static and inserted raw; API strings are never put into script or an attribute (the only dynamic attribute is `data-priority`, a fixed enum). Structure (captured, 17 419 bytes for the fixture):
- `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="<CSP escaped>"><meta name="referrer" content="no-referrer"><title><title> — Prisma AIRS</title><style><CSS></style></head>\n`
- **CSP**: `default-src 'none'; script-src 'sha256-<b64 SHA-256 of JS>'; style-src 'sha256-<b64 SHA-256 of CSS>'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'` with `'` escaped as `&#39;`. Captured hashes (the inline assets are static, `ren.ts:237-263`): script `sha256-5LxzE6qTHVB6GkFp5aSlfgYy4D1HefDNuhJF25u8bAE=`, style `sha256-VLFdq2Qs156m0R7mhD0UAHR12n5y2Ki6ghMmFhbLmow=`.
- `<body class="<health>"><a class="skip" href="#main">Skip to report</a><header><div class="eyebrow">Prisma AIRS · AI Runtime Security</div><h1><title></h1><span class="badge"><HEALTH></span><p><window description><br><time><start></time> → <time><end></time></p><p>Collected <collectionStartedAt> → <generatedAt><br>Read-only evidence · Confidential environment metadata</p></header>\n`
- `<main id="main"><nav aria-label="Report sections">` with links `#findings Attention`, `#applications Activity`, `#profiles Profiles`, `#inventory Inventory`, `#evidence Evidence`, `#scope Scope`, then `</nav>\n<div class="cards">` with one `<div class="card"><span><name></span><strong><value></strong></div>` per metric, `</div>\n`.
- `<section id="findings">` with the heading `What needs attention`, note `Observed violations and configuration review items, not a numerical health score. Collection gaps remain visible in the evidence table.`, the priority filter toolbar (`All findings`, `Attention`, `Review`, `Information`), the `Print / save PDF` button, then one `<article class="finding" data-priority="<p>"><span class="priority"><p></span><h3><title></h3><p><strong>Evidence:</strong> …</p><p><strong>Next step:</strong> …</p><p class="note">Source: …</p></article>` per finding, or the no-findings sentence.
- Then each table as `<section id="<id>" aria-labelledby="<id>-title"><h2 id="<id>-title"><title></h2><p class="note"><note></p>` (the `applications` section adds the search toolbar), and `<div class="table-wrap" role="region" aria-label="<title>" tabindex="0"><table><caption><n> collected rows</caption><thead><tr><th scope="col">…</th>…</tr></thead><tbody><tr><td>…</td>…</tr>…</tbody></table></div>` or `<p>No rows available. …</p>`; then `<section id="scope"><h2>Scope, privacy, and limitations</h2><ul><li>…</li>…</ul></section><footer>Generated by Prisma AIRS CLI · Report schema 2 · Self-contained HTML; no network access required. All evidence remains readable with JavaScript disabled.</footer></main><script><JS></script></body></html>\n`.

### 5.6 Publishing and exit (`rr.ts:64-77`, `io.ts:6-19`)

- stdout: one `process.stdout.write(rendered)` awaited; a stream error → the generic failure, exit 1 (TS test).
- File: `writeReportFile(path, content)`: `open(<dir>/.airs-report-<uuid>.tmp, 'wx', 0o600)`, write UTF-8, `fsync`, close, `link(temp, path)` (fails `EEXIST` on anything at `path`, symlinks included, and gives exactly one winner between concurrent writers), then `unlink(temp)` in `finally` (also after a failure). No directory fsync. Then status `Report → <path with \p{Cc}\p{Cf} → '_'> (mode 0600)`.
- Then, when any source is not `complete`: status `<n> source(s) incomplete; review the evidence section.` (also for stdout delivery).
- Exit 1 when `health === 'unknown'` (the file is still written) or `--strict` and a source is incomplete; else 0. Captured: one unavailable source → exit 0, `--strict` → 1; every source 403 → `Assessment: **Unable to assess**`, seven `HTTP 403: check Management API credentials and grants.` notes, `7 source(s) incomplete; …`, exit 1, and each read replayed once after the 403 (§2.2).

## 6. `runtime profiles backup [profile]` (`pt.ts:148-221`, `rp.ts:1-177`)

### 6.1 Checks (captured order)

1. Parse time: `--max-pages` parser (`pt.ts:94-98`): `^\d+$` and 1–1000, else `--max-pages must be an integer from 1 to 1000` (exit 2; `0`, `1001`, `abc`, `1e2`).
2. `preAction`: the debug refusal (§2.5).
3. A selector with `--all`: `Choose either a profile selector or --all` (exit 2).
4. `--file-format` exactly `json` or `yaml` (case-sensitive): `--file-format must be json or yaml` (exit 2; `exe`, `YAML`).
5. `resolveOutput` (all six formats; loads the config: an invalid config is `  ✗ Cannot read a valid tenant config at <path>` via `failure`, exit 1).
6. `--output-file -`: `Backups require a private file destination, not stdout` (exit 2).
7. `path = resolve(--output-file ?? 'airs-runtime-profiles-backup-<ISO with [:.] → '-'>-<8 of randomUUID>.<json|yaml>')` (captured `airs-runtime-profiles-backup-2026-10-19T00-25-46-303Z-9c2e4151.json`); `extname(path).toLowerCase()` must be `.json` for json, `.yaml`/`.yml` for yaml, else `Backup filename extension must match --file-format` (exit 2).
8. `context()`: the tenant, the TSG/ID/secret check (exit 2), the credentials, the client.
9. The reads (§6.2). **The output path is not checked before the reads**: an existing file or symlink fails only at the write, after every inventory (captured: `EEXIST` after the profile and topic reads, `Profile transfer file operation failed (EEXIST); existing files are not overwritten.`); a missing directory likewise (`ENOENT`).

### 6.2 Requests and selection (captured)

- Profile inventory (`offsetPages`, `rp.ts:44-61`): `GET <mgmt>/v1/mgmt/profiles/tsg/<tsg>?offset=<o>&limit=100&latest=true` from offset 0, at most `--max-pages` pages; more than 10 000 items → `Inventory exceeds the 10000-record safety limit`; `next_offset` absent or `0` ends; a page with no items, a non-safe-integer next or `next <= offset` → `Inventory pagination did not advance`; the budget → `Inventory is incomplete: increase --max-pages before exporting or restoring`. All exit 1 (`failure` prints the message).
- `latestProfiles` (`rp.ts:64-87`): every name must be non-blank and free of U+0000–U+001F and U+007F (`Profile/topic names must be nonempty and contain no control characters`; C1 and `Cf` pass); a repeated `[profile_name, profile_id, revision]` → `Inventory contains repeated profile records`; one name with two `profile_id`s → `Ambiguous profile name: <name>` (raw); the highest `revision ?? 0` per name; sorted by `localeCompare`.
- `assertTenant`: any `tsg_id` that is set and not the tenant's `mgmtTsgId` → `Destination/source profile tenant identity does not match the selected TSG`.
- Selector: `profile_id === sel || profile_name === sel` (no selector: all); none → `No matching profiles to back up`; more than one → `Ambiguous profile selector`.
- Each selected profile needs a `policy` (`Profile has no policy: <name>`) that passes `PolicySchema` (else the zod line).
- Topic references (`rp.ts:110-132`): every object anywhere in the policy with a `topic_id` key must have string `topic_id`, string `topic_name` and a safe integer `revision >= 0` (`Invalid topic identity in profile policy`). Only when there is at least one reference: the topic inventory `GET <mgmt>/v1/mgmt/topics/tsg/<tsg>?offset=<o>&limit=100` (same walk; no `latest`). Each reference needs exactly one topic with the same `[topic_id, revision]` and the same `topic_name`, else `Cannot export the exact referenced topic revision: <name> revision <rev>`. Topics are deduplicated by key, in reference order.

### 6.3 File format (TS, captured)

`RuntimeProfilesBackupSchema` (`rp.ts:20-29`, strict at the top and in `source`):

```json
{
  "version": 1,
  "resourceType": "runtime-security-profiles",
  "exportedAt": "2026-10-19T00:25:46.324Z",
  "source": {
    "tsgId": "100"
  },
  "profiles": [
    {
      "profile_id": "22222222-2222-4222-8222-000000000001",
      "profile_name": "Production",
      "tsg_id": "100",
      "revision": 2,
      "active": true,
      "policy": {
        "ai-security-profiles": [
          {
            "model-type": "default",
            "model-configuration": {
              "mask-data-in-storage": true,
              "latency": {
                "inline-timeout-action": "block"
              },
              "model-protection": [
                {
                  "name": "topic-guardrails",
                  "action": "",
                  "topic-list": [
                    {
                      "action": "block",
                      "topic": [
                        {
                          "topic_name": "Restricted",
                          "topic_id": "11111111-1111-4111-8111-000000000001",
                          "revision": 3
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ],
        "dlp-data-profiles": []
      },
      "created_by": "PRIVATE-USER@example.test",
      "last_modified_ts": "2026-10-01T00:00:00Z"
    }
  ],
  "topics": [
    {
      "topic_id": "11111111-1111-4111-8111-000000000001",
      "topic_name": "Restricted",
      "revision": 3,
      "active": true,
      "description": "Restricted business topics",
      "examples": [
        "Synthetic example"
      ]
    }
  ]
}
```

- Profiles and topics are the SDK-parsed objects: every key the server sent is kept (passthrough, including `created_by`, `updated_by`, `csp_id`, `last_modified_ts` and unknown policy keys), in schema order then server order (the stub sent `topic_id, topic_name, revision`; the file has `topic_name, topic_id, revision`). A topic the server returned without `examples` is written with `"examples": []` (G10, §2.2).
- `version` literal `1`, `resourceType` literal, `exportedAt` an ISO date-time with offset, `source` exactly `{tsgId}` (non-empty), `profiles` 1–10 000, `topics` ≤ 10 000.
- JSON: `JSON.stringify(data, null, 2) + "\n"`. YAML: `dump(data, {schema: JSON_SCHEMA, noRefs: true, lineWidth: -1})` (captured: `tsgId: '100'`, `action: ''`, unquoted `exportedAt: 2026-10-19T00:25:54.990Z`).
- Size: over 20 MiB (`Buffer.byteLength`) → `Backup exceeds the 20 MiB size limit; select individual profiles` (exit 1, no file).
- Written with `writeReportFile` (§5.6): 0600, exclusive, never overwritten, no symlink followed (captured `-rw-------`).

### 6.4 Summary (stdout, captured)

`formatOutput([{file, sourceTsgId, profiles, topics}], [Backup file, Source TSG, Profiles, Topics], pretty ? 'table' : format)` (`pt.ts:199-217`). No status line. The absolute path is printed raw.

```
 Backup file                     │ Source TSG │ Profiles │ Topics 
─────────────────────────────────┼────────────┼──────────┼────────
 /<sandbox>/cwd/s-table.json     │ 100        │ 1        │ 0      
```

(column width = the longest cell; one leading and one trailing space per cell; `│` between cells; `─` × (width + 2) joined by `┼`; not indented.) `json`: `[\n  {\n    "file": "<abs>",\n    "sourceTsgId": "100",\n    "profiles": 1,\n    "topics": 0\n  }\n]`; `yaml`: `- file: <abs>\n  sourceTsgId: '100'\n  profiles: 1\n  topics: 0`; `csv`: `Backup file,Source TSG,Profiles,Topics\n<abs>,100,1,0`; `markdown`: `| Backup file | Source TSG | Profiles | Topics |\n| --- | --- | --- | --- |\n| <abs> | 100 | 1 | 0 |`.

### 6.5 Failures (captured)

Profiles list 500 → `Profile transfer API request failed (HTTP 500); no automatic retry was made.`; a schema-invalid list (`{"ai_profiles":"x"}`) or a topic-list timeout → `Profile transfer API request failed; no automatic retry was made.`; token 401 → `(HTTP 401)`. All exit 1, no file.

## 7. `runtime profiles restore <file>` (`pt.ts:223-357`, `rp.ts:179-749`, `pol.ts`)

### 7.1 Checks (captured order)

1. Parse time: `--max-pages` (as §6.1); `--dlp-map` collects repeated values.
2. `preAction`: the debug refusal.
3. `--on-conflict` ∈ `error, skip, update, verify`: `--on-conflict must be error, verify, skip or update` (exit 2).
4. `--on-missing-dlp` ∈ `error, basic`: `--on-missing-dlp must be error or basic` (exit 2).
5. `--force` without `--expect-tsg`: `--force requires --expect-tsg <destination-tsg>` (exit 2). (`--dry-run --force --expect-tsg` is accepted.)
6. `--dlp-map`: each `source=destination` split at the first `=` with both sides non-empty (`--dlp-map requires source-name=destination-name`); duplicate sources `Duplicate source names in --dlp-map` (exit 2).
7. `extname(resolve(file)).toLowerCase()` ∈ `.json, .yaml, .yml`: `Backup file must use .json, .yaml or .yml` (exit 2).
8. `stat` (follows symlinks): an errno error → `Profile transfer file operation failed (ENOENT); existing files are not overwritten.` (exit 1); not a regular file or larger than 20 MiB → `Backup must be a regular file no larger than 20 MiB` (exit 2; captured for a directory).
9. Read UTF-8; re-check the byte length; `.json` → `JSON.parse` (a BOM fails; duplicate keys: the last wins, captured), else `js-yaml load(text, {schema: JSON_SCHEMA})` (duplicate keys and `!!js/…` tags fail). Any failure → `Backup is not valid JSON/YAML; contents are not logged` (exit 2; captured: invalid JSON holding `PRIVATE-SECRET` not echoed).
10. `RuntimeProfilesBackupSchema.parse` → a zod failure is `Invalid profile backup/request schema; content is not logged.` (**exit 1**; captured: an extra top-level key, `version: 2`, an extra `source` key, empty `profiles`, `exportedAt: "yesterday"`).
11. `resolveOutput` (config), `context()` (tenant, credentials, client).
12. `--expect-tsg` given and not the tenant's `mgmtTsgId`: `--expect-tsg does not match the selected destination tenant; no API request was made` (exit 2; captured: no request).
13. The plan (§7.3), then the warnings, then the dry-run output or the confirmation (§7.5), the execution (§7.6) and the result (§7.7).

A TS backup is the only format the reader accepts; there is no TSG check of the file against the tenant besides the cross-tenant rules (§7.8).

### 7.2 What the plan reads (captured)

Destination profile inventory (as §6.2, `latest=true`), then the destination topic inventory only when a non-skipped profile references a topic, then the DLP data-profile catalog (`GET <dlp>/v2/api/data-profiles?page=<p>&size=100`, `rp.ts:319-337`: until `last`, else `page + 1 >= totalPages`, else a short page; more than 10 000 → `DLP inventory exceeds the safety limit`; an empty non-last page → `DLP inventory pagination did not advance`; the budget → `DLP inventory is incomplete; increase --max-pages`) only when some DLP reference has a destination name (§7.3 step 9). Captured cross-tenant dry run without DLP: `GET profiles/tsg/200?offset=0&limit=100&latest=true`, `GET topics/tsg/200?offset=0&limit=100`; with `--dlp-map`: profiles, then `GET /dlp/v2/api/data-profiles?page=0&size=100`.

### 7.3 Plan (`planRuntimeProfilesRestore`, `rp.ts:340-527`)

1. Re-parse the backup; `maxPages` 1–1000; `--name-prefix` at most 64 UTF-16 units without U+0000–U+001F or U+007F, else `Invalid --name-prefix` (exit 1, no request, captured).
2. `selected = latestProfiles(backup.profiles)` (names, repeats, ambiguity as §6.2); `assertTenant(selected, backup.source.tsgId)`: a profile `tsg_id` other than the file's source TSG fails; `selected.length !== profiles.length` → `Backup contains duplicate profile names/revisions` (one revision per name).
3. `crossTenant = source.tsgId !== destination mgmtTsgId`.
4. Per profile: a policy (`Backup profile has no policy`), `CreateSecurityProfileRequestSchema.parse({profile_name: prefix + name, active, policy})`, and when cross-tenant `assertKnownPolicyReferences` (`rp.ts:289-317`): any key matching `(?:^|[-_])(id|uuid)$|(?:Id|ID|Uuid|UUID)$` whose value is not `null` or `''` must be a known reference key (`topic_id` of a topic reference; `id`/`uuid` of an embedded DLP profile; `id` of a DLP member), else `Unsupported cross-tenant policy reference at policy.<path>.<key>` (before any request).
5. Destination profiles; `assertTenant(existing, destination)`.
6. Per profile, a destination match by exact name: with `--on-conflict error` → `Destination profile already exists: <name>; choose --on-conflict verify, skip or update` (exit 1, captured); a match without `profile_id` → `Destination profile has no identity`; action `create` (no match), `skip`, `verify` or `update`.
7. Topic references of the non-skipped profiles; destination topics when any.
8. Per reference key `[topic_id, revision]` (first occurrence): exactly one backup topic with that key and name, else `Backup lacks an unambiguous topic definition: <name>`; `name = prefix + topic_name` (`assertName`); one name for two keys → `Multiple source revisions use topic name <name>; split the backup by profile/revision before restoring`; destination topics with that name, highest revision first: two distinct ids → `Ambiguous destination topic name: <name>`; a match without id or not `sameTopic` (equal `description`, `JSON.stringify(examples)`, `active ?? true`) → `Destination topic differs: <name>; use --name-prefix to avoid changing a shared topic`; else reuse the match or create.
9. DLP (only when cross-tenant or `--on-missing-dlp basic`; a same-tenant default restore keeps DLP ids as they are): `dlpReferences` (`rp.ts:228-263`) = each `dlp-data-profiles[]` entry (`name` string, else `Invalid embedded DLP reference`) and each `ai-security-profiles[].model-configuration.data-protection.data-leak-detection.member[]` (`text` string, else `Invalid DLP member`), except the built-in Basic member (`text` case-insensitively `sensitive content`, `id` `''` or absent, `version` `'2'` or absent, and no embedded entry of that name). `targetFor(name)` = the `--dlp-map` value, else `undefined` cross-tenant, else the same name. Without a target and `--on-missing-dlp error`: `Cross-tenant DLP reference requires explicit --dlp-map "<name>=<destination-name>"; DLP resources are not cloned. Inspect destination resources with airs-cli runtime dlp profiles list --all --output json, or explicitly accept --on-missing-dlp basic.` (exit 1, captured). The catalog is read when some name has a target; matches by `name` excluding `profile_status` `deleted`/`disabled`; none and `basic` → unresolved; not exactly one or no id → `Missing or ambiguous destination DLP profile: <target>`; a reference with a `version` key and a destination without a version → `Destination DLP version is unknown: <target>`. An HTTP error is never read as a missing profile (TS unit test).
10. Basic fallback for each non-skipped profile with an unresolved name (`basicFallback`, `rp.ts:266-286`): each detection whose members include a custom name must have action `block`, `allow` or `''` (`Cannot safely fall back to Basic: unsupported DLP action`), `mask-data-inline` only with `block` (`Cannot safely fall back to Basic: inline masking requires a block action`); `member` becomes `[{"text":"sensitive content","id":"","version":"2"}]` (`null` for action `''`); none converted → `Cannot safely fall back to Basic: no matching DLP detection configuration`; `dlp-data-profiles` emptied if present. The fallback entry `{profile, unresolved, replaced (all custom names of the profile), reason: 'unmapped-or-missing', protection: 'basic'}`; the original policy is kept in the plan; mappings no longer referenced are dropped.
11. `verify` profiles are checked now, before any write: the mapped policy (§7.6; a topic that would have to be created → `Missing planned topic mapping; an existing profile cannot be verified without its destination dependencies`) compared with `compareRuntimePolicies(expected, existing.policy)`; a mismatch or a differing `active` → `Destination profile does not match restore plan: <name>; verification made no changes`; server defaults recorded.

### 7.4 Dry run and layouts (captured)

Each fallback first prints (stderr, never quiet) `  ⚠ DLP protection change: <profile> will use Basic detection instead of <replaced joined ', '>. Custom rules are not preserved.` Then `summary = {sourceTsgId, destinationTsgId, dryRun, profiles[{name, action}], topics[{name, action: existing ? 'reuse' : 'create'}], dlpMappings[{source, destination}], dlpFallbacks, serverDefaults}` through `renderRestore` (`pt.ts:26-92`):

- `pretty` and `table` (identical): blocks joined by `\n\n`: `Restore preview — no changes made` (or `Restore complete`, `Restore incomplete — completed writes remain`), `Source TSG: <s>\nDestination TSG: <d>`, `Profiles (<n>)`, an `Action | Name` table or `(none)`, `Topics (<n>)`, its table or `(none)`, then if any `DLP mappings` + a `Source | Destination` table, if any `Basic DLP fallbacks — custom protection lost` + one `<profile>: <replaced joined ', '>` block each, if any `Verified server-added defaults (source omitted these fields)` + `<profile>: <n> fields; use --output json for paths` each, and `Error: <error>` when set; one `\n` from `console.log`. Example:

```
Restore preview — no changes made

Source TSG: 100
Destination TSG: 200

Profiles (2)

 Action │ Name       
────────┼────────────
 create │ Production 
 create │ Staging    

Topics (1)

 Action │ Name       
────────┼────────────
 create │ Restricted 
```

- `markdown`: headings `### <text>\n` (so two blank lines follow), the TSG lines separated by a blank line, markdown tables.
- `json`/`yaml`: the **whole summary object** in a one-element array (`formatOutput` does not project for these): `[{"sourceTsgId":"100","destinationTsgId":"200","dryRun":true,"profiles":[…],"topics":[…],"dlpMappings":[],"dlpFallbacks":[],"serverDefaults":[]}]` (2-space JSON).
- `csv`: header `Source TSG,Destination TSG,Profiles,Topics,DLP mappings,Basic DLP fallbacks (custom protection lost),Verified server-added defaults,Dry run,Complete` and one row with the arrays as JSON in quoted cells and an empty `Complete`.
- Names (profile, topic, DLP) are printed raw; only C0/DEL are refused in profile and topic names.

### 7.5 Confirmation (`pt.ts:339-347`, `confirm.ts:32-55`, captured on a pty)

Only when at least one profile is `create` or `update` (skip/verify-only runs never prompt): `confirmOrAbort("Restore <n> profiles from TSG <src> to TSG <dst> (<u> updates, <f> Basic DLP fallbacks losing custom detection)?", --force, {action: 'restore profiles into TSG <dst>'})`.
- `--force` (with a matching `--expect-tsg`): no prompt.
- `process.stdout.isTTY` false: `refusing to restore profiles into TSG <dst> without --force in non-interactive mode` (exit 2) — **after** the plan's reads (captured: token, profile and topic GETs, then the refusal).
- TTY: inquirer on stdout, `? Restore 2 profiles from TSG 100 to TSG 200 (2 updates, 0 Basic DLP fallbacks losing custom detection)? (y/N)`; `n` → `✔ … No`, then `  ℹ Aborted` on **stdout** (cyan), exit 0; `y` → `✔ … Yes`, then the execution.

### 7.6 Execution (`restoreRuntimeProfiles`, `rp.ts:581-717`, captured sequence)

Inside one `try`:
1. Recheck: the destination profile inventory; `assertTenant`; when mappings exist, the DLP catalog again (each mapping exactly one active match with the same id and version, else `Destination DLP profile changed after planning: <dest>`); each non-skipped plan profile's current state must equal the planned one (`unchanged`: same id, revision, active and canonical policy, where an absent `database-security` in a `data-protection` object counts as `null`), or be absent for a create, else `Destination profile changed after planning: <name>`.
2. Per planned topic (in plan order): **a fresh topic inventory walk each time**; a reused topic must still exist with the same id and revision and `sameTopic`, a created one must still be absent by name (`Destination topic changed after planning: <name>`); create = `POST <mgmt>/v1/mgmt/topic` with `{"topic_name","active","description","examples"}` (captured body order `topic_name, active, description, examples`; `examples` may be the fabricated `[]`); the answer must have an id, the name, a safe integer revision and `sameTopic`, else `Topic response did not verify: <name>`; `result.topics.push({name, id, action: 'created'|'reused'})`.
3. Per planned profile (in plan order): `skip` → `{name, action: 'skipped', id}`. Otherwise `policy = mappedPolicy(...)` (`rp.ts:719-749`: each topic reference gets the destination `topic_id`, `topic_name`, `revision`; each mapped DLP reference gets the destination name (`name` for embedded, `text` for members), `uuid` (embedded), `id` where an `id` key exists, `version` as a string where a `version` key exists); `body = {profile_name, active, policy}` (`CreateSecurityProfileRequestSchema`); a fresh profile inventory (tenant check, unchanged/absent check); `verify` → `compareRuntimePolicies`, `Restored profile did not verify: <name>` on a mismatch, else `{action: 'verified'}`; `update` → `PUT <mgmt>/v1/mgmt/profile/uuid/<existing id>` (the SDK asserts a UUID); `create` → `POST <mgmt>/v1/mgmt/profile`; push `{name, action: 'created'|'updated', id: response.profile_id}`; then **a fresh profile inventory** to verify: present with an id, the same id as the answer when the answer had one, the same `active` when the source had one, and `compareRuntimePolicies(policy, verified.policy).matches`, else `Restored profile did not verify: <name>`; server defaults recorded.
4. `complete = true`.

Captured cross-tenant create of two profiles and one topic: `GET profiles`, `GET topics` (plan); `GET profiles` (recheck); `GET topics`, `POST topic`; `GET profiles`, `POST profile` (Production), `GET profiles` (verify); `GET profiles`, `POST profile` (Staging), `GET profiles`. With `--on-conflict update` after a `y`: two `PUT /v1/mgmt/profile/uuid/<id>`, no topic write (reused).

`compareRuntimePolicies(expected, actual)` (`pol.ts:12-161`) is directional: every key and array element of `expected` must be equal in `actual` (same array lengths, same scalars, `null` included); a key present only in `actual` is a difference unless it is one of these observed server defaults, which are recorded as `serverDefaults` paths: `model-configuration.data-protection.database-security: null`; `severity` on `data-protection.database-security[i]` by name (`database-security-create` `medium`, `-read` `low`, `-update` `medium`, `-delete` `high`); `data-protection.source-code-detection.severity: "high"`; `app-protection.malicious-code-protection.severity: "high"` (name `malicious-code`); `model-protection[i].severity: "medium"` for `prompt-injection`, `topic-guardrails`, and `contextual-grounding` with action `block`; `severity: "medium"` on a `topic-guardrails` `topic-list[j].topic[k]` reference of a `block` list with the same id, name and revision; `agent-protection[i].severity: "medium"` (`agent-security`); `app-protection.url-detected-severity: "low"`; `app-protection.default-url-category: {"member": null}` exactly; `severity-by-confidence: {"high":"medium","moderate":"low"}` exactly on a `toxic-content` item or one of its `toxic-category-list` entries with the same category. A key present only in `expected` is always a difference.

### 7.7 Result and exit (captured)

`result = {sourceTsgId, destinationTsgId, complete, dlpFallbacks, serverDefaults, topics[{name, id, action}], profiles[{name, action, id}], error?}` through `renderRestore` (§7.4 layouts; json/yaml print the whole object, e.g. `[{"sourceTsgId":"100","destinationTsgId":"200","complete":true,"dlpFallbacks":[],"serverDefaults":[],"topics":[],"profiles":[{"name":"Production","action":"skipped","id":"<uuid>"},…]}]`). When not complete: the `Error: <error>` block on stdout **and** `  ✗ <error>` on stderr, exit 1. The error text (`rp.ts:704-715`): an integer `statusCode` → `API request failed (HTTP <s>); verify destination state before retrying`; a message starting with `Destination`, `Topic response`, `Missing planned`, `Restored profile`, `Inventory` or `DLP inventory` → that message; anything else (a timeout, a dropped connection, a schema failure) → `Restore stopped; verify destination state before retrying`.

Fault matrix (each from an empty destination, `--force --expect-tsg 200`, `PANW_AI_SEC_TIMEOUT_MS=1500`):

| Fault | Requests | Result |
|---|---|---|
| `POST profile` 503 | plan reads, recheck, `GET topics`, `POST topic`, `GET profiles`, `POST profile → 503` | `Restore incomplete — completed writes remain`, `Profiles (0)` `(none)`, `Topics (1)` `created │ Restricted`, `Error: API request failed (HTTP 503); verify destination state before retrying`; stderr the same line; exit 1 |
| `POST profile` 400 | same | `(HTTP 400)`, exit 1 |
| `POST profile` 401 | `POST profile → 401`, `POST token`, `POST profile → 401` | `(HTTP 401)`, exit 1 (the write was sent twice) |
| `POST profile` 403 | `POST profile → 403`, `POST token`, `POST profile → 403` | `(HTTP 403)`, exit 1 (the write was sent twice) |
| `POST topic` hang | `POST topic` (one attempt) | `Topics (0)` `(none)`, `Error: Restore stopped; verify destination state before retrying`; nothing says the topic may exist; exit 1 |
| SIGINT during `POST profile` | — | exit 130, nothing printed |

Re-runs: the topic created by a failed run is reused on the next run (`sameTopic`); a profile whose create outcome is unknown and that exists stops the next run with `Destination profile already exists: …` unless `--on-conflict verify|skip|update`. `--on-conflict skip` and `verify` runs send no write (captured; TS integration test).

**Absent collections (G10, captured):** a destination profile list answered `{}` is read as an empty inventory (`ai_profiles` default), so a destination that holds `Production` is planned `create │ Production`; the execution would send the create and then fail its verification, leaving a duplicate.

### 7.8 TSG handling

- The destination is the selected tenant's `mgmtTsgId`; `--expect-tsg` must equal it when given and is required with `--force`.
- A backup from another TSG is restored without any flag; cross-tenant only switches on the reference allowlist (§7.3 step 4) and the DLP mapping rules (step 9). Same-tenant restores keep DLP ids and skip the DLP catalog unless `--on-missing-dlp basic`.
- Backup profile `tsg_id`s must equal the file's `source.tsgId`; destination profile `tsg_id`s must equal the destination (checked at plan, recheck and every inventory).

## 8. Sensitive-data exposure (TS)

- **Dashboard and sessions**: stdout prints the full SDK-parsed responses, unknown fields included: application and session names, ids, `attributes.user_id`/`user_ip` (transaction), any extra field the server adds to a session item (captured `prompt`), and with `scan-content --show-content` the stored prompts and responses. C1 and `Cf` characters reach the terminal raw (§3.3). Errors never contain server text, paths or SDK messages. `--debug` logs URLs with `session_id`, `app_name`, `scan_id` (bodies omitted). The file of `scan-content --output-file` is 0600 and exclusive, but its existence check is the only pre-tenant check.
- **Report**: an allowlisted projection; no ids, users, prompts, key names, `auth_code` (dropped from `api_keys_dp_info`), tenant ids or error bodies; labels stripped of `Cc`/`Cf`; HTML and Markdown escaped; CSP pinned; the status path with `Cc`/`Cf` → `_`. Application, profile and registered-app names remain (the limitations say so). Debug refused.
- **Backup file**: every profile policy (detection settings, DLP profile names and ids, topic ids), `profile_id`, `tsg_id`, `csp_id`, `created_by`/`updated_by` (user e-mail addresses), timestamps, and topic definitions with examples. 0600, exclusive. The summary prints the absolute path raw. Debug refused (`PANW_AI_SEC_DEBUG` too).
- **Restore**: names from the file and the destination are printed raw in tables and in error messages; `failure` prints unknown errors' messages verbatim. No credential is involved.

## 9. TS specs to port (acceptance tests)

| Spec | Behaviours |
|---|---|
| `tests/integration/cli/runtime-dashboard.spec.ts` | exact default queries of `applications` (1/day/25/0), `top-applications`, `violations-trend` (1/day), `apps-list` (30/days); `application(-violations)` identity and 7-day window; `chart`; `sessions list --offset 2` → a bare array; `--unit week` rejected before the config (invalid config untouched), before any hook, client or output, with `Supported units: hour, hours, day, days` and `--interval 7 --unit days`, not the operation failure; `weeks, month, months, year, years, fortnight, DAY, ' day '` exit 2 with no client; `week` refused for `chart`, `get`, `transaction`, `top-applications`, `violations-trend`, `apps-list`; `1 hour`, `24 hours`, `1 day`, `7 days` accepted with YAML output; help shows `Time unit: hour, hours, day, days`; `get` defaults 30 days, limit 25, offset 0; `transaction` keeps `scan_sub_req_id` 0 and never calls scan content; `--all` walks two pages and keeps same-name identities; unstable pages (total change, overlap, empty page before the total, total 0) → exit 1, no output; `--all --max 1` → one item, exit 1; `--limit 0`, `--offset -1`, `--max NaN`, `--interval 1oops`, `application --interval 1`, scan content with neither or both destinations → exit 2 before the client; `--output-file` writes 0600 content and a second run fails exit 1 before the client; `--show-content` queries `{scanId, scanSubReqId: 0}`; a 403 with `SECRET BODY` → exit 1, no secret on stderr; `mgmtDashboardEndpoint` used for the dashboard, `mgmtEndpoint` unchanged, `numRetries: 0` |
| `tests/integration/cli/runtime-report.spec.ts` | HTML despite `defaultOutput: json`; `numRetries: 0`; Markdown from the root `--output markdown`; `--output markdown runtime report --output html` writes HTML (both occurrences reach the root option, the last wins, §2.3); stdout delivery in one write, a stream error → exit 1; unique default HTML and Markdown names in the CWD; a partial report exit 0 (`unavailable` in the file), `--strict` exit 1; every source failing (`PRIVATE-ERROR`) → `Unable to assess`, no secret, exit 1; an existing path refused before the client, file unchanged; an invalid config without echoing it; `--output json`, `--max-pages 0|1.5|101`, `--title ''`, a 241-character title, `--debug` → exit 2 before the client |
| `tests/unit/reports/runtime.spec.ts` | seven sources; the session (25), application (100) and profile (latest, 100) queries; schema 2, `no-findings`, the window; no `NEVER-EXPORT`, tenant, session, key, deployment, user or profile ids in the model; absent bodies are unknown, explicit empties are zero with the two findings; HTTP 401/403/429/500/none/`oops`/999 → all `unavailable`, `unknown`, no secret; two session pages with composite identities, the chart disagreement finding; incoherent initial session metadata → `unavailable`; total change, overlap, later error → `partial`; `--max-pages 1` note; label bounds (240, controls, `Unknown` title), invalid counters → null rate; application total change and incomplete pages; absent pagination probes, non-advancing inventories; latest revisions and the three profile findings; the half-open UTC window and explicit failures; ranking and trend counts and the high/critical finding; budgets `-1, 0, 1.5, 101, NaN, Infinity` rejected before requests |
| `tests/unit/reports/render.spec.ts` | `<!doctype html>`, `lang="en"`, no external resources, both inline hashes in the CSP; escaping of a script/attribute/Markdown attack in every dynamic surface (one `<script>`, no `<img`, `&lt;/script&gt;`, Markdown `&#60;/script&#62;`, no `[click]`, no `| \n`); HTML and Markdown carry the same evidence (`Attention required`, `25%`, `Next step:`, `Report schema 2`); unknown and empty sources render `Unknown`, `No rows available`, `unavailable`; `Not in returned inventory`, no `200%`, `Source: unavailable` without sources |
| `tests/unit/reports/io.spec.ts` | a complete 0600 file and no temporary left; refuse an existing file and a symlink to a credential file (`EEXIST`, target unchanged); one winner between two concurrent writers; `ENOENT` for a missing directory |
| `tests/unit/cli/report-naming.spec.ts` | `runtime report` exists once, its description does not say `dashboard`, it has no `dashboard` alias; `runtime dashboard` is a separate group with subcommands |
| `tests/integration/tenant-profile-transfer.spec.ts` | (real CLI + SDK) Basic DLP kept, custom DLP refused without `--dlp-map` (dry run exit 1 mentioning `--dlp-map`), `--on-missing-dlp basic` in every format with the warning and the profile name, json `dlpFallbacks` length 1, no destination write in dry runs, the forced restore converts to Basic, no DLP catalog request, backup and configs unchanged; backup `--all` json summary (1 profile, 1 topic, file in the CWD, 0600), a named YAML backup, a second backup to the same file exit 1 with the file unchanged; a dry run only GETs; a forced YAML restore creates fresh ids, the destination TSG, no source topic id; a second dry run exit 1 (conflict); `skip` creates nothing; `verify` sends no write and reports `verified`; pretty/table/markdown show `Profiles (1)`, no JSON arrays, lines < 160; `--debug`, `PANW_AI_SEC_DEBUG=true`, `--file-format exe`, `--max-pages 0`, invalid JSON (dry run and `--force`) → exit 2 with no request and no debug file; `--expect-tsg 200` against TSG 100 → exit 2, no request; a broken tenant config → exit 1 |
| `tests/unit/backup/runtime-profiles.spec.ts` | verify resumes (existing verified with rewritten topic ids, missing created, no update or topic write); policy/active/missing-topic mismatches refused before writes; a concurrent change after planning stops without writes; server-added severity recorded at create and verify; the `database-security` null normalisation; the built-in `sensitive content` member kept without a DLP read; a custom member named `sensitive content` still needs `--dlp-map`; Basic fallback per action (`block`, `allow`, `''`), unrelated settings kept, the input unchanged; mapping wins over fallback; fallback for a mapped profile proven absent; same-tenant fallback reads the catalog; inventory HTTP 401/403/404/500 never mean missing; ambiguous DLP refused; partial mapping reports every custom name; masking with `allow` refused; skipped profiles not inspected; backup latest revisions and exact topics with unknown settings; selection by name or id; no topic read without references; page walks; absent/wrong-revision/duplicate topics refused; incomplete, stalled and repeated inventories; budgets `0, -1, 1.5, 1001`; missing, ambiguous, wrong-tenant, policy-less profiles; DLP changed after planning; `objectId`/`extra_uuid` in topic objects refused cross-tenant before any request; fresh ids, request keys (`active, policy, profile_name`; `active, description, examples, topic_name`), the prefix; DLP ids and versions bound; unknown DLP version refused; undocumented `object_id` refused; identical topics reused, different or ambiguous ones refused; conflict default and `skip`; `update` uses the destination id; stale plans and new topics stop before writes; a 503 create reports a partial result once, without the body; a changed policy fails verification; invalid archives (`{}`, version 2, wrong source TSG) refused before requests |
| `tests/unit/backup/runtime-policy.spec.ts` | the directional comparison: the contextual-grounding default only for `block`; topic-guardrail severities only for matching blocked references; category confidence defaults; extra or missing categories refused; the empty default URL category only; the ten omitted fields of the fixture accepted and reported without mutating the inputs, the reverse direction refused; explicit severities (`high`, `null`, `''`) and confidence maps must match; unknown `severity|action|name|unknown` changes refused; extra settings, detectors and shapes refused; the null `database-security` addition only |

`tests/e2e/runtime-dashboard.e2e.spec.ts` and `tests/e2e/runtime-report.e2e.spec.ts` are live (`RUN_RUNTIME_REPORT_E2E`) and inform the live tier only.

## 10. scm-sdk 0.1.1 coverage (pointers)

- `rs:airs/management/dashboard.rs` has every dashboard route with typed and `_raw` variants (`application`, `application_violation_breakdown`, `top_applications_violations`, `applications_violations_trend`, `apps_list`, `sessions_chart`, `sessions_overview`, `session`, `session_transaction`, `scan_content`, `applications_overview`, `:350-646`), the same query names (`appid`/`appname` for applications, `app_id`/`app_name` for sessions, `:213-327`), the TS query schemas by name, and `x-tsg-id` forced on (`DashboardClient::new`, `:209-214`). `applications_overview` repeats the TS 1/7/30/60 × `days, day, hour` check (`:329-345`).
- `rs:airs/management/profiles.rs` (`list`, `create`, `update`), `topics.rs` (`list`, `create`) and `customer_apps.rs` (`list`) cover the transfer and report reads and writes; the DLP data-profile list is in the `dlp` feature (`ts-dlp-backup.md` §8). Whether their list models apply the TS `ai_profiles`/`custom_topics`/`examples` defaults, and that `RequestOptions::without_response_defaults()` removes them, must be confirmed by the implementation (G10).

## 11. Live-tier notes

- Reads (both CLIs, TS sandboxed): `dashboard applications --limit 1`, `top-applications`, `violations-trend`, `apps-list`, `sessions chart`, `sessions list --limit 1`, `sessions get` and `transaction` of the first listed identity (TS requires the exact app name and a scan id from `get`), compared structurally in memory (key order differs, §2.2); never `scan-content` on the TS side (prompts) — the Rust side only, with a check that nothing is printed without `--show-content`.
- `runtime report` both CLIs to new files in their sandboxes, compared by the model (source names, statuses, finding titles, table row counts), not by bytes (rolling window, timestamps).
- `profiles backup <existing name>` both CLIs (read-only), compared by profile names, revisions and topic keys.
- Write flow (`AIRS_RS_LIVE_PROFILE_TRANSFER=1`): profiles `airs-rs-e2e-<run id>-…` created with `profiles create`, backed up, deleted, restored, verified, deleted; a TS restore runs only on a TS backup and only if the Rust reader accepts it (the recommendation below is that it does not).

## Acceptance criteria

1. Help: the option sets, defaults and descriptions of §1 (Rust rendering per the shell rules); `sessions list|ls`; `report` has no `dashboard` alias; `runtime dashboard` and `runtime sessions` are groups.
2. Dashboard units: the exact unit lists of §3.1 per command and the message `Unsupported --unit. Supported units: <list>. For one week, use --interval 7 --unit days.` (exit 2) before the tenant and any request; `integer` and `text` messages of §3.1 verbatim; the `applications` and application-detail combination messages.
3. Requests: each command sends exactly one GET with the query names and order of §3.2/§4 (URL-encoded values), on the dashboard host, with `x-tsg-id`; one attempt (no replay after a 5xx, 429 or timeout); a 401 replayed once; a 403 never replayed.
4. Dashboard output: `json` and `pretty` print the response envelope as 2-space JSON (one trailing `\n`); `sessions list` prints a bare array; no status line except the `sessions list` ones; `table` per the Rust decision; `yaml`, `markdown`, `csv` usage errors.
5. `sessions list --all`: the six-step loop of §4.2 with its four status texts, exit 1 for a cap, and no stdout plus exit 1 for unstable, overlapping or incomplete pages; `--max 0` removes the item cap; 100 pages at most.
6. `scan-content`: exactly one destination (exit 2 otherwise); `--output-file` checked before the tenant (existing path, dangling symlink, missing parent) and written 0600 exclusively, never overwritten, no temporary left; the status line without the path; stdout empty; `--show-content` the only way content reaches stdout.
7. Every dashboard/sessions failure after the checks is one line without server text, paths or SDK messages (plus the Rust outcome rules); exit 1.
8. Report argument checks of §5.1 before the tenant; the destination rules of §5.2 (`airs-runtime-report-…` name, `lstat` refusal before the tenant, exit 1, file unchanged).
9. Report collection: the seven sources, queries and page rules of §5.3 with their notes verbatim; statuses `complete`/`partial`/`unavailable`; an absent collection never `complete`; no source fetches transactions or scan content.
10. Report analysis and findings of §5.4 verbatim, health, the model without ids or content; HTML byte-for-byte as §5.5 (CSP hashes, escaping, sections, footer, trailing `\n`) for a fixed clock.
11. Report publishing and exit of §5.6: `Report → <path> (mode 0600)`, the incomplete line, exit 1 for `unknown` or `--strict` with an incomplete source, the generic failure line otherwise.
12. Backup: checks, inventory walk, latest selection, topic exactness and messages of §6.1–§6.2; the output path checked before the tenant; the Rust file written 0600 exclusively, never overwritten; no fabricated default in the file; the summary layouts of §6.4 with a terminal-safe path.
13. Restore: checks of §7.1 (exit codes as decided), the strict reader, the plan rules and messages of §7.3 (conflicts, topics, DLP mapping and fallback, the cross-tenant reference allowlist), the dry-run layouts of §7.4, the confirmation per D81, the execution order and rechecks of §7.6, verification with `compareRuntimePolicies` semantics, one attempt per write, a stop at the first failure with an outcome-unknown line for a write whose answer was lost, and a re-run that never duplicates.
14. Restore against `{}` inventories (profiles, topics) refuses instead of planning creates.
15. Interruption prints the Rust `Interrupted; <context>` line (what may have been written) and exits 130/143; no report or backup file or temporary is left.
16. `--quiet` drops only status lines; warnings, errors and data remain; colour per stream.
17. Every printed server string (names, ids, status values, dashboard JSON strings) passes `terminal_safe`.

## Open questions / likely §12 divergences

Candidates for §12 rows (numbering from D204 is left to the implementation); each is a safety or correctness fix unless marked.

1. **Dashboard formats.** TS allows `pretty` (= JSON), `json`, `yaml`; refuses `table`, `markdown`, `csv`. Rust (settled): `yaml` becomes a usage error. Decide whether `table` gets a layout (the envelopes are nested; a table would need per-command projections) or stays refused as in TS — recommended: refused, `pretty` = `json`.
2. **JSON key order.** TS prints keys in zod schema order then server order; scm-sdk responses through `serde_json` without `preserve_order` print alphabetically. Not a safety fix, but unavoidable: record the row, and compare dashboard/session/backup output structurally in parity tests.
3. **Checks before the tenant.** TS loads the tenant config before the argument checks of `sessions list|get` (preAction) and before the format check of every dashboard command, so a broken config turns usage errors into exit 1, and a `defaultOutput: table` tenant breaks every dashboard command. Rust: all argument checks first; decide what a non-allowed `defaultOutput` does (recommended: fall back to `pretty` for these commands, as `report` ignores it).
4. **403 replay.** TS replays every read and write once after a 403 (and a 401); Rust: 401 once, 403 never (settled). For restore this means TS sends a POST twice after a 403.
5. **Terminal safety.** TS prints C1 and `Cf` characters raw in JSON/YAML dashboard output and in restore names and messages, and the backup summary path raw. Rust: `terminal_safe` for every printed server or file string (JSON escaping alone is not enough for U+009B, U+202E).
6. **`scan-content --output-file` parent.** TS fetches the stored content and then fails on a missing directory. Rust: check the parent before the tenant, so no content is fetched for nothing.
7. **Report format.** As D155: drop Markdown, HTML only, `--output` refused; as D156: refuse `--debug` only, `PANW_AI_SEC_DEBUG` not read.
8. **Report and schema defaults.** TS reads a profile list `{}` as a complete empty inventory and raises `No security profiles returned` (attention). Rust with `without_response_defaults()`: the source is `unavailable` with the no-record-array note.
9. **Report 403 replay** (as 4; the §15.17 G7 re-read for a 401 only?). Decide consistently with the red team report, which kept a CLI re-read after 401 and 403 (G7); for M6d's "403 never" rule, record which applies.
10. **Backup path check.** TS checks the output file only at the write, after every inventory (D175-like). Rust: `lstat` and the parent check before the tenant.
11. **Backup format.** Rust writes its own versioned JSON format (recommended `format: "airs-cli-rs.runtime-profiles"`, `version: 1`, `exportedAt`, `tenant`, `tsgId`, `complete`, `profiles`, `topics`), exclusively at 0600; `--file-format yaml` refused (as D151/D175). Keep the profiles and topics exactly as the server sent them (no `examples: []` fabrication, G10).
12. **TS backup files.** Recommended: refused with a fixed message (no import), consistent with D152/D176; the TS file carries fabricated `examples: []` and no completeness marker. Rejected alternative: accept TS files (the TS schema is strict and versioned), which would require reproducing the zod reordering and defaults.
13. **Restore TSG check.** TS restores a backup from another TSG with no flag. Rust: `--allow-other-tenant` (as D176); keep `--expect-tsg` and "`--force` requires `--expect-tsg`".
14. **Restore confirmation.** TS checks `stdout.isTTY` only after the plan's reads, prompts on stdout and prints `Aborted` on stdout. Rust per D81 (refusal before any request, prompt and outcome on stderr).
15. **Restore outcomes.** TS reports a lost create (5xx, timeout, dropped connection) as `API request failed (HTTP 503)` or `Restore stopped`, with nothing saying the topic or profile may exist (D177-like). Rust: one attempt per write, an outcome-unknown line naming the resource, stop at the first unknown outcome.
16. **Restore and absent collections.** TS reads a destination profile or topic list `{}` as empty and plans creates over existing profiles (captured), producing duplicates. Rust: `without_response_defaults()`; an absent collection fails the plan.
17. **Restore exit codes.** TS exits 1 for a schema-invalid backup but 2 for invalid JSON/YAML; decide whether the Rust strict reader's failures are all usage errors (exit 2) or all operational (exit 1), as D176 did.
18. **Restore error echo.** TS prints unknown errors' messages verbatim (server names in `Ambiguous profile name: …`, raw). Rust: fixed messages with names through `terminal_safe`.
19. **Interruption.** TS ends silently (exit 130/143) during reads and writes. Rust: `Interrupted; <context>` as D193 (e.g. `the profile create request may have been applied`).
20. **Debug refusal environment.** TS also refuses `PANW_AI_SEC_DEBUG` for backup/restore; Rust reads no environment (as D156).
21. **Restore duplicate output of the error** (stdout `Error:` block and stderr line): Rust keeps the error inside the data and one stderr outcome line (stdout data only).
22. **Docs drift (no divergence).** `PANW_MGMT_DASHBOARD_ENDPOINT` is documented but never read; the Rust tenant `mgmtDashboardEndpoint` is the only override.
23. **Open: `sessions get`/`transaction` content.** They print `attributes.user_id`/`user_ip` and any passthrough fields; decide whether Rust withholds anything (recommended: print as TS, they are explicit reads, but never in the live summary).
