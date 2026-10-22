# Spec: TS `airs-cli aigateway report` and the doctor "AI Gateway API" check (M6e)

Commands covered: `aigateway report|dashboard` (the AI Gateway environment report) and the doctor check `AI Gateway API`
(TypeScript check 10). The other `aigateway` commands (workspaces, configs, keys, telemetry, inference, admin) are out of
scope here. In airs-cli-rs the command is `gateway report|dashboard` and the check is `Gateway API` (MILESTONES, Renames).

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0, SDK
  `@cdot65/prisma-airs-sdk` 0.34.0, commander 14, zod 3.25.76). Citations:
  - `ar.ts` is `src/cli/commands/aigateway-report.ts` (the command); `gwr.ts` is `src/reports/aigateway.ts` (the
    collector); `er.ts` is `src/reports/environment-render.ts` (HTML and Markdown, shared with `redteam report`);
    `io.ts` is `src/reports/io.ts` (`writeReportFile`); `typ.ts` is `src/reports/types.ts`.
  - `doc.ts` is `src/cli/commands/doctor.ts`; `svc.ts` is `src/airs/aigateway.ts` (`SdkAiGatewayService`,
    `aiGatewayGrantHint`); `co.ts` is `src/config/client-options.ts`; `sch.ts` is `src/config/schema.ts`;
    `prog.ts` is `src/cli/program.ts`; `ui.ts` and `common.ts` are under `src/cli/renderer/`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` of the reference build;
    `rs:<file>:<line>` is `~/.cargo/registry/src/*/scm-sdk-0.1.1/src/<file>`.
- Shared shell behaviour (commander, the root `--output` consumer, `ui`, quiet, colour) is in `ts-cli-shell.md` and
  `ts-renderer.md`; the HTTP layer (auth replay, `numRetries`, timeouts, zod passthrough) in
  `ts-runtime-dashboard-report.md` §2.2; the red team environment report, which shares `er.ts` and `io.ts`, in
  `ts-redteam-scans.md` and DESIGN §15.17; the doctor in `ts-doctor.md`. They are restated only where this command
  depends on them.
- How behaviour was captured (2026-10-18, node v24.21.0): the reference build `dist/cli/index.js` ran against a
  loopback stub (`node:http` on `127.0.0.1`, random port) implementing `POST /oauth/token` (token `tok-<n>`), the
  gateway data plane under `/gw/data` (`/workspaces`, the 17 `/logs/charts/<metric>` routes,
  `/analytics/filter-boundaries`, `/logs` paged by `pageSize`/`currentPage`, `/configs`, `/api-keys/service`,
  `/api-keys/user`) and the admin plane under `/gw/admin` (`/workspaces`, `/organisations/<tsg>/info`,
  `/utils/static-resources/schema`). Every response satisfied the SDK zod schema unless a fault said otherwise. It
  logged method, path, raw query, auth scheme, bearer token, `x-tsg-id`, `User-Agent`, `service-name`, content type
  and body, and took a per-run scenario (status, raw body, headers such as `x-opa-decision: false` or `Retry-After: 0`,
  a hang, replacement chart bodies, log totals, duplicate ids, out-of-window timestamps, quota flags).
  - Sandbox: `env -i` with `PATH`, `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`,
    `XDG_CACHE_HOME`, `AIRS_CLI_CONFIG_DIR` inside the sandbox; the TS registry selected with
    `PRISMA_AIRS_TENANTS_PATH` (`{"version":1,"active":"test","tenants":[{"name":"test","configPath":…,"tsgId":"100"}]}`);
    the config (0600) `{"mgmtClientId":"client-100","mgmtClientSecret":"FAKE-SECRET-100","mgmtTsgId":"100",
    "mgmtTokenEndpoint":"<base>/oauth/token","mgmtEndpoint":"<base>/mgmt","aiGwDataEndpoint":"<base>/gw/data",
    "aiGwAdminEndpoint":"<base>/gw/admin","iamEndpoint":"<base>/iam"}`. Fixture ids are
    `11111111-1111-4111-8111-<12 digits>`; workspaces `ws-dev-abc123` (`Dev`) and `ws-prod-def456` (`Prod`); fake
    sensitive values are `PRIVATE-…`. `TZ` was unset (host offset −05:00) unless stated.
  - Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and `dns.lookup` and refuses any host
    other than `127.0.0.1`. Its log stayed empty except in the doctor run without `aiGwDataEndpoint` (§14.4), where it
    refused `api.apps.paloaltonetworks.com` three times.
  - Signals were sent with `kill -INT|-TERM` during a hung chart request.
- No real tenant or credential file was read; no host other than loopback was contacted.
- Captures are JSON strings or verbatim blocks, uncoloured (stderr a file) unless stated. The token request
  (`POST <mgmtTokenEndpoint>`, Basic auth, `Content-Type: application/x-www-form-urlencoded`, body
  `grant_type=client_credentials&scope=tsg_id%3A100`, `User-Agent: node`) precedes the first API request and is omitted
  from request lists unless it matters.

## 1. Command surface (help verified)

Registration: `prog.ts:199` → `registerAiGatewayCommand` (`aigateway.ts:130`) → `registerAiGatewayReportCommand`
(`aigateway.ts:136`, `ar.ts:18-124`). Name `report`, alias `dashboard`, description
`Generate an AI Gateway environment report (read-only)` (`ar.ts:19-22`). Captured `aigateway report --help` (stdout,
exit 0; commander sorts options):

```
Usage: airs-cli aigateway report|dashboard [options]

Generate an AI Gateway environment report (read-only)

Options:
  --days <n>            Rolling window in days (default: 1) (default: "1")
  --end <iso>           Explicit ISO-8601 end; requires --start
  -h, --help            display help for command
  --max-pages <n>       Page budget per source, 1–100 (50 transactions/page)
                        (default: "40")
  --output <format>     Deliverable format: html or markdown (default: html)
  --output-file <path>  Destination (default: new timestamped file in CWD); -
                        for stdout; never overwrite
  --start <iso>         Explicit ISO-8601 start; requires --end
  --strict              Exit 1 after writing if any source is incomplete
  --title <text>        Report title (default: "AI Gateway environment report")
  --workspace <ref>     Workspace slug, UUID, or unique display name

Examples:
  $ airs-cli aigateway report --workspace ws-develo-71f8d8 --output-file ./airs-daily.html
  $ airs-cli aigateway report --workspace ws-develo-71f8d8 --output markdown --output-file ./airs-daily.md
  $ airs-cli aigateway report --workspace ws-develo-71f8d8
  $ airs-cli aigateway report --workspace ws-develo-71f8d8 --strict --max-pages 20 --output-file - > daily.html

```

| Option | Declaration | Default | Notes |
|---|---|---|---|
| `--workspace <ref>` | `requiredOption` (`ar.ts:23`) | none | missing → commander `error: required option '--workspace <ref>' not specified` (stderr, **exit 1**, before every other check, the debug refusal included) |
| `--days <n>` | `ar.ts:24` | `"1"` (a string) | the help shows the default twice (`(default: 1) (default: "1")`) |
| `--start <iso>`, `--end <iso>` | `ar.ts:25-26` | none | |
| `--output <format>` | `ar.ts:27` | none | never receives a value: the root `--output` consumes it wherever it appears (`ts-cli-shell.md` §3); the action reads `opts.output ?? root.output ?? 'html'` (`ar.ts:45`); the tenant `defaultOutput` is **ignored** (captured: `defaultOutput: "json"` still writes HTML) |
| `--output-file <path>` | `ar.ts:28-31` | none | `-` is stdout |
| `--title <text>` | `ar.ts:32` | `"AI Gateway environment report"` | the collector's own fallback `AI Gateway daily report` (`gwr.ts:84`) is unreachable from the CLI |
| `--max-pages <n>` | `ar.ts:33` | `"40"` | budget for `telemetry.logs` only (the other sources read one page) |
| `--strict` | `ar.ts:34` | off | |

`--quiet` and `--output` are root options and work before or after the subcommand (captured:
`aigateway dashboard … --quiet` prints nothing on stderr). The alias behaves identically (captured
`aigateway dashboard --output-file - --quiet`: the same 15 231-byte document).

## 2. Shared behaviour

### 2.1 Client, endpoints and credentials

- `new AIGatewayClient({...aiGatewayClientOptions(config), numRetries: 0})` (`ar.ts:87-90`), built after
  `loadConfig()`. `aiGatewayClientOptions` (`co.ts:79-86`) calls `assertManagementCredentials` (`co.ts:34-42`; a
  missing `mgmtClientSecret`, `mgmtClientId` or `mgmtTsgId` throws) and passes `clientId`, `clientSecret`, `tsgId`,
  `tokenEndpoint: mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`, `dataEndpoint: aiGwDataEndpoint ??
  "https://api.apps.paloaltonetworks.com/ai_gw/v2"`, `adminEndpoint: aiGwAdminEndpoint ??
  "https://api.apps.paloaltonetworks.com/ai_gw/admin/v2"`, `iamEndpoint: iamEndpoint ??
  "https://api.apps.paloaltonetworks.com/iam/v1"` (`SDK:125-130`).
- All values are explicit, so the SDK fallbacks `PANW_AI_GW_DATA_ENDPOINT`, `PANW_AI_GW_ADMIN_ENDPOINT`,
  `PANW_IAM_ENDPOINT` and the `PANW_AI_GW_*`/`PANW_MGMT_*` credentials (`SDK:22706-22722`, `resolveOAuthConfig`
  `SDK:11099-11146`) are never reached. The IAM endpoint is configured but the report never calls it. The variables
  that change the report are `PANW_AI_SEC_TIMEOUT_MS` (per-attempt timeout, default 60 000 ms, `SDK:10095`),
  `PANW_AI_SEC_DEBUG` (refusal, §3), `TZ` (query offsets, §4.2), `FORCE_COLOR`/TTY (chalk) and `AIRS_CLI_INVOKED_AS`
  (help prefix).
- Planes (captured): **admin** (`aiGwAdminEndpoint`): `workspaces.list({plane: 'admin'})`, `organisations.getInfo`,
  `guardrails.getCatalog`; **data** (`aiGwDataEndpoint`): the charts, filter boundaries, logs, configs and API keys.
- Headers on every API request (captured): `Authorization: Bearer <token>`, `x-tsg-id: 100` (`TsgHeaderAuth`,
  `SDK:14663-14678`), `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `service-name: api`; no body, no content type.
- One OAuth token per run, fetched lazily by the first request (captured: one `POST /oauth/token`, then 25 GETs).

### 2.2 HTTP layer

- `numRetries: 0`: a 5xx, 429 or timeout is never retried (captured: one GET for 500, 503, 429 with `Retry-After: 0`,
  and a hang).
- Auth replay (`SDK:10854-10871`, `SDK:9816-9823`): a 401, or a 403 without `x-opa-decision: false`, clears the token
  and re-sends once (captured for a 401 on `users`: `GET users (tok-1) → 401, POST token, GET users (tok-2) → 401`,
  later requests use `tok-2`; for a 403 on the admin `workspaces`; with `x-opa-decision: false`: one GET, no token
  request).
- Response bodies are validated by zod schemas (passthrough). A schema mismatch, invalid JSON or an empty body (parsed as
  `{}`) is an `AISecSDKException` without `statusCode`. The SDK validates inputs before any request: the workspace slug
  against `^[A-Za-z0-9][A-Za-z0-9_-]*$` (`SDK:17956-17961`), the TSG against `^\d+$`, the workspace id as a UUID
  (`assertUuid`, `SDK:11148`); a failure throws before the token request and sends nothing.

### 2.3 Streams, quiet and colour

- `ui.status(msg)` (`ui.ts:131-135`): stderr, `"  " + dim(msg)`, suppressed by `--quiet`. `ui.error(msg)`
  (`ui.ts:113-116`): stderr, `"  " + red("✗ " + msg)`, never suppressed. `usageError(msg)` (`common.ts:27-30`): stderr
  `chalk.red("\n  ✗ " + msg + "\n")`, exit 2.
- Captured with `FORCE_COLOR=1`: `  \e[2mCollecting AI Gateway statistics and current configuration (read-only)...\e[22m\n`,
  `  \e[2mReport → <path> (mode 0600)\e[22m\n`, `  \e[2m1 source(s) incomplete; review the evidence section.\e[22m\n`;
  failure `  \e[31m✗ Report generation failed. …\e[39m\n`; usage `\e[31m\e[39m\n\e[31m  ✗ --days must be a positive integer\e[39m\n\e[31m\e[39m\n`.
- stdout carries only the document (`--output-file -`); nothing else is ever written to stdout.

### 2.4 Exit codes

0 success; 1 operational failure, `health` `unknown`, or `--strict` with an incomplete source, and commander's
missing-`--workspace` error; 2 usage errors (§3); 130/143 signals (§11).

## 3. Argument checks (exit 2, in this order, before the tenant and any request)

0. Commander: missing `--workspace` → `error: required option '--workspace <ref>' not specified` (exit **1**; captured
   also with `--debug`, so it precedes the refusal). A missing option argument is commander's usual exit-1 error.
1. `prog.ts:139-151` (preAction, also for the `dashboard` alias since `name()` is `report`): `--debug`, or
   `PANW_AI_SEC_DEBUG` matching `^(1|true|yes|on)$` after trim, case-insensitive →
   `Disable --debug and PANW_AI_SEC_DEBUG for environment reports to avoid persisting sensitive traffic content`
   (captured for `--debug` with a blank `--workspace`, for `--debug --max-pages x`, and for `PANW_AI_SEC_DEBUG=on`).
2. Format `opts.output ?? root.output ?? 'html'` not `html`/`markdown` → `Report output must be html or markdown`
   (`ar.ts:45-47`; captured for `table`, `json`, `bogus`, and before a blank `--workspace`).
3. `--workspace` not a string or blank under JS `trim()` → `--workspace cannot be empty` (`ar.ts:48-49`). The value is
   otherwise used as given (not trimmed; ` ws-dev-abc123` matches nothing, §6.3).
4. `--days` not `^[1-9]\d*$` or not a safe integer → `--days must be a positive integer` (`ar.ts:50-51`; captured `0`,
   `1.5`, `9007199254740993`; checked even when `--start` is given: `--days 0 --start …` gives this message).
5. Exactly one of `--start`/`--end` (truthiness, so `--start ''` counts as absent) →
   `--start and --end must be supplied together` (`ar.ts:52-53`).
6. `--start` given and `getOptionValueSource('days') !== 'default'` → `Use --days or --start/--end, not both`
   (`ar.ts:54-55`). An explicit `--days 1` (the default value) still triggers it (captured).
7. Window (`ar.ts:56-67`): `end = --end ? new Date(--end) : new Date()`;
   `start = --start ? new Date(--start) : new Date(end − days × 86 400 000)`. Fails with
   `Provide a valid increasing ISO-8601 window with timezone` when, with `--start`, either value fails
   `z.string().datetime({offset: true})`, or when either date is invalid, or `start >= end`.
   - The zod 3.25 regex (`zod/v3/types.js:406-431`): date `YYYY-MM-DD` with real month lengths and leap years, `T`,
     `HH:MM` with optional `:SS(.d+)?` (hours `00-23`, seconds `00-59`), then `Z` (uppercase only) or
     `[+-]\d{2}:?\d{2}`. Captured: `…T00:00:00Z`, `…T00:00Z`, `….123456789Z`, `+02:00`, `+0200`, `-00:00`, `+23:59`
     pass; `z`, `T00Z`, `+02`, a space for `T`, `2026-02-30`, `24:00:00`, `23:59:60`, `+002026-…` fail.
     `+24:00` passes zod but `new Date` is invalid, so it fails as an invalid date. A value without a zone
     (`2026-10-17T00:00:00`) fails.
   - `new Date` keeps milliseconds and truncates further digits (`.9999` → `.999`, `.123456` → `.123`).
   - `--days` alone: `--days 100000000` gives a valid start in year −271 764 (the report then runs, §6.4 note);
     `--days 200000000` overflows the Date range and fails here (captured).
8. `--max-pages` not `^[1-9]\d*$`, not safe, or `> 100` → `--max-pages must be an integer from 1 to 100`
   (`ar.ts:68-70`; captured `0`, `01`, `101`). Checked after the window (captured: `start == end` with `--max-pages 0`
   gives the window message).
9. `--title` blank under trim or longer than 240 UTF-16 units → `--title must contain 1–240 characters`
   (`ar.ts:71-72`; captured `''`, `'   '`, 241 ASCII, 121 emoji = 242 units).
10. `--output-file` given and blank under trim → `--output-file cannot be empty` (`ar.ts:73-74`).

The window is fixed here, before the config is read; the collection timestamps come later (captured: window end
`…:28.456Z`, collection start `…:28.458Z`).

## 4. Window and query serialisation

### 4.1 The window in the report

`report.window = {start: start.toISOString(), end: end.toISOString()}` (`gwr.ts:87`), millisecond precision, UTC `Z`
(captured `2026-10-18T02:58:55.015Z → 2026-10-19T02:58:55.015Z` for the default day; with
`--start 2026-10-17T00:00:00.123456+0200 --end 2026-10-18T00:00:00Z`:
`2026-10-16T22:00:00.123Z → 2026-10-18T00:00:00.000Z`). The default window is the `days × 24 h` before the moment of
the checks.

### 4.2 The query (`SDK:17968-17995`)

Every telemetry read serialises `{workspaceSlug, start, end}` to
`organisationId=<mgmtTsgId>&workspaceSlug=<slug>&timeOfGenerationMin=<start>&timeOfGenerationMax=<end>` with
`URLSearchParams` (`:` → `%3A`, `+` → `%2B`). `toOffsetIso` formats in the **process's local time zone** with seconds
precision (milliseconds dropped, not rounded) and a `±HH:MM` offset:

| TZ | captured `timeOfGenerationMin` (decoded) |
|---|---|
| `UTC` | `2026-10-18T02:58:55+00:00` |
| unset (host −05:00) | `2026-10-17T22:00:28-05:00` |
| `Asia/Kolkata` | `2026-10-17T03:30:00+05:30` (for `--start 2026-10-17T00:00:00.123456+0200`) |

`toOffsetIso` rejects a date whose **local** year is below 0 or above 9999 (`SDK:17969-17970`), so `--days 100000000`
makes every telemetry source fail its input validation without a request (captured: the requests were token,
admin workspaces, configs, both key lists, org info, catalog; 19 sources incomplete; health `unknown`; exit 1).
`filterBoundaries` deletes `organisationId` (`SDK:18057-18070`); `logs` adds `pageSize` and `currentPage`
(`SDK:18455-18480`). No other parameters are sent (the chart filters are absent).

## 5. Destination

- `--output-file -` → stdout. Otherwise `resolve(--output-file ?? default)` (`ar.ts:75-77`), the default being
  `airs-aigateway-report-<new Date().toISOString() with ':' → '-'>-<first 8 chars of randomUUID()>.<html|md>` in the
  working directory (captured `airs-aigateway-report-2026-10-19T03-00-28.729Z-20113b39.html`; the `.` and `Z` stay).
- Inside the `try` (`ar.ts:78-85`), before `loadConfig`: `lstat(outputPath)`; `ENOENT` continues, anything present
  (file, directory, dangling symlink, captured) throws → the failure line (§10), exit 1, no request, the existing entry
  untouched. Another `lstat` error (e.g. `EACCES`) is the failure line too.
- The parent directory is **not** checked here: `--output-file nodir/r.html` sends the token request and all 25 reads,
  then fails at publication (captured), as `runtime report` did before D214.

## 6. Collection (`collectGatewayEnvironmentReport`, `gwr.ts:63-396`)

### 6.1 Order and wrapper

After the client is built: status `Collecting AI Gateway statistics and current configuration (read-only)...`
(`ar.ts:91`), then the collector with `{title, maxPages, workspace, tsgId: config.mgmtTsgId ?? '', start, end}`. It
first re-checks `maxPages` (1–100) and throws `Invalid report scope` for a blank workspace or TSG or a bad window
(`gwr.ts:67-77`); this throw is outside any source, so it becomes the failure line (reachable only with a whitespace
TSG). `collectionStartedAt = now().toISOString()` (`gwr.ts:85`).

The 25 sources run **one after the other**, in this order (captured):

| # | Source name (= `method`) | Window label | Request |
|---|---|---|---|
| 1 | `workspaces.list` | `Current active tenant workspaces (admin)` | `GET <admin>/workspaces` (no query) |
| 2–18 | `telemetry.<m>` for `m` in `requests, errors, users, cost, latency, tokens, cacheSummary, cacheHitTrend, userTrends, errorTrends, errorCategoryTrends, groupedErrors, rescuedRetries, feedbackTrend, feedbackWeighted, feedbackScoreDistribution, feedbackModels` | `Displayed telemetry window` | `GET <data>/logs/charts/<kebab m>?<window>` (`cache-summary`, `cache-hit-trend`, `user-trends`, `error-trends`, `error-category-trends`, `grouped-errors`, `rescued-retries`, `feedback-trend`, `feedback-weighted`, `feedback-score-distribution`, `feedback-models`) |
| 19 | `telemetry.filterBoundaries` | `Displayed telemetry window` | `GET <data>/analytics/filter-boundaries?workspaceSlug=…&timeOfGenerationMin=…&timeOfGenerationMax=…` |
| 20 | `telemetry.logs` | `Displayed telemetry window` | `GET <data>/logs?<window>&pageSize=50&currentPage=<p>`, `p` = 0, 1, … |
| 21 | `configs.list` | `Current selected workspace configuration` | `GET <data>/configs?workspace_id=<uuid>` |
| 22 | `apiKeys.listService` | `Current selected workspace configuration` | `GET <data>/api-keys/service?workspace_id=<uuid>` |
| 23 | `apiKeys.listUser` | `Current selected workspace configuration` | `GET <data>/api-keys/user?workspace_id=<uuid>` |
| 24 | `organisations.getInfo` | `Current tenant configuration` | `GET <admin>/organisations/<mgmtTsgId>/info` |
| 25 | `guardrails.getCatalog` | `Current tenant capability catalog (not enabled guardrails)` | `GET <admin>/utils/static-resources/schema?resource=guardrails` |

`source(name, window, collect)` (`gwr.ts:127-149`) pushes `{name, method: name, window, status: 'complete', records: 0,
pages: 0, notes: []}` and runs `collect`. A throw sets `status = records ? 'partial' : 'unavailable'` and pushes one
note: `HTTP <code>: request failed; check access and service availability.` when the error's `statusCode` is an
integer 400–599, else `Request, scope or response validation failed; upstream details omitted.` (no server text). A
source that already set `partial` keeps its notes and gains this one.

### 6.2 Envelope and list helpers

- `envelope(v, s)` (`gwr.ts:150-159`): `v` must be a plain object with `success === true` and an object `data`, else
  it throws. `data.isQuotaExceeded !== false` sets `partial` and pushes
  `Quota exceeded or quota state unknown; aggregates may be incomplete.` (once **per call**: three log pages flagged
  give the note three times, joined by spaces, captured). The SDK schema already requires a boolean `isQuotaExceeded`,
  so an absent flag fails validation (`unavailable`, captured).
- `list(v, s)` (`gwr.ts:160-172`): `success === false` or a non-array `data` throws; every row must be a plain object;
  `total` must be a safe non-negative integer (`count`, `gwr.ts:32-36`). `has_more === true` or `total !== rows.length`
  sets `partial` with `List is truncated or total differs; continuation is not documented.` `records = rows.length`,
  `pages = 1`. No further page is ever requested.

### 6.3 `workspaces.list` and the workspace reference (`gwr.ts:175-188`)

The admin-plane list (all active workspaces of the tenant), then the inventory row
`[workspaces.list, Active workspaces returned, <n>]`. Matching: rows whose `id` or `slug` equals `--workspace`
exactly; if none, rows whose `name` equals it exactly. Exactly one match with string `id` and `slug` is required, else
it throws (`Workspace missing or ambiguous`). Because `records` is already set, a missing or ambiguous workspace makes
`workspaces.list` **partial** with the generic note, and every later workspace-bound source throws
`Workspace unresolved` before any request: the 19 telemetry sources and the three workspace inventories are
`unavailable` with the generic note, only `organisations.getInfo` and `guardrails.getCatalog` are read (captured for an
absent ref and a duplicated display name: requests token, admin workspaces, org info, catalog; 23 incomplete; health
`unknown`; exit 1). By id, by slug and by name all resolve (captured). A matched slug that fails the SDK slug regex
(`bad slug`) fails all 19 telemetry sources without a request; a non-UUID id fails the three inventories without a
request (captured: 22 incomplete).

### 6.4 The 17 charts (`gwr.ts:37-60`, `197-276`)

For each chart: `d = envelope(response)`; for each field of `CHARTS[m]`, walk `field.split('.')` with `record()` at each
step (a missing intermediate object throws) and require `numeric(value)`: `null` is kept as `null`, a non-number or
non-finite value throws. Then, unless the value is `null`, `n < 0` throws for non-feedback charts, and a value that is
not a safe integer throws unless the field is fractional: every `feedback*` chart, `cost`, `latency`, and fields ending
in `avg`, `Latency`, `Speedup`, `Rate` or `Percent`. Then `buckets = d.records ?? d.trend` (must be an array when
present), `records = buckets.length` or 1 when both are absent, `pages = 1`. The metric rows are appended **only after
the whole source succeeded** (`gwr.ts:274`).

| `m` | fields kept (Metric column) | SDK schema (required, `SDK:5156-5300`, `5846-5859`) | records |
|---|---|---|---|
| `requests`, `errors`, `users`, `feedbackTrend`, `feedbackWeighted` | `total` (nullable) | `records[]` of `{x: string, y: number}`, `total` number\|null | `records.length` |
| `cost` | `total`, `avg` | `records[]`, `total`, `avg` numbers | `records.length` |
| `latency` | `total`, `p50`, `p90`, `p99` (nullable) | records `{x,y,p50,p90,p99}` | `records.length` |
| `tokens` | `total`, `total_request_units`, `total_response_units` | records `{x,y,total_request_units,total_response_units,avg}`; `total`, `avg`, both unit totals | `records.length` |
| `cacheSummary` | `summary.cacheHits`, `summary.avgCacheLatency` (nullable), `summary.totalRequests`, `summary.cacheSpeedup` | `summary` | 1 |
| `cacheHitTrend` | `summary.totalCacheHits`, `summary.hitRate` | `trend[]` (`x, simpleHits, semanticHits, hitRate, cumulative…Savings`), `total`, `summary` | `trend.length` |
| `userTrends` | `summary.total`, `summary.unique`, `summary.avg` | `summary`, `trend[]` | `trend.length` |
| `errorTrends` | `summary.errorPercent` | `summary`, `trend[]` | `trend.length` |
| `errorCategoryTrends` | `summary.totalErrors`, `summary.totalUniqueErrorCodes` | `summary`, `trend[]` of `{response_status_code, count}` | `trend.length` |
| `groupedErrors` | `total` | `trend[]` of `{x: string, y: [{response_status_code, count}]}`, `total` | `trend.length` |
| `rescuedRetries` | `total`, `retryTotal`, `fallbackTotal` | `trend[]` (`{x, y: []}`), `total`, `trends[]`, both totals | `trend.length` |
| `feedbackScoreDistribution` | `total` (nullable) | `records[]` of `{x: number, y: number}` | `records.length` |
| `feedbackModels` | none; adds `[feedbackModels, Models with feedback, <records>]` | `records[]` of `{x, y: {avgWeightedFeedback, feedbackCount}}` | `records.length` |

Captured: a negative `requests.total`, a fractional `requests.total` (1.5) and `success: false` make the source
`unavailable` with the generic note; `cost.total = 1e21` and `cost.avg = 1e-7` are kept; `feedbackWeighted.total` −0.5
and `-0` are kept; `isQuotaExceeded: true` makes the source `partial` (records 0, pages 1) and keeps its rows.

**`errorCategoryTrends`** (`gwr.ts:222-256`): each trend entry becomes a row `[response_status_code, count]` of the
`Error categories` table (both must be safe non-negative integers), in server order, pushed before the metrics. Findings,
in this order: any entry with `200 ≤ code < 300` and `count > 0` → `review` `Success-status responses appear in error
analytics` / `The server classifies some HTTP 2xx responses as errors. Error analytics are not identical to non-2xx
transaction counts.` / `Inspect the underlying application/provider error classifications before calculating an HTTP
failure rate.`; then any `count > 0` with `code === 429 || code >= 500` → `attention` `Rate limiting or server errors
observed` / `Error categories include HTTP 429 or 5xx responses in the selected window.` / `Review provider availability,
quotas and retry policies; correlate with transaction logs.`; otherwise any `count > 0` → `review` `Gateway errors or
policy blocks observed` / `Nonzero error-category counts were returned.` / `Review status categories; distinguish expected
AIRS blocks from integration failures.` The `source` of each is `telemetry.errorCategoryTrends`. Zero counts raise
nothing (captured `[500, 0]`: health `No findings in available evidence`).

**`groupedErrors`** (`gwr.ts:257-273`): for each bucket, `x` must be a string with a finite `Date.parse(x)` and `y` an
array; each `y` entry becomes `[new Date(x).toISOString(), code, count]` in the `Error timeline` table (captured
`2026-10-17T11:00:00+02:00` → `2026-10-17T09:00:00.000Z`). `Date.parse` also accepts date-only (`2026-10-17`, UTC
midnight) and zone-less or RFC-2822-like forms (`2026-10-17T10:00`, `Oct 17 2026 10:00`) **in the local time zone**,
so those rows depend on `TZ`. An invalid bucket throws after `records` was set: the source is `partial`
(captured: records 1, pages 1, no `Error timeline` rows and no `groupedErrors total` metric).

### 6.5 `telemetry.filterBoundaries` (`gwr.ts:277-285`)

`envelope`, then for `unique_ai_models` and `unique_status_codes` (must be arrays) the metric rows
`[filterBoundaries, unique_ai_models count, <len>]` and `[filterBoundaries, unique_status_codes count, <len>]`;
`records = 1`, `pages = 1`. The values themselves (model names, environments, keys, metadata keys, which the SDK
documents as possibly sensitive) are never kept.

### 6.6 `telemetry.logs` (`gwr.ts:286-342`)

The `Transaction coverage` table is pushed before the read. Page loop, `currentPage = 0 … maxPages − 1`, `pageSize = 50`:
1. `d = envelope(logs page)`; `pages++` (only pages that parsed count).
2. `total = count(d.total)`; the first page fixes `expected`. `total !== expected`, a non-array `records` or more than 50
   records → throw (`Unstable page`).
3. Each record: `id` a non-empty string not seen before (across pages) and `workspace_slug === <resolved slug>`, else
   throw (`Invalid identity`); `Date.parse(created_at)` finite and within `[start, end]` **inclusive** (ms), else throw
   (`Outside window`); `response_status_code` a safe non-negative integer; then `ids.add`, the per-code counter, and
   `records = ids.size`.
4. `ids.size > expected` → throw; `ids.size === expected` → done (complete); an empty page before that → throw
   (`Premature empty page`).
5. After `maxPages` pages without reaching `expected`: `partial` with
   `Transaction page budget reached. Increase --max-pages to collect the remaining rows.`

`finally` always appends `[Server total, <expected> | null]`, `[Unique collected, <ids.size>]` and one
`[HTTP <code>, <n>]` row per code in ascending numeric order (`gwr.ts:337-341`), so a failed read still shows
`Server total` `Unknown` and `Unique collected` `0`.

Captured: 120 transactions → pages 0, 1, 2 (`complete`, 120/120, `HTTP 200` 60, `HTTP 429` 30, `HTTP 446` 30);
`--max-pages 2` → pages 0, 1, `partial` 100 records, 2 pages, the budget note, and with `--strict` exit 1; total 0 → one
page, complete, `Server total 0`; a duplicated id → `partial` (records 1); a record outside the window → `unavailable`
(records 0, **pages 1**, `Server total 3`); server total 5 with 3 records → page 1 empty → `partial` 3/2 pages; server
total 2 with 3 records → `partial` (`Unexpected total`); a 500 → `unavailable`, pages 0, `Server total Unknown`.
Zone-less `created_at` values are parsed in local time (as §6.4). Raw log rows (models, users, trace ids, URLs, key
ids, metadata) are never kept.

### 6.7 Inventories

- `configs.list`, `apiKeys.listService`, `apiKeys.listUser` (`gwr.ts:343-354`): `list()` and the inventory row
  `[<method>, Rows returned, <n>]`. Captured: `has_more: true` or `total: 7` with one row → `partial` with the list note.
- `organisations.getInfo` (`gwr.ts:355-364`): the SDK schema `GatewayOrganisationInfoSchema` (`SDK:5879-5906`; id, name,
  timestamps, `settings` with eleven fields, `benefits.limits` a record of numbers, `featureFlags`, `subscription`)
  must pass; the row `[organisations.getInfo, Configured limit categories, <keys of benefits.limits>]`; records 1,
  pages 1. Limit values (including `-1` sentinels) are not shown.
- `guardrails.getCatalog` (`gwr.ts:365-374`): `GatewayGuardrailCatalogResponseSchema` (`SDK:5907-5928`); the row
  `[guardrails.getCatalog, Available evaluators, <evals.length>]`; records = `evals.length`.
- Captured: org info 500 and catalog 404 → both `unavailable` with their `HTTP` notes.

### 6.8 Incomplete-evidence findings and health (`gwr.ts:375-394`)

After all sources, one `review` finding per non-complete source in source order: title
`Incomplete evidence: <name>`, evidence = its notes joined by `' '`, recommendation `Resolve source access or validation
problems and rerun. Do not interpret missing metrics as zero.`, source `<name>`. **Findings are not sorted**: the
error-category findings (pushed during collection) come first.

`health`: `unknown` when no source whose name starts with `telemetry.` is complete; otherwise `attention` when any
finding is `attention`, `review` when there is any finding, else `no-findings`. `generatedAt = now().toISOString()`.
Note that `telemetry.logs` counts: with all 17 charts and the boundaries failing (503) but the logs complete, the health
is `review` and the exit 0 (captured).

## 7. The report model and tables

`{schemaVersion: 1, product: 'Prisma AIRS AI Gateway', schemaLabel: 'AI Gateway', windowLabel: 'Telemetry window (UTC)',
title, collectionStartedAt, generatedAt, window, health, sources, findings, tables, limitations}` (`gwr.ts:79-101`).
Table order (the `section id`s): `table-0` `Telemetry metrics`, `table-1` `Error categories`, `table-2`
`Error timeline`, `table-3` `Current configuration and capabilities`, `table-4` `Transaction coverage`, `table-5`
`Evidence and completeness` (added by the renderer, `er.ts:16-34`).

| Table | Note | Headers |
|---|---|---|
| Telemetry metrics | `Server field names are preserved. cost: cents; latency and avgCacheLatency: ms; errorPercent: percent. Feedback is not a request count.` | `Source`, `Metric`, `Value` (Source is the bare method, e.g. `cacheSummary`) |
| Error categories | `Server-reported errors by HTTP status; 446 denotes an AIRS block.` | `HTTP status`, `Errors` |
| Error timeline | `Server UTC buckets; counts by HTTP status. Not a count of unique violating sessions.` | `UTC bucket`, `HTTP status`, `Errors` |
| Current configuration and capabilities | `Aggregate counts only. Active tenant workspaces are tenant-wide; keys and configs use the selected workspace.` | `Source`, `Metric`, `Value` |
| Transaction coverage | `Unique collected transactions by HTTP status; only complete pagination represents the entire window. Raw rows are excluded.` | `Metric`, `Value` |
| Evidence and completeness | `Complete means the source was collected within its budget, not that the environment is secure. Unavailable is not zero.` | `Source`, `SDK method`, `Window`, `Status`, `Records`, `Pages`, `Notes` (`Collection completed.` when no notes) |

The seven limitations, in order (`gwr.ts:92-100`):
1. `Read-only operational evidence, not a security certification or availability SLA. No inference or configuration changes are performed.`
2. `All telemetry uses the displayed fixed window. Configuration and organisation/catalog reads describe current state, not daily changes.`
3. `Requests, errors, feedback and log totals are independent server aggregates, not an atomic snapshot. An AIRS block is not necessarily an outage.`
4. `Cost values are cents; latency values are milliseconds. Feedback scores may be negative. Null means unknown, not zero.`
5. `Only aggregate numbers and HTTP status codes are retained. Keys, user identities, workspace names/IDs, metadata, URLs, prompts, raw logs and configuration bodies are excluded.`
6. `Catalog entries describe available capabilities, not enabled protection. Organisation limit sentinel values are not interpreted as quota exhaustion.`
7. `Incomplete sources and page budgets are explicit. Current inventory lists have no verified continuation contract; total/has_more mismatches are partial.`

## 8. Rendering

### 8.1 HTML (`renderEnvironmentReportHtml`, `er.ts:90-107`; the red team renderer of DESIGN §15.17)

The document is the §15.17 renderer byte for byte with these inputs: `product` `Prisma AIRS AI Gateway`, window label
`Telemetry window (UTC)` (red team: `Scan creation window (UTC)`), footer label `AI Gateway` (red team: `Red Team`),
the gateway tables and limitations. The CSS and JS constants are the same, so the CSP is the same string (captured):

```
default-src 'none'; script-src 'sha256-vxcVmn+OlgkxEN2VQ7q63vmVAZ/uCr6B1goVcd7EK6c='; style-src 'sha256-jPa0PJ+rVzL3fveVWR9DWnRPrxPWaM+zQ/+OnWDs2+A='; connect-src 'none'; base-uri 'none'; form-action 'none'
```

written into the `content` attribute through `html()`, so each `'` is `&#39;`. Skeleton (one line after the first
`\n`; `{…}` are inserted values, `h(…)` is `html()`):

```
<!doctype html>\n
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="h(policy)"><meta name="referrer" content="no-referrer"><title>h(title)</title><style>{CSS}</style></head><body><a class="skip" href="#main">Skip to report</a><header><p>h(product)</p><h1>h(title)</h1><span class="badge">{HEALTH label}</span><p>Collection: h(collectionStartedAt) → h(generatedAt)</p><p>h(windowLabel): h(window.start) → h(window.end)</p><p>Read-only evidence · Confidential environment metadata</p></header><main id="main"><nav aria-label="Report sections"><a href="#findings">Attention</a><a href="#table-0">Evidence tables</a><a href="#scope">Scope</a></nav><section id="findings"><h2>What needs attention</h2><div class="controls js-only"><label for="priority">Priority</label><select id="priority"><option value="all">All</option><option value="attention">Attention</option><option value="review">Review</option></select><span id="count" role="status"></span><button id="print" type="button">Print / save PDF</button></div>{findings}</section>{sections}<section id="scope"><h2>Scope and limitations</h2><ul>{<li>h(limitation)</li>…}</ul></section><footer>Prisma AIRS CLI · AI Gateway report schema 1 · Works offline and without JavaScript.</footer></main><script>{JS}</script></body></html>\n
```

- `{findings}`: per finding `<article class="finding" data-priority="h(priority)"><h3>h(title)</h3><p>h(evidence)</p><p><strong>Next step:</strong> h(recommendation)</p><p class="note">h(source)</p></article>`,
  or `<p>No findings in available evidence; this does not establish absence of risk.</p>`.
- `{sections}`: per table `i`: `<section id="table-i"><h2>h(title)</h2><p class="note">h(note)</p>` then, with rows,
  `<div class="table-wrap" role="region" aria-label="h(title)" tabindex="0"><table><caption>{rows} aggregate rows</caption><thead><tr><th scope="col">h(header)</th>…</tr></thead><tbody><tr><td>h(cell)</td>…</tr>…</tbody></table></div>`,
  without rows `<p>No rows collected; consult source completeness before interpreting this as empty.</p>`; then `</section>`.
- `HEALTH`: `Attention required`, `Review required`, `No findings in available evidence`, `Unable to assess` (not escaped).
- `html(v) = String(v ?? 'Unknown').replace(/[&<>"']/g, c => '&#' + code + ';')`: `&#38; &#60; &#62; &#34; &#39;`
  (captured title `<b>&"'</b> Q3` → `&#60;b&#62;&#38;&#34;&#39;&#60;/b&#62; Q3` in `<title>` and `<h1>`). Nothing else is
  escaped: C0 controls in `--title` reach the document raw (captured `A\x1b[31mB\x07`).
- Cells: a string as is; `null` → `Unknown` (captured `latency p99`, `summary.avgCacheLatency`, `feedbackTrend total`,
  `Server total` of a failed log read); a number through ECMAScript `Number::toString` (captured `1234.5`, `102.875`,
  `8.33`, `-0.5`, `-0` → `0`, `1e+21`, `1e-7`); counts as integers.
- Captured sample: 15 231 bytes with the default fixture, health `Review required`, `34 aggregate rows` of metrics,
  `25 aggregate rows` of evidence, one trailing `\n`.

### 8.2 Markdown (`er.ts:37-89`, TypeScript only)

`--output markdown` writes `# md(title)`, `**md(product)**`, `Assessment: **<HEALTH>**`, `Collection: <a> → <b>`,
`md(windowLabel): <start> → <end>`, `## What needs attention`, per finding `### <PRIORITY>: md(title)` / `Evidence:` /
`Next step:` / `Source:`, the tables as pipe tables (`| --- |` separators), `## Scope and limitations` with `- ` items and
`Prisma AIRS CLI · AI Gateway report schema 1`, lines joined by `\n` with a final `\n`. `md()` maps
`& < > " ' \ ` * _ [ ] { } ( ) | ! # ~` to `&#<code>;` and CR/LF to a space (captured `T <x> | y_z` →
`T &#60;x&#62; &#124; y&#95;z`, `(UTC)` → `&#40;UTC&#41;`). The default file name ends in `.md`.

## 9. Publishing and exit (`ar.ts:100-115`, `io.ts:6-19`)

- File: `writeReportFile(path, rendered)`: `open(<dir>/.airs-report-<uuid>.tmp, 'wx', 0o600)`, `writeFile` UTF-8,
  `sync`, `close`, `link(temp, path)` (fails with `EEXIST` if the destination appeared meanwhile), and in `finally` a
  second `close` and `unlink(temp)`. No directory sync. Captured mode `-rw-------`; no temporary left after success or a
  read-only directory failure. Then the status `Report → <path with \p{Cc}\p{Cf} → _> (mode 0600)` (captured
  `a\tb​c.html` printed as `a_b_c.html`).
- stdout (`--output-file -`): `process.stdout.write(rendered, cb)`; no `Report →` line. Writing to a closed pipe is
  **not** handled: node prints an unhandled `'error'` event stack trace (`Error: write EPIPE … at Command.<anonymous>
  (file:///…/dist/cli/index.js:5699:15)`) on stderr and exits 1 (captured with `| true`). The redteam/runtime
  integration specs describe "propagates stream errors" (`aigateway-dashboard.spec.ts:120`), but on a real pipe the
  socket error escapes the promise.
- Then, when `n = sources not complete > 0`, the status `<n> source(s) incomplete; review the evidence section.`
- Exit 1 when `health === 'unknown'` or (`--strict` and `n > 0`), with the document written; else 0.

## 10. Failures (captured)

Every throw after the argument checks prints only
`  ✗ Report generation failed. Verify Management API configuration and a writable, new output path. Existing files are never overwritten.`
(stderr, red, never suppressed) and exits 1 (`ar.ts:116-122`); no path, OS error, SDK or server text.

| Case | stderr before the failure line | Requests | File |
|---|---|---|---|
| existing file, directory or dangling symlink | none | none | untouched |
| missing `mgmtClientSecret` (credential assertion) | none | none | none |
| invalid tenant config | none | none | none |
| missing parent directory, read-only directory | `Collecting …` | token + 25 reads | none, no temporary |
| stdout `EPIPE` | `Collecting …` then node's stack trace instead of the line | token + 25 reads | n/a, exit 1 |

Source-level failures never reach this line; they become `unavailable`/`partial` sources (§6). Token failures too: a
token `401` makes `workspaces.list`, `organisations.getInfo` and `guardrails.getCatalog` each try a token request (three
`POST /oauth/token`, no API request) and fail with `HTTP 401: request failed; …`; the other 22 sources fail
`Workspace unresolved` with the generic note; all 25 incomplete, `Unable to assess`, exit 1, the file written. A
malformed token body gives the generic note for those three.

## 11. Interruption

No handler is installed. SIGINT or SIGTERM during collection ends node at once: exit 130/143, stderr only the
`Collecting …` line, no file and no temporary (captured with a hung `cost` chart, both for a file and for stdout
delivery). A temporary exists only between `open` and `unlink`. A hung request without a signal ends after
`PANW_AI_SEC_TIMEOUT_MS` (captured 700 ms: `telemetry.cost` `unavailable` with the generic note; the report continues).

## 12. Sensitive-data exposure

- The document holds aggregates only: counts, numeric server metrics, HTTP status codes, bucket times, the title, the
  window and the collection timestamps. Captured: no workspace slug, id, name, scope name, key id or name, config
  name, org id or name, model, user, trace id, URL, filter-boundary value or catalog entry appears (`grep` of
  `PRIVATE`, `ws-dev`, `11111111` in HTML and Markdown: 0).
- The workspace reference is resolved but never printed; the resolved slug and id appear only in query strings.
- No server error text is printed or stored. The failure line names no path. The `Report →` line prints the absolute
  path with control and format characters replaced by `_`.
- `--debug` and `PANW_AI_SEC_DEBUG` are refused, so request URLs (with the slug and workspace id) and bodies are
  never logged.
- `--title` is not cleaned of control characters (§8.1); on stdout delivery to a terminal they reach the terminal.

## 13. Comparison with the Rust report rules (DESIGN §15.17, §18.14)

What carries over unchanged from §15.17 (same TS modules `er.ts`, `io.ts`):
- The checks for `--debug` (D156), `--output` (D155), `--max-pages`, `--title` and `--output-file`, with the same texts.
- The destination rule (`-`, absolute path, `lstat` before the tenant, the failure line), the publisher
  (`files::publish_new`), the `Report →` and `<n> source(s) incomplete` status lines, the exit rule (`unknown` or
  `--strict`), the failure line, the interrupt contexts, and the client built without an upfront token request.
- The HTML skeleton, CSS, JS, CSP and `&#<code>;` escaper of `src/report/html.rs` (the hashes match the capture).

What the gateway report needs beyond §15.17:
- **New options and checks** in TS order after `--output`: `--workspace` required (clap error, exit 2, where commander
  exits 1) and non-blank; `--days` (`^[1-9]\d*$`, safe); the `--start`/`--end` pairing; `--days` given explicitly with
  `--start` (needs clap's value source, since `--days 1` counts); the zod `datetime({offset: true})` grammar and the
  `Date` validity and order; then `--max-pages`, `--title`, `--output-file`. TS puts the format check before the
  workspace check; §15.17 already puts `--debug` and `--output` first, which matches.
- **Renderer parameters**: `src/report/html.rs` hard-codes `PRODUCT` (`Prisma AIRS AI Red Teaming`), the window label
  `Scan creation window (UTC)`, the footer `Red Team` and `LIMITATIONS`; the gateway report needs `Prisma AIRS AI
  Gateway`, `Telemetry window (UTC)`, `AI Gateway` and its own seven limitations. `Cell` has only `Text` and `Count`;
  the gateway needs `Null` (→ `Unknown`) and a JS number (`render::js_number`, which already prints `-0` as `0`).
- **Different source notes**: `HTTP <code>: request failed; check access and service availability.` and
  `Request, scope or response validation failed; upstream details omitted.` (red team: `HTTP <code>: source
  unavailable; …` and `Source request or validation failed. …`). Additional fixed notes: the quota note, the list note,
  the log budget note.
- **No sorting** of findings (the red team and runtime reports sort by priority); the incomplete-evidence findings
  come after the error-category findings.
- **Order and budgets**: TS reads sequentially already (as §18.14). One budget per source (§15.17: 300 s,
  `with_retries(0)`); `telemetry.logs` spends its pages from it.
- **G7**: TS replays a 401 or 403 (not a 403 with `x-opa-decision: false`); the §15.17 CLI re-read after an `Http`
  401/403 `Rejected` applies, and it also re-reads an OPA-denied 403, which TS does not (the CLI cannot see the header).
- **Windows**: the window and its query are new. scm-sdk's `AIGatewayWindowOptions` (`rs:airs/gateway/telemetry.rs:9-67`)
  formats `timeOfGenerationMin/Max` with an explicit `offset_minutes` (default 0, UTC) and seconds precision; TS uses the
  local zone (§4.2). The instants are equal; the bytes differ unless TS runs with `TZ=UTC`.
- **Time parsing**: `Date.parse` of `created_at` and bucket `x` (§6.4, §6.6) needs the §15.17 `parse_iso`
  approximation; TS also accepts date-only and zone-less forms in local time.
- **Parent directory**: TS reads all 25 sources before failing on a missing parent; §18.14's D214 check before the
  tenant applies equally.
- **Renames**: the command `gateway report|dashboard`, the help examples, and (recommended) the default file name
  `airs-gateway-report-…`. The product strings inside the report (`Prisma AIRS AI Gateway`, `AI Gateway report schema 1`,
  the default title `AI Gateway environment report`) name the product, not the command, and stay.

## 14. Doctor: TS `AI Gateway API` (check 10, `doc.ts:462-516`, probe `doc.ts:627-632`)

### 14.1 Placement and gating

Tenth of eleven checks (`doc.ts:51-63`), after `Management OAuth`, before `Typesafe API`. It runs only when
`Management credentials` passed (`hasMgmt`, `doc.ts:713-717`); otherwise `skip` /
`skipped — management credentials not configured` (captured). When the tenant check failed it is
`not evaluated — fix the failed checks above first` like every later check (`doc.ts:670-672`).

### 14.2 How it finds and authenticates to the gateway

`defaultAiGwProbe(config)` (`doc.ts:628-632`): `new SdkAiGatewayService(aiGatewayClientOptions(config))` (a **new**
`AIGatewayClient`, so a second OAuth client and token request; **no** `numRetries`, so the SDK default 5,
`SDK:11111-11114`), then `listWorkspaces()` = `client.workspaces.list()` with no options (`svc.ts:110-113`): the
**data plane**, `GET <aiGwDataEndpoint ?? https://api.apps.paloaltonetworks.com/ai_gw/v2>/workspaces`, no query,
`Authorization: Bearer`, `x-tsg-id: <mgmtTsgId>`; the result is `data.length` (the workspaces the service account holds
a workspace-scope grant on). Credentials and token endpoint are the shared `mgmt*` values (§2.1); `aiGwAdminEndpoint`
and `iamEndpoint` are not used by the probe. The probe is time-boxed by `withTimeout(…, 5000)` (`doc.ts:330-342`), a
race that abandons, not cancels, the request.

Captured sequence: `POST token, GET <mgmt>/v1/mgmt/topics/tsg/100?offset=0&limit=100` (Management OAuth), then
`POST token, GET <data>/workspaces` (AI Gateway API).

### 14.3 Outcomes (`doc.ts:467-516`; `httpStatus` = `err.status ?? err.statusCode`)

| Case (captured) | Status | Detail | Hint |
|---|---|---|---|
| 2xx, n rows | pass | `endpoint reachable (<n> workspace[s] in scope)` (`0 workspaces`, `1 workspace`) | none |
| 403 (after the token replay; with `x-opa-decision: false` no replay) | **warn** | `endpoint reachable, but access denied (HTTP 403): <SDK message>` | `aiGatewayGrantHint(err)` |
| 401 (after the replay) | fail | `AI Gateway API error (HTTP 401): AISEC_CLIENT_SIDE_ERROR:bad token` | `Verify the tenant credentials and network connectivity` |
| 404, 429 | fail | `AI Gateway API error (HTTP <s>): AISEC_CLIENT_SIDE_ERROR:<server message>` | as above |
| 500 | fail | `timed out after 5000ms — network unreachable or endpoint not responding` (four GETs with backoff inside 5 s) | `Check network connectivity to api.apps.paloaltonetworks.com` |
| hang | fail | the timeout detail | the same hint |
| 2xx body failing the schema | fail | `network unreachable: AISEC_RESPONSE_VALIDATION:Response did not match schema: object: invalid_type; total: invalid_type` | `Verify the tenant credentials and network connectivity` |
| token 401 | fail | `AI Gateway API error (HTTP 401): AISEC_OAUTH_ERROR:<error_description from the token response>` | as above |
| no `aiGwDataEndpoint` | fail (here: guard refused the production host, retried, then the 5 s timeout) | the timeout detail | the same hint |

`aiGatewayGrantHint` (`svc.ts:87-100`): for a 403, when the SDK message contains `AB03`, `the service account is missing
a workspace-scope grant (data plane, /ai_gw/v2)`, otherwise `the service account is missing a tenant-root admin grant
(admin plane, /ai_gw/admin/v2)`, followed by `. SCM Access Management edits the existing role row by default — use "Add
Role" so the account ends up with both role rows, not one row moved.` The SDK puts `AB03` into the message only when the
error body has `data.errorCode` (`extractErrorMessage`, `SDK:9713-9725`: `<message> (errorCode: AB03)`); a body with a
top-level `errorCode` (captured `{"errorCode":"AB03","message":"Workspace scope grant missing"}`) or none gives the
**admin-plane** hint although the probe only touched the data plane.

### 14.4 Layouts (captured)

Pretty (stdout; hint 6 spaces, dim):
```
  ⚠ AI Gateway API — endpoint reachable, but access denied (HTTP 403): AISEC_CLIENT_SIDE_ERROR:Not authorised (errorCode: AB03)
      the service account is missing a workspace-scope grant (data plane, /ai_gw/v2). SCM Access Management edits the existing role row by default — use "Add Role" so the account ends up with both role rows, not one row moved.
```
JSON: `{"name":"AI Gateway API","status":"pass","detail":"endpoint reachable (1 workspace in scope)"}`; table row
`AI Gateway API │ pass │ endpoint reachable (1 workspace in scope) │`. A warn never fails the doctor; a fail exits 1.

### 14.5 Sensitive data

The detail embeds the SDK message, which is server text (`message`, `error_message`, `data.message`, the token
response's `error_description`): captured `PRIVATE-desc` from a token 401 printed in the detail. The workspace names are
not printed (only the count).

## 15. Proposed Rust `Gateway API` check (for DESIGN §9; the M6e milestone)

- **Name and place**: `Gateway API` (MILESTONES: renamed doctor checks), the eighth check, after `Management OAuth`;
  D19 becomes 8 checks. JSON, table and pretty rendering as the other checks.
- **Gating**: as TS: `skip` `skipped — management credentials not configured` when management credentials are
  missing; notEvaluated when they were not evaluated.
- **Probe**: the `gateway` feature of scm-sdk 0.1.1 (`AIGatewayClient::new(data, admin, iam)`,
  `rs:airs/gateway/mod.rs`; `workspaces().list(&AIGatewayWorkspaceListOptions::default(), …)`,
  `rs:airs/gateway/workspaces.rs:41-66`), data plane `GET {gatewayDataEndpoint ?? DEFAULT_AI_GW_DATA_ENDPOINT}/workspaces`
  (`rs:constants.rs:625`), `x-tsg-id` set by `common::oauth` (`rs:airs/gateway/common.rs:10-13`), the shared `mgmt*`
  OAuth token (the provider of `ManagementClients`, so one token for both probes), one attempt (D49 extended: no 5xx/429
  retries, no 401/403 replay), within the 5 s probe budget, a cancel → `Interrupted` with no data written.
- **Outcomes** (recommended; TS texts where they are safe): pass `endpoint reachable (<n> workspace[s] in scope)`; 403 →
  warn `endpoint reachable, but access denied (HTTP 403): <message>` with the grant hint; 429 → warn `endpoint reachable,
  but rate limited (HTTP 429): <message>` / `Retry later` (as the Rust Scanner API); 5xx → fail `gateway API error (HTTP
  <s>): <message>` / `Retry later; check the AIRS service status`; other HTTP (401, 404 …) → fail `gateway API error
  (HTTP <s>): <message>` / `Verify the tenant credentials and network connectivity`; a 2xx body that does not decode →
  fail `gateway API error: <message>` / `Fix gatewayDataEndpoint in the tenant file`; transport → fail
  `network unreachable: <message>` / `Check network connectivity, proxy settings, and DNS`; deadline (no HTTP status
  received) → fail `timed out after 5000ms — network unreachable or endpoint not responding` / `Check network
  connectivity and the gatewayDataEndpoint setting`; a token failure → the Management OAuth wording. `<message>` is
  `error::facts_message` (SDK metadata only, §6).
- **Tests**: loopback only; the harness fixture tenants must carry `gatewayDataEndpoint` (else the default production
  host would be contacted); the runner's endpoint check covers it.

## 16. scm-sdk 0.1.1 coverage (pointers)

Every read exists with the TS frozen schemas (`rs:models/generated.rs`, e.g. `CountChartResponse` `s006684`):
`telemetry().{requests, errors, users, cost, latency, tokens, cache_summary, cache_hit_trend, user_trends, error_trends,
error_category_trends, grouped_errors, rescued_retries, feedback_trend, feedback_weighted, feedback_score_distribution,
feedback_models, filter_boundaries, logs}` (`rs:airs/gateway/telemetry.rs:261-610`; `filter_boundaries` drops
`organisationId`, `logs` takes `page_size`/`current_page`), `workspaces().list` with `AIGatewayPlane::Admin`,
`configs().list`, `api_keys().list_service|list_user` (UUID-checked), `organisations().get_info` (numeric TSG),
`guardrails().get_catalog` (`/utils/static-resources/schema?resource=guardrails` on the admin client). The `gateway`
feature (which enables `iam`) is not yet enabled in the CLI. Typed models keep unknown keys (`extensions`), so the
collector can run TS's checks over the serialised JSON (`OValue`) as §15.17 does.

## 17. TS specs to port (acceptance tests)

- `tests/unit/reports/aigateway.spec.ts`: 2xx error classifications (`:26`), policy blocks vs outages (`:38`), signed
  feedback and fractional cost (`:54`), no fallback workspace (`:63`), all 25 sources with one window and no sensitive
  fields (`:73`), zero-based pages and unique transactions (`:105`), budget and inventory truncation (`:159`), quota and
  missing metrics (`:182`), `success: false` and `unknown` (`:196`), server errors, UTC trends, escaped titles (`:203`).
- `tests/integration/cli/aigateway-dashboard.spec.ts`: HTML despite a JSON preference (`:50`), the alias (`:58`),
  Markdown (`:87`, TS only), stdout-only artifact and stream errors (`:120`), unique default files (`:136`), partial
  reports and `--strict` (`:152`), exit 1 with a diagnostic report when nothing is available (`:164`), existing paths
  refused before credentials and network (`:175`), invalid config not exposed (`:184`).
- `tests/unit/cli/doctor.spec.ts` (AI Gateway cases near `:452-683`) and `tests/unit/airs/aigateway.spec.ts:538-560`
  (`aiGatewayGrantHint`).

## Acceptance criteria

1. `gateway report|dashboard` accepts exactly `--workspace` (required), `--days` (default `1`), `--start`, `--end`,
   `--output-file`, `--title` (default `AI Gateway environment report`), `--max-pages` (default `40`) and `--strict`;
   `--output` is refused (D155) and `--debug` refused first (D156).
2. The checks of §3 run in that order with those texts, exit 2, before the tenant is read and before any request; a
   missing `--workspace` is a usage error.
3. The window is fixed at check time; the report header shows it with milliseconds; the queries carry it with seconds
   precision and an explicit offset; the log window check is inclusive at both ends.
4. An existing path (dangling symlink included) and a missing parent fail with the failure line and no request.
5. The 25 sources are read sequentially in §6.1 order with the §6.1 paths and queries, one budget each, no retries, and
   the G7 re-read; one token per run.
6. The workspace resolves by exact id or slug, then by exact name; zero or several matches make `workspaces.list`
   partial and the workspace-bound sources unavailable without requests.
7. Chart, boundary, log and inventory validation, records, pages, notes and rows follow §6.2–§6.7; a failing source
   adds no metric rows; the log coverage rows are always written.
8. Findings appear in TS push order; health follows §6.8 (`telemetry.logs` counts as telemetry).
9. The HTML equals TS's bytes for the same model (the shared renderer with the gateway product, window label, footer
   label, limitations, `Unknown` for null and ECMAScript number strings), including the CSP of §8.1 and one trailing
   `\n`.
10. Publishing, status lines, the failure line, exit codes and interrupt contexts follow §15.17; no temporary is left.
11. Nothing in the document or on any stream carries workspace names, slugs, ids, keys, users, models, URLs, metadata
    or server error text.
12. The doctor's `Gateway API` check probes the data-plane workspace list with the shared OAuth token, one attempt, 5 s,
    and classifies the outcomes of §15.

## Open questions / likely §12 divergences

1. **Command rename and file name** (MILESTONES renames): `gateway report|dashboard`; recommend the default file
   `airs-gateway-report-<time>-<8 hex>.html` and `airs-cli-rs gateway report …` help examples (new §12 row; the report
   title and product strings keep `AI Gateway`).
2. **D155/D156 extended** to the gateway report (HTML only; `PANW_AI_SEC_DEBUG` not read).
3. **Missing `--workspace`**: commander exit 1 before the debug refusal; clap exit 2 (the general parse-error row).
4. **D214 extended**: the parent directory is checked before the tenant (TS reads 25 sources first).
5. **Query offsets**: recommend scm-sdk's UTC (`+00:00`) instead of the local zone; same instants (§12 row, or parity
   fixtures run TS with `TZ=UTC`). Related: TS rejects a window whose *local* year leaves 0–9999 (`--days 100000000`);
   with UTC the boundary moves by the offset.
6. **`Date.parse` approximations** for `created_at` and bucket `x`: date-only as UTC midnight is easy; zone-less and
   RFC-2822-like forms are local time in TS. Recommend accepting only the zoned ISO form plus date-only (choice like
   §18.14 choice 52) and recording the difference.
7. **stdout `EPIPE`**: TS crashes with a node stack trace (exit 1); Rust prints the failure line (exit 1), as §15.17.
8. **G7 and OPA**: the Rust re-read also repeats a 403 that TS does not replay (`x-opa-decision: false`); harmless for a
   read, worth a sentence in the §12 G7 row.
9. **Health from logs alone**: all charts failing but logs complete gives `review`, exit 0. TS parity is safe (every
   failing source is marked and listed); confirm it is kept.
10. **Control characters in `--title`**: written raw into the document and to stdout. Recommend keeping the bytes in
    the file (data) and deciding whether stdout delivery to a TTY should apply `terminal_safe` (it would change the
    document).
11. **Repeated quota note** per log page: keep TS bytes (recommended) or collapse.
12. **Doctor check (D19, D49 extended)**: name `Gateway API`; one attempt, so a 5xx is reported as such (TS: retries
    into the 5 s timeout and says "timed out"); 429 warns; a malformed 2xx is not "network unreachable"; the hint names
    `gatewayDataEndpoint`, not the production host; server text never printed (TS prints the token
    `error_description`).
13. **Doctor grant hint**: TS gives the admin-plane hint for every data-plane 403 whose SDK message lacks `AB03`. Since
    the probe only reads the data plane, recommend the workspace-scope (data-plane) hint for every 403 (§12 row), or
    keep TS's rule if scm-sdk exposes the body's `data.errorCode` in error metadata.
14. **One token for both doctor probes** (TS: two token requests): recommend sharing the provider; if the Management
    OAuth token fetch failed, decide between reporting the same token failure again (TS) or `skip` with a pointer to
    `Management OAuth`.
