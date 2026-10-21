# Spec: TS `airs-cli` AgentGuard (`supplychain` in airs-cli-rs, M6f)

Commands covered: `agentguard scans list|ls`, `agentguard scans vulnerabilities <scanUuid>`, `agentguard stats`, `agentguard rules list|ls` and `agentguard report` (the environment report). That is the whole `agentguard` tree: there are no writes, no deletes, no prompts and no hidden commands. MILESTONES renames the tree to `supplychain` (no alias). "`supplychain report`" is the TypeScript `agentguard report`. It exists (`ag.ts:233-291`, collector `rep.ts`), so §9 specifies it from source and captures. It is not an analogy with the other reports.

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0, SDK `@cdot65/prisma-airs-sdk` 0.34.0, commander 14, zod 3.25.76, js-yaml 4, chalk 5). Citations:
  - `ag.ts` is `src/cli/commands/agentguard.ts` (292 lines, the whole command tree); `rep.ts` is `src/reports/agentguard.ts` (the collector); `er.ts` is `src/reports/environment-render.ts` (HTML and Markdown, shared with the red team and AI Gateway environment reports); `io.ts` is `src/reports/io.ts` (`writeReportFile`); `typ.ts` is `src/reports/types.ts`.
  - `prog.ts` is `src/cli/program.ts`; `co.ts` is `src/config/client-options.ts`; `schema.ts` is `src/config/schema.ts`; `common.ts` and `ui.ts` are under `src/cli/renderer/`; `dbg.ts` is `src/cli/debug-logger.ts`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` of the reference build. `zod:<line>` is `node_modules/zod/v3/types.js`.
  - `rs:<file>:<line>` is `~/.cargo/registry/src/*/scm-sdk-0.1.1/src/<file>`.
  - TS tests: `tests/integration/cli/agentguard.spec.ts` (`it.spec`), `tests/unit/reports/agentguard.spec.ts` (`ut.spec`) and `tests/helpers/agentguard.ts` (fixtures).
- Shared shell behaviour is specified elsewhere and restated here only where AgentGuard depends on it: commander parse errors exit 1, the root `--output` consumer, `resolveOutput`, `ui`, quiet, colour and EPIPE are in `ts-cli-shell.md` and `ts-renderer.md`, and the debug log is in `ts-debug-log.md`. The environment-report renderer is the one the Rust port already ships for red team (DESIGN §15.17, `src/report/html.rs`).
- How behaviour was captured: the reference build (`dist/cli/index.js`, node v24.21.0) ran against a loopback stub (`node:http` on `127.0.0.1`, random port). The stub implemented:
  - `POST /oauth/token`;
  - the data plane under `/aiag/data`: `GET /v1/scans`, `GET /v1/stats/scans` and `GET /v1/scans/<id>/vulnerabilities`;
  - the management plane under `/aiag/mgmt`: `GET /v1/rules`.

  Pages honoured `skip` and `limit`. The scans answer carried `pagination.total_items` = the scan count, and the rules answer `total_items` = the length of the returned page (the observed server behaviour that `SDK:14753-14756` documents). Every request was logged: method, path, raw query, auth scheme, `x-tsg-id`, `User-Agent`, `service-name`, content type and body. A per-route fault plan could set a status, a raw body, headers, a sequence of answers or a hang.
  - Sandbox: `env` reduced to `PATH`, `HOME`, the `XDG_*` variables, `TMPDIR`, `PRISMA_AIRS_TENANTS_PATH` and `AIRS_CLI_CONFIG_DIR`, all inside the sandbox, plus `NO_PROXY`. One TS registry tenant, `test` (TSG `100`, `fake-client` / `FAKE-SECRET-100`), with `mgmtTokenEndpoint` `<base>/oauth/token`, `agentGuardDataEndpoint` `<base>/aiag/data` and `agentGuardMgmtEndpoint` `<base>/aiag/mgmt`. Fixture ids are `11111111-1111-4111-8111-<12 digits>` (written `U(n)`); fake sensitive values are `PRIVATE-…`.
  - Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and `dns.lookup` and refuses any host other than loopback. It fired exactly once, as designed: with `agentGuardDataEndpoint` removed, the stats read went to `api.apps.paloaltonetworks.com`, was refused, and printed the generic failure.
  - Signals were sent with `kill(SIGINT|SIGTERM)` 1.5 s into a hung request.
- No real tenant or credential file was read, and no host other than loopback was contacted.
- Captures are JSON strings and uncoloured (stdout a pipe) unless stated. Every run makes one token request (`POST /oauth/token`, Basic auth, `User-Agent: node`, `Content-Type: application/x-www-form-urlencoded`, body `grant_type=client_credentials&scope=tsg_id%3A100`) before its first API request. The request lists below omit it.

## 1. Command surface (help verified)

Registration: `prog.ts:198` calls `registerAgentGuardCommand` (`ag.ts:136-292`), which registers `scans` (with `list` and `vulnerabilities`), `stats`, `rules` (with `list`) and `report`. The post-registration passes (`prog.ts:204-206`) then do three things:
- They add the alias `ls` to both `list`s.
- They add `--all` (`Walk all pages`) and `--max <n>` (`Maximum items with --all; 0 removes the cap`, parser `Number`, default `10000`) to both `list`s, because those already declare `--limit` and `--offset` (`prog.ts:60-67`).
- They sort options and subcommands in help.

Every leaf except `report` already declares `--output`, so no `--output` is added. No `rm` alias is added, because nothing is named `delete`.

| Command | Registration | Arguments and options (help text; defaults) |
|---|---|---|
| `scans list\|ls` | `ag.ts:141-177` | `--limit <n>` (`Page size`, `integer`, `10`), `--offset <n>` (`Starting offset`, `integer`, `0`), `--output <format>` (`Output format: pretty, table, markdown, csv, json, yaml`), `--start <iso>` (`Inclusive creation time start (ISO timestamp)`), `--end <iso>` (`Creation time end (ISO timestamp)`), added `--all`, `--max` |
| `scans vulnerabilities <scanUuid>` | `ag.ts:178-203` | `--include-content` (`Include source code, paths and finding text (sensitive)`), `--output <format>` |
| `stats` | `ag.ts:204-211` | `--output <format>`, `--time-period <period>` (`Verified period: 30_DAYS`, default `"30_DAYS"`) |
| `rules list\|ls` | `ag.ts:212-231` | `--limit`, `--offset` (as scans), `--output`, added `--all`, `--max` |
| `report` | `ag.ts:233-291` | `--output <format>` (`Deliverable: html (default) or markdown`), `--output-file <path>` (`New file in CWD by default; - for stdout; never overwrite`), `--max-pages <n>` (`Page budget per inventory (1–100, 10 rows/page)`, `integer`, `40`), `--title <text>` (`Report title`, default `"AgentGuard environment report"`), `--strict` (`Exit 1 after writing if any source is incomplete`) |

`integer` (`ag.ts:25-29`) accepts only `^\d+$` that is a safe integer. Otherwise it fails at **parse time** with `Pagination requires a safe nonnegative integer` (exit 2, before the tenant). This applies to `--max-pages abc` too, which is the wrong message for that flag. Leading zeros are accepted (`--limit 007` sends `limit=7`).

Captured help (stdout, exit 0). Root list line: `  agentguard          AI Supply Chain agent and skill scan telemetry\n                      (experimental, OAuth)`.

```
Usage: airs-cli agentguard [options] [command]

AI Supply Chain agent and skill scan telemetry (experimental, OAuth)

Options:
  -h, --help        display help for command

Commands:
  help [command]    display help for command
  report [options]  Generate an aggregate-only 30-day HTML/Markdown report
  rules             Rule catalog (not effective tenant policy)
  scans             Inspect agent and skill scans (read-only)
  stats [options]   Read server rolling 30-day skill statistics
```

```
Usage: airs-cli agentguard scans [options] [command]

Inspect agent and skill scans (read-only)

Options:
  -h, --help                            display help for command

Commands:
  help [command]                        display help for command
  list|ls [options]                     List one page of scans; sensitive
                                        metadata is excluded
  vulnerabilities [options] <scanUuid>  List finding metadata; --include-content
                                        explicitly reveals sensitive details
```

```
Usage: airs-cli agentguard scans list|ls [options]

List one page of scans; sensitive metadata is excluded

Options:
  --all              Walk all pages
  --end <iso>        Creation time end (ISO timestamp)
  -h, --help         display help for command
  --limit <n>        Page size (default: 10)
  --max <n>          Maximum items with --all; 0 removes the cap (default:
                     10000)
  --offset <n>       Starting offset (default: 0)
  --output <format>  Output format: pretty, table, markdown, csv, json, yaml
  --start <iso>      Inclusive creation time start (ISO timestamp)
```

`scans vulnerabilities --help`: `List finding metadata; --include-content explicitly reveals sensitive details` with `--include-content  Include source code, paths and finding text (sensitive)` and `--output`. `stats --help`: `Read server rolling 30-day skill statistics` and `--time-period <period>  Verified period: 30_DAYS (default: "30_DAYS")`. `rules --help`: `Rule catalog (not effective tenant policy)` with `list|ls [options]  List rule catalog defaults`. `rules list --help`: as `scans list`, without `--start` and `--end`. `report --help`:

```
Usage: airs-cli agentguard report [options]

Generate an aggregate-only 30-day HTML/Markdown report

Options:
  -h, --help            display help for command
  --max-pages <n>       Page budget per inventory (1–100, 10 rows/page)
                        (default: 40)
  --output <format>     Deliverable: html (default) or markdown
  --output-file <path>  New file in CWD by default; - for stdout; never
                        overwrite
  --strict              Exit 1 after writing if any source is incomplete
  --title <text>        Report title (default: "AgentGuard environment report")
```

## 2. Shared behaviour

### 2.1 Client, endpoints and credentials

- `createClient` (`ag.ts:23-24`) is `new AgentGuardClient({ ...agentGuardClientOptions(await loadConfig()), numRetries: 0 })`. It builds one client per action and reads the tenant again.
- `agentGuardClientOptions` (`co.ts:53-59`) passes explicit values for everything the SDK could otherwise read from the environment:
  - `clientId`, `clientSecret`, `tsgId` and `tokenEndpoint` (`mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`), after `assertManagementCredentials` (`co.ts:34-42`);
  - `dataEndpoint: agentGuardDataEndpoint ?? AGENT_GUARD_DATA_ENDPOINT` (`https://api.apps.paloaltonetworks.com/aiag/data`, `SDK:180`);
  - `mgmtEndpoint: agentGuardMgmtEndpoint ?? AGENT_GUARD_MGMT_ENDPOINT` (`…/aiag/mgmt`, `SDK:181`).
- The SDK's fallbacks are therefore never reached: `PANW_AGENT_GUARD_DATA_ENDPOINT`, `PANW_AGENT_GUARD_MGMT_ENDPOINT` (`SDK:14696-14697`) and the `PANW_AGENT_GUARD_*` / `PANW_MGMT_*` credentials (`resolveOAuthConfig`, `SDK:11099-11104`). Captured: with `PANW_AGENT_GUARD_DATA_ENDPOINT=http://127.0.0.1:1/x`, `PANW_AGENT_GUARD_CLIENT_ID=other` and `PANW_MGMT_TSG_ID=999` set, the requests still went to the tenant's endpoints with TSG 100.
- Tenant keys (`schema.ts:32-33`): `agentGuardDataEndpoint` and `agentGuardMgmtEndpoint` are `z.string().url()`. An invalid value makes the whole config invalid; captured: `\n  ✗ Error: Cannot read a valid tenant config at <path>\n\n`, exit 1. `agentGuardTokenEndpoint` is a retired key, ignored (`schema.ts:66-71`). In airs-cli-rs these keys are `supplychainDataEndpoint` and `supplychainMgmtEndpoint` (DESIGN §3.3 rows 17-18, D71).
- Planes (`SDK:182-184`, `SDK:14725-14765`): scans, stats and vulnerabilities use the data endpoint (`/v1/scans`, `/v1/stats/scans`, `/v1/scans/<id>/vulnerabilities`). Rules use the management endpoint (`/v1/rules`). Base URLs lose trailing slashes (`SDK:10117`).
- Auth: `TsgHeaderAuth(OAuthAuth)` (`SDK:14662-14678`, `SDK:14704`). Every API request carries `Authorization: Bearer <token>` **and `x-tsg-id: <tsg>`** (captured `tsg=100`). AgentGuard is the only management product so far that sends the TSG header. Other headers: `User-Agent: PAN-AIRS/0.34.0-typescript-sdk` and `service-name: api`. GETs carry no `Content-Type` and no body.
- The token is lazy. `new AgentGuardClient` makes no request, and the first read fetches it. One token per invocation is cached in the client; the report reuses one client for all three sources.
- **Retries: none.** `numRetries: 0` (`ag.ts:24`) passes through `resolveOAuthConfig` (`SDK:11111-11114`, clamp to 0..5). Captured: 500, 503 with `Retry-After: 0`, and 429 each sent **one** GET. The one exception is the SDK's auth replay (`SDK:10208-10230`): a 401, or a 403 without `x-opa-decision: false`, clears the token and replays once. Captured sequences:
  - 401: `token, GET(401), token, GET(401)`;
  - 403: the same;
  - 403 with `x-opa-decision: false`: `token, GET(403)` only.
- Per-attempt timeout: `PANW_AI_SEC_TIMEOUT_MS`, default 60 s (`SDK:10095`). Captured with `300`: a hung list sent one GET and failed with the generic message. No total budget exists; the report runs its three sources one after another, so it can take 3 × 60 s.
- Redirects: the SDK's `fetch` follows them by default. Captured: a 302 to another loopback port was followed and failed with the generic message.

### 2.2 Output format resolution

- The read leaves (`list`, `vulnerabilities`, `stats`) are in `READ_COMMAND_NAMES` and declare `--output`. So the `preAction` hook (`prog.ts:162-175`) runs `resolveOutput` (`common.ts:48-75`) for them:
  - it reads the tenant (no tenant → `\n  ✗ Error: No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'\n\n`, exit 1);
  - it applies the root `--output` (the root consumes every `--output`, the last one wins: `--output table --output json` printed JSON) or else the tenant's `defaultOutput` (captured: `defaultOutput: "json"` made `scans list` print JSON) or else `pretty`;
  - it rejects unknown values: `\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n`, exit 2;
  - it stores the result. `run` calls `resolveOutput` again (`ag.ts:83`), which reads the tenant a second time.
- `markdown`, `csv` and `yaml` work in TS (captured). airs-cli-rs drops them (D50).
- `report` is an environment report (`prog.ts:139-144`): `preAction` skips `resolveOutput`. The action reads `opts.output ?? program.opts().output ?? 'html'` (`ag.ts:242`), which in practice is the root value. The tenant's `defaultOutput` is ignored (captured: `defaultOutput: "json"` still wrote HTML).

### 2.3 Streams, quiet, colour

- stdout carries the data only: the table or the JSON, YAML, Markdown or CSV text, or the report document with `--output-file -`. There is **no banner**. `ui.header` is not used anywhere in `ag.ts`.
- stderr carries:
  - `ui.status` lines (`"  <dim msg>\n"`, quiet-suppressed): `Returned <n> records; see JSON/YAML for pagination metadata.`, `Report → <path> (mode 0600)` and `<n> source(s) incomplete; review the evidence section.`;
  - `ui.error` lines (`"  <red ✗ msg>\n"`, never suppressed);
  - `usageError` (`"\n  <red ✗ msg>\n\n"`), commander errors and the `--debug` status line.
- With `--quiet`, captured: `scans list` printed the same table with an empty stderr, and `report --strict` with a failing source printed nothing at all and exited 1.
- ANSI (captured, `FORCE_COLOR=1`):
  - status `"  \e[2mReturned 1 records; see JSON/YAML for pagination metadata.\e[22m\n"`;
  - error `"  \e[31m✗ AgentGuard request failed (HTTP 500). Check credentials, query options and service availability. No upstream body is included.\e[39m\n"`;
  - usage `"\e[31m\e[39m\n\e[31m  ✗ Invalid AgentGuard query. …\e[39m\n\e[31m\e[39m\n"`.

  Tables and JSON are never coloured.

### 2.4 Errors and exit codes

The read actions run their bodies inside `run` (`ag.ts:81-92`), and every throw becomes **one fixed line**. In particular, a tenant, config or credential error *inside* `run` is printed with this line and not with its own message:

`  ✗ AgentGuard request failed[ (HTTP <s>)]. Check credentials, query options and service availability. No upstream body is included.` (stderr, exit 1, via `process.exitCode = 1`)

` (HTTP <s>)` is present only when the error has an integer `statusCode` from 400 to 599 (`ag.ts:86-89`).

| Situation | Message (captured) | Exit |
|---|---|---|
| commander: unknown option, missing positional, excess argument | `error: unknown option '--bogus'`, `error: missing required argument 'scanUuid'`, `error: too many arguments for 'list'. Expected 0 arguments but got 1.`, `error: unknown option '--limit'` (on `vulnerabilities`) | 1 |
| `--limit`, `--offset` or `--max-pages` not `^\d+$` or not a safe integer (`abc`, `1.5`, `-1`, `9007199254740993`) | `Pagination requires a safe nonnegative integer` (parse time, before the tenant) | 2 |
| invalid `--output` (read leaves) | `Invalid output format 'xml'. Expected: …` (after the tenant read) | 2 |
| query check `query()` (`ag.ts:36-43`): `--limit 0`, a bad or reversed `--start`/`--end`, a non-UUID `scanUuid`, `--time-period` other than `30_DAYS` | `Invalid AgentGuard query. Check pagination, UUID and ISO timestamps; statistics support 30_DAYS only.` (after the tenant read) | 2 |
| `--max` not a safe non-negative integer (with or without `--all`) | `--max must be a safe nonnegative integer` (`ag.ts:99-100`; after the credential check) | 2 |
| missing management credential (e.g. no `mgmtClientSecret`) | the generic line, without the credential message | 1 |
| HTTP 4xx/5xx (token endpoint included: a token 401 gives `(HTTP 401)`) | the generic line with ` (HTTP <s>)`; the server text is never printed (captured with `{"message":"PRIVATE-ECHO server text"}`) | 1 |
| invalid JSON, schema mismatch (e.g. a scan row without its required keys, a non-integer `count`), timeout, network error, followed redirect failure | the generic line without a status | 1 |
| pagination guard (`Unstable pagination`, `Repeated identity`, `Invalid total`, `Premature empty page`, `Pagination safety limit reached`, `ag.ts:109-132`) | the generic line; the internal text is not printed; nothing on stdout | 1 |
| SIGINT / SIGTERM | nothing printed (the process dies by the signal: 130 / 143 in a shell) | 130 / 143 |

### 2.5 Validation order (captured)

For the read leaves:
1. Commander parses the arguments. The `integer` parser runs here, which is why `--limit abc` is exit 2 even without a tenant.
2. `preAction` runs: quiet, then the tenant read and format check, then the debug log.
3. The action's `query()` check runs (exit 2).
4. `run` starts: `resolveOutput` again, then `createClient` (tenant, `assertManagementCredentials`; failures are the generic line, exit 1).
5. `inventory`'s `--max` check runs (exit 2; lists only).
6. Token, then requests.

Captured:
- no tenant with `--limit 0`: the no-tenant error, exit 1;
- no tenant with `--limit abc`: exit 2;
- missing secret with `--max abc`: the generic line, exit 1;
- missing secret with `--limit 0`: exit 2.

### 2.6 Interruption

There are no signal handlers. SIGINT or SIGTERM during a hung `scans list` or `report` killed the process: stdout and stderr were empty, and no report file was written. Nothing is written before collection ends; the temporary file exists only inside `writeReportFile`. Derived from source: a signal between `open(temporary)` and `unlink` (`io.ts:7-18`) would leave `.airs-report-<uuid>.tmp` in the destination directory.

### 2.7 `--debug` and `PANW_AI_SEC_DEBUG`

- For the read leaves, `--debug` creates `debug-api-<ms>-<8 hex>.jsonl` (0600, `wx`) in the **current directory** and prints `  Debug: API log → <abs path>` on stderr (captured). The logger is installed with `omitBodies: true` for any command under `agentguard` (`prog.ts:115-118,183`), and `/aiag/` paths are body-less in any case (`dbg.ts:166-169`). Records therefore hold the method, the URL with its query (`skip`, `limit`, `start_time`, `end_time`, `time_period`; secret-named parameters masked), the redacted headers, the status and the timing. Request and response bodies are `[BODY OMITTED]`. Only PANW hosts are logged (`dbg.ts:12-17`), so the loopback captures produced 0-byte files.
- `PANW_AI_SEC_DEBUG=1` prints SDK lines on stderr (captured):
  - `[airs-sdk] → GET http://127.0.0.1:<port>/aiag/data/v1/scans?skip=0&limit=10&isBackgroundRefresh=false`
  - `[airs-sdk]   headers {"User-Agent":"PAN-AIRS/0.34.0-typescript-sdk","service-name":"api","Authorization":"sha256:<12 hex>","x-tsg-id":"100"}`
  - `[airs-sdk]   body [BODY OMITTED]`
  - `[airs-sdk] ← 200 (1ms) [BODY OMITTED]`

  Every AgentGuard request sets `omitDebugBody: true` (`SDK:14719`). So `PANW_AI_SEC_DEBUG_BODY=1` prints no body, not even for `--include-content` (captured).
- `report` refuses `--debug` (before or after the leaf) and `PANW_AI_SEC_DEBUG` matching `^(1|true|yes|on)$` (case-insensitive, trimmed) in `preAction` (`prog.ts:139-151`): `\n  ✗ Disable --debug and PANW_AI_SEC_DEBUG for environment reports to avoid persisting sensitive traffic content\n\n`, exit 2. This comes before every argument check (captured with `PANW_AI_SEC_DEBUG=yes`).

## 3. Lists: the `inventory` walk (`ag.ts:94-133`)

`inventory(read, opts, pageCount)` is the CLI's own loop. It does not use the SDK's `collectSkipPages`. Its rules:
- `cap = opts.all ? (opts.max || Number.MAX_SAFE_INTEGER) : opts.limit`. **`--offset` is honoured with `--all`** (captured: `rules ls --all --offset 5 --max 12` sent `skip=5&limit=10`, then `skip=15&limit=2`).
- For each page, at most 1000 pages: `limit = min(opts.limit, cap − rows)`, then `read(offset + rows, limit)`.
- `total` is the first page's `total_items`. Each page is then checked:
  - when `!pageCount`, a page whose `total_items` differs from `total` throws `Unstable pagination`;
  - a page with more rows than `limit` throws `Unstable pagination`;
  - a row with an empty `uuid`, or a `uuid` already seen in this walk, throws `Repeated identity`;
  - when `!pageCount`, `next = offset + rows` and `next > total` with rows collected throws `Invalid total`.
- `complete` is `rows.length < limit` for a page-count walk and `next >= total` otherwise.
- The loop returns when `!opts.all`, or when the walk is `complete`, or when `rows === cap`. A non-final empty page throws `Premature empty page`. After 1000 pages it throws `Pagination safety limit reached`.
- The result's `pagination` is `{total_items, returned, skip: opts.offset, next_offset: complete ? null : next, truncated: !complete}`. `total_items` is the server total for scans. For rules it is `rows.length` only when `complete && offset === 0`, else `null`.

**Parsing quirks.**
- `--max` uses commander's `Number`, not `integer`. It accepts `0x2` (2), `1e0` (1), `' 2 '` (2) and `''` (0, meaning no cap); all were captured.
- `--max` is validated even without `--all`.
- `--max 0` removes the item cap but not the 1000-page bound. With `--limit 10`, a tenant with more than 10,000 rows fails with the generic line and prints nothing.
- `--limit` has no upper bound (`--limit 101` sent `limit=101`).
- `--limit 0` is rejected by the SDK schema (`count2.positive()`), not by `integer`.

| Command | Request (captured; query keys in the order sent) |
|---|---|
| `scans list` | `GET <data>/v1/scans?skip=<o>&limit=<l>&isBackgroundRefresh=false[&start_time=<v>][&end_time=<v>]`. Values are `URLSearchParams`-encoded (`:` → `%3A`, `+` → `%2B`), and `isBackgroundRefresh=false` is always sent (`ag.ts:149-155`, schema key order `SDK:9481-9485`). With `--all`, `skip` grows by the rows collected; captured `--limit 1 --all` over 3 rows: `skip=0`, `skip=1`, `skip=2` |
| `rules list` | `GET <mgmt>/v1/rules?skip=<o>&limit=<l>`. With `--all`, the walk continues until a short page; captured 25 rules: `skip=0,10,20`; 20 rules: `skip=0,10,20` (the third page is empty, which ends the walk as complete) |
| `scans vulnerabilities` | `GET <data>/v1/scans/<scanUuid as typed>/vulnerabilities` with no query, one page only, no `inventory` |
| `stats` | `GET <data>/v1/stats/scans?time_period=30_DAYS` (`SDK:14736-14741`) |

Captured outcomes:
- scans, `--limit 2` over 3: `{"total_items":3,"returned":2,"skip":0,"next_offset":2,"truncated":true}`;
- `--offset 2`: `returned 1, skip 2, next_offset null, truncated false`;
- `--offset 5` past a total of 2: `returned 0, skip 5, next_offset null, truncated false`, exit 0;
- an empty first page with `total_items: 5`: `returned 0, next_offset 0, truncated true`, exit 0;
- `--all --max 2 --limit 1`: `returned 2, next_offset 2, truncated true`;
- rules: a full first page of 10 reports `{"total_items":null,"returned":10,"skip":0,"next_offset":10,"truncated":true}`. A catalog of exactly `--limit` rules always looks truncated without `--all`.

Each of these failed with the generic line, exit 1 and an empty stdout:
- a repeated row on page 2;
- `total_items` changing between pages;
- an empty page while more rows were expected (`--all`);
- 2 rows for `limit=1` (also without `--all`);
- 2 rows with `total_items: 1`;
- a row with `uuid: ""`.

## 4. Records and their projections

Response schemas (`SDK:9403-9480`, all `.passthrough()`, counts `int().nonnegative().safe()`):
- **scan**: `uuid, tsg_id, created_at, updated_at, name, git_url|null, artifact_type, status, error_message|null, summary{vulnerability_count, attack_chain_count}|null, eval_outcome|null, eval_summary{total_rules, blocked, allowed}|null, eval_details{rule_outcomes[…], skill_override_applied, unknown_findings}|null, duration_seconds|null, fingerprint, scanner_version|null, device_metadata (record)|null, parent_uuid|null, is_batch, child_scan_uuids[], batch_summary (unknown)`.
- **vulnerability**: `uuid, tsg_id, created_at, updated_at, scan_uuid, title, description, vulnerability_type, file_path, node_id|null, node_type|null, node_name|null, remediation_description|null, original_code|null, suggested_code|null, attack_chain_count, attack_chain_uuids[], type_description`.
- **rule**: `uuid, name, vulnerability_types[], default_state, description, remediation`.
- **stats**: `unique_skills_scanned{count, percent_change (finite)|null}, total_vulnerabilities_found{…}, top_vulnerability{vulnerability_type, finding_count}|null`.

Every listed key is required, including the nullable ones. Lists are `{pagination{total_items, …passthrough}, scans|vulnerabilities|rules[]}`.

What each command prints:

| Command | Printed record | Dropped |
|---|---|---|
| `scans list` (`ag.ts:164-174`) | `uuid, artifact_type, status, eval_outcome, created_at, vulnerability_count (summary?.… ?? null), attack_chain_count (?? null), is_batch, parent_uuid`, in this order | `name`, `git_url`, `fingerprint`, `device_metadata`, `error_message`, `eval_summary`, `eval_details`, `scanner_version`, `child_scan_uuids`, `batch_summary`, `tsg_id`, `updated_at`, `duration_seconds`, passthrough |
| `scans vulnerabilities` (`ag.ts:190-200`) | without `--include-content`: `uuid, scan_uuid, vulnerability_type, attack_chain_count`; with it: **the whole wire record, passthrough included** | — |
| `rules list` | the whole wire record, passthrough included | — |
| `stats` | the whole wire object, passthrough included | — |

JSON documents (`ag.ts:45`, `JSON.stringify(v, null, 2)` plus `\n`):
- `scans list`: `{"pagination": {<inventory pagination>}, "scans": [...]}`.
- `rules list`: `{"pagination": {...}, "rules": [...]}`.
- `scans vulnerabilities`: `{"pagination": <server pagination as sent>, "vulnerabilities": [...], "content_included": <bool>}`.
- `stats`: the server object as sent.

Captured `scans list --output json` (3 rows, fragment):

```
{
  "pagination": {
    "total_items": 3,
    "returned": 3,
    "skip": 0,
    "next_offset": null,
    "truncated": false
  },
  "scans": [
    {
      "uuid": "11111111-1111-4111-8111-000000000101",
      "artifact_type": "SKILL",
      "status": "COMPLETED",
      "eval_outcome": "BLOCKED",
      "created_at": "2026-10-19T01:57:59.751Z",
      "vulnerability_count": 2,
      "attack_chain_count": 1,
      "is_batch": false,
      "parent_uuid": null
    },
    …
      "status": "RUNNING",
      "eval_outcome": "PENDING",
      "created_at": "…",
      "vulnerability_count": null,
      "attack_chain_count": null,
…
```

Captured `scans vulnerabilities <U(101)> --output json`: `{\n  "pagination": {\n    "total_items": 2\n  },\n  "vulnerabilities": [\n    {\n      "uuid": "<U(301)>",\n      "scan_uuid": "<U(101)>",\n      "vulnerability_type": "SECRET_EXPOSURE",\n      "attack_chain_count": 0\n    },\n    …\n  ],\n  "content_included": false\n}\n`. With 0 findings: `{"pagination": {"total_items": 0}, "vulnerabilities": [], "content_included": false}` in the same layout.

## 5. `pretty` and `table` layouts (`emit`, `ag.ts:44-80`)

`pretty` is **identical to `table`** (`format === 'pretty' ? 'table' : format`). It is printed with `console.log(formatOutput(...))` directly, **without the two-space indent** of `ui.table`. The table algorithm (`common.ts:126-139`):
- cells are `displayValue`: `null`/`undefined` → `''`, objects and arrays → `JSON.stringify`, everything else `String`;
- the width is the maximum `.length` (UTF-16 units) of the label and the cells;
- the header is `" " + label.padEnd(w) + " "` per column, joined by `│`;
- the separator is `─` × (w + 2) per column, joined by `┼`;
- each row is laid out like the header;
- lines are joined by `\n`, and `console.log` adds a final `\n`.

**Mode choice.** The first array-valued top-level property of the result (`Object.values(value).find(Array.isArray)`) decides the layout:
- **Record mode.** The columns are the union of the record keys in first-seen order, minus `description` and `remediation`, cut to the first 9. Each label is the key with `_` → space. After the table comes the status `  Returned <n> records; see JSON/YAML for pagination metadata.` (stderr). The pagination object is never shown in a table.
- **Field mode**, when no array exists: rows `{key, value}`, with `value` `JSON.stringify(v)` for objects (so `null` → `null`) and `String(v)` otherwise. The columns are `Field` and `Value`. There is no status line.

Captured `scans list` (pretty and table, 3 rows):

```
 uuid                                 │ artifact type │ status    │ eval outcome │ created at               │ vulnerability count │ attack chain count │ is batch │ parent uuid 
──────────────────────────────────────┼───────────────┼───────────┼──────────────┼──────────────────────────┼─────────────────────┼────────────────────┼──────────┼─────────────
 11111111-1111-4111-8111-000000000101 │ SKILL         │ COMPLETED │ BLOCKED      │ 2026-10-19T01:57:59.616Z │ 2                   │ 1                  │ false    │             
 11111111-1111-4111-8111-000000000102 │ AGENT         │ COMPLETED │ ALLOWED      │ 2026-10-19T01:57:59.616Z │ 2                   │ 1                  │ false    │             
 11111111-1111-4111-8111-000000000103 │ SKILL         │ RUNNING   │ PENDING      │ 2026-10-19T01:57:59.616Z │                     │                    │ false    │             
```

stderr `"  Returned 3 records; see JSON/YAML for pagination metadata.\n"`. Every line, the header included, ends with a padding space before `\n`. `null` metrics and `parent_uuid` are empty cells.

Captured `rules list` (the default columns: `uuid, name, vulnerability_types, default_state`; `description` and `remediation` filtered):

```
 uuid                                 │ name   │ vulnerability types │ default state 
──────────────────────────────────────┼────────┼─────────────────────┼───────────────
 11111111-1111-4111-8111-000000000201 │ Rule 1 │ ["SECRET_EXPOSURE"] │ BLOCKING      
```

Captured `scans vulnerabilities` without `--include-content`:

```
 uuid                                 │ scan uuid                            │ vulnerability type │ attack chain count 
──────────────────────────────────────┼──────────────────────────────────────┼────────────────────┼────────────────────
 11111111-1111-4111-8111-000000000301 │ 11111111-1111-4111-8111-000000000101 │ SECRET_EXPOSURE    │ 0                  
```

With `--include-content`, the first 9 non-filtered wire keys are shown: `uuid │ tsg id │ created at │ updated at │ scan uuid │ title │ vulnerability type │ file path │ node id`. `description` is filtered, but `remediation_description`, `original_code` and the others survive in JSON only, beyond column 9.

Empty record lists (0 vulnerabilities, or a `scans list` page with no rows): `formatOutput([], [], 'table')` is `''`, so stdout is `"\n"` and stderr carries `Returned 0 records; …`.

Captured `stats`:

```
 Field                       │ Value                                                      
─────────────────────────────┼────────────────────────────────────────────────────────────
 unique_skills_scanned       │ {"count":4,"percent_change":12.5}                          
 total_vulnerabilities_found │ {"count":7,"percent_change":null}                          
 top_vulnerability           │ {"vulnerability_type":"SECRET_EXPOSURE","finding_count":3} 
```

`top_vulnerability: null` prints `null`. Passthrough keys add rows. **Quirk:** a passthrough array in the stats answer switches to record mode. Captured `"history":[{"day":"d1","n":1}]` printed only ` day │ n ` / ` d1  │ 1 ` and `Returned 1 records; …`. The three statistics vanished.

Server text is printed raw. Captured: an `artifact_type` of `SK\e[31mILL\nX` and a stats passthrough value `x\e[31mRED\nline` reached stdout with the ESC and the newline, breaking the table.

Dropped formats (TS only, captured): `yaml` is `js-yaml` `dump` of the whole object, with no status line. `csv` and `markdown` are `formatOutput` in record or field mode and are followed by the status line.

## 6. `scans list|ls`

- Options are built at `ag.ts:149-155`: `{skip: --offset, limit: --limit, start_time: --start, end_time: --end, isBackgroundRefresh: false}`, checked with `AgentGuardScanListOptionsSchema` (`SDK:9481-9492`):
  - `skip` and `limit` are safe non-negative integers, and `limit` is positive;
  - `start_time` and `end_time` are zod 3 `datetime({ offset: true })` (`zod:423-433`): a leap-year-checked `YYYY-MM-DD`, then `T`, then `HH:MM`, an optional `:SS`, an optional fraction of any length, then **uppercase** `Z` or `±HH:MM` / `±HHMM`;
  - a refine: when both are given, `Date.parse(start) <= Date.parse(end)`.

  Captured:
  - rejected: `bad`, `2026-10-01`, `2026-10-01T00:00:00` (no zone), `…00z` (lowercase), reversed bounds;
  - accepted and sent as typed: `2026-10-20T00:00:00+02:00` and `…00.123456789Z`;
  - by the regex: `2026-02-29T…` is rejected, while `2028-02-29` passes.
- The `scans` array is then projected (§4).
- The bounds filter on the server's `created_at` (the help says `Inclusive` for `--start` only). The CLI does not filter rows locally.

## 7. `scans vulnerabilities <scanUuid>`

- The check (`ag.ts:185`) is zod `uuid()`: `^[0-9a-fA-F]{8}\b-…-[0-9a-fA-F]{12}$/i` (`zod:368`), so any version and any case pass. The SDK's `assertUuid` (`SDK:14746`, `UUID_RE` `SDK:9555`) is the same shape. The value is sent **as typed** (an uppercase `…00000000010A` was sent unchanged) and `encodeURIComponent`-ed, which is a no-op for a valid UUID. `../escape` and `bad` give the query usage error (exit 2).
- There is one GET with no pagination parameters. The server's first page is all the CLI ever shows. `pagination.total_items` is shown in JSON only and is never compared with the row count.
- `--include-content` prints whole finding records (JSON) or the first 9 columns (table): titles, file paths, `original_code`, `suggested_code`, `remediation_description`, `type_description` and passthrough. The SDK documents that this content "may contain secrets" (`SDK:14742`).

## 8. `stats`, `rules list|ls`

- `stats`: `--time-period` must be the literal `30_DAYS` (`SDK:9493`; `30_days` and `week` give the query usage error). It is always sent as `time_period=30_DAYS`. The output is §4 and §5.
- `rules list`: `{skip, limit}` checked with `AgentGuardPageOptionsSchema` (`.strict()`), walked with `pageCount = true` (§3). The rule catalog is defaults only (help: "not effective tenant policy").

## 9. `report` (the supplychain report)

### 9.1 Argument checks (`ag.ts:242-250`; exit 2; in this order, before the tenant)

These run after commander's `integer` parse of `--max-pages` (`Pagination requires a safe nonnegative integer`) and after the `preAction` debug refusal (§2.7):
1. The format is not `html` or `markdown`: `Report output must be html or markdown` (captured for `json`, `yaml` and `xml`).
2. `--max-pages` is not between 1 and 100: `--max-pages must be between 1 and 100`.
3. `--title` is blank under JS `trim()`, or longer than 240 UTF-16 units: `--title must contain 1–240 characters` (240 `x` pass, 241 fail).
4. `--output-file` is given and blank under `trim()`: `--output-file cannot be empty`.

The first failing check wins (captured: `--output xml --max-pages 0` gives the format error, and `--max-pages 0 --title ' '` gives the page error).

### 9.2 Destination (`ag.ts:251-265`)

- `--output-file -` writes to stdout.
- Otherwise the destination is `resolve(--output-file ?? 'airs-agentguard-report-<new Date().toISOString() with ':' → '-'>-<first 8 chars of randomUUID()>.<html|md>')`, relative to the working directory. Captured: `airs-agentguard-report-2026-10-19T03-00-16.233Z-6b8c8bee.html`.
- `lstat(path)`: an existing entry of any kind, including a dangling symlink, is a failure (§9.6) before `createClient`. No request is made (captured; `it.spec:144-151`). A non-ENOENT `lstat` error is a failure too.
- A missing parent directory is **not** checked up front. Captured `--output-file nodir/x.html`: all four requests ran, then the write failed with the failure line.

### 9.3 Collection (`collectAgentGuardReport`, `rep.ts:10-234`)

One client and one token serve all three sources. Every request has `numRetries: 0` and the §2.1 auth replay. The CLI prints no "Collecting…" status line (red team prints one). `end = now()`, `window = {start: end − 30 × 86400000 ms, end}`, both `toISOString()`.

| # | Source (`name`, `method`, `window`) | Requests (captured) |
|---|---|---|
| 1 | `Scans`, `listScans()`, `<start> to <end>` | `GET <data>/v1/scans?skip=<rows so far>&limit=10&isBackgroundRefresh=false&start_time=<start>&end_time=<end>`, until `rows === total` or `--max-pages` pages |
| 2 | `Statistics`, `getScanStats()`, `Server rolling 30_DAYS` | `GET <data>/v1/stats/scans?time_period=30_DAYS` |
| 3 | `Rules`, `listRules()`, `Current catalog` | `GET <mgmt>/v1/rules?skip=<rows so far>&limit=10`, until a page with fewer than 10 rows |

**The page loop `pages`** (`rep.ts:78-119`; not `inventory`):
- Per page, `s.pages++` after a successful read. Then:
  - a page fails when `total_items` is not a safe non-negative integer, `rows` is not an array, or the page has more than 10 rows;
  - when `!pageCount`, it fails when `total_items` differs from the first page's, or when the collected rows would exceed `total`;
  - it fails on an empty or repeated `uuid`.
- Scans return when `rows === total`; rules return on a page with fewer than 10 rows.
- An empty page that does not finish the walk fails.
- After `maxPages` pages the loop adds the note `Reached the <n>-page budget.` and fails.
- Any failure with rows collected turns the source `partial` and adds the note `Inventory incomplete: pagination changed, repeated, stopped early, failed or reached its budget.`; the rows are kept. With no rows it rethrows.

**`source` wrapper** (`rep.ts:46-77`):
- The source starts `unavailable` with 0 pages and 0 records.
- When the read finishes, the source is `complete` unless it was marked `partial`.
- On a throw it becomes `partial` if records were collected, else `unavailable`, plus the note `Request or validation failed; no upstream error body included.`
- Every non-complete source adds the finding `{review, "<name> incomplete", evidence = the notes joined by " ", "Check service access or increase the page budget, then regenerate.", <name>}`.
- No HTTP status is recorded. Unlike red team, there is no `HTTP <code>` note.

**Scans analysis** (`rep.ts:131-171`):
- `inside` keeps the rows whose `Date.parse(created_at)` is finite and lies within `[start, end]`. If any row is excluded, the source is `partial` with the note `Rows with missing or out-of-window creation timestamps were excluded.` `Date.parse` is V8's: it also accepts zone-less and non-ISO forms (local time). Unlike the red team collector, there is no zone regex.
- `leaf` keeps the `inside` rows with `!is_batch && child_scan_uuids.length === 0`. Child rows (with `parent_uuid`) are counted.
- `label(v, allowed)`: `null` → `UNKNOWN`, a value outside `allowed` → `OTHER`. The comparison is case-sensitive (`skill` → `OTHER`). The vocabularies are `SKILL|AGENT` and `BLOCKED|ALLOWED|PENDING|ERROR`.
- The table `Scan outcomes` has the note `Collected <records> rows; excluded <inside − leaf> parent/batch rows. <Partial inventory only.|Complete inventory for requested window.>`, the headers `Artifact / outcome`, `Scan rows`, and rows `["<artifact> / <outcome>", count]` sorted by `localeCompare`. Over this closed ASCII vocabulary, that order is plain byte order.
- Findings:
  - `attention`, `Blocked scans require review`, `<n> collected non-parent scan rows have BLOCKED evaluations.`, `Inspect the affected scans and findings before approving the artifacts.`, when any leaf is `BLOCKED`;
  - `review`, `Scans without a completed decision`, `<n> collected non-parent rows are pending, failed or have an unfamiliar status.`, `Review scan status; absence of a completed decision is not a passing evaluation.`, for leaves with `status !== 'COMPLETED'` or an outcome other than `ALLOWED`/`BLOCKED`.
- A `partial` scans source still produces the table and these findings. The table is pushed only when the read did not throw with zero rows.

**Statistics** (`rep.ts:173-203`):
- The table `Skill statistics` has the note `Server aggregates; percentage changes may be unavailable.`, the headers `Metric`, `Count`, `Change (%)`, and two rows: `Unique skills scanned` and `Vulnerabilities found`, each with its count and `percent_change`, where `null` is rendered `Unknown`.
- When `total_vulnerabilities_found.count > 0`, the source adds the finding `attention`, `Skill vulnerabilities reported`, `<n> findings reported in the server statistics window.`, `Review vulnerability details and remediate before use; findings are not a count of distinct vulnerable skills.`
- The source records `records 1, pages 1`. `top_vulnerability` is not used.

**Rules** (`rep.ts:204-224`): the table `Rule catalog defaults` has the note `These are not effective tenant policy settings.`, the headers `Default state`, `Rules`, and rows `[label(default_state, BLOCKING|ALLOWING), count]` sorted.

**Health** (`rep.ts:225-231`): `unknown` when every source is `unavailable`; else `attention` when any finding is `attention`; else `review` when any finding exists; else `no-findings`. The finding order is the scans findings, then the scans-incomplete finding, then the stats finding, then the rules-incomplete finding (captured). `generatedAt = now()` at the end.

Constants: `schemaVersion 1`, product `Prisma AIRS AI Supply Chain — AgentGuard`, default title `AgentGuard environment report`, `windowLabel` `30-day scan inventory; rolling 30_DAYS statistics; current rule catalog`, `schemaLabel` `Experimental browser APIs`. The five `limitations` are at `rep.ts:37-41` and appear in the capture in §9.4.

Captured token failure (token endpoint 401): three token requests, one per source and none replayed. All three sources were `unavailable`, the health was `Unable to assess`, the file was written, stderr had `Report → …` and `3 source(s) incomplete; …`, and the exit was 1.

### 9.4 Rendering (`er.ts`)

**HTML** (`renderEnvironmentReportHtml`, `er.ts:96-107`) is the template the Rust port already emits for red team (`src/report/html.rs`), with four parameters that differ:
- `<header><p>Prisma AIRS AI Supply Chain — AgentGuard</p>`;
- `<p>30-day scan inventory; rolling 30_DAYS statistics; current rule catalog: <start> → <end></p>`, where red team prints `Scan creation window (UTC): …`;
- the AgentGuard limitations;
- the footer `Prisma AIRS CLI · Experimental browser APIs report schema 1 · Works offline and without JavaScript.`

The CSS and JS are the shared constants, so the CSP is identical (captured): `default-src &#39;none&#39;; script-src &#39;sha256-vxcVmn+OlgkxEN2VQ7q63vmVAZ/uCr6B1goVcd7EK6c=&#39;; style-src &#39;sha256-jPa0PJ+rVzL3fveVWR9DWnRPrxPWaM+zQ/+OnWDs2+A=&#39;; connect-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;`. `html()` escapes `& < > " '` as `&#<code>;` and renders `null`/`undefined` as `Unknown`; control characters are not removed.
- Tables are the collected ones plus `Evidence and completeness`: headers `Source, SDK method, Window, Status, Records, Pages, Notes`; notes joined by a space, or `Collection completed.`.
- Each table section is `<section id="table-<i>">`, with `<caption><n> aggregate rows</caption>`, or `<p>No rows collected; consult source completeness before interpreting this as empty.</p>` when it has no rows.
- With no findings the body is `<p>No findings in available evidence; this does not establish absence of risk.</p>`.
- The document ends in exactly one `\n`.
- Cells that are numbers are `String(n)` (JS number formatting: `12.5`, and `1e+21` for large values).

Captured body, healthy tenant (CSS and JS elided as `{CSS}` and `{JS}`, times are the run's own):

```
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="…as above…"><meta name="referrer" content="no-referrer"><title>AgentGuard environment report</title><style>{CSS}</style></head><body><a class="skip" href="#main">Skip to report</a><header><p>Prisma AIRS AI Supply Chain — AgentGuard</p><h1>AgentGuard environment report</h1><span class="badge">Attention required</span><p>Collection: 2026-10-19T03:00:16.236Z → 2026-10-19T03:00:16.256Z</p><p>30-day scan inventory; rolling 30_DAYS statistics; current rule catalog: 2026-09-19T03:00:16.236Z → 2026-10-19T03:00:16.236Z</p><p>Read-only evidence · Confidential environment metadata</p></header><main id="main"><nav aria-label="Report sections"><a href="#findings">Attention</a><a href="#table-0">Evidence tables</a><a href="#scope">Scope</a></nav><section id="findings"><h2>What needs attention</h2><div class="controls js-only">…(shared)…</div><article class="finding" data-priority="attention"><h3>Blocked scans require review</h3><p>1 collected non-parent scan rows have BLOCKED evaluations.</p><p><strong>Next step:</strong> Inspect the affected scans and findings before approving the artifacts.</p><p class="note">Scans</p></article><article class="finding" data-priority="review"><h3>Scans without a completed decision</h3>…</article><article class="finding" data-priority="attention"><h3>Skill vulnerabilities reported</h3><p>7 findings reported in the server statistics window.</p>…</article></section><section id="table-0"><h2>Scan outcomes</h2><p class="note">Collected 3 rows; excluded 0 parent/batch rows. Complete inventory for requested window.</p><div class="table-wrap" role="region" aria-label="Scan outcomes" tabindex="0"><table><caption>3 aggregate rows</caption><thead><tr><th scope="col">Artifact / outcome</th><th scope="col">Scan rows</th></tr></thead><tbody><tr><td>AGENT / ALLOWED</td><td>1</td></tr><tr><td>SKILL / BLOCKED</td><td>1</td></tr><tr><td>SKILL / PENDING</td><td>1</td></tr></tbody></table></div></section><section id="table-1"><h2>Skill statistics</h2>…<tr><td>Unique skills scanned</td><td>4</td><td>12.5</td></tr><tr><td>Vulnerabilities found</td><td>7</td><td>Unknown</td></tr>…</section><section id="table-2"><h2>Rule catalog defaults</h2>…<tr><td>ALLOWING</td><td>1</td></tr><tr><td>BLOCKING</td><td>2</td></tr>…</section><section id="table-3"><h2>Evidence and completeness</h2>…<tr><td>Scans</td><td>listScans()</td><td>2026-09-19T03:00:16.236Z to 2026-10-19T03:00:16.236Z</td><td>complete</td><td>3</td><td>1</td><td>Collection completed.</td></tr><tr><td>Statistics</td><td>getScanStats()</td><td>Server rolling 30_DAYS</td><td>complete</td><td>1</td><td>1</td><td>Collection completed.</td></tr><tr><td>Rules</td><td>listRules()</td><td>Current catalog</td><td>complete</td><td>3</td><td>1</td><td>Collection completed.</td></tr>…</section><section id="scope"><h2>Scope and limitations</h2><ul><li>Read-only evidence, not a security certification or numerical health score. Browser APIs are undocumented and may change.</li><li>Scans use explicit start/end timestamps; statistics use the server rolling 30_DAYS window. These independently read sources are not an atomic snapshot and need not reconcile.</li><li>Scan rows are not unique skills. Parent/batch rows are excluded from outcome counts to avoid counting them alongside children; per-scan vulnerability counts are never summed.</li><li>Rule default states describe the catalog, not effective tenant policies. No scan creation, policy changes or skill uploads are performed.</li><li>Missing or incomplete evidence is unknown, not zero. Scan names, identifiers, URLs, device metadata, source code and finding text are excluded.</li></ul></section><footer>Prisma AIRS CLI · Experimental browser APIs report schema 1 · Works offline and without JavaScript.</footer></main><script>{JS}</script></body></html>
```

Title escaping (captured): `--title '<b>"T&x'"'"'</b>'` gives `<title>&#60;b&#62;&#34;T&#38;x&#39;&#60;/b&#62;</title>`.

**Markdown** (TS only, dropped by D155; `er.ts:37-89`). Captured, healthy tenant:

```
# AgentGuard environment report

**Prisma AIRS AI Supply Chain — AgentGuard**

Assessment: **Attention required**

Collection: <started> → <generated>

30-day scan inventory; rolling 30&#95;DAYS statistics; current rule catalog: <start> → <end>

## What needs attention

### ATTENTION: Blocked scans require review

Evidence: 1 collected non-parent scan rows have BLOCKED evaluations.

Next step: Inspect the affected scans and findings before approving the artifacts.

Source: Scans
…
| Metric | Count | Change &#40;%&#41; |
…
Prisma AIRS CLI · Experimental browser APIs report schema 1
```

`md()` escapes `& < > " ' \ \` * _ [ ] { } ( ) | ! # ~` as `&#n;` and turns CR and LF into spaces.

Captured degraded variants:
- **All sources failing (500):** `Assessment: **Unable to assess**`; three `REVIEW: <name> incomplete` findings with the evidence `Request or validation failed; no upstream error body included.`; no data tables, only `Evidence and completeness` with `unavailable | 0 | 0`; exit 1; stderr `  3 source(s) incomplete; review the evidence section.`
- **`--max-pages 2` over 25 scans and 25 rules:** both sources are `partial` with the notes `Reached the 2-page budget. Inventory incomplete: pagination changed, repeated, stopped early, failed or reached its budget.`; `Collected 20 rows; excluded 0 parent/batch rows. Partial inventory only.`; 20 rules counted; exit 0 (no `--strict`).
- **Classification fixture:** a batch parent, a parent with children, a child with a `null` outcome, `artifact_type: "PRIVATE<b>"` with outcome `PRIVATE-X`, a 2020 row, a `garbage` timestamp, `FAILED/ERROR` and a lowercase `skill`. Result: rows `OTHER / ALLOWED 1`, `OTHER / OTHER 1`, `SKILL / ERROR 1`, `SKILL / UNKNOWN 1`; `Collected 8 rows; excluded 2 parent/batch rows. Partial inventory only.`; the `Rows with missing or out-of-window…` note; no `PRIVATE` text in the document.

### 9.5 Publishing and exit (`ag.ts:274-284`, `io.ts:6-19`)

- **File.** `writeReportFile`:
  1. `open(<dir>/.airs-report-<uuid>.tmp, 'wx', 0o600)`;
  2. write and `fsync`;
  3. `close`;
  4. `link(temp, path)`, which is atomic and fails if the path exists;
  5. in `finally`: `close` again and `unlink(temp)`.

  The parent directory is not fsynced. The file is mode 0600 (captured `-rw-------`, 8188 bytes for the healthy capture). Then the status `  Report → <path with \p{Cc}\p{Cf} → _> (mode 0600)`; captured: a name containing a newline printed `a_b.html`.
- **stdout** (`-`): `process.stdout.write(output, cb)`. A write error such as EPIPE rejects into the failure line (`it.spec:152-166`).
- Then, when sources are not complete: `  <n> source(s) incomplete; review the evidence section.`
- **Exit:** 1 when the health is `unknown` or (`--strict` and any source is incomplete), else 0. In both cases the document was written. Captured: `--strict` with rules at 403 wrote the file and exited 1.

### 9.6 Failure line

Every throw in the action is printed as `  ✗ AgentGuard report failed. Check credentials and a writable, new output path. Existing files are never overwritten.` (stderr, `ui.error`, never quiet-suppressed, exit 1). This covers an existing path, no tenant, a missing credential, an invalid config, a failed write and a stdout error. Source failures are not throws: they live inside the document. Captured cases: an existing file, a dangling symlink, no tenant, a missing `mgmtClientSecret`, an invalid `agentGuardDataEndpoint` and a missing parent directory (after collection).

## 10. Writes

No AgentGuard command writes to the service. Every request is a GET; the help says "read-only", and the collector says "No scan creation, policy changes or skill uploads are performed". Local writes:
- the report file and its temporary file (§9.5);
- the `--debug` log in the working directory, for the read leaves only.

## 11. Sensitive-data exposure (TS)

| Item | Where | Exposure |
|---|---|---|
| `mgmtClientSecret` | the token request's Basic header | never printed; the token is hashed (`sha256:<12 hex>`) in the SDK debug lines and redacted in the debug log |
| bearer token, `x-tsg-id` | API requests | the TSG id appears in `PANW_AI_SEC_DEBUG` header lines and in the debug-log headers (not a secret) |
| scan `name`, `git_url`, `fingerprint`, `device_metadata` (captured fixture `{token: …}`), `error_message`, `eval_details` | `scans list` | dropped in every format (`it.spec:44-57`) |
| finding content (`original_code`, `suggested_code`, `file_path`, `title`, `description`, `remediation_description`) | `scans vulnerabilities --include-content` | printed in full in JSON/YAML, partly in tables; may contain secrets from the scanned code (`SDK:14742`). The opt-in flag is the only guard; `content_included: true` marks the JSON |
| rule `description`, `remediation`, stats and rules passthrough | `rules list`, `stats` | printed in JSON; tables drop `description` and `remediation` only |
| server error text | every failure | never printed (generic line, no body) |
| server strings in tables | all reads | control characters printed raw (§5) |
| report | `report` | aggregates only, fixed vocabularies (unfamiliar labels → `OTHER`), no names, ids, URLs or finding text (`ut.spec:11-28`, `ut.spec:86-99`); `--debug` refused; file 0600, no-clobber |

## 12. Doctor and tenant wording

There is no AgentGuard doctor check. The management-credential line names the product: `… — management, red team, model security, AI Gateway and AgentGuard commands are unavailable` (`doctor.ts:299`; the Rust doctor currently keeps this text, DESIGN §9 row "Management credentials"). MILESTONES says the renames cover doctor checks, so this wording is a rename candidate (see the open questions).

## 13. TS specs to port (acceptance tests)

- `it.spec:44-57`: no `PRIVATE-` value in any format, and `BLOCKED` is shown. In Rust, `json`, `pretty` and `table` only.
- `it.spec:58-76`: an `--all` walk over 2 pages reports `returned 2, truncated false`; `--all --max 1` reports `returned 1, truncated true, next_offset 1`.
- `it.spec:77-82`: repeated rows give exit 1.
- `it.spec:83-91`: content is hidden by default; `--include-content` reveals `PRIVATE-CODE`.
- `it.spec:92-114`: stats are called with `{time_period:'30_DAYS'}`; rules are called with `{skip:0, limit:10}`; the rules walk continues past a page-count `total_items` until a short page.
- `it.spec:116-128`: `null` metrics stay `null`.
- `it.spec:129-174`: the default HTML file is created in the working directory with mode 0600, with no overwrite and no client; stdout delivery and a broken pipe give exit 1; `--strict` with an unavailable rules source writes the file and exits 1.
- `it.spec:175-190`: `--limit 0`, `--start bad`, `--time-period week`, `../escape`, `--max-pages 0`, `report --output json` and `report --debug` fail before any client is built.
- `ut.spec`, all of it: the window `start = now − 30 d` sent as `start_time`/`end_time`; pages walked by the total and the rows returned; `repeated`, `empty`, `changed`, `failed` and `oversized` pages turn the source partial; the budget, the parent exclusion and the pending finding; all sources failing gives `unknown` and no tables; out-of-window and unfamiliar text; valid empty data gives `no-findings`; the rule catalog is not cut at a page-count total; an invalid budget is rejected before I/O.

## 14. Rust SDK (`scm-sdk` 0.1.1) pointers

- The `agentguard` feature (`agentguard = ["models"]`) gives `scm::airs::agentguard::AgentGuardClient` (`rs:airs/agentguard/client.rs`).
- `AgentGuardClient::new(client, data, management)` requires OAuth and enables the TSG header (`with_tsg_header(true)`, `rs:engine.rs:447`), which matches TS's `x-tsg-id`.
- The operations:
  - `list_scans(&AgentGuardScanListOptions, opts)`: query keys `skip, limit, isBackgroundRefresh, start_time, end_time`, in TS order;
  - `get_scan_stats(&AgentGuardStatsOptions, opts)`: sends `time_period=30_DAYS` when unset;
  - `list_scan_vulnerabilities(uuid, opts)`: `is_uuid`, any case (`rs:data.rs:324-333`), then `.segment(uuid)`;
  - `list_rules(&AgentGuardPageOptions, opts)`.
- Debug operation names: `airs.agentguard.list_scans`, `get_scan_stats`, `list_scan_vulnerabilities` and `list_rules`.
- Queries are validated against the frozen schemas; number values are formatted with `ryu_js`, as JS does. Unknown query keys are refused.
- Models: the `AgentGuardScan`, `AgentGuardRule`, `AgentGuardScanStats` and `AgentGuardVulnerability` structs carry `extensions` (passthrough), serialized after the known fields.
- The constants `AGENT_GUARD_DATA_ENDPOINT` and `AGENT_GUARD_MGMT_ENDPOINT` match TS (`rs:constants.rs:144-148`).
- To verify before building:
  - whether the Rust schema validation enforces the `start_time <= end_time` refine and zod's datetime pattern (if not, the CLI checks them during planning);
  - whether `extensions` keep the wire order;
  - the 401/403 replay (G7 applies as for red team).

## 15. Live-tier notes

- All five commands are read-only and are safe for the live tier. `report` writes only a local file.
- The service is experimental and undocumented ("Browser APIs"). `redtail-prod` may lack access, as happened for model security in 0.8.
- `scans vulnerabilities --include-content` should not run live, or its output must never be stored: it prints scanned source code.

## Acceptance criteria

1. Both `list`s accept the alias `ls`; there are no other aliases. `--limit` and `--offset` default to 10 and 0; `--all` honours `--offset`; `--max` defaults to 10000, and 0 means no item cap.
2. `scans list` sends `skip`, `limit`, `isBackgroundRefresh=false` and the optional `start_time`/`end_time`, in that order, URL-encoded, values as typed. `rules list` sends `skip` and `limit` to the management base. `vulnerabilities` sends no query. `stats` sends `time_period=30_DAYS`. Every request carries `x-tsg-id`.
3. No AgentGuard request is retried except the single auth replay after a 401, or a 403 without `x-opa-decision: false`.
4. The walk enforces the §3 guards and fails closed with nothing on stdout. Rules use the short-page rule and never trust `total_items`. The pagination object is exactly `{total_items, returned, skip, next_offset, truncated}` with the §3 semantics.
5. The scans projection is exactly the 9 keys of §4. `vulnerabilities` without the opt-in shows exactly 4 keys and `content_included`.
6. `table` and `pretty` print the §5 layout without indent, plus the `Returned <n> records; …` status. The JSON documents are §4 with a trailing newline.
7. A server error never prints server text. A failing read prints one fixed line on stderr and exits 1.
8. The report runs the three sources in order, with the §9.3 page loop, notes, findings and health. The HTML is byte-identical to the shared template with the AgentGuard parameters and the CSP of §9.4. The file is 0600, never overwrites, and is checked with `lstat` before the tenant. `--strict` and `unknown` give exit 1 after writing.
9. The report refuses `--debug`. The read leaves' debug log never holds a body.
10. Interrupting any command writes no report and prints no data.

## Open questions / likely §12 divergences

1. **Rename scope.** The tree becomes `supplychain`. The other rename candidates are:
   - the report's default title `AgentGuard environment report`;
   - the product line `Prisma AIRS AI Supply Chain — AgentGuard`;
   - the file prefix `airs-agentguard-report-`;
   - the messages `Invalid AgentGuard query…`, `AgentGuard request failed…` and `AgentGuard report failed…`;
   - the help texts;
   - the doctor wording (§12).

   MILESTONES lists "report titles" among the renames, so recommend `Supply chain environment report` and `airs-supplychain-report-…`. Keep the product line, which names the service, and keep "AgentGuard" in it as the API name. Each changed string gets one §12 row.
2. **Validation before the tenant** (D184 pattern). In TS, the query errors (`--limit 0`, the window, the UUID, `--time-period`) come after the tenant read, and `--max` after the credential check. In Rust, all usage errors would be exit 2 during planning. Decide whether to keep TS's messages (`Invalid AgentGuard query…`, `Pagination requires a safe nonnegative integer`) or name the flag, for example `--limit must be a positive integer`. Recommend flag-specific text, as §17 did, and `--max-pages must be an integer from 1 to 100` for every `--max-pages` failure (TS prints the pagination text for `abc`).
3. **Generic error line hides tenant and credential errors.** TS prints `AgentGuard request failed…` for a missing credential or an invalid config. Recommend the §3.5/§6 messages (exit 1), with the generic line only for API and validation failures. Keep TS's no-body policy, which is safer than D11's text; the `(HTTP <s>)` suffix can stay.
4. **`--max` parsing.** TS accepts `0x2`, `1e0`, `' 2 '` and `''`. Recommend decimal digits only (§7.1 rule). Also decide the safety bound: TS fails after 1000 pages with nothing printed; the Rust shared walk bound is 1,000,000 items.
5. **Dropped formats.** `yaml`, `csv` and `markdown` become usage errors (D50). The status text `see JSON/YAML for pagination metadata` names YAML: change it to `see JSON for pagination metadata` (a §12 row) or keep it verbatim.
6. **The stats array quirk** (§5): a passthrough array hides the statistics. Recommend always using field mode for `stats`.
7. **Control characters** in table cells and the HTML title (D52): apply `terminal_safe` to tables. Decide whether report HTML also strips them; TS keeps them, escaped only for `& < > " '`.
8. **`vulnerabilities` is single-page and silent.** Fail-closed invariant: when `pagination.total_items` exceeds the rows returned, warn on stderr or exit 1. The API has no paging parameters (unknown). Candidate §12 row.
9. **Report format and debug** (D155, D156): HTML only, and `--debug` refused without naming `PANW_AI_SEC_DEBUG`. Apply them as for red team and runtime.
10. **Report timestamps.** TS uses `Date.parse` with no zone check, so a zone-less `created_at` counts as local time. Recommend the red team rule: zone required, else an unusable timestamp (excluded, and the source becomes partial).
11. **Missing output directory.** TS collects first and fails at the write. Recommend checking the parent directory before the tenant, alongside the `lstat`.
12. **Budgets.** TS allows 60 s per request and no total; red team in Rust uses a 300 s budget per source with `with_retries(0)`. Recommend the red team budget model.
13. **Interruption** (§2.5 cancellation): Rust prints its interrupt context lines (`no report was written`); TS dies silently.
14. **Redirects.** TS's fetch follows them; the Rust origin policy refuses them. This is safer and needs no row if §5 already covers it.
15. **Rules `total_items: null`** and the "always truncated at exactly `--limit`" artefact are TS parity; keep, or probe one more page when a rules page is full without `--all`? Recommend parity.
16. **Uppercase UUIDs** are sent as typed in TS. Keep (parity).

## Appendix A: scratch artifacts (not part of the repo)

The stub, guard and runner are in `/private/tmp/claude-501/-Users-cdot-development-redtail-prisma-airs-cli-rs/2663a1f5-b86a-45e5-9990-00ce664767e6/scratchpad/ag/tools/` (`stub.mjs`, `guard.mjs`, `run.mjs`, `sig.mjs`). The healthy HTML capture is `/private/tmp/claude-501/-Users-cdot-development-redtail-prisma-airs-cli-rs/2663a1f5-b86a-45e5-9990-00ce664767e6/scratchpad/ag/captures/report-default.html`.
