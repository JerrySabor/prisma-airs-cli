# Spec: TS `airs-cli` red team scans and catalogue (M6a): `redteam list|ls`, `status`, `abort`, `categories`, `languages`, `eula`, `scan`, `report|dashboard`, `registry-credentials`, `instances`, `devices`, `prompt-sets`, `prompts`, `properties`

Out of scope here: `redteam targets …`, `adapter …` and `network-broker …` (a separate spec), and `redteam judge` (dropped with TypeSafe; MILESTONES scope table).

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0). It pins `@cdot65/prisma-airs-sdk` 0.34.0, commander 14.0.3 and chalk 5.6.2. Citations:
  - `rt:<line>` is `src/cli/commands/redteam.ts`; `rr:<line>` is `src/cli/commands/redteam-report.ts`; `prog:<line>` is `src/cli/program.ts`.
  - `svc:<line>` is `src/airs/redteam.ts` (`SdkRedTeamService`); `ps:<line>` is `src/airs/promptsets.ts` (`SdkPromptSetService`).
  - `ren:<line>` is `src/cli/renderer/redteam.ts`; `rren:<line>` is `src/cli/renderer/runtime.ts` (the scan progress line); `ui:<line>` is `src/cli/renderer/ui.ts`; `common.ts` is `src/cli/renderer/common.ts`.
  - `env:<line>` is `src/reports/redteam.ts` (the environment report collector); `erender:<line>` is `src/reports/environment-render.ts`; `io:<line>` is `src/reports/io.ts`.
  - `opts:<line>` is `src/config/client-options.ts`; `confirm.ts`, `deprecated-flags.ts` are under `src/cli/`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js`. `rs:<path>:<line>` is `~/.cargo/registry/src/*/scm-sdk-0.1.0/<path>`.
  - Docs: `docs-site/docs/cli/redteam/*.md`. TS tests: `tests/unit/cli/redteam-*.spec.ts`, `tests/unit/airs/redteam.spec.ts`, `tests/unit/reports/redteam.spec.ts`, `tests/integration/cli/redteam-dashboard.spec.ts`. These mock the service or the `RedTeamClient` factory, so they never exercise the SDK's UUID checks, zod request schemas, retries or HTTP classification. §2.4 shows what the real SDK does.
- How behaviour was captured: the reference build (`dist/cli/index.js`, node v24.21.0) ran against a stateful loopback stub of the three red team planes, one fresh sandbox per script. The probe tooling is in this session's scratchpad under `rtprobe/`: `server.mjs` (stub; data plane under `/data`, management plane under `/mgmt`, network broker under `/nb`, OAuth at `/oauth/token`; a scenario file overrides any route by call count), `lib.sh` (sandbox and runner), `guard.mjs`, `fstrace.mjs`, `shapes.mjs` (prints the SDK's zod shapes) and the scenario scripts `s_*.sh`.
  - Each sandbox has `home/`, `state/tenants.json` (a TS registry, `version: 1`, one active tenant `t`, TSG `100`), `configs/t.json` (0600; `mgmtClientId: client-100`, `mgmtClientSecret: FAKE-SECRET-100`, `mgmtTsgId: 100`, `mgmtTokenEndpoint`, and `redTeamDataEndpoint`, `redTeamMgmtEndpoint`, `redTeamNetworkBrokerEndpoint` on the stub), `cwd/` and `tmp/`.
  - Every run used `env -i` with `PATH=/usr/bin:/bin`, `HOME`, `TMPDIR`, `XDG_STATE_HOME`, `XDG_CONFIG_HOME` and `PRISMA_AIRS_TENANTS_PATH` inside the sandbox, `NO_COLOR=1` (or `FORCE_COLOR=1` for colour captures), and every red team environment fallback the SDK reads set to a trap: `PANW_RED_TEAM_DATA_ENDPOINT`, `PANW_RED_TEAM_MGMT_ENDPOINT`, `PANW_RED_TEAM_NETWORK_BROKER_ENDPOINT`, `PANW_RED_TEAM_TOKEN_ENDPOINT`, `PANW_MGMT_ENDPOINT`, `PANW_MGMT_TOKEN_ENDPOINT` → `http://127.0.0.1:<port>/ENVTRAP`, and `PANW_RED_TEAM_CLIENT_ID|CLIENT_SECRET|TSG_ID` → trap values. No request reached the trap (§2.1).
  - Every node run preloaded `guard.mjs` (replaces `globalThis.fetch` and `dns.lookup`, refuses any host but `127.0.0.1`; no refusal was recorded) and `fstrace.mjs` (logs `fs/promises` writes, links and unlinks).
  - Interruptions were driven with `kill -INT` / `kill -TERM` on the node process.
- No real tenant or credential file was read. No host other than loopback was contacted. Captured stdout and stderr are shown as JSON strings. `<SB>` is the sandbox.

## 1. Command surface (help verified)

Aliases come from `prog:42-51`: every `list` gets `ls`, every visible `delete` gets `rm`; `report` has the explicit alias `dashboard` (`rr:23`). Help is sorted (`prog:73-76`). `applyReadContractFlags` (`prog:54-70`) adds `--offset <n>` (Number, 0), `--all` and `--max <n>` (Number, 10000) to every `list` that has `--limit` or `--offset`, and `--output` to every `list`/`get` that lacks it.

| Command | Registration | Arguments and options (help text; defaults as commander prints them) |
|---|---|---|
| `redteam list\|ls` | `rt:519-546` | `--status <status>` (`Filter by status (QUEUED, RUNNING, COMPLETED, FAILED, ABORTED)`), `--type <type>` (`Filter by job type (STATIC, DYNAMIC, CUSTOM)`), `--target <uuid>` (`Filter by target UUID`), `--limit <n>` (`Max results`, `"10"`), `--output <format>` (`Output format: pretty, table, csv, json, yaml`, `"pretty"`), plus the added `--offset <n>` (`Item offset`, `0`), `--all` (`Walk all pages`), `--max <n>` (`Maximum items with --all; 0 removes the cap`, `10000`) |
| `redteam status <jobId>` | `rt:987-999` | none |
| `redteam abort <jobId>` | `rt:266-278` | none |
| `redteam categories` | `rt:283-295` | none |
| `redteam languages` | `rt:1691-1706` | `--management` (`Query the management-plane endpoint instead of the data plane`), `--output <format>` (`pretty, table, csv, json, yaml`, `"pretty"`) |
| `redteam eula status` / `content` | `rt:302-328` | none |
| `redteam eula accept` | `rt:330-359` | `--force` (`Skip confirmation prompt`); hidden deprecated `--confirm` → `--force` |
| `redteam scan` | `rt:896-982` | `--target <uuid>` (required), `--name <name>` (required), `--type <type>` (`Job type: STATIC, DYNAMIC, or CUSTOM`, `"STATIC"`), `--categories <json>` (`Category filter JSON (STATIC scans)`), `--prompt-sets <uuids>` (`Comma-separated prompt set UUIDs (CUSTOM scans)`), `--goals <file>` (`JSON file or inline JSON array of attack goals (DYNAMIC scans)`), `--depth <number>` (`Max conversation turns per goal (DYNAMIC scans)`, `"10"`), `--breadth <number>` (`Parallel agents per goal (DYNAMIC scans)`, `"6"`), `--no-wait` (`Submit scan without waiting for completion`); three Examples lines |
| `redteam report\|dashboard [jobId]` | `rr:17-111`, `rt:848-886` | `--attacks` (`Individual scan only: include attack list`, `false`), `--severity <level>`, `--limit <n>` (`Individual scan only: max attacks to show`, `"20"`), `--output <format>` (`Deliverable format: html or markdown (default: html)`), `--output-file <path>` (`Destination (default: new timestamped file in CWD); - for stdout; never overwrite`), `--title <text>` (`"Red Team environment report"`), `--max-pages <n>` (`Page budget per source, 1–100 (15 records/page)`, `"40"`), `--strict` (`Exit 1 after writing if any source is incomplete`); four Examples lines |
| `redteam registry-credentials` | `rt:500-514` | `--output <format>` (`Output format: pretty, json, yaml`, `"pretty"`); description `Get or create registry credentials` |
| `redteam instances create` | `rt:366-387` | `--tsg-id <id>`, `--tenant-id <id>`, `--app-id <id>`, `--region <region>` (all required) |
| `redteam instances get <tenantId>` | `rt:389-403` | `--output <format>` (`pretty, json, yaml`, `"pretty"`) |
| `redteam instances update <tenantId>` | `rt:405-425` | `--tsg-id`, `--app-id`, `--region` (required) |
| `redteam instances delete\|rm <tenantId>` | `rt:427-440` | none |
| `redteam devices create\|update <tenantId>` | `rt:447-479` | `--config <path>` (required, `JSON file with device request`); update's description ends `(PATCH)` |
| `redteam devices delete\|rm <tenantId>` | `rt:481-495` | `--serial-numbers <list>` (required, `Comma-separated serial numbers`) |
| `redteam prompt-sets list\|ls` | `rt:553-569` | `--limit <n>` (`Max results (client-side)`), `--offset <n>` (`Starting offset (client-side)`), `--output <format>` (`pretty, table, csv, json, yaml`), plus added `--all`, `--max` |
| `redteam prompt-sets get <uuid>` | `rt:571-591` | `--output <format>` (`pretty, json, yaml`) |
| `redteam prompt-sets create` | `rt:593-608` | `--name <name>` (required), `--description <desc>` |
| `redteam prompt-sets update <uuid>` | `rt:610-627` | `--name <name>`, `--description <desc>` |
| `redteam prompt-sets archive <uuid>` | `rt:629-643` | `--unarchive` (`Unarchive instead`) |
| `redteam prompt-sets download <uuid>` | `rt:645-667` | `--output-file <path>` (`Output file path`); hidden deprecated `--output <path>` → `--output-file` |
| `redteam prompt-sets upload <uuid> <file>` | `rt:669-684` | none |
| `redteam prompts list\|ls <setUuid>` | `rt:691-708` | `--limit <n>` (`Max results`, `"50"`), `--output <format>` (`pretty, json, yaml`), plus added `--offset`, `--all`, `--max` (never read) |
| `redteam prompts get <setUuid> <promptUuid>` | `rt:710-724` | `--output <format>` (`pretty, json, yaml`) |
| `redteam prompts add <setUuid>` | `rt:726-740` | `--prompt <text>` (required), `--goal <text>` |
| `redteam prompts update <setUuid> <promptUuid>` | `rt:742-759` | `--prompt <text>`, `--goal <text>` |
| `redteam prompts delete\|rm <setUuid> <promptUuid>` | `rt:761-773` | none |
| `redteam properties list\|ls` | `rt:780-796` | `--limit`, `--offset` (client-side), `--output` (`pretty, table, csv, json, yaml`), plus added `--all`, `--max` |
| `redteam properties create` | `rt:798-811` | `--name <name>` (required) |
| `redteam properties values <name>` | `rt:813-827` | `--output <format>` (`pretty, json, yaml`) |
| `redteam properties add-value` | `rt:829-843` | `--name <name>`, `--value <value>` (both required) |

`redteam --help` (stdout, exit 0), byte-exact; the Rust port drops the `judge` row:

```
Usage: airs-cli redteam [options] [command]

AI Red Team scan operations

Options:
  -h, --help                          display help for command

Commands:
  abort <jobId>                       Abort a running scan
  adapter                             Manage custom target adapters (scripted
                                      targets run via the network broker)
  categories                          List available attack categories
  devices                             Manage Red Team devices
  eula                                Manage Red Team EULA
  help [command]                      display help for command
  instances                           Manage Red Team instances
  judge [options] [scanFile]          Judge red-team attack outputs with
                                      TypeSafe Jev and compute an independent
                                      attack success rate
  languages [options]                 List tenant languages and supported job
                                      types
  list|ls [options]                   List recent scans
  network-broker                      Manage red team network broker channels
  prompt-sets                         Manage custom prompt sets
  prompts                             Manage prompts within prompt sets
  properties                          Manage custom attack properties
  registry-credentials [options]      Get or create registry credentials
  report|dashboard [options] [jobId]  Generate an environment report, or view an
                                      individual scan report by job ID
  scan [options]                      Execute a red team scan against a target
  status <jobId>                      Check scan status
  targets                             Manage red team targets
```

`redteam scan --help`, byte-exact:

```
Usage: airs-cli redteam scan [options]

Execute a red team scan against a target

Options:
  --breadth <number>     Parallel agents per goal (DYNAMIC scans) (default: "6")
  --categories <json>    Category filter JSON (STATIC scans)
  --depth <number>       Max conversation turns per goal (DYNAMIC scans)
                         (default: "10")
  --goals <file>         JSON file or inline JSON array of attack goals (DYNAMIC
                         scans)
  -h, --help             display help for command
  --name <name>          Scan name
  --no-wait              Submit scan without waiting for completion
  --prompt-sets <uuids>  Comma-separated prompt set UUIDs (CUSTOM scans)
  --target <uuid>        Target UUID
  --type <type>          Job type: STATIC, DYNAMIC, or CUSTOM (default:
                         "STATIC")

Examples:
  $ airs-cli redteam scan --target <target-uuid> --name "nightly-static"
  $ airs-cli redteam scan --target <target-uuid> --name "custom-run" --type CUSTOM --prompt-sets <set-uuid>
  $ airs-cli redteam scan --target <target-uuid> --name "agent-probe" --type DYNAMIC --goals goals.json --no-wait

```

`redteam list --help`:

```
Usage: airs-cli redteam list|ls [options]

List recent scans

Options:
  --all              Walk all pages
  -h, --help         display help for command
  --limit <n>        Max results (default: "10")
  --max <n>          Maximum items with --all; 0 removes the cap (default:
                     10000)
  --offset <n>       Item offset (default: 0)
  --output <format>  Output format: pretty, table, csv, json, yaml (default:
                     "pretty")
  --status <status>  Filter by status (QUEUED, RUNNING, COMPLETED, FAILED,
                     ABORTED)
  --target <uuid>    Filter by target UUID
  --type <type>      Filter by job type (STATIC, DYNAMIC, CUSTOM)
```

`redteam report --help`:

```
Usage: airs-cli redteam report|dashboard [options] [jobId]

Generate an environment report, or view an individual scan report by job ID

Options:
  --attacks             Individual scan only: include attack list (default:
                        false)
  -h, --help            display help for command
  --limit <n>           Individual scan only: max attacks to show (default:
                        "20")
  --max-pages <n>       Page budget per source, 1–100 (15 records/page)
                        (default: "40")
  --output <format>     Deliverable format: html or markdown (default: html)
  --output-file <path>  Destination (default: new timestamped file in CWD); -
                        for stdout; never overwrite
  --severity <level>    Individual scan only: filter attacks by severity
  --strict              Exit 1 after writing if any source is incomplete
  --title <text>        Report title (default: "Red Team environment report")

Examples:
  $ airs-cli redteam report --output-file ./airs-daily.html
  $ airs-cli redteam report --output markdown --output-file ./airs-daily.md
  $ airs-cli redteam report
  $ airs-cli redteam report --strict --max-pages 20 --output-file - > daily.html

```

The other help pages are in the scratchpad (`rtprobe/help.txt`); their option lines are the table above.

## 2. Shared behaviour

### 2.1 Client construction and endpoints (`rt:64-74`, `opts:34-69`, `SDK:17279-17320`)

- Every action calls `loadConfig()` and builds `new RedTeamClient(redTeamClientOptions(config))`, once per service (`createService`, `createPromptSetService`); the report collector builds its own client with `numRetries: 0` (`rr:80-83`).
- `redTeamClientOptions` first runs `assertManagementCredentials` (`opts:35`): missing `mgmtClientId`, `mgmtClientSecret` or `mgmtTsgId` fails with `  ✗ Error: Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set t <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)` (exit 1). It then passes concrete values for every option the SDK would otherwise read from the environment: `clientId`, `clientSecret`, `tsgId`, `tokenEndpoint` (`mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`), `dataEndpoint` (`redTeamDataEndpoint ?? https://api.apps.paloaltonetworks.com/ai-red-teaming/data-plane`), `mgmtEndpoint` (`redTeamMgmtEndpoint ?? …/mgmt-plane`), `networkBrokerEndpoint` (`redTeamNetworkBrokerEndpoint ?? …/data-plane/network-broker`) (`SDK:91-93`).
- So the SDK fallbacks `PANW_RED_TEAM_{DATA,MGMT,NETWORK_BROKER}_ENDPOINT` (`SDK:17279-17281`) and the `PANW_RED_TEAM_*` → `PANW_MGMT_*` credential fallbacks of `resolveOAuthConfig` (`SDK:11098-11104`) never apply. Verified: no request reached the trap. The SDK still reads `PANW_AI_SEC_TIMEOUT_MS` (per attempt, default 60000, `SDK:10095`) and `PANW_AI_SEC_DEBUG*`.
- `numRetries` is unset, so `resolveOAuthConfig` gives `MAX_NUMBER_OF_RETRIES` = 5 (`SDK:11111-11114`); the report sets 0.
- Planes (`SDK:17288-17311`):

| Plane (tenant key) | SDK sub-clients used here | Paths |
|---|---|---|
| data (`redTeamDataEndpoint`) | `scans`, `reports`, `customAttackReports`, `getLanguages`, `getScanStatistics`, `getQuotaSummary` | `/v1/scan…`, `/v1/categories`, `/v1/report/static|dynamic/…`, `/v1/custom-attacks/…`, `/v1/languages`, `/v1/dashboard/scan-statistics`, `/v1/metering/quota` |
| management (`redTeamMgmtEndpoint`) | `eula`, `instances`, `customAttacks`, `targets.list`, `adapters.list`, `getManagementLanguages`, `getDashboardOverview` | `/v1/eula/…`, `/v1/instances…`, `/v1/registry-credentials`, `/v1/custom-attack/…`, `/v1/target`, `/v1/adapters`, `/v1/languages`, `/v1/dashboard/overview` |
| network broker (`redTeamNetworkBrokerEndpoint`) | `networkBroker.getChannelStats` | `/v1/channels/stats` |

- Auth: one `POST <mgmtTokenEndpoint>` (client credentials) per process before the first API request; `Authorization: Bearer <token>` on every request; headers also `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `service-name: api`, `Content-Type: application/json` when a JSON body is sent. A token-endpoint transport failure: `  ✗ Error: AISEC_OAUTH_ERROR:Token request failed: fetch failed` (exit 1, no retry, observed in 0 s).

### 2.2 `--output` (`prog:162-175`, `common.ts:48-75`)

- The root parser consumes `--output` anywhere in argv (`ts-cli-shell.md` §3), so a leaf `--output` never gets a value from the command line and keeps its default `'pretty'`.
- `preAction` resolves the format for leaves named in `READ_COMMAND_NAMES` (`prog:18-39`) that have an `--output` option, except `redteam report` (`prog:165`): here `list`, `get`, `languages`, `registry-credentials`, `values`. It loads the tenant config, takes `root --output ?? defaultOutput ?? 'pretty'`, validates it against `pretty, table, markdown, csv, json, yaml` (`  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml`, exit 2; with no tenant selected the tenant error comes first, exit 1) and stores it on the leaf. So `redteam list --output json` works, and the tenant's `defaultOutput` applies to these reads.
- Commands without an `--output` option (`status`, `categories`, `eula *`, `scan`, every create/update/delete, per-job `report`) ignore the root `--output` silently: `redteam categories --output json` and `redteam scan … --output json` print pretty (captured).
- What each format prints, per renderer (all on stdout, `console.log`, so one trailing `\n`):

| Renderer (commands) | pretty | table / csv / markdown | json | yaml | empty list |
|---|---|---|---|---|---|
| `renderScanList` (`list`) `ren:84-133` | §3 | `formatOutput` columns `ID, Name, Status, Type, Score, Created` | array of `{id,name,status,type,score,createdAt}`, `score`/`createdAt` `""` when null | same rows | `  No scans found` in **every** format (`ren:95-98`) |
| `renderPromptSetList` (`prompt-sets list`) `ren:407-440` | §15.1 | columns `ID, Name, Status` (`active`/`inactive`) | `{id,name,status}` rows | rows | `  No prompt sets found` in every format |
| `renderPropertyNames` (`properties list`) `ren:635-656` | bullets | column `Name` | string array | list | pretty: `  No property names found`; json `[]` |
| `renderLanguages` (`languages`) `ren:934-973` | §7 | columns `Code, Name` of `languages` only | `{multilingualEnabled,supportedJobTypes,languages}` | same | — |
| `renderPromptList` (`prompts list`) `ren:571-601` | §16.1 | **nothing** | array of `{uuid,prompt,goal,active,promptSetId}` (`goal: null` kept) | array | pretty `  No prompts found`; json `[]` |
| `renderPromptDetail`, `renderPromptSetDetail`, `renderInstanceDetail`, `renderRegistryCredentials`, `renderPropertyValues`, `renderTargetDetail` | sections below | **nothing** (exit 0) | the normalized object | object (+ an extra `\n`: `yamlDump` ends with `\n`, then `console.log`) | — |

- Captured: `instances get ten-1 --output table`, `registry-credentials --output table`, `prompt-sets get … --output table` and `prompts list … --output table` print nothing, exit 0, after making their requests (the registry one a POST).
- Table bytes (`formatOutput`, `ts-cli-shell.md` §9): header ` Label ` cells padded to the column width and joined by `│`, a `─`×(w+2) separator joined by `┼`, LF, no indent; captured `redteam list --output table`:
  ```
   ID                                   │ Name         │ Status    │ Type    │ Score │ Created              
  ──────────────────────────────────────┼──────────────┼───────────┼─────────┼───────┼──────────────────────
   11111111-1111-4111-8111-111111111111 │ fixture-scan │ COMPLETED │ STATIC  │ 7.5   │ 2026-10-17T10:00:00Z 
   22222222-2222-4222-8222-222222222222 │ second-scan  │ RUNNING   │ DYNAMIC │       │                      
  ```
- No page-status line (`Showing …`) is printed by any red team list.

### 2.3 Banner, streams, quiet, colour

- Banner `renderRedteamHeader` (`ren:7-9`): stdout `"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n"` (bold title, dim subtitle; quiet-suppressed).
  - Printed only when the resolved format is `pretty`: `list`, `languages`, `registry-credentials`, `instances get`, `prompt-sets list|get`, `prompts list|get`, `properties list|values`.
  - Printed unconditionally as the action's first line, **before** the tenant is loaded: every other command here, including `scan`, `status`, `abort`, `eula *`, the writes and the per-job `report`. So a tenant, credential, UUID or file error leaves the banner on stdout (captured for `status` with no tenant: stdout banner, stderr `  ✗ Error: No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'`).
  - The environment report prints no banner.
- `ui.section(l)`: `"\n  <bold l>\n\n"` (quiet-suppressed). `ui.keyValue`: `"  " + dim(key.padEnd(max)) + "  " + value` per line (not suppressed). `ui.success`: stdout `"  ✓ <msg>"` green (not suppressed). `ui.dim`: stdout, suppressed. `ui.status`: **stderr** dim, suppressed. `ui.emptyList`: stdout `"  " + dim("No <x> found")`, not suppressed. `ui.bullet(m,'neutral')`: `"  " + dim("•") + " " + m`.
- Colour: chalk's level follows stdout's TTY (also used for stderr); `NO_COLOR` is ignored, `FORCE_COLOR` forces. Captured under `FORCE_COLOR=1`: bold `\e[1m…\e[22m`, dim `\e[2m…\e[22m`, status colours `statusColor` (`ren:30-47`): `COMPLETED` green, `RUNNING` blue, `QUEUED`/`INIT`/`PARTIALLY_COMPLETE` yellow, `FAILED`/`ABORTED` red, anything else white. `fail()` output colours the leading `\n` separately: `"\e[31m\e[39m\n\e[31m  ✗ Error: …\e[39m\n\n"`.
- `--quiet` removes banner, sections, dim hints and stderr status lines; key/value blocks, tables, success lines, bullets, JSON/YAML and errors stay. Captured `--quiet redteam status <id>`: stdout `"  ID        …\n  Name      fixture-scan\n …\n  ASR       12.3%\n\n"`.
- Server text (names, EULA content, prompts, summaries) is printed raw: an EULA containing `\e[31m` reached the terminal unchanged (captured).

### 2.4 SDK request layer (`SDK:10094-10240`, `SDK:9786-9850`, `SDK:10858-10872`, `SDK:11148-11155`)

- **Client-side checks before any request.** `assertUuid` (`SDK:11148`) throws `AISECSDKException` `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid <field>: <value>` for: `scans.get|abort` (`job id`), every `reports.*` and `customAttackReports.*` (`job id`), `customAttacks.getPromptSet|updatePromptSet|archivePromptSet|getPromptSetVersionInfo|downloadTemplate|uploadPromptsCsv|listPrompts` (`prompt set uuid`), `getPrompt|updatePrompt|deletePrompt` (`prompt set uuid`, then `prompt uuid`). Instance and device `tenantId`, property names and `--serial-numbers` are not checked. The CLI prints it through `fail` (exit 1) after the banner, after the tenant was loaded; no API request is made (the token request is not made either: tokens are fetched in `prepare`).
- **Request schemas (zod).** Bodies are validated before sending; a failure is `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for <METHOD> <path> did not match schema: <field>: <code>; …` (exit 1). Codes only, never values (`SDK:10102-10113`). `validatedBody` (the zod output) is what is sent; captured bodies keep the CLI's key order.
- **Path building.** `path` strings are concatenated without encoding for `instances` (`/v1/instances/${tenantId}`, `/devices`) (`SDK:16653-16884`); `new URL()` then resolves dot segments and splits `?`/`#`. Captured: `redteam instances rm ../registry-credentials` sent **`DELETE /mgmt/v1/registry-credentials`**; `instances get 'a/b?x=1#frag'` sent `GET /mgmt/v1/instances/a/b?x=1`. `getPropertyValues` uses `encodeURIComponent` (`a b/c` → `/property-values/a%20b%2Fc`).
- **Retries are method-blind** (`executeWithRetry`, `SDK:9786-9850`). With `numRetries` 5, a 500/502/503/504 or a network/timeout error is retried up to 5 more times (6 attempts) for **every method**, honouring `Retry-After` (capped at 60 s), else random backoff `0..2^attempt s`. Captured (all with `Retry-After: 0` unless noted): `POST /v1/scan` 503 → 6 identical POSTs, exit 1; 502 then 200 → 2 POSTs, exit 0 (one scan reported, two submitted); a POST that never answers with `PANW_AI_SEC_TIMEOUT_MS=700` → 6 POSTs in 15 s, `  ✗ Error: AISEC_CLIENT_SIDE_ERROR:Request timed out` (no HTTP line); `POST /v1/scan/<id>/abort` 500 → 6 POSTs; `POST /v1/eula/accept` 504 → 6 POSTs; `GET /v1/scan/<id>` 500 → 6 GETs; `GET …/version-info` 500 → 6 GETs.
- **401/403 replay.** `OAuthAuth.onUnauthorized` (`SDK:10865-10872`) clears the token and replays once for a 401, or a 403 without `x-opa-decision: false`; that replay is free. Captured: `POST /v1/scan` 401 then 200 → `token, POST, token, POST`, exit 0; 403 then 200 → the same; 403 with `x-opa-decision: false` → one POST, exit 1; always 401 → two POSTs, `  ✗ Error: AISEC_CLIENT_SIDE_ERROR:expired\n    HTTP 401\n    Re-run with --debug to capture redacted API diagnostics.`; abort 401 then 200 → two aborts.
- **Not retried:** 4xx other than the replayed 401/403, including 409 and 429 (captured: one POST each).
- **Error text** (`fail`, `common.ts:12-25`; SDK `extractErrorMessage`): `"\n  ✗ Error: <TYPE>:<message>\n"` and, with a status, `"    HTTP <status>\n    Re-run with --debug to capture redacted API diagnostics.\n"`, then `"\n"`. `<message>` is the body's `error_message ?? message ?? data.message ?? error.message ?? msg ?? "API error <status>"`; a non-JSON body is echoed: captured 503 `text/html` → `AISEC_SERVER_SIDE_ERROR:API error 503: <html>upstream SECRETBODY</html>` (D11 class). A 422 with FastAPI `detail` → `AISEC_CLIENT_SIDE_ERROR:API error 422; [withheld]`. Bad JSON on 2xx → `AISEC_RESPONSE_VALIDATION:Response body is not valid JSON`; a 2xx failing the response schema → `AISEC_RESPONSE_VALIDATION:Response did not match schema: tsg_id: invalid_type; …` (field paths and codes). Both after the write was applied.
- **Response schemas are strict about required fields** (passthrough for extras), so fixtures must carry them; §21 lists the minimal shapes.

### 2.5 Interruption (`ts-cli-shell.md` §15)

No handler. SIGINT/SIGTERM kill the process (shell exit 130/143) with no message, no cleanup and no abort of a running scan. Captured: SIGINT and SIGTERM during `scan` polling → 130/143, stdout ends inside the progress line (`…25% (10/40)` with no newline), stderr only the two status lines; SIGINT during an unanswered `POST /v1/scan` → 130, the POST already sent (the service may create the scan).

### 2.6 Exit codes (TS)

- 0: success, including `eula accept` without `--force` (prints the EULA and a hint), `scan` ending `ABORTED` or `PARTIALLY_COMPLETE`, table formats that print nothing.
- 1: commander parse errors (D1 class), tenant/credential errors, SDK errors (HTTP, network, schema, UUID), file errors in `devices --config`, `prompt-sets upload`, `prompt-sets download --output-file`, a scan ending `FAILED`, environment report failures, report health `unknown`, `--strict` with an incomplete source.
- 2: `usageError`: `scan` option parse failures (§9.2), report option conflicts and validation (§10, §11), `--output` validation for the five read leaves, `--debug`/`PANW_AI_SEC_DEBUG` with the environment report.
- 130/143: by signal.

## 3. `redteam list|ls` (`rt:519-546`, `svc:483-518`)

Order: parse → preAction (`resolveOutput`, loads the tenant) → banner if pretty → `createService` (loads the tenant again, credential check) → request → render.

Request:
- Without `--all`: `scans.list({status?, job_type?, target_id?, limit?, skip})` → `GET <data>/v1/scan?skip=<offset>&limit=<limit>[&status=…][&job_type=…][&target_id=…]` (query order `skip, limit, status, job_type, target_id`; `serializeListing`, `SDK:10845-10851`).
  - `limit = parseInt(--limit)`; a falsy result (`0`, `NaN` from `abc`) drops `limit` (captured `?skip=0`).
  - `skip = Number(--offset ?? 0)`; captured `--offset -3` → `skip=-3`.
  - Filters are passed through unvalidated (any string).
- With `--all`: `scans.listAll({…filters, limit, max: Number(--max)})` → `collectSkipPages` (`SDK:10813-10826`): pages of `limit` (default 10; `--limit 0` makes `limit` undefined → 50) from `skip=0` until a short page, an empty page or `skip+n >= total_items`, stopping at `max` items (`0` = no cap). `--offset` is ignored. `--max abc` → `NaN` → `  ✗ Error: max must be a non-negative integer` (exit 1, after the banner). An empty page while `total_items` says more ends the walk silently.
- Normalisation (`svc:47-62`): `uuid, name, status, job_type→jobType, target_id, target.name→targetName, score, asr, total, completed, created_at`.

Pretty (captured, two jobs; the second has `score: null`, `created_at: null`):

```
"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n\n  Recent Scans:\n\n  11111111-1111-4111-8111-111111111111\n    fixture-scan  COMPLETED  STATIC  score: 7.5\n    2026-10-17T10:00:00Z\n\n  22222222-2222-4222-8222-222222222222\n    second-scan  RUNNING  DYNAMIC\n\n"
```

Per job (`ren:124-132`): `ui.dim(uuid)`; `"    <name>  <statusColor(status)>  <jobType>[  score: <score>]"`; `"    <dim createdAt>"` when set; a blank line. JSON (captured):

```
[
  {
    "id": "11111111-1111-4111-8111-111111111111",
    "name": "fixture-scan",
    "status": "COMPLETED",
    "type": "STATIC",
    "score": 7.5,
    "createdAt": "2026-10-17T10:00:00Z"
  },
  {
    "id": "22222222-2222-4222-8222-222222222222",
    "name": "second-scan",
    "status": "RUNNING",
    "type": "DYNAMIC",
    "score": "",
    "createdAt": ""
  }
]
```

An empty result prints `"  No scans found\n"` (dim) in pretty, json and table alike (captured for json and table).

## 4. `redteam status <jobId>` (`rt:987-999`)

Banner → `createService` → `scans.get(jobId)` (`assertUuid`, then `GET <data>/v1/scan/<jobId>`) → `renderScanStatus` (`ren:55-81`):

```
"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n\n  Scan Status:\n\n  ID        11111111-1111-4111-8111-111111111111\n  Name      fixture-scan\n  Type      STATIC\n  Target    fixture-target\n  Status    COMPLETED\n  Progress  40/40\n  Score     7.5\n  ASR       12.3%\n\n"
```

Rows: `ID`, `Name`, `Type`, `Target` (only when `target.name` is truthy), `Status` (coloured), `Progress` `<completed>/<total>` (only when both are non-null), `Score` (non-null; `String(number)`), `ASR` `asr.toFixed(1)%` (non-null; 12.345 → `12.3%`). Keys pad to the longest present key. A trailing empty line. `not-a-uuid` → banner, then `  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid job id: not-a-uuid`, exit 1, no request.

## 5. `redteam abort <jobId>` (`rt:266-278`, `svc:520-522`)

Banner → `createService` → `scans.abort(jobId)` (`assertUuid`; `POST <data>/v1/scan/<jobId>/abort`, no body, response `{job_id, message}` required) → stdout `"  ✓ Scan <jobId> aborted.\n"` (green). No confirmation, no status check first. The response's `message` is not shown. Retries: §2.4 (500 → 6 POSTs; 401 → replayed). A 404 → `  ✗ Error: AISEC_CLIENT_SIDE_ERROR:no such job\n    HTTP 404…`, exit 1.

## 6. `redteam categories` (`rt:283-295`, `svc:633-645`, `ren:380-404`)

Banner → `GET <data>/v1/categories` (response: array of `{id, display_name, description, sub_categories:[{id, display_name, description}]}`; all required) → pretty only (the root `--output` is ignored):

```
"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n\n  Attack Categories:\n\n  Security (SECURITY) — Security attacks\n    • Jailbreak (JAILBREAK) — Bypass guardrails\n    • Multi turn (MULTI_TURN) — Multi-turn attacks\n    • Prompt injection (PROMPT_INJECTION)\n\n  Safety (SAFETY)\n    • Toxic content (TOXIC) — Toxicity\n\n"
```

Category line `"  " + bold(displayName) + " " + cyan("(" + id + ")") + [dim(" — " + description) when non-empty]`; sub-category line `"    " + dim("•") + " " + displayName + " " + cyan("(id)") + [dim(" — " + description)]`; a blank line after each category. Empty → `  No categories found`.

## 7. `redteam languages` (`rt:1691-1706`, `svc:745-757`, `ren:934-973`)

`GET <data>/v1/languages`, or `GET <mgmt>/v1/languages` with `--management`; response `{multilingual_enabled, supported_job_types:[…], languages:[{code,name}]}` (all required). Pretty (captured):

```
"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n\n  Tenant Languages:\n\n  Multilingual         inactive\n  Supported Job Types  STATIC, DYNAMIC\n\n  Languages:\n\n    en  English\n    fr  French\n\n"
```

`Multilingual` is `active` (green) / `inactive` (red); job types joined by `, `, or `(none)`; each language `"    " + dim(code) + "  " + name`; no languages → after the key/value block `  No languages found` and no trailing blank line. JSON: `{"multilingualEnabled":…,"supportedJobTypes":[…],"languages":[{"code","name"}]}` (2-space indent). Table: `Code │ Name` of the languages only.

## 8. `redteam eula status|content|accept` (`rt:300-359`, `svc:241-265`, `ren:685-704`)

- `status`: banner → `GET <mgmt>/v1/eula/status` (`{is_accepted}` required; `uuid`, `accepted_at`, `accepted_by_user_id` optional) → section `EULA Status:` with `Accepted  yes|no` (green/red), `Accepted At`, `Accepted By` (when truthy) and a blank line. Captured not accepted: `"…\n\n  EULA Status:\n\n  Accepted  no\n\n"`; accepted: `Accepted     yes` / `Accepted At  2026-10-01T00:00:00Z` / `Accepted By  u@example.com`.
- `content`: banner → `GET <mgmt>/v1/eula/content` (`{content}`) → `"\n  EULA Content:\n\n  <content>\n\n"`. Only the first line is indented; control characters pass through.
- `accept` (`rt:330-359`):
  1. `resolveDeprecatedAliases`: `--confirm` prints stderr `  ⚠ --confirm is deprecated and will be removed in v4 — use --force` (yellow, not quiet-suppressed) and sets `force`.
  2. Banner → `GET <mgmt>/v1/eula/content` (always, also with `--force`).
  3. Without `--force`: renders the content and `ui.dim('Pass --force to accept.')`, exit **0**, no POST. There is **no TTY prompt** (the docs' `--force: Skip confirmation prompt` notwithstanding). Captured: `"…\n\n  EULA Content:\n\n  FIXTURE EULA TEXT v1\n\n  Pass --force to accept.\n"`.
  4. With `--force`: `POST <mgmt>/v1/eula/accept` body `{"eula_content":"<content as fetched>","accepted_at":"<client new Date().toISOString()>"}` → `renderEulaStatus(response)` → `  ✓ EULA accepted.` Captured: `"…\n\n  EULA Status:\n\n  Accepted     yes\n  Accepted At  2026-10-17T10:00:00Z\n  Accepted By  user-1\n\n  ✓ EULA accepted.\n"`. Retries: 504 → 6 POSTs (§2.4). No check of the current status first, so re-running re-POSTs (the docs call it idempotent).

## 9. `redteam scan` (`rt:896-982`, `svc:439-476`, `svc:647-667`)

### 9.1 Validation order

1. commander: `--target` and `--name` required (`error: required option '--target <uuid>' not specified`, exit 1).
2. In the action, before the banner and before the tenant (`rt:921-930`), each failure → `usageError(message)` (exit 2, `"\n  ✗ <message>\n\n"` on stderr):
   - `--categories`: `JSON.parse`; the raw `SyntaxError` message, e.g. `Expected property name or '}' in JSON at position 1 (line 1 column 2)`. Any JSON value is accepted: `[1,2]` is sent as `categories: [1,2]` (the SDK's `z.record(z.unknown())` accepts it, captured), `null` behaves as "not given" (defaults to all).
   - `--goals` (`parseAttackGoals`, `rt:89-102`): trimmed; starts with `[` → inline JSON, else a file path read with `readFileSync(path,'utf-8')` (relative to cwd, symlinks followed, no size cap). Messages: the raw fs error (`ENOENT: no such file or directory, open 'missing.json'`), `--goals: invalid JSON (<SyntaxError message>)`, `--goals: expected a JSON array of non-empty strings`.
   - `--depth`, `--breadth` (`parsePositiveInt`, `rt:119-125`): `parseInt(input,10)`, must be finite and > 0, else `--depth: expected a positive integer, got "0"`. Lenient: `2.5x` → 2 (captured `stream_depth: 2`). Both are parsed for every `--type`.
3. `--prompt-sets` is split on `,` and each part trimmed (empty parts kept); never validated.
4. Banner → `createService` (tenant, credentials).
5. If `--type` is exactly `STATIC` and no categories: `GET <data>/v1/categories`, then `buildDefaultCategories` (`rt:77-86`): `{<category id>: [<sub-category ids except "MULTI_TURN">]}` in server order; stderr status `  No --categories given — defaulting to all <N> categories (MULTI_TURN excluded). Pass --categories to narrow the scan.` where `<N>` counts **sub-categories** (captured `all 3 categories` for 3 sub-categories in 2 categories). An empty catalogue sends `categories: {}`.
6. stderr status `  Creating <type> scan "<name>"...` (the raw `--type` value).
7. `createScan` → zod `JobCreateRequestSchema` (`SDK:3954-3972`): `name` 3–255 characters, `target.uuid` a UUID, `job_type` one of `STATIC|DYNAMIC|CUSTOM|CLARA`, `job_metadata` one of the four metadata shapes. Failures exit 1 **after** the categories GET: `--name ab` → `…did not match schema: name: too_small`; `--target not-a-uuid` → `target.uuid: invalid_string`; `--type static` or `FOO` → `job_type: invalid_enum_value`.
8. `POST <data>/v1/scan` (§2.4 retries), then render, then the wait (§9.4).

Options that do not apply to the chosen type are ignored silently (`--goals` and `--prompt-sets` with `STATIC`, `--categories` with `DYNAMIC`/`CUSTOM`).

### 9.2 Request bodies (captured)

| Invocation | `job_metadata` |
|---|---|
| `STATIC`, no `--categories` | `{"categories":{"SECURITY":["JAILBREAK","PROMPT_INJECTION"],"SAFETY":["TOXIC"]}}` |
| `STATIC --categories '{"SECURITY":["JAILBREAK"]}'` | `{"categories":{"SECURITY":["JAILBREAK"]}}` |
| `DYNAMIC --goals '["leak secrets","escalate"]' --depth 3 --breadth 2` | `{"stream_breadth":2,"stream_depth":3,"attack_goals":["leak secrets","escalate"]}` |
| `DYNAMIC` (no goals) | `{"stream_breadth":6,"stream_depth":10}` (`attack_goals` only when non-empty, `svc:461-466`) |
| `CUSTOM --prompt-sets 'a, b'` | `{"custom_prompt_sets":["a","b"]}` |
| `CUSTOM` without `--prompt-sets` | `{}` (accepted by the schema as the dynamic shape, sent, captured) |

The whole body is `{"name":"<name>","target":{"uuid":"<target>"},"job_type":"<type>","job_metadata":{…}}`. `svc:450-456` also throws `STATIC scans require categories. Pass categories explicitly or use the CLI default.` when categories are missing, unreachable from the CLI.

### 9.3 Output after the POST

`renderScanStatus(job)` of the POST response (§4 layout; a `QUEUED` job without totals has no `Progress`, `Score`, `ASR`). Then:
- `--no-wait`: `ui.keyValue([['Job ID', uuid]])` and `ui.dim('Run `airs-cli redteam status <jobId>` to check progress.')`. Captured:
  ```
  "\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n\n  Scan Status:\n\n  ID      11111111-1111-4111-8111-111111111111\n  Name    nightly\n  Type    STATIC\n  Target  fixture-target\n  Status  QUEUED\n\n  Job ID  11111111-1111-4111-8111-111111111111\n  Run `airs-cli redteam status <jobId>` to check progress.\n"
  ```
  stderr `"  No --categories given — … Pass --categories to narrow the scan.\n  Creating STATIC scan \"nightly\"...\n"`. With `--quiet`: stdout is only the key/value rows, the blank line and `  Job ID  <id>`.
- Waiting (default): stderr `  Waiting for completion...`, then §9.4, then stdout `"\n\n"` (`console.log('\n')`), `renderScanStatus(final job)`, `  Job ID  <id>` and the dim hint `Run `airs-cli redteam report <jobId>` to view results.`

### 9.4 Polling (`svc:647-667`)

- Loop: `GET <data>/v1/scan/<id>` immediately, then every **5000 ms** (`setTimeout`), with **no overall timeout, no poll limit and no limit on consecutive failures** beyond the SDK's per-request retries.
- After each GET: `onProgress` → `renderScanProgress` (`rren:6-20`), written with `process.stdout.write` to **stdout**, not quiet-suppressed, even when stdout is not a TTY: `"\r  <statusColor(status)> <bar> <pct>% (<completed>/<total>)"` with `pct = round(completed/total·100)`, `bar` = `█`×round(pct/5) + `░`×(20 − that), when both counts are set and `total > 0`; else `"\r  <status>..."`.
- `status === 'FAILED'` → throws `Scan <id> failed` → `  ✗ Error: Scan <id> failed` (exit 1; stdout ends without a newline after the progress line).
- `COMPLETED`, `PARTIALLY_COMPLETE`, `ABORTED` → success (exit 0); `ABORTED` and `PARTIALLY_COMPLETE` print the same completion block as `COMPLETED`.
- Any other status (including unknown ones, captured `WEIRD`) keeps polling forever.
- A GET failure (after its 6 attempts for 5xx) ends the command: `  ✗ Error: AISEC_SERVER_SIDE_ERROR:poll fail\n    HTTP 500\n…` exit 1. The scan keeps running on the service and nothing says so; its ID appears only in the earlier `Scan Status` block.
- Captured three-poll run (`QUEUED, RUNNING, COMPLETED`), 10 s:
  ```
  stdout: "…\n  Status  QUEUED\n\n\r  QUEUED █████░░░░░░░░░░░░░░░ 25% (10/40)\r  RUNNING █████░░░░░░░░░░░░░░░ 25% (10/40)\r  COMPLETED ████████████████████ 100% (40/40)\n\n\n  Scan Status:\n\n  ID        11111111-…\n  Name      fixture-scan\n  Type      STATIC\n  Target    fixture-target\n  Status    COMPLETED\n  Progress  40/40\n  Score     7.5\n  ASR       12.3%\n\n  Job ID  11111111-1111-4111-8111-111111111111\n  Run `airs-cli redteam report <jobId>` to view results.\n"
  stderr: "  Creating STATIC scan \"waited\"...\n  Waiting for completion...\n"
  ```
- Interruption: §2.5. Nothing is aborted.

### 9.5 Duplicate and billed-work hazards (captured)

- A 5xx, a timeout or a network error on `POST /v1/scan` re-sends the identical POST up to 5 more times, so up to six billed scans can start while the CLI reports at most one (or none: exit 1 after six 503s).
- A 401/403 replays the POST once (a 401 means not processed; a 403 might have been).
- There is no confirmation, no budget and no idempotency key.

## 10. `redteam report|dashboard <jobId>` (per-job report; `rr:45-55`, `rt:848-886`)

Option checks first (`rr:46-55`), before the banner, the tenant and any request:
- With a job ID, any of `--output`, `--output-file`, `--title`, `--max-pages`, `--strict` given on the leaf (source `cli`) **or** the root `--output` being `html`/`markdown` → `  ✗ Environment report options cannot be combined with a scan job ID` (exit 2). The leaf `--output` never receives a value (§2.2), so `report <id> --output json` passes the check and prints pretty; `report <id> --output html` fails it through the root value.
- `--debug` is allowed here (`prog:144`), unlike the environment report.

Sequence: banner → `createService` → `GET <data>/v1/scan/<id>` → `renderScanStatus` → by `jobType`:
- `CUSTOM`: `GET <data>/v1/custom-attacks/report/<id>` → `renderCustomReport`; with `--attacks`, `GET <data>/v1/custom-attacks/job/<id>/list-custom-attacks?limit=<parseInt(--limit)>` → `renderCustomAttackList`.
- `DYNAMIC`: `GET <data>/v1/report/dynamic/<id>/report` → `renderDynamicReport` (`--attacks` ignored).
- anything else (STATIC, CLARA, unknown): `GET <data>/v1/report/static/<id>/report` → `renderStaticReport`; with `--attacks`, `GET <data>/v1/report/static/<id>/list-attacks?limit=<n>[&severity=<raw --severity>]` → `renderAttackList` with the footnote of `buildAttackListFootnote` (`ren:295-306`).
- `--severity` without `--attacks` is ignored. `--limit abc` sends `limit=NaN`, because `serializeListing` stringifies the `NaN` (as for `prompts list`, §16).

Normalisation (`svc:524-631`): static `severity_report.stats[] → {severity, successful??0, failed??0}`, `security_report.sub_categories[] → {displayName, successful, failed, total ?? s+f, asr = total>0 ? s/total·100 : 0}` (only `security_report`; safety and brand reports are not shown), `report_summary` with `{{CRITICAL_RISK}}`, `{{HIGH_RISK}}`, `{{MEDIUM_RISK}}`, `{{LOW_RISK}}`, `{{INFORMATIONAL_RISK}}` replaced by `critical risk` … (`svc:71-86`; unknown `{{…}}` kept). Dynamic `score, asr, total_goals, goals_achieved, total_streams, total_threats, report_summary`. Custom `total_prompts, total_attacks, total_threats, failed_attacks, score, asr, custom_attack_reports[]`. Attacks: `uuid, attack_name, severity, category, sub_category, sub_category_display_name, threat ?? false`; the attack `prompt` is never printed. Custom attacks: `prompt_text, goal, threat ?? false, asr, prompt_set_name`.

Static layout (captured, STATIC job, `--attacks --severity HIGH --limit 5`):

```
…Scan Status block…
"\n  Static Scan Report:\n\n  Score  8.25\n  ASR    20.0%\n\n  Severity Breakdown:\n\n    HIGH       3 bypassed  7 blocked\n    LOW        0 bypassed  5 blocked\n\n  Categories:\n\n   Category         │ ASR   │ Bypassed/Total \n  ──────────────────┼───────┼────────────────\n   Jailbreak        │ 30.0% │ 3/10           \n   Prompt injection │ 0.0%  │ 0/5            \n\n  Summary:\n\n    Overall high risk posture {{UNKNOWN}}\n\n\n  Attacks:\n\n    HIGH       BYPASSED  Jailbreak [SECURITY]\n    N/A        BLOCKED  Prompt injection [SECURITY]\n  (showing 2 of 10 expected for severity HIGH — list-attacks endpoint excludes some variants; tracking upstream divergence at #206)\n\n"
```

- Severity line `"    " + sevColor(sev.padEnd(10)) + " " + red("<n> bypassed") + "  " + green("<n> blocked")` (`CRITICAL` red, `HIGH` magenta, `MEDIUM` yellow, `LOW` cyan, else dim).
- The categories table is `ui.table` (each line prefixed by two spaces).
- Attack line `"    " + (sev ? sevColor(sev.padEnd(10)) : dim("N/A".padEnd(10))) + " " + (threat ? red("BYPASSED") : green("BLOCKED")) + "  " + (subCategoryDisplayName ?? subCategory ?? "—") + [dim(" [" + category + "]")]`.
- No attacks → `  No attacks found` then the footnote (dim) when warranted and no trailing blank line.
- Score sections print only when present; static and custom ASR are printed as given (`20` → `20.0%`), the **dynamic** ASR is multiplied by 100 (`0.25` → `25.0%`).

Dynamic (captured): `"\n  Dynamic Scan Report:\n\n  Score    6\n  ASR      25.0%\n  Goals    1 achieved / 4 total\n  Streams  24\n  Threats  2\n\n  Summary:\n\n    Dynamic low risk\n\n"`.

Custom with `--attacks --limit 3` (captured): `"\n  Custom Attack Report:\n\n  Score    7\n  ASR      30.0%\n  Attacks  10\n  Threats  3\n\n  Prompt Sets:\n\n   Prompt Set  │ Threats │ Threat Rate \n  ─────────────┼─────────┼─────────────\n   fixture-set │ 3/10    │ 30.0%       \n\n\n  Custom Attacks:\n\n    THREAT ASR: 50.0%  XXXXX…(77 X)...\n      Leak\n\n"`. Prompt text over 80 UTF-16 units becomes the first 77 + `...`; `THREAT` red / `SAFE` green; ` ASR: n%` dim when set; the goal on its own dim line. No custom attacks → `  No custom attacks found`.

`not-a-uuid` → banner, `Invalid job id`, exit 1.

## 11. `redteam report|dashboard` (environment report; `rr:56-110`, `env:55-366`)

### 11.1 Validation order (all exit 2, before the tenant and any request)

1. `prog:139-151`: `--debug` or `PANW_AI_SEC_DEBUG` matching `^(1|true|yes|on)$` (trimmed, case-insensitive) → `  ✗ Disable --debug and PANW_AI_SEC_DEBUG for environment reports to avoid persisting sensitive traffic content`.
2. `--attacks`, `--severity` or `--limit` given → `  ✗ --attacks, --severity and --limit require a scan job ID`.
3. Format `= leaf --output ?? root --output ?? 'html'`; in practice the root value (§2.2). The tenant's `defaultOutput` is **not** used. Not `html`/`markdown` → `  ✗ Report output must be html or markdown`.
4. `--max-pages` must match `^[1-9]\d*$`, be a safe integer and ≤ 100 → `  ✗ --max-pages must be an integer from 1 to 100` (`0`, `101`, `1e1`, `1.5` captured or tested).
5. `--title` must be a non-blank string of ≤ 240 UTF-16 units → `  ✗ --title must contain 1–240 characters`.
6. `--output-file` given but blank after trim → `  ✗ --output-file cannot be empty`.

### 11.2 Destination and pre-checks

- Default name `airs-redteam-report-<new Date().toISOString() with ':' → '-'>-<first 8 chars of a random UUID>.<html|md>` in the cwd, e.g. `airs-redteam-report-2026-10-18T02-12-20.656Z-f0acbe96.html`. The format picks the extension; `--output-file` is used as given (no extension check), resolved against the cwd.
- `--output-file -` → stdout.
- Before loading the tenant: `lstat(path)`. Anything that exists, **including a dangling symlink**, → the generic failure (§11.5), exit 1, no request, the file untouched (captured; TS integration test "refuses existing paths before loading credentials or making network calls"). Other `lstat` errors than `ENOENT` take the same path.
- Then `loadConfig`, `new RedTeamClient({...redTeamClientOptions(config), numRetries: 0})` and stderr `  Collecting Red Team statistics and current configuration (read-only)...`.

### 11.3 Data gathered (one client, sequential, `numRetries: 0` so no 5xx retry; a 401/403 still gets the free token replay, captured)

| # | Source (name, method label, window label) | Request | Read |
|---|---|---|---|
| 1 | `Overview`, `getDashboardOverview()`, `Current dashboard snapshot` | `GET <mgmt>/v1/dashboard/overview` | `total_targets` |
| 2 | `Statistics`, `getScanStatistics()`, `Server-default window (unverified)` | `GET <data>/v1/dashboard/scan-statistics` | `total_scans`, `targets_scanned`, `risk_profile[].{risk_rating,total}`, `scan_status[].{name,count}` |
| 3 | `Targets`, `targets.list()`, `Current paginated inventory` | `GET <mgmt>/v1/target?skip=<n>&limit=15` per page | `target_type` per row |
| 4 | `Quota`, `getQuotaSummary() — GET`, `Current quota snapshot` | `GET <data>/v1/metering/quota` | `static|dynamic|custom.{allocated,consumed,unlimited}` |
| 5 | `Scans`, `scans.list()`, `Paginated inventory; local 24-hour creation filter` | `GET <data>/v1/scan?skip=<n>&limit=15` per page | `status`, `created_at` |
| 6 | `Network broker`, `networkBroker.getChannelStats()`, `Current channel snapshot` | `GET <nb>/v1/channels/stats` | `total_channels`, `online_channels` |
| 7 | `Adapters`, `adapters.list({ include_target_count: true })`, `Current paginated configuration` | `GET <mgmt>/v1/adapters?skip=<n>&limit=15&include_target_count=true` per page | `status` per row |

- Pagination (`env:126-162`): up to `--max-pages` pages; `skip` = rows so far; each page must have a `data` array, a valid `pagination.total_items` equal to the first page's, ≤ 15 rows, unique non-empty `uuid`s; it stops when rows = total; an empty page before that, a total change, rows > total or the budget are errors.
  - With no rows the source becomes `unavailable`; with rows it becomes `partial` with a note.
  - Notes: `Missing inventory array.`, `A required counter is missing or invalid.`, `Inventory changed during pagination.`, `Page exceeds requested size.`, `Missing or repeated identity; pagination stopped.`, `Inventory exceeds reported total.`, `Premature empty page.`, `Reached the <n>-page budget; inventory is incomplete.`, `HTTP <code>: source unavailable; check credentials, service availability and SDK compatibility.`, `Source request or validation failed. No upstream error body is included.`
- Counters must be safe non-negative integers (`count`, `env:41-45`). Labels are stripped of `\p{Cc}\p{Cf}` (→ space) and cut to 120 UTF-16 units (`env:39-40`); groups are counted per label and sorted by `localeCompare`.
- Findings (`priority, title, evidence, recommendation, source`):
  - `attention` `Elevated risk reported` for each `high|critical` risk rating with a total > 0;
  - `attention` `<kind> quota has no remaining allocation` for a finite quota with consumed ≥ allocated;
  - `attention` `Scans require failure review` when collected scans have status `failed|error` (case-insensitive);
  - `review` `Daily activity has timestamp gaps` for scans whose `created_at` lacks `Z`/`±hh:mm` or is in the future;
  - `review` `Confirm expected broker connectivity` when total > online;
  - `review` `<source> incomplete` for every source that is not complete.
- Health: `unknown` when every source is unavailable, else `attention` when any attention finding, else `review` when any finding, else `no-findings`.
- Only aggregates are written: no target names, IDs, connection settings, scripts, variables, prompts or upstream error bodies (`env:82`; TS unit test "excludes sensitive fields"; `PRIVATE-ERROR` from a rejected source never appears).

### 11.4 Rendering and writing

- HTML (`erender:96-107`): a self-contained document with a hash-based CSP (`default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…'; connect-src 'none'; base-uri 'none'; form-action 'none'`), `<meta name="referrer" content="no-referrer">`, inline CSS and JS, every value HTML-escaped as `&#<code>;` for `&<>"'`, sections per table plus `Evidence and completeness`, `Scope and limitations`, and the footer `Prisma AIRS CLI · Red Team report schema 1 · Works offline and without JavaScript.`; one trailing `\n`. A full captured copy is in `rtprobe/envreport.html` (11,704 bytes).
- Markdown (`erender:37-89`): `# <title>`, `**Prisma AIRS AI Red Teaming**`, `Assessment: **<health label>**`, `Collection: <start> → <end>`, `Scan creation window (UTC): <start> → <end>`, `## What needs attention` with `### <PRIORITY>: <title>` blocks, one `## <table title>` per table with a pipe table, `## Scope and limitations` and the footer `Prisma AIRS CLI · Red Team report schema 1`. Text is escaped by replacing each of `&<>"'\`*_[]{}()|!#~` with `&#<code>;` and CR/LF with a space. Captured copies: `rtprobe/envreport.md`, `envreport-strict.md`, `envreport-allfail.md`.
- Health labels: `Attention required`, `Review required`, `No findings in available evidence`, `Unable to assess`.
- Writing (`io:6-19`): `open(<dir>/.airs-report-<uuid>.tmp, 'wx', 0o600)`, write, `fsync`, close, `link(tmp, path)` (fails if the path appeared meanwhile), `unlink(tmp)` (fstrace captured `open`, `link`, `unlink`). The file is 0600 regardless of umask. A missing directory fails at `open` **after** all seven sources were collected.
- Success: stderr `  Report → <absolute path with \p{Cc}\p{Cf} → _> (mode 0600)`. stdout delivery: the document via one `process.stdout.write`; a write error sets exit 1.
- Then stderr `  <n> source(s) incomplete; review the evidence section.` when any source is not complete.

### 11.5 Exit codes and the failure message

- Exit 1 when health is `unknown` (the file is still written; captured all-404/503/401 run: file written, 7 sources incomplete, exit 1), or when `--strict` and any source is incomplete (captured: exit 1 after writing).
- Any thrown error in the `try` (existing path, config or credential error, write failure) → stderr `  ✗ Report generation failed. Verify Management API configuration and a writable, new output path. Existing files are never overwritten.` (red, no leading blank line), exit 1. No path, OS error or server text is shown (TS test "handles invalid config without exposing file contents").

## 12. `redteam registry-credentials` (`rt:500-514`, `svc:344-350`, `ren:778-796`)

- Treated as a read (`READ_COMMAND_NAMES`), but the request is **`POST <mgmt>/v1/registry-credentials`** with no body (`SDK:16873-16882`; "Get or create"). §2.4 retries apply (a 5xx re-POSTs up to 6 times).
- Response `{token, expiry}` (both required).
- Pretty (captured): `"…\n\n  Registry Credentials:\n\n  Token   FAKE-REGISTRY-TOKEN-...\n  Expiry  2026-10-18T10:00:00Z\n\n"`: the **first 20 characters** of the token plus `...`.
- JSON: `{"token": "<full token>", "expiry": …}`; YAML: `token: <full token>`. Table/csv/markdown: nothing, exit 0, after the POST.

## 13. `redteam instances create|get|update|delete` (`rt:364-440`, `svc:267-315`, `ren:732-775`)

| Command | Request | Body / notes |
|---|---|---|
| `create` | `POST <mgmt>/v1/instances` | `{"tsg_id","tenant_id","app_id","region"}` from the flags (zod `InstanceRequestSchema`: four strings) |
| `get <tenantId>` | `GET <mgmt>/v1/instances/<tenantId>` | response `{tsg_id, tenant_id, app_id, region}` required |
| `update <tenantId>` | `PUT <mgmt>/v1/instances/<tenantId>` | `{"tsg_id","tenant_id":<positional>,"app_id","region"}` |
| `delete\|rm <tenantId>` | `DELETE <mgmt>/v1/instances/<tenantId>` | no body; no confirmation |

`<tenantId>` is not encoded (§2.4: `../x` traverses). Write responses `{tsg_id, tenant_id?, app_id?, is_success?}` → `renderInstanceResponse`: section `Instance:` with `TSG ID`, `Tenant ID`, `App ID` (when truthy), `Success yes|no` (green/red, when set), a blank line. Captured create: `"…\n\n  Instance:\n\n  TSG ID     100\n  Tenant ID  ten-1\n  App ID     app-1\n  Success    yes\n\n"`; delete then adds `  ✓ Instance ten-1 deleted.` `get` pretty: section `Instance Detail:` with `TSG ID`, `Tenant ID`, `App ID`, `Region`; JSON `{"tsgId","tenantId","appId","region"}`; table nothing.

## 14. `redteam devices create|update|delete` (`rt:445-495`, `svc:317-342`)

- `create|update <tenantId> --config <path>`: banner → `createService` (tenant) → `JSON.parse(readFileSync(path,'utf-8'))` (raw `ENOENT: …, open 'missing.json'` or `SyntaxError` text as `  ✗ Error: …`, exit 1, no request) → zod `DeviceRequestSchema` (`instance:{app_id,region,tenant_id,tsg_id}` required, `created_by?`, `devices?:[{serial_number, …, licenses?:[{authorizationCode?, …}]}]`; a missing `instance` → `…did not match schema: instance: invalid_type`) → `POST` (create) or `PATCH` (update) `<mgmt>/v1/instances/<tenantId>/devices` with the parsed object.
- `delete|rm <tenantId> --serial-numbers <list>` → `DELETE <mgmt>/v1/instances/<tenantId>/devices?serial_numbers=<list>` (the list passed as one value: `SN1%2CSN2`); no confirmation.
- Output: stdout `  ✓ Devices created:` / `updated:` / `deleted:` (green) followed by `JSON.stringify(response, null, 2)` of the **raw** response (`DeviceResponseSchema` `{devices?:[{status, error?, serial_number?}], status?}` plus any passthrough fields). Captured: `"  ✓ Devices created:\n{\n  \"devices\": [\n    {\n      \"status\": \"created\",\n      \"serial_number\": \"SN1\"\n    }\n  ],\n  \"status\": \"ok\"\n}\n"`. `--output` is ignored.

## 15. `redteam prompt-sets …` (`rt:551-684`, `ps:46-133`, `ren:407-568`)

### 15.1 `list|ls`

- `customAttacks.listPromptSets()` with no options → `GET <mgmt>/v1/custom-attack/list-custom-prompt-sets` with **no query**: one server page (the server's default size), never walked.
- Rows `{uuid, name, active}`; then `sliceClientSide` (`rt:105-116`):
  - `--all` → first `--max` rows (0 = all);
  - otherwise `slice(offset, offset+limit)` with `parseInt`. `--limit -1` → `slice(0,-1)` drops the last row (captured); `--limit abc` → `NaN` → empty; `--all --offset 1` → offset ignored.
- Pretty (captured): `"…\n\n  Prompt Sets:\n\n  44444444-4444-4444-8444-444444444444\n    fixture-set  active\n  66666666-6666-4666-8666-666666666666\n    old-set  inactive\n\n"`; each set `ui.dim(uuid)` and `"    <name>  <active green|inactive red>"`; one blank line at the end.
- JSON `[{"id","name","status":"active|inactive"}]`; table `ID │ Name │ Status`. Empty → `  No prompt sets found` in every format.

### 15.2 `get <uuid>`

- `GET <mgmt>/v1/custom-attack/custom-prompt-set/<uuid>`, then `GET …/<uuid>/version-info`. Any version-info failure (after its retries: a 500 gives 6 GETs) is swallowed (`ps:113-124`).
- Pretty (captured):
  ```
  "…\n\n  Prompt Set Detail:\n\n  UUID         44444444-…\n  Name         fixture-set\n  Status       active\n  Archived     no\n  Description  Fixture prompts\n  Created      2026-10-17T10:00:00Z\n  Updated      2026-10-17T10:00:00Z\n\n\n  Version Info:\n\n  Version   3\n  Total     \n  Active    \n  Inactive  \n\n"
  ```
  `Description`, `Created`, `Updated` are shown only when truthy.
- **Defect:** the CLI reads `stats.total|active|inactive` (`ren:548-561`) but the API (and the SDK schema `CustomPromptSetVersionInfoSchema`) has `stats.total_prompts|active_prompts|inactive_prompts` and a string `version`, so `Total`, `Active` and `Inactive` are always empty.
- Version-info failure → `"\n  Version Info:\n\n  unavailable (version-info endpoint returned an error)\n\n"`.
- JSON (captured): `{"uuid","name","active","archive","description","createdAt","updatedAt","versionInfo":{"uuid","version":"3","stats":{"total_prompts":4,"active_prompts":3,"inactive_prompts":1}}}`; `versionInfo` is omitted when it failed. Table: nothing.

### 15.3 `create`, `update`, `archive`

- `create --name <n> [--description <d>]` → `POST <mgmt>/v1/custom-attack/custom-prompt-set` `{"name":<n>[,"description":<d> when truthy]}` (zod: `name` ≤ 255) → `  ✓ Prompt set created: <uuid>` and `  Name  <name>` (key/value).
- `update <uuid> [--name] [--description]` → `PUT …/custom-prompt-set/<uuid>` with only the truthy flags; **no flags sends `{}`** (captured) → `renderPromptSetDetail(response)` (pretty, no version info).
- `archive <uuid> [--unarchive]` → `PUT …/custom-prompt-set/<uuid>/archive` `{"archive":true|false}` → `  ✓ Prompt set <uuid> archived.` / `unarchived.`. No confirmation.
- The API has no delete for prompt sets (SDK has none; archive is the only removal).

### 15.4 `download <uuid>` (`rt:645-667`)

- `resolveDeprecatedAliases`: the hidden `--output <path>` alias is unreachable because the root parser consumes `--output` (§2.2). Captured: `download <uuid> --output out2.csv` wrote the **default** name, printed no deprecation warning, and set the root output to `out2.csv` (not validated: `download` is not a read).
- `GET <mgmt>/v1/custom-attack/download-template/<uuid>` (`responseType: 'text'`), then `fs.writeFileSync(outPath, csv, 'utf-8')` with `outPath = --output-file || '<uuid>-template.csv'` (cwd-relative).
  - The file is written **after** the request.
  - An existing file is **overwritten** (captured).
  - A **symlink is followed** (captured: `l.csv → victim.txt` replaced the victim's content).
  - The mode is the default `0666 & ~umask` (captured `-rw-r--r--`).
  - `-` creates a file literally named `-` (captured).
  - A missing directory → `  ✗ Error: ENOENT: no such file or directory, open '/nonexistent-dir/x.csv'` exit 1, after the request.
- stdout `  ✓ Template saved to <outPath>`.
- Captured template body: `prompt,goal\n"example prompt","example goal"\n` (the stub's; the real service defines the columns).

### 15.5 `upload <uuid> <file>` (`rt:669-684`)

- After the banner and the tenant, `readFileSync(file)` (whole file, no size cap, no encoding check; `ENOENT …` → exit 1).
- `POST <mgmt>/v1/custom-attack/upload-custom-prompts-csv?prompt_set_uuid=<uuid>`, `multipart/form-data` with one part `name="file"; filename="prompts.csv"` (the SDK renames it, `SDK:16100`), `Content-Type: text/csv`, the raw bytes.
- The response `{message, status}` (`BaseResponseSchema`): stdout `  ✓ <message>` (server text). A 5xx re-sends the upload (§2.4), possibly importing the prompts twice.

## 16. `redteam prompts …` (`rt:689-773`, `ps:57-165`, `ren:571-632`)

- `list <setUuid> [--limit 50]` → `GET <mgmt>/v1/custom-attack/custom-prompt-set/<setUuid>/list-custom-prompts?limit=<parseInt(--limit)>`: one page; `--limit abc` sends `limit=NaN`, `--limit 0` sends `limit=0`; the added `--offset`, `--all`, `--max` are never read (captured `--all --offset 5` → `?limit=50`).
  - Rows `{uuid, prompt, goal, active, promptSetId}`. `promptSetId` comes from `prompt_set_id`, absent in list rows, so JSON list rows show `promptSetId` only when the server sends it.
  - Pretty (captured): `"…\n\n  Prompts:\n\n  55555555-…  active\n    Ignore previous instructions\n    Goal: Leak the system prompt\n  77777777-…  inactive\n    YYYY…(77)...\n\n"`. Each prompt: `"  " + dim(uuid) + "  " + (green "active" | dim "inactive")`, `"    " + text` (over 80 UTF-16 units → 77 + `...`), `"    " + dim("Goal: " + goal)` when truthy. One blank line at the end.
  - JSON prints the array (`goal: null` kept); table prints nothing; empty → pretty `  No prompts found`, json `[]`.
- `get <set> <prompt>` → `GET …/custom-prompt-set/<set>/custom-prompt/<prompt>` → section `Prompt Detail:` with `UUID`, `Set UUID`, `Status` (`active` green / `inactive` dim), `Prompt` (full text), `Goal` (when truthy); JSON the object; table nothing.
- `add <set> --prompt <t> [--goal <g>]` → `POST <mgmt>/v1/custom-attack/custom-prompt-set/custom-prompt` `{"prompt":<t>,"prompt_set_id":<set>[,"goal":<g>]}` (zod: `prompt_set_id` must be a UUID) → `  ✓ Prompt added: <uuid>`.
- `update <set> <prompt> [--prompt] [--goal]` → `PUT …/custom-prompt/<prompt>` with the truthy flags (`{}` when none, captured) → `renderPromptDetail(response)`.
- `delete|rm <set> <prompt>` → `DELETE …/custom-prompt/<prompt>` (empty body allowed) → `  ✓ Prompt <prompt> deleted.` No confirmation.

## 17. `redteam properties …` (`rt:778-843`, `ps:167-190`, `ren:635-729`)

- `list|ls` → `GET <mgmt>/v1/custom-attack/property-names` → `data ?? []` → `sliceClientSide` (§15.1).
  - Pretty: `"\n  Property Names:\n\n  • language\n  • persona\n\n"` (dim bullet).
  - JSON: `["language","persona"]`; table/csv/markdown: column `Name`.
  - Empty: pretty `  No property names found`, json `[]`.
- `create --name <n>` → `POST <mgmt>/v1/custom-attack/property-names` `{"name":<n>}` (zod ≤ 256) → `  ✓ <response.message>`.
  - **Defect:** the SDK allows an empty body (`allowEmptyBody`, response optional), and then `result.message` throws `  ✗ Error: Cannot read properties of undefined (reading 'message')`, exit 1, **after** the name was created (captured).
- `values <name>` → `GET <mgmt>/v1/custom-attack/property-values/<encodeURIComponent(name)>` → `{name: raw.name ?? name, values: raw.values ?? []}`.
  - Pretty: section `Property Values:`, `  Property  <name>`, bullets, blank line; empty values → `  No property values found` (no key/value line).
  - JSON: `{"name","values":[…]}`; table: nothing.
- `add-value --name <n> --value <v>` → `POST <mgmt>/v1/custom-attack/property-values` `{"property_name":<n>,"property_value":<v>}` (zod value ≤ 256) → `  ✓ <message>`.
- Property names and values are tenant-wide; there is no delete.

## 18. Secret and sensitive-data exposure (TS)

| Data | Where it appears in TS |
|---|---|
| OAuth client secret, bearer token | never printed; not in errors (the token request error is `Token request failed: fetch failed`) |
| Registry token (a pull credential) | pretty: first 20 characters; json/yaml: in full; table: not printed (but minted). `--debug` logs only AIRS hostnames, and its key redaction replaces `token` body fields (`ts-debug-log.md`) |
| Server error bodies | echoed in `✗ Error:` for non-JSON bodies and for `message`-style fields (D11 class) |
| EULA content, names, descriptions, prompt text, goals, summaries | printed raw, control characters included (terminal injection) |
| Attack prompts of a static report | never printed (only labels); custom attack prompt text is printed (truncated) by `report --attacks` |
| Device request file (may hold license `authorizationCode`s) | read and sent; not printed; the raw device response is printed in full |
| Target name | printed in every `Scan Status` block |
| Environment report | aggregates only, 0600 file, no-clobber, generic failure text |
| Prompt-set template | written 0644, overwriting, following symlinks |

## 19. TS tests to port as acceptance tests

| TS spec | Behaviours |
|---|---|
| `unit/cli/redteam-scan-helpers.spec.ts` | `parseAttackGoals` (inline, leading whitespace, file, invalid JSON, non-strings, empty strings); `parsePositiveInt` (positive, non-numeric, zero, negative); `buildDefaultCategories` (mapping, MULTI_TURN excluded, empty catalogue → `{}`) |
| `unit/cli/redteam-attacks-renderer.spec.ts` | display name, raw sub-category fallback, `—`, BYPASSED/BLOCKED, footnote |
| `unit/cli/redteam-footnote.spec.ts` | footnote only with severity, known total, matching row, total < expected |
| `unit/cli/redteam-categories-renderer.spec.ts` | empty state; inline IDs; no descriptions |
| `unit/cli/redteam-dynamic-renderer.spec.ts` | header, score, ASR ×100, goals; no summary; missing numbers |
| `unit/cli/redteam-output-flag.spec.ts` (non-target parts) | prompt-set detail json/yaml with `versionInfo`; property values json/yaml/pretty/empty; property names json/yaml/pretty/empty |
| `unit/airs/redteam.spec.ts` (non-target, non-channel, non-adapter parts) | `createScan` bodies per type (STATIC requires categories, CUSTOM sets, DYNAMIC defaults 6/10 and goals); `getScan`/`listScans` normalisation and filters (`skip`); `abortScan`; static/dynamic/custom report normalisation incl. missing fields and `{{…}}` interpolation; `listAttacks` (display name, `threat` default false, `totalItems`); `listCustomAttacks`; `getCategories`; `waitForCompletion` (COMPLETED, PARTIALLY_COMPLETE, ABORTED resolve; FAILED throws; progress per poll); EULA content/status/accept; instances; devices; registry credentials; languages (data vs management) |
| `unit/reports/redteam.spec.ts` | seven reads with independent windows and no sensitive fields; partial records on budget, repeated identity and later page failure; pagination stops at the reported total; quota without the GET method fails closed (no POST); finite exhausted vs unlimited zero quota; no broker outage inferred; timestamp window and missing/future/ambiguous stamps; both formats escaped with inline assets and CSP |
| `integration/cli/redteam-dashboard.spec.ts` | `dashboard` alias; debug refusal through both names (exit 2, no client); HTML by default despite `defaultOutput: json`; Markdown via the root and local flags; stdout delivery and stream-error exit 1; unique default names; partial report exit 0, `--strict` exit 1; all unavailable → file written, `Unable to assess`, exit 1, no `PRIVATE-ERROR`; existing path refused before credentials and requests; invalid config without echoing content; the thirteen invalid-option cases exit 2 before client creation |

## 20. Rust SDK (`scm-sdk 0.1.0`) coverage

Every operation these commands need exists:
- `scans.create|list|list_all|get|abort|get_categories` (`rs:src/airs/red_team/scans.rs:50-170`);
- `reports.get_static_report|get_dynamic_report|list_attacks` (`reports.rs:44-186`);
- `custom_attack_reports.get_report|list_custom_attacks` (`custom_attack_reports.rs:47-167`);
- `eula.get_content|get_status|accept` (`eula.rs:20-56`);
- `instances.*` and `get_registry_credentials` (`instances.rs:15-150`);
- `custom_attacks.*` prompt sets, prompts, properties, `download_template`, `upload_prompts_csv` (filename `prompts.csv`) (`custom_attacks.rs:77-558`);
- `get_languages`, `get_management_languages`, `get_scan_statistics`, `get_quota_summary` (GET), `get_dashboard_overview` (`facade.rs:155-328`);
- `network_broker.get_channel_stats`, `targets.list`, `adapters.list`.

Properties that matter for the port:
- Writes (`create`, `abort`, `accept`, instance and device writes, `get_registry_credentials`, uploads, property and prompt writes) are `RawRequest::new(<method>, …)`, so they are not replay-safe and never re-sent (`rs:src/engine.rs:49-61`, `ts-runtime-writes.md`/`rs-sdk-writes.md` G1). Reads retry per D10.
- `segment()` rejects empty values, controls, `\`, `.`/`..` segments and their percent-encoded forms (`rs:src/config.rs:121-141`), so the `../registry-credentials` traversal of §2.4 becomes a `Validation` error with no request.
- `common::uuid` checks job and prompt-set IDs (`common.rs:55-61`); `common::filter` rejects controls and values over 4096 bytes in filters and `serial_numbers` (`common.rs:37-54`); `listing` rejects `limit == 0` (`common.rs:24`).
- `create_property_name` returns `Option<…>` for an empty body (`custom_attacks.rs:379-394`), so the §17 defect cannot happen with the SDK.
- `RegistryCredentials` has a redacting `Debug`; its `token` field is a plain `String` (`rs:src/models/generated.rs:159433`), so the CLI must add it to the `SecretSet` itself.

**No SDK gap found for these commands.** Not verified here and worth a check when implementing: that the Rust `JobCreateRequest` schema accepts `job_metadata: {}` for CUSTOM the way zod does (only relevant if the port keeps sending it; §Open questions 6 proposes refusing it).

## 21. Fixture contract for the harness

Minimal response shapes that satisfy both SDKs' required fields (zod shapes from `rtprobe/shapes.mjs`):
- Job (`JobResponseSchema`): `uuid, tsg_id, name, target:{uuid, tsg_id, name, status, active, validated, created_at, updated_at}, job_type, job_metadata` (STATIC `{categories:{…}}`, CUSTOM `{custom_prompt_sets:[…]}`, DYNAMIC `{}`), `target_id, target_type`; optional `status, total, completed, score, asr, created_at`.
- `JobListResponseSchema` `{pagination:{total_items?}, data:[job]}`; abort `{job_id, message}`; categories `[{id, display_name, description, sub_categories:[{id, display_name, description}]}]`.
- Languages `{multilingual_enabled, supported_job_types:[], languages:[{code,name}]}`; EULA content `{content}`, status/accept `{is_accepted, …}`.
- Instances `InstanceGetResponseSchema` `{tsg_id, tenant_id, app_id, region}`, writes `{tsg_id, …}`; devices `{devices?:[{status, …}], status?}`; registry `{token, expiry}`.
- Prompt set `{uuid, name, active, archive, status, created_at, updated_at, …}`; list `{pagination, data?:[…]}`; version info `{uuid, status, is_latest, version?, stats?:{total_prompts, active_prompts, inactive_prompts}}`.
- Prompt `{uuid, prompt, user_defined_goal, status, active, prompt_set_id, created_at, updated_at, goal?}`; list rows the same without `prompt_set_id`.
- `BaseResponseSchema` `{message, status}`; property names `{data?:[str]}`; values `{name, values?:[str]}`.
- Static report `{severity_report:{stats:[{severity, successful, failed}]}, asr?, score?, security_report?:{id, display_name, description, sub_categories:[…], asr, total_prompts, total_attacks, successful, failed}, report_summary?}`; dynamic `{…all optional}`; custom `{total_prompts, total_attacks, total_threats, failed_attacks, score, asr, custom_attack_reports?:[{prompt_set_id, prompt_set_name, total_prompts, total_attacks, total_threats, failed_attacks, threat_rate}]}`.
- Attacks `{pagination, data:[{uuid, tsg_id, job_id, target_id, prompt, prompt_mapping_id, prompt_id, category, sub_category, category_display_name, sub_category_display_name, threat?, severity?}]}`; custom attacks `{pagination, data:[{prompt_id, prompt_text, …}], total_attacks, total_threats}`.
- Report sources: overview `{total_targets}`; statistics `{total_scans, targets_scanned, scan_status?, risk_profile?}`; quota `{static|dynamic|custom:{allocated, unlimited, consumed}}`; channel stats `{total_channels?, online_channels?}`; target list rows `{uuid, tsg_id, name, status, active, validated, created_at, updated_at, target_type?}`; adapter list rows `{uuid (UUID), name, status, created_at, updated_at}`.
- The stub must route the three planes by path prefix and count calls per route so retry and replay tests can assert exact request sequences. `Retry-After: 0` keeps TS retries fast but their timing is random; assert counts, never durations (AGENTS.md).

## Acceptance criteria

Behaviour the Rust port must reproduce (parity unless a divergence below says otherwise), each pinned by an executable test against the loopback fixture:

1. Command tree, aliases (`ls`, `rm`, `dashboard`), required options and the help option sets of §1 (without `judge`).
2. Endpoints from the tenant only: data, management and network-broker planes as in §2.1; one token request per process; no environment fallback (a trap endpoint is never contacted).
3. Request shapes (method, path, query order, body keys and values) of §§3–17 for every command, including `skip`/`limit` mapping for `list`, `?limit=` for `prompts list` and the custom attacks list, `limit=15` pages for the report, `serial_numbers` as one value, `prompt_set_uuid` query and a `prompts.csv` part for uploads, `{"archive":bool}`, the EULA accept body with the fetched content and a client timestamp.
4. Scan bodies of §9.2 for STATIC (default all categories minus `MULTI_TURN`, from one categories GET, with the `defaulting to all <N> categories` status counting sub-categories), DYNAMIC (6/10 defaults, `attack_goals` only when non-empty) and CUSTOM; the status lines `Creating <type> scan "<name>"...` and `Waiting for completion...` on stderr.
5. Pretty layouts byte-for-byte as captured in §§3–17 (banner placement rules of §2.3, key padding, section spacing, status colours, truncation at 80 → 77 + `...` counted in UTF-16 units, the `N/A`/`—` fallbacks, footnote text). The ASR scaling stays as TS: static and custom as given, dynamic ×100. Numbers through the JS number formatting helper; `toFixed(1)` must round like JS (ties away from zero on the exact binary value, e.g. `0.25` → `0.3`), not like Rust's `{:.1}`.
6. JSON layouts of §2.2 and §§3–17 (key order, `""` for a missing score/createdAt in `list`, `goal: null` kept, `versionInfo` omitted when version-info fails), except where a divergence changes them.
7. Polling: a GET right after the POST, then every 5 s; `COMPLETED`, `PARTIALLY_COMPLETE`, `ABORTED` end the wait; `FAILED` is `✗ Error: Scan <id> failed`, exit 1; the completion block and the `redteam report <jobId>` hint (with the D73 program name).
8. Per-job report: the job-type dispatch, the conditional sections, `--attacks`/`--severity`/`--limit` handling and the option-conflict usage errors of §10.
9. Environment report: the validation order and messages of §11.1 (exit 2 before the tenant), the existing-path refusal before the tenant and any request (dangling symlinks included), seven sources in order with `numRetries 0`, the pagination and data checks with their notes, findings, health, both renderings (escaping, CSP, footer), 0600 no-clobber publication via temp file + link, `-` to stdout, the stderr lines, exit 1 for `unknown` health or `--strict` with an incomplete source, and the generic failure message.
10. EULA: status and content layouts; `accept` fetches the content first and posts it back.
11. `prompt-sets get` degrades to `unavailable (version-info endpoint returned an error)` when version-info fails, and the set itself still prints.
12. Exit codes of §2.6 as amended by the divergences; interruption exits 130/143.

## Open questions / likely §12 divergences

Numbers are proposals from D133; each needs a §12 row, a `dNN_` parity test asserting both sides, and a COMPATIBILITY.md row. **Bold** items are choices the user should confirm.

1. **D133 scan submission is never repeated.** TS re-POSTs `/v1/scan` on 5xx, network errors and timeouts (up to 6 billed scans, §9.5) and replays 401/403. Rust: one POST, the D95 single 401 replay, never a 403 replay. On outcome `Unknown`: `Outcome unknown: the scan may have been created.` plus a hint to check `redteam list --target <uuid>` before retrying; exit 1; no polling. Safety (duplicate billed work).
2. **D134 abort, EULA accept, registry credentials, uploads and every other red team write: one attempt** (D95 rules). TS retries them up to 6 times (`abort` 6 POSTs, `eula accept` 6 POSTs, `registry-credentials` 6 POSTs that may mint credentials, an upload that may import twice). The `Unknown`-outcome lines name the thing: `the scan may have been aborted`, `the EULA may have been accepted`, `registry credentials may have been issued`, `the prompts may have been uploaded`, etc. Safety.
3. **D135 confirmations (D81).** TS confirms none of these. Proposal: a D81 confirmation (TTY prompt; `--force` for scripts; no TTY and no `--force` → exit 2 before the tenant) for `abort` (stops billed work the user may not own), `instances delete`, `devices delete`, `prompts delete`. Not for `prompt-sets archive` (reversible with `--unarchive`).
   - **Choice:** should `scan` itself confirm (billed)? Recommendation: no prompt (the command's explicit purpose; CI runs it), and no §12 row.
4. **D136 `eula accept` follows D81.** TS: without `--force` it prints the EULA, `Pass --force to accept.`, exit 0, and has no prompt. Rust: on a TTY, show the content and prompt `Accept the Red Team EULA? (y/N)`; `--force` (and the deprecated `--confirm`, with its TS warning) accepts without the prompt; no TTY and no `--force` → usage error exit 2 before the tenant. **Choice:** keep the TS exit-0 "print and hint" path for non-TTY instead of exit 2? Recommendation: exit 2 (consistent with §13; scripts already pass `--force`).
5. **D137 registry credentials output (secret).** TS prints the first 20 characters in pretty, the full token in json/yaml, nothing in table. Proposal: pretty and table print `Token   (withheld; use --output json to print it)` with `Expiry`; json prints `{"token","expiry"}` (the command's purpose is to obtain the pull token); the token joins the `SecretSet` so it never appears in errors or the debug log; one POST (D134). **Choice:** require an explicit `--show-token` even for json? Recommendation: json prints it; pretty never does.
6. **D138 scan argument validation before the tenant (exit 2, no request).** TS validates most of these only in the SDK, after a categories GET, with exit 1, or not at all:
   - `--type` must be `STATIC|DYNAMIC|CUSTOM` (case-sensitive like TS, or accept lowercase? recommendation: exact, the TS enum);
   - `--name` 3–255 characters;
   - `--target` a UUID;
   - `--categories` a JSON object whose values are arrays of strings (TS sends `[1,2]` and treats `null` as absent);
   - `--depth`/`--breadth` strict positive integers (TS: `2.5x` → 2);
   - `--prompt-sets` required for CUSTOM, each a UUID, no empty parts (TS sends `job_metadata: {}`);
   - `--goals`/`--prompt-sets`/`--categories` given for the wrong `--type` → usage error (TS ignores).
   - Messages keep the TS texts where they exist (`--goals: …`, `--depth: expected a positive integer, got "<v>"`); the `--goals` file follows the §13.2 input-file rules (D103: size cap, UTF-8, no OS error text) and is read before the tenant.
   - Correctness, and no billed scan for a typo.
7. **D139 ID arguments.** Job and prompt-set/prompt UUIDs (`status`, `abort`, `report`, `prompt-sets get|update|archive|download|upload`, `prompts *`) and instance/device `tenantId`s are checked before the tenant: UUIDs by shape, `tenantId` by the SDK `segment` rules. A failure is a usage error, exit 2, no banner and no request. TS gives exit 1 after the banner, and `instances rm ../registry-credentials` sends `DELETE /v1/registry-credentials`. Safety (path traversal into another resource) and D2. **Choice:** keep the TS message text `Invalid job id: <id>` (recommended) through `terminal_safe`.
8. **D140 scan waiting.**
   - Progress goes to stderr, not stdout, and is quiet-suppressed: `\r`-redrawn on a terminal, one line per status/count change otherwise. stdout gets only the final block. TS writes `\r` progress into stdout, even when piped and with `--quiet`.
   - A poll failure or interruption prints on stderr `Scan <id> is still running on the service; it was not aborted. Check it with \`airs-cli-rs redteam status <id>\`.` Exit 1, or 130/143 with the §2.5 `Interrupted; …` form.
   - **Choices:**
     - (a) Should `ABORTED` exit 1, as an incomplete outcome (fail closed), while `PARTIALLY_COMPLETE` exits 0 with a warning? Recommendation: `ABORTED` → exit 1 with `Scan <id> was aborted`; `PARTIALLY_COMPLETE` → exit 0 plus `⚠ Scan <id> completed partially`.
     - (b) Bounded waiting: TS polls forever, including unknown statuses. Recommendation: keep polling unknown statuses (they may be new), add `--wait-timeout <minutes>` with no default bound, and stop after 5 consecutive failed polls (each already retried by the SDK) with the still-running line. Alternative: a default 24 h cap.
9. **D141 `prompt-sets download` file safety (settled rule).**
   - No-clobber, decided before the request: `lstat`, and an existing path or symlink is refused with exit 1 and no request.
   - Written 0600 via temp + link, as the report does. TS overwrites, follows symlinks, writes 0644 and writes after the request.
   - `-` writes to stdout (TS creates a file named `-`). **Choice:** confirm that `-` means stdout (recommended, matching `report`).
   - The hidden `--output <path>` alias cannot exist: the root `--output` is the format flag. `download <uuid> --output out.csv` is a usage error (`Invalid output format`); TS silently writes the default name.
10. **D142 `prompt-sets upload` and `devices --config` input files** follow §13.2 D103: a regular file, a size cap (16 MiB for CSV, 1 MiB for JSON), UTF-8 for JSON, messages without OS text, exit 1 before the tenant. TS reads after the tenant, with raw `ENOENT …`/`SyntaxError` text and no cap.
11. **D143 structured output for every command (M3.5 rule).** TS prints nothing for `table` on `instances get`, `registry-credentials`, `prompt-sets get`, `prompts list|get`, `properties values`, and ignores `--output` on `status`, `categories`, `eula status|content`, `scan`, per-job `report` and every write.
    - Rust: `pretty|table|json` everywhere. Table is `Key │ Value` for details and columns for lists. JSON is the normalized object: the job for `status`/`scan --no-wait`, the categories tree, the EULA status, the per-job report object. csv/markdown/yaml are usage errors (settled).
    - **Choice:** `scan` without `--no-wait` in json prints only the final job (recommended).
12. **D144 empty lists in json/table.** TS prints `  No scans found` / `  No prompt sets found` to stdout for `--output json|table`, which is not JSON. Rust: `[]` for json, and the §2.7 empty-table rule (nothing) for table. Correctness.
13. **D145 list pagination honesty.**
    - `prompt-sets list` and `properties list` slice one unpaged server response. Rust walks `list_all_prompt_sets` for prompt sets; property names have no pagination.
    - `prompts list` ignores `--offset/--all/--max`. Rust honours them via `prompt_pages`, or removes them; recommendation: honour them.
    - `--limit abc|0|-1` and negative `--offset` are sent or misapplied by TS. Rust: usage errors (`--limit must be a positive integer`, …) as in §7.
    - An `--all` walk ended by an empty page before `total_items` is reported as incomplete (D14/D15 spirit).
14. **D146 `prompt-sets get` version info.** Rust maps `stats.total_prompts|active_prompts|inactive_prompts` into `Total|Active|Inactive` and prints `version` as given (a string). TS always prints empty values. Correctness. JSON: keep the raw `versionInfo` object (parity) or normalize? Recommendation: keep it raw (parity).
15. **D147 `properties create` with an empty response.** Rust prints `  ✓ Property name created` and exits 0. TS crashes with `Cannot read properties of undefined (reading 'message')`, exit 1, after creating it. Correctness.
16. **Terminal safety.** EULA content, names, prompts, summaries and server messages go through `terminal_safe` (existing D52); control characters reach the terminal raw in TS. No new row if D52's wording covers red team text; otherwise extend it.
17. **Error bodies.** The non-JSON body echo (`API error 503: <html>…`) is the existing D11 difference; red team commands inherit it, with no new row.
18. **Outcome lines on stderr (D94-style).** TS prints `✓ Scan … aborted.`, `✓ Prompt set created: …`, `✓ Devices created:` on stdout, mixed with data. Rust: stdout data only, outcome lines on stderr. For devices that leaves the response JSON as the stdout data, in the format's layout. Needs a row (D148) unless an existing D94 row's wording is extended to M6a.
19. **Environment report format (settled rule vs artifact).** The settled rule drops `markdown` output. **Choice for the user:** recommendation, keep HTML (default) and Markdown as *artifact* formats of `redteam report` only, under a report-specific flag (`--format html|markdown`), because the root `--output` in Rust admits only `json|pretty|table`. Alternatively drop Markdown (a §12 row: `--output markdown` → usage error). Either way `redteam report --output json` stays a usage error, as in TS, and `defaultOutput` is ignored, as in TS.
20. **Report `--debug`.** TS refuses `--debug` and `PANW_AI_SEC_DEBUG` for the environment report (exit 2). Rust has no `PANW_AI_SEC_DEBUG` (D61–D69 class). Keep the `--debug` refusal with the TS text minus the env-var name? Recommendation: keep the refusal; the text names only `--debug`; a §12 row if the text changes.
21. **Report retries.** Keep TS `numRetries: 0` (one attempt per source, the free 401 replay kept), which differs from the D10 read policy; document it in the M6a section rather than as a §12 row.
22. **`redteam list` JSON `""` for a missing score/creation time.** Parity, or `null`? Recommendation: parity (`""`), no row.
23. **Interruption (D149).** Rust prints `Interrupted; the scan may have been created (outcome unknown)` during the POST, the D140 still-running line during the wait, and the §13.2 contexts for other writes. Exit 130/143. TS prints nothing.
