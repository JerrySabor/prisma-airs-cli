# Spec: TS `airs-cli` red team targets, adapters and network broker (M6a)

Commands covered: `redteam targets list|get|create|update|delete|probe|profile|update-profile|validate-auth|metadata|init|templates|backup|restore|error-logs`, `redteam adapter list|get|create|update|delete|validate`, `redteam network-broker channels list|get|create|update` and `redteam network-broker stats`.

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0, SDK `@cdot65/prisma-airs-sdk` 0.34.0, commander 14). Citations:
  - `rt.ts:<line>` is `src/cli/commands/redteam.ts`.
  - `svc.ts:<line>` is `src/airs/redteam.ts` (`SdkRedTeamService`).
  - `rrt.ts:<line>` is `src/cli/renderer/redteam.ts`; `rbk.ts:<line>` is `src/cli/renderer/backup.ts`.
  - `bk.ts`, `rs.ts` are `src/cli/commands/backup.ts` and `restore.ts`; `io.ts` is `src/backup/io.ts`.
  - `ui.ts`, `common.ts`, `confirm.ts`, `program.ts`, `deprecated-flags.ts` are under `src/cli/` (`renderer/` for the first two).
  - `co.ts` is `src/config/client-options.ts`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` of the reference build.
- Shared shell behaviour (commander parse errors exit 1, the root `--output` consumer, `resolveOutput`, the `ui` stream map, quiet mode, colour, EPIPE) is already specified in `ts-cli-shell.md` §3–§15 and is only restated where these commands depend on it.
- How behaviour was captured: the reference build (`dist/cli/index.js`, node v24.21.0) ran against a stateful loopback stub (`node:http` on `127.0.0.1`, random port) that implements the mgmt, data and broker routes used here, logs every request (method, path, ordered query, JSON body) and accepts a fault plan (status, raw body, headers such as `Retry-After: 0`, `x-opa-decision`, or a hang).
  - Sandbox: `env -i` with `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` inside the sandbox, a TS registry selected through `PRISMA_AIRS_TENANTS_PATH`, fake credentials (`fake-client`/`FAKE-SECRET`, TSG `100`) and fake target secrets (`FAKE-TARGET-AUTH`, `FAKE-HEADER-KEY`, `FAKE-OPENAI-KEY`, `NEW-SECRET`, `VAR-SECRET-VAL`).
  - The tenant sets `mgmtTokenEndpoint`, `redTeamDataEndpoint` (`<base>/rt/data`), `redTeamMgmtEndpoint` (`<base>/rt/mgmt`) and `redTeamNetworkBrokerEndpoint` (`<base>/rt/broker`). These CLI commands pass every endpoint explicitly (§2.1), so the SDK's `PANW_RED_TEAM_*`/`PANW_MGMT_*` environment fallbacks are never consulted; the probe environment set none of them.
  - Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and `dns.lookup` and refuses any host other than `127.0.0.1`. The guard log stayed empty: nothing tried to leave loopback.
  - Prompts were driven on a pty with `expect`; signals with `kill -INT|-TERM` during a hung request.
- No real tenant or credential file was read; no host other than loopback was contacted.
- Captures are shown as JSON strings (`"\n  ..."`). `<sb>` stands for the sandbox working directory. `NO_COLOR` has no effect on chalk; captures are uncoloured because stdout was a pipe. §2.8 lists the ANSI codes captured with `FORCE_COLOR=1`.

## 1. Command surface (help verified)

Aliases: every visible `list` gets `ls` and every `delete` gets `rm` (`program.ts:42-51`). Help sorts options and subcommands (`program.ts:73-76`). `applyReadContractFlags` (`program.ts:54-70`) adds `--all` (`Walk all pages`) and `--max <n>` (Number, default 10000, `Maximum items with --all; 0 removes the cap`) to every `list` that has `--limit` or `--offset`; that covers `targets list`, `adapter list` and `channels list`. Help text wraps at 80 columns when stdout is not a terminal.

| Command | Registration | Arguments and options (help text, defaults) |
|---|---|---|
| `targets list\|ls` | `rt.ts:1006-1030` | `--limit <n>` (`Max results (client-side)`), `--offset <n>` (`Starting offset (client-side)`), `--output <format>` (`Output format: pretty, table, csv, json, yaml`, default `"pretty"`), `--all`, `--max <n>`. Examples: `targets list`, `targets list --output json`, `targets ls --limit 5` |
| `targets get <uuid>` | `rt.ts:1032-1046` | `--output <format>` (`pretty, json, yaml`, default `"pretty"`) |
| `targets create` | `rt.ts:1048-1067` | `--config <path>` (required, `JSON file with target configuration`), `--validate` (`Validate target connection before saving`) |
| `targets update <uuid>` | `rt.ts:1069-1089` | `--config <path>` (required, `JSON file with target updates`), `--validate` |
| `targets delete\|rm <uuid>` | `rt.ts:1091-1107` | `--force` (`Skip confirmation prompt`) |
| `targets probe` | `rt.ts:1109-1124` | `--config <path>` (required, `JSON file with connection params`) |
| `targets profile <uuid>` | `rt.ts:1126-1139` | none (`View target profile`) |
| `targets update-profile <uuid>` | `rt.ts:1141-1156` | `--config <path>` (required, `JSON file with profile updates`) |
| `targets validate-auth` | `rt.ts:1158-1178` | `--auth-type <type>` (required, `Auth type: HEADERS, BASIC_AUTH, OAUTH2`), `--config <path>` (required, `JSON file with auth_config`), `--target-id <uuid>` (`Existing target UUID`) |
| `targets metadata` | `rt.ts:1180-1191` | none (`Get target field metadata`) |
| `targets init <provider>` | `rt.ts:1193-1237` | `--output-file <file>` (`Output file path`); hidden deprecated `--output <file>` |
| `targets templates` | `rt.ts:1239-1251` | none (`Get provider-specific target templates`) |
| `targets backup` | `rt.ts:1253-1287` | `--output-dir <path>` (`Output directory`), `--file-format <format>` (`Backup file format: json or yaml`, default `"json"`), `--name <targetName>` (`Backup a single target by name`); hidden deprecated `--output <format>` and `--format <format>` |
| `targets restore` | `rt.ts:1289-1314` | `--input-dir <path>` (`Directory containing backup files`), `--file <path>` (`Single backup file to restore`), `--overwrite` (`Update existing targets with same name (default: skip)`), `--validate`. There is no `--dry-run` (`error: unknown option '--dry-run'`, exit 1) |
| `targets error-logs <targetId>` | `rt.ts:1316-1338` | `--limit <n>` (`Max results`), `--offset <n>` (`Starting offset`), `--search <text>` (`Filter by search text`), `--output <format>` (`pretty, table, csv, json, yaml`, default `"pretty"`). Example `airs-cli redteam targets error-logs <targetId>`. It gets no `--all`/`--max` (not named `list`) |
| `adapter list\|ls` | `rt.ts:1370-1395` | `--limit <n>` (`Max results`), `--offset <n>`, `--search <text>`, `--output <format>` (`pretty, table, csv, json, yaml`), `--all`, `--max <n>` |
| `adapter get <uuid>` | `rt.ts:1397-1410` | `--output <format>` (`pretty, json, yaml`) |
| `adapter create` | `rt.ts:1412-1458` | `--name <name>` (required), `--prompt <text>` (required, `Sample prompt used to exercise the adapter during validation (not stored)`), `--script-file <path>`, `--script-b64 <b64>`, `--description <text>`, `--channel <uuid>` (`Network broker channel UUID (required to activate)`), `--variables <json>` (`JSON array of { key, value, type: VAR\|SECRET }`), `--draft` (`Save as DRAFT without running the validation script`), `--output <format>` (`pretty, json, yaml`). Two examples |
| `adapter update <uuid>` | `rt.ts:1460-1514` | `--prompt <text>` (required, `Sample validation prompt — required on every update because upstream never stores it`), `--name`, `--script-file`, `--script-b64`, `--description`, `--channel`, `--variables <json>` (`REPLACES the whole variable set — omitted keys are deleted upstream. Omit this flag to preserve stored variables.`), `--draft`, `--output`. Description `Update a custom target adapter (read-modify-write; variables preserved unless --variables)` |
| `adapter delete\|rm <uuid>` | `rt.ts:1516-1532` | `--force` |
| `adapter validate` | `rt.ts:1534-1577` | `--channel <uuid>` (required, `must be ONLINE`), `--prompt <text>` (required), `--script-file`, `--script-b64`, `--variables <json>` (`the FULL set the script needs`), `--adapter <uuid>` (`Existing adapter: resolves redacted/null variable values from its stored secrets (and supplies its variable set when --variables is omitted)`), `--output` |
| `network-broker channels list\|ls` | `rt.ts:1585-1611` | `--limit`, `--offset`, `--search`, `--status <status...>` (variadic, `Filter by status (ONLINE, OFFLINE, DRAFT)`), `--output` (`pretty, table, csv, json, yaml`), `--all`, `--max` |
| `network-broker channels get <channelId>` | `rt.ts:1613-1627` | `--output` (`pretty, json, yaml`) |
| `network-broker channels create` | `rt.ts:1629-1647` | `--name <name>` (required), `--description <text>` |
| `network-broker channels update <channelId>` | `rt.ts:1649-1670` | `--name <name>`, `--description <text>` |
| `network-broker stats` | `rt.ts:1672-1686` | `--output` (`pretty, json, yaml`). Description `Show network broker channel statistics` |

`network-broker` has only `channels` and `stats`. A group without a subcommand prints its help on **stderr**, exit 1 (`ts-cli-shell.md` §5). Captured `redteam network-broker`:

```
Usage: airs-cli redteam network-broker [options] [command]

Manage red team network broker channels

Options:
  -h, --help       display help for command

Commands:
  channels         Manage network broker channels
  help [command]   display help for command
  stats [options]  Show network broker channel statistics
```

Captured `redteam targets --help` (stdout, exit 0):

```
Usage: airs-cli redteam targets [options] [command]

Manage red team targets

Options:
  -h, --help                       display help for command

Commands:
  backup [options]                 Backup red team targets to local JSON/YAML
                                   files
  create [options]                 Create a new red team target
  delete|rm [options] <uuid>       Delete a red team target
  error-logs [options] <targetId>  List target-profile error logs
  get [options] <uuid>             Get target details
  help [command]                   display help for command
  init [options] <provider>        Scaffold a target config JSON from a provider
                                   template
  list|ls [options]                List configured red team targets
  metadata                         Get target field metadata
  probe [options]                  Test target connection without saving
  profile <uuid>                   View target profile
  restore [options]                Restore red team targets from local JSON/YAML
                                   backup files
  templates                        Get provider-specific target templates
  update [options] <uuid>          Update a red team target
  update-profile [options] <uuid>  Update target profile
  validate-auth [options]          Validate target auth credentials
```

Captured `redteam targets list --help`:

```
Usage: airs-cli redteam targets list|ls [options]

List configured red team targets

Options:
  --all              Walk all pages
  -h, --help         display help for command
  --limit <n>        Max results (client-side)
  --max <n>          Maximum items with --all; 0 removes the cap (default:
                     10000)
  --offset <n>       Starting offset (client-side)
  --output <format>  Output format: pretty, table, csv, json, yaml (default:
                     "pretty")

Examples:
  $ airs-cli redteam targets list
  $ airs-cli redteam targets list --output json
  $ airs-cli redteam targets ls --limit 5

```

The full help of every command in this spec was captured; the option lines match the table above. The help texts that name `markdown`, `csv`, `yaml` and `--file-format yaml` describe dropped formats (MILESTONES) and change in the port.

## 2. Shared behaviour

### 2.1 Client, endpoints and credentials

- Every command builds `new SdkRedTeamService(redTeamClientOptions(await loadConfig()))` (`rt.ts:65-68`; backup/restore through `bk.ts:8-11`).
- `redTeamClientOptions` (`co.ts:61-69`) first asserts the management credentials (`Management credentials are not configured (missing <keys>). Run 'airs-cli tenant set <name> <key>' for <keys> (secrets prompt hidden, or use --stdin)`, exit 1, captured), then passes `clientId`, `clientSecret`, `tsgId`, `tokenEndpoint: mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT` and the three base URLs:
  - `dataEndpoint: redTeamDataEndpoint ?? https://api.apps.paloaltonetworks.com/ai-red-teaming/data-plane` (`SDK:91`)
  - `mgmtEndpoint: redTeamMgmtEndpoint ?? …/ai-red-teaming/mgmt-plane` (`SDK:92`)
  - `networkBrokerEndpoint: redTeamNetworkBrokerEndpoint ?? …/ai-red-teaming/data-plane/network-broker` (`SDK:93`)
- Because every value is explicit, the SDK constructor's fallbacks `PANW_RED_TEAM_DATA_ENDPOINT`, `PANW_RED_TEAM_MGMT_ENDPOINT`, `PANW_RED_TEAM_NETWORK_BROKER_ENDPOINT` (`SDK:17283-17285`) and the credential fallbacks `PANW_RED_TEAM_*` then `PANW_MGMT_*` (`SDK:11099-11140`, `primaryEnvPrefix: "PANW_RED_TEAM"`) are never reached. Unlike `topics create` (D93), no red team command here bypasses the tenant. The retired key `redTeamTokenEndpoint` is ignored.
- Plane routing (`SDK:17288-17320`): targets, templates, adapters (and eula, instances, custom attacks) use the **mgmt** endpoint; target-profile error logs use the **data** endpoint; channels and stats use the **broker** endpoint.
- Token: one `POST <mgmtTokenEndpoint>` with HTTP Basic `client_id:client_secret`, form `grant_type=client_credentials&scope=tsg_id%3A<tsg>` (captured), cached for the process.
- `numRetries` is not passed, so the SDK default 5 applies (`SDK:11112-11115`).
- The SDK sends `User-Agent`, `service-name: api`, `Authorization: Bearer <token>` and, with a body, `Content-Type: application/json`.

### 2.2 Output format resolution per command

The root `--output <format>` consumes every `--output X` on the line (`ts-cli-shell.md` §3). The leaf `--output` therefore keeps its default `pretty` unless the `preAction` hook (`program.ts:162-175`) resolves it: only for leaf names in `READ_COMMAND_NAMES` (`list`, `get`, `stats`, …; `program.ts:18-39`) that declare `--output`. That resolution loads the tenant config first (no tenant → `No tenant selected…`, exit 1, nothing on stdout) and validates the value against `pretty, table, markdown, csv, json, yaml` (else `\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n`, exit 2, captured). The tenant's `defaultOutput` applies to the same commands.

| Command | `--output` reachable? | What each value prints |
|---|---|---|
| `targets list`, `adapter list`, `channels list` | yes | §3.3, §15.1, §19.1 |
| `targets get` | yes | `pretty` detail; `json`/`yaml` the normalised object; **`table`, `csv`, `markdown`: nothing at all** (exit 0, captured) |
| `adapter get`, `channels get`, `network-broker stats` | yes | `pretty` detail; `json` object; **every other value (`table`, `csv`, `markdown`) prints YAML** (captured for `table`) |
| `targets error-logs` (name not in the set) | **no** | always pretty, even with `--output json` (captured) |
| `adapter create`, `adapter update`, `adapter validate` | **no** (not read names) | always pretty (captured for create and validate) |
| `targets create|update|delete|probe|profile|update-profile|validate-auth|metadata|init|templates|backup|restore`, `channels create|update` | no option | fixed layout; a root `--output json` is accepted and ignored (captured for create, profile) |

Defects to record: an empty list prints `  No <x> found` on stdout **in every format**, `json` included (`rrt.ts:344-347,823-826,1039-1042,987-990`; captured `targets list --output json` → `"  No targets found\n"`), so `| jq` breaks on an empty tenant.

### 2.3 Banner, streams and quiet

- Red team banner (`rrt.ts:7-9`): stdout `"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n"`, quiet-suppressed.
  - Read commands with a format print it only when the format is `pretty` (`rt.ts:1023`, `:1039`, `:1327`, `:1380`, `:1404`, `:1596`, `:1620`, `:1679`), after `preAction` and **before** the client or any request. Failing runs therefore leave the banner on stdout.
  - `adapter create|update|validate` print it when their (always-`pretty`) format is pretty, i.e. always.
  - Write commands print it first in the `try` (`create`, `update`, `probe`, `profile`, `update-profile`, `validate-auth`, `init`, `templates`, channel `create`/`update`), so input-file and usage errors raised inside the try come after it.
  - `targets delete` prints it **after** the confirmation (`rt.ts:1097-1100`); `adapter delete` prints it **before** (`rt.ts:1522-1525`).
  - `targets metadata` prints no banner (`rt.ts:1184`).
- Backup/restore banner (`rbk.ts:5-7`): stdout `"\n  Prisma AIRS — Backup & Restore\n\n"` (no subtitle), quiet-suppressed.
- Every outcome line is on **stdout**: `ui.success` (`  ✓ …`, green), `ui.keyValue`, `ui.bullet`, `ui.emptyList` and `ui.dim` hints. Only `fail`, `usageError`, `ui.error` (`adapter validate`'s failure line) and the deprecation notices are on stderr. `ui.success`, `keyValue`, `bullet` and `emptyList` are **not** quiet-suppressed; `header`, `section`, `dim` are. Under `--quiet` the target list keeps its name rows but loses the dim UUID rows (captured `"    Rest Target One  active  type: APPLICATION\n    Native/OpenAI ✓  inactive  type: MODEL\n    Adapter Target  active  type: AGENT\n\n"`), which leaves rows without their ids.
- `ui.dim` carries data in three places, so `--quiet` deletes data: `targets templates` prints each template through `ui.dim` (quiet output is seven blank lines, captured `"\n\n\n\n\n\n\n"`), `targets list` the UUIDs, `adapter list` the `<n> total` line and the UUIDs, `channels list` the UUIDs.
- `targets probe`, `profile`, `update-profile`, `metadata` print raw `JSON.stringify(x, null, 2)` on stdout after the banner and a dim or success label, so their stdout is never parseable JSON except for `metadata` (no banner) and `probe`/`profile` under `--quiet`.

### 2.4 Errors and exit codes

- `fail(err)` (`common.ts:12-25`): stderr `"\n  ✗ Error: <message>\n"`; when the error has `status`/`statusCode`, two more lines `"    HTTP <status>\n"` and `"    Re-run with --debug to capture redacted API diagnostics.\n"`; then `"\n"`; exit 1. A `CliUsageError` goes to `usageError`.
- `usageError(msg)` (`common.ts:27-30`): stderr `"\n  ✗ <msg>\n\n"`, exit 2.
- Commander parse errors: exit 1 (`error: required option '--config <path>' not specified`, `error: missing required argument 'uuid'`, `error: unknown option '--dry-run'`).
- SDK error messages are `<errorType>:<message>` (`SDK:197-205`):
  - client-side UUID checks (`assertUuid`, `SDK:11148-11155`): `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid target uuid: not-a-uuid` (also `Invalid target id: …`, `Invalid adapter uuid: …`, `Invalid channel id: …`), no request, exit 1 after the banner (captured).
  - request-schema failures: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/target did not match schema: <root>: unrecognized_keys` (captured; target create/update/probe and adapter create/update/validate request schemas are `.strict()`, `SDK:4521-4539,4568-4575,4604-4605,4670-4674`).
  - HTTP errors (`SDK:9713-9725`, `executeWithRetry` `SDK:9786-9850`): JSON `error_message`/`message`/`data.message`/`error.message`/`msg` is printed **verbatim** (`AISEC_CLIENT_SIDE_ERROR:Target <uuid> not found` + `HTTP 404`, captured); a problem-details body (`title`/`detail`/`errors`, also FastAPI `detail` arrays) becomes `API error 422; [withheld]` (captured); **a non-JSON body is printed in full**: a 500 with `text/plain` body `internal: echo Authorization=Bearer NEW-SECRET` printed `AISEC_SERVER_SIDE_ERROR:API error 500: internal: echo Authorization=Bearer NEW-SECRET` (captured). Status ≥ 500 → `AISEC_SERVER_SIDE_ERROR`, else `AISEC_CLIENT_SIDE_ERROR`.
  - timeouts (`PANW_AI_SEC_TIMEOUT_MS`, default 60000, `SDK:10095`): `AISEC_CLIENT_SIDE_ERROR:Request timed out`, no HTTP line (captured).
- Local file errors are raw Node messages: `ENOENT: no such file or directory, open 'nope.json'`, `Expected property name or '}' in JSON at position 1 (line 1 column 2)` (exit 1, after the banner and after the tenant read, captured). `JSON.parse` messages can quote file content (`Unexpected token 'g', "garbage\n" is not valid JSON`, captured for restore).

### 2.5 Retries and write replay (captured)

`request()` (`SDK:10094-10283`) runs every call through `executeWithRetry` with `maxRetries = 5`, **whatever the method**:

| Fault on the write | Attempts observed | Outcome printed |
|---|---|---|
| 503 with `Retry-After: 0` on `POST /v1/target` | 6 identical POSTs | `AISEC_SERVER_SIDE_ERROR:busy`, `HTTP 503`, exit 1 |
| 500 non-JSON on `POST /v1/target` | 6 POSTs | raw body echoed (§2.4) |
| hang with `PANW_AI_SEC_TIMEOUT_MS=300` on `POST /v1/target` | 6 POSTs | `Request timed out`, exit 1 |
| hang on `DELETE /v1/target/<id>` | 6 DELETEs (timeout) | `Request timed out` |
| 500 on `PUT /v1/adapters/<id>` | 6 PUTs (each re-runs the adapter validation upstream unless `--draft`) | exit 1 |
| 502 on restore's `POST /v1/target` | 6 POSTs, then the row is `failed` | exit 1 |
| 401 once on `POST /v1/target` | token, POST, token, POST; second answer wins | exit 0 |
| 403 (no `x-opa-decision`) | token, POST, token, POST | exit 1 (`HTTP 403`) |
| 403 with `x-opa-decision: false` | one POST | exit 1 |
| 429 | one POST (429 is not retried) | `AISEC_CLIENT_SIDE_ERROR:slow down`, `HTTP 429` |

Backoff is `Retry-After` (capped at 60 s) or random `0..2^attempt s`. A create that the server applied before a 5xx, a dropped connection or a timeout is therefore re-sent up to five times: **duplicate targets, adapters and channels** are possible, and a delete that succeeded before a timeout is reported as `HTTP 404 … not found` by its replay. Reads (list/get) retry the same way (6 `GET /v1/target` for backup's listing on a 500, captured).

### 2.6 Confirmations (`targets delete`, `adapter delete`)

`confirmOrAbort` (`confirm.ts:32-55`):
- `--force` skips.
- `process.stdout.isTTY !== true` → `usageError("refusing to delete target <uuid> without --force in non-interactive mode")` / `"…delete adapter <uuid>…"`: stderr `"\n  ✗ refusing to delete target 22222222-2222-4222-8222-222222222222 without --force in non-interactive mode\n\n"`, exit 2, no request (captured). For targets this comes before the tenant read (captured with no tenant selected); for adapters after the banner (stdout has the banner).
- TTY: `@inquirer/prompts` confirm on stdout, `? Delete red team target <uuid>? (y/N)` or `? Delete adapter <uuid>? (y/N)`. Decline → `  ℹ Aborted` (stdout, quiet-suppressed), exit 0, no request. Accept → the request (captured, one DELETE).
- Ctrl-C at the prompt → inquirer throws inside the action's try → `fail`: `  ✗ Error: User force closed the prompt with SIGINT`, exit **1** (captured).
- The prompt does not reject the default `y` variants in any special way: inquirer accepts answers starting with `y`.

### 2.7 Interruption

No signal handler. SIGINT/SIGTERM during a request kills the process by signal (shell exit 130/143, captured for `targets list` and `targets backup` with a hung request); stdout keeps the banner only; nothing is printed. An in-flight write is dropped with unknown outcome and no message. A backup interrupted between files leaves the files written so far; `writeFileSync` is not atomic, so an interrupted write can leave a truncated JSON file.

### 2.8 Colour (captured with `FORCE_COLOR=1`)

chalk follows stdout's TTY status for both streams (`ts-cli-shell.md` §11). Codes used here: banner title `\e[1m…\e[22m`, subtitle and dim rows `\e[2m…\e[22m`, section labels bold, `keyValue` keys dim and padded inside the dim span (`\e[2mUUID  \e[22m  value`), `active`/`ONLINE`/`ACTIVE`/`yes` green `\e[32m…\e[39m`, `inactive`/`OFFLINE`/`no`/error types/stderr and traceback text red `\e[31m`, `DRAFT` and non-`ACTIVE` adapter status yellow `\e[33m`, success lines fully green (`\e[32m✓ Target … deleted.\e[39m`), bullets colour only the glyph (`\e[32m✓\e[39m Rest Target One → rest-target-one.json`, skip `\e[33m○\e[39m`, error `\e[31m✗\e[39m`), `(redacted)` dim. `fail` writes `\e[31m\e[39m\n` (an empty red string, then newline) before `\e[31m  ✗ Error: …\e[39m`, then `\e[31m    HTTP 404\e[39m` and a dim `Re-run` line. The deprecation notice is `\e[33m  ⚠ --format is deprecated … — use --file-format\e[39m`.

### 2.9 Response normalisation artefacts

- The SDK validates responses with zod and returns `result.data`, so object keys come out in **schema order, then unknown keys** (`TargetResponseSchema`, `SDK:4610-4645`, starts `adapter_uuid, canonical_id, …, connection_params, auth_config, …, uuid, tsg_id, name`); the raw printers (`probe`, `update-profile`) show that order (captured).
- `ConnectionParamsSchema` is the union `WebSocket | Streaming | Rest` (`SDK:3881-3885`); the WebSocket variant has `ws_response_timeout: z.number().default(110)` and every field optional, so **every parsed `connection_params` gains `"ws_response_timeout": 110`** even when the server did not send it. It shows in `targets get` (pretty and JSON), create/update details, `probe`, `update-profile`, and it is written into backups and sent back by restore (captured). Request bodies do not gain it (the request union is extended with an optional field, `SDK:3886-3890`).
- `sanitizeTargetMetadata` (`svc.ts:93-102`) drops `multi_turn_error_message` when `multi_turn === false` in `get`/`create`/`update` details and `probe`, not in `update-profile`'s raw print (captured: `"multi_turn_error_message": "noise"` survives there).
- `normalizeTargetDetail` (`svc.ts:140-161`) keeps only: `uuid, name, status, targetType, active, connectionType, apiEndpointType, responseMode, authType, authConfig, networkBrokerChannelUuid, sessionSupported, extraInfo, description, connectionParams, background (target_background), additionalContext, metadata (target_metadata)`. It **drops** `tsg_id`, `validated`, `version`, `secret_version`, timestamps, user ids, `profiling_status`, `canonical_id`, `adapter_uuid`, `adapter_secret_version`, `adapter_variable_overrides` and every unknown key.

### 2.10 `--debug`

Allowed on every command here (no refusal like profile transfer). The logger writes `./debug-api-<ms>-<8 hex>.jsonl` (0600, `wx`) and prints `  Debug: API log → <abs>` on stderr, but it logs only AIRS/SCM hostnames, so loopback traffic is not logged (captured: the file exists, the backup ran). With a real host, response bodies are logged with key-name redaction only (`/token|secret|password|…|api[-_]?key|…/i`); target fields such as `request_headers.x-custom`, `curl`, `connection_params.target_connection_config.access_id` or an OAuth2 `oauth2_body_params.client_secret` value under a non-matching key would be persisted.

## 3. `targets list|ls`

### 3.1 Requests

`service.listTargets()` (`svc.ts:379-388`) → `client.targets.listAll({ limit: 100 })` (`SDK:15698-15727`): `GET <mgmt>/v1/target?skip=0&limit=100`, then `skip=100`, … while a page is non-empty and `next < total_items` (or, with no total, the page was full); at most 10,000 rows (`collectAll` default, `SDK:10802-10812`, silent truncation); a repeated cursor throws `Pagination returned a repeated cursor`. Captured with 123 targets: `skip=0&limit=100`, `skip=100&limit=100`, 123 rows. The walk ignores the CLI flags: `--limit`, `--offset`, `--all` and `--max` only slice the full list client-side (`sliceClientSide`, `rt.ts:105-116`).

### 3.2 Slicing (`sliceClientSide`)

- `--all`: `max = --max` (Number; default 10000); `0` → everything, else `slice(0, max)`; `--offset`/`--limit` ignored. `--max abc` → `NaN` → `slice(0, NaN)` = empty → `No targets found`, exit 0.
- Otherwise `offset = parseInt(--offset) || 0`-ish (`parseInt`, so `1.9` → 1, `-1` → last row via negative slice), `limit = parseInt(--limit)`; `slice(offset, offset+limit)`. `--limit abc` → `NaN` → empty list → `  No targets found`, exit 0 (captured; fails open).
- Captured `--limit 1 --offset 1` → only the second target; `--limit 2 --offset 121` with 123 → the last two.

### 3.3 Layouts

Rows are `{id: uuid, name, status: active ? 'active' : 'inactive', type: targetType ?? ''}` (`rrt.ts:349-354`); the API `status` field is never shown.

pretty (captured, 3 targets):

```
"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n\n  Targets:\n\n  11111111-1111-4111-8111-111111111111\n    Rest Target One  active  type: APPLICATION\n  22222222-2222-4222-8222-222222222222\n    Native/OpenAI ✓  inactive  type: MODEL\n  33333333-3333-4333-8333-333333333333\n    Adapter Target  active  type: AGENT\n\n"
```

Per row: `ui.dim(uuid)` (`  <uuid>`), then `    <name>  <active|inactive>` plus `  type: <targetType>` when set (`rrt.ts:369-376`), then a final blank line. Empty: `"\n  <banner>…\n\n  No targets found\n"`.

table (captured):

```
" ID                                   │ Name            │ Status   │ Type        \n──────────────────────────────────────┼─────────────────┼──────────┼─────────────\n 11111111-1111-4111-8111-111111111111 │ Rest Target One │ active   │ APPLICATION \n 22222222-2222-4222-8222-222222222222 │ Native/OpenAI ✓ │ inactive │ MODEL       \n 33333333-3333-4333-8333-333333333333 │ Adapter Target  │ active   │ AGENT       \n"
```

json (captured): `[{ "id", "name", "status", "type" }, …]` with 2-space indent and one trailing newline. csv: `ID,Name,Status,Type` header, LF rows. yaml and markdown follow `formatOutput` (`common.ts:96-143`); both are dropped in the port.

## 4. `targets get <uuid>`

Request: `GET <mgmt>/v1/target/<uuid>` (`SDK:15728-15740`), after a local UUID check (§2.4).

pretty (`rrt.ts:462-504`; captured for T1):

```
"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n\n  Target Detail:\n\n  UUID    11111111-1111-4111-8111-111111111111\n  Name    Rest Target One\n  Status  active\n  Type    APPLICATION\n\n  Connection:\n\n  api_endpoint              https://target.invalid/v1/chat\n  request_headers           {\n    \"Content-Type\": \"application/json\",\n    \"apikey\": \"FAKE-HEADER-KEY\"\n  }\n  request_json              {\n    \"messages\": [\n      {\n        \"role\": \"user\",\n        \"content\": \"{INPUT}\"\n      }\n    ]\n  }\n  response_json             {\n    …\n  }\n  response_key              choices.0.message.content\n  target_connection_config  null\n  curl                      curl -H 'apikey: FAKE-HEADER-KEY' https://target.invalid/v1/chat\n  multi_turn_config         null\n  ws_response_timeout       110\n\n  Background:\n\n  industry     Generic\n  use_case     Chatbot\n  competitors  [\n    \"A\",\n    \"B\"\n  ]\n\n  Metadata:\n\n  multi_turn  false\n  rate_limit  50\n\n"
```

- Header block: `UUID`, `Name`, `Status` (`active`/`inactive` from `active`), `Type` only when `targetType` is set; keys padded to the longest key.
- `Connection:` lists every `connection_params` key including `null` ones (`String(null)` = `null`); nested values are `JSON.stringify(v, null, 2)` with continuation lines indented by two spaces (`rrt.ts:443-449`), not aligned under the value column.
- `Background:` and `Metadata:` skip null/undefined keys. `additionalContext` (system prompt, banned keywords), `authType`, `authConfig`, `connectionType`, `description`, `extraInfo` and the broker channel are **not** in the pretty view.
- **Secrets printed in pretty:** `connection_params.request_headers` values (API keys), `connection_params.curl` (contains the headers), `connection_params.target_connection_config` (`api_key`, `access_token`, `secret`, `access_secret`, `session_token` of native providers; captured `"api_key": "FAKE-OPENAI-KEY"`). `auth_config` is not shown in pretty.

json (captured): the normalised object of §2.9 in `normalizeTargetDetail` order, `undefined` keys omitted, `null` kept:

```
{ "uuid", "name", "status": "ACTIVE", "targetType", "active", "connectionType", "apiEndpointType", "responseMode", "authType", "authConfig": {"auth_header": {"Authorization": "Bearer FAKE-TARGET-AUTH"}}, "sessionSupported", "extraInfo", "description", "connectionParams": {…, "ws_response_timeout": 110}, "background", "additionalContext", "metadata" }
```

**Secrets printed in json/yaml:** everything above plus `authConfig` (bearer tokens, basic-auth headers, OAuth2 `oauth2_body_params` client secrets) and `additionalContext.system_prompt`. `table`, `csv`, `markdown`: no output, exit 0 (captured). A 404 prints `AISEC_CLIENT_SIDE_ERROR:Target <uuid> not found`, `HTTP 404`, exit 1, banner on stdout (captured).

## 5. `targets create` and `targets update <uuid>`

Order (`rt.ts:1053-1067`, `:1074-1089`): banner → `loadConfig` and client (tenant and credential errors) → `JSON.parse(fs.readFileSync(--config, 'utf-8'))` (no size, type or UTF-8 checks; relative to cwd; symlinks followed) → for update the local UUID check → request → `  ✓ Target created: <uuid>` / `  ✓ Target updated: <uuid>` → `renderTargetDetail(target)` in **pretty only**.

Requests:
- create: `POST <mgmt>/v1/target`, query `validate=true` only with `--validate` (`opts.validate ? {validate:true} : undefined`; `false` is never sent), body = the config object validated with the strict `TargetCreateRequestSchema` and re-serialised in schema key order (`SDK:15644-15671`, captured: `{"name","target_type","connection_type","api_endpoint_type","response_mode","connection_params","auth_config","auth_type"}`).
- update: `PUT <mgmt>/v1/target/<uuid>[?validate=true]`, body = the config object as given (strict `TargetUpdateRequestSchema`, `name` required), **no read-modify-write**: the file is the whole PUT body (captured `{"name":"renamed","description":"d2"}`). Whether upstream treats it as a merge or a replacement is not visible to the CLI; TS sends what the file holds.
- Allowed keys (strict, `SDK:4582-4605`): `name` (required string), `description`, `target_type` (`APPLICATION|AGENT|MODEL`), `connection_type` (`DATABRICKS|BEDROCK|OPENAI|HUGGING_FACE|CUSTOM|REST|STREAMING|WEBSOCKET|WEBSOCKET_STREAMING|MS_COPILOT_STUDIO|CUSTOM_TARGET_ADAPTER`), `api_endpoint_type` (`PUBLIC|PRIVATE|NETWORK_BROKER`), `response_mode` (`REST|STREAMING|WEBSOCKET|WEBSOCKET_STREAMING`), `connection_params`, `auth_config` (headers / OAuth2 / basic union), `auth_type` (`HEADERS|BASIC_AUTH|OAUTH2|CUSTOM_TARGET_ADAPTER`), `canonical_id` (≤512), `session_supported`, `target_metadata`, `target_background`, `additional_context`, `extra_info`, `network_broker_channel_uuid` (uuid), `adapter_uuid` (uuid), `adapter_variable_overrides` (array of `{key ≤255, value?, type VAR|SECRET}`). Any other key → `…did not match schema: <root>: unrecognized_keys`, no request (captured).

Output (captured create):

```
"\n  Prisma AIRS — AI Red Team\n  Adversarial scan operations\n\n  ✓ Target created: e82519f5-d928-4130-b1b7-b9a5d517d44c\n\n  Target Detail:\n\n  UUID    e82519f5-…\n  Name    new-t\n  Status  active\n  Type    APPLICATION\n\n  Connection:\n\n  api_endpoint         https://x.invalid\n  response_key         a\n  ws_response_timeout  110\n\n"
```

`--validate` asks AIRS to connect to the target endpoint before saving (an external call by the service). Retries: §2.5 (duplicate creates possible). The pretty detail echoes the target's `request_headers`/`curl` secrets back.

## 6. `targets delete|rm <uuid>`

Order: confirmation (§2.6) → banner → client → UUID check → `DELETE <mgmt>/v1/target/<uuid>` (`SDK:15789-15800`, empty body or `{message,status}` accepted) → `  ✓ Target <uuid> deleted.` (stdout, not quiet-suppressed; captured `--quiet` 404 path prints only stderr). No existence check; a 404 is `AISEC_CLIENT_SIDE_ERROR:Target <uuid> not found` + `HTTP 404`, exit 1. A delete applied before a timeout or 5xx is replayed and then reported as 404 (§2.5).

## 7. `targets probe`

Banner → client → `JSON.parse(--config)` → `POST <mgmt>/v1/target/probe` with the strict `TargetProbeRequestSchema` (the create fields plus `uuid`, `probe_fields`; `SDK:4670-4674`) → stdout `  Probe result:` (dim, quiet-suppressed) → `JSON.stringify(raw, null, 2)` of the full parsed `TargetResponse` with `target_metadata` sanitised (`svc.ts:416-424`). Captured: the echo includes `"request_headers": {"apikey": "PROBE-SECRET"}` and the injected `ws_response_timeout`. The probe makes AIRS contact the endpoint in the config (external call). 5xx retries re-run the probe.

## 8. `targets profile <uuid>` and `targets update-profile <uuid>`

- `profile`: banner → `GET <mgmt>/v1/target/<uuid>/profile` (`SDK:15848-15858`) → `  Target Profile:` (dim) → raw JSON of `TargetProfileResponse` (`target_id`, `target_version`, `status`, `profiling_status`, `target_background`, `additional_context` (system prompt), `ai_generated_items`, `other_details`, …). `--output json` is ignored (captured; the same pretty bytes).
- `update-profile`: banner → `JSON.parse(--config)` → `PUT <mgmt>/v1/target/<uuid>/profile` with `TargetContextUpdateSchema` (**passthrough**, so unknown keys are sent: captured `"extra": 1`) → `  ✓ Profile updated:` → the **full raw `TargetResponse`** (`svc.ts:431-437`), unsanitised, including `auth_config` and `connection_params` secrets, `tsg_id`, `secret_version` and `multi_turn_error_message` (captured).

## 9. `targets validate-auth`

Banner → client → `JSON.parse(--config)` (the `auth_config` object) → `POST <mgmt>/v1/target/validate-auth` with `{auth_type, auth_config[, target_id]}` (`svc.ts:352-369`; `target_id` only when `--target-id` is non-empty; schema passthrough with `auth_type` enum: `NOPE` → `auth_type: invalid_enum_value`, no request, captured). Output (`rrt.ts:659-672`, captured):

```
"…banner…\n\n  Auth Validation:\n\n  Validated   yes\n  Token       eyJhbGciOi...FAKE\n  Expires In  3599s\n\n"
```

`Validated` is `yes` (green) or `no` (red); `Token` (the server's `token_preview`) and `Expires In` only when present. AIRS calls the target's auth/token endpoint (external call). The `--target-id` value is not checked for UUID shape locally by the CLI; the schema requires a UUID (`SDK:4675-4680`).

## 10. `targets metadata` and `targets templates`

- `metadata` (`rt.ts:1180-1191`): no banner; `GET <mgmt>/v1/template/target-metadata`; stdout `JSON.stringify(metadata, null, 2) + "\n"` (captured); identical under `--quiet`.
- `templates` (`rt.ts:1239-1251`, `rrt.ts:675-682`): banner; `GET <mgmt>/v1/template/target-templates` (response must have `OPENAI, HUGGING_FACE, DATABRICKS, BEDROCK, REST, STREAMING, WEBSOCKET` objects, `SDK:4784-4792`, passthrough); stdout `\n  Target Templates:\n\n` then per provider in response order `\n  <PROVIDER>\n\n` + `ui.dim(JSON with every newline replaced by "\n  ")` + `\n` (captured). Under `--quiet` only the blank lines remain.

## 11. `targets init <provider>`

Order (`rt.ts:1203-1237`):
1. Deprecated `--output <file>` → `--output-file` mapping with a stderr warning. The root parser consumes `--output`, so the alias is unreachable: `init streaming --output old.json` wrote `streaming-target.json`, no warning (captured).
2. Provider check, case-insensitive against `OPENAI, HUGGING_FACE, DATABRICKS, BEDROCK, REST, STREAMING, WEBSOCKET, CUSTOM_TARGET_ADAPTER`: `\n  ✗ Unknown provider "azure". Valid providers: OPENAI, HUGGING_FACE, DATABRICKS, BEDROCK, REST, STREAMING, WEBSOCKET, CUSTOM_TARGET_ADAPTER\n\n`, exit 2, before the tenant (captured).
3. `filename = --output-file ?? "<provider lowercased as typed>-target.json"`; `outputPath = path.resolve(filename)`; `existsSync` → `\n  ✗ File already exists: <abs> (use --output-file to specify a different path)\n\n`, exit 2, before the tenant (captured). A dangling symlink is not "existing" for `existsSync`, and the write follows it.
4. Banner → client (tenant errors after the banner) → `GET <mgmt>/v1/template/target-templates` (made even for `CUSTOM_TARGET_ADAPTER`, which uses no template) → `buildTargetScaffold` → `fs.writeFileSync(outputPath, JSON + "\n")` (flag `w`, mode 0666 & ~umask = 0644 captured; a missing parent directory fails with the raw `ENOENT: no such file or directory, open '<abs>'`, exit 1, after the request, captured). The existence check and the write are not atomic (TOCTOU: a file created in between is overwritten).
5. stdout: `  ✓ Target config scaffolded`, keyValue `File  <abs>` / `Provider  <UPPER>`, dim `  Next steps: edit the file to fill in name and credentials, then run:` and dim `    airs-cli redteam targets create --config <filename as given> --validate` (captured).

Scaffolds (`rt.ts:147-218`, `redteam-init.spec.ts`, captured):
- `CUSTOM_TARGET_ADAPTER`: `{name:"", target_type:"AGENT", connection_type:"CUSTOM_TARGET_ADAPTER", api_endpoint_type:"NETWORK_BROKER", network_broker_channel_uuid:"<channel-uuid>", adapter_uuid:"<adapter-uuid>", adapter_variable_overrides:[], target_background:{use_case:""}, additional_context:{}}`.
- `REST`, `STREAMING`, `WEBSOCKET`, `HUGGING_FACE`: `{name:"", target_type:"APPLICATION", connection_type:"CUSTOM", api_endpoint_type:"PUBLIC", response_mode: STREAMING|WEBSOCKET|REST, auth_type:"HEADERS", auth_config:{auth_header:{Authorization:"Bearer <token>"}}, connection_params:{api_endpoint: template.url ?? "", request_headers:{"Content-Type":"application/json"}, request_json: template.request_json ?? {messages:[{role:"user",content:"{INPUT}"}]}, response_json: template.response_json ?? {choices:[{message:{content:"{RESPONSE}"}}]}, response_key:"choices.0.message.content"}, target_background:{}, additional_context:{}}`. (`HUGGING_FACE` is `response_mode: "REST"`.)
- `OPENAI`, `BEDROCK`, `DATABRICKS`: `{name:"", target_type:"APPLICATION", connection_type:<KEY>, api_endpoint_type:"PUBLIC", response_mode:"REST", auth_type:"HEADERS", auth_config:{…Bearer <token>}, connection_params:{target_connection_config: templates[KEY] ?? {}}, target_background:{}, additional_context:{}}`.
- The `STREAMING` scaffold lacks `response_stop_key`/`response_stop_value`, which the streaming connection schema requires; it passes only as the REST union variant.

## 12. `targets error-logs <targetId>`

Order: banner (always, §2.2) → client → `--limit` through `parsePositiveInt` (`0`/`abc` → `--limit: expected a positive integer, got "0"`, exit **1** via `fail`, after the banner and tenant, captured) → `--offset` `parseInt` (no check) → UUID check (`Invalid target id: nope`) → `GET <data>/v1/error-log/target-profile/<id>?skip=<offset>&limit=<limit>&search=<text>` (only the given ones, in that order; captured `?skip=1&limit=1&search=foo`). One page; `pagination.total_items` is read but never shown.

pretty (`rrt.ts:976-1024`, captured):

```
"…banner…\n\n  Target-Profile Error Logs:\n\n    2026-01-05T00:00:00Z  PROFILING  (TARGET)\n      upstream said 500\n      job: job-1\n\n    2026-01-06T00:00:00Z  error\n\n"
```

Per log: `    <dim createdAt>  <red errorType | dim "error">[  (<errorSource>)]`, then `      <errorMessage>` and `      <dim "job: <jobId>">` when present, then a blank line. Empty: `  No error logs found`. The table/json layouts in `rrt.ts:991-1012` (`Created, Type, Source, Job, Message`) are unreachable. `target_object` (which can hold the target's `auth_config`) and `extra_info` are never printed. Server `error_message` is printed verbatim.

## 13. `targets backup`

### 13.1 Order and requests

1. `resolveDeprecatedAliases` (`--format` → `--file-format`, warning `  ⚠ --format is deprecated and will be removed in v4 — use --file-format` yellow on stderr, captured; `--output` is eaten by the root and silently ignored: `--output yaml` wrote JSON, captured).
2. Banner `Prisma AIRS — Backup & Restore`.
3. `outputDir = path.resolve(--output-dir)` or `path.resolve('./airs-backup', 'targets')` (`io.ts:21-24`).
4. Client → `listTargets()` (the §3.1 walk; a list failure is `fail`, exit 1, no files, captured with 6 GETs on a 500).
5. `--name <n>`: the **first** target whose `name === n` (exact, case-sensitive); none → `  ✗ Error: Target not found: <n>`, exit 1, no directory created (captured).
6. For each selected target, in list order: `GET /v1/target/<uuid>` → envelope → write. A per-target failure (GET error, write error) becomes a `failed` row and the loop continues (captured: a 404 on one of four).
7. Summary; exit 1 when any row failed (`process.exit(1)`), else 0.

`--file-format` is not validated: any value other than `yaml` writes `.json` (captured `--file-format xml` → `.json` files, exit 0).

### 13.2 File format and content

Envelope (`bk.ts:71-76`), `JSON.stringify(envelope, null, 2) + "\n"` or `yaml.dump(envelope, {lineWidth:-1, noRefs:true})`:

```json
{
  "version": "1",
  "resourceType": "redteam-target",
  "exportedAt": "2026-10-18T02:11:18.772Z",
  "data": { … }
}
```

`data` is `toBackupData(normalizeTargetDetail(GET))` (`bk.ts:27-46`), in this key order, each only when truthy (`session_supported` when not null), then `stripNulls` recursively removes every `null`-valued key (arrays keep `null` elements' positions mapped):
`name, target_type, connection_type, api_endpoint_type, response_mode, auth_type, auth_config, network_broker_channel_uuid, session_supported, extra_info, connection_params, target_background, additional_context, target_metadata`.

Captured `rest-target-one.json` (abridged): `auth_config.auth_header.Authorization: "Bearer FAKE-TARGET-AUTH"`, `connection_params.request_headers.apikey: "FAKE-HEADER-KEY"`, `connection_params.curl` with the key, `"ws_response_timeout": 110` (fabricated, §2.9), `additional_context.system_prompt`, `extra_info` without its `null` key, `target_metadata` without `multi_turn_error_message`.

What a backup **loses** (captured for the adapter target, code for the rest): `description`, `canonical_id`, `adapter_uuid`, `adapter_variable_overrides`, every unknown server field, and any `null` that meant "clear". A `CUSTOM_TARGET_ADAPTER` target's backup holds only `name, target_type, connection_type, api_endpoint_type, response_mode, network_broker_channel_uuid` and cannot recreate the target.

What a backup **contains in clear text**: every credential the API returns for the target (`auth_config` headers and OAuth2 settings, `request_headers`, `curl`, native-provider keys in `target_connection_config`). Whether AIRS returns secrets in clear or masked depends on the server; the TS code writes whatever comes back.

### 13.3 File names, modes, overwrite

- Name: `sanitizeFilename(target.name)` (`io.ts:10-18`): lowercase, every char outside `[a-z0-9-]` → `-`, runs of `-` collapsed, leading/trailing `-` trimmed, empty → `unnamed`; extension `.json` or `.yaml`. `Native/OpenAI ✓` → `native-openai.json`.
- `fs.mkdirSync(dir, {recursive:true})` (mode 0777 & ~umask, captured `drwxr-xr-x`), `fs.writeFileSync(path, content, 'utf-8')` (flag `w`, captured `-rw-r--r--`). Secrets are therefore world-readable under a default umask.
- **Existing files are overwritten silently** (captured: a pre-existing `rest-target-one.json` replaced). A symlink at the path is followed and its target overwritten.
- **Name collisions overwrite each other within one run**: `Rest Target One` and `rest target one!` both map to `rest-target-one.json`; the summary reports 4 targets backed up, only 3 files exist and the first target's backup is lost (captured).

### 13.4 Summary layout (`rbk.ts:10-29`, captured)

```
"\n  Prisma AIRS — Backup & Restore\n\n\n  Backed up 3 target(s) to <abs dir>:\n\n  ✓ Rest Target One → rest-target-one.json\n  ✓ Native/OpenAI ✓ → native-openai.json\n  ✓ Adapter Target → adapter-target.json\n\n"
```

With failures: `\n  Failed (1):\n\n  ✗ Native/OpenAI ✓: AISEC_CLIENT_SIDE_ERROR:gone\n` before the final blank line; exit 1 (captured). The section lines are quiet-suppressed, the bullets are not (captured `--quiet`). Zero targets: only the final `\n` after the banner, exit 0, no directory created (by code: `writeBackupFile` creates the directory).

## 14. `targets restore`

### 14.1 Order

1. `!--file && !--input-dir` → `\n  ✗ Specify --file <path> or --input-dir <path>\n\n`, exit 2, before the tenant (captured).
2. Banner → client (tenant/credential errors here; so a missing tenant is reported before a missing file, captured).
3. Read: `--file` wins when both are given (captured). `--file`: `readBackupFile` (`io.ts:44-55`): extension must be `.json`, `.yaml` or `.yml` (`Unsupported file format: .txt (expected .json, .yaml, or .yml)`), whole-file `JSON.parse` or `yaml.load` (raw parse messages, which can quote file content), the object must have `version` and `data` (`Invalid backup file: <path> (missing version or data)`), then `version === '1' && resourceType === 'redteam-target'` (`Invalid backup: version=2, resourceType=redteam-target`, captured). All exit 1. `--input-dir`: `readdirSync` (`ENOENT: no such file or directory, scandir '<dir as typed>'`, exit 1, captured), files matching `/\.(json|ya?ml)$/i` in directory order (sorted on macOS APFS), each parsed and kept if `resourceType === 'redteam-target'`; **any unreadable, malformed or foreign file is skipped silently**, and the `version` is not checked in directory mode. None kept → `No valid backup files found`, exit 1 (captured). No size limit; symlinks followed.
4. `listTargets()` (the full walk) → `Map(name → uuid)`; on duplicate names in the tenant the **last** listed wins.
5. For each envelope in order (`rs.ts:74-114`), `name = data.name`:
   - existing and no `--overwrite` → `skipped` (no request).
   - existing and `--overwrite` → `prepareTargetPayload(data)` → `GET /v1/target/<uuid>` → fill missing `target_type` from it, `connection_type ?? 'CUSTOM'`, `api_endpoint_type ?? 'PUBLIC'`, `response_mode ?? 'REST'` (from the current target first) → `PUT /v1/target/<uuid>[?validate=true]` → `updated`.
   - otherwise → `prepareTargetPayload` → defaults `connection_type: 'CUSTOM'`, `api_endpoint_type: 'PUBLIC'`, `response_mode: 'REST'` when falsy → `POST /v1/target[?validate=true]` → `created`.
   - any error → `failed` with the error message; the loop continues.
6. Summary; exit 1 when any row failed.

`prepareTargetPayload` (`rs.ts:22-41`) deletes `uuid, tsg_id, status, active, validated, version, secret_version, created_at, updated_at, created_by_user_id, updated_by_user_id` and renames legacy `background` → `target_background`, `metadata` → `target_metadata` unless the new key exists. Any other unknown key makes the strict SDK schema fail the row.

### 14.2 Matching and conflict rules (captured)

- Matching is by exact `name` only, against the listing taken **once before the loop**. Two backup files with the same new name both create: `Fresh Name — created` twice, two POSTs, two targets (captured). A file restored twice in one directory, or a backup set holding a name collision, duplicates targets.
- `--overwrite` replaces the existing target with the backup body (full PUT; captured body includes the backed-up `auth_config`, `request_headers` and the fabricated `ws_response_timeout`); there is no diff, preview or confirmation.
- A create that fails with 5xx/timeout is re-sent up to 5 times (6 POSTs captured) and then reported `failed`, although any of the attempts may have created the target; the next restore run then creates it again or skips it, depending on what the listing shows.
- There is no `--dry-run`, no confirmation for `--overwrite`, and no check that the backup came from the same tenant.

### 14.3 Summary layout (`rbk.ts:32-49`, captured)

```
"\n  Prisma AIRS — Backup & Restore\n\n\n  Restore results:\n\n  ○ Adapter Target — skipped\n  ✓ Fresh Name — created\n  ○ Native/OpenAI ✓ — skipped\n  ○ Rest Target One — skipped\n\n  Total: 1 created, 3 skipped\n\n"
```

Bullets: `✓` (green) for `created`/`updated`, `○` (yellow) for `skipped`, `✗` (red) for `failed` with `: <error>` suffix (`  ✗ Fresh Name — failed: AISEC_SERVER_SIDE_ERROR:planned 502`). `Total:` lists the non-zero counts in the order created, updated, skipped, failed, joined by `, `; it is a raw `console.log` (not quiet-suppressed). A backup whose `data.name` is missing shows as `undefined — failed: …`.

## 15. `adapter list|ls` and `adapter get <uuid>`

### 15.1 `adapter list`

- `--limit` through `parsePositiveInt` (`0` → `--limit: expected a positive integer, got "0"`, exit 1 after the banner, captured), `--offset` `parseInt`, `--search`.
- Without `--all`: one `GET <mgmt>/v1/adapters` with `skip`, `limit`, `search` only when given (captured: no query at all by default; `?skip=2&limit=5&search=x`).
- With `--all`: `client.adapters.listAll({limit?, search?, max})` (`SDK:collectSkipPages`, limit default 50, `?skip=0&limit=50`, captured; `--offset` is ignored; `--max 0` = unbounded; `--max abc` → `RangeError: max must be a non-negative integer`, exit 1); `totalItems` is not shown.
- pretty (captured): `\n  Custom Target Adapters:\n\n` then per adapter `  <dim uuid>\n    <name>  <green ACTIVE | yellow other>[  targets: <n>]\n\n`, then dim `  <total> total` when the page had `pagination.total_items` (not with `--all`).
- table/json/csv rows `{uuid, name, status, targets: targetCount ?? '', updated: updatedAt ?? ''}` with labels `UUID, Name, Status, Targets, Updated` (captured table and json).

### 15.2 `adapter get`

`GET <mgmt>/v1/adapters/<uuid>`. pretty (`rrt.ts:1081-1132`, captured):

```
"…banner…\n\n  Adapter Detail:\n\n  UUID            aaaaaaaa-…\n  Name            adapter-one\n  Status          ACTIVE\n  Script          16 base64 chars\n  Description     an adapter\n  Broker Channel  cccccccc-…\n  Targets         1\n  Created         2026-01-01T00:00:00Z\n  Updated         2026-01-02T00:00:00Z\n\n  Variables:\n\n  endpoint (VAR)      http://agent.svc:8080\n  api_token (SECRET)  (redacted)\n\n"
```

A variable with `is_redacted: true` prints dim `(redacted)`; otherwise its value (also a `SECRET` whose server value is not flagged redacted). json is the normalised object (`uuid, tsgId, name, scriptB64, status, description, networkBrokerChannelUuid, variables[{key,value,type,isRedacted}], targetCount, createdAt, updatedAt, createdByUserId, updatedByUserId`), including the **full script** and the server's mask `"**********"` for secrets (captured). Other formats print YAML.

## 16. `adapter create` and `adapter update <uuid>`

### 16.1 create (`rt.ts:1434-1458`, `svc.ts:815-836`)

Order: banner → `resolveScriptB64` (`--script-file and --script-b64 are mutually exclusive`, `one of --script-file or --script-b64 is required`; the file is read as UTF-8 and re-encoded, so binary content is mangled) → `parseAdapterVariables` (`--variables: invalid JSON (<parse message>)`, `--variables: expected a JSON array of { "key": string, "value"?: string|null, "type": "VAR"|"SECRET" }`) → client → when `--channel` and not `--draft`: `GET <broker>/v1/channels/<uuid>`; a status other than `ONLINE` → `network broker channel <uuid> is <STATUS> — adapter validation requires an ONLINE channel (network broker v1.4.0+). Check 'airs-cli redteam network-broker channels list'.` (exit 1, captured); a failing lookup (including a non-UUID channel) is ignored → `POST <mgmt>/v1/adapters?validate=<true|false>` → `  ✓ Adapter created: <uuid>` → pretty detail. All local checks exit 1 after the banner (they are plain `Error`s inside the try), not 2.

- `validate`: `--draft` → `false`; otherwise the SDK default `true` (`SDK:17072-17086`), so a create without `--channel` and without `--draft` asks upstream to validate without a channel.
- Body (strict schema, schema order): `name` (≤255), `description` (when given), `script_b64`, `network_broker_channel_uuid` (uuid), `variables` (`{key,value,type}`), `prompt` (captured `{"name","script_b64","network_broker_channel_uuid","variables","prompt"}`).
- Secret exposure: `--variables` carries `SECRET` values **on the command line** (visible in the process list and shell history); the server masks them in the response.

### 16.2 update (`rt.ts:1486-1514`, `svc.ts:838-867`)

Order: banner → script (only when a script flag is given) → variables → client → channel check (when `--channel` and not `--draft`) → `GET /v1/adapters/<uuid>` → body → `PUT /v1/adapters/<uuid>?validate=<true|false>` → `  ✓ Adapter updated: <uuid>` → detail.

Body (read-modify-write over a full-replacement PUT): `name: --name ?? current`, `script_b64: --script ?? current`, `prompt`, `variables: --variables (replacing the whole set) ?? preserveVariablesForUpdate(current)` (redacted values → `null` meaning "keep stored"), `description: --description ?? current` (omitted if null), `network_broker_channel_uuid: --channel ?? current` (omitted if null). Captured: `{"name":"adapter-one","description":"new","script_b64":"…","network_broker_channel_uuid":"…","variables":[{"key":"endpoint","value":"http://agent.svc:8080","type":"VAR"},{"key":"api_token","value":null,"type":"SECRET"}],"prompt":"hi"}`. There is no way to clear the description or the channel. The read and the write are not conditional (a concurrent change between them is overwritten).

## 17. `adapter delete|rm <uuid>`

Banner → confirmation (§2.6; non-TTY refusal exit 2 with the banner on stdout, captured) → client → `DELETE <mgmt>/v1/adapters/<uuid>` (204 accepted) → `  ✓ Adapter <uuid> deleted.` (captured). Same replay caveat as §6.

## 18. `adapter validate`

Order: banner → script → variables → client → channel check (always; non-ONLINE → the §16.1 error) → when `--adapter` and no `--variables`: `GET /v1/adapters/<adapter>` and its variables via `preserveVariablesForUpdate` → `POST <mgmt>/v1/adapters/validate` with `{script_b64, network_broker_channel_uuid, prompt[, variables][, adapter_uuid]}` (strict; captured both shapes) → render → exit 1 when `validated` is false (`process.exitCode = 1`).

pretty success (captured): `"…banner…\n  ✓ Adapter script validated\n\n  stdout:\n\nadapter said hi\n\n"`. Failure (captured): stderr `  ✗ Adapter script validation FAILED`; stdout sections `stdout:`, `stderr:` (text red), `traceback:` (red), each `\n  <bold label>\n\n<raw text>\n`, then a blank line. The script's own stdout/stderr/traceback is printed raw: it can contain anything the script printed, including variable values. Not persistent upstream, but it executes the script in the customer's broker (external effect); the POST is retried on 5xx (§2.5).

## 19. `network-broker`

### 19.1 `channels list|ls`

`GET <broker>/v1/channels` with `skip`, `limit`, `search`, then one `status` per `--status` value (captured `?skip=1&limit=3&search=s&status=ONLINE&status=OFFLINE`; no default query). `--limit` via `parsePositiveInt`. `--all`: `listAllChannels` (`svc.ts:686-702`) pages from offset 0 (ignoring `--offset`) with `limit ?? 100`, stops on a short page or `total_items`, capped by `--max` (`0` = unbounded; captured `--max 1` → one row). pretty (captured):

```
"…banner…\n\n  Network Broker Channels:\n\n  cccccccc-…\n    chan-online  ONLINE  clients: 2\n\n  dddddddd-…\n    chan-offline  OFFLINE  clients: 0\n\n"
```

Status colours: ONLINE green, DRAFT yellow, OFFLINE red, other white, missing → dim `unknown`; name `(unnamed)` when missing; `  clients: <n>` when the count is not null. Rows for table/json/csv: `{id, name, status, clients, lastOnline}` labels `ID, Name, Status, Clients, Last Online`, nulls → `''` (captured).

### 19.2 `channels get`

`GET <broker>/v1/channels/<uuid>` (UUID checked). pretty `Channel Detail:` with `UUID` always, then `Name`, `Description`, `Status` (coloured), `Connected Clients`, `Outdated Clients`, `Last Online`, `Added By`, `Created`, `Updated` when not null, and a `Features:` keyValue block when non-empty (captured). json: normalised camelCase object (captured); other formats YAML.

### 19.3 `channels create` and `channels update`

- create: banner → `POST <broker>/v1/channels` with `{name[, description]}` (schema: `name` 1–64 chars, passthrough; 65 chars → `name: too_big`, no request, exit 1, captured) → `  ✓ Channel created: <uuid>` → pretty detail (captured). Retried on 5xx (duplicate channels possible).
- update: neither `--name` nor `--description` → `\n  ✗ Specify --name and/or --description to update\n\n`, exit 2, before the banner and tenant (captured) → banner → `PATCH <broker>/v1/channels/<uuid>` with only the given fields → `  ✓ Channel updated: <uuid>` → detail.
- There is no channel delete command.

### 19.4 `stats`

`GET <broker>/v1/channels/stats`. pretty `Network Broker Stats:` with `Online Channels, Total Channels, Server Domain, Docker Registry, Docker Image, Helm Chart, Client Version` when not null (captured). json camelCase `{serverDomain, dockerRegistry, helmChart, dockerImage, onlineChannels, totalChannels, clientVersion}`; other formats YAML. No secrets.

## 20. Secret exposure matrix (TS)

| Command | Credential-bearing fields printed or written |
|---|---|
| `targets get` pretty | `request_headers` values, `curl`, `target_connection_config` keys (native provider API keys, tokens, secrets) |
| `targets get` json/yaml | all of the above plus `authConfig` (bearer headers, basic auth, OAuth2 body params), `additionalContext.system_prompt` |
| `targets create`/`update` | pretty detail of the response (as `get` pretty) |
| `targets probe` | full response echo, including the probed config's headers |
| `targets update-profile` | full raw response: `auth_config`, `connection_params`, `tsg_id`, `secret_version` |
| `targets profile` | system prompt and AI-discovered items (sensitive, not credentials) |
| `targets validate-auth` | `token_preview` (a server-shortened token) |
| `targets error-logs` | server `error_message` verbatim; `target_object` not printed |
| `targets backup` | every returned credential, in clear text, files 0644, directory 0755, overwrite allowed |
| `targets restore` | sends the backup's credentials; parse errors can quote file content |
| `adapter get` json | full `scriptB64` (scripts may embed credentials), VAR values, server masks for SECRETs |
| `adapter create`/`update`/`validate` | `--variables` SECRET values on argv; validate prints the script's raw output |
| errors (all) | non-JSON HTTP error bodies printed in full; JSON `message` printed verbatim |
| `--debug` | key-name redaction only; loopback not logged |

## 21. TS specs to port

| TS spec | Behaviour to pin in Rust (adjusted by the §12 rows below) |
|---|---|
| `tests/unit/cli/redteam-init.spec.ts` | the scaffold shapes per provider family; case-insensitive provider; the exact unknown-provider message |
| `tests/unit/cli/redteam-adapter-helpers.spec.ts` | `--script-b64` passthrough; `--script-file` encodes the file; both/neither errors; `--variables` accepts `null` values; rejects invalid JSON, bad `type`, non-arrays |
| `tests/unit/cli/redteam-output-flag.spec.ts` (target detail part) | pretty never prints `[object Object]`; nested values expand as indented JSON; json carries the full target (secret parts change under the redaction row) |
| `tests/unit/airs/redteam.spec.ts` (`listTargets`, `getTarget`, `createTarget`, `updateTarget`, `deleteTarget`, `probeTarget`, `multi_turn_error_message` sanitisation, `getTargetProfile`, `updateTargetProfile`, `validateTargetAuth` incl. optional `targetId`, `getTargetMetadata`, `getTargetTemplates`, `listChannels` filters and total, `getChannel`, `createChannel`, `updateChannel`, `getChannelStats`, `getTargetProfileErrorLogs` filters and total) | request shapes and normalisation, as executable loopback tests |
| `tests/unit/airs/redteam-adapters.spec.ts` | list maps offset→skip; detail keeps redaction flags; create maps to snake_case and passes validate; update is read-modify-write and never wipes variables unless `--variables`; delete; validate auto-fills the variable set from `--adapter` |
| `tests/unit/cli/backup.spec.ts` | backup of all targets, of one by `--name`, `Target not found: <n>`; server fields stripped; `background` → `target_background` (the file format itself is Rust-defined) |
| `tests/unit/cli/restore.spec.ts` | create, skip without `--overwrite`, update with `--overwrite`, directory restore, errors collected without aborting, `--validate` passed, server fields stripped and legacy names normalised |
| `tests/unit/backup/io.spec.ts` | filename sanitisation rules; default directory; malformed files in a directory (Rust: reported, not silently skipped) |
| `tests/unit/cli/backup-renderer.spec.ts` | summary counts and failed rows |

## 22. Rust SDK (`scm-sdk` 0.1.0) coverage

Every operation in this spec has a typed method: `RedTeamTargetsClient::{create, list, list_pages, list_all, get, update, delete, probe, get_profile, update_profile, validate_auth, get_target_metadata, get_target_templates}` (`src/airs/red_team/targets.rs:133-363`, `TargetOperationOptions.validate` omitted by default, `:26-31`), `RedTeamAdaptersClient::{list, list_all, get, create, update, delete, validate}` (`adapters.rs:85-241`, `validate` defaults to `true` as in TS, `:91`, `:141`), `RedTeamNetworkBrokerClient::{list_channels (repeated status), create_channel, get_channel_stats, get_channel, update_channel}` (`network_broker.rs:37-127`), and the facade's `get_target_profile_error_logs` (`facade.rs:239`). The facade takes explicit management and broker endpoints (`facade.rs:44-52`). `TargetResponse` keeps unknown keys (`#[serde(flatten)] extensions`, `models/generated.rs:176325`). The CLI must enable the `red-team` feature (`Cargo.toml` currently enables `scan` and `management`). No gap was found for these commands; whether the SDK's write calls report post-dispatch failures as an unknown outcome for these routes (as for M4/M5) belongs to the SDK research step.

## 23. Live-tier notes

- Safe reads for `AIRS_RS_LIVE=1`: `targets list`, `targets get` (compare with secrets redacted on both sides), `targets metadata`, `targets templates`, `targets error-logs` of an existing target, `adapter list`, `adapter get`, `network-broker channels list|get`, `network-broker stats`, and `targets backup` into the run's temp directory (0600 files; the TS side's 0644 files must also stay inside the temp dir and be removed).
- Not live: `targets create|update|probe|validate-auth|update-profile` and `restore` (AIRS contacts the target endpoint, or a target is changed), `adapter create|update|validate` (run a script through a customer broker), `adapter delete` and `targets delete` of anything the run did not create, `channels create|update` (no delete exists: tenant infrastructure). A target with `connection_type` pointing at a non-routable endpoint and no `--validate` might be creatable and deletable; whether the API contacts it on create without `--validate` is unknown, so it stays excluded unless the user decides otherwise (open question 9).

## Acceptance criteria

Each is a loopback executable test of airs-cli-rs; parity tests compare both CLIs where the behaviour is shared.

1. `targets list` walks `GET /v1/target?skip=0&limit=100` until the total, prints the §3.3 pretty, table and json layouts byte-for-byte (json keys `id, name, status, type`), and applies `--limit/--offset/--all/--max` client-side.
2. An empty list prints `[]` for json and nothing for table (§12 row), `  No targets found` for pretty.
3. `targets get` prints the §4 pretty layout (header block, `Connection:`, `Background:`, `Metadata:`), with the redaction row applied to credential fields; json is the normalised object with the same redaction; `table` prints a `Key │ Value` table instead of nothing.
4. A non-UUID id fails before any request with exit 2 (§12 row) and names the argument.
5. `targets create|update` read `--config` before the tenant with the §13.2 input-file rules, validate the body against the strict schema before sending, send exactly one write (plus one replay after a 401, none after a 403), and report an unknown outcome on 5xx/timeout/transport failure without re-sending.
6. `targets delete` and `adapter delete` follow D81/D105: `--force`, terminal gate on stdin and stderr, `y`/`yes` only, EOF declines, Ctrl-C exits 130 with no request; the non-interactive refusal is exit 2 before the tenant with nothing on stdout.
7. `targets init` refuses an unknown provider and an existing path (including a dangling symlink) before the tenant, writes the §11 scaffold exclusively (`O_EXCL`), never over an existing file, and prints the §11 outcome lines.
8. `targets backup` writes the Rust format (0600 file in a 0700 directory created by the run), refuses an existing file and an existing name collision before the first request where possible, keeps `description`, `adapter_uuid`, `adapter_variable_overrides` and `canonical_id`, never writes the fabricated `ws_response_timeout`, and exits 1 with a partial-failure summary when a target fails.
9. `targets restore` refuses a TypeScript backup (`version: "1"`, `resourceType: "redteam-target"`) with a fixed message, refuses duplicate names within the backup and ambiguous (duplicate) names in the tenant before any write, offers `--dry-run`, never re-sends a create after an unknown outcome, and stops creating after an unknown outcome (§12 row).
10. `targets error-logs`, `adapter create|update|validate` honour `--output` (json reachable); `--limit 0` is a usage error (exit 2) before the tenant.
11. `adapter update` sends the read-modify-write body of §16.2 with redacted variables as `null`.
12. `adapter validate` exits 1 when `validated` is false, prints stdout/stderr/traceback through `terminal_safe` and the secret set, and checks the channel is ONLINE first.
13. `channels list` sends repeated `status` params in order; `channels update` without fields is exit 2 before the tenant.
14. No output path prints a SecretSet value or a non-JSON error body; server text goes through `terminal_safe`.
15. A SIGINT during any write exits 130 with an `Interrupted; …` context naming whether the change may have been applied.

## Open questions / likely §12 divergences

Numbers are assigned by the orchestrator from D133. Each is a safety or correctness fix; the ones marked **(choice)** need the user's confirmation.

1. **Write retries and unknown outcomes (safety).** TS re-sends POST/PUT/DELETE/PATCH up to 5 times on 5xx, transport errors and timeouts, and once after a 403 (§2.5), duplicating targets, adapters and channels and turning a successful delete into a 404. Rust: D95 (one attempt, one replay after a 401, none after a 403) and the `Outcome unknown: the target may have been created.` detail line; restore stops creating after an unknown outcome.
2. **Target credentials in output (safety, choice).** TS prints `request_headers`, `curl`, `target_connection_config` keys and (json) `auth_config` in clear. Proposal: redact values of `auth_config`, `request_headers`, `oauth2_*` header/body maps, `target_connection_config` keys matching a secret-name list (`api_key`, `access_token`, `token`, `secret`, `client_secret`, `access_secret`, `session_token`, `password`), and replace `curl` with `(redacted)`, in every format of `get`, `create`, `update`, `probe`, `update-profile`; no reveal flag in 0.6. Alternative: a `--show-secrets` flag. `validate-auth`: print `Token` only as `(redacted)`, or keep TS's server preview (choice).
3. **Backups contain secrets (safety, choice).** Options: (a) full-fidelity backups with credentials, 0600 file in a 0700 directory, exclusive create, a stderr warning `  ⚠ The backup contains target credentials; keep it private.`; (b) redacted backups that restore cannot replay. Recommendation (a); TS writes 0644/0755.
4. **Backup overwrite and collisions (safety).** TS overwrites existing files and lets two targets with the same sanitised name overwrite each other (§13.3). Rust: refuse an existing file before any request where the names are known (after the listing, before any target GET), and make names unique (for example `<sanitised>-<first 8 of uuid>.json`, or one bundle file per run, choice).
5. **Backup format (settled: Rust-defined).** Proposal: one bundle file per run, `airs-redteam-targets-<UTC timestamp>.json`, `{"format":"airs-cli-rs/redteam-targets","version":1,"exportedAt","tenant":{"tsgId"},"targets":[{…full create body incl. description, adapter_uuid, adapter_variable_overrides, canonical_id…}]}`; `--file-format yaml` dropped (yaml is a dropped format) or kept as json-only with a usage error for other values (choice). TS writes one file per target.
6. **Lossy backups (correctness).** TS drops `description`, `adapter_uuid`, `adapter_variable_overrides`, `canonical_id`, nulls, and writes the fabricated `ws_response_timeout: 110` (§2.9, §13.2), so `CUSTOM_TARGET_ADAPTER` targets cannot be restored.
7. **Restore matching (safety).** TS creates duplicates for repeated names in a backup set, picks the last of duplicate tenant names, silently skips malformed or foreign files, checks no tenant identity, and has no preview. Rust: refuse duplicates and ambiguous names before any write, report each skipped file, refuse a backup from another TSG unless `--allow-other-tenant` (choice), add `--dry-run`, and require confirmation (D81) or `--force` for `--overwrite` (choice).
8. **Fabricated `ws_response_timeout` (correctness).** TS shows and re-sends a default the server never returned; Rust prints only server fields.
9. **Live exclusions.** Is target create without `--validate` known not to contact the endpoint? If yes, a prefixed throwaway target create/delete could join the live write flow; until then targets are excluded from live writes and only adapters with `--draft` are candidates (does a draft create/delete contact the broker? unknown).
10. **Output reachability (correctness).** `targets error-logs`, `adapter create|update|validate` ignore `--output` in TS (root consumer, `READ_COMMAND_NAMES`); `targets get --output table` prints nothing; `adapter get`, `channels get`, `stats` print YAML for `table`. Rust: every value works per the json/pretty/table set, others are usage errors.
11. **Empty lists in json (correctness).** TS prints `  No targets found` for `--output json`; Rust prints `[]`.
12. **Quiet mode deletes data (correctness).** `targets templates --quiet` prints only blank lines and the list commands drop their id rows; Rust keeps data on stdout and moves outcome and hint lines to stderr (D106 style).
13. **Validation order and exit codes (correctness).** TS reads `--config` after the tenant, reports non-UUID ids, `--limit 0`, script/variables errors and the channel check with exit 1 after the banner, and `--limit abc` on `targets list` silently prints an empty list. Rust: usage errors (exit 2) before the tenant; file checks per §13.2.
14. **Non-JSON error bodies (safety).** TS prints `API error 500: <raw body>`; Rust uses the §6 message from SDK metadata only.
15. **`targets init` (safety).** TS checks existence then writes with `w` (race, symlink followed, 0644). Rust: exclusive create, 0600 or 0644 (choice; the scaffold has only placeholders).
16. **Secrets on argv (safety, choice).** `adapter create|update|validate --variables` puts SECRET values in the process list. Add `--variables-file <path>` (and keep `--variables`, possibly with a warning).
17. **`adapter validate` output (safety).** Script stdout/stderr/traceback go through `terminal_safe` and the SecretSet; a SECRET value the user passed is added to the set.
18. **Ctrl-C at the confirmation (correctness).** TS exits 1 with `User force closed the prompt with SIGINT`; Rust 130 with `Cancelled; nothing was changed.` (D81).
19. **Interrupted backup (safety).** TS can leave truncated files; Rust writes temp + rename (or the single bundle atomically) and reports which targets were written.
20. **`adapter update` cannot clear `description` or the channel, and is not conditional.** Keep TS semantics (documented) unless the user wants `--clear-description` (choice, low priority).
