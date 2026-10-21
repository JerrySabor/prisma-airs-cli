# Spec: TS `airs-cli` Model Security (M6c, except `install` and `pypi-auth`)

Commands covered: `model-security groups list|get|create|update|delete`, `rules list|get`, `rule-instances list|get|update`, `scans list|get|create|evaluations|evaluation|violations|violation|files`, `models list|get|versions|version|files`, `labels add|set|delete|keys|values`. `install` and `pypi-auth` (`ms.ts:216-293,385-400`) need their own spec and appear here only where they share machinery (§2, §12).

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0, SDK `@cdot65/prisma-airs-sdk` 0.34.0, commander 14). Citations:
  - `ms.ts` is `src/cli/commands/modelsecurity.ts`; `svc.ts` is `src/airs/modelsecurity.ts` (normalisers and SDK wrappers); `rms.ts` is `src/cli/renderer/modelsecurity.ts`; `view.ts`, `common.ts`, `ui.ts` are under `src/cli/renderer/`; `program.ts` is `src/cli/program.ts`; `co.ts` is `src/config/client-options.ts`; `dbg.ts` is `src/cli/debug-logger.ts`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` of the reference build.
  - `rs:<file>:<line>` is `~/.cargo/registry/src/*/scm-sdk-0.1.1/src/<file>`.
- Shared shell behaviour (commander parse errors exit 1, the root `--output` consumer, `resolveOutput`, `ui`, quiet, colour, EPIPE) is in `ts-cli-shell.md` and `ts-renderer.md`, the debug log in `ts-debug-log.md`; it is restated only where Model Security depends on it.
- How behaviour was captured: the reference build (`dist/cli/index.js`, node v24.21.0) ran against a stateful loopback stub (`node:http` on `127.0.0.1`, random port) implementing `POST /oauth/token`, the management plane under `/aims/mgmt/v1/` (security groups with create/get/PUT/DELETE in a hard or soft delete mode, rule instances list/get/PUT, security rules list/get) and the data plane under `/aims/data/v1/` (scans list/create/get, evaluations, files, `rule-violations`, labels POST/PUT/DELETE kept in state, `label-keys`, values, evaluations/violations by id, models, model versions, version files). Pages honoured `skip`/`limit` and returned `pagination.total_items`. It logged every request (method, path, raw query, content type, auth scheme, raw body) and accepted a fault plan (status, raw body, headers such as `Retry-After: 0` or `x-opa-decision: false`, or a hang).
  - Sandbox: `env -i` with `PATH`, `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` inside the sandbox, the TS registry selected with `PRISMA_AIRS_TENANTS_PATH`, one tenant `test` (TSG `100`, `fake-client`/`FAKE-SECRET-100`), `mgmtTokenEndpoint` `<base>/oauth/token`, `modelSecDataEndpoint` `<base>/aims/data`, `modelSecMgmtEndpoint` `<base>/aims/mgmt`. Fixture ids are `11111111-1111-4111-8111-<12 digits>` (written `U(n)` below); fake sensitive values are `PRIVATE-…`.
  - **Endpoint fallbacks.** The CLI passes `dataEndpoint: config.modelSecDataEndpoint ?? DEFAULT_MODEL_SEC_DATA_ENDPOINT` and `mgmtEndpoint: config.modelSecMgmtEndpoint ?? DEFAULT_MODEL_SEC_MGMT_ENDPOINT` (`co.ts:71-77`; defaults `https://api.apps.paloaltonetworks.com/aims/data` and `…/aims/mgmt`, `SDK:75-76`), plus explicit `clientId`, `clientSecret`, `tsgId`, `tokenEndpoint: mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT` (`co.ts:34-42`). The SDK's environment fallbacks `PANW_MODEL_SEC_DATA_ENDPOINT`, `PANW_MODEL_SEC_MGMT_ENDPOINT` (`SDK:14603-14604`) and `PANW_MODEL_SEC_*`/`PANW_MGMT_*` credentials (`resolveOAuthConfig`, `SDK:11099-11104`) are therefore never reached (`client-options.spec.ts:63-79`). `modelSecTokenEndpoint` is a retired key, ignored when present (`schema.ts:64-71`). The only environment variables that change model-security behaviour are `PANW_AI_SEC_TIMEOUT_MS` (per-attempt timeout, `SDK:10095`), `PANW_AI_SEC_DEBUG`, `PANW_AI_SEC_DEBUG_BODY` (§2.10), `AIRS_CLI_INVOKED_AS`, and `FORCE_COLOR`/TTY for chalk.
  - Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and `dns.lookup` and refuses any host other than `127.0.0.1`; its log stayed empty.
  - Signals were sent with `kill -INT|-TERM` during a hung write.
- No real tenant or credential file was read; no host other than loopback was contacted.
- Captures are JSON strings (`"\n  ..."`), uncoloured (stdout a pipe) unless stated; §4 lists the ANSI codes captured with `FORCE_COLOR=1`. The stub's token request (`POST /oauth/token`, Basic auth, `grant_type=client_credentials&scope=tsg_id%3A100`) precedes the first API request of every run and is omitted from the request lists below.

## 1. Command surface (help verified)

Registration: `program.ts:197` calls `registerModelSecurityCommand` (`ms.ts:87-790`), which registers, in order, `groups`, `install`, `labels`, `pypi-auth`, `rule-instances`, `rules`, `scans`, `models`. After registration (`program.ts:204-206`): every `list` gets alias `ls`, every `delete` gets `rm` (`program.ts:42-51`, `aliases.spec.ts:66-86`); every `list`/`get` without `--output` gets `--output <format>` (`Output format: pretty, table, markdown, csv, json, yaml`); every `list` with `--limit` or `--offset` is completed with `--offset <n>` (`Item offset`, `Number`, default `0`), `--all` (`Walk all pages`) and `--max <n>` (`Maximum items with --all; 0 removes the cap`, `Number`, default `10000`) (`program.ts:54-70`); help sorts options and subcommands. No `--force` exists on any model-security command, and nothing prompts. No hidden `--size`/`--page` aliases.

| Command | Registration | Arguments and options (help text; defaults) |
|---|---|---|
| `groups list\|ls` | `ms.ts:97-132` | `--source-types <types>` (`Filter by source types (comma-separated)`), `--search <query>` (`Search by name or UUID`), `--sort-field <field>` (`Sort field (created_at, updated_at)`), `--sort-dir <dir>` (`Sort direction (asc, desc)`), `--enabled-rules <uuids>` (`Filter by enabled rule UUIDs (comma-separated)`), `--limit <n>` (`Max results`, default `"20"`, a **string**), `--output <format>`, added `--offset`, `--all`, `--max` |
| `groups get <uuid>` | `ms.ts:134-148` | `--output <format>` |
| `groups create` | `ms.ts:150-170` | `--config <path>` (`JSON file with group configuration`, **required**) |
| `groups update <uuid>` | `ms.ts:172-190` | `--name <name>` (`New name`), `--description <desc>` (`New description`) |
| `groups delete\|rm <uuid>` | `ms.ts:192-211` | none |
| `rules list\|ls` | `ms.ts:469-494` | `--source-type <type>` (`Filter by source type`), `--search <query>` (`Search by name or UUID`), `--limit <n>` (`Max results`, `"20"`), `--output`, added `--offset`, `--all`, `--max` |
| `rules get <uuid>` | `ms.ts:496-509` | added `--output` |
| `rule-instances list\|ls <groupUuid>` | `ms.ts:407-427` | `--security-rule-uuid <uuid>` (`Filter by security rule UUID`), `--state <state>` (`Filter by state (DISABLED, ALLOWING, BLOCKING)`), `--limit <n>` (`Max results`, `"20"`), added `--output`, `--offset`, `--all`, `--max` (the last three are **ignored**, §7.1) |
| `rule-instances get <groupUuid> <instanceUuid>` | `ms.ts:429-442` | added `--output` |
| `rule-instances update <groupUuid> <instanceUuid>` | `ms.ts:444-462` | `--config <path>` (`JSON file with rule instance updates`, required) |
| `scans list\|ls` | `ms.ts:516-557` | `--model-version <uuid>` (`Filter scans by model version UUID`), `--start <iso>` (`Creation time start (ISO timestamp)`), `--end <iso>` (`Creation time end (ISO timestamp)`), `--eval-outcome <outcome>` (`Filter by eval outcome`), `--source-type <type>` (`Filter by source type`), `--scan-origin <origin>` (`Filter by scan origin`; **never sent**, §8.1), `--search <query>` (`Search scans`), `--limit <n>` (`"20"`), `--output`, added `--offset`, `--all`, `--max`; help examples (`help-examples.spec.ts:42`) |
| `scans get <uuid>` | `ms.ts:559-572` | added `--output` |
| `scans create` | `ms.ts:574-589` | `--config <path>` (`JSON file with scan configuration`, required) |
| `scans evaluations <scanUuid>` | `ms.ts:591-606` | `--limit <n>` (`"20"`) |
| `scans evaluation <uuid>` | `ms.ts:608-620` | none |
| `scans violations <scanUuid>` | `ms.ts:622-637` | `--limit <n>` (`"20"`) |
| `scans violation <uuid>` | `ms.ts:639-651` | none |
| `scans files <scanUuid>` | `ms.ts:653-672` | `--type <type>` (`Filter by file type`), `--result <result>` (`Filter by result`), `--limit <n>` (`"20"`) |
| `models list\|ls` | `ms.ts:679-713` | `--start <iso>`, `--end <iso>` (as scans), `--search <text>` (`Filter by search text`), `--search-query <text>` (`Filter by model UUID or name`), `--sort-field <field>` (`Sort field: created_at, updated_at`), `--sort-order <order>` (`Sort order: asc, desc`), `--limit <n>` (`Max results`, **no default**), `--offset <n>` (`Starting offset`, **no default**, string), `--output`, added `--all`, `--max`; help example |
| `models get <uuid>` | `ms.ts:715-729` | `--output` |
| `models versions <modelUuid>` | `ms.ts:731-752` | `--sort-order <order>`, `--limit <n>`, `--offset <n>` (no defaults), `--output`; no `--all` (not named `list`) |
| `models version <uuid>` | `ms.ts:754-768` | `--output` |
| `models files <modelVersionUuid>` | `ms.ts:770-789` | `--limit <n>`, `--offset <n>` (no defaults), `--output`; no `--all` |
| `labels add <scanUuid>` | `ms.ts:300-314` | `--labels <json>` (`JSON array of {key, value} labels`, required) |
| `labels set <scanUuid>` | `ms.ts:316-330` | `--labels <json>` (required); description `Replace all labels on a scan` |
| `labels delete\|rm <scanUuid>` | `ms.ts:332-346` | `--keys <keys>` (`Comma-separated label keys to delete`, required) |
| `labels keys` | `ms.ts:348-363` | `--limit <n>` (`"20"`) |
| `labels values <key>` | `ms.ts:365-380` | `--limit <n>` (`"20"`) |

Captured `model-security --help` (stdout, exit 0):

```
Usage: airs-cli model-security [options] [command]

AI Model Security operations — groups, rules, scans

Options:
  -h, --help         display help for command

Commands:
  groups             Manage security groups
  help [command]     display help for command
  install [options]  Install the model-security-client Python package from AIRS
                     PyPI
  labels             Manage scan labels
  models             Browse the scanned model catalog (read-only)
  pypi-auth          Get PyPI authentication URL for Google Artifact Registry
  rule-instances     Manage rule instances in groups
  rules              Browse security rules
  scans              Model security scan operations
```

Group descriptions: `groups` `Manage security groups`, `rules` `Browse security rules`, `rule-instances` `Manage rule instances in groups`, `scans` `Model security scan operations`, `models` `Browse the scanned model catalog (read-only)`, `labels` `Manage scan labels`. Captured leaf help, for example `scans list --help`:

```
Usage: airs-cli model-security scans list|ls [options]

List model security scans

Options:
  --all                     Walk all pages
  --end <iso>               Creation time end (ISO timestamp)
  --eval-outcome <outcome>  Filter by eval outcome
  -h, --help                display help for command
  --limit <n>               Max results (default: "20")
  --max <n>                 Maximum items with --all; 0 removes the cap
                            (default: 10000)
  --model-version <uuid>    Filter scans by model version UUID
  --offset <n>              Item offset (default: 0)
  --output <format>         Output format: pretty, table, markdown, csv, json,
                            yaml
  --scan-origin <origin>    Filter by scan origin
  --search <query>          Search scans
  --source-type <type>      Filter by source type
  --start <iso>             Creation time start (ISO timestamp)

Examples:
  $ airs-cli model-security scans list
  $ airs-cli model-security scans list --eval-outcome MALICIOUS --limit 10
  $ airs-cli model-security scans list --output json

```

The example's `MALICIOUS` is not an eval outcome (`PENDING|ALLOWED|BLOCKED|ERROR`, `SDK:2916-2921`); it is sent unchanged (`eval_outcomes=MALICIOUS`, captured).

## 2. Shared behaviour

### 2.1 Client, endpoints and credentials

- Every action builds a fresh `SdkModelSecurityService(modelSecurityClientOptions(await loadConfig()))` (`ms.ts:81-84`): tenant first (no tenant → `\n  ✗ Error: No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'\n\n`, exit 1), then `assertManagementCredentials` (`\n  ✗ Error: Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set test <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)\n\n`, exit 1, captured). One OAuth token per invocation, cached in the client.
- Planes (`SDK:14588-14630`): `securityGroups` (with rule instances) and `securityRules` use `mgmtEndpoint`; `scans` (with evaluations, violations, files, labels) and `models` use `dataEndpoint`. Base URLs lose trailing slashes (`SDK:10117`). Paths (`SDK:83-90`): `/v1/scans`, `/v1/evaluations`, `/v1/violations`, `/v1/models`, `/v1/model-versions`, `/v1/security-groups`, `/v1/security-rules`.
- Headers: `Authorization: Bearer <token>`, `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `service-name: api`, `Content-Type: application/json` on bodies. No TSG header.
- `numRetries` is not passed, so the SDK maximum 5 applies (`SDK:11111-11114`); `airsNumRetries` is a scanner-plane key and does not apply.

### 2.2 Output format resolution

Three classes, decided by the leaf name and options:

| Class | Commands | Behaviour (captured) |
|---|---|---|
| A: resolved reads | `groups list\|get`, `rules list\|get`, `rule-instances list\|get`, `scans list\|get`, `models list\|get\|versions\|version\|files` | `preAction` (`program.ts:162-175`) runs `resolveOutput` because the leaf name is in `READ_COMMAND_NAMES` and has `--output`: tenant loaded first (no tenant → exit 1 even with `--output xml`), then `Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml` (`\n  ✗ …\n\n`, exit 2). The root consumes every `--output` (last wins: `groups ls --output table --output json` prints JSON); the tenant's `defaultOutput` applies (captured: `defaultOutput: "json"` makes `rules list` print JSON). `markdown`, `csv`, `yaml` work (§11.4). |
| B: always pretty | `scans evaluations\|evaluation\|violations\|violation\|files`, `labels keys\|values` | no `--output` option; `--output json` is consumed by the root and ignored (captured: pretty output, exit 0); `defaultOutput` ignored. The renderers have unreachable structured branches (§11.3). |
| C: writes | `groups create\|update\|delete`, `rule-instances update`, `scans create`, `labels add\|set\|delete` | no `--output`; always the pretty layout; `--output json` ignored (captured). |

Inside class A, `rules get`, `rule-instances list|get` and `scans get` read `opts.output` (`ms.ts:415,434,501,564`) instead of calling `resolveOutput` again; they still receive the value the `preAction` hook stored (source `implied`).

### 2.3 Banner, streams, quiet

- Banner `renderModelSecurityHeader` (`rms.ts:45-47`) = `ui.header('Prisma AIRS — Model Security', 'ML model supply chain security')`: stdout `"\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n"`, quiet-suppressed. Class A prints it only when the format is `pretty`, after the tenant was read in `preAction` and before `createService`; classes B and C print it **first**, before the tenant and credentials are read, so a no-tenant, credential or argument error leaves the banner on stdout (captured for `groups create`, `labels add`). In class A a missing tenant fails in `preAction` before the banner (stdout empty), but the `scans list`/`models list` window error comes after it (banner on stdout, captured).
- stdout: banner, every layout, empty-list phrases, every write acknowledgement (`ui.success` → `  ✓ …`), and the `groups delete` soft-delete warning (`ui.warn` writes to **stdout**, `ui.ts:95-97`).
- stderr: errors (`fail`, `usageError`, commander), the `--debug` status line. Model-security lists print **no page status line** (`structuredList` passes no `page`, `rms.ts:25-33`).
- `--quiet` suppresses `ui.header`, `ui.section` and `ui.dim`. Because every pretty list prints its record UUID with `ui.dim`, **quiet pretty lists lose their identifiers** (captured `--quiet groups list`: `"    Default LOCAL  ACTIVE  source: LOCAL\n    Pending S3  PENDING  source: S3\n\n"`); the rules-get remediation URL and the delete re-check hint vanish too. `ui.keyValue`, item lines, `ui.success`, `ui.warn`, bullets, empty-list phrases and structured output still print.

### 2.4 Errors and exit codes

Every action wraps its body in `try { … } catch (err) { fail(err) }` (`common.ts:12-25`):

- `fail`: `CliUsageError` → `usageError`. Otherwise stderr `"\n  ✗ Error: <message>\n"`, then for errors with `status`/`statusCode` `"    HTTP <s>\n"` and `"    Re-run with --debug to capture redacted API diagnostics.\n"`, then `"\n"`; exit 1.
- `usageError(msg)`: stderr `"\n  ✗ <msg>\n\n"`, exit 2.

| Situation | Message (captured) | Exit |
|---|---|---|
| commander: missing positional, missing required option, unknown option, excess arguments | `error: missing required argument 'uuid'`, `error: missing required argument 'instanceUuid'`, `error: required option '--config <path>' not specified`, `error: unknown option '--bogus'`, `error: too many arguments for 'list'. Expected 0 arguments but got 1.` | 1 |
| invalid `--output` (class A) | `Invalid output format 'xml'. Expected: …` | 2 |
| `scans list`/`models list` window (§8.1, §9.1) | `Use valid ISO timestamps with start <= end and a valid model-version UUID.` | 2 |
| SDK id check (`assertUuid`, `SDK:11148-11155`, `UUID_RE` `SDK:9555`, case-insensitive) | `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid security group uuid: not-a-uuid` (also `rule instance uuid`, `security rule uuid`, `scan uuid`, `evaluation uuid`, `violation uuid`, `model uuid`, `model version uuid`); no token request is made | 1 |
| SDK request schema (§2.7) | `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/security-groups did not match schema: name: too_small; source_type: invalid_enum_value` | 1 |
| `--all` with bad numbers | `limit must be a positive integer`, `max must be a non-negative integer` (`SDK:10814-10815,10803-10805`), after the banner and tenant | 1 |
| JSON syntax in `--config`/`--labels` | the V8 message, **quoting the input**: `Unexpected token 'x', "{"PRIVATE": x}\n" is not valid JSON`, `Unexpected token 'P', "PRIVATE-NOT-JSON" is not valid JSON` | 1 |
| `--config` file errors | `ENOENT: no such file or directory, open '<path as typed>'`, `EISDIR: illegal operation on a directory, read`; a file holding `null` gives `Cannot read properties of null (reading 'name')` | 1 |
| HTTP errors | `AISEC_CLIENT_SIDE_ERROR:security group not found` + `HTTP 404` (§2.6 for the text) | 1 |
| response validation | `AISEC_RESPONSE_VALIDATION:Response did not match schema: security_groups.0.tsg_id: invalid_type; …` (paths and zod codes only), `AISEC_RESPONSE_VALIDATION:Response body is not valid JSON` | 1 |
| timeout | `AISEC_CLIENT_SIDE_ERROR:Request timed out` (no `HTTP` line) | 1 |
| token failure | `AISEC_OAUTH_ERROR:invalid_client` + `HTTP 401` | 1 |
| SIGINT / SIGTERM | nothing printed | 130 / 143 |

### 2.5 Validation order (captured)

- Class A: argv (commander) → `preAction`: tenant read, format check → action: banner (pretty) → tenant and credentials (`createService`) → list window check (`scans list`, `models list`) → SDK id check → token → request.
- Class B: argv → banner → tenant and credentials → SDK id check → token → request.
- Class C: argv → banner → tenant and credentials → `--config` read and `JSON.parse` (or `--labels` parse, `--keys` split) → SDK id check → SDK request schema → token → request. A missing tenant hides a missing `--config` file (captured).

### 2.6 HTTP error text and retries (captured)

- No model-security request sets `safeErrorMessages`, so `executeWithRetry` (`SDK:9786-9850`) builds the message with `extractErrorMessage` (`SDK:9713-9725`): a problem-details body (`title`/`detail`/`errors`) is reduced to allowlisted text (`AISEC_CLIENT_SIDE_ERROR:API error 422; [withheld]`); otherwise the JSON `error_message`, `message`, `data.message`, `error.message` or `msg` is printed **verbatim** (`AISEC_CLIENT_SIDE_ERROR:bad PRIVATE-ECHO value`), including control characters (`evil \e[31mRED\nline2` reached stderr unchanged); a non-JSON body is printed whole: `AISEC_CLIENT_SIDE_ERROR:API error 400: PRIVATE plain text body`. Status ≥ 500 gives `AISEC_SERVER_SIDE_ERROR:`.
- Every method, writes included, is re-sent up to 5 times on 500/502/503/504 (`SDK:31`), transport errors and per-attempt timeouts (default 60 s), with jittered backoff (`SDK:9703-9706`) or `Retry-After` (≤ 60 s). Captured: `groups list` against a permanent 503 sent 6 GETs; `groups create` against three 502s sent **4 POSTs** and printed one created group; `scans create` against two 500s sent **3 POSTs** (a billed, long-running scan); `labels set` against two 503s sent 3 PUTs; with `PANW_AI_SEC_TIMEOUT_MS=300` a hung `groups create` sent **6 POSTs** in 22 s and a hung `groups delete` 6 DELETEs, both ending `Request timed out`; a hung `labels set` that answered on the second attempt printed `✓ Labels set.` after 2 PUTs. No outcome-unknown text exists.
- 401 and 403 (without `x-opa-decision: false`) clear the token and replay once (`SDK:10865-10872`): `token, GET(401), token, GET(401)` → `API error 401`, exit 1; a 403 with `x-opa-decision: false` is sent once.

### 2.7 Request schemas and bodies (`SDK:3029-3330`, all `.passthrough()`)

Bodies are the zod output, serialised with `JSON.stringify`; failures list paths and zod codes only, before any token request.

| Body | Schema | Notes |
|---|---|---|
| group create | `ModelSecurityGroupCreateRequestSchema` (`SDK:3303-3308`): `name` 1..255, `source_type` ∈ `LOCAL\|HUGGING_FACE\|S3\|GCS\|AZURE\|ARTIFACTORY\|GITLAB\|ALL`, `description` ≤ 1000 **default `""`**, `rule_configurations` record of `{field_values?, state?}` | the CLI copies only `name`, `source_type`, `description`, `rule_configurations` from the file (`ms.ts:158-163`, `svc.ts:252-262`); other keys are dropped (captured `extra` not sent); a missing description is sent as `"description":""` |
| group update | `ModelSecurityGroupUpdateRequestSchema` (`SDK:3321-3324`): `name` 1..255 nullable, `description` ≤ 1000 nullable | built from flags, each only when truthy (`ms.ts:181-183`) |
| rule-instance update | `ModelSecurityRuleInstanceUpdateRequestSchema` (`SDK:3294-3298`): `security_group_uuid` uuid, `state` ∈ `DISABLED\|ALLOWING\|BLOCKING` nullable, `field_values` record nullable | `security_group_uuid` is the positional group; the file's `state` and `field_values` are copied when not `undefined` (`svc.ts:330-347`), so `null` is sent; other keys (including the file's own `security_group_uuid`) are dropped |
| scan create | `ScanCreateRequestSchema` (`SDK:3084-3096`): `model_uri` string, `security_group_uuid` uuid, optional `scan_origin` enum, `allow_patterns`, `ignore_patterns`, `labels`, `model_author`, `model_name`, `model_version`, `scan_details` | **the whole file** is the body (`ms.ts:582-583`); unknown keys are sent (captured `"unknown":"kept"`) |
| labels add/set | `LabelsCreateRequestSchema` (`SDK:3038-3040`): `labels` array **min 1** of `{key 1..128, value 1..256}` | `{labels: <parsed --labels>}` |

### 2.8 Ids and path segments

All UUID positionals pass `assertUuid` before the token (§2.4), so they cannot alter paths. The one free-text segment is `labels values <key>`, `encodeURIComponent`-ed (`SDK:13965`): `a/b c?d` → `/v1/scans/label-keys/a%2Fb%20c%3Fd/values`; but `''` and `..` are not encoded and the URL parser normalises them: `labels values ''` sends `GET /aims/data/v1/scans/label-keys//values`, and `labels values ..` sends **`GET /aims/data/v1/scans/values`**, a different endpoint (captured; the error then printed that endpoint's server text). The Rust SDK refuses these segments (`rs:config.rs`, `RawRequest::segment`).

### 2.9 Interruption

No handlers and no prompts. SIGINT or SIGTERM during a hung `groups create` exited 130 / 143; stdout held the banner only, stderr was empty, and nothing said whether the group was created (captured).

### 2.10 `--debug` and `PANW_AI_SEC_DEBUG`

- `--debug` creates `debug-api-<ms>-<8 hex>.jsonl` (0600, `wx`) in the **current directory** and prints `  Debug: API log → <abs path>` on stderr (captured). The logger is installed with `omitBodies: agentGuard || dlp` (`program.ts:183`), so **model-security request and response bodies are recorded**, passed through `redactDeep`, which masks values of keys matching `/token|secret|password|passwd|credential|authorization|cookie|api[-_]?key|client[-_]?auth|auth[-_]?code|^key$/i` (`dbg.ts:31-61`). Consequences derived from the source: group and scan configs, rule field values, scan records, label **values** and model URIs are written; label `key` fields become `***` (the `^key$` rule) while their values stay; the `pypi-auth` response `url` (a credential) is kept. Only PANW hosts are logged (`dbg.ts:12-27,163-165`), so the loopback capture produced a 0-byte file.
- `PANW_AI_SEC_DEBUG=1` prints SDK lines on stderr (captured): `[airs-sdk] → POST http://127.0.0.1:<port>/aims/data/v1/scans/<U(401)>/labels`, `[airs-sdk]   headers {"User-Agent":"PAN-AIRS/0.34.0-typescript-sdk","service-name":"api","Content-Type":"application/json","Authorization":"sha256:<12 hex>"}`, `[airs-sdk]   body [BODY OMITTED]`, `[airs-sdk] ← 200 (1ms) [BODY OMITTED]`. Unlike DLP (`program.ts:122-127`), model-security does not force `PANW_AI_SEC_DEBUG_BODY=0`: with `PANW_AI_SEC_DEBUG_BODY=1` the bodies are printed (captured `body {"labels":[{"key":"k","value":"PRIVATE-LABEL-VALUE"}]}` and `← 200 (3ms) {}`).

### 2.11 Normalised records, dropped fields, fabricated defaults

Every printed record is a camelCase projection built by `svc.ts:29-192`, not the wire object. JSON prints the projection (keys with `undefined` omitted); table detail prints every own key (undefined → empty cell).

| Record | Fields kept (order) | Wire fields dropped | Values invented by the CLI |
|---|---|---|---|
| group (`svc.ts:29-39`) | `uuid, name, description, sourceType, state, createdAt, updatedAt` | `tsg_id`, `is_tombstone`, `enabled_rule_count`, passthrough | — |
| rule instance (`svc.ts:42-53`) | `uuid, securityGroupUuid, securityRuleUuid, state, createdAt, updatedAt, rule, fieldValues` | `tsg_id`, `custom_rule`, `custom_rule_uuid`, `created_by`, `updated_by` | `fieldValues: {}`; `rule` is the **raw snake_case** rule object (captured `rule_type`, `compatible_sources` inside camelCase JSON) |
| rule (`svc.ts:56-80`) | `uuid, name, description, ruleType, compatibleSources, defaultState, remediation, editableFields[{attributeName,type,displayName,displayType,description,dropdownValues}], constantValues, defaultValues` | `enabled_security_group_count` | `editableFields: []`, `constantValues: {}`, `defaultValues: {}` |
| scan (`svc.ts:83-103`) | `uuid, evalOutcome, modelUri, scanOrigin, sourceType, securityGroupName, evalSummary{rulesFailed,rulesPassed,totalRules}\|null, createdAt, updatedAt, labels` | `tsg_id`, `owner`, `security_group_uuid`, `model_version_uuid`, `error_code`, `error_message`, `created_by`, `model_formats`, `scanner_version`, `time_started`, `total_files_*`, `sdk_version`, `enabled_rule_count_snapshot`, `count_capped` (list) | `''` for missing strings, `labels: []`, summary counts `0` |
| evaluation (`svc.ts:106-116`) | `uuid, result, violationCount, ruleInstanceUuid, ruleName, ruleDescription, ruleInstanceState` | `tsg_id`, timestamps, `scan_uuid`, `rule_origin` | `0`/`''` |
| violation (`svc.ts:119-130`) | `uuid, description, threat, threatDescription, file, ruleName, ruleDescription, ruleInstanceState` | `remediation`, `hash`, `module`, `operator`, `insights_url`, `threat_kb_url`, `rule_instance_uuid`, timestamps | `''` for null `threat`/`file` |
| file (`svc.ts:133-141`) | `uuid, path, type, formats, result` | `tsg_id`, timestamps, `parent_path`, `model_version_uuid`, `blob_id`, `scan_uuid` | `formats: []` (captured for a file without `formats`), `path: ''` |
| model (`svc.ts:144-160`) | `uuid, tsgId, name, createdAt, updatedAt, latestVersion{Uuid,Fingerprint,Revision,HfCommitSha,Outcome,Formats,SourceTypes,ScanTime}` | passthrough | — |
| model version (`svc.ts:163-192`) | `uuid, tsgId, modelUuid, revision, createdAt, updatedAt, fingerprint, fileCount, license, latestScanTime, hfCommitSha, hfCommitTitle, hfCommitAuthors, hfModelName, hfOrganization, modelFormats, sourceTypes, lastEvalOutcome, lastEvalSummary` | passthrough | summary counts `0` |

**Schema defaults (G10).** Walking `rs:validation/schema_graph.json` from every `src/models/model-security*.ts` root finds `ZodDefault` nodes only in `EvalSummarySchema` (`rules_failed`, `rules_passed`, `total_rules` default 0, `SDK:3050-3054`), reached from `ScanBaseResponseSchema`, `ScanListSchema`, `ModelVersionResponseSchema`, `ModelVersionListSchema`, and in `ModelSecurityGroupCreateRequestSchema.description` (request side). Captured: a scan with `"eval_summary":{}` prints `  Rules      0 passed  0 failed  / 0 total` and JSON `"evalSummary": {"rulesFailed": 0, "rulesPassed": 0, "totalRules": 0}`: a pending scan is shown as evaluated against zero rules.

## 3. Lists: flags, requests, pagination

### 3.1 Parsing (captured)

- `--limit` (string default `"20"` where declared): `Number.parseInt(v, 10)`, no check. `--limit abc` → `limit=NaN` is **sent** (`groups list`: `?skip=0&limit=NaN`; `scans evaluations --limit abc`: `?limit=NaN`), exit 0; `--limit 1.5` → `limit=1`; `--limit 0` → `limit=0` (the stub then returned nothing: `  No security groups found`); `--limit 500` → `limit=500` (no client cap; the SDK's 1..100 check covers only custom rules, `SDK:13450-13462`).
- `--offset` (added `Number` parser, default `0`): `Number(opts.offset ?? 0)` → `skip`; `--offset -2` → `skip=-2` sent. `models list|versions|files` declare `--offset` as a string without default: absent → no `skip`; `--offset 0` → `skip=0` (the string is truthy); `--offset abc` → `skip=NaN` sent.
- `models list|versions|files --limit`: absent → no `limit` (server default page size, unknown); `--limit 0` → `limit=0`.
- `--all`: `listAll*({…, limit, max: Number(opts.max)})` (`svc.ts:232-245,373-383,424-438,599-613`). **`--offset` is dropped** (`groups list --limit 1 --all --max 1 --offset 1` started at `skip=0`); `--limit` becomes the page size (`models list --all` without `--limit` uses 50, `SDK:10814`); `--limit abc` → `limit must be a positive integer`; `--max abc` → `max must be a non-negative integer`; `--max 0` removes the cap; `--max` without `--all` is ignored. `rule-instances list` ignores `--all`, `--offset` and `--max` entirely (§7.1).
- Comma lists (`--source-types`, `--enabled-rules`) are split on `,` and trimmed (`'LOCAL, S3'` → `source_types=LOCAL&source_types=S3`); empty items are kept. Single-value filters (`--eval-outcome`, `--source-type`) become one-element arrays for scans.

### 3.2 Walk (`collectSkipPages`, `SDK:10813-10826`)

`GET ?skip=0&limit=<n>…`, then `skip += items.length` while the page is non-empty and (`total_items` known ? `next < total` : `items.length === limit`); collection stops at `max` items without saying so (`collectAll`, `SDK:10802-10812`). Captured `groups list --limit 1 --all`: `?skip=0&limit=1`, `?skip=1&limit=1` (total 2).

### 3.3 Request per list (captured; query keys in the order sent)

| Command | Without `--all` | With `--all` |
|---|---|---|
| `groups list` | `GET /aims/mgmt/v1/security-groups?skip=<o>&limit=<l>[&sort_field][&sort_dir][&source_types…][&search_query][&enabled_rules…]` (`SDK:14025-14033`) | same filters, `skip` walked |
| `rules list` | `GET /aims/mgmt/v1/security-rules?skip&limit[&source_type][&search_query]` | same |
| `rule-instances list` | `GET /aims/mgmt/v1/security-groups/<g>/rule-instances?limit=<l>[&security_rule_uuid][&state]` (no `skip`) | identical (ignored) |
| `scans list` | `GET /aims/data/v1/scans?skip&limit[&search][&model_version_uuid][&eval_outcomes][&source_types][&start_time][&end_time]` | `…?skip&limit[&model_version_uuid][&search_query][&eval_outcomes][&source_types][&start_time][&end_time]` |
| `models list` | `GET /aims/data/v1/models[?skip][&limit][&search][&search_query][&sort_field][&sort_order][&start_time][&end_time]` | `skip`, `limit` (default 50) walked, same filters |
| `models versions` | `GET /aims/data/v1/models/<m>/model-versions[?skip][&limit][&sort_order]` | — |
| `models files` | `GET /aims/data/v1/model-versions/<v>/files[?skip][&limit]` | — |
| `scans evaluations` | `GET /aims/data/v1/scans/<s>/evaluations?limit=<l>` | — |
| `scans violations` | `GET /aims/data/v1/scans/<s>/rule-violations?limit=<l>` | — |
| `scans files` | `GET /aims/data/v1/scans/<s>/files?limit=<l>[&type][&result]` | — |
| `labels keys` | `GET /aims/data/v1/scans/label-keys?limit=<l>` | — |
| `labels values` | `GET /aims/data/v1/scans/label-keys/<encoded key>/values?limit=<l>` | — |

Wrong listings in TS: `scans list --scan-origin` is never sent (`buildScanListParams`, `SDK:13622-13638`, has no `scan_origin`, so the service's `scan_origin` key is dropped; `svc.ts:408`, `modelsecurity.spec.ts:525-548` asserts only the service call), so the filter silently returns every origin; `scans list --search` is sent as `search` without `--all` but as `search_query` with `--all` (`svc.ts:409,433`); class-B lists and `models versions|files` fetch one page only and give no sign that more exist; no list prints a total.

## 4. Pretty primitives and colours

- `ui.section(l)` `"\n  <bold l>\n\n"` (quiet-suppressed), `ui.keyValue` `"  <dim key.padEnd(W)>  <String(v ?? '')>\n"` with W the longest key of that call (padding inside the dim span), `ui.dim(m)` `"  <dim m>\n"` (quiet-suppressed), `ui.emptyList(r)` `"  <dim No <r> found>\n"`, `ui.bullet(m)` `"  <dim •> m\n"`, `ui.success(m)` `"  <green ✓ m>\n"`, `ui.warn(m)` `"  <yellow ⚠ m>\n"` (stdout).
- `stateColor` (`rms.ts:50-67`): green for `ACTIVE`, `ALLOWED`, `ALLOWING`, `PASSED`, `SUCCESS`; red for `BLOCKED`, `BLOCKING`, `FAILED`; dim for `DISABLED`; **yellow for everything else**, `ERROR` and `PENDING` included. Groups use green for `ACTIVE`, yellow otherwise (`rms.ts:96,112`); files green `SUCCESS`, yellow `SKIPPED`, red otherwise (`rms.ts:493-494`).
- ANSI (captured, `FORCE_COLOR=1`): bold `\e[1m…\e[22m`, dim `\e[2m…\e[22m`, green `\e[32m…\e[39m`, red `\e[31m…\e[39m`, yellow `\e[33m…\e[39m`. Errors: chalk splits the red text per line: `"\e[31m\e[39m\n\e[31m  ✗ Error: AISEC_CLIENT_SIDE_ERROR:security group not found\e[39m\n\e[31m    HTTP 404\e[39m\n\e[2m    Re-run with --debug to capture redacted API diagnostics.\e[22m\n\n"`; usage errors `"\e[31m\e[39m\n\e[31m  ✗ Use valid ISO timestamps …\e[39m\n\e[31m\e[39m\n"`. Colour level follows stdout's TTY for both streams (`ts-renderer.md` §2.6).
- Server text (names, descriptions, URIs, paths, labels, error messages) is printed raw: a group name `Evil\e[31mRED\nline2` reached stdout with its escape and newline in pretty and table output (captured).

## 5. `groups`

### 5.1 `list` (`ms.ts:97-132`, `rms.ts:70-100`)

Request §3.3. Pretty: section `Security Groups:`, per group `ui.dim(uuid)` then `"    <name>  <state coloured>  source: <dim sourceType>\n"`, then `"\n"`; empty → `  No security groups found`. Captured:

`"\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n\n  Security Groups:\n\n  11111111-1111-4111-8111-000000000001\n    Default LOCAL  ACTIVE  source: LOCAL\n  11111111-1111-4111-8111-000000000002\n    Pending S3  PENDING  source: S3\n\n"`

Colour: `"  \e[2m<uuid>\e[22m\n    Default LOCAL  \e[32mACTIVE\e[39m  source: \e[2mLOCAL\e[22m\n"`, `\e[33mPENDING\e[39m`.

### 5.2 `get <uuid>` (`ms.ts:134-148`, `rms.ts:103-123`)

`GET /aims/mgmt/v1/security-groups/<uuid>`. Pretty: section `Security Group Detail:`, keys `UUID`, `Name`, `Description` (dim `(none)` when empty), `Source Type`, `State` (green `ACTIVE`, else yellow), `Created`, `Updated`, then `"\n"`. Captured: `"…\n\n\n  Security Group Detail:\n\n  UUID         11111111-1111-4111-8111-000000000001\n  Name         Default LOCAL\n  Description  Auto group\n  Source Type  LOCAL\n  State        ACTIVE\n  Created      2026-01-01T00:00:00Z\n  Updated      2026-01-01T00:00:00Z\n\n"`.

### 5.3 `create --config <path>` (`ms.ts:150-170`, `svc.ts:252-262`)

Order §2.5 (class C). The file is read with `fs.readFileSync(path, 'utf-8')` (relative to the cwd, symlinks followed, no regular-file check, no size limit) and parsed; `POST /aims/mgmt/v1/security-groups` with §2.7's body, e.g. captured `{"name":"g1","source_type":"LOCAL","description":"d1","rule_configurations":{"<U(201)>":{"state":"BLOCKING"}}}` and, for a file without description, `{"name":"g2","source_type":"LOCAL","description":""}`. Output (stdout, every format): banner, `  ✓ Group created: <uuid>`, then the §5.2 detail of the response (`ms.ts:165-166`). Captured: `"\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n  ✓ Group created: 11111111-1111-4111-8111-000000000102\n\n  Security Group Detail:\n\n  UUID         11111111-1111-4111-8111-000000000102\n  Name         g1\n  Description  d1\n  Source Type  LOCAL\n  State        PENDING\n  Created      2026-01-01T00:00:00Z\n  Updated      2026-01-01T00:00:00Z\n\n"`. Quiet: `"  ✓ Group created: <uuid>\n  UUID …\n…\n\n"`. Replayed on 5xx/timeouts (§2.6): duplicates possible.

### 5.4 `update <uuid> [--name] [--description]` (`ms.ts:172-190`)

`PUT /aims/mgmt/v1/security-groups/<uuid>` with `{name?, description?}`, each only when the flag value is truthy: `--description ''` cannot clear a description (dropped), and no flags sends `{}` and still prints `✓ Group updated: <uuid>` (captured). Output: `  ✓ Group updated: <uuid>` + §5.2 detail of the response. Schema errors (`description: too_big` for 1001 characters, captured) exit 1. No confirmation.

### 5.5 `delete|rm <uuid>` (`ms.ts:192-211`, `svc.ts:284-292`)

`DELETE /aims/mgmt/v1/security-groups/<uuid>`, then immediately `GET` the same path (`deleteGroupAndVerify`). No confirmation, no `--force`.

- GET fails (**any** error) → `  ✓ Group <uuid> deleted.` (exit 0). Captured: after a hard delete (GET 404) — correct; but also when the GET answered 500 six times (`DELETE`, 6×`GET`) and when it answered 401 twice: the CLI reports a deletion it never observed.
- GET succeeds → stdout `  ⚠ Delete request accepted, but group <uuid> still reports state '<state>'.` and dim `  Deletion is asynchronous (soft-delete) — re-check with \`model-security groups get <uuid>\`.`, exit 0 (captured; quiet keeps only the ⚠ line). `is_tombstone` is not consulted.
- DELETE fails → `fail` (404: `AISEC_CLIENT_SIDE_ERROR:security group not found` + `HTTP 404`, exit 1). DELETE is replayed on 5xx/timeouts (6 DELETEs on a hang, captured).

## 6. `rules`

### 6.1 `list` (`ms.ts:469-494`, `rms.ts:126-161`)

Request §3.3. Pretty: section `Security Rules:`, per rule `ui.dim(uuid)`, `"    <name>  type: <dim ruleType>  default: <dim defaultState>\n"`, `"    <dim description>\n"`, `"    Sources: <dim s1>, <dim s2>\n"`; then `"\n"`; empty → `  No security rules found`. Captured: `"…\n\n\n  Security Rules:\n\n  11111111-1111-4111-8111-000000000201\n    Load Time Code Execution Check  type: ARTIFACT  default: BLOCKING\n    No unsafe operators at load time\n    Sources: ALL\n  11111111-1111-4111-8111-000000000202\n    Stored In Approved File Format  type: METADATA  default: ALLOWING\n    Formats must be approved\n    Sources: LOCAL, S3\n\n"`.

### 6.2 `get <uuid>` (`ms.ts:496-509`, `rms.ts:164-200`)

`GET /aims/mgmt/v1/security-rules/<uuid>`. Pretty: section `Security Rule Detail:`, keys `UUID`, `Name`, `Description`, `Rule Type`, `Default State`, `Sources` (joined `, `); when `remediation.description` is non-empty: section `Remediation:`, `"  <description>\n"`, one bullet per step, `ui.dim(url)` when non-empty; when `editableFields` is non-empty: section `Editable Fields:`, `"  <displayName> (<dim attributeName>): <displayType>\n"` and `"    <dim description>\n"` when present (dropdown values, constant and default values are not shown); then `"\n"`. Captured: `"…\n\n\n  Security Rule Detail:\n\n  UUID           11111111-1111-4111-8111-000000000201\n  Name           Load Time Code Execution Check\n  Description    No unsafe operators at load time\n  Rule Type      ARTIFACT\n  Default State  BLOCKING\n  Sources        ALL\n\n  Remediation:\n\n  Remove unsafe operators\n  • Review the violation\n  • Use a safe format\n  https://docs.example.invalid/r1\n\n"` and `"…  Sources        LOCAL, S3\n\n  Editable Fields:\n\n  Approved Formats (approved_formats): MULTI_SELECT\n    Formats allowed\n\n"`. Quiet drops the section headings and the URL, leaving `"  Remove unsafe operators\n  • Review the violation\n  • Use a safe format\n\n"` glued under `Sources`.

## 7. `rule-instances`

### 7.1 `list <groupUuid>` (`ms.ts:407-427`, `svc.ts:298-320`, `rms.ts:203-232`)

Request §3.3: `?limit=<l>[&security_rule_uuid=<u>][&state=<s>]`. `--offset`, `--all` and `--max` are registered (help and docs-site document them) but **never read**: `rule-instances list <g> --limit 1 --offset 1 --all --max 1` sent `?limit=1&…` once (captured), so a group with more than `--limit` (default 20) instances is listed incompletely with no hint. `--state` and `--security-rule-uuid` are not validated (`--state bogus` sent). Pretty: section `Rule Instances:`, per instance `ui.dim(uuid)` and `"    <rule.name ?? securityRuleUuid>  <stateColor(state)>\n"`; empty → `  No rule instances found`. Captured: `"…\n\n\n  Rule Instances:\n\n  11111111-1111-4111-8111-000000000301\n    Load Time Code Execution Check  BLOCKING\n  11111111-1111-4111-8111-000000000302\n    11111111-1111-4111-8111-000000000202  DISABLED\n\n"`. An instance of a custom rule (no `security_rule_uuid`, no `rule`, with `custom_rule {name}`) prints `    undefined  BLOCKING` (captured); its JSON lacks `securityRuleUuid` and the custom rule.

### 7.2 `get <groupUuid> <instanceUuid>` (`ms.ts:429-442`, `rms.ts:235-266`)

`GET /aims/mgmt/v1/security-groups/<g>/rule-instances/<i>`. Pretty: section `Rule Instance Detail:`, keys `UUID`, `Group UUID`, `Rule UUID`, `State` (stateColor), `Rule Name` (only when `rule.name`), `Created`, `Updated`; section `Field Values:` when non-empty, one key per field, arrays joined `, `, other values `String(v)` (an object prints `[object Object]`, derived). Captured: `"…\n\n\n  Rule Instance Detail:\n\n  UUID        11111111-1111-4111-8111-000000000302\n  Group UUID  11111111-1111-4111-8111-000000000001\n  Rule UUID   11111111-1111-4111-8111-000000000202\n  State       DISABLED\n  Created     2026-01-01T00:00:00Z\n  Updated     2026-01-01T00:00:00Z\n\n  Field Values:\n\n  approved_formats  onnx, safetensors\n\n"`; with the rule embedded the `Rule Name` line follows `State`. The custom-rule instance prints empty `Rule UUID`, `Created`, `Updated` values.

### 7.3 `update <groupUuid> <instanceUuid> --config <path>` (`ms.ts:444-462`, `svc.ts:330-347`)

`PUT /aims/mgmt/v1/security-groups/<g>/rule-instances/<i>` with `{"security_group_uuid":"<g>"[,"state":…][,"field_values":…]}` (captured `{"security_group_uuid":"<U(1)>","state":"ALLOWING","field_values":{"approved_formats":["onnx"]}}`; `{}` in the file sends only the group id and still reports success). Whether the server treats an omitted `field_values` as "keep" or "clear" is unknown (PUT). Output: `  ✓ Rule instance updated: <uuid>` + §7.2 detail. Replayed on 5xx/timeouts; no confirmation.

## 8. `scans`

### 8.1 `list` (`ms.ts:516-557`, `svc.ts:399-438`, `rms.ts:273-312`)

`supplyChainWindow` (`ms.ts:38-54`): zod `start`/`end` `datetime({offset:true})`, `modelVersion` UUID, `start <= end`; any failure → usage error `Use valid ISO timestamps with start <= end and a valid model-version UUID.` (exit 2, after the banner and tenant, before the token; captured for `--start 2026-01-01`, reversed range, `--model-version not-a-uuid`). Request §3.3 (captured `?skip=1&limit=2&search=s1&model_version_uuid=<U(901)>&eval_outcomes=BLOCKED&source_types=LOCAL&start_time=2026-01-01T00%3A00%3A00Z&end_time=2026-02-01T00%3A00%3A00%2B01%3A00`; `--scan-origin` absent). Pretty: section `Model Security Scans:`, per scan `ui.dim(uuid)`, `"    <stateColor(evalOutcome)>  <dim scanOrigin>  <dim createdAt>\n"`, `"    <dim modelUri>\n"` when non-empty, `"    Rules: <green N passed>  <red N failed>  / T total\n"` when `evalSummary`; then `"\n"`; empty → `  No scans found`. Captured: `"…\n\n\n  Model Security Scans:\n\n  11111111-1111-4111-8111-000000000401\n    BLOCKED  MODEL_SECURITY_SDK  2026-01-01T00:00:00Z\n    hf://org/model\n    Rules: 3 passed  1 failed  / 4 total\n  11111111-1111-4111-8111-000000000402\n    ALLOWED  MODEL_SECURITY_API  2026-01-01T00:00:00Z\n\n"`.

### 8.2 `get <uuid>` (`ms.ts:559-572`, `rms.ts:315-344`)

`GET /aims/data/v1/scans/<uuid>`. Pretty: section `Scan Detail:`, keys `UUID`, `Outcome` (stateColor), `Model URI` (when non-empty), `Origin`, `Source`, `Group` (security group name), `Created`, `Updated`, `Rules` (when summary); section `Labels:` with one `key  value` line per label. Captured: `"…\n\n\n  Scan Detail:\n\n  UUID       11111111-1111-4111-8111-000000000401\n  Outcome    BLOCKED\n  Model URI  hf://org/model\n  Origin     MODEL_SECURITY_SDK\n  Source     HUGGING_FACE\n  Group      Default LOCAL\n  Created    2026-01-01T00:00:00Z\n  Updated    2026-01-01T00:00:00Z\n  Rules      3 passed  1 failed  / 4 total\n\n  Labels:\n\n  env   prod\n  team  ml\n\n"`. Error codes and messages of a failed scan are not shown.

### 8.3 `create --config <path>` (`ms.ts:574-589`)

The parsed file is the body (§2.7); `POST /aims/data/v1/scans`. Output: `  ✓ Scan created: <uuid>` + §8.2 detail of the response (captured with `Outcome    PENDING` and the labels). The create is billed and long-running server-side; TS re-sends it on 5xx and timeouts (§2.6: 3 POSTs captured).

### 8.4 `evaluations <scanUuid>` and `evaluation <uuid>` (`ms.ts:591-620`, `rms.ts:351-404`)

Class B. List: section `Rule Evaluations:`, per item `ui.dim(uuid)` and `"    <ruleName>  <stateColor(result)>  <dim ruleInstanceState>\n"`; empty → `  No evaluations found`. Captured: `"…\n\n\n  Rule Evaluations:\n\n  11111111-1111-4111-8111-000000000501\n    Load Time Code Execution Check  FAILED  BLOCKING\n  11111111-1111-4111-8111-000000000502\n    Stored In Approved File Format  PASSED  ALLOWING\n\n"`. Detail (`GET /aims/data/v1/evaluations/<uuid>`): section `Evaluation Detail:`, keys `UUID`, `Rule`, `Description`, `Instance UUID`, `Instance State`, `Result` (stateColor), `Violations`; captured `"…  UUID            <U(501)>\n  Rule            Load Time Code Execution Check\n  Description     No unsafe operators\n  Instance UUID   <U(301)>\n  Instance State  BLOCKING\n  Result          FAILED\n  Violations      2\n\n"`.

### 8.5 `violations <scanUuid>` and `violation <uuid>` (`ms.ts:622-651`, `rms.ts:411-464`)

List (`/rule-violations`): section `Violations:`, per item `ui.dim(uuid)`, `"    <red ruleName>  <dim file>\n"`, `"    <description>\n"`, `"    Threat: <dim threat>\n"`; empty → `  No violations found`. Captured `"…\n\n\n  Violations:\n\n  11111111-1111-4111-8111-000000000601\n    Load Time Code Execution Check  model.pkl\n    Found os.system\n    Threat: PAIT-PKL-100\n\n"`. Detail (`GET /aims/data/v1/violations/<uuid>`): section `Violation Detail:`, keys `UUID`, `Rule` (red), `Description` (rule description), `State`, `File`, `Threat`, `Detail` (violation description); remediation, module, operator and URLs are not shown.

### 8.6 `files <scanUuid>` (`ms.ts:653-672`, `rms.ts:471-499`)

Query §3.3 (`type`, `result` unvalidated). Section `Scanned Files:`, per file `"    <coloured result>  <type>  <path>[<dim " [f1, f2]">]\n"` (no id line), then `"\n"`; empty → `  No files found`. Captured: `"…\n\n\n  Scanned Files:\n\n    FAILED  FILE  model.pkl [pickle]\n    SKIPPED  FILE  README.md\n    SUCCESS  DIRECTORY  weights\n\n"`.

## 9. `models`

### 9.1 `list` (`ms.ts:679-713`, `rms.ts:536-577`)

Window check as §8.1 (no `--model-version`). Request §3.3 (captured `?skip=1&limit=1&search=a&search_query=b&sort_field=created_at&sort_order=desc&start_time=…&end_time=…`). Pretty: section `Models:`, per model `ui.dim(uuid)`, `"    <name>  <stateColor(outcome) or dim 'unscanned'>[<dim " [formats]">]\n"` and an empty line after **each** model (no final extra line). Captured: `"…\n\n\n  Models:\n\n  11111111-1111-4111-8111-000000000801\n    org/model  BLOCKED [pickle, onnx]\n\n  11111111-1111-4111-8111-000000000802\n    local/unscanned  unscanned\n\n"`; empty → `  No models found`.

### 9.2 `get <uuid>` (`ms.ts:715-729`, `rms.ts:580-610`)

`GET /aims/data/v1/models/<uuid>`. Section `Model Detail:`, keys `UUID`, `Name`, `Created`, `Updated`, then when not null `Latest Version`, `Latest Revision`, `Latest Outcome` (stateColor), `Formats`, `Source Types` (non-empty arrays), `Last Scan`. Captured `"…  UUID             <U(801)>\n  Name             org/model\n  Created          2026-01-01T00:00:00Z\n  Updated          2026-01-01T00:00:00Z\n  Latest Version   <U(901)>\n  Latest Revision  main\n  Latest Outcome   BLOCKED\n  Formats          pickle, onnx\n  Source Types     HUGGING_FACE\n  Last Scan        2026-01-01T00:00:00Z\n\n"`; an unscanned model prints only the first four keys.

### 9.3 `versions <modelUuid>`, `version <uuid>`, `files <modelVersionUuid>` (`ms.ts:731-789`, `rms.ts:613-701`)

- versions: section `Model Versions:`, per version `ui.dim(uuid)`, `"    <revision>  <outcome or dim 'unscanned'>[  files: N]\n"` and an empty line after each; empty → `  No versions found`. Captured `"…\n\n\n  Model Versions:\n\n  <U(901)>\n    main  BLOCKED  files: 3\n\n  <U(902)>\n    v0  unscanned\n\n"`.
- version (`GET /aims/data/v1/model-versions/<uuid>`): section `Model Version Detail:`, keys `UUID`, `Model`, `Revision`, `Created`, `Updated`, then when present `File Count`, `License`, `Formats`, `Source Types`, `HF Model`, `HF Organization`, `Last Outcome`, `Last Scan`; section `Last Eval Summary:` with `Passed`, `Failed`, `Total`. Captured `"…  UUID             <U(901)>\n  Model            <U(801)>\n  Revision         main\n  Created          …\n  Updated          …\n  File Count       3\n  License          mit\n  Formats          pickle\n  Source Types     HUGGING_FACE\n  HF Model         model\n  HF Organization  org\n  Last Outcome     BLOCKED\n  Last Scan        2026-01-01T00:00:00Z\n\n  Last Eval Summary:\n\n  Passed  3\n  Failed  1\n  Total   4\n\n"`. HF commit sha, title and authors and the fingerprint are not shown.
- files: §8.6 layout (`renderModelFileList` → `renderFileList`), `Scanned Files:` heading.

## 10. `labels`

| Command | Request (captured) | Output | Notes |
|---|---|---|---|
| `add <scan> --labels <json>` | `POST /aims/data/v1/scans/<s>/labels` `{"labels":[…]}` | `  ✓ Labels added.` | merges by key on the stub; a key already present is overwritten |
| `set <scan> --labels <json>` | `PUT …/labels` `{"labels":[…]}` | `  ✓ Labels set.` | **replaces every label**: the stub's `env`, `team`, `new` became `only` alone (captured); no confirmation, no listing of what was dropped; `[]` is refused by the schema (`labels: too_small`) |
| `delete\|rm <scan> --keys <csv>` | `DELETE …/labels?keys=only&keys=nope` | `  ✓ Labels deleted.` | split on `,`, trimmed; `--keys ''` sends `?keys=`, `--keys ,` sends `?keys=&keys=`, both "succeed"; absent keys are not reported; no confirmation |
| `keys [--limit]` | `GET /aims/data/v1/scans/label-keys?limit=20` | section `Label Keys:`, `"  <key>\n"` each, `"\n"`; empty `  No label keys found` | tenant-wide |
| `values <key> [--limit]` | `GET …/label-keys/<encoded>/values?limit=20` | section `Label Values for "<key>":`, `"  <value>\n"` each; empty `  No values for key "<key>" found` | §2.8 traversal |

`--labels` is parsed with `JSON.parse` after the tenant (§2.5); a JSON object instead of an array gives `labels: invalid_type`, an empty key `labels.0.key: too_small`. Label values are on argv (process list, shell history). The acks print nothing about which scan or how many labels.

## 11. Table, JSON and dropped formats

### 11.1 Table (class A)

`formatOutput(…, 'table')` (`common.ts:126-139`, `ts-renderer.md` §2.3): header ` <label padEnd w> ` joined by `│`, rule `─`×(w+2) joined by `┼`, every cell followed by a space, widths in UTF-16 units, no indent, values `String(v)`, objects compact JSON, `null`/`undefined` empty; an empty list prints nothing. Lists project these columns (`rms.ts`):

| List | Columns (label ← field) |
|---|---|
| groups | `ID`←uuid, `Name`, `State`, `Source Type`←sourceType |
| rules | `ID`, `Name`, `Type`←ruleType, `Default State`←defaultState, `Sources`←compatibleSources joined `, ` |
| rule instances | `ID`, `Rule ID`←securityRuleUuid, `State` |
| scans | `ID`, `Outcome`←evalOutcome, `Origin`←scanOrigin, `Model URI`←modelUri, `Created`←createdAt |
| models | `ID`, `Name`, `Outcome`←latestVersionOutcome, `Formats`←latestVersionFormats joined `, `, `Last Scan`←latestVersionScanTime |
| model versions | `ID`, `Revision`, `Files`←fileCount, `Outcome`←lastEvalOutcome, `Last Scan`←latestScanTime |
| model files | `ID`, `Path`, `Type`, `Result` |

Captured: `" ID                                   │ Name          │ State   │ Source Type \n──────────────────────────────────────┼───────────────┼─────────┼─────────────\n 11111111-1111-4111-8111-000000000001 │ Default LOCAL │ ACTIVE  │ LOCAL       \n 11111111-1111-4111-8111-000000000002 │ Pending S3    │ PENDING │ S3          \n"`; scans `" ID                                   │ Outcome │ Origin             │ Model URI      │ Created              \n…\n 11111111-1111-4111-8111-000000000402 │ ALLOWED │ MODEL_SECURITY_API │                │ 2026-01-01T00:00:00Z \n"`.

Details print a `Key │ Value` table over every key of the §2.11 record in record order (camelCase keys, objects compact JSON, undefined empty). Captured `groups get --output table`: `" Key         │ Value                                \n─────────────┼──────────────────────────────────────\n uuid        │ 11111111-1111-4111-8111-000000000001 \n name        │ Default LOCAL                        \n description │ Auto group                           \n sourceType  │ LOCAL                                \n state       │ ACTIVE                               \n createdAt   │ 2026-01-01T00:00:00Z                 \n updatedAt   │ 2026-01-01T00:00:00Z                 \n"`; `rule-instances get` puts the whole snake_case rule into one 420-column cell (`rule │ {"uuid":…,"rule_type":"ARTIFACT",…}`); `models version` lists all 19 keys with empty cells for absent ones.

### 11.2 JSON (class A)

List: `JSON.stringify(rows, null, 2)` + `\n` of the §2.11 records; empty → `[]\n`. Detail: the record, 2-space indent. Captured `groups get --output json`: `"{\n  \"uuid\": \"11111111-1111-4111-8111-000000000001\",\n  \"name\": \"Default LOCAL\",\n  \"description\": \"Auto group\",\n  \"sourceType\": \"LOCAL\",\n  \"state\": \"ACTIVE\",\n  \"createdAt\": \"2026-01-01T00:00:00Z\",\n  \"updatedAt\": \"2026-01-01T00:00:00Z\"\n}\n"`; scans include `"evalSummary": null` when absent and `"labels": []`; models omit absent `latestVersion*` keys; versions print `"lastEvalSummary": null` when the server sent `null` and omit other absent keys; rule instances embed the snake_case `rule` (`modelsecurity-groupdetail-output.spec.ts:16-25,47-60`).

### 11.3 Unreachable structured branches

`renderEvaluationList|Detail`, `renderViolationList|Detail`, `renderFileList` (scans), `renderLabelKeys|Values` have no `--output` reaching them (class B), and every write passes no format, so their JSON/table branches (columns evaluations `ID, Rule, Result, State`; violations `ID, Rule, File, Threat`) are dead code in the CLI.

### 11.4 `markdown`, `csv`, `yaml` (TS only)

Accepted on class A (captured `groups list`: csv `"ID,Name,State,Source Type\n<U(1)>,Default LOCAL,ACTIVE,LOCAL\n…"`, markdown `"| ID | Name | State | Source Type |\n| --- | --- | --- | --- |\n…"`, yaml `"- uuid: …\n  createdAt: '2026-01-01T00:00:00Z'\n…"`; empty yaml `"[]\n\n"`). Settled: usage errors in Rust.

## 12. Sensitive-data exposure (TS)

| Where | What can leak |
|---|---|
| HTTP error text | non-problem error bodies verbatim (`API error 400: <body>`) and JSON `message`/`error_message` text, control characters included (§2.6) |
| `--config` / `--labels` JSON errors | an excerpt of the input (`Unexpected token …, "<input>" is not valid JSON`), file contents of group, rule-instance and scan configs |
| `--config` read | no regular-file check or size limit; `ENOENT` prints the path as typed; `/dev/stdin` or a FIFO is read |
| argv | `--labels` values, `--keys`, `--description`, `--name` |
| `--debug` file | request and response bodies (redacted only by key name; label keys masked, values kept; `pypi-auth` URL kept), URL queries (search terms, label keys), in the cwd (§2.10) |
| `PANW_AI_SEC_DEBUG_BODY=1` | bodies on stderr (not forced off for model-security) |
| stdout | model URIs (could carry userinfo or signed-URL queries; printed in list, get, table, json), label values, rule field values, file paths; all raw (no control-character filtering) |
| scans create | unknown keys of the config are forwarded to the service |

## 13. Doctor and tenant wording

- `doctor`'s management-credentials check names the product: `missing: <keys> — management, red team, model security, AI Gateway and AgentGuard commands are unavailable` (`doctor.ts:299`; already ported, `src/commands/doctor.rs:323`). No doctor check reads `modelSecDataEndpoint`/`modelSecMgmtEndpoint` or probes the planes.
- `tenant`: the two endpoint keys are ordinary config keys (`schema.ts:30-31`; DESIGN §3 rows 15–16); `modelSecTokenEndpoint` is retired (`schema.ts:68`). No other model-security wording, no scopes.

## 14. TS specs to port

| TS spec | Behaviour to port as executable tests |
|---|---|
| `tests/unit/airs/modelsecurity.spec.ts` (`:100-1000`) | per operation: the request built from options (group filters `:150-174`, rule-instance filters `:338-354`, rule filters `:445-455`, scan filters `:525-548` (minus `scan_origin`, §3.3), file filters `:729-739`, model list filters and omitted unset filters `:814-880`, version sort and pagination `:897-945`, version files `:964-1000`); normalised records and defaults (§2.11; `total` 0, empty arrays, null summary `:947-962`); create with rule configurations `:220-243`; rule-instance update body with `security_group_uuid` `:375-403`; labels add/set bodies and delete keys `:741-767`; label keys/values `:769-794`; `deleteGroupAndVerify` `:274-304` (confirmed when the re-read fails with not-found, not confirmed with the state when it still resolves, a failed delete propagates) |
| `tests/unit/cli/modelsecurity-groupdetail-output.spec.ts` | `groups get --output json` is the full record; pretty keeps `Security Group Detail`; list json is the bare array of complete records, `[]` when empty; columns `ID, Name, State, Source Type` (the yaml/markdown cases become usage-error tests) |
| `tests/unit/cli/aliases.spec.ts:66-86` | `ls` on `groups`, `rules`, `rule-instances`, `scans` (and `models`) lists; `rm` on `groups delete` and `labels delete` |
| `tests/unit/cli/help-examples.spec.ts:42` | `scans list --help` has an `Examples:` block with `$ airs-cli …` lines |
| `tests/unit/cli/completion.spec.ts:38,82` | `model-security` and `model-security scans` in completion scripts |
| `tests/unit/config/client-options.spec.ts:38,55,71,100-107,146-152` | shared OAuth credentials and `mgmtTokenEndpoint`; refusal without them; no option left for environment fallback (`PANW_*` ignored); `modelSecMgmtEndpoint`/`modelSecDataEndpoint` overrides and the SDK default bases |
| `tests/integration/*` | none exist for model security |

## 15. Rust SDK (`scm-sdk` 0.1.1) pointers

- Feature `model-security` (`Cargo.toml:66`, implies `models`) is not enabled yet in airs-cli. Every operation the port needs exists: groups `create`/`list`/`pages`/`list_all`/`get`/`update`/`delete`/`list_rule_instances`/`get_rule_instance`/`update_rule_instance` (`rs:airs/model_security/groups.rs:21-205`), rules `list`/`get` (`rs:airs/model_security/inventory.rs:263-339`), scans `create`/`list`/`pages`/`list_all`/`get`/`get_evaluations`/`get_files`/`add_labels`/`set_labels`/`delete_labels`/`get_violations`/`get_label_keys`/`get_label_values`/`get_evaluation`/`get_violation` (`rs:airs/model_security/scans.rs:107-392`), models `list_models`/`get_model`/`list_model_versions`/`get_model_version`/`list_model_version_files` with `*_pages`/`list_all_*` (`rs:airs/model_security/inventory.rs:22-241`), `get_pypi_auth` (`rs:airs/model_security/client.rs:74`).
- Gap: neither SDK can filter scans by origin (`ModelSecurityScanListOptions` has no `scan_origin`, `rs:airs/model_security/query.rs:62-76`; TS `SDK:13622-13638`). The CLI cannot send it without patching the SDK; see open question 6.
- `limit == 0` and values above 2^53 are refused before sending (`rs:airs/model_security/query.rs:33-40`); label key segments are validated (§2.8); `delete_labels` accepts empty keys (`rs:airs/model_security/scans.rs:288-308`), so the CLI must refuse them.
- G10 (§2.11): pass `RequestOptions::without_response_defaults()` (`rs:config.rs:406`) on `scans list/get/create`, the walk pages, and `models versions/version` (the `EvalSummary` holders); doing it on every model-security read is harmless. Whether the Rust SDK applies the request-side `description: ""` default on group create must be checked (TS sends it).

## 16. Live-tier notes

- New groups come back `PENDING`; deletion is soft and asynchronous (`deleteGroupAndVerify` exists because a deleted group can still read `ACTIVE`, prisma-airs-cli#239). The sweeper and ledger must treat "DELETE accepted" plus a later 404, `is_tombstone: true` or absence from listings as cleaned, and must not re-send a delete in a loop.
- Default groups (`Default LOCAL`, `Default S3`, …, docs-site) always exist; the read comparison's "first listed item" is one of them. Rule instances in a new group are created by the service (unverified); the write flow should list them first and update one it then restores.
- TS reads to compare must use class-A JSON where both CLIs agree (§11.2 records differ from wire objects; the Rust port must keep TS's projection or the comparison must project). TS lists without `--limit` fetch 20 (`models` the server default).
- `labels set` replaces all labels and `labels delete` takes keys: run them only on the run's own scan (settled), and compare `scans get` labels before and after.
- `scans create` is billed and TS re-sends it on 5xx/timeouts; the TS side must never run it live under a fault (the live tier has no faults, but a real 5xx would duplicate the scan).

## Acceptance criteria

Each is a loopback executable test of airs-cli-rs; parity tests compare both CLIs where the behaviour is shared.

1. Every model-security command uses only the selected tenant's `mgmt*` credentials, `mgmtTokenEndpoint`, `modelSecMgmtEndpoint` (groups, rule instances, rules) and `modelSecDataEndpoint` (scans, evaluations, violations, files, labels, models), with the SDK default bases, and ignores `PANW_*` variables; tenant files are unchanged.
2. Requests match §3.3 and §5–§10 (method, path, query keys and repetition, bodies of §2.7); `--scan-origin` follows the §12 decision (open question 6), `--search` means one thing with and without `--all`.
3. Pretty layouts match §5–§10 byte for byte (sections, key padding, state colours of §4, empty-list phrases, the models/versions blank lines) on stdout, except where a §12 row changes them; the banner is printed only for pretty output and never before argument checks fail.
4. `--output pretty|table|json` is honoured on every read that has it in TS (class A), and on class B and C commands per the §12 decision; `markdown`, `csv`, `yaml` and unknown values are usage errors (exit 2) before the tenant is read.
5. Table and JSON output match §11.1–§11.2 (column sets, `Key │ Value` details, the §2.11 records with their key order, `[]` for empty lists); no fabricated `0` summary or invented `''`/`[]` is printed where the server sent nothing (G10 and the §12 decision on normaliser defaults).
6. List flag errors (`--limit 0|abc|1.5|-1|>max`, `--offset -1|abc`, `--max abc`, `--all` with `--offset`, `--all`/`--offset`/`--max` on `rule-instances list` per the §12 decision) are usage errors before the tenant (exit 2); `--all` walks under `--max` and never reports a capped or partial walk as complete.
7. `--start`/`--end`/`--model-version` are checked before the tenant (exit 2, the TS message); UUID positionals are checked before the tenant with a fixed message (exit 2); `labels values` refuses `''`, `.`, `..` and control characters.
8. `--config` and `--labels` inputs are checked before the tenant (regular file, size cap, UTF-8, one JSON object or array as required, required fields), and no error echoes their content.
9. Every write is sent once (one replay after a 401, none after a 403); a 5xx, transport failure or deadline after dispatch prints the outcome-unknown line naming the action (`the security group may have been created`, `the scan may have been created`, `the labels may have been replaced`, …) and exits 1.
10. `groups delete`, `labels delete` and `labels set` confirm per D81 (`--force` skips; no TTY and no `--force` is a usage error before the tenant; declining or Ctrl-C at the prompt changes nothing); `groups delete` reports deleted only when the re-read returns not-found (or a tombstone, per the §12 decision), "accepted, still present" when it resolves, and outcome-unknown when the re-read fails otherwise.
11. Acknowledgements and the delete outcome go to stderr (quiet-suppressed success lines; warnings kept), stdout carries only data (the record in json/table), and `--quiet` never removes identifiers from pretty data lines.
12. Server text (names, descriptions, URIs, paths, labels, threats, remediation, error messages) goes through `terminal_safe`; error text is built from SDK metadata only (§6), never from raw bodies.
13. `--debug` records method, path, status and headers only, never bodies or query values beyond the paging keys.
14. SIGINT/SIGTERM during a write exits 130/143 with the `Interrupted; …` line saying the change may have been applied.

## Open questions / likely §12 divergences

Numbers are assigned by the orchestrator from D179. Each is a safety or correctness fix.

1. **Write replay (safety).** TS re-sends group create/update/delete, rule-instance update, scan create (billed) and label writes up to 5 times on 5xx, timeouts and transport errors (§2.6: 4 group POSTs, 3 scan POSTs, 6 DELETEs captured). Rust: D95 (one attempt, one 401 replay, no 403 replay) with outcome-unknown lines.
2. **Confirmations (safety).** No TS command confirms. Settled for Rust: `groups delete` and `labels delete` follow D81; `labels set` is replace-style (drops every label not listed, §10) and confirms too. Choice to decide: whether `rule-instances update` confirms (it can disable a blocking rule; recommendation: no, it names one instance and the change is reversible, but print the old and new state), and whether `labels set` lists the labels it will drop in the prompt (recommendation: yes, after a `scans get` read).
3. **Delete verification (correctness/safety).** TS prints `Group <uuid> deleted.` when the follow-up GET fails for any reason (500, 401, network, captured) and ignores `is_tombstone`. Rust: deleted only on a not-found re-read or `is_tombstone: true` (choice), "accepted; still reports state …" when it resolves, an outcome line (`the deletion could not be confirmed`) on any other failure.
4. **Ignored paging flags (correctness).** `rule-instances list` advertises `--offset/--all/--max` but ignores them (truncated listings); `--all` drops `--offset` everywhere. Rust: honour them on `rule-instances list` (the Rust SDK has `list_rule_instances` with `skip`/`limit` but no `pages` helper, `rs:airs/model_security/groups.rs:143`, so the CLI walks `skip` itself), and make `--all --offset` a usage error (D-row as DLP/red team). Choice: give class-B lists and `models versions|files` `--offset/--all/--max` (recommendation: yes for parity of the read contract; at minimum print a "more available" hint).
5. **List flag parsing (correctness).** `limit=NaN`, `skip=NaN`, `limit=0`, negative `skip` are sent; `--max abc` fails after the tenant with exit 1 (§3.1). Rust: §7.1 messages, exit 2, before the tenant; `limit` range 1..(server maximum; choice: 100 like custom rules, or no upper bound).
6. **`--scan-origin` (correctness, SDK gap).** Silently dropped by both SDKs. Options: (a) keep the flag and refuse it with a usage error naming the gap; (b) drop the flag (clap rejects it); (c) filter client-side after fetching (wrong with paging). Recommendation (a) until the SDK supports it; record as an SDK gap.
7. **`--search` meaning (correctness).** `search` without `--all`, `search_query` with `--all`. Rust sends one parameter for both (choice: `search`, which matches the non-`--all` TS default and the flag help).
8. **Output formats on class B and C (correctness, choice).** TS ignores `--output` there. Recommendation: honour `pretty|table|json` on every model-security command (DESIGN D94 precedent), with writes printing the response record in json/table; the evaluations/violations/files/labels renderers' TS columns exist (§11.3).
9. **Quiet removes identifiers (correctness).** Pretty list ids, the remediation URL and the delete hint use `ui.dim` and vanish under `--quiet` (§2.3). Rust: data lines always print.
10. **Banner before validation (correctness).** Classes B/C print the banner before the tenant and argument checks, and errors leave it on stdout. Rust: validation first; banner only on success paths with pretty output (as other Rust ports).
11. **Fabricated values (correctness, G10 + CLI).** The SDK's `EvalSummary` defaults and the normalisers' `''`, `0`, `[]` (§2.11) print invented data (a pending scan as `0 passed 0 failed / 0 total`, files with `formats: []`). Rust: `without_response_defaults()`; absent fields stay absent (`null`/omitted in json, line omitted in pretty). Choice: whether json keeps TS's projection (recommended, for the read comparison) but with absent values omitted.
12. **Custom-rule instances (correctness).** `undefined` as the rule name, the custom rule dropped from json (§7.1). Rust: show `custom_rule.name` (else the custom rule uuid) and keep `customRuleUuid`/`customRule` in json.
13. **Raw nested rule in json/table (correctness, choice).** `rule-instances` json embeds the snake_case rule; Rust: camelCase it like the top level (recommended) or keep it raw for parity.
14. **Empty or no-op writes (correctness).** `groups update` with no flags sends `{}` and reports success; `--description ''` cannot clear; `rule-instances update` with `{}` sends a no-op PUT; `labels delete --keys ''`/`,` sends empty keys. Rust: usage errors (at least one change; empty keys refused); choice: allow `--description ''` to clear (send `""`).
15. **Config files (safety).** `scans create` forwards the whole file (unknown keys sent); `groups create`/`rule-instances update` silently drop unknown keys, and a `security_group_uuid` in the rule-instance file is ignored. Rust: refuse unknown keys with a fixed message naming the key (not its value), refuse a file `security_group_uuid` that differs from the positional; D103-style file rules before the tenant; errors never quote content.
16. **Error text from bodies (safety).** TS prints non-problem error bodies and server `message` text raw (§2.6). Rust: §6 (SDK error metadata only), through `terminal_safe`.
17. **Terminal safety (safety).** All printed server text through `terminal_safe` (`terminal_safe_lines` for descriptions and remediation steps).
18. **Path traversal in `labels values` (safety).** `..` reaches `/v1/scans/values` (§2.8). Rust: usage error before the tenant (the SDK refuses it anyway).
19. **Stdout acks and warnings (correctness).** `✓ Group created: …`, `✓ Labels set.`, the soft-delete `⚠` warning are on stdout. Rust: stderr (D94/D106 precedent), data on stdout only.
20. **`--debug` and body logging (safety, settled).** TS records model-security bodies in the debug file (label values, configs, the PyPI URL) and lets `PANW_AI_SEC_DEBUG_BODY=1` print them. Rust: status and headers only.
21. **Model URIs (safety, choice).** `model_uri` may contain userinfo or a signed query (S3/GCS/Azure/Artifactory URIs). Options: (a) print as sent (parity); (b) withhold userinfo and query values in pretty/table/json (`https://***@host/path?…`), as D139/D140 do for credentials. Recommendation (b) for userinfo and query values, keeping scheme, host and path.
22. **Interruption (correctness).** TS exits silently on SIGINT/SIGTERM; Rust prints the §13.2 `Interrupted; …` context (the write may have been applied).
23. **Help texts.** `MALICIOUS` in the `scans list` example is not a valid outcome (choice: replace with `BLOCKED`); format lists change; the docs-site pretty examples (`UUID:` with colons) are stale and are not a contract.
