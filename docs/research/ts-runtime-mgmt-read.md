# Spec: TS `airs-cli` read-only runtime management — `runtime profiles list|get`, `runtime topics list|get`

## 0. Sources and method

- CLI source: `/Users/cdot/development/redtail/prisma-airs-cli/src/**` (v7.2.1-forgejo.0, `package.json:4`). Pins `@cdot65/prisma-airs-sdk` 0.34.0 (`package.json:68`; lockfile integrity `pnpm-lock.yaml:170-171`) and `commander ^14.0.3`.
- The Rust project already has a gitignored, runnable TS baseline at `/Users/cdot/development/redtail/prisma-airs-cli-rs/.reference/prisma-airs-cli/`. It contains a built `dist/cli/index.js` (the `bin` from `package.json`) and `node_modules`. Its `src/` is byte-identical to the original repo (`diff -rq` is empty). It installs SDK 0.34.0 and commander 14.0.3. SDK citations below are `SDK:<line>` in `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js`.
  - The frozen contract tree under `scm-sdk-rs/contracts/sources/typescript/src` only contains `models/`, so the bundled dist was the only source for client code.
  - A second 0.34.0 copy under `~/.cache/airs-permissions-*/` differs only in dashboard, red-team and AgentGuard schemas, not in the code cited here.
- Behaviour was checked two ways:
  - by reading the code;
  - by running the reference build against a loopback-only fixture (`127.0.0.1`) in the scratchpad, with fake credentials, `env -i`, an isolated `HOME`, `PRISMA_AIRS_TENANTS_PATH` pointing at a scratch registry, and `NO_COLOR=1`.
- No real tenant or credential file was read, and no external host was contacted. Probe tooling: `/private/tmp/claude-501/-Users-cdot-development-redtail-prisma-airs-cli-rs/2663a1f5-b86a-45e5-9990-00ce664767e6/scratchpad/fixture/server.mjs` and `.../scratchpad/fixture/probe.sh`.

## 1. Command surface (exact help, verified)

Registration:
- `runtime profiles list`: `src/cli/commands/runtime.ts:611-654`
- `runtime profiles get`: `runtime.ts:656-690`
- `runtime topics get`: `runtime.ts:1133-1167`
- `runtime topics list`: `runtime.ts:1169-1205`

Pagination flags come from `registerListFlags(..., {dialect:'offset'})` (`src/cli/pagination.ts:20-30`).

```
Usage: airs-cli runtime profiles list|ls [options]

List security profiles

Options:
  --all              Walk all pages
  --all-versions     Include every profile revision
  -h, --help         display help for command
  --limit <n>        Items per page (default: 100) (default: 100)
  --max <n>          Maximum items with --all; 0 removes the cap (default:
                     10000)
  --offset <n>       Item offset (default: 0) (default: 0)
  --output <format>  Output format: pretty, table, markdown, csv, json, yaml

Examples:
  $ airs-cli runtime profiles list
  $ airs-cli runtime profiles list --output json
  $ airs-cli runtime profiles list --limit 20 --offset 20
```

- `runtime topics list|ls`: the same option set, with the description `List custom topics` and `--all-versions  Include every topic revision`. It has no Examples block.
- `runtime profiles get [options] <nameOrId>`: description `Get a security profile by name or UUID`. Options are `--all-versions  Return every matching revision`, `-h, --help`, `--output <format>` and `--revision <n>  Select an exact revision`.
- `runtime topics get [options] <nameOrId>`: description `Get a custom topic by name or UUID`, with the same options.

Help notes:
- The duplicated `(default: 100) (default: 100)` is a real bug: commander appends the default to a description that already contains it.
- Help is sorted (`program.ts:73-76`).
- Hints show `airs cli` instead of `airs-cli` only when `AIRS_CLI_INVOKED_AS='airs cli'` (`invocation.ts:2-9`).

### Flags and parsing

| Flag | Applies to | Parser / default | Validation (`pagination.ts:32-56`) |
|---|---|---|---|
| `--limit <n>` | both lists | `Number`, default 100 (`DEFAULT_OFFSET_LIMIT`, `pagination.ts:7`) | `Number.isSafeInteger && >=1`, else usage error `--limit must be a positive integer` |
| `--offset <n>` | both lists | `Number`, default 0 | `>=0` safe integer, else `--offset must be a non-negative integer` |
| `--all` | both lists | boolean | `--all` plus an `--offset` given on the CLI (even `--offset 0`) gives `--all cannot be combined with --offset` (`pagination.ts:52-54`) |
| `--max <n>` | both lists | `Number`, default 10000 (`DEFAULT_MAX_ITEMS`) | `>=0` safe integer, else `--max must be a non-negative integer`; validated even without `--all` |
| `--all-versions` | all four | boolean | — |
| `--revision <n>` | both gets | `Number`, **no validation** | `abc` becomes `NaN`, which matches nothing and produces a not-found error (exit 1) |
| `--output <format>` | all four (also global) | — | see §2 |

- Values go through JS `Number()`, so `--limit 0x2`, `--limit 1e2` and `--limit " 5"` are accepted (verified: `--limit 0x2` was accepted).
- `--limit` has no upper bound.
- **No deprecated aliases** exist on these four commands. `--page`/`--size` give `error: unknown option '--page'` with exit 1. `registerPageAliases` is used only by `scan-logs query` and the DLP lists.
- **Command aliases:** every `list` subcommand gets `ls`, applied after registration (`program.ts:42-51`, tested in `tests/unit/cli/aliases.spec.ts:28-73`). There is no `get` alias.
- **Global options** (`program.ts:107-109`): `--debug`, `--output <format>`, `--quiet`, plus `-V/--version`.
  - The program does not call `enablePositionalOptions()`, so commander's root parser consumes `--output X`, `--output=X`, `--quiet` and `--debug` **anywhere** on the line. This includes after the subcommand: the root's `parseOptions` matches known options before its unknown-option fallthrough.
  - As a result, the subcommand's own `--output` never has source `cli`. Repeated `--output` values follow last-wins. `airs-cli --output json runtime profiles get alpha` and `... get alpha --output json` behave identically (verified).

## 2. Execution pipeline (order matters for exit codes)

1. **commander parse** (exit 1, `error: ...` on stderr):
   - unknown option: `error: unknown option '--bogus'`
   - missing argument: `error: missing required argument 'nameOrId'`
   - excess arguments: `error: too many arguments for 'list'. Expected 0 arguments but got 1.` and `... for 'get'. Expected 1 argument but got 2.`
   - unknown subcommand: `error: unknown command 'bogus'`
   - a bare group (`runtime profiles`) prints its help on stderr and exits 1.
   - Commander's default exit code is 1, and the program installs no `exitOverride` (verified for all of these).
2. **preAction hook** (`program.ts:111-175`):
   - Sets quiet mode.
   - Because `list`/`get` are in `READ_COMMAND_NAMES` (`program.ts:18-39`), it calls `resolveOutput` (`renderer/common.ts:48-75`).
   - `resolveOutput` calls **`loadConfig()` first** (`common.ts:60`), so any tenant problem exits 1 before flags are validated.
   - The resolved format is stored with source `implied`.
3. **Tenant/config load** (`config/loader.ts:84-92`):
   - The registry comes from `PRISMA_AIRS_TENANTS_PATH`, else `$XDG_STATE_HOME/prisma-airs/tenants.json`, else `~/.local/state/prisma-airs/tenants.json` (`config/tenants.ts:34-40`).
   - Errors (exit 1, through `fail`):
     - `No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'`, or `No tenant selected. Run 'airs-cli tenant switch <name>' (registered: a, b)` (`loader.ts:39-45`)
     - `Cannot read tenant registry at <path>; restore a valid registry before proceeding`
     - `Cannot read a valid tenant config at <path>` (also raised for schema-invalid values such as `defaultOutput:"xml"`)
     - `Tenant config TSG differs from its registered identity; register it under a new name` (`tenants.ts:90-93`)
   - All of these were verified.
4. **Output format** (`common.ts:53-74`):
   - The value is the explicit `--output`, else the tenant `defaultOutput`, else `pretty`.
   - An invalid value gives usage error `Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml` (exit 2).
   - With no tenant, the same invalid value exits **1** (`No tenant selected`), because config loads first. The same applies to `--limit 0` (verified).
5. The action calls `resolveOutput` again, then `resolveListParams` for lists only (usage errors, exit 2).
6. In `pretty` mode only, the banner goes to stdout (`renderRuntimeConfigHeader`, `renderer/runtime.ts:74-76`).
   - For `get`, the banner is printed **before** service creation. For lists, it comes after list-param validation.
   - On a later failure in pretty mode, stdout already holds the banner.
7. `createMgmtService()` (`runtime.ts:175-178`):
   - Calls `loadConfig()` again, then `managementClientOptions` (`config/client-options.ts:34-51`).
   - `assertManagementCredentials` (`config/credentials.ts:54-63`) can throw `Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set dev <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)` (exit 1, verified).
   - Credential errors come **after** flag validation: `--all --offset 3` with missing credentials exits 2.
8. SDK calls (§3), then rendering (§8), then exit 0.

Credential isolation:
- `managementClientOptions` passes explicit `clientId`, `clientSecret`, `tsgId`, `tokenEndpoint` (`mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`) and `apiEndpoint` (`mgmtEndpoint ?? DEFAULT_MGMT_ENDPOINT`). The SDK's `PANW_MGMT_*` fallbacks (`SDK:11099-11160`, `ManagementClient` `SDK:13407+`) are therefore never consulted. Verified with `PANW_MGMT_CLIENT_SECRET` set: it was ignored.
- `numRetries` is **not** passed, so the SDK default `MAX_NUMBER_OF_RETRIES = 5` applies (`SDK:30`).
- The service is a process singleton (`management.ts:543-554`).
- The SDK **does** read non-credential environment variables:
  - `PANW_AI_SEC_TIMEOUT_MS`: per-attempt timeout, default 60000 (`SDK:10095`)
  - `PANW_AI_SEC_DEBUG` / `PANW_AI_SEC_DEBUG_BODY`: `[airs-sdk] → ...` stderr logging (`SDK:10000`, `logRequest`)

## 3. HTTP layer (SDK-owned behaviour)

Defaults: `DEFAULT_MGMT_ENDPOINT = https://api.apps.paloaltonetworks.com/aisec` and `DEFAULT_TOKEN_ENDPOINT = https://auth.apps.paloaltonetworks.com/oauth2/access_token` (`SDK:34-35`). Paths are `/v1/mgmt/profiles/tsg/{tsgId}` and `/v1/mgmt/topics/tsg/{tsgId}` (`SDK:46,48`). Trailing slashes are stripped from the base URL (`SDK:~10120`).

**OAuth** (`OAuthClient.fetchToken`, `SDK:11017+`). There is exactly one token POST per process, cached in memory and refreshed 30 s before expiry. Verified wire shape:

```
POST <mgmtTokenEndpoint>
Authorization: Basic base64("<mgmtClientId>:<mgmtClientSecret>")
Content-Type: application/x-www-form-urlencoded
User-Agent: node            (undici default, NOT the SDK UA)
body: grant_type=client_credentials&scope=tsg_id%3A<mgmtTsgId>
```

The response must match `{access_token: non-empty string, expires_in: number>=0, token_type?, scope?}` (passthrough).

Token errors (no retry; 30 s deadline):

| Condition | Message |
|---|---|
| network failure | `AISEC_OAUTH_ERROR:Token request failed: <err.message>` (e.g. `fetch failed`, no HTTP line) |
| non-2xx | `AISEC_OAUTH_ERROR:<error_description ?? error ?? "Token request failed with status N">` with statusCode N |
| invalid JSON | `AISEC_OAUTH_ERROR:Token response is not valid JSON` |
| schema miss | `AISEC_OAUTH_ERROR:Token response did not match the OAuth schema` |
| timeout | `AISEC_OAUTH_ERROR:Token request timed out` |

**Data requests** (`request`, `SDK:10094+`; verified headers):
- `GET <mgmtEndpoint>/v1/mgmt/profiles/tsg/<tsg>?offset=<o>&limit=<l>[&latest=<true|false>]`. The query order is always offset, limit, latest, and the values are strings.
- Headers:
  - `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`
  - `service-name: api`
  - `Authorization: Bearer <access_token>`
  - undici defaults: `accept: */*`, `accept-language: *`, `sec-fetch-mode: cors`, `accept-encoding: gzip, deflate`
- No Content-Type and no body.

**Retry and auth refresh** (`executeWithRetry`, `SDK:9786+`; `OAuthAuth.onUnauthorized`, `SDK:10865`):
- **500/502/503/504** are retried up to 5 times (6 attempts in total; verified). The delay is `Retry-After` in seconds or an HTTP-date, capped at 60 s; otherwise a random value in `[0, 2^attempt*1000]` ms. Fixtures should send `Retry-After: 0`.
- Network errors are retried with the same backoff, up to about 31 s worst case. After the last attempt they become `AISEC_CLIENT_SIDE_ERROR:<message>`.
- **401, or 403 without `x-opa-decision: false`:** the token is cleared, a new POST token is made, and the request is retried once without consuming a retry. Verified sequence: token, 401, token, success.
- **403 with `x-opa-decision: false`:** no refresh. The result is `AISEC_CLIENT_SIDE_ERROR:<msg>` with `HTTP 403` (verified).
- **429 is not retried.**

**Error message** (`extractErrorMessage`, `SDK:9713-9725`):
- Prefix: `AISEC_SERVER_SIDE_ERROR:` when status >= 500, else `AISEC_CLIENT_SIDE_ERROR:` (`SDK:9710`).
- **Problem-details body** (has `title`/`detail`/`errors`): `API error <s>; <title>; <detail>`, with non-allowlisted text replaced by `[withheld]` (`SDK:9643-9684`). Verified: `AISEC_CLIENT_SIDE_ERROR:API error 400; Bad Request; [withheld]`.
- **Other JSON body:** the first present of `error_message`, `message`, `data.message`, `error.message`, `msg`, else `API error <s>`. A ` (errorCode: X)` suffix is added when `data.errorCode` exists.
- **Non-JSON body:** `API error <s>: <raw body>` (the body is echoed verbatim), or `API error <s>` when the body is empty.
- **Response validation** (zod `safeParse`): `AISEC_RESPONSE_VALIDATION:Response did not match schema: <path>: <code>; ...` (verified: `ai_profiles.0.profile_name: invalid_type; next_offset: invalid_type`). Invalid JSON gives `AISEC_RESPONSE_VALIDATION:Response body is not valid JSON`.

**Pagination helpers** (`SDK:10790-10812`):
- `paginate` stops when `next` is `undefined`; the callers map `next_offset || undefined`, so **`0` or absent ends the walk**. A repeated cursor throws a plain `Error('Pagination returned a repeated cursor')`, rendered as `✗ Error: Pagination returned a repeated cursor` (verified).
- `collectAll` uses `max = opts.max ?? 10000`, validated as a non-negative safe integer. It **silently stops** once `items.length >= max` (when max > 0) and fetches no further pages (verified: `--all --max 2 --limit 1` made 2 requests). `max: 0` means unbounded.
- An endless sequence of empty pages with increasing cursors never terminates; there is no page cap.

**Response schemas** (zod v3 `.passthrough()`, `SDK:1957-2030`):
- `SecurityProfileListResponseSchema = {ai_profiles: SecurityProfile[] (default []), next_offset?: number}`
- `SecurityProfile`: `profile_name: string` is **required**; `profile_id`, `csp_id`, `tsg_id`, `revision` (number), `active` (bool), `policy` (PolicySchema), `created_by`, `updated_by`, `last_modified_ts` (string) are optional.
- `CustomTopicListResponseSchema = {custom_topics: CustomTopic[] (default []), next_offset?: number}`
- `CustomTopic`: **required** `topic_name: string`, `revision: number`, `description: string`. `examples: string[]` defaults to `[]`. `topic_id`, `active`, `created_by`, `updated_by`, `last_modified_ts`, `created_ts` are optional.
- Optional means absent: **`null` is rejected** for these fields and for `next_offset`.
- The nested policy schemas are strict in places: `latency.max-inline-latency` must be an int; `topic-list[].topic[]` needs `topic_name`, `topic_id` and an integer `revision`.
- **zod reorders keys:** keys known to the schema come out in schema order, then unknown keys in input order. Inside plain JS objects, integer-like keys sort first. Verified: input `{custom, dlp-data-profiles, ai-security-profiles}` was output as `ai-security-profiles, dlp-data-profiles, custom`; `latency{max-inline-latency, inline-timeout-action}` came out as `inline-timeout-action, max-inline-latency`; `{b,a,"10","2"}` came out as `"2","10",b,a`.

## 4. `runtime profiles list` (`runtime.ts:611-654`; `management.ts:266-283`; `SDK:11265-11297`)

- **Default (single page):** `listProfiles({limit, offset, latest: !allVersions})` calls `GET ...profiles/tsg/<tsg>?offset=<offset>&limit=<limit>&latest=true`, or `latest=false` with `--all-versions`. **The server collapses revisions; the CLI does not.**
  - Output: the normalized `ai_profiles`.
  - Status: `nextOffset = response.next_offset` (raw), giving `page = {returned, next}`.
  - Stderr: `  Showing <n> (more available)` whenever `next_offset` is present, **including `0`**; otherwise `  Showing <n>`. The next offset value itself is never printed. Verified, including `[]` with `next_offset: 0` giving `Showing 0 (more available)`.
- **`--all`:** `listAllProfiles({limit, latest: !allVersions, max})` walks pages with `offset=0, then next_offset, ...`, each with `limit=<--limit>&latest=...`, capped by `--max` (0 = unlimited).
  - Stderr: `  Showing all <n>`, even when the walk was truncated by `--max`. There is no warning and the exit code is 0.
- `--max` is ignored without `--all`.

## 5. `runtime profiles get <nameOrId>` (`runtime.ts:656-690`; `management.ts:256-264`; `SDK:11314-11350`)

- **UUID detection:** `/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i`. The input is never lowercased, and later comparisons are exact.
- **Without `--revision`/`--all-versions`:**
  - UUID: `SDK profiles.get(id)` calls `listAll()` (limit 100, **no `latest` param**, max 10000) and returns the first record with `profile_id === id`.
  - Name: `profiles.getByName(name)` makes the same requests and returns the highest `(revision ?? 0)`; on a tie the first one seen wins.
  - Not found: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: <input>`, exit 1, no HTTP line (verified for both).
  - There is no dedicated GET-by-id endpoint.
- **With `--revision N` and/or `--all-versions`:**
  - `listAllProfiles({latest:false})` requests `?offset=0&limit=100&latest=false` and follows pages (max 10000).
  - It filters by `profileId === input` (UUID) or `profileName === input`, then by `revision === N` when `--revision` is given.
  - Empty result: `Profile <input> not found` (no prefix, no quotes).
  - `--all-versions` emits a **list** (JSON array, no paging status line), and with `--revision` that list is filtered. Otherwise the output is the detail of `selected[0]`, the first one in API order.
- Requests per run: one token POST, then one or more list GETs.

## 6. `runtime topics list` (`runtime.ts:1169-1205`; `management.ts:55-66`; `SDK:11524-11570`)

- **Default (latest only):** `listLatestTopics({offset, limit})` calls SDK `topics.list({latestOnly:true, offset, limit})`.
  - It fetches **all pages with `limit=200`**: `GET ...topics/tsg/<tsg>?offset=0&limit=200`, then the next offsets. There is no `latest` param. The walk is silently capped at 10,000 raw records.
  - It collapses by `topic_name` to the highest revision, keeping first-seen name order and first-seen ties (JS `Map`).
  - It slices `[offset, offset+limit)` client-side.
  - **`--limit`/`--offset` never reach the wire.** The SDK's computed `next_offset` is discarded by the CLI, so stderr is always `  Showing <n>`, even when more topics exist (verified with `--limit 1` against 2 latest topics).
- **`--all` (latest):** `listLatestTopics({offset:0, limit: max===0 ? 10000 : max})` makes the same 200-per-page walk, then slices to `max`. Stderr: `  Showing all <n>`.
  - `--max 0` therefore still caps at 10,000.
  - `--limit` is ignored.
- **`--all-versions`:** `listTopics()` calls SDK `topics.listAll()` with **`limit=100`** pages (offset 0, then next_offset), max 10000, regardless of `--limit` and `--max`.
  - Without `--all`, it slices client-side. Stderr: `  Showing <n> of <total> (next --offset <offset+limit>)` when `offset+limit < total`, else `  Showing <n> of <total>` (verified: `Showing 1 of 3 (next --offset 2)`).
  - With `--all`, the result is everything and stderr is `  Showing all <n>`.
- Status text comes from `renderPageStatus` (`renderer/view.ts:32-41`), which writes to stderr through `ui.status` (`ui.ts:131-135`, suppressed by `--quiet`).

## 7. `runtime topics get <nameOrId>` (`runtime.ts:1133-1167`; `management.ts:68-80`)

All paths use the CLI's own `listTopics()`, which calls SDK `topics.listAll()` (`?offset=0&limit=100`, paged, max 10000).

| Input and flags | Selection | Not-found message (exit 1) |
|---|---|---|
| UUID, no flags | first record with `topic_id === id` (an exact revision) | `Topic <uuid> not found` |
| name, no flags | highest `revision`; ties keep the first one seen | `Topic "<name>" not found` (quoted) |
| `--revision N` and/or `--all-versions` | filter by `topic_id`/`topic_name`, then by `revision === N` | `Topic <input> not found` (unquoted) |

`--all-versions` emits a list with no status line. Not-found errors are plain `Error`s with no AISEC prefix. All three forms were verified.

## 8. Output

Data goes to stdout through `console.log`, so there is a trailing `\n`. Status lines and errors go to stderr.

**JSON list = bare array; JSON detail = bare object.** `JSON.stringify(x, null, 2)` (`common.ts:109`, `view.ts:69`). There is no envelope and no pagination metadata. An empty list prints `[]`. `undefined` fields are omitted.

**Profiles:** the CLI-normalized record (`management.ts:243-254`), in this key order: `profileId, profileName, revision, active, createdBy, updatedBy, lastModifiedTs, policy`.
- Passthrough extras (`csp_id`, `tsg_id`, unknown fields) are **dropped**.
- `policy` is emitted as zod parsed it (reordered as described in §3).
- Numbers keep their JS form: `2` (never `2.0`), and `2.5` stays `2.5`.
- Example (verified):

```json
{
  "profileId": "00000000-0000-4000-8000-000000000002",
  "profileName": "alpha",
  "revision": 2,
  "active": true,
  "lastModifiedTs": "2026-02-01T00:00:00Z",
  "policy": {}
}
```

**Topics:** the `topicsView.structured` mapping (`renderer/views/runtime.ts:64-75`), in this key order: `topicId, topicName, revision, active, description, examples, createdBy, updatedBy, lastModifiedTs, createdTs`. It is the same for list and detail.
- `examples` is always present (zod default `[]`); `description` and `revision` are always present.
- `csp_id` and `tsg_id` are dropped.
- Example (verified):

```json
{
  "topicId": "00000000-0000-4000-8000-000000000011",
  "topicName": "fin",
  "revision": 1,
  "active": true,
  "description": "old",
  "examples": ["e1"],
  "createdBy": "a@example.com",
  "lastModifiedTs": "2026-01-01T00:00:00Z",
  "createdTs": "2025-12-01T00:00:00Z"
}
```

(The real output puts `examples` on multiple lines with 2-space indentation.) Non-ASCII text and U+2028 pass through unescaped; `\n` and `"` are escaped.

Other formats (secondary):
- **List** `table`/`csv`/`markdown` (`view.ts:43-61`, `common.ts:96-143`) project the view columns:
  - profiles: `ID, Name, Active, Revision`, from `profileId, profileName, active, revision`; `active` renders as `true`/`false`
  - topics: `ID, Name, Revision, Description`
  - CSV quotes cells containing `" , \r \n`.
- **Detail** in these formats is a `Key | Value` table of the structured record (objects are JSON-stringified; undefined shows as empty).
- **YAML:** js-yaml `dump(..., {noRefs:true, lineWidth:-1})`. Lists are a sequence, nested policy is block YAML, and timestamps are quoted. An empty list prints `[]` followed by a blank line.
- **pretty:** the banner is `\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n`.
  - List: `\n  Security Profiles:\n\n`, then per item `  <id>` and `    <name>  active|inactive rev:<n>`, then a blank line. Topics show `    <name> rev:<n> — <desc[0..80]>`.
  - Empty list: `  No profiles found` / `  No topics found` on **stdout**.
  - Detail: aligned key/value pairs without colons (`ID`, `Name`, `Status`, `Revision`, `Created`, `Updated`, `Modified`, `Policy` with indented JSON). Topics also print `  Examples:` with `  • <ex>` bullets.

## 9. Errors and exit codes

- `fail(err)` (`common.ts:12-25`) writes to stderr: `\n  ✗ Error: <message>\n`, then, when `err.status ?? err.statusCode` exists, `    HTTP <code>\n    Re-run with --debug to capture redacted API diagnostics.\n`, then `\n`. Exit 1.
- `CliUsageError` goes to `usageError` (`common.ts:27-30`): `\n  ✗ <message>\n\n`, exit 2.
- Commander errors exit 1. Success exits 0.
- Colours (chalk) are disabled by `NO_COLOR` or a non-TTY stdout.
- Verified examples:
  - `\n  ✗ Error: AISEC_CLIENT_SIDE_ERROR:nope\n    HTTP 404\n    Re-run with --debug to capture redacted API diagnostics.\n\n`
  - `\n  ✗ --all cannot be combined with --offset\n\n`

## 10. Fixture contract for the loopback server

- **`POST /oauth/token`:** return `{"access_token":"local-test-token","token_type":"Bearer","expires_in":3600}`. Assert the Basic credentials and the `scope=tsg_id:<tsg>` form field.
- **`GET /v1/mgmt/profiles/tsg/<tsg>`:**
  - Honour `offset` and `limit`.
  - `latest=true` returns the highest revision per `profile_name`.
  - `latest=false` returns all revisions.
  - When `latest` is **absent** (the get paths), behaviour on the real service is unknown; serve all revisions.
  - Set `next_offset` only when more items exist. To exercise the TS quirk, also serve `next_offset: 0`.
- **`GET /v1/mgmt/topics/tsg/<tsg>`:** honour `offset` and `limit` (the CLI sends 100 or 200). Never apply a latest filter.
- **Sample page bodies:**
  - `{"ai_profiles":[{"profile_id":"<uuid>","profile_name":"alpha","revision":2,"active":true,"created_by":"a@example.com","updated_by":"b@example.com","last_modified_ts":"2026-02-01T00:00:00Z","policy":{"ai-security-profiles":[{"model-type":"default","model-configuration":{"mask-data-in-storage":false}}],"dlp-data-profiles":[]}}],"next_offset":2}`
  - `{"custom_topics":[{"topic_id":"<uuid>","topic_name":"fin","revision":2,"active":true,"description":"new","examples":["e1","e2"]}]}`
- Never use `null` for optional scalars. Add `Retry-After: 0` on 5xx.
- Useful error modes: 404 `{"message":"nope"}`, 500 with `{"error_message":"boom"}`, 401-once, 403 with `x-opa-decision:false`, a problem+json 400, a repeated `next_offset`, invalid schema, token 401 `{"error_description":...}`, and a token body missing `access_token`.
- The proven harness pattern is `tests/integration/tenant-setup.spec.ts:52-110`: `PRISMA_AIRS_TENANTS_PATH`, `NO_COLOR=1`, `PANW_*` stripped, and an assertion that `FAKE-SECRET` never appears in stdout or stderr.

## 11. Rust SDK (`scm-sdk-rs`) gaps the Rust CLI must cover

- `CollectOptions{max_items:10000, max_pages:1000, max_bytes:64MiB}` rejects `max_items == 0` (`crates/scm-sdk/src/pagination.rs:47-91`). The CLI must map `--max 0` to a legal upper bound and handle truncation explicitly.
- `get` and `get_by_name` return `ErrorKind::Limit` when the collection is incomplete, where TS silently truncates. Not-found is `ErrorKind::Validation` with no TS-style text (`airs/management/profiles.rs:154-199`). The CLI must build the exact strings itself.
- `next_offset` 0 or unset ends the walk; negative or fractional values are a Decode error (`management/mod.rs:167-178`).
- Topics `list(latest_only)` mirrors TS: limit 200, first-seen order, first tie wins. It returns `Limit` beyond 10,000 instead of truncating (`topics.rs:98-140`).

The Rust CLI must reproduce, in its own code:
- the `latest` query semantics
- client-side slicing
- the CLI's own `getTopic`/`getTopicByName`
- normalization, key order (including zod's policy reorder) and integer formatting


## Acceptance criteria
- `airs-cli-rs runtime profiles list --output json` with the default flags makes exactly POST <mgmtTokenEndpoint>, then GET /v1/mgmt/profiles/tsg/<tsg>?offset=0&limit=100&latest=true, and exits 0.
- The OAuth POST sends Authorization: Basic base64(mgmtClientId:mgmtClientSecret), Content-Type application/x-www-form-urlencoded, and form fields grant_type=client_credentials and scope=tsg_id:<mgmtTsgId>; exactly one token POST is made per run when no 401 occurs.
- Every data GET carries Authorization: Bearer <access_token> and no request body.
- `profiles list --all-versions` sends latest=false; `profiles list --limit 2 --offset 4` sends offset=4&limit=2&latest=true in one request.
- `profiles list --all --limit 2` follows next_offset (offset=0, then 2, then 4, ...) until next_offset is absent or 0, and prints a bare JSON array of every item.
- `profiles list --all --max 2 --limit 1` stops after 2 items, makes only 2 page requests, and exits 0.
- `profiles list --all --max 0` walks every page with no item cap.
- Single-page `profiles list` prints `  Showing <n> (more available)` on stderr when next_offset is present (including 0) and `  Showing <n>` otherwise; `--all` prints `  Showing all <n>`; nothing else goes to stderr in json mode.
- `profiles list --output json` stdout is a bare array of objects with keys in the order profileId, profileName, revision, active, createdBy, updatedBy, lastModifiedTs, policy; absent fields are omitted, csp_id/tsg_id/unknown top-level fields are dropped, and output uses 2-space indentation and a trailing newline.
- Integer revisions print as `2`, never `2.0`; the policy subtree keeps zod order (known schema keys first, in schema order, then unknown keys).
- An empty profile or topic list prints `[]` in json mode and exits 0.
- `profiles get <name> --output json` makes GET ...profiles/tsg/<tsg>?offset=0&limit=100 with no latest param, follows pages, and prints the single highest-revision record as a bare JSON object; ties keep the first record seen.
- `profiles get <uuid>` (case-insensitive UUID regex) returns the first record whose profile_id equals the input exactly.
- `profiles get <missing>` exits 1 with stderr `\n  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: <missing>\n\n` and empty stdout.
- `profiles get <name> --revision N` requests latest=false pages and returns the record matching both name and revision; when none matches it exits 1 with `✗ Error: Profile <name> not found`.
- `profiles get <name> --all-versions` prints a JSON array of every matching revision in API order and writes no status line.
- `topics list --output json` (latest default) makes GET /v1/mgmt/topics/tsg/<tsg>?offset=0&limit=200 and follows every page regardless of --limit/--offset; it collapses by topic_name to the highest revision in first-seen order, slices client-side, and prints `  Showing <n>` on stderr.
- `topics list --all-versions --limit 1 --offset 1` fetches with limit=100 pages, slices client-side, and prints `  Showing 1 of <total> (next --offset 2)` when more remain.
- `topics list --all --max K` returns at most K latest topics and prints `  Showing all <n>`.
- Topic JSON objects (list and detail) use the key order topicId, topicName, revision, active, description, examples, createdBy, updatedBy, lastModifiedTs, createdTs; examples is `[]` when the server omits it, and csp_id/tsg_id are not emitted.
- `topics get <name>` returns the highest revision; not found exits 1 with `✗ Error: Topic "<name>" not found` (name quoted).
- `topics get <uuid>` not found exits 1 with `✗ Error: Topic <uuid> not found`; with --revision or --all-versions, not found exits 1 with `✗ Error: Topic <input> not found` (unquoted).
- `--all --offset <n>` (any explicitly given value, including 0) exits 2 with stderr `\n  ✗ --all cannot be combined with --offset\n\n` and makes no HTTP request.
- `--limit 0`, `--limit 1.5` and `--limit abc` exit 2 with `✗ --limit must be a positive integer`; `--offset -1` exits 2 with `✗ --offset must be a non-negative integer`; `--max -1` exits 2 with `✗ --max must be a non-negative integer`; none of them makes an HTTP request.
- `--output xml` with a valid tenant exits 2 with `✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml`.
- `--output` is accepted both before the subcommand (global) and after it, and `--output=json` is equivalent to `--output json`.
- The tenant config's `defaultOutput` is used when no --output is given.
- `ls` works as an alias of `list` for both `runtime profiles` and `runtime topics`.
- A server 404 with body {"message":"nope"} gives exit 1 and stderr `\n  ✗ Error: AISEC_CLIENT_SIDE_ERROR:nope\n    HTTP 404\n    Re-run with --debug to capture redacted API diagnostics.\n\n`.
- A server 500 with Retry-After: 0 is attempted 6 times in total, then exits 1 with `AISEC_SERVER_SIDE_ERROR:<error_message>` and `HTTP 500`.
- A 401 on a data GET triggers one new token POST and one retry of the same GET, then succeeds.
- A 403 with header x-opa-decision: false does not refresh the token and exits 1 with HTTP 403.
- A token endpoint 401 with {"error_description":"Client authentication failed"} exits 1 with `✗ Error: AISEC_OAUTH_ERROR:Client authentication failed` and `HTTP 401`, and makes no data request.
- A response violating the schema (missing profile_name, missing topic description, or next_offset: null) exits 1 with `AISEC_RESPONSE_VALIDATION:Response did not match schema: ...` and no HTTP line.
- During --all, a next_offset equal to an already-requested offset exits 1 with `✗ Error: Pagination returned a repeated cursor`.
- Credential environment variables (PANW_MGMT_CLIENT_ID/SECRET/TSG_ID/ENDPOINT/TOKEN_ENDPOINT) never change the requests: only the selected tenant file's mgmt* values are used.
- A tenant whose mgmtTsgId differs from the registry's tsgId exits 1 with `✗ Error: Tenant config TSG differs from its registered identity; register it under a new name` and makes no HTTP request; the tenant files are not modified.
- A tenant missing mgmtClientSecret exits 1 with `Management credentials are not configured (missing mgmtClientSecret). ...` and makes no HTTP request.
- The client secret and the access token never appear in stdout or stderr in any success or error case.
- In json mode, stdout contains only the JSON payload, and all status lines go to stderr; `--quiet` removes the status lines but keeps the data.


## Discrepancies
- Exit-code contract versus code: docs (docs-site/docs/getting-started/exit-codes-and-output.md:11) and the user's contract say usage errors exit 2, but commander parse errors (unknown option, missing argument, too many arguments, unknown command, bare group) exit 1 with `error: ...` (verified). Only CLI-validated usage errors (CliUsageError) exit 2.
- Config loads before flag validation: preAction calls resolveOutput, which calls loadConfig() before validating the format or list flags (program.ts:162-175, common.ts:60). With no or invalid tenant, `--output xml`, `--limit 0` etc. exit 1 ('No tenant selected') instead of 2. Credential checks, by contrast, run after flag validation (`--all --offset` with missing credentials exits 2).
- Profiles single-page status treats next_offset: 0 as 'more available' (`Showing 0 (more available)`, verified), while the --all walk treats 0 as terminal (`page.next_offset || void 0`, SDK:11292). The fixture in tests/integration/tenant-setup.spec.ts:85 returns next_offset: 0, which hits this case.
- topics list (latest-only default) never sends --limit/--offset to the server: the SDK fetches every page at limit=200 and slices locally (SDK:11524-11538), and the CLI discards the computed next_offset (management.ts:59-66). Stderr therefore never reports '(more available)' even when results were truncated.
- `topics list --all --max 0` maps to limit 10000 (runtime.ts:1183), so '0 removes the cap' is false for topics. `topics list --all-versions` ignores both --max and --limit (SDK default limit 100, max 10000).
- Silent truncation: --all and every get/name-resolution walk stop at 10,000 records (collectAll default, SDK:10802-10812) with no warning, and stderr still says `Showing all <n>`. Docs claim a traversal limit but do not say it is silent.
- Profile not-found messages differ by path: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: <x>` (SDK, no flags) versus `Profile <x> not found` (CLI, with --revision/--all-versions). Topic not-found messages differ three ways (`Topic <id> not found`, `Topic "<name>" not found`, `Topic <x> not found`).
- `--revision` is parsed with Number and never validated: `--revision abc` becomes NaN and produces a not-found error (exit 1) instead of a usage error; `--revision 0x2` matches revision 2.
- Pagination flags use JS Number(): `--limit 0x10`, `1e2`, ' 5' are accepted and there is no upper bound on --limit (the Rust SDK caps limit at u32).
- Help text bug: `--limit <n>  Items per page (default: 100) (default: 100)` and `--offset <n>  Item offset (default: 0) (default: 0)`, because the default is duplicated in the description.
- Docs drift (docs-site/docs/cli/runtime/profiles.md): the pretty example shows 'Next offset: 2' and 'ID:' with colons, but the code prints `Showing 2 (more available)` on stderr and no colons; the list JSON example shows only 4 keys in the order active, revision, while the code emits the full normalized record (including policy) with revision before active; the get YAML example claims the policy is 'emitted as inline JSON', but js-yaml emits nested block YAML.
- Docs drift (docs-site/docs/cli/runtime/topics.md): get JSON shows cspId/tsgId (the code drops them); list JSON shows keys id/name/revision/description (the code emits the topicId/topicName/... structured shape); list YAML shows `---`-separated documents (the code emits one sequence); pretty shows 'Showing 3 of 100 topics' (the code prints `Showing 3`).
- Docs say output precedence is local --output, then global --output, then defaultOutput. In practice the root program consumes --output wherever it appears (no enablePositionalOptions), so the local option is never 'cli'; the outcome is the same, but the two are one flag.
- The 'credential env vars ignored' contract holds for credentials, but the TS SDK still reads PANW_AI_SEC_TIMEOUT_MS (per-attempt timeout) and PANW_AI_SEC_DEBUG/PANW_AI_SEC_DEBUG_BODY (stderr wire logging) from the environment (SDK:10095, 10000).
- Non-JSON error bodies are echoed verbatim into the error message (`API error <s>: <body>`, SDK:9723). A server that reflects request data could leak it into stderr; only problem-details bodies are sanitized.
- UUID-shaped input is matched by a case-insensitive regex but compared exactly, so an uppercase UUID is routed as an ID and then not found. A profile or topic whose name looks like a UUID can only be fetched by ID.
- In pretty mode the banner is written to stdout before credential and HTTP failures (get: before service creation), so failing pretty runs leave partial stdout.
- The SDK schema rejects null for optional scalar fields (created_by, last_modified_ts, revision, next_offset, ...). If the live service ever returns null, the TS CLI fails with AISEC_RESPONSE_VALIDATION.
- Behaviour differences the Rust CLI must compensate for: Rust scm-sdk get/get_by_name/list(latest_only) return ErrorKind::Limit when a walk is incomplete, where TS silently truncates; Rust not-found is ErrorKind::Validation with no TS text; CollectOptions rejects max_items=0, so `--max 0` needs explicit mapping.


## Open questions
- Should airs-cli-rs exit 2 for parser-level usage errors (clap's default, and the user's stated contract) even though the TS CLI exits 1 for commander errors? If so, the comparison harness needs an allowlist for this divergence.
- Should Rust validate flags before loading the tenant (exit 2 even with no tenant selected), or keep TS's config-first ordering (exit 1)?
- Should Rust reproduce the known TS quirks byte-for-byte: `Showing 0 (more available)` for next_offset 0, topics latest-list never signalling truncation, `--max 0` capping topics at 10,000, silent 10,000-record truncation? Or should it fix them (for example, warn on stderr and exit 0, or exit 1 when incomplete, as the Rust SDK's Limit error suggests)?
- What does the live AIRS service return from /v1/mgmt/profiles/tsg/<tsg> when the `latest` param is omitted (the get-by-name/UUID path): all revisions, or only the latest? Live comparison should confirm this; the fixture currently serves all revisions.
- Should error hints in airs-cli-rs mention `airs-cli tenant ...` (the TS tool that owns tenant registration) or `airs-cli-rs ...`, given Rust only reads the registry? Help-text comparisons will also differ in the program name.
- Should the first release support all six output formats, or JSON (plus a minimal default) only? If pretty is the default and not implemented, what should `profiles list` with no --output do?
- Should the Rust CLI honour the TS SDK's environment knobs (PANW_AI_SEC_TIMEOUT_MS, PANW_AI_SEC_DEBUG) or ignore all environment variables? The harness should unset them for deterministic comparison.
- Proxy handling: Node fetch ignores HTTP(S)_PROXY by default while reqwest honours it. Should airs-cli-rs disable environment proxies, or should the harness set NO_PROXY=127.0.0.1,localhost?
- Retry timing: the TS SDK backs off randomly (up to ~31 s) on network errors and on 5xx without Retry-After. Should the harness only use Retry-After: 0 fixtures, and should the Rust CLI expose a retry or timeout knob for tests?
- Cancellation (SIGINT) for list/get is unhandled in TS (Node's default signal exit). What exit code and stderr should the Rust version produce (130?), and does it need to match?
- Should Rust preserve the zod key reordering of the profile `policy` subtree (schema order, then unknown keys; JS integer-key ordering) for byte-identical JSON, or is semantic JSON equality acceptable in comparisons?
