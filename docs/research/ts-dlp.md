# Spec: TS `airs-cli` runtime DLP CRUD (M6b)

Commands covered: `runtime dlp filtering-profiles list|get|replace`, `runtime dlp patterns list|create|get|replace|patch|delete`, `runtime dlp profiles list|create|get|replace|patch|delete`, `runtime dlp dictionaries list|create|get|replace|patch|delete`, the shared visibility flag, body builders, `--body`/`--body-file`/stdin escape hatches, `--set`/`--clear` merge patch, the dictionary multipart upload, delete safety, the DLP debug-body handling, and the registration of the dropped `runtime dlp generate`. `runtime dlp backup|restore` (`transfer.ts`, `src/backup/dlp-resources.ts`) are only listed here (§1); they need their own spec.

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0, SDK `@cdot65/prisma-airs-sdk` 0.34.0, commander 14). Citations:
  - `idx.ts`, `cfg.ts`, `vis.ts`, `patch.ts`, `bb.ts`, `fp.ts`, `pat.ts`, `prof.ts`, `dict.ts`, `gen.ts` are `src/cli/commands/dlp/{index,config,visibility,patch,build-body,filtering-profiles,patterns,profiles,dictionaries,generate}.ts`.
  - `svc/<x>.ts` is `src/airs/dlp/<x>.ts` (thin wrappers over the SDK; only `svc/dictionaries.ts:36-47` adds logic).
  - `rdlp.ts` is `src/cli/renderer/dlp.ts`; `view.ts`, `common.ts`, `ui.ts` are under `src/cli/renderer/`.
  - `program.ts`, `pagination.ts`, `deprecated-flags.ts` are under `src/cli/`; `co.ts` is `src/config/client-options.ts`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` of the reference build.
  - `rs:<file>:<line>` is `~/.cargo/registry/src/*/scm-sdk-0.1.0/src/<file>` (the Rust SDK in use).
- Shared shell behaviour (commander parse errors exit 1, the root `--output` consumer, `resolveOutput`, `ui`, quiet, colour, EPIPE) is specified in `ts-cli-shell.md` and `ts-renderer.md`; the debug log in `ts-debug-log.md`. It is restated only where DLP depends on it.
- How behaviour was captured: the reference build (`dist/cli/index.js`, node v24.21.0) ran against a stateful loopback stub (`node:http` on `127.0.0.1`, random port) implementing `POST /oauth/token` and the four DLP collections under `/dlp/v2/api/` (Spring page envelopes, create/get/PUT/PATCH/DELETE, multipart parsing, a 204 mode for dictionary PUT). It logged every request (method, path, ordered query, content type, raw body) and accepted a fault plan (status, raw body, headers such as `Retry-After: 0` or `x-opa-decision: false`, or a hang).
  - Sandbox: `env -i` with `PATH`, `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` inside the sandbox, a TS registry selected through `PRISMA_AIRS_TENANTS_PATH`, one tenant `test` with fake credentials (`fake-client`/`FAKE-SECRET`, TSG `100`), `mgmtTokenEndpoint` `<base>/oauth/token`, `mgmtEndpoint` `<base>/mgmt` and `dlpEndpoint` `<base>/dlp`. Fixture data used fake sensitive values (`FAKE-REGEX-[0-9]+`, `FAKE-PROX`, `FAKE-KEYWORD-1`, `FAKE-KW-A`).
  - **DLP endpoint fallbacks.** The CLI passes `dlpEndpoint: config.dlpEndpoint ?? DEFAULT_DLP_ENDPOINT` (`co.ts:44-51`), and the SDK uses `opts.dlpEndpoint ?? DEFAULT_DLP_ENDPOINT` (`SDK:13420`, default `https://api.dlp.paloaltonetworks.com`, `SDK:70`). There is **no** environment fallback for the DLP base in SDK 0.34.0 (the docs-site's `PANW_DLP_ENDPOINT` row is stale: `dlp-tenant-auth.spec.ts:236-245` sets it and it is ignored). Credentials and token endpoint are explicit too (`co.ts:34-42`), so `PANW_MGMT_*` fallbacks are never reached. The only DLP-relevant environment variables the TS CLI/SDK read are `PANW_AI_SEC_TIMEOUT_MS` (per-attempt timeout, `SDK:10095`), `PANW_AI_SEC_DEBUG` and `PANW_AI_SEC_DEBUG_BODY` (§2.9), and `FORCE_COLOR`/TTY for chalk.
  - Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and `dns.lookup` and refuses any host other than `127.0.0.1`. The guard log stayed empty.
  - Signals were sent with `kill -INT|-TERM` during a hung write.
- No real tenant or credential file was read; no host other than loopback was contacted.
- Captures are shown as JSON strings (`"\n  ..."`). Captures are uncoloured (stdout a pipe) unless stated; §2.3 lists the ANSI codes captured with `FORCE_COLOR=1`. Stub ids such as `new-112` are arbitrary.

## 1. Command surface (help verified)

Registration: `runtime.ts:1230` calls `registerDlpCommands` (`idx.ts:9-21`), which registers, in order, `filtering-profiles`, `patterns`, `profiles`, `dictionaries`, `generate`, then `backup`/`restore` (`transfer.ts`). Aliases: every `list` gets `ls`, every visible `delete` gets `rm` (`program.ts:42-51`). Help sorts options and subcommands (`program.ts:73-76`). `applyReadContractFlags` (`program.ts:54-70`) adds `--all` (`Walk all pages`) and `--max <n>` (`Number`, default 10000) to every DLP `list`, since each declares `--limit`. Hidden deprecated aliases `--size <n>` (→ `--limit`) and `--page <n>` (→ `--offset`) are registered on every DLP `list` (`pagination.ts:64-80`); they are not in help.

| Command | Registration | Arguments and options (help text; defaults) |
|---|---|---|
| `filtering-profiles list\|ls` | `fp.ts:9-19,38-53` | `--limit <n>` (`Max results per page (API page size)`, `parseInt`), `--offset <n>` (`Starting offset — rounds down to a page boundary`, `parseInt`), `--sort <field,dir>` (`Sort criteria (repeatable)`), `--output <fmt>` (`Output format: pretty, table, markdown, csv, json, yaml`, no default), `--all`, `--max <n>`. **No** `--include-predefined` (`error: unknown option '--include-predefined'`, exit 1, captured) |
| `filtering-profiles get <id>` | `fp.ts:55-66` | `--output <fmt>` |
| `filtering-profiles replace <id>` | `fp.ts:68-98` | `--file-based` (`Apply to file-based scans (boolean)`), `--non-file-based`, `--description <s>`, `--direction <s>` (`Direction: BOTH\|UPLOAD\|DOWNLOAD`), `--log-severity <s>` (`Severity: CRITICAL\|HIGH\|MEDIUM\|LOW\|INFORMATIONAL`), `--scan-type <s>` (`Scan type: include\|exclude`), `--data-profile-id <n>` (`Data profile ID`, parser `Number`), `--euc-template-id <s>`, `--end-user-coaching`, `--granular` (`Granular profile`), `--file-type <s>` (`File type (repeatable)`), `--body <json\|->` (`Raw JSON body (escape hatch; or "-" for stdin)`), `--body-file <path>` (`Raw JSON body file (escape hatch)`), `--output <fmt>` (`Output format`, default `"pretty"`) |
| `patterns list\|ls` | `pat.ts:10-20,52-70` | as filtering-profiles list, plus `--include-predefined` (`Include predefined (PANW-shipped) records; listings show only tenant-created records by default`, `vis.ts:6-11`) |
| `patterns create` / `patterns replace <id>` | `pat.ts:22-38,72-117` | `--name <s>` (`Pattern name (required unless --body-file)`), `--type <s>` (`Pattern type: predefined\|custom\|file_property (default: custom)`), `--description <s>`, `--technique <s>` (`Detection technique (default: regex)`), `--confidence-levels <csv>`, `--regex <pattern>` (`Regex with weight=1 (repeatable)`), `--weighted-regex <PATTERN\|N>` (repeatable), `--delimiter <s>`, `--proximity-distance <n>` (`Proximity window (2..1000)`, string), `--proximity-keyword <s>` (repeatable), `--tag <k=v>` (`Tag (repeatable, value can be CSV)`), `--body <json\|->`, `--body-file <path>`, `--output <fmt>` (default `"pretty"`) |
| `patterns get <id>` | `pat.ts:88-101` | `--output <fmt>` |
| `patterns patch <id>` | `pat.ts:119-147` | `--body-file <path>` (`JSON merge-patch body file`), `--set <k=v...>` (`Set scalar field (repeatable)`), `--clear <key...>` (`Clear field via merge-patch null (repeatable)`), `--output <fmt>` (default `"pretty"`). No `--body` (`error: unknown option '--body'`, exit 1) |
| `patterns delete\|rm <id>` | `pat.ts:149-159` | none (`Soft-delete (archive) a data pattern`); no `--force`, no `--output` |
| `profiles list\|ls` | `prof.ts:25-35,150-168` | as patterns list |
| `profiles create` / `profiles replace <id>` | `prof.ts:37-59,170-215` | `--name <s>` (`Profile name (required unless --body-file)`), `--profile-type <s>` (`Profile type: advanced (basic writes are unsupported)`), `--description <s>`, `--granular` (`Granular data profile`), `--pattern-id <id>` (`Data pattern ID to include (repeatable). Builds a simple expression_tree.`), `--combinator <op>` (`… or\|and\|not\|and_not\|or_not (default: or)`), `--confidence <level>` (`… (default: high)`), `--body <json\|->`, `--body-file <path>` (`Raw JSON body file (escape hatch; required for complex rule trees)`), `--output <fmt>` (default `"pretty"`) |
| `profiles get <id>` | `prof.ts:186-199` | `--output <fmt>` |
| `profiles patch <id>` | `prof.ts:217-253` | as patterns patch; description adds `body must include name + profile_type.` |
| `profiles delete\|rm <id>` | `prof.ts:255-266` | none (`Not supported — explains the cleanup limitation and exits 2`) |
| `dictionaries list\|ls` | `dict.ts:75-109` | `--limit`, `--offset`, `--sort <field,dir>` (help text only `(repeatable)`), `--keywords` (`Include keyword list in response`), `--include-keywords` (`Alias for --keywords`), `--output <fmt>`, `--include-predefined`, `--all`, `--max` |
| `dictionaries create` | `dict.ts:111-138` | `--name <s>`, `--category <s>`, `--description <s>` (all with empty help text), `--region <s>` (`SCM region display name, e.g. "United States"`), `--classification <s>` (`Legacy top-level metadata field (server support unverified)`), `--file <path>` (`Keyword file: TXT (one keyword per line), or CSV (header required)`), `--metadata-file <path>` (`JSON metadata file (overrides --name/--category/...)`), `--include-keywords` (`Include keywords in response`), `--output <fmt>` (default `"pretty"`) |
| `dictionaries get <id>` | `dict.ts:140-157` | no description; `--keywords` (empty help), `--include-keywords` (`Alias for --keywords`), `--output <fmt>` |
| `dictionaries replace <id>` | `dict.ts:159-193` | as create, with `--file` help `Required: TXT (one keyword per line), or CSV (header required)`, `--metadata-file` help `JSON metadata file`, `--include-keywords` with empty help. Description `Full-replace via multipart upload. --file required. May return 200 (body) or 204 (re-get; falls back to "(state not echoed)" on transient failure).` |
| `dictionaries patch <id>` | `dict.ts:195-227` | no description; `--body-file <path>` (empty help), `--set <k=v...>` / `--clear <key...>` (help `(repeatable)`), `--output <fmt>` (default `"pretty"`) |
| `dictionaries delete\|rm <id>` | `dict.ts:229-239` | none (`Delete a dictionary`) |
| `generate` | `gen.ts:49-93` | dropped in Rust (§14) |
| `backup`, `restore <file>` | `transfer.ts` | out of scope here |

Captured `runtime dlp --help` (stdout, exit 0):

```
Usage: airs-cli runtime dlp [options] [command]

DLP management (filtering-profiles, patterns, profiles, dictionaries, generate,
backup/restore)

Options:
  -h, --help                display help for command

Commands:
  backup [options]          Back up custom DLP dictionaries (with keywords),
                            data patterns and data profiles with their
                            referenced dependencies
  dictionaries              DLP dictionaries (multipart upload)
  filtering-profiles        DLP data filtering profiles. Read + full-replace
                            only. Create, patch, and delete are not exposed by
                            the DLP API.
  generate [options]        Generate clean + dirty DLP test files (synthetic
                            sensitive data) across PDF/PNG/JPEG/SVG/DOCX
  help [command]            display help for command
  patterns                  DLP data patterns (full CRUD)
  profiles                  DLP data profiles. No supported DELETE; status-based
                            retirement is not live-verified.
  restore [options] <file>  Restore DLP resources into the selected tenant,
                            staged dictionaries → patterns → profiles; validate
                            all dependencies before changes
```

Captured `runtime dlp patterns patch --help`:

```
Usage: airs-cli runtime dlp patterns patch [options] <id>

JSON Merge Patch. Use --body-file for nested fields. --set/--clear coerce
values: numbers/booleans/JSON literals. To force a string, quote: --set
count='"5"'.

Options:
  --body-file <path>  JSON merge-patch body file
  --clear <key...>    Clear field via merge-patch null (repeatable)
  -h, --help          display help for command
  --output <fmt>      Output format (default: "pretty")
  --set <k=v...>      Set scalar field (repeatable)
```

Captured `runtime dlp dictionaries list --help`:

```
Usage: airs-cli runtime dlp dictionaries list|ls [options]

List dictionaries

Options:
  --all                 Walk all pages
  -h, --help            display help for command
  --include-keywords    Alias for --keywords
  --include-predefined  Include predefined (PANW-shipped) records; listings show
                        only tenant-created records by default
  --keywords            Include keyword list in response
  --limit <n>           Max results per page (API page size)
  --max <n>             Maximum items with --all; 0 removes the cap (default:
                        10000)
  --offset <n>          Starting offset — rounds down to a page boundary
  --output <fmt>        Output format: pretty, table, markdown, csv, json, yaml
  --sort <field,dir>    (repeatable)
```

The full help of all 27 DLP leaves and groups was captured; the option lines match the table above. Group texts: `filtering-profiles` `DLP data filtering profiles. Read + full-replace only. Create, patch, and delete are not exposed by the DLP API.`; `patterns` `DLP data patterns (full CRUD)`; `profiles` `DLP data profiles. No supported DELETE; status-based retirement is not live-verified.`; `dictionaries` `DLP dictionaries (multipart upload)`. A group without a subcommand prints its help on **stderr**, exit 1 (captured for `runtime dlp` and `runtime dlp patterns`). Commander errors exit 1: `error: missing required argument 'id'`, `error: too many arguments for 'get'. Expected 1 argument but got 2.`, `error: unknown option '--force'` (captured).

**Variadic `--set`/`--clear`.** `<k=v...>` and `<key...>` are commander variadic options with a custom parser (`pat.ts:127-128`, `prof.ts:225-226`, `dict.ts:198-199`): `--set name=My type=custom 'detection_config={…}'` collects three values (captured), and a positional after them is swallowed (`patch --set a=1 p-cus-1` → `error: missing required argument 'id'`, exit 1, captured).

## 2. Shared behaviour

### 2.1 Client, endpoints and credentials

- Every command builds its service from `loadDlpClientOptions()` (`cfg.ts:5-7`) = `managementClientOptions(await loadConfig())` (`co.ts:44-51`): `assertManagementCredentials` first (`Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set test <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)`, captured), then `clientId`, `clientSecret`, `tsgId`, `tokenEndpoint: mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`, `apiEndpoint: mgmtEndpoint ?? DEFAULT`, `dashboardEndpoint`, `dlpEndpoint: dlpEndpoint ?? https://api.dlp.paloaltonetworks.com`.
- The management client is a process singleton (`management.ts:549-554`), so all DLP services share one token cache. The DLP namespace uses `baseUrl = dlpEndpoint` (`SDK:13445`) with paths `/v2/api/data-filtering-profiles`, `/v2/api/data-patterns`, `/v2/api/dictionaries`, `/v2/api/data-profiles` (`SDK:71-74`). The `dlpEndpoint` value is used with trailing slashes stripped (`SDK:10117`), so `<base>/dlp` produces `<base>/dlp/v2/api/…` (captured).
- Token: one `POST <mgmtTokenEndpoint>` with HTTP Basic `client_id:client_secret`, form `grant_type=client_credentials&scope=tsg_id%3A100` (captured), cached for the process; then `Authorization: Bearer <token>`, `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `service-name: api`, and `Content-Type` per body (§2.6).
- No DLP doctor check exists in TS; `dlpEndpoint` appears only in the config schema (`schema.ts:26`) and `co.ts:49` (DESIGN §3 row 11 already covers it as an endpoint key).

### 2.2 Output format resolution

- Reads (`list`, `get`): `program.ts:162-175` resolves `--output` in `preAction` (they are in `READ_COMMAND_NAMES` and declare `--output`): it loads the tenant config first (no tenant → `\n  ✗ Error: No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'\n\n`, exit 1, captured), then validates against `pretty, table, markdown, csv, json, yaml` (`\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n`, exit 2, captured). The tenant's `defaultOutput` applies.
- Writes (`create`, `replace`, `patch`) call `resolveOutput(command, opts)` themselves (`common.ts:48-75`). Because the root `--output` consumes the value (`ts-cli-shell.md` §3), the leaf default `pretty` is "not explicit", so the root value or the tenant's `defaultOutput` wins; `--output json` therefore works on every DLP write (captured), and `defaultOutput: json` makes `patterns create` print JSON without a flag (captured). `markdown`/`csv`/`yaml` are accepted (csv ack captured: `action,id,name,type,status,version\ncreated,new-124,x,custom,active,1\n`).
- `delete` has no `--output` and always prints the pretty ack (§5.2), even with `defaultOutput: json` (captured).

### 2.3 Streams, quiet and colour

- stdout: list/get layouts, all write acks (including the pretty `  ✓ …` lines, which use `console.log`, `ui.ts:90-93`), the dictionary 204 fallback line, and empty-list phrases.
- stderr: the page status line (`ui.status`, quiet-suppressed), deprecation warnings `  ⚠ --size is deprecated and will be removed in v4 — use --limit` and `  ⚠ --page is deprecated and will be removed in v4 — use --offset` (`deprecated-flags.ts:44`, not quiet-suppressed, captured), errors, the dictionary region hint (§11.6), the debug status line.
- `--quiet` suppresses `ui.section` headings and the page status; list item lines and get key/value lines still print (captured: `"  p-cus-1\n    My Pattern  custom  active regex v1\n  p-dis-1\n    Disabled Pattern  custom  disabled weighted_regex v4\n\n"`). Acks print in quiet mode.
- Colours (captured with `FORCE_COLOR=1`): section heading bold `\e[1m…\e[22m`; ids, technique, `dir:`, `sev:`, `v<n>`, `<n> kw` dim `\e[2m…\e[22m`; type cyan `\e[36m…\e[39m`; status green for `active`, yellow for `deleted`/`disabled`, dim otherwise, a missing status is dim `—` (`rdlp.ts:15-25`); get keys dim and padded inside the escape (`\e[2mID          \e[22m  dp-cus-1`); the page status dim; ack green `  \e[32m✓ created new-118  NP4 v1\e[39m`; `fail` red with the `Re-run` line dim; chalk splits multi-line red text per line, so the error starts `"\e[31m\e[39m\n\e[31m  ✗ Error: …\e[39m\n"`.

### 2.4 Errors and exit codes

Two error renderers (`common.ts:12-30`):

- `fail(err)`: `CliUsageError` → `usageError`. Otherwise stderr `"\n  ✗ Error: <message>\n"`, and when the error has `status`/`statusCode`: `"    HTTP <s>\n"` and `"    Re-run with --debug to capture redacted API diagnostics.\n"`; then `"\n"`; exit 1.
- `usageError(msg)`: stderr `"\n  ✗ <msg>\n\n"`, exit 2. No HTTP lines.

Which one each command uses decides its exit codes (all captured):

| Command | Handler | Consequence |
|---|---|---|
| every `list`, `get` | `fail` | API, network, tenant and credential errors exit 1; format errors exit 2 |
| `filtering-profiles replace`, `patterns create`, `patterns replace`, `patterns patch` | `catch → usageError(message)` (`fp.ts:95-97`, `pat.ts:82-84,113-115,144-146`) | **every** failure exits 2 with the bare message: no tenant (`\n  ✗ No tenant selected. …\n\n`), missing credentials, `ENOENT: no such file or directory, open 'missing.json'`, HTTP 4xx/5xx (`\n  ✗ AISEC_SERVER_SIDE_ERROR:API error 500; Internal Server Error; [withheld]\n\n`), network failures; no `HTTP` line |
| `patterns delete`, `dictionaries delete` | `fail` | exit 1 |
| `profiles create`, `replace`, `patch` | `profileFailure` (`prof.ts:73-81`) | `CliUsageError` → 2; SDK `AISEC_USER_REQUEST_PAYLOAD_ERROR` → 2 with the fixed `Invalid profile metadata: verify required fields and value types`; everything else `fail` → 1 (missing credentials, `Referenced pattern is not active; no profile was written`, HTTP errors with `HTTP` line) |
| `profiles delete` | `usageError` | always 2, no tenant read, no request |
| `dictionaries create`, `replace` | `uploadFailure` → `dictionaryFailure` (`dict.ts:28-52`) | as profiles, fixed `Invalid dictionary metadata: verify required fields and value types`; `ENOENT` of `--file`/`--metadata-file` exits 1 via `fail` |
| `dictionaries patch` | `dictionaryFailure` | as above |

SDK error messages carry the `<ERROR_TYPE>:` prefix (`AISEC_CLIENT_SIDE_ERROR:API error 404; Not Found`). Problem-details text is allowlisted by the SDK (`SDK:9593-9683`): non-allowlisted `title`/`detail`/`reason` print `[withheld]`; a non-problem error body prints only `API error <s>` because every DLP call sets `safeErrorMessages: true` (captured: a 400 with body `PRIVATE plain text` → `AISEC_CLIENT_SIDE_ERROR:API error 400`). Response decode errors: `AISEC_RESPONSE_VALIDATION:Response body is not valid JSON` and `AISEC_RESPONSE_VALIDATION:Response did not match schema: status: invalid_enum_value` (exit 1, captured).

### 2.5 Retries and write replay (captured)

- `numRetries` is not passed, so the SDK default 5 applies. `executeWithRetry` (`SDK:9786-9850`) re-sends **every** method, writes included, on 500/502/503/504 (`SDK:31`) and on transport errors and per-attempt timeouts, with jittered backoff or `Retry-After` (≤ 60 s). Captured: a `patterns create` against a permanent 500 sent the POST 6 times then exited 2; `profiles replace` against 502 sent 6 PUTs and exited 1; `patterns delete` against 503 sent 6 DELETEs and exited 1; a hung `dictionaries delete` with `PANW_AI_SEC_TIMEOUT_MS=500` sent 6 DELETEs and exited 1 with `AISEC_CLIENT_SIDE_ERROR:Network request failed` after ~23 s of backoff.
- 401 and 403 (unless `x-opa-decision: false`) clear the token and replay the request once with a new token (`SDK:10865-10872`, `specialRetryUsed`): captured `token, POST(401), token, POST(201)` → success; `token, POST(401), token, POST(401)` → exit 2; the same for 403; `403` with `x-opa-decision: false` → one POST, no replay.
- A write can therefore be applied several times (duplicate patterns, profiles or dictionaries; a successful delete that later answers 404). No outcome-unknown text exists.

### 2.6 Request validation and body serialisation

- Each JSON write passes its body through the SDK zod request schema before any token or request (`SDK:10103-10116`): failure is `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for <METHOD> <path> did not match schema: <path>: <code>; …` (paths and zod codes only, no values; captured `matching_rules.proximity_distance: too_small`, `name: too_big`, `detection_config.supported_confidence_levels.0: invalid_enum_value`, `<root>: invalid_type`). No token request precedes it (captured).
- Schemas (`SDK:2487-2880`; all `.passthrough()`, so unknown keys are kept):
  - `DataFilteringProfileRequest`: `file_based`, `non_file_based` (booleans, required); optional `description`, `direction` ∈ `BOTH|UPLOAD|DOWNLOAD`, `log_severity` ∈ `CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL`, `scan_type` ∈ `include|exclude`, `data_profile_id` (number), `euc_template_id`, `is_end_user_coaching_enabled`, `is_granular_profile`, `file_type[]`, `criteria_details[]`, `exception_rules[]`, `exclusions`, `rule1`, `rule2`. No `name`.
  - `DataPatternRequest`: `name` (1..64), `type` ∈ `predefined|custom|file_property`, `detection_config {technique ∈ 13 techniques, supported_confidence_levels ∈ low|medium|high}` required; optional `description`, `matching_rules {delimiter, proximity_distance int 2..1000, proximity_keywords[], regexes[{regex min 1, weight number}], metadata_criteria[]}`, `tags {classification[], compliance[], geography[]}`.
  - `DataPatternPatchRequest`: `name`, `type`, `detection_config` **required**; `description`, `matching_rules`, `tags` nullable.
  - `AdvancedDataProfileRequest`: `name` (1..64), `detection_rules[]` (discriminated `expression_tree`/`multi_profile`) required; optional `description`, `is_granular_data_profile`.
  - `DataProfilePatchRequest`: `name`, `profile_type` ∈ `basic|advanced` **required**; `description`, `detection_rules` nullable.
  - `DictionaryPatchRequest`: `category` ∈ 9 values (`Academic, Confidential, Employment, Financial, Government, Healthcare, Legal, Marketing, Source Code`), `name`, `original_file_name` **required**; `description`, `is_case_sensitive`, `region_name` nullable.
  - Dictionary create/replace metadata is **not** validated by the TS SDK (no `requestSchema`, `SDK:13229-13315`); `DictionaryRequestSchema` (category, name, original_file_name, region_name required) exists but is unused.
- The sent body is the zod output, so keys come in schema order, then passthrough keys in input order: `{"name":"NP","detection_rules":[…],"description":"dd","is_granular_data_profile":true,"profile_type":"advanced"}` although the builder wrote `profile_type` second (captured). `rule_item` keys likewise follow `DetectionRuleItemSchema` order.
- PATCH bodies are sent with `Content-Type: application/merge-patch+json`; other JSON bodies `application/json`.
- No DLP schema contains a zod default (checked by reachability over `rs:validation/schema_graph.json` from every `src/models/dlp-*.ts` root: only Array, Boolean, DiscriminatedUnion, Enum, Lazy, Literal, Never, Nullable, Number, Object, Optional, Record, String and Union nodes). **SDK gap G10 does not affect DLP**: neither CLI fabricates fields in DLP output or backups.
- Response enums are strict: one record with an unknown `status` (`"weird"`) fails the whole `get` or list page (`AISEC_RESPONSE_VALIDATION:Response did not match schema: status: invalid_enum_value`, exit 1, captured). `type` of patterns, profiles and dictionaries, `profile_status`, `profile_type`, `license_type`, `detection_technique`, `scan_type` are enums too.

### 2.7 Ids and paths

No id format check. The id is `encodeURIComponent`-ed into the path (`a/b?c` → `/v2/api/data-patterns/a%2Fb%3Fc`, captured), but `''`, `.` and `..` are not encoded and the URL parser normalises them: `patterns delete ''` sends `DELETE /dlp/v2/api/data-patterns/` (the collection), `patterns get ..` sends `GET /dlp/v2/api/` (captured). The Rust SDK refuses these segments (`rs:config.rs:121-133`, empty, `.`, `..`, control characters, backslash, also after percent-decoding).

### 2.8 Interruption

No signal handlers and no prompts. SIGINT or SIGTERM during a hung write exits 130 / 143 with nothing on stdout or stderr (captured); whether the write was applied is not reported.

### 2.9 `--debug` and `PANW_AI_SEC_DEBUG`

- `program.ts:111-127`: for any action under `runtime dlp`, `PANW_AI_SEC_DEBUG_BODY` is forced to `0` during the action and restored afterwards (`postAction` and a `finally` around `parseAsync`, `program.ts:83-100`; `dlp-debug.spec.ts:79-93`), so the SDK's own stderr logger never prints bodies.
- `--debug` (root option, before or after the subcommand) installs the CLI logger with `omitBodies: agentGuard || dlp` (`program.ts:176-192`): `debug-api-<ms>-<8 hex>.jsonl` in the **current directory**, mode 0600, status line `  Debug: API log → <abs path>` on stderr. Request and response bodies are recorded as `[BODY OMITTED]`; method, URL with query, status and headers are kept (`dlp-debug.spec.ts:18-77`). Its host filter logs only PANW hosts (`ts-debug-log.md` §host filter), so against loopback the file stays empty (captured: 0-byte file).
- `PANW_AI_SEC_DEBUG=1` (environment) prints SDK lines on stderr (captured): `[airs-sdk] → POST http://127.0.0.1:<port>/dlp/v2/api/data-patterns`, `[airs-sdk]   headers {"User-Agent":"PAN-AIRS/0.34.0-typescript-sdk","service-name":"api","Content-Type":"application/json","Authorization":"sha256:0fe7f85b834a"}`, `[airs-sdk]   body [BODY OMITTED]`, `[airs-sdk] ← 201 (3ms) [BODY OMITTED]`. The URL query is printed (only `keywords=true`, `page`, `size`, `sort` occur).
- Rust context: DESIGN §2.9 replaces both mechanisms; the Rust SDK reads no environment. The settled rule for 0.7 is "status and headers only, never bodies".

### 2.10 JSON normalisation (`camelize`)

List and get `json` (and `table` for get) print the full validated record with every object key converted from snake/kebab case to camelCase, recursively (`rdlp.ts:58-73`; regex `[_-]([a-z0-9])`): `detection_config.supported_confidence_levels` → `detectionConfig.supportedConfidenceLevels`. This also renames **data keys**: a pattern tag `my_tag` prints as `myTag` (captured), and `exclusions.exclusion_list` category names are renamed when they contain `_` + lowercase or digit (`Some_Category` stays, captured). Acks are not camelised (§5).

## 3. List commands (shared)

### 3.1 Flags and parsing (captured)

- `--limit`, `--offset`: `Number.parseInt(v, 10)`; `--limit abc` → `NaN` → no `size` sent, the server default applies, exit 0; `--limit 1.5` → `size=1`; `--limit 0` → `size=0` sent; `--limit -1` → `size=-1` sent; `--offset -5` → `page=-1` sent. No usage errors.
- `resolvePageParams` (`pagination.ts:91-123`): `page = floor(offset / (limit ?? 50))` when `--offset` is given; deprecated `--page` passes through verbatim; `--size` maps to `--limit`. `--offset` without `--limit` divides by 50.
- `--sort` repeats in order (`sort=id,desc&sort=name`); default `['name,asc']`, always sent.
- `--all`: `listAll({size, sort, max: Number(opts.max)})`; `--offset`/`--page` are ignored silently (`--all --offset 0` accepted); `--all` without `--limit` uses `size=50`. `--max abc` → `NaN` → `RangeError` `max must be a non-negative integer`, rendered `\n  ✗ Error: max must be a non-negative integer\n\n`, exit 1, after the tenant is read and before any request. `--max 0` removes the cap. `--max` without `--all` is ignored.
- `dictionaries list --keywords` or `--include-keywords` adds `keywords=true`; otherwise no `keywords` parameter.

### 3.2 Requests

- Without `--all`: one `GET <path>?[page=<p>&][size=<n>&]sort=…[&keywords=true]` (order `page, size, sort…, keywords`, captured). Without `--limit`/`--offset` no `page`/`size` is sent.
- With `--all`: `GET ?page=0&size=<n>&sort=…`, `page=1`, … until the page is last: `last`, else `page+1 >= totalPages`, else `content.length < size` (`SDK:12696-12706`); an empty non-final page throws `Pagination returned an empty non-final page`; collection stops at `max` items (`SDK:10802-10838`) without saying it stopped.

### 3.3 Visibility (`--include-predefined`)

`visibleRecords` (`vis.ts:14-19`) drops records whose `type === 'predefined'` **after** fetching, for patterns, profiles and dictionaries (not filtering profiles, which list predefined records always). The filter runs on the fetched page only, and the renderer is given `{content: visible, totalElements: visible.length}` (`pat.ts:62-66`, `prof.ts:160-164`, `dict.ts:101-105`). Consequences (captured with one predefined and two custom patterns):

- `patterns list --limit 1` (first page holds the predefined record) prints `  No data patterns found` and `  Showing 0 of 0`, exit 0, although custom patterns exist.
- `patterns list` with no `--limit` uses the server's default page size (Spring's default is 20; not verified live): a tenant with more than 20 patterns shows only the custom ones of the first 20, with `Showing <n> of <n>`.
- `--all --max 2` returns 2 records and `Showing 2 of 2`, with no sign of the cap; the cap counts predefined records that are then hidden.

### 3.4 Page status line (stderr, `view.ts:32-41`)

`  Showing <returned> of <total>[ (next --offset <k>)]`, where `next = (number+1)*size` when that is `< total`, from `page.pageable.pageNumber/pageSize` (`rdlp.ts:48-56,101-105`). Only `filtering-profiles list` passes the server envelope (`fp.ts:46-49`), so only it can print a server total and a `next` hint (captured `  Showing 1 of 2 (next --offset 1)`; with `--offset 1 --limit 1`: `  Showing 1 of 2`). The other lists always print `Showing <n> of <n>` (§3.3). With `--all` filtering profiles print `Showing <n> of <n>` too.

### 3.5 Layouts

**pretty** (stdout; `rdlp.ts:75-106`): `ui.section("<Header>:")` → `"\n  <Header>:\n\n"`, one entry per record, then `"\n"`. Empty → `"  No <header lower-cased> found\n"` (`ui.emptyList`), e.g. `  No data patterns found`, `  No data profiles found`, `  No data filtering profiles found`, `  No data dictionaries found`. Entry lines (`<x>` dim, `[…]` only when the field is set, a missing `name` or `id` prints `undefined`):

| Resource | Header | Entry |
|---|---|---|
| filtering profiles | `Data Filtering Profiles` | `  <id>\n    <name>  <cyan type or ''>[ dir:<direction>][ sev:<log_severity>][ v<version>]` |
| patterns | `Data Patterns` | `  <id>\n    <name>  <cyan type>  <status>[ <technique>][ v<version>]` |
| profiles | `Data Profiles` | `  <id>\n    <name>  <cyan type>  <profile_status>[ <profile_type>][ v<version>]` |
| dictionaries | `Data Dictionaries` | `  <id>\n    <name>  <cyan type>  <status>[ <keywords.length> kw][ v<version>]` |

Captured: `"\n  Data Patterns:\n\n  p-cus-1\n    My Pattern  custom  active regex v1\n  p-dis-1\n    Disabled Pattern  custom  disabled weighted_regex v4\n\n"`; `"\n  Data Filtering Profiles:\n\n  fp-1\n    Bulk CCN  predefined dir:c2s sev:low v1\n  fp-2\n    Custom FP  custom v2\n\n"`; `"\n  Data Dictionaries:\n\n  d-pre-1\n    Predef Dict  predefined  active v1\n  d-cus-1\n    My Dict  custom  active 2 kw v2\n\n"` (with `--keywords --include-predefined`).

**table** (stdout; `common.ts:126-139`, printed without indent): header ` <label padEnd w> ` cells joined by `│`, separator `─`×(w+2) joined by `┼`, body rows likewise, every cell followed by one space, widths in UTF-16 units over label and values, `null`/`undefined` → empty, objects `JSON.stringify`. Empty → nothing on stdout (status line still printed). Columns:

| Resource | Columns (label ← field) |
|---|---|
| filtering profiles | `ID` id, `Name` name, `Type` type, `Direction` direction, `Severity` log_severity, `Version` version |
| patterns | `ID`, `Name`, `Type`, `Status` status, `Technique` detection_config.technique, `Version` |
| profiles | `ID`, `Name`, `Type`, `Profile Type` profile_type, `Status` profile_status, `Version` |
| dictionaries | `ID`, `Name`, `Type`, `Status`, `Keywords` keywords.length (empty without `--keywords`), `Version` |

Captured: `" ID      │ Name               │ Type       │ Status   │ Technique      │ Version \n─────────┼────────────────────┼────────────┼──────────┼────────────────┼─────────\n p-pre-1 │ Credit Card Number │ predefined │ active   │ regex          │ 2       \n p-cus-1 │ My Pattern         │ custom     │ active   │ regex          │ 1       \n p-dis-1 │ Disabled Pattern   │ custom     │ disabled │ weighted_regex │ 4       \n"`.

**json**: `JSON.stringify(rows, null, 2)` of the camelised full records (§2.10), schema key order then passthrough keys; empty → `[]`. Captured (abridged): `[\n  {\n    "id": "p-cus-1",\n    "name": "My Pattern",\n    "description": "desc one",\n    "type": "custom",\n    "status": "active",\n    "version": 1,\n    "detectionConfig": {…},\n    "matchingRules": {\n      "proximityKeywords": [\n        "FAKE-PROX"\n      ],\n      "regexes": [ … "regex": "FAKE-REGEX-[0-9]+" … ]\n    },\n    "tags": {\n      "myTag": […]\n    },\n    "auditMetadata": {\n      "createdBy": "someone@example.com",\n      "updatedAt": 1700000000000\n    }\n  }, …\n]`. `markdown`/`csv`/`yaml` exist in TS (dropped in Rust).

## 4. Get commands (shared)

Request: `GET <path>/<encoded id>` (dictionaries: `?keywords=true` with `--keywords`/`--include-keywords`). Response validated by the resource schema.

**pretty** (`rdlp.ts:108-134`): `"\n  <Title>:\n\n"` (quiet-suppressed), then `ui.keyValue` over the fields whose value is not `undefined`, `null` or `''`: `"  <dim label padEnd w>  <value>\n"` with `w` the longest kept label, then `"\n"`. `Updated` is `new Date(audit_metadata.updated_at).toISOString()` when truthy (an invalid date is dropped). Server text is printed raw: a name `Evil\e[31mRED\nline2` reaches the terminal with its escape and newline (captured).

| Resource (title) | Fields in order |
|---|---|
| filtering profile (`Data Filtering Profile`) | `ID`, `Name`, `Type`, `Data Profile` (data_profile_id), `Direction`, `Severity` (log_severity), `Scan Type`, `File Based` (`yes`/`no`, always shown), `Non-File Based` (`yes`/`no`, always), `Version`, `File Types` (file_type.length), `Updated` |
| pattern (`Data Pattern`) | `ID`, `Name`, `Description`, `Type`, `Status`, `Technique`, `Confidence` (levels joined `, `), `Regexes` (count), `Version`, `Updated` |
| profile (`Data Profile`) | `ID`, `Name`, `Description`, `Type`, `Profile Type`, `Status` (profile_status), `Version`, `Updated` |
| dictionary (`Data Dictionary`) | `ID`, `Name`, `Description`, `Type`, `Status`, `Keywords` (count, only when keywords were returned), `Version`, `Updated` |

Captured: `"\n  Data Pattern:\n\n  ID           p-cus-1\n  Name         My Pattern\n  Description  desc one\n  Type         custom\n  Status       active\n  Technique    regex\n  Confidence   high\n  Regexes      1\n  Version      1\n  Updated      2023-11-14T22:13:20.000Z\n\n"`; `"\n  Data Filtering Profile:\n\n  ID              fp-1\n  Name            Bulk CCN\n  Type            predefined\n  Data Profile    11995031\n  Direction       c2s\n  Severity        low\n  Scan Type       include\n  File Based      yes\n  Non-File Based  no\n  Version         1\n  File Types      2\n  Updated         2023-11-14T22:13:20.000Z\n\n"`. Pretty never prints regexes, keywords, proximity keywords or rule trees.

**table** (`view.ts:63-88`): a `Key │ Value` table of the camelised record in record order, object values as compact JSON (captured `matchingRules │ {"proximityKeywords":["FAKE-PROX"],"regexes":[{"regex":"FAKE-REGEX-[0-9]+","weight":1}]}`, `keywords │ ["FAKE-KEYWORD-1","FAKE-KEYWORD-2"]`).

**json**: the camelised record, 2-space indent. Dictionary `status` and `version` are passthrough keys (not in `DictionaryResponseSchema`), so they print last (captured).

## 5. Write acknowledgements

### 5.1 `emitAck(verb, item, fmt)` (`rdlp.ts:136-160`)

The ack object is `{action: verb}` plus, when not null, `id`, `name`, `type`, `status` (from `status`, overwritten by `profile_status`), `version`, in that order. Verbs: `created`, `replaced`, `patched`.

- pretty: `"  ✓ <verb> <id or ''>  <name or ''>[ v<version>]\n"` on stdout (green, not quiet-suppressed); captured `"  ✓ created new-112  NP1 v1\n"`, `"  ✓ replaced fp-1   v2\n"` (filtering profile without name).
- json: the ack object; captured `{\n  "action": "created",\n  "id": "new-114",\n  "name": "NP2",\n  "type": "custom",\n  "status": "active",\n  "version": 1\n}\n`.
- table: one-row table whose columns are the ack keys; captured `" action  │ id      │ name │ type   │ status │ version \n─────────┼─────────┼──────┼────────┼────────┼─────────\n created │ new-116 │ NP3  │ custom │ active │ 1       \n"`.

### 5.2 Id acks

`patterns delete` → `"  ✓ archived <id>\n"`; `dictionaries delete` → `"  ✓ deleted <id>\n"`; dictionary replace 204 without a readable re-get → `"  ✓ replaced <id> (state not echoed by region)\n"`. All on stdout, in every format (the fallback ignores `--output json`, captured).

## 6. Body escape hatches (`parseBody`, `patch.ts:53-79`)

- Order: `--body-file` wins, then `--body -` (all of stdin, UTF-8, no size cap; blocks on a terminal), then `--body <json>`. The text is `JSON.parse`d; failure → `invalid JSON in body: <V8 message>`.
- **The V8 message quotes the input**: `--body 'PRIVATE-REGEX-123'` → `invalid JSON in body: Unexpected token 'P', "PRIVATE-REGEX-123" is not valid JSON`; a file `{"PRIVATE": x}\n` → `… "{"PRIVATE": x}\n" is not valid JSON` (newline included); long inputs are excerpted (`…"TE-KEY": nope}"`) (captured, patterns). Profiles replace it with `Cannot read profile body as JSON; verify the file and JSON syntax` (`prof.ts:94-98`); dictionaries with `Invalid JSON in dictionary metadata file` (`dict.ts:13-26`).
- File errors are the raw Node messages: `ENOENT: no such file or directory, open 'missing.json'`, `EISDIR: illegal operation on a directory, read` (paths as typed, no content). Paths are relative to the working directory and follow symlinks; there is no size limit or regular-file check (`/dev/stdin` works as a `--body-file`, captured).
- Quirks (patterns and filtering profiles, `pat.ts:40-47`, `fp.ts:21-28`): the hatch is used only when `opts.body || opts.bodyFile` is truthy, so `--body ''` and `--body-file ''` fall through to the flag builder (`--name is required`); a parsed `null`, `0`, `false` or `""` gives `--body or --body-file was empty`; `[]` reaches the SDK (`<root>: invalid_type`); empty stdin gives `invalid JSON in body: Unexpected end of JSON input`. When both `--body` and `--body-file` are given, the file wins silently; any build flags given with a body are ignored silently (captured: `--body '{…"name":"B1"…}' --name ignored` sent `B1`).
- Profiles (`prof.ts:83-101`): `--body` and `--body-file` together → `--body and --body-file are mutually exclusive` (exit 2); the body must be a JSON object (`Profile body must be a JSON object`), with `validateProfileName` and `validateProfileType` applied (§10.2).

## 7. Merge patch (`--set`/`--clear`, `buildMergePatch`, `patch.ts:10-51`)

- `--set k=v`: split at the first `=`; `eq < 1` → `--set expected key=value, got: <entry>`; a key containing `.` → `--set <key>: use --body-file for nested fields`; the raw value `null` → `--set <key>=null: to clear a field, use --clear <key>`. Value coercion: `true`/`false` → booleans; `^-?\d+(\.\d+)?$` → number; a value starting with `{`, `[` or `"` → `JSON.parse`, falling back to the raw string on failure (`bad='{oops'` sent as `"{oops"`); otherwise the string. `'"5"'` → string `"5"`; `'"null"'` → string `null`.
- `--clear k`: `k: null`; a dotted key → `--clear <key>: use --body-file for nested fields`. Clears are applied after sets, so `--set k=v --clear k` sends `k: null`. Repeated `--set` of one key keeps the last.
- No flags → `{}`; the SDK patch schema then fails (§2.6).
- `--body-file` together with `--set` or `--clear` → `--body-file is mutually exclusive with --set/--clear` (exit 2, before any request; checked after the tenant/output resolution).
- Captured patterns PATCH body for `--set name=My --set type=custom --set 'detection_config={"technique":"regex"}' --set n=5 --set s='"5"' --set b=true --set arr='[1,2]' --set bad='{oops' --clear description`: `{"name":"My","type":"custom","detection_config":{"technique":"regex"},"description":null,"n":5,"s":"5","b":true,"arr":[1,2],"bad":"{oops"}` (schema order, then passthrough).
- Error text exposure: patterns print the `buildMergePatch` messages, which echo the entry (`--set expected key=value, got: PRIVATEk`). Profiles map every build or parse failure to `Invalid profile patch: verify JSON syntax and --set key=value/--clear key flags`; dictionaries to `Invalid dictionary patch flags: use --set key=value, --clear key, or --body-file for nested fields` (captured).
- Required fields per resource (§2.6): a patch that does not repeat `name`, `type`, `detection_config` (patterns), `name`, `profile_type` (profiles) or `name`, `category`, `original_file_name` (dictionaries) is refused locally (patterns: the SDK message, exit 2; profiles: `Profile name is required and must be a nonblank string`; dictionaries: `Invalid dictionary metadata: verify required fields and value types`).

## 8. `filtering-profiles`

### 8.1 `list` and `get`

§3, §4. Visible records include predefined ones; no visibility filter.

### 8.2 `replace <id>` (`fp.ts:68-98`, `bb.ts:99-117`)

- Order: `preAction` (debug) → `resolveReplaceBody` (body or flags) → `resolveOutput` (tenant, format) → client (credentials) → `PUT /v2/api/data-filtering-profiles/<id>` with the body → ack `replaced`. Every failure exits 2 (§2.4).
- Flag builder: `--file-based` and `--non-file-based` are both required (`--file-based and --non-file-based are both required`); as presence flags they can only send `true`, so `false` needs `--body`. Then `description`, `direction`, `log_severity`, `scan_type`, `data_profile_id` (`asNum`: `abc` is dropped silently, `1e3` → `1000`), `euc_template_id`, `is_end_user_coaching_enabled`, `is_granular_profile`, `file_type[]` (captured body `{"file_based":true,"non_file_based":true,"description":"d","direction":"UPLOAD","log_severity":"HIGH","scan_type":"exclude","data_profile_id":123,"euc_template_id":"e1","is_end_user_coaching_enabled":true,"is_granular_profile":true,"file_type":["pdf","docx"]}`). Enum values are not lower/upper-cased (`--direction sideways` → SDK `direction: invalid_enum_value`).
- **Full replace without a read**: the PUT carries no `name` and none of `criteria_details`, `exception_rules`, `exclusions`, `rule1`, `rule2`, so a flag-built replace drops whatever the server stored there (to the extent the server treats PUT as a replace). There is no read, no predefined check (captured PUT on the predefined `fp-1`), no confirmation and no `--dry-run`.

## 9. `patterns`

### 9.1 Body builder (`buildPatternBody`, `bb.ts:65-93`)

- `--name` required (`--name is required`). `type` = `--type ?? 'custom'`; `detection_config = {technique: --technique ?? 'regex', supported_confidence_levels?}` from `--confidence-levels` split on `,`, trimmed, empties dropped (`'high, low,'` → `["high","low"]`).
- `matching_rules` (only when a key is set): `delimiter`; `proximity_distance` = `asNum(--proximity-distance)` (`abc` → `undefined`, and `matching_rules: {}` is still sent, captured); `proximity_keywords`; `regexes` = each `--regex` as `{regex, weight: 1}`, then each `--weighted-regex` split at the **last** `|` (`'A|B|2.5'` → `{regex:"A|B", weight:2.5}`; no `|` → `--weighted-regex must be 'PATTERN|weight' (got 'abc')`; non-finite weight → `--weighted-regex weight invalid in 'a|zz'`; `'a|'` → weight `0`, accepted, captured).
- `tags` from `--tag k=v[,v…]`: values split on `,`, trimmed, empties dropped, appended per key across repeats (`--tag 'compliance=PCI, HIPAA' --tag compliance=SOX --tag geo=` → `{"compliance":["PCI","HIPAA","SOX"],"geo":[]}`); no `=` → `--tag must be 'key=value' (got 'foo')`; empty key → `--tag missing key (got '=v')`.
- Body order (as sent): `name, type, detection_config, description, matching_rules, tags`. `--type predefined` is accepted by the SDK schema and sent (captured).

### 9.2 `create` and `replace <id>` (`pat.ts:72-117`)

Order: `resolveOutput` (tenant, format) → body (hatch or builder) → client → SDK schema → token → `POST /v2/api/data-patterns` or `PUT /v2/api/data-patterns/<id>` → ack `created`/`replaced`. Replace requires `--name` too and defaults `type` to `custom`: `patterns replace p-pre-1 --name Hijack` sent `{"name":"Hijack","type":"custom","detection_config":{"technique":"regex"}}` to a predefined pattern (captured). Every failure exits 2.

### 9.3 `patch <id>` (`pat.ts:119-147`)

Order: `resolveOutput` → mutual-exclusion check → body (`--body-file` via `parseBody`, or `buildMergePatch`) → client → SDK patch schema → `PATCH` (`application/merge-patch+json`) → ack `patched`. No predefined check (captured PATCH of `p-pre-1` with `type: predefined`).

### 9.4 `delete|rm <id>` (`pat.ts:149-159`)

Client → `DELETE /v2/api/data-patterns/<id>` (204) → `  ✓ archived <id>`. No read, no predefined check (captured `archived p-pre-1`), no confirmation, no `--force`. The service archives (soft delete): the record stays readable with `status: "deleted"` (docs-site `runtime/dlp/overview.md`).

## 10. `profiles`

### 10.1 Builder (`bb.ts:127-213`)

- `validateProfileFlags`: `--name` required (`--name is required`); `validateProfileName`: a nonblank string (`Profile name is required and must be a nonblank string`) of at most 32 characters (`Profile name must be at most 32 characters`; the live API rejected 33, `bb.ts:143-146`); `validateProfileType`: `basic` → `Basic profile writes are unsupported: the API returned advanced for basic requests. Use advanced or manage basic profiles in SCM.`, any other non-`advanced` value → `Profile type must be advanced`; `--combinator` (lower-cased) ∈ `and|or|not|and_not|or_not` (`--combinator must be one of and|or|not|and_not|or_not`); `--confidence` ∈ `low|medium|high` (`--confidence must be low|medium|high`, case-sensitive).
- Body: `{name, profile_type: "advanced", description?, is_granular_data_profile?, detection_rules?}`. With `--pattern-id`: one `expression_tree` rule with `operator_type` = combinator and one leaf per `--pattern-id` **including duplicates** (captured three leaves for `p-cus-1, p-pre-1, p-cus-1`): `rule_item {id, name, version, detection_technique: pattern technique, confidence_level, supported_confidence_levels: pattern levels or [confidence], match_type: "include", occurrence_operator_type: "more_than_equal_to", occurrence_count: 1}`. A pattern whose levels exclude `--confidence` → `Requested confidence is not supported by every referenced pattern` (exit 2, after the GETs).
- Without `--pattern-id` the body has no `detection_rules`, which the SDK schema requires: `profiles create --name x` → `Invalid profile metadata: verify required fields and value types` (exit 2, no request, captured).

### 10.2 `create` and `replace <id>` (`prof.ts:83-141,170-215`)

Order: `resolveOutput` → `validateProfileType(--profile-type)` (even with a body) → body hatch (mutual exclusion, parse, object, name, type) **or** flag validation → pattern resolution → build → client → SDK schema → `POST /v2/api/data-profiles` or `PUT /v2/api/data-profiles/<id>` → ack.

Pattern resolution (flags only): for each **distinct** `--pattern-id` in first-appearance order, `GET /v2/api/data-patterns/<id>` (reads, SDK retries). The record must have the same `id`, a `name`, a `detection_config.technique` and an integer `version ≥ 1`, else `Referenced pattern did not return a matching ID, name, technique, and version; no profile was written` (exit 1); `status !== 'active'` → `Referenced pattern is not active; no profile was written` (exit 1); a 404 → `Error: AISEC_CLIENT_SIDE_ERROR:API error 404; Not Found` + `HTTP 404` (exit 1). Predefined patterns may be referenced. Captured request sequence for `create --pattern-id p1 --pattern-id p2`: `token, GET p1, GET p2, POST` (`dlp-profile-pattern-flags.spec.ts:124-179`). No predefined check on replace (captured PUT to `dp-pre-1`).

### 10.3 `patch <id>` (`prof.ts:217-253`)

Order: `resolveOutput` → mutual exclusion → body (`--body-file` or `--set/--clear`; failures masked, §7) → `validateBodyType` (object, `name` nonblank ≤ 32, `profile_type` advanced or absent) → `PATCH`. A missing `name` gives `Profile name is required and must be a nonblank string`. `--set profile_status=deleted` is passed through (captured on the predefined `dp-pre-1`; docs say the live API answered 500).

### 10.4 `delete|rm <id>` (`prof.ts:255-266`)

No tenant, no client, no request; stderr (exit 2):

```
\n  ✗ This DLP API has no DELETE for data profiles.
  Status-based retirement is not live-verified: the latest owned-fixture
  PATCH/PUT returned HTTP 500; an advertised DELETE returned HTTP 501.
  No API request was sent by this command. Do not assume the profile was removed.
  Inspect current state with: airs-cli runtime dlp profiles get <id> --output json\n\n
```

The id is echoed raw. `dlp-delete-safety.spec.ts` pins exit 2, no fetch, the texts `not live-verified` and `No API request was sent`, and the absence of `--set profile_status`.

## 11. `dictionaries`

### 11.1 `list` and `get`

§3, §4, with `--keywords`/`--include-keywords` → `keywords=true`. With it, pretty and table lists show counts; `json` lists and `table`/`json` gets print the **full keyword list** (captured `"keywords": ["FAKE-KEYWORD-1", "FAKE-KEYWORD-2"]`).

### 11.2 Metadata (`buildMetadata`, `dict.ts:55-70`)

- `--metadata-file` wins over all metadata flags silently: the file is read (UTF-8), parsed (`Invalid JSON in dictionary metadata file`, exit 2) and must be an object (`Dictionary metadata must be a JSON object`, exit 2); it is sent **as is**, with no `original_file_name` added from `--file`.
- Otherwise `--name`, `--category`, `--region` and `--file` are all required (`--name, --category, --region, and --file are required`, exit 2), and the metadata is `{name, category, region_name: --region, original_file_name: basename(--file), description?, classification?}` (undefined keys dropped by `JSON.stringify`). The category is not checked client-side (`--category Bogus` was sent, captured).
- Then `--file` is required in every case (`--file is required (multipart upload)`, exit 2) and read whole with `readFile` (bytes; no size cap, no UTF-8 or CSV-header check; `ENOENT` → exit 1).

### 11.3 Multipart layout (`SDK:13137-13153`, undici `FormData`)

`POST /v2/api/dictionaries[?keywords=true]` (create) or `PUT /v2/api/dictionaries/<id>[?keywords=true]` (replace), `Content-Type: multipart/form-data; boundary=----formdata-undici-<12 digits>`. Captured body:

```
------formdata-undici-043350386432\r\n
Content-Disposition: form-data; name="json"; filename="metadata.json"\r\n
Content-Type: application/json\r\n
\r\n
{"name":"D1","category":"Confidential","region_name":"United States","original_file_name":"kw.txt","description":"dd","classification":"pab"}\r\n
------formdata-undici-043350386432\r\n
Content-Disposition: form-data; name="file"; filename="kw.txt"\r\n
Content-Type: application/octet-stream\r\n
\r\n
FAKE-KW-A\nFAKE-KW-B\n\r\n
------formdata-undici-043350386432--\r\n
```

The file part's filename is `metadata.original_file_name`; a metadata file without it sends `filename="blob"` (captured). `--include-keywords` adds `keywords=true` to the query (create and replace).

### 11.4 `create` (`dict.ts:111-138`)

Order: `resolveOutput` (tenant, format) → metadata → `--file` check → file read → client → POST → ack `created`.

### 11.5 `replace <id>` (`dict.ts:159-193`, `svc/dictionaries.ts:36-47`)

Order: metadata → `resolveOutput` → `--file` check → file read → client → PUT. A 200 body → ack `replaced`. A 204 (empty body, `allowEmptyBody`) → `GET /v2/api/dictionaries/<id>` (no `keywords`, reads with retries) → ack from it; if that GET fails → `  ✓ replaced <id> (state not echoed by region)` on stdout, exit 0 (captured: PUT, then 6 GETs against 500). No predefined check (captured PUT to `d-pre-1`).

### 11.6 Upload errors (`dict.ts:36-52`)

A 400 whose problem has no `detail` and no `errors` first prints, uncoloured and unindented on stderr, `Dictionary upload rejected. Verify the SCM region display name (for example, --region "United States"); region codes such as GLOBAL or us-west-2 are not equivalent.`, then the `fail` block (captured, also for a non-JSON 400 body). Field errors print as allowlisted problem text: `AISEC_CLIENT_SIDE_ERROR:API error 400; Bad Request; originalFileName: must not be blank` (`dlp-dictionary-errors.spec.ts:120-145`).

### 11.7 `patch <id>` (`dict.ts:195-227`)

Order: `resolveOutput` → mutual exclusion → body (`--body-file` through `readMetadata`, so it must be a JSON object; or `--set/--clear`) → SDK patch schema (masked) → `PATCH` → ack. Captured body: `{"category":"Legal","name":"N","original_file_name":"kw.txt","description":null}`.

### 11.8 `delete|rm <id>` (`dict.ts:229-239`)

Client → `DELETE /v2/api/dictionaries/<id>` → `  ✓ deleted <id>`. No read, no predefined check (captured `deleted d-pre-1`), no confirmation.

## 12. Predefined resources and delete safety (TS state)

| Operation | Read first? | Predefined check | Confirmation |
|---|---|---|---|
| `patterns\|profiles\|dictionaries list` | — | hidden by default (§3.3) | — |
| `filtering-profiles list` | — | shown | — |
| `filtering-profiles replace` | no | none (PUT sent to predefined `fp-1`) | none |
| `patterns replace`, `patch` | no | none (PUT/PATCH sent to `p-pre-1`; replace also rewrites `type` to `custom`) | none |
| `patterns delete` | no | none (`archived p-pre-1`) | none |
| `profiles replace`, `patch` | no | none (PUT/PATCH sent to `dp-pre-1`) | none |
| `profiles delete` | — | refused for every profile (no request) | — |
| `dictionaries replace`, `patch` | no | none | none |
| `dictionaries delete` | no | none (`deleted d-pre-1`) | none |
| create bodies | — | `type: predefined` accepted (patterns: SDK enum; dictionaries: unvalidated metadata) | — |

What the live service does with such writes is unknown (no TS test or doc covers it). `is_parent_managed` (present in every DLP response schema) is not consulted anywhere.

## 13. Sensitive-data exposure (TS)

| Where | What can leak |
|---|---|
| `--body`/`--body-file`/stdin JSON errors (patterns, filtering profiles) | an excerpt of the input (regexes, keywords, metadata) in `invalid JSON in body: …` (§6) |
| `--set` errors (patterns) | the whole entry (`got: <entry>`, §7) |
| `--tag`, `--weighted-regex` errors | the tag or regex value (`got '<v>'`, `in '<r>'`) |
| argv | regexes (`--regex`, `--weighted-regex`), proximity keywords, `--body` JSON are on the command line (process list, shell history) |
| stdout `json`/`table` | full regexes, proximity keywords, tag values, rule trees; dictionary keywords with `--keywords`; `audit_metadata` user identities (`createdBy` e-mail). Pretty shows counts only. Acks show id, name, type, status, version only |
| server text | printed raw (no control-character filtering, §4); error bodies reduced to allowlisted problem fields (§2.4) |
| SDK schema errors | field paths and zod codes only |
| `--debug` file and `PANW_AI_SEC_DEBUG` | bodies omitted; method, URL with query, status, headers (Authorization hashed) |
| file reads | `--body-file`, `--metadata-file`, `--file` read with no regular-file check or size cap; errors print the path |

## 14. `runtime dlp generate` (dropped in Rust)

Registered by `idx.ts:19` after `dictionaries` (`gen.ts:49-93`): `generate [options]`, `Generate clean + dirty DLP test files (synthetic sensitive data) across PDF/PNG/JPEG/SVG/DOCX`; options `--types <list>` (default `"all"`), `--count <n>` (default `"1"`), `--out <dir>` (default `"./temp"`), `--techniques <list>` (default `"all"`), `--seed <n>`, `--output <format>` (`Summary format: pretty or json`, default `"pretty"`). It lazily imports optional native dependencies (`sharp`, `pdf-lib`, `docx`, `piexifjs`; `DLP generate requires optional dependencies. Install them with: pnpm add sharp pdf-lib docx piexifjs`). Usage errors exit 2 (`Unknown type(s): bogus. Valid: pdf, png, jpeg, svg, docx`, captured). It appears in the `runtime dlp` group help and description. In Rust it is not a command, exactly like `redteam judge` (DESIGN §15.1): clap reports an unrecognised subcommand (exit 2, D1), the group help lists no `generate`, and the group description loses the word. `tests/unit/dlp/**` and `dlp-generate-*.spec.ts` test only `generate` and are not ported.

## 15. TS specs to port

| TS spec | Behaviour to port as executable tests |
|---|---|
| `tests/unit/cli/dlp-build-body.spec.ts` | §9.1 builder (defaults, weighted regex last pipe and errors, confidence CSV, tags CSV and errors, proximity fields), §8.2 builder (both booleans required, optional fields), §10.1 builder (32-char name, advanced default, OR default, combinator, unresolved pattern, confidence support, basic refusal) |
| `tests/unit/cli/dlp-patch.spec.ts` | §7 coercion table, `--set k=null` refusal, dotted keys, malformed entries, empty patch; `parseBody` file, stdin, malformed |
| `tests/unit/cli/dlp-renderer.spec.ts` | §3.5/§4 json is the full camelised record, list json a bare array, §5 acks, `archived`/`deleted` lines, 204 fallback line |
| `tests/unit/cli/dlp-visibility.spec.ts` | §3.3 predefined hidden by default, shown with the flag |
| `tests/unit/cli/dlp-delete-safety.spec.ts` | §10.4 no request, exit 2, texts |
| `tests/unit/cli/dlp-debug.spec.ts` | §2.9 bodies never logged, status and URL kept, before and after placement of `--debug` |
| `tests/unit/airs/dlp/*.spec.ts` | request shapes per operation (§3.2, §8–§11), dictionary replace 200/204/re-get/fallback, `client-wiring.spec.ts`: the DLP base comes only from the tenant's `dlpEndpoint` or the default |
| `tests/integration/dlp-dictionary-errors.spec.ts` | §11.3 multipart parts, §11.6 field errors exit 1 and the region hint, usage errors before any request, no echo of keyword or metadata values, debug bodies omitted |
| `tests/integration/dlp-profile-pattern-flags.spec.ts` | §10.2 GET sequence and leaf shape, missing/inactive/mismatched patterns stop before the write, basic refusals, 32/33-character names for flags and raw bodies |
| `tests/integration/dlp-tenant-auth.spec.ts` | the selected tenant's credentials and `dlpEndpoint` for every group; per-tenant TSG; environment credentials ignored; tenant files unchanged |
| `tests/unit/backup/dlp-resources.spec.ts`, `tests/integration/dlp-transfer-contract.spec.ts` | backup/restore spec (not here) |
| `tests/unit/dlp/**`, `dlp-generate-*.spec.ts` | not ported (generate dropped) |

## 16. Rust SDK (`scm-sdk` 0.1.0) coverage

- Feature `dlp` (`scm-sdk-0.1.0/Cargo.toml:53`) must be enabled in airs-cli's `scm` dependency; `DlpClient::new(oauth_client)` takes the management OAuth client with an explicit DLP base (`rs:dlp/mod.rs:51-54`).
- Every operation the CRUD port needs exists: filtering profiles `list`/`get`/`replace` (`rs:dlp/filtering_profiles.rs:19-74`), patterns `list`/`create`/`get`/`replace`/`patch`/`delete` (`rs:dlp/data_patterns.rs:19-111`), profiles `list`/`create`/`get`/`replace`/`patch` and no `delete` (`rs:dlp/data_profiles.rs`, matching the API), dictionaries `list`/`get(include_keywords)`/`create`/`replace → Option`/`patch`/`delete` (`rs:dlp/dictionaries.rs:55-186`), plus `list_pages`/`list_all` with item/page caps. **No blocking SDK gap for the CRUD commands.**
- Differences from the TS SDK the port inherits (record as §12 rows or design notes):
  - Spring query validation: `size == 0`, more than 128 `sort` values, an empty or control-character sort value are `Validation` errors before sending (`rs:dlp/common.rs:76-99`); an empty non-final page is a `Pagination` error (`rs:dlp/common.rs:129-131`).
  - Dictionary metadata is validated with `DictionaryRequestSchema` before upload (`rs:dlp/dictionaries.rs:100-103`): `category` must be one of the 9 values, `name`, `original_file_name`, `region_name` required. TS sends any metadata (§11.2).
  - The file part's filename comes from `metadata.original_file_name` through `BinaryFile::with_filename`, which refuses empty, `.`, `..`, longer than 255 bytes, control characters, `/`, `\` and `"` (`rs:models/support.rs:305-319`); default part type `application/octet-stream` and filename `blob` (`rs:multipart.rs:46-54`), as TS.
  - Request bodies are capped at 8 MiB (`max_request_bytes`, `rs:config.rs:289`), multipart included (`rs:dlp/dictionaries.rs:98-104`). TS has no cap.
  - Path segments are validated (`rs:config.rs:121-133`, §2.7).
  - Unknown (passthrough) keys live in `Extensions`, a `BTreeMap` (`rs:models/support.rs:9`), so they serialise sorted; TS keeps input order. Known keys follow schema order in both. JSON parity comparisons must be order-insensitive for extension keys.
  - Response enums are strict in both SDKs (§2.6).
- G10: not applicable to DLP (§2.6). Neither DLP output nor a DLP backup will show fabricated defaults with 0.1.0.

## 17. Live-tier notes

- **Data profiles cannot be deleted.** The API has no working DELETE (501 per docs) and TS refuses the command; docs record an orphaned live test profile. A live flow that creates a data profile cannot clean it up, which conflicts with "all deleted at the end". Unless the user accepts a retirement PATCH that is not verified (it returned 500 live), data-profile create/patch/replace cannot run live.
- **Pattern and dictionary deletes are soft** (`status: "deleted"`, still readable). The sweeper and the ledger must count an archived resource as cleaned up and must not retry its delete. Whether an archived name stays reserved is unknown; run-id-prefixed names avoid collisions.
- A pattern referenced by a profile probably cannot be deleted (unverified); with no live profile this does not arise.
- Dictionary create needs a region display name valid for the tenant; take it from configuration (for example an `AIRS_E2E_DLP_REGION` variable) or from an existing dictionary's `region_name` read during the run. Keyword files must hold only synthetic values.
- Read comparison: default listings hide predefined records and may be empty; pick "the first listed item" from an `--include-predefined` listing; compare dictionaries without `--keywords` (counts only) so keyword lists are never printed by either CLI; TS json is camelised (§2.10).

## Acceptance criteria

Each is a loopback executable test of airs-cli-rs; parity tests compare both CLIs where the behaviour is shared.

1. Every DLP command uses only the selected tenant's `mgmt*` credentials, `mgmtTokenEndpoint` and `dlpEndpoint` (default `https://api.dlp.paloaltonetworks.com`), sends `POST <token>` then `/v2/api/…` requests on the DLP base, and ignores `PANW_*` variables; tenant files are unchanged.
2. Lists send `?page&size&sort…[&keywords=true]` as §3.2 (default `sort=name,asc`), walk with `--all` under `--max`, print the §3.5 pretty and table layouts byte-for-byte and the camelised json array (`[]` when empty), and never report an incomplete or filtered page as complete or as not-found (§12 row).
3. Gets print the §4 pretty layouts (dropping empty fields, `yes`/`no` booleans, ISO `Updated`), the `Key │ Value` table and the camelised json; server text in pretty and table output goes through `terminal_safe` (multi-line descriptions through `terminal_safe_lines`).
4. List flag errors (`--limit 0|abc|1.5|-1`, `--offset -1`, `--max abc`, `--all` with `--offset`) are usage errors before the tenant is read (exit 2, §12 row); `--size`/`--page` keep their deprecation warnings (or are dropped, choice).
5. `markdown`, `csv` and `yaml` are usage errors for every DLP command, including writes.
6. Pattern, filtering-profile and profile builders produce the §8.2/§9.1/§10.1 bodies (validated with the SDK request schema before any token request); malformed flag values are usage errors that do not echo the value.
7. `--body`, `--body-file` and `--body -` follow §6 with the D103-style input rules (regular file, size cap, UTF-8, one JSON object), are mutually exclusive with each other and with build flags, and never echo body content in errors.
8. `--set`/`--clear` build the §7 merge patch with the same coercions; errors are fixed texts without the entry; required patch fields are checked before the request.
9. Profile creates and replaces with `--pattern-id` GET each distinct pattern first and stop before any write on a missing, inactive or mismatched pattern or unsupported confidence; `basic` and names over 32 characters are refused before the token.
10. Dictionary create and replace read `--metadata-file` and `--file` before the tenant, validate the metadata with the SDK schema, upload the §11.3 two-part body, print the region hint for a detail-free 400, and handle the 204 re-get (fallback per the §12 choice).
11. Every write is sent once (one replay after a 401, none after a 403); a 5xx, transport failure or deadline after dispatch reports `Outcome unknown: the <thing> may have been <done>.` and is never re-sent.
12. `patterns|dictionaries delete`, every `replace` and every `patch` read the resource first and refuse a predefined resource (`type: predefined`; choice: also `is_parent_managed: true`) before any write; create bodies with `type: predefined` are refused.
13. Deletes and replaces (and patch, choice) confirm per D81/D105: `--force` skips; no TTY and no `--force` is a usage error before the tenant; Ctrl-C at the prompt exits 130 with `Cancelled; nothing was changed.`.
14. `profiles delete` sends nothing and exits 2 with the §10.4 text (id through `terminal_safe`).
15. `--debug` for DLP records method, path, status and headers only, never bodies or queries with values beyond `page|size|sort|keywords`; no output path prints keywords, regexes or metadata from an error.
16. stdout carries data only (acks per the §12 choice), outcome lines on stderr, `--quiet` suppresses status and success lines, colour per stream.
17. SIGINT or SIGTERM during a write exits 130/143 with `Interrupted; …` naming whether the change may have been applied.

## Open questions / likely §12 divergences

Numbers are assigned by the orchestrator from D160. Each is a safety or correctness fix; **(choice)** marks those the user should confirm.

1. **Write retries (safety).** TS re-sends POST/PUT/PATCH/DELETE up to 5 times on 5xx, timeouts and transport errors (§2.5), so a create can duplicate patterns or dictionaries. Rust: D95 (one attempt, one 401 replay, no 403 replay) with `Outcome unknown: the data pattern may have been created.` and the matching `replaced`/`patched`/`deleted` words for `data pattern`, `data profile`, `dictionary`, `data filtering profile`.
2. **Predefined resources (safety).** TS sends replace, patch and delete to predefined records and accepts `type: predefined` in create bodies (§12). Rust: GET first and refuse a predefined record with a fixed message (for example `<id> is a predefined data pattern; predefined records are never modified`); refuse `type: predefined` in bodies and dictionary metadata. **(choice)** also treat `is_parent_managed: true` as read-only.
3. **Confirmations (safety).** TS never confirms. Rust: `patterns|dictionaries delete`, every `replace` (full replace) follow D81/D105 with `--force`; **(choice)** whether `patch` confirms too (recommendation: no, it changes only named fields).
4. **Filtering-profile replace (safety, choice).** A flag-built PUT drops `name`, exclusions, exception rules, criteria and rules (§8.2), and the booleans can only be `true`. Options: (a) keep PUT semantics, add the read, the predefined refusal and the confirmation; (b) read-modify-write: overlay the flags on the GET result (as D117 did for profiles), `--body` stays a raw replace. Recommendation (b) plus (a)'s checks. Never live either way.
5. **Pattern replace rewrites `type` (correctness).** Flag-built replace defaults `type` to `custom` (§9.2); Rust takes `type` from the existing record when `--type` is absent (or refuses a type change, choice).
6. **Filtered listings report wrong totals (correctness, choice).** §3.3: a page holding only predefined records reports `No data patterns found` / `Showing 0 of 0`, and capped walks say nothing. Options: (a) the default (custom-only) listing walks all pages under `--max` and applies `--limit/--offset` to the filtered list; (b) keep server paging and print the server total, the hidden count and the next offset. Recommendation (a).
7. **List flag parsing (correctness).** `--limit abc` ignored, `--limit 1.5` truncated, `--offset -5` sent as `page=-1`, `--limit 0` sent, `--all --offset` accepted, `--max abc` exit 1 after the tenant (§3.1). Rust: §7.1 messages, exit 2, before the tenant. **(choice)** keep the hidden `--size`/`--page` aliases with their warnings, or drop them (TS says "removed in v4"; the CLI is v7).
8. **Exit codes (correctness).** TS exits 2 for every failure of `filtering-profiles replace` and `patterns create|replace|patch`, including HTTP and network errors, without `HTTP` lines (§2.4). Rust: usage errors 2, operational failures 1 with the §6 lines, as every other write.
9. **Echo of sensitive input (safety).** TS prints body excerpts (`invalid JSON in body: …`), `--set` entries, tag values and regexes in errors (§13). Rust: fixed texts naming only the flag or path (`<path> is not valid JSON`, `--body is not valid JSON`, `--set expects key=value`, `--tag expects key=value`).
10. **Input files (safety).** TS reads `--body-file`, `--metadata-file`, `--file` and stdin with no regular-file check or size limit, after the tenant (§6, §11.2). Rust: D103-style rules before the tenant: regular file, ≤ 1 MiB for JSON inputs, keyword file ≤ the SDK's 8 MiB request cap minus metadata, UTF-8 for JSON (**choice:** whether the keyword file must be UTF-8; recommendation: no, bytes as given), `--body -` refused when stdin is a terminal (choice).
11. **Ambiguous inputs (correctness).** `--body` + `--body-file` (file wins), body + build flags (flags ignored), `--metadata-file` + metadata flags (flags ignored), duplicate `--pattern-id` (duplicate leaves): usage errors in Rust (**choice** for duplicates: refuse, or de-duplicate silently).
12. **Silent value loss (correctness).** `--proximity-distance abc` sends `matching_rules: {}`, `--weighted-regex 'a|'` sends weight 0, `--data-profile-id abc` is dropped, `--tag geo=` sends `[]` (§8.2, §9.1). Rust: usage errors.
13. **Ids (safety).** `''`, `.` and `..` reach the collection or `/v2/api/` (§2.7). Rust: usage errors before the tenant (the SDK refuses them anyway).
14. **Terminal safety (safety).** Names, descriptions and other server text go through `terminal_safe` (`terminal_safe_lines` for descriptions).
15. **JSON camelisation of data keys (correctness, choice).** TS renames tag keys and exclusion-list category names (§2.10). Options: (a) parity (camelise everything); (b) camelise schema field names and passthrough keys, keep map keys under `tags` and `exclusions.exclusion_list` verbatim. Recommendation (b).
16. **stdout for outcome lines (correctness, choice).** TS prints pretty acks (`✓ created …`, `archived`, `deleted`, the 204 fallback) on stdout, in every format for deletes and the fallback. DESIGN §13.2 moved such lines to stderr (D94/D106). Proposal: pretty acks on stderr (quiet-suppressed success lines), `json`/`table` acks on stdout; deletes print nothing on stdout; the 204 fallback becomes a stderr warning `replaced <id>; the service did not return the new state` and json prints the ack without a record (choice).
17. **Dictionary metadata validation (correctness).** Rust validates create/replace metadata with the SDK schema and refuses unsafe filenames (§16); TS sends any metadata. Message: `Invalid dictionary metadata: verify required fields and value types` (exit 2, as TS's patch).
18. **Keyword exposure (safety, choice).** `--keywords` prints full keyword lists in json and table. Keep (the user asked for them), but **(choice)** require `--output json` for keyword lists and print counts in pretty/table (TS already does in pretty).
19. **`--debug` (settled).** Status and headers only, never bodies; the TS file in the working directory and the empty log against non-PANW hosts become the §2.9 Rust log.
20. **Interruption (correctness).** TS exits silently on SIGINT/SIGTERM; Rust prints the §13.2 `Interrupted; …` context.
21. **`generate` (settled).** Not a command (§14); the `runtime dlp` description drops "generate".
22. **Live scope (blocker for the orchestrator).** Data profiles cannot be deleted (§17), so a live data-profile create breaks "all deleted at the end". Recommendation: live DLP writes cover a pattern and a dictionary only; data-profile writes stay loopback-only unless the user accepts a residue or an unverified retirement PATCH. Soft deletes count as cleaned.
23. **Help texts.** Empty TS help strings (`dictionaries get`, `patch`, `--name`, `--category`, `--description`, `--keywords`) and the format lists change; whether Rust fills the empty descriptions is a **(choice)** (recommendation: keep TS texts except the format line, for help parity).
