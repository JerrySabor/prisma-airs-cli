# Spec: TS `airs-cli` DLP backup and restore (M6b)

Commands covered: `runtime dlp backup` and `runtime dlp restore <file>`. The DLP CRUD
commands (`filtering-profiles`, `patterns`, `profiles`, `dictionaries`) are specified
elsewhere; this spec cites them only where backup or restore depends on them.

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`,
  7.2.1-forgejo.0, SDK `@cdot65/prisma-airs-sdk` 0.34.0, commander 14). Citations:
  - `tr.ts:<line>` is `src/cli/commands/dlp/transfer.ts` (435 lines).
  - `dr.ts:<line>` is `src/backup/dlp-resources.ts` (1529 lines).
  - `rio.ts:<line>` is `src/reports/io.ts` (`writeReportFile`); `confirm.ts:<line>` is
    `src/cli/confirm.ts`; `ui.ts`, `common.ts` are under `src/cli/renderer/`;
    `co.ts:<line>` is `src/config/client-options.ts`; `program.ts:<line>` is `src/cli/program.ts`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` of the reference build.
  - `rs:<path>:<line>` is the Rust SDK `scm-sdk-0.1.0` under `~/.cargo/registry/src/*/`.
  - Specs: `tests/unit/backup/dlp-resources.spec.ts` (1793 lines, "DR-spec") and
    `tests/integration/dlp-transfer-contract.spec.ts` (404 lines, "DT-spec"); user docs
    `docs-site/docs/runtime/dlp/transfer.md`.
- Shared shell behaviour (commander parse errors exit 1, the root `--output` consumer,
  `resolveOutput`, the `ui` stream map, quiet mode, colour, EPIPE) is specified in
  `ts-cli-shell.md` §3–§15 and `ts-renderer.md`; only what these two commands depend on is
  restated.
- **How behaviour was captured.** The reference build (`dist/cli/index.js`, node v24.21.0)
  ran against a stateful loopback stub (`node:http` on `127.0.0.1`, random port) that
  implements `POST /oauth/token` and `GET|POST <dlp>/v2/api/{dictionaries,data-patterns,data-profiles}[/<id>]`
  as Spring pages (sorted by name, `size` honoured, dictionaries optionally capped at 50 like
  the live service), parses the dictionary multipart body, logs every request (method, path,
  query, content type, JSON or multipart body) and takes a fault plan (status, body, content
  type, headers such as `x-opa-decision`, `nth` occurrence, "apply then fail", hang, dropped
  connection).
  - Sandbox: `env -i` with `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`,
    `XDG_CACHE_HOME` and the working directory inside a scratch sandbox; a TS registry
    selected through `PRISMA_AIRS_TENANTS_PATH` with two tenants, `src` (TSG `100`) and `dst`
    (TSG `200`), fake credentials (`fake-client`/`FAKE-SECRET`), and `mgmtTokenEndpoint`,
    `mgmtEndpoint` and `dlpEndpoint` (`http://127.0.0.1:<port>/dlp`) on loopback.
  - **The DLP endpoint.** `managementClientOptions` passes `dlpEndpoint: config.dlpEndpoint ??
    DEFAULT_DLP_ENDPOINT` (`co.ts:44-50`; default `https://api.dlp.paloaltonetworks.com`,
    `SDK:70`), and `ManagementClient` uses `opts.dlpEndpoint ?? DEFAULT_DLP_ENDPOINT` with **no
    environment fallback** (`SDK:13420`). The credentials and token endpoint are explicit too
    (`co.ts:34-42`), so the SDK's `PANW_MGMT_*` fallbacks are never reached; the sandbox set
    none of them. A tenant without `dlpEndpoint` would go to the production host, so every
    capture tenant set it.
  - Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and
    `dns.lookup` and refuses any host other than `127.0.0.1`. The guard log stayed empty.
  - Fake sensitive values: dictionary keywords `PRIVATE-KW-ALPHA`/`PRIVATE-KW-BRAVO`, regex
    `PRIVATE-REGEX-[0-9]{6}`, proximity keyword `PRIVATE-PROX`; error bodies echoing them.
  - Prompts were driven on a pty (python `pty.fork`); signals with `kill -INT|-TERM` during a
    hung request.
- No real tenant or credential file was read; no host other than loopback was contacted.
- Captures are shown as JSON strings. `<sb>` is the sandbox working directory (an absolute
  path). Captures are uncoloured (stdout a pipe) unless §2.6 says otherwise.

## 1. Command surface (help verified)

`runtime dlp --help` (stdout, exit 0) lists `backup [options]` (`Back up custom DLP
dictionaries (with keywords), data patterns and data profiles with their referenced
dependencies`) and `restore [options] <file>` (`Restore DLP resources into the selected
tenant, staged dictionaries → patterns → profiles; validate all dependencies before
changes`) next to the CRUD groups and `generate`. Help options are sorted (`program.ts:73-76`).

Captured `runtime dlp backup --help`:

```
Usage: airs-cli runtime dlp backup [options]

Back up custom DLP dictionaries (with keywords), data patterns and data profiles
with their referenced dependencies

Options:
  --file-format <format>  Backup file format: json or yaml (default: "json")
  -h, --help              display help for command
  --max-pages <n>         Maximum pages per inventory; incomplete exports fail
                          (default: 100)
  --output <format>       Output format: pretty, table, markdown, csv, json,
                          yaml
  --output-file <path>    New private backup file; defaults to the current
                          directory
  --resources <list>      Comma-separated primary resources: dictionaries,
                          patterns, profiles (default: all)
  --skip-unsupported      Exclude profiles with non-transferable rules
                          (multi-profile, direct EDM) instead of failing

Examples:
  $ airs-cli runtime dlp backup --output-file ./dlp-backup.json
  $ airs-cli runtime dlp backup --resources profiles --skip-unsupported --output-file ./profiles.yaml --file-format yaml

```

Captured `runtime dlp restore --help`:

```
Usage: airs-cli runtime dlp restore [options] <file>

Restore DLP resources into the selected tenant, staged dictionaries → patterns →
profiles; validate all dependencies before changes

Options:
  --dry-run                           Read and validate a restore plan without
                                      changing destination resources
  --expect-tsg <id>                   Assert destination tenant ID; required
                                      with --force
  --force                             Execute without a prompt; requires
                                      --expect-tsg and does not override
                                      conflicts
  -h, --help                          display help for command
  --max-pages <n>                     Maximum pages per inventory; incomplete
                                      inventories fail (default: 100)
  --name-prefix <prefix>              Prefix restored custom resource names to
                                      avoid collisions
  --on-conflict <policy>              Existing data profile names: error, verify
                                      (resume without writes), skip, or
                                      reconcile (verify active duplicates, and
                                      give archived-name collisions a unique
                                      suffix). Profile update is a live server
                                      error, so a divergent active profile still
                                      fails. (default: "error")
  --output <format>                   Output format: pretty, table, markdown,
                                      csv, json, yaml
  --pattern-map <source=destination>  Bind a tenant-bound or predefined source
                                      pattern to an existing destination pattern
                                      (repeatable) (default: [])
  --skip-unresolved                   Skip references with no destination match,
                                      and every profile depending on them; whole
                                      profiles only, each reported

Examples:
  $ airs-cli runtime dlp restore ./dlp-backup.json --dry-run --output json
  $ airs-cli runtime dlp restore ./dlp-backup.json --pattern-map "EDM SSN=Dest SSN" --dry-run
  $ airs-cli runtime dlp restore ./dlp-backup.json --name-prefix migrated- --expect-tsg <destination-tsg> --force

```

| Option | Registration | Parsing and default |
|---|---|---|
| backup `--resources <list>` | `tr.ts:206-210` | `resourceKinds` (`tr.ts:40-49`): split on `,`, each item trimmed; every item must be `dictionaries`, `patterns` or `profiles`, no duplicate, non-empty. It **throws** `CliUsageError` from commander's `parseArg`, which nothing catches: node prints the stack trace (`CliUsageError: --resources takes a unique list of dictionaries, patterns, profiles` + 12 frames + `Node.js v24.21.0`) on stderr, exit 1 (captured for `nope`, `patterns,patterns`, `""`). `" patterns , profiles "` is accepted. Omitted = all three (`dr.ts:368`) |
| backup `--file-format <format>` | `tr.ts:211` | default `json`; checked in the action: anything but exactly `json` or `yaml` (`YAML` included) → `--file-format must be json or yaml`, exit 2, first check, before the tenant (captured) |
| backup `--output-file <path>` | `tr.ts:212` | `-` → `Backups contain dictionary keywords and require a private file destination, not stdout` (exit 2, after the tenant load). Omitted: `airs-dlp-backup-<ISO time with : and . replaced by ->-<first 8 of a random UUID><ext>` in the working directory (`tr.ts:241-244`; captured `airs-dlp-backup-2026-10-18T13-04-14-873Z-b2beda25.json`). The path is `path.resolve`d |
| backup `--skip-unsupported` | `tr.ts:213-216` | boolean |
| `--max-pages <n>` (both) | `tr.ts:217-222`, `:317-322` | `maxPages` (`tr.ts:34-38`): `/^\d+$/`, 1..1000, else `--max-pages must be an integer from 1 to 1000` via `usageError` inside `parseArg` (exit 2, before anything; captured `0`, `1001`, `1.5`, `abc`); `007` accepted as 7; default 100 |
| `--output <format>` (both) | `tr.ts:223`, `:328` | not in `READ_COMMAND_NAMES`, so `preAction` leaves it; the action calls `resolveOutput` (loads the tenant config; `xml` → `\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n`, exit 2). A root `--output json` before the subcommand also works (captured) |
| restore `<file>` | `tr.ts:296` | required (commander `error: missing required argument 'file'`, exit 1) |
| restore `--dry-run` | `tr.ts:300` | boolean |
| restore `--name-prefix <prefix>` | `tr.ts:301` | checked in the plan (`dr.ts:789-794`): longer than 64 UTF-16 units or holding a C0 control or DEL → `Invalid --name-prefix` (plain `Error`, exit 1, no request; captured for a tab and for 65 chars). Empty allowed |
| restore `--on-conflict <policy>` | `tr.ts:302-306` | default `error`; `error|verify|skip|reconcile`, else `--on-conflict must be error, verify, skip or reconcile` (exit 2, first check) |
| restore `--pattern-map <source=destination>` | `tr.ts:307-312` | repeatable; `patternMap` (`tr.ts:51-61`): split at the **first** `=`; `=` at index 0 or at the end, or no `=` → `--pattern-map requires source-name=destination-name`; a repeated source → `Duplicate source names in --pattern-map` (both exit 2, before the file). `a=b=c` maps `a` → `b=c` |
| restore `--skip-unresolved` | `tr.ts:313-316` | boolean |
| restore `--expect-tsg <id>` | `tr.ts:323` | compared with `===` to the tenant's `mgmtTsgId` after the tenant load |
| restore `--force` | `tr.ts:324-327` | `--force` without `--expect-tsg` → `--force requires --expect-tsg <destination-tsg>` (exit 2, second check, before the file) |

`--dry-run --force` is accepted (dry run wins, `tr.ts:411-414`). There is no `--allow-other-tenant`,
`--input-dir` or overwrite option: restore never updates or deletes anything (§5.9).

## 2. Shared behaviour

### 2.1 Client, credentials and retries

- `context()` (`tr.ts:63-78`): `loadConfig()` (no tenant → `No tenant selected. Run 'airs-cli
  tenant switch <name>' (registered: src, dst)`, printed by `failure` as `  ✗ <msg>\n`, exit 1,
  captured); then `!mgmtTsgId || !mgmtClientId || !mgmtClientSecret` →
  `DLP transfer requires configured Management client ID, secret and TSG ID` (`CliUsageError`,
  `\n  ✗ …\n\n`, **exit 2**, captured), before `managementClientOptions` and its own credential
  assertion.
- `new ManagementClient({...managementClientOptions(config), numRetries: 0})`: **every**
  request (reads included) gets one attempt for 5xx, transport errors and timeouts
  (`executeWithRetry`, `SDK:9786-9850`). The auth hook still replays once (`onRetryableFailure`,
  `SDK:10215-10236`): captured `POST data-patterns` → 401 → `POST /oauth/token` → `POST
  data-patterns` (second answer wins, exit 0); a 403 without `x-opa-decision` → token → second
  `POST` (also 403, exit 1); `x-opa-decision: false` → one POST.
- Token: one `POST <mgmtTokenEndpoint>` (HTTP Basic, form `grant_type=client_credentials&scope=tsg_id%3A<tsg>`),
  cached for the process; the client is built after the file checks, and the token is fetched
  by the first DLP request (captured: argument and plan-option failures send nothing).
- `PANW_AI_SEC_TIMEOUT_MS` (default 60000, `SDK:10095`) bounds each attempt; a timeout is a
  network failure (captured with 700 ms on a hung POST: one POST, then the error).
- Every DLP request uses `safeErrorMessages: true`: an HTTP error message is
  `API error <status>` (problem-details bodies become the problem summary, `SDK:9838`), a
  transport failure `Network request failed`. The transfer commands never print those messages
  anyway (§2.4, §5.10).

### 2.2 Requests (HTTP, captured)

| Operation | Method and path | Query | Body |
|---|---|---|---|
| inventory page (dictionaries) | `GET <dlp>/v2/api/dictionaries` | `page=<n>&size=100&sort=name%2Casc&keywords=true` | – |
| inventory page (patterns) | `GET <dlp>/v2/api/data-patterns` | `page=<n>&size=100&sort=name%2Casc` | – |
| inventory page (profiles) | `GET <dlp>/v2/api/data-profiles` | `page=<n>&size=100&sort=name%2Casc` | – |
| dictionary create | `POST <dlp>/v2/api/dictionaries` | `keywords=true` | multipart (below) |
| dictionary read-back | `GET <dlp>/v2/api/dictionaries/<id>` | `keywords=true` | – |
| pattern create | `POST <dlp>/v2/api/data-patterns` | – | JSON `DataPatternRequest` |
| pattern read-back | `GET <dlp>/v2/api/data-patterns/<id>` | – | – |
| profile create | `POST <dlp>/v2/api/data-profiles` | – | JSON `AdvancedDataProfileRequest` |
| profile read-back | `GET <dlp>/v2/api/data-profiles/<id>` | – | – |

- Ids are `encodeURIComponent`-encoded path segments. Headers: `User-Agent`, `service-name: api`,
  `Authorization: Bearer <token>`, `Content-Type: application/json` with a JSON body.
- **Dictionary multipart** (`buildFormData`, `SDK:13144-13153`; captured with node `FormData`):
  two parts in this order: `json` (filename `metadata.json`, `Content-Type: application/json`,
  the `DictionaryRequest` JSON) and `file` (filename = `metadata.original_file_name`,
  `Content-Type: text/plain`, the keyword text of §5.6). Captured metadata
  `{"category":"Confidential","name":"Secret Words","original_file_name":"words.txt","region_name":"United States","description":"kw dict","is_case_sensitive":false}`
  and file `"PRIVATE-KW-ALPHA\nPRIVATE-KW-BRAVO\n"`.
- No `PUT`, `PATCH` or `DELETE` is ever sent by either command (DT-spec asserts this,
  `dlp-transfer-contract.spec.ts:108`). Filtering profiles are never read or written.

### 2.3 Inventories (`springPages`, `dr.ts:111-252`)

`inventories()` reads dictionaries, then patterns, then profiles, each with its own sweep, in
that order, sequentially. Per sweep, pages `0, 1, …` up to `--max-pages`, each requested with
`size=100` and `sort=name,asc` (the "live-verified stable name sort", DR-spec:357). Every page is
checked against all metadata it supplies, camelCase and snake_case alike (`alias` rejects a pair
that disagrees):

- the effective page size is the first supplied `size` / `pageable.pageSize|page_size`
  (1..100, then constant), else 100 (the live dictionaries cap is 50, DR-spec:484);
- `number`, `numberOfElements|number_of_elements`, `first`, `empty`, `pageable.pageNumber|page_number`,
  `pageable.offset` must equal the page index, content length, `page === 0`, length `=== 0`,
  index and `index * size`;
- `totalPages|total_pages` and `totalElements|total_elements` must be non-negative safe
  integers, constant across pages, consistent with each other (`totalPages ===
  ceil(totalElements / size)`), with the page index (`page < max(totalPages, 1)`), with each
  page's length, and with `last`;
- ids must be non-empty strings and unique across the sweep;
- more than 10000 records in one sweep → `Inventory of <label> exceeds the 10000-record safety limit`;
- an empty non-last page → `Inventory of <label> did not advance`;
- `last` is `result.last`, else derived from the totals, else `content.length < size`;
- after `--max-pages` pages without `last` → `Inventory of <label> is incomplete: increase --max-pages`
  (captured with 51 dictionaries, cap 50, `--max-pages 1`).

Labels are `dictionaries`, `data patterns`, `data profiles`. The other messages are
`Inventory of <label> has inconsistent pagination metadata; retry the operation`,
`Inventory of <label> contains a missing resource ID; retry the operation`,
`Inventory of <label> contains duplicate resource IDs; retry the operation`. They never quote
content. Each is a plain `Error` → `  ✗ <message>\n` on stderr, exit 1. A page that fails the
SDK response schema is not a `ZodError` at this level: the SDK wraps it as `AISecSDKException`
(`Response did not match schema: …`, `SDK:10264-10269`), so it prints the §2.4 API row.

Captured with 51 dictionaries and a cap of 50: `page=0`, `page=1` for dictionaries, one page each
for patterns and profiles.

### 2.4 Errors and exit codes (`failure`, `tr.ts:80-96`)

| Thrown | Printed (stderr) | Exit |
|---|---|---|
| `CliUsageError` | `usageError`: `"\n  ✗ <msg>\n\n"` | 2 |
| `ZodError` (the backup envelope schema, or a request schema in the plan) | `  ✗ Invalid DLP backup/request schema; content is not logged.` | 1 |
| `AISecSDKException` (HTTP, transport, timeout, response schema; inventories and backup reads) | `  ✗ DLP transfer API request failed[ (HTTP <status>)]; no automatic retry was made.` (captured `(HTTP 500)`; connection refused and timeouts without the status) | 1 |
| an error with an errno `code` | `  ✗ DLP transfer file operation failed (<code>); existing files are not overwritten.` (captured `EEXIST`, `ENOENT`) | 1 |
| any other `Error` | `  ✗ <message>` (plan and backup messages of §4, §5) | 1 |

`ui.error` lines are `"  " + red("✗ " + msg) + "\n"` on stderr, not quiet-suppressed. The exit
is `process.exitCode = 1`, so stdout written earlier stays (the pretty `ℹ` lines). A restore
that started writing reports its own failure (§5.10) and exits 1 the same way.

### 2.5 Streams, quiet and formats

- `ui.info` (`  ℹ <msg>`, cyan, **stdout**, quiet-suppressed): the progress lines, only when the
  resolved format is `pretty` (`progressRenderer`, `tr.ts:109-124`).
- `ui.bullet(..., 'success'|'skip')` (`  ✓ <msg>` green glyph / `  ○ <msg>` yellow glyph,
  **stdout**, **not** quiet-suppressed): restore's per-item progress in pretty. Under `--quiet` a
  pretty restore keeps the `✓` lines above the summary (captured).
- `ui.warning` (`  ⚠ <msg>`, yellow, stderr, never suppressed): skipped profiles (backup),
  unresolved references and skipped profiles (restore).
- `console.log(formatOutput(...))`: the result, stdout. `formatOutput` (`common.ts:96-142`):
  `json` = `JSON.stringify(rows, null, 2)` (always a one-element **array**), `yaml` =
  `js-yaml dump(rows)`, `csv` with quoting of `",\r\n`, `markdown` pipe tables, `table` the box
  table (` <label padded> │ …`, separator `─` × (width + 2) joined by `┼`, cells padded with
  `padEnd` to the UTF-16 width, objects as `JSON.stringify`, `null`/`undefined` as empty).
- The confirmation prompt (inquirer) writes to **stdout**, also in `--output json` mode
  (captured: the prompt text precedes the JSON array on the pty).
- `--debug` (`program.ts:113-191`): for any `runtime dlp` command `PANW_AI_SEC_DEBUG_BODY` is
  forced to `0` and the CLI logger omits bodies (`omitBodies`). The logger writes
  `./debug-api-<ms>-<8 hex>.jsonl` (0600) and prints `  Debug: API log → <abs path>` (dim,
  stderr); it logs only AIRS/SCM hosts (`api.dlp.paloaltonetworks.com` included), so the
  loopback capture produced an empty file and the backup ran normally. Unlike profile transfer,
  `--debug` is **not** refused for DLP transfer.

### 2.6 Colour (captured with `FORCE_COLOR=1`)

`ℹ` lines `\x1b[36m…\x1b[39m` (whole line after the indent), `✓` glyph `\x1b[32m✓\x1b[39m` (glyph
only), `⚠` lines `\x1b[33m…\x1b[39m`, `✗` lines `\x1b[31m…\x1b[39m`. Tables and the restore
headings are never coloured. `NO_COLOR` is not honoured by chalk here (`ts-cli-shell.md`).

### 2.7 Interruption

No signal handler. SIGINT/SIGTERM kill the process by signal (exit 130/143, captured for a
restore with a hung `POST data-patterns` and a backup with a hung profile inventory). Nothing
is printed after the last progress line; an in-flight create is dropped with unknown outcome and
no message; completed creates stay. A backup interrupted before `link` leaves no file (the
temporary is not cleaned up by a signal kill: `.airs-report-<uuid>.tmp` can remain, by code;
the captured interruption came before the temporary was opened).

## 3. Resource model (what the commands work on)

- **Kinds.** Dictionaries (`type` `predefined|custom`), data patterns (`type`
  `predefined|custom|file_property`; `status` `active|disabled|deleted|deprecated|silent`;
  `detection_config.technique`), data profiles (`type` subtype `custom|predefined`;
  `profile_status` `active|disabled|deleted`; `profile_type` `basic|advanced`;
  `detection_rules` of `rule_type` `expression_tree` or `multi_profile`). Filtering profiles are
  not part of a DLP backup (they are tenant configuration with no create).
- **Dependencies.** A profile's `expression_tree` leaves (`rule_item`, nested through
  `sub_expressions`) reference a dictionary (`detection_technique: dictionary`, `id`, `name`,
  optional `version`) or a data pattern (any other technique, `id`, `name`, optional `version`).
  Leaves without an `id` are inline. Leaves with `edm_dataset_id` reference an EDM dataset.
  `multi_profile` rules reference other profiles by per-tenant numeric id.
- **Retired.** Patterns with `status` `deleted|disabled` and profiles with `profile_status`
  `deleted|disabled` are excluded when selecting and when matching names (`dr.ts:54-55`);
  `deprecated` and `silent` patterns are not. Dictionaries have no lifecycle filter.
- **Portable techniques** (`dr.ts:52`): `regex`, `weighted_regex`, `file_property`. Other
  custom patterns (EDM, fingerprints, classifiers, …) are tenant-bound and can only be mapped.
- **Live limits recorded in the code**: profile names are limited to 32 UTF-16 units on
  create (`dr.ts:1169-1173`); basic profiles read back with `detection_rules: null` and cannot
  be recreated (`dr.ts:425-431`); copies of predefined patterns read back with `regexes: null`
  (`dr.ts:975-995`); a CSV dictionary upload consumes its first row as a header (`dr.ts:655-671`);
  there is no profile DELETE, and a profile deleted in the UI reserves its name (409 on create)
  (`transfer.md`, "Known limits"; `profiles delete` exits 2 without a request,
  `src/cli/commands/dlp/profiles.ts:255-266`).

## 4. `runtime dlp backup`

### 4.1 Order (captured)

1. Commander parses `--resources` (stack trace, exit 1) and `--max-pages` (exit 2).
2. `--file-format` not `json|yaml` → exit 2 (before the tenant; captured with no tenant selected).
3. `resolveOutput` → tenant config load (no tenant: exit 1) and `--output` validation (exit 2).
4. `--output-file -` → exit 2.
5. Path: `resolve(--output-file ?? default)`; its extension (lower-cased) must be `.json` for
   `json` and `.yaml`/`.yml` for `yaml`, else `Backup filename extension must match --file-format`
   (exit 2; captured for `./noext`, `""` (resolves to the cwd), `./a2.yaml` without
   `--file-format yaml`, `./a2.json` with it). `./A.JSON` is accepted.
6. `context()` (credentials, exit 2).
7. `ℹ Reading inventories (dictionaries, data patterns, data profiles)…` (pretty), then the three
   sweeps (§2.3) and `tenantIdentity` over patterns and profiles: more than one distinct non-null
   `tenant_id` → `Inventory reports mixed DLP tenant identities` (exit 1).
8. Selection and dependency closure (§4.2), validation, schema parse.
9. `⚠ Skipped unsupported data profile: <name> (<reason>)` per excluded profile (stderr; only
   with `--skip-unsupported`).
10. Serialisation, the 20 MiB check (`Backup exceeds the 20 MiB size limit; select fewer --resources`,
    exit 1), `writeReportFile` (§4.4).
11. Summary (§4.5), exit 0.

**The output path is checked for existence only at step 10, after every request** (captured: an
existing `b1.json`, `a.yaml` and a dangling symlink `dang.json` all printed the `ℹ` line, read all
three inventories, then failed with `(EEXIST)`; a missing parent directory failed with `(ENOENT)`).

### 4.2 Selection (`backupDlpResources`, `dr.ts:357-507`)

- **Primary selection** by `--resources`:
  - `dictionaries`: every dictionary whose `type` is not `predefined` (`dr.ts:407-409`);
  - `patterns`: every pattern not `predefined` and not retired (`dr.ts:410-413`);
  - `profiles`: every profile not `predefined` and not retired, each checked (below).
- **Dependency closure.** Each kept profile's referenced dictionaries and patterns are added
  whatever `--resources` says (DR-spec:191: `--resources profiles` still embeds `Keywords`,
  `Custom Regex` and `SSN`). Captured: `--resources patterns` → 0 dictionaries, 1 pattern, 0
  profiles; `--resources dictionaries` → the custom dictionary only; the default → both
  dictionaries (custom and the referenced predefined), both patterns, the profile.
- **Predefined dependencies** are stored as stubs, never as content (`dr.ts:377-405`):
  dictionary `{id, name, type}`; pattern `{id, name, type, version?, detection_config?: {technique}}`
  (captured: the predefined pattern's `matching_rules.regexes` from the inventory is dropped).
- **Custom dependencies and primaries** are stored as the full inventory record
  (`structuredClone`, after the SDK's passthrough schema: every server field kept, including
  `tenant_id`, `status`, `version`, `audit_metadata`, `is_parent_managed`, unknown keys such as
  the captured `extra_server_field`). A custom dictionary without a `keywords` array →
  `Dictionary keywords were not returned by the region: <name>` (exit 1).
- **Per-profile checks**, in order (`dr.ts:420-475`), each producing a reason:
  1. no or empty `detection_rules` → `has no exported detection rules (the API does not expose basic data profile content)`;
  2. a rule not an object → `Unsupported detection rule shape`; a `rule_type` other than
     `expression_tree` → `Unsupported detection rule type: <rule_type>` (`multi_profile`);
     tree deeper than 100 → `Unsupported detection rule: expression tree too deep`; a leaf
     without a string technique → `Unsupported detection rule: leaf without a detection technique`;
  3. per leaf with an `id`: non-string → `has a non-string rule reference id`; inline leaf
     with `edm_dataset_id` → `references an EDM dataset directly`;
  4. dictionary leaf: unknown id → `references an unknown dictionary: <id>`; `version` not
     null and not 1 → `references a version-pinned dictionary: <id>`;
  5. pattern leaf: unknown id → `references an unknown data pattern: <id>`; technique differs
     from the pattern's → `references a data pattern with a different detection technique`;
     retired pattern → `references a retired data pattern: <name or id>`; `version` set and
     unequal to the catalog's → `references data pattern version <v>, but the catalog holds version <w|unknown>: <id>`.
- Without `--skip-unsupported`, any failing profile fails the whole backup with every reason at
  once: `Profiles cannot be exported: <name> (<reason>); <name> (<reason>); exclude unsupported profiles explicitly with --skip-unsupported`
  (names in inventory order, i.e. name order; a missing name is `(unnamed)`; captured with four
  profiles). With it, each is skipped and reported (§4.1 step 9); the dependencies of skipped
  profiles are not added (DR-spec:1124).
- Then each array is sorted by `name` with `localeCompare` (predefined stubs mixed in), and
  names are checked: missing → `Backup contains a <label> without a name`; empty after trim or
  holding a C0 control/DEL → `DLP resource names must be nonempty and contain no control characters`
  (captured for a pattern named `Evil\x1b[31mRed`); duplicate → `Backup contains duplicate <label> names: <name>`
  (captured for two custom patterns named `Custom Regex`). Labels `dictionary`, `data pattern`,
  `data profile`.
- Nothing selected → `No matching DLP resources to back up` (exit 1, captured on an empty tenant).
- There is no per-resource GET: everything comes from the list pages (dictionaries with
  `keywords=true`).

### 4.3 File format (TypeScript, captured)

`JSON.stringify(envelope, null, 2) + "\n"`, or for `yaml` `js-yaml dump(envelope, {schema: JSON_SCHEMA, noRefs: true, lineWidth: -1})`
(no trailing extra newline beyond the dump's own). The envelope is parsed with
`DlpResourcesBackupSchema` (`dr.ts:30-40`) before writing:

```json
{
  "version": 1,
  "resourceType": "dlp-resources",
  "exportedAt": "2026-10-18T13:02:22.916Z",
  "source": {
    "tsgId": "100"
  },
  "dictionaries": [ { "id": "src-dict-pre", "name": "Legal Terms", "type": "predefined" },
                    { "id": "src-dict-1", "name": "Secret Words", "description": "kw dict", "category": "Confidential",
                      "region_name": "United States", "type": "custom", "is_case_sensitive": false,
                      "dictionary_metadata": { "number_of_keywords": 2, "original_file_name": "words.txt" },
                      "keywords": [ "PRIVATE-KW-ALPHA", "PRIVATE-KW-BRAVO" ],
                      "audit_metadata": { "created_by": "a@example.com" } } ],
  "patterns": [ { "id": "src-pat-1", "name": "Custom Regex", "description": "regex pat", "tenant_id": "src-tenant",
                  "type": "custom", "status": "active", "version": 2,
                  "detection_config": { "technique": "regex", "supported_confidence_levels": [ "high" ] },
                  "matching_rules": { "proximity_keywords": [ "PRIVATE-PROX" ],
                                      "regexes": [ { "regex": "PRIVATE-REGEX-[0-9]{6}", "weight": 1 } ] },
                  "audit_metadata": { "created_by": "a@example.com" }, "extra_server_field": "x" },
                { "id": "src-pat-pre", "name": "Social Security Numbers", "type": "predefined", "version": 3,
                  "detection_config": { "technique": "ml" } } ],
  "profiles": [ { "id": "src-prof-1", "name": "PII Guardrail", "description": "prof", "tenant_id": "src-tenant",
                  "type": "custom", "profile_status": "active", "profile_type": "advanced", "version": 4,
                  "detection_rules": [ { "rule_type": "expression_tree", "expression_tree": { "operator_type": "or",
                    "sub_expressions": [ { "rule_item": { "detection_technique": "regex", "id": "src-pat-1",
                      "name": "Custom Regex", "version": 2, "match_type": "include", "confidence_level": "high",
                      "occurrence_operator_type": "any" } }, … ] } } ] } ]
}
```

(Abridged here onto fewer lines; the file is two-space indented, one key per line.)

- `version` is the **number** `1` (the red team targets backup uses the string `"1"`).
- Keys within a record follow the SDK zod schema order, then passthrough keys in input order
  (captured: `rule_item` reorders `confidence_level` before `occurrence_operator_type`,
  `match_type` before `confidence_level`). Nested order: dictionaries
  `id, name, description, category, region_name, type, is_case_sensitive, is_parent_managed,
  detection_technique, detection_sub_technique, dictionary_metadata, keywords, tags, attributes,
  audit_metadata`; patterns `id, name, description, tenant_id, type, status, license_type,
  is_parent_managed, version, detection_config, matching_rules, tags, audit_metadata`; profiles
  `id, name, description, tenant_id, type, profile_status, profile_type,
  is_granular_data_profile, is_parent_managed, version, advance_data_patterns_rule_request,
  detection_rules, audit_metadata`.
- **No schema default is inserted**: no `ZodDefault` is reachable from any DLP request,
  response or page schema in the TS SDK (`SDK:2470-2800` hold none) nor in the Rust SDK's frozen
  graph (`rs:src/validation/schema_graph.json`, checked by walking every node reachable from the
  15 DLP roots). DLP is not affected by gap G10.
- `null` values are kept as returned (no `stripNulls`).
- **What the file does not record**: the source tenant's name, the DLP `tenant_id` (only
  inside records), which `--resources` were selected, whether profiles were skipped under
  `--skip-unsupported` (a partial backup looks complete), and the CLI version.
- **What it holds in clear**: every keyword of every custom dictionary, every custom regex and
  proximity keyword, `audit_metadata` (user e-mail addresses), and descriptions.

### 4.4 File naming, mode, overwrite (`writeReportFile`, `rio.ts:5-19`)

`open(<dir>/.airs-report-<uuid>.tmp, 'wx', 0o600)`, `writeFile`, `sync`, `close`,
`link(temp, path)`, then `unlink(temp)` in `finally`. So: the file is created 0600 (captured
`-rw-------`), never overwrites (EEXIST, a dangling symlink included), is never partially
visible, and the directory is not created (ENOENT). The containing directory is not `fsync`ed.
Errors are the errno line of §2.4 (`(EEXIST)`, `(ENOENT)`, `(EACCES)`…). The YAML default name ends
`.yaml`.

### 4.5 Summary layouts (captured)

Columns `Backup file, Source TSG, Dictionaries, Patterns, Profiles, Skipped` with values
`file` (absolute path), `sourceTsgId`, the three array lengths (predefined stubs counted) and
the skipped-profile count. `pretty` prints the **table** layout, preceded by the `ℹ` line:

```
"  ℹ Reading inventories (dictionaries, data patterns, data profiles)…\n Backup file<pad> │ Source TSG │ Dictionaries │ Patterns │ Profiles │ Skipped \n<─ × (w+2)>┼────────────┼──────────────┼──────────┼──────────┼─────────\n <abs path> │ 100        │ 2            │ 2        │ 1        │ 0       \n"
```

`table`: the same without the `ℹ` line; `--quiet` pretty: the same. `json`:

```
"[\n  {\n    \"file\": \"<sb>/j.json\",\n    \"sourceTsgId\": \"100\",\n    \"dictionaries\": 2,\n    \"patterns\": 2,\n    \"profiles\": 1,\n    \"skipped\": 0\n  }\n]\n"
```

`yaml`: `- file: <abs>\n  sourceTsgId: '100'\n  dictionaries: 2\n  …`; `csv`: header line and one
row; `markdown`: a pipe table. The skipped profiles' names appear only in the stderr warnings.

## 5. `runtime dlp restore <file>`

### 5.1 Order (captured)

1. `--on-conflict` value (exit 2); 2. `--force` without `--expect-tsg` (exit 2);
3. `--pattern-map` syntax and duplicates (exit 2); 4. extension of `resolve(file)` not
`.json|.yaml|.yml` → `Backup file must use .json, .yaml or .yml` (exit 2);
5. `stat` (follows symlinks): failure → errno line (`(ENOENT)`, exit 1); not a regular file or
larger than 20 MiB → `Backup must be a regular file no larger than 20 MiB` (exit 2; captured for a
directory named `dir.json`); 6. read UTF-8 and parse (`JSON.parse` for `.json`, `js-yaml load`
with `JSON_SCHEMA` otherwise); any failure (or a decoded size over 20 MiB) → `Backup is not valid
JSON/YAML; contents are not logged` (exit 2); 7. `DlpResourcesBackupSchema.parse` (strict at the
top level and in `source`; each record a passthrough response schema; at most 10000 per array;
`version` the literal number 1; `exportedAt` an ISO datetime with offset) → `Invalid DLP
backup/request schema; content is not logged.` (exit 1; captured for `{"version":1}`, an extra
top-level key, `version: 2`, and a red team backup);
8. `resolveOutput` (tenant load, `--output`); 9. `context()` (no tenant exit 1, credentials exit 2);
10. `--expect-tsg` given and `!== mgmtTsgId` → `--expect-tsg does not match the selected
destination tenant; no API request was made` (exit 2, captured: no request);
11. plan (§5.2–§5.5), including its inventory reads; 12. warnings (§5.6);
13. `--dry-run` → print the plan (§5.7), exit 0; 14. confirmation (§5.8);
15. execute (§5.9); 16. result (§5.10).

A file problem is therefore reported before a missing tenant (captured), and nothing in the file
is ever echoed by these checks.

### 5.2 Plan: validation before any request (`planDlpResourcesRestore`, `dr.ts:778-830`)

In order, each a plain `Error` (exit 1) unless noted: the envelope re-parsed; `Destination TSG ID
is required`; `maxPages`; `Invalid --name-prefix`; `Invalid conflict policy`; the unique-name
checks of §4.2 on each array (`Backup contains duplicate data profile names: …`);
dictionary and pattern ids must be unique across both kinds (`Backup contains duplicate
dependency identities`, DR-spec:1656: no list request is made); every `--pattern-map` source must
be a backup pattern name (`--pattern-map names absent from the backup: <a>, <b>`, captured);
`crossTenant = source.tsgId !== destination TSG`.

### 5.3 Plan: destination inventories and tenant identity (`dr.ts:831-844`)

`ℹ Reading inventories (dictionaries, data patterns, data profiles)…`, the three sweeps (§2.3,
same queries as backup). Then the DLP `tenant_id` of the backup's patterns and profiles and of the
destination's (each must be uniform, else `Inventory reports mixed DLP tenant identities`). When
both are known:

- cross-TSG but the same `tenant_id` → `Destination credentials report the source DLP tenant; check the selected tenant before restoring`
  (captured);
- same TSG but a different `tenant_id` → `Destination DLP tenant does not match the backup source; use distinct tenant credentials deliberately`
  (captured: restoring the TSG-100 backup into TSG 100 whose records carry another `tenant_id`).

This is the only "wrong tenant" check besides `--expect-tsg`; a cross-TSG restore is the
documented use (prod → dev) and needs no extra flag.

### 5.4 Plan: dependencies (`dr.ts:846-1032`)

Matching is by **exact name** against the destination inventory; more than one non-retired match
→ `Ambiguous destination <label> name: <name>`. `name = <prefix><source name>` for every custom
resource (the prefix never applies to predefined ones or to mapped targets).

**Dictionaries**, per backup dictionary in file order (identity required: `Backup dictionary lacks identity`):

| Case | Plan |
|---|---|
| predefined, destination has a `predefined` dictionary with that name | `resolve` (bound to the destination id) |
| predefined, no such match | `--skip-unresolved`: unresolved `missing predefined destination dictionary`; else `Missing predefined destination dictionary: <name>` (captured) |
| custom, no destination match | `create`; the request is rebuilt (`dictionaryRequest`, `dr.ts:693-707`: `category, name, original_file_name (from dictionary_metadata, default keywords.txt), region_name, description?, is_case_sensitive?, tags?`, checked with `DictionaryRequestSchema`; failure `Dictionary cannot be rebuilt from the backup: <name>`), keywords must be a string array (`Backup dictionary lacks keywords: <name>`), and the upload text is validated now (§5.6 rules) |
| custom, a destination match that echoes the request (projection without `original_file_name`, the echoed file name if present, and the **sorted** keyword set equal) | `reuse` |
| custom, a match that differs | `Destination dictionary differs: <name>; use --name-prefix to avoid changing a shared dictionary` |

Destination dictionaries are matched without a lifecycle filter, and the "custom" match is not
required to be custom.

**Patterns**, per backup pattern (`Backup data pattern lacks identity`):

1. predefined and not in `--pattern-map`: a destination pattern with the **same id**, `predefined`,
   not retired, same technique; else by name (non-retired). A match must be `predefined` with an
   id and a name, else it is a miss. Misses are collected: with `--skip-unresolved` each is
   unresolved (`no identity or name match in the destination catalog`, with candidates); without,
   after all patterns: `Missing predefined destination data patterns: <name> (candidates: "<a>", "<b>"); <name> (no candidates); bind each with --pattern-map "<source-name>=<destination-name>"`
   (captured). A match with a different technique → `Destination data pattern detection technique differs: <name>`.
   Plan `resolve`, named after the **destination** name.
   - Candidates (`dr.ts:743-765`): destination predefined, non-retired, same technique; names
     normalised (lower-case, non-alphanumerics → space, trimmed); score 2 equal, 1 containment
     either way; sorted by score then `localeCompare`; deduplicated; at most 3. Never bound
     automatically.
2. in `--pattern-map`: the named destination pattern (non-retired, any type) must exist
   (`Missing mapped destination data pattern: <target>`) with the same technique (`Mapped
   destination data pattern detection technique differs: <target>`). Plan `map`.
3. custom with a technique outside the portable set: `--skip-unresolved` → unresolved
   `tenant-bound detection technique without --pattern-map`; else
   `Data pattern uses a tenant-bound detection technique: <name>; provision it in the destination and bind it with --pattern-map "<name>=<destination-name>"`.
4. custom `regex`/`weighted_regex` without a non-empty `matching_rules.regexes`:
   `--skip-unresolved` → unresolved `detection content is not exported by the API (copy of a predefined pattern)`;
   else `Data pattern has no exported detection content (a copy of a predefined pattern): <name>; bind an equivalent with --pattern-map "<name>=<destination-name>" or exclude dependents with --skip-unresolved`.
5. custom portable: request rebuilt (`patternRequest`, `dr.ts:709-722`: `name, type,
   detection_config, matching_rules?, description?, tags?`, `DataPatternRequestSchema`;
   failure `Data pattern cannot be rebuilt from the backup: <name>`). Cross-tenant: any key under
   the body matching `/(?:^|[-_])(id|uuid)$|(?:Id|ID|Uuid|UUID)$/` with a non-null, non-empty
   value → `Unsupported cross-tenant reference in pattern <name> at <path>.<key>`. No destination
   match (retired ones ignored) → `create`; a match that echoes the body (`compareEcho`, §5.5) →
   `reuse`; else `Destination data pattern differs: <name>; use --name-prefix to avoid changing a shared pattern`.

### 5.5 Plan: profiles and bindings (`dr.ts:1034-1222`)

- Per backup profile: no name → `Backup data profile lacks identity`; `predefined` →
  `Backup contains a predefined data profile`; `name = prefix + name`; destination match by name
  among non-retired profiles. A match with `--on-conflict error` →
  `Destination data profile already exists: <name>; choose --on-conflict verify or skip`
  (captured on a second run); `skip` → plan `skip`; `verify` and `reconcile` → plan `verify`.
  No match → `create`.
- Bindings: every `resolve`, `map` and `reuse` dependency binds the source id to the destination
  id, name, technique and version (dictionaries version 1). `create` dependencies bind at
  execute time.
- For each non-skip profile, every leaf with an id: if the id is a backup dependency, the leaf's
  technique must match (`Data profile rule detection technique does not match its dependency`)
  and a pinned version must equal the backup's (`Backup rule pins an unknown source dependency version`);
  ids neither planned nor in the backup → `Backup data profile references a resource absent from the backup: <name>`
  (also with `--skip-unresolved`); ids whose dependency is unresolved → the profile becomes
  `skip` with reason `unresolved references: <names>` (only when **every** missing id is an
  acknowledged unresolved reference).
- `profileRequest` (`dr.ts:1163-1222`) builds the create body: for `create`, a name longer than
  32 UTF-16 units → `Data profile name exceeds the live API limit of 32 characters`;
  `profile_type: basic` → `Data profile basic writes cannot round-trip through the API`; no
  rules → `Data profile has no exported detection rules to create`. Each bound leaf gets
  `id ← destination id`, `name ← destination name` (when the leaf has a name), `version ←
  destination version` (when the leaf has one; unknown → `Destination data pattern version is unknown: <name>`);
  a dictionary leaf version other than 1 → `Dictionary rule has an unsupported version pin`.
  Body: `{name, detection_rules, profile_type?, description?, is_granular_data_profile?}`
  parsed by `AdvancedDataProfileRequestSchema` (sent key order `name, detection_rules,
  description, …passthrough profile_type`, captured). Cross-tenant: the id/uuid key scan with
  the leaves themselves exempt for `id` (`Unsupported cross-tenant reference in profile <name> at …`).
- `verify` plans must have every binding now (`Missing planned dependency binding; an existing data profile cannot be verified without its destination dependencies: <name>`)
  and the destination profile must echo the body (`Destination data profile does not match restore plan: <name>; verification made no changes`).
- **`compareEcho`** (`dr.ts:595-647`): every requested field must equal the read-back
  (`null` ≡ absent); fields only the server has are "server-added" (reported, never failures);
  at the top level the server metadata keys `id, version, status, profile_status, tenant_id,
  license_type, is_parent_managed, audit_metadata, type, advance_data_patterns_rule_request,
  dictionary_metadata, detection_technique, detection_sub_technique, attributes, keywords, tags`
  are ignored when not requested; a `supported_confidence_levels` array may gain levels; arrays
  compare by length and position.
- Version handling: a predefined leaf pinned to `version 3` in the source is rewritten to the
  destination's `7` (captured); custom created patterns pin the version read back after create.

### 5.6 Plan output: warnings, and the upload text

- Warnings on stderr after the plan (`tr.ts:375-385`), never suppressed:
  `  ⚠ Unresolved dictionary: <name> (<reason>)`, `  ⚠ Unresolved data pattern: <name> (<reason>)[; candidates: "<a>", "<b>"]`,
  `  ⚠ Skipping data profile: <name> (<reason>)` (captured).
- **Upload text** (`dictionaryFile`, `dr.ts:661-671`): keywords non-empty, none empty or holding
  `\r`/`\n` (else `Dictionary contains keywords that cannot be faithfully uploaded`);
  `original_file_name` ending `.csv` (any case): no keyword with `,` (`Dictionary CSV contains
  unsupported multi-column keywords`), text `keywords\n<k1>\n…\n`; `.txt`: `<k1>\n…\n`; anything
  else → `Dictionary filename must end in .csv or .txt for a verified upload`. Keywords are sent in
  the backup's order (the reuse comparison sorts). A `reuse` of a legacy `.data` dictionary needs no
  upload and passes (DR-spec:1514). None of these messages quotes a keyword (DR-spec:1481).

### 5.7 Dry run (captured)

`summary` = `{sourceTsgId, destinationTsgId, dryRun, dictionaries: [{name, action}],
patterns: [{name, action}], profiles: [{name, action, reason?}], unresolved: [{kind, name,
reason}]}` with plan actions `create|reuse|resolve|map|verify|skip`. Rendered by
`renderRestore` (`tr.ts:126-198`): for `pretty`/`table`/`markdown` a sequence of blocks joined by
`\n\n`, for others `formatOutput([summary], columns, format)`.

Pretty (the `ℹ` line first; `table` and `--quiet` without it):

```
"  ℹ Reading inventories (dictionaries, data patterns, data profiles)…\nRestore preview — no changes made\n\nSource TSG: 100\nDestination TSG: 200\n\nDictionaries (2)\n\n Action  │ Name         \n─────────┼──────────────\n resolve │ Legal Terms  \n create  │ Secret Words \n\nData patterns (2)\n\n Action  │ Name                    \n─────────┼─────────────────────────\n create  │ Custom Regex            \n resolve │ Social Security Numbers \n\nData profiles (1)\n\n Action │ Name          \n────────┼───────────────\n create │ PII Guardrail \n"
```

An empty section prints `(none)`. With unresolved references the block
`Unresolved references — dependent profiles skipped` follows, then one block per entry
`<kind> <name>: <reason>` (`dictionary Legal Terms: missing predefined destination dictionary`).
The heading is `Restore preview — no changes made` for a dry run. Markdown prefixes headings with
`### ` (and puts a blank line between the TSG lines). JSON (captured):

```
"[\n  {\n    \"sourceTsgId\": \"100\",\n    \"destinationTsgId\": \"200\",\n    \"dryRun\": true,\n    \"dictionaries\": [\n      {\n        \"name\": \"Legal Terms\",\n        \"action\": \"resolve\"\n      },\n …\n    \"unresolved\": []\n  }\n]\n"
```

CSV puts JSON arrays in cells (`"[{""name"":""Legal Terms"",…}]"`). Dry run exits 0 even with
skipped profiles. The dry run reads the destination inventories once.

### 5.8 Confirmation (`tr.ts:415-424`, `confirm.ts:32-55`, captured on a pty)

`writes` = the number of `create` rows (dictionaries + patterns + profiles). Only when
`writes > 0`: `confirmOrAbort("Restore <writes> DLP resources from TSG <src> to TSG <dst>?",
--force, {action: "restore DLP resources into TSG <dst>"})`:

- `--force` (which requires `--expect-tsg`) → no prompt.
- stdout not a TTY → `\n  ✗ refusing to restore DLP resources into TSG 200 without --force in non-interactive mode\n\n`,
  exit 2, **after** the plan's inventory reads (captured: the `ℹ` line and three list requests
  precede it).
- interactive: inquirer `? Restore 3 DLP resources from TSG 100 to TSG 200? (y/N)` on stdout;
  `n` → `✔ … No`, `  ℹ Aborted`, exit 0; `y` → proceeds; Ctrl-C →
  `  ✗ User force closed the prompt with SIGINT`, exit 1 (captured).
- A plan with only `reuse/resolve/map/verify/skip` rows runs without a prompt and without
  `--force`, also non-interactively.

### 5.9 Execute (`restoreDlpResources`, `dr.ts:1281-1529`)

1. `ℹ Rechecking destination state before writing…`; the three sweeps again; for every planned
   item, the current name match must be canonically equal (sorted-key JSON) to the planned
   `existing` record, or absent for a `create`; else `Destination <kind> changed after planning: <name>`
   (DR-spec:899, before any write).
2. Stages in order, each announced `ℹ Restoring <dictionaries|data patterns|data profiles> (<n>)…`
   (only when the stage has rows), items in plan order:
   - non-create dependency → result `resolved|reused|mapped` with the destination id, bullet
     `✓ <dictionary|data pattern> <action>: <name> (<i>/<n>)`.
   - create → **one** POST (§2.2), the `created.id` must be present (`Restored <kind> did not verify: <name>`),
     the receipt `{kind, name, id}` is pushed to `unverifiedCreates`, then the read-back GET; the
     read-back must echo the request (`dictionaryEcho` or `compareEcho`), carry the same id and name,
     and (patterns, profiles) not be retired, else
     `Restored <kind> did not verify: <name> (created id <id>; inspect it before retrying)`.
     Server-added fields are recorded. The new binding is set, the result row `created`, the receipt
     popped, bullet `✓ … created: <name> (<i>/<n>)`.
   - profile `skip` → row `skipped` (id of the existing profile, reason), bullet `○ data profile skipped: …`.
   - profile `verify` → `compareEcho` again (no request), row `verified`, bullet `✓`.
   - profile `create` → POST; under `--on-conflict reconcile` a **409** (any 409) is retried
     **once** under `suffixedProfileName(name, <6 lowercase hex random>)` (base cut so the result
     fits 32 units, `<base>-<hex>`), row `created` with `renamedFrom` (captured
     `PII Guardrail-eb187b`); without reconcile the 409 stops the run (captured
     `API request failed (HTTP 409); …`).
3. `complete: true`.

Any throw stops the run (no rollback, no further stages). `result.error` (`dr.ts:1513-1527`):
an error with an integer `statusCode` → `API request failed (HTTP <status>); verify destination state before retrying`;
an `Error` whose message starts with `Destination|Restored|Missing|Inventory|Ambiguous|Dictionary|Data pattern|Data profile`
→ that message; anything else (transport failure, timeout, dropped connection) →
`Restore stopped; verify destination state before retrying`. If a receipt is still in
`unverifiedCreates`, the suffix `; unverified create: <kind> <name> (id <id>); inspect this resource before retrying`
is appended (`<kind>` is `dictionaries|patterns|profiles`).

### 5.10 Result layouts and exit (captured)

`console.log(renderRestore({...result}))`, then when `!complete` `ui.error(result.error)` on stderr
and exit 1. JSON keys in order `sourceTsgId, destinationTsgId, complete, dictionaries, patterns,
profiles, serverAdded, unverifiedCreates, unresolved, error?` (no `dryRun` key); rows
`{name, action, id}` with `created|reused|resolved|mapped|verified|skipped` (profiles also
`reason?`, `renamedFrom?`). Pretty after the progress lines:

```
"…  ✓ data profile created: PII Guardrail (1/1)\nRestore complete\n\nSource TSG: 100\nDestination TSG: 200\n\nDictionaries (2)\n\n Action   │ Name         \n──────────┼──────────────\n resolved │ Legal Terms  \n created  │ Secret Words \n\nData patterns (2)\n …\n"
```

Incomplete (a 503 on the dictionary read-back, captured):

```
stdout "…  ✓ dictionary resolved: Legal Terms (1/2)\nRestore incomplete — completed writes remain\n\nSource TSG: 100\nDestination TSG: 200\n\nDictionaries (1)\n\n Action   │ Name        \n──────────┼─────────────\n resolved │ Legal Terms \n\nData patterns (0)\n\n(none)\n\nData profiles (0)\n\n(none)\n\nCreated resources awaiting verification\n\n Resource     │ Name         │ Created ID  \n──────────────┼──────────────┼─────────────\n dictionaries │ Secret Words │ dest-dict-0 \n\nError: API request failed (HTTP 503); verify destination state before retrying; unverified create: dictionaries Secret Words (id dest-dict-0); inspect this resource before retrying\n"
stderr "  ✗ API request failed (HTTP 503); verify destination state before retrying; unverified create: dictionaries Secret Words (id dest-dict-0); inspect this resource before retrying\n"
```

Further blocks when present: `Renamed around archived-name collisions` + `<from> -> <to>` lines;
`Verified server-added fields (source omitted these)` + `<resource>: <n> fields; use --output json for paths`.
Errors raised before execute (plan, recheck failures thrown by the plan) use §2.4 instead.

### 5.11 Fault matrix (captured; each one run against a fresh destination)

| Fault | Requests after the token | Printed | Exit |
|---|---|---|---|
| 500 on `POST dictionaries` (body echoing a keyword) | 1 POST | `error: API request failed (HTTP 500); …`, dictionaries `[Legal Terms resolved]`; keyword never printed | 1 |
| 400 `application/problem+json` echoing a keyword on `POST dictionaries` | 1 POST | `API request failed (HTTP 400); …` | 1 |
| 503 text body on the dictionary read-back | POST, GET | `unverifiedCreates` row, suffix with the created id | 1 |
| applied, then 502 on `POST data-patterns` | POST (created on the server) | `API request failed (HTTP 502)`; nothing marks the pattern as possibly created | 1 |
| rerun after that | – | the applied pattern is **reused** (exact echo), profile created | 0 |
| hang on `POST data-patterns` with a 700 ms timeout | 1 POST | `Restore stopped; verify destination state before retrying`; no receipt, no "may have been created" | 1 |
| dropped connection on `POST data-patterns` | 1 POST | same | 1 |
| 401 once on `POST data-patterns` | POST, token, POST | complete | 0 |
| 403 on `POST data-patterns` | POST, token, POST | `API request failed (HTTP 403)` | 1 |
| 403 with `x-opa-decision: false` | 1 POST | same | 1 |
| 409 on `POST data-profiles`, `--on-conflict reconcile` | POST (409), POST (suffixed), GET | created `PII Guardrail-eb187b`, renamed block | 0 |
| 409 on `POST data-profiles`, default | 1 POST | `API request failed (HTTP 409)` | 1 |
| 500 on the pattern inventory (backup) | 1 GET | `DLP transfer API request failed (HTTP 500); no automatic retry was made.` | 1 |
| connection refused | – | `DLP transfer API request failed; no automatic retry was made.` | 1 |
| SIGINT during a hung `POST data-patterns` | 1 POST | nothing after `ℹ Restoring data patterns (2)…` | 130 |

## 6. Sensitive-data exposure (TS)

| Path | Exposure |
|---|---|
| backup file | every keyword, regex, proximity keyword, description and `audit_metadata` in clear; 0600, exclusive create (good) |
| stdout/stderr | no keyword or regex in any message (DT-spec asserts on `PRIVATE-*` markers; captured); HTTP errors reduced to the status |
| names | server names are printed raw: a profile named `Evil\x1b[31mProf` skipped under `--skip-unsupported` printed the escape in the warning (captured); destination candidate names likewise. Backed-up names must be control-free (`assertName`), destination names are not checked |
| `--debug` | bodies omitted for DLP; status, headers (Authorization masked) and URLs (queries) logged for DLP hosts |
| prompt | names only the two TSGs |
| interrupted backup | no partial file (hard-link publish); a `.tmp` can remain after a signal kill |

## 7. TS specs to port (acceptance tests)

| TS spec | Behaviours (Rust tests adjusted by §12 rows) |
|---|---|
| `tests/unit/backup/dlp-resources.spec.ts` `backupDlpResources` (DR:179-562) | closure, sorting, selection by `--resources`, retired and predefined exclusion, every unsupported reason in one failure, `--skip-unsupported`, EDM-direct, unknown id, keywords missing, duplicate names, unknown kind / empty inventory / missing TSG, the pagination checks (non-advance, 10000 limit, max pages, every inconsistent-metadata case, camel/snake aliases, the 50 cap, empty zero-total pages), the name-sort query, duplicate and missing ids, mixed tenant identities |
| same, `planDlpResourcesRestore` (DR:564-826) | stage plan, missing predefined with remedy, identity binding, technique guard, aggregated misses with ranked candidates, `--pattern-map` for predefined and tenant-bound patterns, absent map names, missing map target, cross-tenant references, absent profile references, conflict policies, differing dictionary/pattern, retired-name collision, option validation, tenant identity both ways |
| same, `restoreDlpResources` and later groups (DR:828-1793) | prefixed restore with remapped ids and versions, resumable second pass, skip policy, change-after-planning, failed read-back, keyword round trip, sanitised errors, version pins, retired read-back, predefined dictionaries, verify mismatch, retired dependency, basic profiles, unexported content, slim stubs, candidate quality, skip-unresolved and progress events, `compareEcho`, CSV/TXT upload fidelity and refusals, legacy reuse, impossible page shapes, receipts on read-back failure, identity mismatch, opaque errors, technique mismatch via name and map, malformed references, cross-kind duplicate ids, nominal dictionary revision 1, reconcile (suffix, no suffix outside reconcile, active duplicate → verify, 32-char truncation, invalid policy) |
| `tests/integration/dlp-transfer-contract.spec.ts` | the HTTP contract over the real binary: aggregated misses with no write, `--pattern-map` + re-GET, mixed profile skipped while an independent one is created, dictionary created then a 400 stops before patterns without leaking keywords, a v1 envelope restored with ids remapped (now: a Rust-format file), no PUT/PATCH/DELETE ever, no marker in output |

## 8. Rust SDK (`scm-sdk` 0.1.0, feature `dlp`) coverage

- Present and matching TS paths: `DictionariesClient::{list, get, create}` (`rs:src/dlp/dictionaries.rs:55-141`;
  `keywords` query; multipart `json` part `metadata.json`/`application/json`, `file` part named
  after `original_file_name`, `DictionaryUpload::text` sets `text/plain`), `DataPatternsClient::{list, create, get}`,
  `DataProfilesClient::{list, create, get}` (`rs:src/dlp/data_patterns.rs`, `data_profiles.rs`);
  `SpringListParams` sends `page`, `size`, then each `sort` (`rs:src/dlp/common.rs:76-99`).
- Typed models keep absent vs `null` (`Patch`), unknown keys at every level (`extensions`) and
  integer numbers (`FiniteNumber`), so a re-serialised record is lossless up to key order.
  Page metadata in snake_case (`total_elements`, `pageable.page_size`, …) lands in `extensions`
  and is readable; the CLI should run the §2.3 checks itself over the single-page `list` (the
  SDK's `list_pages` defaults dictionaries to `size=50` and checks only `last`/`totalPages`,
  `rs:src/dlp/common.rs:107-142`).
- **G10 does not apply**: no schema default is reachable from any DLP schema (§4.3), so DLP
  output and backups show no fabricated values.
- Not present, and not needed: data profile DELETE (the API has none; TS `profiles delete`
  refuses). Nothing here is blocked on the SDK.

## 9. Proposed Rust backup format (version 1, Rust-only)

One JSON document per run, `serde_json` pretty layout plus `"\n"`, keys in this order:

```json
{
  "format": "airs-cli-rs.dlp-resources",
  "version": 1,
  "exportedAt": "2026-10-18T12:00:00.000Z",
  "tenant": "prod",
  "tsgId": "100",
  "dlpTenantId": "src-tenant",
  "resources": ["dictionaries", "patterns", "profiles"],
  "complete": true,
  "dictionaries": [
    {"id": "src-dict-1", "name": "Secret Words", "predefined": false, "record": { …the inventory record as returned… }},
    {"id": "src-dict-pre", "name": "Legal Terms", "predefined": true, "record": {"id": "src-dict-pre", "name": "Legal Terms", "type": "predefined"}}
  ],
  "patterns": [ … same entry shape; predefined record = TS stub {id, name, type, version?, detection_config?: {technique}} … ],
  "profiles": [ … same entry shape, predefined always false … ],
  "skipped": [{"kind": "profile", "id": "src-prof-multi", "name": "Multi", "reason": "Unsupported detection rule type: multi_profile"}]
}
```

- `tenant` the store name, `tsgId` its `mgmtTsgId`, `dlpTenantId` the uniform `tenant_id` of
  the inventory (`null` when none), `resources` the `--resources` selection in canonical order,
  `complete` exactly `skipped` empty. Entries sorted by name as TS (`localeCompare`
  approximation of §15.17); the entry `id`/`name` must equal the record's.
- `record` is the raw document the server sent (validated with the SDK response schema and
  pruned to the raw keys, as §15.18 does), so nothing is fabricated and unknown fields survive.
- Same selection, closure, per-profile reasons, unique-name and control-character rules as TS
  (§4.2); without `--skip-unsupported` an unsupported profile fails the run and no file is
  written (TS parity, fail closed).
- **Location**: `--output-file <path>` (TS name), default
  `./airs-dlp-backup-<UTC yyyymmddThhmmssZ>-<8 lowercase hex>.json`; `-` refused (TS text);
  extension `.json` required (any case); `--file-format json` accepted, `yaml` a usage error
  (`--file-format must be json (yaml was dropped)`, §15.18 style). Existence (`lstat`, dangling
  symlinks included) and the parent directory are checked **before the tenant is read**; the
  publish is `files::publish_new` (0600, `O_EXCL|O_NOFOLLOW`, link, directory fsync), so a race
  is still refused at link time.
- After writing: `  ⚠ <path> contains DLP dictionary keywords and pattern definitions; keep it private (mode 0600)`
  when it holds a custom dictionary or pattern (never quiet-suppressed).
- Size limit 20 MiB (TS), checked before publishing.

## 10. Proposed Rust restore plan

1. **Argument checks** (exit 2, before the file and the tenant): `--on-conflict` value;
   `--force` without `--expect-tsg` (TS); `--dry-run` with `--force` (§15.19); `--pattern-map`
   syntax and duplicates; `--name-prefix` length and control characters (TS: exit 1 in the plan);
   `--max-pages`; dropped `--output` values; without `--dry-run` and `--force` and without a
   terminal on stdin and stderr: `refusing to restore DLP resources without --force in non-interactive mode`
   (D81; TS decides after the plan and only when something is created).
2. **The file** (before the tenant; `input` rules, 20 MiB, UTF-8, `.json`): malformed JSON;
   a TypeScript backup (an object with `resourceType`, or a `.yaml`/`.yml` file, or a YAML
   `resourceType:` line) → `<path> is a TypeScript airs-cli backup; airs-cli-rs cannot restore it. Restore it with the TypeScript airs-cli, or back the resources up again with 'airs-cli-rs runtime dlp backup'.`;
   newer version; schema breaks with fixed reasons (unknown keys refused at the envelope and entry
   level, records checked with the SDK response schemas); `complete: false` → warning
   `  ⚠ <path> is incomplete: <n> data profile(s) were skipped when it was backed up`.
3. **Tenant checks**: `--expect-tsg` mismatch (TS text, exit 2, no request); file `tsgId` ≠
   tenant `mgmtTsgId` → refused unless `--allow-other-tenant` (§15.19 text; choice, §12 row);
   the TS DLP `tenant_id` checks after the inventories (kept).
4. **Plan**: the TS planner unchanged (§5.2–§5.5), names through `terminal_safe`, the 32-unit
   profile limit counted in UTF-16 units, every refusal before any write.
5. **`--dry-run`**: the plan layout of §5.7 (json, pretty, table), exit 0, or 1 when the plan
   holds a refusal it could not express (the planner throws instead, so 1 is its error).
6. **Confirmation** (D81 prompt on stderr) when at least one `create`, naming both TSGs:
   `Restore <n> DLP resources from TSG <a> to TSG <b>?`.
7. **Recheck**, then **writes** in stage order, one attempt each (D95: 401 replayed once, 403
   never, no replay on 5xx/timeout/transport); read-backs are replay-safe reads with the SDK's
   retries. A rejected create (3xx/4xx) stops the run like TS (later items `notAttempted`); an
   unknown outcome stops it with the D95 line `Outcome unknown: the <dictionary|data pattern|data profile> <name> may have been created.`
   and a rerun hint (`run the restore again: an identical resource is reused; for a data profile use --on-conflict verify`);
   a 2xx whose read-back fails or does not echo keeps TS's "unverified create" receipt.
   `reconcile`'s suffixed retry only after a definite 409 answer, one attempt.
8. **Output**: TS layouts (stdout data; the `ℹ`/`✓` progress moved to stderr and
   quiet-suppressed, D106 style), json keeping TS's one-element array with Rust additions
   `outcomeUnknown` (`{kind, name}` or `null`) and `notAttempted` (names). Exit 1 when not
   complete. Interrupt context: `nothing was changed` before the first write, then
   `<c> created; the <kind> <name> may have been created (outcome unknown)` style counts.
9. Restore never sends PUT, PATCH or DELETE and never modifies a predefined resource (TS invariant, kept and tested).

## 11. Live-tier notes

- Reads (`AIRS_RS_LIVE=1`): a `runtime dlp backup` into the run's temp directory on both CLIs
  (TS's file is 0600 too); compare counts and names only (never contents), then a
  `restore --dry-run` of each CLI's own backup into the same tenant: every custom resource must
  plan `reuse` and every profile fail with `already exists` (default policy) or `verify`
  (`--on-conflict verify`), which proves the planner without writes.
- Writes (`AIRS_RS_LIVE_DLP_WRITES=1`): **a data profile cannot be deleted** (no API DELETE; a
  UI-deleted profile reserves its name for ever), so the rule "every created resource deleted
  at the end" cannot hold for profiles. Options for the user: (a) exclude profile create from
  the live flow (dictionaries and patterns only); (b) accept one permanent, uniquely named
  `airs-rs-e2e-<run id>-prof` per CLI per run, recorded in the ledger as "undeletable". The
  recommendation is (a).
- Restore live: only `--dry-run`, plus at most a restore of a test-composed Rust-format file that
  holds only the run's own custom dictionary and pattern, with
  `--name-prefix airs-rs-e2e-<run id>-r-`, `--expect-tsg`, `--force`; each created copy is
  ledgered and deleted. A restore of a real tenant backup (which holds every custom resource)
  must never run live. TS restores are excluded from live writes (its backup selection cannot be
  limited to the run's resources without composing a TS-format file).

## Acceptance criteria

Each is a loopback executable test of airs-cli-rs; parity tests compare both CLIs where the
behaviour is shared.

1. `backup` sends exactly the three sorted inventory sweeps of §2.2–§2.3 (dictionaries with
   `keywords=true`) and refuses every inconsistent page, duplicate or missing id, the 10000 limit
   and an incomplete sweep with the TS messages, writing no file.
2. `backup` selects, closes and refuses as §4.2 (every TS reason, all at once), writes the §9
   format (raw records, slim predefined stubs, `skipped` and `complete`), at 0600, refuses an
   existing path or dangling symlink before the tenant is read, and prints the §4.5 summary.
3. `--resources` and `--max-pages` errors are exit 2 usage errors with no request (TS: a stack
   trace with exit 1 for `--resources`); `--file-format yaml` is a usage error.
4. `restore` refuses a TypeScript backup (JSON and YAML) with the fixed message and no request.
5. `restore --dry-run` prints the §5.7 plan for every action kind, sends only inventory reads, and
   exits 0.
6. The plan refuses (before any write, exit 1): missing predefined references with ranked
   candidates, tenant-bound patterns without a map, unexported content, differing destination
   dictionaries and patterns, ambiguous names, references absent from the backup, unsupported
   version pins, names over 32 units, basic profiles, cross-tenant id references, mixed or
   swapped DLP tenant identities, and an existing profile under `--on-conflict error`.
7. A full restore creates dictionaries (multipart layout of §2.2, CSV header and TXT rules),
   patterns and profiles in stage order with remapped ids, names and versions, reads each back,
   and a second run with `--on-conflict verify` writes nothing.
8. Each create is sent once: a 5xx, a timeout or a dropped connection stops the run with the
   outcome-unknown line and no further request; a 401 is replayed once; a 403 is not.
9. A read-back failure leaves the unverified-create receipt in the output (§5.10 text) and stops
   the later stages.
10. `--on-conflict reconcile` retries one 409 under a 32-unit suffixed name; outside reconcile a
    409 stops the run.
11. Confirmation: `--force` needs `--expect-tsg`; a mismatch is exit 2 with no request; the D81
    prompt and its non-interactive refusal; a backup from another TSG needs
    `--allow-other-tenant` (choice).
12. No keyword, regex or proximity keyword appears on stdout, stderr or in the debug log in any
    path (the DT-spec markers), and server names pass through `terminal_safe`.
13. Restore never sends PUT, PATCH or DELETE.
14. SIGINT during a create exits 130 with a context naming the resource that may have been created.

## Open questions / likely §12 divergences

Numbers are assigned by the orchestrator from D160. Each is a safety or correctness fix; the ones
marked **(choice)** need the user's confirmation.

1. **Overwrite check timing (safety).** TS refuses an existing backup path (and a dangling
   symlink) only at publish, after reading every keyword of the tenant (§4.1). Rust checks before
   the tenant is read and again at link.
2. **Backup format (settled: Rust-defined).** §9; TS envelopes and YAML files are refused by
   restore with a fixed message (D152 style). `--file-format yaml` is a usage error.
3. **Incomplete backups are unmarked (correctness).** TS's file does not record profiles excluded
   by `--skip-unsupported` (§4.3); Rust records `skipped` and `complete: false`, and restore warns.
4. **Wrong-tenant restores (safety, choice).** TS needs nothing beyond its DLP `tenant_id` check
   for a cross-TSG restore, and `--expect-tsg` is optional without `--force`. Options: (a)
   §15.19 consistency: a file from another TSG needs `--allow-other-tenant`, `--expect-tsg` kept
   (required with `--force`); (b) keep TS (cross-TSG is the documented migration). Recommendation (a).
5. **Confirmation (safety, choice).** TS prompts on stdout (corrupting `--output json` on a
   terminal), refuses non-interactive runs only after the inventory reads and only when
   something would be created, and Ctrl-C exits 1. Rust: D81 (stderr prompt, `y`/`yes`, Ctrl-C
   130); the non-interactive refusal up front (before the tenant) for any non-dry-run restore
   without `--force` (choice: up front vs after the plan).
6. **`--dry-run --force` (consistency).** TS accepts; Rust follows §15.19 (usage error).
7. **Unknown outcomes (safety).** TS stops on any failure (good) but reports a create lost to a
   5xx/timeout/transport failure as `API request failed (HTTP 502)` or `Restore stopped`, with
   nothing saying the resource may exist (§5.11), and replays a POST after a 403. Rust: D95 (no
   403 replay) and the outcome-unknown line naming the resource; the rerun is safe for
   dependencies (exact reuse) and for profiles with `--on-conflict verify`.
8. **Reconcile duplicates (safety, choice).** Any 409 on a profile create becomes a suffixed
   copy, and reruns create more copies; profiles cannot be deleted. Keep TS semantics (only
   after a definite 409, one attempt, reported) or require confirmation of the renamed create
   in non-`--force` runs (choice; recommendation: keep, document).
9. **Read retries (choice).** TS sends every read once (`numRetries: 0`): one transient 5xx on
   an inventory page fails a backup. Rust may use the SDK's replay-safe read retries for
   inventories and read-backs; the page consistency checks still apply.
10. **Streams and quiet (correctness).** TS prints `ℹ` progress and `✓` item bullets on stdout
    (bullets even under `--quiet`). Rust: progress on stderr, quiet-suppressed (D106 style).
11. **Dropped formats.** `markdown`, `csv`, `yaml` output are usage errors (D50).
12. **Validation exit codes (correctness).** `--resources` errors crash with a stack trace
    (exit 1); `Invalid --name-prefix` and `--pattern-map names absent…` are exit 1; missing
    credentials are exit 2 with a DLP-specific text. Rust: usage errors exit 2 before the
    tenant where the file is not needed; credentials through the shared §3 message.
13. **Terminal safety (safety).** Skipped-profile warnings and candidate names print server text
    raw (captured ESC). Rust: `terminal_safe`.
14. **Interrupted runs (correctness).** TS dies silently on SIGINT/SIGTERM (130/143); Rust prints
    the interrupt context (what was created, what may have been).
15. **Debug log.** TS logs nothing on loopback and omits DLP bodies; Rust: status and headers
    only for every request of the invocation (§2.9), never bodies, never queries.
16. **Profiles in the live write flow (rules, needs the user).** No profile DELETE exists
    (§11): exclude profiles from live writes, or accept a permanent ledgered residue.
17. **Filtering profiles are not backed up.** TS parity; MILESTONES says "DLP backup/restore"
    without naming them. Keep (they have no create, so a restore could only PUT tenant config).
