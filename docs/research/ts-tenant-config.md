# TS CLI tenant registry and config loading: specification for a read-only `airs-cli-rs`

Sources: `prisma-airs-cli` 7.2.1-forgejo.0 (`package.json:4`), zod 3.25.76 (v3 API, `pnpm-lock.yaml:2059`), commander ^14, chalk ^5, js-yaml ^4. The SDK `@cdot65/prisma-airs-sdk@0.34.0` is not in `node_modules` (no install), so I read its bundled `dist/index.js` from the local pnpm content store (`~/Library/pnpm/store/v10/files/3c/6738…dab7`). Line numbers for that file are given as `sdk:NNN`. No tenant or credential file was read. No network calls were made.

---

## 1. Registry location: `tenantStorePath()` (`src/config/tenants.ts:34-40`)

The path is resolved in this order:

1. If `PRISMA_AIRS_TENANTS_PATH` is **truthy** (set and non-empty), the result is `resolve(expandConfigPath(value))`.
   - `expandConfigPath` (`tenants.ts:42-44`) expands **only** the exact value `~` (to `homedir()`) or a `~/` prefix (to `join(homedir(), rest)`). `~someone/x` is left alone. The test is `tenants.spec.ts:191`.
   - Node's `path.resolve` turns a relative path into an absolute one under `process.cwd()`. It also normalizes the path lexically (`.`, `..`, doubled `/`, trailing `/`).
   - An empty string falls through to step 2.
2. Otherwise `XDG_STATE_HOME` is checked. If it is set, non-empty and not absolute (`path.isAbsolute`, which on POSIX means it starts with `/`), the function **throws** `XDG_STATE_HOME must be an absolute path` (`tenants.ts:38`; test `tenants.spec.ts:192-193`). This check is never reached when `PRISMA_AIRS_TENANTS_PATH` is set. `XDG_STATE_HOME` is not `~`-expanded.
3. The result is `join(XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'prisma-airs', 'tenants.json')`. `path.join` normalizes lexically, so `XDG_STATE_HOME=/s/../t` displays as `/t/prisma-airs/tenants.json`. The test is `tenants.spec.ts:186-189`.

`homedir()` is `$HOME` if set, otherwise the passwd entry. The registry path appears verbatim in error messages and doctor details, so Rust must apply the same lexical normalization to keep message parity.

## 2. Reading the registry: `readTenantStore()` (`tenants.ts:51-63`)

The function performs only reads. It never creates directories, locks or temporary files.

1. It runs `lstatSync(path)`, which does **not** follow a symlink at the final component. Symlinked parent directories are fine.
2. If `!stat.isFile()` (directory, symlink, FIFO and so on) or `stat.size > 1_048_576`, it throws. A file of exactly 1 MiB is allowed.
3. It runs `JSON.parse(readFileSync(path, 'utf8'))`. Node decodes UTF-8 lossily, turning invalid bytes into U+FFFD. A BOM makes the parse fail. Duplicate keys resolve last-wins.
4. It validates with `StoreSchema` (`tenants.ts:17-28`). `.strict()` applies at top level and on every entry:
   - `version`: `z.literal(1)`, which must be the number 1. JSON `1.0` also parses to 1 in JS.
   - `active`: `z.string().nullable()`. It is **required**: if the key is missing, the registry is invalid.
   - `tenants`: an array of at most **1000** entries.
   - Each entry (`tenants.ts:10-16`), strict:
     - `name` must match `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$` (`tenants.ts:9`). That is 1–64 ASCII characters, and the first must be alphanumeric.
     - `configPath` must be a string satisfying `path.isAbsolute`. It does not have to exist or be normalized.
     - `tsgId` must be a string with `min(1)`. Whitespace-only is allowed, and a number is invalid.
   - `superRefine`: names must be unique, and if `active` is non-null it must equal a registered name. Duplicate `configPath` or `tsgId` values are allowed.
5. **ENOENT anywhere** in this sequence (the file or a parent directory is missing) returns `{ version: 1, active: null, tenants: [] }` (`tenants.ts:58`; test `tenants.spec.ts:44-48`).
6. **Every other failure** throws the same message: `Cannot read tenant registry at ${path}; restore a valid registry before proceeding` (`tenants.ts:59-61`). That covers ENOTDIR, EACCES, a symlink, a directory, an oversized file, invalid JSON, an empty 0-byte file, schema failures, unknown keys, `version: 2`, a missing `active`, an `active` that names no tenant, duplicate names, relative paths and bad names. No fragment of the file is ever echoed. Tests: `tenants.spec.ts:167-177` and `doctor.spec.ts:597-605`.

Zod's output object key order follows the shape: entries come out as `name, configPath, tsgId`, whatever the file order. The order of entries in the array is preserved from the file. The write path sorts entries with `localeCompare` (`tenants.ts:158`), but a hand-written registry can be in any order.

Lock files (`tenants.json.lock`) are ignored by every read path. Reads proceed even while a writer holds the lock.

## 3. Selecting the active tenant

- **No per-invocation tenant flag exists.** A grep of `src` finds no `--tenant`; the only near match is the unrelated `redteam … --tenant-id`. There is also no `--config` global option. Several product commands have a `--config <path>`, but that is a request-body JSON file, not configuration. Selection comes **only** from `registry.active`, written by `tenant switch`. The registry location can be redirected with `PRISMA_AIRS_TENANTS_PATH`, which tests and docs use as the per-job selection mechanism (`docs-site/docs/cli/tenant.md:114-115`; `tests/helpers/live-tenant.ts:19-28`).
- `resolveConfigContext()` (`loader.ts:55-64`) returns one of three shapes:
  - `{selection:'tenant', path: entry.configPath, tenant, registryPath}` when `active` matches an entry.
  - `{selection:'none', registryPath, registered: names in registry order}` otherwise.
  - `{selection:'explicit', …}` exists only when a caller passes `configFilePath`, which happens only through the library API. The CLI never passes it.
- `NoTenantSelectedError` (`loader.ts:39-52`): `name = 'NoTenantSelectedError'`, and the message passes through `commandHint()`:
  - When names are registered: `No tenant selected. Run 'airs-cli tenant switch <name>' (registered: a, b)`
  - When none are: `No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'`
  - Tests: `loader.spec.ts:66-80`.
- `commandHint` (`src/cli/invocation.ts:1-9`) replaces `airs-cli ` with `airs cli ` only when `AIRS_CLI_INVOKED_AS === 'airs cli'` exactly (`tests/unit/cli/invocation.spec.ts`).
- The tenant subcommands use their own resolver, `resolveEntry(name?)` (`src/cli/commands/tenant.ts:45-57`), with **different wording and no commandHint**:
  - No name given, nothing selected, tenants registered: `No tenant selected; pass a name or run 'airs-cli tenant switch <name>' (registered: a, b)`
  - No name given, nothing selected, no tenants: `No tenant selected; run 'airs-cli tenant create <name>' first`
  - Name not in the registry: `Tenant not found`

## 4. Reading a tenant config file: `readTenantConfigFile(path, expectedTsgId?)` (`tenants.ts:75-95`)

The checks run in this order, all inside one try block:

1. `lstatSync(realpathSync(path))`. Symlinks at the config path are **followed** (`tenants.spec.ts:115-119`). The real target must be a regular file of at most 1,048,576 bytes.
2. `JSON.parse(readFileSync(path, 'utf8'))`. Note that it reads the original path, not the realpath.
3. The parsed value must be a non-null, non-array object.
4. `ConfigSchema.parse(parsed)` runs on the **raw** object. Empty strings have not been stripped at this point.

Any failure in steps 1–4 throws `Cannot read a valid tenant config at ${path}`, where `path` is the registry's `configPath` as given, not its realpath. The underlying error is discarded. This matters because Node's JSON `SyntaxError` and Zod enum errors include input fragments. Tests: `tenants.spec.ts:146-156` (`null`, `[]`, truncated JSON containing `SUPER-SECRET`, `{"scanConcurrency":99}`) and `tenants.spec.ts:121-129` (file deleted after selection).

5. **TSG pin.** This runs outside the try, after a successful parse: `if (expectedTsgId !== undefined && config.mgmtTsgId !== expectedTsgId)` throws `Tenant config TSG differs from its registered identity; register it under a new name` (`tenants.ts:90-93`; test `tenants.spec.ts:131-137`).
   - The comparison is strict string equality with no trimming.
   - A file **without** `mgmtTsgId` also fails here with the "differs" message, not with a missing-credential message.
   - The message never includes either TSG value.
   - Every CLI read of the selected tenant passes `tenant.tsgId`: `loader.ts:77` and `tenant.ts:174,230`.
6. The function returns the **raw parsed object**, including unknown keys. `readTenantConfig` (`tenants.ts:71-73`) returns `ConfigSchema.parse(raw)` instead.

Neither function checks file permissions. Read-only files (`0400`) and read-only mounts are fully supported (`tenants.spec.ts:34-35,50-67`; `dlp-tenant-auth.spec.ts:126,232-233`).

## 5. Tenant config schema (`src/config/schema.ts:10-56`)

The object is non-strict, so **unknown keys are silently stripped**. Zod v3 semantics apply throughout:

- An absent optional key stays absent in the output. A defaulted key is always present.
- Output key order follows the schema order shown below.
- `null` is **invalid** for every key.
- `z.string()` does not coerce, so a numeric `mgmtTsgId` makes the file invalid.
- `z.coerce.number()` applies JS `Number()` before validating. That means `"3"`, `" 3 "`, `"0x5"`, `"1e1"`, `true` (1), `false` (0), `[]` (0), `[4]` (4) and `""` (0) are all coerced. `NaN` (from `{}` or `"abc"`) and non-integers fail.
- `.url()` in v3 means "`new URL(value)` does not throw" (the WHATWG parse). It is permissive: `localhost:8080` and `mailto:x` both pass.

| # | Key | Type / validation | Default | Secret per `isTenantSecret` |
|---|---|---|---|---|
| 1 | `airsApiKey` | string | — | yes |
| 2 | `airsApiToken` | string | — | yes |
| 3 | `airsApiEndpoint` | string (no URL check) | — (code uses `DEFAULT_ENDPOINT`) | no |
| 4 | `airsNumRetries` | coerce number, int, 0..5 | — (SDK uses 5) | no |
| 5 | `mgmtClientId` | string | — | no |
| 6 | `mgmtClientSecret` | string | — | yes |
| 7 | `mgmtTsgId` | string | — | no |
| 8 | `mgmtEndpoint` | string | — | no |
| 9 | `mgmtDashboardEndpoint` | string `.url()` | — | no |
| 10 | `mgmtTokenEndpoint` | string | — | no |
| 11–21 | `dlpEndpoint`, `redTeamDataEndpoint`, `redTeamMgmtEndpoint`, `redTeamNetworkBrokerEndpoint`, `modelSecDataEndpoint`, `modelSecMgmtEndpoint`, `agentGuardDataEndpoint` (`.url()`), `agentGuardMgmtEndpoint` (`.url()`), `aiGwDataEndpoint`, `aiGwAdminEndpoint`, `iamEndpoint` | string | — | no |
| 22–25 | `aiGwInferenceEndpoint`, `aiGwInferenceApiKey`, `aiGwInferenceModel`, `aiGwEmbeddingModel` | string | — | `aiGwInferenceApiKey` only |
| 26–28 | `typesafeApiKey`, `typesafeBaseUrl` (`.url()`), `typesafeModel` | string | — | `typesafeApiKey` only |
| 29 | `scanConcurrency` | coerce number, int, 1..20 | `5` | no |
| 30 | `defaultOutput` | enum `pretty, table, markdown, csv, json, yaml` | — | no |
| 31 | `dataDir` | string | `~/.prisma-airs/runs` | no |

- **Retired keys** (`schema.ts:66-71`): `redTeamTokenEndpoint`, `modelSecTokenEndpoint`, `agentGuardTokenEndpoint`, `aiGwTokenEndpoint`. They are just unknown keys: stripped and ignored (`schema.spec.ts:46-58`; `loader.spec.ts:82-90`). Doctor gives them a specific hint (section 11).
- **Unknown keys** are accepted by the loader and dropped from the effective config. `tenant set` retains them on disk (`tenant-settings.spec.ts:62-77`). They are invisible in `tenant read`. `tenant get <unknown>` is rejected with the key-validation error. Doctor reports them as `warn`, which does not change the exit code. Guided `create` rejects them (`tenant-settings.ts:37`). `create --config` accepts them.
- `isTenantSecret(key)` is `/(?:key|secret|token|password)$/i` on the **key name** (`tenant-settings.ts:21-23`; tests `tenant-settings.spec.ts:122-133`). `mgmtTokenEndpoint` and `typesafeBaseUrl` are not secrets.

## 6. The effective config: `loadConfig(cliOverrides = {})` (`src/config/loader.ts:84-92`)

1. `readConfigSource` resolves the context. `none` throws `NoTenantSelectedError`. `tenant` calls `readTenantConfigFile(path, tsgId)`, which applies the full section 4 checks plus the pin.
2. `stripUndefined` (`loader.ts:26-28`) drops keys whose value is `undefined` **or `''`**. It runs on both the file and the overrides.
3. The merge is `{...file, ...overrides}`, then `ConfigSchema.parse`.
4. `dataDir` is expanded by `expandHome` (`loader.ts:13-15`). This is a **different** expander: any leading `~` becomes `join(homedir(), p.slice(1))`, so `~foo` turns into `$HOME/foo`.
5. The environment is never consulted. `loader.spec.ts:17-42` sets `PANW_AI_SEC_API_KEY`, `PANW_MGMT_*`, `PANW_CLI_OUTPUT`, `SCAN_CONCURRENCY` and `PRISMA_AIRS_CONFIG_PATH` and checks that none of them has an effect. The same is checked in `tenants.spec.ts:69-81`.

Empty-string consequences for a **registered** tenant (validation runs on raw values, then stripping happens):

- `"scanConcurrency": ""` coerces to 0, which is below the minimum, so the **whole file is invalid**. The `loader.spec.ts:97-100` test "treats empty strings as unset" only covers the library's explicit-path mode.
- `"airsNumRetries": ""` coerces to 0, which is valid. It is then stripped, so the effective value is undefined and the SDK default of 5 applies. `tenant read` still displays `0`.
- `"airsApiEndpoint": ""` and other plain strings are valid. They are stripped, so the default endpoint applies. `tenant read` displays `""`.
- `"mgmtDashboardEndpoint": ""` fails `.url()`, so the file is invalid.

CLI overrides are in practice never passed: every call site is `loadConfig()` or `loadConfig({})`. The documented "CLI flags > file > defaults" precedence is real only for output selection.

**Output-format precedence**, from `resolveOutput` (`src/cli/renderer/common.ts:48-75`):

1. An explicit `--output`, local or global.
2. The tenant's `defaultOutput`, read through `loadConfig()`.
3. `pretty`.

The global `--output` is declared on the program (`program.ts:108`). Commander by default recognizes program options after subcommands, so in practice the root consumes the value and the last occurrence wins. Tenant commands and doctor pass `ignoreConfig: true`, so their output never reads the tenant file.

Failures are reported as follows:

- An invalid format raises `CliUsageError` with `Invalid output format '<x>'. Expected: pretty, table, markdown, csv, json, yaml`, which exits 2.
- A disallowed format exits 2 with `Output format '<x>' is not supported here. Expected: …`.

For runtime read commands (`list`/`get` and friends), the `preAction` hook (`program.ts:162-175`) calls `resolveOutput` **without** `ignoreConfig`. Tenant and registry errors therefore surface there first, through `fail()`, with exit 1.

## 7. Credential checks and remedies (`src/config/credentials.ts`)

- `present(v)` means `typeof v === 'string' && v.trim() !== ''`, using JS whitespace semantics (`credentials.ts:15-17`). Whitespace-only values count as missing (`credentials.spec.ts:41-48`).
- The management set is `['mgmtClientId','mgmtClientSecret','mgmtTsgId']`, checked in that order. The scanner needs either `airsApiKey` or `airsApiToken` (`credentials.ts:6-13`).
- `settingRemedy(keys, context = safeContext())` (`credentials.ts:37-51`). `safeContext()` re-reads the registry and swallows errors, which leads to the third case below.
  - Selected tenant: `Run 'airs-cli tenant set <name> <key>' for <k1, k2> (secrets prompt hidden, or use --stdin)`
  - Explicit (library only): `Add <k1, k2> to <path>`
  - None, or registry unreadable: `Run 'airs-cli tenant create <name>' (prompts for the OAuth credentials), then 'airs-cli tenant switch <name>'`
  - All three pass through `commandHint`.
- Management error: `Management credentials are not configured (missing mgmtClientSecret, mgmtTsgId). <remedy>` (`credentials.ts:54-63`). It is raised by `oauth()` in `client-options.ts:34-42` **before any SDK client is built**, so it costs zero HTTP requests. Tests: `client-options.spec.ts:52-62` and `credentials.spec.ts:50-56`.
- Scanner error: `Scanner credentials are not configured (airsApiKey or airsApiToken). <remedy for airsApiKey>` (`credentials.ts:65-70`). It is raised by `runtimeInitOptions` (`client-options.ts:89-97`) and by `bulk-scan` (`runtime.ts:315-316`).
- Because of the pin, a selected tenant can only report "missing mgmtTsgId" when both the registry `tsgId` and the file are whitespace-only. In every other case a missing `mgmtTsgId` surfaces as the TSG-mismatch error.
- The checks are independent. Management commands never check scanner keys, and scanning never checks management keys. However, the pin still requires the file's `mgmtTsgId` to equal the registry's, so every selected file carries a `mgmtTsgId`.
- Values are **not trimmed** when sent. OAuth uses the raw `mgmtClientId` and `mgmtClientSecret` in Basic auth. The SDK scanner trims key and token itself (`sdk:241-242`).

## 8. SDK option mapping and environment leakage

- Management-plane builders (`client-options.ts:44-86`) pass every option explicitly: `clientId`, `clientSecret`, `tsgId`, `tokenEndpoint` (`mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`) and every base URL (file override, else SDK constant). The SDK's `resolveOAuthConfig` env fallbacks (`sdk:11099-11104`, `opts.x ?? process.env.PANW_MGMT_*`) are therefore never reached. This is tested in `client-options.spec.ts:64-81`.
- Defaults:
  - `DEFAULT_TOKEN_ENDPOINT`: `https://auth.apps.paloaltonetworks.com/oauth2/access_token`
  - `DEFAULT_MGMT_ENDPOINT`: `https://api.apps.paloaltonetworks.com/aisec`
  - CLI `DEFAULT_MGMT_DASHBOARD_ENDPOINT`: `https://api.apps.paloaltonetworks.com/aisec` (`client-options.ts:27`)
  - `DEFAULT_ENDPOINT` (scanner): `https://service.api.aisecurity.paloaltonetworks.com`
  - `DEFAULT_DLP_ENDPOINT`: `https://api.dlp.paloaltonetworks.com`
- The OAuth token request (`sdk:11017+`) is a `POST {tokenEndpoint}` with:
  - `Content-Type: application/x-www-form-urlencoded`
  - `Authorization: Basic base64(clientId:clientSecret)`
  - body `grant_type=client_credentials&scope=tsg_id%3A<tsg>`
  - The integration test server (`tenant-setup.spec.ts:58-79`) checks `scope=tsg_id:100` and Basic `client-100:FAKE-SECRET`.
- **Scanner leak (bug).** `runtimeInitOptions` passes `apiKey: config.airsApiKey, apiToken: config.airsApiToken`, either of which may be `undefined`. SDK `init()` resolves `opts.apiKey ?? process.env.PANW_AI_SEC_API_KEY` and `opts.apiToken ?? process.env.PANW_AI_SEC_API_TOKEN` (`sdk:241-242`).
  - A tenant with only `airsApiToken` therefore picks up `PANW_AI_SEC_API_KEY` from the environment.
  - A tenant with only `airsApiKey` picks up `PANW_AI_SEC_API_TOKEN`.
  - `ApiKeyAuth` then sends **both** `Authorization: Bearer …` and `x-pan-token: …`, plus `x-payload-hash` when the key is present (`sdk:9577-9589`).
  - The endpoint is always passed, so `PANW_AI_SEC_API_ENDPOINT` cannot leak. `numRetries: undefined` falls to the SDK default of 5 (`sdk:273`), not to an environment value.
  - No test covers this: `client-options.spec.ts:194-199` only covers the case where both are missing.
  - The Rust SDK never reads the environment implicitly (`scm-sdk-rs/crates/scm-sdk/src/environment.rs:1`). Rust should pass only the configured credentials and must not call `EnvironmentSnapshot::capture`.

## 9. Environment variables

These are read by the CLI itself:

- `PRISMA_AIRS_TENANTS_PATH`, `XDG_STATE_HOME`, `HOME` (through `homedir()`).
- `AIRS_CLI_INVOKED_AS`, which is display-only.
- `PANW_AI_SEC_DEBUG`, which some commands refuse to run with.

The SDK reads `PANW_AI_SEC_DEBUG`, `PANW_AI_SEC_DEBUG_BODY` and `PANW_AI_SEC_TIMEOUT_MS` (default 60000; `sdk:10095`). The CLI forces `PANW_AI_SEC_DEBUG_BODY=0` for `runtime dlp` commands (`program.ts:122-127`).

chalk derives its colour level from **stdout**. With stdout piped, neither stream contains ANSI codes. The tests also set `NO_COLOR=1`.

`ignoredEnvironment(env)` (`env.ts:42-51`) returns the names of variables that are set and non-empty and match either of:

- any name starting with `PANW_` except `PANW_AI_SEC_DEBUG`, `PANW_AI_SEC_DEBUG_BODY` and `PANW_AI_SEC_TIMEOUT_MS`;
- any of the retired names `PRISMA_AIRS_CONFIG_PATH`, `TYPESAFE_API_KEY`, `TYPESAFE_BASE_URL`, `TYPESAFE_DEFAULT_MODEL`, `SCAN_CONCURRENCY`, `DATA_DIR`, `MEMORY_ENABLED`, `MEMORY_DIR`, `MAX_MEMORY_CHARS`, `ACCUMULATE_TESTS` and `MAX_ACCUMULATED_TESTS`.

The list is sorted in code-unit order and contains names only. `PRISMA_AIRS_TENANTS_PATH` and `XDG_STATE_HOME` are never reported. Tests: `env.spec.ts:8-53`.

## 10. Read-only tenant subcommands (`src/cli/commands/tenant.ts`)

Shared plumbing:

- `fail(err)` (`common.ts:12-25`) writes `\n  ✗ Error: <message>\n` to stderr. If the error carries `status` or `statusCode`, it adds `    HTTP <n>\n` and `    Re-run with --debug to capture redacted API diagnostics.\n`. It then writes `\n` and **exits 1**.
- `fail` converts a `CliUsageError` into `usageError`, which writes `\n  ✗ <message>\n\n` and **exits 2** (`common.ts:27-30`).
- `ui.status` writes `  <msg>\n` to **stderr**, and `--quiet` suppresses it (`ui.ts:131-135`).
- `ui.emptyList` writes `  No <x> found\n` to **stdout** and is not suppressed by `--quiet` (`ui.ts:138-140`).
- Each command's `console.log` output ends with `\n`.
- `program.ts:42-51` gives `tenant list` the alias `ls` and `tenant delete` the alias `rm`.
- Commander parse errors (`error: missing required argument 'key'`, `error: unknown option '--x'`, `error: too many arguments for 'read'. Expected 1 argument but got 2.`, `error: unknown command 'x'`) exit **1**. No `exitOverride` is configured.
- `formatOutput` (`common.ts:96-143`):
  - JSON is `JSON.stringify(rows, null, 2)`, the full rows rather than the column projection.
  - YAML is js-yaml `dump(rows,{noRefs:true,lineWidth:-1}).trimEnd()`.
  - CSV is `label,label` then values, quoted when a value contains `",\r\n`.
  - Markdown is `| A | B |`, then `| --- | --- |`, then rows. `\` and `|` are escaped, and newlines become `<br>`.
  - Table rows are ` value.padEnd(w) ` joined by `│`, with a separator of `'─'.repeat(w+2)` joined by `┼`. There is no indentation and no outer border, and objects are JSON-stringified.
  - For empty rows: JSON gives `[]`, YAML gives `[]\n` (so stdout shows `[]\n\n`), and every other format gives an empty string (so stdout shows `\n`).

### `tenant list` (`tenant.ts:195-218`)

The command reads **only the registry** and never opens a config file.

1. `resolveOutput(…, {ignoreConfig:true})`. An invalid format exits 2.
2. `readTenantStore()`. On error, `fail`, exit 1.
3. If there are zero tenants and the format is `pretty`: stdout `  No tenants found`, stderr status `  Run 'airs-cli tenant create <name>' to register one.`, exit 0.
4. If `active === null` and tenants exist: stderr status `  No tenant selected; run 'airs-cli tenant switch <name>'.`
5. Rows are `{name, configPath, tsgId, active: boolean}` in registry order. Columns: `Tenant`, `Selected`, `TSG ID`, `Config file`. `pretty` maps to `table`.

JSON example:

```json
[
  {
    "name": "dev",
    "configPath": "/r/configs/dev.json",
    "tsgId": "100",
    "active": true
  }
]
```

Table example:

```
 Tenant │ Selected │ TSG ID │ Config file         
────────┼──────────┼────────┼─────────────────────
 dev    │ true     │ 100    │ /r/configs/dev.json 
```

CSV example: `Tenant,Selected,TSG ID,Config file\ndev,true,100,/r/configs/dev.json`.

YAML quotes `tsgId: '100'`.

### `tenant read [name]` (`tenant.ts:220-240`)

1. `resolveOutput`, exit 2 if invalid.
2. `resolveEntry`.
3. `readTenantConfig(configPath, tsgId)`, with the pin applied.
4. Rows are `{key, value: redact(key, value)}` for each key of the **Zod-parsed** config. That means schema order, unknown keys hidden, and `scanConcurrency` and `dataDir` always present. Coerced numbers stay JSON numbers, and `dataDir` is not expanded.
5. `redact` (`tenant.ts:59-61`): a secret key with a truthy value becomes `[REDACTED]`; anything else becomes `value ?? ''`. An empty secret therefore shows `""`.
6. stderr status: `  Tenant <name> (TSG <tsg>): <configPath>`.
7. Columns `Key`, `Value`; `pretty` maps to `table`.

For the file `{mgmtTsgId:'100', mgmtClientId:'client-100', mgmtClientSecret:'X'}`, the JSON output is:

`[{"key":"mgmtClientId","value":"client-100"},{"key":"mgmtClientSecret","value":"[REDACTED]"},{"key":"mgmtTsgId","value":"100"},{"key":"scanConcurrency","value":5},{"key":"dataDir","value":"~/.prisma-airs/runs"}]`, pretty-printed with 2-space indentation.

The integration test is `tenant-setup.spec.ts:122-124`.

### `tenant get <name> <key>` (`tenant.ts:165-181`)

Both arguments are required. The checks run in this order:

1. `validateTenantSettingKey(key)`, using `Object.hasOwn(shape,key)`, so `__proto__` and `constructor` are rejected. Failure prints `Unknown configuration key. Supported keys: airsApiKey, airsApiToken, …, dataDir` (all 31 keys in schema order) and exits 1.
2. Output resolution, exit 2 if invalid.
3. `resolveEntry`.
4. `readTenantConfig` with the pin.
5. `redact`.

`pretty` prints `String(value)` alone: `100`, `5`, `[REDACTED]`, or an empty line when the key is unset. Every other format prints a **one-element array**, `[{"key":"mgmtTsgId","value":"100"}]`. The value is the effective one, so `scanConcurrency` gives 5 by default and `dataDir` gives the unexpanded `~/.prisma-airs/runs`.

### `tenant path [name]` (`tenant.ts:242-251`)

stdout is `<configPath>\n`. The command never reads the config, so the pin is not checked. It has no `--output`; a global `--output` value is consumed and ignored without validation. Errors from `resolveEntry` or the registry exit 1.

The write commands (`create`, `switch`, `set`, `unset`, `delete`) are out of scope. They use the registry lock `tenants.json.lock` (`wx`), atomic temp-and-rename writes, modes 0700/0600, and the per-config lock `<config>.lock`. They refuse read-only configs, and the exit code is 130 on prompt cancellation.

## 11. Doctor's config-related checks (`src/cli/commands/doctor.ts`)

`checkTenant` (`doctor.ts:107-129`):

- Pass: `<name> (TSG <tsg>) selected in <registryPath>`.
- Fail with names registered: `no tenant selected (registered: a, b)`, hint `Run 'airs-cli tenant switch <name>'`.
- Fail with nothing registered: `no tenants registered in <registryPath>`, hint `Run 'airs-cli tenant create <name>' (prompts for TSG ID, client ID and secret), then 'airs-cli tenant switch <name>'`.

A registry error (`doctor.ts:132-139,654-668`) produces a Tenant `fail` whose detail is the error message, with hint `Restore or remove <registryPath>; PRISMA_AIRS_CONFIG_PATH bypasses the registry meanwhile`. That hint is wrong, because `PRISMA_AIRS_CONFIG_PATH` is ignored. Every later check is then `skip` with `not evaluated — fix the failed checks above first`.

`checkConfigFile` (`doctor.ts:145-226`) reads the file with a plain `readFile`. It applies no realpath, size or regular-file check. The outcomes are:

| Case | Detail | Hint |
|---|---|---|
| Any read error, including EACCES and EISDIR (fail) | `not found at <path>` | `Restore the file, or register another with 'airs-cli tenant create <name> --config <path>' and delete '<name>'` |
| Bad JSON (fail) | `<path> is not valid JSON` | |
| Not an object (fail) | `<path> is not a JSON object` | |
| Schema failure (fail) | `<path> has invalid values for: k1, k2` | key paths only |
| TSG mismatch (fail) | `<path> carries a different mgmtTsgId than the registration (TSG <tsg>)` | `Register the file under a new tenant name with 'airs-cli tenant create <name> --config <path>'` |
| Unknown keys (warn) | `valid at <path>; ignored N key(s): a, b` | retired hint: `Every product authenticates through mgmtTokenEndpoint now (…) ignored; remove them with 'airs-cli tenant unset <name> <key>'`; otherwise `Remove unknown keys with 'airs-cli tenant unset <name> <key>'` |
| Pass | `valid tenant config at <path> (TSG <tsg> matches registration)` | |

`checkEnvironment` (`doctor.ts:233-247`):

- Warn: `ignored N variable(s): A, B[; SDK diagnostics on: …]`, hint `Configuration comes only from tenant files ('airs-cli tenant set <name> <key>'); unset these`.
- Pass: `no configuration variables set[; SDK diagnostics on: …]`.

The credential checks use `inspectConfig()`, the stripped file plus defaults with a `file` or `default` source per key, and print only key names and sources.

## 12. Test fixtures and the harness

- `tests/helpers/tenant.ts:20-43` (`writeTestRegistry`) is the reference layout: configs are written to `<dirname(registry)>/configs/<name>.json` with mode 0600; the registry is `{"version":1,"active":…,"tenants":[{name,configPath,tsgId:String(mgmtTsgId)}]}` with 2-space indentation and a trailing newline. The default credentials are `{mgmtClientId:'client', mgmtClientSecret:'secret', mgmtTsgId:'123'}`.
- `tests/setup.ts:6-15` isolates the registry per test file for unit and integration tests only (`vitest.config.ts:6`). `vitest.e2e.config.ts` has no setup file, so e2e runs use the operator's real registry.
- `tests/helpers/live-tenant.ts` selects the operator's active tenant, or `AIRS_E2E_TENANT`, which is read by the test helper and not by the CLI. It then writes a temporary single-entry registry that references the same config by path. That is the safe pattern for live parity runs of both binaries.
- The executable tests (`tenant-setup.spec.ts:10-50`, `dlp-tenant-auth.spec.ts:17-34,105-111`):
  - remove `PANW_*` and `PRISMA_AIRS_*` from the environment, then set `PRISMA_AIRS_TENANTS_PATH` and `NO_COLOR=1`;
  - assert the exit code and that no fake secret or token appears in stdout or stderr;
  - run `node [AIRS_CLI_ENTRY | tsx src/cli/index.ts]`, so they cannot exec a native binary without adaptation.
- The DLP environment-ignore test (`dlp-tenant-auth.spec.ts:236-245`) sets `PANW_MGMT_CLIENT_ID`, `PANW_MGMT_CLIENT_SECRET`, `PANW_MGMT_TSG_ID`, `PANW_DLP_ENDPOINT` and `PRISMA_AIRS_CONFIG_PATH`, and asserts that only the tenant-file credentials authenticate.

## 13. What the read-only Rust reimplementation needs

**MUST:**

- Resolve the registry path exactly as in section 1, with the same message.
- Read the registry as in section 2: `symlink_metadata`, regular file, at most 1 MiB, parse into a JSON value and then validate manually so that duplicate keys resolve last-wins, strict keys, the version-1 literal, `active` required and nullable, the name regex, absolute paths, non-empty `tsgId`, unique names, the active reference, at most 1000 entries, ENOENT treated as empty, and one generic message for everything else.
- Select only from `active`. Reproduce both no-tenant messages.
- Read the config as in section 4: canonicalize, regular file, at most 1 MiB, a JSON object, full schema validation including JS-style numeric coercion and URL checks on the four `.url()` keys, then the pin with its exact message.
- Strip `''` values after validation, apply the defaults, and leave unknown keys ignored.
- Run the credential assertions before any HTTP, with the exact messages and remedies.
- Ignore the environment for every value. Construct SDK clients explicitly, passing the token endpoint and base URLs from the file or the defaults.
- Never write, create a directory, take a lock, or chmod anything.
- Use the same exit codes and the same stdout/stderr split as `fail` and `usageError`.

**SHOULD:**

- Provide `tenant list`, `read`, `get` and `path` with identical JSON and redaction, and `ls`.
- Provide `ignoredEnvironment` for doctor.
- Provide doctor's Tenant, Config file, Environment and credential checks.
- Honor `defaultOutput` in the precedence chain.

**NOT (initially):** create, switch, set, unset, delete, prompts, stdin input, or lock handling.

## Acceptance criteria
- With PRISMA_AIRS_TENANTS_PATH pointing to a nonexistent file in a nonexistent directory, `runtime profiles list --output json` exits 1, stdout is empty, stderr contains "No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'", the HTTP server receives 0 requests, and neither the file nor its parent directory is created.
- A registry {version:1, active:null, tenants:[dev, prod]} makes any API command exit 1 with stderr containing "No tenant selected. Run 'airs-cli tenant switch <name>' (registered: dev, prod)" (registry order), and 0 HTTP requests are made.
- Each of these registry files makes any API command exit 1 with stderr "Cannot read tenant registry at <abs path>; restore a valid registry before proceeding": a symlink to a valid registry, a directory, invalid JSON, a 0-byte file, a file over 1,048,576 bytes, version 2, a missing `active` key, an unknown top-level key, an unknown entry key, an active name that is not registered, duplicate names, a relative configPath, an empty tsgId, a numeric tsgId, a name '-bad' or one 65 characters long, or 1001 entries.
- A registry of exactly 1,048,576 bytes that is otherwise valid (for example, whitespace-padded) is accepted.
- With PRISMA_AIRS_TENANTS_PATH unset and XDG_STATE_HOME=relative, any API command exits 1 with stderr containing 'XDG_STATE_HOME must be an absolute path'.
- With PRISMA_AIRS_TENANTS_PATH unset and XDG_STATE_HOME=<tmp>, the registry is read from <tmp>/prisma-airs/tenants.json. With both unset, it is read from $HOME/.local/state/prisma-airs/tenants.json (test with HOME=<tmp>).
- PRISMA_AIRS_TENANTS_PATH='' falls back to the XDG/HOME path. PRISMA_AIRS_TENANTS_PATH='~/r.json' resolves to $HOME/r.json. PRISMA_AIRS_TENANTS_PATH='r.json' resolves against the cwd. '~other/r.json' is treated as a cwd-relative path that starts with '~other'.
- A selected config whose mgmtTsgId ('200') differs from the registry tsgId ('100') makes `runtime profiles list` exit 1 with stderr containing 'Tenant config TSG differs from its registered identity; register it under a new name', with no OAuth or API request made and neither TSG value printed.
- A selected config with no mgmtTsgId produces the same TSG-differs message, not a missing-credential message.
- A selected config containing '{"mgmtClientSecret":"SUPER-SECRET",oops' makes the command exit 1 with stderr 'Cannot read a valid tenant config at <registry configPath>', and 'SUPER-SECRET' appears in neither stdout nor stderr.
- Each of these selected configs is rejected with 'Cannot read a valid tenant config at <path>': `null`, `[]`, {scanConcurrency:99}, {scanConcurrency:''}, {scanConcurrency:null}, {defaultOutput:'xml'}, {mgmtDashboardEndpoint:'not a url'}, {typesafeBaseUrl:'not a url'}, {mgmtTsgId:100 (number)}, {airsApiKey:null}, {airsNumRetries:6}, a file over 1 MiB, a directory, a missing file, and a UTF-8 BOM prefix.
- A selected config that is a symlink to a valid file is accepted. The canonical target must be a regular file.
- A selected config with extra keys (custom, redTeamTokenEndpoint) loads normally; the extra keys have no effect, and the file's bytes and mtime are unchanged.
- A selected config with scanConcurrency '3' (string) or 3 is accepted.
- Read-only operation: with the config at mode 0400, the registry at mode 0400, a pre-existing tenants.json.lock and a <config>.lock, every read-only command succeeds and leaves no new files in the registry directory.
- Environment is ignored: with PANW_MGMT_CLIENT_ID, PANW_MGMT_CLIENT_SECRET, PANW_MGMT_TSG_ID=200, PANW_MGMT_ENDPOINT, PANW_MGMT_TOKEN_ENDPOINT, PANW_AI_SEC_API_KEY, PANW_AI_SEC_API_ENDPOINT, PANW_CLI_OUTPUT=yaml and PRISMA_AIRS_CONFIG_PATH=<other tenant file> all set, the OAuth request goes to the file's mgmtTokenEndpoint with the file's credentials and scope tsg_id:<file TSG>, and stdout format follows only --output or defaultOutput.
- OAuth request shape: POST to the configured mgmtTokenEndpoint with Content-Type application/x-www-form-urlencoded, Authorization 'Basic base64(mgmtClientId:mgmtClientSecret)', and a form body with grant_type=client_credentials and scope=tsg_id:<mgmtTsgId>. Subsequent API calls carry 'Authorization: Bearer <access_token>'.
- A selected config missing mgmtClientSecret makes a management command exit 1 with stderr containing "Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set <name> <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)", and 0 HTTP requests.
- Whitespace-only mgmtClientId ('  ') is reported as missing, in the order mgmtClientId, mgmtClientSecret, mgmtTsgId.
- A selected config with neither airsApiKey nor airsApiToken (or only whitespace) makes `runtime scan` exit 1 with stderr containing "Scanner credentials are not configured (airsApiKey or airsApiToken). Run 'airs-cli tenant set <name> <key>' for airsApiKey (secrets prompt hidden, or use --stdin)", and 0 HTTP requests, even when PANW_AI_SEC_API_KEY is set in the environment.
- A scanner-only tenant (mgmtTsgId pinned, no client ID or secret, airsApiKey set) can run `runtime scan`. A management-only tenant can run `runtime profiles list` without scanner keys.
- Rust divergence (intentional fix): with only airsApiToken in the tenant file and PANW_AI_SEC_API_KEY set in the environment, scan requests carry no x-pan-token or x-payload-hash header (the TS CLI does send them, which is a bug).
- Without --output, a runtime read command uses the tenant file's defaultOutput (for example 'json'). An explicit --output overrides it. The last --output occurrence wins (`--output yaml tenant list --output json` gives JSON). An invalid --output exits 2 with stderr "Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml".
- `tenant list --output json` prints [{name, configPath, tsgId, active}] in registry order, with 2-space indentation and a trailing newline, and exits 0 even when the selected config is missing or invalid.
- `tenant list --output json` on an empty or missing registry prints '[]\n' to stdout and exits 0. In pretty format it prints '  No tenants found' to stdout and "  Run 'airs-cli tenant create <name>' to register one." to stderr.
- `tenant list` with active null and tenants present writes "  No tenant selected; run 'airs-cli tenant switch <name>'." to stderr (suppressed by --quiet) and data to stdout.
- `tenant ls` is an alias of `tenant list`.
- `tenant read --output json` prints [{key, value}] rows in schema order containing only keys present in the file plus scanConcurrency and dataDir. Secret-named keys with non-empty values show '[REDACTED]'. stderr shows '  Tenant <name> (TSG <tsg>): <configPath>'. The exit code is 0.
- `tenant read` with no name and no active tenant exits 1 with "No tenant selected; pass a name or run 'airs-cli tenant switch <name>' (registered: …)". `tenant read missing` exits 1 with 'Tenant not found'.
- `tenant get dev mgmtClientSecret --output json` prints [{"key":"mgmtClientSecret","value":"[REDACTED]"}]. `tenant get dev scanConcurrency` (pretty) prints '5' when unset. `tenant get dev defaultOutput` prints an empty line when unset.
- `tenant get dev notAKey` exits 1 with stderr containing 'Unknown configuration key. Supported keys: airsApiKey, airsApiToken, airsApiEndpoint, …, dataDir' (all 31 keys in schema order).
- `tenant path dev` prints only the registry configPath plus a newline to stdout, exits 0, and does not read or validate the config file (it succeeds even when the file is missing).
- All error output goes to stderr in the form '\n  ✗ Error: <message>\n\n' (exit 1), or '\n  ✗ <message>\n\n' for usage errors (exit 2). stdout is empty on error, and no ANSI escapes appear when stdout and stderr are piped.
- Doctor with a TSG-mismatched config reports a Config file check fail whose detail is '<path> carries a different mgmtTsgId than the registration (TSG <registry tsg>)', and exits 1.
- Doctor with PANW_MGMT_CLIENT_SECRET, PRISMA_AIRS_CONFIG_PATH and SCAN_CONCURRENCY set (plus PANW_AI_SEC_DEBUG, PRISMA_AIRS_TENANTS_PATH and XDG_STATE_HOME) reports an Environment warn with detail 'ignored 3 variables: PANW_MGMT_CLIENT_SECRET, PRISMA_AIRS_CONFIG_PATH, SCAN_CONCURRENCY; SDK diagnostics on: PANW_AI_SEC_DEBUG'. Only names are printed, never values.
- Doctor with an unreadable registry reports a Tenant fail whose detail contains 'tenant registry'; every later check is skipped with 'not evaluated — fix the failed checks above first', and the exit code is 1.


## Discrepancies
- BUG (credential env leak, depends on the TS SDK): runtimeInitOptions (src/config/client-options.ts:89-97) passes apiKey or apiToken as undefined when only one is configured. SDK init() then falls back to process.env.PANW_AI_SEC_API_KEY or PANW_AI_SEC_API_TOKEN (sdk dist/index.js:241-242), and ApiKeyAuth sends both headers (sdk:9577-9589). This contradicts 'credential environment variables are ignored' and docs-site/docs/reference/environment-variables.md:52-53 ('the SDK never falls back to them either'). No test covers it; client-options.spec.ts:194-199 only tests the case where both are missing.
- Doctor's registry-failure hint (src/cli/commands/doctor.ts:137) says 'PRISMA_AIRS_CONFIG_PATH bypasses the registry meanwhile', but PRISMA_AIRS_CONFIG_PATH is a retired, ignored variable (env.ts:19; loader.spec.ts:28; dlp-tenant-auth.spec.ts:242).
- Exit codes: the docs (getting-started/exit-codes-and-output.md:7-12) define 2 as the usage-error code, but commander parse errors (missing argument, unknown option, too many arguments, unknown subcommand, or a group invoked with no subcommand) exit 1, because no exitOverride is configured anywhere in src. Only CliUsageError/usageError paths exit 2.
- Streams: the docs (exit-codes-and-output.md:19-22, renderer/DESIGN.md:11-12) say stdout carries data only, but ui.success, ui.info, ui.emptyList and ui.bullet write to stdout (ui.ts:90-140). For example, an empty pretty `tenant list` prints '  No tenants found' to stdout, and tenant write success lines go to stdout.
- Docs reference/configuration.md:87 says airsNumRetries defaults to 5, but the schema has no default (schema.ts:15). The 5 comes from the SDK (sdk:273), and tenant read/get show the key as absent or empty.
- Docs reference/configuration.md:19-21 says '~ in any path value is expanded'. Only dataDir is expanded, by loader.ts expandHome, which turns `~foo` into `$HOME/foo`. PRISMA_AIRS_TENANTS_PATH uses a different expander (tenants.ts:42-44) that handles only `~` and `~/`. Registry configPath must be absolute and is never expanded.
- Docs cli/tenant.md:88 says `tenant read` shows 'file settings'. It actually shows the Zod-parsed effective config: unknown and retired keys are hidden, scanConcurrency and dataDir defaults always appear, numbers are coerced, and empty strings are shown as-is.
- `tenant get` emits a one-element array [{key, value}] in json/yaml, which conflicts with the 'details are objects' contract in exit-codes-and-output.md:45.
- Empty-string inconsistency: readTenantConfigFile validates raw values (tenants.ts:86), so `scanConcurrency: ""` makes a registered tenant file invalid. loader.spec.ts:97-100 ('treats empty strings as unset') only exercises the library-only explicit-path mode. Also, `airsNumRetries: ""` coerces to 0 and passes, but is then stripped to undefined (SDK default 5) while tenant read displays 0.
- Doctor's Config file check (doctor.ts:145-226) uses an unbounded readFile with no realpath, regular-file or 1 MiB checks, while every command uses readTenantConfigFile. For an oversized but valid config, doctor's file check passes or warns, inspectConfig throws and the error is swallowed (doctor.ts:675-679), the credential and probe checks become 'skip', and doctor can exit 0 while every command fails. EACCES and EISDIR are reported as 'not found at <path>'.
- A missing mgmtTsgId in a registered file surfaces as 'Tenant config TSG differs from its registered identity…' rather than a missing-credential message. settingRemedy can suggest `tenant set <name> <key>` for mgmtTsgId, which setTenantSetting refuses unless the value equals the pin (tenant-settings.ts:70-71).
- resolveEntry messages (tenant.ts:48-55) are not passed through commandHint and use wording different from NoTenantSelectedError (loader.ts:39-45): 'No tenant selected; pass a name or run …' versus 'No tenant selected. Run …'. fail() itself never applies commandHint.
- Credential presence checks trim (credentials.ts:15-17), but raw untrimmed mgmtClientId and mgmtClientSecret are sent to OAuth (client-options.ts:36-41). The SDK trims scanner key and token itself.
- The library-only explicit config mode (loader.ts:17-24, fromFile) silently falls back to defaults for missing or malformed files, unlike the fail-closed tenant path. The CLI never uses it, but doctor exposes a configFilePath dependency.
- Only 4 endpoint keys are URL-validated (mgmtDashboardEndpoint, agentGuardDataEndpoint, agentGuardMgmtEndpoint, typesafeBaseUrl). airsApiEndpoint, mgmtEndpoint and mgmtTokenEndpoint accept any string, so failures surface later in the SDK.
- The registry and config are decoded lossily as UTF-8 by Node (readFileSync 'utf8'), so invalid byte sequences inside JSON strings do not fail. A strict Rust parser would reject them.
- Docs cli/tenant.md:110-112 says doctor lists 'any PANW_* or PRISMA_AIRS_CONFIG_PATH variables'. It also lists TYPESAFE_*, SCAN_CONCURRENCY, DATA_DIR, MEMORY_* and ACCUMULATE_* names, and excludes the three SDK diagnostic PANW_ names.
- The e2e suite (vitest.e2e.config.ts) does not load tests/setup.ts registry isolation, so live e2e runs read the operator's real registry, through tests/helpers/live-tenant.ts. This relates to the user-noted claim that 'no tests hit live APIs'.
- Likely (unverified, could not run): `doctor --output xml` calls resolveOutput outside any try/fail (doctor.ts:799), so the CliUsageError would escape as a top-level-await rejection, probably exiting 1 with a raw error instead of the documented exit 2.


## Open questions
- How should airs-cli-rs select a tenant 'explicitly'? TS parity means only registry.active at PRISMA_AIRS_TENANTS_PATH or the XDG/HOME default, with no --tenant flag. Options are parity only (the harness writes an isolated registry, as live-tenant.ts isolatedRegistry does), or a Rust-only read-only `--tenant <name>` flag that applies the pin and never writes. The second would diverge from the TS CLI.
- Remedy and hint text names TS-only commands (`airs-cli tenant switch|set|create`) that airs-cli-rs will not implement. Should the Rust messages keep 'airs-cli …' verbatim (pointing users at the TS CLI for registry changes), rewrite them to 'airs-cli-rs', or should the harness normalize command names when comparing stderr?
- Exit code for argument-parse errors: the TS CLI (commander) exits 1, while clap and the stated contract use 2. Match actual TS behavior or the documented contract? The parity harness needs a decision.
- Should Rust replicate JS Number() coercion for scanConcurrency and airsNumRetries exactly (hex '0x5', '1e1', whitespace, booleans, [n] arrays, ''→0)? Otherwise some files are valid in one CLI and invalid in the other.
- Rust M2 initially supports only JSON output. What should happen when the tenant's defaultOutput is pretty, table, yaml, csv or markdown and no --output is given: fall back to JSON, reject with exit 2, or implement those formats?
- Should Rust fix the scanner env-fallback bug (recommended, since the Rust SDK never reads the environment)? Fixing it means live and fixture comparisons with PANW_AI_SEC_* set will differ on purpose.
- Should Rust's doctor Config file check use the same bounded reader as the loader (fixing the oversized, directory and EACCES divergence), or mirror the TS doctor exactly?
- Should airs-cli-rs honor AIRS_CLI_INVOKED_AS, PANW_AI_SEC_TIMEOUT_MS or PANW_AI_SEC_DEBUG (SDK diagnostics in TS), and should doctor's Environment check still treat the three SDK diagnostic names as 'honored'?
- Should the read-only tenant subcommands (list/ls, read, get, path) ship in M1? They need no credentials and help diagnose, but they require table, csv, markdown and yaml formatting with js-yaml-compatible quoting (for example tsgId: '100' and value: '[REDACTED]') for full parity.
- Should Rust accept invalid UTF-8 in registry or config files (Node decodes lossily), and handle duplicate JSON keys last-wins (parse into a serde_json Value, not a derived struct)? Doctor's ignored-key list follows JS key order, which would need serde_json's preserve_order feature to match.
