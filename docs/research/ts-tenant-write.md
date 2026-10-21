# TS CLI tenant write commands: behavioural specification for M4t

This spec covers `tenant create`, `set`, `unset`, `switch` and `delete` (`rm`) in the TypeScript `airs-cli`. It extends [ts-tenant-config.md](ts-tenant-config.md), which covers registry location, the read path, the config schema and the read-only subcommands. That material is cited here and not repeated.

**Sources.**
- The frozen reference `prisma-airs-cli` at `5711012246d325f20dbe93b710dcc697a7f18a8a` (`7.2.1-forgejo.0`), read from the sibling checkout. Line numbers point into that tree.
- The main files: `src/cli/commands/tenant.ts`, `src/config/tenants.ts`, `src/config/tenant-settings.ts`, `src/config/schema.ts`, `src/cli/tenant-input.ts`, `src/cli/confirm.ts`, `src/cli/renderer/{ui,common}.ts`, `src/cli/program.ts`, `src/cli/invocation.ts` and `src/cli/process-guards.ts`.
- Tests: `tests/unit/config/{tenants,tenant-settings}.spec.ts`, `tests/unit/cli/{tenant-input,tenant-wizard,confirm}.spec.ts` and `tests/integration/tenant-setup.spec.ts`.
- Docs: `docs-site/docs/cli/tenant.md`.
- Dependency sources under `.reference/prisma-airs-cli/node_modules/.pnpm`: `@inquirer/prompts` 8.3.0 with input 5.0.8, password 5.0.8, confirm 6.0.8 and core 11.1.5; commander 14.0.3; chalk 5.6.2; zod 3.25.76.

**Method.**
- Every "observed" result below was captured from the built reference (`.reference/prisma-airs-cli/dist/cli/index.js`, node v24.21.0) in throwaway sandboxes under the session scratchpad.
- The environment was cleared with `env -i HOME=<sandbox>/home PATH=/usr/bin:/bin NO_COLOR=1`, plus `PRISMA_AIRS_TENANTS_PATH` or `XDG_STATE_HOME` pointing into the sandbox. The cwd was `<sandbox>/cwd`.
- All values were fake (`FAKE-SECRET`, TSG `100`/`200`). No network was used.
- Interactive cases ran under a Python `pty` driver. stdin and stderr, or stdin, stdout and stderr, were attached to the pty, and the remaining streams were piped.
- Sandbox paths are shown as `<SB>`.
- In byte-exact strings, `\n` is LF and `\e` is ESC.

No real HOME, registry, config or `.env` file was touched. Neither TS checkout was modified.

---

## 1. Shared plumbing

### 1.1 Output channels

| Helper | Stream | Bytes (no colour) | `--quiet` | Source |
|---|---|---|---|---|
| `ui.success(msg)` | **stdout** | `  ✓ <msg>\n` | not suppressed | `ui.ts:90-93` |
| `ui.info(msg)` | **stdout** | `  ℹ <msg>\n` | suppressed | `ui.ts:106-110` |
| `ui.status(msg)` | stderr | `  <msg>\n` | suppressed | `ui.ts:131-135` |
| `fail(err)` | stderr | `\n  ✗ Error: <err.message>\n\n`, exit **1** (adds `    HTTP <n>` lines only when the error has `status`; no write path does) | n/a | `common.ts:12-25` |
| `usageError(msg)` | stderr | `\n  ✗ <msg>\n\n`, exit **2** | n/a | `common.ts:27-30` |

- Every success line of a write command goes to **stdout**, and `--quiet` does not hide it. The observed `airs-cli --quiet tenant switch prod` prints `  ✓ Selected prod (TSG 200)\n` on stdout.
- `ui.info` (the `unset` no-op and the `delete` "Aborted") also goes to stdout, but `--quiet` removes it.
- `ui.success`, `ui.info` and `ui.status` pass their text through `commandHint` (`invocation.ts:7-9`). `fail` and `usageError` do **not**.
  - Observed: with `AIRS_CLI_INVOKED_AS='airs cli'`, create prints `… Use airs cli tenant switch dev2.`
- `fail` prints `err.message` verbatim. Write paths therefore leak raw Node `fs` errors and raw Zod issue dumps; see sections 4.4 and 11.
- `tenantInputFailure` (`tenant.ts:23-30`) is used only by `create` and `set`.
  - For an error named `ExitPromptError` it prints the status `  Cancelled; no configuration saved.` on stderr (suppressed by `--quiet`) and sets `process.exitCode = 130`. Nothing goes to stdout.
  - Anything else goes to `fail` (exit 1).
  - `unset`, `switch` and `delete` call `fail` directly, so a prompt cancellation in `delete` exits 1 (section 9).

### 1.2 Commander parse errors (exit 1, D1)

None of these errors have the `✗` decoration. Each is one line on stderr, and the exit code is 1 (no `exitOverride`).

- `error: missing required argument 'name'`, and `'key'` for `set` and `unset`.
- `error: too many arguments for 'set'. Expected 3 arguments but got 4.`
- `error: too many arguments for 'switch'. Expected 1 argument but got 2.`
- `error: option '--tsg-id <id>' argument missing`
- `error: unknown option '--bogus'`
- A value that starts with `-` is parsed as an option: `tenant set dev mgmtEndpoint -x` gives `error: unknown option '-x'`. Negative numbers are positional: `tenant set dev scanConcurrency -1` reaches validation and gives `Invalid value for configuration setting`. `--` ends option parsing: `tenant create --tsg-id 100 -- -bad` reaches name validation.
- A name that looks like an option, `tenant create -bad`, gives `error: unknown option '-bad'`.
- Repeating an option keeps the last value: `--tsg-id 1 --tsg-id 2` registers TSG 2 (observed). A repeated boolean flag is accepted, per commander semantics.
- A root `--output xml` before a write command is consumed by the root and ignored. `airs-cli --output xml tenant switch dev` exits 0. Write commands never call `resolveOutput`, and `program.ts:162-175` skips the `tenant` parent.
- `--debug` is honoured: `--debug tenant switch dev` creates `./debug-api-<ms>-<8hex>.jsonl` in the cwd and prints the status `  Debug: API log → <path>` (D63).

### 1.3 Colour (D58)

- chalk 5.6.2 picks its level once, from **stdout** (`chalk/source/index.js:30`, vendored supports-color). It **ignores `NO_COLOR`** and honours `FORCE_COLOR`.
- Observed: under a pty with `TERM=xterm-256color` and `NO_COLOR=1`, the switch success line was still `  \e[32m✓ Selected dev (TSG 100)\e[39m`.
- Observed: with stdout a TTY and stderr piped, the error on the piped stderr was coloured.
- With stdout piped (the test setup) neither stream carries SGR.
- The exact coloured forms, captured with `FORCE_COLOR=1`:
  - success: `  \e[32m✓ <msg>\e[39m\n`
  - info: `  \e[36mℹ <msg>\e[39m\n`
  - `fail`: `\e[31m\e[39m\n\e[31m  ✗ Error: <msg>\e[39m\n\n`. chalk closes and reopens the colour on each line of the `\n`-prefixed string, and the final `console.error('')` is uncoloured.
  - `usageError`: `\e[31m\e[39m\n\e[31m  ✗ <msg>\e[39m\n\e[31m\e[39m\n`
  - status: `  \e[2m<msg>\e[22m\n` (from `chalk.dim`; not captured)
- Inquirer prompts style text with `node:util` `styleText` (`@inquirer/core/dist/lib/theme.js`). That follows `process.stdout`, not the prompt's stream. Observed: no SGR in any prompt when stdout was piped. Whether it honours `NO_COLOR` on a TTY was not captured; it does per Node's docs.

### 1.4 Help text (observed, stdout, exit 0)

The `tenant` group help lists, sorted:
- `create [options] <name>`: `Create a config with guided prompts, or register an existing JSON file; does not activate it`
- `delete|rm [options] <name>`: `Unregister a tenant; retain its source config file and clear the selection if it was selected`
- `set [options] <name> <key> [value]`: `Update one tenant setting; prompt when omitted, hide secrets`
- `switch <name>`: `Persist the selected tenant for subsequent commands`
- `unset <name> <key>`: `Remove one tenant setting so the default applies; credentials cannot be cleared`

These are followed by the nine `Examples:` lines (`tenant.ts:69-79`).

Per-command options:
- `create`: `--client-id <id>` (`OAuth client ID for a new config`), `--client-secret-stdin` (`Read the new config OAuth secret from piped stdin`), `--config <path>` (`Existing Prisma AIRS JSON config file (no copying or editing)`), `--tsg-id <id>` (`Tenant service group ID for a new config`).
- `set`: `--stdin` (`Read one value from piped stdin (recommended for automated secret updates)`).
- `delete`: `--force` (`Skip interactive confirmation`).
- `switch` and `unset` have only `-h, --help`.
- `tenant rm --help` prints `Usage: airs-cli tenant delete|rm [options] <name>`.

---

## 2. Validation rules

### 2.1 Tenant name: `validateTenantName` (`tenants.ts:133-139`)

- The regex is `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`: 1–64 ASCII characters, starting with a letter or digit.
- The failure message has an EN DASH (U+2013) in `1–64`:
  `Tenant name must be 1–64 letters, digits, hyphens or underscores and start with a letter/digit` (exit 1, via `fail`).
- Observed rejections: `a/b`, `space name`, 65×`a`, `` (empty argv), `é`, `_x`, and `-bad` (after `--`).
- Only `create` validates the name. `set`, `unset`, `switch` and `delete` look the name up. An invalid name is simply not found: `tenant switch 'bad name'` gives `Tenant not found`.

### 2.2 Setting key: `validateTenantSettingKey` (`tenant-settings.ts:14-19`)

- The check is `Object.hasOwn(ConfigSchema.shape, key)`. `__proto__`, `constructor`, unknown keys and the retired `*TokenEndpoint` keys are all rejected (observed).
- Message (exit 1):
  `Unknown configuration key. Supported keys: airsApiKey, airsApiToken, airsApiEndpoint, airsNumRetries, mgmtClientId, mgmtClientSecret, mgmtTsgId, mgmtEndpoint, mgmtDashboardEndpoint, mgmtTokenEndpoint, dlpEndpoint, redTeamDataEndpoint, redTeamMgmtEndpoint, redTeamNetworkBrokerEndpoint, modelSecDataEndpoint, modelSecMgmtEndpoint, agentGuardDataEndpoint, agentGuardMgmtEndpoint, aiGwDataEndpoint, aiGwAdminEndpoint, iamEndpoint, aiGwInferenceEndpoint, aiGwInferenceApiKey, aiGwInferenceModel, aiGwEmbeddingModel, typesafeApiKey, typesafeBaseUrl, typesafeModel, scanConcurrency, defaultOutput, dataDir`
- That is the full list of **31 settable keys**, in schema order. Every one of them can be `set`.

### 2.3 Secret and credential classes

- **Secrets** (`isTenantSecret`, `tenant-settings.ts:21-23`, `/(?:key|secret|token|password)$/i` on the key name). Exactly five of the 31 keys match: `airsApiKey`, `airsApiToken`, `mgmtClientSecret`, `aiGwInferenceApiKey` and `typesafeApiKey`.
  - Secrets may not be passed as an argv value (section 6).
  - They get a hidden prompt.
  - `read` and `get` redact them when truthy.
- **Credentials** (`CREDENTIAL_KEYS`, `tenant-settings.ts:64`) are `mgmtTsgId`, `mgmtClientId` and `mgmtClientSecret`.
  - `unset` refuses them.
  - Every rewrite requires all three to be non-blank.
  - `mgmtTsgId` and `mgmtClientId` are **not** secrets: they are echoed at the prompt and allowed on argv.
- **Blank-credential check**, with two different messages for the same rule:
  - `validateCredentials` (`tenant-settings.ts:25-32`), used by managed create and every rewrite: each of the three must be a `string` whose `.trim()` is non-empty, else `Tenant config requires nonempty mgmtTsgId, mgmtClientId and mgmtClientSecret`.
  - `createTenant` (`tenants.ts:151-152`), used by `--config` and as the second step of managed create: `Tenant config requires mgmtTsgId, mgmtClientId and mgmtClientSecret` (no "nonempty").

### 2.4 Value validation per key (`set`; `setTenantSetting`, `tenant-settings.ts:67-77`)

- The value is always a JS string: from argv, the prompt or stdin.
- `ConfigSchema.safeParse({...current, [key]: value})` validates the **whole** merged object.
- On failure the message is `Invalid value for configuration setting` (exit 1), and the value is never echoed.
- On success the stored value is the **parsed** output for that key, `Reflect.get(result.data, key)`. Coerced numbers are therefore stored as JSON numbers.

Observed results:

| Key class | Accepted (stored as) | Rejected |
|---|---|---|
| `scanConcurrency` (`z.coerce.number().int().min(1).max(20)`) | `7`→7, `' 7 '`→7, `0x5`→5, `0b11`→3, `+3`→3, `1e1`→10, `5.0`→5, `1`, `20` | `0`, `21`, `''` (coerces to 0), `abc`, `5.5`, `-1`, `Infinity`, `1_0` |
| `airsNumRetries` (int 0..5) | `0`, `3`, `5`, and **`''`→0** | `6`, `true` (`Number('true')` is NaN) |
| `defaultOutput` (enum) | `pretty`, `table`, `markdown`, `csv`, `json`, `yaml` | `JSON` (case-sensitive), `xml`, `''` |
| URL keys `mgmtDashboardEndpoint`, `agentGuardDataEndpoint`, `agentGuardMgmtEndpoint`, `typesafeBaseUrl` (`z.string().url()`, which is `new URL()`) | `https://x.test`, `http://127.0.0.1:1/`, **`localhost:8080`**, **`mailto:x`** | `not a url`, `''`, `https://`, `http://exa mple.com` |
| All other 23 string keys, including `mgmtEndpoint`, `mgmtTokenEndpoint`, `airsApiEndpoint`, `dataDir` and the models | anything: `not a url`, `''`, `'  '`, `file:///etc/passwd`, `rel/dir`, `~/runs` | nothing |
| `mgmtTsgId` | only a value **byte-equal** to the registry `tsgId` (`' 100'` is rejected when the pin is `100`) | anything else: `TSG identity is pinned; create another tenant instead of changing mgmtTsgId` (checked before the file is read) |
| `mgmtClientId` | any non-blank string | `''`, `'  '`: `Tenant config requires nonempty …` (after schema validation, inside the rewrite) |
| Secret keys | only via prompt or `--stdin`, so never empty (both inputs refuse blanks, section 3) | any argv value, `''` included |

There are no boolean keys in the schema. The only numeric keys are the two above.

---

## 3. Input channels

### 3.1 Prompt: `promptTenantValue(message, secret)` (`tenant-input.ts:3-17`)

- **Gate.** The prompt needs `process.stdin.isTTY && process.stderr.isTTY`. Otherwise it throws (exit 1):
  `Interactive setup requires a terminal. Use --config, or --tsg-id and --client-id with --client-secret-stdin. For tenant set, pass a value or use --stdin.`
  - The same text is used for `create` and `set`.
  - Observed with only stdin on a pty: the same error.
  - stdout need not be a TTY. The prompt is written to stderr.
- `secret=false` uses `@inquirer/input` and `secret=true` uses `@inquirer/password`. Both use `{input: process.stdin, output: process.stderr}`.
- **Validation** is `value.trim() !== ''`, else the prompt re-asks inline with `> A nonempty value is required`.
  - The returned value is **not trimmed**. A prompt answer of ` 100 ` is stored as `" 100 "` (observed).
  - No other validation happens at the prompt. A bad value (`defaultOutput` `xml`) is accepted by the prompt, then fails afterwards with `Invalid value for configuration setting` and exit 1, with no re-prompt (observed).
- **Rendering** (observed on the pty, without colour):
  - Input prompt: `? <message> <typed text>`. When done: `✔ <message> <value>`, then `\r\n\e[?25h`.
  - Password prompt: `? <message> [input is masked]\e[?25l`. Nothing typed is echoed (no mask characters). When done: `✔ <message>`, with **no value shown**, then `\e[?25h`.
  - Prompt texts: `Tenant service group ID (mgmtTsgId):`, `OAuth client ID (mgmtClientId):`, `OAuth client secret (mgmtClientSecret):` (hidden), and for `set`, `<key>:` (hidden when `isTenantSecret(key)`).
- **Ctrl-C** makes inquirer reject with `ExitPromptError` (`create-prompt.js:69`).
  - `create` and `set` respond with stderr `  Cancelled; no configuration saved.` and **exit 130**. Nothing is written.
  - With `--quiet` the status line is suppressed but the exit is still 130 (observed).
- **Ctrl-D** (EOF on the TTY) at a `create` prompt was observed to print `Warning: Detected unsettled top-level await at file:///…/dist/cli/index.js:15804` and the `await buildProgram().parseAsync();` caret block, then `  Cancelled; no configuration saved.`, then exit 130. signal-exit turns Node's exit 13 into an `ExitPromptError`.

### 3.2 Piped stdin: `readTenantStdin()` (`tenant-input.ts:19-36`)

This is used by `create --client-secret-stdin` and `set --stdin`.

1. If `process.stdin.isTTY`, it throws `--stdin requires piped input`. That text is used for the `create` flag too (observed).
2. It reads every chunk until EOF. After each chunk, if the cumulative **raw byte** count exceeds 65,536, it throws `Configuration input exceeds 64 KiB`.
   - The final newline counts toward the limit: 65,536 bytes is accepted, but 65,536 bytes plus `\n` (65,537) is rejected (observed).
   - Without EOF it waits forever, with no timeout. SIGINT or SIGTERM kills Node by signal (exit 130/143, no message, nothing written; observed).
3. It decodes UTF-8 **lossily**: `\xff\xfe` becomes U+FFFD U+FFFD and is stored (observed).
4. It strips exactly one trailing `\n` or `\r\n` (`/\r?\n$/`).
5. It rejects (`Provide one nonempty configuration value on stdin`) when what remains is blank under `.trim()`, or contains `\r`, `\n` or `\0`.
   - Observed rejections: empty input, `FAKE\nsecond`, `FAKE\n\n`, `   \n`, `FAKE\0SECRET` and `FAKE\r` (a bare CR is not stripped).
   - Observed acceptances: `FAKE-SECRET`, `FAKE-SECRET\n`, `FAKE-SECRET\r\n` (all stored as `FAKE-SECRET`) and `  FAKE SECRET  \n` (stored with its spaces).
6. Other control characters (ESC, TAB, BEL) are accepted as-is.

### 3.3 Confirmation: `confirmOrAbort(message, force, {action})` (`confirm.ts:32-55`)

1. `--force` returns immediately.
2. Interactivity is decided by **`process.stdout.isTTY` only**. If stdout is not a TTY, the call is `usageError('refusing to <action> without --force in non-interactive mode')` and **exits 2**. This holds even when stdin and stderr are TTYs (observed).
3. Otherwise `@inquirer/confirm` runs with `{message, default: false}`. It has **no stream options**, so it reads `process.stdin` and writes `process.stdout`.
   - Rendering: `? <message> (y/N) `. `y`, `yes` or anything matching `/^(y|yes)/i` confirms. Enter, `n` or anything else declines.
   - Done line: `✔ <message> Yes|No`.
4. **Decline** prints `  ℹ Aborted` on stdout and exits **0**. `--quiet` suppresses the text but the exit is still 0.
5. **Ctrl-C** is not caught by `confirmOrAbort`. The `ExitPromptError` reaches `fail`: `\n  ✗ Error: User force closed the prompt with SIGINT\n\n`, exit **1** (observed; the docs promise 130 only for create).
6. If stdout is a TTY but **stdin is a closed pipe** (EOF; observed), the result is the unsettled-top-level-await warning followed by `\n  ✗ Error: User force closed the prompt with 13 null\n\n`, exit 1.

---

## 4. Files, modes, locking and atomicity

### 4.1 Locations and environment variables

- **Registry path** `R`, as in ts-tenant-config §1:
  - `PRISMA_AIRS_TENANTS_PATH` when non-empty, with `~` and `~/` expanded, then `path.resolve` against the **cwd**. Observed: `rel/t.json` went to `<cwd>/rel/t.json`, and `~/r/t.json` went to `$HOME/r/t.json`.
  - Otherwise `$XDG_STATE_HOME/prisma-airs/tenants.json`.
  - Otherwise `$HOME/.local/state/prisma-airs/tenants.json`.
- A relative `XDG_STATE_HOME` makes every write that resolves `R` fail with `XDG_STATE_HOME must be an absolute path` (exit 1). This is not checked when `PRISMA_AIRS_TENANTS_PATH` is set.
- **Managed config directory**: `dirname(R)/configs`. It follows whichever variable chose `R` (observed for all three forms).
  - Two registries in one directory share a `configs/` directory.
- **Managed config file**: `configs/<name>-<randomUUID v4>.json`, for example `dev-1a6b359d-c111-4533-ab75-afeb36c1cccd.json`.
  - The registry stores its **realpath**. Observed: a registry reached through a symlinked directory recorded `<SB>/real/configs/…`. On macOS `/tmp` would become `/private/tmp`.
- **Lock files**:
  - Registry: `R + '.lock'`.
  - Config: `<configPath>.lock`, next to the config, which may be a user's `/secure/x.json` registered with `--config`.
- **Temporary files**:
  - Registry: `dirname(R)/.airs-tenants-<uuid>.tmp`.
  - Config: `dirname(configPath)/.airs-config-<uuid>.tmp`.
- **Environment variables that change any write location:** `PRISMA_AIRS_TENANTS_PATH`, `XDG_STATE_HOME` and `HOME` (through `os.homedir()`, and for `~` in `PRISMA_AIRS_TENANTS_PATH` and in `create --config`). The cwd affects relative `PRISMA_AIRS_TENANTS_PATH`, relative `--config` paths and the `--debug` log. No variable supplies a value.
  - `AIRS_CLI_INVOKED_AS` changes hint text only.
  - `FORCE_COLOR` and `TERM` change colour.
  - `NO_COLOR` is ignored by chalk.

### 4.2 Registry write: `changeStore(change)` (`tenants.ts:97-131`)

This is used by `createTenant`, `switchTenant` and `deleteTenant`.

1. `mkdir(dirname(R), {recursive: true, mode: 0o700})`.
   - Every directory it **creates** gets 0700 (minus umask). Observed: a sandbox HOME received `.local`, `.local/state` and `.local/state/prisma-airs` at `drwx------`, and `a/b/` under `umask 000` were both 0700.
   - An existing directory is **not** tightened. A pre-existing 0755 `reg/` stays 0755.
   - This runs before the lock and before any validation. `tenant switch dev` with no registry creates the registry directory and then fails with `Tenant not found` (observed).
2. `open(R.lock, 'wx', 0o600)` takes an exclusive-create lock. The file is empty and holds no pid.
   - Any failure (EEXIST, EACCES, ENOENT) gives `Cannot lock tenant registry at <R>.lock; another change may be in progress`.
   - There is **no wait, no retry and no stale detection**. A lock left behind blocks every registry write until someone removes it by hand. The docs (`tenant.md:105-106`) tell users to do that.
3. Under the lock, `readTenantStore()` runs (the strict reader; any defect gives the generic `Cannot read tenant registry …`), then `change(store)` mutates the Zod-parsed object, then `StoreSchema.parse(store)` validates again.
   - Errors thrown by `change` (`Tenant not found`, `Tenant name already exists`, pin or config errors) propagate.
   - A failure of the re-validation propagates as a **raw ZodError**, whose message is the JSON issue list. Observed when adding a 1001st tenant:
     ```
     
       ✗ Error: [
       {
         "code": "too_big",
         "maximum": 1000,
         "type": "array",
         "inclusive": true,
         "exact": false,
         "message": "Array must contain at most 1000 element(s)",
         "path": [
           "tenants"
         ]
       }
     ]
     
     ```
4. `open(tmp, 'wx', 0o600)`, write `JSON.stringify(store, null, 2) + '\n'`, `fsync`, `close`, `rename(tmp, R)`.
   - The directory is **not** fsynced.
   - On failure the tmp file is unlinked. A crash or SIGKILL between `open(tmp)` and `rename` leaves the tmp file, and nothing ever cleans it up.
5. `finally`: close and unlink the lock. That cleanup is skipped if the process dies by signal: Node's default SIGINT/SIGTERM handling runs no `finally`.

**Registry bytes.** The write is the Zod-parsed object.
- Key order is always `version, active, tenants`, and each entry is `name, configPath, tsgId`, whatever the order in the file.
- Indentation is 2 spaces, with a trailing LF.
- A hand-written `"version":1.0` becomes `1`.
- Entry order is kept, except that **create re-sorts all entries** with `a.name.localeCompare(b.name)` (`tenants.ts:158`). `switch` and `delete` keep the existing order (observed).
- `localeCompare` depends on ICU and the locale (`LANG`/`LC_ALL`). Observed with `en-US`: `10 9 a a_b a-b a1 A1 ab aB b B prod Z`. `da_DK` puts `aa` after `z`, and `lt_LT` puts `y` before `j`.
- The new file is always mode **0600**, whatever the old mode. Observed: a registry at **0444 was silently replaced with a 0600 file**, so the registry has no read-only protection, unlike configs (section 4.4). Ownership becomes the current user.
- The **1 MiB read limit is not checked on write**. Observed: a create that took the registry from 1,048,376 to 1,048,598 bytes succeeded. After that, `tenant list` and `tenant delete` fail with `Cannot read tenant registry …`. A successful write can brick the registry.

### 4.3 Managed config creation: `createManagedTenant` (`tenant-settings.ts:35-61`)

1. `validateTenantName`, `validateTenantSettingKey` for each key, `ConfigSchema.safeParse` (`Invalid tenant configuration`; unreachable from the CLI, which passes only the three credential keys), `validateCredentials`, then the duplicate-name check against the registry (unlocked).
2. `mkdir(dirname(R)/configs, {recursive: true, mode: 0o700})`. This is **outside any try**: EACCES surfaces raw, as `EACCES: permission denied, mkdir '<SB>/reg/configs'` (observed).
3. `open(path, 'wx', 0o600)`, also outside the try. Observed raw: `EACCES: permission denied, open '<SB>/reg/configs/dev-<uuid>.json'`.
4. It writes `{mgmtTsgId, mgmtClientId, mgmtClientSecret}` in that order, from the Zod output with no defaults added, as `JSON.stringify(data, null, 2) + '\n'`. Then `fsync` and `close`.
   - This is a **direct write to the final name**, not temp-and-rename. A crash mid-write leaves a partial or empty `configs/<name>-<uuid>.json` that is not registered.
5. It calls `createTenant(name, path)` (section 5.2 steps 3–6), which registers through `changeStore`. **Any** failure there, whether lock contention, a lost duplicate race or the 1000-entry cap, closes and unlinks the new file and becomes `Could not create tenant configuration; registration was not completed`. The `configs/` directory stays behind, empty (observed).

### 4.4 Config rewrite: `rewriteTenantConfig(entry, change)` (`tenant-settings.ts:105-143`)

This is used by `set` and `unset`. **No registry lock is taken.**

1. `open(<configPath>.lock, 'wx', 0o600)`. Any failure gives `Cannot lock tenant config; it may be read-only or another edit is in progress`. That covers EEXIST, an unwritable directory and a missing directory (observed for the first two).
2. `lstat(configPath)`. A missing file escapes **raw**: `ENOENT: no such file or directory, lstat '<SB>/src/prod.json'` (observed). The lock is still removed.
3. The file is refused if it is not a regular file, including a **symlink**, or if `(mode & 0o222) === 0`. The message is `Tenant config is not a writable regular file`. Observed for 0400 and for a symlinked config.
4. `access(W_OK)`. A failure surfaces as the raw Node `EACCES: … access '<path>'` text (from the code; not captured). A file with a write bit that the caller cannot write, such as one owned by another user, would hit this.
5. `readTenantConfigFile(path, tsgId)`. This is the strict read plus the pin. It returns the **raw** JSON object, so unknown and retired keys are kept.
6. `change(current)`, then `validateCredentials(next)`. If `next === current` (only for an `unset` of an absent key) it returns without writing.
7. `open(.airs-config-<uuid>.tmp, 'wx', 0o600)`, write `JSON.stringify(next, null, 2) + '\n'`, `fsync`, `rename` over `configPath`. The directory is not fsynced. The tmp file is unlinked on error.
8. `finally`: close and unlink the lock.

**Rewrite effects** (observed on a `--config` file that started at 0644):
- The mode becomes 0600 and the owner becomes the current user.
- A hard link to the old file is broken, and xattrs and ACLs are lost.
- The original formatting is replaced with 2-space JSON.
- Existing keys keep their position. A new key is appended at the end.
- Unknown and retired keys are kept verbatim, including nested objects.
- Raw values are kept unparsed: `"scanConcurrency":"3"` stays a string.
- Numbers go through JS doubles: `1.50` became `1.5`, and `12345678901234567890` became `12345678901234567000`.
- `set` and `unset` therefore **modify a file registered with `--config`**, even though `create --config` says `config file unchanged`. The docs (`tenant.md:10-11`) promise only that registering, switching, reading and deleting leave it alone.

---

## 5. `tenant create <name>` (`tenant.ts:82-123`)

### 5.1 Validation order (common prefix)

1. `validateTenantName(name)`.
2. If `opts.config` is **truthy** and any of `tsgId !== undefined`, `clientId !== undefined` or `clientSecretStdin` holds, the error is `--config cannot be combined with new-config options`.
   - `--client-id ''` still counts as given (observed).
   - `--config ''` is falsy, so it is treated as no `--config` and the guided path runs (observed: the terminal-required error).
3. If there is no `--config`: `readTenantStore()` (corrupt registry gives `Cannot read tenant registry at <R>; restore a valid registry before proceeding`), then the duplicate check, `Tenant name already exists`. Both happen **before any prompt or stdin read**.

### 5.2 `--config <path>` (`createTenant`, `tenants.ts:142-161`)

1. `validateTenantName` again.
2. `realpathSync(resolve(expandConfigPath(path)))`. Relative paths are resolved against the cwd, and `~`/`~/` are expanded. Any failure (missing file, dangling link, EACCES on a parent) gives `Tenant config file does not exist or cannot be resolved`.
3. `readTenantConfig(realpath)`: regular file, at most 1 MiB, a JSON object, schema-valid; no pin yet. A failure gives `Cannot read a valid tenant config at <realpath>`. Observed for bad JSON, `scanConcurrency: 99` and a directory.
4. The trimmed presence check gives `Tenant config requires mgmtTsgId, mgmtClientId and mgmtClientSecret`. Observed for `{"mgmtTsgId":"300"}` and for a whitespace `mgmtClientId`.
5. `changeStore`: lock (`Cannot lock tenant registry …`), then registry read (`Cannot read tenant registry …`), then the duplicate check (`Tenant name already exists`, only here for `--config`), then push and sort.
   - A duplicate name with an invalid file therefore reports the **file** error first.
   - A relative `XDG_STATE_HOME` with a missing file reports the **file** error first (observed).
6. The entry is `{name, configPath: realpath, tsgId: config.mgmtTsgId}`. tsgId is untrimmed.
   - Several names may share one `configPath`: `prod` and `prod2` both pointed at `src/prod.json` (observed).
   - Unknown and retired keys in the file are accepted.
   - The file's bytes, mode and mtime are untouched, and a 0400 file is fine.
7. Success (stdout): `  ✓ Registered <name> (TSG <tsg>); config file unchanged. Use airs-cli tenant switch <name>.` The registration is **not** activated.

### 5.3 Guided path and flags

- Values are collected in order:
  - `mgmtTsgId` = `--tsg-id`, else prompt 1.
  - `mgmtClientId` = `--client-id`, else prompt 2.
  - `mgmtClientSecret` = `readTenantStdin()` if `--client-secret-stdin`, else hidden prompt 3.
- There is **no flag for the secret value**; only stdin or the prompt can supply it.
- Each missing value hits the terminal gate (section 3.1) when it is reached. `create dev --tsg-id 100` without a TTY fails at prompt 2. `create dev --client-secret-stdin` without a TTY fails at prompt 1, before reading stdin (observed).
- With a TTY and `--client-secret-stdin` but no IDs, the user answers prompts 1 and 2 before `--stdin requires piped input` fails (from the code).
- After all three are collected, `createManagedTenant` runs (section 4.3).
  - Blank `--tsg-id ''` or `--client-id ' '` gives `Tenant config requires nonempty mgmtTsgId, mgmtClientId and mgmtClientSecret`, after stdin has been read.
  - Empty stdin gives `Provide one nonempty configuration value on stdin` first (observed).
- `--tsg-id` and `--client-id` are not checked for format or control characters. Observed: `--tsg-id $'1\e[31mX\nY'` was stored in the registry and printed raw in `create` and `switch` success lines (terminal injection; compare D52). `tenant list --output json` showed `"1\u001b[31mX\nY"`.
- Non-digit TSGs are accepted (compare D28).
- Success (stdout): `  ✓ Registered <name> (TSG <tsg>); private config created. Use airs-cli tenant switch <name>.` The tenant is not activated.

### 5.4 Captured create transcripts

```
$ printf 'FAKE-SECRET\n' | airs-cli tenant create dev --tsg-id 100 --client-id client-100 --client-secret-stdin
stdout: "  ✓ Registered dev (TSG 100); private config created. Use airs-cli tenant switch dev.\n"   exit 0
files:  R (0600), dirname(R)/configs (0700), configs/dev-<uuid>.json (0600):
        {\n  "mgmtTsgId": "100",\n  "mgmtClientId": "client-100",\n  "mgmtClientSecret": "FAKE-SECRET"\n}\n
        R: {\n  "version": 1,\n  "active": null,\n  "tenants": [\n    {\n      "name": "dev",\n      "configPath": "<realpath>",\n      "tsgId": "100"\n    }\n  ]\n}\n

$ airs-cli tenant create dev            (no TTY)
stderr: "\n  ✗ Error: Interactive setup requires a terminal. Use --config, or --tsg-id and --client-id with --client-secret-stdin. For tenant set, pass a value or use --stdin.\n\n"   exit 1   (no files, no directories)

$ airs-cli tenant create dev --config /unused --tsg-id 100
stderr: "\n  ✗ Error: --config cannot be combined with new-config options\n\n"   exit 1

$ airs-cli tenant create dev …           (registry lock held, managed path)
stderr: "\n  ✗ Error: Could not create tenant configuration; registration was not completed\n\n"   exit 1   (configs/ left, empty; lock untouched)

$ airs-cli tenant create prod --config …  (registry lock held)
stderr: "\n  ✗ Error: Cannot lock tenant registry at <R>.lock; another change may be in progress\n\n"   exit 1
```

Guided (pty on stdin and stderr). Prompt 1 receives `100⏎`, prompt 2 `client-100⏎`, prompt 3 `FAKE-SECRET⏎`. The stderr transcript ends with `✔ OAuth client secret (mgmtClientSecret):`, the secret is never echoed, and stdout carries the same success line. Ctrl-C at any prompt gives stderr `  Cancelled; no configuration saved.`, exit 130, and no files (`tenant-wizard.spec.ts:50-60`).

---

## 6. `tenant set <name> <key> [value] [--stdin]` (`tenant.ts:125-150`)

The checks run in this order, each exiting 1:

1. `validateTenantSettingKey(key)`. This runs **before** the registry is read, so it wins even over a corrupt registry or a relative `XDG_STATE_HOME` (observed).
2. `readTenantStore()`, then the existence check, `Tenant not found; register a named tenant first`. Note the suffix, unlike `switch` and `delete`.
3. `--stdin` together with a value gives `Use a value or --stdin, not both`. This runs before the secret check, so `set dev airsApiKey X --stdin` reports this message.
4. A secret key with a value (any value, `''` included) gives `Do not pass credentials as arguments. Omit the value for a hidden prompt, or use --stdin.` The value has already been on argv by then: the refusal does not stop it from appearing in shell history or `ps`.
5. The value comes from `--stdin` (section 3.2), else argv, else the prompt (`<key>:`, hidden for secrets; section 3.1).
6. `setTenantSetting` (`tenant-settings.ts:67-77`):
   - `validateTenantSettingKey` again, then `findTenant` (the registry is re-read), then the **pin** (`mgmtTsgId` must equal `entry.tsgId` exactly), then `rewriteTenantConfig` (section 4.4).
   - Inside the rewrite: lock, `lstat`, writable check, strict read with pin, schema merge (`Invalid value for configuration setting`), then `validateCredentials`.
7. Success (stdout): `  ✓ Updated <key> for tenant <name>; selection unchanged.` The file is **always rewritten**, even when the value is unchanged. `set dev mgmtTsgId 100` with pin `100` succeeds and rewrites.

Consequences:

- A file without credentials can be `switch`ed (section 8) but **cannot be repaired with `set`**. Every rewrite runs `validateCredentials`, so adding `mgmtClientId` alone fails with `Tenant config requires nonempty …` while the secret is still absent (observed on `{"mgmtTsgId":"200","defaultOutput":"json"}`).
- `set` does not take the registry lock, so it can race `delete` and `switch` (section 12).
- No value is ever echoed in an error. `tenant-settings.spec.ts:79-96` checks that `FAKE-SECRET` never appears and that the file bytes are unchanged on rejection.

---

## 7. `tenant unset <name> <key>` (`tenant.ts:152-163`; `unsetTenantSetting`, `tenant-settings.ts:83-96`)

The checks run in this order, each exiting 1 via `fail`:

1. `validateTenantSettingKey(key)`. Unknown and **retired keys cannot be unset**: `unset dev redTeamTokenEndpoint` and `unset dev custom` give the `Unknown configuration key …` error (observed). This contradicts doctor's hint `remove them with 'airs-cli tenant unset <name> <key>'` (ts-tenant-config §11).
2. A credential key gives `<key> is a credential and cannot be cleared; set a new value instead`. This runs before the tenant lookup, so `unset nope mgmtClientId` reports it (observed). Secret non-credentials (`airsApiKey` and the other three) **can** be unset.
3. `findTenant`, `Tenant not found; register a named tenant first`.
4. `rewriteTenantConfig`. The lock, writable and strict-read checks run **even when the key is absent**. A read-only config gives `Tenant config is not a writable regular file` for a no-op unset (observed).
5. If the key was present, it is removed and the file rewritten. stdout: `  ✓ Removed <key> from tenant <name>; selection unchanged.`
6. If it was absent there is no write. stdout: `  ℹ <key> is not set for tenant <name> — nothing to do`, with an EM DASH (U+2014). `--quiet` suppresses this, giving empty output and exit 0.
   - Defaulted keys (`scanConcurrency`, `dataDir`) that are absent from the file report "not set" even though `tenant get` shows a value.

`unset` never prompts and does not use `tenantInputFailure`.

---

## 8. `tenant switch <name>` (`tenant.ts:183-193`; `switchTenant`, `tenants.ts:164-173`)

1. `changeStore`: `mkdir` of the registry directory (created even when the switch then fails), lock, registry read.
2. Lookup gives `Tenant not found` (no suffix, no hint).
3. `readTenantConfig(configPath, tsgId)` runs **under the registry lock**:
   - `Cannot read a valid tenant config at <configPath>` for a missing, invalid or oversized file, or a directory;
   - `Tenant config TSG differs from its registered identity; register it under a new name` for a pin mismatch.
4. `active = name`, then the atomic rewrite (section 4.2). There is no credential check: a pinned `{"mgmtTsgId":"200"}` with no client ID or secret switches successfully (observed).
5. Success (stdout): `  ✓ Selected <name> (TSG <tsg>)`. Switching to the tenant that is already active rewrites the registry and prints the same line.
6. On any failure the prior `active` is unchanged (`tenants.spec.ts:131-144`).

---

## 9. `tenant delete <name> [--force]` (alias `rm`; `tenant.ts:253-277`; `deleteTenant`, `tenants.ts:179-190`)

1. `readTenantStore()`, then the existence check, `Tenant not found`. This runs before the confirmation, so `delete nope` without `--force` exits 1, not 2 (observed).
2. `selected = (store.active === name)`, read **before** the lock.
3. `confirmOrAbort(msg, force, {action: 'unregister tenant <name>'})` (section 3.3).
   - The message is `Unregister tenant <name>?` + (`selected` ? ` It is the selected tenant; no tenant will be selected afterwards.` : ``) + ` Its config file will be retained.`
   - Without a TTY on stdout and without `--force`: stderr `\n  ✗ refusing to unregister tenant <name> without --force in non-interactive mode\n\n`, exit **2**. The same holds with `--quiet`.
4. `deleteTenant` (`changeStore`) re-checks existence under the lock (`Tenant not found`), filters the entry out, and sets `active = null` if it was active.
5. Success (stdout):
   - `  ✓ Unregistered <name>; source config file retained`
   - or, when the selection was cleared: `  ✓ Unregistered <name>; source config file retained; no tenant is selected`
6. The config file is **never deleted**, including CLI-created `configs/<name>-<uuid>.json` files that hold the OAuth secret.
   - Re-creating the same name writes a new `<name>-<uuid2>.json`, so plaintext secrets accumulate as orphans.
   - Observed: after `delete dev --force` the `configs/dev-<uuid>.json` (0600) with `FAKE-SECRET` remained and the registry was `{"version":1,"active":null,"tenants":[]}`.
7. `delete` never reads the config, so it works on a missing or corrupt config. That is the recovery path.

Observed interactive results (stdout on the pty):

| Input | Output | Exit |
|---|---|---|
| Enter | `✔ Unregister tenant dev? It is the selected tenant; no tenant will be selected afterwards. Its config file will be retained. No`, then `  ℹ Aborted` | 0 |
| `n` | the same | 0 |
| `y` / `yes` | the `✓ Unregistered …` line | 0 |
| Ctrl-C | stderr side: `\n  ✗ Error: User force closed the prompt with SIGINT\n\n` | 1 |

---

## 10. TSG pin interactions

- The pin is set at registration: `tsgId = mgmtTsgId` from the file (`--config`) or from `--tsg-id`/the prompt (guided). It is never trimmed.
- It is enforced by:
  - `switch`, under the registry lock;
  - `set` and `unset`, at `setTenantSetting` time for a `mgmtTsgId` value, and in the rewrite's strict read for the file's current `mgmtTsgId`;
  - `read`, `get` and every API command (ts-tenant-config §4).
- It is **not** enforced by `list`, `path` or `delete`.
- A mismatched file cannot be fixed through the CLI: `set dev mgmtTsgId <registered>` reads the file first and fails on the pin. The only remedy is to delete the tenant and re-register under a name (`register it under a new name`).
- `create --config` of a file whose `mgmtTsgId` was later changed on disk is fine. The new registration pins the new value.

---

## 11. Corrupt and abnormal inputs (observed unless noted)

| Condition | create (managed) | create `--config` | set / unset | switch | delete |
|---|---|---|---|---|---|
| Registry invalid (`{bad`) | `Cannot read tenant registry at <R>; restore a valid registry before proceeding` (before prompts) | the same, after the file checks | the same; `set` with an unknown key reports the key error first | the same | the same |
| Relative `XDG_STATE_HOME` | `XDG_STATE_HOME must be an absolute path` | file errors first, then this | the same; key and credential errors first | the same | the same |
| Registry lock present | `Could not create tenant configuration; registration was not completed` (the new file is removed) | `Cannot lock tenant registry at <R>.lock; another change may be in progress` | not affected | `Cannot lock …` | `Cannot lock …` (after confirmation) |
| Registry 0444 | written; becomes 0600 | the same | n/a | the same | the same |
| Registry directory not writable | raw `EACCES: permission denied, mkdir '<dir>/configs'` | `Cannot lock …` | not affected | `Cannot lock …` | `Cannot lock …` |
| Registry at 1000 entries | `Could not create …` | raw ZodError JSON (section 4.2) | not affected | not affected | not affected |
| Config lock present | n/a | n/a | `Cannot lock tenant config; it may be read-only or another edit is in progress` | not affected (no config lock) | not affected |
| Config 0400 / symlink | n/a | accepted | `Tenant config is not a writable regular file` | accepted | not read |
| Config missing | n/a | `Tenant config file does not exist or cannot be resolved` | raw `ENOENT: no such file or directory, lstat '<path>'` | `Cannot read a valid tenant config at <path>` | not read |
| Config invalid / TSG mismatch | n/a | `Cannot read a valid tenant config at <realpath>` | `Cannot read a valid tenant config at <path>` / pin message | the same | not read |
| Config without credentials | n/a | `Tenant config requires mgmtTsgId, mgmtClientId and mgmtClientSecret` | `Tenant config requires nonempty …` | accepted | not read |

---

## 12. Concurrency and crash behaviour

- **Registry writers** (create, switch, delete) serialise through `O_EXCL` on `R.lock`. A loser fails immediately and never waits.
  - Observed: six parallel guided creates of different names gave one success and five `Could not create tenant configuration; registration was not completed`. No orphans were left, because each removed its own file.
- **Config writers** (set, unset) serialise through `<config>.lock`.
  - Observed: of six parallel `set`s of different keys, one succeeded and the rest got `Cannot lock tenant config …`. No update was lost; the losers failed.
- **Reads take no lock.** `switch` reads a config while a `set` may be rewriting it. Because the write is a rename, the reader sees either the old or the new file.
- **Registry and config are not locked together.**
  - `set` can update a config while a concurrent `delete` unregisters it.
  - `delete`'s "selected" text comes from an unlocked read before the prompt. The final `selectionCleared` comes from the locked read, so the success line is accurate but the prompt text may not be.
- **Managed create** checks for duplicates twice: unlocked at `tenant.ts:103` and `tenant-settings.ts:41`, then locked in `createTenant`. A race between the two is masked as `Could not create …`.
- **Crashes.** Node's default SIGINT/SIGTERM (outside a prompt) and SIGKILL skip `finally`:
  - a `.lock` file left behind blocks that file's writes until removed by hand;
  - a `.airs-*.tmp` file may be left behind;
  - a guided create interrupted after writing its config but before registering leaves an unregistered secret file.
  - Writes are fsynced, but the directories are not, so a rename may not survive a power loss.
- The lock files are empty. There is no pid, host or age to detect staleness, and no tooling to break a stale lock.

---

## 13. What the read commands show afterwards (observed)

After create (`dev`, TSG 100), then `set scanConcurrency 0x7`, `set defaultOutput yaml`, `set airsNumRetries ''`, `set mgmtEndpoint ''` and `set airsApiKey --stdin`:

- `tenant list --output json` gives `[{"name":"dev","configPath":"<SB>/reg/configs/dev-<uuid>.json","tsgId":"100","active":false}]`. Because nothing is selected, stderr also carries `  No tenant selected; run 'airs-cli tenant switch <name>'.` After `switch`, `active` is `true` and the status line is gone.
- `tenant read dev --output json` gives rows in schema order: `airsApiKey` `[REDACTED]`, `airsNumRetries` `0`, `mgmtClientId` `client-100`, `mgmtClientSecret` `[REDACTED]`, `mgmtTsgId` `100`, `mgmtEndpoint` `""`, `scanConcurrency` `7`, `defaultOutput` `yaml`, `dataDir` `~/.prisma-airs/runs`. stderr: `  Tenant dev (TSG 100): <configPath>`.
  - `airsNumRetries` is shown as 0, but the stored `''` set earlier was coerced to 0 at write time. So `set airsNumRetries ''` silently becomes "0 retries".
- `tenant get dev scanConcurrency` prints `7`. `get dev airsApiKey` prints `[REDACTED]`. `get dev mgmtEndpoint` prints an empty line.
- `tenant path dev` prints the realpath of the managed config.
- After `delete dev --force` (selected):
  - `tenant list` gives stdout `  No tenants found` and stderr `  Run 'airs-cli tenant create <name>' to register one.`, exit 0.
  - `tenant read` and `tenant path` give `No tenant selected; run 'airs-cli tenant create <name>' first`, exit 1.
  - `runtime profiles list --output json` gives `No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'`, exit 1.

---

## 14. Rust M4t mapping notes

- M4t replaces the storage (MILESTONES "Tenants and state"):
  - TOML at `~/.config/airs-cli/config.toml` (active tenant) plus `tenants/<name>.toml`, or under `AIRS_CLI_CONFIG_DIR`;
  - `flock` with pid and host;
  - atomic rename at 0600/0700.
  - The TS registry is read only by `tenant import`.
- Sections 4.1–4.4 are therefore the **import-side** contract: what `import` must locate and read without modifying.
- Sections 2, 3, 5–10 and 13 are the **UX** contract: messages, ordering, streams, exit codes and the pin.
- TS layout facts that `import` must handle:
  - a registry entry may point at any absolute path, including a symlinked or shared file;
  - several names may share one file;
  - managed files are named `<name>-<uuid>.json`;
  - orphaned managed files exist and are not referenced;
  - files may carry retired, unknown, string-typed numeric or high-precision numeric values.

---

## Acceptance criteria

Each item states the TS behaviour to pin. "§12 candidate" items should be pinned as a `dNN_` divergence instead, if the Rust port decides to differ.

1. `tenant create dev --tsg-id 100 --client-id client-100 --client-secret-stdin` with stdin `FAKE-SECRET\n` exits 0. stdout is exactly `  ✓ Registered dev (TSG 100); private config created. Use airs-cli tenant switch dev.\n`, stderr is empty, nothing is selected, and the stored secret is `FAKE-SECRET` (one LF stripped). The secret appears in no output and not in the registry or index file.
2. Stdin `FAKE-SECRET\r\n` stores `FAKE-SECRET`. Stdin `  FAKE SECRET  \n` stores `  FAKE SECRET  ` (untrimmed).
3. Each of these stdin inputs exits 1 with `Provide one nonempty configuration value on stdin` and creates no file or directory: empty, `   \n`, `FAKE\nsecond`, `FAKE\n\n`, `FAKE\0SECRET`, `FAKE\r`.
4. Stdin of exactly 65,536 bytes is accepted. 65,537 bytes, including 65,536 bytes plus `\n`, exits 1 with `Configuration input exceeds 64 KiB`.
5. `--client-secret-stdin` (create) or `--stdin` (set) with a TTY on stdin exits 1 with `--stdin requires piped input`.
6. `tenant create dev` with no TTY, or `create dev --tsg-id 100` with no TTY, exits 1 with the exact `Interactive setup requires a terminal. …` message and creates no file or directory. The prompt gate needs both stdin and stderr to be TTYs.
7. The guided create prompts, in order on stderr, `Tenant service group ID (mgmtTsgId):`, `OAuth client ID (mgmtClientId):` and the hidden `OAuth client secret (mgmtClientSecret):`. A blank or whitespace answer re-prompts with `A nonempty value is required`. Answers are stored untrimmed. Ctrl-C at any prompt exits 130 with stderr `  Cancelled; no configuration saved.` (suppressed by `--quiet`) and leaves nothing on disk.
8. Name validation runs first. `create 'a/b'`, `create ''`, `create _x`, `create é` and a 65-character name each exit 1 with `Tenant name must be 1–64 letters, digits, hyphens or underscores and start with a letter/digit` (U+2013), before any prompt, stdin read or file access.
9. `create dev --config X` combined with `--tsg-id`, `--client-id` (even `''`) or `--client-secret-stdin` exits 1 with `--config cannot be combined with new-config options`, after name validation and before any registry access. `--config ''` behaves as if `--config` were absent.
10. Guided `create` of an existing name exits 1 with `Tenant name already exists` before prompting. `--config` with an existing name and a valid file gives the same message. With an invalid file, the file error wins.
11. `create prod --config <symlink>` stores the realpath of the target, prints `  ✓ Registered prod (TSG 200); config file unchanged. Use airs-cli tenant switch prod.`, and leaves the source bytes, mode (0400 is fine) and mtime unchanged. Relative paths resolve against the cwd, and `~/x` against `$HOME`.
12. `create --config` of a missing path exits 1 with `Tenant config file does not exist or cannot be resolved`. Invalid JSON, a directory or `scanConcurrency: 99` gives `Cannot read a valid tenant config at <realpath>`. A file lacking any of the three credentials, or with a whitespace one, gives `Tenant config requires mgmtTsgId, mgmtClientId and mgmtClientSecret`.
13. A new registry is written as `{"version":1,"active":null,"tenants":[{name,configPath,tsgId}]}` with 2-space indentation and a trailing LF, mode 0600. Every directory created on the way is 0700. A pre-existing directory keeps its mode.
14. Managed configs live at `dirname(registry)/configs/<name>-<uuid>.json` (0600, directory 0700). The registry records the realpath.
15. With `<registry>.lock` present, guided create exits 1 with `Could not create tenant configuration; registration was not completed`, leaves no config file and leaves the lock's content unchanged. `create --config`, `switch` and `delete --force` exit 1 with `Cannot lock tenant registry at <registry>.lock; another change may be in progress`.
16. `set dev notAKey v` exits 1 with the full 31-key `Unknown configuration key. Supported keys: …` message, even when the registry is corrupt. `__proto__` and `constructor` are rejected too.
17. `set nope defaultOutput json` exits 1 with `Tenant not found; register a named tenant first`.
18. `set dev defaultOutput json --stdin` exits 1 with `Use a value or --stdin, not both`. So does `set dev airsApiKey X --stdin`.
19. `set dev <secret> <value>` exits 1 with `Do not pass credentials as arguments. Omit the value for a hidden prompt, or use --stdin.` for each of `airsApiKey`, `airsApiToken`, `mgmtClientSecret`, `aiGwInferenceApiKey` and `typesafeApiKey`, including an empty value. The file is unchanged.
20. `set dev mgmtTsgId 200` (pin 100) and `set dev mgmtTsgId ' 100'` exit 1 with `TSG identity is pinned; create another tenant instead of changing mgmtTsgId`. `set dev mgmtTsgId 100` succeeds.
21. `set dev mgmtClientId ''` or `'  '` exits 1 with `Tenant config requires nonempty mgmtTsgId, mgmtClientId and mgmtClientSecret`, and the file is unchanged.
22. Value table (section 2.4). `scanConcurrency` `0x5`, `' 7 '` and `1e1` store the numbers 5, 7 and 10. `0`, `21`, `''`, `5.5` and `abc` exit 1 with `Invalid value for configuration setting`. `airsNumRetries ''` stores 0. `defaultOutput JSON` is rejected. `typesafeBaseUrl localhost:8080` is accepted and `not a url` is rejected. `mgmtEndpoint 'not a url'` and `''` are accepted.
23. A successful `set` prints `  ✓ Updated <key> for tenant <name>; selection unchanged.` on stdout, even under `--quiet`. It rewrites the file at 0600, even when the file was 0644. It keeps unknown keys and the existing key order, appends new keys, and leaves `active` unchanged.
24. `set` or `unset` on a 0400 config or a symlinked config exits 1 with `Tenant config is not a writable regular file`, leaving bytes and mode unchanged. With `<config>.lock` present it exits 1 with `Cannot lock tenant config; it may be read-only or another edit is in progress`, and the lock's content is unchanged.
25. `unset dev mgmtTsgId|mgmtClientId|mgmtClientSecret` exits 1 with `<key> is a credential and cannot be cleared; set a new value instead`, even for an unknown tenant name. `unset dev redTeamTokenEndpoint` and `unset dev custom` exit 1 with the unknown-key message.
26. `unset dev defaultOutput` prints `  ✓ Removed defaultOutput from tenant dev; selection unchanged.` when the key is present. When it is absent it prints `  ℹ defaultOutput is not set for tenant dev — nothing to do` (U+2014), and with `--quiet` it prints nothing. Both exit 0. The absent case does not rewrite the file but still requires it to be writable.
27. `switch dev` prints `  ✓ Selected dev (TSG 100)` and sets `active`. A missing or invalid config gives `Cannot read a valid tenant config at <path>`. A pin mismatch gives `Tenant config TSG differs from its registered identity; register it under a new name`. An unknown name gives `Tenant not found`. Every failure leaves `active` unchanged. A config with only `mgmtTsgId` can be selected.
28. `delete prod` with stdout not a TTY exits 2 with stderr `\n  ✗ refusing to unregister tenant prod without --force in non-interactive mode\n\n`. `delete nope` (with or without `--force`) exits 1 with `Tenant not found`.
29. `delete dev --force` on the selected tenant prints `  ✓ Unregistered dev; source config file retained; no tenant is selected` and sets `active: null`. On a tenant that is not selected it prints `  ✓ Unregistered prod; source config file retained`. The config file, managed ones included, remains on disk unchanged.
30. Interactive delete: Enter or `n` gives `  ℹ Aborted` on stdout, exit 0, registry unchanged. `y` or `yes` deletes. The prompt reads `Unregister tenant dev? It is the selected tenant; no tenant will be selected afterwards. Its config file will be retained. (y/N)`.
31. `tenant rm` is an alias of `delete`. Commander parse errors on write commands exit 1 in TS (D1: Rust exits 2).
32. A successful create re-sorts the registry entries by name, `localeCompare` under `en-US`: `10 9 a a_b a-b a1 A1 ab aB b B Z`. `switch` and `delete` keep the order.
33. Registry writes rewrite a hand-edited registry canonically: key order `version, active, tenants` and `name, configPath, tsgId`, 2-space indentation, `1.0` written as `1`.

---

## Open questions / likely §12 divergences

Safety items come first. "Recommend" is the suggested Rust behaviour; each needs a §12 row and a `dNN_` test if adopted.

1. **Secrets on argv are refused, but only after the fact.** `set dev airsApiKey <secret>` already exposed the secret to shell history and `ps` before the refusal, and `--tsg-id`/`--client-id` are always argv. Rust (clap) can do no better for a value already typed. Recommend keeping the refusal with the same text, printed before any file access as TS does (the key check comes first). Consider making it a usage error (exit 2) under D1/D34 logic, because it is input validation.
2. **Registry read-only bypass (safety).** TS silently replaces a 0444 registry with a 0600 file (section 4.2) but refuses read-only configs. Recommend applying the config rule (`not a writable regular file`) to Rust's `config.toml` and tenant files consistently.
3. **Rewrites change user-owned `--config` files.** `set` and `unset` reset the mode to 0600, change the owner, break hard links, reformat, and lose numeric precision (`12345678901234567890` becomes `12345678901234567000`). In M4t the files are Rust-owned TOML and `import` never writes TS files, so this mostly disappears. Recommend recording that Rust never rewrites a file it did not create.
4. **Non-atomic managed create.** The secret file is written in place, not via temp and rename. A crash leaves a partial or unregistered secret file. Recommend writing to a temp file, fsyncing, renaming, and fsyncing the directory.
5. **No directory fsync** on any rename (registry or config). Recommend fsyncing the parent directory after the rename.
6. **Stale locks are permanent.** The lock is an empty `O_EXCL` file with no pid or host. A killed writer blocks all writes until manual removal, and any `open` failure (EACCES included) is reported as "another change may be in progress". M4t specifies `flock` with pid and host. Recommend wording that names the holder when it is known, and a distinct message for permission errors.
7. **Fail-fast locking.** Concurrent writers fail immediately (5 of 6 parallel creates). Recommend a short bounded wait on `flock` or keeping fail-fast; either way, a §12 row is needed if the behaviour differs.
8. **Registry and config are not locked together.** `set`/`unset` run without the registry lock, and `delete`'s prompt text comes from an unlocked read. Recommend one lock (the `config.toml` flock) covering both the index and the tenant file for every write.
9. **Orphaned plaintext secrets.** `delete` retains CLI-created `configs/<name>-<uuid>.json`, and re-creating the name adds another file. Recommend that Rust `delete` remove the Rust-owned `tenants/<name>.toml` (a deliberate §12 row) or at least name the retained file. `import` must ignore unreferenced TS files.
10. **Raw internal errors reach users.** These include `ENOENT: … lstat '<path>'`, `EACCES: … mkdir|open '<path>'` and a raw ZodError JSON dump for the 1001st tenant. No secret leaks this way, but the text is not contractual. Recommend mapping them to fixed messages.
11. **Writes can brick the registry.** A create that pushes the registry past 1 MiB succeeds, and every later read fails. Recommend checking the size and entry limits before the rename.
12. **Control characters in IDs.** `--tsg-id`/`--client-id` accept ESC and LF, which are stored and echoed raw in success lines (terminal injection). Recommend applying D52 (`terminal_safe`) to the echoes, and considering rejecting non-digit TSGs at create, since D28 already makes them a local error later.
13. **Untrimmed credentials.** Prompt and stdin values are stored untrimmed (` 100 ` as TSG, a secret with surrounding spaces). Presence checks trim, but values are sent raw. Recommend keeping parity, or trimming TSG and client ID only, with a §12 row.
14. **Empty-string coercions.** `set airsNumRetries ''` stores 0, and `set mgmtEndpoint ''` stores `""` (later stripped to the default). Recommend rejecting empty values for numeric keys (strict parsing, consistent with D17) and treating `''` for string keys as an error, pointing users to `unset`.
15. **JS `Number()` coercion on write** (`0x5`, `0b11`, `+3`, `1e1`, `5.0`, `' 7 '`). Recommend decimal integers only (D17 precedent).
16. **URL validation is weak and inconsistent.** Only four keys are `.url()`-checked, `localhost:8080` and `mailto:x` pass, and the other endpoints accept anything. Rust already has D48 endpoint admission. Recommend validating every endpoint key at `set` time with the D48 rules, with a §12 row.
17. **`defaultOutput` markdown, csv and yaml** are accepted by TS `set`. Under D51 Rust must reject them at `set` time with `Invalid value for configuration setting` (or a more specific message).
18. **Retired and unknown keys cannot be unset**, yet doctor's hint says to use `tenant unset`. For M4t, `import` reports and drops them, so Rust files never carry them. Recommend changing the hint (doctor D-row) rather than the command.
19. **A credential-less but pinned file can be switched to but not repaired** (`set` demands all three credentials on every rewrite). Recommend allowing `set` of a credential key when the result has more credentials than before, or documenting it. Under M4t, Rust-created tenants always have all three.
20. **Exit codes.**
    - Ctrl-C at the `delete` prompt exits 1 with `User force closed the prompt with SIGINT`, while create and set exit 130. Recommend 130 everywhere (D32 family).
    - Stdin EOF at the confirm prompt prints Node's unsettled-top-level-await warning and exits 1. Recommend treating EOF as decline or as a usage error.
    - The non-interactive refusal checks only stdout. With stdout piped and stdin a TTY, the prompt is refused even though a user is present. Recommend checking stdin and stderr, with the prompt on stderr, so `tenant delete x | cat` still asks.
21. **Streams.** Success and info lines go to stdout, and success ignores `--quiet`, which conflicts with the "stdout carries data only" invariant in AGENTS.md. Recommend a §12 row: Rust writes write-command outcomes to stderr (status), or keeps them on stdout. This needs a decision, because scripts may parse them.
22. **Colour.** chalk ignores `NO_COLOR` and decides once from stdout (D58 already covers this). Prompt styling follows stdout, not the prompt stream.
23. **Locale-dependent registry order.** `localeCompare` sorting depends on `LANG` (`da_DK` sorts `aa` after `z`). Recommend sorting by byte order in Rust's index (§12 row; affects `tenant list` order only).
24. **Registry directory created on failure.** `tenant switch <unknown>` creates the registry directory. Recommend not creating directories until a write is certain.
25. **Hidden-prompt rendering.** TS shows `[input is masked]` and no mask characters, and the done line omits the value. Exact prompt bytes (cursor codes) are inquirer-specific. Recommend matching the visible text (`? <message>`, `[input is masked]`, `✔ <message>`) and not the escape sequences, with a §12 note that prompt escape sequences are not a parity surface.
26. **`--tenant` (D33) on write commands.** TS has none. Recommend clarifying whether `--tenant` is rejected on `tenant` subcommands, since they take a positional name.
