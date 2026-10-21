# Spec: TS `airs-cli` `model-security pypi-auth` and `model-security install` (M6c), and the uv facts for the Rust port

Commands covered: `model-security pypi-auth` and `model-security install` (every option), the PyPI auth request, the install step sequence, the dry-run output, messages, exit codes, interruption and every place the TS CLI exposes the PyPI credential. Then the uv research for the Rust port: the pinned release with its archive SHA-256 values, how a credential-bearing index reaches `uv add` without appearing in argv, and what uv writes to `pyproject.toml`, `uv.lock`, the cache and the venv. It ends with the proposed Rust design for both commands (uv only, `--fetch-uv`, credential never printed). The other `model-security` commands (groups, rules, rule-instances, scans, models, labels) need their own spec.

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0, SDK `@cdot65/prisma-airs-sdk` 0.34.0, commander 14). Citations:
  - `ms.ts` is `src/cli/commands/modelsecurity.ts`; `svc.ts` is `src/airs/modelsecurity.ts`; `types.ts` is `src/airs/types.ts`.
  - `ui.ts`, `common.ts`, `rms.ts` are `src/cli/renderer/{ui,common,modelsecurity}.ts`; `program.ts`, `dbg.ts`, `guards.ts` are `src/cli/{program,debug-logger,process-guards}.ts`; `co.ts` is `src/config/client-options.ts`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js` of the reference build.
  - `rs:<file>:<line>` is `~/.cargo/registry/src/*/scm-sdk-0.1.1/src/<file>` (the Rust SDK in use).
  - Docs: `docs-site/docs/cli/model-security/{install,pypi-auth}.md`.
- Shared shell behaviour (commander parse errors exit 1, the root `--output` consumer, `resolveOutput`, quiet, colour, EPIPE) is in `ts-cli-shell.md` and `ts-renderer.md`, the debug log in `ts-debug-log.md`. It is restated only where these commands depend on it.
- How behaviour was captured: the reference build (`dist/cli/index.js`, node v24.21.0) ran against a loopback stub (`node:http` on `127.0.0.1`, random port) implementing `POST /oauth/token` and `GET <mgmt>/v1/pypi/authenticate`. The stub logged every request (method, path, the first 7 characters of `Authorization`, user agent) and took a fault plan (status, raw body, headers such as `retry-after: 0`, or a hang).
  - Sandbox: `env -i` with `PATH`, `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` and `TMPDIR` inside the sandbox, a TS registry selected through `PRISMA_AIRS_TENANTS_PATH`, and one tenant `test` with fake credentials (`fake-client`/`FAKE-SECRET`, TSG `100`). Its `mgmtTokenEndpoint` was `<base>/oauth/token`, `modelSecMgmtEndpoint` `<base>/ms/mgmt` and `modelSecDataEndpoint` `<base>/ms/data`. The stub's PyPI answer was `{"url":"https://oauth2accesstoken:FAKE-PYPI-CRED-123@us-west1-python.pkg.dev/fake-proj/fake-repo/simple/","expires_at":"2026-10-18T15:06:25"}`. That host was never contacted, because `uv` was a fake.
  - **Model-security endpoint fallbacks.** The CLI passes `dataEndpoint: config.modelSecDataEndpoint ?? DEFAULT_MODEL_SEC_DATA_ENDPOINT` and `mgmtEndpoint: config.modelSecMgmtEndpoint ?? DEFAULT_MODEL_SEC_MGMT_ENDPOINT` (`co.ts:71-77`), and passes the credentials and token endpoint explicitly (`co.ts:34-42`). The SDK's environment fallbacks therefore never apply: `opts.mgmtEndpoint ?? process.env.PANW_MODEL_SEC_MGMT_ENDPOINT ?? DEFAULT` (`SDK:14603-14604`), the `PANW_MODEL_SEC_*`/`PANW_MGMT_*` credential fallbacks (`SDK:14605-14614`) and `PANW_MODEL_SEC_TOKEN_ENDPOINT` (`SDK:82`). This was captured: with `modelSecMgmtEndpoint` removed from the tenant and `PANW_MODEL_SEC_MGMT_ENDPOINT=http://127.0.0.1:<port>/envms` set, the CLI went to the default `https://api.apps.paloaltonetworks.com/aims/mgmt` (`SDK:76`), which the guard refused. The defaults are `https://api.apps.paloaltonetworks.com/aims/{data,mgmt}` (`SDK:75-76`; `rs:constants.rs:630-631` match). The other environment variables read are `PANW_AI_SEC_TIMEOUT_MS` (per-attempt timeout, default 60000, `SDK:10095`), `PANW_AI_SEC_DEBUG`, and `FORCE_COLOR`/TTY for chalk.
  - Every node run preloaded a guard (`--import`) that replaces `globalThis.fetch` and `dns.lookup` and refuses any host other than `127.0.0.1`. For one `--debug` capture (§2.6) the guard also rewrote `https://api.apps.paloaltonetworks.com/...` to the loopback stub before any connection, so the debug logger (which logs AIRS hosts only) saw the real host name. Nothing was ever sent to that host.
  - Fake tools: `uv`, `python3` and `pip` were shell scripts on the sandbox `PATH`. They recorded every argv element (bracketed, one invocation per line), answered `--version` with exit 0, printed one stdout and one stderr line, and could sleep or exit with a chosen code.
  - Signals were sent with `kill -INT|-TERM` to the node process during a hung request or a sleeping fake `uv`.
- uv research (§7): the real local uv (`/opt/homebrew/bin/uv`, `uv 0.12.17 (Homebrew 2026-09-18 aarch64-apple-darwin)`) ran only against loopback PEP 503 indexes (§7.3). The only non-loopback requests in this research were the official checksum files of the pinned uv release (§7.1).
- No real tenant or credential file was read. No host other than loopback was contacted, apart from the §7.1 checksum files on `github.com`.
- Captures are shown as JSON strings (`"\n  ..."`) and are uncoloured (stdout a pipe) unless stated. §2.3 lists the ANSI codes captured with `FORCE_COLOR=1`.

## 1. Command surface (help verified)

Registration: `ms.ts:216-293` (`install`) and `ms.ts:385-400` (`pypi-auth`), under `model-security` (`ms.ts:88-90`). Neither command declares `--output`. `applyReadContractFlags` adds `--output` only to commands named `list` or `get` (`program.ts:54-59`), so neither command gets one. `pypi-auth` is in `READ_COMMAND_NAMES` (`program.ts:27`), but the preAction output resolution runs only for a command that has an `--output` option (`program.ts:162-175`). Help sorts options and subcommands (`program.ts:73-76`).

| Command | Arguments and options (help text; defaults) |
|---|---|
| `model-security pypi-auth` | none. Description `Get PyPI authentication URL for Google Artifact Registry` |
| `model-security install` | `--extras <type>` (`Source type extras to install (all, aws, gcp, azure, artifactory, gitlab)`, default `"all"`), `--dir <path>` (`Directory to create the project in`, default `"model-security"`), `--dry-run` (`Print the commands without executing`). Description `Install the model-security-client Python package from AIRS PyPI` |

Captured help (stdout, exit 0):

```
Usage: airs-cli model-security pypi-auth [options]

Get PyPI authentication URL for Google Artifact Registry

Options:
  -h, --help  display help for command
```

```
Usage: airs-cli model-security install [options]

Install the model-security-client Python package from AIRS PyPI

Options:
  --dir <path>     Directory to create the project in (default:
                   "model-security")
  --dry-run        Print the commands without executing
  --extras <type>  Source type extras to install (all, aws, gcp, azure,
                   artifactory, gitlab) (default: "all")
  -h, --help       display help for command
```

In `model-security --help` the two rows are `install [options]  Install the model-security-client Python package from AIRS` / `PyPI` (wrapped) and `pypi-auth          Get PyPI authentication URL for Google Artifact Registry`.

Parsing quirks (captured):

- An extra positional fails: `error: too many arguments for 'pypi-auth'. Expected 0 arguments but got 1.` (and the same for `'install'`), on stderr with exit 1. An unknown option fails with `error: unknown option '--foo'`, exit 1. A missing value fails with `error: option '--extras <type>' argument missing`, exit 1. No request is sent in any of these cases.
- The last occurrence wins (`--extras foo --extras aws` installs `aws`). `--extras=gcp` works. `--dry-run --dry-run` is accepted.
- A value that starts with a dash is taken as the value: `--dir --x` gives `uv init --x` (an option to uv, see §4.7). An empty value is kept: `--dir ""` gives `uv init ` with an empty argv element.
- `--extras` must match exactly and is case-sensitive: `ALL` is refused (§4.2).
- `--output` (root or local, any value, even `bogus`) is consumed by the root parser and ignored. Both commands always print the pretty layout, exit 0.
- `--quiet` is the root flag (`program.ts:109,113`).

## 2. Shared behaviour

### 2.1 Client, endpoints and credentials

`createService()` (`ms.ts:81-84`) calls `loadConfig()` and builds `SdkModelSecurityService(modelSecurityClientOptions(config))`. `oauth(config)` first calls `assertManagementCredentials` (`co.ts:34-42`). A missing secret prints (captured, stderr, exit 1):

```
"\n  ✗ Error: Management credentials are not configured (missing mgmtClientSecret). Run 'airs-cli tenant set test <key>' for mgmtClientSecret (secrets prompt hidden, or use --stdin)\n\n"
```

The client is `ModelSecurityClient` (`SDK:14588-14636`). Its OAuth client is shared by the data and management planes. `getPyPIAuth` is on the root client (`SDK:14650-14659`), not on a sub-client.

### 2.2 The request (captured)

1. `POST <mgmtTokenEndpoint>`: client-credentials token with `Authorization: Basic …` (see `ts-cli-shell.md` for the body).
2. `GET <modelSecMgmtEndpoint>/v1/pypi/authenticate` (`SDK:90`, `SDK:14650-14659`). No query and no body. Headers are `Authorization: Bearer <token>`, `User-Agent: PAN-AIRS/0.34.0-typescript-sdk` and `service-name: api` (from the debug capture, §2.6).

The response schema is `PyPIAuthResponseSchema = z.object({url: z.string(), expires_at: z.string()}).passthrough()` (`SDK:3329-3332`). `svc.ts:562-569` keeps `{url: raw.url, expiresAt: raw.expires_at}` (`types.ts:911-914`) and drops every other field. Neither field is checked further: any string is accepted, an empty string and control characters included.

`install --dry-run` sends the same two requests (captured), so a dry run mints a credential too.

### 2.3 Streams, quiet and colour

`ui.header` (`ui.ts:56-61`), `ui.section` (`ui.ts:64-67`) and `ui.dim` (`ui.ts:124-128`) write to **stdout** and are suppressed by `--quiet`. `ui.keyValue` (`ui.ts:70-75`) and `ui.success` (`ui.ts:90-93`) write to stdout and are never suppressed. `ui.status` (`ui.ts:131-135`) writes to stderr and is suppressed by quiet. `usageError` and `fail` (`common.ts:12-30`) write to stderr.

Colours captured with `FORCE_COLOR=1`:

- The header title is `\e[1m…\e[22m` and the subtitle `\e[2m…\e[22m`.
- The section label is `\e[1m…\e[22m`.
- A keyValue key is dim and padded inside the escape: `\e[2mURL    \e[22m  <value>`. The value is uncoloured.
- A dim line is `\e[2m…\e[22m`, which covers the dry-run commands and `Activate:`.
- A status line is `\e[2m→ uv init\e[22m`.
- The success line is `\e[32m✓ …\e[39m`.
- `fail` wraps each line in `chalk.red`, and the `Re-run with --debug …` line in `chalk.dim`.

### 2.4 Errors and exit codes

`usageError(msg)` prints `"\n  ✗ <msg>\n\n"` and exits 2. `fail(err)` prints `"\n  ✗ Error: <message>\n"`. When the error carries `status`, `fail` adds `"    HTTP <status>\n    Re-run with --debug to capture redacted API diagnostics.\n"`, then `"\n"`, and exits 1. Commander parse errors exit 1. Signals end the process with 130 or 143 (§2.7).

Captured `pypi-auth` failures. In every case stdout already holds the header (`"\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n"`) and the exit code is 1.

| Stub answer | stderr | `pypi/authenticate` requests |
|---|---|---|
| 400, 404 with `{"error":{"message":"FAKE-SERVER-MSG https://oauth2accesstoken:FAKE-ECHO@x/"}}` | `✗ Error: AISEC_CLIENT_SIDE_ERROR:FAKE-SERVER-MSG https://oauth2accesstoken:FAKE-ECHO@x/` + `HTTP <s>` + `Re-run …` | 1 |
| 401 (same body) | same, `HTTP 401` | 2 (refresh and replay) |
| 403 (same body) | same, `HTTP 403` | 2 |
| 429 (`retry-after: 0`) | same, `HTTP 429` | 1 |
| 500, 503 (`retry-after: 0`) | `AISEC_SERVER_SIDE_ERROR:FAKE-SERVER-MSG …` + `HTTP <s>` | 6 (one plus 5 retries) |
| 401 with `{}` | `✗ Error: AISEC_CLIENT_SIDE_ERROR:API error 401` + `HTTP 401` | 2 |
| hang, `PANW_AI_SEC_TIMEOUT_MS=300` | `✗ Error: AISEC_CLIENT_SIDE_ERROR:Request timed out` (no HTTP line) | 6 |
| 200 `{"expires_at":"x"}` or `{"url":123,…}` | `✗ Error: AISEC_RESPONSE_VALIDATION:Response did not match schema: url: invalid_type` | 1 |
| 200 `not json` | `✗ Error: AISEC_RESPONSE_VALIDATION:Response body is not valid JSON` | 1 |

**Server text is printed raw.** A server message, including a URL with userinfo in it, appears verbatim in the error line.

### 2.5 Retries

These are the SDK defaults for a GET: up to 5 retries on 5xx and timeouts, and one replay after a 401 or a 403 with a fresh token. Each attempt may mint a new PyPI token on the server. The request is a read, so no replay duplicates a resource.

### 2.6 `--debug` (captured with the AIRS host name)

The debug logger records only URLs whose host is an AIRS domain (`dbg.ts:11-27`; `api.apps.paloaltonetworks.com` is one of them), so a loopback endpoint writes an empty log. With the host rewritten by the guard, `--debug model-security pypi-auth` printed `  Debug: API log → <cwd>/debug-api-<ms>-<8 hex>.jsonl` on stderr and wrote one 0600 record. In that record `Authorization` is `***`, and **the response body holds the credential in clear**:

```
"response":{"status":200,…,"body":{"url":"https://oauth2accesstoken:FAKE-PYPI-CRED-123@us-west1-python.pkg.dev/fake-proj/fake-repo/simple/","expires_at":"2026-10-18T15:06:25"}}
```

`redactDeep` masks values only by key name (`dbg.ts:32-61`). The key `url` does not match `SENSITIVE_KEY_PATTERN`, and `redactUrl` masks only query parameters (`dbg.ts:65-78`), never userinfo. `install --debug --dry-run` writes the same record (one credential occurrence in the log). The file lands in the current directory and is never pruned (`dbg.ts:140-142`).

### 2.7 Interruption

There are no signal handlers (`guards.ts` registers only `unhandledRejection`), so node's defaults apply.

- SIGINT during a hung `pypi-auth` exits 130 and SIGTERM exits 143. Nothing is printed beyond the header already on stdout.
- During an install step (captured with a fake `uv` that sleeps 4 s and traps signals), a signal sent to the CLI process alone ends the CLI at once (130 or 143). The child is **not signalled and keeps running to completion** (the fake recorded `uv finished init` after the CLI had exited, and no `uv got INT`). From a terminal, Ctrl-C reaches the whole foreground process group, so uv gets its own SIGINT.
- A child killed by a signal (SIGKILL to the fake `uv`) is reported as `✗ Error: uv init failed with exit code null`, exit 1 (`ms.ts:73-75`; `code` is `null`).

## 3. `model-security pypi-auth` (`ms.ts:385-400`)

Steps:

1. `renderModelSecurityHeader()` (`rms.ts:45-47`, stdout, quiet-suppressed).
2. `createService()` reads the tenant and asserts the management credentials (§2.1).
3. `getPyPIAuth()` sends the request (§2.2).
4. `ui.section('PyPI Authentication')`.
5. `ui.keyValue([['URL', auth.url], ['Expires', auth.expiresAt]])`.

The keys are padded to 7 (`Expires`) and followed by two spaces. Values go through `String(v ?? '')`.

Captured stdout, exit 0, stderr empty:

```
"\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n\n  PyPI Authentication\n\n  URL      https://oauth2accesstoken:FAKE-PYPI-CRED-123@us-west1-python.pkg.dev/fake-proj/fake-repo/simple/\n  Expires  2026-10-18T15:06:25\n"
```

- `--quiet` gives `"  URL      https://oauth2accesstoken:FAKE-PYPI-CRED-123@…/simple/\n  Expires  2026-10-18T15:06:25\n"`. The credential still prints.
- An empty `expires_at` prints `  Expires  ` (the value is empty and no trailing space is added beyond the padding).
- Control characters are printed raw. `url: "https://u:FAKE-C@h/s/\e[31mRED\a"` and `expires_at: "2026\r\nX"` reached the terminal unmodified.
- The docs page (`docs-site/.../pypi-auth.md`) shows `URL:` and `Expires:` with colons, a username `oauth2accesstoken`, a `ya29.` OAuth access token and `Expires: 2026-05-25T15:06:25` (no zone). The real output has no colons. The SDK's example uses the username `_token` (`SDK:14645-14648`).
- There is no json, table or file output. `--output` is ignored (§1).

## 4. `model-security install` (`ms.ts:216-293`)

### 4.1 Validation order

1. Commander parse (§1): exit 1.
2. `renderModelSecurityHeader()` (stdout). It is printed **before** any validation, so a usage error still leaves the header on stdout.
3. `--extras` must be in `VALID_EXTRAS = ['all','aws','gcp','azure','artifactory','gitlab']` (`ms.ts:56,230-233`), else a usage error, exit 2 (§4.2). This runs before the tool check and the tenant.
4. Tool detection (`ms.ts:236-240`): `hasBin('uv')` runs `uv --version` with ignored stdio (`ms.ts:59-66`). It is true when the spawn succeeds and exits 0. If that fails, `hasBin('python3')` is tried. If both fail: `✗ Error: Neither uv nor python3 found on PATH. Install one first.`, exit 1, before the tenant is read (captured: no request).
5. `createService()` and `getPyPIAuth()` (§2.1, §2.2), also for `--dry-run`.
6. The steps are built (§4.3). With `--dry-run` they are printed and the command returns (§4.4). Otherwise they run in order (§4.5).

`--dir` is not checked at all: it is not tested for existence or an existing project, not resolved, and not checked for a leading dash.

### 4.2 Messages

| When | Stream | Text | Exit |
|---|---|---|---|
| bad `--extras` | stderr | `"\n  ✗ Invalid extras \"foo\". Valid: all, aws, gcp, azure, artifactory, gitlab\n\n"` (the value raw) | 2 |
| no uv, no python3 | stderr | `"\n  ✗ Error: Neither uv nor python3 found on PATH. Install one first.\n\n"` | 1 |
| step start | stderr (status) | `"  → uv init\n"`, `"  → uv add\n"` (pip path: `→ create venv`, `→ pip install`) | |
| step failed | stderr | `"\n  ✗ Error: uv init failed with exit code 3\n\n"` (`<label> failed with exit code <code\|null>`) | 1 |
| spawn failed | stderr | `"\n  ✗ Error: Failed to start model-security/.venv/bin/pip: spawn model-security/.venv/bin/pip ENOENT\n\n"` | 1 |
| success | stdout | `"  ✓ model-security-client installed successfully.\n"` (kept under `--quiet`) | 0 |
| hint | stdout (dim, quiet-suppressed) | uv: `"  Activate:  cd model-security\n"`; pip: `"  Activate:  source model-security/.venv/bin/activate\n"` (two spaces after the colon) | |

### 4.3 Steps (`ms.ts:245-265`)

`pkg = "model-security-client[<extras>]"`.

| Tool | Step label | argv |
|---|---|---|
| uv | `uv init` | `uv`, `init`, `<dir>` |
| uv | `uv add` | `uv`, `add`, `--project`, `<dir>`, `model-security-client[<extras>]`, `--index`, `<auth.url>` |
| pip | `create venv` | `python3`, `-m`, `venv`, `<dir>/.venv` |
| pip | `pip install` | `<dir>/.venv/bin/pip`, `install`, `model-security-client[<extras>]`, `--extra-index-url`, `<auth.url>` |

Captured argv of the fake uv (each element bracketed):

```
uv [--version]
uv [init] [model-security]
uv [add] [--project] [model-security] [model-security-client[all]] [--index] [https://oauth2accesstoken:FAKE-PYPI-CRED-123@us-west1-python.pkg.dev/fake-proj/fake-repo/simple/]
```

**The credential-bearing URL is an argv element of the `uv add` process.** Any local user can read it with `ps` for as long as uv resolves and installs. The children inherit the CLI's whole environment, stdin, stdout and stderr (`spawn(bin, args, {stdio:'inherit'})`, `ms.ts:69-78`), and the CLI waits for `close`.

### 4.4 `--dry-run` output (`ms.ts:267-276`, captured)

`ui.section('Commands that would be executed')`, then one `ui.dim("$ <cmd>")` per step. An argument is wrapped in double quotes only when it contains `[` or a space. Nothing else is quoted or escaped.

```
"\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n\n  Commands that would be executed\n\n  $ uv init model-security\n  $ uv add --project model-security \"model-security-client[all]\" --index https://oauth2accesstoken:FAKE-PYPI-CRED-123@us-west1-python.pkg.dev/fake-proj/fake-repo/simple/\n"
```

- `--extras aws --dir "my dir"` gives `$ uv init "my dir"` and `$ uv add --project "my dir" "model-security-client[aws]" --index https://…`.
- `--dir '/abs/$(id)'` gives `$ uv init /abs/$(id)` unquoted, so pasting the line into a shell runs `id`.
- pip fallback: `$ python3 -m venv model-security/.venv` and `$ model-security/.venv/bin/pip install "model-security-client[all]" --extra-index-url https://…`.
- **`--quiet --dry-run` prints nothing at all** (stdout and stderr empty, exit 0). Every dry-run line is `ui.dim`, and the section is quiet-suppressed.
- The dry run is on stdout, carries the credential, and still mints it (§2.2). `| head -1` exits 0 (EPIPE handled as in `ts-renderer.md`).

### 4.5 Run (captured with the fake uv)

stdout: `"\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\nfake uv stdout line\nfake uv stdout line\n  ✓ model-security-client installed successfully.\n  Activate:  cd model-security\n"`.
stderr: `"  → uv init\nfake uv stderr line\n  → uv add\nfake uv stderr line\n"`. Exit 0.

**The children's stdout is mixed into the CLI's stdout.** Under `--quiet` the output is stdout `"  ✓ model-security-client installed successfully.\n"` and an empty stderr, apart from the children's own output.

### 4.6 Sensitive-data exposure (TS)

| Channel | Credential exposed? |
|---|---|
| `pypi-auth` stdout (also `--quiet`) | yes, the full URL |
| `install --dry-run` stdout | yes |
| `uv add` / `pip install` argv (`ps`, process accounting, shell audit tools) | yes, for the whole run |
| `--debug` log (cwd, 0600, AIRS hosts only) | yes, the response body (§2.6) |
| Error lines | server text verbatim (§2.4), which may carry the credential |
| `pyproject.toml` / `uv.lock` written by uv 0.12.17 | no: uv strips the userinfo (§7.3, experiment A) |
| pip fallback | pip keeps no project file. Its cache and logs were not examined (the path is dropped in Rust) |

### 4.7 Other hazards (not covered by a TS test)

These were established with the real uv in the loopback sandbox (§7.3):

- **Existing project.** `uv init <dir>` where `<dir>/pyproject.toml` exists fails with `error: Project is already initialized in `<abs>` (`pyproject.toml` file exists)`, exit 2. TS then reports `uv init failed with exit code 2`, exit 1, after minting a credential.
- **Existing directory without a project.** uv adds its files and keeps existing ones: an existing `README.md` and `main.py` were left untouched, and `.git`, `.gitignore`, `.python-version`, `pyproject.toml` and `src/` were added.
- **Nested in a uv project (silent side effect).** `uv init <dir>` inside an existing uv project prints `Adding `model-security` as member of workspace `<parent>`` and **rewrites the parent `pyproject.toml`** (`[tool.uv.workspace] members = ["model-security"]`). `--no-workspace` avoids it.
- **Option injection.** A `--dir` that starts with `-` becomes a uv option (§1).
- uv 0.12.17's default `uv init` creates a packaged app: `src/<name>/`, `[project.scripts]`, and `[build-system] requires = ["uv_build>=0.12.17,<0.13.0"]`. uv builds it in-process, and no request for `uv_build` was observed.

## 5. TS specs to port

- `tests/unit/airs/modelsecurity.spec.ts:794-809` (`getPyPIAuth`): the service maps `{url, expires_at}` to `{url, expiresAt}`. In Rust this becomes the json view `{"url": <withheld form>, "expiresAt": …}` (§8.1). No other spec covers `pypi-auth` or `install`: `tests/**` has no CLI test for either. `help-examples.spec.ts` and `aliases.spec.ts` list only model-security list/delete commands.
- The docs pages `install.md` (options table, four examples, "auto-detects uv or pip") and `pypi-auth.md` (the sample output above) are the user-facing contract. The Rust docs must replace "auto-detects uv or pip" with uv only and `--fetch-uv`.

## 6. Rust SDK (`scm-sdk` 0.1.1) coverage

- `ModelSecurityClient::get_pypi_auth(&self, options: Option<&RequestOptions>) -> Result<PyPIAuthResponse>` (`rs:airs/model_security/client.rs:73-86`). It sends `RawRequest::read("/v1/pypi/authenticate").named("airs.model_security.get_pypi_auth")` on the management client, contract `PyPIAuthResponseSchema`. `read()` marks the request `safe_read` (`rs:engine.rs:63-67`), so the SDK's read retries apply. The client is built with `ModelSecurityClient::new(client, data, management)` (`client.rs:28-34`), and both endpoints must be admitted by the destination policy.
- **Feature gate.** The type sits behind `model-security = ["models"]` (`scm-sdk` `Cargo.toml:66`). `airs-cli` enables `["reqwest-transport","scan","management","red-team","dlp"]` (`Cargo.toml:46`), so M6c must add `"model-security"`.
- `PyPIAuthResponse { url: String, expires_at: String, extensions }` (`rs:models/generated.rs:158957-158966`). Its `Debug` prints `PyPIAuthResponse([REDACTED])` (`:159042-159046`), so a stray `{:?}` cannot leak it. The schema `s010295` (`src/validation/schema_graph.json`) has two required strings with no checks and **no defaults** (`passthrough`, catchall never). G10 does not apply: `without_response_defaults()` changes nothing here. Pass it anyway, for uniformity with the other M6c reads, and record that it is a no-op.
- No gap found for these two commands.

## 7. uv research

### 7.1 Pinned release: uv 0.12.17

Chosen because it is the version installed locally (Homebrew build dated 2026-09-18, more than two weeks old), so the §7.3 persistence results were measured on the pinned version. Release base: `https://github.com/astral-sh/uv/releases/download/0.12.17/`. Asset `uv-<target>.tar.gz`. The SHA-256 values below come from the release's `sha256.sum`, cross-checked against each asset's own `uv-<target>.tar.gz.sha256` (all six agree; fetched 2026-10-18):

| Target | Asset | SHA-256 |
|---|---|---|
| aarch64-apple-darwin | `uv-aarch64-apple-darwin.tar.gz` | `85f00cbdc6dd3e97eba4c31b4d014375a9fdfe8f570023b84e5102fc3456896b` |
| x86_64-apple-darwin | `uv-x86_64-apple-darwin.tar.gz` | `8dcf05a8c809bb3c471d2b614788ba27a6e41298fc8c31ac84b5f4339fd468e5` |
| aarch64-unknown-linux-musl | `uv-aarch64-unknown-linux-musl.tar.gz` | `a6096da273d548cb9f277d237a01ac7344a39ef0f455c0e148e4dc9737c1596b` |
| x86_64-unknown-linux-musl | `uv-x86_64-unknown-linux-musl.tar.gz` | `6401c4665d8fa2a9893e087c91f585430738e3170f5398a1141483efb4a93310` |
| aarch64-unknown-linux-gnu | `uv-aarch64-unknown-linux-gnu.tar.gz` | `d636d1b678e9e7f367ecb22b46bd1cabbed234d6bc3b4d96365d2b507f72f86c` |
| x86_64-unknown-linux-gnu | `uv-x86_64-unknown-linux-gnu.tar.gz` | `fa82fd8dde8e8eefdecada6aa0889666556cfceb690d06e0c3bca49eb3070a63` |

The release also ships Windows `.zip`, `i686`, `armv7`, `arm`, `powerpc64le`, `riscv64gc` and `s390x` assets, which are unused here.

**Archive layout (not verified: the archive itself was not downloaded).** The expected layout is a top-level directory `uv-<target>/` holding the executables `uv` and `uvx`. This is the cargo-dist convention, consistent with the official installer extracting with `--strip-components 1`. The extractor design (§8.3) selects only these two names and fails clearly if `uv-<target>/uv` is absent. A first manual `--fetch-uv` run by the maintainer confirms it (open question 1).

### 7.2 Sandbox

Two `ThreadingHTTPServer` PEP 503 indexes ran on `127.0.0.1`. Index P served `/private/simple/` and required `Authorization: Basic base64("oauth2accesstoken:FAKE-PYPI-CRED-123")`, answering 401 without it. Index Q served `/public/simple/` with no auth. Each server was on its own port, so the two had different origins, as Google Artifact Registry and PyPI do. Both logged method, path and auth state (`good`/`bad`/`none`).

The fake wheels were `model_security_client-1.0.0` on P (requires `fake-common`, extras `all`/`aws` add `fake-boto`, plus `gcp`, `azure`, `artifactory` and `gitlab`), and `fake_common-2.0.0` and `fake_boto-2.0.0` on Q.

uv ran under `env -i` with:

- `HOME`, `XDG_*` and `UV_CACHE_DIR` inside the sandbox;
- `UV_PYTHON_INSTALL_DIR` in the sandbox, `UV_PYTHON_DOWNLOADS=never` and `UV_PYTHON=/opt/homebrew/bin/python3.14`;
- `UV_DEFAULT_INDEX=http://127.0.0.1:<Q>/public/simple/`;
- `ALL_PROXY`, `HTTP_PROXY` and `HTTPS_PROXY` set to a dead loopback port, with `NO_PROXY=127.0.0.1,localhost`, so any non-loopback request would have failed;
- `UV_NO_CONFIG=1` (omitted in the runs marked "config on").

After each experiment the whole sandbox was searched for the password, both in clear and as the Basic base64 string. That covers the project, `.venv`, the uv cache and the XDG data dir.

### 7.3 Experiments and results

| # | How the index and credential were passed | argv carries the credential | Install | What uv persisted |
|---|---|---|---|---|
| A | TS form: `uv add --project ms "model-security-client[all]" --index http://oauth2accesstoken:FAKE-PYPI-CRED-123@127.0.0.1:<P>/private/simple/` | yes | ok | `pyproject.toml`: `[[tool.uv.index]] url = "http://127.0.0.1:<P>/private/simple/"`, **userinfo stripped**. `uv.lock`: `source = { registry = "http://127.0.0.1:<P>/private/simple/" }` and wheel URLs with no userinfo. No credential anywhere in the sandbox |
| B | `UV_INDEX=http://oauth2accesstoken:…@127.0.0.1:<P>/private/simple/` in the env, no `--index` | no | ok | same as A (the env index **is persisted** into `pyproject.toml`, stripped) |
| C | `--index airs-model-security=http://127.0.0.1:<P>/private/simple/` (no userinfo) with `UV_INDEX_AIRS_MODEL_SECURITY_USERNAME=oauth2accesstoken` and `UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD=FAKE-PYPI-CRED-123` | no | ok | `[[tool.uv.index]] name = "airs-model-security"` with the URL. The lock holds credential-free URLs. Nothing else contains the credential |
| C′ | `UV_INDEX=airs-model-security=http://oauth2accesstoken:<pct-encoded>@…` | no | ok | named index, stripped |
| F | as C, two origins, config off and on | no | ok | the credential was sent only to index P. Every request to Q was `auth: none` |

Further results:

- **Later `uv sync` (config on).** Without the env credentials it fails: `HTTP status client error (401 Unauthorized) for url (http://127.0.0.1:<P>/private/files/model_security_client-1.0.0-py3-none-any.whl)` (the URL is credential-free). With the two env variables it succeeds. The named index in `pyproject.toml` is therefore the durable, credential-free record, and the user re-supplies the credential per use.
- **`UV_NO_CONFIG=1` ignores the project's `[tool.uv.index]`.** In experiment F (config off), a later `uv sync --refresh --reinstall` queried only the default index and failed with `No solution found … only model-security-client[all]<1.0.0 is available`. **The Rust CLI must not set `UV_NO_CONFIG`** for its uv runs. It is harmless for the one `uv add` (the index is on the command line), but it would mislead any later check.
- **Same-origin credential reuse.** When P and Q shared one origin, uv sent the P credential to Q's paths too: uv keys credentials by realm (scheme, host, port). With separate origins (the real case) it did not. This was a lab artefact, recorded so tests use two ports.
- **Percent-encoding.** Userinfo in a URL is percent-decoded by uv (`FAKE%2DPYPI-CRED-123` in the URL authenticated as `FAKE-PYPI-CRED-123`). Env variable values are taken literally (the same string in `…_PASSWORD` gave `auth: bad`). The CLI must percent-decode the username and password from the service URL before putting them in the environment.
- **Env name derivation.** The index name `airs-model-security` maps to `UV_INDEX_AIRS_MODEL_SECURITY_{USERNAME,PASSWORD}` (upper case, `-` becomes `_`). Verified.
- **uv's messages never showed the credential.** With a wrong password in `UV_INDEX` and `-v`, uv's errors and debug lines showed `http://127.0.0.1:<P>/private/simple/` (the hint was `An index URL (…) could not be queried due to a lack of valid authentication credentials (401 Unauthorized)`). The wrong password occurred 0 times. The named-index variant gave the same result.
- **What persists the env.** `UV_DEFAULT_INDEX` and `UV_INDEX` from the environment are written into `pyproject.toml` by `uv add` (stripped). A user's own `UV_INDEX`/`UV_DEFAULT_INDEX` therefore ends up in the new project: their configuration, not a credential.
- **Proposed argv verified.** `uv init --no-workspace -- "<abs>/-odd dir/model-security"` then `uv add --project "<abs>/-odd dir/model-security" --index airs-model-security=<url> -- "model-security-client[all]"` work, with a leading-dash path segment and a space. `--` ends the options for both subcommands.
- **Residual exposure of the environment.**
  - Exposure: a process's environment is readable only by the same uid or root (`/proc/<pid>/environ` is 0400 on Linux; `ps -E` on macOS shows other users' environments only to root), whereas argv is world-readable. The env channel is a strict improvement.
  - Inheritance: uv passes its environment to the build backends it runs for source distributions, and to `git` during `uv init`. For that reason the credential goes only to `uv add`, never to `uv init`.
  - The rest is the same exposure any package-install tool has.

## 8. Proposed Rust design

### 8.1 `model-security pypi-auth`

- **Surface.** No positionals. Formats via the global `--output`: `pretty|table|json` (FormatPolicy `TENANT_DEFAULT`, as other management reads), where `markdown|csv|yaml` are usage errors (D50 class). New `--url-file <path>`.
- **Validation before the tenant.**
  - Parse errors exit 2.
  - With `--url-file`: the value `-` is a usage error (it would mean stdout). An existing path is refused with `files::refuse_existing` (`<path> already exists; choose another --url-file`, exit 1). A missing parent fails the same way as `publish_new`.
- **Request.** One `get_pypi_auth(Some(&RequestOptions::default().without_response_defaults()))` (a no-op, §6). It is a read with the SDK's read retries (choice 3).
- **Secret handling.** Immediately on receipt, the full URL, the decoded and encoded password, and the userinfo string join the invocation's `SecretSet`. The URL is parsed with `url::Url`.
  - **Withheld form**: `<scheme>://[withheld]@<host>[:<port>]<path>`, where the whole userinfo is replaced, and a query or fragment, if present, becomes `?[withheld]`.
  - A URL that does not parse, or has no host, is shown as `[withheld]`.
  - `expires_at` is printed through `terminal_safe`.
- **pretty (stdout).**

  ```
  "\n  Prisma AIRS — Model Security\n  ML model supply chain security\n\n\n  PyPI Authentication\n\n  URL      https://[withheld]@us-west1-python.pkg.dev/fake-proj/fake-repo/simple/\n  Expires  2026-10-18T15:06:25\n"
  ```

  This is the TS layout, colours and quiet rules (§3, §2.3), with the userinfo withheld.
- **table.** One row with the columns `URL` and `Expires`, the same values, in the shared box layout (`ts-renderer.md`).
- **json.** `{"url":"https://[withheld]@…/simple/","expiresAt":"2026-10-18T15:06:25"}` followed by a newline. There is no reveal flag in any format.
- **`--url-file`.** Writes `<full URL>\n` with `files::publish_new` (exclusive link, 0600, never overwrites, fsync), after the response and before rendering. On stderr (outcome line, kept under `--quiet`): `  ✓ Wrote the PyPI index URL, credential included, to <path> (mode 0600).` (the path as given, `terminal_safe`). If the write fails, nothing is rendered and the command exits 1 with the `publish_new` message.
- **Errors.** Built from SDK error metadata only (DESIGN §6): no server text, no URL.
- **Debug log.** Status and headers only (D64), so the body never reaches it.

### 8.2 `model-security install`

Options: `--extras <type>` (default `all`, exact match), `--dir <path>` (default `model-security`), `--dry-run`, and the new `--fetch-uv`. A global `--output` is validated, then ignored (FormatPolicy `NoData`), and `markdown|csv|yaml` are usage errors.

**Order** (every check before the tenant except where stated):

1. Parse: exit 2.
2. `--extras` not in the list: `Invalid extras "<value>". Valid: all, aws, gcp, azure, artifactory, gitlab` (the value `terminal_safe`), exit 2.
3. `--dir`:
   - An empty value is a usage error.
   - The path is resolved to an absolute path against the cwd, and the lexical form is kept (no symlink resolution). The absolute path is what goes to uv.
   - `lstat` must report not-found, else `<dir> already exists; choose another --dir` (`refuse_existing`, exit 1).
   - The parent must be an existing directory, else `Cannot create <dir>; its parent directory does not exist`, exit 1.
4. Resolve uv (§8.3). Without `--fetch-uv`, take the first `uv` on `PATH` that is an executable regular file. If there is none, use the managed copy if it is present and verifies. If neither exists, fail with exit 1:

   ```
   uv was not found on PATH. Install uv (https://docs.astral.sh/uv/) or re-run with --fetch-uv to download uv 0.12.17 into <tools dir>.
   ```

   With `--fetch-uv`, use the managed copy and download it if it is absent; `PATH` is ignored. The chosen uv then runs `<uv> --version` (stdin null, output captured, 10 s cap), and its first line is shown in the status `  Using uv <version> (<path>)`. A non-zero exit, a spawn failure or a timeout is exit 1 (`<path> --version failed`).
5. Read the tenant and assert the management credentials.
6. `GET /v1/pypi/authenticate` (as in §8.1). The secrets join the `SecretSet`.
7. **Check the URL**:
   - it parses;
   - the scheme is `https`;
   - it has a host;
   - the username and password are non-empty after percent-decoding.

   Otherwise fail: `The PyPI auth response is not a usable index URL; nothing was installed.` (exit 1; the URL is never printed).

   `index = <URL with the userinfo, query and fragment removed>`.
8. `--dry-run`: print the plan (below) and exit 0. Nothing is run, created or downloaded.
9. `uv init --no-workspace -- <abs dir>`:
   - environment: inherited, minus `UV_INDEX_AIRS_MODEL_SECURITY_USERNAME` and `UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD` if the user had them set;
   - stdin `/dev/null`, child stdout to the CLI's stderr, child stderr inherited;
   - with the CLI's `--quiet`, `--quiet` is added after `uv`.
10. `uv add --project <abs dir> --index airs-model-security=<index> -- model-security-client[<extras>]`, with the same streams, plus `UV_INDEX_AIRS_MODEL_SECURITY_USERNAME=<decoded user>` and `UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD=<decoded password>`. Neither argv carries the credential. `UV_NO_CONFIG` is never set (§7.3).
11. Success (stderr, outcome lines):

    ```
      ✓ model-security-client installed in <dir>.
      Activate:  cd <dir>
    ```

    The `Activate` line is suppressed by `--quiet`. A dim note follows: `Later uv commands that use the AIRS index need fresh credentials: set UV_INDEX_AIRS_MODEL_SECURITY_USERNAME and UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD from 'airs-cli-rs model-security pypi-auth --url-file <file>'.` (quiet-suppressed).

**Status lines** (stderr, quiet-suppressed): `  → uv init`, `  → uv add`. These are the TS labels.

**Step failures** (exit 1, stderr):

- `uv init failed (exit status <n>)` or `uv init was terminated by signal <n>`. Nothing was installed. The dir may exist if uv created it before failing.
- For `uv add`, the same first line, then `<dir> was created, but model-security-client was not added. Remove <dir> and re-run, or add it with uv yourself.`
- The CLI never deletes the directory (choice 9).

**Dry-run plan** (stdout, data, printed under `--quiet` too):

- In pretty, the header and the section `Commands that would be executed` come first (quiet-suppressed).
- Then one line per command, `  $ ` followed by POSIX shell-quoted words. A word is single-quoted unless it matches `[A-Za-z0-9_@%+=:,./-]+`, and `'` becomes `'\''`. The credential env assignments are shown as the literal words `UV_INDEX_AIRS_MODEL_SECURITY_USERNAME=[withheld]` and `UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD=[withheld]`.

  ```
    $ uv init --no-workspace -- /abs/cwd/model-security
    $ UV_INDEX_AIRS_MODEL_SECURITY_USERNAME=[withheld] UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD=[withheld] uv add --project /abs/cwd/model-security --index airs-model-security=https://us-west1-python.pkg.dev/fake-proj/fake-repo/simple/ -- 'model-security-client[all]'
  ```

  The `[withheld]` words are deliberately not shell-quoted, so a pasted line cannot authenticate by accident. The `uv` shown is the resolved path when it did not come from `PATH` (the managed copy).
- With `--fetch-uv` and no managed copy, a first line `  # would download uv 0.12.17 (uv-<target>.tar.gz, sha256 <hex>) into <tools dir>` is printed, and the commands then show the managed path.
- The dry run still sends the PyPI auth request, for TS parity and because the plan shows the real index host (choice 6).

**Interruption.** Before a child is spawned, the usual phases apply (exit 130/143, no output beyond what was printed). While a child runs:

- the CLI forwards the received signal once to the child (`rustix::process::kill_process`) and waits for it;
- a second signal sends SIGKILL to the child;
- the CLI then prints `Interrupted during uv <init|add>; <dir> may be incomplete.` (stderr) and exits 130 or 143.

Ctrl-C from a terminal also reaches uv directly through the process group, so uv may see the signal twice. How uv handles a second SIGINT was not measured; the second signal sends SIGKILL to the child either way.

### 8.3 `--fetch-uv`

- **Location.**
  - Data root: `$XDG_DATA_HOME` when it is set, non-empty and absolute; otherwise `$HOME/.local/share`. The managed copy lives in `<root>/airs-cli/tools/uv-0.12.17-<target>/` and holds `uv` (0755), `uvx` (0755) and `SHA256SUMS` (0600: the archive hash and the hashes of the two binaries).
  - Directories: `airs-cli` and `tools` are created 0700 when missing. A missing `<root>` is created 0700, one level only; a missing `$HOME/.local` is an error.
  - Every existing component the CLI creates or uses must be a real directory (`lstat`, never a symlink), owned by the euid and not group- or other-writable. Otherwise: `Refusing to use <path>: it is a symlink, not owned by you, or writable by others.` (exit 1).
- **Target.** Chosen by `cfg(target_os, target_arch)`: macOS `aarch64` or `x86_64` gives `*-apple-darwin`. On Linux, `aarch64` or `x86_64` **always selects the musl asset**: it is static and runs on glibc too, and a musl-built CLI cannot reliably detect libc. The gnu hashes are recorded in §7.1 but not used (choice 11). Any other host fails with `--fetch-uv has no pinned uv release for this platform; install uv yourself.` (exit 1).
- **Download.**
  - One `GET https://github.com/astral-sh/uv/releases/download/0.12.17/uv-<target>.tar.gz`, one attempt with no retry.
  - Redirects: at most 5, `https` only. No other host restriction, because integrity comes from the hash.
  - Limits: 64 MiB body cap and a 120 s total timeout.
  - Proxy: the same policy as the CLI's API transport.
  - Status: `  → Downloading uv 0.12.17 (<target>)` (stderr, quiet-suppressed).
  - Errors from transport metadata only: `Cannot download uv 0.12.17: <kind>` (exit 1).
- **Verify before extracting.** Compute the SHA-256 of the whole body (`sha2`, already a dependency) and compare it with the hard-coded value. On a mismatch: `The downloaded uv archive does not match its pinned SHA-256; nothing was installed.` (exit 1). Nothing has touched the disk at this point.
- **Extract** (pure Rust, in memory):
  - `flate2` gunzip, exact-pinned `=1.1.10`, already in the lock file through reqwest's `async-compression`, using the backend features already enabled there. Decompressed output is capped at 256 MiB.
  - An **in-house strict tar reader** (no new crate; `tar` is not in the lock file):
    - It reads 512-byte headers and checks each header checksum.
    - Names come from ustar `prefix`/`name`. Pax `x` `path=` records and GNU `L` long names apply to the next entry; pax `g` records are skipped.
    - It selects exactly `uv-<target>/uv` and `uv-<target>/uvx`, each with typeflag `0` or NUL. The same name with any other typeflag, a duplicate, or a size beyond the data is an error.
    - Every other entry is skipped without touching the filesystem, symlinks, hardlinks, devices and `..` names included. **No archive-supplied path is ever used to write**, because output paths are built by the CLI.
    - A missing `uv` entry fails with `The uv archive does not contain uv-<target>/uv.` (exit 1).
- **Install atomically.**
  1. `mkdir tools/.uv-<16 hex>.tmp` with mode 0700, exclusive.
  2. Create `uv`, `uvx` and `SHA256SUMS` with `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, `fchmod`, write and `fsync`, then `fsync` the directory.
  3. Rename to the final name without replacing: `renameat_with(NOREPLACE)` where rustix offers it, else `rename(2)`, which refuses a non-empty target. Then `fsync` `tools/`.
  4. On any failure, remove the temporary directory. **An existing file is never overwritten.**
- **Reuse.**
  - If the final directory exists, the CLI verifies it:
    - the directory and the files pass the ownership and mode checks;
    - `SHA256SUMS` names the pinned archive hash;
    - the hashes of `uv` and `uvx` match `SHA256SUMS`.
  - If it verifies, the copy is reused with no download.
  - Otherwise: `<path> exists but is not the verified uv 0.12.17; remove it to download again.` (exit 1).
- **Order.** The fetch runs before the tenant is read (§8.2 step 4), so a failed download never mints a credential.
- **Test hook.** Compiled only with `cfg(debug_assertions)`; release builds ignore it. `AIRS_CLI_TEST_UV_ARCHIVE_URL` (an `http://127.0.0.1:<port>/…` or `http://[::1]:<port>/…` URL; anything else is refused with exit 2) and `AIRS_CLI_TEST_UV_ARCHIVE_SHA256` (64 hex) replace the release URL and the pinned hash. Tests serve a fake archive from the harness: a `uv-<target>/uv` shell script that records its argv and the `UV_INDEX_AIRS_MODEL_SECURITY_*` env, plus `uvx`, and variants with a traversal entry, a symlink entry, a bad checksum, no `uv`, and duplicates. The managed copy goes under the sandbox `XDG_DATA_HOME`.

### 8.4 Fixture and test notes

- The harness `FixtureServer` gains `GET <mgmt>/v1/pypi/authenticate`, answering a fake URL `https://oauth2accesstoken:<marker>@pypi.invalid/fake/simple/`. It is never contacted, because uv is a fake.
- A fake `uv` script on the sandbox `PATH` records argv elements one per line, the two env variables, and `UV_NO_CONFIG`. Tests assert:
  - the marker is absent from argv, stdout, stderr and the debug log;
  - the marker is present in the env of `uv add` only;
  - `--no-workspace` and `--` are present;
  - the absolute `--dir` is passed;
  - the fake's stdout lands on the CLI's stderr.
- The TS reference cannot run `install` live or against a real uv. Parity tests compare it with fake tools on `PATH` only: the TS dry-run with its credential, the TS argv, and the TS python3 fallback.
- Every test sets `HOME`, `XDG_DATA_HOME` and `XDG_STATE_HOME` inside the sandbox. A guard test asserts that nothing is created under the real `~/.local/share/airs-cli`.

## 9. Live-tier notes

- `pypi-auth` runs live **only on the Rust side**: `--url-file <private live dir>/pypi-url` to learn the credential, then `--output pretty`, `table`, `json` and `--debug`. The run asserts that the password (and the URL with userinfo) appears in none of stdout, stderr, the debug log or the live summary, and that the file is 0600. The file is then removed. The summary records only `credentialWithheld: true` and the URL host. The TS `pypi-auth` never runs live, because it prints the credential.
- `install` never runs live, on either CLI.

## Acceptance criteria

1. `pypi-auth`: one token request and one `GET <mgmt>/v1/pypi/authenticate` (counted per route).
   - pretty is byte-equal to §8.1, with `[withheld]` replacing the userinfo; table and json withhold it the same way.
   - `--quiet` keeps the key/value lines.
   - `markdown|csv|yaml` exit 2 before the tenant.
   - The marker password never appears in stdout, stderr or the debug log in any format, also on 4xx, 5xx and validation failures.
2. `pypi-auth --url-file F` writes exactly `<url>\n` at 0600.
   - An existing F (a dangling symlink included) is refused before the tenant read, and nothing is sent.
   - `--url-file -` is a usage error.
   - The outcome line is on stderr.
3. `pypi-auth` prints server text only through `terminal_safe`. A control character in `expires_at` becomes U+FFFD. A non-URL `url` prints `[withheld]`.
4. `install` validation order:
   - parse errors and a bad `--extras` exit 2 with no request;
   - an existing `--dir` (file, directory, symlink) exits 1 with no request and no uv run;
   - a missing uv without `--fetch-uv` exits 1 with the hint naming `--fetch-uv` and no request;
   - none of these leaves anything in the store or the data dir.
5. `install` with the fake uv:
   - argv is exactly `uv init --no-workspace -- <abs>` then `uv add --project <abs> --index airs-model-security=<credential-free index> -- model-security-client[<extras>]`;
   - the env of `uv add` holds the decoded username and password, and the env of `uv init` does not;
   - `UV_NO_CONFIG` is not set by the CLI;
   - stdout is empty (the fake's stdout lands on stderr);
   - the success and `Activate` lines are on stderr;
   - exit 0.
6. `install` with a non-https or credential-less auth URL exits 1 with no uv run, and the URL is not printed.
7. `install --dry-run` prints the §8.2 plan on stdout (also under `--quiet`), with `[withheld]` env words and POSIX quoting (a `$(id)` dir is single-quoted). It runs no uv, creates nothing and downloads nothing.
8. Step failures: the fake uv exiting 3 at init gives exit 1 with `uv init failed (exit status 3)`; at add, the extra remove/re-run line. A fake uv killed by a signal reports `was terminated by signal <n>`.
9. Interruption: SIGINT or SIGTERM to the CLI during a sleeping fake uv is forwarded to the child (the fake records the signal). The CLI waits, prints the interruption line, and exits 130 or 143. No child outlives the CLI.
10. `--fetch-uv` against the loopback archive fixture:
    - the archive is verified before extraction, and a bad hash leaves nothing on disk;
    - traversal and symlink entries are ignored, and a symlink named `uv-<target>/uv` is refused;
    - a duplicate `uv` and a missing `uv` are refused;
    - the result is `uv` and `uvx` at 0755 and `SHA256SUMS` at 0600 under 0700 directories in the sandbox `XDG_DATA_HOME`;
    - a second run reuses the copy without a request;
    - a tampered copy, a symlinked `tools` or a group-writable directory is refused and left unchanged;
    - the real `~/.local/share/airs-cli` is untouched.
11. The release build ignores the test hook (a unit test under `cfg(not(debug_assertions))` or a constant check).
12. Parity tests (`dNN_`, §12 rows below) assert both sides with fake tools: TS prints the credential in pretty and dry-run and passes it in argv; Rust does neither.

## Open questions / likely §12 divergences

Candidate rows, numbered from D179 (the implementer confirms the numbers):

- **D179 `pypi-auth` output.** TS prints the full credential-bearing URL in its only (pretty) layout, also under `--quiet`, and ignores `--output`. Rust withholds the userinfo, query and fragment in pretty, table and json, and adds `--url-file` (new file, 0600, never overwritten) as the only channel. The credential joins the `SecretSet`. Reason: secret safety, as D139/D140.
- **D180 debug log.** TS's `--debug` log stores the PyPI response body with the credential (AIRS hosts). Rust logs status and headers only (D64 extended).
- **D181 install uv only.** TS falls back to `python3 -m venv` and pip, and fails with `Neither uv nor python3 found on PATH. Install one first.`. Rust requires uv, fails with the `--fetch-uv` hint, and adds `--fetch-uv` (pinned uv 0.12.17, SHA-256 checked before extraction). Reason: MILESTONES scope; one verified toolchain, and the credential never in argv.
- **D182 credential channel.** TS passes `--index <URL with credential>` in argv (visible in `ps`). Rust passes a credential-free named index `airs-model-security` and the credential in `UV_INDEX_AIRS_MODEL_SECURITY_USERNAME/PASSWORD` to `uv add` only. As a result `pyproject.toml` gains `name = "airs-model-security"` on the index entry; the URL is credential-free in both (uv strips it).
- **D183 dry run.** TS prints the credential, quotes only `[` and space (`$(…)` is pasted unquoted), prints the plan as quiet-suppressed dim lines (`--quiet --dry-run` prints nothing), and shows the TS argv. Rust withholds the credential, uses POSIX quoting, prints the plan as data under `--quiet` too, and shows the Rust argv.
- **D184 `--dir` rule.** TS passes any value to uv:
  - an existing project fails late, after a credential is minted;
  - an existing directory is filled;
  - a directory inside a uv project silently becomes a workspace member, which rewrites the parent `pyproject.toml`;
  - a leading `-` becomes a uv option.

  Rust refuses any existing path before the tenant, passes an absolute path after `--`, and uses `--no-workspace`.
- **D185 streams.** TS writes the success and `Activate` lines to stdout and inherits the child's stdout. Rust writes them to stderr, sends the child's stdout to stderr, and leaves stdout for dry-run data only.
- **D186 interruption.** TS exits at once and leaves the uv child running when the CLI alone is signalled. Rust forwards the signal, waits for the child, prints an outcome line, and exits 130 or 143.
- **D187 URL check.** TS hands any `url` string to uv (http, no credential, control characters). Rust requires https and a credential before running uv.
- **D188 error text.** TS prints server error messages verbatim (`AISEC_CLIENT_SIDE_ERROR:<server text>`). Rust uses SDK metadata only. This is probably covered by the existing DESIGN §6 row: extend it rather than add a new one.

Open questions:

1. The uv 0.12.17 archive layout (`uv-<target>/uv`, `uvx`) is expected, not observed (§7.1). The maintainer should run `--fetch-uv` once, by hand, before release.
2. Whether `SHA256SUMS` should also record the uv binary's version string. The current proposal checks it at run time with `uv --version`.
3. Whether the managed uv should be used implicitly, without `--fetch-uv`, when uv is not on `PATH` (proposed: yes, after verification; choice 10).

Choices proposed for the DESIGN §17 "Choices decided" subsection (each with the rejected alternative):

1. Pin uv 0.12.17, the locally installed version, so the persistence results apply. Rejected: the newest release, whose persistence behaviour was not measured.
2. pypi-auth withholds the whole userinfo, the username included. Rejected: masking only the password, since the username is constant but still part of the credential.
3. pypi-auth is a read with the SDK's read retries. Rejected: one attempt as for D133's `registry-credentials` POST, because a GET duplicates nothing.
4. The credential channel is `--url-file` holding the full URL. Rejected: a dotenv or shell-export file (quoting injection), netrc (a host-wide credential that outlives the run), and a reveal flag to stdout.
5. The credential goes to uv through the named-index env variables, to `uv add` only. Rejected: `UV_INDEX` with userinfo, which clobbers the user's `UV_INDEX`; netrc via `NETRC`, which writes a temporary credential file.
6. The dry run still fetches the PyPI auth, to show the real index host and to check the tenant (TS parity). Rejected: skipping the request.
7. `--dir` must not exist. Rejected: allowing an existing empty directory, which adds a time-of-check race and reuse ambiguity.
8. A non-workspace index (TS semantics; uv's first-index strategy keeps every package the AIRS index carries on that index). Rejected: `explicit = true` with a `[tool.uv.sources]` pin, which would break dependencies hosted only on the AIRS index.
9. A failed `uv add` leaves the directory and says so. Rejected: deleting a directory, a destructive step after an external tool ran in it.
10. The managed uv is used when `PATH` has none and it verifies. `--fetch-uv` forces the managed copy and ignores `PATH`. Rejected: ignoring a previously fetched copy.
11. Linux always uses the musl uv asset. Rejected: detecting glibc, which is unreliable from a static musl CLI.
12. Executables are 0755 inside 0700 directories. Rejected: 0700 executables, which give no extra protection under a 0700 parent.
13. The `--fetch-uv` test hook exists only in debug builds, and only for loopback URLs. Rejected: a hidden flag or an environment override in release builds, which would be a checksum bypass.
14. An in-house strict tar reader. Rejected: the `tar` crate, a new dependency that would also materialise links.
