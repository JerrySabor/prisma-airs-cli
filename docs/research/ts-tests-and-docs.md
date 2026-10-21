# TS CLI test harness, live testing and the testing-guide discrepancy: spec input for `airs-cli-rs`

Scope: how `/Users/cdot/development/redtail/prisma-airs-cli` (binary `airs-cli`, SDK `@cdot65/prisma-airs-sdk` 0.34.0) tests itself. That covers loopback executable tests, SDK contract tests, in-process tests, live E2E specs and live scripts. It also covers the documentation claim that no tests hit live APIs, and what to reuse for a side-by-side harness that runs `airs-cli` and `airs-cli-rs` against one deterministic loopback server.

**Nothing was executed.** The checkout has no `node_modules/` and no `dist/` (`ls node_modules` and `ls dist` were both empty), and installing or building was out of scope. Every statement below comes from reading the code. Where a behavior depends on the TS SDK or on Commander/Vitest/Node internals rather than on CLI code, it is marked **[SDK-dependent]** or **[runtime-dependent]**.

---

## 1. The documentation discrepancy

### 1.1 Exact claims and where they are

| Location | Exact text |
|---|---|
| `docs-site/docs/development/testing.md:48` | "No tests in this repo hit a live API. For live AIRS coverage, run the manual checklist in [Live Smoke Tests](smoke-tests.md) — that's the authoritative way to catch backend wire-format drift, especially under SDK 0.8.0's now-on runtime Zod validation." |
| `testing.md:12-13` | ":::info[No AIRS credentials needed for the unit suite] Unit tests never instantiate the `@cdot65/prisma-airs-sdk` clients. They inject mock service implementations directly into the code paths under test, so the SDK and its HTTP layer are bypassed entirely. You can run `pnpm test` with no AIRS env vars set." |
| `testing.md:46` | "...the SDK and its `Scanner` / `ManagementClient` / `RedTeamClient` / `ModelSecurityClient` are never instantiated. Because no HTTP requests ever leave the process, no AIRS credentials are required." |
| `testing.md:18-32` | The test tree lists only `tests/unit/` (with a non-existent `airs-cli/` folder; the real folder is `tests/unit/airs/`) and `tests/helpers/mocks.ts`. It omits `tests/integration/`, `tests/e2e/` and `tests/fixtures/`. |
| `docs-site/docs/development/smoke-tests.md:5` | "The unit suite uses fully mocked services. Zero tests in this repo hit a real Prisma AIRS tenant." |
| `docs-site/docs/development/local-setup.md:31-33` | ":::note[Tests run without credentials] Unit and integration tests use MSW mocks — you only need real credentials for actual AIRS operations." MSW is not a dependency and no test imports it. It appears in `pnpm-lock.yaml:53,71` only as an optional peer of vitest. |

Docs that contradict those claims:
- `CLAUDE.md:25`: "`pnpm test:e2e              # E2E tests (requires real creds, opt-in)`"
- `local-setup.md:29`: "Live e2e scripts use the selected tenant (or `AIRS_E2E_TENANT=<name>`)."
- `docs-site/docs/cli/aigateway/resources.md:183-191` ("Local live-safe E2E", `RUN_AIGATEWAY_E2E=1`, `pnpm test:e2e:aigateway`)
- `AGENTS.md:24` ("Use `scripts/e2e-agentguard.mjs` for read-only live acceptance")
- `AGENTS.md:339-340` (`scripts/e2e-full-runtime-migration.mjs --execute ...`)
- `docs-site/docs/about/release-notes.md:127-128`

### 1.2 What `pnpm test` actually runs

`vitest.config.ts:8-9` includes `tests/**/*.spec.ts` and excludes `tests/e2e/**`, with setup file `tests/setup.ts`. So `pnpm test` runs 117 unit spec files plus 18 integration specs. It never contacts a live API, but it does instantiate the real SDK and real HTTP:

- **Executable-level, real SDK, loopback `node:http` server (7 files).** These spawn the CLI as a child process:
  - `tests/integration/dlp-tenant-auth.spec.ts`
  - `tenant-setup.spec.ts`
  - `tenant-profile-transfer.spec.ts`
  - `dlp-dictionary-errors.spec.ts`
  - `dlp-profile-pattern-flags.spec.ts`
  - `dlp-transfer-contract.spec.ts`
  - `aigateway-admin-guardrails.spec.ts`
- **SDK contract with a stubbed global `fetch`:** `sdk-runtime-contract.spec.ts`, `sdk-gateway-*.spec.ts`.
- **In-process Commander program:** `buildProgram().parseAsync(...)`, sometimes with `vi.mock('@cdot65/prisma-airs-sdk')`. Covers `tests/integration/cli/*.spec.ts`, including `runtime-bulk-scan.spec.ts`.

The claim that the SDK is never instantiated and no HTTP leaves the process is therefore false for integration tests. What is true is narrower: `pnpm test` never contacts a non-loopback host.

### 1.3 Every executable test or script that hits live APIs, and how it is gated

`vitest.e2e.config.ts:7` includes only `tests/e2e/**/*.e2e.spec.ts` and has **no `setupFiles`**, so these specs read the operator's real tenant registry. They are run with `pnpm test:e2e` (`package.json:26`) or `pnpm test:e2e:aigateway` (`package.json:27`). CI (`.forgejo/workflows/ci.yml`) runs neither the E2E specs nor any `scripts/e2e-*`.

| File | Gate | Tenant source | Mutations | CLI entry |
|---|---|---|---|---|
| `tests/e2e/aigateway-cli.e2e.spec.ts` | `RUN_AIGATEWAY_E2E === '1'` **and** a tenant is selected (`:9-17`, `describe.skipIf(!hasCredentials)` `:52`) | Operator's real registry; spawned with `env: process.env` (`:26`), with no isolation and no config hash check | Creates, updates and deletes one config `cli-e2e-<8 hex>`. `finally` retries the delete (`:104-152`). | Source: `['--import','tsx','src/cli/index.ts', '--quiet','--output','json','aigateway', ...]` (`:22-23`) |
| `tests/e2e/aigateway-dashboard.e2e.spec.ts` | `RUN_AIGATEWAY_DASHBOARD_E2E !== '1'` skips (`:10`) | `isolatedRegistry(selectedTenant())` | Report files only | `AIGATEWAY_DASHBOARD_CLI_ENTRY ?? 'dist/cli/index.js'` (`:13`) |
| `tests/e2e/redteam-dashboard.e2e.spec.ts` | `RUN_REDTEAM_DASHBOARD_E2E` (`:10`) | Isolated registry | Report files | `REDTEAM_DASHBOARD_CLI_ENTRY` (`:13`) |
| `tests/e2e/runtime-dashboard.e2e.spec.ts` | `RUN_RUNTIME_REPORT_E2E` (`:12`) | Isolated registry | None (content read, not persisted) | `RUNTIME_REPORT_CLI_ENTRY` (`:14`) |
| `tests/e2e/runtime-report.e2e.spec.ts` | `RUN_RUNTIME_REPORT_E2E` (`:13`) | Isolated registry. Also reads the real config's secrets and builds an SDK `ManagementClient` directly (`:50, :96-105`). | Report files | `RUNTIME_REPORT_CLI_ENTRY` (`:16`) |
| `scripts/e2e-tenant-profiles.mjs` | None. Runs live whenever invoked (`node scripts/e2e-tenant-profiles.mjs`). | `selectedTenant().configPath` (`:16`), registered with `tenant create live --config` into a fresh private registry | 1 synthetic topic and 1 profile `cli-transfer-e2e-<8hex>`, plus `copy-<8hex>-` restored copies; deleted in `finally` | `AIRS_CLI_ENTRY ?? dist/cli/index.js` (`:23`) |
| `scripts/e2e-dlp-fallback.mjs` | None | Real registry via `tenant list`; `AIRS_DLP_SOURCE_TENANT` (default `aisecurity`) and `AIRS_DLP_DEST_TENANT` (default `cdot65`) (`:24-30`) | 5 profiles `dlp-*-e2e-<12hex>`, deleted | `AIRS_CLI_ENTRY` (`:15`) |
| `scripts/e2e-agentguard.mjs` | None. Read-only. Optional `AIRS_BROWSER_CAPTURE_PATH` for an offline schema check of captured curl responses. | `isolatedRegistry(selectedTenant())` | None | `AIRS_CLI_ENTRY` (`:155`) |
| `scripts/e2e-full-runtime-migration.mjs` | Requires `--execute --source NAME --destination NAME --expect-source-tsg ID --expect-tsg ID` (`:21-28`) | **Real registry. Switches the operator's selection** and "Leaves destination selected" (`:2`). | Full restore; "Never deletes resources" | `AIRS_CLI_ENTRY` (`:32`) |
| `docs-site/docs/development/smoke-tests.md`, `full-cli-sweep.md` | Manual copy-paste | Selected tenant | `full-cli-sweep` creates `smoke-test-*` resources | Installed `airs-cli` |

Not live:
- `scripts/validate-prod-dev-evidence.mjs` (offline tarball validation, `:1`).
- `scripts/runtime-migration-helpers.bash`. Sourcing it makes no calls (`:3`), but its functions do call `airs-cli`.
- `.github/scripts/verify-dlp-consumer.mjs` and `verify-package-consumer.mjs` (no credentials, no external API).

### 1.4 Proposed resolution

1. Replace `testing.md:48` with: "`pnpm test` never contacts a live Prisma AIRS API. Integration specs spawn the real CLI and SDK against a loopback HTTP server with synthetic credentials. Live coverage is opt-in: `pnpm test:e2e` (each spec gated by a `RUN_*_E2E=1` flag and a selected tenant), the manual `scripts/e2e-*.mjs` acceptance scripts, and the manual [smoke](smoke-tests.md) and [sweep](full-cli-sweep.md) checklists."
2. Rewrite `testing.md:12-13` and `:46` so that only *unit* tests are described as SDK-free. Then document three tiers (unit, loopback integration, live) and fix the directory tree.
3. Fix `smoke-tests.md:5` the same way. Fix `local-setup.md:31-33` (remove the MSW claim). Fix the stale credential guidance:
   - `smoke-tests.md:19-22` ("Set the following environment variables (or have them in `~/.prisma-airs/config.json`)").
   - `full-cli-sweep.md:11`.
   - `local-setup.md:88` and `:106-108` ("CLI flags > environment variables > config file").

   The CLI ignores those variables and that file.
4. For `airs-cli-rs`, adopt the same three tiers from day one:
   - `cargo test` means unit tests plus loopback executable tests. It can never reach a non-loopback host.
   - Live runs need an explicit opt-in variable **and** an explicit tenant name, are bounded, and write sanitized summaries.
   - The README states this precisely.

---

## 2. Executable-level loopback harness (the reusable design)

### 2.1 Invocation

Every executable spec shares this helper (`dlp-tenant-auth.spec.ts:17-34`; the same pattern appears in `tenant-setup.spec.ts:24-50`, `tenant-profile-transfer.spec.ts:23-41`, `dlp-dictionary-errors.spec.ts:17-45`, `dlp-profile-pattern-flags.spec.ts:17-33` and `aigateway-admin-guardrails.spec.ts:15-31`):

```ts
const entry = process.env.AIRS_CLI_ENTRY
  ? [resolve(process.env.AIRS_CLI_ENTRY)]
  : ['--import', resolve('node_modules/tsx/dist/loader.mjs'), resolve('src/cli/index.ts')];
result = await exec(process.execPath, [...entry, ...args], { cwd: directory, env: { ...env, ...extraEnv }, timeout: 20000 });
// on rejection: result = error (carries stdout, stderr, code)
expect(result.code ?? 0, result.stderr).toBe(code);
expect(result.stdout + result.stderr).not.toMatch(/FAKE-SECRET|mock-token/);
```

Details:
- `AIRS_CLI_ENTRY` must be a **JavaScript file** run by `node` (`process.execPath`), not a native executable. A Rust harness needs a general argv prefix instead.
- `cwd` is a fresh `mkdtemp` directory, which captures `--debug` JSONL files and default output files.
- The exit-code check passes the CLI's stderr as the assertion message.
- `tenant-setup.spec.ts:34-48` uses a raw `execFile` callback with `child.stdin?.end(stdin)` to feed secrets on stdin. The promisified variant leaves stdin as an open pipe that is never written.

### 2.2 Environment construction

```ts
env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('PANW_') && !k.startsWith('PRISMA_AIRS_')));
env.PRISMA_AIRS_TENANTS_PATH = join(directory, 'tenants.json');
env.NO_COLOR = '1';
```

This pattern is at `dlp-tenant-auth.spec.ts:105-111`, `tenant-setup.spec.ts:12-18` and `dlp-dictionary-errors.spec.ts:85-91`.

Variants:
- `tenant-profile-transfer.spec.ts:177-185` instead drops `PANW_*`, `PRISMA_AIRS_CONFIG_PATH` and `FORCE_COLOR`, and uses `.../state/tenants.json`.
- The strictest pattern is an allowlist: `.github/scripts/verify-dlp-consumer.mjs:49-56` passes only `{PATH, PRISMA_AIRS_TENANTS_PATH, NO_COLOR:'1', XDG_CACHE_HOME}`, and `verify-package-consumer.mjs:58` passes only `{PATH, NO_COLOR:'1'}`.
- None of the tests override `HOME`. If `PRISMA_AIRS_TENANTS_PATH` were ever missing, the CLI would fall back to `$XDG_STATE_HOME/prisma-airs/tenants.json` or `~/.local/state/prisma-airs/tenants.json` (`src/config/tenants.ts:34-40`).
- `tests/setup.ts:6-15` gives each in-process test file its own empty registry: "Unit/integration tests must never depend on or mutate the user's selected tenant."

Environment variables the CLI or SDK still read, which the harness must control:
- `PRISMA_AIRS_TENANTS_PATH` (`~` expanded, resolved to absolute) and `XDG_STATE_HOME` (must be absolute, else "XDG_STATE_HOME must be an absolute path") (`tenants.ts:34-40`).
- `AIRS_CLI_INVOKED_AS` (`'airs cli'` changes the displayed command name and hints, `src/cli/invocation.ts:3`).
- `NO_COLOR` and `FORCE_COLOR` (chalk).
- `PANW_AI_SEC_DEBUG`, `PANW_AI_SEC_DEBUG_BODY`, `PANW_AI_SEC_TIMEOUT_MS`. These are "Read by the SDK on every request" (`src/config/env.ts:7-12`) **[SDK-dependent]**.
- The CLI itself also tests `PANW_AI_SEC_DEBUG` against `/^(1|true|yes|on)$/i` and refuses profile backup/restore, environment reports and `redteam judge` with exit 2 (`src/cli/program.ts:134-160`). Example: "Disable --debug and PANW_AI_SEC_DEBUG for profile transfer; backups can contain sensitive policy configuration".
- The CLI forces `PANW_AI_SEC_DEBUG_BODY=0` for `runtime dlp` (`program.ts:121-127`).

### 2.3 How tenants are registered for tests

1. **Through the CLI** (`dlp-tenant-auth.spec.ts:113-129`, `tenant-profile-transfer.spec.ts:186-198, 254-256`):
   - Write the config JSON with `{ mode: 0o400 }` (read-only), then run `tenant create <name> --config <file>` and `tenant switch <name>`.
   - Fixture config: `{mgmtClientId:"client-<tsg>", mgmtClientSecret:"FAKE-SECRET-<tsg>", mgmtTsgId:"<tsg>", mgmtEndpoint, mgmtTokenEndpoint:"<base>/oauth/token", dlpEndpoint}` for TSGs `100` (prod) and `200` (dev).
   - `mgmtEndpoint` is deliberately `<base>/not-the-dlp-host` in the DLP test, to prove the DLP calls use `dlpEndpoint`.
   - `create` prints "Registered <name> (TSG <tsg>); config file unchanged. Use airs-cli tenant switch <name>." (`src/cli/commands/tenant.ts:116-118`).
   - `switch` prints "Selected <name> (TSG <tsg>)" (`tenant.ts:189`).
   - After the run, config bytes are compared to the originals (`dlp-tenant-auth.spec.ts:232-233`; sha256 digests at `tenant-profile-transfer.spec.ts:401-406`).
2. **Writing the registry directly**, which is what `airs-cli-rs` M1 will need, because it never writes the registry. The helper is `writeTestRegistry(registryPath, specs, active)` (`tests/helpers/tenant.ts:20-43`):
   - Configs go to `<dirname(registry)>/configs/<name>.json` with mode 0600; the directory gets mode 0700.
   - Each config is merged over `TEST_CREDENTIALS = {mgmtClientId:'client', mgmtClientSecret:'secret', mgmtTsgId:'123'}`.
   - The registry is written as `JSON.stringify({version:1, active, tenants:[{name, configPath, tsgId:String(mgmtTsgId)}]}, null, 2) + "\n"` with mode 0600.
   - It is used by `dlp-dictionary-errors.spec.ts:92-106` and wrapped by `useTestTenant()` (`tenant.ts:49-58`).
3. **Guided creation** with `tenant create dev --tsg-id 100 --client-id client-100 --client-secret-stdin` (secret on stdin) plus `tenant set dev mgmtTokenEndpoint <url>` and `tenant set dev mgmtEndpoint <base>` (`tenant-setup.spec.ts:91-97`).

The registry contract the Rust reader must accept or reject identically (`src/config/tenants.ts`):

| Rule | Location |
|---|---|
| Strict schema: `version` literal 1, `active` is a string or null, at most 1000 tenants, unique names, `active` must be registered | `:9-28` |
| Name regex `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$` | `:9` |
| `configPath` must be absolute | `:13` |
| `tsgId` has minimum length 1 | `:14` |
| Registry must pass `lstat` as a regular file of at most 1 MiB | `:54-55` |
| A missing registry means an empty registry | `:57` |
| Any other failure: "Cannot read tenant registry at <path>; restore a valid registry before proceeding" | `:60` |
| Config: `realpath` then `lstat` must be a file of at most 1 MiB, must be a JSON object, and must pass `ConfigSchema`; otherwise "Cannot read a valid tenant config at <path>" | `:82-88` |
| TSG mismatch (wrong-tenant): "Tenant config TSG differs from its registered identity; register it under a new name" | `:90-92` |
| No selection, API commands: "No tenant selected. Run 'airs-cli tenant switch <name>' (registered: a, b)" or "No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'" | `src/config/loader.ts:39-45` |

### 2.4 Loopback server behavior

**OAuth** (`dlp-tenant-auth.spec.ts:46-71`, `tenant-profile-transfer.spec.ts:96-128`, `tenant-setup.spec.ts:58-79`). On `POST /oauth/token`:
- Parse the body as `URLSearchParams` and take `tsg = scope.replace('tsg_id:','')`.
- Accept if the TSG is known **and** either Basic `base64decode(Authorization minus "Basic ")` equals `client-<tsg>:FAKE-SECRET-<tsg>`, **or** the form fields `client_id`/`client_secret` match. Both client-authentication styles are accepted. The TS SDK's actual choice is not asserted **[SDK-dependent]**.
- Neither `grant_type` nor Content-Type is checked.
- On failure: `401` with body `{}`.
- On success: record `{method:'POST', path, tsg}` and reply `{"access_token":"mock-token-<tsg>","expires_in":3600,"token_type":"Bearer"}`. Some specs reply `{access_token:'mock-token', expires_in:3600}` with no `token_type` and no credential check (`dlp-dictionary-errors.spec.ts:78-81`).
- `tenant-setup` matches the exact `req.url === '/oauth/token'` and requires the exact scope `tsg_id:100`.

**Bearer verification and tenant attribution.**
- `tsg = Authorization.replace('Bearer mock-token-','')`; an unknown TSG gets `401 {}` (`dlp-tenant-auth.spec.ts:72-76`). Encoding the TSG in the token lets each API request be attributed to the tenant whose credentials minted the token.
- `tenant-profile-transfer.spec.ts:136-141` returns `403 {}` when a `/(profiles|topics)/tsg/<x>` path TSG differs from the token's TSG. This is the cross-tenant guard.
- AI Gateway additionally requires the header `x-tsg-id: 123` (`aigateway-admin-guardrails.spec.ts:45`).

**Management wire shapes used** (`mgmtEndpoint` = bare base URL):
- `GET .../v1/mgmt/profiles/tsg/<tsg>` returns `{"ai_profiles":[...],"next_offset":0}`.
- `GET .../v1/mgmt/topics/tsg/<tsg>` returns `{"custom_topics":[...],"next_offset":0}`.
- `POST /v1/mgmt/profile|topic` rejects bodies that contain `tsg_id`, `profile_id`, `topic_id` or `revision` with 400 (`tenant-profile-transfer.spec.ts:136-167`).
- An empty list makes `runtime profiles list --output json` print `[]` after exactly `['oauth:100','profiles:100']` (`tenant-setup.spec.ts:98-103`).

**Error bodies:** `application/problem+json` 400 responses with `detail`/`errors[].rejectedValue` that contain private markers, to prove the CLI does not echo them (`dlp-dictionary-errors.spec.ts:66-84, 123-145`).

### 2.5 Assertions

- **Exit codes** on every call, compared against an expected code, defaulting to 0.
- **Secret leakage.** Every invocation, including expected failures, asserts that stdout+stderr do not match `/FAKE-SECRET|mock-token/` (or `/PRIVATE-KEYWORD|FAKE-SECRET|mock-token/`, `/PRIVATE-PAYLOAD|.../`). The registry file must not contain `FAKE-SECRET` (`tenant-profile-transfer.spec.ts:407-409`). `tenant read` must render `[REDACTED]` for `mgmtClientSecret` (`tenant-setup.spec.ts:122-124`).
- **Credential env vars ignored.** `PANW_MGMT_CLIENT_ID=wrong-client`, `PANW_MGMT_CLIENT_SECRET=wrong-secret`, `PANW_MGMT_TSG_ID=200`, `PANW_DLP_ENDPOINT=http://127.0.0.1:9/never` and `PRISMA_AIRS_CONFIG_PATH=<dev.json>` still yield requests attributed only to `['100','100']` (`dlp-tenant-auth.spec.ts:236-245`).
- **Request accounting.** `requests` has exactly 2 entries (OAuth, then GET); there are no requests on usage errors; dry-runs make no non-GET requests (`tenant-profile-transfer.spec.ts:300-302`).
- **Wrong-tenant and usage errors before any network I/O** (`tenant-profile-transfer.spec.ts:412-436`):
  - `--debug`, `PANW_AI_SEC_DEBUG=true`, `--file-format exe`, `--max-pages 0` and malformed restore JSON each exit 2 with `requests == []` and no `*.jsonl` written.
  - `--expect-tsg 200` against TSG 100 exits 2 with no new requests. The message is "--expect-tsg does not match the selected destination tenant; no API request was made" (`src/cli/commands/profile-transfer.ts:295`).
  - Overwriting a writable config with `{}` makes `backup` exit 1.
- **Error formats** (`src/cli/renderer/common.ts:12-30`):
  - Operational errors write `\n  ✗ Error: <message>` to stderr, then `    HTTP <status>` and `    Re-run with --debug to capture redacted API diagnostics.` when a status is known, then a blank line, and exit 1.
  - Usage errors write `\n  ✗ <message>\n` and exit 2.
  - Unhandled rejections write `\n  Unexpected error: <message>` and exit 1 (`src/cli/process-guards.ts:4-9`).
- **Debug logs cannot be validated on loopback.** "The CLI logger filters non-PANW hosts" (`dlp-dictionary-errors.spec.ts:236-240`; allowlisted domains at `src/cli/debug-logger.ts:13-23`), so the JSONL file is `''`. TS SDK debug lines on stderr include `← 400` and `[BODY OMITTED]` **[SDK-dependent]**.

### 2.6 Weaknesses to avoid in the Rust harness

- **A killed process can pass as success.** `result.code ?? 0` treats a process killed by the 20 s timeout (Node sets `code=null`, `signal='SIGTERM'`) as exit 0 **[runtime-dependent]**. `verify-package-consumer.mjs` does it correctly by asserting `result.signal === null`.
- **Only the DLP specs run against the build in CI.** The consumer matrix (Node 20.17.0, 22.13.0, 24) runs `AIRS_CLI_ENTRY="$PWD/dist/cli/index.js" pnpm exec vitest run` on the four DLP specs only (`.forgejo/workflows/ci.yml:84-104`). `tenant-setup` and `tenant-profile-transfer` support `AIRS_CLI_ENTRY` but run only from source in CI.
- **Command code is not coverage-gated.** Coverage excludes `src/cli/**` (`vitest.config.ts:13`), so exit codes, stdout and stderr are covered only by these spawn tests.
- **No executable-level test exists for `runtime scan`, `runtime profiles get`, `runtime topics list/get` or `doctor`.** Those milestone 1-3 surfaces need new fixtures.

---

## 3. SDK runtime contract (`tests/integration/sdk-runtime-contract.spec.ts`)

This is SDK-level, not a CLI test. It stubs global `fetch` and calls `init({apiKey:'contract-api-key', apiEndpoint:'https://contract.invalid', numRetries:5})`, then `new Scanner().asyncScan(REQUEST, {numRetries:0})`. `REQUEST` is `[{req_id:0, scan_req:{ai_profile:{profile_name:'contract-profile'}, contents:[{prompt:'contract prompt'}]}}]` (`:4-12`).

- A network rejection (`TypeError('connection reset')`) rejects with `{failureKind:'network'}`, and `fetch` is called exactly once (`:19-32`). A per-call `numRetries:0` overrides the global value of 5.
- HTTP 429 with `Retry-After: 2` rejects with `{failureKind:'http', statusCode:429, retryAfterMs:2000}` after exactly one call (`:34-54`).
- `MAX_NUMBER_OF_BATCH_SCAN_OBJECTS === 20`. Twenty objects are accepted; the response `{received, scan_id:'contract-batch-20'}` resolves after one call (`:56-80`).

Rust equivalents to pin: Rust `init()` defaults `num_retries` to 5 and rejects values above 5 (`scm-sdk-rs/crates/scm-sdk/src/configuration.rs:93-96`).

## 4. Bulk-scan harness (milestone 5 notes only)

`tests/integration/cli/runtime-bulk-scan.spec.ts` runs **in process**:
- It mocks the SDK's `init` and `Scanner` with hoisted `asyncScan`, `queryByReportIds`, `queryByScanIds` and `syncScan` mocks (`:7-21`).
- It calls `useTestTenant({airsApiKey:'test-api-key', dataDir:<tmp>/runs})`, and state lands in `<tmp>/bulk-scans` (`:36, :131`).
- It spies `process.exit` to throw `ProcessExitError(exitCode)` and asserts `.rejects.toMatchObject({exitCode:1})` (`:111-129, :959-963`).
- It checks the `<state>.lock` lifecycle (`:200, :207`).
- Rows come from `completeRow(scanId, reqId, action, category, promptDetected)`, which returns `{scan_id, req_id, status:'complete', result:{scan_id, report_id:'report-<scan>', action, category, prompt_detected}}` (`:965-984`).

None of this exercises the executable or HTTP, so milestone 5 needs new loopback tests.

---

## 5. Live tests: tenant selection, cost bounds, sanitization and cleanup

### 5.1 Tenant selection

Two parallel helpers exist: `tests/helpers/live-tenant.ts` (schema-validated through `src/config/tenants.ts` `readTenantStore`) and `scripts/lib/live-tenant.mjs` (plain `JSON.parse`, no schema).

- `registryPath()` returns `PRISMA_AIRS_TENANTS_PATH`, else `$XDG_STATE_HOME/prisma-airs/tenants.json`, else `~/.local/state/prisma-airs/tenants.json` (`live-tenant.mjs:11-16`).
- `selectedTenant(name = process.env.AIRS_E2E_TENANT)` picks the named entry, else the registry's `active`. Otherwise it throws "No tenant selected. Run 'airs-cli tenant switch <name>' or set AIRS_E2E_TENANT to a registered tenant" (`live-tenant.mjs:29-38`, `live-tenant.ts:7-16`).
- `isolatedRegistry(tenant)` writes `{version:1, active:tenant.name, tenants:[tenant]}` (mode 0600) into `mkdtemp(tmpdir()/airs-e2e-registry-)`. The path is passed to the spawned CLI as `PRISMA_AIRS_TENANTS_PATH`, so the operator's registry is never written. These temp directories are never removed.
- `e2e-tenant-profiles` instead uses an empty private registry and runs `tenant create live --config <real path>` (no copying or editing).

### 5.2 Environment for live runs

- The E2E specs use `{...process.env, PRISMA_AIRS_TENANTS_PATH, PANW_AI_SEC_DEBUG:'0', PANW_AI_SEC_DEBUG_BODY:'0', PANW_AI_SEC_TIMEOUT_MS:'20000'}`. They do **not** scrub `PANW_*` credential variables and rely on the CLI ignoring them (`runtime-report.e2e.spec.ts:52-58`).
- The scripts scrub `PANW_*`, `PRISMA_AIRS_CONFIG_PATH` and `FORCE_COLOR`, and set `NO_COLOR=1` (`e2e-tenant-profiles.mjs:20-30`).
- `e2e-agentguard` keeps `process.env` and only sets the debug variables to 0 and `NO_COLOR` (`:23-29`).

### 5.3 Cost and blast-radius bounds

- No live test submits a runtime scan. `doctor`'s scanner probe deliberately avoids quota by querying results for one random UUID: "syncScan/asyncScan (which submit content and burn scan quota)" (`src/cli/commands/doctor.ts:605-618`).
- Bounded inputs:
  - Fixed time windows: `--days 1`, `--days 30`, 2026-09-07..08, a 30-day AgentGuard window.
  - Small page sizes (`limit` 15/10/100, `--all --limit 3`).
  - Fixed check lists, e.g. `runtime-dashboard` expects 15 checks.
  - Per-command timeouts of 60 s, 90 s, 180 s and 300 s; `maxBuffer` 5-30 MB.
  - `--max 0` (explicitly uncapped) only in migration inventories.
- Writes are limited to uniquely named disposable resources (random UUID suffix), checked for name collisions first (`e2e-dlp-fallback.mjs:153-156`). Ownership is reconciled by **name as well as response ID**, because "a timeout may occur after the service commits" (`e2e-tenant-profiles.mjs:250-273`). Absence is verified after delete.
- Every live run hashes the tenant config with sha256 before and after and asserts it is unchanged.

### 5.4 Sanitization

- Errors are recorded only as `{errorType: error.name, statusCode}`, never as messages. `full-runtime-migration` records the first line of an `AssertionError` message.
- Comments in the code: "Never attach raw stderr, arguments, output, or SDK errors to the test report." (`runtime-dashboard.e2e.spec.ts:41`) and "No stderr/raw error output: it can contain credentials or customer metadata." (`runtime-report.e2e.spec.ts:41`). The exit-status assertion message is "CLI exit status mismatch (output intentionally omitted)".
- Secret checks:
  - The scripts assert stdout and stderr exclude `mgmtClientSecret`, `airsApiKey` and `aiGwInferenceApiKey`.
  - `runtime-report` derives secrets from config keys matching `/secret|api.?key|token/i` with values of 8 or more characters, and checks raw, `encodeURIComponent` and base64 forms (`:206-224`).
  - `full-migration` uses `/secret|token|apikey/i` with values longer than 8 characters.
- Evidence goes to the gitignored `artifacts/<suite>-*/` (`.gitignore:47-65`), mode 0600, flag `wx`: `validation.json` or `results.json`. **`cli-transcript.json` and `command-N.json` contain full stdout and stderr**, so they are private rather than sanitized. Console output is limited to check names and counts.

---

## 6. Running the TS CLI from a built dist

- Build with `pnpm install --frozen-lockfile && pnpm run build`. tsup (`tsup.config.ts`) emits ESM `dist/cli/index.js` with all dependencies and optionalDependencies **external**, so the dist needs the repo's `node_modules/`.
- `buildProgram()` reads `../../package.json` relative to `dist/cli/` for `--version` (`src/cli/program.ts:79-80`), so the dist must stay inside the package root.
- Node engines: `^20.17.0 || ^22.13.0 || >=23.5.0`. CI uses 24 plus the matrix above.
- Run it as `node /abs/prisma-airs-cli/dist/cli/index.js <args>`, or `AIRS_CLI_ENTRY=/abs/.../dist/cli/index.js pnpm exec vitest run tests/integration/<spec>`. The live suites use `RUNTIME_REPORT_CLI_ENTRY`, `REDTEAM_DASHBOARD_CLI_ENTRY` and `AIGATEWAY_DASHBOARD_CLI_ENTRY`.
- Without a build, source mode needs `node_modules/tsx/dist/loader.mjs`.
- `pnpm local:smoke` runs build, `--version` and `--help`.

---

## 7. Recommended side-by-side harness for `airs-cli-rs`

1. **Commands.** Use argv prefixes, e.g. `TS=[node, <abs>/dist/cli/index.js]` and `RS=[<abs>/target/aarch64-apple-darwin/release/airs-cli-rs]`. Run each in its own `mkdtemp` cwd with stdin closed (`/dev/null`) and a per-command timeout. Record `{status, signal, stdout, stderr, requests}`, and require `signal == null` with a numeric status.
2. **Environment.** Use an allowlist: `PATH`, `HOME=<tmp>/home`, `TMPDIR`, `PRISMA_AIRS_TENANTS_PATH=<tmp>/state/tenants.json`, `NO_COLOR=1`. Never pass `XDG_STATE_HOME`, `FORCE_COLOR` or `AIRS_CLI_INVOKED_AS`. Add `PANW_*` and `PRISMA_AIRS_CONFIG_PATH` only in tests that prove they are ignored.
3. **Fixtures.** Write the registry directly in `writeTestRegistry` format, with absolute config paths and configs at mode 0400. Hash the config and registry bytes before and after **every** command. Point every endpoint key at loopback: `mgmtEndpoint`, `mgmtTokenEndpoint`, `airsApiEndpoint`, `dlpEndpoint`, `mgmtDashboardEndpoint`, `aiGwDataEndpoint`, `aiGwAdminEndpoint`, `iamEndpoint`. Otherwise the TS `doctor` probes production AI Gateway, because it always runs `checkAiGatewayApi` when management credentials exist (`doctor.ts:707-711`). The Rust SDK requires `Endpoint::loopback` for `http` and permits only `localhost` or loopback IPs (`scm-sdk-rs/crates/scm-sdk/src/config.rs:25-41, 177-196`).
4. **Server.** On `127.0.0.1:0`, with one request log of method, path, query, redacted header names, body and attributed TSG.
   - OAuth: accept Basic, form-decoding each side (the Rust SDK sends `Basic base64(urlenc(id):urlenc(secret))` and the form `grant_type=client_credentials&scope=tsg_id:<tsg>`, `auth.rs:615-637`), or form `client_id`/`client_secret`. Record which style each CLI used.
   - Issue `mock-token-<tsg>`. Require `Bearer mock-token-<tsg>` on management calls and return 403 when the path TSG differs.
   - Scan: require `x-pan-token: <airsApiKey>` and `x-payload-hash = hex(HMAC-SHA256(key, body))` on bodies, or `Authorization: Bearer <airsApiToken>` (`auth.rs:752-775`). Reject management bearers on scan routes and scan keys on management routes.
5. **Per-invocation invariants.** Neither stream contains any fixture secret or token (raw, URL-encoded or base64). `--output json` stdout parses. Error runs have empty stdout. Usage errors make zero requests.
6. **Comparison policy.**
   - Compare exit codes, stdout JSON (normalized) and request shapes exactly.
   - Compare stderr by required substrings, or with `--quiet`, because TS status and decoration differ.
   - Compare doctor per check name for the scoped subset (`Tenant`, `Config file`, `Environment`, `Scanner credentials`, `Management credentials`, `Scanner API`, `Management OAuth`), not by exit code.
7. **Live mode.** Opt in with `AIRS_RS_LIVE=1` plus `AIRS_E2E_TENANT=<name>` (required, never defaulted to the active tenant). Use an isolated registry copy and verify hashes. Cap the number of prompts and the time budget. Compare security outcomes (`action`, `category`, detection flags), never `scan_id`, `report_id` or timestamps. Write only sanitized summaries; any transcripts are private 0600 files in a gitignored directory.

---

## 8. Bugs and surprises found

- `scripts/e2e-tenant-profiles.mjs:279` runs `tenant switch default` in the private registry, where only `live` exists. `switchTenant` throws 'Tenant not found' (`tenants.ts:168`), so cleanup always records `{check:'Config/registry cleanup', passed:false}` and `tenant delete live --force` never runs.
- `scripts/e2e-dlp-fallback.mjs:21-22, 37, 285`: `tenantList()` closes over `env`, which is later mutated to the isolated registry. The final `assert.equal(await tenantList(), beforeRegistry)` therefore compares the isolated registry with the real one. It fails inside `finally` before `results.json` and the transcript are written. The documented passing output predates the isolated-registry change.
- `e2e-tenant-profiles.mjs:22`, `e2e-dlp-fallback.mjs:48` and `e2e-full-runtime-migration.mjs:34` call `mkdtemp(<repo>/artifacts/...)` without creating `artifacts/`, which does not exist in this checkout. On a fresh checkout they fail with ENOENT. Only `e2e-agentguard` runs `mkdir` first.
- `aigateway-dashboard`, `redteam-dashboard` and `runtime-report` call `selectedTenant()` in the `describe.skipIf` factory body. Vitest runs skipped-suite factories during collection, so without a selected tenant `pnpm test:e2e` fails at collection even when no `RUN_*` flag is set **[runtime-dependent, plausible]**.
- There is no Commander `exitOverride`. Commander's own parse errors (unknown option, missing argument, help shown with an error) use Commander's default exit 1, not 2 **[runtime-dependent, plausible]**. Tenant input-mode conflicts also exit 1 (`tenant-setup.spec.ts:153-161`).
- `runtimeInitOptions` (`src/config/client-options.ts:89-96`) passes `apiToken: config.airsApiToken`, which may be `undefined`. The TS SDK may fall back to `PANW_AI_SEC_API_TOKEN`/`PANW_AI_SEC_API_KEY` for the missing credential; the Rust SDK mirrors exactly that in `init_from_environment`. If so, credential environment variables are not fully ignored for scanning **[SDK-dependent]**. The Rust SDK's `init()` uses `EnvironmentSnapshot::empty()` (`configuration.rs:64-66`), so `airs-cli-rs` should never call `init_from_environment` with a captured snapshot.
- The TS `doctor` scanner check treats any HTTP status other than 401/403 as a pass (`doctor.ts:393-401`), so a misrouted fixture returning 404 could produce a false pass **[SDK-dependent]**.
- `e2e-full-runtime-migration.mjs` mutates the operator's real registry selection, which conflicts with the read-only tenant policy wanted for `airs-cli-rs` live runs.


## Acceptance criteria
- Harness: every invocation of either CLI is spawned with stdin closed, a temp cwd and an allowlisted env, and is required to terminate with a numeric exit status and signal == null (a timeout or kill is a failure, never exit 0).
- Harness: a tenant registry written directly as {"version":1,"active":"prod","tenants":[{"name":"prod","configPath":"<abs>","tsgId":"100"}]} plus a mode-0400 config is accepted by both CLIs without either one writing the registry or config (sha256 unchanged after every command).
- OAuth: `runtime profiles list --output json` sends exactly one POST to the configured mgmtTokenEndpoint (path /oauth/token) whose form body has scope=tsg_id:100 and whose credentials (Basic base64(client-100:FAKE-SECRET-100) or form client_id/client_secret) come only from the selected tenant file.
- Bearer: every management request after token issuance carries Authorization: Bearer mock-token-100; the server answers 401 to any other bearer and the CLI then exits 1.
- Profiles list empty page: the server returns {"ai_profiles":[],"next_offset":0} for GET <mgmtEndpoint>/v1/mgmt/profiles/tsg/100; the CLI prints [] on stdout, exits 0, and the request log is exactly [POST /oauth/token, GET .../v1/mgmt/profiles/tsg/100].
- Topics list: GET <mgmtEndpoint>/v1/mgmt/topics/tsg/100 returning {"custom_topics":[...],"next_offset":0} yields parseable JSON on stdout and exit 0.
- Env ignored: with PANW_MGMT_CLIENT_ID=wrong-client, PANW_MGMT_CLIENT_SECRET=wrong-secret, PANW_MGMT_TSG_ID=200, PANW_DLP_ENDPOINT=http://127.0.0.1:9/never, PANW_AI_SEC_API_KEY=FAKE-ENV-KEY, PANW_AI_SEC_API_TOKEN=FAKE-ENV-TOKEN, PANW_AI_SEC_API_ENDPOINT=http://127.0.0.1:9 and PRISMA_AIRS_CONFIG_PATH=<dev.json>, every server request is attributed to TSG 100 or to the tenant's airsApiKey, and no request carries an env-derived value.
- Wrong tenant: a registry entry with tsgId "100" pointing at a config whose mgmtTsgId is "200" makes list, get and scan exit 1 with stderr containing 'Tenant config TSG differs from its registered identity; register it under a new name', empty stdout, and zero HTTP requests.
- Two-tenant isolation: switching the registry's active entry between prod (100) and dev (200) makes all requests of each run carry only that tenant's token (mock-token-100 or mock-token-200); the server's path-vs-token TSG check (403) is never triggered.
- Corrupt registry (invalid JSON, a symlink, a file over 1 MiB, an unknown key, or active naming an unregistered tenant) exits 1 with stderr 'Cannot read tenant registry at <path>; restore a valid registry before proceeding' and makes zero requests.
- Missing registry file or active:null with registered tenants exits 1 with stderr "No tenant selected. Run 'airs-cli tenant switch <name>' (registered: prod, dev)" (or the create-then-switch variant when the registry is empty) and makes zero requests.
- Unreadable or invalid config (e.g. '{}' or non-JSON) exits 1 with stderr 'Cannot read a valid tenant config at <path>' and no JSON fragment or value from the file appears in output.
- Secret safety: across all invocations, including 401/400/500 server responses and usage errors, stdout+stderr never contain FAKE-SECRET*, mock-token*, the airsApiKey or the airsApiToken in raw, URL-encoded or base64 form.
- Token endpoint 401: when the server rejects OAuth, the CLI exits 1, stdout is empty, stderr reports an authentication failure and contains no client secret or token.
- Stream discipline: for --output json, stdout contains only the JSON document and all status/progress text is on stderr; with --quiet stderr carries no status lines on success.
- Usage errors (invalid flag value detected by the CLI's own validation) exit 2 with empty stdout and zero HTTP requests; operational/API failures exit 1.
- Scan request: `runtime scan --profile <name> <prompt>` sends POST <airsApiEndpoint>/v1/scan/sync/request with header x-pan-token equal to the tenant's airsApiKey, x-payload-hash equal to hex HMAC-SHA256(airsApiKey, raw body), and no Authorization header; no OAuth token request is made for scan-only work.
- Credential separation: the server rejects (and the test fails on) any management request carrying x-pan-token, and any scan request carrying a management Bearer token.
- Doctor scanner probe: the scanner connectivity check issues only GET <airsApiEndpoint>/v1/scan/results with one random UUID and never POSTs scan content.
- Doctor environment check: with PANW_MGMT_CLIENT_SECRET=FAKE-SECRET-ENV set, doctor warns and lists the variable NAME PANW_MGMT_CLIENT_SECRET but never its value; warnings and skips alone leave exit 0, and any failed check exits 1.
- Doctor with no scanner key: the Scanner API check reports skip ('skipped — no scanner credentials configured') and makes no scanner request.
- Loopback endpoints: http://127.0.0.1:<port>, http://localhost:<port> and http://[::1]:<port> endpoints in the tenant file are accepted; any other http:// host is rejected as a configuration error before any request.
- Live mode is never entered unless an explicit opt-in variable AND an explicit tenant name are set; a live run uses an isolated registry copy, verifies the real config's sha256 is unchanged, caps prompt count and wall time, and writes only sanitized summaries (check name, pass/fail, counts, status codes).


## Discrepancies
- docs-site/docs/development/testing.md:48 says 'No tests in this repo hit a live API.' But tests/e2e/*.e2e.spec.ts (5 suites, gated by RUN_AIGATEWAY_E2E, RUN_AIGATEWAY_DASHBOARD_E2E, RUN_REDTEAM_DASHBOARD_E2E and RUN_RUNTIME_REPORT_E2E) and scripts/e2e-{tenant-profiles,dlp-fallback,agentguard,full-runtime-migration}.mjs all call live APIs. The accurate claim is narrower: `pnpm test` never contacts a non-loopback host.
- smoke-tests.md:5 says 'Zero tests in this repo hit a real Prisma AIRS tenant.' This is contradicted by the same suites and scripts.
- testing.md:12-13 and :46 say the SDK clients are never instantiated and no HTTP leaves the process. Seven integration specs spawn the real CLI and SDK and make HTTP requests to a loopback node:http server; sdk-*.spec.ts instantiate SDK clients with a stubbed fetch.
- testing.md:18-32 test tree omits tests/integration, tests/e2e and tests/fixtures, and names a folder 'airs-cli/' that is actually tests/unit/airs/.
- local-setup.md:31-33 says unit and integration tests use MSW mocks. MSW is not a dependency and no test imports it; it appears in the lockfile only as vitest's optional peer.
- smoke-tests.md:19-22 and full-cli-sweep.md:11 tell users to set PANW_AI_SEC_API_KEY/PANW_MGMT_* or ~/.prisma-airs/config.json. local-setup.md:88 says to pass PANW_* variables and local-setup.md:106-108 gives 'CLI flags > environment variables > config file'. The CLI now ignores all of these; only tenant files supply credentials (src/config/env.ts, AGENTS.md:47).
- testing.md:48 references SDK 0.8.0; package.json pins @cdot65/prisma-airs-sdk 0.34.0.
- Integration harness bug: `result.code ?? 0` treats a child killed by the 20 s execFile timeout (code null, signal SIGTERM) as exit 0, so hung commands can pass when success is expected (dlp-tenant-auth.spec.ts:31 and siblings).
- scripts/e2e-tenant-profiles.mjs:279 runs `tenant switch default` against a private registry that only contains 'live'. switchTenant throws 'Tenant not found' (src/config/tenants.ts:168), so cleanup always reports failure and `tenant delete live --force` never runs.
- scripts/e2e-dlp-fallback.mjs: tenantList() closes over env, which is later mutated to the isolated registry (line 37). The final `assert.equal(await tenantList(), beforeRegistry)` therefore compares isolated vs real registry and fails, throwing from finally before results.json and cli-transcript.json are written. The passing output in docs-site/docs/runtime/dlp-fallback-validation.md predates this change.
- Three scripts (e2e-tenant-profiles:22, e2e-dlp-fallback:48, e2e-full-runtime-migration:34) call mkdtemp under <repo>/artifacts/ without creating it. The directory is absent in this checkout, so they fail with ENOENT on a fresh clone. Only e2e-agentguard runs mkdir first.
- Plausible: aigateway-dashboard, redteam-dashboard and runtime-report E2E specs call selectedTenant() inside the describe.skipIf factory. Vitest executes skipped-suite factories, so `pnpm test:e2e` errors at collection on machines with no selected tenant even when no RUN_* flag is set.
- Plausible: there is no Commander exitOverride or exit-code mapping (grep finds only usageError's process.exit(2)), so Commander parse errors (unknown option, missing argument) exit 1, contradicting the documented '2 = usage error'. Tenant input-mode conflicts also exit 1 (tenant-setup.spec.ts:153-161). No test asserts the Commander case.
- Credential env vars are not entirely ignored. The CLI reads PANW_AI_SEC_DEBUG to refuse profile backup/restore, reports and judge with exit 2 (program.ts:134-160) and forces PANW_AI_SEC_DEBUG_BODY=0 for runtime dlp. The TS SDK reads PANW_AI_SEC_DEBUG, PANW_AI_SEC_DEBUG_BODY and PANW_AI_SEC_TIMEOUT_MS on every request (env.ts:7-12), and the live E2E specs set PANW_AI_SEC_TIMEOUT_MS=20000. The Rust SDK reads none of these.
- SDK-dependent: runtimeInitOptions (client-options.ts:89-96) passes apiKey/apiToken that may be undefined. If the TS SDK falls back to PANW_AI_SEC_API_TOKEN/PANW_AI_SEC_API_KEY for an undefined value (the Rust SDK's init_from_environment mirrors exactly that), scanning can pick up an env credential, contrary to the comment 'Every builder passes a concrete value'.
- TS doctor always probes AI Gateway (and TypeSafe when configured) and Node version, so it is broader than the scoped Rust doctor. Unless the fixture points aiGwDataEndpoint etc. at loopback, TS doctor contacts production AI Gateway with a fake bearer. Its exit code also depends on that check (403 gives warn and exit 0; 404 or network failure gives fail and exit 1).
- SDK-dependent: TS doctor's scanner check treats any HTTP status other than 401/403 as 'pass' (doctor.ts:393-401), so a fixture 404 on a misrouted path could report the scanner as reachable.
- --debug JSONL logging filters non-PANW hosts (debug-logger.ts:13-23), so debug redaction cannot be verified against a loopback fixture; the log is empty (dlp-dictionary-errors.spec.ts:236-240).
- CI runs only the four DLP executable specs against the built dist (.forgejo/workflows/ci.yml:96-104). tenant-setup and tenant-profile-transfer support AIRS_CLI_ENTRY but run only from source in CI. Coverage excludes src/cli/**.
- Live harnesses are inconsistent. E2E specs pass {...process.env} without scrubbing PANW_*, while scripts scrub. aigateway-cli.e2e uses the operator's real registry, source via tsx, no isolation and no config-hash check. e2e-full-runtime-migration switches the operator's real registry selection.
- 'Sanitized' applies only to console and summary files. cli-transcript.json and command-N.json store full stdout/stderr (customer policy data), protected only by mode 0600 and .gitignore. isolatedRegistry temp directories are never removed.
- e2e-agentguard hard-codes Model Security endpoints (https://api.apps.paloaltonetworks.com/aims/data and /aims/mgmt) instead of using the tenant's modelSecDataEndpoint/modelSecMgmtEndpoint overrides, unlike the CLI.


## Open questions
- Which OAuth client-authentication style does TS SDK 0.34.0 use (HTTP Basic or form client_id/client_secret)? The TS fixture accepts both; the Rust SDK uses Basic with form-urlencoded parts. Confirm by running the built TS CLI against a logging fixture before deciding whether the comparison asserts the style or only the credentials.
- Does TS SDK init() fall back to PANW_AI_SEC_API_KEY/PANW_AI_SEC_API_TOKEN/PANW_AI_SEC_API_ENDPOINT when the CLI passes undefined? If yes, should airs-cli-rs deliberately differ (never read env), with the harness asserting TS's behavior as a known divergence?
- Should airs-cli-rs honor PANW_AI_SEC_DEBUG / PANW_AI_SEC_DEBUG_BODY / PANW_AI_SEC_TIMEOUT_MS (TS SDK diagnostics), ignore them, or report them in doctor like TS's 'SDK diagnostics on: ...' suffix?
- What exit code do Commander parse errors (unknown option, missing required argument) produce in the built TS CLI? If 1, should airs-cli-rs match it or follow clap's default and the documented contract of 2?
- What exactly does the TS CLI write to stderr on successful list/get/scan without --quiet (spinners, status lines, empty-list notes)? This needs a baseline capture from the built CLI before choosing exact versus substring stderr comparison.
- How should the Rust CLI 'explicitly select' a tenant: only the registry's active entry (as TS does), or also a per-invocation selector (e.g. --tenant NAME or an expect-TSG guard like TS's --expect-tsg, which exits 2 with '--expect-tsg does not match the selected destination tenant; no API request was made')?
- Doctor comparison scope: which TS checks (Tenant, Config file, Environment, Scanner credentials, Management credentials, Scanner API, Management OAuth) must match the Rust scoped doctor, and how are TS-only checks (Node.js version, AI Gateway API, Typesafe credentials and API) excluded from exit-code comparison?
- Live scan bounds for the first release: which profile in the user's tenant, how many prompts, which benign/malicious prompts, and which expected outcomes (action/category/detection flags) define pass?
- Should the side-by-side harness be written in Rust (cargo integration tests spawning both binaries) or in Node/vitest reusing the existing helper patterns? Which Node version is the TS baseline (CI uses 24)?
- How should SIGINT/cancellation during `runtime scan` be specified? The TS CLI installs no SIGINT handler for runtime commands (only aigateway inference does), so TS dies by signal with no output; does the Rust CLI need a defined exit code and stderr message instead?
- Does the TS SDK verify or require x-payload-hash on scan requests the same way as the Rust SDK (HMAC-SHA256 of the body keyed by the API key)? This determines whether the fixture can enforce it for both CLIs.
