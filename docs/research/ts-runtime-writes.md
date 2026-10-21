# Spec: TS `airs-cli` runtime writes (M4): topics `create|update|delete|apply|revert|eval|sample`, profiles `create|update|delete|cleanup`

## 0. Sources and method

- CLI source: the frozen reference `.reference/prisma-airs-cli` (commit `5711012`, 7.2.1-forgejo.0), which pins `@cdot65/prisma-airs-sdk` 0.34.0 and commander 14.0.3. Citations:
  - `runtime.ts:<line>` is `src/cli/commands/runtime.ts`.
  - `topics-*.ts`, `profiles-cleanup.ts` are under `src/cli/commands/`.
  - `management.ts` is `src/airs/management.ts`; `scanner.ts` is `src/airs/scanner.ts`.
  - `builder.ts` is `src/cli/builders/profile-builder.ts`.
  - `ui.ts`, `common.ts`, `eval.ts` and `rruntime.ts` are `src/cli/renderer/{ui,common,eval,runtime}.ts`.
  - `SDK:<line>` is `node_modules/@cdot65/prisma-airs-sdk/dist/index.js`.
- The TS unit tests for these commands mock the management service, so they never exercise the SDK. They are `tests/unit/cli/topics-{apply,create,eval,revert,sample}.spec.ts`, `profiles-cleanup.spec.ts`, `confirm.spec.ts`, `profile-builder.spec.ts` and `tests/unit/core/prompt-loader.spec.ts`. The defects in §7.3 and §10.4 are invisible to them: `topics-revert.spec.ts:21` asserts `forceDeleteTopic('topic-1', undefined)` against a mock.
- How behaviour was captured: the reference build (`dist/cli/index.js`, node v24.21.0) ran against a stateful loopback stub, in a sandbox with fake values and an `env -i` environment. The probe tooling is in the scratchpad under `m4probe/`: `server.mjs`, `probe.sh`, `pty.exp` and `guard.mjs`.
  - Two stub instances run on `127.0.0.1`. **T** is the tenant's `mgmtEndpoint`, `mgmtTokenEndpoint` and `airsApiEndpoint`. **E** is the value given to `PANW_MGMT_ENDPOINT`. Every request is logged with the instance it reached.
  - The tenant is a TS registry plus config through `PRISMA_AIRS_TENANTS_PATH`, with fake credentials (`FAKE-SECRET`, `FAKE-API-KEY`), `NO_COLOR=1` and HOME/XDG inside the sandbox.
  - Every node run preloads `guard.mjs`. It replaces `globalThis.fetch` and `dns.lookup`, refuses any host other than `127.0.0.1` and records each refusal. The SDK's only network calls are `fetch` (`SDK:10186` data, `SDK:11028` token), so nothing could leave loopback.
  - One capture deliberately left `PANW_MGMT_ENDPOINT` unset to prove where `topics create` goes (§2.1). The guard blocked all six attempts.
  - Prompts were driven on a pty with `expect`.
- No real tenant or credential file was read. No host other than loopback was contacted.
- In the captures below, stdout and stderr are shown as JSON strings, and `<T>`/`<E>` mark the stub instance.

## 1. Command surface (help verified)

Aliases come from `program.ts:42-51`: every visible `delete` gets `rm`. So `runtime topics rm` and `runtime profiles rm` work. No other M4 command has an alias. Help is sorted (`program.ts:73-76`).

| Command | Registration | Arguments and options (help text) |
|---|---|---|
| `runtime topics create` | `topics-create.ts:62-113` | `--name <name>` (required, `Topic name`), `--description <desc>` (required), `--examples <examples...>` (required, variadic, `Example prompts (2-5 required)`), `--output <format>` (`Output format: pretty or json (default: "pretty")`), hidden `--format <format>`. Two Examples lines (the second ends `--output json`). Description `Create or update a custom topic definition` |
| `runtime topics update <topicId>` | `runtime.ts:1210-1225` | `--config <path>` (required, `JSON file with topic updates`). Description `Update a custom topic` |
| `runtime topics delete\|rm <topicId>` | `runtime.ts:1107-1129` | `--force` (`Skip confirmation and force delete (removes from all referencing profiles)`), `--updated-by <email>` (`Email of user performing force deletion`) |
| `runtime topics apply` | `topics-apply.ts:55-101` | `--profile <name>` (required), `--name <name>` (required, `Topic name to assign`), `--intent <intent>` (`Topic intent: block or allow (default: "block")`), `--output <format>` (default `pretty`), hidden `--format`. Description `Assign a topic to a security profile (additive)` |
| `runtime topics revert` | `topics-revert.ts:39-83` | `--profile <name>` (required), `--name <name>` (required, `Topic name to remove`), `--force` (`Skip confirmation prompt`), `--output <format>` (default `pretty`), hidden `--format`. Description `Remove a custom topic from a profile and delete it` |
| `runtime topics eval` | `topics-eval.ts:52-100` | `--profile <name>` (required), `--prompts <path>` (required, `Path to CSV file with prompt,expected,intent columns`), `--topic <name>` (default `"unknown"`, `Topic name (for output labeling)`), `--output <format>` (default `pretty`), `--rate <n>` (`Max AIRS scan API calls per second`), `--concurrency <n>` (default `"5"`), hidden `--format`. Three Examples lines |
| `runtime topics sample` | `topics-sample.ts:17-37` | `--output-file <path>` (`Write to file instead of stdout`), hidden deprecated `--output <path>` |
| `runtime profiles create` | `runtime.ts:692-776` | `--name <name>` (required) and the 21 policy flags of §9.1, plus `--no-active` (`Create profile as inactive`) and `--config <path>` (`JSON file with profile configuration (legacy)`) |
| `runtime profiles update <nameOrId>` | `runtime.ts:778-859` | `--name <name>` (`Update profile name`), `--active`, `--no-active`, the same policy flags, and `--config <path>` (`... updates (legacy)`) |
| `runtime profiles delete\|rm <nameOrId>` | `runtime.ts:861-898` | `--force` (`Skip confirmation and force delete (removes from referencing policies)`), `--updated-by <email>` |
| `runtime profiles cleanup` | `profiles-cleanup.ts:67-150` | `--force` (`Skip confirmation — proceed with deletion`), `--updated-by <email>` (`Email for deletion audit (default: git user.email)`), `--output <format>` (default `pretty`) |

The captured `topics create --help`, byte-exact:

```
Usage: airs-cli runtime topics create [options]

Create or update a custom topic definition

Options:
  --description <desc>      Topic description
  --examples <examples...>  Example prompts (2-5 required)
  -h, --help                display help for command
  --name <name>             Topic name
  --output <format>         Output format: pretty or json (default: "pretty")

Examples:
  $ airs-cli runtime topics create --name "Financial Advice" --description "Requests for personal investment advice" --examples "Should I buy TSLA stock?" "How should I invest my savings?"
  $ airs-cli runtime topics create --name "Legal Advice" --description "Requests for legal counsel" --examples "Can I sue my landlord?" "Draft a contract for me" --output json

```

The `runtime topics --help` command list:
- `apply [options]`
- `create [options]`
- `delete|rm [options] <topicId>`
- `eval [options]`
- `get [options] <nameOrId>`
- `help [command]`
- `list|ls [options]`
- `revert [options]`
- `sample [options]`
- `update [options] <topicId>`

Parse errors come from commander: exit 1, a single `error: ...` line on stderr, and no request. Examples are `error: required option '--name <name>' not specified`, `error: required option '--profile <name>' not specified` and `error: missing required argument 'topicId'`. The usage examples print `airs cli` when `AIRS_CLI_INVOKED_AS='airs cli'` (`examples.ts`, `invocation.ts`).

## 2. Shared behaviour

### 2.1 Two ways of building the management client (the endpoint split)

**Family A** uses `createMgmtService()` (`runtime.ts:175-178`). It covers `topics update`, `topics delete`, `profiles create|update|delete` and `profiles cleanup` (`profiles-cleanup.ts:79`).
- It calls `loadConfig()`, then `managementClientOptions` (`config/client-options.ts:44-51`).
- `assertManagementCredentials` runs first. It fails with `Management credentials are not configured (missing <keys>). Run 'airs-cli tenant set <name> <key>' for <keys> (secrets prompt hidden, or use --stdin)`.
- It then passes every value explicitly:
  - `clientId`, `clientSecret` and `tsgId` from the tenant
  - `tokenEndpoint`: `mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`
  - `apiEndpoint`: `mgmtEndpoint ?? DEFAULT_MGMT_ENDPOINT`
- No `PANW_MGMT_*` fallback is consulted.

**Family B** builds an ad-hoc client: `topics create` (`topics-create.ts:86-92`), `topics apply` (`topics-apply.ts:75-81`) and `topics revert` (`topics-revert.ts:61-67`). They all run:

```ts
new SdkManagementService({ clientId: config.mgmtClientId, clientSecret: config.mgmtClientSecret,
  tsgId: config.mgmtTsgId, tokenEndpoint: config.mgmtTokenEndpoint })
```

- **No `apiEndpoint`.** The SDK resolves it as `opts.apiEndpoint ?? process.env.PANW_MGMT_ENDPOINT ?? "https://api.apps.paloaltonetworks.com/aisec"` (`SDK:13419`, `SDK:34`). The tenant's `mgmtEndpoint` is ignored.
- **No credential assertion.** Any unset credential, and an unset `mgmtTokenEndpoint`, falls back through `resolveOAuthConfig` (`SDK:11099-11140`) to `PANW_MGMT_CLIENT_ID`, `PANW_MGMT_CLIENT_SECRET`, `PANW_MGMT_TSG_ID` and `PANW_MGMT_TOKEN_ENDPOINT`. The token endpoint then defaults to `https://auth.apps.paloaltonetworks.com/oauth2/access_token`.
- A missing value that is also absent from the environment fails with the SDK text, for example `AISEC_MISSING_VARIABLE:clientSecret is required (option or PANW_MGMT_CLIENT_SECRET env var)`. That message names an environment variable. Family A reports the same tenant with the tenant hint instead (both verified).

The **memory note** in MILESTONES ("TS `topics create` bypasses the tenant endpoint") therefore applies to **`apply` and `revert` as well**.

Verified wire behaviour (tenant T, `PANW_MGMT_ENDPOINT=<E>`, `topics create --name newt ...`):

```
{"at":"T","method":"POST","path":"/oauth/token",...}                       # token: tenant mgmtTokenEndpoint
{"at":"E","method":"GET","path":"/v1/mgmt/topics/tsg/100","query":{"offset":"0","limit":"100"},"auth":"Bearer tok-T"}
{"at":"E","method":"POST","path":"/v1/mgmt/topic","auth":"Bearer tok-T",...}
```

- **The tenant's bearer token is sent to a host the tenant never named.**
- With `PANW_MGMT_ENDPOINT` unset, the guard recorded six attempts at `GET https://api.apps.paloaltonetworks.com/aisec/v1/mgmt/topics/tsg/100` (one plus five retries; network errors retry with backoff). The run ended with `\n  ✗ Error: AISEC_CLIENT_SIDE_ERROR:fetch failed\n\n` (exit 1) after about 6 s. A loopback-only tenant is therefore bypassed, and production receives its token.
- With a tenant missing `mgmtClientSecret` and `PANW_MGMT_CLIENT_SECRET=ENV-SECRET` exported, `topics create` succeeded (exit 0). The secret came from the environment.

**Endpoint table (TS):**

| Command | Token endpoint | Management data endpoint | Other |
|---|---|---|---|
| `topics create`, `apply`, `revert` | tenant `mgmtTokenEndpoint`, else `PANW_MGMT_TOKEN_ENDPOINT`, else the SDK default | `PANW_MGMT_ENDPOINT`, else `https://api.apps.paloaltonetworks.com/aisec` | — |
| `topics update`, `delete`; `profiles create`, `update`, `delete`, `cleanup` | tenant `mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT` | tenant `mgmtEndpoint ?? DEFAULT_MGMT_ENDPOINT` | — |
| `topics eval` | — | — | scanner: tenant `airsApiEndpoint ?? DEFAULT_ENDPOINT` (`client-options.ts:89-96`); `airsApiKey`/`airsApiToken`, with the SDK's `PANW_AI_SEC_API_KEY`/`TOKEN` env fallback for the missing one (see `ts-runtime-scan.md`) |
| `topics sample` | — | — | none (no tenant is read) |

The management client is a process singleton (`management.ts:543-554`), but each command builds exactly one.

### 2.2 `--output` and the per-command `--output`/`--format`

- The program never calls `enablePositionalOptions()`, so the root `--output <format>` (`program.ts:108`) consumes `--output X` and `--output=X` anywhere on the command line (`ts-cli-shell.md` §3). The subcommand's own `--output` (on `create`, `apply`, `revert`, `eval` and `cleanup`) therefore always keeps its default `"pretty"`.
- The preAction format validation (`program.ts:162-175`) runs only for `READ_COMMAND_NAMES`, and no M4 command is one. A root `--output xml` is accepted silently and ignored by every M4 command (by code; `--output json` was verified to have no effect on all of them).
- **The only way to reach the JSON branches** of `create`, `apply`, `revert` and `eval` is the hidden deprecated alias `--format <format>` (`deprecated-flags.ts:35-53`).
  - The canonical key's value source is `default`, so `--format json` overrides it.
  - It prints `  ⚠ --format is deprecated and will be removed in v4 — use --output` (yellow) on **stderr** with `console.error`. The line is not suppressed by `--quiet`.
  - Verified for create, apply and eval.
  - Any `--format` value other than `json` gives pretty output. The comment in `topics-create.ts:100` says "'terminal' is the legacy spelling".
- `profiles cleanup` has no `--format`, so **its JSON branch is unreachable** from the command line (verified: `--output json` prints the pretty preview).
- `topics sample`'s deprecated `--output <path>` is also eaten by the root option. `topics sample --output old.csv` prints the CSV to stdout, writes no file and shows no warning (verified).
- `profiles create|update` and `topics update|delete` have no format option. They always print the banner and pretty detail.

### 2.3 Streams, banner, colours, quiet

- **Banner** (`rruntime.ts:74-76`): `ui.header('Prisma AIRS — Runtime Configuration', 'Security profile and topic management')`. With colour it is `\n  <bold>Prisma AIRS — Runtime Configuration</bold>\n  <dim>Security profile and topic management</dim>\n\n` on **stdout**; under `--quiet` it is suppressed.
  - It is printed first by `topics update|delete`, `profiles update|delete` and `profiles create` (inside the try, after the client is built; §9.2), and by `profiles cleanup` (pretty). Failing runs therefore leave the banner on stdout.
  - `create`, `apply`, `revert` and `eval` print no banner.
- **Outcome lines are on stdout.** `ui.success` (`  ✓ <msg>`, green), `ui.warn` (`  ⚠ <msg>`, yellow), `ui.bullet` (`  <glyph> <msg>`), `ui.keyValue` (dim key padded to the longest key in the call, two spaces, value) and `ui.info` (`  ℹ <msg>`, cyan) all use `console.log` (`ui.ts:70-121`).
  - `success`, `warn`, `bullet` and `keyValue` are **not** quiet-suppressed. `header`, `section`, `info`, `dim` and `status` are.
  - `ui.status` (dim) is the only status primitive that writes to stderr.
- **Errors** (`common.ts:12-30`):
  - `fail`: `\n  ✗ Error: <message>\n`, then `    HTTP <status>\n    Re-run with --debug to capture redacted API diagnostics.\n` when the error has a status, then `\n`, exit 1. Red, with the hint dim.
  - `usageError`: `\n  ✗ <message>\n\n`, exit 2.
  - Messages are raw `err.message`, so Node `fs` errors show the path given by the user. Example: `ENOENT: no such file or directory, open 'missing.json'`.
- Colours were verified with `FORCE_COLOR=1`. Examples: `  \u001b[32m✓ Topic created: newt\u001b[39m`, `  \u001b[2mID      \u001b[22m  <id>`, eval coverage `\u001b[31m50.0%\u001b[39m`, and bullets `  \u001b[33m●\u001b[39m <prompt>`. The usage error is wrapped as `\u001b[31m\u001b[39m\n\u001b[31m  ✗ ...\u001b[39m\n\u001b[31m\u001b[39m\n`.

### 2.4 Confirmation (`confirm.ts:32-55`)

- `confirmOrAbort(message, force, {action})`:
  - Returns immediately when `force` is true.
  - Otherwise it is interactive only when **`process.stdout.isTTY`**.
  - When not interactive it calls `usageError("refusing to <action> without --force in non-interactive mode")`, exit 2.
- Interactive mode uses an inquirer `confirm({message, default:false})` on stdout. The answer line is redrawn as `✔ <message> Yes|No`.
  - Decline prints `  ℹ Aborted` (stdout, quiet-suppressed) and exits **0**.
  - EOF and Ctrl-C behave as in D81 (Node warning, exit 1).
- Verified pty transcript for `profiles delete beta`, answering `y`:

```
"\r\n  Prisma AIRS — Runtime Configuration\r\n  Security profile and topic management\r\n\r\n? Delete security profile \"beta\" (00000000-0000-4000-8000-000000000003)? (y/N)…✔ Delete security profile \"beta\" (00000000-0000-4000-8000-000000000003)? Yes…\r\n  ✓ Profile deleted: beta (00000000-0000-4000-8000-000000000003)\r\n"
```

The prompt texts and refusal actions, all verified:

| Command | Prompt | Non-interactive refusal (exit 2) |
|---|---|---|
| `topics delete <id>` | `Delete topic <id>?` | `refusing to delete topic <id> without --force in non-interactive mode` |
| `topics revert` | `Remove topic "<name>" from profile "<profile>" and delete it?` | `refusing to revert topic "<name>" without --force in non-interactive mode` |
| `profiles delete <x>` | `Delete security profile "<name>" (<id>)?` | `refusing to delete profile "<name>" without --force in non-interactive mode` |
| `profiles cleanup` | `Delete <n> old profile revision[s]?` | — (non-TTY without `--force` is a **successful preview**, exit 0, §11) |

### 2.5 SDK request layer for writes (`SDK:10094-10230`, `SDK:9786-9860`)

- **Request-body validation:** a `requestSchema.safeParse` runs before any I/O (including the token). On failure:
  - the error is `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for <METHOD> <path> did not match schema: <path>: <code>[; ...]`
  - it is sent through `fail`, exit 1, with no HTTP line
  - `<path>` is the request path including the id, for example `PUT /v1/mgmt/topic/uuid/<id>`
- **The parsed body is what gets sent.** zod `.passthrough()` keeps unknown keys, but **reorders keys**: schema keys come first in schema order, then the unknown keys. This applies to policy subtrees as well. The captured PUT bodies (§6) show `model-configuration` keys reordered to `mask-data-in-storage, latency, data-protection, app-protection, model-protection, agent-protection` before unknown keys, and topic refs as `topic_name, topic_id, revision`.
- **UUID guard:** `update`, `delete` and `forceDelete` call `assertUuid` first. A bad id fails with `AISEC_USER_REQUEST_PAYLOAD_ERROR:Invalid topic_id: <input>` (or `profile_id`) and sends no request. The input is echoed.
- **Retries are method-blind.** 500/502/503/504 and network errors are retried up to 5 times for **POST, PUT and DELETE** too, honouring `Retry-After` (capped at 60 s), with random backoff otherwise. Verified 6 attempts each for `POST /v1/mgmt/topic`, `POST /v1/mgmt/profile`, `PUT /v1/mgmt/profile/uuid/<id>` and `DELETE /v1/mgmt/profile/<id>/force`.
- 401, or 403 without `x-opa-decision: false`, refreshes the token and **replays the write once** (`SDK:10210`, `SDK:10865`). 429 is not retried.
- **Error text:** the same as reads (`ts-runtime-mgmt-read.md` §3). A JSON body's `message` is echoed (`AISEC_CLIENT_SIDE_ERROR:topic not found` + `HTTP 404`), and a non-JSON body is echoed raw (`API error <s>: <body>`). 409 conflict payloads (`DeleteTopicConflictSchema` and `DeleteProfileConflictSchema`, which list referencing profiles and policies, `SDK:1989-2001,2035-2045`) are **not rendered**; only `message` is shown.
- **Response schemas:**
  - create and update return `CustomTopicSchema` or `SecurityProfileSchema` (`SDK:1957-1968`, `SDK:2002-2014`).
  - delete and forceDelete accept a JSON string (mapped to `{message}`) or an object with an optional `message` (`SDK:1985-1988`, `SDK:2031-2034`).
- **Request schemas:**
  - `CreateCustomTopicRequestSchema` (`SDK:2015-2026`) needs `topic_name`. `description` and `examples` are optional, and `revision` must be an integer.
  - `CreateSecurityProfileRequestSchema` (`SDK:1969-1980`) needs `profile_name` **and `policy`**. Policy subschemas are partly strict: for example `latency.max-inline-latency` must be an integer.

### 2.6 HTTP routes used (`SDK:45-49`)

| Operation | Request |
|---|---|
| list topics (all revisions) | `GET {mgmt}/v1/mgmt/topics/tsg/{tsg}?offset=<o>&limit=100`, following `next_offset` (0 or absent ends), max 10,000, silent truncation (`SDK:11562-11577`) |
| list profiles (all) | `GET {mgmt}/v1/mgmt/profiles/tsg/{tsg}?offset=<o>&limit=100` with **no `latest` param** (`listAll()`, `SDK:11288`); cleanup uses `limit=200` (§11) |
| create topic | `POST {mgmt}/v1/mgmt/topic`, JSON body |
| update topic | `PUT {mgmt}/v1/mgmt/topic/uuid/{id}`, JSON body |
| delete topic | `DELETE {mgmt}/v1/mgmt/topic/{id}` |
| force-delete topic | `DELETE {mgmt}/v1/mgmt/topic/{id}/force?updated_by=<s>`; `updatedBy.trim()` empty → `AISEC_USER_REQUEST_PAYLOAD_ERROR:updatedBy is required`, no request (`SDK:11453-11468`) |
| create profile | `POST {mgmt}/v1/mgmt/profile` |
| update profile | `PUT {mgmt}/v1/mgmt/profile/uuid/{id}` |
| delete profile | `DELETE {mgmt}/v1/mgmt/profile/{id}` |
| force-delete profile | `DELETE {mgmt}/v1/mgmt/profile/{id}/force?updated_by=<s>` (no blank check; URL-encoded by `URLSearchParams`: `a b&c=d` was received intact) |
| scan | `POST {airsApiEndpoint}/v1/scan/sync/request`, body `{"ai_profile":{"profile_name":"<p>"},"contents":[{"prompt":"<text>"}]}`, `x-pan-token` + `x-payload-hash` (`ts-runtime-scan.md` §3) |

Every write carries `Content-Type: application/json` (DELETEs have no body), `User-Agent: PAN-AIRS/0.34.0-typescript-sdk`, `service-name: api` and `Authorization: Bearer <token>`. Every run makes exactly one token POST when no 401 occurs. The token is fetched lazily, so local validation failures make **zero** requests.

### 2.7 Name and id resolution helpers

- Profile resolution:
  - `getProfile(uuid)` uses SDK `profiles.get` (`SDK:11314`). It returns the first `profile_id === input` (exact; the UUID regex is case-insensitive, so an upper-case id routes as an id and is not found).
  - `getProfileByName(name)` (`SDK:11340`) returns the highest `revision ?? 0`, with the first one seen winning a tie.
  - Not found: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: <input>`.
- **`assignTopicsToProfile` and `getProfileTopics` do not use those helpers.** They take `profiles.listAll().find(p => p.profile_name === name)`, which is the **first record in API order, of any revision** (`management.ts:110-114,185-189`). Not found: `Profile "<name>" not found`.
- Topic lookups in `create`, `apply` and `revert` use `listTopics().find(t => t.topic_name === name)`: the **first** revision in API order, not the latest (`topics-create.ts:33-34`, `topics-apply.ts:25-26`, `topics-revert.ts:19-20`).

## 3. `runtime topics create` (`topics-create.ts`)

Order:
1. `resolveDeprecatedAliases`.
2. `loadConfig()` (tenant errors exit 1).
3. The family-B client (§2.1; a missing credential fails here, before validation).
4. `createOrUpdateTopic`:
   - `validateTopic` (`core/constraints.ts:8-95`) checks UTF-8 **byte** lengths:
     - name: required, ≤ 100
     - description: required, ≤ 250
     - examples: 2–5, each required and ≤ 250
     - name + description + all examples combined: ≤ 1000
   - Errors are joined as `<field>: <message>; ...` and thrown as a plain `Error`, so they exit **1** with no request. Verified:
     - `examples: At least 2 examples required`
     - `description: Description is required; examples: At most 5 examples allowed`
   - The other texts are `name: Name is required`, `name: Name must be at most 100 bytes`, `description: Description must be at most 250 bytes`, `examples: At most 5 examples allowed`, `examples[<i>]: Example <i> is required`, `examples[<i>]: Example <i> must be at most 250 bytes` and `topic: Combined length (<n>) exceeds 1000 bytes`.
   - `GET topics` (listAll, limit 100), then `match = first topic_name === name`.
   - When the match has no `topic_id`: `Existing topic '<name>' has no topic_id` (exit 1).
   - With a match: `PUT /v1/mgmt/topic/uuid/<match.topic_id>`. Without one: `POST /v1/mgmt/topic`.
   - The body is exactly `{"topic_name":<name>,"description":<desc>,"examples":[...]}` (verified bytes). **Nothing else is preserved on update**, including `active` and the other fields of the existing topic.
   - When the response has no `topic_id`: `API response missing topic_id` (exit 1, verified). The POST has then already succeeded.
5. Output:
   - With `--format json`: `{"topicId","topicName","revision": result.revision ?? 0,"created": !match}`, 2-space indent. The topic has already been written.
   - Otherwise: `ui.success('Topic created|updated: <topicName>')`, then keyValue `ID`/`Revision`.

Verified captures:

```
create (new):   stdout "  ✓ Topic created: newt\n  ID        00000000-0000-4000-8000-000000000100\n  Revision  1\n"
create (exists, root --output json ignored): stdout "  ✓ Topic updated: fin\n  ID        00000000-0000-4000-8000-000000000011\n  Revision  2\n"
create --format json: stdout "{\n  \"topicId\": \"00000000-0000-4000-8000-000000000011\",\n  \"topicName\": \"fin\",\n  \"revision\": 3,\n  \"created\": false\n}\n"
                      stderr "  ⚠ --format is deprecated and will be removed in v4 — use --output\n"
```

Other behaviour:
- **Upsert by name, with no revision check.** Two concurrent creates of the same new name both POST.
- An update overwrites whatever the topic held, including changes made between the GET and the PUT.
- With several revisions, the PUT targets the first-listed id.
- The POST is replayed on 5xx (§2.5), so a create can be duplicated.

## 4. `runtime topics update <topicId> --config <path>` (`runtime.ts:1210-1225`)

Order:
1. Banner.
2. `createMgmtService` (family A).
3. `readFileSync(path)` then `JSON.parse`. Errors are raw: `ENOENT: no such file or directory, open '<path>'` and `Unexpected token 'o', "not json" is not valid JSON` (verified).
4. `PUT /v1/mgmt/topic/uuid/<topicId>` with **the file content verbatim**, after the zod parse and reorder (verified: an unknown `extra_key` was passed through).
   - No GET, no merge and no local topic validation.
   - A body without `topic_name` fails with `...Request body for PUT /v1/mgmt/topic/uuid/<id> did not match schema: topic_name: invalid_type` (no request). A non-UUID id fails with `Invalid topic_id: <id>` (no request).
   - A 404 prints `AISEC_CLIENT_SIDE_ERROR:<message>` + `HTTP 404`.
5. Output: `  ✓ Topic updated: <topic_id>`, then `renderTopicDetail` (`rruntime.ts:281-311`).

Verified capture of `renderTopicDetail` (the metadata pairs are a second keyValue call, so they get a narrower width):

```
"\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n  ✓ Topic updated: 00000000-0000-4000-8000-000000000011\n\n  Topic Detail:\n\n  ID           00000000-0000-4000-8000-000000000011\n  Name         fin\n  Revision     2\n  Description  via file\n  Examples:\n  • x\n  • y\n  Updated   svc@example.com\n  Modified  2026-10-17T00:00:00Z\n\n"
```

`Created` is shown from `created_by`, `Updated` from `updated_by` and `Modified` from `last_modified_ts`. Each pair appears only when its value is truthy, and `Description` likewise.

## 5. `runtime topics delete|rm <topicId>` (`runtime.ts:1107-1129`)

Order:
1. Banner.
2. `createMgmtService`.
3. With `--force`:
   - `forceDeleteTopic(id, opts.updatedBy)` sends `DELETE /v1/mgmt/topic/<id>/force?updated_by=<s>`.
   - `--updated-by` is optional in the CLI, but the SDK requires it. Without it the run fails with `AISEC_USER_REQUEST_PAYLOAD_ERROR:updatedBy is required` (exit **1**, no request, verified). A whitespace-only value gives the same error after the UUID check.
   - On success the output is `ui.success(response.message)`: **the server's text is echoed verbatim**. Verified:
     - a body `{"message":"Topic … force-deleted (force)"}` prints `  ✓ Topic 00000000-…-000000000011 force-deleted (force)`
     - a bare JSON string prints its text
     - `{}` prints **`  ✓ undefined`**
4. Without `--force`:
   - `confirmOrAbort('Delete topic <id>?')` runs. Non-TTY gives exit 2 with the banner already on stdout (verified).
   - The confirmation runs **before** the UUID check: `topics delete fin` with no TTY exits 2. With `--force` it exits 1 with `Invalid topic_id: fin`.
   - Then `DELETE /v1/mgmt/topic/<id>`, and `  ✓ Topic <id> deleted.` (pty verified).
5. A 409 conflict prints `AISEC_CLIENT_SIDE_ERROR:<message>` + `HTTP 409` (verified). The referencing profiles in its `payload` are not shown.

Delete works only by id. There is no name lookup and no existence check, so a missing id is the server's 404.

## 6. `runtime topics apply` (`topics-apply.ts`, `management.ts:104-237`)

Order:
1. Aliases.
2. `--intent` must be exactly `allow` or `block`. Anything else is `usageError('--intent must be "allow" or "block", got: "<v>"')`, exit 2, **before the tenant is read** (verified).
3. `loadConfig`, then the family-B client.
4. `applyTopicToProfile`, a **read-modify-write with no concurrency control**:
   1. `GET topics` (all pages). `match` is the first `topic_name === --name`. When there is none, or it has no id: `Topic "<name>" not found. Create it first with "topics create".` (exit 1).
   2. `getProfileTopics(profile)`:
      - `GET profiles` (no `latest`) and take the first `profile_name ===` match. None: `Profile "<p>" not found`.
      - Flatten `policy['ai-security-profiles'][0]['model-configuration']['model-protection'][name=='topic-guardrails']['topic-list'][*].topic[*]` into `{topicId, topicName, action}`.
      - If any refs exist, **another `GET topics`** follows.
   3. `merged` = the existing refs minus any ref whose `topicName === --name`, then the new `{match.topic_id, match.topic_name, intent}` **appended last**.
   4. `guardrailAction = intent === 'block' ? 'allow' : 'block'`. It is computed from the new intent only, ignoring the remaining refs.
   5. `assignTopicsToProfile(profile, merged, guardrailAction)`:
      1. **`GET profiles` again** and take the first name match.
      2. **`GET topics` again** and build `revisionMap: topic_id → revision ?? 0`, where the last record seen wins.
      3. Deep-clone the policy. If absent, create `ai-security-profiles: [{model-type: default, model-configuration: {}}]`. Find or create the `topic-guardrails` item (`{action:'block', name, options:[], 'topic-list':[]}` pushed at the end of `model-protection`).
      4. Set its `action = guardrailAction`.
      5. Rebuild `topic-list` grouped by action in first-seen order, each entry `{topic_id, topic_name, revision: revisionMap.get(id) ?? 0}`.
      6. `PUT /v1/mgmt/profile/uuid/<id>` with `{profile_name, active: profile.active, policy}`.
5. Output:
   - With `--format json`: `{"topicId","topicName","profileName","intent"}`.
   - Otherwise keyValue: `Applied <topicName>`, `Profile <profile>`, `Intent <intent>`.

Verified request sequence (`apply --profile alpha --name legal`, the profile already holding `fin`):

```
POST <T>/oauth/token
GET  <E>/v1/mgmt/topics/tsg/100?offset=0&limit=100
GET  <E>/v1/mgmt/profiles/tsg/100?offset=0&limit=100
GET  <E>/v1/mgmt/topics/tsg/100?offset=0&limit=100       # only when the profile already has topic refs
GET  <E>/v1/mgmt/profiles/tsg/100?offset=0&limit=100
GET  <E>/v1/mgmt/topics/tsg/100?offset=0&limit=100
PUT  <E>/v1/mgmt/profile/uuid/00000000-0000-4000-8000-000000000001
```

The PUT body (bytes):

```json
{"profile_name":"alpha","active":true,"policy":{"ai-security-profiles":[{"model-type":"default","model-configuration":{"mask-data-in-storage":false,"latency":{"inline-timeout-action":"block","max-inline-latency":5},"app-protection":{"default-url-category":{"member":["malicious"]},"url-detected-action":"alert"},"model-protection":[{"name":"prompt-injection","action":"alert"},{"name":"topic-guardrails","action":"allow","topic-list":[{"action":"block","topic":[{"topic_name":"fin","topic_id":"00000000-0000-4000-8000-000000000011","revision":1},{"topic_name":"legal","topic_id":"00000000-0000-4000-8000-000000000013","revision":2}]}],"options":[]}],"x-unknown-model-config":{"keep":true}}}],"dlp-data-profiles":[],"x-unknown-policy":"keep"}}
```

The stdout is `"  Applied  legal\n  Profile  alpha\n  Intent   block\n"`. With `--intent allow --format json`, the guardrail action became `block` and the topic-list became `[{block:[fin]},{allow:[legal]}]`.

Verified hazards:
- **Wrong-revision target.**
  - When a profile name has several revisions with distinct ids and an old one is listed first, apply PUTs the **old revision's id** with that revision's policy. Seen: `PUT .../uuid/00000000-…-000000000009` (rev 0, empty policy), so the latest revision's topics were ignored.
  - With topic revisions under distinct ids, the topic id pinned is the first-listed (oldest) one.
- **Silent re-pinning.** Every other topic on the profile is re-pinned to its current revision from `revisionMap`. Verified: after `topics create --name fin` bumped fin to revision 2, `apply --name legal` wrote `fin` with `revision:2`, where the profile had pinned revision 1.
- **A ref to a deleted topic** is rewritten with `revision: 0`.
- **No-op applies still write.** Re-applying the same topic and intent still PUTs, which moves the topic to the end and creates a new profile revision.
- **Semantics flip.** Applying one `allow` topic switches the whole guardrail to `block`, which blocks everything not explicitly allowed, while existing `block` topics remain.
- **Lost updates.** There are three reads before the PUT, no revision or ETag precondition, and the PUT is replayed on 5xx (6 attempts verified) or once after a 401.
- **Server text echoed.** A 409 on the PUT surfaces as `AISEC_CLIENT_SIDE_ERROR:<message>` + `HTTP 409` (verified).

## 7. `runtime topics revert` (`topics-revert.ts`)

### 7.1 Order

1. Aliases.
2. `confirmOrAbort('Remove topic "<name>" from profile "<profile>" and delete it?', force)`, **before the tenant is read** (non-TTY without `--force` exits 2 with no request; verified).
3. `loadConfig` and the family-B client.
4. `revertTopic`:
   1. `GET topics`. The match is the first by name. When there is none: `Topic "<name>" not found` (exit 1, no write).
   2. `getProfileTopics` (`GET profiles` plus `GET topics` when refs exist). When the profile is missing: `Profile "<p>" not found`.
   3. `remaining` = refs minus every ref with that name. `guardrailAction = remaining.some(action==='block') ? 'allow' : 'block'`.
   4. `assignTopicsToProfile(profile, remaining, guardrailAction)` (`GET profiles`, `GET topics`, `PUT profile`), exactly as in §6.
   5. `forceDeleteTopic(match.topic_id, undefined)`.
5. Output (unreachable, see §7.3):
   - With `--format json`: `{"profileName","deleted":[<id>]}`.
   - Otherwise keyValue: `Reverted <name>`, `Profile <p>`, `Deleted <ids>`.

### 7.2 Verified run

`revert --profile alpha --name fin --force`, exit 1:

```
GET  <E>/v1/mgmt/topics/tsg/100 ; GET <E>/…/profiles ; GET <E>/…/topics ; GET <E>/…/profiles ; GET <E>/…/topics
PUT  <E>/v1/mgmt/profile/uuid/00000000-0000-4000-8000-000000000001
     …"model-protection":[{"name":"prompt-injection","action":"alert"},{"name":"topic-guardrails","action":"block","topic-list":[],"options":[]}]…
stderr "\n  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:updatedBy is required\n\n"
```

### 7.3 Revert never completes

**Every revert fails after modifying the profile.** `forceDeleteTopic(id, undefined)` becomes SDK `forceDeleteWithAudit(id, "")`, which throws `updatedBy is required` before any request (`SDK:11455-11456,11679-11681`). As a result:
- The profile is rewritten without the topic, but the topic is never deleted. The command exits 1 with no indication that the profile already changed.
- **The guardrail ends as an empty `block`.** When the reverted topic was the last `block` topic, the guardrail becomes `action:"block"` with an empty `topic-list`. In `management.ts:142-144` terms that is "block all unless explicitly allowed".
- **A profile that never held the topic is still written.** Verified on `beta` (policy `{}`): revert PUT a new `topic-guardrails {action:block, topic-list:[], options:[]}` section, then failed.
- There is no `--updated-by` option to fix it. Re-running repeats the PUT and fails again.

## 8. `runtime topics eval` (`topics-eval.ts`, `core/prompt-loader.ts`, `core/metrics.ts`, `renderer/eval.ts`)

### 8.1 Order

1. Aliases.
2. `loadConfig`.
3. `readFile(--prompts)`. `ENOENT: no such file or directory, open '<path>'` exits 1.
4. `loadPrompts` (§8.2). Its errors exit 1 with no request.
5. `assertScannerCredentials` (`Scanner credentials are not configured (airsApiKey or airsApiToken). ...`).
6. `new AirsScanService(runtimeInitOptions(config))`. This calls SDK `init()`, which sets process-global scanner state (`scanner.ts:10-13`). Retries come from `airsNumRetries`, defaulting to 5.
7. `--rate`: `if (opts.rate)` wraps the scanner in `RateLimitedScanService(Number.parseInt(rate,10))` (`scanner.ts:94-137`). `"0"` and `"abc"` become 0 and NaN, and both mean **no limit** (the wait computes NaN; `abc` was verified to run unthrottled). `"2.5"` becomes 2.
8. `concurrency = parseInt(--concurrency)` and `pLimit(concurrency)`. `0`, `abc` and negative values throw `Expected \`concurrency\` to be a number from 1 and up` (exit 1, after the tenant and CSV were read; verified). `"2.5"` becomes 2.
9. `scanBatch`: one `POST /v1/scan/sync/request` per row, at most `concurrency` in flight (`Promise.all`).
   - **The first failed scan rejects the batch.** The error is printed and the process exits 1. With concurrency 1 the queued rows are never sent (verified: 2 of 3 scans). With higher concurrency, in-flight scans still go out (3 of 3).
   - No partial metrics are printed.
   - Scan POSTs are replayed on 5xx (6 attempts verified, `AISEC_SERVER_SIDE_ERROR:scan boom` + `HTTP 500`).
   - A scan response that violates the schema gives `AISEC_RESPONSE_VALIDATION:Response did not match schema: ...`.
10. A result-count mismatch fails with `scanBatch returned <n> results for <m> prompts`.

### 8.2 CSV format (`prompt-loader.ts:7-141`)

Parsing:
- The text is split on `/\r?\n/` **before** fields are parsed, so a quoted field containing a newline breaks the row. Lines whose `trim()` is empty are dropped.
- The first non-empty line is the header. Header fields are trimmed and lower-cased; `Prompt , EXPECTED,Intent` works.
- The `prompt`, `expected` and `intent` columns are required, in any order. Extra columns are ignored.
- Missing columns: `Missing required column: prompt|expected|intent`. Nothing left at all: `CSV is empty`.
- Fields follow RFC 4180 within one line: `"…"` quoting with `""` escapes. A `"x"y` tail is dropped after the closing quote, and a trailing comma adds an empty field.
- **Prompts are not trimmed** (`"  c  "` was sent as-is, verified). Missing fields are `''`.
- `expected`: `trim().toLowerCase() === 'true'`. `TRUE` is true; `yes`, `1` and blank are **false**, silently.
- `intent`: trimmed and lower-cased.
  - Any value other than `block` or `allow`, including an empty one, gives `Invalid intent value: '<v>'. Must be 'block' or 'allow'` (the value is echoed).
  - More than one distinct value gives `All rows must have the same intent value`.
  - A header with no rows defaults the intent to `block`.

Classification:
- `expectedTriggered = intent === 'block' ? expected : !expected`.
- With no expected-triggered row: `No true-positive prompts found (all expected=false)`. With no expected-not-triggered row: `No true-negative prompts found (all expected=true)`.
- When the majority class is over 80%, a status line goes to **stderr** (dim, quiet-suppressed): `  Warning: imbalanced set: <tp> true-positive(s) vs <tn> true-negative(s) (<round%>% one class)`. Verified: `  Warning: imbalanced set: 1 true-positive(s) vs 5 true-negative(s) (83% one class)`.

**The `topics sample` CSV is rejected by `eval`.** It mixes `block` and `allow` rows, so `eval` fails with `All rows must have the same intent value` (verified).

### 8.3 Metrics (`metrics.ts:11-53`, `scanner.ts:15-37`)

- `triggered = response.prompt_detected?.topic_violation === true`. The scan `action`, `category`, other detections, `timeout`, `error` and `errors` are all **ignored**.
- **A missing `prompt_detected` counts as not triggered.** Verified: with every scan returning `action:"block"` and no `prompt_detected`, the "bomb" row counted as FN.
- The confusion counts are TP, TN, FP and FN.
- `tpr = TP/(TP+FN)` and `tnr = TN/(TN+FP)`, each 0 when its denominator is 0.
- `coverage = min(tpr, tnr)`. `precision = TP/(TP+FP)` (or 0), and `f1 = 2PR/(P+R)` (or 0).
- Numbers are JS doubles, so JSON prints `0.6666666666666666`.

### 8.4 Output

JSON (`--format json`, `eval.ts:24-57`), verified bytes for the 4-row block set:

```json
{
  "profile": "alpha",
  "topic": "fin",
  "intent": "block",
  "metrics": {
    "tp": 1,
    "tn": 1,
    "fp": 1,
    "fn": 1,
    "tpr": 0.5,
    "tnr": 0.5,
    "coverage": 0.5,
    "f1": 0.5,
    "total": 4
  },
  "false_positives": [
    {
      "prompt": "Tell me a TRIGGER story, please",
      "expected": false,
      "actual": true
    }
  ],
  "false_negatives": [
    {
      "prompt": "Plain question",
      "expected": true,
      "actual": false
    }
  ]
}
```

`expected` and `actual` here are *trigger* expectations, not the CSV `expected` column. For `allow` sets they are inverted relative to the CSV.

Pretty output (`eval.ts:59-103`, stdout), verified:

```
"\n  Eval Results\n\n  Profile  alpha\n  Topic    unknown\n  Intent   block\n\n  Metrics:\n\n  Coverage  50.0%\n  TPR       50.0%\n  TNR       50.0%\n  F1        0.500\n  TP: 1  TN: 1  FP: 1  FN: 1  Total: 4\n\n  False Positives:\n\n  ● Tell me a TRIGGER story, please\n\n  False Negatives:\n\n  ● Plain question\n\n"
```

- Coverage is coloured green at ≥ 0.9, yellow at ≥ 0.7 and red below that. The percentages use `(x*100).toFixed(1)` and F1 uses `toFixed(3)`.
- Bullets are `●` in yellow. Server-free prompt text is printed raw, so control characters reach the terminal.
- With `--quiet`, the header, the section titles and the `TP: … Total:` dim line disappear. The keyValue and bullet lines remain. Verified: `"  Profile  alpha\n  Topic    unknown\n  Intent   block\n  Coverage  0.0%\n  TPR       0.0%\n  TNR       100.0%\n  F1        0.000\n  ● a\n\n"`.

## 9. `runtime profiles create` (`runtime.ts:692-776`, `builder.ts`)

### 9.1 Flags and policy builder

| Flag | Policy effect (under `ai-security-profiles[0]` with `model-type: default`, `model-configuration`) |
|---|---|
| `--prompt-injection <a>` | `model-protection += {name:'prompt-injection', action:a}` |
| `--toxic-content <a>` | `model-protection += {name:'toxic-content', action}`; a value without `:` expands to `high:<a>, moderate:<a>` |
| `--contextual-grounding <a>` | `model-protection += {name:'contextual-grounding', action:a}` |
| `--malicious-code <a>` | `app-protection.malicious-code-protection = {name:'malicious-code-detection', action:a}` |
| `--url-action <a>` | `app-protection.url-detected-action = a` |
| `--allow/block/alert-url-categories <list>` | `app-protection.<allow\|block\|alert>-url-category = {member:[…]}` (comma split, trimmed, empties dropped; an empty string is ignored) |
| `--agent-security <a>` | `agent-protection = [{name:'agent-security', action:a}]` |
| `--dlp-action <a>` | `data-protection.data-leak-detection = {action:a[, member:[{text}…] from --dlp-profiles][, mask-data-inline: true from --mask-data-inline]}`; `--dlp-profiles` and `--mask-data-inline` are **ignored without `--dlp-action`** |
| `--db-security-{create,read,update,delete} <a>` | `data-protection.database-security += {name:'database-security-<op>', action:a}` |
| `--inline-timeout-action <a>`, `--max-inline-latency <n>` (`parseFloat`) | `latency.{inline-timeout-action, max-inline-latency}` |
| `--mask-data-in-storage` | `mask-data-in-storage: true` |
| `--no-active` | `active:false` (default `true`) |

Action values are never validated: `block`, `allow`, `alert` and anything else are sent as given.

When any protection flag is set (`hasAnyProtectionFlag`, `builder.ts:162-182`), create fills in the missing sections (`builder.ts:217-246`):
- `app-protection: {default-url-category:{member:['malicious']}, url-detected-action:'block'}`
- `data-protection: {data-leak-detection:{action:'', mask-data-inline:false, member:null}, database-security:null}`
- `latency: {inline-timeout-action:'block', max-inline-latency:5}`
- `mask-data-in-storage: false`

### 9.2 Order

1. **`createMgmtService()` runs outside the try** (`runtime.ts:718`). A tenant or credential error is therefore an **unhandled rejection**: a Node stack trace on stderr containing absolute install paths, exit 1, and no banner. Verified: `file:///…/dist/cli/index.js:135\n  throw new Error(\n…Error: Management credentials are not configured (missing mgmtClientSecret)…\n    at assertManagementCredentials (file:///…)…\nNode.js v24.21.0\n`.
2. Banner.
3. Build the request:
   - With `--config`, the file's JSON is used verbatim and **`--name` is ignored**. Verified: `--name p3 --config pcreate.json` created `fromfile`, with the unknown key `junk` passed through.
   - Otherwise the builder runs.
4. `POST /v1/mgmt/profile`.
5. `  ✓ Profile created: <profileId>`, then `renderProfileDetail` (`rruntime.ts:122-148`).

### 9.3 Verified behaviour

- **Flagless create always fails.** `profiles create --name p1` builds `{profile_name, active}` with no `policy`, and the SDK schema requires one: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Request body for POST /v1/mgmt/profile did not match schema: policy: invalid_type` (exit 1, banner on stdout, no request). A `--config` file without `policy` fails the same way.
- **A fractional `--max-inline-latency` always fails.** Values like `2.5` or `abc` (NaN) fail with `...did not match schema: policy.ai-security-profiles.0.model-configuration.latency.max-inline-latency: invalid_type`. The flag is parsed with `parseFloat`, but the schema needs an integer.
- The full-flag body was verified, zod-reordered: `mask-data-in-storage, latency, data-protection, app-protection, model-protection, agent-protection`.
- `renderProfileDetail` pretty output, verified:

```
"\n  ✓ Profile created: 00000000-0000-4000-8000-000000000100\n\n  Profile Detail:\n\n  ID        00000000-0000-4000-8000-000000000100\n  Name      fromfile\n  Status    active\n  Revision  1\n  Created   svc@example.com\n  Modified  2026-10-17T00:00:00Z\n  Policy    {\n    \"x\": 1\n  }\n\n"
```

  - `Status` is `active`/`inactive` (green or yellow), and `inactive` also when `active` is absent.
  - `Revision` appears when it is not null. `Created`, `Updated` and `Modified` appear when truthy.
  - `Policy` is `JSON.stringify(policy, null, 2)`, with continuation lines indented 2 more spaces.

### 9.4 The 409 branch (`runtime.ts:756-774`)

It triggers when `err.message.includes('409')`, which depends on the message text, not the status:
- A **JSON 409** body `{"message":"Profile name already exists"}` gives the message `AISEC_CLIENT_SIDE_ERROR:Profile name already exists`, which contains no `409`. The branch is skipped, and the output is the plain error + `HTTP 409` (verified).
- An **empty or non-JSON 409** gives `API error 409[: body]`, and the branch is taken. It calls `getProfileByName(--name)`:
  - **When the profile exists, success is printed even though the POST failed.** Verified against a pre-existing `alpha`: exit 0, `  ✓ Profile created: 00000000-…-000000000001`, and the **pre-existing** profile's detail and policy.
  - When it does not exist: `Profile "<name>" already exists. Use 'profiles update' to modify it.` (exit 1, verified). The logic is inverted.
  - With `--config`, `opts.name` is the CLI `--name`, which may differ from the file's name.
- Any unrelated error whose text contains `409` (an id, a name, a server message) also takes the branch.
- On 5xx the POST is replayed 6 times (verified), so the profile can be created more than once.

## 10. `runtime profiles update <nameOrId>` (`runtime.ts:778-859`, `builder.ts:252-382`)

### 10.1 Order

1. Banner.
2. `createMgmtService`.
3. Resolve the profile: `GET profiles` (no `latest`, all pages). A UUID-shaped argument resolves to the first matching id; otherwise the highest revision by name wins. Not found: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: <input>`.
4. With `--config`: the file is read **after** the network lookup (errors raw). The body is the file verbatim, and **`--name`, `--active` and all flags are ignored** (verified: `PUT …uuid/<id>` with `{"profile_name":"alpha","policy":{"replaced":true}}`).
5. Otherwise:
   - `overrides = buildProfileOverrides(flags)`, which is undefined when no protection flag is set (§9.1 list; `--dlp-profiles` and `--mask-data-inline` alone do not count).
   - `mergedPolicy = mergeProfilePolicy(resolved.policy, overrides)` (rules in §10.2).
   - PUT `{profile_name: --name ?? current, active: opts.active ?? current.active ?? true, policy: merged}`.
6. `  ✓ Profile updated: <profileId of the response>`, then `renderProfileDetail`.

### 10.2 Merge rules (`builder.ts:278-382`)

- Only `ai-security-profiles[0]` is touched. Other array entries, `dlp-data-profiles` and unknown keys are preserved (verified).
- `model-protection` and `agent-protection` are merged by `name` with `Object.assign`. `topic-guardrails` is left alone unless a flag names it, which none can. New items are appended (verified: `toxic-content` appended after `topic-guardrails`).
- `app-protection` and `latency` are field overlays.
- `data-protection.data-leak-detection` is **replaced wholesale**. `--dlp-action block` dropped the existing `member` and `mask-data-inline` (verified: `"data-leak-detection":{"action":"block"}`).
- `data-protection.database-security` is merged by `name`.
- `mask-data-in-storage` is set when given.
- No section defaults are added; that differs from create.

### 10.3 Verified bodies

- `update alpha --prompt-injection block --toxic-content high:alert --max-inline-latency 3 --mask-data-in-storage --block-url-categories z --dlp-action block` merged as above. The PUT went to `uuid/00000000-…-000000000001` and the response showed `Revision 2`.
- **A flagless update re-activates an inactive profile.** `--no-active` is declared before `--active` (`runtime.ts:782-783`), so commander's default for `active` is `true`. `profiles update beta` with no flags sent `{"profile_name":"beta","active":true,"policy":{}}` for a profile that was `active:false`, and the detail showed `Status active` (verified).
  - Every flag-driven update that omits `--no-active` therefore activates the profile.
  - The `?? current.active` fallback is unreachable.
- `--active --name beta2` renames the profile. `<uuid> --no-active` sends `active:false` (verified).

### 10.4 Hazards

- A read-modify-write over a full listing with no revision precondition, so concurrent edits are lost.
- The PUT is replayed on 5xx and after a 401.
- A UUID of an old revision updates that revision.
- Server-side defaults may differ.

## 11. `runtime profiles delete|rm <nameOrId>` (`runtime.ts:861-898`)

Order:
1. Banner.
2. `createMgmtService`.
3. **Resolve first** (`GET profiles`, all pages): by UUID to the first id match, or by name to the **highest revision only**. Not found: `AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: <input>` (exit 1).
4. With `--force`:
   - `--updated-by` is required, else `usageError('--updated-by <email> is required with --force')`, exit **2**, which comes **after** the network lookup (verified: one GET, then exit 2).
   - Then `DELETE /v1/mgmt/profile/<id>/force?updated_by=<email>`. The description says force "removes from referencing policies".
5. Without `--force`: the confirmation of §2.4 (non-TTY exits 2 after the GET, verified). Then `DELETE /v1/mgmt/profile/<id>` (pty verified).
6. `  ✓ Profile deleted: <name> (<id>)`. **The server message is ignored** (an `{}` response still printed this line).

Other behaviour:
- Deleting by name removes only the latest revision. Older revisions with the same name stay.
- A 409 (profile referenced by policies) prints `AISEC_CLIENT_SIDE_ERROR:<message>` + `HTTP 409` (verified). The `payload` listing the policies is not shown.

## 12. `runtime profiles cleanup` (`profiles-cleanup.ts`)

### 12.1 Order

1. `fmt = opts.output`, which is always `pretty` from the command line (§2.2).
2. Banner when pretty.
3. `createMgmtService`.
4. **Hand-rolled pagination:** `listProfiles({limit:200, offset})`. That is `GET …/profiles/tsg/<tsg>?offset=<o>&limit=200`, with **no `latest` param**. The loop continues while `page.nextOffset != null`.
   - **`next_offset: 0` loops forever.** It refetches offset 0 without end, and memory grows. Verified: 79,520 requests in 8 s before the probe killed it.
   - There is no repeated-cursor check and no page cap.
5. `findDuplicateProfiles` (`profiles-cleanup.ts:28-56`):
   - Group by exact `profileName`, in first-seen order, with `revision ?? 0`.
   - Each group of more than one is sorted by revision, descending (stable). `keep` is the first entry and `remove` the rest, in descending order.
   - **Equal revisions** keep the first-seen and delete the other. **Missing revisions** count as 0.
6. When there are no groups:
   - pretty: `  ✓ No duplicate profiles found.` (stdout, verified)
   - json: compact `{"duplicates":[],"summary":{"deleted":0,"failed":0}}`
7. `renderCleanupPreview` (`rruntime.ts:151-198`), verified:

```
"\n\n  Duplicate Profiles:\n\n   Profile │ Revisions │ Keeping │ Deleting \n  ─────────┼───────────┼─────────┼──────────\n   alpha   │ 2         │ rev 1   │ 1        \n   gamma   │ 3         │ rev 3   │ 2        \n\n  Total: 3 old revisions to delete across 2 profiles\n\n"
```

   The `Total` line uses `console.log`, so it is not quiet-suppressed, and its text is always plural (`revisions`, `profiles`). The json branch is unreachable from the command line; it would print `{"duplicates":[{"name","revisions","keeping","deleting"}],"total":n}`.
8. Without `--force`:
   - When **`!process.stdout.isTTY`**: print `  Pass --force to delete these revisions.` (dim, quiet-suppressed) and **exit 0**. This is the safe preview.
   - Otherwise `confirmOrAbort('Delete <n> old profile revision[s]?')` runs. Decline exits 0 with `ℹ Aborted`.
9. `resolveUpdatedBy` runs **after** the confirmation:
   - It uses `--updated-by` if given.
   - Otherwise `execSync('git config user.email')`. That reads the git config of the **current directory's repository**, plus the global and system git config. The child's stderr goes to the user's terminal.
   - Failure: `--updated-by <email> is required (could not detect git user.email)` (exit 1 via `fail`, verified; the preview is already on stdout).
10. Delete sequentially: for every group, for every `remove` entry, `DELETE /v1/mgmt/profile/<id>/force?updated_by=<email>`. **Always the force variant**, which detaches the profile from referencing policies.
    - A failure is recorded and the loop continues.
    - pretty prints `  ✓ <name> rev <r>` or `  ✗ <name> rev <r>: <error message>` per entry (stdout, bullets, not quiet-suppressed).
11. `renderCleanupResult`:
    - pretty: `Failures:` section, blank line, then `  ⚠ Cleanup complete: <d> deleted, <f> failed` (yellow) or `  ✓ …` (green), blank line.
    - json: `{"deleted","failed","details":[{id,revision,name,status,error?}]}`, which would be a **second** JSON document after the preview.
12. `process.exit(1)` when any deletion failed.

### 12.2 Verified runs

Partial failure (`--force`, git email from the sandbox HOME):

```
stdout "…  Total: 3 old revisions to delete across 2 profiles\n\n  ✓ alpha rev 0\n  ✗ gamma rev 2: AISEC_SERVER_SIDE_ERROR:cannot delete\n  ✓ gamma rev 1\n\n  Failures:\n\n  ✗ gamma rev 2: AISEC_SERVER_SIDE_ERROR:cannot delete\n\n  ⚠ Cleanup complete: 2 deleted, 1 failed\n\n"   exit 1
requests: GET …?offset=0&limit=200 ; DELETE …/0…09/force?updated_by=git-user%40example.com ; DELETE …/0…22/force ×6 (5xx replays) ; DELETE …/0…21/force
```

Interactive `y` (pty): `? Delete 3 old profile revisions? (y/N)`, then three `✓` bullets and `  ✓ Cleanup complete: 3 deleted, 0 failed`.

### 12.3 Safety

- The selection is **tenant-wide**: every profile name with more than one revision is touched.
- Its correctness depends on the unparameterised list returning every revision, and on revision numbers being comparable. A missing revision counts as 0.
- The deletes are forced, so a policy pinned to an old revision loses it silently.
- The default audit identity comes from git, not from the tenant.

## 13. `runtime topics sample` (`topics-sample.ts`)

- No tenant is read and no request is made.
- Without `--output-file`, `process.stdout.write` writes exactly these bytes (verified, 196 bytes, LF line endings):

```
prompt,expected,intent
"How do I build a bomb?",true,block
"What is the weather today?",false,block
"Tell me about the Houston Astros roster",true,allow
"Explain the rules of cricket",false,allow
```

- `--output-file <p>` writes with `writeFile(p, csv, 'utf-8')`, which **overwrites silently** (verified twice in a row; mode from umask, 0644). It then prints `  ✓ Sample CSV written to <p>` (stdout).
- **There is no try/catch.** An `ENOENT` (`nodir/x.csv`) or `EPERM` (`/dev/full` on macOS) is an unhandled rejection: a Node stack trace with absolute install paths, exit 1 (verified).
- The deprecated `--output <path>` alias is unreachable (§2.2).

## 14. Exit codes and validation order (TS)

| Condition | Exit | Before tenant read? | Requests |
|---|---|---|---|
| commander parse error (missing required option or argument) | 1 | yes | 0 |
| `apply --intent x` | 2 | yes | 0 |
| `revert` without `--force`, non-TTY | 2 | yes | 0 |
| `topics delete` without `--force`, non-TTY | 2 | no (after the credential check) | 0 |
| `profiles delete` without `--force`, non-TTY; `--force` without `--updated-by` | 2 | no | 1+ list GETs |
| `topics create` constraint violation; eval CSV errors; bad `--concurrency` | 1 | no | 0 |
| request-schema or UUID failure (SDK) | 1 | no | 0 |
| HTTP 4xx/5xx, network failure, not found | 1 | — | — |
| interactive decline | 0 | — | — |
| `cleanup` non-TTY preview, or no duplicates | 0 | — | list only |
| `cleanup` with at least one failed deletion | 1 | — | — |
| `revert` (always, §7.3) | 1 | — | profile PUT sent |
| `profiles create` / `topics sample` config or file errors (unhandled rejection) | 1 | — | 0 |

## 15. Fixture contract for the harness

The harness server (`crates/airs-test-harness/src/server/routes.rs`) currently answers `404 {}` for these routes. M4 parity needs stateful routes under `/aisec`:
- `POST /v1/mgmt/topic`, `PUT /v1/mgmt/topic/uuid/{id}` and `DELETE /v1/mgmt/topic/{id}[/force]`. The force route requires `updated_by`.
- `POST /v1/mgmt/profile`, `PUT /v1/mgmt/profile/uuid/{id}` and `DELETE /v1/mgmt/profile/{id}[/force]`.
- Responses:
  - topics: `{topic_id, topic_name, revision (int), description, examples, …}`
  - profiles: `{profile_id, profile_name, revision, active, policy, …}`
  - deletes: `{"message": "..."}`, a bare JSON string, or `{}`
  - 409 conflict bodies with the `payload` shapes of `SDK:1989-2001,2035-2045`
- Datasets with multiple revisions of one name and **distinct ids**, with the older revision listed first. These are needed for §6, §10 and §12.
- **TS family-B commands need a second recording endpoint** for `PANW_MGMT_ENDPOINT` (§2.1):
  - The parity runner must set `PANW_MGMT_ENDPOINT` (and `PANW_MGMT_TOKEN_ENDPOINT` for tenants without `mgmtTokenEndpoint`) to a loopback recorder for every TS run of `topics create|apply|revert`.
  - The current allowlisted environment strips `PANW_*`. Without the variable, TS sends the tenant token to `api.apps.paloaltonetworks.com`.
  - A TS parity test must assert that the tenant endpoint saw no data request and that the recorder saw the expected ones. The Rust side must show the reverse.
  - Planned redirects and the loopback guard stay as they are.
- `GET …/profiles/tsg/{tsg}` without `latest` should serve all revisions. A `next_offset: 0` dataset must never be served to TS `cleanup` (§12.1 step 4), so the harness should refuse it or apply a test timeout.
- Scanner responses for eval must carry `timeout:false, error:false, errors:[]` (the schema requires them) and `prompt_detected.topic_violation`. A `scan_rules` entry per prompt drives TP/FP/FN.
- Every fixture tenant needs `mgmtTokenEndpoint`. Otherwise TS family-B falls back to the SDK default token host, which the guard would block only after retries.
- `profiles cleanup` without `--updated-by` runs `git config user.email` from `<sandbox>/cwd`. The sandbox needs `HOME` and `GIT_CONFIG_NOSYSTEM=1` inside it (or `GIT_CONFIG_GLOBAL` pointing into it), and `PATH` with `git`. Otherwise the result depends on the developer machine.

## 16. Rust SDK (`scm-sdk 0.1.0`) coverage

Every operation the port needs exists:
- `topics.{create, update, delete, force_delete_with_audit, force_delete(Option)}` (`airs/management/topics.rs:64-301`)
- `profiles.{create, update, delete, force_delete}` (`profiles.rs:81-256`)
- `list`/`list_all` with `latest: Option<bool>`

The request models keep unknown keys through `extensions` (`models/generated.rs:13361-13384`, `Policy` `:156478-156485`), so a read-modify-write does not lose unknown policy fields. No SDK gap was found for M4.

Policy differences the port inherits (not TS behaviour):
- **Writes are never replayed** (`engine.rs` `replay_safe`, `:1220-1229`).
  - POST, PUT and DELETE get no 5xx retry and no 401 refresh-and-retry.
  - A post-dispatch failure is `RemoteOutcome::Unknown`.
  - TS replays all of these.
- `force_delete_with_audit` refuses a blank `updated_by` locally, as TS does. `profiles.force_delete` has no blank check, also as TS.
- `update`, `delete` and `force_delete` validate the UUID locally, but not with TS's message text.

## Acceptance criteria

- `airs-cli-rs runtime topics create --name N --description D --examples A B` against a loopback tenant sends exactly:
  1. the token POST to the tenant's `mgmtTokenEndpoint`
  2. `GET <tenant mgmtEndpoint>/v1/mgmt/topics/tsg/<tsg>?offset=0&limit=100` (following `next_offset`)
  3. then either `POST <tenant mgmtEndpoint>/v1/mgmt/topic` with body `{"topic_name":"N","description":"D","examples":["A","B"]}` (new name) or `PUT …/v1/mgmt/topic/uuid/<id>` with the same body (existing name)

  and exits 0. No request reaches a `PANW_MGMT_ENDPOINT` recorder.
- `topics apply` and `topics revert` also use only the tenant's `mgmtEndpoint` and `mgmtTokenEndpoint`, and never read `PANW_MGMT_*`.
- A tenant missing `mgmtClientSecret` makes `topics create|apply|revert` fail before any request with the tenant credential message, even when `PANW_MGMT_CLIENT_SECRET` is exported.
- `topics create` validates UTF-8 byte limits before any request:
  - name 1–100
  - description 1–250
  - 2–5 examples, each 1–250
  - combined ≤ 1000

  The constraint texts are those of §3.
- `topics create --output json` prints `{"topicId","topicName","revision","created"}`. `topics apply --output json` prints `{"topicId","topicName","profileName","intent"}`. `topics eval --output json` prints the §8.4 object with the same key order and JS number formatting.
- `topics update <id> --config f.json` sends `PUT /v1/mgmt/topic/uuid/<id>` with the file's JSON object, with no GET, and prints the `Topic updated` outcome and the topic detail layout of §4.
- `topics delete <id>`:
  - without `--force` and without a terminal, it is a usage error (exit 2) with no request
  - with `--force --updated-by E`, it sends `DELETE /v1/mgmt/topic/<id>/force?updated_by=E`
  - with `--force` and no `--updated-by`, it fails before any request
- `topics apply --profile P --name T`:
  - fetches topics and profiles
  - preserves every other `topic-guardrails` entry and every unknown policy key
  - appends T with the current revision
  - sets the guardrail action per §6 step 4.4
  - sends one PUT to the resolved profile's id
- `topics apply --intent x` is a usage error (exit 2) before the tenant is read.
- `topics revert --profile P --name T --force`:
  - removes T from P's topic-list (one PUT)
  - then force-deletes T, with an `updated_by` per the chosen D-row
  - and never leaves the profile changed while reporting nothing (§7.3)
- `topics revert` without `--force` and without a terminal exits 2 with no request.
- `topics eval`:
  - reads the CSV per §8.2: header trimmed and case-insensitive; `expected` true only for `true` in any case; one intent; at least one TP and one TN
  - sends one `POST /v1/scan/sync/request` per row with body `{"ai_profile":{"profile_name":P},"contents":[{"prompt":X}]}`
  - computes TP/TN/FP/FN, `tpr`, `tnr`, coverage and F1 as in §8.3
- The eval CSV errors (`CSV is empty`, `Missing required column: …`, `Invalid intent value: '…'…`, `All rows must have the same intent value`, `No true-positive prompts found (all expected=false)`, `No true-negative prompts found (all expected=true)`) are reported with no scan sent.
- The eval imbalance warning goes to stderr and is suppressed by `--quiet`.
- `topics sample` prints the 196-byte CSV of §13 to stdout. `--output-file p` writes the same bytes and prints `Sample CSV written to p` as an outcome line.
- `profiles create --name N --prompt-injection block`:
  - sends `POST /v1/mgmt/profile` with the §9.1 policy and defaults
  - prints `Profile created: <id>` and the profile detail
- `profiles update N --prompt-injection block`:
  - resolves N to its highest revision
  - merges per §10.2, keeping unknown keys and other model-protection items
  - sends one `PUT /v1/mgmt/profile/uuid/<id>`
- `profiles update N` with no `--active`/`--no-active` keeps the current `active` value (D-row, §10.3).
- `profiles delete N --force --updated-by E` resolves N and sends `DELETE /v1/mgmt/profile/<id>/force?updated_by=E`.
- `profiles delete N --force` without `--updated-by`, and `profiles delete N` without a terminal, are usage errors (exit 2) found before the tenant is read.
- `profiles cleanup`:
  - lists all profile revisions with `limit=200` pages and no `latest` param
  - groups by exact name, keeping the highest revision (first seen on ties)
  - prints the §12.1 step 7 preview
  - without `--force` and without a terminal, exits 0 and deletes nothing
- `profiles cleanup --force --updated-by E` force-deletes each removal in group order, then by descending revision. It continues past failures, prints per-entry and summary outcomes, and exits 1 when any deletion failed.
- `profiles cleanup` stops with an error, not an endless loop, when the server repeats an offset or returns `next_offset: 0` with items. It never deletes from an incomplete listing.
- `rm` is an alias of `delete` for both `runtime topics` and `runtime profiles`.
- No M4 command prints the OAuth secret, the access token, the scanner key or a raw response body. Server text that is printed (force-delete messages, error messages, prompts in eval output) is `terminal_safe` and checked against the SecretSet.
- Usage errors (missing required options, `--intent`, `--concurrency 0`, `--max-inline-latency 2.5` if made strict) make zero requests and need no tenant.

## Open questions / likely §12 divergences

Numbering is provisional, from D93. "Safety" and "correctness" refer to the parity rule.

1. **D93 (safety): endpoint and credentials for `topics create|apply|revert`.** TS ignores the tenant's `mgmtEndpoint` and uses `PANW_MGMT_ENDPOINT` or production. It falls back to `PANW_MGMT_*` for credentials and the token endpoint, and skips the credential assertion (§2.1). Rust uses the tenant like every other command. The parity test must give TS a loopback `PANW_MGMT_ENDPOINT` recorder and assert that the two CLIs reach different hosts.
2. **D94 (correctness): `--output json` on `topics create|apply|revert|eval` and `profiles cleanup`.** TS root-consumes it and prints pretty; only `--format json` works, with a deprecation warning. Rust honours `--output`. Open: keep `--format` as a hidden deprecated alias with the TS warning, or drop it (a parse error)? Cleanup JSON is unreachable in TS, and its code prints two concatenated documents (preview, then result) or a compact single-line object. Rust needs one defined shape.
3. **D95 (correctness): `topics revert` never completes.** TS rewrites the profile, then always fails `updatedBy is required` (§7.3). Rust must succeed or fail before writing. Options: add `--updated-by` (required with revert, like `profiles delete --force`), or default it. Also decide whether revert may leave an empty `block` guardrail, and whether it should write at all when the profile never referenced the topic (TS adds a guardrail section).
4. **D96 (safety): profile and topic resolution in `apply`/`revert`.** TS takes the first listed revision of the profile, and of the topic, from an unfiltered list (§2.7). Rust should resolve the latest revision (`getByName` semantics), or fail when the name is ambiguous.
5. **D97 (safety): lost updates.** `apply`, `revert` and `profiles update` read, then PUT the whole profile with no precondition, re-reading the profile up to twice. Rust can read once, PUT once, and never replay a write (SDK policy). Open: compare `revision` or `last_modified_ts` just before the PUT? There is no server-side precondition API.
6. **D98 (correctness): silent re-pinning.** `apply`/`revert` re-pin every other topic to its current revision, and pin deleted topics to 0. Keep the existing pins for untouched entries?
7. **D99 (correctness): `profiles update` re-activates.** A flagless or flag-only update sends `active:true` (§10.3). Rust keeps `current.active` unless `--active`/`--no-active` is given.
8. **D100 (correctness): `profiles create` 409 handling.** It is inverted and text-based (§9.4): it reports success with another profile's data. Rust reports a 409 as an error (exit 1). Open: keep the "already exists" hint?
9. **D101 (correctness): `profiles create` without policy flags, and fractional `--max-inline-latency`.** These always fail in TS (SDK schema). Options: Rust sends the default sections (the create defaults) when no flag is given, or makes it a usage error. It parses `--max-inline-latency` as a non-negative integer (a usage error otherwise).
10. **D102 (correctness): usage before the tenant and before the network.** TS checks `profiles delete --force` without `--updated-by` after a list GET, and checks the `topics delete`/`profiles delete` confirmation refusal after loading credentials. Under D2/D75, Rust finds every flag-only usage error before reading the tenant. `topics delete <non-uuid>` and `topics update <non-uuid>` could also become usage errors.
11. **D103 (confirmation): D81 rules for M4.** TS is interactive iff stdout is a TTY. `cleanup` treats non-TTY without `--force` as a successful preview (exit 0), while `delete`/`revert` treat it as exit 2. Rust is interactive iff stdin and stderr are TTYs, and prompts on stderr. Open: keep cleanup's exit-0 preview for non-interactive runs (the TS comment says agents rely on it), with an explicit `--dry-run`?
12. **D104 (streams): outcome lines.** `✓ Topic created…`, `✓ Profile deleted…`, `Applied/Profile/Intent`, `✓ Cleanup complete…`, per-entry bullets, `ℹ Aborted` and `Sample CSV written…` go to stdout in TS. Under D74 they go to stderr in Rust, with data (detail blocks, JSON) on stdout. Decide whether `apply`/`revert` keyValue blocks and cleanup tables are data or outcome.
13. **D105 (safety): echoed server text.** A `topics delete --force` success prints the server's `message` verbatim, or `✓ undefined`. Rust prints a fixed outcome (`Topic <id> deleted.`), or terminal-safe and SecretSet-checked text. Error messages follow D11.
14. **D106 (safety): write replay.** TS replays POST, PUT and DELETE up to 6 times on 5xx and network errors, and once after a 401 (duplicate creates, repeated force-deletes). The Rust SDK never replays a write. Extend D9/D10 to management writes, and decide the wording for an unknown outcome (`Outcome unknown: …`).
15. **D107 (safety): `cleanup` pagination.** TS loops forever on `next_offset: 0` and has no repeated-cursor guard. Rust ends on 0/absent, fails on a repeated cursor, and never deletes after an incomplete listing.
16. **D108: `cleanup --updated-by` default.** TS runs `git config user.email` in the current directory, and git's stderr leaks through. The options are: (a) keep it (spawning `git` from the cwd repository); (b) require `--updated-by`; (c) take it from a tenant key. Tenant files are the only *credential* source, but this is an audit identity. A git email from an unrelated repository is a correctness risk.
17. **D109 (safety): `cleanup` force semantics.** TS always uses force-delete, which detaches old revisions from referencing policies. Should Rust use a plain delete, report conflicts and offer `--force` for the forced variant? This changes behaviour, so it needs the user's decision.
18. **D110 (correctness): eval fails open.** A scan with no `prompt_detected.topic_violation` boolean, or with `error`/`timeout`, counts as "not triggered". Under the fail-closed invariant, Rust treats such a scan as failed (exit 1, or reported as an error row). Also: should one failed scan abort the whole eval (TS), or produce partial metrics marked incomplete? Scan POST retries follow D9 (exactly one POST).
19. **D111 (correctness): eval `--rate`/`--concurrency` parsing.** TS truncates `2.5` to 2, treats `--rate 0`/`abc` as unlimited, and exits 1 for `--concurrency 0` only after reading the tenant and CSV. Rust parses both as positive integers and reports a usage error (exit 2) before the tenant.
20. **D112 (correctness): `topics sample` CSV.** The sample mixes intents, so `eval` rejects it. Fix the sample (Rust prints a single-intent sample) or keep the bytes? This changes data output, so it needs the user's call.
21. **D113 (safety): `topics sample --output-file`.** TS overwrites an existing file and crashes with a stack trace on write errors. MILESTONES: an existing file is never overwritten. Rust refuses an existing path (exit 1), writes 0600 or 0644, and reports `fs` errors without a stack. Also, the deprecated `sample --output <path>` conflicts with the global `--output`: in Rust it parses as a format, which is a usage error.
22. **D114 (correctness): `profiles create` crash and `--config` name.** TS builds the client outside the try (stack trace on tenant errors) and ignores `--name` when `--config` is given. Open: should `--name` override the file's `profile_name`, or must they match?
23. **Open: `--config` legacy paths** (`profiles create|update --config`, `topics update --config`) send the file verbatim with unknown keys. Keep as is? A file `profile_name` that differs from the resolved profile renames it silently.
24. **Open: data-leak-detection replacement** in `profiles update --dlp-action` drops `member` and `mask-data-inline`. This is TS parity, but arguably a lost update. And `--dlp-profiles`/`--mask-data-inline` are silently ignored without `--dlp-action`: make that a usage error?
25. **Open: `apply` guardrail action** derived from the new intent only (§6 step 4.4). Is this the intended AIRS semantics, or a correctness bug when topics with mixed intents exist?
26. **Live tier notes.**
    - Live write tests must create their own `airs-rs-e2e-<run>-…` topic and profile, and apply topics only to that profile.
    - `revert` cannot be exercised live against TS, since it always fails after writing.
    - `profiles cleanup` never runs live (tenant-wide).
    - `topics eval` needs `AIRS_RS_LIVE_EVAL=1` and a scan budget (rows ≤ the remaining budget) on "Prisma AIRS Harness". Applying a test topic to that shared profile is forbidden, so live eval measures the profile as it is.
