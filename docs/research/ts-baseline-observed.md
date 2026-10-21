# Observed TS CLI baseline (ground truth for parity tests)

What the built TypeScript reference CLI **actually does** against the loopback fixture
server from `crates/airs-test-harness`. Everything below was executed, not read from code.

- CLI: `.reference/prisma-airs-cli/dist/cli/index.js`, package `7.2.1-forgejo.0`, commit
  `5711012246d325f20dbe93b710dcc697a7f18a8a`, TS SDK `@cdot65/prisma-airs-sdk` 0.34.0.
- Node `v24.21.0`, macOS (Darwin 27), 2026-10-16.
- Harness invariants for every run: `env -i`-style allowlist (`PATH`, `HOME=<sandbox>/home`,
  `TMPDIR=<sandbox>/tmp`, `PRISMA_AIRS_TENANTS_PATH=<sandbox>/state/tenants.json`,
  `NO_COLOR=1`, `NO_PROXY=127.0.0.1,localhost`), stdin `/dev/null`, cwd `<sandbox>/cwd`,
  synthetic credentials only, and **every endpoint key** of the tenant file pointing at
  `http://127.0.0.1:<port>` (`FixtureConfig::standard`). `airsNumRetries` is `0`.
- Fixture tenant `prod`, TSG `100`: `mgmtClientId=client-100`,
  `mgmtClientSecret=FAKE-SECRET-100`, `airsApiKey=FAKE-APIKEY-100`; endpoints
  `mgmtEndpoint=<base>/aisec`, `mgmtTokenEndpoint=<base>/oauth/token`,
  `airsApiEndpoint=<base>/scan`, `aiGwDataEndpoint=<base>/ai_gw/v2`, the rest on other
  `<base>/...` paths.
- Reproduce or refresh: `cargo run -p airs-test-harness --example ts_baseline [filter]`.
  The pinned subset is asserted by `cargo test -p airs-test-harness --test ts_reference`.

Global observations that held for **every** scenario below:

- The registry, the configs and the `state/` and `configs/` listings were byte-, mode- and
  mtime-identical after the run. No lock file was created. `HOME` and cwd stayed empty.
- No secret, token or base64/URL-encoded form of one appeared on stdout or stderr.
- No request reached an unknown fixture route, except the 302 scenario, which is the
  redirect target.
- Every connection was keep-alive (`connection: keep-alive`).

## 1. Wire shapes

### 1.1 OAuth token request (management, doctor, AI Gateway)

```
POST /oauth/token
content-type: application/x-www-form-urlencoded
authorization: Basic base64("client-100:FAKE-SECRET-100")
user-agent: node                       (undici default, not the SDK UA)
accept: */*, accept-language: *, sec-fetch-mode: cors, accept-encoding: gzip, deflate
body: grant_type=client_credentials&scope=tsg_id%3A100
```

- Client authentication is **HTTP Basic only**, never form fields.
- **Raw, not form-encoded:** with `mgmtClientSecret = "FAKE+SECRET/=x y:z"` the Basic
  pair matched the secret **raw** (`BasicEncoding::Raw`). This confirms DESIGN D29 (Rust
  form-encodes per RFC 6749). The two forms are identical for the fixture's unreserved
  secrets (`BasicEncoding::Indistinguishable`).
- The `:` in the scope is percent-encoded (`tsg_id%3A100`).
- There is one token request per client per process. The doctor makes **two**: one for
  Management OAuth and one for the AI Gateway client.

### 1.2 Management GET

```
GET /aisec/v1/mgmt/profiles/tsg/100?offset=0&limit=100&latest=true
user-agent: PAN-AIRS/0.34.0-typescript-sdk
service-name: api
authorization: Bearer mock-token-100
(+ undici accept/accept-language/sec-fetch-mode/accept-encoding)
```

There is no body, no content-type and no `x-tsg-id`. The query order is always `offset, limit[, latest]`.

| Invocation | Queries observed |
|---|---|
| `profiles list` | `offset=0&limit=100&latest=true` |
| `profiles list --limit 1` | `offset=0&limit=1&latest=true` |
| `profiles list --all --limit 1 --all-versions` | `offset=0&limit=1&latest=false`, `offset=1&…`, `offset=2&…` (one token) |
| `profiles get <name>` / `<uuid>` | `offset=0&limit=100` (no `latest`) |
| `profiles get <name> --revision 9` | `offset=0&limit=100&latest=false` |
| `topics list` | `GET /aisec/v1/mgmt/topics/tsg/100?offset=0&limit=200` |
| `topics list --all-versions --limit 1 --offset 1` | `?offset=0&limit=100` (slice is local) |
| `topics get <name>` | `?offset=0&limit=100` |
| doctor Management OAuth | `GET .../topics/tsg/100?offset=0&limit=100` |

### 1.3 Scan request

```
POST /scan/v1/scan/sync/request
user-agent: PAN-AIRS/0.34.0-typescript-sdk
service-name: api
content-type: application/json
x-pan-token: FAKE-APIKEY-100
x-payload-hash: <lowercase hex HMAC-SHA256(key, exact body)>    (verified valid by the fixture)
body: {"ai_profile":{"profile_name":"fixture-profile"},"contents":[{"prompt":"hello world"}]}
```

- With `--response "an answer"`: `{"ai_profile":{"profile_name":"p"},"contents":[{"prompt":"q","response":"an answer"}]}`.
- Token-only tenant (`airsApiToken`, no key): `authorization: Bearer <token>`, no
  `x-pan-token` and no `x-payload-hash`.
- Key and token: all three headers are sent.
- A scan makes no OAuth request.

### 1.4 Doctor probes (in this order)

1. `GET /scan/v1/scan/results?scan_ids=<random uuid v4>`: `x-pan-token`, **no**
   `x-payload-hash`, `service-name: api`, the SDK user agent.
2. `POST /oauth/token`, then `GET /aisec/v1/mgmt/topics/tsg/100?offset=0&limit=100`.
3. `POST /oauth/token`, then `GET /ai_gw/v2/workspaces` with `authorization: Bearer
   mock-token-100` **and `x-tsg-id: 100`**. The response must match
   `{"object": string, "total": number, "data": [...]}`; the fixture answers
   `{"object":"list","total":0,"data":[]}`.
4. No Typesafe request is made when `typesafeApiKey` is unset (even with `typesafeBaseUrl` set).

## 2. Success outputs

| Scenario | exit | stdout | stderr |
|---|---|---|---|
| `--version` | 0 | `7.2.1-forgejo.0\n` | — |
| `runtime profiles list --output json`, empty | 0 | `[]\n` | `  Showing 0\n` |
| same, rows `alpha r1, alpha r2, beta r1` (server collapses) | 0 | 2-space JSON array: `alpha` rev 2, `beta` rev 1; keys `profileId, profileName, revision, active, createdBy, updatedBy, lastModifiedTs, policy` | `  Showing 2\n` |
| `--limit 1` (server sends `next_offset: 1`) | 0 | 1 row | `  Showing 1 (more available)\n` |
| last page carries `next_offset: 0` | 0 | rows | `  Showing 2 (more available)\n` (D12 quirk confirmed) |
| `--all --limit 1 --all-versions`, 3 rows | 0 | 3 rows | `  Showing all 3\n` |
| `runtime topics list --output json` (fin r1, fin r2, legal r1) | 0 | `fin` r2, `legal` r1; keys `topicId, topicName, revision, active, description, examples, createdBy, lastModifiedTs, createdTs` | `  Showing 2\n` |
| `topics list --all-versions --limit 1 --offset 1` | 0 | `fin` r2 | `  Showing 1 of 3 (next --offset 2)\n` |
| `profiles get alpha --output json` | 0 | bare object, highest revision (2) | empty |
| `profiles get 00000000-0000-4000-8000-000000000001` | 0 | that exact row (revision 1) | empty |
| `topics get fin --output json` | 0 | bare object, revision 2 | empty |
| `tenant list --output json` | 0 | `[{"name":"prod","configPath":"<abs>","tsgId":"100","active":true}]` (pretty) | empty |
| profiles `401` once, then success | 0 | `[]\n` | `  Showing 0\n`; requests: token, GET (401), token, GET |

### 2.1 Scan (pretty only; `--output json` silently ignored)

Status lines on stderr (all three, before the request):
`  Prisma AIRS Runtime Scan\n  Profile: fixture-profile\n  Prompt:  "hello world"\n`

| Verdict fixture | exit | stdout |
|---|---|---|
| allow (`scan_allow`) | 0 | `\n  Scan Result\n\n  Action     ALLOW\n  Category   benign\n  Triggered  no\n  Scan ID    00000000-0000-4000-8000-0000000000a1\n  Report ID  R00000000-0000-4000-8000-0000000000a1\n` |
| block (`scan_block`) | 0 | `…  Action     BLOCK\n  Category   malicious\n  Triggered  yes\n  Scan ID    …b2\n  Report ID  R…b2\n\n  Detections\n\n  ● injection\n  ● toxic_content\n` (the `response_detected.dlp: true` is ignored) |
| failed (`error: true`) | 0 | `Action     ALLOW`, `Category   error`, `Triggered  no` (D6 confirmed) |
| `--quiet` | 0 | heading suppressed: stdout starts with `  Action     ALLOW`; stderr empty |
| `--output json --response …` | 0 | the same pretty layout; json is ignored (D5) |

### 2.2 Doctor

`doctor --output json`: exit 0, stderr empty, stdout a 2-space JSON array of **11**
checks, in this order:

| # | name | status | detail |
|---|---|---|---|
| 1 | Node.js version | pass | `v24.21.0 (^20.17.0 \|\| ^22.13.0 \|\| >=23.5.0 required)` |
| 2 | Tenant | pass | `prod (TSG 100) selected in <sandbox>/state/tenants.json` |
| 3 | Config file | pass | `valid tenant config at <sandbox>/configs/prod.json (TSG 100 matches registration)` |
| 4 | Environment | pass | `no configuration variables set` |
| 5 | Scanner credentials | pass | `airsApiKey (file)` |
| 6 | Management credentials | pass | `set: mgmtClientId (file), mgmtClientSecret (file), mgmtTsgId (file)` |
| 7 | Typesafe credentials | skip | `not configured — redteam judge is unavailable`, hint `Run 'airs-cli tenant set prod <key>' for typesafeApiKey (secrets prompt hidden, or use --stdin)` |
| 8 | Scanner API | pass | `endpoint reachable, API key accepted` |
| 9 | Management OAuth | pass | `OAuth token obtained, topics API answered (0 custom topics)` |
| 10 | AI Gateway API | pass | `endpoint reachable (0 workspaces in scope)` |
| 11 | Typesafe API | skip | `skipped — typesafeApiKey not configured` |

Note: the Typesafe credentials check (7) comes **before** the network checks, so the
order differs from ts-doctor.md §2's numbered list.

`hint` is present only where shown. The pretty form (stdout, exit 0):

```
\n  Doctor\n  Prisma AIRS CLI preflight checks\n\n
  ✓ Node.js version — v24.21.0 (...)
  ...
  ○ Typesafe credentials — not configured — redteam judge is unavailable
      Run 'airs-cli tenant set prod <key>' for typesafeApiKey (secrets prompt hidden, or use --stdin)
  ...
\n  ✓ All checks passed (2 skipped)\n\n
```

Variants:

| Fixture | Changed checks | exit |
|---|---|---|
| no `airsApiKey` | Scanner credentials skip `not configured — runtime scan, bulk-scan and topics eval are unavailable` (hint `Run 'airs-cli tenant set prod <key>' for airsApiKey (secrets prompt hidden, or use --stdin)`); Scanner API skip `skipped — no scanner credentials configured`; no scanner request | 0 |
| scanner results `503` | Scanner API **pass** `endpoint reachable, API key accepted (HTTP 503 on probe query)` (D20) | 0 |
| scanner results `401 {"message":"bad key"}` | Scanner API fail `API key rejected (HTTP 401): AISEC_CLIENT_SIDE_ERROR:bad key`, hint `Verify airsApiKey belongs to this tenant and is not expired` | 1 |
| token endpoint `401 {}` | Management OAuth fail `management API error (HTTP 401): AISEC_OAUTH_ERROR:Token request failed with status 401`, hint `Verify mgmtClientId / mgmtClientSecret / mgmtTsgId belong to this tenant`; AI Gateway API fail `AI Gateway API error (HTTP 401): AISEC_OAUTH_ERROR:Token request failed with status 401`, hint `Verify the tenant credentials and network connectivity`; requests: results probe, token, token | 1 |

## 3. Error outputs

Operational errors are `\n  ✗ Error: <msg>\n` + (`    HTTP <s>\n    Re-run with --debug to capture redacted API diagnostics.\n` when a status is known) + `\n`, exit 1, stdout empty.

| Scenario | Requests | stderr message line | HTTP line |
|---|---|---|---|
| token `401 {}` | token ×1 (no data request) | `AISEC_OAUTH_ERROR:Token request failed with status 401` | `HTTP 401` |
| token `401 {"error":"invalid_client","error_description":"Client authentication failed"}` | token ×1 | `AISEC_OAUTH_ERROR:Client authentication failed` (server text echoed) | `HTTP 401` |
| token `200 {"token_type":"Bearer"}` | token ×1 | `AISEC_OAUTH_ERROR:Token response did not match the OAuth schema` | none |
| profiles `404 {"message":"nope"}` | token, GET | `AISEC_CLIENT_SIDE_ERROR:nope` | `HTTP 404` |
| profiles `404 {}` | token, GET | `AISEC_CLIENT_SIDE_ERROR:API error 404` | `HTTP 404` |
| profiles `429 {"message":"slow down"}` + `Retry-After: 0` | token, GET ×1 (**not retried**) | `AISEC_CLIENT_SIDE_ERROR:slow down` | `HTTP 429` |
| profiles `503 {"message":"busy"}` + `Retry-After: 0` | token, GET ×**6** (`airsNumRetries` does not apply to management) | `AISEC_SERVER_SIDE_ERROR:busy` | `HTTP 503` |
| profiles `502 text/plain "oops"` + `Retry-After: 0` | token, GET ×6 | `AISEC_SERVER_SIDE_ERROR:API error 502: oops` (raw body echoed) | `HTTP 502` |
| profiles `302 Location: <base>/elsewhere` | token, GET, **GET /elsewhere** (redirect followed, with the bearer) → fixture 404 | `AISEC_CLIENT_SIDE_ERROR:API error 404` | `HTTP 404` |
| profiles `200 {"ai_profiles":[{"revision":1}],"next_offset":null}` | token, GET | `AISEC_RESPONSE_VALIDATION:Response did not match schema: ai_profiles.0.profile_name: invalid_type; next_offset: invalid_type` | none |
| profiles `200 "{not json"` | token, GET | `AISEC_RESPONSE_VALIDATION:Response body is not valid JSON` | none |
| `--all`, every page `next_offset: 5` | token, `offset=0`, `offset=5`, then stop | `Pagination returned a repeated cursor` (no prefix) | none |
| `profiles get missing` | token, GET | `AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: missing` | none |
| `profiles get alpha --revision 9` | token, GET `latest=false` | `Profile alpha not found` | none |
| `topics get nope` | token, GET | `Topic "nope" not found` | none |
| scan `503 {"message":"busy"}` + `Retry-After: 0`, `airsNumRetries: 0` | POST ×1 | `AISEC_SERVER_SIDE_ERROR:busy` (after the 3 status lines) | `HTTP 503` |
| scan `429 {"message":"slow down"}` | POST ×1 | `AISEC_CLIENT_SIDE_ERROR:slow down` | `HTTP 429` |
| scan `401 {}` | POST ×1 | `AISEC_CLIENT_SIDE_ERROR:API error 401` | `HTTP 401` |
| scan with prompt `""` | none | status lines, then `AISEC_USER_REQUEST_PAYLOAD_ERROR:At least one of prompt, response, codePrompt, codeResponse, or toolEvent must be provided` | none |
| config `mgmtTsgId: "200"`, registry `tsgId: "100"` | none | `Tenant config TSG differs from its registered identity; register it under a new name` | none |
| registry `active: null`, one tenant | none | `No tenant selected. Run 'airs-cli tenant switch <name>' (registered: prod)` | none |
| empty registry | none | `No tenant selected. Run 'airs-cli tenant create <name>' and then 'airs-cli tenant switch <name>'` | none |

### 3.1 Parse and usage errors (zero requests)

| argv | exit | stderr |
|---|---|---|
| `runtime profiles list --bogus` | **1** | `error: unknown option '--bogus'\n` |
| `runtime profiles get` | **1** | `error: missing required argument 'nameOrId'\n` |
| `runtime bogus` | **1** | `error: unknown command 'bogus'\n` |
| `runtime profiles` (bare group) | **1** | the group help (`Usage: airs-cli runtime profiles [options] [command]` …) on **stderr** |
| `runtime scan q` | **1** | `error: required option '--profile <name>' not specified\n` |
| `runtime profiles list extra` | **1** | `error: too many arguments for 'list'. Expected 0 arguments but got 1.\n` |
| `runtime profiles list --limit 0` | 2 | `\n  ✗ --limit must be a positive integer\n\n` |
| `runtime profiles list --all --offset 0` | 2 | `\n  ✗ --all cannot be combined with --offset\n\n` |
| `runtime profiles list --output xml` | 2 | `\n  ✗ Invalid output format 'xml'. Expected: pretty, table, markdown, csv, json, yaml\n\n` |

The last three ran with a valid selected tenant. Commander errors exit 1 (DESIGN D1).

### 3.2 Signals

`runtime profiles list --output json` with a hung profiles response, SIGINT sent after the
GET arrived: the process **died by signal 2** (no handler; a shell reports 130), stdout
and stderr were empty, and the fixture observed the client disconnect. Matches D32.

## 4. Contradictions with the research specs and DESIGN.md

1. **Doctor token failure detail (DESIGN §9, Management OAuth).** DESIGN specifies
   `authentication failed (HTTP <s>): <message>` for a token non-2xx. TS prints
   `management API error (HTTP 401): AISEC_OAUTH_ERROR:Token request failed with status
   401`, because the TS SDK attaches the status to the OAuth error. This answers
   ts-doctor.md open question 415. The difference is **not listed in DESIGN §12**, so
   parity tests must either treat it as an intended divergence or DESIGN must adopt the
   TS text.
2. **Doctor check order.** ts-doctor.md §2 numbers the checks, but TS emits `Typesafe
   credentials` as check 7, before `Scanner API`. DESIGN's 7-check subset keeps its own
   relative order, which matches TS on the intersection.
3. **Repeated cursor text.** TS: `Pagination returned a repeated cursor` (no `AISEC_`
   prefix, exit 1). DESIGN §6: `AISEC_SDK_ERROR:Pagination stopped: …`. This is not in
   §12 (D11 covers only server text).
4. **Response-validation texts.** TS lists zod issues
   (`Response did not match schema: <path>: <code>; …`) and has a distinct non-JSON text
   (`Response body is not valid JSON`). DESIGN §6 maps every Decode failure to
   `AISEC_RESPONSE_VALIDATION:Response did not match the expected schema`. This is not
   listed in §12.
5. **Redirects.** TS follows a 302 on the management API to the redirect target and
   re-sends the bearer to it (same origin here). D30 records only "followed by fetch".
   Note the credential forwarding.
6. **Management retries.** TS sends 6 GETs for 503 and for a non-JSON 502, consistent with
   D10. 429 is not retried, and Rust retries 429 (D10).
7. **AI Gateway request carries `x-tsg-id`.** The doctor's workspaces probe sends
   `x-tsg-id: 100`, while the management profile/topic routes do not. This is consistent
   with DESIGN §5.
8. **ts-runtime-mgmt-read.md §5 (`profiles get` by UUID or name) is confirmed:** gets
   send no `latest` query.
9. Everything else in ts-runtime-scan.md §9 (error matrix), ts-runtime-mgmt-read.md §3/§9
   (headers, retry, message shapes) and ts-tests-and-docs.md §2.4 was observed exactly as
   specified.
