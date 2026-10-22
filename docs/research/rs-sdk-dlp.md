# Rust SDK for M6b (0.7): DLP

Scope: every M6b command, which is all of `runtime dlp` except `generate`. That means
`filtering-profiles list|get|replace`, `patterns list|create|get|replace|patch|delete`,
`profiles list|create|get|replace|patch|delete`, `dictionaries list|create|get|replace|patch|delete`,
`backup` and `restore`. For each one, this file gives the `scm-sdk` 0.1.0 API that serves it and
compares it with the HTTP calls the frozen TS CLI makes (5711012) through its SDK 0.34.0.
Everything here was read from source. The only commands run were `--help` invocations of the
reference build, with a scratch `HOME` and scratch XDG directories, and two read-only Python scripts that
walk the SDK's frozen schema graph. Nothing was built, and no network call was made.

Citation prefixes:

- `rs:` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scm-sdk-0.1.0/src/`, the
  published crate the CLI pins. `dlp:` = `rs:dlp/`, `gen:` = `rs:models/generated.rs`.
- `tsdk:` = `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js`
  (0.34.0, the bundle the TS CLI really runs).
- `cli:` = `.reference/prisma-airs-cli/src/`, the TS CLI. `cmd:` = `cli:cli/commands/dlp/`.
  `bk:` = `cli:backup/dlp-resources.ts`.
- `docs:` = `.reference/prisma-airs-cli/docs-site/docs/`. `here:` = this repository.

Companion specs: `rs-sdk-foundation.md` (engine and auth), `rs-sdk-management.md` (models,
pagination and key order), `rs-sdk-writes.md` (the write path, G1–G6 and D95) and
`rs-sdk-redteam.md` (G7–G10, the targets backup). This file covers only what M6b adds. Its
gap numbers continue from G10.

---

## 0. Summary

- **Every M6b command has an SDK operation, except `profiles delete`.** The DLP API has no
  delete for that command, and the TS command sends no request (§4.3). Paths, methods, query
  parameters, request schemas and response schemas match the TS SDK one for one
  (`dlp:*.rs` vs `tsdk:12652-13405`). The paths are `/v2/api/data-filtering-profiles`,
  `/v2/api/data-patterns`, `/v2/api/data-profiles` and `/v2/api/dictionaries`
  (`rs:constants.rs:640-643` = `tsdk:71-74`).
- **The `dlp` feature is already compiled in.** The CLI enables `management`, and scm-sdk
  declares `management = ["models", "dlp"]` (`rs:../Cargo.toml:62-65`), so `scm::dlp::DlpClient`
  is available today. The computed task's premise ("does not enable yet") is therefore wrong in
  effect. Listing `"dlp"` explicitly in `here:Cargo.toml` documents the dependency and changes
  nothing in the lock file. It is recommended.
- **No SDK schema default reaches DLP output (G10 is not a DLP issue).** I walked the frozen
  schema graph (`rs:validation/schema_graph.json`, `semantics.json`) from all 14 DLP roots:
  - Request roots: pattern, profile, dictionary and filtering-profile requests, plus their patch
    forms.
  - Response roots: the matching responses and the four `Page…` envelopes.

  The walk found zero `ZodDefault` nodes and zero `ZodEffects` nodes, and every object is
  `passthrough`. The same script finds the four known defaults under `TargetResponseSchema`
  (`ws_response_timeout` and the others), so the method works. The typed DLP models keep
  unset, `null` and unknown keys (`Patch<T>`, `Extensions`). DLP reads, outputs and backups are
  therefore lossless through the typed SDK calls. They need neither the raw-read workaround
  of `targets backup` nor `Mode::ResponseWithoutDefaults`. Request bodies gain no fields
  either (`send_model` validates in `Mode::Request` with no defaults on these schemas).
- **One attempt per write holds by construction.** Every DLP write is built with
  `RawRequest::new(METHOD, …)`, which sets `replay_safe = false` (`rs:engine.rs:49-60`):
  - POST, PUT and DELETE;
  - PATCH (merge-patch);
  - both multipart uploads.

  The SDK therefore never re-sends one, after a 5xx, a transport error or a 401/403
  (`rs:engine.rs:1173-1236`). `writes::attempt` adds the D95 single replay after a 401 with
  outcome `Rejected`. TS is different: its CRUD client uses `numRetries` 5 for every method,
  so a 500, 502, 503 or 504 on a pattern POST re-sends the create up to five times
  (`tsdk:9786-9848`, `tsdk:9707`, `tsdk:11111-11114`). Only TS `backup` and `restore` pass
  `numRetries: 0` (`cmd:transfer.ts:69`). This is a §12 candidate.
- **Gaps (§9).**
  - **G11** is not an SDK bug, but it **blocks the live rule** for data-profile writes. There
    is no data-profile DELETE in the API or in the SDK, and a deleted profile keeps its name
    reserved.
  - **G12**: the SDK Spring walk has no duplicate, count-drift or metadata-consistency checks.
    It also misses snake_case totals. The CLI-side page loop is safe.
  - **G13**: the response size and node limits can refuse keyword-bearing dictionary pages.
    Raising the CLI-side limits and reading keywords per dictionary is safe.
  - **G14 to G17** are not gaps. They are behaviour differences or ergonomics: upload cap and
    filename rules, local metadata validation, list-params construction, and operation names.

  No SDK patch is needed for any M6b command.

---

## 1. Client construction

### 1.1 The TS side

- `cmd:config.ts:5-7` calls `managementClientOptions(loadConfig())`
  (`cli:config/client-options.ts:44-51`). That function passes the tenant's `mgmtClientId`,
  `mgmtClientSecret`, `mgmtTsgId`, `mgmtTokenEndpoint` and
  `dlpEndpoint ?? DEFAULT_DLP_ENDPOINT` (`https://api.dlp.paloaltonetworks.com`, `tsdk:70`).
- `new ManagementClient(opts)` (`tsdk:13407-13447`) builds one `OAuthAuth` and a
  `DlpNamespace({ baseUrl: dlpEndpoint, auth, numRetries })` (`tsdk:13369-13405`).
  - Its `numRetries` defaults to `MAX_NUMBER_OF_RETRIES` = 5 (`tsdk:30`, `tsdk:11111-11114`).
    `transfer.ts` passes 0.
  - It reads no environment variable for the DLP base. Its `apiEndpoint` falls back to
    `PANW_MGMT_ENDPOINT`, which DLP never uses. The test
    `tests/unit/airs/dlp/client-wiring.spec.ts` pins this.
- Requests carry `User-Agent`, `service-name: api` and the bearer token. No `x-tsg-id` header
  is sent.

### 1.2 The Rust side (proposed `clients::DlpClients`)

Mirror `RedTeamClients::build` (`here:src/clients.rs:429-496`) and reuse its private
`oauth_parts`:

1. **Endpoints.** Admit `dlpEndpoint` with `admit("dlpEndpoint", config.effective_str("dlpEndpoint"), scm::constants::DEFAULT_DLP_ENDPOINT)`
   (`rs:constants.rs:626`; the constants module is `pub`, `rs:lib.rs:11`). Admit
   `mgmtTokenEndpoint` with `DEFAULT_TOKEN_ENDPOINT`. The D48 message names the key and never
   echoes the value. The fixture tenant already sets `dlpEndpoint = <base>/dlp`
   (`here:crates/airs-test-harness/src/sandbox.rs:77`), and `dlpEndpoint` is a known tenant key
   (`here:src/tenant/config.rs:22`).
2. **Identity and transport.** Call `oauth_parts(config, &issuer, &[dlp.clone()], session, secrets, debug, &LastStatus::default())`.
   It runs the §3.5 management credential check, the TSG digit rule, the lease-recording
   provider, one transport (the direct one when either endpoint is loopback http), and one
   `OriginPolicy` that admits the DLP base and the issuer. The DLP plane is the management
   OAuth plane and never sends scanner credentials.
3. **Limits.** Start from `Limits::default()` and set `max_retries = MANAGEMENT_RETRIES` (5,
   for reads only). Raise `max_response_bytes` to 32 MiB (see G13; validation then scales to
   400,000 nodes, `rs:validation.rs:44-55`). Leave `max_request_bytes` at 8 MiB (see G14).
4. **Client.** Build with
   `Client::builder(dlp).transport(..).destination_policy(..).authentication(Authentication::oauth(provider, false)).session(..).limits(..).build()`,
   then `scm::dlp::DlpClient::new(client)`. `DlpClient::new` requires OAuth
   (`dlp:mod.rs:51-54`). On a construction failure, report
   `AISEC_SDK_ERROR:The DLP client could not be configured` (exit 1). Before the first call,
   each command awaits `provider.get_token(..)`, as `RedTeamClients::authenticate` does, so a
   token failure is reported as `AISEC_OAUTH_ERROR:…`.
5. **Sub-clients.** `DlpClient` hands out cheap clones:
   - `data_patterns()` → `DataPatternsClient`;
   - `data_profiles()` → `DataProfilesClient`;
   - `dictionaries()` → `DictionariesClient`;
   - `data_filtering_profiles()` → `DataFilteringProfilesClient`.

   `client()` gives the `&Client` for a raw request, which no command needs (§0).

No environment variable is read on either side. TS never applies a `PANW_*` fallback to DLP,
so no `/ts-env` trap is needed.

### 1.3 Budgets

| Call | Rust budget |
|---|---|
| Single request | Default `RequestOptions` (the 60 s operation budget, `rs:config.rs:288`) |
| Walks (`--all`, backup inventories, restore plan and recheck, `profiles create --pattern-id` lookups) | `RequestOptions::with_timeout(300 s)` per walk (§5 of DESIGN) |

Never use `RequestOptions::with_retries(0)` for a read: it also drops the 401/403
refresh-and-replay (G7).

---

## 2. Engine behaviour for DLP calls

| Call shape | SDK path | Replay by the SDK | Outcome on failure |
|---|---|---|---|
| GET list or get | `RawRequest::read(PATH)…named("dlp.*")` → `send_contract` (`dlp:data_patterns.rs:19-34`, `:50-64`) | `replay_safe`: up to `max_retries` on transport errors and retryable statuses (honouring `Retry-After` up to `max_retry_delay` 5 s); one 401/403 refresh and replay (`rs:engine.rs:1173-1236`) | `Rejected` for 3xx and 4xx, `Unknown` for 5xx (irrelevant for reads) |
| POST, PUT or PATCH JSON | `RawRequest::new(METHOD, PATH)` → `send_model(body, req_schema, resp_schema)` (`dlp:data_patterns.rs:35-101`) | never | `NotSent` before dispatch (validation, `Limit`, token); `Rejected` for 3xx and 4xx; `Unknown` for 5xx, transport errors after dispatch (a refused connection included, G3) and a cancel after dispatch; for a decode error after a 2xx, the error kind `Decode` carries the 2xx status (G4) |
| PATCH | as above, plus `.content_type("application/merge-patch+json")` (`dlp:data_patterns.rs:93`, `data_profiles.rs:94`, `dictionaries.rs:168`) | never | as above |
| DELETE | `RawRequest::new(DELETE, …)` → `send_empty` (`dlp:data_patterns.rs:102-111`, `dictionaries.rs:177-186`); any 2xx body is ignored | never | as above |
| Multipart create or replace | `upload_request` → `send_contract` or `send_optional_contract` (`dlp:dictionaries.rs:92-157`) | never (`RawRequest::new`) | as above. The metadata validation and the file-size check run before dispatch (`NotSent`) |

**Request bodies.**

- `send_model` serialises the typed model and parses it with the request schema in
  `Mode::Request`, then re-serialises it with sorted keys (`rs:engine.rs:524-582`, D35).
- The CLI should parse every body itself during planning with
  `<Model>::parse(value, Mode::Request)`:
  - `DataPatternRequest` and `DataPatternPatchRequest`;
  - `AdvancedDataProfileRequest` and `DataProfilePatchRequest`;
  - `DictionaryRequest` and `DictionaryPatchRequest`;
  - `DataFilteringProfileRequest`.

  That turns schema failures into usage errors before the tenant is read, and unknown keys
  survive in `extensions`.
- The SDK's own validation failure is `ErrorKind::Validation` with outcome `NotSent`, so it
  never reaches the wire.

**Required fields** (from the schema graph; TS has the same, frozen):

| Body | Required (absent or `null` refused) |
|---|---|
| Pattern create and replace | `name`, `type`, `detection_config` |
| Pattern patch | `name`, `type`, `detection_config`. `description`, `matching_rules` and `tags` accept `null` |
| Advanced profile create and replace | `name`, `detection_rules` (an array of the discriminated union `rule_type` = `expression_tree` or `multi_profile`). `profile_type` is not a declared key: the TS `profile_type: "advanced"` travels as an extension |
| Profile patch | `name`, `profile_type`. `description` and `detection_rules` are nullable |
| Dictionary metadata | `category` (closed enum of nine names), `name`, `original_file_name`, `region_name` |
| Dictionary patch | `category`, `name`, `original_file_name`. `description`, `is_case_sensitive` and `region_name` are nullable |
| Filtering-profile replace | `file_based`, `non_file_based` |

So a `--set description=x`-only patch fails the schema on both CLIs (TS: `Invalid … metadata`,
exit 2; tests `integration/dlp-dictionary-errors.spec.ts:210-252`).

**Response decoding** uses `Mode::Response` with no defaults. Enum-typed fields have
`Unknown(String)` variants in the Rust model, but the frozen zod enums still refuse an
unfamiliar value. For example, a new `DataPatternStatus` is a `Decode` error on both CLIs
(TS parity). Nested expression trees deeper than the validator's 64 levels
(`rs:validation.rs:20`) are a `Limit` on Rust. TS bounds them at 100 (`bk:281`). This is
recorded, but not a practical concern.

---

## 3. Common API facts the CLI must know

- **Pagination is zero-based Spring paging.**
  - `SpringListParams { page: Option<u64>, size: Option<u32>, sort: Vec<String> }` serialises
    only the set fields, as `page=`, `size=` and one `sort=` per entry in caller order
    (`dlp:common.rs:76-99`).
  - Local checks give `ErrorKind::Validation`: page ≤ 2^53−1, size ≠ 0, at most 128 sort
    entries, each 1–1024 bytes with no control character. The CLI must check `--limit`,
    `--offset` and `--sort` itself first, so these become usage errors.
  - TS sends `sort=name,asc` by default on every list (`cmd:patterns.ts:60-61` and the other
    commands). The SDK sends no sort unless asked, so the CLI passes `vec!["name,asc"]` when
    `--sort` is absent.
- **List params.** `DataPatternListParams` and `DataProfileListParams` are aliases of
  `SpringListParams`, with builders. `DictionaryListParams` adds `keywords: Option<bool>`.
  `DataFilteringProfileListParams` adds `status` and `name`, which TS never exposes. The last
  two are `#[non_exhaustive]` and have no constructor (G16): build them as
  `let mut p = DictionaryListParams::default(); p.size = Some(n); …`.
- **Page envelopes** (`gen:155280-156110`) rename `numberOfElements`, `totalElements`,
  `totalPages` and `pageable.{pageNumber,pageSize}` to camelCase. Dictionaries return
  snake_case metadata (`bk:110-116`), and that metadata lands in `extensions` (G12).
- **Dictionary keywords** come only with `keywords=true`:
  - `list`: `params.keywords`;
  - `get`: `get(id, Some(true), …)`;
  - `create` and `replace`: `DictionaryUpload::include_keywords(true)`, which adds the query
    `?keywords=true` (`dlp:dictionaries.rs:61-63`, `:80`, `:117-122`).

  TS maps `--keywords` and `--include-keywords` the same way (`cmd:dictionaries.ts:91-97`,
  `:147-151`, `:132`).
- **Ids** go through `RawRequest::segment`. It accepts a non-empty value of at most the
  segment limit. It refuses `.` and `..` components, `\` and control characters, also after
  up to eight percent-decodes, and encodes `/` as `%2F` (`rs:config.rs:121-151`). TS
  `encodeURIComponent`s whatever it gets. So `patterns get ..` is refused locally on Rust,
  and the CLI should report it as a usage error with the redteam segment helper
  (`here:src/redteam/mod.rs:37`).
- **Predefined records.** `type == "predefined"` marks PANW-shipped patterns, dictionaries and
  profiles, and listings hide them unless `--include-predefined` is given (`cmd:visibility.ts`).
  - Data profiles carry `type` as `DataProfileSubtype` and their lifecycle in
    `profile_status`. Patterns carry `status`.
  - The deleted and disabled states count as "retired" for name matching (`bk:52-54`).
  - Filtering profiles' `type` is a free string.
  - `is_parent_managed` exists on patterns, profiles, dictionaries and filtering profiles.
- **Soft delete.** A pattern DELETE archives the pattern: `get` then shows `status: "deleted"`
  (`docs:runtime/dlp/patterns.md:209-221`). A dictionary DELETE is a delete. There is no
  profile DELETE, and a deleted profile reserves its name, so a later create gets 409
  (`docs:runtime/dlp/transfer.md:215-218`, `docs:runtime/dlp/profiles.md:10`).
- **Live-observed limits** that TS enforces client-side and the port keeps:
  - profile names of at most 32 UTF-16 units (`cmd:build-body.ts:139-147`);
  - `basic` profile writes refused (`:127-137`);
  - a CSV upload consumes its first row as a header (`bk:603-618`);
  - regions use the display name (`cmd:dictionaries.ts:36-52`).

---

## 4. Command → SDK map

Unless a row says otherwise, every call is `dlp.<sub>().<op>(…, Some(&options))`, and the
operation name below is what the `--debug` log records (G17). "TS" names the TS SDK method and
its wire call.

### 4.1 `filtering-profiles` (`dlp:filtering_profiles.rs`; TS `tsdk:12652-12760`)

| Command | Rust | Wire | TS difference |
|---|---|---|---|
| `list` (one page) | `list(&params{page,size,sort})`, `dlp.filtering_profiles.list` | `GET /v2/api/data-filtering-profiles?page&size&sort` | none |
| `list --all` | CLI walk over `list` (§5) | same, `page=0,1,…`, `size=--limit` (default 50) | TS `listAll` = `collectSpringPages` (`tsdk:10826-10839`) without duplicate checks |
| `get <id>` | `get(id)`, `dlp.filtering_profiles.get` | `GET …/{id}` | none |
| `replace <id>` | `replace(id, &DataFilteringProfileRequest)`, `dlp.filtering_profiles.replace` | `PUT …/{id}`, JSON | TS retries up to 5 times on 5xx; Rust sends one attempt. TS reports every failure as a usage error, exit 2 (`cmd:filtering-profiles.ts:95-97`); Rust exits 1 for operational errors |

### 4.2 `patterns` (`dlp:data_patterns.rs`; TS `tsdk:12762-12953`)

| Command | Rust | Wire |
|---|---|---|
| `list [--all]` | `list` / CLI walk; `dlp.data_patterns.list` | `GET /v2/api/data-patterns?page&size&sort` |
| `get <id>` | `get(id)`; `dlp.data_patterns.get` | `GET …/{id}` |
| `create` | `create(&DataPatternRequest)`; `dlp.data_patterns.create` | `POST /v2/api/data-patterns` |
| `replace <id>` | `replace(id, &DataPatternRequest)`; `dlp.data_patterns.replace` | `PUT …/{id}` |
| `patch <id>` | `patch(id, &DataPatternPatchRequest)`; `dlp.data_patterns.patch` | `PATCH …/{id}`, `Content-Type: application/merge-patch+json` |
| `delete\|rm <id>` | `delete(id)`; `dlp.data_patterns.delete` | `DELETE …/{id}` (soft delete) |

TS reports every failure of `create`, `replace` and `patch` (HTTP 5xx included) as a usage
error with the raw message, exit 2 (`cmd:patterns.ts:82-84`, `:113-115`, `:144-146`). This is
a §12 candidate.

The proposed predefined guard (§8) adds a `get(id)` before `replace`, `patch` and `delete`.

### 4.3 `profiles` (`dlp:data_profiles.rs`; TS `tsdk:12955-13136`)

| Command | Rust | Wire |
|---|---|---|
| `list [--all]` | `list` / CLI walk; `dlp.data_profiles.list` | `GET /v2/api/data-profiles?page&size&sort` |
| `get <id>` | `get(id)`; `dlp.data_profiles.get` | `GET …/{id}` |
| `create` | `create(&AdvancedDataProfileRequest)`; `dlp.data_profiles.create` | `POST /v2/api/data-profiles` |
| `replace <id>` | `replace(id, &AdvancedDataProfileRequest)`; `dlp.data_profiles.replace` | `PUT …/{id}` |
| `patch <id>` | `patch(id, &DataProfilePatchRequest)`; `dlp.data_profiles.patch` | `PATCH …/{id}`, merge-patch |
| `delete\|rm <id>` | **no SDK operation (G11)**, which is correct. The TS command is a usage error (exit 2) that sends no request, reads no tenant and prints the limitation text (`cmd:profiles.ts:255-266`; spec `dlp-delete-safety.spec.ts`). Port it as a clap leaf that fails in planning (zero requests, no debug log), with the program name `airs-cli-rs` in the hint (D73) | none |

`create --pattern-id <id>…` (and `replace`) first resolves each unique id with
`data_patterns().get(id)`, one read each, before any write:

- an id mismatch, a missing name or technique, or a version that is not an integer ≥ 1 is an
  error;
- a pattern that is not `active` is an error;
- a `--confidence` outside the pattern's levels is an error.

See `cmd:profiles.ts:107-140` and `integration/dlp-profile-pattern-flags.spec.ts`. TS sends
these GETs after building the client but before writing. Rust does the same.

### 4.4 `dictionaries` (`dlp:dictionaries.rs`; TS `tsdk:13154-13368`)

| Command | Rust | Wire |
|---|---|---|
| `list [--keywords\|--include-keywords] [--all]` | `list(&DictionaryListParams{page,size,sort,keywords})` / CLI walk; `dlp.dictionaries.list` | `GET /v2/api/dictionaries?page&size&sort[&keywords=true]` |
| `get <id> [--keywords]` | `get(id, Some(true)\|None)`; `dlp.dictionaries.get` | `GET …/{id}[?keywords=true]` |
| `create` | `create(&DictionaryUpload)`; `dlp.dictionaries.create` | `POST /v2/api/dictionaries[?keywords=true]`, `multipart/form-data` |
| `replace <id>` | `replace(id, &DictionaryUpload)` → `Option<DictionaryResponse>`; `dlp.dictionaries.replace` | `PUT …/{id}[?keywords=true]`, multipart; a 2xx with an empty body is `Ok(None)` (`dlp:dictionaries.rs:142-157`) |
| `patch <id>` | `patch(id, &DictionaryPatchRequest)`; `dlp.dictionaries.patch` | `PATCH …/{id}`, merge-patch |
| `delete\|rm <id>` | `delete(id)`; `dlp.dictionaries.delete` | `DELETE …/{id}` |

**Multipart.** Both SDKs send the same two parts:

1. `name="json"; filename="metadata.json"`, `Content-Type: application/json`, holding the
   metadata JSON. Rust validates it with `DictionaryRequestSchema` and writes sorted keys. TS
   sends `JSON.stringify` of the CLI object, unvalidated (G15).
2. `name="file"; filename="<metadata.original_file_name>"`, holding the file bytes.

Details:

- For the file part, Rust uses `BinaryFile::new(bytes)` with no content type, which is sent as
  `application/octet-stream` (`rs:multipart.rs:46-54`). TS sends a `Blob` from a `Buffer`,
  which is also `application/octet-stream` (`tsdk:13138-13153`). The bodies are equal modulo
  the boundary (`scm-sdk-<16 hex>` vs undici's).
- `BinaryFile::new` takes `impl Into<Bytes>`, and a `Vec<u8>` converts, so no `bytes`
  dependency is needed.
- Build the upload as `DictionaryUpload::new(metadata, file).include_keywords(true)`.
  `DictionaryUpload` is `Clone`, so the D95 401 replay can re-send it.

**After the 204 of a `replace`,** TS GETs the dictionary again (`get(id)` without keywords).
If that read fails, it prints `replaced <id> (state not echoed by region)`
(`cli:airs/dlp/dictionaries.ts:36-47`). Rust: `Ok(None)` → `get(id, None)` (a read) → the same
fallback.

**The TS region hint.** For a 400 with no problem `detail` and no `errors`, TS prints
`Dictionary upload rejected. Verify the SCM region display name …` (`cmd:dictionaries.ts:36-52`).
Rust can evaluate the same test on `error.problem()`: `detail()` is `Some` (possibly
`"[withheld]"`) whenever the server sent one, and `errors()` is `Some` when sent
(`rs:error/problem.rs:115-170`). The test is therefore exact without retaining server text.
The DLP-specific allowlist already exists in the SDK (`rs:error/problem.rs:8-62`:
`Required request part 'json' is not present`, `originalFileName`, `region_name`, …), so the
§6 message shows field-level reasons such as `originalFileName: must not be blank` (spec
`dlp-dictionary-errors.spec.ts:119-146`).

### 4.5 `backup` (TS `cmd:transfer.ts:200-293`, `bk:347-497`)

TS makes three complete inventories, each a `springPages` walk with `size=100`,
`sort=name,asc`, at most `--max-pages` pages, and strict consistency checks (`bk:118-253`):

- dictionaries `list({page,size:100,sort,keywords:true})`;
- patterns `list(...)`;
- profiles `list(...)`.

Then it makes no other request. Rust uses the same calls through the CLI walk (§5), so there
are only reads. Under G13, the proposal is to list dictionaries without keywords, then
`get(id, Some(true))` each custom dictionary the backup stores. These are bounded per-item
reads, and a failure is that dictionary's failed row rather than a dead walk. TS behaviour
(fail on any inventory error) is kept for the three walks.

### 4.6 `restore` (TS `cmd:transfer.ts:295-434`, `bk:776-1529`)

1. **Plan.** The three inventories (as backup), plus the tenant-identity checks on `tenant_id`
   (`bk:830-845`).
2. **Confirmation**, then a **recheck**: the three inventories again, and the plan is refused
   if anything changed (`bk:1308-1340`).
3. **Stages, in order.**
   - **Dictionaries.** `create(DictionaryUpload::text(metadata, rebuilt keywords).include_keywords(true))`.
     The file is `text/plain`, as in TS, where a string becomes a `text/plain` Blob
     (`tsdk:13138-13143`). Then a read-back `get(created, Some(true))`.
   - **Patterns.** `create`, then a read-back `get`.
   - **Profiles.** `create`, then a read-back `get`. Under `--on-conflict reconcile`, a 409
     (`Rejected`, so nothing was created) is followed by one more `create` under
     `<name>-<6 hex>` (`bk:1474-1484`). That is a different body after a definite rejection,
     not a replay, and it is safe.
4. **No updates, no deletes.** `DlpTransferApi` exposes only `list`, `create` and `get`
   (`bk:17-25`), and the port keeps that, so a restore never duplicates or overwrites. An
   existing same-name resource is reused only when it compares equal (`compareEcho`,
   `bk:543-598`). Otherwise the plan fails.
5. **Stop rule.** TS stops at the first failure of any kind and reports
   `unverifiedCreates` (`bk:1505-1527`). Rust adds the outcome classes: `Unknown`,
   unreadable (decode after a 2xx), `Rejected` and `NotSent`. At the first unknown or
   unreadable outcome, the run stops and every later row is `notAttempted`.

---

## 5. Walks (the CLI page loop, `dlp::walk`)

Do not use the SDK's `list_pages`, `list_items` or `list_all` (G12). Use one loop over the
single-page `list()` for all four resources, used by `list --all`, backup and restore:

- Start at `page = 0` (or the page `--offset` rounds down to: `floor(offset / limit)`, as TS
  `cli:cli/pagination.ts:91-123`). Use `size = --limit` (CRUD lists; default 50) or `size = 100`
  (inventories). Sort as given, else `name,asc`.
- Read the page metadata from the typed fields and from `extensions` (snake_case spellings:
  `total_pages`, `total_elements`, `number_of_elements`, `pageable.page_number`,
  `pageable.page_size`). Refuse disagreeing spellings, as in `bk:131-141`.
- **Inventories** (backup and restore) apply every `springPages` consistency rule (`bk:142-231`):
  - effective size stable and between 1 and 100;
  - totals stable;
  - `totalPages == ceil(totalElements / size)`;
  - `number`, `first`, `empty` and `offset` consistent;
  - a missing id or a duplicate id fails;
  - at most 10,000 records;
  - `last` agrees with the totals;
  - "did not advance" fails;
  - at most `--max-pages` pages (`Inventory of <label> is incomplete: increase --max-pages`).

  These are TS texts and fail closed. CRUD `--all` applies the D147 subset: an empty
  intermediate page and a repeated `id` are the D37 error, and `--max` cuts the walk with the
  D14 status line.
- `last` comes from `last`, else `totalPages`, else `items < size` (TS `listAll`,
  `tsdk:12696-12705`). Under the 300 s walk budget and the §7.2 byte bound.

This is a read-only CLI-side check, as `redteam::walk` is (D147), so it is safe.

---

## 6. Errors (what M6b adds to DESIGN §6)

- **No server text.** The SDK keeps only allowlisted problem fields, and all four TS DLP
  clients set `safeErrorMessages: true`. TS's CLI still echoes `err.message` through
  `usageError` for patterns and filtering profiles, so Rust's §6 messages differ there (they
  have no server text and exit 1, §12).
- **Write outcome words** (`writes::Change::Words`):

  | Command | Words |
  |---|---|
  | `patterns create\|replace\|patch\|delete` | `data pattern` / `created\|replaced\|patched\|deleted` |
  | `profiles create\|replace\|patch` | `data profile` / … |
  | `dictionaries create\|replace\|patch\|delete` | `dictionary` / … |
  | `filtering-profiles replace` | `filtering profile` / `replaced` |
  | restore rows | per kind, `created` |

  The detail lines are the §13.2 ones: `Outcome unknown: …` and `Outcome: … could not be read.`
- **Local SDK errors** are refused before dispatch, all outcome `NotSent`:
  - `ErrorKind::Validation` from `segment`, `query`, `BinaryFile::with_filename`, multipart
    names and metadata validation;
  - `ErrorKind::Limit` from the upload size.

  The CLI pre-validates every one of them in planning, so these paths are defensive only.
- **TS usage texts to keep** (exit 2, no request):
  - `Invalid dictionary metadata: verify required fields and value types`;
  - `Invalid profile metadata: verify required fields and value types`;
  - `Invalid JSON in dictionary metadata file`;
  - `Dictionary metadata must be a JSON object`;
  - `--body-file is mutually exclusive with --set/--clear`;
  - `--name, --category, --region, and --file are required`;
  - the merge-patch texts of `cmd:patch.ts`.

  None of them echoes file content (TS comment `cmd:dictionaries.ts:19`).
- **Restore and backup errors.** TS maps every SDK error to
  `DLP transfer API request failed (HTTP <n>); no automatic retry was made.`
  (`cmd:transfer.ts:80-96`), and restore results to
  `API request failed (HTTP <n>); verify destination state before retrying`
  (`bk:1507-1524`). The Rust rows carry the §6 message, which is equally free of server text.

---

## 7. Secrets and sensitive data

- **Sensitive content.** Dictionary keywords, pattern regexes, proximity keywords and
  metadata can be sensitive (TS `cli:cli/program.ts:116-127` forces
  `PANW_AI_SEC_DEBUG_BODY=0` for every `runtime dlp` command). The Rust debug log never
  records bodies or queries (D64), so the DLP policy is plain `log`, with no refusal. TS
  refuses `--debug` only for *profile* backup and restore, not for DLP transfer.
- **Typed models** never `{:?}`-print content: `DictionaryUpload`, `BinaryFile` and the params
  are redacted (`dlp:dictionaries.rs:44-48`, `rs:models/support.rs:349-352`).
- **Printed server text** (names, descriptions, region names) goes through `terminal_safe`.
  Descriptions keep their line breaks via `terminal_safe_lines` in pretty detail layouts.
  Server text is checked against the `SecretSet` (`[withheld]`) as in §15.3. Keyword lists and
  regexes are printed only in `json` and only when asked for (`get --keywords`). Pretty and
  table show counts, as in TS (`cli:cli/renderer/dlp.ts:362-412`).
- **Backups** hold keywords and regexes. That is why the file is written once with
  `files::publish_new` (0600, never overwriting, no partial file), why `--output-file -` is
  refused (TS text `Backups contain dictionary keywords and require a private file destination, not stdout`),
  and why no file content appears in an error.

---

## 8. Proposed safety rules beyond TS (§12 candidates from D160; to confirm)

1. **One attempt per write** (all DLP writes). TS CRUD retries a write after a 5xx up to 5
   times.
2. **Exit 1 for operational failures** of `patterns create|replace|patch` and
   `filtering-profiles replace`. TS exits 2 and echoes the SDK message.
3. **Confirmations (D81, as D137).** These commands get `--force`, with a TTY prompt and a
   non-interactive usage error:
   - `patterns delete` and `dictionaries delete`;
   - every `replace` (patterns, profiles, dictionaries, filtering profiles);
   - a non-dry-run `restore` that creates anything.

   TS confirms only `restore`. `patch` confirms nothing: it is a partial change, like topic
   updates.
4. **Predefined guard.** Before `replace`, `patch` and `delete` of a pattern, profile,
   dictionary or filtering profile, `get(id)` the record (one read). Refuse when
   `type == "predefined"` (also `is_parent_managed == true`, which is to confirm) with a usage
   message and exit 1. A create or replace body with `"type": "predefined"` (TS allows
   `patterns create --type predefined`) is a usage error in planning. TS has no such guard.
   The only protection it has is the `profiles delete` stub, which is kept.
5. **Dictionary metadata validated locally** with the closed category enum (G15) and the
   upload filename rules (G14). TS sends them unvalidated.
6. **Upload cap.** `--file` and `--metadata-file` follow the §13.2 input-file rules: a regular
   file, bounded, read once. The cap is 7 MiB, as for `prompt-sets upload`, so the 8 MiB SDK
   request bound is never the first to fire (G14).
7. **Backup.** Rust format only:
   - one file per run;
   - the default name `airs-dlp-backup-<UTC yyyymmddThhmmssZ>-<8 hex>.json` in the working
     directory, or `--output-file <path>`;
   - never overwrite, 0600, `publish_new`;
   - `--file-format` `json` only (yaml is a usage error);
   - lossless records.

   The envelope:
   ```json
   {"format":"airs-cli-rs.dlp-resources","version":1,"exportedAt":"…","tenant":"<store name>",
    "tsgId":"<mgmtTsgId>","resources":["dictionaries","patterns","profiles"],"complete":true,
    "dictionaries":[…],"patterns":[…],"profiles":[…],
    "skipped":[{"kind":"profile","name":"…","reason":"…"}],
    "failed":[{"kind":"dictionary","id":"…","name":"…","error":"<§6 message>"}]}
   ```
   - Records are stored as returned (typed responses re-serialised; lossless, §0), with
     predefined dependencies as the TS resolve-only stubs (`bk:378-404`).
   - `complete` is `false` exactly when `skipped` or `failed` is not empty.
   - `--skip-unsupported` keeps TS semantics: without it, unsupported profiles fail the run
     with no file.
8. **Restore.**
   - **The file.** Refuse a TS file (an object with `resourceType`, or a string or number
     `version` with no `format`; a `.yaml`/`.yml` file, or a `resourceType:` line) with the
     D152-style message naming `runtime dlp backup`. Refuse a newer `version`. Any other
     schema break gets a fixed reason, never content. `complete: false` gives a warning.
   - **TSG check** (as §15.19). The file's `tsgId` must equal the tenant's `mgmtTsgId`, unless
     `--allow-other-tenant` is given. TS's `--expect-tsg <id>` is kept as an extra assertion,
     checked before any request (TS text
     `--expect-tsg does not match the selected destination tenant; no API request was made`).
     TS's rule that `--force` requires `--expect-tsg` is kept: it is stricter than §15.19 and
     safe.
   - **Prefix and policies.** `--name-prefix` is kept: the prefix applies to custom
     resources, and the 32-unit profile limit is checked before any write. `--on-conflict`,
     `--pattern-map`, `--skip-unresolved` and `--max-pages` are kept with TS semantics.
   - **`--dry-run`** prints the plan and writes nothing.
   - **Never duplicates.** There are only creates and verified reuses, and a recheck before
     the first write.
   - **Stop rule.** It stops at the first unknown or unreadable outcome, and the rows after
     it are `notAttempted`.
9. **Formats.** `markdown`, `csv` and `yaml` are usage errors (D50 extended). `generate` is
   not a command (clap `unrecognized subcommand`, exit 2, as `redteam judge`, D1). The TS
   specs `tests/unit/dlp/**` and `tests/unit/cli/dlp-generate-*` are all `generate` specs
   (embed-*, lorem, rng, payload, manifest, orchestrate), so they have nothing to port.

---

## 9. Gaps

| # | Operation | What is missing or different | Evidence | CLI-side workaround |
|---|---|---|---|---|
| **G11** | `profiles delete`; live cleanup of data profiles | The API has no DELETE: an owned-fixture DELETE returned 501, and PATCH/PUT "retirement" returned 500. The SDK correctly has no `delete`. A UI-deleted profile reserves its name (409 on create) | `dlp:data_profiles.rs:19-151` (no delete); `cmd:profiles.ts:143-148`, `:255-266`; `docs:runtime/dlp/profiles.md:10`; `docs:runtime/dlp/transfer.md:215-218` | For the command, none is needed (no-request usage stub, TS parity). **For the live rule "create … delete a data profile", no safe workaround exists**: every live profile create leaves a permanent resource. **Blocker for the live design**: see §12.2 |
| **G12** | `list_pages`, `list_items` and `list_all` of all four clients | No duplicate-id, count-drift or metadata-consistency checks. Only the camelCase `totalPages` is read (dictionaries' snake_case `total_pages` sits in `extensions`). Without `last` it falls back to `items < size`, which ends early when the server caps the page size (dictionaries cap 100 → 50). Live tenants have repeated ids while omitting records when unsorted | `dlp:common.rs:107-141`; `dlp:dictionaries.rs:187-214`; `gen:155895-155996` (renames); `bk:110-116` | **Safe:** the CLI page loop over single-page `list()` (§5), a read-only check like D147 |
| **G13** | Dictionary `list` and `get` with `keywords=true` | The default `max_response_bytes` is 8 MiB (`rs:config.rs:286-299`), and validation allows 100,000 nodes per 8 MiB, capped at 1,000,000 (`rs:validation.rs:33-55`). A keyword-bearing page of 100 dictionaries can exceed either and fail with `Limit` ("Response exceeded a client safety limit"). TS has no such bound | `rs:engine.rs:411-422` | **Safe:** raise `max_response_bytes` on the DLP client (32 MiB → 400,000 nodes). Backups list without keywords and `get(id, Some(true))` per stored dictionary. A single dictionary over the bound is a `failed` row |
| G14 (difference) | Multipart create and replace | Request cap 8 MiB (`max_request_bytes`); filenames refused when empty, over 255 bytes, `.`, `..`, or containing a control character, `/`, `\` or `"`. TS has no cap and escapes quotes | `rs:models/support.rs:305-318`; `rs:multipart.rs:62-104`; `dlp:dictionaries.rs:98-115` | Usage errors in planning; §12 row |
| G15 (difference) | Multipart metadata | Rust validates it with `DictionaryRequestSchema` (closed `category` enum, required fields) before sending. TS create and replace send it unvalidated (no `requestSchema`) | `dlp:dictionaries.rs:100-103`; `tsdk:13229-13250`, `:13297-13315` | Safer; §12 row; a usage error before the tenant |
| G16 (ergonomics) | `DictionaryListParams`, `DataFilteringProfileListParams` | No `new()` or builders; `#[non_exhaustive]` with pub fields | `dlp:common.rs:38-74` | `Default::default()` plus field assignment |
| G17 (naming) | Debug operation names | `dlp.filtering_profiles.*` for the `data_filtering_profiles()` client; others are `dlp.data_patterns.*`, `dlp.data_profiles.*`, `dlp.dictionaries.*` | `dlp:filtering_profiles.rs:36`, … | Pin them in debug tests (as G9) |
| G10 (status) | DLP responses and backups | **No fabricated defaults.** Zero `ZodDefault` reachable from the DLP roots | Schema-graph walk, §0 | Nothing to do; scm-sdk 0.1.1's `Mode::ResponseWithoutDefaults` is not needed for DLP |

G3, G4 and G7 (`rs-sdk-writes.md`, `rs-sdk-redteam.md`) apply unchanged.

---

## 10. Proposed CLI module layout (mirrors `src/redteam` + `src/commands/redteam_*`)

| File | Contents |
|---|---|
| `src/dlp/mod.rs` | Argument checks: ids (segment rule), `--limit`, `--offset` with page rounding and the hidden `--size`/`--page` aliases, `--sort` (SDK bounds), `--max`, `--include-predefined` filter (`type != "predefined"`), resource-kind words |
| `src/dlp/body.rs` | Port of `build-body.ts`: pattern, filtering-profile and profile builders; `--body <json\|->`, `--body-file`, stdin through `input::read_piped_stdin`; every body parsed with the SDK request schema in planning |
| `src/dlp/patch.rs` | `--set` and `--clear` merge-patch (`cmd:patch.ts`), with no echo of values in errors |
| `src/dlp/walk.rs` | §5 page loop and the inventory consistency rules |
| `src/dlp/views.rs` | camelCase JSON (`cli:cli/renderer/dlp.ts:59-73`), ack objects, pretty and table layouts, `withhold` |
| `src/dlp/backup.rs` | Envelope document, `parse` (TS-file detection, fixed reasons), predefined stubs |
| `src/dlp/plan.rs` | Restore planner: `ruleLeaves`, bindings, `compareEcho`, `dictionaryFile` (CSV/TXT rebuild), candidate ranking, recheck |
| `src/commands/dlp_write.rs` | Shared connect, authenticate, confirm and predefined guard (as `redteam_write.rs`) |
| `src/commands/dlp_filtering.rs`, `dlp_patterns.rs`, `dlp_profiles.rs`, `dlp_dictionaries.rs` | The CRUD leaves |
| `src/commands/dlp_backup.rs` | `backup` and `restore` |

Existing modules:

- `clients.rs` gains `DlpClients`.
- `cli.rs` gains the `runtime dlp` clap tree: sorted subcommands, `ls` and `rm` aliases, no
  `generate`.
- `writes.rs` is unchanged; it uses `Change::Words`.
- `files::publish_new` is reused for backups.
- `Cargo.toml` lists `"dlp"` explicitly.
- `error.rs` gets a `Plane::Management` context, which it already has.

---

## 11. Fixture-server routes the loopback harness needs

A new `server/dlp.rs` with a seeded dataset (`fixtures_dlp.rs`), under the existing `/dlp`
prefix. Every route checks the `mock-token-<tsg>` bearer.

| Route | Behaviour |
|---|---|
| `GET /dlp/v2/api/data-filtering-profiles` | Spring page from `page`, `size` and repeated `sort`; records the query |
| `GET /dlp/v2/api/data-filtering-profiles/{id}` | Record, or 404 |
| `PUT /dlp/v2/api/data-filtering-profiles/{id}` | Replace and echo; counted (the live self-test asserts 0) |
| `GET` / `POST /dlp/v2/api/data-patterns` | Page; create assigns id, `version: 1` and `status: active`, and expands `supported_confidence_levels` (live behaviour, `bk:612-624`) |
| `GET` / `PUT` / `PATCH` / `DELETE /dlp/v2/api/data-patterns/{id}` | PATCH requires `Content-Type: application/merge-patch+json` and applies RFC 7386; DELETE sets `status: deleted` (soft) |
| `GET` / `POST /dlp/v2/api/data-profiles` | Page; create (with a knob for a 409 on an archived name); a name over 32 → 400 |
| `GET` / `PUT` / `PATCH /dlp/v2/api/data-profiles/{id}` | As patterns |
| `DELETE /dlp/v2/api/data-profiles/{id}` | **Trap**: 501, counted, must stay 0 |
| `GET` / `POST /dlp/v2/api/dictionaries` | Page with snake_case metadata, a size cap at 50, `keywords=true`; POST parses multipart (part names, filenames, content types, metadata JSON) and records a hash of the file bytes, never the bytes |
| `GET` / `PUT` / `PATCH` / `DELETE /dlp/v2/api/dictionaries/{id}` | PUT answers 200 with a body or 204 (knob) |

**Knobs**, through the existing `once`/`defaults` plans:

- page metadata styles: camelCase, snake_case, no `last`, inconsistent totals, repeated ids,
  an empty middle page, more than `--max-pages`;
- seeded predefined, deleted and disabled records, and mixed `tenant_id`;
- a 400 problem with allowlisted, non-allowlisted or no `detail`;
- a 401 once, a 403, a 5xx with `Retry-After: 0`, a held-then-dropped connection, a 2xx with
  malformed JSON, a 2xx with an empty body;
- per-route request counters.

Bodies that contain the markers `PRIVATE-KEYWORD` and `FAKE-SECRET-<tsg>` prove that nothing
leaks to stdout, stderr or the debug log.

---

## 12. Live-tier design for M6b (within the LIVE RULES)

### 12.1 Read comparison (`AIRS_RS_LIVE=1 AIRS_E2E_TENANT`; both CLIs; TS sandboxed as today)

- **Commands.** `runtime dlp filtering-profiles|patterns|profiles|dictionaries list --output json`
  (the default custom-only view; one page with `--limit 50`), then `get <first id> --output json`
  when a row exists (dictionaries without `--keywords`).
- **Comparison.** Compare the projections `id`, `name`, `type`, `status`/`profileStatus` and
  `version`, plus the full `get` documents (TS camelises them; Rust must match).
- **Backup.** `runtime dlp backup --skip-unsupported --output-file <run tmp>/<cli>.json` for
  each CLI. TS writes its own format. Compare only counts and the name sets per kind. Check
  0600, and remove both files with the temp dir. The summaries print counts only, never
  keywords or regexes. Both are read-only.

### 12.2 Write flow (`AIRS_RS_LIVE_DLP_WRITES=1`, on top of the read opt-ins)

- **Gate and resources.** `gate_with(lookup, "AIRS_RS_LIVE_DLP_WRITES", …)` refuses before any
  request. Per CLI, it creates one custom pattern and one dictionary, so 4 resources in all
  (≤ 10). Names follow
  `airs-rs-e2e-<unix>-<pid>-<n>-<pattern|dictionary>-<rs|ts>` (the existing `parse_name`
  shape with two new kinds).
- **Pattern.** `create` (regex `airs-rs-e2e-[0-9]{6}`, technique `regex`), then `get`, then
  `patch --set description=…`, then `replace --body-file` (same name, second regex), then
  `delete` (Rust `--force`). Expect a soft delete: `get` shows `status: deleted`.
- **Dictionary.** `create` with a two-line TXT of synthetic keywords and the region taken from
  the read phase's first dictionary `region_name` (else `AIRS_E2E_DLP_REGION`, else the
  dictionary flow is skipped with a notice). Then `get --keywords`, then
  `patch --set description=…` with name, category and original file name, then `replace`
  (new file), then `delete`.
- **Ledger.** Every create and delete goes to the ledger with new `Kind::Pattern` and
  `Kind::Dictionary`. Teardown deletes by id, also after a failure or a panic.
- **The sweeper** lists `patterns list --all` and `dictionaries list --all` (Rust, json) and
  deletes only `active` prefixed names older than 1 h.
- **Data profile: not live (G11). The user must confirm this.** No CLI and no API can delete a
  profile, a deleted name stays reserved, and live PATCH/PUT returned 500. Any live profile
  create would break "all deleted at the end". Profile create, replace and patch are covered
  on loopback only. If the user wants live coverage anyway, the only option is one permanent,
  journalled profile per run. That is not recommended.
- **Never live:**
  - `filtering-profiles replace`;
  - any write to a predefined record;
  - `profiles delete` (it sends nothing anyway).

### 12.3 Restore (live)

`restore --dry-run --on-conflict skip` of each CLI's own backup into the same tenant: only
reads, so the TSG matches and no `--allow-other-tenant` is needed. A non-dry-run restore is
**not** live, for three reasons:

- the backup holds every custom resource of the tenant, so a restore with `--name-prefix`
  would create more than 10 copies;
- it would include profiles, which cannot be deleted (G11);
- restricting it to run-created resources would need a selection option that neither CLI
  has.

### 12.4 Loopback self-tests (`LiveTarget::loopback`)

- The gate unset gives zero recorded requests.
- Every POST and PUT body name starts with the run prefix.
- No `PUT …/data-filtering-profiles/*`, no non-GET to `…/data-profiles*`, and no write to a
  seeded predefined id.
- No file is written outside the sandbox (runner guard).
- The ledger has a matching `ok` delete for every `ok` create.
- An injected 500 on `patch` still tears everything down.
- The sweeper ignores names that are young, unprefixed or of the wrong kind, and `deleted`
  patterns.
- The backup files are 0600 and are removed.

---

## 13. Choices to record and confirm

1. Live data-profile writes are dropped (G11). The live rule asks for them, but they cannot be
   cleaned up.
2. The predefined guard (§8.4): one extra GET before each replace, patch and delete; whether
   `is_parent_managed` also blocks.
3. Confirmations on every `replace` and on the deletes, plus `restore` (§8.3); `patch` does not
   confirm.
4. Restore keeps `--expect-tsg` (and `--force` ⇒ `--expect-tsg`) **and** adds
   `--allow-other-tenant` for a cross-TSG file.
5. Backups read dictionary keywords per dictionary (G13), not from the keyword-bearing listing
   TS uses. This means more requests and bounded responses.
6. The upload cap is 7 MiB, and the filename rules are those of the SDK (G14).
7. `--on-conflict reconcile` is kept (one suffixed create after a 409).
