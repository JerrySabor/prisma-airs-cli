# Rust SDK for M6c (0.8): Model Security

Scope: every `model-security` command of the frozen TS CLI (5711012): `groups list|get|create|update|delete`,
`rules list|get`, `rule-instances list|get|update`, `scans list|get|create|evaluations|evaluation|violations|violation|files`,
`models list|get|versions|version|files`, `labels add|set|delete|keys|values`, `pypi-auth` and `install`.
For each one, this file gives the `scm-sdk` 0.1.1 API that serves it and compares it with the HTTP calls
the TS CLI makes through its SDK 0.34.0. It ends with the proposed module layout, the fixture routes,
the live-tier design and the `install`/`pypi-auth` mechanics.

Method. Everything here was read from source, with five exceptions, all in the session scratchpad:

- `--help` runs of the reference build, with a scratch `HOME` and scratch XDG directories.
- A read-only Python walk of the SDK's frozen schema graph.
- Four offline runs of the local uv 0.12.17 (`/opt/homebrew/bin/uv`) against a loopback fake PyPI index.
  They used `UV_NO_CONFIG=1`, `UV_CACHE_DIR`, `UV_PYTHON_INSTALL_DIR`, `HOME` and the XDG dirs all inside
  the sandbox, `UV_PYTHON_DOWNLOADS=never`, a loopback default index and a fake credential (§12.2).
- One fetch of the official `sha256.sum` of uv 0.12.17 from GitHub. This was the only non-loopback
  request.
- No Rust was built, and no tenant or credential file was read.

Citation prefixes:

- `rs:` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/scm-sdk-0.1.1/src/`;
  `ms:` = `rs:airs/model_security/`; `gen:` = `rs:models/generated.rs`.
- `tsdk:` = `.reference/prisma-airs-cli/node_modules/@cdot65/prisma-airs-sdk/dist/index.js` (0.34.0).
- `cli:` = `.reference/prisma-airs-cli/src/`; `cmd:` = `cli:cli/commands/modelsecurity.ts`;
  `svc:` = `cli:airs/modelsecurity.ts`; `rnd:` = `cli:cli/renderer/modelsecurity.ts`.
- `docs:` = `.reference/prisma-airs-cli/docs-site/docs/`; `here:` = this repository.

Companion specs: `rs-sdk-foundation.md` (engine, auth), `rs-sdk-management.md`, `rs-sdk-writes.md`
(G1–G6, D95), `rs-sdk-redteam.md` (G7–G10), `rs-sdk-dlp.md` (G11–G17). This file covers only what M6c
adds, and its gap numbers continue from G17.

---

## 0. Summary

- **Every M6c API command has an SDK operation.** Paths, methods, request schemas and response
  schemas match the TS SDK one for one (`ms:*.rs` vs `tsdk:13657-14659`). The bases are
  `modelSecDataEndpoint` (default `…/aims/data`) and `modelSecMgmtEndpoint` (default `…/aims/mgmt`)
  (`rs:constants.rs:630-631` = `tsdk:75-76`). The data plane serves scans, evaluations, violations,
  files, labels and models. The management plane serves groups, rule instances, rules and PyPI auth.
  The SDK client also has custom-rule and snapshot-version operations, but the TS CLI exposes neither,
  so they are out of scope.
- **The `model-security` feature must be enabled.** It is `model-security = ["models"]`
  (`rs:../Cargo.toml:66`). It adds no dependency and does not change the lock file. Today
  `here:Cargo.toml` enables `reqwest-transport, scan, management, red-team, dlp`.
- **Schema defaults (G10) do reach model-security output.** The schema-graph walk from all 34
  model-security roots finds `ZodDefault` in exactly two places:
  - `EvalSummary.{rules_failed, rules_passed, total_rules}` default to `0`. They are reachable from
    `ScanBaseResponse`, `ScanList`, `ModelVersionResponse` and `ModelVersionList`. With the SDK
    default, a scan whose summary omits a count prints `0 failed`, which is a fabricated clean result.
    **`RequestOptions::without_response_defaults()` is required** on `scans list|get|create` and
    `models versions|version`. I recommend it on every model-security call, through one options
    helper.
  - `ModelSecurityGroupCreateRequest.description` defaults to `""` in request mode. Both CLIs
    therefore send `"description": ""` when the config has none. This is parity, not a difference.

  Every other object is `passthrough`, and no response schema has an enum, so D178 does not arise.
- **One attempt per write holds by construction.** Every write is `RawRequest::new(METHOD, …)`, so
  `replay_safe = false` (`rs:engine.rs:49-61`, `:1173-1236`):
  - groups create, update and delete;
  - rule-instance update;
  - scans create;
  - labels add, set and delete.

  `writes::attempt` adds the D95 single replay after a 401. The TS SDK re-sends every one of them up to
  5 times on 500/502/503/504 and network errors, and once after a 401 or 403 (`tsdk:30-31`,
  `:9786-9848`, `:10865`, `:11099-11114`). That includes the **billed `scans create`**. This is the
  D179 candidate.
- **Gaps (§9).** No SDK patch is needed, and no M6c behaviour is skipped.
  - **G18**: `scans list --scan-origin` has no SDK query field. TS silently drops it too. A local
    row filter is a safe workaround.
  - **G19**: the SDK's skip/limit walks lack the D147 checks, so the CLI reuses the red team loop.
  - **G20**: the G10 defaults above.
  - **G21–G24**: differences and ergonomics (segment rule, non-exhaustive options, operation names,
    a plain-`String` PyPI URL).
- **`pypi-auth` and `install` are settled with evidence (§12).** uv 0.12.17 never persists the index
  credential: not in `pyproject.toml`, not in `uv.lock`, not in the cache or the venv. This holds
  whether the credential comes from argv, from `UV_INDEX` or from `UV_INDEX_<NAME>_PASSWORD`, and its
  trace log masks the password. The proposal:
  - the credential travels only in the child's environment, as `UV_INDEX_<NAME>_USERNAME` and
    `UV_INDEX_<NAME>_PASSWORD`;
  - argv carries `--index prisma-airs-model-security=<credential-free URL>`;
  - uv's output is piped through a secret scrub;
  - a post-run scan of the written files checks that the credential is absent;
  - `--fetch-uv` pins uv **0.12.17** with the six official archive SHA-256 values (§12.4).

---

## 1. Client construction

### 1.1 The TS side

- `createService()` (`cmd:81-84`) calls `modelSecurityClientOptions(loadConfig())`
  (`cli:config/client-options.ts:71-77`). That passes `mgmtClientId`, `mgmtClientSecret`,
  `mgmtTsgId`, `mgmtTokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT`,
  `modelSecDataEndpoint ?? DEFAULT_MODEL_SEC_DATA_ENDPOINT` and `modelSecMgmtEndpoint ?? …MGMT…`.
- `new ModelSecurityClient(opts)` (`tsdk:14588-14637`) builds one `OAuthAuth` and five sub-clients.
  `scans` and `models` use the data endpoint. `securityGroups`, `securityRules`, `customRules` and
  `getPyPIAuth` use the management endpoint.
- `numRetries` defaults to 5 for every method. The CLI passes concrete values for everything, so the
  `PANW_MODEL_SEC_*` and `PANW_MGMT_*` env fallbacks (`tsdk:14603-14613`, `:11099-11103`) are never
  used. The harness also strips those variables (`here:crates/airs-test-harness/src/runner.rs:539-541`).
- No `x-tsg-id` header is sent (plain `OAuthAuth`).

### 1.2 The Rust side (proposed `clients::ModelSecurityClients`)

Mirror `DlpClients::build` (`here:src/clients.rs:536-584`):

1. **Admit the endpoints:**
   - `admit("modelSecDataEndpoint", config.effective_str("modelSecDataEndpoint"), scm::constants::DEFAULT_MODEL_SEC_DATA_ENDPOINT)`;
   - the same for `modelSecMgmtEndpoint`;
   - `mgmtTokenEndpoint` with `DEFAULT_TOKEN_ENDPOINT`.

   D48 messages apply. Both keys are already known tenant keys (`here:src/tenant/config.rs:26-27`),
   and the fixture tenant sets them to `<base>/aims/data` and `<base>/aims/mgmt`
   (`here:crates/airs-test-harness/src/sandbox.rs:81-82`).
2. **Build the identity and transport** with
   `oauth_parts(config, &issuer, &[data.clone(), mgmt.clone()], session, secrets, debug, &LastStatus::default())`.
   This uses the management OAuth plane only, so scanner credentials are never sent.
3. **Set the limits:** `Limits::default()` with `max_retries = MANAGEMENT_RETRIES` (5, reads only).
   The default 8 MiB response bound suffices, because no model-security payload is bulk text.
4. **Build the client:** `Client::builder(data).transport(..).destination_policy(..).authentication(Authentication::oauth(provider, false)).session(..).limits(..).build()`,
   then `scm::airs::model_security::ModelSecurityClient::new(client, data, mgmt)`.
   - `new` requires OAuth, turns off the TSG header and re-scopes one client per plane
     (`ms:client.rs:28-34`, `ms:mod.rs:36-39`). That matches TS (no TSG header).
   - On failure, report `AISEC_SDK_ERROR:The model security client could not be configured` (exit 1).
5. **Authenticate:** `authenticate(options, budget)` as `DlpClients::authenticate`, so a token
   failure is `AISEC_OAUTH_ERROR:…`.
6. **Sub-clients** are cheap clones: `scans()` and `models()` (data), `security_groups()` and
   `security_rules()` (management), plus `get_pypi_auth()` on the client itself (management).

### 1.3 Options and budgets

| Call | `RequestOptions` |
|---|---|
| Single request | `RequestOptions::with_timeout(SINGLE_REQUEST_BUDGET)?.without_response_defaults()` (`rs:config.rs:368`, `:406-409`) |
| `--all` walks, the delete verification | `with_timeout(WALK_BUDGET)` per walk, plus `.without_response_defaults()` |

Never use `with_retries(0)` on a read: it also drops the 401/403 refresh (G7).

---

## 2. Engine behaviour for model-security calls

| Call shape | SDK path | SDK replay | Outcome on failure |
|---|---|---|---|
| GET list or get | `RawRequest::read(PATH).segment(id)?.named("airs.model_security.*").query(..)` → `send_contract` | up to `max_retries` on transport errors and 429/502/503/504 (`Retry-After` ≤ `max_retry_delay`), plus one 401/403 refresh (`rs:engine.rs:1173-1236`, `:1345-1349`, `:1372-1374`). TS: 500/502/503/504 and network, 5 retries (D10 applies) | read errors per §6 |
| POST or PUT JSON | `RawRequest::new(..)` → `send_model(body, req_schema, resp_schema)` (`ms:groups.rs:21-36`, `:113-131`, `:182-204`; `ms:scans.rs:107-122`, `:248-287`) | never | `NotSent` before dispatch (validation, `Limit`, token); `Rejected` for 3xx/4xx; `Unknown` for 5xx, post-dispatch transport errors and cancels (G3); a 2xx decode error carries the status (G4) |
| DELETE | `RawRequest::new(DELETE, …)` → `send_empty` (`ms:groups.rs:132-142`; `ms:scans.rs:288-309`, with `keys` repeated in the query) | never | as above; any 2xx body is ignored |

**Request bodies.** `send_model` validates the typed model in `Mode::Request`, which inserts request
defaults (the group `description: ""`), and re-serialises it with sorted keys (D35). The CLI parses
every input file or JSON argument itself during planning with `<Model>::parse(value, Mode::Request)`.
That makes schema failures usage errors before the tenant, and unknown keys survive in `extensions`.

| Body (`gen:` line) | Required | Notes |
|---|---|---|
| `ModelSecurityGroupCreateRequest` (152571) | `name`, `source_type` (closed: `LOCAL HUGGING_FACE S3 GCS AZURE ARTIFACTORY GITLAB ALL`) | `description` gets the default `""`; `rule_configurations` is a typed map of `RuleConfiguration`; the TS CLI picks only these four keys from `--config` (`cmd:158-164`) |
| `ModelSecurityGroupUpdateRequest` (152973) | none (`name` and `description` are `Patch`, nullable) | TS sends `{}` when neither flag is given (`cmd:181-184`), and ignores `--name ""` (truthiness) |
| `ModelSecurityRuleInstanceUpdateRequest` (153487) | `security_group_uuid` (the CLI fills it from the positional, `svc:335-339`) | `state` is closed (`DISABLED ALLOWING BLOCKING`); `field_values` is a JSON map |
| `ScanCreateRequest` (163192) | `model_uri`, `security_group_uuid` | `scan_origin` is closed (`MODEL_SECURITY_SDK MODEL_SECURITY_API MODEL_SECURITY_FRONTEND HUGGING_FACE`); passthrough, and TS sends the whole `--config` object (`cmd:583-584`) |
| `LabelsCreateRequest` (145464) | `labels`: an array of `{key, value}` strings | TS wraps whatever `JSON.parse(--labels)` returns (`svc:516-522`) |

A closed request enum refuses an unfamiliar value locally on both sides. TS refuses it only after the
tenant is read; Rust refuses it in planning, as a usage error.

**Responses** (`gen:` fields; all `passthrough`, unknown keys in `extensions`, no enums):

- `ScanBaseResponse` (162831) requires `uuid tsg_id created_at updated_at model_uri owner scan_origin security_group_uuid security_group_name eval_outcome source_type`.
  `eval_summary` is a `Patch<EvalSummary>`, and `labels` is an `Optional`.
- `ModelSecurityGroupResponse` (152743) requires `uuid tsg_id created_at updated_at name description source_type state is_tombstone`.
- `ModelSecurityRuleInstanceResponse` (153150) requires `uuid tsg_id security_group_uuid state`.
  `rule` is a `Patch`, and `field_values` is an `Optional` map.
- `ModelSecurityRuleResponse` (153633) requires `uuid name description rule_type compatible_sources default_state remediation editable_fields constant_values default_values`.
- The remaining types (`RuleEvaluationResponse` 161475, `ViolationResponse` 181142, `FileResponse`
  35100, `ModelResponse` 152050, `ModelVersionResponse` 153932, `PyPIAuthResponse` 158960) carry the
  fields the TS normalisers read.
- `Patch` keeps unset, `null` and a value apart. That is exactly what the TS views need: an absent
  key is omitted, and `null` is printed as `null` (`svc:151-158`, `:172-183`).
- The required sets are the frozen zod sets, so a record missing one fails both CLIs alike (parity).

---

## 3. Common API facts the CLI must know

- **Pagination is skip/limit.**
  - Every list sends `skip` and `limit` (`ms:query.rs:33-41`). The SDK refuses `limit = 0` and values
    above 2^53−1 with `Validation`. The CLI checks `--limit`, `--offset` and `--max` first (D17).
  - Every page carries `pagination.total_items` (`Patch<FiniteNumber>`, `gen:153067`).
  - `ScanList` also has `count_capped: Optional<bool>` (`gen:163829`). When it is true, the total is
    a cap, not a count. The SDK walk latches this and then ignores the total (`ms:scans.rs:160-168`).
    TS ignores `count_capped`, so its `scans list --all` stops at the capped total (D183).
- **Ids.**
  - Every UUID parameter is checked locally by the SDK with the same rule as TS: 36 characters, hex
    digits with dashes at positions 8, 13, 18 and 23, any case. Compare `rs:data.rs:324-333` with
    `tsdk:9555-9558`. A bad id is `Validation`, `NotSent`.
  - TS checks after the tenant and the banner (`tsdk:11148-11155`, `Invalid scan uuid: <value>`).
  - The CLI checks with `pagination::is_uuid` (`here:src/pagination.rs:98-107`), as a usage error
    before the tenant.
  - The label key in `labels values <key>` is not a UUID. It goes through `.segment(key)`
    (`ms:scans.rs:352-354`), which refuses `.`, `..`, `\`, control characters and recursively encoded
    traversal, and encodes `/` (G21).
- **Array filters** repeat the key: `eval_outcomes=X`, `source_types=a&source_types=b` and so on
  (`ms:query.rs:48-55`). TS does the same (`url.searchParams.append`, `tsdk:10119-10122`).
- **Option structs are `#[non_exhaustive]` with `Default`** (G22). Build them as
  `let mut q = ModelSecurityGroupListOptions::default(); q.limit = Some(n); …`.
- **Soft delete of groups.** A successful `DELETE /v1/security-groups/{id}` does not remove the group
  at once: a `get` may still return it (`svc:276-292`, prisma-airs-cli#239). The response carries the
  required `is_tombstone: bool` (`gen:152743`), which TS never reads.
- **Scans cannot be deleted.** Neither SDK has a scans DELETE. Labels are the only mutable part of a
  scan (§13).
- **Debug operation names** are fixed (G23): `airs.model_security.groups.{create,list,get,update,delete,list_rule_instances,get_rule_instance,update_rule_instance}`,
  `….rules.{list,get}`, `….scans.{create,list,get,get_evaluations,get_files,add_labels,set_labels,delete_labels,get_violations,get_label_keys,get_label_values,get_evaluation,get_violation}`,
  `….models.{list_models,get_model,list_model_versions,get_model_version,list_model_version_files}`,
  and `airs.model_security.get_pypi_auth`.

---

## 4. Command → SDK map

"TS" gives the options as `--help` lists them after `applyReadContractFlags`
(`cli:cli/program.ts:52-69`). That function adds `--output` to every `list` and `get`, and
`--offset`/`--all`/`--max` to every `list` that has `--limit`. Each Rust call is
`ms.<sub>().<op>(…, Some(&options))`, with the options of §1.3. "G10" marks the calls where
`without_response_defaults()` changes the output.

### 4.1 `groups` (management; `ms:groups.rs`; TS `tsdk:14024-14307`)

| Command (TS options) | Rust | Wire | Notes |
|---|---|---|---|
| `list\|ls` (`--source-types --search --sort-field --sort-dir --enabled-rules --limit`="20" `--offset`=0 `--all --max`=10000 `--output`) | `security_groups().list(&q)`; `--all`: CLI loop (§5) | `GET /v1/security-groups?skip&limit&sort_field&sort_dir&source_types*&search_query&enabled_rules*` | `--search` → `search_query`. The comma lists are split and trimmed (`cmd:112-124`). TS always sends `skip=0` (`Number(opts.offset ?? 0)`), and `--limit abc` sends `limit=NaN` (D17) |
| `get <uuid>` (`--output`) | `.get(id)` | `GET /v1/security-groups/{uuid}` | |
| `create --config <path>` | `.create(&body)` (one attempt) | `POST /v1/security-groups` | Body from the four picked keys (§2). Pretty prints `Group created: <uuid>` and then the detail. TS has no `--output` here (M4 rule: Rust honours the global one) |
| `update <uuid>` (`--name --description`) | `.update(id, &body)` (one attempt) | `PUT /v1/security-groups/{uuid}` | An empty update is a usage error in Rust (D187) |
| `delete\|rm <uuid>` | `.delete(id)`, then `.get(id)` | `DELETE …/{uuid}`, then `GET …/{uuid}` | TS reports deleted when **any** error follows the delete (`svc:284-291`); its specs pin 404 → confirmed and state → warning (`tests/unit/airs/modelsecurity.spec.ts:274-304`). Rust adds the D81 confirmation with `--force` (D186) and the verification of D185 |

### 4.2 `rules` and `rule-instances` (management; `ms:inventory.rs:253-354`, `ms:groups.rs:143-204`)

| Command (TS options) | Rust | Wire | Notes |
|---|---|---|---|
| `rules list\|ls` (`--source-type --search --limit`="20" `--offset --all --max --output`) | `security_rules().list(&q)`; CLI loop | `GET /v1/security-rules?skip&limit&source_type&search_query` | `--search` → `search_query` (`cmd:482-487`) |
| `rules get <uuid>` (`--output`) | `.get(id)` | `GET /v1/security-rules/{uuid}` | TS reads `opts.output` raw, without `resolveOutput` (`cmd:500-505`), so a tenant `defaultOutput` is ignored. Rust resolves it as every other read does |
| `rule-instances list\|ls <groupUuid>` (`--security-rule-uuid --state --limit`="20", plus the added `--offset --all --max --output`) | `security_groups().list_rule_instances(g, &q)`; CLI loop | `GET /v1/security-groups/{g}/rule-instances?limit&security_rule_uuid&state` | TS ignores `--offset`, `--all` and `--max` (`cmd:417-423`). Rust honours them (D184, as D147) |
| `rule-instances get <g> <i>` (`--output`) | `.get_rule_instance(g, i)` | `GET …/{g}/rule-instances/{i}` | |
| `rule-instances update <g> <i> --config <path>` | `.update_rule_instance(g, i, &body)` (one attempt) | `PUT …/{g}/rule-instances/{i}` | Body `{security_group_uuid: g, state?, field_values?}` (`svc:335-339`). A config with neither field is a usage error in Rust (D187) |

### 4.3 `scans` (data; `ms:scans.rs`; TS `tsdk:13657-14022`)

| Command (TS options) | Rust | Wire | Notes |
|---|---|---|---|
| `list\|ls` (`--model-version --start --end --eval-outcome --source-type --scan-origin --search --limit`="20" `--offset --all --max --output`) | `scans().list(&q)`; CLI loop with the `count_capped` latch | `GET /v1/scans?skip&limit&search&model_version_uuid&eval_outcomes&source_types&start_time&end_time` | **G10.** `--start` and `--end` must be ISO datetimes with an offset (zod `datetime({offset:true})`), with start ≤ end; `--model-version` must be a UUID (`cmd:38-54`). A usage error before the tenant in Rust; after it in TS. `--scan-origin` goes nowhere (G18, D182). **TS `--all` sends `search_query=<--search>` where a single page sends `search`** (`svc:409` vs `:433`). Mirror it per mode (choice 4) |
| `get <uuid>` (`--output`) | `.get(id)` | `GET /v1/scans/{uuid}` | **G10** |
| `create --config <path>` | `.create(&body)` (one attempt, billed) | `POST /v1/scans` | **G10** on the answer. An outcome-unknown failure prints `Outcome unknown: the scan may have been created.`; TS re-POSTs up to 5 times (D179) |
| `evaluations <scanUuid>` (`--limit`="20") | `.get_evaluations(id, &q)` | `GET /v1/scans/{id}/evaluations?limit` | No `--offset` or `--all` in TS; mirror |
| `evaluation <uuid>` | `.get_evaluation(id)` | `GET /v1/evaluations/{uuid}` | |
| `violations <scanUuid>` (`--limit`) | `.get_violations(id, &q)` | `GET /v1/scans/{id}/rule-violations?limit` | |
| `violation <uuid>` | `.get_violation(id)` | `GET /v1/violations/{uuid}` | |
| `files <scanUuid>` (`--type --result --limit`) | `.get_files(id, &q)` (`q.type_`, `q.result`) | `GET /v1/scans/{id}/files?limit&type&result` | |

### 4.4 `models` (data; `ms:inventory.rs:12-252`)

| Command (TS options) | Rust | Wire | Notes |
|---|---|---|---|
| `list\|ls` (`--start --end --search --search-query --sort-field --sort-order --limit` (no default) `--offset --all --max --output`) | `models().list_models(&q)`; CLI loop (page size 50 when `--limit` is absent, as `collectSkipPages`, `tsdk:10813-10825`) | `GET /v1/models?skip&limit&search&search_query&sort_field&sort_order&start_time&end_time` | Without `--limit`, no `limit` is sent (server default), as in TS (`cmd:702-705`) |
| `get <uuid>` | `.get_model(id)` | `GET /v1/models/{uuid}` | |
| `versions <modelUuid>` (`--sort-order --limit --offset --output`) | `.list_model_versions(id, &q)` | `GET /v1/models/{id}/model-versions?skip&limit&sort_order` | **G10.** Not named `list`, so TS adds no `--all` |
| `version <uuid>` | `.get_model_version(id)` | `GET /v1/model-versions/{uuid}` | **G10** |
| `files <modelVersionUuid>` (`--limit --offset --output`) | `.list_model_version_files(id, &q)` (`q` is the label-list options alias, `ms:query.rs:560`) | `GET /v1/model-versions/{id}/files?skip&limit` | |

### 4.5 `labels` (data; `ms:scans.rs:248-361`)

| Command (TS options) | Rust | Wire | Notes |
|---|---|---|---|
| `add <scanUuid> --labels <json>` | `scans().add_labels(id, &body)` (one attempt) | `POST /v1/scans/{id}/labels` | Merges. Prints `Labels added.` |
| `set <scanUuid> --labels <json>` | `.set_labels(id, &body)` (one attempt) | `PUT /v1/scans/{id}/labels` | **Replaces all labels**, so it drops data: D81 confirmation plus `--force` (D186) |
| `delete\|rm <scanUuid> --keys <a,b>` | `.delete_labels(id, &keys)` (one attempt) | `DELETE /v1/scans/{id}/labels?keys=a&keys=b` | D81 confirmation plus `--force`. Keys are split and trimmed (`cmd:340`); an empty key is a usage error in Rust |
| `keys` (`--limit`="20") | `.get_label_keys(&q)` | `GET /v1/scans/label-keys?limit` | TS prints pretty only (`rnd:506-517`); for Rust json, see choice 13 |
| `values <key>` (`--limit`) | `.get_label_values(key, &q)` | `GET /v1/scans/label-keys/{key}/values?limit` | Segment rule (G21) |

### 4.6 `pypi-auth` and `install`

| Command | Rust | Wire | Notes |
|---|---|---|---|
| `pypi-auth` | `ms.get_pypi_auth(Some(&options))` → `PyPIAuthResponse { url: String, expires_at: String }` (`ms:client.rs:74-86`; `Debug` is redacted, `gen:159042-159046`) | `GET <mgmt>/v1/pypi/authenticate` | The `url` is credential-bearing: `https://oauth2accesstoken:ya29.<token>@us-west1-python.pkg.dev/<project>/<repo>/simple/` (`docs:cli/model-security/pypi-auth.md`). TS prints it whole (`cmd:391-396`). Rust output: §12.1 |
| `install` (`--extras`="all" `--dir`="model-security" `--dry-run`, plus Rust `--fetch-uv`) | the same `get_pypi_auth`, then uv child processes | `GET …/pypi/authenticate` | TS runs `uv init <dir>`, then `uv add --project <dir> <pkg> --index <credential URL>`, or the python3 venv and pip fallback (`cmd:216-293`). Rust: §12.2–§12.4 |

---

## 5. Walks (`--all`)

Do not use the SDK's `pages`, `list_all`, `list_all_models` or the version and file walks (G19).
`next_skip` ends silently on an empty page even when `total_items` says more exist
(`ms:mod.rs:63-73`). It has no repeated-row check. `list_all` defaults to 10,000 items, 1,000 pages
and 64 MiB with SDK truncation semantics (`rs:pagination.rs:47-60`).

Instead, reuse the red team skip/limit loop (`here:src/redteam/walk.rs:59-140`, D147):

- the limit is `--limit` (TS uses it as the page size, `svc:232-243`);
- `total` is `pagination.total_items` as a safe integer;
- the key is the row `uuid`;
- the bounds are 100,000 pages, 512 MiB and 1,000,000 items (D40);
- an empty page while `skip < total` is the D37 error;
- a repeated `uuid` is the D37 error;
- `--max` truncates (`stopped_at_max`).

For scans, the fetch closure latches `count_capped == true` across pages and then passes `total: None`,
which is the SDK's own rule (`ms:scans.rs:160-168`). Recommendation: move `walk.rs` to `src/walk.rs`
as a shared skip/limit walker, with red team and model security as callers.

The single-page status lines reuse `pagination::showing_*`. TS prints no status lines for these lists,
so the existing rows apply.

---

## 6. Errors (what M6c adds to DESIGN §6)

- **Planes.** Every model-security call is `Plane::Management`. Reads use `Operation::Read`, and every
  POST, PUT and DELETE uses `Operation::Write` with `writes::describe` and `Change::Words`:
  - `("security group", "created" | "updated" | "deleted")`;
  - `("rule instance", "updated")`;
  - `("scan", "created")`;
  - `("labels", "added" | "replaced" | "deleted")`.
- **Local SDK refusals** (`Validation`, `Limit`, `NotSent`) cannot occur once planning has checked
  ids, numbers and bodies. If one does occur anyway, it is the §6 SDK-error text, never echoing input.
- **Delete verification** (D185):
  - a `get` answering 404 (`ErrorKind::Http`, `status() == Some(404)`) confirms the delete;
  - a 2xx with `is_tombstone: true` reads `Group <uuid> deleted (the service is removing it).`;
  - a 2xx with `is_tombstone: false` gets the TS warning and its dim hint;
  - any other failure gets `Delete request accepted, but the group's removal could not be verified.`
    The exit code is 0, because the DELETE itself succeeded.
- **The PyPI URL never reaches an error.** Any failure after `get_pypi_auth` is built from SDK
  metadata only, and the URL, its userinfo and its password join the `SecretSet` the moment they are
  parsed (§12.1).

---

## 7. Secrets and sensitive data

| Data | Rule |
|---|---|
| PyPI URL userinfo (an OAuth access token) | Never printed, logged or persisted: §12 |
| Group, rule, scan, label and violation text | Server text: `output::terminal_safe` / `terminal_safe_lines`, checked against the `SecretSet` |
| `--labels` JSON and `--config` files | Never echoed in errors (§2 messages name the flag and the schema path only, as `tsdk:10105-10115`) |
| `--debug` | Status and headers only. The pypi request URL has no query, and the response body is never logged |

---

## 8. Proposed §12 rows (candidates, from D179)

Each row needs its `dNN_` parity test and a COMPATIBILITY.md row.

| # | Area | TypeScript | Rust (proposed) | Why |
|---|---|---|---|---|
| D179 | model-security write attempts (groups create/update/delete, rule-instance update, scans create, labels add/set/delete) | re-sent up to 5× on 500/502/503/504 and network errors, and once after 401/403 (`tsdk:9786-9848`) | one attempt; a 401 replayed once; outcome-unknown and unreadable lines (D95 shape) | a replayed `scans create` bills a second scan; a replayed delete or replace repeats a destructive write |
| D180 | eval summary counts the server omitted (`scans list/get/create`, `models versions/version`) | `0` (zod default plus `?? 0`, `svc:94-96`, `:186-188`) | only what the server sent: JSON `null`, pretty `?`, table empty (`without_response_defaults()`, G20) | a fabricated `0 failed` is a fail-open display |
| D181 | `scans list --scan-origin` | accepted and silently ignored (`svc:408`; `tsdk:13622-13638` drops it) | rows filtered locally by exact `scan_origin`, with the §5 walk for `--all` (G18) | a filter must not be silently dropped |
| D182 | `scans list --all` when the service caps the count (`count_capped: true`) | stops at the capped `total_items`, reported as complete | keeps walking full pages, ignoring the capped total (the SDK rule) | an incomplete walk is never complete |
| D183 | `rule-instances list` `--offset/--all/--max` | listed in help, ignored (`cmd:417-423`) | honoured | flags do what help says (D147) |
| D184 | `groups delete` verification | any error after the DELETE → `Group … deleted.` (`svc:289-290`) | 404 or `is_tombstone: true` confirm; other failures → "could not be verified" (exit 0) | a timeout is not proof of deletion |
| D185 | confirmations (`groups delete`, `labels set`, `labels delete`) | never asks | the D81 rules with a Rust-only `--force`; the refusal is a usage error before the tenant (as D137) | each drops data that cannot be restored |
| D186 | empty updates (`groups update` with no flag or an empty value; `rule-instances update` with neither `state` nor `field_values`) | `PUT {}` / `PUT {security_group_uuid}` sent | usage error, no request | a replace-style PUT with nothing in it may reset fields |
| D187 | `pypi-auth` output | the credential-bearing URL in full | the URL with its credential withheld, plus the expiry; the full URL only with `--credential-file <new path>` (exclusive 0600) | an access token must not land on a terminal or in a CI log |
| D188 | `install` without uv | python3 `venv` plus `pip install --extra-index-url <credential URL>` | error `uv was not found on PATH; install uv or pass --fetch-uv` (exit 1); uv older than 0.12.0 refused the same way | the pip path puts the credential in argv; only uv's handling was verified |
| D189 | `install` credential handling | `--index <credential URL>` in uv's argv (visible in `ps`); `--dry-run` prints it (`cmd:255`, `:267-275`) | a credential-free URL in argv, credentials in the child env only (§12.2); dry-run withholds them; uv output scrubbed; a post-run file scan | argv is world-readable; secret safety |
| D190 | `install --dir` | any path; `uv init` adds files to a non-empty dir; inside a uv workspace the new project becomes a member and `uv add` writes the parent's `uv.lock` | the dir must be absent or an empty real directory (the CLI creates it exclusively); refused inside a uv workspace; `uv init --no-workspace` | never change files outside `--dir` |
| D191 | `install` child output and `--quiet` | uv inherits stdio (its stdout is the CLI's stdout) | uv's stdout and stderr go line by line to the CLI's stderr through the scrub; `--quiet` passes `--quiet` to uv | stdout is data only |
| D192 | `install --fetch-uv` | n/a | downloads the pinned, checksum-verified uv 0.12.17 into `$XDG_DATA_HOME/airs-cli/tools/` (§12.4) | a verified uv without a system install |

Existing rows that extend to M6c: D10 (read retries), D17, D35, D37/D40/D147 (walks), D48, D50
(output formats: `markdown`, `csv` and `yaml` are usage errors), the segment-id rule (G21), the M4
`--output` rule for commands where TS ignores `--output`, and the "argument checks before the tenant"
usage contract (D2/D34).

---

## 9. Gaps

| # | Operation | What is missing or different | Evidence | CLI-side workaround |
|---|---|---|---|---|
| **G18** | `scans list --scan-origin` | `ModelSecurityScanListOptions` has no `scan_origin` field, so the SDK cannot send it. The TS SDK does not send it either: the CLI sets `sdkOpts.scan_origin`, which `buildScanListParams` drops, and `listAllScans` never passes it | `ms:query.rs:62-97`; `svc:408`, `:427-436`; `tsdk:13622-13638` | **Safe:** filter the returned rows locally by `scan_origin` (`gen:162831`), exactly. With `--all` this is exact; a single page may hold fewer than `--limit` rows. No raw request is needed, and none is proposed: it is unknown whether the API honours the parameter |
| **G19** | `pages`, `list_all`, `model_pages`, `version_pages`, `file_pages` | No repeated-row check; an empty page while `total_items` says more exist ends silently; the default collect caps and truncation differ from the CLI's D40 rules | `ms:mod.rs:63-73`; `ms:groups.rs:52-96`; `ms:inventory.rs:37-81`; `rs:pagination.rs:47-60` | **Safe:** the shared red team loop over single-page `list` calls (§5), keeping the scans `count_capped` latch |
| **G20** (G10 for M6c) | `scans list/get/create`, `models versions/version` | The schema defaults `rules_failed/rules_passed/total_rules = 0` are inserted when the server omits them | schema walk: `EvalSummary` nodes `s009825`, `s009828`, `s009831` under `ScanBaseResponseSchema`, `ScanListSchema`, `ModelVersionResponseSchema`, `ModelVersionListSchema`; `gen:33714` | **Safe:** `RequestOptions::without_response_defaults()` (scm-sdk 0.1.1), on every model-security call. The request default `description: ""` is TS parity |
| G21 (difference) | `labels values <key>` | `.segment(key)` refuses `.`, `..`, `\`, control characters and encoded traversal, and caps the length; TS `encodeURIComponent`s anything | `ms:scans.rs:352-354`; `rs:config.rs:121-151`; `tsdk:13965` | Usage error in planning (the red team segment helper, `here:src/redteam/mod.rs:37`) |
| G22 (ergonomics) | every options struct | `#[non_exhaustive]`, `Default` only; `ModelSecurityViolationListOptions` and `ModelSecurityModelVersionFileListOptions` are aliases of `ModelSecurityLabelListOptions` | `ms:query.rs:60-567` | `Default::default()` plus field assignment |
| G23 (naming) | debug operation names | `airs.model_security.*` (list in §3) | `ms:*.rs` `.named(..)` | Pin them in the debug tests (as G9/G17) |
| G24 (shape) | `get_pypi_auth` | The URL is a plain `String`: the SDK marks nothing as secret (only `Debug` is redacted) and does not validate the URL | `gen:158960-158966`, `:159042-159046` | The CLI parses and validates the URL and registers its credential in the `SecretSet` before any other use (§12.1) |

G3, G4 and G7 apply unchanged. **No blocker:** every M6c behaviour is portable on scm-sdk 0.1.1.

---

## 10. Proposed CLI module layout (mirrors `src/dlp` + `src/commands/dlp*`)

| File | Contents |
|---|---|
| `src/modelsec/mod.rs` | Argument checks: UUIDs, label-key segment, ISO window (`--start`/`--end`, offset required, start ≤ end), comma lists (`--source-types`, `--enabled-rules`, `--keys`), `--extras` vocabulary (`all aws gcp azure artifactory gitlab`), list numbers (D17), the options helper (§1.3) |
| `src/modelsec/views.rs` | Ports of the TS normalisers (`svc:28-192`): camelCase projections with `Patch` semantics, the TS `?? ''`/`?? []`/`?? {}` fallbacks kept, except the D180 counts. The pretty and table layouts of `rnd:` (columns `rnd:76-82` etc.), the `stateColor` mapping (`rnd:50-67`), the banner |
| `src/modelsec/body.rs` | `--config` (group create, rule-instance update, scan create) through `files::read_config`; `--labels` inline JSON; each parsed with the SDK request schema in planning; the empty-update refusals (D186) |
| `src/modelsec/pypi.rs` | The PyPI URL type: parse with `url`, validate, split the credential, withheld display form, `SecretSet` registration, `--credential-file` publishing (§12.1) |
| `src/modelsec/uv.rs` | uv discovery (absolute PATH entries only, `uv --version` floor), the dir and workspace preflight, the two-step plan, the child env, dry-run rendering, spawn with scrubbed forwarding and signal handling, the post-run persistence scan (§12.2, §12.3) |
| `src/modelsec/fetch.rs` | The pinned release table, the download (https, redirect and size bounds, no transparent gzip), SHA-256 before anything else, gunzip (`flate2`), the minimal ustar reader, the exclusive install into the tools dir (§12.4) |
| `src/commands/modelsec.rs` | Dispatch plus the reads (groups/rules/rule-instances/scans/models list and get, evaluations, violations, files, labels keys and values) |
| `src/commands/modelsec_write.rs` | Shared connect, authenticate, confirm (D81 plus `--force`) and `writes::send` wrappers (as `dlp_write.rs`) |
| `src/commands/modelsec_groups.rs`, `modelsec_rules.rs`, `modelsec_scans.rs`, `modelsec_labels.rs` | The write leaves and the delete verification |
| `src/commands/modelsec_install.rs` | `pypi-auth` and `install` |

Changes to existing modules:

- `clients.rs` gains `ModelSecurityClients`.
- `cli.rs` gains the `model-security` clap tree: sorted subcommands, `ls`/`rm` aliases, `--force` on
  the three confirmations, `--fetch-uv` and `--credential-file`.
- `redteam/walk.rs` moves to `src/walk.rs`.
- `files.rs`: `publish_new` gains a mode parameter (0600 for the credential file, 0755 for the uv
  binary).
- `Cargo.toml` adds the `"model-security"` feature, and
  `flate2 = { version = "=1.1.10", default-features = false, features = ["rust_backend"] }`. It is
  already in the lock file through reqwest's gzip, with `miniz_oxide` and `zlib-rs`, both pure Rust.
  No `tar` crate (choice 10).
- `signals.rs`: a child-process phase.

The doctor and tenant need nothing new. The management-credential line already names model security
(`here:src/commands/doctor.rs:323`, TS `cli:cli/commands/doctor.ts:299`). The TS doctor has no
model-security probe. The retired `modelSecTokenEndpoint` is covered by the `*TokenEndpoint` rule
(`here:src/tenant/config.rs:95-101`).

---

## 11. Fixture-server routes the loopback harness needs

Add `server/modelsec.rs` (reads), `server/modelsec_writes.rs` and a seeded dataset
`fixtures_modelsec.rs`: two groups, rule instances, rules with editable fields, three scans (one with
a full `eval_summary`, one with counts omitted, one with `count_capped`), evaluations, violations,
files, models, versions and labels. Every route checks the `mock-token-<tsg>` bearer and records the
query. Classify `/v1/scans/label-keys…` **before** `/v1/scans/{uuid}`.

| Route (`/aims/mgmt` prefix) | Behaviour |
|---|---|
| `GET` / `POST /v1/security-groups` | skip/limit page with `pagination.total_items`; POST validates `name` and `source_type`, assigns a UUID, `state: PENDING`, `is_tombstone: false` |
| `GET` / `PUT` / `DELETE /v1/security-groups/{id}` | DELETE sets `is_tombstone`; a knob for the later `get` (404, still `ACTIVE`, 500) |
| `GET /v1/security-groups/{g}/rule-instances`, `GET` / `PUT …/{i}` | PUT checks the body's `security_group_uuid == g` |
| `GET /v1/security-rules`, `GET /v1/security-rules/{id}` | |
| `GET /v1/pypi/authenticate` | `{"url": "<scheme>://oauth2accesstoken:FAKE-PYPI-SECRET-<tsg>@127.0.0.1:<port>/pypi/airs/simple/", "expires_at": …}`; knobs: an https host, no userinfo, a query, a fragment, a non-loopback http URL, a malformed URL |

| Route (`/aims/data` prefix) | Behaviour |
|---|---|
| `GET` / `POST /v1/scans` | page with `count_capped`; POST answers `eval_outcome: PENDING`; POSTs are counted (the self-tests assert ≤ 1) |
| `GET /v1/scans/{id}`, `…/evaluations`, `…/rule-violations`, `…/files` | `type` and `result` filters on files |
| `POST` / `PUT` / `DELETE /v1/scans/{id}/labels` | merge, replace, delete by repeated `keys`; `{}` answers |
| `GET /v1/scans/label-keys`, `GET /v1/scans/label-keys/{key}/values` | |
| `GET /v1/evaluations/{id}`, `GET /v1/violations/{id}` | |
| `GET /v1/models`, `/v1/models/{id}`, `/v1/models/{id}/model-versions`, `/v1/model-versions/{id}`, `/v1/model-versions/{id}/files` | versions with and without `last_eval_summary` counts |

| Route (no tenant prefix; install tests only) | Behaviour |
|---|---|
| `GET` / `HEAD /pypi/airs/simple/model-security-client/`, `/pypi/airs/files/<wheel>` | Basic-auth-checked fake index for the offline real-uv test (§12.2); records whether each request carried the credential |
| `GET /uv-release/uv-<target>.tar.gz` | A deterministic fake uv archive. Knobs: wrong bytes (checksum mismatch), oversize, a redirect to http, a `../` entry, an absolute path, a symlink or hardlink entry, a device entry, a PAX path override, a missing `uv` member, an extra member |

**Other knobs** (the existing `once`/`defaults` plans):

- a 401 once on a write (one replay), a 403, a 500 or 502 on a write (exactly one request, outcome
  unknown), a held-then-dropped connection on `POST /v1/scans`;
- a 2xx with malformed JSON;
- an empty page while `total_items` says more, a repeated `uuid`.

**Markers.** `FAKE-PYPI-SECRET-<tsg>` must never appear in stdout, stderr, the debug log, any file
outside an explicit `--credential-file`, a fake-uv argv record, `pyproject.toml` or `uv.lock`.

**Fake uv.** `airs_test_harness::fake_uv(sandbox)` writes `<sandbox>/bin/uv`, an `sh` script that:

- appends its argv, and the presence and value-digests of the `UV_INDEX_PRISMA_AIRS_MODEL_SECURITY_*`
  variables, to `tmp/uv-calls.jsonl`;
- answers `--version` with a configurable version;
- creates `pyproject.toml` on `init`;
- can be told to exit non-zero, sleep (interruption tests), echo the credential (scrub test), or
  write the credential into `pyproject.toml` (persistence-check test).

**Runner.** Add `--dir` and `--credential-file` to `PATH_FLAGS`. Default `XDG_DATA_HOME` to
`<sandbox>/data` (it is already a `PATH_VARIABLES` entry, `runner.rs:752-760`). Install tests prepend
`<sandbox>/bin` to `PATH`.

---

## 12. `pypi-auth` and `install` mechanics

### 12.1 The PyPI URL (`src/modelsec/pypi.rs`)

1. **Parse** `PyPIAuthResponse.url` with `url::Url`. Accept it only when all of these hold:
   - the scheme is `https`, or `http` with a loopback host (the D48 rule);
   - the host is non-empty;
   - there is no query and no fragment;
   - the path is non-empty.

   Otherwise fail with `The PyPI index URL returned by the service has an unexpected form` (exit 1).
   Never echo the value. A query would be persisted by uv, and the AGENTS rule forbids printing URL
   queries.
2. **Register** the full URL, the percent-encoded userinfo and the percent-decoded password (and the
   username when no password is present) in the `SecretSet`. Do this immediately, before anything
   is printed or spawned.
3. **Display form**, used by `pypi-auth` and the `install --dry-run` lines:
   `<scheme>://(withheld)@<host>[:<port>]<path>`. The whole userinfo is replaced, so a token in the
   username position is withheld too. Server text goes through `terminal_safe`.
4. **`pypi-auth` output:**
   - pretty: the TS layout (`PyPI Authentication:`, `URL: <display form>`, `Expires: <expires_at>`);
   - json: `{"url": "<display form>", "expiresAt": "…", "credential": "withheld"}`;
   - table: the same two rows;
   - a stderr hint: `The index credential is withheld; pass --credential-file <path> to save the full URL.`
5. **`--credential-file <path>`** (Rust only): the full URL plus `\n`, written with the 0600
   `files::publish_new` (exclusive link, never overwrites, a symlink refused). The destination is
   checked with `files::refuse_existing` before the tenant. Stdout then holds the same display
   document, and stderr says `Saved the PyPI index URL to <path> (mode 0600).` This is the only
   channel that can return the credential.

### 12.2 What uv persists (verified offline with uv 0.12.17)

Sandbox per §0. Fake token `FAKETOKEN-ya29-SECRETSECRET`; loopback index with Basic auth logging.

| Experiment | Credential channel | `pyproject.toml` | `uv.lock` | Token in any sandbox file (cache, `.venv`, home, XDG) | Index got Basic auth |
|---|---|---|---|---|---|
| A (TS shape) | `uv add … --index http://oauth2accesstoken:TOKEN@host/airs/simple/` (argv) | `[[tool.uv.index]] url = "http://host/airs/simple/"` (no credential, no name) | `registry = "http://host/airs/simple/"` | none | yes |
| B (proposed) | argv `--index prisma-airs-model-security=http://host/airs/simple/`; env `UV_INDEX_PRISMA_AIRS_MODEL_SECURITY_USERNAME` and `…_PASSWORD` | `name = "prisma-airs-model-security"` plus the credential-free URL | credential-free | none | yes, for the index page **and** for files under the index root |
| C | env `UV_INDEX=prisma-airs-model-security=http://user:TOKEN@host/airs/simple/` | as B | as B | none | yes |
| E, G | a 401 index | n/a | n/a | none; the error hint shows the URL without userinfo | n/a |
| F | C with `RUST_LOG=trace` | as C | as C | none; trace lines show `oauth2accesstoken:****@…` | yes |
| D | `uv sync` of B with a cold cache and no credential | unchanged | unchanged | none | failed to resolve (expected: the credential is not stored) |

Two more results:

- **Workspace.** `uv init` (with or without `--no-workspace`) inside a parent declaring
  `[tool.uv.workspace] members = ["*"]` left the parent `pyproject.toml` unchanged, but `uv add --project <dir>`
  then wrote **the parent's** `uv.lock` (D190).
- **Existing dirs.** `uv init` on an existing project fails (`Project is already initialized`,
  exit 2). On a non-empty directory without a project it adds files beside the existing ones.

Credentials attach only to URLs under the index root. A file URL outside it went without auth.
Artifact Registry serves files under `<project>/<repo>/`, so they are covered.

Mechanism B is chosen (choice 5). argv holds only the credential-free URL, and the secret lives only
in one child's environment (readable only by the same user). The persisted named index lets a user
re-supply credentials later through the same two variables.

### 12.3 `install` flow (`src/modelsec/uv.rs`)

**Order.**

1. Arguments, before the tenant:
   - `--extras` must be in the vocabulary (usage error with the TS text);
   - `--dir` must be non-empty;
   - the dir rule: the path is absent (its parent must exist and be a directory), or it is an empty
     real directory found by `lstat`, not a symlink;
   - the workspace preflight: walk the ancestors of the absolute target, and refuse when a
     `pyproject.toml` parses with a `[tool.uv.workspace]` table. The message is
     `<dir> is inside the uv workspace at <path>; choose a --dir outside it`.
2. Locate uv:
   - with `--fetch-uv`, the pinned uv (§12.4);
   - otherwise the first absolute `PATH` entry with an executable `uv`;
   - `<uv> --version` must parse as ≥ 0.12.0;
   - else D188.
3. Tenant and management credentials, then `get_pypi_auth`, then §12.1 validation.
4. `--dry-run`:
   - print to stdout: `$ uv init --no-workspace <dir>`, then
     `$ UV_INDEX_PRISMA_AIRS_MODEL_SECURITY_USERNAME=(withheld) UV_INDEX_PRISMA_AIRS_MODEL_SECURITY_PASSWORD=(withheld) uv add --project <dir> "model-security-client[<extras>]" --index prisma-airs-model-security=<credential-free URL>`
     (TS quoting rule: quote args containing `[` or a space, `cmd:270-272`);
   - with `--fetch-uv` and no installed pinned uv, first a line
     `# would fetch uv 0.12.17 for <target> into <tools dir>`;
   - stop there: nothing is created and nothing is downloaded.
5. Create `<dir>` exclusively when it is absent (`mkdir`, mode 0755 minus the umask).
6. `uv init --no-workspace <dir>`.
7. `uv add --project <dir> model-security-client[<extras>] --index prisma-airs-model-security=<credential-free URL>`.
   The child env is the inherited one plus the two `UV_INDEX_PRISMA_AIRS_MODEL_SECURITY_*` values,
   which override any inherited ones. No `--index` URL ever carries userinfo.
8. The persistence scan: read `<dir>/pyproject.toml` and `<dir>/uv.lock` (bounded 8 MiB each) and
   search for the password, raw, percent-encoded and in the userinfo form. A hit fails with
   `The PyPI credential was written to <file>; remove it from the file` (exit 1), never showing the
   value.
9. Print `model-security-client installed successfully.` and `Activate:  cd <dir>` (TS), plus
   `The index credential was not stored; run model-security install again to refresh it.`

**Children.**

- Spawn by absolute path with stdin inherited, and stdout and stderr piped.
- Forwarding threads write each line, after `terminal_safe_lines` and a scrub that replaces every
  `SecretSet` hit with `(withheld)`, to the CLI's stderr (D191).
- `--quiet` passes `--quiet` to uv.
- A non-zero exit gives `<step> failed with exit code <n>` (TS text), exit 1.

**Interruption.** SIGINT reaches uv through the terminal's process group. SIGTERM is forwarded to the
child. The CLI waits for the child, then prints the cancellation text plus
`The project in <dir> may be incomplete.` and exits 130 or 143.

### 12.4 `--fetch-uv` (`src/modelsec/fetch.rs`)

**The pin.** uv **0.12.17**. It is the version verified in §12.2, released by 2026-09-18, more than
two weeks old. The values are from the official
`https://github.com/astral-sh/uv/releases/download/0.12.17/sha256.sum` (fetched once):

| Host target (Rust `cfg`) | Archive | SHA-256 |
|---|---|---|
| aarch64 macOS | `uv-aarch64-apple-darwin.tar.gz` | `85f00cbdc6dd3e97eba4c31b4d014375a9fdfe8f570023b84e5102fc3456896b` |
| x86_64 macOS | `uv-x86_64-apple-darwin.tar.gz` | `8dcf05a8c809bb3c471d2b614788ba27a6e41298fc8c31ac84b5f4339fd468e5` |
| aarch64 Linux | `uv-aarch64-unknown-linux-musl.tar.gz` | `a6096da273d548cb9f277d237a01ac7344a39ef0f455c0e148e4dc9737c1596b` |
| x86_64 Linux | `uv-x86_64-unknown-linux-musl.tar.gz` | `6401c4665d8fa2a9893e087c91f585430738e3170f5398a1141483efb4a93310` |

The musl archives are static and match the CLI's own Linux builds. The gnu values (aarch64
`d636d1b6…f86c`, x86_64 `fa82fd8d…0a63`) are recorded for reference and not used. Any other host
gets `No pinned uv build exists for this platform; install uv yourself` (exit 1).

**Download.** `https://github.com/astral-sh/uv/releases/download/0.12.17/<archive>`, sent with
reqwest with these settings:

- https only on every hop, at most 5 redirects (GitHub redirects to its asset host);
- `.no_gzip()`, so the hash covers the exact bytes;
- a 64 MiB body cap and the walk budget;
- no credentials of any kind.

**Verify.** The SHA-256 of the whole body (sha2, already a dependency) is checked before any parse.
A mismatch gives `The downloaded uv archive failed its checksum; nothing was installed` (exit 1).

**Extract** in memory:

- gunzip with `flate2`, with the decompressed size bounded at 256 MiB;
- read the ustar archive with an in-house reader of about 150 lines;
- accept only these entries:
  - regular files (`0` or NUL type) and directories (`5`);
  - PAX `x`/`g` headers, whose `path` record replaces the next name;
- refuse the archive on any symlink, hardlink, device, FIFO, GNU long name, absolute path, `..`
  component, NUL in a name, a size field that is not octal, or a truncated entry;
- take only `uv-<target>/uv`, and ignore other regular files;
- a missing `uv` member is the error `unexpected archive layout`.

The layout `uv-<target>/{uv,uvx}` is the documented cargo-dist one. It could not be observed without
downloading the archive, so a different layout fails closed.

**Install.**

- The directory is `$XDG_DATA_HOME/airs-cli/tools/uv-0.12.17-<target>/`. Without `XDG_DATA_HOME` it is
  `~/.local/share/…`, with the same relative-path rule as the bulk-scan state dir.
- Each component the CLI creates is `mkdir` 0700. Each existing component must be a real directory
  found by `lstat`, owned by the effective uid and not group- or world-writable.
- The binary is published with `publish_new` at mode 0755 (exclusive, never overwrites), followed by
  a sidecar `uv.sha256` (0600) holding the binary's digest.
- If the binary already exists, it is reused only when its digest equals the sidecar. A different
  file is refused (`<path> exists and differs from the pinned uv; remove it`).
- The fetched uv is used only with `--fetch-uv` (choice 7).

**Tests.** A loopback fixture serves a fake archive. The URL and digest override is compiled only
under `cfg(debug_assertions)`: the variable `AIRS_CLI_TEST_UV_PIN=<http://127.0.0.1:…/path>#<sha256>`,
honoured only for a loopback http base (choice 9). Release builds contain neither the variable nor
the code. Tests point `XDG_DATA_HOME` into the sandbox, so nothing touches the real
`~/.local/share/airs-cli`.

---

## 13. Live-tier design for M6c (within the LIVE RULES)

### 13.1 Read comparison (`AIRS_RS_LIVE=1 AIRS_E2E_TENANT`; both CLIs; TS sandboxed as today)

- **Commands**, all with `--output json`. These are read-only:
  - `groups list --limit 20`, `rules list --limit 20`, `scans list --limit 20` and
    `models list --limit 20`, then `get <first uuid>` for each;
  - `rule-instances list <first group>` and `get <first group> <first instance>`;
  - `scans evaluations`, `violations` and `files` of the first scan (TS pretty only, so Rust json is
    compared against the projections; see choice 13);
  - `models versions` and `files <first version>` of the first model;
  - `labels keys`, and `labels values <first key>` when a key exists.
- **Compare** the TS projections field by field (§10 views). An eval summary count that TS shows as
  `0` and Rust as `null` is reported as the expected D180 row, not as a mismatch. The summary prints
  counts and ids only.
- **`pypi-auth`: Rust only.** Run `model-security pypi-auth --output json --debug --credential-file <session tmp>/pypi.url`.
  The harness then:
  - reads the file into memory and extracts the password, never printing it;
  - asserts the password and the full URL are absent from stdout, stderr, the debug log and the live
    summary;
  - asserts the stdout `url` contains `(withheld)` and the file mode is 0600;
  - removes the file.

  The TS `pypi-auth` never runs live, and `install` never runs live on either CLI.

### 13.2 Write flow (`AIRS_RS_LIVE_MS_WRITES=1`, on top of the read opt-ins)

- **Gate and budget.** `gate_with(lookup, "AIRS_RS_LIVE_MS_WRITES", …)` refuses before any request.
  The `ResourceBudget` allows `MAX_RESOURCES` (10) and is checked before each create.
- **Names.** `airs-rs-e2e-<unix>-<pid>-<n>-group-<rs|ts>`, which is the existing `parse_name` shape
  with a new `group` kind. A new ledger `Kind::SecurityGroup` uses UUID ids.
- **Per CLI:**
  1. `groups create --config` (`source_type: LOCAL`, a description);
  2. `groups get`;
  3. `groups update --description …`;
  4. `rule-instances list <own group>` and `get <own group> <first instance>`;
  5. `rule-instances update` that sets `state` to a different value from the vocabulary (own group
     only), then `get` to check;
  6. `groups delete` (Rust `--force`), then the D184 verification.

  Every create, update and delete goes to the ledger.
- **Teardown.** Always, also after an abort or a panic. Every planned name found in a
  `groups list --all --search airs-rs-e2e-<run>` and every captured id is deleted with Rust
  `groups delete <id> --force`. 404 or `is_tombstone: true` counts as deleted. `resourcesLeft` counts
  the rest.
- **Sweeper.** The `group` kind is added: `groups list --all --search airs-rs-e2e-` (Rust json), and
  it deletes prefixed, well-formed, non-tombstoned groups older than 1 h, at most 20.
- **Never live:**
  - any write to a group the run did not create;
  - `install`;
  - anything tenant-wide.

### 13.3 Scan flow (`AIRS_RS_LIVE_MS_SCAN=1` plus `AIRS_E2E_MS_MODEL_URI`; billed; budget 1)

- **Gate.** `AIRS_RS_LIVE_MS_SCAN=1` and a model URI the user supplies (for example a small public
  Hugging Face model). Without the URI, the flow is skipped with a notice. A scan counter refuses a
  second `scans create`.
- **Resources.** One run group `airs-rs-e2e-<…>-group-sc` with `source_type: HUGGING_FACE`, and one
  scan from Rust `scans create --config`. The TS side only reads it (`scans get`), so the budget of 1
  holds. The scan goes in the ledger as `Kind::MsScan`.
- **Labels**, only on that scan:
  1. Rust `labels add`;
  2. TS `labels add`;
  3. both `scans get` (labels compared);
  4. Rust `labels set --force` (one label);
  5. TS `labels delete <key>` and Rust `labels delete --force` of the rest;
  6. `labels keys`, to check the prefixed key is gone.

  Keys and values are `airs-rs-e2e-<run>-…`.
- **Optional wait.** Poll `scans get` until `eval_outcome != PENDING` within
  `AIRS_RS_LIVE_MS_SCAN_MINUTES` (default 15). When it completes, compare `evaluations`,
  `violations` and `files` of the scan.
- **Permanence.** A scan cannot be deleted (§3), like a red team scan. The ledger records it with the
  note `undeletable`, its labels are removed, and the group is then deleted (a refusal is recorded
  and left to the sweeper).

### 13.4 Loopback self-tests (`LiveTarget::loopback`)

- With each gate unset there are zero recorded requests; the scan gate unset gives zero `POST /v1/scans`.
- Every `POST /v1/security-groups` body name starts with the run prefix. There is no
  `PUT`/`DELETE` on a seeded group id, and no labels write on a seeded scan.
- At most one `POST /v1/scans`, and only with the scan gate.
- The ledger has an `ok` delete for every `ok` group create.
- An injected 500 on `groups update` still tears everything down.
- The sweeper ignores young, unprefixed, wrong-kind and tombstoned groups.
- The pypi marker `FAKE-PYPI-SECRET-<tsg>` appears only in the credential file, which is 0600 and
  then removed.
- No file is written outside the sandbox, by the runner guard.

---

## 14. Choices decided (for §17 "Choices decided"; each with the rejected alternative)

1. **`without_response_defaults()` on every model-security call**, not only on the five that need it.
   Rejected: per-call selection (easy to miss when a view grows).
2. **The walk:** the shared red team skip/limit loop with the scans `count_capped` latch. Rejected:
   the SDK `pages`/`list_all` (G19).
3. **`--scan-origin` becomes a local exact filter.** Rejected: a usage error (it breaks the TS flag),
   or a raw request with an undocumented parameter.
4. **`scans list --search` mirrors TS per mode:** `search` on one page, `search_query` with `--all`.
   Rejected: unifying them. There is no evidence which parameter the API honours, so a change could
   break a working path.
5. **The uv credential channel** is `UV_INDEX_<NAME>_USERNAME/PASSWORD` in the child env plus
   `--index prisma-airs-model-security=<credential-free URL>`. Rejected: the credential URL in argv
   (TS, visible in `ps`), and `UV_INDEX` with the full URL. The latter is equally safe, but it
   replaces a user's own `UV_INDEX`.
6. **uv version floor 0.12.0.** Rejected: any uv (older behaviour unverified) and exactly 0.12.17
   (too strict for PATH installs).
7. **The fetched uv is used only with `--fetch-uv`.** It is reused when its sidecar digest matches.
   Rejected: silently preferring it over PATH, and re-downloading every run.
8. **The `--dir` rule:** absent or an empty real directory, created exclusively by the CLI, with a
   refusal inside a uv workspace and `uv init --no-workspace`. Rejected: TS's anything-goes, and
   injecting a `[tool.uv.workspace]` table into the new project to stop discovery (it edits uv's
   output).
9. **The test hook for `--fetch-uv`:** `AIRS_CLI_TEST_UV_PIN` compiled only under
   `cfg(debug_assertions)`, loopback only. Rejected: a runtime flag or env in release builds, a cargo
   feature (CI and test selection churn), and real downloads in tests (forbidden).
10. **Archive extraction:** `flate2` (already locked) plus an in-house ustar reader that never calls
    an unpack API. Rejected: the `tar` crate (a new dependency and extra transitive crates for a
    two-member archive).
11. **The `pypi-auth` display:** the whole userinfo is replaced by `(withheld)` in every format, and
    JSON adds `"credential": "withheld"`. The only way to get the credential is
    `--credential-file <new path>` (0600, exclusive). Rejected: D139's "json prints it" (the scope
    forbids it), and printing the username.
12. **uv's output** is piped and scrubbed onto stderr. Rejected: inherited stdio, which can neither
    keep stdout data-only nor guarantee that a future uv never prints the credential.
13. **Commands where TS prints only pretty** (`scans evaluations|evaluation|violations|violation|files`,
    `labels keys|values`, `pypi-auth`) honour `--output json|table` with the TS normaliser
    projection. JSON arrays hold strings for label keys and values. Rejected: ignoring `--output` (it
    contradicts the M4 rule).
14. **Group delete verification:** 404 or `is_tombstone: true` confirm, other failures are "could not
    be verified" with exit 0. Rejected: TS's catch-all success, and exit 1 after an accepted DELETE.
15. **Empty updates are usage errors** (D186). Rejected: sending `PUT {}`.
16. **Live scans:** the Rust CLI creates the one budgeted scan, and TS only reads it and writes
    labels. Rejected: one scan per CLI, which exceeds the budget of 1.
