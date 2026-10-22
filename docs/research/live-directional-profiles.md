# Directional profiles against the live service (8.0 B7)

What the live AIRS management service **actually did** with directional security profiles
(DESIGN §13.17) when driven by this CLI. Everything below was executed, not read from code.
Run once, on 2026-10-22, against `redtail-prod`. The maintainer authorised the run.

- Binary: `target/release/airs` built with `cargo build --release --locked` from
  `port/typescript-7.3.0`. It was first built at `60d0296` (before D335), then rebuilt with
  D335 for steps 20–22.
- Tenant: read only from the CLI's own tenant store (the selected tenant). Nothing came from
  the environment. No credential was printed, and no response body was printed (the CLI never
  prints one, DESIGN §6).
- Run id `20261022200128`. Every resource created was named
  `airs-rs-live-20261022200128-…`, and nothing without that prefix was written. `<TSG>` below
  stands for the tenant's TSG ID.
- Each step was checked by reading the profile back with `runtime profiles get <name>
  --output json`, not just by its exit code. The diffs compared every direction and
  `model-configuration` before and after.
- Deletes used the plain `delete` (never `--force`), answered `y` on a pty, as the live
  tier's teardown does (docs/TESTING.md §6.7). Every revision of every run-created profile
  was deleted by id.

## Results

| Step | Command (names shortened: `P` = `airs-rs-live-20261022200128`) | Exit | Verified result |
|---|---|---|---|
| 0 | `runtime profiles list --all --max 0 --all-versions --output json`; `runtime topics list …` | 0, 0 | 35 profile revisions and 5 topics; no `airs-rs-` resource from an earlier run |
| 1 | `runtime profiles create --name P-flags-prompt --direction prompt --prompt-injection block --toxic-content block --malicious-code block --url-action alert --max-inline-latency 10 --inline-timeout-action allow --output json` (binary at `60d0296`) | 1 | **Refused**: HTTP 400. Run three times, the same each time |
| 2 | the same flag create for `response`, `tool-call` and `tool-response` (at `60d0296`; detectors valid for each direction) | 1, 1, 1 | **Refused**: HTTP 400 for every direction |
| 3 | `--config` probes, then `profiles update P-probe-b --config <file>` probes (below) | — | The service requires all four direction keys; a body padded with three empty directions is accepted. This is a CLI defect, fixed as D335 |
| 4 | `runtime profiles create --config config.json --output json` (four directions, shared settings, `"dlp_tenant_id": "<TSG>"`) | 0 | **Accepted.** All four directions and every value sent were stored. The service added severities, `default-url-category: {member: null}`, `url-detected-severity` and a default `data-leak-detection`. The create answer carried `dlpTenantId: "<TSG>"` |
| 5 | `get P-config --output json`; `--output pretty`; `list --all-versions` | 0 | json carries no `dlpTenantId` key; pretty has no `DLP tenant` line; `Protection locations  AI[0] default / prompt, … / response, … / tool-call, … / tool-response` |
| 6 | `profiles update P-config --direction prompt --prompt-injection alert --url-action block` | 0 | **Accepted.** Only `prompt` changed (the two values); the other three directions and `model-configuration` are unchanged |
| 7 | `… --direction response --toxic-content block --malicious-code block` | 0 | **Accepted.** Only `response` changed (toxic levels; malicious-code item added) |
| 8 | `… --direction tool-call --agent-security block --db-security-read alert` | 0 | **Accepted.** Only `tool-call` changed (agent-protection added; database-security-read appended, delete kept) |
| 9 | `… --direction tool-response --url-action alert --toxic-content "high:block, moderate:allow"` | 0 | **Accepted.** Only `tool-response` changed |
| 10 | `… --max-inline-latency 20 --inline-timeout-action allow --no-mask-data-in-storage --enable-full-conversation-inspection` (shared, no direction) | 0 | **Accepted.** Only `model-configuration` changed (`false` written for storage masking); all four directions unchanged |
| 11 | `… --prompt-injection block` (no `--direction`) | 2 | `Directional protection edits require --direction`; revision unchanged (6), nothing written |
| 12 | `runtime topics create --name P-topic-<d> --description … --examples … …` for each direction | 0 ×4 | Four topics, revision 1 |
| 13 | `runtime topics apply --profile P-config --name P-topic-<d> --direction <d> --intent block` for each direction | 0 ×4 | **Accepted.** Each apply added a `topic-guardrails` item (`action: allow`, one `block` group with the topic's id, name and revision) to its own direction only; the other directions and the shared settings are unchanged |
| 14 | `runtime profiles backup P-config --output-file backup.json --output json` | 0 | 1 profile (revision 10), 4 topics; file mode 0600 |
| 15 | `runtime profiles delete <id>` for each of the 10 revisions (pty, `y`) | 0 ×10 | `list --all-versions` shows no `P-config` |
| 16 | `runtime profiles restore backup.json --dry-run --output json` | 0 | Plan: profile `create`, four topics `reuse`, no DLP mapping or fallback |
| 17 | `runtime profiles restore backup.json --expect-tsg <TSG> --force --output json` | 0 | **Accepted.** `complete: true`, profile `created`, topics `reused`. The restored policy is identical (sorted JSON) to the backup's, in every direction and with every topic ref |
| 18 | `… --on-conflict verify --expect-tsg <TSG> --force --output json` | 0 | `verified`, no write (revision still 1) |
| 19 | `runtime topics revert --profile P-config --name P-topic-<d> --direction <d> --force` for each direction | 0 ×4 | **Accepted.** Each revert removed the guardrail from its own direction only. Each topic was kept with the 0.4.1 warning (the service answered 409 because older revisions still referenced it). After the four reverts the policy equals the pre-apply policy of step 10 |
| 20 | with D335: `profiles create --name P-flags-<d> --direction <d> …` for each direction (the step 1–2 flags) | 0 ×4 | **Accepted.** Each stored all four directions: the named one with exactly the flags' values, the other three `{}`; the shared settings as given |
| 21 | `profiles update P-flags-prompt --direction response --toxic-content "high:block, moderate:allow"` | 0 | **Accepted.** Only `response` changed (from `{}`), which the empty direction from D335 makes possible without `--config` |
| 22 | `profiles update P-flags-prompt --mask-data-in-storage --no-enable-full-conversation-inspection` | 0 | **Accepted.** Only the shared settings changed |
| 23 | `profiles update P-flags-response --direction response --prompt-injection block` | 1 | **Refused** by the service (HTTP 400): `response` takes no `prompt-injection`. Revision unchanged |
| 24 | cleanup: `profiles delete <id>` for all 47 remaining revisions of 6 names; `topics delete <id>` for the 4 topics (pty, `y`) | 0 ×51 | Every delete answered `✓` |
| 25 | final `profiles list --all --max 0 --all-versions` and `topics list …` | 0, 0 | 35 profile revisions and 5 topics, with ids, names and revisions identical to step 0; zero `airs-rs-` resources. No pre-existing profile gained a revision |

All four directions (`prompt`, `response`, `tool-call`, `tool-response`) and the shared
settings were accepted for create (with D335), edit and topic apply and revert. No direction
was refused as a whole.

## The bisection (step 3)

The CLI prints no response body, and its `--debug` log records status and headers only.
The probes therefore varied one thing at a time. A 400 creates nothing; an accepted create
makes one resource (`P-probe-b`), and every later probe was a `profiles update --config`
PUT on that profile. 63 probe runs: 36 accepted, 27 refused.

| Body | Result |
|---|---|
| The step 1 flag body as a `--config` create; the same plus the full shared settings; the same plus `dlp-data-profiles: []` | 400, 400, 400 |
| A copy of a console-created directional profile's policy (four directions, every section) | accepted (`P-probe-b`) |
| That policy with only `prompt`; without `tool-response`; without `response`; without `prompt` | 400 each (repeated: deterministic) |
| The step 1 flag body plus `response: {}`, `tool-call: {}`, `tool-response: {}` | **accepted** |
| Four empty directions (with the full shared settings, or with latency only) | 400 (all-empty refused) |
| `tool-response: {}`, or one section only, in an otherwise full policy | accepted |
| Removing `data-protection`, `agent-protection`, `model-protection` or `app-protection` (or any one `app-protection` key) from `prompt` | accepted |
| `prompt-injection` added to `response` | 400 (repeated) |
| `toxic-content` `high:block, moderate:alert` | 400 (seen once, below); `moderate:block` and `moderate:allow` accepted |
| `dlp_tenant_id: "<TSG>"` added to an accepted body | accepted |

**Transient refusals.** Four consecutive PUTs (removing `app-protection`, `default-url-category`,
the three URL-category objects, `url-detected-severity`) were refused with 400 and were each
accepted when re-sent unchanged a few minutes later. Four identical control PUTs in a row all
succeeded. These four are not counted as rules.

Request IDs of the refusals taken as rules, for the service owner: one-direction flag creates
`b26a63b4-3683-4d55-92fb-edc449928c2b` (prompt), `9d059b14-ef40-418f-94cf-b954a638b151`
(response), `72bc2bfc-c1d6-4ab5-9507-703651e7107f` (tool-call),
`c0e61a53-080e-445d-8166-62377796a113` (tool-response); a missing direction
`04916dac-85d0-4a6b-a07e-e8dd02f49bc6`; `prompt-injection` in `response`
`343b967c-6700-422c-bbeb-8d98baf28a06`, `0d721e6a-c658-4a7c-80af-b650b3bf1417`; four empty
directions `3ed44707-ade5-4071-981e-617d7008b825`; a toxic `alert` level
`ac1b73e7-3f86-4ad9-87fc-4df569e2b347`.

**The toxic `alert` refusal was seen once.** This record gives one request ID for it and no
repeat count (unlike the `prompt-injection` and missing-direction refusals, which were
repeated). It might have been one of the transient 400s above. The rule below rests on that
one refusal; the CLI's documentation follows it and uses only `block` and `allow`.

## Service rules found

1. A directional entry must hold all four direction keys; any of them may be `{}`. The
   request schema (TS SDK 0.35.0, scm-sdk 0.2.4) marks each direction optional. TypeScript
   7.3.0's flag builder writes only the selected one, so its flag create can never succeed.
   **D335** makes the Rust flag create write the other three as `{}`.
2. A policy whose four directions are all empty is refused, also with the shared settings
   set. At the time of the run the CLI kept TypeScript's local rule (at least one protection
   or shared setting), so a shared-only directional flag create reached the service and
   failed with 400. **D336** (after the run, offline) refuses such a create locally (exit 2,
   before OAuth), naming this rule. A `--config` body with four empty directions is still
   sent.
3. `response` refuses `prompt-injection`. `tool-call` and `tool-response` accept it.
4. `toxic-content` takes `block` or `allow` per level; `alert` was refused (seen once; see
   above).
5. The service adds `severity` to detectors and URL actions, `severity-by-confidence` to
   `toxic-content`, `default-url-category: {member: null}`, and an empty `data-leak-detection`
   (`action: ""`, `member: null`) where a section is present. It adds nothing to an empty
   direction or to `model-configuration`. These additions read back through every later flag
   update and topic write and validate against the request root (steps 6–10, 13, 19).
6. Every PUT creates a new revision with a new `profile_id` (as for legacy profiles, DESIGN
   §13.9), so a `revert` after an apply keeps the topic with the 0.4.1 warning, and teardown
   must delete every revision.

## `dlp_tenant_id` on a PUT that omits it

- No `get` or `list` answer carried `dlp_tenant_id`, for the run's profiles or for any
  pre-existing one. A profile created with `"dlp_tenant_id": "<TSG>"` reads back without the
  key.
- Write answers always carry it. A create or PUT that sends it echoes the value sent; one that
  omits it answers `"dlp_tenant_id": "none"`. Examples: step 4's create answered `<TSG>`; its
  next PUT (step 6, a flag update, which sends `{profile_name, active, policy}`) answered
  `"none"`. On `P-probe-b`, a `--config` PUT carrying `<TSG>` answered `<TSG>`, and the next
  PUT without it answered `"none"`.
- Conclusion: the answer reports `none`; the effect on the stored binding is unknown. A
  `"none"` in a write answer may only reflect the request, not the stored state, and no read
  returns the field, so this run cannot tell a cleared binding from a kept one. The CLI prints
  each answer as sent (`"dlpTenantId": "none"` in the json of every flag update in steps
  6–10).
- Every CLI write that changes a profile omits `dlp_tenant_id` unless a `--config` file holds
  it: a flag `profiles update`, `topics apply|revert`, a restore (create and overwrite; it
  never sends the source's value, DESIGN §13.17), and a `profiles update --config` whose
  file leaves the key out. TypeScript 7.3.0 does the same. This applies to legacy profiles
  too; the CLI cannot keep the value because no read returns it.

### Open question for the service owner

Does a create or PUT that omits `dlp_tenant_id` clear a profile's stored DLP tenant binding,
or does the write answer only echo the request (`"none"` when the key is absent)? The run
recorded no request ID for the `dlp_tenant_id` observations themselves (step 4's create
answering `<TSG>`, step 6's PUT answering `"none"`, and the two `P-probe-b` PUTs). They were
made in run `20261022200128` on 2026-10-22 against `redtail-prod`, on the profiles
`airs-rs-live-20261022200128-config` and `airs-rs-live-20261022200128-probe-b`, in the same
session as the request IDs listed above (for example `b26a63b4-3683-4d55-92fb-edc449928c2b`,
`04916dac-85d0-4a6b-a07e-e8dd02f49bc6` and `3ed44707-ade5-4071-981e-617d7008b825`), which
locate the run in the service's logs.

**The distinguishing test (not run).** Copy a DLP-bound profile under a run-prefixed name with
`profiles create --config`, the file holding its policy and `"dlp_tenant_id": "<TSG>"` (as
step 4 sent it; a backup and restore would not send the value). Run a DLP-triggering scan
against the copy: it must detect, or the copy is not bound and the test shows nothing.
Update the copy through the CLI with a change unrelated to DLP (for example `profiles update
<copy> --max-inline-latency <n>`, which omits `dlp_tenant_id`). Run the same scan again. If DLP still detects, the binding is kept and the `"none"` only
echoes the request; if it no longer does, the omitted key cleared it. Then delete every
revision of the copy. This needs a DLP-bound profile and a scan budget, and it has not been
run.

## Departures from the live test rules (MILESTONES)

The maintainer's release brief for B7 set the `airs-rs-live-` prefix and authorised the run.
The departures below follow from it. The maintainer waived them for B7, given that the final
listing matched the preflight's (step 25).

- The prefix is `airs-rs-live-`, as the B7 brief asked, not the live tier's `airs-rs-e2e-`, so
  the `live_cleanup` sweeper does not recognise it and would not find a leftover. None was
  left (step 25).
- The run was not a `tests/live.rs` flow. It used the Rust CLI only (TypeScript 7.3.0's flag
  create sends the body that step 1 shows refused) and its own tenant store, not a private
  import under `target/live/`. Writes were journalled in a step log outside the repository,
  not in `target/live/ledger.jsonl`.
- It created 11 named resources (6 profiles, one of them twice through the restore, and 4
  topics), against the cap of 10. With the 50 further revisions the probes, edits and topic
  writes made, it deleted 61 records in all (57 profile revisions, 4 topics).
- There is no `target/live/ledger.jsonl` ledger for it (see the step log above).
- Follow-up, not implemented: a Rust-only directional step in the live tier's
  `live_write_flow` (`tests/live.rs`, recorded under D93 like the other Rust-only steps), so a
  later run repeats this inside the tier's rules (the `airs-rs-e2e-` prefix, the ledger, the
  cap). It must stay within the cap of 10 resources and is not run live now.

## Not exercised live

Profiles with several AI entries (`--ai-profile-index`), DLP blocks inside a direction
(`--dlp-action`, `--dlp-profiles`), and the runtime report's `Protection configurations`
column. The offline contract (DESIGN §13.17, the `tests/parity_runtime_directional.rs`
scenarios) covers them.
