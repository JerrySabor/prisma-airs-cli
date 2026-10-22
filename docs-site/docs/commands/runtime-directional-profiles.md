---
title: Directional profiles
sidebar_position: 4
---

# Directional security profiles

:::note Live acceptance
Directional profiles follow the TypeScript CLI 7.3.0 and `scm-sdk` 0.2.4. A live run against
a tenant (2026-10-22) accepted flag and `--config` creates, a protection edit of each
direction, shared-settings edits, a topic applied and reverted in each direction, and backup
and restore. Not yet exercised live: profiles with several AI entries (`--ai-profile-index`)
and DLP blocks inside a direction.
:::

The service applies rules of its own; a write that breaks one fails with HTTP 400 (exit 1),
and nothing is written:

- A directional entry must hold all four direction keys. A flag create writes the directions
  it does not fill as empty objects (`{}`); a `--config` body must list all four.
- A policy whose directions are all empty is refused.
- The `response` direction refuses `prompt-injection`.
- `toxic-content` takes `block` or `allow` for each level (`high:block, moderate:allow`), not
  `alert`.

A security profile's policy holds AI entries (`ai-security-profiles`). Two layouts exist:

- A **legacy** entry keeps its protections (`model-protection`, `app-protection`,
  `agent-protection`, `data-protection`) and its shared settings in `model-configuration`.
  Existing legacy profiles need no migration.
- A **directional** entry has `content-type-mode: per_content_type` (or a
  `content-type-configurations` key). Its protections live per direction in
  `content-type-configurations`, under `prompt`, `response`, `tool-call` and
  `tool-response`; the service requires all four keys, though a direction may be empty. Its
  `model-configuration` keeps only the
  shared settings: `latency`, `mask-data-in-storage` and
  `enable-full-conversation-inspection`.

## Creating

```bash
# A legacy profile, as before
airs runtime profiles create --name Legacy --prompt-injection block

# A directional profile with response protections
airs runtime profiles create --name Directional --direction response \
  --toxic-content 'high:block, moderate:allow' --no-enable-full-conversation-inspection

# A complete JSON body: the file names the profile; --name and every other flag are refused
airs runtime profiles create --config ./directional.json --output json
```

Directional flag creation needs at least one protection or shared setting, and the service
also refuses a profile whose four directions are all empty, so give at least one protection.
The flags fill the `--direction` you name; the other three directions are written empty, so
a later `update --direction` can fill any of them. A DLP block needs `--dlp-action` on a
create.

## Updating

```bash
# Edit only the response protections; every other direction and severity stays
airs runtime profiles update Directional --direction response \
  --toxic-content 'high:alert, moderate:allow' --no-mask-data-inline

# Shared settings need no direction and keep every direction
airs runtime profiles update Directional --max-inline-latency 8 \
  --no-mask-data-in-storage --no-enable-full-conversation-inspection

# A complete replacement (also how a direction is added, or a layout converted)
airs runtime profiles update Directional --config ./directional.json
```

| Rule | What happens |
|---|---|
| A protection edit on a directional profile | needs `--direction`, even with one direction |
| The selected direction is absent | refused; add it with a complete `--config` |
| `--direction` on a legacy profile | refused; convert it with a complete `--config` |
| Several AI entries | `--ai-profile-index <n>` (zero-based) selects one, also for shared settings; the others stay |
| An unknown `content-type-mode` | kept by shared edits; protection edits are refused |
| Detectors | merged by name: a match keeps its severities and topic lists; a name listed twice is refused |
| `--no-…` flags | write an explicit `false`; of a pair, the last one given wins |
| A setting you do not pass | stays as stored, or absent; no default is written |
| An unknown direction key | kept with its value by reads, updates, backup and restore; no direction is added |
| `--dlp-profiles`, `--[no-]mask-data-inline` | change only their fields on update; no `--dlp-action` needed |

These refusals happen after the profile is read; nothing is written and the exit code is 2.
`--direction` and `--ai-profile-index` values are checked before anything is read
(`--ai-profile-index` takes decimal digits only).

## Topics

```bash
airs runtime topics apply --profile Directional --name Restricted --intent block --direction prompt
airs runtime topics revert --profile Directional --name Restricted --direction prompt --force
```

`apply` adds the topic to the selected direction and keeps every other topic and direction.
`revert` removes it from the selected direction and deletes the topic with a plain delete. It
refuses, with nothing written or deleted, when:

- the selected direction does not reference the topic;
- another direction, another AI entry or a retained legacy block of the profile still
  references it (detach those first).

A topic still referenced by another profile (or an older revision) is kept with a warning, as
for legacy profiles.

## Reading

- `airs runtime profiles get` shows `DLP tenant` (when the service returns one) and
  `Protection locations` (`AI[0] default / prompt, AI[0] default / response, …`). JSON adds
  `dlpTenantId` (a string); a GET may omit it. A value the service sends that the schema does
  not expect (a `null`, a number) is printed as sent; the TypeScript CLI refused such a read.
- A `--config` file is checked before the tenant is read: `dlp_tenant_id` must be a string,
  `content-type-mode` a string, each direction an object and
  `enable-full-conversation-inspection` a boolean, never `null` (exit 2).
- `airs runtime report` adds a **Protection configurations** column: one entry per AI entry
  and direction, with the protection sections it holds.
- `airs runtime profiles backup` and `restore` carry every direction: DLP mappings, the Basic
  fallback and topic remapping work per direction, and `--on-conflict verify` compares
  directions strictly. A backup keeps each record as the service sent it; a restore does not
  send the source tenant's `dlp_tenant_id`.

The behavioural contract is DESIGN §13.17 in the repository.
