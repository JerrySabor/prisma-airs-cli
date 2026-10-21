---
title: tenant
sidebar_position: 1
---

# `airs tenant`

Tenants are the only configuration source. `tenant` commands read and change the `airs`
store; they build no API client and send no request.

| Command | What it does |
|---|---|
| `tenant list` (`ls`) | every registered tenant, the selected one marked; no credentials read |
| `tenant path [name]` | the tenant file's path (default: the selected tenant) |
| `tenant read [name]` | the effective settings as `Key │ Value`, secrets `[REDACTED]` |
| `tenant get <name> <key>` | one effective setting, secrets redacted |
| `tenant create <name>` | a new tenant from prompts, or `--tsg-id`, `--client-id` and `--client-secret-stdin`; does not select it |
| `tenant set <name> <key> [value]` | one setting; omit the value for a prompt (hidden for secrets) or pipe it with `--stdin` |
| `tenant unset <name> <key>` | remove one setting so the default applies; credentials cannot be cleared |
| `tenant switch <name>` | select the tenant for later commands |
| `tenant delete <name>` (`rm`) | delete the tenant and its file; asks first, `--force` skips the question |
| `tenant import` | copy tenants from the TypeScript CLI's registry; its files are not changed |

```sh
airs tenant create development
airs tenant switch development
airs tenant set development defaultOutput json
printf '%s\n' "$KEY" | airs tenant set development airsApiKey --stdin
airs tenant read
airs tenant import --dry-run
```

- Outcome lines (`✓ …`, `ℹ …`) go to stderr and `--quiet` hides them; stdout stays empty
  for the write commands.
- Input errors (a bad name, key or value, a secret on the command line, no terminal for a
  prompt, `delete` without `--force` when not interactive) exit 2.
- Tenant names are 1–64 letters, digits, hyphens or underscores; names that differ only in
  case are refused.

See [Configuration and tenants](../getting-started/configuration.md) for the store, the
settings and the credential planes, [Upgrading from 7.x](../getting-started/upgrading-from-typescript.md)
for `tenant import`, and the [reference](../reference/commands/tenant.md) for every flag.
