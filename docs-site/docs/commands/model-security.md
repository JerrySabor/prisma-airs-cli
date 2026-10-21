---
title: model-security
sidebar_position: 6
---

# `airs model-security`

`airs model-security` covers AI Model Security: security groups, rules and rule
instances, scans and their evaluations, violations and files, models and versions,
labels, the PyPI index for the model-security client, and `install`.

## Reads

```sh
airs model-security groups list
airs model-security groups get <uuid> --output json
airs model-security rules list --source-type LOCAL --all
airs model-security rule-instances list <groupUuid> --state BLOCKING
airs model-security scans list --eval-outcome BLOCKED --start 2026-01-01T00:00:00Z
airs model-security scans list --scan-origin MODEL_SECURITY_SDK --all --output json
airs model-security scans evaluations <scanUuid> --output table
airs model-security models versions <modelUuid> --all
airs model-security labels values env
```

The model-security commands use the selected tenant's `modelSecMgmtEndpoint` (groups, rule
instances, rules) and `modelSecDataEndpoint` (scans, models, labels), else
`https://api.apps.paloaltonetworks.com/aims/mgmt` and `…/aims/data`, with its management
credentials. Every read prints `pretty`, `table` and `json` (the scan sub-reads and the label
lists too, which the TypeScript CLI prints in pretty only); the group, rule,
rule-instance, scan and model reads honour the tenant's `defaultOutput`. UUIDs, the time
window, numbers and filters are checked before the tenant is read (exit 2). Nothing the
service did not send is printed: a scan summary without counts shows no `Rules` line, and its
json counts are `null`. Model URIs are printed with their credentials, query and
fragment `[withheld]`. `--all` walks every page and fails rather than print a partial
list; every list honours `--offset`, `--all` and `--max`; a page that does not show
everything says so on stderr. `scans list --scan-origin` filters exactly over every page
(the service has no such filter).

## Writes

```sh
airs model-security groups create --config group.json
airs model-security groups update <uuid> --description ''
airs model-security groups delete <uuid>            # asks; --force for scripts
airs model-security rule-instances update <groupUuid> <instanceUuid> --config state.json
airs model-security scans create --config scan.json --output json
airs model-security labels add <scanUuid> --labels '[{"key":"env","value":"prod"}]'
airs model-security labels set <scanUuid> --labels '[{"key":"env","value":"prod"}]' --force
airs model-security labels rm <scanUuid> --keys env,team --force
```

Every write is sent once: after a timeout, a 5xx or a dropped connection the CLI says the
outcome is unknown instead of re-sending (a 401 is retried once with a fresh token), so a
billed `scans create` is never sent twice. `groups delete`, `labels set` (which
replaces every label and names the ones it drops) and `labels delete` ask on a terminal and
need `--force` elsewhere. `groups delete` re-reads the group and reports `deleted` only
on a 404 or a tombstone; a group the service still shows gets a warning. A group config
takes `name`, `source_type`, `description` and `rule_configurations`, a rule-instance config
`state`, `field_values` and `security_group_uuid`; other keys, a file that changes nothing and a
`groups update` without a flag are refused before the tenant is read, and no file or label
content is ever echoed in a message. `--description ''` clears a description. The
written record prints in the chosen `--output` on stdout, the `✓` line on stderr.

## PyPI access and install

```sh
airs model-security pypi-auth                         # the index URL, credential withheld
airs model-security pypi-auth --url-file pypi.url     # the full URL into a new 0600 file
airs model-security install --dry-run                 # the uv commands, credential withheld
airs model-security install --extras aws --dir ./ms   # uv init + uv add
airs model-security install --fetch-uv                # use a pinned, verified uv 0.12.17
```

The PyPI index URL carries a short-lived access token. `pypi-auth` prints it with the credential
`[withheld]` in every format; the only way to get the full URL is `--url-file <path>`, a new file
created with mode 0600 that is never overwritten. `install` uses uv only (0.12.0 or
later on `PATH`; TypeScript's python/pip fallback is gone): it runs `uv init
--no-workspace -- <dir>` and `uv add --project <dir> --index airs-model-security=<index> --
'model-security-client[<extras>]'`, handing the credential to `uv add` only through
`UV_INDEX_AIRS_MODEL_SECURITY_USERNAME`/`_PASSWORD` in its environment, never in its arguments,
and checks afterwards that `pyproject.toml` and `uv.lock` do not hold it. `--dir` must not
exist yet and must not lie inside a uv workspace. uv's output is scrubbed and goes to
stderr; stdout stays empty. Ctrl-C is passed on to uv, which the CLI waits for.
`--dry-run` prints the commands with the credential withheld, quoted for a POSIX shell.
`--fetch-uv` downloads uv 0.12.17 for your platform into `$XDG_DATA_HOME/airs-cli/tools`
(else `~/.local/share/airs-cli/tools`), verifies its pinned SHA-256 before extracting, and reuses
a copy that verifies. Later uv commands in the project need the credential again: set the two
variables from the URL `pypi-auth --url-file` saves.

## Every flag

Every command and flag is in the [command reference](../reference/commands/model-security.md).
