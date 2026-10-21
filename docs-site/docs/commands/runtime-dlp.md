---
title: runtime dlp
sidebar_position: 4
---

# `airs runtime dlp`

`airs runtime dlp` manages Enterprise DLP resources: data patterns, data profiles,
dictionaries and filtering profiles, and backs them up and restores them.

## Patterns, profiles, dictionaries and filtering profiles

```sh
airs runtime dlp patterns list
airs runtime dlp patterns list --include-predefined --limit 20 --offset 20
airs runtime dlp profiles get <id> --output json
airs runtime dlp dictionaries list --keywords --output json
airs runtime dlp filtering-profiles list --all
airs runtime dlp patterns create --name "Employee ID" --regex 'EMP-[0-9]{6}' --confidence-levels high
airs runtime dlp patterns patch <id> --set name="Employee ID" type=custom 'detection_config={"technique":"regex"}'
airs runtime dlp profiles create --name "HR data" --pattern-id <pattern-id>
airs runtime dlp dictionaries create --name Codes --category Confidential --region "United States" --file ./codes.txt
airs runtime dlp patterns delete <id>            # asks on a terminal; --force for scripts
airs runtime dlp backup --output-file ./dlp-backup.json
airs runtime dlp restore ./dlp-backup.json --name-prefix migrated- --dry-run
airs runtime dlp restore ./dlp-backup.json --name-prefix migrated- --expect-tsg <tsg> --force
```

The DLP commands use the selected tenant's `dlpEndpoint` (else
`https://api.dlp.paloaltonetworks.com`) with its management credentials. Every read prints
`pretty`, `table` and `json` and honours the tenant's `defaultOutput`. Pattern, profile and
dictionary listings show the tenant's own (custom) records by default, read from every page;
`--include-predefined` shows the service's pages as they are. Ids, numbers and `--sort` are
checked before the tenant is read (exit 2). JSON is the full record in camelCase, with the
keys of your tags and exclusion lists kept as they are; keywords are fetched only with
`--keywords`. DLP records hold detection content (regexes, keywords): it is printed only by the
json and table reads and never in an error or the `--debug` log.

The writes build their body from flags, or take it whole from `--body <json>`, `--body -`
(piped stdin) or `--body-file` (never both; patches take `--set key=value`/`--clear key` or
`--body-file`). Every argument and body is checked before the tenant is read. Before a
replace, patch or delete the record is read: predefined (PANW-shipped), parent-managed and
unfamiliar-type records are refused, and nothing is sent. Deletes and replaces ask for
confirmation on a terminal and need `--force` otherwise; a replace names the fields it would
drop. Each write is sent once (a 401 is retried once with a fresh token): when its outcome is
unknown the error says so and, for a create, how to check before creating it again.
`patterns replace` keeps the pattern's type and technique unless you give them. The API has no
data-profile DELETE, so `profiles delete` explains that and sends nothing (exit 2). Outcome
lines go to stderr; `--output json` and `table` print the acknowledgement on stdout.

`runtime dlp backup` writes one `airs` backup file (mode 0600, never overwriting anything; the
path is checked before the tenant is read) holding your custom dictionaries with their
keywords, patterns and profiles, with every predefined record a profile references as a
reference only. It records what it could not store (`skipped`, `failed`, `complete`); a
dictionary whose keywords cannot be read is a failed row (exit 1). The file holds detection
content in clear, so keep it private. `runtime dlp restore <file>` reads only `airs`
backups (a TypeScript backup is refused), refuses a backup from another TSG unless you pass
`--allow-other-tenant`, plans every row against the destination before any write (predefined
references resolved by id or name, `--pattern-map` for the rest, `--name-prefix` for copies),
offers `--dry-run`, asks on a terminal (`--force --expect-tsg <tsg>` for scripts), only ever
creates (never updates or deletes), sends each create once and stops at the first failure,
naming a resource that may have been created. `--on-conflict reconcile` gives an
archived-name collision a deterministic suffix, so a re-run verifies that copy instead of
creating another.

## Every flag

Every command and flag is in the [command reference](../reference/commands/runtime.md#airs-runtime-dlp).
