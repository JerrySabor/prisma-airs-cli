---
title: redteam
sidebar_position: 5
---

# `airs redteam`

`airs redteam` covers AI Red Teaming: scans and their reports, targets, prompt sets and
prompts, properties, adapters, instances and devices, the network broker, the EULA, the
environment report, and target backup and restore.

## Reads

```sh
airs redteam list --status COMPLETED --limit 5
airs redteam status <jobId>
airs redteam categories --output json
airs redteam targets list --all --output json
airs redteam targets get <uuid>
airs redteam prompt-sets download <uuid> --output-file template.csv
airs redteam network-broker channels list --status ONLINE OFFLINE
```

The red team commands use the selected tenant's `redTeamDataEndpoint`,
`redTeamMgmtEndpoint` and `redTeamNetworkBrokerEndpoint` (else the AIRS defaults) with its
management credentials. Every read prints `pretty`, `table` and `json`; the lists and gets
honour the tenant's `defaultOutput`. Ids, numbers and filters are checked before the
tenant is read (a bad UUID is a usage error, exit 2), and so are the values the red team
API contract refuses: `--limit` of `list`, `targets error-logs` and
`report <jobId> --attacks` is at most 100; `list --status`, `--type` and `--target` and
`report --attacks --severity` take the API's values (for example `PARTIALLY_COMPLETE`,
`CLARA`, a target UUID, `HIGH`); `targets error-logs --offset` and `--search` are refused,
because the API pages error logs by `--limit` only; and `scan --depth` and `--breadth` are
at most 20. The `report --attacks` checks apply whatever the job type.

Answers are not checked for string formats: where the TypeScript CLI refuses an answer on a
format (an adapter whose `created_by_user_id` is not a UUID, for one), `airs` reads and
prints it; `adapter update` names a stored channel that is not a UUID and asks for
`--channel`. `targets create`, `update`, `probe` and `restore` send the red team management
API 0.86.0 values: `connection_type` `VERTEX_AI` and `N8N`, `response_mode` `REALTIME`, the
`client_session` multi-turn config and a Vertex AI connection config (`project_id`,
`location`, `engine_id`, `customer_sa_email`; a Vertex AI value outside the API's pattern
is refused before anything is sent). Such targets are read, printed (redacted) and backed
up. A Vertex AI target whose answer masks its `project_id`, `location` or `engine_id`
cannot be sent back, so the backup lists it as failed, naming the masked fields and telling
you to recreate the target or set them by hand, and exits 1; a mask only in
`customer_sa_email` is stored, marked as withheld.

Target, adapter and error-log documents never show a credential: auth settings (the basic
username and password included), secret headers, `curl` and the audio template
`audio_curl`, provider keys and the Vertex AI settings, secret-named keys and
`SECRET` adapter variables are `[REDACTED]` in every format. Lists are complete or an error: `prompt-sets list` reads every page and an
`--all` walk that meets an empty page before the reported total fails.
`prompt-sets download` never overwrites: an existing path is refused before any request,
the template is written at mode 0600, and `--output-file -` prints it.

## Writes and scans

```sh
airs redteam scan --target <uuid> --name nightly                 # STATIC, all categories, waits
airs redteam scan --target <uuid> --name probe --type DYNAMIC --goals goals.json --no-wait
airs redteam abort <jobId> --force
airs redteam targets init rest                                   # rest-target.json, mode 0600
airs redteam targets create --config rest-target.json --validate
airs redteam adapter create --name a --script-file adapter.py --prompt Hello --variables-file vars.json
airs redteam prompt-sets upload <uuid> prompts.csv
```

Every red team write is sent once: a 5xx, a timeout or a lost connection is never re-sent;
the error says the outcome is unknown, and for a scan start, an abort, the EULA and an upload
it names the command that shows what happened. Only a 401 is replayed, once, with a
fresh token. `scan` waits with progress on stderr for at most `--wait-timeout` minutes
(default 1440); a scan that is still running when the wait ends, fails or is interrupted is
reported as started and never aborted; `ABORTED` exits 1 and `PARTIALLY_COMPLETE` exits 0
with a warning. `abort`, `eula accept` and the deletes ask on a terminal; scripts
pass `--force` (without a terminal and without `--force` they are usage errors).
`devices delete` refuses a `--serial-numbers` list that names no serial number, and
`eula accept` an empty EULA.
Outcome lines and hints go to stderr; stdout holds the data in the chosen format. The
registry token is shown only with `--output json`; credentials in answers and the
validate-auth token preview are `[REDACTED]`. Input files (`--config`, `--goals`,
`--script-file`, `--variables-file`, the upload CSV) are read before the tenant with size caps;
`SECRET` adapter variables are refused on the command line, so put them in a
`--variables-file`. `targets init` never overwrites and writes mode 0600.

## Reports, backups and restores

```sh
airs redteam report <jobId> --attacks --severity HIGH            # one scan's report
airs redteam report <jobId> --output json
airs redteam report                                               # airs-redteam-report-<time>-<id>.html, 0600
airs redteam report --strict --output-file - > daily.html
airs redteam targets backup --output-dir ./backups                # one 0600 file with every target
airs redteam targets restore --file backups/airs-redteam-targets-….json --dry-run
airs redteam targets restore --file backups/airs-redteam-targets-….json --overwrite
```

A scan job report prints the TypeScript layout, or `--output json`/`table`. The
environment report reads seven sources (aggregates only, no names, ids or settings) and is
written as self-contained HTML only: `--output` is refused, and so is `--debug`;
it never overwrites a file and is mode 0600. `targets backup` writes one `airs` backup file per
run into an existing directory (default the current directory), mode 0600, never
overwritten; it holds every credential the service returns, so keep it private. It
stores only the settings the service sent. A target whose credentials the service withholds
(masks) is stored as returned, marked `credentialsWithheld` and listed with `⚠`; restore
refuses it, so recreate it or set its credentials by hand. `targets restore` reads only such a file (a
TypeScript backup is refused with a message), checks that it comes from the selected tenant's
TSG (`--allow-other-tenant` overrides), refuses duplicate or ambiguous names and withheld
credentials before any write, offers `--dry-run`, asks before `--overwrite` on a terminal
(`--force` for scripts), sends each write once and stops at the first unknown outcome.

## Every flag

Every command and flag is in the [command reference](../reference/commands/redteam.md).
