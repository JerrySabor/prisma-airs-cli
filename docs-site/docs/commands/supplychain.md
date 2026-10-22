---
title: supplychain
sidebar_position: 8
---

# `airs supplychain`

`airs supplychain` (the TypeScript CLI's `agentguard`) reads AI Supply Chain agent and
skill scan telemetry: scans and their findings, statistics, rules and the environment
report.

## Scans, statistics, rules and the report

```sh
airs supplychain scans list                                  # one page of 10 scans
airs supplychain scans ls --all --max 0 --output json        # every scan
airs supplychain scans list --start 2026-10-01T00:00:00Z --end 2026-10-20T00:00:00Z
airs supplychain scans vulnerabilities <scanUuid>            # finding metadata only
airs supplychain scans vulnerabilities <scanUuid> --include-content --output json > findings.json
airs supplychain stats
airs supplychain rules list --all
airs supplychain report                                      # new 0600 HTML file in the working directory
airs supplychain report --strict --max-pages 20 --output-file - > supplychain.html
```

The supplychain commands (TypeScript `agentguard`) use the tenant's `supplychainDataEndpoint`
and `supplychainMgmtEndpoint` (else the SDK defaults) with the management OAuth identity and the
`x-tsg-id` header. Every request is a read, sent once (a 401 or 403 is re-read once with a fresh
token). `scans list` prints nine fields of each scan and never its name, git URL, fingerprint,
device metadata or error text. `scans vulnerabilities` prints four fields of each finding;
`--include-content` prints each finding whole (titles, file paths, code and remediation text,
which can contain secrets from the scanned artifacts) on stdout only, with a notice on stderr; it never reaches stderr or the debug log. The service cannot page findings: when it
reports more findings than it returned, the rows are printed and the command fails with exit 1. `stats` is always a `Field │ Value` table. `pretty` is the table; the status line
says when a list is truncated and names the next `--offset`. `--limit`, `--offset` and
`--max` take decimal digits only, `--start` and `--end` ISO-8601 times with a zone, and every
argument check runs before the tenant is read (exit 2). A failure prints one line
with at most the HTTP status and no server text; a missing credential or a bad endpoint keeps
its own message. Answers are bounded at 32 MiB and 1,000,000 JSON values.

The service sends `null` in scan fields the published API contract requires (for example a
scan's `fingerprint`), which makes the TypeScript CLI refuse the whole scan list. `airs`
reads the scan list itself : a `null` field prints as `null` in JSON and an empty cell in
the tables, and every other row prints exactly as before. A scan list it still cannot
read, such as a scan without an id, fails with `The AgentGuard answer does not match the API
contract; nothing was printed.` (exit 1). The report counts such rows too: a missing
creation time excludes the row, a row marked as a batch or listing child scans is a parent
either way, and a row whose batch membership neither field decides is left out of the outcome
counts with a note. An empty answer to a scan list prints the request failure line, as
TypeScript does.

`supplychain report` writes an aggregate-only HTML report of the last 30 days: scan outcomes by
artifact type (parent and batch rows excluded), the server's 30-day skill statistics and the rule
catalog's default states, with an evidence table that marks every source `complete`, `partial` or
`unavailable`. No scan name, id, URL, fingerprint, device metadata, rule text or finding text is in
it. The default file is `airs-supplychain-report-<time>-<8 hex>.html`, created new at 0600
and never overwriting; `--output-file -` writes to stdout. HTML is the only format and
`--debug` is refused; `--max-pages` (1–100, default 40) bounds each paged source. Creation
times must carry a zone (a date alone is UTC midnight). Exit 1 when no source could be read,
or with `--strict` when one is incomplete; the document is written either way. Any other failure
prints one line, `Supply chain report failed …`.

## Every flag

Every command and flag is in the [command reference](../reference/commands/supplychain.md).
