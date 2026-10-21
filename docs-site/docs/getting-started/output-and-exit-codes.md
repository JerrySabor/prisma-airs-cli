---
title: Output, exit codes and the debug log
sidebar_label: Output and exit codes
sidebar_position: 4
---

# Output, exit codes and the debug log

## Global flags

Every command accepts these flags, before or after the subcommand (the last one wins):

| Flag | Meaning |
|---|---|
| `--output <format>` | `pretty`, `table` or `json`. Any other value (including the dropped `markdown`, `csv` and `yaml`) is a usage error, exit 2. Without it, the read commands use the tenant's `defaultOutput`, else `pretty`. |
| `--quiet` | Suppress status lines, banners and headings. Data and errors still print. |
| `--debug` | Write redacted API diagnostics to a private JSONL file ([below](#the-debug-log)). Accepted and ignored by `tenant` commands. |
| `--tenant <name>` | Use this registered tenant for one invocation without changing the selection. Refused by the commands that change tenants, which take the name as an argument. |
| `-V`, `--version` | Print the bare version, such as `8.0.0`. |
| `-h`, `--help` | Print help. Every command's help is also in the [command reference](../reference/commands/index.md). |

A positional value that starts with `-` needs `--` before it
(`airs runtime scan --profile p -- "-a prompt"`). Option values may start with `-`.

## Output formats

| Format | Shape |
|---|---|
| `pretty` | a banner and readable blocks; the default |
| `table` | a box-drawing table (`Key │ Value` for a single record) |
| `json` | JSON: an array for lists, an object for single records |

`markdown`, `csv` and `yaml` are not supported. The HTML reports (`runtime report`,
`redteam report` without a job id, `gateway report`, `supplychain report`) are written as
HTML only and refuse `--output`.

Colour follows the terminal, decided separately for stdout and stderr: on for a terminal
(with `TERM` set and not `dumb`), off for pipes and files. `NO_COLOR` turns it off,
`CLICOLOR_FORCE` turns it on even when piped, and `CLICOLOR=0` turns it off. Tables, JSON
and bare values are never coloured.

## Streams

- **stdout carries data only.** A failing command leaves it empty, with these exceptions:
  `doctor` prints its report and exits 1 when a check fails; a scan whose verdict is
  `failed` prints its `FAILED` result and exits 1; `runtime bulk-scan` and
  `runtime resume-poll` print their summary and exit 1 when a row failed.
- **stderr carries status lines and errors.** `--quiet` hides the status lines, never the
  errors.
- **Secrets never print.** No output contains credentials, tokens, raw response bodies or
  URL queries; credential values are `[REDACTED]` or `[withheld]`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. A scan whose verdict is `block` also exits 0. |
| 1 | Operational failure: store, lock, tenant or tenant-file errors, missing credentials, HTTP, network or timeout errors, not found, failed scans, a failed doctor check, a write whose outcome is unknown. |
| 2 | Usage error, including every argument-parse error and every input error found before the tenant is read. Usage is checked before the tenant store is read, so a usage error never makes a request or a change. |
| 130 | Interrupted by SIGINT, or a prompt cancelled with Ctrl-C or Ctrl-D. In-flight requests are cancelled first. |
| 143 | Terminated by SIGTERM. In-flight requests are cancelled first. |

## The debug log

`--debug` writes `debug-api-<epoch ms>-<8 hex>.jsonl` to `$XDG_STATE_HOME/airs-cli/debug/`
(default `~/.local/state/airs-cli/debug/`). The directory is created 0700 and the file
0600; only the newest 20 logs are kept. stderr names the file (`  Debug: API log → <path>`,
hidden by `--quiet`). Each line is one HTTP attempt (token requests, retries and replays
included):

```json
{"timestamp":"2026-10-17T11:03:44.500Z","durationMs":6,"operation":"airs.management.profiles.list","request":{"method":"GET","url":"https://api.apps.paloaltonetworks.com/aisec/v1/mgmt/profiles/tsg/100","headers":{"authorization":"***","service-name":"api","user-agent":"PAN-AIRS/0.2.3-rust-sdk"}},"response":{"status":200,"statusText":"OK","headers":{"content-type":"application/json"}}}
```

Header values outside a short allow-list (`content-type`, `user-agent`, `date`,
`retry-after`, `x-request-id`, …) are written as `***`. No request or response body and no
URL query is ever written, so prompts, profiles and tokens never reach the file. A log that
cannot be created fails the command before any request; a write that fails later only
prints a warning and never changes the result. The HTML reports refuse `--debug`.
