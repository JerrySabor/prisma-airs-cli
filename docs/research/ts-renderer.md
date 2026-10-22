# TS renderer: `pretty` and `table` output, spec for `airs-cli-rs` 0.2 (M3.5)

Scope: the exact stdout/stderr bytes the TypeScript CLI writes in `pretty` and `table`
format (and when `--output` is absent) for every command `airs-cli-rs` has:
`tenant list|ls`, `tenant path`, `tenant read`, `tenant get`, `doctor`,
`runtime profiles list|ls`, `runtime profiles get`, `runtime topics list|ls`,
`runtime topics get`, `runtime scan`. It also records what the dropped formats
(`markdown`, `csv`, `yaml`) do today, lists TS behaviour the port should not copy, and
proposes the Rust renderer and its parity tests.

Sources:
- TS source at the frozen reference commit `5711012`:
  `.reference/prisma-airs-cli/src/cli/renderer/{common,ui,view,runtime}.ts`,
  `renderer/views/runtime.ts`, `cli/commands/{runtime,tenant,doctor}.ts`,
  `cli/program.ts`, `cli/invocation.ts`, `airs/management.ts`. Paths below are relative
  to `.reference/prisma-airs-cli/`.
- Libraries as installed in `.reference/prisma-airs-cli/node_modules`: chalk **5.6.2**
  (vendored supports-color), commander **14.0.3**, js-yaml **4.3.2**, TS SDK
  `@cdot65/prisma-airs-sdk` **0.34.0** (zod schemas in `dist/index.js`).
- Captures: `node .reference/prisma-airs-cli/dist/cli/index.js …` (node v24.21.0) run
  through the `airs-test-harness` runner (piped stdio, scrubbed environment that includes
  `NO_COLOR=1`) against a `FixtureServer` + `Sandbox`, with TTY runs under
  `script -q /dev/null sh -c …`. Loopback only, synthetic credentials. The capture tool
  is a scratch program (see Appendix A); it is not part of the repository.

Conventions in the captured blocks:
- Fenced blocks are verbatim stdout or stderr. Each block ends with the stream's final
  `\n`, which the block's last line ending stands for. **Table rows end with one
  space**; the rule line does not. When the exact bytes matter, the JSON-escaped string
  is given as well.
- The sandbox root (a 153-character temporary directory) is shown as `$SB`. In the one
  table whose padding depends on that path (doctor), the capture keeps a mask of the
  same length (`/SANDBOX____…`) so the padding stays exact. The fixture port is shown as
  `NNNNN` (same length).
- TTY captures show ESC as `\e`; the pty's `\r\n` line endings are shown as `\n` (Node
  writes `\n`; the terminal driver adds `\r`).

---

## 0. Findings in brief

1. **There is one table algorithm**, `formatOutput(rows, columns, 'table')`
   (`src/cli/renderer/common.ts:126-139`): cells are ` value.padEnd(w) `, joined by `│`;
   a rule of `─`×(w+2) joined by `┼`; no outer border, no indentation, no colour, no
   truncation, no wrapping. Widths are **UTF-16 code-unit lengths**. An empty row set
   renders as the empty string.
2. **No output depends on terminal width.** Nothing in the renderer reads
   `process.stdout.columns`. A 1,100-character policy cell is printed on one line, and a
   pty set to 30 columns gives the same bytes as a pipe (§2.7).
3. **Colour is chalk's, keyed off stdout alone.** It is on only when stdout is a TTY and
   `TERM`/`COLORTERM`/`TERM_PROGRAM` look capable, or when `FORCE_COLOR` forces it.
   `NO_COLOR` is **ignored**. Tables are never coloured; pretty layouts, status lines and
   errors are. Under the harness (pipes) there is never colour (§2.6).
4. **`pretty` means three different things.** For management commands it is a bespoke
   layout (banner, section, ID lines, key/value blocks). For `tenant list` and
   `tenant read` it is an alias of `table`. For `tenant get` it is the bare value.
5. **Format resolution**: explicit root `--output` (last occurrence anywhere in argv)
   wins. Otherwise management list/get use the tenant's `defaultOutput`, and every other
   command uses `pretty`. `tenant path` and `runtime scan` ignore `--output` entirely,
   even an invalid one (§1).
6. **Detail tables include unset fields as empty rows** (the JSON omits them), and detail
   tables JSON-stringify nested values compactly. The profile `policy` cell is one line.
7. **Candidate §12 rows** (§4): raw control characters in pretty and table output,
   `--quiet` dropping the ID lines of pretty lists, `undefined` printed for a missing
   ID, UTF-16 width padding misaligning CJK and combining text, surrogate-splitting
   description truncation, TTY colour and `NO_COLOR`, the pretty banner left on stdout by
   failing runs, the dropped formats, and `scan --output table`.

---

## 1. Format resolution

### 1.1 `resolveOutput` (`src/cli/renderer/common.ts:48-75`)

```ts
const localIsExplicit = command.getOptionValueSource?.('output') === 'cli';
// root = walk command.parent to the top
const globalOutput = root.getOptionValueSource('output') === 'cli' ? root.opts().output : undefined;
const configured = resolution.ignoreConfig ? undefined : (await loadConfig()).defaultOutput;
const candidate = String(localIsExplicit ? opts.output : (globalOutput ?? configured ?? 'pretty'));
if (!OUTPUT_FORMATS.includes(candidate))  throw CliUsageError(`Invalid output format '${candidate}'. Expected: pretty, table, markdown, csv, json, yaml`);
if (!allowed.includes(candidate))         throw CliUsageError(`Output format '${candidate}' is not supported here. Expected: ${allowed.join(', ')}`);
```

- `OUTPUT_FORMATS` is `pretty, table, markdown, csv, json, yaml` (`common.ts:32-40`).
  Names are case-sensitive.
- No command in scope passes `allowed`, so the "not supported here" branch never fires
  for them.
- No environment variable is consulted (`PANW_CLI_OUTPUT` is ignored), and neither is
  TTY status. The default is always `pretty`.
- **The tenant config is loaded before the format is validated** (except under
  `ignoreConfig`). So an invalid `--output` with no tenant selected exits 1 with the
  tenant error, not 2 (D2).

### 1.2 Interaction with commander's root parser

- The root registers `--output <format>` (`src/cli/program.ts:108`) without
  `enablePositionalOptions()`. The root therefore consumes `--output` **anywhere** in argv
  before a literal `--`, including after the leaf name, and **the last occurrence wins**.
  Leaf `--output` options (`runtime.ts:614,661,1138,1172`, `tenant.ts:168,198,225`,
  `doctor.ts:788`, `program.ts:58`) never receive a value. `localIsExplicit` is
  therefore never true in practice, and the resolved value always comes from the root.
- Captured: `--output table runtime profiles list` and `runtime profiles list --output
  table` print the same table (`profiles-list-root-output-table`).
- `preAction` (`program.ts:111-175`) resolves the format first for leaves whose name is
  in `READ_COMMAND_NAMES` (`program.ts:18-39`, includes `list` and `get`) and that have an
  `--output` option, except `tenant *` children. It stores the result with source
  `implied`; a resolution error goes through `fail()` (usage → exit 2). The action then
  resolves again (`runtime.ts:625,664,1141,1175`).

### 1.3 Per-command matrix (TS)

| Command | Accepts | When `--output` is absent | Tenant `defaultOutput` | `pretty` renders as | Invalid value |
|---|---|---|---|---|---|
| `runtime profiles list`, `profiles get`, `topics list`, `topics get` | all six | `defaultOutput ?? 'pretty'` | **honoured** (captured: `defaultOutput: "table"` gives a table, `"markdown"` gives markdown) | bespoke layout (§3.1–§3.4) | exit 2 `Invalid output format …` (after the tenant loads) |
| `tenant list` / `ls` | all six | `pretty` | ignored (`ignoreConfig`, `tenant.ts:201`) | `table` (`tenant.ts:214`) | exit 2 |
| `tenant read` | all six | `pretty` | ignored (`tenant.ts:228`) | `table` (`tenant.ts:236`) | exit 2 |
| `tenant get` | all six | `pretty` | ignored (`tenant.ts:172`; captured `defaultOutput-table-tenant-get`) | `String(value)` (`tenant.ts:176`) | exit 2, **after** key validation (D34) |
| `tenant path` | none of its own | n/a | n/a | n/a | **ignored**; `--output xml` prints the path, exit 0 (captured) |
| `doctor` | all six | `pretty` | ignored (`doctor.ts:799`) | bespoke layout (§3.9) | uncaught `CliUsageError`: a Node stack trace on stderr, exit 1 (captured `extra-doctor-bad`) |
| `runtime scan` | none | n/a | ignored | always the pretty layout | **ignored**; `--output xml` and `--output table` print the pretty result, exit 0 (captured) |

### 1.4 The dropped formats today (TS)

These remain valid TS names. The bytes, for reference only (`common.ts:96-125`,
`view.ts:53-58,63-87`):

- `json`: `JSON.stringify(x, null, 2)` + `\n`, using the structured record. An empty list
  is `[]\n`.
- `yaml`: `js-yaml dump(x, {noRefs: true, lineWidth: -1}).trimEnd()` + `\n`, using the
  structured record (nested block YAML; timestamps and digit strings are single-quoted).
  An empty list is `[]\n\n` (`formatOutput` returns `'[]\n'` and `console.log` adds
  another newline).
- `csv`: the label row, then the rows, joined by `\n` (no CRLF). A cell is quoted when it
  matches `/[",\r\n]/`, with `"` doubled. Objects are JSON-stringified and null or
  undefined become empty. An empty list prints **nothing** (`emitList` skips an empty
  render; `tenant list` prints `\n`).
- `markdown`: `| L1 | L2 |`, then `| --- | --- |`, then rows. `\` becomes `\\`, `|`
  becomes `\|` and line breaks become `<br>`. An empty list prints nothing.
- Status lines are the same as for every other format.

Captured `runtime profiles list --output csv` / `--output markdown` (stderr `  Showing 2`):

```
ID,Name,Active,Revision
00000000-0000-4000-8000-000000000002,alpha,true,2
00000000-0000-4000-8000-000000000003,beta,true,1
```

```
| ID | Name | Active | Revision |
| --- | --- | --- | --- |
| 00000000-0000-4000-8000-000000000002 | alpha | true | 2 |
| 00000000-0000-4000-8000-000000000003 | beta | true | 1 |
```

Captured `runtime profiles list --output yaml` (first profile shown):

```
- profileId: 00000000-0000-4000-8000-000000000002
  profileName: alpha
  revision: 2
  active: true
  createdBy: creator@example.com
  updatedBy: updater@example.com
  lastModifiedTs: '2026-02-01T00:00:00Z'
  policy:
    ai-security-profiles:
      - model-type: default
        model-configuration:
          mask-data-in-storage: false
    dlp-data-profiles: []
```

Empty yaml list: stdout `"[]\n\n"`; empty csv: stdout `""`.

---

## 2. Shared primitives

### 2.1 Writes

All output goes through `console.log` / `console.error`, so each call appends `\n`, and
`console.log()` with no argument writes `\n`. Writes are immediate: in TS the pretty
banner reaches stdout before any request is made (§4, R8).

### 2.2 `ui` primitives (`src/cli/renderer/ui.ts`)

Indent `INDENT = "  "` (`ui.ts:13`). Glyphs (`ui.ts:34-42`): neutral `•` U+2022,
success `✓` U+2713, error `✗` U+2717, warn `⚠` U+26A0, skip `○` U+25CB, flag `●` U+25CF,
info `ℹ` U+2139. Colours (`ui.ts:44-52`): neutral dim, success green, error red, warn,
skip and flag yellow, info cyan.

| Primitive | Bytes (no colour) | Stream | `--quiet` | Colour (TTY) |
|---|---|---|---|---|
| `header(t, s)` `:56-61` | `\n  <t>\n` + (`s` ? `  <s>\n` : ``) + `\n` | stdout | suppressed | `t` bold, `s` dim |
| `section(l)` `:64-67` | `\n  <l>\n\n` | stdout | suppressed | bold |
| `keyValue(pairs)` `:70-75` | per pair `  ` + key.padEnd(W) + `  ` + `String(v ?? '')` + `\n`, W = max key `.length` in this call | stdout | **printed** | padded key dim (padding inside the dim span) |
| `bullet(m, kind)` `:119-121` | `  <glyph> <m>\n` | stdout | **printed** | glyph only |
| `dim(m)` `:124-128` | `  <m>\n` (after `commandHint`) | stdout | suppressed | dim |
| `status(m)` `:131-135` | `  <m>\n` (after `commandHint`) | **stderr** | suppressed | dim |
| `emptyList(r)` `:138-140` | `  No <r> found\n` | stdout | **printed** | dim |
| `success(m)` `:90-93` | `  ✓ <m>\n` | stdout | printed | `✓ m` green |
| `error(m)` `:113-116` | `  ✗ <m>\n` | stderr | printed | `✗ m` red |

`commandHint` (`src/cli/invocation.ts:7-9`) rewrites `airs-cli ` to `airs cli ` only when
`AIRS_CLI_INVOKED_AS === 'airs cli'`. It is applied to `dim` and `status` text, which
includes the profile and topic ID lines of pretty lists. With that variable set, a
profile without `profile_id` makes `ui.dim(undefined)` throw (`text.replaceAll` of
undefined); without it, `undefined` is printed (§3.1). This was derived from the source,
not captured.

### 2.3 The table algorithm (`formatOutput(..., 'table')`, `common.ts:82-85,96-106,126-139`)

```ts
function displayValue(value) {               // common.ts:82-85
  if (value == null) return '';               // null and undefined
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}
if (rows.length === 0) return '';             // common.ts:101-105
const projected = rows.map(row => columns.map(c => row[c.key]));
const values = projected.map(row => row.map(displayValue));
const widths = columns.map((c, i) => Math.max(c.label.length, ...values.map(r => r[i].length)));
const separator = widths.map(w => '─'.repeat(w + 2)).join('┼');
const header = columns.map((c, i) => ` ${c.label.padEnd(widths[i])} `).join('│');
const body = values.map(r => r.map((v, i) => ` ${v.padEnd(widths[i])} `).join('│'));
return [header, separator, ...body].join('\n');
```

Exact properties:
- `│` is U+2502, `─` U+2500, `┼` U+253C. There is no outer border, no top or bottom rule
  and no indentation (`ui.table`, the indented variant at `ui.ts:78-88`, is not used by
  any in-scope command).
- The header and every body line start with a space and **end with a space**. The rule
  line has neither, and it is exactly as long as the header in UTF-16 units.
- `.length` and `padEnd` count **UTF-16 code units**. `ø` counts 1, `日` counts 1 but
  displays 2 columns, `🚀` counts 2 and displays 2, a combining mark counts 1 and
  displays 0. So CJK and combining text misalign (captured in §3.1 and §3.3).
- Values are not escaped, so a `\n` inside a cell breaks the row across lines and a `\t`
  or ESC passes straight through (captured in §3.1, §3.3 and §4).
- `String(number)` is ECMAScript `Number::toString`: `2.5`, `1e+21`, `0.000001`, `1e-7`.
  `String(boolean)` is `true` or `false`.
- Objects and arrays use `JSON.stringify(value)`, which is compact, keeps insertion
  order (JS puts integer-like keys first, ascending), leaves non-ASCII unescaped and
  escapes `"`, `\` and C0 controls.
- No truncation, no wrapping, no width limit.
- The caller writes the result with `console.log`, adding one `\n`. `emitList` skips the
  write when the result is empty (`view.ts:57-58`); `tenant list` and `emitDetail` do
  not (§3.5).

### 2.4 `emitList` / `emitDetail` (`src/cli/renderer/view.ts:43-88`)

- `emitList(view, items, format, {page})`:
  - `pretty`: `items.length === 0` → `ui.emptyList(view.name)`, else
    `view.pretty.list(items)`.
  - otherwise: `json`/`yaml` use `view.structured?.(item) ?? item`. `table`, `csv` and
    `markdown` use the **column projection** `{[col.key]: item[col.key]}`. The result
    goes to `formatOutput`, and is printed only when non-empty.
  - Then, for every format, `renderPageStatus(page)`.
- `emitDetail(view, item, format)`:
  - `pretty`: `view.pretty.detail(item)`.
  - `json`: `JSON.stringify(structured, null, 2)`.
  - `table`, `csv`, `markdown`: rows `{key, value}` for **every own key** of the
    structured record (`Object.entries`, so keys whose value is `undefined` are
    included), with object values pre-stringified. Columns are `Key` and `Value`.
  - No page status.
- The view columns (`src/cli/renderer/views/runtime.ts`):
  - profiles (`:15-27`): `ID←profileId, Name←profileName, Active←active,
    Revision←revision`. No `structured`, so the record is the normalised
    `SecurityProfileInfo` (`src/airs/management.ts:243-254`), which always has the eight
    keys `profileId, profileName, revision, active, createdBy, updatedBy, lastModifiedTs,
    policy`, some possibly `undefined`.
  - topics (`:56-80`): `ID←topic_id, Name←topic_name, Revision←revision,
    Description←description`, projected from the raw (zod-parsed) wire object. The
    structured record has the ten keys `topicId, topicName, revision, active,
    description, examples, createdBy, updatedBy, lastModifiedTs, createdTs`.
- The `format !== 'pretty'` branches inside `renderProfileList` / `renderTopicList`
  (`renderer/runtime.ts:94-109,249-269`, columns `ID, Name, Status, Revision` with
  `active`/`inactive`) are **unreachable** from these commands: `emitList` only calls
  them with `'pretty'`.

### 2.5 Page status (`view.ts:32-41`, stderr, `--quiet` suppresses it, every format)

`all` → `Showing all <total ?? returned>`; `total` known → `Showing <r> of <t>` plus
` (next --offset <n>)` when `next` is set; else `next` set → `Showing <r> (more
available)`; else `Showing <r>`. An empty list prints `Showing 0`. `get --all-versions`
prints no status. Per command, see §3 and DESIGN §7.3 (D12–D14 apply to every format).

### 2.6 Colour

Level detection (`node_modules/chalk/source/index.js:30`,
`vendor/supports-color/index.js`):
- The level is computed **once, from stdout** (`tty.isatty(1)`), and the same chalk
  instance colours stderr. So `cmd 2>file` on a terminal writes ANSI into `file`, while
  `cmd | cat` leaves stderr uncoloured even on a terminal (both captured).
- `FORCE_COLOR` (`supports-color:33-45`): `true` or empty means level 1, `false` means
  off, otherwise `min(parseInt(v), 3)`, so `0` is off. A non-numeric value gives `NaN`,
  which is neither a force nor an off: it falls through to the TTY and `TERM` checks.
- argv flags `--color`, `--no-color`, `--color=…` are sniffed before `--`. They would
  also be rejected by commander as unknown options, so they are not usable.
- `TF_BUILD` + `AGENT_NAME` gives level 1 **even when piped** (`:86-88`).
- Not a TTY and not forced → 0 (`:90-92`). `TERM=dumb` → 0 unless forced.
- On a TTY: `CI` (level 3 for GitHub/Gitea/Circle, 1 for Travis and others, else 0),
  `COLORTERM=truecolor` → 3, `TERM_PROGRAM` iTerm/Apple_Terminal → 3/2, `TERM` matching
  `-256(color)?$` → 2, or `^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux` →
  1, `COLORTERM` set → 1, **otherwise 0**. A pty with no `TERM` is uncoloured (captured
  `tty-profiles-list-noterm`).
- **`NO_COLOR` is not read by chalk.** Every TTY capture below ran with `NO_COLOR=1`
  and is coloured. Node itself warns when both `FORCE_COLOR` and `NO_COLOR` are set;
  stderr then starts with two extra lines (captured `piped-force-color-1`):

  ```
  (node:<pid>) Warning: The 'NO_COLOR' env is ignored due to the 'FORCE_COLOR' env being set.
  (Use `node --trace-warnings ...` to show where the warning was created)
  ```

SGR codes (any level ≥ 1; these basic styles are identical at levels 1–3): bold
`\e[1m…\e[22m`, dim `\e[2m…\e[22m`, red `\e[31m…\e[39m`, green `\e[32m…\e[39m`, yellow
`\e[33m…\e[39m`, cyan `\e[36m…\e[39m`. chalk's `applyStyle` (`chalk/source/index.js:168-199`):
- An empty string gets no codes.
- A string containing `\n` is closed before each line break and reopened after it. So
  `chalk.red("\n  ✗ Error: x")` is `\e[31m\e[39m\n\e[31m  ✗ Error: x\e[39m`.
- A string that already contains the style's close code has it replaced by a re-open
  code.

What is coloured, per command, is listed in §3. Tables (`formatOutput`) and the bare
`tenant get` value never are.

Captured, pty with `TERM=xterm-256color`, stderr redirected to a file (`$CLI 2>"$ERR"`),
`runtime profiles list`:

```

  \e[1mPrisma AIRS — Runtime Configuration\e[22m
  \e[2mSecurity profile and topic management\e[22m


  \e[1mSecurity Profiles:\e[22m

  \e[2m00000000-0000-4000-8000-000000000002\e[22m
    alpha  \e[32mactive\e[39m\e[2m rev:2\e[22m
  \e[2m00000000-0000-4000-8000-000000000003\e[22m
    beta  \e[32mactive\e[39m\e[2m rev:1\e[22m

```

stderr (a file, still coloured because stdout is a TTY): `"  \u001b[2mShowing 2\u001b[22m\n"`

Same command with stdout redirected to a file and stderr on the pty (`$CLI 2>&1 >"$ERR"`):
the file gets the uncoloured pretty layout and the terminal gets `  Showing 2` with no
ANSI (`tty-profiles-list-stdout-piped`). With `FORCE_COLOR=0`, or with no `TERM`, the pty
output has no ANSI at all.

Piped with `FORCE_COLOR=1` (`piped-force-color-1`), stdout:

```

  \e[1mPrisma AIRS — Runtime Configuration\e[22m
  \e[2mSecurity profile and topic management\e[22m


  \e[1mSecurity Profiles:\e[22m

  \e[2m00000000-0000-4000-8000-000000000002\e[22m
    alpha  \e[32mactive\e[39m\e[2m rev:2\e[22m
  \e[2m00000000-0000-4000-8000-000000000003\e[22m
    beta  \e[32mactive\e[39m\e[2m rev:1\e[22m

```

### 2.7 Terminal width

No in-scope output reads `process.stdout.columns`; only commander's help text wraps
(help is not in scope). Under `script` the pty starts at 0×0
(`process.stdout.columns === 0`). With `stty cols 30` the table bytes are unchanged
(`tty-profiles-list-table`):

```
 ID                                   │ Name  │ Active │ Revision 
──────────────────────────────────────┼───────┼────────┼──────────
 00000000-0000-4000-8000-000000000002 │ alpha │ true   │ 2        
 00000000-0000-4000-8000-000000000003 │ beta  │ true   │ 1        
```

The only truncations in scope are the topic list description (`slice(0, 80)`, UTF-16
units, no ellipsis, §3.3) and the scan prompt preview on stderr (DESIGN §8.2, D43).

### 2.8 Value formatting summary

| Value | pretty layouts | table cell |
|---|---|---|
| string | verbatim (control characters included) | verbatim |
| number | `String(n)` (`rev:2.5`, `rev:1e+21`) | `String(n)` |
| boolean `active` | `active` / `inactive` (truthiness: `undefined` → `inactive`) | `true` / `false`; `undefined` → empty |
| `undefined` / `null` | field line omitted (detail), or `undefined` (list ID line) | empty |
| timestamps | verbatim strings (no date parsing or reformatting) | verbatim |
| object / array | profile `Policy`: `JSON.stringify(v, null, 2)`, continuation lines indented by 2 | `JSON.stringify(v)` (compact) |

---

## 3. Per-command output

Fixtures (from `crates/airs-test-harness/src/fixtures.rs`): profiles `alpha` r1 (id …001),
`alpha` r2 (…002), `beta` r1 (…003); topics `fin` r1 "old" (…011), `fin` r2 "new" (…012),
`legal` r1 "legal desc" (…013), each with one example `<name> example`. Edge rows are
described where they are used.

### 3.1 `runtime profiles list` (`runtime.ts:611-650`, `renderer/runtime.ts:79-119`)

**pretty** (the default when neither `--output` nor `defaultOutput` is set):

```
stdout:
  [banner, quiet-suppressed]  "\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n"
  empty list:                 "  No profiles found\n"                       (printed under --quiet)
  otherwise:
    [section, quiet-suppressed] "\n  Security Profiles:\n\n"
    per profile, in service order:
      [ui.dim, quiet-suppressed] "  " + String(profileId) + "\n"            ("undefined" when absent)
      "    " + profileName + "  " + (active ? "active" : "inactive") + (revision != null ? " rev:" + String(revision) : "") + "\n"
    "\n"                                                                     (printed under --quiet)
stderr: page status (§2.5)
```

- Banner: `renderRuntimeConfigHeader` (`renderer/runtime.ts:74-76`), written **before**
  credentials are checked and before any request (`runtime.ts:627`). The em dash is
  U+2014.
- TTY colour: banner title bold, subtitle dim, section bold, ID line dim, `active` green,
  `inactive` yellow, ` rev:N` dim (the leading space is inside the dim span), status dim.

Captured (stderr `  Showing 2`; `--limit 1` gives `  Showing 1 (more available)`,
`--all` gives `  Showing all 2`, `--all-versions` lists all three rows with
`  Showing 3`):

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Security Profiles:

  00000000-0000-4000-8000-000000000002
    alpha  active rev:2
  00000000-0000-4000-8000-000000000003
    beta  active rev:1

```

`--quiet` (stderr empty):

```
    alpha  active rev:2
    beta  active rev:1

```

Empty: stdout `"\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n  No profiles found\n"`, stderr `"  Showing 0\n"`.
Empty with `--quiet`: stdout `"  No profiles found\n"`, stderr empty.

Edge rows (a profile without `profile_id`, `revision`, `created_by`, `updated_by` and
`policy`, with `active: false`; one without `active`, `revision: 0`; a 76-character name;
`prøfile-日本語-🚀`; `pipe|comma,quote"`; `multi\nline`; `big-policy`):

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Security Profiles:

  undefined
    no-id-inactive  inactive
  00000000-0000-4000-8000-000000000010
    no-active-field  inactive rev:0
  00000000-0000-4000-8000-000000000005
    a-very-long-security-profile-name-that-goes-on-and-on-for-a-while-0123456789  active rev:3
  00000000-0000-4000-8000-000000000006
    prøfile-日本語-🚀  active rev:1
  00000000-0000-4000-8000-000000000007
    pipe|comma,quote"  active rev:1
  00000000-0000-4000-8000-000000000008
    multi
line  active rev:1
  00000000-0000-4000-8000-000000000004
    big-policy  active rev:7

```

**table**: columns `ID | Name | Active | Revision` from `profileId, profileName,
active, revision`. stdout is the table + `\n`; an empty list prints **nothing** (stdout
empty); stderr has the page status. No banner. `--quiet` removes only the status.

```
 ID                                   │ Name  │ Active │ Revision 
──────────────────────────────────────┼───────┼────────┼──────────
 00000000-0000-4000-8000-000000000002 │ alpha │ true   │ 2        
 00000000-0000-4000-8000-000000000003 │ beta  │ true   │ 1        
```

Exact bytes: `" ID                                   │ Name  │ Active │ Revision \n──────────────────────────────────────┼───────┼────────┼──────────\n 00000000-0000-4000-8000-000000000002 │ alpha │ true   │ 2        \n 00000000-0000-4000-8000-000000000003 │ beta  │ true   │ 1        \n"`

Edge rows. Note the empty ID cell, the empty `Active` cell for an absent `active`, the
three-column drift caused by `日本語` (3 UTF-16 units, 6 columns), and the row broken by
the embedded newline:

```
 ID                                   │ Name                                                                         │ Active │ Revision 
──────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────┼────────┼──────────
                                      │ no-id-inactive                                                               │ false  │          
 00000000-0000-4000-8000-000000000010 │ no-active-field                                                              │        │ 0        
 00000000-0000-4000-8000-000000000005 │ a-very-long-security-profile-name-that-goes-on-and-on-for-a-while-0123456789 │ true   │ 3        
 00000000-0000-4000-8000-000000000006 │ prøfile-日本語-🚀                                                               │ true   │ 1        
 00000000-0000-4000-8000-000000000007 │ pipe|comma,quote"                                                            │ true   │ 1        
 00000000-0000-4000-8000-000000000008 │ multi
line                                                                   │ true   │ 1        
 00000000-0000-4000-8000-000000000004 │ big-policy                                                                   │ true   │ 7        
```

Number formatting (`revision` 2.5 and 1e21) and raw control characters (a name
containing ESC `[31m` and a TAB). `pretty`:

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Security Profiles:

  00000000-0000-4000-8000-000000000031
    frac-rev  active rev:2.5
  00000000-0000-4000-8000-000000000032
    huge-rev  active rev:1e+21
  00000000-0000-4000-8000-000000000033
    ctl[31mred	tab  active rev:1

```

`table` (bytes `" ID                                   │ Name            │ Active │ Revision \n──────────────────────────────────────┼─────────────────┼────────┼──────────\n 00000000-0000-4000-8000-000000000031 │ frac-rev        │ true   │ 2.5      \n 00000000-0000-4000-8000-000000000032 │ huge-rev        │ true   │ 1e+21    \n 00000000-0000-4000-8000-000000000033 │ ctl\u001b[31mred\ttab │ true   │ 1        \n"`).

### 3.2 `runtime profiles get <nameOrId>` (`runtime.ts:656-690`, `renderer/runtime.ts:122-148`)

**pretty**: banner (as in §3.1, quiet-suppressed) + section `\n  Profile Detail:\n\n`
(quiet-suppressed) + `ui.keyValue(pairs)` + `\n`. `pairs`, in this order:

| Key | Included when | Value |
|---|---|---|
| `ID` | always | `String(profileId ?? '')` |
| `Name` | always | `profileName` |
| `Status` | always | `active ? 'active' : 'inactive'` (TTY: green / yellow) |
| `Revision` | `revision != null` (0 included) | `String(revision)` |
| `Created` | `createdBy` truthy | verbatim |
| `Updated` | `updatedBy` truthy | verbatim |
| `Modified` | `lastModifiedTs` truthy | verbatim |
| `Policy` | `policy` truthy (`{}` included) | `JSON.stringify(policy, null, 2)` with every `\n` replaced by `\n  ` |

The key width W is the longest included key (8 when `Revision` or `Modified` is present,
otherwise 7 or 6). Each line is `"  " + key.padEnd(W) + "  " + value`. Policy
continuation lines therefore start at column 2 plus the JSON indent, **not** under the
value column. Keys are dim on a TTY. The key/value lines and the final `\n` are printed
under `--quiet`.

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Profile Detail:

  ID        00000000-0000-4000-8000-000000000002
  Name      alpha
  Status    active
  Revision  2
  Created   creator@example.com
  Updated   updater@example.com
  Modified  2026-02-01T00:00:00Z
  Policy    {
    "ai-security-profiles": [
      {
        "model-type": "default",
        "model-configuration": {
          "mask-data-in-storage": false
        }
      }
    ],
    "dlp-data-profiles": []
  }

```

`--quiet`:

```
  ID        00000000-0000-4000-8000-000000000002
  Name      alpha
  Status    active
  Revision  2
  Created   creator@example.com
  Updated   updater@example.com
  Modified  2026-02-01T00:00:00Z
  Policy    {
    "ai-security-profiles": [
      {
        "model-type": "default",
        "model-configuration": {
          "mask-data-in-storage": false
        }
      }
    ],
    "dlp-data-profiles": []
  }

```

Sparse profile (no id, revision, creator, updater or policy; `active: false`):

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Profile Detail:

  ID        
  Name      no-id-inactive
  Status    inactive
  Modified  2026-02-01T00:00:00Z

```

`policy: {}` → the line `  Policy    {}` (`extra-profiles-get-emptypolicy`).

Large policy (the JSON key order is the zod-parsed order; JS puts integer-like keys of
an object first, so the unknown object `{"10":…,"2":…,"a":…,"b":…}` from the wire prints
`"2", "10", "a", "b"`):

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Profile Detail:

  ID        00000000-0000-4000-8000-000000000004
  Name      big-policy
  Status    active
  Revision  7
  Created   creator@example.com
  Updated   updater@example.com
  Modified  2026-02-01T00:00:00Z
  Policy    {
    "ai-security-profiles": [
      {
        "model-type": "default",
        "content-type": "text",
        "model-configuration": {
          "mask-data-in-storage": true,
          "latency": {
            "inline-timeout-action": "block",
            "max-inline-latency": 20
          },
          "data-protection": {
            "data-leak-detection": {
              "member": [
                {
                  "text": "Bank Account Numbers",
                  "id": "11995035",
                  "version": "2"
                }
              ],
              "action": "block",
              "mask-data-inline": false
            },
            "database-security": [
              {
                "name": "database-security-create",
                "action": "allow"
              }
            ]
          },
          "app-protection": {
            "alert-url-category": {
              "member": [
                "adult",
                "gambling"
              ]
            },
            "block-url-category": {
              "member": null
            },
            "url-detected-action": "alert",
            "malicious-code-protection": {
              "name": "malicious-code",
              "action": "block"
            }
          },
          "model-protection": [
            {
              "name": "prompt-injection",
              "action": "block",
              "options": []
            },
            {
              "name": "topic-guardrails",
              "action": "",
              "topic-list": [
                {
                  "action": "block",
                  "topic": [
                    {
                      "topic_name": "fin",
                      "topic_id": "00000000-0000-4000-8000-000000000012",
                      "revision": 2
                    }
                  ]
                }
              ]
            },
            {
              "name": "toxic-content",
              "action": "high:block, moderate:block"
            }
          ],
          "agent-protection": [
            {
              "name": "agent-security",
              "action": "block"
            }
          ]
        }
      }
    ],
    "dlp-data-profiles": [
      {
        "name": "Bank Account Numbers",
        "uuid": "aa3c0e2b-0000-4000-8000-000000000001",
        "rule1": {
          "action": "block"
        }
      }
    ],
    "zz-unknown": {
      "2": "two",
      "10": "ten",
      "a": 1,
      "b": 2
    }
  }

```

TTY (`tty-profiles-get-pretty`; the key padding is inside the dim span):

```

  \e[1mPrisma AIRS — Runtime Configuration\e[22m
  \e[2mSecurity profile and topic management\e[22m


  \e[1mProfile Detail:\e[22m

  \e[2mID      \e[22m  00000000-0000-4000-8000-000000000002
  \e[2mName    \e[22m  alpha
  \e[2mStatus  \e[22m  \e[32mactive\e[39m
  \e[2mRevision\e[22m  2
  \e[2mCreated \e[22m  creator@example.com
  \e[2mUpdated \e[22m  updater@example.com
  \e[2mModified\e[22m  2026-02-01T00:00:00Z
  \e[2mPolicy  \e[22m  {
    "ai-security-profiles": [
      {
        "model-type": "default",
        "model-configuration": {
          "mask-data-in-storage": false
        }
      }
    ],
    "dlp-data-profiles": []
  }

```

**table**: a `Key | Value` table of all eight record keys in the order
`profileId, profileName, revision, active, createdBy, updatedBy, lastModifiedTs, policy`.
Unset keys are **empty rows**. `policy` is compact JSON. No banner, no status.

```
 Key            │ Value                                                                                                                           
────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 profileId      │ 00000000-0000-4000-8000-000000000002                                                                                            
 profileName    │ alpha                                                                                                                           
 revision       │ 2                                                                                                                               
 active         │ true                                                                                                                            
 createdBy      │ creator@example.com                                                                                                             
 updatedBy      │ updater@example.com                                                                                                             
 lastModifiedTs │ 2026-02-01T00:00:00Z                                                                                                            
 policy         │ {"ai-security-profiles":[{"model-type":"default","model-configuration":{"mask-data-in-storage":false}}],"dlp-data-profiles":[]} 
```

Sparse profile:

```
 Key            │ Value                
────────────────┼──────────────────────
 profileId      │                      
 profileName    │ no-id-inactive       
 revision       │                      
 active         │ false                
 createdBy      │                      
 updatedBy      │                      
 lastModifiedTs │ 2026-02-01T00:00:00Z 
 policy         │                      
```

The large policy gives a single 1,000+ character `policy` cell, and every row is padded
to it (`profiles-get-big-table`).

**`--all-versions`**: `emitList` without a page. pretty is the list layout of §3.1 (banner,
`Security Profiles:` section) for the matching rows, **with no status line**; table is
the list table (`ID | Name | Active | Revision`). **`--revision N`** (without
`--all-versions`): the detail views.

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Security Profiles:

  00000000-0000-4000-8000-000000000001
    alpha  active rev:1
  00000000-0000-4000-8000-000000000002
    alpha  active rev:2

```

**Not found / any failure in pretty**: the banner is already on stdout, then the error on
stderr. Exit 1.

stdout `"\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n"`; stderr `"\n  ✗ Error: AISEC_USER_REQUEST_PAYLOAD_ERROR:Profile not found: nosuch\n\n"`.
In `table` the stdout is empty (`profiles-get-notfound-table`).

### 3.3 `runtime topics list` (`runtime.ts:1169-1201`, `renderer/runtime.ts:236-278`)

**pretty**:

```
stdout:
  [banner, quiet-suppressed]
  empty: "  No topics found\n"
  otherwise:
    [section, quiet-suppressed] "\n  Custom Topics:\n\n"
    per topic:
      [ui.dim, quiet-suppressed] "  " + String(topic_id) + "\n"             ("undefined" when absent)
      "    " + topic_name + (revision != null ? " rev:" + String(revision) : "") + (description ? " — " + description.slice(0, 80) : "") + "\n"
    "\n"
stderr: page status
```

- `revision` is required by the SDK schema, so ` rev:N` is always present. An empty
  description omits the ` — …` part.
- The description is cut to the first **80 UTF-16 units** with **no ellipsis**; a cut
  through a surrogate pair leaves a lone surrogate, which Node writes as U+FFFD
  (`EF BF BD`).
- TTY: ID dim, ` rev:N` dim, ` — desc` dim (as separate spans).
- Status: latest listing always `Showing <n>` (D13: `--limit 1` with more rows still says
  `  Showing 1`); `--all-versions` page `Showing <r> of <t>[ (next --offset <n>)]`;
  `--all` `Showing all <n>`.

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Custom Topics:

  00000000-0000-4000-8000-000000000012
    fin rev:2 — new
  00000000-0000-4000-8000-000000000013
    legal rev:1 — legal desc

```

Edge rows (an 80-character prefix that ends inside `🚀`; several examples; an empty
description; no `topic_id`; `tøpic-日本語` with a newline in the description):

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Custom Topics:

  00000000-0000-4000-8000-000000000020
    long-desc rev:1 — ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd�
  00000000-0000-4000-8000-000000000021
    many-examples rev:3 — Has several examples
  00000000-0000-4000-8000-000000000022
    no-examples rev:1
  undefined
    no-id rev:1 — desc
  00000000-0000-4000-8000-000000000024
    tøpic-日本語 rev:1 — line one
line two | pipe

```

`--quiet`: `"    fin rev:2 — new\n    legal rev:1 — legal desc\n\n"`. Empty: stdout `"\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n  No topics found\n"`,
stderr `"  Showing 0\n"`.

**table**: columns `ID | Name | Revision | Description` from the raw `topic_id,
topic_name, revision, description`. The description is **not** truncated. An empty list
prints nothing.

```
 ID                                   │ Name  │ Revision │ Description 
──────────────────────────────────────┼───────┼──────────┼─────────────
 00000000-0000-4000-8000-000000000012 │ fin   │ 2        │ new         
 00000000-0000-4000-8000-000000000013 │ legal │ 1        │ legal desc  
```

`--all-versions --limit 2` (stderr `  Showing 2 of 3 (next --offset 2)`):

```
 ID                                   │ Name │ Revision │ Description 
──────────────────────────────────────┼──────┼──────────┼─────────────
 00000000-0000-4000-8000-000000000011 │ fin  │ 1        │ old         
 00000000-0000-4000-8000-000000000012 │ fin  │ 2        │ new         
```

Edge rows:

```
 ID                                   │ Name          │ Revision │ Description                                                                                              
──────────────────────────────────────┼───────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────
 00000000-0000-4000-8000-000000000020 │ long-desc     │ 1        │ ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd🚀tail after the boundary 
 00000000-0000-4000-8000-000000000021 │ many-examples │ 3        │ Has several examples                                                                                     
 00000000-0000-4000-8000-000000000022 │ no-examples   │ 1        │                                                                                                          
                                      │ no-id         │ 1        │ desc                                                                                                     
 00000000-0000-4000-8000-000000000024 │ tøpic-日本語     │ 1        │ line one
line two | pipe                                                                                 
```

### 3.4 `runtime topics get <nameOrId>` (`runtime.ts:1133-1167`, `renderer/runtime.ts:281-311`)

**pretty**: banner + section `\n  Topic Detail:\n\n` (both quiet-suppressed), then:

1. `keyValue` block 1, with its own width: `ID` (always, `topic_id ?? ''`), `Name`
   (always), `Revision` (`!= null`), `Description` (truthy). Width 11 with
   `Description`, else 8.
2. When `examples.length > 0`: `"  Examples:\n"` (plain, printed under `--quiet`), then
   per example `"  • " + example + "\n"` (`ui.bullet` neutral: the glyph is dim on a
   TTY, the text is verbatim and can contain newlines).
3. `keyValue` block 2, only when non-empty, with its **own** width: `Created`
   (`created_by` truthy), `Updated` (`updated_by` truthy), `Modified`
   (`last_modified_ts` truthy). Width 8 when `Modified` is present, else 7.
4. `"\n"`.

`active` and `created_ts` are never shown in pretty.

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Topic Detail:

  ID           00000000-0000-4000-8000-000000000012
  Name         fin
  Revision     2
  Description  new
  Examples:
  • fin example
  Created   creator@example.com
  Modified  2026-02-01T00:00:00Z

```

Many examples (one with a newline, one with non-ASCII) and an updater:

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Topic Detail:

  ID           00000000-0000-4000-8000-000000000021
  Name         many-examples
  Revision     3
  Description  Has several examples
  Examples:
  • first example
  • second, with comma
  • third | pipe
  • multi
line example
  • ünïcödé 日本 🚀
  Created   creator@example.com
  Updated   updater@example.com
  Modified  2026-02-01T00:00:00Z

```

No description, no examples, no metadata:

```

  Prisma AIRS — Runtime Configuration
  Security profile and topic management


  Topic Detail:

  ID        00000000-0000-4000-8000-000000000022
  Name      no-examples
  Revision  1

```

TTY (`tty-topics-get-pretty`):

```

  \e[1mPrisma AIRS — Runtime Configuration\e[22m
  \e[2mSecurity profile and topic management\e[22m


  \e[1mTopic Detail:\e[22m

  \e[2mID         \e[22m  00000000-0000-4000-8000-000000000012
  \e[2mName       \e[22m  fin
  \e[2mRevision   \e[22m  2
  \e[2mDescription\e[22m  new
  Examples:
  \e[2m•\e[22m fin example
  \e[2mCreated \e[22m  creator@example.com
  \e[2mModified\e[22m  2026-02-01T00:00:00Z

```

**table**: a `Key | Value` table of all ten structured keys in the order `topicId,
topicName, revision, active, description, examples, createdBy, updatedBy,
lastModifiedTs, createdTs`. Unset keys are empty rows. `examples` is compact JSON (`[]`
when absent: the zod default).

```
 Key            │ Value                                
────────────────┼──────────────────────────────────────
 topicId        │ 00000000-0000-4000-8000-000000000012 
 topicName      │ fin                                  
 revision       │ 2                                    
 active         │ true                                 
 description    │ new                                  
 examples       │ ["fin example"]                      
 createdBy      │ creator@example.com                  
 updatedBy      │                                      
 lastModifiedTs │ 2026-02-01T00:00:00Z                 
 createdTs      │ 2026-01-01T00:00:00Z                 
```

```
 Key            │ Value                                
────────────────┼──────────────────────────────────────
 topicId        │ 00000000-0000-4000-8000-000000000022 
 topicName      │ no-examples                          
 revision       │ 1                                    
 active         │                                      
 description    │                                      
 examples       │ []                                   
 createdBy      │                                      
 updatedBy      │                                      
 lastModifiedTs │                                      
 createdTs      │                                      
```

```
 Key            │ Value                                                                                       
────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────
 topicId        │ 00000000-0000-4000-8000-000000000021                                                        
 topicName      │ many-examples                                                                               
 revision       │ 3                                                                                           
 active         │ true                                                                                        
 description    │ Has several examples                                                                        
 examples       │ ["first example","second, with comma","third | pipe","multi\nline example","ünïcödé 日本 🚀"] 
 createdBy      │ creator@example.com                                                                         
 updatedBy      │ updater@example.com                                                                         
 lastModifiedTs │ 2026-02-01T00:00:00Z                                                                        
 createdTs      │ 2026-01-01T00:00:00Z                                                                        
```

`--all-versions`: the list layout (pretty: the `Custom Topics:` section, no status; table:
the list table). Not found in pretty: banner on stdout, then `\n  ✗ Error: Topic "nosuch"
not found\n\n` on stderr, exit 1 (`topics-get-notfound-pretty`).

### 3.5 `tenant list` / `ls` (`tenant.ts:195-218`)

Order: resolve the format (`ignoreConfig`), read the registry, then:
- Zero tenants and format `pretty`: stdout `"  No tenants found\n"` (printed under
  `--quiet`), stderr status `"  Run 'airs-cli tenant create <name>' to register one.\n"`.
  Exit 0.
- Otherwise, when tenants exist and none is active: stderr status
  `"  No tenant selected; run 'airs-cli tenant switch <name>'.\n"` (every format).
- stdout: `console.log(formatOutput(rows, COLUMNS, pretty ? 'table' : format))` with rows
  `{...entry, active: entry.name === store.active}` in registry order and `COLUMNS`
  `Tenant←name, Selected←active, TSG ID←tsgId, Config file←configPath`
  (`tenant.ts:32-37`). **pretty and table are byte-identical.**
- **Empty registry in `table`: stdout is `"\n"`** (the empty render is still logged),
  unlike the management lists. No status line.
- No colour in the table. On a TTY, `No tenants found` and the status are dim.

Captured (registry: `prod` active, `dev` with config path `/r/configs/dév-日本-🚀.json`,
`a-much-longer-tenant-name`). This is the default, `--output pretty`,
`--output table` and `ls --quiet` alike; stderr is empty:

```
 Tenant                    │ Selected │ TSG ID     │ Config file                                   
───────────────────────────┼──────────┼────────────┼───────────────────────────────────────────────
 prod                      │ true     │ 100        │ /r/configs/prod.json                          
 dev                       │ false    │ 1234567890 │ /r/configs/dév-日本-🚀.json                     
 a-much-longer-tenant-name │ false    │ 7          │ /r/a/much/longer/path/to/configs/staging.json 
```

Bytes: `" Tenant                    │ Selected │ TSG ID     │ Config file                                   \n───────────────────────────┼──────────┼────────────┼───────────────────────────────────────────────\n prod                      │ true     │ 100        │ /r/configs/prod.json                          \n dev                       │ false    │ 1234567890 │ /r/configs/dév-日本-🚀.json                     \n a-much-longer-tenant-name │ false    │ 7          │ /r/a/much/longer/path/to/configs/staging.json \n"`

None selected: the same table with every `Selected` false, and stderr
`"  No tenant selected; run 'airs-cli tenant switch <name>'.\n"` (suppressed by `--quiet`).

Empty registry: default stdout `"  No tenants found\n"` with stderr
`"  Run 'airs-cli tenant create <name>' to register one.\n"`; `--quiet` stdout `"  No tenants found\n"`
with stderr empty; `--output table` stdout `"\n"` with stderr
empty; `--output json` stdout `"[]\n"`.

### 3.6 `tenant read [name]` (`tenant.ts:220-240`)

Rows are `{key, value: redact(key, value)}` for every key of the zod-parsed config, in
schema order with `scanConcurrency` and `dataDir` defaults (DESIGN §3.6). `redact` is
`[REDACTED]` for a truthy secret, else `value ?? ''`. stderr status (suppressed by
`--quiet`): `  Tenant <name> (TSG <tsg>): <configPath>`. stdout: the `Key | Value` table.
pretty and table are byte-identical. On a TTY only the status is coloured (dim).

stderr: `"  Tenant prod (TSG 100): $SB/configs/prod.json\n"`

```
 Key                          │ Value                                  
──────────────────────────────┼────────────────────────────────────────
 airsApiKey                   │ [REDACTED]                             
 airsApiEndpoint              │ http://127.0.0.1:NNNNN/scan            
 airsNumRetries               │ 0                                      
 mgmtClientId                 │ client-100                             
 mgmtClientSecret             │ [REDACTED]                             
 mgmtTsgId                    │ 100                                    
 mgmtEndpoint                 │ http://127.0.0.1:NNNNN/aisec           
 mgmtDashboardEndpoint        │ http://127.0.0.1:NNNNN/dashboard       
 mgmtTokenEndpoint            │ http://127.0.0.1:NNNNN/oauth/token     
 dlpEndpoint                  │ http://127.0.0.1:NNNNN/dlp             
 redTeamDataEndpoint          │ http://127.0.0.1:NNNNN/redteam/data    
 redTeamMgmtEndpoint          │ http://127.0.0.1:NNNNN/redteam/mgmt    
 redTeamNetworkBrokerEndpoint │ http://127.0.0.1:NNNNN/redteam/broker  
 modelSecDataEndpoint         │ http://127.0.0.1:NNNNN/aims/data       
 modelSecMgmtEndpoint         │ http://127.0.0.1:NNNNN/aims/mgmt       
 agentGuardDataEndpoint       │ http://127.0.0.1:NNNNN/agentguard/data 
 agentGuardMgmtEndpoint       │ http://127.0.0.1:NNNNN/agentguard/mgmt 
 aiGwDataEndpoint             │ http://127.0.0.1:NNNNN/ai_gw/v2        
 aiGwAdminEndpoint            │ http://127.0.0.1:NNNNN/ai_gw/admin/v2  
 iamEndpoint                  │ http://127.0.0.1:NNNNN/iam             
 aiGwInferenceEndpoint        │ http://127.0.0.1:NNNNN/ai_gw/inference 
 typesafeBaseUrl              │ http://127.0.0.1:NNNNN/typesafe        
 scanConcurrency              │ 5                                      
 dataDir                      │ ~/.prisma-airs/runs                    
```

### 3.7 `tenant get <name> <key>` (`tenant.ts:165-181`)

- **pretty** (the default): `console.log(String(value))`, so `100\n`, `5\n`,
  `[REDACTED]\n`, or **`\n`** for an unset key. Never coloured.
- **table**: a one-row `Key | Value` table:

```
 Key       │ Value 
───────────┼───────
 mgmtTsgId │ 100   
```

```
 Key              │ Value      
──────────────────┼────────────
 mgmtClientSecret │ [REDACTED] 
```

Unset key (`defaultOutput`):

```
 Key           │ Value 
───────────────┼───────
 defaultOutput │       
```

- No status lines. Key validation (D34) precedes format validation.

### 3.8 `tenant path [name]` (`tenant.ts:242-251`)

`console.log(configPath)`. `--output` (any value, including `table` or `xml`) is
consumed by the root and ignored; the bytes are the same in every format.

### 3.9 `doctor` (`doctor.ts:769-825`)

**pretty** (DESIGN §9 already specifies the Rust layout):
`ui.header('Doctor', 'Prisma AIRS CLI preflight checks')`, per check
`ui.bullet("<name> — <detail>", kind)` and, when there is a hint, `ui.dim("    " + hint)`
(6 spaces in total, quiet-suppressed); `console.log('')`; then the summary,
`ui.success(...)` on stdout or `ui.error(...)` on **stderr**; `console.log('')`. TTY: the
glyph is coloured (✓ green, ⚠ ○ yellow, ✗ red), the hint dim, and the success summary
green as a whole (`✓ All checks passed` inside one span).

```

  Doctor
  Prisma AIRS CLI preflight checks

  ✓ Node.js version — v24.21.0 (^20.17.0 || ^22.13.0 || >=23.5.0 required)
  ✓ Tenant — prod (TSG 100) selected in $SB/state/tenants.json
  ✓ Config file — valid tenant config at $SB/configs/prod.json (TSG 100 matches registration)
  ✓ Environment — no configuration variables set
  ✓ Scanner credentials — airsApiKey (file)
  ✓ Management credentials — set: mgmtClientId (file), mgmtClientSecret (file), mgmtTsgId (file)
  ○ Typesafe credentials — not configured — redteam judge is unavailable
      Run 'airs-cli tenant set prod <key>' for typesafeApiKey (secrets prompt hidden, or use --stdin)
  ✓ Scanner API — endpoint reachable, API key accepted
  ✓ Management OAuth — OAuth token obtained, topics API answered (3 custom topics)
  ✓ AI Gateway API — endpoint reachable (0 workspaces in scope)
  ○ Typesafe API — skipped — typesafeApiKey not configured

  ✓ All checks passed (2 skipped)

```

**table**: `formatOutput(checks, [Name←name, Status←status, Detail←detail, Hint←hint],
'table')` + `\n` on stdout. `status` is the raw lowercase `pass|warn|fail|skip`, and an
absent hint is an empty cell. There is **no header, no summary and no stderr output**, and
`--quiet` changes nothing. The exit code is still 1 when any check fails
(`doctor.ts:823`). The TS run has 11 checks (Node.js, Typesafe and AI Gateway included,
D19), so the column widths differ from any Rust table.

Captured with the Scanner API probe answering 401 (exit 1, stderr empty; the sandbox
mask keeps the real path length):

```
 Name                   │ Status │ Detail                                                                                                                                                                                                                            │ Hint                                                                                            
────────────────────────┼────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────
 Node.js version        │ pass   │ v24.21.0 (^20.17.0 || ^22.13.0 || >=23.5.0 required)                                                                                                                                                                              │                                                                                                 
 Tenant                 │ pass   │ prod (TSG 100) selected in /SANDBOX_________________________________________________________________________________________________________________________________________________/state/tenants.json                           │                                                                                                 
 Config file            │ pass   │ valid tenant config at /SANDBOX_________________________________________________________________________________________________________________________________________________/configs/prod.json (TSG 100 matches registration) │                                                                                                 
 Environment            │ pass   │ no configuration variables set                                                                                                                                                                                                    │                                                                                                 
 Scanner credentials    │ pass   │ airsApiKey (file)                                                                                                                                                                                                                 │                                                                                                 
 Management credentials │ pass   │ set: mgmtClientId (file), mgmtClientSecret (file), mgmtTsgId (file)                                                                                                                                                               │                                                                                                 
 Typesafe credentials   │ skip   │ not configured — redteam judge is unavailable                                                                                                                                                                                     │ Run 'airs-cli tenant set prod <key>' for typesafeApiKey (secrets prompt hidden, or use --stdin) 
 Scanner API            │ fail   │ API key rejected (HTTP 401): AISEC_CLIENT_SIDE_ERROR:bad key                                                                                                                                                                      │ Verify airsApiKey belongs to this tenant and is not expired                                     
 Management OAuth       │ pass   │ OAuth token obtained, topics API answered (0 custom topics)                                                                                                                                                                       │                                                                                                 
 AI Gateway API         │ pass   │ endpoint reachable (0 workspaces in scope)                                                                                                                                                                                        │                                                                                                 
 Typesafe API           │ skip   │ skipped — typesafeApiKey not configured                                                                                                                                                                                           │                                                                                                 
```

### 3.10 `runtime scan` (`runtime.ts:67-85,1043-1069`)

TS has **no** table or other format: `--output table`, `--output xml` and
`defaultOutput` are ignored (captured `scan-allow-table`, `extra-scan-bad`,
`defaultOutput-table-scan`). The pretty layout is DESIGN §8.4. TTY colour: header and
`Detections` bold, keys dim, `BLOCK` red or `ALLOW` green, `yes` red or `no` green, the
Scan ID and Report ID values dim, `●` yellow, status lines dim (stderr).

```

  Scan Result

  Action     BLOCK
  Category   malicious
  Triggered  yes
  Scan ID    00000000-0000-4000-8000-0000000000b2
  Report ID  R00000000-0000-4000-8000-0000000000b2

  Detections

  ● injection
  ● toxic_content
```

stderr: `"  Prisma AIRS Runtime Scan\n  Profile: p\n  Prompt:  \"BLOCKME please\"\n"`

TTY (stdout):

```

  \e[1mScan Result\e[22m

  \e[2mAction   \e[22m  \e[31mBLOCK\e[39m
  \e[2mCategory \e[22m  malicious
  \e[2mTriggered\e[22m  \e[31myes\e[39m
  \e[2mScan ID  \e[22m  \e[2m00000000-0000-4000-8000-0000000000b2\e[22m
  \e[2mReport ID\e[22m  \e[2mR00000000-0000-4000-8000-0000000000b2\e[22m

  \e[1mDetections\e[22m

  \e[33m●\e[39m injection
  \e[33m●\e[39m toxic_content
```

TTY stderr (redirected to a file): `"  \u001b[2mPrisma AIRS Runtime Scan\u001b[22m\n  \u001b[2mProfile: p\u001b[22m\n  \u001b[2mPrompt:  \"BLOCKME please\"\u001b[22m\n"`

---

## 4. TS behaviour the port should not copy (candidate §12 rows)

DESIGN §12 ends at D49, so adopted rows would be numbered from D50. R1 and R11 rewrite
D4 and D42 rather than adding rows.

| # | Behaviour | TypeScript | Recommended airs-cli-rs | Reason |
|---|---|---|---|---|
| R1 | Formats `markdown`, `csv`, `yaml` (replaces D4 and D42 for table) | rendered for management, tenant and doctor | usage error, exit 2 (§5.6 gives the message) | MILESTONES scope: permanently dropped |
| R2 | Tenant `defaultOutput` naming a dropped format | honoured | the management default falls back to `pretty`, with status line `defaultOutput '<x>' is not supported by airs-cli-rs; writing pretty` | the TS file stays loadable; MILESTONES makes it invalid only in the M4t TOML layout |
| R3 | Control characters (ESC, TAB, LF, C1) in server or file text inside pretty layouts and table cells | written raw: ESC sequences reach the terminal, and LF/TAB break tables (§3.1, §3.3) | `terminal_safe` (U+FFFD) on every printed string cell and pretty value. This extends D47. U+FFFD is one UTF-16 unit, so the widths of other rows are unchanged | terminal integrity, an existing invariant |
| R4 | Table width counts UTF-16 code units | CJK misaligns by its extra columns; combining marks and ZWJ sequences misalign the other way | pad by display width (`unicode-width`, UAX #11). ASCII and Latin text are byte-identical; emoji (2 units, 2 columns) are identical too | aligned tables; differs only for wide, zero-width or astral non-emoji text |
| R5 | Topic list description `slice(0, 80)` through a surrogate pair | lone surrogate written as U+FFFD | drop the straddling character (the D43 rule); still no ellipsis | never emit a broken character |
| R6 | `--quiet` in pretty lists | removes the profile and topic **ID lines** (`ui.dim`), leaving names only | either copy it (parity) or keep the ID lines (IDs are data; DESIGN §2.3 says quiet suppresses only status and decoration). Recommended: keep them, with a §12 row | `--quiet` must not drop data |
| R7 | Pretty list row without `profile_id` / `topic_id` | prints `  undefined` (and throws with `AIRS_CLI_INVOKED_AS='airs cli'`) | omit the ID line (the detail view already prints an empty `ID`) | JS artefact |
| R8 | A failing pretty management command | banner already on stdout, then the error | stdout empty (the buffered output, DESIGN §2.2) | failing runs leave stdout empty (D4 records this today) |
| R9 | Colour | chalk on a capable TTY, decided from stdout and applied to stderr too; `NO_COLOR` ignored; FORCE_COLOR + NO_COLOR produces a Node warning | no ANSI (DESIGN §2.2). If colour is added later: per-stream `isatty`, honour `NO_COLOR` (and `TERM=dumb`), with the SGR mapping of §2.6 | existing contract; parity tests run piped, so it is invisible there |
| R10 | `runtime scan --output table` | ignored; pretty printed | a Rust `Key \| Value` table (§5.5) | "pretty and table for every command" (M3.5). D5 is updated |
| R11 | `doctor --output <invalid>` | uncaught rejection: a stack trace, exit 1 | usage error, exit 2 (already the Rust behaviour; D42 is narrowed to the dropped formats) | usage contract |
| R12 | Unknown policy keys in the pretty `Policy` block and the compact `policy` cell | JS object order (integer-like keys first, then insertion order) | sorted (SDK model), as D35 already says for JSON | extend D35's wording to the pretty and table renderings |

Copy these (parity, no §12 row needed):
- the empty-list asymmetry (management table: no stdout; `tenant list` table: `\n`);
- the trailing space on table lines;
- `tenant get` printing an empty line for an unset key;
- `Showing 0` after `No profiles found`;
- no status for `get --all-versions`;
- the description cut with no ellipsis;
- Policy continuation lines not aligned under the value column;
- the separate key widths of the two topic key/value blocks;
- `pretty` = `table` for `tenant list|read`;
- `active` → `active`/`inactive` in pretty but `true`/`false`/empty in tables.

Not renderer-specific, noted while capturing: `String(number)` and `JSON.stringify` use
ECMAScript `Number::toString`. Rust's `json::normalize_numbers` maps integral floats up
to 2^53 to integers, and serde_json formats other floats via ryu. These differ for
integral values in (2^53, 1e21), which JS prints in full (`100000000000000000000`) and
ryu prints as `1e20`, and for magnitudes in [1e-6, 1e-5), which JS prints as `0.00000x`.
A JS-exact formatter (for example the `ryu-js` crate, or a port of `Number::toString`)
should back both the JSON output and the table cells.

---

## 5. Recommended Rust design

### 5.1 Module layout

```
src/render/mod.rs       Cell, js_number(), cell_text(), width(); terminal_safe applied here
src/render/table.rs     table(labels, rows) -> String  (the §2.3 algorithm, display-width padding)
src/render/pretty.rs    banner(), section(), key_value(), bullet(), empty_list(): the ui.ts primitives
                        as functions that push into Output (data vs decoration)
src/views.rs            (existing) JSON projections + per-resource rows:
                        profile_list_row, profile_detail_rows (all 8 keys), topic_list_row,
                        topic_detail_rows (all 10 keys), profile_pretty_list/detail,
                        topic_pretty_list/detail
src/output.rs           Format {Pretty, Table, Json}; one policy table per command (§5.6)
src/commands/*.rs       pick a renderer by Format; data still buffered via Output
```

`Output` already has the right split. `data*` is printed under `--quiet` (key/value
lines, list rows, bullets, empty-list text, tables, the bare `tenant get` value).
`decoration` is suppressed by `--quiet` (banner, section, and, under the TS rule only, ID
lines). `status` goes to stderr. Every renderer writes into the buffer, so a failing
command leaves stdout empty (R8).

### 5.2 Table helper (exact algorithm)

```rust
/// TS formatOutput(rows, columns, 'table') (common.ts:126-139). Empty rows → "".
pub fn table(labels: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() { return String::new(); }
    let w = |s: &str| UnicodeWidthStr::width(s);           // R4; parity alternative: s.encode_utf16().count()
    let widths: Vec<usize> = (0..labels.len())
        .map(|i| rows.iter().map(|r| w(&r[i])).fold(w(labels[i]), usize::max))
        .collect();
    let line = |cells: &mut dyn Iterator<Item = &str>| -> String {
        cells.zip(&widths)
            .map(|(c, &wd)| format!(" {c}{} ", " ".repeat(wd - w(c))))
            .collect::<Vec<_>>().join("│")
    };
    let mut out = vec![line(&mut labels.iter().copied())];
    out.push(widths.iter().map(|wd| "─".repeat(wd + 2)).collect::<Vec<_>>().join("┼"));
    for r in rows { out.push(line(&mut r.iter().map(String::as_str))); }
    out.join("\n")                                          // caller adds the final "\n"
}
```

Cells reach `table` already converted by `cell_text`:
- absent or null → `""`;
- a string → `terminal_safe(s)` (R3);
- a number → `js_number(f64)` (ECMAScript `Number::toString`);
- a bool → `true` / `false`;
- an object or array → the compact JS-ordered JSON of the projection with JS numbers
  (`serde_json::to_string` of the normalised `OValue`). JSON escapes control
  characters, so no `terminal_safe` is needed there.

Emission rules:
- list commands: `if !t.is_empty() { data_line(&t) }`;
- `tenant list`: always `data_line(&t)` (an empty table prints `\n`);
- detail tables: always.

Golden unit tests: the captured blocks of §3 as byte strings (ASCII rows, an empty cell,
a long cell), plus the Unicode rows under whichever width rule is chosen.

### 5.3 Key/value helper

```rust
/// ui.keyValue: "  " + key.padEnd(W) + "  " + value, W = longest key in THIS call.
fn key_value(out: &mut Output, pairs: &[(&str, String)]) {
    let w = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);   // keys are ASCII labels
    for (k, v) in pairs { out.data_line(&format!("  {k:<w$}  {v}")); }
}
```

Values are run through `terminal_safe`, except the Policy block. That block is
`json::to_pretty(policy)` with `"\n"` replaced by `"\n  "`; its string contents are
already JSON-escaped.

### 5.4 Pretty emitters

Implement §3.1–§3.4 literally:
- banner via `decoration`;
- section via `decoration`;
- ID line via `decoration` (TS) or `data` (R6);
- name line via `data`;
- the trailing `"\n"` via `data`;
- `No profiles found` / `No topics found` / `No tenants found` via `data`;
- `Examples:` and bullets via `data`.

The topic description preview uses the D43 helper with a limit of 80 UTF-16 units and no
ellipsis. `tenant list` and `tenant read` route `pretty` to the table. `tenant get`
`pretty` prints `Shown::display()`.

### 5.5 `runtime scan` table (Rust-only, R10)

Follow the TS detail-table convention (`emitDetail`): `Key | Value` rows from the
`--output json` record, minus `result` (the raw SDK response, which can be large). The
keys are `profileName, scanId, reportId, action, category, triggered, detections,
responseDetections`, plus `error` for failed scans. Objects are compact JSON, and the
values carry the withheld forms of §8.3. The exit code and the failure line on stderr
are as for pretty. The scan status lines go to stderr as in pretty (they are status,
not decoration).

### 5.6 Format policy for 0.2

| Command | Supported | Default (`--output` absent) | `defaultOutput` |
|---|---|---|---|
| `runtime profiles` / `topics` `list` / `get` | pretty, table, json | `defaultOutput` when it is pretty, table or json, else `pretty` + R2 status line | honoured |
| `tenant list`, `tenant read`, `tenant get` | pretty, table, json | pretty | ignored |
| `tenant path` | none (`--output` ignored, as today) | — | — |
| `doctor` | pretty, table, json | pretty | ignored |
| `runtime scan` | pretty, table, json | pretty | ignored |

Every command supports the same three, so the simplest message for the dropped names is
`Invalid output format 'csv'. Expected: pretty, table, json`: `Format` keeps only the
three, and the "not supported here" branch goes. The alternative is to keep six valid
names with `Output format 'csv' is not supported here. Expected: pretty, table, json`.
Either way the TS text differs (it lists six names), which R1 records. The help strings
(`Output format: pretty, table, json`) come from the same table, as they do now.

---

## 6. Parity tests needed

All of these run piped (no colour on either side), on a fresh `Sandbox` +
`FixtureServer`, comparing exit codes, request logs, and **exact stdout and stderr
bytes** (not JSON-semantic). Where a §12 row applies, a `dNN_` test asserts both sides.

| File | Test | Formats | Scenario |
|---|---|---|---|
| parity_management.rs | profiles_list_render | default, pretty, table, each ± `--quiet` | alpha/beta latest; `--limit 1` (more available); `--all`; `--all-versions`; empty |
| | profiles_list_render_edges | pretty, table | no id, `active` false or absent, `revision` 0 or absent, a long name, `revision` 2.5 (JS number text) |
| | profiles_get_render | pretty, table, `--quiet` | by name; by id; `--revision 1`; `--all-versions` (list layout, no status); a sparse profile (empty table rows); `policy: {}`; a large policy |
| | profiles_get_render_failure | pretty, table | not found: TS banner on stdout vs Rust empty (dNN R8) |
| | topics_list_render | default, pretty, table, ± `--quiet` | latest; `--all-versions` (`of` and `next --offset` status); `--all`; empty; descriptions of 80 and 81 ASCII characters; an empty description |
| | topics_get_render | pretty, table | one example; many examples; no examples, description or metadata (block widths); `--all-versions` |
| | default_output_render | none | `defaultOutput: table` → table; `--output pretty` overrides it; `--output table` before the subcommand, and last-wins |
| | dNN_dropped_formats (R1, replaces d4_yaml_output) | csv, markdown, yaml | Rust exit 2 with the message; TS renders |
| | dNN_default_output_dropped (R2) | none | `defaultOutput: markdown`: TS markdown, Rust pretty + status line |
| | dNN_control_characters (R3) | pretty, table | ESC/TAB/LF in profile and topic names, descriptions and examples |
| | dNN_unicode_width (R4) | table | `日本語` and combining text in names; ASCII rows identical |
| | dNN_description_surrogate_cut (R5) | pretty | 79 ASCII + `🚀` |
| | dNN_quiet_id_lines (R6), dNN_missing_id (R7) | pretty | as described |
| | dNN_policy_key_order (R12) | pretty, table | unknown policy keys `{"10","2","a","b"}` |
| parity_tenant.rs | tenant_list_render | default, pretty, table, `--quiet` | selected; none selected (status); empty (pretty text + status; table `\n`; json `[]`) |
| | tenant_read_render | default, pretty, table, `--quiet` | the standard config (status line + table) |
| | tenant_get_render | default, pretty, table | a set value, a secret, an unset key (empty line or empty cell), a defaulted number |
| | tenant_path_ignores_output | table, `xml` | path printed, exit 0 |
| | dNN_dropped_formats_tenant (R1, replaces d4_tenant_list_and_read_formats) | csv, markdown, yaml | as above |
| parity_doctor.rs | doctor_table_shape | table | the byte layout cannot match (11 vs 7 checks, D19), so assert the structure: header `Name │ Status │ Detail │ Hint`, the rule, one row per check, and cells (split on `│`, then trimmed) equal for the checks both CLIs have; no summary; stderr empty; exit 0 / 1 |
| | doctor_table_quiet | table | `--quiet` changes nothing |
| | d42 (narrowed) | csv, markdown, yaml | Rust exit 2; TS renders |
| parity_scan.rs | dNN_scan_table (R10, D5 update) | table | TS pretty, exit 0; Rust key/value table; allow, block, and failed (exit 1 with the stderr line) |
| parity_shell.rs | dNN_colour (R9) | default | piped: neither CLI emits ANSI; `FORCE_COLOR=1`: TS emits ANSI (+ the Node warning with `NO_COLOR=1`), Rust none |
| unit (src/render) | golden tables | — | the §3 captures as literal byte strings, an empty-rows → `""` case, the rule-line length, the trailing space |

The pretty doctor and scan parity tests that exist already stay as they are.

---

## Appendix A: how the captures were made

A scratch Rust program (not in the repo) that depends on `crates/airs-test-harness` by
path:
- `FixtureServer::start()`;
- `Sandbox::new()` with `add_fixture_tenant_with(&server, "prod", "100", edit)` and
  `register`;
- datasets via `set_profiles` / `set_topics` / `add_scan_verdict`;
- piped runs through `airs_test_harness::run(&Cli::ts(), …)`, which also runs the leak
  and tenant-unchanged checks;
- TTY runs: `child_environment(&sandbox, &opts)` checked by `assert_safe_for_ts`, then
  `script -q /dev/null sh -c 'eval "$CLI" 2>"$ERR"'`, with `TERM=xterm-256color` added
  unless stated, and `stty cols 30 rows 10` for the width test. The leading `^D\b\b`
  that macOS `script` writes was stripped.
- `tenant list` used registry entries with non-existent config paths (`tenant list`
  never opens configs; tenant names must match `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`, so
  only paths carry Unicode).

The same scenarios can be added to `crates/airs-test-harness/examples/ts_baseline.rs` if
a persistent capture is wanted.
