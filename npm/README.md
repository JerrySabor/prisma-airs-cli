# @cdot65/prisma-airs-cli

The Prisma AIRS CLI, the `airs` command: a native Rust CLI for Palo Alto Networks Prisma
AIRS (runtime security profiles, topics and scans, DLP, AI Red Team, Model Security, AI
Gateway and AI Supply Chain), built on the `scm-sdk` crate.

From 8.0.0 this package installs prebuilt native binaries of the Rust CLI (crate
`airs-cli`). It replaces the TypeScript CLI that this package carried through 7.x.

```sh
npm install -g @cdot65/prisma-airs-cli
airs --version
airs doctor
```

It installs two commands, `airs` and `airs-cli`, which run the same program. Help and
hints name `airs`.

- **Platforms:** macOS on Apple Silicon (signed and notarised) and Linux x64 and arm64
  (static musl builds that run on glibc and musl alike). npm installs the one platform
  package that matches, as an optional dependency; nothing is downloaded by a script.
  Intel macOS, Windows and other platforms get an error that names the other ways to
  install: `cargo install --locked airs-cli` or the Homebrew tap
  `cdot65/prisma-airs-cli`.
- **Node:** 18 or newer. Node only starts the binary.
- **One channel:** install `airs` from one of npm, Homebrew, cargo or a release tarball.
  Homebrew's Node puts npm's global commands in `/opt/homebrew/bin`, where the Homebrew
  formula links `airs` too. `airs doctor` warns when another `airs`, `airs-cli` or
  `airs-cli-rs` earlier on `PATH` is a different program.
- **Upgrading from the TypeScript CLI (7.x):** run `airs tenant import` once to copy
  your tenants; see the upgrade guide.

Documentation: https://cdot65.github.io/prisma-airs-cli/ ·
Source: https://git.cdot.io/cdot/prisma-airs-cli (mirrored to
https://github.com/cdot65/prisma-airs-cli) · License: Apache-2.0.
