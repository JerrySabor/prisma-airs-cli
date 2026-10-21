---
title: Install
sidebar_position: 1
---

# Install

`airs` is one self-contained executable. Install it through **one** of the channels
below; mixing channels puts two copies on `PATH` and the first one wins (see
[Choosing a channel](#choosing-a-channel)).

| Channel | Platforms | Provides |
|---|---|---|
| [Homebrew](#homebrew) | macOS and Linux (built from source) | `airs`, with `airs-cli` and `airs-cli-rs` linked to it |
| [npm](#npm) | Apple Silicon macOS, Linux x86_64 and arm64 | the `airs` and `airs-cli` launchers |
| [cargo](#cargo) | anywhere Rust 1.89 or newer builds | `airs`, `airs-cli` and `airs-cli-rs` |
| [Release tarballs](#release-tarballs) | Apple Silicon macOS, Linux x86_64 and arm64 | `airs`, with `airs-cli` and `airs-cli-rs` links |

## Names

The command is `airs`. `airs-cli` and `airs-cli-rs` run the same program and print the same
output, byte for byte:

- `airs-cli` is the TypeScript CLI's command name, so scripts written for 7.x keep finding a
  command after the upgrade;
- `airs-cli-rs` is the Rust CLI's name before 1.0.

Help, hints and examples always say `airs`, whatever name started the program. Check the
version with `airs --version`; it prints the bare version, such as `8.0.0`.

## Homebrew

The formula lives in the public tap
[`cdot65/homebrew-prisma-airs-cli`](https://github.com/cdot65/homebrew-prisma-airs-cli) and
builds `airs` from the published crates.io crate, so Homebrew installs Rust as a build
dependency. Homebrew loads a third-party tap's formulae only after `brew trust`:

```sh
brew tap cdot65/prisma-airs-cli
brew trust cdot65/prisma-airs-cli
brew install airs-cli
brew upgrade airs-cli        # later releases
```

It installs `airs` and links `airs-cli` and `airs-cli-rs` to it. The tap carries stable
releases only.

## npm

```sh
npm install -g @cdot65/prisma-airs-cli
```

From 8.0.0 the npm package `@cdot65/prisma-airs-cli` distributes the Rust CLI. It installs
two launchers, `airs` and `airs-cli`, that start the prebuilt binary for your platform. The
binaries come in optional platform packages (versions of the same package such as
`8.0.0-darwin-arm64`) that npm picks by `os` and `cpu`; nothing is downloaded or built at
install time and there is no install script.

| Platform | Binary |
|---|---|
| macOS on Apple Silicon (`darwin-arm64`) | the signed and notarised `aarch64-apple-darwin` build |
| Linux x86_64 (`linux-x64`) | the static `x86_64-unknown-linux-musl` build (runs on glibc and musl alike) |
| Linux arm64 (`linux-arm64`) | the static `aarch64-unknown-linux-musl` build |

On any other platform (Intel macOS, Windows and others), or when npm skipped the optional
dependency, the launcher prints an error that names `cargo install airs-cli` and the
Homebrew tap, and exits non-zero. Node 18 or newer is required.

An installed TypeScript 7.x package upgrades in place:

```sh
npm install -g @cdot65/prisma-airs-cli@latest
airs-cli --version    # 8.0.0 or later
```

Then read [Upgrading from the TypeScript CLI](./upgrading-from-typescript.md): the tenants
must be imported once.

## cargo

The crate is [`airs-cli`](https://crates.io/crates/airs-cli). It needs Rust 1.89 or newer:

```sh
cargo install --locked airs-cli
```

It installs `airs`, `airs-cli` and `airs-cli-rs`, three copies of the same program built
from one source, so they cannot drift.

## Release tarballs

Prebuilt binaries are attached to each
[Forgejo release](https://git.cdot.io/cdot/prisma-airs-cli/releases) (it needs a login),
with a `SHA256SUMS` file. Each `airs-cli-<version>-<target>.tar.gz` holds `airs`, the
relative links `airs-cli -> airs` and `airs-cli-rs -> airs`, `README.md` and `LICENSE`.

| Target | Notes |
|---|---|
| `aarch64-apple-darwin` | signed with a Developer ID and notarised |
| `x86_64-unknown-linux-musl` | static |
| `aarch64-unknown-linux-musl` | static |

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf airs-cli-<version>-<target>.tar.gz
mkdir -p ~/.local/bin
install -m 0755 airs ~/.local/bin/airs
ln -sf airs ~/.local/bin/airs-cli         # the other names, if you want them
ln -sf airs ~/.local/bin/airs-cli-rs
```

`~/.local/bin` must be on `PATH`, ahead of any other `airs`.

## From source

```sh
git clone https://github.com/cdot65/prisma-airs-cli.git   # the public mirror of the Forgejo repository
cd prisma-airs-cli
cargo build --release
```

The SDK, `scm-sdk`, comes from crates.io, so the first build needs access to the crates.io
index.

This produces `target/release/airs` (and `airs-cli` and `airs-cli-rs`, copies of the same
program). Install it with `cargo install --locked --path .`.

## Choosing a channel

Install `airs` through one channel only. Two channels put two copies on `PATH`, and the
shell runs whichever comes first:

- **Homebrew and npm collide in `/opt/homebrew/bin`.** Homebrew's Node puts npm's global
  executables in `/opt/homebrew/bin`, the directory where the Homebrew formula links `airs`
  too. Whichever was installed last owns the names there, and `brew link` refuses to
  overwrite a file npm created. Pick one: `npm uninstall -g @cdot65/prisma-airs-cli` before
  installing with Homebrew, or `brew uninstall airs-cli` before installing with npm.
- **The TypeScript CLI.** Before installing with Homebrew, cargo or a tarball, remove the
  TypeScript package from every Node version that has it
  (`npm uninstall -g @cdot65/prisma-airs-cli`, and `pnpm remove -g` if you used pnpm), or
  its `airs-cli` keeps answering. Upgrading through npm replaces it in place.
- **An unrelated `airs`.** Another program named `airs` earlier on `PATH` wins by `PATH`
  order.

Check what runs:

```sh
type -a airs airs-cli airs-cli-rs
airs --version
airs doctor
```

`airs doctor` has an `Executable` check that warns when another `airs`, `airs-cli` or
`airs-cli-rs` earlier on `PATH` resolves to a different file than the program that is
running. It is a warning only and never fails the run (see [doctor](../commands/doctor.md)).

## Next steps

[Create or import a tenant](./configuration.md), then run `airs doctor`.
