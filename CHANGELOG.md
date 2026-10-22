# Changelog

Release notes for each version are in [docs/RELEASE-NOTES/](docs/RELEASE-NOTES/). This
file records the changes to the repository itself.

## Unreleased (8.0.0)

### The Rust CLI replaces the TypeScript CLI in this repository

- **Source.** The Rust CLI (crate `airs-cli`, command `airs`, version 1.0.0) was copied
  from `cdot/prisma-airs-cli-rs`
  (`ssh://git@git-ssh.cdot.io/cdot/prisma-airs-cli-rs.git`) at
  `a9d7864f037cc3bf0d2ef6de2c8ac6341ce3842a` with `git archive`, without its history.
  Its release notes up to 1.0.0 are in `docs/RELEASE-NOTES/`.
- **Removed from the tree.** The TypeScript CLI (`@cdot65/prisma-airs-cli` through
  7.2.1-forgejo.0 on `main` at `5711012`): its sources, tests, build and release tooling,
  configs, lockfiles, TypeScript-only workflows (`docker-publish.yml.disabled` included)
  and assessment notes. They stay in the git history and in every `v7.*` tag (7.3.0 is
  `v7.3.0`, `7a54e46`); the parity tests build the TypeScript reference from that history.
- **Added.** The `airs-cli` name for the Rust CLI (D330), the doctor's `Executable` check
  (D331), the npm launcher package and `scripts/npm-package.sh`, the Rust docs site in
  `docs-site/` with a command reference generated from `--help`, and `NOTICE` in the
  crate, the release tarballs and the npm packages.
- **Next.** The TypeScript CLI 7.3.0 port (directional runtime security profiles) on
  `scm-sdk` 1.0.1, then one 8.0.0 release on crates.io, npm, Homebrew, the Forgejo release
  and the docs site. There is no 1.0.1 or 1.1.0 release.
