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
- **Next.** The bounded live run of the 7.3.0 port and its review, then one 8.0.0 release
  on crates.io, npm, Homebrew, the Forgejo release and the docs site. There is no 1.0.1 or
  1.1.0 release.

### The TypeScript CLI 7.3.0 port

- **Reference.** The parity reference moves to tag `v7.3.0` (`7a54e46eee4f`, TS SDK
  0.35.0), the final TypeScript release (docs/TESTING.md §3.4).
- **SDK.** `scm-sdk` 0.2.4, the TypeScript SDK 0.35.0 overlay. **Temporary:** until 0.2.4
  is on crates.io, `Cargo.toml` takes the exact Forgejo commit
  `4825616ccf4c29272aff9a1ec3dcffb8b2e91535` (`cdot/scm-sdk-rs`, branch
  `feat/typescript-035-parity`) as a git dependency; replace it with `=0.2.4` when
  published (DESIGN §15.25). `Cargo.lock` also moves `rustls-webpki` to 0.103.16 and
  `webpki-root-certs` to 1.0.10 (RUSTSEC-2026-0382, -0383).
- **Directional security profiles** (experimental, DESIGN §13.17): `--direction` and
  `--ai-profile-index` on `runtime profiles create|update` and `runtime topics
  apply|revert`; `--[no-]enable-full-conversation-inspection`, `--no-mask-data-inline`,
  `--no-mask-data-in-storage`; `create --config` names the profile from the file;
  `--config` is exclusive with every write flag; the recursive merge; the layout refusals
  (exit 2); the profile views, the runtime report and profile backup and restore read every
  direction.
- **The rest of 7.3.0.** Highest-revision profile lookups in `topics apply|revert`; ref and
  group metadata kept; every profile body validated with the 0.35.0 request schema;
  `profiles create|update` print a status line and the banner-less detail and honour the
  tenant's `defaultOutput`; `--active` only when given; the `malicious-code` name on the
  update merge path; `--dlp-profiles` and `--[no-]mask-data-inline` without `--dlp-action`
  on update; `revert` refuses a topic the profile does not reference.
- **§12 rows.** New: D332, D333. Retired: D117. Reworded: D26, D50, D93, D94, D96,
  D98–D103, D106, D115, D116.
