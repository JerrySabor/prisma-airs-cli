# Repository authority and delivery

The canonical repository is https://git.cdot.io/cdot/prisma-airs-cli.
Open new issues and pull requests there. GitHub is a public source mirror;
historical GitHub pull requests remain available, and their open heads were
preserved as `archive/github-pr-N` branches in Forgejo.

From 8.0 this repository holds the Rust CLI (crate `airs-cli`, command `airs`), which
replaced the TypeScript CLI; the TypeScript sources stay in the history and the `v7.*`
tags, which must never be deleted (the parity tests build the reference from them).
`cdot/prisma-airs-cli-rs`, where the Rust CLI was developed, is archived after the move.

Forgejo owns CI and release authorization (`.forgejo/workflows/ci.yml`, docs/TESTING.md
§10; releases: docs/RELEASING.md). The TypeScript-era GitHub package and container
workflows were removed with the TypeScript CLI. GitHub Pages remains at its existing URL.
Documentation is deployed only from an `airs-docs-<full commit SHA>` tag approved in
Forgejo (`.forgejo/workflows/docs-release.yml`, which requires the CI jobs to be green)
and copied by the push mirror. The GitHub Pages job verifies that the tag matches the
exact source commit.

Package destinations: crates.io (`airs-cli`), npmjs.org (`@cdot65/prisma-airs-cli`, from
8.0 a launcher for prebuilt binaries), the Homebrew tap `cdot65/homebrew-prisma-airs-cli`
on GitHub, and npm.cdot.io for Harness. The npm dist-tags `latest` and `next` move to
each Rust release; `forgejo-preview` is left alone (docs/RELEASING.md §7).
The npm publishing credential is held at Conjur
`data/airs-release-bot/npmjs/token`; never put its value in source or logs.
Direct granular-token publishing is a temporary bridge: npm removes it in
January 2027. Before expiry, adopt staged releases with maintainer approval or a
supported trusted-publishing runner. See https://docs.npmjs.com/about-access-tokens/.

Clone the canonical source:

```sh
git clone git@git-ssh.cdot.io:cdot/prisma-airs-cli.git
```

Do not force-update a mirror until all destination-only commits and refs are
preserved. Stop mirroring before any emergency GitHub-authority rollback, then
reconcile both histories before resuming. Existing package versions are immutable.

## Release operations

Use Forgejo pull requests and wait for required checks before merging. For a
migration prerelease, push a matching `vX.Y.Z-forgejo.N` tag after CI passes;
`publish-prerelease.yml` writes only `forgejo-preview`. For a stable release,
create an explicitly published non-prerelease release record on Forgejo for the
matching stable tag. `publish-stable.yml` rejects a rollback of `latest` and
preserves unrelated channels. Never create GitHub releases to trigger publishing.
The CLI remains in Changesets prerelease mode during migration: use
`pnpm changeset pre exit` and `pnpm changeset version` for its next stable release.

Run **Authorize GitHub Pages release** on Forgejo's `main` after CI. It verifies
required checks and creates an exact-source tag; the mirror triggers Pages.
For CLI container recovery, dispatch **Publish private CLI container** on main.
Existing image versions are verified by digest without rebuilding or overwriting. Stable container aliases are promoted only
after both architecture checks; prereleases never move stable aliases.

npm may process an accepted upload asynchronously. A verification timeout does
not authorize replacing a version: inspect registry state and install the exact
version before retrying. Keep the Conjur npm token and Forgejo `NPM_TOKEN` secret
copies synchronized on rotation. The scoped Harbor publisher expires after 90
days; rotate its escrowed credential and `HARBOR_PASSWORD` before expiry.
