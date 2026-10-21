# Prisma AIRS CLI documentation site

The Docusaurus 3 site published at <https://cdot65.github.io/prisma-airs-cli/>. It documents
the Rust CLI (`airs`) built from this repository.

```sh
pnpm install --frozen-lockfile   # pnpm 10.6.5 (packageManager)
pnpm start                       # local preview
pnpm build                       # broken links and anchors fail the build
```

- `docs/getting-started/` and `docs/commands/` are written by hand.
- `docs/reference/commands/` is generated from the CLI's clap definitions: run
  `scripts/cli-reference.sh` from the repository root after changing a command or its help;
  `cargo test --test cli_reference` fails while the committed pages are stale.
- Forgejo CI (`.forgejo/workflows/ci.yml`, job `docs-site`) builds the site on every push and
  pull request. The site is deployed by `.github/workflows/deploy-docs.yml` on the GitHub
  mirror, from an `airs-docs-<commit sha>` tag that the Forgejo `docs-release` workflow
  creates after CI passed on `main`.
