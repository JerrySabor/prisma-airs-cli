#!/usr/bin/env bash
# Regenerates the docs site's command reference from the clap definitions.
# usage() below holds the usage text (--help prints it).
set -euo pipefail

usage() {
  cat <<'USAGE'
Regenerates the docs site's command reference from the clap definitions.

  scripts/cli-reference.sh          rewrite docs-site/docs/reference/commands/
  scripts/cli-reference.sh --check  only check that the committed pages are current

The pages are the --help texts of the airs binary, walked from the root down
(tests/cli_reference.rs). The rewrite runs
  AIRS_UPDATE_CLI_REFERENCE=1 cargo test --locked --test cli_reference
and --check runs the same test without the variable, so it fails, naming the
stale, missing or extra pages, when the committed reference is out of date.
USAGE
}

mode=write
for arg in "$@"; do
  case "$arg" in
    --check) mode=check ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "cli-reference: unknown argument: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [ "$mode" = check ]; then
  env -u AIRS_UPDATE_CLI_REFERENCE cargo test --locked --test cli_reference
else
  AIRS_UPDATE_CLI_REFERENCE=1 cargo test --locked --test cli_reference
fi
