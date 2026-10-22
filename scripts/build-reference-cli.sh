#!/usr/bin/env bash
# Builds the TypeScript reference CLI (airs-cli) that the parity tests run against,
# from the pinned TypeScript commit in this repository's own history.
# usage() below holds the usage text (--help prints it).
set -euo pipefail

usage() {
  cat <<'USAGE'
Builds the TypeScript reference CLI (airs-cli) that the parity tests run against.

  scripts/build-reference-cli.sh            clone (if needed) + install + build
  scripts/build-reference-cli.sh --verify   check an existing build; changes nothing
  scripts/build-reference-cli.sh --dry-run  print the steps; changes nothing
  scripts/build-reference-cli.sh --force    rebuild even when the build is current
  scripts/build-reference-cli.sh --clone-only  clone/check out and verify HEAD; no pnpm

Environment:
  AIRS_TS_SOURCE   git source to clone: a URL or a local repository path (default: this
                   repository's Forgejo URL, ssh://git@git-ssh.cdot.io/cdot/prisma-airs-cli.git;
                   AIRS_TS_SOURCE=. clones this checkout's own history, offline)
  AIRS_TS_COMMIT   pinned commit (default below; parity expectations are tied to it)

The TypeScript reference is a commit in this repository's own history (the TypeScript
CLI lived here until the Rust CLI replaced it). A local source is only read
(git clone --no-hardlinks). The clone lands in .reference/prisma-airs-cli (gitignored).
`pnpm install` downloads npm packages; it is skipped by --verify and --dry-run and when
the build is already current.
USAGE
}

PINNED_COMMIT="${AIRS_TS_COMMIT:-7a54e46eee4f7914d610bc78d2f98dd7de09fbfe}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# This repository's own Forgejo URL: the pin is a commit in its history.
REPOSITORY_URL="ssh://git@git-ssh.cdot.io/cdot/prisma-airs-cli.git"
SOURCE="${AIRS_TS_SOURCE:-$REPOSITORY_URL}"
DEST="$ROOT/.reference/prisma-airs-cli"
ENTRY="$DEST/dist/cli/index.js"

mode=build
force=0
for arg in "$@"; do
  case "$arg" in
    --verify) mode=verify ;;
    --dry-run) mode=dry-run ;;
    --clone-only) mode=clone-only ;;
    --force) force=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

die() {
  echo "build-reference-cli: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH"
}

# HEAD of the clone, or empty when there is no clone.
clone_head() {
  if [ -d "$DEST/.git" ]; then
    git -C "$DEST" rev-parse HEAD 2>/dev/null || true
  fi
}

# Tracked files of the clone are unmodified (dist/ and node_modules/ are ignored).
clone_clean() {
  [ -z "$(git -C "$DEST" status --porcelain --untracked-files=no)" ]
}

is_current() {
  [ "$(clone_head)" = "$PINNED_COMMIT" ] && clone_clean && [ -f "$ENTRY" ] && [ -d "$DEST/node_modules" ]
}

report() {
  need node
  echo "reference: $DEST"
  echo "commit:    $(clone_head)"
  echo "node:      $(node --version)"
  # Isolated environment: --version reads no tenant state, but never let it see ours.
  local home
  home="$(mktemp -d)"
  echo "airs-cli:  $(env -i PATH="$PATH" HOME="$home" NO_COLOR=1 node "$ENTRY" --version)"
  rm -rf "$home"
}

need git

case "$mode" in
  verify)
    [ -d "$DEST/.git" ] || die "no clone at $DEST; run scripts/build-reference-cli.sh"
    head="$(clone_head)"
    [ "$head" = "$PINNED_COMMIT" ] || die "clone HEAD is $head, expected $PINNED_COMMIT"
    clone_clean || die "tracked files in $DEST are modified"
    [ -f "$ENTRY" ] || die "missing $ENTRY; run scripts/build-reference-cli.sh"
    [ -d "$DEST/node_modules" ] || die "missing $DEST/node_modules; run scripts/build-reference-cli.sh"
    report
    echo "verify: ok"
    exit 0
    ;;
  dry-run)
    echo "source:  $SOURCE"
    echo "dest:    $DEST"
    echo "commit:  $PINNED_COMMIT"
    if is_current && [ "$force" -eq 0 ]; then
      echo "state:   current (nothing to do; --force rebuilds)"
      exit 0
    fi
    if [ "$(clone_head)" = "" ]; then
      echo "would:   git clone --no-hardlinks --no-checkout $SOURCE $DEST"
    else
      echo "would:   git -C $DEST fetch origin (clone HEAD $(clone_head))"
    fi
    echo "would:   git -C $DEST checkout --detach $PINNED_COMMIT"
    echo "would:   pnpm install --frozen-lockfile && pnpm run build (in $DEST)"
    exit 0
    ;;
esac

if [ "$mode" = build ] && is_current && [ "$force" -eq 0 ]; then
  echo "reference build is current"
  report
  exit 0
fi

# A local source (a directory) is checked before cloning; a URL after (below).
if [ -d "$SOURCE" ]; then
  git -C "$SOURCE" cat-file -e "$PINNED_COMMIT^{commit}" 2>/dev/null \
    || die "commit $PINNED_COMMIT is not in $SOURCE"
fi

if [ ! -d "$DEST/.git" ]; then
  [ ! -e "$DEST" ] || die "$DEST exists but is not a git clone; remove it first"
  mkdir -p "$(dirname "$DEST")"
  # --no-checkout leaves an empty index, so there is nothing to protect yet.
  git clone --no-hardlinks --no-checkout "$SOURCE" "$DEST"
else
  clone_clean || die "tracked files in $DEST are modified; refusing to check out over them"
  git -C "$DEST" fetch --quiet --tags origin
fi
git -C "$DEST" cat-file -e "$PINNED_COMMIT^{commit}" 2>/dev/null \
  || die "commit $PINNED_COMMIT is not in $SOURCE"
git -C "$DEST" -c advice.detachedHead=false checkout --quiet --detach "$PINNED_COMMIT"
head="$(clone_head)"
[ "$head" = "$PINNED_COMMIT" ] || die "clone HEAD is $head after checkout, expected $PINNED_COMMIT"
if [ "$mode" = clone-only ]; then
  echo "clone at $DEST is at $head"
  exit 0
fi

need node
need pnpm
(
  cd "$DEST"
  pnpm install --frozen-lockfile
  pnpm run build
)
[ -f "$ENTRY" ] || die "build finished without $ENTRY"
report
